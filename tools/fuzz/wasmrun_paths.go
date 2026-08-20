package fuzz

import (
	"encoding/binary"
	"errors"
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// Layer 2 (plans/OPUS.md §N7): the compiled paths the original find-only
// fuzzer never reaches — anchored match, captures via TDFA, captures via
// Backtracking, and set match/find_all.
//
// Memory layout, deliberately different from wasmrun.go's find layout and from
// tools/re2test's:
//
//	[0,               pathsInputCap)  test input
//	[pathsOutBase,    pathsTableBase) output buffer (capture slots / set matches)
//	[pathsTableBase,  ...          )  DFA / TDFA / BT tables
//
// re2test puts its slots buffer at offset 512 with input at 0, which caps
// usable input at 512 bytes before the two collide. That is fine for
// exhaustive short strings but useless here: §N1 is an input-length-dependent
// Backtracking bug that only appears past numAlts*4096 bytes, so the whole
// point of this layer is to reach long inputs. Hence a 128 KB input window and
// a separate 128 KB output window, both below the tables.
const (
	pathsInputBase = int32(0)
	pathsInputCap  = 128 * 1024        // 131072 — covers BT thresholds up to numAlts=32
	pathsOutBase   = int32(128 * 1024) // capture slots / set match records
	pathsTableBase = int64(256 * 1024) // tables start here; page-aligned

	// maxFuzzGroups bounds how many capture groups a fuzzed pattern may have
	// before the harness skips it, so the slot buffer cannot run into the
	// tables. 128 groups = 256 slots = 1 KB, far inside the output window.
	maxFuzzGroups = 128

	// setBatchCap is how many (patternID, start, length) records a set
	// find_all call may return per invocation. 3 i32s per record.
	setBatchCap = 1024
)

// compileMatch compiles pat into a standalone module exporting a single
// anchored match function. No captures, so this exercises the DFA /
// CompiledDFA / lit-chain match bodies.
func compileMatch(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, MatchFunc: "match"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
	return w, err
}

// compileGroups compiles pat with a groups export, letting the selector pick
// the engine (TDFA when eligible, Backtracking otherwise).
func compileGroups(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, GroupsFunc: "groups"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
	return w, err
}

// compileGroupsForced compiles pat with a groups export on a specific engine,
// so a single pattern can be checked against both capture backends. Without
// this, whichever engine the selector prefers is the only one the fuzzer ever
// sees for a given pattern shape, and the other backend stays dark.
func compileGroupsForced(pat string, eng compile.EngineType) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, GroupsFunc: "groups"}
	w, _, err := compile.CompileForced([]config.RegexEntry{entry}, pathsTableBase, true, eng)
	return w, err
}

// compileSet compiles pats as one set exporting find_all. Patterns are named
// p0..pN-1 so the set selector can reference them; the pattern ID reported by
// the WASM is the index into pats.
func compileSet(pats []string) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:     "s",
		FindAll:  "set_find_all",
		Patterns: config.PatternSelector{Names: names},
	}}
	// CompileFile hard-codes tableBase = 0 for the sets path, so a set's
	// tables always start at address 0 and the input CANNOT live at offset 0
	// the way it does for the single-pattern paths. cfg.Output == "" selects
	// standalone. runWasmSetFindAll therefore derives its layout from the
	// emitted data section rather than using pathsInputBase.
	cfg := config.BuildConfig{Regexps: entries, Sets: sets}
	w, _, err := compile.CompileFile(cfg, "")
	return w, err
}

// instantiate builds and instantiates a module, returning the store, instance
// and its exported memory.
func instantiate(wasmBytes []byte) (*wasmtime.Store, *wasmtime.Instance, *wasmtime.Memory, error) {
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, nil, nil, err
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		return nil, nil, nil, fmt.Errorf("module has no exported memory")
	}
	return store, inst, memExp.Memory(), nil
}

// runWasmMatch calls the "match" export. Returns the end position on match,
// ok=false for no match. hang=true means the watchdog interrupted a runaway
// call.
func runWasmMatch(wasmBytes []byte, input string) (end int, ok bool, hang bool, err error) {
	store, inst, mem, err := instantiate(wasmBytes)
	if err != nil {
		return 0, false, false, err
	}
	fn := inst.GetFunc(store, "match")
	if fn == nil {
		return 0, false, false, fmt.Errorf("module missing match export")
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[pathsInputBase:], input)
	}

	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, pathsInputBase, int32(len(input)))
	wd.Disarm()
	if callErr != nil {
		if isTimeout(callErr) {
			return 0, false, true, nil
		}
		return 0, false, false, callErr
	}
	r := res.(int32)
	if r == abi.BTStackOverflow {
		return 0, false, false, errBTOverflow
	}
	if r < 0 {
		return 0, false, false, nil
	}
	return int(r), true, false, nil
}

// runWasmGroupsPath calls the "groups" export: (ptr, len, out_ptr) -> i32.
// Returns slots as []int{s0,e0,s1,e1,...} with -1 for unset, matching the
// layout of Go's FindStringSubmatchIndex. ok=false means no match.
func runWasmGroupsPath(wasmBytes []byte, input string, numGroups int) (slots []int, ok bool, hang bool, err error) {
	store, inst, mem, err := instantiate(wasmBytes)
	if err != nil {
		return nil, false, false, err
	}
	fn := inst.GetFunc(store, "groups")
	if fn == nil {
		return nil, false, false, fmt.Errorf("module missing groups export")
	}
	buf := mem.UnsafeData(store)
	if len(input) > 0 {
		copy(buf[pathsInputBase:], input)
	}
	// Pre-set every slot to -1: the WASM only writes slots that participated,
	// so an un-initialised buffer would read as stale data from a prior call.
	nSlots := numGroups * 2
	for i := 0; i < nSlots; i++ {
		binary.LittleEndian.PutUint32(buf[int(pathsOutBase)+i*4:], 0xFFFFFFFF)
	}

	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase)
	wd.Disarm()
	if callErr != nil {
		if isTimeout(callErr) {
			return nil, false, true, nil
		}
		return nil, false, false, callErr
	}
	if res.(int32) == abi.BTStackOverflow {
		return nil, false, false, errBTOverflow
	}
	if res.(int32) < 0 {
		return nil, false, false, nil
	}
	buf = mem.UnsafeData(store)
	slots = make([]int, nSlots)
	for i := range slots {
		slots[i] = int(int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:])))
	}
	return slots, true, false, nil
}

// setMatch is one match reported by a set find_all call.
type setMatch struct {
	PatternID  int
	Start, End int
}

// runWasmSetFindAll calls "set_find_all":
// (ptr, len, out_ptr, out_cap, start_pos) -> i32 count, writing count records
// of (patternID, start, length). Drains repeatedly so a full buffer does not
// silently truncate the result — the same resume rule the generated Go/JS
// stubs implement.
func runWasmSetFindAll(wasmBytes []byte, input string) (matches []setMatch, hang bool, err error) {
	store, inst, mem, err := instantiate(wasmBytes)
	if err != nil {
		return nil, false, err
	}
	fn := inst.GetFunc(store, "set_find_all")
	if fn == nil {
		return nil, false, fmt.Errorf("module missing set_find_all export")
	}

	// Set tables start at address 0 (see compileSet), so the layout has to be
	// derived from the emitted data section rather than fixed: input goes on the
	// first page above the tables, output above the input span. Same approach as
	// tools/re2test's testSetBlock.
	const pageSize = 65536
	dataTop, dtErr := utils.ParseDataSectionBytes(wasmBytes)
	if dtErr != nil {
		return nil, false, fmt.Errorf("parse data section: %w", dtErr)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	inputSpan := int32((len(input) + pageSize - 1) / pageSize * pageSize)
	if inputSpan < pageSize {
		inputSpan = pageSize
	}
	outBase := inBase + inputSpan
	outBytes := int64(setBatchCap) * 12

	neededPages := uint64((int64(outBase) + outBytes + pageSize - 1) / pageSize)
	if cur := mem.Size(store); neededPages > cur {
		if _, growErr := mem.Grow(store, neededPages-cur); growErr != nil {
			return nil, false, fmt.Errorf("memory.Grow to %d pages: %w", neededPages, growErr)
		}
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}

	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, inBase, int32(len(input)), outBase, int32(setBatchCap), int32(0))
	wd.Disarm()
	if callErr != nil {
		if isTimeout(callErr) {
			return nil, true, nil
		}
		return nil, false, callErr
	}
	n := int(res.(int32))
	// Set frontends are DFA-only today (compile/set.go builds prefix/suffix
	// DFAs and drops patterns it cannot handle), so BTStackOverflow is not
	// currently reachable here. Checked anyway, and BEFORE the n <= 0 test
	// that would otherwise read it as "no matches": if a set frontend ever
	// gains a BT-hosting path, the failure mode without this line is a silent
	// wrong answer that the oracle comparison would blame on the compiler.
	if n == abi.BTStackOverflow {
		return nil, false, errBTOverflow
	}
	if n <= 0 {
		return nil, false, nil
	}
	if n >= setBatchCap {
		// Buffer full. find_all's resume protocol (re-call with
		// startPos = lastStart+1) can re-report matches whose start is inside
		// the previous batch's span, and the dedup rule for that is not
		// something this harness should be guessing at — a wrong guess shows up
		// as a fuzz FAILURE against the oracle, i.e. a false accusation against
		// the compiler. Deliberately report truncation and let the caller skip.
		return nil, false, errSetOutputTruncated
	}
	buf := mem.UnsafeData(store)
	for i := 0; i < n; i++ {
		base := int(outBase) + i*12
		id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
		s := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
		l := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
		matches = append(matches, setMatch{PatternID: id, Start: s, End: s + l})
	}
	return matches, false, nil
}

// errSetOutputTruncated signals that a set find_all call filled its output
// buffer, so the result is incomplete and not comparable to the oracle.
var errSetOutputTruncated = errors.New("set find_all output buffer full (truncated)")
