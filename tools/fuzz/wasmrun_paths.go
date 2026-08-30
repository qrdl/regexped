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
// Layer 2: the compiled paths the original find-only
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
func compileSet(pats []string) ([]byte, map[int]bool, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name: "s",
		Find: "set_find",
		// Ungated body: every start position is enumerated, which is what
		// allStartPositionMatches models.
		Overlapping: true,
		Patterns:    config.PatternSelector{Names: names},
	}}
	// CompileFile hard-codes tableBase = 0 for the sets path, so a set's
	// tables always start at address 0 and the input CANNOT live at offset 0
	// the way it does for the single-pattern paths. cfg.Output == "" selects
	// standalone. runWasmSetFindAll therefore derives its layout from the
	// emitted data section rather than using pathsInputBase.
	cfg := config.BuildConfig{Regexps: entries, Sets: sets}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	return w, droppedFromSet(diags), err
}

// droppedFromSet returns the indices of the patterns the compiler EXCLUDED
// from the set it just built.
//
// A set is allowed to drop a pattern: a suffix DFA over max_dfa_states is
// warned about and recorded rather than failing the compile (see CLAUDE.md,
// and compile/set.go's warnPatternDropped). Such a pattern is not in the set,
// so the set reports none of its matches — and a differential test that keeps
// it in the oracle reports the engine as wrong for obeying its own contract.
// That was a real harness defect, whose threshold was exactly one DFA state
// wide: 1024 states passed, 1025 was dropped and "failed".
//
// The ids here are the set's global pattern ids, which compileSet assigns as
// the index into pats — so they index the caller's slice directly.
func droppedFromSet(diags []compile.SetDiag) map[int]bool {
	dropped := map[int]bool{}
	for _, d := range diags {
		for _, ref := range d.StateLimitDropped {
			dropped[ref.ID] = true
		}
		for _, ref := range d.CaptureBearingDropped {
			dropped[ref.ID] = true
		}
	}
	return dropped
}

// instantiate builds and instantiates a module, returning the store, instance,
// its exported memory, and a release func the caller MUST call when done —
// `defer release()` at the call site, so it runs after every use of the store,
// instance and memory.
//
// Releasing explicitly is not optional housekeeping. A Module owns
// JIT-compiled code and a Store owns the linear memory,
// both allocated on the C side. Without Close they are freed only when a
// runtime.SetFinalizer callback runs, and a fuzz iteration allocates almost no
// GO memory — so the GC pacer, which sees only the Go heap, can idle while
// C-side allocations pile up. Nothing here should depend on finalizer timing.
//
// Scope of the claim: this is a resource-management defect, established by
// reading the API (wasmtime-go v42 does expose Store.Close and Module.Close;
// we simply never called them). It is NOT known to cause any particular
// observed failure — in particular it does not explain bug 49's worker aborts,
// which survived this fix, and measurement afterwards showed 200 iterations of
// a bug-49 repro sitting flat at 102 MB.
//
// Order matters: the store must go first, because the instance and memory live
// inside it and the module's compiled code is what the instance runs.
func instantiate(wasmBytes []byte) (*wasmtime.Store, *wasmtime.Instance, *wasmtime.Memory, func(), error) {
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, nil, nil, func() {}, err
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	release := func() {
		store.Close()
		mod.Close()
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		release()
		return nil, nil, nil, func() {}, err
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		release()
		return nil, nil, nil, func() {}, fmt.Errorf("module has no exported memory")
	}
	return store, inst, memExp.Memory(), release, nil
}

// runWasmMatch calls the "match" export. Returns the end position on match,
// ok=false for no match. hang=true means the watchdog interrupted a runaway
// call.
func runWasmMatch(wasmBytes []byte, input string) (end int, ok bool, hang bool, err error) {
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
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
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
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
	// groups is (ptr, len, out_ptr, from); a one-shot call starts at 0.
	res, callErr := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(0))
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

// setMatch is one match reported by a set `find` call.
type setMatch struct {
	PatternID  int
	Start, End int
}

// runWasmSetFind drives "set_find" to exhaustion:
//
//	find(ptr, len, from, out_ptr, out_cap) -> i32 total
//
// Each call returns the TOTAL number of matches at the first matching position
// at or after `from`, writing min(total, out_cap) (patternID, start, end)
// tuples. Every tuple in one call shares a start,
// so the resume rule is `from = start + 1` and no dedup guesswork is needed —
// the ambiguity the old find_all harness had to skip on is gone by
// construction.
//
// The buffer is sized at the set's pattern count, which is the exact worst case
// for a single position, so an overflow here is an engine bug rather than a
// harness limitation.
func runWasmSetFind(wasmBytes []byte, input string, numPatterns int) (matches []setMatch, hang bool, err error) {
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
	if err != nil {
		return nil, false, err
	}
	fn := inst.GetFunc(store, "set_find")
	if fn == nil {
		return nil, false, fmt.Errorf("module missing set_find export")
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
	// The gate array, which every `find` takes —
	// overlapping sets record no gates in it and keep the once-per-drive
	// preflight verdict there instead. Zeroing it starts the drive.
	gateBase := inBase + inputSpan
	outBase := gateBase + pageSize
	outCap := int32(numPatterns)
	outBytes := int64(outCap) * 12

	neededPages := uint64((int64(outBase) + outBytes + pageSize - 1) / pageSize)
	if cur := mem.Size(store); neededPages > cur {
		if _, growErr := mem.Grow(store, neededPages-cur); growErr != nil {
			return nil, false, fmt.Errorf("memory.Grow to %d pages: %w", neededPages, growErr)
		}
	}
	for i := int32(0); i < pageSize; i++ {
		mem.UnsafeData(store)[gateBase+i] = 0
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}

	_, wd := sharedEngine()
	from := int32(0)
	prevStart := -1
	for {
		wd.Arm(store)
		res, callErr := fn.Call(store, inBase, int32(len(input)), from, gateBase, outBase, outCap)
		wd.Disarm()
		if callErr != nil {
			if isTimeout(callErr) {
				return nil, true, nil
			}
			return nil, false, callErr
		}
		n := int(res.(int32))
		// A set CAN reach this now: a member whose fallback DFA exceeded
		// max_fallback_states is admitted on the Backtracking engine
		//, and an exhausted frame budget answers "unknown"
		// rather than "no match". Tested BEFORE the n <= 0 check below, which
		// would otherwise read the sentinel as "no matches" and end the scan
		// reporting success.
		if n == abi.BTStackOverflow {
			return nil, false, errBTOverflow
		}
		if n <= 0 {
			return matches, false, nil
		}
		if n > int(outCap) {
			return nil, false, fmt.Errorf("%w: %d tuples at one position, buffer holds %d",
				errSetOutputTruncated, n, outCap)
		}
		buf := mem.UnsafeData(store)
		start := -1
		for i := 0; i < n; i++ {
			base := int(outBase) + i*12
			id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
			s := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
			e := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
			if i == 0 {
				start = s
			} else if s != start {
				return nil, false, fmt.Errorf("tuples in one call disagree on start: %d vs %d", start, s)
			}
			matches = append(matches, setMatch{PatternID: id, Start: s, End: e})
		}
		if start < int(from) {
			return nil, false, fmt.Errorf("reported start %d is before from=%d", start, from)
		}
		if start <= prevStart {
			return nil, false, fmt.Errorf("start did not advance: %d after %d", start, prevStart)
		}
		prevStart = start
		from = int32(start) + 1
	}
}

// errSetOutputTruncated signals that one `find` call reported more matches at a
// single position than patterns_in_set, which the overflow contract says is
// impossible.
var errSetOutputTruncated = errors.New("set find reported more tuples at one position than the set has patterns")
