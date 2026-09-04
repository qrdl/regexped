// settest is a CLI benchmarking tool for one SET — the set analogue of
// tools/pattest. It takes the set from a YAML config file (the same schema
// `regexped compile` reads), compiles it three times with the set-level hint
// varied over neutral / prefer-match / prefer-no-match, and reports what each
// hint did to the module and to the cost of one capability call.
//
// Usage:
//
//	settest -config <yaml> [-set <name>] [-cap <capability>] -inputs <file>
//	        [-detailed] [-force-frontend <fe>] [-iters <n>]
//
// The question it answers is "can THIS set benefit from a hint", in three
// layers, cheapest first:
//
//   - Does the hint change the emitted module at all? A hint that compiles
//     byte-identical to neutral cannot help; the run says so and skips the
//     measurement rather than reporting timing noise as a delta.
//   - If it changed the module, WHAT did it change? Each mode prints its
//     SetDiag row — frontend, scan-pair body, anchored body, bucket count —
//     which is the only place a body selection is visible.
//   - Did the change pay? Fuel (deterministic) and wall-clock p50 for one
//     capability call, against a matching and a non-matching bucket of the
//     caller's own inputs.
//
// -inputs points to a text file with one candidate input per line (no embedded
// newlines within a single input). Bucketing uses Go's stdlib regexp package
// as ground truth: an input is "matching" when ANY pattern the set actually
// contains matches it — anchored over the whole input for match_any/match_all,
// unanchored for scan_any/scan_all/find.
//
// Only the SET-level `hints:` is varied, and set compilation resolves its mode
// from the set's OWN hints alone — a per-pattern `hints:` never feeds it. Those
// reach `compilePattern` and so shape the per-pattern exports the same config
// may also declare; since settest rewrites nothing but the set's hints, they
// are identical across all three builds and cannot contribute to any delta
// reported here. What they can move is the baseline: they are part of the
// module whose size is printed, and part of what the identical-WASM verdict
// compares.
//
// The module is compiled with every capability the config declares, not just
// the one being driven: that is the module the user would actually ship, so it
// is the one whose size is worth reporting. The identical-WASM verdict is
// therefore about the whole module, which makes it conservative in the right
// direction — "identical" is a definitive no for every capability at once.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/benchshim"
	"github.com/qrdl/regexped/internal/utils"
)

const (
	fuelBudget = uint64(10_000_000_000)
	pageSize   = int64(65536)
	// warmupTime precedes every timed series. Short on purpose: unlike
	// likelytest's fixed corpus this tool runs once per user input, so the
	// warmup is paid len(inputs)*3 times.
	warmupTime = 20 * time.Millisecond
)

// --------------------------------------------------------------------------
// Capabilities

type capKind int

const (
	capFind capKind = iota
	capScanAny
	capScanAll
	capMatchAny
	capMatchAll
)

var capOrder = []capKind{capMatchAny, capMatchAll, capScanAny, capScanAll, capFind}

func (c capKind) String() string {
	switch c {
	case capFind:
		return "find"
	case capScanAny:
		return "scan_any"
	case capScanAll:
		return "scan_all"
	case capMatchAny:
		return "match_any"
	case capMatchAll:
		return "match_all"
	}
	return "?"
}

// anchored reports whether c requires the match to span the whole input, which
// is what the Go-side oracle has to mirror when it buckets the inputs.
func (c capKind) anchored() bool { return c == capMatchAny || c == capMatchAll }

// declaredExport returns the export name sc gives capability c, or "" when the
// set does not declare it.
func declaredExport(sc config.SetConfig, c capKind) string {
	switch c {
	case capFind:
		return sc.Find
	case capScanAny:
		return sc.ScanAny
	case capScanAll:
		return sc.ScanAll
	case capMatchAny:
		return sc.MatchAny
	case capMatchAll:
		return sc.MatchAll
	}
	return ""
}

// --------------------------------------------------------------------------
// Hint modes

var modeNames = [3]string{"neutral", "prefer-match", "prefer-no-match"}

// modeHints is the YAML `hints:` list each mode installs on the set. Nil is
// the absent key, which is how a config expresses neutral.
var modeHints = [3][]string{nil, {"prefer-match"}, {"prefer-no-match"}}

// build is one compiled module plus what the compiler decided while building it.
type build struct {
	wasm []byte
	diag compile.SetDiag
	// identical marks a mode whose module came out byte-identical to
	// neutral's: the hint reached no emitter, so any measured delta would be
	// noise. Never set for neutral itself.
	identical bool
}

type cell struct {
	fuel uint64
	t    time.Duration
}

func main() {
	wcallCase = "settest"
	// Silence regexped's slog output. Set-composition warnings (a dropped
	// pattern, a demoted frontend) reach us through SetDiag instead, which is
	// reported per mode.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	configFlag := flag.String("config", "", "YAML config file declaring the set (required)")
	setFlag := flag.String("set", "", "name of the set to test; optional when the config declares exactly one")
	capFlag := flag.String("cap", "", "capability to drive: find, scan_any, scan_all, match_any, match_all; optional when the set declares exactly one")
	inputsFlag := flag.String("inputs", "", "path to a text file of candidate inputs, one per line (required)")
	detailed := flag.Bool("detailed", false, "show per-input results instead of bucket averages")
	forceFE := flag.String("force-frontend", "", "TEST-ONLY: pin the literal frontend (teddy, ac, scalar, packed-pair, shufti); empty lets the chooser decide")
	adaptive := flag.String("adaptive", "", "TEST-ONLY: pin the Shufti density switch on or off; empty uses the compiler's verdict")
	iters := flag.Int("iters", 1000, "timed passes per input per mode; the reported time is their p50")
	flag.Parse()

	if *configFlag == "" || *inputsFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: settest -config <yaml> [-set <name>] [-cap <capability>] -inputs <file> [-detailed] [-force-frontend <fe>] [-adaptive on|off] [-iters <n>]")
		os.Exit(2)
	}
	if *iters < 1 {
		fmt.Fprintln(os.Stderr, "error: -iters must be at least 1")
		os.Exit(2)
	}

	opts, err := compileOverrides(*forceFE, *adaptive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	cfg, err := config.LoadConfig(*configFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	setIdx, err := resolveSet(cfg, *setFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	kind, err := resolveCap(cfg.Sets[setIdx], *capFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	export := declaredExport(cfg.Sets[setIdx], kind)
	// Both counts come from the SAME config methods the compiler and the stub
	// generators use, so the buffers this harness sizes and the indexing the
	// module performs cannot disagree. They differ only for a named subset,
	// and using the wrong one there is a memory-safety bug rather than a wrong
	// answer: the gate array is indexed by global pattern id.
	patternCount := cfg.Sets[setIdx].PatternCount(cfg)
	idSpace := cfg.Sets[setIdx].IDSpaceSize(cfg)

	inputs, err := readInputs(*inputsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading inputs: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no inputs found in file")
		os.Exit(1)
	}

	// Compile all three modes before anything is measured, so a config error
	// surfaces immediately rather than after a bucket of timings.
	builds, err := compileModes(cfg, setIdx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// The oracle is built from what the set ACTUALLY contains: a pattern the
	// packer dropped cannot match, so counting it would put inputs in the
	// wrong bucket and then fail the sanity check for a reason that is not a
	// bug. Drops are a property of the compile, so they are read from the
	// neutral build's diagnostics.
	oracle, exact := buildOracle(cfg, cfg.Sets[setIdx], builds[0].diag, kind)
	if len(oracle) == 0 {
		fmt.Fprintln(os.Stderr, "error: no pattern in the set could be compiled by Go's regexp package; cannot bucket inputs")
		os.Exit(1)
	}

	var matching, nonMatching []string
	for _, in := range inputs {
		if anyMatch(oracle, in) {
			matching = append(matching, in)
		} else {
			nonMatching = append(nonMatching, in)
		}
	}

	engine := newWatchedEngine(nil)
	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := newWatchedEngine(fuelCfg)

	printHeader(*configFlag, cfg, setIdx, kind, export, patternCount, idSpace, len(matching), len(nonMatching), exact)
	printCompileTable(builds)

	// Sanity: the driven export must agree with the oracle about whether each
	// input matches at all. It is not a correctness suite — re2test's set mode
	// is — but a mis-driven ABI measures the wrong work entirely, and every
	// number below it would be meaningless rather than merely wrong.
	if exact {
		if err := sanityCheck(builds, kind, export, patternCount, idSpace, inputs, oracle, engine); err != nil {
			fmt.Fprintf(os.Stderr, "\nSANITY FAIL: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("  (sanity check skipped: the oracle is incomplete, see above)")
		fmt.Println()
	}

	report := printSummary
	if *detailed {
		report = printDetailed
	}
	report("Matching inputs", matching, builds, kind, export, patternCount, idSpace, *iters, engine, fuelEngine)
	report("Non-matching inputs", nonMatching, builds, kind, export, patternCount, idSpace, *iters, engine, fuelEngine)
}

// --------------------------------------------------------------------------
// Resolution

func resolveSet(cfg config.BuildConfig, name string) (int, error) {
	if len(cfg.Sets) == 0 {
		return 0, fmt.Errorf("config declares no sets")
	}
	if name == "" {
		if len(cfg.Sets) != 1 {
			var names []string
			for _, s := range cfg.Sets {
				names = append(names, s.Name)
			}
			return 0, fmt.Errorf("config declares %d sets (%s); pick one with -set",
				len(cfg.Sets), strings.Join(names, ", "))
		}
		return 0, nil
	}
	for i, s := range cfg.Sets {
		if s.Name == name {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no set named %q in the config", name)
}

func resolveCap(sc config.SetConfig, name string) (capKind, error) {
	var declared []capKind
	for _, c := range capOrder {
		if declaredExport(sc, c) != "" {
			declared = append(declared, c)
		}
	}
	if name == "" {
		if len(declared) != 1 {
			var names []string
			for _, c := range declared {
				names = append(names, c.String())
			}
			return 0, fmt.Errorf("set %q declares %d capabilities (%s); pick one with -cap",
				sc.Name, len(declared), strings.Join(names, ", "))
		}
		return declared[0], nil
	}
	for _, c := range capOrder {
		if c.String() == name {
			if declaredExport(sc, c) == "" {
				return 0, fmt.Errorf("set %q does not declare %s", sc.Name, name)
			}
			return c, nil
		}
	}
	return 0, fmt.Errorf("unknown capability %q", name)
}

// compileOverrides turns -force-frontend and -adaptive into compiler overrides.
//
// "shufti" is not a value chooseLiteralFrontend can be told to return: Shufti
// is reachable only from the SCALAR branch, after Aho-Corasick declines over
// its table budget. Asking for it therefore means simulating that decline with
// a one-byte AC budget and letting the chooser proceed — which lands on Shufti
// only if the set's first-byte union is in the band, and on plain scalar
// otherwise. The frontend column reports what actually shipped either way.
func compileOverrides(fe, adaptive string) (compile.CompileSetOptions, error) {
	var opts compile.CompileSetOptions
	switch fe {
	case "":
	case "teddy":
		opts = opts.WithForcedFrontend(compile.SetFrontendTeddy)
	case "ac":
		opts = opts.WithForcedFrontend(compile.SetFrontendAC)
	case "scalar":
		opts = opts.WithForcedFrontend(compile.SetFrontendScalar)
	case "packed-pair":
		opts = opts.WithForcedFrontend(compile.SetFrontendPackedPair)
	case "shufti":
		opts.ACBudgetBytes = 1
	default:
		return opts, fmt.Errorf("-force-frontend: unknown value %q (teddy, ac, scalar, packed-pair, shufti)", fe)
	}

	// -adaptive pins the Shufti density switch, the runtime counter that
	// disables the SIMD probe for the rest of a call once it has stopped
	// paying. Nothing reachable from YAML compiles both arms of it — the
	// verdict is `prefer-no-match && !rare`, deterministic per set — so
	// "does the switch still earn its cost" is answerable only here.
	switch adaptive {
	case "":
	case "on":
		opts = opts.WithShuftiAdaptive(true)
	case "off":
		opts = opts.WithShuftiAdaptive(false)
	default:
		return opts, fmt.Errorf("-adaptive: unknown value %q (on, off, or empty)", adaptive)
	}
	return opts, nil
}

// --------------------------------------------------------------------------
// Compilation

// compileModes compiles cfg three times, varying only the hint on set setIdx.
func compileModes(cfg config.BuildConfig, setIdx int, opts compile.CompileSetOptions) ([3]build, error) {
	var out [3]build
	for i := range modeNames {
		// Copy the sets slice before touching Hints: the entries are values,
		// but the slice backs every mode and a shared write would make each
		// compile see the previous mode's hint.
		c := cfg
		c.Sets = append([]config.SetConfig(nil), cfg.Sets...)
		c.Sets[setIdx].Hints = modeHints[i]
		// Standalone is selected by an EMPTY cfg.Output, not by the output
		// argument — a config written for the merge path would otherwise
		// compile a module that imports "main" memory and cannot be
		// instantiated on its own.
		c.Output = ""

		wasm, _, diags, err := compile.CompileFileOpts(c, "", opts)
		if err != nil {
			return out, fmt.Errorf("compile (%s): %w", modeNames[i], err)
		}
		if setIdx >= len(diags) {
			return out, fmt.Errorf("compile (%s): no diagnostics for set index %d", modeNames[i], setIdx)
		}
		out[i] = build{wasm: wasm, diag: diags[setIdx]}
		if i > 0 && bytes.Equal(wasm, out[0].wasm) {
			out[i].identical = true
		}
	}
	return out, nil
}

// --------------------------------------------------------------------------
// The Go-side oracle

// oracleEntry is one set member as Go's regexp package sees it.
type oracleEntry struct {
	id int
	re *regexp.Regexp
}

// buildOracle compiles the patterns the set actually contains, in the form the
// capability's semantics require. The second result is false when some
// selected pattern could not be compiled by Go — the bucketing is then a
// best effort and the sanity check is skipped rather than trusted.
func buildOracle(cfg config.BuildConfig, sc config.SetConfig, diag compile.SetDiag, kind capKind) ([]oracleEntry, bool) {
	dropped := map[int]bool{}
	for _, refs := range [][]compile.PatternRef{
		diag.CaptureBearingDropped, diag.StateLimitDropped,
	} {
		for _, r := range refs {
			dropped[r.ID] = true
		}
	}
	// UnparseableDropped excludes a pattern from the ANCHORED capabilities
	// only; `find` and the scan pair keep it.
	if kind.anchored() {
		for _, r := range diag.UnparseableDropped {
			dropped[r.ID] = true
		}
	}

	selected := map[string]bool{}
	for _, n := range sc.Patterns.Names {
		selected[n] = true
	}

	exact := true
	var out []oracleEntry
	for id, re := range cfg.Regexps {
		if !sc.Patterns.All && !selected[re.Name] {
			continue
		}
		if dropped[id] {
			continue
		}
		src := re.Pattern
		if kind.anchored() {
			// "Anchored" here is full consumption, 0..len — the same rule
			// docs/sets.md gives for match_any/match_all.
			src = `\A(?:` + src + `)\z`
		}
		c, err := regexp.Compile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: pattern %d (%q) rejected by Go's regexp: %v\n", id, re.Pattern, err)
			exact = false
			continue
		}
		out = append(out, oracleEntry{id: id, re: c})
	}
	if len(dropped) > 0 {
		var ids []int
		for id := range dropped {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		fmt.Fprintf(os.Stderr, "warning: %d pattern(s) dropped from the set by the compiler (ids %v); excluded from the oracle\n",
			len(ids), ids)
	}
	return out, exact
}

func anyMatch(oracle []oracleEntry, input string) bool {
	for _, e := range oracle {
		if e.re.MatchString(input) {
			return true
		}
	}
	return false
}

func readInputs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024) // allow long single-line inputs
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// --------------------------------------------------------------------------
// Memory layout
//
// CompileFile places the set's tables from offset 0 upwards, so everything the
// harness owns goes ABOVE them. Writing the input at a fixed low address (the
// single-pattern convention) would silently overwrite the frontend tables and
// the set would answer garbage.

type memPlan struct {
	inputBase int32
	outBase   int32 // find tuples, 12 bytes each
	gatePtr   int32 // id_space u32s
	bitmapPtr int32 // ceil(id_space/8) bytes, for the wide _all ABI
	needTop   int64
}

func planMem(wasmBytes []byte, maxInputLen, patternCount, idSpace int) (memPlan, error) {
	top, err := utils.ParseDataSectionBytes(wasmBytes)
	if err != nil {
		return memPlan{}, fmt.Errorf("locate table top: %w", err)
	}
	inBase := (top + pageSize - 1) / pageSize * pageSize
	outBase := inBase + int64(maxInputLen) + 4096
	gate := outBase + int64(patternCount)*12 + 64
	bitmap := gate + int64(idSpace)*4 + 64
	need := bitmap + int64((idSpace+7)/8) + 64
	return memPlan{
		inputBase: int32(inBase),
		outBase:   int32(outBase),
		gatePtr:   int32(gate),
		bitmapPtr: int32(bitmap),
		needTop:   need,
	}, nil
}

// --------------------------------------------------------------------------
// Driving one capability

// runner owns an instantiated module and drives ONE capability against it.
// Both the fuel path and the timing path go through it, so the two can never
// measure different work for the same run.
type runner struct {
	store   *wasmtime.Store
	mem     *wasmtime.Memory
	fn      *wasmtime.Func
	plan    memPlan
	kind    capKind
	wide    bool // the _all capability took the out_ptr bitmap ABI
	idSpace int
	outCap  int32
}

// newRunner instantiates wasmBytes and resolves the driven export. The `_all`
// ABI is read off the function's TYPE rather than predicted from the id space:
// a Backtracking member selects the wide form at any width, so the pattern
// count is not enough to know which one shipped.
func newRunner(engine *wasmtime.Engine, wasmBytes []byte, kind capKind, export string, plan memPlan, patternCount, idSpace int, fuel bool) (*runner, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("module: %w", err)
	}
	store := wasmtime.NewStore(engine)
	if !fuel {
		store.SetWasi(wasmtime.NewWasiConfig())
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, fmt.Errorf("instance: %w", err)
	}
	memExport := inst.GetExport(store, "memory")
	if memExport == nil {
		return nil, fmt.Errorf("module exports no memory")
	}
	mem := memExport.Memory()
	fn := inst.GetFunc(store, export)
	if fn == nil {
		return nil, fmt.Errorf("missing export %q", export)
	}

	wide := false
	if kind == capScanAll || kind == capMatchAll {
		res := fn.Type(store).Results()
		wide = len(res) == 0 || res[0].Kind() != wasmtime.KindI64
	}

	// Grow once, here: a grow between timed passes would be measured.
	needPages := uint64((plan.needTop + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needPages > cur {
		if _, err := mem.Grow(store, needPages-cur); err != nil {
			return nil, fmt.Errorf("mem grow: %w", err)
		}
	}
	return &runner{
		store: store, mem: mem, fn: fn, plan: plan, kind: kind,
		wide: wide, idSpace: idSpace, outCap: int32(patternCount),
	}, nil
}

// setInput writes input at the planned base and returns its length.
func (r *runner) setInput(input string) int32 {
	buf := r.mem.UnsafeData(r.store)
	copy(buf[r.plan.inputBase:], input)
	// buf is a raw pointer into wasmtime's native memory, not a Go reference
	// to the store, so the store has to be kept alive across the last use.
	runtime.KeepAlive(r.store)
	return int32(len(input))
}

// drive performs ONE unit of work — a full `find` exhaustion, or a single call
// for every other capability — and reports whether anything matched.
//
// A failed call is an ERROR, never `false`. Collapsing a trap or a watchdog
// timeout into "did not match" is the worst possible outcome for this tool: on
// a non-matching input it agrees with the oracle, so the sanity check passes,
// and the fuel and timing of the aborted call are then published as a
// measurement of work that never ran.
func (r *runner) drive(inputLen int32) (bool, error) {
	p := r.plan
	switch r.kind {
	case capMatchAny:
		v, err := wcall(r.fn, r.store, p.inputBase, inputLen)
		if err != nil {
			return false, err
		}
		return v.(int32) >= 0, nil
	case capScanAny:
		v, err := wcall(r.fn, r.store, p.inputBase, inputLen, int32(0))
		if err != nil {
			return false, err
		}
		return v.(int32) >= 0, nil
	case capMatchAll, capScanAll:
		if r.wide {
			// The module only ORs bits in and counts 0->1 transitions, so a
			// dirty bitmap reports stale patterns: zero it every call.
			r.zero(p.bitmapPtr, int32((r.idSpace+7)/8))
			var args []interface{}
			if r.kind == capScanAll {
				args = []interface{}{p.inputBase, inputLen, int32(0), p.bitmapPtr}
			} else {
				args = []interface{}{p.inputBase, inputLen, p.bitmapPtr}
			}
			v, err := wcall(r.fn, r.store, args...)
			if err != nil {
				return false, err
			}
			return v.(int32) > 0, nil
		}
		var args []interface{}
		if r.kind == capScanAll {
			args = []interface{}{p.inputBase, inputLen, int32(0)}
		} else {
			args = []interface{}{p.inputBase, inputLen}
		}
		v, err := wcall(r.fn, r.store, args...)
		if err != nil {
			return false, err
		}
		return v.(int64) != 0, nil
	default:
		return r.exhaustFind(inputLen)
	}
}

// exhaustFind drives `find` the way a generated iterator does: zero the gate
// array, then call
//
//	find(ptr, len, from, gate_ptr, out_ptr, out_cap) -> total at that position
//
// resuming at start+1. Every tuple of one call shares a start, so reading the
// first tuple is enough to resume. out_cap is the pattern count, the exact
// worst case for one position, so the overflow path is never taken.
func (r *runner) exhaustFind(inputLen int32) (bool, error) {
	p := r.plan
	r.zero(p.gatePtr, int32(r.idSpace)*4)
	found := false
	for from := int32(0); ; {
		n, err := wcall(r.fn, r.store, p.inputBase, inputLen, from, p.gatePtr, p.outBase, r.outCap)
		if err != nil {
			return found, err
		}
		if n.(int32) <= 0 {
			return found, nil
		}
		found = true
		buf := r.mem.UnsafeData(r.store)
		base := int(p.outBase)
		start := int32(buf[base+4]) | int32(buf[base+5])<<8 | int32(buf[base+6])<<16 | int32(buf[base+7])<<24
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

func (r *runner) zero(ptr, n int32) {
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < n; i++ {
		buf[ptr+i] = 0
	}
	runtime.KeepAlive(r.store)
}

// --------------------------------------------------------------------------
// Measurement

// measureMode measures every input against one mode's module, reusing a single
// instance across them: instantiation is not part of what a hint changes, and
// paying it per input would dominate short inputs.
func measureMode(b build, kind capKind, export string, inputs []string, iters int, engine, fuelEngine *wasmtime.Engine, patternCount, idSpace int) ([]cell, error) {
	maxLen := 0
	for _, in := range inputs {
		if len(in) > maxLen {
			maxLen = len(in)
		}
	}
	plan, err := planMem(b.wasm, maxLen, patternCount, idSpace)
	if err != nil {
		return nil, err
	}
	fuelRun, err := newRunner(fuelEngine, b.wasm, kind, export, plan, patternCount, idSpace, true)
	if err != nil {
		return nil, err
	}
	timeRun, err := newRunner(engine, b.wasm, kind, export, plan, patternCount, idSpace, false)
	if err != nil {
		return nil, err
	}

	out := make([]cell, len(inputs))
	for i, in := range inputs {
		n := fuelRun.setInput(in)
		if err := fuelRun.store.SetFuel(fuelBudget); err != nil {
			return nil, fmt.Errorf("set fuel: %w", err)
		}
		before, _ := fuelRun.store.GetFuel()
		if _, err := fuelRun.drive(n); err != nil {
			return nil, fmt.Errorf("fuel pass over %q: %w", truncate(in, 60), err)
		}
		after, _ := fuelRun.store.GetFuel()

		n = timeRun.setInput(in)
		samples := make([]byte, iters*4)
		// One arm for the whole series, not one per call. Arming costs a
		// channel handoff and a timer — ~850 ns on the development machine —
		// which is the same order as a scan call over a short input and would
		// land inside every sample, diluting exactly the hint deltas this tool
		// exists to show. The bound therefore covers the warmup and all
		// `iters` passes together; it stays a liveness check, and a case that
		// legitimately needs longer raises REGEXPED_WASM_TIMEOUT.
		err := watchedSeries(timeRun.store, func() error {
			for end := time.Now().Add(warmupTime); time.Now().Before(end); {
				if _, err := timeRun.drive(n); err != nil {
					return err
				}
			}
			for k := 0; k < iters; k++ {
				t0 := time.Now()
				_, err := timeRun.drive(n)
				d := uint32(time.Since(t0).Nanoseconds())
				if err != nil {
					return err
				}
				samples[k*4] = byte(d)
				samples[k*4+1] = byte(d >> 8)
				samples[k*4+2] = byte(d >> 16)
				samples[k*4+3] = byte(d >> 24)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("timed pass over %q: %w", truncate(in, 60), err)
		}
		out[i] = cell{fuel: before - after, t: benchshim.ComputeStat(samples, 50)}
	}
	return out, nil
}

// sanityCheck confirms the driven export agrees with the oracle about whether
// each input matches at all, for every mode that compiled distinct code.
func sanityCheck(builds [3]build, kind capKind, export string, patternCount, idSpace int, inputs []string, oracle []oracleEntry, engine *wasmtime.Engine) error {
	maxLen := 0
	for _, in := range inputs {
		if len(in) > maxLen {
			maxLen = len(in)
		}
	}
	for i, b := range builds {
		if b.identical {
			continue
		}
		plan, err := planMem(b.wasm, maxLen, patternCount, idSpace)
		if err != nil {
			return err
		}
		r, err := newRunner(engine, b.wasm, kind, export, plan, patternCount, idSpace, false)
		if err != nil {
			return err
		}
		wcallCase = fmt.Sprintf("sanity/%s", modeNames[i])
		for _, in := range inputs {
			want := anyMatch(oracle, in)
			got, err := r.drive(r.setInput(in))
			if err != nil {
				return fmt.Errorf("%s/%s: input %q: %w", modeNames[i], kind, truncate(in, 60), err)
			}
			if got != want {
				return fmt.Errorf("%s/%s: input %q — engine says matched=%v, Go says %v",
					modeNames[i], kind, truncate(in, 60), got, want)
			}
		}
	}
	wcallCase = "settest"
	return nil
}

// --------------------------------------------------------------------------
// Reporting

func printHeader(configPath string, cfg config.BuildConfig, setIdx int, kind capKind, export string, patternCount, idSpace, nMatch, nNoMatch int, exact bool) {
	sc := cfg.Sets[setIdx]
	fmt.Printf("settest — set-level hint matrix\n\n")
	fmt.Printf("config:     %s\n", configPath)
	fmt.Printf("set:        %s\n", sc.Name)
	fmt.Printf("capability: %s (export %q)", kind, export)
	if kind == capFind && sc.Overlapping {
		fmt.Printf("  [overlapping]")
	}
	fmt.Println()
	fmt.Printf("patterns:   %d in set, id space %d\n", patternCount, idSpace)
	fmt.Printf("inputs:     %d matching, %d non-matching", nMatch, nNoMatch)
	if !exact {
		fmt.Printf("  (oracle incomplete — see warnings)")
	}
	fmt.Println()
	fmt.Println()
}

func printCompileTable(builds [3]build) {
	fmt.Println("=== Compile ===")
	// The two body columns go LAST because their content is open-ended
	// ("buckets:single_sparse_bucket" is a real value): a long one then makes
	// the row ragged at the end instead of shifting every column after it.
	fmt.Printf("  %-16s %11s %7s %8s  %-12s %-14s %s\n",
		"mode", "wasm size", "Δ%", "buckets", "frontend", "scan body", "anchored body")
	base := float64(len(builds[0].wasm))
	for i, b := range builds {
		g := "—"
		if i > 0 {
			g = gain(float64(len(b.wasm)), base)
		}
		note := ""
		if b.identical {
			note = "   [identical WASM — the hint reached no emitter]"
		}
		fmt.Printf("  %-16s %11s %7s %8d  %-12s %-14s %s%s\n",
			modeNames[i], fmtFuel(uint64(len(b.wasm))), g, len(b.diag.Buckets),
			frontendCol(b.diag), scanCol(b.diag), anchoredCol(b.diag), note)
	}
	fmt.Println()
}

func frontendCol(d compile.SetDiag) string {
	if d.Frontend == "" {
		return "—"
	}
	if d.FrontendDemotion != nil {
		return fmt.Sprintf("%s←%s", d.Frontend, d.FrontendDemotion.From)
	}
	return d.Frontend
}

func scanCol(d compile.SetDiag) string {
	u := d.UnionScan
	if u == nil {
		return "—"
	}
	if !u.Used {
		return "walk:" + u.Refused
	}
	s := "union/narrow"
	if u.Wide {
		s = "union/wide"
	}
	if u.Phase2 {
		s += "+p2"
	}
	return s
}

func anchoredCol(d compile.SetDiag) string {
	a := d.AnchoredUnion
	if a == nil {
		return "—"
	}
	if !a.Used {
		return "buckets:" + a.Refused
	}
	if a.Wide {
		return "union/wide"
	}
	return "union/narrow"
}

func printSummary(title string, inputs []string, builds [3]build, kind capKind, export string, patternCount, idSpace, iters int, engine, fuelEngine *wasmtime.Engine) {
	fmt.Printf("=== %s (%d) ===\n", title, len(inputs))
	if len(inputs) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	var rows [3]cell
	var haveRow [3]bool
	for i, b := range builds {
		if b.identical {
			continue
		}
		cells, err := measureMode(b, kind, export, inputs, iters, engine, fuelEngine,
			patternCount, idSpace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  measure %s: %v\n", modeNames[i], err)
			continue
		}
		var totalFuel uint64
		var totalTime time.Duration
		for _, c := range cells {
			totalFuel += c.fuel
			totalTime += c.t
		}
		n := uint64(len(cells))
		rows[i] = cell{fuel: totalFuel / n, t: totalTime / time.Duration(n)}
		haveRow[i] = true
	}
	printTable(builds, rows, haveRow)
	fmt.Println()
}

func printDetailed(title string, inputs []string, builds [3]build, kind capKind, export string, patternCount, idSpace, iters int, engine, fuelEngine *wasmtime.Engine) {
	fmt.Printf("=== %s (%d) ===\n", title, len(inputs))
	if len(inputs) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	var per [3][]cell
	var haveRow [3]bool
	for i, b := range builds {
		if b.identical {
			continue
		}
		cells, err := measureMode(b, kind, export, inputs, iters, engine, fuelEngine,
			patternCount, idSpace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  measure %s: %v\n", modeNames[i], err)
			continue
		}
		per[i] = cells
		haveRow[i] = true
	}
	for idx, in := range inputs {
		var rows [3]cell
		var have [3]bool
		for i := range builds {
			if haveRow[i] {
				rows[i] = per[i][idx]
				have[i] = true
			}
		}
		fmt.Printf("--- input #%d: %q ---\n", idx+1, truncate(in, 60))
		printTable(builds, rows, have)
	}
	fmt.Println()
}

func printTable(builds [3]build, rows [3]cell, have [3]bool) {
	baseFuel := float64(rows[0].fuel)
	baseTime := float64(rows[0].t)
	fmt.Printf("  %-16s %14s %7s %14s %7s\n", "mode", "fuel", "Δ%", "p50 time", "Δ%")
	for i := range rows {
		if builds[i].identical {
			fmt.Printf("  %-16s %s\n", modeNames[i],
				"identical WASM — the hint reached no emitter, measurement skipped")
			continue
		}
		if !have[i] {
			fmt.Printf("  %-16s %14s\n", modeNames[i], "(failed)")
			continue
		}
		gFuel, gTime := "—", "—"
		if i > 0 && have[0] {
			gFuel = gain(float64(rows[i].fuel), baseFuel)
			gTime = gain(float64(rows[i].t), baseTime)
		}
		fmt.Printf("  %-16s %14s %7s %14s %7s\n", modeNames[i],
			fmtFuel(rows[i].fuel), gFuel, fmtDur(rows[i].t), gTime)
	}
}

// gain returns a signed percentage like "-23%"/"+8%" for cur against base (the
// neutral row). Negative = cheaper than neutral.
func gain(cur, base float64) string {
	if base == 0 {
		return "—"
	}
	pct := (cur - base) / base * 100
	if pct > -0.5 && pct < 0.5 {
		return "0%"
	}
	return fmt.Sprintf("%+.0f%%", pct)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "n/a"
	}
	if d >= time.Millisecond {
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	}
	if d >= time.Microsecond {
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	}
	return fmt.Sprintf("%d ns", d.Nanoseconds())
}

func fmtFuel(n uint64) string {
	s := fmt.Sprintf("%d", n)
	var b []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, byte(c))
	}
	return string(b)
}
