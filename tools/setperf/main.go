// Command setperf compares every regexped set capability against
// `regex-automata`, the layer underneath the `regex` crate's facade
// (plans/SETS.md §9.9).
//
// # Why a separate tool from perftest
//
// `perftest --sets` compares against `RegexSet::matches` plus a per-pattern
// rescan, because `RegexSet` deliberately reports *which* patterns match and
// never *where*. That two-pass composite is a fair model of what a `regex`
// user would write, but an unfair model of the engine — we benchmark against
// an emulation, which flatters us. `regex-automata` maps onto the new set API
// almost one-to-one: `Input::span` IS the `from` parameter, `PatternSet` is
// our bitmask plus pattern ids, and `MatchKind::LeftmostFirst` is its default,
// so we are not comparing against leftmost-longest by accident.
//
// It is a separate TOOL because perftest's committed baselines are the
// standing regression signal for everything else in the project; churning
// them through set work would entangle the two. The methodology — p50
// sampling, wasmtime fuel metering, module size, exact-fuel gating — is
// copied deliberately rather than reinvented.
//
// # Reading the numbers
//
// Fuel is EXACT and deterministic within one engine, and is the gating metric
// for our own regressions. ACROSS engines it is indicative only: it counts
// WASM instructions, and Rust→WASM codegen differs structurally from our
// hand-emitted WASM. Track the ratio over time; a single absolute number
// means nothing. The two kinds of fuel are labelled differently for that
// reason.
//
// Wall-clock on this machine is instruction-placement noise (see
// plans/TODO.md's placement-roulette entry); compare the ratio, averaged over
// several runs, or don't compare it at all.
//
// Usage:
//
//	go run .                  # the full matrix
//	go run . -fuel            # our fuel only (deterministic; the regression gate)
//	go run . -size            # module sizes, ours vs theirs
//	go run . -verify          # cross-engine correctness on the honest pairings
//	go run . -compare-fuel baseline_fuel.txt
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

const (
	pageSize   = 65536
	fuelBudget = 4_000_000_000
	benchIters = 2000
)

// capability names the seven exports, in a fixed order.
type capability string

const (
	capMatch    capability = "match"
	capMatchAny capability = "match_any"
	capMatchAll capability = "match_all"
	capScan     capability = "scan"
	capScanAny  capability = "scan_any"
	capScanAll  capability = "scan_all"
	capFind     capability = "find"
	// capFindOverlapping is the ungated `find`. regex-automata has no
	// equivalent — per-start-position enumeration is not a search it can
	// express — so it is measured but never compared.
	capFindOverlapping capability = "find(overlapping)"
)

var allCaps = []capability{
	capMatch, capMatchAny, capMatchAll,
	capScan, capScanAny, capScanAll,
	capFind, capFindOverlapping,
}

// exportName is the WASM export each capability is compiled under.
func exportName(c capability) string {
	if c == capFindOverlapping {
		return "cap_find"
	}
	return "cap_" + string(c)
}

// raPairing names the regex-automata export a capability is compared against,
// or "" when the pairing would be dishonest (§9.9's table).
func raPairing(c capability) string {
	switch c {
	case capScan:
		return "ra_bench_scan"
	case capScanAny:
		return "ra_bench_scan_any"
	case capScanAll:
		return "ra_bench_scan_all"
	case capMatch, capMatchAny:
		return "ra_bench_match"
	case capMatchAll:
		return "ra_bench_match_all"
	case capFind:
		// Per-pattern find_iter merged — the same construction as the
		// plans/SETS.md §9.6.1 oracle. regex-automata's own multi-pattern
		// find_iter is SET-WIDE non-overlapping while our gated find is
		// PER-PATTERN; pairing those directly would be confidently wrong.
		return "ra_bench_find_gated"
	}
	return ""
}

// setCase is one (set, input) row of the matrix.
type setCase struct {
	name     string
	patterns []string
	input    string
	inputLbl string
}

func main() {
	fuelOnly := flag.Bool("fuel", false, "print our fuel only (deterministic)")
	sizeOnly := flag.Bool("size", false, "print module sizes only")
	verify := flag.Bool("verify", false, "cross-engine correctness on the honest pairings")
	compareFuel := flag.String("compare-fuel", "", "compare our fuel against a baseline file; exit 1 on any change")
	compareSize := flag.String("compare-size", "", "compare module sizes against a baseline file; exit 1 on any change")
	flag.Parse()

	cases := buildMatrix()

	switch {
	case *compareFuel != "":
		os.Exit(runCompare(*compareFuel, cases, measureFuelRow, "fuel"))
	case *compareSize != "":
		os.Exit(runCompare(*compareSize, cases, measureSizeRow, "size"))
	case *fuelOnly:
		printRows(cases, measureFuelRow, "fuel")
		return
	case *sizeOnly:
		printRows(cases, measureSizeRow, "bytes")
		return
	case *verify:
		os.Exit(runVerify(cases))
	}
	runFullMatrix(cases)
}

// --------------------------------------------------------------------------
// The matrix.
//
// Set sizes cross the structural thresholds: 2 (trivial), 8, 32 (the
// per-bucket bitmask width), 64 and 128 (the <=64 / >64 `_all` split).

func buildMatrix() []setCase {
	var out []setCase
	for _, n := range []int{2, 8, 32, 64, 128} {
		pats := keywordPatterns(n)
		out = append(out,
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusNoMatch(), "no-match 100KB"},
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusSparse(pats), "sparse 100KB"},
			setCase{fmt.Sprintf("keywords-%d", n), pats, corpusDense(pats), "dense 100KB"},
		)
	}
	// A literal-anchored set, the shape §9.8 wants the "~1x from gating"
	// claim measured on.
	secrets := []string{
		`AKIA[A-Z0-9]{16}`,
		`ghp_[A-Za-z0-9]{36}`,
		`sk_live_[A-Za-z0-9]{24}`,
		`eyJ[A-Za-z0-9_-]{20,}`,
	}
	out = append(out,
		setCase{"secrets-4", secrets, corpusNoMatch(), "no-match 100KB"},
		setCase{"secrets-4", secrets, corpusSparse(secrets), "sparse 100KB"},
	)
	// A set with no mandatory literal at all: every position is visited, so
	// this is where gating has the most to recover.
	greedy := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	out = append(out,
		setCase{"greedy-3", greedy, strings.Repeat("a", 50000), "50K a's"},
		setCase{"greedy-3", greedy, corpusNoMatch(), "no-match 100KB"},
	)
	return out
}

func keywordPatterns(n int) []string {
	pats := make([]string, n)
	for i := 0; i < n; i++ {
		pats[i] = fmt.Sprintf("kw%03d[0-9a-z]{3}", i)
	}
	return pats
}

// corpusNoMatch is 100KB of filler none of the patterns can match.
func corpusNoMatch() string {
	var b strings.Builder
	line := "the quick brown fox jumps over the lazy dog 0123456789 "
	for b.Len() < 100*1024 {
		b.WriteString(line)
	}
	return b.String()
}

// corpusSparse plants a handful of matches in otherwise inert filler.
func corpusSparse(pats []string) string {
	base := corpusNoMatch()
	needles := sampleNeedles(pats, 5)
	step := len(base) / (len(needles) + 1)
	var b strings.Builder
	for i, nd := range needles {
		b.WriteString(base[i*step : (i+1)*step])
		b.WriteString(nd)
	}
	b.WriteString(base[len(needles)*step:])
	return b.String()
}

// corpusDense plants a match roughly every 40 bytes.
func corpusDense(pats []string) string {
	needles := sampleNeedles(pats, len(pats))
	filler := "..... filler ..... "
	var b strings.Builder
	for i := 0; b.Len() < 100*1024; i++ {
		b.WriteString(filler)
		b.WriteString(needles[i%len(needles)])
		b.WriteString(" ")
	}
	return b.String()
}

// sampleNeedles produces a concrete matching string for each of up to k
// patterns. It only understands the shapes buildMatrix uses.
func sampleNeedles(pats []string, k int) []string {
	if k > len(pats) {
		k = len(pats)
	}
	out := make([]string, 0, k)
	for i := 0; i < k; i++ {
		switch p := pats[i]; {
		case strings.HasPrefix(p, "kw"):
			out = append(out, p[:5]+"abc")
		case strings.HasPrefix(p, "AKIA"):
			out = append(out, "AKIAIOSFODNN7EXAMPLE")
		case strings.HasPrefix(p, "ghp_"):
			out = append(out, "ghp_"+strings.Repeat("A", 36))
		case strings.HasPrefix(p, "sk_live_"):
			out = append(out, "sk_live_"+strings.Repeat("B", 24))
		case strings.HasPrefix(p, "eyJ"):
			out = append(out, "eyJ"+strings.Repeat("C", 24))
		case p == `a+`:
			out = append(out, "aaaa")
		case strings.Contains(p, "ERROR"):
			out = append(out, "ERROR")
		default:
			out = append(out, "xy")
		}
	}
	return out
}

// --------------------------------------------------------------------------
// regexped side.

// compileCase compiles one set exporting every capability. `overlapping`
// selects which find body is emitted; the other six are unaffected.
func compileCase(c setCase, overlapping bool) ([]byte, error) {
	entries := make([]config.RegexEntry, len(c.patterns))
	names := make([]string, len(c.patterns))
	for i, p := range c.patterns {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Match:       "cap_match",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		Scan:        "cap_scan",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	return w, err
}

// rxInstance is an instantiated regexped module with its memory layout.
type rxInstance struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	inBase   int32
	outPtr   int32
	gatePtr  int32
	bitmapPt int32
	npat     int32
	inLen    int32
}

func newRxInstance(engine *wasmtime.Engine, wasm []byte, c setCase, withFuel bool) (*rxInstance, error) {
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	if withFuel {
		if err := store.SetFuel(fuelBudget); err != nil {
			return nil, err
		}
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, err
	}
	exp := inst.GetExport(store, "memory")
	if exp == nil {
		return nil, fmt.Errorf("module has no memory export")
	}
	mem := exp.Memory()

	dataTop, err := utils.ParseDataSectionBytes(wasm)
	if err != nil {
		return nil, err
	}
	npat := int32(len(c.patterns))
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(c.input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	outPtr := inBase + span
	gatePtr := outPtr + npat*12
	bitmapPt := gatePtr + npat*4
	top := int64(bitmapPt) + int64(npat)/8 + 4096
	needed := uint64((top + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			return nil, err
		}
	}
	copy(mem.UnsafeData(store)[inBase:], c.input)
	runtime.KeepAlive(store)
	return &rxInstance{
		store: store, inst: inst, mem: mem,
		inBase: inBase, outPtr: outPtr, gatePtr: gatePtr, bitmapPt: bitmapPt,
		npat: npat, inLen: int32(len(c.input)),
	}, nil
}

// zeroBitmap clears the >64-pattern bitmap before a wide `_all` call.
//
// The wide body only ORs hit bits in and counts 0->1 transitions, so it
// REQUIRES an all-zero bitmap on entry — every generated stub zeroes one
// (Rust [0u8; N], JS .fill(0), Go a fresh slice, C = {0}). Measuring without
// zeroing meant the warm-up call set every bit and each measured call then
// skipped the store-and-count branch for every already-set pattern, so the
// recorded fuel described a code path no real caller executes
// (plans/SETS.md §11 R7).
func (r *rxInstance) zeroBitmap() {
	buf := r.mem.UnsafeData(r.store)
	n := (r.npat + 7) / 8
	for i := int32(0); i < n; i++ {
		buf[r.bitmapPt+i] = 0
	}
}

// call runs one whole-input operation for the given capability, exactly as a
// caller would: the `_all` pair once, the boolean and `_any` pair once, and
// `find` driven to exhaustion.
func (r *rxInstance) call(c capability, wide bool) error {
	fn := r.inst.GetFunc(r.store, exportName(c))
	if fn == nil {
		return fmt.Errorf("missing export %s", exportName(c))
	}
	switch c {
	case capMatch, capMatchAny:
		_, err := fn.Call(r.store, r.inBase, r.inLen)
		return err
	case capMatchAll:
		if wide {
			r.zeroBitmap()
			_, err := fn.Call(r.store, r.inBase, r.inLen, r.bitmapPt)
			return err
		}
		_, err := fn.Call(r.store, r.inBase, r.inLen)
		return err
	case capScan, capScanAny:
		_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0))
		return err
	case capScanAll:
		if wide {
			r.zeroBitmap()
			_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0), r.bitmapPt)
			return err
		}
		_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0))
		return err
	case capFind:
		return r.exhaustFind(fn, true)
	case capFindOverlapping:
		return r.exhaustFind(fn, false)
	}
	return fmt.Errorf("unknown capability %q", c)
}

// exhaustFind drives `find` to exhaustion the way a generated iterator does.
func (r *rxInstance) exhaustFind(fn *wasmtime.Func, gated bool) error {
	if gated {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < r.npat*4; i++ {
			buf[r.gatePtr+i] = 0
		}
		runtime.KeepAlive(r.store)
	}
	from := int32(0)
	for {
		var res interface{}
		var err error
		if gated {
			res, err = fn.Call(r.store, r.inBase, r.inLen, from, r.gatePtr, r.outPtr, r.npat)
		} else {
			res, err = fn.Call(r.store, r.inBase, r.inLen, from, r.outPtr, r.npat)
		}
		if err != nil {
			return err
		}
		if res.(int32) <= 0 {
			return nil
		}
		buf := r.mem.UnsafeData(r.store)
		start := int32(binary.LittleEndian.Uint32(buf[int(r.outPtr)+4:]))
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

// --------------------------------------------------------------------------
// Measurement.

type row struct {
	key   string
	value uint64
}

func rowKey(c setCase, cap capability) string {
	return c.name + "|" + c.inputLbl + "|" + string(cap)
}

func measureFuelRow(c setCase) []row {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	var out []row
	for _, cap := range allCaps {
		overlapping := cap == capFindOverlapping
		wasm, err := compileCase(c, overlapping)
		if err != nil {
			continue
		}
		r, err := newRxInstance(engine, wasm, c, true)
		if err != nil {
			continue
		}
		wide := r.npat > 64
		// Warm-up call, uncounted: the first call pays lazy compilation.
		_ = r.call(cap, wide)
		if err := r.store.SetFuel(fuelBudget); err != nil {
			continue
		}
		before, _ := r.store.GetFuel()
		if err := r.call(cap, wide); err != nil {
			continue
		}
		after, _ := r.store.GetFuel()
		out = append(out, row{rowKey(c, cap), before - after})
	}
	return out
}

func measureSizeRow(c setCase) []row {
	var out []row
	for _, overlapping := range []bool{false, true} {
		wasm, err := compileCase(c, overlapping)
		if err != nil {
			continue
		}
		label := "module(gated)"
		if overlapping {
			label = "module(overlapping)"
		}
		out = append(out, row{rowKey(c, capability(label)), uint64(len(wasm))})
	}
	return out
}

// measureTime returns the p50 of benchIters whole-input operations.
func measureTime(engine *wasmtime.Engine, c setCase, cap capability) (time.Duration, error) {
	wasm, err := compileCase(c, cap == capFindOverlapping)
	if err != nil {
		return 0, err
	}
	r, err := newRxInstance(engine, wasm, c, false)
	if err != nil {
		return 0, err
	}
	wide := r.npat > 64
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if err := r.call(cap, wide); err != nil {
			return 0, err
		}
	}
	samples := make([]time.Duration, benchIters)
	for i := range samples {
		t0 := time.Now()
		if err := r.call(cap, wide); err != nil {
			return 0, err
		}
		samples[i] = time.Since(t0)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// --------------------------------------------------------------------------
// regex-automata side.

type raHarness struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	inputPtr int32
	timings  int32
	outPtr   int32
}

func newRaHarness(engine *wasmtime.Engine, wasm []byte, c setCase) (*raHarness, error) {
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return nil, err
	}
	inst, err := linker.Instantiate(store, mod)
	if err != nil {
		return nil, err
	}
	mem := inst.GetExport(store, "memory").Memory()

	get := func(name string) (int32, error) {
		fn := inst.GetFunc(store, name)
		if fn == nil {
			return 0, fmt.Errorf("harness missing %s", name)
		}
		v, err := fn.Call(store)
		if err != nil {
			return 0, err
		}
		return v.(int32), nil
	}
	patPtr, err := get("get_set_patterns_ptr")
	if err != nil {
		return nil, err
	}
	inputPtr, err := get("get_input_ptr")
	if err != nil {
		return nil, err
	}
	timings, err := get("get_timings_ptr")
	if err != nil {
		return nil, err
	}
	outPtr, err := get("ra_out_ptr")
	if err != nil {
		return nil, err
	}

	joined := strings.Join(c.patterns, "\n")
	buf := mem.UnsafeData(store)
	copy(buf[patPtr:], joined)
	copy(buf[inputPtr:], c.input)
	runtime.KeepAlive(store)

	initFn := inst.GetFunc(store, "ra_set_init")
	if initFn == nil {
		return nil, fmt.Errorf("harness missing ra_set_init")
	}
	res, err := initFn.Call(store, int32(len(joined)))
	if err != nil {
		return nil, err
	}
	if res.(int32) == 0 {
		return nil, fmt.Errorf("regex-automata rejected the pattern set")
	}
	return &raHarness{store: store, inst: inst, mem: mem, inputPtr: inputPtr, timings: timings, outPtr: outPtr}, nil
}

// bench runs the named regex-automata bench export and returns its p50.
func (h *raHarness) bench(name string, inputLen int) (time.Duration, error) {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		return 0, fmt.Errorf("harness missing %s", name)
	}
	// The harness times each iteration internally and writes ns to TIMINGS_BUF.
	const iters = 2000
	if _, err := fn.Call(h.store, int32(inputLen), int32(200)); err != nil {
		return 0, err // warm-up
	}
	if _, err := fn.Call(h.store, int32(inputLen), int32(iters)); err != nil {
		return 0, err
	}
	buf := h.mem.UnsafeData(h.store)
	vals := make([]uint32, iters)
	for i := range vals {
		vals[i] = binary.LittleEndian.Uint32(buf[int(h.timings)+i*4:])
	}
	runtime.KeepAlive(h.store)
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return time.Duration(vals[len(vals)/2]), nil
}

// --------------------------------------------------------------------------
// Output.

func harnessPath() string {
	dir, _ := os.Getwd()
	return filepath.Join(dir, "..", "perftest", "regex_bench", "target", "wasm32-wasip1", "release", "regex_bench.wasm")
}

func runFullMatrix(cases []setCase) {
	raBytes, err := os.ReadFile(harnessPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the regex-automata harness (run 'make harnesses' in ../perftest): %v\n", err)
		os.Exit(1)
	}
	engine := wasmtime.NewEngine()
	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := wasmtime.NewEngineWithConfig(fuelCfg)

	fmt.Println("setperf — regexped set capabilities vs regex-automata")
	fmt.Println(strings.Repeat("─", 96))
	fmt.Println("Fuel is EXACT within an engine and indicative ACROSS engines; wall-clock is")
	fmt.Println("placement noise on this machine — compare the ratio, not the absolute.")
	fmt.Println()

	for _, c := range cases {
		fmt.Printf("\n=== %s / %s (%d patterns, %d bytes) ===\n", c.name, c.inputLbl, len(c.patterns), len(c.input))
		gated, err := compileCase(c, false)
		if err != nil {
			fmt.Printf("  compile failed: %v\n", err)
			continue
		}
		over, _ := compileCase(c, true)
		fmt.Printf("  module: gated %d B, overlapping %d B, regex-automata harness %d B (whole engine)\n",
			len(gated), len(over), len(raBytes))

		ra, raErr := newRaHarness(engine, raBytes, c)
		fuel := map[string]uint64{}
		for _, r := range measureFuelRow(c) {
			fuel[r.key] = r.value
		}

		fmt.Printf("  %-18s %12s %12s %12s %9s\n", "capability", "our fuel", "our p50", "theirs p50", "ratio")
		fmt.Println("  " + strings.Repeat("─", 68))
		for _, cap := range allCaps {
			ours, err := measureTime(engine, c, cap)
			if err != nil {
				fmt.Printf("  %-18s %12s %12s %12s %9s\n", cap, "-", "error", "-", "-")
				continue
			}
			f := fmtFuel(fuel[rowKey(c, cap)])
			pairing := raPairing(cap)
			if pairing == "" || raErr != nil {
				note := "no comparison"
				if raErr != nil {
					note = "harness error"
				}
				fmt.Printf("  %-18s %12s %12s %12s %9s\n", cap, f, fmtDur(ours), note, "-")
				continue
			}
			theirs, err := ra.bench(pairing, len(c.input))
			if err != nil {
				fmt.Printf("  %-18s %12s %12s %12s %9s\n", cap, f, fmtDur(ours), "error", "-")
				continue
			}
			ratio := "-"
			if ours > 0 && theirs > 0 {
				ratio = fmt.Sprintf("%.2fx", float64(theirs)/float64(ours))
			}
			fmt.Printf("  %-18s %12s %12s %12s %9s\n", cap, f, fmtDur(ours), fmtDur(theirs), ratio)
		}
		_ = fuelEngine
	}
}

func printRows(cases []setCase, measure func(setCase) []row, unit string) {
	for _, c := range cases {
		for _, r := range measure(c) {
			fmt.Printf("%s = %d %s\n", r.key, r.value, unit)
		}
	}
}

// runCompare checks every measured row against a baseline file. Both fuel and
// module size are deterministic, so the comparison is EXACT: a change is a
// change, and it must be attributed rather than absorbed into a tolerance.
func runCompare(path string, cases []setCase, measure func(setCase) []row, unit string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read baseline %s: %v\n", path, err)
		return 1
	}
	base := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.Index(line, " = ")
		if i < 0 {
			continue
		}
		key := line[:i]
		rest := strings.Fields(line[i+3:])
		if len(rest) == 0 {
			continue
		}
		v, err := strconv.ParseUint(rest[0], 10, 64)
		if err != nil {
			continue
		}
		base[key] = v
	}
	bad := 0
	for _, c := range cases {
		for _, r := range measure(c) {
			want, ok := base[r.key]
			if !ok {
				fmt.Fprintf(os.Stderr, "  no baseline for %q\n", r.key)
				continue
			}
			if want != r.value {
				fmt.Fprintf(os.Stderr, "REGRESSION %s: baseline=%d current=%d %s\n", r.key, want, r.value, unit)
				bad++
			}
		}
	}
	if bad > 0 {
		return 1
	}
	fmt.Printf("All %s baselines match exactly.\n", unit)
	return 0
}

// --------------------------------------------------------------------------
// Cross-engine correctness (§9.9's secondary mode).
//
// On the pairings marked honest, running both engines over the same inputs
// yields a THIRD independent implementation to check against — strengthening
// the §9.6.1 story for multi-pattern interleaving, which Go's FindAllIndex
// union covers by construction rather than by an independent engine. It is a
// separate mode from the perf path so a semantic mismatch can never quietly
// corrupt the numbers.

func runVerify(cases []setCase) int {
	raBytes, err := os.ReadFile(harnessPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the regex-automata harness (run 'make harnesses' in ../perftest): %v\n", err)
		return 1
	}
	engine := wasmtime.NewEngine()
	bad := 0
	for _, c := range cases {
		ra, err := newRaHarness(engine, raBytes, c)
		if err != nil {
			fmt.Printf("SKIP %s/%s: %v\n", c.name, c.inputLbl, err)
			continue
		}
		wasm, err := compileCase(c, false)
		if err != nil {
			fmt.Printf("SKIP %s/%s: compile: %v\n", c.name, c.inputLbl, err)
			continue
		}
		r, err := newRxInstance(engine, wasm, c, false)
		if err != nil {
			fmt.Printf("SKIP %s/%s: instantiate: %v\n", c.name, c.inputLbl, err)
			continue
		}
		wide := r.npat > 64

		// scan: a boolean, directly comparable.
		theirScan := raCallI32(ra, "ra_scan", int32(len(c.input)), 0)
		ourScan := rxCallI32(r, "cap_scan", r.inBase, r.inLen, 0)
		if (theirScan != 0) != (ourScan != 0) {
			fmt.Printf("MISMATCH %s/%s scan: ours=%d theirs=%d\n", c.name, c.inputLbl, ourScan, theirScan)
			bad++
		}

		// scan_any: the START must agree exactly; the id is unspecified when
		// several patterns match there, so only membership can be checked and
		// this tool does not have the oracle for that — the start is the part
		// that is a hard contract.
		theirAny := raCallI64(ra, "ra_scan_any", int32(len(c.input)), 0)
		ourAny := rxCallI64(r, "cap_scan_any", r.inBase, r.inLen, 0)
		if (theirAny < 0) != (ourAny < 0) {
			fmt.Printf("MISMATCH %s/%s scan_any presence: ours=%d theirs=%d\n", c.name, c.inputLbl, ourAny, theirAny)
			bad++
		} else if theirAny >= 0 && (theirAny>>32) != (ourAny>>32) {
			fmt.Printf("MISMATCH %s/%s scan_any start: ours=%d theirs=%d\n",
				c.name, c.inputLbl, ourAny>>32, theirAny>>32)
			bad++
		}

		// scan_all: exact set equality.
		theirIDs := raScanAllIDs(ra, int32(len(c.input)))
		ourIDs := rxScanAllIDs(r, wide)
		if !sameIDs(theirIDs, ourIDs) {
			fmt.Printf("MISMATCH %s/%s scan_all: ours=%v theirs=%v\n", c.name, c.inputLbl, ourIDs, theirIDs)
			bad++
		}
		fmt.Printf("ok   %s/%s\n", c.name, c.inputLbl)
	}
	if bad > 0 {
		fmt.Printf("\n%d mismatch(es)\n", bad)
		return 1
	}
	fmt.Println("\nregex-automata agrees on every honest pairing.")
	return 0
}

func raCallI32(h *raHarness, name string, args ...interface{}) int32 {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		return -1
	}
	v, err := fn.Call(h.store, args...)
	if err != nil {
		return -1
	}
	return v.(int32)
}

func raCallI64(h *raHarness, name string, args ...interface{}) int64 {
	fn := h.inst.GetFunc(h.store, name)
	if fn == nil {
		return -1
	}
	v, err := fn.Call(h.store, args...)
	if err != nil {
		return -1
	}
	return v.(int64)
}

func rxCallI32(r *rxInstance, name string, args ...interface{}) int32 {
	fn := r.inst.GetFunc(r.store, name)
	if fn == nil {
		return -1
	}
	v, err := fn.Call(r.store, args...)
	if err != nil {
		return -1
	}
	return v.(int32)
}

func rxCallI64(r *rxInstance, name string, args ...interface{}) int64 {
	fn := r.inst.GetFunc(r.store, name)
	if fn == nil {
		return -1
	}
	v, err := fn.Call(r.store, args...)
	if err != nil {
		return -1
	}
	return v.(int64)
}

func raScanAllIDs(h *raHarness, inputLen int32) []int {
	n := raCallI32(h, "ra_scan_all", inputLen, int32(0))
	buf := h.mem.UnsafeData(h.store)
	out := make([]int, 0, n)
	for i := int32(0); i < n; i++ {
		out = append(out, int(int32(binary.LittleEndian.Uint32(buf[int(h.outPtr)+int(i)*4:]))))
	}
	runtime.KeepAlive(h.store)
	sort.Ints(out)
	return out
}

func rxScanAllIDs(r *rxInstance, wide bool) []int {
	var out []int
	if wide {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i <= r.npat/8; i++ {
			buf[r.bitmapPt+i] = 0
		}
		runtime.KeepAlive(r.store)
		rxCallI32(r, "cap_scan_all", r.inBase, r.inLen, int32(0), r.bitmapPt)
		buf = r.mem.UnsafeData(r.store)
		for k := int32(0); k < r.npat; k++ {
			if buf[int(r.bitmapPt)+int(k)/8]&(1<<uint(k%8)) != 0 {
				out = append(out, int(k))
			}
		}
		runtime.KeepAlive(r.store)
		return out
	}
	mask := uint64(rxCallI64(r, "cap_scan_all", r.inBase, r.inLen, int32(0)))
	for k := int32(0); k < r.npat && k < 64; k++ {
		if mask&(1<<uint(k)) != 0 {
			out = append(out, int(k))
		}
	}
	return out
}

func sameIDs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --------------------------------------------------------------------------

func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "n/a"
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	case d >= time.Microsecond:
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	default:
		return fmt.Sprintf("%d ns", d.Nanoseconds())
	}
}

func fmtFuel(v uint64) string {
	if v == 0 {
		return "-"
	}
	s := strconv.FormatUint(v, 10)
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	return strings.Join(append([]string{s}, parts...), ",")
}
