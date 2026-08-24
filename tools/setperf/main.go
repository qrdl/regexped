// Command setperf compares every regexped set capability against
// `regex-automata`, the layer underneath the `regex` crate's facade.
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
// Wall-clock on this machine is instruction-placement noise; compare the
// ratio, averaged over several runs, or don't compare it at all.
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

	// callBoundFuel is the fuel below which a wall-clock ratio describes the
	// two HARNESSES rather than the two engines, so the ratio column is
	// suppressed.
	//
	// Our side times one Go→wasmtime Func.Call per sample; theirs loops
	// `iters` times INSIDE WASM and reports per-iteration nanoseconds. That
	// call costs ~4-7 us (measured independently in §10.5), which is fixed
	// per row. Every anchored row spends 52-58 WASM instructions — work that
	// cannot take 4 us — and duly printed "~0.02x", reading as a 50x loss on
	// capabilities where we are in fact spending almost nothing.
	//
	// 10,000 was chosen so the suppressed band is the one where the call
	// dominates: at roughly a nanosecond per instruction, 10K fuel is ~10 us
	// of real work, i.e. the first point at which the ~4-7 us call is a
	// minority of the sample. Rows above it print a ratio; rows below print
	// "call-bound" and still show both raw times.
	callBoundFuel = 10_000

	// overlappingTimedCap bounds the INPUT for the timed find(overlapping)
	// row only.
	//
	// That body is the deliberate every-start-position enumeration of §7.10,
	// so on a set with no mandatory literal it is O(n^2): greedy-3 over 50,000
	// 'a's is ~1.25 BILLION DFA steps for ONE exhaustion, and measureTime
	// wants benchIters of them. The default matrix therefore could not be run
	// to completion — which is the mechanical reason §9.9's cross-engine
	// numbers went unrecorded for the whole project (§13 F4/F5).
	//
	// Only the timed path is bounded. Fuel rows keep the full input: they do
	// one exhaustion, which completes, and bounding them would silently
	// change the committed fuel baselines. The consequence is that for a
	// capped row the fuel column and the time column describe different input
	// lengths, so the row is labelled to say so rather than quietly mixing
	// them.
	overlappingTimedCap = 2048

	// timedFuelCap is the fuel above which the TIMED run switches to the
	// shortened input (see overlappingTimedCap). benchIters samples of a row
	// this expensive is minutes to hours of wall time.
	//
	// §13 F4 blamed the unrunnable matrix on find(overlapping) alone. That was
	// the row it happened to be killed in; measuring showed the property is
	// not specific to that capability but to "must visit every start position
	// on a set with no mandatory literal", which on greedy-3 over 50,000 'a's
	// makes scan_all and find quadratic too — all three exhaust even the fuel
	// budget. Keying the bound on measured cost rather than on a capability
	// name covers whichever rows actually turn out to be quadratic.
	timedFuelCap = 50_000_000

	// fuelExhausted marks a row whose single measurement ran out of fuel.
	// Distinct from any real count, which is bounded by fuelBudget.
	fuelExhausted = ^uint64(0)
)

// capability names the exports, in a fixed order.
//
// `match` and `scan` are gone: TODO task 59 decision (2) retired them, since
// `match_any(...) >= 0` and `scan_any(...) >= 0` are exactly what they
// returned.
type capability string

const (
	capMatchAny capability = "match_any"
	capMatchAll capability = "match_all"
	capScanAny  capability = "scan_any"
	capScanAll  capability = "scan_all"
	capFind     capability = "find"
	// capFindBatch is §19's multi-position find, now requested with
	// `hints: [batch-find]` rather than declared (decision (11)). It is the row that makes the
	// `find` comparison an honest one: ra_bench_find_gated runs its WHOLE
	// enumeration inside ONE wasm call, while our `find` crosses the host
	// boundary once per position. find_batch crosses once per BUFFERFUL, so
	// the two sides finally differ by engine work rather than by call count.
	capFindBatch capability = "find_batch"
	// capFindOverlapping is the ungated `find`. regex-automata has no
	// equivalent — per-start-position enumeration is not a search it can
	// express — so it is measured but never compared.
	capFindOverlapping capability = "find(overlapping)"
)

var allCaps = []capability{
	capMatchAny, capMatchAll,
	capScanAny, capScanAll,
	capFind, capFindBatch, capFindOverlapping,
}

// batchCap is the tuple buffer the find_batch row is driven with, in matches.
// It is the default the generated stubs pick, so the row measures what a stub
// user actually gets rather than a best case tuned for the benchmark.
const batchCap = 256

// exportName is the WASM export each capability is compiled under.
func exportName(c capability) string {
	switch c {
	case capFindOverlapping:
		return "cap_find"
	case capFindBatch:
		// Synthesized from `find`'s name under the hint, not declared, so it
		// is derived through the same function the compiler and the six
		// generators use.
		return config.SetBatchExportName("cap_find")
	}
	return "cap_" + string(c)
}

// raPairing names the regex-automata export a capability is compared against,
// or "" when the pairing would be dishonest (§9.9's table).
func raPairing(c capability) string {
	switch c {
	case capScanAny:
		return "ra_bench_scan_any"
	case capScanAll:
		return "ra_bench_scan_all"
	case capMatchAny:
		return "ra_bench_match"
	case capMatchAll:
		return "ra_bench_match_all"
	case capFind:
		// Per-pattern find_iter merged — the same construction the
		// gated-find oracle uses. regex-automata's own multi-pattern
		// find_iter is SET-WIDE non-overlapping while our gated find is
		// PER-PATTERN; pairing those directly would be confidently wrong.
		return "ra_bench_find_gated"
	case capFindBatch:
		// The same pairing as `find`, and the fair one: both sides now make
		// O(matches / buffer) host crossings instead of one side making O(1)
		// and the other O(matches).
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
	// A set whose literals share NO first byte. Every keywords-* literal
	// starts 'k', so before this the matrix could not see the AC frontend's
	// first-byte prefilter at all: moving that prefilter from a per-byte
	// compare chain to Shufti cut this shape's scan fuel by 28% and moved
	// not one of the 146 committed rows. Prefix sharing
	// is also what decides AC's node count, so this is the shape that governs
	// the table budget too (§14.1, sharpening 1).
	diverse := make([]string, 32)
	for i := range diverse {
		diverse[i] = fmt.Sprintf("%cQ%03d[0-9a-z]{3}", "abcdefghijklmnopqrstuvwxyz0123456789"[i%36], i)
	}
	out = append(out,
		setCase{"diverse-32", diverse, corpusNoMatch(), "no-match 100KB"},
		setCase{"diverse-32", diverse, corpusSparse(diverse), "sparse 100KB"},
	)
	// A set whose patterns share one SUFFIX behind distinct literals. Every
	// other set here has a counted-class-chain suffix ([0-9a-z]{3} and
	// friends), which genSuffixWASM answers with SIMD and no table at all —
	// so nothing in the matrix built a suffix table to begin with, and
	// suffix-table dedup moved zero rows despite cutting these shapes'
	// modules by ~70%. An alternation suffix does build a
	// table, which is what makes this case load-bearing.
	shared := make([]string, 32)
	for i := range shared {
		shared[i] = fmt.Sprintf("kw%03d(?:alpha|beta|gamma)", i)
	}
	out = append(out,
		setCase{"sharedsuffix-32", shared, corpusNoMatch(), "no-match 100KB"},
		setCase{"sharedsuffix-32", shared, corpusSparse(shared), "sparse 100KB"},
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
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Hints:       []string{"batch-find"},
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
	batchPtr int32
	npat     int32
	inLen    int32
	// fnCache holds resolved exports. Resolving inside the timed loop meant
	// every measured operation paid a string-keyed export lookup that is
	// neither engine work nor the wasmtime crossing — pure harness cost, and
	// it inflated every one of our rows.
	fnCache map[capability]*wasmtime.Func
}

// fnFor resolves a capability's export once and caches it.
func (r *rxInstance) fnFor(c capability) *wasmtime.Func {
	if r.fnCache == nil {
		r.fnCache = make(map[capability]*wasmtime.Func, len(allCaps))
	}
	if fn, ok := r.fnCache[c]; ok {
		return fn
	}
	fn := r.inst.GetFunc(r.store, exportName(c))
	r.fnCache[c] = fn
	return fn
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
	// The batch buffer sits above the bitmap, 4 KB clear of it.
	batchPtr := bitmapPt + int32(npat)/8 + 4096
	top := int64(batchPtr) + int64(batchCap)*12 + 4096
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
		batchPtr: batchPtr,
		npat:     npat, inLen: int32(len(c.input)),
	}, nil
}

// zeroBitmap clears the >64-pattern bitmap before a wide `_all` call.
//
// The wide body only ORs hit bits in and counts 0->1 transitions, so it
// REQUIRES an all-zero bitmap on entry — every generated stub zeroes one
// (Rust [0u8; N], JS .fill(0), Go a fresh slice, C = {0}). Measuring without
// zeroing meant the warm-up call set every bit and each measured call then
// skipped the store-and-count branch for every already-set pattern, so the
// recorded fuel described a code path no real caller executes.
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
// call runs one whole-input operation and returns how many Go→wasmtime
// crossings it took. The count is what lets measureTime subtract the harness
// boundary cost: every crossing carries a fixed ~4 us that has nothing to do
// with the engine, and `find` pays one per match.
func (r *rxInstance) call(c capability, wide bool) (int, error) {
	fn := r.fnFor(c)
	if fn == nil {
		return 0, fmt.Errorf("missing export %s", exportName(c))
	}
	switch c {
	case capMatchAny:
		_, err := fn.Call(r.store, r.inBase, r.inLen)
		return 1, err
	case capMatchAll:
		if wide {
			r.zeroBitmap()
			_, err := fn.Call(r.store, r.inBase, r.inLen, r.bitmapPt)
			return 1, err
		}
		_, err := fn.Call(r.store, r.inBase, r.inLen)
		return 1, err
	case capScanAny:
		_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0))
		return 1, err
	case capScanAll:
		if wide {
			r.zeroBitmap()
			_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0), r.bitmapPt)
			return 1, err
		}
		_, err := fn.Call(r.store, r.inBase, r.inLen, int32(0))
		return 1, err
	case capFind:
		return r.exhaustFind(fn, true)
	case capFindBatch:
		return r.exhaustFindBatch(fn, true)
	case capFindOverlapping:
		return r.exhaustFind(fn, false)
	}
	return 0, fmt.Errorf("unknown capability %q", c)
}

// exhaustFind drives `find` to exhaustion the way a generated iterator does.
func (r *rxInstance) exhaustFind(fn *wasmtime.Func, gated bool) (int, error) {
	if gated {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < r.npat*4; i++ {
			buf[r.gatePtr+i] = 0
		}
		runtime.KeepAlive(r.store)
	}
	from := int32(0)
	calls := 0
	for {
		var res interface{}
		var err error
		calls++
		if gated {
			res, err = fn.Call(r.store, r.inBase, r.inLen, from, r.gatePtr, r.outPtr, r.npat)
		} else {
			res, err = fn.Call(r.store, r.inBase, r.inLen, from, r.outPtr, r.npat)
		}
		if err != nil {
			return calls, err
		}
		if res.(int32) <= 0 {
			return calls, nil
		}
		buf := r.mem.UnsafeData(r.store)
		start := int32(binary.LittleEndian.Uint32(buf[int(r.outPtr)+4:]))
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

// exhaustFindBatch drives `find_batch` to exhaustion the way a generated batch
// iterator does: start from cursor 0, hand the previous return value back
// unchanged, stop when its top 32 bits are all ones.
//
// The count field is not decoded here. The driver only needs to know when to
// stop, and reading the tuples would add harness work to a timed loop that is
// meant to measure the engine.
func (r *rxInstance) exhaustFindBatch(fn *wasmtime.Func, gated bool) (int, error) {
	if gated {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < r.npat*4; i++ {
			buf[r.gatePtr+i] = 0
		}
		runtime.KeepAlive(r.store)
	}
	cursor := int64(0)
	calls := 0
	for {
		var res interface{}
		var err error
		calls++
		if gated {
			res, err = fn.Call(r.store, r.inBase, r.inLen, cursor, r.gatePtr, r.batchPtr, int32(batchCap))
		} else {
			res, err = fn.Call(r.store, r.inBase, r.inLen, cursor, r.batchPtr, int32(batchCap))
		}
		if err != nil {
			return calls, err
		}
		packed := res.(int64)
		if uint32(packed>>32) == 0xFFFFFFFF {
			return calls, nil
		}
		cursor = packed
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
		_, _ = r.call(cap, wide)
		if err := r.store.SetFuel(fuelBudget); err != nil {
			continue
		}
		before, _ := r.store.GetFuel()
		if _, err := r.call(cap, wide); err != nil {
			// Almost always the fuel budget running out. Record that as a
			// SENTINEL rather than dropping the row: a bare `continue` here
			// is why greedy-3's scan_all/find/find(overlapping) had no fuel
			// number anywhere — the map lookup then yielded 0, and the matrix
			// printed "0 fuel" for the three most expensive rows it has.
			// printRows filters sentinels back out so
			// the baseline files keep their exact-equality format.
			out = append(out, row{rowKey(c, cap), fuelExhausted})
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

// timedCase returns the case to use for the TIMED measurement of cap, and
// whether the input was shortened.
//
// ourFuel is the measured fuel for this row, or fuelExhausted when the single
// measurement could not even complete. Rows are shortened on measured cost —
// see timedFuelCap for why capability name is the wrong key.
func timedCase(c setCase, cap capability, ourFuel uint64) (setCase, bool) {
	quadratic := ourFuel == fuelExhausted || ourFuel > timedFuelCap
	if !quadratic || len(c.input) <= overlappingTimedCap {
		return c, false
	}
	c.input = c.input[:overlappingTimedCap]
	return c, true
}

// measureTime returns the p50 of benchIters whole-input operations, together
// with the number of Go→wasmtime crossings one operation costs.
//
// The crossing count is not incidental: it is the correction term that makes
// this side comparable with the regex-automata side at all. Our sample
// brackets a host call; theirs is taken by the Rust
// harness INSIDE wasm, around the engine work alone. Subtracting
// crossings × callFloor from our p50 puts both on the same footing.
func measureTime(engine *wasmtime.Engine, c setCase, cap capability, ourFuel uint64) (time.Duration, int, time.Duration, error) {
	c, _ = timedCase(c, cap, ourFuel)
	wasm, err := compileCase(c, cap == capFindOverlapping)
	if err != nil {
		return 0, 0, 0, err
	}
	r, err := newRxInstance(engine, wasm, c, false)
	if err != nil {
		return 0, 0, 0, err
	}
	floor := measureInstanceFloor(r)
	wide := r.npat > 64
	calls := 0
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if calls, err = r.call(cap, wide); err != nil {
			return 0, 0, 0, err
		}
	}
	samples := make([]time.Duration, benchIters)
	for i := range samples {
		t0 := time.Now()
		n, err := r.call(cap, wide)
		if err != nil {
			return 0, 0, 0, err
		}
		samples[i] = time.Since(t0)
		calls = n
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], calls, floor, nil
}

// --------------------------------------------------------------------------
// The harness-boundary correction.

// measureInstanceFloor times a call into THIS module that does essentially no
// work: `cap_match` on a zero-length input, which enters the anchored probe
// and returns within a couple of instructions.
//
// Measuring the boundary on the real module rather than on a synthetic empty
// one matters. A hand-built noop module measured 2.0-3.0 us here with no
// ordering by arity — i.e. dominated by noise — and it under-reported: the
// cheapest real row in the matrix (greedy-3 / 50K a's / scan, 48 fuel, so
// arithmetically no work at all) samples at 3.8 us. Module size, memory
// footprint and the number of exports all move the crossing cost, so the
// floor is taken per instance, against the very module being timed.
//
// The floor uses the SAME estimator as the rows it corrects — p50 over
// benchIters samples, after an equal warm-up. That symmetry is the point: a
// min-of-rounds floor is biased low, and subtracting a low-biased floor from
// an unbiased p50 leaves a residual that looks like engine work but is not.
// Calibration check: with matched estimators the anchored rows, which do
// 54-60 fuel of work, correct to approximately zero.
func measureInstanceFloor(r *rxInstance) time.Duration {
	fn := r.fnFor(capMatchAny)
	if fn == nil {
		return 0
	}
	for end := time.Now().Add(50 * time.Millisecond); time.Now().Before(end); {
		if _, err := fn.Call(r.store, r.inBase, int32(0)); err != nil {
			return 0
		}
	}
	samples := make([]time.Duration, benchIters)
	for i := range samples {
		t0 := time.Now()
		if _, err := fn.Call(r.store, r.inBase, int32(0)); err != nil {
			return 0
		}
		samples[i] = time.Since(t0)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2]
}

// engineTime strips the harness boundary from a raw sample: one crossing per
// call the operation made. Clamped at zero — when the correction exceeds the
// sample the row was pure boundary, which is what call-bound means.
func engineTime(raw time.Duration, calls int, floor time.Duration) time.Duration {
	corrected := raw - time.Duration(calls)*floor
	if corrected < 0 {
		return 0
	}
	return corrected
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
	fmt.Println("BOTH SIDES ARE WASM: regex-automata is built for wasm32-wasip1 and runs in the")
	fmt.Println("same wasmtime engine. What differs is where the clock sits (§17.5). Our sample")
	fmt.Println("brackets a Go→wasmtime call; the Rust harness times itself INSIDE wasm. So our")
	fmt.Println("raw p50 carries one crossing per call — and `find` makes one call per match.")
	fmt.Println("`our engine` subtracts calls × the measured crossing cost for that arity, and")
	fmt.Println("the ratio is computed from it, so both columns describe engine work alone.")
	fmt.Printf("Ratios are still withheld below %d fuel (\"call-bound\"): once the correction\n", callBoundFuel)
	fmt.Println("is the bulk of the sample, what remains is measurement noise, not a result.")
	fmt.Printf("find(overlapping) is timed on at most %d bytes: it is the every-start-position\n", overlappingTimedCap)
	fmt.Println("enumeration, quadratic on literal-less sets, and blocks the matrix otherwise (F4).")
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

		fmt.Printf("  %-18s %12s %11s %7s %11s %11s %9s  %s\n",
			"capability", "our fuel", "our p50", "calls", "our engine", "theirs p50", "ratio", "note")
		fmt.Println("  " + strings.Repeat("─", 100))
		for _, cap := range allCaps {
			ourFuel := fuel[rowKey(c, cap)]
			ours, calls, floor, err := measureTime(engine, c, cap, ourFuel)
			if err != nil {
				fmt.Printf("  %-18s %12s %11s %7s %11s %11s %9s\n", cap, "-", "error", "-", "-", "-", "-")
				continue
			}
			ourEng := engineTime(ours, calls, floor)
			f := fmtFuel(ourFuel)
			// F4: say so when the timed input was shortened, because then this
			// row's fuel and time describe different input lengths.
			var note string
			if _, capped := timedCase(c, cap, ourFuel); capped {
				note = fmt.Sprintf("time on %dB input; fuel on %dB", overlappingTimedCap, len(c.input))
			}
			if ourFuel == fuelExhausted {
				f = "exhausted"
				note = fmt.Sprintf("one call exceeds the %s fuel budget; time on %dB input", fmtFuel(fuelBudget), overlappingTimedCap)
			}
			pairing := raPairing(cap)
			if pairing == "" || raErr != nil {
				reason := "no comparison"
				if raErr != nil {
					reason = "harness error"
				}
				fmt.Printf("  %-18s %12s %11s %7d %11s %11s %9s  %s\n",
					cap, f, fmtDur(ours), calls, fmtDur(ourEng), reason, "-", note)
				continue
			}
			theirs, err := ra.bench(pairing, len(c.input))
			if err != nil {
				fmt.Printf("  %-18s %12s %11s %7d %11s %11s %9s  %s\n",
					cap, f, fmtDur(ours), calls, fmtDur(ourEng), "error", "-", note)
				continue
			}
			// A ratio is printed only when both sides did comparable work.
			// F3: below callBoundFuel the sample is dominated by our harness's
			// per-call cost. F4: a shortened timed input means our time covers
			// a fraction of the bytes theirs does. Both print the raw times
			// and withhold only the ratio.
			_, capped := timedCase(c, cap, ourFuel)
			ratio := "-"
			switch {
			case capped:
				ratio = "input differs"
			case ourFuel > 0 && ourFuel < callBoundFuel:
				ratio = "call-bound"
				if note == "" {
					note = fmt.Sprintf("our work is %s fuel; ratio would measure harness call overhead", f)
				}
			case ourEng > 0 && theirs > 0:
				// Engine-vs-engine: both sides now exclude the host boundary.
				ratio = fmt.Sprintf("%.2fx", float64(theirs)/float64(ourEng))
			case ours > 0 && theirs > 0:
				// The correction consumed the whole sample — the row was
				// boundary, not engine. Say so rather than dividing by zero.
				ratio = "boundary"
				if note == "" {
					note = fmt.Sprintf("%d call(s) x %s crossing >= the %s sample",
						calls, fmtDur(floor), fmtDur(ours))
				}
			}
			fmt.Printf("  %-18s %12s %11s %7d %11s %11s %9s  %s\n",
				cap, f, fmtDur(ours), calls, fmtDur(ourEng), fmtDur(theirs), ratio, note)
		}
		_ = fuelEngine
	}
}

func printRows(cases []setCase, measure func(setCase) []row, unit string) {
	for _, c := range cases {
		for _, r := range measure(c) {
			if r.value == fuelExhausted {
				// Not a number, so it cannot join an exact-equality baseline.
				// Announced on stderr so `make baseline` (which redirects
				// stdout only) still shows the gap rather than hiding it.
				fmt.Fprintf(os.Stderr, "note: %s exceeded the %d fuel budget — no baseline row\n", r.key, uint64(fuelBudget))
				continue
			}
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
				if r.value == fuelExhausted {
					// printRows deliberately emits no line for a row over the
					// budget, so its absence is the expected state and not a
					// gap in coverage.
					fmt.Fprintf(os.Stderr, "  %s: exceeds the fuel budget, no baseline (expected)\n", r.key)
					continue
				}
				// Any other missing row IS a failure. This gate exists to
				// prove every measured row is unchanged; a row with nothing to
				// compare against was not checked, and letting it pass meant
				// an empty or stale baseline file could report success while
				// checking almost nothing.
				fmt.Fprintf(os.Stderr, "UNCHECKED %s: no baseline row (current=%d %s); re-run `make baseline` if the row is new\n",
					r.key, r.value, unit)
				bad++
				continue
			}
			if r.value == fuelExhausted {
				// Was measurable when the baseline was taken and is not now:
				// a real regression, but printing the sentinel as a number
				// would just look like corruption.
				fmt.Fprintf(os.Stderr, "REGRESSION %s: baseline=%d current=exceeds the %d %s budget\n", r.key, want, uint64(fuelBudget), unit)
				bad++
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

		// The anchored trio. regex-automata's Anchored::Yes over the whole
		// haystack is exactly our `match` contract, and Anchored::Pattern(k)
		// per pattern is exactly `match_all`'s, so both are honest pairings —
		// they were simply never wired up here, which left four of the seven
		// capabilities resting on `make sets` alone.
		//
		// Driven at several PREFIX LENGTHS rather than only at the full input.
		// Both sides take the haystack length as a parameter, so this costs no
		// restaging — and it is what makes the check bite. The corpora are
		// 100 KB scan haystacks, so "does a pattern match the whole thing" is
		// no on 22 of the 23 rows; comparing only that would be a check that
		// agrees because both sides say no, which is the failure mode this
		// whole block exists to fix. Short prefixes reach the anchored
		// automaton's real answers, and length 0 covers the empty input.
		anchoredMatches := 0
		for _, n := range anchoredLens(len(c.input)) {
			// `match` is retired (decision (2)); regex-automata's boolean is
			// still the oracle, now compared against match_any's sign.
			theirMatch := raCallI32(ra, "ra_match", int32(n))
			if theirMatch != 0 {
				anchoredMatches++
			}

			// match_all: exact set equality, and the oracle for match_any.
			theirMatchIDs := raAllIDs(ra, "ra_match_all", int32(n))
			ourMatchIDs := rxAllIDs(r, wide, "cap_match_all", int32(n))
			if !sameIDs(theirMatchIDs, ourMatchIDs) {
				fmt.Printf("MISMATCH %s/%s match_all@%d: ours=%v theirs=%v\n", c.name, c.inputLbl, n, ourMatchIDs, theirMatchIDs)
				bad++
			}

			// match_any: which id you get is unspecified when several patterns
			// match the whole input, so presence is the hard contract — but
			// unlike scan_any the id DOES have an oracle here, since
			// match_all's set is every legal answer.
			ourMatchAny := rxCallI32(r, "cap_match_any", r.inBase, int32(n))
			if (ourMatchAny >= 0) != (theirMatch != 0) {
				fmt.Printf("MISMATCH %s/%s match_any@%d presence: ours=%d theirs=%d\n", c.name, c.inputLbl, n, ourMatchAny, theirMatch)
				bad++
			} else if ourMatchAny >= 0 && !containsID(theirMatchIDs, int(ourMatchAny)) {
				fmt.Printf("MISMATCH %s/%s match_any@%d id: ours=%d, not in theirs=%v\n", c.name, c.inputLbl, n, ourMatchAny, theirMatchIDs)
				bad++
			}
		}

		// scan_any: PRESENCE only. TODO task 59 decision (10) removed the
		// start it used to report, and the id is unspecified when several
		// patterns match, so agreement on "did anything match" is the whole
		// contract this tool can check. regex-automata still returns a span,
		// so only the sign of its answer is comparable.
		theirAny := raCallI64(ra, "ra_scan_any", int32(len(c.input)), 0)
		ourAny := int64(rxCallI32(r, "cap_scan_any", r.inBase, r.inLen, 0))
		if (theirAny < 0) != (ourAny < 0) {
			fmt.Printf("MISMATCH %s/%s scan_any presence: ours=%d theirs=%d\n", c.name, c.inputLbl, ourAny, theirAny)
			bad++
		}

		// scan_all: exact set equality.
		theirIDs := raAllIDs(ra, "ra_scan_all", int32(len(c.input)), int32(0))
		ourIDs := rxAllIDs(r, wide, "cap_scan_all", r.inLen, int32(0))
		if !sameIDs(theirIDs, ourIDs) {
			fmt.Printf("MISMATCH %s/%s scan_all: ours=%v theirs=%v\n", c.name, c.inputLbl, ourIDs, theirIDs)
			bad++
		}

		// find (gated, the default body): ra_find_gated is the per-pattern
		// merged find_iter — the same construction the gated-find oracle
		// uses, and the one raPairing already trusts for the fuel rows. This
		// is the only capability here whose EXTENTS are checked, not just its
		// ids, which is why leaving it out mattered.
		ourFind := rxCollectFind(r)
		if theirFind, complete := raFindGated(ra, int32(len(c.input))); !complete {
			// The harness buffer is fixed, and ra_find_gated truncates rather
			// than growing it. A truncated list is not a smaller answer, so
			// comparing it would manufacture a mismatch.
			fmt.Printf("SKIP %s/%s find: regex-automata output buffer full at %d tuples\n",
				c.name, c.inputLbl, len(theirFind))
		} else if !sameMatches(theirFind, ourFind) {
			fmt.Printf("MISMATCH %s/%s find: ours=%d matches, theirs=%d\n",
				c.name, c.inputLbl, len(ourFind), len(theirFind))
			bad++
		}

		// find vs find_batch: the two are independent bodies over shared
		// suffix functions and must report the identical multiset. The
		// regex-automata pairing above bounds `find` itself; this one is
		// internal because there is no pairing for the BATCHED shape, and it
		// is what exercises §19's split-position resume, since batchCap is
		// deliberately not "big enough for one call".
		ourBatch := rxCollectFindBatch(r)
		if !sameMatches(ourFind, ourBatch) {
			fmt.Printf("MISMATCH %s/%s find vs find_batch: find=%d matches, batch=%d\n",
				c.name, c.inputLbl, len(ourFind), len(ourBatch))
			bad++
		}

		// The anchored hit count is printed, not just tallied: a row where no
		// prefix matches proves only that both engines said no, and that is
		// worth seeing rather than hiding behind "ok".
		fmt.Printf("ok   %s/%s (anchored: %d/%d prefixes match, find: %d matches)\n",
			c.name, c.inputLbl, anchoredMatches, len(anchoredLens(len(c.input))), len(ourFind))
	}
	if bad > 0 {
		fmt.Printf("\n%d mismatch(es)\n", bad)
		return 1
	}
	fmt.Println("\nregex-automata agrees on every honest pairing.")
	return 0
}

// setTuple is one (pattern id, start, end) triple read back from a find or
// find_batch buffer.
type setTuple struct{ id, start, end int32 }

// rxCollectFind drives the gated `find` to exhaustion and returns every tuple.
func rxCollectFind(r *rxInstance) []setTuple {
	fn := r.inst.GetFunc(r.store, "cap_find")
	if fn == nil {
		return nil
	}
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	runtime.KeepAlive(r.store)
	var out []setTuple
	from := int32(0)
	for {
		res, err := fn.Call(r.store, r.inBase, r.inLen, from, r.gatePtr, r.outPtr, r.npat)
		if err != nil {
			return out
		}
		n := res.(int32)
		if n <= 0 {
			return out
		}
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < n && i < r.npat; i++ {
			base := int(r.outPtr) + int(i)*12
			out = append(out, setTuple{
				int32(binary.LittleEndian.Uint32(buf[base:])),
				int32(binary.LittleEndian.Uint32(buf[base+4:])),
				int32(binary.LittleEndian.Uint32(buf[base+8:])),
			})
		}
		start := int32(binary.LittleEndian.Uint32(buf[int(r.outPtr)+4:]))
		runtime.KeepAlive(r.store)
		from = start + 1
	}
}

// rxCollectFindBatch drives `find_batch` to exhaustion and returns every tuple.
func rxCollectFindBatch(r *rxInstance) []setTuple {
	fn := r.inst.GetFunc(r.store, "cap_find_batch")
	if fn == nil {
		return nil
	}
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < r.npat*4; i++ {
		buf[r.gatePtr+i] = 0
	}
	runtime.KeepAlive(r.store)
	countMask := int64(1)<<uint(config.SetCursorCountBits(int(r.npat))) - 1
	var out []setTuple
	cursor := int64(0)
	for {
		res, err := fn.Call(r.store, r.inBase, r.inLen, cursor, r.gatePtr, r.batchPtr, int32(batchCap))
		if err != nil {
			return out
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i < n; i++ {
			base := int(r.batchPtr) + int(i)*12
			out = append(out, setTuple{
				int32(binary.LittleEndian.Uint32(buf[base:])),
				int32(binary.LittleEndian.Uint32(buf[base+4:])),
				int32(binary.LittleEndian.Uint32(buf[base+8:])),
			})
		}
		runtime.KeepAlive(r.store)
		if uint32(packed>>32) == 0xFFFFFFFF || n == 0 {
			return out
		}
		cursor = packed
	}
}

// sameMatches compares two tuple lists as multisets. Within-call tuple order
// is unspecified, so order must not be part of the test.
func sameMatches(a, b []setTuple) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(v []setTuple) []setTuple {
		c := append([]setTuple(nil), v...)
		sort.Slice(c, func(i, j int) bool {
			if c[i].id != c[j].id {
				return c[i].id < c[j].id
			}
			if c[i].start != c[j].start {
				return c[i].start < c[j].start
			}
			return c[i].end < c[j].end
		})
		return c
	}
	x, y := key(a), key(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
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

// raAllIDs decodes an `_all` answer from the regex-automata harness, which
// writes ids to RA_OUT_BUF and returns the count. `export` is "ra_scan_all"
// (which takes a `from`, passed in extra) or "ra_match_all" (which does not).
func raAllIDs(h *raHarness, export string, args ...interface{}) []int {
	n := raCallI32(h, export, args...)
	buf := h.mem.UnsafeData(h.store)
	out := make([]int, 0, n)
	for i := int32(0); i < n; i++ {
		out = append(out, int(int32(binary.LittleEndian.Uint32(buf[int(h.outPtr)+int(i)*4:]))))
	}
	runtime.KeepAlive(h.store)
	sort.Ints(out)
	return out
}

// rxAllIDs decodes one of our `_all` capabilities into an ascending id list.
// `export` is "cap_scan_all" (whose `from` goes in extra) or "cap_match_all".
// Both ABI forms are handled: an i64 bitmask return, or the >64-id out_ptr
// bitmap, which the caller must zero because the module only sets bits.
func rxAllIDs(r *rxInstance, wide bool, export string, inLen int32, extra ...interface{}) []int {
	args := append([]interface{}{r.inBase, inLen}, extra...)
	var out []int
	if wide {
		buf := r.mem.UnsafeData(r.store)
		for i := int32(0); i <= r.npat/8; i++ {
			buf[r.bitmapPt+i] = 0
		}
		runtime.KeepAlive(r.store)
		rxCallI32(r, export, append(args, r.bitmapPt)...)
		buf = r.mem.UnsafeData(r.store)
		for k := int32(0); k < r.npat; k++ {
			if buf[int(r.bitmapPt)+int(k)/8]&(1<<uint(k%8)) != 0 {
				out = append(out, int(k))
			}
		}
		runtime.KeepAlive(r.store)
		return out
	}
	mask := uint64(rxCallI64(r, export, args...))
	for k := int32(0); k < r.npat && k < 64; k++ {
		if mask&(1<<uint(k)) != 0 {
			out = append(out, int(k))
		}
	}
	return out
}

// raOutTuples is how many (id, start, end) triples RA_OUT_BUF holds. Keep it in
// step with automata.rs — ra_find_gated silently stops filling at this count
// rather than growing, so a returned count of exactly this is "at least this
// many", not "this many".
const raOutTuples = 65536

// raFindGated collects regex-automata's per-pattern merged enumeration, the
// pairing for our default gated `find`. complete is false when the harness
// buffer filled, in which case the tuples are a prefix and cannot be compared.
func raFindGated(h *raHarness, inputLen int32) (tuples []setTuple, complete bool) {
	n := raCallI32(h, "ra_find_gated", inputLen, int32(0))
	buf := h.mem.UnsafeData(h.store)
	out := make([]setTuple, 0, n)
	for i := int32(0); i < n; i++ {
		base := int(h.outPtr) + int(i)*12
		out = append(out, setTuple{
			int32(binary.LittleEndian.Uint32(buf[base:])),
			int32(binary.LittleEndian.Uint32(buf[base+4:])),
			int32(binary.LittleEndian.Uint32(buf[base+8:])),
		})
	}
	runtime.KeepAlive(h.store)
	return out, n < raOutTuples
}

// anchoredLens returns the prefix lengths the anchored trio is compared at.
//
// Small lengths first, because "the whole input matches" is what the anchored
// capabilities answer and a 100 KB scan corpus is not that: the short prefixes
// are where the anchored automaton actually returns yes, and 0 covers the empty
// input. The tail lengths keep the full-input case and one interior point.
func anchoredLens(n int) []int {
	var out []int
	for _, k := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 32, 64, n / 2, n} {
		if k >= 0 && k <= n && (len(out) == 0 || k != out[len(out)-1]) {
			out = append(out, k)
		}
	}
	return out
}

// containsID reports whether an ascending id list holds id.
func containsID(ids []int, id int) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
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
