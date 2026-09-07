// lentest — the length-sweep harness.
//
// Every SIMD mechanism regexped emits is gated on 16 to 33 bytes of remaining
// input, and every crossover, budget and period around them was calibrated on a
// 50 KB or 100 KB corpus. Nothing in the tree measures a SHORT input: every
// likelytest input is 50 KB, every setperf corpus is 100 KB, and perftest's
// short anchored rows carry no SIMD channel at all. On an input shorter than
// one chunk those mechanisms cannot execute, so they are pure cost with nothing
// to amortise over — and the pattern carries no signal about it, because the
// win case and the harm case of a given channel compile the identical pattern.
// Only the caller knows, which is what CompileOptions.InputLength is for.
//
// # What this measures that the other harnesses cannot
//
// likelytest varies MODE at a fixed input and prints three cells. What is
// needed here is two-dimensional — the length the caller DECLARED against the
// length they actually passed:
//
//	            actual 8 B   32 B   256 B   1 KB   16 KB   100 KB
//	(unset)       base       base   base    base   base    base
//	declared 16   win?        ?      ?       ?     harm?   harm?
//	declared 64    ?          ?      ?       ?      ?       ?
//
// The top-left is the win, the right-hand side of a small declaration is the
// mispredict harm, and the cells between are the gradient. That gradient is the
// number the plan's contract ("an expectation, never a promise") is currently
// asserted without, and neither likelytest's hard-wired [3]LikelyMode matrix nor
// settest's modeNames[3] can produce it.
//
// # Reading the output
//
// Fuel is the gate: it is deterministic, so a difference is a real difference.
// Wall-clock p50 is informative only — instruction placement on the development
// machine swings timings by tens of percent between runs of identical bytes, so
// a time column that moves while fuel does not is noise, not signal.
//
// When a declared build is byte-identical to the unset build the row prints
// `identical WASM` and is not measured at all. That is the common case while a
// mechanism is still unwired, and it is the honest report: comparing wall-clock
// across identical bytes measures the machine, not the change.
//
// # Status
//
// CompileOptions.InputLength and CompileSetOptions.InputLength exist but NO
// emitter consumes them yet, so today every declared value produces an
// identical module and every row short-circuits. That is deliberate: the tool
// comes first so that each mechanism wired to the hint has a before and an
// after from the same instrument, rather than an instruction count read off an
// emitter. Two such counts have already proved wrong in opposite directions —
// one 12x too optimistic because a runtime predicate gated the code, one too
// pessimistic because the emission ran ~4.5 times per call.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// Memory layout, identical to likelytest's so the two can be compared directly.
const (
	inputBase  = int32(0)
	slotsBase  = int32(65536)  // page 1: clear of input (up to 64 KiB at offset 0)
	tableBase  = int64(131072) // page 2; pages 0-1 reserved for input + slots
	fuelBudget = uint64(10_000_000_000)
)

// timeIters is the number of host-side repetitions per timing cell.
//
// Deliberately NOT the in-WASM shim likelytest uses. The shortest cells here are
// a few hundred fuel — tens of nanoseconds — and the whole point is to compare
// them against 100 KB cells in the same table, so the harness must drive the
// real export the same way at both ends rather than switching instruments
// halfway. p50 over this many host calls is stable enough to read while staying
// honest about what it is: informative, never a gate.
const timeIters = 2000

type driveMode int

const (
	modeFind driveMode = iota
	modeAnchored
	modeGroups
	modeSet
)

func (m driveMode) String() string {
	switch m {
	case modeAnchored:
		return "match"
	case modeGroups:
		return "groups"
	case modeSet:
		return "set"
	}
	return "find"
}

// setCap is the one capability a set case declares and drives. One per case, as
// in likelytest: the compiler emits only the machinery the declared
// capabilities need, so declaring two would put a frontend in the module that
// the measurement is not driving and report the union in the size column.
type setCap int

const (
	setCapFind setCap = iota
	setCapScanAny
	setCapScanAll
)

// inputGen builds an input of EXACTLY n bytes.
//
// Exactness is the contract, not an approximation: the whole tool is a sweep
// over length, so a generator that returns 30 bytes when asked for 32 silently
// moves the row it is reporting. `matching` selects whether the result should
// match the case's pattern; a generator that cannot honour either at a given n
// returns ok=false and the row is skipped and NAMED, never quietly filled with
// something else.
//
// This is the sampleNeedles lesson from setperf, where a corpus that silently
// matched nothing produced three separate incidents of rows that looked like
// measurements and were not. There the default arm is now a hard error; here
// the generator reports failure and the caller prints it.
type inputGen func(n int, matching bool) (string, bool)

type lenCase struct {
	name string
	desc string
	mode driveMode

	pattern     string   // unset when mode == modeSet
	setPatterns []string // only when mode == modeSet
	cap         setCap   // only when mode == modeSet
	likely      compile.LikelyMode

	gen inputGen

	// actual is the input-length axis for this case. Defaults to defaultActual
	// when nil. A case whose shape only exists at certain lengths (a 4-byte
	// literal cannot be probed at 2 bytes) narrows it here rather than
	// generating something that is not the shape under test.
	actual []int

	// declared is the declared-length axis. Defaults to defaultDeclared.
	declared []int

	// task names the LENGTH-HINT.md task this case exists to measure, so a row
	// that moves can be traced to the change that moved it.
	task string
}

var (
	// Deliberately NOT all multiples of 16. A 16-byte-chunked scan leaves a
	// remainder of `len mod 16`, so an axis built from powers of two measures
	// only the lengths that HAVE no remainder — which is how the first version
	// of this axis made a tail-recovery change look like a flat regression.
	// Real callers' inputs are not chunk-aligned.
	defaultActual   = []int{4, 8, 15, 16, 17, 31, 32, 100, 1000, 16384, 100000}
	defaultDeclared = []int{0, 16, 32, 64, 16384}
)

// ---------------------------------------------------------------------------
// Input generators.

// repeatTo pads body out to exactly n bytes with filler, or truncates a filler
// prefix in front of it. Returns false when body itself does not fit.
func repeatTo(body, filler string, n int) (string, bool) {
	if len(body) > n || filler == "" {
		return "", false
	}
	pad := n - len(body)
	var b strings.Builder
	b.Grow(n)
	for b.Len() < pad {
		need := pad - b.Len()
		if need >= len(filler) {
			b.WriteString(filler)
		} else {
			b.WriteString(filler[:need])
		}
	}
	b.WriteString(body)
	return b.String(), true
}

// fillOnly is a generator for cases whose non-matching input is a plain run of
// filler and whose matching input is that run with `needle` placed at the end.
func fillOnly(filler, needle string) inputGen {
	return func(n int, matching bool) (string, bool) {
		if !matching {
			s, ok := repeatTo("", filler, n)
			return s, ok
		}
		return repeatTo(needle, filler, n)
	}
}

// ---------------------------------------------------------------------------
// Cases.
//
// One per mechanism LENGTH-HINT.md's Groups A and B would change, so that every
// task has a row here before it has a line of emitter code. The `task` field is
// the link.

func cases() []lenCase {
	return []lenCase{
		{
			name: "teddy-prefix-find",
			desc: "Teddy prefix scan on a general find body — the preload and the 16-byte bounds guard",
			mode: modeFind, task: "A3, D1",
			pattern: `(?:ab|cd)[a-z]{200}`,
			gen:     fillOnly("qrs", "ab"+strings.Repeat("z", 200)),
			actual:  []int{4, 8, 15, 16, 17, 31, 32, 100, 1000, 16384},
		},
		{
			name: "tdfa-capture-body",
			desc: "the row that started the plan: <([a-z]+)> groups, +10.2% under prefer-match on a 5-byte input",
			mode: modeGroups, task: "A1, A5, D3, D4",
			pattern: `<([a-z]+)>`,
			likely:  compile.LikelyMatch,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "q", n)
				}
				if n < 3 {
					return "", false
				}
				return "<" + strings.Repeat("a", n-2) + ">", true
			},
		},
		{
			name: "mid-dominant-find",
			desc: "mid-accept dominant channel, emitted in EVERY mode and with no hysteresis",
			mode: modeFind, task: "A1",
			pattern: `x[^\n]+`,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "\n", n)
				}
				if n < 2 {
					return "", false
				}
				return "x" + strings.Repeat("y", n-1), true
			},
		},
		{
			name: "anchored-wide-loop",
			desc: `"[^"]*" anchored match — Phase-4 dominant load on every input byte; no perftest row has this shape`,
			mode: modeAnchored, task: "A2",
			pattern: `"[^"]*"`,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "q", n)
				}
				if n < 2 {
					return "", false
				}
				return `"` + strings.Repeat("a", n-2) + `"`, true
			},
		},
		{
			name: "class-chain",
			desc: "class-chain SIMD verify under prefer-match; its 16-byte guard falls to scalar below one chunk",
			mode: modeFind, task: "A4",
			pattern: `[a-zA-Z]{20,}`,
			likely:  compile.LikelyMatch,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "0", n)
				}
				if n < 20 {
					return "", false
				}
				return repeatTo(strings.Repeat("a", 20), "0", n)
			},
			actual: []int{4, 8, 15, 16, 17, 31, 32, 100, 1000, 16384},
		},
		{
			name: "minlen-exit",
			desc: "a pattern with a high minimum length, on inputs below it — A7 shipped unconditionally, this is its row",
			mode: modeFind, task: "A7",
			pattern: `https?://[a-z]+\.[a-z]{2,}/[a-z]*`,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "q", n)
				}
				const u = "http://example.com/a"
				if n < len(u) {
					return "", false
				}
				return repeatTo(u, "q", n)
			},
		},
		{
			name: "set-keywords-8",
			desc: "8 literals — the frontend chooser's crossovers were all calibrated at 100 KB",
			mode: modeSet, cap: setCapFind, task: "B2, B3",
			setPatterns: []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"},
			gen:         fillOnly("qrs", "charlie"),
		},
		{
			name: "set-classchain-scan",
			desc: "literal-less set driving scan_any over the union automaton under prefer-no-match",
			mode: modeSet, cap: setCapScanAny, task: "B4, D2",
			setPatterns: []string{
				`[a-z]{4}[0-9]{2}`, `[a-z]{6}[0-9]{3}`, `[a-z]{3}[0-9]{4}`, `[a-z]{5}[0-9]{2}`,
			},
			likely: compile.LikelyNoMatch,
			gen: func(n int, matching bool) (string, bool) {
				if !matching {
					return repeatTo("", "-", n)
				}
				const needle = "abcd12"
				if n < len(needle) {
					return "", false
				}
				return repeatTo(needle, "-", n)
			},
		},
		{
			name: "set-fallback-32",
			desc: "32-pattern set: the per-call gate prologues run once per call and are ~17 x patterns",
			mode: modeSet, cap: setCapFind, task: "B6",
			setPatterns: func() []string {
				out := make([]string, 32)
				for i := range out {
					out[i] = fmt.Sprintf(`kw%02d[a-z]{3}`, i)
				}
				return out
			}(),
			gen: fillOnly("...", "kw07abc"),
		},
	}
}

// ---------------------------------------------------------------------------
// Compilation.

func compileCase(c lenCase) ([]byte, error) {
	if c.mode == modeSet {
		entries := make([]config.RegexEntry, len(c.setPatterns))
		for i, p := range c.setPatterns {
			entries[i] = config.RegexEntry{Pattern: p}
		}
		sc := config.SetConfig{
			Name:     "bench_set",
			Patterns: config.PatternSelector{All: true},
			Hints:    hintsYAML(c.likely),
		}
		switch c.cap {
		case setCapScanAny:
			sc.ScanAny = "set_scan_any"
		case setCapScanAll:
			sc.ScanAll = "set_scan_all"
		default:
			sc.Find = "set_find"
		}
		cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
		opts := compile.CompileSetOptions{
			LikelyMode:  c.likely,
		}
		wasm, _, _, err := compile.CompileFileOpts(cfg, "", opts)
		return wasm, err
	}

	re := config.RegexEntry{Pattern: c.pattern}
	switch c.mode {
	case modeAnchored:
		re.MatchFunc = "match"
	case modeGroups:
		re.GroupsFunc = "groups"
	default:
		re.FindFunc = "find"
	}
	opts := compile.CompileOptions{LikelyMode: c.likely}
	wasm, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true, opts)
	return wasm, err
}

func hintsYAML(m compile.LikelyMode) []string {
	switch m {
	case compile.LikelyMatch:
		return []string{"prefer-match"}
	case compile.LikelyNoMatch:
		return []string{"prefer-no-match"}
	}
	return nil
}

// exportName is the WASM export a case drives.
func (c lenCase) exportName() string {
	switch c.mode {
	case modeAnchored:
		return "match"
	case modeGroups:
		return "groups"
	case modeSet:
		switch c.cap {
		case setCapScanAny:
			return "set_scan_any"
		case setCapScanAll:
			return "set_scan_all"
		}
		return "set_find"
	}
	return "find"
}

// ---------------------------------------------------------------------------
// Driving.

// ---------------------------------------------------------------------------
// Driving.
//
// Two things here are easy to get wrong in a way that produces a NUMBER rather
// than an error, which is why they are centralised:
//
//  1. The ABIs differ per capability. `set_find` is
//     (ptr, len, from, gatePtr, outPtr, outCap) and the scan pair is
//     (ptr, len, offset). A call with the wrong trailing argument still returns
//     an i32, and the harness would publish the fuel of the wrong work.
//  2. A SET module's DFA tables live in its own low memory. Writing input at
//     address 0, as the single-pattern cases do, would overwrite them — so set
//     input goes above the module's data-section top, page-aligned.

// setOutCap is the match-record capacity a set `find` drive offers per call.
const setOutCap = int32(64)

type memPlan struct {
	inputBase  int32
	outputBase int32
	gateBase   int32
}

// planMem places the input and any output buffers for one case and input length.
func planMem(c lenCase, wasmBytes []byte, inputLen int) memPlan {
	if c.mode != modeSet {
		return memPlan{inputBase: inputBase, outputBase: slotsBase}
	}
	const pageSize = 65536
	top := int64(0)
	if t, err := utils.ParseDataSectionBytes(wasmBytes); err == nil && t > top {
		top = t
	}
	in := int32((top + pageSize - 1) / pageSize * pageSize)
	out := in + int32(inputLen) + 4096
	return memPlan{
		inputBase:  in,
		outputBase: out,
		gateBase:   out + setOutCap*12,
	}
}

type instance struct {
	store *wasmtime.Store
	inst  *wasmtime.Instance
	mem   *wasmtime.Memory
	fn    *wasmtime.Func
	plan  memPlan
}

func newInstance(engine *wasmtime.Engine, wasmBytes []byte, c lenCase, inputLen int, withFuel bool) (*instance, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, err
	}
	store := wasmtime.NewStore(engine)
	if withFuel {
		if err := store.SetFuel(fuelBudget); err != nil {
			return nil, err
		}
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, err
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil {
		return nil, fmt.Errorf("module exports no memory")
	}
	mem := memExp.Memory()
	fn := inst.GetFunc(store, c.exportName())
	if fn == nil {
		return nil, fmt.Errorf("module has no %q export", c.exportName())
	}
	plan := planMem(c, wasmBytes, inputLen)

	// Grow to cover the plan before anything writes into it: a set module
	// declares only the pages its tables need, and the input sits above them.
	need := int64(plan.gateBase) + int64(setOutCap)*4 + int64(inputLen) + 65536
	if have := int64(mem.DataSize(store)); have < need {
		pages := (need - have + 65535) / 65536
		if _, err := mem.Grow(store, uint64(pages)); err != nil {
			return nil, fmt.Errorf("grow to %d bytes: %w", need, err)
		}
	}
	return &instance{store: store, inst: inst, mem: mem, fn: fn, plan: plan}, nil
}

// drive performs ONE unit of work: a single call for the anchored, find, groups
// and scan cases, and a full exhaustion pass for a set `find` — which is the
// only one of them whose single call does not consume the whole input.
func (in *instance) drive(c lenCase, input string) error {
	buf := in.mem.UnsafeData(in.store)
	copy(buf[in.plan.inputBase:], input)
	inputLen := int32(len(input))
	runtime.KeepAlive(in.store)

	switch c.mode {
	case modeAnchored:
		_, err := wcall(in.fn, in.store, in.plan.inputBase, inputLen)
		return err
	case modeGroups:
		_, err := wcall(in.fn, in.store, in.plan.inputBase, inputLen, in.plan.outputBase, int32(0))
		return err
	case modeFind:
		_, err := wcall(in.fn, in.store, in.plan.inputBase, inputLen, int32(0))
		return err
	}

	// modeSet.
	switch c.cap {
	case setCapScanAny, setCapScanAll:
		_, err := wcall(in.fn, in.store, in.plan.inputBase, inputLen, int32(0))
		return err
	}

	// set find: zero the caller-owned gate array, then exhaust.
	buf = in.mem.UnsafeData(in.store)
	for i := int32(0); i < setOutCap*4; i++ {
		buf[in.plan.gateBase+i] = 0
	}
	runtime.KeepAlive(in.store)
	from := int32(0)
	for {
		n, err := wcall(in.fn, in.store, in.plan.inputBase, inputLen, from,
			in.plan.gateBase, in.plan.outputBase, setOutCap)
		if err != nil {
			return err
		}
		count, _ := n.(int32)
		if count <= 0 {
			return nil
		}
		buf := in.mem.UnsafeData(in.store)
		base := int(in.plan.outputBase)
		end := int32(buf[base+8]) | int32(buf[base+9])<<8 |
			int32(buf[base+10])<<16 | int32(buf[base+11])<<24
		runtime.KeepAlive(in.store)
		next := end
		if next <= from {
			next = from + 1
		}
		if next >= inputLen {
			return nil
		}
		from = next
	}
}

func measureFuel(engine *wasmtime.Engine, wasmBytes []byte, c lenCase, input string) (uint64, error) {
	in, err := newInstance(engine, wasmBytes, c, len(input), true)
	if err != nil {
		return 0, err
	}
	before, _ := in.store.GetFuel()
	if err := in.drive(c, input); err != nil {
		return 0, err
	}
	after, _ := in.store.GetFuel()
	return before - after, nil
}

func measureTime(engine *wasmtime.Engine, wasmBytes []byte, c lenCase, input string) (time.Duration, error) {
	in, err := newInstance(engine, wasmBytes, c, len(input), false)
	if err != nil {
		return 0, err
	}
	samples := make([]time.Duration, 0, timeIters)
	err = watchedSeries(in.store, func() error {
		for i := 0; i < timeIters; i++ {
			t0 := time.Now()
			if err := in.drive(c, input); err != nil {
				return err
			}
			samples = append(samples, time.Since(t0))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// ---------------------------------------------------------------------------
// Reporting.

type cell struct {
	fuel    uint64
	dur     time.Duration
	skipped string // non-empty when this cell was not measured, and why
}

// Column widths for the sweep tables. rowLabelW is sized to the header
// "declared \\ actual" (17 chars): when it was 14 the header overflowed its own
// field and every column heading sat three characters right of the data under
// it. colW must hold the widest cell any row prints — a six-digit fuel figure
// plus its percentage, which is why the delta form below is %7d%5s and not
// %5d%5s.
const (
	rowLabelW = 18
	colW      = 12
	// The T0.6 table's own pair. Its label column holds "<mechanism> (<scope>)"
	// — "prefix-scan-simd (wide)" is 23 characters and overflowed a 22-wide
	// field, putting that one row a character right of every other.
	mechLabelW = 26
	mechColW   = 9
)

func pct(cur, base uint64) string {
	if base == 0 {
		return "    —"
	}
	d := (float64(cur) - float64(base)) / float64(base) * 100
	if d == 0 {
		return "   0%"
	}
	return fmt.Sprintf("%+4.0f%%", d)
}

func humanLen(n int) string {
	switch {
	// 0 is not a declared length of zero — it is the build with NO
	// declaration, which is the baseline every other row is a delta against.
	// Printing it as "0" read as "declared zero bytes" and was misleading.
	case n == 0:
		return "no-hint"
	case n >= 1024 && n%1024 == 0:
		return fmt.Sprintf("%dK", n/1024)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func main() {
	setsOnly := flag.Bool("sets", false, "run only the set cases (mode == modeSet)")
	t06 := flag.Bool("t06", false, "LENGTH-HINT T0.6: sweep the MECHANISM axis (which SIMD channel is de-emitted) instead of the declared-length axis")
	withTime := flag.Bool("time", false, "also measure p50 wall-clock (see the README: a ~2.4µs host-call floor makes it meaningless below ~1 KB)")
	_ = flag.Bool("fuel", true, "deprecated no-op: fuel and size are always measured, timing is opt-in via -time")
	flag.Parse()
	filter := os.Getenv("LENTEST_FILTER")

	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelCfg.SetWasmSIMD(true)
	fuelEngine := newWatchedEngine(fuelCfg)

	timeCfg := wasmtime.NewConfig()
	timeCfg.SetWasmSIMD(true)
	timeEngine := newWatchedEngine(timeCfg)

	if *t06 {
		runT06(fuelEngine, filter, *setsOnly)
		return
	}

	failures := 0
	for _, c := range cases() {
		if *setsOnly && c.mode != modeSet {
			continue
		}
		if filter != "" && !strings.Contains(c.name, filter) {
			continue
		}
		wcallCase = c.name

		actual := c.actual
		if actual == nil {
			actual = defaultActual
		}

		fmt.Printf("\n=== %s  [%s%s] ===\n", c.name, c.mode, likelySuffix(c.likely))
		fmt.Printf("  %s\n", c.desc)
		fmt.Printf("  measures: %s\n", c.task)

		w, err := compileCase(c)
		if err != nil {
			fmt.Printf("  COMPILE FAILED: %v\n", err)
			failures++
			continue
		}
		fmt.Printf("  wasm size: %d B\n", len(w))

		var firstErr error
		for _, matching := range []bool{false, true} {
			label := "no-match"
			if matching {
				label = "match"
			}
			fmt.Printf("\n  --- %s inputs ---\n", label)
			fmt.Printf("  %-*s", rowLabelW, "input length")
			for _, a := range actual {
				fmt.Printf("%*s", colW, humanLen(a))
			}
			fmt.Println()

			fmt.Printf("  %-*s", rowLabelW, "fuel")
			for _, a := range actual {
				in, ok := c.gen(a, matching)
				if !ok {
					fmt.Printf("%*s", colW, "n/a")
					continue
				}
				if len(in) != a {
					fmt.Printf("%*s", colW, "BADGEN")
					failures++
					continue
				}
				f, err := measureFuel(fuelEngine, w, c, in)
				if err != nil {
					fmt.Printf("%*s", colW, "ERR")
					if firstErr == nil {
						firstErr = err
					}
					failures++
					continue
				}
				fmt.Printf("%*d", colW, f)
			}
			fmt.Println()

			if *withTime {
				reportTimes(timeEngine, c, w, actual, matching)
			}
		}
		if firstErr != nil {
			fmt.Printf("  first error: %v\n", firstErr)
		}
	}

	if failures > 0 {
		fmt.Printf("\n%d failure(s)\n", failures)
		os.Exit(1)
	}
}

func likelySuffix(m compile.LikelyMode) string {
	switch m {
	case compile.LikelyMatch:
		return ", prefer-match"
	case compile.LikelyNoMatch:
		return ", prefer-no-match"
	}
	return ""
}

// reportTimes prints the p50 row set. Opt-in (-time) and informative only.
//
// TWO independent reasons not to gate on it. The documented one is instruction
// placement: timings swing by tens of percent between runs of identical bytes on
// the development machine. The one this harness adds is a floor — it drives the
// real export from the HOST once per sample, so every cell carries a wasmtime
// call crossing of about 2.4µs. A 4-byte case does ~98 fuel of work under that,
// so below roughly 1 KB the column measures the crossing and nothing else.
//
// The floor is the price of driving the same ABI at 4 bytes and at 100 KB, which
// is what makes the two ends of a row comparable. likelytest avoids it with an
// in-WASM iteration shim, and pays for that by measuring a shim rather than the
// export.
func reportTimes(engine *wasmtime.Engine, c lenCase, w []byte,
	actual []int, matching bool) {

	fmt.Printf("  %-*s", rowLabelW, "p50 (informative)")
	for _, a := range actual {
		in, ok := c.gen(a, matching)
		if !ok || len(in) != a {
			fmt.Printf("%*s", colW, "n/a")
			continue
		}
		dur, err := measureTime(engine, w, c, in)
		if err != nil {
			fmt.Printf("%*s", colW, "ERR")
			continue
		}
		fmt.Printf("%*s", colW, dur.String())
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// T0.6 — the narrow-vs-wide scope measurement.

// mechanism is one de-emission the input-length hint might perform, and the
// scope bucket LENGTH-HINT.md §T0.6 puts it in.
//
// The distinction is the whole question. A NARROW mechanism is one a
// prefer-match / prefer-no-match hint ADDED, so de-emitting it lands the caller
// back on the neutral build: mispredicting costs them the hint's win and never
// more. A WIDE one is emitted in neutral builds too, so de-emitting it makes a
// mispredicting caller slower than using no hint at all — and how much slower
// has never been measured. That is what the "harm" columns below are.
type mechanism struct {
	name  string
	mask  compile.MeasureMask
	scope string // "narrow" or "wide"
	task  string
}

func mechanisms() []mechanism {
	return []mechanism{
		{"prefix-scan-simd", compile.MeasurePrefixScanSIMD, "wide", "A3"},
		{"tdfa-bulk-skip", compile.MeasureTDFABulkSkip, "wide", "A5"},
		{"dominant-find", compile.MeasureDominantFind, "wide", "A1 (mid half; the non-mid half is narrow)"},
		{"dominant-match", compile.MeasureDominantMatch, "wide", "A2"},
		{"non-mid-shufti", compile.MeasureNonMidShufti, "narrow", "A1 (the row that started the plan)"},
		{"class-chain", compile.MeasureClassChain, "narrow", "A4"},
		{"dense-switch", compile.MeasureDenseSwitch, "narrow", "A6"},
		{"union-stride", compile.MeasureUnionStride, "narrow", "B4"},
		{"member-skip", compile.MeasureMemberSkip, "narrow", "B5"},
	}
}

// runT06 prints, per case and per mechanism, the fuel change from de-emitting
// that mechanism at every input length the case carries.
//
// Read the SHORT columns as the win the hint could buy and the LONG ones as
// what a caller pays for mispredicting. A wide mechanism whose long columns are
// badly negative is one the hint should probably not touch.
func runT06(fuelEngine *wasmtime.Engine, filter string, setsOnly bool) {
	fmt.Println("LENGTH-HINT T0.6 — narrow vs wide, measured")
	fmt.Println()
	fmt.Println("  Each row de-emits ONE mechanism and reports fuel Δ% against the")
	fmt.Println("  unmodified build at the same input length. Negative = de-emitting is")
	fmt.Println("  cheaper (the hint's win). Positive = de-emitting costs (the mispredict")
	fmt.Println("  harm). `identical` means that case never emits that mechanism.")

	for _, c := range cases() {
		if setsOnly && c.mode != modeSet {
			continue
		}
		if filter != "" && !strings.Contains(c.name, filter) {
			continue
		}
		wcallCase = c.name
		actual := c.actual
		if actual == nil {
			actual = defaultActual
		}

		compile.SetMeasureDisabled(0)
		base, err := compileCase(c)
		if err != nil {
			fmt.Printf("\n=== %s === COMPILE FAILED: %v\n", c.name, err)
			continue
		}

		fmt.Printf("\n=== %s  [%s%s] === %s\n", c.name, c.mode, likelySuffix(c.likely), c.desc)

		for _, matching := range []bool{false, true} {
			label := "no-match"
			if matching {
				label = "match"
			}
			// Baseline fuel per length.
			baseFuel := map[int]uint64{}
			any := false
			for _, a := range actual {
				in, ok := c.gen(a, matching)
				if !ok || len(in) != a {
					continue
				}
				f, err := measureFuel(fuelEngine, base, c, in)
				if err != nil {
					continue
				}
				baseFuel[a] = f
				any = true
			}
			if !any {
				continue
			}

			fmt.Printf("\n  --- %s ---\n", label)
			fmt.Printf("  %-*s", mechLabelW, "mechanism (scope)")
			for _, a := range actual {
				fmt.Printf("%*s", mechColW, humanLen(a))
			}
			fmt.Println()
			fmt.Printf("  %-*s", mechLabelW, "baseline fuel")
			for _, a := range actual {
				if f, ok := baseFuel[a]; ok {
					fmt.Printf("%*d", mechColW, f)
				} else {
					fmt.Printf("%*s", mechColW, "n/a")
				}
			}
			fmt.Println()

			for _, m := range mechanisms() {
				prev := compile.SetMeasureDisabled(m.mask)
				w, err := compileCase(c)
				compile.SetMeasureDisabled(prev)
				if err != nil {
					fmt.Printf("  %-*s COMPILE FAILED: %v\n", mechLabelW, m.name, err)
					continue
				}
				if string(w) == string(base) {
					fmt.Printf("  %-*s identical — this case never emits it\n",
						mechLabelW, m.name+" ("+m.scope+")")
					continue
				}
				fmt.Printf("  %-*s", mechLabelW, m.name+" ("+m.scope+")")
				for _, a := range actual {
					bf, ok := baseFuel[a]
					if !ok {
						fmt.Printf("%*s", mechColW, "n/a")
						continue
					}
					in, _ := c.gen(a, matching)
					f, err := measureFuel(fuelEngine, w, c, in)
					if err != nil {
						fmt.Printf("%*s", mechColW, "ERR")
						continue
					}
					fmt.Printf("%*.1f%%", mechColW-1, (float64(f)-float64(bf))/float64(bf)*100)
				}
				fmt.Println()
			}
		}
	}
	compile.SetMeasureDisabled(0)
}
