// pattest is a CLI benchmarking tool for a single regexp pattern. It compiles
// the pattern under all three LikelyMode values (neutral, likely-match,
// likely-nomatch), classifies a user-supplied list of candidate inputs into
// matching / non-matching buckets, and reports fuel (measured once) and
// average wall-clock time (averaged over 100,000 iterations) for each mode
// against each bucket.
//
// Usage:
//
//	pattest -pattern <regex> -mode match|find -inputs <file> [-detailed]
//
// -inputs points to a text file with one candidate input per line (no
// embedded newlines within a single input). Bucket classification uses Go's
// stdlib regexp package (RE2 semantics, matching this project's own
// leftmost-first semantics) as ground truth: -mode match checks for a match
// anchored at the start of the input; -mode find checks for a match anywhere.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

const (
	inputBase    = int32(0)
	minTableBase = int64(131072) // page 2; matches likelytest's convention for small inputs
	benchIters   = 100_000
	fuelBudget   = uint64(10_000_000_000)
)

// tableBase is computed per run from the longest input (see main): a fixed
// constant would silently corrupt results for any input long enough to
// overlap the DFA table region placed right after it in memory.
var tableBase = minTableBase

var minimalWASM = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

var likelyModes = [3]compile.LikelyMode{compile.LikelyNeutral, compile.LikelyMatch, compile.LikelyNoMatch}
var likelyModeNames = [3]string{"neutral", "likely-match", "likely-nomatch"}

type cell struct {
	fuel    uint64
	avgTime time.Duration
}

func main() {
	wcallCase = "pattest"
	// Silence regexped's slog output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	patternFlag := flag.String("pattern", "", "regexp pattern to test (required)")
	modeFlag := flag.String("mode", "", "match or find (required)")
	inputsFlag := flag.String("inputs", "", "path to a text file of candidate inputs, one per line (required)")
	detailed := flag.Bool("detailed", false, "show per-input results instead of bucket averages")
	flag.Parse()

	if *patternFlag == "" || *modeFlag == "" || *inputsFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: pattest -pattern <regex> -mode match|find -inputs <file> [-detailed]")
		os.Exit(2)
	}
	if *modeFlag != "match" && *modeFlag != "find" {
		fmt.Fprintln(os.Stderr, "error: -mode must be 'match' or 'find'")
		os.Exit(2)
	}

	inputs, err := readInputs(*inputsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading inputs: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no inputs found in file")
		os.Exit(1)
	}

	classifyRe, err := classifierRegexp(*patternFlag, *modeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid pattern: %v\n", err)
		os.Exit(1)
	}

	var matching, nonMatching []string
	for _, in := range inputs {
		if classifyRe.MatchString(in) {
			matching = append(matching, in)
		} else {
			nonMatching = append(nonMatching, in)
		}
	}

	var maxLen int
	for _, in := range inputs {
		if len(in) > maxLen {
			maxLen = len(in)
		}
	}
	if aligned := utils.PageAlign(int64(maxLen)); aligned > tableBase {
		tableBase = aligned
	}

	engine := newWatchedEngine(nil)
	warmup(engine)
	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := newWatchedEngine(fuelCfg)

	wasmByMode := make(map[compile.LikelyMode][]byte, 3)
	for _, m := range likelyModes {
		wasm, err := compilePattern(*patternFlag, *modeFlag, m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: compile (%s): %v\n", m, err)
			os.Exit(1)
		}
		wasmByMode[m] = wasm
	}

	fmt.Printf("pattern: %s\n", *patternFlag)
	fmt.Printf("mode: %s\n", *modeFlag)
	fmt.Printf("inputs: %d matching, %d non-matching\n\n", len(matching), len(nonMatching))

	if *detailed {
		printDetailed("Matching inputs", matching, *modeFlag, wasmByMode, engine, fuelEngine)
		printDetailed("Non-matching inputs", nonMatching, *modeFlag, wasmByMode, engine, fuelEngine)
	} else {
		printSummary("Matching inputs", matching, *modeFlag, wasmByMode, engine, fuelEngine)
		printSummary("Non-matching inputs", nonMatching, *modeFlag, wasmByMode, engine, fuelEngine)
	}
}

// readInputs reads one candidate input per non-empty line from path.
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
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// classifierRegexp compiles pattern (via Go's stdlib regexp, RE2 semantics)
// for use as ground truth when bucketing inputs. match mode anchors the
// start of the search (mirrors regexped's anchored match_func semantics:
// a match starting at position 0, not necessarily consuming the whole
// input); find mode is a plain unanchored search.
func classifierRegexp(pattern, mode string) (*regexp.Regexp, error) {
	if mode == "match" {
		return regexp.Compile("^(?:" + pattern + ")")
	}
	return regexp.Compile(pattern)
}

// compilePattern compiles pattern as a standalone WASM module exporting
// match_func or find_func (named after the mode) under the given LikelyMode.
func compilePattern(pattern, mode string, likely compile.LikelyMode) ([]byte, error) {
	re := config.RegexEntry{Pattern: pattern}
	switch mode {
	case "match":
		re.MatchFunc = "match"
	case "find":
		re.FindFunc = "find"
	}
	opts := compile.CompileOptions{LikelyMode: likely}
	wasm, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true, opts)
	return wasm, err
}

// measureOne compiles-once-uses-many: runs fuel (single call) and time
// (benchIters calls via the WASM bench shim) measurement for one
// (wasm, mode, input) combination.
func measureOne(wasm []byte, mode, input string, engine, fuelEngine *wasmtime.Engine) (cell, error) {
	fuel, err := benchFuel(wasm, mode, input, fuelEngine)
	if err != nil {
		return cell{}, fmt.Errorf("fuel: %w", err)
	}
	t, err := benchTime(wasm, mode, input, engine)
	if err != nil {
		return cell{}, fmt.Errorf("time: %w", err)
	}
	return cell{fuel: fuel, avgTime: t}, nil
}

// benchFuel measures fuel consumed by a single call.
func benchFuel(wasmBytes []byte, mode, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
	mod, err := wasmtime.NewModule(fuelEngine, wasmBytes)
	if err != nil {
		return 0, err
	}
	store := wasmtime.NewStore(fuelEngine)
	if err := store.SetFuel(fuelBudget); err != nil {
		return 0, err
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, err
	}
	mem := inst.GetExport(store, "memory").Memory()
	fn := inst.GetFunc(store, mode)
	if fn == nil || mem == nil {
		return 0, fmt.Errorf("missing exports")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	before, _ := store.GetFuel()
	args := []any{inputBase, inputLen}
	if mode == "find" {
		args = append(args, int32(0)) // find is (ptr, len, from)
	}
	if _, err := wcall(fn, store, args...); err != nil {
		return 0, err
	}
	after, _ := store.GetFuel()
	return before - after, nil
}

// benchTime times benchIters calls via the WASM bench shim and returns the
// mean of those in-WASM nanosecond samples.
func benchTime(wasmBytes []byte, mode, input string, engine *wasmtime.Engine) (time.Duration, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return 0, fmt.Errorf("module: %w", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, fmt.Errorf("instance: %w", err)
	}
	mem := inst.GetExport(store, "memory").Memory()
	rpdFn := inst.GetFunc(store, mode)
	if rpdFn == nil || mem == nil {
		return 0, fmt.Errorf("missing exports")
	}

	var shimBytes []byte
	if mode == "match" {
		shimBytes = buildMatchBenchShim()
	} else {
		shimBytes = buildFindBenchShim()
	}
	shimMod, err := wasmtime.NewModule(engine, shimBytes)
	if err != nil {
		return 0, fmt.Errorf("shim module: %w", err)
	}
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return 0, fmt.Errorf("linker wasi: %w", err)
	}
	if err := linker.Define(store, "regexped", mode, rpdFn); err != nil {
		return 0, fmt.Errorf("linker define: %w", err)
	}
	shimInst, err := linker.Instantiate(store, shimMod)
	if err != nil {
		return 0, fmt.Errorf("shim instantiate: %w", err)
	}
	shimMem := shimInst.GetExport(store, "memory").Memory()
	benchFn := shimInst.GetFunc(store, "bench")

	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	// 50 ms warmup.
	warmupEnd := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		wcall(benchFn, store, inputBase, inputLen, int32(benchIters)) //nolint:errcheck
	}

	if _, err := wcall(benchFn, store, inputBase, inputLen, int32(benchIters)); err != nil {
		return 0, fmt.Errorf("bench call: %w", err)
	}
	shimBuf := shimMem.UnsafeData(store)
	return computeStat(shimBuf[:timingsBytes]), nil
}

func warmup(engine *wasmtime.Engine) {
	mod, err := wasmtime.NewModule(engine, minimalWASM)
	if err != nil {
		return
	}
	store := wasmtime.NewStore(engine)
	_, _ = wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
}

// --------------------------------------------------------------------------
// Reporting

// bucketCells measures all three LikelyMode values against every input in
// inputs and returns the per-mode average (fuel and time both averaged
// arithmetically across inputs).
func bucketCells(inputs []string, mode string, wasmByMode map[compile.LikelyMode][]byte, engine, fuelEngine *wasmtime.Engine) ([3]cell, error) {
	var out [3]cell
	if len(inputs) == 0 {
		return out, nil
	}
	for i, lm := range likelyModes {
		var totalFuel uint64
		var totalTime time.Duration
		for _, in := range inputs {
			c, err := measureOne(wasmByMode[lm], mode, in, engine, fuelEngine)
			if err != nil {
				return out, err
			}
			totalFuel += c.fuel
			totalTime += c.avgTime
		}
		n := uint64(len(inputs))
		out[i] = cell{fuel: totalFuel / n, avgTime: totalTime / time.Duration(n)}
	}
	return out, nil
}

func printSummary(title string, inputs []string, mode string, wasmByMode map[compile.LikelyMode][]byte, engine, fuelEngine *wasmtime.Engine) {
	fmt.Printf("=== %s (%d) ===\n", title, len(inputs))
	if len(inputs) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	rows, err := bucketCells(inputs, mode, wasmByMode, engine, fuelEngine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		fmt.Println()
		return
	}
	printTable(rows)
	fmt.Println()
}

func printDetailed(title string, inputs []string, mode string, wasmByMode map[compile.LikelyMode][]byte, engine, fuelEngine *wasmtime.Engine) {
	fmt.Printf("=== %s (%d) ===\n", title, len(inputs))
	if len(inputs) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	for idx, in := range inputs {
		var rows [3]cell
		var measureErr error
		for i, lm := range likelyModes {
			c, err := measureOne(wasmByMode[lm], mode, in, engine, fuelEngine)
			if err != nil {
				measureErr = err
				break
			}
			rows[i] = c
		}
		fmt.Printf("--- input #%d: %q ---\n", idx+1, truncate(in, 60))
		if measureErr != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", measureErr)
			continue
		}
		printTable(rows)
	}
	fmt.Println()
}

func printTable(rows [3]cell) {
	baseFuel := float64(rows[0].fuel)
	baseTime := float64(rows[0].avgTime)
	fmt.Printf("  %-16s %14s %7s %14s %7s\n", "mode", "fuel", "Δ%", "avg time", "Δ%")
	for i, name := range likelyModeNames {
		gFuel, gTime := "—", "—"
		if i > 0 {
			gFuel = gain(float64(rows[i].fuel), baseFuel)
			gTime = gain(float64(rows[i].avgTime), baseTime)
		}
		fmt.Printf("  %-16s %14s %7s %14s %7s\n", name,
			fmtFuel(rows[i].fuel), gFuel, fmtDur(rows[i].avgTime), gTime)
	}
}

// gain returns a signed percentage like "-23%"/"+8%" for cur against base
// (the neutral row). Negative = faster/cheaper than neutral. Callers only
// invoke this for non-baseline rows; the baseline itself always prints "—".
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
