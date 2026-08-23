// Package fuzz is Layer 1 of plans/FUZZER.md: a byte-level correctness
// fuzzer comparing regexped's compiled WASM find body against Go stdlib
// regexp on the same (pattern, input) pair. Run with:
//
//	go test -fuzz=FuzzCorrectness -fuzztime=10m
//
// or without -fuzz to just replay the seed corpus (a regular test run).
package fuzz

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/qrdl/regexped/compile"
)

// seedFile is the shared re2test custom corpus, used as fuzz seeds.
const seedFile = "../re2test/custom-tests.txt"

// inputCap bounds fuzz input length. Test input is written at WASM memory
// offset 0 and DFA tables start at tableBase (see wasmrun.go); an input at
// or past that offset would spill into table data and produce a spurious
// mismatch that isn't a regexped bug, so such inputs are skipped rather than
// tested. Byte-mutation fuzzing essentially never needs inputs this long.
const inputCap = int(tableBase)

// maxNFAInsts bounds the unrolled NFA program size (regexp/syntax
// instruction count) a pattern is allowed to reach before the fuzzer skips
// it rather than compiling it. This is a fuzz-harness-only limitation, not
// a regexped one (see CLAUDE.md's "runtime over compile time" design
// principle) — it exists because a single go test -fuzz worker call covers
// both compileFind and the WASM run, and Go's internal/fuzz worker treats
// any call exceeding 10s as a hang and reports it as a crasher
// (plans/FUZZER_BUGS.md #23).
//
// # Calibration
//
// The default of 2000 was derived on 2026-08-18 from 24238 timed calls
// measured under the conditions that actually apply — an instrumented
// go test -fuzz build, -parallel=4, real worker processes — not from solo
// uninstrumented compiles. That distinction is the entire point: the
// previous value of 5000 was calibrated solo and admitted calls of 9.2s
// against the 10s deadline, which is plans/FUZZER_BUGS.md #42.
//
// Worst observed per-call wall clock among patterns each cap admits, on the
// reference box (4 CPUs, Linux, Go 1.25.9):
//
//	cap    worst admitted call   headroom vs 10s
//	1000   1594ms                6.3x
//	1500   1906ms                5.2x
//	2000   2825ms                3.5x   <- default
//	2500   4450ms                2.2x
//	3000   5863ms                1.7x
//	4000   8323ms                1.2x
//	5000   9246ms                1.1x   <- previous value, bug #42
//	none   11927ms               0.8x
//
// Real fuzz-worker conditions cost roughly 3.5x the solo compile time:
// (.|()){1000} measures 3.4s alone and 11.9s here. Any recalibration must
// therefore be done under -fuzz, never with a standalone benchmark.
//
// # This is a proxy, not a bound
//
// Instruction count correlates with compile cost only loosely — cost per
// instruction spans ~380x across NFA shapes ((a*){900} is 3602 insts and
// 6ms; (.?){900} is 3602 insts and 2.07s). The cap bounds the tail, it does
// not bound the cost: (.?)4.{450} is only 457 insts yet takes 1594ms, so
// even a cap of 1000 has a ~1.6s worst case. 2000 is chosen for margin
// rather than precision, which is why the headroom column above matters
// more than the admitted-pattern count.
//
// # Overriding
//
// Set REGEXPED_FUZZ_MAX_NFA_INSTS to raise the cap on faster hardware,
// where more of the pattern space fits under the deadline:
//
//	REGEXPED_FUZZ_MAX_NFA_INSTS=4000 go test -fuzz=FuzzCorrectness
//
// Compile cost for the worst family scales about n^1.5 over the measured
// range, so a box K times faster sustains roughly K^0.67 times the cap
// (2x faster ~ 3200, 4x faster ~ 5000). Re-measure before trusting that
// estimate — deriving this number from an unrepresentative measurement is
// exactly how the previous one went stale.
//
// Note that any cap only ever narrows fuzz coverage. On the real seed
// corpus this is a thin slice (the largest seed is 601 insts, p50 is 8),
// and the DFA-size-driven paths are unaffected because those come from
// small NFAs ([ab]*a[ab]{20} is 25 insts), but the exclusion is real.
// Resolved lazily, on first use inside a running test, rather than in a
// package-level initialiser. go test's result cache only tracks environment
// variables read after testing.M.Run installs its testlog hook; an init-time
// read is invisible to it, so a changed REGEXPED_FUZZ_MAX_NFA_INSTS would
// silently replay a stale cached result on non -fuzz replay runs.
var maxNFAInsts = sync.OnceValue(envMaxNFAInsts)

// envMaxNFAInsts returns the REGEXPED_FUZZ_MAX_NFA_INSTS override, or the
// calibrated default. A malformed override panics rather than falling back
// silently: a typo'd cap would otherwise run the whole fuzz session at the
// wrong bound while looking like it had been applied.
func envMaxNFAInsts() int {
	const def = 2000
	raw, ok := os.LookupEnv("REGEXPED_FUZZ_MAX_NFA_INSTS")
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		panic(fmt.Sprintf("REGEXPED_FUZZ_MAX_NFA_INSTS must be a positive integer, got %q", raw))
	}
	return n
}

// maxSetOracleInput bounds the INPUT length FuzzSet admits, for the same 10s
// worker deadline maxNFAInsts guards — but against a cost term that cap cannot
// see (plans/FUZZER_BUGS.md bug 45). FuzzSetCaps needs no such variable: it
// already caps input at 64 bytes for an unrelated reason, which is why only
// FuzzSet ever reached the deadline.
//
// maxNFAInsts bounds the PATTERN's NFA. FuzzSet's dominant cost is neither the
// pattern nor the engine: it is the harness oracle. allStartPositionMatches
// calls regexp.Compile once per start position, on a pattern carrying a
// `.{p}` prefix, so its cost grows superlinearly in INPUT length while the
// pattern stays trivial. On the crasher that exposed this — patterns
// `a(?:b|bc)` + `a\x00\x00b\)`, 1,903 bytes — compile was 0.33ms and the WASM
// run 3.19ms against 405ms of oracle: 99% of the call.
//
// # Calibration
//
// Oracle wall clock for that pattern pair, measured 2026-08-22 on the
// reference box (4 CPUs, Linux, Go 1.25.9), against the same 3.5x
// solo→fuzz-worker factor maxNFAInsts documents:
//
//	input   oracle solo   x3.5      headroom vs 10s
//	512     53ms          187ms     53x
//	1024    216ms         756ms     13x
//	2048    744ms         2.6s      3.8x   <- default
//	4096    3.70s         12.9s     0.8x   (already over)
//	8192    17.1s         60s       0.17x
//	16384   80.2s         281s      0.04x
//
// Growth is ~n^2.2, so the cliff is sharp: every doubling past 2048 costs
// ~4.6x. pathsInputCap (128 KB) is no bound at all here — it admits inputs
// whose oracle alone would run for hours.
//
// This narrows coverage, and the loss is real: plans/SETS.md §18.7 records a
// genuine oracle bug found on a 3,282-byte input, which this cap excludes.
// Raise it deliberately (and re-measure) when hunting long-input behaviour:
//
//	REGEXPED_FUZZ_MAX_SET_INPUT=4096 go test -run='FuzzSet$' -fuzz='FuzzSet$'
var maxSetOracleInput = sync.OnceValue(envMaxSetOracleInput)

func envMaxSetOracleInput() int {
	const def = 2048
	raw, ok := os.LookupEnv("REGEXPED_FUZZ_MAX_SET_INPUT")
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		panic(fmt.Sprintf("REGEXPED_FUZZ_MAX_SET_INPUT must be a positive integer, got %q", raw))
	}
	return n
}

// maxSetCapsNFAInsts is maxNFAInsts for FuzzSetCaps, which needs a tighter one
// for a structural reason: maxNFAInsts bounds ONE pattern, and what the 10s
// deadline actually sees is a whole call — but FuzzSetCaps compiles TWO
// patterns into a set that emits all eight capability bodies plus the anchored
// automata, where FuzzSet compiles one find body. Same instruction budget,
// several times the work (plans/FUZZER_BUGS.md 56).
//
// # Calibration
//
// Measured 2026-08-23 on the reference box, `compileCaps` of two patterns of
// EQUAL size (the worst case a per-pattern cap admits), against the same 3.5x
// solo→fuzz-worker factor maxNFAInsts documents:
//
//	insts/pattern   compileCaps solo   x3.5      headroom vs 10s
//	504             756ms              2.65s     3.8x   <- default
//	704             1.235s             4.32s     2.3x
//	804             1.456s             5.10s     2.0x
//	1004            1.906s             6.67s     1.5x
//	1994            3.289s             11.5s     0.87x  (over before contention)
//
// The last row is the shared cap of 2000, i.e. what FuzzSetCaps ran under
// until now: already past the deadline solo, which is why it tripped the
// moment anything else shared the CPU (plans/SETS.md §21.14). Cost is ~linear
// in instructions and dominated by compilation — instantiate is 2-8ms and the
// oracle sweep 4-26ms across the whole range, so neither is worth capping.
//
// This narrows FuzzSetCaps' pattern coverage, and only FuzzSetCaps': every
// other target keeps maxNFAInsts. Raise it deliberately (and re-measure) when
// hunting large-pattern set behaviour:
//
//	REGEXPED_FUZZ_MAX_CAPS_NFA_INSTS=1000 go test -run=FuzzSetCaps -fuzz=FuzzSetCaps
var maxSetCapsNFAInsts = sync.OnceValue(envMaxSetCapsNFAInsts)

func envMaxSetCapsNFAInsts() int {
	const def = 512
	raw, ok := os.LookupEnv("REGEXPED_FUZZ_MAX_CAPS_NFA_INSTS")
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		panic(fmt.Sprintf("REGEXPED_FUZZ_MAX_CAPS_NFA_INSTS must be a positive integer, got %q", raw))
	}
	return n
}

func FuzzCorrectness(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}

	f.Fuzz(func(t *testing.T, pat, input string) {
		if hasUnsupportedUnicode(input) {
			t.Skip() // regexped's DFA/find path is byte-oriented; Unicode is out of scope (see CLAUDE.md)
		}
		if len(input) >= inputCap {
			t.Skip()
		}
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Skip() // not a regexp at all
		}
		if prog, err := syntax.Compile(parsed.Simplify()); err == nil && len(prog.Inst) > maxNFAInsts() {
			t.Skip() // NFA too large to compile within the fuzz worker's hang deadline — see maxNFAInsts
		}
		// Use the compiler's own predicate rather than hasUnsupportedUnicode's
		// raw-string scan: escapes like \x80 are pure ASCII text but denote a
		// non-ASCII codepoint once parsed, which the raw scan can't see (see
		// the \x80 fuzz failure this replaced).
		if needsUnicode, err := compile.NeedsUnicodeSupport(pat); err != nil || needsUnicode {
			t.Skip() // requires Unicode support — out of scope (see CLAUDE.md), or doesn't parse
		}
		ref, err := regexp.Compile(pat)
		if err != nil {
			t.Skip() // Go stdlib rejects it too — no oracle to compare against
		}

		wasmBytes, compErr := compileFind(pat)
		if compErr != nil {
			if errors.Is(compErr, compile.ErrBTProgramTooLarge) || errors.Is(compErr, compile.ErrBTStackTooLarge) || errors.Is(compErr, compile.ErrBTLoopCountTooLarge) || errors.Is(compErr, compile.ErrBTEmptyBodyLoopChainTooLarge) {
				t.Skip() // legitimate resource ceiling, no further fallback possible — not a regexped bug
			}
			t.Fatalf("compile error on a pattern Go stdlib accepts: pat=%q: %v", pat, compErr)
		}

		expected := ref.FindStringIndex(input)
		span, ok, hang, runErr := runWasmFind(wasmBytes, input)
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pat=%q input=%q: %v", pat, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog timeout after %s): pat=%q input=%q", wasmCallTimeout, pat, input)
		}
		if !indexEqual(expected, span, ok) {
			t.Fatalf("mismatch: pat=%q input=%q expected=%s got=%s", pat, input, fmtGoIndex(expected), fmtSpan(span, ok))
		}
	})
}

// indexEqual compares a Go stdlib FindStringIndex result against the WASM
// find result.
func indexEqual(expected []int, span [2]int, ok bool) bool {
	if expected == nil {
		return !ok
	}
	return ok && expected[0] == span[0] && expected[1] == span[1]
}

// hasUnsupportedUnicode reports whether s contains anything outside
// regexped's byte-oriented (ASCII) support: a rune above 127, or a \p/\P
// Unicode class escape. Mirrors tools/re2test/main.go's hasUnicode.
func hasUnsupportedUnicode(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return strings.Contains(s, `\p`) || strings.Contains(s, `\P`)
}

func fmtGoIndex(m []int) string {
	if m == nil {
		return "no match"
	}
	return fmt.Sprintf("[%d,%d)", m[0], m[1])
}

func fmtSpan(span [2]int, ok bool) string {
	if !ok {
		return "no match"
	}
	return fmt.Sprintf("[%d,%d)", span[0], span[1])
}
