package fuzz

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/qrdl/regexped/compile"
)

// Package fuzz is a byte-level correctness
// fuzzer comparing regexped's compiled WASM find body against Go stdlib
// regexp on the same (pattern, input) pair. Run with:
//
//	go test -fuzz=FuzzCorrectness -fuzztime=10m
//
// or without -fuzz to just replay the seed corpus (a regular test run).

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
// any call exceeding 10s as a hang and reports it as a crasher.
//
// # Calibration
//
// The default of 2000 was derived on 2026-08-18 from 24238 timed calls
// measured under the conditions that actually apply — an instrumented
// go test -fuzz build, -parallel=4, real worker processes — not from solo
// uninstrumented compiles. That distinction is the entire point: the
// previous value of 5000 was calibrated solo and admitted calls of 9.2s
// against the 10s deadline.
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
// see. FuzzSetCaps needs no such variable: it
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
// This narrows coverage, and the loss is real: a genuine oracle bug was once
// found on a 3,282-byte input, which this cap excludes.
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
// several times the work.
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
// moment anything else shared the CPU. Cost is ~linear
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

// Layer 2 of the fuzzer: the four compiled paths
// FuzzCorrectness never reaches.
//
// FuzzCorrectness only ever sets FindFunc, so it exercises exactly one of the
// five compiled paths — the no-capture DFA/CompiledDFA find body. Thirty-nine
// fuzzer bugs came out of that single path; anchored match, the two capture
// backends, and the whole set pipeline had no coverage at all. The BT
// stack-overflow bug (Backtracking silently returning "no match" once the
// input passes numAlts*4096 bytes) was
// found by hand-pointing a harness at the BT capture path, which is the direct
// argument for this file existing.
//
// Run one target:
//
//	go test -fuzz=FuzzMatch -fuzztime=10m
//
// or without -fuzz to replay the seed corpus as a normal test.

// skipPattern applies the shared "is this pattern in scope at all?" gate, in the
// same order and for the same reasons as FuzzCorrectness. Returns a non-empty
// reason when the case should be skipped.
//
// Kept as one helper so all four Layer-2 targets stay consistent: a skip rule
// that exists in one target but not another produces failures that look like
// engine bugs but are really harness gaps.
func skipPattern(pat, input string) string {
	if hasUnsupportedUnicode(input) {
		return "input has non-ASCII: the byte-oriented engines are out of scope for Unicode (CLAUDE.md)"
	}
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return "not a regexp"
	}
	if prog, err := syntax.Compile(parsed.Simplify()); err == nil && len(prog.Inst) > maxNFAInsts() {
		return "NFA too large for the fuzz worker's hang deadline (see maxNFAInsts)"
	}
	// The compiler's own predicate, not a raw-string scan: escapes like \x80 are
	// pure ASCII text but denote a non-ASCII codepoint once parsed.
	if needsUnicode, err := compile.NeedsUnicodeSupport(pat); err != nil || needsUnicode {
		return "needs Unicode support"
	}
	if _, err := regexp.Compile(pat); err != nil {
		return "Go stdlib rejects it too — no oracle"
	}
	return ""
}

// isResourceCeiling reports whether a compile error is a legitimate, documented
// resource ceiling rather than a bug. These are surfaced as typed errors on
// purpose (contrast the Backtracking frame budget, whose *runtime* ceiling was
// silent until it got its own sentinel).
func isResourceCeiling(err error) bool {
	return errors.Is(err, compile.ErrBTProgramTooLarge) ||
		errors.Is(err, compile.ErrBTStackTooLarge) ||
		errors.Is(err, compile.ErrBTLoopCountTooLarge) ||
		errors.Is(err, compile.ErrBTEmptyBodyLoopChainTooLarge) ||
		// The SET path's helper-DFA ceiling (maxHelperDFAStates, 2048). Unlike
		// the four above it has no fallback — the set compile fails — but it is
		// the same KIND of event: a construction refused as effectively
		// unbounded, not an answer that disagrees with Go. Omitting it is what
		// made FuzzSet/40f883ef54d47f63 look like a defect.
		errors.Is(err, compile.ErrDFAStateLimit)
}

// hasCaptures reports whether pat contains at least one capture group.
//
// A groups export is only emitted for patterns with MaxCap() > 0: setting
// groups_func on a capture-less pattern yields a module with no groups export at
// all. tools/re2test gates on exactly this (`parsed.MaxCap() > 0`) before
// setting GroupsFunc, so the Layer-2 groups targets must too — otherwise every
// capture-less seed fails with "module missing groups export", which is a
// harness gap wearing an engine bug's clothes.
func hasCaptures(pat string) bool {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	return err == nil && parsed.MaxCap() > 0
}

// ---------------------------------------------------------------------------
// Path 1: anchored match (match_func) — DFA / CompiledDFA / lit-chain bodies.

// FuzzMatch checks the match export against a full-consumption oracle.
//
// The contract was established empirically, not from the docs: match_func
// matches only when the pattern consumes the ENTIRE input, and returns
// len(input) when it does. Probed cases that pin this down — `a` vs "ab" is NO
// match, `a+` vs "aab" is NO match, `abc` vs "abcdef" is NO match, `.*` vs "xyz"
// returns 3. So the oracle is `\A(?:pat)\z`, NOT FindStringIndex.
//
// Note this is also why tools/re2test compares match results against col0 (the
// RE2 full-match column) and skips col0 entirely for capturing patterns.
func FuzzMatch(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}

		wasmBytes, compErr := compileMatch(pat)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("compile error on a pattern Go stdlib accepts: pat=%q: %v", pat, compErr)
		}

		// Full-consumption oracle. Wrapping in \A(?:...)\z is safe for any
		// pattern Go already accepted, and (?: ) keeps alternation from
		// re-associating across the anchors.
		full, err := regexp.Compile(`\A(?:` + pat + `)\z`)
		if err != nil {
			t.Skip("pattern cannot be anchor-wrapped for the oracle")
		}
		want := full.MatchString(input)

		end, ok, hang, runErr := runWasmMatch(wasmBytes, input)
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pat=%q input=%q: %v", pat, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog timeout after %s): pat=%q input=%q", wasmCallTimeout, pat, input)
		}
		if ok != want {
			t.Fatalf("match mismatch: pat=%q input=%q expected match=%v got match=%v (end=%d)",
				pat, input, want, ok, end)
		}
		// On a match the returned end must be the full input length — that IS
		// the full-consumption contract, and a wrong end would otherwise pass
		// the boolean check above unnoticed.
		if ok && end != len(input) {
			t.Fatalf("match end mismatch: pat=%q input=%q full-consumption implies end=%d, got %d",
				pat, input, len(input), end)
		}
	})
}

// ---------------------------------------------------------------------------
// Path 2/3: captures (groups_func) — TDFA when eligible, Backtracking otherwise.

// FuzzGroups checks the groups export against Go's FindStringSubmatchIndex.
//
// groups_func is NON-anchored despite CLAUDE.md describing it as "anchored +
// captures" — verified empirically ((a)(b) vs "xxab" returns [2 4 2 3 3 4], and
// re2test's col0 handling filters on slots[0] != 0 for exactly this reason). So
// the oracle is plain FindStringSubmatchIndex with no anchoring.
func FuzzGroups(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}
		if !hasCaptures(pat) {
			t.Skip("no capture groups: no groups export is emitted for such patterns")
		}
		ref := regexp.MustCompile(pat)
		numGroups := ref.NumSubexp() + 1
		if numGroups > maxFuzzGroups {
			t.Skip("too many capture groups for the harness slot buffer")
		}

		wasmBytes, compErr := compileGroups(pat)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("compile error on a pattern Go stdlib accepts: pat=%q: %v", pat, compErr)
		}

		want := ref.FindStringSubmatchIndex(input)
		got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, input, numGroups)
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pat=%q input=%q: %v", pat, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog timeout after %s): pat=%q input=%q", wasmCallTimeout, pat, input)
		}
		if msg := compareSlots(want, got, ok); msg != "" {
			eng, _ := compile.SelectEngine(pat, compile.CompileOptions{})
			t.Fatalf("groups mismatch (%s): pat=%q input=%q engine=%v\n  expected %v\n  got      %v (ok=%v)",
				msg, pat, input, eng, want, got, ok)
		}
	})
}

// FuzzGroupsBothEngines runs the same pattern through TDFA and Backtracking and
// checks both against the oracle.
//
// Without this, the selector decides which capture backend ever gets fuzzed for
// a given pattern shape, so whichever engine it does not pick stays dark. It
// also cross-checks the two engines against each other, which catches the case
// where both are self-consistent but disagree — the shape CLAUDE.md's
// "load-bearing gates" section warns about when moving patterns between
// backends.
func FuzzGroupsBothEngines(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}
		if !hasCaptures(pat) {
			t.Skip("no capture groups: no groups export is emitted for such patterns")
		}
		ref := regexp.MustCompile(pat)
		numGroups := ref.NumSubexp() + 1
		if numGroups > maxFuzzGroups {
			t.Skip("too many capture groups for the harness slot buffer")
		}
		want := ref.FindStringSubmatchIndex(input)

		type result struct {
			slots []int
			ok    bool
			ran   bool
		}
		results := map[compile.EngineType]result{}

		// Which engines is it legitimate to run this pattern on?
		//
		// CompileForced bypasses selectBestEngine's eligibility gate, and TDFA
		// is documented as INVALID for whole pattern families — non-greedy
		// quantifiers, line anchors, word boundaries, ambiguous captures
		// (CLAUDE.md, compile/selector.go). Forcing TDFA on `(?m:(foo)$)` and
		// then calling the wrong answer a bug is garbage-in: the compiler never
		// claimed TDFA handles it. So TDFA is only exercised when the selector
		// itself would pick it; Backtracking is the general fallback and is
		// always fair game.
		selected, _ := compile.SelectEngine(pat, compile.CompileOptions{})
		engines := []compile.EngineType{compile.EngineBacktrack}
		if selected == compile.EngineTDFA {
			engines = append(engines, compile.EngineTDFA)
		}

		for _, eng := range engines {
			wasmBytes, compErr := compileGroupsForced(pat, eng)
			if compErr != nil {
				// A forced engine can still legitimately refuse (BT resource
				// ceilings). Not a bug — just no coverage from it here.
				continue
			}
			got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, input, numGroups)
			if errors.Is(runErr, errBTOverflow) {
				// One engine can hit its frame ceiling while the other
				// answers fine, so the cross-engine comparison below is not
				// meaningful for this input — skip the whole case, not just
				// this engine.
				t.Skip("backtracking frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("wasm error (engine=%v): pat=%q input=%q: %v", eng, pat, input, runErr)
			}
			if hang {
				t.Fatalf("hang (engine=%v, watchdog %s): pat=%q input=%q", eng, wasmCallTimeout, pat, input)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Fatalf("groups mismatch (%s) on engine=%v: pat=%q input=%q\n  expected %v\n  got      %v (ok=%v)",
					msg, eng, pat, input, want, got, ok)
			}
			results[eng] = result{slots: got, ok: ok, ran: true}
		}

		// Cross-engine agreement, when both actually compiled.
		tr, tok := results[compile.EngineTDFA]
		br, bok := results[compile.EngineBacktrack]
		if tok && bok && tr.ran && br.ran {
			if tr.ok != br.ok || !slotsEqual(tr.slots, br.slots) {
				t.Fatalf("TDFA and Backtracking disagree: pat=%q input=%q\n  TDFA %v (ok=%v)\n  BT   %v (ok=%v)",
					pat, input, tr.slots, tr.ok, br.slots, br.ok)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Path 4: sets (find_all).

// FuzzSet checks a two-pattern `overlapping: true` set's find against
// per-start-position anchored matching.
//
// Comparison is per pattern and by MULTISET, not by sequence: the set ABI
// leaves the order of the tuples within one call unspecified. Patterns
// carrying capture groups are skipped: the set pipeline drops capture-bearing
// patterns (SetDiag.CaptureBearingDropped), so including one would produce an
// oracle mismatch that is expected behaviour rather than a bug.
func FuzzSet(f *testing.F) {
	// Seed with pattern pairs drawn from consecutive corpus entries, so the
	// seeds contain patterns that actually share literals and inputs.
	corpus := seedCorpus(seedFile)
	for i := 0; i+1 < len(corpus) && i < 400; i += 2 {
		f.Add(corpus[i].pattern, corpus[i+1].pattern, corpus[i].input)
	}
	f.Add(`abc`, `abd`, "xxabcabd")
	f.Add(`a+`, `b+`, "aabbaa")
	// First-position inversions: literal-candidate order is
	// not match-start order once prefixes vary in length.
	f.Add(`bX`, `.+Y`, "abXY")         // unbounded prefix recovers an earlier start
	f.Add(`(?:ab)+Y`, `cX`, "abcXabY") // variable-length prefix, state-dependent
	f.Add(`xxxFOO`, `FOO`, "yxxxFOOy") // fixed-vs-fixed prefix skew (non-zero drain)
	f.Add(`a.{3}Z`, `Z`, "qaqqqZ")     // fixed prefix 4 vs trivial

	f.Fuzz(func(t *testing.T, pat1, pat2, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		// The oracle below costs ~n^2.2 in input length and dominates the
		// call, so pathsInputCap is no protection against the fuzz worker's
		// 10s hang deadline — see maxSetOracleInput for the measurements.
		if len(input) > maxSetOracleInput() {
			t.Skip("input longer than the per-start-position oracle can price under the worker deadline")
		}
		// The whole-input oracle below counts RUNES in its `.{p}` prefix, so
		// it is only exact on single-byte-rune input.
		for i := 0; i < len(input); i++ {
			if input[i] >= 0x80 {
				t.Skip("non-ASCII input: the rune-counted whole-input oracle would misalign")
			}
		}
		pats := []string{pat1, pat2}
		refs := make([]*regexp.Regexp, len(pats))
		for i, p := range pats {
			if reason := skipPattern(p, input); reason != "" {
				t.Skip(reason)
			}
			re := regexp.MustCompile(p)
			if re.NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
			refs[i] = re
		}

		wasmBytes, dropped, compErr := compileSet(pats)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("set compile error on patterns Go stdlib accepts: %q + %q: %v", pat1, pat2, compErr)
		}

		got, hang, runErr := runWasmSetFind(wasmBytes, input, len(pats))
		if errors.Is(runErr, errSetOutputTruncated) {
			t.Fatalf("set find overflowed a patterns_in_set-sized buffer: pats=%q,%q input=%q: %v",
				pat1, pat2, input, runErr)
		}
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pats=%q,%q input=%q: %v", pat1, pat2, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog %s): pats=%q,%q input=%q", wasmCallTimeout, pat1, pat2, input)
		}

		byID := map[int][][2]int{}
		for _, m := range got {
			byID[m.PatternID] = append(byID[m.PatternID], [2]int{m.Start, m.End})
		}
		for i, re := range refs {
			if dropped[i] {
				// Not in the set the engine built, so the set reports none of
				// its matches and the oracle must not expect any.
				if n := len(byID[i]); n != 0 {
					t.Fatalf("set pattern[%d]=%q was DROPPED from the set but reported %d matches",
						i, pats[i], n)
				}
				continue
			}
			want := allStartPositionMatches(re, input)
			gotI := byID[i]
			sortSpans(want)
			sortSpans(gotI)
			if len(want) != len(gotI) {
				t.Fatalf("set pattern[%d]=%q match count: input=%q expected %d %v, got %d %v",
					i, pats[i], input, len(want), want, len(gotI), gotI)
			}
			for k := range want {
				if want[k][0] != gotI[k][0] || want[k][1] != gotI[k][1] {
					t.Fatalf("set pattern[%d]=%q match %d: input=%q expected %v, got %v",
						i, pats[i], k, input, want[k], gotI[k])
				}
			}
		}
	})
}

// sortSpans orders spans by (start, end) so two multisets can be compared
// element-wise. The set ABI leaves within-call tuple order
// unspecified, so the comparison must be multiset-based.
func sortSpans(v [][2]int) {
	sort.Slice(v, func(i, j int) bool {
		if v[i][0] != v[j][0] {
			return v[i][0] < v[j][0]
		}
		return v[i][1] < v[j][1]
	})
}

// allStartPositionMatches is the oracle for an `overlapping: true` set find.
//
// It reports, for every start position, the match beginning exactly at that
// position — so its results OVERLAP, where Go's FindAll skips forward past each
// match. Measured difference, which is how this was caught:
//
//	a{2,5}? vs "aaaaaa"  Go FindAll: [0-2] [2-4] [4-6]
//	                     find:       [0-2] [1-3] [2-4] [3-5] [4-6]
//	.*?end  vs "xyzend"  Go FindAll: [0-6]
//	                     find:       [0-6] [1-6] [2-6] [3-6]
//	a*      vs "a"       Go FindAll: [0-1]
//	                     find:       [0-1] [1-1]
//
// tools/re2test compares against the corpus's col4 column rather than computing
// this, so it never had to state the rule explicitly.
//
// Implemented with the whole-input technique: `\A(?s:.{p})(?:pat)` over
// the WHOLE input hands `pat` position p with its real left context, so `\b`,
// `\B` and `(?m:^)` judge actual neighbours. The slice technique it replaces
// (`\A(?:pat)` over input[p:]) judged them against a slice boundary instead
// and forced every context-sensitive pattern to be skipped — which is exactly
// how the \b and (?m:^) set defects stayed invisible to this target.
//
// `.{p}` counts runes, so callers must restrict the corpus to ASCII.
//
// The pattern is re-serialised through regexp/syntax before being embedded:
// the raw source may contain `\Q`, which quotes everything after it and would
// swallow the closing paren of the `(?:...)` wrapper, silently building a
// DIFFERENT regexp and blaming the engine for the difference.
func allStartPositionMatches(re *regexp.Regexp, input string) [][2]int {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		panic("oracle: pattern Go already accepted failed to re-parse: " + err.Error())
	}
	body := parsed.String()
	var out [][2]int
	for p := 0; p <= len(input); p++ {
		anchored, err := regexp.Compile(`\A` + dotPrefix(p) + `(?:` + body + `)`)
		if err != nil {
			// Never return "no matches" here: a broken oracle expression
			// would read as "the engine over-reported" and blame the
			// compiler for a harness bug. This is exactly how the
			// maxRepeat ceiling below first showed up.
			panic("oracle: could not build the position-" + strconv.Itoa(p) + " probe: " + err.Error())
		}
		if m := anchored.FindStringIndex(input); m != nil {
			out = append(out, [2]int{p, m[1]})
		}
	}
	return out
}

// dotPrefix builds a regexp matching exactly p bytes of anything.
//
// The obvious `(?s:.{p})` hits regexp/syntax's maxRepeat ceiling of 1000 and
// fails to compile for any longer input — silently, if the caller treats a
// compile error as "no matches".
//
// NESTING a repeat inside another repeat does NOT lift that ceiling, contrary
// to what this comment claimed until 2026-08-21: Go rejects on the PRODUCT of
// nested counts, so `(?:.{1000}){2}` is an error just as `.{2000}` is, and the
// oracle panicked on every input of 2000 bytes or more while `pathsInputCap`
// admits 128 KB. Found by FuzzSet on a 3,282-byte input.
//
// CONCATENATION has no such limit — each term is independently under the
// ceiling — so p/1000 copies of `.{1000}` plus a remainder term is correct for
// any length the fuzzer can produce, at the cost of a longer pattern string.
func dotPrefix(p int) string {
	q, r := p/1000, p%1000
	out := "(?s:"
	for i := 0; i < q; i++ {
		out += ".{1000}"
	}
	if r > 0 {
		out += ".{" + strconv.Itoa(r) + "}"
	}
	return out + ")"
}

// ---------------------------------------------------------------------------
// Slot comparison helpers.

// compareSlots compares a Go FindStringSubmatchIndex result against the WASM
// slot buffer. Returns "" when they agree, else a short reason.
func compareSlots(want []int, got []int, ok bool) string {
	if want == nil {
		if ok {
			return "expected no match"
		}
		return ""
	}
	if !ok {
		return "expected a match, got none"
	}
	if len(got) < len(want) {
		return "fewer slots than groups"
	}
	for i := range want {
		if want[i] != got[i] {
			return "slot value differs"
		}
	}
	return ""
}

func slotsEqual(a, b []int) bool {
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

// Emitter reach, measured from the run that checks the answers.
//
// # The problem this solves
//
// A behavioural sweep is worth exactly what its reach can be shown to be. The
// find sweep passed for weeks over shapes that reached eight of fourteen
// emitters; the six it never touched included two that answered with a match
// starting before the position they were asked to search from
// (plans/FUZZER_BUGS.md 65).
//
// The obvious accounting — a second corpus, in package `compile`, driving the
// emitters and recording which fired — proves the wrong thing. It shows that
// SOME list reaches every emitter, not that the list which checks answers does.
// Two corpora drift, and the drift is silent.
//
// So reach is measured here, from the coverage profile of the sweeps
// themselves. One run produces both facts, and they cannot disagree.
//
//	make from-coverage
//
// which is `go test -run 'TestFindFrom|TestGroupsFrom' -coverpkg=…/compile
// -coverprofile=…` followed by this test with REGEXPED_COVERPROFILE set.
// Without that variable it skips, so `go test ./...` stays self-contained.
//
// # Why no hook in `compile`
//
// An earlier version put `seedTrace`/`captureTrace` function variables in the
// compile package and a `traceCaptureEmitter()` call at the top of six
// emitters. It worked, but it is test scaffolding living in production
// emitters, and it still measured a second corpus. Coverage needs neither:
// it observes without disturbing execution, and it crosses the module
// boundary (`tools/fuzz` requires the root module via `replace`, and
// `-coverpkg` instruments it into the same test binary).
//
// # How emitters are enumerated
//
// Not from a hand-written list, which would silently miss a new emitter, and
// not from a marker, which is the scaffolding just removed. From the code's own
// structure:
//
//   - a FIND emitter is any function containing a call to `emitFindFromSeed`,
//     the one thing every find body must do;
//   - a CAPTURE emitter is any function whose result is assigned to
//     `p.captureBody` or passed to `p.setCaptureBody`.
//
// Add an emitter and it joins the list automatically; the test then fails until
// a shape reaches it.

const coverProfileEnv = "REGEXPED_COVERPROFILE"

type emitterDecl struct {
	name, file, kind   string
	startLine, endLine int
}

// compileDir is the compile package's source, relative to this test.
const compileDir = "../../compile"

func enumerateEmitters(t *testing.T) []emitterDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(compileDir)
	if err != nil {
		t.Fatalf("read %s: %v", compileDir, err)
	}
	var out []emitterDecl
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// Capture emitters are named at their CALL sites, so collect those
		// names first, then match them against declarations below.
		captureNames := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "captureBody" && i < len(v.Rhs) {
						if call, ok := v.Rhs[i].(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok {
								captureNames[id.Name] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setCaptureBody" && len(v.Args) > 0 {
					if inner, ok := v.Args[0].(*ast.CallExpr); ok {
						if id, ok := inner.Fun.(*ast.Ident); ok {
							captureNames[id.Name] = true
						}
					}
				}
			}
			return true
		})
		for n := range captureNames {
			out = append(out, emitterDecl{name: n, kind: "capture"})
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "emitFindFromSeed" {
				continue
			}
			seeds := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "emitFindFromSeed" {
						seeds = true
					}
				}
				return true
			})
			if seeds {
				out = append(out, emitterDecl{
					name: fn.Name.Name, file: name, kind: "find",
					startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
				})
			}
		}
	}
	// Resolve declaration ranges for the capture emitters named above.
	decls := map[string]emitterDecl{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				decls[fn.Name.Name] = emitterDecl{
					name: fn.Name.Name, file: name,
					startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
				}
			}
		}
	}
	var final []emitterDecl
	seen := map[string]bool{}
	for _, e := range out {
		if seen[e.name] {
			continue
		}
		seen[e.name] = true
		if e.file == "" {
			d, ok := decls[e.name]
			if !ok {
				t.Fatalf("capture emitter %q named at a call site but not declared in the package", e.name)
			}
			d.kind = e.kind
			e = d
		}
		final = append(final, e)
	}
	sort.Slice(final, func(i, j int) bool { return final[i].name < final[j].name })
	if len(final) == 0 {
		t.Fatal("no emitters enumerated — has emitFindFromSeed or captureBody been renamed?")
	}
	return final
}

// coveredLines returns, per compile-package file, the set of line numbers with
// at least one executed statement.
func coveredLines(t *testing.T, path string) map[string]map[int]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]map[int]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// name.go:startLine.col,endLine.col numStmt count
		colon := strings.LastIndex(line, ":")
		sp := strings.Fields(line[colon+1:])
		if colon < 0 || len(sp) != 3 {
			continue
		}
		count, err := strconv.Atoi(sp[2])
		if err != nil || count == 0 {
			continue
		}
		file := filepath.Base(line[:colon])
		rng := strings.SplitN(sp[0], ",", 2)
		if len(rng) != 2 {
			continue
		}
		start, err1 := strconv.Atoi(strings.SplitN(rng[0], ".", 2)[0])
		end, err2 := strconv.Atoi(strings.SplitN(rng[1], ".", 2)[0])
		if err1 != nil || err2 != nil {
			continue
		}
		if out[file] == nil {
			out[file] = map[int]bool{}
		}
		for l := start; l <= end; l++ {
			out[file][l] = true
		}
	}
	return out
}

func TestEveryEmitterIsReachedBySweeps(t *testing.T) {
	profile := os.Getenv(coverProfileEnv)
	if profile == "" {
		t.Skipf("set %s (see `make from-coverage`) to check emitter reach", coverProfileEnv)
	}
	emitters := enumerateEmitters(t)
	cov := coveredLines(t, profile)

	var missing []string
	for _, e := range emitters {
		hit := false
		for l := e.startLine; l <= e.endLine && !hit; l++ {
			if cov[e.file][l] {
				hit = true
			}
		}
		if !hit {
			missing = append(missing, fmt.Sprintf("%s (%s, %s:%d)", e.name, e.kind, e.file, e.startLine))
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d of %d emitters are never reached by the property sweeps:\n  %s\n\n"+
			"Each is a body whose answers no test checks. Add a shape to "+
			"findFromShapes or groupsFromShapes that reaches it — on the find side, "+
			"two of six unreached emitters turned out to be broken.",
			len(missing), len(emitters), strings.Join(missing, "\n  "))
	}
	t.Logf("%d emitters, all reached by the sweeps", len(emitters))
}

// ── Set emitters ───────────────────────────────────────
//
// The same question for the set path, where the surface is an order of
// magnitude larger: 19,800 lines across compile/set_*.go.
//
// `compile/set_module_test.go` already reaches these emitters by
// COMPILING them, and its opening comment names the exact split this measures
// from the other side:
//
//	"the correctness of what they emit is checked elsewhere … `make setcaps` …
//	 `tools/fuzz` … Both live in SEPARATE MODULES, so neither contributes a
//	 single statement to this package's coverage, and the gap that hid was
//	 total: `set_overlap_dp.go`, 314 statements of backward sweep, sat at 2.5%
//	 while being exercised thousands of times a second by a fuzz target one
//	 directory away."
//
// So the smoke matrix proves a shape still compiles; this proves the tests
// that CHECK ANSWERS actually drive the emitter. Neither implies the other,
// and on the single-pattern path the same measurement found six of fourteen
// emitters undriven, two of them broken.
//
// A set emitter is defined structurally, not by a list: a function declared in
// compile/set_*.go whose name begins build/emit/gen and which returns []byte —
// i.e. something that produces WASM. Their input conventions differ (some take
// `b []byte`, some a `*compiledSet`), so the result type is the reliable mark.

const setCoverProfileEnv = "REGEXPED_SETCOVERPROFILE"

func returnsBytes(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, r := range fn.Type.Results.List {
		if at, ok := r.Type.(*ast.ArrayType); ok {
			if id, ok := at.Elt.(*ast.Ident); ok && id.Name == "byte" && at.Len == nil {
				return true
			}
		}
	}
	return false
}

func enumerateSetEmitters(t *testing.T) []emitterDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(compileDir)
	if err != nil {
		t.Fatalf("read %s: %v", compileDir, err)
	}
	var out []emitterDecl
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "set_") || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			n := fn.Name.Name
			if !(strings.HasPrefix(n, "build") || strings.HasPrefix(n, "emit") || strings.HasPrefix(n, "gen")) {
				continue
			}
			if !returnsBytes(fn) {
				continue
			}
			out = append(out, emitterDecl{
				name: n, file: name, kind: "set",
				startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	if len(out) == 0 {
		t.Fatal("no set emitters enumerated — have compile/set_*.go been renamed?")
	}
	return out
}

func TestEverySetEmitterIsReached(t *testing.T) {
	profile := os.Getenv(setCoverProfileEnv)
	if profile == "" {
		t.Skipf("set %s (see `make set-coverage`) to check set emitter reach", setCoverProfileEnv)
	}
	emitters := enumerateSetEmitters(t)
	cov := coveredLines(t, profile)

	var missing []string
	for _, e := range emitters {
		hit := false
		for l := e.startLine; l <= e.endLine && !hit; l++ {
			if cov[e.file][l] {
				hit = true
			}
		}
		if !hit {
			missing = append(missing, fmt.Sprintf("%s (%s:%d, %d lines)",
				e.name, e.file, e.startLine, e.endLine-e.startLine))
		}
	}
	t.Logf("%d set emitters, %d reached, %d not", len(emitters), len(emitters)-len(missing), len(missing))
	if len(missing) > 0 {
		t.Errorf("%d of %d set emitters are never reached by the answer-checking tests:\n  %s",
			len(missing), len(emitters), strings.Join(missing, "\n  "))
	}
}
