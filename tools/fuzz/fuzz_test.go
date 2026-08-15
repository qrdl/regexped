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
	"regexp"
	"regexp/syntax"
	"strings"
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
// 5000 was picked empirically, live against the post-#23-fix compiler:
// the worst NFA shape reachable at all (large bounded-repeat patterns
// like (.|()){N}, which keep ~N NFA instructions simultaneously live per
// DFA state) tops out around 7000 instructions — Go's own regexp/syntax
// caps repeat counts at 1000 and tracks cumulative repeat products across
// nesting, so nothing bigger is constructible — and that ceiling measured
// at 4.3s single-threaded. 5000 sits below that ceiling with real margin
// (go test -fuzz runs multiple workers in parallel sharing CPU, and
// scaling for this pattern family is worse than linear), while staying
// above every other measured pattern, so it only excludes the extreme
// tail rather than typical fuzzer-generated patterns.
const maxNFAInsts = 5000

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
		if prog, err := syntax.Compile(parsed.Simplify()); err == nil && len(prog.Inst) > maxNFAInsts {
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
