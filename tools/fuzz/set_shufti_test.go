package fuzz

import (
	"fmt"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// The Shufti frontend, checked against Go for the first time.
//
// `make set-coverage` reported 39 of 40 set emitters reached by the tests that
// check answers. The one exception was `emitSetMatchFnFinalShufti` —
// compile/set_emit.go, 215 lines of SIMD first-byte prefilter — and tracing why
// gave a worse answer than "nobody wrote a shape for it":
//
//   - Shufti is selected only from the SCALAR branch, which needs Aho-Corasick
//     to decline first;
//   - AC declines only when its table would exceed ACBudgetBytes, default
//     512 KB (compile/set.go);
//   - `ACBudgetBytes` lives on CompileSetOptions, which no module-building
//     entry point accepted — `CompileSet` is exported but returns an unexported
//     type, and everything else took only a config.BuildConfig.
//
// So no test that can RUN a module could produce a Shufti one. Two tests in
// package `compile` reach the emitter (`TestSetHintsSelectsShuftiFrontend` and
// `setEmitCovShuftiSet`), but that package has no wasmtime: they assert the
// frontend was SELECTED and that a body was emitted, never what it answers.
//
// The path is not dead code — a large enough literal set exceeds AC's budget in
// production and lands here. `ACBudgetBytes: 1`, via the CompileFileOpts entry
// added for this, simulates that condition without building a set of that size.

// shuftiPatterns builds a set that selects the Shufti frontend: more literals
// than Teddy accepts (teddyMaxLiterals is 64), with first bytes cycling
// \x01..\x1f — 31 distinct, inside Shufti's 17..64 band, and all rarity 0 so
// the adaptive density trigger stays off. Modelled on `setEmitCovShuftiSet` in
// package compile, which established this shape.
func shuftiPatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`\x%02xqq%02dxx[a-z]+`, 1+i%31, i)
	}
	return out
}

// compileCapsShufti is compileCaps with AC forced out of budget.
func compileCapsShufti(t *testing.T, pats []string, overlapping bool) []byte {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
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
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileOpts(
		config.BuildConfig{Regexps: entries, Sets: sets}, "",
		compile.CompileSetOptions{ACBudgetBytes: 1})
	if err != nil {
		t.Fatalf("compile shufti set: %v", err)
	}
	// Without this the test silently degrades into a second scalar-frontend
	// case the moment selection changes — which is exactly how the emitter
	// went unchecked in the first place.
	if len(diags) != 1 {
		t.Fatalf("got %d set diagnostics, want 1", len(diags))
	}
	if diags[0].Frontend != "shufti" {
		t.Fatalf("frontend = %q, want \"shufti\" — this set no longer reaches "+
			"emitSetMatchFnFinalShufti, so the test is checking something else",
			diags[0].Frontend)
	}
	if n := len(droppedFromSet(diags)); n != 0 {
		t.Fatalf("%d patterns dropped from the set; the oracle would compare "+
			"against patterns the engine was never asked to build", n)
	}
	return w
}

func TestSetShuftiFrontendAgainstOracle(t *testing.T) {
	pats := shuftiPatterns(65) // one past teddyMaxLiterals

	// Inputs are short on purpose: checkCapsAgainstOracle sweeps every `from`
	// and evaluates all 65 patterns at each, so length is quadratic-ish here.
	inputs := []string{
		"",
		"\x01qq00xxabc",                 // pattern 0 matches
		"zz\x02qq01xxdef",               // pattern 1, not at position 0
		"\x01qq00xxab \x02qq01xxcd",     // two patterns, two positions
		"\x03qq02xx",                    // first bytes present, suffix absent
		"nothing here at all",           // no first byte present
		strings.Repeat("q", 40),         // long, no candidate
		"\x01qq00xxaaaaaaaaaaaaaaaaaaa", // one long match
	}
	for i, input := range inputs {
		t.Run(fmt.Sprintf("input%d", i), func(t *testing.T) {
			w := compileCapsShufti(t, pats, true)
			r := newCapRunnerFrom(t, w, pats, input)
			defer r.Close()
			checkCapsAgainstOracle(t, r, pats, input)
		})
	}
}
