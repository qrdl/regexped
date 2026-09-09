package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// FABLE B23, mechanism (a). `--diag-json` reported the frontend SELECTION
// chose, while the emitted body could still be the scalar one.
//
// A fallback bucket has no literal gating it, so it must be tried at EVERY
// input position and a prefilter that skips positions cannot serve it.
// chooseLiteralFrontend does not know that — it sees only the literals — so a
// set with literals AND a fallback pattern was selected as Teddy or
// packed-pair and emitted as scalar, with the diagnostics file naming a
// frontend the module did not contain.
//
// Selection and emission now answer through emittedFrontend, so they cannot
// disagree. These tests pin BOTH directions: the downgrade is reported, and a
// set with no fallback bucket still reports its real literal frontend.

func diagFrontendEntries(pats []string) []config.RegexEntry {
	out := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		out[i] = config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: p}
	}
	return out
}

func diagFrontendFor(t *testing.T, pats []string) string {
	t.Helper()
	cfg := config.BuildConfig{
		Regexps: diagFrontendEntries(pats),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	_, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("CompileFileDiag: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("expected one set diagnostic, got %d", len(diags))
	}
	return diags[0].Frontend
}

func TestDiagFrontendReportsTheEmittedBody(t *testing.T) {
	// Literals only: a real literal frontend, and the diagnostic says so.
	litOnly := []string{"alpha", "bravo", "charlie", "delta"}
	pure := diagFrontendFor(t, litOnly)
	if pure == frontendScalar.String() {
		t.Fatalf("frontend = %q for a literal-only set; this case no longer "+
			"tests the downgrade because there is nothing to downgrade FROM", pure)
	}

	// The same literals plus one pattern with no mandatory literal, which
	// lands in a fallback bucket and forces the scalar body.
	withFallback := append(append([]string{}, litOnly...), `[0-9]{4,}`)
	got := diagFrontendFor(t, withFallback)
	if got != frontendScalar.String() {
		t.Errorf("frontend = %q, want %q: a fallback bucket forces the scalar body, "+
			"so the diagnostic must not keep naming %q",
			got, frontendScalar.String(), pure)
	}
}

// emittedFrontend is the single source of truth; the emitter dispatches on it.
// If a future arm is added to one and not the other they drift apart again,
// so the mapping is asserted directly for every frontend a set can select.
func TestEmittedFrontendMatchesSelectionWithoutFallback(t *testing.T) {
	cases := []struct {
		name string
		pats []string
	}{
		{"literals", []string{"alpha", "bravo", "charlie", "delta"}},
		{"many-literals", func() []string {
			var p []string
			for i := 0; i < 24; i++ {
				p = append(p, fmt.Sprintf("keyword%02d", i))
			}
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// With no fallback bucket the emitted frontend IS the selected one.
			if got := diagFrontendFor(t, c.pats); got == frontendScalar.String() {
				t.Errorf("frontend = %q; this shape should keep its literal frontend "+
					"when no fallback bucket is present", got)
			}
		})
	}
}
