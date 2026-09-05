package compile

import "testing"

// twinLayout builds a find layout the way compilePattern does, with
// lnmAction5 set as a prefer-no-match compile would set it.
func twinLayout(t *testing.T, pattern string, lnm bool) (*dfaLayout, *dfaTable) {
	t.Helper()
	m, err := compile(pattern, CompileOptions{
		MaxDFAStates: 4096, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile(%q): %v", pattern, err)
	}
	table := dfaTableFrom(m.(*dfa))
	l := buildDFALayout(dfaLayoutParams{
		t: table, tableBase: 0, needFind: true, leftmostFirst: true,
		compiledDFAThreshold: resolveCompiledDFAThreshold(&CompileOptions{}),
	})
	l.lnmAction5 = lnm
	return l, table
}

// TestFindNeutralTwinEmission pins WHEN a neutral twin is emitted and, just as
// importantly, when it is not.
//
// The twin exists so the adaptive dense switch can hand the rest of a call to a
// body with no gate at all, rather than paying two instructions per attempt for
// the remainder — ~40,000 of them on a 50 KB scan. It is worth emitting only
// where that switch exists, so the predicate here and the one inside
// emitPrefixScan have to agree; they are the same call to shuftiPrefixPlan for
// that reason.
//
// Both DISPATCH SHAPES are covered on purpose. `[a-zA-Z]{20,}` stays under the
// 256-state threshold and compiles through the hybrid (Compiled DFA) body;
// `[a-zA-Z]{300,}` does not, and takes the plain table-driven one. The two are
// separate emitters with separate params literals, and a field filled in only
// one of them is exactly how the chain probe and soleMidDominant each went
// silently dead on their own target pattern earlier.
func TestFindNeutralTwinEmission(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		lnm      bool
		wantTwin bool
		hybrid   bool
	}{
		{"hybrid, hinted", `[a-zA-Z]{20,}`, true, true, true},
		{"hybrid, neutral", `[a-zA-Z]{20,}`, false, false, true},
		{"plain dfa, hinted", `[a-zA-Z]{300,}`, true, true, false},
		{"plain dfa, neutral", `[a-zA-Z]{300,}`, false, false, false},
		// A mandatory literal fronts the scan, so there is no dense switch to
		// escape from and nothing to hand off to.
		{"mandatory literal", `ERROR[a-zA-Z]{20,}`, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, table := twinLayout(t, tc.pattern, tc.lnm)
			if l.useHybridDispatch != tc.hybrid {
				t.Fatalf("useHybridDispatch = %v, want %v — the case no longer "+
					"covers the dispatch shape it was written for",
					l.useHybridDispatch, tc.hybrid)
			}
			_, _, twin, patch := appendFindCodeEntryTwinned(
				nil, l, table, findMandatoryLit(tc.pattern), 0)
			if (twin != nil) != tc.wantTwin {
				t.Errorf("twin emitted = %v, want %v", twin != nil, tc.wantTwin)
			}
			// The twin and its handoff call-site patch are emitted together or
			// not at all; compilePattern panics on the mismatch, so the pairing
			// is worth asserting where it is cheap to.
			if (twin != nil) != (patch >= 0) {
				t.Errorf("twin=%v but patch offset=%d — the two must agree",
					twin != nil, patch)
			}
			if twin != nil && len(twin) == 0 {
				t.Error("twin is non-nil but empty")
			}
		})
	}
}
