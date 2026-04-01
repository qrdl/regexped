package compile

import (
	"regexp/syntax"
	"testing"
)

// tdfaStats compiles pattern to TDFA and returns state/register/op counts.
// Uses a high state limit (2000) so it never returns (0,0,0,false) due to the cap.
// Returns (0,0,0,false) only if the pattern fails to parse or compile as NFA.
func tdfaStats(pattern string) (numStates, numRegs, totalTagOps int, ok bool) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return
	}
	tt, success := newTDFA(prog, 2000)
	if !success {
		numStates = -1
		ok = false
		return
	}
	numStates = tt.numStates
	numRegs = tt.numRegs
	for _, ops := range tt.tagOps {
		totalTagOps += len(ops)
	}
	ok = true
	return
}

func TestTDFAStats(t *testing.T) {
	cases := []struct {
		pattern string
		wantOK  bool
	}{
		// Simple capture: TDFA-eligible.
		{"(a+)", true},
		// Named capture.
		{"(?P<x>foo)+", true},
		// Patterns with non-greedy return ok=true from tdfaStats (it builds the table
		// regardless); use SelectEngine to check what engine is actually used.
		// Here we just verify ok=true for eligible patterns.
	}
	for _, c := range cases {
		_, _, _, ok := tdfaStats(c.pattern)
		if ok != c.wantOK {
			t.Errorf("tdfaStats(%q).ok = %v, want %v", c.pattern, ok, c.wantOK)
		}
	}
}

func TestTDFAStatsValues(t *testing.T) {
	numStates, numRegs, totalTagOps, ok := tdfaStats("(a+)")
	if !ok {
		t.Fatal("tdfaStats((a+)): expected ok=true")
	}
	if numStates <= 0 {
		t.Errorf("numStates = %d, want > 0", numStates)
	}
	if numRegs <= 0 {
		t.Errorf("numRegs = %d, want > 0", numRegs)
	}
	if totalTagOps <= 0 {
		t.Errorf("totalTagOps = %d, want > 0", totalTagOps)
	}
}

func TestTDFARegisterMinimization(t *testing.T) {
	// After minimization, register count should not exceed the default limit.
	_, numRegs, _, ok := tdfaStats("(a+)(b+)(c+)")
	if !ok {
		t.Skip("pattern not TDFA-eligible")
	}
	if numRegs > resolveMaxTDFARegs(nil) {
		t.Errorf("numRegs %d exceeds default limit %d", numRegs, resolveMaxTDFARegs(nil))
	}
}
