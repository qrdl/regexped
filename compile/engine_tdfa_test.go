package compile

import (
"testing"
)

func TestTDFAStats(t *testing.T) {
cases := []struct {
pattern string
wantOK  bool
}{
// Simple capture: TDFA-eligible.
{"(a+)", true},
// Named capture.
{"(?P<x>foo)+", true},
// Patterns with non-greedy return ok=true from TDFAStats (it builds the table
// regardless); use SelectEngine to check what engine is actually used.
// Here we just verify ok=true for eligible patterns.
}
for _, c := range cases {
_, _, _, ok := TDFAStats(c.pattern)
if ok != c.wantOK {
t.Errorf("TDFAStats(%q).ok = %v, want %v", c.pattern, ok, c.wantOK)
}
}
}

func TestTDFAStatsValues(t *testing.T) {
numStates, numRegs, totalTagOps, ok := TDFAStats("(a+)")
if !ok {
t.Fatal("TDFAStats((a+)): expected ok=true")
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
_, numRegs, _, ok := TDFAStats("(a+)(b+)(c+)")
if !ok {
t.Skip("pattern not TDFA-eligible")
}
if numRegs > resolveMaxTDFARegs(nil) {
t.Errorf("numRegs %d exceeds default limit %d", numRegs, resolveMaxTDFARegs(nil))
}
}
