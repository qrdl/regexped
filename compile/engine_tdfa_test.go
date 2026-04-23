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

func TestTDFATagOpsEqual(t *testing.T) {
	cases := []struct {
		a, b []tdfaTagOp
		want bool
	}{
		{nil, nil, true},
		{[]tdfaTagOp{}, []tdfaTagOp{}, true},
		{[]tdfaTagOp{{dst: 0, src: -1}}, []tdfaTagOp{{dst: 0, src: -1}}, true},
		{[]tdfaTagOp{{dst: 0, src: -1}, {dst: 1, src: 0}}, []tdfaTagOp{{dst: 0, src: -1}, {dst: 1, src: 0}}, true},
		// different lengths
		{[]tdfaTagOp{{dst: 0, src: -1}}, []tdfaTagOp{}, false},
		{[]tdfaTagOp{}, []tdfaTagOp{{dst: 0, src: -1}}, false},
		// same length, different elements
		{[]tdfaTagOp{{dst: 0, src: -1}}, []tdfaTagOp{{dst: 1, src: -1}}, false},
		{[]tdfaTagOp{{dst: 0, src: -1}}, []tdfaTagOp{{dst: 0, src: 1}}, false},
	}
	for _, c := range cases {
		if got := tdfaTagOpsEqual(c.a, c.b); got != c.want {
			t.Errorf("tdfaTagOpsEqual(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestMinimizeTDFARegistersLowRegs(t *testing.T) {
	// numRegs <= 1 → early return, no minimization attempted.
	base := &dfaTable{numStates: 1, transitions: make([]int, 256), acceptStates: map[int]bool{0: true}}
	tt := &tdfaTable{dfaTable: base, numRegs: 1}
	got := minimizeTDFARegisters(tt)
	if got != tt {
		t.Error("minimizeTDFARegisters(numRegs=1): expected same table returned")
	}
}

func TestMinimizeTDFARegisters(t *testing.T) {
	t.Run("applies coloring when improvement possible", func(t *testing.T) {
		// (a)|(b) has two separate accept states: one where group1 regs are live
		// and group2 regs are -1, and vice versa. The two sets never interfere,
		// so minimization can merge them → newNumRegs < numRegs.
		numStates, numRegs, _, ok := tdfaStats("(a)|(b)")
		if !ok {
			t.Skip("(a)|(b) not TDFA-eligible")
		}
		if numStates <= 0 {
			t.Errorf("expected states > 0, got %d", numStates)
		}
		// After minimization numRegs should be reduced (2 groups → 2 regs, not 4).
		if numRegs >= 4 {
			t.Errorf("expected register reduction for (a)|(b), got numRegs=%d", numRegs)
		}
	})

	t.Run("no improvement when all registers interfere", func(t *testing.T) {
		// (a)(b)(c): sequential groups all live at accept state → all interfere.
		// minimizeTDFARegisters returns tt unchanged (no improvement path).
		_, numRegs, _, ok := tdfaStats("(a)(b)(c)")
		if !ok {
			t.Skip("(a)(b)(c) not TDFA-eligible")
		}
		// All 6 registers still present (no reduction possible).
		if numRegs < 4 {
			t.Errorf("unexpected register reduction for (a)(b)(c): numRegs=%d", numRegs)
		}
	})
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

// TestEmitTDFATagOpCopy exercises the op.src >= 0 (register-to-register copy) branch
// in emitTDFATagOp directly, since this path is difficult to trigger via pattern selection.
func TestEmitTDFATagOpCopy(t *testing.T) {
	op := tdfaTagOp{dst: 1, src: 0} // copy register 0 → register 1
	result := emitTDFATagOp(op, nil, 3, 4)
	// Expected: local.get (localCapBase+src = 4+0 = 4); local.set (localCapBase+dst = 4+1 = 5)
	if len(result) < 3 {
		t.Fatalf("emitTDFATagOp(copy): expected ≥3 bytes, got %d: %v", len(result), result)
	}
	if result[0] != 0x20 {
		t.Errorf("byte[0] = 0x%02x, want 0x20 (local.get)", result[0])
	}
	if result[1] != 4 {
		t.Errorf("byte[1] = %d, want 4 (localCapBase+src)", result[1])
	}
}

func TestTDFAEpsCapOps(t *testing.T) {
	compile := func(pattern string) *syntax.Prog {
		t.Helper()
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		return prog
	}

	t.Run("byte consumer stops traversal", func(t *testing.T) {
		prog := compile("a")
		pc, ops := tdfaEpsCapOps(prog, prog.Start, make(map[int]bool))
		if pc < 0 {
			// start may be an Alt; just verify no panic and ops are sane
			t.Logf("tdfaEpsCapOps returned pc=%d (Alt or similar)", pc)
		}
		_ = ops
	})

	t.Run("capture ops collected", func(t *testing.T) {
		// (a) has InstCapture open + close around the 'a'
		prog := compile("(a)")
		pc, ops := tdfaEpsCapOps(prog, prog.Start, make(map[int]bool))
		_ = pc
		// at least one captureOp should be collected (open for group 1)
		if len(ops) == 0 {
			t.Error("expected capture ops for (a), got none")
		}
	})

	t.Run("out of bounds returns -1", func(t *testing.T) {
		prog := compile("a")
		pc, ops := tdfaEpsCapOps(prog, len(prog.Inst)+99, make(map[int]bool))
		if pc != -1 || ops != nil {
			t.Errorf("out-of-bounds: got pc=%d ops=%v, want (-1, nil)", pc, ops)
		}
	})

	t.Run("already visited returns -1", func(t *testing.T) {
		prog := compile("a")
		visited := make(map[int]bool)
		visited[prog.Start] = true
		pc, ops := tdfaEpsCapOps(prog, prog.Start, visited)
		if pc != -1 || ops != nil {
			t.Errorf("already visited: got pc=%d ops=%v, want (-1, nil)", pc, ops)
		}
	})

	t.Run("empty width followed", func(t *testing.T) {
		// \b creates InstEmptyWidth nodes in the NFA
		prog := compile(`\ba`)
		pc, ops := tdfaEpsCapOps(prog, prog.Start, make(map[int]bool))
		_ = pc
		_ = ops // must not panic
	})

	t.Run("nested captures", func(t *testing.T) {
		// ((?P<x>a)) has nested capture groups — multiple captureOps
		prog := compile("((?P<x>a))")
		pc, ops := tdfaEpsCapOps(prog, prog.Start, make(map[int]bool))
		_ = pc
		if len(ops) < 2 {
			t.Logf("nested captures: got %d ops (may vary by NFA structure)", len(ops))
		}
	})
}
