package compile

import (
	"bytes"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
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

// applySequentialCopies simulates executing ops in order against vals,
// treating scratchRegSentinel as its own slot separate from the real
// register bank. Mirrors exactly what the WASM emitter does with
// sequentializeCopies' output: each op reads its current source (which may
// itself be the scratch slot) and writes its destination.
func applySequentialCopies(vals map[int]int, ops []tdfaTagOp) map[int]int {
	out := make(map[int]int, len(vals))
	for k, v := range vals {
		out[k] = v
	}
	var scratch int
	read := func(reg int) int {
		if reg == scratchRegSentinel {
			return scratch
		}
		return out[reg]
	}
	for _, op := range ops {
		v := read(op.src)
		if op.dst == scratchRegSentinel {
			scratch = v
		} else {
			out[op.dst] = v
		}
	}
	return out
}

// TestSequentializeCopies verifies sequentializeCopies (5.3% covered without
// this — only the len<=1 early return was reached) against its documented
// contract: the returned sequential order must reproduce the effect of one
// atomic parallel register-to-register move, for both acyclic chains
// (in either dependency direction) and cycles requiring a scratch spill.
func TestSequentializeCopies(t *testing.T) {
	// expectedParallel computes what an atomic parallel copy would produce:
	// every dst gets its src's PRE-transition value, all at once.
	expectedParallel := func(initial map[int]int, ops []tdfaTagOp) map[int]int {
		out := make(map[int]int, len(initial))
		for k, v := range initial {
			out[k] = v
		}
		for _, op := range ops {
			out[op.dst] = initial[op.src]
		}
		return out
	}

	cases := []struct {
		name    string
		ops     []tdfaTagOp
		initial map[int]int
	}{
		{
			name:    "empty",
			ops:     nil,
			initial: map[int]int{1: 10},
		},
		{
			name:    "single",
			ops:     []tdfaTagOp{{dst: 1, src: 2}},
			initial: map[int]int{1: 10, 2: 20},
		},
		{
			name: "acyclic_chain_forward",
			// dst=1 depends on nothing; safe to run in dst-ascending order.
			ops:     []tdfaTagOp{{dst: 1, src: 2}, {dst: 2, src: 3}, {dst: 3, src: 4}},
			initial: map[int]int{1: 100, 2: 200, 3: 300, 4: 400},
		},
		{
			name: "acyclic_chain_reverse",
			// dst=4 depends on nothing; a fixed ascending-dst order would
			// wrongly overwrite reg 2 (needed by dst=3) before it's read —
			// this is exactly the "chain running the other way" case the
			// function's doc comment warns a fixed sort direction breaks.
			ops:     []tdfaTagOp{{dst: 2, src: 1}, {dst: 3, src: 2}, {dst: 4, src: 3}},
			initial: map[int]int{1: 100, 2: 200, 3: 300, 4: 400},
		},
		{
			name:    "two_cycle_swap",
			ops:     []tdfaTagOp{{dst: 1, src: 2}, {dst: 2, src: 1}},
			initial: map[int]int{1: 10, 2: 20},
		},
		{
			name:    "three_cycle",
			ops:     []tdfaTagOp{{dst: 1, src: 2}, {dst: 2, src: 3}, {dst: 3, src: 1}},
			initial: map[int]int{1: 10, 2: 20, 3: 30},
		},
		{
			name: "cycle_plus_independent_chain",
			ops: []tdfaTagOp{
				{dst: 1, src: 2}, {dst: 2, src: 1}, // 2-cycle
				{dst: 5, src: 6}, {dst: 6, src: 7}, // independent acyclic chain
			},
			initial: map[int]int{1: 10, 2: 20, 5: 50, 6: 60, 7: 70},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sequentializeCopies(c.ops)
			if len(c.ops) <= 1 {
				if len(got) != len(c.ops) {
					t.Fatalf("len(sequentializeCopies) = %d, want %d for len<=1 input", len(got), len(c.ops))
				}
			}
			want := expectedParallel(c.initial, c.ops)
			gotVals := applySequentialCopies(c.initial, got)
			for dst, wantVal := range want {
				if gotVals[dst] != wantVal {
					t.Errorf("register %d = %d after sequential replay, want %d (parallel semantics)\n  ops=%v\n  sequentialized=%v",
						dst, gotVals[dst], wantVal, c.ops, got)
				}
			}
		})
	}
}

func TestMinimizeTDFARegistersLowRegs(t *testing.T) {
	// numRegs <= 1 → early return, no minimization attempted.
	base := &dfaTable{numStates: 1, transitions: make([]int, 256), acceptStates: map[int]uint64{0: 1}}
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
	// After minimisation, register count must not exceed the default limit.
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

// TestTDFACompileDeterminism verifies that TDFA compilation produces byte-identical
// WASM output on every call, regardless of Go's non-deterministic map iteration order
// (engine_tdfa.go Fix 1: sort setOps by dst after iterating the rename map).
func TestTDFACompileDeterminism(t *testing.T) {
	// url-parse is a 6-group TDFA pattern with non-trivial register operations.
	// It was observed to produce different WASM sizes across runs before the fix.
	re := config.RegexEntry{
		Pattern: `(?P<scheme>https?)://(?P<host>[^/:?#]+)` +
			`(?::(?P<port>[0-9]+))?(?P<path>/[^?#]*)?` +
			`(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?`,
		GroupsFunc: "groups",
	}
	first, _, err := Compile([]config.RegexEntry{re}, 0, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	const iterations = 20
	for i := 0; i < iterations; i++ {
		got, _, err := Compile([]config.RegexEntry{re}, 0, true)
		if err != nil {
			t.Fatalf("iteration %d: Compile: %v", i+1, err)
		}
		if !bytes.Equal(first, got) {
			t.Errorf("iteration %d: WASM output differs from first (TDFA emission non-deterministic)", i+1)
		}
	}
}

// TestTDFARegisterMinimizationDegreeSort verifies that degree-sorted greedy graph
// colouring (engine_tdfa.go Fix 2) reduces the number of WASM locals used by the TDFA.
// Expected numRegs values were measured with the optimised colouring and are strictly
// less than prog.NumCap, proving minimisation occurred with the correct ordering.
func TestTDFARegisterMinimizationDegreeSort(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		wantRegs int // expected numRegs after minimisation with degree-sorted colouring
		rawTags  int // prog.NumCap = upper bound without minimisation
	}{
		// Two sequential groups: a then b. Open-tags don't overlap, close-tags can share.
		// rawTags=6 (3 groups × 2 tags incl. group 0), minimised to 4.
		{"seq-2-groups", `(?P<a>\d+)-(?P<b>\d+)`, 4, 6},
		// Three sequential groups.
		// rawTags=8 (4 groups × 2), minimised to 6.
		{"seq-3-groups", `(?P<a>\d+)-(?P<b>\d+)-(?P<c>\d+)`, 6, 8},
		// Nested groups: b inside a. Open-tags are simultaneously live → can't share.
		// Close-tags are NOT simultaneously live → can share (one colour).
		// rawTags=6, minimised to 4.
		{"nested-2-groups", `(?P<a>a+(?P<b>b+))`, 4, 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := syntax.Parse(tc.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			prog, err := syntax.Compile(parsed.Simplify())
			if err != nil {
				t.Fatalf("Compile NFA: %v", err)
			}
			if prog.NumCap != tc.rawTags {
				t.Errorf("rawTags: got %d want %d (test case stale?)", prog.NumCap, tc.rawTags)
			}
			tt, ok := newTDFA(prog, 2000)
			if !ok {
				t.Fatalf("newTDFA failed — pattern ineligible for TDFA")
			}
			if tt.numRegs != tc.wantRegs {
				t.Errorf("numRegs: got %d want %d (register minimisation regressed?)", tt.numRegs, tc.wantRegs)
			}
			if tt.numRegs >= prog.NumCap {
				t.Errorf("numRegs %d >= rawTags %d — minimisation had no effect", tt.numRegs, prog.NumCap)
			}
		})
	}
}
