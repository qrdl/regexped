package compile

import (
	"bytes"
	"fmt"
	"math/bits"
	"math/rand"
	"reflect"
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

// TestTDFAAllZeroTagOpsSkip exercises the "if !anyHasOps { return b }" early
// skip in emitTDFATagOps, reached when the whole TDFA transition table has
// zero register-set/copy ops. a has one zero-width capture
// group, resolved entirely via entry ops before the first byte-consuming
// transition (anyHasOps=false).
func TestTDFAAllZeroTagOpsSkip(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "()a", GroupsFunc: "g"}})
}

// TestTDFAMinimizeRegistersApplyColoring exercises the block in
// minimizeTDFARegisters that rewrites tagOps/acceptOps/acceptRegMap after
// graph coloring finds a real register-count reduction (guarded by
// newNumRegs < numRegs). Two alternated, order-swapped
// capture groups inside a `+` loop give the construction-time canonical
// register numbering more registers than liveness analysis actually needs.
// Confirmed live: numRegs is minimised to 19 (well below the raw tag count),
// and TestMinimizeTDFARegisters-style patterns never hit this because their
// canonical numbering is already minimal.
func TestTDFAMinimizeRegistersApplyColoring(t *testing.T) {
	const pattern = `(?:(a+)(b+)|(b+)(a+))+`
	numStates, numRegs, _, ok := tdfaStats(pattern)
	if !ok {
		t.Fatalf("tdfaStats(%q): pattern ineligible for TDFA", pattern)
	}
	t.Logf("numStates=%d numRegs=%d", numStates, numRegs)
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
}

// TestTDFAU16TableAddressing exercises the useU8=false (2-byte state ID)
// branch of buildTDFAMatchBody/emitTDFATagOps. Bounded
// repetition unrolls into many states without necessarily blowing up
// register count: confirmed live via newTDFA, this pattern has 511 states
// (> 256, forcing u16) and 24 registers (within the default 32-register
// limit) — only u8 TDFA tables were previously exercised.
func TestTDFAU16TableAddressing(t *testing.T) {
	const pattern = `(\w{1,10}-){1,20}(\d{1,10}){1,10}`
	numStates, _, _, ok := tdfaStats(pattern)
	if !ok {
		t.Fatalf("tdfaStats(%q): pattern ineligible for TDFA", pattern)
	}
	if numStates <= 256 {
		t.Fatalf("tdfaStats(%q): numStates = %d, want > 256 (u16 table)", pattern, numStates)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
}

// TestTDFAEpsWalkAltFallthrough exercises the "try inst.Arg after inst.Out
// fails" fallback in tdfaEpsCapOps/tdfaEpsCapOpsTo's InstAlt handling.
// (?:(a)|(b)): the nested alternation's Out branch doesn't
// reach the target/capture being searched for, so the epsilon walk must
// fall through to Arg. Top-level Op is OpAlternate (not OpCapture/OpConcat),
// so the whole-pattern-single-capture shortcut never applies
// regardless of MaxCap — confirmed live.
func TestTDFAEpsWalkAltFallthrough(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:(a)|(b))`, GroupsFunc: "g"}})
}

// TestTDFAStartThreadOffMainEntry exercises startThreads[i]'s capture-op
// discovery via tdfaEpsCapOpsTo for a start PC that isn't the main entry
// target (newTDFA's comment: "e.g. (a*) reaching InstMatch").
// (a*) alone reaches InstMatch via a pure-epsilon path from Start, exactly
// the mechanism this targets — but it also trips the whole-pattern-
// single-capture shortcut (MaxCap()==1, confirmed live), which would bypass
// TDFA construction entirely. (a*)(b*) keeps both groups nullable (so
// InstMatch is still reachable via pure epsilon from Start, preserving the
// mechanism) while MaxCap()==2 keeps clear of the shortcut.
func TestTDFAStartThreadOffMainEntry(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a*)(b*)", GroupsFunc: "g"}})
}

func newTDFAForPattern(t *testing.T, pattern string) *tdfaTable {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", pattern, err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	tt, ok := newTDFA(prog, 2000)
	if !ok {
		t.Fatalf("newTDFA rejected pattern %q", pattern)
	}
	return tt
}

func TestDetectTDFABulkSkipAccept(t *testing.T) {
	cases := []struct {
		name       string
		pattern    string
		minSelfLen int
	}{
		{"word-class", `(\w+)`, 60},
		{"lower-class", `<([a-z]+)>`, 24},
		// Constructed via newTDFA directly, bypassing selectBestEngine — note
		// this exact pattern is routed to Backtracking in production because
		// the trailing Y overlaps the [a-zA-Z] self-loop class, triggering
		// hasAmbiguousCaptures. This test is only
		// exercising the detector in isolation, not real engine selection.
		{"letter-class", `X([a-zA-Z]+)Y`, 50},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tt := newTDFAForPattern(t, c.pattern)
			info := detectTDFABulkSkip(tt)
			if info == nil {
				t.Fatalf("detectTDFABulkSkip(%q) = nil, want non-nil", c.pattern)
			}
			if len(info.selfLoopBytes) < c.minSelfLen {
				t.Errorf("selfLoopBytes = %d bytes, want >= %d", len(info.selfLoopBytes), c.minSelfLen)
			}
			for _, op := range info.ops {
				if op.src != -1 {
					t.Errorf("op %+v is not set-to-pos (src=%d)", op, op.src)
				}
			}
			gs := int(info.wasmState) - 1
			count := 0
			for bv := 0; bv < 256; bv++ {
				if tt.transitions[gs*256+bv] == gs {
					count++
				}
			}
			if count != len(info.selfLoopBytes) {
				t.Errorf("independent self-loop recount = %d, detector reported %d", count, len(info.selfLoopBytes))
			}
		})
	}
}

// buildTestTDFATable hand-builds a single-state tdfaTable (state 0 only) that
// self-loops on selfLoopBytes, firing ops on every one of them. Bytes not in
// selfLoopBytes are dead transitions. Used to construct detector reject cases
// that are impractical to reach via a real pattern.
func buildTestTDFATable(selfLoopBytes []byte, ops []tdfaTagOp, immediateAccept bool) *tdfaTable {
	trans := make([]int, 256)
	for i := range trans {
		trans[i] = -1
	}
	tagOps := make([][]tdfaTagOp, 256)
	for _, bv := range selfLoopBytes {
		trans[bv] = 0
		tagOps[bv] = ops
	}
	imm := map[int]uint64{}
	if immediateAccept {
		imm[0] = 1
	}
	dt := &dfaTable{
		numStates:             1,
		transitions:           trans,
		immediateAcceptStates: imm,
	}
	return &tdfaTable{dfaTable: dt, tagOps: tagOps}
}

func bytesRange(n int) []byte {
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = byte(i)
	}
	return bs
}

func TestDetectTDFABulkSkipReject(t *testing.T) {
	setOp := []tdfaTagOp{{dst: 0, src: -1}}

	t.Run("non-uniform-ops", func(t *testing.T) {
		trans := make([]int, 256)
		for i := range trans {
			trans[i] = -1
		}
		tagOps := make([][]tdfaTagOp, 256)
		for bv := 0; bv < 10; bv++ {
			trans[bv] = 0
			if bv < 5 {
				tagOps[bv] = []tdfaTagOp{{dst: 0, src: -1}}
			} else {
				tagOps[bv] = []tdfaTagOp{{dst: 1, src: -1}}
			}
		}
		tt := &tdfaTable{dfaTable: &dfaTable{numStates: 1, transitions: trans, immediateAcceptStates: map[int]uint64{}}, tagOps: tagOps}
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("non-uniform tag ops on self-loop must be rejected, got %+v", info)
		}
	})

	t.Run("copy-op", func(t *testing.T) {
		copyOp := []tdfaTagOp{{dst: 0, src: 1}}
		tt := buildTestTDFATable(bytesRange(20), copyOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("copy-op self-loop must be rejected (out of v1 scope), got %+v", info)
		}
	})

	t.Run("too-few-bytes", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(tdfaBulkSkipMinBytes-1), setOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("self-loop below min size must be rejected, got %+v", info)
		}
	})

	t.Run("too-many-bytes", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(tdfaBulkSkipMaxBytes+1), setOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("self-loop above max size must be rejected, got %+v", info)
		}
	})

	t.Run("immediate-accept-state", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(20), setOp, true)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("immediate-accept state must be excluded from candidacy, got %+v", info)
		}
	})

	t.Run("qualifying-boundary-sizes", func(t *testing.T) {
		for _, n := range []int{tdfaBulkSkipMinBytes, tdfaBulkSkipMaxBytes} {
			tt := buildTestTDFATable(bytesRange(n), setOp, false)
			info := detectTDFABulkSkip(tt)
			if info == nil {
				t.Errorf("self-loop of exactly %d bytes should qualify", n)
				continue
			}
			if len(info.selfLoopBytes) != n {
				t.Errorf("n=%d: selfLoopBytes = %d, want %d", n, len(info.selfLoopBytes), n)
			}
		}
	})
}

// decodeControlFlow walks emitted WASM bytecode that uses only the fixed
// instruction set emitTDFABulkSkip/emitShuftiPrefixCheck emit, and returns
// the sequence of control-flow instructions (block/loop/if/else/end/br/
// br_if) encountered, with br/br_if immediates rendered inline. All other
// instructions are decoded just far enough to skip their operands. This
// independently verifies the block/loop/if nesting and branch depths
// without needing a live WASM runtime — the only way to catch a
// depth-arithmetic bug that isn't also a validator error (an off-by-one branch depth is still a *valid* WASM program, just
// one that jumps to the wrong place).
func decodeControlFlow(t *testing.T, b []byte) []string {
	t.Helper()
	var ops []string
	i := 0
	skipLEB := func() {
		for i < len(b) && b[i]&0x80 != 0 {
			i++
		}
		i++
	}
	readDepth := func() byte {
		start := i
		skipLEB()
		if start >= len(b) {
			t.Fatalf("decodeControlFlow: truncated branch immediate at byte %d", start)
		}
		return b[start]
	}
	for i < len(b) {
		op := b[i]
		switch op {
		case 0x02: // block
			i++
			i++ // blocktype
			ops = append(ops, "block")
		case 0x03: // loop
			i++
			i++
			ops = append(ops, "loop")
		case 0x04: // if
			i++
			i++
			ops = append(ops, "if")
		case 0x05: // else
			i++
			ops = append(ops, "else")
		case 0x0B: // end
			i++
			ops = append(ops, "end")
		case 0x0C: // br
			i++
			d := readDepth()
			ops = append(ops, fmt.Sprintf("br %d", d))
		case 0x0D: // br_if
			i++
			d := readDepth()
			ops = append(ops, fmt.Sprintf("br_if %d", d))
		case 0x20, 0x21, 0x22, 0x41: // local.get/set/tee, i32.const
			i++
			skipLEB()
		case 0x45, 0x46, 0x47, 0x4B, 0x4F, 0x6A, 0x6B, 0x68, 0x73, 0x76: // eqz, eq, ne, gt_u, ge_u, add, sub, ctz, xor, shr_u
			i++
		case 0xFD: // SIMD prefix
			i++
			sub := b[i]
			i++
			switch sub {
			case 0x00: // v128.load: align, offset
				skipLEB()
				skipLEB()
			case 0x0C: // v128.const: 16 raw bytes
				i += 16
			case 0x0E, 0x0F, 0x23, 0x24, 0x4E, 0x50, 0x64, 0x6D:
				// swizzle, splat, eq, ne, and, or, bitmask, shr_u — no
				// immediates. eq joined the list when the bulk skip switched to
				// the STOP polarity (emitShuftiStopMask): it compares the merged
				// lanes against zero instead of taking a member mask and
				// inverting it with an i32 xor.
			default:
				t.Fatalf("decodeControlFlow: unhandled SIMD subopcode 0x%02x at byte %d", sub, i-2)
			}
		default:
			t.Fatalf("decodeControlFlow: unhandled opcode 0x%02x at byte %d", op, i)
		}
	}
	return ops
}

// bulkSkipWantShape is the control-flow shape emitTDFABulkSkip must produce.
//
// Shared by both shape tests so the two cannot drift apart, and spelled out
// rather than compared against a golden dump because the POINT of the test is
// that a reader can see the nesting is what the emitter's comments claim.
//
// The leading `if` nest is the overlapping tail probe: the loop no longer
// abandons a run when fewer than 16 bytes remain, it takes one more chunk
// backwards from the end and masks off the lanes it has already passed. Before
// that landed this began `br_if 1`, straight out to $skip_done.
func bulkSkipWantShape() []string {
	return []string{
		"block", // $skip_done
		"loop",  // $chunks
		"if",    // pos + 16 > len: the tail probe
		"if",    //   len >= 16: a full window exists
		"if",    //     mask == 0: every remaining byte self-loops
		"else",  //     otherwise stop on the first exit byte
		"end",
		"end",  //   end $tail_window
		"br 2", //   -> $skip_done either way
		"end",  // end $tail
		"if",   // mask == 0 (the full-chunk path)
		"br 1", // continue $chunks
		"else",
		"br 2", // break $skip_done
		"end",  // end if
		"end",  // end loop $chunks
		"end",  // end block $skip_done
		"if",   // pos != skipStart
		"br 2", // loop back to $main
		"end",  // end if
	}
}

func TestEmitTDFABulkSkipShape(t *testing.T) {
	info := &tdfaBulkSkipInfo{
		wasmState:     5,
		selfLoopBytes: bytesRange(20),
		ops:           []tdfaTagOp{{dst: 0, src: -1}},
	}
	const (
		localPos       = 3
		localChunk     = 10
		localMask      = 11
		localSkipStart = 12
		localCapBase   = 7
	)
	b := emitTDFABulkSkip(nil, info, localPos, localChunk, localMask, localSkipStart, localCapBase, nil)

	got := decodeControlFlow(t, b)
	want := bulkSkipWantShape()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control-flow shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestEmitTDFABulkSkipShapeNoTagOps(t *testing.T) {
	// A self-loop with zero tag ops (state that fires no capture writes at
	// all) must still bulk-skip correctly — the "if pos != skipStart" body
	// is simply empty apart from the loop-back branch.
	info := &tdfaBulkSkipInfo{
		wasmState:     5,
		selfLoopBytes: bytesRange(10),
		ops:           nil,
	}
	b := emitTDFABulkSkip(nil, info, 3, 10, 11, 12, 7, nil)
	got := decodeControlFlow(t, b)
	want := bulkSkipWantShape()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control-flow shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestTDFABulkSkipMidAcceptModuleValid compiles whole modules for the
// bulk-skip shapes end to end, so the mid-accept tail is type-checked by
// mustCompileEntries' validator rather than only by the
// control-flow shape decoder above.
//
// The tail is emitted INSIDE emitTDFABulkSkip's "if pos != skipStart" body and
// is followed by `br 2` out to loop $main, so it has to be perfectly balanced:
// emitTDFAWriteCaptures opens a block per TDFA state, and one missing `end`
// would retarget that branch at the wrong label. Nothing in the unit tests
// above would notice — the shape decoder is handed a nil tail.
//
// Behavioural coverage (right capture values, not just a well-formed module)
// lives in tools/fuzz's TestTDFABulkSkipMidAccept, which needs wasmtime.
func TestTDFABulkSkipMidAcceptModuleValid(t *testing.T) {
	// Each pattern's dominant state self-loops on a class of 8..64 bytes AND
	// is mid-accepting, which is exactly the combination that emits the tail.
	for _, pattern := range []string{
		`^([a-z]+)`,
		`^([0-9]+)`,
		`^([a-zA-Z]+)`,
		`^(\w+)`,
		`^([a-z]+)([0-9]*)`,
	} {
		t.Run(pattern, func(t *testing.T) {
			tt := newTDFAForPattern(t, pattern)
			if detectTDFABulkSkip(tt) == nil {
				t.Fatalf("pattern %q no longer has a bulk-skip state — this test would compile nothing relevant", pattern)
			}
			mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
		})
	}
}

// TestSequentializeCopiesMatchesReference pins the fast parallel-copy
// sequencer to the reference implementation it replaced.
//
// The two must agree op for op, not merely produce a valid order: the emitted
// sequence ends up as WASM register moves, and a sequence that orders them
// differently can read a register an earlier move in the same batch already
// overwrote. That failure is silent — the module validates and answers wrongly
// — which is why this is a differential rather than a property test.
//
// Random bijections over a small register pool are exactly the interesting
// input, because a bijection is what the rename produces and cycles (A needs
// B's slot, B needs A's) are what force the scratch-register break.
func TestSequentializeCopiesMatchesReference(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260918))
	var cyclic int
	const iters = 200000
	for iter := 0; iter < iters; iter++ {
		n := 1 + rnd.Intn(10)
		extra := rnd.Intn(3) // some sources outside the destination set
		pool := make([]int, n+extra)
		for i := range pool {
			pool[i] = i
		}
		rnd.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		ops := make([]tdfaTagOp, 0, n)
		ok := true
		for i := 0; i < n; i++ {
			if pool[i] == i { // a self-copy: the rename never emits one
				ok = false
				break
			}
			ops = append(ops, tdfaTagOp{dst: i, src: pool[i]})
		}
		if !ok {
			continue
		}
		want := sequentializeCopiesRoundwise(append([]tdfaTagOp(nil), ops...))
		got := sequentializeCopies(append([]tdfaTagOp(nil), ops...))
		if len(want) != len(got) {
			t.Fatalf("length differs for %v:\n reference %v\n fast      %v", ops, want, got)
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("op %d differs for %v:\n reference %v\n fast      %v", i, ops, want, got)
			}
		}
		if len(want) > len(ops) {
			cyclic++
		}
	}
	// A run that never needed the scratch register would not have tested the
	// cycle-breaking arm at all, which is the half most likely to diverge.
	if cyclic < iters/10 {
		t.Fatalf("only %d of %d cases needed cycle-breaking; the generator is not producing cycles", cyclic, iters)
	}
	t.Logf("%d cases, %d required cycle-breaking through the scratch register", iters, cyclic)
}

// TestBatchEdgeSetsMatchThePairLoops pins minimizeTDFARegisters' per-batch
// interference edges against the pair-at-a-time construction they replaced.
//
// The original added one edge per pair: every (dst_i, dst_j) with i < j, and
// every (dst_i, src_j) with i != j. That is O(len(ops)^2) stores into a dense
// matrix, and on a 900-register batch it was 47% of SelectEngine's whole
// runtime. The shipped version instead ORs a whole mask into one register's
// row at a time, which is `words` machine words instead of |set| stores.
//
// The masks are the easy part. The "i != j" exclusion is not: (dst_i, src_i)
// belongs in the graph only when some OTHER op names the same register, so a
// register named exactly once has to be taken back out of the mask again, on
// BOTH halves of the symmetry. That reasoning is what this test checks — byte
// identity over a corpus cannot, because a corpus may never produce a batch
// with a duplicated dst or a duplicated src.
//
// Coloring reads the matrix only as a set of edges, so equal edge sets give
// equal register assignments and therefore equal emitted bytes.
func TestBatchEdgeSetsMatchThePairLoops(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200000; iter++ {
		numRegs := 1 + rng.Intn(12)
		ops := make([]tdfaTagOp, rng.Intn(6))
		for i := range ops {
			// -1 stands for "no register", which both halves must ignore.
			ops[i].dst = rng.Intn(numRegs + 1)
			if ops[i].dst == numRegs {
				ops[i].dst = -1
			}
			ops[i].src = -1
			if rng.Intn(3) != 0 {
				ops[i].src = rng.Intn(numRegs)
			}
		}
		want := referenceBatchEdges(ops, numRegs)
		got := shippedBatchEdges(ops, numRegs)
		if len(want) != len(got) {
			t.Fatalf("iter %d ops=%+v numRegs=%d: %d edges, want %d\n got  %v\n want %v",
				iter, ops, numRegs, len(got), len(want), got, want)
		}
		for e := range want {
			if !got[e] {
				t.Fatalf("iter %d ops=%+v numRegs=%d: missing edge %v\n got  %v\n want %v",
					iter, ops, numRegs, e, got, want)
			}
		}
	}
}

// referenceBatchEdges is the ORIGINAL construction, kept verbatim so the test
// compares against the algorithm that shipped for months rather than against a
// restatement of the new one.
func referenceBatchEdges(ops []tdfaTagOp, numRegs int) map[[2]int]bool {
	out := map[[2]int]bool{}
	addEdge := func(r1, r2 int) {
		if r1 != r2 && r1 >= 0 && r1 < numRegs && r2 >= 0 && r2 < numRegs {
			out[[2]int{r1, r2}] = true
			out[[2]int{r2, r1}] = true
		}
	}
	for i := 0; i < len(ops); i++ {
		for j := i + 1; j < len(ops); j++ {
			addEdge(ops[i].dst, ops[j].dst)
		}
	}
	for i := 0; i < len(ops); i++ {
		for j := 0; j < len(ops); j++ {
			if i != j && ops[j].src >= 0 {
				addEdge(ops[i].dst, ops[j].src)
			}
		}
	}
	return out
}

// shippedBatchEdges mirrors minimizeTDFARegisters' addBatchEdges. It is a copy
// rather than a call because the real one closes over the function's bitset
// and its per-batch scratch; keeping the copy honest is this file's job, and
// any divergence shows up as a failure here first.
func shippedBatchEdges(ops []tdfaTagOp, numRegs int) map[[2]int]bool {
	words := (numRegs + 63) / 64
	interfere := make([]uint64, numRegs*words)
	orInto := func(r int, mask []uint64) {
		base := r * words
		for w := 0; w < words; w++ {
			interfere[base+w] |= mask[w]
		}
		interfere[base+r/64] &^= 1 << uint(r%64)
	}
	out := map[[2]int]bool{}
	if len(ops) < 2 {
		return out
	}
	dstMask := make([]uint64, words)
	srcMask := make([]uint64, words)
	dstCount := make([]int32, numRegs)
	srcCount := make([]int32, numRegs)
	for _, op := range ops {
		if op.dst >= 0 && op.dst < numRegs {
			dstMask[op.dst/64] |= 1 << uint(op.dst%64)
			dstCount[op.dst]++
		}
		if op.src >= 0 && op.src < numRegs {
			srcMask[op.src/64] |= 1 << uint(op.src%64)
			srcCount[op.src]++
		}
	}
	for _, op := range ops {
		if op.dst < 0 || op.dst >= numRegs {
			continue
		}
		orInto(op.dst, dstMask)
		if op.src >= 0 && op.src < numRegs && srcCount[op.src] == 1 {
			m := uint64(1) << uint(op.src%64)
			srcMask[op.src/64] &^= m
			orInto(op.dst, srcMask)
			srcMask[op.src/64] |= m
		} else {
			orInto(op.dst, srcMask)
		}
	}
	for _, op := range ops {
		if op.src < 0 || op.src >= numRegs {
			continue
		}
		if srcCount[op.src] == 1 && op.dst >= 0 && op.dst < numRegs && dstCount[op.dst] == 1 {
			m := uint64(1) << uint(op.dst%64)
			dstMask[op.dst/64] &^= m
			orInto(op.src, dstMask)
			dstMask[op.dst/64] |= m
		} else {
			orInto(op.src, dstMask)
		}
	}
	for r := 0; r < numRegs; r++ {
		for w := 0; w < words; w++ {
			m := interfere[r*words+w]
			for m != 0 {
				b := bits.TrailingZeros64(m)
				m &= m - 1
				out[[2]int{r, w*64 + b}] = true
			}
		}
	}
	return out
}
