package compile

import (
	"bytes"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

func compileBTTestProg(t *testing.T, pattern string) *syntax.Prog {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	return prog
}

func TestNeedsBitState(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
		note    string
	}{
		{"a*", false, ""},
		{"a+", false, ""},
		{"a+?", false, ""},
		// (?:a?)* is the canonical "catastrophic backtracking" pattern, yet it
		// does NOT need BitState.  The outer loop is greedy, so its InstAlt has
		// Out < PC (body) and Arg > PC (exit).  The zero-progress guard in the
		// emitted WASM takes the exit branch whenever pos == loop_pos_local,
		// preventing infinite re-entry without consuming BitState bits.
		{"(?:a?)*", false, "greedy outer loop — zero-progress guard is sufficient"},
		{"(?:a?)*?", true, ""},
	}
	for _, c := range cases {
		prog := compileBTTestProg(t, c.pattern)
		if got := needsBitState(prog); got != c.want {
			t.Errorf("needsBitState(%q) = %v, want %v (%s)", c.pattern, got, c.want, c.note)
		}
	}
}

func TestNfaFirstBytes(t *testing.T) {
	cases := []struct {
		pattern      string
		wantAllBytes bool
		wantFirst    []byte
	}{
		{"abc", false, []byte{'a'}},
		{"[abc]", false, []byte{'a', 'b', 'c'}},
		{"(?s).", true, nil},
		{"cat|dog", false, []byte{'c', 'd'}},
	}
	for _, c := range cases {
		prog := compileBTTestProg(t, c.pattern)
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes != c.wantAllBytes {
			t.Errorf("nfaFirstBytes(%q).allBytes = %v, want %v", c.pattern, allBytes, c.wantAllBytes)
			continue
		}
		if c.wantAllBytes {
			continue
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range c.wantFirst {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes(%q): missing byte %q in first set", c.pattern, b)
			}
		}
	}
}

func TestBtFoldRune(t *testing.T) {
	cases := []struct {
		r    rune
		want rune
	}{
		{'a', 'A'}, {'z', 'Z'}, {'m', 'M'}, // lowercase → uppercase
		{'A', 'a'}, {'Z', 'z'}, {'M', 'm'}, // uppercase → lowercase
		{'1', '1'}, {'!', '!'}, {' ', ' '}, // other → unchanged
	}
	for _, c := range cases {
		if got := btFoldRune(c.r); got != c.want {
			t.Errorf("btFoldRune(%q) = %q, want %q", c.r, got, c.want)
		}
	}
}

// TestBtCheckRune1FoldDirect exercises the isFold=true branch in btCheckRune1
// by calling it with a manually constructed InstRune1+FoldCase instruction.
// Go's regexp compiler never produces InstRune1 with FoldCase (it expands case-
// insensitive single chars to InstRune with a character class), so this branch
// is only reachable via a directly constructed instruction.
func TestBtCheckRune1FoldDirect(t *testing.T) {
	inst := syntax.Inst{
		Op:   syntax.InstRune1,
		Arg:  uint32(syntax.FoldCase),
		Rune: []rune{'a'},
	}
	result := btCheckRune1(nil, inst, 0)
	if len(result) == 0 {
		t.Error("btCheckRune1(isFold=true): expected non-empty WASM output")
	}
}

func TestBtCheckRune1CaseFold(t *testing.T) {
	// (?i:a) compiled with BT engine exercises btCheckRune1 with isFold=true.
	_, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "(?i:a)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced((?i:a) BT): %v", err)
	}
}

func TestLoopCaptureLocals(t *testing.T) {
	t.Run("captures inside loop", func(t *testing.T) {
		// (a)+ has a greedy loop with a capture group inside — loopCaptureLocals
		// should find the capture locals for that loop.
		prog := compileBTTestProg(t, "(a)+")
		bt := newBacktrack(prog)
		if len(bt.loops) == 0 {
			t.Skip("no loops found in (a)+")
		}
		foundCapture := false
		for pc := range bt.loops {
			locals := loopCaptureLocals(prog, pc)
			if len(locals) > 0 {
				foundCapture = true
			}
		}
		if !foundCapture {
			t.Error("loopCaptureLocals: expected capture locals for (a)+, got none")
		}
	})

	t.Run("no captures inside loop", func(t *testing.T) {
		// (?:a)+ has a loop but no captures — loopCaptureLocals should return nil.
		prog := compileBTTestProg(t, "(?:a)+")
		bt := newBacktrack(prog)
		for pc := range bt.loops {
			locals := loopCaptureLocals(prog, pc)
			if len(locals) != 0 {
				t.Errorf("loopCaptureLocals: expected nil for (?:a)+, got %v", locals)
			}
		}
	})
}

func TestBtAllocSizes(t *testing.T) {
	prog := compileBTTestProg(t, "(a)(b)(c)")
	bt := newBacktrack(prog)
	stackSize, memoSize := btAllocSizes(bt, false, 0, 128*1024)
	if stackSize <= 0 {
		t.Errorf("btAllocSizes: stackSize = %d, want > 0", stackSize)
	}
	if memoSize != 0 {
		t.Errorf("btAllocSizes(useMemo=false): memoSize = %d, want 0", memoSize)
	}
	_, memoSize2 := btAllocSizes(bt, true, 0, 128*1024)
	if memoSize2 != 128*1024 {
		t.Errorf("btAllocSizes(useMemo=true): memoSize = %d, want 131072", memoSize2)
	}
}

// TestBTCompileDeterminism guards against a class of bug found and fixed
// 2026-08-06: buildBacktrackBody/buildBTMatchBody/buildBTFindBody built a
// sorted loopPCsSorted slice for deterministic local assignment, but then
// emitted the loop-local (and loop-capture-snapshot) zero-init instructions
// by ranging directly over the loopLocalIdx/loopSnapBase maps instead of
// over loopPCsSorted. Go randomizes map iteration order per process, so the
// same pattern could compile to different (same-length) WASM bytes across
// runs — mirrors TestTDFACompileDeterminism, which guards the equivalent
// fix already made in the TDFA engine.
func TestBTCompileDeterminism(t *testing.T) {
	cases := []struct {
		name string
		re   config.RegexEntry
		opts []CompileOptions
	}{
		// buildBacktrackBody (capture path): non-greedy loop wrapping a
		// capture populates both loopLocalIdx and loopSnapBase.
		{"capture_loop_snapshot", config.RegexEntry{Pattern: "((a?)*?)", GroupsFunc: "g"}, nil},
		// buildBacktrackBody: 4 quantified sub-expressions give loopLocalIdx
		// 4 entries with no snapshot locals.
		{"capture_multi_loop", config.RegexEntry{Pattern: `(?i)(\bOR\b|\bAND\b)\s+[0-9]+\s*=\s*[0-9]+`, GroupsFunc: "g"}, nil},
		// buildBTMatchBody (no-capture match, forced via DFA-too-large
		// fallback): 2 independent loops.
		{"match_bt_multi_loop", config.RegexEntry{Pattern: "[a-z]+[0-9]+", MatchFunc: "m"}, []CompileOptions{{MaxDFAStates: 1}}},
		// buildBTFindBody, mandatory-literal branch (no-capture find,
		// forced via DFA-too-large fallback): loops on both sides of a
		// mandatory interior literal.
		{"find_bt_mandlit", config.RegexEntry{Pattern: "[a-z]+SECRET[0-9]+", FindFunc: "f"}, []CompileOptions{{MaxDFAStates: 1}}},
		// buildBTFindBody, general-scan (OnMatch closure) branch: same
		// loop shape but no mandatory literal to anchor the scan.
		{"find_bt_no_mandlit", config.RegexEntry{Pattern: "[a-z]+[0-9]+", FindFunc: "f"}, []CompileOptions{{MaxDFAStates: 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first, _, err := Compile([]config.RegexEntry{c.re}, 0, true, c.opts...)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			const iterations = 20
			for i := 0; i < iterations; i++ {
				got, _, err := Compile([]config.RegexEntry{c.re}, 0, true, c.opts...)
				if err != nil {
					t.Fatalf("iteration %d: Compile: %v", i+1, err)
				}
				if !bytes.Equal(first, got) {
					t.Errorf("iteration %d: WASM output differs from first (BT emission non-deterministic)", i+1)
				}
			}
		})
	}
}

// TestBTMemoInitNeedsBitState exercises the BitState memo-init path in
// buildBacktrackBody (memo locals + bitset zero-init/memory.fill, gated on
// needsBitState) — TEST.md T19. ((a?)*?) has a nested capture group ((a?)
// inside the outer capture), so MaxCap()==2 — task 41's whole-pattern-
// single-capture shortcut (which requires MaxCap()==1) does not intercept
// it, unlike its close cousin ((?:a?)+?) — confirmed live via
// isWholePatternSingleCapture/isAnchoredFind probing.
func TestBTMemoInitNeedsBitState(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "((a?)*?)", GroupsFunc: "g"}})
}

// TestBTNonLoopAltPushContinue exercises the plain-alternation (non-loop
// InstAlt) push-frame-and-continue path in emitBTInstHandler — TEST.md T20.
// (a)\B(?:x|y): the capture plus \B word-boundary force Backtracking (both
// are TDFA-exclusion gates in selectBestEngine); (?:x|y) is a non-loop
// InstAlt.
func TestBTNonLoopAltPushContinue(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a)\B(?:x|y)`, GroupsFunc: "g"}})
}

// TestBTWordBoundaryFalse exercises the \B case dispatch and the
// wantBoundary=false fail-if-boundary-present logic in btWordBoundary —
// TEST.md T21. A second capture group ((c)) is added to the doc's original
// (a)\B suggestion: confirmed live that (a)\B alone (MaxCap==1, one capture
// spanning past a zero-width-only assertion) trips task 41's whole-pattern-
// single-capture shortcut and never reaches BT capture compilation at all;
// the second group makes isWholePatternSingleCapture reject it.
func TestBTWordBoundaryFalse(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a)\B(c)`, GroupsFunc: "g"}})
}

// TestBTInstNop exercises the InstNop case in emitBTInstHandler, only
// reachable when the NFA program contains an InstNop (emitted by
// regexp/syntax.Compile for an empty alternation branch) — TEST.md T22. As
// with T21, a second capture group is added: (a|)\B alone (MaxCap==1) trips
// the task 41 shortcut (confirmed live), so (a|)\B(c) is used instead —
// confirmed live to still produce an InstNop instruction and route to
// Backtracking.
func TestBTInstNop(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a|)\B(c)`, GroupsFunc: "g"}})
}

// TestBTInvertedClassNonASCIISkip exercises the Unicode-range skip
// (if lo > 0x7F { continue/return }) in btCheckRuneRanges/btEmitSingleRange,
// triggered by an inverted class whose compiled ranges include a
// [0xE000, 0x10FFFF]-style tail — TEST.md T23. This is exactly the pattern
// family CLAUDE.md's "Load-bearing engine-selection gates" section
// documents (hasAmbiguousCaptures routes inverted-class captures to
// Backtracking, deliberately, not a bug).
func TestBTInvertedClassNonASCIISkip(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `<([^>]+)>`, GroupsFunc: "g"}})
}

// TestBTInstCaptureNoCapturesFallback exercises the InstCapture no-captures
// branch end-to-end via the no-capture match/find BT fallback path
// (compilePattern's DFA-too-large fallback) — TEST.md T24. Go's
// syntax.Compile always emits an implicit group-0 InstCapture even though
// no user captures are requested (MatchFunc/FindFunc only); MaxDFAStates: 1
// forces the DFA-too-large fallback to Backtracking.
func TestBTInstCaptureNoCapturesFallback(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[^a]+", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestNfaFirstBytesCaseFold exercises the case-insensitive alt-byte
// computation in nfaFirstBytes, for both a singleton (InstRune1) and a
// class (InstRune) instruction, plus the len(firstBytes)==0 && !allBytes
// branch for an entirely-non-ASCII first-byte set — TEST.md T25. Existing
// TestNfaFirstBytes cases have no (?i) at all.
func TestNfaFirstBytesCaseFold(t *testing.T) {
	t.Run("singleton_fold", func(t *testing.T) {
		prog := compileBTTestProg(t, "(?i)cat|dog")
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Fatalf("nfaFirstBytes((?i)cat|dog): allBytes = true, want false")
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range []byte{'c', 'C', 'd', 'D'} {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes((?i)cat|dog): missing fold byte %q", b)
			}
		}
	})
	t.Run("class_fold", func(t *testing.T) {
		prog := compileBTTestProg(t, "(?i)[a-c]+")
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Fatalf("nfaFirstBytes((?i)[a-c]+): allBytes = true, want false")
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range []byte{'a', 'A', 'b', 'B', 'c', 'C'} {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes((?i)[a-c]+): missing fold byte %q", b)
			}
		}
	})
	t.Run("all_non_ascii", func(t *testing.T) {
		prog := compileBTTestProg(t, `[^\x00-\x7F]+`)
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): allBytes = true, want false (first-byte set entirely non-ASCII)")
		}
		if len(first) != 0 {
			t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): first = %v, want empty", first)
		}
	})
}

// TestBTFindMandatoryLitCluster exercises the loop-local reset, memo
// zero-init, and overflowFind closure body inside buildBTFindBody's
// mandLit != nil branch — TEST.md T26. [a-z]{1,3}SECRET(?:b?)*? has: a
// variable-offset mandatory literal "SECRET" (minOff=1, maxOff=3, so it
// isn't a trivial fixed-offset literal-chain prefix), a loop on both sides,
// and needsBitState=true (non-greedy loop over an optional body) —
// confirmed live via findMandatoryLit/needsBitState direct calls.
// MaxDFAStates: 1 forces the DFA-too-large fallback to BT find.
func TestBTFindMandatoryLitCluster(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{1,3}SECRET(?:b?)*?", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestLoopBodyCanMatchEmptyVisitedGuard exercises the visited-guard in
// loopBodyCanMatchEmpty for a loop body with path reconvergence before
// reaching loopPC (two ?-quantified sub-terms in sequence, where both arms
// of the first rejoin before the second) — TEST.md T27. ((a?b?)*?) has a
// nested capture, so MaxCap()==2 and task 41's single-capture shortcut
// (confirmed live) does not intercept it.
func TestLoopBodyCanMatchEmptyVisitedGuard(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "((a?b?)*?)", GroupsFunc: "g"}})
}
