package compile

import (
	"regexp/syntax"
	"testing"
)

// Regression tests for plans/FABLE.md wave 3 (B6, B7, B9, B10, B11, B12).
//
// Every fix in that wave is a *gate*: the emitter it protects cannot express
// the shape, so the analyser must refuse it and let the pattern fall through
// to the classic DFA. These tests pin both halves — the shapes that must be
// rejected and the neighbouring shapes that must keep taking the fast path,
// since an over-broad gate silently costs the fast path on patterns that were
// always correct. End-to-end behaviour is covered by
// tools/re2test/custom-tests.txt category 36 (blocks Fable B6/B7/B9/B10/B11),
// which needs `make findonly` for the alternation halves.

// B6 — the three Gap E mixed-prefix emitters never referenced
// startAnchor/endAnchor, so anchored `<class>{M}<literal><class>{N}` patterns
// matched as if unanchored.
func TestAnalyseLitChainPrefixed_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^[ab]{4}XY[0-9]{24}`,
		`\A[ab]{4}XY[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}$`,
		`[ab]{4}XY[0-9]{24}\z`,
		`\b[!-,]{4}XY[0-9]{24}`,
		`\B[!-,]{4}XY[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}\b`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainPrefixed(pat); ok {
			t.Errorf("analyseLitChainPrefixed(%q) accepted an anchored shape", pat)
		}
	}
	if _, ok := analyseLitChainPrefixed(`[ab]{4}XY[0-9]{24}`); !ok {
		t.Errorf("analyseLitChainPrefixed rejected the unanchored control")
	}
}

func TestAnalyseLitChainAltPrefixed_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^[ab]{4}XY[0-9]{24}|^[cd]{4}ZW[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}$|[cd]{4}ZW[0-9]{24}$`,
		// Only one branch anchored is enough to disqualify the whole alt.
		`[ab]{4}XY[0-9]{24}|^[cd]{4}ZW[0-9]{24}`,
		`\b[!-,]{4}XY[0-9]{24}|[cd]{4}ZW[0-9]{24}`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainAltPrefixed(pat); ok {
			t.Errorf("analyseLitChainAltPrefixed(%q) accepted an anchored branch", pat)
		}
	}
	if _, ok := analyseLitChainAltPrefixed(`[ab]{4}XY[0-9]{24}|[cd]{4}ZW[0-9]{24}`); !ok {
		t.Errorf("analyseLitChainAltPrefixed rejected the unanchored control")
	}
}

// B9 — branches whose prefix lengths differ make the candidate-scan order
// (literal position) diverge from the match-start order (attempt_start minus
// prefixCount), so a later-starting match can be reported over an earlier one.
func TestAnalyseLitChainAltPrefixed_RequiresEqualPrefixCount(t *testing.T) {
	if _, ok := analyseLitChainAltPrefixed(
		`[0-9]{2}a[A-Za-z]{15}|[0-9a]{4}ZW[A-Za-z]{14}`); ok {
		t.Errorf("analyseLitChainAltPrefixed accepted unequal prefix lengths (2 vs 4)")
	}
	if _, ok := analyseLitChainAltPrefixed(
		`[0-9]{4}a[A-Za-z]{15}|[0-9a]{4}ZW[A-Za-z]{14}`); !ok {
		t.Errorf("analyseLitChainAltPrefixed rejected equal prefix lengths (4 vs 4)")
	}
}

// B7 (capture half) — buildLitChainRangeFindGroupsBody has no anchor handling,
// unlike its fixed-count sibling.
func TestAnalyseLitChainGroupsRange_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^A([0-9]{24,30})`,
		`A([0-9]{24,30})$`,
		`\bA([0-9]{24,30})`,
		`A([0-9]{24,30})\b`,
	}
	for _, pat := range rejected {
		if _, _, ok := analyseLitChainGroupsRange(pat); ok {
			t.Errorf("analyseLitChainGroupsRange(%q) accepted an anchored shape", pat)
		}
	}
	if _, _, ok := analyseLitChainGroupsRange(`A([0-9]{24,30})`); !ok {
		t.Errorf("analyseLitChainGroupsRange rejected the unanchored control")
	}
}

// B11 — emitLitChainAltLitBranchBodyRange checks the end anchor only at the
// maximal match length, with no backoff.
func TestAnalyseLitChainAltRange_EndAnchorBackoff(t *testing.T) {
	rejected := []string{
		// \b with a class mixing word and non-word bytes: backing off to a
		// shorter length can create a boundary the maximal length lacks.
		`q[a ]{24,26}\b|zz[0-9]{24}`,
		`q[a.]{24,26}\b|zz[0-9]{24}`,
		// \B is never safe at-max-only: every interior length satisfies it.
		`q[a-z]{24,26}\B|zz[0-9]{24}`,
		`q[a ]{24,26}\B|zz[0-9]{24}`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainAltRange(pat); ok {
			t.Errorf("analyseLitChainAltRange(%q) accepted an at-max-only end anchor", pat)
		}
	}
	// B10, alternation sibling: buildLitChainAltRangeFindBody collapses a
	// non-greedy branch to {N,N}, freezing the length the end anchor is
	// checked at. Start anchors are position-based and stay allowed.
	nonGreedyRejected := []string{
		`A[0-9]{24,30}?$|zz[0-9]{24}`,
		`A[0-9]{24,30}?\b|zz[0-9]{24}`,
		`A[0-9]{24,30}?\z|zz[0-9]{24}`,
	}
	for _, pat := range nonGreedyRejected {
		if _, ok := analyseLitChainAltRange(pat); ok {
			t.Errorf("analyseLitChainAltRange(%q) accepted a non-greedy range with an end anchor", pat)
		}
	}

	accepted := []string{
		// Non-greedy range with only a START anchor — the collapse is safe.
		`^A[0-9]{24,30}?|zz[0-9]{24}`,
		// Non-greedy range, no anchors.
		`A[0-9]{24,30}?|zz[0-9]{24}`,
		// Homogeneous all-word class + \b — the realistic secrets shape.
		`AKIA[A-Z0-9]{16,32}\b|zz[0-9]{24}`,
		// Homogeneous all-non-word class + \b.
		`q[!-,]{24,26}\b|zz[0-9]{24}`,
		// $ is monotone in match length.
		`q[a ]{24,26}$|zz[0-9]{24}`,
		// No end anchor at all.
		`q[a ]{24,26}|zz[0-9]{24}`,
		// \b on a FIXED-count branch is immune — no length to back off to.
		`q[a ]{24}\b|zz[0-9]{24,30}`,
	}
	for _, pat := range accepted {
		if _, ok := analyseLitChainAltRange(pat); !ok {
			t.Errorf("analyseLitChainAltRange(%q) rejected a safe end anchor", pat)
		}
	}
}

func TestClassWordHomogeneous(t *testing.T) {
	mk := func(bytes string) [32]byte {
		var bm [32]byte
		for i := 0; i < len(bytes); i++ {
			b := bytes[i]
			bm[b>>3] |= 1 << uint(b&7)
		}
		return bm
	}
	cases := []struct {
		name  string
		class string
		want  bool
	}{
		{"all word", "abzAZ09_", true},
		{"all non-word", " .,!-", true},
		{"mixed", "a ", false},
		{"mixed underscore vs dot", "_.", false},
		{"empty", "", true},
	}
	for _, c := range cases {
		if got := classWordHomogeneous(mk(c.class)); got != c.want {
			t.Errorf("classWordHomogeneous(%s=%q) = %v, want %v", c.name, c.class, got, c.want)
		}
	}
}

func TestRangeEndAnchorSafe(t *testing.T) {
	var word, mixed [32]byte
	for _, b := range []byte("abz09_") {
		word[b>>3] |= 1 << uint(b&7)
	}
	for _, b := range []byte("ab ") {
		mixed[b>>3] |= 1 << uint(b&7)
	}
	cases := []struct {
		anchor anchorType
		bitmap [32]byte
		want   bool
	}{
		{anchorNone, mixed, true},
		{anchorEndText, mixed, true},
		{anchorBeginText, mixed, true},
		{anchorWordBoundary, word, true},
		{anchorWordBoundary, mixed, false},
		{anchorNoWordBoundary, word, false},
		{anchorNoWordBoundary, mixed, false},
	}
	for _, c := range cases {
		if got := rangeEndAnchorSafe(c.anchor, c.bitmap); got != c.want {
			t.Errorf("rangeEndAnchorSafe(%v, ...) = %v, want %v", c.anchor, got, c.want)
		}
	}
}

// B12 — planRangeChunks covers [K, K+countMax) rounded up to 16, while callers
// only bounds-check K+countMin, so chunks past that window need the load
// clamp. This pins which chunks emitRangeClassVerify must guard; the trap it
// prevents is exercised end-to-end by tools/fuzz's
// TestRangeVerifyNoOverreadAtMemoryEnd.
func TestPlanRangeChunks_ClampWindow(t *testing.T) {
	cases := []struct {
		k, countMin, countMax int
		wantClamped           int // chunks with offsetFromK+16 > countMin
	}{
		{1, 24, 30, 1}, // chunk [0,16) safe, chunk [16,32) clamped
		{1, 24, 24, 1}, // exact: chunk [16,32) still reaches past 24
		{1, 32, 60, 2}, // chunks [0,16) [16,32) safe; [32,48) [48,64) clamped
		{4, 48, 48, 0}, // every chunk ends within countMin
		{1, 24, 900, 56},
	}
	for _, c := range cases {
		chunks := planRangeChunks(c.k, c.countMax)
		got := 0
		for _, ch := range chunks {
			if ch.offsetFromK+16 > c.countMin {
				got++
			}
		}
		if got != c.wantClamped {
			t.Errorf("k=%d countMin=%d countMax=%d: %d chunks need clamping, want %d",
				c.k, c.countMin, c.countMax, got, c.wantClamped)
		}
	}
}

// B8 — extractLitChainCaptures gave every OpRepeat a Min-based width, and the
// range slot-write emitter re-derived "this capture ends at the chain" by
// testing `endOffset == K + countMax`. For a true range Min ≠ Max, so that
// equality can never hold and every chain-covering capture got a frozen
// `attemptStart + K + Min` end. The walk now records the fact structurally.
func TestExtractLitChainCaptures_VariableTail(t *testing.T) {
	cases := []struct {
		pat string
		// want[group] = endsAtVariableTail
		want map[int]bool
	}{
		// Range: the chain-covering captures end at a variable tail.
		{`A([0-9]{24,30})`, map[int]bool{1: true}},
		{`(A[0-9]{24,30})`, map[int]bool{1: true}},
		{`(A)([0-9]{24,30})`, map[int]bool{1: false, 2: true}},
		{`((A)[0-9]{24,30})`, map[int]bool{1: true, 2: false}},
		{`(A([0-9]{24,30}))`, map[int]bool{1: true, 2: true}},
		// A trailing zero-width assertion must not clear the flag.
		{`(A[0-9]{24,30})\b`, map[int]bool{1: true}},
		// Fixed count: nothing is variable, so every offset stays compile-time
		// and the fixed-count emitter keeps its byte-identical output.
		{`A([0-9]{24})`, map[int]bool{1: false}},
		{`(A[0-9]{24})`, map[int]bool{1: false}},
		{`(A)([0-9]{24})`, map[int]bool{1: false, 2: false}},
	}
	for _, c := range cases {
		re, err := syntax.Parse(c.pat, syntax.Perl)
		if err != nil {
			t.Fatalf("pattern=%q parse: %v", c.pat, err)
		}
		caps, _, ok := extractLitChainCaptures(re)
		if !ok {
			t.Errorf("pattern=%q: extractLitChainCaptures rejected", c.pat)
			continue
		}
		got := make(map[int]bool, len(caps))
		for _, cg := range caps {
			got[cg.group] = cg.endsAtVariableTail
		}
		for g, want := range c.want {
			if got[g] != want {
				t.Errorf("pattern=%q group %d: endsAtVariableTail=%v, want %v",
					c.pat, g, got[g], want)
			}
		}
		if len(got) != len(c.want) {
			t.Errorf("pattern=%q: %d captures, want %d", c.pat, len(got), len(c.want))
		}
	}
}
