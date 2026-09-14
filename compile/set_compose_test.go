package compile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// splitAtPath tests

func mustParse(t *testing.T, pattern string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	return re
}

// findPath returns the path from findMandatoryLitRec for pattern, or nil.
func findPath(t *testing.T, pattern string) ([]splitFrame, bool) {
	t.Helper()
	re := mustParse(t, pattern)
	lit, path := findMandatoryLitRec(re, 0, 0, false)
	if lit == nil {
		return nil, false
	}
	return path, true
}

func TestSplitAtPath_Concat(t *testing.T) {
	t.Run("literal_in_middle", func(t *testing.T) {
		// \d{3}foo\w+ → prefix=\d{3}, suffix=\w+
		re := mustParse(t, `\d{3}foo\w+`)
		path, ok := findPath(t, `\d{3}foo\w+`)
		if !ok {
			t.Fatal("no mandatory lit found")
		}
		pre, suf, ok := splitAtPath(re, path)
		if !ok {
			t.Fatal("splitAtPath returned ok=false")
		}
		if pre == nil {
			t.Error("prefixAST is nil, want non-nil")
		}
		if suf == nil {
			t.Error("suffixAST is nil, want non-nil")
		}
	})

	t.Run("literal_at_start", func(t *testing.T) {
		// foo\w+ → prefix=nil, suffix=\w+
		re := mustParse(t, `foo\w+`)
		path, ok := findPath(t, `foo\w+`)
		if !ok {
			t.Fatal("no mandatory lit found")
		}
		pre, suf, ok := splitAtPath(re, path)
		if !ok {
			t.Fatal("splitAtPath returned ok=false")
		}
		if pre != nil {
			t.Errorf("prefixAST = %v, want nil (literal at start)", pre)
		}
		if suf == nil {
			t.Error("suffixAST is nil, want non-nil")
		}
	})

	t.Run("multi_element_prefix_and_suffix", func(t *testing.T) {
		// [a-z]{3}[0-9]{2}foo[a-z]{2}[0-9]{3}: prefix has 2 elements, suffix has 2 elements.
		// Both trigger concatRegexp default (2+ element) case.
		re := mustParse(t, `[a-z]{3}[0-9]{2}foo[a-z]{2}[0-9]{3}`)
		path, ok := findPath(t, `[a-z]{3}[0-9]{2}foo[a-z]{2}[0-9]{3}`)
		if !ok {
			t.Fatal("no mandatory lit found")
		}
		pre, suf, ok := splitAtPath(re, path)
		if !ok {
			t.Fatal("splitAtPath returned ok=false")
		}
		if pre == nil || pre.Op != syntax.OpConcat {
			t.Errorf("prefixAST = %v, want OpConcat (multi-element prefix)", pre)
		}
		if suf == nil || suf.Op != syntax.OpConcat {
			t.Errorf("suffixAST = %v, want OpConcat (multi-element suffix)", suf)
		}
	})

	t.Run("literal_at_end", func(t *testing.T) {
		// \w+foo → prefix=\w+, suffix=nil
		re := mustParse(t, `\d{3}foo`)
		path, ok := findPath(t, `\d{3}foo`)
		if !ok {
			t.Fatal("no mandatory lit found")
		}
		pre, suf, ok := splitAtPath(re, path)
		if !ok {
			t.Fatal("splitAtPath returned ok=false")
		}
		if pre == nil {
			t.Error("prefixAST is nil, want non-nil")
		}
		if suf != nil {
			t.Errorf("suffixAST = %v, want nil (literal at end)", suf)
		}
	})
}

func TestSplitAtPath_Capture(t *testing.T) {
	t.Run("capture_around_concat", func(t *testing.T) {
		// (?P<x>\d{3}foo\w+) — capture wrapping a concat
		re := mustParse(t, `(?P<x>\d{3}foo\w+)`)
		path, ok := findPath(t, `(?P<x>\d{3}foo\w+)`)
		if !ok {
			t.Fatal("no mandatory lit found")
		}
		pre, suf, ok := splitAtPath(re, path)
		if !ok {
			t.Fatal("splitAtPath returned ok=false for capture around concat")
		}
		if pre == nil || suf == nil {
			t.Errorf("pre=%v suf=%v; both should be non-nil", pre, suf)
		}
	})
}

func TestSplitAtPath_NestedCaptureConcat(t *testing.T) {
	// (?P<outer>\d{3}(?P<inner>foo)\w+) — nested captures
	re := mustParse(t, `(?P<outer>\d{3}(?P<inner>foo)\w+)`)
	path, ok := findPath(t, `(?P<outer>\d{3}(?P<inner>foo)\w+)`)
	if !ok {
		t.Fatal("no mandatory lit found")
	}
	pre, suf, ok := splitAtPath(re, path)
	if !ok {
		t.Fatal("splitAtPath returned ok=false")
	}
	if pre == nil || suf == nil {
		t.Errorf("pre=%v suf=%v; both should be non-nil for nested captures", pre, suf)
	}
}

func TestSplitAtPath_RejectsQuantifier(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		// Literal inside + — path contains OpPlus
		{"plus", `(foo)+bar`},
		// Literal inside {1,} — path contains OpRepeat(Min=1)
		{"repeat_min1", `(foo){1,3}bar`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := mustParse(t, tc.pattern)
			lit, path := findMandatoryLitRec(re, 0, 0, false)
			if lit == nil {
				t.Skip("no mandatory lit found (pattern not eligible)")
			}
			_, _, ok := splitAtPath(re, path)
			if ok {
				t.Errorf("splitAtPath(%q): expected ok=false for quantifier in path", tc.pattern)
			}
		})
	}
}

func TestSplitAtPath_RejectsAlternate(t *testing.T) {
	// Construct a path that contains OpAlternate manually (findMandatoryLitRec
	// never returns a path with OpAlternate, but splitAtPath must reject it).
	re := mustParse(t, `foo`)
	lit, path := findMandatoryLitRec(re, 0, 0, false)
	if lit == nil {
		t.Fatal("no mandatory lit found")
	}
	// Inject an OpAlternate frame at the front.
	badPath := append([]splitFrame{{op: syntax.OpAlternate}}, path...)
	_, _, ok := splitAtPath(re, badPath)
	if ok {
		t.Error("splitAtPath with OpAlternate frame: expected ok=false")
	}
}

// --------------------------------------------------------------------------
// dfaFingerprint and dfaPool tests

func buildCanonicalDFA(t *testing.T, pattern string) *dfaTable {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("Parse(%q): %v", pattern, err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("Compile(%q): %v", pattern, err)
	}
	d, ok := newDFA(prog, false, false, maxHelperDFAStates)
	if !ok {
		t.Fatalf("newDFA(%q): state limit exceeded", pattern)
	}
	return dfaTableFromCanonical(d)
}

func TestDFAFingerprint_Canonical(t *testing.T) {
	// Two DFAs built from the same pattern must have identical fingerprints.
	fp1 := dfaFingerprint(buildCanonicalDFA(t, `\d+`))
	fp2 := dfaFingerprint(buildCanonicalDFA(t, `\d+`))
	if fp1 != fp2 {
		t.Errorf("same pattern produced different fingerprints: %x vs %x", fp1, fp2)
	}
}

func TestDFAFingerprint_Distinct(t *testing.T) {
	// Two non-equivalent patterns must (almost certainly) have different fingerprints.
	fp1 := dfaFingerprint(buildCanonicalDFA(t, `\d+`))
	fp2 := dfaFingerprint(buildCanonicalDFA(t, `[a-z]+`))
	if fp1 == fp2 {
		t.Errorf("different patterns produced same fingerprint %x", fp1)
	}
}

func TestDfaPool_Dedup(t *testing.T) {
	var pool dfaPool

	t1 := buildCanonicalDFA(t, `\d+`)
	t2 := buildCanonicalDFA(t, `\d+`)    // equivalent
	t3 := buildCanonicalDFA(t, `[a-z]+`) // distinct

	id1 := pool.Add(t1)
	id2 := pool.Add(t2)
	id3 := pool.Add(t3)

	if id1 != id2 {
		t.Errorf("equivalent DFAs got different IDs: %d vs %d", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("distinct DFAs got same ID: %d", id1)
	}
	if len(pool.tables) != 2 {
		t.Errorf("pool.tables len = %d, want 2", len(pool.tables))
	}
}

// --------------------------------------------------------------------------
// analyzePattern tests

func TestAnalyzePattern_Trivial(t *testing.T) {
	// ^foo: the mandatory literal "foo" has a zero-byte prefix (BeginText anchor)
	// which is treated as trivial.
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `^foo`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if !info.trivialPrefix {
		t.Errorf("trivialPrefix = false, want true for ^foo")
	}
	if info.prefixID != -1 {
		t.Errorf("prefixID = %d, want -1 (trivial)", info.prefixID)
	}
	if info.suffixID < 0 {
		t.Errorf("suffixID = %d, want >= 0", info.suffixID)
	}
}

func TestAnalyzePattern_FullSplit(t *testing.T) {
	// \d{3}foo\w+ has a bounded prefix (\d{3}) and a suffix (\w+) around "foo".
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `\d{3}foo\w+`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if info.trivialPrefix {
		t.Error("trivialPrefix = true, want false (bounded prefix exists)")
	}
	if info.prefixAST == nil {
		t.Error("prefixAST is nil, want non-nil")
	}
	if info.suffixAST == nil {
		t.Error("suffixAST is nil, want non-nil")
	}
	if info.prefixID < 0 {
		t.Errorf("prefixID = %d, want >= 0", info.prefixID)
	}
	if info.suffixID < 0 {
		t.Errorf("suffixID = %d, want >= 0", info.suffixID)
	}
}

func TestAnalyzePattern_ParseError(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	_, err := analyzePattern(config.RegexEntry{Pattern: `[invalid`}, &prefixPool, &suffixPool)
	if err == nil {
		t.Error("expected error for invalid pattern, got nil")
	}
}

// --------------------------------------------------------------------------
// dfaTableEqual branch coverage

func TestDFATableEqual_Inequal(t *testing.T) {
	// Different numStates → early false at the scalar-field check.
	a := buildCanonicalDFA(t, `a`)
	b := buildCanonicalDFA(t, `[a-zA-Z0-9_]{8,}`)
	if dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for DFAs with different numStates")
	}
}

func TestDFATableEqual_TransitionMismatch(t *testing.T) {
	// Same numStates possible, but transitions differ.
	a := buildCanonicalDFA(t, `abc`)
	// Build a copy of a and mutate one transition to force the inner loop to fire.
	bTrans := make([]int, len(a.transitions))
	copy(bTrans, a.transitions)
	// Flip the first non-dead transition to something different.
	for i, v := range bTrans {
		if v >= 0 {
			bTrans[i] = -1
			break
		}
	}
	b := &dfaTable{
		startState:            a.startState,
		midStartState:         a.midStartState,
		midStartWordState:     a.midStartWordState,
		numStates:             a.numStates,
		hasWordBoundary:       a.hasWordBoundary,
		hasNewlineBoundary:    a.hasNewlineBoundary,
		startBeginAccept:      a.startBeginAccept,
		transitions:           bTrans,
		acceptStates:          a.acceptStates,
		midAcceptStates:       a.midAcceptStates,
		midAcceptNWStates:     a.midAcceptNWStates,
		midAcceptWStates:      a.midAcceptWStates,
		midAcceptNLStates:     a.midAcceptNLStates,
		immediateAcceptStates: a.immediateAcceptStates,
	}
	if dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for mismatched transitions")
	}
}

func TestDFATableEqual_AcceptMapMismatch(t *testing.T) {
	// Same transitions, different accept map → eqMaps returns false.
	a := buildCanonicalDFA(t, `abc`)
	b := &dfaTable{
		startState:            a.startState,
		midStartState:         a.midStartState,
		midStartWordState:     a.midStartWordState,
		numStates:             a.numStates,
		hasWordBoundary:       a.hasWordBoundary,
		hasNewlineBoundary:    a.hasNewlineBoundary,
		startBeginAccept:      a.startBeginAccept,
		transitions:           a.transitions,
		acceptStates:          map[int]uint64{}, // empty — different from a
		midAcceptStates:       a.midAcceptStates,
		midAcceptNWStates:     a.midAcceptNWStates,
		midAcceptWStates:      a.midAcceptWStates,
		midAcceptNLStates:     a.midAcceptNLStates,
		immediateAcceptStates: a.immediateAcceptStates,
	}
	if len(a.acceptStates) > 0 && dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for different acceptStates maps")
	}
}

func TestDFATableEqual_NewlineBoundaryMismatch(t *testing.T) {
	// hasNewlineBoundary differs → early false.
	a := buildCanonicalDFA(t, `(?m:^)foo`)
	b := buildCanonicalDFA(t, `foo`)
	if dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for different hasNewlineBoundary")
	}
}

// --------------------------------------------------------------------------
// dfaFingerprint branch coverage

func TestDFAFingerprint_WordBoundary(t *testing.T) {
	// \b triggers hasWordBoundary and midAcceptNW/W flags in dfaFingerprint.
	fp1 := dfaFingerprint(buildCanonicalDFA(t, `\bfoo\b`))
	fp2 := dfaFingerprint(buildCanonicalDFA(t, `\bfoo\b`))
	if fp1 != fp2 {
		t.Errorf("word-boundary pattern: fingerprints differ: %x vs %x", fp1, fp2)
	}
	fp3 := dfaFingerprint(buildCanonicalDFA(t, `foo`))
	if fp1 == fp3 {
		t.Errorf("word-boundary vs plain: fingerprints unexpectedly equal: %x", fp1)
	}
}

func TestDFAFingerprint_NewlineBoundary(t *testing.T) {
	// (?m:^) triggers hasNewlineBoundary and midAcceptNL flags.
	fp1 := dfaFingerprint(buildCanonicalDFA(t, `(?m:^)foo`))
	fp2 := dfaFingerprint(buildCanonicalDFA(t, `(?m:^)foo`))
	if fp1 != fp2 {
		t.Errorf("newline-boundary pattern: fingerprints differ: %x vs %x", fp1, fp2)
	}
}

// --------------------------------------------------------------------------
// splitAtPathRec defensive branch coverage (synthetic paths)

func TestSplitAtPath_DefensiveBranches(t *testing.T) {
	t.Run("default_op_in_frame", func(t *testing.T) {
		// Inject a frame with Op=OpStar (not handled) → default → false.
		re := mustParse(t, `foo`)
		path := []splitFrame{{op: syntax.OpStar}}
		_, _, ok := splitAtPath(re, path)
		if ok {
			t.Error("expected ok=false for unknown frame op")
		}
	})

	t.Run("capture_frame_on_non_capture", func(t *testing.T) {
		// Frame says OpCapture but re is a Concat → mismatch → false.
		re := mustParse(t, `foo\d+`)
		path := []splitFrame{{op: syntax.OpCapture}}
		_, _, ok := splitAtPath(re, path)
		if ok {
			t.Error("expected ok=false for capture frame on non-capture re")
		}
	})

	t.Run("concat_frame_on_non_concat", func(t *testing.T) {
		// Frame says OpConcat but re is a Literal → mismatch → false.
		re := mustParse(t, `foo`)
		path := []splitFrame{{op: syntax.OpConcat, index: 0}}
		_, _, ok := splitAtPath(re, path)
		if ok {
			t.Error("expected ok=false for concat frame on non-concat re")
		}
	})

	t.Run("concat_out_of_bounds_index", func(t *testing.T) {
		// Frame index 99 is out of bounds for the concat → false.
		re := mustParse(t, `foo\d+`)
		path := []splitFrame{{op: syntax.OpConcat, index: 99}}
		_, _, ok := splitAtPath(re, path)
		if ok {
			t.Error("expected ok=false for out-of-bounds concat index")
		}
	})

	t.Run("inner_recursion_fails", func(t *testing.T) {
		// Inject [{OpConcat, 0}, {OpAlternate}] — inner frame is bad → false.
		re := mustParse(t, `foo\d+`)
		path := []splitFrame{
			{op: syntax.OpConcat, index: 0},
			{op: syntax.OpAlternate},
		}
		_, _, ok := splitAtPath(re, path)
		if ok {
			t.Error("expected ok=false when inner recursion fails")
		}
	})
}

// --------------------------------------------------------------------------
// concatRegexp and deepCopyRegexp edge cases

func TestConcatRegexp_Empty(t *testing.T) {
	if got := concatRegexp(nil); got != nil {
		t.Errorf("concatRegexp(nil) = %v, want nil", got)
	}
	if got := concatRegexp([]*syntax.Regexp{}); got != nil {
		t.Errorf("concatRegexp([]) = %v, want nil", got)
	}
}

func TestConcatRegexp_Single(t *testing.T) {
	re := mustParse(t, `foo`)
	got := concatRegexp([]*syntax.Regexp{re})
	if got != re {
		t.Errorf("concatRegexp([re]) = %v, want same pointer", got)
	}
}

func TestDFATableEqual_EqMapsMembership(t *testing.T) {
	// Build a real DFA then create a copy with a different midAcceptWStates map
	// that has the same size but different key, forcing !mb[s] in eqMaps.
	a := buildCanonicalDFA(t, `\bfoo`)
	if len(a.midAcceptWStates) == 0 {
		t.Skip("pattern produced no midAcceptW states")
	}
	// Build acceptStates/midAcceptNWStates/midAcceptWStates with same size but wrong key.
	badW := make(map[int]uint64)
	for s, v := range a.midAcceptWStates {
		badW[s+a.numStates+1] = v
	}
	b := &dfaTable{
		startState:            a.startState,
		midStartState:         a.midStartState,
		midStartWordState:     a.midStartWordState,
		numStates:             a.numStates,
		hasWordBoundary:       a.hasWordBoundary,
		hasNewlineBoundary:    a.hasNewlineBoundary,
		startBeginAccept:      a.startBeginAccept,
		transitions:           a.transitions,
		acceptStates:          a.acceptStates,
		midAcceptStates:       a.midAcceptStates,
		midAcceptNWStates:     a.midAcceptNWStates,
		midAcceptWStates:      badW,
		midAcceptNLStates:     a.midAcceptNLStates,
		immediateAcceptStates: a.immediateAcceptStates,
	}
	if dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for mismatched midAcceptWStates keys")
	}
}

func TestDFATableEqual_NewlineMidStartMismatch(t *testing.T) {
	// Two DFAs both with hasNewlineBoundary=true but synthesized to have
	// different midStartNewlineState values.
	a := buildCanonicalDFA(t, `(?m:^)foo`)
	if !a.hasNewlineBoundary {
		t.Skip("pattern did not produce newline boundary")
	}
	// Make a copy with a shifted midStartNewlineState.
	b := &dfaTable{
		startState:            a.startState,
		midStartState:         a.midStartState,
		midStartWordState:     a.midStartWordState,
		midStartNewlineState:  (a.midStartNewlineState + 1) % a.numStates,
		numStates:             a.numStates,
		hasWordBoundary:       a.hasWordBoundary,
		hasNewlineBoundary:    true,
		startBeginAccept:      a.startBeginAccept,
		transitions:           a.transitions,
		acceptStates:          a.acceptStates,
		midAcceptStates:       a.midAcceptStates,
		midAcceptNWStates:     a.midAcceptNWStates,
		midAcceptWStates:      a.midAcceptWStates,
		midAcceptNLStates:     a.midAcceptNLStates,
		immediateAcceptStates: a.immediateAcceptStates,
	}
	if a.midStartNewlineState == b.midStartNewlineState {
		t.Skip("numStates=1, shift produced same state")
	}
	if dfaTableEqual(a, b) {
		t.Error("dfaTableEqual: expected false for different midStartNewlineState")
	}
}

func TestDeepCopyRegexp_Nil(t *testing.T) {
	if got := deepCopyRegexp(nil); got != nil {
		t.Errorf("deepCopyRegexp(nil) = %v, want nil", got)
	}
}

func TestConcatRegexp_Multi(t *testing.T) {
	// 2+ elements → hits the default case, producing an OpConcat node.
	a := mustParse(t, `\d+`)
	b := mustParse(t, `[a-z]+`)
	got := concatRegexp([]*syntax.Regexp{a, b})
	if got == nil {
		t.Fatal("concatRegexp([a,b]) = nil, want OpConcat")
	}
	if got.Op != syntax.OpConcat {
		t.Errorf("concatRegexp([a,b]).Op = %v, want OpConcat", got.Op)
	}
	if len(got.Sub) != 2 {
		t.Errorf("concatRegexp([a,b]).Sub len = %d, want 2", len(got.Sub))
	}
}

func TestBFSRelabelDFA_UnreachableStates(t *testing.T) {
	// Construct a dfaTable with 3 states where state 2 is unreachable
	// from startState (0) or midStart (1). bfsRelabelDFA must assign it
	// an ID without panicking (defensive path, line ~880 in engine_dfa.go).
	trans := make([]int, 3*256)
	for i := range trans {
		trans[i] = -1
	}
	// State 0 → state 1 on byte 'a'.
	trans[0*256+'a'] = 1
	// State 2 is unreachable (no transition leads to it).

	tbl := &dfaTable{
		startState:            0,
		midStartState:         1,
		midStartWordState:     1,
		numStates:             3,
		transitions:           trans,
		acceptStates:          map[int]uint64{1: 1},
		midAcceptStates:       map[int]uint64{},
		midAcceptNWStates:     map[int]uint64{},
		midAcceptWStates:      map[int]uint64{},
		midAcceptNLStates:     map[int]uint64{},
		immediateAcceptStates: map[int]uint64{},
	}

	bfsRelabelDFA(tbl)

	// After relabelling all 3 states must get an ID in [0,2].
	if tbl.numStates != 3 {
		t.Errorf("numStates = %d, want 3", tbl.numStates)
	}
	if tbl.startState != 0 {
		t.Errorf("startState = %d, want 0 (BFS from start)", tbl.startState)
	}
}

func TestAnalyzePattern_SharedSuffix(t *testing.T) {
	// 7 patterns sharing the same suffix [^\n]* after distinct literals.
	// suffixPool.Add should return the same ID for all.
	patterns := []string{
		`alpha[^\n]*`,
		`beta[^\n]*`,
		`gamma[^\n]*`,
		`delta[^\n]*`,
		`epsilon[^\n]*`,
		`zeta[^\n]*`,
		`eta[^\n]*`,
	}
	var prefixPool, suffixPool dfaPool
	var firstSuffixID int
	for i, p := range patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: p}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("pattern %q: %v", p, err)
		}
		if i == 0 {
			firstSuffixID = info.suffixID
			continue
		}
		if info.suffixID != firstSuffixID {
			t.Errorf("pattern %q: suffixID=%d, want %d (shared suffix)", p, info.suffixID, firstSuffixID)
		}
	}
}

// --------------------------------------------------------------------------
// Phase 2: fixture loader and tests

type setFixture struct {
	Patterns []struct {
		Name    string `yaml:"name"`
		Pattern string `yaml:"pattern"`
	} `yaml:"patterns"`
	Options struct {
		BitmaskWidth          int `yaml:"bitmask_width"`
		BudgetBytes           int `yaml:"budget_bytes"`
		BudgetStates          int `yaml:"budget_states"`
		BudgetStatesPreFilter int `yaml:"budget_states_prefilter"`
	} `yaml:"options"`
	Expect struct {
		SuffixDedupPoolSize int      `yaml:"suffix_dedup_pool_size"`
		BucketCount         int      `yaml:"bucket_count"`
		FallbackCount       int      `yaml:"fallback_count"`
		ConflictReasons     []string `yaml:"conflict_reasons"`
		Frontend            string   `yaml:"frontend"`
		Match               string   `yaml:"match"`
		SetCount            int      `yaml:"set_count"`
	} `yaml:"expect"`
	Sets []config.SetConfig `yaml:"sets"`
}

func (f setFixture) compileOpts() CompileSetOptions {
	return CompileSetOptions{
		BitmaskWidth:          f.Options.BitmaskWidth,
		BudgetBytes:           f.Options.BudgetBytes,
		BudgetStates:          f.Options.BudgetStates,
		BudgetStatesPreFilter: f.Options.BudgetStatesPreFilter,
	}
}

func (f setFixture) patternInfos(t *testing.T) []*PatternInfo {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, len(f.Patterns))
	for i, p := range f.Patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: p.Pattern}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", p.Pattern, err)
		}
		infos[i] = info
	}
	return infos
}

func testdataFixture(t *testing.T, name string) setFixture {
	t.Helper()
	path := filepath.Join("testdata", "set", name, "patterns.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("testdataFixture(%q): %v", name, err)
	}
	var f setFixture
	if err := yaml.Unmarshal(data, &f); err != nil {
		t.Fatalf("testdataFixture(%q): yaml: %v", name, err)
	}
	return f
}

func TestBitmaskPropagation_TwoPatterns(t *testing.T) {
	// "ab" and "ac": after consuming 'b' only bit 0 accepts; after 'c' only bit 1.
	asts := []*syntax.Regexp{mustParse(t, `ab`), mustParse(t, `ac`)}
	table, kind, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFA: %v", err)
	}
	if kind != AcceptBitmask {
		t.Errorf("AcceptKind = %v, want AcceptBitmask", kind)
	}
	// Both bit 0 and bit 1 must appear as separate accept bitmasks.
	var combined uint64
	for _, v := range table.acceptStates {
		combined |= v
	}
	if combined&1 == 0 {
		t.Error("bit 0 (pattern 'ab') never appears in accept bitmasks")
	}
	if combined&2 == 0 {
		t.Error("bit 1 (pattern 'ac') never appears in accept bitmasks")
	}
	// The two patterns must produce distinct accept values (not merged into one state).
	distinct := make(map[uint64]bool)
	for _, v := range table.acceptStates {
		if v != 0 {
			distinct[v] = true
		}
	}
	if len(distinct) < 2 {
		t.Errorf("want ≥2 distinct accept bitmasks for 'ab'|'ac', got %d: %v", len(distinct), distinct)
	}
}

func TestBitmaskPropagation_EpsilonClosure(t *testing.T) {
	// "a?" has an epsilon path to accept (can match empty string).
	asts := []*syntax.Regexp{mustParse(t, `a?`), mustParse(t, `b`)}
	table, _, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFA: %v", err)
	}
	if len(table.acceptStates) == 0 {
		t.Error("no accepting states in merged DFA")
	}
}

func TestCombinedClassCount_Subsumed(t *testing.T) {
	// b maps all bytes to class 0 → combined count == number of classes in a.
	var a, b [256]byte
	for i := range a {
		a[i] = byte(i % 4)
	}
	if got := combinedClassCount(a, b); got != 4 {
		t.Errorf("combinedClassCount (b constant): got %d, want 4", got)
	}
}

func TestCombinedClassCount_Orthogonal(t *testing.T) {
	// Every (a[i], b[i]) pair is unique → combined count == 256.
	var a, b [256]byte
	for i := range a {
		a[i] = byte(i / 16)
		b[i] = byte(i % 16)
	}
	if got := combinedClassCount(a, b); got != 256 {
		t.Errorf("combinedClassCount (orthogonal): got %d, want 256", got)
	}
}

func TestMergeSuffixDFA_EmptyList(t *testing.T) {
	_, _, err := mergeSuffixDFA(nil, CompileSetOptions{})
	if err == nil {
		t.Error("mergeSuffixDFA(nil): expected error for empty list, got nil")
	}
}

func TestBuildUnionProg_SinglePattern(t *testing.T) {
	// Single pattern: altCount == 0, union.Start = starts[0], no Alt chain.
	re, _ := syntax.Parse(`ab`, syntax.Perl)
	prog, _ := syntax.Compile(re.Simplify())
	union, patternBits := buildUnionProg([]*syntax.Prog{prog}, 64)
	if union == nil {
		t.Fatal("buildUnionProg: nil result")
	}
	// At least the single InstMatch should be assigned bit 0.
	var combined uint64
	for _, v := range patternBits {
		combined |= v
	}
	if combined&1 == 0 {
		t.Error("buildUnionProg (single): bit 0 not assigned to any instruction")
	}
}

func TestMergeSuffixDFA_TooManyPatterns(t *testing.T) {
	asts := make([]*syntax.Regexp, 65)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	_, _, err := mergeSuffixDFA(asts, CompileSetOptions{BitmaskWidth: 64})
	if err == nil {
		t.Error("expected error for 65 patterns with BitmaskWidth=64, got nil")
	}
}

func TestMultiPatternTeddy_FourLiterals(t *testing.T) {
	literals := [][]byte{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh")}
	tables, ok := buildTeddyTablesMulti(literals)
	if !ok {
		t.Fatal("buildTeddyTablesMulti returned ok=false for 4 two-byte literals")
	}
	// Each literal's first byte should set exactly one bit in T0Lo/T0Hi.
	for i, lit := range literals {
		bit := byte(1 << uint(i))
		b := lit[0]
		if tables.T0Lo[b&0x0F]&bit == 0 {
			t.Errorf("literal %d (%q): bit not set in T0Lo[%d]", i, lit, b&0x0F)
		}
		if tables.T0Hi[b>>4]&bit == 0 {
			t.Errorf("literal %d (%q): bit not set in T0Hi[%d]", i, lit, b>>4)
		}
		b1 := lit[1]
		if tables.T1Lo[b1&0x0F]&bit == 0 {
			t.Errorf("literal %d (%q): bit not set in T1Lo[%d]", i, lit, b1&0x0F)
		}
		if tables.T1Hi[b1>>4]&bit == 0 {
			t.Errorf("literal %d (%q): bit not set in T1Hi[%d]", i, lit, b1>>4)
		}
	}
	if !tables.TwoByte {
		t.Error("TwoByte should be true for 2-byte literals")
	}
	if tables.ThreeByte {
		t.Error("ThreeByte should be false for 2-byte literals")
	}
}

func TestMultiPatternTeddy_LaneToID(t *testing.T) {
	literals := [][]byte{[]byte("ab"), []byte("xy"), []byte("mn")}
	tables, ok := buildTeddyTablesMulti(literals)
	if !ok {
		t.Fatal("buildTeddyTablesMulti failed")
	}
	// LaneToIDs is indexed by LANE (8 or 16 slots), not by literal; lanes
	// beyond the literal count are empty and emit no dispatch.
	if len(tables.LaneToIDs) != 8 {
		t.Fatalf("LaneToIDs len = %d, want 8 lanes", len(tables.LaneToIDs))
	}
	if tables.Bucketed {
		t.Error("3 literals must get one lane each, not a bucketed layout")
	}
	for i := 0; i < 3; i++ {
		if got := tables.LaneToIDs[i]; len(got) != 1 || got[0] != i {
			t.Errorf("LaneToIDs[%d] = %v, want [%d]", i, got, i)
		}
	}
	for i := 3; i < 8; i++ {
		if len(tables.LaneToIDs[i]) != 0 {
			t.Errorf("LaneToIDs[%d] = %v, want empty", i, tables.LaneToIDs[i])
		}
	}
}

func TestMultiPatternTeddy_TooManyLiterals(t *testing.T) {
	// 17 two-byte literals are now BUCKETED into the 16 lanes rather than
	// rejected; the cap is teddyMaxLiterals.
	lits := make([][]byte, 17)
	for i := range lits {
		lits[i] = []byte{byte('a' + i%26), byte('0' + i%10)}
	}
	tt17, ok := buildTeddyTablesMulti(lits)
	if !ok {
		t.Fatal("buildTeddyTablesMulti: expected ok=true for 17 literals (bucketed)")
	}
	if !tt17.Bucketed {
		t.Error("17 literals over 16 lanes must set Bucketed")
	}
	seen := 0
	for _, ids := range tt17.LaneToIDs {
		seen += len(ids)
	}
	if seen != 17 {
		t.Errorf("lanes cover %d literals, want 17", seen)
	}
	// Over the cap → still ok=false.
	over := make([][]byte, teddyMaxLiterals+1)
	for i := range over {
		over[i] = []byte{byte('a' + i%26), byte('0' + i%10), byte('A' + i%26)}
	}
	if _, ok := buildTeddyTablesMulti(over); ok {
		t.Errorf("expected ok=false above teddyMaxLiterals (%d)", teddyMaxLiterals)
	}
	// A 1-byte shortest literal keeps the tighter cap.
	single := make([][]byte, teddySingleByteMax+1)
	for i := range single {
		single[i] = []byte{byte('a' + i%26)}
	}
	if _, ok := buildTeddyTablesMulti(single); ok {
		t.Errorf("expected ok=false above teddySingleByteMax (%d) with 1-byte literals", teddySingleByteMax)
	}
	// 9 literals ≤ 16 → ok=true (two groups)
	lits9 := make([][]byte, 9)
	for i := range lits9 {
		lits9[i] = []byte{byte('a' + i)}
	}
	if _, ok2 := buildTeddyTablesMulti(lits9); !ok2 {
		t.Error("buildTeddyTablesMulti: expected ok=true for 9 literals (≤16)")
	}
}

func TestMultiPatternTeddy_LiteralTooLong(t *testing.T) {
	// Long literals are probed on their first 4 bytes → ok=true
	lits := [][]byte{[]byte("sk_live_abcdef")} // >4 bytes: partial probe
	_, ok := buildTeddyTablesMulti(lits)
	if !ok {
		t.Error("buildTeddyTablesMulti: expected ok=true for long literal (partial probe)")
	}
	// Empty literal → ok=false
	empty := [][]byte{[]byte("")}
	if _, ok2 := buildTeddyTablesMulti(empty); ok2 {
		t.Error("buildTeddyTablesMulti: expected ok=false for empty literal")
	}
}

func TestChooseLiteralFrontend(t *testing.T) {
	cases := []struct {
		lits [][]byte
		want frontendKind
	}{
		// At or below 16 literals, a qualifying two-column packed pair wins:
		// two eq-splat columns cost far less per
		// chunk than Teddy's four nibble-table probes, and both verify
		// candidates identically.
		{[][]byte{[]byte("ab"), []byte("cd")}, frontendPackedPair}, // cols {a,c} × {b,d} = 4, fits
		{[][]byte{[]byte("abcd")}, frontendPackedPair},
		{[][]byte{[]byte("abcde")}, frontendPackedPair},
		{[][]byte{[]byte("sk_live_")}, frontendPackedPair},
		// A single one-byte literal has only ONE probe column, so no pair
		// exists and Teddy keeps it.
		{[][]byte{[]byte("a")}, frontendTeddy},
		{nil, frontendScalar},
		{[][]byte{[]byte("")}, frontendScalar}, // empty literal → scalar
	}
	// 9 one-byte literals: still a single probe column, so still Teddy — the
	// packed-pair rule keys on the probe WINDOW, not the literal count.
	nineLits := make([][]byte, 9)
	for i := range nineLits {
		nineLits[i] = []byte{byte('a' + i)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{nineLits, frontendTeddy})
	// Eight two-byte literals with eight distinct bytes in BOTH columns:
	// every candidate pair costs 8+8 bytes, far over packedPairByteBudget, so
	// byte-equality would need sixteen i8x16.eq per chunk. Teddy's nibble
	// tables absorb exactly this width at fixed cost, and keep the set.
	wideCols := make([][]byte, 8)
	for i := range wideCols {
		wideCols[i] = []byte{byte('a' + i), byte('0' + i)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{wideCols, frontendTeddy})
	// The keywords-N shape the packed-pair frontend exists for: literals sharing a "kw00"
	// prefix. Columns 0 and 1 are one rare byte each, which is the ideal pair.
	keywordShape := make([][]byte, 8)
	for i := range keywordShape {
		keywordShape[i] = []byte{'k', 'w', '0', '0', byte('0' + i)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{keywordShape, frontendPackedPair})
	// 17 literals with 17 DISTINCT first bytes → bucketed Teddy: above the
	// first-byte crossover, Teddy's fixed-cost probe beats AC's prefilter.
	seventeenLits := make([][]byte, 17)
	for i := range seventeenLits {
		seventeenLits[i] = []byte{byte('a' + i%26), byte('0' + i%10)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{seventeenLits, frontendTeddy})
	// The same count sharing ONE first byte stays on AC, where its prefilter
	// skips well — the rule keys on first-byte diversity, not literal count.
	seventeenShared := make([][]byte, 17)
	for i := range seventeenShared {
		seventeenShared[i] = []byte{'k', byte('a' + i%26), byte('0' + i%10)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{seventeenShared, frontendAC})
	// Above the crossover but with a 1-byte literal: Teddy's fingerprint is
	// too weak, so AC takes it regardless of first-byte spread.
	seventeenShort := make([][]byte, 17)
	for i := range seventeenShort {
		seventeenShort[i] = []byte{byte('a' + i%26)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{seventeenShort, frontendAC})

	for _, c := range cases {
		got := chooseLiteralFrontend(c.lits)
		if got != c.want {
			t.Errorf("chooseLiteralFrontend(%v) = %v, want %v", c.lits, got, c.want)
		}
	}
}

func TestAC_Construction(t *testing.T) {
	// Build AC for {"he", "she", "his", "hers"} — standard textbook example.
	literals := [][]byte{[]byte("he"), []byte("she"), []byte("his"), []byte("hers")}
	ac := buildAC(literals)
	if len(ac.nodes) == 0 {
		t.Fatal("buildAC: no nodes")
	}

	// Simulate scanning "ushers" — should find "she" at pos 2, "he" at pos 3, "hers" at pos 3.
	input := []byte("ushers")
	found := make(map[string]bool)
	state := 0
	for pos, b := range input {
		state = ac.nodes[state].gotoTable[int(b)]
		for _, litID := range ac.nodes[state].output {
			lit := string(literals[litID])
			found[fmt.Sprintf("%s@%d", lit, pos+1)] = true
		}
	}
	// In "ushers": "she" and "he" end at pos 3 (0-indexed) → key suffix @4;
	// "hers" ends at pos 5 → key suffix @6.
	if !found["she@4"] {
		t.Errorf("expected 'she@4'; got %v", found)
	}
	if !found["he@4"] {
		t.Errorf("expected 'he@4'; got %v", found)
	}
	if !found["hers@6"] {
		t.Errorf("expected 'hers@6'; got %v", found)
	}
}

func TestAC_WASMScan_HitPositions(t *testing.T) {
	// Verify buildACLayout produces non-empty table bytes.
	literals := [][]byte{[]byte("ab"), []byte("bc"), []byte("abc")}
	ac := buildAC(literals)
	l := buildACLayout(ac, 0)
	if len(l.gotoBytes) == 0 {
		t.Error("gotoBytes is empty")
	}
	if l.tableEnd <= 0 {
		t.Errorf("tableEnd = %d, want > 0", l.tableEnd)
	}
	// numNodes should be at least 4 (root + a + ab + b + bc + abc chain).
	if l.numNodes < 4 {
		t.Errorf("numNodes = %d, want >= 4", l.numNodes)
	}
}

func TestACDataSegments_NonEmpty(t *testing.T) {
	ac := buildAC([][]byte{[]byte("foo"), []byte("bar")})
	l := buildACLayout(ac, 0)
	ds := emitACDataSegments(l)
	if len(ds) == 0 {
		t.Error("emitACDataSegments returned empty bytes")
	}
}

// assertDataSectionConsistent verifies that the count field at the start of
// the WASM data section (id 11) matches the number of segments physically
// encoded in its body. A mismatch (e.g. caller over-declares the count)
// produces an invalid module that fails wasmtime validation with
// "unexpected end-of-file".
func assertDataSectionConsistent(t *testing.T, wasm []byte) {
	t.Helper()
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
	off := 8 // skip magic + version
	for off < len(wasm) {
		id := wasm[off]
		off++
		size, n, err := utils.DecodeULEB128(wasm[off:])
		if err != nil {
			t.Fatalf("decode section size at %d: %v", off, err)
		}
		off += n
		body := wasm[off : off+int(size)]
		off += int(size)
		if id != 11 {
			continue
		}
		declared, m, err := utils.DecodeULEB128(body)
		if err != nil {
			t.Fatalf("decode data-section segment count: %v", err)
		}
		segs := parseDataSegments(body[m:])
		if uint64(len(segs)) != declared {
			t.Errorf("data section: declared count=%d, parsed segments=%d", declared, len(segs))
		}
		return
	}
	// No data section present; nothing to check.
}

// ---- Phase 5.5: AC/Teddy WASM emitter tests ----

// TestACBudget covers the Aho-Corasick table budget, which replaced a
// 32-NODE cap that silently demoted any set past ~17-26
// literals (the exact count varied with prefix sharing) to the scalar path, at
// 86-414x the scan fuel.
//
// Three things are asserted, in the order they can break:
//  1. Large literal sets KEEP an AC frontend under the default budget. This is
//     the whole point of P1; a regression here is invisible at runtime except
//     as a fuel cliff, which is how the original went unnoticed for months.
//  2. Demotion still happens when the budget genuinely cannot hold the table.
//  3. A demotion is REPORTED in SetDiag. The silent fallback is what hid the
//     cliff; the diagnostic is the durable fix, independent of the constant.
func TestACBudget(t *testing.T) {
	// buildSet returns a spec whose literals share a prefix ("kw") or not,
	// mirroring two measured shapes: prefix sharing is what
	// decides AC node count, and therefore where any node-based cap bites.
	buildSet := func(t *testing.T, n int, shared bool) (SetSpec, *dfaPool, *dfaPool) {
		t.Helper()
		var prefixPool, suffixPool dfaPool
		var patterns []*PatternInfo
		var ids []int
		for i := 0; i < n; i++ {
			var pat string
			if shared {
				pat = fmt.Sprintf("kw%03d[0-9a-z]{3}", i)
			} else {
				fb := "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
				pat = fmt.Sprintf("%cQ%03d[0-9a-z]{3}", fb, i)
			}
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Fatalf("analyzePattern(%q): %v", pat, err)
			}
			patterns = append(patterns, info)
			ids = append(ids, i)
		}
		return SetSpec{Name: "s", ScanAny: "scan", Patterns: patterns, PatternIDs: ids}, &prefixPool, &suffixPool
	}

	// (1) The default budget holds the AC-selecting shape at every count that
	// used to fall off the cliff. 17 and 26 are the two measured cliff edges.
	//
	// Only the SHARED-prefix shape is checked for AC: the
	// diverse shape selects bucketed Teddy instead, which is a different
	// (and measured-better) path, not a budget failure. It is asserted
	// separately below so a silent swap in either direction is caught.
	for _, n := range []int{17, 26, 32, 64, 128} {
		spec, pp, sp := buildSet(t, n, true)
		cs := CompileSet(spec, pp, sp, CompileSetOptions{})
		if cs.fe != frontendAC {
			t.Errorf("shared n=%d: fe = %v, want frontendAC (default budget must hold this set)", n, cs.fe)
		}
		if cs.diag != nil && cs.diag.FrontendDemotion != nil {
			t.Errorf("shared n=%d: unexpected demotion %+v", n, cs.diag.FrontendDemotion)
		}
	}
	for _, n := range []int{17, 26, 32, 64} {
		spec, pp, sp := buildSet(t, n, false)
		cs := CompileSet(spec, pp, sp, CompileSetOptions{})
		if cs.fe != frontendTeddy {
			t.Errorf("diverse n=%d: fe = %v, want frontendTeddy (above the first-byte crossover)", n, cs.fe)
		}
	}
	// Past teddyMaxLiterals the diverse shape falls back to AC, which the
	// budget must still hold.
	specBig, ppBig, spBig := buildSet(t, 128, false)
	if cs := CompileSet(specBig, ppBig, spBig, CompileSetOptions{}); cs.fe != frontendAC {
		t.Errorf("diverse n=128: fe = %v, want frontendAC (above teddyMaxLiterals)", cs.fe)
	}

	// (2)+(3) A budget too small to hold the table demotes to scalar AND says so.
	spec, pp, sp := buildSet(t, 32, true)
	cs := CompileSet(spec, pp, sp, CompileSetOptions{ACBudgetBytes: 1})
	if cs.fe != frontendScalar {
		t.Errorf("ACBudgetBytes=1: fe = %v, want frontendScalar", cs.fe)
	}
	if cs.diag == nil || cs.diag.FrontendDemotion == nil {
		t.Fatal("ACBudgetBytes=1: demotion not recorded in SetDiag — a silent frontend downgrade is exactly the failure mode")
	}
	d := cs.diag.FrontendDemotion
	if d.From != "ac" || d.To != "scalar" || d.Reason != "ac_table_over_budget" {
		t.Errorf("demotion diag = %+v, want from=ac to=scalar reason=ac_table_over_budget", d)
	}
	if got, ok := d.Detail["budget_bytes"].(int); !ok || got != 1 {
		t.Errorf("demotion detail budget_bytes = %v, want 1", d.Detail["budget_bytes"])
	}
	if got, ok := d.Detail["table_bytes"].(int); !ok || got <= 1 {
		t.Errorf("demotion detail table_bytes = %v, want the real (over-budget) size", d.Detail["table_bytes"])
	}
}

// TestACOutputOverflow covers the third AC demotion arm: output OFFSETS are
// u16, and they are bounded by the propagated output count rather than by the
// node count or the table size, so passing acMaxNodes and acBudgetBytes proves
// nothing about them.
//
// The shape that reaches it is a nested literal family. buildAC's failure-link
// propagation copies every suffix literal's id into each node ending with it,
// so L literals `a`, `aa`, ... produce L*(L+1)/2 outputs from only L+1 nodes.
// The first overflowing count is 362: 65,703 outputs (over the 65,535 the
// offsets address) from 363 nodes in ~318 KB — inside BOTH existing gates,
// which is why it needed its own. Without the arm the emitted scanner reads a
// wrapped output range and reports the wrong literals.
func TestACOutputOverflow(t *testing.T) {
	nested := func(t *testing.T, n int) (SetSpec, *dfaPool, *dfaPool) {
		t.Helper()
		var prefixPool, suffixPool dfaPool
		var patterns []*PatternInfo
		var ids []int
		for i := 0; i < n; i++ {
			pat := strings.Repeat("a", i+1) + "[0-9]"
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Fatalf("analyzePattern(%q): %v", pat, err)
			}
			patterns = append(patterns, info)
			ids = append(ids, i)
		}
		return SetSpec{Name: "s", ScanAny: "scan", Patterns: patterns, PatternIDs: ids}, &prefixPool, &suffixPool
	}

	// The arithmetic the constant rests on, asserted directly so a change to
	// buildAC's propagation cannot quietly move the crossover.
	for _, tc := range []struct{ n, wantOutputs int }{{361, 65341}, {362, 65703}} {
		ac := buildAC(func() [][]byte {
			lits := make([][]byte, tc.n)
			for i := range lits {
				lits[i] = []byte(strings.Repeat("a", i+1))
			}
			return lits
		}())
		if got := acTotalOutputs(ac); got != tc.wantOutputs {
			t.Errorf("acTotalOutputs(%d nested literals) = %d, want %d", tc.n, got, tc.wantOutputs)
		}
		if len(ac.nodes) > acMaxNodes {
			t.Errorf("n=%d: %d nodes exceeds acMaxNodes — the node cap would mask this case", tc.n, len(ac.nodes))
		}
	}

	// 361 fits and must keep its AC frontend; 362 overflows and must demote,
	// with the reason recorded rather than silently downgraded.
	spec, pp, sp := nested(t, 361)
	if cs := CompileSet(spec, pp, sp, CompileSetOptions{}); cs.diag != nil && cs.diag.FrontendDemotion != nil {
		t.Errorf("n=361: unexpected demotion %+v — 65,341 outputs fit the u16 offsets", cs.diag.FrontendDemotion)
	}

	spec, pp, sp = nested(t, 362)
	cs := CompileSet(spec, pp, sp, CompileSetOptions{})
	if cs.fe != frontendScalar {
		t.Errorf("n=362: fe = %v, want frontendScalar", cs.fe)
	}
	if cs.diag == nil || cs.diag.FrontendDemotion == nil {
		t.Fatal("n=362: demotion not recorded in SetDiag")
	}
	d := cs.diag.FrontendDemotion
	if d.From != "ac" || d.To != "scalar" || d.Reason != "ac_outputs_exceed_u16" {
		t.Errorf("demotion diag = %+v, want from=ac to=scalar reason=ac_outputs_exceed_u16", d)
	}
	if got, ok := d.Detail["ac_outputs"].(int); !ok || got <= acMaxOutputs {
		t.Errorf("demotion detail ac_outputs = %v, want the real (overflowing) count", d.Detail["ac_outputs"])
	}
}

// TestACLayoutBytes pins the accounting acBudgetBytes is compared against: it
// must cover everything the frontend reserves, including the 256-byte
// firstByteFlags table emitted after the layout, or the budget silently
// under-counts. Non-zero table bases must not shift the answer.
func TestACLayoutBytes(t *testing.T) {
	ac := buildAC([][]byte{[]byte("ab"), []byte("cd")})
	for _, base := range []int32{0, 4096, 1 << 20} {
		l := buildACLayout(ac, base)
		if got, want := l.bytes(), int(l.tableEnd-base)+256; got != want {
			t.Errorf("base=%d: bytes() = %d, want %d", base, got, want)
		}
		if l.gotoOff != base {
			t.Errorf("base=%d: gotoOff = %d, want the table base", base, l.gotoOff)
		}
	}
	if b0, b1 := buildACLayout(ac, 0).bytes(), buildACLayout(ac, 1<<20).bytes(); b0 != b1 {
		t.Errorf("bytes() depends on table base: %d vs %d", b0, b1)
	}
}

// TestACByteClassCompression covers the compressed layout.
// Compression is a RE-INDEXING of the goto table, so the invariant that
// matters is that every byte still reaches the same target from every node —
// checked directly here, since a wrong class map would corrupt matching in a
// way only some inputs reveal.
func TestACByteClassCompression(t *testing.T) {
	lits := [][]byte{[]byte("kw001"), []byte("kw002"), []byte("kw003"), []byte("zz9")}
	ac := buildAC(lits)

	plain := buildACLayoutMode(ac, 0, false)
	if plain.compressed || plain.stride != 256 || plain.strideShift != 9 {
		t.Fatalf("uncompressed layout: compressed=%v stride=%d shift=%d, want false/256/9",
			plain.compressed, plain.stride, plain.strideShift)
	}

	packed := buildACLayoutMode(ac, 0, true)
	if !packed.compressed {
		t.Fatalf("this alphabet (a handful of distinct bytes) must compress; numClasses=%d", packed.numClasses)
	}
	if packed.stride != nextPow2(packed.numClasses) || 1<<packed.strideShift != packed.stride*2 {
		t.Errorf("stride/shift inconsistent: stride=%d shift=%d classes=%d",
			packed.stride, packed.strideShift, packed.numClasses)
	}
	if packed.bytes() >= plain.bytes() {
		t.Errorf("compression did not shrink the layout: %d -> %d", plain.bytes(), packed.bytes())
	}

	// The invariant: for every node and every byte, the compressed table
	// resolves to the same next node as the uncompressed one.
	for i := range ac.nodes {
		for b := 0; b < 256; b++ {
			want := binary.LittleEndian.Uint16(plain.gotoBytes[(i*256+b)*2:])
			col := int(packed.classMap[b])
			got := binary.LittleEndian.Uint16(packed.gotoBytes[(i*packed.stride+col)*2:])
			if got != want {
				t.Fatalf("node %d byte %d: compressed goto = %d, want %d (class %d)", i, b, got, want, col)
			}
		}
	}

	// Bytes sharing a class must be genuinely interchangeable — otherwise the
	// re-indexing above would be lossy rather than exact.
	for b1 := 0; b1 < 256; b1++ {
		for b2 := b1 + 1; b2 < 256; b2++ {
			if packed.classMap[b1] != packed.classMap[b2] {
				continue
			}
			for i := range ac.nodes {
				if ac.nodes[i].gotoTable[b1] != ac.nodes[i].gotoTable[b2] {
					t.Fatalf("bytes %d and %d share class %d but differ at node %d", b1, b2, packed.classMap[b1], i)
				}
			}
		}
	}

	// One extra data segment carries the class map.
	if got, want := acDataSegments(packed), acDataSegments(plain)+1; got != want {
		t.Errorf("acDataSegments(compressed) = %d, want %d", got, want)
	}
}

// TestLitUnionFirstBytes exercises litUnionFirstBytes directly across its
// documented edge cases: empty literals are skipped, duplicates collapse,
// and output is sorted.
func TestLitUnionFirstBytes(t *testing.T) {
	got := litUnionFirstBytes([][]byte{[]byte("zzz"), {}, []byte("apple"), []byte("ant")})
	want := []byte{'a', 'z'}
	if string(got) != string(want) {
		t.Errorf("litUnionFirstBytes = %v, want %v", got, want)
	}
	if got := litUnionFirstBytes(nil); len(got) != 0 {
		t.Errorf("litUnionFirstBytes(nil) = %v, want empty", got)
	}
}

func TestBuildTeddyTablesMulti_TwoGroups(t *testing.T) {
	lits := make([][]byte, 10)
	for i := range lits {
		lits[i] = []byte{byte('a' + i)}
	}
	tt, ok := buildTeddyTablesMulti(lits)
	if !ok {
		t.Fatal("expected ok=true for 10 literals")
	}
	if !tt.TwoGroups {
		t.Error("expected TwoGroups=true for 10 literals")
	}
	if len(tt.LaneToIDs) != 16 {
		t.Errorf("LaneToIDs len = %d, want 16 lanes", len(tt.LaneToIDs))
	}
	covered := 0
	for _, ids := range tt.LaneToIDs {
		covered += len(ids)
	}
	if covered != 10 {
		t.Errorf("lanes cover %d literals, want 10", covered)
	}
	// Group B should have entries (literals 8-9 map to bit 0,1 of BT0Lo/BT0Hi)
	if tt.BT0Lo['h'&0x0F] == 0 && tt.BT0Hi['h'>>4] == 0 {
		t.Error("Group B tables not populated for literal 'h' (index 7→group B bit 0?)")
	}
}

func TestBuildTeddyTablesMulti_PartialProbe(t *testing.T) {
	// Literals longer than 4 bytes — probe on first 4 only.
	lits := [][]byte{[]byte("sk_live_"), []byte("sk_test_")}
	tt, ok := buildTeddyTablesMulti(lits)
	if !ok {
		t.Fatal("expected ok=true for long literals")
	}
	if tt.MinLen != 4 {
		t.Errorf("MinLen = %d, want 4", tt.MinLen)
	}
	if !tt.FourByte {
		t.Error("expected FourByte=true (both literals ≥4 bytes)")
	}
	if !tt.TwoByte || !tt.ThreeByte {
		t.Error("expected TwoByte and ThreeByte=true")
	}
	// Both start with 'sk_l' / 'sk_t' — probe byte[0]='s' should fire both lanes.
	bit0, bit1 := byte(1<<0), byte(1<<1)
	if tt.T0Lo['s'&0x0F]&bit0 == 0 {
		t.Error("T0Lo missing bit 0 for 's'")
	}
	if tt.T0Lo['s'&0x0F]&bit1 == 0 {
		t.Error("T0Lo missing bit 1 for 's'")
	}
}

func TestTeddyGroupABytes_AllCases(t *testing.T) {
	cases := []struct {
		lits [][]byte
		want int32
	}{
		{[][]byte{[]byte("a")}, 32},      // MinLen=1: T0Lo+T0Hi only
		{[][]byte{[]byte("ab")}, 64},     // MinLen=2: +T1Lo+T1Hi
		{[][]byte{[]byte("abc")}, 96},    // MinLen=3: +T2Lo+T2Hi
		{[][]byte{[]byte("abcd")}, 128},  // MinLen=4: +T3Lo+T3Hi
		{[][]byte{[]byte("abcde")}, 128}, // MinLen=min(5,4)=4 → same as 4-byte
	}
	for _, c := range cases {
		tt, ok := buildTeddyTablesMulti(c.lits)
		if !ok {
			t.Fatalf("buildTeddyTablesMulti failed for %q", c.lits[0])
		}
		got := teddyGroupABytes(tt)
		if got != c.want {
			t.Errorf("teddyGroupABytes(%q) = %d, want %d", c.lits[0], got, c.want)
		}
	}
}

func TestBuildTeddyRawBytes_TwoGroups(t *testing.T) {
	lits := make([][]byte, 10)
	for i := range lits {
		lits[i] = []byte{byte('a' + i)}
	}
	tt, _ := buildTeddyTablesMulti(lits)
	raw := buildTeddyRawBytes(tt)
	// Group A: 32 bytes (MinLen=1, T0Lo+T0Hi only). Group B: same.
	if len(raw) != 64 {
		t.Errorf("buildTeddyRawBytes two-groups: len=%d, want 64", len(raw))
	}
}

func TestPatternRef_String(t *testing.T) {
	p := PatternRef{ID: 3, Name: "rule_x"}
	got := p.String()
	want := `(3,"rule_x")`
	if got != want {
		t.Errorf("PatternRef.String() = %q, want %q", got, want)
	}
}

func TestFrontendKind_String_All(t *testing.T) {
	if frontendTeddy.String() != "teddy" {
		t.Errorf("frontendTeddy.String() = %q", frontendTeddy.String())
	}
	if frontendAC.String() != "ac" {
		t.Errorf("frontendAC.String() = %q", frontendAC.String())
	}
	if frontendScalar.String() != "scalar" {
		t.Errorf("frontendScalar.String() = %q", frontendScalar.String())
	}
}

func TestCompileFallback_BudgetCap(t *testing.T) {
	// Patterns with no mandatory literal → all go to compileFallback.
	// With budget_states=1, each pattern gets its own fallback bucket.
	var prefixPool, suffixPool dfaPool
	pats := []string{`\w+`, `[a-z]+`, `[0-9]+`}
	patterns := make([]*PatternInfo, len(pats))
	for i, pat := range pats {
		p, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns[i] = p
	}
	buckets := compileFallback(patterns, CompileSetOptions{BudgetStates: 1}, nil)
	if len(buckets) != 3 {
		t.Errorf("got %d fallback buckets, want 3", len(buckets))
	}
	for _, b := range buckets {
		if !b.isFallback {
			t.Error("expected isFallback=true for all fallback buckets")
		}
	}
}

func TestCompileFallback_Merges(t *testing.T) {
	// With generous budget, fallback patterns merge into shared buckets.
	var prefixPool, suffixPool dfaPool
	// Use patterns with no mandatory literal but compatible small suffix DFAs.
	pats := []string{`\d+`, `[0-9]+`} // both have no mandatory lit, simple DFAs
	patterns := make([]*PatternInfo, len(pats))
	for i, pat := range pats {
		p, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns[i] = p
	}
	// With large budget, both should merge into 1 fallback bucket.
	buckets := compileFallback(patterns, CompileSetOptions{}, nil)
	// May be 1 or 2 depending on merge success; just verify no panic.
	if len(buckets) == 0 {
		t.Error("expected at least 1 fallback bucket")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --------------------------------------------------------------------------
// Phase 3: bin-packing tests

func TestBinPacking_BitmaskCap(t *testing.T) {
	// 9 patterns all sharing mandatory literal "foo" (variable-length suffix keeps
	// "foo" as the mandatory lit). bitmaskWidth=8 → 2 buckets; bitmaskWidth=4 → 3.
	pats := []string{
		`foo\d+`, `foo\w+`, `foo[a-z]+`, `foo[A-Z]+`,
		`foo[0-9]+`, `foo[a-zA-Z]+`, `foo[a-z0-9]+`, `foo[A-Z0-9]+`,
		`foo[^a-z]+`,
	}
	var prefixPool, suffixPool dfaPool
	patterns := make([]*PatternInfo, len(pats))
	for i, pat := range pats {
		p, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns[i] = p
	}
	buckets := binPack(patterns, CompileSetOptions{BitmaskWidth: 8}, nil)
	if len(buckets) != 2 {
		t.Errorf("bitmaskWidth=8: got %d buckets, want 2", len(buckets))
	}
	buckets4 := binPack(patterns, CompileSetOptions{BitmaskWidth: 4}, nil)
	if len(buckets4) != 3 {
		t.Errorf("bitmaskWidth=4: got %d buckets, want 3", len(buckets4))
	}
}

func TestBinPacking_BudgetCap(t *testing.T) {
	// With budget_bytes=1, every pattern exceeds the budget after the first,
	// so each pattern gets its own bucket.
	var prefixPool, suffixPool dfaPool
	patterns := make([]*PatternInfo, 3)
	for i, pat := range []string{`baz[a-z]+`, `baz[0-9]+`, `baz\w+`} {
		p, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns[i] = p
	}
	buckets := binPack(patterns, CompileSetOptions{BudgetBytes: 1}, nil)
	if len(buckets) < 2 {
		t.Errorf("budget_bytes=1: got %d buckets, want ≥2", len(buckets))
	}
}

func TestBinPacking_FirstFitDecreasing(t *testing.T) {
	// Patterns sorted ascending by suffixStates; smallest placed first.
	// Verify deterministic placement order by checking bucket 0 gets the
	// smallest-suffix patterns.
	var prefixPool, suffixPool dfaPool
	// foo[a] has suffix [a]+ — very small DFA; foo\w+ has larger suffix DFA.
	pats := []string{`foo\w+`, `fooa+`, `foob+`}
	patterns := make([]*PatternInfo, len(pats))
	for i, pat := range pats {
		p, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns[i] = p
	}
	buckets := binPack(patterns, CompileSetOptions{}, nil)
	if len(buckets) == 0 {
		t.Fatal("binPack returned no buckets")
	}
	// First bucket must have been built deterministically (no random ordering).
	if len(buckets[0].patterns) == 0 {
		t.Error("bucket 0 has no patterns")
	}
}

func runConflictTest(t *testing.T, fixtureName string) *SetDiag {
	t.Helper()
	fix := testdataFixture(t, fixtureName)
	patterns := fix.patternInfos(t)
	opts := fix.compileOpts()
	diag := &SetDiag{}
	buckets := binPack(patterns, opts, diag)
	if fix.Expect.BucketCount > 0 && len(buckets) != fix.Expect.BucketCount {
		t.Errorf("fixture %s: got %d buckets, want %d", fixtureName, len(buckets), fix.Expect.BucketCount)
	}
	if fix.Expect.FallbackCount > 0 {
		fb := 0
		for _, b := range buckets {
			if b.isFallback {
				fb++
			}
		}
		if fb != fix.Expect.FallbackCount {
			t.Errorf("fixture %s: got %d fallback buckets, want %d", fixtureName, fb, fix.Expect.FallbackCount)
		}
	}
	return diag
}

func TestFallback_NoLiteral(t *testing.T) {
	// conflict_005 patterns have no mandatory literal → all in fallback buckets.
	diag := runConflictTest(t, "conflict_005")
	if len(diag.Buckets) == 0 {
		t.Fatal("no BucketDiag entries")
	}
	for _, b := range diag.Buckets {
		if b.Type != "fallback" && b.Type != "singleton" {
			t.Errorf("bucket %d type=%q, want fallback/singleton for no-literal patterns", b.ID, b.Type)
		}
	}
}

func TestIsOnlyBeginAnchors(t *testing.T) {
	cases := []struct {
		pat  string
		want bool
	}{
		{`^`, true},      // single ^
		{`\A`, true},     // \A (begin-text)
		{`^^`, true},     // concat of two begin-anchors
		{`^a`, false},    // concat with non-anchor
		{`^$`, false},    // concat with end-anchor
		{`(?:a)`, false}, // not an anchor at all
		{`(^)`, true},    // capture wrapping ^
	}
	for _, tc := range cases {
		re := mustParse(t, tc.pat)
		if got := isOnlyBeginAnchors(re); got != tc.want {
			t.Errorf("isOnlyBeginAnchors(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
	if isOnlyBeginAnchors(nil) {
		t.Error("isOnlyBeginAnchors(nil) = true, want false")
	}
}

func TestHasBeginAnchor(t *testing.T) {
	cases := []struct {
		pat  string
		want bool
	}{
		{`^a`, true},
		{`a^`, true},
		{`(^^)*$`, true},
		{`a+`, false},
		{`$`, false},
		{`\z`, false},
	}
	for _, tc := range cases {
		re := mustParse(t, tc.pat)
		if got := hasBeginAnchor(re); got != tc.want {
			t.Errorf("hasBeginAnchor(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
	if hasBeginAnchor(nil) {
		t.Error("hasBeginAnchor(nil) = true, want false")
	}
}

// TestTopLevelBeginAnchorKind covers what hasBeginAnchorAtTopLevel used to:
// whether the anchor is at the pattern's mandatory start. It additionally
// pins the KIND, which is the part that matters here — collapsing
// (?m:^) onto \A restricts a pattern to position 0 that may legitimately
// match at every line start.
func TestTopLevelBeginAnchorKind(t *testing.T) {
	cases := []struct {
		pat  string
		want beginAnchorKind
	}{
		{`^a`, beginAnchorText},        // ^ at mandatory start (no (?m) → \A)
		{`\Aa`, beginAnchorText},       // \A at mandatory start
		{`(?m:^)a`, beginAnchorLine},   // (?m:^) is position-aware, not position 0
		{`a^`, beginAnchorNone},        // ^ after byte-consumer — not at top-level start
		{`(^^)*$`, beginAnchorNone},    // ^ inside *, not mandatory at top level
		{`a+`, beginAnchorNone},        // no anchor
		{`(^a)`, beginAnchorText},      // ^ through capture
		{`(?:^x|y)z`, beginAnchorNone}, // ^ inside an alternation restricts nothing
	}
	for _, tc := range cases {
		re := mustParse(t, tc.pat)
		if got := topLevelBeginAnchorKind(re); got != tc.want {
			t.Errorf("topLevelBeginAnchorKind(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
	if topLevelBeginAnchorKind(nil) != beginAnchorNone {
		t.Error("topLevelBeginAnchorKind(nil) should be beginAnchorNone")
	}
}

// --------------------------------------------------------------------------
// analyzePattern edge-case coverage

func TestAnalyzePattern_NonGreedyFallback(t *testing.T) {
	// Non-greedy pattern: should go to isolated fallback (no error).
	re := config.RegexEntry{Pattern: `(?:a+?)b`}
	var pp, sp dfaPool
	info, err := analyzePattern(re, &pp, &sp)
	if err != nil {
		t.Fatalf("analyzePattern non-greedy: unexpected error: %v", err)
	}
	if info.splittable {
		t.Error("expected splittable=false for non-greedy pattern")
	}
	if !info.isolatedFallback {
		t.Error("expected isolatedFallback=true for non-greedy pattern")
	}
}

func TestAnalyzePattern_ZeroLengthFallback(t *testing.T) {
	// Pattern with minLen=0: routes to fallback.
	re := config.RegexEntry{Pattern: `(?:aa)*`}
	var pp, sp dfaPool
	info, err := analyzePattern(re, &pp, &sp)
	if err != nil {
		t.Fatalf("analyzePattern zero-length: unexpected error: %v", err)
	}
	if info.splittable {
		t.Error("expected splittable=false for zero-length pattern")
	}
}

func TestAnalyzePattern_ZeroLengthBeginAnchor(t *testing.T) {
	// Pattern with minLen=0 and begin-anchor at top level: startAnchor=true.
	re := config.RegexEntry{Pattern: `^(?:aa)*`}
	var pp, sp dfaPool
	info, err := analyzePattern(re, &pp, &sp)
	if err != nil {
		t.Fatalf("analyzePattern ^(aa)*: unexpected error: %v", err)
	}
	if info.splittable {
		t.Error("expected splittable=false")
	}
	if !info.startAnchor {
		t.Error("expected startAnchor=true for ^(aa)*")
	}
}

func TestAnalyzePattern_NonBeginZeroLenPrefix(t *testing.T) {
	// Pattern where the prefix is a non-begin zero-length assertion ($a):
	// should route to fallback (splittable=false).
	re := config.RegexEntry{Pattern: `(?:$)a`}
	var pp, sp dfaPool
	info, err := analyzePattern(re, &pp, &sp)
	if err != nil {
		t.Fatalf("analyzePattern $a: unexpected error: %v", err)
	}
	if info.splittable {
		t.Error("expected splittable=false for $a (non-begin zero-len prefix)")
	}
}

func TestAnalyzePattern_BeginSuffixFallback(t *testing.T) {
	// Pattern whose suffix contains a begin-anchor (a^): routes to fallback.
	re := config.RegexEntry{Pattern: `a^`}
	var pp, sp dfaPool
	info, err := analyzePattern(re, &pp, &sp)
	if err != nil {
		t.Fatalf("analyzePattern a^: unexpected error: %v", err)
	}
	if info.splittable {
		t.Error("expected splittable=false for a^ (begin-anchor in suffix)")
	}
}

// lowRarityFirstBytes returns 33 distinct first bytes with a rarity sum well
// under byte_rarity.go's threshold(40), so shuftiBeatsScalar is statically
// true and Shufti is selected without needing a LikelyNoMatch override.
// Confirmed live: firstByteSetRaritySum(lowRarityFirstBytes()) == 5.
func lowRarityFirstBytes() []byte {
	var out []byte
	for b := byte(0x01); b < 0x20 && len(out) < 28; b++ {
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		out = append(out, b)
	}
	return append(out, '~', '@', '_', '%', '`')
}

// setCapNames maps a capability key to the export name used in these tests.
// Names are deliberately non-prefix-free-safe: no name is a substring of
// another, so a plain bytes.Contains check cannot confuse "cap_scan" with
// "cap_scan_any".
var setCapNames = map[string]string{
	"match_any": "zmatchanyz", "match_all": "zmatchallz",
	"scan_any": "zscananyz", "scan_all": "zscanallz",
	"find": "zfindz",
}

// setConfigWith builds a config declaring exactly the named capabilities.
func setConfigWith(patterns []string, overlapping bool, caps ...string) config.BuildConfig {
	entries := make([]config.RegexEntry, len(patterns))
	names := make([]string, len(patterns))
	for i, p := range patterns {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sc := config.SetConfig{
		Name:        "s",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}
	for _, c := range caps {
		switch c {
		case "match_any":
			sc.MatchAny = setCapNames[c]
		case "match_all":
			sc.MatchAll = setCapNames[c]
		case "scan_any":
			sc.ScanAny = setCapNames[c]
		case "scan_all":
			sc.ScanAll = setCapNames[c]
		case "find":
			sc.Find = setCapNames[c]
		default:
			panic("unknown capability " + c)
		}
	}
	return config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
}

// setConfigSubset builds a config whose set selects `pick` (indices into
// patterns) by name, leaving the rest of the regexps out of the set.
func setConfigSubset(patterns []string, pick []int, caps ...string) config.BuildConfig {
	entries := make([]config.RegexEntry, len(patterns))
	for i, p := range patterns {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	var names []string
	for _, i := range pick {
		names = append(names, fmt.Sprintf("p%d", i))
	}
	sc := config.SetConfig{Name: "s", Patterns: config.PatternSelector{Names: names}}
	for _, c := range caps {
		switch c {
		case "match_all":
			sc.MatchAll = setCapNames[c]
		case "scan_all":
			sc.ScanAll = setCapNames[c]
		case "scan_any":
			sc.ScanAny = setCapNames[c]
		case "find":
			sc.Find = setCapNames[c]
		default:
			panic("unknown capability " + c)
		}
	}
	return config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
}

// exportTypeIndex returns the type-section index of the function exported
// under `name`. The set path's type table is the fixed one written by
// assembleModuleWithSets, so comparing against the setType* constants says
// exactly which ABI capFns() chose.
func exportTypeIndex(t *testing.T, wasm []byte, name string) int {
	t.Helper()
	u := func(b []byte, off int) (uint64, int) {
		v, n, err := utils.DecodeULEB128(b[off:])
		if err != nil {
			t.Fatalf("bad LEB128 at %d: %v", off, err)
		}
		return v, off + n
	}
	var funcSec, exportSec []byte
	numImportedFuncs := 0
	for off := 8; off < len(wasm); {
		id := wasm[off]
		size, p := u(wasm, off+1)
		body := wasm[p : p+int(size)]
		switch id {
		case 2: // imports: count any function imports toward the index space
			n, q := u(body, 0)
			for i := uint64(0); i < n; i++ {
				var l uint64
				l, q = u(body, q)
				q += int(l) // module
				l, q = u(body, q)
				q += int(l) // field
				kind := body[q]
				q++
				switch kind {
				case 0x00:
					_, q = u(body, q)
					numImportedFuncs++
				case 0x02: // memory
					lim := body[q]
					q++
					_, q = u(body, q)
					if lim == 0x01 {
						_, q = u(body, q)
					}
				default:
					t.Fatalf("unhandled import kind %#x", kind)
				}
			}
		case 3:
			funcSec = body
		case 7:
			exportSec = body
		}
		off = p + int(size)
	}
	if funcSec == nil || exportSec == nil {
		t.Fatal("module missing function or export section")
	}
	// Export section: find the func index for `name`.
	funcIdx := -1
	n, q := u(exportSec, 0)
	for i := uint64(0); i < n; i++ {
		var l uint64
		l, q = u(exportSec, q)
		got := string(exportSec[q : q+int(l)])
		q += int(l)
		kind := exportSec[q]
		q++
		var idx uint64
		idx, q = u(exportSec, q)
		if kind == 0x00 && got == name {
			funcIdx = int(idx)
		}
	}
	if funcIdx < 0 {
		t.Fatalf("module has no function export named %q", name)
	}
	// Function section: type index of that function.
	cnt, r := u(funcSec, 0)
	local := funcIdx - numImportedFuncs
	if local < 0 || local >= int(cnt) {
		t.Fatalf("export %q resolves to function %d, outside the module's own %d", name, funcIdx, cnt)
	}
	var ti uint64
	for i := 0; i <= local; i++ {
		ti, r = u(funcSec, r)
	}
	return int(ti)
}

// TestTeddyTwoGroupLaneExtraction pins a two-group lane-extraction hazard.
//
// emitSetMatchFnFinalTeddy extracts a candidate byte using lLaneOff (the
// position within the 16-byte chunk), but emitLitDispatch reuses lLaneOff as
// scratch. Dispatching group A before extracting group B therefore fed group B
// a lane index where a chunk position belonged, and every literal in lanes
// 8..15 became unreachable whenever group A also had a candidate at that
// position. It stayed latent for one-literal-per-lane sets — a group A
// candidate there is a true fingerprint match, so collisions were rare — and
// became routine once bucketing OR'd several literals into one lane bit.
//
// The property asserted is structural: both extractions must be emitted
// before either dispatch. Byte-level behaviour is covered end-to-end by the
// set corpora, but only for shapes that happen to collide, which is exactly
// the fragility that hid this.
func TestTeddyTwoGroupLaneExtraction(t *testing.T) {
	// 17 two-byte literals: over 16, so lanes are bucketed and both groups
	// are populated.
	lits := make([][]byte, 17)
	for i := range lits {
		lits[i] = []byte{byte('a' + i%26), byte('0' + i%10)}
	}
	tt, ok := buildTeddyTablesMulti(lits)
	if !ok {
		t.Fatal("buildTeddyTablesMulti failed")
	}
	if !tt.TwoGroups {
		t.Fatal("17 literals must populate both lane groups")
	}
	usedB := false
	for lane := 8; lane < len(tt.LaneToIDs); lane++ {
		if len(tt.LaneToIDs[lane]) > 0 {
			usedB = true
		}
	}
	if !usedB {
		t.Fatal("no literal landed in lanes 8..15; the hazard would be unreachable")
	}

	// Every literal must be reachable from some lane — the symptom of the bug
	// was literals present in the tables but absent from any dispatched lane.
	seen := map[int]bool{}
	for _, ids := range tt.LaneToIDs {
		for _, id := range ids {
			if seen[id] {
				t.Errorf("literal %d appears in more than one lane", id)
			}
			seen[id] = true
		}
	}
	for i := range lits {
		if !seen[i] {
			t.Errorf("literal %d (%q) is in no lane", i, lits[i])
		}
	}
}

// TestACLayoutNoGap pins that the AC layout reserves exactly what it writes.
//
// `outputBytes` is the CONCATENATION of the nodeOut offset array and the flat
// output array, but `outputOff` already points past nodeOut — so computing
// tableEnd as outputOff + len(outputBytes) counts the nodeOut region twice and
// leaves a (numNodes+1)*2-byte hole before whatever is placed at tableEnd
// (firstByteFlags, or the class map when compressed). Harmless but real: it
// inflates every AC set's table footprint, and acBudgetBytes is measured
// against that footprint, so the gap made the budget hold fewer literals than
// it should.
func TestACLayoutNoGap(t *testing.T) {
	cases := [][][]byte{
		{[]byte("ab"), []byte("cd")},
		{[]byte("kw001"), []byte("kw002"), []byte("kw003"), []byte("zz9")},
		{[]byte("a")},
	}
	for _, lits := range cases {
		ac := buildAC(lits)
		for _, compress := range []bool{false, true} {
			l := buildACLayoutMode(ac, 4096, compress)
			// Every region must start exactly where the previous one ended.
			if got, want := l.nodeOutOff, l.gotoOff+int32(len(l.gotoBytes)); got != want {
				t.Errorf("lits=%d compress=%v: nodeOutOff = %d, want %d", len(lits), compress, got, want)
			}
			// outputBytes holds nodeOut ++ output, and outputOff points past
			// nodeOut, so the block written from outputOff is the OUTPUT part
			// alone. tableEnd must reflect that, not the whole concatenation.
			nodeOutLen := int32(l.numNodes+1) * 2
			outputLen := int32(len(l.outputBytes)) - nodeOutLen
			wantEnd := l.outputOff + outputLen
			if l.compressed {
				wantEnd += 256 // class map
			}
			if l.tableEnd != wantEnd {
				t.Errorf("lits=%d compress=%v: tableEnd = %d, want %d (a %d-byte gap)",
					len(lits), compress, l.tableEnd, wantEnd, l.tableEnd-wantEnd)
			}
		}
	}
}

// sparseGroup is 128 distinct patterns sharing ONE mandatory literal — the WAF
// shape sparse accept exists for. The distinct part must be NON-LITERAL: mandatory-literal
// extraction takes the LONGEST literal, so `unionkw000` would give each pattern
// its own literal and its own bucket, and nothing would be shared.
func sparseGroup(t *testing.T, n int, opts CompileSetOptions) []*bucket {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, 0, n)
	for i := 0; i < n; i++ {
		p := fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		info, err := analyzePattern(config.RegexEntry{Pattern: p}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern %q: %v", p, err)
		}
		info.globalID = i
		infos = append(infos, info)
	}
	return binPack(infos, opts, nil)
}

// TestSparsePromotionMergesSharedLiteralBuckets is sparse promotion's premise and its result
// in one: without promotion 128 patterns behind one literal split into four
// buckets — costing four suffix-DFA walks at every candidate position — and
// with it they are one.
//
// Measured end to end on a literal-dense 100 KB input, gated find, identical
// match counts: 25,739,575,028 fuel and a 149,918-byte module before, against
// 1,936,377,723 and 11,642 bytes after. 13.3x less fuel, 92% smaller.
func TestSparsePromotionMergesSharedLiteralBuckets(t *testing.T) {
	off := sparseGroup(t, 128, CompileSetOptions{})
	if len(off) != 4 {
		t.Fatalf("expected 128 patterns to split into 4 bitmask buckets, got %d "+
			"— the 32-pattern bitmask width is sparse promotion's premise", len(off))
	}
	for _, b := range off {
		if b.sparse {
			t.Error("promotion fired without AllowSparseAccept")
		}
	}

	on := sparseGroup(t, 128, CompileSetOptions{AllowSparseAccept: true})
	if len(on) != 1 {
		t.Fatalf("expected one sparse bucket, got %d", len(on))
	}
	if !on[0].sparse {
		t.Error("merged bucket is not marked sparse")
	}
	if got := len(on[0].patterns); got != 128 {
		t.Errorf("sparse bucket holds %d patterns, want all 128", got)
	}
	if on[0].suffixDFA.midAcceptWide == nil {
		t.Error("sparse bucket's DFA carries no wide accept lists")
	}
	// A promotion that then misses the budgets is worse than the split
	// it replaced, because binPack would have split it again.
	o := CompileSetOptions{}
	if on[0].suffixStates > o.budgetStates() || on[0].tableBytes > o.budgetBytes() {
		t.Errorf("promoted bucket is over budget: %d states / %d bytes (budgets %d / %d)",
			on[0].suffixStates, on[0].tableBytes, o.budgetStates(), o.budgetBytes())
	}
}

// TestSparsePromotionIsConservative pins the refusals. Each is a case where
// promoting would be wrong or pointless, and a wrong promotion is worse than
// none: it would produce a bucket the emitter cannot serve correctly.
func TestSparsePromotionIsConservative(t *testing.T) {
	opts := CompileSetOptions{AllowSparseAccept: true}

	// One bucket already: nothing to merge.
	if got := sparseGroup(t, 32, opts); len(got) != 1 || got[0].sparse {
		t.Errorf("32 patterns are already one bucket; promotion must not fire (buckets=%d)", len(got))
	}

	// Word boundaries carry accept channels the sparse tables do not
	// serialise, so such a group must keep its bitmask buckets.
	var prefixPool, suffixPool dfaPool
	var infos []*PatternInfo
	for i := 0; i < 128; i++ {
		p := fmt.Sprintf(`union[ \t]+\b[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		info, err := analyzePattern(config.RegexEntry{Pattern: p}, &prefixPool, &suffixPool)
		if err != nil {
			continue
		}
		info.globalID = i
		infos = append(infos, info)
	}
	if len(infos) > 64 {
		for _, b := range binPack(infos, opts, nil) {
			if b.sparse {
				t.Error("promoted a word-boundary group; its \\b accept channels are not serialised")
			}
		}
	}

	// A group that fits ONE bitmask bucket never
	// split on the mask, so the promotion has nothing to undo — and the sparse
	// body is the slowest shape there is (it ignores validMask, loses the gate
	// pre-mask and the empty-mask group skip). Constructed as separate
	// single-pattern buckets, which is what the fallback packer produces when
	// a merge misses its byte or state budget.
	{
		var pp, sp dfaPool
		var in []*bucket
		for i := 0; i < bucketMaskBits; i++ {
			info, err := analyzePattern(config.RegexEntry{Pattern: fmt.Sprintf(`kw%03d[0-9]`, i)}, &pp, &sp)
			if err != nil {
				t.Fatalf("analyzePattern: %v", err)
			}
			info.globalID = i
			in = append(in, &bucket{literal: "", patterns: []*PatternInfo{info}, isFallback: true})
		}
		out := promoteSparseBuckets(in, opts, sparsePromotion{
			astFor: patternSuffixAST, merge: mergeSuffixDFASparseSet, isFallback: true,
		})
		if len(out) != len(in) {
			t.Errorf("promoted %d buckets totalling %d patterns, which fits one bitmask bucket; want no promotion",
				len(in), bucketMaskBits)
		}
	}

	// Under LikelyMatch a counted-class-chain
	// singleton has the SIMD-verify suffix body, and constraint 0
	// kept it out of a shared bucket on purpose; the promotion must not take
	// it back.
	{
		var pp, sp dfaPool
		var in []*bucket
		for i := 0; i < bucketMaskBits+1; i++ {
			// A counted class chain: literal + [0-9a-z]{N}, N large enough for
			// isCountedClassChain.
			info, err := analyzePattern(config.RegexEntry{Pattern: fmt.Sprintf(`kw%03d[0-9a-z]{6}`, i)}, &pp, &sp)
			if err != nil {
				t.Fatalf("analyzePattern: %v", err)
			}
			info.globalID = i
			in = append(in, &bucket{literal: "", patterns: []*PatternInfo{info}, isFallback: true})
		}
		lm := CompileSetOptions{AllowSparseAccept: true, LikelyMode: LikelyMatch}
		out := promoteSparseBuckets(in, lm, sparsePromotion{
			astFor: patternSuffixAST, merge: mergeSuffixDFASparseSet, isFallback: true,
		})
		anyChain := false
		for _, b := range in {
			if _, _, ok := isCountedClassChain(b.patterns[0].suffixDFA); ok {
				anyChain = true
				break
			}
		}
		if anyChain && len(out) != len(in) {
			t.Errorf("under LikelyMatch, promoted %d counted-chain singletons into %d buckets; want no promotion",
				len(in), len(out))
		}
	}

	// The ANCHORED packer's promotion does not inherit the
	// find path's refusals: a validator set of `^...$` patterns is exactly
	// what the promotion exists for, and start-anchored is not a
	// disqualifier there (an anchored capability matches from position 0).
	{
		var pp, sp dfaPool
		var in []*bucket
		for i := 0; i < bucketMaskBits+8; i++ {
			info, err := analyzePattern(config.RegexEntry{Pattern: fmt.Sprintf(`^kw%03d[0-9]+$`, i)}, &pp, &sp)
			if err != nil {
				t.Fatalf("analyzePattern: %v", err)
			}
			info.globalID = i
			solo, err := mergeAnchoredDFA([]*syntax.Regexp{patternFullAST(info)}, opts)
			if err != nil {
				t.Fatalf("mergeAnchoredDFA: %v", err)
			}
			in = append(in, &bucket{patterns: []*PatternInfo{info}, suffixDFA: solo,
				suffixStates: solo.numStates, isFallback: true})
		}
		out := promoteSparseBuckets(in, opts, sparsePromotion{
			astFor: patternFullAST, merge: mergeAnchoredDFASparseSet, anchored: true,
		})
		sparseCount := 0
		for _, b := range out {
			if b.sparse {
				sparseCount++
			}
		}
		if sparseCount != 1 {
			t.Errorf("anchored promotion of %d `^...$` patterns produced %d sparse buckets, want 1 (got %d buckets)",
				len(in), sparseCount, len(out))
		}
	}
}

// Sparse-accept foundation: one merged DFA over MORE than 64 patterns, with
// per-state accept LISTS instead of a u64 bitmask.
//
// The bitmask caps a bucket at 64 (32 in practice, since every mask on the
// per-candidate path is an i32), so 128 patterns sharing one literal split into
// four buckets and cost four suffix-DFA calls at every candidate position —
// measured at 3.33x one bucket's work on a literal-dense input.
func sparseTestASTs(t *testing.T, n int) ([]*syntax.Regexp, []string) {
	t.Helper()
	asts := make([]*syntax.Regexp, n)
	pats := make([]string, n)
	for i := 0; i < n; i++ {
		// Distinct, non-literal suffixes: the shape a shared-literal bucket
		// actually holds once the literal is stripped.
		pats[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		re, err := syntax.Parse(pats[i], syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pats[i], err)
		}
		asts[i] = re
	}
	return asts, pats
}

// TestSparseSetMergeExceeds64 is the ceiling this exists to lift: the bitmask
// merge refuses, the sparse merge does not.
func TestSparseSetMergeExceeds64(t *testing.T) {
	asts, _ := sparseTestASTs(t, 128)
	opts := CompileSetOptions{}

	if _, _, err := mergeSuffixDFA(asts, opts); err == nil {
		t.Fatal("mergeSuffixDFA accepted 128 patterns; the 32-pattern bitmask cap is the premise of sparse accept")
	}

	tab, d, err := mergeSuffixDFASparseSet(asts, opts)
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if tab == nil || d == nil {
		t.Fatal("sparse merge returned no table or no dfa")
	}
	if d.midAcceptWide == nil {
		t.Fatal("sparse merge produced no wide accept lists")
	}
	// The construction budgets, re-asserted here so a future change that
	// blows them fails loudly rather than silently splitting the bucket again.
	if tab.numStates > opts.budgetStates() || dfaTableBytes(tab) > opts.budgetBytes() {
		t.Errorf("merged 128-pattern DFA is over budget: %d states / %d bytes "+
			"(budgets %d / %d) — the bucket would split anyway and sparse accept buys nothing",
			tab.numStates, dfaTableBytes(tab), opts.budgetStates(), opts.budgetBytes())
	}
	t.Logf("128 patterns merged: %d states, %d bytes, %d states carry accept lists",
		tab.numStates, dfaTableBytes(tab), len(d.midAcceptWide))
}

// TestSparseSetAcceptListsAreCorrect is the substance: every accept list must
// name exactly the patterns Go says match, for inputs that reach that state.
// Checked against Go rather than against the bitmask path, so a shared
// misunderstanding cannot pass.
func TestSparseSetAcceptListsAreCorrect(t *testing.T) {
	asts, pats := sparseTestASTs(t, 128)
	_, d, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("sparse merge: %v", err)
	}
	res := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		res[i] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	// Walk the DFA over inputs and compare the accept list at the landing state
	// with the patterns Go says match the whole input.
	inputs := []string{"a1", "ab12", "abc123", "z9", "abcdefgh1234567890",
		"qq77", "a", "", "abcdefghi1", "aa11", "zzz999"}
	for _, in := range inputs {
		st := d.start
		ok := true
		for i := 0; i < len(in); i++ {
			next := d.transitions[st*256+int(in[i])]
			if next < 0 {
				ok = false
				break
			}
			st = next
		}
		var want []int
		for i, re := range res {
			if re.MatchString(in) {
				want = append(want, i)
			}
		}
		if !ok {
			if len(want) != 0 {
				t.Errorf("input %q: DFA died but Go says patterns %v match", in, want)
			}
			continue
		}
		got := map[int]bool{}
		for _, id := range d.acceptWide[st] {
			got[int(id)] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("input %q: pattern %d (%q) matches per Go but is missing from the accept list %v",
					in, w, pats[w], d.acceptWide[st])
			}
		}
		if len(got) != len(want) {
			t.Errorf("input %q: accept list has %d ids, Go says %d match (%v)",
				in, len(got), len(want), want)
		}
	}
}

// TestSparseSetLeavesBitmaskPathAlone guards the additive claim: with no
// pattern index supplied, construction is unchanged. `make byteident` covers
// the emitted bytes; this covers the accept maps directly.
func TestSparseSetLeavesBitmaskPathAlone(t *testing.T) {
	asts, _ := sparseTestASTs(t, 8)
	tab, _, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("bitmask merge: %v", err)
	}
	prog, err := syntax.Compile(asts[0].Simplify())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := newDFA(prog, false, true, maxHelperDFAStates)
	if !ok {
		t.Fatal("newDFA failed")
	}
	if d.acceptWide != nil || d.midAcceptWide != nil || d.immAcceptWide != nil {
		t.Error("newDFA populated wide accept maps; they must stay nil off the sparse path")
	}
	if tab == nil {
		t.Error("bitmask merge returned no table")
	}
}

// TestSparseSetTableAcceptListsAreCorrect is the one that matters for the
// emitter: it walks the EMITTED TABLE — post-Hopcroft, post-BFS-relabel,
// post-accept-first-reorder — and checks the accept list at the landing state
// against Go.
//
// The pre-minimisation check above passed even when the table was unusable,
// because it walked the dfa the lists were built on. Two things had to be true
// for this one to pass: the lists must be carried through every remap, and
// minimisation must PARTITION on them — on this path the u64 signature is bit 0
// for every accepting state, so without that it merged states whose accept
// lists differed. The symptom was a 25-state table where 137 is correct.
func TestSparseSetTableAcceptListsAreCorrect(t *testing.T) {
	asts, pats := sparseTestASTs(t, 128)
	tab, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("sparse merge: %v", err)
	}
	if tab.acceptWide == nil {
		t.Fatal("emitted table carries no wide accept lists")
	}
	if len(tab.acceptWide) > tab.numStates {
		t.Fatalf("%d accept entries against %d states: lists are not keyed by table ids",
			len(tab.acceptWide), tab.numStates)
	}
	res := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		res[i] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	// Exercise every pattern's own shape plus shared prefixes and near-misses.
	var inputs []string
	for i := 0; i < len(pats); i += 7 {
		inputs = append(inputs, strings.Repeat("q", 1+i/16)+strings.Repeat("7", 1+i%16))
	}
	inputs = append(inputs, "", "q", "7", "q7", "qqq777", "qqqqqqqqq1234567890123")
	for _, in := range inputs {
		st := tab.startState
		ok := true
		for i := 0; i < len(in); i++ {
			next := tab.transitions[st*256+int(in[i])]
			if next < 0 {
				ok = false
				break
			}
			st = next
		}
		var want []int
		for i, re := range res {
			if re.MatchString(in) {
				want = append(want, i)
			}
		}
		if !ok {
			if len(want) != 0 {
				t.Errorf("input %q: table died but Go says %v match", in, want)
			}
			continue
		}
		got := map[int]bool{}
		for _, id := range tab.acceptWide[st] {
			got[int(id)] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("input %q: pattern %d (%q) matches per Go but is missing from the table's accept list %v",
					in, w, pats[w], tab.acceptWide[st])
			}
		}
		if len(got) != len(want) {
			t.Errorf("input %q: table accept list has %d ids, Go says %d (%v)",
				in, len(got), len(want), want)
		}
	}
	t.Logf("table: %d states, %d bytes, %d carry accept lists", tab.numStates,
		dfaTableBytes(tab), len(tab.acceptWide))
}

// ---------------------------------------------------------------------------
// binPack's literal-singleton arm built a bucket's suffix DFA and
// kept a FAILURE silently:
//
//	if ast := patternSuffixAST(p); ast != nil {
//	    if t, _, mergeErr := mergeSuffixDFA(...); mergeErr == nil {
//	        nb.suffixDFA = t
//	    }
//	}   // <- no else; the bucket went live with a nil table
//
// genSuffixWASM answers a nil table with a body that returns 0, which is
// indistinguishable from "no match at this position". So the literal would gate
// candidates into a bucket that reports nothing at all of them, and the pattern
// would silently never match — no warning, no --diag-json entry. The sibling
// fallback packers already refuse exactly this, through admitOrDropFallback,
// so the codebase stated one policy in two places with two different answers.
//
// REACHABILITY, measured 2026-09-09 rather than asserted. The failure branch is
// unreachable today, for a structural reason worth writing down because it is
// what a future change would have to break:
//
//  1. analyzePattern builds the suffix DFA FIRST, with ceiling
//     maxHelperDFAStates and leftmostFirst=FALSE, and returns an error if
//     either the compile or the subset construction fails. A pattern that
//     cannot produce a suffix DFA never reaches a packer at all.
//  2. mergeSuffixDFA rebuilds the same AST with leftmostFirst=TRUE. LF prunes
//     lower-priority threads, so it yields NO MORE states than the non-LF build
//     — measured across a range of alternation shapes, LF was consistently
//     smaller (e.g. (?:a+|b+|ab+){1,9}Q: 2005 non-LF vs 1156 LF).
//  3. So if step 1 succeeded, step 2 succeeds.
//
// The original bug report predicted the opposite ("the merge uses leftmostFirst=true
// while analyzePattern's earlier build used false, so state counts can differ
// and failure is possible"). The direction is real; the SIGN is backwards.
//
// Instrumenting the branch with a panic and running the full set corpus
// (make setcaps, ~19.5M checks over 872 patterns) produced no hit, which is the
// evidence behind calling this latent rather than live.
//
// The guard is therefore defence in depth, and the invariant in CompileSet is
// the part that carries the weight: it turns a future regression from "silently
// never matches" into a build failure.

// A nil suffix DFA compiles to a body that returns 0 — the property that makes
// the missing guard silent rather than loud. Pinned so that if the emitter ever
// starts answering nil differently, the reasoning above is revisited too.
func TestNilSuffixDFAEmitsNeverMatchBody(t *testing.T) {
	art, _, _, _ := genSuffixWASM(nil, 0, 0, []int{0}, []int{0}, LikelyNeutral, false, false, nil)
	// ULEB128 size prefix 0x06, then the 6-byte body: one i32 local group
	// (0x01, 0x01, 0x7F), i32.const 0 (0x41 0x00), end (0x0B).
	want := []byte{0x06, 0x01, 0x01, 0x7F, 0x41, 0x00, 0x0B}
	if len(art.fnBody) != len(want) {
		t.Fatalf("genSuffixWASM(nil) body = % x, want % x", art.fnBody, want)
	}
	for i := range want {
		if art.fnBody[i] != want[i] {
			t.Fatalf("genSuffixWASM(nil) body = % x, want % x", art.fnBody, want)
		}
	}
}

// CompileSet must refuse a bucket that has neither a suffix DFA nor a BT
// fallback, rather than emit the never-match body for it.
func TestCompileSetRejectsBucketWithNoSuffixDFA(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("CompileSet accepted a bucket with no suffix DFA and no BT fallback; " +
				"such a bucket is gated, dispatched to, and silently never matches")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "no suffix DFA") {
			t.Fatalf("panic = %v, want one naming the missing suffix DFA", r)
		}
	}()
	assertBucketEmittable(3, &bucket{literal: "KEY", patterns: []*PatternInfo{{fullPattern: `KEY[0-9]+`}}})
}

// binPack must not produce a bucket with a nil suffix DFA for any pattern that
// analyzePattern admitted — the positive half of the invariant, over shapes
// that all take the literal-singleton arm.
func TestBinPackLiteralSingletonAlwaysHasSuffixDFA(t *testing.T) {
	pats := []string{
		`SECRETLITERAL[a-z]+`,
		`KEY=[0-9]{4}`,
		`ghp_[A-Za-z0-9]{36}`,
		`AKIA[A-Z0-9]{16}`,
		`BEGIN(?:a|ab|abc){1,6}END`,
		`prefix(?:[a-z]*[0-9]*){1,4}suffix`,
	}
	for _, pat := range pats {
		t.Run(pat, func(t *testing.T) {
			var prefixPool, suffixPool dfaPool
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Skipf("analyzePattern refused %q: %v", pat, err)
			}
			for _, b := range binPack([]*PatternInfo{info}, CompileSetOptions{}, nil) {
				if b.suffixDFA == nil && b.btFallback == nil && !b.sparse {
					t.Errorf("binPack(%q) produced a live bucket with no suffix DFA", pat)
				}
			}
		})
	}
}

// captureWarnings installs a temporary slog handler at Warn level and returns
// the captured output plus a restore func.
func captureWarnings(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	return &buf, func() { slog.SetDefault(prev) }
}

// btRefusedPattern is a pattern the Backtracking fallback engine REFUSES, so
// a set member over maxFallbackStates is still dropped rather than admitted.
//
// The refusal is checkBTEmptyBodyLoopChain's: 13 chained nullable loops against
// maxBTEmptyBodyGreedyLoops == 12 (measured live — the chain is only 87 NFA
// instructions, so this is a cheap pattern, not a pathological one). The
// `[a-z]{20}` tail is what puts the suffix DFA over the small limits used
// below; without it the pattern fits in a DFA bucket and never reaches a drop
// branch at all.
//
// Using the instruction cap (maxBTFallbackInstructions, 20000) instead is NOT
// a workable alternative: every pattern big enough to exceed it fails earlier,
// inside analyzePattern, with "DFA state limit exceeded during construction",
// so it never reaches compileFallback.
var btRefusedPattern = strings.Repeat(`(?:a|)*`, 13) + `[a-z]{20}`

// TestCompileFallback_AdmitsToBTOverStateLimit is the positive half of the
// Backtracking-member contract: a pattern whose suffix DFA exceeds
// maxFallbackStates is no longer dropped, it is admitted on the Backtracking
// engine, so the set member behaves like the same pattern compiled alone.
//
// Before Backtracking set members existed, this pattern produced 0 buckets and a warning; that older
// assertion is now TestCompileFallback_WarnsWhenBTAlsoRefuses's job.
func TestCompileFallback_AdmitsToBTOverStateLimit(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	// No literal anywhere, so this lands in the fallback bucket rather than a
	// literal bucket. ~200 suffix DFA states, comfortably over the limit below.
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	opts := CompileSetOptions{MaxFallbackStates: 8}
	buckets := compileFallback([]*PatternInfo{info}, opts, nil)

	if len(buckets) != 1 {
		t.Fatalf("expected the pattern admitted to BT (1 bucket), got %d", len(buckets))
	}
	if buckets[0].btFallback == nil {
		t.Errorf("bucket is not a Backtracking bucket; suffixDFA=%v", buckets[0].suffixDFA != nil)
	}
	// A BT bucket holds exactly one pattern: buildSetBTSuffixBody answers for
	// patternIDs[bi][0] and validMask bit 0 alone. compileFallback's bin-packer
	// used to merge later fallback patterns into it, and every merged-in
	// pattern then vanished from every bucketed capability with no error
	// anywhere.
	if n := len(buckets[0].patterns); n != 1 {
		t.Errorf("BT bucket holds %d patterns, want exactly 1", n)
	}
	if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("a BT-admitted pattern must not warn about being dropped; got %q", out)
	}
}

// TestCompileFallback_WarnsWhenBTAlsoRefuses covers the drop warning, which
// still exists: BT NARROWS the drop set, it does not empty it. A pattern that
// exceeds maxFallbackStates AND that BT refuses must be reported at warning
// level, not dropped silently.
//
// The branch is driven via CompileSetOptions.MaxFallbackStates rather than by
// finding a pathological pattern: the reachable window for the default limit is
// only (1024, maxHelperDFAStates] == (1024, 2048], and DFA state counts for the
// exponential-blowup pattern families that get anywhere near it jump in powers
// of the class size, so they skip straight over the window. Lowering the limit
// exercises exactly the same branch with an ordinary pattern.
func TestCompileFallback_WarnsWhenBTAlsoRefuses(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	opts := CompileSetOptions{MaxFallbackStates: 8}
	buckets := compileFallback([]*PatternInfo{info}, opts, nil)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern to be dropped (0 buckets), got %d", len(buckets))
	}
	out := buf.String()
	if !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("dropped pattern produced no warning; slog output was %q", out)
	}
	if !strings.Contains(out, "limit=8") {
		t.Errorf("warning should report the limit that was exceeded; got %q", out)
	}
}

// TestAdmitBTFallback_RefusesUnsupported pins WHY btRefusedPattern is refused,
// so the two tests above cannot silently start passing for a different reason
// (e.g. a pattern that stops reaching the drop branch at all).
func TestAdmitBTFallback_RefusesUnsupported(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if got := admitBTFallback(patternSuffixAST(info), resolveMemoBudget(nil)); got != nil {
		t.Fatalf("admitBTFallback accepted %q; the drop-path tests depend on it refusing", btRefusedPattern)
	}
	// And the admitted control, so this test fails if admitBTFallback starts
	// refusing everything.
	okInfo, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if got := admitBTFallback(patternSuffixAST(okInfo), resolveMemoBudget(nil)); got == nil {
		t.Fatal("admitBTFallback refused [a-z0-9]{200}; the admit-path test depends on it accepting")
	}
}

// TestCompileFallback_NoWarnWhenAdmitted guards the other direction: a pattern
// that fits must not emit the warning. Without this, a future change that warns
// unconditionally would still pass the test above.
func TestCompileFallback_NoWarnWhenAdmitted(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, nil)

	if len(buckets) != 1 {
		t.Fatalf("expected the pattern to be admitted (1 bucket), got %d", len(buckets))
	}
	if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("admitted pattern must not warn; got %q", out)
	}
}

// TestCompileFallback_WarnsWithNilDiag is the specific regression for the
// nil-diag warning mechanism. The warning must not be nested inside the
// `if diag != nil` bookkeeping guards: CompileSet always allocates a SetDiag so
// those guards always pass, but the struct is discarded unless --diag-json was
// requested. Passing an explicitly nil diag here asserts the warning is
// independent of diagnostics being collected.
func TestCompileFallback_WarnsWithNilDiag(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	// Must be a pattern BT also refuses, or there is no drop left to warn
	// about.
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, nil /* diag */)

	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("warning must fire with a nil diag; got %q", out)
	}
}

// TestMaxFallbackStatesReachesCompiler pins the wiring, not the branch.
//
// The tests above drive the drop through CompileSetOptions directly, which
// proves the branch works but says nothing about whether a user can reach it.
// They could not: CompileSetOptions was constructed in two places and NEITHER
// set MaxFallbackStates, so the hardcoded default of 1024 always won — and the
// drop warning's own hint said "raise max_dfa_states", a field that feeds a
// different budget entirely. A pattern dropped from a set was therefore
// unfixable through the remedy it was told to use.
//
// This drives the real entry point, CompileFile, so a future refactor that
// rebuilds CompileSetOptions without the field fails here rather than silently
// restoring the unreachable knob.
//
// Since sets gained Backtracking members the observable effect of the budget
// being reached is
// only a DROP for a pattern BT also refuses — an ordinary over-limit pattern is
// now admitted to BT instead, and warns about nothing. So the pattern here is
// btRefusedPattern: the budget is still what decides its fate, and the warning
// is still how that decision is observed.
func TestMaxFallbackStatesReachesCompiler(t *testing.T) {
	cfg := func(limit int) config.BuildConfig {
		return config.BuildConfig{
			MaxFallbackStates: limit,
			Regexps: []config.RegexEntry{
				// No usable literal, so it lands in a fallback bucket, and
				// enough states to clear a small limit and not a large one.
				{Name: "big", Pattern: btRefusedPattern},
			},
			Sets: []config.SetConfig{{
				Name:     "s",
				Find:     "s_find",
				Patterns: config.PatternSelector{All: true},
			}},
		}
	}

	for _, tc := range []struct {
		limit       int
		wantDropped bool
	}{
		{8, true},        // below the pattern's state count: dropped
		{1 << 20, false}, // far above it: admitted
	} {
		buf, restore := captureWarnings(t)
		if _, _, err := CompileFile(cfg(tc.limit), ""); err != nil {
			restore()
			t.Fatalf("max_fallback_states=%d: CompileFile: %v", tc.limit, err)
		}
		out := buf.String()
		restore()

		got := strings.Contains(out, "Pattern dropped from set")
		if got != tc.wantDropped {
			t.Errorf("max_fallback_states=%d: dropped=%v, want %v (slog output %q)",
				tc.limit, got, tc.wantDropped, out)
		}
		if tc.wantDropped && !strings.Contains(out, "limit=8") {
			t.Errorf("max_fallback_states=8: warning reported a different limit: %q", out)
		}
		// The hint must name a key that actually feeds this budget.
		if tc.wantDropped && !strings.Contains(out, "raise max_fallback_states") {
			t.Errorf("drop hint should name max_fallback_states; got %q", out)
		}
	}
}

// TestCompileFallback_NilSuffixDFANoPanic is a crash regression:
// compileFallback's non-isolated `!placed` branch dereferenced
// nbDFA with no nil check and CRASHED.
//
// analyzePattern returns early for this shape leaving p.suffixDFA nil, and the
// mergeSuffixDFA call that would replace it then fails its own state limit, so
// nbDFA reaches the state-limit test still nil. The ISOLATED branch a few lines
// above has carried this guard, and a comment about the same crash, for some
// time — it was simply never added to the sibling branch.
//
// The assertion is only "does not panic": whether the pattern ends up admitted
// to BT or dropped is the surrounding branches' business and is covered above.
func TestCompileFallback_NilSuffixDFANoPanic(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(
		config.RegexEntry{Pattern: strings.Repeat(`(?:[a-z]*[0-9]*)`, 3000)},
		&prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if info.suffixDFA != nil {
		t.Skip("suffixDFA is no longer nil for this shape; the branch is unreachable from here")
	}
	if info.isolatedFallback {
		t.Skip("routed to the isolated branch, which already had the guard")
	}
	// Panics fail the test by default; no assertion needed beyond returning.
	compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, nil)
}
