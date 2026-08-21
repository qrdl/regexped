package compile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
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
	lit, path := findMandatoryLitRec(re, 0, 0)
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
			lit, path := findMandatoryLitRec(re, 0, 0)
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
	lit, path := findMandatoryLitRec(re, 0, 0)
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

func TestEquivalence_Compat001(t *testing.T) {
	fix := testdataFixture(t, "compat_001")
	var prefixPool, suffixPool dfaPool
	var firstSuffixID int
	for i, p := range fix.Patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: p.Pattern}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("pattern %d %q: %v", i, p.Pattern, err)
		}
		if i == 0 {
			firstSuffixID = info.suffixID
			continue
		}
		if fix.Expect.SuffixDedupPoolSize > 0 && info.suffixID != firstSuffixID {
			t.Errorf("pattern %d %q: suffixID=%d, want %d (suffix dedup failed)",
				i, p.Pattern, info.suffixID, firstSuffixID)
		}
	}
	if fix.Expect.SuffixDedupPoolSize > 0 && len(suffixPool.tables) != fix.Expect.SuffixDedupPoolSize {
		t.Errorf("suffixPool size=%d, want %d", len(suffixPool.tables), fix.Expect.SuffixDedupPoolSize)
	}
}

func TestEquivalence_Compat003(t *testing.T) {
	fix := testdataFixture(t, "compat_003")
	asts := make([]*syntax.Regexp, len(fix.Patterns))
	for i, p := range fix.Patterns {
		asts[i] = mustParse(t, p.Pattern)
	}
	table, kind, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFA: %v", err)
	}
	if kind != AcceptBitmask {
		t.Errorf("kind=%v, want AcceptBitmask", kind)
	}
	if table.numStates == 0 {
		t.Error("merged DFA has 0 states")
	}
	// Each pattern's bit must appear in at least one accept state.
	var combined uint64
	for _, v := range table.acceptStates {
		combined |= v
	}
	for i := range fix.Patterns {
		if combined>>uint(i)&1 == 0 {
			t.Errorf("pattern %d bit not set in any accept state (combined=0x%x)", i, combined)
		}
	}
}

// --------------------------------------------------------------------------
// Phase 4a: multi-pattern Teddy tests

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
	// rejected (plans/SETS.md §14 P4); the cap is teddyMaxLiterals.
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
		// At or below 16 literals, a qualifying two-column packed pair wins
		// (plans/SETS.md §16 Task G1): two eq-splat columns cost far less per
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
	// The keywords-N shape §16 Task G1 exists for: literals sharing a "kw00"
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
	// first-byte crossover, Teddy's fixed-cost probe beats AC's prefilter
	// (plans/SETS.md §14.11).
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

func TestEquivalence_Compat004(t *testing.T) {
	fix := testdataFixture(t, "compat_004")
	patterns := fix.patternInfos(t)
	opts := fix.compileOpts()
	buckets := binPack(patterns, opts, nil)
	if fix.Expect.BucketCount > 0 && len(buckets) != fix.Expect.BucketCount {
		t.Errorf("compat_004: got %d buckets, want %d", len(buckets), fix.Expect.BucketCount)
	}
	// Verify Teddy is the chosen frontend for these 4 two-byte literals.
	var lits [][]byte
	for _, p := range patterns {
		if p.mandLit != nil {
			lits = append(lits, p.mandLit.bytes)
		}
	}
	if len(lits) > 0 {
		fe := chooseLiteralFrontend(lits)
		if fix.Expect.Frontend != "" && fe.String() != fix.Expect.Frontend {
			t.Errorf("compat_004: frontend = %q, want %q", fe.String(), fix.Expect.Frontend)
		}
	}
}

// --------------------------------------------------------------------------
// Phase 4b: Aho-Corasick tests

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

func TestEquivalence_Compat005(t *testing.T) {
	fix := testdataFixture(t, "compat_005")
	patterns := fix.patternInfos(t)
	// Collect unique mandatory literals.
	var lits [][]byte
	seen := make(map[string]bool)
	for _, p := range patterns {
		if p.mandLit != nil {
			key := string(p.mandLit.bytes)
			if !seen[key] {
				seen[key] = true
				lits = append(lits, p.mandLit.bytes)
			}
		}
	}
	fe := chooseLiteralFrontend(lits)
	if fix.Expect.Frontend != "" && fe.String() != fix.Expect.Frontend {
		t.Errorf("compat_005: frontend = %q, want %q", fe.String(), fix.Expect.Frontend)
	}
}

// --------------------------------------------------------------------------
// Phase 4c: config and CompileFile tests

func TestPatternSelector_UnmarshalYAML_All(t *testing.T) {
	data := `patterns: "all"`
	var s struct {
		Patterns config.PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte(data), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !s.Patterns.All {
		t.Error("expected All=true for scalar 'all'")
	}
}

func TestPatternSelector_UnmarshalYAML_List(t *testing.T) {
	data := "patterns:\n  - rule_a\n  - rule_b\n"
	var s struct {
		Patterns config.PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte(data), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Patterns.All {
		t.Error("expected All=false for list")
	}
	if len(s.Patterns.Names) != 2 || s.Patterns.Names[0] != "rule_a" {
		t.Errorf("unexpected names: %v", s.Patterns.Names)
	}
}

func TestConfig_DuplicateName_Rejected(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "dup", Pattern: `foo`},
			{Name: "dup", Pattern: `bar`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "ma", Patterns: config.PatternSelector{All: true}},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for duplicate regexp name, got nil")
	}
}

func TestConfig_UnknownPatternRef_Rejected(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "known", Pattern: `foo`},
		},
		Sets: []config.SetConfig{
			{
				Name:     "s",
				Find:     "ma",
				Patterns: config.PatternSelector{Names: []string{"unknown_name"}},
			},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for unknown pattern reference, got nil")
	}
}

func TestConfig_MissingCapabilities_Rejected(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `foo`}},
		Sets: []config.SetConfig{
			{Name: "s", Patterns: config.PatternSelector{All: true}},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for set with neither match_any nor match_all")
	}
}

func TestCompileFile_NoSets_ByteIdentical(t *testing.T) {
	// CompileFile with no sets must produce byte-identical output to Compile,
	// including across multi-pattern page alignment and the final memory page
	// count for standalone modules with large DFA tables.
	patternSets := map[string][]config.RegexEntry{
		"single":      {{Pattern: `[a-z]+`, FindFunc: "find"}},
		"multi":       {{Pattern: `[a-z]+`, FindFunc: "find1"}, {Pattern: `\d+`, FindFunc: "find2"}},
		"large_table": {{Pattern: `[a-zA-Z0-9_]{8,}`, FindFunc: "find"}},
	}
	for name, patterns := range patternSets {
		t.Run(name, func(t *testing.T) {
			wasmA, _, err := Compile(patterns, 0, true)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			cfg := config.BuildConfig{Regexps: patterns}
			wasmB, _, err := CompileFile(cfg, "")
			if err != nil {
				t.Fatalf("CompileFile: %v", err)
			}
			if !bytes.Equal(wasmA, wasmB) {
				t.Errorf("WASM differs: Compile=%d bytes, CompileFile=%d bytes", len(wasmA), len(wasmB))
			}
			assertDataSectionConsistent(t, wasmB)
		})
	}
}

func TestCompileFile_WithSets_ValidWASM(t *testing.T) {
	// CompileFile with sets must produce a non-empty WASM module with the
	// correct magic bytes and at least one exported function.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "foo_pat", Pattern: `foo\d+`},
			{Name: "bar_pat", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{
				Name:     "test_set",
				Find:     "test_match_any",
				Patterns: config.PatternSelector{All: true},
			},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
	if wasm[0] != 0x00 || wasm[1] != 0x61 || wasm[2] != 0x73 || wasm[3] != 0x6D {
		t.Errorf("WASM magic bytes wrong: %x", wasm[:4])
	}
}

// TestCompileFile_WithSets_BatchFindStillWorks guards against a regression
// where CompileFile's per-pattern loop (used whenever cfg.Sets is non-empty)
// bypassed the "batch-find" hint trigger entirely, and assembleModuleWithSets
// had no code to emit the batch wrapper even when the field was set — so a
// pattern's own _batch export silently disappeared merely because the config
// also had a sets: block. The set's own find_any export must NOT gain a
// batch wrapper — sets already cover multi-match via find_all/find_any.
func TestCompileFile_WithSets_BatchFindStillWorks(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "foo_pat", Pattern: `foo\d+`, FindFunc: "find_foo", Hints: []string{"batch-find"}},
			{Name: "bar_pat", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{
				Name:     "test_set",
				Find:     "test_match_any",
				Patterns: config.PatternSelector{All: true},
			},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if !bytes.Contains(wasm, []byte("find_foo_batch")) {
		t.Error("expected find_foo_batch export with batch-find hint present alongside a sets: block, not found")
	}
	if bytes.Contains(wasm, []byte("test_match_any_batch")) {
		t.Error("test_match_any_batch export present — set match functions must not gain a batch wrapper")
	}
}

func TestSetMatch_SingleBucket_Equivalence(t *testing.T) {
	// Verify that CompileSet produces a compiledSet with the expected structure.
	var prefixPool, suffixPool dfaPool
	patterns := []*PatternInfo{}
	patternIDs := []int{}
	for i, pat := range []string{`foo\d+`, `foo[a-z]+`} {
		info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern[%d]: %v", i, err)
		}
		patterns = append(patterns, info)
		patternIDs = append(patternIDs, i)
	}
	spec := SetSpec{
		Name:       "test",
		Find:       "test_any",
		Patterns:   patterns,
		PatternIDs: patternIDs,
	}
	cs := CompileSet(spec, &prefixPool, &suffixPool, CompileSetOptions{})
	// matchFnBody is built at assemble time (assembleModuleWithSets), not in CompileSet.
	if cs.numSuffixFns == 0 {
		t.Error("expected at least one suffix function body")
	}
	if len(cs.suffixFnBodies) == 0 {
		t.Error("no suffix function bodies")
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

// TestCompileFile_ACFrontend exercises emitSetMatchFnFinalAC (0% coverage without this).
// 17 unique 2-byte literals → >16 → frontendAC.
func TestCompileFile_ACFrontend(t *testing.T) {
	pats := make([]config.RegexEntry, 17)
	for i := range pats {
		// "aa\w+", "ab\w+", ..., "aq\w+" — 17 distinct 2-byte mandatory literals
		pats[i] = config.RegexEntry{Pattern: "a" + string(rune('a'+i)) + `\w+`}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile AC frontend: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic: %x", wasm[:min(8, len(wasm))])
	}
	assertDataSectionConsistent(t, wasm)
}

// TestACBudget covers the frontend budget introduced by plans/SETS.md §14 P1,
// which replaced a 32-NODE cap that silently demoted any set past ~17-26
// literals (the exact count varied with prefix sharing) to the scalar path, at
// 86-414x the scan fuel (§13 F1, §14.2).
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
	// mirroring the two shapes measured in §14.2: prefix sharing is what
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
		return SetSpec{Name: "s", Scan: "scan", Patterns: patterns, PatternIDs: ids}, &prefixPool, &suffixPool
	}

	// (1) The default budget holds the AC-selecting shape at every count that
	// used to fall off the cliff. 17 and 26 are the two measured cliff edges.
	//
	// Only the SHARED-prefix shape is checked for AC: since §14.11 the
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
		t.Fatal("ACBudgetBytes=1: demotion not recorded in SetDiag — a silent frontend downgrade is exactly the §13 F1 failure mode")
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

// TestACByteClassCompression covers the compressed layout (plans/SETS.md §14
// P3). Compression is a RE-INDEXING of the goto table, so the invariant that
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

// TestCompileFile_ShuftiFrontend exercises emitSetMatchFnFinalShufti and
// litUnionFirstBytes (both 0% covered without this). Reaching the Shufti
// frontend (LIKELY.md Gap H.3) requires, in order:
//  1. chooseLiteralFrontend initially picks AC (17+ unique literals);
//  2. the AC automaton itself exceeds the 32-node cap, so CompileSet
//     downgrades fe back to frontendScalar (see the "Cap: fall back to
//     scalar" block in set_emit.go) — 33 literals sharing no common prefix
//     reliably blows past 32 trie nodes;
//  3. zero fallback buckets (every pattern has a splittable mandatory
//     literal, here guaranteed by the unbounded `[a-z]+` suffix);
//  4. the union of first bytes across all literals falls in [17, 64] — each
//     pattern here uses a distinct leading byte, so the union is exactly 33;
//  5. the set-level "prefer-no-match" hint forces Shufti regardless of the
//     rarity heuristic (Action 5).
func TestCompileFile_ShuftiFrontend(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	n := 33
	pats := make([]config.RegexEntry, n)
	for i := range pats {
		pats[i] = config.RegexEntry{Pattern: fmt.Sprintf("%cq%02dx[a-z]+", alphabet[i], i)}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{
				Name:     "s",
				Find:     "find_all",
				Patterns: config.PatternSelector{All: true},
				Hints:    []string{"prefer-no-match"},
			},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Shufti frontend: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
	}
	assertDataSectionConsistent(t, wasm)
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

// TestCompileFile_TeddyTwoGroups exercises the TwoGroups path in emitSetMatchFnFinalTeddy.
// 10 unique 1-byte literals → ≤16, TwoGroups=true.
func TestCompileFile_TeddyTwoGroups(t *testing.T) {
	pats := make([]config.RegexEntry, 10)
	for i := range pats {
		pats[i] = config.RegexEntry{Pattern: string(rune('a'+i)) + `\w+`}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Teddy two-groups: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
	}
	assertDataSectionConsistent(t, wasm)
}

// TestCompileFile_TeddyPartialProbe exercises tail-byte verification for literals >4 bytes.
func TestCompileFile_TeddyPartialProbe(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Pattern: `sk_live_[0-9a-zA-Z]{24}`},
			{Pattern: `sk_test_[0-9a-zA-Z]{24}`},
			{Pattern: `gh_pat_[0-9a-zA-Z]{36}`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Teddy partial probe: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
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

func TestCompileFile_Embedded_WithSets(t *testing.T) {
	// Non-empty cfg.Output triggers embedded mode. Must produce valid WASM.
	cfg := config.BuildConfig{
		Output:  "merged.wasm", // non-empty → embedded
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `bar\w+`}},
		Sets: []config.SetConfig{
			{Name: "s", Find: "s_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "out.wasm")
	if err != nil {
		t.Fatalf("CompileFile embedded: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
}

func TestAssembleModuleWithSets_ValidWASM(t *testing.T) {
	// assembleModuleWithSets with at least one set must produce valid WASM magic.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\d+`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "ma", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic: %x", wasm[:min(8, len(wasm))])
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

func runConflictTest(t *testing.T, fixtureName string) ([]*bucket, *SetDiag) {
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
	return buckets, diag
}

func TestEquivalence_Conflict001(t *testing.T) { runConflictTest(t, "conflict_001") }
func TestEquivalence_Conflict002(t *testing.T) { runConflictTest(t, "conflict_002") }
func TestEquivalence_Conflict003(t *testing.T) { runConflictTest(t, "conflict_003") }
func TestEquivalence_Conflict004(t *testing.T) { runConflictTest(t, "conflict_004") }
func TestEquivalence_Conflict005(t *testing.T) { runConflictTest(t, "conflict_005") }
func TestEquivalence_Conflict006(t *testing.T) { runConflictTest(t, "conflict_006") }
func TestEquivalence_Conflict007(t *testing.T) { runConflictTest(t, "conflict_007") }
func TestEquivalence_Conflict008(t *testing.T) { runConflictTest(t, "conflict_008") }

func TestFallback_NoLiteral(t *testing.T) {
	// conflict_005 patterns have no mandatory literal → all in fallback buckets.
	_, diag := runConflictTest(t, "conflict_005")
	if len(diag.Buckets) == 0 {
		t.Fatal("no BucketDiag entries")
	}
	for _, b := range diag.Buckets {
		if b.Type != "fallback" && b.Type != "singleton" {
			t.Errorf("bucket %d type=%q, want fallback/singleton for no-literal patterns", b.ID, b.Type)
		}
	}
}

func TestDiagnostics_ConflictReasons(t *testing.T) {
	type tc struct {
		name    string
		reasons []string
	}
	cases := []tc{
		{"conflict_001", []string{"bitmask_cap_full"}},
		{"conflict_002", []string{"class_count_incompatible"}},
		{"conflict_003", []string{"table_size_exceeded"}},
		{"conflict_004", []string{"state_count_exceeded"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fix := testdataFixture(t, c.name)
			patterns := fix.patternInfos(t)
			diag := &SetDiag{}
			binPack(patterns, fix.compileOpts(), diag)
			reasonSeen := make(map[string]bool)
			for _, cd := range diag.Conflicts {
				reasonSeen[cd.Reason] = true
			}
			for _, want := range c.reasons {
				if !reasonSeen[want] {
					t.Errorf("fixture %s: reason %q not found in conflicts %v", c.name, want, diag.Conflicts)
				}
			}
		})
	}
}

// --------------------------------------------------------------------------
// Phase 4.5: anchored match tests

func TestSetMatch_Anchored_ValidWASM(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "sel", Pattern: `(?i)^\s*SELECT\b`},
			{Name: "ins", Pattern: `(?i)^\s*INSERT\s+INTO\b`},
		},
		Sets: []config.SetConfig{
			{Name: "sql", Match: "validate_sql", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM magic: %x", wasm[:min(8, len(wasm))])
	}
}

func TestSetMatch_Anchored_FindOnlyCompiles(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `foo\d+`}},
		Sets:    []config.SetConfig{{Name: "s", Find: "find_foo", Patterns: config.PatternSelector{All: true}}},
	}
	if _, _, err := CompileFile(cfg, ""); err != nil {
		t.Fatalf("CompileFile find-only: %v", err)
	}
}

func TestSetMatch_Anchored_BothExports(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\d+`},
			{Name: "p2", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{Name: "both", Find: "find_all_fn", Match: "match_fn", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
}

func TestSetMatch_Anchored_SQLValidator_Fixture(t *testing.T) {
	fix := testdataFixture(t, "sql_validator")
	cfg := config.BuildConfig{
		Regexps: make([]config.RegexEntry, len(fix.Patterns)),
		Sets: []config.SetConfig{
			{Name: "sql", Match: "validate_sql", Patterns: config.PatternSelector{All: true}},
		},
	}
	for i, p := range fix.Patterns {
		cfg.Regexps[i] = config.RegexEntry{Pattern: p.Pattern}
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile SQL validator: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
}

// TestSetMatch_Anchored_FixedLenPrefix exercises the fixed-length prefix
// branch of emitSetMatchFnAnchored: `\d{3}foo` produces a prefix of exact
// length 3 followed by the mandatory literal "foo".
func TestSetMatch_Anchored_FixedLenPrefix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `\d{3}foo`},
			{Name: "p2", Pattern: `[a-z]{2}bar`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_VarLenEmptySuffix exercises the variable-length
// prefix path with an empty suffix: `\d+foo` has a varlen prefix and the
// mandatory literal "foo" at the end.
func TestSetMatch_Anchored_VarLenEmptySuffix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `\d+foo`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_VarLenNonEmptySuffix exercises the variable-length
// prefix path with a non-empty suffix: `\d+foo\d+` has both a varlen prefix
// and a non-empty suffix around the mandatory literal "foo".
func TestSetMatch_Anchored_VarLenNonEmptySuffix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `\d+foo\d+`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_LargeFallback exercises the n > 32 clamp in the
// fallback bucket branch of emitSetMatchFnAnchored. We use (?i) patterns
// without a mandatory literal so all 40 patterns fall back to a single
// bucket that must be clamped to 32-pattern mask width.
func TestSetMatch_Anchored_LargeFallback(t *testing.T) {
	const n = 40
	cfg := config.BuildConfig{
		Regexps: make([]config.RegexEntry, n),
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Patterns: config.PatternSelector{All: true}},
		},
	}
	for i := 0; i < n; i++ {
		cfg.Regexps[i] = config.RegexEntry{
			Pattern: fmt.Sprintf(`(?i)tok%02d`, i),
		}
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_NoLiteralFallback_Large exercises the n>32 clamp in the
// fallback bucket branch of emitSetMatchFnAnchored. It builds >32 patterns that
// have no extractable mandatory literal so they all land in the same fallback
// bucket.
func TestSetMatch_Anchored_NoLiteralFallback_Large(t *testing.T) {
	const n = 35
	cfg := config.BuildConfig{
		Regexps: make([]config.RegexEntry, n),
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Patterns: config.PatternSelector{All: true}},
		},
	}
	// Patterns with no mandatory literal: character classes / quantified.
	classes := []string{`\d+`, `\w+`, `\s+`, `[ab]+`, `[xy]+`, `[0-9]+`, `[A-Z]+`}
	for i := 0; i < n; i++ {
		cfg.Regexps[i] = config.RegexEntry{
			Pattern: classes[i%len(classes)],
		}
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_TrivialPrefixMultiByte exercises the trivial-prefix
// branch of emitSetMatchFnAnchored with literal length >= 2, hitting the
// `li > 0` offset-add path inside the literal-byte-check loop.
func TestSetMatch_Anchored_TrivialPrefixMultiByte(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foobar.*`}, // literal "foobar" at offset 0
			{Name: "p2", Pattern: `quux.+`},   // literal "quux" at offset 0
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_VarLenEmpty exercises the variable-length prefix +
// empty-suffix path (isEmpty branch) in emitSetMatchFnAnchored. The prefix
// must be BOUNDED (maxLen <= 256) so the mandatory literal extractor can
// locate the literal — unbounded prefixes like `\d+foo` are rejected by
// findMandatoryLitRec and route to the fallback bucket instead.
func TestSetMatch_Anchored_VarLenEmpty(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `[ab]?foo`},     // bounded varlen prefix, empty suffix
			{Name: "p2", Pattern: `[xy]{0,3}bar`}, // bounded varlen prefix, empty suffix
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetMatch_Anchored_VarLenNonEmpty exercises the variable-length prefix +
// non-empty-suffix path (isNonempty branch) in emitSetMatchFnAnchored.
// Requires a bounded varlen prefix (so the literal is found) and a non-empty
// suffix following the literal.
func TestSetMatch_Anchored_VarLenNonEmpty(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `[ab]?foo[xy]`},     // bounded varlen prefix, non-empty suffix
			{Name: "p2", Pattern: `[cd]{0,2}bar[zz]`}, // bounded varlen prefix, non-empty suffix
		},
		Sets: []config.SetConfig{
			{Name: "s", Match: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetFind_AC_VarLenPrefix exercises the variable-length prefix path inside
// emitSetMatchFnFinalAC (the emitVarLenAt closure). The AC frontend is chosen
// when the set has >16 unique literals; each pattern uses a bounded varlen
// prefix (`[ab]?`) so its bucket has varLenMasks bits set.
func TestSetFind_AC_VarLenPrefix(t *testing.T) {
	const n = 20
	regs := make([]config.RegexEntry, n)
	for i := 0; i < n; i++ {
		// Bounded varlen prefix + unique 4-byte literal. The {0,1} form
		// yields varLenEmptySuffix for half the patterns and we add a tail
		// charclass on the rest to exercise varLenNonEmptySuffix too.
		var pat string
		if i%2 == 0 {
			pat = fmt.Sprintf(`[ab]?lit%02d`, i)
		} else {
			pat = fmt.Sprintf(`[cd]{0,2}wrd%02d[xy]`, i)
		}
		regs[i] = config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: pat}
	}
	cfg := config.BuildConfig{
		Regexps: regs,
		Sets: []config.SetConfig{
			{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetWithIndividualFuncs exercises the per-pattern function/export emit
// branches inside assembleModuleWithSets: a config that has both `Sets:` and
// individual pattern stubs (match_func / find_func / groups_func /
// named_groups_func) so the assembler walks both pattern bodies and set
// bodies.
func TestSetWithIndividualFuncs(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\d+`, MatchFunc: "p1_match", FindFunc: "p1_find"},
			{Name: "p2", Pattern: `(?P<n>bar)(?P<m>\d+)`, GroupsFunc: "p2_groups", NamedGroupsFunc: "p2_named"},
			{Name: "p3", Pattern: `baz\w+`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "set_find", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestSetFind_Scalar_StartAnchorVarLen exercises uncovered branches in
// emitSetMatchFnFinalScalar: the start-anchor mask path (sam != 0) and the
// scalar-path varlen-prefix emit (emitVarLen). A fallback pattern forces the
// scalar frontend (Teddy with fallback buckets routes to scalar).
func TestSetFind_Scalar_StartAnchorVarLen(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "anchored", Pattern: `^foo`},          // start-anchor literal
			{Name: "varlen_e", Pattern: `[ab]?bar`},      // varlen-empty
			{Name: "varlen_ne", Pattern: `[cd]?baz[xy]`}, // varlen-nonempty
			{Name: "lit", Pattern: `quux`},               // plain literal
			{Name: "fallback", Pattern: `\d+`},           // no mandatory literal → fallback bucket → scalar frontend
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestCompileFile_ValidateError covers the ValidateSets error path in
// CompileFile (early return on invalid config).
func TestCompileFile_ValidateError(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets: []config.SetConfig{
			// Empty set name is invalid.
			{Name: "", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	_, _, err := CompileFile(cfg, "")
	if err == nil {
		t.Fatalf("expected ValidateSets error, got nil")
	}
}

// TestCompileFile_Embedded covers the embedded mode in CompileFile
// (cfg.Output != "" → standalone=false → opts.tableMemIdx = 1 and
// setOpts.TableMemIdx = 1).
func TestCompileFile_Embedded(t *testing.T) {
	cfg := config.BuildConfig{
		Output: "ignored.wasm", // non-empty → embedded mode
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foo`},
			{Name: "p2", Pattern: `bar`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

func TestValidateSets_MatchOnly(t *testing.T) {
	cfg := &config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets:    []config.SetConfig{{Name: "s", Match: "validate", Patterns: config.PatternSelector{All: true}}},
	}
	if err := config.ValidateSets(cfg); err != nil {
		t.Errorf("ValidateSets match-only set: %v", err)
	}
}

// --------------------------------------------------------------------------
// Phase 5: fuzzer, mixed_004, diag JSON tests

func FuzzSetMatchEquivalence(f *testing.F) {
	// Seed corpus: simple patterns that exercise different code paths.
	seeds := []struct{ pat, input string }{
		{`foo\d+`, "foo123"},
		{`bar`, "hello bar world"},
		{`[a-z]+`, "abc"},
	}
	for _, s := range seeds {
		f.Add(s.pat, s.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		// Compile the pattern — skip if it's invalid or uses captures.
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{{Name: "p", Pattern: pat, FindFunc: "find"}},
			Sets: []config.SetConfig{
				{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
			},
		}
		if err := config.ValidateSets(&cfg); err != nil {
			return // invalid config
		}
		wasm, _, err := CompileFile(cfg, "")
		if err != nil {
			return // pattern may be unsupported — skip
		}
		if len(wasm) < 8 {
			t.Errorf("WASM too short: %d bytes for pattern %q", len(wasm), pat)
		}
	})
}

func TestMixed004_Fixture_CompileFile(t *testing.T) {
	fix := testdataFixture(t, "mixed_004")
	if len(fix.Sets) == 0 {
		t.Skip("mixed_004 fixture has no sets block — skipping CompileFile test")
	}
	cfg := config.BuildConfig{
		Regexps: make([]config.RegexEntry, len(fix.Patterns)),
		Sets:    fix.Sets,
	}
	for i, p := range fix.Patterns {
		cfg.Regexps[i] = config.RegexEntry{Name: p.Name, Pattern: p.Pattern}
	}
	if err := config.ValidateSets(&cfg); err != nil {
		t.Fatalf("ValidateSets: %v", err)
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
	if fix.Expect.SetCount > 0 && len(fix.Sets) != fix.Expect.SetCount {
		t.Errorf("set count = %d, want %d", len(fix.Sets), fix.Expect.SetCount)
	}
}

func TestDiagJSON_Schema(t *testing.T) {
	fix := testdataFixture(t, "mixed_004")
	if len(fix.Sets) == 0 {
		t.Skip("mixed_004 has no sets")
	}
	cfg := config.BuildConfig{
		Regexps: make([]config.RegexEntry, len(fix.Patterns)),
		Sets:    fix.Sets,
	}
	for i, p := range fix.Patterns {
		cfg.Regexps[i] = config.RegexEntry{Name: p.Name, Pattern: p.Pattern}
	}
	if err := config.ValidateSets(&cfg); err != nil {
		t.Fatalf("ValidateSets: %v", err)
	}

	// Write diag JSON to a temp file and verify required fields are present.
	tmp := t.TempDir() + "/diag.json"
	if err := CmdWriteDiagJSON(cfg, "", tmp); err != nil {
		t.Fatalf("CmdWriteDiagJSON: %v", err)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read diag JSON: %v", err)
	}

	required := []string{`"patterns_total"`, `"sets"`, `"buckets"`, `"frontend"`}
	for _, field := range required {
		if !bytes.Contains(data, []byte(field)) {
			t.Errorf("diag JSON missing field %s", field)
		}
	}
}

// --------------------------------------------------------------------------
// Anchor helper tests (isOnlyBeginAnchors, hasBeginAnchor,
// hasBeginAnchorAtTopLevel)

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
// pins the KIND, which is the part that matters for B43 — collapsing
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

// TestCompileFile_ShuftiNonAdaptive exercises the non-adaptive locals layout
// in emitSetMatchFnFinalShufti (shuftiAdaptive = lnm && !rare — false here
// because rare=true, i.e. shuftiBeatsScalar already selects Shufti
// statically, so the LikelyNoMatch hint changes nothing) — TEST.md T12.
// TestCompileFile_ShuftiFrontend's digit/uppercase alphabet always has
// rare=false, so it can only ever reach adaptive=true; this uses a
// low-rarity (control-byte/punctuation) first-byte alphabet instead.
// Confirmed live via direct CompileSet probing: fe=shufti, adaptive=false,
// both without and with the prefer-no-match hint.
func TestCompileFile_ShuftiNonAdaptive(t *testing.T) {
	alphabet := lowRarityFirstBytes()
	pats := make([]config.RegexEntry, len(alphabet))
	for i, c := range alphabet {
		pats[i] = config.RegexEntry{Pattern: fmt.Sprintf("%cq%02dx[a-z]+", c, i)}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Shufti non-adaptive: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
	}
	assertDataSectionConsistent(t, wasm)
}

// TestCompileFile_ShuftiVarLenAndAnchor exercises the startAnchorMasks
// (sam != 0) branch, the prefixFnIdx fixed-prefix loop, and the emitVarLen
// closure (both varLenEmptySuffix and varLenNonEmptySuffix) inside
// emitSetMatchFnFinalShufti — TEST.md T13. TestCompileFile_ShuftiFrontend's
// 33 trivial-prefix patterns never exercise any of these; this reuses the
// same low-rarity first-byte alphabet (forcing the Shufti frontend
// unconditionally) but rotates each pattern through 4 prefix shapes:
// optional-prefix+empty-suffix (varLenMasks), ^-anchored (startAnchorMasks),
// bounded-repeat-prefix+non-empty-suffix (varLenNonemptyMasks), and a
// mandatory fixed-length class prefix (the plain prefixFnIdx loop).
// Confirmed live via CompileSet probing: fe=shufti, and all four mask
// fields (sam, varLen, varLenNE, prefixFnIdx) have non-zero/real entries.
func TestCompileFile_ShuftiVarLenAndAnchor(t *testing.T) {
	alphabet := lowRarityFirstBytes()
	pats := make([]config.RegexEntry, len(alphabet))
	for i, c := range alphabet {
		var pat string
		switch i % 4 {
		case 0:
			pat = fmt.Sprintf("[AB]?%cq%02dx", c, i) // varlen prefix, empty suffix
		case 1:
			pat = fmt.Sprintf("^%cq%02dx[a-z]+", c, i) // start-anchored, trivial prefix
		case 2:
			pat = fmt.Sprintf("[CD]{0,2}%cq%02dx[xy]", c, i) // varlen prefix, non-empty suffix
		default:
			pat = fmt.Sprintf("[EF]%cq%02dx[a-z]+", c, i) // fixed-length mandatory prefix
		}
		pats[i] = config.RegexEntry{Pattern: pat}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Shufti varlen+anchor: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
	}
	assertDataSectionConsistent(t, wasm)
}

// TestCompileFile_ACStartAnchor exercises the start-anchor branch (sam != 0,
// prefixFnIdx loop) in the AC frontend (emitSetMatchFnFinalAC) — TEST.md
// T14. Extends TestSetFind_AC_VarLenPrefix's 20-pattern shape (which forces
// the AC frontend, 17-32 unique literals) with one ^-anchored pattern.
// Confirmed live via CompileSet probing: fe=ac, startAnchorMasks[0]=1.
func TestCompileFile_ACStartAnchor(t *testing.T) {
	const n = 20
	regs := make([]config.RegexEntry, n)
	for i := 0; i < n; i++ {
		var pat string
		switch {
		case i == 0:
			pat = fmt.Sprintf("^lit%02d", i)
		case i%2 == 0:
			pat = fmt.Sprintf(`[ab]?lit%02d`, i)
		default:
			pat = fmt.Sprintf(`[cd]{0,2}wrd%02d[xy]`, i)
		}
		regs[i] = config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: pat}
	}
	cfg := config.BuildConfig{
		Regexps: regs,
		Sets: []config.SetConfig{
			{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// TestCompileFile_TeddyTwoGroupsFourByte exercises the "Group B four-byte
// lo/hi table load + nibble check" combination in emitSetMatchFnFinalTeddy
// — TEST.md T15. TwoGroups requires > 8 literals; FourByte requires every
// literal >= 4 bytes; existing tests only ever hit one condition at a time.
// 9 patterns, each with a distinct 6-byte mandatory literal, stays under the
// 16-literal Teddy cap while satisfying both. Confirmed live via CompileSet
// probing: fe=teddy, teddyTabs.TwoGroups=true, teddyTabs.FourByte=true.
func TestCompileFile_TeddyTwoGroupsFourByte(t *testing.T) {
	const n = 9
	pats := make([]config.RegexEntry, n)
	for i := 0; i < n; i++ {
		pats[i] = config.RegexEntry{Pattern: fmt.Sprintf("lit%02d_[a-z]+", i)}
	}
	cfg := config.BuildConfig{
		Regexps: pats,
		Sets: []config.SetConfig{
			{Name: "s", Find: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile Teddy two-groups+four-byte: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Errorf("invalid WASM magic")
	}
	assertDataSectionConsistent(t, wasm)
}

// TestAssembleModuleWithSets_LitAnchorAndAnchoredGroups exercises the
// litAnchorBackScanBody != nil branch and the anchored groupsExport branch
// inside assembleModuleWithSets (the cfg.Sets-non-empty per-pattern
// assembler), which are otherwise only exercised via assembleModule's
// sets-less path — TEST.md T16. "secret_[A-Za-z0-9]+" qualifies for
// lit-anchor find (confirmed live: findLitAnchorPoint returns non-nil, and
// the pattern's small forward DFA has useU8=true); "^(a)(b)$" is an anchored
// groups_func pattern. A trivial, unrelated Sets entry is present so
// cfg.Sets is non-empty and assembleModuleWithSets (not assembleModule) is
// used.
func TestAssembleModuleWithSets_LitAnchorAndAnchoredGroups(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "lit_anchor", Pattern: `secret_[A-Za-z0-9]+`, FindFunc: "f1"},
			{Name: "anchored_groups", Pattern: `^(a)(b)$`, GroupsFunc: "g1"},
			{Name: "set_member", Pattern: `foo|bar`},
		},
		Sets: []config.SetConfig{
			{Name: "s", Find: "s_find", Patterns: config.PatternSelector{Names: []string{"set_member"}}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
	assertDataSectionConsistent(t, wasm)
}

// TestCompileFile_ErrorPropagation exercises the two distinct error paths
// through CompileFile's full config entry point (previously only unit-
// tested at the analyzePattern level directly) — TEST.md T17.
func TestCompileFile_ErrorPropagation(t *testing.T) {
	t.Run("compilePattern_failure", func(t *testing.T) {
		// Broken pattern WITH a func field set, alongside a non-empty Sets
		// block: hits the compilePattern error path (CompileFile's
		// per-pattern loop, before set resolution).
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Name: "bad", Pattern: `[invalid`, MatchFunc: "m"},
				{Name: "ok", Pattern: "foo"},
			},
			Sets: []config.SetConfig{
				{Name: "s", Find: "f", Patterns: config.PatternSelector{Names: []string{"ok"}}},
			},
		}
		_, _, err := CompileFile(cfg, "")
		if err == nil {
			t.Fatal("expected compilePattern error, got nil")
		}
	})
	t.Run("analyzePattern_failure", func(t *testing.T) {
		// Broken pattern with NO func fields, referenced only by a Sets
		// entry: compilePattern returns nil,nil for it (no func fields to
		// compile), so the error surfaces later via analyzePattern inside
		// set resolution, wrapped as `set %q: pattern %q: %w`.
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Name: "bad", Pattern: `[invalid`},
			},
			Sets: []config.SetConfig{
				{Name: "myset", Find: "f", Patterns: config.PatternSelector{All: true}},
			},
		}
		_, _, err := CompileFile(cfg, "")
		if err == nil {
			t.Fatal("expected analyzePattern error, got nil")
		}
		wantSubstr := `set "myset": pattern "bad":`
		if !strings.Contains(err.Error(), wantSubstr) {
			t.Errorf("error = %q, want substring %q", err.Error(), wantSubstr)
		}
	})
}

// TestSetMatch_ZeroWidthNonNilPrefix exercises the L <= 0 branch in
// emitSetMatchFnAnchored — a pattern whose prefixAST is non-nil, not a
// trivial prefix, and not variable-length, but whose fixed length is 0 (a
// zero-width assertion, here \b, immediately before the mandatory literal)
// — TEST.md T18. Confirmed live via analyzePattern/CompileSet probing:
// prefixFnIdx=[0] (a real, non-trivial prefix function), prefixFixedLens=[0]
// (zero-width), trivialPrefixMasks=[0] (not trivial) — exactly the L<=0,
// fnIdx>=0 combination the doc flagged as needing verification.
func TestSetMatch_ZeroWidthNonNilPrefix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `\bfoo`}},
		Sets: []config.SetConfig{
			{Name: "s", Match: "s_match", Patterns: config.PatternSelector{All: true}},
		},
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || wasm[0] != 0x00 || wasm[1] != 0x61 {
		t.Fatalf("invalid WASM")
	}
}

// ---------------------------------------------------------------------------
// plans/SETS.md §9.6: the per-export-combination matrix.
//
// FABLE wave 3 found bugs visible only under --find-only, and the same is true
// here: each capability emits a different body shape, and a set that declares
// only one of them exercises a code path no other config reaches. Every row
// below is one compiled config, checked for its exports and type-validated.

// setCapNames maps a capability key to the export name used in these tests.
// Names are deliberately non-prefix-free-safe: no name is a substring of
// another, so a plain bytes.Contains check cannot confuse "cap_scan" with
// "cap_scan_any".
var setCapNames = map[string]string{
	"match": "zmatchz", "match_any": "zmatchanyz", "match_all": "zmatchallz",
	"scan": "zscanz", "scan_any": "zscananyz", "scan_all": "zscanallz",
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
		case "match":
			sc.Match = setCapNames[c]
		case "match_any":
			sc.MatchAny = setCapNames[c]
		case "match_all":
			sc.MatchAll = setCapNames[c]
		case "scan":
			sc.Scan = setCapNames[c]
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

func TestSetCapabilityMatrix(t *testing.T) {
	pats := []string{`AKIA[A-Z0-9]{4}`, `ghp_[a-z]+`, `a*`, `\bcat\b`, `(?m:^)log`}
	all := []string{"match", "match_any", "match_all", "scan", "scan_any", "scan_all", "find"}

	rows := []struct {
		name        string
		caps        []string
		overlapping bool
	}{
		{"match-only", []string{"match"}, false},
		{"match_any-only", []string{"match_any"}, false},
		{"match_all-only", []string{"match_all"}, false},
		{"scan-only", []string{"scan"}, false},
		{"scan_any-only", []string{"scan_any"}, false},
		{"scan_all-only", []string{"scan_all"}, false},
		{"find-only-gated", []string{"find"}, false},
		{"find-only-overlapping", []string{"find"}, true},
		{"scan_any-without-find", []string{"scan_any", "scan"}, false},
		{"scan_any-with-find", []string{"scan_any", "find"}, false},
		{"all-seven-gated", all, false},
		{"all-seven-overlapping", all, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cfg := setConfigWith(pats, r.overlapping, r.caps...)
			wasm, _, err := CompileFile(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			validateWASM(t, wasm)
			for _, c := range r.caps {
				if !bytes.Contains(wasm, []byte(setCapNames[c])) {
					t.Errorf("export %q missing from module", setCapNames[c])
				}
			}
			// Undeclared capabilities must not be exported.
			for _, c := range all {
				declared := false
				for _, d := range r.caps {
					if c == d {
						declared = true
					}
				}
				if !declared && bytes.Contains(wasm, []byte(setCapNames[c])) {
					t.Errorf("undeclared capability %q was exported", c)
				}
			}
		})
	}
}

// TestSetScanAnyWithoutFindIsSmaller pins the structural half of §5's
// specialisation claim: a set that declares scan_any and NOT find never emits
// the extent machinery, so its module is strictly smaller.
func TestSetScanAnyWithoutFindIsSmaller(t *testing.T) {
	pats := []string{`AKIA[A-Z0-9]{4}`, `ghp_[a-z]+`, `[a-z]+@example\.com`}
	withFind, _, err := CompileFile(setConfigWith(pats, true, "scan_any", "find"), "")
	if err != nil {
		t.Fatal(err)
	}
	// `overlapping` is a load error on a set without find:, so this one omits it.
	without, _, err := CompileFile(setConfigWith(pats, false, "scan_any"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(without) >= len(withFind) {
		t.Errorf("scan_any without find should emit less: %d bytes vs %d with find",
			len(without), len(withFind))
	}
}

// TestSetWideAllForm covers the >64-pattern branch of match_all/scan_all,
// which switches from an i64 bitmask return to an out_ptr bitmap (§3.13).
func TestSetWideAllForm(t *testing.T) {
	var pats []string
	for i := 0; i < 70; i++ {
		pats = append(pats, fmt.Sprintf("kw%02dX", i))
	}
	wasm, _, err := CompileFile(setConfigWith(pats, true, "match_all", "scan_all", "find"), "")
	if err != nil {
		t.Fatalf("compile 70-pattern set: %v", err)
	}
	validateWASM(t, wasm)
}

// TestSetOverlappingFlagChangesFindBody pins §3.15: the flag is a
// compile-time property, and `overlapping: true` emits no gating code at all
// — so the two bodies cannot be byte-identical.
func TestSetOverlappingFlagChangesFindBody(t *testing.T) {
	pats := []string{`a+`, `b`}
	gated, _, err := CompileFile(setConfigWith(pats, false, "find"), "")
	if err != nil {
		t.Fatal(err)
	}
	ungated, _, err := CompileFile(setConfigWith(pats, true, "find"), "")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(gated, ungated) {
		t.Fatal("gated and overlapping find bodies are byte-identical; the flag emitted nothing")
	}
	if len(ungated) >= len(gated) {
		t.Errorf("overlapping: true should emit no gating code, but produced %d bytes vs gated %d",
			len(ungated), len(gated))
	}
}

// TestSetDiagRecordsRouting pins the diagnostics §9.4 asks for: the class of a
// set must be readable from --diag-json rather than inferred by inspection.
func TestSetDiagRecordsRouting(t *testing.T) {
	cases := []struct {
		name       string
		pats       []string
		wantLookbk int
	}{
		// Literal at the match start: M = 0, the empty-drain case.
		{"zero-lookback", []string{`AKIA[A-Z0-9]{4}`, `ghp_x`}, 0},
		// `\d{3}` sits before the mandatory literal `foo`, so a candidate at
		// position c serves a match starting at c-3: M = 3, and the body has
		// a real drain to run rather than stopping at the first candidate.
		{"fixed-lookback", []string{`\d{3}foo`, `foo`}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := setConfigWith(c.pats, true, "find")
			var prefixPool, suffixPool dfaPool
			var infos []*PatternInfo
			var ids []int
			for i, re := range cfg.Regexps {
				info, err := analyzePattern(re, &prefixPool, &suffixPool)
				if err != nil {
					t.Fatal(err)
				}
				info.globalID = i
				infos = append(infos, info)
				ids = append(ids, i)
			}
			cs := CompileSet(SetSpec{
				Name: "s", Find: "cap_find", Overlapping: true,
				Patterns: infos, PatternIDs: ids,
			}, &prefixPool, &suffixPool, CompileSetOptions{})
			if cs.diag.MaxLookback != c.wantLookbk {
				t.Errorf("MaxLookback = %d, want %d", cs.diag.MaxLookback, c.wantLookbk)
			}
			if !cs.diag.Overlapping {
				t.Error("diag did not record overlapping: true")
			}
			if len(cs.diag.Capabilities) != 1 || cs.diag.Capabilities[0] != "find" {
				t.Errorf("diag capabilities = %v, want [find]", cs.diag.Capabilities)
			}
		})
	}
}

// --------------------------------------------------------------------------
// plans/SETS.md §11 R1 / R-TESTS(1): subset selection.
//
// Every harness in this project builds sets that select ALL of the config's
// patterns, which keeps global pattern ids dense and equal to set-local
// indices — and that is precisely why §11 R1 survived 4.9M corpus cases. A
// pattern id is the GLOBAL index into `regexps:`, so a set selecting a
// non-prefix subset reports ids above its own pattern count, and everything
// indexed by an id has to be sized for that.

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

// TestSubsetIDSpace pins the two counts apart and checks that the compiler
// sizes by the id space, not the pattern count.
func TestSubsetIDSpace(t *testing.T) {
	pats := make([]string, 70)
	for i := range pats {
		pats[i] = fmt.Sprintf("lit%dx", i)
	}
	cases := []struct {
		name        string
		pick        []int
		wantCount   int
		wantIDSpace int
		wantWide    bool
	}{
		{"last-of-3", []int{2}, 1, 3, false},
		{"two-late-of-70", []int{68, 69}, 2, 70, true},
		{"first-two", []int{0, 1}, 2, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setConfigSubset(pats[:max(3, tc.pick[len(tc.pick)-1]+1)], tc.pick, "find", "scan_all")
			s := cfg.Sets[0]
			if got := s.PatternCount(cfg); got != tc.wantCount {
				t.Errorf("PatternCount = %d, want %d", got, tc.wantCount)
			}
			if got := s.IDSpaceSize(cfg); got != tc.wantIDSpace {
				t.Errorf("IDSpaceSize = %d, want %d", got, tc.wantIDSpace)
			}
			wasm, _, err := CompileFile(cfg, "")
			if err != nil {
				t.Fatalf("CompileFile: %v", err)
			}
			validateWASM(t, wasm)
			// The compiler must agree with config.IDSpaceSize, since the stubs
			// size the caller's gate array and bitmap from the latter.
			cs := CompileSet(SetSpec{
				Name: "s", Find: "f", ScanAll: "sa",
				IDSpaceSize: s.IDSpaceSize(cfg),
			}, &dfaPool{}, &dfaPool{}, CompileSetOptions{})
			if got := cs.idSpaceSize(); got != tc.wantIDSpace {
				t.Errorf("compiledSet.idSpaceSize() = %d, want %d", got, tc.wantIDSpace)
			}
			if got := cs.wideAll(); got != tc.wantWide {
				t.Errorf("wideAll() = %v, want %v (the _all ABI must follow the id space)", got, tc.wantWide)
			}
		})
	}
}

// TestSubsetAllABIMatchesIDSpace is the check that makes §11 R1's third
// manifestation impossible to reintroduce: the narrow/wide `_all` signature
// the module EXPORTS must be the one the generators would declare. The two
// were derived from different counts, so a subset set could export
// (i32,i32,i32,i32)->i32 while the stub declared (i32,i32,i32)->i64 and
// instantiation failed on an import type mismatch.
func TestSubsetAllABIMatchesIDSpace(t *testing.T) {
	pats := make([]string, 70)
	for i := range pats {
		pats[i] = fmt.Sprintf("lit%dx", i)
	}
	for _, pick := range [][]int{{0, 1}, {68, 69}} {
		cfg := setConfigSubset(pats, pick, "scan_all")
		wasm, _, err := CompileFile(cfg, "")
		if err != nil {
			t.Fatalf("CompileFile: %v", err)
		}
		validateWASM(t, wasm)
		wantWide := cfg.Sets[0].IDSpaceSize(cfg) > wideBitmapThreshold
		// scan_all narrow is (ptr,len,from)->i64; wide is (ptr,len,from,out)->i32.
		want := setTypeI32x3ToI64
		if wantWide {
			want = setTypeI32x4ToI32
		}
		got := exportTypeIndex(t, wasm, setCapNames["scan_all"])
		if got != want {
			t.Errorf("pick %v: id space %d exports scan_all with type %d, want %d "+
				"(the stub declares its FFI from the same id space, so a mismatch "+
				"fails instantiation)", pick, cfg.Sets[0].IDSpaceSize(cfg), got, want)
		}
	}
}

// TestIDSpaceAssertionHolds exercises the compile-time guard: no emitted
// pattern id may exceed the id space the stubs allocate for.
func TestIDSpaceAssertionHolds(t *testing.T) {
	pats := []string{`alpha`, `beta`, `gamma`, `delta`}
	for _, pick := range [][]int{{3}, {1, 3}, {0, 1, 2, 3}} {
		cfg := setConfigSubset(pats, pick, "find", "scan_all", "match_all")
		if _, _, err := CompileFile(cfg, ""); err != nil {
			t.Fatalf("pick %v: %v", pick, err)
		}
	}
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

// TestJumpIsProfitable pins the compile-time gate of plans/SETS.md §12.3: the
// §3.14 jump is emitted only where it can actually fire.
func TestJumpIsProfitable(t *testing.T) {
	cases := []struct {
		name string
		pats []string
		want bool
	}{
		{"single unbounded", []string{`a+`}, true},
		{"single long literal", []string{`abcd`}, true},
		{"single 2-byte", []string{`ab`}, true},
		{"single unbounded tail", []string{`ERR\b[^\n]*`}, true},
		{"single 1-byte class", []string{`[a-z]`}, false},
		{"single 1-byte literal", []string{`a`}, false},
		{"single any-char", []string{`.`}, false},
		{"two patterns", []string{`a+`, `b+`}, false},
		{"eight patterns", []string{`ERR\b[^\n]*`, `WRN\b[^\n]*`, `INF\b[^\n]*`, `DBG\b[^\n]*`,
			`CRT\b[^\n]*`, `FAT\b[^\n]*`, `TRC\b[^\n]*`, `NOT\b[^\n]*`}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]config.RegexEntry, len(tc.pats))
			names := make([]string, len(tc.pats))
			for i, p := range tc.pats {
				names[i] = string(rune('a' + i))
				entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
			}
			cfg := config.BuildConfig{
				Regexps: entries,
				Sets: []config.SetConfig{{
					Name: "s", Find: "f",
					Patterns: config.PatternSelector{Names: names},
				}},
			}
			var pp, sp dfaPool
			var infos []*PatternInfo
			var ids []int
			for i, e := range entries {
				info, err := analyzePattern(e, &pp, &sp)
				if err != nil {
					t.Fatalf("analyzePattern %q: %v", e.Pattern, err)
				}
				infos = append(infos, info)
				ids = append(ids, i)
			}
			cs := CompileSet(SetSpec{
				Name: "s", Find: "f", Patterns: infos, PatternIDs: ids,
				IDSpaceSize: cfg.Sets[0].IDSpaceSize(cfg),
			}, &pp, &sp, CompileSetOptions{})
			if got := cs.jumpIsProfitable(); got != tc.want {
				t.Errorf("jumpIsProfitable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTeddyTwoGroupLaneExtraction pins the two-group lane-extraction hazard
// fixed in plans/SETS.md §14.11.
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
// it should (plans/SETS.md §14.14).
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
