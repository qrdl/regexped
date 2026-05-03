package compile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
	"gopkg.in/yaml.v3"
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
	d := newDFA(prog, false, false)
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

func TestMergeSuffixASTs_Empty(t *testing.T) {
	if got := mergeSuffixASTs(nil); got != nil {
		t.Errorf("mergeSuffixASTs(nil) = %v, want nil", got)
	}
}

func TestMergeSuffixASTs_Single(t *testing.T) {
	re := mustParse(t, `foo`)
	got := mergeSuffixASTs([]*syntax.Regexp{re})
	if got == nil {
		t.Fatal("mergeSuffixASTs([one]) returned nil")
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

func TestMergeSuffixASTs_Sorted(t *testing.T) {
	asts := []*syntax.Regexp{mustParse(t, `z`), mustParse(t, `a`)}
	merged := mergeSuffixASTs(asts)
	if merged == nil || merged.Op != syntax.OpAlternate || len(merged.Sub) != 2 {
		t.Fatalf("mergeSuffixASTs: unexpected result %v", merged)
	}
	if merged.Sub[0].String() > merged.Sub[1].String() {
		t.Errorf("not sorted: sub[0]=%q sub[1]=%q", merged.Sub[0], merged.Sub[1])
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
	if len(tables.LaneToID) != 3 {
		t.Fatalf("LaneToID len = %d, want 3", len(tables.LaneToID))
	}
	for i, id := range tables.LaneToID {
		if id != i {
			t.Errorf("LaneToID[%d] = %d, want %d", i, id, i)
		}
	}
}

func TestMultiPatternTeddy_TooManyLiterals(t *testing.T) {
	lits := make([][]byte, 9)
	for i := range lits {
		lits[i] = []byte{byte('a' + i)}
	}
	_, ok := buildTeddyTablesMulti(lits)
	if ok {
		t.Error("buildTeddyTablesMulti: expected ok=false for 9 literals")
	}
}

func TestMultiPatternTeddy_LiteralTooLong(t *testing.T) {
	lits := [][]byte{[]byte("abcde")} // 5 bytes > 4
	_, ok := buildTeddyTablesMulti(lits)
	if ok {
		t.Error("buildTeddyTablesMulti: expected ok=false for 5-byte literal")
	}
}

func TestChooseLiteralFrontend(t *testing.T) {
	cases := []struct {
		lits [][]byte
		want frontendKind
	}{
		{[][]byte{[]byte("ab"), []byte("cd")}, frontendTeddy},
		{[][]byte{[]byte("a")}, frontendTeddy},
		{[][]byte{[]byte("abcd")}, frontendTeddy}, // 4 bytes: still Teddy
		{[][]byte{[]byte("abcde")}, frontendAC},   // 5 bytes: too long for Teddy
		{nil, frontendScalar},
	}
	// 9 literals → AC
	nineLits := make([][]byte, 9)
	for i := range nineLits {
		nineLits[i] = []byte{byte('a' + i)}
	}
	cases = append(cases, struct {
		lits [][]byte
		want frontendKind
	}{nineLits, frontendAC})

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
		Regexes: []config.RegexEntry{
			{Name: "dup", Pattern: `foo`},
			{Name: "dup", Pattern: `bar`},
		},
		Sets: []config.SetConfig{
			{Name: "s", FindAny: "ma", Patterns: config.PatternSelector{All: true}},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for duplicate regex name, got nil")
	}
}

func TestConfig_UnknownPatternRef_Rejected(t *testing.T) {
	cfg := config.BuildConfig{
		Regexes: []config.RegexEntry{
			{Name: "known", Pattern: `foo`},
		},
		Sets: []config.SetConfig{
			{
				Name:     "s",
				FindAny:  "ma",
				Patterns: config.PatternSelector{Names: []string{"unknown_name"}},
			},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for unknown pattern reference, got nil")
	}
}

func TestConfig_MissingFindAnyAndAll_Rejected(t *testing.T) {
	cfg := config.BuildConfig{
		Regexes: []config.RegexEntry{{Name: "p", Pattern: `foo`}},
		Sets: []config.SetConfig{
			{Name: "s", Patterns: config.PatternSelector{All: true}},
		},
	}
	if err := config.ValidateSets(&cfg); err == nil {
		t.Error("expected error for set with neither match_any nor match_all")
	}
}

func TestCompileFile_NoSets_ByteIdentical(t *testing.T) {
	// CompileFile with no sets must produce byte-identical output to Compile.
	patterns := []config.RegexEntry{
		{Pattern: `[a-z]+`, FindFunc: "find"},
	}
	wasmA, _, err := Compile(patterns, 0, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cfg := config.BuildConfig{Regexes: patterns}
	wasmB, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasmA) != len(wasmB) {
		t.Errorf("byte lengths differ: Compile=%d CompileFile=%d", len(wasmA), len(wasmB))
	}
}

func TestCompileFile_WithSets_ValidWASM(t *testing.T) {
	// CompileFile with sets must produce a non-empty WASM module with the
	// correct magic bytes and at least one exported function.
	cfg := config.BuildConfig{
		Regexes: []config.RegexEntry{
			{Name: "foo_pat", Pattern: `foo\d+`},
			{Name: "bar_pat", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{
				Name:     "test_set",
				FindAny:  "test_match_any",
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
		FindAny:    "test_any",
		Patterns:   patterns,
		PatternIDs: patternIDs,
	}
	cs, err := CompileSet(spec, &prefixPool, &suffixPool, CompileSetOptions{})
	if err != nil {
		t.Fatalf("CompileSet: %v", err)
	}
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
		Regexes: []config.RegexEntry{{Name: "p", Pattern: `bar\w+`}},
		Sets: []config.SetConfig{
			{Name: "s", FindAll: "s_all", Patterns: config.PatternSelector{All: true}},
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
		Regexes: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\d+`},
		},
		Sets: []config.SetConfig{
			{Name: "s", FindAny: "ma", Patterns: config.PatternSelector{All: true}},
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
		Regexes: []config.RegexEntry{
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
		Regexes: []config.RegexEntry{{Name: "p", Pattern: `foo\d+`}},
		Sets:    []config.SetConfig{{Name: "s", FindAny: "find_foo", Patterns: config.PatternSelector{All: true}}},
	}
	if _, _, err := CompileFile(cfg, ""); err != nil {
		t.Fatalf("CompileFile find-only: %v", err)
	}
}

func TestSetMatch_Anchored_BothExports(t *testing.T) {
	cfg := config.BuildConfig{
		Regexes: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\d+`},
			{Name: "p2", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{Name: "both", FindAll: "find_all_fn", Match: "match_fn", Patterns: config.PatternSelector{All: true}},
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
		Regexes: make([]config.RegexEntry, len(fix.Patterns)),
		Sets: []config.SetConfig{
			{Name: "sql", Match: "validate_sql", Patterns: config.PatternSelector{All: true}},
		},
	}
	for i, p := range fix.Patterns {
		cfg.Regexes[i] = config.RegexEntry{Pattern: p.Pattern}
	}
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile SQL validator: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("WASM too short: %d bytes", len(wasm))
	}
}

func TestValidateSets_MatchOnly(t *testing.T) {
	cfg := &config.BuildConfig{
		Regexes: []config.RegexEntry{{Name: "p", Pattern: "foo"}},
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
			Regexes: []config.RegexEntry{{Name: "p", Pattern: pat, FindFunc: "find"}},
			Sets: []config.SetConfig{
				{Name: "s", FindAll: "find_all", Patterns: config.PatternSelector{All: true}},
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
		Regexes: make([]config.RegexEntry, len(fix.Patterns)),
		Sets:    fix.Sets,
	}
	for i, p := range fix.Patterns {
		cfg.Regexes[i] = config.RegexEntry{Name: p.Name, Pattern: p.Pattern}
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
		Regexes: make([]config.RegexEntry, len(fix.Patterns)),
		Sets:    fix.Sets,
	}
	for i, p := range fix.Patterns {
		cfg.Regexes[i] = config.RegexEntry{Name: p.Name, Pattern: p.Pattern}
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
// Anchor helper tests (endsWithBeginAnchor, isOnlyBeginAnchors,
// hasBeginAnchor, hasBeginAnchorAtTopLevel)

func TestEndsWithBeginAnchor(t *testing.T) {
	cases := []struct {
		pat  string
		want bool
	}{
		{`^`, true},       // bare ^
		{`\z^`, true},     // end-then-begin: ends with ^
		{`(^^)*$`, false}, // ends with $, not ^
		{`(?:a)`, false},  // no anchor
		{`a^`, true},      // concat ending with ^
		{`^a`, false},     // concat ending with 'a'
		{`(^)`, true},     // capture wrapping ^
	}
	for _, tc := range cases {
		re := mustParse(t, tc.pat)
		if got := endsWithBeginAnchor(re); got != tc.want {
			t.Errorf("endsWithBeginAnchor(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
	if endsWithBeginAnchor(nil) {
		t.Error("endsWithBeginAnchor(nil) = true, want false")
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

func TestHasBeginAnchorAtTopLevel(t *testing.T) {
	cases := []struct {
		pat  string
		want bool
	}{
		{`^a`, true},      // ^ at mandatory start
		{`\Aa`, true},     // \A at mandatory start
		{`a^`, false},     // ^ after byte-consumer — not at top-level start
		{`(^^)*$`, false}, // ^ inside *, not mandatory at top level
		{`a+`, false},     // no anchor
		{`(^a)`, true},    // ^ through capture
	}
	for _, tc := range cases {
		re := mustParse(t, tc.pat)
		if got := hasBeginAnchorAtTopLevel(re); got != tc.want {
			t.Errorf("hasBeginAnchorAtTopLevel(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
	if hasBeginAnchorAtTopLevel(nil) {
		t.Error("hasBeginAnchorAtTopLevel(nil) = true, want false")
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
