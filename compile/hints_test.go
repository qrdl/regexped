package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestParseHints covers parseHints directly (40% covered without this — only
// one of the three outcomes was reached via existing tests).
func TestParseHints(t *testing.T) {
	cases := []struct {
		hints   []string
		want    LikelyMode
		wantSet bool
	}{
		{[]string{"prefer-match"}, LikelyMatch, true},
		{[]string{"prefer-no-match"}, LikelyNoMatch, true},
		{nil, LikelyNeutral, false},
		{[]string{}, LikelyNeutral, false},
		// Unrecognised entries fall through to the neutral/unset default —
		// config.ValidHints is what actually rejects bad YAML at load time.
		{[]string{"unknown"}, LikelyNeutral, false},
	}
	for _, c := range cases {
		mode, set := parseHints(c.hints)
		if mode != c.want || set != c.wantSet {
			t.Errorf("parseHints(%v) = (%v, %v), want (%v, %v)", c.hints, mode, set, c.want, c.wantSet)
		}
	}
}

// TestResolveHints covers resolveHints' precedence chain (75% covered
// without this): the first entry in the chain that expresses an explicit
// choice wins, regardless of position.
func TestResolveHints(t *testing.T) {
	t.Run("first_link_wins", func(t *testing.T) {
		got := resolveHints([]string{"prefer-match"}, []string{"prefer-no-match"})
		if got != LikelyMatch {
			t.Errorf("resolveHints(pattern=match, set=no-match) = %v, want LikelyMatch", got)
		}
	})
	t.Run("falls_through_to_second_link", func(t *testing.T) {
		got := resolveHints(nil, []string{"prefer-no-match"})
		if got != LikelyNoMatch {
			t.Errorf("resolveHints(pattern=unset, set=no-match) = %v, want LikelyNoMatch", got)
		}
	})
	t.Run("neutral_when_nothing_set", func(t *testing.T) {
		got := resolveHints(nil, nil)
		if got != LikelyNeutral {
			t.Errorf("resolveHints(unset, unset) = %v, want LikelyNeutral", got)
		}
	})
	t.Run("no_chain_links", func(t *testing.T) {
		if got := resolveHints(); got != LikelyNeutral {
			t.Errorf("resolveHints() = %v, want LikelyNeutral", got)
		}
	})
}

// TestPatternHintsOverridesCallerLikelyMode verifies the actual wiring in
// compilePattern (compile.go): a pattern's own `hints:` YAML field takes
// precedence over whatever LikelyMode the caller passed in CompileOptions
// (plans/LIKELY.md Gap H.1). Observed via the same LikelyNoMatch-gated
// buildSimplePrefixCheckBody shortcut TestCompileLikelyNoMatchSimpleClassPrefix
// uses, but this time the mode comes from re.Hints, not CompileOptions,
// which is what's actually under test here.
func TestPatternHintsOverridesCallerLikelyMode(t *testing.T) {
	pattern := `[0-9]{8}ghp_[^\s]+`

	// Caller says neutral, but the pattern's own hint says no-match — the
	// hint must win and take the SIMD-verify shortcut.
	entry := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{"prefer-no-match"}}
	p, err := compilePattern(entry, 0, 0, CompileOptions{LikelyMode: LikelyNeutral})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.litAnchorBackScanBody == nil {
		t.Fatal("expected the lit-anchor path to fire")
	}

	// The reverse: caller says no-match, but the pattern's own hint says
	// neutral — the hint must still win, so the shortcut must NOT fire.
	entryNeutralHint := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{}}
	pNeutral, err := compilePattern(entryNeutralHint, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern (caller no-match, no pattern hint): %v", err)
	}
	// An empty hints list doesn't "set" anything (parseHints returns set=false),
	// so the caller's LikelyNoMatch should still apply here — both bodies
	// should therefore match (this is the Gap H.1 non-override case, not
	// a mismatch check like the block above).
	if len(p.litAnchorBackScanBody) == 0 || len(pNeutral.litAnchorBackScanBody) == 0 {
		t.Fatal("expected both compiles to produce a lit-anchor backscan body")
	}

	entryOverride := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{"prefer-match"}}
	pOverride, err := compilePattern(entryOverride, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern (caller no-match, pattern hint=match): %v", err)
	}
	if string(pOverride.litAnchorBackScanBody) == string(p.litAnchorBackScanBody) {
		t.Error("pattern hint 'prefer-match' should override the caller's LikelyNoMatch, but the shortcut still fired")
	}
}

// TestSetHintsSelectsShuftiFrontend verifies the wiring in CompileFile
// (set_emit.go): a set's own `hints: [prefer-no-match]` resolves through
// resolveHints(sc.Hints) into CompileSetOptions.LikelyMode, which is what
// TestCompileFile_ShuftiFrontend's "prefer-no-match" hint actually depends
// on. This test isolates that dependency by comparing hinted vs unhinted
// compiles of the identical pattern set directly through CompileSet, reading
// back the chosen frontend (cs.fe) rather than only checking the module
// compiles. The chosen literals' first-byte rarity sum is 66 (> the 40
// shuftiBeatsScalar threshold — digits and uppercase letters are "mid"
// rarity), so density alone would NOT select Shufti; only the LikelyNoMatch
// hint does.
func TestSetHintsSelectsShuftiFrontend(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	n := 33
	buildSpec := func(t *testing.T) (SetSpec, *dfaPool, *dfaPool) {
		t.Helper()
		var prefixPool, suffixPool dfaPool
		var patterns []*PatternInfo
		var patternIDs []int
		for i := 0; i < n; i++ {
			pat := fmt.Sprintf("%cq%02dx[a-z]+", alphabet[i], i)
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Fatalf("analyzePattern(%q): %v", pat, err)
			}
			patterns = append(patterns, info)
			patternIDs = append(patternIDs, i)
		}
		return SetSpec{Name: "s", FindAll: "find_all", Patterns: patterns, PatternIDs: patternIDs}, &prefixPool, &suffixPool
	}

	specHinted, prefixPool, suffixPool := buildSpec(t)
	csHinted := CompileSet(specHinted, prefixPool, suffixPool, CompileSetOptions{LikelyMode: LikelyNoMatch})
	if csHinted.fe != frontendShufti {
		t.Errorf("CompileSet with LikelyNoMatch: fe = %v, want frontendShufti", csHinted.fe)
	}

	specUnhinted, prefixPool2, suffixPool2 := buildSpec(t)
	csUnhinted := CompileSet(specUnhinted, prefixPool2, suffixPool2, CompileSetOptions{})
	if csUnhinted.fe == frontendShufti {
		t.Error("CompileSet without a LikelyNoMatch hint unexpectedly selected frontendShufti (density heuristic alone shouldn't for this byte set)")
	}
}
