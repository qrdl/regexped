package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// btABISet builds a one-set config declaring the capabilities the `_all` ABI
// switch touches. maxFallback = 1 forces its fallback members onto BT.
func btABISet(pats []string, maxFallback int) (config.SetConfig, config.BuildConfig) {
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sc := config.SetConfig{
		Name: "s", MatchAll: "s_match_all", ScanAll: "s_scan_all",
		ScanAny: "s_scan_any", Find: "s_find",
		Patterns: config.PatternSelector{All: true},
	}
	return sc, config.BuildConfig{
		Regexps: entries, MaxFallbackStates: maxFallback,
		Sets: []config.SetConfig{sc},
	}
}

// compileBTABISet compiles the set and hands back the artefact, so a test can
// ask what the emitter actually decided rather than infer it.
func compileBTABISet(t *testing.T, pats []string, maxFallback int) *compiledSet {
	t.Helper()
	sc, cfg := btABISet(pats, maxFallback)
	var prefixPool, suffixPool dfaPool
	idxs := make([]int, len(cfg.Regexps))
	for i := range idxs {
		idxs[i] = i
	}
	infos, gids, err := setPatternInfos(sc, cfg, idxs, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("setPatternInfos: %v", err)
	}
	spec := SetSpec{
		Name: sc.Name, MatchAll: sc.MatchAll, ScanAll: sc.ScanAll,
		ScanAny: sc.ScanAny, Find: sc.Find,
		DeclaredPatternCount: len(cfg.Regexps), IDSpaceSize: len(cfg.Regexps),
		Patterns: infos, PatternIDs: gids,
	}
	return CompileSet(spec, &prefixPool, &suffixPool,
		CompileSetOptions{MaxFallbackStates: maxFallback})
}

// TestSetBTForcesMemoryAllABI pins the Backtracking `_all` ABI: admitting a
// Backtracking member moves the `_all` bitmap into MEMORY and frees the return
// value to carry a count, whatever the id space.
//
// The narrow form is the only capability shape with no room for "unknown": its
// i64 return IS the bitmask, so -2 there reads as "everything matched except
// pattern 0" and no stub can tell the two apart.
//
// CONDITIONAL is half the contract — a set with no BT member must keep the
// cheap i64 form, so this asserts both directions on the same patterns.
func TestSetBTForcesMemoryAllABI(t *testing.T) {
	pats := []string{`(?:ab|cd)+xyz`, `hello`}

	plain := compileBTABISet(t, pats, 0)
	if plain.hasBTMember() {
		t.Fatal("no BT member expected at the default limit; the rest of this test is meaningless")
	}
	if plain.wideAll() {
		t.Error("a set with no BT member and a 2-id space must keep the narrow i64 _all form")
	}

	bt := compileBTABISet(t, pats, 1)
	if !bt.hasBTMember() {
		// Failing to build the required fixture is a failure, not a skip:
		// without a BT member there is no wide-_all arm left to assert, and a
		// skip would make this ABI regression test silently vacuous.
		t.Fatal("max_fallback_states=1 admitted no BT member; the forced-BT " +
			"fixture no longer builds and the wide-_all arm is untested")
	}
	if !bt.wideAll() {
		t.Error("a set with a BT member must use the memory _all form even at a 2-id space")
	}
}

// TestSetBTDisablesTwoPhaseSplit pins the other half of that decision.
//
// Phase 2 of the scan split is a union walk that answers with an i64
// accumulator and has no out_ptr at all — the NARROW _all ABI only. A BT member
// forces the wide form, so taking the split would compose two phases of
// different shapes, which is a module that does not validate.
func TestSetBTDisablesTwoPhaseSplit(t *testing.T) {
	// A literal-bearing pattern and a literal-less one: the mixed shape the
	// split exists for.
	pats := []string{`hello[0-9]{3}`, `(?:ab|cd)+`}
	bt := compileBTABISet(t, pats, 1)
	if !bt.hasBTMember() {
		t.Fatal("max_fallback_states=1 admitted no BT member; the forced-BT " +
			"fixture no longer builds and the split-suppression arm is untested")
	}
	if bt.phase2Union != nil {
		t.Error("a set with a BT member must not take the two-phase scan split: " +
			"phase 2 implements the narrow _all ABI only")
	}
}
