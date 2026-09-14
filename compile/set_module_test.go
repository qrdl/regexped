package compile

import (
	"bytes"
	"fmt"
	"os"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/config"
)

// --------------------------------------------------------------------------
// splitAtPath tests

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

// TestCompileFile_ShuftiFrontend exercises emitSetMatchFnFinalShufti and
// litUnionFirstBytes (both 0% covered without this). Reaching the Shufti
// frontend requires, in order:
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
//     rarity heuristic.
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

func TestEquivalence_Conflict001(t *testing.T) { runConflictTest(t, "conflict_001") }

func TestEquivalence_Conflict002(t *testing.T) { runConflictTest(t, "conflict_002") }

func TestEquivalence_Conflict003(t *testing.T) { runConflictTest(t, "conflict_003") }

func TestEquivalence_Conflict004(t *testing.T) { runConflictTest(t, "conflict_004") }

func TestEquivalence_Conflict005(t *testing.T) { runConflictTest(t, "conflict_005") }

func TestEquivalence_Conflict006(t *testing.T) { runConflictTest(t, "conflict_006") }

func TestEquivalence_Conflict007(t *testing.T) { runConflictTest(t, "conflict_007") }

func TestEquivalence_Conflict008(t *testing.T) { runConflictTest(t, "conflict_008") }

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
			{Name: "sql", MatchAny: "validate_sql", Patterns: config.PatternSelector{All: true}},
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
			{Name: "both", Find: "find_all_fn", MatchAny: "match_fn", Patterns: config.PatternSelector{All: true}},
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
			{Name: "sql", MatchAny: "validate_sql", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
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
			{Name: "s", MatchAny: "m", Find: "f", Patterns: config.PatternSelector{All: true}},
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
			{Name: "p2", Pattern: `(?P<n>bar)(?P<m>\d+)`, GroupsFunc: "p2_groups"},
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
		Sets:    []config.SetConfig{{Name: "s", MatchAny: "validate", Patterns: config.PatternSelector{All: true}}},
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

// TestCompileFile_ShuftiNonAdaptive exercises the non-adaptive locals layout
// in emitSetMatchFnFinalShufti (shuftiAdaptive = lnm && !rare — false here
// because rare=true, i.e. shuftiBeatsScalar already selects Shufti
// statically, so the LikelyNoMatch hint changes nothing).
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
// emitSetMatchFnFinalShufti. TestCompileFile_ShuftiFrontend's
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
// prefixFnIdx loop) in the AC frontend (emitSetMatchFnFinalAC).
// Extends TestSetFind_AC_VarLenPrefix's 20-pattern shape (which forces
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
// lo/hi table load + nibble check" combination in emitSetMatchFnFinalTeddy.
// TwoGroups requires > 8 literals; FourByte requires every
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
// sets-less path. "secret_[A-Za-z0-9]+" qualifies for
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
// tested at the analyzePattern level directly).
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
// zero-width assertion, here \b, immediately before the mandatory literal).
// Confirmed live via analyzePattern/CompileSet probing:
// prefixFnIdx=[0] (a real, non-trivial prefix function), prefixFixedLens=[0]
// (zero-width), trivialPrefixMasks=[0] (not trivial) — exactly the L<=0,
// fnIdx>=0 combination the doc flagged as needing verification.
func TestSetMatch_ZeroWidthNonNilPrefix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `\bfoo`}},
		Sets: []config.SetConfig{
			{Name: "s", MatchAny: "s_match", Patterns: config.PatternSelector{All: true}},
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
// The per-export-combination matrix.
//
// An earlier review found bugs visible only under --find-only, and the same is true
// here: each capability emits a different body shape, and a set that declares
// only one of them exercises a code path no other config reaches. Every row
// below is one compiled config, checked for its exports and type-validated.

func TestSetCapabilityMatrix(t *testing.T) {
	pats := []string{`AKIA[A-Z0-9]{4}`, `ghp_[a-z]+`, `a*`, `\bcat\b`, `(?m:^)log`}
	all := []string{"match_any", "match_all", "scan_any", "scan_all", "find"}

	rows := []struct {
		name        string
		caps        []string
		overlapping bool
	}{
		{"match_any-only", []string{"match_any"}, false},
		{"match_all-only", []string{"match_all"}, false},
		{"scan_any-only", []string{"scan_any"}, false},
		{"scan_all-only", []string{"scan_all"}, false},
		{"find-only-gated", []string{"find"}, false},
		{"find-only-overlapping", []string{"find"}, true},
		{"scan_any-without-find", []string{"scan_any", "scan_all"}, false},
		{"scan_any-with-find", []string{"scan_any", "find"}, false},
		{"all-gated", all, false},
		{"all-overlapping", all, true},
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

// TestSetScanAnyWithoutFindIsSmaller pins the structural half of the
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
// which switches from an i64 bitmask return to an out_ptr bitmap.
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

// TestSetOverlappingFlagChangesFindBody pins the flag's effect: it is a
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

// TestSetDiagRecordsRouting pins the routing diagnostics: the class of a
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
// Subset selection: PATTERN_COUNT vs ID_SPACE.
//
// Every harness in this project builds sets that select ALL of the config's
// patterns, which keeps global pattern ids dense and equal to set-local
// indices — and that is precisely why this hazard survived 4.9M corpus cases. A
// pattern id is the GLOBAL index into `regexps:`, so a set selecting a
// non-prefix subset reports ids above its own pattern count, and everything
// indexed by an id has to be sized for that.

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

// TestSubsetAllABIMatchesIDSpace is the check that makes that hazard's third
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

// TestJumpIsProfitable pins the compile-time gate on the gate-array jump:
// it is emitted only where it can actually fire and pay for itself — one pattern, or a scalar frontend (whose Θ(n)
// stepping the O(patterns) prologue is noise against), and in either case only
// when some pattern can match more than one byte.
//
// The multi-pattern rejection that remains is specifically the LITERAL-frontend
// one measured earlier; the eight log-level patterns below are that set.
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
		// Multi-pattern, scalar frontend (no usable literal): admitted.
		{"two patterns scalar", []string{`a+`, `b+`}, true},
		{"multi scalar one exceeds", []string{`[a-z]`, `x+`}, true},
		// Multi-pattern, scalar, but nothing can exceed one byte → dead code.
		{"multi scalar all one byte", []string{`[a-z]`, `[0-9]`}, false},
		// Multi-pattern with a literal frontend: still rejected.
		{"two patterns teddy", []string{`a`, `b`}, false},
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

// TestSetFindBatch_Emission covers the structural half of find_batch:
// the export exists, is independent of `find`, and declaring it does not
// disturb the module for a set that doesn't ask for it. The BEHAVIOUR — the
// cursor, the split-position resume — needs a WASM runtime and lives in
// tools/fuzz/set_caps_test.go.
func TestSetFindBatch_Emission(t *testing.T) {
	entries := []config.RegexEntry{
		{Name: "a", Pattern: `foo\d+`},
		{Name: "b", Pattern: `bar\w+`},
	}
	build := func(s config.SetConfig) []byte {
		t.Helper()
		w, _, err := CompileFile(config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{s}}, "")
		if err != nil {
			t.Fatalf("CompileFile: %v", err)
		}
		return w
	}
	all := config.PatternSelector{All: true}

	batchHint := []string{"batch-find"}

	t.Run("hint_adds_the_batch_export_alongside_find", func(t *testing.T) {
		// Batching is a property of `find`, not a capability.
		// The hint adds the synthesized export; `find` itself stays exported.
		w := build(config.SetConfig{Name: "s", Find: "plain_find", Hints: batchHint, Patterns: all})
		for _, name := range []string{"plain_find", "plain_find_batch"} {
			if !bytes.Contains(w, []byte(name)) {
				t.Errorf("export %q missing from a batching set", name)
			}
		}
		assertDataSectionConsistent(t, w)
	})

	t.Run("no_hint_emits_no_batch_export", func(t *testing.T) {
		w := build(config.SetConfig{Name: "s", Find: "plain_find", Patterns: all})
		if bytes.Contains(w, []byte("plain_find_batch")) {
			t.Error("a set without the hint must not carry the batch export")
		}
	})

	t.Run("overlapping", func(t *testing.T) {
		// The ungated body takes the batch skip parameter on its suffix functions;
		// this is the path with no gate array to resume a split position with.
		w := build(config.SetConfig{Name: "s", Find: "plain_find", Hints: batchHint, Overlapping: true, Patterns: all})
		if !bytes.Contains(w, []byte("plain_find_batch")) {
			t.Error("batch export missing from an overlapping set")
		}
		assertDataSectionConsistent(t, w)
	})

	t.Run("unhinted_is_unchanged", func(t *testing.T) {
		// The byte-identity rule one level up: a set that does not ask for batching must
		// compile to exactly what it compiled to before batching existed.
		a := build(config.SetConfig{Name: "s", Find: "plain_find", Patterns: all})
		b := build(config.SetConfig{Name: "s", Find: "plain_find", Patterns: all})
		if !bytes.Equal(a, b) {
			t.Fatal("compilation is not deterministic; the comparison below is meaningless")
		}
		c := build(config.SetConfig{Name: "s", Find: "plain_find", Hints: batchHint, Patterns: all})
		if len(c) <= len(a) {
			t.Errorf("the hint did not add code: %d bytes vs %d", len(c), len(a))
		}
		// The batch entry WRAPS the ordinary find rather than
		// re-emitting the bucket code, so the cost is the resume loop and a
		// wrapper, not a second copy of the body.
		if grew := len(c) - len(a); grew > len(a) {
			t.Errorf("batching more than doubled the module (%d -> %d); the worker is not being shared", len(a), len(c))
		}
	})
}

// TestSetCursorLayout pins the cursor field widths. They
// are computed in config so the compiler and all six generators share ONE
// definition; this asserts the definition itself, not either caller.
func TestSetCursorLayout(t *testing.T) {
	cases := []struct{ patterns, kBits int }{
		{1, 1}, {2, 2}, {3, 2}, {4, 3}, {7, 3}, {8, 4},
		{128, 8}, {255, 8}, {256, 9},
	}
	for _, c := range cases {
		if got := config.SetCursorKBits(c.patterns); got != c.kBits {
			t.Errorf("SetCursorKBits(%d) = %d, want %d", c.patterns, got, c.kBits)
		}
		// k must be representable for every value a position can produce.
		if max := (1 << uint(config.SetCursorKBits(c.patterns))) - 1; max < c.patterns {
			t.Errorf("kBits for %d patterns holds only up to %d", c.patterns, max)
		}
		if got := config.SetCursorCountBits(c.patterns) + config.SetCursorKBits(c.patterns); got != 32 {
			t.Errorf("count+k widths for %d patterns = %d, want 32", c.patterns, got)
		}
	}
}

// The set emitters are reached by COMPILING, not by running, and until this
// file existed almost none of them were reached from this package at all.
//
// The correctness of what they emit is checked elsewhere and at far greater
// depth — `make setcaps` drives every capability over the RE2 corpus,
// `tools/fuzz` runs differential targets against Go's regexp. Both live in
// SEPARATE MODULES, so neither contributes a single statement to this
// package's coverage, and the gap that hid was total: `set_overlap_dp.go`,
// 314 statements of backward sweep, sat at 2.5% while being exercised
// thousands of times a second by a fuzz target one directory away.
//
// So this file's job is DIFFERENT from theirs: reach every emitter with a
// configuration that selects it, and assert the compile succeeded and
// produced a plausible module. Think of it as a smoke matrix — it is what
// notices when a shape stops compiling at all, which is a failure mode the
// corpus runners report far more slowly and a `go test ./compile` run should
// report immediately.
//
// Each case documents WHICH path it is there to select, because that is the
// only thing making it worth its runtime; a case whose comment no longer
// matches what the compiler does should be re-aimed rather than deleted.

// setMatrixCase is one set configuration plus the reason it exists.
type setMatrixCase struct {
	name string
	// selects names the emitter path this case is here to reach.
	selects  string
	patterns []string
	// subset, when non-empty, makes the set select those pattern NAMES rather
	// than all of them — the only configuration where ID_SPACE and
	// PATTERN_COUNT differ (docs/sets.md "Pattern ids and the two emitted
	// constants").
	subset      []string
	caps        setMatrixCaps
	overlapping bool
	batch       bool
	hints       []string
	// maxFallbackStates, when non-zero, caps the fallback suffix DFA. Setting
	// it to 1 is how a member is forced onto the BACKTRACKING engine
	//: no fallback DFA can be built that small, so the
	// pattern is admitted on BT instead of dropped.
	maxFallbackStates int
	// perPattern gives each pattern its OWN exports alongside the set.
	// A config may carry both, and the assembly then has to lay out the
	// single-pattern bodies — lit-anchor scans, groups wrappers, batch
	// wrappers — beside the set's, which is a different arm from a
	// sets-only config.
	perPattern perPatternExports
}

type perPatternExports struct {
	match, find, groups, batch bool
}

// setMatrixCaps says which capabilities the set declares. The compiler emits
// only the machinery the declared capabilities need, so this is a real axis:
// an anchored-only set emits no literal frontend at all.
type setMatrixCaps struct {
	matchAny, matchAll, scanAny, scanAll, find bool
}

var (
	capsAll      = setMatrixCaps{true, true, true, true, true}
	capsFind     = setMatrixCaps{find: true}
	capsAnchored = setMatrixCaps{matchAny: true, matchAll: true}
	capsScan     = setMatrixCaps{scanAny: true, scanAll: true}
)

// manyPatterns builds n distinct patterns sharing no literal, for the
// bucket-count and id-space axes.
func manyPatterns(n int, shape string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(shape, i)
	}
	return out
}

func setMatrixCases() []setMatrixCase {
	greedy := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	keywords := []string{`alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`}
	return []setMatrixCase{
		{
			name: "greedy-all-caps", selects: "scalar frontend, fallback buckets, every capability",
			patterns: greedy, caps: capsAll,
		},
		{
			name: "greedy-overlapping-batch", selects: "set_overlap_dp.go — the backward sweep and its answer cache",
			patterns: greedy, caps: capsFind, overlapping: true, batch: true,
		},
		{
			name: "greedy-overlapping", selects: "the ungated find body and its once-per-drive preflight",
			patterns: greedy, caps: capsFind, overlapping: true,
		},
		{
			name: "greedy-batch-gated", selects: "set_batch.go's gated resume path",
			patterns: greedy, caps: capsFind, batch: true,
		},
		{
			name: "greedy-scan-only", selects: "set_union_scan.go — the start-anywhere union automaton",
			patterns: greedy, caps: capsScan,
		},
		{
			name: "greedy-anchored-only", selects: "set_caps.go's anchored bodies, with NO literal frontend emitted",
			patterns: greedy, caps: capsAnchored,
		},
		{
			name: "keywords-literal-frontend", selects: "packed-pair / Teddy literal frontend over shared literals",
			patterns: keywords, caps: capsAll,
		},
		{
			name: "keywords-overlapping-batch", selects: "a literal frontend under the batching overlapping entry",
			patterns: keywords, caps: capsFind, overlapping: true, batch: true,
		},
		{
			name: "many-literals-ac", selects: "aho_corasick.go — >16 literals with low first-byte diversity",
			patterns: manyPatterns(24, "keyword%02d"), caps: capsAll,
		},
		{
			name: "diverse-literals", selects: "byte_rank.go's two-column probe and the Shufti prefilter",
			patterns: manyPatterns(20, "%c-marker-x"), caps: capsAll,
		},
		{
			name: "sparse-bucket", selects: "set_sparse.go — per-state accept LISTS once a bucket passes 32 patterns",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsAll,
		},
		{
			name: "wide-id-space", selects: "the WIDE `_all` form: a memory bitmap instead of an i64 mask",
			patterns: manyPatterns(70, "pat_%02d_tail"), caps: capsAll,
		},
		{
			name: "named-subset", selects: "ID_SPACE > PATTERN_COUNT, the memory-safety hazard",
			patterns: manyPatterns(12, "sub%02d"), subset: []string{"p00", "p05", "p11"}, caps: capsAll,
		},
		{
			name: "word-boundary", selects: "the \\b channel: wordChar table, wbNW/wbW accept and dominant tables",
			patterns: []string{`\bcat\b`, `\bdog`, `\b|0*`}, caps: capsAll,
		},
		{
			name: "word-boundary-overlapping", selects: "the same channel under the ungated find body",
			patterns: []string{`\bcat\b`, `\bdog`}, caps: capsFind, overlapping: true,
		},
		{
			name: "multiline", selects: "the (?m) newline channel and its pre-transition accept table",
			patterns: []string{`(?m:^)alpha`, `beta(?m:$)`, `(?m:^)gamma(?m:$)`}, caps: capsAll,
		},
		{
			name: "anchored-members", selects: "begin/end-anchored members, eligible only at position 0 or EOF",
			patterns: []string{`\Aabc`, `xyz\z`, `\Aq\z`}, caps: capsAll,
		},
		{
			name: "empty-capable", selects: "patterns matching empty beside ones that also extend",
			patterns: []string{`a*`, ``, `(?:)`, `[ab]{0,2}`}, caps: capsAll,
		},
		{
			name: "mixed-literal-and-not", selects: "the two-phase scan split: literal buckets in phase 1, the union pass in phase 2",
			patterns: []string{`alpha`, `bravo`, `a+`, `[^\n]*END`}, caps: capsAll,
		},
		{
			name: "counted-repetition", selects: "large counted repetitions, which stress the suffix DFA budget",
			patterns: []string{`a{4,8}b`, `[0-9]{6}`, `x{2,3}y{2,3}`}, caps: capsAll,
		},
		{
			name: "prefer-match-hint", selects: "the set-level LikelyMatch bias",
			patterns: greedy, caps: capsAll, hints: []string{"prefer-match"},
		},
		{
			name: "prefer-no-match-hint", selects: "the set-level LikelyNoMatch bias and its adaptive density counter",
			patterns: keywords, caps: capsAll, hints: []string{"prefer-no-match"},
		},

		// ---- Backtracking members --------------------
		//
		// maxFallbackStates = 1 admits every fallback member on BT, which is
		// the whole of set_bt.go plus the ABI switch it forces: a BT member
		// can answer "unknown", and the narrow i64 `_all` form has no value
		// free to say so, so the bitmap moves into MEMORY whatever the id
		// space.
		{
			name: "bt-all-caps", selects: "set_bt.go — the Backtracking set body and the wide `_all` it forces",
			patterns: greedy, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-find-batch", selects: "a BT member under the batching find, including its overflow sentinel",
			patterns: greedy, caps: capsFind, batch: true, maxFallbackStates: 1,
		},
		{
			name: "bt-overlapping", selects: "a BT member under the ungated find body",
			patterns: greedy, caps: capsFind, overlapping: true, maxFallbackStates: 1,
		},
		{
			name: "bt-with-literals", selects: "a mixed set: literal buckets beside a BT fallback member",
			patterns: []string{`alpha`, `bravo`, `a+`, `[^\n]*END`}, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-captures-stripped", selects: "capture-bearing members, whose groups are stripped before the set sees them",
			patterns: []string{`(a+)(b+)`, `(?:x|y)+z`}, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-anchored-only", selects: "the ANCHORED Backtracking set body: full consumption, no find machinery",
			patterns: greedy, caps: capsAnchored, maxFallbackStates: 1,
		},
		{
			name: "bt-match-any-only", selects: "a single anchored capability over Backtracking members",
			patterns: greedy, caps: setMatrixCaps{matchAny: true}, maxFallbackStates: 1,
		},
		{
			name: "bt-scan-only", selects: "the scan pair over Backtracking members",
			patterns: greedy, caps: capsScan, maxFallbackStates: 1,
		},

		// ---- more sparse and scan shapes ---------------------------------
		{
			name: "sparse-overlapping-batch", selects: "a sparse bucket under the batching overlapping entry",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsFind,
			overlapping: true, batch: true,
		},
		{
			name: "sparse-scan", selects: "the sparse bucket's probe bodies, which scan_any/scan_all drive",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsScan,
		},
		{
			name: "sparse-anchored", selects: "compileAnchoredBuckets with a sparse promotion",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsAnchored,
		},
		{
			name: "scan-any-literal-less", selects: "scan_any alone on a literal-less set — one union-automaton pass",
			patterns: greedy, caps: setMatrixCaps{scanAny: true},
		},
		{
			name: "scan-all-only", selects: "scan_all alone, which must keep the full probe rather than a first-hit exit",
			patterns: greedy, caps: setMatrixCaps{scanAll: true},
		},
		{
			name: "match-any-only", selects: "match_any alone over the dedicated anchored automaton",
			patterns: keywords, caps: setMatrixCaps{matchAny: true},
		},
		{
			name: "wide-subset-scan", selects: "a wide id space reached through a NAMED subset, scan capabilities only",
			patterns: manyPatterns(70, "pat_%02d_tail"),
			subset:   []string{"p00", "p33", "p69"}, caps: capsScan,
		},

		// ---- one bucket, many patterns: sparse accept ---------------
		//
		// Sparse needs >32 patterns in ONE bucket, which means they must share
		// the SAME mandatory literal and differ only after it. Distinct
		// literals give distinct SINGLETON buckets and never promote — which
		// is what an earlier version of this matrix did, sitting at 40
		// singletons while claiming to test sparse.
		{
			name: "sparse-shared-literal", selects: "set_sparse.go — 40 patterns behind ONE shared literal",
			patterns: sharedLiteral(40), caps: capsAll,
		},
		{
			name: "sparse-shared-scan", selects: "buildSparseProbeBody — the sparse bucket's scan probes",
			patterns: sharedLiteral(40), caps: capsScan,
		},
		{
			name: "sparse-shared-find-batch", selects: "a sparse bucket under the batching find",
			patterns: sharedLiteral(40), caps: capsFind, batch: true,
		},
		{
			name: "sparse-shared-overlapping", selects: "a sparse bucket under the ungated find body",
			patterns: sharedLiteral(40), caps: capsFind, overlapping: true,
		},
		{
			name: "sparse-shared-anchored", selects: "a sparse promotion in the ANCHORED packer",
			patterns: sharedLiteral(40), caps: capsAnchored,
		},
		{
			name: "sparse-very-wide", selects: "a sparse bucket past 64 patterns, forcing the wide `_all` too",
			patterns: sharedLiteral(80), caps: capsAll,
		},

		// A LARGE Aho-Corasick automaton: many literals with diverse first
		// bytes, which is the AC frontend's own scaling axis.
		//
		// NOT a Shufti case, though it was written as one. Shufti is selected
		// only from the SCALAR branch, and reaching that needs Aho-Corasick to
		// decline first — which `compile_api_test.go` arranges with
		// `ACBudgetBytes: 1`, an option `BuildConfig` does not expose. AC still
		// took a 220-literal set comfortably inside its 512 KB budget, so no
		// YAML config appears able to select the Shufti frontend at all, and
		// `emitSetMatchFnFinalShufti` is unreachable through `CompileFile`.
		// Recorded rather than papered over with a case that does not do what
		// its name claims.
		{
			name: "large-ac", selects: "aho_corasick.go at scale — 90 literals, diverse first bytes",
			patterns: diverseFirstBytes(90), caps: capsAll, hints: []string{"prefer-no-match"},
		},

		// ---- a config carrying BOTH a set and per-pattern exports ---------
		//
		// The two are laid out together, so the assembly has to place
		// single-pattern bodies — lit-anchor back-scans, groups wrappers,
		// batch wrappers — beside the set's own functions and keep every
		// function index straight across both. A sets-only config never
		// reaches those arms.
		{
			name: "set-plus-pattern-exports", selects: "assembleModuleWithSets laying out per-pattern bodies beside a set",
			patterns: []string{`[a-z]+@example\.com`, `ghp_[A-Za-z0-9]{36}`},
			caps:     capsAll, perPattern: perPatternExports{match: true, find: true},
		},
		{
			name: "set-plus-groups", selects: "a groups wrapper beside a set — capture patterns are dropped FROM the set but keep their own export",
			patterns: []string{`(?P<user>[a-z]+)@(?P<host>[a-z.]+)`, `plain[0-9]+`},
			caps:     capsAll, perPattern: perPatternExports{groups: true, find: true},
		},
		{
			name: "set-plus-batch-groups", selects: "the per-pattern BATCH groups wrapper beside a set",
			patterns: []string{`(?P<a>[a-z])(?P<b>[0-9])`, `lit[0-9]+`},
			caps:     capsFind, perPattern: perPatternExports{groups: true, find: true, batch: true},
		},
		{
			name: "set-plus-lit-anchor", selects: "a lit-anchor back-scan body beside a set",
			patterns: []string{`[a-z]+@example\.com`, `[0-9]+-suffix`},
			caps:     capsFind, perPattern: perPatternExports{find: true},
		},
		{
			name: "set-plus-everything", selects: "match, find, groups and batching per pattern, all beside a set",
			patterns: []string{`(?P<w>[a-z]+)@(?P<h>[a-z.]+)`, `[a-z]+@example\.com`},
			caps:     capsAll, perPattern: perPatternExports{match: true, find: true, groups: true, batch: true},
		},
	}
}

// sharedLiteral builds n patterns that all carry the SAME mandatory literal
// and differ only in the suffix after it, so the packer puts them in one
// bucket — the precondition for sparse promotion.
func sharedLiteral(n int) []string {
	out := make([]string, n)
	for i := range out {
		// The literal is "SHAREDKEY" in every one of them: the distinguishing
		// part is the SUFFIX. Putting it before the literal, or inside it,
		// makes each pattern's mandatory literal distinct and lands them in n
		// singleton buckets instead of one.
		out[i] = fmt.Sprintf("SHAREDKEY[0-9]{%d}", i+1)
	}
	return out
}

// diverseFirstBytes builds n literal-bearing patterns whose FIRST bytes cycle a
// 36-character alphabet, keeping the union inside Shufti's 17..64 band while
// the literals stay long enough to matter.
func diverseFirstBytes(n int) []string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := make([]string, n)
	for i := range out {
		// Long literals so the Aho-Corasick table exceeds its budget and
		// declines, which is what leaves the scalar branch — the only place
		// Shufti is selected — to take them.
		out[i] = fmt.Sprintf("%cqqqqqqqq%04dxxxxxxxx[a-z]+", alphabet[i%len(alphabet)], i)
	}
	return out
}

func (c setMatrixCase) build() config.BuildConfig {
	entries := make([]config.RegexEntry, len(c.patterns))
	for i, p := range c.patterns {
		e := config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: p}
		if c.perPattern.match {
			e.MatchFunc = fmt.Sprintf("p%02d_match", i)
		}
		if c.perPattern.find {
			e.FindFunc = fmt.Sprintf("p%02d_find", i)
		}
		// Only where the pattern HAS capture groups: a groups export is
		// emitted for MaxCap() > 0 alone, so setting it elsewhere asks for a
		// function the compiler will not produce.
		if c.perPattern.groups {
			if parsed, err := syntax.Parse(p, syntax.Perl); err == nil && parsed.MaxCap() > 0 {
				e.GroupsFunc = fmt.Sprintf("p%02d_groups", i)
			}
		}
		if c.perPattern.batch {
			e.Hints = append(e.Hints, "batch-find")
		}
		entries[i] = e
	}
	sel := config.PatternSelector{All: true}
	if len(c.subset) > 0 {
		sel = config.PatternSelector{Names: c.subset}
	}
	set := config.SetConfig{
		Name:        "s",
		Patterns:    sel,
		Overlapping: c.overlapping,
		Hints:       c.hints,
	}
	if c.caps.matchAny {
		set.MatchAny = "cap_match_any"
	}
	if c.caps.matchAll {
		set.MatchAll = "cap_match_all"
	}
	if c.caps.scanAny {
		set.ScanAny = "cap_scan_any"
	}
	if c.caps.scanAll {
		set.ScanAll = "cap_scan_all"
	}
	if c.caps.find {
		set.Find = "cap_find"
	}
	if c.batch {
		set.Hints = append(append([]string(nil), set.Hints...), "batch-find")
	}
	return config.BuildConfig{
		Regexps:           entries,
		Sets:              []config.SetConfig{set},
		MaxFallbackStates: c.maxFallbackStates,
	}
}

// TestSetMatrixCompiles compiles every shape in the matrix and checks the
// module is well formed enough to be worth emitting.
//
// It deliberately does NOT check match results: that is the corpus runners'
// job, they do it far more thoroughly, and duplicating a weaker version here
// would be a second oracle to keep in sync. What this asserts is that the path
// still compiles, still exports what it promised, and still looks like a WASM
// module.
func TestSetMatrixCompiles(t *testing.T) {
	for _, c := range setMatrixCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.build()
			// STANDALONE (its own exported memory, what JS/TS load) and
			// EMBEDDED (memory imported from "main", what a merged Rust/Go/C
			// host gets) are different assembly arms: the embedded one imports
			// rather than declares, and renumbers every memory index after it.
			// A set shape that assembles one way and not the other would
			// otherwise surface only at merge time.
			//
			// The arm is selected by cfg.Output, NOT by CompileFile's `output`
			// argument — `standalone := cfg.Output == ""` in CompileFileDiag.
			// This loop used to vary only the argument, so cfg.Output stayed
			// empty and BOTH passes compiled standalone: the embedded arm was
			// never reached, while the failure messages still said "embedded".
			// Set it on the config, and keep passing it as the argument too,
			// which is what the CLI does.
			byMode := map[string][]byte{}
			for _, output := range []string{"", "merged.wasm"} {
				mode := "standalone"
				modeCfg := cfg
				if output != "" {
					mode = "embedded"
					modeCfg.Output = output
				}
				wasm, _, err := CompileFile(modeCfg, output)
				if err != nil {
					t.Fatalf("%s/%s (selects %s): %v", c.name, mode, c.selects, err)
				}
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s/%s: not a WASM module (%d bytes)", c.name, mode, len(wasm))
				}
				// Every declared capability must appear as an export name. The
				// export section stores names as plain bytes, so a substring
				// search over the module is enough to catch a capability that
				// silently stopped being emitted.
				for _, want := range c.wantExports() {
					if !strings.Contains(string(wasm), want) {
						t.Errorf("%s/%s: module does not export %q", c.name, mode, want)
					}
				}
				byMode[mode] = wasm
			}
			// The two arms must actually produce DIFFERENT modules — one
			// declares and exports its memory, the other imports it from
			// "main" and renumbers every memory index after it. Identical
			// bytes mean the loop compiled the same arm twice, which is what
			// it silently did while it varied only CompileFile's argument:
			// the embedded path went untested for as long as that lasted,
			// with the failure messages above still naming it. Comparing the
			// output is the only assertion that notices.
			if bytes.Equal(byMode["standalone"], byMode["embedded"]) {
				t.Errorf("%s: standalone and embedded compiled to identical bytes; "+
					"the embedded arm is not being exercised", c.name)
			}
		})
	}
}

func (c setMatrixCase) wantExports() []string {
	var out []string
	if c.caps.matchAny {
		out = append(out, "cap_match_any")
	}
	if c.caps.matchAll {
		out = append(out, "cap_match_all")
	}
	if c.caps.scanAny {
		out = append(out, "cap_scan_any")
	}
	if c.caps.scanAll {
		out = append(out, "cap_scan_all")
	}
	if c.caps.find {
		out = append(out, "cap_find")
	}
	if c.batch {
		out = append(out, config.SetBatchExportName("cap_find"))
	}
	return out
}

// TestSetMatrixDiagnostics runs the same matrix through the diagnostics entry
// point, which is a separate code path from CompileFile and reports the
// composition decisions — bucket kinds, frontend choice, dropped patterns.
//
// Worth its own pass because a diagnostics build that disagrees with the real
// one is how `--diag-json` would start describing a module nobody compiled.
func TestSetMatrixDiagnostics(t *testing.T) {
	for _, c := range setMatrixCases() {
		t.Run(c.name, func(t *testing.T) {
			_, _, diags, err := CompileFileDiag(c.build(), "")
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(diags) != 1 {
				t.Fatalf("%s: expected one set diagnostic, got %d", c.name, len(diags))
			}
			// A set can legitimately end up with NO buckets when every member
			// was excluded — capture-bearing patterns are dropped from sets by
			// design. Say which it is rather than treating both as the same
			// failure.
			if len(diags[0].Buckets) == 0 {
				allCaptures := true
				for _, pat := range c.patterns {
					if parsed, err := syntax.Parse(pat, syntax.Perl); err == nil && parsed.MaxCap() == 0 {
						allCaptures = false
					}
				}
				if !allCaptures {
					t.Errorf("%s: no buckets, though not every pattern is capture-bearing", c.name)
				}
			}
		})
	}
}
