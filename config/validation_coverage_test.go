package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Coverage for the package's config validation, including the branches that
// were the only untested ones left in it. Each case is a REFUSAL: the value under test is one a user can
// write in a config file, and the assertion is that loading it fails with a
// message naming the problem rather than reaching the generators.

// TestLoadConfigRejectsEmptyPattern covers the empty-`pattern:` guard
// . An empty pattern used to compile to something matching
// the empty string everywhere — almost always a YAML slip.
func TestLoadConfigRejectsEmptyPattern(t *testing.T) {
	for _, c := range []struct{ name, yaml, want string }{
		{
			name: "named entry",
			yaml: "regexps:\n  - name: broken\n    pattern: \"\"\n    match_func: m\n",
			want: `regexp broken has an empty pattern`,
		},
		{
			name: "unnamed entry falls back to its index",
			yaml: "regexps:\n  - pattern: \"\"\n    match_func: m\n",
			want: `regexp #0 has an empty pattern`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := loadYAML(t, c.yaml)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}

// TestLoadConfigRejectsUnknownStubType covers surfacing ResolveStubType's error
// at load rather than only at `generate` (D9).
func TestLoadConfigRejectsUnknownStubType(t *testing.T) {
	err := loadYAML(t, "stub_type: pascal\nregexps:\n  - pattern: 'a'\n    match_func: m\n")
	if err == nil || !strings.Contains(err.Error(), "pascal") {
		t.Errorf("want an error naming the unknown stub_type, got %v", err)
	}
}

// TestLoadConfigReadErrors covers the two failure paths before parsing.
func TestLoadConfigReadErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
			t.Error("want an error for a missing config file")
		}
	})
	t.Run("empty path defaults to regexped.yaml in cwd", func(t *testing.T) {
		// Run from a directory that has no regexped.yaml, so the default is
		// exercised and then fails to read.
		dir := t.TempDir()
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(cwd) //nolint:errcheck
		if _, err := LoadConfig(""); err == nil || !strings.Contains(err.Error(), "regexped.yaml") {
			t.Errorf("want the defaulted path in the error, got %v", err)
		}
	})
	t.Run("malformed YAML", func(t *testing.T) {
		if err := loadYAML(t, "regexps: [unclosed\n"); err == nil {
			t.Error("want a parse error for malformed YAML")
		}
	})
}

// TestValidateHintsRejectsPointlessBatchFind covers both arms of the
// "batch-find needs something to batch" rule (D9): the per-regexp one is new,
// the per-set one already existed.
func TestValidateHintsRejectsPointlessBatchFind(t *testing.T) {
	t.Run("regexp with neither find_func nor groups_func", func(t *testing.T) {
		cfg := &BuildConfig{Regexps: []RegexEntry{
			{Name: "p", Pattern: "a", MatchFunc: "m", Hints: []string{"batch-find"}},
		}}
		err := validateHints(cfg)
		if err == nil || !strings.Contains(err.Error(), "batch-find") {
			t.Errorf("want a batch-find error, got %v", err)
		}
	})
	t.Run("regexp with groups_func is accepted", func(t *testing.T) {
		cfg := &BuildConfig{Regexps: []RegexEntry{
			{Name: "p", Pattern: "(a)", GroupsFunc: "g", Hints: []string{"batch-find"}},
		}}
		if err := validateHints(cfg); err != nil {
			t.Errorf("groups_func alone should accept batch-find: %v", err)
		}
	})
	t.Run("unknown hint on a regexp", func(t *testing.T) {
		cfg := &BuildConfig{Regexps: []RegexEntry{
			{Name: "p", Pattern: "a", MatchFunc: "m", Hints: []string{"prefer-nothing"}},
		}}
		if err := validateHints(cfg); err == nil {
			t.Error("want an error for an unknown hint")
		}
	})
	t.Run("unknown hint on a set", func(t *testing.T) {
		cfg := &BuildConfig{
			Regexps: []RegexEntry{{Name: "p", Pattern: "a"}},
			Sets: []SetConfig{{
				Name: "s", Find: "f", Patterns: PatternSelector{All: true},
				Hints: []string{"prefer-nothing"},
			}},
		}
		if err := validateHints(cfg); err == nil {
			t.Error("want an error for an unknown set hint")
		}
	})
}

// TestSetBatchPatternCount covers SetCursorMaxPatterns' bound without building
// a slice of 16,777,217 names — see setBatchPatternCount's doc comment.
func TestSetBatchPatternCount(t *testing.T) {
	batching := SetConfig{Name: "s", Find: "f", Hints: []string{"batch-find"}}
	t.Run("no batch hint is always ok", func(t *testing.T) {
		s := SetConfig{Name: "s", Find: "f", Patterns: PatternSelector{All: true}}
		cfg := &BuildConfig{Regexps: make([]RegexEntry, SetCursorMaxPatterns+1)}
		if _, ok := setBatchPatternCount(s, cfg); !ok {
			t.Error("a set with no batch-find hint has no cursor and no limit")
		}
	})
	t.Run("named subset within the limit", func(t *testing.T) {
		s := batching
		s.Patterns = PatternSelector{Names: []string{"a", "b"}}
		if n, ok := setBatchPatternCount(s, &BuildConfig{}); n != 2 || !ok {
			t.Errorf("got (%d, %v), want (2, true)", n, ok)
		}
	})
	t.Run("patterns: all counts the regexps", func(t *testing.T) {
		s := batching
		s.Patterns = PatternSelector{All: true}
		cfg := &BuildConfig{Regexps: make([]RegexEntry, 3)}
		if n, ok := setBatchPatternCount(s, cfg); n != 3 || !ok {
			t.Errorf("got (%d, %v), want (3, true)", n, ok)
		}
	})
	t.Run("over the cursor limit", func(t *testing.T) {
		s := batching
		s.Patterns = PatternSelector{All: true}
		cfg := &BuildConfig{Regexps: make([]RegexEntry, SetCursorMaxPatterns+1)}
		if n, ok := setBatchPatternCount(s, cfg); ok {
			t.Errorf("got (%d, true), want ok=false past %d", n, SetCursorMaxPatterns)
		}
	})
	// The cap must be the one SetCursorKBits actually enforces, or the check
	// rejects configs the cursor could have carried (or admits ones it cannot).
	if got := SetCursorKBits(SetCursorMaxPatterns); got != 24 {
		t.Errorf("SetCursorKBits(%d) = %d, want the 24-bit cap", SetCursorMaxPatterns, got)
	}
}

// TestSetBatchExportName pins the synthesized batch export name. It lost its
// only in-package caller when the dead `_batch` reservation was removed (D9).
func TestSetBatchExportName(t *testing.T) {
	if got := SetBatchExportName("scan_urls"); got != "scan_urls_batch" {
		t.Errorf("SetBatchExportName = %q, want %q", got, "scan_urls_batch")
	}
}

// TestValidateSetsRejectsBatchSuffixAndStemCollisions covers the two
// name-shape refusals in ValidateSets.
func TestValidateSetsRejectsBatchSuffixAndStemCollisions(t *testing.T) {
	t.Run("regexp export ending in _batch", func(t *testing.T) {
		cfg := &BuildConfig{
			Regexps: []RegexEntry{{Name: "p", Pattern: "a", FindFunc: "scan_batch"}},
			Sets:    []SetConfig{{Name: "s", Find: "f", Patterns: PatternSelector{All: true}}},
		}
		err := ValidateSets(cfg)
		if err == nil || !strings.Contains(err.Error(), "_batch") {
			t.Errorf("want a _batch-suffix error, got %v", err)
		}
	})
	t.Run("two set names collapsing to one stem", func(t *testing.T) {
		cfg := &BuildConfig{
			Regexps: []RegexEntry{{Name: "p", Pattern: "a"}},
			Sets: []SetConfig{
				{Name: "url-guard", Find: "f1", Patterns: PatternSelector{All: true}},
				{Name: "url_guard", Find: "f2", Patterns: PatternSelector{All: true}},
			},
		}
		err := ValidateSets(cfg)
		if err == nil || !strings.Contains(err.Error(), "rename one") {
			t.Errorf("want a stem-collision error, got %v", err)
		}
	})
}

// TestValidateIdentifierRejectsBlank covers the blank-identifier refusal
// : `_` passes the character-shape rule but `pub fn _` is
// invalid Rust and `func _()` invalid Go.
func TestValidateIdentifierRejectsBlank(t *testing.T) {
	if err := ValidateIdentifier("_"); err == nil {
		t.Error("want an error for the blank identifier")
	}
	if err := ValidateIdentifier("_x"); err != nil {
		t.Errorf("a leading underscore is otherwise fine: %v", err)
	}
}

// TestValidateConfigChecksPatternNamesForNameMap covers the emit_name_map
// charset rule (D9): `name:` reaches generated source as a %q string literal,
// whose escapes are not valid in all six languages.
func TestValidateConfigChecksPatternNamesForNameMap(t *testing.T) {
	withNameMap := func(name string) *BuildConfig {
		return &BuildConfig{
			StubType: "c", ImportModule: "m",
			Regexps: []RegexEntry{{Name: name, Pattern: "a", MatchFunc: "m1"}},
			Sets: []SetConfig{{
				Name: "s", Find: "f", Patterns: PatternSelector{All: true},
				EmitNameMap: true,
			}},
		}
	}
	for _, bad := range []string{"a\x00b", "quote\"d", "back\\slash", "café"} {
		if err := ValidateConfig(withNameMap(bad)); err == nil {
			t.Errorf("name %q: want an error, got nil", bad)
		}
	}
	if err := ValidateConfig(withNameMap("plain name 1")); err != nil {
		t.Errorf("printable ASCII must be accepted: %v", err)
	}
	// Without emit_name_map the name never reaches generated source.
	cfg := withNameMap("café")
	cfg.Sets[0].EmitNameMap = false
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("without emit_name_map the name is unconstrained: %v", err)
	}
}

// TestASIteratorTypeCollision covers the AssemblyScript arm of the
// iterator-type check (K2): AS Pascal-cases its iterator name, so the
// colliding spelling differs from Go's.
func TestASIteratorTypeCollision(t *testing.T) {
	cfg := &BuildConfig{
		StubType: "as", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "a", FindFunc: "url_find"},
			{Name: "b", Pattern: "b", MatchFunc: "UrlFindIter"},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("want a collision with the AS iterator type UrlFindIter")
	}
}

// TestDerivedNameStyles covers derivedName's two casing arms and the
// empty-suffix identity, plus the exported pin the generate package uses.
func TestDerivedNameStyles(t *testing.T) {
	cases := map[[2]string]string{
		{"url_groups", "index"}: "url_groups_index",
		{"urlGroups", "index"}:  "urlGroupsIndex",
		{"find", "names"}:       "find_names",
		{"X", "count"}:          "X_count",
		{"url_groups", ""}:      "url_groups",
	}
	for in, want := range cases {
		if got := DerivedNameForValidation(in[0], in[1]); got != want {
			t.Errorf("derivedName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// TestDerivedExportSuffixes covers the per-language suffix table, including
// the AS arm (which adds `_iter` for both find and groups) and the fields that
// contribute nothing.
func TestDerivedExportSuffixes(t *testing.T) {
	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}
	if got := derivedExportSuffixes("groups_func", "go"); !has(got, "count") || has(got, "indices") {
		t.Errorf("go groups suffixes = %v", got)
	}
	if got := derivedExportSuffixes("groups_func", "ts"); !has(got, "indices") {
		t.Errorf("ts groups suffixes = %v, want indices", got)
	}
	if got := derivedExportSuffixes("groups_func", "as"); !has(got, "iter") {
		t.Errorf("as groups suffixes = %v, want iter", got)
	}
	if got := derivedExportSuffixes("find_func", "as"); !has(got, "iter") {
		t.Errorf("as find suffixes = %v, want iter", got)
	}
	if got := derivedExportSuffixes("find_func", "go"); len(got) != 0 {
		t.Errorf("go find derives no symbols, got %v", got)
	}
	if got := derivedExportSuffixes("match_func", "go"); len(got) != 0 {
		t.Errorf("match_func derives no symbols, got %v", got)
	}
}

// TestStubSharedSymbolsForValidation covers the mirror accessor the generate
// package pins against its own list.
func TestStubSharedSymbolsForValidation(t *testing.T) {
	if got := StubSharedSymbolsForValidation("go"); len(got) == 0 {
		t.Error("go declares shared symbols; the mirror returned none")
	}
	if got := StubSharedSymbolsForValidation("rust"); len(got) != 0 {
		t.Errorf("rust is isolated by `pub mod`, want no shared symbols, got %v", got)
	}
	// The accessor must COPY: a caller mutating the result must not be able to
	// change what validation denies.
	a := StubSharedSymbolsForValidation("go")
	a[0] = "mutated"
	if b := StubSharedSymbolsForValidation("go"); b[0] == "mutated" {
		t.Error("the accessor handed out its backing array")
	}
}

// TestSetNameStemTransforms covers the three stem transforms' edge cases: the
// lower-to-upper split, and the empty result a name of only separators gives.
func TestSetNameStemTransforms(t *testing.T) {
	if got := ScreamingSetName("sqlValidator"); got != "SQL_VALIDATOR" {
		t.Errorf("ScreamingSetName = %q, want SQL_VALIDATOR", got)
	}
	if got := ScreamingSetName("url9Guard"); got != "URL9_GUARD" {
		t.Errorf("ScreamingSetName digit-to-upper = %q, want URL9_GUARD", got)
	}
	if got := CamelSetName("-"); got != "" {
		t.Errorf("CamelSetName of a separator-only name = %q, want empty", got)
	}
	if got := PascalSetName("url-guard"); got != "UrlGuard" {
		t.Errorf("PascalSetName = %q, want UrlGuard", got)
	}
	// An unknown stub type derives no per-set constants.
	if got := setDerivedNames(SetConfig{Name: "s"}, "cobol"); got != nil {
		t.Errorf("setDerivedNames for an unknown stub type = %v, want nil", got)
	}
}

// TestValidateIdentShapeRejects covers validateIdentShape through the
// import_module check, which is its only caller.
func TestValidateIdentShapeRejects(t *testing.T) {
	// The empty case never reaches validateIdentShape through this caller —
	// validateImportModule returns early, because required-ness is main.go's
	// check — so it is exercised directly.
	if err := validateIdentShape(""); err == nil {
		t.Error("validateIdentShape(\"\"): want an error")
	}
	for _, c := range []struct{ name, mod string }{
		{"digit-leading", "9mod"},
		{"hyphenated", "my-mod"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := &BuildConfig{
				StubType: "rust", ImportModule: c.mod,
				Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "m"}},
			}
			if err := ValidateConfig(cfg); err == nil {
				t.Errorf("import_module %q: want an error", c.mod)
			}
		})
	}
}

// loadYAML writes body to a temp file and loads it, so LoadConfig's own path
// resolution and strict decoding are exercised rather than bypassed.
func loadYAML(t *testing.T, body string) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "regexped.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(p)
	return err
}

// TestValidateSetsRejectsOverCursorLimit drives the bound through ValidateSets
// itself, not just setBatchPatternCount. The named-subset form is what makes
// that affordable: 2^24+1 EMPTY strings are 268 MB of zeroed pages and no
// per-element allocation, and the check runs before the name-resolution loop,
// so nothing iterates the slice.
func TestValidateSetsRejectsOverCursorLimit(t *testing.T) {
	cfg := &BuildConfig{
		Sets: []SetConfig{{
			Name:     "s",
			Find:     "s_find",
			Hints:    []string{"batch-find"},
			Patterns: PatternSelector{Names: make([]string, SetCursorMaxPatterns+1)},
		}},
	}
	err := ValidateSets(cfg)
	if err == nil {
		t.Fatalf("%d patterns in a batching set: want an error", SetCursorMaxPatterns+1)
	}
	if !strings.Contains(err.Error(), "cursor") {
		t.Errorf("error %q does not name the cursor limit it tripped", err)
	}
}

// TestPatternSelectorDecodeError covers UnmarshalYAML's inner decode failure,
// which is a different path from its own "expected \"all\" or a list" verdict:
// the value never becomes a Go value at all, so the switch below never runs.
func TestPatternSelectorDecodeError(t *testing.T) {
	err := loadYAML(t, `
regexps:
  - pattern: 'a'
    name: a
sets:
  - name: s
    find: s_find
    patterns: !!binary [1]
`)
	if err == nil {
		t.Fatal("a patterns: value the YAML decoder cannot build: want an error")
	}
}
