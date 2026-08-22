package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestCaptureStubsRequested(t *testing.T) {
	cases := []struct {
		entry RegexEntry
		want  bool
	}{
		{RegexEntry{}, false},
		{RegexEntry{MatchFunc: "m"}, false},
		{RegexEntry{FindFunc: "f"}, false},
		{RegexEntry{GroupsFunc: "g"}, true},
		{RegexEntry{NamedGroupsFunc: "ng"}, true},
		{RegexEntry{GroupsFunc: "g", NamedGroupsFunc: "ng"}, true},
	}
	for _, c := range cases {
		if got := c.entry.CaptureStubsRequested(); got != c.want {
			t.Errorf("CaptureStubsRequested(%+v) = %v, want %v", c.entry, got, c.want)
		}
	}
}

func TestGroupsExportName(t *testing.T) {
	cases := []struct {
		entry RegexEntry
		want  string
	}{
		{RegexEntry{GroupsFunc: "grp"}, "grp"},
		{RegexEntry{NamedGroupsFunc: "ng"}, "ng"},
		{RegexEntry{GroupsFunc: "grp", NamedGroupsFunc: "ng"}, "grp"},
		{RegexEntry{}, ""},
	}
	for _, c := range cases {
		if got := c.entry.GroupsExportName(); got != c.want {
			t.Errorf("GroupsExportName(%+v) = %q, want %q", c.entry, got, c.want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	yaml := "regexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Regexps) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cfg.Regexps))
	}
	if cfg.Regexps[0].MatchFunc != "foo_match" {
		t.Errorf("MatchFunc = %q, want foo_match", cfg.Regexps[0].MatchFunc)
	}
}

func TestLoadConfigBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(":\t{{invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for bad YAML, got nil")
	}
}

func TestLoadConfigNoRegexes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte("output: merged.wasm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for config with no regexps, got nil")
	}
}

func TestLoadConfigPathResolution(t *testing.T) {
	dir := t.TempDir()
	yaml := "wasm_file: regexps.wasm\nstub_file: src/stub.rs\noutput: final.wasm\nregexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.WasmFile != filepath.Join(dir, "regexps.wasm") {
		t.Errorf("WasmFile = %q, want %q", cfg.WasmFile, filepath.Join(dir, "regexps.wasm"))
	}
	if cfg.StubFile != filepath.Join(dir, "src/stub.rs") {
		t.Errorf("StubFile = %q, want %q", cfg.StubFile, filepath.Join(dir, "src/stub.rs"))
	}
	if cfg.Output != filepath.Join(dir, "final.wasm") {
		t.Errorf("Output = %q, want %q", cfg.Output, filepath.Join(dir, "final.wasm"))
	}
}

func TestLoadConfigWasmMergeResolution(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name      string
		wasmMerge string
		want      string
	}{
		{"relative path", "tools/wasm-merge", filepath.Join(dir, "tools/wasm-merge")},
		{"bare command", "wasm-merge", filepath.Join(dir, "wasm-merge")},
		{"absolute path", "/usr/local/bin/wasm-merge", "/usr/local/bin/wasm-merge"},
		{"home relative", "~/bin/wasm-merge", homeJoin("bin/wasm-merge")},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := "wasm_merge: " + c.wasmMerge + "\nregexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"
			if c.wasmMerge == "" {
				yaml = "regexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"
			}
			path := filepath.Join(dir, "regexped.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.WasmMerge != c.want {
				t.Errorf("WasmMerge = %q, want %q", cfg.WasmMerge, c.want)
			}
		})
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/regexped.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent config file, got nil")
	}
}

func TestPatternSelector_UnmarshalYAML_All(t *testing.T) {
	var s struct {
		P PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte("patterns: \"all\"\n"), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !s.P.All {
		t.Error("All=false, want true")
	}
	if len(s.P.Names) != 0 {
		t.Errorf("Names=%v, want empty", s.P.Names)
	}
}

func TestPatternSelector_UnmarshalYAML_List(t *testing.T) {
	var s struct {
		P PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte("patterns:\n  - rule_a\n  - rule_b\n"), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.P.All {
		t.Error("All=true, want false")
	}
	if len(s.P.Names) != 2 || s.P.Names[0] != "rule_a" || s.P.Names[1] != "rule_b" {
		t.Errorf("Names=%v, want [rule_a rule_b]", s.P.Names)
	}
}

func TestPatternSelector_UnmarshalYAML_Invalid(t *testing.T) {
	var s struct {
		P PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte("patterns: 42\n"), &s); err == nil {
		t.Error("expected error for invalid patterns value, got nil")
	}
}

func TestValidateSets_Valid(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p1", Pattern: "foo"}, {Name: "p2", Pattern: "bar"}},
		Sets: []SetConfig{
			{Name: "s1", ScanAny: "s1_any", Patterns: PatternSelector{All: true}},
			{Name: "s2", ScanAll: "s2_all", Patterns: PatternSelector{Names: []string{"p1"}}},
		},
	}
	if err := ValidateSets(cfg); err != nil {
		t.Errorf("ValidateSets valid config: %v", err)
	}
}

func TestValidateSets_DuplicateRegexName(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "dup", Pattern: "foo"}, {Name: "dup", Pattern: "bar"}},
		Sets:    []SetConfig{{Name: "s", ScanAny: "ma", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for duplicate regexp name, got nil")
	}
}

func TestValidateSets_DuplicateSetName(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets: []SetConfig{
			{Name: "same", ScanAny: "a", Patterns: PatternSelector{All: true}},
			{Name: "same", ScanAll: "b", Patterns: PatternSelector{All: true}},
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for duplicate set name, got nil")
	}
}

func TestValidateSets_UnknownPatternRef(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "known", Pattern: "foo"}},
		Sets:    []SetConfig{{Name: "s", ScanAny: "ma", Patterns: PatternSelector{Names: []string{"unknown"}}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for unknown pattern reference, got nil")
	}
}

func TestValidateSets_NoExportField(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets:    []SetConfig{{Name: "s", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for set with no export field, got nil")
	}
}

func TestValidateSets_MissingSetName(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets:    []SetConfig{{ScanAny: "ma", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for set with missing name, got nil")
	}
}

func TestValidateSets_EmptySets(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p", Pattern: "foo"}},
	}
	if err := ValidateSets(cfg); err != nil {
		t.Errorf("ValidateSets empty sets: %v", err)
	}
}

// homeJoin builds the expected result of expanding "~/<rel>". Skips nothing:
// os.UserHomeDir is always resolvable in the test environments this runs in,
// and ExpandHome's fallback (return unchanged) is covered by the "~alice" case.
func homeJoin(rel string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/" + rel
	}
	return filepath.Join(home, rel)
}

func TestExpandHome(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"~/x", homeJoin("x")},
		{"~", "~"},
		{"~alice/x", "~alice/x"},
		{"/abs/~/x", "/abs/~/x"},
		{"rel/path", "rel/path"},
	}
	for _, c := range cases {
		if got := ExpandHome(c.in); got != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveFilePath(t *testing.T) {
	base := "/home/user/project"
	cases := []struct {
		path string
		want string
	}{
		{"", ""},
		{"/absolute/path", "/absolute/path"},
		{"~/bin/tool", homeJoin("bin/tool")},
		{"~alice/bin/tool", "/home/user/project/~alice/bin/tool"},
		{"relative/file", "/home/user/project/relative/file"},
		{"bare.wasm", "/home/user/project/bare.wasm"},
	}
	for _, c := range cases {
		got := resolveFilePath(base, c.path)
		if got != c.want {
			t.Errorf("resolveFilePath(%q, %q) = %q, want %q", base, c.path, got, c.want)
		}
	}
}

func TestPatternSelector_UnmarshalYAML_InvalidString(t *testing.T) {
	var s struct {
		P PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte("patterns: \"some\"\n"), &s); err == nil {
		t.Error("expected error for scalar value other than \"all\", got nil")
	}
}

func TestPatternSelector_UnmarshalYAML_NonStringListItem(t *testing.T) {
	var s struct {
		P PatternSelector `yaml:"patterns"`
	}
	if err := yaml.Unmarshal([]byte("patterns:\n  - 42\n"), &s); err == nil {
		t.Error("expected error for non-string list item, got nil")
	}
}

func TestValidateSets_DuplicateRegexExportName(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{
			{Name: "p1", Pattern: "foo", MatchFunc: "dup"},
			{Name: "p2", Pattern: "bar", FindFunc: "dup"},
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected duplicate WASM export name error among regexps, got nil")
	}
}

func TestValidateSets_RegexSetExportCollision(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p1", Pattern: "foo", MatchFunc: "shared"}},
		Sets: []SetConfig{
			{Name: "s1", ScanAll: "shared", Patterns: PatternSelector{All: true}},
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected duplicate WASM export name error between regexp and set, got nil")
	}
}

func TestValidateSets_MissingPatternsField(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p1", Pattern: "foo"}},
		Sets: []SetConfig{
			{Name: "s1", ScanAny: "s1_any"}, // patterns omitted entirely
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected missing-patterns error, got nil")
	}
}

func TestValidateSets_DuplicatePatternInSet(t *testing.T) {
	cfg := &BuildConfig{
		Regexps: []RegexEntry{{Name: "p1", Pattern: "foo"}},
		Sets: []SetConfig{
			{Name: "s1", ScanAny: "s1_any", Patterns: PatternSelector{Names: []string{"p1", "p1"}}},
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected duplicate-pattern error, got nil")
	}
}

func TestValidHints(t *testing.T) {
	cases := []struct {
		hints []string
		want  bool
	}{
		{nil, true},
		{[]string{}, true},
		{[]string{"prefer-match"}, true},
		{[]string{"prefer-no-match"}, true},
		{[]string{"prefer-match", "prefer-no-match"}, false},
		{[]string{"bogus"}, false},
		// batch-find (task 44): valid alone and combined with either of the
		// other two, since it's orthogonal to the prefer-match/prefer-no-match
		// exclusion.
		{[]string{"batch-find"}, true},
		{[]string{"batch-find", "prefer-match"}, true},
		{[]string{"batch-find", "prefer-no-match"}, true},
		{[]string{"batch-find", "prefer-match", "prefer-no-match"}, false},
	}
	for _, c := range cases {
		if got := ValidHints(c.hints); got != c.want {
			t.Errorf("ValidHints(%v) = %v, want %v", c.hints, got, c.want)
		}
	}
}

// TestValidateHintList_BatchFindRejectedForSets verifies validateHintList's
// isSet parameter: "batch-find" is a load-time error on a sets: entry (sets
// have their own find_all batching), distinct from being merely unrecognised.
func TestValidateHintList_BatchFindRejectedForSets(t *testing.T) {
	if err := validateHintList([]string{"batch-find"}, false); err != nil {
		t.Errorf("validateHintList(batch-find, isSet=false) = %v, want nil", err)
	}
	err := validateHintList([]string{"batch-find"}, true)
	if err == nil {
		t.Fatal("validateHintList(batch-find, isSet=true) = nil, want error")
	}
	if got := err.Error(); got != `"batch-find" is not valid for sets` {
		t.Errorf("validateHintList(batch-find, isSet=true) error = %q, want the sets-specific message", got)
	}
}

func TestLoadConfig_HintsMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - pattern: 'foo'\n" +
		"    match_func: foo_match\n" +
		"    hints: [prefer-match, prefer-no-match]\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected error for mutually exclusive hints, got nil")
	}
}

func TestLoadConfig_HintsUnknownValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - pattern: 'foo'\n" +
		"    match_func: foo_match\n" +
		"    hints: [bogus]\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected error for unknown hint value, got nil")
	}
}

func TestLoadConfig_SetHintsMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - name: p1\n    pattern: 'foo'\n" +
		"sets:\n" +
		"  - name: s1\n" +
		"    find_any: any1\n" +
		"    patterns: \"all\"\n" +
		"    hints: [prefer-match, prefer-no-match]\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected error for mutually exclusive set hints, got nil")
	}
}

// TestLoadConfig_BatchFindInvalidForSets verifies "batch-find" (task 44) is a
// load-time error on a sets: entry — sets have their own find_all batching
// (batch_size) and don't wire up the per-pattern _batch export mechanism.
func TestLoadConfig_BatchFindInvalidForSets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - name: p1\n    pattern: 'foo'\n" +
		"sets:\n" +
		"  - name: s1\n" +
		"    find_any: any1\n" +
		"    patterns: \"all\"\n" +
		"    hints: [batch-find]\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected error for batch-find on a sets: entry, got nil")
	}
}

// TestLoadConfig_BatchFindValidForRegexps verifies "batch-find" loads cleanly
// on a regexps: entry, alone or combined with prefer-match/prefer-no-match.
func TestLoadConfig_BatchFindValidForRegexps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - pattern: 'foo'\n" +
		"    find_func: foo_find\n" +
		"    hints: [batch-find, prefer-match]\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Errorf("expected batch-find + prefer-match to load cleanly, got %v", err)
	}
}

func TestLoadConfig_ValidateSetsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	yamlData := "regexps:\n" +
		"  - name: p1\n    pattern: 'foo'\n" +
		"sets:\n" +
		"  - name: s1\n" +
		"    find_any: any1\n" +
		"    patterns:\n      - unknown_name\n"
	if err := os.WriteFile(path, []byte(yamlData), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Error("expected ValidateSets error to surface through LoadConfig, got nil")
	}
}

// ---------------------------------------------------------------------------
// plans/SETS.md S0: the seven-capability schema and strict parsing (§3.12,
// §3.19 / D5, D10/D11).

// writeCfg writes yaml to a temp regexped.yaml and returns its path.
func writeCfg(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig_RetiredSetKeysAreUnknownFields(t *testing.T) {
	// The retired keys are caught loudly by strict parsing rather than by a
	// targeted "renamed to" message (§3.19). The `match:` meaning change is
	// deliberately NOT catchable here — that lives in the migration notes.
	cases := []struct {
		name, key, yaml string
	}{
		{"find_all", "find_all", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find_all: sf\n    patterns: all\n"},
		{"find_any", "find_any", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find_any: sf\n    patterns: all\n"},
		{"batch_size", "batch_size", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find: sf\n    batch_size: 128\n    patterns: all\n"},
		{"typo", "mach_func", "regexps:\n  - pattern: 'foo'\n    mach_func: m\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadConfig(writeCfg(t, c.yaml))
			if err == nil {
				t.Fatalf("expected an unknown-field error naming %q", c.key)
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Fatalf("error should name the offending key %q, got: %v", c.key, err)
			}
		})
	}
}

func TestLoadConfig_OverlappingRoundTrips(t *testing.T) {
	base := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find: sf\n    patterns: all\n"
	cfg, err := LoadConfig(writeCfg(t, base))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Sets[0].Overlapping {
		t.Error("overlapping must default to false (the gated body is the default, D11)")
	}
	if !cfg.Sets[0].Gated() {
		t.Error("a set without overlapping: true is gated")
	}

	cfg, err = LoadConfig(writeCfg(t, base+"    overlapping: true\n"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Sets[0].Overlapping {
		t.Error("overlapping: true did not round-trip")
	}
	if cfg.Sets[0].Gated() {
		t.Error("overlapping: true selects the ungated body")
	}
}

func TestLoadConfig_OverlappingWithoutFindIsError(t *testing.T) {
	yaml := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    scan: sc\n    overlapping: true\n    patterns: all\n"
	_, err := LoadConfig(writeCfg(t, yaml))
	if err == nil {
		t.Fatal("overlapping on a set without find: must be a load error (§3.15)")
	}
	if !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("error should mention overlapping, got: %v", err)
	}
}

func TestSetCapabilities(t *testing.T) {
	s := SetConfig{
		Name: "s", Match: "m", MatchAny: "ma", MatchAll: "mall",
		Scan: "sc", ScanAny: "sa", ScanAll: "sall", Find: "f",
	}
	got := s.Capabilities()
	want := []string{"match", "match_any", "match_all", "scan", "scan_any", "scan_all", "find"}
	if len(got) != len(want) {
		t.Fatalf("Capabilities() returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Field != want[i] {
			t.Errorf("Capabilities()[%d].Field = %q, want %q", i, got[i].Field, want[i])
		}
	}
	if (SetConfig{}).HasExports() {
		t.Error("a set with no capability keys has no exports")
	}
}

func TestValidateSets_AllSevenCapabilityNamesValidated(t *testing.T) {
	// Every capability value goes through the identifier/reserved-word check,
	// exactly like the per-pattern _func fields.
	for _, key := range []string{"match", "match_any", "match_all", "scan", "scan_any", "scan_all", "find"} {
		t.Run(key, func(t *testing.T) {
			yaml := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    " + key + ": struct\n    patterns: all\n"
			_, err := LoadConfig(writeCfg(t, yaml))
			if err == nil {
				t.Fatalf("%s: a reserved word must be rejected as an export name", key)
			}
		})
	}
}

func TestValidateSets_NoCapabilityIsError(t *testing.T) {
	yaml := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    patterns: all\n"
	_, err := LoadConfig(writeCfg(t, yaml))
	if err == nil {
		t.Fatal("a set declaring no capability must be rejected")
	}
}
