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
		// batch-find: valid alone and combined with either of the
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

// TestBatchFindOnSets covers the hint's history: "batch-find" USED TO
// BE a load-time error on a sets: entry and is now how a set asks for batching
// at all, replacing the retired `find_batch:` key. It still requires `find` on
// the same set — with nothing to batch, silently ignoring it would leave the
// caller believing they had asked for something.
func TestBatchFindOnSets(t *testing.T) {
	if err := validateHintList([]string{"batch-find"}); err != nil {
		t.Errorf("validateHintList(batch-find) = %v, want nil", err)
	}
	withFind := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n" +
		"  - name: s\n    find: sf\n    hints: [batch-find]\n    patterns: all\n"
	cfg, err := LoadConfig(writeCfg(t, withFind))
	if err != nil {
		t.Fatalf("batch-find with find: %v", err)
	}
	if !cfg.Sets[0].BatchFind() {
		t.Error("BatchFind() = false on a set with find: and hints: [batch-find]")
	}
	noFind := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n" +
		"  - name: s\n    scan_any: sa\n    hints: [batch-find]\n    patterns: all\n"
	if _, err := LoadConfig(writeCfg(t, noFind)); err == nil {
		t.Error("batch-find without find: expected an error")
	} else if !strings.Contains(err.Error(), "batch-find") {
		t.Errorf("error should name the hint, got: %v", err)
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

// TestLoadConfig_BatchFindInvalidForSets verifies "batch-find" is a
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
// The seven-capability schema and strict parsing (
// the capability grid).

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
	// targeted "renamed to" message. The `match:` meaning change is
	// deliberately NOT catchable here — that lives in the migration notes.
	cases := []struct {
		name, key, yaml string
	}{
		{"find_all", "find_all", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find_all: sf\n    patterns: all\n"},
		{"find_any", "find_any", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find_any: sf\n    patterns: all\n"},
		{"batch_size", "batch_size", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find: sf\n    batch_size: 128\n    patterns: all\n"},
		// Retired keys: `match:` and `scan:` and
		// `find_batch:` (decision (11)). Dropping the KEYS rather than
		// repurposing them is the point — a surviving `match:` with match_any
		// semantics would leave every existing config compiling while its
		// callers silently switched from reading 0/1 to reading an id.
		{"match", "match", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    match: sm\n    patterns: all\n"},
		{"scan", "scan", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    scan: ss\n    patterns: all\n"},
		{"find_batch", "find_batch", "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    find_batch: fb\n    patterns: all\n"},
		// Retired. It was never a separate capability — both
		// stubs called the SAME WASM export — so `groups_func` plus the
		// generated name→index constants replaces it, and C and AS gain named
		// access they never had.
		{"named_groups_func", "named_groups_func", "regexps:\n  - pattern: '(?P<a>x)'\n    named_groups_func: ng\n"},
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
		t.Error("overlapping must default to false (the gated body is the default)")
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

// TestLoadConfig_OverlappingWithoutFindIsIgnored: `overlapping` selects
// between two find bodies. On a set declaring neither `find` nor `find_batch`
// there is no body to select, so the key has no effect and is accepted rather
// than rejected — a harmless key should not be a build failure.
func TestLoadConfig_OverlappingWithoutFindIsIgnored(t *testing.T) {
	yaml := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    scan_any: sc\n    overlapping: true\n    patterns: all\n"
	cfg, err := LoadConfig(writeCfg(t, yaml))
	if err != nil {
		t.Fatalf("overlapping without find must be ignored, got error: %v", err)
	}
	if cfg.Sets[0].Gated() {
		t.Error("a set with no find capability gates nothing")
	}
	if cfg.Sets[0].HasFind() {
		t.Error("HasFind must be false for a scan-only set")
	}
}

// TestLoadConfig_BatchFindIsNotACapability: batching
// batching is a property of `find`, not a capability of its own. A batch-only
// set — legal until then — no longer exists, and asking for batching adds
// nothing to Capabilities().
func TestLoadConfig_BatchFindIsNotACapability(t *testing.T) {
	yaml := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n" +
		"  - name: s\n    find: fb\n    hints: [batch-find]\n    patterns: all\n"
	cfg, err := LoadConfig(writeCfg(t, yaml))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Sets[0].HasFind() || !cfg.Sets[0].Gated() {
		t.Error("a find set is gated by default")
	}
	caps := cfg.Sets[0].Capabilities()
	if len(caps) != 1 || caps[0].Field != "find" || caps[0].Name != "fb" {
		t.Errorf("batching must not appear as a capability: %+v", caps)
	}
}

// TestLoadConfig_BatchNameCollision: a set's `find` synthesizes <find>_batch
// under `hints: [batch-find]`, exactly as a pattern's find_func does, so no
// capability may be NAMED into that space and no two owners may claim the same
// synthesized name. Reserved whether or not the hint is present today —
// otherwise adding the hint to a working config would turn a valid export into
// a duplicate.
func TestLoadConfig_BatchNameCollision(t *testing.T) {
	ending := "regexps:\n  - name: p\n    pattern: 'foo'\nsets:\n" +
		"  - name: s\n    find: my_batch\n    patterns: all\n"
	if _, err := LoadConfig(writeCfg(t, ending)); err == nil {
		t.Fatal("a set capability ending in _batch must be rejected")
	}
	collide := "regexps:\n  - name: p\n    pattern: 'foo'\n    find_func: ff\nsets:\n" +
		"  - name: s\n    scan_any: ff_batch\n    patterns: all\n"
	if _, err := LoadConfig(writeCfg(t, collide)); err == nil {
		t.Fatal("a set capability claiming a pattern's synthesized batch name must be rejected")
	}
	ok := "regexps:\n  - name: p\n    pattern: 'foo'\n    find_func: ff\nsets:\n" +
		"  - name: s\n    find: set_find\n    hints: [batch-find]\n    patterns: all\n"
	if _, err := LoadConfig(writeCfg(t, ok)); err != nil {
		t.Fatalf("a non-colliding batching set must be accepted, got: %v", err)
	}
}

func TestSetCapabilities(t *testing.T) {
	s := SetConfig{
		Name: "s", MatchAny: "ma", MatchAll: "mall",
		ScanAny: "sa", ScanAll: "sall", Find: "f",
	}
	got := s.Capabilities()
	want := []string{"match_any", "match_all", "scan_any", "scan_all", "find"}
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

func TestValidateSets_AllCapabilityNamesValidated(t *testing.T) {
	// Every capability value goes through the identifier/reserved-word check,
	// exactly like the per-pattern _func fields.
	for _, key := range []string{"match_any", "match_all", "scan_any", "scan_all", "find"} {
		t.Run(key, func(t *testing.T) {
			// A Go stub, so `struct` is reserved in the generated language.
			yaml := "stub_file: x.go\nregexps:\n  - name: p\n    pattern: 'foo'\nsets:\n  - name: s\n    " + key + ": struct\n    patterns: all\n"
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

// TestLoadConfigRetiredToolKeys: `wasm_merge:`, `wasm_tools:` and `wac:` are
// retired. Strict YAML makes each a line-numbered unknown-field error naming it.
func TestLoadConfigRetiredToolKeys(t *testing.T) {
	for _, key := range []string{"wasm_merge", "wasm_tools", "wac"} {
		_, err := LoadConfig(writeCfg(t, key+": x\nregexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"))
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: err = %v, want an unknown-field error naming it", key, err)
		}
	}
}

// TestLoadConfigToolPathKeys pins how a tool path key resolves at load: an
// absolute value as is, `~` and `~/dir` against the home directory, and anything
// else against the CONFIG FILE's directory — not the working directory, which is
// why the load runs from somewhere else. `~user` is not expanded: it is taken
// literally, as a relative path. The value as written is kept for messages.
func TestLoadConfigToolPathKeys(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory:", err)
	}
	dir := t.TempDir()
	t.Chdir(t.TempDir())
	for _, key := range []string{"wasm_merge_path", "wasm_tools_path", "wac_path"} {
		for _, c := range []struct{ value, want string }{
			{"/usr/local/bin", "/usr/local/bin"},
			{"/usr/local/bin/wasm-merge-118", "/usr/local/bin/wasm-merge-118"},
			{"tools", filepath.Join(dir, "tools")},
			{"~", home},
			{"~/bin", filepath.Join(home, "bin")},
			{"~bob/bin", filepath.Join(dir, "~bob/bin")},
		} {
			path := filepath.Join(dir, "regexped.yaml")
			yaml := key + ": '" + c.value + "'\nregexps:\n  - pattern: 'foo'\n    match_func: foo_match\n"
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("%s %q: %v", key, c.value, err)
			}
			got := map[string]string{
				"wasm_merge_path": cfg.WasmMergePath,
				"wasm_tools_path": cfg.WasmToolsPath,
				"wac_path":        cfg.WacPath,
			}[key]
			if got != c.want {
				t.Errorf("%s %q resolved to %q, want %q", key, c.value, got, c.want)
			}
			if w := cfg.ToolPathAsWritten(key); w != c.value {
				t.Errorf("%s %q: value as written = %q", key, c.value, w)
			}
		}
	}
}

// LoadConfig's REFUSALS.
//
// This is the CLI's front door, and every one of these errors is the last
// chance to tell a user something useful. A config that loads and then
// produces a stub which will not compile — a reserved word as a function name,
// a hint the compiler does not know, a set naming a pattern that is not there
// — costs far more to diagnose downstream than at the point of reading the
// file.

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "regexped.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"unparseable YAML",
			"regexps: [oh dear\n",
			"",
		},
		{
			"a reserved word as a function name",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: match\n",
			"",
		},
		{
			"a function name that is not an identifier",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: 'my func'\n",
			"",
		},
		{
			"a set naming a pattern that does not exist",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find: f\n    patterns: [nope]\n",
			"",
		},
		{
			"a set with no patterns key",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find: f\n",
			"patterns",
		},
		{
			"an unknown hint",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: m\n    hints: [go-faster]\n",
			"",
		},
		{
			"two sets exporting the same name",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n" +
				"  - name: s1\n    find: dup\n    patterns: all\n" +
				"  - name: s2\n    find: dup\n    patterns: all\n",
			"",
		},
		{
			"a retired key: named_groups_func",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: '(a)'\n    named_groups_func: g\n",
			"",
		},
		{
			"a retired key: find_batch",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find_batch: fb\n    patterns: all\n",
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := func() error {
				_, err := LoadConfig(writeConfig(t, c.body))
				return err
			}()
			if err == nil {
				t.Fatal("accepted a config that should have been refused")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestLoadConfigMissingFile: the path the CLI hands over may simply not exist.
func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("accepted a config path that does not exist")
	}
}

// TestLoadConfigAccepts is the other half: a config exercising the keys the
// refusals above are about must load cleanly, or the checks are simply
// rejecting everything.
func TestLoadConfigAccepts(t *testing.T) {
	path := writeConfig(t, `
wasm_file: out.wasm
stub_file: stubs.rs
import_module: demo
max_dfa_states: 2048
max_tdfa_regs: 48
max_fallback_states: 512
regexps:
  - name: url
    pattern: '(?P<scheme>https?)://(?P<host>[a-z.]+)'
    match_func: url_match
    find_func: url_find
    groups_func: url_groups
    hints: [prefer-match]
  - name: num
    pattern: '[0-9]+'
sets:
  - name: secrets
    match_any: which_secret
    match_all: all_kinds
    scan_any: first_secret
    scan_all: kinds
    find: scan_secrets
    overlapping: true
    hints: [batch-find]
    patterns: all
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	if len(cfg.Regexps) != 2 || len(cfg.Sets) != 1 {
		t.Fatalf("loaded %d regexps and %d sets, want 2 and 1", len(cfg.Regexps), len(cfg.Sets))
	}
	if cfg.MaxDFAStates != 2048 || cfg.MaxTDFARegs != 48 || cfg.MaxFallbackStates != 512 {
		t.Errorf("the numeric limits did not survive loading: %+v", cfg)
	}
	if !cfg.Sets[0].Overlapping || !cfg.Sets[0].BatchFind() {
		t.Error("overlapping / batch-find did not survive loading")
	}
	if !cfg.Sets[0].Patterns.All {
		t.Error("`patterns: all` did not survive loading")
	}
}

// TestPatternSelectorForms covers the selector's two YAML shapes — the scalar
// "all" and a list of names — through the unmarshaller rather than by
// constructing the struct, since the unmarshaller is what a user's file meets.
func TestPatternSelectorForms(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
stub_file: s.rs
regexps:
  - name: a
    pattern: 'a'
  - name: b
    pattern: 'b'
sets:
  - name: s1
    find: f1
    patterns: all
  - name: s2
    find: f2
    patterns: [a]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Sets[0].Patterns.All {
		t.Error("`patterns: all` did not parse as the All form")
	}
	if cfg.Sets[1].Patterns.All || len(cfg.Sets[1].Patterns.Names) != 1 {
		t.Errorf("a name list parsed as %+v", cfg.Sets[1].Patterns)
	}
}

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
// at load rather than only at `generate`.
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
// "batch-find needs something to batch" rule: the per-regexp one is new,
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
// only in-package caller when the dead `_batch` reservation was removed.
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
// charset rule: `name:` reaches generated source as a %q string literal,
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
// iterator-type check: AS Pascal-cases its iterator name, so the
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

// TestToolPathAsWrittenUnknownKey covers ToolPathAsWritten's fallthrough: a key
// that is not one of the three tool-path keys has no path to report.
func TestToolPathAsWrittenUnknownKey(t *testing.T) {
	cfg := BuildConfig{WasmMergePath: "a", WasmToolsPath: "b", WacPath: "c"}
	for _, key := range []string{"wasm_merge_path", "wasm_tools_path", "wac_path"} {
		if cfg.ToolPathAsWritten(key) == "" {
			t.Errorf("ToolPathAsWritten(%q) = \"\", want the configured path", key)
		}
	}
	for _, key := range []string{"", "stub_file", "wasm_merge", "WAC_PATH"} {
		if got := cfg.ToolPathAsWritten(key); got != "" {
			t.Errorf("ToolPathAsWritten(%q) = %q, want \"\"", key, got)
		}
	}
}

// TestResolveToolPathTildeWithoutHome covers resolveToolPath's fallback for a
// bare `~` when the home directory cannot be determined: the value is left
// exactly as written rather than resolved to something wrong.
//
// os.UserHomeDir reports an error on Unix when $HOME is empty, which is what
// t.Setenv arranges here (and undoes when the test ends).

// TestResolveToolPathTildeWithoutHome covers resolveToolPath's fallback for a
// bare `~` when the home directory cannot be determined: the value is left
// exactly as written rather than resolved to something wrong.
//
// os.UserHomeDir reports an error on Unix when $HOME is empty, which is what
// t.Setenv arranges here (and undoes when the test ends).
func TestResolveToolPathTildeWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	if got := resolveToolPath("/base", "~"); got != "~" {
		t.Errorf("resolveToolPath(\"~\") with no home = %q, want %q", got, "~")
	}
}

// TestValidateConfigRejectsMalformedSetCapabilityName covers the set half of
// ValidateConfig's shape check. The existing tests give a set a RESERVED word,
// which fails later on, in the per-language pass; this one gives it a name that
// is not an identifier at all, which is the earlier check.

// TestWitWorldNameDefaultFailures covers the two arms WitWorldName takes when
// wit_world is UNSET and so defaults to the package name: the package name
// being invalid, and the package name colliding with an interface the package
// itself defines.
func TestWitWorldNameDefaultFailures(t *testing.T) {
	t.Run("invalid_package", func(t *testing.T) {
		cfg := BuildConfig{WitPackage: "Not A Package"}
		_, err := cfg.WitWorldName()
		if err == nil {
			t.Fatal("WitWorldName = nil error, want the package name's error")
		}
		if !strings.Contains(err.Error(), "wit_package") {
			t.Errorf("error does not come from the package name: %v", err)
		}
	})
	for _, name := range []string{"matcher", "sets"} {
		t.Run("defaults_to_"+name, func(t *testing.T) {
			cfg := BuildConfig{WitPackage: name}
			_, err := cfg.WitWorldName()
			if err == nil {
				t.Fatalf("WitWorldName with wit_package %q = nil error, want a collision error", name)
			}
			if !strings.Contains(err.Error(), "set wit_world") {
				t.Errorf("error does not tell the user to set wit_world: %v", err)
			}
		})
	}
}
