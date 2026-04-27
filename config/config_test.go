package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
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
	yaml := "regexes:\n  - pattern: 'foo'\n    match_func: foo_match\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Regexes) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cfg.Regexes))
	}
	if cfg.Regexes[0].MatchFunc != "foo_match" {
		t.Errorf("MatchFunc = %q, want foo_match", cfg.Regexes[0].MatchFunc)
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
		t.Fatal("expected error for config with no regexes, got nil")
	}
}

func TestLoadConfigPathResolution(t *testing.T) {
	dir := t.TempDir()
	yaml := "wasm_file: regexps.wasm\nstub_file: src/stub.rs\noutput: final.wasm\nregexes:\n  - pattern: 'foo'\n    match_func: foo_match\n"
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
		{"home relative", "~/bin/wasm-merge", "~/bin/wasm-merge"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := "wasm_merge: " + c.wasmMerge + "\nregexes:\n  - pattern: 'foo'\n    match_func: foo_match\n"
			if c.wasmMerge == "" {
				yaml = "regexes:\n  - pattern: 'foo'\n    match_func: foo_match\n"
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
		Regexes: []RegexEntry{{Name: "p1", Pattern: "foo"}, {Name: "p2", Pattern: "bar"}},
		Sets: []SetConfig{
			{Name: "s1", FindAny: "s1_any", Patterns: PatternSelector{All: true}},
			{Name: "s2", FindAll: "s2_all", Patterns: PatternSelector{Names: []string{"p1"}}},
		},
	}
	if err := ValidateSets(cfg); err != nil {
		t.Errorf("ValidateSets valid config: %v", err)
	}
}

func TestValidateSets_DuplicateRegexName(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "dup", Pattern: "foo"}, {Name: "dup", Pattern: "bar"}},
		Sets:    []SetConfig{{Name: "s", FindAny: "ma", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for duplicate regex name, got nil")
	}
}

func TestValidateSets_DuplicateSetName(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets: []SetConfig{
			{Name: "same", FindAny: "a", Patterns: PatternSelector{All: true}},
			{Name: "same", FindAll: "b", Patterns: PatternSelector{All: true}},
		},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for duplicate set name, got nil")
	}
}

func TestValidateSets_UnknownPatternRef(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "known", Pattern: "foo"}},
		Sets:    []SetConfig{{Name: "s", FindAny: "ma", Patterns: PatternSelector{Names: []string{"unknown"}}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for unknown pattern reference, got nil")
	}
}

func TestValidateSets_NoExportField(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets:    []SetConfig{{Name: "s", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for set with no export field, got nil")
	}
}

func TestValidateSets_MissingSetName(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "p", Pattern: "foo"}},
		Sets:    []SetConfig{{FindAny: "ma", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateSets(cfg); err == nil {
		t.Error("expected error for set with missing name, got nil")
	}
}

func TestValidateSets_EmptySets(t *testing.T) {
	cfg := &BuildConfig{
		Regexes: []RegexEntry{{Name: "p", Pattern: "foo"}},
	}
	if err := ValidateSets(cfg); err != nil {
		t.Errorf("ValidateSets empty sets: %v", err)
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
		{"~/bin/tool", "~/bin/tool"},
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
