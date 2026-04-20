package config

import (
	"os"
	"path/filepath"
	"testing"
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
