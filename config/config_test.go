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

func TestEffectiveStubFile(t *testing.T) {
	cases := []struct {
		entry      RegexEntry
		globalStub string
		want       string
	}{
		{RegexEntry{StubFile: "local.rs"}, "global.rs", "local.rs"},
		{RegexEntry{}, "global.rs", "global.rs"},
		{RegexEntry{}, "", ""},
	}
	for _, c := range cases {
		if got := c.entry.EffectiveStubFile(c.globalStub); got != c.want {
			t.Errorf("EffectiveStubFile(%+v, %q) = %q, want %q", c.entry, c.globalStub, got, c.want)
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
