package generate

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

func TestIterTypeName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"find_it", "FindItIter"},
		{"foo", "FooIter"},
		{"find_github_token", "FindGithubTokenIter"},
		{"m", "MIter"},
	}
	for _, c := range cases {
		got := iterTypeName(c.input)
		if got != c.want {
			t.Errorf("iterTypeName(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestGenRustMatchStub(t *testing.T) {
	out := genRustMatchStub("mymod", "my_match")
	for _, sub := range []string{"\"mymod\"", "\"my_match\"", "ffi_my_match", "pub fn my_match"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genRustMatchStub: output missing %q", sub)
		}
	}
}

func TestGenRustFindIterStub(t *testing.T) {
	out := genRustFindIterStub("mymod", "find_tok")
	for _, sub := range []string{"\"mymod\"", "\"find_tok\"", "ffi_find_tok", "FindTokIter", "pub fn find_tok"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genRustFindIterStub: output missing %q", sub)
		}
	}
}

func TestGenRustGroupsIterStub(t *testing.T) {
	out := genRustGroupsIterStub("mymod", "grp", "grp", true, 3)
	for _, sub := range []string{"\"mymod\"", "GrpIter", "pub fn grp"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genRustGroupsIterStub: output missing %q", sub)
		}
	}
}

func TestGenRustNamedGroupsIterStub(t *testing.T) {
	named := map[string]int{"x": 1, "y": 2}
	out := genRustNamedGroupsIterStub("mymod", "ng", "ng", true, 3, named)
	for _, sub := range []string{"\"mymod\"", "NgIter", "pub fn ng", "HashMap"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genRustNamedGroupsIterStub: output missing %q", sub)
		}
	}
}

func TestExtractGroupInfo(t *testing.T) {
	cases := []struct {
		pattern    string
		wantGroups int
		wantNamed  map[string]int
	}{
		{"(a)(b)", 3, map[string]int{}},
		{"(?P<x>a)(?P<y>b)", 3, map[string]int{"x": 1, "y": 2}},
		{"abc", 1, map[string]int{}},
	}
	for _, c := range cases {
		numGroups, named, err := extractGroupInfo(c.pattern)
		if err != nil {
			t.Errorf("extractGroupInfo(%q): %v", c.pattern, err)
			continue
		}
		if numGroups != c.wantGroups {
			t.Errorf("extractGroupInfo(%q) numGroups = %d, want %d", c.pattern, numGroups, c.wantGroups)
		}
		for k, v := range c.wantNamed {
			if named[k] != v {
				t.Errorf("extractGroupInfo(%q) named[%q] = %d, want %d", c.pattern, k, named[k], v)
			}
		}
	}
}

func TestGenRustStubFileSingle(t *testing.T) {
	entries := []config.RegexEntry{
		{MatchFunc: "url_match"},
	}
	out, err := genRustStubFile(entries, "url")
	if err != nil {
		t.Fatalf("genRustStubFile: %v", err)
	}
	if !strings.Contains(out, "Auto-generated") {
		t.Error("genRustStubFile: missing header comment")
	}
	if !strings.Contains(out, "url_match") {
		t.Error("genRustStubFile: missing function name")
	}
	if !strings.Contains(out, "pub mod url") {
		t.Error("genRustStubFile: missing pub mod block")
	}
}

func TestGenRustStubFileMultiple(t *testing.T) {
	entries := []config.RegexEntry{
		{MatchFunc: "url_match"},
		{FindFunc: "tok_find"},
	}
	out, err := genRustStubFile(entries, "mymod")
	if err != nil {
		t.Fatalf("genRustStubFile: %v", err)
	}
	if !strings.Contains(out, "pub mod mymod") {
		t.Error("genRustStubFile: missing pub mod block")
	}
	if !strings.Contains(out, "url_match") {
		t.Error("genRustStubFile: missing url_match")
	}
	if !strings.Contains(out, "tok_find") {
		t.Error("genRustStubFile: missing tok_find")
	}
}

func TestGenJSStubFile(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regex.js",
		Regexes: []config.RegexEntry{
			{MatchFunc: "url_match", FindFunc: "url_find"},
			{GroupsFunc: "tok_groups", NamedGroupsFunc: "tok_named", Pattern: "(a)(b)"},
		},
	}
	out, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("genJSStubFile: %v", err)
	}
	for _, sub := range []string{
		"url_match", "url_find",
		"tok_groups", "tok_named",
		"export async function init", "WebAssembly.instantiate", "_SLOTS",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSStubFile: output missing %q", sub)
		}
	}
}

func TestGenTSStubFile(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regex.ts",
		Regexes: []config.RegexEntry{
			{MatchFunc: "url_match", FindFunc: "url_find"},
			{GroupsFunc: "tok_groups", NamedGroupsFunc: "tok_named", Pattern: "(a)(b)"},
		},
	}
	out, err := genTSStubFile(cfg)
	if err != nil {
		t.Fatalf("genTSStubFile: %v", err)
	}
	for _, sub := range []string{
		"url_match", "url_find",
		"tok_groups", "tok_named",
		"export async function init", "Promise<void>",
		"WebAssembly.Module", "WebAssembly.instantiate",
		"Generator<[number, number]>",
		"Generator<Record<string, [number, number]>>",
		"_SLOTS",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSStubFile: output missing %q", sub)
		}
	}
}

func TestResolveStubType(t *testing.T) {
	cases := []struct {
		cfg     config.BuildConfig
		want    string
		wantErr bool
	}{
		{config.BuildConfig{StubType: "rust"}, "rust", false},
		{config.BuildConfig{StubType: "js"}, "js", false},
		{config.BuildConfig{StubType: "ts"}, "ts", false},
		{config.BuildConfig{StubType: "invalid"}, "", true},
		{config.BuildConfig{StubFile: "out.rs"}, "rust", false},
		{config.BuildConfig{StubFile: "out.js"}, "js", false},
		{config.BuildConfig{StubFile: "out.ts"}, "ts", false},
		{config.BuildConfig{StubFile: "out.wasm"}, "", true},
		{config.BuildConfig{}, "", true},
	}
	for _, c := range cases {
		got, err := ResolveStubType(c.cfg)
		if c.wantErr {
			if err == nil {
				t.Errorf("ResolveStubType(%+v): expected error, got %q", c.cfg, got)
			}
		} else {
			if err != nil {
				t.Errorf("ResolveStubType(%+v): unexpected error: %v", c.cfg, err)
			} else if got != c.want {
				t.Errorf("ResolveStubType(%+v) = %q, want %q", c.cfg, got, c.want)
			}
		}
	}
}
