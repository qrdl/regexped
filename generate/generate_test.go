package generate

import (
	"os"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// readFile is a small helper used by TestCmdDummyMain.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

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

func TestGroupByStubFile(t *testing.T) {
	cfg := config.BuildConfig{
		StubFile: "stubs.rs",
		Regexes: []config.RegexEntry{
			{ImportModule: "a", MatchFunc: "m1", StubFile: "a.rs"},
			{ImportModule: "b", MatchFunc: "m2"},
			{ImportModule: "c", MatchFunc: "m3"},
		},
	}
	groups := groupByStubFile(cfg)
	if len(groups["a.rs"]) != 1 {
		t.Errorf("groupByStubFile: a.rs has %d entries, want 1", len(groups["a.rs"]))
	}
	if len(groups["stubs.rs"]) != 2 {
		t.Errorf("groupByStubFile: stubs.rs has %d entries, want 2", len(groups["stubs.rs"]))
	}
	// Entry with no stub_file and no global stub_file should not appear.
	cfg2 := config.BuildConfig{
		Regexes: []config.RegexEntry{
			{ImportModule: "x", MatchFunc: "m"},
		},
	}
	g2 := groupByStubFile(cfg2)
	if len(g2) != 0 {
		t.Errorf("groupByStubFile: expected empty map, got %d entries", len(g2))
	}
}

func TestGenRustStubFileSingle(t *testing.T) {
	entries := []config.RegexEntry{
		{ImportModule: "url", MatchFunc: "url_match"},
	}
	out, err := genRustStubFile(entries)
	if err != nil {
		t.Fatalf("genRustStubFile: %v", err)
	}
	if !strings.Contains(out, "Auto-generated") {
		t.Error("genRustStubFile: missing header comment")
	}
	if !strings.Contains(out, "url_match") {
		t.Error("genRustStubFile: missing function name")
	}
	if strings.Contains(out, "pub mod") {
		t.Error("genRustStubFile: unexpected pub mod for single entry")
	}
}

func TestGenRustStubFileMultiple(t *testing.T) {
	entries := []config.RegexEntry{
		{ImportModule: "url", MatchFunc: "url_match"},
		{ImportModule: "tok", FindFunc: "tok_find"},
	}
	out, err := genRustStubFile(entries)
	if err != nil {
		t.Fatalf("genRustStubFile: %v", err)
	}
	if !strings.Contains(out, "pub mod url") {
		t.Error("genRustStubFile: missing pub mod url")
	}
	if !strings.Contains(out, "pub mod tok") {
		t.Error("genRustStubFile: missing pub mod tok")
	}
}

func TestGenJSStubFile(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regex.js",
		Regexes: []config.RegexEntry{
			{ImportModule: "url", MatchFunc: "url_match", FindFunc: "url_find"},
			{ImportModule: "tok", GroupsFunc: "tok_groups", NamedGroupsFunc: "tok_named"},
		},
	}
	out, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("genJSStubFile: %v", err)
	}
	for _, sub := range []string{
		"merged.wasm", "url_match", "url_find",
		"tok_groups", "tok_named",
		"WebAssembly.instantiateStreaming", "_SLOTS",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSStubFile: output missing %q", sub)
		}
	}
}

func TestCmdDummyMain(t *testing.T) {
	dir := t.TempDir()
	if err := CmdDummyMain(dir, ""); err != nil {
		t.Fatalf("CmdDummyMain: %v", err)
	}
	data, err := readFile(dir + "/main.wasm")
	if err != nil {
		t.Fatalf("reading main.wasm: %v", err)
	}
	if len(data) < 4 || string(data[:4]) != "\x00asm" {
		t.Errorf("CmdDummyMain: output is not valid WASM")
	}
}
