package generate

import (
	"os"
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

func TestGoPublicName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"url_match", "UrlMatch"},
		{"find_github_token", "FindGithubToken"},
		{"m", "M"},
		{"foo", "Foo"},
	}
	for _, c := range cases {
		got := goPublicName(c.input)
		if got != c.want {
			t.Errorf("goPublicName(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestGenGoMatchStub(t *testing.T) {
	out := genGoMatchStub("url", "url_match")
	for _, sub := range []string{
		"//go:wasmimport url url_match",
		"ffi_url_match",
		"func UrlMatch(input []byte) (int, bool)",
		"unsafe.Pointer",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoMatchStub: output missing %q", sub)
		}
	}
}

func TestGenGoFindStub(t *testing.T) {
	out := genGoFindStub("url", "url_find")
	for _, sub := range []string{
		"//go:wasmimport url url_find",
		"ffi_url_find",
		"func UrlFind(input []byte) iter.Seq2[int, int]",
		"uint64(r)>>32",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoFindStub: output missing %q", sub)
		}
	}
}

func TestGenGoGroupsStub(t *testing.T) {
	out := genGoGroupsStub("url", "url_groups", "url_groups", true, 3)
	for _, sub := range []string{
		"//go:wasmimport url url_groups",
		"ffi_url_groups",
		"func UrlGroups(input []byte) iter.Seq[[][]int]",
		"make([]int32, 6)",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoGroupsStub: output missing %q", sub)
		}
	}
}

func TestGenGoNamedGroupsStub(t *testing.T) {
	named := map[string]int{"scheme": 1, "host": 2}
	out := genGoNamedGroupsStub("url", "url_named_groups", "url_groups", false, 3, named)
	for _, sub := range []string{
		"func UrlNamedGroups(input []byte) iter.Seq[map[string][]int]",
		`named["scheme"]`,
		`named["host"]`,
		"ffi_url_groups",
		"make([]int32, 6)",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoNamedGroupsStub: output missing %q", sub)
		}
	}
	// declareFFI=false: no wasmimport block expected
	if strings.Contains(out, "//go:wasmimport") {
		t.Error("genGoNamedGroupsStub: unexpected //go:wasmimport when declareFFI=false")
	}
}

func TestGenGoStubFileMatchOnly(t *testing.T) {
	entries := []config.RegexEntry{
		{MatchFunc: "url_match"},
	}
	out, err := genGoStubFile(entries, "url", "url")
	if err != nil {
		t.Fatalf("genGoStubFile: %v", err)
	}
	for _, sub := range []string{
		"//go:build wasip1",
		"package url",
		`import "unsafe"`,
		"url_match",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoStubFile match-only: missing %q", sub)
		}
	}
	if strings.Contains(out, `"iter"`) {
		t.Error("genGoStubFile match-only: should not import iter")
	}
}

func TestGenGoStubFileFull(t *testing.T) {
	entries := []config.RegexEntry{
		{MatchFunc: "url_match", FindFunc: "url_find",
			GroupsFunc: "url_groups", NamedGroupsFunc: "url_named",
			Pattern: "(?P<scheme>https?)://(?P<host>[^/]+)"},
	}
	out, err := genGoStubFile(entries, "url", "url")
	if err != nil {
		t.Fatalf("genGoStubFile: %v", err)
	}
	for _, sub := range []string{
		"//go:build wasip1",
		"package url",
		`"iter"`,
		`"unsafe"`,
		"url_match", "url_find", "url_groups", "UrlNamed",
		"iter.Seq2[int, int]",
		"iter.Seq[[][]int]",
		"iter.Seq[map[string][]int]",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoStubFile full: missing %q", sub)
		}
	}
}

func TestGenRustStubFileGroupsAndNamed(t *testing.T) {
	entries := []config.RegexEntry{{
		GroupsFunc:      "url_groups",
		NamedGroupsFunc: "url_named",
		Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
	}}
	out, err := genRustStubFile(entries, "url")
	if err != nil {
		t.Fatalf("genRustStubFile groups+named: %v", err)
	}
	// FFI block emitted only once (for groups_func); named_groups_func shares it.
	if count := strings.Count(out, `#[link(wasm_import_module = "url")]`); count != 1 {
		t.Errorf("genRustStubFile groups+named: want 1 FFI block, got %d", count)
	}
	if !strings.Contains(out, "UrlGroupsIter") {
		t.Error("missing UrlGroupsIter")
	}
	if !strings.Contains(out, "UrlNamedIter") {
		t.Error("missing UrlNamedIter")
	}
}

func TestGenRustStubFileNamedOnly(t *testing.T) {
	entries := []config.RegexEntry{{
		NamedGroupsFunc: "url_named",
		Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
	}}
	out, err := genRustStubFile(entries, "url")
	if err != nil {
		t.Fatalf("genRustStubFile named-only: %v", err)
	}
	if !strings.Contains(out, `#[link(wasm_import_module = "url")]`) {
		t.Error("genRustStubFile named-only: missing FFI block")
	}
	if !strings.Contains(out, "UrlNamedIter") {
		t.Error("missing UrlNamedIter")
	}
}

func TestGenRustStubFileNoFuncs(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: "something"}}
	out, err := genRustStubFile(entries, "url")
	if err != nil {
		t.Fatalf("genRustStubFile no-funcs: %v", err)
	}
	if out != "" {
		t.Errorf("genRustStubFile no-funcs: expected empty output, got %q", out)
	}
}

func TestGenCMatchParts(t *testing.T) {
	h := genCMatchHPart("my_match")
	c := genCMatchCPart("mymod", "my_match")
	for _, sub := range []string{"int my_match", "anchored match"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCMatchHPart: output missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("my_match")`,
		"_ffi_my_match", "int my_match",
	} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCMatchCPart: output missing %q", sub)
		}
	}
}

func TestGenCFindParts(t *testing.T) {
	h := genCFindHPart("tok_find")
	c := genCFindCPart("mymod", "tok_find")
	for _, sub := range []string{"rx_match_t tok_find", "offset"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCFindHPart: output missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("tok_find")`,
		"_ffi_tok_find", "rx_match_t tok_find",
		"unsigned long long", "0xFFFFFFFFU",
	} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCFindCPart: output missing %q", sub)
		}
	}
}

func TestGenCGroupsStubParts(t *testing.T) {
	named := map[string]int{"scheme": 1, "host": 2}
	h, c := genCGroupsStubParts("mymod", "parse_url", "parse_url", 3, named)
	for _, sub := range []string{
		"PARSE_URL_GROUP_SCHEME", "PARSE_URL_GROUP_HOST",
		"PARSE_URL_GROUPS", "const rx_group_t *parse_url",
	} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCGroupsStubParts h: missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("parse_url")`,
		"_ffi_parse_url", "PARSE_URL_GROUP_SCHEME",
		"const rx_group_t *parse_url",
	} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCGroupsStubParts c: missing %q", sub)
		}
	}
}

func TestGenCStubFilesFind(t *testing.T) {
	entries := []config.RegexEntry{{FindFunc: "tok_find"}}
	h, c, err := genCStubFiles(entries, "mymod", "stub.h")
	if err != nil {
		t.Fatalf("genCStubFiles find: %v", err)
	}
	for _, sub := range []string{"#pragma once", "rx_match_t", "tok_find"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCStubFiles find h: missing %q", sub)
		}
	}
	for _, sub := range []string{`#include "stub.h"`, "_ffi_tok_find", "rx_match_t tok_find"} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCStubFiles find c: missing %q", sub)
		}
	}
}

func TestGenCStubFilesGroupsAndNamed(t *testing.T) {
	// named_groups_func is not supported for C stubs — must return an error.
	entries := []config.RegexEntry{{
		GroupsFunc:      "url_groups",
		NamedGroupsFunc: "url_named",
		Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
	}}
	_, _, err := genCStubFiles(entries, "mymod", "stub.h")
	if err == nil {
		t.Fatal("genCStubFiles groups+named: expected error for named_groups_func, got nil")
	}
}

func TestGenCStubFilesSingle(t *testing.T) {
	entries := []config.RegexEntry{{MatchFunc: "url_match"}}
	h, c, err := genCStubFiles(entries, "mymod", "stub.h")
	if err != nil {
		t.Fatalf("genCStubFiles: %v", err)
	}
	for _, sub := range []string{"Auto-generated", "#pragma once", "url_match"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCStubFiles h: missing %q", sub)
		}
	}
	for _, sub := range []string{`#include "stub.h"`, "url_match"} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCStubFiles c: missing %q", sub)
		}
	}
}

func TestGenCStubFilesWithNamedGroups(t *testing.T) {
	// named_groups_func is not supported for C stubs — must return an error.
	entries := []config.RegexEntry{
		{NamedGroupsFunc: "url_named", Pattern: "(?P<scheme>https?)://(?P<host>[^/]+)"},
	}
	_, _, err := genCStubFiles(entries, "mymod", "stub.h")
	if err == nil {
		t.Fatal("genCStubFiles named groups: expected error for named_groups_func, got nil")
	}
}

func TestGenJSStubFileWithNamedPattern(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regex.js",
		Regexes: []config.RegexEntry{{
			NamedGroupsFunc: "url_named",
			Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
		}},
	}
	out, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("genJSStubFile named pattern: %v", err)
	}
	for _, sub := range []string{"url_named", `result['scheme']`, `result['host']`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSStubFile named pattern: missing %q", sub)
		}
	}
}

func TestGenTSStubFileWithNamedPattern(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regex.ts",
		Regexes: []config.RegexEntry{{
			NamedGroupsFunc: "url_named",
			Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
		}},
	}
	out, err := genTSStubFile(cfg)
	if err != nil {
		t.Fatalf("genTSStubFile named pattern: %v", err)
	}
	for _, sub := range []string{"url_named", `result['scheme']`, `result['host']`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSStubFile named pattern: missing %q", sub)
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
		{config.BuildConfig{StubType: "go"}, "go", false},
		{config.BuildConfig{StubType: "c"}, "c", false},
		{config.BuildConfig{StubType: "invalid"}, "", true},
		{config.BuildConfig{StubFile: "out.rs"}, "rust", false},
		{config.BuildConfig{StubFile: "out.js"}, "js", false},
		{config.BuildConfig{StubFile: "out.ts"}, "ts", false},
		{config.BuildConfig{StubFile: "out.go"}, "go", false},
		{config.BuildConfig{StubFile: "out.h"}, "c", false},
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

func TestGenASMatchStub(t *testing.T) {
	out := genASMatchStub("mymod", "url_match")
	for _, sub := range []string{`@external("mymod", "url_match")`, "_ffi_url_match", "export function url_match", "i32"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genASMatchStub: missing %q", sub)
		}
	}
	if strings.Contains(out, "bool") {
		t.Error("genASMatchStub: must not return bool")
	}
}

func TestGenASFindStub(t *testing.T) {
	out := genASFindStub("mymod", "url_find")
	for _, sub := range []string{`@external("mymod", "url_find")`, "_ffi_url_find", "export function url_find", "offset: i32", "i64"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genASFindStub: missing %q", sub)
		}
	}
	if strings.Contains(out, "_url_find_off") {
		t.Error("genASFindStub: must not have module-level offset state")
	}
}

func TestGenASGroupsStub(t *testing.T) {
	out := genASGroupsStub("mymod", "parse_url", "parse_url", 3)
	for _, sub := range []string{`@external("mymod", "parse_url")`, "_ffi_parse_url", "export function parse_url", "offset: i32", "Int32Array(6)", "dataStart"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genASGroupsStub: missing %q", sub)
		}
	}
	if strings.Contains(out, "_parse_url_off") {
		t.Error("genASGroupsStub: must not have module-level offset state")
	}
}

func TestGenASStubNamedGroupsFuncError(t *testing.T) {
	entries := []config.RegexEntry{
		{NamedGroupsFunc: "find_email", Pattern: "(?P<user>[^@]+)@(?P<domain>.+)"},
	}
	_, err := genASStubFile(config.BuildConfig{Regexes: entries, ImportModule: "mymod"})
	if err == nil {
		t.Fatal("genASStubFile: expected error for named_groups_func, got nil")
	}
}

func TestGenASStubFileGroupsFunc(t *testing.T) {
	entries := []config.RegexEntry{
		{GroupsFunc: "find_email", Pattern: "(?P<user>[^@]+)@(?P<domain>.+)"},
	}
	out, err := genASStubFile(config.BuildConfig{Regexes: entries, ImportModule: "mymod"})
	if err != nil {
		t.Fatalf("genASStubFile: %v", err)
	}
	for _, sub := range []string{"Auto-generated", "find_email", "offset: i32", "Int32Array", "dataStart"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genASStubFile groups_func: missing %q", sub)
		}
	}
}

// TestCmdGenerateStubDispatchers covers the per-type stub dispatcher functions
// (asStub, cStub, goStub, jsStub, tsStub, rustStub) by passing "-" as the
// output path, which bypasses file I/O and writes to stdout.
func TestCmdGenerateStubDispatchers(t *testing.T) {
	cases := []struct {
		name     string
		stubType string
		cfg      config.BuildConfig
	}{
		{
			name:     "rust",
			stubType: "rust",
			cfg: config.BuildConfig{
				StubType:     "rust",
				ImportModule: "mymod",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "go",
			stubType: "go",
			cfg: config.BuildConfig{
				StubType:     "go",
				ImportModule: "mymod",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "js",
			stubType: "js",
			cfg: config.BuildConfig{
				StubType:     "js",
				ImportModule: "mymod",
				Output:       "merged.wasm",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "ts",
			stubType: "ts",
			cfg: config.BuildConfig{
				StubType:     "ts",
				ImportModule: "mymod",
				Output:       "merged.wasm",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "c",
			stubType: "c",
			cfg: config.BuildConfig{
				StubType:     "c",
				ImportModule: "mymod",
				StubFile:     "stub.h",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "as",
			stubType: "as",
			cfg: config.BuildConfig{
				StubType:     "as",
				ImportModule: "mymod",
				Regexes:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CmdGenerateStub(c.cfg, "-"); err != nil {
				t.Errorf("CmdGenerateStub(%s): %v", c.stubType, err)
			}
		})
	}
}

func TestWriteStub(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sub/out.txt"
	if err := writeStub(path, []byte("hello")); err != nil {
		t.Fatalf("writeStub: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("writeStub: got %q, want %q", string(data), "hello")
	}
}

// --------------------------------------------------------------------------
// Set stub tests (Phase 5)

// setTestCfg builds a BuildConfig with two named patterns and one set that
// exercises all three export types: find_all, find_any, and match.
func setTestCfg() config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "mymod",
		Regexes: []config.RegexEntry{
			{Name: "pat_a", Pattern: `foo\d+`},
			{Name: "pat_b", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{
				Name:        "scanner",
				FindAll:     "scan_all",
				FindAny:     "scan_any",
				Match:       "validate",
				EmitNameMap: true,
				Patterns:    config.PatternSelector{All: true},
			},
		},
	}
}

func TestGenRustSetInner(t *testing.T) {
	cfg := setTestCfg()
	out := genRustSetInner(cfg)
	required := []string{
		"SetMatch",
		"range(self)",
		"scan_all",
		"scan_any",
		"validate",
		"pattern_name",
		"\"pat_a\"",
		"\"pat_b\"",
		"ffi_scan_all",
		"ffi_validate",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genRustSetInner: missing %q", s)
		}
	}
	if strings.Contains(out, "SetAnchorMatch") {
		t.Error("genRustSetInner: should not contain SetAnchorMatch (removed in 5.4.1)")
	}
}

func TestGenGoSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genGoSetSection(cfg, "mymod")
	required := []string{
		"SetMatch",
		"ScanAll",
		"ScanAny",
		"Validate",
		"PatternName",
		"find_all", // wasmimport directive
		"validate", // wasmimport directive
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genGoSetSection: missing %q", s)
		}
	}
}

func TestGenJSSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genJSSetSection(cfg)
	required := []string{
		"scan_all",
		"scan_any",
		"validate",
		"patternName",
		"patternId",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genJSSetSection: missing %q", s)
		}
	}
}

func TestGenTSSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genTSSetSection(cfg)
	required := []string{
		"SetMatch",
		"scan_all",
		"scan_any",
		"validate",
		"patternName",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genTSSetSection: missing %q", s)
		}
	}
}

func TestGenCStubFilesWithSets(t *testing.T) {
	cfg := setTestCfg()
	h, c, err := genCStubFilesWithSets(cfg, "stub.h")
	if err != nil {
		t.Fatalf("genCStubFilesWithSets: %v", err)
	}
	for _, s := range []string{"rx_set_match_t", "rx_set_anchor_t", "scan_all", "validate", "pattern_name"} {
		if !strings.Contains(h, s) && !strings.Contains(c, s) {
			t.Errorf("genCStubFilesWithSets: missing %q in output", s)
		}
	}
}

func TestGenASSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genASSetSection(cfg)
	required := []string{
		"SetMatch",
		"scan_all",
		"scan_any",
		"validate",
		"patternName",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genASSetSection: missing %q", s)
		}
	}
}

func TestRustStub_WithSets(t *testing.T) {
	cfg := setTestCfg()
	inner, err := genRustStubsInner(cfg.Regexes, cfg.ImportModule)
	if err != nil {
		t.Fatalf("genRustStubsInner: %v", err)
	}
	inner += genRustSetInner(cfg)
	out := wrapRustModule(inner, cfg.ImportModule)
	if !strings.Contains(out, "SetMatch") {
		t.Error("rust stub with sets: missing SetMatch type")
	}
	if !strings.Contains(out, "pub mod "+cfg.ImportModule) {
		t.Error("rust stub with sets: missing module wrapper")
	}
}

func TestSetSection_NoSets_Empty(t *testing.T) {
	cfg := config.BuildConfig{ImportModule: "m", Regexes: []config.RegexEntry{{Pattern: `foo`}}}
	if s := genRustSetInner(cfg); s != "" {
		t.Errorf("genRustSetInner with no sets: got non-empty %q", s)
	}
	if s := genGoSetSection(cfg, "m"); s != "" {
		t.Errorf("genGoSetSection with no sets: got non-empty %q", s)
	}
	if s := genJSSetSection(cfg); s != "" {
		t.Errorf("genJSSetSection with no sets: got non-empty %q", s)
	}
	if s := genTSSetSection(cfg); s != "" {
		t.Errorf("genTSSetSection with no sets: got non-empty %q", s)
	}
	if s := genASSetSection(cfg); s != "" {
		t.Errorf("genASSetSection with no sets: got non-empty %q", s)
	}
}

func TestSetSection_FindAllOnly(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "m",
		Regexes:      []config.RegexEntry{{Pattern: `foo`}},
		Sets: []config.SetConfig{
			{Name: "s", FindAll: "find_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	rust := genRustSetInner(cfg)
	if !strings.Contains(rust, "find_all") {
		t.Error("find_all not in Rust set stub")
	}
	if strings.Contains(rust, "fn validate") || strings.Contains(rust, "ffi_find_any") {
		t.Error("unexpected exports in find_all-only Rust stub")
	}
}
