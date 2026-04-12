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
	entries := []config.RegexEntry{{
		GroupsFunc:      "url_groups",
		NamedGroupsFunc: "url_named",
		Pattern:         "(?P<scheme>https?)://(?P<host>[^/]+)",
	}}
	h, c, err := genCStubFiles(entries, "mymod", "stub.h")
	if err != nil {
		t.Fatalf("genCStubFiles groups+named: %v", err)
	}
	// When both are set, groups_func takes precedence
	for _, sub := range []string{"url_groups", "URL_GROUPS_GROUP_SCHEME", "URL_GROUPS_GROUP_HOST"} {
		if !strings.Contains(h+c, sub) {
			t.Errorf("genCStubFiles groups+named: missing %q", sub)
		}
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
	entries := []config.RegexEntry{
		{NamedGroupsFunc: "url_named", Pattern: "(?P<scheme>https?)://(?P<host>[^/]+)"},
	}
	h, c, err := genCStubFiles(entries, "mymod", "stub.h")
	if err != nil {
		t.Fatalf("genCStubFiles: %v", err)
	}
	for _, sub := range []string{"URL_NAMED_GROUP_SCHEME", "URL_NAMED_GROUP_HOST", "url_named"} {
		if !strings.Contains(h+c, sub) {
			t.Errorf("genCStubFiles named groups: missing %q", sub)
		}
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
