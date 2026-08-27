package generate

import (
	"fmt"
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

// TestGenRustGroupIndexConsts covers what replaced `named_groups_func` in Rust
// (TODO task 62): one constant per named group, a runtime lookup and an
// index-aligned name table.
func TestGenRustGroupIndexConsts(t *testing.T) {
	named := map[string]int{"scheme": 1, "host": 2}
	out := genRustGroupIndexConsts("url_groups", 4, named)
	for _, sub := range []string{
		"pub const url_groups_count: usize = 4;",
		"pub const url_groups_scheme: usize = 1;",
		"pub const url_groups_host: usize = 2;",
		"pub fn url_groups_index(name: &str) -> Option<usize>",
		`"scheme" => Some(1)`,
		"pub fn url_groups_names() -> &'static [&'static str]",
		// Index-aligned, "" where unnamed — index 0 and index 3 here.
		`&["", "scheme", "host", ""]`,
		// A lowercase const is deliberate (names follow the config's casing),
		// so the lint has to be suppressed rather than the name changed.
		"#[allow(non_upper_case_globals)]",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genRustGroupIndexConsts: output missing %q\ngot:\n%s", sub, out)
		}
	}
	// A pattern with no named group gets none of it.
	if got := genRustGroupIndexConsts("plain", 2, nil); got != "" {
		t.Errorf("genRustGroupIndexConsts with no named groups: want empty, got %q", got)
	}
}

// TestDerivedNamesFollowConfigCasing pins the rule that a symbol derived from a
// user-chosen name copies that name's STYLE rather than the language's.
func TestDerivedNamesFollowConfigCasing(t *testing.T) {
	cases := []struct{ base, suffix, want string }{
		{"url_groups", "index", "url_groups_index"},
		{"urlGroups", "index", "urlGroupsIndex"},
		{"find", "names", "find_names"},
		{"URLGroups", "index", "URLGroupsIndex"},
	}
	for _, c := range cases {
		if got := derivedFuncName(c.base, c.suffix); got != c.want {
			t.Errorf("derivedFuncName(%q, %q) = %q, want %q", c.base, c.suffix, got, c.want)
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
		StubFile: "regexp.js",
		Regexps: []config.RegexEntry{
			{MatchFunc: "url_match", FindFunc: "url_find"},
			{GroupsFunc: "tok_groups", Pattern: "(?P<first>a)(b)"},
		},
	}
	out, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("genJSStubFile: %v", err)
	}
	for _, sub := range []string{
		"url_match", "url_find",
		"tok_groups", "tok_groups_indices",
		"export async function init", "WebAssembly.instantiate", "_inBase", "_outBase",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSStubFile: output missing %q", sub)
		}
	}
}

func TestGenTSStubFile(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regexp.ts",
		Regexps: []config.RegexEntry{
			{MatchFunc: "url_match", FindFunc: "url_find"},
			{GroupsFunc: "tok_groups", Pattern: "(?P<first>a)(b)"},
		},
	}
	out, err := genTSStubFile(cfg)
	if err != nil {
		t.Fatalf("genTSStubFile: %v", err)
	}
	for _, sub := range []string{
		"url_match", "url_find",
		"tok_groups", "tok_groups_indices",
		"export async function init", "Promise<void>",
		"WebAssembly.Module", "WebAssembly.instantiate",
		"Generator<[number, number]>",
		"as const",
		"_inBase", "_outBase",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSStubFile: output missing %q", sub)
		}
	}
}

// The Go generator's PascalCase transform is GONE (TODO task 62): a name the
// user wrote in the config is the name a caller writes, in every language. If
// that leaves a symbol unexported, that is the user's choice and is warned
// about once per stub rather than corrected.
func TestGoStubKeepsConfigNameVerbatim(t *testing.T) {
	out := genGoMatchStub("url", "url_match")
	if !strings.Contains(out, "func url_match(input []byte)") {
		t.Errorf("genGoMatchStub should emit the config name verbatim, got:\n%s", out)
	}
	if strings.Contains(out, "func UrlMatch") {
		t.Error("genGoMatchStub still Pascal-cases the config name")
	}
}

func TestGenGoMatchStub(t *testing.T) {
	out := genGoMatchStub("url", "url_match")
	for _, sub := range []string{
		"//go:wasmimport url url_match",
		"ffi_url_match",
		"func url_match(input []byte) (end uint, ok bool, err error)",
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
		"func (iter *url_findIter) Matches() iter.Seq2[uint, uint]",
		"uint64(packed) >> 32",
		// The whole buffer and a start position, not a narrowed slice.
		"uint32(len(input)), uint32(pos)",
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
		"func (iter *url_groupsIter) Matches() iter.Seq[[]Span]",
		"slotBuffer [6]int32",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoGroupsStub: output missing %q", sub)
		}
	}
}

// TestGenGoGroupIndexConsts covers what replaced `named_groups_func` in Go
// (TODO task 62).
func TestGenGoGroupIndexConsts(t *testing.T) {
	named := map[string]int{"scheme": 1, "host": 2}
	out := genGoGroupIndexConsts("url_groups", 4, named)
	for _, sub := range []string{
		"const url_groups_count = 4",
		"url_groups_scheme = 1",
		"url_groups_host = 2",
		"func url_groups_index(name string) (int, bool)",
		`case "scheme":`,
		"func url_groups_names() []string",
		`[]string{"", "scheme", "host", ""}`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoGroupIndexConsts: output missing %q\ngot:\n%s", sub, out)
		}
	}
	if got := genGoGroupIndexConsts("plain", 2, nil); got != "" {
		t.Errorf("genGoGroupIndexConsts with no named groups: want empty, got %q", got)
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
			GroupsFunc: "url_groups",
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
		"url_match", "url_find", "url_groups", "url_groups_index",
		"iter.Seq2[uint, uint]",
		"iter.Seq[[]Span]",
		"url_groups_names",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genGoStubFile full: missing %q", sub)
		}
	}
}

func TestGenRustStubFileGroupsAndNamed(t *testing.T) {
	entries := []config.RegexEntry{{
		GroupsFunc: "url_groups",
		Pattern:    "(?P<scheme>https?)://(?P<host>[^/]+)",
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
	if !strings.Contains(out, "url_groups_index") {
		t.Error("missing url_groups_index")
	}
}

func TestGenRustStubFileNamedOnly(t *testing.T) {
	entries := []config.RegexEntry{{
		GroupsFunc: "url_groups",
		Pattern:    "(?P<scheme>https?)://(?P<host>[^/]+)",
	}}
	out, err := genRustStubFile(entries, "url")
	if err != nil {
		t.Fatalf("genRustStubFile named-only: %v", err)
	}
	if !strings.Contains(out, `#[link(wasm_import_module = "url")]`) {
		t.Error("genRustStubFile named-only: missing FFI block")
	}
	if !strings.Contains(out, "url_groups_index") {
		t.Error("missing url_groups_index")
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
	for _, sub := range []string{"ptrdiff_t my_match", "anchored match"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCMatchHPart: output missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("my_match")`,
		"_ffi_my_match", "ptrdiff_t my_match",
	} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCMatchCPart: output missing %q", sub)
		}
	}
}

func TestGenCFindParts(t *testing.T) {
	h := genCFindHPart("tok_find")
	c := genCFindCPart("mymod", "tok_find")
	for _, sub := range []string{"int tok_find_next(rx_tok_find_iter_t *iter, rx_match_t *out_match)", "offset"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCFindHPart: output missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("tok_find")`,
		"_ffi_tok_find", "int tok_find_next(rx_tok_find_iter_t *iter, rx_match_t *out_match)",
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
		"parse_url_scheme", "parse_url_host",
		"PARSE_URL_GROUPS", "int parse_url_next(rx_parse_url_iter_t *iter, rx_group_t out_groups[static PARSE_URL_GROUPS])",
	} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCGroupsStubParts h: missing %q", sub)
		}
	}
	for _, sub := range []string{
		`import_module("mymod")`, `import_name("parse_url")`,
		"_ffi_parse_url", "parse_url_index", "_parse_url_names",
		// The .h prototype uses the macro; the .c definition uses the literal
		// count, so this asserts the definition rather than repeating the .h.
		"int parse_url_next(rx_parse_url_iter_t *iter, rx_group_t out_groups[static 3])",
		"int parse_url_init(rx_parse_url_iter_t *iter,",
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
	for _, sub := range []string{`#include "stub.h"`, "_ffi_tok_find", "int tok_find_next(rx_tok_find_iter_t *iter, rx_match_t *out_match)"} {
		if !strings.Contains(c, sub) {
			t.Errorf("genCStubFiles find c: missing %q", sub)
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

// TestGenCStubFilesNamedGroupIndices covers what replaced `named_groups_func`
// in C (TODO task 62): C used to REJECT the key outright, and now gets the
// named access it never had, through index constants.
func TestGenCStubFilesNamedGroupIndices(t *testing.T) {
	entries := []config.RegexEntry{
		{GroupsFunc: "url_groups", Pattern: "(?P<scheme>https?)://(?P<host>[^/]+)"},
	}
	h, _, err := genCStubFiles(entries, "mymod", "stub.h")
	if err != nil {
		t.Fatalf("genCStubFiles: %v", err)
	}
	for _, sub := range []string{"url_groups_scheme", "url_groups_host", "url_groups_index"} {
		if !strings.Contains(h, sub) {
			t.Errorf("genCStubFiles h: missing %q", sub)
		}
	}
}

func TestGenJSStubFileWithNamedPattern(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regexp.js",
		Regexps: []config.RegexEntry{{
			GroupsFunc: "url_groups",
			Pattern:    "(?P<scheme>https?)://(?P<host>[^/]+)",
		}},
	}
	out, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("genJSStubFile named pattern: %v", err)
	}
	for _, sub := range []string{"url_groups_indices", "scheme: 1", "host: 2"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSStubFile named pattern: missing %q", sub)
		}
	}
}

func TestGenTSStubFileWithNamedPattern(t *testing.T) {
	cfg := config.BuildConfig{
		Output:   "merged.wasm",
		StubFile: "regexp.ts",
		Regexps: []config.RegexEntry{{
			GroupsFunc: "url_groups",
			Pattern:    "(?P<scheme>https?)://(?P<host>[^/]+)",
		}},
	}
	out, err := genTSStubFile(cfg)
	if err != nil {
		t.Fatalf("genTSStubFile named pattern: %v", err)
	}
	for _, sub := range []string{"url_groups_indices", "scheme: 1", "host: 2"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSStubFile named pattern: missing %q", sub)
		}
	}
}

// TestGenJSGroupsFuncHasBatchPath and its TS/named-groups siblings verify the
// batch-detect-and-drain block (task 44) is emitted by every groups/find
// generator, JS and TS, including named_groups_func — this is a structural
// (source-text) check; the actual batch-vs-non-batch behavioural
// equivalence was verified via a scratch wasmtime/Node differential harness
// (not committed).
func TestGenJSFindFuncHasBatchPath(t *testing.T) {
	out := genJSFindFunc("f")
	for _, sub := range []string{`_exp['f_batch']`, `f_batch'](_inBase`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSFindFunc: missing %q", sub)
		}
	}
}

func TestGenTSFindFuncHasBatchPath(t *testing.T) {
	out := genTSFindFunc("f")
	for _, sub := range []string{`_exp['f_batch']`, `f_batch'] as CallableFunction)(_inBase`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSFindFunc: missing %q", sub)
		}
	}
}

func TestGenJSGroupsFuncHasBatchPath(t *testing.T) {
	out := genJSGroupsFunc("g", 2)
	for _, sub := range []string{`_exp['g_batch']`, `g_batch'](_inBase`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSGroupsFunc: missing %q", sub)
		}
	}
}

func TestGenTSGroupsFuncHasBatchPath(t *testing.T) {
	out := genTSGroupsFunc("g", 2)
	for _, sub := range []string{`_exp['g_batch']`, `g_batch'] as CallableFunction)(_inBase`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSGroupsFunc: missing %q", sub)
		}
	}
}

// The batch feature-detect is keyed on the WASM export name. That used to be
// worth its own test because `named_groups_func` could name an export
// different from `groups_func`'s; with the key retired (TODO task 62) there is
// only ever one name, so the checks below cover it.
// TestGenJSGroupIndices covers what replaced `named_groups_func` in JS (TODO
// task 62): one frozen name→index object, suffixed `indices` because without a
// suffix its derived name would collide with the generator function's.
func TestGenJSGroupIndices(t *testing.T) {
	out := genJSGroupIndices("url_groups", 4, map[string]int{"scheme": 1, "host": 2})
	for _, sub := range []string{
		"export const url_groups_indices = Object.freeze({",
		"scheme: 1,",
		"host: 2,",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSGroupIndices: missing %q\ngot:\n%s", sub, out)
		}
	}
	if got := genJSGroupIndices("plain", 2, nil); got != "" {
		t.Errorf("genJSGroupIndices with no named groups: want empty, got %q", got)
	}
}

func TestGenTSGroupIndices(t *testing.T) {
	out := genTSGroupIndices("url_groups", 4, map[string]int{"scheme": 1, "host": 2})
	for _, sub := range []string{
		"export const url_groups_indices = {",
		"scheme: 1,",
		"host: 2,",
		"} as const;",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSGroupIndices: missing %q\ngot:\n%s", sub, out)
		}
	}
	if got := genTSGroupIndices("plain", 2, nil); got != "" {
		t.Errorf("genTSGroupIndices with no named groups: want empty, got %q", got)
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
	for _, sub := range []string{`@external("mymod", "url_find")`, "_ffi_url_find", "export function url_find", "offset: u32", "i64"} {
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
	for _, sub := range []string{`@external("mymod", "parse_url")`, "_ffi_parse_url", "export function parse_url", "offset: u32", "Int32Array(6)", "dataStart"} {
		if !strings.Contains(out, sub) {
			t.Errorf("genASGroupsStub: missing %q", sub)
		}
	}
	if strings.Contains(out, "_parse_url_off") {
		t.Error("genASGroupsStub: must not have module-level offset state")
	}
}

func TestGenASStubFileGroupsFunc(t *testing.T) {
	entries := []config.RegexEntry{
		{GroupsFunc: "find_email", Pattern: "(?P<user>[^@]+)@(?P<domain>.+)"},
	}
	out, err := genASStubFile(config.BuildConfig{Regexps: entries, ImportModule: "mymod"})
	if err != nil {
		t.Fatalf("genASStubFile: %v", err)
	}
	for _, sub := range []string{"Auto-generated", "find_email", "offset: u32", "Int32Array", "dataStart"} {
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
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "go",
			stubType: "go",
			cfg: config.BuildConfig{
				StubType:     "go",
				ImportModule: "mymod",
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "js",
			stubType: "js",
			cfg: config.BuildConfig{
				StubType:     "js",
				ImportModule: "mymod",
				Output:       "merged.wasm",
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "ts",
			stubType: "ts",
			cfg: config.BuildConfig{
				StubType:     "ts",
				ImportModule: "mymod",
				Output:       "merged.wasm",
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "c",
			stubType: "c",
			cfg: config.BuildConfig{
				StubType:     "c",
				ImportModule: "mymod",
				StubFile:     "stub.h",
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
			},
		},
		{
			name:     "as",
			stubType: "as",
			cfg: config.BuildConfig{
				StubType:     "as",
				ImportModule: "mymod",
				Regexps:      []config.RegexEntry{{MatchFunc: "url_match"}},
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
		Regexps: []config.RegexEntry{
			{Name: "pat_a", Pattern: `foo\d+`},
			{Name: "pat_b", Pattern: `bar\w+`},
		},
		Sets: []config.SetConfig{
			{
				Name:        "scanner",
				MatchAny:    "validate_any",
				MatchAll:    "validate_all",
				ScanAny:     "probe_any",
				ScanAll:     "probe_all",
				Find:        "set_find",
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
		"SCANNER_PATTERN_COUNT",                  // D16: the emitted constant
		"SCANNER_ID_SPACE",                       // §11 R1: the id-space constant
		"buf: [[i32; 3]; SCANNER_PATTERN_COUNT]", // tuples: at most one per pattern per position
		"gates: [u32; SCANNER_ID_SPACE]",         // D14/D15 + §11 R1: indexed by pattern id
		"set_find", "probe_any", "probe_all", "probe",
		"validate", "validate_any", "validate_all",
		"pattern_name",
		"\"pat_a\"",
		"\"pat_b\"",
		"ffi_set_find",
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
	// D24/D15: `find` is iterator-only; no stateless probe variant exists.
	if strings.Contains(out, "set_findAt") {
		t.Error("genRustSetInner: emitted a stateless find probe, which D24 removed")
	}
}

func TestGenGoSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genGoSetSection(cfg, "mymod")
	required := []string{
		"SetMatch",
		"ScannerPatternCount",
		"set_find", "probe_any", "probe_all", "probe",
		"validate", "validate_any", "validate_all",
		"PatternName",
		"set_find", // wasmimport directive
		"validate", // wasmimport directive
		"iter.Seq[SetMatch]",
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
		"set_find",
		"probe_any",
		"validate",
		"scannerPatternCount",
		"patternName",
		"patternId",
		"_exp",
		"_mem",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genJSSetSection: missing %q", s)
		}
	}
	if strings.Contains(out, "_inst") {
		t.Errorf("genJSSetSection: should not contain _inst")
	}
}

func TestGenTSSetSection(t *testing.T) {
	cfg := setTestCfg()
	out := genTSSetSection(cfg)
	required := []string{
		"SetMatch",
		"set_find",
		"probe_any",
		"validate",
		"scannerPatternCount",
		"patternName",
		"_exp",
		"_mem",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genTSSetSection: missing %q", s)
		}
	}
	if strings.Contains(out, "_inst") {
		t.Errorf("genTSSetSection: should not contain _inst")
	}
	if strings.Contains(out, "SetAnchorMatch") {
		t.Errorf("genTSSetSection: SetAnchorMatch should be removed (unified into SetMatch)")
	}
}

func TestGenCStubFilesWithSets(t *testing.T) {
	cfg := setTestCfg()
	h, c, err := genCStubFilesWithSets(cfg, "stub.h")
	if err != nil {
		t.Fatalf("genCStubFilesWithSets: %v", err)
	}
	for _, s := range []string{
		"rx_set_match_t", "set_find_init", "rx_scanner_scanner_t",
		"SCANNER_PATTERN_COUNT", "validate", "probe_all", "pattern_name",
	} {
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
		"SCANNER_PATTERN_COUNT",
		"class SetFindIter",
		"probe_any",
		"validate",
		"patternName",
	}
	disallowed := []string{"Generator<", "function*", "yield"}
	for _, s := range disallowed {
		if strings.Contains(out, s) {
			t.Errorf("genASSetSection: must not contain %q (AS has no generator support)", s)
		}
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("genASSetSection: missing %q", s)
		}
	}
}

func TestRustStub_WithSets(t *testing.T) {
	cfg := setTestCfg()
	inner, err := genRustStubsInner(cfg.Regexps, cfg.ImportModule)
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
	cfg := config.BuildConfig{ImportModule: "m", Regexps: []config.RegexEntry{{Pattern: `foo`}}}
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

func TestSetSection_FindOnly(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "m",
		Regexps:      []config.RegexEntry{{Pattern: `foo`}},
		Sets: []config.SetConfig{
			{Name: "s", Find: "set_find", Patterns: config.PatternSelector{All: true}},
		},
	}
	rust := genRustSetInner(cfg)
	if !strings.Contains(rust, "fn set_find") {
		t.Error("set_find not in Rust set stub")
	}
	// A find-only set must not drag in any of the other six capabilities.
	for _, unexpected := range []string{"fn validate", "ffi_probe", "ffi_validate"} {
		if strings.Contains(rust, unexpected) {
			t.Errorf("unexpected %q in a find-only Rust stub", unexpected)
		}
	}
}

func TestPatternsInSet_Names(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "a", Pattern: "a"},
			{Name: "b", Pattern: "b"},
			{Name: "c", Pattern: "c"},
		},
	}
	s := config.SetConfig{
		Patterns: config.PatternSelector{Names: []string{"a", "c"}},
	}
	if got := patternsInSet(s, cfg); got != 2 {
		t.Errorf("patternsInSet(Names): got %d, want 2", got)
	}
}

func TestCmdGenerateStub_ResolveError(t *testing.T) {
	cfg := config.BuildConfig{StubType: "bogus"}
	if err := CmdGenerateStub(cfg, "-"); err == nil {
		t.Fatal("CmdGenerateStub(bogus stub_type): expected error, got nil")
	}
}

func TestExtractGroupInfo_ParseError(t *testing.T) {
	if _, _, err := extractGroupInfo("(unclosed"); err == nil {
		t.Fatal("extractGroupInfo(invalid): expected error, got nil")
	}
}

func TestWriteStub_MkdirError(t *testing.T) {
	// Create a file, then try to write into a path that treats it as a parent dir.
	tmp := t.TempDir()
	blocker := tmp + "/blocker"
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := writeStub(blocker+"/inner/file.txt", []byte("data")); err == nil {
		t.Fatal("writeStub: expected mkdir error, got nil")
	}
}

// TestConfigPascalCaseMatchesGenerators guards the one duplicated transform in
// the per-stub-type validation. config cannot
// import generate, so config.pascalCase is a hand copy of iterTypeName minus
// its "Iter" suffix. If that transform changes, the collision check silently
// stops matching what is emitted — this test fails instead.
//
// Go dropped out of this in TODO task 62: its names are now verbatim, so
// nothing there Pascal-cases. Rust's iterator TYPE name still does.
func TestConfigPascalCaseMatchesGenerators(t *testing.T) {
	names := []string{
		"url_match", "urlMatch", "UrlMatch", "set_match", "a_b_c",
		"_leading", "x9", "find", "named_groups_func", "aB_cD",
	}
	for _, n := range names {
		if got, wantIter := config.PascalCaseForValidation(n)+"Iter", iterTypeName(n); got != wantIter {
			t.Errorf("config.PascalCaseForValidation(%q)+\"Iter\" = %q, but iterTypeName = %q", n, got, wantIter)
		}
	}
}

// TestSetAllDecodesOverIDSpace covers the narrow (<=64 id) `_all` decode in
// every generator. The i64 bitmask carries bit positions, and a bit position is
// a GLOBAL pattern id — so the decode loop is bounded by the id space, not by
// the set's pattern count. The two are equal for a whole-config set, which is
// why the C generator's loop over PATTERN_COUNT went unnoticed; for a named
// subset of two late-declared patterns it dropped every match.
func TestSetAllDecodesOverIDSpace(t *testing.T) {
	// Six patterns, of which the set selects only the last two: count 2,
	// id space 6, ids 4 and 5. A loop bounded by the count never inspects
	// either bit.
	cfg := config.BuildConfig{
		ImportModule: "mymod",
		Regexps: []config.RegexEntry{
			{Name: "p0", Pattern: "a"}, {Name: "p1", Pattern: "b"},
			{Name: "p2", Pattern: "c"}, {Name: "p3", Pattern: "d"},
			{Name: "p4", Pattern: "e"}, {Name: "p5", Pattern: "f"},
		},
		Sets: []config.SetConfig{{
			Name:     "scanner",
			MatchAll: "validate_all",
			ScanAll:  "probe_all",
			Patterns: config.PatternSelector{Names: []string{"p4", "p5"}},
		}},
	}
	set := cfg.Sets[0]
	if n, id := patternsInSet(set, cfg), idSpaceSize(set, cfg); n != 2 || id != 6 {
		t.Fatalf("test set is not the sparse shape: count=%d idSpace=%d, want 2 and 6", n, id)
	}
	if wideAllForm(set, cfg) {
		t.Fatal("test set took the wide _all form; this test must exercise the narrow bitmask decode")
	}

	hStub, cStub, err := genCStubFilesWithSets(cfg, "stubs.h")
	if err != nil {
		t.Fatalf("genCStubFilesWithSets: %v", err)
	}
	for _, lang := range []struct{ name, out, count, idSpace string }{
		{"rust", genRustSetInner(cfg), "SCANNER_PATTERN_COUNT", "SCANNER_ID_SPACE"},
		{"go", genGoSetSection(cfg, "mymod"), "ScannerPatternCount", "ScannerIDSpace"},
		{"js", genJSSetSection(cfg), "scannerPatternCount", "scannerIdSpace"},
		{"ts", genTSSetSection(cfg), "scannerPatternCount", "scannerIdSpace"},
		{"as", genASSetSection(cfg), "SCANNER_PATTERN_COUNT", "SCANNER_ID_SPACE"},
		{"c", hStub + cStub, "SCANNER_PATTERN_COUNT", "SCANNER_ID_SPACE"},
	} {
		for _, fn := range []string{"validate_all", "probe_all"} {
			body, ok := allDecodeBody(lang.out, fn)
			if !ok {
				t.Errorf("%s: no %s body found", lang.name, fn)
				continue
			}
			if !strings.Contains(body, lang.idSpace) {
				t.Errorf("%s: %s decodes without %s; a loop that stops at the pattern count "+
					"never inspects the bits of a sparse subset's ids\n%s", lang.name, fn, lang.idSpace, body)
			}
			// The check is about the LOOP BOUND, not about every mention of
			// the count: C's _all parameter is declared
			// `int patterns[static <SET>_PATTERN_COUNT]` (TODO task 59
			// decision (12)), which names the count legitimately — that is the
			// most entries the loop can ever APPEND, while the bit positions
			// it walks are ids. So the signature line is excluded.
			decode := body
			if i := strings.Index(decode, "\n"); i >= 0 {
				decode = decode[i+1:]
			}
			if strings.Contains(decode, lang.count) {
				t.Errorf("%s: %s decode is bounded by %s, but bit positions are global pattern ids\n%s",
					lang.name, fn, lang.count, body)
			}
		}
	}
}

// allDecodeBody extracts the emitted `_all` wrapper for fn — everything from
// the line that names it up to the closing brace at that indentation — so the
// bound can be asserted against the DECODE loop rather than against the whole
// file, where the other constant is always present somewhere.
func allDecodeBody(out, fn string) (string, bool) {
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		// The definition line: names fn and opens a block. Import/extern
		// declarations name it too, so require the brace.
		if !strings.Contains(ln, fn) || !strings.Contains(ln, "{") || strings.Contains(ln, "ffi_"+fn) {
			continue
		}
		for j := i + 1; j < len(lines) && j < i+30; j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "}") &&
				len(lines[j])-len(strings.TrimLeft(lines[j], " \t")) == len(ln)-len(strings.TrimLeft(ln, " \t")) {
				return strings.Join(lines[i:j+1], "\n"), true
			}
		}
	}
	return "", false
}

// TestConfigSetDerivedNamesMatchGenerators is the same guard for the per-set
// constants. config.setDerivedNames reserves those names so a capability export
// cannot collide with one, and a reservation that does not match what is
// actually emitted protects nothing: too narrow and the collision still ships,
// too wide and it rejects names no generator uses. The batch config is used
// because it emits all four.
func TestConfigSetDerivedNamesMatchGenerators(t *testing.T) {
	cfg := setBatchTestCfg()
	set := cfg.Sets[0]
	hStub, cStub, err := genCStubFilesWithSets(cfg, "stubs.h")
	if err != nil {
		t.Fatalf("genCStubFilesWithSets: %v", err)
	}
	for _, lang := range []struct{ name, out string }{
		{"rust", genRustSetInner(cfg)},
		{"go", genGoSetSection(cfg, "mymod")},
		{"js", genJSSetSection(cfg)},
		{"ts", genTSSetSection(cfg)},
		{"as", genASSetSection(cfg)},
		{"c", hStub + cStub},
	} {
		names := config.SetDerivedNamesForValidation(set, lang.name)
		if len(names) != 3 {
			t.Errorf("%s: reserved %d names, want 3 (pattern count, id space, batch size limit)", lang.name, len(names))
		}
		for _, n := range names {
			// The batch-size limit is reserved in every language but EMITTED
			// only by JS/TS, which is the only configuration with a host
			// boundary to amortise (decision (3)/(11)). Reserving it
			// everywhere is what keeps `stub_type` from changing which configs
			// are valid.
			if strings.HasSuffix(n, "BatchMaxSize") || strings.HasSuffix(n, "_BATCH_MAX_SIZE") {
				if lang.name != "js" && lang.name != "ts" {
					continue
				}
			}
			if !strings.Contains(lang.out, n) {
				t.Errorf("%s: reserves %q, but the generator emits no such name", lang.name, n)
			}
		}
	}
}

// setBatchTestCfg is setTestCfg with batching requested the way decision (11)
// requires: a hint on the set, not a second capability.
func setBatchTestCfg() config.BuildConfig {
	cfg := setTestCfg()
	cfg.Sets[0].Hints = []string{"batch-find"}
	return cfg
}

// TestSetBatchFindIsJSTSOnly covers decision (11) and the (3) reasoning it
// generalised: batching amortises HOST-BOUNDARY crossings and nothing else, so
// only JS/TS — the one configuration with a real boundary — carries any of it.
// The four merged languages (C, Go, Rust, AS) call into the same module and
// have no crossing to amortise, so the hint is a no-op for them.
func TestSetBatchFindIsJSTSOnly(t *testing.T) {
	cfg := setBatchTestCfg()
	merged := map[string]string{
		"rust": genRustSetInner(cfg),
		"go":   genGoSetSection(cfg, "mymod"),
		"as":   genASSetSection(cfg),
	}
	for lang, out := range merged {
		for _, forbidden := range []string{"batchSize", "SetTuple", "BatchMaxSize", "_batch"} {
			if strings.Contains(out, forbidden) {
				t.Errorf("%s set stub: %q must not appear — batching is JS/TS-only", lang, forbidden)
			}
		}
	}
	for lang, out := range map[string]string{"js": genJSSetSection(cfg), "ts": genTSSetSection(cfg)} {
		for _, want := range []string{"batchSize", "scannerBatchMaxSize", "set_find_batch"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s set stub: missing %q", lang, want)
			}
		}
		// One public function, not two: batching is a parameter.
		if n := strings.Count(out, "function* set_find"); n != 1 {
			t.Errorf("%s set stub: %d find generators, want exactly 1", lang, n)
		}
	}
}

// TestSetBatchSizeAbsentWithoutHint: without `hints: [batch-find]` the
// parameter is not in the signature at all, so TypeScript rejects
// find(input, 0, 64) at build time and no runtime check is needed.
func TestSetBatchSizeAbsentWithoutHint(t *testing.T) {
	cfg := setTestCfg() // no hint
	outs := map[string]string{
		"rust": genRustSetInner(cfg),
		"go":   genGoSetSection(cfg, "mymod"),
		"js":   genJSSetSection(cfg),
		"ts":   genTSSetSection(cfg),
		"as":   genASSetSection(cfg),
	}
	for lang, out := range outs {
		for _, forbidden := range []string{"batchSize", "BatchMaxSize", "BatchCountBits", "batchCountBits", "_batch"} {
			if strings.Contains(out, forbidden) {
				t.Errorf("%s set stub: %q leaked into an unhinted set", lang, forbidden)
			}
		}
	}
}

// bigSetCfg builds a config whose set is large enough to cross the by-value
// budget: 300 patterns is 300*12 + 300*4 = 4,800 bytes of inline arrays.
func bigSetCfg(t *testing.T, n int) config.BuildConfig {
	t.Helper()
	regexps := make([]config.RegexEntry, n)
	for i := range regexps {
		regexps[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: fmt.Sprintf(`kw%d\d+`, i)}
	}
	return config.BuildConfig{
		ImportModule: "mymod",
		Regexps:      regexps,
		Sets: []config.SetConfig{{
			Name:     "scanner",
			Find:     "set_find",
			Hints:    []string{"batch-find"},
			Patterns: config.PatternSelector{All: true},
		}},
	}
}

// TestRustSetIterBoxedAboveBudget pins SETS_PLAN item 5.
//
// The Rust iterator is a VALUE: it is returned from the constructor, moved into
// a `for`, moved again by `.take()` or `.map()`. Holding PATTERN_COUNT tuples
// and ID_SPACE gates inline makes that value grow with the set — measured at
// 32,032 bytes for 2,000 patterns, which rustc turned into a memset, a memcpy
// and a 60 KB stack frame on a three-line adapter chain.
//
// Above the budget both arrays are boxed; below it nothing changes, which is
// the half worth pinning hardest — `find` allocating NOTHING is a property
// SETS §19.6 bought deliberately, and it must survive for the sets that can
// afford it.
func TestRustSetIterBoxedAboveBudget(t *testing.T) {
	small := genRustSetInner(setTestCfg())
	for _, want := range []string{
		"buf: [[i32; 3]; SCANNER_PATTERN_COUNT]",
		"gates: [u32; SCANNER_ID_SPACE]",
	} {
		if !strings.Contains(small, want) {
			t.Errorf("2-pattern set: expected inline %q, got a boxed form", want)
		}
	}
	if strings.Contains(small, "Box<") {
		t.Error("2-pattern set: boxed an array that fits the by-value budget")
	}

	big := genRustSetInner(bigSetCfg(t, 300))
	for _, want := range []string{
		"buf: Box<[[i32; 3]]>",
		"gates: Box<[u32]>",
		"vec![[0; 3]; SCANNER_PATTERN_COUNT].into_boxed_slice()",
		"vec![0u32; SCANNER_ID_SPACE].into_boxed_slice()",
	} {
		if !strings.Contains(big, want) {
			t.Errorf("300-pattern set: missing %q", want)
		}
	}
	if strings.Contains(big, "buf: [[i32; 3]; SCANNER_PATTERN_COUNT]") {
		t.Error("300-pattern set: still holds the tuple buffer by value")
	}
	// Rust has ONE set iterator since decision (11) removed find_batch from
	// the merged languages, so there is one gate array to judge rather than
	// two. At 300 patterns the tuple buffer (300*12 = 3,600 B) plus the gates
	// (300*4 = 1,200 B) crosses the 4 KB budget, so both are boxed together —
	// the pair is one struct and it is the struct that gets moved.
	huge := genRustSetInner(bigSetCfg(t, 2000))
	if strings.Count(huge, "gates: Box<[u32]>") != 1 {
		t.Error("2000-pattern set: the iterator's gate array should be boxed")
	}
}

// TestSetInlineBudgetCrossover pins where the two shapes meet. The tuple buffer
// is 12 bytes an entry and the gate array 4, so a gated set of P patterns with
// P ids costs 16P: 256 patterns is exactly the 4 KB budget and stays inline,
// 257 is over it.
func TestSetInlineBudgetCrossover(t *testing.T) {
	for _, tc := range []struct {
		n     int
		boxed bool
	}{{255, false}, {256, false}, {257, true}} {
		out := genRustSetInner(bigSetCfg(t, tc.n))
		got := strings.Contains(out, "buf: Box<[[i32; 3]]>")
		if got != tc.boxed {
			t.Errorf("%d patterns (%d bytes inline): boxed=%v, want %v",
				tc.n, tc.n*16, got, tc.boxed)
		}
	}
}

// TestSetFindCScannerShape pins TODO task 59 decisions (4), (5) and (6) for
// the C set scanner:
//
//	(4) fill-and-count, not one-at-a-time — C has no iterator protocol, and
//	    the raw ABI already fills a buffer and returns a count, which is also
//	    the C idiom (read, getdents, recv).
//	(5) the scanner holds the INPUT. Every other language takes it once when
//	    the scan is created; C was the only one passing it on every step, and
//	    the split was backwards — it remembered the position, which changes
//	    every step, and forgot the input, which never does.
//	(6) _init returns int: 0 or a negative RX_ERR_*, the dominant C
//	    convention for operation status.
func TestSetFindCScannerShape(t *testing.T) {
	h, c, err := genCStubFilesWithSets(setTestCfg(), "stub.h")
	if err != nil {
		t.Fatalf("genCStubFilesWithSets: %v", err)
	}
	for _, want := range []string{
		"int set_find_init(rx_scanner_scanner_t *s, const char *input, size_t len, size_t offset);",
		"int set_find(rx_scanner_scanner_t *s, rx_set_match_t *buf, size_t cap);",
		"    const char *input;",
		"    size_t len, offset;",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("C set scanner: header missing %q", want)
		}
	}
	// The buffer is the CALLER's and is passed per call, not stored.
	structAt := strings.Index(h, "} rx_scanner_scanner_t;")
	if structAt < 0 {
		t.Fatal("C set scanner: struct not emitted")
	}
	declStart := strings.LastIndex(h[:structAt], "typedef struct {")
	for _, forbidden := range []string{"int buf[", "int *buf;", "int cap;"} {
		if strings.Contains(h[declStart:structAt], forbidden) {
			t.Errorf("C set scanner: struct still carries %q", forbidden)
		}
	}
	// The gate array stays inside: its length is a size the compiler knows,
	// not one the caller picks.
	if !strings.Contains(h, "unsigned gates[SCANNER_ID_SPACE];") {
		t.Error("C set scanner: gate array should stay stub-owned")
	}
	// (6): argument validation, and NOT rejecting the two things §4.2 makes
	// legitimate — an empty input and offset > len.
	for _, want := range []string{"return RX_ERR_NULL_ARG;", "return RX_ERR_RANGE;"} {
		if !strings.Contains(c, want) {
			t.Errorf("C set scanner: _init missing %q", want)
		}
	}
	if strings.Contains(c, "len == 0") {
		t.Error("C set scanner: an empty input is a legitimate scan and must not be refused")
	}
	// (4): the transactional overflow rule is reported, not hidden.
	if !strings.Contains(c, "if ((size_t)got > cap) return got;") {
		t.Error("C set scanner: over-capacity must return the position's total without advancing")
	}
}

// TestNamespacePrefixesOnlySharedSymbols covers the `namespace:` key (TODO
// task 62): it renames the symbols a stub declares that the USER did not name,
// which is exactly what two stubs in one package collide on, and leaves every
// user-chosen export name alone.
func TestNamespacePrefixesOnlySharedSymbols(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "demo",
		Namespace:    "acme",
		StubFile:     "stubs.go",
		Regexps: []config.RegexEntry{
			{Name: "u", Pattern: `(?P<host>[a-z.]+)`, GroupsFunc: "url_groups"},
		},
		Sets: []config.SetConfig{
			{Name: "sec", Find: "scan_secrets", Patterns: config.PatternSelector{All: true}, EmitNameMap: true},
		},
	}
	body, needsIter := genGoSetBody(cfg)
	single, _, err := genGoStubsBody(cfg.Regexps, cfg.ImportModule)
	if err != nil {
		t.Fatalf("genGoStubsBody: %v", err)
	}
	_ = needsIter
	out := applyNamespace(cfg, "go", goErrorPreamble(cfg, true)+single+body)

	for _, want := range []string{"acme_Span", "acme_ErrBacktrackOverflow", "acme_SetMatch", "acme_PatternName"} {
		if !strings.Contains(out, want) {
			t.Errorf("namespace: missing %q", want)
		}
	}
	// The user's own names, and anything derived from them, are untouched.
	for _, keep := range []string{"url_groups", "scan_secrets", "url_groups_host", "url_groups_index"} {
		if !strings.Contains(out, keep) {
			t.Errorf("namespace: user-chosen name %q should survive verbatim", keep)
		}
		if strings.Contains(out, "acme_"+keep) {
			t.Errorf("namespace: %q must not be prefixed — the key exists to let two stubs share a package, not to rename the API", keep)
		}
	}
	// Empty namespace changes nothing.
	cfg.Namespace = ""
	if got := applyNamespace(cfg, "go", "type Span struct{}"); got != "type Span struct{}" {
		t.Errorf("empty namespace should be a no-op, got %q", got)
	}
	// Rust is deliberately absent from the table: pub mod already isolates it.
	cfg.Namespace = "acme"
	if got := applyNamespace(cfg, "rust", "pub struct Span;"); got != "pub struct Span;" {
		t.Errorf("namespace should be a no-op for Rust, got %q", got)
	}
}
