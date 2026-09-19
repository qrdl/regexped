package generate

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// TestGenRustGroupIndexConsts covers what replaced `named_groups_func` in Rust:
// one constant per named group, a runtime lookup and an
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

// The Go generator's PascalCase transform is GONE: a name the
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

// TestGenGoGroupIndexConsts covers what replaced `named_groups_func` in Go.
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
			Pattern:    "(?P<scheme>https?)://(?P<host>[^/]+)"},
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
	h, c, err := genCStubFiles(entries, "mymod", "stub.h", false)
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
	h, c, err := genCStubFiles(entries, "mymod", "stub.h", false)
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
// in C: C used to REJECT the key outright, and now gets the
// named access it never had, through index constants.
func TestGenCStubFilesNamedGroupIndices(t *testing.T) {
	entries := []config.RegexEntry{
		{GroupsFunc: "url_groups", Pattern: "(?P<scheme>https?)://(?P<host>[^/]+)"},
	}
	h, _, err := genCStubFiles(entries, "mymod", "stub.h", false)
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
	for _, sub := range []string{"url_groups_indices", `"scheme": 1`, `"host": 2`} {
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
	for _, sub := range []string{"url_groups_indices", `"scheme": 1`, `"host": 2`} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSStubFile named pattern: missing %q", sub)
		}
	}
}

// TestGenJSGroupsFuncHasBatchPath and its TS/named-groups siblings verify the
// batch-detect-and-drain block is emitted by every groups/find
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
// different from `groups_func`'s; with the key retired there is
// only ever one name, so the checks below cover it.
// TestGenJSGroupIndices covers what replaced `named_groups_func` in JS (TODO
// one frozen name→index object, suffixed `indices` because without a
// suffix its derived name would collide with the generator function's.
func TestGenJSGroupIndices(t *testing.T) {
	out := genJSGroupIndices("url_groups", 4, map[string]int{"scheme": 1, "host": 2})
	for _, sub := range []string{
		"export const url_groups_indices = Object.freeze({",
		`"scheme": 1,`,
		`"host": 2,`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSGroupIndices: missing %q\ngot:\n%s", sub, out)
		}
	}
	if got := genJSGroupIndices("plain", 2, nil); got != "" {
		t.Errorf("genJSGroupIndices with no named groups: want empty, got %q", got)
	}
	// Go's regexp/syntax accepts a digit-leading group name; a BARE key of
	// that shape is a SyntaxError that takes the whole module down.
	if got := genJSGroupIndices("g", 2, map[string]int{"1a": 1}); !strings.Contains(got, `"1a": 1,`) {
		t.Errorf("genJSGroupIndices: digit-leading name not quoted\ngot:\n%s", got)
	}
}

func TestGenTSGroupIndices(t *testing.T) {
	out := genTSGroupIndices("url_groups", 4, map[string]int{"scheme": 1, "host": 2})
	for _, sub := range []string{
		"export const url_groups_indices = {",
		`"scheme": 1,`,
		`"host": 2,`,
		"} as const;",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSGroupIndices: missing %q\ngot:\n%s", sub, out)
		}
	}
	if got := genTSGroupIndices("plain", 2, nil); got != "" {
		t.Errorf("genTSGroupIndices with no named groups: want empty, got %q", got)
	}
	if got := genTSGroupIndices("g", 2, map[string]int{"1a": 1}); !strings.Contains(got, `"1a": 1,`) {
		t.Errorf("genTSGroupIndices: digit-leading name not quoted\ngot:\n%s", got)
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
		"SCANNER_PATTERN_COUNT",                  // the emitted constant
		"SCANNER_ID_SPACE",                       // the id-space constant
		"buf: [[i32; 3]; SCANNER_PATTERN_COUNT]", // tuples: at most one per pattern per position
		"gates: [u32; SCANNER_ID_SPACE]",         // indexed by pattern id
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
	// `find` is iterator-only; no stateless probe variant exists.
	if strings.Contains(out, "set_findAt") {
		t.Error("genRustSetInner: emitted a stateless find probe, which was removed")
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
		// The live buffer, not the cached `_mem` view: a call into the module
		// may grow memory and detach it.
		"_exp.memory.buffer",
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
		"(_exp.memory as WebAssembly.Memory).buffer",
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
// Go dropped out of this: its names are now verbatim, so
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
			// `int patterns[static <SET>_PATTERN_COUNT]`, which names the count legitimately — that is the
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

// TestRustSetIterBoxedAboveBudget pins the Rust set-iterator boxing budget.
//
// The Rust iterator is a VALUE: it is returned from the constructor, moved into
// a `for`, moved again by `.take()` or `.map()`. Holding PATTERN_COUNT tuples
// and ID_SPACE gates inline makes that value grow with the set — measured at
// 32,032 bytes for 2,000 patterns, which rustc turned into a memset, a memcpy
// and a 60 KB stack frame on a three-line adapter chain.
//
// Above the budget both arrays are boxed; below it nothing changes, which is
// the half worth pinning hardest — `find` allocating NOTHING is a property
// the caller-owned buffer design bought deliberately, and it must survive for the sets that can
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

// TestSetFindCScannerShape pins the caller-owned scanner shape for
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
	// (6): argument validation, and NOT rejecting the two things the contract makes
	// legitimate — an empty input and offset > len.
	for _, want := range []string{"return RX_ERR_NULL_ARG;", "return RX_ERR_RANGE;"} {
		if !strings.Contains(c, want) {
			t.Errorf("C set scanner: _init missing %q", want)
		}
	}
	if strings.Contains(c, "len == 0") {
		t.Error("C set scanner: an empty input is a legitimate scan and must not be refused")
	}
	// (4): a buffer below one position's worst case is REFUSED, the rule the
	// component format shares through the same header; the transactional
	// over-capacity arm it replaces is gone.
	if !strings.Contains(c, "if (cap < (size_t)SCANNER_PATTERN_COUNT) return RX_ERR_RANGE;") {
		t.Error("C set scanner: a cap below PATTERN_COUNT must be refused with RX_ERR_RANGE")
	}
	if strings.Contains(c, "if ((size_t)got > cap) return got;") {
		t.Error("C set scanner: the transactional over-capacity arm is still emitted")
	}
}

// TestNamespacePrefixesOnlySharedSymbols covers the `namespace:` key (TODO
// It renames the symbols a stub declares that the USER did not name,
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
	body, needsIter := genGoSetBody(cfg, newSetShapes(cfg))
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

// TestSharedSymbolsMirrorIsInStep pins config's copy of sharedSymbols against
// the list applyNamespace actually rewrites.
//
// The copy exists because generate imports config and not the reverse, so the
// config-side collision checks cannot read this list directly. A copy nothing
// compares is a copy that drifts — which is how an export named `Span` came to
// pass validation and then duplicate the Go type.
func TestSharedSymbolsMirrorIsInStep(t *testing.T) {
	for _, stubType := range []string{"go", "js", "ts", "as", "c", "rust"} {
		want := sharedSymbols[stubType]
		got := config.StubSharedSymbolsForValidation(stubType)
		if len(want) != len(got) {
			t.Errorf("%s: generate has %v, config mirrors %v", stubType, want, got)
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("%s: generate has %v, config mirrors %v", stubType, want, got)
				break
			}
		}
	}
}

// TestDerivedNameMatchesGenerator pins config's copy of derivedFuncName —
// which the derived-symbol collision check is built on —
// against the transform the generators actually apply. A check computing a
// different name than the generator emits is a check that reserves the wrong
// symbol and misses the real one.
func TestDerivedNameMatchesGenerator(t *testing.T) {
	for _, base := range []string{"url_groups", "urlGroups", "find", "a_b", "aB", "X"} {
		for _, suf := range []string{"index", "names", "count", "indices", "iter"} {
			if got, want := config.DerivedNameForValidation(base, suf), derivedFuncName(base, suf); got != want {
				t.Errorf("derivedName(%q, %q) = %q, generator emits %q", base, suf, got, want)
			}
		}
	}
}

// ── The set-stub descriptor helpers ────────────────────────────────────────
//
// The six language templates each used to hand-roll the argument list of every
// set export. They agreed at the time; what the shared descriptor removes is
// FORWARD drift — the cross-batch empty-match suppression that ended up in the
// find path and not the groups path is what that looks like when it happens.
//
// These helpers are pure functions over the config, so their refusals and
// their boundaries are testable directly rather than through six generated
// files.

// TestCapByKind covers the lookup, including the miss.
//
// A nil result means "the set did not declare this capability", and every
// caller must handle it — spellJSArgs is handed one directly. Returning a
// zero-valued capability instead would spell an argument list for an export
// that does not exist.
func TestCapByKind(t *testing.T) {
	caps := []setCapability{
		{Kind: "find", Export: "s_find"},
		{Kind: "scan_any", Export: "s_scan_any"},
	}
	if got := capByKind(caps, "find"); got == nil || got.Export != "s_find" {
		t.Errorf("capByKind(find) = %+v, want the find capability", got)
	}
	if got := capByKind(caps, "match_all"); got != nil {
		t.Errorf("capByKind(undeclared) = %+v, want nil", got)
	}
	if got := capByKind(nil, "find"); got != nil {
		t.Errorf("capByKind over no capabilities = %+v, want nil", got)
	}
}

// TestSpellJSArgs covers the renderer, every ABI parameter it can be handed,
// and both of its refusals.
//
// The nil guard matters because capByKind returns nil for an undeclared
// capability and the templates call straight through; the panic matters
// because a new ABI parameter with no JS spelling must stop the build rather
// than silently render an argument list one short.
func TestSpellJSArgs(t *testing.T) {
	s := jsArgSpelling{
		inPtr: "inPtr", inLen: "inLen", from: "from", gate: "gatePtr",
		bitmap: "bitmapPtr", tuple: "tuplePtr", outCap: "outCap", cursor: "cursor",
	}
	t.Run("nil capability spells nothing", func(t *testing.T) {
		if got := spellJSArgs(nil, s); got != "" {
			t.Errorf("spellJSArgs(nil) = %q, want the empty string", got)
		}
	})
	t.Run("every parameter has a spelling", func(t *testing.T) {
		all := &setCapability{Kind: "find", Params: []abiParam{
			abiInputPtr, abiInputLen, abiFrom, abiScratchPtr,
			abiBitmapPtr, abiTuplePtr, abiOutCap, abiCursor,
		}}
		got := spellJSArgs(all, s)
		want := "inPtr, inLen, from, gatePtr, bitmapPtr, tuplePtr, outCap, cursor"
		if got != want {
			t.Errorf("spellJSArgs = %q, want %q", got, want)
		}
	})
	t.Run("order follows the ABI, not the spelling struct", func(t *testing.T) {
		// Reversing the params must reverse the output: the renderer walks the
		// capability's list, which IS the export's signature.
		rev := &setCapability{Params: []abiParam{abiCursor, abiInputLen, abiInputPtr}}
		if got := spellJSArgs(rev, s); got != "cursor, inLen, inPtr" {
			t.Errorf("spellJSArgs = %q, want the parameters in ABI order", got)
		}
	})
	t.Run("an unspellable parameter stops the build", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("an unknown ABI parameter rendered instead of panicking")
			}
			if msg, ok := r.(string); !ok || !strings.Contains(msg, "JS spelling") {
				t.Errorf("panic %v does not name the cause", r)
			}
		}()
		// A parameter value no case handles. If a real one is ever added past
		// abiCursor this test starts passing for the wrong reason, which the
		// message above is there to make obvious.
		bogus := &setCapability{Params: []abiParam{abiCursor + 99}}
		_ = spellJSArgs(bogus, s)
	})
}

// TestDerivedFuncName covers the naming rule that keeps every generated symbol
// in the config's own casing: url_groups + index -> url_groups_index, but
// urlGroups + index -> urlGroupsIndex.
//
// The empty-suffix arm is the one no generator reaches today; it exists so a
// caller asking for the base name gets it rather than a trailing separator.
func TestDerivedFuncName(t *testing.T) {
	cases := []struct{ base, suffix, want string }{
		{"url_groups", "index", "url_groups_index"},
		{"url_groups", "", "url_groups"},
		{"urlGroups", "index", "urlGroupsIndex"},
		{"urlGroups", "", "urlGroups"},
		{"p", "names", "p_names"},
	}
	for _, c := range cases {
		if got := derivedFuncName(c.base, c.suffix); got != c.want {
			t.Errorf("derivedFuncName(%q, %q) = %q, want %q",
				c.base, c.suffix, got, c.want)
		}
	}
}

// TestDefaultBatchCapBounds covers the batch buffer sizing, which is clamped from
// BELOW by a floor and from ABOVE by what the cursor's count field can encode.
//
// The upper clamp is the interesting one: a buffer larger than the cursor can
// count would let a call report more matches than the resume cursor could
// describe, and the next call would restart in the wrong place.
func TestDefaultBatchCapBounds(t *testing.T) {
	mk := func(n int) (config.SetConfig, config.BuildConfig) {
		entries := make([]config.RegexEntry, n)
		for i := range entries {
			entries[i] = config.RegexEntry{
				Name: string(rune('a'+i%26)) + string(rune('0'+i/26)), Pattern: `x`,
			}
		}
		s := config.SetConfig{
			Name: "s", Find: "s_find", Patterns: config.PatternSelector{All: true},
		}
		return s, config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{s}}
	}
	t.Run("small sets take the floor", func(t *testing.T) {
		s, cfg := mk(3)
		if got := defaultBatchCap(s, cfg); got != 256 {
			t.Errorf("defaultBatchCap for 3 patterns = %d, want the 256 floor", got)
		}
	})
	t.Run("never exceeds what the cursor can count", func(t *testing.T) {
		s, cfg := mk(40)
		got := defaultBatchCap(s, cfg)
		if max := int(cursorMaxCount(s, cfg)); got > max {
			t.Errorf("defaultBatchCap = %d exceeds the cursor's maximum count %d", got, max)
		}
		if got < 1 {
			t.Errorf("defaultBatchCap = %d, want at least 1", got)
		}
	})
}

// The four per-language ABI SPELLERS, exercised over every parameter the
// descriptor can hand them.
//
// The descriptor in set_stub.go decides WHICH parameters a capability takes
// and in what order; each speller decides only how one is written. That split
// is the whole point of the shared descriptor — the generators stopped deciding the ABI — and it
// means a speller is a pure lookup, so the honest test is to hand it every
// value rather than wait for a set shape that happens to produce one.
//
// The gap that hid here: `abiBitmapPtr` is only produced by the WIDE `_all`
// form, so until a >64-id set appeared in some other test, a quarter of every
// speller was unwritten. A missing arm is not a compile error — the switch
// falls through to its panic — so nothing would have said so until a user with
// seventy patterns generated a stub.

func allABIParams() []abiParam {
	return []abiParam{
		abiInputPtr, abiInputLen, abiFrom, abiScratchPtr,
		abiBitmapPtr, abiTuplePtr, abiOutCap, abiCursor,
	}
}

func TestABISpellersHandleEveryParam(t *testing.T) {
	spellers := map[string]func(abiParam) string{
		"rust": rustABIParam,
		"go":   goABIParam,
		"c":    cABIParam,
		"as":   asABIParam,
	}
	for lang, spell := range spellers {
		t.Run(lang, func(t *testing.T) {
			seen := map[string]abiParam{}
			for _, p := range allABIParams() {
				got := func() (s string) {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s: param %d panicked: %v", lang, p, r)
						}
					}()
					return spell(p)
				}()
				if strings.TrimSpace(got) == "" {
					t.Errorf("%s: param %d spelled as empty", lang, p)
					continue
				}
				// Two parameters may share a spelling only when they share a
				// slot by design — Go and AssemblyScript write the bitmap and
				// the tuple buffer the same way, because both are just a
				// pointer there. Anything else is two ABI positions that would
				// be indistinguishable in a generated signature.
				if prev, dup := seen[got]; dup {
					sharedSlot := (prev == abiBitmapPtr && p == abiTuplePtr) ||
						(prev == abiTuplePtr && p == abiBitmapPtr)
					if !sharedSlot {
						t.Errorf("%s: params %d and %d both spell as %q", lang, prev, p, got)
					}
				}
				seen[got] = p
			}
		})
	}
}

// TestABISpellersRejectUnknownParam: the switches end in a panic on purpose.
// A new abiParam that a speller has not learned must stop the build loudly
// rather than emit a signature missing an argument, which would fail much
// later as an arity mismatch in someone else's compiler.
func TestABISpellersRejectUnknownParam(t *testing.T) {
	unknown := abiParam(9999)
	for lang, spell := range map[string]func(abiParam) string{
		"rust": rustABIParam,
		"go":   goABIParam,
		"c":    cABIParam,
		"as":   asABIParam,
	} {
		t.Run(lang, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("an unknown abiParam was spelled instead of rejected")
				}
			}()
			spell(unknown)
		})
	}
}

// TestABIRetSpellers covers the return-type half, which is only two values but
// decides whether a capability hands back a bitmask or a count.
func TestABIRetSpellers(t *testing.T) {
	for lang, spell := range map[string]func(abiRet) string{
		"rust": rustABIRet,
		"go":   goABIRet,
		"c":    cABIRet,
		"as":   asABIRet,
	} {
		t.Run(lang, func(t *testing.T) {
			i32, i64 := spell(abiRetI32), spell(abiRetI64)
			if i32 == "" || i64 == "" {
				t.Fatalf("empty return spelling: i32=%q i64=%q", i32, i64)
			}
			if i32 == i64 {
				t.Errorf("i32 and i64 both spell as %q; a 64-bit bitmask would "+
					"be truncated to a count with no diagnostic", i32)
			}
		})
	}
}

// TestMustCapByKindPanicsOnDisagreement covers the guard the C, Go and AS set
// generators share. Nothing a config can express reaches it — each generator
// asks only inside `if s.<Cap> != ""`, where setCapabilities has added the
// capability by construction — so it is driven directly: a nil return there
// means the two have drifted, and a nil dereference would report that as a
// crash somewhere downstream instead.
func TestMustCapByKindPanicsOnDisagreement(t *testing.T) {
	capSet := config.SetConfig{
		Name:     "s",
		Patterns: config.PatternSelector{All: true},
		Find:     "s_find",
	}
	capCfg := config.BuildConfig{Regexps: []config.RegexEntry{{Pattern: "a"}}}
	caps := setCapabilities(capSet, capCfg, wideAllForm(capSet, capCfg))

	if got := mustCapByKind(caps, "find", "C"); got == nil || got.Export != "s_find" {
		t.Fatalf("mustCapByKind(find) = %+v, want the declared find", got)
	}

	for _, lang := range []string{"C", "Go", "AS"} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("%s: mustCapByKind on an undeclared capability did not panic", lang)
					return
				}
				msg, _ := r.(string)
				if !strings.Contains(msg, lang) || !strings.Contains(msg, "match_any") {
					t.Errorf("%s: panic = %q, want it to name the language and the kind", lang, msg)
				}
			}()
			mustCapByKind(caps, "match_any", lang)
		}()
	}
}

// TestGenerateStubRejectsUnknownType covers the dispatch arm that exists as the
// net under adding a stub type to config.ResolveStubType and forgetting it here.
func TestGenerateStubRejectsUnknownType(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "m",
		Regexps:      []config.RegexEntry{{Pattern: "a", MatchFunc: "a_match"}},
	}
	err := generateStub(cfg, "kotlin", filepath.Join(t.TempDir(), "stub.kt"))
	if err == nil {
		t.Fatal("generateStub with an unknown type succeeded")
	}
	if !strings.Contains(err.Error(), "unknown stub type") {
		t.Errorf("error = %v, want it to name the unknown type", err)
	}
}

// TestCmdGenerateStubDispatchesEveryResolvableType is the other half: every type
// config.ResolveStubType can return must reach a generator, not the arm above.
func TestCmdGenerateStubDispatchesEveryResolvableType(t *testing.T) {
	for _, tc := range []struct{ stubType, ext string }{
		{"rust", ".rs"}, {"js", ".js"}, {"ts", ".ts"},
		{"go", ".go"}, {"c", ".h"}, {"as", ".ts"}, {"wit", ".wit"},
	} {
		t.Run(tc.stubType, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.BuildConfig{
				ImportModule: "m",
				StubType:     tc.stubType,
				Output:       "merged.wasm",
				WasmFile:     "m.wasm",
				Regexps:      []config.RegexEntry{{Pattern: "a", MatchFunc: "a_match"}},
			}
			if tc.stubType == "wit" {
				cfg.WasmFormat = "component"
			}
			err := CmdGenerateStub(cfg, filepath.Join(dir, "stub"+tc.ext))
			if err != nil && strings.Contains(err.Error(), "unknown stub type") {
				t.Fatalf("%s is resolvable but not dispatched: %v", tc.stubType, err)
			}
			if err != nil {
				t.Fatalf("CmdGenerateStub: %v", err)
			}
		})
	}
}

// TestDefaultBatchCapClampsToCursorCount covers the clamp. The cursor packs the
// per-position index k and the tuple count into one 32-bit word, so a set wide
// enough to need many k bits leaves fewer count bits than the 256 default — and
// a buffer larger than the count field can report would have the iterator
// believe a short call was a full one.
func TestDefaultBatchCapClampsToCursorCount(t *testing.T) {
	small := config.SetConfig{Name: "s", Patterns: config.PatternSelector{Names: []string{"a", "b"}}}
	cfg := config.BuildConfig{}
	if got := defaultBatchCap(small, cfg); got != 256 {
		t.Errorf("defaultBatchCap(2 patterns) = %d, want the 256 default", got)
	}

	// 70_000 patterns: 17 k bits leave 15 count bits, so the count field tops
	// out at 32767 — below the pattern count, which is what the default would
	// otherwise be.
	wide := config.SetConfig{Name: "w", Patterns: config.PatternSelector{Names: make([]string, 70_000)}}
	max := int(config.SetCursorMaxCount(70_000))
	if max >= 70_000 {
		t.Fatalf("cursor max count %d is not below the pattern count; the clamp is unreachable", max)
	}
	if got := defaultBatchCap(wide, cfg); got != max {
		t.Errorf("defaultBatchCap(70000 patterns) = %d, want the cursor maximum %d", got, max)
	}
}

// TestGenGoSetSectionWithoutIter covers the no-iterator arm of the
// backward-compatible wrapper: a set declaring no `find` needs no `iter` import,
// and emitting one would not compile.
func TestGenGoSetSectionWithoutIter(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "m",
		Regexps:      []config.RegexEntry{{Name: "a", Pattern: "[a-z]+"}, {Name: "b", Pattern: "[0-9]+"}},
		Sets: []config.SetConfig{{
			Name:     "s",
			Patterns: config.PatternSelector{All: true},
			MatchAny: "s_which",
		}},
	}
	got := genGoSetSection(cfg, "m")
	if got == "" {
		t.Fatal("genGoSetSection returned nothing for a set declaring match_any")
	}
	if strings.Contains(got, `"iter"`) {
		t.Errorf("a set with no find imported iter:\n%s", got)
	}
	if !strings.Contains(got, "func s_which(") {
		t.Errorf("match_any wrapper missing:\n%s", got)
	}

	// And nothing at all when there is no set to emit.
	if got := genGoSetSection(config.BuildConfig{ImportModule: "m"}, "m"); got != "" {
		t.Errorf("genGoSetSection with no sets = %q, want empty", got)
	}
}

// TestGenGoStubFileEmpty covers the early return of the backward-compatible
// wrapper: entries with no _func fields produce no stub at all, and a file
// holding only a package clause is worse than no file.
func TestGenGoStubFileEmpty(t *testing.T) {
	got, err := genGoStubFile([]config.RegexEntry{{Pattern: "[a-z]+"}}, "m", "m")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("genGoStubFile for a func-less entry = %q, want empty", got)
	}
	if _, err := genGoStubFile([]config.RegexEntry{{Pattern: "(", GroupsFunc: "g"}}, "m", "m"); err == nil {
		t.Error("genGoStubFile on an unparseable pattern succeeded")
	}
}

// ---------------------------------------------------------------------------
// Component stub edges.

// TestCComponentStubWriteFailures covers the two write arms. They are separate
// because the .h and the .c are two files and a build with only one of them is
// worse than a build with neither: the header alone compiles and links to
// nothing.
func TestCComponentStubWriteFailures(t *testing.T) {
	cfg := cComponentCfg()

	t.Run("header", func(t *testing.T) {
		dir := t.TempDir()
		// A FILE where the stub's parent directory must be, so MkdirAll fails.
		blocker := filepath.Join(dir, "blocked")
		if err := os.WriteFile(blocker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		err := cComponentStub(cfg, filepath.Join(blocker, "stub.c"))
		if err == nil {
			t.Fatal("cComponentStub into an unwritable directory succeeded")
		}
	})

	t.Run("body", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "stub.c")
		// A DIRECTORY where the .c must go: the .h beside it writes fine, so
		// this is the only way to reach the second arm.
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		err := cComponentStub(cfg, out)
		if err == nil {
			t.Fatal("cComponentStub over a directory succeeded")
		}
		if _, statErr := os.Stat(filepath.Join(dir, "stub.h")); statErr != nil {
			t.Errorf("the header was not written first, so the .c arm was not what failed: %v", statErr)
		}
	})
}

// TestWriteComponentWitDirRejectsUnrepresentableName covers the error arm of the
// WIT-directory writer. cComponentStub cannot reach it — genCComponentStubFiles
// runs witParts first and fails there — so it is driven directly, because an arm
// that cannot be called is an arm that cannot be shown to still report.
func TestWriteComponentWitDirRejectsUnrepresentableName(t *testing.T) {
	cfg := cComponentCfg()
	cfg.WitPackage = "Not_A_Wit_Name"
	err := writeComponentWitDir(cfg, filepath.Join(t.TempDir(), "wit"))
	if err == nil {
		t.Fatal("writeComponentWitDir accepted an unrepresentable wit_package")
	}
	if !strings.Contains(err.Error(), "wit_package") {
		t.Errorf("error = %v, want it to name the key the user must edit", err)
	}
}

// TestCComponentStubVersionedImports pins the version's placement in BOTH the
// interface import the .c declares and the WIT the consumer builds against —
// the version goes after the INTERFACE name, and the two must agree or
// `component new` cannot find the export.
func TestCComponentStubVersionedImports(t *testing.T) {
	cfg := cComponentCfg()
	cfg.WitVersion = "2.3.0"
	dir := t.TempDir()
	if err := cComponentStub(cfg, filepath.Join(dir, "stub.c")); err != nil {
		t.Fatal(err)
	}
	cText, err := os.ReadFile(filepath.Join(dir, "stub.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"regexped:urlparts/matcher@2.3.0", "regexped:urlparts/sets@2.3.0"} {
		if !strings.Contains(string(cText), want) {
			t.Errorf(".c does not import %q", want)
		}
	}
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"import regexped:urlparts/matcher@2.3.0;",
		"import regexped:urlparts/sets@2.3.0;",
	} {
		if !strings.Contains(string(consumer), want) {
			t.Errorf("consumer.wit does not carry %q:\n%s", want, consumer)
		}
	}
}

// TestStripExportWorldOneLineWorld covers the single-line world. A `world x {}`
// opens and closes on one line, so the depth counter must settle on that line
// rather than swallow the rest of the document.
func TestStripExportWorldOneLineWorld(t *testing.T) {
	in := "package regexped:m;\n\ninterface matcher {\n    x: func() -> u32;\n}\n\nworld m { }\n\ninterface after {\n}\n"
	got := stripExportWorld(in)
	if strings.Contains(got, "world m") {
		t.Errorf("the world survived:\n%s", got)
	}
	for _, want := range []string{"interface matcher {", "interface after {"} {
		if !strings.Contains(got, want) {
			t.Errorf("stripExportWorld swallowed %q:\n%s", want, got)
		}
	}
}

// TestComponentStubsRejectUnparseablePattern covers the group-info error arms of
// both component generators. `groups_func` is the only field whose stub needs
// the pattern's shape, so it is the only one a bad pattern can fail.
func TestComponentStubsRejectUnparseablePattern(t *testing.T) {
	cfg := config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "m",
		WasmFile:     "m.wasm",
		Regexps:      []config.RegexEntry{{Pattern: "(?P<a>", GroupsFunc: "g"}},
	}
	if _, _, err := genCComponentStubFiles(cfg, "stub.h"); err == nil {
		t.Error("genCComponentStubFiles accepted an unparseable pattern")
	}
	if _, err := genRustComponentStubFile(cfg); err == nil {
		t.Error("genRustComponentStubFile accepted an unparseable pattern")
	}
	if _, err := genRustComponentInner(cfg, map[string]string{"g": "g"}); err == nil {
		t.Error("genRustComponentInner accepted an unparseable pattern")
	}
}

// The stub writers' FAILURE paths.
//
// Every one of these functions ends by writing a file, and every one of them
// can fail there — an unwritable directory, a path that is not a directory, a
// stub type nothing recognises. Those arms were unreached, which for a CLI is
// the wrong place to be untested: a swallowed write error means `regexped
// generate` reports success and produces nothing, and the next build fails
// somewhere else entirely with a missing import.

func errCfg(stubFile string) config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "demo",
		StubFile:     stubFile,
		Regexps: []config.RegexEntry{
			{Name: "p", Pattern: `[a-z]+`, MatchFunc: "p_match", FindFunc: "p_find"},
		},
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Patterns: config.PatternSelector{All: true},
		}},
	}
}

// unwritablePath returns a path whose PARENT is a regular file, so any attempt
// to create it fails with ENOTDIR. More portable than relying on permissions,
// which root ignores.
func unwritablePath(t *testing.T, name string) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, name)
}

// TestStubWritersReportWriteFailures: each generator must surface the error
// rather than report success having written nothing.
func TestStubWritersReportWriteFailures(t *testing.T) {
	for _, w := range []struct {
		kind string
		file string
		gen  func(config.BuildConfig, string) error
	}{
		{"rust", "stubs.rs", rustStub},
		{"go", "stubs.go", goStub},
		{"js", "stubs.js", jsStub},
		{"ts", "stubs.ts", tsStub},
		{"c", "stubs.h", cStub},
		{"as", "stubs.ts", asStub},
	} {
		t.Run(w.kind, func(t *testing.T) {
			out := unwritablePath(t, w.file)
			if err := w.gen(errCfg(out), out); err == nil {
				t.Error("reported success writing into a path that cannot exist")
			}
		})
	}
}

// TestCmdGenerateStubRejectsUnknownType covers the dispatch: an extension
// nothing recognises has to be refused before any generator runs, or the CLI
// silently does nothing.
func TestCmdGenerateStubRejectsUnknownType(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"stubs.py", "stubs", "stubs.txt"} {
		out := filepath.Join(dir, name)
		err := CmdGenerateStub(errCfg(out), out)
		if err == nil {
			t.Errorf("%s: accepted an unrecognised stub type", name)
			continue
		}
		if !strings.Contains(err.Error(), "stub") {
			t.Errorf("%s: error %q does not explain the stub type", name, err)
		}
	}
}

// TestCmdGenerateStubWritesEachType drives the dispatch's SUCCESS arms, one
// per language, through the same entry point the CLI uses.
func TestCmdGenerateStubWritesEachType(t *testing.T) {
	for _, c := range []struct{ file, mustContain string }{
		{"stubs.rs", "p_match"},
		{"stubs.go", "p_match"},
		{"stubs.js", "p_match"},
		{"stubs.ts", "p_match"},
		{"stubs.h", "p_match"},
	} {
		t.Run(c.file, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "demo")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, c.file)
			if err := CmdGenerateStub(errCfg(out), out); err != nil {
				t.Fatalf("CmdGenerateStub: %v", err)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("nothing written: %v", err)
			}
			if !strings.Contains(string(b), c.mustContain) {
				t.Errorf("output does not mention %q", c.mustContain)
			}
		})
	}
}

// TestCmdGenerateStubExplicitType: `stub_type:` overrides the extension, so a
// `.txt` path is legal when the type says otherwise. This is the arm that lets
// a user write the stub anywhere they like.
func TestCmdGenerateStubExplicitType(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "stubs.txt")
	cfg := errCfg(out)
	cfg.StubType = "rust"
	if err := CmdGenerateStub(cfg, out); err != nil {
		t.Fatalf("CmdGenerateStub with an explicit type: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "pub mod") {
		t.Error("explicit stub_type rust did not produce Rust")
	}
}

// ── The two arms every stub writer shares ──────────────────────────────────
//
// Each of the six generators ends the same way: build the content, return
// early if there is none, then write it either to a file or to stdout. Both
// early arms were unreached.
//
// "No content" is not a hypothetical. An entry with a pattern but no `_func`
// fields is explicitly VALID — the compiler skips it silently and emits no
// WASM for it — so a config made entirely of such entries must produce no stub
// rather than an empty file. A file with only a header would look to the next
// build like a stub whose functions had all vanished.

// noFuncCfg is a config whose entries are valid but contribute nothing: a
// pattern with no capability requested.
func noFuncCfg(stubFile string) config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "demo",
		StubFile:     stubFile,
		Regexps: []config.RegexEntry{
			{Name: "a", Pattern: `[a-z]+`},
			{Name: "b", Pattern: `[0-9]+`},
		},
	}
}

// FOUR of the six generators guard against this and write no file at all:
// rust (`allInner == ""`), go (`singleBody == "" && setBody == ""`), c
// (`hContent == ""`) and as (`content == ""`).
//
// JS and TS carry NO such guard and write a zero-byte file instead. That is an
// inconsistency rather than a decision — an empty .js that a build imports
// fails later with "module has no exports", which is the diagnosis the other
// four generators' guards exist to avoid — but changing it changes CLI
// behaviour, so this test records what each one does today and names the
// difference rather than papering over it.
func TestStubWritersProduceNothingWithoutCapabilities(t *testing.T) {
	cases := []struct {
		stubType  string
		wantsFile bool // true = writes a (zero-byte) file rather than skipping
	}{
		{"rust", false},
		{"go", false},
		{"c", false},
		{"as", false},
		{"js", true}, // no empty guard — see the comment above
		{"ts", true},
	}
	for _, tc := range cases {
		t.Run(tc.stubType, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "stub.out")
			cfg := noFuncCfg(out)
			cfg.StubType = tc.stubType
			if err := CmdGenerateStub(cfg, out); err != nil {
				t.Fatalf("CmdGenerateStub: %v", err)
			}
			b, err := os.ReadFile(out)
			switch {
			case tc.wantsFile:
				if os.IsNotExist(err) {
					t.Skipf("%s now skips the write too — the guard was added; "+
						"update this table", tc.stubType)
				}
				if err != nil {
					t.Fatalf("stat: %v", err)
				}
				if len(b) != 0 {
					t.Errorf("wrote %d bytes for a config with no capabilities:\n%s",
						len(b), b)
				}
			default:
				if err == nil {
					t.Errorf("%s wrote a %d-byte stub where it should have "+
						"written nothing", tc.stubType, len(b))
				} else if !os.IsNotExist(err) {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestStubWritersToStdout covers the `-` path, which the CLI uses for
// `regexped generate -o -` and which writes through a different call than the
// file path does.
func TestStubWritersToStdout(t *testing.T) {
	cfg := func(stubType string) config.BuildConfig {
		return config.BuildConfig{
			ImportModule: "demo",
			StubFile:     "stub." + stubType,
			StubType:     stubType,
			Regexps: []config.RegexEntry{
				{Name: "p", Pattern: `[a-z]+`, MatchFunc: "p_match", FindFunc: "p_find"},
			},
		}
	}
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := CmdGenerateStub(cfg(stubType), "-"); err != nil {
					t.Fatalf("CmdGenerateStub(-): %v", err)
				}
			})
			if strings.TrimSpace(out) == "" {
				t.Fatal("stdout path produced nothing")
			}
			// Whatever the language, the generated text must name the export
			// it was asked for — that is the one thing all six share.
			if !strings.Contains(out, "p_match") && !strings.Contains(out, "p_find") {
				t.Errorf("stdout output names neither export:\n%s", out)
			}
		})
	}
}

// captureStdout redirects os.Stdout for the duration of fn. The stub writers
// print rather than taking a writer, so this is the only way to reach that arm.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}

// TestCmdGenerateStubUnknownType covers the dispatcher's default arm.
//
// config.ResolveStubType is what normally rejects an unknown type, so this arm
// is only reachable if the two ever disagree — which is exactly when a silent
// fallthrough would be worst, because the CLI would report success and write
// nothing at all.
func TestCmdGenerateStubUnknownType(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "demo",
		StubFile:     filepath.Join(t.TempDir(), "stub.xyz"),
		Regexps: []config.RegexEntry{
			{Name: "p", Pattern: `[a-z]+`, MatchFunc: "p_match"},
		},
	}
	err := CmdGenerateStub(cfg, cfg.StubFile)
	if err == nil {
		t.Fatal("an unresolvable stub type reported success")
	}
	if !strings.Contains(err.Error(), "xyz") && !strings.Contains(err.Error(), "stub type") {
		t.Errorf("error %q names neither the extension nor the problem", err)
	}
}

// ── When a pattern will not parse ──────────────────────────────────────────
//
// Every generator reads the pattern back to learn its capture groups, so an
// unparseable one fails INSIDE generation rather than at config load. The
// error then has to travel up through three or four frames to the CLI.
//
// Each of those frames returns the error rather than logging it, and none of
// them was covered. That is the wrong arm to leave untested for a code
// generator: a swallowed error means `regexped generate` reports success and
// writes a stub with the broken entry silently missing, and the next build
// fails somewhere else entirely with an unresolved symbol.
//
// The config layer does not reject this — patterns are validated by the
// COMPILER, and a stub can legitimately be generated without compiling — so
// the path is reachable in ordinary use, not just in tests.
func badPatternCfg(stubType, out string) config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "demo",
		StubFile:     out,
		StubType:     stubType,
		Regexps: []config.RegexEntry{
			// A valid entry first, so the failure happens PART WAY through
			// the loop rather than on its first iteration — the shape that
			// would otherwise let a generator emit a partial file.
			{Name: "ok", Pattern: `[a-z]+`, GroupsFunc: "ok_groups"},
			{Name: "bad", Pattern: `([a-z]+`, GroupsFunc: "bad_groups"},
		},
	}
}

func TestStubGeneratorsPropagateParseErrors(t *testing.T) {
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "stub.out")
			err := CmdGenerateStub(badPatternCfg(stubType, out), out)
			if err == nil {
				t.Fatal("an unparseable pattern generated a stub and reported success")
			}
			// The message must be traceable to the pattern. Without that the
			// user is told only that generation failed, on a config that may
			// hold hundreds of entries.
			if !strings.Contains(err.Error(), "missing closing )") &&
				!strings.Contains(err.Error(), "error parsing regexp") {
				t.Errorf("error %q does not explain what failed to parse", err)
			}
		})
	}
}

// TestStubGeneratorsWriteNothingOnParseError is the half that matters most: a
// failed generation must not leave a partial file behind for the next build to
// pick up.
func TestStubGeneratorsWriteNothingOnParseError(t *testing.T) {
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "stub.out")
			if err := CmdGenerateStub(badPatternCfg(stubType, out), out); err == nil {
				t.Fatal("expected an error")
			}
			entries, err := readDirNames(dir)
			if err != nil {
				t.Fatalf("read temp dir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("a failed generation left %v behind", entries)
			}
		})
	}
}

func readDirNames(dir string) ([]string, error) {
	des, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		out = append(out, filepath.Base(d))
	}
	return out, nil
}

// Generated symbols keep the config's casing VERBATIM. That
// was a deliberate choice — a user who writes `url_match` gets `url_match` —
// and it has one consequence worth telling them about: in Go a lower-case name
// is unexported, so in a LIBRARY package the generated function is invisible
// outside it.
//
// The decision was to WARN, not to rename and not to reject: if the user wants
// it private to the package, that is their call. So the contract has three
// parts and all three matter — the stub still generates, the name is
// untouched, and the warning is conditional.
//
// Which package the stub lands in is not configured directly: `goStub` infers
// it from the OUTPUT PATH, using `main` unless the parent directory is named
// after the import module. That inference is the thing being exercised here,
// so these tests write real files rather than calling the string builder.

func writeGoStub(t *testing.T, dirName, importModule, matchFunc, setFind string) string {
	t.Helper()
	src, _ := writeGoStubCapturingLog(t, dirName, importModule, matchFunc, setFind)
	return src
}

// writeGoStubCapturingLog is writeGoStub plus the slog output goStub produced
// while running. The warning is the whole point of this file, and it is not
// observable in the generated source — only in the log — so the tests that
// assert it need this rather than the string builder.
//
// slog.SetDefault is process-global, so these tests must not run in parallel
// with anything else in the package that logs.
func writeGoStubCapturingLog(t *testing.T, dirName, importModule, matchFunc, setFind string) (string, string) {
	t.Helper()
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	return writeGoStubInner(t, dirName, importModule, matchFunc, setFind), logBuf.String()
}

func writeGoStubInner(t *testing.T, dirName, importModule, matchFunc, setFind string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "stubs.go")
	cfg := config.BuildConfig{
		ImportModule: importModule,
		StubFile:     out,
		Regexps: []config.RegexEntry{
			{Name: "p", Pattern: `[a-z]+`, MatchFunc: matchFunc},
		},
	}
	if setFind != "" {
		cfg.Sets = []config.SetConfig{{
			Name: "s", Find: setFind, Patterns: config.PatternSelector{All: true},
		}}
	}
	if err := goStub(cfg, out); err != nil {
		t.Fatalf("goStub: %v", err)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// TestGoStubKeepsNamesVerbatim: the name the user wrote is the name emitted,
// whatever its case, and the removed PascalCase transform has not
// come back.
func TestGoStubKeepsNamesVerbatim(t *testing.T) {
	src := writeGoStub(t, "mylib", "mylib", "url_match", "scan_all_secrets")
	for _, want := range []string{"func url_match(", "func scan_all_secrets("} {
		if !strings.Contains(src, want) {
			t.Errorf("generated stub lacks %q — the name was transformed", want)
		}
	}
	for _, unwanted := range []string{"func UrlMatch(", "func ScanAllSecrets("} {
		if strings.Contains(src, unwanted) {
			t.Errorf("generated stub contains %q: names must be verbatim", unwanted)
		}
	}
}

// TestGoStubPackageNameFromOutputPath drives both arms of the package-name
// inference, which is what decides whether the unexported-name warning is
// meaningful at all.
//
// A stub written into a directory named after the import module is a LIBRARY
// package, where a lower-case name is invisible to callers. Anywhere else it
// is `main`, which exports nothing to anyone and where the warning would be
// pure noise.
func TestGoStubPackageNameFromOutputPath(t *testing.T) {
	cases := []struct {
		name      string
		dirName   string
		module    string
		matchFunc string
		setFind   string
		wantPkg   string
	}{
		{"library package, unexported names", "mylib", "mylib", "url_match", "scan_secrets", "mylib"},
		{"library package, exported names", "mylib", "mylib", "URLMatch", "ScanSecrets", "mylib"},
		{"directory does not match the module: main", "cmd", "mylib", "url_match", "scan_secrets", "main"},
		{"library package, mixed casing", "mylib", "mylib", "URLMatch", "scan_secrets", "mylib"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := writeGoStub(t, c.dirName, c.module, c.matchFunc, c.setFind)
			if !strings.Contains(src, "package "+c.wantPkg+"\n") {
				t.Errorf("stub is not in package %q", c.wantPkg)
			}
			// Generation SUCCEEDS in every case: the warning is advice, never
			// a rejection.
			if !strings.Contains(src, "func "+c.matchFunc+"(") {
				t.Errorf("stub does not declare %q", c.matchFunc)
			}
			if c.setFind != "" && !strings.Contains(src, c.setFind) {
				t.Errorf("stub does not mention the set export %q", c.setFind)
			}
		})
	}
}

// TestGoStubWarnsOnlyForHiddenLibraryNames asserts the WARNING itself, which no
// other test in this file can see: it is emitted through slog and leaves no
// trace in the generated source. Without this, the warning could disappear
// entirely, fire for package main where it is pure noise, or name the wrong
// symbols, and every other case here would still pass.
func TestGoStubWarnsOnlyForHiddenLibraryNames(t *testing.T) {
	cases := []struct {
		name      string
		dirName   string
		module    string
		matchFunc string
		setFind   string
		wantWarn  bool
		wantNames []string
	}{
		{
			name:    "library package, both names unexported: warns and names both",
			dirName: "mylib", module: "mylib",
			matchFunc: "url_match", setFind: "scan_secrets",
			wantWarn: true, wantNames: []string{"url_match", "scan_secrets"},
		},
		{
			name:    "library package, both names exported: silent",
			dirName: "mylib", module: "mylib",
			matchFunc: "URLMatch", setFind: "ScanSecrets",
			wantWarn: false,
		},
		{
			// The set export is the only hidden one, so it must be the only
			// one named — a warning that lists every symbol would be useless.
			name:    "library package, mixed casing: names only the hidden one",
			dirName: "mylib", module: "mylib",
			matchFunc: "URLMatch", setFind: "scan_secrets",
			wantWarn: true, wantNames: []string{"scan_secrets"},
		},
		{
			// package main exports nothing to anyone, so the advice does not
			// apply and the warning would be noise.
			name:    "package main, unexported names: silent",
			dirName: "cmd", module: "mylib",
			matchFunc: "url_match", setFind: "scan_secrets",
			wantWarn: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, logs := writeGoStubCapturingLog(t, c.dirName, c.module, c.matchFunc, c.setFind)
			got := strings.Contains(logs, "not exported")
			if got != c.wantWarn {
				t.Fatalf("warning emitted = %v, want %v; log was:\n%s", got, c.wantWarn, logs)
			}
			if !c.wantWarn {
				return
			}
			for _, want := range c.wantNames {
				if !strings.Contains(logs, want) {
					t.Errorf("warning does not name %q; log was:\n%s", want, logs)
				}
			}
			if c.matchFunc == "URLMatch" && strings.Contains(logs, "URLMatch") {
				t.Errorf("warning names the EXPORTED symbol URLMatch; log was:\n%s", logs)
			}
		})
	}
}

// A matrix over the six stub generators.
//
// The existing tests here are mostly assertions about ONE generator's output
// text for ONE shape. That leaves whole arms unreached: a set with no `find`,
// a set with only anchored capabilities, the wide `_all` form, a config with
// no sets at all, a config with several sets, and the batching entry — each of
// which changes what a generator emits, and several of which change it in ALL
// SIX languages at once.
//
// TestGeneratedStubsCompile hands one config to every real compiler and is the
// stronger check; it is also slow and needs four toolchains. This is the cheap
// companion: many shapes, six generators, checking the generator RUNS and
// produces something with the promised names in it.

type stubShape struct {
	name    string
	selects string
	cfg     config.BuildConfig
	// wantAll are substrings every language's output must contain.
	wantAll []string
}

func entry(name, pattern string, match, find, groups bool) config.RegexEntry {
	e := config.RegexEntry{Name: name, Pattern: pattern}
	if match {
		e.MatchFunc = name + "_match"
	}
	if find {
		e.FindFunc = name + "_find"
	}
	if groups {
		e.GroupsFunc = name + "_groups"
	}
	return e
}

func manyEntries(n int) []config.RegexEntry {
	out := make([]config.RegexEntry, n)
	for i := range out {
		out[i] = config.RegexEntry{
			Name: fmt.Sprintf("p%02d", i), Pattern: fmt.Sprintf("lit%02d[a-z]+", i),
		}
	}
	return out
}

func stubShapes() []stubShape {
	base := []config.RegexEntry{
		entry("url", `(?P<scheme>https?)://(?P<host>[a-z.]+)/`, true, true, true),
		entry("num", `[0-9]+`, true, true, false),
	}
	return []stubShape{
		{
			name: "patterns-only", selects: "a config with NO sets: the single-pattern arms alone",
			cfg:     config.BuildConfig{ImportModule: "demo", Regexps: base},
			wantAll: []string{"url_match", "url_find", "url_groups", "num_match"},
		},
		{
			name: "find-only-set", selects: "a set declaring only `find`",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "scan_all", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"scan_all"},
		},
		{
			name: "anchored-only-set", selects: "a set with only the anchored pair, and hence no find machinery",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", MatchAny: "which", MatchAll: "all_kinds",
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"which", "all_kinds"},
		},
		{
			name: "scan-only-set", selects: "a set with only the scan pair",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", ScanAny: "first_hit", ScanAll: "every_hit",
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"first_hit", "every_hit"},
		},
		{
			name: "overlapping-batch-set", selects: "`overlapping: true` plus `hints: [batch-find]` — the answer-cache shape",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "scan_overlapping",
					Patterns:    config.PatternSelector{All: true},
					Overlapping: true, Hints: []string{"batch-find"},
				}},
			},
			wantAll: []string{"scan_overlapping"},
		},
		{
			name: "wide-all-set", selects: "the WIDE `_all` form: past 64 ids the bitmask becomes a memory bitmap",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: manyEntries(70),
				Sets: []config.SetConfig{{
					Name: "s", MatchAll: "wide_all", ScanAll: "wide_scan_all",
					Find: "wide_find", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"wide_all", "wide_scan_all", "wide_find"},
		},
		{
			name: "named-subset-set", selects: "ID_SPACE > PATTERN_COUNT, which sizes the gate array and the bitmap",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: manyEntries(20),
				Sets: []config.SetConfig{{
					Name: "s", Find: "subset_find", MatchAll: "subset_all",
					Patterns: config.PatternSelector{Names: []string{"p00", "p19"}},
				}},
			},
			wantAll: []string{"subset_find", "subset_all"},
		},
		{
			name: "two-sets", selects: "several sets in one config, whose derived constants must not collide",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{
					{Name: "alpha", Find: "alpha_find", Patterns: config.PatternSelector{All: true}},
					{Name: "beta", MatchAny: "beta_any", Patterns: config.PatternSelector{All: true}},
				},
			},
			wantAll: []string{"alpha_find", "beta_any"},
		},
		{
			name: "name-map", selects: "emit_name_map, which adds the pattern-name helper",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "named_find", EmitNameMap: true,
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"named_find"},
		},
		{
			name: "namespace", selects: "the optional namespace, which prefixes symbols with no user name to inherit",
			cfg: config.BuildConfig{
				ImportModule: "demo", Namespace: "rx2", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "ns_find", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"ns_find"},
		},
	}
}

// stubWriters maps a stub type to the file extension its generator writes,
// so each shape can be rendered by all six.
var stubWriters = []struct {
	kind string
	ext  string
	gen  func(config.BuildConfig, string) error
}{
	{"rust", ".rs", rustStub},
	{"go", ".go", goStub},
	{"js", ".js", jsStub},
	{"ts", ".ts", tsStub},
	{"c", ".h", cStub},
	{"as", ".ts", asStub},
}

// TestStubMatrixGenerates renders every shape with every generator.
//
// It checks the generator RUNS and that the export names it was given appear
// in what it wrote. Whether the result COMPILES is TestGeneratedStubsCompile's
// job, and whether it behaves is the runtime isolation test's — this one is
// about breadth of shape rather than depth of check.
func TestStubMatrixGenerates(t *testing.T) {
	for _, shape := range stubShapes() {
		for _, w := range stubWriters {
			t.Run(shape.name+"/"+w.kind, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), shape.cfg.ImportModule)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(dir, "stubs"+w.ext)
				cfg := shape.cfg
				cfg.StubFile = out
				if err := w.gen(cfg, out); err != nil {
					t.Fatalf("%s (selects %s): %v", w.kind, shape.selects, err)
				}
				src := readIfPresent(t, out)
				if src == "" {
					t.Fatalf("%s: wrote nothing", w.kind)
				}
				for _, want := range shape.wantAll {
					if !strings.Contains(src, want) {
						t.Errorf("%s: output does not mention %q", w.kind, want)
					}
				}
			})
		}
	}
}

func readIfPresent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}
