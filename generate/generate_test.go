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
		StubFile: "regexp.js",
		Regexps: []config.RegexEntry{
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
		"_inBase", "_outBase",
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
		"func UrlMatch(input []byte) (uint, bool)",
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
		"func UrlFind(input []byte, offset uint) iter.Seq2[uint, uint]",
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
		"func UrlGroups(input []byte, offset uint) iter.Seq[[][]uint]",
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
		"func UrlNamedGroups(input []byte, offset uint) iter.Seq[map[string][]uint]",
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
		"iter.Seq2[uint, uint]",
		"iter.Seq[[][]uint]",
		"iter.Seq[map[string][]uint]",
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
		StubFile: "regexp.js",
		Regexps: []config.RegexEntry{{
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
		StubFile: "regexp.ts",
		Regexps: []config.RegexEntry{{
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

// TestGenJSNamedGroupsFuncBatchUsesExportName verifies the named-groups
// generator's batch feature-detect is keyed on exportName (the WASM export
// this pattern's groups_func/named_groups_func share), not funcName — so a
// named_groups_func-only pattern (funcName != exportName) still finds its
// batch export, which is named after exportName.
func TestGenJSNamedGroupsFuncBatchUsesExportName(t *testing.T) {
	out := genJSNamedGroupsFunc("named_ab", "plain_ab", 2, map[string]int{"g1": 1})
	for _, sub := range []string{
		`_exp['plain_ab_batch']`,
		`plain_ab_batch'](_inBase`,
		`result['g1']`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genJSNamedGroupsFunc: missing %q", sub)
		}
	}
	if strings.Contains(out, `named_ab_batch`) {
		t.Error("genJSNamedGroupsFunc: batch export must be named after exportName, not funcName")
	}
}

func TestGenTSNamedGroupsFuncBatchUsesExportName(t *testing.T) {
	out := genTSNamedGroupsFunc("named_ab", "plain_ab", 2, map[string]int{"g1": 1})
	for _, sub := range []string{
		`_exp['plain_ab_batch']`,
		`plain_ab_batch'] as CallableFunction)(_inBase`,
		`result['g1']`,
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("genTSNamedGroupsFunc: missing %q", sub)
		}
	}
	if strings.Contains(out, `named_ab_batch`) {
		t.Error("genTSNamedGroupsFunc: batch export must be named after exportName, not funcName")
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

func TestGenASStubNamedGroupsFuncError(t *testing.T) {
	entries := []config.RegexEntry{
		{NamedGroupsFunc: "find_email", Pattern: "(?P<user>[^@]+)@(?P<domain>.+)"},
	}
	_, err := genASStubFile(config.BuildConfig{Regexps: entries, ImportModule: "mymod"})
	if err == nil {
		t.Fatal("genASStubFile: expected error for named_groups_func, got nil")
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
		"SetFind", "ProbeAny", "ProbeAll", "Probe",
		"Validate", "ValidateAny", "ValidateAll",
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
// import generate, so config.pascalCase is a hand copy of goPublicName (and of
// iterTypeName minus its "Iter" suffix). If either generator's transform
// changes, the collision check silently stops matching what is emitted — this
// test fails instead.
func TestConfigPascalCaseMatchesGenerators(t *testing.T) {
	names := []string{
		"url_match", "urlMatch", "UrlMatch", "set_match", "a_b_c",
		"_leading", "x9", "find", "named_groups_func", "aB_cD",
	}
	for _, n := range names {
		want := goPublicName(n)
		if got := config.PascalCaseForValidation(n); got != want {
			t.Errorf("config.PascalCaseForValidation(%q) = %q, but goPublicName = %q", n, got, want)
		}
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
			if lang.name == "go" {
				fn = goPublicName(fn) // Go's public surface is Pascal-cased
			}
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
