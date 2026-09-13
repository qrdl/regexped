package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

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
