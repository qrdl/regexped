package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TODO task 62 made generated symbols keep the config's casing VERBATIM. That
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
// whatever its case, and the PascalCase transform task 62 removed has not
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
