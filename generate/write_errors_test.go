package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

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
