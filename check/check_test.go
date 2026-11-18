package check

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

func load(t *testing.T, src string) config.BuildConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestRun: with no writer check prints nothing and answers by its error;
// with one it writes the report compile writes — for a module config with a
// stub, a component config (no wasm-tools needed: only its core module is
// built), and a config naming a stub type and no file — and nothing is
// written beside the config.
func TestRun(t *testing.T) {
	for _, c := range []struct{ src, kind string }{
		{"import_module: m\nstub_file: s.rs\npatterns:\n  - {name: url, regexp: 'https?://[a-z]+', find_func: url_find}\n" +
			"  - {regexp: '(\\d+)-(\\d+)', groups_func: num}\nsets:\n  - {name: s, find: s_find, patterns: [url]}\n", "standalone module"},
		{"wasm_format: component\nimport_module: m\npatterns:\n  - {regexp: 'abc', match_func: m}\n", "component core module"},
		{"import_module: m\nstub_type: c\npatterns:\n  - {regexp: 'abc', find_func: f}\n", "standalone module"},
	} {
		cfg := load(t, c.src)
		if err := Run(cfg, nil, compile.VerboseBrief, compile.VerbosePlain); err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		var b bytes.Buffer
		if err := Run(cfg, &b, compile.VerboseFull, compile.VerboseJSON); err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		var r compile.Report
		if err := json.Unmarshal(b.Bytes(), &r); err != nil || r.Module == nil || r.Module.Kind != c.kind {
			t.Errorf("%q: %v\n%s\nwant a report of a %s", c.src, err, b.String(), c.kind)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.StubFile), "s.rs")); cfg.StubFile != "" && err == nil {
			t.Errorf("%q: the stub was written", c.src)
		}
	}
	// The brief report is the one compile prints.
	cfg := load(t, "import_module: m\npatterns:\n  - {name: url, regexp: 'https?://[a-z]+', find_func: url_find}\n")
	var got, want bytes.Buffer
	if err := Run(cfg, &got, compile.VerboseBrief, compile.VerbosePlain); err != nil {
		t.Fatal(err)
	}
	if err := compile.CmdCompileReport(cfg, filepath.Join(t.TempDir(), "o.wasm"), &want, compile.VerboseBrief, compile.VerbosePlain); err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() || got.Len() == 0 {
		t.Errorf("check's report %q, compile's %q", got.String(), want.String())
	}
}

// TestRunErrors: what compile or generate would refuse, check refuses.
func TestRunErrors(t *testing.T) {
	cfg := config.BuildConfig{Patterns: []config.PatternEntry{{Regexp: `a{2000}`, FindFunc: "f"}}}
	if err := Run(cfg, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil {
		t.Error("an uncompilable module config passed")
	}
	comp := config.BuildConfig{WasmFormat: "component", ImportModule: "m", Patterns: []config.PatternEntry{{Regexp: `a{2000}`, FindFunc: "f"}}}
	if err := Run(comp, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil {
		t.Error("an uncompilable component config passed")
	}
	bad := config.BuildConfig{ImportModule: "m", StubFile: "s.txt", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(bad, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil || !strings.Contains(err.Error(), "stub type") {
		t.Errorf("an unknown stub type: err = %v", err)
	}
	gen := config.BuildConfig{ImportModule: "m", StubFile: "s.h", Patterns: []config.PatternEntry{{Regexp: `a*`, GroupsFunc: "g"}}}
	if err := Run(gen, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil {
		t.Error("a groups_func with no capture group passed")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	ok := config.BuildConfig{ImportModule: "m", StubFile: "s.h", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(ok, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil {
		t.Error("no temporary directory for the stub, and no error")
	}
}

// TestRunRefusesWhatGenerateRefuses: a Rust stub with no import_module.
func TestRunRefusesWhatGenerateRefuses(t *testing.T) {
	c := config.BuildConfig{StubFile: "s.rs", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(c, &bytes.Buffer{}, compile.VerboseBrief, compile.VerbosePlain); err == nil || !strings.Contains(err.Error(), "import_module") {
		t.Errorf("err = %v, want the import_module error", err)
	}
}
