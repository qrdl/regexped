package check

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// TestRun: a module config with a stub, a component config (no wasm-tools
// needed: only its core module is built), and a config naming a stub type
// and no file — one line per pattern and set, then the summary, and nothing
// written beside the config.
func TestRun(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"import_module: m\nstub_file: s.rs\npatterns:\n  - {name: url, regexp: 'https?://[a-z]+', find_func: url_find}\n" +
			"  - {regexp: '(\\d+)-(\\d+)', groups_func: num}\nsets:\n  - {name: s, find: s_find, patterns: [url]}\n",
			"pattern url: Compiled DFA, byte mode\npattern (\\d+)-(\\d+): TDFA, byte mode\nset s: find; 1 members; frontend packed-pair\n" +
				"ok: 2 patterns, 1 set; module "},
		{"wasm_format: component\nimport_module: m\npatterns:\n  - {regexp: 'abc', match_func: m}\n", "ok: 1 pattern, 0 sets; component core module "},
		{"import_module: m\nstub_type: c\npatterns:\n  - {regexp: 'abc', find_func: f}\n", ", c stub; nothing written\n"},
	} {
		cfg := load(t, c.src)
		var b bytes.Buffer
		if err := Run(cfg, &b); err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		if !strings.Contains(b.String(), c.want) {
			t.Errorf("%q:\n%s\nwant %q", c.src, b.String(), c.want)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.StubFile), "s.rs")); cfg.StubFile != "" && err == nil {
			t.Errorf("%q: the stub was written", c.src)
		}
	}
}

// TestRunErrors: what compile or generate would refuse, check refuses.
func TestRunErrors(t *testing.T) {
	cfg := config.BuildConfig{Patterns: []config.PatternEntry{{Regexp: `a{2000}`, FindFunc: "f"}}}
	if err := Run(cfg, &bytes.Buffer{}); err == nil {
		t.Error("an uncompilable module config passed")
	}
	comp := config.BuildConfig{WasmFormat: "component", ImportModule: "m", Patterns: []config.PatternEntry{{Regexp: `a{2000}`, FindFunc: "f"}}}
	if err := Run(comp, &bytes.Buffer{}); err == nil {
		t.Error("an uncompilable component config passed")
	}
	bad := config.BuildConfig{ImportModule: "m", StubFile: "s.txt", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(bad, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "stub type") {
		t.Errorf("an unknown stub type: err = %v", err)
	}
	gen := config.BuildConfig{ImportModule: "m", StubFile: "s.h", Patterns: []config.PatternEntry{{Regexp: `a*`, GroupsFunc: "g"}}}
	if err := Run(gen, &bytes.Buffer{}); err == nil {
		t.Error("a groups_func with no capture group passed")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	ok := config.BuildConfig{ImportModule: "m", StubFile: "s.h", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(ok, &bytes.Buffer{}); err == nil {
		t.Error("no temporary directory for the stub, and no error")
	}
}

// TestRunRefusesWhatGenerateRefuses: a Rust stub with no import_module.
func TestRunRefusesWhatGenerateRefuses(t *testing.T) {
	c := config.BuildConfig{StubFile: "s.rs", Patterns: []config.PatternEntry{{Regexp: `abc`, FindFunc: "f"}}}
	if err := Run(c, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "import_module") {
		t.Errorf("err = %v, want the import_module error", err)
	}
}
