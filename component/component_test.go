package component

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/tools"
)

// needWasmTools skips a test when the tool is absent, the same convention the
// compile package uses for its validator: a suite that silently passes without
// the tool would be checking nothing.
func needWasmTools(t *testing.T) string {
	t.Helper()
	tool, err := exec.LookPath("wasm-tools")
	if err != nil {
		t.Skip("wasm-tools not in PATH")
	}
	return tool
}

func TestResolveWasmTools(t *testing.T) {
	// wasm_tools_path as a DIRECTORY: the tool name is appended. $WASM_TOOLS is
	// ignored, set to garbage to prove it.
	dir := t.TempDir()
	fake := filepath.Join(dir, "wasm-tools")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WASM_TOOLS", "/garbage/wasm-tools")
	if got, err := resolveWasmTools(config.BuildConfig{WasmToolsPath: dir}); err != nil || got != fake {
		t.Errorf("resolveWasmTools(directory) = %q, %v; want %q", got, err, fake)
	}
	// Omitted: $PATH only.
	t.Setenv("WASM_TOOLS", fake)
	t.Setenv("PATH", t.TempDir())
	if _, err := resolveWasmTools(config.BuildConfig{}); err == nil || !strings.Contains(err.Error(), "$PATH") {
		t.Errorf("err = %v; with wasm_tools_path omitted only $PATH is consulted, never $WASM_TOOLS", err)
	}
}

func findCfg(name string) config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: name,
		Regexps: []config.RegexEntry{
			{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "token_find"},
			{Pattern: `[a-z]+`, MatchFunc: "lower_match"},
			{Pattern: `(?P<opt>x)?y`, GroupsFunc: "opt_groups"},
		},
	}
}

func TestWitPathFor(t *testing.T) {
	for in, want := range map[string]string{
		"out/secrets.wasm": "out/secrets.wit",
		"secrets.wasm":     "secrets.wit",
		"noext":            "noext.wit",
		"-":                "", // streaming to stdout has no sibling
		"":                 "",
	} {
		if got := WitPathFor(in); got != want {
			t.Errorf("WitPathFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunToolFailureSurfaces(t *testing.T) {
	if err := tools.Run("sh", []string{"-c", "exit 3"}, "", nil); err == nil {
		t.Error("a non-zero tool exit must be an error")
	}
	if err := tools.Run("sh", []string{"-c", "exit 0"}, "", nil); err != nil {
		t.Errorf("a zero tool exit must not be: %v", err)
	}
}

func TestWrapMissingTool(t *testing.T) {
	cfg := findCfg("secrets")
	cfg.WasmToolsPath = filepath.Join(t.TempDir(), "absent")
	err := Wrap(cfg, []byte{0, 'a', 's', 'm'}, "package regexped:x;\n", filepath.Join(t.TempDir(), "o.wasm"))
	if err == nil || !strings.Contains(err.Error(), "wasm_format: component") {
		t.Errorf("err = %v, want one naming the format that needs the tool", err)
	}
}

// An unrepresentable world name must fail BEFORE the tool is invoked, so the
// message names the config key rather than surfacing as a WIT complaint.
func TestWrapRejectsBadWorldName(t *testing.T) {
	cfg := findCfg("secrets")
	cfg.WitWorld = "Not Kebab"
	err := Wrap(cfg, []byte{0, 'a', 's', 'm'}, "package regexped:x;\n", filepath.Join(t.TempDir(), "o.wasm"))
	if err == nil || !strings.Contains(err.Error(), "wit_world") {
		t.Errorf("err = %v, want one naming wit_world", err)
	}
}

// A core module wasm-tools rejects must surface as an error from the step that
// rejected it, not as a silent empty output.
func TestWrapPropagatesToolFailure(t *testing.T) {
	needWasmTools(t)
	cfg := findCfg("secrets")
	err := Wrap(cfg, []byte("not a wasm module at all"), "package regexped:secrets;\n\nworld secrets {\n}\n",
		filepath.Join(t.TempDir(), "o.wasm"))
	if err == nil || !strings.Contains(err.Error(), "wasm-tools component embed") {
		t.Errorf("err = %v, want the embed step named", err)
	}
}

func TestCmdCompileRejectsWrongFormat(t *testing.T) {
	cfg := findCfg("secrets")
	cfg.WasmFormat = "module"
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "wasm_format") {
		t.Errorf("err = %v", err)
	}
}

func TestCmdCompileRejectsConfigWithNoExports(t *testing.T) {
	cfg := config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "secrets",
		// A pattern with no _func fields compiles to nothing, so there is no
		// interface to build a component around.
		Regexps: []config.RegexEntry{{Pattern: `abc`}},
	}
	err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil)
	if err == nil || !strings.Contains(err.Error(), "no exports") {
		t.Errorf("err = %v, want the no-exports refusal", err)
	}
}

func TestCmdCompileSurfacesNameErrors(t *testing.T) {
	// A func name that cannot be a WIT identifier: caught while building the
	// WIT, before anything is compiled.
	cfg := findCfg("secrets")
	cfg.Regexps = []config.RegexEntry{{Pattern: "a", FindFunc: "_bad"}}
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "find_func") {
		t.Errorf("bad func name: err = %v", err)
	}
	// An import_module that cannot be kebab-cased, with no wit_package to save it.
	cfg = findCfg("9x")
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "wit_package") {
		t.Errorf("bad package name: err = %v", err)
	}
	// A world name that is not a WIT identifier.
	cfg = findCfg("secrets")
	cfg.WitWorld = "Bad World"
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "wit_world") {
		t.Errorf("bad world name: err = %v", err)
	}
}

func TestCmdCompileRejectsUncompilablePattern(t *testing.T) {
	cfg := findCfg("secrets")
	// A rune above the byte-mode limit: rejected in both modes.
	cfg.Regexps = []config.RegexEntry{{Pattern: "\u4e2d", FindFunc: "f"}}
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "compile") {
		t.Errorf("err = %v, want a compile failure", err)
	}
}

// The end-to-end path: a component on disk, its sibling .wit, and both of them
// acceptable to wasm-tools.
func TestCmdCompileWritesComponentAndWit(t *testing.T) {
	tool := needWasmTools(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "secrets.wasm")
	cfg := findCfg("secrets")

	var report strings.Builder
	if err := CmdCompile(cfg, out, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("component not written: %v", err)
	}
	witPath := WitPathFor(out)
	witBytes, err := os.ReadFile(witPath)
	if err != nil {
		t.Fatalf("sibling .wit not written: %v", err)
	}
	if !strings.Contains(string(witBytes), "package regexped:secrets;") {
		t.Errorf("unexpected WIT:\n%s", witBytes)
	}
	if out, err := exec.Command(tool, "validate", out).CombinedOutput(); err != nil {
		t.Fatalf("wasm-tools rejected the component: %v\n%s", err, out)
	}
	// The component's own view of its interface must name every export.
	printed, err := exec.Command(tool, "component", "wit", out).CombinedOutput()
	if err != nil {
		t.Fatalf("component wit: %v\n%s", err, printed)
	}
	for _, want := range []string{"token-find", "lower-match", "opt-groups"} {
		if !strings.Contains(string(printed), want) {
			t.Errorf("component interface is missing %q:\n%s", want, printed)
		}
	}
}

// `-` streams the component and writes no sibling: there is no path to put one
// beside.
func TestCmdCompileToStdout(t *testing.T) {
	needWasmTools(t)
	cfg := findCfg("secrets")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1<<20)
		n, _ := r.Read(buf)
		done <- buf[:n]
	}()
	err = CmdCompile(cfg, "-", nil)
	w.Close()
	os.Stdout = saved
	if err != nil {
		t.Fatal(err)
	}
	got := <-done
	if len(got) < 8 || string(got[:4]) != "\x00asm" {
		t.Fatalf("stdout did not receive a WASM binary (%d bytes)", len(got))
	}
	// A component's preamble differs from a core module's in the version word.
	if got[4] != 0x0d {
		t.Errorf("expected a COMPONENT preamble, got version byte %#x", got[4])
	}
}

// os.MkdirTemp honours TMPDIR, so pointing it at a path that does not exist is
// the one way to reach the temp-dir failure.
func TestWrapTempDirFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "no", "such", "dir"))
	cfg := findCfg("secrets")
	sh, lerr := exec.LookPath("sh")
	if lerr != nil {
		t.Skip("sh not on PATH")
	}
	cfg.WasmToolsPath = sh // a tool that exists, so the failure is the temp dir
	err := Wrap(cfg, []byte{0}, "x", filepath.Join(t.TempDir(), "o.wasm"))
	if err == nil || !strings.Contains(err.Error(), "temp dir") {
		t.Errorf("err = %v, want the temp-dir failure", err)
	}
}

// A parent that is a regular FILE cannot be created as a directory.
func TestWrapOutputDirFailure(t *testing.T) {
	needWasmTools(t)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	core, witText := realCore(t, findCfg("secrets"))
	err := Wrap(findCfg("secrets"), core, witText, filepath.Join(blocker, "o.wasm"))
	if err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Errorf("err = %v, want the mkdir failure", err)
	}
}

// `embed` only attaches a custom section, so it accepts a core module with no
// canonical exports; `new` is the step that then has nothing to lift. This
// covers the second tool failure, which the embed-failure test cannot reach.
func TestWrapPropagatesComponentNewFailure(t *testing.T) {
	needWasmTools(t)
	cfg := findCfg("secrets")
	// A module-format build: valid WASM, but without a single canonical export.
	plain := plainCore(t, cfg)
	witText, _, _, err := artifacts(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{filepath.Join(t.TempDir(), "o.wasm"), "-"} {
		err := Wrap(cfg, plain, witText, out)
		if err == nil || !strings.Contains(err.Error(), "wasm-tools component new") {
			t.Errorf("out=%q: err = %v, want the `new` step named", out, err)
		}
	}
}

// The sibling .wit cannot be written when something already occupies its path as
// a directory. It is written FIRST: it is pure text from the config and cannot
// fail for a reason the component would not, so a .wit that cannot be written
// must stop the build before a fresh .wasm lands beside a stale or missing
// interface file — the half-updated output `--diag-json` is already refused for.
func TestCmdCompileWitWriteFailure(t *testing.T) {
	needWasmTools(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "secrets.wasm")
	if err := os.MkdirAll(WitPathFor(out), 0o755); err != nil {
		t.Fatal(err)
	}
	err := CmdCompile(findCfg("secrets"), out, nil)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Errorf("err = %v, want the .wit write failure", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a fresh .wasm was left beside a .wit that could not be written")
	}
}

// The sibling .wit's directory cannot be created when a regular file sits where
// one of its parents should be. That too stops the build before anything is
// wrapped, so no .wasm is left behind.
func TestCmdCompileWitDirFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(blocker, "sub", "secrets.wasm")
	err := CmdCompile(findCfg("secrets"), out, nil)
	if err == nil || !strings.Contains(err.Error(), "mkdir "+filepath.Dir(WitPathFor(out))) {
		t.Errorf("err = %v, want the failure to create the .wit's directory", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a .wasm was written although the .wit's directory could not be created")
	}
}

// Wrap's failure must propagate out of CmdCompile rather than being swallowed.
func TestCmdCompileSurfacesWrapFailure(t *testing.T) {
	cfg := findCfg("secrets")
	cfg.WasmToolsPath = filepath.Join(t.TempDir(), "absent")
	if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil); err == nil ||
		!strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("err = %v, want the missing-tool failure", err)
	}
}

// The four I/O failures that act on a file in a directory the function itself
// just created. They are unreachable without the seams in component.go, and a
// handler that is never executed is a handler nobody has checked.
func TestUnreachableIOFailuresAreHandled(t *testing.T) {
	needWasmTools(t)
	cfg := findCfg("secrets")
	core, witText := realCore(t, cfg)

	saveWrite, saveRead, saveStat := writeFile, readFile, statFile
	t.Cleanup(func() { writeFile, readFile, statFile = saveWrite, saveRead, saveStat })

	boom := os.ErrPermission

	t.Run("core module write", func(t *testing.T) {
		writeFile = func(string, []byte, os.FileMode) error { return boom }
		defer func() { writeFile = saveWrite }()
		err := Wrap(cfg, core, witText, filepath.Join(t.TempDir(), "o.wasm"))
		if err == nil || !strings.Contains(err.Error(), "write core module") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("WIT write", func(t *testing.T) {
		n := 0
		writeFile = func(p string, b []byte, m os.FileMode) error {
			n++
			if n == 1 { // let the core module through, fail the WIT
				return saveWrite(p, b, m)
			}
			return boom
		}
		defer func() { writeFile = saveWrite }()
		err := Wrap(cfg, core, witText, filepath.Join(t.TempDir(), "o.wasm"))
		if err == nil || !strings.Contains(err.Error(), "write WIT") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("component read back for stdout", func(t *testing.T) {
		readFile = func(string) ([]byte, error) { return nil, boom }
		defer func() { readFile = saveRead }()
		err := Wrap(cfg, core, witText, "-")
		if err == nil || !strings.Contains(err.Error(), "read component") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("stat of the finished component", func(t *testing.T) {
		statFile = func(string) (os.FileInfo, error) { return nil, boom }
		defer func() { statFile = saveStat }()
		err := CmdCompile(cfg, filepath.Join(t.TempDir(), "o.wasm"), nil)
		if err == nil || !strings.Contains(err.Error(), "stat output") {
			t.Errorf("err = %v", err)
		}
	})
}

// A VERSIONED component must actually wrap, not merely produce plausible-looking
// export names. `wit_version` shipped broken because the only test was a string
// assertion that agreed with the bug: the version was emitted as
// `regexped:pkg@2.3.0/matcher` when wasm-tools wants
// `regexped:pkg/matcher@2.3.0`, and `component new` failed with "failed to find
// export of interface". Nothing caught it until a versioned component was built.
// So this test builds one.
func TestCmdCompileVersionedComponent(t *testing.T) {
	tool := needWasmTools(t)
	cfg := findCfg("secrets")
	cfg.WitVersion = "2.3.0"
	out := filepath.Join(t.TempDir(), "secrets.wasm")
	if err := CmdCompile(cfg, out, nil); err != nil {
		t.Fatalf("a versioned component must build: %v", err)
	}
	if out, err := exec.Command(tool, "validate", out).CombinedOutput(); err != nil {
		t.Fatalf("wasm-tools rejected the versioned component: %v\n%s", err, out)
	}
	printed, err := exec.Command(tool, "component", "wit", out).CombinedOutput()
	if err != nil {
		t.Fatalf("component wit: %v\n%s", err, printed)
	}
	// The version belongs on the exported interface AND on the package.
	for _, want := range []string{
		"export regexped:secrets/matcher@2.3.0;",
		"package regexped:secrets@2.3.0",
	} {
		if !strings.Contains(string(printed), want) {
			t.Errorf("missing %q in:\n%s", want, printed)
		}
	}
	// And the sibling .wit must be the versioned one.
	witBytes, err := os.ReadFile(WitPathFor(out))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(witBytes), "package regexped:secrets@2.3.0;") {
		t.Errorf("sibling .wit is not versioned:\n%s", witBytes)
	}
}

// TestCmdCompileWritesSetComponent runs `wasm-tools component new` on a
// SET-bearing core — the `[resource-new]` import, the `[dtor]` binding and the
// `sets` interface — in the ordinary suite, rather than only in a manual run.
func TestCmdCompileWritesSetComponent(t *testing.T) {
	tool := needWasmTools(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "runs.wasm")
	cfg := config.BuildConfig{
		WasmFormat: "component", ImportModule: "runs", WitPackage: "runs",
		Regexps: []config.RegexEntry{
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "digits", Pattern: `[0-9]+`},
		},
		Sets: []config.SetConfig{{
			Name: "runs", Patterns: config.PatternSelector{All: true},
			MatchAny: "runs_match_any", MatchAll: "runs_match_all",
			ScanAny: "runs_scan_any", ScanAll: "runs_scan_all",
			Find: "scan_runs", Overlapping: true,
		}},
	}
	if err := CmdCompile(cfg, out, nil); err != nil {
		t.Fatal(err)
	}
	if o, err := exec.Command(tool, "validate", out).CombinedOutput(); err != nil {
		t.Fatalf("wasm-tools rejected the set component: %v\n%s", err, o)
	}
	printed, err := exec.Command(tool, "component", "wit", out).CombinedOutput()
	if err != nil {
		t.Fatalf("component wit: %v\n%s", err, printed)
	}
	for _, want := range []string{"interface sets", "resource scan-runs", "runs-scan-all"} {
		if !strings.Contains(string(printed), want) {
			t.Errorf("the set component's interface is missing %q:\n%s", want, printed)
		}
	}
}
