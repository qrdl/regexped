package merge

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// CmdMerge's failure paths.
//
// Merging shells out to `wasm-merge`, so the two things that go wrong in
// practice are the tool not being there and the tool failing. Both have to be
// reported as errors: the merged module is what a Rust or Go host links
// against, and a merge that reports success having produced nothing turns into
// a link failure a long way from here.

// TestCmdMergeReportsMissingTool covers the availability check, which runs
// BEFORE any work so the user is told the real problem rather than watching a
// subprocess fail.
func TestCmdMergeReportsMissingTool(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{
		WasmMergePath: filepath.Join(dir, "definitely-not-installed"),
	}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success with no wasm-merge available")
	}
	if !strings.Contains(err.Error(), "definitely-not-installed") &&
		!strings.Contains(strings.ToLower(err.Error()), "wasm-merge") {
		t.Errorf("error %q names neither the tool nor the path", err)
	}
}

// TestCmdMergeReportsToolFailure: when the tool exists but fails — here
// because its inputs do not exist — the exit status has to surface rather than
// be swallowed into a "merged" log line.
func TestCmdMergeReportsToolFailure(t *testing.T) {
	dir := t.TempDir()
	// `false` is on every POSIX system and does nothing but exit non-zero,
	// which is exactly the shape of a wasm-merge that refused its inputs.
	cfg := config.BuildConfig{WasmMergePath: lookPath(t, "false")}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though the merge tool exited non-zero")
	}
}

// TestCmdMergeReportsMissingOutput: a tool that succeeds but writes nothing
// must still be an error, because the next step in the build reads that file.
// `true` models exactly that.
func TestCmdMergeReportsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{WasmMergePath: lookPath(t, "true")}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though no output file was produced")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("error %q does not explain that the output is missing", err)
	}
}

// The component arm's failure paths mirror the module arm's, because the
// asymmetry to guard against is silent SUCCESS: a component whose imports were
// never satisfied loads fine and traps at the first call, a long way from here.
//
// `wasm_format: component` is set through a config literal rather than a YAML
// file: these tests exercise CmdMerge's dispatch, not config loading.

// componentCfg pairs the wac under test with a mock wasm-tools, which the plug
// pre-check runs before wac.
func componentCfg(t *testing.T, wac string) config.BuildConfig {
	return config.BuildConfig{WasmFormat: "component", WacPath: wac, WasmToolsPath: mockWasmTools(t)}
}

// TestCmdMergeComponentReportsMissingTool: the wac availability check runs
// before any work, and its message must name the format that needed it — a
// module user who has never heard of wac can otherwise reach it by mistake.
func TestCmdMergeComponentReportsMissingTool(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, filepath.Join(dir, "definitely-not-installed")),
		filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"),
		[]string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success with no wac available")
	}
	if !strings.Contains(err.Error(), "definitely-not-installed") {
		t.Errorf("error %q does not name the missing tool", err)
	}
	if !strings.Contains(err.Error(), "component") {
		t.Errorf("error %q does not say which wasm_format needed it", err)
	}
}

func TestCmdMergeComponentReportsToolFailure(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, lookPath(t, "false")), filepath.Join(dir, "guest.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though wac exited non-zero")
	}
	if !strings.Contains(err.Error(), "wac") {
		t.Errorf("error %q does not name wac", err)
	}
}

func TestCmdMergeComponentReportsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, lookPath(t, "true")), filepath.Join(dir, "guest.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though no output file was produced")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("error %q does not explain that the output is missing", err)
	}
}

// lookPath is the absolute path of a system tool: a tool path key is a PATH, so a
// bare name there would be resolved against the working directory.
func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH", name)
	}
	return p
}

// TestComposeIgnoresTheEnvironmentAndKeepsArgumentOrder: wac is found through
// `wac_path` or `$PATH` and never through $WAC, and `wac plug` gets its plugs,
// output and socket in the documented order — checked without wac installed, by
// a mock that records its argv.
func TestComposeIgnoresTheEnvironmentAndKeepsArgumentOrder(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	t.Setenv("REGEXPED_MOCK_WASM_MERGE", "1")
	t.Setenv("REGEXPED_MOCK_ARGV", argv)
	t.Setenv("WAC", "/garbage/wac")
	mainWasm, out := filepath.Join(dir, "main.wasm"), filepath.Join(dir, "out.wasm")
	a, b := filepath.Join(dir, "a.wasm"), filepath.Join(dir, "b.wasm")
	for _, p := range []string{mainWasm, a, b} {
		if err := os.WriteFile(p, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CmdMerge(componentCfg(t, exe), mainWasm, out, []string{a, b}); err != nil {
		t.Fatalf("CmdMerge: %v", err)
	}
	got, err := os.ReadFile(argv)
	if err != nil {
		t.Fatalf("the mock recorded no argv: %v", err)
	}
	if want := "plug --plug " + a + " --plug " + b + " -o " + out + " " + mainWasm; string(got) != want {
		t.Errorf("wac argv = %q, want %q", got, want)
	}

	t.Setenv("WAC", exe)
	t.Setenv("PATH", t.TempDir())
	if err := CmdMerge(config.BuildConfig{WasmFormat: "component", WasmToolsPath: mockWasmTools(t)}, mainWasm, out, []string{a}); err == nil ||
		!strings.Contains(err.Error(), "$PATH") {
		t.Errorf("err = %v; with wac_path omitted only $PATH is consulted, never $WAC", err)
	}
}

// mockWasmTools is a stand-in for `wasm-tools component wit <plug>`: it prints
// the canned WIT in `<plug>.mockwit`, or an empty world when there is none, so
// the plug pre-check runs without wasm-tools installed.
func mockWasmTools(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wasm-tools")
	script := "#!/bin/sh\n[ \"$1 $2\" = \"component wit\" ] || exit 3\n" +
		"if [ -f \"$3.mockwit\" ]; then cat \"$3.mockwit\"; else printf 'package root:component;\\n\\nworld root {\\n}\\n'; fi\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// plugWithWit writes an empty plug file and the WIT the mock reports for it.
func plugWithWit(t *testing.T, dir, name string, exports ...string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	wit := "package root:component;\n\nworld root {\n  import wasi:io/error@0.2.0;\n"
	for _, e := range exports {
		wit += "  export " + e + ";\n"
	}
	wit += "}\npackage regexped:x {\n  interface matcher {\n    variant error-code { export }\n  }\n}\n"
	for path, body := range map[string]string{p: "plug", p + ".mockwit": wit} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// TestCmdMergeComponentRefusesDuplicatePlugExports: two plugs exporting the SAME
// regexped interface make `wac plug` fail with the text a genuine name mismatch
// gives. The pre-check names both plugs and the interface instead, and runs
// before wac does anything.
func TestCmdMergeComponentRefusesDuplicatePlugExports(t *testing.T) {
	dir := t.TempDir()
	a := plugWithWit(t, dir, "a.wasm", "regexped:pkg-a/matcher", "regexped:pkg-a/sets")
	b := plugWithWit(t, dir, "b.wasm", "regexped:pkg-b/matcher")
	c := plugWithWit(t, dir, "c.wasm", "regexped:pkg-a/sets")
	argv := filepath.Join(dir, "wac-ran")
	wac := filepath.Join(dir, "wac")
	if err := os.WriteFile(wac, []byte("#!/bin/sh\ntouch "+argv+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: wac, WasmToolsPath: mockWasmTools(t)}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{a, b, c})
	if err == nil {
		t.Fatal("two plugs exporting regexped:pkg-a/sets were composed without complaint")
	}
	for _, want := range []string{a, c, "both export regexped:pkg-a/sets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if _, statErr := os.Stat(argv); statErr == nil {
		t.Error("wac ran although the plugs were already known to collide")
	}

	// Distinct packages pass the pre-check and reach wac, whose failure is then
	// the one reported. An `export` word inside an interface body is not an export.
	err = CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{a, b})
	if err == nil || !strings.Contains(err.Error(), "wac plug") {
		t.Errorf("err = %v; distinct plugs must reach wac", err)
	}
}

// TestCmdMergeComponentNeedsWasmTools: the pre-check makes wasm-tools a
// requirement of a component merge as well as of a component compile, and its
// absence is reported with the path tried and the format that needed it.
func TestCmdMergeComponentNeedsWasmTools(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-wasm-tools-here")
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: lookPath(t, "true"), WasmToolsPath: missing}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"),
		[]string{plugWithWit(t, dir, "a.wasm", "regexped:a/matcher")})
	if err == nil {
		t.Fatal("reported success with no wasm-tools available")
	}
	for _, want := range []string{missing, "wasm_format: component"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestCmdMergeComponentReportsUnreadablePlug: a plug wasm-tools cannot read is
// named in the error, before wac runs.
func TestCmdMergeComponentReportsUnreadablePlug(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.wasm")
	failing := filepath.Join(dir, "wasm-tools")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\necho 'not a component' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: lookPath(t, "true"), WasmToolsPath: failing}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{bad})
	if err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "wasm-tools") {
		t.Errorf("err = %v; want wasm-tools named together with the plug %s", err, bad)
	}
}
