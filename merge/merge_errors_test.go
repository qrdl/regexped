package merge

import (
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
		WasmMerge: filepath.Join(dir, "definitely-not-installed"),
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
	cfg := config.BuildConfig{WasmMerge: "false"}
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
	cfg := config.BuildConfig{WasmMerge: "true"}
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

func componentCfg(wac string) config.BuildConfig {
	return config.BuildConfig{WasmFormat: "component", Wac: wac}
}

// TestCmdMergeComponentReportsMissingTool: the wac availability check runs
// before any work, and its message must name the format that needed it — a
// module user who has never heard of wac can otherwise reach it by mistake.
func TestCmdMergeComponentReportsMissingTool(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(filepath.Join(dir, "definitely-not-installed")),
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
	err := CmdMerge(componentCfg("false"), filepath.Join(dir, "guest.wasm"),
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
	err := CmdMerge(componentCfg("true"), filepath.Join(dir, "guest.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though no output file was produced")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("error %q does not explain that the output is missing", err)
	}
}

// TestResolveWac pins the lookup ORDER. It is the same order as wasm-merge's
// and wasm-tools', and the reason to test it is that a $WAC left over in the
// environment must never win over an explicit config value.
func TestResolveWac(t *testing.T) {
	t.Setenv("WAC", "/from/env/wac")
	if got := resolveWac(config.BuildConfig{Wac: "/from/config/wac"}); got != "/from/config/wac" {
		t.Errorf("config value lost to the environment: got %q", got)
	}
	if got := resolveWac(config.BuildConfig{}); got != "/from/env/wac" {
		t.Errorf("$WAC ignored: got %q", got)
	}
	t.Setenv("WAC", "")
	if got := resolveWac(config.BuildConfig{}); got != "wac" {
		t.Errorf("bare name not the last resort: got %q", got)
	}
	// A leading ~/ expands, so a config written by hand works without a shell.
	if got := resolveWac(config.BuildConfig{Wac: "~/bin/wac"}); strings.HasPrefix(got, "~") {
		t.Errorf("~/ not expanded: got %q", got)
	}
}
