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
