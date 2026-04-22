package merge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestMain doubles as a mock wasm-merge subprocess. When invoked with
// REGEXPED_MOCK_WASM_MERGE=1, it finds the -o <file> flag, creates that file,
// and exits 0 — mimicking a successful wasm-merge run without the real binary.
func TestMain(m *testing.M) {
	if os.Getenv("REGEXPED_MOCK_WASM_MERGE") == "1" {
		args := os.Args
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("mock"), 0o644)
				break
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestModuleNameForWasm(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.BuildConfig
		path string
		want string
	}{
		{"top-level ImportModule", config.BuildConfig{ImportModule: "global"}, "anything.wasm", "global"},
		{"basename fallback", config.BuildConfig{}, "/dir/other.wasm", "other"},
		{"bare filename fallback", config.BuildConfig{}, "tokens.wasm", "tokens"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := moduleNameForWasm(c.cfg, c.path)
			if got != c.want {
				t.Errorf("moduleNameForWasm: got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory:", err)
	}
	cases := []struct {
		input string
		want  string
	}{
		{"~/foo/bar", filepath.Join(home, "foo/bar")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, c := range cases {
		got := expandHome(c.input)
		if got != c.want {
			t.Errorf("expandHome(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestExpandHomeNoTilde(t *testing.T) {
	input := "~user/foo"
	got := expandHome(input)
	if strings.HasPrefix(got, "/") {
		t.Errorf("expandHome(%q) = %q, should not expand ~user", input, got)
	}
}

func TestRunCmd(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		if err := runCmd("/bin/true", nil, "", nil); err != nil {
			t.Errorf("runCmd(/bin/true): unexpected error: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		if err := runCmd("/bin/false", nil, "", nil); err == nil {
			t.Error("runCmd(/bin/false): expected error, got nil")
		}
	})

	t.Run("extra env", func(t *testing.T) {
		if err := runCmd("/bin/true", nil, "", []string{"REGEXPED_TEST=1"}); err != nil {
			t.Errorf("runCmd with extra env: unexpected error: %v", err)
		}
	})
}

func TestCheckTool(t *testing.T) {
	t.Run("abs path exists and executable", func(t *testing.T) {
		if err := checkTool("/bin/sh"); err != nil {
			t.Errorf("checkTool(/bin/sh): unexpected error: %v", err)
		}
	})

	t.Run("abs path not found", func(t *testing.T) {
		if err := checkTool("/nonexistent/path/to/tool_regexped_test_xyz"); err == nil {
			t.Error("checkTool: expected error for non-existent absolute path")
		}
	})

	t.Run("abs path not executable", func(t *testing.T) {
		f, err := os.CreateTemp("", "regexped-test-noexec-*")
		if err != nil {
			t.Skip("cannot create temp file:", err)
		}
		defer os.Remove(f.Name())
		f.Close()
		// leave permissions as 0600 (not executable)
		if err := os.Chmod(f.Name(), 0o600); err != nil {
			t.Skip("cannot chmod:", err)
		}
		if err := checkTool(f.Name()); err == nil {
			t.Error("checkTool: expected error for non-executable file")
		}
	})

	t.Run("name in PATH", func(t *testing.T) {
		if err := checkTool("sh"); err != nil {
			t.Errorf("checkTool(sh): unexpected error: %v", err)
		}
	})

	t.Run("name not in PATH", func(t *testing.T) {
		if err := checkTool("nonexistent_tool_regexped_xyz_test"); err == nil {
			t.Error("checkTool: expected error for non-existent tool name")
		}
	})
}

func TestResolveWasmMerge(t *testing.T) {
	t.Run("config takes precedence over env", func(t *testing.T) {
		t.Setenv("WASM_MERGE", "/from/env")
		got := resolveWasmMerge(config.BuildConfig{WasmMerge: "/from/config"})
		if got != "/from/config" {
			t.Errorf("got %q, want /from/config", got)
		}
	})
	t.Run("env var used when config empty", func(t *testing.T) {
		t.Setenv("WASM_MERGE", "/from/env")
		got := resolveWasmMerge(config.BuildConfig{})
		if got != "/from/env" {
			t.Errorf("got %q, want /from/env", got)
		}
	})
	t.Run("falls back to wasm-merge", func(t *testing.T) {
		t.Setenv("WASM_MERGE", "")
		got := resolveWasmMerge(config.BuildConfig{})
		if got != "wasm-merge" {
			t.Errorf("got %q, want wasm-merge", got)
		}
	})
}

func TestCmdMerge(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGEXPED_MOCK_WASM_MERGE", "1")

	run := func(t *testing.T, cfg config.BuildConfig) {
		t.Helper()
		dir := t.TempDir()
		mainWasm := filepath.Join(dir, "main.wasm")
		regexWasm := filepath.Join(dir, "regex.wasm")
		output := filepath.Join(dir, "out.wasm")
		if err := os.WriteFile(mainWasm, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(regexWasm, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CmdMerge(cfg, mainWasm, output, []string{regexWasm}); err != nil {
			t.Fatalf("CmdMerge: %v", err)
		}
		if _, err := os.Stat(output); err != nil {
			t.Errorf("output file not created: %v", err)
		}
	}

	t.Run("binary from config", func(t *testing.T) {
		run(t, config.BuildConfig{WasmMerge: exe})
	})
	t.Run("binary from env var", func(t *testing.T) {
		t.Setenv("WASM_MERGE", exe)
		run(t, config.BuildConfig{})
	})
}
