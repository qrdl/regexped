package merge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

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
