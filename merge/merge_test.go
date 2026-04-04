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
