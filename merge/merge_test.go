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
		if argvFile := os.Getenv("REGEXPED_MOCK_ARGV"); argvFile != "" {
			_ = os.WriteFile(argvFile, []byte(strings.Join(os.Args[1:], " ")), 0o644)
		}
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
		regexWasm := filepath.Join(dir, "regexp.wasm")
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

	// The test binary is the mock, and it is NOT named wasm-merge: pointing the
	// key at a file uses that file whatever it is called.
	t.Run("binary from config, under another name", func(t *testing.T) {
		run(t, config.BuildConfig{WasmMergePath: exe})
	})
	t.Run("the environment is ignored", func(t *testing.T) {
		t.Setenv("WASM_MERGE", "/garbage/wasm-merge")
		run(t, config.BuildConfig{WasmMergePath: exe})

		t.Setenv("WASM_MERGE", exe)
		t.Setenv("PATH", t.TempDir())
		dir := t.TempDir()
		err := CmdMerge(config.BuildConfig{}, filepath.Join(dir, "main.wasm"),
			filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
		if err == nil || !strings.Contains(err.Error(), "$PATH") {
			t.Errorf("err = %v; with the key omitted only $PATH is consulted, never $WASM_MERGE", err)
		}
	})
}

// The world block is read up to its closing brace; text that never closes it, or
// has no world at all, yields what was seen rather than nothing or a panic.
func TestRegexpedExportsWithoutAClosedWorld(t *testing.T) {
	for _, c := range []struct{ name, wit, want string }{
		{"empty", "", ""},
		{"no world", "package regexped:a;\n\ninterface matcher {\n}\n", ""},
		{"unterminated world", "world root {\n  import wasi:io/streams;\n  export regexped:a/matcher;\n  export regexped:a/sets;\n",
			"regexped:a/matcher,regexped:a/sets"},
	} {
		if got := strings.Join(regexpedExports(c.wit), ","); got != c.want {
			t.Errorf("%s: regexpedExports = %q, want %q", c.name, got, c.want)
		}
	}
}
