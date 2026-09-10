package component

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCapture(tool string, args ...string) ([]byte, error) {
	return exec.Command(tool, args...).CombinedOutput()
}

var exportLine = regexp.MustCompile(`\(export "([^"]*)" \(func (\d+)\)\)`)

// exportMap reads `wasm-tools print` and returns export name -> function index.
func exportMap(t *testing.T, tool string, wasm []byte) map[string]string {
	t.Helper()
	out, err := runCapture(tool, "print", writeTemp(t, wasm))
	if err != nil {
		t.Fatalf("wasm-tools print: %v\n%s", err, out)
	}
	m := map[string]string{}
	for _, match := range exportLine.FindAllStringSubmatch(string(out), -1) {
		m[match[1]] = match[2]
	}
	return m
}

// artifacts is generate.ComponentArtifacts, wrapped for tests.
func artifacts(t *testing.T, cfg config.BuildConfig) (string, map[string]string, string, error) {
	t.Helper()
	return generate.ComponentArtifacts(cfg)
}

// realCore builds a core module WITH the component adapters.
func realCore(t *testing.T, cfg config.BuildConfig) ([]byte, string) {
	t.Helper()
	witText, names, prefix, err := generate.ComponentArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	core, _, err := compile.Compile(cfg.Regexps, 0, true, compile.CompileOptions{
		Component:            true,
		ComponentPackage:     prefix,
		ComponentExportNames: names,
	})
	if err != nil {
		t.Fatal(err)
	}
	return core, witText
}

// plainCore builds the same patterns WITHOUT adapters: valid WASM that
// `component new` has nothing to lift from.
func plainCore(t *testing.T, cfg config.BuildConfig) []byte {
	t.Helper()
	core, _, err := compile.Compile(cfg.Regexps, 0, true, compile.CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return core
}
