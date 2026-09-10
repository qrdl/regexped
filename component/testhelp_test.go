package component

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
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
