package component

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

var updateFixture = flag.Bool("update-component-core", false,
	"regenerate component/testdata/component_core/expected.wasm")

// The CORE module is pinned, not the wrapped component: the component's bytes
// are produced by whichever wasm-tools is installed, so pinning them would make
// the test fail on a tool upgrade that changed nothing here. The core module is
// entirely ours — adapters, allocator, post-return, export names — and it is
// where a regression in this work would actually show.
//
// It lives in this package rather than beside compile/testdata/byteident because
// building it needs the WIT-derived export names, and generate/ already imports
// compile/, so compile/ cannot import generate/.
func TestComponentCoreByteIdentical(t *testing.T) {
	dir := filepath.Join("testdata", "component_core")
	raw, err := os.ReadFile(filepath.Join(dir, "patterns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.BuildConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse fixture config: %v", err)
	}
	if !cfg.Component() {
		t.Fatal("the fixture config must set wasm_format: component")
	}

	got := buildCore(t, cfg)

	path := filepath.Join(dir, "expected.wasm")
	if *updateFixture {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s (%d bytes)", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (run with -update-component-core to create it): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("component core module differs from the checked-in fixture: got %d bytes, want %d.\n"+
			"If the change is intended, rerun with -update-component-core and review the diff.",
			len(got), len(want))
	}

	// A fixture that pins bytes nothing can load would be worse than none.
	if tool, err := exec.LookPath("wasm-tools"); err == nil {
		if out, err := runCapture(tool, "validate", writeTemp(t, got)); err != nil {
			t.Fatalf("wasm-tools rejected the pinned core module: %v\n%s", err, out)
		}
	} else {
		t.Log("wasm-tools not in PATH; skipping validation of the pinned bytes")
	}
}

// The adapters must not disturb the pattern functions: with Component off, the
// same config compiles to what it always did, and the component build must be
// that module plus APPENDED functions — never a reordering of it. Checked by
// requiring the module-format bytes to be a strict prefix... they are not, since
// section sizes and counts change, so instead the check is structural: every
// export the module build has, the component build still has, at the same
// function index.
func TestComponentKeepsModuleExportsAtTheSameIndices(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "component_core", "patterns.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.BuildConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}

	componentCore := buildCore(t, cfg)

	moduleCfg := cfg
	moduleCfg.WasmFormat = ""
	plain, _, err := compile.Compile(moduleCfg.Regexps, 0, true, compile.CompileOptions{})
	if err != nil {
		t.Fatalf("module compile: %v", err)
	}

	tool, err := exec.LookPath("wasm-tools")
	if err != nil {
		t.Skip("wasm-tools not in PATH")
	}
	plainExports := exportMap(t, tool, plain)
	componentExports := exportMap(t, tool, componentCore)

	if len(plainExports) == 0 {
		t.Fatal("the module build exported nothing; the fixture is not exercising anything")
	}
	for name, idx := range plainExports {
		got, ok := componentExports[name]
		if !ok {
			t.Errorf("component build dropped the raw export %q", name)
			continue
		}
		if got != idx {
			t.Errorf("raw export %q moved from function %s to %s — adapters must be APPENDED, "+
				"so no pattern function index changes", name, idx, got)
		}
	}
}

// buildCore compiles cfg's core module with the component adapters, deriving the
// export names the same way CmdCompile does.
func buildCore(t *testing.T, cfg config.BuildConfig) []byte {
	t.Helper()
	core, _, err := Core(cfg, nil)
	if err != nil {
		t.Fatalf("component compile: %v", err)
	}
	return core
}
