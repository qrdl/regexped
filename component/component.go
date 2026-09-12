// Package component wraps a core WASM module into a Component Model component.
//
// It mirrors merge/: a thin shell-out to an external Bytecode Alliance tool,
// with the same binary-resolution order and the same habit of surfacing the
// tool's own stderr rather than paraphrasing it.
//
// Two steps, both `wasm-tools`:
//
//	wasm-tools component embed <wit> <core> --world <world> -o <tmp>
//	wasm-tools component new <tmp> -o <out>
//
// `embed` attaches the WIT to the core module as a custom section; `new` reads
// that section plus the canonical-ABI exports the compiler emitted
// (compile/component.go) and produces the component, synthesising the canon-lift
// wrappers. Shelling out is deliberate: a hand-rolled component encoder would
// have to track the Component Model spec release by release — async lifts,
// stream types, callback options — which wasm-tools does for free, and the
// wasm-merge precedent shows an external tool is acceptable here.
package component

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qrdl/regexped/config"
)

// Test seams. The error paths guarded by these are real — a full disk, a revoked
// permission, a vanished file — but unreachable from a test without indirection,
// because every one of them acts on a file in a directory the function itself
// just created. Left as package vars so those paths stay exercised rather than
// merely written.
var (
	writeFile = os.WriteFile
	readFile  = os.ReadFile
	statFile  = os.Stat
)

// resolveWasmTools returns the wasm-tools binary path, in the same lookup order
// merge uses for wasm-merge: config field → $WASM_TOOLS → $PATH.
func resolveWasmTools(cfg config.BuildConfig) string {
	if cfg.WasmTools != "" {
		return expandHome(cfg.WasmTools)
	}
	if env := os.Getenv("WASM_TOOLS"); env != "" {
		return expandHome(env)
	}
	return "wasm-tools"
}

// Wrap turns core (a module compiled with CompileOptions.Component) plus witText
// into a component, written to out.
//
// The WIT is written beside the component as well, because jco, wit-bindgen and
// wasmtime's bindgen! all need the interface text and a component alone does not
// hand it over in a form those tools take.
func Wrap(cfg config.BuildConfig, core []byte, witText, out string) error {
	tool := resolveWasmTools(cfg)
	if err := checkTool(tool); err != nil {
		return fmt.Errorf("%w (needed for wasm_format: component)", err)
	}
	world, err := cfg.WitWorldName()
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "regexped-component-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	corePath := filepath.Join(dir, "core.wasm")
	if err := writeFile(corePath, core, 0o644); err != nil {
		return fmt.Errorf("write core module: %w", err)
	}
	witPath := filepath.Join(dir, "regexped.wit")
	if err := writeFile(witPath, []byte(witText), 0o644); err != nil {
		return fmt.Errorf("write WIT: %w", err)
	}
	embedPath := filepath.Join(dir, "embed.wasm")

	if err := runTool(tool, "component", "embed", witPath, corePath, "--world", world, "-o", embedPath); err != nil {
		return fmt.Errorf("wasm-tools component embed: %w", err)
	}
	if out == "-" {
		// `new` cannot write to a pipe, so produce a file and stream it, the
		// way the compile command already streams a module.
		tmpOut := filepath.Join(dir, "component.wasm")
		if err := runTool(tool, "component", "new", embedPath, "-o", tmpOut); err != nil {
			return fmt.Errorf("wasm-tools component new: %w", err)
		}
		data, err := readFile(tmpOut)
		if err != nil {
			return fmt.Errorf("read component: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
	}
	if err := runTool(tool, "component", "new", embedPath, "-o", out); err != nil {
		return fmt.Errorf("wasm-tools component new: %w", err)
	}
	return nil
}

// WitPathFor is the sibling .wit path for a component output path: the same
// name with the extension replaced. `-` has no sibling.
func WitPathFor(out string) string {
	if out == "-" || out == "" {
		return ""
	}
	return strings.TrimSuffix(out, filepath.Ext(out)) + ".wit"
}

// runTool runs wasm-tools, letting its stderr through: its diagnostics name the
// offending export or type, and paraphrasing them would lose that.
func runTool(tool string, args ...string) error {
	cmd := exec.Command(tool, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkTool(path string) error {
	if filepath.IsAbs(path) {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("tool not found: %s", path)
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("tool not executable: %s", path)
		}
		return nil
	}
	if _, err := exec.LookPath(path); err != nil {
		return fmt.Errorf("tool not found in PATH: %s", path)
	}
	return nil
}

func expandHome(path string) string { return config.ExpandHome(path) }
