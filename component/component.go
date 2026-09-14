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
	"path/filepath"
	"strings"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/tools"
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

// resolveWasmTools finds wasm-tools the way merge finds its tools:
// wasm_tools_path, else $PATH, and no environment variable. See tools.Resolve.
func resolveWasmTools(cfg config.BuildConfig) (string, error) {
	return tools.Resolve("wasm_tools_path", cfg.ToolPathAsWritten("wasm_tools_path"), cfg.WasmToolsPath, "wasm-tools")
}

// Wrap turns core (a module compiled with CompileOptions.Component) plus witText
// into a component, written to out ("-" streams it to stdout).
//
// It writes ONLY the component. witText goes to `wasm-tools component embed` in a
// temporary directory and nowhere else: a caller that wants the interface text
// beside the component — which jco, wit-bindgen and wasmtime's bindgen! all need,
// and a component alone does not hand over in a form they take — writes it
// itself. CmdCompile does, staging both files so neither ships without the other.
func Wrap(cfg config.BuildConfig, core []byte, witText, out string) error {
	tool, err := resolveWasmTools(cfg)
	if err != nil {
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

	if err := tools.Run(tool, []string{"component", "embed", witPath, corePath, "--world", world, "-o", embedPath}, "", nil); err != nil {
		return fmt.Errorf("wasm-tools component embed: %w", err)
	}
	if out == "-" {
		// `new` cannot write to a pipe, so produce a file and stream it, the
		// way the compile command already streams a module.
		tmpOut := filepath.Join(dir, "component.wasm")
		if err := tools.Run(tool, []string{"component", "new", embedPath, "-o", tmpOut}, "", nil); err != nil {
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
	if err := tools.Run(tool, []string{"component", "new", embedPath, "-o", out}, "", nil); err != nil {
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
