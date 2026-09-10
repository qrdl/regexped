package component

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
)

// CmdCompile is `regexped compile` for `wasm_format: component`.
//
// It lives here rather than in compile/ because it needs the WIT generator, and
// generate/ already imports compile/ — so compile/ cannot import generate/.
// This package sits above both.
//
// The sequence: derive the WIT and the canonical export names from ONE source
// (generate), compile a core module carrying the matching adapters, wrap it, and
// write the .wit beside the binary. Deriving the names once is what keeps the
// interface and the module from disagreeing about a single export.
func CmdCompile(cfg config.BuildConfig, output string, report io.Writer) error {
	if !cfg.Component() {
		return fmt.Errorf("component.CmdCompile called for wasm_format: %q", cfg.WasmFormat)
	}
	witText, err := generate.WitText(cfg)
	if err != nil {
		return err
	}
	names, err := generate.ComponentExportNames(cfg)
	if err != nil {
		return err
	}
	prefix, err := generate.WitInterfacePrefix(cfg)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no exports to build a component from: every regexp entry needs at least one of match_func, find_func or groups_func")
	}

	slog.Info("Compiling regexps", "count", len(cfg.Regexps), "output", output, "format", "component")

	var rep *compile.Reporter
	if report != nil {
		rep = &compile.Reporter{}
	}
	// Standalone is FORCED: a component owns and exports its own memory, so
	// `output:` (the wasm-merge target) is meaningless here and must not be
	// allowed to select the embedded shape.
	core, _, err := compile.Compile(cfg.Regexps, 0, true, compile.CompileOptions{
		MaxDFAStates:         cfg.MaxDFAStates,
		MaxTDFARegs:          cfg.MaxTDFARegs,
		Report:               rep,
		Component:            true,
		ComponentPackage:     prefix,
		ComponentExportNames: names,
	})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	rep.Render(report)

	if err := Wrap(cfg, core, witText, output); err != nil {
		return err
	}
	if output == "-" {
		return nil
	}

	// The WIT rides alongside the binary: jco, wit-bindgen and wasmtime's
	// bindgen! all need the interface text, and a component does not hand it
	// over in a form they take.
	witPath := WitPathFor(output)
	if err := os.WriteFile(witPath, []byte(witText), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", witPath, err)
	}
	info, err := os.Stat(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Done", "component", output, "bytes", info.Size(), "wit", witPath)
	return nil
}
