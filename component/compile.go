package component

import (
	"fmt"
	"io"
	"log/slog"

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
	var rep *compile.Reporter
	if report != nil {
		rep = &compile.Reporter{}
	}
	core, witText, err := Core(cfg, rep)
	if err != nil {
		return err
	}
	slog.Info("Compiling regexps", "count", len(cfg.Regexps), "sets", len(cfg.Sets), "output", output, "format", "component")
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
	if err := writeFile(witPath, []byte(witText), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", witPath, err)
	}
	info, err := statFile(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Done", "component", output, "bytes", info.Size(), "wit", witPath)
	return nil
}

// Core compiles the CORE MODULE of a component — the bytes `wasm-tools` then
// wraps — together with the WIT text that describes it.
//
// It is exported because it is the only place the two halves of a component
// build are joined, and three callers need exactly that join: CmdCompile,
// the fixture test that pins these bytes, and the property test that drives the
// adapters directly. A caller that rebuilt the join would be free to pass
// compile/ a name generate/ never derived, which is the one thing this
// arrangement exists to prevent.
//
// rep may be nil.
func Core(cfg config.BuildConfig, rep *compile.Reporter) (core []byte, witText string, err error) {
	if !cfg.Component() {
		return nil, "", fmt.Errorf("component.Core called for wasm_format: %q", cfg.WasmFormat)
	}
	witText, names, setNames, prefix, err := generate.ComponentArtifactsWithSets(cfg)
	if err != nil {
		return nil, "", err
	}
	if len(names) == 0 && len(setNames) == 0 {
		return nil, "", fmt.Errorf("no exports to build a component from: every regexp entry needs at least one of match_func, find_func or groups_func, or a sets: entry needs a capability")
	}

	// Standalone is FORCED whichever path runs: a component owns and exports
	// its own memory, so `output:` — which selects the embedded shape for a
	// module, and is the merge target for both — must not reach that choice.
	if len(cfg.Sets) > 0 {
		// The set path is a second assembler and needs the set names too.
		core, _, err = compile.CompileFileComponent(cfg, prefix, names, toCompileSetNames(setNames), rep)
	} else {
		core, _, err = compile.Compile(cfg.Regexps, 0, true, compile.CompileOptions{
			MaxDFAStates:         cfg.MaxDFAStates,
			MaxTDFARegs:          cfg.MaxTDFARegs,
			Report:               rep,
			Component:            true,
			ComponentPackage:     prefix,
			ComponentExportNames: names,
		})
	}
	if err != nil {
		return nil, "", fmt.Errorf("compile: %w", err)
	}
	return core, witText, nil
}

// toCompileSetNames converts generate/'s per-set name table into compile/'s.
//
// The two structs are deliberately separate rather than shared: compile/ cannot
// import generate/ (generate/ imports compile/), so the alternative is a third
// package for one struct. This function is the seam, and it is the only place
// the two shapes have to agree.
func toCompileSetNames(in map[string]generate.SetExportNames) map[string]compile.ComponentSetNames {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]compile.ComponentSetNames, len(in))
	for name, n := range in {
		out[name] = compile.ComponentSetNames{
			Caps:           n.Caps,
			Constructor:    n.Constructor,
			Next:           n.Next,
			Dtor:           n.Dtor,
			ResourceImport: n.ResourceImport,
			ResourceNew:    n.ResourceNew,
		}
	}
	return out
}
