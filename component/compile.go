package component

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

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
// (generate), compile a core module carrying the matching adapters, stage the
// .wit and the wrapped component, and rename both into place. Deriving the names
// once is what keeps the interface and the module from disagreeing about a
// single export; staging is what keeps a half-finished build from shipping a
// .wit the component beside it does not implement.
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

	if output == "-" {
		// The binary goes to stdout and there is nowhere beside it for the
		// interface text, which a consumer cannot build without. Say so rather
		// than lose it silently.
		fmt.Fprintln(os.Stderr, "regexped: no sibling .wit written for `-`; run `regexped generate` with `stub_type: wit`")
		return Wrap(cfg, core, witText, output)
	}

	// The WIT rides alongside the binary: jco, wit-bindgen and wasmtime's
	// bindgen! all need the interface text, and a component does not hand it
	// over in a form they take.
	//
	// BOTH are STAGED next to their destinations and renamed only once wrapping
	// has succeeded. Whichever of the two were written first, a failure in the
	// step after it — a missing `wasm-tools` is the everyday one — would leave a
	// fresh file beside a stale one, and a consumer then builds against a
	// contract the binary does not implement. Staged in the DESTINATION
	// directory, never a temp dir, so the rename cannot fail for crossing a
	// filesystem.
	//
	// The .wit is renamed first because that rename is the one that can
	// realistically fail — something already occupying its path — and failing it
	// must not leave a fresh .wasm behind. The reverse order is then all that is
	// left uncovered: two fully written files, and the second rename failing for
	// a destination `wasm-tools` could not have written to either.
	witPath := WitPathFor(output)
	if err := os.MkdirAll(filepath.Dir(witPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(witPath), err)
	}
	witTmp := witPath + ".tmp"
	defer os.Remove(witTmp) // a no-op once it has been renamed away
	if err := writeFile(witTmp, []byte(witText), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", witPath, err)
	}
	coreTmp := output + ".tmp"
	defer os.Remove(coreTmp)
	if err := Wrap(cfg, core, witText, coreTmp); err != nil {
		return err
	}
	if err := os.Rename(witTmp, witPath); err != nil {
		return fmt.Errorf("write %s: %w", witPath, err)
	}
	if err := os.Rename(coreTmp, output); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
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
	witText, names, resources, setNames, prefix, err := generate.ComponentArtifactsWithSets(cfg)
	if err != nil {
		return nil, "", err
	}
	if len(names) == 0 && len(resources) == 0 && len(setNames) == 0 {
		return nil, "", fmt.Errorf("no exports to build a component from: every regexp entry needs at least one of match_func, find_func or groups_func, or a sets: entry needs a capability")
	}

	// ONE path, for a config with sets and for one without. CompileFileComponent
	// delegates to Compile when cfg.Sets is empty and is byte-identical to
	// calling it directly (TestSetComponentNoSetsDelegates is the standing
	// proof), so dispatching here as well only gave the same CompileOptions two
	// construction sites — and a field added to one and not the other is silent.
	//
	// Standalone is FORCED down there: a component owns and exports its own
	// memory, so `output:` — which selects the embedded shape for a module, and
	// is the merge target for both — must not reach that choice.
	core, _, err = compile.CompileFileComponent(cfg, prefix, names,
		toCompilePatternResources(resources), toCompileSetNames(setNames), rep)
	if err != nil {
		return nil, "", fmt.Errorf("compile: %w", err)
	}
	return core, witText, nil
}

// toCompilePatternResources converts generate/'s per-resource name table into
// compile/'s, for the same reason toCompileSetNames exists: compile/ cannot
// import generate/, so this function is the seam and the only place the two
// shapes have to agree.
func toCompilePatternResources(in map[string]generate.PatternResourceNames) map[string]compile.ComponentPatternResource {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]compile.ComponentPatternResource, len(in))
	for name, n := range in {
		out[name] = compile.ComponentPatternResource{
			Groups:         n.Groups,
			Constructor:    n.Constructor,
			Next:           n.Next,
			Dtor:           n.Dtor,
			ResourceImport: n.ResourceImport,
			ResourceNew:    n.ResourceNew,
		}
	}
	return out
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
