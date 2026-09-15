package merge

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/ownership"
	"github.com/qrdl/regexped/internal/tools"
)

// resolveWasmMerge finds wasm-merge: wasm_merge_path, else $PATH. No
// environment variable is read. See tools.Resolve.
func resolveWasmMerge(cfg config.BuildConfig) (string, error) {
	return tools.Resolve("wasm_merge_path", cfg.ToolPathAsWritten("wasm_merge_path"), cfg.WasmMergePath, "wasm-merge")
}

// resolveWac finds wac the same way: wac_path, else $PATH.
func resolveWac(cfg config.BuildConfig) (string, error) {
	return tools.Resolve("wac_path", cfg.ToolPathAsWritten("wac_path"), cfg.WacPath, "wac")
}

// CmdMerge links the main WASM artifact with the regexp artifacts and writes
// output. mainWasm is the host's own binary; regexWasms are regexped's
// (at least one required).
//
// WHICH TOOL depends on the output kind, and that is the whole point of this
// function: a caller runs `regexped merge` and does not have to know whether
// its config compiled modules or components.
//
//	wasm_format: module     → wasm-merge, which links two core modules into one
//	wasm_format: component  → wac plug, which satisfies the socket component's
//	                          imports from the plug components' exports
//
// Composition is NOT merging: the output keeps two instances with two memories
// and the call between them goes through the canonical ABI, where wasm-merge
// produces a single module whose regexp code reads the host's memory directly.
// The command is the same; the cost model is not. See docs/component.md.
func CmdMerge(cfg config.BuildConfig, mainWasm, output string, regexWasms []string) error {
	if cfg.Component() {
		return composeComponents(cfg, mainWasm, output, regexWasms)
	}
	return mergeModules(cfg, mainWasm, output, regexWasms)
}

// composeComponents is `wac plug` — the component-format arm of CmdMerge.
//
//	wac plug --plug <regexp1.wasm> ... -o <output> <main.wasm>
//
// The main component is the SOCKET (the one with unsatisfied imports) and every
// regexp component is a PLUG. `--plug` may be repeated: wac is documented as
// plugging "the exports of any number of 'plug' components", so several regexp
// components compose in one call, with no intermediate files.
//
// ONE ASYMMETRY WITH THE MODULE PATH, and it is worth stating because the
// module path's comment says the opposite (see moduleNameForWasm): every regexp
// MODULE may safely share one import_module name, because nothing imports it.
// Components are matched by their WIT INTERFACE name — regexped:<wit_package>/
// matcher — which the socket genuinely imports, so two regexp components built
// from configs sharing a wit_package export the same interface and wac cannot
// tell which should satisfy the import. Multi-plug therefore requires DISTINCT
// wit_package values, where multi-module merging requires nothing — and
// checkDistinctPlugExports says so by name, because wac's own message for it is
// the one a genuine mismatch gives.
func composeComponents(cfg config.BuildConfig, mainWasm, output string, plugs []string) error {
	wacCmd, err := resolveWac(cfg)
	if err != nil {
		return fmt.Errorf("%w (needed for wasm_format: component)", err)
	}
	if err := checkDistinctPlugExports(cfg, plugs); err != nil {
		return err
	}

	args := []string{"plug"}
	for _, path := range plugs {
		args = append(args, "--plug", path)
	}
	args = append(args, "-o", output, mainWasm)

	slog.Debug("Composing components")
	if err := tools.Run(wacCmd, args, "", nil); err != nil {
		return fmt.Errorf("wac plug: %w", err)
	}
	// wac writes the output itself, as a child of this process: under the
	// Docker image that makes it root-owned on the host.
	ownership.Fix(output)

	info, err := os.Stat(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Composed", "output", output, "bytes", info.Size(), "plugs", len(plugs))
	return nil
}

// resolveWasmTools finds wasm-tools: wasm_tools_path, else $PATH.
func resolveWasmTools(cfg config.BuildConfig) (string, error) {
	return tools.Resolve("wasm_tools_path", cfg.ToolPathAsWritten("wasm_tools_path"), cfg.WasmToolsPath, "wasm-tools")
}

// checkDistinctPlugExports refuses two plugs that export the same regexped
// interface, before wac runs.
//
// wac reports that case as "the socket component had no matching imports for the
// plugs that were provided" — word for word what a genuine name mismatch gives —
// so the one mistake the distinct-wit_package rule exists to prevent was
// indistinguishable from every other. Each plug's world is read with
// `wasm-tools component wit`, one subprocess per plug. That makes a component
// merge need wasm-tools as well as wac, which costs nothing real: a component
// cannot be compiled without it.
func checkDistinctPlugExports(cfg config.BuildConfig, plugs []string) error {
	wasmTools, err := resolveWasmTools(cfg)
	if err != nil {
		return fmt.Errorf("%w (needed for wasm_format: component)", err)
	}
	owner := map[string]string{}
	for _, plug := range plugs {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(wasmTools, "component", "wit", plug)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("wasm-tools component wit %s: %w\n%s", plug, err, strings.TrimSpace(stderr.String()))
		}
		for _, name := range regexpedExports(stdout.String()) {
			if first, dup := owner[name]; dup {
				return fmt.Errorf("plugs %s and %s both export %s: composing several regexp components needs a distinct wit_package in each", first, plug, name)
			}
			owner[name] = plug
		}
	}
	return nil
}

// regexpedExports lists the `regexped:` interfaces a component's WORLD exports,
// from `wasm-tools component wit` output. Only the world block is read: the
// package blocks after it spell out interface bodies, which are not exports.
func regexpedExports(wit string) []string {
	var out []string
	inWorld := false
	for _, line := range strings.Split(wit, "\n") {
		switch {
		case strings.HasPrefix(line, "world "):
			inWorld = true
		case inWorld && strings.HasPrefix(line, "}"):
			return out
		case inWorld:
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "export regexped:") && strings.HasSuffix(t, ";") {
				out = append(out, strings.TrimSuffix(strings.TrimPrefix(t, "export "), ";"))
			}
		}
	}
	return out
}

// mergeModules is `wasm-merge` — the module-format arm of CmdMerge, and what
// this package did unconditionally before components existed. Users may invoke
// wasm-merge directly:
//
//	wasm-merge --enable-multimemory --enable-simd <main.wasm> main <regexp.wasm> <module> \
//	           --rename-export-conflicts -o output
func mergeModules(cfg config.BuildConfig, mainWasm, output string, regexWasms []string) error {
	// Resolved and verified before doing any work.
	wasmMergeCmd, err := resolveWasmMerge(cfg)
	if err != nil {
		return err
	}

	// Feature flags must precede input files so Binaryen applies them during parsing.
	// Main module is listed first so it keeps memory index 0 in the merged output
	// (wasm-merge assigns memory indices in argument order). Regexp modules come after
	// and get renumbered to higher indices by wasm-merge.
	mergeArgs := []string{"--enable-multimemory", "--enable-simd", "--enable-bulk-memory", "--enable-bulk-memory-opt"}
	mergeArgs = append(mergeArgs, mainWasm, "main")
	for _, path := range regexWasms {
		module := moduleNameForWasm(cfg, path)
		mergeArgs = append(mergeArgs, path, module)
	}
	mergeArgs = append(mergeArgs, "--rename-export-conflicts", "-o", output)

	slog.Debug("Merging modules")
	if err := tools.Run(wasmMergeCmd, mergeArgs, "", nil); err != nil {
		return fmt.Errorf("wasm-merge: %w", err)
	}
	// As in composeComponents: wasm-merge, not this process, created the file.
	ownership.Fix(output)

	info, err := os.Stat(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Merged", "output", output, "bytes", info.Size())
	return nil
}

// moduleNameForWasm returns the import_module name for a given WASM file.
// Uses cfg.ImportModule if set; falls back to the basename without extension.
//
// When cfg.ImportModule is set, EVERY regex module is handed the same name.
// That is deliberate and safe — do not "fix" it by deriving unique per-module
// names. wasm-merge uses this name only to resolve imports *between* the merged
// inputs, and a regexped regex module imports exactly one thing:
// "main"."memory". Nothing imports the regex module's own name, so it is a
// provider label with no consumers and duplicates cannot be ambiguous. The one
// name that IS imported ("main", passed for the host module) is unique.
//
// Verified empirically against Binaryen 132: two distinct regex modules merged
// under the same name produce a module whose exports each bind to their own DFA
// tables and memory, confirmed by executing both under wasmtime including
// negative cases.
//
// This rests on the import invariant above. If regex modules ever gain
// inter-module imports, revisit: they would then need unique names, while still
// exposing the host-facing import name the generated stubs expect.
func moduleNameForWasm(cfg config.BuildConfig, path string) string {
	if cfg.ImportModule != "" {
		return cfg.ImportModule
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
