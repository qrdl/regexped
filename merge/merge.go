package merge

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qrdl/regexped/config"
)

// resolveWasmMerge returns the wasm-merge binary path using the lookup order:
// config field → $WASM_MERGE env var → "wasm-merge" in $PATH.
func resolveWasmMerge(cfg config.BuildConfig) string {
	if cfg.WasmMerge != "" {
		return expandHome(cfg.WasmMerge)
	}
	if env := os.Getenv("WASM_MERGE"); env != "" {
		return expandHome(env)
	}
	return "wasm-merge"
}

// resolveWac returns the wac binary path, in the same lookup order the other two
// external tools use: config field → $WAC → "wac" in $PATH.
//
// Like wasm_tools: and unlike wasm_merge:, the config value is NOT resolved
// against the config file's directory. A bare tool name must stay a bare name
// for $PATH lookup to find it.
func resolveWac(cfg config.BuildConfig) string {
	if cfg.Wac != "" {
		return expandHome(cfg.Wac)
	}
	if env := os.Getenv("WAC"); env != "" {
		return expandHome(env)
	}
	return "wac"
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
// wit_package values, where multi-module merging requires nothing.
func composeComponents(cfg config.BuildConfig, mainWasm, output string, plugs []string) error {
	wacCmd := resolveWac(cfg)
	if err := checkTool(wacCmd); err != nil {
		return fmt.Errorf("%w (needed for wasm_format: component)", err)
	}

	args := []string{"plug"}
	for _, path := range plugs {
		args = append(args, "--plug", path)
	}
	args = append(args, "-o", output, mainWasm)

	slog.Debug("Composing components")
	if err := runCmd(wacCmd, args, "", nil); err != nil {
		return fmt.Errorf("wac plug: %w", err)
	}

	info, err := os.Stat(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Composed", "output", output, "bytes", info.Size(), "plugs", len(plugs))
	return nil
}

// mergeModules is `wasm-merge` — the module-format arm of CmdMerge, and what
// this package did unconditionally before components existed. Users may invoke
// wasm-merge directly:
//
//	wasm-merge --enable-multimemory --enable-simd <main.wasm> main <regexp.wasm> <module> \
//	           --rename-export-conflicts -o output
func mergeModules(cfg config.BuildConfig, mainWasm, output string, regexWasms []string) error {
	wasmMergeCmd := resolveWasmMerge(cfg)

	// Verify tool is available before doing any work.
	if err := checkTool(wasmMergeCmd); err != nil {
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
	if err := runCmd(wasmMergeCmd, mergeArgs, "", nil); err != nil {
		return fmt.Errorf("wasm-merge: %w", err)
	}

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

// checkTool verifies that the given executable exists and is accessible.
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

// expandHome replaces a leading "~/" with the user's home directory. The
// implementation lives in config so the config-file paths (output, wasm_file,
// stub_file, wasm_merge) and this one — the wasm-merge binary, which can also
// come from $WASM_MERGE and so never passes through config — expand
// identically.
func expandHome(path string) string {
	return config.ExpandHome(path)
}

// runCmd executes name with args, streaming stdout and stderr to the process's
// own stdout/stderr. dir sets the working directory (empty = inherit);
// extraEnv, if non-nil, adds variables to the inherited environment.
func runCmd(name string, args []string, dir string, extraEnv []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.Run()
}
