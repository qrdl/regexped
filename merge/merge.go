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

// CmdMerge merges the main WASM module with the regexp WASM modules using wasm-merge.
// mainWasm is the path to the host main module.
// regexWasms are the regexp WASM files to merge (at least one required).
//
// This is a thin wrapper around wasm-merge. Users may invoke wasm-merge directly:
//
//	wasm-merge --enable-multimemory --enable-simd <main.wasm> main <regexp.wasm> <module> \
//	           --rename-export-conflicts -o output
//
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

func CmdMerge(cfg config.BuildConfig, mainWasm, output string, regexWasms []string) error {
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
