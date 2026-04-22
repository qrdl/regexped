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

// CmdMerge merges the main WASM module with the regex WASM modules using wasm-merge.
// mainWasm is the path to the host main module.
// regexWasms are the regex WASM files to merge (at least one required).
//
// This is a thin wrapper around wasm-merge. Users may invoke wasm-merge directly:
//
//	wasm-merge --enable-multimemory --enable-simd <main.wasm> main <regex.wasm> <module> \
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
	// (wasm-merge assigns memory indices in argument order). Regex modules come after
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

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
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
