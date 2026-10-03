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
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/ownership"
	"github.com/qrdl/regexped/internal/tools"
	"github.com/qrdl/regexped/internal/utils"
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
// Components are matched by their WIT INTERFACE name — regexped:<wit_package>/
// matcher — which the socket genuinely imports, so two regexp components built
// from configs sharing a wit_package export the same interface and wac cannot
// tell which should satisfy the import. Multi-plug therefore requires DISTINCT
// wit_package values, as multi-module merging requires distinct import_module
// values (mergeModules) — and checkDistinctPlugExports says so by name, because
// wac's own message for it is the one a genuine mismatch gives.
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
	//
	// nontrapping-float-to-int is the HOST's feature, not ours: Go 1.26's wasip1
	// output uses i64.trunc_sat_f64_s (runtime.fastexprand), and without the flag
	// Binaryen rejects the main module ("all used features should be allowed"),
	// so every Go host failed to merge.
	mergeArgs := []string{"--enable-multimemory", "--enable-simd", "--enable-bulk-memory", "--enable-bulk-memory-opt",
		"--enable-nontrapping-float-to-int"}
	mergeArgs = append(mergeArgs, mainWasm, "main")
	// Two modules under one name are an ERROR: wasm-merge would resolve every
	// import of that name against one of them only.
	seen := map[string]string{"main": mainWasm}
	for _, path := range regexWasms {
		module := moduleNameForWasm(cfg, path)
		if prev, dup := seen[module]; dup {
			return fmt.Errorf("merge: %s and %s are both named %q: give each config its own import_module", prev, path, module)
		}
		seen[module] = path
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

// moduleNameForWasm returns the module name a regexp WASM file is merged under:
// the import_module its stubs import from, which `regexped compile` records in
// the module itself (abi.ImportModuleSection). A module without the record —
// built before it existed, or not by `regexped compile` — gets the config's
// import_module, else its file name without the extension.
//
// The name is the module's own, not the config's, because a merged program is
// assembled from modules built from several configs: one config's
// import_module named them all, so modules with distinct names could not be
// merged at all, and modules sharing one were each handed the same name — and
// every stub's call to the search setter (abi.SearchExport), which each module
// exports under one fixed name, then bound to one module only.
func moduleNameForWasm(cfg config.BuildConfig, path string) string {
	if raw, err := os.ReadFile(path); err == nil {
		if name, ok := utils.CustomSection(raw, abi.ImportModuleSection); ok && len(name) > 0 {
			return string(name)
		}
	}
	if cfg.ImportModule != "" {
		return cfg.ImportModule
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
