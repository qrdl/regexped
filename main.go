// Command regexped compiles regexp patterns to WASM match functions.
//
// Usage:
//
//	regexped [--debug] generate [--config=<file>] [--output=<file>|-]
//	regexped [--debug] compile  [--config=<file>] [--output=<file>|-]
//	regexped [--debug] merge    [--config=<file>] --main=<file> [--output=<file>|-] <regex1.wasm> ...
//
// The config file defaults to regexped.yaml in the current directory when not specified.
// Global flags (--debug) must appear before the subcommand name.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/merge"
)

// Exit codes. See plans/IMPROVEMENT_PLAN.md #24.
//
// Every failure path goes through failf, so these are the only non-zero codes
// the tool produces. Note that this requires the flag sets to use
// ContinueOnError: flag.ExitOnError exits with 2 of its own accord, which would
// report a bad command line as a compile failure.
const (
	exitOK      = 0 // success
	exitUsage   = 1 // bad command line: missing/unknown subcommand, missing or conflicting flags
	exitCompile = 2 // config content rejected, or compile / generate / merge failed
	exitIO      = 3 // filesystem failure: unreadable config, unwritable output
)

// failf reports a fatal error and exits with code.
//
// Errors go through slog rather than the log package. main used to call
// log.Fatal, but slog.SetDefault routes the log package through the slog
// handler at level INFO, and the handler's level is WARN unless --debug — so
// every one of those messages was silently discarded and the tool exited
// non-zero in complete silence. slog.Error is above the WARN threshold and
// therefore always reaches the user.
func failf(code int, format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(code)
}

// exitCodeFor returns exitIO when err carries a filesystem failure, and
// fallback otherwise. Every producer of these errors wraps with %w, so a
// missing config file is reported as an I/O failure while a malformed or
// invalid one is reported under the caller's own class.
func exitCodeFor(err error, fallback int) int {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, fs.ErrPermission) {
		return exitIO
	}
	return fallback
}

// parseFlags parses fs and terminates on anything other than success. The flag
// package has already printed the message and usage by the time Parse returns,
// so there is nothing to report here — only the exit code to set.
func parseFlags(fset *flag.FlagSet, args []string) {
	err := fset.Parse(args)
	switch {
	case err == nil:
		return
	case errors.Is(err, flag.ErrHelp):
		os.Exit(exitOK)
	default:
		os.Exit(exitUsage)
	}
}

func main() {
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Usage = printUsage
	parseFlags(flag.CommandLine, os.Args[1:])

	level := slog.LevelWarn
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(exitUsage)
	}

	switch flag.Arg(0) {
	case "generate":
		runGenerateCmd(flag.Args()[1:])
	case "compile":
		runCompileCmd(flag.Args()[1:])
	case "merge":
		runMergeCmd(flag.Args()[1:])
	default:
		slog.Error(fmt.Sprintf("unknown command: %s", flag.Arg(0)))
		printUsage()
		os.Exit(exitUsage)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: regexped [--debug] <command> [options]

Global flags:
  --debug   Enable debug logging (default: warnings only)

Commands:
  generate  Generate language stubs (Rust/Go/JS/TS/AS) from a config file
  compile   Compile regexp patterns to a standalone WASM module
  merge     Merge WASM modules into a single binary (thin wrapper around wasm-merge)

Run 'regexped <command> -h' for command-specific options.
`)
}

func runGenerateCmd(args []string) {
	fset := flag.NewFlagSet("generate", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	var out string
	fset.StringVar(&out, "output", "", "override stub output file from config; - writes to stdout")
	fset.StringVar(&out, "o", "", "output file (alias for --output)")
	parseFlags(fset, args)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.StubFile
	}
	if outPath == "" {
		failf(exitUsage, "generate: --output is required (or set stub_file in config)")
	}

	// Validate stub type before doing any work.
	stubType, err := generate.ResolveStubType(cfg)
	if err != nil {
		failf(exitCompile, "%v", err)
	}

	// Rust, Go, C, and AS stubs require import_module for the FFI/WASM import module name.
	// Config content rather than command line, hence exitCompile.
	if (stubType == "rust" || stubType == "go" || stubType == "c" || stubType == "as") && cfg.ImportModule == "" {
		failf(exitCompile, "generate: import_module is required in config for Rust, Go, C, and AS stubs")
	}

	if err := generate.CmdGenerateStub(cfg, outPath); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
}

func runCompileCmd(args []string) {
	fset := flag.NewFlagSet("compile", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	diagJSON := fset.String("diag-json", "", "write set-composition diagnostics as JSON to this path (- for stdout)")
	var out string
	fset.StringVar(&out, "output", "", "override wasm_file from config; - writes to stdout")
	fset.StringVar(&out, "o", "", "output file (alias for --output)")
	parseFlags(fset, args)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.WasmFile
	}
	if outPath == "" {
		failf(exitUsage, "compile: --output is required (or set wasm_file in config)")
	}

	// Validate output conflict before writing any output: refuse to send both
	// streams to the same destination (stdout/stdout, or the same filesystem
	// path), which would silently corrupt the WASM with the JSON diagnostics.
	if *diagJSON != "" && len(cfg.Sets) > 0 {
		if outPath == "-" && *diagJSON == "-" {
			failf(exitUsage, "compile: --output=- and --diag-json=- cannot both write to stdout; use a file path for one of them")
		}
		if outPath != "-" && *diagJSON != "-" {
			absOut, err1 := filepath.Abs(outPath)
			absDiag, err2 := filepath.Abs(*diagJSON)
			if err1 == nil && err2 == nil && absOut == absDiag {
				failf(exitUsage, "compile: --output and --diag-json resolve to the same path (%s); use distinct paths", absOut)
			}
		}
	}

	if err := compile.CmdCompile(cfg, outPath); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}

	if *diagJSON != "" && len(cfg.Sets) > 0 {
		if err := compile.CmdWriteDiagJSON(cfg, outPath, *diagJSON); err != nil {
			failf(exitCodeFor(err, exitCompile), "%v", err)
		}
	}
}

func runMergeCmd(args []string) {
	fset := flag.NewFlagSet("merge", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	mainFlag := fset.String("main", "", "main WASM file to merge into (required)")
	var out string
	fset.StringVar(&out, "output", "", "override output from config; - writes to stdout")
	fset.StringVar(&out, "o", "", "output file (alias for --output)")
	parseFlags(fset, args)

	if *mainFlag == "" {
		failf(exitUsage, "merge: --main=<file> is required")
	}

	regexWasms := fset.Args()
	if len(regexWasms) == 0 {
		failf(exitUsage, "merge: at least one regexp WASM file is required as a positional argument")
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.Output
	}
	if outPath == "" {
		failf(exitUsage, "merge: --output is required (or set output in config)")
	}

	if err := merge.CmdMerge(cfg, *mainFlag, outPath, regexWasms); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
}
