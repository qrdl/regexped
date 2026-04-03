// Command regexped compiles regex patterns to WASM DFA match functions.
//
// Usage:
//
//	regexped generate [--config=<file>] [--output=<file>|-]
//	regexped compile  [--config=<file>] [--main=<file>] [--output=<file>|-]
//	regexped merge    [--config=<file>] (--main=<file>|--dummy-main) [--output=<file>|-] <regex1.wasm> ...
//
// The config file defaults to regexped.yaml in the current directory when not specified.
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/merge"
)

func main() {
	log.SetFlags(0)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		runGenerateCmd(os.Args[2:])
	case "compile":
		runCompileCmd(os.Args[2:])
	case "merge":
		runMergeCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: regexped <command> [options]

Commands:
  generate  Generate language stubs (Rust/JS/TS) from a config file
  compile   Compile regex patterns to a WASM module
  merge     Patch memory and merge WASM modules into a single binary

Run 'regexped <command> -h' for command-specific options.
`)
}

func runGenerateCmd(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	var out string
	fs.StringVar(&out, "output", "", "override stub output file from config; - writes to stdout")
	fs.StringVar(&out, "o", "", "output file (alias for --output)")
	fs.Parse(args)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.StubFile
	}
	if outPath == "" {
		fmt.Fprintln(os.Stderr, "generate: --output is required (or set stub_file in config)")
		os.Exit(1)
	}

	// Validate stub type before doing any work.
	stubType, err := generate.ResolveStubType(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Rust stubs require import_module for the pub mod block name.
	if stubType == "rust" && cfg.ImportModule == "" {
		fmt.Fprintln(os.Stderr, "generate: import_module is required in config for Rust stubs")
		os.Exit(1)
	}

	if err := generate.CmdGenerateStub(cfg, outPath); err != nil {
		log.Fatal(err)
	}
}

func runCompileCmd(args []string) {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	mainWasm := fs.String("main", "", "main WASM file for memory layout; if omitted, rustTop=0 is assumed")
	var out string
	fs.StringVar(&out, "output", "", "override wasm_file from config; - writes to stdout")
	fs.StringVar(&out, "o", "", "output file (alias for --output)")
	fs.Parse(args)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.WasmFile
	}
	if outPath == "" {
		fmt.Fprintln(os.Stderr, "compile: --output is required (or set wasm_file in config)")
		os.Exit(1)
	}

	if err := compile.CmdCompile(cfg, *mainWasm, outPath); err != nil {
		log.Fatal(err)
	}
}

func runMergeCmd(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	mainFlag := fs.String("main", "", "main WASM file (mutually exclusive with --dummy-main)")
	dummyMain := fs.Bool("dummy-main", false, "use built-in dummy main (for JS/browser/CF Worker deployments)")
	var out string
	fs.StringVar(&out, "output", "", "override output from config; - writes to stdout")
	fs.StringVar(&out, "o", "", "output file (alias for --output)")
	fs.Parse(args)

	// Validate flags before loading config.
	if *mainFlag != "" && *dummyMain {
		fmt.Fprintln(os.Stderr, "merge: --main and --dummy-main are mutually exclusive")
		os.Exit(1)
	}
	if *mainFlag == "" && !*dummyMain {
		fmt.Fprintln(os.Stderr, "merge: --main=<file> or --dummy-main is required")
		os.Exit(1)
	}

	regexWasms := fs.Args()
	if len(regexWasms) == 0 {
		fmt.Fprintln(os.Stderr, "merge: at least one regex WASM file is required as a positional argument")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Resolve effective output path.
	outPath := out
	if outPath == "" {
		outPath = cfg.Output
	}
	if outPath == "" {
		fmt.Fprintln(os.Stderr, "merge: --output is required (or set output in config)")
		os.Exit(1)
	}

	mainWasm := *mainFlag // empty string when --dummy-main is used
	if err := merge.CmdMerge(cfg, mainWasm, outPath, regexWasms); err != nil {
		log.Fatal(err)
	}
}
