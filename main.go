// Command regexped compiles regex patterns to WASM DFA match functions.
//
// Usage:
//
//	regexped stub    [--config=<file>] [--out-dir=<dir>] --rust
//	regexped compile [--config=<file>] [--out-dir=<dir>] --wasm-input=<file>
//	regexped merge   [--config=<file>] [--output=<file>] <main.wasm> <regex1.wasm> ...
//
// The config file defaults to regexped.yaml in the current directory when not specified.
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/merge"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/compile"
)

func main() {
	log.SetFlags(0)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "stub":
		runStubCmd(os.Args[2:])
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
  stub     Generate language stubs for each regex in the config
  compile  Compile regex patterns to WASM modules
  merge    Patch memory and merge WASM modules into a single binary

Run 'regexped <command> -h' for command-specific options.
`)
}

func runStubCmd(args []string) {
	fs := flag.NewFlagSet("stub", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	rust := fs.Bool("rust", false, "generate Rust stub files")
	var outDir string
	fs.StringVar(&outDir, "out-dir", "", "output directory for stub files (overrides config stub_dir)")
	fs.StringVar(&outDir, "d", "", "output directory for stub files (alias for --out-dir)")
	fs.Parse(args)

	if !*rust {
		fmt.Fprintln(os.Stderr, "stub: specify at least one output format (e.g. --rust)")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	if outDir == "" {
		if cfg.StubDir != "" {
			outDir = cfg.StubDir
		} else {
			outDir = "."
		}
	}
	if err := generate.CmdStub(cfg, outDir, *rust); err != nil {
		log.Fatal(err)
	}
}

func runCompileCmd(args []string) {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	wasmInput  := fs.String("wasm-input", "", "pre-built WASM file used to measure memory layout (required)")
	var outDir string
	fs.StringVar(&outDir, "out-dir", "", "output directory for compiled WASM files (overrides config wasm_dir)")
	fs.StringVar(&outDir, "d", "", "output directory for compiled WASM files (alias for --out-dir)")
	fs.Parse(args)

	if *wasmInput == "" {
		fmt.Fprintln(os.Stderr, "compile: --wasm-input is required")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	if outDir == "" {
		if cfg.WasmDir != "" {
			outDir = cfg.WasmDir
		} else {
			outDir = "."
		}
	}
	if err := compile.CmdCompile(cfg, *wasmInput, outDir); err != nil {
		log.Fatal(err)
	}
}

func runMergeCmd(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	configFile := fs.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	var outputFile string
	fs.StringVar(&outputFile, "output", "", "output WASM file (overrides YAML 'output' field)")
	fs.StringVar(&outputFile, "o", "", "output WASM file (alias for --output)")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) < 2 {
		fmt.Fprintln(os.Stderr, "merge: requires <main.wasm> and at least one <regex.wasm>")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	outFile := outputFile
	if outFile == "" {
		outFile = cfg.Output
	}
	if outFile == "" {
		fmt.Fprintln(os.Stderr, "merge: --output is required (or set 'output' in YAML config)")
		os.Exit(1)
	}
	if err := merge.CmdMerge(cfg, outFile, inputs); err != nil {
		log.Fatal(err)
	}
}
