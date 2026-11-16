// Command regexped compiles regexp patterns to WASM match functions.
//
// Usage:
//
//	regexped [--debug] generate [--config=<file>] [--output=<file>|-]
//	regexped [--debug] compile  [--config=<file>] [--output=<file>|-] [--verbose]
//	regexped [--debug] merge    [--config=<file>] --main=<file> [--output=<file>|-] <regex1.wasm> ...
//	regexped [--debug] check    [--config=<file>]
//	regexped help [<command>]
//	regexped --version
//
// The config file defaults to regexped.yaml in the current directory when not specified.
// Global flags (--debug, --version) must appear before the subcommand name.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/qrdl/regexped/check"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/component"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/internal/clilog"
	"github.com/qrdl/regexped/merge"
)

// Exit codes.
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
// therefore always reaches the user — as plain text (internal/clilog), or as
// slog's structured records under --debug.
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
	debugFlag := flag.Bool("debug", false, "enable debug logging: every record, structured")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() { printUsage(os.Stderr) }
	parseFlags(flag.CommandLine, os.Args[1:])

	if *debugFlag {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(clilog.New(os.Stderr)))
	}
	if *version {
		fmt.Println("regexped " + versionString())
		os.Exit(exitOK)
	}

	if flag.NArg() < 1 {
		printUsage(os.Stderr)
		os.Exit(exitUsage)
	}

	switch flag.Arg(0) {
	case "generate":
		runGenerateCmd(flag.Args()[1:])
	case "compile":
		runCompileCmd(flag.Args()[1:])
	case "merge":
		runMergeCmd(flag.Args()[1:])
	case "check":
		runCheckCmd(flag.Args()[1:])
	case "help":
		runHelpCmd(flag.Args()[1:])
	default:
		slog.Error(fmt.Sprintf("unknown command: %s", flag.Arg(0)))
		printUsage(os.Stderr)
		os.Exit(exitUsage)
	}
}

// versionString is the version the Go toolchain stamped into the binary: the
// module version for `go install …@v1.2.3` (and a release build from a tag),
// else "(devel)" with the VCS revision a local build records.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	v := info.Main.Version
	if v == "" {
		v = "(devel)"
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && len(s.Value) >= 12:
			rev = s.Value[:12]
		case s.Key == "vcs.modified" && s.Value == "true":
			dirty = "+dirty"
		}
	}
	if rev != "" && v == "(devel)" {
		v += " " + rev + dirty
	}
	return v
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: regexped [--debug] <command> [options]

Global flags:
  --debug     Print every log record, structured (default: warnings and errors, as plain text)
  --version   Print the version and exit

Commands:
  generate  Generate language stubs (Rust/Go/JS/TS/C/AS) or a WIT interface from a config file
  compile   Compile regexp patterns to a WASM module, or to a component plus its .wit
  merge     Link your binary with the regexp artifacts: wasm-merge for modules, wac plug for components
  check     Check a config the way compile and generate do, and write nothing
  help      Print this, or a command's options: regexped help <command>

Run 'regexped help <command>' for command-specific options.
`)
}

// commandFlags is each command's flag set, built without running it, so that
// `regexped help <command>` prints the same options `<command> -h` does.
var commandFlags = map[string]func() *flag.FlagSet{
	"generate": func() *flag.FlagSet { fs, _, _ := generateFlags(); return fs },
	"compile":  func() *flag.FlagSet { fs, _ := compileFlags(); return fs },
	"merge":    func() *flag.FlagSet { fs, _ := mergeFlags(); return fs },
	"check":    func() *flag.FlagSet { fs, _ := checkFlags(); return fs },
}

// runHelpCmd prints the usage, to stdout: help was asked for.
func runHelpCmd(args []string) {
	switch {
	case len(args) == 0:
		printUsage(os.Stdout)
	case len(args) > 1:
		failf(exitUsage, "help: one command at most, got %d arguments", len(args))
	default:
		mk, ok := commandFlags[args[0]]
		if !ok {
			failf(exitUsage, "help: unknown command: %s", args[0])
		}
		fs := mk()
		fs.SetOutput(os.Stdout)
		fmt.Fprintf(os.Stdout, "Usage of %s:\n", args[0])
		fs.PrintDefaults()
	}
}

// noArgs refuses positional arguments a command does not take: they used to
// be ignored, so `regexped compile other.yaml` compiled regexped.yaml.
func noArgs(fset *flag.FlagSet) {
	if fset.NArg() > 0 {
		failf(exitUsage, "%s: unexpected argument %q (flags go before arguments; the config is --config=<file>)", fset.Name(), fset.Arg(0))
	}
}

func generateFlags() (*flag.FlagSet, *string, *string) {
	fset := flag.NewFlagSet("generate", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	out := new(string)
	fset.StringVar(out, "output", "", "override stub output file from config; - writes to stdout. Without stub_type, its extension picks the language")
	fset.StringVar(out, "o", "", "output file (alias for --output)")
	return fset, configFile, out
}

func runGenerateCmd(args []string) {
	fset, configFile, outp := generateFlags()
	parseFlags(fset, args)
	noArgs(fset)
	out := *outp

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

	// The language: stub_type, else the extension of the path written.
	cfg, err = generate.ForOutput(cfg, out)
	if err != nil {
		failf(exitCompile, "%v", err)
	}
	if err := generate.CmdGenerateStub(cfg, outPath); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
}

type compileOpts struct {
	configFile, diagJSON, out *string
	verbose                   *bool
}

func compileFlags() (*flag.FlagSet, compileOpts) {
	fset := flag.NewFlagSet("compile", flag.ContinueOnError)
	o := compileOpts{out: new(string)}
	o.configFile = fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	o.diagJSON = fset.String("diag-json", "", "write set-composition diagnostics as JSON to this path (- for stdout)")
	o.verbose = fset.Bool("verbose", false, "report what the compiler decided per pattern and per set, to stderr")
	fset.StringVar(o.out, "output", "", "override wasm_file from config; - writes to stdout")
	fset.StringVar(o.out, "o", "", "output file (alias for --output)")
	return fset, o
}

func runCompileCmd(args []string) {
	fset, o := compileFlags()
	parseFlags(fset, args)
	noArgs(fset)
	configFile, diagJSON, verbose, out := o.configFile, o.diagJSON, o.verbose, *o.out

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
	if *diagJSON != "" {
		// Set-less configs are refused HERE rather than by CmdWriteDiagJSON,
		// which runs after the module has already been written. Both report the
		// same thing, but only this one reports it before the command has had
		// an effect: `compile --diag-json=x.json` on a config with no sets used
		// to exit non-zero AND leave a freshly generated .wasm behind, which is
		// the worst combination for a build script — a failure it must not
		// ignore, next to output it cannot tell apart from a success.
		if len(cfg.Sets) == 0 {
			failf(exitUsage, "compile: --diag-json: the config declares no sets, and set composition is all this reports")
		}
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

	// stderr, never stdout: `--output -` writes the WASM module to stdout, and
	// interleaving a report with it would corrupt the module.
	var report io.Writer
	if *verbose {
		report = os.Stderr
	}
	// `wasm_format: component` is a different output KIND, not a variant of the
	// module path: it wraps the core module through wasm-tools and writes a
	// sibling .wit. The choice comes from the config alone — there is
	// deliberately no --wasm-format flag, because `generate` must make the same
	// choice and a flag lets the two diverge.
	if cfg.Component() {
		if err := component.CmdCompile(cfg, outPath, report); err != nil {
			failf(exitCodeFor(err, exitCompile), "%v", err)
		}
	} else if err := compile.CmdCompileVerbose(cfg, outPath, report); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}

	if *diagJSON != "" {
		if err := compile.CmdWriteDiagJSON(cfg, outPath, *diagJSON); err != nil {
			failf(exitCodeFor(err, exitCompile), "%v", err)
		}
	}
}

func mergeFlags() (*flag.FlagSet, [3]*string) {
	fset := flag.NewFlagSet("merge", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	mainFlag := fset.String("main", "", "main WASM file to merge into (required)")
	out := new(string)
	// "-" is handled by merge.CmdMerge, which merges into a temporary file and
	// copies it: wasm-merge, handed -o verbatim, would create a file named "-".
	fset.StringVar(out, "output", "", "override output from config; - writes to stdout")
	fset.StringVar(out, "o", "", "output file (alias for --output)")
	return fset, [3]*string{configFile, mainFlag, out}
}

func runMergeCmd(args []string) {
	fset, f := mergeFlags()
	parseFlags(fset, args)
	configFile, mainFlag, out := f[0], f[1], *f[2]

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

func checkFlags() (*flag.FlagSet, *string) {
	fset := flag.NewFlagSet("check", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	return fset, configFile
}

// runCheckCmd is `regexped check`: the config loaded, compiled and its stub
// generated in memory, one summary line per pattern and set, nothing written.
func runCheckCmd(args []string) {
	fset, configFile := checkFlags()
	parseFlags(fset, args)
	noArgs(fset)
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
	if err := check.Run(cfg, os.Stdout); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
}
