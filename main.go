// Command regexped compiles regexp patterns to WASM match functions.
//
// Usage:
//
//	regexped [--debug] generate [--config=<file>] [--output=<file>|-]
//	regexped [--debug] compile  [--config=<file>] [--output=<file>|-] [--verbose[=brief|full]] [--verbose-format=plain|json]
//	regexped [--debug] merge    [--config=<file>] --main=<file> [--output=<file>|-] <regex1.wasm> ...
//	regexped [--debug] check    [--config=<file>] [--verbose[=brief|full]] [--verbose-format=plain|json]
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
	"runtime/debug"
	"strings"

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
	"check":    func() *flag.FlagSet { fs, _, _ := checkFlags(); return fs },
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
		if a := fset.Arg(0); a == string(compile.VerboseBrief) || a == string(compile.VerboseFull) {
			failf(exitUsage, "%s: unexpected argument %q (the level goes after an '=': --verbose=%s)", fset.Name(), a, a)
		}
		failf(exitUsage, "%s: unexpected argument %q (flags go before arguments; the config is --config=<file>)", fset.Name(), fset.Arg(0))
	}
}

// verboseFlag is --verbose[=brief|full]: a bare flag means brief.
type verboseFlag struct {
	set   bool
	level compile.VerboseLevel
}

func (v *verboseFlag) String() string   { return string(v.level) }
func (v *verboseFlag) IsBoolFlag() bool { return true }
func (v *verboseFlag) Set(s string) error {
	l, err := compile.ParseVerboseLevel(s)
	if err != nil {
		return errors.New("want brief or full")
	}
	v.set, v.level = true, l
	return nil
}

// formatFlag is --verbose-format=plain|json.
type formatFlag struct {
	set    bool
	format compile.VerboseFormat
}

func (f *formatFlag) String() string { return string(f.format) }
func (f *formatFlag) Set(s string) error {
	v, err := compile.ParseVerboseFormat(s)
	if err != nil {
		return errors.New("want plain or json")
	}
	f.set, f.format = true, v
	return nil
}

// reportFlags are the report flags compile and check share.
type reportFlags struct {
	verbose verboseFlag
	format  formatFlag
}

func (r *reportFlags) register(fset *flag.FlagSet) {
	fset.Var(&r.verbose, "verbose", "report what the compiler decided per pattern and per set, to stdout: brief (the default) or full")
	fset.Var(&r.format, "verbose-format", "write the report as plain (the default) or json; implies --verbose=brief when --verbose is not given")
}

// on reports whether a report was asked for, and at which level and format.
func (r *reportFlags) on() (bool, compile.VerboseLevel, compile.VerboseFormat) {
	if !r.verbose.set && !r.format.set {
		return false, "", ""
	}
	level, format := compile.VerboseBrief, compile.VerbosePlain
	if r.verbose.set {
		level = r.verbose.level
	}
	if r.format.set {
		format = r.format.format
	}
	return true, level, format
}

// refuseDiagJSON stops a command line that still passes --diag-json, which the
// report replaced.
func refuseDiagJSON(cmd string, args []string) {
	for _, a := range args {
		if a == "--" {
			return
		}
		for _, f := range []string{"-diag-json", "--diag-json"} {
			if a == f || strings.HasPrefix(a, f+"=") {
				failf(exitUsage, "%s: --diag-json was removed; the report carries the set diagnostics: --verbose=full --verbose-format=json", cmd)
			}
		}
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
	configFile, out *string
	report          *reportFlags
}

func compileFlags() (*flag.FlagSet, compileOpts) {
	fset := flag.NewFlagSet("compile", flag.ContinueOnError)
	o := compileOpts{out: new(string), report: &reportFlags{}}
	o.configFile = fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	o.report.register(fset)
	fset.StringVar(o.out, "output", "", "override wasm_file from config; - writes to stdout")
	fset.StringVar(o.out, "o", "", "output file (alias for --output)")
	return fset, o
}

func runCompileCmd(args []string) {
	refuseDiagJSON("compile", args)
	fset, o := compileFlags()
	parseFlags(fset, args)
	noArgs(fset)
	configFile, out := o.configFile, *o.out
	report, level, format := o.report.on()

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
	// The report goes to stdout, so the module cannot: refused before
	// anything is compiled or written.
	if report && outPath == "-" {
		failf(exitUsage, "compile: --output=- and the report both write to stdout; write the module to a file, or drop --verbose / --verbose-format")
	}

	var w io.Writer
	if report {
		w = os.Stdout
	}
	// `wasm_format: component` is a different output KIND, not a variant of the
	// module path: it wraps the core module through wasm-tools and writes a
	// sibling .wit. The choice comes from the config alone — there is
	// deliberately no --wasm-format flag, because `generate` must make the same
	// choice and a flag lets the two diverge.
	if cfg.Component() {
		if err := component.CmdCompileReport(cfg, outPath, w, level, format); err != nil {
			failf(exitCodeFor(err, exitCompile), "%v", err)
		}
	} else if err := compile.CmdCompileReport(cfg, outPath, w, level, format); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
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

func checkFlags() (*flag.FlagSet, *string, *reportFlags) {
	fset := flag.NewFlagSet("check", flag.ContinueOnError)
	configFile := fset.String("config", "", "YAML config file (default: regexped.yaml in cwd)")
	rf := &reportFlags{}
	rf.register(fset)
	return fset, configFile, rf
}

// runCheckCmd is `regexped check`: the config loaded, compiled and its stub
// generated in memory, nothing written. It answers by its exit code; with a
// report flag it prints the report compile would print.
func runCheckCmd(args []string) {
	refuseDiagJSON("check", args)
	fset, configFile, rf := checkFlags()
	parseFlags(fset, args)
	noArgs(fset)
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
	var w io.Writer
	report, level, format := rf.on()
	if report {
		w = os.Stdout
	}
	if err := check.Run(cfg, w, level, format); err != nil {
		failf(exitCodeFor(err, exitCompile), "%v", err)
	}
}
