package compile

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/utils"
)

// MatchMode controls the generated WASM function's matching behaviour.
type MatchMode int

const (
	// ModeAnchoredMatch generates a function (ptr, len i32) -> i32 that matches
	// the full input anchored at position 0, returning end position or -1.
	ModeAnchoredMatch MatchMode = 0

	// ModeFind generates a function (ptr, len i32) -> i64 that scans the input
	// for the leftmost-longest match, returning packed (start<<32|end) or -1.
	ModeFind MatchMode = 1
)

// EngineType represents the type of regex engine implementation.
type EngineType byte

const (
	EngineDFA EngineType = iota + 1
	EngineBacktrack
	EngineOnePass
	EnginePikeVM
	EngineAdaptiveNFA
)

// String returns the human-readable name of the engine type.
func (e EngineType) String() string {
	switch e {
	case EngineBacktrack:
		return "Backtracking"
	case EngineDFA:
		return "DFA"
	case EngineOnePass:
		return "One-Pass DFA"
	case EnginePikeVM:
		return "Pike VM"
	case EngineAdaptiveNFA:
		return "Adaptive NFA"
	default:
		return "Unknown"
	}
}

// Matcher is the common interface implemented by all regex engines.
type Matcher interface {
	Type() EngineType
}

// CompileOptions contains optional parameters for engine selection.
type CompileOptions struct {
	MaxDFAStates       int        // Maximum DFA states before falling back (default: 1000)
	MaxDFAMemory       int        // Maximum DFA memory in bytes (default: 102400)
	Unicode            bool       // Enable Unicode support
	AdaptiveNFACutover int        // Input size in bytes to switch to Pike VM in AdaptiveNFA
	ForceEngine        EngineType // If non-zero, skip engine selection and use this engine type
	Mode               MatchMode  // ModeAnchoredMatch (default) or ModeFind
	LeftmostFirst      bool       // Use leftmost-first (RE2/Perl) semantics for alternations
}

// CmdCompile compiles all regex patterns from cfg to WASM modules.
// wasmInput is a pre-built WASM file used to determine where in memory
// to place the DFA tables.
func CmdCompile(cfg config.BuildConfig, wasmInput, outDir string) error {
	rustTop, err := utils.RustMemTop(wasmInput)
	if err != nil {
		return fmt.Errorf("read wasm-input: %w", err)
	}
	slog.Info("Compiling regexes", "count", len(cfg.Regexes))
	slog.Debug("Rust memory top", "bytes", rustTop)

	tableBase := utils.PageAlign(rustTop)
	for i, re := range cfg.Regexes {
		slog.Info("Compiling pattern", "n", i+1, "total", len(cfg.Regexes), "module", re.ImportModule, "wasm", re.WasmFile)

		wasmBytes, tableEnd, err := compileRegexEntry(re, tableBase)
		if err != nil {
			return fmt.Errorf("compile regex %d (%s): %w", i+1, re.ImportModule, err)
		}

		wasmPath := filepath.Join(outDir, re.WasmFile)
		if err := os.WriteFile(wasmPath, wasmBytes, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", wasmPath, err)
		}
		slog.Debug("Compiled pattern", "table_end", tableEnd, "file", wasmPath, "bytes", len(wasmBytes))
		tableBase = tableEnd
	}
	slog.Info("Done")
	return nil
}

// CompileRegex compiles a single regex pattern to WASM bytes.
// tableBase must be page-aligned and >= 0.
// If standalone is true, the module defines its own memory (suitable for testing);
// otherwise it imports memory from the "main" module.
// Returns the WASM bytes and the next available table base (page-aligned end of this module's data).
// An optional CompileOptions argument overrides the defaults.
func CompileRegex(pattern, exportName string, tableBase int64, standalone bool, userOpts ...CompileOptions) ([]byte, int64, error) {
	opts := CompileOptions{
		MaxDFAStates: 100000,
		Unicode:      false,
		ForceEngine:  EngineDFA,
	}
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	matcher, err := compile(pattern, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("compile error: %w", err)
	}
	if matcher.Type() != EngineDFA {
		return nil, 0, fmt.Errorf("unexpected engine %v (wanted DFA)", matcher.Type())
	}
	table := dfaTableFrom(matcher.(*dfa))

	if opts.MaxDFAStates > 0 && table.numStates > opts.MaxDFAStates {
		return nil, 0, fmt.Errorf("DFA has %d states, exceeds limit %d", table.numStates, opts.MaxDFAStates)
	}

	numWASM := table.numStates + 1
	var dfaSize int64
	switch {
	case numWASM <= 256 && numWASM*256 > 32*1024: // u8 + compression
		_, _, nc := computeByteClasses(table)
		dfaSize = int64(256 + numWASM*nc + numWASM)
	case numWASM <= 256: // u8, no compression
		dfaSize = int64(numWASM*256 + numWASM)
	default: // u16
		dfaSize = int64(numWASM*256*2 + numWASM)
	}
	if opts.Mode == ModeFind {
		dfaSize += int64(numWASM) // midAccept flags
		// firstByte flags (256 bytes) only when there is no literal prefix;
		// with a prefix the skip uses hardcoded comparisons, no table needed.
		if len(computePrefix(table)) == 0 {
			dfaSize += 256
		}
		// wordCharTable (256 bytes) prepended before DFA table for word-boundary patterns.
		// Also add midAcceptNW and midAcceptW flag arrays (numWASM bytes each).
		if table.hasWordBoundary {
			dfaSize += 256 + int64(numWASM)*2
		}
	}
	if opts.LeftmostFirst && len(table.immediateAcceptStates) > 0 {
		dfaSize += int64(numWASM) // immediateAccept flags
	}

	tableEnd := utils.PageAlign(tableBase + dfaSize)
	memPages := int32(tableEnd / 65536)

	wasmBytes := genWASM(table, tableBase, exportName, standalone, memPages, opts.Mode, opts.LeftmostFirst)
	return wasmBytes, tableEnd, nil
}

// compileRegexEntry compiles a single RegexEntry to WASM using the new config schema.
// It determines the appropriate engine based on which function stubs are requested.
func compileRegexEntry(re config.RegexEntry, tableBase int64) ([]byte, int64, error) {
	captureNeeded := re.CaptureStubsRequested()

	// Determine which export name and mode to use for the primary function.
	// Priority: groups > find > match.
	if captureNeeded {
		return CompileOnePassGroups(re.Pattern, "groups", tableBase, false)
	}
	if re.FindFunc != "" {
		return CompileRegex(re.Pattern, "find", tableBase, false,
			CompileOptions{MaxDFAStates: 100000, ForceEngine: EngineDFA, Mode: ModeFind})
	}
	return CompileRegex(re.Pattern, "match", tableBase, false,
		CompileOptions{MaxDFAStates: 100000, ForceEngine: EngineDFA})
}

// CompileOnePassGroups compiles a pattern to a OnePass WASM module exporting
// a groups function: (ptr i32, len i32, out_ptr i32) → i32.
// If the pattern does not qualify for OnePass, returns an error.
func CompileOnePassGroups(pattern, exportName string, tableBase int64, standalone bool) ([]byte, int64, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, 0, fmt.Errorf("parse error: %w", err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, 0, fmt.Errorf("compile error: %w", err)
	}
	if needsUnicodeSupport(prog) {
		return nil, 0, fmt.Errorf("pattern contains Unicode features not yet supported")
	}
	if !isOnePass(prog) {
		return nil, 0, fmt.Errorf("pattern is not one-pass deterministic")
	}

	op := newOnePass(prog)

	// Data section: transition table (numStates * 256 bytes).
	dataSize := int64(op.numStates * 256)
	tableEnd := utils.PageAlign(tableBase + dataSize)
	memPages := int32(tableEnd / 65536)

	wasmBytes := genOnePassWASM(op, tableBase, exportName, standalone, memPages)
	return wasmBytes, tableEnd, nil
}

// stripCaptures converts all capture groups in the regexp tree to non-capturing
// by replacing each OpCapture node with its single sub-expression in-place.
// Used when the pattern has captures but capture stubs are not requested.
func stripCaptures(re *syntax.Regexp) {
	for _, sub := range re.Sub {
		stripCaptures(sub)
	}
	if re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		*re = *re.Sub[0]
	}
}

// SelectEngine returns the EngineType that would be chosen for the given pattern,
// without actually compiling it. Returns an error if the pattern cannot be parsed
// or compiled to NFA bytecode.
func SelectEngine(pattern string, opts CompileOptions) (EngineType, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, fmt.Errorf("parse error: %w", err)
	}
	hasCapturesBeforeSimplify := re.MaxCap() > 0
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0, fmt.Errorf("compile error: %w", err)
	}
	if needsUnicodeSupport(prog) && !opts.Unicode {
		return 0, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}
	return selectBestEngine(prog, hasCapturesBeforeSimplify, &opts), nil
}

// parseMode converts the YAML mode string to a MatchMode constant.
func parseMode(s string) MatchMode {
	if s == "find" {
		return ModeFind
	}
	return ModeAnchoredMatch
}

// compile parses the pattern, selects the optimal engine, and returns a compiled Matcher.
func compile(pattern string, opts ...CompileOptions) (Matcher, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	hasCapturesBeforeSimplify := re.MaxCap() > 0
	originalMaxCap := re.MaxCap()
	_ = originalMaxCap

	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("compile error: %w", err)
	}

	var options CompileOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	if requiresUnicode := needsUnicodeSupport(prog); requiresUnicode && !options.Unicode {
		return nil, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}

	var engineType EngineType
	if options.ForceEngine != 0 {
		engineType = options.ForceEngine
	} else {
		engineType = selectBestEngine(prog, hasCapturesBeforeSimplify, &options)
	}

	switch engineType {
	case EngineDFA:
		return newDFA(prog, options.Unicode, options.LeftmostFirst), nil
	default:
		return nil, fmt.Errorf("engine %v not yet supported by wasm compiler", engineType)
	}
}

// needsUnicodeSupport analyzes whether a compiled program requires Unicode support.
func needsUnicodeSupport(prog *syntax.Prog) bool {
	const maxUnicode = 0x10ffff

	for i := range prog.Inst {
		inst := &prog.Inst[i]

		switch inst.Op {
		case syntax.InstRune, syntax.InstRune1:
			hasASCII := false
			hasNonASCII := false

			for _, r := range inst.Rune {
				if r <= 127 {
					hasASCII = true
				} else if r != maxUnicode {
					hasNonASCII = true
				}
			}

			if hasNonASCII && !hasASCII {
				return true
			}
		}
	}
	return false
}
