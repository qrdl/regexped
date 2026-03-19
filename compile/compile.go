package compile

import (
	"fmt"
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
	EngineLazyDFA
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
	case EngineLazyDFA:
		return "Lazy DFA"
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
}

// CmdCompile compiles all regex patterns from cfg to WASM modules.
// wasmInput is a pre-built WASM file used to determine where in memory
// to place the DFA tables.
func CmdCompile(cfg config.BuildConfig, wasmInput, outDir string) error {
	rustTop, err := utils.RustMemTop(wasmInput)
	if err != nil {
		return fmt.Errorf("read wasm-input: %w", err)
	}
	fmt.Fprintf(os.Stderr, "==> Compiling %d regex(es) to WASM...\n", len(cfg.Regexes))
	fmt.Fprintf(os.Stderr, "    Rust memory top: %d (0x%x)\n", rustTop, rustTop)

	tableBase := utils.PageAlign(rustTop)
	for i, re := range cfg.Regexes {
		fmt.Fprintf(os.Stderr, "    [%d/%d] module=%s  wasm=%s\n",
			i+1, len(cfg.Regexes), re.ImportModule, re.WasmFile)

		wasmBytes, tableEnd, err := CompileRegex(re.Pattern, re.ExportName, tableBase, false,
			CompileOptions{MaxDFAStates: 100000, ForceEngine: EngineDFA, Mode: parseMode(re.Mode)})
		if err != nil {
			return fmt.Errorf("compile regex %d (%s): %w", i+1, re.ImportModule, err)
		}

		wasmPath := filepath.Join(outDir, re.WasmFile)
		if err := os.WriteFile(wasmPath, wasmBytes, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", wasmPath, err)
		}
		fmt.Fprintf(os.Stderr, "        table_end=%d  written %s (%d bytes)\n",
			tableEnd, wasmPath, len(wasmBytes))
		tableBase = tableEnd
	}
	fmt.Fprintln(os.Stderr, "==> Done.")
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
		dfaSize += int64(numWASM) // extra midAccept flags
	}

	tableEnd := utils.PageAlign(tableBase + dfaSize)
	memPages := int32(tableEnd / 65536)

	wasmBytes := genWASM(table, tableBase, exportName, standalone, memPages, opts.Mode)
	return wasmBytes, tableEnd, nil
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
		engineType = selectBestEngine(prog, hasCapturesBeforeSimplify, opts...)
	}

	switch engineType {
	case EngineDFA:
		return newDFA(prog, options.Unicode), nil
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
