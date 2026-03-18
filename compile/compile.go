package compile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/utils"
)

// regexResult holds the memory layout output of compiling a single regex.
type regexResult struct {
	tableEnd      int64
	initialMemory int64
}

// CmdCompile compiles all regex patterns from cfg to WASM modules and stub
// files. wasmInput is a pre-built WASM file used to determine where in memory
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
		fmt.Fprintf(os.Stderr, "    [%d/%d] module=%s  wasm=%s  stub=src/%s\n",
			i+1, len(cfg.Regexes), re.ImportModule, re.WasmFile, re.StubFile)

		res, err := compileRegex(
			re.Pattern, outDir, re.WasmFile, /*re.ImportModule, re.StubFile, */
			re.ExportName /*re.FuncName, */, tableBase,
		)
		if err != nil {
			return fmt.Errorf("compile regex %d (%s): %w", i+1, re.ImportModule, err)
		}
		fmt.Fprintf(os.Stderr, "        table_end=%d\n", res.tableEnd)
		tableBase = res.tableEnd
	}
	fmt.Fprintln(os.Stderr, "==> Done.")
	return nil
}

// compileRegex compiles a single regex pattern to a WASM DFA,
// tableBase must be page-aligned and >= 0.
func compileRegex(
	pattern, outDir, wasmFile /*importModule, stubFile,*/, exportName /*, funcName */ string,
	tableBase int64,
) (regexResult, error) {
	opts := CompileOptions{
		MaxDFAStates: 100000,
		Unicode:      false,
		ForceEngine:  EngineDFA,
	}
	matcher, err := compile(pattern, opts)
	if err != nil {
		return regexResult{}, fmt.Errorf("compile error: %w", err)
	}
	if matcher.Type() != EngineDFA {
		return regexResult{}, fmt.Errorf("unexpected engine %v (wanted DFA)", matcher.Type())
	}
	table := dfaTableFrom(matcher.(*dfa))

	fmt.Fprintf(os.Stderr, "DFA: %d states, start=%d, %d accept states\n",
		table.numStates, table.startState, len(table.acceptStates))

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

	fmt.Fprintf(os.Stderr, "Table base: %d (0x%x), DFA size: %d\n", tableBase, tableBase, dfaSize)

	initialMemory := utils.PageAlign(tableBase + dfaSize)

	wasmBytes := genWASM(table, tableBase, exportName)
	wasmPath := filepath.Join(outDir, wasmFile)
	if err := os.WriteFile(wasmPath, wasmBytes, 0o644); err != nil {
		return regexResult{}, fmt.Errorf("write %s: %w", wasmPath, err)
	}
	fmt.Fprintf(os.Stderr, "Written %s (%d bytes)\n", wasmPath, len(wasmBytes))

	if err := os.MkdirAll(filepath.Join(outDir, "src"), 0o755); err != nil {
		return regexResult{}, fmt.Errorf("mkdir %s/src: %w", outDir, err)
	}
	/*	stubsPath := filepath.Join(outDir, "src", stubFile)
		stubs := genRustStubs(pattern, importModule, exportName, funcName)
		if err := os.WriteFile(stubsPath, []byte(stubs), 0o644); err != nil {
			return regexResult{}, fmt.Errorf("write %s: %w", stubsPath, err)
		}
		fmt.Fprintf(os.Stderr, "Written %s\n", stubsPath) */

	return regexResult{tableEnd: initialMemory, initialMemory: initialMemory}, nil
}
