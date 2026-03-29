package generate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// dummyMainWASM is a minimal WASM module that exports 2 pages (128 KB) of memory.
// It has no code, no data, and no imports.
//
// Equivalent WAT:
//
//	(module
//	  (memory (export "memory") 2))
var dummyMainWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, // magic "\0asm"
	0x01, 0x00, 0x00, 0x00, // version 1
	// Memory section (id=5): 1 memory, min=2 pages, no max
	0x05, 0x03, 0x01, 0x00, 0x02,
	// Export section (id=7): export "memory" as memory 0
	0x07, 0x0a, 0x01, 0x06,
	0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, // "memory"
	0x02, 0x00,
}

// CmdDummyMain writes a minimal main.wasm to outDir.
// If out is "-", WASM bytes are written to stdout instead.
//
// The generated module exports 2 pages of memory and has no code, making it
// suitable as the --wasm-input for the compile command and as the "main" module
// for wasm-merge in deployments where no host-language runtime is needed (e.g.
// browser environments where JS provides the memory directly).
func CmdDummyMain(outDir, out string) error {
	if out == "-" {
		_, err := os.Stdout.Write(dummyMainWASM)
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	path := filepath.Join(outDir, "main.wasm")
	if err := os.WriteFile(path, dummyMainWASM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	slog.Info("Written dummy main", "file", path)
	return nil
}
