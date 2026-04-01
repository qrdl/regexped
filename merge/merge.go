package merge

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/utils"
)

// cmdMerge patches the main WASM module's memory size and merges it with the
// regex WASM modules. inputs[0] is the main module; the rest are regex modules.
func CmdMerge(cfg config.BuildConfig, output string, inputs []string) error {
	wasmMergeCmd := expandHome(cfg.WasmMerge)
	if wasmMergeCmd == "" {
		wasmMergeCmd = "wasm-merge"
	}

	// Verify tool is available before doing any work.
	if err := checkTool(wasmMergeCmd); err != nil {
		return err
	}

	mainWasm := inputs[0]
	regexWasms := inputs[1:]

	// Sanity check: verify each non-first file looks like a compiled regex WASM.
	slog.Debug("Checking WASM modules")
	for _, path := range regexWasms {
		if !isRegexWasm(path) {
			return fmt.Errorf("%s does not appear to be a compiled regex WASM (missing memory import from \"main\")", path)
		}
	}

	// Find the required memory size from the regex WASMs' data segments.
	requiredMem, err := regexMemoryTop(regexWasms)
	if err != nil {
		return fmt.Errorf("measure regex memory: %w", err)
	}
	pages := uint32(utils.PageAlign(requiredMem) / utils.WasmPageSize)
	slog.Debug("Memory requirement", "bytes", utils.PageAlign(requiredMem), "pages", pages)

	// Read main WASM, patch memory section in memory, write to temp file.
	mainRaw, err := os.ReadFile(mainWasm)
	if err != nil {
		return fmt.Errorf("read %s: %w", mainWasm, err)
	}
	patched, err := patchMemoryMin(mainRaw, pages)
	if err != nil {
		return fmt.Errorf("patch memory section: %w", err)
	}

	tmp, err := os.CreateTemp("", "regexped-main-*.wasm")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(patched); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmpPath)
	slog.Debug("Patched harness memory", "pages", pages, "source", mainWasm)

	// Build wasm-merge args: <main> main <regex1> <module1> ...
	slog.Debug("Merging modules")
	mergeArgs := []string{tmpPath, "main"}
	for _, path := range regexWasms {
		module := moduleNameForWasm(cfg, path)
		mergeArgs = append(mergeArgs, path, module)
	}
	mergeArgs = append(mergeArgs, "--rename-export-conflicts", "--enable-simd", "-o", output)

	if err := runCmd(wasmMergeCmd, mergeArgs, "", nil); err != nil {
		return fmt.Errorf("wasm-merge: %w", err)
	}

	info, err := os.Stat(output)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	slog.Info("Merged", "output", output, "bytes", info.Size())
	return nil
}

// moduleNameForWasm returns the import_module for a given WASM file.
// Uses top-level cfg.ImportModule if set; falls back to the basename
// without extension, or per-entry import_module for multi-file legacy configs.
func moduleNameForWasm(cfg config.BuildConfig, path string) string {
	if cfg.ImportModule != "" {
		return cfg.ImportModule
	}
	base := filepath.Base(path)
	for _, re := range cfg.Regexes {
		if re.ImportModule != "" && filepath.Base(re.WasmFile) == base {
			return re.ImportModule
		}
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// checkTool verifies that the given executable exists and is accessible.
func checkTool(path string) error {
	if filepath.IsAbs(path) {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("tool not found: %s", path)
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("tool not executable: %s", path)
		}
		return nil
	}
	if _, err := exec.LookPath(path); err != nil {
		return fmt.Errorf("tool not found in PATH: %s", path)
	}
	return nil
}

// isRegexWasm returns true if the WASM file at path contains a memory import
// from module "main", which is the signature of our generated regex modules.
func isRegexWasm(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 8 || string(raw[:4]) != "\x00asm" {
		return false
	}
	off := 8
	for off < len(raw) {
		sectionID := raw[off]
		off++
		secSize, n := utils.DecodeULEB128(raw[off:])
		off += n
		secEnd := off + int(secSize)
		if secEnd > len(raw) {
			break
		}
		if sectionID == 2 { // import section
			return hasMemoryImportFromMain(raw[off:secEnd])
		}
		off = secEnd
	}
	return false
}

// hasMemoryImportFromMain parses a WASM import section and returns true if it
// contains a memory import with module name "main".
func hasMemoryImportFromMain(data []byte) bool {
	off := 0
	count, n := utils.DecodeULEB128(data[off:])
	off += n

	for i := uint64(0); i < count && off < len(data); i++ {
		// module name
		modLen, n := utils.DecodeULEB128(data[off:])
		off += n
		if off+int(modLen) > len(data) {
			return false
		}
		mod := string(data[off : off+int(modLen)])
		off += int(modLen)

		// field name (skip)
		fieldLen, n := utils.DecodeULEB128(data[off:])
		off += n
		off += int(fieldLen)

		if off >= len(data) {
			return false
		}
		kind := data[off]
		off++

		if kind == 0x02 && mod == "main" { // memory import from "main"
			return true
		}

		// Skip import descriptor to advance to the next import.
		switch kind {
		case 0x00: // func – type index
			_, n = utils.DecodeULEB128(data[off:])
			off += n
		case 0x01: // table – reftype + limits
			off++ // reftype
			flags := data[off]
			off++
			_, n = utils.DecodeULEB128(data[off:])
			off += n
			if flags&0x01 != 0 {
				_, n = utils.DecodeULEB128(data[off:])
				off += n
			}
		case 0x02: // memory – limits
			flags := data[off]
			off++
			_, n = utils.DecodeULEB128(data[off:])
			off += n
			if flags&0x01 != 0 {
				_, n = utils.DecodeULEB128(data[off:])
				off += n
			}
		case 0x03: // global – valtype + mutability
			off += 2
		}
	}
	return false
}

// regexMemoryTop returns the highest data segment end address across all
// given WASM files, representing the total memory consumed by the regex tables.
func regexMemoryTop(paths []string) (int64, error) {
	var max int64
	for _, path := range paths {
		v, err := utils.RustMemTop(path)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		if v > max {
			max = v
		}
	}
	return max, nil
}

// patchMemoryMin rebuilds the WASM memory section with newMinPages as the
// minimum page count. The rest of the binary is unchanged.
func patchMemoryMin(raw []byte, newMinPages uint32) ([]byte, error) {
	if len(raw) < 8 || string(raw[:4]) != "\x00asm" {
		return nil, fmt.Errorf("not a WASM file")
	}

	off := 8
	for off < len(raw) {
		sectionStart := off
		sectionID := raw[off]
		off++
		secSize, n := utils.DecodeULEB128(raw[off:])
		off += n
		secEnd := off + int(secSize)
		if secEnd > len(raw) {
			return nil, fmt.Errorf("truncated WASM section at %d", sectionStart)
		}

		if sectionID == 5 { // memory section
			// Rebuild memory section content with new min pages.
			sec := raw[off:secEnd]
			secOff := 0
			count, cn := utils.DecodeULEB128(sec[secOff:])
			secOff += cn

			var newSec []byte
			newSec = utils.AppendULEB128(newSec, uint32(count))

			for i := uint64(0); i < count && secOff < len(sec); i++ {
				flags := sec[secOff]
				secOff++
				_, mn := utils.DecodeULEB128(sec[secOff:]) // skip old min
				secOff += mn

				newSec = append(newSec, flags)
				newSec = utils.AppendULEB128(newSec, newMinPages)

				if flags&0x01 != 0 { // has max
					maxVal, maxN := utils.DecodeULEB128(sec[secOff:])
					secOff += maxN
					if newMinPages > uint32(maxVal) {
						return nil, fmt.Errorf("cannot patch memory: new min (%d pages) exceeds existing max (%d pages)", newMinPages, maxVal)
					}
					newSec = utils.AppendULEB128(newSec, uint32(maxVal))
				}
			}

			// Reassemble: prefix + section_id + new_size + new_content + suffix.
			var out []byte
			out = append(out, raw[:sectionStart]...)
			out = append(out, sectionID)
			out = utils.AppendULEB128(out, uint32(len(newSec)))
			out = append(out, newSec...)
			out = append(out, raw[secEnd:]...)
			return out, nil
		}

		off = secEnd
	}
	return nil, fmt.Errorf("memory section not found in WASM binary")
}

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// runCmd executes name with args, streaming stdout and stderr to the process's
// own stdout/stderr. dir sets the working directory (empty = inherit);
// extraEnv, if non-nil, adds variables to the inherited environment.
func runCmd(name string, args []string, dir string, extraEnv []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.Run()
}
