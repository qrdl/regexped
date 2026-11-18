// Package check is `regexped check`: every test `compile` and `generate` make
// of a config, with nothing written.
//
// The config is compiled in memory — the module `compile` would write, or a
// component's core module and its WIT, which needs no wasm-tools — and the
// stub, when the config names one, is generated into a temporary directory
// removed afterwards, so the generator's own checks run too. It answers by its
// error alone; given a writer, it writes the --verbose report compile would.
package check

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/component"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
)

// stubExt is the file a stub type is generated as, for a config that names
// its type and no file.
var stubExt = map[string]string{"rust": ".rs", "go": ".go", "js": ".js", "ts": ".ts", "c": ".h", "as": ".ts", "wit": ".wit"}

// Run checks cfg; when w is non-nil it writes the report to w at level, in
// format.
func Run(cfg config.BuildConfig, w io.Writer, level compile.VerboseLevel, format compile.VerboseFormat) error {
	rep := &compile.Reporter{Progress: os.Stderr}
	var err error
	if cfg.Component() {
		_, _, err = component.Core(cfg, rep)
	} else {
		_, err = compile.CompileModule(cfg, rep)
	}
	if err != nil {
		// What was decided before the error — a refused pattern's mode among
		// it — is reported as `compile` reports it; the compile error wins.
		_ = rep.Write(w, level, format)
		return err
	}
	compile.WarnUnboundedMemory(cfg, rep)
	if cfg.StubFile != "" || cfg.StubType != "" {
		typ, err := generate.ResolveStubType(cfg)
		if err != nil {
			return err
		}
		dir, err := os.MkdirTemp("", "regexped-check-")
		if err != nil {
			return fmt.Errorf("check: %w", err)
		}
		defer os.RemoveAll(dir)
		name := filepath.Base(cfg.StubFile)
		if cfg.StubFile == "" {
			name = "stub" + stubExt[typ]
		}
		if err := generate.CmdGenerateStub(cfg, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return rep.Write(w, level, format)
}
