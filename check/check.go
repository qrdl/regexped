// Package check is `regexped check`: every test `compile` and `generate` make
// of a config, with nothing written.
//
// The config is compiled in memory — the module `compile` would write, or a
// component's core module and its WIT, which needs no wasm-tools — and the
// stub, when the config names one, is generated into a temporary directory
// removed afterwards, so the generator's own checks run too. What is printed
// is one line per pattern and per set, then a line saying what was checked.
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

// Run checks cfg and writes its summary to w.
func Run(cfg config.BuildConfig, w io.Writer) error {
	rep := &compile.Reporter{Progress: os.Stderr}
	kind := "module"
	var size int
	if cfg.Component() {
		kind = "component core module"
		core, _, err := component.Core(cfg, rep)
		if err != nil {
			return err
		}
		size = len(core)
	} else {
		b, err := compile.CompileModule(cfg, rep)
		if err != nil {
			return err
		}
		size = len(b)
	}
	compile.WarnUnboundedMemory(cfg, rep)
	stub := ""
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
		stub = ", " + typ + " stub"
	}
	members := map[string]int{}
	for _, s := range cfg.Sets {
		members[s.Name] = len(s.Members(cfg))
	}
	rep.Summary(w, members)
	fmt.Fprintf(w, "ok: %s, %s; %s %d bytes%s; nothing written\n", count(len(cfg.Patterns), "pattern"), count(len(cfg.Sets), "set"), kind, size, stub)
	return nil
}

func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}
