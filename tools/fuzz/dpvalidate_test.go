package fuzz

import (
	"testing"

	"github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// The sweep is hand-emitted WASM. Compiling the Go that emits it proves
// nothing about the bytes; only a validator does.
func TestOverlapDPModuleValidates(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "a", Pattern: `a+`},
			{Name: "e", Pattern: `[^\n]*ERROR`},
			{Name: "x", Pattern: `x?y`},
		},
		Sets: []config.SetConfig{{
			Name:        "s",
			Find:        "cap_find",
			Patterns:    config.PatternSelector{All: true},
			Overlapping: true,
			Hints:       []string{"batch-find"},
		}},
	}
	wasm, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := wasmtime.NewEngine()
	if _, err := wasmtime.NewModule(engine, wasm); err != nil {
		t.Fatalf("emitted module does not validate:\n%v", err)
	}
	t.Logf("validated, %d bytes", len(wasm))
}
