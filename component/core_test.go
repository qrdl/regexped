package component

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
)

// Core is the seam between the WIT derivation and the compiler, and it is the one
// place a set-bearing config takes the second assembler. These tests cover both
// arms and the refusals, because a caller that rebuilt the join would be free to
// hand compile/ a name generate/ never derived — which is what this arrangement
// exists to prevent.

func coreSetCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		WasmFile:     "t.wasm",
		Regexps: []config.RegexEntry{
			{Pattern: `ghp_[A-Za-z0-9]{4}`},
			{Pattern: `AKIA[A-Z0-9]{6}`},
		},
		Sets: []config.SetConfig{{
			Name:     "s",
			Patterns: config.PatternSelector{All: true},
			ScanAny:  "any_hit",
			ScanAll:  "all_hits",
			Find:     "scan_it",
		}},
	}
}

// A set-bearing config must reach the SET assembler and come out with the set's
// canonical exports in it — the arm the single-pattern fixture cannot exercise.
func TestCoreBuildsSetComponent(t *testing.T) {
	core, witText, err := Core(coreSetCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(witText, "interface sets {") {
		t.Error("the WIT does not carry the sets interface")
	}
	for _, want := range []string{
		"regexped:t/sets#any-hit",
		"regexped:t/sets#[constructor]scan-it",
		"[resource-new]scan-it",
	} {
		if !strings.Contains(string(core), want) {
			t.Errorf("core module is missing %q", want)
		}
	}
	if tool := lookTool(t); tool != "" {
		if out, err := runCapture(tool, "validate", writeTemp(t, core)); err != nil {
			t.Fatalf("wasm-tools rejected the set core module: %v\n%s", err, out)
		}
	}
}

// A config with sets AND single-pattern funcs exports both interfaces, and the
// two must not interfere: the set functions sit past every pattern function, and
// the resource's import offsets them all.
func TestCoreBuildsMixedComponent(t *testing.T) {
	cfg := coreSetCfg()
	cfg.Regexps[0].MatchFunc = "token_match"
	core, witText, err := Core(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interface matcher {", "interface sets {", "export matcher;", "export sets;"} {
		if !strings.Contains(witText, want) {
			t.Errorf("the WIT is missing %q", want)
		}
	}
	for _, want := range []string{"regexped:t/matcher#token-match", "regexped:t/sets#any-hit"} {
		if !strings.Contains(string(core), want) {
			t.Errorf("core module is missing %q", want)
		}
	}
	if tool := lookTool(t); tool != "" {
		if out, err := runCapture(tool, "validate", writeTemp(t, core)); err != nil {
			t.Fatalf("wasm-tools rejected the mixed core module: %v\n%s", err, out)
		}
	}
}

// Core refuses a MODULE config rather than quietly building a component from it:
// the caller has dispatched wrongly, and every export name below would carry a
// package the config never asked for.
func TestCoreRefusesModuleConfig(t *testing.T) {
	cfg := coreSetCfg()
	cfg.WasmFormat = ""
	_, _, err := Core(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "wasm_format") {
		t.Fatalf("err = %v, want a refusal naming wasm_format", err)
	}
}

// A config with no exports at all — no `_func` anywhere and no set capability —
// has nothing to build an interface from, and the message says what to add.
func TestCoreRefusesConfigWithNoExports(t *testing.T) {
	cfg := coreSetCfg()
	cfg.Sets = nil
	_, _, err := Core(cfg, nil)
	if err == nil {
		t.Fatal("a config with no exports produced a component")
	}
	for _, want := range []string{"match_func", "sets:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A name the WIT cannot represent must fail HERE, by the key the user edits,
// rather than as a wasm-tools complaint about the interface.
func TestCoreSurfacesNamingErrors(t *testing.T) {
	cfg := coreSetCfg()
	cfg.Sets[0].ScanAny = "_bad"
	if _, _, err := Core(cfg, nil); err == nil {
		t.Error("an unrepresentable set capability name was accepted")
	}

	cfg = coreSetCfg()
	cfg.WitPackage = "_bad"
	if _, _, err := Core(cfg, nil); err == nil {
		t.Error("an unrepresentable WIT package name was accepted")
	}
}

// A pattern the compiler cannot build must surface as a compile error, not as an
// empty component. The set path and the single-pattern path have separate error
// returns, so both are exercised.
func TestCoreSurfacesCompileErrors(t *testing.T) {
	// A rune above 0xFF has no byte to be, and `byte_mode:` cannot help, so this
	// is refused inside the compiler rather than at config load.
	const unsupported = `a€b`

	cfg := coreSetCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: unsupported, MatchFunc: "m"}}
	cfg.Sets = nil
	if _, _, err := Core(cfg, nil); err == nil {
		t.Error("an unsupported rune compiled")
	}

	cfg = coreSetCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: unsupported}}
	if _, _, err := Core(cfg, nil); err == nil {
		t.Error("an unsupported rune compiled through the set path")
	}
}

// toCompileSetNames is the seam between two deliberately separate structs — the
// packages cannot import each other — so it is the one place their shapes have
// to agree. A field dropped here would silently un-name an export.
func TestToCompileSetNames(t *testing.T) {
	if got := toCompileSetNames(nil); got != nil {
		t.Errorf("toCompileSetNames(nil) = %v, want nil", got)
	}
	in := map[string]generate.SetExportNames{"s": {
		Caps:           map[string]string{"any_hit": "regexped:t/sets#any-hit"},
		Constructor:    "regexped:t/sets#[constructor]scan-it",
		Next:           "regexped:t/sets#[method]scan-it.next",
		Dtor:           "regexped:t/sets#[dtor]scan-it",
		ResourceImport: "[export]regexped:t/sets",
		ResourceNew:    "[resource-new]scan-it",
	}}
	got := toCompileSetNames(in)
	n, ok := got["s"]
	if !ok {
		t.Fatal("the set is missing from the converted table")
	}
	for _, c := range []struct{ got, want string }{
		{n.Caps["any_hit"], in["s"].Caps["any_hit"]},
		{n.Constructor, in["s"].Constructor},
		{n.Next, in["s"].Next},
		{n.Dtor, in["s"].Dtor},
		{n.ResourceImport, in["s"].ResourceImport},
		{n.ResourceNew, in["s"].ResourceNew},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// lookTool returns the wasm-tools path, or "" when it is not installed. Pinning
// bytes nothing can load would be worse than not checking, so the checks above
// validate when they can and say nothing when they cannot.
func lookTool(t *testing.T) string {
	t.Helper()
	tool, err := exec.LookPath("wasm-tools")
	if err != nil {
		t.Log("wasm-tools not in PATH; skipping validation")
		return ""
	}
	return tool
}
