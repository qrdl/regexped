package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadCfgSrc writes src to a temp regexped.yaml and loads it.
func loadCfgSrc(t *testing.T, src string) (BuildConfig, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

const onePattern = "regexps:\n  - pattern: 'abc'\n    find_func: find_abc\n"

func TestKebabIdent(t *testing.T) {
	ok := []struct{ in, want string }{
		{"regexps", "regexps"},
		{"url_ipv6", "url-ipv6"},
		{"urlMatch", "url-match"},
		{"URLMatch", "urlmatch"}, // a run of capitals stays one word
		{"v2_x", "v2-x"},
		{"already-kebab", "already-kebab"},
	}
	for _, c := range ok {
		got, err := KebabIdent(c.in)
		if err != nil || got != c.want {
			t.Errorf("KebabIdent(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
	// Rejected rather than mangled: the user must choose the name.
	for _, bad := range []string{"", "_x", "x__y", "9x", "my.mod", "a b"} {
		if got, err := KebabIdent(bad); err == nil {
			t.Errorf("KebabIdent(%q) = %q, want an error", bad, got)
		}
	}
}

func TestNameRoleFallbacks(t *testing.T) {
	// Nothing set but import_module: every role is import_module, which is how
	// every config that predates these keys must keep behaving.
	cfg := BuildConfig{ImportModule: "regexps"}
	if got := cfg.RustModuleName(); got != "regexps" {
		t.Errorf("RustModuleName = %q, want regexps", got)
	}
	if got := cfg.GoPackageName(); got != "regexps" {
		t.Errorf("GoPackageName = %q, want regexps", got)
	}
	if got, err := cfg.WitPackageName(); err != nil || got != "regexps" {
		t.Errorf("WitPackageName = %q, %v; want regexps, nil", got, err)
	}
	if got, err := cfg.WitWorldName(); err != nil || got != "regexps" {
		t.Errorf("WitWorldName = %q, %v; want regexps, nil", got, err)
	}

	// Each key overrides its own role and nothing else.
	cfg = BuildConfig{ImportModule: "url_ipv6", RustModule: "urlipv6", GoPackage: "urlipv6", WitPackage: "url-v6"}
	if got := cfg.RustModuleName(); got != "urlipv6" {
		t.Errorf("RustModuleName = %q", got)
	}
	if got, err := cfg.WitPackageName(); err != nil || got != "url-v6" {
		t.Errorf("WitPackageName = %q, %v", got, err)
	}
	// wit_world falls back to wit_package, not to import_module.
	if got, err := cfg.WitWorldName(); err != nil || got != "url-v6" {
		t.Errorf("WitWorldName = %q, %v; want url-v6", got, err)
	}
	cfg.WitWorld = "scanner"
	if got, err := cfg.WitWorldName(); err != nil || got != "scanner" {
		t.Errorf("WitWorldName = %q, %v; want scanner", got, err)
	}

	// import_module that cannot be kebabbed is an error naming the escape.
	cfg = BuildConfig{ImportModule: "9x"}
	if _, err := cfg.WitPackageName(); err == nil || !strings.Contains(err.Error(), "wit_package") {
		t.Errorf("WitPackageName error = %v, want one naming wit_package", err)
	}
}

func TestWasmFormatValidation(t *testing.T) {
	cases := []struct {
		name, src, wantErr string
	}{
		{"default is module", onePattern, ""},
		{"explicit module", "wasm_format: module\n" + onePattern, ""},
		{"component", "wasm_format: component\nimport_module: regexps\n" + onePattern, ""},
		{"unknown format", "wasm_format: wasip2\n" + onePattern, `unknown wasm_format "wasip2"`},
		{"component needs a name", "wasm_format: component\n" + onePattern, "is required for wasm_format: component"},
		{"component takes wit_package alone", "wasm_format: component\nwit_package: regexps\n" + onePattern, ""},
		{"unrepresentable name", "wasm_format: component\nimport_module: '9x'\n" + onePattern, "set wit_package explicitly"},
		{"bad wit_package", "wasm_format: component\nwit_package: 'Not_Kebab'\n" + onePattern, "wit_package"},
		{"bad wit_world", "wasm_format: component\nimport_module: regexps\nwit_world: 'Bad World'\n" + onePattern, "wit_world"},
		{"bad semver", "wasm_format: component\nimport_module: regexps\nwit_version: '1.2'\n" + onePattern, "not a semver triple"},
		{"non-numeric semver", "wasm_format: component\nimport_module: regexps\nwit_version: '1.2.x'\n" + onePattern, `non-numeric component "x"`},
		{"good semver", "wasm_format: component\nimport_module: regexps\nwit_version: '2.3.0'\n" + onePattern, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadCfgSrc(t, c.src)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("error %v does not contain %q", err, c.wantErr)
			}
		})
	}
}

// A component config carrying sets is refused rather than half-emitted.
// Sets under `component` LOAD as of phase 3.2: their raw ABI does not cross the
// boundary (`_all` lifts to a list of ids, `find` becomes a resource), so there
// is nothing left to refuse about them.
func TestComponentAcceptsSets(t *testing.T) {
	src := "wasm_format: component\nimport_module: regexps\n" +
		"regexps:\n  - name: a\n    pattern: 'abc'\n" +
		"sets:\n  - name: s\n    find: find_s\n    patterns: all\n"
	if _, err := loadCfgSrc(t, src); err != nil {
		t.Fatalf("a component config with sets must load: %v", err)
	}
}

// `hints: [batch-find]` is the ONE set feature with no component form. It is
// refused rather than ignored: the user asked for a second entry point, and the
// component interface has one position per call through the resource. An ignored
// hint would silently cost them the amortisation they asked for.
func TestComponentRejectsBatchFindHint(t *testing.T) {
	src := "wasm_format: component\nimport_module: regexps\n" +
		"regexps:\n  - name: a\n    pattern: 'abc'\n" +
		"sets:\n  - name: s\n    find: find_s\n    patterns: all\n    hints: [batch-find]\n"
	_, err := loadCfgSrc(t, src)
	if err == nil || !strings.Contains(err.Error(), "batch-find") {
		t.Fatalf("error = %v, want the batch-find refusal", err)
	}
	// The same config is fine as a module.
	if _, err := loadCfgSrc(t, strings.Replace(src, "wasm_format: component\n", "", 1)); err != nil {
		t.Fatalf("batch-find must stay valid for a module: %v", err)
	}
}

// wit_version under `module` is INERT, and inert must mean warn-and-proceed:
// not a load error (a usable module is still produced) and not silence (the
// user believes they versioned their interface).
func TestWitVersionUnderModuleWarnsAndProceeds(t *testing.T) {
	cfg, err := loadCfgSrc(t, "wit_version: '1.2.3'\nimport_module: regexps\n"+onePattern)
	if err != nil {
		t.Fatalf("wit_version under module must not fail the load: %v", err)
	}
	if cfg.WitVersion != "1.2.3" {
		t.Errorf("WitVersion = %q, want it preserved", cfg.WitVersion)
	}
	var warned []string
	c := cfg
	if err := validateFormat(&c, func(f string, a ...any) { warned = append(warned, f) }); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "ignored for wasm_format") {
		t.Errorf("warnings = %v, want exactly one about being ignored", warned)
	}
}

// Two different messages, and the difference is load-bearing: "yet" promises a
// later phase, and go/as are never coming.
func TestStubTypeForFormat(t *testing.T) {
	component := &BuildConfig{WasmFormat: "component", ImportModule: "regexps"}
	for _, st := range []string{"rust", "c", "wit"} {
		if err := validateStubTypeForFormat(component, st); err != nil {
			t.Errorf("%s is a supported component stub type: %v", st, err)
		}
	}
	// js and ts sit with go and as: no JS runtime loads a component, and the
	// module format already serves a JS user without a transpiler.
	for _, st := range []string{"go", "as", "js", "ts"} {
		err := validateStubTypeForFormat(component, st)
		if err == nil {
			t.Fatalf("stub %s under component: want an error", st)
		}
		if strings.HasSuffix(err.Error(), "yet") {
			t.Errorf("stub %s is not a component target; its message must not say \"yet\": %v", st, err)
		}
	}
	if err := validateStubTypeForFormat(component, "wit"); err != nil {
		t.Errorf("wit under component: %v", err)
	}
	// And wit is meaningless without a component.
	module := &BuildConfig{ImportModule: "regexps"}
	if err := validateStubTypeForFormat(module, "wit"); err == nil {
		t.Error("wit under module: want an error")
	}
	for _, st := range []string{"rust", "js", "ts", "go", "c", "as"} {
		if err := validateStubTypeForFormat(module, st); err != nil {
			t.Errorf("stub %s under module must stay valid: %v", st, err)
		}
	}
}

// The per-role identifier rules must apply to the EFFECTIVE value: a config
// setting no role key gets exactly the errors it always got, and setting one
// is the escape hatch that did not exist before.
func TestPerRoleValidationUsesEffectiveValue(t *testing.T) {
	// `match` is a Rust keyword: rejected as it always was...
	cfg := BuildConfig{ImportModule: "match", StubType: "rust"}
	problems := validateImportModule(&cfg, "rust")
	if len(problems) != 1 || !strings.Contains(problems[0], "reserved word") {
		t.Fatalf("problems = %v, want a reserved-word error", problems)
	}
	if !strings.Contains(problems[0], "import_module") {
		t.Errorf("message must name the key that carries the value: %v", problems[0])
	}
	// ...unless rust_module overrides it.
	cfg.RustModule = "matcher"
	if problems := validateImportModule(&cfg, "rust"); len(problems) != 0 {
		t.Errorf("rust_module must be the escape hatch, got %v", problems)
	}
	// The wire name keeps only its own constraint: a keyword is fine for c/as.
	cfg = BuildConfig{ImportModule: "match", StubType: "c"}
	if problems := validateImportModule(&cfg, "c"); len(problems) != 0 {
		t.Errorf("a keyword is a legal wire name for c: %v", problems)
	}
	// But a quote in it is not.
	cfg.ImportModule = `a"b`
	if problems := validateImportModule(&cfg, "c"); len(problems) != 1 {
		t.Errorf("a quote must still be rejected for c: %v", problems)
	}
}

// wit_package and wit_world are as inert under `module` as wit_version, and must
// warn for the same reason: the user believes they named something.
func TestWitPackageAndWorldUnderModuleWarn(t *testing.T) {
	cfg := BuildConfig{ImportModule: "m", WitPackage: "a-b", WitWorld: "c-d"}
	var warned []string
	if err := validateFormat(&cfg, func(f string, a ...any) {
		warned = append(warned, fmt.Sprintf(f, a...))
	}); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 2 {
		t.Fatalf("warnings = %v, want one per inert key", warned)
	}
	for _, want := range []string{"wit_package", "wit_world"} {
		found := false
		for _, w := range warned {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning mentions %s: %v", want, warned)
		}
	}
}

func TestValidateSemverEmptyComponent(t *testing.T) {
	if err := validateSemver("1..3"); err == nil || !strings.Contains(err.Error(), "empty component") {
		t.Errorf("err = %v, want the empty-component message", err)
	}
	if err := validateSemver(".."); err == nil {
		t.Error("`..` must be rejected")
	}
}

// LoadConfig must apply the per-format stub rule, not just the CLI.
func TestLoadConfigRejectsStubTypeForFormat(t *testing.T) {
	for _, st := range []string{"rust", "c"} {
		if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: m\nstub_type: "+st+"\n"+onePattern); err != nil {
			t.Errorf("%s under component must load: %v", st, err)
		}
	}
	// js/ts/go/as remain permanent refusals.
	for _, st := range []string{"js", "ts", "go", "as"} {
		_, err := loadCfgSrc(t, "wasm_format: component\nimport_module: m\nstub_type: "+st+"\n"+onePattern)
		if err == nil || !strings.Contains(err.Error(), "is not supported for wasm_format: component") {
			t.Errorf("%s under component: err = %v", st, err)
		}
		if err != nil && strings.HasSuffix(err.Error(), "yet") {
			t.Errorf("%s must not be described as temporary: %v", st, err)
		}
	}
	if _, err := loadCfgSrc(t, "stub_type: wit\nimport_module: m\n"+onePattern); err == nil ||
		!strings.Contains(err.Error(), "requires wasm_format: component") {
		t.Errorf("wit under module: err = %v", err)
	}
}

// A `.wit` stub_file infers the type, like every other extension.
func TestResolveStubTypeInfersWit(t *testing.T) {
	got, err := ResolveStubType(BuildConfig{StubFile: "out/regexps.wit"})
	if err != nil || got != "wit" {
		t.Errorf("ResolveStubType = %q, %v; want wit", got, err)
	}
	if _, err := ResolveStubType(BuildConfig{StubFile: "out/regexps.xyz"}); err == nil {
		t.Error("an unknown extension must not resolve")
	}
}

// The c/as branch has nothing to check when no name is set; required-ness is the
// CLI's business, not this function's.
func TestValidateImportModuleEmptyNameForCAndAS(t *testing.T) {
	for _, st := range []string{"c", "as"} {
		cfg := BuildConfig{StubType: st}
		if problems := validateImportModule(&cfg, st); len(problems) != 0 {
			t.Errorf("%s with no name: %v", st, problems)
		}
	}
	// Same for the identifier branch.
	for _, st := range []string{"rust", "go"} {
		cfg := BuildConfig{StubType: st}
		if problems := validateImportModule(&cfg, st); len(problems) != 0 {
			t.Errorf("%s with no name: %v", st, problems)
		}
	}
	// And a stub type with no rule at all.
	cfg := BuildConfig{ImportModule: "my-mod", StubType: "js"}
	if problems := validateImportModule(&cfg, "js"); len(problems) != 0 {
		t.Errorf("js has no naming rule: %v", problems)
	}
}

func TestGoPackageOverride(t *testing.T) {
	cfg := BuildConfig{ImportModule: "url_ipv6", GoPackage: "urlipv6"}
	if got := cfg.GoPackageName(); got != "urlipv6" {
		t.Errorf("GoPackageName = %q, want the override", got)
	}
}

// validateWitIdent is reached through several doors; these are the arms the
// public paths cannot produce.
func TestValidateWitIdentDirect(t *testing.T) {
	if err := validateWitIdent(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: %v", err)
	}
	if err := validateWitIdent("a$b"); err == nil || !strings.Contains(err.Error(), "cannot appear") {
		t.Errorf("bad char inside a word: %v", err)
	}
	if err := validateWitIdent("a-"); err == nil || !strings.Contains(err.Error(), "empty word") {
		t.Errorf("trailing hyphen: %v", err)
	}
	if err := validateWitIdent("1a"); err == nil || !strings.Contains(err.Error(), "lowercase letter") {
		t.Errorf("leading digit: %v", err)
	}
	if err := validateWitIdent("a-b2"); err != nil {
		t.Errorf("a valid identifier was rejected: %v", err)
	}
}

// PatternSelector rejects a shape it cannot interpret, rather than guessing.
func TestPatternSelectorUnmarshalError(t *testing.T) {
	var p PatternSelector
	want := errors.New("boom")
	if err := p.UnmarshalYAML(func(any) error { return want }); !errors.Is(err, want) {
		t.Errorf("err = %v, want it propagated", err)
	}
}

// witKeywordList is WIT's full keyword set, every one of which wasm-tools
// rejects as a function name.
var witKeywordList = []string{
	"as", "bool", "borrow", "char", "constructor", "enum", "export", "f32", "f64",
	"flags", "from", "func", "future", "import", "include", "interface", "list",
	"option", "own", "package", "record", "resource", "result", "s8", "s16", "s32",
	"s64", "static", "stream", "string", "tuple", "type", "u8", "u16", "u32", "u64",
	"use", "variant", "with", "world",
}

// Under wasm_format: component every func and capability name becomes a WIT
// identifier, so a WIT keyword is refused at LOAD, naming the key — not later,
// inside `wasm-tools component embed`. A module build with no stub produces no
// WIT and no source, so the same name loads there.
func TestComponentRefusesWITKeywordNames(t *testing.T) {
	for _, kw := range witKeywordList {
		for _, key := range []string{"match_func", "find_func"} {
			comp := "wasm_format: component\nimport_module: t\nregexps:\n  - pattern: 'abc'\n    " +
				key + ": " + kw + "\n"
			if _, err := loadCfgSrc(t, comp); err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("component %s %q: err = %v, want a refusal naming %s", key, kw, err, key)
			}
			if _, err := loadCfgSrc(t, strings.Replace(comp, "wasm_format: component\n", "", 1)); err != nil {
				t.Errorf("module %s %q with no stub must load: %v", key, kw, err)
			}
		}
		set := "wasm_format: component\nimport_module: t\nregexps:\n  - name: a\n    pattern: 'abc'\n" +
			"sets:\n  - name: s\n    scan_all: " + kw + "\n    patterns: all\n"
		if _, err := loadCfgSrc(t, set); err == nil || !strings.Contains(err.Error(), "scan_all") {
			t.Errorf("component set capability %q: err = %v, want a refusal naming scan_all", kw, err)
		}
	}
	for _, c := range []struct{ key, src string }{
		{"wit_package", "wasm_format: component\nwit_package: world\n" + onePattern},
		{"wit_world", "wasm_format: component\nimport_module: t\nwit_world: record\n" + onePattern},
		{"groups_func", "wasm_format: component\nimport_module: t\nregexps:\n  - pattern: '(a)'\n    groups_func: list\n"},
	} {
		if _, err := loadCfgSrc(t, c.src); err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s as a WIT keyword: err = %v, want a refusal naming it", c.key, err)
		}
	}
}

// Two names are not keywords but collide with a TYPE the interface defines:
// `error-code` in both interfaces and `set-match` in `sets`. Escaping cannot fix
// a duplicate, so they are refused under the same gate.
func TestComponentRefusesWITTypeNames(t *testing.T) {
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - pattern: 'abc'\n    find_func: error_code\n"); err == nil ||
		!strings.Contains(err.Error(), "error-code") {
		t.Errorf("find_func error_code: err = %v, want a refusal naming error-code", err)
	}
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - name: a\n    pattern: 'abc'\nsets:\n  - name: s\n    match_all: set_match\n    patterns: all\n"); err == nil ||
		!strings.Contains(err.Error(), "set-match") {
		t.Errorf("set match_all set_match: err = %v, want a refusal naming set-match", err)
	}
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - pattern: 'abc'\n    find_func: record_x\n"); err != nil {
		t.Errorf("record_x is not a keyword and must load: %v", err)
	}
	if _, err := loadCfgSrc(t, "regexps:\n  - pattern: 'abc'\n    find_func: error_code\n"); err != nil {
		t.Errorf("a module build defines no error-code type, so error_code must load: %v", err)
	}
}

// wit_version is a strict MAJOR.MINOR.PATCH: a component with a leading zero is
// not semver, and ParseUint accepted it.
func TestWitVersionRejectsLeadingZeros(t *testing.T) {
	base := "wasm_format: component\nimport_module: t\n" + onePattern
	for _, v := range []string{"01.2.3", "1.02.3", "1.2.03"} {
		if _, err := loadCfgSrc(t, "wit_version: '"+v+"'\n"+base); err == nil {
			t.Errorf("wit_version %q loaded; a leading zero is not semver", v)
		}
	}
	for _, v := range []string{"0.0.0", "10.20.30"} {
		if _, err := loadCfgSrc(t, "wit_version: '"+v+"'\n"+base); err != nil {
			t.Errorf("wit_version %q must load: %v", v, err)
		}
	}
}

// The world shares the package's item namespace with its interfaces, so a world
// named `matcher` or `sets` is a duplicate item wasm-tools refuses.
func TestWitWorldMayNotNameAnInterface(t *testing.T) {
	for _, w := range []string{"matcher", "sets"} {
		src := "wasm_format: component\nimport_module: t\nwit_world: " + w + "\n" + onePattern
		if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), "wit_world") {
			t.Errorf("wit_world %q: err = %v, want a refusal naming wit_world", w, err)
		}
	}
}

// Regexp-level `hints: [batch-find]` has no component form either: the batch
// groups export it asks for has no WIT shape, and its only consumers, JS and TS,
// are refused under component. Ignoring it silently is what the set-level
// refusal exists to prevent.
func TestComponentRejectsRegexpBatchFindHint(t *testing.T) {
	src := "wasm_format: component\nimport_module: t\nregexps:\n" +
		"  - pattern: '(a)b'\n    groups_func: g\n    hints: [batch-find]\n"
	if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), "batch-find") {
		t.Errorf("err = %v, want the batch-find refusal", err)
	}
	if _, err := loadCfgSrc(t, strings.Replace(src, "wasm_format: component\n", "", 1)); err != nil {
		t.Errorf("batch-find must stay valid for a module: %v", err)
	}
}

// The Rust COMPONENT stub reaches every export through the wit-bindgen binding,
// whose name is the snake_case of the WIT name — not the config spelling. So
// `match_func: Match` passes the case-sensitive Rust list, and the stub then
// calls `matcher::match(...)`; a keyword package produces `use
// super::regexped::loop::matcher;`. Refused where a Rust component stub is
// generated, and only there: WIT itself and C never spell these as Rust.
func TestRustComponentRefusesKeywordBindingNames(t *testing.T) {
	rust := "wasm_format: component\nimport_module: t\nstub_type: rust\n"
	for _, c := range []struct{ key, name string }{
		{"match_func", "Match"}, {"find_func", "Type"}, {"match_func", "Loop"},
	} {
		src := rust + "regexps:\n  - pattern: 'abc'\n    " + c.key + ": " + c.name + "\n"
		if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s %q with a Rust component stub: err = %v, want a refusal naming %s", c.key, c.name, err, c.key)
		}
	}
	pkg := "wasm_format: component\nimport_module: loop\nrust_module: m\nstub_type: rust\n" + onePattern
	if _, err := loadCfgSrc(t, pkg); err == nil || !strings.Contains(err.Error(), "import_module") {
		t.Errorf("a keyword package with a Rust component stub: err = %v, want a refusal naming import_module", err)
	}
	if _, err := loadCfgSrc(t, rust+"regexps:\n  - pattern: 'abc'\n    match_func: matchIt\n"); err != nil {
		t.Errorf("matchIt binds as match_it and must load: %v", err)
	}
	for _, st := range []string{"c", "wit"} {
		src := "wasm_format: component\nimport_module: t\nstub_type: " + st +
			"\nregexps:\n  - pattern: 'abc'\n    match_func: Match\n"
		if _, err := loadCfgSrc(t, src); err != nil {
			t.Errorf("Match with stub_type %s never becomes a Rust identifier and must load: %v", st, err)
		}
	}
}

// TestKebabEdgesPerKey pins the naming edge cases to the DOCUMENTED rules, per
// key, because three keys take three routes. A func name must pass the
// identifier shape and then convert with KebabIdent; import_module converts with
// KebabIdent (and, for a Rust stub, must also be a Rust identifier, since it is
// the `pub mod` name); wit_package must already BE a WIT identifier. An empty
// want means the load is refused. A disagreement here is a finding, not a test
// to bend. wit_package refuses every row, so it has no column.
func TestKebabEdgesPerKey(t *testing.T) {
	for _, c := range []struct {
		in                              string
		findFunc, importWit, importRust string
	}{
		{"My-Mod", "", "my-mod", ""},
		{"a--b", "", "", ""},
		{"aBC", "a-bc", "a-bc", "a-bc"},
		{"A", "a", "a", "a"},
		{"x_", "", "", ""},
		{"_x", "", "", ""},
		{"URLMatch", "urlmatch", "urlmatch", "urlmatch"},
	} {
		src := "wasm_format: component\nimport_module: t\nstub_type: wit\n" +
			"regexps:\n  - pattern: 'abc'\n    find_func: '" + c.in + "'\n"
		_, err := loadCfgSrc(t, src)
		switch {
		case c.findFunc == "" && err == nil:
			t.Errorf("find_func %q loaded; want it refused", c.in)
		case c.findFunc == "" && !strings.Contains(err.Error(), "find_func"):
			t.Errorf("find_func %q refused by a message that does not name the key: %v", c.in, err)
		case c.findFunc != "" && err != nil:
			t.Errorf("find_func %q: %v; want the WIT name %q", c.in, err, c.findFunc)
		case c.findFunc != "":
			if k, _ := KebabIdent(c.in); k != c.findFunc {
				t.Errorf("find_func %q becomes %q, want %q", c.in, k, c.findFunc)
			}
		}

		for _, route := range []struct{ stub, want string }{{"wit", c.importWit}, {"rust", c.importRust}} {
			cfg, err := loadCfgSrc(t, "wasm_format: component\nimport_module: '"+c.in+"'\nstub_type: "+route.stub+"\n"+onePattern)
			switch {
			case route.want == "" && err == nil:
				t.Errorf("import_module %q (stub_type %s) loaded; want it refused", c.in, route.stub)
			case route.want == "" && !strings.Contains(err.Error(), "import_module"):
				t.Errorf("import_module %q (stub_type %s) refused by a message that does not name the key: %v", c.in, route.stub, err)
			case route.want != "" && err != nil:
				t.Errorf("import_module %q (stub_type %s): %v; want package %q", c.in, route.stub, err, route.want)
			case route.want != "":
				if p, _ := cfg.WitPackageName(); p != route.want {
					t.Errorf("import_module %q (stub_type %s) gives package %q, want %q", c.in, route.stub, p, route.want)
				}
			}
		}

		if _, err := loadCfgSrc(t, "wasm_format: component\nwit_package: '"+c.in+"'\nstub_type: wit\n"+onePattern); err == nil {
			t.Errorf("wit_package %q loaded; it is not a WIT identifier", c.in)
		} else if !strings.Contains(err.Error(), "wit_package") {
			t.Errorf("wit_package %q refused by a message that does not name the key: %v", c.in, err)
		}
	}
}
