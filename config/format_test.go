package config

import (
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
func TestComponentRejectsSets(t *testing.T) {
	src := "wasm_format: component\nimport_module: regexps\n" +
		"regexps:\n  - name: a\n    pattern: 'abc'\n" +
		"sets:\n  - name: s\n    find: find_s\n    patterns: all\n"
	_, err := loadCfgSrc(t, src)
	if err == nil || !strings.Contains(err.Error(), "sets are not supported") {
		t.Fatalf("error = %v, want the sets rejection", err)
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
	for _, st := range []string{"rust", "js", "ts", "c"} {
		err := validateStubTypeForFormat(component, st)
		if err == nil || !strings.HasSuffix(err.Error(), "yet") {
			t.Errorf("stub %s under component: err = %v, want one ending in \"yet\"", st, err)
		}
	}
	for _, st := range []string{"go", "as"} {
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
