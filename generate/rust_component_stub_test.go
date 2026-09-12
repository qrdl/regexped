package generate

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

func rustComponentCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "secrets",
		WasmFile:     "/somewhere/secrets.wasm",
		Regexps: []config.RegexEntry{
			{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "find_github_token"},
			{Pattern: `(?P<user>[a-z]+)@(?P<host>[a-z.]+)`, GroupsFunc: "mail_groups"},
			{Pattern: `[a-z]+`, MatchFunc: "lower_match"},
		},
		// A SET too, so the parity check covers every capability and the find
		// resource — the one place the component stub's mechanism differs most
		// from the module stub's, and therefore the one most likely to leak into
		// the public surface.
		Sets: []config.SetConfig{{
			Name:     "secret_scanner",
			Patterns: config.PatternSelector{All: true},
			MatchAny: "which_secret",
			MatchAll: "all_secrets",
			ScanAny:  "any_secret",
			ScanAll:  "all_secret_hits",
			Find:     "scan_secrets",
		}},
	}
}

// PARITY is the whole point of this generator, so it is what the test asserts:
// the same config must produce the same PUBLIC surface under both formats. A
// change that drops an iterator, a constant or the error type shows up here even
// if both files still compile.
func TestRustComponentStubHasIdenticalPublicAPI(t *testing.T) {
	component := rustComponentCfg()
	module := component
	module.WasmFormat = ""

	componentText, err := genRustComponentStubFile(component)
	if err != nil {
		t.Fatal(err)
	}
	// Compose the module stub exactly as rustStub does — the preamble carries
	// Error, Result and Span, and comparing against the inner text alone would
	// make the component side look like it had invented them.
	moduleInner, err := genRustStubsInner(module.Regexps, module.ImportModule)
	if err != nil {
		t.Fatal(err)
	}
	moduleText := wrapRustModule(rustErrorPreamble()+moduleInner+genRustSetInner(module), module.RustModuleName())

	got, want := publicAPI(componentText), publicAPI(moduleText)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("public API differs between formats.\n--- component ---\n%s\n--- module ---\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(got) == 0 {
		t.Fatal("extracted no public API; the extractor is broken, not the stub")
	}
}

var pubItem = regexp.MustCompile(`pub (fn [a-z_0-9]+\([^)]*\)(?: -> [^{]+)?|struct [A-Za-z0-9_]+|enum [A-Za-z0-9_]+|type [A-Za-z0-9_]+|mod [a-z_0-9]+)`)

func publicAPI(src string) []string {
	var out []string
	for _, m := range pubItem.FindAllString(src, -1) {
		out = append(out, strings.TrimSpace(m))
	}
	sort.Strings(out)
	return uniq(out)
}

func uniq(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// The macro cannot be reached by hand-written imports, so the generated file
// must carry the pieces that make it link at all.
func TestRustComponentStubStructure(t *testing.T) {
	text, err := genRustComponentStubFile(rustComponentCfg())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wit_bindgen::generate!({",
		"inline: r#\"",                           // no wit/ directory: the path option resolves against the crate manifest
		"package regexped-consumer:secrets;",     // the consumer's own package
		"world secrets-consumer {",               // distinct from the component's export world
		"import regexped:secrets/matcher;",       // by its REAL name, or wac finds no matching import
		"package regexped:secrets {",             // our interface, nested as a dependency
		"generate_all,",                          // else the macro refuses: interface from another package
		"use super::regexped::secrets::matcher;", // relative, so the stub can be included anywhere
		"pub mod secrets {",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated stub is missing %q", want)
		}
	}
	// The export world must NOT survive into the dependency package: a
	// dependency supplies the interface only.
	if strings.Contains(text, "export matcher;") {
		t.Error("the export world leaked into the inline WIT dependency")
	}
	// The Cargo dependency is the one place build parity does not hold, so the
	// stub has to say so itself.
	if !strings.Contains(text, witBindgenReq) {
		t.Errorf("the stub does not tell the user to add %s", witBindgenReq)
	}
	// The header must not leak an absolute build path.
	if strings.Contains(text, "/somewhere/") {
		t.Error("an absolute wasm_file path leaked into the generated header")
	}
}

// A version reaches the import name; it must not reach the module path, which is
// derived from the package name alone.
func TestRustComponentStubWithVersion(t *testing.T) {
	cfg := rustComponentCfg()
	cfg.WitVersion = "2.3.0"
	text, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The version goes after the INTERFACE name, not the package — the other
	// placement makes wasm-tools reject the core module.
	if !strings.Contains(text, "import regexped:secrets/matcher@2.3.0;") {
		t.Error("the version is missing from, or misplaced in, the import")
	}
	if strings.Contains(text, "regexped:secrets@2.3.0/matcher") {
		t.Error("the version is on the package rather than the interface")
	}
	if !strings.Contains(text, "package regexped:secrets@2.3.0 {") {
		t.Error("the version is missing from the nested package")
	}
	if !strings.Contains(text, "use super::regexped::secrets::matcher;") {
		t.Error("the version must NOT change the generated module path")
	}
}

// A hyphenated package becomes an underscored Rust module.
func TestRustComponentStubHyphenatedPackage(t *testing.T) {
	cfg := rustComponentCfg()
	cfg.ImportModule = "url_ipv6"
	text, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "import regexped:url-ipv6/matcher;") {
		t.Error("the WIT import must use the kebab package name")
	}
	if !strings.Contains(text, "use super::regexped::url_ipv6::matcher;") {
		t.Error("the Rust module path must use the underscored form")
	}
}

// rust_module names the `pub mod`, independently of the wire and WIT names.
func TestRustComponentStubHonoursRustModule(t *testing.T) {
	cfg := rustComponentCfg()
	cfg.RustModule = "matchers"
	text, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "pub mod matchers {") {
		t.Error("rust_module was ignored")
	}
	if !strings.Contains(text, "import regexped:secrets/matcher;") {
		t.Error("rust_module must not affect the WIT names")
	}
}

// Naming errors surface from the generator, not from rustc later.
func TestRustComponentStubNameErrors(t *testing.T) {
	cfg := rustComponentCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: "a", FindFunc: "_bad"}}
	if _, err := genRustComponentStubFile(cfg); err == nil ||
		!strings.Contains(err.Error(), "find_func") {
		t.Errorf("err = %v", err)
	}
}

// An entry with no _func fields contributes nothing, and a config of only such
// entries produces no file at all — the same rule the module stubs follow.
func TestRustComponentStubEmpty(t *testing.T) {
	cfg := rustComponentCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: "abc"}}
	cfg.Sets = nil // a set declaring a capability IS an export
	text, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if text != "" {
		t.Errorf("a config with no exports produced a stub:\n%s", text)
	}
	out := filepath.Join(t.TempDir(), "stubs.rs")
	if err := rustComponentStub(cfg, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("no file should have been written")
	}
}

// stub_type: rust under component routes here, not to the module generator.
func TestRustComponentStubDispatch(t *testing.T) {
	cfg := rustComponentCfg()
	out := filepath.Join(t.TempDir(), "stubs.rs")
	cfg.StubFile = out
	cfg.StubType = "rust"
	if err := CmdGenerateStub(cfg, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "wit_bindgen::generate!") {
		t.Error("component config produced the MODULE stub")
	}
	// ...and with the format off, it routes to the module generator.
	cfg.WasmFormat = ""
	if err := CmdGenerateStub(cfg, out); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(out)
	if strings.Contains(string(data), "wit_bindgen::generate!") {
		t.Error("module config produced the COMPONENT stub")
	}
	if !strings.Contains(string(data), "#[link(wasm_import_module") {
		t.Error("module config did not produce the FFI stub")
	}
}

func TestRustComponentStubToStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 1<<20)
		n, _ := r.Read(buf)
		done <- string(buf[:n])
	}()
	err = rustComponentStub(rustComponentCfg(), "-")
	w.Close()
	os.Stdout = saved
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(<-done, "wit_bindgen::generate!") {
		t.Error("stdout did not receive the stub")
	}
}

func TestRustComponentStubWriteFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rustComponentStub(rustComponentCfg(), filepath.Join(blocker, "stubs.rs")); err == nil {
		t.Error("want an error writing under a regular file")
	}
}
