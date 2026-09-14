package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
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
	component := rustParityCfg()
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

// rustParityCfg exercises every naming and capability path the public surface
// has: camelCase and snake_case func names, groups with names, and two sets
// declaring all five capabilities, one of them overlapping.
func rustParityCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "parity",
		WasmFile:     "parity.wasm",
		Regexps: []config.RegexEntry{
			{Name: "tok", Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "findAwsKey", MatchFunc: "matchToken"},
			{Name: "mail", Pattern: `(?P<user>[a-z]+)@(?P<host>[a-z.]+)`, GroupsFunc: "mailGroups"},
			{Name: "lower", Pattern: `[a-z]+`, MatchFunc: "lower_match"},
			{Name: "digits", Pattern: `[0-9]+`},
		},
		Sets: []config.SetConfig{
			{
				Name: "secret_scanner", Patterns: config.PatternSelector{Names: []string{"tok", "lower"}},
				MatchAny: "whichSecret", MatchAll: "allSecrets", ScanAny: "anySecret",
				ScanAll: "allSecretHits", Find: "scanSecrets",
			},
			{
				Name: "runs", Patterns: config.PatternSelector{Names: []string{"lower", "digits"}},
				MatchAny: "runs_match_any", MatchAll: "runs_match_all", ScanAny: "runs_scan_any",
				ScanAll: "runs_scan_all", Find: "scan_runs", Overlapping: true,
			},
		},
	}
}

// publicAPI lists every public item of a generated Rust stub with its FULL
// signature, whitespace-normalised: functions of any casing, constants with
// their types and values, structs with their public fields, enums with their
// variants, type aliases, and each iterator's `type Item`. Compared by name
// alone, a component stub with a different constant value, field type or
// iterator item would pass as identical.
func publicAPI(src string) []string {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	lines := strings.Split(src, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		switch {
		case (strings.HasPrefix(t, "pub struct ") || strings.HasPrefix(t, "pub enum ")) && strings.HasSuffix(t, "{"):
			kind := strings.Fields(t)[1]
			head := norm(strings.TrimSuffix(t, "{"))
			out = append(out, head)
			for i++; i < len(lines); i++ {
				f := strings.TrimSpace(lines[i])
				if f == "}" {
					break
				}
				if f == "" || strings.HasPrefix(f, "//") || strings.HasPrefix(f, "#[") {
					continue
				}
				if kind == "struct" && !strings.HasPrefix(f, "pub ") {
					continue
				}
				out = append(out, head+" :: "+norm(strings.TrimSuffix(f, ",")))
			}
		case strings.HasPrefix(t, "pub "):
			sig := t
			for !strings.ContainsAny(sig, "{;") && i+1 < len(lines) {
				i++
				sig += " " + strings.TrimSpace(lines[i])
			}
			if k := strings.IndexAny(sig, "{;"); k >= 0 {
				sig = sig[:k]
			}
			out = append(out, norm(sig))
		case strings.HasPrefix(t, "type Item = "):
			out = append(out, norm(strings.TrimSuffix(t, ";")))
		}
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

// TestRustComponentStubBindsCamelCaseNames: a camelCase name reaches the WIT in
// kebab case and the wit-bindgen binding as that name's snake_case — match_it —
// which is not a Rust keyword, so it binds normally while the public wrapper
// keeps the config's own spelling. Config load refuses only a TRUE keyword
// collision (Match -> match).
func TestRustComponentStubBindsCamelCaseNames(t *testing.T) {
	cfg := config.BuildConfig{
		WasmFormat: "component", ImportModule: "t",
		Regexps: []config.RegexEntry{{Pattern: "abc", MatchFunc: "matchIt"}},
	}
	text, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, want := range []string{"matcher::match_it(", "pub fn matchIt("} {
		if !strings.Contains(text, want) {
			t.Errorf("the Rust component stub is missing %q", want)
		}
	}
}

// TestRustComponentSetFindConstructsLazily: the module-format iterator allocates
// nothing until it is driven, so the component one must not construct its
// resource — a full copy of the input into the regexp component — in the
// function that returns it. A caller that builds an iterator and drops it
// undriven pays nothing in either format.
func TestRustComponentSetFindConstructsLazily(t *testing.T) {
	text := genRustComponentSetFind("scan_it", "ScanIt")
	i := strings.Index(text, "pub fn scan_it(")
	if i < 0 {
		t.Fatalf("no scan_it function in:\n%s", text)
	}
	if body := text[i:]; strings.Contains(body, "sets::ScanIt::new(") {
		t.Errorf("scan_it constructs the resource eagerly:\n%s", body)
	}
	if !strings.Contains(text, "inner: Option<sets::ScanIt>,") {
		t.Error("the iterator does not hold its resource as an Option created on first use")
	}
}

func cComponentCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "urlparts",
		WasmFile:     "/somewhere/urlparts.wasm",
		Regexps: []config.RegexEntry{
			{Pattern: `(?P<scheme>https?)://(?P<host>[^/:?#\s]+)`, GroupsFunc: "parse_url"},
			{Pattern: `AKIA[A-Z0-9]{16}`, FindFunc: "find_aws_key"},
			{Pattern: `[a-z]+`, MatchFunc: "lower_match"},
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "digits", Pattern: `[0-9]+`},
			{Name: "upper", Pattern: `[A-Z]+`},
		},
		// A SET too, so the header-parity check covers every capability and the
		// find scanner — the one place the component mechanism differs most
		// (a resource handle rather than a caller-owned drive), and therefore
		// the most likely to leak into the API.
		Sets: []config.SetConfig{{
			Name:     "secrets",
			Patterns: config.PatternSelector{All: true},
			MatchAny: "which_secret",
			MatchAll: "all_secrets",
			ScanAny:  "any_secret",
			ScanAll:  "all_secret_hits",
			Find:     "scan_secrets",
		}, {
			// CACHE-ELIGIBLE: an overlapping set over literal-less patterns is
			// the only shape whose module scanner struct carries the two
			// answer-cache fields, and the component struct lacked them. With
			// only the set above, the parity test compared two headers that
			// happened to agree.
			Name:        "runs",
			Patterns:    config.PatternSelector{Names: []string{"lower", "digits", "upper"}},
			Find:        "scan_runs",
			Overlapping: true,
		}},
	}
}

// The HEADER is the API, and it is generated by the module-format code for both
// formats. Asserting equality here is what makes "same API" a fact rather than an
// intention: a change to either generator that moved the surface would fail.
func TestCComponentHeaderIsIdenticalToModuleHeader(t *testing.T) {
	component := cComponentCfg()
	module := component
	module.WasmFormat = ""

	componentH, _, err := genCComponentStubFiles(component, "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	moduleH, _, err := genCStubFilesWithSets(module, "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	// The lead comment differs by design — the component one documents a
	// different build — so compare from the include guard onwards.
	const anchor = "#ifndef REGEXPED_TYPES_DEFINED"
	ci, mi := strings.Index(componentH, anchor), strings.Index(moduleH, anchor)
	if ci < 0 || mi < 0 {
		t.Fatal("could not locate the shared preamble in one of the headers")
	}
	got, want := stripCFFIImports(componentH[ci:]), stripCFFIImports(moduleH[mi:])
	if got != want {
		t.Errorf("headers differ below the lead comment.\n--- component ---\n%s\n--- module ---\n%s", got, want)
	}
}

// stripCFFIImports removes the raw WASM import declarations from a header.
//
// They are NOT API: they are how one stub reaches the module it was generated
// for, and the two formats import different things from different modules under
// different signatures — a module build imports `ffi_scan_secrets(ptr, len, from,
// gates, out, cap)` from the config's import_module, a component build imports
// `[method]scan-it.next(handle, retptr)` from a WIT interface. Neither could
// carry the other's, so requiring them to match would be requiring the wrong
// thing.
//
// Everything a CALLER touches — the constants, the types, the function
// declarations — is compared. The set declarations are the only place the module
// generator puts import lines in the header at all; the per-pattern ones already
// live in the .c.
func stripCFFIImports(h string) string {
	var out []string
	lines := strings.Split(h, "\n")
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "__attribute__((import_module(") {
			i++ // and the declaration it applies to
			continue
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n")
}

// A WASM import_name carries the WIT function name verbatim, which is KEBAB.
// Using the snake_case form produced "import interface … is missing function
// parse_url" at `component new` — a failure the generator can prevent.
func TestCComponentImportsUseKebabNames(t *testing.T) {
	_, cContent, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`__import_module__("regexped:urlparts/matcher")`,
		// `match` is a plain function; the two ITERATING exports are resources,
		// so each contributes a constructor, a method and a drop.
		`__import_name__("lower-match")`,
		`__import_name__("[constructor]parse-url")`,
		`__import_name__("[method]parse-url.next")`,
		`__import_name__("[resource-drop]parse-url")`,
		`__import_name__("[constructor]find-aws-key")`,
		`__import_name__("[method]find-aws-key.next")`,
		`__import_name__("[resource-drop]find-aws-key")`,
	} {
		if !strings.Contains(cContent, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{
		`__import_name__("parse_url")`, `__import_name__("find_aws_key")`,
		// The FUNCTION forms are gone: importing one would ask the component
		// for an export the interface no longer declares.
		`__import_name__("parse-url")`, `__import_name__("find-aws-key")`,
	} {
		if strings.Contains(cContent, bad) {
			t.Errorf("import name %q must not appear", bad)
		}
	}
}

// A returned list is allocated in the CONSUMER's memory, so a stub that receives
// one must export an allocator — and one that never does must not carry it.
func TestCComponentAllocatorOnlyWhenAListIsReturned(t *testing.T) {
	_, withGroups, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withGroups, `export_name("cabi_realloc")`) {
		t.Error("a groups export needs cabi_realloc: the returned list lives in our memory")
	}
	// Save/restore, NOT a wholesale reset: cabi_realloc is the whole component's
	// allocator — the wasip1 adapter calls it too — so resetting it would hand
	// out memory something else is still using. That trapped in
	// `adapter!allocate_stack` when the C example was first built as a command.
	if !strings.Contains(withGroups, "regexped_cabi_mark()") ||
		!strings.Contains(withGroups, "regexped_cabi_release(_mark)") {
		t.Error("the groups wrapper must save and restore the bump mark")
	}
	if strings.Contains(withGroups, "cabi_reset") {
		t.Error("a wholesale reset is unsafe: the adapter's allocations live in the same heap")
	}
	// Weak, so a program with its own allocator wins.
	if !strings.Contains(withGroups, "__weak__") {
		t.Error("cabi_realloc must be weak")
	}
	// Every exit from the loop body must release, or a suppressed empty match
	// leaks the list it allocated.
	if strings.Count(withGroups, "regexped_cabi_release(_mark)") < 5 {
		t.Errorf("only %d release sites; every exit from the loop body needs one",
			strings.Count(withGroups, "regexped_cabi_release(_mark)"))
	}

	cfg := cComponentCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: `abc`, FindFunc: "f"}}
	cfg.Sets = nil // a set's `_all` and `find` return lists too
	_, noGroups, err := genCComponentStubFiles(cfg, "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(noGroups, "cabi_realloc") {
		t.Error("no list is ever returned here, so no allocator should be emitted")
	}

	// A SET capability that returns a list needs the allocator just as much: the
	// `_all` pair hands back a list of ids and the scanner a list of tuples, and
	// the canonical ABI lowers both into the CALLER's memory. Getting this wrong
	// fails late, at `component new`, with "module does not export a function
	// named cabi_realloc".
	setOnly := cComponentCfg()
	setOnly.Regexps = []config.RegexEntry{{Pattern: `abc`}, {Pattern: `def`}}
	_, setC, err := genCComponentStubFiles(setOnly, "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setC, `export_name("cabi_realloc")`) {
		t.Error("a set returning lists needs cabi_realloc")
	}
}

// The lowered signatures differ per shape: the anchored one takes no start.
func TestCComponentLoweredSignatures(t *testing.T) {
	_, cContent, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cContent, "extern void ffi_lower_match(const unsigned char *ptr, unsigned int len, unsigned char *ret);") {
		t.Error("the anchored import must take (ptr, len, retptr)")
	}
	// An iterating export is a resource: its constructor takes the input and
	// answers a handle, and its `next` takes only that handle.
	if !strings.Contains(cContent, "extern int ffi_parse_url__res_new(const unsigned char *ptr, unsigned int len, unsigned int start);") {
		t.Error("a resource constructor must take (ptr, len, start) and return a handle")
	}
	if !strings.Contains(cContent, "extern void ffi_parse_url(int handle, unsigned char *ret);") {
		t.Error("a resource method must take (handle, retptr)")
	}
	if !strings.Contains(cContent, "extern void ffi_parse_url__res_drop(int handle);") {
		t.Error("a resource must be droppable")
	}
	// The result areas are read, not unpacked from an i64 as the module stub does.
	if strings.Contains(cContent, "long long") {
		t.Error("a component stub has no packed i64 return")
	}
	for _, want := range []string{"area[12]", "area[16]"} {
		if !strings.Contains(cContent, want) {
			t.Errorf("missing result area %s", want)
		}
	}
}

// Both drive rules must survive into the component implementation.
func TestCComponentKeepsTheDriveRules(t *testing.T) {
	_, cContent, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cContent, "iter->offset = (end > start) ? end : start + 1;") {
		t.Error("the advance rule is missing; a zero-length match would spin")
	}
	if !strings.Contains(cContent, "if (start == end && iter->prev_end == start) continue;") {
		t.Error("Go's adjacent-empty rule is missing")
	}
}

// The WIT directory layout is load-bearing: `component embed` resolves deps/ only
// when given the DIRECTORY, and a dependency package must not carry an exporting
// world.
func TestCComponentWritesWitDirectory(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.h")
	if err := cComponentStub(cComponentCfg(), out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"stub.h", "stub.c", "wit/consumer.wit", "wit/deps/regexped-urlparts/urlparts.wit"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing generated file %s: %v", f, err)
		}
	}
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(consumer), "world urlparts-consumer {") ||
		!strings.Contains(string(consumer), "import regexped:urlparts/matcher;") {
		t.Errorf("consumer world is wrong:\n%s", consumer)
	}
	dep, err := os.ReadFile(filepath.Join(dir, "wit", "deps", "regexped-urlparts", "urlparts.wit"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dep), "world ") {
		t.Errorf("the export world leaked into the dependency package:\n%s", dep)
	}
	if !strings.Contains(string(dep), "interface matcher {") {
		t.Errorf("the dependency lost its interface:\n%s", dep)
	}
}

func TestCComponentVersioned(t *testing.T) {
	cfg := cComponentCfg()
	cfg.WitVersion = "2.3.0"
	_, cContent, err := genCComponentStubFiles(cfg, "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	// The version follows the INTERFACE name in the import module.
	if !strings.Contains(cContent, `__import_module__("regexped:urlparts/matcher@2.3.0")`) {
		t.Error("the version is missing from, or misplaced in, the import module")
	}
}

func TestCComponentDispatchAndEmpty(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.h")
	cfg := cComponentCfg()
	cfg.StubType = "c"
	cfg.StubFile = out
	if err := CmdGenerateStub(cfg, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "stub.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "__import_module__(\"regexped:") {
		t.Error("component config produced the MODULE stub")
	}

	// A config with no exports writes nothing at all.
	cfg.Regexps = []config.RegexEntry{{Pattern: "abc"}}
	cfg.Sets = nil // a set declaring a capability IS an export
	empty := filepath.Join(t.TempDir(), "stub.h")
	if err := cComponentStub(cfg, empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Error("no header should have been written")
	}
}

func TestCComponentStubToStdout(t *testing.T) {
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
	err = cComponentStub(cComponentCfg(), "-")
	w.Close()
	os.Stdout = saved
	if err != nil {
		t.Fatal(err)
	}
	got := <-done
	if !strings.Contains(got, "#pragma once") || !strings.Contains(got, "__import_module__") {
		t.Error("stdout did not receive both halves")
	}
}

func TestCComponentNameErrors(t *testing.T) {
	cfg := cComponentCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: "a", FindFunc: "_bad"}}
	if _, _, err := genCComponentStubFiles(cfg, "stub.h"); err == nil {
		t.Error("an unrepresentable func name must be rejected")
	}
}

func TestStripExportWorld(t *testing.T) {
	in := "package regexped:x;\n\ninterface matcher {\n    enum e { a }\n}\n\nworld x {\n    export matcher;\n}\n"
	got := stripExportWorld(in)
	if strings.Contains(got, "world") {
		t.Errorf("world survived:\n%s", got)
	}
	if !strings.Contains(got, "interface matcher {") || !strings.Contains(got, "package regexped:x;") {
		t.Errorf("stripping removed too much:\n%s", got)
	}
}

// cFunctionBody returns the body of the C function whose definition line starts
// with `prefix`, up to its closing brace at column 0.
func cFunctionBody(t *testing.T, src, prefix string) string {
	t.Helper()
	i := strings.Index(src, "\n"+prefix)
	if i < 0 {
		t.Fatalf("no function starting %q in the generated source", prefix)
	}
	body := src[i+1:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j+2]
	}
	return body
}

// The set wrappers that RECEIVE a list — the `_all` pair and the scanner — must
// release it on every return after the call, as the groups wrapper does. The
// composition glue allocates the returned list in this component's memory
// through cabi_realloc, and without the mark and release every call leaked it
// from the bump heap for the life of the process.
func TestCComponentSetListsAreReleasedPerCall(t *testing.T) {
	_, c, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"int all_secret_hits(", "int all_secrets(", "int scan_secrets(rx_secrets_scanner_t"} {
		body := cFunctionBody(t, c, prefix)
		mark := strings.Index(body, "cabi_mark(")
		if mark < 0 || strings.Count(body, "cabi_mark(") != 1 {
			t.Errorf("%s: want exactly one mark before the call, got %d", prefix, strings.Count(body, "cabi_mark("))
			continue
		}
		after := body[mark:]
		if r, n := strings.Count(after, "cabi_release("), strings.Count(after, "return "); r != n {
			t.Errorf("%s: %d releases for %d return paths after the mark:\n%s", prefix, r, n, body)
		}
	}
}

// A scanner call whose buffer cannot hold one position's worst case is refused
// with RX_ERR_RANGE before anything is written or advanced — in BOTH formats,
// since they share the header that states the rule. The module call used to be
// transactional and the component one silently discarded what did not fit.
func TestCScannerRefusesABufferBelowPatternCount(t *testing.T) {
	const want = "if (cap < (size_t)SECRETS_PATTERN_COUNT) return RX_ERR_RANGE;"
	h, c, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c, want) {
		t.Errorf("the component scanner does not refuse a small buffer: missing %q", want)
	}
	mod := cComponentCfg()
	mod.WasmFormat = ""
	dir := t.TempDir()
	if err := cStub(mod, filepath.Join(dir, "stub.h")); err != nil {
		t.Fatal(err)
	}
	mc, err := os.ReadFile(filepath.Join(dir, "stub.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mc), want) {
		t.Errorf("the module scanner does not refuse a small buffer: missing %q", want)
	}
	if strings.Contains(h, "transactional") {
		t.Error("the shared header still promises a transactional overflow")
	}
}

// Re-initialising a LIVE component scanner drops the resource it held before
// constructing a new one; the header promises it. A magic word tells a live
// scanner from an uninitialised struct, as the module scanner's does.
func TestCComponentReinitDropsTheLiveHandle(t *testing.T) {
	_, c, err := genCComponentStubFiles(cComponentCfg(), "stub.h")
	if err != nil {
		t.Fatal(err)
	}
	body := cFunctionBody(t, c, "int scan_secrets_init(")
	if !strings.Contains(body, fmt.Sprint(abi.FindScratchMagic)) {
		t.Errorf("_init does not test the scanner's magic word:\n%s", body)
	}
	drop, ctor := strings.Index(body, "_drop("), strings.Index(body, "_new(")
	if drop < 0 || ctor < 0 || drop > ctor {
		t.Errorf("_init must drop a live handle BEFORE constructing (drop at %d, construct at %d):\n%s",
			drop, ctor, body)
	}
}

// Two component C stubs in ONE guest must link. The allocator's mark and release
// were strong, non-static definitions, so a second stub was a duplicate symbol;
// and a per-stub copy of the heap state would let one stub rewind a counter the
// winning cabi_realloc never advanced. Every allocator symbol is WEAK, shared by
// name, so the linker keeps one of each.
func TestTwoCComponentStubsLinkInOneGuest(t *testing.T) {
	for _, tool := range []string{"cc", "nm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	dir := t.TempDir()
	mk := func(ns, pkg, set string) config.BuildConfig {
		return config.BuildConfig{
			WasmFormat: "component", ImportModule: pkg, WitPackage: pkg, Namespace: ns,
			Regexps: []config.RegexEntry{{Name: "a", Pattern: `[a-z]+`}, {Name: "d", Pattern: `[0-9]+`}},
			Sets: []config.SetConfig{{
				Name: set, Patterns: config.PatternSelector{All: true},
				ScanAll: set + "_hits", Find: "scan_" + set,
			}},
		}
	}
	var objs []string
	for _, s := range []struct{ ns, pkg, set string }{{"nsa", "pkg-a", "ova"}, {"nsb", "pkg-b", "ovb"}} {
		sub := filepath.Join(dir, s.ns)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := cComponentStub(mk(s.ns, s.pkg, s.set), filepath.Join(sub, "stub.h")); err != nil {
			t.Fatalf("generate %s: %v", s.ns, err)
		}
		obj := filepath.Join(dir, s.ns+".o")
		run(t, sub, nil, "cc", "-c", "-Wno-attributes", "-o", obj, "stub.c")
		objs = append(objs, obj)
	}
	main := "#include \"nsa/stub.h\"\n#include \"nsb/stub.h\"\nint main(void) { return 0; }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, nil, "cc", "-fsyntax-only", "-Wno-attributes", "main.c")

	strong := map[string][]string{}
	for _, obj := range objs {
		out, err := exec.Command("nm", obj).CombinedOutput()
		if err != nil {
			t.Fatalf("nm %s: %v\n%s", obj, err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && (f[1] == "T" || f[1] == "D" || f[1] == "B") && strings.Contains(f[2], "cabi") {
				strong[f[2]] = append(strong[f[2]], filepath.Base(obj))
			}
		}
	}
	for sym, in := range strong {
		if len(in) > 1 {
			t.Errorf("%s is a strong definition in %v: two stubs in one guest cannot link", sym, in)
		}
	}
}

// A capability named like the resource's own imports must not collide with
// them. The resource imports were `_ffi_<find>_next` and friends, so a
// `scan_all: scan_it_next` beside `find: scan_it` declared one symbol twice with
// two signatures.
func TestCComponentCapabilityNamedLikeTheResourceImport(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not on PATH")
	}
	cfg := config.BuildConfig{
		WasmFormat: "component", ImportModule: "t", WitPackage: "t",
		Regexps: []config.RegexEntry{{Name: "a", Pattern: `[a-z]+`}, {Name: "d", Pattern: `[0-9]+`}},
		Sets: []config.SetConfig{{
			Name: "s", Patterns: config.PatternSelector{All: true},
			ScanAll: "scan_it_next", Find: "scan_it",
		}},
	}
	dir := t.TempDir()
	if err := cComponentStub(cfg, filepath.Join(dir, "stub.h")); err != nil {
		t.Fatalf("generate: %v", err)
	}
	run(t, dir, nil, "cc", "-fsyntax-only", "-Wno-attributes", "stub.c")
}

// The SET halves of the two component stub generators, and their refusals.
//
// The happy paths are covered by the parity tests beside these — the Rust stub by
// extracted public surface, the C header by text comparison — so what is left is
// what those cannot reach: a name that is not a WIT identifier, reported by the
// KEY the user has to edit rather than as a failure from somewhere downstream.

func setStubCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		WasmFile:     "t.wasm",
		Regexps: []config.RegexEntry{
			{Pattern: `ghp_[A-Za-z0-9]{4}`, MatchFunc: "token_match"},
			{Pattern: `AKIA[A-Z0-9]{6}`},
		},
		Sets: []config.SetConfig{{
			Name:        "s",
			Patterns:    config.PatternSelector{All: true},
			MatchAny:    "which_matches",
			MatchAll:    "all_matches",
			ScanAny:     "any_hit",
			ScanAll:     "all_hits",
			Find:        "scan_it",
			EmitNameMap: true,
		}},
	}
}

// setStubWit is the validated WIT view the generators now take, so a test does
// not re-derive names the generator no longer derives either.
func setStubWit(t *testing.T, cfg config.BuildConfig) []witSet {
	t.Helper()
	_, _, _, sets, err := witParts(cfg)
	if err != nil {
		t.Fatalf("witParts: %v", err)
	}
	return sets
}

// The Rust set wrappers: the constants, every capability, and the iterator over
// the resource. The iterator keeps its lifetime parameter even though the scan
// copied the input — it is part of the type the module stub exposes.
func TestRustComponentSetInner(t *testing.T) {
	cfg0 := setStubCfg()
	out := genRustComponentSetInner(cfg0, setStubWit(t, cfg0))
	for _, want := range []string{
		"pub const S_PATTERN_COUNT: usize = 2;",
		"pub const S_ID_SPACE: usize = 2;",
		"pub struct SetMatch {",
		"pub fn which_matches(input: &[u8]) -> Result<Option<i32>>",
		"pub fn all_matches(input: &[u8]) -> Result<impl Iterator<Item = i32> + '_>",
		"pub fn any_hit(input: &[u8], offset: usize) -> Result<Option<i32>>",
		"pub fn all_hits(input: &[u8], offset: usize) -> Result<impl Iterator<Item = i32> + '_>",
		"pub struct ScanItIter<'a> {",
		"inner: Option<sets::ScanIt>,",
		"sets::ScanIt::new(input, offset)",
		"impl std::iter::FusedIterator for ScanItIter<'_> {}",
		"pub fn pattern_name(id: i32) -> &'static str {",
		// The error arm must come BEFORE the finished test, or an engine that
		// gave up ends the iteration and reports success.
		"Err(e) => {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Rust set stub is missing %q", want)
		}
	}
	// No sets: nothing at all, so the caller needs no branch.
	cfg := setStubCfg()
	cfg.Sets = nil
	if got := genRustComponentSetInner(cfg, nil); got != "" {
		t.Errorf("genRustComponentSetInner(no sets) = %q, want empty", got)
	}
}

// Every name that reaches WIT goes through KebabIdent, and a set has five places
// to put an unrepresentable one. Each must be refused rather than mangled — and
// the refusal happens ONCE, in witParts, which is why the stub generators no
// longer have an error to return at all.
func TestComponentSetBadNamesRefusedOnce(t *testing.T) {
	for _, c := range []struct {
		field string
		set   func(*config.SetConfig)
	}{
		{"match_any", func(s *config.SetConfig) { s.MatchAny = "_bad" }},
		{"match_all", func(s *config.SetConfig) { s.MatchAll = "_bad" }},
		{"scan_any", func(s *config.SetConfig) { s.ScanAny = "_bad" }},
		{"scan_all", func(s *config.SetConfig) { s.ScanAll = "_bad" }},
		{"find", func(s *config.SetConfig) { s.Find = "_bad" }},
	} {
		cfg := setStubCfg()
		c.set(&cfg.Sets[0])
		if _, _, _, _, err := witParts(cfg); err == nil {
			t.Errorf("%s: an unrepresentable name was accepted", c.field)
		}
		// And the whole-stub generators refuse it, because they go through
		// witParts first.
		if _, err := genRustComponentStubFile(cfg); err == nil {
			t.Errorf("%s: the Rust stub accepted it", c.field)
		}
		if _, _, err := genCComponentStubFiles(cfg, "stub.h"); err == nil {
			t.Errorf("%s: the C stub accepted it", c.field)
		}
	}
}

// The two name mappings must agree with wit-bindgen's own, or the generated Rust
// does not compile: a function becomes snake_case, an imported resource becomes
// UpperCamel.
func TestRustResourceTypeAndFuncName(t *testing.T) {
	for _, c := range []struct{ kebab, wantType, wantFn string }{
		{"scan-it", "ScanIt", "scan_it"},
		{"scan", "Scan", "scan"},
		{"scan-all-secret-positions", "ScanAllSecretPositions", "scan_all_secret_positions"},
	} {
		if got := rustResourceType(c.kebab); got != c.wantType {
			t.Errorf("rustResourceType(%q) = %q, want %q", c.kebab, got, c.wantType)
		}
		if got := rustWitFuncName(c.kebab); got != c.wantFn {
			t.Errorf("rustWitFuncName(%q) = %q, want %q", c.kebab, got, c.wantFn)
		}
	}
}

// witSetKebab is the lookup that replaced re-deriving names. A capability the WIT
// view does not know is an internal disagreement, not a config error, so it is
// loud.
func TestWitSetKebabPanicsOnDisagreement(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a capability with no WIT name returned silently")
		}
	}()
	witSetKebab(witSet{}, config.SetCapability{Field: "scan_any", Name: "nope"})
}

// The C set bodies: the lowered imports, the id-list copy, and the resource
// trio. The declarations are the module stub's, checked by the header-parity test.
func TestCComponentSetParts(t *testing.T) {
	cfg0 := setStubCfg()
	h, c := genCComponentSetParts(cfg0, setStubWit(t, cfg0), "regexped:t/sets", newSetShapes(cfg0))
	for _, want := range []string{
		"#define S_PATTERN_COUNT 2",
		"#define S_ID_SPACE 2",
		"int which_matches(const char *input, size_t len);",
		"void scan_it_free(rx_s_scanner_t *s);",
		"const char *pattern_name(int id);",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("C set header is missing %q", want)
		}
	}
	for _, want := range []string{
		`__import_name__("which-matches")`,
		`__import_name__("[constructor]scan-it")`,
		`__import_name__("[method]scan-it.next")`,
		`__import_name__("[resource-drop]scan-it")`,
		// The constructor RETURNS a handle, so it is the one import that is not
		// void and takes no return area.
		"extern int ffi_scan_it__res_new(const unsigned char *ptr, unsigned int len, unsigned int start);",
		// The ids arrive as a list; the body copies rather than scanning bits,
		// reading each u32 by its bytes rather than through a cast pointer.
		"const unsigned char *ids = (const unsigned char *)(size_t)rx_cabi_u32(area + 4);",
		"patterns[i] = (int)rx_cabi_u32(ids + 4 * i);",
		// The handle lives in scratch[0] — the same field the MODULE stub
		// builds its ABI descriptor in; neither format uses both.
		"s->scratch[0] = (unsigned)ffi_scan_it__res_new(",
		// Dropping is idempotent: a second free must not drop twice, so free
		// needs a live handle and clears both words.
		"|| s->scratch[0] == 0) return;",
		"s->scratch[1] = 0;",
		"rx_pattern_names[] = {",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("C set body is missing %q", want)
		}
	}

	cfg := setStubCfg()
	cfg.Sets = nil
	if h, c := genCComponentSetParts(cfg, nil, "regexped:t/sets", newSetShapes(cfg)); h != "" || c != "" {
		t.Errorf("genCComponentSetParts(no sets) = %q/%q, want empty", h, c)
	}
}

// A refused config must leave NO file behind. A stub written from a config the
// WIT generator rejects is worse than no stub: the build then fails later,
// somewhere else.
func TestComponentStubsWriteNothingOnBadSetNames(t *testing.T) {
	cfg := setStubCfg()
	cfg.Sets[0].Find = "_bad"
	dir := t.TempDir()
	if err := rustComponentStub(cfg, filepath.Join(dir, "stubs.rs")); err == nil {
		t.Error("rustComponentStub reported success")
	}
	if err := cComponentStub(cfg, filepath.Join(dir, "stub.h")); err == nil {
		t.Error("cComponentStub reported success")
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Errorf("files were written for a refused config: %v", ents)
	}
}

// A set whose `_all` or `find` returns a list makes cabi_realloc mandatory in the
// C consumer, and the WIT directory has to import the sets interface — without
// either, the failure surfaces from `wasm-tools component new`, not from here.
func TestCComponentSetWitDirAndAllocator(t *testing.T) {
	dir := t.TempDir()
	if err := cComponentStub(setStubCfg(), filepath.Join(dir, "stub.h")); err != nil {
		t.Fatal(err)
	}
	cBytes, err := os.ReadFile(filepath.Join(dir, "stub.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cBytes), `export_name("cabi_realloc")`) {
		t.Error("a set returning lists needs cabi_realloc")
	}
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"import regexped:t/matcher;", "import regexped:t/sets;"} {
		if !strings.Contains(string(consumer), want) {
			t.Errorf("consumer.wit is missing %q:\n%s", want, consumer)
		}
	}
	dep, err := os.ReadFile(filepath.Join(dir, "wit", "deps", "regexped-t", "t.wit"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dep), "interface sets {") {
		t.Error("the dependency package must carry both interfaces")
	}
	// A dependency package supplies interfaces only: an exporting world in it
	// would describe a component rather than a dependency.
	if strings.Contains(string(dep), "world ") {
		t.Error("the export world must be stripped from the dependency")
	}
}

// A sets-only config imports only `sets`, in both generators. Importing an
// interface the document does not define is a macro error in Rust and an
// unresolvable world in C.
func TestComponentStubsSetsOnlyImports(t *testing.T) {
	cfg := setStubCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: `abc`}, {Pattern: `def`}}

	rs, err := genRustComponentStubFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rs, "import regexped:t/matcher;") || strings.Contains(rs, "::matcher;") {
		t.Error("a sets-only config imported the matcher interface in Rust")
	}
	if !strings.Contains(rs, "import regexped:t/sets;") || !strings.Contains(rs, "::sets;") {
		t.Error("a sets-only config did not import the sets interface in Rust")
	}

	dir := t.TempDir()
	if err := cComponentStub(cfg, filepath.Join(dir, "stub.h")); err != nil {
		t.Fatal(err)
	}
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(consumer), "regexped:t/matcher") {
		t.Errorf("a sets-only consumer world imported matcher:\n%s", consumer)
	}
}

// The WIT directory is written to the filesystem, so its failure has to surface.
// An unwritable destination is the reachable case.
func TestCComponentWitDirWriteFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "wit")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeComponentWitDir(setStubCfg(), blocker); err == nil {
		t.Error("writing the WIT directory over a file reported success")
	}
}

// TestCComponentSetWrappersEndToEnd DRIVES the generated C component set
// wrappers rather than reading their text: a real guest built with the header's
// own recipe, wrapped, composed with the regexp component by `regexped merge`,
// and run under wasmtime.
//
// Every other test of the C component stub compiles it for the HOST or checks
// its source. That is how three defects survived: `_all` and the scanner leaked
// every returned list from the guest's bump heap, the scanner silently discarded
// what did not fit a small buffer while the shared header promised a
// transactional overflow, and re-initialising a live scanner orphaned its
// resource. Each export of the guest below exercises one of them and returns 0
// on success, or the number of the check that failed.
func TestCComponentSetWrappersEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a composed component; skipped in -short")
	}
	clang := wasiClang(t)
	if clang == "" {
		t.Skip("no clang that targets wasm32-wasi: the C component wrappers are not driven here")
	}
	for _, tool := range []string{"go", "wasm-tools", "wac", "wasmtime"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH: the C component wrappers are not driven here", tool)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "regexped")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/qrdl/regexped").CombinedOutput(); err != nil {
		t.Fatalf("build regexped: %v\n%s", err, out)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("regexped.yaml", e2eConfig)
	run(t, dir, nil, bin, "compile", "--config=regexped.yaml")
	run(t, dir, nil, bin, "generate", "--config=regexped.yaml")

	// The generated consumer world imports the interfaces and exports nothing; a
	// component with no exports can be composed but not run.
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatalf("generate wrote no consumer world: %v", err)
	}
	cw := string(consumer)
	end := strings.LastIndex(cw, "}")
	if end < 0 {
		t.Fatalf("unexpected consumer world:\n%s", cw)
	}
	exports := "    export sanity: func() -> s32;\n    export lists: func() -> s32;\n" +
		"    export small-buffer: func() -> s32;\n    export reinit: func() -> s32;\n"
	write(filepath.Join("wit", "consumer.wit"), cw[:end]+exports+cw[end:])
	write("main.c", e2eGuest)

	run(t, dir, nil, clang, "--target=wasm32-wasi", "-nostdlib", "-Wl,--no-entry",
		"-DRX_SET_CACHE=0", "-DREGEXPED_CABI_HEAP_BYTES=4096",
		"-o", "core.wasm", "main.c", "stub.c")
	run(t, dir, nil, "wasm-tools", "component", "embed", "wit", "core.wasm",
		"--world", "e2e-consumer", "-o", "embedded.wasm")
	run(t, dir, nil, "wasm-tools", "component", "new", "embedded.wasm", "-o", "guest.wasm")
	run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=guest.wasm", "e2e.wasm")

	for _, c := range []struct {
		name, export string
		flags        []string
	}{
		{"sanity", "sanity", nil},
		// 5,000 `_all` calls and a long scan at a 4 KB guest heap: any list the
		// wrappers do not release exhausts it within a few hundred calls.
		{"lists are released", "lists", nil},
		{"a buffer below PATTERN_COUNT is refused", "small-buffer", nil},
		// Each leaked resource holds an input block, gates and a cache inside the
		// regexp component, which grows its memory to hold them. Capped at 64 MiB
		// a leaking build traps well inside 10,000 iterations; a correct one
		// reuses the same blocks every time.
		{"re-init drops the live handle", "reinit",
			[]string{"-W", "max-memory-size=67108864", "-W", "trap-on-grow-failure=y"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"run"}, c.flags...)
			args = append(args, "--invoke", c.export+"()", "composed.wasm")
			cmd := exec.Command("wasmtime", args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("wasmtime %s: %v\n%s", strings.Join(args, " "), err, out)
			}
			if got := strings.TrimSpace(string(out)); got != "0" {
				t.Fatalf("%s() returned %s, want 0 (the number is the failing check)", c.export, got)
			}
		})
	}
}

// e2eConfig is one pattern plus one set with all five capabilities, overlapping
// and cache-eligible: literal-less patterns in one bucket.
const e2eConfig = `wasm_format: component
wit_package: e2e
import_module: e2e
wasm_file: e2e.wasm
output: composed.wasm
stub_file: stub.h
regexps:
  - name: word
    pattern: '[a-z]+'
    match_func: word_match
  - name: digits
    pattern: '[0-9]+'
  - name: upper
    pattern: '[A-Z]+'
sets:
  - name: runs
    patterns: all
    match_any: runs_match_any
    match_all: runs_match_all
    scan_any: runs_scan_any
    scan_all: runs_scan_all
    find: scan_runs
    overlapping: true
`

// e2eGuest is the consumer. No libc: every result comes back as an int.
const e2eGuest = `#include "stub.h"

static const char SHORT[] = "ab12CD ab12CD ab12CD";
#define SHORT_LEN (sizeof SHORT - 1)
#define BIG 65536
static char big[BIG];

static void fill(void) {
    static const char unit[] = "ab12CD ";
    for (int i = 0; i < BIG; i++) big[i] = unit[i % 7];
}

__attribute__((export_name("sanity")))
int sanity(void) {
    int ids[RUNS_PATTERN_COUNT];
    if (word_match("abc", 3) != 3) return 1;
    if (runs_scan_all(SHORT, SHORT_LEN, 0, ids) != 3) return 2;
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    if (scan_runs_init(&s, SHORT, SHORT_LEN, 0) != 0) return 3;
    int total = 0, n;
    while ((n = scan_runs(&s, buf, RUNS_PATTERN_COUNT)) > 0) total += n;
    scan_runs_free(&s);
    if (n < 0) return 4;
    if (total == 0) return 5;
    return 0;
}

__attribute__((export_name("lists")))
int lists(void) {
    int ids[RUNS_PATTERN_COUNT];
    for (int i = 0; i < 5000; i++) {
        if (runs_scan_all(SHORT, SHORT_LEN, 0, ids) != 3) return 1;
        if (runs_match_all("abc", 3, ids) != 1) return 2;
    }
    fill();
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    if (scan_runs_init(&s, big, 16384, 0) != 0) return 3;
    int positions = 0, n;
    while ((n = scan_runs(&s, buf, RUNS_PATTERN_COUNT)) > 0) positions++;
    scan_runs_free(&s);
    if (n < 0) return 4;
    if (positions < 1000) return 5;
    return 0;
}

__attribute__((export_name("small-buffer")))
int small_buffer(void) {
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    unsigned char *raw = (unsigned char *)buf;
    for (unsigned i = 0; i < sizeof buf; i++) raw[i] = 0x5A;
    if (scan_runs_init(&s, SHORT, SHORT_LEN, 0) != 0) return 1;
    if (scan_runs(&s, buf, RUNS_PATTERN_COUNT - 1) != RX_ERR_RANGE) return 2;
    for (unsigned i = 0; i < sizeof buf; i++) if (raw[i] != 0x5A) return 3;
    if (scan_runs(&s, buf, RUNS_PATTERN_COUNT) <= 0) return 4;
    if (buf[0].start != 0) return 5; /* the refused call did not advance */
    scan_runs_free(&s);
    return 0;
}

__attribute__((export_name("reinit")))
int reinit(void) {
    fill();
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    for (int i = 0; i < 10000; i++) {
        if (scan_runs_init(&s, big, BIG, 0) != 0) return 1;
        if (scan_runs_init(&s, big, BIG, 0) != 0) return 2;
        if (scan_runs(&s, buf, RUNS_PATTERN_COUNT) <= 0) return 3;
        scan_runs_free(&s);
    }
    return 0;
}
`
