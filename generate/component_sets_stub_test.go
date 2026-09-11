package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

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
		"inner: sets::ScanIt,",
		"sets::ScanIt::new(input, offset as u32)",
		"impl std::iter::FusedIterator for ScanItIter<'_> {}",
		"pub fn pattern_name(id: i32) -> &'static str {",
		// The error arm must come BEFORE the finished test, or an engine that
		// gave up ends the iteration and reports success.
		"Err(sets::ErrorCode::BacktrackOverflow) => {",
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
	h, c := genCComponentSetParts(cfg0, setStubWit(t, cfg0), "regexped:t/sets")
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
		"extern int _ffi_scan_it_new(const unsigned char *ptr, unsigned int len, unsigned int start);",
		// The ids arrive as a list; the body copies rather than scanning bits.
		"const unsigned int *ids = *(const unsigned int **)(area + 4);",
		"patterns[i] = (int)ids[i];",
		// The handle lives in gates[0]; the real gate array is inside the
		// component.
		"s->gates[0] = (unsigned)_ffi_scan_it_new(",
		// Dropping is idempotent: a second free must not drop twice.
		"if (!s || s->gates[0] == 0) return;",
		"_pattern_names[] = {",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("C set body is missing %q", want)
		}
	}

	cfg := setStubCfg()
	cfg.Sets = nil
	if h, c := genCComponentSetParts(cfg, nil, "regexped:t/sets"); h != "" || c != "" {
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
	dep, err := os.ReadFile(filepath.Join(dir, "wit", "deps", "regexped-t", "matcher.wit"))
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
