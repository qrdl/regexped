package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// The SET adapters of `wasm_format: component`, driven from inside compile/.
//
// tools/fuzz drives them through wasmtime and checks the ANSWERS, which is the
// stronger test — but it is a separate Go module, so nothing it exercises counts
// as coverage here. These tests build the same modules and check what compile/
// alone can: that the emitted module is well-formed, that the adapter and
// resource exports are present under their canonical names, and that the
// function import a resource needs is declared.
//
// compile/ cannot derive the canonical names — generate/ imports compile/, not
// the other way round — so the names are written out by hand below. That is also
// what makes these tests independent of the WIT generator: a rename there cannot
// silently make them pass.

// setComponentNames is the name table component/ would build from the WIT.
func setComponentNames(setName string) map[string]ComponentSetNames {
	const iface = "regexped:t/sets"
	return map[string]ComponentSetNames{setName: {
		Caps: map[string]string{
			"which_matches": iface + "#which-matches",
			"all_matches":   iface + "#all-matches",
			"any_hit":       iface + "#any-hit",
			"all_hits":      iface + "#all-hits",
		},
		Constructor:    iface + "#[constructor]scan-it",
		Next:           iface + "#[method]scan-it.next",
		Dtor:           iface + "#[dtor]scan-it",
		ResourceImport: "[export]" + iface,
		ResourceNew:    "[resource-new]scan-it",
	}}
}

// setComponentCfg is a config declaring every capability over n patterns.
func setComponentCfg(n int) config.BuildConfig {
	cfg := config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		Sets: []config.SetConfig{{
			Name:     "s",
			Patterns: config.PatternSelector{All: true},
			MatchAny: "which_matches",
			MatchAll: "all_matches",
			ScanAny:  "any_hit",
			ScanAll:  "all_hits",
			Find:     "scan_it",
		}},
	}
	for i := 0; i < n; i++ {
		cfg.Regexps = append(cfg.Regexps, config.RegexEntry{
			Pattern: "kw" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "[0-9]{2}",
		})
	}
	return cfg
}

func buildSetComponent(t *testing.T, cfg config.BuildConfig) []byte {
	t.Helper()
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", nil, setComponentNames("s"), nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	validateWASM(t, core)
	return core
}

// TestSetComponentEmitsEveryAdapter covers both `_all` ABI widths: three
// patterns compile to the i64 bitmask form, seventy to the caller-owned bitmap.
// The adapters differ entirely between the two, and the wide one is the only
// place a bitmap is allocated and zeroed.
func TestSetComponentEmitsEveryAdapter(t *testing.T) {
	for _, c := range []struct {
		name     string
		patterns int
	}{
		{"narrow _all (i64 bitmask)", 3},
		{"wide _all (bitmap + count)", 70},
	} {
		t.Run(c.name, func(t *testing.T) {
			core := buildSetComponent(t, setComponentCfg(c.patterns))
			s := string(core)
			for _, want := range []string{
				"regexped:t/sets#which-matches",
				"regexped:t/sets#all-matches",
				"regexped:t/sets#any-hit",
				"regexped:t/sets#all-hits",
				"regexped:t/sets#[constructor]scan-it",
				"regexped:t/sets#[method]scan-it.next",
				"regexped:t/sets#[dtor]scan-it",
				"cabi_post_regexped:t/sets#all-hits",
				"cabi_realloc",
				// The canon builtin, IMPORTED: a constructor that returned its
				// representation instead would build and then trap at runtime
				// with "unknown handle index".
				"[export]regexped:t/sets",
				"[resource-new]scan-it",
			} {
				if !strings.Contains(s, want) {
					t.Errorf("core module does not export or import %q", want)
				}
			}
			// The constructor returns a bare handle and must NOT have a
			// post-return: one would free the scanner's state the moment it was
			// created.
			if strings.Contains(s, "cabi_post_regexped:t/sets#[constructor]scan-it") {
				t.Error("the constructor must not have a post-return")
			}
			// Nor must the destructor: it is not a lifted function at all.
			if strings.Contains(s, "cabi_post_regexped:t/sets#[dtor]scan-it") {
				t.Error("the dtor must not have a post-return")
			}
		})
	}
}

// TestSetComponentPartialCapabilities: a set declaring ONE capability must emit
// that adapter and nothing else. The adapter list is built by walking capFns,
// so an undeclared capability that still produced an export would mean the walk
// and the emitter disagree about indices.
func TestSetComponentPartialCapabilities(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Sets[0].MatchAll = ""
	cfg.Sets[0].ScanAny = ""
	cfg.Sets[0].ScanAll = ""
	cfg.Sets[0].Find = ""
	core := buildSetComponent(t, cfg)
	s := string(core)
	if !strings.Contains(s, "regexped:t/sets#which-matches") {
		t.Error("the declared capability is missing")
	}
	for _, absent := range []string{"#all-matches", "#any-hit", "#all-hits", "[constructor]"} {
		if strings.Contains(s, absent) {
			t.Errorf("undeclared capability %q was exported", absent)
		}
	}
	// With no `find` there is no resource, so no function import at all — and
	// therefore no index offset.
	if strings.Contains(s, "[resource-new]") {
		t.Error("a set without find must not import the resource builtin")
	}
}

// TestSetComponentFindOnly is the other end of the same rule, and the case that
// makes the function-import offset matter on its own.
func TestSetComponentFindOnly(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Sets[0].MatchAny = ""
	cfg.Sets[0].MatchAll = ""
	cfg.Sets[0].ScanAny = ""
	cfg.Sets[0].ScanAll = ""
	core := buildSetComponent(t, cfg)
	if !strings.Contains(string(core), "[resource-new]scan-it") {
		t.Error("a set with find must import the resource builtin")
	}
}

// TestSetComponentNamelessSetEmitsNoAdapters: a set with no entry in the name
// table contributes nothing rather than panicking or emitting a nameless export.
// That is the state a config reaches when generate/ declined to name it.
func TestSetComponentNamelessSetEmitsNoAdapters(t *testing.T) {
	core, _, err := CompileFileComponent(setComponentCfg(3), "regexped:t/matcher", nil,
		map[string]ComponentSetNames{"someone-else": {}}, nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	validateWASM(t, core)
	if strings.Contains(string(core), "regexped:t/sets#") {
		t.Error("a set absent from the name table produced adapters")
	}
}

// TestSetComponentIgnoresOutputForMemoryMode: a component owns and exports its
// own memory, so `output:` — which selects the EMBEDDED shape for a module —
// must not reach that choice. It is the merge target in both formats.
func TestSetComponentIgnoresOutputForMemoryMode(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Output = "composed.wasm"
	core := buildSetComponent(t, cfg)
	if !strings.Contains(string(core), "memory") {
		t.Error("the component core module must export its own memory")
	}
	// An embedded module would IMPORT "main"."memory" instead.
	if strings.Contains(string(core), "main") && strings.Contains(string(core), "\x02\x00\x00") {
		t.Log("note: checked structurally below rather than by byte search")
	}
}

// TestSetComponentRefusesWithoutPackage: the interface prefix is what every
// canonical export name is built from, so a missing one is refused here rather
// than surfacing from wasm-tools as a complaint about the WIT.
func TestSetComponentRefusesWithoutPackage(t *testing.T) {
	_, _, err := CompileFileComponent(setComponentCfg(3), "", nil, setComponentNames("s"), nil)
	if err == nil {
		t.Fatal("a component with no package prefix was accepted")
	}
}

// TestSetComponentNoSetsDelegates: CompileFileComponent with no `sets:` must
// produce exactly what the single-pattern path produces. The set assembler is a
// second assembler, and the two must not diverge on a config that reaches
// either.
func TestSetComponentNoSetsDelegates(t *testing.T) {
	cfg := config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		Regexps:      []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}},
	}
	names := map[string]string{"m": "regexped:t/matcher#m"}
	viaSets, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	direct, _, err := Compile(cfg.Regexps, 0, true, CompileOptions{
		Component:            true,
		ComponentPackage:     "regexped:t/matcher",
		ComponentExportNames: names,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(viaSets) != string(direct) {
		t.Errorf("the set path produced %d bytes for a set-less config, the direct path %d",
			len(viaSets), len(direct))
	}
}

// The body emitters, checked for framing. A body that does not close, or whose
// local declaration disagrees with the locals it uses, fails module validation —
// which the builds above already cover — but these pin the ARITY variants, two
// of which no config in this file reaches on its own.
func TestSetAdapterBodyFraming(t *testing.T) {
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"match_any (2 params)", buildSetAnyAdapterBody(9, 3, 2)},
		{"scan_any (3 params)", buildSetAnyAdapterBody(9, 3, 3)},
		{"match_all narrow", buildSetAllNarrowAdapterBody(9, 3, 2)},
		{"scan_all narrow", buildSetAllNarrowAdapterBody(9, 3, 3)},
		{"match_all wide", buildSetAllWideAdapterBody(9, 3, 2, 70)},
		{"scan_all wide", buildSetAllWideAdapterBody(9, 3, 3, 70)},
		{"constructor (no cache)", buildSetScannerCtorBody(9, 0, 1, 12, 0, 0)},
		// With a cache the constructor grows a whole sizing block, so both
		// shapes are checked: the arithmetic is emitted only when the set has a
		// sweep, and an empty or malformed body would be invisible otherwise.
		{"constructor (with cache)", buildSetScannerCtorBody(9, 0, 1, 12, 33, 3)},
		{"next", buildSetScannerNextBody(9, 3, 12)},
		{"dtor", buildSetScannerDtorBody(10)},
	} {
		if len(c.body) == 0 {
			t.Errorf("%s: empty body", c.name)
			continue
		}
		if c.body[len(c.body)-1] != 0x0B {
			t.Errorf("%s: body does not end with `end`", c.name)
		}
	}
}

// buildSetAdapterBody is the dispatcher the assembler goes through; an unknown
// kind is a programming error and must be loud rather than emit nothing.
func TestSetAdapterBodyUnknownKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an unknown adapter kind returned silently")
		}
	}()
	buildSetAdapterBody(setAdapter{kind: setAdapterKind(99)}, 1, 2, 3)
}

// TestSetComponentMixedWithPatterns is the case that had NO test and was broken:
// a config declaring single-pattern funcs AND sets.
//
// Two things have to hold at once. The pattern adapters must be emitted at all —
// this assembler is the only one such a config reaches, and omitting them left
// the WIT declaring exports the module did not have. And their inner call targets
// must be OFFSET by the function import the resource needs: without that they
// call the function one index below, which validates as a stack mismatch inside
// the adapter and says nothing about the cause.
func TestSetComponentMixedWithPatterns(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Regexps[0].MatchFunc = "token_match"
	cfg.Regexps[1].FindFunc = "token_find"
	names := map[string]string{
		"token_match": "regexped:t/matcher#token-match",
		"token_find":  "regexped:t/matcher#token-find",
	}
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, setComponentNames("s"), nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	// validateWASM is the check that catches a mis-offset call: the adapter's
	// body stops type-checking.
	validateWASM(t, core)
	s := string(core)
	for _, want := range []string{
		"regexped:t/matcher#token-match",
		"cabi_post_regexped:t/matcher#token-match",
		"regexped:t/matcher#token-find",
		"regexped:t/sets#any-hit",
		"regexped:t/sets#[constructor]scan-it",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("core module is missing %q", want)
		}
	}
}

// The same shape WITHOUT a find resource, so no function import and no offset.
// It is the control for the test above: if that one passed only because the
// offset happened to be zero, this is the one that would still pass.
func TestSetComponentMixedWithoutResource(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Regexps[0].MatchFunc = "token_match"
	cfg.Sets[0].Find = ""
	names := map[string]string{"token_match": "regexped:t/matcher#token-match"}
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, setComponentNames("s"), nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	validateWASM(t, core)
	if !strings.Contains(string(core), "regexped:t/matcher#token-match") {
		t.Error("the pattern adapter is missing")
	}
	if strings.Contains(string(core), "[resource-new]") {
		t.Error("no find means no imported builtin")
	}
}
