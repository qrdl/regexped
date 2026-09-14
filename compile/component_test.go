package compile

import (
	"errors"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The canonical export names are supplied by generate/ in production. The tests
// here mint their own, because compile/ must not import generate/ (generate/
// already imports compile/), and because what compile/ actually depends on is
// only that a name EXISTS for a func — not how it was spelled.
func canonicalNames(entries []config.RegexEntry) map[string]string {
	const prefix = "regexped:test/matcher"
	names := map[string]string{}
	for _, e := range entries {
		for _, n := range []string{e.MatchFunc, e.FindFunc, e.GroupsFunc} {
			if n != "" {
				names[n] = prefix + "#" + strings.ReplaceAll(n, "_", "-")
			}
		}
	}
	return names
}

func componentOpts(entries []config.RegexEntry) CompileOptions {
	return CompileOptions{
		Component:            true,
		ComponentPackage:     "regexped:test/matcher",
		ComponentExportNames: canonicalNames(entries),
	}
}

// The zero value of asmOpts means MODULE — that is the property that lets every
// pre-existing call site pass asmOpts{} and keep its bytes.
func TestAsmOptsZeroValueMeansModule(t *testing.T) {
	var o asmOpts
	if o.Component {
		t.Error("the zero value must not request a component")
	}
	if err := o.validate(); err != nil {
		t.Errorf("the zero value must validate: %v", err)
	}
}

// The struct permits a state the emitter must not act on: a component with no
// package prefix would name its exports without one, and wasm-tools would then
// fail to match them against the WIT — late, and with a message about the WIT.
func TestAsmOptsRejectsComponentWithoutPackage(t *testing.T) {
	o := asmOpts{Component: true}
	if err := o.validate(); !errors.Is(err, errComponentNoPackage) {
		t.Errorf("err = %v, want errComponentNoPackage", err)
	}
	o.ComponentPackage = "regexped:x/matcher"
	if err := o.validate(); err != nil {
		t.Errorf("a component with a package must validate: %v", err)
	}
}

func TestCompileRejectsComponentWithoutStandalone(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: `abc`, FindFunc: "f"}}
	_, _, err := Compile(entries, 0, false, componentOpts(entries))
	if !errors.Is(err, errComponentNeedsStandalone) {
		t.Errorf("err = %v, want errComponentNeedsStandalone", err)
	}
}

func TestCompileRejectsComponentWithoutPackage(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: `abc`, FindFunc: "f"}}
	opts := componentOpts(entries)
	opts.ComponentPackage = ""
	if _, _, err := Compile(entries, 0, true, opts); !errors.Is(err, errComponentNoPackage) {
		t.Errorf("err = %v, want errComponentNoPackage", err)
	}
}

func TestPatternBaseIndices(t *testing.T) {
	if idx, total := patternBaseIndices(nil); total != 0 || len(idx) != 0 {
		t.Errorf("empty: idx=%v total=%d", idx, total)
	}
	entries := []config.RegexEntry{
		{Pattern: `abc`, MatchFunc: "m"},
		{Pattern: `def`, FindFunc: "f"},
	}
	// Compile once so the patterns carry real function layouts, then check the
	// bases are cumulative and the total is their sum.
	compiled := compileForTest(t, entries)
	idx, total := patternBaseIndices(compiled)
	if len(idx) != len(compiled) {
		t.Fatalf("got %d bases for %d patterns", len(idx), len(compiled))
	}
	want := 0
	for i, p := range compiled {
		if idx[i] != want {
			t.Errorf("base[%d] = %d, want %d", i, idx[i], want)
		}
		want += p.funcCount()
	}
	if total != want {
		t.Errorf("total = %d, want %d", total, want)
	}
}

// compileForTest compiles entries and returns the internal patterns, so the
// adapter list can be checked against real function layouts.
func compileForTest(t *testing.T, entries []config.RegexEntry) []*compiledPattern {
	t.Helper()
	var out []*compiledPattern
	cur := int64(0)
	for _, e := range entries {
		p, err := compilePattern(e, cur, 0, CompileOptions{globals: &moduleGlobals{}})
		if err != nil {
			t.Fatalf("compile %q: %v", e.Pattern, err)
		}
		if p == nil {
			continue
		}
		out = append(out, p)
		cur = p.tableEnd
	}
	return out
}

// One adapter per exported function, in the order the functions are appended,
// and NONE for a func whose canonical name the caller did not supply — the
// assembler must never invent a name.
func TestComponentAdaptersSelection(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `abc`, MatchFunc: "m"},
		{Pattern: `def`, FindFunc: "f"},
		{Pattern: `(?P<g>x)y`, GroupsFunc: "g"},
		{Pattern: `zzz`}, // no _func: contributes nothing
	}
	compiled := compileForTest(t, entries)
	names := canonicalNames(entries)

	got := componentAdapters(compiled, names, nil, 0)
	if len(got) != 3 {
		t.Fatalf("got %d adapters, want 3: %+v", len(got), got)
	}
	wantKinds := []adapterKind{adapterMatch, adapterFind, adapterGroups}
	for i, a := range got {
		if a.kind != wantKinds[i] {
			t.Errorf("adapter %d kind = %v, want %v", i, a.kind, wantKinds[i])
		}
		if a.export == "" {
			t.Errorf("adapter %d has no export name", i)
		}
	}
	if got[2].numGroups < 2 {
		t.Errorf("groups adapter numGroups = %d, want at least 2 (group 0 plus one)", got[2].numGroups)
	}

	// Drop one name: that function keeps its raw export and gains no adapter.
	delete(names, "f")
	if got := componentAdapters(compiled, names, nil, 0); len(got) != 2 {
		t.Errorf("with one name missing, got %d adapters, want 2", len(got))
	}
	// No names at all: no adapters.
	if got := componentAdapters(compiled, nil, nil, 0); len(got) != 0 {
		t.Errorf("with no names, got %d adapters", len(got))
	}
}

// The emitted bodies must be well-formed WASM in context, which is what
// assembling and validating the whole module checks. Driving all three adapter
// kinds at once also covers the shared allocator and post-return.
func TestComponentModuleAssemblesAndValidates(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `[a-z]+`, MatchFunc: "lower_match"},
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "token_find"},
		{Pattern: `(?P<opt>x)?(?P<tail>y+)`, GroupsFunc: "opt_groups"},
	}
	wasm, _, err := Compile(entries, 0, true, componentOpts(entries))
	if err != nil {
		t.Fatal(err)
	}
	validateWASM(t, wasm)

	// The exports the canonical ABI requires, plus the raw ones, which are kept.
	for _, want := range []string{
		"cabi_realloc", "memory",
		"regexped:test/matcher#lower-match",
		"cabi_post_regexped:test/matcher#lower-match",
		"regexped:test/matcher#token-find",
		"regexped:test/matcher#opt-groups",
		"lower_match", "token_find", "opt_groups",
	} {
		if !strings.Contains(string(wasm), want) {
			t.Errorf("export %q missing from the module", want)
		}
	}
}

// A pattern with many capture groups is the case a byte-sized memarg offset got
// wrong: at 22 groups the element buffer passes offset 255, so the adapter must
// encode its offsets as LEB128. A module that validates is the proof.
func TestGroupsAdapterHandlesOffsetsPastOneByte(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("(a)")
	}
	entries := []config.RegexEntry{{Pattern: sb.String(), GroupsFunc: "many_groups"}}
	wasm, _, err := Compile(entries, 0, true, componentOpts(entries))
	if err != nil {
		t.Fatal(err)
	}
	validateWASM(t, wasm)
}

// A component module with NO groups export must still declare the
// (i32,i32,i32,i32) type cabi_realloc needs — it is shared with the groups-from
// wrapper, which is absent here.
func TestComponentWithoutGroupsStillTypesRealloc(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: `abc`, MatchFunc: "m"}}
	wasm, _, err := Compile(entries, 0, true, componentOpts(entries))
	if err != nil {
		t.Fatal(err)
	}
	validateWASM(t, wasm)
}

// The allocator and post-return are emitted from one place and reference their
// two globals only through it, so the allocator can be replaced without
// touching the adapters.
func TestComponentAllocatorBodies(t *testing.T) {
	realloc := buildComponentReallocBody(1, 2, 0x30000)
	if len(realloc) == 0 {
		t.Fatal("empty cabi_realloc body")
	}
	// One local group, then the body; the last byte closes the function.
	if realloc[0] != 0x01 || realloc[len(realloc)-1] != 0x0B {
		t.Errorf("unexpected body framing: % x … %#x", realloc[:3], realloc[len(realloc)-1])
	}
	if free := buildComponentFreeBody(0x30000); len(free) == 0 || free[len(free)-1] != 0x0B {
		t.Error("cm_free body is empty or unterminated")
	}
	post := buildComponentPostBody(2, 7)
	// The post-return now walks the per-call chain, so it HAS locals — a body
	// with none is the old bump-reset version and cannot free anything.
	if post[0] == 0x00 {
		t.Error("the post-return declares no locals: it cannot be walking the call chain")
	}
	if post[len(post)-1] != 0x0B {
		t.Error("the post-return body must close")
	}
	// It must contain a loop (0x03), which the reset version never did.
	if !strings.Contains(string(post), "\x03\x40") {
		t.Error("no loop in the post-return body: nothing is walking the chain")
	}
}

// A non-zero global initialiser is what the heap pointer needs; every other
// global stays at zero, which is why the module-format bytes do not move.
func TestModuleGlobalsAllocInit(t *testing.T) {
	g := &moduleGlobals{}
	plain := g.Alloc()
	withInit := g.AllocInit(0x30000)
	zeroInit := g.AllocInit(0)
	if plain == withInit || withInit == zeroInit {
		t.Fatalf("indices must be distinct: %d %d %d", plain, withInit, zeroInit)
	}
	if g.Count() != 4 { // find-from plus the three above
		t.Errorf("Count = %d, want 4", g.Count())
	}
	if g.inits[withInit] != 0x30000 {
		t.Errorf("init not recorded: %v", g.inits)
	}
	if _, ok := g.inits[zeroInit]; ok {
		t.Error("a zero initialiser must not be recorded — it is the default")
	}
	// The section must carry the recorded value, and zeros elsewhere.
	sec := g.Section()
	if len(sec) == 0 {
		t.Fatal("empty global section")
	}
	// 0x80 0x80 0x0C is SLEB128 for 0x30000; its presence proves the
	// initialiser reached the section rather than being dropped.
	if !strings.Contains(string(sec), "\x80\x80\x0c") {
		t.Errorf("the non-zero initialiser is missing from the section: % x", sec)
	}
}

// CompileOptions projects onto asmOpts in one place, so a new component option is
// added once rather than at each assembler.
func TestCompileOptionsProjection(t *testing.T) {
	names := map[string]string{"f": "regexped:x/matcher#f"}
	o := CompileOptions{Component: true, ComponentPackage: "regexped:x/matcher", ComponentExportNames: names}
	got := o.asmOpts(nil)
	if !got.Component || got.ComponentPackage != o.ComponentPackage || got.ExportNames["f"] != names["f"] {
		t.Errorf("projection lost something: %+v", got)
	}
	if (CompileOptions{}).asmOpts(nil).Component {
		t.Error("a plain CompileOptions must project to module")
	}
}

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
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", nil, nil, setComponentNames("s"), nil)
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
	core, _, err := CompileFileComponent(setComponentCfg(3), "regexped:t/matcher", nil, nil,
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
	if imports, exported := memoryImportsExports(t, core); imports != 0 || !exported {
		t.Errorf("the component core imports %d memories and exports one: %v; a component owns and exports its own",
			imports, exported)
	}

	// The control: an EMBEDDED module imports its memory, and the walk must say
	// so, or the assertion above would pass on a parser that finds nothing.
	embedded, _, err := Compile([]config.RegexEntry{{Pattern: `a+`, MatchFunc: "m"}}, 0, false, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if imports, _ := memoryImportsExports(t, embedded); imports != 1 {
		t.Errorf("an embedded module imports %d memories by this walk, want 1", imports)
	}
}

// memoryImportsExports walks a module's import and export sections: how many
// MEMORIES it imports, and whether it exports one named "memory". A byte search
// cannot tell those apart — an embedded module carries the string "memory" too,
// in the name of the memory it imports.
func memoryImportsExports(t *testing.T, mod []byte) (memImports int, memExported bool) {
	t.Helper()
	uleb := func(i int) (uint64, int) {
		v, n, err := utils.DecodeULEB128(mod[i:])
		if err != nil {
			t.Fatalf("malformed LEB128 at %d: %v", i, err)
		}
		return v, i + n
	}
	name := func(i int) (string, int) {
		n, j := uleb(i)
		return string(mod[j : j+int(n)]), j + int(n)
	}
	limits := func(i int) int {
		flags := mod[i]
		_, i = uleb(i + 1)
		if flags&1 != 0 {
			_, i = uleb(i)
		}
		return i
	}
	for i := 8; i < len(mod); {
		id := mod[i]
		size, j := uleb(i + 1)
		end := j + int(size)
		switch id {
		case 2: // imports
			cnt, k := uleb(j)
			for e := uint64(0); e < cnt; e++ {
				_, k = name(k)
				_, k = name(k)
				kind := mod[k]
				k++
				switch kind {
				case 0x00:
					_, k = uleb(k)
				case 0x01:
					k = limits(k + 1)
				case 0x02:
					memImports++
					k = limits(k)
				case 0x03:
					k += 2
				default:
					t.Fatalf("unknown import kind %#x", kind)
				}
			}
		case 7: // exports
			cnt, k := uleb(j)
			for e := uint64(0); e < cnt; e++ {
				var nm string
				nm, k = name(k)
				kind := mod[k]
				_, k = uleb(k + 1)
				if kind == 0x02 && nm == "memory" {
					memExported = true
				}
			}
		}
		i = end
	}
	return memImports, memExported
}

// TestSetComponentRefusesWithoutPackage: the interface prefix is what every
// canonical export name is built from, so a missing one is refused here rather
// than surfacing from wasm-tools as a complaint about the WIT.
func TestSetComponentRefusesWithoutPackage(t *testing.T) {
	_, _, err := CompileFileComponent(setComponentCfg(3), "", nil, nil, setComponentNames("s"), nil)
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
	viaSets, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, nil, nil, nil)
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
		{"constructor (no cache)", buildSetScannerCtorBody(setScannerCtor{reallocIdx: 9, callListGlobal: 1, idSpace: 12})},
		// With a cache the constructor grows a whole sizing block, so both
		// shapes are checked: the arithmetic is emitted only when the set has a
		// sweep, and an empty or malformed body would be invisible otherwise.
		{"constructor (with cache)", buildSetScannerCtorBody(setScannerCtor{reallocIdx: 9, callListGlobal: 1, idSpace: 12, cells: 33, pats: 3})},
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
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, nil, setComponentNames("s"), nil)
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
	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", names, nil, setComponentNames("s"), nil)
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

// TestSetComponentSkipsMissingCapabilityName: a capability with no canonical
// name in the table is SKIPPED, the way the pattern path skips a pattern with no
// name — not exported under the empty string, which builds and then fails only
// inside `wasm-tools component new`.
func TestSetComponentSkipsMissingCapabilityName(t *testing.T) {
	names := setComponentNames("s")
	delete(names["s"].Caps, "any_hit")
	core, _, err := CompileFileComponent(setComponentCfg(3), "regexped:t/matcher", nil, nil, names, nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	if moduleExports(core, "") {
		t.Error("a capability with no canonical name was exported under the empty string")
	}
	if !moduleExports(core, "regexped:t/sets#which-matches") {
		t.Error("the capabilities that do have names must still be exported")
	}
}

// ---------------------------------------------------------------------------
// The single-pattern find/groups RESOURCES, from the compile package's side.
//
// tools/fuzz drives these adapters over the real ABI; these tests pin what the
// ASSEMBLER does with them — imports, type and function sections, exports and
// the dispatch of each body — which is where an off-by-one import index or a
// post-return on the wrong export would hide.

// patternResourceNames builds the resource name table for every find and groups
// export in entries, in the canonical form generate/ derives, so these tests do
// not need generate/ (which imports this package).
func patternResourceNames(entries []config.RegexEntry) map[string]ComponentPatternResource {
	const prefix = "regexped:test/matcher"
	out := map[string]ComponentPatternResource{}
	add := func(name string, groups bool) {
		if name == "" {
			return
		}
		k := strings.ReplaceAll(name, "_", "-")
		out[name] = ComponentPatternResource{
			Groups:         groups,
			Constructor:    prefix + "#[constructor]" + k,
			Next:           prefix + "#[method]" + k + ".next",
			Dtor:           prefix + "#[dtor]" + k,
			ResourceImport: "[export]" + prefix,
			ResourceNew:    "[resource-new]" + k,
		}
	}
	for _, e := range entries {
		add(e.FindFunc, false)
		add(e.GroupsFunc, true)
	}
	return out
}

// matchOnlyNames keeps the plain function names for the MATCH exports only:
// find and groups travel in the resource table.
func matchOnlyNames(entries []config.RegexEntry) map[string]string {
	names := map[string]string{}
	for _, e := range entries {
		if e.MatchFunc != "" {
			names[e.MatchFunc] = "regexped:test/matcher#" + strings.ReplaceAll(e.MatchFunc, "_", "-")
		}
	}
	return names
}

// TestComponentPatternResourcesAssembleAndValidate builds a single-pattern
// component with a match, a find resource and a groups resource, and checks the
// result is VALID WASM — the check that catches an import that shifted one call
// target but not another — and carries exactly the exports the WIT expects.
func TestComponentPatternResourcesAssembleAndValidate(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `[a-z]+`, MatchFunc: "lower_match"},
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "token_find"},
		{Pattern: `(?P<opt>x)?(?P<tail>y+)`, GroupsFunc: "opt_groups"},
	}
	wasm, _, err := Compile(entries, 0, true, CompileOptions{
		Component:                 true,
		ComponentPackage:          "regexped:test/matcher",
		ComponentExportNames:      matchOnlyNames(entries),
		ComponentPatternResources: patternResourceNames(entries),
	})
	if err != nil {
		t.Fatal(err)
	}
	validateWASM(t, wasm)

	s := string(wasm)
	for _, want := range []string{
		"regexped:test/matcher#lower-match",
		"cabi_post_regexped:test/matcher#lower-match",
		"regexped:test/matcher#[constructor]token-find",
		"regexped:test/matcher#[method]token-find.next",
		"cabi_post_regexped:test/matcher#[method]token-find.next",
		"regexped:test/matcher#[dtor]token-find",
		"regexped:test/matcher#[constructor]opt-groups",
		"regexped:test/matcher#[method]opt-groups.next",
		"regexped:test/matcher#[dtor]opt-groups",
		// One [resource-new] import per resource, from the synthetic module.
		"[export]regexped:test/matcher",
		"[resource-new]token-find",
		"[resource-new]opt-groups",
		// The raw exports are kept.
		"lower_match", "token_find", "opt_groups",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("module is missing %q", want)
		}
	}
	// A constructor returns a bare handle and a destructor nothing: giving
	// either a post-return would free the scanner's own state.
	for _, bad := range []string{
		"cabi_post_regexped:test/matcher#[constructor]token-find",
		"cabi_post_regexped:test/matcher#[dtor]token-find",
		"cabi_post_regexped:test/matcher#[constructor]opt-groups",
		"cabi_post_regexped:test/matcher#[dtor]opt-groups",
	} {
		if strings.Contains(s, bad) {
			t.Errorf("module exports %q, which must have no post-return", bad)
		}
	}
}

// TestSetComponentMixedWithPatternResources is the mixed config: a set with its
// own find resource beside a single pattern's find resource. Both kinds import a
// [resource-new] builtin, and the pattern ones come FIRST; a module that got the
// two orders wrong still assembles, and fails validation because an adapter
// calls the wrong import. The Reporter is non-nil so the set diagnostics reach it.
func TestSetComponentMixedWithPatternResources(t *testing.T) {
	cfg := setComponentCfg(3)
	cfg.Regexps[1].FindFunc = "token_find"
	resources := patternResourceNames(cfg.Regexps)
	rep := &Reporter{}
	core, _, err := CompileFileComponent(cfg, "regexped:test/matcher", nil, resources, setComponentNames("s"), rep)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	validateWASM(t, core)
	s := string(core)
	for _, want := range []string{
		"regexped:test/matcher#[constructor]token-find",
		"regexped:test/matcher#[method]token-find.next",
		"regexped:test/matcher#[dtor]token-find",
		"[resource-new]token-find",
		"regexped:t/sets#[constructor]scan-it",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("core module is missing %q", want)
		}
	}
	// The pattern resource's builtin is imported BEFORE the set's.
	if p, q := strings.Index(s, "[resource-new]token-find"), strings.Index(s, "[resource-new]scan-it"); p < 0 || q < 0 || p > q {
		t.Errorf("import order: pattern resource at %d, set resource at %d — the pattern ones must come first", p, q)
	}
	if len(rep.Sets) != 1 {
		t.Errorf("the Reporter holds %d set diagnostics, want 1 — --verbose would print no set section", len(rep.Sets))
	}
}

func TestAdapterKindNeedsPost(t *testing.T) {
	for kind, want := range map[adapterKind]bool{
		adapterMatch:         true,
		adapterFind:          true,
		adapterGroups:        true,
		adapterPatCtor:       false,
		adapterPatFindNext:   true,
		adapterPatGroupsNext: true,
		adapterPatDtor:       false,
	} {
		if got := kind.needsPost(); got != want {
			t.Errorf("adapterKind(%d).needsPost() = %v, want %v", kind, got, want)
		}
	}
}

func TestPatternAdapterBodyUnknownKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a function-shaped kind reached the resource dispatcher without a panic")
		}
	}()
	buildPatternAdapterBody(componentAdapter{kind: adapterMatch}, 0, 0, 0)
}

func TestPatRepSize(t *testing.T) {
	if got := patRepSize(false, 0); got != patRepBytes {
		t.Errorf("find representation = %d, want %d", got, patRepBytes)
	}
	if got, want := patRepSize(true, 3), int32(patRepBytes+3*slotPairLen); got != want {
		t.Errorf("groups representation with 3 groups = %d, want %d", got, want)
	}
}

// TestOrderedPatternResources pins the skips: no table at all, a name with no
// entry, and a name whose Groups flag contradicts the export it is attached to
// — each emits no resource rather than a mis-shaped one.
func TestOrderedPatternResources(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "token_find"},
		{Pattern: `(?P<opt>x)?y`, GroupsFunc: "opt_groups"},
	}
	compiled := compileForTest(t, entries)
	if got := orderedPatternResources(compiled, nil, 0); got != nil {
		t.Errorf("no table: got %d resources, want none", len(got))
	}
	res := patternResourceNames(entries)
	got := orderedPatternResources(compiled, res, 5)
	if len(got) != 2 || got[0].funcName != "token_find" || got[1].funcName != "opt_groups" {
		t.Fatalf("got %+v, want token_find then opt_groups", got)
	}
	if got[0].inner < 5 || got[1].numGroups == 0 {
		t.Errorf("find inner index %d (want past the offset 5), groups numGroups %d (want > 0)",
			got[0].inner, got[1].numGroups)
	}
	// Swap the Groups flags: neither export matches its entry's shape.
	flipped := map[string]ComponentPatternResource{}
	for k, v := range res {
		v.Groups = !v.Groups
		flipped[k] = v
	}
	if got := orderedPatternResources(compiled, flipped, 0); len(got) != 0 {
		t.Errorf("contradicting Groups flags: got %d resources, want none", len(got))
	}
}
