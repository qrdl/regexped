package compile

import (
	"errors"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
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

	got := componentAdapters(compiled, names)
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
	if got := componentAdapters(compiled, names); len(got) != 2 {
		t.Errorf("with one name missing, got %d adapters, want 2", len(got))
	}
	// No names at all: no adapters.
	if got := componentAdapters(compiled, nil); len(got) != 0 {
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

// The allocator and post-return are emitted from one place and reference the
// heap global only through it, so a future async allocator can be swapped in
// without touching the adapters.
func TestComponentAllocatorBodies(t *testing.T) {
	realloc := buildComponentReallocBody(1)
	if len(realloc) == 0 {
		t.Fatal("empty cabi_realloc body")
	}
	// One i32 local group, then the body; the last byte closes the function.
	if realloc[0] != 0x01 || realloc[len(realloc)-1] != 0x0B {
		t.Errorf("unexpected body framing: % x … %#x", realloc[:3], realloc[len(realloc)-1])
	}
	post := buildComponentPostBody(1, 0x30000)
	if post[0] != 0x00 {
		t.Error("the post-return needs no locals")
	}
	if post[len(post)-1] != 0x0B {
		t.Error("the post-return body must close")
	}
	// The static top must appear as an i32.const in the reset.
	if !strings.Contains(string(post), "\x41") {
		t.Error("no i32.const in the post-return body")
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
	got := o.asmOpts()
	if !got.Component || got.ComponentPackage != o.ComponentPackage || got.ExportNames["f"] != names["f"] {
		t.Errorf("projection lost something: %+v", got)
	}
	if (CompileOptions{}).asmOpts().Component {
		t.Error("a plain CompileOptions must project to module")
	}
}
