package fuzz

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/component"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/internal/abi"
)

// The SET adapters of `wasm_format: component`, driven directly.
//
// Every canonical export is also a RAW core export (the core module keeps them
// so `wasm-tools component unbundle` yields something the module-path harnesses
// can drive), so these tests instantiate the CORE module and call the adapters
// by their canonical names. No component runtime is involved, which is why this
// can live in Go: wasmtime-go has no component API.
//
// The one thing a bare core module cannot supply is the `[resource-new]` canon
// builtin the scanner's constructor calls. It is stubbed with a host function
// that returns its argument, which is exactly what the real builtin does as far
// as the guest can observe: hand back a handle the guest then passes to `next`.
// The REAL builtin returns an opaque handle index, and the component runtime
// translates it back to the representation before calling a method — so passing
// the representation straight through models the round trip faithfully.
//
// What this covers that nothing else does: the id-list conversion in both `_all`
// widths, the resource's drive and its advance rule, two scanners in flight, and
// that a dropped scanner's state is actually reclaimed.

type setHarness struct {
	t     *testing.T
	store *wasmtime.Store
	inst  *wasmtime.Instance
	mem   *wasmtime.Memory
	pkg   string
}

// newSetHarness compiles cfgYAML as a component core module and instantiates it.
func newSetHarness(t *testing.T, cfgYAML string) *setHarness {
	t.Helper()
	var cfg config.BuildConfig
	if err := yaml.Unmarshal([]byte(cfgYAML), &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	core, _, err := component.Core(cfg, nil)
	if err != nil {
		t.Fatalf("component core: %v", err)
	}
	store, inst, mem := instantiateCore(t, core)
	return &setHarness{t: t, store: store, inst: inst, mem: mem, pkg: "regexped:t/sets"}
}

// instantiateCore instantiates a component CORE module in the shared engine and
// returns its store, instance and exported memory. Each function import is
// supplied as a [resource-new] stand-in that hands back its argument, which is
// what the real builtin does as far as the guest can observe (see above); a
// core with no imports gets none. The epoch deadline is set far out: the shared
// engine interrupts a store with no deadline immediately, and these are adapter
// and allocator calls, not pattern drives, so there is nothing to time out.
func instantiateCore(t *testing.T, core []byte) (*wasmtime.Store, *wasmtime.Instance, *wasmtime.Memory) {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, core)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1 << 40)
	var externs []wasmtime.AsExtern
	for _, imp := range mod.Imports() {
		if imp.Type().FuncType() == nil {
			t.Fatalf("unexpected non-function import %v", imp.Name())
		}
		externs = append(externs, wasmtime.WrapFunc(store, func(rep int32) int32 { return rep }))
	}
	inst, err := wasmtime.NewInstance(store, mod, externs)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		t.Fatal("component core module does not export its memory")
	}
	return store, inst, memExp.Memory()
}

func (h *setHarness) fn(name string) *wasmtime.Func {
	h.t.Helper()
	f := h.inst.GetFunc(h.store, name)
	if f == nil {
		h.t.Fatalf("core module has no export %q", name)
	}
	return f
}

// writeInput lowers an input the way the canonical ABI would: allocate through
// cabi_realloc, then copy the bytes in.
func (h *setHarness) writeInput(s string) (ptr, length int32) {
	h.t.Helper()
	r, err := h.fn("cabi_realloc").Call(h.store, int32(0), int32(0), int32(1), int32(len(s)))
	if err != nil {
		h.t.Fatalf("lower input: %v", err)
	}
	ptr = r.(int32)
	copy(h.mem.UnsafeData(h.store)[ptr:], s)
	return ptr, int32(len(s))
}

func (h *setHarness) u32(addr int32) uint32 {
	return binary.LittleEndian.Uint32(h.mem.UnsafeData(h.store)[addr:])
}

// option reads a result<option<u32>, error-code> area.
func (h *setHarness) option(ret int32) (val uint32, some, errored bool) {
	data := h.mem.UnsafeData(h.store)
	if data[ret] == 1 {
		return 0, false, true
	}
	if data[ret+4] == 0 {
		return 0, false, false
	}
	return h.u32(ret + 8), true, false
}

// list reads a result<list<u32>, error-code> area into a slice of ids.
func (h *setHarness) list(ret int32) ([]uint32, bool) {
	data := h.mem.UnsafeData(h.store)
	if data[ret] == 1 {
		return nil, true
	}
	ptr := int32(h.u32(ret + 4))
	n := int32(h.u32(ret + 8))
	out := make([]uint32, 0, n)
	for i := int32(0); i < n; i++ {
		out = append(out, h.u32(ptr+i*4))
	}
	return out, false
}

// matches reads a result<list<set-match>, error-code> area. The raw find tuple
// layout IS the record layout, which is the point of the adapter not converting.
func (h *setHarness) matches(ret int32) ([][3]uint32, bool) {
	data := h.mem.UnsafeData(h.store)
	if data[ret] == 1 {
		return nil, true
	}
	ptr := int32(h.u32(ret + 4))
	n := int32(h.u32(ret + 8))
	var out [][3]uint32
	for i := int32(0); i < n; i++ {
		base := ptr + i*12
		out = append(out, [3]uint32{h.u32(base), h.u32(base + 4), h.u32(base + 8)})
	}
	return out, false
}

func (h *setHarness) call(name string, args ...any) int32 {
	h.t.Helper()
	r, err := h.fn(name).Call(h.store, args...)
	if err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	if r == nil {
		return 0
	}
	return r.(int32)
}

// drain runs a scanner to exhaustion through the resource's own methods.
func (h *setHarness) drain(res string, input string, start int32) [][3]uint32 {
	h.t.Helper()
	ptr, n := h.writeInput(input)
	handle := h.call(h.pkg+"#[constructor]"+res, ptr, n, start)
	var all [][3]uint32
	for {
		ret := h.call(h.pkg+"#[method]"+res+".next", handle)
		got, errored := h.matches(ret)
		if errored {
			h.t.Fatalf("next reported an error")
		}
		if len(got) == 0 {
			break
		}
		all = append(all, got...)
		// The post-return takes the retptr, and running it is not optional: it
		// is what frees the call's blocks.
		h.call("cabi_post_"+h.pkg+"#[method]"+res+".next", ret)
	}
	h.call(h.pkg+"#[dtor]"+res, handle)
	return all
}

const narrowSetCfg = `
wasm_format: component
wit_package: t
import_module: t
regexps:
  - pattern: 'ghp_[A-Za-z0-9]{4}'
  - pattern: 'AKIA[A-Z0-9]{6}'
  - pattern: '[0-9]{3}-[0-9]{2}'
sets:
  - name: s
    patterns: all
    match_any: which_matches
    match_all: all_matches
    scan_any: any_hit
    scan_all: all_hits
    find: scan_it
`

// TestComponentSetCapabilities drives all five capabilities of a narrow set —
// three patterns, so `_all` compiles to the i64 bitmask form.
func TestComponentSetCapabilities(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	const text = "ghp_ab12 AKIAZZZZZZ 123-45"

	// Anchored: the whole input is not any single pattern.
	ptr, n := h.writeInput(text)
	_, some, errored := h.option(h.call(h.pkg+"#which-matches", ptr, n))
	if some || errored {
		t.Errorf("match_any on a non-matching whole input: some=%v err=%v", some, errored)
	}
	if ids, _ := h.list(h.call(h.pkg+"#all-matches", ptr, n)); len(ids) != 0 {
		t.Errorf("match_all = %v, want none", ids)
	}

	// Anchored against exactly one pattern's own text.
	p1, n1 := h.writeInput("ghp_ab12")
	id, some, _ := h.option(h.call(h.pkg+"#which-matches", p1, n1))
	if !some || id != 0 {
		t.Errorf("match_any = (%d, some=%v), want some(0)", id, some)
	}
	if ids, _ := h.list(h.call(h.pkg+"#all-matches", p1, n1)); len(ids) != 1 || ids[0] != 0 {
		t.Errorf("match_all = %v, want [0]", ids)
	}

	// Non-anchored, with `start` bounding the search.
	for _, c := range []struct {
		from int32
		want []uint32
	}{
		{0, []uint32{0, 1, 2}},
		{9, []uint32{1, 2}},
		{20, []uint32{2}},
		{25, nil},
		{999, nil}, // start > len is "nothing found", not an error
	} {
		got, errored := h.list(h.call(h.pkg+"#all-hits", ptr, n, c.from))
		if errored {
			t.Fatalf("scan_all(from=%d) reported an error", c.from)
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("scan_all(from=%d) = %v, want %v", c.from, got, c.want)
		}
	}
	if _, some, _ := h.option(h.call(h.pkg+"#any-hit", ptr, n, int32(0))); !some {
		t.Error("scan_any found nothing in an input with three matches")
	}

	// find, through the resource.
	got := h.drain("scan-it", text, 0)
	want := [][3]uint32{{0, 0, 8}, {1, 9, 19}, {2, 20, 26}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("find drive = %v, want %v", got, want)
	}
	// Resuming mid-input skips what is behind it.
	if got := h.drain("scan-it", text, 9); fmt.Sprint(got) != fmt.Sprint(want[1:]) {
		t.Errorf("find drive from 9 = %v, want %v", got, want[1:])
	}
	// An empty input is legitimate and finishes immediately.
	if got := h.drain("scan-it", "", 0); len(got) != 0 {
		t.Errorf("find over an empty input = %v, want nothing", got)
	}
}

// TestComponentSetScannersAreIndependent: two live handles must not share state.
// The module-format C scanner is caller-owned and has that property; a component
// resource has to earn it, since its state lives in OUR memory.
func TestComponentSetScannersAreIndependent(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	const text = "ghp_ab12 AKIAZZZZZZ 123-45"
	pa, na := h.writeInput(text)
	pb, nb := h.writeInput(text)
	a := h.call(h.pkg+"#[constructor]scan-it", pa, na, int32(0))
	b := h.call(h.pkg+"#[constructor]scan-it", pb, nb, int32(9))
	if a == b {
		t.Fatal("two constructors returned the same handle")
	}
	fa, _ := h.matches(h.call(h.pkg+"#[method]scan-it.next", a))
	fb, _ := h.matches(h.call(h.pkg+"#[method]scan-it.next", b))
	if len(fa) == 0 || len(fb) == 0 {
		t.Fatalf("a scanner reported nothing: a=%v b=%v", fa, fb)
	}
	if fa[0][1] != 0 || fb[0][1] != 9 {
		t.Errorf("interleaved scanners: a started at %d, b at %d; want 0 and 9", fa[0][1], fb[0][1])
	}
	h.call(h.pkg+"#[dtor]scan-it", a)
	h.call(h.pkg+"#[dtor]scan-it", b)
}

// TestComponentSetScannerReclaimsItsState is the allocator property at the
// RESOURCE level. The constructor detaches its blocks from the call chain — they
// outlive the call — so the destructor is the only thing that can give them
// back. A missing or wrong dtor leaks per scan, which is exactly what a bump
// allocator could not avoid and why the free lists exist.
func TestComponentSetScannerReclaimsItsState(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	const text = "ghp_ab12 AKIAZZZZZZ 123-45"
	cycle := func() {
		ptr, n := h.writeInput(text)
		handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
		ret := h.call(h.pkg+"#[method]scan-it.next", handle)
		h.call("cabi_post_"+h.pkg+"#[method]scan-it.next", ret)
		h.call(h.pkg+"#[dtor]scan-it", handle)
	}
	for i := 0; i < 50; i++ { // let the classes fill
		cycle()
	}
	before := len(h.mem.UnsafeData(h.store))
	for i := 0; i < 5000; i++ {
		cycle()
	}
	if after := len(h.mem.UnsafeData(h.store)); after != before {
		t.Errorf("memory grew over 5000 scanner lifecycles: %d → %d bytes (+%d)",
			before, after, after-before)
	}
}

// TestComponentSetWideAll covers the OTHER `_all` ABI: above 64 patterns the
// body ORs bits into a caller-owned bitmap and returns a count, so the adapter
// has to allocate that bitmap, ZERO it, and convert the bits to ids.
//
// The zeroing is the part worth a test of its own: the allocator hands back
// reused memory and the body only ORs, so a stale bitmap reports ids from an
// earlier call. The loop below alternates answers for exactly that reason.
func TestComponentSetWideAll(t *testing.T) {
	cfg := "\nwasm_format: component\nwit_package: t\nimport_module: t\nregexps:\n"
	for i := 0; i < 70; i++ {
		cfg += fmt.Sprintf("  - pattern: 'kw%03d[a-z]{2}'\n", i)
	}
	cfg += "sets:\n  - name: s\n    patterns: all\n    match_all: all_matches\n    scan_all: all_hits\n    find: scan_it\n"
	h := newSetHarness(t, cfg)

	const text = "kw003xy and kw041pq and kw069zz"
	ptr, n := h.writeInput(text)
	if got, _ := h.list(h.call(h.pkg+"#all-hits", ptr, n, int32(0))); fmt.Sprint(got) != "[3 41 69]" {
		t.Errorf("wide scan_all = %v, want [3 41 69]", got)
	}
	if got, _ := h.list(h.call(h.pkg+"#all-hits", ptr, n, int32(12))); fmt.Sprint(got) != "[41 69]" {
		t.Errorf("wide scan_all(from=12) = %v, want [41 69]", got)
	}

	one, oneN := h.writeInput("kw069zz")
	if got, _ := h.list(h.call(h.pkg+"#all-matches", one, oneN)); fmt.Sprint(got) != "[69]" {
		t.Errorf("wide match_all = %v, want [69]", got)
	}

	// Alternate the answers: a bitmap not zeroed per call would accumulate.
	for i := 0; i < 300; i++ {
		r1 := h.call(h.pkg+"#all-hits", one, oneN, int32(0))
		if got, _ := h.list(r1); fmt.Sprint(got) != "[69]" {
			t.Fatalf("iteration %d: %v, want [69] — a stale bitmap?", i, got)
		}
		h.call("cabi_post_"+h.pkg+"#all-hits", r1)
		r2 := h.call(h.pkg+"#all-hits", ptr, n, int32(0))
		if got, _ := h.list(r2); fmt.Sprint(got) != "[3 41 69]" {
			t.Fatalf("iteration %d: %v, want [3 41 69]", i, got)
		}
		h.call("cabi_post_"+h.pkg+"#all-hits", r2)
	}

	got := h.drain("scan-it", text, 0)
	want := [][3]uint32{{3, 0, 7}, {41, 12, 19}, {69, 24, 31}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("wide find drive = %v, want %v", got, want)
	}
}

// TestComponentNarrowAllReportsBit63: a narrow `_all` answer whose mask equals
// the Backtracking sentinel's bit pattern — ids 1..63 matched, id 0 did not, so
// the i64 is -2 — is a LEGAL answer. The narrow form is emitted only for a set
// with no Backtracking member (one selects the wide form), so its export cannot
// return the sentinel at all, and the adapter used to turn this mask into
// err(backtrack-overflow).
func TestComponentNarrowAllReportsBit63(t *testing.T) {
	cfg := "\nwasm_format: component\nwit_package: t\nimport_module: t\nregexps:\n  - pattern: 'zzz'\n"
	for i := 1; i < 64; i++ {
		cfg += fmt.Sprintf("  - pattern: 'a{1,%d}'\n", i)
	}
	cfg += "sets:\n  - name: s\n    patterns: all\n    match_all: all_matches\n    scan_all: all_hits\n"
	h := newSetHarness(t, cfg)
	want := make([]uint32, 0, 63)
	for i := uint32(1); i < 64; i++ {
		want = append(want, i)
	}
	ptr, n := h.writeInput("a")
	matchRet := h.call(h.pkg+"#all-matches", ptr, n)
	scanRet := h.call(h.pkg+"#all-hits", ptr, n, int32(0))
	for _, c := range []struct {
		name string
		ret  int32
	}{{"match_all", matchRet}, {"scan_all", scanRet}} {
		got, errored := h.list(c.ret)
		if errored {
			t.Errorf("%s over \"a\" reported an error; the mask of ids 1..63 is -2 and is a legal answer", c.name)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want ids 1..63", c.name, got)
		}
	}

	// And the ordinary case beside it: one pattern of two matching, mask 2.
	h2 := newSetHarness(t, "\nwasm_format: component\nwit_package: t\nimport_module: t\nregexps:\n"+
		"  - pattern: 'zzz'\n  - pattern: 'a'\nsets:\n  - name: s\n    patterns: all\n"+
		"    match_all: all_matches\n    scan_all: all_hits\n")
	p2, n2 := h2.writeInput("a")
	if got, errored := h2.list(h2.call(h2.pkg+"#all-matches", p2, n2)); errored || fmt.Sprint(got) != "[1]" {
		t.Errorf("match_all over a two-pattern set = %v (errored=%v), want [1]", got, errored)
	}
	if got, errored := h2.list(h2.call(h2.pkg+"#all-hits", p2, n2, int32(0))); errored || fmt.Sprint(got) != "[1]" {
		t.Errorf("scan_all over a two-pattern set = %v (errored=%v), want [1]", got, errored)
	}
}

// The component allocator's properties.
//
// `wasm_format: component` allocates through an emitted `cabi_realloc` backed by
// segregated free lists, and frees through the shared post-return, which walks
// the chain every allocation joins (compile/component.go). A behaviour table
// cannot see a defect in that: a component answers correctly right up to the
// point it exhausts memory, and the exhaustion is what a user hits in
// production rather than in a test.
//
// So these tests drive the allocator DIRECTLY, on the emitted core module rather
// than the wrapped component: `cabi_realloc` and the post-return are both raw
// core exports (the post-return under `cabi_post_<export>`), so wasmtime-go can
// call them without any component-model support.
//
// They exist because a proof of concept measured, in a hand-written equivalent,
// two leaks a bump allocator could not avoid: 82 MB over 20,000 dropped handles,
// and 82 MB over 20,000 stateless calls whose lowered input a mark taken at
// function entry came too late to cover. The high-water-mark test below is the
// standing gate on both.

// allocHarness instantiates the core module of a one-pattern component and
// exposes its allocator.
type allocHarness struct {
	t     *testing.T
	store *wasmtime.Store
	mem   *wasmtime.Memory
	alloc *wasmtime.Func
	post  *wasmtime.Func
}

func newAllocHarness(t *testing.T) *allocHarness {
	t.Helper()
	entries := []config.RegexEntry{{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "token_find"}}
	core, _, err := compile.Compile(entries, 0, true, compile.CompileOptions{
		Component:            true,
		ComponentPackage:     "regexped:t/matcher",
		ComponentExportNames: map[string]string{"token_find": "token-find"},
	})
	if err != nil {
		t.Fatalf("compile component core: %v", err)
	}
	store, inst, mem := instantiateCore(t, core)
	h := &allocHarness{t: t, store: store, mem: mem}
	h.alloc = inst.GetFunc(store, "cabi_realloc")
	h.post = inst.GetFunc(store, "cabi_post_token-find")
	if h.alloc == nil || h.post == nil {
		t.Fatalf("core module is missing cabi_realloc or the post-return")
	}
	return h
}

func (h *allocHarness) call(size, align int32) int32 {
	h.t.Helper()
	r, err := h.alloc.Call(h.store, int32(0), int32(0), align, size)
	if err != nil {
		h.t.Fatalf("cabi_realloc(size=%d, align=%d): %v", size, align, err)
	}
	return r.(int32)
}

// freeAll runs the post-return, which is what a component call's cleanup is.
func (h *allocHarness) freeAll() {
	h.t.Helper()
	if _, err := h.post.Call(h.store, int32(0)); err != nil {
		h.t.Fatalf("post-return: %v", err)
	}
}

func (h *allocHarness) memBytes() int { return len(h.mem.UnsafeData(h.store)) }

// TestComponentAllocReturnsUsableMemory: every pointer handed out must be
// 8-aligned and wholly inside memory. A misaligned or out-of-bounds result area
// is not a wrong answer — the HOST reads through that pointer.
func TestComponentAllocReturnsUsableMemory(t *testing.T) {
	h := newAllocHarness(t)
	for _, size := range []int32{0, 1, 4, 8, 12, 13, 16, 17, 64, 1000, 4096, 65536, 200000} {
		for _, align := range []int32{1, 2, 4, 8} {
			p := h.call(size, align)
			if p <= 0 {
				t.Fatalf("size=%d align=%d: got pointer %d", size, align, p)
			}
			if p%8 != 0 {
				t.Errorf("size=%d align=%d: pointer %d is not 8-aligned", size, align, p)
			}
			if int(p)+int(size) > h.memBytes() {
				t.Errorf("size=%d: block [%d,%d) is outside memory of %d bytes",
					size, p, int(p)+int(size), h.memBytes())
			}
			// The two header words must be inside memory too: the allocator
			// writes the class and the chain link there.
			if p < 8 {
				t.Errorf("pointer %d leaves no room for the block header", p)
			}
		}
	}
}

// TestComponentAllocBlocksNeverOverlap: two LIVE allocations must be disjoint,
// including their headers. This is the property that a class computed one bit
// wrong would break — and it would break silently, as one call's result area
// quietly overwriting another's.
func TestComponentAllocBlocksNeverOverlap(t *testing.T) {
	h := newAllocHarness(t)
	type span struct{ lo, hi int }
	var live []span
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		size := int32(rng.Intn(3000) + 1)
		p := h.call(size, 4)
		// The header occupies the 8 bytes below the payload.
		live = append(live, span{int(p) - 8, int(p) + int(size)})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].lo < live[j].lo })
	for i := 1; i < len(live); i++ {
		if live[i].lo < live[i-1].hi {
			t.Fatalf("live blocks overlap: [%d,%d) and [%d,%d)",
				live[i-1].lo, live[i-1].hi, live[i].lo, live[i].hi)
		}
	}
}

// TestComponentAllocHighWaterMarkIsFlat is THE test. A repeated identical call
// must not grow memory: the post-return returns its blocks to their classes and
// the next call reuses them. A bump allocator passes the first iteration and
// fails this one, which is precisely the defect that made the free lists
// necessary.
func TestComponentAllocHighWaterMarkIsFlat(t *testing.T) {
	h := newAllocHarness(t)
	cycle := func() {
		// The shape of a real call: the host lowers a 4 KB input, the adapter
		// allocates a result area, then the post-return frees both.
		h.call(4096, 1)
		h.call(16, 4)
		h.freeAll()
	}
	for i := 0; i < 50; i++ { // warm up: let the classes fill
		cycle()
	}
	before := h.memBytes()
	for i := 0; i < 20000; i++ {
		cycle()
	}
	if after := h.memBytes(); after != before {
		t.Errorf("memory grew over 20000 identical cycles: %d → %d bytes (+%d)",
			before, after, after-before)
	}
}

// TestComponentAllocReusesFreedBlocks pins reuse directly rather than through
// the memory size: the same request after a free must come back at the same
// address. Without it "flat" could be satisfied by an allocator that grows
// memory in huge steps and merely has not needed a second step yet.
func TestComponentAllocReusesFreedBlocks(t *testing.T) {
	h := newAllocHarness(t)
	first := h.call(100, 4)
	h.freeAll()
	again := h.call(100, 4)
	if again != first {
		t.Errorf("a freed block was not reused: %d then %d", first, again)
	}
	// Same class, different size: 100 and 120 both land in the 128-byte class,
	// so the block is still the right one to hand back.
	h.freeAll()
	sameClass := h.call(120, 4)
	if sameClass != first {
		t.Errorf("a block of the same class was not reused: %d then %d", first, sameClass)
	}
}

// TestComponentAllocSurvivesMixedSizes: varying sizes must not corrupt the
// class lists. A block freed into the wrong class would be handed out later for
// a request too large for it, and the overflow would land in the next block.
func TestComponentAllocSurvivesMixedSizes(t *testing.T) {
	h := newAllocHarness(t)
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 2000; i++ {
		n := rng.Intn(4) + 1
		var ptrs []int32
		var sizes []int32
		for j := 0; j < n; j++ {
			size := int32(rng.Intn(5000) + 1)
			p := h.call(size, 4)
			ptrs = append(ptrs, p)
			sizes = append(sizes, size)
		}
		// Write a byte pattern into every payload, then verify it: a block
		// handed out twice, or sized too small for its class, shows up here.
		data := h.mem.UnsafeData(h.store)
		for j, p := range ptrs {
			for k := int32(0); k < sizes[j]; k++ {
				data[int(p)+int(k)] = byte(j + 1)
			}
		}
		for j, p := range ptrs {
			for k := int32(0); k < sizes[j]; k++ {
				if data[int(p)+int(k)] != byte(j+1) {
					t.Fatalf("block %d (size %d) was overwritten at offset %d", j, sizes[j], k)
				}
			}
		}
		h.freeAll()
	}
}

// TestCabiReallocTrapsOnHugeSizes: a size the size classes cannot represent
// must TRAP. The class was 32 - clz(new_size + 7) with no upper bound, so near
// 2 GiB it named a class whose carve wrapped, and 0xFFFFFFF0 / 0xFFFFFFFF
// wrapped the + 7 itself: each returned a pointer — one of them inside the DFA
// table — and the next carve overlapped live data. Only a host lowering a list
// of 2 GiB or more reaches it, and that copy traps anyway, but the allocator's
// state was corrupted before it did.
func TestCabiReallocTrapsOnHugeSizes(t *testing.T) {
	for _, size := range []uint32{0x7FFFFFF9, 0x7FFFFFFF, 0xFFFFFFF0, 0xFFFFFFFF} {
		// A fresh instance each time: a trap may leave the last one unusable.
		h := newAllocHarness(t)
		if r, err := h.alloc.Call(h.store, int32(0), int32(0), int32(8), int32(size)); err == nil {
			t.Errorf("cabi_realloc(size=0x%X) returned %v; want a trap", size, r)
		}
	}
	// The boundary itself still allocates: the largest request whose block fits
	// the top class.
	h := newAllocHarness(t)
	if _, err := h.alloc.Call(h.store, int32(0), int32(0), int32(8), int32(0x7FFFFFF0-8)); err != nil {
		t.Errorf("cabi_realloc(size=0x%X), the largest size the classes hold, trapped: %v", 0x7FFFFFF0-8, err)
	}
}

// TestCabiReallocTrapsWhenTheCarveWrapsTheAddressSpace: the size guard bounds a
// SINGLE carve at 2 GiB, so no one request can wrap `heap + (1 << class)` — two
// of them can. The second block of the top class computes an end past 4 GiB,
// which comes back as a LOW address: it passes the unsigned fit check, skips the
// grow, and resets the bump pointer to near zero, where the next carve overlaps
// the DFA table. Silent corruption rather than the exhaustion trap it must be.
func TestCabiReallocTrapsWhenTheCarveWrapsTheAddressSpace(t *testing.T) {
	const top = int32(0x7FFFFFF0 - 8) // the largest size the classes hold
	h := newAllocHarness(t)
	if _, err := h.alloc.Call(h.store, int32(0), int32(0), int32(8), top); err != nil {
		t.Skipf("the first 2 GiB block could not be allocated here: %v", err)
	}
	if r, err := h.alloc.Call(h.store, int32(0), int32(0), int32(8), top); err == nil {
		t.Errorf("the second 2 GiB carve returned %v; want a trap on the wrap", r)
	}
}

// The canonical-ABI adapters are ordinary core functions — `(ptr,len[,start])
// → retptr` — so they can be driven directly, without a Component Model
// runtime. That matters for two things the `wasmtime run --invoke` path cannot
// reach:
//
//   - the -2 (BTStackOverflow) arm, which needs a squeezed compile and a 60 KB
//     input, impossible to express as a WAVE list on a command line;
//   - the post-return reset, since --invoke gives every call a fresh instance
//     and so can never show a leak.
//
// Result-area layouts follow the canonical ABI and are asserted here by
// reading the bytes back.

// componentWasm compiles entries as a component core module and returns the
// bytes plus the canonical export name for each configured func name.
func componentWasm(t *testing.T, entries []config.RegexEntry, opts compile.CompileOptions) ([]byte, map[string]string, map[string]generate.PatternResourceNames) {
	t.Helper()
	cfg := config.BuildConfig{WasmFormat: "component", ImportModule: "regexps", Regexps: entries}
	_, names, resources, _, prefix, err := generate.ComponentArtifactsWithSets(cfg)
	if err != nil {
		t.Fatalf("component artifacts: %v", err)
	}
	opts.Component = true
	opts.ComponentPackage = prefix
	opts.ComponentExportNames = names
	// find and groups are RESOURCES, so their names travel in this second table.
	// A build without it emits no constructor and no `next` for them.
	compiled := map[string]compile.ComponentPatternResource{}
	for k, v := range resources {
		compiled[k] = compile.ComponentPatternResource{
			Groups: v.Groups, Constructor: v.Constructor, Next: v.Next, Dtor: v.Dtor,
			ResourceImport: v.ResourceImport, ResourceNew: v.ResourceNew,
		}
	}
	opts.ComponentPatternResources = compiled
	w, _, err := compile.Compile(entries, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return w, names, resources
}

// adapterResult is one decoded result area.
type adapterResult struct {
	err      bool // result discriminant: true = err(backtrack-overflow)
	some     bool // option discriminant
	a, b     uint32
	retptr   uint32
	memPages uint32
}

func TestComponentAdaptersOverTheRealABI(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `[a-z]+`, MatchFunc: "m"},
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "f"},
		{Pattern: `(?P<opt>x)?y`, GroupsFunc: "g"},
	}
	w, names, res := componentWasm(t, entries, compile.CompileOptions{})
	// instantiateCore, not instantiate: every find and groups resource imports a
	// `[resource-new]` builtin, which instantiateCore supplies as the identity
	// function — what the real builtin does as far as the guest can observe.
	store, inst, mem := instantiateCore(t, w)

	fn := func(export string) *wasmtime.Func {
		t.Helper()
		f := inst.GetFunc(store, export)
		if f == nil {
			t.Fatalf("no %q export", export)
		}
		return f
	}
	i32 := func(r any, err error) int32 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r.(int32)
	}
	u32 := func(addr uint32) uint32 { return binary.LittleEndian.Uint32(mem.UnsafeData(store)[addr:]) }

	call := func(export, input string, extra ...int32) adapterResult {
		t.Helper()
		buf := mem.UnsafeData(store)
		copy(buf[pathsInputBase:], input)
		args := []any{any(int32(pathsInputBase)), any(int32(len(input)))}
		for _, e := range extra {
			args = append(args, any(e))
		}
		ret := uint32(i32(fn(export).Call(store, args...)))
		buf = mem.UnsafeData(store)
		r := adapterResult{
			retptr:   ret,
			err:      buf[ret] == 1,
			some:     buf[ret+4] == 1,
			memPages: uint32(mem.Size(store) / 65536),
		}
		r.a = u32(ret + 8)
		r.b = u32(ret + 12)
		return r
	}
	// construct lowers the input to the static input window and builds a
	// scanner. The constructor does not find that block at the head of the
	// per-call chain, so it takes its COPY path; the take-over path is pinned by
	// the constructor tests further down.
	construct := func(r generate.PatternResourceNames, input string, start int32) int32 {
		t.Helper()
		copy(mem.UnsafeData(store)[pathsInputBase:], input)
		return i32(fn(r.Constructor).Call(store, int32(pathsInputBase), int32(len(input)), start))
	}
	next := func(r generate.PatternResourceNames, handle int32) uint32 {
		t.Helper()
		return uint32(i32(fn(r.Next).Call(store, handle)))
	}
	// drop runs the destructor, which returns NOTHING — so its result is not an
	// int32 and must not go through i32.
	drop := func(r generate.PatternResourceNames, handle int32) {
		t.Helper()
		if _, err := fn(r.Dtor).Call(store, handle); err != nil {
			t.Fatalf("%s: %v", r.Dtor, err)
		}
	}
	// find's next: result<option<tuple<u32,u32>>, error-code>, 16 bytes.
	readFind := func(ret uint32) adapterResult {
		b := mem.UnsafeData(store)
		return adapterResult{retptr: ret, err: b[ret] == 1, some: b[ret+4] == 1,
			a: u32(ret + 8), b: u32(ret + 12), memPages: uint32(mem.Size(store) / 65536)}
	}

	t.Run("match", func(t *testing.T) {
		got := call(names["m"], "abc")
		if got.err || !got.some || got.a != 3 {
			t.Errorf("m(abc) = %+v, want ok(some(3))", got)
		}
		if got := call(names["m"], "ABC"); got.err || got.some {
			t.Errorf("m(ABC) = %+v, want ok(none)", got)
		}
	})

	t.Run("find", func(t *testing.T) {
		const in = "xxghp_ab12yy"
		f := res["f"]
		h := construct(f, in, 0)
		if got := readFind(next(f, h)); got.err || !got.some || got.a != 2 || got.b != 10 {
			t.Errorf("next over %q from 0 = %+v, want ok(some((2,10)))", in, got)
		}
		if got := readFind(next(f, h)); got.err || got.some {
			t.Errorf("second next = %+v, want ok(none): the scan has one match", got)
		}
		drop(f, h)
		// Started beyond any match, at len, and past len: all ok(none), no trap.
		for _, start := range []int32{3, int32(len(in)), int32(len(in)) + 1} {
			h := construct(f, in, start)
			if got := readFind(next(f, h)); got.err || got.some {
				t.Errorf("next over %q from %d = %+v, want ok(none)", in, start, got)
			}
			drop(f, h)
		}
	})

	t.Run("groups with an unset group", func(t *testing.T) {
		g := res["g"]
		// groups' next: result<list<option<tuple<u32,u32>>>, error-code> —
		// @0 disc, @4 list ptr, @8 list len — and an EMPTY list is "finished".
		readList := func(ret uint32) (ptr, n uint32, errored bool) {
			return u32(ret + 4), u32(ret + 8), mem.UnsafeData(store)[ret] == 1
		}
		// "xy": both groups participate.
		h := construct(g, "xy", 0)
		ptr, n, errored := readList(next(g, h))
		if errored || n != 2 {
			t.Fatalf("next over %q = (%d elements, errored %v), want a list of 2", "xy", n, errored)
		}
		b := mem.UnsafeData(store)
		if b[ptr] != 1 || u32(ptr+4) != 0 || u32(ptr+8) != 2 {
			t.Errorf("group 0 over %q = %v, want some((0,2))", "xy", b[ptr:ptr+12])
		}
		if b[ptr+12] != 1 {
			t.Errorf("group 1 over %q must be some", "xy")
		}
		if _, n, errored := readList(next(g, h)); errored || n != 0 {
			t.Errorf("second next over %q = (%d elements, errored %v), want an empty list", "xy", n, errored)
		}
		drop(g, h)

		// "y": the optional group is UNSET, and must be `none` — the element
		// path a happy-path test never reaches.
		h = construct(g, "y", 0)
		ptr, n, errored = readList(next(g, h))
		if errored || n != 2 {
			t.Fatalf("next over %q = (%d elements, errored %v)", "y", n, errored)
		}
		b = mem.UnsafeData(store)
		if b[ptr] != 1 {
			t.Errorf("group 0 over %q must be some", "y")
		}
		if b[ptr+12] != 0 {
			t.Errorf("group 1 disc over %q = %d, want 0 (none)", "y", b[ptr+12])
		}
		drop(g, h)
	})

	// A full scanner lifecycle — construct, next, post-return, destroy — repeated
	// a thousand times must be FLAT: the same result area every time and no
	// memory growth. The post-return returns next's result area to its class's
	// free list and the destructor returns the scanner's state and input copy, so
	// every iteration pops exactly the blocks the previous one pushed. Drop either
	// and a block is carved fresh each time, which moves the retptr.
	t.Run("post-return reset", func(t *testing.T) {
		f := res["f"]
		post := fn("cabi_post_" + f.Next)
		// Prime one reset first. The subtests above ran on this same store
		// without ever calling the post-return, so blocks are still on the
		// per-call chain; a baseline taken before freeing them would differ from
		// every later iteration for that reason alone. The post-return ignores
		// its argument — it frees whatever is on the chain — so 0 is a fine
		// retptr here.
		if _, err := post.Call(store, any(int32(0))); err != nil {
			t.Fatalf("priming post: %v", err)
		}
		var baseRetptr, basePages uint32
		for i := 0; i < 1000; i++ {
			h := construct(f, "xxghp_ab12yy", 0)
			got := readFind(next(f, h))
			if !got.some || got.a != 2 || got.b != 10 {
				t.Fatalf("iteration %d answered %+v, want ok(some((2,10)))", i, got)
			}
			if i == 0 {
				baseRetptr, basePages = got.retptr, got.memPages
			} else {
				if got.retptr != baseRetptr {
					t.Fatalf("iteration %d landed at %d, the first at %d — a block is not being returned",
						i, got.retptr, baseRetptr)
				}
				if got.memPages != basePages {
					t.Fatalf("iteration %d grew memory from %d to %d pages", i, basePages, got.memPages)
				}
			}
			if _, err := post.Call(store, any(int32(got.retptr))); err != nil {
				t.Fatalf("post %d: %v", i, err)
			}
			if _, err := fn(f.Dtor).Call(store, h); err != nil {
				t.Fatalf("dtor %d: %v", i, err)
			}
		}
	})
}

// The -2 sentinel means the answer is UNKNOWN, and must lift to
// err(backtrack-overflow) rather than to a definite ok(none). Reaching it needs
// the same squeeze tools/fuzz uses elsewhere: Backtracking forced by a tiny
// MaxDFAStates, a small memo budget, and an input long enough to exhaust the
// frame budget.
func TestComponentAdapterLiftsBacktrackOverflow(t *testing.T) {
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000
	entries := []config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}
	// BTWorkBudgetOff: with the budget on, a body past its static regions hands
	// the call to its fallback, which sizes its memory from the input and
	// answers — so -2 would need memory that cannot grow. Off, the body keeps
	// answering -2 at its static ceiling, which is the arm under test.
	w, _, res := componentWasm(t, entries, compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096, BTWorkBudget: compile.BTWorkBudgetOff})

	store, inst, mem := instantiateCore(t, w)
	f := res["f"]
	ctor := inst.GetFunc(store, f.Constructor)
	next := inst.GetFunc(store, f.Next)
	if ctor == nil || next == nil {
		t.Fatalf("missing resource exports: constructor %v, next %v", ctor != nil, next != nil)
	}
	raw := inst.GetFunc(store, "f")
	if raw == nil {
		t.Fatalf("the raw export is kept under component, and this test needs it")
	}

	busy := strings.Repeat("Z", length) // every position is a candidate
	buf := mem.UnsafeData(store)
	if length > int(pathsOutBase-pathsInputBase) {
		t.Fatalf("input runs into the output window")
	}
	copy(buf[pathsInputBase:], busy)

	// First establish that the underlying body really does answer -2 here; a
	// test that silently stopped overflowing would otherwise pass while
	// checking nothing.
	_, wd := sharedEngine()
	wd.Arm(store)
	rawRes, err := raw.Call(store, any(int32(pathsInputBase)), any(int32(length)), any(int32(0)))
	wd.Disarm()
	if err != nil {
		t.Fatalf("raw find: %v", err)
	}
	if got := rawRes.(int64); got != abi.BTStackOverflow {
		t.Skipf("this shape no longer overflows (raw find returned %d); the -2 arm needs a new one", got)
	}

	h, err := ctor.Call(store, any(int32(pathsInputBase)), any(int32(length)), any(int32(0)))
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	handle := h.(int32)

	// The resource's `next` has its OWN copy of the -2 arm — the function-shaped
	// adapter it replaced is gone — so this is the only place that proves an
	// unknown answer is lifted to err(backtrack-overflow) rather than to
	// ok(none), a definite "no more matches" the engine never established.
	// Called twice: a scanner that reported an error must KEEP reporting it,
	// not settle into "finished" on the next pull.
	for call := 0; call < 2; call++ {
		wd.Arm(store)
		r, err := next.Call(store, any(handle))
		wd.Disarm()
		if err != nil {
			t.Fatalf("next %d: %v", call, err)
		}
		ret := uint32(r.(int32))
		buf = mem.UnsafeData(store)
		if buf[ret] != 1 {
			t.Errorf("next %d: result discriminant = %d, want 1 (err) — an UNKNOWN answer must not lift to ok(none)",
				call, buf[ret])
		}
		if buf[ret+4] != 0 {
			t.Errorf("next %d: error enum index = %d, want 0 (backtrack-overflow)", call, buf[ret+4])
		}
	}
}

// The scanner constructor TAKES OVER the block the canonical ABI lowered its
// input into, instead of copying it.
//
// The host copies a `list<u8>` into this component's memory through
// cabi_realloc before the constructor runs, and that block is linked on the
// per-call chain. The constructor used to copy it a SECOND time into a block of
// its own and leave the lowered one on the chain, where only some later call's
// post-return freed it: a host that built many scanners before driving any held
// every lowered input at once, and grown memory never shrinks. Unlinking the
// lowered block and keeping it as the scanner's input removes both the copy and
// the deferral. When that block is not the newest one on the chain the
// constructor falls back to the copy.

// ctorText and ctorOther are the same length and match at different places, and
// are long enough that their blocks sit in a size class of their own — no result
// area, gate array or representation competes for it, so free-list reuse is
// predictable.
var (
	ctorText  = pad300("ghp_ab12 AKIAZZZZZZ 123-45")
	ctorOther = pad300("AKIAZZZZZZ ghp_ab12 123-45")
	ctorWant  = [][3]uint32{{0, 0, 8}, {1, 9, 19}, {2, 20, 26}}
	otherWant = [][3]uint32{{1, 0, 10}, {0, 11, 19}, {2, 20, 26}}
)

func pad300(s string) string { return s + strings.Repeat(" ", 300-len(s)) }

// driveHandle runs `next` to exhaustion on a live handle, running each call's
// post-return as a host would, and leaves the handle for the caller to drop.
func (h *setHarness) driveHandle(handle int32) [][3]uint32 {
	h.t.Helper()
	var all [][3]uint32
	for {
		ret := h.call(h.pkg+"#[method]scan-it.next", handle)
		got, errored := h.matches(ret)
		if errored {
			h.t.Fatal("next reported an error")
		}
		h.call("cabi_post_"+h.pkg+"#[method]scan-it.next", ret)
		if len(got) == 0 {
			return all
		}
		all = append(all, got...)
	}
}

// Construct-and-drop with NO other call in between must not grow memory.
func TestComponentConstructorLeavesNoLoweredInputBehind(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	text := strings.Repeat("x", 4096)
	cycle := func() {
		ptr, n := h.writeInput(text)
		handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
		h.call(h.pkg+"#[dtor]scan-it", handle)
	}
	for i := 0; i < 50; i++ { // let the classes fill
		cycle()
	}
	before := len(h.mem.UnsafeData(h.store))
	for i := 0; i < 1000; i++ {
		cycle()
	}
	if after := len(h.mem.UnsafeData(h.store)); after != before {
		t.Errorf("memory grew over 1000 construct/drop pairs with no call between: %d → %d bytes (+%d)",
			before, after, after-before)
	}
}

// The scanner's input IS the lowered block, and it answers correctly from it.
func TestComponentConstructorAdoptsTheLoweredInput(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	ptr, n := h.writeInput(ctorText)
	handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
	// The handle is the representation here (see newSetHarness), and its first
	// word is the scanner's input pointer.
	if got := int32(h.u32(handle)); got != ptr {
		t.Errorf("the scanner reads its input at %d but the host lowered it at %d: it was copied", got, ptr)
	}
	if got := h.driveHandle(handle); fmt.Sprint(got) != fmt.Sprint(ctorWant) {
		t.Errorf("drive over the adopted input = %v, want %v", got, ctorWant)
	}
	h.call(h.pkg+"#[dtor]scan-it", handle)
}

// A block freed by one scanner's dtor and adopted by the next carries no state
// from the first.
func TestComponentAdoptedInputCarriesNoStaleState(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	pa, na := h.writeInput(ctorText)
	a := h.call(h.pkg+"#[constructor]scan-it", pa, na, int32(0))
	gotA := h.driveHandle(a)
	h.call(h.pkg+"#[dtor]scan-it", a)

	pb, nb := h.writeInput(ctorOther)
	if pb != pa {
		t.Fatalf("the second input was lowered at %d, not into the block the first scanner freed "+
			"(%d): the first scanner did not own the lowered block, so this proves nothing", pb, pa)
	}
	b := h.call(h.pkg+"#[constructor]scan-it", pb, nb, int32(0))
	gotB := h.driveHandle(b)
	h.call(h.pkg+"#[dtor]scan-it", b)

	if fmt.Sprint(gotA) != fmt.Sprint(ctorWant) {
		t.Errorf("first drive = %v, want %v", gotA, ctorWant)
	}
	if fmt.Sprint(gotB) != fmt.Sprint(otherWant) {
		t.Errorf("second drive, over the reused block = %v, want %v", gotB, otherWant)
	}
}

// GUARD — it passes before the change as well as after it. When the lowered
// input is NOT the newest block on the per-call chain the constructor copies, as
// it always did. Two ways in: another allocation after the lowering, and a
// zero-length input the host never allocated (pointer 0).
func TestComponentConstructorFallsBackToACopy(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	ptr, n := h.writeInput(ctorText)
	h.call("cabi_realloc", int32(0), int32(0), int32(4), int32(16)) // a newer block
	handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
	if got := int32(h.u32(handle)); got == ptr {
		t.Error("the constructor took over a lowered block that was not the newest on the chain")
	}
	if got := h.driveHandle(handle); fmt.Sprint(got) != fmt.Sprint(ctorWant) {
		t.Errorf("drive over the copied input = %v, want %v", got, ctorWant)
	}
	h.call(h.pkg+"#[dtor]scan-it", handle)

	empty := h.call(h.pkg+"#[constructor]scan-it", int32(0), int32(0), int32(0))
	if got := h.driveHandle(empty); len(got) != 0 {
		t.Errorf("a zero-length input reported %v, want nothing", got)
	}
	h.call(h.pkg+"#[dtor]scan-it", empty)
}

// An OVERLAPPING component set, which until now was the only output kind left
// quadratic.
//
// A component consumer has no pointer to hand in and nothing to free, so the
// answer cache can only come from the resource's own constructor. That was
// deferred while the region was over a hundred megabytes; checkpointed it is a
// small fraction of that, and the constructor now reserves it.
const overlapSetCfg = `
wasm_format: component
wit_package: t
import_module: t
regexps:
  - pattern: '[a-z]+'
  - pattern: '[0-9]+'
  - pattern: '[A-Z]+'
sets:
  - name: s
    patterns: all
    overlapping: true
    find: scan_it
`

// TestComponentOverlapCacheAnswersCorrectly drives the resource to exhaustion
// over an input long enough for the cache to engage, and checks the answer
// against the enumeration the contract promises: every start position, in
// order, with every pattern that matches there.
//
// The cache engaging is the point. Below the work threshold the drive walks and
// this test would pass without the constructor reserving anything at all, which
// is why the input is long and dense rather than a handful of bytes.
func TestComponentOverlapCacheAnswersCorrectly(t *testing.T) {
	h := newSetHarness(t, overlapSetCfg)
	text := strings.Repeat("abcdefgh", 512) // 4096 bytes, every position matches
	p, n := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, n, int32(0))
	defer h.call(h.pkg+"#[dtor]scan-it", sc)

	var starts []uint32
	for i := 0; i < len(text)+8; i++ {
		got, _ := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc))
		if len(got) == 0 {
			break
		}
		starts = append(starts, got[0][1])
	}
	if len(starts) != len(text) {
		t.Fatalf("reported %d positions over %d bytes; an overlapping drive reports every start",
			len(starts), len(text))
	}
	for i, s := range starts {
		if s != uint32(i) {
			t.Fatalf("position %d reported start %d: the enumeration is not in order", i, s)
		}
	}
	// A correct answer is no evidence that the cache produced it — the walk
	// answers identically. `ready` says which engine did.
	cachePtr := int32(h.u32(sc + 20))
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no answer cache for a 4 KB overlapping drive")
	}
	if ready := int32(h.u32(cachePtr + config.SetOverlapHdrReadyOff)); ready != 1 {
		t.Fatalf("the cache header's ready is %d after the drive: it walked", ready)
	}
}

// The gate, from the other side of it. The test above uses 4 KB, where the
// region is a SINGLE BLOCK — the stride is the whole span, nothing is ever
// re-swept, and the square-root arm, the 16 floor and the over-budget decline
// have never run at all.
//
// This input crosses into the checkpointed regime, which for a 3-pattern set
// (16 bytes a row) is a little over 4 MB. What is checked is the arithmetic the
// constructor does and the engagement that follows it, not the enumeration: a
// drive of four and a half million positions through one component call each is
// not a unit test, so the first hundred positions are checked against the
// contract and the rest is left to the corpus.
func TestComponentOverlapCacheCrossesTheGate(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 4.5 MB input; skipped in -short")
	}
	h := newSetHarness(t, overlapSetCfg)
	// One long lowercase run: `[a-z]+` then matches at every position with an
	// extent running to the end, so the work counter — which charges MATCHED
	// BYTES — crosses the sweep's threshold within the first handful of calls
	// rather than needing the whole drive.
	const n = 4_500_000
	text := strings.Repeat("a", n)
	p, ln := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, ln, int32(0))
	defer h.call(h.pkg+"#[dtor]scan-it", sc)

	// The handle IS the representation here (see newSetHarness), so the
	// descriptor is readable: cache pointer at +20, its length at +24.
	cachePtr := int32(h.u32(sc + 20))
	cacheLen := h.u32(sc + 24)
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no cache for a 4.5 MB input")
	}
	sh, err := compile.SetOverlapCacheShape(overlapSetCfgSet(t), overlapSetCfgBuild(t))
	if err != nil || !sh.Eligible {
		t.Fatalf("shape: %v %+v", err, sh)
	}
	want := uint32(config.SetOverlapCheckpointBytes(n, sh.Cells, sh.Patterns))
	if cacheLen != want {
		t.Fatalf("cache_len = %d, config says %d: the constructor's arithmetic and "+
			"config's have diverged, and the sweep validates against config's", cacheLen, want)
	}
	// Past the gate the stride is NOT the whole span any more, which is the
	// arm this test exists for.
	if k := config.SetOverlapCheckpointStride(n, sh.Cells, sh.Patterns); k >= n+1 {
		t.Fatalf("stride %d is still the whole span: this input no longer crosses the gate", k)
	}

	for i := 0; i < 100; i++ {
		got, errored := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc))
		if errored {
			t.Fatalf("position %d: the scanner reported an error", i)
		}
		if len(got) != 1 || got[0][1] != uint32(i) || got[0][2] != uint32(n) {
			t.Fatalf("position %d: got %v, want one match [0 %d %d]", i, got, i, n)
		}
	}
	// And it engaged: `ready` is the one header field a caller may read, and
	// without this the test passes on a drive that quietly walked.
	if ready := int32(h.u32(cachePtr + 8)); ready != 1 {
		t.Fatalf("ready = %d after 100 positions of a quadratic drive, want 1", ready)
	}
}

// A scanner that reported an ERROR keeps reporting it.
//
// `next` set a done flag on the error and then answered "ok, no more matches"
// for ever after — the silent degradation the sentinels exist to prevent,
// reachable by any raw WIT consumer. The Rust and C stubs latch a `done` of
// their own and never observe it, which is why nothing caught it.
//
// The error is provoked through the CACHE HEADER rather than a Backtracking
// overflow, because the constructor owns that header and the harness can reach
// it: the handle is the representation here, so zeroing the stride between two
// calls is exactly the "one region, two scanners" mistake the -4 sentinel
// exists for. It also checks the other half — that the component adapter maps
// -4 to `malformed-cache` and not to `backtrack-overflow`, which the C
// consumer got wrong by reading only the result discriminant.
func TestComponentScannerRepeatsItsError(t *testing.T) {
	h := newSetHarness(t, overlapSetCfg)
	// Quadratic enough for the sweep to engage within a few calls, so there is
	// a live cache to corrupt.
	text := strings.Repeat("a", 200000)
	p, ln := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, ln, int32(0))

	cachePtr := int32(h.u32(sc + 20))
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no cache, so there is no header to corrupt")
	}
	for i := 0; i < 200; i++ {
		if _, errored := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc)); errored {
			t.Fatalf("position %d errored before the header was touched", i)
		}
		if int32(h.u32(cachePtr+config.SetOverlapHdrReadyOff)) == 1 {
			break
		}
	}
	if int32(h.u32(cachePtr+config.SetOverlapHdrReadyOff)) != 1 {
		t.Fatal("the sweep never engaged, so the header being corrupted proves nothing")
	}

	// A stride of zero: the likeliest form of the mistake, and the one that
	// would divide by zero rather than answer.
	binary.LittleEndian.PutUint32(h.mem.UnsafeData(h.store)[cachePtr+16:], 0)

	code, errored := h.nextErr(sc)
	if !errored {
		t.Fatal("a malformed header was accepted: the call answered normally")
	}
	// error-code { backtrack-overflow = 0, malformed-cache = 1 }
	if code != 1 {
		t.Fatalf("error-code %d, want 1 (malformed-cache); 0 would be reporting a "+
			"cache mistake as a backtracking overflow", code)
	}
	for i := 0; i < 3; i++ {
		again, stillErrored := h.nextErr(sc)
		if !stillErrored {
			t.Fatalf("call %d after the error answered OK: a scanner that could not "+
				"finish must not become 'no more matches'", i+2)
		}
		if again != code {
			t.Fatalf("call %d reported error-code %d, the first reported %d", i+2, again, code)
		}
	}
	// And the dtor still works on an errored scanner: it owns an input copy, a
	// gate array, a cache and the representation, whatever state it stopped in.
	h.call(h.pkg+"#[dtor]scan-it", sc)
}

// nextErr calls next and reports the error-code discriminant beside the result
// discriminant, which `matches` folds into a bool.
func (h *setHarness) nextErr(sc int32) (code byte, errored bool) {
	h.t.Helper()
	ret := h.call(h.pkg+"#[method]scan-it.next", sc)
	data := h.mem.UnsafeData(h.store)
	if data[ret] != 1 {
		return 0, false
	}
	return data[ret+4], true
}

// overlapSetCfgBuild and overlapSetCfgSet parse overlapSetCfg the way the
// generator would, so the region the test expects comes from the same shape the
// constructor was emitted from rather than a constant repeated here.
func overlapSetCfgBuild(t *testing.T) config.BuildConfig {
	t.Helper()
	var cfg config.BuildConfig
	if err := yaml.Unmarshal([]byte(overlapSetCfg), &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func overlapSetCfgSet(t *testing.T) config.SetConfig {
	t.Helper()
	return overlapSetCfgBuild(t).Sets[0]
}

// A scanner whose position went BACKWARDS below the floor of its engaged cache
// reports out-of-order — the error-code's third case, discriminant 2 — and
// keeps reporting it, as every other error does.
//
// A consumer cannot provoke this through the resource, which only moves
// forward. The harness rewinds the representation's position field directly,
// which is what a corrupted or shared scanner amounts to, and which checks the
// half that matters here: the adapter lifts -6 into its own case, not into
// malformed-cache or backtrack-overflow.
func TestComponentScannerReportsOutOfOrder(t *testing.T) {
	h := newSetHarness(t, overlapSetCfg)
	text := strings.Repeat("a", 200000)
	p, ln := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, ln, int32(0))

	cachePtr := int32(h.u32(sc + 20))
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no cache, so there is no floor to fall below")
	}
	for i := 0; i < 200; i++ {
		if _, errored := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc)); errored {
			t.Fatalf("position %d errored before the position was touched", i)
		}
		if int32(h.u32(cachePtr+config.SetOverlapHdrReadyOff)) == 1 {
			break
		}
	}
	if int32(h.u32(cachePtr+config.SetOverlapHdrReadyOff)) != 1 {
		t.Fatal("the sweep never engaged, so nothing has a floor to fall below")
	}
	if floor := int32(h.u32(cachePtr + 20)); floor <= 0 {
		t.Fatalf("the sweep engaged at floor %d, so no position lies below it", floor)
	}

	// repPos, the representation's next-position field.
	binary.LittleEndian.PutUint32(h.mem.UnsafeData(h.store)[sc+8:], 0)

	code, errored := h.nextErr(sc)
	if !errored {
		t.Fatal("a position below the floor was served: the call answered normally")
	}
	// error-code { backtrack-overflow = 0, malformed-cache = 1, out-of-order = 2 }
	if code != 2 {
		t.Fatalf("error-code %d, want 2 (out-of-order)", code)
	}
	for i := 0; i < 3; i++ {
		again, stillErrored := h.nextErr(sc)
		if !stillErrored || again != code {
			t.Fatalf("call %d after the error answered errored=%v code=%d; the first reported %d",
				i+2, stillErrored, again, code)
		}
	}
	h.call(h.pkg+"#[dtor]scan-it", sc)
}

const geometrySetCfg = `wasm_format: component
import_module: t
wit_package: t
regexps:
  - name: p0
    pattern: '[^\n]*[0-2]'
  - name: p1
    pattern: '[^\n]*[3-5]'
sets:
  - name: s
    patterns: all
    overlapping: true
    find: scan_it
`

// TestComponentCacheGeometryMatchesConfig DRIVES the constructor and compares
// the region it reserved — its length, and the stride it wrote into the header —
// with what config computes from the compiler's shape. The same numbers are
// stamped into the adapter at compile time, and a test that only checks the
// exports exist cannot tell a constructor sizing for the wrong column from one
// sizing for the right one.
func TestComponentCacheGeometryMatchesConfig(t *testing.T) {
	var cfg config.BuildConfig
	if err := yaml.Unmarshal([]byte(geometrySetCfg), &cfg); err != nil {
		t.Fatal(err)
	}
	sh, err := compile.SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil || !sh.Eligible {
		t.Fatalf("shape = %+v, %v: this set must get a sweep", sh, err)
	}
	h := newSetHarness(t, geometrySetCfg)
	for _, n := range []int{100, 1000, 4096} {
		p, l := h.writeInput(strings.Repeat("x1y4", n/4))
		sc := h.call(h.pkg+"#[constructor]scan-it", p, l, int32(0))
		cachePtr, cacheLen := int32(h.u32(sc+20)), int(h.u32(sc+24))
		if cachePtr == 0 {
			t.Errorf("len %d: the constructor reserved no cache", l)
		} else {
			if want := config.SetOverlapCheckpointBytes(int(l), sh.Cells, sh.Patterns); cacheLen != want {
				t.Errorf("len %d: region is %d bytes, config computes %d", l, cacheLen, want)
			}
			if got, want := int(h.u32(cachePtr+config.SetOverlapHdrStrideOff)), config.SetOverlapCheckpointStride(int(l), sh.Cells, sh.Patterns); got != want {
				t.Errorf("len %d: stride is %d, config computes %d", l, got, want)
			}
		}
		h.call(h.pkg+"#[dtor]scan-it", sc)
	}
}

// --- the single-pattern find/groups RESOURCES -------------------------------
//
// `find` and `groups` are resources rather than functions, for the reason a
// set's `find` is: an iterating function is handed the input again on every
// step and the canonical ABI copies it, so a scan of n bytes reporting m
// matches copied n*(m+1) bytes. The constructor takes it once.
//
// Driven here over the RAW core ABI, exactly as the set resources are, with the
// `[resource-new]` builtin stubbed by instantiateCore's identity function.

// patternResourceHarness is setHarness pointed at the `matcher` interface.
func newPatternResourceHarness(t *testing.T, entries []config.RegexEntry) (*setHarness, map[string]generate.PatternResourceNames) {
	t.Helper()
	cfg := config.BuildConfig{
		WasmFormat: "component", ImportModule: "t", WitPackage: "t", Regexps: entries,
	}
	_, _, resources, _, _, err := generate.ComponentArtifactsWithSets(cfg)
	if err != nil {
		t.Fatalf("component artifacts: %v", err)
	}
	core, _, err := component.Core(cfg, nil)
	if err != nil {
		t.Fatalf("component core: %v", err)
	}
	store, inst, mem := instantiateCore(t, core)
	return &setHarness{t: t, store: store, inst: inst, mem: mem, pkg: "regexped:t/matcher"}, resources
}

// spans reads a result<option<tuple<u32,u32>>, error-code> area.
func (h *setHarness) spans(ret int32) (start, end uint32, some, errored bool) {
	data := h.mem.UnsafeData(h.store)
	if data[ret] == 1 {
		return 0, 0, false, true
	}
	if data[ret+4] == 0 {
		return 0, 0, false, false
	}
	return h.u32(ret + 8), h.u32(ret + 12), true, false
}

// TestComponentPatternFindResource drives a find resource to exhaustion and
// checks the positions AND the advance rule: every match is reported once, in
// order, and a scan over an empty-matchable pattern terminates.
func TestComponentPatternFindResource(t *testing.T) {
	h, res := newPatternResourceHarness(t, []config.RegexEntry{
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "f"},
		{Pattern: `a*`, FindFunc: "empties"},
	})

	drive := func(funcName, input string) [][2]uint32 {
		n := res[funcName]
		if n.Constructor == "" {
			t.Fatalf("%s has no resource names", funcName)
		}
		ptr, length := h.writeInput(input)
		handle := h.call(n.Constructor, ptr, length, int32(0))
		var out [][2]uint32
		for i := 0; i < 4*len(input)+8; i++ {
			ret := h.call(n.Next, handle)
			start, end, some, errored := h.spans(ret)
			if errored {
				t.Fatalf("%s.next reported an error", funcName)
			}
			if !some {
				h.call("cabi_post_"+n.Next, ret)
				h.call(n.Dtor, handle)
				return out
			}
			out = append(out, [2]uint32{start, end})
			h.call("cabi_post_"+n.Next, ret)
		}
		t.Fatalf("%s did not terminate: the advance rule does not step past a zero-length match", funcName)
		return nil
	}

	got := drive("f", "xxghp_ab12 and ghp_cd34yy")
	want := [][2]uint32{{2, 10}, {15, 23}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("find over two tokens = %v, want %v", got, want)
	}

	// `a*` matches empty everywhere, so this is the shape that hangs if the
	// advance does not step past a zero-length match.
	if got := drive("empties", "ab"); len(got) != 3 {
		t.Errorf("a* over %q reported %v; want one match at each of 0, 1, 2", "ab", got)
	}

	// A finished scanner keeps answering `none` rather than restarting.
	n := res["f"]
	ptr, length := h.writeInput("nothing")
	handle := h.call(n.Constructor, ptr, length, int32(0))
	for i := 0; i < 3; i++ {
		if _, _, some, errored := h.spans(h.call(n.Next, handle)); some || errored {
			t.Fatalf("call %d on a non-matching input: some=%v errored=%v", i, some, errored)
		}
	}
	h.call(n.Dtor, handle)
}

// TestComponentPatternGroupsResource drives a groups resource, including the
// UNSET group — the element path a happy-path test never reaches — and the
// empty list that means the scan is finished.
func TestComponentPatternGroupsResource(t *testing.T) {
	h, res := newPatternResourceHarness(t, []config.RegexEntry{
		{Pattern: `(?P<opt>x)?y`, GroupsFunc: "g"},
	})
	n := res["g"]
	if !n.Groups {
		t.Fatal("a groups_func must be marked as the groups shape")
	}

	// groups' next answers result<list<option<tuple<u32,u32>>>, error-code>:
	// @0 disc, @4 list ptr, @8 list len. An empty list is "finished".
	readGroups := func(ret int32) [][3]int64 {
		data := h.mem.UnsafeData(h.store)
		if data[ret] == 1 {
			t.Fatalf("next reported an error")
		}
		ptr := int32(h.u32(ret + 4))
		count := int32(h.u32(ret + 8))
		var out [][3]int64
		for i := int32(0); i < count; i++ {
			el := ptr + i*12
			out = append(out, [3]int64{
				int64(h.mem.UnsafeData(h.store)[el]),
				int64(h.u32(el + 4)), int64(h.u32(el + 8)),
			})
		}
		return out
	}

	ptr, length := h.writeInput("xy y")
	handle := h.call(n.Constructor, ptr, length, int32(0))

	// "xy" at 0: both groups participate.
	first := readGroups(h.call(n.Next, handle))
	if len(first) != 2 || first[0][0] != 1 || first[0][1] != 0 || first[0][2] != 2 {
		t.Fatalf("first match groups = %v, want group 0 some(0,2) and two entries", first)
	}
	if first[1][0] != 1 {
		t.Errorf("group 1 must be some for %q", "xy")
	}

	// "y" at 3: the optional group is UNSET and must come back as none.
	second := readGroups(h.call(n.Next, handle))
	if len(second) != 2 || second[0][0] != 1 || second[0][1] != 3 || second[0][2] != 4 {
		t.Fatalf("second match groups = %v, want group 0 some(3,4)", second)
	}
	if second[1][0] != 0 {
		t.Errorf("group 1 disc = %d for %q, want 0 (none)", second[1][0], "y")
	}

	// Finished: an EMPTY list, and it stays empty.
	for i := 0; i < 2; i++ {
		if got := readGroups(h.call(n.Next, handle)); len(got) != 0 {
			t.Errorf("call %d after the last match returned %v, want an empty list", i, got)
		}
	}
	h.call(n.Dtor, handle)
}

// TestComponentPatternScannersAreIndependent: two scanners over the same
// pattern, interleaved, must not share a position — the property the resource
// exists to provide and the one a module-level global would break.
func TestComponentPatternScannersAreIndependent(t *testing.T) {
	h, res := newPatternResourceHarness(t, []config.RegexEntry{
		{Pattern: `[0-9]+`, FindFunc: "nums"},
	})
	n := res["nums"]
	pa, la := h.writeInput("1 22 333")
	pb, lb := h.writeInput("44 5")
	a := h.call(n.Constructor, pa, la, int32(0))
	b := h.call(n.Constructor, pb, lb, int32(0))

	next := func(handle int32) (uint32, uint32, bool) {
		start, end, some, errored := h.spans(h.call(n.Next, handle))
		if errored {
			t.Fatal("next reported an error")
		}
		return start, end, some
	}
	if s, e, _ := next(a); s != 0 || e != 1 {
		t.Errorf("scanner A first = (%d,%d), want (0,1)", s, e)
	}
	if s, e, _ := next(b); s != 0 || e != 2 {
		t.Errorf("scanner B first = (%d,%d), want (0,2)", s, e)
	}
	if s, e, _ := next(a); s != 2 || e != 4 {
		t.Errorf("scanner A second = (%d,%d), want (2,4) — B moved A's position", s, e)
	}
	if s, e, _ := next(b); s != 3 || e != 4 {
		t.Errorf("scanner B second = (%d,%d), want (3,4)", s, e)
	}
	h.call(n.Dtor, a)
	h.call(n.Dtor, b)
}
