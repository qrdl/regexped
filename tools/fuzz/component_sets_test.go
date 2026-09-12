package fuzz

import (
	"encoding/binary"
	"fmt"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/component"
	"github.com/qrdl/regexped/config"
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
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, core)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1 << 40)

	// Supply a [resource-new] for every import the module declares, in order.
	var externs []wasmtime.AsExtern
	for _, imp := range mod.Imports() {
		if imp.Type().FuncType() == nil {
			t.Fatalf("unexpected non-function import %v", imp.Name())
		}
		fn := wasmtime.WrapFunc(store, func(rep int32) int32 { return rep })
		externs = append(externs, fn)
	}
	inst, err := wasmtime.NewInstance(store, mod, externs)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		t.Fatal("component core module does not export its memory")
	}
	return &setHarness{t: t, store: store, inst: inst, mem: memExp.Memory(), pkg: "regexped:t/sets"}
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
