package fuzz

import (
	"math/rand"
	"sort"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

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
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, core)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	// The shared engine runs with epoch interruption on (wasmrun.go), so a store
	// with no deadline is interrupted immediately. These calls are allocator
	// calls, not pattern drives: there is nothing to time out, so the deadline
	// is set far out rather than armed per call.
	store.SetEpochDeadline(1 << 40)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	h := &allocHarness{t: t, store: store}
	h.alloc = inst.GetFunc(store, "cabi_realloc")
	h.post = inst.GetFunc(store, "cabi_post_token-find")
	memExp := inst.GetExport(store, "memory")
	if h.alloc == nil || h.post == nil || memExp == nil || memExp.Memory() == nil {
		t.Fatalf("core module is missing cabi_realloc, the post-return or memory")
	}
	h.mem = memExp.Memory()
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
