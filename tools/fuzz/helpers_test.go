package fuzz

import (
	"encoding/binary"
	"fmt"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// writeFindScratch lays a scratch descriptor into guest memory and returns its
// address — the argument `find` and `find_batch` take in place of a bare gate
// pointer (internal/abi).
//
// Every test in this package that drives a set's find used to pass the gate
// array directly. They pass this instead, and the magic word is what turned
// each missed call site into an immediate trap rather than a wrong answer: the
// parameter has the same type it always had.
//
// The descriptor is placed immediately above the gate array. Callers here own
// their memory layouts and all of them leave room above it.
func writeFindScratch(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen int32) int32 {
	return writeFindScratchStride(store, mem, gatePtr, idSpaceWords, cachePtr, cacheLen, 0)
}

// writeFindScratchStride is writeFindScratch plus the CHECKPOINTED cache's one
// caller-written header field.
//
// The stride is chosen by whoever allocates the region — a generated `init` in
// a real consumer, these helpers in a test — because the allocation and the
// stride come from the same formula and must agree. A zero stride is a
// malformed header and the sweep reports it rather than guessing, so a test
// that offers a cache must seed this or it is testing the refusal path.
func writeFindScratchStride(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen, stride int32) int32 {
	scratch := gatePtr + idSpaceWords*4
	buf := mem.UnsafeData(store)
	abi.WriteFindScratch(buf, scratch, gatePtr, cachePtr, cacheLen)
	if cachePtr != 0 {
		for i := int32(0); i < config.SetOverlapCheckpointHeaderBytes; i++ {
			buf[cachePtr+i] = 0
		}
		binary.LittleEndian.PutUint32(buf[cachePtr+config.SetOverlapHdrStrideOff:], uint32(stride))
	}
	return scratch
}

// overlapCacheFor sizes and strides a checkpointed cache for one set, the way
// a generated `init` would: it recompiles the set to learn the sweep column,
// then asks config for both numbers so the test and the sweep cannot disagree.
func overlapCacheFor(input string, pats []string) (length, stride int32) {
	cfg := overlapSizingCfg(pats)
	// One helper for both numbers: the region is sized FROM the stride, and a
	// harness that computed them separately would hand the sweep a header it
	// reports as malformed.
	bytes, k, err := compile.SetOverlapCacheSizing(cfg.Sets[0], cfg, len(input))
	if err != nil {
		return int32(config.SetOverlapCheckpointHeaderBytes), 1
	}
	return int32(bytes), int32(k)
}

// overlapCacheForK sizes a region for a CHOSEN stride rather than the formula's.
//
// The block-boundary tests force tiny strides, and a region sized at the
// formula's stride does not hold one: at k = 1 the checkpoint array is a column
// per position, which for a 4 KB input is three times the single-block region.
// Sizing it the other way made the sweep refuse, the drive walk, and the test
// compare the walk with itself at every stride below 5.
func overlapCacheForK(input string, pats []string, k int32) int32 {
	cfg := overlapSizingCfg(pats)
	sh, err := compile.SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil || !sh.Eligible {
		return int32(config.SetOverlapCheckpointHeaderBytes)
	}
	return int32(config.SetOverlapCheckpointBytesForStride(
		len(input), sh.Cells, sh.Patterns, int(k)))
}

// overlapSizingCfg is the set overlapCacheFor and overlapCacheForK size a region
// for: an overlapping find over pats, by the pattern names the drives use.
func overlapSizingCfg(pats []string) config.BuildConfig {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	return config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "find", Overlapping: true,
			Patterns: config.PatternSelector{Names: names},
		}},
	}
}

// cacheLayout is how a cache drive lays out its instance: the entry it drives,
// the region it offers, and what a test steers the header with.
type cacheLayout struct {
	batch       bool  // drive set_find_batch (the set carries the hint) rather than set_find
	scratchLen  int32 // bytes allocated for the answer cache
	offer       bool  // hand that region to the export; false passes no cache at all
	stride      int32 // the stride written into the header
	preArmWork  bool  // saturate `work`, so the first call sweeps whatever it costs
	canaryBelow int32 // bytes of 0xA5 immediately below the region, on a page of their own
	canaryAbove int32 // bytes of 0xA5 immediately above it
}

// cacheDrive is one overlapping set compiled, instantiated and laid out for a
// drive: the input, the gate array, the tuple buffer and the region each on
// pages of their own, the descriptor built and the header seeded. Every cache
// drive in this package starts from one; each used to carry its own copy of
// this setup, and the copies had begun to differ in how many pages the input
// got.
type cacheDrive struct {
	store                                     *wasmtime.Store
	mem                                       *wasmtime.Memory
	fn                                        *wasmtime.Func
	release                                   func()
	inBase, gatePtr, outPtr, scratchPtr, desc int32
}

func (d *cacheDrive) buf() []byte { return d.mem.UnsafeData(d.store) }

func newCacheDrive(t *testing.T, pats []string, input string, lay cacheLayout) *cacheDrive {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	set := config.SetConfig{
		Name: "s", Find: "set_find",
		Patterns: config.PatternSelector{All: true}, Overlapping: true,
	}
	export := "set_find"
	if lay.batch {
		set.Hints = []string{"batch-find"}
		export = "set_find_batch"
	}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{set}}, "")
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fail := func(format string, args ...any) {
		release()
		t.Fatalf(format, args...)
	}
	if !lay.batch && inst.GetFunc(store, "set_find_batch") != nil {
		fail("the set declared no batch hint but a batch entry was exported")
	}
	fn := inst.GetFunc(store, export)
	if fn == nil {
		fail("module missing %s export", export)
	}
	const pageSize = 65536
	d := &cacheDrive{store: store, mem: mem, fn: fn, release: release}
	if d.inBase, d.gatePtr, d.outPtr, d.scratchPtr, err = cacheDriveAddrs(w, len(input), lay.canaryBelow > 0); err != nil {
		fail("parse data section: %v", err)
	}
	needed := uint64((int64(d.scratchPtr) + int64(lay.scratchLen) + int64(lay.canaryAbove) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			fail("grow: %v", err)
		}
	}
	buf := d.buf()
	copy(buf[d.inBase:], input)
	// The caller zeroes BOTH regions to start a drive — that is the whole
	// contract, for the gates and for the cache header alike.
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[d.gatePtr+i] = 0
	}
	for i := int32(0); i < lay.scratchLen; i++ {
		buf[d.scratchPtr+i] = 0
	}
	for i := int32(0); i < lay.canaryBelow; i++ {
		buf[d.scratchPtr-lay.canaryBelow+i] = 0xA5
	}
	for i := int32(0); i < lay.canaryAbove; i++ {
		buf[d.scratchPtr+lay.scratchLen+i] = 0xA5
	}
	cachePtr, cacheLen := int32(0), int32(0)
	if lay.offer {
		cachePtr, cacheLen = d.scratchPtr, lay.scratchLen
	}
	d.desc = writeFindScratchStride(store, mem, d.gatePtr, int32(len(pats)), cachePtr, cacheLen, lay.stride)
	if lay.preArmWork && lay.offer {
		binary.LittleEndian.PutUint32(d.buf()[d.scratchPtr+config.SetOverlapHdrWorkOff:], 0x7FFFFFFF)
	}
	return d
}

// cacheDriveAddrs is the page layout every cache drive uses: the input above the
// module's data on as many pages as it needs — the megabyte-scale shapes that
// reach the layout arithmetic's 32-bit edges do not fit in one — then a page each
// for the gate array and the tuple buffer, then the region. With a canary it
// sits one page further up, so a write below the region lands in the canary
// rather than in the tuple buffer, where it would pass for ordinary tuples.
func cacheDriveAddrs(w []byte, inputLen int, canaryBelow bool) (inBase, gatePtr, outPtr, regionPtr int32, err error) {
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	inBase = int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((inputLen + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr = inBase + span
	outPtr = gatePtr + pageSize
	regionPtr = outPtr + pageSize
	if canaryBelow {
		regionPtr += pageSize
	}
	return inBase, gatePtr, outPtr, regionPtr, nil
}

// TestSetKeyDistinguishesPatternOrderAndSeparators pins the set module cache's
// key against the collision below.
//
// The cache is keyed by the caller, and the four set callers used to build the
// key with fmt.Sprintf("%v", pats). %v joins a []string with a SPACE, so
// {" ", ""} and {"", " "} both render as "[  ]" — one set then silently got
// the other set's compiled module. A pattern's INDEX is its id, so swapping
// two patterns swaps every id the set reports, and the harness checked one
// module's answers against the other's oracle. Five crasher files came out of
// that, all of which passed when replayed alone.
//
// Joining on a separator does not fix it either, whatever the separator: the
// fuzzer mutates arbitrary bytes and Go's regexp compiles a NUL as an ordinary
// literal, so a NUL join makes {"a\x00b"} and {"a", "b"} collide exactly as %v
// did. Only a length prefix is injective.
//
// The pairs below are the ones that actually collided under each rejected
// scheme, so this test fails if anyone reverts to either.
func TestSetKeyDistinguishesPatternOrderAndSeparators(t *testing.T) {
	pairs := [][2][]string{
		{{" ", ""}, {"", " "}},     // the raw crashers: %v renders both "[  ]"
		{{"a\x00b"}, {"a", "b"}},   // a NUL join would collide here
		{{"a b"}, {"a", "b"}},      // a space join would collide here
		{{""}, {"", ""}},           // arity must matter
		{{"ab", "c"}, {"a", "bc"}}, // the split point must matter
		{{"1:x"}, {"", "x"}},       // the length prefix must not be forgeable
	}
	for _, p := range pairs {
		if a, b := setKey(p[0]), setKey(p[1]); a == b {
			t.Errorf("setKey(%q) == setKey(%q) == %q: two different sets share one cache entry", p[0], p[1], a)
		}
	}
}

// TestSetCacheReturnsThePatternsOwnModule is the end-to-end half: the two
// orderings must not hand back the same bytes, which is what the crashers saw.
func TestSetCacheReturnsThePatternsOwnModule(t *testing.T) {
	first, _, err := compileCaps([]string{" ", ""}, false)
	if err != nil {
		t.Fatalf("compile {\" \", \"\"}: %v", err)
	}
	second, _, err := compileCaps([]string{"", " "}, false)
	if err != nil {
		t.Fatalf("compile {\"\", \" \"}: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal(`compileCaps([" ", ""]) and compileCaps(["", " "]) returned the same module: ` +
			`the cache key does not separate them, so one set is answering with the other's pattern ids`)
	}
}
