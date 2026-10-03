package abi

import (
	"encoding/binary"
	"math"
	"testing"
)

// This package is a handful of constants plus the descriptor writer, so these
// tests pin the INVARIANTS the doc
// comment states rather than the literal values — the values are arbitrary,
// but every property below is load-bearing for a host trying to tell "the
// input does not match" from "the engine gave up".

// TestSentinelsAreDistinguishable covers the reason the package exists. A host
// that cannot separate the two reports BTStackOverflow as "no match", which is
// a false negative that scales with input length and carries no diagnostic.
func TestSentinelsAreDistinguishable(t *testing.T) {
	if NoMatch == BTStackOverflow {
		t.Fatalf("the two sentinels collide at %d; a host cannot tell an unknown answer from a negative one", NoMatch)
	}
	for _, c := range []struct {
		name string
		v    int
	}{{"NoMatch", NoMatch}, {"BTStackOverflow", BTStackOverflow}} {
		if c.v >= 0 {
			t.Errorf("%s = %d: a non-negative sentinel is indistinguishable from a match end position", c.name, c.v)
		}
	}
}

// TestSentinelsSurviveSignExtension covers the i64-returning find exports,
// which emit these as i64.const — so the i32 and i64 spellings must denote the
// same value. A sentinel that changed meaning on widening would be caught by
// nothing else: the stubs read i64, the emitters write the i32 constant.
func TestSentinelsSurviveSignExtension(t *testing.T) {
	if got := int64(int32(NoMatch)); got != int64(NoMatch) {
		t.Errorf("NoMatch sign-extends to %d, want %d", got, NoMatch)
	}
	if got := int64(int32(BTStackOverflow)); got != int64(BTStackOverflow) {
		t.Errorf("BTStackOverflow sign-extends to %d, want %d", got, BTStackOverflow)
	}
}

// TestPackedFindResultNeverCollides covers the doc's central claim: a genuine
// packed (start << 32 | end) always has bit 63 clear, because start is a
// non-negative i32. If that ever stopped holding, a real match at some extreme
// position would be read as an error by every generated stub — a wrong answer
// no corpus run would surface, since the corpus never reaches 2^31 bytes.
func TestPackedFindResultNeverCollides(t *testing.T) {
	starts := []int32{0, 1, 2, math.MaxInt32 - 1, math.MaxInt32}
	ends := []uint32{0, 1, 2, math.MaxInt32, math.MaxUint32 - 1, math.MaxUint32}
	for _, s := range starts {
		for _, e := range ends {
			packed := int64(s)<<32 | int64(e)
			if packed < 0 {
				t.Errorf("packed(start=%d, end=%d) = %d is negative", s, e, packed)
			}
			if packed == int64(NoMatch) || packed == int64(BTStackOverflow) {
				t.Errorf("packed(start=%d, end=%d) = %d collides with a sentinel", s, e, packed)
			}
		}
	}
}

// TestWriteFindScratchLaysTheDocumentedLayout is the only executable check that
// the descriptor's four fields land where every consumer expects them.
//
// The layout is agreed by five Go harnesses, six stub generators emitting
// source text in other languages, and the WASM prologue compile/ splices into
// every `find` — and a field written at the wrong offset is a wrong POINTER, not
// a compile error. The magic word turns a stale caller into a trap; it cannot
// help a writer that puts the gate pointer where the cache goes.
//
// The write is placed at a non-zero offset, because a `put` that forgot to add
// `off` is correct at 0 and wrong everywhere else — which is exactly how the
// harnesses call it.
func TestWriteFindScratchLaysTheDocumentedLayout(t *testing.T) {
	const off = 64
	buf := make([]byte, off+FindScratchBytes+8)
	// A canary past the descriptor: writing more than FindScratchBytes would
	// corrupt whatever the caller put next to it, which in every harness is
	// live memory.
	for i := off + FindScratchBytes; i < len(buf); i++ {
		buf[i] = 0xAB
	}
	WriteFindScratch(buf, off, 0x1111, 0x2222, 0x3333)

	read := func(at int) uint32 { return binary.LittleEndian.Uint32(buf[off+at:]) }
	for _, c := range []struct {
		name string
		at   int
		want uint32
	}{
		{"magic", FindScratchMagicOff, FindScratchMagic},
		{"gate_ptr", FindScratchGateOff, 0x1111},
		{"cache_ptr", FindScratchCacheOff, 0x2222},
		{"cache_len", FindScratchCacheLenOff, 0x3333},
	} {
		if got := read(c.at); got != c.want {
			t.Errorf("%s at +%d = %#x, want %#x", c.name, c.at, got, c.want)
		}
	}
	for i := off + FindScratchBytes; i < len(buf); i++ {
		if buf[i] != 0xAB {
			t.Fatalf("byte %d past the descriptor was overwritten: the write is wider than FindScratchBytes", i-off)
		}
	}

	// Declining the cache is `0, 0` and must leave two honest zeros rather than
	// a stale value: the same buffer is reused across drives in every harness.
	WriteFindScratch(buf, off, 0x4444, 0, 0)
	if got := read(FindScratchCacheOff); got != 0 {
		t.Errorf("declined cache_ptr = %#x, want 0", got)
	}
	if got := read(FindScratchCacheLenOff); got != 0 {
		t.Errorf("declined cache_len = %#x, want 0", got)
	}
	if got := read(FindScratchGateOff); got != 0x4444 {
		t.Errorf("rewritten gate_ptr = %#x, want 0x4444", got)
	}

	// The second form: its own magic, the same four fields, then blocks_ptr —
	// and nothing past FindScratchBlocksBytes.
	big := make([]byte, off+FindScratchBlocksBytes+8)
	for i := off + FindScratchBlocksBytes; i < len(big); i++ {
		big[i] = 0xAB
	}
	WriteFindScratchBlocks(big, off, 0x1111, 0x2222, 0x3333, 0x5555, 7)
	readB := func(at int) uint32 { return binary.LittleEndian.Uint32(big[off+at:]) }
	for _, c := range []struct {
		name string
		at   int
		want uint32
	}{
		{"magic", FindScratchMagicOff, FindScratchMagicBlocks},
		{"gate_ptr", FindScratchGateOff, 0x1111},
		{"cache_ptr", FindScratchCacheOff, 0x2222},
		{"cache_len", FindScratchCacheLenOff, 0x3333},
		{"blocks_ptr", FindScratchBlocksOff, 0x5555},
		{"blocks_n", FindScratchBlocksCountOff, 7},
	} {
		if got := readB(c.at); got != c.want {
			t.Errorf("blocks form: %s at +%d = %#x, want %#x", c.name, c.at, got, c.want)
		}
	}
	for i := off + FindScratchBlocksBytes; i < len(big); i++ {
		if big[i] != 0xAB {
			t.Fatalf("byte %d past the blocks descriptor was overwritten", i-off)
		}
	}
}

// TestSearchBlockLayout pins the per-search block: every field inside the
// block, none overlapping another, the i64 fields 8-aligned, and every offset
// below 128 — the compiler writes them as one-byte memarg offsets, and the
// generated stubs carry them as literal constants, so a field that moved would
// silently read another's bytes.
func TestSearchBlockLayout(t *testing.T) {
	fields := []struct {
		name      string
		off, size int
	}{
		{"wasted", SearchWastedOff, 8}, {"first", SearchFirstOff, 4}, {"armed", SearchArmedOff, 4},
		{"resume", SearchResumeOff, 4}, {"ptr", SearchPtrOff, 4}, {"len", SearchLenOff, 4},
		{"notes", SearchNotesOff, 4}, {"high", SearchHighOff, 4}, {"seen", SearchSeenOff, 4},
		{"bt_state", SearchBTStateOff, 4}, {"notes_cap", SearchNotesCapOff, 4},
		{"bt_budget", SearchBTBudgetOff, 8}, {"bt_memo", SearchBTMemoOff, 4},
		{"bt_cap", SearchBTCapOff, 4}, {"bt_memo_cap", SearchBTMemoCapOff, 4},
		{"far", SearchFarOff, 4},
	}
	used := make([]string, SearchBlockBytes)
	for _, f := range fields {
		if f.off < 0 || f.off+f.size > SearchBlockBytes || f.off >= 128 {
			t.Errorf("%s at %d..%d is outside the %d-byte block", f.name, f.off, f.off+f.size, SearchBlockBytes)
			continue
		}
		if f.off%f.size != 0 {
			t.Errorf("%s at %d is not %d-aligned", f.name, f.off, f.size)
		}
		for i := f.off; i < f.off+f.size; i++ {
			if used[i] != "" {
				t.Errorf("%s overlaps %s at byte %d", f.name, used[i], i)
			}
			used[i] = f.name
		}
	}
	if SearchBlockAlign != 8 || SearchBlockBytes%SearchBlockAlign != 0 {
		t.Errorf("block %d bytes, %d-aligned: the i64 fields need 8", SearchBlockBytes, SearchBlockAlign)
	}
}
