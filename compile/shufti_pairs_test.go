package compile

import (
	"math/rand"
	"testing"
)

// decodeShuftiPairs reproduces, in Go, exactly what the emitted SIMD does to
// one byte: swizzle both nibble tables of every pair, AND them, OR the pairs,
// and report whether anything survived. Testing against this rather than
// against buildShuftiPairs' own internals is the point — it is the emitted
// arithmetic that has to be exact, not the bookkeeping that produced it.
func decodeShuftiPairs(pairs [][2][16]byte, c byte) bool {
	var merged byte
	for _, p := range pairs {
		merged |= p[0][c&0x0F] & p[1][c>>4]
	}
	return merged != 0
}

// TestBuildShuftiPairsExact is the correctness contract for the rectangle
// cover: for EVERY byte 0..255 the emitted test must agree with real set
// membership. A false positive here is not wasted work — the same primitive
// decides whether a byte keeps a set walk in its state (see
// encodeMemberSet), where a false positive skips a byte that should have
// left the state and reports the wrong extent, silently.
func TestBuildShuftiPairsExact(t *testing.T) {
	check := func(t *testing.T, name string, set []byte) {
		t.Helper()
		var want [256]bool
		for _, c := range set {
			want[c] = true
		}
		pairs := buildShuftiPairs(set)
		if len(pairs) > 2 {
			t.Fatalf("%s: got %d pairs, want <= 2 (16 rows cannot need more)", name, len(pairs))
		}
		for c := 0; c < 256; c++ {
			if got := decodeShuftiPairs(pairs, byte(c)); got != want[c] {
				t.Fatalf("%s: byte %#02x membership = %v, want %v", name, c, got, want[c])
			}
		}
	}

	rangeSet := func(lo, hi byte) []byte {
		var out []byte
		for c := int(lo); c <= int(hi); c++ {
			out = append(out, byte(c))
		}
		return out
	}
	union := func(sets ...[]byte) []byte {
		var out []byte
		for _, s := range sets {
			out = append(out, s...)
		}
		return out
	}

	// The classes this compiler actually meets, plus the structural edges.
	named := map[string][]byte{
		"empty":            nil,
		"single":           {'a'},
		"a-z":              rangeSet('a', 'z'),
		"A-Za-z":           union(rangeSet('A', 'Z'), rangeSet('a', 'z')),
		"word":             union(rangeSet('0', '9'), rangeSet('A', 'Z'), rangeSet('a', 'z'), []byte{'_'}),
		"printable-nosp":   rangeSet('!', '~'),
		"printable":        rangeSet(' ', '~'),
		"a-z0-9":           union(rangeSet('0', '9'), rangeSet('a', 'z')),
		"control":          rangeSet(0x00, 0x1f),
		"high":             rangeSet(0x80, 0xff),
		"all":              rangeSet(0x00, 0xff),
		"nul-only":         {0x00},
		"ff-only":          {0xff},
		"nibble-corners":   {0x00, 0x0f, 0xf0, 0xff},
		"punct":            []byte("<>{}[]|`"),
		"one-per-row":      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"eight-rows-alike": {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70},
	}
	for name, set := range named {
		check(t, name, set)
	}

	// "one-per-row" above is the worst case for the cover: 16 rows, every mask
	// distinct, so it must use both pairs. If a future change made the cover
	// coarser this assertion is what notices.
	if n := len(buildShuftiPairs(named["one-per-row"])); n != 2 {
		t.Errorf("16 distinct row masks used %d pairs, want exactly 2", n)
	}
	// The everyday classes must all collapse to one pair — that IS the
	// optimisation, and a regression to two would silently halve it.
	for _, name := range []string{"a-z", "A-Za-z", "word", "printable", "printable-nosp", "a-z0-9", "all"} {
		if n := len(buildShuftiPairs(named[name])); n != 1 {
			t.Errorf("%s used %d pairs, want 1", name, n)
		}
	}

	// Random sets, including sets far wider than the old one-bit-per-member
	// encoding could express at all.
	rng := rand.New(rand.NewSource(20260902))
	for i := 0; i < 500; i++ {
		n := 1 + rng.Intn(256)
		perm := rng.Perm(256)[:n]
		set := make([]byte, n)
		for j, v := range perm {
			set[j] = byte(v)
		}
		check(t, "random", set)
	}
}

// TestEmitShuftiPrefixCheckEmpty pins the empty-set early return: the emitter
// must leave an i32 on the stack even with nothing to test, or the enclosing
// body fails WASM validation rather than merely answering wrongly.
func TestEmitShuftiPrefixCheckEmpty(t *testing.T) {
	got := emitShuftiPrefixCheck(nil, nil, 9)
	if len(got) != 2 || got[0] != 0x41 || got[1] != 0x00 {
		t.Errorf("emitShuftiPrefixCheck(empty set) = % x, want 41 00 (i32.const 0)", got)
	}
}
