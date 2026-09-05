package compile

import (
	"math/rand"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
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

// TestShuftiMaskPolarities pins the contract between the two emitters: they
// must differ in the final lane comparison and in NOTHING else.
//
// The stop polarity replaced a member mask followed by `i32.const 0xFFFF;
// i32.xor`. That the xor is redundant rests on i8x16.bitmask zero-extending
// its result, so the complement over the 16 relevant lanes is exactly what
// `lane == 0` produces. If someone reintroduces the xor, or flips the compare
// in the wrong emitter, every bulk skip in the compiler advances to the first
// byte that IS a member — a walk that stops immediately and never strides,
// which costs performance silently rather than failing.
func TestShuftiMaskPolarities(t *testing.T) {
	const (
		opEq = 0x23 // i8x16.eq, after the 0xFD prefix
		opNe = 0x24 // i8x16.ne
	)
	for _, set := range [][]byte{
		[]byte("abcdefghijklmnopqrstuvwxyz"),
		[]byte("0123456789"),
		{0x00, 0x7F, 0x80, 0xFF},
	} {
		member := emitShuftiPrefixCheck(nil, set, 7)
		stop := emitShuftiStopMask(nil, set, 7)
		if len(member) != len(stop) {
			t.Fatalf("polarities differ in length: member %d, stop %d — the stop "+
				"mask must be the same emission with one opcode changed",
				len(member), len(stop))
		}
		diffs := 0
		for i := range member {
			if member[i] != stop[i] {
				diffs++
				if member[i] != opNe || stop[i] != opEq {
					t.Fatalf("byte %d differs as %#02x/%#02x, want the compare "+
						"opcode %#02x/%#02x", i, member[i], stop[i], opNe, opEq)
				}
			}
		}
		if diffs != 1 {
			t.Fatalf("polarities differ in %d bytes, want exactly 1 (the compare)", diffs)
		}
		// No 0xFFFF constant may survive in either emission: its presence is
		// the signature of the inversion this replaced.
		for i := 0; i+3 < len(stop); i++ {
			if stop[i] == 0x41 && stop[i+1] == 0xFF && stop[i+2] == 0xFF && stop[i+3] == 0x03 {
				t.Fatalf("stop mask still emits i32.const 0xFFFF at byte %d", i)
			}
		}
	}
}

// TestShuftiStopMaskEmptySet pins the empty-set constant, which is the one
// place the two polarities legitimately differ by more than an opcode: with no
// members every lane is a non-member, so the stop mask's honest answer is
// 0xFFFF and the member mask's is 0.
func TestShuftiStopMaskEmptySet(t *testing.T) {
	if got := emitShuftiPrefixCheck(nil, nil, 7); len(got) != 2 || got[0] != 0x41 || got[1] != 0x00 {
		t.Errorf("member mask on empty set = % x, want i32.const 0", got)
	}
	got := emitShuftiStopMask(nil, nil, 7)
	if len(got) == 0 || got[0] != 0x41 {
		t.Fatalf("stop mask on empty set = % x, want an i32.const", got)
	}
	if v, _, err := utils.DecodeSLEB128(got[1:]); err != nil || v != 0xFFFF {
		t.Errorf("stop mask on empty set = i32.const %d (err %v), want 65535", v, err)
	}
}
