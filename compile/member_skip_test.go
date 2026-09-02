package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestMemberSkipIsVisibleAndHintGated pins the mechanism's VISIBILITY and its
// gate, which is the guard the two drifted cases in this project lacked.
//
// `set-shufti-dense-harm` was labelled a Shufti target while compiling to
// Teddy, and `tdfa-bulk-skip-word-class` was labelled a TDFA target while
// compiling to a Compiled DFA. Both sat wrong for weeks because nothing
// asserted which body they got. --diag-json now reports the member-skip
// counts, and this test asserts they say what the emitter did:
//
//   - hinted, eligible shape -> a non-zero count;
//   - neutral, same shape     -> zero, because the skip is hint-gated;
//   - hinted, WIDE self-loop  -> also non-zero, since the rectangle-cover
//     encoding serves any width (this used to be the refusal case).
//
// A future change that silently stops emitting the skip fails the first case
// rather than merely getting slower.
func TestMemberSkipIsVisibleAndHintGated(t *testing.T) {
	// 40 patterns behind one shared literal, each with a one-byte self-loop
	// tail — the shape that packs into a single sparse bucket.
	eligible := make([]config.RegexEntry, 40)
	for i := range eligible {
		eligible[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`union[ \t]+k%02da+`, i),
		}
	}
	// Same shape, but the tail self-loop is \w — 63 bytes. Under the old
	// one-bit-per-member encoding the forty BODY states were REFUSED as
	// oversized and only the shared `[ \t]+` run stayed eligible. The
	// rectangle cover spends a bit per nibble ROW instead, so \w is one pair
	// like every other class and those forty states are now served too.
	wide := make([]config.RegexEntry, 40)
	for i := range wide {
		wide[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`union[ \t]+k%02d\w+`, i),
		}
	}

	count := func(entries []config.RegexEntry, hints []string) int {
		cfg := config.BuildConfig{
			Regexps: entries,
			Sets: []config.SetConfig{{
				Name:     "s",
				Find:     "s_find",
				Patterns: config.PatternSelector{All: true},
				Hints:    hints,
			}},
		}
		_, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		n := 0
		for _, d := range diags {
			for _, b := range d.Buckets {
				n += b.MemberSkipStates
			}
		}
		return n
	}

	if got := count(eligible, []string{"prefer-match"}); got == 0 {
		t.Error("hinted eligible set reports no member-skip states — either the skip stopped " +
			"being emitted, or it stopped being reported; both are silent failures")
	}
	if got := count(eligible, nil); got != 0 {
		t.Errorf("neutral set reports %d member-skip states, want 0 — the skip must stay "+
			"hint-gated, since it costs a few percent on buckets with no runs to skip", got)
	}
	elig, wideN := count(eligible, []string{"prefer-match"}), count(wide, []string{"prefer-match"})
	if wideN < elig {
		t.Errorf("the \\w-tailed set reports %d member-skip states against %d for the "+
			"one-byte-tailed set — a 63-byte self-loop is one nibble pair under the "+
			"rectangle cover, so it must be served, not refused", wideN, elig)
	}
}

// TestMemberSetEncodingIsExact checks encodeMemberSet's claim that its
// nibble tables are EXACT, not approximate.
//
// The Shufti family is usually a prefilter where a false positive is merely
// wasted work. Here it decides whether a byte keeps the walk in the same
// state, so a false positive skips a byte that should have left the state —
// a wrong answer, not a slow one.
//
// The last three sets are ones the former one-bit-per-member encoding could
// not express at all: \w (63), a `[^\n]`-style tail (255) and one byte in
// every nibble row (16 distinct rows, the cover's worst case, two pairs).
func TestMemberSetEncodingIsExact(t *testing.T) {
	wordClass := func() []byte {
		var out []byte
		for c := 0; c < 256; c++ {
			b := byte(c)
			if b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
				out = append(out, b)
			}
		}
		return out
	}()
	notNewline := func() []byte {
		var out []byte
		for c := 0; c < 256; c++ {
			if byte(c) != '\n' {
				out = append(out, byte(c))
			}
		}
		return out
	}()
	sets := [][]byte{
		{'a'},
		{'a', 'b', 'c'},
		[]byte("0123456789"),
		[]byte("abcdefghijklmnop"),
		{0x00, 0xFF, 0x0F, 0xF0},
		{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98},
		wordClass,
		notNewline,
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}
	for _, set := range sets {
		tab := encodeMemberSet(set)
		in := map[byte]bool{}
		for _, m := range set {
			in[m] = true
		}
		for b := 0; b < 256; b++ {
			by := byte(b)
			var hit bool
			for pair := 0; pair < memberSetPairs; pair++ {
				lo := tab[pair*32+int(by&0x0F)]
				hi := tab[pair*32+16+int(by>>4)]
				if lo&hi != 0 {
					hit = true
				}
			}
			if hit != in[by] {
				t.Errorf("set of %d bytes: %#02x reported member=%v, want %v",
					len(set), by, hit, in[by])
			}
		}
	}
}

// TestMemberSetsAdmitWide confirms a state with a wide self-loop set is now
// SERVED, and served exactly.
//
// This is the inverse of the assertion that stood here while the encoding
// spent one bit per member: a set of more than sixteen bytes then had to be
// refused, because truncating it would have strided over bytes that are NOT
// members and left the state without noticing — the silent-wrong-answer
// version of this feature. The rectangle cover removes the ceiling rather
// than the danger, so the exactness check below is the part that matters.
func TestMemberSetsAdmitWide(t *testing.T) {
	for _, width := range []int{20, 63, 200, 255} {
		tbl := &dfaTable{numStates: 2, transitions: make([]int, 2*256)}
		for i := range tbl.transitions {
			tbl.transitions[i] = -1
		}
		for b := 0; b < width; b++ {
			tbl.transitions[1*256+b] = 1 // global state 1 self-loops on `width` bytes
		}
		idTab, setTab := buildMemberSets(tbl, 3)
		if len(setTab) != memberSetBytes {
			t.Fatalf("width %d: got %d table bytes, want one set of %d",
				width, len(setTab), memberSetBytes)
		}
		// idTab is indexed by WASM state, which is the global state plus one
		// (state 0 is dead), so global state 1 is entry 2.
		if idTab == nil || idTab[2] != 1 {
			t.Fatalf("width %d: the self-loop state was not given set id 1: idTab=%v", width, idTab)
		}
		for b := 0; b < 256; b++ {
			by := byte(b)
			var hit bool
			for pair := 0; pair < memberSetPairs; pair++ {
				if setTab[pair*32+int(by&0x0F)]&setTab[pair*32+16+int(by>>4)] != 0 {
					hit = true
				}
			}
			if want := b < width; hit != want {
				t.Fatalf("width %d: byte %#02x reported member=%v, want %v",
					width, by, hit, want)
			}
		}
	}

	// A state with no self-loop at all still produces nothing, so a bucket
	// that can never skip pays no per-byte dispatch.
	tbl := &dfaTable{numStates: 2, transitions: make([]int, 2*256)}
	for i := range tbl.transitions {
		tbl.transitions[i] = -1
	}
	if idTab, setTab := buildMemberSets(tbl, 3); idTab != nil || setTab != nil {
		t.Error("a table with no self-loop state produced member tables")
	}
}
