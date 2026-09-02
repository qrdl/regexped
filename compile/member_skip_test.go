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
//   - hinted, eligible shape  -> a non-zero count;
//   - neutral, same shape     -> zero, because the skip is hint-gated;
//   - hinted, ineligible shape (self-loop wider than memberMaxBytes) -> zero.
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
	// Same shape, but the tail self-loop is \w — 63 bytes, past
	// memberMaxBytes. The forty BODY states are therefore refused. The set
	// still has one eligible state, the shared `[ \t]+` run, and that is
	// correct: refusal is per state, not per bucket.
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
	if wideN >= elig {
		t.Errorf("widening the body self-loop past memberMaxBytes (%d) left %d skip states "+
			"against %d for the narrow shape — the oversized body states must be REFUSED, "+
			"not truncated, since a truncated set would stride over non-members",
			memberMaxBytes, wideN, elig)
	}
}

// TestMemberSetEncodingIsExact checks encodeMemberSet's claim that its
// one-bit-per-member nibble tables are EXACT, not approximate.
//
// The Shufti family is usually a prefilter where a false positive is merely
// wasted work. Here it decides whether a byte keeps the walk in the same
// state, so a false positive skips a byte that should have left the state —
// a wrong answer, not a slow one.
func TestMemberSetEncodingIsExact(t *testing.T) {
	sets := [][]byte{
		{'a'},
		{'a', 'b', 'c'},
		[]byte("0123456789"),
		[]byte("abcdefghijklmnop"), // memberMaxBytes
		{0x00, 0xFF, 0x0F, 0xF0},
		{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98},
	}
	for _, set := range sets {
		if len(set) > memberMaxBytes {
			t.Fatalf("test set of %d exceeds memberMaxBytes %d", len(set), memberMaxBytes)
		}
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
				t.Errorf("set %v: byte %#02x reported member=%v, want %v", set, by, hit, in[by])
			}
		}
	}
}

// TestMemberSetsRefuseOversized confirms a state whose self-loop set is wider
// than memberMaxBytes is left alone rather than truncated.
//
// Truncating would be the silent-wrong-answer version of this feature: the
// skip would stride over bytes that are NOT members and leave the state
// without noticing.
func TestMemberSetsRefuseOversized(t *testing.T) {
	// 20 distinct self-loop bytes, past the 16 the encoding can hold.
	tbl := &dfaTable{numStates: 2, transitions: make([]int, 2*256)}
	for i := range tbl.transitions {
		tbl.transitions[i] = -1
	}
	for b := 0; b < 20; b++ {
		tbl.transitions[1*256+b] = 1 // state 1 self-loops on 20 bytes
	}
	idTab, setTab := buildMemberSets(tbl, 3)
	if len(setTab) != 0 {
		t.Fatalf("a %d-byte self-loop set was admitted; memberMaxBytes is %d", 20, memberMaxBytes)
	}
	if idTab != nil {
		t.Error("no eligible state, so no id table should be produced")
	}
}
