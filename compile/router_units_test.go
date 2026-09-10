package compile

import (
	"bytes"
	"testing"
)

// Unit coverage for the small routers and pure helpers that decide what the
// emitters emit. They are cheap to reach directly and expensive to reach
// through a compile, because each needs a DFA of a particular shape — so the
// end-to-end corpora exercise the common answer and never the tie-breaks.

// dwTable builds a synthetic dfaTable with the given per-state self-loop byte
// counts. State s self-loops on the first selfLoops[s] bytes and leaves on the
// rest, which is exactly the shape both walk routers score.
func dwTable(selfLoops []int, accepting bool) *dfaTable {
	n := len(selfLoops)
	t := &dfaTable{
		numStates:       n,
		transitions:     make([]int, n*256),
		acceptStates:    map[int]uint64{},
		midAcceptStates: map[int]uint64{},
	}
	for s := 0; s < n; s++ {
		for b := 0; b < 256; b++ {
			if b < selfLoops[s] {
				t.transitions[s*256+b] = s // self-loop
			} else {
				t.transitions[s*256+b] = (s + 1) % n // leaves
			}
		}
		if accepting {
			t.acceptStates[s] = 1
		}
	}
	return t
}

// dominantWalkStates ranks candidate states by self-loop coverage, widest
// first, and keeps at most dominantMaxStates of them. Both the ordering and
// the cap decide which state the emitted bulk skip is built around, so a wrong
// answer is a silent performance loss rather than a failure — the kind nothing
// else notices.
func TestDominantWalkStatesOrdersAndCaps(t *testing.T) {
	// Three qualifying states, deliberately in ASCENDING coverage order, so
	// the result is only right if the ranking actually reorders them.
	tab := dwTable([]int{250, 252, 254}, false)
	got := dominantWalkStates(tab)

	if len(got) != dominantMaxStates {
		t.Fatalf("got %d states, want %d (the cap) — three qualified",
			len(got), dominantMaxStates)
	}
	if got[0].Coverage < got[1].Coverage {
		t.Errorf("states came back widest-last: %d then %d",
			got[0].Coverage, got[1].Coverage)
	}
	// The widest is state index 2, emitted as WASM state 3.
	if got[0].WASMState != 3 || got[0].Coverage != 254 {
		t.Errorf("widest state = WASM %d coverage %d, want 3 / 254",
			got[0].WASMState, got[0].Coverage)
	}
	// Below the self-loop floor nothing qualifies at all. Two states, because
	// with one the "leaves" edge wraps back to the same state and every byte
	// would self-loop.
	if s := dominantWalkStates(dwTable([]int{dominantSelfLoopMin - 1, 0}, false)); len(s) != 0 {
		t.Errorf("a state with %d self-loops qualified; the floor is %d",
			dominantSelfLoopMin-1, dominantSelfLoopMin)
	}
	if s := dominantWalkStates(nil); s != nil {
		t.Error("a nil table produced states")
	}
	if s := dominantWalkStates(&dfaTable{}); s != nil {
		t.Error("a zero-state table produced states")
	}
}

// memberWalkStates is the same router one level down, for the sparse member
// self-loop skip: it looks only at ACCEPTING states and only at narrow
// self-loops (memberSelfLoopMax), because the skip's whole premise is that a
// run through such a state changes nothing but the position.
func TestMemberWalkStatesOrdersAndGuards(t *testing.T) {
	if s := memberWalkStates(nil); s != nil {
		t.Error("a nil table produced states")
	}
	if s := memberWalkStates(&dfaTable{}); s != nil {
		t.Error("a zero-state table produced states")
	}

	// Two accepting states with 1 and 2 self-loop bytes, ascending, so the
	// ranking has to reorder them. Both are inside memberSelfLoopMax.
	tab := dwTable([]int{1, 2}, true)
	got := memberWalkStates(tab)
	if len(got) != 2 {
		t.Fatalf("got %d states, want 2", len(got))
	}
	if got[0].Coverage < got[1].Coverage {
		t.Errorf("states came back widest-last: %d then %d",
			got[0].Coverage, got[1].Coverage)
	}

	// A NON-accepting state is not a member-skip candidate however narrow its
	// self-loop: the skip suppresses per-byte recording, and there is nothing
	// to suppress where nothing accepts.
	if s := memberWalkStates(dwTable([]int{1, 2}, false)); len(s) != 0 {
		t.Errorf("%d non-accepting states qualified for the member skip", len(s))
	}
	// And a self-loop wider than the cap is refused.
	if s := memberWalkStates(dwTable([]int{memberSelfLoopMax + 1}, true)); len(s) != 0 {
		t.Errorf("a %d-byte self-loop qualified; the cap is %d",
			memberSelfLoopMax+1, memberSelfLoopMax)
	}
}

// emitOverlapDPTransition reads the transition table two ways, and which one it
// emits is a property of the LAYOUT rather than of the set: a u16 table with
// duplicate rows carries a rowMap, and the walk must go through it. Emitting
// the direct form against a deduplicated table indexes by state into a table
// indexed by row — a valid module reading the wrong cells.
func TestEmitOverlapDPTransitionRowDedup(t *testing.T) {
	base := &dfaLayout{tableOff: 4096}
	direct := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: base}, 0, 3, 4, 5)

	deduped := &dfaLayout{tableOff: 4096, useRowDedup: true, rowMapOff: 2048}
	viaRowMap := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: deduped}, 0, 3, 4, 5)

	if len(viaRowMap) <= len(direct) {
		t.Errorf("the rowMap form is %d bytes and the direct one %d; the extra "+
			"indirection must emit strictly more", len(viaRowMap), len(direct))
	}
	// The rowMap base appears only in the deduplicated form.
	rowMapConst := []byte{0x41, 0x80, 0x10} // i32.const 2048, SLEB128
	if !bytes.Contains(viaRowMap, rowMapConst) {
		t.Error("the rowMap form never loads rowMapOff")
	}
	if bytes.Contains(direct, rowMapConst) {
		t.Error("the direct form loads a rowMap it was not given")
	}

	// Byte-class compression narrows the stride from 256 to numClasses, which
	// is the other half of the address computation.
	compressed := &dfaLayout{tableOff: 4096, useCompression: true, numClasses: 7}
	comp := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: compressed}, 0, 3, 4, 5)
	if bytes.Equal(comp, direct) {
		t.Error("compression did not change the emitted stride")
	}
}

// shuftiPrefixPlan is the frontend chooser for the first-byte prefilter. The
// widest band exists only under prefer-no-match AND only where the caller has
// reserved the dense-switch locals, because the switch is what bounds a wrong
// bet — so `canAdapt` is a promise about the frame, not a preference.
func TestShuftiPrefixPlanBands(t *testing.T) {
	set := func(n int) []byte {
		s := make([]byte, n)
		for i := range s {
			s[i] = byte(i)
		}
		return s
	}

	// At or below 16 the scalar compare chain wins outright.
	if use, dense := shuftiPrefixPlan(set(16), true, true); use || dense {
		t.Errorf("16 first bytes selected Shufti (use=%v dense=%v)", use, dense)
	}
	// The wide band: past maxShuftiFirstBytes, only with both flags.
	wide := set(maxShuftiFirstBytes + 1)
	if use, dense := shuftiPrefixPlan(wide, true, true); !use || !dense {
		t.Errorf("the wide band was refused with both flags (use=%v dense=%v)", use, dense)
	}
	if use, _ := shuftiPrefixPlan(wide, true, false); use {
		t.Error("the wide band was taken without the dense-switch locals reserved")
	}
	if use, _ := shuftiPrefixPlan(wide, false, true); use {
		t.Error("the wide band was taken without prefer-no-match")
	}
	// Past even the widened ceiling, nothing.
	if use, _ := shuftiPrefixPlan(set(maxShuftiFirstBytesLNM+1), true, true); use {
		t.Errorf("a set of %d first bytes selected Shufti", maxShuftiFirstBytesLNM+1)
	}
}

// firstByteSet powers the per-pattern eligibility masks, and its contract is
// "nil means undetermined, assume every byte". A non-ASCII rune is led by a
// UTF-8 lead byte rather than by the rune, so deriving a first BYTE from it
// would be wrong — the function gives up instead, and a caller that took a
// derived answer here would skip positions where a match can begin.
func TestFirstByteSetGivesUpOnNonASCII(t *testing.T) {
	if got := firstByteSet(`\x{00e9}cafe`); got != nil {
		t.Error("a pattern starting with a non-ASCII rune produced a first-byte set")
	}
	if got := firstByteSet(`[`); got != nil {
		t.Error("an unparseable pattern produced a first-byte set")
	}
	// The positive control: an ordinary ASCII pattern resolves, and only to
	// the bytes that can actually lead it.
	got := firstByteSet(`abc`)
	if got == nil {
		t.Fatal("an ASCII literal produced no first-byte set")
	}
	if !got['a'] {
		t.Error("'a' is not marked startable for /abc/")
	}
	for _, b := range []byte{'b', 'c', 'z'} {
		if got[b] {
			t.Errorf("%q is marked startable for /abc/", b)
		}
	}
}
