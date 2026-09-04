package compile

import "testing"

// ── The build-time invariant guards ────────────────────────────────────────
//
// Several emitters protect themselves with a panic rather than a fallback,
// deliberately: the alternative in each case is a module that VALIDATES and
// answers wrongly. blockStack's own header makes the argument — a `br 2` where
// `br 3` was meant is well-typed and branches somewhere plausible, and nothing
// but a full corpus run catches it.
//
// A guard that has never fired is a guard nobody has checked. These assert the
// panic happens AND that its message names the problem, since these messages
// are read by whoever is mid-refactor when one finally does fire.

// TestBlockStackGuards covers the two ways a branch-depth question can be
// wrong: asking about a label that is not open, and popping a level that was
// never pushed. Both are emitter bugs that a returned number would hide.
func TestBlockStackGuards(t *testing.T) {
	t.Run("depth of an unopened label", func(t *testing.T) {
		var s blockStack
		s.Push("outer")
		mustPanic(t, "not an open block", func() { s.Depth("nope") })
	})
	t.Run("pop with nothing open", func(t *testing.T) {
		var s blockStack
		mustPanic(t, "no level open", func() { s.Pop() })
	})
	t.Run("depth counts outward", func(t *testing.T) {
		var s blockStack
		s.Push("a")
		s.Push("b")
		s.Push("c")
		if d := s.Depth("c"); d != 0 {
			t.Errorf("Depth(innermost) = %d, want 0", d)
		}
		if d := s.Depth("a"); d != 2 {
			t.Errorf("Depth(outermost of 3) = %d, want 2", d)
		}
		s.Pop()
		if d := s.Depth("b"); d != 0 {
			t.Errorf("after Pop, Depth(new innermost) = %d, want 0", d)
		}
	})
	t.Run("depth past a byte is refused", func(t *testing.T) {
		// A `br` operand is LEB128 in the binary but every emitter here writes
		// it as a single byte, so a depth past 255 would be truncated into a
		// branch to somewhere else entirely. There is no legitimate emitter
		// this deep; the guard exists so that if one ever appears it stops
		// rather than misbranches.
		var s blockStack
		s.Push("target")
		for i := 0; i < 300; i++ {
			s.Push("filler")
		}
		mustPanic(t, "exceeds a byte", func() { s.Depth("target") })
	})
	t.Run("a label may repeat and the nearest wins", func(t *testing.T) {
		var s blockStack
		s.Push("loop")
		s.Push("x")
		s.Push("loop")
		if d := s.Depth("loop"); d != 0 {
			t.Errorf("Depth with a repeated label = %d, want the nearest (0)", d)
		}
	})
}

// TestFindFromModeGuards covers setFind and setCaptureBody's refusal of
// ffUnset.
//
// The zero value being invalid is the entire mechanism: a find body whose mode
// was never claimed would otherwise start every scan at 0 and ignore the
// caller's offset for ever, which is a hang in the host's iteration loop
// rather than a wrong answer. find_from.go records that this shipped twice.
func TestFindFromModeGuards(t *testing.T) {
	t.Run("setFind rejects the zero value", func(t *testing.T) {
		p := &compiledPattern{}
		mustPanic(t, "unset findFromMode", func() { p.setFind([]byte{0x0B}, ffUnset) })
	})
	t.Run("setCaptureBody rejects the zero value", func(t *testing.T) {
		p := &compiledPattern{}
		mustPanic(t, "unset findFromMode", func() { p.setCaptureBody([]byte{0x0B}, ffUnset) })
	})
	t.Run("a claimed mode is recorded", func(t *testing.T) {
		p := &compiledPattern{}
		p.setFind([]byte{0x0B}, ffNative)
		if p.findFromMode != ffNative || len(p.findBody) == 0 {
			t.Errorf("setFind did not record the body and mode: %v, %d bytes",
				p.findFromMode, len(p.findBody))
		}
		p.setCaptureBody([]byte{0x0B}, ffAnchoredZeroOnly)
		if p.captureFromMode != ffAnchoredZeroOnly {
			t.Errorf("setCaptureBody recorded mode %v", p.captureFromMode)
		}
	})
}

// TestDFATableEqualDiscriminates covers dfaTableEqual, which decides whether
// two patterns can SHARE a compiled suffix DFA in a set.
//
// A false positive there merges two patterns onto one automaton and makes one
// of them answer for the other, so the negative cases are the ones that
// matter: every field it compares needs to be able to say no.
func TestDFATableEqualDiscriminates(t *testing.T) {
	base := compileTestDFA(t, `[a-z]{3}x`, true)
	if !dfaTableEqual(base, base) {
		t.Fatal("a table is not equal to itself")
	}
	same := compileTestDFA(t, `[a-z]{3}x`, true)
	if !dfaTableEqual(base, same) {
		t.Error("two compiles of the same pattern produced unequal tables")
	}
	for _, other := range []string{
		`[a-z]{4}x`,   // different state count
		`[a-z]{3}y`,   // same shape, different transitions
		`\b[a-z]+x`,   // word-boundary tracking
		`(?m:^)[a-z]`, // newline-boundary tracking
	} {
		o := compileTestDFA(t, other, true)
		if dfaTableEqual(base, o) {
			t.Errorf("dfaTableEqual said %q equals %q", `[a-z]{3}x`, other)
		}
	}
}

// TestDFATableEqualWideAccepts covers the WIDE accept comparison, which is the
// half of dfaTableEqual that decides sharing for sets past 64 patterns.
//
// On the wide path the narrow u64 masks carry no discriminating power at all —
// every accepting state has bit 0 set — so if the wide lists were not compared
// too, any two wide tables of the same SHAPE would look equal and two patterns
// would share an automaton that answers for only one of them.
func TestDFATableEqualWideAccepts(t *testing.T) {
	// Two structurally identical tables that differ ONLY in the wide lists.
	mk := func(wide map[int][]uint16) *dfaTable {
		t.Helper()
		base := compileTestDFA(t, `[a-z]{3}x`, true)
		cp := *base
		cp.acceptWide = wide
		return &cp
	}
	a := mk(map[int][]uint16{2: {7, 9}})
	b := mk(map[int][]uint16{2: {7, 9}})
	if !dfaTableEqual(a, b) {
		t.Error("tables with identical wide accept lists compared unequal")
	}
	for name, other := range map[string]map[int][]uint16{
		"different id":     {2: {7, 8}},
		"different length": {2: {7}},
		"different state":  {3: {7, 9}},
		"extra state":      {2: {7, 9}, 3: {1}},
		"empty":            {},
	} {
		if dfaTableEqual(a, mk(other)) {
			t.Errorf("wide lists differing by %q compared EQUAL — two patterns "+
				"would share an automaton that answers for one of them", name)
		}
	}
}

// TestAssertGroupsFromWrapperMode covers the guard that stands between a
// groups export and a body that cannot receive its start offset.
//
// The groups-from wrapper seeds the find-from channel, which only an ffNative
// body reads. Exporting groups over a legacy-narrow body would compile, would
// validate, and would then ignore the caller's offset for ever — the exact
// failure find_from.go records as having shipped twice.
func TestAssertGroupsFromWrapperMode(t *testing.T) {
	t.Run("anchored-only needs no channel", func(t *testing.T) {
		// captureBody IS the export, so the mode is never consulted and even
		// the invalid zero value must be tolerated.
		assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffUnset}, true)
	})
	t.Run("native find body passes", func(t *testing.T) {
		assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffNative}, false)
	})
	t.Run("native capture body passes", func(t *testing.T) {
		assertGroupsFromWrapperMode(
			&compiledPattern{anchored: true, captureFromMode: ffNative}, false)
	})
	t.Run("legacy-narrow find body is refused", func(t *testing.T) {
		mustPanic(t, "find body", func() {
			assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffLegacyNarrow}, false)
		})
	})
	t.Run("non-native capture body is refused", func(t *testing.T) {
		// The message must name the CAPTURE body, not the find one: which of
		// the two carries the channel depends on p.anchored, and a message
		// naming the wrong half sends the reader to the wrong emitter.
		mustPanic(t, "capture body", func() {
			assertGroupsFromWrapperMode(
				&compiledPattern{anchored: true, captureFromMode: ffLegacyNarrow}, false)
		})
	})
}

// TestEmitUnionSkipArmNoStates covers the empty-state guard: a union automaton
// with nothing to stride over must emit NOTHING, not an arm that arms itself
// on a state id that does not exist.
func TestEmitUnionSkipArmNoStates(t *testing.T) {
	before := []byte{0x01, 0x02}
	got := emitUnionSkipArm(append([]byte(nil), before...), &unionScanDFA{}, 7)
	if len(got) != len(before) {
		t.Errorf("emitUnionSkipArm with no skip states appended %d bytes, want 0",
			len(got)-len(before))
	}
}

// TestFutureAcceptsEmptyTable covers the empty-table guards in the liveness
// pass, and the WASM-id conversion's bound check.
//
// futureAccepts answers "can anything still match from here", which the set
// preflight uses to retire a pattern early. On an empty table the honest
// answer is nothing at all — returning a zero-length slice rather than
// indexing it.
func TestFutureAcceptsEmptyTable(t *testing.T) {
	if got := futureAccepts(nil); got != nil {
		t.Errorf("futureAccepts(nil) = %v, want nil", got)
	}
	if got := futureAccepts(&dfaTable{}); got != nil {
		t.Errorf("futureAccepts(empty) = %v, want nil", got)
	}
	// numWASM smaller than the table's state count must be tolerated: the
	// conversion skips states that do not fit rather than panicking, because
	// a caller sizing by a stale numWASM would otherwise take the whole
	// compile down.
	tbl := compileTestDFA(t, `[a-z]{3}x`, true)
	if got := futureAcceptsWASM(tbl, 2); len(got) != 2 {
		t.Errorf("futureAcceptsWASM with a short numWASM returned %d slots, want 2", len(got))
	}
	full := futureAcceptsWASM(tbl, tbl.numStates+1)
	if len(full) != tbl.numStates+1 {
		t.Errorf("futureAcceptsWASM returned %d slots, want %d", len(full), tbl.numStates+1)
	}
	if full[0] != 0 {
		t.Errorf("slot 0 (the dead state) = %#x, want 0 — nothing accepts from dead", full[0])
	}
}

// TestEncodeMemberSetWidths covers the member-set encoder across the widths the
// rectangle cover has to handle, including the one that used to be refused.
//
// Two nibble pairs cover a set of ANY width, which is what removed the old
// 16-byte ceiling; the panic guard exists only so a future change to
// memberSetPairs fails loudly instead of truncating, and truncating is exactly
// the wrong-extent bug the skip must never produce.
func TestEncodeMemberSetWidths(t *testing.T) {
	widths := map[string][]byte{}
	var lower, wordish, wide []byte
	for c := byte('a'); c <= 'z'; c++ {
		lower = append(lower, c)
	}
	for c := 0; c < 256; c++ {
		if c != '\n' {
			wide = append(wide, byte(c))
		}
	}
	wordish = append(append([]byte(nil), lower...), '_', '0', '9')
	widths["single byte"] = []byte{'x'}
	widths["lowercase"] = lower
	widths["word-ish"] = wordish
	widths["all but newline"] = wide

	for name, set := range widths {
		out := encodeMemberSet(set)
		if len(out) != memberSetBytes {
			t.Errorf("%s: encodeMemberSet returned %d bytes, want %d",
				name, len(out), memberSetBytes)
		}
		// The encoding must be EXACT: decode it back through the same
		// arithmetic the emitted SIMD performs and compare membership.
		var want [256]bool
		for _, c := range set {
			want[c] = true
		}
		for c := 0; c < 256; c++ {
			var merged byte
			for p := 0; p < memberSetPairs; p++ {
				lo := out[p*32 : p*32+16]
				hi := out[p*32+16 : p*32+32]
				merged |= lo[c&0x0F] & hi[c>>4]
			}
			if (merged != 0) != want[c] {
				t.Fatalf("%s: byte %#02x membership = %v, want %v",
					name, c, merged != 0, want[c])
			}
		}
	}
}

// TestApplyDominantStateEncodingSkipsOutOfRange covers the bound check: a
// dominant whose state id is past the table is skipped rather than written
// out of bounds. The two arrays are sized independently, so this is a real
// guard rather than a formality.
func TestApplyDominantStateEncodingSkipsOutOfRange(t *testing.T) {
	l := &dfaLayout{numWASM: 3}
	l.midAcceptBytes = make([]byte, 3)
	l.dominantStates = []dominantInfo{
		{state: 1, encodedByte: 128, isMidAccept: true},
		{state: 99, encodedByte: 129, isMidAccept: true}, // past the table
	}
	applyDominantStateEncoding(l, true)
	if l.midAcceptBytes[1] != 128 {
		t.Errorf("in-range dominant not encoded: %#x", l.midAcceptBytes[1])
	}
	// A non-mid dominant must be skipped when encodeNonMid is false.
	l2 := &dfaLayout{numWASM: 3}
	l2.midAcceptBytes = make([]byte, 3)
	l2.dominantStates = []dominantInfo{{state: 1, encodedByte: 254}}
	applyDominantStateEncoding(l2, false)
	if l2.midAcceptBytes[1] != 0 {
		t.Errorf("non-mid dominant encoded despite encodeNonMid=false: %#x",
			l2.midAcceptBytes[1])
	}
}
