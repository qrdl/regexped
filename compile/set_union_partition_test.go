package compile

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// The mid-accept-first partition (SETS_PLAN item 21 phase 2).
//
// Both scan bodies and the gated/overlapping find preflight replace a per-byte
// accept LOAD with the compare `state < midAcceptLimit`. That is only sound if
// the partition means exactly what the bodies assume: states below the limit
// are precisely the ones whose MID-STRING accept entry is non-empty. Nothing
// downstream re-checks it — a state on the wrong side of the line is a wrong
// answer with no trap and no diagnostic.
//
// It is tested as an INVARIANT rather than through a witness input on purpose.
// Mutation testing showed why: partitioning by the END-OF-INPUT accepts instead
// (`d.accepting` / `d.acceptWide` in place of `d.midAccepting` /
// `d.midAcceptWide`) survived every behavioural suite in the project. The two
// sets coincide for any pattern without an end anchor, which is nearly every
// pattern anyone writes, so finding an input that separates them is luck. The
// invariant separates them by construction.
func TestUnionScanMidAcceptPartition(t *testing.T) {
	shapes := []struct {
		name string
		pats []string
	}{
		{"classes", []string{`[a-z]{2}[0-9]{3}`, `[p-r]+`, `[^\n]*[0-2]`}},
		{"end-anchored", []string{`[a-z]+$`, `[0-9]\z`, `[a-c]+`}},
		{"nullable", []string{`[0-9]*`, `\A`, `[^\n]*[3-5]`}},
		{"begin-anchored", []string{`^[0-9]`, `[a-z]{3}`, `[q]+`}},
		{"mixed-anchors", []string{`^[a-z]+$`, `[0-9]{2}`, `\A[a-c]`}},
		// The two DEGENERATE limits, which are not variations of the general
		// case but SEPARATE emitted code: at 0 the bodies emit no mid-accept
		// arm at all, and at numStates they emit it with no guard, because the
		// compare could never be false. Each is one `if` in three emitters, and
		// a branch nothing exercises is a branch nobody has checked.
		{"limit-zero", []string{`[a-z]+\z`, `[0-9]{2}\z`}},
		{"limit-full", []string{`[0-9]*`, `[a-c]{2}`}},
		{"wide", nil}, // filled below: 96 patterns, the >64-id accept form
	}
	// The wide fixture needs END-ANCHORED members for the same reason the
	// narrow ones do: without them a state's mid-accept set and its
	// end-of-input set are identical, and a partition built from the wrong one
	// is indistinguishable. Every fourth pattern carries `\z`.
	wide := make([]string, 96)
	for i := range wide {
		wide[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%8, 1+i/8%8)
		if i%4 == 0 {
			wide[i] += `\z`
		}
	}
	shapes[len(shapes)-1].pats = wide

	// Which of the three emission cases each shape reached. Asserted at the end
	// rather than assumed: a fixture that stops reaching a case turns its
	// branch back into untested code silently.
	var sawZero, sawFull, sawGuarded bool

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			infos, ids, _, _ := setEmitCovInfos(t, sh.pats)
			spec := SetSpec{
				Name: "s", ScanAny: "s_scan_any", ScanAll: "s_scan_all",
				Patterns: infos, PatternIDs: ids,
				DeclaredPatternCount: len(infos), IDSpaceSize: len(infos),
			}
			u := buildUnionScanDFA(spec, CompileSetOptions{}, 0, false)
			if u == nil {
				t.Skip("union automaton refused for this shape")
			}

			// midAccepts(newState) read back from the EMITTED tables, which is
			// what the bodies actually index — not from the dfa the partition
			// was computed on. That is the point: this compares the two.
			midAccepts := func(s int) bool {
				if u.isWide() {
					return binary.LittleEndian.Uint32(
						unionSegBytes(t, u, u.midReprOff)[s*4:]) != 0
				}
				return binary.LittleEndian.Uint64(
					unionSegBytes(t, u, u.acceptOff)[s*8:]) != 0
			}

			if u.midAcceptLimit < 0 || u.midAcceptLimit > u.numStates {
				t.Fatalf("midAcceptLimit %d out of range for %d states",
					u.midAcceptLimit, u.numStates)
			}
			switch {
			case u.midAcceptLimit == 0:
				sawZero = true
			case u.midAcceptLimit >= u.numStates:
				sawFull = true
			default:
				sawGuarded = true
			}
			t.Logf("%s: %d states, midAcceptLimit %d", sh.name, u.numStates, u.midAcceptLimit)
			for s := 0; s < u.numStates; s++ {
				want := s < u.midAcceptLimit
				if got := midAccepts(s); got != want {
					t.Fatalf("state %d: mid-accepting = %v, but the partition says %v "+
						"(midAcceptLimit = %d, states = %d). Every body tests "+
						"`state < midAcceptLimit` INSTEAD of loading the accept "+
						"entry, so a state on the wrong side is a silently wrong answer.",
						s, got, want, u.midAcceptLimit, u.numStates)
				}
			}

			// The start states are indices into the same partitioned space, so a
			// permutation that forgot them points at another state's row.
			for _, st := range []struct {
				name string
				id   int
			}{{"startState", u.startState}, {"midStartState", u.midStartState}} {
				if st.id < 0 || st.id >= u.numStates {
					t.Fatalf("%s = %d is outside 0..%d", st.name, st.id, u.numStates-1)
				}
			}
		})
	}

	if !sawZero || !sawFull || !sawGuarded {
		t.Errorf("the fixtures no longer cover all three emission cases "+
			"(limit==0: %v, limit==numStates: %v, guarded: %v). Each is separate "+
			"emitted code in three bodies, so an uncovered one is a branch nobody "+
			"has checked.", sawZero, sawFull, sawGuarded)
	}
}

// unionSegBytes returns the payload of the emitted data segment that starts at
// `off`, so a test can read a table exactly as the WASM body will.
func unionSegBytes(t *testing.T, u *unionScanDFA, off int32) []byte {
	t.Helper()
	for _, s := range parseDataSegments(u.dataBytes) {
		if s.offset == off {
			return s.data
		}
	}
	t.Fatalf("no data segment at offset %d", off)
	return nil
}
