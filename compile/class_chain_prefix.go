package compile

import "sort"

// ── Chain-start SIMD verify for `[class]{N,}` ──────────────────────────────
//
// A pattern whose automaton is a linear chain of N steps on ONE byte class C
// spends the head of every candidate proving, one scalar byte at a time, that
// the next 16 bytes are all in C. A single Shufti probe answers the same
// question, and answers more besides: when the run is SHORT, the position of
// the first non-member byte proves that no start in that whole range can begin
// a match, because each of those positions has fewer than N class bytes ahead
// of it.
//
// That second half is what makes this worth more than a constant factor. The
// scalar scan retries at p+1, p+2, … and re-walks the same bytes; the probe
// retires the entire failed range in one step. On prose, where the longest
// letter run is a word, that is the difference between ~104 fuel per byte and
// one probe per word.
//
// `counted_chain.go` has the SET-suffix, exact-count `{N}` sibling
// (`isCountedClassChain`), which verifies a whole match rather than a prefix
// and reports it. This one only decides where the DFA walk should resume, so
// it is sound for open-ended tails that detector has to refuse.

// minClassChainPrefix is the shortest chain worth probing.
//
// At n = 1 the probe LOSES on both arms, which is how it put two rows above
// neutral when it had no floor:
//
//   - the success arm replaces ONE scalar step (~11 fuel) with a chunk load, a
//     nibble-table pair and a mask reduction (~30);
//   - the failure arm retires NOTHING. The range-retirement argument — a
//     non-member at offset r proves no start in [p, p+r] can match — is empty
//     at n = 1, because it retires only position p, which is what the scalar
//     scan does anyway. Its value grows with n.
//
// Break-even on the success arm alone is near n = 3 (≈30 against n × 11); 4
// takes one step of margin. Nothing is at risk in between: the shortest chain
// that MEASURED a win is `[A-Z]{8,}` at n = 8 (−44%), and the two patterns that
// regressed — `([^,]+)` and `(\w+)` — are both n = 1, so the gap the threshold
// sits in is 1 against 8.
//
// This is the same floor `minLMBareShuftiLen` provides for the bare-prefix
// Shufti lift, for the same reason, and `(\w+)` is the pattern that motivated
// BOTH. See detectShuftiSelfLoop's doc comment: "the fixed SIMD chunk-scan
// setup this lifts costs more than it saves when the typical match is a
// handful of bytes."
const minClassChainPrefix = 4

// maxClassChainPrefix bounds the chain length this detector will report. The
// emitter probes at most 16 bytes, so a longer chain is served identically;
// the bound exists only to keep the scan cheap on pathological tables.
const maxClassChainPrefix = 256

// classChainPrefix describes a linear class chain at the head of a pattern.
type classChainPrefix struct {
	// class is the byte set every step of the chain consumes, sorted.
	class []byte
	// n is the number of chain steps before the accepting state.
	n int
	// states[k] is the WASM state id reached after k+1 class bytes, for
	// k in [0, min(n,16)). states[15] is where a full 16-byte probe lands.
	states []int32
	// acceptsAtN is true when the state after n bytes accepts at any position,
	// which lets the N<=16 form publish last_accept without a scalar step.
	acceptsAtN bool
}

// detectClassChainPrefix reports whether l's automaton begins with a linear
// chain of one byte class, and if so describes it.
//
// The conditions are deliberately strict; every one of them is a case where
// the emitted probe would otherwise be unsound rather than merely unhelpful:
//
//   - No word or newline boundary anywhere, and startState == midStartState.
//     The probe jumps the walk forward without consulting the preceding byte,
//     so a pattern whose start state depends on that byte would be entered in
//     the wrong one. isCountedClassChain refuses on the same grounds.
//   - Every intermediate state accepts in NO channel. An intermediate accept
//     means a SHORTER prefix already matched, and the probe would jump past
//     the position where that match had to be recorded.
//   - Every step consumes exactly the same class and has exactly one
//     destination. Anything else is not a chain.
//
// The final state is allowed to self-loop (the `{N,}` open tail) or to be
// terminal; both are fine, because the probe hands the walk to the scalar
// engine at that state rather than reporting a match itself.
func detectClassChainPrefix(l *dfaLayout, t *dfaTable) (classChainPrefix, bool) {
	var none classChainPrefix
	if l.numWASM <= 1 || l.needWordCharTable || len(l.midAcceptNLBytes) > 0 {
		return none, false
	}
	// A begin-anchored or context-dependent start makes the two entry points
	// different automata; the probe has only one.
	if l.wasmStart != l.wasmMidStart ||
		(l.wasmMidStartWord != 0 && l.wasmMidStartWord != l.wasmMidStart) ||
		(l.wasmMidStartNewline != 0 && l.wasmMidStartNewline != l.wasmMidStart) {
		return none, false
	}

	// liveSet returns the bytes with a live transition out of state, plus the
	// single destination they all share; ok is false when they disagree.
	liveSet := func(state int) (set []byte, dest int32, ok bool) {
		dest = -1
		for b := 0; b < 256; b++ {
			t := l.transitionOn(state, b)
			if t == 0 {
				continue
			}
			if dest < 0 {
				dest = t
			} else if t != dest {
				return nil, 0, false
			}
			set = append(set, byte(b))
		}
		return set, dest, dest > 0
	}
	// acceptsAnywhere: does this state record a match without consuming more?
	// Every channel counts, including the EOF one — a state that accepts only
	// at end of input still means a shorter prefix matched there.
	//
	// # Why this reads the TABLE and not l.midAcceptBytes
	//
	// midAcceptBytes is an OVERLOADED encoding: applyDominantStateEncoding
	// writes dominant markers into the same bytes (2..127 mid-accept dominant,
	// 128..253 Shufti, 254..255 non-mid), so `!= 0` there does not mean
	// "accepting". detectSkipSafeOnDead makes the same test safely, but only
	// because it runs inside buildDFALayout, BEFORE that pass — its comment
	// says so explicitly. This detector runs at emission time, AFTER it.
	//
	// Read against the encoded table, `[a-z]{50,}[0-9]` reported a chain of 50:
	// its state 50 self-loops on [a-z] and does not accept until a digit
	// arrives, but under prefer-match it becomes a Shufti dominant, and the
	// encoding byte read as an accept. The dfaTable's own accept maps carry no
	// such second meaning, so they are the source that answers the question
	// actually being asked.
	//
	// Table state ids are WASM ids minus one (state 0 is the implicit dead
	// state), which is the offset every other consumer of these maps applies.
	acceptsAnywhere := func(state int32) bool {
		ts := int(state) - 1
		if ts < 0 {
			return false
		}
		for _, m := range []map[int]uint64{
			t.acceptStates, t.midAcceptStates,
			t.midAcceptNWStates, t.midAcceptWStates, t.midAcceptNLStates,
			t.immediateAcceptStates,
		} {
			if m[ts] != 0 {
				return true
			}
		}
		// The >64-pattern accept form, nil off the sparse path.
		for _, m := range []map[int][]uint16{
			t.acceptWide, t.midAcceptWide, t.immAcceptWide,
		} {
			if len(m[ts]) > 0 {
				return true
			}
		}
		return false
	}

	start := int(l.wasmStart)
	class, dest, ok := liveSet(start)
	if !ok || len(class) == 0 {
		return none, false
	}
	// The start state itself must not accept: an empty match makes the whole
	// chain irrelevant and the probe would skip past position p.
	if acceptsAnywhere(int32(start)) {
		return none, false
	}

	sameSet := func(a, b []byte) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	out := classChainPrefix{class: class}
	cur := dest
	seen := map[int32]bool{int32(start): true}
	for {
		out.states = append(out.states, cur)
		out.n++
		if out.n > maxClassChainPrefix {
			return none, false
		}
		if acceptsAnywhere(cur) {
			// The chain ends here: `[a-zA-Z]{20,}` and `[a-z]{5}` both land
			// on an accepting state after exactly n class bytes.
			out.acceptsAtN = true
			break
		}
		// A state that SELF-LOOPS on the class also ends the chain, even
		// though it does not accept. Reaching it already proves n class bytes
		// were consumed, which is all the probe needs: it resumes the walk
		// there, and the skip argument only requires that a match needs at
		// least n of them.
		//
		// This is the `{N,}`-followed-by-something shape. `[a-z]{50,}[0-9]`
		// reaches a state that self-loops on [a-z] and exits on [0-9] — two
		// destinations, so the single-destination rule below refuses it, and
		// the chain would be lost even though the pattern demonstrably needs
		// 50 class bytes. Checked BEFORE liveSet for that reason.
		if l.transitionOn(int(cur), int(class[0])) == cur {
			selfLoops := true
			for _, c := range class {
				if l.transitionOn(int(cur), int(c)) != cur {
					selfLoops = false
					break
				}
			}
			if selfLoops {
				break
			}
		}
		if seen[cur] {
			// A cycle with no accept and no self-loop is not a bounded chain.
			return none, false
		}
		seen[cur] = true
		set, next, ok := liveSet(int(cur))
		if !ok || !sameSet(set, class) {
			return none, false
		}
		cur = next
	}
	if out.n < minClassChainPrefix {
		return none, false
	}
	// Only the first 16 states can ever be jumped to.
	if len(out.states) > 16 {
		out.states = out.states[:16]
	}
	sort.Slice(out.class, func(i, j int) bool { return out.class[i] < out.class[j] })
	return out, true
}
