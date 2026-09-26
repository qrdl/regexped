package compile

import "math/bits"

// Per-state liveness for set probes.
//
// futureAccepts[s] answers "which patterns can still accept at or after state
// s?". A walk may stop as soon as every pattern the caller still WANTS is
// either already recorded or provably unreachable — a strictly stronger exit
// than "every wanted pattern has been seen", which is all the probe had.
//
// This table was built once before as Candidate A, measured at +37.5%
// and reverted it. The mechanism was right and the gate was missing: on
// greedy-3 the wanted set contains `[^\n]*ERROR`, which on a corpus with no
// newline is simultaneously never-recorded and never-dead, so the check cost
// ~12 instructions per byte and could never fire. It is only emitted for sets
// where a union preflight has first removed such patterns from the wanted
// mask, which is what lets the exit actually fire.
//
// SAFETY DIRECTION. Over-approximating a state's future is safe: the walk
// merely exits later than it could. UNDER-approximating loses matches. Every
// accept channel must therefore be folded in, and an unreachable-state entry
// must be a union of everything, not zero.

// futureAccepts returns, per DFA state, the union of accept bits over every
// state reachable from it (including itself). Index is the raw dfaTable state;
// callers converting to WASM ids add one.
func futureAccepts(t *dfaTable) []uint64 {
	if t == nil || t.numStates == 0 {
		return nil
	}
	n := t.numStates
	out := make([]uint64, n)

	// Seed with every accept channel a probe or suffix body can observe.
	// Missing one here would under-approximate, which is the unsafe
	// direction — so this deliberately includes the word-boundary and
	// newline channels even though the emission gate excludes such sets.
	for s := 0; s < n; s++ {
		out[s] = t.acceptStates[s] | t.midAcceptStates[s] | t.immediateAcceptStates[s] |
			t.midAcceptNWStates[s] | t.midAcceptWStates[s] | t.midAcceptNLStates[s]
	}

	// Fixpoint over successors. The graph may cycle, so iterate to stability
	// rather than assuming a topological order; n rounds is the worst case and
	// this runs once per bucket at compile time.
	for round := 0; round < n+1; round++ {
		changed := false
		for s := 0; s < n; s++ {
			acc := out[s]
			for b := 0; b < 256; b++ {
				nx := t.transitions[s*256+b]
				if nx < 0 {
					continue
				}
				acc |= out[nx]
			}
			if acc != out[s] {
				out[s] = acc
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return out
}

// futureAcceptsWASM returns futureAccepts re-indexed into the WASM state-id
// space the emitters compare against: slot 0 is the dead state (nothing can
// accept from dead), slot s+1 holds raw state s. It is the compile-time twin
// of the table futureAcceptsBytes serialises, for emitters that know a state
// at compile time and can therefore fold its future into a constant instead
// of loading it.
func futureAcceptsWASM(t *dfaTable, numWASM int) []uint64 {
	fa := futureAccepts(t)
	out := make([]uint64, numWASM)
	for s, bits := range fa {
		if s+1 >= numWASM {
			continue
		}
		out[s+1] = bits
	}
	return out
}

// futureAcceptsBytes serialises futureAccepts into the u64-per-WASM-state
// layout the emitted tables use: slot 0 is the dead state and is left zero
// (nothing can accept from dead), slot s+1 holds state s.
func futureAcceptsBytes(t *dfaTable, numWASM int) []byte {
	fa := futureAccepts(t)
	bs := make([]byte, numWASM*8)
	for s, bits := range fa {
		if bits == 0 || s+1 >= numWASM {
			continue
		}
		off := (s + 1) * 8
		for i := 0; i < 8; i++ {
			bs[off+i] = byte(bits >> uint(i*8))
		}
	}
	return bs
}

// livenessCanFire reports whether a bucket's walk can outlive one of its
// members for arbitrarily long: whether a cycle is reachable through states
// from which some member of the bucket can no longer accept while another
// still can. That is where the liveness exit pays in a LITERAL bucket — the
// members share one merged walk, so a member with an accepting loop
// (`foo\w+`) keeps the walk going for a sibling that is long dead (`foo[0-9]`
// after `fooa`), and once the looping member is gated out or recorded,
// nothing but the exit stops that walk. Without such a cycle the walk past a
// dead member is bounded, so the exit could only ever save a bounded amount
// and costs a load and a branch on every byte; it is not emitted.
func livenessCanFire(t *dfaTable) bool {
	fa := futureAccepts(t)
	if fa == nil {
		return false
	}
	var full uint64
	for _, m := range fa {
		full |= m
	}
	if bits.OnesCount64(full) < 2 {
		return false
	}
	reach := make([]bool, t.numStates)
	var stack []int
	for _, r := range []int{t.startState, t.midStartState, t.midStartWordState, t.midStartNewlineState} {
		if r >= 0 && r < t.numStates && !reach[r] {
			reach[r] = true
			stack = append(stack, r)
		}
	}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for c := 0; c < 256; c++ {
			if n := t.transitions[s*256+c]; n >= 0 && !reach[n] {
				reach[n] = true
				stack = append(stack, n)
			}
		}
	}
	partial := func(s int) bool { return reach[s] && fa[s] != 0 && fa[s] != full }
	// A cycle through partial states: iterative DFS with colours.
	const white, grey, black = 0, 1, 2
	colour := make([]int, t.numStates)
	type frame struct{ s, c int }
	for root := 0; root < t.numStates; root++ {
		if !partial(root) || colour[root] != white {
			continue
		}
		colour[root] = grey
		frames := []frame{{root, 0}}
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			if f.c == 256 {
				colour[f.s] = black
				frames = frames[:len(frames)-1]
				continue
			}
			n := t.transitions[f.s*256+f.c]
			f.c++
			if n < 0 || !partial(n) {
				continue
			}
			switch colour[n] {
			case grey:
				return true
			case white:
				colour[n] = grey
				frames = append(frames, frame{n, 0})
			}
		}
	}
	return false
}
