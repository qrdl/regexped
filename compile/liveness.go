package compile

// Per-state liveness for set probes.
//
// futureAccepts[s] answers "which patterns can still accept at or after state
// s?". A walk may stop as soon as every pattern the caller still WANTS is
// either already recorded or provably unreachable — a strictly stronger exit
// than "every wanted pattern has been seen", which is all the probe had.
//
// §16.5.2 built this table once before as Candidate A, measured it at +37.5%
// and reverted it. The mechanism was right and the gate was missing: on
// greedy-3 the wanted set contains `[^\n]*ERROR`, which on a corpus with no
// newline is simultaneously never-recorded and never-dead, so the check cost
// ~12 instructions per byte and could never fire. G8 only emits it for sets
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
	// newline channels even though G8's emission gate excludes such sets.
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
