package compile

// Dominant-walk-state detection for the anchored probe (plans/SETS.md §18.1).
//
// A merged anchored DFA frequently spends an entire input in ONE state whose
// self-loop covers almost every byte, waiting for a handful of bytes that may
// never arrive. Measured on the greedy-3 anchored automaton over
// corpusNoMatch(): occupancy 4096/4096 sampled bytes in a single state whose
// self-loop covers 254 of 256 bytes, the exceptions being '\n' and 'E'. G5
// showed the per-byte loop is already minimal at 24 instructions; what it
// could not show is that on such a walk the per-byte work is unnecessary
// altogether. That is a SIMD bulk-skip shape.
//
// This is a performance ROUTER and nothing else. Mis-detection may cost speed;
// it may never change an answer. The emitters that consume it re-derive the
// skip's correctness from the self-loop property itself, not from this
// function's judgement.

const (
	// dominantSelfLoopMin is how much of the byte space a state's self-loop
	// must cover before a chunked skip pays. Below this, exceptions are common
	// enough that the SIMD probe rarely advances a whole chunk.
	dominantSelfLoopMin = 240
	// dominantMaxExceptions bounds the SIMD compare chain: each exception byte
	// costs one splat+eq+or per chunk, so a long list erases the win.
	dominantMaxExceptions = 8
	// dominantMaxStates bounds how many states get an emitted check, since
	// each costs a compare on every non-dominant byte.
	dominantMaxStates = 2
)

// dominantWalkState is one state worth special-casing, in WASM id space.
type dominantWalkState struct {
	// WASMState is the id the emitted code compares lState against — the
	// dfaTable is already relabelled by reorderAcceptFirst when this runs, so
	// it is simply the table index plus one (0 is the implicit dead state).
	WASMState int
	// Exceptions are the bytes that do NOT self-loop. Every other byte leaves
	// the state unchanged, which is what makes skipping them sound.
	Exceptions []byte
	// Coverage is the self-loop size, for diagnostics and ordering.
	Coverage int
}

// dominantWalkStates returns the states of t worth a bulk skip, widest
// self-loop first, at most dominantMaxStates of them.
//
// A state qualifies when its self-loop covers at least dominantSelfLoopMin of
// the 256 byte transitions and it has at most dominantMaxExceptions bytes that
// leave it. Dead transitions (-1) count as exceptions: they leave the state,
// and the walk must see them to terminate.
func dominantWalkStates(t *dfaTable) []dominantWalkState {
	if t == nil || t.numStates == 0 {
		return nil
	}
	var out []dominantWalkState
	for s := 0; s < t.numStates; s++ {
		self := 0
		var exc []byte
		for b := 0; b < 256; b++ {
			if t.transitions[s*256+b] == s {
				self++
			} else {
				exc = append(exc, byte(b))
			}
		}
		if self < dominantSelfLoopMin || len(exc) > dominantMaxExceptions {
			continue
		}
		out = append(out, dominantWalkState{WASMState: s + 1, Exceptions: exc, Coverage: self})
	}
	// Widest coverage first; ties by state id so emission is deterministic.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if b.Coverage > a.Coverage || (b.Coverage == a.Coverage && b.WASMState < a.WASMState) {
				out[j-1], out[j] = b, a
				continue
			}
			break
		}
	}
	if len(out) > dominantMaxStates {
		out = out[:dominantMaxStates]
	}
	return out
}

// hasNeverDyingState reports whether t contains a state that can hold a walk
// to end of input. Used by G8/G9 as an emission gate: those tasks only pay for
// their machinery on sets where a walk actually fails to terminate early.
func hasNeverDyingState(t *dfaTable) bool {
	return len(dominantWalkStates(t)) > 0
}
