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
//
// Two flavours, distinguished by which side of the self-loop is small enough
// to test with a short SIMD compare chain (plans/SETS.md §21.2 / G11):
//
//	Exceptions != nil — the EXIT set is small ("no chunk byte LEAVES").
//	Members    != nil — the SELF-LOOP set is small ("every chunk byte STAYS").
//
// They are exactly the same skip with the test inverted, and rest on the same
// soundness argument: every byte skipped maps the state to itself.
type dominantWalkState struct {
	// WASMState is the id the emitted code compares lState against — the
	// dfaTable is already relabelled by reorderAcceptFirst when this runs, so
	// it is simply the table index plus one (0 is the implicit dead state).
	WASMState int
	// Exceptions are the bytes that do NOT self-loop. Every other byte leaves
	// the state unchanged, which is what makes skipping them sound.
	Exceptions []byte
	// Members is the self-loop set itself, for the inverted flavour. Mutually
	// exclusive with Exceptions.
	Members []byte
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
//
// Deliberately asks dominantWalkStates ONLY, never memberWalkStates. A 1-byte
// self-loop can hold a walk to end of input too, so widening this would be
// defensible in the abstract — but it would flip futureOff from 0 to non-zero
// on sets that have no wide-self-loop state at all, changing G8/G9 emission
// far outside G11's remit. G11 is a skip, not a re-gate.
func hasNeverDyingState(t *dfaTable) bool {
	return len(dominantWalkStates(t)) > 0
}

const (
	// memberSelfLoopMax is the widest self-loop the inverted test can afford:
	// one splat+eq+bitmask+or per member per chunk, same budget as
	// dominantMaxExceptions spends on the other side.
	memberSelfLoopMax = 2
	// memberMaxStates bounds the member arms, separately from
	// dominantMaxStates. Each costs a compare per walk iteration on inputs
	// that never enter the state, and member mode cannot argue from coverage
	// the way exception mode can (§21.2's "collateral" note).
	memberMaxStates = 2
)

// memberWalkStates returns the states worth a bulk skip under the INVERTED
// test: those whose self-loop is 1..memberSelfLoopMax bytes wide.
//
// Restricted to ACCEPTING states. Small self-loops are everywhere — every
// literal chain has them — but a run of that byte in the actual input is not,
// and each emitted state taxes every walk that never enters it. An accepting
// state with a tiny self-loop is specifically the "long run that keeps
// matching" shape this exists for: greedy-3's `a+` sits in one for all 50,000
// bytes. Non-accepting small self-loops are left alone until measurement asks
// for them.
//
// Like its sibling this is a performance ROUTER only; the emitted skip
// re-derives soundness from the self-loop property itself.
func memberWalkStates(t *dfaTable) []dominantWalkState {
	if t == nil || t.numStates == 0 {
		return nil
	}
	var out []dominantWalkState
	for s := 0; s < t.numStates; s++ {
		if t.acceptStates[s] == 0 && t.midAcceptStates[s] == 0 {
			continue
		}
		var members []byte
		for b := 0; b < 256; b++ {
			if t.transitions[s*256+b] == s {
				members = append(members, byte(b))
				if len(members) > memberSelfLoopMax {
					break
				}
			}
		}
		if len(members) == 0 || len(members) > memberSelfLoopMax {
			continue
		}
		out = append(out, dominantWalkState{WASMState: s + 1, Members: members, Coverage: len(members)})
	}
	// Widest self-loop first (it can hold the longer run); ties by state id so
	// emission is deterministic.
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
	if len(out) > memberMaxStates {
		out = out[:memberMaxStates]
	}
	return out
}
