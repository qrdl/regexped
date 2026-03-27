package compile

import (
	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Hybrid DFA engine
//
// Table-driven state transitions (no per-state br_table dispatch) combined
// with a literal-chain prefix optimisation. Shared helpers buildStateDispatch
// and literalChain are used by all three entry points:
//
//   buildHybridMatchBody        — anchored match
//   buildHybridAnchoredFindBody — anchored find (^ prefix)
//   buildHybridFindBody         — non-anchored find

// stateDispatchInfo holds the pre-computed transition summary for one DFA state.
type stateDispatchInfo struct {
	liveClasses     []int    // class indices that have a live transition
	nextState       []uint32 // nextState[j] = WASM next state for liveClasses[j] (1-based)
	selfLoopClasses []int    // subset of liveClasses where nextState[j] == this state
}

// buildStateDispatch pre-computes dispatch info for every live DFA state.
func buildStateDispatch(t *dfaTable, l *dfaLayout) []stateDispatchInfo {
	N := l.numWASM - 1
	K := l.numClasses
	info := make([]stateDispatchInfo, N)
	for i := 0; i < N; i++ {
		gs := i
		var liveC []int
		ns := make([]uint32, K)
		for c, rep := range l.classRep {
			next := t.transitions[gs*256+rep]
			if next >= 0 {
				ns[c] = uint32(next + 1) // WASM 1-based
				liveC = append(liveC, c)
			}
		}
		var liveNS []uint32
		for _, c := range liveC {
			liveNS = append(liveNS, ns[c])
		}
		wasmSt := uint32(i + 1)
		var selfLoop []int
		for j, c := range liveC {
			if liveNS[j] == wasmSt {
				selfLoop = append(selfLoop, c)
			}
		}
		info[i] = stateDispatchInfo{
			liveClasses:     liveC,
			nextState:       liveNS,
			selfLoopClasses: selfLoop,
		}
	}
	return info
}

// literalChain returns the sequence of (raw byte, nextWasmState) for a chain
// of single-transition, single-byte-class states starting from wasmState ws.
// A chain step is valid only when:
//   - exactly one live class for that state
//   - that class maps to exactly one raw byte (classByteCount[c] == 1)
//   - the current state is not an accept or immediateAccept state
//   - the next state has not been visited already (no cycles)
//
// The chain ends as soon as any condition fails. Returns nil if no chain exists.
func literalChain(t *dfaTable, l *dfaLayout, disp []stateDispatchInfo, hasImmAccept bool, startWS uint32) []struct {
	rawByte byte
	nextWS  uint32
} {
	// classByteCount[c] = number of raw bytes mapping to class c.
	classByteCount := make([]int, l.numClasses)
	for _, c := range l.classMap {
		classByteCount[c]++
	}

	visited := make(map[uint32]bool)
	var chain []struct {
		rawByte byte
		nextWS  uint32
	}
	ws := startWS
	for {
		if visited[ws] {
			break // cycle detected
		}
		visited[ws] = true
		gs := int(ws) - 1 // WASM state to DFA state
		// Stop if accept or immediateAccept — we can't skip the accept check.
		if t.acceptStates[gs] {
			break
		}
		if hasImmAccept && t.immediateAcceptStates[gs] {
			break
		}
		d := disp[gs]
		if len(d.liveClasses) != 1 {
			break
		}
		c := d.liveClasses[0]
		if classByteCount[c] != 1 {
			break
		}
		// Find the unique byte for this class.
		var raw byte
		for bi, cls := range l.classMap {
			if int(cls) == c {
				raw = byte(bi)
				break
			}
		}
		nextWS := d.nextState[0]
		chain = append(chain, struct {
			rawByte byte
			nextWS  uint32
		}{raw, nextWS})
		ws = nextWS
		if ws == 0 { // dead next state
			break
		}
	}
	return chain
}

// buildHybridMatchBody returns the WASM function body for the hybrid DFA path:
// pure table-driven state transitions (no br_table dispatch, no self-loop blocks)
// combined with a literal-chain prefix optimisation when applicable.
//
// When l.useCompression is true the inner loop uses the compressed table:
//
//	class = classMap[mem[ptr+pos]];  state = table[state*numClasses + class]
//
// When l.useCompression is false the inner loop uses the uncompressed table:
//
//	state = table[(state<<8) + mem[ptr+pos]]   (multiply replaced by bit-shift)
//
// This eliminates both the br_table overhead of the pure compiled path and the
// forced-multiply overhead of the compressed-only previous hybrid implementation.
func buildHybridMatchBody(t *dfaTable, l *dfaLayout, hasImmAccept bool) []byte {
	var b []byte

	// Class info must have been pre-computed in buildDFALayout for literalChain.
	disp := buildStateDispatch(t, l)
	chain := literalChain(t, l, disp, hasImmAccept, l.wasmStart)

	const localState = uint32(2)
	const localPos = uint32(3)
	const localClass = uint32(4)

	if l.useCompression {
		b = append(b, 0x01, 0x03, 0x7F) // 3 locals: state, pos, class
	} else {
		b = append(b, 0x01, 0x02, 0x7F) // 2 locals: state, pos
	}

	// Literal chain prefix.
	if len(chain) >= 2 {
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(len(chain)))
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F) // return -1
		b = append(b, 0x0B)
		for _, step := range chain {
			b = append(b, 0x20, 0x00)
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(step.rawByte))
			b = append(b, 0x47) // i32.ne
			b = append(b, 0x04, 0x40)
			b = append(b, 0x41, 0x7F)
			b = append(b, 0x0F) // return -1
			b = append(b, 0x0B)
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, byte(localPos))
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(chain[len(chain)-1].nextWS))
		b = append(b, 0x21, byte(localState))
	} else {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.wasmStart))
		b = append(b, 0x21, byte(localState))
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br_if $done
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x0D, 0x01) // br_if 1

	if l.useCompression {
		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.classMapOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, byte(localClass))

		// state = table[tableOff + state*numClasses + class]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.numClasses))
		b = append(b, 0x6C) // i32.mul
		b = append(b, 0x6A)
		b = append(b, 0x20, byte(localClass))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, byte(localState))
	} else {
		// state = table[tableOff + (state<<8) + mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x41, 0x08) // i32.const 8
		b = append(b, 0x74)       // i32.shl
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // mem[ptr+pos]
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → new state
		b = append(b, 0x21, byte(localState))
	}

	// if state == 0: return -1
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Immediate-accept check.
	if hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x0F)
		b = append(b, 0x0B)
	}

	// pos++
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, byte(localPos))

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop $main
	b = append(b, 0x0B)       // end block $done

	// accept[state] != 0 ? pos : -1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x05)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B)

	b = append(b, 0x0B) // end function
	return b
}

// buildHybridAnchoredFindBody returns the WASM function body for the hybrid find path
// when the pattern is anchored (starts with ^). It is a thin wrapper that delegates to
// buildAnchoredFindBody with parameters taken from the pre-computed dfaLayout.
//
// Row deduplication is guaranteed to be disabled for the hybrid path (enforced in
// buildDFALayout), so rowMapOff/useRowDedup are always the zero values.
func buildHybridAnchoredFindBody(t *dfaTable, l *dfaLayout) []byte {
	return buildAnchoredFindBody(
		l.wasmStart, l.tableOff, l.acceptOff, l.midAcceptOff,
		l.classMapOff, l.numClasses, l.useU8, l.useCompression,
		l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept,
		l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff,
		l.rowMapOff, l.useRowDedup, l.midAcceptNLOff, t.hasNewlineBoundary,
	)
}

// buildHybridFindBody returns the WASM function body for the hybrid find path when the
// pattern is non-anchored. It is a thin wrapper that delegates to buildFindBody with
// parameters taken from the pre-computed dfaLayout.
//
// The SIMD prefix scan (EmitPrefixScan) is already table/SIMD-only with no br_table
// dispatch, so no restructuring is required for the find hot path.
// Row deduplication is guaranteed disabled for the hybrid path.
func buildHybridFindBody(t *dfaTable, l *dfaLayout, mandatoryLit *MandatoryLit) []byte {
	return buildFindBody(
		l.wasmStart, l.wasmMidStart, l.wasmMidStartWord,
		l.wasmMidStartNewline, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff,
		l.firstByteOff, l.prefix, l.classMapOff, l.numClasses,
		l.useU8, l.useCompression, l.startBeginAccept,
		l.immediateAcceptOff, l.hasImmAccept,
		l.wordCharTableOff, l.needWordCharTable,
		l.midAcceptNWOff, l.midAcceptWOff, t.hasNewlineBoundary,
		l.firstByteFlags, l.firstBytes,
		l.teddyLoOff, l.teddyHiOff,
		l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0,
		l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0,
		mandatoryLit, l.rowMapOff, l.useRowDedup, l.midAcceptNLOff,
	)
}
