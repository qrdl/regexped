package compile

import (
	"github.com/qrdl/regexped/internal/utils"
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
func literalChain(t *dfaTable, l *dfaLayout, disp []stateDispatchInfo, startWS uint32) []struct {
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
	for !visited[ws] { // until cycle detected
		visited[ws] = true
		gs := int(ws) - 1 // WASM state to DFA state
		// Stop if accept — we can't skip the accept check. There is no
		// immediateAccept case to stop on: match mode is compiled LL, so
		// l.hasImmAccept is always false here (see buildMatchBody).
		if t.acceptStates[gs] != 0 {
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
func buildHybridMatchBody(t *dfaTable, l *dfaLayout, tableMemIdx int) []byte {
	var b []byte

	// Class info must have been pre-computed in buildDFALayout for literalChain.
	disp := buildStateDispatch(t, l)
	chain := literalChain(t, l, disp, l.wasmStart)

	const localState = uint32(2)
	const localPos = uint32(3)
	const localClass = uint32(4)

	// Phase 4: when mid-accept dominants exist, add v128 chunk local
	// (and tmp i32 for the non-compressed path, which lacks a class local).
	// Non-mid dominants additionally need 2 i32 hysteresis locals
	// (counter at 6, scratch at 7).
	emitMidDom := len(l.dominantStates) > 0
	hystDom := false
	for _, info := range l.dominantStates {
		if !info.isMidAccept {
			hystDom = true
		}
	}
	if l.useCompression {
		switch {
		case hystDom:
			b = append(b, 0x03, 0x03, 0x7F, 0x01, 0x7B, 0x02, 0x7F) // 3 i32 + 1 v128 + 2 i32 (hyst)
		case emitMidDom:
			b = append(b, 0x02, 0x03, 0x7F, 0x01, 0x7B) // 3 i32 + 1 v128
		default:
			b = append(b, 0x01, 0x03, 0x7F) // 3 i32: state, pos, class
		}
	} else {
		switch {
		case hystDom:
			b = append(b, 0x03, 0x03, 0x7F, 0x01, 0x7B, 0x02, 0x7F) // 3 i32 (+tmp) + 1 v128 + 2 i32 (hyst)
		case emitMidDom:
			b = append(b, 0x02, 0x03, 0x7F, 0x01, 0x7B) // 3 i32 (+tmp) + 1 v128
		default:
			b = append(b, 0x01, 0x02, 0x7F) // 2 i32: state, pos
		}
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
		b = append(b, 0x2D, 0x00, 0x00) // INPUT: mem[ptr+pos]
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // TABLE: classMap[classMapOff + input_byte]
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
		b = appendTableLoad8u(b, tableMemIdx) // TABLE: table[state*numClasses+class] (== state)
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
		b = append(b, 0x2D, 0x00, 0x00) // INPUT: mem[ptr+pos]
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // TABLE: table[state*256+input_byte] (== state)
		b = append(b, 0x21, byte(localState))
	}

	// if state == 0: return -1
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Phase 4 dispatch: chunk=5 v128, tmp=4 (reuse class on useCompression,
	// or extra i32 added by the locals declaration above), hyst=6/7.
	b = emitPhase4Dispatch(b, l.dominantStates, l.midAcceptOff, tableMemIdx, soleMidDominant(l))

	// pos++
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, byte(localPos))

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop $main
	b = append(b, 0x0B)       // end block $done

	// EOF accept (Option D): accepting iff (state-1) u< acceptLimit ? pos : -1
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B) // i32.sub (state - 1)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptLimit)
	b = append(b, 0x49) // i32.lt_u
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
func buildHybridAnchoredFindBody(t *dfaTable, l *dfaLayout, tableMemIdx int) []byte {
	return buildAnchoredFindBody(anchoredFindBodyParams{
		startState:         l.wasmStart,
		tableOff:           l.tableOff,
		midAcceptOff:       l.midAcceptOff,
		classMapOff:        l.classMapOff,
		numClasses:         l.numClasses,
		useU8:              l.useU8,
		useCompression:     l.useCompression,
		acceptLimit:        l.acceptLimit,
		startBeginAccept:   l.startBeginAccept,
		immAcceptLimit:     l.immAcceptLimit,
		hasImmAccept:       l.hasImmAccept,
		wordCharTableOff:   l.wordCharTableOff,
		hasWordBoundary:    l.needWordCharTable,
		midAcceptNWOff:     l.midAcceptNWOff,
		midAcceptWOff:      l.midAcceptWOff,
		midAcceptNLOff:     l.midAcceptNLOff,
		hasNewlineBoundary: t.hasNewlineBoundary,
		tableMemIdx:        tableMemIdx,
	})
}

// buildHybridFindBody returns the WASM function body for the hybrid find path when the
// pattern is non-anchored. It is a thin wrapper that delegates to buildFindBody with
// parameters taken from the pre-computed dfaLayout.
//
// The SIMD prefix scan (emitPrefixScan) is already table/SIMD-only with no br_table
// dispatch, so no restructuring is required for the find hot path.
// Row deduplication is guaranteed disabled for the hybrid path.
// buildHybridFindBody takes the two knobs a neutral TWIN needs: whether a twin
// exists to hand off to (false for the twin itself, which never hands off) and
// an explicit lnmAction5, so the twin can be built from the SAME layout with
// the hint un-forced. Ordinary callers pass (false, l.lnmAction5).
func buildHybridFindBody(t *dfaTable, l *dfaLayout, mandatoryLit *mandatoryLit, tableMemIdx int, hasTwin, lnm bool) ([]byte, findFromMode, int) {
	return buildFindBody(findBodyParams{
		startState:            l.wasmStart,
		midStartState:         l.wasmMidStart,
		midStartWordState:     l.wasmMidStartWord,
		midStartNewlineState:  l.wasmMidStartNewline,
		prefixEndState:        l.wasmPrefixEnd,
		prefixEndStateWord:    l.wasmPrefixEndWord,
		prefixEndStateStart:   l.wasmPrefixEndStart,
		prefixEndStateNewline: l.wasmPrefixEndNewline,
		tableOff:              l.tableOff,
		midAcceptOff:          l.midAcceptOff,
		soleMidDominant:       soleMidDominant(l),
		classChain:            classChainFor(l, t),
		firstByteOff:          l.firstByteOff,
		prefix:                l.prefix,
		classMapOff:           l.classMapOff,
		numClasses:            l.numClasses,
		useU8:                 l.useU8,
		useCompression:        l.useCompression,
		acceptLimit:           l.acceptLimit,
		startBeginAccept:      l.startBeginAccept,
		immAcceptLimit:        l.immAcceptLimit,
		hasImmAccept:          l.hasImmAccept,
		wordCharTableOff:      l.wordCharTableOff,
		hasWordBoundary:       l.needWordCharTable,
		midAcceptNWOff:        l.midAcceptNWOff,
		midAcceptWOff:         l.midAcceptWOff,
		hasNewlineBoundary:    t.hasNewlineBoundary,
		firstByteFlags:        l.firstByteFlags,
		firstBytes:            l.firstBytes,
		teddyLoOff:            l.teddyLoOff,
		teddyHiOff:            l.teddyHiOff,
		teddyT1LoOff:          l.teddyT1LoOff,
		teddyT1HiOff:          l.teddyT1HiOff,
		teddyTwoByte:          len(l.teddyT1LoBytes) > 0,
		teddyT2LoOff:          l.teddyT2LoOff,
		teddyT2HiOff:          l.teddyT2HiOff,
		teddyThreeByte:        len(l.teddyT2LoBytes) > 0,
		teddyT3LoOff:          l.teddyT3LoOff,
		teddyT3HiOff:          l.teddyT3HiOff,
		teddyFourByte:         len(l.teddyT3LoBytes) > 0,
		mandatoryLit:          mandatoryLit,
		rowMapOff:             l.rowMapOff,
		useRowDedup:           l.useRowDedup,
		midAcceptNLOff:        l.midAcceptNLOff,
		tableMemIdx:           tableMemIdx,
		dominantStates:        l.dominantStates,
		lnmAction5:            lnm,
		hasTwin:               hasTwin,
		skipSafeOnDead:        l.skipSafeOnDead,
		eofSkipSafe:           l.eofSkipSafe,
	})
}
