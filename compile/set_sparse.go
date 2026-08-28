package compile

import (
	"github.com/qrdl/regexped/internal/utils"
)

// ── Sparse-set accept: the >32-pattern suffix body (SETS §23, task G17) ──────
//
// A set whose patterns share ONE mandatory literal packs into ceil(N/32)
// buckets, because the accept bitmask every other path uses is an i32 on the
// per-candidate path. Each bucket costs its own suffix-DFA call at every
// candidate position, so 128 patterns behind one literal cost four walks where
// one would do — measured at 3.33x on a literal-dense input (setperf's
// sharedlit-32 vs sharedlit-128 rows).
//
// This body takes the whole bucket in one walk. Instead of a bitmask per state
// it reads a LIST of pattern indices, which is what lifts the ceiling: the
// bitmask has 32 usable bits, a list has as many entries as the state needs.
//
// WHAT IT DELIBERATELY DOES NOT DO, and why the driver needs no changes:
// `validMask` is ignored. Every mask on the per-candidate path — the group
// mask, the gate pre-mask, §21.6's first-byte mask — is an i32 and cannot
// express more than 32 patterns, and widening all of them to i64 was rejected
// (§23.3) as bigger and riskier than this format, for half the benefit. So the
// per-pattern filtering the driver would have done up front happens HERE
// instead, once per pattern that actually accepted, using the gate array the
// body already receives. The cost is losing the pre-mask's early exits for
// these buckets; the gain is one walk instead of four.

// sparseScratch is the per-bucket working memory a sparse body needs. It is
// allocated once in the module's table memory, not per call.
//
// Nothing here is zeroed per call. `seen` is the only field whose staleness
// would matter, and the body clears exactly the entries it set, walking the
// `fired` list it already has — O(matches), not O(patterns). Untouched WASM
// memory starts zeroed, so the first call sees a clean slate.
type sparseScratch struct {
	endPos int32 // u32 per pattern: where that pattern last accepted
	seen   int32 // u8 per pattern: already in `fired`
	fired  int32 // u16 per pattern: indices that accepted, in first-seen order
	end    int32
}

func planSparseScratch(base int32, numPatterns int) sparseScratch {
	s := sparseScratch{endPos: base}
	s.seen = s.endPos + int32(numPatterns)*4
	s.fired = s.seen + int32(numPatterns)
	s.end = s.fired + int32(numPatterns)*2
	// 8-align so a following table starts clean.
	s.end = (s.end + 7) &^ 7
	return s
}

// sparseAcceptTables is the emitted form of a dfaTable's wide accept lists:
// one 8-byte (offset, count) pair per state per channel, plus one flat u16
// array of pattern indices per channel.
//
// Offset+count rather than an inline list after each transition row because
// the row stride must stay constant for the transition arithmetic; a variable
// tail would cost a multiply per byte on the hot path to save one load here.
type sparseAcceptTables struct {
	midOff, midList int32
	eofOff, eofList int32
	immOff, immList int32
	end             int32
	data            []byte
}

// buildSparseAcceptTables serialises the three channels. Pattern indices are
// BUCKET-LOCAL; the body maps them to global ids through a compile-time table
// when it writes tuples.
func buildSparseAcceptTables(t *dfaTable, base int32, numWASM int) sparseAcceptTables {
	out := sparseAcceptTables{}
	cur := base
	emit := func(m map[int][]uint16) (offTab, listTab int32, blob []byte) {
		offTab = cur
		offBytes := make([]byte, numWASM*8)
		var list []byte
		for gs := 0; gs < numWASM; gs++ {
			// WASM state ids are 1-based against the table's 0-based ids: state
			// 0 is the dead state and carries no accepts.
			ids := m[gs-1]
			if len(ids) == 0 {
				continue
			}
			off := uint32(len(list) / 2)
			putU32(offBytes, gs*8, off)
			putU32(offBytes, gs*8+4, uint32(len(ids)))
			for _, id := range ids {
				list = append(list, byte(id), byte(id>>8))
			}
		}
		cur += int32(len(offBytes))
		listTab = cur
		cur += int32(len(list))
		return offTab, listTab, append(offBytes, list...)
	}
	var b []byte
	var blob []byte
	out.midOff, out.midList, blob = emit(t.midAcceptWide)
	b = append(b, blob...)
	out.eofOff, out.eofList, blob = emit(t.acceptWide)
	b = append(b, blob...)
	out.immOff, out.immList, blob = emit(t.immAcceptWide)
	b = append(b, blob...)
	out.end = cur
	out.data = b
	return out
}

func putU32(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}

// sparseAnchoredInfo is what an anchored bucket's sparse probe hands back to
// the capability body: where it leaves the indices it collected, and the map
// that turns them into global pattern ids. Nil when the bucket took the
// ordinary bitmask probe.
type sparseAnchoredInfo struct {
	scratch  sparseScratch
	idMapOff int32
}

// sparseSuffixParams is everything buildSparseSuffixBody needs that is not
// derivable from the layout.
type sparseSuffixParams struct {
	l            *dfaLayout
	tabs         sparseAcceptTables
	scratch      sparseScratch
	globalIDs    []int // bucket-local index -> global pattern id
	idMapOff     int32 // u32 per pattern: the same map, for the runtime walk
	prefixLen    int   // fixed prefix length to subtract from lPos, 0 if none
	wasmStart    uint32
	wasmMidStart uint32
	tableMemIdx  int
	gated        bool
	hasSkip      bool
}

// buildSparseSuffixBody emits the tuple-writing suffix function for a
// sparse-set bucket. Signature is identical to the bitmask body's, so the
// driver calls it the same way:
//
//	ungated (type 3): (ptr, start, len, lPos, out_ptr, out_cap, validMask) -> i32
//	gated   (type 9): ... , gate_ptr                                       -> i32
func buildSparseSuffixBody(p sparseSuffixParams) []byte {
	const (
		pPtr    = byte(0)
		pStart  = byte(1)
		pLen    = byte(2)
		pLPos   = byte(3)
		pOutPtr = byte(4)
		pOutCap = byte(5)
		_       = byte(6) // validMask: see the file header for why it is unused
		pGate   = byte(7)
		pSkip   = byte(7)
	)
	base := byte(7)
	if p.gated || p.hasSkip {
		base = 8
	}
	var (
		lState = base
		lPos   = base + 1
		lFired = base + 2
		lOff   = base + 3
		lCnt   = base + 4
		lIdx   = base + 5
		lPat   = base + 6
		lTmp   = base + 7
		lOut   = base + 8
		lStart = base + 9
	)
	nLocals := 10

	var b []byte
	b = append(b, 0x01)
	b = utils.AppendULEB128(b, uint32(nLocals))
	b = append(b, 0x7F) // all i32

	// matchStart is lPos minus the bucket's fixed prefix length; computed once.
	b = append(b, 0x20, pLPos)
	if p.prefixLen > 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(p.prefixLen))
		b = append(b, 0x6B)
	}
	b = append(b, 0x21, lStart)

	b = append(b, 0x41, 0x00, 0x21, lFired)
	b = append(b, 0x20, pStart, 0x21, lPos)

	// Entry state, mirroring emitSetEntryState's no-word-boundary path:
	// start == 0 enters with begin-of-text context, otherwise mid-start.
	//
	// These come from the TABLE's own start states, not from the layout —
	// l.wasmMidStart is only populated in find mode and is 0 (the DEAD state)
	// for a suffix DFA, which walks nowhere and reports nothing.
	b = append(b, 0x20, pStart, 0x45)
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(p.wasmStart))
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(p.wasmMidStart))
	b = append(b, 0x0B)
	b = append(b, 0x21, lState)

	// record(channelOffTab, channelListTab) walks the accept list of lState and
	// stamps lPos into endPos for each pattern, adding first-timers to `fired`.
	record := func(b []byte, offTab, listTab int32) []byte {
		// off = offTab[state*8]; cnt = offTab[state*8+4]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, offTab)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad32(b, p.tableMemIdx, 0)
		b = append(b, 0x21, lOff)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, offTab)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad32(b, p.tableMemIdx, 4)
		b = append(b, 0x21, lCnt)
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = append(b, 0x02, 0x40) // block $done
		b = append(b, 0x20, lCnt, 0x45, 0x0D, 0x00)
		b = append(b, 0x03, 0x40) // loop
		// pat = list[(off+idx)*2]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, listTab)
		b = append(b, 0x20, lOff, 0x20, lIdx, 0x6A, 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, p.tableMemIdx)
		b = append(b, 0x21, lPat)
		// endPos[pat] = lPos
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.endPos)
		b = append(b, 0x20, lPat, 0x41, 0x02, 0x74, 0x6A)
		b = append(b, 0x20, lPos)
		b = appendTableStore32(b, p.tableMemIdx, 0)
		// if !seen[pat]: seen[pat]=1; fired[firedCount++] = pat
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.seen)
		b = append(b, 0x20, lPat, 0x6A)
		b = appendTableLoad8u(b, p.tableMemIdx)
		b = append(b, 0x45, 0x04, 0x40) // if eqz
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.seen)
		b = append(b, 0x20, lPat, 0x6A, 0x41, 0x01)
		b = appendTableStore8(b, p.tableMemIdx)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.fired)
		b = append(b, 0x20, lFired, 0x41, 0x01, 0x74, 0x6A)
		b = append(b, 0x20, lPat)
		b = appendTableStore16(b, p.tableMemIdx)
		b = append(b, 0x20, lFired, 0x41, 0x01, 0x6A, 0x21, lFired)
		b = append(b, 0x0B) // end if
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x20, lIdx, 0x20, lCnt, 0x49, 0x0D, 0x00) // idx < cnt -> loop
		b = append(b, 0x0B)                                     // end loop
		b = append(b, 0x0B)                                     // end block
		return b
	}

	b = record(b, p.tabs.midOff, p.tabs.midList)

	// ── the walk ────────────────────────────────────────────────────────────
	b = append(b, 0x02, 0x40)                               // block $exit
	b = append(b, 0x03, 0x40)                               // loop
	b = append(b, 0x20, lPos, 0x20, pLen, 0x4F, 0x0D, 0x01) // pos >= len -> exit
	// emitSetTransition stores the next state into lState itself; it leaves
	// nothing on the stack.
	b = emitSetTransition(b, p.l, lState, lTmp, pPtr, lPos, p.tableMemIdx)
	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01) // dead -> exit
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = record(b, p.tabs.midOff, p.tabs.midList)
	b = append(b, 0x0C, 0x00) // continue
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $exit

	// End-of-input accepts, only when the walk really reached the end.
	b = append(b, 0x20, lPos, 0x20, pLen, 0x46, 0x04, 0x40)
	b = record(b, p.tabs.eofOff, p.tabs.eofList)
	b = append(b, 0x0B)

	// ── emit one tuple per fired pattern ────────────────────────────────────
	b = append(b, 0x41, 0x00, 0x21, lOut) // out count
	b = append(b, 0x41, 0x00, 0x21, lIdx)
	b = append(b, 0x02, 0x40) // block $noneFired
	b = append(b, 0x20, lFired, 0x45, 0x0D, 0x00)
	b = append(b, 0x03, 0x40) // loop over fired
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.fired)
	b = append(b, 0x20, lIdx, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, p.tableMemIdx)
	b = append(b, 0x21, lPat)
	// seen[pat] = 0 — clearing exactly what was set, so no per-call memset.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.seen)
	b = append(b, 0x20, lPat, 0x6A, 0x41, 0x00)
	b = appendTableStore8(b, p.tableMemIdx)
	// end = endPos[pat]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.endPos)
	b = append(b, 0x20, lPat, 0x41, 0x02, 0x74, 0x6A)
	b = appendTableLoad32(b, p.tableMemIdx, 0)
	b = append(b, 0x21, lTmp)

	b = append(b, 0x02, 0x40) // block $skipTuple
	if p.gated {
		// §3.16, applied here rather than by the driver's pre-mask, which
		// cannot address more than 32 patterns. gate[id] is the doubled 2s+1
		// encoding; a non-empty extent needs 2s+1 >= gate, an empty one the
		// stricter 2s >= gate.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.idMapOff)
		b = append(b, 0x20, lPat, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, p.tableMemIdx, 0)
		b = append(b, 0x21, lCnt) // lCnt reused: global id
		b = append(b, 0x20, pGate)
		b = append(b, 0x20, lCnt, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, 0, 0) // gate array lives in the CALLER's memory
		b = append(b, 0x21, lOff)      // lOff reused: gate value
		// bound = 2*start + (extent empty ? 0 : 1)
		b = append(b, 0x20, lStart, 0x41, 0x01, 0x74)
		b = append(b, 0x20, lTmp, 0x20, lStart, 0x47) // end != start
		b = append(b, 0x6A)
		b = append(b, 0x20, lOff, 0x49, 0x0D, 0x00) // bound < gate -> skip
	}
	// §19's skip belongs in the WRITE condition, not in a branch past it: the
	// tuple is counted either way, because the count is what tells the caller
	// how much of this position is still owed. Branching to $skipTuple would
	// jump over the increment below, pinning lOut under `skip` forever — every
	// resumed call then returned 0 tuples and the position's later matches were
	// lost. Only the GATE may branch out, since a gated tuple is not part of
	// this position's sequence at all. buildSetSuffixBody has the same split.
	if p.hasSkip {
		b = append(b, 0x20, lOut, 0x20, pOutCap, 0x48) // out < cap
		b = append(b, 0x20, lOut, 0x20, pSkip, 0x4E)   // out >= skip
		b = append(b, 0x71, 0x04, 0x40)                // and; if
	} else {
		b = append(b, 0x20, lOut, 0x20, pOutCap, 0x48, 0x04, 0x40)
	}
	b = append(b, 0x20, pOutPtr, 0x20, lOut, 0x41, 12, 0x6C, 0x6A, 0x21, lCnt)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.idMapOff)
	b = append(b, 0x20, lPat, 0x41, 0x02, 0x74, 0x6A)
	b = appendTableLoad32(b, p.tableMemIdx, 0)
	b = append(b, 0x21, lOff) // global id
	b = append(b, 0x20, lCnt, 0x20, lOff, 0x36, 0x02, 0x00)
	b = append(b, 0x20, lCnt, 0x20, lStart, 0x36, 0x02, 0x04)
	b = append(b, 0x20, lCnt, 0x20, lTmp, 0x36, 0x02, 0x08)
	b = append(b, 0x0B) // end if room
	b = append(b, 0x20, lOut, 0x41, 0x01, 0x6A, 0x21, lOut)
	b = append(b, 0x0B) // end block $skipTuple

	b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
	b = append(b, 0x20, lIdx, 0x20, lFired, 0x49, 0x0D, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block $noneFired

	b = append(b, 0x20, lOut)
	b = append(b, 0x0B) // end function
	return b
}

// buildSparseProbeBody is the sparse bucket's answer to the scan capabilities.
//
//	(ptr, start, len, validMask) -> i32
//
// A bitmask probe returns bucket-local bits and therefore tops out at 32
// patterns — the same ceiling the tuple body just escaped, and returning one
// from a sparse bucket would silently report only its first 32 patterns. So
// this returns a COUNT instead and writes the matching GLOBAL pattern ids into
// the bucket's scratch, which the driver reads back. The count is an i32 and
// the ids are u32s in memory, so nothing here has a width limit.
//
// Scan semantics, not find: the question is only WHICH patterns match somewhere
// from this start, so no end position is tracked and each pattern is reported
// once. `seen` is cleared on the way out, walking the ids just collected.
func buildSparseProbeBody(p sparseSuffixParams) []byte {
	const (
		pPtr   = byte(0)
		pStart = byte(1)
		pLen   = byte(2)
		_      = byte(3) // validMask: see this file's header
	)
	const (
		lState = byte(4)
		lPos   = byte(5)
		lFound = byte(6)
		lOff   = byte(7)
		lCnt   = byte(8)
		lIdx   = byte(9)
		lPat   = byte(10)
		lTmp   = byte(11)
	)
	var b []byte
	b = append(b, 0x01, 0x08, 0x7F) // 8 i32 locals

	b = append(b, 0x41, 0x00, 0x21, lFound)
	b = append(b, 0x20, pStart, 0x21, lPos)
	b = append(b, 0x20, pStart, 0x45)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(p.wasmStart))
	b = append(b, 0x05)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(p.wasmMidStart))
	b = append(b, 0x0B)
	b = append(b, 0x21, lState)

	// collect walks lState's accept list, appending first-seen GLOBAL ids to
	// the scratch `fired` slots (reused here as a u32 id list).
	collect := func(b []byte, offTab, listTab int32) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, offTab)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad32(b, p.tableMemIdx, 0)
		b = append(b, 0x21, lOff)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, offTab)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad32(b, p.tableMemIdx, 4)
		b = append(b, 0x21, lCnt)
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = append(b, 0x02, 0x40)
		b = append(b, 0x20, lCnt, 0x45, 0x0D, 0x00)
		b = append(b, 0x03, 0x40)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, listTab)
		b = append(b, 0x20, lOff, 0x20, lIdx, 0x6A, 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, p.tableMemIdx)
		b = append(b, 0x21, lPat)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.seen)
		b = append(b, 0x20, lPat, 0x6A)
		b = appendTableLoad8u(b, p.tableMemIdx)
		b = append(b, 0x45, 0x04, 0x40)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.seen)
		b = append(b, 0x20, lPat, 0x6A, 0x41, 0x01)
		b = appendTableStore8(b, p.tableMemIdx)
		// idList[found] = pat — the BUCKET-LOCAL index, not the global id.
		// Storing the global id instead forced the clear-down below to search
		// the id map for each one, which is O(found x patterns): 16K iterations
		// per matching position on a 128-pattern bucket, and it showed up as a
		// 3.5x scan_all regression. The driver maps local to global itself.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.scratch.endPos) // reused as the index list
		b = append(b, 0x20, lFound, 0x41, 0x02, 0x74, 0x6A)
		b = append(b, 0x20, lPat)
		b = appendTableStore32(b, p.tableMemIdx, 0)
		b = append(b, 0x20, lFound, 0x41, 0x01, 0x6A, 0x21, lFound)
		b = append(b, 0x0B)
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x20, lIdx, 0x20, lCnt, 0x49, 0x0D, 0x00)
		b = append(b, 0x0B)
		b = append(b, 0x0B)
		return b
	}

	b = collect(b, p.tabs.midOff, p.tabs.midList)
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	b = append(b, 0x20, lPos, 0x20, pLen, 0x4F, 0x0D, 0x01)
	b = emitSetTransition(b, p.l, lState, lTmp, pPtr, lPos, p.tableMemIdx)
	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01)
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = collect(b, p.tabs.midOff, p.tabs.midList)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	b = append(b, 0x20, lPos, 0x20, pLen, 0x46, 0x04, 0x40)
	b = collect(b, p.tabs.eofOff, p.tabs.eofList)
	b = append(b, 0x0B)

	// Clear `seen` for exactly the indices collected — O(found), no search.
	b = append(b, 0x41, 0x00, 0x21, lIdx)
	b = append(b, 0x02, 0x40)
	b = append(b, 0x20, lFound, 0x45, 0x0D, 0x00)
	b = append(b, 0x03, 0x40)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.seen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.endPos)
	b = append(b, 0x20, lIdx, 0x41, 0x02, 0x74, 0x6A)
	b = appendTableLoad32(b, p.tableMemIdx, 0)
	b = append(b, 0x6A, 0x41, 0x00)
	b = appendTableStore8(b, p.tableMemIdx)
	b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
	b = append(b, 0x20, lIdx, 0x20, lFound, 0x49, 0x0D, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B)

	b = append(b, 0x20, lFound)
	b = append(b, 0x0B)
	return b
}

// buildSparseAnchoredProbeBody is the sparse bucket's answer to the ANCHORED
// trio, and the twin of buildSetProbeBody(anchored=true):
//
//	(ptr, start, len, validMask) -> i32
//
// Same signature as the bitmask anchored probe so emitSetAnchoredCapBody's call
// shape is unchanged, but — like the scan probe above — it returns a COUNT and
// leaves the matching BUCKET-LOCAL indices in the scratch `endPos` array rather
// than a bitmask, because a bitmask is the 32-pattern ceiling this exists to
// escape.
//
// Much smaller than the scan probe, for two reasons that are both consequences
// of "the match must span the whole input" (§3.3):
//
//   - Only the EOF channel is read. A mid-walk accept says nothing about
//     reaching `len`, so there is no per-byte collect and no mid-accept table
//     load in the loop at all.
//   - The scratch `seen` array is never touched. Collection happens ONCE, from
//     a single state's accept list, and a state's list holds distinct indices —
//     so no duplicate can arise and there is nothing to de-duplicate or clear.
//     The scan probe needs `seen` only because it collects at every position.
func buildSparseAnchoredProbeBody(p sparseSuffixParams) []byte {
	const (
		pPtr   = byte(0)
		pStart = byte(1)
		pLen   = byte(2)
		_      = byte(3) // validMask: see this file's header
	)
	const (
		lState = byte(4)
		lPos   = byte(5)
		lFound = byte(6)
		lOff   = byte(7)
		lCnt   = byte(8)
		lIdx   = byte(9)
		lPat   = byte(10)
		lTmp   = byte(11)
	)
	var b []byte
	b = append(b, 0x01, 0x08, 0x7F) // 8 i32 locals

	b = append(b, 0x41, 0x00, 0x21, lFound)
	b = append(b, 0x20, pStart, 0x21, lPos)
	// Unconditionally the start state: emitSetAnchoredCapBody always passes
	// start = 0, so the mid-start branch the scan probe carries would be dead
	// code here — and wasmMidStart is the DEAD state on some tables, which is a
	// trap worth not leaving armed.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(p.wasmStart))
	b = append(b, 0x21, lState)

	// --- walk to end of input ---
	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $walk
	b = append(b, 0x20, lPos, 0x20, pLen, 0x4F, 0x0D, 0x01)
	b = emitSetTransition(b, p.l, lState, lTmp, pPtr, lPos, p.tableMemIdx)
	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01) // dead state: br $done
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	// EOF accepts count only when the whole input was consumed: a run that died
	// early left lPos < len and did not match anchored at all.
	b = append(b, 0x20, lPos, 0x20, pLen, 0x46, 0x04, 0x40)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.tabs.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad32(b, p.tableMemIdx, 0)
	b = append(b, 0x21, lOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.tabs.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad32(b, p.tableMemIdx, 4)
	b = append(b, 0x21, lCnt)
	b = append(b, 0x41, 0x00, 0x21, lIdx)
	b = append(b, 0x02, 0x40)
	b = append(b, 0x20, lCnt, 0x45, 0x0D, 0x00)
	b = append(b, 0x03, 0x40)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.tabs.eofList)
	b = append(b, 0x20, lOff, 0x20, lIdx, 0x6A, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, p.tableMemIdx)
	b = append(b, 0x21, lPat)
	// endPos doubles as the index list, exactly as in the scan probe, and holds
	// BUCKET-LOCAL indices: the driver maps them through idMapOff itself.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, p.scratch.endPos)
	b = append(b, 0x20, lFound, 0x41, 0x02, 0x74, 0x6A)
	b = append(b, 0x20, lPat)
	b = appendTableStore32(b, p.tableMemIdx, 0)
	b = append(b, 0x20, lFound, 0x41, 0x01, 0x6A, 0x21, lFound)
	b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
	b = append(b, 0x20, lIdx, 0x20, lCnt, 0x49, 0x0D, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	b = append(b, 0x0B) // end if lPos == len

	b = append(b, 0x20, lFound)
	b = append(b, 0x0B) // end function
	return b
}
