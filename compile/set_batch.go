package compile

import (
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// Set `find_batch`.
//
// `find` answers one position per call and is the right shape for a caller who
// may stop early. `find_batch` answers as many CONSECUTIVE positions as fit in
// the caller's buffer, so a caller who intends to consume everything pays one
// host-boundary crossing per bufferful instead of one per match. They are
// independent capabilities and independent bodies: batching speculates, and a
// `find` caller must never be charged for speculation it discards.
//
// # The cursor
//
// One i64 carries everything the caller must hand back:
//
//	bits 63..32          resume position, or 0xFFFFFFFF when the scan is done
//	bits 31..countBits   k, the intra-position resume index
//	bits countBits-1..0  count — how many tuples of the buffer are valid
//
// countBits is 32 - kBits, and kBits is fixed at compile time from the set's
// pattern count (the worst case for k, since a position reports at most one
// match per pattern). The stubs emit both as constants; a caller decodes count
// and the done flag and passes the whole value back unchanged.
//
// The sentinel is 0xFFFFFFFF rather than 0, because 0 is a legal resume
// position: a first call whose buffer fills on the matches at position 0 must
// resume AT 0.
//
// # Resuming a split position
//
// A position's tuples are all-or-nothing only in `find`. The batch body may
// deliver part of a position and resume inside it, which is what removes any
// lower bound on the buffer size — any capacity >= 1 makes progress. How the
// remainder is remembered differs by mode:
//
//   - gated (the default): the worker records gates for the tuples it
//     DELIVERED rather than for a position that fitted whole, so re-entering
//     the position finds exactly the undelivered patterns still eligible under
//     the §3.16 pre-mask. k stays 0.
//   - overlapping: there is no gate array, so k is passed to the worker as an
//     explicit `skip` and the suffix functions count-but-do-not-write below it.
//
// Both rely on one property: re-entering a position enumerates it identically.
// Candidate order is ascending scan position in either run, the drain stops at
// the same place because lMinStart is the same, and no group at a SMALLER start
// can exist — the resume `from` is the position itself.

// setCursorKBits is config.SetCursorKBits — the ONE definition of the cursor
// layout, shared with every stub generator so the two sides cannot drift.
func setCursorKBits(patternCount int) int { return config.SetCursorKBits(patternCount) }

// setCursorCountBits is the width of the cursor's count field.
func setCursorCountBits(patternCount int) int { return config.SetCursorCountBits(patternCount) }

// setCursorMaxCount is the largest tuple count one find_batch call can report.
// The body clamps out_cap to it, so an over-large buffer costs a shorter batch
// rather than a count that overflows into k.
func setCursorMaxCount(patternCount int) int32 { return config.SetCursorMaxCount(patternCount) }

// emitSetWorkerBody emits the SHARED per-position worker of a batching set:
// the ordinary `find` body, built with compiledSet.batchPos set.
//
// Decision (11a) is what makes it shared. Previously this was the batch
// export's private copy, and the module carried the bucket code twice — the
// exported `find` body plus this one — which is where the measured 10-59%
// module-size cost of declaring `find_batch` came from. Now the exported
// `find` is a thin wrapper over this function too, so a batching set has ONE
// set of bucket code and `find` pays one extra call per position.
//
// The two callers differ in exactly two ways, and both are runtime arguments
// rather than compile-time variants:
//
//   - gated: the gate write-back rule. `find` is transactional at position
//     granularity (§3.11 — an overflowing position records nothing and does
//     not advance); the batch loop gates what it DELIVERED so it can resume
//     inside a split position. That is one parameter, `batch_mode`, tested
//     once per position.
//   - overlapping: `skip`, which already existed. `find` passes 0.
func emitSetWorkerBody(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	cs.batchPos = true
	defer func() { cs.batchPos = false }()
	return emitSetMatchFnFinal(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, capFind, 0)
}

// workerTypeIdx is the WASM type of the shared worker: `find`'s own signature
// plus one trailing i32 — `batch_mode` when gated, §19's `skip` when not.
func (cs *compiledSet) workerTypeIdx() int {
	// Both flavours carry the gate slot now (findGateSlot), so both workers
	// are (ptr, len, from, gate, out, cap, trailing) -> i32. The trailing
	// argument is `batch_mode` when gated and §19's `skip` when not.
	return setMatchTypeSuffix // (i32 x 7) -> i32
}

// emitSetFindWrapperBody emits the exported `find` of a batching set: a
// forwarding call into the shared worker with the batch-only argument zeroed.
//
// Gated:       find(ptr,len,from,gate,out,cap) -> worker(..., batch_mode = 0)
// Overlapping: find(ptr,len,from,gate,out,cap) -> worker(..., skip = 0)
//
// The two signatures are identical since item 11 gave the overlapping body the
// gate slot for its preflight verdict; only the trailing argument's meaning
// differs, and `find` zeroes it either way.
func emitSetFindWrapperBody(cs *compiledSet, workerIdx int) []byte {
	nparams := 5
	if cs.findGateSlot() {
		nparams = 6
	}
	b := []byte{0x00} // no locals
	for i := 0; i < nparams; i++ {
		b = append(b, 0x20, byte(i))
	}
	b = append(b, 0x41, 0x00) // the trailing argument: batch_mode / skip = 0
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(workerIdx))
	b = append(b, 0x0B)
	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitSetFindBatchBody emits the exported find_batch loop.
//
// Signature, both flavours: (ptr, len, cursor i64, gate_ptr, out_ptr, out_cap) -> i64
//
// The overlapping form records no match gates; its array carries the
// once-per-drive preflight verdict (SETS_PLAN item 11).
//
// workerIdx is the function index of the per-position worker emitted by
// emitSetBatchPosBody.
func emitSetFindBatchBody(cs *compiledSet, workerIdx, dpIdx int) []byte {
	gated := cs.gatedFind()
	countBits := setCursorCountBits(cs.patternCount)
	maxCount := setCursorMaxCount(cs.patternCount)
	kMask := int32(uint32(1)<<uint(setCursorKBits(cs.patternCount))) - 1

	// Parameters.
	//
	// The scratch pair is on BOTH flavours, and a gated set simply passes
	// zero. Stage A's lesson was that one signature for both is worth more
	// than two tight ones: the stubs, the descriptor and the docs each stop
	// carrying a fork. Only SETS_PLAN item 11 stage C's overlapping sweep
	// reads it, and it treats a null pointer as "not offered".
	var pInPtr, pInLen, pCursor, pGate, pOutPtr, pOutCap, pScratch, pScratchLen byte
	pInPtr, pInLen, pCursor = 0, 1, 2
	pGate, pOutPtr, pOutCap = 3, 4, 5
	pScratch, pScratchLen = 6, 7
	localBase := byte(8)
	var (
		lPos     = localBase
		lK       = localBase + 1
		lCount   = localBase + 2
		lTotal   = localBase + 3
		lStart   = localBase + 4
		lAvail   = localBase + 5
		lDeliver = localBase + 6
		lDone    = localBase + 7
		lCap     = localBase + 8 // out_cap, clamped to the cursor's count field
		// SETS_PLAN item 11 stage C, cache path only.
		lReady      = localBase + 9
		lIdx        = localBase + 10
		lCacheTotal = localBase + 11
		lSrc        = localBase + 12
		// The adaptive trigger's working locals.
		lWork    = localBase + 13 // matched bytes this drive has delivered
		lWorkIdx = localBase + 14 // cursor over the tuples just delivered
		lWorkTmp = localBase + 15
	)

	// SETS_PLAN item 11 stage C: WHEN to sweep.
	//
	// The sweep costs a flat numStates x patterns per input byte. The walk's
	// cost is data-dependent, and on most shapes it is far cheaper — measured,
	// sweeping unconditionally won 2 rows and lost 5, the worst by 11,557x.
	// No compile-time rule can separate them either: `a+` never dies on 50,000
	// a's and dies instantly on mixed text, so the same set wants opposite
	// answers on different inputs.
	//
	// So the drive decides for itself. It walks, counting the bytes it has
	// matched, and sweeps only once that count exceeds what the sweep would
	// have cost — at which point the sweep is at worst a second helping of
	// work already spent, and it removes a quadratic tail. A drive that never
	// crosses the line never sweeps and keeps the walk's fuel to the
	// instruction.
	sweepCostPerByte := int64(1)
	if bi := cs.overlapDPBucket(); bi >= 0 {
		sweepCostPerByte = int64(cs.buckets[bi].dp.numWASM * len(cs.buckets[bi].patterns))
	}

	var b []byte
	b = append(b, 0x01, 0x10, 0x7F) // 16 x i32

	// emitWorkExceedsSweep pushes 1 when the walk has already spent more than
	// the sweep would cost. Computed in i64 because len * cost overflows i32
	// on a large input, which would make the test wrap and fire at random.
	emitWorkExceedsSweep := func() {
		b = append(b, 0x20, lWork, 0xAD) // (u64) work
		b = append(b, 0x20, pInLen, 0xAD)
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, sweepCostPerByte)
		b = append(b, 0x7E) // i64.mul
		b = append(b, 0x56) // i64.gt_u
	}

	// lCap = min(out_cap, maxCount).
	b = append(b, 0x20, pOutCap)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x20, pOutCap, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x4C) // out_cap <= maxCount
	b = append(b, 0x1B) // select
	b = append(b, 0x21, lCap)

	// ---------------------------------------------------------------
	// SETS_PLAN item 11 stage C: serve from the caller's tuple cache.
	//
	// The sweep runs ONCE per drive and writes every tuple into the caller's
	// scratch; each call after that is a bounds check and a memory.copy. That
	// is the whole reason this beats the walk on a never-dying pattern, where
	// the walk is quadratic and the sweep is linear.
	//
	// Everything below falls through to the ordinary walk when the cache is
	// not available — no scratch offered, or the sweep said the scratch was
	// too small. That is the same rule `out_cap` underflow has: the answer is
	// never wrong, only slower.
	if dpIdx >= 0 {
		// -1 is "this drive has no cache", which is what the walk-loop
		// trigger below tests. Set unconditionally so the two paths read one
		// local rather than each deciding for itself.
		b = append(b, 0x41, 0x7F, 0x21, lReady)
		b = append(b, 0x41, 0x00, 0x21, lWork)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x45)       // i32.eqz -> no scratch offered
		b = append(b, 0x04, 0x40) // if
		b = append(b, 0x05)       // else: scratch is present
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, overlapDPHdrReady)
		b = append(b, 0x21, lReady)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, overlapDPHdrWork)
		b = append(b, 0x21, lWork)

		// Not swept yet AND the walk has already cost more than the sweep
		// would. The second half is the whole of stage C's engagement rule:
		// without it this is the unconditional sweep that measured 2 wins and
		// 5 regressions. The caller zeroed the scratch to start the drive, so
		// a zero `ready` IS "not swept yet" — the same contract the gate array
		// has, and the reason no magic value is needed.
		b = append(b, 0x20, lReady)
		b = append(b, 0x45)
		emitWorkExceedsSweep()
		b = append(b, 0x71) // i32.and
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, pInLen)
		// from = the resume position. Sweeping only [from, len] is what lets a
		// drive switch mid-flight: the walk has already delivered everything
		// below it, so cache index 0 is the first tuple still owed.
		b = append(b, 0x20, pCursor, 0x42, 0x20, 0x88, 0xA7)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x20, pScratchLen)
		b = append(b, 0x10) // call
		b = utils.AppendULEB128(b, uint32(dpIdx))
		b = append(b, 0x41, 0x00)
		b = append(b, 0x48) // i32.lt_s -> the sweep refused
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x41, 0x7F) // -1: refused, and this drive must not retry
		b = append(b, 0x36, 0x02, overlapDPHdrReady)
		b = append(b, 0x0B) // end if the sweep refused
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, overlapDPHdrReady)
		b = append(b, 0x21, lReady)
		b = append(b, 0x0B) // end if not swept yet

		b = append(b, 0x20, lReady)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4A) // i32.gt_s -> the cache is live
		b = append(b, 0x04, 0x40)

		// The cursor's high half carries a TUPLE INDEX on this path rather
		// than a text position. Both are opaque to the caller (docs/wasm.md:
		// "treat everything but the sentinel and count as opaque"), and a
		// drive never mixes the two — `ready` is decided on its first call.
		b = append(b, 0x20, pCursor, 0x42, 0x20, 0x88, 0xA7, 0x21, lIdx)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, overlapDPHdrCount)
		b = append(b, 0x21, lCacheTotal)

		b = append(b, 0x20, lIdx)
		b = append(b, 0x20, lCacheTotal)
		b = append(b, 0x4E) // i32.ge_s -> nothing left
		b = append(b, 0x04, 0x40)
		b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86) // (i64)-1 << 32: done, zero tuples
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		// deliver = min(total - idx, cap)
		b = append(b, 0x20, lCacheTotal)
		b = append(b, 0x20, lIdx)
		b = append(b, 0x6B)
		b = append(b, 0x21, lDeliver)
		b = append(b, 0x20, lDeliver)
		b = append(b, 0x20, lCap)
		b = append(b, 0x20, lDeliver)
		b = append(b, 0x20, lCap)
		b = append(b, 0x4C) // deliver <= cap
		b = append(b, 0x1B) // select
		b = append(b, 0x21, lDeliver)

		// src = scratch + dataOff + idx*12
		b = append(b, 0x20, pScratch)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, overlapDPHdrDataOff)
		b = append(b, 0x6A)
		b = append(b, 0x20, lIdx)
		b = append(b, 0x41, 0x0C, 0x6C) // * 12
		b = append(b, 0x6A)
		b = append(b, 0x21, lSrc)

		b = append(b, 0x20, pOutPtr)
		b = append(b, 0x20, lSrc)
		b = append(b, 0x20, lDeliver)
		b = append(b, 0x41, 0x0C, 0x6C)
		b = append(b, 0xFC, 0x0A, 0x00, 0x00) // memory.copy

		b = append(b, 0x20, lIdx)
		b = append(b, 0x20, lDeliver)
		b = append(b, 0x6A)
		b = append(b, 0x21, lIdx)

		// ret = (idx or sentinel) << 32 | count
		b = append(b, 0x20, lIdx)
		b = append(b, 0x20, lCacheTotal)
		b = append(b, 0x4E)
		b = append(b, 0x04, 0x7E)
		b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86)
		b = append(b, 0x05)
		b = append(b, 0x20, lIdx, 0xAD, 0x42, 0x20, 0x86)
		b = append(b, 0x0B)
		b = append(b, 0x20, lDeliver, 0xAD, 0x84)
		b = append(b, 0x0F)

		b = append(b, 0x0B) // end if cache-live
		b = append(b, 0x0B) // end if/else scratch present
	}

	// lPos = cursor >> 32
	b = append(b, 0x20, pCursor, 0x42, 0x20, 0x88, 0xA7, 0x21, lPos)
	// lK = (wrap(cursor) >> countBits) & kMask
	if gated {
		// The gated worker has no skip parameter: it resumes a split position
		// through the gate array, so k is structurally 0 and never decoded.
		// The FIELD still exists in the cursor — one layout across both modes,
		// one decode in the stubs — it is just always zero here.
		b = append(b, 0x41, 0x00, 0x21, lK)
	} else {
		b = append(b, 0x20, pCursor, 0xA7, 0x41)
		b = utils.AppendSLEB128(b, int32(countBits))
		b = append(b, 0x76, 0x41)
		b = utils.AppendSLEB128(b, kMask)
		b = append(b, 0x71, 0x21, lK)
	}
	b = append(b, 0x41, 0x00, 0x21, lCount)
	// lDone = cap < 1. A buffer with no room can deliver nothing and would
	// otherwise return the caller's own resume position unchanged, so a raw-ABI
	// caller looping on the cursor spins. Reporting the scan finished makes that
	// loop terminate; `find` keeps treating out_cap = 0 as a size probe, which
	// it can, because it returns a count rather than a resumable cursor.
	b = append(b, 0x20, lCap, 0x41, 0x01, 0x48, 0x21, lDone)

	b = append(b, 0x02, 0x40) // block $exit
	b = append(b, 0x03, 0x40) // loop  $L

	// if count >= cap: br $exit  (buffer full — more may remain)
	b = append(b, 0x20, lCount, 0x20, lCap, 0x4E, 0x0D, 0x01)

	// if pos > len: done
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4A, 0x04, 0x40)
	b = append(b, 0x41, 0x01, 0x21, lDone)
	b = append(b, 0x0C, 0x02)
	b = append(b, 0x0B)

	// avail = cap - count
	b = append(b, 0x20, lCap, 0x20, lCount, 0x6B, 0x21, lAvail)

	// total = worker(ptr, len, pos, gate, out_ptr + (count-k)*12,
	//                avail + k [, k])
	b = append(b, 0x20, pInPtr, 0x20, pInLen, 0x20, lPos)
	b = append(b, 0x20, pGate)
	b = append(b, 0x20, pOutPtr, 0x20, lCount)
	if !gated {
		b = append(b, 0x20, lK, 0x6B)
	}
	b = append(b, 0x41, 12, 0x6C, 0x6A)
	b = append(b, 0x20, lAvail)
	if !gated {
		b = append(b, 0x20, lK, 0x6A)
	}
	if gated {
		// batch_mode = 1: gate what is DELIVERED rather than only a position
		// that fitted whole (decision (11a) made this a runtime argument, so
		// the exported `find` can share this worker by passing 0).
		b = append(b, 0x41, 0x01)
	} else {
		b = append(b, 0x20, lK)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(workerIdx))
	b = append(b, 0x21, lTotal)

	// The worker can return abi.BTStackOverflow instead of a count when a
	// Backtracking bucket exhausted its frame budget. Both exits below treat a
	// small total as "nothing more to find", so without this guard "I don't
	// know" would be delivered to the caller as "the scan finished" — the exact
	// silent-wrong-answer this sentinel exists to prevent.
	//
	// The reply is the reserved position word with an all-zero low half, so a
	// caller that decodes before testing still reads a count of zero rather
	// than tuples that were never written.
	if cs.hasBTMember() {
		b = append(b, 0x20, lTotal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, int64(config.SetCursorOverflowPos))
		b = append(b, 0x42, 0x20, 0x86) // << 32
		b = append(b, 0x0F)             // return
		b = append(b, 0x0B)
	}

	// if total <= k: nothing left at or after pos → done. Gated, k is 0 and
	// this is the ordinary "no match" exit.
	// For k == 0 this is the ordinary "no match" exit; for k > 0 it can only
	// fire if a re-entered position enumerated differently, which the resume
	// argument above rules out — the test is what keeps that a truncation
	// rather than a hang if it ever did.
	if gated {
		b = append(b, 0x20, lTotal, 0x41, 0x00, 0x4C, 0x04, 0x40)
	} else {
		b = append(b, 0x20, lTotal, 0x20, lK, 0x4C, 0x04, 0x40)
	}
	b = append(b, 0x41, 0x01, 0x21, lDone)
	b = append(b, 0x0C, 0x02)
	b = append(b, 0x0B)

	// start = out[count].start — every tuple of one position shares it, and
	// the tuple at buffer index `count` is the first one this call delivered.
	b = append(b, 0x20, pOutPtr, 0x20, lCount, 0x41, 12, 0x6C, 0x6A)
	b = append(b, 0x28, 0x02, 0x04)
	b = append(b, 0x21, lStart)

	// deliver = total - k. Gated, k is structurally 0, so the subtraction and
	// its local are skipped and lTotal IS the deliverable count — this loop
	// runs once per POSITION, so its constant matters on a dense input.
	deliver := lTotal
	if !gated {
		b = append(b, 0x20, lTotal, 0x20, lK, 0x6B, 0x21, lDeliver)
		deliver = lDeliver
	}

	// if deliver > avail: the position is split here.
	b = append(b, 0x20, deliver, 0x20, lAvail, 0x4A, 0x04, 0x40)
	b = append(b, 0x20, lCap, 0x21, lCount)
	if !gated {
		b = append(b, 0x20, lK, 0x20, lAvail, 0x6A, 0x21, lK)
	}
	b = append(b, 0x20, lStart, 0x21, lPos)
	b = append(b, 0x0C, 0x02) // br $exit
	b = append(b, 0x0B)

	// Whole position delivered: advance one past its start, exactly as a
	// `find` caller does.
	if dpIdx >= 0 {
		// The first tuple index of this position, for the work sum below.
		b = append(b, 0x20, lCount, 0x21, lWorkIdx)
	}
	b = append(b, 0x20, lCount, 0x20, deliver, 0x6A, 0x21, lCount)
	if !gated {
		b = append(b, 0x41, 0x00, 0x21, lK)
	}
	b = append(b, 0x20, lStart, 0x41, 0x01, 0x6A, 0x21, lPos)

	if dpIdx >= 0 {
		// Accumulate the bytes this position matched, then decide whether to
		// stop walking and sweep the rest.
		//
		// HERE and nowhere else, for two reasons. The work counter only
		// changes when tuples are delivered, so no other point can cross the
		// line; and this is a POSITION BOUNDARY — k is back to 0 — which the
		// switch requires. Switching mid-position would hand the cache a
		// window whose first tuples the walk had already reported.
		// Only while a switch is still possible. ready is -1 when the caller
		// offered no cache or the sweep refused one, and 1 once it has swept —
		// in all three the counter can change nothing. This is the ONE place
		// the adaptive machinery could otherwise charge a caller who declined
		// it, so guarding here is what makes "offer nothing, pay nothing"
		// true rather than nearly true.
		b = append(b, 0x20, lReady)
		b = append(b, 0x45)                                           // ready == 0
		b = append(b, 0x04, 0x40)                                     // if
		b = append(b, 0x02, 0x40)                                     // block $sumDone
		b = append(b, 0x03, 0x40)                                     // loop  $sum
		b = append(b, 0x20, lWorkIdx, 0x20, lCount, 0x4E, 0x0D, 0x01) // idx >= count
		b = append(b, 0x20, pOutPtr, 0x20, lWorkIdx, 0x41, 12, 0x6C, 0x6A)
		b = append(b, 0x22, lWorkTmp)
		b = append(b, 0x28, 0x02, 0x08) // tuple.end
		b = append(b, 0x20, lWorkTmp)
		b = append(b, 0x28, 0x02, 0x04) // tuple.start
		b = append(b, 0x6B)             // end - start
		b = append(b, 0x20, lWork, 0x6A)
		// Saturate. The counter only ever grows and is compared unsigned, so
		// a wrap would read as "cheap" on the most expensive drive there is.
		b = append(b, 0x22, lWorkTmp)
		b = append(b, 0x41, 0x00, 0x48) // < 0 -> it wrapped
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x21, lWork) // 0x7FFFFFFF
		b = append(b, 0x05)
		b = append(b, 0x20, lWorkTmp, 0x21, lWork)
		b = append(b, 0x0B)
		b = append(b, 0x20, lWorkIdx, 0x41, 0x01, 0x6A, 0x21, lWorkIdx)
		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop
		b = append(b, 0x0B) // end block

		emitWorkExceedsSweep()
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, pInLen)
		b = append(b, 0x20, lPos) // from = the next position, already advanced
		b = append(b, 0x20, pScratch)
		b = append(b, 0x20, pScratchLen)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(dpIdx))
		b = append(b, 0x41, 0x00)
		b = append(b, 0x48) // the sweep refused
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x36, 0x02, overlapDPHdrReady)
		b = append(b, 0x41, 0x7F, 0x21, lReady) // and stop asking
		b = append(b, 0x05)
		// Swept. Hand back what this call has already delivered with an
		// INDEX-form cursor: the sweep set ready = 1, so the next call enters
		// through the cache block and reads from tuple 0 — the first start at
		// or after lPos, which is exactly the first one still owed. The count
		// is at least 1 because a position was just delivered, so the caller's
		// "count == 0 means finished" test cannot misfire.
		b = append(b, 0x20, pScratch)
		b = append(b, 0x20, lWork)
		b = append(b, 0x36, 0x02, overlapDPHdrWork)
		b = append(b, 0x20, lCount, 0xAD)
		b = append(b, 0x0F) // return (0 << 32) | count
		b = append(b, 0x0B)
		b = append(b, 0x0B) // end if the work exceeds the sweep
		b = append(b, 0x0B) // end if ready == 0
	}

	b = append(b, 0x0C, 0x00) // continue $L
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $exit

	// The work counter is drive state, so it goes back to the caller's scratch
	// before every walk-path return — otherwise each call would start from
	// zero and a drive of many short calls could never cross the line.
	if dpIdx >= 0 {
		b = append(b, 0x20, pScratch)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x20, lWork)
		b = append(b, 0x36, 0x02, overlapDPHdrWork)
		b = append(b, 0x0B)
	}

	// ret = (pos|sentinel) << 32 | k << countBits | count
	b = append(b, 0x20, lDone, 0x04, 0x7E)
	b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86) // (i64)-1 << 32
	b = append(b, 0x05)
	b = append(b, 0x20, lPos, 0xAD, 0x42, 0x20, 0x86)
	b = append(b, 0x0B)
	b = append(b, 0x20, lK, 0xAD, 0x42)
	b = utils.AppendSLEB128_64(b, int64(countBits))
	b = append(b, 0x86, 0x84)
	b = append(b, 0x20, lCount, 0xAD, 0x84)

	b = append(b, 0x0B) // end function

	out := utils.AppendULEB128(nil, uint32(len(b)))
	return append(out, b...)
}
