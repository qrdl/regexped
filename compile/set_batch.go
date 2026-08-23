package compile

import (
	"github.com/qrdl/regexped/config"
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

// emitSetBatchPosBody emits the hidden per-position worker for a find_batch
// export: the ordinary `find` body, built with compiledSet.batchPos set, which
// swaps in §19's gate rule (gated) or its `skip` parameter (overlapping).
func emitSetBatchPosBody(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	cs.batchPos = true
	defer func() { cs.batchPos = false }()
	return emitSetMatchFnFinal(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, capFind, 0)
}

// emitSetFindBatchBody emits the exported find_batch loop.
//
// Signature, gated:      (ptr, len, cursor i64, gate_ptr, out_ptr, out_cap) -> i64
// Signature, overlapping: (ptr, len, cursor i64, out_ptr, out_cap)          -> i64
//
// workerIdx is the function index of the per-position worker emitted by
// emitSetBatchPosBody.
func emitSetFindBatchBody(cs *compiledSet, workerIdx int) []byte {
	gated := cs.gatedFind()
	countBits := setCursorCountBits(cs.patternCount)
	maxCount := setCursorMaxCount(cs.patternCount)
	kMask := int32(uint32(1)<<uint(setCursorKBits(cs.patternCount))) - 1

	// Parameters.
	var pInPtr, pInLen, pCursor, pGate, pOutPtr, pOutCap byte
	pInPtr, pInLen, pCursor = 0, 1, 2
	if gated {
		pGate, pOutPtr, pOutCap = 3, 4, 5
	} else {
		pOutPtr, pOutCap = 3, 4
	}
	localBase := byte(5)
	if gated {
		localBase = 6
	}
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
	)

	var b []byte
	b = append(b, 0x01, 0x09, 0x7F) // 9 x i32

	// lCap = min(out_cap, maxCount).
	b = append(b, 0x20, pOutCap)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x20, pOutCap, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x4C) // out_cap <= maxCount
	b = append(b, 0x1B) // select
	b = append(b, 0x21, lCap)

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

	// total = worker(ptr, len, pos, [gate,] out_ptr + (count-k)*12,
	//                avail + k [, k])
	b = append(b, 0x20, pInPtr, 0x20, pInLen, 0x20, lPos)
	if gated {
		b = append(b, 0x20, pGate)
	}
	b = append(b, 0x20, pOutPtr, 0x20, lCount)
	if !gated {
		b = append(b, 0x20, lK, 0x6B)
	}
	b = append(b, 0x41, 12, 0x6C, 0x6A)
	b = append(b, 0x20, lAvail)
	if !gated {
		b = append(b, 0x20, lK, 0x6A)
	}
	if !gated {
		b = append(b, 0x20, lK)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(workerIdx))
	b = append(b, 0x21, lTotal)

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
	b = append(b, 0x20, lCount, 0x20, deliver, 0x6A, 0x21, lCount)
	if !gated {
		b = append(b, 0x41, 0x00, 0x21, lK)
	}
	b = append(b, 0x20, lStart, 0x41, 0x01, 0x6A, 0x21, lPos)

	b = append(b, 0x0C, 0x00) // continue $L
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $exit

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
