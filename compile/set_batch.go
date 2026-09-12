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
//     the gate pre-mask. k stays 0.
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
//     granularity — an overflowing position records nothing and does
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
// plus one trailing i32 — `batch_mode` when gated, the batch `skip` when not.
func (cs *compiledSet) workerTypeIdx() int {
	// Both flavours carry the gate slot now (findGateSlot), so both workers
	// are (ptr, len, from, gate, out, cap, trailing) -> i32. The trailing
	// argument is `batch_mode` when gated and the batch `skip` when not.
	return setMatchTypeSuffix // (i32 x 7) -> i32
}

// emitSetFindWrapperBody emits the exported `find` when it is a WRAPPER: a
// forwarding call into a hidden inner body, with the answer cache read in front
// of it and the drive's work counter charged behind it.
//
// Two independent reasons put a wrapper here (see findWrapped), and they
// compose into one body:
//
//	batching:    find(ptr,len,from,scratch,out,cap) -> worker(..., batch_mode/skip = 0)
//	cache only:  find(ptr,len,from,scratch,out,cap) -> the ordinary find body
//
// The two inner signatures differ by exactly the batch-only trailing argument,
// which `find` zeroes either way.
//
// dpIdx is the backward sweep's function index, or -1 when this set has no
// answer cache — in which case NOTHING below the forwarding call is emitted and
// the body is the bare forwarder it has always been.
//
// # Serving a call out of the cache
//
// The cache holds every (id, start, end) tuple of the drive, ascending by start
// and contiguous within a start, so `find`'s answer is a RUN: the tuples at the
// first cached position at or after `from`. Locating that run is a binary
// search rather than a walk from tuple 0 — a linear locate would make the drive
// quadratic in the tuple count, which is the cost the cache exists to remove.
//
// `find` needs no cursor to do this and is given none: the cache is indexed by
// position and `from` IS the position. The transactional rule is the walk's,
// unchanged — a run longer than out_cap writes nothing and returns the total,
// so the documented "grow the buffer and retry from the same position" still
// holds on this path.
func emitSetFindWrapperBody(cs *compiledSet, innerIdx, dpIdx int) []byte {
	// SIX parameters, always. findGateSlot() is hasFind() by another name and
	// this wrapper is only emitted for a set with `find`, so the 5-parameter
	// branch that used to stand here could not be taken.
	if !cs.findGateSlot() {
		panic("compile: the find wrapper was emitted for a set with no gate slot")
	}
	const (
		pInPtr = iota
		pInLen
		pFrom
		// The SCRATCH DESCRIPTOR on entry. With a cache it is overwritten with
		// the gate pointer below, the same way injectScratchPrologue converts
		// a non-wrapped body's parameter in place.
		pScratch
		pOutPtr
		pOutCap
		nparams
	)

	sweepCostPerByte := int64(1)
	if bi := cs.overlapDPBucket(); bi >= 0 {
		sweepCostPerByte = int64(cs.buckets[bi].dp.numWASM * len(cs.buckets[bi].patterns))
	}

	// Locals only when there is a cache to read, so a set without one emits the
	// same empty declaration vector — and the same bytes — it always has.
	a := newLocalAlloc(nparams)
	var (
		lCache, lCacheLen, lReady, lWork byte
		lTotal, lLo, lHi, lMid, lIdx     byte
		lStart, lSrc, lRun, lN, lTmp     byte
	)
	if dpIdx >= 0 {
		lCache, lCacheLen = a.I32(), a.I32()
		lReady, lWork = a.I32(), a.I32()
		lTotal, lLo, lHi, lMid, lIdx = a.I32(), a.I32(), a.I32(), a.I32(), a.I32()
		lStart, lSrc, lRun, lN, lTmp = a.I32(), a.I32(), a.I32(), a.I32(), a.I32()
	}

	var b []byte
	b = a.EmitDecls(b)

	// The export takes a SCRATCH DESCRIPTOR where the inner body takes a gate
	// pointer, so the wrapper checks the magic and dereferences — the same two
	// steps injectScratchPrologue splices into a non-wrapped set's body. The
	// inner body is left taking a gate, because every one of its callers has
	// dereferenced.
	b = append(b, 0x20, pScratch)
	b = append(b, 0x28, 0x02, abi.FindScratchMagicOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagic)
	b = append(b, 0x47)       // i32.ne
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x00)       // unreachable
	b = append(b, 0x0B)       // end

	cache := overlapCacheCtx{
		dpIdx: dpIdx, costPerByte: sweepCostPerByte,
		pInPtr: pInPtr, pInLen: pInLen,
		pCache: lCache, pCacheLen: lCacheLen,
		lReady: lReady, lWork: lWork,
	}

	if dpIdx >= 0 {
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, abi.FindScratchCacheOff)
		b = append(b, 0x21, lCache)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, abi.FindScratchCacheLenOff)
		b = append(b, 0x21, lCacheLen)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x28, 0x02, abi.FindScratchGateOff)
		b = append(b, 0x21, pScratch)

		b = cache.emitDefaults(b)
		b = append(b, 0x20, lCache)
		b = append(b, 0x45)       // i32.eqz -> no cache offered
		b = append(b, 0x04, 0x40) // if
		b = append(b, 0x05)       // else: the cache is present
		b = cache.emitHeaderRead(b)
		// from = this call's own position. Sweeping only [from, len] is what
		// lets a drive switch mid-flight: every position below `from` was
		// delivered by the walk already, so cache index 0 is the first tuple
		// still owed. `find` has no cursor, so no entry-sweep flag either.
		b = cache.emitEntrySweep(b, func(b []byte) []byte {
			return append(b, 0x20, pFrom)
		}, -1)

		b = append(b, 0x20, lReady)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4A)       // i32.gt_s -> the cache is live
		b = append(b, 0x04, 0x40) // if

		// lo = lower_bound(from): the first tuple whose start is >= from.
		b = append(b, 0x20, lCache)
		b = append(b, 0x28, 0x02, overlapDPHdrCount)
		b = append(b, 0x21, lTotal)
		b = append(b, 0x41, 0x00, 0x21, lLo)
		b = append(b, 0x20, lTotal, 0x21, lHi)
		b = append(b, 0x02, 0x40) // block $found
		b = append(b, 0x03, 0x40) // loop  $bs
		b = append(b, 0x20, lLo, 0x20, lHi, 0x4E, 0x0D, 0x01)
		b = append(b, 0x20, lHi, 0x20, lLo, 0x6B, 0x41, 0x01, 0x76) // (hi-lo) >> 1
		b = append(b, 0x20, lLo, 0x6A)
		b = append(b, 0x22, lMid)
		b = append(b, 0x41, setMatchTupleBytes, 0x6C)
		b = append(b, 0x20, lCache)
		b = append(b, 0x28, 0x02, overlapDPHdrDataOff)
		b = append(b, 0x6A)
		b = append(b, 0x20, lCache, 0x6A)
		b = append(b, 0x28, 0x02, 0x04) // tuple.start
		b = append(b, 0x20, pFrom)
		b = append(b, 0x48)       // i32.lt_s
		b = append(b, 0x04, 0x40) // if
		b = append(b, 0x20, lMid, 0x41, 0x01, 0x6A, 0x21, lLo)
		b = append(b, 0x05) // else
		b = append(b, 0x20, lMid, 0x21, lHi)
		b = append(b, 0x0B)       // end if
		b = append(b, 0x0C, 0x00) // continue $bs
		b = append(b, 0x0B)       // end loop
		b = append(b, 0x0B)       // end block

		// Nothing at or after `from`: the drive is over. `find` says that with
		// a zero count, as the walk does.
		b = append(b, 0x20, lLo, 0x20, lTotal, 0x4E)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x0F) // return 0
		b = append(b, 0x0B)

		// src = cache + dataOff + lo*12, and the run's shared start.
		b = append(b, 0x20, lCache)
		b = append(b, 0x20, lCache)
		b = append(b, 0x28, 0x02, overlapDPHdrDataOff)
		b = append(b, 0x6A)
		b = append(b, 0x20, lLo, 0x41, setMatchTupleBytes, 0x6C, 0x6A)
		b = append(b, 0x22, lSrc)
		b = append(b, 0x28, 0x02, 0x04)
		b = append(b, 0x21, lStart)

		// The run: consecutive tuples sharing that start. Bounded by the
		// pattern count, since a position reports at most one match per
		// pattern.
		b = append(b, 0x20, lLo, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x02, 0x40) // block $runDone
		b = append(b, 0x03, 0x40) // loop  $run
		b = append(b, 0x20, lIdx, 0x20, lTotal, 0x4E, 0x0D, 0x01)
		b = append(b, 0x20, lIdx, 0x20, lLo, 0x6B, 0x41, setMatchTupleBytes, 0x6C)
		b = append(b, 0x20, lSrc, 0x6A)
		b = append(b, 0x28, 0x02, 0x04) // tuple.start
		b = append(b, 0x20, lStart, 0x47, 0x0D, 0x01)
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop
		b = append(b, 0x0B) // end block
		b = append(b, 0x20, lIdx, 0x20, lLo, 0x6B, 0x21, lRun)

		// Transactional at position granularity, exactly as the walk is: a run
		// that does not fit writes NOTHING and reports the total, so out_cap = 0
		// keeps working as a size probe.
		b = append(b, 0x20, lRun, 0x20, pOutCap, 0x4C)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pOutPtr)
		b = append(b, 0x20, lSrc)
		b = append(b, 0x20, lRun, 0x41, setMatchTupleBytes, 0x6C)
		b = append(b, 0xFC, 0x0A, 0x00, 0x00) // memory.copy
		b = append(b, 0x0B)
		b = append(b, 0x20, lRun)
		b = append(b, 0x0F) // return

		b = append(b, 0x0B) // end if the cache is live
		b = append(b, 0x0B) // end if/else the cache is present
	}

	// The walk.
	for i := 0; i < nparams; i++ {
		if i == pScratch {
			b = append(b, 0x20, pScratch)
			if dpIdx < 0 {
				// No cache block ran, so the parameter is still the descriptor.
				b = append(b, 0x28, 0x02, abi.FindScratchGateOff)
			}
			continue
		}
		b = append(b, 0x20, byte(i))
	}
	if cs.batchFind {
		// The worker's trailing argument: batch_mode when gated, the batch
		// skip when not. `find` zeroes it either way. A set wrapped only for
		// the cache calls the ordinary find body, which has no such parameter.
		b = append(b, 0x41, 0x00)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))

	if dpIdx >= 0 {
		// Charge the drive for what the walk just delivered, so the trigger can
		// fire on a later call. ready == 0 is "a cache exists and has not swept
		// yet" — it is -1 when none was offered or the sweep refused one, and
		// the live case returned above — which is what makes "offer nothing,
		// pay nothing" true rather than nearly true.
		//
		// Only tuples actually WRITTEN are charged: a count over out_cap is the
		// transactional overflow, which wrote none, and a Backtracking bucket
		// answers with a negative sentinel instead of a count.
		b = append(b, 0x21, lN)
		b = append(b, 0x20, lReady)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, lN, 0x41, 0x00, 0x4A)
		b = append(b, 0x20, lN, 0x20, pOutCap, 0x4C)
		b = append(b, 0x71) // i32.and
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = cache.emitAccumulateWork(b, pOutPtr, lIdx, lN, lTmp)
		b = cache.emitStoreWork(b)
		b = append(b, 0x0B) // end if anything was written
		b = append(b, 0x0B) // end if ready == 0
		b = append(b, 0x20, lN)
	}

	b = append(b, 0x0B)
	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitSetFindBatchBody emits the exported find_batch loop.
//
// Signature, both flavours: (ptr, len, cursor i64, gate_ptr, out_ptr, out_cap,
// scratch_ptr, scratch_len) -> i64 — EIGHT parameters. The scratch pair is on
// both flavours (only the overlapping sweep reads it), and listing six here
// was simply out of date.
//
// The overlapping form records no match gates; its array carries the
// once-per-drive preflight verdict.
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
	// carrying a fork. Only the overlapping backward sweep
	// reads it, and it treats a null pointer as "not offered".
	var pInPtr, pInLen, pCursor, pGate, pOutPtr, pOutCap byte
	pInPtr, pInLen, pCursor = 0, 1, 2
	pGate, pOutPtr, pOutCap = 3, 4, 5
	// SIX parameters now, not eight. The answer cache used to arrive as the
	// trailing pair; it arrives in the scratch descriptor instead, which is the
	// same place the gate pointer comes from — one description of the caller's
	// scratch rather than two.
	//
	// pGate is the DESCRIPTOR on entry and the gate pointer after the prologue
	// below overwrites it, which is what lets every reference to it stand.
	// Locals come from the allocator, in declaration order (task 67): the index
	// and the declaration are one statement rather than two that must agree.
	a := newLocalAlloc(6)
	var (
		lScratch    = a.I32() // cache_ptr, from the descriptor
		lScratchLen = a.I32() // cache_len
	)
	pScratch, pScratchLen := lScratch, lScratchLen
	var (
		lPos        = a.I32()
		lK          = a.I32()
		lCount      = a.I32()
		lTotal      = a.I32()
		lStart      = a.I32()
		lAvail      = a.I32()
		lDeliver    = a.I32()
		lDone       = a.I32()
		lCap        = a.I32() // out_cap, clamped to the cursor's count field
		lReady      = a.I32()
		lIdx        = a.I32()
		lCacheTotal = a.I32()
		lSrc        = a.I32()
		// The adaptive trigger's working locals.
		lWork    = a.I32() // matched bytes this drive has delivered
		lWorkIdx = a.I32() // cursor over the tuples just delivered
		lWorkTmp = a.I32()
		// 1 when the ENTRY-TIME sweep just ran, so the cursor's high half is
		// still a text POSITION and the cache must be served from tuple 0.
		lEntrySwept = a.I32()
	)

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

	// The cache logic is COMMON code (set_overlap_dp.go): the same emitters
	// serve the exported `find`, which reaches a cache through the same
	// descriptor this entry does.
	cache := overlapCacheCtx{
		dpIdx: dpIdx, costPerByte: sweepCostPerByte,
		pInPtr: pInPtr, pInLen: pInLen,
		pCache: pScratch, pCacheLen: pScratchLen,
		lReady: lReady, lWork: lWork,
	}

	var b []byte
	b = a.EmitDecls(b) // the i32 locals allocated above

	// The scratch prologue, and it has to come FIRST: pGate holds the
	// descriptor on entry, so the cache fields are read before the gate pointer
	// overwrites it. The magic check turns a caller still passing a bare gate
	// array into an immediate trap rather than a pointer read out of gate[0].
	b = append(b, 0x20, pGate)
	b = append(b, 0x28, 0x02, abi.FindScratchMagicOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagic)
	b = append(b, 0x47)       // i32.ne
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x00)       // unreachable
	b = append(b, 0x0B)       // end
	b = append(b, 0x20, pGate)
	b = append(b, 0x28, 0x02, abi.FindScratchCacheOff)
	b = append(b, 0x21, lScratch)
	b = append(b, 0x20, pGate)
	b = append(b, 0x28, 0x02, abi.FindScratchCacheLenOff)
	b = append(b, 0x21, lScratchLen)
	b = append(b, 0x20, pGate)
	b = append(b, 0x28, 0x02, abi.FindScratchGateOff)
	b = append(b, 0x21, pGate)

	// lCap = min(out_cap, maxCount).
	b = append(b, 0x20, pOutCap)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x20, pOutCap, 0x41)
	b = utils.AppendSLEB128(b, maxCount)
	b = append(b, 0x4C) // out_cap <= maxCount
	b = append(b, 0x1B) // select
	b = append(b, 0x21, lCap)

	// out_cap < 1: no room for a tuple, on ANY path. Reported as "the scan
	// finished, zero tuples" so a raw-ABI caller looping on the cursor
	// terminates instead of spinning on its own resume value.
	//
	// It has to be HERE, above the cache block, not only in the walk loop. The
	// cache path runs first and used to return the caller's own cursor with a
	// zero count, which a caller whose rule is "count == 0 means finished"
	// (the TS stub's) reads as the end of the drive — silently dropping every
	// remaining match. A NEGATIVE out_cap was worse still: it reached
	// memory.copy with deliver*12 wrapped to a huge u32, i.e. a trap. The
	// walk path keeps its own lDone form as belt and braces.
	b = append(b, 0x20, lCap, 0x41, 0x01, 0x48) // cap < 1 (signed)
	b = append(b, 0x04, 0x40)                   // if
	b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86) // (i64)-1 << 32
	b = append(b, 0x0F)                         // return
	b = append(b, 0x0B)                         // end if

	// ---------------------------------------------------------------
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
		b = cache.emitDefaults(b)
		b = append(b, 0x41, 0x00, 0x21, lEntrySwept)
		b = append(b, 0x20, pScratch)
		b = append(b, 0x45)       // i32.eqz -> no scratch offered
		b = append(b, 0x04, 0x40) // if
		b = append(b, 0x05)       // else: scratch is present
		b = cache.emitHeaderRead(b)

		// from = the resume position. Sweeping only [from, len] is what lets a
		// drive switch mid-flight: the walk has already delivered everything
		// below it, so cache index 0 is the first tuple still owed.
		//
		// lEntrySwept remembers that THIS call is the one that swept — the
		// cursor it was handed still carries a text POSITION in its high half,
		// and the block below reads that half as a tuple INDEX, so without it
		// the serve would start from tuple P (or report "done") for a resume
		// position P. Unreachable today (every walk-path return leaves
		// work <= threshold or ready != 0, so an entry with work over the line
		// and ready == 0 cannot happen), which is precisely why it must not be
		// left armed for the first change that makes it reachable. `find` has
		// no cursor and passes -1 for it.
		b = cache.emitEntrySweep(b, func(b []byte) []byte {
			return append(b, 0x20, pCursor, 0x42, 0x20, 0x88, 0xA7)
		}, int(lEntrySwept))

		b = append(b, 0x20, lReady)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4A) // i32.gt_s -> the cache is live
		b = append(b, 0x04, 0x40)

		// The cursor's high half carries a TUPLE INDEX on this path rather
		// than a text position. Both are opaque to the caller (docs/wasm.md:
		// "treat everything but the sentinel and count as opaque"), and a
		// drive never mixes the two — `ready` is decided on its first call.
		//
		// EXCEPT on the call that swept at entry: its cursor is still the
		// position form, and everything below that position was delivered
		// before, so cache index 0 is the first tuple still owed.
		b = append(b, 0x20, lEntrySwept)
		b = append(b, 0x04, 0x7F)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x05)
		b = append(b, 0x20, pCursor, 0x42, 0x20, 0x88, 0xA7)
		b = append(b, 0x0B)
		b = append(b, 0x21, lIdx)
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
	//
	// But ONLY when this call has delivered nothing yet. config.SetCursorOverflowPos'
	// contract — "a call returning it has answered nothing, no tuples were
	// written" — is a promise about the CALL, and tuples already written and
	// GATED earlier in this same call cannot be unwritten. Reporting count 0
	// over them loses them for good (the stub throws before yielding, a direct
	// caller reads zero) while the gate array has advanced for matches nobody
	// saw. So a call that has tuples in hand returns them under the ordinary
	// resume cursor, leaving lPos where it is; the next call re-enters at the
	// same position, the worker overflows again with nothing delivered, and
	// the sentinel goes out with a genuinely-zero count and untouched gates.
	if cs.hasBTMember() {
		b = append(b, 0x20, lTotal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
		b = append(b, 0x46)                           // i32.eq
		b = append(b, 0x04, 0x40)                     // if (void)
		b = append(b, 0x20, lCount, 0x41, 0x00, 0x4A) // count > 0
		b = append(b, 0x04, 0x40)                     // if
		// br 3: 0 = this if, 1 = the overflow if, 2 = loop $L, 3 = block $exit.
		b = append(b, 0x0C, 0x03)
		b = append(b, 0x0B) // end if count > 0
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
		b = append(b, 0x45)       // ready == 0
		b = append(b, 0x04, 0x40) // if
		b = cache.emitAccumulateWork(b, pOutPtr, lWorkIdx, lCount, lWorkTmp)

		b = cache.emitWorkExceedsSweep(b)
		b = append(b, 0x04, 0x40)
		// from = the next position, already advanced.
		b = cache.emitSweepCall(b, func(b []byte) []byte {
			return append(b, 0x20, lPos)
		})
		b = append(b, 0x04, 0x40)
		b = cache.emitMarkRefused(b)
		b = append(b, 0x41, 0x7F, 0x21, lReady) // and stop asking
		b = append(b, 0x05)
		// Swept. Hand back what this call has already delivered with an
		// INDEX-form cursor: the sweep set ready = 1, so the next call enters
		// through the cache block and reads from tuple 0 — the first start at
		// or after lPos, which is exactly the first one still owed. The count
		// is at least 1 because a position was just delivered, so the caller's
		// "count == 0 means finished" test cannot misfire.
		b = cache.emitStoreWork(b)
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
		b = cache.emitStoreWork(b)
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
