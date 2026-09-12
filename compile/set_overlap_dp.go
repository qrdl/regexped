package compile

import (
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// The backward sweep, and the caller-owned answer cache that makes it
// RESUMABLE.
//
// THE PROBLEM. `overlapping: true` enumerates every start position, so the
// natural implementation walks the suffix DFA forward from each one. On a
// pattern whose automaton never dies — greedy-3's `[^\n]*ERROR` on
// newline-free input — every walk runs to the end of the input and the drive
// is quadratic. Stage A closed the case where such a pattern matches NOWHERE,
// by retiring it once per drive. It cannot touch the case where the pattern is
// genuinely there, which is the `late ERROR 100KB` row: over the 4e9 fuel
// budget in one call.
//
// THE RECURRENCE. The leftmost-first extent of a match from start s is fully
// determined by (state, position, suffix of input), so it satisfies a
// right-to-left recurrence — which is exactly the forward engine's stopping
// rule read backwards (run until dead or immediate-accept; the answer is the
// last accept seen). With q' = delta(q, input[t]):
//
//	t == n   ->  g(q,n) = n if q accepts at EOF, else DEAD
//	otherwise -> g(q,t) = g(q',t+1) if that is not DEAD
//	                      else t if q mid-accepts, else DEAD
//
// THERE IS NO immediateAccept BRANCH, and its absence is load-bearing rather
// than an omission. An earlier form began `q in immediateAccept -> g(q,t) = t`,
// mirroring the forward engine's early stop. It is WRONG here: the forward
// body's immediate-accept arm retires ONE pattern from validMask and keeps
// walking for the others, while the branch as written stops that pattern at
// the CURRENT position — so on `{a*, ""}` over "a" it reported a* as the empty
// match 0-0 instead of 0-1. The corpus found it (`make setcaps`, custom-sets);
// hand-picked patterns did not, because the shape needs a pattern that can
// match empty AND longer sharing a bucket with one that only matches empty.
//
// Dropping it costs nothing, including for the non-greedy patterns it was
// meant to serve: leftmost-first is already encoded in the CONSTRUCTION, so
// after `a+?` takes its minimal match the walk simply stops accepting that
// pattern and the recursion below is dead. That was checked by mutation over
// `a+?`, `a*?b`, `.*?b`, `(?:ab|cd)*?x`, `a|ab`, `(a|b)*?c` and `a+?`-with-
// `a+` before the corpus independently proved the branch harmful.
//
// ONE right-to-left sweep keeping only the CURRENT COLUMN answers every start
// at once, in O(n * |Q|) time and O(|Q|) space, reading the SAME forward
// transition and bitmask tables the ordinary body reads. It emits no tables of
// its own — that is the only reason a second implementation of the
// per-position semantics is defensible.
//
// WHY STAGE B FAILED, AND WHAT CHANGED. Stage B computed that sweep inside ONE
// call and could deliver only if the WHOLE answer fitted the caller's buffer.
// For the shape it targets that is unreachable, and the reason is structural:
// a never-dying pattern that matches anywhere matches from almost every start
// position, so the answer is Theta(n) tuples and no fixed buffer holds it. The
// counting pass then ran, decided it could not deliver, and the ordinary loop
// did the work anyway — measured at a 19.6x REGRESSION, and reverted.
//
// Stage C removes the fits-entirely restriction by making the sweep RESUMABLE.
// It sweeps ONCE on the first call of a drive and writes every tuple into
// caller-owned scratch; every later call copies its window straight out of
// that cache and re-sweeps nothing. That is the move the empty-match rule
// already made once: the module may not own state across calls, and gates
// got past it by making the state the CALLER's. The answer is the same shape
// of problem and takes the same answer.
//
// WHY THE CACHE AND NOT CHECKPOINTED COLUMNS. The first design for this stage
// kept only periodic column snapshots and re-swept from the nearest one on
// each call, trading memory for recomputation. It is strictly worse here. The
// scratch it saves is not saved at all in the case that matters — a never-dying
// pattern's answer is Theta(n) tuples either way — while every call pays a
// re-sweep of up to `stride` positions, so a drive at capacity 1 re-sweeps the
// input Theta(n) times. Storing the finished tuples costs one sweep for the
// whole drive and makes each later call a memcpy. It is also a much smaller
// emitter: no stride arithmetic, no column serialisation, no partial-window
// replay.
//
// WHAT THIS FILE MUST NOT DO, because stage B did it. The sweep must never run
// when stage A's preflight has already retired the patterns: that row
// (`no-match 100KB`) is 9,196,084 fuel today, and stage B took it to
// 179,884,554 by sweeping 100KB to conclude what the preflight already knew.
// Eligibility is therefore gated on the ALIVE mask, not merely on the set's
// shape.

// overlapDPTables is the table geometry one bucket's sweep needs, copied from
// the very params buildSetSuffixBody was given so the forward and backward
// readers cannot disagree about where a table is.
type overlapDPTables struct {
	// ok is false for a bucket whose body was emitted by a path that did not
	// populate this — a sparse or Backtracking bucket — so the sweep can
	// refuse rather than guess.
	ok bool
	l  *dfaLayout

	// The two accept tables the recurrence reads. There is deliberately no
	// immediateAccept table here: see the recurrence above for why that branch
	// was removed, and note that the FORWARD body still reads its own.
	midBitmaskOff int32
	eofBitmaskOff int32

	// The same two tables as VALUES, indexed by WASM state. Lever C's
	// projection is a compile-time partition refinement over them and the
	// transition table, and cannot read a data-segment offset.
	midMasks []uint64
	eofMasks []uint64

	numWASM      int
	wasmStart    uint32
	wasmMidStart uint32

	hasWordChar        bool
	hasNewlineBoundary bool

	// dominant records that the forward body has bulk-skip states. The sweep
	// does NOT use them — it visits every position regardless — but their
	// presence means the forward body's per-position cost is not the sweep's,
	// which matters when comparing the two.
	dominant bool
}

// overlapDPMaxColumn bounds states x patterns. The column is swept twice per
// position (read one, write the other), so this is the per-byte constant of
// the whole sweep as well as its memory.
const overlapDPMaxColumn = 4096

// usesOverlapDP reports whether this set's `find` carries the sweep.
//
// BOTH position-reporting entries, since 2026-09-11: the cache logic is common
// code and `find` calls it, so the sweep is emitted for any overlapping set
// whose shape qualifies rather than only for one that asked for batching.
func (cs *compiledSet) usesOverlapDP() bool { return cs.overlapDPBucket() >= 0 }

// overlapDPBucket returns the index of the single bucket the sweep would run
// over, or -1.
//
// Every restriction here exists to keep ONE reimplementation of the
// per-position semantics defensible. The sweep reproduces buildSetSuffixBody's
// stopping rule exactly; each shape it refuses is one whose rule it would have
// to reproduce a SECOND time, and a second copy of a semantics is how R4
// diverged.
func (cs *compiledSet) overlapDPBucket() int {
	// The sweep only ever runs on an OVERLAPPING set: it enumerates every
	// start position, which is that policy's contract and nobody else's.
	//
	// `hints: [batch-find]` is NOT required. It used to be, because the code
	// that reads a cache lived inside the batching loop; that code is now
	// shared and `find` calls it too, so requiring the hint would be requiring
	// a second entry point nobody asked for in order to make the first one
	// linear.
	if cs.find == "" || !cs.overlapping {
		return -1
	}
	// ONE bucket. With several, a position's tuples come from several DFAs and
	// the delivery order across buckets is a second problem this does not
	// solve.
	if len(cs.buckets) != 1 {
		return -1
	}
	bkt := cs.buckets[0]
	// The bucket must be a FALLBACK one — no literal gate.
	//
	// A literal bucket's suffixDFA matches only what comes AFTER its literal;
	// the frontend finds the literal and enters the DFA at the literal's end.
	// The sweep has no frontend, so running that DFA from every position
	// answers a different question entirely. `a$` as a whole set is one
	// literal bucket, and the sweep reported `2-2` on "aa" where the answer
	// is `1-2` — the suffix `$` matching empty at EOF, with the "a" never
	// looked for. Caught by the corpus (`make setcaps`), not by hand-picked
	// patterns: the earlier literal sets in the differential test all had
	// SEVERAL buckets and were refused a line below, so the one-bucket
	// literal case was the gap.
	if !bkt.isFallback {
		return -1
	}
	dp := bkt.dp
	if !dp.ok || dp.l == nil {
		return -1
	}
	// A sparse bucket keeps per-state accept LISTS rather than an i64 mask,
	// and the sparse rule is that nothing on the candidate path may read an i32
	// mask as authoritative for one. The sweep reads masks.
	if bkt.sparse {
		return -1
	}
	// A Backtracking member has no DFA to sweep at all.
	if bkt.btFallback != nil {
		return -1
	}
	// The mask is i64, so more than 64 patterns cannot be expressed in it.
	// The column bound below is stricter in practice.
	if len(bkt.patterns) == 0 || len(bkt.patterns) > wideBitmapThreshold {
		return -1
	}
	// Anchors and the word-boundary / newline channels change which START
	// STATE a position gets, and the sweep would have to reproduce that choice
	// a second time. Refuse rather than duplicate it.
	if dp.hasWordChar || dp.hasNewlineBoundary {
		return -1
	}
	// u16 state ids would need a second load width throughout. numWASM <= 255
	// is the condition the layout itself uses to pick u8, but assert the flag
	// rather than infer it: they are two decisions and only one is ours.
	if dp.numWASM < 2 || dp.numWASM > 255 || !dp.l.useU8 {
		return -1
	}
	if dp.numWASM*len(bkt.patterns) > overlapDPMaxColumn {
		return -1
	}
	return 0
}

// overlapDPColumnBytes is the module memory the sweep needs for its two
// working columns. This is MODULE scratch and is fine: it lives only for the
// duration of one call, which is what the no-module-state rule permits. The TUPLES are the part
// that must survive between calls, and those are the caller's.
func (cs *compiledSet) overlapDPColumnBytes() int32 {
	bi := cs.overlapDPBucket()
	if bi < 0 {
		return 0
	}
	dp := cs.buckets[bi].dp
	if p := cs.overlapProjFor(bi); p != nil {
		return int32(2 * p.cells * 4)
	}
	return int32(2 * dp.numWASM * len(cs.buckets[bi].patterns) * 4)
}

// overlapProjFor returns lever C's projection for a bucket, computing it once.
//
// Cached on the compiledSet because three places need the SAME answer — the
// column sizing, the emitted projection table and the sweep bodies — and a
// second call that decided differently would size a column one thing and index
// it another.
func (cs *compiledSet) overlapProjFor(bi int) *overlapProj {
	if cs.overlapProjDone {
		return cs.overlapProj
	}
	cs.overlapProjDone = true
	if bi < 0 {
		return nil
	}
	bkt := cs.buckets[bi]
	cs.overlapProj = buildOverlapProj(bkt.dp, len(bkt.patterns))
	return cs.overlapProj
}

// overlapProjTabBytes is the emitted projection table: for each pattern, the
// BYTE OFFSET within a column of every WASM state's cell. u16 because a column
// is bounded well under 64 KB.
func (cs *compiledSet) overlapProjTabBytes() []byte {
	bi := cs.overlapDPBucket()
	if bi < 0 {
		return nil
	}
	p := cs.overlapProjFor(bi)
	if p == nil {
		return nil
	}
	n := cs.buckets[bi].dp.numWASM
	out := make([]byte, 0, len(p.cellOf)*n*2)
	for _, col := range p.cellOf {
		for w := 0; w < n; w++ {
			off := uint16(col[w] * 4)
			out = append(out, byte(off), byte(off>>8))
		}
	}
	return out
}

// emitOverlapDPTransition pushes delta(stateLocal, byteLocal) into dstLocal.
//
// It reproduces the FORWARD table's own indexing — byte-class compression and
// row dedup — because the sweep reads that table rather than emitting one of
// its own. That is the single most important property of this file: there is
// one transition table, and reversing the traversal does not fork it.
// emitOverlapDPCell computes the byte's equivalence class ONCE per position
// and leaves it in cellLocal, which emitOverlapDPTransition then reads.
//
// It used to be inside the transition emitter, i.e. inside the per-STATE loop,
// where `classMap[input[pos]]` is loop-invariant: a load and an add per state
// per byte for a value that cannot change until the position does.
func emitOverlapDPCell(b []byte, dp overlapDPTables, tableMemIdx int, byteLocal, cellLocal byte) []byte {
	if dp.l.useCompression {
		b = append(b, 0x20, byteLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, dp.l.classMapOff)
		b = append(b, 0x6A) // i32.add
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = append(b, 0x20, byteLocal)
	}
	return append(b, 0x21, cellLocal)
}

func emitOverlapDPTransition(b []byte, dp overlapDPTables, tableMemIdx int, stateLocal, cellLocal, dstLocal byte) []byte {
	l := dp.l
	cellsPerState := 256
	if l.useCompression {
		cellsPerState = l.numClasses
	}

	// row = useRowDedup ? rowMap[state] : state
	if l.useRowDedup {
		b = append(b, 0x20, stateLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.rowMapOff)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = append(b, 0x20, stateLocal)
	}
	// addr = tableOff + row*cellsPerState + cell
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(cellsPerState))
	b = append(b, 0x6C) // i32.mul
	b = append(b, 0x20, cellLocal)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.tableOff)
	b = append(b, 0x6A) // i32.add
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x21, dstLocal)
	return b
}

// --- the shared cache logic -------------------------------------------------
//
// Reading a cache is COMMON code, called from both `find` and `find_batch`.
// It used to live inside emitSetFindBatchBody, which is the only reason `find`
// ignored a cache the caller had already handed it: the descriptor carries
// cache_ptr and cache_len and `find` takes the descriptor.
//
// Serving is the one piece that does NOT come out whole, because the two
// entries ask different questions — `find` wants the tuples at the first
// cached position at or after `from` and how many there are, `find_batch`
// wants a bounded slice from its cursor. So the trigger, the sweep call, its
// refusal handling and the work accumulation are here, and each entry keeps
// only its own protocol.

// overlapCacheCtx bundles the local and parameter indices the shared cache
// emitters read. Locals rather than a fixed convention: the two callers
// allocate their frames independently, and threading indices is what lets the
// SAME bytes come out of both.
type overlapCacheCtx struct {
	// dpIdx is the function index of the CHECKPOINT PASS.
	dpIdx int
	// blkIdx is the function index of the BLOCK MATERIALISER. The checkpointed
	// cache answers a position out of one materialised block at a time, so
	// every serving path needs both: the pass to build the checkpoints, and
	// this to turn the one block it wants into tuples.
	blkIdx int
	// costPerByte is what one input byte of sweeping costs, in the same
	// currency the work counter uses (matched bytes).
	costPerByte int64

	pInPtr    byte // input pointer parameter
	pInLen    byte // input length parameter
	pCache    byte // cache_ptr, from the scratch descriptor
	pCacheLen byte // cache_len
	lReady    byte // the header's `ready`, cached for this call
	lWork     byte // the header's `work`, cached for this call
	// lSweepRet holds the sweep's return so the caller can tell a REFUSAL
	// (the region is too small — walk, same answer) from a MALFORMED header
	// (the caller got it wrong — report it).
	lSweepRet byte
	// i64Ret marks the entry whose export returns an i64, which changes only
	// how the error is packed.
	i64Ret bool
}

// emitWorkExceedsSweep pushes 1 when the walk has already spent more than the
// sweep would cost.
//
// Computed in i64 because len * cost overflows i32 on a large input, which
// would make the test wrap and fire at random.
func (c overlapCacheCtx) emitWorkExceedsSweep(b []byte) []byte {
	b = append(b, 0x20, c.lWork, 0xAD) // (u64) work
	b = append(b, 0x20, c.pInLen, 0xAD)
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, c.costPerByte)
	b = append(b, 0x7E) // i64.mul
	b = append(b, 0x56) // i64.gt_u
	return b
}

// emitDefaults seeds the two cached header fields for a call that may find no
// cache at all. -1 is "this drive has no cache", which is what every trigger
// below tests, so both paths read one local rather than each deciding for
// itself.
func (c overlapCacheCtx) emitDefaults(b []byte) []byte {
	b = append(b, 0x41, 0x7F, 0x21, c.lReady)
	b = append(b, 0x41, 0x00, 0x21, c.lWork)
	return b
}

// emitHeaderRead loads `ready` and `work` out of the cache header. Valid only
// where the cache pointer is known non-zero.
func (c overlapCacheCtx) emitHeaderRead(b []byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x28, 0x02, ckptHdrReady)
	b = append(b, 0x21, c.lReady)
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x28, 0x02, ckptHdrWork)
	b = append(b, 0x21, c.lWork)
	return b
}

// emitSweepCall emits the sweep call itself and leaves 1 on the stack when it
// REFUSED — the scratch could not hold the tuples, which is a fallback signal
// rather than an error.
func (c overlapCacheCtx) emitSweepCall(b []byte, pushFrom func([]byte) []byte) []byte {
	b = append(b, 0x20, c.pInPtr)
	b = append(b, 0x20, c.pInLen)
	b = pushFrom(b)
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x20, c.pCacheLen)
	b = append(b, 0x10) // call
	b = utils.AppendULEB128(b, uint32(c.dpIdx))
	b = append(b, 0x22, c.lSweepRet)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48) // i32.lt_s -> the sweep did not deliver
	return b
}

// emitMalformedReturn turns a self-contradictory header into the CALLER's
// error, instead of the silent walk a merely-too-small region gets.
//
// The two outcomes look alike from inside — both are a negative return from the
// sweep — and treating them alike is what plans §9.2 decision 3 forbids. A
// region the caller could not afford is a legitimate answer and degrades
// quietly; a header whose stride is nonsense is a MISTAKE, and left quiet it is
// indistinguishable from the engine declining the shape, on precisely the
// inputs the cache exists for.
//
// Emitted inside the "did not deliver" arm, so the ordinary refusal falls
// through to marking the drive and walking.
func (c overlapCacheCtx) emitMalformedReturn(b []byte, i64Ret bool) []byte {
	b = append(b, 0x20, c.lSweepRet)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.OverlapCacheMalformed))
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.OverlapCacheMalformed))
	if i64Ret {
		// find_batch returns an i64 cursor+count pair. The error rides in the
		// COUNT half, which is where every other negative answer on that entry
		// already lives, with the sentinel cursor above it so a caller that
		// ignores the sign still stops.
		b = append(b, 0xAC) // i64.extend_i32_s
		b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86)
		b = append(b, 0x84) // i64.or
	}
	b = append(b, 0x0F) // return
	b = append(b, 0x0B)
	return b
}

// emitMarkRefused records that this drive must not ask again.
func (c overlapCacheCtx) emitMarkRefused(b []byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x36, 0x02, ckptHdrReady)
	return b
}

// emitStoreWork writes the work counter back to the caller's cache header.
//
// Drive state, so it goes back before every walk-path return — otherwise each
// call would start from zero and a drive of many short calls could never cross
// the line.
func (c overlapCacheCtx) emitStoreWork(b []byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x20, c.lWork)
	b = append(b, 0x36, 0x02, ckptHdrWork)
	return b
}

// emitEntrySweep is the ENTRY-TIME half of the adaptive trigger: not swept yet
// AND the walk has already cost more than the sweep would.
//
// The second half is the whole of the engagement rule: without it this is the
// unconditional sweep that measured 2 wins and 5 regressions. The caller zeroed
// the scratch to start the drive, so a zero `ready` IS "not swept yet" — the
// same contract the gate array has, and the reason no magic value is needed.
//
// lEntrySwept, when >= 0, is set to 1 inside the taken arm: `find_batch` needs
// to know that THIS call is the one that swept, because the cursor it was
// handed still carries a text position where the cache path reads a tuple
// index. `find` has no cursor and passes -1.
func (c overlapCacheCtx) emitEntrySweep(b []byte, pushFrom func([]byte) []byte, lEntrySwept int) []byte {
	b = append(b, 0x20, c.lReady)
	b = append(b, 0x45)
	b = c.emitWorkExceedsSweep(b)
	b = append(b, 0x71) // i32.and
	b = append(b, 0x04, 0x40)
	b = c.emitSweepCall(b, pushFrom)
	b = append(b, 0x04, 0x40)
	b = c.emitMalformedReturn(b, c.i64Ret)
	b = c.emitMarkRefused(b)
	b = append(b, 0x0B) // end if the sweep did not deliver
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x28, 0x02, ckptHdrReady)
	b = append(b, 0x21, c.lReady)
	if lEntrySwept >= 0 {
		b = append(b, 0x41, 0x01, 0x21, byte(lEntrySwept))
	}
	b = append(b, 0x0B) // end if not swept yet
	return b
}

// emitAccumulateWork adds the matched bytes of out[idx..count) to the work
// counter, saturating.
//
// The counter only ever grows and is compared unsigned, so a wrap would read as
// "cheap" on the most expensive drive there is.
//
// idxLocal is consumed as the loop cursor and must already hold the first tuple
// index to charge for.
func (c overlapCacheCtx) emitAccumulateWork(b []byte, pOutPtr, idxLocal, countLocal, tmpLocal byte) []byte {
	b = append(b, 0x02, 0x40)                                          // block $sumDone
	b = append(b, 0x03, 0x40)                                          // loop  $sum
	b = append(b, 0x20, idxLocal, 0x20, countLocal, 0x4E, 0x0D, 0x01)  // idx >= count
	b = append(b, 0x20, pOutPtr, 0x20, idxLocal, 0x41, 12, 0x6C, 0x6A) //nolint:mnd // tuple stride
	b = append(b, 0x22, tmpLocal)
	b = append(b, 0x28, 0x02, 0x08) // tuple.end
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x28, 0x02, 0x04) // tuple.start
	b = append(b, 0x6B)             // end - start
	b = append(b, 0x20, c.lWork, 0x6A)
	b = append(b, 0x22, tmpLocal)
	b = append(b, 0x41, 0x00, 0x48) // < 0 -> it wrapped
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x21, c.lWork) // 0x7FFFFFFF
	b = append(b, 0x05)
	b = append(b, 0x20, tmpLocal, 0x21, c.lWork)
	b = append(b, 0x0B)
	b = append(b, 0x20, idxLocal, 0x41, 0x01, 0x6A, 0x21, idxLocal)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block
	return b
}

// emitEnsureBlock makes block `jLocal` the materialised one, calling the block
// body only when it is not already.
//
// `curBlock` is stored +1 so that the caller's zeroed header reads as "no block
// materialised" without a magic value — the same trick `ready` uses, and the
// reason a drive needs no initialisation beyond zeroing.
//
// It is here, in the shared file, because BOTH find entries need it and a
// second copy is how the two would come to disagree about which block is live
// while sharing one header to say so.
func (c overlapCacheCtx) emitEnsureBlock(b []byte, jLocal byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x28, 0x02, ckptHdrCurBlock)
	b = append(b, 0x20, jLocal)
	b = append(b, 0x41, 0x01, 0x6A) // j+1
	b = append(b, 0x47)             // i32.ne
	b = append(b, 0x04, 0x40)       // if
	b = append(b, 0x20, c.pInPtr)
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x20, jLocal)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(c.blkIdx))
	b = append(b, 0x1A) // drop: the count lands in the header
	b = append(b, 0x0B)
	return b
}

// emitBlockCum pushes cum[idxLocal] — the number of tuples in blocks below it.
func (c overlapCacheCtx) emitBlockCum(b []byte, idxLocal byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x28, 0x02, ckptHdrCntOff)
	b = append(b, 0x20, c.pCache, 0x6A)
	b = append(b, 0x20, idxLocal)
	b = append(b, 0x41, 0x04, 0x6C, 0x6A)
	b = append(b, 0x28, 0x02, 0x00)
	return b
}
