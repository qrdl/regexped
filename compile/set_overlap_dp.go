package compile

import (
	"github.com/qrdl/regexped/config"
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

// usesOverlapDP reports whether this set's batching `find` carries the sweep.
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
	// The sweep only ever runs from the batching entry of an OVERLAPPING set:
	// it enumerates every start position, which is that policy's contract and
	// nobody else's.
	if cs.find == "" || !cs.overlapping || !cs.batchFind {
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
	return int32(2 * dp.numWASM * len(cs.buckets[bi].patterns) * 4)
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

// Scratch header, in i32 slots at scratchPtr. The caller zeroes the whole
// region to start a drive, exactly as it zeroes the gate array, so a zero
// `ready` slot IS "this drive has not swept yet" and needs no magic value.
const (
	overlapDPHdrDataOff = 0 // byte offset of the first tuple, from scratchPtr
	overlapDPHdrCount   = 4 // tuples written
	overlapDPHdrReady   = 8 // non-zero once the sweep has run
	// overlapDPHdrWork is the drive's accumulated WORK, in matched bytes: the
	// sum of (end - start) over every tuple the walk has delivered so far.
	//
	// It lives in the caller's scratch for the same reason the gate array
	// does — the module may not own state across calls — and it is
	// what makes the sweep ADAPTIVE rather than unconditional. The header was
	// already 16 bytes with this slot as padding, so nothing about the
	// contract changes: the caller zeroes the header to start a drive, and a
	// zero work count is the honest starting value.
	overlapDPHdrWork = 12
	// The width is config's, not ours: every stub generator has to agree on
	// it independently, so it is stated once, beside the cursor layout.
	overlapDPHdrBytes = config.SetOverlapCacheHeaderBytes
)

// emitOverlapDPBody emits the sweep.
//
//	(ptr, len, from, scratchPtr, scratchLen) -> i32
//
// Sweeps [from, len] ONCE, right to left, and writes every (start,
// pattern, extent) tuple into the caller's scratch. Returns the tuple count,
// or -1 when the scratch could not hold them — which is a FALLBACK signal
// rather than an error: the caller then runs the ordinary walk, the same rule
// `out_cap` underflow already has, so the answer is never wrong, only slower.
//
// TUPLES COME OUT ASCENDING despite the sweep running backwards, and no
// counting pass is needed to arrange that. The writer starts at the END of the
// scratch region and moves DOWN, so the first tuple produced (the highest
// start) lands last in memory and the final tuple lands first. The header
// records where the block begins. Stage B needed a counting pass for exactly
// this and paid for it twice.
//
// The pattern loop is UNROLLED — the count is a compile-time property of the
// bucket — which turns every accept test into a constant mask, every tuple's
// pattern id into a constant, and every column access into a static offset off
// a row base. That is most of the per-entry cost.
func emitOverlapDPBody(cs *compiledSet, tableMemIdx int, colOff int32) []byte {
	bi := cs.overlapDPBucket()
	bkt := cs.buckets[bi]
	dp := bkt.dp
	ids := cs.patternIDs[bi]
	numPat := len(ids)
	numStates := dp.numWASM
	rowBytes := int32(numPat * 4)
	entries := numStates * numPat

	const (
		pPtr = iota
		pLen
		// pFrom bounds the sweep BELOW: it produces tuples for starts in
		// [from, len] and nothing under `from`. That is what lets a drive
		// switch to the cache after the walk has already delivered a prefix —
		// cache index 0 is then the first UNDELIVERED tuple, so no search and
		// no skip count are needed, and the walk-delivered and cache-served
		// halves meet in ascending order by construction.
		pFrom
		pScratch
		pScratchLen
	)
	// Locals begin one past the last parameter. Derived rather than written
	// out: adding `from` to the signature shifted every local by one, and a
	// hardcoded base turned that into a validation error instead of a compile
	// error.
	const (
		lCur = pScratchLen + 1 + iota
		lPrev
		lPos
		lByte
		lState
		lNext
		lVal
		lCount
		lWrite
		lLimit
		lCurRow
		lPrevRow
		lSwap
		lStartRow
	)
	// lCell holds the current byte's equivalence class, computed once per
	// position rather than once per state.
	const lCell = lStartRow + 1
	const (
		lMidMask = lCell + 1 + iota
		lEofMask
	)

	colA := colOff
	colB := colOff + int32(entries*4)

	var b []byte
	b = append(b, 0x02)       // two local groups
	b = append(b, 0x0F, 0x7F) // 15 i32
	b = append(b, 0x02, 0x7E) // 2 i64

	konst := func(v int32) { b = append(b, 0x41); b = utils.AppendSLEB128(b, v) }
	// i64.const takes a SIGNED LEB128, and the whole 64-bit value: encoding it
	// unsigned, or through a uint32, is wrong twice over. Bit 6 is where it
	// first shows — 1<<6 is the single byte 0x40, which reads back as -64, so
	// the mask tests bits 6..63 together instead of bit 6 alone. That is
	// invisible until a bucket holds EIGHT patterns, because with seven there
	// are no higher bits to pick up and the wrong constant gives the right
	// answer. Caught by the corpus, and the reason the differential test now
	// carries a wide-bucket case.
	konst64 := func(v uint64) { b = append(b, 0x42); b = utils.AppendSLEB128_64(b, int64(v)) }
	get := func(l byte) { b = append(b, 0x20, l) }
	set := func(l byte) { b = append(b, 0x21, l) }
	tee := func(l byte) { b = append(b, 0x22, l) }
	add := func() { b = append(b, 0x6A) }
	mul := func() { b = append(b, 0x6C) }

	// loadMask64 pushes the i64 accept mask for the state in `stateLocal`.
	loadMask64 := func(off int32, stateLocal byte) {
		get(stateLocal)
		konst(8)
		mul()
		konst(off)
		add()
		b = appendTableLoad64(b, tableMemIdx)
	}
	// storeCol stores the value on the stack into the current column row at
	// slot k.
	//
	// The two working columns live at cs.overlapDPColOff — a TABLE-memory
	// address (their zero-filled data segment is rewritten to memory 1 in
	// embedded mode), so the access must carry the memory index like every
	// other table access in this body. Standalone (tableMemIdx == 0, which is
	// every harness in this repo) is the same bytes either way; embedded with
	// a raw memory-0 store wrote over the HOST's heap.
	storeCol := func(k int) {
		b = appendTableStore32(b, tableMemIdx, uint32(k*4))
	}
	// loadCol pushes the column value at slot k of the row whose address is
	// already on the stack.
	loadCol := func(k int) {
		b = appendTableLoad32(b, tableMemIdx, uint32(k*4))
	}

	// ---- prologue ----
	get(pScratch)
	get(pScratchLen)
	add()
	set(lWrite) // exclusive end; the writer predecrements
	get(pScratch)
	konst(overlapDPHdrBytes)
	add()
	set(lLimit)
	konst(0)
	set(lCount)
	konst(colA)
	set(lCur)
	konst(colB)
	set(lPrev)

	// ---- column at t == len: len when the state accepts at EOF, else -1 ----
	// From state 1: row 0 is the dead state's, and nothing reads it.
	konst(1)
	set(lState)
	b = append(b, 0x02, 0x40) // block $stateDone
	b = append(b, 0x03, 0x40) // loop $state
	get(lState)
	konst(int32(numStates))
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x0D, 0x01) // br_if $stateDone
	loadMask64(dp.eofBitmaskOff, lState)
	set(lEofMask)
	get(lCur)
	get(lState)
	konst(rowBytes)
	mul()
	add()
	set(lCurRow)
	for k := 0; k < numPat; k++ {
		get(lCurRow)
		get(lEofMask)
		konst64(uint64(1) << uint(k))
		b = append(b, 0x83) // i64.and
		b = append(b, 0x50) // i64.eqz
		b = append(b, 0x04, 0x7F)
		konst(-1)
		b = append(b, 0x05)
		get(pLen)
		b = append(b, 0x0B)
		storeCol(k)
	}
	get(lState)
	konst(1)
	add()
	set(lState)
	b = append(b, 0x0C, 0x00) // br $state
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block

	// emitTuplesAt writes one tuple per matching pattern for the position in
	// lPos, reading the column row for that position's START STATE.
	//
	// Unrolled over patterns so the id is a constant and the column access is
	// a static offset. Writes DOWNWARD from the end of the scratch, which is
	// what makes the finished block ascending without a counting pass.
	emitTuplesAt := func(atZero bool) {
		startState := dp.wasmMidStart
		if atZero {
			startState = dp.wasmStart
		}
		get(lCur)
		konst(int32(startState) * rowBytes)
		add()
		set(lStartRow)
		for k := 0; k < numPat; k++ {
			get(lStartRow)
			loadCol(k)
			tee(lVal)
			konst(-1)
			b = append(b, 0x47)       // i32.ne  -> this pattern matched here
			b = append(b, 0x04, 0x40) // if

			// Reserve twelve bytes. Running past the header is the
			// insufficient-scratch case: bail with -1 and let the caller walk.
			get(lWrite)
			konst(12)
			b = append(b, 0x6B) // i32.sub
			tee(lWrite)
			get(lLimit)
			b = append(b, 0x48) // i32.lt_s
			b = append(b, 0x04, 0x40)
			konst(-1)
			b = append(b, 0x0F) // return -1
			b = append(b, 0x0B)

			get(lWrite)
			konst(int32(ids[k]))
			b = append(b, 0x36, 0x02, 0x00) // tuple.id
			get(lWrite)
			get(lPos)
			b = append(b, 0x36, 0x02, 0x04) // tuple.start
			get(lWrite)
			get(lVal)
			b = append(b, 0x36, 0x02, 0x08) // tuple.end
			get(lCount)
			konst(1)
			add()
			set(lCount)
			b = append(b, 0x0B) // end if
		}
	}

	// Position len first: the empty match at end of input is a legitimate
	// start, and it is the HIGHEST one, so it must be written before any
	// other for the downward fill to come out ascending.
	//
	// The start state is the mid one EXCEPT on empty input, where position
	// len IS position 0 and a begin-anchored pattern has to see the
	// begin-anchored state. The main sweep below runs len-1 down to 0, so on
	// empty input it runs no iterations at all and cannot supply that case —
	// which is why the test is here and not only there. Found by the corpus:
	// `^(?:(?:.|(?:c?)))$` on "" must report 0-0 and reported nothing.
	get(pLen)
	set(lPos)
	// ...but only if position len is at or above the floor. A caller resuming
	// past the end of the input gets nothing, which is the documented contract.
	get(pLen)
	get(pFrom)
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x04, 0x40) // if
	get(pLen)
	b = append(b, 0x45)       // i32.eqz -> the input is empty
	b = append(b, 0x04, 0x40) // if
	emitTuplesAt(true)
	b = append(b, 0x05) // else
	emitTuplesAt(false)
	b = append(b, 0x0B)
	b = append(b, 0x0B)

	// ---- main sweep: t = len-1 down to 0 ----
	get(pLen)
	konst(1)
	b = append(b, 0x6B)
	set(lPos)
	b = append(b, 0x02, 0x40) // block $sweepDone
	b = append(b, 0x03, 0x40) // loop $sweep
	get(lPos)
	get(pFrom)
	b = append(b, 0x48)       // i32.lt_s -> below the caller's floor
	b = append(b, 0x0D, 0x01) // br_if $sweepDone

	// The column just computed becomes the suffix answer for this position.
	get(lCur)
	set(lSwap)
	get(lPrev)
	set(lCur)
	get(lSwap)
	set(lPrev)

	get(pPtr)
	get(lPos)
	add()
	b = appendInputLoad8u(b)
	set(lByte)
	b = emitOverlapDPCell(b, dp, tableMemIdx, lByte, lCell)

	// State 0 is the DEAD state, and its column is never read: every read goes
	// through prev[lNext] with lNext != 0, and both start states are >= 1. It
	// was computed at every position anyway, which at the eligibility floor is
	// a third to a half of the whole sweep.
	konst(1)
	set(lState)
	b = append(b, 0x02, 0x40) // block $stDone
	b = append(b, 0x03, 0x40) // loop $st
	get(lState)
	konst(int32(numStates))
	b = append(b, 0x4E)
	b = append(b, 0x0D, 0x01)

	b = emitOverlapDPTransition(b, dp, tableMemIdx, lState, lCell, lNext)
	loadMask64(dp.midBitmaskOff, lState)
	set(lMidMask)

	get(lCur)
	get(lState)
	konst(rowBytes)
	mul()
	add()
	set(lCurRow)
	get(lPrev)
	get(lNext)
	konst(rowBytes)
	mul()
	add()
	set(lPrevRow)

	for k := 0; k < numPat; k++ {
		get(lCurRow)
		// The recursion, when the suffix answered and the step is not dead.
		get(lNext)
		b = append(b, 0x04, 0x7F)
		get(lPrevRow)
		loadCol(k)
		b = append(b, 0x05)
		konst(-1)
		b = append(b, 0x0B)
		tee(lVal)
		konst(-1)
		b = append(b, 0x47) // i32.ne -> the suffix answered
		b = append(b, 0x04, 0x7F)
		get(lVal)
		b = append(b, 0x05)
		// Otherwise the last accept seen, which is here or nowhere.
		get(lMidMask)
		konst64(uint64(1) << uint(k))
		b = append(b, 0x83)
		b = append(b, 0x50)
		b = append(b, 0x04, 0x7F)
		konst(-1)
		b = append(b, 0x05)
		get(lPos)
		b = append(b, 0x0B)
		b = append(b, 0x0B)
		storeCol(k)
	}

	get(lState)
	konst(1)
	add()
	set(lState)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B) // end state loop

	// Position 0 gets the begin-anchored start state; every other position
	// gets the mid one. The test is on the position, not on the loop, so an
	// input of length 1 reaches both arms correctly.
	get(lPos)
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40)
	emitTuplesAt(true)
	b = append(b, 0x05)
	emitTuplesAt(false)
	b = append(b, 0x0B)

	get(lPos)
	konst(1)
	b = append(b, 0x6B)
	set(lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B) // end sweep

	// ---- header ----
	get(pScratch)
	get(lWrite)
	get(pScratch)
	b = append(b, 0x6B) // i32.sub -> offset of the first tuple
	b = append(b, 0x36, 0x02, overlapDPHdrDataOff)
	get(pScratch)
	get(lCount)
	b = append(b, 0x36, 0x02, overlapDPHdrCount)
	get(pScratch)
	konst(1)
	b = append(b, 0x36, 0x02, overlapDPHdrReady)

	get(lCount)
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}
