package compile

import (
	"github.com/qrdl/regexped/internal/abi"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The CHECKPOINTED answer cache.
//
// WHAT CHANGES FROM THE WHOLE-DRIVE FORM. The sweep in set_overlap_dp.go
// computes every answer in one right-to-left pass holding ONE column, and then
// stores every tuple it produced — Theta(n * P) bytes, because a never-dying
// pattern matches from nearly every start. Storing the output is the only
// reason the region is linear in the input; the COMPUTATION never needed more
// than a column.
//
// So: keep the pass, throw the output away, and save a COLUMN every k
// positions instead. To answer a position, reload the checkpoint above its
// block and re-sweep that block, writing tuples this time. Each position is
// swept at most twice per drive — once by the checkpoint pass, once when its
// block is materialised — so the drive stays LINEAR, while the region falls to
//
//	hdr + nb*(C+4) + k*B,  minimised at k = sqrt(m*C/B)  ->  ~2*sqrt(m*C*B)
//
// square-root in the input. config.SetOverlapCheckpointBytes is that formula
// and is the ONE copy of it; every stub and both harnesses call it, and the
// sweep VALIDATES what they computed rather than deriving it itself.
//
// WHY A DRIVE AT CAPACITY 1 IS NOT QUADRATIC. The obvious objection to
// checkpointing is that each call re-sweeps up to k positions, so a drive of
// one tuple per call re-sweeps the input Theta(n) times. It does not: a block
// is materialised ONCE and then served out of, which `curBlock` in the header
// is what makes true across calls — and the header is the caller's memory for
// the same reason the gate array is.
//
// WHAT IS DELIBERATELY NOT HERE. The trigger, the sweep call, its
// refusal-versus-error split and the block-ensure are set_overlap_dp.go's and
// are CALLED, not copied. The RECURRENCE itself lives here, in emitAdvance and
// the two EOF-column emitters, because the checkpointed form needs it per CELL
// rather than per (state, pattern); what is shared with the forward body is
// the TABLES it reads, which is the part a second implementation would get
// wrong.

// Header layout, i32 slots at cache_ptr. 48 bytes: eleven fields plus one
// spare word, 4-byte aligned.
//
// The caller zeroes the header to start a drive and then writes `stride`, so a
// zero `ready` still means "not swept yet" and needs no magic value. `stride`
// is the one field the CALLER computes, because the caller is what sized the
// allocation from it: `init` sizes
// the allocation and picks k from the same formula, so the two cannot
// disagree — and the sweep validates it, because the header is caller-owned
// memory and a hand-written caller can write anything.
const (
	ckptHdrBlockOff = 0 // byte offset of the block buffer from cache_ptr
	// Slot +4 is RESERVED and unread. It held the materialised block's tuple
	// count, which nothing consulted: under lever B a block is a row per
	// position and the row masks are the truth, so serving scans them rather
	// than trusting a count. cum[] at ckptHdrCntOff carries what a caller
	// actually wants — cum[j+1]-cum[j] is block j's total — and the tests read
	// it there.
	ckptHdrReady     = 8  // 0 not swept, 1 swept, -1 refused
	ckptHdrWork      = 12 // the drive's accumulated matched bytes
	ckptHdrStride    = 16 // k, written by the CALLER
	ckptHdrFloor     = 20 // the `from` the checkpoint pass used
	ckptHdrNumBlocks = 24 // nb
	ckptHdrCurBlock  = 28 // materialised block index, stored +1 (0 = none)
	ckptHdrCkptOff   = 32 // byte offset of checkpoint 1
	ckptHdrCntOff    = 36 // byte offset of cum[0..nb]
	ckptHdrRowBase   = 40 // the POSITION row 0 of the block buffer stands for
	ckptHdrBytes     = config.SetOverlapCheckpointHeaderBytes
)

// ckptEmit carries every index and constant the checkpoint bodies share, so
// the two of them and the per-position step cannot disagree about a local.
//
// Locals are ALLOCATED rather than hand-numbered (internal/wlocals): the
// declaration vector is generated from the same allocation that hands out the
// indices, which is what makes adding a field to this struct safe.
type ckptEmit struct {
	dp       overlapDPTables
	tableMem int

	numPat    int
	numStates int
	rowBytes  int32
	colA      int32
	colB      int32

	// Parameters, by index.
	pPtr, pLen, pScratch byte

	// Working locals.
	lCur, lPrev, lPos, lByte, lCell, lState, lNext, lVal    byte
	lCount, lWrite, lCurRow, lPrevRow, lSwap, lStart        byte
	lFloor, lStride, lNumBlocks, lCkptOff, lCntOff, lBlkOff byte
	lTmp, lHi, lLo                                          byte
	lMidMask, lEofMask                                      byte

	// lRowBase is the POSITION that row 0 of the block buffer stands for, and
	// lBlkBase the buffer's address. Lever B indexes the buffer by position
	// rather than packing tuples into it, so a row's address is arithmetic on
	// the position and nothing has to be searched to find it.
	lRowBase, lBlkBase, lMask byte

	// lSum is the prefix sum's running total. Its own local rather than a
	// borrowed row pointer: the two have nothing to do with each other, and a
	// reader tracing lPrevRow through this file should not find it holding a
	// count.
	lSum byte

	// proj is lever C's projection, or nil when the column stays one cell per
	// (state, pattern). When set, the column is indexed by CELL and a runtime
	// successor table stands between the state loop and the update.
	proj    *overlapProj
	projOff int32 // data-segment offset of projTab: P*numWASM u16 byte offsets
	// succOff is the scratch array's offset in TABLE memory, one byte per
	// state. No local holds its base: every access is at a compile-time
	// constant address, which is what the full unroll buys.
	succOff int32
}

// colBytes is one working column: cells under lever C, states x patterns
// otherwise.
func (e *ckptEmit) colBytes() int32 {
	if e.proj != nil {
		return int32(e.proj.cells * 4)
	}
	return int32(e.numStates * e.numPat * 4)
}

// rowBytesB is one BLOCK-BUFFER row: a mask word plus one end per pattern.
// `id` and `start` are the row's own coordinates and are not stored — that is
// the whole of the saving, and it is why a dead cell may hold garbage: every
// reader consults the mask first.
//
// Not to be confused with e.rowBytes, which is a COLUMN row (one i32 per
// pattern) in the unprojected sweep. Two different widths, and the names have
// been one letter apart since the block buffer stopped holding tuples.
func (e *ckptEmit) rowBytesB() int32 { return int32(config.SetOverlapBlockRowBytes(e.numPat)) }

// newCkptEmit derives the geometry from the compiled bucket.
func newCkptEmit(cs *compiledSet, tableMemIdx int, colOff int32) *ckptEmit {
	bi := cs.overlapDPBucket()
	bkt := cs.buckets[bi]
	e := &ckptEmit{
		dp:        bkt.dp,
		tableMem:  tableMemIdx,
		numPat:    len(cs.patternIDs[bi]),
		numStates: bkt.dp.numWASM,
	}
	e.rowBytes = int32(e.numPat * 4)
	e.proj = cs.overlapProjFor()
	e.projOff = cs.overlapProjTabOff
	e.succOff = cs.overlapSuccOff
	e.colA = colOff
	e.colB = colOff + e.colBytes()
	return e
}

// ---- small emit helpers, shared by both bodies ----

func (e *ckptEmit) konst(b []byte, v int32) []byte {
	b = append(b, 0x41)
	return utils.AppendSLEB128(b, v)
}
func (e *ckptEmit) konst64(b []byte, v uint64) []byte {
	b = append(b, 0x42)
	return utils.AppendSLEB128_64(b, int64(v))
}
func (e *ckptEmit) get(b []byte, l byte) []byte { return append(b, 0x20, l) }
func (e *ckptEmit) set(b []byte, l byte) []byte { return append(b, 0x21, l) }
func (e *ckptEmit) tee(b []byte, l byte) []byte { return append(b, 0x22, l) }

// The two header accessors take an INT offset and encode it, rather than a
// byte emitted raw. Every header slot is under 128 today, so the two spellings
// agree — but the memarg offset is a ULEB128, and a bare byte of 128 or more is
// read as a continuation. That exact bug shipped once in this file, in the row
// writer at 32 patterns, and there is no reason to keep the shape that caused
// it anywhere it could recur.
func (e *ckptEmit) hdrLoad(b []byte, off int) []byte {
	b = e.get(b, e.pScratch)
	b = append(b, 0x28, 0x02)
	return utils.AppendULEB128(b, uint32(off)) //nolint:gosec // a header offset
}
func (e *ckptEmit) hdrStore(b []byte, off int, push func([]byte) []byte) []byte {
	b = e.get(b, e.pScratch)
	b = push(b)
	b = append(b, 0x36, 0x02)
	return utils.AppendULEB128(b, uint32(off)) //nolint:gosec // a header offset
}

// storeConstAt writes a constant i32 at a byte offset from the region base.
//
// Separate from hdrStore because the offset is not a header slot and can pass
// 127, where a bare byte would be read as the first byte of a multi-byte
// ULEB128 and silently address somewhere else entirely.
func (e *ckptEmit) storeConstAt(b []byte, off, val int32) []byte {
	b = e.get(b, e.pScratch)
	b = e.konst(b, val)
	b = append(b, 0x36, 0x02)
	return utils.AppendULEB128(b, uint32(off))
}

// emitFitsOrRefuse returns -1 when the region cannot hold the layout, where
// pushBlkOff64 pushes the block buffer's i64 offset.
//
// EVERYTHING IS i64 AND THE COMPARISON IS UNSIGNED. The products here reach
// 2^31 on legal inputs and cache_len is a u32; a signed i32 test read a wrapped
// product as "fits" and let the sweep write outside the region.
func (e *ckptEmit) emitFitsOrRefuse(b []byte, pScratchLen byte, pushBlkOff64 func([]byte) []byte) []byte {
	b = pushBlkOff64(b)
	b = e.get(b, e.lStride)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = e.konst64(b, uint64(e.rowBytesB()))
	b = append(b, 0x7E) // i64.mul
	b = append(b, 0x7C) // i64.add
	b = e.get(b, pScratchLen)
	b = append(b, 0xAD)
	b = append(b, 0x56) // i64.gt_u
	b = append(b, 0x04, 0x40)
	b = e.konst(b, -1)
	b = append(b, 0x0F)
	b = append(b, 0x0B)
	return b
}

// loadMask64 pushes the i64 accept mask for the state in stateLocal.
func (e *ckptEmit) loadMask64(b []byte, off int32, stateLocal byte) []byte {
	b = e.get(b, stateLocal)
	b = e.konst(b, 8)
	b = append(b, 0x6C) // i32.mul
	b = e.konst(b, off)
	b = append(b, 0x6A) // i32.add
	return appendTableLoad64(b, e.tableMem)
}

// emitEOFColumn fills the CURRENT column with the t == len answer: `len` where
// the state accepts at EOF, DEAD otherwise.
//
// From state 1: row 0 is the dead state's and nothing reads it, since every
// read goes through a non-zero successor and both start states are >= 1.
func (e *ckptEmit) emitEOFColumn(b []byte) []byte {
	if e.proj != nil {
		return e.emitEOFColumnProj(b)
	}
	b = e.konst(b, 1)
	b = e.set(b, e.lState)
	b = append(b, 0x02, 0x40) // block
	b = append(b, 0x03, 0x40) // loop
	b = e.get(b, e.lState)
	b = e.konst(b, int32(e.numStates))
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x0D, 0x01) // br_if done
	b = e.loadMask64(b, e.dp.eofBitmaskOff, e.lState)
	b = e.set(b, e.lEofMask)
	b = e.get(b, e.lCur)
	b = e.get(b, e.lState)
	b = e.konst(b, e.rowBytes)
	b = append(b, 0x6C, 0x6A) // i32.mul, i32.add
	b = e.set(b, e.lCurRow)
	for k := 0; k < e.numPat; k++ {
		b = e.get(b, e.lCurRow)
		b = e.get(b, e.lEofMask)
		b = e.konst64(b, uint64(1)<<uint(k))
		b = append(b, 0x83) // i64.and
		b = append(b, 0x50) // i64.eqz
		b = append(b, 0x04, 0x7F)
		b = e.konst(b, -1)
		b = append(b, 0x05)
		b = e.get(b, e.pLen)
		b = append(b, 0x0B)
		b = appendTableStore32(b, e.tableMem, uint32(k*4))
	}
	b = e.get(b, e.lState)
	b = e.konst(b, 1)
	b = append(b, 0x6A)
	b = e.set(b, e.lState)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitAdvance emits ONE position's transition: swap the columns, read
// input[lPos], and recompute every state's row from the previous column.
//
// This is set_overlap_dp.go's recurrence, unchanged, and it is the reason both
// bodies below can exist without a second copy of the semantics.
func (e *ckptEmit) emitAdvance(b []byte) []byte {
	if e.proj != nil {
		return e.emitAdvanceProj(b)
	}
	b = e.get(b, e.lCur)
	b = e.set(b, e.lSwap)
	b = e.get(b, e.lPrev)
	b = e.set(b, e.lCur)
	b = e.get(b, e.lSwap)
	b = e.set(b, e.lPrev)

	b = e.get(b, e.pPtr)
	b = e.get(b, e.lPos)
	b = append(b, 0x6A)
	b = appendInputLoad8u(b)
	b = e.set(b, e.lByte)
	b = emitOverlapDPCell(b, e.dp, e.tableMem, e.lByte, e.lCell)

	b = e.konst(b, 1)
	b = e.set(b, e.lState)
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	b = e.get(b, e.lState)
	b = e.konst(b, int32(e.numStates))
	b = append(b, 0x4E)
	b = append(b, 0x0D, 0x01)

	b = emitOverlapDPTransition(b, e.dp, e.tableMem, e.lState, e.lCell, e.lNext)
	b = e.loadMask64(b, e.dp.midBitmaskOff, e.lState)
	b = e.set(b, e.lMidMask)

	b = e.get(b, e.lCur)
	b = e.get(b, e.lState)
	b = e.konst(b, e.rowBytes)
	b = append(b, 0x6C, 0x6A)
	b = e.set(b, e.lCurRow)
	b = e.get(b, e.lPrev)
	b = e.get(b, e.lNext)
	b = e.konst(b, e.rowBytes)
	b = append(b, 0x6C, 0x6A)
	b = e.set(b, e.lPrevRow)

	for k := 0; k < e.numPat; k++ {
		b = e.get(b, e.lCurRow)
		b = e.get(b, e.lNext)
		b = append(b, 0x04, 0x7F)
		b = e.get(b, e.lPrevRow)
		b = appendTableLoad32(b, e.tableMem, uint32(k*4))
		b = append(b, 0x05)
		b = e.konst(b, -1)
		b = append(b, 0x0B)
		b = e.tee(b, e.lVal)
		b = e.konst(b, -1)
		b = append(b, 0x47) // i32.ne -> the suffix answered
		b = append(b, 0x04, 0x7F)
		b = e.get(b, e.lVal)
		b = append(b, 0x05)
		b = e.get(b, e.lMidMask)
		b = e.konst64(b, uint64(1)<<uint(k))
		b = append(b, 0x83, 0x50)
		b = append(b, 0x04, 0x7F)
		b = e.konst(b, -1)
		b = append(b, 0x05)
		b = e.get(b, e.lPos)
		b = append(b, 0x0B, 0x0B)
		b = appendTableStore32(b, e.tableMem, uint32(k*4))
	}

	b = e.get(b, e.lState)
	b = e.konst(b, 1)
	b = append(b, 0x6A)
	b = e.set(b, e.lState)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitAtPosition emits the per-position ACTION for the position in lPos,
// reading the start-state row of the current column.
//
// write=false only counts into lCount; write=true also writes the position's
// ROW, at the row's own address — rowBase + (pos - rowBase) * rowBytes — so
// there is no fill order to get right and nothing to sort afterwards. Both are
// emitted from one function so the "which patterns match here" test cannot fork
// between counting and writing: a block whose count and contents disagree would
// make cum[] describe a block that is not there.
func (e *ckptEmit) emitAtPosition(b []byte, atZero bool, write bool) []byte {
	startState := e.dp.wasmMidStart
	if atZero {
		startState = e.dp.wasmStart
	}
	if e.proj == nil {
		b = e.get(b, e.lCur)
		b = e.konst(b, int32(startState)*e.rowBytes)
		b = append(b, 0x6A)
		b = e.set(b, e.lStart)
	} else {
		// Projected: the start state is a compile-time constant, so its cell
		// for each pattern is one too, and the row base is just the column.
		b = e.get(b, e.lCur)
		b = e.set(b, e.lStart)
	}

	// The row's address, computed ONCE per position rather than per pattern:
	// blockBase + (pos - rowBase) * rowBytes.
	if write {
		b = e.get(b, e.lBlkBase)
		b = e.get(b, e.lPos)
		b = e.get(b, e.lRowBase)
		b = append(b, 0x6B) // pos - rowBase
		b = e.konst(b, e.rowBytesB())
		b = append(b, 0x6C, 0x6A)
		b = e.set(b, e.lWrite)
		b = e.konst(b, 0)
		b = e.set(b, e.lMask)
	}

	for k := 0; k < e.numPat; k++ {
		b = e.get(b, e.lStart)
		if e.proj != nil {
			b = appendTableLoad32(b, e.tableMem, uint32(e.cellFor(k, int(startState))))
		} else {
			b = appendTableLoad32(b, e.tableMem, uint32(k*4))
		}
		b = e.tee(b, e.lVal)
		b = e.konst(b, -1)
		b = append(b, 0x47) // i32.ne
		b = append(b, 0x04, 0x40)
		if write {
			// One store per HIT — the end — against three under the tuple
			// form, plus one mask store per position below.
			// The memarg OFFSET is ULEB128, not a byte. At 32 patterns the
			// last row field sits at 128, which as a bare byte is a
			// continuation marker and swallowed the next opcode — the module
			// failed to validate with "nothing on stack" a long way from here.
			b = e.get(b, e.lWrite)
			b = e.get(b, e.lVal)
			b = append(b, 0x36, 0x02)
			b = utils.AppendULEB128(b, uint32(config.SetOverlapRowEndOff(k))) //nolint:gosec // a row offset
			b = e.get(b, e.lMask)
			b = e.konst(b, int32(1)<<uint(k))
			b = append(b, 0x72) // i32.or
			b = e.set(b, e.lMask)
		}
		b = e.get(b, e.lCount)
		b = e.konst(b, 1)
		b = append(b, 0x6A)
		b = e.set(b, e.lCount)
		b = append(b, 0x0B)
	}

	// The mask is stored ALWAYS, zero included: it is what tells a reader the
	// row holds nothing, and it is how serving skips a run of non-matching
	// positions without consulting anything else.
	if write {
		b = e.get(b, e.lWrite)
		b = e.get(b, e.lMask)
		b = append(b, 0x36, 0x02, 0x00)
	}
	return b
}

// emitAtPositionGuarded picks the begin-anchored start state at position 0 and
// the mid one elsewhere.
func (e *ckptEmit) emitAtPositionGuarded(b []byte, write bool) []byte {
	b = e.get(b, e.lPos)
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40)
	b = e.emitAtPosition(b, true, write)
	b = append(b, 0x05)
	b = e.emitAtPosition(b, false, write)
	b = append(b, 0x0B)
	return b
}

// allocCommon allocates the locals BOTH checkpoint bodies use, in one order.
//
// The two allocated the same thirteen by hand, in the same sequence, and the
// declaration vector is generated from the allocation — so a body that added
// one in the middle would renumber every local after it in itself alone. The
// order is the emitted order and is load-bearing; nothing here may be
// reordered without regenerating both sweep fixtures.
func (e *ckptEmit) allocCommon(a *localAlloc) {
	e.lCur, e.lPrev = a.I32(), a.I32()
	e.lPos, e.lByte, e.lCell = a.I32(), a.I32(), a.I32()
	e.lState, e.lNext, e.lVal = a.I32(), a.I32(), a.I32()
	e.lCount, e.lWrite = a.I32(), a.I32()
	e.lCurRow, e.lPrevRow, e.lSwap, e.lStart = a.I32(), a.I32(), a.I32(), a.I32()
	e.lFloor, e.lStride, e.lNumBlocks = a.I32(), a.I32(), a.I32()
	e.lCkptOff, e.lCntOff, e.lBlkOff = a.I32(), a.I32(), a.I32()
}

// emitCkptPassBody emits the CHECKPOINT PASS.
//
//	(ptr, len, from, scratch, scratchLen) -> i32
//
// Sweeps [from, len] once, right to left, saving a column every `stride`
// positions and counting each block's tuples — and materialising block 0 as it
// goes, since the pass ENDS inside block 0 and the first call of a drive would
// otherwise have to re-sweep it immediately.
//
// Returns the tuple count of block 0, or -1 when the region is too small (a
// FALLBACK signal: the caller walks, same answer, slower), or -4 when the
// header contradicts itself (an ERROR, surfaced to the caller, because a
// silently-declined cache is indistinguishable from the engine legitimately
// refusing the shape).
//
// THE SWEEP IS TWO LOOPS, NOT ONE WITH A MODE BIT. Block 0 is the LAST block
// visited, so "count above it, count and write inside it" is a split in the
// position range rather than a per-position branch. Loop A runs down to just
// above block 0 and only counts; loop B runs through block 0 and also writes.
// At nb == 1 loop A is empty and loop B covers everything, which is the
// degenerate case that a mode bit would have had to get right at every
// position instead of once.
// emitCkptPassPrologue validates the caller's header, derives the layout and
// seeds the sweep's working state.
//
// Split out because it is a UNIT and the rest of the pass is a different one:
// everything here is about what the caller handed in — is the region big
// enough, is the stride sane, does the layout fit — and nothing about the
// recurrence. It is also what the serving paths' own validator has to agree
// with, field for field, which is easier to see when it is one function.
//
// Returns early (a WASM `return`) on every refusal, so the caller's code after
// it runs only on a header the sweep accepted.
func (e *ckptEmit) emitCkptPassPrologue(b []byte, pFrom, pLen, pScratch, pScratchLen byte,
	lM, lBlkIdx, lBound, lBlk0End, lCnt64, lBlk64 byte, cellBytes int32,
) []byte {
	// ---- prologue: validate, then derive the layout ----
	//
	// The order is load-bearing. A region too small to hold the header is
	// refused before one byte of it is written; the stride is validated before
	// EITHER arm uses it, so a malformed header reports -4 whatever the resume
	// position is; and only then does `from > len` take its shortcut.

	// Unsigned, because cache_len is a u32 byte count in the ABI.
	b = e.get(b, pScratchLen)
	b = e.konst(b, ckptHdrBytes)
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)
	b = e.konst(b, -1)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// A stride BELOW 1 is a header the caller got wrong, and is reported rather
	// than guessed at: zero would divide by zero and a negative one would index
	// backwards out of the region.
	b = e.hdrLoad(b, ckptHdrStride)
	b = e.tee(b, e.lStride)
	b = e.konst(b, 1)
	b = append(b, 0x48) // i32.lt_s
	b = append(b, 0x04, 0x40)
	b = e.konst(b, int32(abi.OverlapCacheMalformed))
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// `from` above `len` is not an error: the ABI defines it as "nothing
	// found". It still has to leave a LAYOUT behind, because it publishes
	// `ready` and serving validates the header it then reads. What it writes is
	// the empty ONE-BLOCK layout a real single-position sweep would have
	// produced, so the validator needs no special case — a `cntOff` of 48 here
	// would contradict `cntOff == ckptOff + numBlocks*cellBytes` and turn every
	// such call into -4.
	b = e.get(b, pFrom)
	b = e.get(b, pLen)
	b = append(b, 0x4A) // i32.gt_s
	b = append(b, 0x04, 0x40)
	// The stride becomes 1 and is stored: this layout spans ONE position that
	// does not exist, so one row is all it could ever need, and the caller's k
	// — sized for the whole input — would otherwise demand a block buffer the
	// region need not have and turn a legal resume into a refusal.
	b = e.konst(b, 1)
	b = e.set(b, e.lStride)
	b = e.emitFitsOrRefuse(b, pScratchLen, func(b []byte) []byte {
		return e.konst64(b, uint64(ckptHdrBytes+cellBytes+8))
	})
	b = e.hdrStore(b, ckptHdrStride, func(b []byte) []byte { return e.konst(b, 1) })
	b = e.hdrStore(b, ckptHdrCkptOff, func(b []byte) []byte { return e.konst(b, ckptHdrBytes) })
	b = e.hdrStore(b, ckptHdrCntOff, func(b []byte) []byte { return e.konst(b, ckptHdrBytes+cellBytes) })
	b = e.hdrStore(b, ckptHdrBlockOff, func(b []byte) []byte { return e.konst(b, ckptHdrBytes+cellBytes+8) })
	b = e.hdrStore(b, ckptHdrCurBlock, func(b []byte) []byte { return e.konst(b, 1) })
	b = e.hdrStore(b, ckptHdrNumBlocks, func(b []byte) []byte { return e.konst(b, 1) })
	b = e.hdrStore(b, ckptHdrFloor, func(b []byte) []byte { return e.get(b, pFrom) })
	b = e.hdrStore(b, ckptHdrRowBase, func(b []byte) []byte { return e.get(b, pFrom) })
	// cum[0] = cum[1] = 0: an empty block 0 and a zero total.
	b = e.storeConstAt(b, ckptHdrBytes+cellBytes, 0)
	b = e.storeConstAt(b, ckptHdrBytes+cellBytes+4, 0)
	b = e.hdrStore(b, ckptHdrReady, func(b []byte) []byte { return e.konst(b, 1) })
	b = e.konst(b, 0)
	b = append(b, 0x0F) // return 0
	b = append(b, 0x0B)

	b = e.get(b, pFrom)
	b = e.set(b, e.lFloor)
	b = e.get(b, pLen)
	b = e.get(b, e.lFloor)
	b = append(b, 0x6B) // i32.sub
	b = e.konst(b, 1)
	b = append(b, 0x6A)
	b = e.set(b, lM) // m = len - from + 1

	// A stride WIDER than the span being swept is NOT an error, and treating it
	// as one broke every drive that engaged late. `init` sizes the stride for
	// the WHOLE input, because that is all it knows at allocation time, but the
	// sweep runs over [from, len] and engages only once the walk has proven
	// expensive — so by the time it runs, `from` may leave fewer positions than
	// one stride. Clamp to m, which is the single-block case, and the region
	// sized for the full input is necessarily large enough for it.
	b = e.get(b, e.lStride)
	b = e.get(b, lM)
	b = append(b, 0x4A) // i32.gt_s
	b = append(b, 0x04, 0x40)
	b = e.get(b, lM)
	b = e.set(b, e.lStride)
	b = append(b, 0x0B)
	// The clamped value goes BACK to the header. Serving divides by the
	// header's copy to locate a block, so a pass that kept a different stride
	// to itself would have the two disagree about where every block starts.
	b = e.hdrStore(b, ckptHdrStride, func(b []byte) []byte { return e.get(b, e.lStride) })

	// nb = ceil(m / stride)
	b = e.get(b, lM)
	b = e.get(b, e.lStride)
	b = append(b, 0x6A)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.get(b, e.lStride)
	b = append(b, 0x6E) // i32.div_u
	b = e.set(b, e.lNumBlocks)

	// Layout: ckpt | cum | block buffer, computed in i64.
	//
	// nb*cellBytes passes 2^31 at a legal stride of 1 — a 131 KB input with a
	// 16 KB column, or a 1.5 KB column at 1.4 MB — and an i32 product wraps
	// NEGATIVE, which a signed "too small" test reads as "fits". Every
	// checkpoint then lands at a wrapped address in the caller's memory, which
	// is precisely what this check exists to prevent.
	b = e.konst64(b, uint64(ckptHdrBytes))
	b = e.get(b, e.lNumBlocks)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = e.konst64(b, uint64(cellBytes))
	b = append(b, 0x7E) // i64.mul
	b = append(b, 0x7C) // i64.add
	b = e.set(b, lCnt64)
	b = e.get(b, lCnt64)
	b = e.get(b, e.lNumBlocks)
	b = append(b, 0xAD)
	b = e.konst64(b, 1)
	b = append(b, 0x7C)
	b = e.konst64(b, 4)
	b = append(b, 0x7E)
	b = append(b, 0x7C)
	b = e.set(b, lBlk64)

	// Too small: refuse, and let the drive walk.
	b = e.emitFitsOrRefuse(b, pScratchLen, func(b []byte) []byte { return e.get(b, lBlk64) })

	// Past the check the three offsets are below cache_len and are used as i32
	// addresses from here on, exactly as every other address in this file is.
	b = e.konst(b, ckptHdrBytes)
	b = e.set(b, e.lCkptOff)
	b = e.get(b, lCnt64)
	b = append(b, 0xA7) // i32.wrap_i64
	b = e.set(b, e.lCntOff)
	b = e.get(b, lBlk64)
	b = append(b, 0xA7)
	b = e.set(b, e.lBlkOff)

	// Header fields the serving paths read.
	b = e.hdrStore(b, ckptHdrFloor, func(b []byte) []byte { return e.get(b, e.lFloor) })
	b = e.hdrStore(b, ckptHdrNumBlocks, func(b []byte) []byte { return e.get(b, e.lNumBlocks) })
	b = e.hdrStore(b, ckptHdrCkptOff, func(b []byte) []byte { return e.get(b, e.lCkptOff) })
	b = e.hdrStore(b, ckptHdrCntOff, func(b []byte) []byte { return e.get(b, e.lCntOff) })
	b = e.hdrStore(b, ckptHdrBlockOff, func(b []byte) []byte { return e.get(b, e.lBlkOff) })

	// block0End = min(floor + stride - 1, len)
	b = e.get(b, e.lFloor)
	b = e.get(b, e.lStride)
	b = append(b, 0x6A)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.tee(b, lBlk0End)
	b = e.get(b, pLen)
	b = append(b, 0x4A)
	b = append(b, 0x04, 0x40)
	b = e.get(b, pLen)
	b = e.set(b, lBlk0End)
	b = append(b, 0x0B)

	// Rows are written AT their own address, in whatever order the sweep
	// reaches them, so there is no downward fill and no ordering trick: row r
	// stands for position rowBase + r and nothing else can occupy it.
	b = e.get(b, pScratch)
	b = e.get(b, e.lBlkOff)
	b = append(b, 0x6A)
	b = e.set(b, e.lBlkBase)
	b = e.get(b, e.lFloor)
	b = e.set(b, e.lRowBase)

	b = e.konst(b, 0)
	b = e.set(b, e.lCount)
	b = e.konst(b, e.colA)
	b = e.set(b, e.lCur)
	b = e.konst(b, e.colB)
	b = e.set(b, e.lPrev)
	b = e.emitSeedDeadCell(b)

	return b
}

func emitCkptPassBody(cs *compiledSet, tableMemIdx int, colOff int32) []byte {
	e := newCkptEmit(cs, tableMemIdx, colOff)

	const (
		pPtr = iota
		pLen
		pFrom
		pScratch
		pScratchLen
		nparams
	)
	e.pPtr, e.pLen, e.pScratch = pPtr, pLen, pScratch

	a := newLocalAlloc(nparams)
	e.allocCommon(a)
	e.lTmp, e.lHi, e.lLo = a.I32(), a.I32(), a.I32()
	lM, lBlkIdx, lBound, lBlk0End := a.I32(), a.I32(), a.I32(), a.I32()
	e.lRowBase, e.lBlkBase, e.lMask = a.I32(), a.I32(), a.I32()
	e.lSum = a.I32()
	e.lMidMask, e.lEofMask = a.I64(), a.I64()
	// The layout is computed in i64 (see the prologue): nb*cellBytes passes
	// 2^31 at a stride of 1 on a large input with a wide column.
	lCnt64, lBlk64 := a.I64(), a.I64()

	cellBytes := e.colBytes()

	var b []byte
	b = a.EmitDecls(b)

	konst := func(v int32) { b = e.konst(b, v) }
	get := func(l byte) { b = e.get(b, l) }
	set := func(l byte) { b = e.set(b, l) }

	b = e.emitCkptPassPrologue(b, pFrom, pLen, pScratch, pScratchLen,
		lM, lBlkIdx, lBound, lBlk0End, lCnt64, lBlk64, cellBytes)

	// ---- the EOF column, and checkpoint nb ----
	b = e.emitEOFColumn(b)
	b = e.emitCopyColumnToCkpt(b, e.lNumBlocks, cellBytes)

	// Position len. It belongs to block 0 exactly when nb == 1, and is WRITTEN
	// only then — the bug the earlier draft of the plan had was excluding it
	// from the block sweep entirely, which silently dropped every
	// end-of-input match.
	// Per-block counting runs from the TOP block down; cum[] is prefix-summed
	// in the epilogue, because the pass produces the blocks in reverse. This is
	// seeded BEFORE position `len` is emitted, because `len` belongs to the top
	// block and has to be counted into it and close it.
	get(e.lNumBlocks)
	konst(1)
	b = append(b, 0x6B)
	set(lBlkIdx)
	get(e.lFloor)
	get(lBlkIdx)
	get(e.lStride)
	b = append(b, 0x6C, 0x6A)
	set(lBound)

	get(pLen)
	set(e.lPos)
	b = e.emitCheckpointAt(b, lBlkIdx, lBound, cellBytes)
	get(pLen)
	get(lBlk0End)
	b = append(b, 0x4C) // i32.le_s -> len is inside block 0
	b = append(b, 0x04, 0x40)
	b = e.emitAtPositionGuarded(b, true)
	b = append(b, 0x05)
	b = e.emitAtPositionGuarded(b, false)
	b = append(b, 0x0B)
	b = e.emitCloseBlockAt(b, lBlkIdx, lBound)

	// ---- loop A: t = len-1 .. block0End+1, COUNT ONLY ----
	b = e.emitSweepLoop(b, lBlk0End, lBlkIdx, lBound, cellBytes)

	// ---- loop B: t = min(len, block0End) .. floor, COUNT AND WRITE ----
	// Position len was already handled above, so B starts one below it when
	// block 0 reaches the end of the input.
	b = e.emitSweepLoopBlockZero(b)

	// cnt[0] is block 0's.
	b = e.emitStoreBlockCount(b, lBlkIdx)

	// ---- epilogue: prefix-sum cum[], publish the materialised block ----
	b = e.emitPrefixSumCounts(b)
	b = e.hdrStore(b, ckptHdrCurBlock, func(b []byte) []byte { return e.konst(b, 1) })
	b = e.hdrStore(b, ckptHdrRowBase, func(b []byte) []byte { return e.get(b, e.lRowBase) })
	b = e.hdrStore(b, ckptHdrReady, func(b []byte) []byte { return e.konst(b, 1) })

	get(e.lCount)
	b = append(b, 0x0B)

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitCopyColumnToCkpt copies the CURRENT working column into checkpoint
// `idxLocal` (1-based; checkpoint nb is the EOF column).
//
// `memory.copy` with TWO memory indices, and they differ in embedded mode: the
// working columns live in TABLE memory, which is memory 1 after wasm-merge,
// while the cache is in the CALLER's memory 0. Emitting a same-memory copy
// here wrote over the host's heap — the trap set_overlap_dp.go's storeCol
// comment records for the single-value case, and it applies with more force to
// a bulk copy.
func (e *ckptEmit) emitCopyColumnToCkpt(b []byte, idxLocal byte, cellBytes int32) []byte {
	// dst = scratch + ckptOff + (idx-1)*cellBytes
	b = e.get(b, e.pScratch)
	b = e.get(b, e.lCkptOff)
	b = append(b, 0x6A)
	b = e.get(b, idxLocal)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.konst(b, cellBytes)
	b = append(b, 0x6C, 0x6A)
	// src = the current column
	b = e.get(b, e.lCur)
	b = e.konst(b, cellBytes)
	// memory.copy dst src len, with dst memory 0 (caller) and src the table memory.
	b = append(b, 0xFC, 0x0A, 0x00, byte(e.tableMem))
	return b
}

// emitLoadCkptToColumn is the reverse: checkpoint `idxLocal` into the current
// working column, which is how a block materialisation starts.
func (e *ckptEmit) emitLoadCkptToColumn(b []byte, idxLocal byte, cellBytes int32) []byte {
	b = e.get(b, e.lCur)
	b = e.get(b, e.pScratch)
	b = e.get(b, e.lCkptOff)
	b = append(b, 0x6A)
	b = e.get(b, idxLocal)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.konst(b, cellBytes)
	b = append(b, 0x6C, 0x6A)
	b = e.konst(b, cellBytes)
	b = append(b, 0xFC, 0x0A, byte(e.tableMem), 0x00)
	return b
}

// emitStoreBlockCount writes the running count into cnt[idxLocal] and resets it.
func (e *ckptEmit) emitStoreBlockCount(b []byte, idxLocal byte) []byte {
	b = e.get(b, e.pScratch)
	b = e.get(b, e.lCntOff)
	b = append(b, 0x6A)
	b = e.get(b, idxLocal)
	b = e.konst(b, 4)
	b = append(b, 0x6C, 0x6A)
	b = e.get(b, e.lCount)
	b = append(b, 0x36, 0x02, 0x00)
	b = e.konst(b, 0)
	b = e.set(b, e.lCount)
	return b
}

// emitSweepLoop is loop A: t from len-1 down to just above block 0, counting
// only, saving a checkpoint and closing a block whenever it crosses a boundary.
func (e *ckptEmit) emitSweepLoop(b []byte, lBlk0End, lBlkIdx, lBound byte, cellBytes int32) []byte {
	b = e.get(b, e.pLen)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.set(b, e.lPos)

	b = append(b, 0x02, 0x40) // block done
	b = append(b, 0x03, 0x40) // loop
	b = e.get(b, e.lPos)
	b = e.get(b, lBlk0End)
	b = append(b, 0x4C)       // i32.le_s -> we have reached block 0
	b = append(b, 0x0D, 0x01) // br_if done

	b = e.emitAdvance(b)

	// The column just computed is the suffix answer at lPos. When lPos is a
	// block start it is exactly the checkpoint the block BELOW needs.
	b = e.emitCheckpointAt(b, lBlkIdx, lBound, cellBytes)

	// COUNT ONLY: loop A runs above block 0, and only block 0 is materialised
	// by the pass. Everything above it is rebuilt on demand.
	b = e.emitAtPositionGuarded(b, false)

	// Closing a block: lPos has just been counted into it, and the next
	// position down belongs to the block beneath.
	b = e.emitCloseBlockAt(b, lBlkIdx, lBound)

	b = e.get(b, e.lPos)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.set(b, e.lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitSweepLoopBlockZero is loop B: the positions of block 0, counted AND
// written. lPos is already correct on entry from loop A's exit.
func (e *ckptEmit) emitSweepLoopBlockZero(b []byte) []byte {
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	b = e.get(b, e.lPos)
	b = e.get(b, e.lFloor)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x0D, 0x01) // br_if done
	b = e.emitAdvance(b)
	b = e.emitAtPositionGuarded(b, true)
	b = e.get(b, e.lPos)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.set(b, e.lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitPrefixSumCounts turns the per-block counts into cumulative ones:
// cum[j] = tuples in blocks 0..j-1, with cum[nb] the drive's total.
//
// Done in the epilogue rather than as the pass goes, because the pass visits
// blocks from the TOP down and a prefix sum reads from the bottom up.
func (e *ckptEmit) emitPrefixSumCounts(b []byte) []byte {
	// Walk j = nb-1 .. 0 turning cnt[j] into a running total shifted up by one
	// slot, so cnt[] becomes cum[] in place with cum[0] = 0.
	b = e.konst(b, 0)
	b = e.set(b, e.lTmp) // running
	b = e.konst(b, 0)
	b = e.set(b, e.lLo) // j
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	b = e.get(b, e.lLo)
	b = e.get(b, e.lNumBlocks)
	b = append(b, 0x4E) // i32.ge_s
	b = append(b, 0x0D, 0x01)

	// addr = scratch + cntOff + j*4
	b = e.get(b, e.pScratch)
	b = e.get(b, e.lCntOff)
	b = append(b, 0x6A)
	b = e.get(b, e.lLo)
	b = e.konst(b, 4)
	b = append(b, 0x6C, 0x6A)
	b = e.set(b, e.lHi)

	// next = running + cnt[j]; cnt[j] = running; running = next
	b = e.get(b, e.lHi)
	b = append(b, 0x28, 0x02, 0x00)
	b = e.get(b, e.lTmp)
	b = append(b, 0x6A)
	b = e.set(b, e.lSum) // the running total
	b = e.get(b, e.lHi)
	b = e.get(b, e.lTmp)
	b = append(b, 0x36, 0x02, 0x00)
	b = e.get(b, e.lSum)
	b = e.set(b, e.lTmp)

	b = e.get(b, e.lLo)
	b = e.konst(b, 1)
	b = append(b, 0x6A)
	b = e.set(b, e.lLo)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)

	// cum[nb] = the total.
	b = e.get(b, e.pScratch)
	b = e.get(b, e.lCntOff)
	b = append(b, 0x6A)
	b = e.get(b, e.lNumBlocks)
	b = e.konst(b, 4)
	b = append(b, 0x6C, 0x6A)
	b = e.get(b, e.lTmp)
	b = append(b, 0x36, 0x02, 0x00)
	return b
}

// emitCkptBlockBody materialises ONE block on demand.
//
//	(ptr, len, scratch, j) -> i32     returns the block's tuple count
//
// Loads the checkpoint ABOVE the block into the working column and re-sweeps
// the block's positions, writing tuples this time. Cannot refuse: the block
// buffer is sized for a full stride at one tuple per pattern per position,
// which is the worst case for any block.
//
// POSITION `len` IS PART OF THE LAST BLOCK and is emitted from the loaded
// checkpoint itself, before the downward sweep. That is not a detail: the
// empty match at end of input is a legitimate start, checkpoint `nb` IS the
// EOF column, and a block loop written as `hi .. blockStart` with `hi` one
// below the block's top silently drops every end-of-input match. The plan
// carried exactly that defect until it was corrected.
func emitCkptBlockBody(cs *compiledSet, tableMemIdx int, colOff int32) []byte {
	e := newCkptEmit(cs, tableMemIdx, colOff)

	const (
		pPtr = iota
		pLen
		pScratch
		pBlk
		nparams
	)
	e.pPtr, e.pLen, e.pScratch = pPtr, pLen, pScratch

	a := newLocalAlloc(nparams)
	e.allocCommon(a)
	e.lHi, e.lLo = a.I32(), a.I32()
	lNextCkpt := a.I32()
	e.lRowBase, e.lBlkBase, e.lMask = a.I32(), a.I32(), a.I32()
	e.lMidMask, e.lEofMask = a.I64(), a.I64()

	cellBytes := e.colBytes()

	var b []byte
	b = a.EmitDecls(b)

	konst := func(v int32) { b = e.konst(b, v) }
	get := func(l byte) { b = e.get(b, l) }
	set := func(l byte) { b = e.set(b, l) }

	b = e.hdrLoad(b, ckptHdrStride)
	set(e.lStride)
	b = e.hdrLoad(b, ckptHdrFloor)
	set(e.lFloor)
	b = e.hdrLoad(b, ckptHdrNumBlocks)
	set(e.lNumBlocks)
	b = e.hdrLoad(b, ckptHdrCkptOff)
	set(e.lCkptOff)
	b = e.hdrLoad(b, ckptHdrCntOff)
	set(e.lCntOff)
	b = e.hdrLoad(b, ckptHdrBlockOff)
	set(e.lBlkOff)

	// lo = floor + j*stride ; hi = min(floor + (j+1)*stride - 1, len)
	get(e.lFloor)
	get(pBlk)
	get(e.lStride)
	b = append(b, 0x6C, 0x6A)
	set(e.lLo)
	get(e.lLo)
	get(e.lStride)
	b = append(b, 0x6A)
	konst(1)
	b = append(b, 0x6B)
	set(e.lHi)
	get(e.lHi)
	get(pLen)
	b = append(b, 0x4A) // i32.gt_s
	b = append(b, 0x04, 0x40)
	get(pLen)
	set(e.lHi)
	b = append(b, 0x0B)

	konst(e.colA)
	set(e.lCur)
	konst(e.colB)
	set(e.lPrev)
	b = e.emitSeedDeadCell(b)

	get(pBlk)
	konst(1)
	b = append(b, 0x6A)
	set(lNextCkpt)
	b = e.emitLoadCkptToColumn(b, lNextCkpt, cellBytes)

	get(pScratch)
	get(e.lBlkOff)
	b = append(b, 0x6A)
	set(e.lBlkBase)
	get(e.lLo)
	set(e.lRowBase)
	konst(0)
	set(e.lCount)

	// The last block holds position `len` itself, and the column just loaded
	// IS the EOF column, so its tuples come straight out of it.
	get(e.lHi)
	set(e.lPos)
	get(e.lHi)
	get(pLen)
	b = append(b, 0x46) // i32.eq
	b = append(b, 0x04, 0x40)
	b = e.emitAtPositionGuarded(b, true)
	get(pLen)
	konst(1)
	b = append(b, 0x6B)
	set(e.lPos)
	b = append(b, 0x0B)

	// Sweep the rest of the block downward.
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	get(e.lPos)
	get(e.lLo)
	b = append(b, 0x48) // i32.lt_s
	b = append(b, 0x0D, 0x01)
	b = e.emitAdvance(b)
	b = e.emitAtPositionGuarded(b, true)
	get(e.lPos)
	konst(1)
	b = append(b, 0x6B)
	set(e.lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)

	b = e.hdrStore(b, ckptHdrCurBlock, func(b []byte) []byte {
		b = e.get(b, pBlk)
		b = e.konst(b, 1)
		return append(b, 0x6A)
	})
	b = e.hdrStore(b, ckptHdrRowBase, func(b []byte) []byte { return e.get(b, e.lRowBase) })

	get(e.lCount)
	b = append(b, 0x0B)

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitCheckpointAt saves the current column when lPos is the start of block
// lBlkIdx, which is precisely the column the block BELOW it re-sweeps from.
//
// BLOCK 0 IS EXCLUDED, and the guard is not cosmetic. Checkpoint indices are
// 1-based — checkpoint j is stored at (j-1)*cellBytes — because block 0's
// lower boundary is the floor and nothing re-sweeps from it. A span of one
// position makes nb == 1, so lBlkIdx is 0 while lPos == lBound == floor, and
// without the guard the column is copied to ckptOff - cellBytes: over the
// header for a narrow column, and up to 16 KiB BEFORE the caller's region for
// a wide one.
func (e *ckptEmit) emitCheckpointAt(b []byte, lBlkIdx, lBound byte, cellBytes int32) []byte {
	b = e.get(b, e.lPos)
	b = e.get(b, lBound)
	b = append(b, 0x46) // i32.eq
	b = e.get(b, lBlkIdx)
	b = e.konst(b, 0)
	b = append(b, 0x4A) // i32.gt_s
	b = append(b, 0x71) // i32.and
	b = append(b, 0x04, 0x40)
	b = e.emitCopyColumnToCkpt(b, lBlkIdx, cellBytes)
	b = append(b, 0x0B)
	return b
}

// emitCloseBlockAt finishes block lBlkIdx when lPos is its first position, and
// steps the bookkeeping down to the block beneath.
//
// IT MUST RUN FOR POSITION `len` TOO, not only inside the sweep loop. The
// highest block can contain nothing but `len` itself — nb is ceil(m/stride) and
// the top block is the partial one — and `len` is emitted BEFORE the loop
// starts, from the EOF column. Running the bookkeeping only inside the loop
// therefore left that block never closed and its boundary never crossed, so
// `lBound` stayed at a position the loop never visits and NOT ONE checkpoint or
// block count was ever written. Every cum[] entry came out zero, `find` read
// every block as empty, and a drive that engaged the cache silently ended at
// the position it engaged on. It cost 240 of 256 matches on the shape that
// caught it and nothing at all on the shapes that did not.
// Block 0 is excluded for the reason emitCheckpointAt gives: it is closed by
// the epilogue's emitStoreBlockCount, not by crossing a boundary, and letting
// it close here at nb == 1 decremented lBlkIdx to -1 and wrote cnt[-1] over
// the last checkpoint cell while resetting the counter the header publishes.
func (e *ckptEmit) emitCloseBlockAt(b []byte, lBlkIdx, lBound byte) []byte {
	b = e.get(b, e.lPos)
	b = e.get(b, lBound)
	b = append(b, 0x46)
	b = e.get(b, lBlkIdx)
	b = e.konst(b, 0)
	b = append(b, 0x4A) // i32.gt_s
	b = append(b, 0x71) // i32.and
	b = append(b, 0x04, 0x40)
	b = e.emitStoreBlockCount(b, lBlkIdx)
	b = e.get(b, lBlkIdx)
	b = e.konst(b, 1)
	b = append(b, 0x6B)
	b = e.set(b, lBlkIdx)
	b = e.get(b, lBound)
	b = e.get(b, e.lStride)
	b = append(b, 0x6B)
	b = e.set(b, lBound)
	b = append(b, 0x0B)
	return b
}

// --- lever C: the projected column -----------------------------------------

// cellFor returns the column BYTE OFFSET pattern p's answer for WASM state w
// lives at. Compile-time, so every start-state read is a constant.
func (e *ckptEmit) cellFor(pat, w int) int32 { return e.proj.cellOf[pat][w] * 4 }

// emitEOFColumnProj fills the t == len column: `len` where the cell's
// representative accepts at EOF, DEAD otherwise. Every address is constant, so
// there is no loop at all — the column is a fixed list of stores.
//
// Cell 0 is the shared DEAD cell. It is written -1 here and never again, which
// is what lets a read through a dead projection skip its own branch.
func (e *ckptEmit) emitEOFColumnProj(b []byte) []byte {
	for pat := 0; pat < e.numPat; pat++ {
		bit := uint64(1) << uint(pat)
		for c := 1; c < e.proj.cells; c++ {
			if e.proj.owner[c] != int32(pat) {
				continue // this cell belongs to another pattern
			}
			w := int(e.proj.rep[c])
			b = e.get(b, e.lCur)
			if e.dp.eofMasks[w]&bit != 0 {
				b = e.get(b, e.pLen)
			} else {
				b = e.konst(b, -1)
			}
			b = appendTableStore32(b, e.tableMem, uint32(c*4))
		}
	}
	return b
}

// emitAdvanceProj is one position's transition over the projected column.
//
// TWO PHASES, and the split is what the projection costs. First a loop over
// STATES filling the successor scratch, because delta depends on the input byte
// and cannot be folded; then an UNROLLED pass over CELLS, each reading its
// representative's successor at a constant offset, the successor's cell through
// the projection table, and the old column there.
//
// The column is unrolled rather than looped: every address
// bar the projection lookup is a compile-time constant, at the price of a
// module that grows with the cell count.
func (e *ckptEmit) emitAdvanceProj(b []byte) []byte {
	b = e.get(b, e.lCur)
	b = e.set(b, e.lSwap)
	b = e.get(b, e.lPrev)
	b = e.set(b, e.lCur)
	b = e.get(b, e.lSwap)
	b = e.set(b, e.lPrev)

	b = e.get(b, e.pPtr)
	b = e.get(b, e.lPos)
	b = append(b, 0x6A)
	b = appendInputLoad8u(b)
	b = e.set(b, e.lByte)
	b = emitOverlapDPCell(b, e.dp, e.tableMem, e.lByte, e.lCell)

	// Phase 1: succ[w] = delta(w, class) for every state.
	b = e.konst(b, 1)
	b = e.set(b, e.lState)
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)
	b = e.get(b, e.lState)
	b = e.konst(b, int32(e.numStates))
	b = append(b, 0x4E)
	b = append(b, 0x0D, 0x01)
	b = e.konst(b, e.succOff)
	b = e.get(b, e.lState)
	b = append(b, 0x6A)
	b = emitOverlapDPTransition(b, e.dp, e.tableMem, e.lState, e.lCell, e.lNext)
	b = e.get(b, e.lNext)
	b = appendTableStore8(b, e.tableMem)
	b = e.get(b, e.lState)
	b = e.konst(b, 1)
	b = append(b, 0x6A)
	b = e.set(b, e.lState)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B)

	// Phase 2: one update per CELL, unrolled.
	for pat := 0; pat < e.numPat; pat++ {
		bit := uint64(1) << uint(pat)
		for c := 1; c < e.proj.cells; c++ {
			if e.proj.owner[c] != int32(pat) {
				continue
			}
			w := int(e.proj.rep[c])
			b = e.get(b, e.lCur)

			// w' = succ[rep], at a constant address.
			b = e.konst(b, e.succOff+int32(w))
			b = appendTableLoad8u(b, e.tableMem)
			b = e.set(b, e.lNext)

			// The suffix answer: prev[projTab[pat][w']]. A dead successor
			// lands on cell 0, which holds -1 permanently, so the "is it dead"
			// branch the unprojected form needs is gone.
			b = e.get(b, e.lPrev)
			b = e.konst(b, e.projOff+int32(pat*e.numStates*2))
			b = e.get(b, e.lNext)
			b = e.konst(b, 2)
			b = append(b, 0x6C, 0x6A)
			b = appendTableLoad16u(b, e.tableMem)
			b = append(b, 0x6A)
			b = appendTableLoad32(b, e.tableMem, 0)
			b = e.tee(b, e.lVal)
			b = e.konst(b, -1)
			b = append(b, 0x47) // the suffix answered
			b = append(b, 0x04, 0x7F)
			b = e.get(b, e.lVal)
			b = append(b, 0x05)
			if e.dp.midMasks[w]&bit != 0 {
				b = e.get(b, e.lPos)
			} else {
				b = e.konst(b, -1)
			}
			b = append(b, 0x0B)
			b = appendTableStore32(b, e.tableMem, uint32(c*4))
		}
	}
	return b
}

// emitSeedDeadCell writes -1 into cell 0 of BOTH working columns.
//
// It must be BOTH, and that is not obvious: the columns SWAP at every position,
// so seeding only the one that happens to be current leaves the other holding
// the zero its data segment was born with — and zero is a legitimate position,
// so every dead successor reported a match ending at 0. The cell is never
// written again, which is the whole point of it: a dead projection is read
// without a branch precisely because its cell is permanently DEAD.
func (e *ckptEmit) emitSeedDeadCell(b []byte) []byte {
	if e.proj == nil {
		return b
	}
	for _, col := range []int32{e.colA, e.colB} {
		b = e.konst(b, col)
		b = e.konst(b, -1)
		b = appendTableStore32(b, e.tableMem, 0)
	}
	return b
}
