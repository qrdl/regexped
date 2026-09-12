package compile

import (
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// Canonical-ABI adapters for SET capabilities under `wasm_format: component`.
//
// The raw set ABI is the one documented in docs/wasm.md, and none of it crosses
// the component boundary:
//
//	match_any / scan_any   a pattern id or -1          → option<u32>
//	match_all / scan_all   an i64 bitmask, or a count
//	                       plus a CALLER-OWNED bitmap  → list<u32> of ids
//	find                   one position per call, with
//	                       a caller-owned gate array   → a resource that owns the drive
//
// Two of those hand the caller a pointer into its own memory, which a component
// consumer cannot provide — the same reason phase 1's result areas are allocated
// here. So the adapters allocate both, and the `_all` pair converts.
//
// The id list is measured, not assumed: it beat handing the bitmap over in all
// twelve shapes tried (§9.2). The scan is what costs, and a bitmap does not
// avoid it — it moves it to the consumer and adds the transfer on top. Which is
// also why every scan below uses ctz plus `v &= v-1` and visits only SET bits: a
// bit-by-bit scan measured up to eleven times the whole call.

// Result-area sizes. All three set result types are 12 bytes, 4-aligned:
// a one-byte discriminant padded to 4, then either an option's own
// discriminant and value, or a list's (ptr, len).
const (
	areaSetAny = 12 // result<option<u32>, error-code>
	areaSetAll = 12 // result<list<u32>, error-code> and result<list<set-match>, ...>
)

// Scanner representation, the state one `find` drive needs. Allocated by the
// constructor, freed by the destructor.
//
// The input is COPIED here rather than borrowed from the argument the canonical
// ABI lowered. The lowered block belongs to the call, and the call's post-return
// frees it; a resource outlives its constructor's call, so borrowing it would
// leave the scanner reading freed memory from its second `next` onwards.
const (
	repInput = 0  // the copy of the input
	repLen   = 4  // its length
	repPos   = 8  // the next position to search from
	repGate  = 12 // the gate array, id_space u32s
	repDone  = 16 // set once the drive has reported its last position
	// The SCRATCH DESCRIPTOR the `find` export takes in place of a bare gate
	// pointer (internal/abi), carried INLINE here rather than allocated
	// separately: the representation never moves — it is ours, and the handle
	// holds it — so the gate pointer it contains cannot go stale, and the
	// constructor can fill it once.
	repScratch = 20
	repBytes   = repScratch + abi.FindScratchBytes
)

// setMatchTupleBytes is one raw find tuple: {id, start, end} as three i32.
//
// It is EXACTLY the canonical layout of `record set-match { id: u32, start: u32,
// end: u32 }` — size 12, align 4 — so the buffer the find body fills IS the
// list's element array, and `next` hands it over without converting anything.
const setMatchTupleBytes = 12

// buildSetAnyAdapterBody emits the adapter for `match_any` or `scan_any`:
//
//	(ptr, len[, start]) → retptr
//
// Inner: the same parameters → i32, a pattern id, -1 for no match, or -2 for a
// Backtracking frame-budget overflow. nParams is 2 for match_any and 3 for
// scan_any, whose `start` is a real parameter of the raw export.
//
// The shape is the single-pattern match adapter's, and the two are NOT shared
// because the sentinel MEANINGS differ: there the payload is an end position,
// here it is a pattern id, and 0 is a legitimate id where it would be a
// degenerate end. Keeping them apart means neither grows a flag.
func buildSetAnyAdapterBody(reallocIdx, innerIdx, nParams int) []byte {
	lR := byte(nParams)
	lRet := byte(nParams + 1)

	var b []byte
	b = append(b, 0x01, 0x02, 0x7F) // 2 i32 locals: r, ret

	b = callRealloc(b, reallocIdx, 4, areaSetAny)
	b = append(b, 0x21, lRet)

	for i := 0; i < nParams; i++ {
		b = append(b, 0x20, byte(i))
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lR)

	// -2 before -1: an UNKNOWN answer is not "no match", and folding them
	// together would report a definite negative the engine never established.
	b = append(b, 0x20, lR, 0x41, 0x7E, 0x46) // r == -2
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0) // ok

	b = append(b, 0x20, lR, 0x41, 0x7F, 0x46) // r == -1
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 4, 0) // none
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 4, 1) // some(id)
	b = append(b, 0x20, lRet, 0x20, lR)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// buildSetAllNarrowAdapterBody emits the adapter for the NARROW `_all` form —
// at most 64 patterns, where the answer IS the returned i64 bitmask:
//
//	(ptr, len[, start]) → retptr        inner: same params → i64
//
// A bitmask of 0 is a legitimate answer meaning "none", so only -2 is an error.
// The list is sized by popcount and filled by ctz, so the loop runs once per HIT
// rather than once per id.
func buildSetAllNarrowAdapterBody(reallocIdx, innerIdx, nParams int) []byte {
	lM := byte(nParams)       // i64: the bitmask, consumed as it is scanned
	lRet := byte(nParams + 1) // i32
	lOut := byte(nParams + 2) // i32: the id array
	lN := byte(nParams + 3)   // i32: how many ids
	lI := byte(nParams + 4)   // i32: write cursor

	var b []byte
	// Two local groups: one i64, then four i32.
	b = append(b, 0x02, 0x01, 0x7E, 0x04, 0x7F)

	b = callRealloc(b, reallocIdx, 4, areaSetAll)
	b = append(b, 0x21, lRet)

	for i := 0; i < nParams; i++ {
		b = append(b, 0x20, byte(i))
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lM)

	// m == -2 (sign-extended): the Backtracking sentinel.
	b = append(b, 0x20, lM)
	b = append(b, 0x42, 0x7E) // i64.const -2
	b = append(b, 0x51)       // i64.eq
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0) // ok

	// n = popcount(m)
	b = append(b, 0x20, lM)
	b = append(b, 0x7B) // i64.popcnt
	b = append(b, 0xA7) // i32.wrap_i64
	b = append(b, 0x21, lN)

	// out = realloc(4, n*4). A zero-length list still gets a pointer: the
	// allocator's minimum block is a block, and a null data pointer for an
	// empty list is not worth a special case.
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x04)
	b = append(b, 0x20, lN)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74) // i32.shl — n*4
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(reallocIdx))
	b = append(b, 0x21, lOut)

	b = appendIDScanFromMask(b, lM, lOut, lI)

	b = append(b, 0x20, lRet, 0x20, lOut)
	b = storeI32(b, 4)
	b = append(b, 0x20, lRet, 0x20, lN)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// appendIDScanFromMask writes the set bit indices of the i64 in lMask to
// lOut as i32s, ascending, using lI as the write cursor. It CONSUMES lMask.
//
//	while m != 0 { out[i++] = ctz(m); m &= m - 1 }
func appendIDScanFromMask(b []byte, lMask, lOut, lI byte) []byte {
	b = append(b, 0x41, 0x00, 0x21, lI) // i = 0
	b = append(b, 0x02, 0x40)           // block
	b = append(b, 0x03, 0x40)           // loop
	b = append(b, 0x20, lMask)
	b = append(b, 0x50)       // i64.eqz
	b = append(b, 0x0D, 0x01) // br_if 1 — no bits left
	// out[i] = ctz(m)
	b = append(b, 0x20, lOut)
	b = append(b, 0x20, lI)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x20, lMask)
	b = append(b, 0x7A) // i64.ctz
	b = append(b, 0xA7) // i32.wrap_i64
	b = storeI32(b, 0)
	// m &= m - 1 — clears the lowest set bit, so the loop runs once per HIT
	b = append(b, 0x20, lMask)
	b = append(b, 0x20, lMask)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7D)       // i64.sub
	b = append(b, 0x83)       // i64.and
	b = append(b, 0x21, lMask)
	b = append(b, 0x20, lI)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, lI)
	b = append(b, 0x0C, 0x00) // br 0
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block
	return b
}

// buildSetAllWideAdapterBody emits the adapter for the WIDE `_all` form — more
// than 64 patterns, where the body ORs hit bits into a caller-owned bitmap and
// returns a count:
//
//	(ptr, len[, start]) → retptr
//	inner: (same params, bitmap_ptr) → i32 count
//
// The bitmap is ours to allocate AND TO ZERO: the body only ORs bits in, and the
// allocator hands back reused memory, so a stale bitmap would report ids from an
// earlier call. idSpace is one past the largest id the set can report — NOT the
// pattern count, which differs whenever the set selects a named subset.
func buildSetAllWideAdapterBody(reallocIdx, innerIdx, nParams, idSpace int) []byte {
	words := (idSpace + 31) / 32
	bmBytes := words * 4

	lRet := byte(nParams)
	lBM := byte(nParams + 1)
	lN := byte(nParams + 2)
	lOut := byte(nParams + 3)
	lI := byte(nParams + 4) // write cursor into out
	lW := byte(nParams + 5) // word index
	lV := byte(nParams + 6) // the word being scanned

	var b []byte
	b = append(b, 0x01, 0x07, 0x7F) // 7 i32 locals

	b = callRealloc(b, reallocIdx, 4, areaSetAll)
	b = append(b, 0x21, lRet)

	b = callRealloc(b, reallocIdx, 4, int32(bmBytes))
	b = append(b, 0x21, lBM)
	// memory.fill(bm, 0, bmBytes) — memory 0, which a component always owns.
	b = append(b, 0x20, lBM)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(bmBytes))
	b = append(b, 0xFC, 0x0B, 0x00)

	for i := 0; i < nParams; i++ {
		b = append(b, 0x20, byte(i))
	}
	b = append(b, 0x20, lBM)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lN)

	// A negative count is the Backtracking sentinel; a zero count is "none".
	b = append(b, 0x20, lN)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48) // i32.lt_s
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0) // ok

	// out = realloc(4, n*4)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x04)
	b = append(b, 0x20, lN)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(reallocIdx))
	b = append(b, 0x21, lOut)

	// Walk the bitmap word by word, ctz within each word.
	b = append(b, 0x41, 0x00, 0x21, lI)
	b = append(b, 0x41, 0x00, 0x21, lW)
	b = append(b, 0x02, 0x40) // block: words
	b = append(b, 0x03, 0x40) // loop: words
	b = append(b, 0x20, lW)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(words))
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1 — done
	// v = bm[w]
	b = append(b, 0x20, lBM)
	b = append(b, 0x20, lW)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74)
	b = append(b, 0x6A)
	b = loadI32(b, 0)
	b = append(b, 0x21, lV)
	b = append(b, 0x02, 0x40) // block: bits
	b = append(b, 0x03, 0x40) // loop: bits
	b = append(b, 0x20, lV)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x0D, 0x01) // br_if 1 — word exhausted
	// out[i] = w*32 + ctz(v)
	b = append(b, 0x20, lOut)
	b = append(b, 0x20, lI)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74)
	b = append(b, 0x6A)
	b = append(b, 0x20, lW)
	b = append(b, 0x41, 0x05)
	b = append(b, 0x74) // w << 5
	b = append(b, 0x20, lV)
	b = append(b, 0x68) // i32.ctz
	b = append(b, 0x6A) // i32.add
	b = storeI32(b, 0)
	// v &= v - 1 ; i++
	b = append(b, 0x20, lV)
	b = append(b, 0x20, lV)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B) // i32.sub
	b = append(b, 0x71) // i32.and
	b = append(b, 0x21, lV)
	b = append(b, 0x20, lI)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, lI)
	b = append(b, 0x0C, 0x00) // br 0 — next bit
	b = append(b, 0x0B)       // end loop: bits
	b = append(b, 0x0B)       // end block: bits
	b = append(b, 0x20, lW)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, lW)
	b = append(b, 0x0C, 0x00) // br 0 — next word
	b = append(b, 0x0B)       // end loop: words
	b = append(b, 0x0B)       // end block: words

	b = append(b, 0x20, lRet, 0x20, lOut)
	b = storeI32(b, 4)
	b = append(b, 0x20, lRet, 0x20, lN)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// buildSetScannerCtorBody emits `[constructor]<res>`:
//
//	(ptr, len, start) → handle
//
// THREE things here are not obvious and each of them was a defect first:
//
//   - It must return a HANDLE, obtained from the imported `[resource-new]`
//     builtin. Returning the representation instead type-checks, builds, and
//     traps at the first use with "unknown handle index <pointer>".
//   - The input is COPIED. The block the canonical ABI lowered belongs to the
//     constructor's call, and some later call's post-return frees it; a scanner
//     reading it would be reading freed memory.
//   - The call chain is RESTORED to what it was on entry, which detaches the
//     scanner's own blocks from it. Everything this function allocates outlives
//     the call and is freed by the destructor instead. Without that, the next
//     post-return frees a live scanner's state.
func buildSetScannerCtorBody(reallocIdx, resNewIdx int, callListGlobal uint32, idSpace int) []byte {
	const (
		pPtr   = 0x00
		pLen   = 0x01
		pStart = 0x02
		lRep   = 0x03
		lGate  = 0x04
		lCopy  = 0x05
		lChain = 0x06
	)
	var b []byte
	b = append(b, 0x01, 0x04, 0x7F) // 4 i32 locals

	// Remember the chain, so the blocks below can be taken off it.
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, callListGlobal)
	b = append(b, 0x21, lChain)

	b = callRealloc(b, reallocIdx, 4, repBytes)
	b = append(b, 0x21, lRep)

	b = callRealloc(b, reallocIdx, 4, int32(idSpace*4))
	b = append(b, 0x21, lGate)
	// All zeros means a clean scan: the only operation a caller ever performs
	// on the gate array, and the allocator hands back reused memory.
	b = append(b, 0x20, lGate)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(idSpace*4))
	b = append(b, 0xFC, 0x0B, 0x00) // memory.fill

	// copy = realloc(1, len) ; copy <- input
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x20, pLen)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(reallocIdx))
	b = append(b, 0x21, lCopy)
	// memory.copy(copy, ptr, len). A zero length is legitimate — `a*`, `(?:)`
	// and `\A\z` all match the empty input — and memory.copy of 0 bytes is
	// defined, so it needs no guard.
	b = append(b, 0x20, lCopy)
	b = append(b, 0x20, pPtr)
	b = append(b, 0x20, pLen)
	b = append(b, 0xFC, 0x0A, 0x00, 0x00)

	b = append(b, 0x20, lRep, 0x20, lCopy)
	b = storeI32(b, repInput)
	b = append(b, 0x20, lRep, 0x20, pLen)
	b = storeI32(b, repLen)
	b = append(b, 0x20, lRep, 0x20, pStart)
	b = storeI32(b, repPos)
	b = append(b, 0x20, lRep, 0x20, lGate)
	b = storeI32(b, repGate)
	b = append(b, 0x20, lRep, 0x41, 0x00)
	b = storeI32(b, repDone)

	// The descriptor, filled once: magic, the gate array, and no answer cache.
	// The cache is what makes an overlapping drive linear, and the `find` this
	// resource drives READS one when offered — so what is missing here is the
	// region, not the plumbing: whether a component should reserve one, and out
	// of whose budget, is an open question (memory.grow is one-way, so a
	// reservation stays in the process footprint after the handle is dropped).
	b = append(b, 0x20, lRep, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagic)
	b = storeI32(b, repScratch+abi.FindScratchMagicOff)
	b = append(b, 0x20, lRep, 0x20, lGate)
	b = storeI32(b, repScratch+abi.FindScratchGateOff)
	b = append(b, 0x20, lRep, 0x41, 0x00)
	b = storeI32(b, repScratch+abi.FindScratchCacheOff)
	b = append(b, 0x20, lRep, 0x41, 0x00)
	b = storeI32(b, repScratch+abi.FindScratchCacheLenOff)

	// Detach: the chain goes back to what it held on entry, so the blocks above
	// belong to the handle and not to this call.
	b = append(b, 0x20, lChain)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, callListGlobal)

	b = append(b, 0x20, lRep)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(resNewIdx))
	b = append(b, 0x0B)
	return b
}

// buildSetScannerNextBody emits `[method]<res>.next`:
//
//	(rep) → retptr, carrying result<list<set-match>, error-code>
//
// One position per call, the same contract the raw export has and the module
// stubs present. The buffer is PATTERN_COUNT tuples, which is the exact worst
// case for a single start — one match per pattern — so the raw ABI's
// transactional overflow rule cannot fire and there is no retry path to get
// wrong.
//
// The advance is the module stubs' rule: every tuple in one call shares a start,
// so the next search begins one past it.
func buildSetScannerNextBody(reallocIdx, findIdx, patternCount int) []byte {
	const (
		pRep = 0x00
		lRet = 0x01
		lOut = 0x02
		lN   = 0x03
	)
	var b []byte
	b = append(b, 0x01, 0x03, 0x7F) // 3 i32 locals

	b = callRealloc(b, reallocIdx, 4, areaSetAll)
	b = append(b, 0x21, lRet)
	b = storeDisc(b, lRet, 0, 0) // ok unless proven otherwise

	// Already finished: an empty list, and no call into the body. A finished
	// scanner that kept calling would keep answering 0 — correct but wasteful —
	// while a scanner that had reported an ERROR must not silently become "no
	// more matches".
	b = append(b, 0x20, pRep)
	b = loadI32(b, repDone)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, lRet, 0x41, 0x00)
	b = storeI32(b, 4)
	b = append(b, 0x20, lRet, 0x41, 0x00)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = callRealloc(b, reallocIdx, 4, int32(patternCount*setMatchTupleBytes))
	b = append(b, 0x21, lOut)

	// find(input, len, pos, gate, out, PATTERN_COUNT)
	b = append(b, 0x20, pRep)
	b = loadI32(b, repInput)
	b = append(b, 0x20, pRep)
	b = loadI32(b, repLen)
	b = append(b, 0x20, pRep)
	b = loadI32(b, repPos)
	// The descriptor's ADDRESS, not the gate pointer: the export dereferences.
	b = append(b, 0x20, pRep)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, repScratch)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x20, lOut)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(patternCount))
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findIdx))
	b = append(b, 0x21, lN)

	// Negative is the Backtracking sentinel, not a count: what remains is
	// UNKNOWN, so the scan ends AND reports an error.
	b = append(b, 0x20, lN)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48) // i32.lt_s
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, pRep, 0x41, 0x01)
	b = storeI32(b, repDone)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	// Zero means the drive is finished.
	b = append(b, 0x20, lN)
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, pRep, 0x41, 0x01)
	b = storeI32(b, repDone)
	b = append(b, 0x20, lRet, 0x20, lOut)
	b = storeI32(b, 4)
	b = append(b, 0x20, lRet, 0x41, 0x00)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	// pos = out[0].start + 1
	b = append(b, 0x20, pRep)
	b = append(b, 0x20, lOut)
	b = loadI32(b, 4)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = storeI32(b, repPos)

	b = append(b, 0x20, lRet, 0x20, lOut)
	b = storeI32(b, 4)
	b = append(b, 0x20, lRet, 0x20, lN)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// buildSetScannerDtorBody emits `[dtor]<res>`: (rep) → ().
//
// It frees exactly what the constructor detached from the call chain — the input
// copy, the gate array, and the representation itself. Everything a `next` call
// allocated was freed by that call's post-return.
//
// An absent dtor is not a compile error: dropping the handle traps instead.
func buildSetScannerDtorBody(freeIdx int) []byte {
	const pRep = 0x00
	var b []byte
	b = append(b, 0x00) // no locals

	for _, off := range []int{repInput, repGate} {
		b = append(b, 0x20, pRep)
		b = loadI32(b, off)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(freeIdx))
	}
	b = append(b, 0x20, pRep)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(freeIdx))
	b = append(b, 0x0B)
	return b
}

// --- wiring the set adapters into a component build -------------------------

// ComponentSetNames is the canonical export name of every function ONE set
// contributes, plus what the find resource needs to reach the canon builtins.
//
// It is populated by the component/ package from generate/'s WIT derivation —
// compile/ cannot derive it, because generate/ imports compile/ and not the
// other way round — and it exists so the .wit and the core module cannot
// disagree about a single name.
type ComponentSetNames struct {
	// Caps maps a configured capability name (`match_any: hits` → "hits") to
	// its canonical export name.
	Caps map[string]string

	// Constructor, Next and Dtor are empty unless the set declares `find:`.
	//
	// Dtor is not reachable from the WIT and has no counterpart in the
	// interface: `wasm-tools component new` binds it to the resource's
	// destructor BY NAME, and a component that omits it traps when a handle is
	// dropped rather than failing to build.
	Constructor string
	Next        string
	Dtor        string

	// ResourceImport / ResourceNew name the `[resource-new]` canon builtin the
	// constructor calls. It is a FUNCTION IMPORT, which is why a set-bearing
	// component offsets every function index by the number of imports: a
	// constructor that returned its representation instead would build and then
	// trap with "unknown handle index".
	ResourceImport string
	ResourceNew    string
}

// setAdapterKind selects which body an entry of the adapter list carries.
type setAdapterKind int

const (
	setAdapterAny setAdapterKind = iota
	setAdapterAllNarrow
	setAdapterAllWide
	setAdapterCtor
	setAdapterNext
	setAdapterDtor
)

// setAdapter is one emitted component function for a set capability.
type setAdapter struct {
	kind    setAdapterKind
	inner   int    // the raw set function it wraps; unused by ctor and dtor
	export  string // canonical export name
	nParams int    // raw parameter count, for the `any` and `_all` shapes
	idSpace int    // one past the largest reportable id, for the bitmap and gates
	count   int    // PATTERN_COUNT, the worst case at one position
	typeIdx byte   // WASM type index of the ADAPTER's own signature
	// post reports whether this export needs a post-return. Everything that
	// returns a result area does; the constructor, which returns a bare handle,
	// does not — and giving it one would free the scanner's state.
	post bool
}

// componentSetAdapters lists the adapters a set-bearing component needs, in
// emission order. setBase[si] is the first function index of set si, and
// resNewIdx[si] the index of its imported resource.new builtin (-1 when the set
// declares no `find`).
//
// The order here IS the function-index order, so the function, export and code
// sections all walk this one list.
func componentSetAdapters(sets []*compiledSet, setBase, resNewIdx []int,
	names map[string]ComponentSetNames, anyTypeIdx2, anyTypeIdx3, nextTypeIdx, dtorTypeIdx byte,
) []setAdapter {
	var out []setAdapter
	for si, cs := range sets {
		n, ok := names[cs.name]
		if !ok {
			continue
		}
		for i, c := range cs.capFns() {
			inner := setBase[si] + i
			switch c.kind {
			case capFind:
				if resNewIdx[si] < 0 {
					// No builtin was imported for this set, so there is nothing
					// for the constructor to call. Emitting the trio anyway
					// would put -1 in a call instruction.
					continue
				}
				out = append(out,
					setAdapter{kind: setAdapterCtor, export: n.Constructor, idSpace: cs.idSpaceSize(),
						inner: resNewIdx[si], typeIdx: anyTypeIdx3},
					setAdapter{kind: setAdapterNext, export: n.Next, inner: inner,
						count: cs.patternCount, typeIdx: nextTypeIdx, post: true},
					setAdapter{kind: setAdapterDtor, export: n.Dtor, typeIdx: dtorTypeIdx},
				)
			case capMatchAny:
				out = append(out, setAdapter{kind: setAdapterAny, inner: inner,
					export: n.Caps[c.name], nParams: 2, typeIdx: anyTypeIdx2, post: true})
			case capScanAny:
				out = append(out, setAdapter{kind: setAdapterAny, inner: inner,
					export: n.Caps[c.name], nParams: 3, typeIdx: anyTypeIdx3, post: true})
			case capMatchAll, capScanAll:
				nParams := 2
				typeIdx := anyTypeIdx2
				if c.kind == capScanAll {
					nParams, typeIdx = 3, anyTypeIdx3
				}
				kind := setAdapterAllNarrow
				if cs.wideAll() {
					// The wide body takes the bitmap as one more parameter, but
					// the ADAPTER's own signature is unchanged: it allocates
					// that bitmap itself.
					kind = setAdapterAllWide
				}
				out = append(out, setAdapter{kind: kind, inner: inner, export: n.Caps[c.name],
					nParams: nParams, idSpace: cs.idSpaceSize(), typeIdx: typeIdx, post: true})
			case capFindBatch:
				// Refused at config load for components: the interface exposes
				// one position per call through the resource, so there is
				// nothing for a batch entry to be reached through.
			}
		}
	}
	return out
}

// buildSetAdapterBody dispatches to the body emitter for one adapter.
func buildSetAdapterBody(a setAdapter, reallocIdx, freeIdx int, callListGlobal uint32) []byte {
	switch a.kind {
	case setAdapterAny:
		return buildSetAnyAdapterBody(reallocIdx, a.inner, a.nParams)
	case setAdapterAllNarrow:
		return buildSetAllNarrowAdapterBody(reallocIdx, a.inner, a.nParams)
	case setAdapterAllWide:
		return buildSetAllWideAdapterBody(reallocIdx, a.inner, a.nParams, a.idSpace)
	case setAdapterCtor:
		return buildSetScannerCtorBody(reallocIdx, a.inner, callListGlobal, a.idSpace)
	case setAdapterNext:
		return buildSetScannerNextBody(reallocIdx, a.inner, a.count)
	case setAdapterDtor:
		return buildSetScannerDtorBody(freeIdx)
	}
	panic("compile: unknown set adapter kind")
}
