package compile

import (
	"fmt"

	"github.com/qrdl/regexped/internal/utils"
)

// The six non-`find` set capabilities.
//
//	match    (ptr, len)                -> i32   0 | 1
//	match_any(ptr, len)                -> i32   pattern id, or -1
//	match_all(ptr, len)                -> i64   bitmask            (<= 64 patterns)
//	match_all(ptr, len, out_ptr)       -> i32   count + bitmap     (>  64)
//	scan     (ptr, len, from)          -> i32   0 | 1
//	scan_any (ptr, len, from)          -> i32   pattern id, or -1
//	scan_all (ptr, len, from)          -> i64   bitmask            (<= 64)
//	scan_all (ptr, len, from, out_ptr) -> i32   count + bitmap     (>  64)
//
// All six are built on the bitmask probes of set_probe.go rather than on the
// tuple-writing suffix function: none of them reports a position and extent,
// so none pays for per-pattern endPos tracking, the immBitmask lookup, or an
// output buffer (§5).
//
// The anchored trio walks candidate literal placements inside a match pinned
// at 0..len; the scan trio walks positions like `find` does.

// setCapKind selects which of the six bodies to emit.
type setCapKind int

const (
	capFind setCapKind = iota
	capMatch
	capMatchAny
	capMatchAll
	capScan
	capScanAny
	capScanAll
	// capFindBatch is the exported multi-position loop.
	// Its per-position worker is emitted separately, as a hidden function,
	// with mode capFind and compiledSet.batchPos set — see emitSetBatchFn.
	capFindBatch
)

// wideBitmapThreshold is the pattern count above which the `_all` pair
// switches from an i64 return value to a caller-provided bitmap (§3.13).
const wideBitmapThreshold = 64

// idSpaceSize returns one past the largest pattern id this set can report —
// the size of everything indexed BY a pattern id: the gate array, the `_all`
// bitmask/bitmap, and hence the narrow-vs-wide `_all` ABI choice.
//
// It comes from config.SetConfig.IDSpaceSize (via SetSpec), which is the same
// function the stub generators call — that shared definition is what keeps the
// two sides from disagreeing.
//
// The fallback, for a SetSpec built directly by a harness rather than from a
// config, derives the bound from the ids actually packed. It must consider
// BOTH packings: a pattern can be dropped from the find buckets at the state
// limit yet retained in an anchored bucket, and reading only cs.patternIDs
// would then under-size the id space and make emitRecordBits compute
// `uint64(1)<<gid` == 0 for gid >= 64 — a pattern that silently can never
// appear in match_all.
func (cs *compiledSet) idSpaceSize() int {
	if cs.declaredIDSpace > 0 {
		return cs.declaredIDSpace
	}
	max := -1
	for _, ids := range [][][]int{cs.patternIDs, cs.anchoredIDs} {
		for _, bucket := range ids {
			for _, id := range bucket {
				if id > max {
					max = id
				}
			}
		}
	}
	return max + 1
}

// numPatterns returns how many patterns the set actually compiled into its
// find-path buckets. Distinct from idSpaceSize: this counts patterns, that
// bounds their ids. Used for the "every pattern has been seen" early exit,
// which is a count comparison and would never fire against an id bound.
func (cs *compiledSet) numPatterns() int {
	n := 0
	for bi, ids := range cs.patternIDs {
		if cs.phase1Only && cs.buckets[bi].isFallback {
			continue // see allPatternsMask
		}
		n += len(ids)
	}
	return n
}

// checkIDSpace asserts that every pattern id this set can emit fits the id
// space the stubs were told to allocate for.
//
// Every gate offset (gate + id*4) and every `_all` bit position IS a pattern
// id, and the caller's array is sized by config.SetConfig.IDSpaceSize. If the
// two ever diverge the symptom is an out-of-bounds write into the host's
// memory — silent, data-dependent, and a defect this project has already had.
// A panic here turns that class of bug into a build failure instead.
func (cs *compiledSet) checkIDSpace() {
	size := cs.idSpaceSize()
	for _, group := range [][][]int{cs.patternIDs, cs.anchoredIDs} {
		for _, bucket := range group {
			for _, id := range bucket {
				if id < 0 || id >= size {
					panic(fmt.Sprintf(
						"compile: set %q emits pattern id %d but its id space is %d — "+
							"gate arrays and _all bitmaps are sized by that bound",
						cs.name, id, size))
				}
			}
		}
	}
}

// hasBTMember reports whether any bucket in this set was admitted on the
// Backtracking engine (SETS_PLAN item 20). It is the one condition that can
// make a capability answer "I don't know" instead of yes or no.
func (cs *compiledSet) hasBTMember() bool { return cs.numBTFns > 0 }

// wideAll reports whether this set's `_all` capabilities use the out_ptr bitmap
// form rather than the i64 bitmask return.
//
// Two independent reasons select it:
//
//   - ID SPACE > 64 — the original one: the form exists to carry bit positions
//     and a bit position is a pattern id (§3.13), so more than 64 ids simply do
//     not fit in an i64.
//
//   - A BACKTRACKING MEMBER — SETS_PLAN item 20 decision 3. BT is the first
//     engine here that can return "unknown" (abi.BTStackOverflow) rather than a
//     definite yes/no, and that third outcome needs somewhere to live. The
//     narrow form is the only capability shape with no room for it: its i64
//     return IS the bitmask, so every one of the 2^64 values is already a legal
//     answer and -2 reads as "everything matched except pattern 0". Moving the
//     bitmap into memory frees the return value to carry a count, which can go
//     negative.
//
// CONDITIONAL, deliberately: a set with no BT member keeps the cheap i64 form
// untouched, so nothing that exists today changes shape.
func (cs *compiledSet) wideAll() bool {
	return cs.idSpaceSize() > wideBitmapThreshold || cs.hasBTMember()
}

// emitSetAnyID records ONE arbitrary matching pattern id from a bucket-local
// bitmask into dst — the `_any` capabilities' whole answer.
//
// Which id is unspecified (§3.5), so the lowest set bit is as good as any, and
// the test is one compare per pattern unrolled at compile time. escapeDepth >=
// 0 additionally leaves that block once an id is found; the non-anchored form
// passes -1 and lets the mode's drain check do the leaving instead, which
// keeps this emitter free of each frontend's br-depth bookkeeping. Both forms
// stop at the first id now that `scan_any` reports no start (TODO task 59
// decision (10)) — before that, a later candidate could still improve the
// answer by starting earlier.
//
// Shared by emitRecordBits and setFindCtx.emitRecordProbe, which each carried
// a copy.
func emitSetAnyID(b []byte, ids []int, bitsLocal, dst byte, escapeDepth int) []byte {
	for k, gid := range ids {
		if k >= 32 {
			break
		}
		b = append(b, 0x20, bitsLocal, 0x41)
		b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
		b = append(b, 0x71, 0x04, 0x40)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(gid))
		b = append(b, 0x21, dst)
		if escapeDepth >= 0 {
			b = append(b, 0x0C, byte(escapeDepth+1)) // +1: inside this `if`
		}
		b = append(b, 0x0B)
	}
	return b
}

// emitSetAllBits records EVERY matching pattern of a bucket-local bitmask —
// the `_all` capabilities' answer, in whichever of the two §3.13 forms this
// set uses.
//
// Narrow (id space <= 64): OR the bit into an i64 accumulator.
// Wide: set bit gid in the caller's little-endian bitmap and count only the
// 0->1 transitions, so the returned count is distinct patterns rather than
// hits. That read-modify-write is why the export REQUIRES an all-zero bitmap
// on entry (docs/wasm.md).
//
// Shared by emitRecordBits (match_all) and setFindCtx.emitRecordProbe
// (scan_all), which were byte-for-byte copies — including the SLEB128 hazard
// noted below, which was documented in only one of them (§11 R12).
func emitSetAllBits(b []byte, ids []int, bitsLocal byte, wide bool, pOutPtr, lCount, lAcc byte) []byte {
	for k, gid := range ids {
		if k >= 32 {
			break
		}
		b = append(b, 0x20, bitsLocal, 0x41)
		b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
		b = append(b, 0x71, 0x04, 0x40)
		if wide {
			byteOff := gid / 8
			// i32.const takes a SIGNED LEB128, so a bit value of 0x80
			// (gid % 8 == 7) cannot be written as a bare byte: 0x80 has the
			// continuation bit set and would swallow the next opcode.
			bitInByte := int32(1) << uint(gid%8)
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(byteOff))
			b = append(b, 0x6A, 0x2D, 0x00, 0x00) // load8_u
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, bitInByte)
			b = append(b, 0x71, 0x45, 0x04, 0x40) // and; eqz; if (bit was clear)
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(byteOff))
			b = append(b, 0x6A)
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(byteOff))
			b = append(b, 0x6A, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, bitInByte)
			b = append(b, 0x72)             // or
			b = append(b, 0x3A, 0x00, 0x00) // i32.store8
			b = append(b, 0x20, lCount, 0x41, 0x01, 0x6A, 0x21, lCount)
			b = append(b, 0x0B)
		} else {
			b = append(b, 0x20, lAcc, 0x42)
			b = utils.AppendSLEB128_64(b, int64(uint64(1)<<uint(gid)))
			b = append(b, 0x84, 0x21, lAcc) // i64.or
		}
		b = append(b, 0x0B)
	}
	return b
}

// capAccumulator emits the "record that pattern gid matched" step shared by
// every capability, given the bucket-local bits already in bitsLocal.
type capAccumulator struct {
	kind    setCapKind
	wide    bool
	lAcc    byte // i64 bitmask accumulator (narrow _all forms)
	lCount  byte // i32 hit count (wide _all forms)
	lAnyID  byte // i32 pattern id (the _any forms)
	pOutPtr byte // caller bitmap pointer (wide _all forms)
}

// emitRecordBits emits the per-bit handling of one bucket's probe result.
// `escapeDepth` is the br depth of the block to leave once the answer is
// settled — used by the bare and `_any` forms, which stop at the first hit.
//
// Only the ANCHORED trio reaches this: the scan trio shares find's frontend
// bodies and records through setFindCtx.emitRecordProbe instead. Both now
// delegate the per-bit work to the shared emitters above.
func (a capAccumulator) emitRecordBits(b []byte, bitsLocal byte, ids []int, escapeDepth byte) []byte {
	switch a.kind {
	case capMatch:
		// Any bit at all settles a boolean answer. lCount doubles as the
		// result flag so the epilogue has one thing to return whichever way
		// the block was left.
		b = append(b, 0x20, bitsLocal, 0x04, 0x40)
		b = append(b, 0x41, 0x01, 0x21, a.lCount)
		b = append(b, 0x0C, escapeDepth+1)
		b = append(b, 0x0B)
		return b
	case capMatchAny:
		return emitSetAnyID(b, ids, bitsLocal, a.lAnyID, int(escapeDepth))
	default: // capMatchAll
		return emitSetAllBits(b, ids, bitsLocal, a.wide, a.pOutPtr, a.lCount, a.lAcc)
	}
}

// emitRecordSparseCount is emitRecordBits for a G17 SPARSE anchored bucket.
//
// The probe could not hand back bucket-local bits — 32 of them is the ceiling
// the sparse form exists to escape — so it returned a COUNT and left the
// matching bucket-local indices in its scratch. Recording therefore becomes a
// runtime loop over that scratch, mapping each index to a global id through the
// bucket's id map, where the bitmask path could unroll one compare per pattern
// at compile time.
//
// lIdx and lID are scratch i32 locals owned by the caller; both are dead
// between buckets.
func (a capAccumulator) emitRecordSparseCount(b []byte, countLocal byte, bkt *bucket, tableMemIdx int, lIdx, lID, escapeDepth byte) []byte {
	sc := bkt.sparseScratch
	// pushID emits the global id of the collected entry whose index is on top
	// of the stack as a byte offset into the scratch index list.
	pushID := func(b []byte, idxOff func([]byte) []byte) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, bkt.sparseIDMapOff)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, sc.endPos)
		b = idxOff(b)
		b = appendTableLoad32(b, tableMemIdx, 0) // bucket-local index
		b = append(b, 0x41, 0x02, 0x74, 0x6A)    // idMapOff + idx*4
		return appendTableLoad32(b, tableMemIdx, 0)
	}
	switch a.kind {
	case capMatch:
		// Any hit at all settles a boolean answer; the count is enough and the
		// ids never need reading.
		b = append(b, 0x20, countLocal, 0x04, 0x40)
		b = append(b, 0x41, 0x01, 0x21, a.lCount)
		b = append(b, 0x0C, escapeDepth+1)
		b = append(b, 0x0B)
		return b
	case capMatchAny:
		// Which id is unspecified (§3.5), so the first collected one will do.
		b = append(b, 0x20, countLocal, 0x04, 0x40)
		b = pushID(b, func(b []byte) []byte { return b }) // entry 0: offset 0
		b = append(b, 0x21, a.lAnyID)
		b = append(b, 0x0C, escapeDepth+1)
		b = append(b, 0x0B)
		return b
	default: // capMatchAll
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = append(b, 0x02, 0x40)
		b = append(b, 0x20, countLocal, 0x45, 0x0D, 0x00)
		b = append(b, 0x03, 0x40)
		b = pushID(b, func(b []byte) []byte {
			return append(b, 0x20, lIdx, 0x41, 0x02, 0x74, 0x6A)
		})
		b = append(b, 0x21, lID)
		if a.wide {
			// Count only 0->1 transitions so the returned count stays DISTINCT
			// patterns, matching emitSetAllBits' contract.
			b = append(b, 0x20, a.pOutPtr, 0x20, lID, 0x41, 0x03, 0x76, 0x6A)
			b = appendTableLoad8u(b, 0)
			b = append(b, 0x41, 0x01, 0x20, lID, 0x41, 0x07, 0x71, 0x74)
			b = append(b, 0x71, 0x45, 0x04, 0x40)
			b = append(b, 0x20, a.lCount, 0x41, 0x01, 0x6A, 0x21, a.lCount)
			b = append(b, 0x0B)
			b = append(b, 0x20, a.pOutPtr, 0x20, lID, 0x41, 0x03, 0x76, 0x6A)
			b = append(b, 0x20, a.pOutPtr, 0x20, lID, 0x41, 0x03, 0x76, 0x6A)
			b = appendTableLoad8u(b, 0)
			b = append(b, 0x41, 0x01, 0x20, lID, 0x41, 0x07, 0x71, 0x74, 0x72)
			b = appendTableStore8(b, 0)
		} else {
			b = append(b, 0x20, a.lAcc, 0x42, 0x01)
			b = append(b, 0x20, lID, 0xAD, 0x86, 0x84, 0x21, a.lAcc)
			// The bare `match` form reads lCount as its flag, and match_all's
			// narrow epilogue returns lAcc, so bumping it here is harmless and
			// keeps a hit visible to both.
			b = append(b, 0x20, a.lCount, 0x41, 0x01, 0x6A, 0x21, a.lCount)
		}
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x20, lIdx, 0x20, countLocal, 0x49, 0x0D, 0x00)
		b = append(b, 0x0B)
		b = append(b, 0x0B)
		return b
	}
}

// ---------------------------------------------------------------------------
// Anchored trio: match / match_any / match_all.

// emitSetAnchoredCapBody emits one of the three anchored capabilities.
//
// The match must span the whole input (§3.3), which is what the anchored probe
// tests: it reports pattern k only when the run from position 0 reaches `len`
// in a state accepting for k. These run over the set's ANCHORED buckets — full
// patterns, merged without leftmost-first pruning — so there is no literal
// frontend, no prefix DFA and no candidate enumeration here at all. §5's table
// says as much: a `match`-only set needs no literal machinery, because it can
// never execute.
func emitSetAnchoredCapBody(cs *compiledSet, kind setCapKind, probeFnBase int) []byte {
	wide := cs.wideAll() && kind == capMatchAll
	const (
		pInPtr  = byte(0)
		pInLen  = byte(1)
		pOutPtr = byte(2) // wide _all only
	)
	nParams := byte(2)
	if wide {
		nParams = 3
	}
	// The two scratch locals a G17 sparse bucket's recording loop needs are
	// declared ONLY when one is present. Declaring them unconditionally would
	// change the emitted bytes of every anchored body in the project for no
	// reason, and module size is an exact gate (tools/setperf `make check`).
	anySparse := false
	for _, ab := range cs.anchoredBuckets {
		if ab.sparse {
			anySparse = true
			break
		}
	}
	nI32 := byte(3)
	if anySparse {
		nI32 = 5
	}
	lBits := nParams
	lCount := nParams + 1
	lAnyID := nParams + 2
	lTmpA := nParams + 3
	lTmpB := nParams + 4
	lAcc := nParams + nI32 // i64, last

	var b []byte
	b = append(b, 0x02, nI32, 0x7F, 0x01, 0x7E) // n x i32, 1 x i64

	acc := capAccumulator{kind: kind, wide: wide, lAcc: lAcc, lCount: lCount, lAnyID: lAnyID, pOutPtr: pOutPtr}

	b = append(b, 0x41, 0x00, 0x21, lCount)
	b = append(b, 0x41, 0x7F, 0x21, lAnyID) // -1
	b = append(b, 0x42, 0x00, 0x21, lAcc)

	b = append(b, 0x02, 0x40) // block $done

	for bi := range cs.anchoredBuckets {
		n := len(cs.anchoredBuckets[bi].patterns)
		if n > 32 {
			n = 32
		}
		mask := uint32(0xFFFFFFFF)
		if n < 32 {
			mask = uint32(1)<<uint(n) - 1
		}
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x41, 0x00) // start = 0: the match must begin at input position 0
		b = append(b, 0x20, pInLen)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(mask))
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(probeFnBase+bi))
		b = append(b, 0x21, lBits)
		// A G17 sparse bucket returned a COUNT, not bits — the mask passed
		// above is ignored by its probe, exactly as on the find path.
		if cs.anchoredBuckets[bi].sparse {
			b = acc.emitRecordSparseCount(b, lBits, cs.anchoredBuckets[bi], cs.tableMemIdx, lTmpA, lTmpB, 0)
			continue
		}
		b = acc.emitRecordBits(b, lBits, cs.anchoredIDs[bi], 0)
	}

	b = append(b, 0x0B) // end $done
	return finishAnchoredCapBody(b, kind, wide, lAcc, lCount, lAnyID)
}

// ---------------------------------------------------------------------------
// Scan trio: scan / scan_any / scan_all.
//
// These are NOT emitted here. They go through emitSetMatchFnFinal with a
// non-capFind mode, so they get the same literal frontend (Teddy / Shufti /
// AC / scalar), the same candidate loop, the same prefix checks and the same
// first-position drain as `find` — and differ only in what they record at a
// matching position. See setFindCtx.mode in compile/set_find.go.
//
// A scalar-only implementation was tried first and measured at 17x the fuel
// of `find` on a keywords-8 no-match corpus (11.7M vs 679K), because it
// visited every position where `find` skipped with Teddy. `scan` is supposed
// to be one of the CHEAP capabilities; that was backwards.

// allPatternsMask returns the i64 bitmask with a bit per pattern in the set.
// Only meaningful for the narrow (<= 64 patterns) `_all` forms.
func allPatternsMask(cs *compiledSet) uint64 {
	var m uint64
	for bi, ids := range cs.patternIDs {
		// Under phase1Only the fallback buckets belong to phase 2, so their
		// ids can never appear in this body's accumulator. Including them
		// would make `scan_all`'s "every pattern seen" exit unreachable and
		// run phase 1 to end of input on every call — correct, but it throws
		// away the exit for exactly the sets the split exists to speed up.
		if cs.phase1Only && cs.buckets[bi].isFallback {
			continue
		}
		for _, id := range ids {
			if id < 64 {
				m |= uint64(1) << uint(id)
			}
		}
	}
	return m
}

// finishAnchoredCapBody emits the anchored capability's return value and the
// function end.
//
// Anchored only. The scan trio returns through setFindCtx.emitEpilogue, which
// is where §3.17's packed-i64 encoding lives; this function used to carry dead
// capScan/capScanAny/capScanAll arms and an lMinStart parameter its only
// caller always passed as 0, so the encoding was specified twice.
func finishAnchoredCapBody(b []byte, kind setCapKind, wide bool, lAcc, lCount, lAnyID byte) []byte {
	switch kind {
	case capMatch:
		b = append(b, 0x20, lCount) // 1 iff some probe reported a hit
	case capMatchAny:
		b = append(b, 0x20, lAnyID)
	default: // capMatchAll
		if wide {
			b = append(b, 0x20, lCount)
		} else {
			b = append(b, 0x20, lAcc)
		}
	}
	b = append(b, 0x0B) // end function
	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}
