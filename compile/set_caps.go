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

// wideAll reports whether this set's `_all` capabilities use the >64-pattern
// out_ptr bitmap form. Keyed on the ID SPACE, because the form exists to carry
// bit positions and a bit position is a pattern id (§3.13).
func (cs *compiledSet) wideAll() bool { return cs.idSpaceSize() > wideBitmapThreshold }

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
	lBits := nParams
	lCount := nParams + 1
	lAnyID := nParams + 2
	lAcc := nParams + 3 // i64

	var b []byte
	b = append(b, 0x02, 0x03, 0x7F, 0x01, 0x7E) // 3 x i32, 1 x i64

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
