package compile

import "github.com/qrdl/regexped/internal/utils"

// The six non-`find` set capabilities (plans/SETS.md §3.12, §3.13, §3.17).
//
//	match    (ptr, len)                -> i32   0 | 1
//	match_any(ptr, len)                -> i32   pattern id, or -1
//	match_all(ptr, len)                -> i64   bitmask            (<= 64 patterns)
//	match_all(ptr, len, out_ptr)       -> i32   count + bitmap     (>  64)
//	scan     (ptr, len, from)          -> i32   0 | 1
//	scan_any (ptr, len, from)          -> i64   (start<<32)|id, or -1
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
)

// wideBitmapThreshold is the pattern count above which the `_all` pair
// switches from an i64 return value to a caller-provided bitmap (§3.13).
const wideBitmapThreshold = 64

// maxRetireLocals bounds the highest local index scan_all's per-bucket
// retire masks may occupy. Local indices are ULEB128 in the spec, but every
// emitter in this package writes them as a single byte, so 127 is the
// ceiling; one slot is left for the i64 accumulator that follows them.
const maxRetireLocals = 126

// patternCount returns the number of patterns the set actually compiled.
func (cs *compiledSet) patternCount() int {
	max := -1
	for _, ids := range cs.patternIDs {
		for _, id := range ids {
			if id > max {
				max = id
			}
		}
	}
	return max + 1
}

// wideAll reports whether this set's `_all` capabilities use the >64-pattern
// out_ptr bitmap form.
func (cs *compiledSet) wideAll() bool { return cs.patternCount() > wideBitmapThreshold }

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
func (a capAccumulator) emitRecordBits(b []byte, bitsLocal byte, ids []int, escapeDepth byte) []byte {
	switch a.kind {
	case capMatch, capScan:
		// Any bit at all settles a boolean answer. lCount doubles as the
		// result flag so the epilogue has one thing to return whichever way
		// the block was left.
		b = append(b, 0x20, bitsLocal, 0x04, 0x40)
		b = append(b, 0x41, 0x01, 0x21, a.lCount)
		b = append(b, 0x0C, escapeDepth+1)
		b = append(b, 0x0B)
		return b
	case capMatchAny:
		// Which id is unspecified (§3.5), so the lowest set bit is as good as
		// any — and it is one compare per pattern, unrolled at compile time.
		for k, gid := range ids {
			if k >= 32 {
				break
			}
			b = append(b, 0x20, bitsLocal, 0x41)
			b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
			b = append(b, 0x71, 0x04, 0x40)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(gid))
			b = append(b, 0x21, a.lAnyID)
			b = append(b, 0x0C, escapeDepth+1) // +1: inside this `if`
			b = append(b, 0x0B)
		}
		return b
	case capScanAny:
		// The caller settles the start; this only records the id, and must
		// keep recording as long as the start it belongs to is still the best.
		for k, gid := range ids {
			if k >= 32 {
				break
			}
			b = append(b, 0x20, bitsLocal, 0x41)
			b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
			b = append(b, 0x71, 0x04, 0x40)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(gid))
			b = append(b, 0x21, a.lAnyID)
			b = append(b, 0x0B)
		}
		return b
	default: // capMatchAll, capScanAll
		for k, gid := range ids {
			if k >= 32 {
				break
			}
			b = append(b, 0x20, bitsLocal, 0x41)
			b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
			b = append(b, 0x71, 0x04, 0x40)
			if a.wide {
				// Set bit gid in the caller's little-endian bitmap, counting
				// only the 0->1 transitions so the returned count is the
				// number of distinct patterns rather than the number of hits.
				byteOff := gid / 8
				// i32.const takes a SIGNED LEB128, so a bit value of 0x80
				// (gid % 8 == 7) cannot be written as a bare byte: 0x80 has
				// the continuation bit set and would swallow the next opcode.
				bitInByte := int32(1) << uint(gid%8)
				b = append(b, 0x20, a.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A, 0x2D, 0x00, 0x00) // load8_u
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, bitInByte)
				b = append(b, 0x71, 0x45, 0x04, 0x40)
				b = append(b, 0x20, a.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A)
				b = append(b, 0x20, a.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A, 0x2D, 0x00, 0x00)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, bitInByte)
				b = append(b, 0x72)
				b = append(b, 0x3A, 0x00, 0x00) // i32.store8
				b = append(b, 0x20, a.lCount, 0x41, 0x01, 0x6A, 0x21, a.lCount)
				b = append(b, 0x0B)
			} else {
				b = append(b, 0x20, a.lAcc, 0x42)
				b = utils.AppendSLEB128_64(b, int64(uint64(1)<<uint(gid)))
				b = append(b, 0x84, 0x21, a.lAcc) // i64.or
			}
			b = append(b, 0x0B)
		}
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
	return finishCapBody(b, kind, wide, lAcc, lCount, lAnyID, 0)
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
	for _, ids := range cs.patternIDs {
		for _, id := range ids {
			if id < 64 {
				m |= uint64(1) << uint(id)
			}
		}
	}
	return m
}

// finishCapBody emits the anchored capability's return value and the function
// end. (The scan trio uses setFindCtx.emitEpilogue instead — it shares the
// four frontend bodies.)
func finishCapBody(b []byte, kind setCapKind, wide bool, lAcc, lCount, lAnyID, lMinStart byte) []byte {
	switch kind {
	case capMatch, capScan:
		b = append(b, 0x20, lCount) // 1 iff some probe reported a hit
	case capMatchAny:
		b = append(b, 0x20, lAnyID)
	case capScanAny:
		// (start << 32) | id, or -1 (§3.17). lAnyID stays -1 when nothing
		// matched, and -1 is unambiguous because both fields are < 2^31.
		b = append(b, 0x20, lAnyID, 0x41, 0x00, 0x48, 0x04, 0x7E) // if id < 0
		b = append(b, 0x42, 0x7F)                                 // i64.const -1
		b = append(b, 0x05)
		b = append(b, 0x20, lMinStart, 0xAD, 0x42, 0x20, 0x86) // (i64)start << 32
		b = append(b, 0x20, lAnyID, 0xAD, 0x84)                // | (i64)id
		b = append(b, 0x0B)
	default: // capMatchAll, capScanAll
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
