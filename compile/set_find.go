package compile

import (
	"sort"

	"github.com/qrdl/regexped/internal/utils"
)

// Set `find` body support (plans/SETS.md §3.6, §3.11, §3.18, §9.4).
//
// All four frontend bodies (Scalar, Shufti, AC, Teddy) share the same
// per-candidate work: compute the bucket's validMask and run its suffix DFA.
// Before this file that logic was copy-pasted four times; the S1 rework needs
// it in one place, because the first-position obligation of §9.4 threads
// through every one of those sites.
//
// # What a `find` call returns
//
//	find(ptr, len, from, out_ptr, out_cap) -> i32
//
// The scan finds the SMALLEST match start >= from at which any pattern
// matches, and returns every match at that position.  The return value is the
// TOTAL number of such matches, which may exceed out_cap; the buffer receives
// min(total, out_cap) tuples.  Every tuple in one call shares the same start.
//
// # Why "first position" is not free (§9.4)
//
// Candidate order is not match-start order.  A bucket whose mandatory literal
// sits L bytes into the pattern reports a match starting at `c - L` for a
// literal candidate at `c`, so two buckets with different L interleave their
// starts as `c` advances.  The body therefore tracks lMinStart (the best start
// seen so far) and treats the output buffer as "the tuples at lMinStart":
//
//	s <  lMinStart -> the tuples written so far belong to a later start;
//	                  discard them (rewind lTotal to 0) and start over at s
//	s == lMinStart -> append
//	s >  lMinStart -> skip
//
// Committing lMinStart/lTotal only when the suffix DFA actually reported
// something is what keeps a *candidate* that produces no match from poisoning
// the scan: a bucket can pass its literal check and still match nothing.
//
// # The drain (§9.4 class A / class B)
//
// Scanning must continue past the first productive candidate, because a later
// candidate can recover an earlier start.  How far is bounded by the set's
// maximum lookback M = the largest fixed prefix length over the set's patterns:
//
//	stop as soon as  candidatePos - M > lMinStart
//
// With M == 0 — every pattern's mandatory literal at its start, the flagship
// `AKIA[A-Z0-9]{16}` shape — the drain is empty and the body is exactly
// stop-at-first-productive-candidate, which is §9.4's class A with an empty
// drain.  A larger M is class A with a real drain.  §9.4's class B (nothing can
// be skipped, because a literal arbitrarily far to the right can serve a match
// starting here) is the variable-length-prefix case, and analyzePattern routes
// those patterns to a fallback bucket instead — see its comment on why the
// split representation cannot answer them correctly at all.

// prefixLenGroup is one (fixed prefix length, pattern bits) partition of a
// bucket. Every pattern in the group has its mandatory literal exactly L bytes
// after the match start, so one suffix-DFA call covers the whole group and its
// match start is `candidatePos - L` — a single value the caller can compare
// against lMinStart.
type prefixLenGroup struct {
	L    int    // fixed prefix length (0 = trivial prefix, literal at the match start)
	mask uint32 // bucket-local bits of the patterns with that length
}

// buildPrefixLenGroups partitions bucket bi's patterns by fixed prefix length,
// sorted by DESCENDING L so that the groups are emitted in ascending
// match-start order within one candidate (fewer lMinStart rewinds).
func buildPrefixLenGroups(cs *compiledSet, bi int) []prefixLenGroup {
	byLen := map[int]uint32{}
	for k := range cs.prefixFixedLens[bi] {
		if k >= 32 {
			break
		}
		byLen[cs.prefixFixedLens[bi][k]] |= uint32(1) << uint(k)
	}
	groups := make([]prefixLenGroup, 0, len(byLen))
	for l, m := range byLen {
		if m == 0 {
			continue
		}
		groups = append(groups, prefixLenGroup{L: l, mask: m})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].L > groups[j].L })
	return groups
}

// setMaxLookback returns the set's maximum lookback M: the largest number of
// bytes between a mandatory literal and the match start it can serve.
func setMaxLookback(cs *compiledSet) int {
	m := 0
	for bi := range cs.buckets {
		for k := range cs.prefixFixedLens[bi] {
			if k >= 32 {
				break
			}
			if l := cs.prefixFixedLens[bi][k]; l > m {
				m = l
			}
		}
	}
	return m
}

// setFindCtx holds the register allocation of one set `find` body so the
// shared per-candidate emitters below can be reused by every frontend.
type setFindCtx struct {
	cs              *compiledSet
	suffixFnBase    int
	prefixFnBaseIdx int
	// mode selects what the body records at a matching position. capFind
	// writes tuples through the suffix DFA; the scan trio records a bitmask
	// through the cheap probes of set_probe.go. Everything else — the literal
	// frontend, the candidate loop, the prefix checks, the first-position
	// drain — is shared, which is the point: routing the scan trio through
	// the scalar body instead cost 17x the fuel on a keywords-8 no-match
	// corpus (11.7M vs 679K), because it visited every position where `find`
	// skipped with Teddy.
	mode        setCapKind
	probeFnBase int
	wideBitmap  bool // scan_all with > 64 patterns: write a bitmap, count hits
	maxLookback int  // M
	// drainSlack is added to M in the drain test. It covers frontends whose
	// loop variable trails the literal start: the AC body advances a cursor to
	// the literal's LAST byte, so a candidate discovered at `pos` can have its
	// literal — and therefore its match — start up to (maxLiteralLen - 1)
	// bytes earlier.
	drainSlack int
	// perPositionDrain is true when the body re-checks the drain bound before
	// every single candidate position it evaluates. Only the Scalar and Shufti
	// bodies do: Teddy evaluates a whole 16-byte chunk's lanes between checks,
	// and AC can fire several literals of different lengths — and therefore
	// several distinct match starts — at one cursor position. When it is
	// false the `start > lMinStart` guard is load-bearing rather than
	// redundant, even at M == 0.
	perPositionDrain bool

	// Parameters, in the §4.1 order:
	//   ungated: (ptr, len, from, out_ptr, out_cap)
	//   gated:   (ptr, len, from, gate_ptr, out_ptr, out_cap)
	pInPtr, pInLen, pFrom, pOutPtr, pOutCap byte

	// localBase is the first local index (one past the last parameter), and
	// lPos is the scan cursor every frontend allocates first.
	localBase byte
	lPos      byte

	// gated selects the default, per-pattern non-overlapping body
	// (plans/SETS.md §3.14-3.16). pGate then names the gate-array parameter.
	gated bool
	pGate byte

	// Locals.
	lTmp       byte // scratch (prefix-DFA result, suffix-call result)
	lValidMask byte
	lOutBase   byte // tuple base pointer for direct writes; the _any pattern id in scan modes
	lTotal     byte // matches at lMinStart (find); the boolean flag / hit count in scan modes
	lMinStart  byte // best match start seen so far; minStartSentinel when none
	lBase      byte // tuple index this call's writes start at
	lStart     byte // the match start of the group currently being evaluated
	lAcc       byte // i64 bitmask accumulator, scan_all only
}

// minStartSentinel is lMinStart's "nothing found yet" value. It is larger than
// any real position, so the drain comparison `pos - M > lMinStart` is false
// until something is actually found, and it is positive so the signed
// comparisons throughout stay well-defined.
const minStartSentinel = int32(0x7FFFFFFF)

// needMinStartCompare reports whether the body must compare a candidate start
// against lMinStart at all. With M == 0 every match start equals the candidate
// position, so a body that re-checks the drain before every position already
// guarantees `pos <= lMinStart` on entry to the bucket work and the comparison
// is provably redundant. Bodies that batch several candidates between drain
// checks still need it.
func (c *setFindCtx) needMinStartCompare() bool {
	// scan and scan_all track no minimum start at all — the first is a
	// boolean and the second accumulates over the whole input — so lMinStart
	// stays at its sentinel and the compare can never fire.
	if c.mode == capScan || c.mode == capScanAll {
		return false
	}
	return c.maxLookback != 0 || !c.perPositionDrain
}

// emitValidMask computes lValidMask for bucket bi at position posLocal:
// trivial-prefix patterns are always eligible, \A-anchored ones only at
// position 0, (?m:^)-anchored ones at position 0 or right after a newline,
// and fixed-length-prefix ones pass when their backward prefix DFA accepts
// ending at posLocal-1.
func (c *setFindCtx) emitValidMask(b []byte, bi int, posLocal byte) []byte {
	cs := c.cs
	tm := cs.trivialPrefixMasks[bi]
	sam := cs.startAnchorMasks[bi]
	lam := cs.lineAnchorMasks[bi]
	tmNoAnchor := tm &^ (sam | lam)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(tmNoAnchor))
	b = append(b, 0x21, c.lValidMask)
	if sam != 0 {
		b = append(b, 0x20, posLocal, 0x45, 0x04, 0x40) // if posLocal == 0
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(sam))
		b = append(b, 0x72, 0x21, c.lValidMask)
		b = append(b, 0x0B)
	}
	if lam != 0 {
		// posLocal == 0 || input[posLocal-1] == '\n'
		b = append(b, 0x20, posLocal, 0x45) // posLocal == 0
		b = append(b, 0x20, posLocal, 0x04, 0x7F)
		b = append(b, 0x20, c.pInPtr, 0x20, posLocal, 0x41, 0x01, 0x6B, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x41, 0x0A, 0x46) // == newline
		b = append(b, 0x05)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x0B) // end if (guards the load against posLocal == 0)
		b = append(b, 0x72) // i32.or
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(lam))
		b = append(b, 0x72, 0x21, c.lValidMask)
		b = append(b, 0x0B)
	}
	for k, fnIdx := range cs.prefixFnIdx[bi] {
		if k >= 32 || fnIdx < 0 {
			continue
		}
		bit := uint32(1) << uint(k)
		b = append(b, 0x20, c.pInPtr)
		b = append(b, 0x20, posLocal, 0x41, 0x01, 0x6B) // posLocal - 1
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(c.prefixFnBaseIdx+fnIdx))
		b = append(b, 0x22, c.lTmp, 0x41, 0x00, 0x4E, 0x04, 0x40) // if result >= 0
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x72, 0x21, c.lValidMask)
		b = append(b, 0x0B)
	}
	return b
}

// emitStartGuards emits the two eligibility checks a candidate start must pass
// before its group is evaluated, as br_if's out of an enclosing block at
// depth 0: the start must be at or after `from`, and it must not be later than
// the best start found so far.
//
// needFromCheck is false for L == 0 groups, whose start is the candidate
// position itself and therefore never below `from`.
func (c *setFindCtx) emitStartGuards(b []byte, needFromCheck bool) []byte {
	if needFromCheck {
		b = append(b, 0x20, c.lStart, 0x20, c.pFrom, 0x48, 0x0D, 0x00) // lStart < from → skip
	}
	if c.needMinStartCompare() {
		b = append(b, 0x20, c.lStart, 0x20, c.lMinStart, 0x4A, 0x0D, 0x00) // lStart > lMinStart → skip
	}
	return b
}

// emitSelectBase sets lBase to the tuple index this group's writes begin at:
// 0 when lStart beats the best start so far (the tuples already in the buffer
// belong to a later position and are discarded), else the running total.
func (c *setFindCtx) emitSelectBase(b []byte) []byte {
	b = append(b, 0x41, 0x00)                              // i32.const 0  (value when cond)
	b = append(b, 0x20, c.lTotal)                          // lTotal       (value when !cond)
	b = append(b, 0x20, c.lStart, 0x20, c.lMinStart, 0x48) // lStart < lMinStart
	b = append(b, 0x1B)                                    // select
	b = append(b, 0x21, c.lBase)
	return b
}

// emitCommit records that the group produced a match count (on the stack)
// starting at lStart. Nothing is committed when the count is zero, so a
// candidate whose literal matched but whose DFA found nothing cannot move
// lMinStart.
func (c *setFindCtx) emitCommit(b []byte) []byte {
	b = append(b, 0x22, c.lTmp, 0x04, 0x40) // tee count; if count != 0
	b = append(b, 0x20, c.lStart, 0x21, c.lMinStart)
	b = append(b, 0x20, c.lBase, 0x20, c.lTmp, 0x6A, 0x21, c.lTotal)
	b = append(b, 0x0B)
	return b
}

// emitGateMask folds the §3.16 pre-mask into lValidMask: pattern k stays
// eligible at match start s only while `2s + 1 >= gate[k]`.
//
// This is what collapses the quadratic behaviour of §3.14 — a bucket whose
// mask ends up empty is skipped entirely, so no literal check, no prefix DFA
// and no suffix DFA run at that position. The bound used here is the weaker,
// non-empty one; an empty extent needs the stricter `2s >= gate[k]`, which
// only the suffix body can apply because only it knows the extent (see
// emitWriteMatchK's gated branch).
//
// gate[k] is indexed by GLOBAL pattern id, so the byte offset is a
// compile-time constant per pattern and the load needs no arithmetic.
func (c *setFindCtx) emitGateMask(b []byte, bi int, mask uint32) []byte {
	if !c.gated {
		return b
	}
	for k, gid := range c.cs.patternIDs[bi] {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		if mask&bit == 0 {
			continue
		}
		// if (2*lStart + 1) < gate[gid]: clear bit k
		b = append(b, 0x20, c.lStart, 0x41, 0x01, 0x74, 0x41, 0x01, 0x6A) // 2*lStart + 1
		b = append(b, 0x20, c.pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4)) // i32.load offset=gid*4
		b = append(b, 0x49)                       // i32.lt_u
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(^bit))
		b = append(b, 0x71, 0x21, c.lValidMask)
		b = append(b, 0x0B)
	}
	return b
}

// emitGateWriteback records the reported matches in the gate array, using
// scratch locals the scan loop has finished with.
//
// Write-back runs ONLY for a fully delivered position (§3.11 / D2): an
// overflowing call must leave the array byte-for-byte as it found it, so that
// the caller's grown retry sees the identical world. The same rule covers the
// out_cap = 0 size probe.
func (c *setFindCtx) emitGateWriteback(b []byte, lPos byte) []byte {
	if !c.gated {
		return b
	}
	// if lTotal > 0 && lTotal <= out_cap
	b = append(b, 0x20, c.lTotal, 0x04, 0x40)
	b = append(b, 0x20, c.lTotal, 0x20, c.pOutCap, 0x4C, 0x04, 0x40) // <= (signed)
	b = append(b, 0x41, 0x00, 0x21, lPos)
	b = append(b, 0x02, 0x40)                                   // block $wb_done
	b = append(b, 0x03, 0x40)                                   // loop $wb
	b = append(b, 0x20, lPos, 0x20, c.lTotal, 0x4E, 0x0D, 0x01) // idx >= total → done
	b = append(b, 0x20, c.pOutPtr, 0x20, lPos, 0x41, 12, 0x6C, 0x6A, 0x21, c.lOutBase)
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x00, 0x21, c.lTmp)   // id
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x04, 0x21, c.lStart) // start
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x08, 0x21, c.lBase)  // end
	// gate[id] = 2*end + (end > start ? 1 : 2)   — §3.16's biased encoding.
	b = append(b, 0x20, c.pGate, 0x20, c.lTmp, 0x41, 0x02, 0x74, 0x6A) // &gate[id]
	b = append(b, 0x20, c.lBase, 0x41, 0x01, 0x74)                     // 2*end
	b = append(b, 0x41, 0x01, 0x41, 0x02)                              // 1, 2
	b = append(b, 0x20, c.lBase, 0x20, c.lStart, 0x4A)                 // end > start
	b = append(b, 0x1B)                                                // select
	b = append(b, 0x6A)                                                // +
	b = append(b, 0x36, 0x02, 0x00)                                    // i32.store
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $wb
	b = append(b, 0x0B) // end block $wb_done
	b = append(b, 0x0B) // end if total <= cap
	b = append(b, 0x0B) // end if total > 0
	return b
}

// emitSuffixCall emits the call to bucket bi's suffix DFA for the pattern bits
// in mask, with the literal at position posLocal.
func (c *setFindCtx) emitSuffixCall(b []byte, bi, litLen int, posLocal byte, mask uint32) []byte {
	b = append(b, 0x20, c.pInPtr)
	b = append(b, 0x20, posLocal)
	if litLen != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A)
	}
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x20, c.pOutPtr, 0x20, c.lBase, 0x41, 12, 0x6C, 0x6A)
	b = append(b, 0x20, c.pOutCap, 0x20, c.lBase, 0x6B)
	b = append(b, 0x20, c.lValidMask, 0x41)
	b = utils.AppendSLEB128(b, int32(mask))
	b = append(b, 0x71)
	if c.gated {
		b = append(b, 0x20, c.pGate)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(c.suffixFnBase+bi))
	return b
}

// emitBucketAt emits the complete per-candidate evaluation of bucket bi with
// its mandatory literal at posLocal (litLen == 0 for a fallback bucket, whose
// suffix DFA models the whole pattern anchored at posLocal).
func (c *setFindCtx) emitBucketAt(b []byte, bi, litLen int, posLocal byte) []byte {
	b = c.emitValidMask(b, bi, posLocal)

	for _, g := range c.cs.prefixLenGroups[bi] {
		b = append(b, 0x02, 0x40) // block $skip_group
		// lStart = posLocal - L. The bucket's mandatory literal sits L bytes
		// into the pattern, so a candidate at posLocal is a match STARTING at
		// posLocal - L — and L differs between patterns sharing a literal,
		// which is why each length is its own group.
		b = append(b, 0x20, posLocal)
		if g.L != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(g.L))
			b = append(b, 0x6B)
		}
		b = append(b, 0x21, c.lStart)
		b = c.emitStartGuards(b, g.L != 0)
		if c.mode == capFind {
			b = c.emitGateMask(b, bi, g.mask)
			b = c.emitSelectBase(b)
			b = c.emitSuffixCall(b, bi, litLen, posLocal, g.mask)
			b = c.emitCommit(b)
		} else {
			b = c.emitProbeCall(b, bi, litLen, posLocal, g.mask)
			b = c.emitRecordProbe(b, bi)
		}
		b = append(b, 0x0B) // end block $skip_group
	}
	return b
}

// emitProbeCall calls bucket bi's bitmask probe for the pattern bits in mask,
// leaving the result in lTmp.
func (c *setFindCtx) emitProbeCall(b []byte, bi, litLen int, posLocal byte, mask uint32) []byte {
	b = append(b, 0x20, c.pInPtr)
	b = append(b, 0x20, posLocal)
	if litLen != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A)
	}
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x20, c.lValidMask, 0x41)
	b = utils.AppendSLEB128(b, int32(mask))
	b = append(b, 0x71)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(c.probeFnBase+bi))
	b = append(b, 0x21, c.lTmp)
	return b
}

// emitRecordProbe folds a probe result into the mode's answer.
//
// Nothing here branches out of the loop: the exit is the drain check at the
// top of the next iteration (emitDrainCheck), which is mode-aware. That keeps
// this emitter free of the br-depth bookkeeping the four frontends would
// otherwise each need their own version of.
func (c *setFindCtx) emitRecordProbe(b []byte, bi int) []byte {
	switch c.mode {
	case capScan:
		// Any bit settles a boolean answer.
		b = append(b, 0x20, c.lTmp, 0x04, 0x40)
		b = append(b, 0x41, 0x01, 0x21, c.lTotal)
		b = append(b, 0x0B)
		return b
	case capScanAny:
		// Keep the earliest start, and one arbitrary id matching there (§3.5).
		b = append(b, 0x20, c.lTmp, 0x04, 0x40)
		b = append(b, 0x20, c.lStart, 0x20, c.lMinStart, 0x48, 0x04, 0x40) // start < best
		b = append(b, 0x20, c.lStart, 0x21, c.lMinStart)
		for k, gid := range c.cs.patternIDs[bi] {
			if k >= 32 {
				break
			}
			b = append(b, 0x20, c.lTmp, 0x41)
			b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
			b = append(b, 0x71, 0x04, 0x40)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(gid))
			b = append(b, 0x21, c.lOutBase)
			b = append(b, 0x0B)
		}
		b = append(b, 0x0B)
		b = append(b, 0x0B)
		return b
	default: // capScanAll
		for k, gid := range c.cs.patternIDs[bi] {
			if k >= 32 {
				break
			}
			b = append(b, 0x20, c.lTmp, 0x41)
			b = utils.AppendSLEB128(b, int32(uint32(1)<<uint(k)))
			b = append(b, 0x71, 0x04, 0x40)
			if c.wideBitmap {
				// Set bit gid in the caller's little-endian bitmap, counting
				// only the 0->1 transitions so the count is distinct patterns.
				byteOff := gid / 8
				bitInByte := int32(1) << uint(gid%8)
				b = append(b, 0x20, c.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A, 0x2D, 0x00, 0x00)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, bitInByte)
				b = append(b, 0x71, 0x45, 0x04, 0x40)
				b = append(b, 0x20, c.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A)
				b = append(b, 0x20, c.pOutPtr, 0x41)
				b = utils.AppendSLEB128(b, int32(byteOff))
				b = append(b, 0x6A, 0x2D, 0x00, 0x00)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, bitInByte)
				b = append(b, 0x72)
				b = append(b, 0x3A, 0x00, 0x00)
				b = append(b, 0x20, c.lTotal, 0x41, 0x01, 0x6A, 0x21, c.lTotal)
				b = append(b, 0x0B)
			} else {
				b = append(b, 0x20, c.lAcc, 0x42)
				b = utils.AppendSLEB128_64(b, int64(uint64(1)<<uint(gid)))
				b = append(b, 0x84, 0x21, c.lAcc)
			}
			b = append(b, 0x0B)
		}
		return b
	}
}

// emitFindPrologue initialises the running state every body shares.
func (c *setFindCtx) emitFindPrologue(b []byte, lPos byte) []byte {
	b = append(b, 0x41, 0x00, 0x21, c.lTotal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, minStartSentinel)
	b = append(b, 0x21, c.lMinStart)
	b = append(b, 0x20, c.pFrom, 0x21, lPos)
	switch c.mode {
	case capScanAny:
		b = append(b, 0x41, 0x7F, 0x21, c.lOutBase) // id = -1
	case capScanAll:
		b = append(b, 0x42, 0x00, 0x21, c.lAcc)
	}
	return b
}

// emitEpilogue pushes the body's return value.
func (c *setFindCtx) emitEpilogue(b []byte) []byte {
	switch c.mode {
	case capScan:
		return append(b, 0x20, c.lTotal) // 1 iff some probe reported a hit
	case capScanAny:
		// (start << 32) | id, or -1 (§3.17). The id stays -1 when nothing
		// matched, and -1 is unambiguous because both fields are < 2^31.
		b = append(b, 0x20, c.lOutBase, 0x41, 0x00, 0x48, 0x04, 0x7E)
		b = append(b, 0x42, 0x7F)
		b = append(b, 0x05)
		b = append(b, 0x20, c.lMinStart, 0xAD, 0x42, 0x20, 0x86)
		b = append(b, 0x20, c.lOutBase, 0xAD, 0x84)
		b = append(b, 0x0B)
		return b
	case capScanAll:
		if c.wideBitmap {
			return append(b, 0x20, c.lTotal)
		}
		return append(b, 0x20, c.lAcc)
	default:
		return append(b, 0x20, c.lTotal)
	}
}

// emitDrainCheck emits the §9.4 drain test as a br_if to the given depth: once
// no remaining candidate can produce a start at or before lMinStart, the scan
// is finished.
func (c *setFindCtx) emitDrainCheck(b []byte, lPos byte, depth byte) []byte {
	switch c.mode {
	case capScan:
		// A boolean answer is settled by the first hit; finishing the current
		// position or chunk costs nothing measurable and keeps this check
		// independent of each frontend's block nesting.
		return append(b, 0x20, c.lTotal, 0x0D, depth)
	case capScanAll:
		// No first-position notion at all: scan_all asks which patterns match
		// ANYWHERE at or after `from`, so the only early exit is "every
		// pattern has already been seen" (§3.13).
		if c.wideBitmap {
			b = append(b, 0x20, c.lTotal, 0x41)
			b = utils.AppendSLEB128(b, int32(c.cs.patternCount()))
			b = append(b, 0x4E, 0x0D, depth)
			return b
		}
		b = append(b, 0x20, c.lAcc, 0x42)
		b = utils.AppendSLEB128_64(b, int64(allPatternsMask(c.cs)))
		b = append(b, 0x51, 0x0D, depth)
		return b
	}
	bound := c.maxLookback + c.drainSlack
	b = append(b, 0x20, lPos)
	if bound != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(bound))
		b = append(b, 0x6B)
	}
	b = append(b, 0x20, c.lMinStart, 0x4A, 0x0D, depth) // lPos - M > lMinStart
	return b
}

// litOrderFor returns the literal buckets in the order the find bodies
// evaluate them: shortest literal first, and within one length the
// highest-numbered bucket first (binPack assigns buckets ascending by suffix
// state count, so the last bucket holds the `$`-suffix patterns that fire
// only at EOF and are most at risk of being crowded out of the buffer).
func litOrderFor(cs *compiledSet) []int {
	order := make([]int, 0, len(cs.buckets))
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback && bkt.literal != "" {
			order = append(order, bi)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		li := len(cs.buckets[order[i]].literal)
		lj := len(cs.buckets[order[j]].literal)
		if li != lj {
			return li < lj
		}
		return order[i] > order[j]
	})
	return order
}

// newSetFindCtx allocates the parameter and shared-local indices for one find
// body. The five locals every frontend needs — lPos, lTotal, lTmp, lValidMask,
// lOutBase — come first, at localBase..localBase+4; each frontend allocates
// its own after those and sets lMinStart/lBase/lStart wherever it has room.
//
// The gated body carries one extra parameter, so every local index shifts by
// one. Keeping that in one place is why the frontends compute their indices
// from localBase rather than declaring constants.
func newSetFindCtx(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, drainSlack int, mode setCapKind, probeFnBase int) *setFindCtx {
	gated := mode == capFind && cs.find != "" && !cs.overlapping
	c := &setFindCtx{
		cs: cs, suffixFnBase: suffixFnBase, prefixFnBaseIdx: prefixFnBaseIdx,
		mode: mode, probeFnBase: probeFnBase,
		maxLookback: cs.maxLookback, drainSlack: drainSlack,
		gated:  gated,
		pInPtr: 0, pInLen: 1, pFrom: 2,
	}
	switch {
	case mode != capFind:
		// scan / scan_any: (ptr, len, from).
		// scan_all >64 patterns: (ptr, len, from, out_ptr).
		c.localBase = 3
		if mode == capScanAll && cs.wideAll() {
			c.wideBitmap = true
			c.pOutPtr = 3
			c.localBase = 4
		}
	case gated:
		c.pGate, c.pOutPtr, c.pOutCap = 3, 4, 5
		c.localBase = 6
	default:
		c.pOutPtr, c.pOutCap = 3, 4
		c.localBase = 5
	}
	c.lPos = c.localBase
	c.lTotal = c.localBase + 1
	c.lTmp = c.localBase + 2
	c.lValidMask = c.localBase + 3
	c.lOutBase = c.localBase + 4
	// Defaults for a frontend that declares nothing beyond the shared five
	// (the Scalar body); the others override these.
	c.lMinStart = c.localBase + 5
	c.lBase = c.localBase + 6
	c.lStart = c.localBase + 7
	return c
}
