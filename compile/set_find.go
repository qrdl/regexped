package compile

import (
	"sort"

	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// Set `find` body support.
//
// All four frontend bodies (Scalar, Shufti, AC, Teddy) share the same
// per-candidate work: compute the bucket's validMask and run its suffix DFA.
// Before this file that logic was copy-pasted four times; sharing it needs
// it in one place, because the first-position obligation threads
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
// # Why "first position" is not free
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
// # The drain (class A / class B)
//
// Scanning must continue past the first productive candidate, because a later
// candidate can recover an earlier start.  How far is bounded by the set's
// maximum lookback M = the largest fixed prefix length over the set's patterns:
//
//	stop as soon as  candidatePos - M > lMinStart
//
// With M == 0 — every pattern's mandatory literal at its start, the flagship
// `AKIA[A-Z0-9]{16}` shape — the drain is empty and the body is exactly
// stop-at-first-productive-candidate, which is class A with an empty
// drain.  A larger M is class A with a real drain.  Class B (nothing can
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
		if k >= bucketMaskBits {
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
// Never returns a negative: every prefixFixedLens entry is a FIXED length, and
// a pattern with a variable-length prefix is fallback-routed before it gets
// one (see compiledSet.maxLookback).
func setMaxLookback(cs *compiledSet) int {
	m := 0
	for bi := range cs.buckets {
		for k := range cs.prefixFixedLens[bi] {
			if k >= bucketMaskBits {
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
	// tableMemIdx is the memory holding this set's tables. Only the bodies
	// that read a table through setFindCtx set it — today the scalar body, for
	// the first-byte eligibility masks. Bodies that never do leave it 0, which is
	// harmless because the features that use it are gated off for them.
	tableMemIdx int
	// anyProbeBase / useAnyProbe route `scan` and `scan_any` to a bucket's
	// first-hit-exit probe where one was emitted.
	anyProbeBase int
	useAnyProbe  bool
	wideBitmap   bool // scan_all with > 64 patterns: write a bitmap, count hits
	maxLookback  int  // M
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

	// Parameters, in the documented order. BOTH find flavours are 6-param: the
	// overlapping body takes the gate slot for its preflight verdict; the 5-param ungated form below is retired, and
	// pGate's own doc two fields down is the accurate one.
	//   (ptr, len, from, gate_ptr, out_ptr, out_cap)
	pInPtr, pInLen, pFrom, pOutPtr, pOutCap byte

	// localBase is the first local index (one past the last parameter), and
	// lPos is the scan cursor every frontend allocates first.
	localBase byte
	lPos      byte

	// gated selects the default, per-pattern non-overlapping body: the
	// gate pre-mask, the write-time empty-extent rule and the write-back.
	gated bool
	// pGate names the gate-array parameter, which EVERY `find` body has
	// — the overlapping one included, where the
	// array holds no match gates at all. So the presence of the parameter
	// and the applicability of the gate RULE are two different questions:
	// this field answers neither on its own. Ask `gated` for the rule and
	// readsGate() for whether anything is loaded from the array.
	pGate byte
	// preflight is true when this body emits the overlapping preflight and
	// therefore has something to read out of the array. Without it an
	// overlapping body still carries the pointer but never loads from it, so
	// every set that gains no preflight stays byte-identical.
	preflight bool

	// batch marks this body as the hidden per-position WORKER of a
	// find_batch export rather than the exported `find`.
	// Two things change:
	//
	//   - gated: gates are written for every tuple actually DELIVERED, not
	//     only for a position that fitted whole. That is what lets the batch
	//     loop resume a split position — the gate pre-mask then excludes
	//     exactly the patterns already handed to the caller. `find` keeps D2's
	//     transactional rule, which is why this is a separate body.
	//   - ungated: pSkip names a trailing parameter holding how many of this
	//     position's tuples to count but not write. There is no gate array to
	//     record the delivered ones, so the split has to be carried explicitly.
	batch   bool
	hasSkip bool
	pSkip   byte
	// pBatchMode names the gated worker's trailing parameter: 0 selects
	// `find`'s transactional gate rule, non-zero the batch loop's
	// deliver-and-gate rule (decision (11a)). Valid only when batch && gated.
	pBatchMode byte

	// Locals.
	lTmp       byte // scratch (prefix-DFA result, suffix-call result)
	lValidMask byte
	lOutBase   byte // tuple base pointer for direct writes; the _any pattern id in scan modes
	lTotal     byte // matches at lMinStart (find); the boolean flag / hit count in scan modes
	lMinStart  byte // best match start seen so far; minStartSentinel when none
	lBase      byte // tuple index this call's writes start at
	lStart     byte // the match start of the group currently being evaluated
	// gateLocalBase is the first of one i32 local per GLOBAL id in the set's
	// id space, holding gate[gid] read once in the prologue. 0 means the body
	// declared none and the readers go to memory.
	//
	// The array is immutable for the whole call — the write-back runs once,
	// after the scan loop — so every read of it during the scan is a reload of
	// a call-invariant value. Hoisting saves ONE instruction per pattern per
	// CANDIDATE and costs two per pattern per CALL, so it pays exactly when a
	// body evaluates several candidates per call. See gateLocalsProfitable.
	gateLocalBase byte

	// lAllElig is the smallest match start at which EVERY pattern passes the
	// gate pre-mask — `max_k(gate[k]) >> 1`, computed once per call beside
	// emitGateJump's minimum. At starts from there
	// on, emitGateMask's per-pattern chain provably clears nothing, so ONE
	// compare replaces up to 32 load-and-compare pairs.
	//
	// 0 means "not allocated": only the scalar `find` body declares the local,
	// because it is the only one whose per-position cost the chain dominates —
	// a literal frontend has already skipped most positions before reaching a
	// bucket, and giving it the local would move bytes it is supposed to keep.
	lAllElig byte
	lAcc     byte // i64 bitmask accumulator, scan_all only
	// aliveMask is an i64 local holding the ids that match SOMEWHERE in
	// [from,len). G9's gated-`find` preflight fills it and writes it back as
	// gate sentinels.
	//
	// G8's `scan_any` preflight also used it, to intersect every bucket's
	// validMask and make the liveness exit fire. That is gone with
	// decision (10): `scan_any` is the union walk now, so there is no
	// per-position walk left to narrow. `aliveReady` and `emitAliveNarrow`
	// went with it.
	aliveMask byte
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
	// The scan trio tracks no minimum start at all — `scan` is a boolean,
	// `scan_all` accumulates over the whole input, and `scan_any` stopped
	// reporting a start at all — so lMinStart stays
	// at its sentinel and the compare can never fire.
	if c.mode == capScanAll || c.mode == capScanAny {
		return false
	}
	return c.maxLookback != 0 || !c.perPositionDrain
}

// emitGroupMask computes lValidMask for ONE prefix-length group of bucket bi
// at position posLocal — the cheap, branch-free half of eligibility.
//
// A group is either entirely trivial-prefix (L == 0) or entirely
// fixed-prefix (L > 0); the two never mix, because prefixFixedLens is what
// buildPrefixLenGroups partitions on and a trivial prefix has length 0. The
// anchor masks live wholly in the L == 0 group: a splittable pattern with a
// non-trivial prefix never carries a begin anchor (analyzePattern strips a
// zero-length anchor prefix to a mask and routes anything else to fallback),
// so startAnchorMasks/lineAnchorMasks only ever name trivial-prefix patterns.
//
//   - L == 0: start from the unconditionally-eligible bits, then OR in the
//     \A-anchored ones at position 0 and the (?m:^)-anchored ones at position
//     0 or just after a newline.
//   - L > 0: every pattern is a CANDIDATE, and emitPrefixChecks clears the
//     ones whose backward prefix DFA rejects. Starting from all-set is what
//     lets the gate pre-mask and the empty-mask skip run BEFORE those DFA
//     calls rather than after them.
func (c *setFindCtx) emitGroupMask(b []byte, bi int, g prefixLenGroup, posLocal byte) []byte {
	cs := c.cs
	if g.L != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(g.mask))
		b = append(b, 0x21, c.lValidMask)
		return b
	}
	sam := cs.startAnchorMasks[bi] & g.mask
	lam := cs.lineAnchorMasks[bi] & g.mask
	base := g.mask & cs.trivialPrefixMasks[bi] &^ (sam | lam)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(base))
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
		b = appendInputLoad8u(b)        // INPUT byte
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
	return b
}

// emitPrefixChecks runs the backward prefix DFA for each pattern of a
// fixed-prefix group that is STILL a candidate, clearing the ones it rejects.
//
// "Still a candidate" is the point. These calls are backward DFA scans over
// the input — by far the most expensive thing per candidate position — and
// they used to run for every pattern of the bucket before the three cheap
// tests that can discard the whole group: `lStart < from`, the drain
// guard `lStart > lMinStart`, and the gate pre-mask. A candidate past
// the committed minimum start paid a full backward scan per pattern and then
// branched out without reading a single result bit.
//
// The per-pattern liveness guard is only emitted when a gate could have
// cleared some but not all of the group's bits; otherwise the group-level
// empty-mask skip has already proved every bit live.
func (c *setFindCtx) emitPrefixChecks(b []byte, bi int, g prefixLenGroup, posLocal byte) []byte {
	if g.L == 0 {
		return b
	}
	perBitGuard := c.readsGate() && bitsInMask(g.mask) > 1
	for k, fnIdx := range c.cs.prefixFnIdx[bi] {
		if k >= bucketMaskBits || fnIdx < 0 {
			continue
		}
		bit := uint32(1) << uint(k)
		if g.mask&bit == 0 {
			continue
		}
		b = append(b, 0x02, 0x40) // block $skip_pattern
		if perBitGuard {
			b = append(b, 0x20, c.lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x71, 0x45, 0x0D, 0x00) // and; eqz; br_if $skip_pattern
		}
		b = append(b, 0x20, c.pInPtr)
		b = append(b, 0x20, posLocal, 0x41, 0x01, 0x6B) // posLocal - 1
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(c.prefixFnBaseIdx+fnIdx))
		b = append(b, 0x41, 0x00, 0x4E, 0x0D, 0x00) // result >= 0 → keep the bit
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(^bit))
		b = append(b, 0x71, 0x21, c.lValidMask) // else clear it
		b = append(b, 0x0B)                     // end block $skip_pattern
	}
	return b
}

// bitsInMask is a popcount over the 32 bucket-local pattern bits.
func bitsInMask(m uint32) int {
	n := 0
	for ; m != 0; m &= m - 1 {
		n++
	}
	return n
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
//
// btBucket selects the overflow guard: a Backtracking suffix body can return
// abi.BTStackOverflow instead of a count, and the commit below tests `count !=
// 0` — which -2 passes. Without the guard the total becomes `lBase - 2`, a
// silently corrupted count that the caller reads as a tuple quantity. The
// guard returns it instead, unchanged, so "unknown" reaches the caller as
// "unknown".
func (c *setFindCtx) emitCommit(b []byte, btBucket bool) []byte {
	if btBucket {
		b = append(b, 0x21, c.lTmp) // set (not tee): the guard re-pushes it
		b = append(b, 0x20, c.lTmp)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x48)       // i32.lt_s
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, c.lTmp)
		b = append(b, 0x0F) // return the sentinel unchanged
		b = append(b, 0x0B)
		b = append(b, 0x20, c.lTmp) // restore for the tee below
	}
	b = append(b, 0x22, c.lTmp, 0x04, 0x40) // tee count; if count != 0
	b = append(b, 0x20, c.lStart, 0x21, c.lMinStart)
	b = append(b, 0x20, c.lBase, 0x20, c.lTmp, 0x6A, 0x21, c.lTotal)
	b = append(b, 0x0B)
	return b
}

// emitGateMask folds the gate pre-mask into lValidMask: pattern k stays
// eligible at match start s only while `2s + 1 >= gate[k]`.
//
// This is what collapses the quadratic gate behaviour — a bucket whose
// mask ends up empty is skipped entirely, so no literal check, no prefix DFA
// and no suffix DFA run at that position. The bound used here is the weaker,
// non-empty one; an empty extent needs the stricter `2s >= gate[k]`, which
// only the suffix body can apply because only it knows the extent (see
// emitWriteMatchK's gated branch).
//
// gate[k] is indexed by GLOBAL pattern id, so the byte offset is a
// compile-time constant per pattern and the load needs no arithmetic.
func (c *setFindCtx) emitGateMask(b []byte, bi int, mask uint32) []byte {
	if !c.readsGate() || c.sparseBucket(bi) {
		return b
	}
	// Skip the whole chain where it provably clears nothing (item 22 fix 2b).
	// Wrapping is safe because the chain below contains no branch out of this
	// block — only one `if` per pattern — so nothing inside it depends on the
	// nesting depth.
	shortcut := c.gateMaskCanShortcut(bi, mask)
	if shortcut {
		b = append(b, 0x20, c.lStart, 0x20, c.lAllElig, 0x49) // lStart < lAllElig
		b = append(b, 0x04, 0x40)                             // if: some pattern may be gated off
	}
	first := true
	for k, gid := range c.cs.patternIDs[bi] {
		if k >= bucketMaskBits {
			break
		}
		bit := uint32(1) << uint(k)
		if mask&bit == 0 {
			continue
		}
		if first {
			// 2*lStart + 1 is loop-invariant across the group's patterns, so
			// compute it once into lTmp instead of re-emitting the shift-and-add
			// for each of up to 32 patterns per candidate.
			// lTmp is free here: emitCommit and emitSuffixCall only write it
			// later.
			b = append(b, 0x20, c.lStart, 0x41, 0x01, 0x74, 0x41, 0x01, 0x6A)
			b = append(b, 0x21, c.lTmp)
			first = false
		}
		// if (2*lStart + 1) < gate[gid]: clear bit k
		b = append(b, 0x20, c.lTmp)
		b = c.emitGateValue(b, gid)
		b = append(b, 0x49) // i32.lt_u
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, c.lValidMask, 0x41)
		b = utils.AppendSLEB128(b, int32(^bit))
		b = append(b, 0x71, 0x21, c.lValidMask)
		b = append(b, 0x0B)
	}
	if shortcut {
		b = append(b, 0x0B) // end if
	}
	return b
}

// emitGateValue pushes gate[gid] — from the hoisted local when the body has
// one, otherwise straight from the caller's array.
func (c *setFindCtx) emitGateValue(b []byte, gid int) []byte {
	if c.gateLocalBase != 0 && gid >= 0 && gid < c.cs.idSpaceSize() &&
		int(c.gateLocalBase)+gid < 256 {
		return append(b, 0x20, byte(int(c.gateLocalBase)+gid))
	}
	return append(append(b, 0x20, c.pGate, 0x28, 0x02),
		utils.AppendULEB128(nil, uint32(gid*4))...)
}

// emitGateLocalsPrologue fills the hoisted gate locals, once per call.
func (c *setFindCtx) emitGateLocalsPrologue(b []byte) []byte {
	if c.gateLocalBase == 0 {
		return b
	}
	for gid := 0; gid < c.cs.idSpaceSize(); gid++ {
		if int(c.gateLocalBase)+gid >= 256 {
			break
		}
		b = append(b, 0x20, c.pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4))
		b = append(b, 0x21, byte(int(c.gateLocalBase)+gid))
	}
	return b
}

// gateLocalsProfitable decides AT COMPILE TIME whether hoisting the gate array
// into locals can pay for itself.
//
// The trade is 2 instructions per id per CALL against 1 per pattern per
// CANDIDATE, so it needs a body that evaluates several candidates per call.
// A LITERAL frontend does not: it skips almost every position, so a call
// typically evaluates one candidate and the prologue is pure loss — which is
// the shape of the +5.5% regression the gate jump measured on greedy-3.
// A set with FALLBACK buckets evaluates every position, so one call over a
// non-matching input amortises the prologue across the whole input.
//
// It is ALSO bounded by the id space, and that bound came from measurement
// rather than from the argument above. Candidates-per-call is the gap between
// matches, which is data and not something compile time can know: on a
// match-dense input a call ends at the first position it tries, and the
// prologue is pure loss. classchain-32 (32 ids) measured +1.40% on its dense
// `find` row for exactly that reason, while its no-match row — one call over
// the whole input — was flat. Capping the id space caps the per-call loss in
// absolute terms, which is the only bound available without knowing the input.
//
// Also bounded by the local index space: local indices are emitted as a single
// byte throughout these emitters, so the whole block must sit below 256.
func gateLocalsProfitable(cs *compiledSet, gated bool, localCount int) bool {
	if !gated || !hasSetFallbackBuckets(cs) {
		return false
	}
	n := cs.idSpaceSize()
	return n > 0 && n <= maxHoistedGateLocals && localCount+n < 256
}

// maxHoistedGateLocals bounds F2's per-call prologue. See gateLocalsProfitable.
const maxHoistedGateLocals = 8

// gateGroups is 1 when F2's gate locals are declared, 0 otherwise — the amount
// to add to a body's local-GROUP count.
func gateGroups(n int) byte {
	if n > 0 {
		return 1
	}
	return 0
}

// appendGateLocalGroup appends the trailing i32 group holding F2's gate locals.
func appendGateLocalGroup(b []byte, n int) []byte {
	if n <= 0 {
		return b
	}
	b = utils.AppendULEB128(b, uint32(n))
	return append(b, 0x7F)
}

// sparseBucket reports whether bucket bi carries G17's per-state accept LISTS
// rather than a 32-bit accept mask. Every mask-based shortcut on the candidate
// path has to consult this: the masks are i32s and cannot describe such a
// bucket's patterns, so a shortcut that reads one as authoritative silently
// drops everything past the 32nd pattern.
func (c *setFindCtx) sparseBucket(bi int) bool {
	return bi >= 0 && bi < len(c.cs.buckets) && c.cs.buckets[bi].sparse
}

// emitGateWriteback records the reported matches in the gate array, using
// scratch locals the scan loop has finished with.
//
// Write-back runs ONLY for a fully delivered position: an
// overflowing call must leave the array byte-for-byte as it found it, so that
// the caller's grown retry sees the identical world. The same rule covers the
// out_cap = 0 size probe.
func (c *setFindCtx) emitGateWriteback(b []byte, lPos byte) []byte {
	if !c.gated {
		return b
	}
	// if lTotal > 0 && (batch_mode != 0 || lTotal <= out_cap)
	//
	// The second half is `find`'s transactional rule and the batch loop's
	// absence of one, selected at RUNTIME because both callers share this
	// body (decision (11a)). A non-batching set has no batch_mode parameter
	// and keeps the compile-time form, so its `find` is unchanged.
	b = append(b, 0x20, c.lTotal, 0x41, 0x00, 0x4A) // total > 0 (signed)
	if c.batch && c.gated {
		b = append(b, 0x20, c.pBatchMode)
		b = append(b, 0x20, c.lTotal, 0x20, c.pOutCap, 0x4C) // total <= cap
		b = append(b, 0x72)                                  // i32.or
		b = append(b, 0x71)                                  // i32.and
	} else if !c.batch {
		b = append(b, 0x20, c.lTotal, 0x20, c.pOutCap, 0x4C, 0x71) // && total <= cap
	}
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x41, 0x00, 0x21, lPos)
	b = append(b, 0x02, 0x40)                                   // block $wb_done
	b = append(b, 0x03, 0x40)                                   // loop $wb
	b = append(b, 0x20, lPos, 0x20, c.lTotal, 0x4E, 0x0D, 0x01) // idx >= total → done
	if c.batch {
		// The batch worker gates what it DELIVERED, so the loop also
		// stops at the buffer. An overflowing position leaves the patterns it
		// could not report ungated, and the gate pre-mask lets exactly those
		// match again when the caller resumes at this same position.
		//
		// Unconditional even in `find` mode, where it cannot fire: the guard
		// above has already established total <= cap there, so bounding the
		// loop at cap as well changes nothing and saves a second branch on
		// batch_mode.
		b = append(b, 0x20, lPos, 0x20, c.pOutCap, 0x4E, 0x0D, 0x01) // idx >= cap → done
	}
	b = append(b, 0x20, c.pOutPtr, 0x20, lPos, 0x41, 12, 0x6C, 0x6A, 0x21, c.lOutBase)
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x00, 0x21, c.lTmp)   // id
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x04, 0x21, c.lStart) // start
	b = append(b, 0x20, c.lOutBase, 0x28, 0x02, 0x08, 0x21, c.lBase)  // end
	// gate[id] = 2*end + (end > start ? 1 : 2)   — the biased gate encoding.
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
	b = append(b, 0x0B) // end if
	return b
}

// emitEmptyMaskSkip leaves the enclosing $skip_group block when no pattern of
// the group is eligible, so the group's DFA never runs.
//
// THIS is what collapses the quadratic, and it was missing: emitGateMask
// computed the pre-mask and the body then called the suffix DFA anyway, which
// walked to its full extent only to AND every accept bit with zero. Measured
// on the gate ladder (`a+` over n x "a", gated, driven to exhaustion) the
// terminating call cost 7.8M fuel at n=500 and 1.98B at n=8000 — x4 per
// doubling, textbook O(n^2). An earlier measurement read that as linear because TestGatedLadder
// counted calls rather than work.
//
// It is emitted for every mode, not just the gated one: the valid mask starts
// from the trivial-prefix mask and ORs in only the patterns whose anchor and
// backward-prefix checks pass, so an empty mask is reachable without any gate
// being involved. A suffix call with mask 0 can only return 0 (every accept is
// ANDed with validMask), so skipping it changes nothing but the work done.
func (c *setFindCtx) emitEmptyMaskSkip(b []byte, bi int, mask uint32) []byte {
	// A SPARSE bucket's pre-mask describes at most its first 32 patterns, so an
	// empty mask does NOT mean the group has nothing left to report — patterns
	// 32.. are simply invisible to it. Skipping the group on that lost every
	// pattern past the 32nd once the first 32 had been gated off, which showed
	// up as a gated batch delivering exactly 32 tuples of 40 (the
	// body applies the real per-pattern rule itself, see set_sparse.go's
	// header).
	if c.sparseBucket(bi) {
		return b
	}
	b = append(b, 0x20, c.lValidMask, 0x41)
	b = utils.AppendSLEB128(b, int32(mask))
	b = append(b, 0x71)       // i32.and
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x0D, 0x00) // br_if $skip_group
	return b
}

// scan_all group retirement: MEASURED AND REJECTED.
//
// The original design wanted "retire each pattern once it hits", and an
// earlier note recorded the
// per-bucket-local version as unimplementable (WASM local indices are a single
// byte here, so a large set runs out of slots). A cheaper form does exist —
// test the i64 accumulator against the group's compile-time-constant global
// mask, which needs no local at all — and it was built and measured.
//
// It does not pay. On every narrow row of tools/setperf it cost fuel and saved
// none: keywords-8 dense +48, keywords-32 dense +192, keywords-64 dense +384,
// and nothing anywhere went down. The reason is that emitDrainCheck already
// ends the whole scan once EVERY pattern has been seen, and on these corpora
// the patterns are hit at a similar rate, so that global exit fires before any
// individual group has been exhausted long enough to matter. Group retirement
// would only pay on a skewed corpus where some groups saturate early while
// others never hit — a workload no benchmark here has, and inventing one to
// justify the code would be backwards. CLAUDE.md's Gap I is this lesson.
//
// Recorded rather than silently dropped, so anyone revisiting that
// retirement idea knows it has been tried at this level and what it measured.

// maskCanBeEmpty reports whether `lValidMask & g.mask` can be zero at the
// point just before the prefix DFAs run — i.e. whether the first empty-mask
// skip of emitBucketAt is reachable at all.
//
// Three things can clear bits between emitGroupMask and that point, and if
// none of them applies the mask is a known non-zero constant and the skip is
// dead code:
//
//   - the gate pre-mask, which exists only in the gated `find` body;
//   - a trivial-prefix (L == 0) group whose patterns are all anchored, whose
//     base is then 0 until the position test enables them;
//   - nothing else: a fixed-prefix (L > 0) group starts from the full g.mask
//     by construction (emitGroupMask), and its bits are cleared later, by
//     emitPrefixChecks, which runs after this point.
//
// This matters because the common literal set — every pattern's mandatory
// literal at its own match start, no anchors, a non-gated capability — hits
// the dead case for EVERY group at EVERY candidate. On setperf's keywords-128
// row that was ten wasted instructions per group per candidate.
func (c *setFindCtx) maskCanBeEmpty(bi int, g prefixLenGroup) bool {
	return c.readsGate() || c.maskEmptyFromAnchors(bi, g)
}

// readsGate reports whether this body loads from the gate array at all, and
// is the condition on every per-position gate test.
//
// It is deliberately NOT "does pGate exist": an overlapping body that emits
// no preflight carries the pointer for signature uniformity and must still
// emit no loads, so that every set which gains nothing from the gate slot
// stays byte-identical to before it. That is what the setperf run confirms —
// the 29 overlapping rows without a preflight moved by the one instruction
// that pushes the extra argument, and by nothing else.
func (c *setFindCtx) readsGate() bool { return c.gated || c.preflight }

// maskEmptyFromAnchors reports whether emitGroupMask alone can leave the group
// with no eligible pattern — true only for a trivial-prefix group whose every
// pattern is anchored, where the base mask is 0 until the position test enables
// it. A fixed-prefix group starts from the full g.mask by construction.
func (c *setFindCtx) maskEmptyFromAnchors(bi int, g prefixLenGroup) bool {
	if g.L != 0 {
		return false
	}
	sam := c.cs.startAnchorMasks[bi] & g.mask
	lam := c.cs.lineAnchorMasks[bi] & g.mask
	return g.mask&c.cs.trivialPrefixMasks[bi]&^(sam|lam) == 0
}

// emitGateSkipSingle is the fused gate test for a group holding exactly ONE
// pattern: "is this pattern ineligible here" and "is the group empty" are then
// the same question, so asking it twice — once as a mask edit, once as a mask
// test — is redundant.
//
// The general path computes 2*lStart+1 into a scratch local, compares it
// against the gate, clears the pattern's bit, and then re-reads the mask to
// discover it went to zero. This does the compare once and branches straight
// out, leaving lValidMask at the full g.mask that emitSuffixCall wants.
//
// One-pattern groups are not a corner case: a set of distinct literals gives
// every pattern its own bucket and therefore its own single-pattern group,
// which is the entire keywords-N family in tools/setperf.
//
// Only sound when the mask cannot ALREADY be empty on arrival (anchors), since
// this leaves lValidMask untouched — hence the maskEmptyFromAnchors guard at
// the call site.
func (c *setFindCtx) emitGateSkipSingle(b []byte, bi int, g prefixLenGroup) []byte {
	gid := -1
	for k, id := range c.cs.patternIDs[bi] {
		if k >= bucketMaskBits {
			break
		}
		if g.mask&(uint32(1)<<uint(k)) != 0 {
			gid = id
			break
		}
	}
	if gid < 0 {
		return b
	}
	// if (2*lStart + 1) < gate[gid] → br $skip_group   (pre-mask bound)
	b = append(b, 0x20, c.lStart, 0x41, 0x01, 0x74, 0x41, 0x01, 0x6A)
	b = c.emitGateValue(b, gid)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x0D, 0x00) // br_if $skip_group
	return b
}

// setPatternIDs returns every global pattern id in the set's find buckets,
// ascending and deduplicated.
func setPatternIDs(cs *compiledSet) []int {
	seen := map[int]bool{}
	var out []int
	for _, ids := range cs.patternIDs {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Ints(out)
	return out
}

// jumpIsProfitable decides AT COMPILE TIME whether emitting the gate jump can
// pay for itself.
//
// The jump advances to the MINIMUM next-eligible position over all patterns,
// so it can only fire when EVERY pattern is gated past the cursor. With
// several patterns that is a property of the input rather than of the set:
// patterns that match in turn leave the oldest one's gate behind the cursor
// and the minimum never rises above it. Measured on perftest's
// log-levels-dense (8 keyword patterns, every line a match) the jump never
// fired once, while its O(patterns) prologue cost +6.8% fuel — ~78
// instructions on each of ~1,460 calls.
//
// With ONE pattern there is nobody to pin the minimum. After reporting (s, e)
// the gate gives p_min = e while the caller resumes at from = s+1, so
// the jump fires whenever the match is at least two bytes long, and what it
// skips is the whole match extent. That is precisely the jump's motivating case
// (`a+` over a run of `a`s: 7,999 stepped positions become one leap) and the
// shape re2test's one-pattern-set mode drives over the entire corpus.
//
// The remaining static test is whether a match can exceed one byte at all: a
// pattern that cannot never satisfies e > s+1, so the prologue would be dead
// code. regexpMinMaxLen answers that (maxLen == -1 means unbounded).
//
// Multi-pattern sets were NOT undecidable-so-assume-yes here; they were
// measured-negative — but only on a LITERAL-frontend set. That
// measurement is what task G13 narrows: log-levels-dense costs ~1K
// fuel per call because Teddy skips the whole line, so an O(patterns)
// prologue is +6.8% of a small number. A SCALAR-frontend set has no such
// skip: its calls cost Θ(n) at ~55 fuel per stepped position, against which
// the same prologue is noise — and the terminal call of a gated drive (every
// pattern gated past the cursor, nothing left to find) is exactly the shape
// the jump was designed for. So the static test is: ONE pattern, or a scalar
// frontend.
//
// The maxLen test is unchanged in intent but now quantifies over the whole
// set: if NO pattern can match more than one byte, then after reporting (s,
// s+1) every gate gives p_min = s+1 = from and the jump can never
// fire, so the prologue would be dead code. regexpMinMaxLen answers that
// (maxLen == -1 means unbounded).
// The frontend test comes FIRST because patternFullAST re-parses the pattern:
// a literal-frontend set must reach the same verdict as before G13 without
// paying for a walk it will discard.
func (cs *compiledSet) jumpIsProfitable() bool {
	n := 0
	for _, bkt := range cs.buckets {
		n += len(bkt.patterns)
	}
	if n == 0 || (n > 1 && cs.fe != frontendScalar) {
		return false
	}
	for _, bkt := range cs.buckets {
		for _, p := range bkt.patterns {
			ast := patternFullAST(p)
			if ast == nil {
				continue
			}
			if _, maxLen := regexpMinMaxLen(ast); maxLen < 0 || maxLen >= 2 {
				return true
			}
		}
	}
	return false
}

// emitAllEligibleFrom computes lAllElig = max_k(gate[k]) >> 1 once per call —
// the smallest match start at which the gate pre-mask clears NOTHING.
//
// Pattern k survives the pre-mask at start s while `2s + 1 >= gate[k]`, so
// every pattern survives while `2s + 1 >= max_k gate[k]`, and the smallest
// such s is that maximum shifted right by one — the same algebra emitGateJump
// applies to the MINIMUM, for the opposite purpose. Where the jump asks "can I
// skip this position entirely", this asks "can I skip asking".
//
// It is the mirror of the jump in profitability too. The jump fires only when
// EVERY pattern is gated past the cursor, which one never-matched pattern
// pins at 0 forever; this fires once the cursor passes the FURTHEST gate,
// which a never-matched pattern (gate 0) cannot prevent at all — it only
// lowers the maximum. On a dense drive the gates trail the cursor by at most
// one match extent, so the shortcut is taken at nearly every position after
// the first few of each call.
//
// O(patterns) once per call, replacing O(patterns) at every position it
// covers. Sound to hoist for exactly emitGateJump's reason: the gate array
// cannot change during a call, since write-back runs after the scan loop.
func (c *setFindCtx) emitAllEligibleFrom(b []byte) []byte {
	if !c.anyGroupCanShortcut() {
		// Nothing will read it. Emitting it anyway is not free: the loop is
		// O(patterns) on EVERY call, and a set whose buckets are all G17-sparse
		// suppresses the chain entirely, so the prologue would be pure cost
		// against no saving at all. Measured before this test existed:
		// classchain-128 (four sparse buckets) paid +19.4% on its dense `find`
		// for a shortcut none of its buckets could take.
		return b
	}
	ids := setPatternIDs(c.cs)
	b = append(b, 0x41, 0x00, 0x21, c.lAllElig) // max = 0
	for _, gid := range ids {
		b = append(b, 0x20, c.pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4)) // i32.load offset=gid*4
		b = append(b, 0x22, c.lTmp)               // tee candidate
		b = append(b, 0x20, c.lAllElig, 0x4B)     // candidate > max (unsigned)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, c.lTmp, 0x21, c.lAllElig)
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, c.lAllElig, 0x41, 0x01, 0x76, 0x21, c.lAllElig) // >>= 1
	return b
}

// gateShortcutMinPatterns is how long a gate chain has to be before guarding
// it with the lAllElig compare pays.
//
// The trade is measured, not derived, because the deciding quantity is how
// OFTEN the shortcut fires and that is a property of the input. When it fires
// it saves ~6 fuel per pattern; when it misses it costs ~4, plus the
// prologue's O(patterns) on every call. Both ends were measured on the setperf
// corpus with no threshold at all: 32 patterns in one bucket won 4.5% on
// classchain-32's dense `find`, while THREE patterns lost 5.5% on every
// greedy-3 gated row — the same shape item 11's refutations warn about, a
// per-position test that does not fire often enough to repay itself. 8 sits
// between the measured points, on the winning side of both.
const gateShortcutMinPatterns = 8

// gateMaskCanShortcut reports whether emitGateMask should guard its chain with
// the lAllElig compare for this group: the local must exist, the group must
// actually read gates, and the chain has to be long enough to be worth
// skipping.
func (c *setFindCtx) gateMaskCanShortcut(bi int, mask uint32) bool {
	return c.lAllElig != 0 && c.readsGate() && !c.sparseBucket(bi) &&
		bitsInMask(mask) >= gateShortcutMinPatterns
}

// anyGroupCanShortcut reports whether any group of any bucket will emit the
// shortcut, which is what decides whether lAllElig is worth computing.
func (c *setFindCtx) anyGroupCanShortcut() bool {
	for bi := range c.cs.prefixLenGroups {
		for _, g := range c.cs.prefixLenGroups[bi] {
			if c.gateMaskCanShortcut(bi, g.mask) {
				return true
			}
		}
	}
	return false
}

// emitGateJump advances lPos past every position at which no pattern can
// possibly match — the gate's second optimisation ("jump, don't step"), which was
// never built.
//
// Pattern k's earliest eligible position is the smallest p with
// 2p + 1 >= gate[k], i.e. ceil((gate[k]-1)/2), which for the biased encoding is
// exactly gate[k] >> 1: g = 2e+1 gives e, g = 2e+2 gives e+1, and g <= 1 gives
// 0. Below min_k of that, the pre-mask clears every pattern, so no position
// there can produce output and the scan may skip straight to it.
//
// The whole computation is hoisted to the prologue rather than repeated per
// position, which is sound because the gate array cannot change during a call:
// write-back runs once, after the scan loop has finished (emitGateWriteback).
// So this is O(patterns) once per call, replacing O(patterns) at every skipped
// position. It only fires when EVERY pattern is gated past
// `from` — one never-matched pattern pins the minimum at 0 — which is why the
// mask skip above, not this, is the load-bearing half.
func (c *setFindCtx) emitGateJump(b []byte, lPos byte) []byte {
	// Gated bodies only, and MEASURED so rather than assumed. An overlapping
	// body's gates hold 1 for an alive pattern, so the minimum over
	// `gate[id] >> 1` is 0 the moment anything is alive and the jump can only
	// pay in the all-dead case — where emitEmptyMaskSkip already makes each
	// position nearly free. Emitting it there cost 1.6M fuel on
	// greedy-3 / 50K a's and 119K on the no-match row, and saved nothing.
	if !c.gated {
		return b
	}
	if !c.cs.jumpIsProfitable() {
		return b
	}
	ids := setPatternIDs(c.cs)
	if len(ids) == 0 {
		return b
	}
	// lTmp = min over patterns of (gate[id] >> 1); lStart is free scratch here.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, minStartSentinel)
	b = append(b, 0x21, c.lTmp)
	for _, gid := range ids {
		b = append(b, 0x20, c.pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4)) // i32.load offset=gid*4
		b = append(b, 0x41, 0x01, 0x76)           // i32.shr_u 1
		b = append(b, 0x22, c.lStart)             // tee candidate
		b = append(b, 0x20, c.lTmp, 0x49)         // candidate < min (unsigned)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, c.lStart, 0x21, c.lTmp)
		b = append(b, 0x0B)
	}
	// if lPos < min: lPos = min   (forward only — never rewinds the cursor)
	b = append(b, 0x20, lPos, 0x20, c.lTmp, 0x49)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, c.lTmp, 0x21, lPos)
	b = append(b, 0x0B)
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
	} else if c.cs.suffixHasSkip {
		// Rebase the position-level skip onto this call's tuple index
		// space. lBase tuples are already committed at this position, so a
		// tuple with local index i is position-index lBase+i and must be
		// written when lBase+i >= skip. The suffix compares against `skip -
		// lBase`, signed — negative simply means "write everything".
		//
		// The non-batch `find` body passes 0, which the same comparison reads
		// as "no tuple is skipped": local indices are never negative.
		if c.hasSkip {
			b = append(b, 0x20, c.pSkip, 0x20, c.lBase, 0x6B)
		} else {
			b = append(b, 0x41, 0x00)
		}
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(c.suffixFnBase+bi))
	return b
}

// emitBucketAt emits the complete per-candidate evaluation of bucket bi with
// its mandatory literal at posLocal (litLen == 0 for a fallback bucket, whose
// suffix DFA models the whole pattern anchored at posLocal).
// Order within a group is deliberate: cheap static mask,
// then the two start guards, then the gate pre-mask, then the empty-mask skip
// — and only after all of those, the backward prefix DFA calls, which are the
// expensive part. Each stage can retire the group before the next one runs.
func (c *setFindCtx) emitBucketAt(b []byte, bi, litLen int, posLocal byte) []byte {
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
		b = c.emitGroupMask(b, bi, g, posLocal)
		// First-byte eligibility comes FIRST. Both
		// it and the gate chain only refine lValidMask, so their order is
		// semantics-free — but the costs are not remotely equal. The gate
		// chain unrolls a load and a compare PER PATTERN (~190 fuel at 32
		// patterns), while this is one table lookup that carries its own
		// empty-mask skip, so on the positions it rejects the chain is never
		// reached at all. On classchain-32's dense corpus that is 75% of them.
		b = c.emitStartableMask(b, bi, g, posLocal)
		// Gate test plus the first empty-mask skip. The skip guards the prefix
		// DFAs (the expensive part); the second one below guards the
		// suffix/probe call once those DFAs have had their say. Each is
		// emitted only where it can actually fire — unconditional emission is
		// dead code in the common literal-set shape (see maskCanBeEmpty), and
		// for a single-pattern gated group the two collapse into one branch.
		if c.readsGate() && bitsInMask(g.mask) == 1 && !c.maskEmptyFromAnchors(bi, g) {
			b = c.emitGateSkipSingle(b, bi, g)
		} else {
			if c.mode == capFind {
				b = c.emitGateMask(b, bi, g.mask)
			}
			if c.maskCanBeEmpty(bi, g) {
				b = c.emitEmptyMaskSkip(b, bi, g.mask)
			}
		}
		b = c.emitPrefixChecks(b, bi, g, posLocal)
		if g.L != 0 {
			// Only a fixed-prefix group runs prefix DFAs, so only there can
			// the mask have changed since the check above.
			b = c.emitEmptyMaskSkip(b, bi, g.mask)
		}
		if c.mode == capFind {
			b = c.emitSelectBase(b)
			b = c.emitSuffixCall(b, bi, litLen, posLocal, g.mask)
			b = c.emitCommit(b, bi < len(c.cs.buckets) && c.cs.buckets[bi].btFallback != nil)
		} else {
			b = c.emitProbeCall(b, bi, litLen, posLocal, g.mask)
			b = c.emitRecordProbe(b, bi)
		}
		b = append(b, 0x0B) // end block $skip_group
	}
	return b
}

// emitStartableMask applies bucket bi's first-byte eligibility table:
// a pattern that cannot CONSUME input[posLocal] as its
// first byte cannot match starting there, so its bit is cleared before the
// suffix DFA is called — and when the whole mask goes empty, the call is
// skipped.
//
// Emitted only where the table exists, which is fallback buckets of a scalar
// frontend that had something to clear; every other bucket and every other set
// gets nothing, and stays byte-identical.
//
// Two conditions are load-bearing:
//
//   - L must be 0. The table is indexed by the byte at the MATCH START, and
//     only a trivial-prefix group starts at posLocal; a fixed-prefix group
//     starts L bytes earlier. Fallback buckets have no literal and therefore
//     only L == 0 groups, so this is an assertion rather than a restriction.
//   - posLocal < len must be TESTED. The scan loop processes position len once
//     (for `$`-anchored patterns), where there is no byte to read: loading one
//     anyway would index whatever follows the input and could clear a pattern
//     that genuinely matches empty there.
func (c *setFindCtx) emitStartableMask(b []byte, bi int, g prefixLenGroup, posLocal byte) []byte {
	// Mode-INDEPENDENT. The table says which patterns can BEGIN at a byte,
	// which is as true for a scan as for a find; the gate was a leftover from
	// G16 shipping on the find path first. The remaining
	// conditions are the real ones: L must be 0, and the emission side decides
	// which buckets have a table at all.
	if g.L != 0 {
		return b
	}
	if bi >= len(c.cs.startableOff) || c.cs.startableOff[bi] < 0 {
		return b
	}
	// if posLocal < pInLen { lValidMask &= startable[input[posLocal]] }
	b = append(b, 0x20, posLocal, 0x20, c.pInLen, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)                           // if
	b = append(b, 0x20, c.lValidMask)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, c.cs.startableOff[bi])
	b = append(b, 0x20, c.pInPtr, 0x20, posLocal, 0x6A)
	b = appendInputLoad8u(b)              // the candidate's first byte
	b = append(b, 0x41, 0x02, 0x74, 0x6A) // *4; + table base
	b = appendTableLoad32(b, c.tableMemIdx, 0)
	b = append(b, 0x71, 0x21, c.lValidMask) // i32.and; set
	b = append(b, 0x0B)                     // end if

	// Nothing left to look for at this position.
	b = append(b, 0x20, c.lValidMask, 0x45, 0x0D, 0x00) // eqz; br_if $skip_group
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
	b = utils.AppendULEB128(b, uint32(c.probeIndex(bi)))
	b = append(b, 0x21, c.lTmp)
	b = c.emitProbeOverflowEscape(b, bi)
	return b
}

// emitProbeOverflowEscape returns abi.BTStackOverflow out of the whole
// capability the moment a Backtracking probe reports it.
//
// Returning IMMEDIATELY is the point. A probe that gave up has not proved a
// non-match, so folding its answer into the accumulator — an id, a boolean, a
// bitmap bit — would publish "no" for a question the engine never answered.
// There is nothing to salvage from the rest of the scan either: any later
// position could have been the one this pattern matched at.
//
// Emitted ONLY for BT buckets. Every other probe is table-driven and always
// terminates with a definite answer, so for them this would be dead code on
// the hot path.
//
// The return type is i32 for every mode that can reach here: `scan` and
// `scan_any` are i32 already, and `scan_all` is in its out_ptr form because
// wideAll() is forced true by hasBTMember() — which is exactly why decision 3
// requires that form. A narrow scan_all would need an i64 here and have no
// value free to carry.
func (c *setFindCtx) emitProbeOverflowEscape(b []byte, bi int) []byte {
	if bi >= len(c.cs.buckets) || c.cs.buckets[bi].btFallback == nil {
		return b
	}
	b = append(b, 0x20, c.lTmp)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
	b = append(b, 0x0F) // return
	b = append(b, 0x0B)
	return b
}

// emitRecordProbe folds a probe result into the mode's answer.
//
// Nothing here branches out of the loop: the exit is the drain check at the
// top of the next iteration (emitDrainCheck), which is mode-aware. That keeps
// this emitter free of the br-depth bookkeeping the four frontends would
// otherwise each need their own version of.
func (c *setFindCtx) emitRecordProbe(b []byte, bi int) []byte {
	if bi < len(c.cs.buckets) && c.cs.buckets[bi].sparse {
		return c.emitRecordSparseProbe(b, bi)
	}
	switch c.mode {
	case capScanAny:
		// One arbitrary id matching anywhere at or after `from`. `scan_any`
		// reports no start, so there is nothing
		// to improve on once an id is recorded and no reason to keep looking
		// for an earlier candidate — the drain check exits at the first hit,
		// exactly as `scan`'s does. No escape depth: leaving the loop is that
		// check's job, which keeps this emitter free of each frontend's
		// br-depth bookkeeping.
		b = append(b, 0x20, c.lTmp, 0x04, 0x40)
		b = emitSetAnyID(b, c.cs.patternIDs[bi], c.lTmp, c.lOutBase, -1)
		b = append(b, 0x0B)
		return b
	default: // capScanAll
		return emitSetAllBits(b, c.cs.patternIDs[bi], c.lTmp, c.wideBitmap,
			c.pOutPtr, c.lTotal, c.lAcc)
	}
}

// emitRecordSparseProbe folds a SPARSE bucket's probe result into the mode's
// answer.
//
// A sparse probe cannot return a bucket-local bitmask — that is the 32-pattern
// ceiling it exists to escape — so it returns a COUNT and leaves the matching
// BUCKET-LOCAL indices in the bucket's scratch, which the code below maps to
// global ids through sparseIDMapOff.
//
// What makes this simpler than the bitmask path is that it is a LOOP rather
// than a compile-time unrolled chain — not that the mapping is absent. The
// comment here used to say the ids "are already global, no mapping to unroll",
// which a reader simplifying per the comment would act on by writing ids in
// the wrong space, straight into the caller's arrays.
func (c *setFindCtx) emitRecordSparseProbe(b []byte, bi int) []byte {
	sc := c.cs.buckets[bi].sparseScratch
	switch c.mode {
	case capScanAny:
		// Which id is unspecified, so the first collected one will do.
		b = append(b, 0x20, c.lTmp, 0x04, 0x40)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, c.cs.buckets[bi].sparseIDMapOff)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, sc.endPos)
		b = appendTableLoad32(b, c.cs.tableMemIdx, 0)
		b = append(b, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, c.cs.tableMemIdx, 0)
		b = append(b, 0x21, c.lOutBase)
		b = append(b, 0x0B)
		return b
	default: // capScanAll
		// Walk the collected ids, setting each one's bit. lTmp is the count.
		//
		// Only two locals are borrowed — lStart as the index and lBase as the
		// id — both dead in scan mode once the probe has been recorded, and
		// both recomputed by the next group. The bitmap update itself is
		// stack-only, recomputing the byte address rather than holding it, so
		// this needs no local of its own.
		b = append(b, 0x41, 0x00, 0x21, c.lStart)
		b = append(b, 0x02, 0x40)
		b = append(b, 0x20, c.lTmp, 0x45, 0x0D, 0x00)
		b = append(b, 0x03, 0x40)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, c.cs.buckets[bi].sparseIDMapOff)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, sc.endPos)
		b = append(b, 0x20, c.lStart, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, c.cs.tableMemIdx, 0)
		b = append(b, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, c.cs.tableMemIdx, 0)
		b = append(b, 0x21, c.lBase) // the global id
		if c.wideBitmap {
			b = emitWideBitmapSet(b, c.pOutPtr, c.lBase, c.lTotal)
		} else {
			b = emitAccOrID(b, c.lAcc, c.lBase)
		}
		b = append(b, 0x20, c.lStart, 0x41, 0x01, 0x6A, 0x21, c.lStart)
		b = append(b, 0x20, c.lStart, 0x20, c.lTmp, 0x49, 0x0D, 0x00)
		b = append(b, 0x0B)
		b = append(b, 0x0B)
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
	b = c.emitGateJump(b, lPos)
	b = c.emitAllEligibleFrom(b)
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
	case capScanAny:
		// A bare pattern id, or -1. lOutBase is
		// initialised to -1 and only ever written with a real id, so it IS
		// the answer.
		return append(b, 0x20, c.lOutBase)
	case capScanAll:
		if c.wideBitmap {
			return append(b, 0x20, c.lTotal)
		}
		return append(b, 0x20, c.lAcc)
	default:
		return append(b, 0x20, c.lTotal)
	}
}

// emitDrainCheck emits the drain test as a br_if to the given depth: once
// no remaining candidate can produce a start at or before lMinStart, the scan
// is finished.
func (c *setFindCtx) emitDrainCheck(b []byte, lPos byte, depth byte) []byte {
	switch c.mode {
	case capScanAny:
		// Settled by the first hit for the same reason, now that no start is
		// reported: any recorded id is a final answer. lOutBase is -1 until
		// one is recorded, so "id >= 0" is the test.
		return append(b, 0x20, c.lOutBase, 0x41, 0x00, 0x4E, 0x0D, depth)
	case capScanAll:
		// No first-position notion at all: scan_all asks which patterns match
		// ANYWHERE at or after `from`, so the only early exit is "every
		// pattern has already been seen".
		if c.wideBitmap {
			// lTotal counts DISTINCT patterns seen, so the bound is how many
			// patterns the set has — not the id space. Comparing against the
			// id bound made this exit unreachable for any set whose ids are
			// sparse.
			b = append(b, 0x20, c.lTotal, 0x41)
			b = utils.AppendSLEB128(b, int32(c.cs.numPatterns()))
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

// emitLiteralBuckets emits the per-position literal check and bucket
// evaluation for every literal bucket, shortest literal first.
//
// Shared by the Scalar and Shufti bodies, which held identical copies — the
// same bound check, the same per-byte compare chain, the same emitBucketAt
// call. The Teddy and AC bodies do not use it: their
// frontends already identify WHICH literal fired, so they dispatch straight to
// that literal's buckets instead of re-testing all of them.
// firstByteLocal is 0 when the caller has no local to hoist input[lPos] into.
// Local index 0 is always a PARAMETER (pInPtr), so it can never name a real
// scratch local and doubles as the "not offered" signal.
const noFirstByteLocal = byte(0)

// minHoistedLiteralBuckets is how many literal buckets must share a position
// before hoisting its first byte is worth the guarded load and select. Below
// it the hoist is pure overhead — see emitLiteralBucketsHoisted.
const minHoistedLiteralBuckets = 4

func (c *setFindCtx) emitLiteralBuckets(b []byte, lPos byte) []byte {
	return c.emitLiteralBucketsHoisted(b, lPos, noFirstByteLocal)
}

// emitLiteralBucketsHoisted is emitLiteralBuckets with the option of loading
// input[lPos] ONCE per position into firstByteLocal instead of once per bucket.
//
// Every bucket's first compare reads the same byte. An AC-demoted scalar set
// carries dozens to hundreds of buckets, so that is N loads of one byte at
// every position — and the load is the whole cost of the compare for the
// buckets that do not match, which is nearly all of them. Bytes at li >= 1 are
// still loaded per bucket: they differ by literal length and are only reached
// once the first byte has already matched.
//
// The hoisted load must be GUARDED by lPos < len: the scan loop visits
// position len itself (for `$`-anchored patterns), where there is no byte to
// read. The per-bucket fit test below would have rejected every bucket there
// anyway, which is why the unhoisted form needs no guard.
func (c *setFindCtx) emitLiteralBucketsHoisted(b []byte, lPos, firstByteLocal byte) []byte {
	// PROFITABILITY. The hoist trades N per-bucket loads for one guarded load
	// plus a select, so it pays only once several buckets share the position.
	// Measured: applying it unconditionally cost classchain and greedy-3
	// between +1.6% and +10.5% fuel — those sets have NO literal buckets at
	// all, so the hoisted load ran at every position for nothing.
	if len(litOrderFor(c.cs)) < minHoistedLiteralBuckets {
		firstByteLocal = noFirstByteLocal
	}
	if firstByteLocal != noFirstByteLocal {
		// firstByte = lPos < len ? input[lPos] : -1   (-1 matches no literal)
		b = append(b, 0x20, lPos, 0x20, c.pInLen, 0x49) // i32.lt_u
		b = append(b, 0x04, 0x7F)                       // if (result i32)
		b = append(b, 0x20, c.pInPtr, 0x20, lPos, 0x6A)
		b = appendInputLoad8u(b)
		b = append(b, 0x05)       // else
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0B)       // end if
		b = append(b, 0x21, firstByteLocal)
	}
	for _, bi := range litOrderFor(c.cs) {
		lit := []byte(c.cs.buckets[bi].literal)
		litLen := len(lit)

		b = append(b, 0x02, 0x40) // block $skip_bucket
		// The literal must fit in what is left of the input.
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, c.pInLen, 0x4B, 0x0D, 0x00)

		for li, lb := range lit {
			if li == 0 && firstByteLocal != noFirstByteLocal {
				b = append(b, 0x20, firstByteLocal)
			} else {
				b = append(b, 0x20, c.pInPtr, 0x20, lPos, 0x6A)
				if li > 0 {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(li))
					b = append(b, 0x6A)
				}
				b = appendInputLoad8u(b)
			}
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00) // ne → skip this bucket
		}

		b = c.emitBucketAt(b, bi, litLen, lPos)

		b = append(b, 0x0B) // end block $skip_bucket
	}
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
// probeIndex is the function index of the probe bucket bi should call.
//
// `scan` and `scan_any` take the first-hit-exit body where the bucket has one;
// `scan_all` always takes the ordinary mask-complete body, because its answer
// is the full bitmask at this position and an early exit would drop bits.
// Single-pattern buckets have no separate body — their mask-complete test
// already fires at the first bit — so both callers share one probe.
func (c *setFindCtx) probeIndex(bi int) int {
	if c.useAnyProbe && bi < len(c.cs.anyProbeIdx) && c.cs.anyProbeIdx[bi] >= 0 {
		return c.anyProbeBase + c.cs.anyProbeIdx[bi]
	}
	return c.probeFnBase + bi
}

func newSetFindCtx(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, drainSlack int, mode setCapKind, probeFnBase int) *setFindCtx {
	gated := mode == capFind && cs.gatedFind()
	batch := mode == capFind && cs.batchPos
	// Only the ungated batch worker needs an explicit skip; see setFindCtx.
	hasSkip := batch && !gated
	c := &setFindCtx{
		cs: cs, suffixFnBase: suffixFnBase, prefixFnBaseIdx: prefixFnBaseIdx,
		mode: mode, probeFnBase: probeFnBase,
		// probeFnBase is the scan-probe base; the first-hit bodies follow the
		// ordinary ones, so their base is that plus however many there are.
		anyProbeBase: probeFnBase + len(cs.scanProbeBodies),
		useAnyProbe:  mode == capScanAny,
		maxLookback:  cs.maxLookback, drainSlack: drainSlack,
		gated:   gated,
		batch:   batch,
		hasSkip: hasSkip,
		pInPtr:  0, pInLen: 1, pFrom: 2,
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
	default:
		// Both `find` flavours: (ptr, len, from, gate, out, cap).
		c.pGate, c.pOutPtr, c.pOutCap = 3, 4, 5
		c.localBase = 6
		switch {
		case batch && gated:
			// The shared worker's trailing argument: 0 = `find`'s
			// transactional gate rule, non-zero = the batch deliver-and-gate.
			c.pBatchMode = 6
			c.localBase = 7
		case hasSkip:
			c.pSkip = 6
			c.localBase = 7
		}
		c.preflight = !gated && cs.usesOverlappingFindPreflight()
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
