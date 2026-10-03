package compile

import (
	"fmt"
	"regexp/syntax"
	"slices"

	"github.com/qrdl/regexped/config"
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
// transition and bitmask tables the ordinary body reads. The only tables it
// adds are the column's projection table and a one-byte-per-state successor
// scratch; the automaton itself is the forward body's, which is the reason a
// second implementation of the per-position semantics is defensible at all.
//
// WHY STAGE B FAILED, AND WHAT CHANGED. Stage B computed that sweep inside ONE
// call and could deliver only if the WHOLE answer fitted the caller's buffer.
// For the shape it targets that is unreachable, and the reason is structural:
// a never-dying pattern that matches anywhere matches from almost every start
// position, so the answer is Theta(n) tuples and no fixed buffer holds it. The
// counting pass then ran, decided it could not deliver, and the ordinary loop
// did the work anyway — measured at a 19.6x REGRESSION, and reverted.
//
// Stage C removes the fits-entirely restriction by making the sweep RESUMABLE
// through CALLER-OWNED memory. That is the move the empty-match rule already
// made once: the module may not own state across calls, and gates got past it
// by making the state the caller's.
//
// WHAT THE CALLER'S REGION HOLDS, and it is not the tuples. Keeping every tuple
// made the region linear in the input — 117 MB for 32 patterns over 400 KB —
// which is unreasonable to reserve invisibly. It holds CHECKPOINTS instead: a
// column snapshot every `stride` positions, and one materialised block of rows.
// A block is rebuilt from the checkpoint below it when a call needs it, so the
// region is the square root of the input and every position is swept at most
// TWICE. See set_overlap_ckpt.go, which is where that lives.
//
// The objection to checkpointing was that a drive at capacity 1 would re-sweep
// up to `stride` positions PER CALL and so re-sweep the input Theta(n) times.
// It does not: a block is materialised ONCE and then served out of, which
// `curBlock` in the header is what makes true across calls. Below
// config.SetOverlapCacheMaxBytes the stride is the whole span, which is one
// block — byte for byte the whole-drive behaviour, one sweep and no re-sweep at
// all — so the second sweep is bought only when the region would otherwise be
// too large.
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

	// The boundary channels, as the forward body reads them: the start state
	// a position gets from the byte before it (emitSetEntryState), and the
	// accepts a state makes before a word byte, a non-word byte or a '\n'
	// (emitWBCheck, emitNLCheck), as VALUES for the unrolled column. nil
	// masks mean the automaton has no such channel.
	wasmMidStartWord, wasmMidStartNewline uint32
	wordCharTableOff                      int32
	wMasks, nwMasks, nlMasks              []uint64
	// The DOMINANT subsets of wMasks / nwMasks: a boundary accept that is the
	// leftmost-first winner and no later accept may replace. They are ONE
	// flag per state, not per pattern (markDominant is single-pattern), so,
	// like the forward body, the sweep reads them only when the automaton
	// holds one pattern.
	wDomMasks, nwDomMasks []uint64

	// dominant records that the forward body has bulk-skip states. The sweep
	// does NOT use them — it visits every position regardless — but their
	// presence means the forward body's per-position cost is not the sweep's,
	// which matters when comparing the two.
	dominant bool

	// wide is an automaton of MORE than 64 patterns' accepts, one bitset of
	// ⌈n/64⌉ words per WASM state per channel (wideMid … wideNL), from the
	// per-state lists the wide construction records. nil below 65 patterns,
	// where the u64 masks above are the whole story. Above it those masks say
	// nothing — the wide construction degrades every one to bit 0 — so every
	// compile-time reader asks through the *Has methods, and the sweep's
	// runtime-table tier, which reads the u64 tables, is never chosen.
	wide [wideChannels][][]uint64
}

// The wide channels, in overlapDPTables.wide.
const (
	wideMid = iota
	wideEOF
	wideW
	wideNW
	wideNL
	wideChannels
)

// isWide reports an automaton of more than 64 patterns.
func (dp *overlapDPTables) isWide() bool { return dp.wide[wideMid] != nil }

// has reports pattern pat's bit in WASM state w's accepts on one channel: the
// u64 mask below 65 patterns, the wide bitset above. A channel the automaton
// does not have accepts nothing.
func (dp *overlapDPTables) has(ch int, narrow []uint64, w, pat int) bool {
	if dp.isWide() {
		// A word past the bitset is a pattern no state accepts (an
		// unsatisfiable member), not an error.
		m := dp.wide[ch]
		return m != nil && pat/64 < len(m[w]) && m[w][pat/64]>>uint(pat%64)&1 != 0
	}
	return narrow != nil && pat < 64 && narrow[w]>>uint(pat)&1 != 0
}

func (dp *overlapDPTables) midHas(w, pat int) bool { return dp.has(wideMid, dp.midMasks, w, pat) }
func (dp *overlapDPTables) eofHas(w, pat int) bool { return dp.has(wideEOF, dp.eofMasks, w, pat) }
func (dp *overlapDPTables) wHas(w, pat int) bool   { return dp.has(wideW, dp.wMasks, w, pat) }
func (dp *overlapDPTables) nwHas(w, pat int) bool  { return dp.has(wideNW, dp.nwMasks, w, pat) }
func (dp *overlapDPTables) nlHas(w, pat int) bool  { return dp.has(wideNL, dp.nlMasks, w, pat) }

// wDomHas / nwDomHas: the dominant flags, which are one per STATE and so mean
// anything only for a one-pattern automaton — the only kind the sweep reads
// them for. Never wide.
func (dp *overlapDPTables) wDomHas(w int) bool { return dp.wDomMasks != nil && dp.wDomMasks[w]&1 != 0 }
func (dp *overlapDPTables) nwDomHas(w int) bool {
	return dp.nwDomMasks != nil && dp.nwDomMasks[w]&1 != 0
}

// wideBits turns a channel's per-state accept LISTS (table state gs at WASM
// state gs+1) into one bitset of `words` words per WASM state. A nil map
// accepts nothing: all-zero bitsets, never nil, since a nil mid channel would
// read as "not wide".
func wideBits(m map[int][]uint16, numWASM, words int) [][]uint64 {
	out := make([][]uint64, numWASM)
	for i := range out {
		out[i] = make([]uint64, words)
	}
	for gs, l := range m {
		for _, p := range l {
			out[gs+1][int(p)/64] |= uint64(1) << uint(int(p)%64)
		}
	}
	return out
}

// stateMaskBytes encodes a per-state accept map as the 8-byte-per-state table
// the set bodies read, WASM state gs+1 at (gs+1)*8.
func stateMaskBytes(m map[int]uint64, numWASM int) []byte {
	bs := make([]byte, numWASM*8)
	for gs, bits := range m {
		if bits != 0 {
			off := (gs + 1) * 8
			for i := 0; i < 8; i++ {
				bs[off+i] = byte(bits >> uint(i*8))
			}
		}
	}
	return bs
}

// stateMaskValues decodes stateMaskBytes' table back into one value per WASM
// state. The sweep's values are DERIVED FROM THE EMITTED BYTES rather than
// re-walking the map, so "computed on the same table the body reads" holds by
// construction.
func stateMaskValues(bs []byte, numWASM int) []uint64 {
	out := make([]uint64, numWASM)
	for w := range out {
		var v uint64
		for i := 0; i < 8; i++ {
			v |= uint64(bs[w*8+i]) << uint(i*8)
		}
		out[w] = v
	}
	return out
}

// fillSweepBoundary copies the boundary channels of t — as the forward body
// reads them — into dp, whose hasWordChar / hasNewlineBoundary are already set.
func fillSweepBoundary(dp *overlapDPTables, t *dfaTable, l *dfaLayout) {
	vals := func(m map[int]uint64) []uint64 { return stateMaskValues(stateMaskBytes(m, l.numWASM), l.numWASM) }
	dp.wasmMidStartNewline = uint32(t.midStartNewlineState + 1) //nolint:gosec // a state id
	if dp.hasWordChar {
		dp.wasmMidStartWord = l.wasmMidStartWord
		dp.wordCharTableOff = l.wordCharTableOff
		dp.wMasks, dp.nwMasks = vals(t.midAcceptWStates), vals(t.midAcceptNWStates)
		dp.wDomMasks, dp.nwDomMasks = vals(t.midAcceptWStatesDominant), vals(t.midAcceptNWStatesDominant)
	}
	if dp.hasNewlineBoundary {
		dp.nlMasks = vals(t.midAcceptNLStates)
	}
	if t.acceptWide == nil && t.midAcceptWide == nil {
		return
	}
	// A wide automaton: its lists, as bitsets, on the channels it has.
	words := max((wideTablePatterns(t)+63)/64, 1)
	dp.wide[wideMid] = wideBits(t.midAcceptWide, l.numWASM, words)
	dp.wide[wideEOF] = wideBits(t.acceptWide, l.numWASM, words)
	if dp.hasWordChar {
		dp.wide[wideW] = wideBits(t.midAcceptWWide, l.numWASM, words)
		dp.wide[wideNW] = wideBits(t.midAcceptNWWide, l.numWASM, words)
	}
	if dp.hasNewlineBoundary {
		dp.wide[wideNL] = wideBits(t.midAcceptNLWide, l.numWASM, words)
	}
}

// wideTablePatterns is one past the highest pattern index a wide table's
// accept lists name.
func wideTablePatterns(t *dfaTable) int {
	n := 0
	for _, m := range t.wideMaps() {
		for _, l := range *m {
			for _, p := range l {
				n = max(n, int(p)+1)
			}
		}
	}
	return n
}

// genSweepTables lays out a WHOLE-SET automaton's tables for the sweep alone:
// the transition layout and the two accept tables genSuffixWASM places for a
// fallback bucket over the same automaton, and no forward body — the walk keeps
// the set's own buckets.
func genSweepTables(t *dfaTable, tableBase int64) (dp overlapDPTables, dataBytes []byte, dataSegCount int, next int32) {
	l := buildDFALayout(dfaLayoutParams{
		t:             t,
		tableBase:     tableBase,
		leftmostFirst: true,
		forceWordChar: t.hasWordBoundary,
	})
	midOff := int32(l.tableEnd)
	eofOff := midOff + int32(l.numWASM)*8
	raw, cnt := stripSegCount(dfaDataSegments(l, false, false))
	mid := stateMaskBytes(t.midAcceptStates, l.numWASM)
	eof := stateMaskBytes(t.acceptStates, l.numWASM)
	dataBytes = append(dataBytes, raw...)
	dataBytes = append(dataBytes, appendDataSegment(nil, midOff, mid)...)
	dataBytes = append(dataBytes, appendDataSegment(nil, eofOff, eof)...)
	dp = overlapDPTables{
		ok:                 true,
		l:                  l,
		midMasks:           stateMaskValues(mid, l.numWASM),
		eofMasks:           stateMaskValues(eof, l.numWASM),
		midBitmaskOff:      midOff,
		eofBitmaskOff:      eofOff,
		numWASM:            l.numWASM,
		wasmStart:          uint32(t.startState + 1),    //nolint:gosec // a state id
		wasmMidStart:       uint32(t.midStartState + 1), //nolint:gosec // a state id
		hasWordChar:        t.hasWordBoundary && l.needWordCharTable,
		hasNewlineBoundary: t.hasNewlineBoundary,
	}
	fillSweepBoundary(&dp, t, l)
	return dp, dataBytes, cnt + 2, eofOff + int32(l.numWASM)*8
}

// overlapDPMaxColumn bounds the UNPROJECTED column, states x patterns, which is
// what the eligibility gate measures and what two working columns cost in
// module scratch.
//
// It is not the per-position work any more. Lever C narrows the column to one
// cell per projection, so a position costs `numStates` successor lookups plus
// `cells` updates — see overlapSweepCostPerByte, which is what the adaptive
// trigger uses. Bounding the unprojected width is still the right gate: the
// projection is computed after the automaton is built, and a set that would
// need a 16 KB column before projection is one this whole path declines.
const overlapDPMaxColumn = 4096

// overlapProjMaxCells bounds the PROJECTED column: the projection table stores
// each cell's byte offset in a u16.
const overlapProjMaxCells = 0xFFFF / 4

// overlapSweep is what the answer cache's sweep runs over: an automaton's
// geometry, the global id each of its pattern bits stands for, and the
// column's projection (nil: one cell per (state, pattern)).
type overlapSweep struct {
	dp   overlapDPTables
	ids  []int
	proj *overlapProj
	// wholeSet marks the set's own whole-set automaton (planWholeSetSweep),
	// as opposed to bucket 0's.
	wholeSet bool
}

// usesOverlapDP reports whether this set's `find` carries the sweep.
//
// BOTH position-reporting entries, since 2026-09-11: the cache logic is common
// code and `find` calls it, so the sweep is emitted for any overlapping set
// whose shape qualifies rather than only for one that asked for batching.
func (cs *compiledSet) usesOverlapDP() bool { return cs.sweepSrc() != nil }

// sweepSrc returns what this set's sweep runs over, or nil, resolving it once.
//
// Cached because every reader — the column sizing, the emitted projection
// table, the sweep bodies, the serving geometry, every stub's region
// arithmetic — must see the SAME answer; a second resolution that decided
// differently would size a column one way and index it another. Valid only
// once compileSetWith has built the buckets, which is the only place a
// compiledSet is made.
func (cs *compiledSet) sweepSrc() *overlapSweep {
	if cs.sweepDone {
		return cs.sweep
	}
	cs.sweepDone = true
	// The sweep only ever runs on an OVERLAPPING set: it enumerates every
	// start position, which is that policy's contract and nobody else's.
	//
	// `hints: [batch-find]` is NOT required. It used to be, because the code
	// that reads a cache lived inside the batching loop; that code is now
	// shared and `find` calls it too, so requiring the hint would be requiring
	// a second entry point nobody asked for in order to make the first one
	// linear.
	if cs.find == "" || !cs.overlapping || cs.noSweep {
		return nil
	}
	if cs.wholeSweep != nil {
		cs.sweep = cs.wholeSweep
		return cs.sweep
	}
	bi := cs.overlapDPBucket()
	if bi < 0 {
		return nil
	}
	bkt := cs.buckets[bi]
	cs.sweep = vetSweep(&overlapSweep{dp: bkt.dp, ids: cs.patternIDs[bi]},
		func() bool { return dfaWalksNest(bkt.suffixDFA) })
	return cs.sweep
}

// overlapDPBucket returns 0 when the set is ONE bucket the sweep can run over
// directly — its own automaton, read through the forward body's own tables —
// or -1. The table-level limits are vetSweep's.
//
// Every restriction here exists to keep ONE reimplementation of the
// per-position semantics defensible. The sweep reproduces buildSetSuffixBody's
// stopping rule exactly; each shape it refuses is one whose rule it would have
// to reproduce a SECOND time, and a second copy of a semantics is how an
// earlier copy diverged.
func (cs *compiledSet) overlapDPBucket() int {
	// ONE bucket. With several, a position's tuples come from several DFAs,
	// and the sweep runs over the set's whole-set automaton instead
	// (planWholeSetSweep).
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
	// literal case was the gap. Such a set is swept over its whole-set
	// automaton now, which models the literal.
	if !bkt.isFallback {
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
	return 0
}

// vetSweep applies the table-level limits to a candidate sweep and fills in its
// projection, or returns nil.
//
// TWO tiers. Inside the original limits — u8 state ids, no word-boundary or
// newline channel, an unprojected column within overlapDPMaxColumn — a sweep
// is built exactly as it always was, projected only where that narrows the
// column. Past them — 16-bit ids, a boundary channel, a wider column — the
// column is ALWAYS projected, since the projected step is the one that carries
// those, and only where walks can nest (nests, asked lazily: dfaWalksNest): a
// set whose overlapping drive is linear without a cache keeps its module
// unchanged.
func vetSweep(sw *overlapSweep, nests func() bool) *overlapSweep {
	dp, n := sw.dp, len(sw.ids)
	if !dp.ok || dp.l == nil || dp.numWASM < 2 {
		return nil
	}
	// A block row's mask is as wide as the sweep (config.SetOverlapRowMaskBytes),
	// so the pattern count itself is no limit. The AUTOMATON's is: its u64
	// accept masks hold 64 patterns, so a sweep over more must come from the
	// wide construction, whose per-state lists every compile-time reader then
	// uses. One that does not would lose its high patterns from every row,
	// silently.
	if n == 0 || (n > 64 && !dp.isWide()) {
		return nil
	}
	// numWASM <= 255 is the condition the layout itself uses to pick u8, but
	// assert the flag rather than infer it: they are two decisions and only one
	// is ours. A WIDE automaton (more than 64 patterns) is never original: that
	// tier reads the u64 accept tables at run time, and on a wide automaton
	// they carry no per-pattern bits.
	original := dp.l.useU8 && dp.numWASM <= 255 && !dp.hasWordChar && !dp.hasNewlineBoundary && !dp.isWide()
	if original && dp.numWASM*n <= overlapDPMaxColumn {
		sw.proj = buildOverlapProj(dp, n, false)
		return sw
	}
	if !nests() {
		return nil
	}
	sw.proj = buildOverlapProj(dp, n, true)
	if sw.proj == nil || sw.proj.cells > overlapProjMaxCells {
		return nil
	}
	return sw
}

// wholeSetPlan is a set's whole-set automaton, decided before its buckets'
// bodies are emitted: they must know whether to stamp how far they walked.
type wholeSetPlan struct {
	t   *dfaTable
	ids []int // the global id of each pattern bit
}

// planWholeSetSweep decides whether an overlapping set the sweep cannot run over
// directly — several buckets, or a literal one — is swept over a WHOLE-SET
// automaton: every member's full pattern merged, as a fallback bucket merges
// its members, beside the buckets the walk keeps. nil when it is not.
//
// This is the one sweep that does NOT read the forward body's own tables, so
// its answers agree with the walk's only where the two automata agree. Every
// refusal below is a member whose semantics the merge does not keep:
//
//   - a Backtracking member has no DFA at all;
//   - a NON-GREEDY member is isolated in a bucket of its own precisely because
//     merging it contaminates the merged automaton's other patterns
//     (analyzePattern);
//   - a boundary-ambiguous one is on Backtracking already;
//   - a member whose DOMINANT boundary accept decides an answer, in a set of
//     several: the dominant tables are one flag per state, which the sweep
//     reads only for a one-pattern automaton — as the forward body does for a
//     one-pattern bucket — so a member the walk serves alone, dominance and
//     all, would be answered without it (dominanceDecides).
//
// And, as vetSweep asks of every sweep past the original limits, the walks must
// be able to nest (dfaWalksNest): a set whose overlapping drive is linear
// without a cache keeps its module unchanged.
//
// Not for a SPLIT compile (split): its `find` is the merge wrapper, which calls
// the bucket body directly and never reads a cache. Such a set was split
// because its trial compile — this same plan — was refused.
func planWholeSetSweep(spec SetSpec, buckets []*bucket, patternIDs [][]int, opts CompileSetOptions, noSweep, split bool) *wholeSetPlan {
	if spec.Find == "" || !spec.Overlapping || noSweep || split || len(buckets) == 0 {
		return nil
	}
	if b := buckets[0]; len(buckets) == 1 && b.isFallback && !b.sparse && b.btFallback == nil {
		return nil // swept directly, over its own tables
	}
	var asts []*syntax.Regexp
	var ids []int
	for bi, bkt := range buckets {
		if bkt.btFallback != nil {
			return nil
		}
		for j, p := range bkt.patterns {
			if p.isolatedFallback || p.boundaryAmbiguous {
				return nil
			}
			re := fullPatternAST(p)
			if re == nil {
				return nil
			}
			asts = append(asts, re)
			ids = append(ids, patternIDs[bi][j])
		}
	}
	if len(asts) == 0 {
		return nil
	}
	// The automaton's accept form follows its width: the bucket's own u32
	// masks up to 32 members (the merge a fallback bucket makes, so a set
	// that always qualified builds exactly what it did), u64 masks up to 64,
	// and per-state lists above — the sparse construction, the only one with
	// no ceiling.
	var t *dfaTable
	var err error
	switch {
	case len(asts) <= bucketMaskBits:
		t, _, err = mergeSuffixDFA(asts, opts)
	case len(asts) <= 64:
		t, err = mergeSuffixDFAWidth(asts, 64)
	default:
		t, _, err = mergeSuffixDFASparseSet(asts, opts)
	}
	if err != nil || t.numStates > opts.maxFallbackStates() || !dfaWalksNest(t) {
		return nil
	}
	if len(asts) > 1 {
		for _, re := range asts {
			one, _, err := mergeSuffixDFA([]*syntax.Regexp{re}, opts)
			if err != nil || dominanceDecides(one) {
				return nil
			}
		}
	}
	// The table-level limits, on a trial layout: only the offsets differ at the
	// real base, and vetSweep reads none of them.
	dp, _, _, _ := genSweepTables(t, 0)
	if vetSweep(&overlapSweep{dp: dp, ids: ids}, func() bool { return true }) == nil {
		return nil
	}
	return &wholeSetPlan{t: t, ids: ids}
}

// dominanceDecides reports whether a dominant boundary accept of t decides an
// answer: whether a walk that took the boundary's byte out of a W-dominant (or
// NW-dominant) state can still accept afterwards. Only then would a later
// accept replace the dominant one if the dominance were ignored. The tables are
// filled for patterns with no word boundary at all, and for `bar\b`, whose
// boundary accept nothing can follow, so their mere presence says nothing.
func dominanceDecides(t *dfaTable) bool {
	if t == nil || !t.hasWordBoundary {
		return false
	}
	_, co := dfaReachCo(t)
	check := func(m map[int]uint64, word bool) bool {
		for q, v := range m {
			if v == 0 {
				continue
			}
			for c := 0; c < 256; c++ {
				if isWordByte(byte(c)) != word {
					continue
				}
				if n := t.transitions[q*256+c]; n >= 0 && co[n] {
					return true
				}
			}
		}
		return false
	}
	return check(t.midAcceptWStatesDominant, true) || check(t.midAcceptNWStatesDominant, false)
}

// dfaWalksNest reports whether an overlapping drive over t can have
// arbitrarily many walks alive at once — the condition for its per-position
// walk to be quadratic on long overlapping matches, and so for the answer
// cache's sweep to be worth its code. It is: a word W and a state q with
// s·W = q and q·W = q for a mid start state s, every state of both walks alive
// (reachable, and able to still accept). Over W×k every |W|-th position then
// starts a walk still alive at the end: `foo\w+` over `foo`×N, `X[a-zA-Z]+Y`
// over `XaY`×N. Without such a W the walks alive at once are bounded in number
// whatever their lengths: `union[ \t]+[a-z]{3}[0-9]` matches unboundedly long,
// but no match can hold the start of another, and its drive is linear.
//
// Exact, by a breadth-first search over state PAIRS for each q on a cycle,
// the second component kept inside q's strongly connected component (q·W = q
// never leaves it) and the bytes taken one per class. Past maxNestWork pair
// steps it answers true: the side that costs a sweep nobody needed rather than
// a quadratic drive.
func dfaWalksNest(t *dfaTable) bool {
	if t == nil || t.numStates == 0 {
		return false
	}
	reach, co := dfaReachCo(t)
	n := t.numStates
	alive := make([]bool, n)
	for q := range alive {
		alive[q] = reach[q] && co[q]
	}
	_, reps, _ := computeByteClasses(t)
	step := func(q, c int) int {
		if m := t.transitions[q*256+c]; m >= 0 && alive[m] {
			return m
		}
		return -1
	}
	comp := aliveSCCs(n, alive, reps, step)
	// Each component's states, once, and every state's index within its own:
	// the pair's second half lives in one component, so the search indexes
	// pairs (x, y) as x*|C| + idx[y].
	var members [][]int
	idx := make([]int, n)
	for q := 0; q < n; q++ {
		if c := comp[q]; c >= 0 {
			for len(members) <= c {
				members = append(members, nil)
			}
			idx[q] = len(members[c])
			members[c] = append(members[c], q)
		}
	}
	// A component is a cycle when it has two states, or one with a self-loop.
	onCycle := func(q int) bool {
		if comp[q] < 0 {
			return false
		}
		if len(members[comp[q]]) > 1 {
			return true
		}
		for _, c := range reps {
			if step(q, c) == q {
				return true
			}
		}
		return false
	}
	var starts []int
	for _, st := range []int{t.midStartState, t.midStartWordState, t.midStartNewlineState} {
		if st >= 0 && st < n && alive[st] && !slices.Contains(starts, st) {
			starts = append(starts, st)
		}
	}
	// The budget counts every pair step AND every pair slot a search's seen
	// set spans: a large component's n*|C| slots are work too, and counting
	// only the steps let a component of a thousand states allocate gigabytes.
	// One component's seen set is capped on its own as well (16 MB).
	const maxNestWork, maxNestSlots = 1 << 26, 1 << 22
	work := 0
	type pair struct{ x, y int }
	var queue []pair
	for c, cm := range members {
		if len(cm) == 0 || !onCycle(cm[0]) {
			continue
		}
		width := len(cm)
		if work += n * width; work > maxNestWork || n*width > maxNestSlots {
			return true
		}
		// One seen set per component, reused across its searches: a slot is
		// seen when it holds the current search's stamp.
		seen := make([]uint32, n*width)
		stamp := uint32(0)
		for _, q := range cm {
			for _, st := range starts {
				if st == q {
					return true // the start state is on the cycle: W is the cycle
				}
				stamp++
				queue = append(queue[:0], pair{st, q})
				seen[st*width+idx[q]] = stamp
				for len(queue) > 0 {
					p := queue[0]
					queue = queue[1:]
					for _, b := range reps {
						if work++; work > maxNestWork {
							return true
						}
						x, y := step(p.x, b), step(p.y, b)
						if x < 0 || y < 0 || comp[y] != c {
							continue
						}
						if x == q && y == q {
							return true
						}
						if k := x*width + idx[y]; seen[k] != stamp {
							seen[k] = stamp
							queue = append(queue, pair{x, y})
						}
					}
				}
			}
		}
	}
	return false
}

// aliveSCCs numbers the strongly connected components of the graph over the
// alive states (edges: step over one representative byte per class), -1 for a
// state that is not alive. Kosaraju, iteratively.
func aliveSCCs(n int, alive []bool, reps []int, step func(q, c int) int) []int {
	order := make([]int, 0, n)
	visited := make([]bool, n)
	type frame struct{ q, i int }
	for r := 0; r < n; r++ {
		if !alive[r] || visited[r] {
			continue
		}
		visited[r] = true
		stack := []frame{{r, 0}}
		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			if f.i == len(reps) {
				order = append(order, f.q)
				stack = stack[:len(stack)-1]
				continue
			}
			m := step(f.q, reps[f.i])
			f.i++
			if m >= 0 && !visited[m] {
				visited[m] = true
				stack = append(stack, frame{m, 0})
			}
		}
	}
	preds := make([][]int, n)
	for q := 0; q < n; q++ {
		if !alive[q] {
			continue
		}
		for _, c := range reps {
			if m := step(q, c); m >= 0 {
				preds[m] = append(preds[m], q)
			}
		}
	}
	comp := make([]int, n)
	for q := range comp {
		comp[q] = -1
	}
	nc := 0
	for i := len(order) - 1; i >= 0; i-- {
		r := order[i]
		if comp[r] >= 0 {
			continue
		}
		comp[r] = nc
		stack := []int{r}
		for len(stack) > 0 {
			q := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, p := range preds[q] {
				if comp[p] < 0 {
					comp[p] = nc
					stack = append(stack, p)
				}
			}
		}
		nc++
	}
	return comp
}

// dfaRoots are the states a walk of t can begin in: the start state and the
// three mid-start states (after a non-word byte, after a word byte, after a
// newline). The ONE list every analysis of where a walk can go starts from —
// three copies of it once had to be kept in step, and a start state added to
// one and not the others would have a soundness proof examine a smaller graph.
func dfaRoots(t *dfaTable) []int {
	return []int{t.startState, t.midStartState, t.midStartWordState, t.midStartNewlineState}
}

// dfaReachable reports the states of t a walk can reach from dfaRoots.
func dfaReachable(t *dfaTable) []bool {
	reach := make([]bool, t.numStates)
	var stack []int
	for _, r := range dfaRoots(t) {
		if r >= 0 && r < t.numStates && !reach[r] {
			reach[r] = true
			stack = append(stack, r)
		}
	}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for c := 0; c < 256; c++ {
			if n := t.transitions[s*256+c]; n >= 0 && !reach[n] {
				reach[n] = true
				stack = append(stack, n)
			}
		}
	}
	return reach
}

// longestPaths walks the graph of the n nodes `in` admits, whose edges are
// next(s, c) for c in 0..255 (-1 for none, and an edge to a node `in` refuses
// is ignored). It returns each node's longest path in nodes — itself counted —
// or cyclic when a cycle is reachable within the graph, in which case longest
// is meaningless. An iterative DFS with colours: a grey successor is a cycle.
func longestPaths(n int, in func(s int) bool, next func(s, c int) int) (longest []int, cyclic bool) {
	const white, grey, black = 0, 1, 2
	colour := make([]int, n)
	longest = make([]int, n)
	type frame struct{ s, c int }
	for root := 0; root < n; root++ {
		if !in(root) || colour[root] != white {
			continue
		}
		colour[root] = grey
		frames := []frame{{root, 0}}
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			if f.c == 256 {
				best := 0
				for c := 0; c < 256; c++ {
					if m := next(f.s, c); m >= 0 && in(m) && longest[m] > best {
						best = longest[m]
					}
				}
				longest[f.s] = best + 1
				colour[f.s] = black
				frames = frames[:len(frames)-1]
				continue
			}
			m := next(f.s, f.c)
			f.c++
			if m < 0 || !in(m) {
				continue
			}
			switch colour[m] {
			case grey:
				return nil, true
			case white:
				colour[m] = grey
				frames = append(frames, frame{m, 0})
			}
		}
	}
	return longest, false
}

// dfaReachCo returns which states a walk reaches from a start state, and which
// can still reach an accepting one — a boundary accept or an end-of-input one
// counting — through any path.
func dfaReachCo(t *dfaTable) (reach, co []bool) {
	n := t.numStates
	accepts := func(s int) bool {
		if t.midAcceptStates[s] != 0 || t.acceptStates[s] != 0 || t.midAcceptNWStates[s] != 0 ||
			t.midAcceptWStates[s] != 0 || t.midAcceptNLStates[s] != 0 {
			return true
		}
		for _, m := range t.wideMaps() {
			if len((*m)[s]) > 0 {
				return true
			}
		}
		return false
	}
	reach = dfaReachable(t)
	preds := make([][]int, n)
	for s := 0; s < n; s++ {
		if !reach[s] {
			continue
		}
		for c := 0; c < 256; c++ {
			if m := t.transitions[s*256+c]; m >= 0 {
				preds[m] = append(preds[m], s)
			}
		}
	}
	var stack []int
	co = make([]bool, n)
	for s := 0; s < n; s++ {
		if reach[s] && accepts(s) {
			co[s] = true
			stack = append(stack, s)
		}
	}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range preds[s] {
			if !co[p] {
				co[p] = true
				stack = append(stack, p)
			}
		}
	}
	return reach, co
}

// overlapSweepCostPerByte is what one input BYTE of sweeping costs, in the
// currency the adaptive trigger counts: matched bytes the walk has delivered.
//
// The per-position work is the COLUMN, one update per cell — which under lever
// C is the projected width and not states x patterns, the figure this was
// spelled as in two places. And under checkpointing a position may be swept
// TWICE: once by the pass and once when its block is rebuilt — 2 * cells.
//
// The threshold is HALF that: `cells`. Measured on setperf (fuel), against
// 2 * cells: the dense overlap rows −25% to −31%, greedy-3's quadratic rows
// −0.6% to 0.0% where the in-call counter charges each walk once, and no row
// worse; ×0.25 gained more but doubles the worst case again. The price is that
// worst case: a drive whose walk would have ended just past the threshold pays
// a sweep it did not need — up to ~3× walking alone, where 2 * cells bounded
// it at ~2×.
//
// The per-byte rate alone misses what STARTING a sweep costs, which is why the
// threshold is priced over overlapSweepSetupBytes more bytes than the input
// has — see there.
//
// The units are not comparable in any exact sense — one side counts matched
// bytes, the other column updates — and never were. What the constant has to
// do is scale like the sweep does, so that a drive whose walk is genuinely
// quadratic crosses and a drive the walk handles cheaply does not.
//
// The rate is then divided by overlapSweepTriggerDiv, so the line sits at a
// sixteenth of a sweep's cost — see there.
func (cs *compiledSet) overlapSweepCostPerByte() int64 {
	cells := cs.overlapCells()
	if cells <= 0 {
		return 1
	}
	return max(1, int64(cells)/overlapSweepTriggerDiv)
}

// overlapSweepTriggerDiv lowers the trigger to 1/16 of a sweep's per-byte
// cost. At the full cost a WIDE set walked up to about two sweeps' worth
// before switching — linear, but ×4 per doubling up to that point: 96
// members over `a`×n fired only at 16 KB (281,595 fuel/byte). Measured at
// ÷16: that row 108,705 from 2 KB, 40 members 49,072 → 21,120, 128 members
// 56,052 → 23,440; match-heavy drives −36% to +2.3%; setperf's overlapping
// rows no dearer (overlap-shape-3 −27% to −34%); and ordinary text never
// fires — its work per byte stays 11× to 134× under the line (÷64 gained only
// 6-8% more on hostile input and left as little as 2.8×). A sweep fired on
// ordinary text costs 30× to 250× the walk, which is why there is a line at
// all.
const overlapSweepTriggerDiv = 16

// overlapSweepSetupBytes is what STARTING a sweep costs, in bytes of sweeping
// at the FULL per-byte rate (`cells`): the drive engages once its work passes
// len × costPerByte + this × cells (overlapSweepSetupWork). The allowance is
// not divided by overlapSweepTriggerDiv with the rate — dividing it put 3- to
// 13-byte inputs back over the line, onto a sweep that costs them more than
// the walk (the losses measured below).
//
// A per-byte rate alone prices a sweep over a 3-byte input at three bytes'
// worth, and the drives that then crossed paid more than walking — measured
// (fuel, sweep against the same module kept on the walk): `a+` over "aaa"
// +24%, `a*` +14%, `[^\n]*ERROR` over 13 bytes +4%, greedy-3's batch entry at
// capacity 1 over the same 13 bytes +23%. Their work at the end of the walk
// exceeded len × cells by at most 5 × cells, and every drive where the sweep
// won (`a+` from 8 bytes, −12%; `[^\n]*ERROR` and greedy-3 from 32, −24% to
// −34%) by at least 16 × cells — so the allowance scales with the column,
// which is what the setup work does, and sits between the two. A flat constant
// fitted the same drives only inside [35, 48) work units. At 100 KB the
// allowance moves the line by eight bytes and nothing measurable.
const overlapSweepSetupBytes = 8

// overlapSweepSetupWork is the start-up allowance in work units:
// overlapSweepSetupBytes at the full per-byte rate.
func (cs *compiledSet) overlapSweepSetupWork() int64 {
	return overlapSweepSetupBytes * max(1, int64(cs.overlapCells()))
}

// emitSweepThreshold pushes the i64 len × costPerByte + setupWork, with len
// the input-length parameter pInLen. The ONE spelling of the line: the
// between-calls trigger and both in-call budgets compare against it, and two
// of three drifting apart would have a call's budget run out on a drive the
// trigger says is cheap.
func emitSweepThreshold(b []byte, pInLen byte, costPerByte, setupWork int64) []byte {
	b = append(b, 0x20, pInLen, 0xAD) // (u64) len
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, costPerByte)
	b = append(b, 0x7E) // i64.mul
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, setupWork)
	return append(b, 0x7C) // i64.add
}

// overlapCacheGeometry is everything the two serving paths need to know about
// a cache's shape, derived ONCE.
//
// Both entries computed it separately from the same bucket, which is how they
// came to disagree about the sweep's cost per byte: one spelling said states x
// patterns and the other the same thing again, and the projection had made both wrong.
func (cs *compiledSet) overlapCacheGeometry() (numPat int, ids []int, rowBytes int32, costPerByte int64) {
	costPerByte = 1
	sw := cs.sweepSrc()
	if sw == nil {
		return 0, nil, 0, costPerByte
	}
	numPat = len(sw.ids)
	rowBytes = int32(config.SetOverlapBlockRowBytes(numPat)) //nolint:gosec // a row is at most a few KB
	return numPat, sw.ids, rowBytes, cs.overlapSweepCostPerByte()
}

// overlapCells is the sweep column's WIDTH in cells: one per projection class
// when the column is projected, one per (state, pattern) otherwise.
//
// ONE definition, because the column sizing, the emitted projection table, the
// two sweep bodies, the serving validator and every stub's region arithmetic
// must agree on it exactly — a width computed twice is a region sized for one
// column and indexed as another.
func (cs *compiledSet) overlapCells() int {
	sw := cs.sweepSrc()
	if sw == nil {
		return 0
	}
	if sw.proj != nil {
		return sw.proj.cells
	}
	return sw.dp.numWASM * len(sw.ids)
}

// overlapDPColumnBytes is the module memory the sweep needs for its two
// working columns. This is MODULE scratch and is fine: it lives only for the
// duration of one call, which is what the no-module-state rule permits. The
// CHECKPOINTS and the materialised block are the parts that must survive
// between calls, and those are the caller's.
func (cs *compiledSet) overlapDPColumnBytes() int32 {
	return int32(2 * cs.overlapCells() * 4) //nolint:gosec // bounded by vetSweep
}

// overlapProjFor returns the column projection, or nil when the column is not
// projected (or there is no sweep).
func (cs *compiledSet) overlapProjFor() *overlapProj {
	if sw := cs.sweepSrc(); sw != nil {
		return sw.proj
	}
	return nil
}

// overlapProjTabBytes is the emitted projection table: for each pattern, the
// BYTE OFFSET within a column of every WASM state's cell. u16 because a
// projected column is bounded by overlapProjMaxCells.
func (cs *compiledSet) overlapProjTabBytes() []byte {
	sw := cs.sweepSrc()
	if sw == nil || sw.proj == nil {
		return nil
	}
	p, n := sw.proj, sw.dp.numWASM
	// The bound lives in vetSweep and the wrap here would be silent, pointing
	// every state at the wrong cell.
	if p.cells*4 > 0xFFFF {
		panic(fmt.Sprintf("overlap projection table: a column of %d cells is %d bytes, "+
			"past what a u16 offset can address", p.cells, p.cells*4))
	}
	out := make([]byte, 0, len(p.cellOf)*n*2)
	for _, col := range p.cellOf {
		for w := 0; w < n; w++ {
			off := uint16(col[w] * 4) //nolint:gosec // bounded above
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
	if !l.useU8 {
		// 16-bit ids, emitU16Transition's indexing: no class map, so the cell
		// IS the byte; tableOff + row*512 + byte*2.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		if l.useRowDedup {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, l.rowMapOff)
			b = append(b, 0x20, stateLocal, 0x6A)
			b = appendTableLoad8u(b, tableMemIdx) // rowMap[state] -> row
		} else {
			b = append(b, 0x20, stateLocal)
		}
		b = append(b, 0x41, 0x09, 0x74, 0x6A)            // + row << 9
		b = append(b, 0x20, cellLocal, 0x41, 0x01, 0x74) // byte << 1
		b = append(b, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx)
		return append(b, 0x21, dstLocal)
	}
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
	// currency the work counter uses (matched bytes). See
	// overlapSweepCostPerByte.
	costPerByte int64
	// setupWork is the start-up allowance (overlapSweepSetupWork).
	setupWork int64
	// cellBytes and rowBytes are the layout constants the serving validator
	// checks the caller's header against: one checkpoint column, and one
	// position's row in the block buffer.
	cellBytes int32
	rowBytes  int32
	// numPat is the sweep's pattern count, which fixes the row's mask width
	// and so where each pattern's end sits (config.SetOverlapRowEndOff).
	numPat int

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
	// lCumBase and lBlockBase are the ABSOLUTE addresses of cum[] and of the
	// block buffer, derived from nb once per call by emitLayoutBases, so the
	// per-block and per-row reads each start from a local.
	lCumBase   byte
	lBlockBase byte
	// i64Ret marks the entry whose export returns an i64, which changes only
	// how the error is packed.
	i64Ret bool

	// walkEndGlobal is the module global the suffix body stamps with the
	// farthest position its walk reached, or -1 when this set's bucket carries
	// no such store. Seeded with the call's `from` before the walk and read
	// back after it, so the difference is the bytes this call WALKED.
	walkEndGlobal int32
	// midWorkP1 is one past the in-call counter's global (compiledSet.
	// midSweepWork), 0 = none. That counter sums every candidate's walk in
	// the call, where walkEndGlobal — re-seeded per candidate for it — ends
	// up holding only the last candidate's stop; emitStoreWork folds it into
	// the drive's work so the between-calls trigger sees every walk.
	midWorkP1 int32
}

// hdrLoadOp appends an i32.load of the cache header field at byte offset off;
// the region's base must already be on the stack. hdrStoreOp is the matching
// i32.store, with the base and the value on the stack.
//
// EVERY header access goes through these two, in both serving entries and the
// checkpoint bodies. The memarg offset is a ULEB128: every slot is under 128
// today, so a raw byte and the encoding agree — but a bare byte of 128 or more
// is read as a continuation, which is exactly the bug that once shipped in the
// row writer, and nothing should keep the shape that caused it.
func hdrLoadOp(b []byte, off int) []byte {
	b = append(b, 0x28, 0x02)
	return utils.AppendULEB128(b, uint32(off)) //nolint:gosec // a header offset
}

func hdrStoreOp(b []byte, off int) []byte {
	b = append(b, 0x36, 0x02)
	return utils.AppendULEB128(b, uint32(off)) //nolint:gosec // a header offset
}

// emitWorkExceedsSweep pushes 1 when the walk has already spent more than the
// sweep would cost (emitSweepThreshold).
//
// Computed in i64 because the threshold overflows i32 on a large input, which
// would make the test wrap and fire at random.
//
// A SATURATED counter counts as over the line. work is an i32 that stops at
// 0x7FFFFFFF while len * cost is not bounded by it: past about 3 MB on a
// 353-cell column the threshold is out of the counter's reach, and the cache
// was then offered, sized and reserved — and never engaged, leaving the drive
// quadratic with nothing to tell it from a cheap one.
func (c overlapCacheCtx) emitWorkExceedsSweep(b []byte) []byte {
	b = append(b, 0x20, c.lWork)
	b = append(b, 0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07) // 0x7FFFFFFF
	b = append(b, 0x46)                               // i32.eq -> saturated
	b = append(b, 0x20, c.lWork, 0xAD)                // (u64) work
	b = emitSweepThreshold(b, c.pInLen, c.costPerByte, c.setupWork)
	b = append(b, 0x56) // i64.gt_u
	b = append(b, 0x72) // i32.or: saturated, or over the threshold
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
	b = hdrLoadOp(b, ckptHdrReady)
	b = append(b, 0x21, c.lReady)
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrWork)
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
// sweep — and treating them alike is the silent degradation this sentinel
// exists to prevent. A
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
	b = c.emitMalformedNow(b, i64Ret)
	b = append(b, 0x0B)
	return b
}

// emitMalformedNow reports a malformed header UNCONDITIONALLY, in whichever
// shape the entry's export returns.
func (c overlapCacheCtx) emitMalformedNow(b []byte, i64Ret bool) []byte {
	if i64Ret {
		// find_batch returns an i64 cursor+count pair, so the error is a
		// RESERVED RESUME POSITION with a zero count, exactly as the
		// backtracking overflow is. It cannot ride in the count half: every
		// decoder masks that half to countBits and would read -4 as a large
		// positive tuple count.
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, malformedCursor())
	} else {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(abi.OverlapCacheMalformed))
	}
	b = append(b, 0x0F) // return
	return b
}

// malformedCursor is the packed i64 the batch entry returns for a malformed
// header: the reserved position word on top, a zero count below.
func malformedCursor() int64 {
	var w uint64 = config.SetCursorMalformedPos
	return int64(w << 32) //nolint:gosec // a reserved bit pattern, not a count
}

// emitValidateHeader rejects a header that contradicts itself, on EVERY call
// rather than only the one that swept.
//
// The pass validates what it is handed and then publishes a layout; nothing
// re-checked that layout on the calls that followed, so a caller that zeroed or
// rewrote the header mid-drive got a division by zero (a TRAP, not an answer)
// or a block located outside the region. It checks what serving READS: a
// stride of at least 1, the floor, nb exactly as a pass derives it from (len,
// floor, stride), and a region large enough for the layout nb implies. The
// layout itself is not stored — every reader derives it from nb — so there is no
// offset to check, and nothing a pass could not have written gets past: -4.
func (c overlapCacheCtx) emitValidateHeader(b []byte, tmp byte) []byte {
	hdr := func(b []byte, off int) []byte {
		b = append(b, 0x20, c.pCache)
		return hdrLoadOp(b, off)
	}
	b = hdr(b, ckptHdrNumBlocks)
	b = append(b, 0x21, tmp)

	// The stride and numBlocks are tested FIRST, on their own: the block count
	// below divides by the stride, and a chain of i32.or evaluates every
	// operand whatever the earlier ones said.
	b = hdr(b, ckptHdrStride)
	b = append(b, 0x41, 0x01, 0x48) // stride < 1
	b = append(b, 0x20, tmp, 0x41, 0x01, 0x48)
	b = append(b, 0x72)       // or numBlocks < 1
	b = append(b, 0x04, 0x40) // if
	b = c.emitMalformedNow(b, c.i64Ret)
	b = append(b, 0x0B)

	b = hdr(b, ckptHdrFloor)
	b = append(b, 0x20, c.pInLen, 0x41, 0x01, 0x6A)
	b = append(b, 0x4A) // floor > len+1

	// numBlocks must be the count a pass would have derived from (len, floor,
	// stride). Every reader derives the layout FROM numBlocks, so an inflated
	// count moves the whole layout with it and nothing else here would notice —
	// serving would locate a block past the real last one, whose rebuild wrote
	// a row BELOW the block buffer. In i64 with the floor sign-extended, so a
	// negative floor cannot wrap the span into agreement.
	b = hdr(b, ckptHdrFloor)
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x4A)       // floor > len: the past-the-end layout
	b = append(b, 0x04, 0x7E) // if (result i64)
	b = append(b, 0x42, 0x01) // is one block
	b = append(b, 0x05)       // else
	b = emitBlockCount(b, true,
		func(b []byte) []byte { // m = len - floor + 1
			b = append(b, 0x20, c.pInLen, 0xAC) // i64.extend_i32_s
			b = hdr(b, ckptHdrFloor)
			b = append(b, 0xAC)
			b = append(b, 0x7D)       // i64.sub
			b = append(b, 0x42, 0x01) // + 1
			return append(b, 0x7C)
		},
		func(b []byte) []byte {
			b = hdr(b, ckptHdrStride)
			return append(b, 0xAD) // i64.extend_i32_u: >= 1, tested above
		})
	b = append(b, 0x0B)
	b = append(b, 0x20, tmp, 0xAD)
	b = append(b, 0x52) // i64.ne -> numBlocks is not the pass's
	b = append(b, 0x72)

	// The region still has to hold what the header describes, in i64 for the
	// reason the pass computes its layout that way.
	// blockOff = 48 + nb*cellBytes + (nb+1)*4 = 52 + nb*(cellBytes+4), derived
	// as every reader derives it.
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, int64(ckptHdrBytes)+4)
	b = append(b, 0x20, tmp, 0xAD, 0x42)
	b = utils.AppendSLEB128_64(b, int64(c.cellBytes)+4)
	b = append(b, 0x7E, 0x7C) // i64.mul, i64.add
	b = hdr(b, ckptHdrStride)
	b = append(b, 0xAD)
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, int64(c.rowBytes))
	b = append(b, 0x7E, 0x7C)
	b = append(b, 0x20, c.pCacheLen, 0xAD)
	b = append(b, 0x56) // blockOff + stride*rowBytes > cache_len
	b = append(b, 0x72)

	b = append(b, 0x04, 0x40) // if
	b = c.emitMalformedNow(b, c.i64Ret)
	b = append(b, 0x0B)
	return b
}

// emitOutOfOrderCheck reports a position BELOW the floor of the engaged cache
// as abi.OverlapCacheOutOfOrder — `find`'s -6, or the batch entry's reserved
// position word — instead of serving it from the floor, which silently dropped
// every match in [pos, floor).
//
// Valid only once the cache is live and its header validated, since it reads
// the floor. Detection is BEST EFFORT: this is the one place a backwards
// position is visible, so a drive that has not engaged, or offered no region,
// is not checked at all. No legitimate drive reaches it: every sweep takes its
// floor from the position the drive is at, and both entries only move forward
// from there.
func (c overlapCacheCtx) emitOutOfOrderCheck(b []byte, posLocal byte) []byte {
	b = append(b, 0x20, posLocal)
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrFloor)
	// UNSIGNED. `from` is a u32 in the ABI, and the floor a pass wrote is
	// always in [0, len+1], so the comparison is between two values a signed
	// test agrees with everywhere below 2^31 — and disagrees with above it,
	// where a `from` the ABI defines as "nothing found" reads as negative and
	// is reported as a scan that went backwards. Nothing generated can reach
	// that (the C stubs refuse a length or offset over 0x7FFFFFFF outright),
	// which is why it was latent rather than a live defect.
	b = append(b, 0x49)       // i32.lt_u -> below the floor
	b = append(b, 0x04, 0x40) // if
	if c.i64Ret {
		// The batch entry's cursor cannot carry a negative, so the error is a
		// reserved POSITION word with a zero count, as the other two are.
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, outOfOrderCursor())
	} else {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(abi.OverlapCacheOutOfOrder))
	}
	b = append(b, 0x0F) // return
	b = append(b, 0x0B)
	return b
}

// outOfOrderCursor is the packed i64 the batch entry returns for a resume below
// the floor: the reserved position word on top, a zero count below.
func outOfOrderCursor() int64 {
	var w uint64 = config.SetCursorOutOfOrderPos
	return int64(w << 32) //nolint:gosec // a reserved bit pattern, not a count
}

// emitPastEndCheck answers a position beyond the input the way the WALK does —
// "nothing found" — instead of letting it reach the block arithmetic.
//
// The ABI defines `from > len` as the capability's nothing, and the walk
// implements it directly. The cache path had no such test: it relied on the
// located block landing past the last one, which is true for a `from` a few
// positions past the end and FALSE once `from` is large enough that
// `(from - floor) / stride` overflows into a negative i32 — the block loop's
// `j >= nb` is signed, so a huge j reads as "not yet at the end" and the drive
// then indexes cum[] at a wild offset.
//
// Measured before this existed, on an engaged cache over a 4-byte input:
// the walk answered 0 for `from` = 2^31 and 2^32-16, and the cache answered 1 —
// the matches at position 0, because the row clamp folded a negative difference
// back to row zero. Cache and walk disagreeing is the one thing this whole path
// may not do.
//
// UNSIGNED, because `from` is a u32. Placed before emitOutOfOrderCheck, which
// can then only ever see a position inside the input: a floor is at most
// len + 1, so `from > len` already implies `from >= floor`.
func (c overlapCacheCtx) emitPastEndCheck(b []byte, posLocal byte) []byte {
	b = append(b, 0x20, posLocal)
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	if c.i64Ret {
		// The batch entry says "finished" with the sentinel resume word and a
		// zero count, which is what a caller's `count == 0` loop expects.
		b = append(b, 0x42, 0x7F, 0x42, 0x20, 0x86) // (i64)-1 << 32
	} else {
		b = append(b, 0x41, 0x00)
	}
	b = append(b, 0x0F) // return
	b = append(b, 0x0B)
	return b
}

// emitMarkRefused records that this drive must not ask again.
func (c overlapCacheCtx) emitMarkRefused(b []byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x41, 0x7F)
	b = hdrStoreOp(b, ckptHdrReady)
	return b
}

// emitStoreWork writes the work counter back to the caller's cache header.
//
// Drive state, so it goes back before every walk-path return — otherwise each
// call would start from zero and a drive of many short calls could never cross
// the line.
func (c overlapCacheCtx) emitStoreWork(b []byte) []byte {
	if c.midWorkP1 > 0 {
		// work += this call's candidate walks, saturating (both are
		// non-negative, so a sum past the i32 maximum reads negative); then
		// zero them, so a second store in the call does not count them again.
		g := uint32(c.midWorkP1 - 1) //nolint:gosec // a global index
		b = append(b, 0x20, c.lWork, 0x23)
		b = utils.AppendULEB128(b, g)
		b = append(b, 0x6A, 0x22, c.lWork, 0x41, 0x00, 0x48, 0x04, 0x40)
		b = append(b, 0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x21, c.lWork, 0x0B)
		b = append(b, 0x41, 0x00, 0x24)
		b = utils.AppendULEB128(b, g)
	}
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x20, c.lWork)
	b = hdrStoreOp(b, ckptHdrWork)
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
// It carried a third argument once: a local set to 1 when THIS call was the one
// that swept, because the batch cursor's high half was a text position where
// the cache path read a tuple INDEX. Lever B retired the index form — rows are
// addressed by position — so the two halves mean the same thing on both paths
// and there is nothing left to tell apart.
func (c overlapCacheCtx) emitEntrySweep(b []byte, pushFrom func([]byte) []byte) []byte {
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
	b = hdrLoadOp(b, ckptHdrReady)
	b = append(b, 0x21, c.lReady)
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
// emitSeedWalkEnd stamps the global with the position the walk is about to
// start from, so whatever the suffix body leaves there is a position at or
// above it and the difference is this call's walk.
//
// Emitted only where a charge follows, and only for a set whose bucket carries
// the store — a module without one declares no such global.
func (c overlapCacheCtx) emitSeedWalkEnd(b []byte, fromLocal byte) []byte {
	if c.walkEndGlobal < 0 {
		return b
	}
	b = append(b, 0x20, fromLocal)
	b = append(b, 0x24)
	return utils.AppendULEB128(b, uint32(c.walkEndGlobal)) //nolint:gosec // a global index
}

// emitChargeWalkExtent adds the bytes this call WALKED to the work counter,
// saturating, where fromLocal is the position it started from.
//
// THE REASON THE COUNTER CANNOT BE DELIVERED EXTENT ALONE. The trigger exists
// to spot a drive whose walks are quadratic, and a walk's cost is how far it
// ran — not how much of what it found was reported. `(?:a*b)?` over a run of
// `a`s walks to the end of the input from every start and delivers a
// zero-length match at each, so the delivered sum stays 0 for ever: measured at
// 8,000 bytes the counter read 0, `ready` stayed 0 and the drive ran 268 ms,
// against 75 ms for `a*` — the same shape with a non-empty match — which
// engaged on its first call.
//
// Charged in ADDITION to the delivered extent rather than instead of it: the
// two measure different halves of the same call (a position that matched long
// and one that walked far), and taking the larger of the two would let a dense
// drive under-report.
func (c overlapCacheCtx) emitChargeWalkExtent(b []byte, fromLocal, tmpLocal byte) []byte {
	// Not with the in-call counter: it re-seeds the global per candidate and
	// sums every candidate's walk into midSweepWork, which emitStoreWork folds
	// into the drive's work — so walkEnd - from here would charge the LAST
	// candidate's walk a second time, and the sweep would engage earlier than
	// the trigger's model says.
	if c.walkEndGlobal < 0 || c.midWorkP1 > 0 {
		return b
	}
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, uint32(c.walkEndGlobal)) //nolint:gosec // a global index
	b = append(b, 0x20, fromLocal)
	b = append(b, 0x6B) // walkEnd - from
	b = append(b, 0x20, c.lWork, 0x6A)
	b = append(b, 0x22, tmpLocal)
	b = append(b, 0x41, 0x00, 0x48) // < 0 -> it wrapped
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x21, c.lWork) // saturate
	b = append(b, 0x05)
	b = append(b, 0x20, tmpLocal, 0x21, c.lWork)
	b = append(b, 0x0B)
	return b
}

func (c overlapCacheCtx) emitAccumulateWork(b []byte, pOutPtr, idxLocal, countLocal, tmpLocal byte) []byte {
	b = append(b, 0x02, 0x40)                                         // block $sumDone
	b = append(b, 0x03, 0x40)                                         // loop  $sum
	b = append(b, 0x20, idxLocal, 0x20, countLocal, 0x4E, 0x0D, 0x01) // idx >= count
	b = append(b, 0x20, pOutPtr, 0x20, idxLocal, 0x41, abi.SetMatchTupleBytes, 0x6C, 0x6A)
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

// emitLocateBlock computes which block a POSITION falls in and leaves it in
// jLocal: `(pos - floor) / stride`, floored at 0.
//
// The floor clamp is a GUARD, not a path. Both entries run emitOutOfOrderCheck
// first, which reports a position below the floor as out of order — serving it
// from block 0 was what silently dropped the matches below the floor.
//
// Shared, because the two entries located a block with the same arithmetic
// written twice and one of them had already drifted into a different if-shape.
func (c overlapCacheCtx) emitLocateBlock(b []byte, posLocal, jLocal, tmpLocal byte) []byte {
	b = append(b, 0x20, posLocal)
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrFloor)
	b = append(b, 0x6B) // pos - floor
	b = append(b, 0x22, tmpLocal)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x4C)       // i32.le_s -> at or below the floor
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x05)
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrStride)
	b = append(b, 0x6E) // i32.div_u
	b = append(b, 0x0B)
	b = append(b, 0x21, jLocal)
	return b
}

// emitBlockRowCount loads the materialised block's row base into rowBaseLocal
// and leaves min(stride, len - rowBase + 1) in rowsLocal: the last block is
// partial, and reading past it would read another region's bytes. strideLocal
// is scratch, left holding the stride.
//
// This and emitRowAddr are the pieces of the two serving loops that were the
// same instructions written twice. What stays per entry differs on purpose:
// `find` clamps a row below the block with `<=` and has no skip, while the
// batch entry must test `<` and reset its skip there, and the two leave their
// loops for different reasons (one position answered, or a buffer full).
func (c overlapCacheCtx) emitBlockRowCount(b []byte, rowBaseLocal, rowsLocal, strideLocal byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrRowBase)
	b = append(b, 0x21, rowBaseLocal)
	b = append(b, 0x20, c.pInLen)
	b = append(b, 0x20, rowBaseLocal)
	b = append(b, 0x6B, 0x41, 0x01, 0x6A)
	b = append(b, 0x21, rowsLocal)
	b = append(b, 0x20, c.pCache)
	b = hdrLoadOp(b, ckptHdrStride)
	b = append(b, 0x21, strideLocal)
	b = append(b, 0x20, rowsLocal, 0x20, strideLocal, 0x20, rowsLocal, 0x20, strideLocal)
	b = append(b, 0x4C) // rows <= stride
	b = append(b, 0x1B) // select -> min
	b = append(b, 0x21, rowsLocal)
	return b
}

// emitRowAddr pushes the address of row rowLocal of the materialised block.
func (c overlapCacheCtx) emitRowAddr(b []byte, rowLocal byte) []byte {
	b = append(b, 0x20, c.lBlockBase)
	b = append(b, 0x20, rowLocal, 0x41)
	b = utils.AppendSLEB128(b, c.rowBytes)
	b = append(b, 0x6C, 0x6A)
	return b
}

// emitBlockIsEmpty pushes 1 when block jLocal holds no tuples, which is what
// lets a sparse drive skip it WITHOUT materialising it — the difference between
// one re-sweep per block and none.
//
// cum[] is the prefix sum, so block j is empty exactly when cum[j+1] == cum[j].
func (c overlapCacheCtx) emitBlockIsEmpty(b []byte, jLocal, tmpLocal byte) []byte {
	b = c.emitBlockCum(b, jLocal)
	b = append(b, 0x20, jLocal, 0x41, 0x01, 0x6A, 0x21, tmpLocal)
	b = c.emitBlockCum(b, tmpLocal)
	b = append(b, 0x46) // i32.eq
	return b
}

// emitStoreTuple writes one {id, start, end} tuple at the address in dstLocal,
// reading the end out of the row at srcLocal. pushStart pushes the start
// position, which the two entries spell differently — `find` has it in a local
// and the batch entry adds the row index to the block's base.
func (c overlapCacheCtx) emitStoreTuple(b []byte, k, id int, dstLocal, srcLocal byte, pushStart func([]byte) []byte) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(id)) //nolint:gosec // a pattern id
	b = append(b, 0x36, 0x02, 0x00)
	b = append(b, 0x20, dstLocal)
	b = pushStart(b)
	b = append(b, 0x36, 0x02, 0x04)
	b = append(b, 0x20, dstLocal)
	b = append(b, 0x20, srcLocal, 0x28, 0x02)
	b = utils.AppendULEB128(b, uint32(config.SetOverlapRowEndOff(k, c.numPat))) //nolint:gosec // a row offset
	b = append(b, 0x36, 0x02, 0x08)
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
	b = hdrLoadOp(b, ckptHdrCurBlock)
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

// emitLayoutBases derives, from nb in nbLocal, the absolute addresses of cum[]
// (into lCumBase) and of the block buffer (into lBlockBase). The header stores
// no offsets: checkpoint 1 follows the header, cum[] follows nb columns, and the
// block buffer follows nb+1 counts.
//
// Valid once the header is validated, which bounds nb and proves the region
// holds this layout, so the i32 arithmetic cannot wrap.
func (c overlapCacheCtx) emitLayoutBases(b []byte, nbLocal byte) []byte {
	b = append(b, 0x20, c.pCache)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(ckptHdrBytes))
	b = append(b, 0x6A)
	b = append(b, 0x20, nbLocal, 0x41)
	b = utils.AppendSLEB128(b, c.cellBytes)
	b = append(b, 0x6C, 0x6A)       // + nb*cellBytes
	b = append(b, 0x22, c.lCumBase) // local.tee
	b = append(b, 0x20, nbLocal, 0x41, 0x01, 0x6A, 0x41, 0x04, 0x6C, 0x6A)
	b = append(b, 0x21, c.lBlockBase) // + (nb+1)*4
	return b
}

// emitBlockCum pushes cum[idxLocal] — the number of tuples in blocks below it.
func (c overlapCacheCtx) emitBlockCum(b []byte, idxLocal byte) []byte {
	b = append(b, 0x20, c.lCumBase)
	b = append(b, 0x20, idxLocal)
	b = append(b, 0x41, 0x04, 0x6C, 0x6A)
	b = append(b, 0x28, 0x02, 0x00)
	return b
}
