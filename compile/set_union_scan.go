package compile

import (
	"encoding/binary"
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Start-anywhere union DFA for the scan trio
//
// A set with no mandatory literal has no way to skip input, so the scan bodies
// visit every position and run every bucket's probe from it. That is
// O(positions x buckets), and on an unbounded pattern it is quadratic in the
// input: `[^\n]*ERROR` re-scans to the end of the line from each of 100,000
// positions. It is the 151M-fuel `greedy-3 / no-match / scan` row, and the
// reason `scan_all` and `find` on that set exhaust even a 4e9 fuel budget.
//
// The fix is the shape regex-automata uses for the same question: ONE
// left-to-right pass over an automaton that can start a match at any position,
// whose accept states carry the set of patterns matching there. Cost becomes
// one table lookup and one OR per input byte, independent of pattern count.
//
// This serves `scan`, `scan_any` and the narrow `scan_all`:
//   - `scan_any` joined them later. It used to be
//     excluded because it reported WHERE the match started and a forward pass
//     over a start-anywhere automaton knows only where matches END; with the
//     start dropped, the accumulator IS its answer — any set bit names a
//     genuinely matching pattern. Measured 78 -> 27 fuel/byte.
//   - `find` needs per-pattern extents, which is the suffix machinery's job.
//   - the wide (>64 id) `scan_all` ABI writes a caller bitmap; not built here.

// unionScanDFA holds the emitted form of the start-anywhere union automaton.
type unionScanDFA struct {
	numStates int
	// startState carries begin-of-text context (so `^`/\A can fire);
	// midStartState does not. Which one the body enters depends on `from`.
	startState    int
	midStartState int

	// Table layout. stateWidth is 1 when every state id fits a byte, and
	// numClasses is 256 when no byte-class map is emitted; classMapOff is
	// then unused. A row is numClasses*stateWidth bytes.
	stateWidth  int
	numClasses  int
	classMapOff int32

	transOff  int32 // [numStates][numClasses] next-state, stateWidth bytes each
	acceptOff int32 // [numStates] u64: patterns accepting at any position
	eofOff    int32 // [numStates] u64: patterns accepting at end of input

	// midAcceptLimit partitions the state space: states [0, midAcceptLimit) can
	// accept mid-string, the rest cannot. It is what
	// turns the per-byte "does a match end here" question from a table load into
	// a compare against a constant.
	//
	// 0 means NO state can accept mid-string — the set matches nothing except
	// possibly at end of input — and the bodies then emit no mid-accept arm at
	// all rather than a branch that is never taken.
	midAcceptLimit int

	// --- the WIDE form ---
	//
	// maskWords is 1 for every set that fits the u64 accumulator, and
	// ceil(idSpace/64) above it. When it is > 1 the u64 tables above are NOT
	// emitted at all (acceptOff/eofOff are -1) and these take their place:
	//
	//   midReprOff/eofReprOff  [numStates] i32 — 0 when the state accepts
	//     nothing, else SOME accepting global id, plus one. `scan_any` needs
	//     no more than this: which id `scan_any` reports is unspecified, so
	//     one i32 load replaces a mask load, an OR and an accumulator.
	//   midWordsOff/eofWordsOff [numStates][rowBytes] — the accept set as a
	//     bitmap ROW shaped exactly like the caller's `_all` bitmap, so
	//     recording is a straight OR of a table row into caller memory. Built
	//     only when the set exports `scan_all`; -1 otherwise.
	//
	// bitmapBytes is ceil((maxID+1)/8) — derived from the ids this automaton
	// can actually set, never from the declared id space, so a row can never
	// be wider than the caller's allocation even when the two disagree.
	maskWords int
	// wideAccept records WHICH ACCEPT FORM was emitted, which is a different
	// question from how many words a row takes.
	//
	// maskWords is (idSpace+63)/64, so it is 1 for a set of 8 ids whichever
	// form was built — and `isWide()` used to be `maskWords > 1`. Once
	// buildAnchoredUnionDFA gained forceWideAll, a small set
	// with a Backtracking member began building WIDE while maskWords stayed 1,
	// and every reader keyed on isWide() then went to the narrow tables that
	// the wide path never emits: match_any read acceptOff == -1 and trapped on
	// a load at 0xFFFFFFFF. The two questions now have two fields.
	wideAccept  bool
	rowBytes    int
	bitmapBytes int
	distinctIDs int // the `scan_all` early-exit target: ids this union can set
	// idMask is the set of GLOBAL ids this automaton can report, as a bitmask.
	// Narrow form only (an i64 cannot hold more than 64 ids); 0 on the wide
	// path, where nothing consults it.
	//
	// It exists so the bodies can tell whether the answer needs restricting to
	// the BUCKET universe at all: the automaton is built from the spec, which
	// still names patterns the packer dropped at the state limit, so
	// idMask &^ fullIDMask() is exactly "ids this walk can set that no bucket
	// answers for". When that is empty — the ordinary case — the masking is a
	// no-op and is not emitted.
	idMask      uint64
	midReprOff  int32
	eofReprOff  int32
	midWordsOff int32
	eofWordsOff int32

	dataBytes []byte
	dataSegs  int
	tableEnd  int32
}

// isWide reports whether this automaton carries the >64-id accept form.
// isWide reports whether the WIDE accept form was emitted — per-state
// representative ids plus bitmap rows — rather than the u64 accept/eof tables.
// See wideAccept for why this is not `maskWords > 1`.
func (u *unionScanDFA) isWide() bool { return u != nil && u.wideAccept }

// maxUnionScanStates bounds the subset construction. The construction is a
// `.*`-prefixed union, so it is larger than the plain union it replaces —
// measured at 1.6x to 4.2x on the shapes that reach it — but it is
// still a determinisation and can blow up. Over budget, the set keeps the
// per-position path it has today.
const maxUnionScanStates = 4096

// maxUnionScanIDs bounds the ID SPACE the one-pass automaton will serve, which
// is a different budget from maxUnionScanStates: that one bounds the
// determinisation, this one bounds the per-state accept ROW (rowBytes =
// 8*ceil(idSpace/64)) and the straight-line WASM that ORs it into the caller's
// bitmap — one unrolled word per 64 ids, in the body, per accepting state.
//
// 256 keeps that at four words. It was 64 before the wide accept form, not as a
// budget but because the accumulator was a single u64; the six classchain scan
// rows were the cost of treating that representation limit as an eligibility
// limit — a 128-pattern set fell all the way back to the per-position bucket
// walk at ~168 fuel/byte against the union pass's 24.7.
const maxUnionScanIDs = 256

// unionTableBudget is the size above which the transition matrix is byte-class
// compressed, mirroring the DFA engine's own "compress once the table exceeds
// 32 KB" rule (docs/wasm.md).
//
// Measured 2026-08-24, four layouts against each other on the two-phase
// split's shapes, 100 KB no-match, fuel per byte and module bytes:
//
//   - u8 state ids are FASTER, not merely free: -2.0 fuel/byte, because the
//     entry index loses its `*2` shift. Applied unconditionally at <= 256
//     states.
//   - byte classes cost +3.0 fuel/byte — one extra classMap[byte] load. The
//     shl->mul on a non-power-of-two row costs nothing measurable: a 5-class
//     table paid the same +3.0 as a 2-class one.
//   - they buy 3.9x to 9.4x on the table. mostly-fallback-2+3 went 356,374
//     -> 39,413 module bytes, and the literal-less fallback-3 went 354,386
//     -> 37,655, which is BELOW what it cost before any of this work.
//
// Hence the threshold rather than always-on: a small automaton keeps the
// faster uncompressed row, and only the tables big enough to matter pay the
// extra load. Every mixed set measured has an 18-state phase 2 (4,608 bytes
// under u8) and stays uncompressed; the 632-state ones are 323,584 bytes and
// always compress.
const unionTableBudget = 32 * 1024

// buildUnionScanDFA constructs the start-anywhere automaton for a set, or
// returns nil when the set is not eligible.
//
// Eligibility is deliberately narrow, because every exclusion here is a case
// where a single forward pass cannot answer the question:
//
//   - Word boundaries and (?m) line anchors need the prev-byte context tables
//     (prevWasWord / prevWasNewline) that the per-position path threads
//     through midAcceptNW/W/NL. A context-free one-pass loop would silently
//     get those patterns wrong, so such sets are excluded outright.
//   - Ids at or above maxUnionScanIDs, which bounds the per-state accept row.
//   - A pattern that cannot be re-parsed is skipped everywhere else too, and
//     a union missing a pattern would under-report.
//
// wantAcceptRows asks for the per-state accept BITMAP ROWS even when the set
// exports no `scan_all` — the gated find preflight reads them in its wide form
// . It has no effect on a narrow build, where
// the u64 accept pair is emitted instead and the rows do not exist at all.
func buildUnionScanDFA(spec SetSpec, tableBase int32, wantAcceptRows bool) *unionScanDFA {
	if len(spec.Patterns) == 0 {
		return nil
	}

	// The id space this automaton must represent, taken from the ids it can
	// actually set and NOT from spec.IDSpaceSize. Two reasons, and they pull
	// the same way: a named subset can declare an id space of 128 while every
	// id it holds is below 64, and reading the declared bound would push such
	// a set into the wide form and change a module that has no need to move;
	// and a row sized by the ids present can never be wider than the caller's
	// bitmap, which is sized by the declared bound and therefore at least as
	// large (the id-space hazard, in the direction that is safe).
	maxID := -1
	for _, id := range spec.PatternIDs {
		if id > maxID {
			maxID = id
		}
	}
	idSpace := maxID + 1
	if idSpace > maxUnionScanIDs || len(spec.Patterns) > maxUnionScanIDs {
		return nil
	}
	// Exactly the old refusal, restated as a representation choice: below the
	// threshold everything is emitted as it always was, byte for byte.
	wide := idSpace > wideBitmapThreshold || len(spec.Patterns) > wideBitmapThreshold

	progs := make([]*syntax.Prog, 0, len(spec.Patterns))
	for _, p := range spec.Patterns {
		ast := patternFullAST(p)
		if ast == nil {
			return nil
		}
		pr, err := syntax.Compile(ast.Simplify())
		if err != nil {
			return nil
		}
		progs = append(progs, pr)
	}

	// leftmostFirst=false in both arms: the question is which patterns match
	// ANYWHERE, so every live thread must be kept. Pruning to the
	// highest-priority thread is what a leftmost-first search wants and would
	// lose lower-priority patterns' accepts here.
	var d *dfa
	var ok bool
	if wide {
		// newDFAWide records per-state SORTED lists of pattern INDICES
		// (acceptWide/midAcceptWide) instead of a u64 mask — G17 built it for
		// the >64-pattern buckets and it answers exactly this question. Its
		// u64 maps degrade to "bit 1 = something accepts here" on this path
		// (pBits is nil), which is why nothing below reads them: the lists are
		// the authority, and the state identity that keeps two differently
		// accepting states apart is the NFA set itself, not the mask.
		prog, patternIdx := buildStartAnywhereUnionProgIndexed(progs)
		d, ok = newDFAWide(prog, false, maxUnionScanStates, patternIdx)
	} else {
		prog, patternBits := buildStartAnywhereUnionProg(progs, 64)
		d, ok = newDFA(prog, false, false, maxUnionScanStates, patternBits)
	}
	if !ok {
		return nil
	}
	if d.hasWordBoundary || d.hasNewlineBoundary {
		return nil // needs prev-byte context this loop does not carry
	}
	if d.numStates > maxUnionScanStates || d.numStates == 0 {
		return nil
	}

	u := &unionScanDFA{
		numStates: d.numStates, startState: d.start, midStartState: d.midStart,
		maskWords: 1, midReprOff: -1, eofReprOff: -1, midWordsOff: -1, eofWordsOff: -1,
	}
	if !wide {
		for _, id := range spec.PatternIDs {
			if id >= 0 && id < 64 {
				u.idMask |= uint64(1) << uint(id)
			}
		}
	}
	if wide {
		u.wideAccept = true
		u.maskWords = (idSpace + 63) / 64
		u.rowBytes = u.maskWords * 8
		u.bitmapBytes = (idSpace + 7) / 8
		seen := make(map[int]bool, len(spec.PatternIDs))
		for _, id := range spec.PatternIDs {
			seen[id] = true
		}
		u.distinctIDs = len(seen)
	}
	if d.midStart < 0 || d.midStart >= d.numStates {
		return nil
	}

	// The `.*` prefix keeps a live thread at every position, so no byte can
	// lead to the dead state. Verified rather than assumed: a -1 here would
	// mean the loop below reads a state id that does not exist.
	for st := 0; st < d.numStates; st++ {
		for b := 0; b < 256; b++ {
			if next := d.transitions[st*256+b]; next < 0 || next >= d.numStates {
				return nil
			}
		}
	}

	// Mid-accept-first renumbering.
	//
	// Every byte of every scan asks the same question — "can a match END here?"
	// — and it used to be answered by LOADING the state's accept entry: a u64
	// mask in the narrow form, a representative id in the wide one. Partitioned
	// this way the question becomes `state < midAcceptLimit`, a compare against
	// a constant, and the load happens only where the answer is yes. On input
	// that matches nothing, which is where a scan spends its time, that is
	// never.
	//
	// This is the DFA engine's own reorderAcceptFirst trick (engine_dfa.go)
	// applied to the union's own table build. It is done here rather than
	// through dfaTable because the union emits its tables directly from the
	// dfa, and because the partition it needs is MID-accept, not the
	// end-of-input accept dfaTable partitions by: the two are different sets of
	// states, and the end-of-input one is read once per call, where a load
	// costs nothing worth reordering for.
	midAccepts := func(s int) bool {
		if wide {
			return len(d.midAcceptWide[s]) > 0
		}
		return d.midAccepting[s] != 0
	}
	oldToNew := make([]int, d.numStates)
	newToOld := make([]int, d.numStates)
	next := 0
	for pass := 0; pass < 2; pass++ {
		want := pass == 0
		for s := 0; s < d.numStates; s++ {
			if midAccepts(s) == want {
				oldToNew[s] = next
				newToOld[next] = s
				next++
			}
		}
	}
	for s := 0; s < d.numStates; s++ {
		if midAccepts(s) {
			u.midAcceptLimit++
		}
	}
	u.startState = oldToNew[d.start]
	u.midStartState = oldToNew[d.midStart]

	u.stateWidth, u.numClasses = 2, 256
	var classMap [256]byte
	if d.numStates <= 256 {
		u.stateWidth = 1
	}
	if d.numStates*256*u.stateWidth > unionTableBudget {
		// Byte classes group BYTES that every state treats alike, which is
		// invariant under renumbering the states — so this may be computed
		// from the pre-permutation table.
		cm, _, nc := computeByteClasses(dfaTableFrom(d))
		if nc < 256 {
			classMap, u.numClasses = cm, nc
		}
	}
	rowLen := u.numClasses * u.stateWidth
	trans := make([]byte, d.numStates*rowLen)
	for newSt := 0; newSt < d.numStates; newSt++ {
		oldSt := newToOld[newSt]
		for b := 0; b < 256; b++ {
			col := b
			if u.numClasses < 256 {
				col = int(classMap[b])
			}
			next := uint16(oldToNew[d.transitions[oldSt*256+b]])
			if u.stateWidth == 1 {
				trans[newSt*rowLen+col] = byte(next)
			} else {
				binary.LittleEndian.PutUint16(trans[newSt*rowLen+col*2:], next)
			}
		}
	}

	// Remap each pattern's bit position to its GLOBAL id, so the accumulated
	// mask is directly the set's answer and needs no translation at runtime.
	remap := func(bits uint64) uint64 {
		var out uint64
		for k := 0; k < len(spec.Patterns) && k < 64; k++ {
			if bits&(1<<uint(k)) != 0 {
				out |= 1 << uint(spec.PatternIDs[k])
			}
		}
		return out
	}
	off := tableBase
	if u.numClasses < 256 {
		u.classMapOff = off
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.classMapOff, classMap[:])...)
		u.dataSegs++
		off += 256
	}
	u.transOff = off
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.transOff, trans)...)
	u.dataSegs++
	off = u.transOff + int32(len(trans))

	if !wide {
		accept := make([]byte, d.numStates*8)
		eof := make([]byte, d.numStates*8)
		for newSt := 0; newSt < d.numStates; newSt++ {
			oldSt := newToOld[newSt]
			binary.LittleEndian.PutUint64(accept[newSt*8:], remap(d.midAccepting[oldSt]))
			binary.LittleEndian.PutUint64(eof[newSt*8:], remap(d.accepting[oldSt]))
		}
		// 8-ALIGNED. These are u64 tables read with an i64 load on every
		// mid-accepting byte, and the transition table above them can end
		// anywhere — an odd numClasses on a compressed u8 table makes `off`
		// odd. The wide rows below were already aligned; the narrow pair,
		// which is the hotter of the two, was not.
		off = (off + 7) &^ 7
		u.acceptOff = off
		u.eofOff = u.acceptOff + int32(len(accept))
		u.tableEnd = u.eofOff + int32(len(eof))
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.acceptOff, accept)...)
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofOff, eof)...)
		u.dataSegs += 2
		return u
	}

	// Wide: the u64 pair above is not emitted at all, so acceptOff/eofOff stay
	// at their zero value and emitUnionScanBody refuses to read them.
	u.acceptOff, u.eofOff = -1, -1
	// The repr tables are i32 loads; the rows below are i64. Both get their
	// natural alignment rather than inheriting the transition table's end.
	off = (off + 3) &^ 3

	// wideRow turns one state's SORTED list of pattern indices into the two
	// forms the wide bodies read: a representative global id (plus one, so 0
	// can mean "accepts nothing") and a bitmap row shaped like the caller's.
	wideRow := func(list []uint16) (int32, []byte) {
		if len(list) == 0 {
			return 0, make([]byte, u.rowBytes)
		}
		row := make([]byte, u.rowBytes)
		repr := int32(0)
		for _, k := range list {
			if int(k) >= len(spec.PatternIDs) {
				// A pattern index the spec has no id for cannot be answered
				// for, and SKIPPING it is a silent "no match" for that pattern
				// in a wide scan — the one outcome no defensive `continue`
				// should produce. The lists come from the very progs built
				// from spec.Patterns, so this is unreachable by construction.
				panic("compile: union accept list names a pattern index outside the spec")
			}
			gid := spec.PatternIDs[k]
			row[gid/8] |= 1 << uint(gid%8)
			if repr == 0 {
				repr = int32(gid) + 1
			}
		}
		return repr, row
	}

	midRepr := make([]byte, d.numStates*4)
	eofRepr := make([]byte, d.numStates*4)
	midWords := make([]byte, d.numStates*u.rowBytes)
	eofWords := make([]byte, d.numStates*u.rowBytes)
	for newSt := 0; newSt < d.numStates; newSt++ {
		oldSt := newToOld[newSt]
		mr, mrow := wideRow(d.midAcceptWide[oldSt])
		er, erow := wideRow(d.acceptWide[oldSt])
		binary.LittleEndian.PutUint32(midRepr[newSt*4:], uint32(mr))
		binary.LittleEndian.PutUint32(eofRepr[newSt*4:], uint32(er))
		copy(midWords[newSt*u.rowBytes:], mrow)
		copy(eofWords[newSt*u.rowBytes:], erow)
	}

	u.midReprOff = off
	u.eofReprOff = u.midReprOff + int32(len(midRepr))
	u.tableEnd = u.eofReprOff + int32(len(eofRepr))
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.midReprOff, midRepr)...)
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofReprOff, eofRepr)...)
	u.dataSegs += 2

	// The bitmap rows serve `scan_all` — `scan_any` answers from the
	// representative — and, since item 22 fix 2a-wide, the gated find
	// preflight's wide alive walk, which ORs the same rows into its word
	// accumulators. A set that needs neither pays no table for them.
	if spec.ScanAll != "" || wantAcceptRows {
		// 8-aligned: the rows are read with i64 loads, and rowBytes is a
		// multiple of 8, so aligning the base aligns every row. Misalignment
		// would be legal (WASM treats the align field as a hint) and slow,
		// which is the combination that never shows up as a failure.
		u.tableEnd = (u.tableEnd + 7) &^ 7
		u.midWordsOff = u.tableEnd
		u.eofWordsOff = u.midWordsOff + int32(len(midWords))
		u.tableEnd = u.eofWordsOff + int32(len(eofWords))
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.midWordsOff, midWords)...)
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofWordsOff, eofWords)...)
		u.dataSegs += 2
	}
	return u
}

// unionUnroll is how many input bytes one iteration of the union scan's bulk
// loop steps. Four is what the task specifies: it takes
// the per-byte scaffolding from ~14 fuel to ~3.5 while adding three copies of
// a ~22-instruction step to two bodies per set.
const unionUnroll = 4

// A prev-state skip — `if state != lastOr` inside the mid-accept arm, so a
// repeat visit to the same accepting state records nothing — was BUILT here
// and REVERTED the same day.
// Its premise was that a run of identical bytes sits in ONE accepting state.
// It does not: the `.*`-prefixed subset construction allocates PARITY COPIES
// of states (the same NFA set arriving in two orders on alternate bytes), so
// a saturated run alternates between two accepting states, the skip never
// fires, and its test is pure per-byte cost — measured +20.9% on the very row
// it targeted (greedy-3 / 50K a's / scan_all). Do not rebuild it while the
// copies exist.
// tools/fuzz/set_union_prevstate_test.go keeps the coverage that episode
// added, including the fuel pin on the saturated-run shape.

// emitUnionEntryState selects the walk's start state from `from` and seeds the
// cursor pair.
//
// The entry state depends on `from`, and getting it wrong is SILENT. ptr/len
// describe the WHOLE input and `from` bounds only the search, so zero-width
// assertions must see real context: at from == 0 the scan really is at the
// start of text and `^`/\A may fire, so the begin-context start state is
// correct; at from > 0 it is not, and midStart is the same closure without
// that context. Entering startState at from > 0 makes `^[0-9]` match at
// position 1.
//
// Only two states are needed because buildUnionScanDFA refuses sets with word
// boundaries or (?m) line anchors — those would additionally need the
// prev-byte context states.
//
// lPos and lEnd are absolute INPUT POINTERS (pInPtr + offset), not offsets:
// that is what takes the per-byte address arithmetic down to one instruction
// (see emitUnionTransition).
//
// Written out three times before this — in both scan bodies and the alive-mask
// walk — with the reasoning in one of them.
func emitUnionEntryState(b []byte, u *unionScanDFA, pInPtr, pInLen, fromIdx, lState, lPos, lEnd byte) []byte {
	b = append(b, 0x20, fromIdx, 0x45) // from == 0
	b = append(b, 0x04, 0x40)          // if
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.startState))
	b = append(b, 0x21, lState)
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.midStartState))
	b = append(b, 0x21, lState)
	b = append(b, 0x0B) // end if
	b = append(b, 0x20, pInPtr, 0x20, fromIdx, 0x6A, 0x21, lPos)
	return append(b, 0x20, pInPtr, 0x20, pInLen, 0x6A, 0x21, lEnd)
}

// emitUnionScanBody emits the one-pass scan body.
//
// Signature matches the capability it replaces: (ptr, len, from) -> i32 for
// `scan` and `scan_any`, (ptr, len, from) -> i64 for the narrow `scan_all`.
//
//	state = start
//	for pos = from; pos < len; pos++ {
//	    state = trans[state*256 + input[pos]]
//	    acc  |= accept[state]          // match ending at pos+1
//	    if scan && acc != 0 { return 1 }
//	}
//	acc |= eof[state]
//
// `scan` exits at the first accepting state — it answers a yes/no question, so
// there is nothing to gain past the first match. `scan_all` accumulates to the
// end, but stops as soon as every id in the set is present.
//
// # The unroll
//
// The loop above runs at ~36 fuel/byte, of which only ~22 is the automaton:
// the rest is the bounds test, the position increment, the mode's exit test
// and the backward branch. unionUnroll bytes are therefore stepped per
// iteration, with that scaffolding paid once, and a tail loop handles the
// last len%unionUnroll bytes byte-at-a-time.
//
// What can and cannot be amortised:
//
//   - `acc |= accept[state]` CANNOT be: every transition has its own accept
//     set, and skipping one loses the ids that match ending there.
//   - `input[pos+k]` costs nothing extra: k folds into the load's memarg
//     offset, so an unrolled step is byte-for-byte the rolled step.
//   - the exit tests CAN move to once per block. Both are monotone — `scan`
//     exits on acc != 0, `scan_all` on acc == fullMask, and acc only ever
//     gains bits — so delaying either by up to unionUnroll-1 bytes changes
//     how much work is done, never the answer.
//
// The end-of-input OR must still see the TRUE final state, which it does: a
// block only runs when all its bytes are in range, so an early exit leaves
// lPos <= len, and the `pos >= len` guard admits the EOF accepts exactly when
// the whole input was consumed.
func emitUnionScanBody(u *unionScanDFA, mode setCapKind, fullMask uint64, tableMemIdx int) []byte {
	if u.isWide() {
		// A wide automaton emits no u64 accept tables at all, so every load
		// below would read the transition table as accept masks — wrong
		// answers, not a trap. The dispatch in set_emit.go is what keeps the
		// two apart; this turns a mistake there into a build failure.
		panic("compile: narrow union scan body emitted for a wide union automaton")
	}
	const (
		pInPtr = 0
		pInLen = 1
		pFrom  = 2
	)
	// locals: lPos, lState, lEnd (i32), lAcc (i64).
	//
	// lPos is an absolute INPUT POINTER (pInPtr + position) and lEnd is
	// pInPtr + len, so the per-byte load needs no address arithmetic at all —
	// see emitUnionTransition. Nothing here reports a position, which is what
	// makes the offset expendable.
	lPos, lState, lEnd, lAcc := byte(3), byte(4), byte(5), byte(6)
	// Does this walk need its answer restricted to fullMask's universe? Only
	// if it can set a bit fullMask does not name — i.e. only if the packer
	// dropped a pattern the automaton still carries.
	needMask := fullMask != 0 && u.idMask&^fullMask != 0
	var b []byte
	b = append(b, 0x02, 0x03, 0x7F, 0x01, 0x7E) // 3 x i32, 1 x i64

	b = append(b, 0x42, 0x00, 0x21, lAcc)
	// Entry state depends on `from`, and getting this wrong is silent.
	//
	// ptr/len describe the WHOLE input and `from` bounds
	// only the search, so zero-width assertions must see real context. At
	// from==0 the scan really is at the start of text and `^`/\A may fire, so
	// the begin-context start state is correct; at from>0 it is not the start
	// of text and entering that same state would make `^[0-9]` match at
	// position 1. midStart is the same closure without begin context.
	//
	// Only these two are needed because sets with word boundaries or (?m)
	// line anchors are refused in buildUnionScanDFA — those would additionally
	// need the prev-byte context states.
	b = emitUnionEntryState(b, u, pInPtr, pInLen, pFrom, lState, lPos, lEnd)

	// `from > len` yields the capability's "nothing" result. The loop guard
	// alone does NOT deliver that: the entry-state
	// accept below and the end-of-input accept after the loop both run
	// regardless of how the loop exited, so a `from` past the end still
	// reported every nullable and every `\z`-anchored pattern. `from == len`
	// is a REAL position and must still be evaluated, hence gt_u and not ge_u.
	b = append(b, 0x20, pFrom, 0x20, pInLen, 0x4B, 0x04, 0x40) // if from > len (u)
	switch mode {
	case capScanAny:
		b = append(b, 0x41, 0x7F) // i32.const -1
	default:
		b = append(b, 0x42, 0x00) // i64.const 0
	}
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if

	// Record the ENTRY state's accepts before consuming anything: a pattern
	// that matches EMPTY at `from` accepts here and nowhere else. The loop
	// below only ORs after a transition, so without this `\A` (and `a*`, and
	// any other nullable pattern) is silently dropped — found by
	// tools/fuzz FuzzSetCaps on {`$`, `\A`} over "0", which reported only
	// `$`.
	//
	// The mid-accept OR, guarded by the phase-2 partition: states below
	// midAcceptLimit are exactly the ones that can accept mid-string, so the
	// load happens only where it can contribute. A limit of 0 means no state
	// ever accepts mid-string and the arm is not emitted at all; a limit equal
	// to the state count means every state does, and the compare would be a
	// branch that is never false, so the OR is emitted bare.
	emitMidAccept := func(b []byte) []byte {
		if u.midAcceptLimit == 0 {
			return b
		}
		guarded := u.midAcceptLimit < u.numStates
		if guarded {
			b = append(b, 0x20, lState, 0x41)
			b = utils.AppendSLEB128(b, int32(u.midAcceptLimit))
			b = append(b, 0x49)       // i32.lt_u
			b = append(b, 0x04, 0x40) // if
		}
		b = append(b, 0x20, lAcc)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, u.acceptOff)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A) // + state*8
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0x84, 0x21, lAcc) // i64.or; set
		if guarded {
			b = append(b, 0x0B) // end if
		}
		return b
	}
	b = emitMidAccept(b)

	// One step over input[pos+k]: state = trans[state*rowLen + col], then the
	// guarded mid-accept OR. k rides in the load's memarg offset.
	emitStep := func(b []byte, k byte) []byte {
		b = emitUnionTransition(b, u, lPos, lState, k, tableMemIdx)
		return emitMidAccept(b)
	}

	// The mode's early exit, branching to $done at br depth `depth`.
	emitExit := func(b []byte, depth byte) []byte {
		switch mode {
		case capScanAny:
			// Any bit set answers the question: `scan_any` reports no start,
			// so the first id found is as good as any other (the contract leaves the
			// id unspecified).
			b = append(b, 0x20, lAcc, 0x42, 0x00, 0x52, 0x0D, depth) // acc != 0
		case capScanAll:
			// Every id present: nothing further can change the answer.
			//
			// ANDed rather than compared outright, for the reason
			// emitUnionAliveMask states at length: the automaton is built from
			// the SPEC while fullMask comes from the BUCKETS, so a pattern the
			// packer dropped at the state limit has a bit in acc and none in
			// fullMask. A bare == would then never fire (every call walks the
			// whole input), and when it did fire first the dropped pattern's
			// bit would be truncated out of the answer — making whether
			// scan_all reports it depend on input order.
			if fullMask == 0 {
				// Nothing to wait for and nothing to report: exiting here
				// would answer "all present" with acc == 0. Same suppression
				// emitUnionAliveMask makes.
				break
			}
			b = append(b, 0x20, lAcc, 0x42)
			if needMask {
				// Only when the walk can set a bit no bucket answers for. In
				// the ordinary case acc is already a subset of fullMask and
				// the AND is a no-op — worth avoiding, since this runs once
				// per 4-byte block.
				b = utils.AppendSLEB128_64(b, int64(fullMask))
				b = append(b, 0x83) // i64.and
				b = append(b, 0x42)
			}
			b = utils.AppendSLEB128_64(b, int64(fullMask))
			b = append(b, 0x51, 0x0D, depth) // (acc & fullMask) == fullMask
		}
		return b
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x02, 0x40) // block $bulk_exit
	b = append(b, 0x03, 0x40) // loop $bulk

	// pos + unionUnroll > len → the block would read past the end: leave the
	// bulk loop and finish in the tail. Unsigned, and no overflow to worry
	// about: pos <= len < 2^31 on entry (the from > len case already returned).
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A)
	b = append(b, 0x20, lEnd, 0x4B, 0x0D, 0x01) // gt_u → br $bulk_exit

	for k := byte(0); k < unionUnroll; k++ {
		b = emitStep(b, k)
	}
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A, 0x21, lPos)
	b = emitExit(b, 0x02) // → $done, past $bulk and $bulk_exit
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $bulk
	b = append(b, 0x0B) // end block $bulk_exit

	b = append(b, 0x03, 0x40)                               // loop $tail
	b = append(b, 0x20, lPos, 0x20, lEnd, 0x4F, 0x0D, 0x01) // cur >= end → br $done
	b = emitStep(b, 0)
	b = emitExit(b, 0x01) // → $done
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $tail
	b = append(b, 0x0B)       // end loop $tail
	b = append(b, 0x0B)       // end block $done

	// End-of-input accepts. Reached whether the loop ran out of input or
	// broke early; in the early-exit cases the extra OR cannot change a
	// non-zero acc for `scan`, and for `scan_all` a full mask stays full.
	b = append(b, 0x20, lPos, 0x20, lEnd, 0x4F, 0x04, 0x40) // if cur >= end
	b = append(b, 0x20, lAcc)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, lAcc)
	b = append(b, 0x0B) // end if

	// Restrict the answer to the BUCKET universe. The automaton is built from
	// the spec, which still names patterns the packer dropped at the state
	// limit, and reporting one of those from scan_any/scan_all while `find`
	// answers nothing for it is an inconsistency this masking prevents.
	// Masking here is also what makes the early exits above sound: they
	// already reason in fullMask's universe.
	//
	// Emitted only when the walk can actually set such a bit — see
	// unionScanDFA.idMask. With nothing dropped this is a no-op and the body
	// is byte-identical to the one before U3.
	if needMask {
		b = append(b, 0x20, lAcc, 0x42)
		b = utils.AppendSLEB128_64(b, int64(fullMask))
		b = append(b, 0x83, 0x21, lAcc) // acc &= fullMask
	}

	switch mode {
	case capScanAny:
		// Lowest set bit's index IS a global pattern id: buildUnionScanDFA
		// remaps every accept mask through spec.PatternIDs, so no translation
		// is needed here. -1 when the accumulator is empty.
		b = append(b, 0x20, lAcc, 0x42, 0x00, 0x51, 0x04, 0x7F) // if acc == 0 (result i32)
		b = append(b, 0x41, 0x7F)                               // -1
		b = append(b, 0x05)                                     // else
		b = append(b, 0x20, lAcc, 0x7A, 0xA7)                   // i64.ctz; i32.wrap_i64
		b = append(b, 0x0B)                                     // end if
	default:
		b = append(b, 0x20, lAcc)
	}
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitUnionScanWideBody is emitUnionScanBody for an automaton whose ids do not
// fit a u64. Same pass, same entry-state rule, same
// unroll; what changes is how an accepting state is RECOGNISED and RECORDED.
//
// Signatures are the ones the capability already declares, unchanged:
//
//	scan_any (ptr, len, from)          -> i32   a global id, or -1
//	scan_all (ptr, len, from, out_ptr) -> i32   count of distinct patterns
//
// # Recognition
//
// The narrow body ORs an i64 accept mask into an accumulator on every byte,
// because the mask IS its answer. Here the answer lives elsewhere, so each byte
// only asks "does this state accept anything" — one i32 load of midRepr and a
// branch, taken only where a match ends. On input that matches nothing, which
// is where a scan spends its time, that is strictly less work than the narrow
// body does.
//
// # Recording
//
//   - scan_any returns midRepr[state]-1 on the spot. The contract leaves which id it
//     reports unspecified, so the representative baked into the table is a
//     complete answer and no accumulator is needed at all.
//   - scan_all ORs the state's bitmap row into the caller's bitmap, counting
//     the 0->1 transitions with popcnt so the returned count stays DISTINCT
//     PATTERNS — emitSetAllBits' contract, which is also why the export
//     requires an all-zero bitmap on entry. Idempotence comes free: OR-ing the
//     same row twice adds nothing and counts nothing, so no visited-state
//     bookkeeping is needed to keep the count honest.
//
// # The write must stay inside the caller's allocation
//
// The bitmap is ceil(idSpace/8) BYTES (generate/set_stub.go's bitmapBytes; all
// six stub generators allocate exactly that). An id space that is not a
// multiple of 64 therefore has a final PARTIAL word, and an i64 store there
// would write up to seven bytes past the caller's array — the id-space class of
// defect: silent, data-dependent memory corruption rather than a wrong answer.
// So whole words are emitted only while the whole word fits, and the remainder
// is done byte at a time.
func emitUnionScanWideBody(u *unionScanDFA, mode setCapKind, tableMemIdx int) []byte {
	if !u.isWide() {
		panic("compile: wide union scan body emitted for a narrow union automaton")
	}
	if mode != capScanAny && mode != capScanAll {
		panic("compile: wide union scan body emitted for an unsupported capability")
	}
	if mode == capScanAll && u.midWordsOff < 0 {
		panic("compile: wide scan_all body emitted without accept bitmap rows")
	}
	const (
		pInPtr  = 0
		pInLen  = 1
		pFrom   = 2
		pOutPtr = 3 // scan_all only
	)
	var b []byte
	// lPos/lState are shared; the rest are scan_all's recording scratch.
	localBase := byte(3)
	if mode == capScanAll {
		localBase = 4
	}
	// lPos is an absolute INPUT POINTER and lEnd is pInPtr + len, so the
	// per-byte load needs no address arithmetic (see emitUnionTransition).
	lPos, lState := localBase, localBase+1
	// scan_all's recording scratch; scan_any declares only the cursor pair and
	// the end bound, since it keeps nothing between bytes at all.
	// lEnd is the LAST i32 of each shape, so the i64 pair that follows it
	// shifts up by one against the pre-pointer layout.
	lCount, lAddr := localBase+2, localBase+3
	lOld32, lNew32 := localBase+4, localBase+5
	lEnd := localBase + 2
	lOld64, lNew64 := localBase+7, localBase+8
	if mode == capScanAll {
		lEnd = localBase + 6
		b = append(b, 0x02, 0x07, 0x7F, 0x02, 0x7E) // 7 x i32, 2 x i64
	} else {
		b = append(b, 0x01, 0x03, 0x7F) // 3 x i32
	}

	// repr[state], left on the stack.
	loadRepr := func(b []byte, off int32) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, off)
		b = append(b, 0x20, lState, 0x41, 0x02, 0x74, 0x6A) // + state*4
		return appendTableLoad32(b, tableMemIdx, 0)
	}

	// OR one state's accept row into the caller's bitmap, adding the number of
	// bits that flipped 0->1 to lCount.
	orRow := func(b []byte, off int32) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, off)
		b = append(b, 0x20, lState, 0x41)
		if sh := shiftForRow(u.rowBytes); sh >= 0 {
			b = utils.AppendSLEB128(b, int32(sh))
			b = append(b, 0x74, 0x6A) // shl; add
		} else {
			b = utils.AppendSLEB128(b, int32(u.rowBytes))
			b = append(b, 0x6C, 0x6A) // mul; add
		}
		b = append(b, 0x21, lAddr)

		full := (u.bitmapBytes / 8) * 8
		for o := 0; o < full; o += 8 {
			// old = bitmap[o]
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A, 0x29, 0x00, 0x00) // i64.load align=0, memory 0
			b = append(b, 0x21, lOld64)
			// new = old | row[o]
			b = append(b, 0x20, lOld64)
			b = append(b, 0x20, lAddr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A)
			b = appendTableLoad64(b, tableMemIdx)
			b = append(b, 0x84, 0x21, lNew64) // i64.or
			// bitmap[o] = new
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A, 0x20, lNew64)
			b = append(b, 0x37, 0x00, 0x00) // i64.store align=0, memory 0
			// count += popcnt(new ^ old)
			b = append(b, 0x20, lCount)
			b = append(b, 0x20, lNew64, 0x20, lOld64, 0x85) // i64.xor
			b = append(b, 0x7B, 0xA7)                       // i64.popcnt; i32.wrap_i64
			b = append(b, 0x6A, 0x21, lCount)
		}
		for o := full; o < u.bitmapBytes; o++ {
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A, 0x2D, 0x00, 0x00) // i32.load8_u, memory 0
			b = append(b, 0x21, lOld32)
			b = append(b, 0x20, lOld32)
			b = append(b, 0x20, lAddr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A)
			b = appendTableLoad8u(b, tableMemIdx)
			b = append(b, 0x72, 0x21, lNew32) // i32.or
			b = append(b, 0x20, pOutPtr, 0x41)
			b = utils.AppendSLEB128(b, int32(o))
			b = append(b, 0x6A, 0x20, lNew32)
			b = append(b, 0x3A, 0x00, 0x00) // i32.store8, memory 0
			b = append(b, 0x20, lCount)
			b = append(b, 0x20, lNew32, 0x20, lOld32, 0x73) // i32.xor
			b = append(b, 0x69)                             // i32.popcnt
			b = append(b, 0x6A, 0x21, lCount)
		}
		return b
	}

	// The whole "this state accepts" arm: record, and for scan_all leave early
	// once every id the set can report has been seen. That target is the count
	// of DISTINCT IDS, never the id space — a named subset leaves gaps it can
	// never fill, and comparing against the bound would make the exit dead.
	//
	// `mid` selects how the arm is OPENED, and the two are genuinely different
	// questions. Mid-string, the phase-2 partition answers it with a compare
	// against a constant — states below midAcceptLimit are exactly those that
	// can accept — so the representative is loaded only inside the branch, and
	// is known non-zero there by construction. At end of input there is no
	// partition (a different set of states accepts there, and the arm runs once
	// per call), so it keeps the load-and-test it always had.
	emitAcceptArm := func(b []byte, reprOff, wordsOff int32, exit, mid bool) []byte {
		guarded := true
		if mid {
			switch {
			case u.midAcceptLimit == 0:
				return b // no state can accept mid-string: no arm at all
			case u.midAcceptLimit >= u.numStates:
				guarded = false // every state can: the compare is never false
			default:
				b = append(b, 0x20, lState, 0x41)
				b = utils.AppendSLEB128(b, int32(u.midAcceptLimit))
				b = append(b, 0x49)       // i32.lt_u
				b = append(b, 0x04, 0x40) // if
			}
		} else {
			b = loadRepr(b, reprOff)
			b = append(b, 0x04, 0x40) // if it is non-zero
		}
		switch mode {
		case capScanAny:
			// Loaded INSIDE the branch rather than kept in a local across the
			// loop: what the hot path needs is the yes/no, and the id itself
			// is needed only on the byte that ends the scan.
			b = loadRepr(b, reprOff)
			b = append(b, 0x41, 0x01, 0x6B, 0x0F) // return repr-1
		default: // capScanAll
			b = orRow(b, wordsOff)
			if exit {
				b = append(b, 0x20, lCount, 0x41)
				b = utils.AppendSLEB128(b, int32(u.distinctIDs))
				b = append(b, 0x4E, 0x04, 0x40)   // i32.ge_s; if
				b = append(b, 0x20, lCount, 0x0F) // return count
				b = append(b, 0x0B)
			}
		}
		if guarded {
			b = append(b, 0x0B) // end if
		}
		return b
	}

	// Entry state: at from == 0 the scan really is at the start of text and
	// `^`/\A may fire; at from > 0 it is not, and midStart is the same closure
	// without that context. Identical to the narrow body, and getting it wrong
	// is silent.
	b = emitUnionEntryState(b, u, pInPtr, pInLen, pFrom, lState, lPos, lEnd)

	// `from > len` yields the capability's "nothing" answer. gt_u, not
	// ge_u: `from == len` is a real position, and a pattern matching empty
	// there must still be reported.
	b = append(b, 0x20, pFrom, 0x20, pInLen, 0x4B, 0x04, 0x40)
	if mode == capScanAny {
		b = append(b, 0x41, 0x7F) // -1
	} else {
		b = append(b, 0x41, 0x00) // count 0
	}
	b = append(b, 0x0F, 0x0B)

	// The ENTRY state's own accepts, before consuming anything: a pattern that
	// matches EMPTY at `from` accepts here and nowhere else, and the loop below
	// only tests after a transition.
	b = emitAcceptArm(b, u.midReprOff, u.midWordsOff, true, true)

	step := func(b []byte, k byte) []byte {
		b = emitUnionTransition(b, u, lPos, lState, k, tableMemIdx)
		return emitAcceptArm(b, u.midReprOff, u.midWordsOff, true, true)
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x02, 0x40) // block $bulk_exit
	b = append(b, 0x03, 0x40) // loop $bulk
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A)
	b = append(b, 0x20, lEnd, 0x4B, 0x0D, 0x01) // cur+4 > end (u) -> $bulk_exit
	for k := byte(0); k < unionUnroll; k++ {
		b = step(b, k)
	}
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $bulk
	b = append(b, 0x0B)       // end loop $bulk
	b = append(b, 0x0B)       // end block $bulk_exit

	b = append(b, 0x03, 0x40)                               // loop $tail
	b = append(b, 0x20, lPos, 0x20, lEnd, 0x4F, 0x0D, 0x01) // cur >= end -> $done
	b = step(b, 0)
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $tail
	b = append(b, 0x0B)       // end loop $tail
	b = append(b, 0x0B)       // end block $done

	// End-of-input accepts. No `pos >= len` guard, unlike the narrow body: this
	// body's only exit from the loops is the tail's own `pos >= len` test —
	// every accept leaves through `return`, not through a break — so the guard
	// would be a branch that can never be false. The narrow body needs it
	// because its monotone early exits do leave with pos < len.
	b = emitAcceptArm(b, u.eofReprOff, u.eofWordsOff, false, false)

	if mode == capScanAny {
		b = append(b, 0x41, 0x7F) // nothing matched
	} else {
		b = append(b, 0x20, lCount)
	}
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// unionScanDiagOf describes a union-automaton build for --diag-json.
//
// The refusal reason is reconstructed rather than threaded out of
// buildUnionScanDFA: everything it decides internally is reported as
// "construction", and only the id-space bound — the one an author can act on
// by splitting a set — is distinguished, because it is the bound the wide
// accept form raised and the one most likely to be hit next.
func unionScanDiagOf(u *unionScanDFA, spec SetSpec, phase2 bool) *UnionScanDiag {
	d := &UnionScanDiag{Phase2: phase2}
	if u == nil {
		maxID := -1
		for _, id := range spec.PatternIDs {
			if id > maxID {
				maxID = id
			}
		}
		d.Refused = "construction"
		if maxID+1 > maxUnionScanIDs || len(spec.Patterns) > maxUnionScanIDs {
			d.Refused = "id_space"
		}
		return d
	}
	d.Used = true
	d.Wide = u.isWide()
	d.States = u.numStates
	d.MaskWords = u.maskWords
	return d
}

// dataBlob is one region of a set's emitted data: its bytes and how many
// active segments they encode.
type dataBlob struct {
	bytes []byte
	segs  int
}

// dataBlobs is the ONE authority on what data a set contributes, in the order
// assembleModuleWithSets concatenates it.
//
// It replaces three hand-maintained parallel lists — the rawData appends and
// the totalSegs sum in the assembler, and dataTop's own blob list — whose
// comments each said they "MUST stay in step". They did not: the class was
// fixed twice on this branch (the BT regions, then the anchored eofBitmask),
// and a table missing from the accounting is a table the module writes but
// does not size for, which relocates the NEXT set on top of this one.
func (cs *compiledSet) dataBlobs() []dataBlob {
	out := []dataBlob{
		{cs.dataBytes, cs.dataSegCount},
		{cs.prefixDataBytes, cs.prefixDataSegCount},
		{cs.acDataBytes, cs.acDataSegCount},
		{cs.teddyDataBytes, cs.teddyDataSegCount},
		{cs.anchoredDataBytes, cs.anchoredDataSegs},
		{cs.startableDataBytes, cs.startableDataSegs},
	}
	if cs.unionScan != nil {
		out = append(out, dataBlob{cs.unionScan.dataBytes, cs.unionScan.dataSegs})
	}
	if cs.phase2Union != nil {
		out = append(out, dataBlob{cs.phase2Union.dataBytes, cs.phase2Union.dataSegs})
	}
	return out
}

// dataTop returns one past the highest address this set's tables occupy,
// derived from the segments actually emitted rather than from a running offset
// or a length sum.
func (cs *compiledSet) dataTop() int64 {
	var top int64
	for _, blob := range cs.dataBlobs() {
		if e := dataSegmentsTop(blob.bytes); e > top {
			top = e
		}
	}
	return top
}

// usesUnionScan reports whether capability kind is served by the one-pass
// automaton rather than the per-position bucket walk.
//
// `scan_any` qualifies since decision (10) dropped its start: it needs no id
// space check of its own because buildUnionScanDFA already refuses any set with
// an id >= 64. The wide `scan_all` ABI is excluded because it writes a
// caller-provided bitmap.
func (cs *compiledSet) usesUnionScan(kind setCapKind) bool {
	if cs.unionScan == nil {
		return false
	}
	switch kind {
	case capScanAny:
		return true
	case capScanAll:
		// Two bodies, two ABIs, and the automaton's own representation picks
		// between them.
		//
		// The NARROW walk answers with an i64 accumulator and takes no
		// out_ptr, so it can only serve a capability using that ABI. Keyed on
		// wideAll() rather than on the id space alone because the id space is
		// no longer the only thing that selects the wide form: a Backtracking
		// member forces it at any size. Testing
		// the size here left the walk serving a capability that had already
		// moved to the memory form — an i64 pushed where an i32 was expected,
		// i.e. a module that does not validate.
		//
		// The WIDE union body writes the caller's bitmap itself, so it serves
		// the memory ABI directly (item 21 phase 1). Its rows are emitted only
		// for a set that exports `scan_all`, so that is checked and not
		// assumed. A set made wide by a BT member alone keeps a narrow
		// automaton and stays on the walk.
		if cs.unionScan.isWide() {
			return cs.wideAll() && cs.unionScan.midWordsOff >= 0
		}
		return !cs.wideAll()
	}
	return false
}

// fullIDMask is the accumulator value at which `scan_all` can stop: every id
// the set can report is present, so no further input can change the answer.
//
// Built from the ids actually emitted rather than from idSpaceSize(), because
// a named subset leaves gaps — a set of patterns 0, 5 and 9 can never set the
// bits between them, and comparing against a dense mask would mean the early
// exit never fires.
func (cs *compiledSet) fullIDMask() uint64 {
	return cs.fullIDMaskWords(1)[0]
}

// fullIDMaskWords is fullIDMask over an id space wider than one u64: word w
// holds ids [64w, 64w+64), matching the bit order of the union automaton's
// accept ROWS (buildUnionScanDFA's wideRow sets bit gid%8 of byte gid/8, which
// an i64 load at word w reads as bit gid%64).
//
// Ids at or above 64*words are dropped rather than folded, exactly as
// fullIDMask drops ids past 63: the mask's only consumer is an early exit whose
// safe direction is to fire LATE, and an id with no bit simply keeps the walk
// going.
func (cs *compiledSet) fullIDMaskWords(words int) []uint64 {
	m := make([]uint64, words)
	for _, ids := range cs.patternIDs {
		for _, id := range ids {
			if w := id / 64; id >= 0 && w < words {
				m[w] |= 1 << uint(id%64)
			}
		}
	}
	return m
}

// preflightAliveWords is how many i64 locals the find preflight's alive mask
// occupies — 1 for every narrow set, ceil(idSpace/64) for a wide one.
//
// It mirrors emitSetMatchFnFinalScalar's own choice of preflight arm: the
// absence prefilter is capped at absenceMaxPatterns (64) ids and always answers
// in a single word, so a set taking that path is narrow whatever its automaton
// would have been.
func (cs *compiledSet) preflightAliveWords() int {
	if cs.usesAbsencePrefilter() || cs.unionScan == nil {
		return 1
	}
	return cs.unionScan.maskWords
}

// emitUnionAliveMask runs the start-anywhere union automaton over [from, len)
// and leaves in aliveLocal the i64 mask of pattern ids that match SOMEWHERE in
// that range.
//
// This is emitUnionScanBody's loop without the capability epilogue, and it
// keeps that body's entry-state rule: at from == 0 the
// scan really is at start of text and `^`/\A may fire, so the begin-context
// state is correct; at from > 0 it is not, and midStart is. Getting that wrong
// is silent, which is why it is restated here rather than assumed.
// fromIdx is the index of an i32 holding the position the walk starts at —
// see emitLiteralAbsenceMask for why it is not the hardcoded 2 it once was.
//
// fullMask is the caller's fullIDMaskWords: once every id it names is alive the
// walk can stop, because the only consumer of this mask is "which patterns are
// DEAD" and the answer is already "none". This is what bounds the pass on
// matching input — the walk costs at most the bytes up to the first position
// where the last pattern shows alive, which a per-position drive has to cover
// anyway — and it is why the preflight can be offered to every eligible set
// instead of only to never-dying ones. An earlier candidate was a pass that
// cost the whole input and retired nothing. The test is
// ANDed rather than compared outright because the union is built from the SPEC
// while fullMask comes from the BUCKETS: a pattern the packer dropped has a
// bit here and not there, and a bare == would then never fire. Pass nil, or an
// all-zero mask, to suppress the exit.
//
// WIDTH. aliveLocal is the FIRST of
// u.maskWords consecutive i64 locals, and fullMask must be that long. The two
// forms differ only in how the accept entry is addressed and how many
// accumulators it lands in:
//
//   - narrow (maskWords == 1) reads the u64 accept tables at acceptOff/eofOff,
//     stride 8, into one accumulator;
//   - wide reads the accept ROWS at midWordsOff/eofWordsOff, stride rowBytes,
//     one i64 load per word — the same rows emitUnionScanWideBody ORs into the
//     caller's `_all` bitmap, read here into locals instead.
//
// Word w of the row holds ids [64w, 64w+64) because wideRow lays bits out by
// global id, so no remapping is needed on either path: the narrow tables are
// already remapped to global ids and the wide rows are built from them.
//
// The narrow arm emits byte for byte what it emitted before the width existed.
func emitUnionAliveMask(b []byte, u *unionScanDFA, lPos, lState, aliveLocal, fromIdx, lEnd byte, tableMemIdx int, fullMask []uint64) []byte {
	const (
		pInPtr = 0
		pInLen = 1
	)
	words := 1
	midOff, eofOff, stride := u.acceptOff, u.eofOff, 8
	if u.isWide() {
		if u.midWordsOff < 0 || u.eofWordsOff < 0 {
			panic("compile: wide union alive mask emitted without accept bitmap rows")
		}
		words, midOff, eofOff, stride = u.maskWords, u.midWordsOff, u.eofWordsOff, u.rowBytes
	}
	if len(fullMask) < words {
		fullMask = append(append([]uint64(nil), fullMask...), make([]uint64, words-len(fullMask))...)
	}
	anyFull := false
	for _, m := range fullMask[:words] {
		if m != 0 {
			anyFull = true
		}
	}

	// One state's accept entry ORed into the accumulators: `alive[w] |=
	// table[off + state*stride + 8w]`. The address constant folds the word
	// offset in, so a wide read costs exactly what the narrow one does per word.
	orAccepts := func(b []byte, off int32) []byte {
		for w := 0; w < words; w++ {
			b = append(b, 0x20, aliveLocal+byte(w))
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, off+int32(w*8))
			b = append(b, 0x20, lState, 0x41)
			if sh := shiftForRow(stride); sh >= 0 {
				b = utils.AppendSLEB128(b, int32(sh))
				b = append(b, 0x74, 0x6A) // shl; add
			} else {
				b = utils.AppendSLEB128(b, int32(stride))
				b = append(b, 0x6C, 0x6A) // mul; add
			}
			b = appendTableLoad64(b, tableMemIdx)
			b = append(b, 0x84, 0x21, aliveLocal+byte(w)) // i64.or
		}
		return b
	}

	for w := 0; w < words; w++ {
		b = append(b, 0x42, 0x00, 0x21, aliveLocal+byte(w))
	}
	b = emitUnionEntryState(b, u, pInPtr, pInLen, fromIdx, lState, lPos, lEnd)

	// The mid-accept OR, under the phase-2 partition — the same guard the scan
	// body uses, and for the same reason: this walk visits every byte of the
	// input once per drive, so a load it can skip is a load worth skipping.
	//
	// exitDepth >= 0 additionally leaves the walk once every id in fullMask is
	// alive. It sits INSIDE the mid-accept guard because that is the only place
	// aliveLocal can change, so a byte that ends no match pays nothing for it.
	emitAlive := func(b []byte, exitDepth int) []byte {
		if u.midAcceptLimit == 0 {
			return b
		}
		guarded := u.midAcceptLimit < u.numStates
		if guarded {
			b = append(b, 0x20, lState, 0x41)
			b = utils.AppendSLEB128(b, int32(u.midAcceptLimit))
			b = append(b, 0x49, 0x04, 0x40) // i32.lt_u; if
		}
		b = orAccepts(b, midOff)
		if exitDepth >= 0 && anyFull {
			d := exitDepth
			if guarded {
				d++ // the `if` above is one more level of nesting
			}
			// (alive[w] & full[w]) == full[w], ANDed across the words that have
			// anything to wait for. A word whose full mask is zero is satisfied
			// by every value, so testing it would be a compare that is always
			// true — dropped rather than emitted, which is what keeps the narrow
			// arm byte-identical to the single-word test it replaces.
			first := true
			for w := 0; w < words; w++ {
				if fullMask[w] == 0 {
					continue
				}
				b = append(b, 0x20, aliveLocal+byte(w), 0x42)
				b = utils.AppendSLEB128_64(b, int64(fullMask[w]))
				b = append(b, 0x83, 0x42) // i64.and
				b = utils.AppendSLEB128_64(b, int64(fullMask[w]))
				b = append(b, 0x51) // i64.eq
				if !first {
					b = append(b, 0x71) // i32.and
				}
				first = false
			}
			b = append(b, 0x0D, byte(d)) // br_if
		}
		if guarded {
			b = append(b, 0x0B)
		}
		return b
	}

	// Entry-state accepts: a pattern matching EMPTY at `from` accepts here and
	// nowhere else (for the same reason as in the scan body).
	// No early exit here: this runs before $done exists to branch to, and a set
	// whose every pattern matches empty is not the shape the exit is for.
	b = emitAlive(b, -1)

	// UNROLLED by unionUnroll, exactly as both scan bodies are. This walk runs
	// over the whole input once per drive, so paying the loop's bounds test
	// per byte where the scan bodies pay it per four was a difference with no
	// argument behind it — no comment claimed it was deliberate.
	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x02, 0x40) // block $bulk_exit
	b = append(b, 0x03, 0x40) // loop $bulk

	// pos + unionUnroll > end → finish in the tail.
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A)
	b = append(b, 0x20, lEnd, 0x4B, 0x0D, 0x01) // gt_u → br $bulk_exit
	for k := byte(0); k < unionUnroll; k++ {
		b = emitUnionTransition(b, u, lPos, lState, k, tableMemIdx)
		b = emitAlive(b, 2) // 2 = $done, past $bulk and $bulk_exit
	}
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $bulk
	b = append(b, 0x0B) // end block $bulk_exit

	b = append(b, 0x03, 0x40) // loop $tail
	b = append(b, 0x20, lPos, 0x20, lEnd, 0x4F, 0x0D, 0x01)
	b = emitUnionTransition(b, u, lPos, lState, 0, tableMemIdx)
	b = emitAlive(b, 1) // 1 = $done, past $tail
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $tail
	b = append(b, 0x0B) // end block $done

	// End-of-input accepts, guarded by pos >= len exactly as emitUnionScanBody
	// guards its own — the early exit above can leave the loop mid-input, where
	// this state's EOF accepts say nothing about what matches in the rest of
	// the input. Reading them anyway would only ever ADD alive bits, which is
	// the safe direction (fewer patterns retired), but the guard keeps the mask
	// meaning what its name says rather than relying on the consumer.
	b = append(b, 0x20, lPos, 0x20, lEnd, 0x4F, 0x04, 0x40) // if cur >= end
	b = orAccepts(b, eofOff)
	b = append(b, 0x0B) // end if
	return b
}

// usesGatedFindPreflight reports whether this set's gated `find` should run
// B′: one union preflight per drive, whose result is written back into the
// caller's gate array as a never-again sentinel.
func (cs *compiledSet) usesGatedFindPreflight() bool {
	if cs.unionScan == nil && !cs.usesAbsencePrefilter() {
		return false
	}
	// A WIDE automaton emits no acceptOff/eofOff u64 pair (item 21 phase 1), so
	// what it must have instead is the per-state accept ROWS the wide alive walk
	// reads (item 22 fix 2a-wide). Requiring them by their offsets rather than
	// by re-deriving who asked for them is the point: the rows are emitted for
	// `scan_all` OR at the gated preflight's own request, and if that request
	// never reached buildUnionScanDFA — a refusal it makes for reasons no
	// predicate here can reproduce — this must come back false. Reading a table
	// that was not emitted would be silent in the worst direction: a pattern
	// wrongly declared dead stops reporting matches.
	if cs.unionScan.isWide() && (cs.unionScan.midWordsOff < 0 || cs.unionScan.eofWordsOff < 0) {
		return false
	}
	return cs.gatedPreflightShape()
}

// gatedPreflightShape is usesGatedFindPreflight's structural half, answerable
// from the set alone — before the union automaton is built, which is what
// decides whether to build one at all (the same split overlapPreflightShape
// exists for).
//
// It used to be the engagement rule — offer the preflight only where a suffix
// DFA can walk forever, because the reverted Candidate A was a pass that cost the
// whole input and retired nothing. What retires that objection is
// emitUnionAliveMask's fullMask early exit (fix 2a prerequisite 2): the pass
// now stops at the first position where the last pattern shows alive, so on
// input the walk was going to cover anyway it costs a fraction of a pass, and
// on input where patterns really do match nowhere it retires them and the
// drive ends in emitGateJump's prologue. The OVERLAPPING twin keeps its
// never-dying test — item 11's refutations are about that body's economics,
// not this one's.
func (cs *compiledSet) gatedPreflightShape() bool {
	if cs.find == "" || cs.overlapping {
		return false
	}
	if cs.fe != frontendScalar {
		return false
	}
	// The alive mask is ceil(idSpace/64) i64 locals (item 22 fix 2a-wide), so
	// what bounds it here is the automaton's own id ceiling rather than one
	// word. Above maxUnionScanIDs no union is built at all, and an id with no
	// bit in the mask could never be retired.
	//
	// This used to be a flat `> 64` refusal, and it is what kept classchain-128
	// on the per-position walk for a whole no-match drive: the same verdict the
	// preflight computes in one pass was simply unrepresentable. The OVERLAPPING
	// twin below still refuses at 64 — its one-slot freshness guard reads
	// ids[0]'s gate, so every id must fit the word that guard is written for.
	if cs.idSpaceSize() > maxUnionScanIDs || cs.numPatterns() > maxUnionScanIDs {
		return false
	}
	// Sparse buckets are NOT excluded, unlike the overlapping twin: that one
	// applies its verdict through the i32 validMask, which set_sparse.go's
	// header forbids reading as authoritative for such a bucket, while this
	// one writes the caller's GATE ARRAY — which a sparse bucket's body reads
	// per pattern for itself.
	for _, b := range cs.buckets {
		if b.suffixDFA == nil {
			continue
		}
		if b.suffixDFA.hasWordBoundary || b.suffixDFA.hasNewlineBoundary {
			return false
		}
	}
	return true
}

// usesOverlappingFindPreflight reports whether this set's OVERLAPPING `find`
// should run the same preflight, keeping its verdict in the caller's gate
// array.
//
// The row this exists for is greedy-3's `[^\n]*ERROR` on newline-free input:
// a fallback pattern whose suffix DFA never dies, walked from every start
// position, which makes one overlapping call O(n^2). The verdict "this
// pattern matches nowhere at or after `from`" retires it from validMask, and
// the G9 liveness exit inside the suffix body then truncates the walk as soon
// as only retired patterns could still accept.
//
// It shares gatedFind's eligibility except for the two differences that
// matter:
//
//   - SPARSE buckets are excluded outright. The verdict is applied through
//     the i32 validMask, which is not authoritative for such a bucket (see
//     set_sparse.go's header), and the liveness exit reads the same mask.
//   - the id space must fit the i64 alive mask, as it must for the union walk
//     itself.
//
// The never-dying requirement is what keeps this off every other overlapping
// set: without it the preflight is that reverted Candidate A — a pass that costs
// the whole input and retires nothing.
func (cs *compiledSet) usesOverlappingFindPreflight() bool {
	if cs.unionScan.isWide() {
		return false // same reason as usesGatedFindPreflight; see there
	}
	return cs.overlapPreflightShape() &&
		(cs.unionScan != nil || cs.usesAbsencePrefilter())
}

// overlapPreflightShape is usesOverlappingFindPreflight minus the question of
// whether anything exists yet to COMPUTE the verdict with.
//
// Split out because the union automaton is built from this answer: a find-only
// overlapping set has no scan capability to build it for, so the table has to
// be requested by the preflight that will read it. Everything here is settled
// by bucket construction, which finishes first.
// It is the NARROWER of the two: overlapCanPreflight (set_emit.go) asks the
// same question earlier, from the spec and the raw bucket list, and admitting
// a set here that it refuses would leave a preflight with no table to read.
// TestOverlapPreflightPredicatesAgree pins the containment.
func (cs *compiledSet) overlapPreflightShape() bool {
	if cs.find == "" || !cs.overlapping {
		return false
	}
	if cs.fe != frontendScalar {
		return false
	}
	if cs.idSpaceSize() > wideBitmapThreshold {
		return false
	}
	for _, b := range cs.buckets {
		if b.sparse {
			return false
		}
		if b.suffixDFA == nil {
			continue
		}
		if b.suffixDFA.hasWordBoundary || b.suffixDFA.hasNewlineBoundary {
			return false
		}
	}
	for _, b := range cs.buckets {
		if b.suffixDFA != nil && hasNeverDyingState(b.suffixDFA) {
			return true
		}
	}
	return false
}

// emitFindPreflight emits B′ for BOTH `find` bodies, gated and overlapping.
//
// Run the union automaton over [from,len) once per drive and write the verdict
// into the caller's gate array: `2*len + 2` for every pattern it proves
// matches NOWHERE, `1` for every pattern still alive.
//
// The dead value is already legal in the gate encoding — it is what an empty
// match at `len` writes, and the pre-mask `2p + 1 >= gate[k]` is false for
// every p <= len, so the pattern is excluded for the rest of the drive. No new
// kind of value is introduced; that is the whole reason B′ is preferable to B.
// The alive value's only job is to be NON-ZERO: the same pre-mask reads
// `2s + 1 >= 1` as true at every position, and emitGateJump's `gate[id] >> 1`
// reads it as 0, exactly as a fresh 0 does.
//
// TWO FRESHNESS GUARDS, one per body, and the difference is forced.
//
// OVERLAPPING uses the gate array itself: it writes no gates of its own, so
// before item 11 an alive pattern kept its zero for the whole drive and a "is
// ANY gate zero" guard re-armed on every call — 3,724 union passes instead of
// one on greedy-3 / 50K a's. Marking alive patterns with 1 makes the array
// all-non-zero after the first call, so ONE slot answers for the whole array.
//
// GATED cannot use that marker, though an early prescription assumed it
// could. `1` IS invisible to the pre-mask (`2s + 1 >= 1` holds everywhere) and to
// emitGateJump (`1 >> 1 == 0`), which is as far as that prescription checked.
// It is NOT invisible to the third reader: emitWriteMatchK's write-time rule
// for an EMPTY extent is the stricter `2s >= gate[k]`, and at s == 0 that
// rejects 1 while accepting 0. The whole gated corpus agrees — marking alive
// patterns dropped every empty match at position 0 (24 setcaps failures, all
// nullable patterns on empty input). No value can serve: the marker must be
// non-zero for the guard and <= 0 for that rule.
//
// So the gated guard asks `from == 0` instead. A gated drive advances `from`
// strictly (an overlapping drive resumes at start + 1), so this is true on its first call and
// false on every later one — once per drive, in O(1), with nothing written to
// a slot the match path reads. Its verdict stays valid as `from` grows: a
// pattern that matches nowhere in [0, len) matches nowhere in any subrange.
// A drive that legitimately STARTS at from > 0 simply gets no preflight, which
// costs it the optimisation and nothing else. Re-running on a later call that
// is again at from == 0 is harmless: the pass is idempotent and writes nothing
// for alive patterns.
//
// One further gift, shared by both: with every pattern dead, emitGateJump's
// minimum over `gate[id] >> 1` is len + 1, so the scan cursor jumps past the
// end and the call returns 0 without entering the loop.
//
// TWO CONTRACT NOTES:
//   - the verdict is written at CALL ENTRY, independent of whether a position
//     is fully delivered, so it sits outside D2's "only after a fully
//     delivered position" rule;
//   - a caller resuming at a smaller `from` must zero the gate array first,
//     which the gate mask already requires.
//
// Both are documented in docs/sets.md.
func emitFindPreflight(b []byte, cs *compiledSet, lPos, lState, aliveLocal, pGate, pInLen, fromIdx, lEnd byte, tableMemIdx int, absence bool, lMask, lChunk, lCand byte) []byte {
	ids := setPatternIDs(cs)
	if len(ids) == 0 {
		return b
	}
	// aliveLocal is the first of this many consecutive i64 locals; word w holds
	// ids [64w, 64w+64). The overlapping body is narrow by its own eligibility
	// (overlapPreflightShape refuses an id space over 64), and the absence
	// prefilter is narrow by absenceMaxPatterns — asserted rather than assumed,
	// because a silent width mismatch here reads a local that belongs to
	// something else.
	words := cs.preflightAliveWords()
	if words > 1 && (cs.overlapping || absence) {
		panic("compile: wide find preflight emitted for a narrow-only path")
	}
	// Run only on a fresh drive. See the header for why the two bodies answer
	// that question differently — the gated one MUST NOT use the gate array,
	// because the marker that would make one slot answer for all of them is
	// exactly the value emitWriteMatchK reads as "no empty match here".
	if cs.overlapping {
		b = append(b, 0x20, pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(ids[0]*4))
		b = append(b, 0x45) // i32.eqz
	} else {
		b = append(b, 0x20, fromIdx, 0x45) // from == 0
	}
	b = append(b, 0x04, 0x40) // if the drive is fresh

	if absence {
		// G12: prove absence by literal search instead of walking the union
		// automaton — same over-approximating contract, ~15x cheaper.
		b = emitLiteralAbsenceMask(b, cs, lPos, lState, lMask, lChunk, aliveLocal, fromIdx, lCand)
	} else {
		b = emitUnionAliveMask(b, cs.unionScan, lPos, lState, aliveLocal, fromIdx, lEnd, tableMemIdx, cs.fullIDMaskWords(words))
	}

	for _, gid := range ids {
		if gid >= 64*words {
			// Outside the alive mask: leave the gate at 0 so the pattern is
			// never retired. It also leaves an overlapping drive's one-slot
			// guard armed if ids[0] is itself that wide, which is why that
			// eligibility predicate refuses an id space over 64 rather than
			// relying on this loop. Unreachable for the gated body, whose mask
			// is sized from the same id space this loop walks, and kept as the
			// fail-safe direction if the two ever disagree.
			continue
		}
		b = append(b, 0x20, aliveLocal+byte(gid/64))
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, int64(gid%64))
		b = append(b, 0x88)
		b = append(b, 0x42, 0x01, 0x83)
		b = append(b, 0x50) // i64.eqz -> not alive
		if cs.overlapping {
			// Alive patterns are marked too, so one slot answers "has this
			// drive run the pass". Sound only here: this body's gates are the
			// preflight's own storage and no match path reads them.
			b = append(b, 0x04, 0x7F)                                       // if (result i32)
			b = append(b, 0x20, pInLen, 0x41, 0x01, 0x74, 0x41, 0x02, 0x6A) // 2*len + 2
			b = append(b, 0x05)                                             // else
			b = append(b, 0x41, 0x01)                                       // 1: eligible everywhere, and non-zero
			b = append(b, 0x0B)
			b = append(b, 0x21, lState) // stash, then store through pGate
			b = append(b, 0x20, pGate, 0x20, lState)
			b = append(b, 0x36, 0x02)
			b = utils.AppendULEB128(b, uint32(gid*4)) // i32.store offset=gid*4
			continue
		}
		// Gated: write the DEAD sentinel only. An alive pattern keeps its 0,
		// which is the only value the empty-extent rule reads as "no
		// constraint" (see the header).
		b = append(b, 0x04, 0x40) // if not alive
		b = append(b, 0x20, pGate)
		b = append(b, 0x20, pInLen, 0x41, 0x01, 0x74, 0x41, 0x02, 0x6A) // 2*len + 2
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4)) // i32.store offset=gid*4
		b = append(b, 0x0B)
	}
	b = append(b, 0x0B) // end if the drive is fresh
	return b
}

// --------------------------------------------------------------------------
// Phase 2 of the two-phase scan

// fallbackSubSpec returns spec restricted to the patterns that landed in
// FALLBACK buckets, preserving their global ids.
//
// Built from the BUCKETS rather than from spec.Patterns on purpose: bucket
// placement is what decides which patterns phase 1 can reach, and it is also
// where a pattern dropped for exceeding max_fallback_states has already been
// removed. Filtering the spec directly would put a dropped pattern back into
// phase 2 and make the set report a pattern its `find` cannot.
func fallbackSubSpec(spec SetSpec, buckets []*bucket) SetSpec {
	sub := spec
	sub.Patterns = nil
	sub.PatternIDs = nil
	for _, bkt := range buckets {
		if !bkt.isFallback {
			continue
		}
		for _, p := range bkt.patterns {
			sub.Patterns = append(sub.Patterns, p)
			sub.PatternIDs = append(sub.PatternIDs, p.globalID)
		}
	}
	return sub
}

// hasLiteralBuckets reports whether any bucket carries a literal gate — the
// half of a mixed set that phase 1 serves.
func hasLiteralBuckets(buckets []*bucket) bool {
	for _, bkt := range buckets {
		if !bkt.isFallback {
			return true
		}
	}
	return false
}

// usesTwoPhaseScan reports whether this capability is emitted as phase 1 plus
// phase 2 instead of one interleaved per-position walk.
//
// `find` is excluded: it reports positions and extents, which phase 2's
// automaton does not carry — it knows only WHICH patterns match, which is
// exactly what the scan trio asks. `scan` is not listed because it is retired.
func (cs *compiledSet) usesTwoPhaseScan(kind setCapKind) bool {
	if cs.phase2Union == nil {
		return false
	}
	switch kind {
	case capScanAny:
		return true
	case capScanAll:
		// Same reason as usesUnionScan, and the same two bodies: phase 2's
		// automaton serves the memory ABI when it is wide and the accumulator
		// ABI when it is not. Keyed on wideAll() for the same reason too — a
		// Backtracking member selects the wide form at any id space, and such
		// a set never reaches here (phase 2 is not built for it at all).
		if cs.phase2Union.isWide() {
			return cs.wideAll() && cs.phase2Union.midWordsOff >= 0
		}
		return !cs.wideAll()
	}
	return false
}

// twoPhaseCaps returns the capabilities emitted through the split, in capFns
// order, so the hidden phase bodies get stable indices.
func (cs *compiledSet) twoPhaseCaps() []setCapKind {
	var out []setCapKind
	for _, c := range cs.capFns() {
		if cs.usesTwoPhaseScan(c.kind) {
			out = append(out, c.kind)
		}
	}
	return out
}

// twoPhaseFnOffset returns the index of this capability's hidden PHASE 1 body
// within the set's functions; phase 2 is the next one. -1 when the capability
// is not split.
//
// The hidden bodies sit immediately after the batch worker, which itself sits
// immediately after the exported capabilities.
func (cs *compiledSet) twoPhaseFnOffset(kind setCapKind) int {
	base := len(cs.capFns())
	if cs.batchFind {
		base++
	}
	for _, k := range cs.twoPhaseCaps() {
		if k == kind {
			return base
		}
		base += 2
	}
	return -1
}

// phase2Mask is the set of ids phase 2 can report: exactly the fallback
// patterns. `scan_all` ORs it with phase 1's accumulator, and the two are
// disjoint by construction because a pattern is in one bucket only.
func (cs *compiledSet) phase2Mask() uint64 {
	var m uint64
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback {
			continue
		}
		for _, id := range cs.patternIDs[bi] {
			if id < 64 {
				m |= 1 << uint(id)
			}
		}
	}
	return m
}

// emitTwoPhaseScanBody emits the exported capability as a wrapper over the two
// hidden phase bodies.
//
//	scan_any:  r = phase1(); if r >= 0 { return r }; return phase2()
//	scan_all:  return phase1() | phase2()
//
// `scan_any` short-circuits because either phase's id is a complete answer —
// it reports no start, so there is nothing a second phase could improve. That
// is the whole reason decision (10) is what makes this split worth building:
// with a start to report, phase 1's hit could not be returned without checking
// whether phase 2 had an earlier one, and both phases would always run.
func emitTwoPhaseScanBody(cs *compiledSet, kind setCapKind, phase1Idx int) []byte {
	const (
		pInPtr  = 0
		pInLen  = 1
		pFrom   = 2
		pOutPtr = 3 // wide scan_all only
	)
	phase2Idx := phase1Idx + 1
	wide := kind == capScanAll && cs.wideAll()
	var b []byte

	call := func(b []byte, idx int) []byte {
		b = append(b, 0x20, pInPtr, 0x20, pInLen, 0x20, pFrom)
		if wide {
			b = append(b, 0x20, pOutPtr)
		}
		b = append(b, 0x10)
		return utils.AppendULEB128(b, uint32(idx))
	}

	if wide {
		// Both phases write the SAME caller bitmap and each returns how many
		// bits it set, so the answer is their sum. They cannot double-count: a
		// pattern lives in exactly one bucket, so phase 1's ids and phase 2's
		// are disjoint — the same argument phase2Mask rests on.
		b = append(b, 0x00) // no locals
		b = call(b, phase1Idx)
		b = call(b, phase2Idx)
		b = append(b, 0x6A) // i32.add
		b = append(b, 0x0B)
		body := utils.AppendULEB128(nil, uint32(len(b)))
		return append(body, b...)
	}

	switch kind {
	case capScanAny:
		b = append(b, 0x01, 0x01, 0x7F) // one i32 local
		lR := byte(3)
		b = call(b, phase1Idx)
		b = append(b, 0x21, lR)
		b = append(b, 0x20, lR, 0x41, 0x00, 0x4E, 0x04, 0x40) // if r >= 0
		b = append(b, 0x20, lR, 0x0F)                         // return r
		b = append(b, 0x0B)                                   // end if
		b = call(b, phase2Idx)
	default: // capScanAll, narrow ABI
		b = append(b, 0x00) // no locals
		b = call(b, phase1Idx)
		b = call(b, phase2Idx)
		b = append(b, 0x84) // i64.or
	}
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitUnionTransition emits one step of the union automaton:
//
//	state = trans[state*rowLen + column(input[pos+k])]
//
// where the column is the input byte itself, or its byte class when the table
// is compressed, and an entry is stateWidth bytes wide. It is shared by
// emitUnionScanBody and emitUnionAliveMask because those two carried
// byte-for-byte copies of it against a HARDCODED layout — the exact place a
// layout change silently produces a module that reads its own tables wrong.
// lCur is an ABSOLUTE INPUT POINTER, not an offset — `pInPtr + position`,
// maintained by the caller.
//
// It was `pInPtr + lPos` computed here, which cost three instructions on every
// byte of every union walk (two local.gets and an add) where a pointer costs
// one. The callers all pay for it once instead: they seed the cursor with
// `pInPtr + from` and carry a second local holding `pInPtr + len` to compare
// against. Nothing in any of those bodies needs the numeric POSITION — the
// scan pair reports ids and masks, the alive mask reports a mask, the anchored
// walk reports accepts — so the offset had no other reader to keep it for.
// Measured saving: ~2 fuel per byte against a per-byte cost of ~19.75.
func emitUnionTransition(b []byte, u *unionScanDFA, lCur, lState, k byte, tableMemIdx int) []byte {
	return emitUnionTransitionAddr(b, u, lState, k, tableMemIdx, func(b []byte) []byte {
		return append(b, 0x20, lCur)
	})
}

// emitUnionTransitionOffset is emitUnionTransition for a walk that keeps an
// OFFSET rather than a pointer: it pays the `base + offset` add on every byte
// and saves the two instructions of setup a pointer cursor needs.
//
// That trade is only worth taking one way round, and which way depends on how
// far the walk goes. A pointer costs +4 instructions once (seed the cursor,
// compute the end bound) and saves 2 per byte, so it repays itself after two
// bytes — which every scan walk clears by five orders of magnitude, and which
// the ANCHORED walk does not clear at all: it dies within a byte or two by
// design, so in pointer form it measured +2 fuel on every one of the 48
// anchored rows. Hence two forms, chosen by how long the walk lives.
func emitUnionTransitionOffset(b []byte, u *unionScanDFA, lBase, lOff, lState, k byte, tableMemIdx int) []byte {
	return emitUnionTransitionAddr(b, u, lState, k, tableMemIdx, func(b []byte) []byte {
		return append(b, 0x20, lBase, 0x20, lOff, 0x6A)
	})
}

// emitUnionTransitionAddr is the body both forms share; pushAddr leaves the
// address of the input byte on the stack.
func emitUnionTransitionAddr(b []byte, u *unionScanDFA, lState, k byte, tableMemIdx int, pushAddr func([]byte) []byte) []byte {
	rowLen := u.numClasses * u.stateWidth
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.transOff)
	// + state*rowLen. A power-of-two row is a shift; anything else is a
	// multiply, which is why byte-class compression is not free even before
	// its extra load.
	b = append(b, 0x20, lState, 0x41)
	if sh := shiftForRow(rowLen); sh >= 0 {
		b = utils.AppendSLEB128(b, int32(sh))
		b = append(b, 0x74, 0x6A) // shl; add
	} else {
		b = utils.AppendSLEB128(b, int32(rowLen))
		b = append(b, 0x6C, 0x6A) // mul; add
	}
	// The column: the input byte, or its class.
	if u.numClasses < 256 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, u.classMapOff)
		b = pushAddr(b)
		b = append(b, 0x2D, 0x00, k) // i32.load8_u offset=k (input, memory 0)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = pushAddr(b)
		b = append(b, 0x2D, 0x00, k) // i32.load8_u offset=k (input, memory 0)
	}
	if u.stateWidth == 2 {
		b = append(b, 0x41, 0x01, 0x74) // *2
	}
	b = append(b, 0x6A) // add
	if u.stateWidth == 1 {
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = appendTableLoad16u(b, tableMemIdx)
	}
	return append(b, 0x21, lState)
}

// shiftForRow returns the shift for a power-of-two row length, or -1 when the
// row length needs a multiply instead.
func shiftForRow(n int) int {
	if n <= 0 || n&(n-1) != 0 {
		return -1
	}
	return log2Exact(n)
}
