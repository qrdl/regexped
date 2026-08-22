package compile

import (
	"encoding/binary"
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Start-anywhere union DFA for the scan trio (plans/SETS.md §14 P5)
//
// A set with no mandatory literal has no way to skip input, so the scan bodies
// visit every position and run every bucket's probe from it. That is
// O(positions x buckets), and on an unbounded pattern it is quadratic in the
// input: `[^\n]*ERROR` re-scans to the end of the line from each of 100,000
// positions. It is the 151M-fuel `greedy-3 / no-match / scan` row, and the
// reason `scan_all` and `find` on that set exhaust even a 4e9 fuel budget
// (§14.7).
//
// The fix is the shape regex-automata uses for the same question: ONE
// left-to-right pass over an automaton that can start a match at any position,
// whose accept states carry the set of patterns matching there. Cost becomes
// one table lookup and one OR per input byte, independent of pattern count.
//
// This serves `scan` and the narrow `scan_all` only:
//   - `scan_any` must report WHERE the match starts, and a forward pass over a
//     start-anywhere automaton knows only where matches END.
//   - `find` needs per-pattern extents, which is the suffix machinery's job.
//   - the wide (>64 id) `scan_all` ABI writes a caller bitmap; not built here.

// unionScanDFA holds the emitted form of the start-anywhere union automaton.
type unionScanDFA struct {
	numStates int
	// startState carries begin-of-text context (so `^`/\A can fire);
	// midStartState does not. Which one the body enters depends on `from`.
	startState    int
	midStartState int

	transOff  int32 // [numStates][256] u16 next-state
	acceptOff int32 // [numStates] u64: patterns accepting at any position
	eofOff    int32 // [numStates] u64: patterns accepting at end of input

	dataBytes []byte
	dataSegs  int
	tableEnd  int32
}

// maxUnionScanStates bounds the subset construction. The construction is a
// `.*`-prefixed union, so it is larger than the plain union it replaces —
// measured at 1.6x to 4.2x on the shapes that reach it (§14.12) — but it is
// still a determinisation and can blow up. Over budget, the set keeps the
// per-position path it has today.
const maxUnionScanStates = 4096

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
//   - Ids above 63 do not fit the u64 accept mask this emits.
//   - A pattern that cannot be re-parsed is skipped everywhere else too, and
//     a union missing a pattern would under-report.
func buildUnionScanDFA(spec SetSpec, opts CompileSetOptions, tableBase int32) *unionScanDFA {
	if len(spec.Patterns) == 0 {
		return nil
	}
	progs := make([]*syntax.Prog, 0, len(spec.Patterns))
	for k, p := range spec.Patterns {
		if k >= 64 || spec.PatternIDs[k] >= 64 {
			return nil // accept masks are u64
		}
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

	prog, patternBits := buildStartAnywhereUnionProg(progs, 64)
	// leftmostFirst=false: the question is which patterns match ANYWHERE, so
	// every live thread must be kept. Pruning to the highest-priority thread
	// is what a leftmost-first search wants and would lose lower-priority
	// patterns' accepts here.
	d, ok := newDFA(prog, false, false, maxUnionScanStates, patternBits)
	if !ok {
		return nil
	}
	if d.hasWordBoundary || d.hasNewlineBoundary {
		return nil // needs prev-byte context this loop does not carry
	}
	if d.numStates > maxUnionScanStates || d.numStates == 0 {
		return nil
	}

	u := &unionScanDFA{numStates: d.numStates, startState: d.start, midStartState: d.midStart}
	if d.midStart < 0 || d.midStart >= d.numStates {
		return nil
	}

	// The `.*` prefix keeps a live thread at every position, so no byte can
	// lead to the dead state. Verified rather than assumed: a -1 here would
	// mean the loop below reads a state id that does not exist.
	trans := make([]byte, d.numStates*256*2)
	for s := 0; s < d.numStates; s++ {
		for b := 0; b < 256; b++ {
			next := d.transitions[s*256+b]
			if next < 0 || next >= d.numStates {
				return nil
			}
			binary.LittleEndian.PutUint16(trans[(s*256+b)*2:], uint16(next))
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
	accept := make([]byte, d.numStates*8)
	eof := make([]byte, d.numStates*8)
	for s := 0; s < d.numStates; s++ {
		binary.LittleEndian.PutUint64(accept[s*8:], remap(d.midAccepting[s]))
		binary.LittleEndian.PutUint64(eof[s*8:], remap(d.accepting[s]))
	}

	u.transOff = tableBase
	u.acceptOff = u.transOff + int32(len(trans))
	u.eofOff = u.acceptOff + int32(len(accept))
	u.tableEnd = u.eofOff + int32(len(eof))
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.transOff, trans)...)
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.acceptOff, accept)...)
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofOff, eof)...)
	u.dataSegs = 3
	return u
}

// emitUnionScanBody emits the one-pass scan body.
//
// Signature matches the capability it replaces: (ptr, len, from) -> i32 for
// `scan`, (ptr, len, from) -> i64 for the narrow `scan_all`.
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
func emitUnionScanBody(u *unionScanDFA, mode setCapKind, fullMask uint64, tableMemIdx int) []byte {
	const (
		pInPtr = 0
		pInLen = 1
		pFrom  = 2
	)
	// locals: lPos, lState (i32), lAcc (i64)
	lPos, lState, lAcc := byte(3), byte(4), byte(5)
	var b []byte
	b = append(b, 0x02, 0x02, 0x7F, 0x01, 0x7E) // 2 x i32, 1 x i64

	b = append(b, 0x42, 0x00, 0x21, lAcc)
	// Entry state depends on `from`, and getting this wrong is silent.
	//
	// plans/SETS.md §3.2: ptr/len describe the WHOLE input and `from` bounds
	// only the search, so zero-width assertions must see real context. At
	// from==0 the scan really is at the start of text and `^`/\A may fire, so
	// the begin-context start state is correct; at from>0 it is not the start
	// of text and entering that same state would make `^[0-9]` match at
	// position 1. midStart is the same closure without begin context.
	//
	// Only these two are needed because sets with word boundaries or (?m)
	// line anchors are refused in buildUnionScanDFA — those would additionally
	// need the prev-byte context states.
	b = append(b, 0x20, pFrom, 0x45) // from == 0
	b = append(b, 0x04, 0x40)        // if
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.startState))
	b = append(b, 0x21, lState)
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.midStartState))
	b = append(b, 0x21, lState)
	b = append(b, 0x0B) // end if
	b = append(b, 0x20, pFrom, 0x21, lPos)
	// A `from` past the end yields no match, which the loop guard handles.

	// Record the ENTRY state's accepts before consuming anything: a pattern
	// that matches EMPTY at `from` accepts here and nowhere else. The loop
	// below only ORs after a transition, so without this `\A` (and `a*`, and
	// any other nullable pattern) is silently dropped — found by
	// tools/fuzz FuzzSetCaps on {`$`, `\A`} over "0", which reported only
	// `$` (plans/SETS.md §18.7).
	b = append(b, 0x20, lAcc)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.acceptOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, lAcc)

	b = append(b, 0x02, 0x40)                                 // block $done
	b = append(b, 0x03, 0x40)                                 // loop $scan
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01) // pos >= len → br $done

	// state = trans[state*512 + input[pos]*2]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.transOff)
	b = append(b, 0x20, lState, 0x41, 0x09, 0x74, 0x6A) // + state*512
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)       // i32.load8_u (input byte, memory 0)
	b = append(b, 0x41, 0x01, 0x74, 0x6A) // *2; add
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lState)

	// acc |= accept[state]
	b = append(b, 0x20, lAcc)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.acceptOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A) // + state*8
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, lAcc) // i64.or; set

	switch mode {
	case capScan:
		// Any bit set answers the question.
		b = append(b, 0x20, lAcc, 0x42, 0x00, 0x52, 0x0D, 0x01) // acc != 0 → br $done
	case capScanAll:
		// Every id present: nothing further can change the answer.
		b = append(b, 0x20, lAcc, 0x42)
		b = utils.AppendSLEB128_64(b, int64(fullMask))
		b = append(b, 0x51, 0x0D, 0x01) // acc == fullMask → br $done
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $scan
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	// End-of-input accepts. Reached whether the loop ran out of input or
	// broke early; in the early-exit cases the extra OR cannot change a
	// non-zero acc for `scan`, and for `scan_all` a full mask stays full.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x04, 0x40) // if pos >= len
	b = append(b, 0x20, lAcc)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, lAcc)
	b = append(b, 0x0B) // end if

	switch mode {
	case capScan:
		b = append(b, 0x20, lAcc, 0x42, 0x00, 0x52) // i64.ne → i32 0/1
	default:
		b = append(b, 0x20, lAcc)
	}
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// unionScanDataLen / unionScanDataSegs report the union automaton's
// contribution to the module's data section, or zero when the set has none.
func (cs *compiledSet) unionScanDataLen() int {
	if cs.unionScan == nil {
		return 0
	}
	return len(cs.unionScan.dataBytes)
}

func (cs *compiledSet) unionScanDataSegs() int {
	if cs.unionScan == nil {
		return 0
	}
	return cs.unionScan.dataSegs
}

// dataTop returns one past the highest address this set's tables occupy,
// derived from the segments actually emitted rather than from a running offset
// or a length sum (plans/FUZZER_BUGS.md bug 44).
//
// The blob list MUST stay in step with the one assembleModuleWithSets
// concatenates into rawData: a table missing here is a table the module writes
// but does not account for, which under-sizes the memory and relocates the
// NEXT set on top of this one.
func (cs *compiledSet) dataTop() int64 {
	blobs := [][]byte{
		cs.dataBytes, cs.prefixDataBytes, cs.acDataBytes,
		cs.teddyDataBytes, cs.anchoredDataBytes,
	}
	if cs.unionScan != nil {
		blobs = append(blobs, cs.unionScan.dataBytes)
	}
	var top int64
	for _, raw := range blobs {
		if e := dataSegmentsTop(raw); e > top {
			top = e
		}
	}
	return top
}

// usesUnionScan reports whether capability kind is served by the one-pass
// automaton rather than the per-position bucket walk.
//
// `scan_any` is excluded because it must report the match START, which a
// forward pass over a start-anywhere automaton cannot know; the wide `scan_all`
// ABI is excluded because it writes a caller-provided bitmap.
func (cs *compiledSet) usesUnionScan(kind setCapKind) bool {
	if cs.unionScan == nil {
		return false
	}
	switch kind {
	case capScan:
		return true
	case capScanAll:
		return cs.idSpaceSize() <= 64
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
	var m uint64
	for _, ids := range cs.patternIDs {
		for _, id := range ids {
			if id < 64 {
				m |= 1 << uint(id)
			}
		}
	}
	return m
}

// --------------------------------------------------------------------------
// G8: union preflight for `scan_any` (plans/SETS.md §18.4)

// usesScanAnyPreflight reports whether this set's `scan_any` body should run
// the union automaton once up front and narrow every bucket's validMask with
// the result.
//
// All three gates matter, and the third is what separates this from §16.5.2's
// reverted Candidate A. That change emitted a liveness check unconditionally,
// measured +37.5%, and could never fire — because greedy-3's wanted mask
// contained a pattern that was simultaneously never-recorded and never-dead.
// The preflight removes exactly such patterns from the wanted mask, so the
// check fires; without a never-dying state there is nothing to remove and the
// whole mechanism is cost with no benefit, so it is not emitted at all.
func (cs *compiledSet) usesScanAnyPreflight(mode setCapKind) bool {
	if mode != capScanAny || cs.unionScan == nil {
		return false
	}
	if cs.fe != frontendScalar {
		return false // a literal frontend already skips input
	}
	for _, b := range cs.buckets {
		if b.suffixDFA != nil && hasNeverDyingState(b.suffixDFA) {
			return true
		}
	}
	return false
}

// needsLivenessTable reports whether bucket bi should carry the G8 future
// table. Emitted only for the sets the preflight serves, so ineligible sets
// stay byte-identical.
func (cs *compiledSet) needsLivenessTable() bool {
	return cs.scanAny != "" && cs.unionScan != nil && cs.fe == frontendScalar
}

// emitUnionAliveMask runs the start-anywhere union automaton over [from, len)
// and leaves in aliveLocal the i64 mask of pattern ids that match SOMEWHERE in
// that range.
//
// This is emitUnionScanBody's loop without the capability epilogue, and it
// keeps that body's entry-state rule (plans/SETS.md §14.12): at from == 0 the
// scan really is at start of text and `^`/\A may fire, so the begin-context
// state is correct; at from > 0 it is not, and midStart is. Getting that wrong
// is silent, which is why it is restated here rather than assumed.
func emitUnionAliveMask(b []byte, u *unionScanDFA, lPos, lState, aliveLocal byte, tableMemIdx int) []byte {
	const (
		pInPtr = 0
		pInLen = 1
		pFrom  = 2
	)
	b = append(b, 0x42, 0x00, 0x21, aliveLocal)
	b = append(b, 0x20, pFrom, 0x45)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.startState))
	b = append(b, 0x21, lState)
	b = append(b, 0x05)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.midStartState))
	b = append(b, 0x21, lState)
	b = append(b, 0x0B)
	b = append(b, 0x20, pFrom, 0x21, lPos)

	// Entry-state accepts: a pattern matching EMPTY at `from` accepts here and
	// nowhere else (the §18.7 fix, for the same reason as in the scan body).
	b = append(b, 0x20, aliveLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.acceptOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, aliveLocal)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $scan
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.transOff)
	b = append(b, 0x20, lState, 0x41, 0x09, 0x74, 0x6A)
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lState)

	b = append(b, 0x20, aliveLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.acceptOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, aliveLocal)

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	// End-of-input accepts.
	b = append(b, 0x20, aliveLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, aliveLocal)
	return b
}

// usesGatedFindPreflight reports whether this set's gated `find` should run
// B′: one union preflight per drive, whose result is written back into the
// caller's gate array as a never-again sentinel (plans/SETS.md §18.5 / G9).
func (cs *compiledSet) usesGatedFindPreflight() bool {
	if cs.find == "" || cs.overlapping || cs.unionScan == nil {
		return false
	}
	if cs.fe != frontendScalar {
		return false
	}
	for _, b := range cs.buckets {
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

// emitGatedFindPreflight emits B′ (plans/SETS.md §18.5 / G9).
//
// Only while some gate is still 0 — i.e. the first call of a drive — run the
// union automaton over [from,len) and, for every pattern it proves matches
// NOWHERE, write `gate[id] = 2*len + 2`.
//
// That value is already legal in the §3.16 encoding: it is what an empty match
// at `len` writes, and the pre-mask `2p + 1 >= gate[k]` is false for every
// p <= len, so the pattern is excluded for the rest of the drive. No new kind
// of value is introduced — that is the whole reason B′ is preferable to B.
//
// TWO CONTRACT NOTES, per §18.5:
//   - the sentinel is written at CALL ENTRY, independent of whether a position
//     is fully delivered, so it sits outside D2's "only after a fully
//     delivered position" rule;
//   - a caller resuming at a smaller `from` must zero the gate array first,
//     which §3.14 already requires.
//
// Both are documented in docs/sets.md.
func emitGatedFindPreflight(b []byte, cs *compiledSet, lPos, lState, aliveLocal, pGate, pInLen byte, tableMemIdx int, absence bool, lMask, lChunk byte) []byte {
	ids := setPatternIDs(cs)
	if len(ids) == 0 {
		return b
	}
	// Run only when some gate is still zero: a fresh drive.
	b = append(b, 0x41, 0x00, 0x21, lState) // lState doubles as "any gate zero"
	for _, gid := range ids {
		b = append(b, 0x20, pGate, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4))
		b = append(b, 0x45) // i32.eqz
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x01, 0x21, lState)
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, lState)
	b = append(b, 0x04, 0x40) // if some gate is zero

	if absence {
		// G12: prove absence by literal search instead of walking the union
		// automaton — same over-approximating contract, ~15x cheaper.
		b = emitLiteralAbsenceMask(b, cs, lPos, lState, lMask, lChunk, aliveLocal)
	} else {
		b = emitUnionAliveMask(b, cs.unionScan, lPos, lState, aliveLocal, tableMemIdx)
	}

	// gate[id] = 2*len + 2 for every id the pass proved dead.
	for _, gid := range ids {
		if gid >= 64 {
			continue
		}
		b = append(b, 0x20, aliveLocal)
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, int64(gid))
		b = append(b, 0x88)
		b = append(b, 0x42, 0x01, 0x83)
		b = append(b, 0x50)       // not alive
		b = append(b, 0x04, 0x40) // if
		b = append(b, 0x20, pGate)
		b = append(b, 0x20, pInLen, 0x41, 0x01, 0x74, 0x41, 0x02, 0x6A) // 2*len + 2
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, uint32(gid*4)) // i32.store offset=gid*4
		b = append(b, 0x0B)
	}
	b = append(b, 0x0B) // end if some gate zero
	return b
}
