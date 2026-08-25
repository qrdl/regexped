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
// reason `scan_all` and `find` on that set exhaust even a 4e9 fuel budget
// (§14.7).
//
// The fix is the shape regex-automata uses for the same question: ONE
// left-to-right pass over an automaton that can start a match at any position,
// whose accept states carry the set of patterns matching there. Cost becomes
// one table lookup and one OR per input byte, independent of pattern count.
//
// This serves `scan`, `scan_any` and the narrow `scan_all`:
//   - `scan_any` joined them under TODO task 59 decision (10). It used to be
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

// unionTableBudget is the size above which the transition matrix is byte-class
// compressed, mirroring the DFA engine's own "compress once the table exceeds
// 32 KB" rule (docs/wasm.md).
//
// Measured 2026-08-24, four layouts against each other on the SETS_PLAN item
// 19 shapes, 100 KB no-match, fuel per byte and module bytes:
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
	for st := 0; st < d.numStates; st++ {
		for b := 0; b < 256; b++ {
			if next := d.transitions[st*256+b]; next < 0 || next >= d.numStates {
				return nil
			}
		}
	}

	u.stateWidth, u.numClasses = 2, 256
	var classMap [256]byte
	if d.numStates <= 256 {
		u.stateWidth = 1
	}
	if d.numStates*256*u.stateWidth > unionTableBudget {
		cm, _, nc := computeByteClasses(dfaTableFrom(d))
		if nc < 256 {
			classMap, u.numClasses = cm, nc
		}
	}
	rowLen := u.numClasses * u.stateWidth
	trans := make([]byte, d.numStates*rowLen)
	for st := 0; st < d.numStates; st++ {
		for b := 0; b < 256; b++ {
			col := b
			if u.numClasses < 256 {
				col = int(classMap[b])
			}
			next := uint16(d.transitions[st*256+b])
			if u.stateWidth == 1 {
				trans[st*rowLen+col] = byte(next)
			} else {
				binary.LittleEndian.PutUint16(trans[st*rowLen+col*2:], next)
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
	accept := make([]byte, d.numStates*8)
	eof := make([]byte, d.numStates*8)
	for s := 0; s < d.numStates; s++ {
		binary.LittleEndian.PutUint64(accept[s*8:], remap(d.midAccepting[s]))
		binary.LittleEndian.PutUint64(eof[s*8:], remap(d.accepting[s]))
	}

	off := tableBase
	if u.numClasses < 256 {
		u.classMapOff = off
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.classMapOff, classMap[:])...)
		u.dataSegs++
		off += 256
	}
	u.transOff = off
	u.acceptOff = u.transOff + int32(len(trans))
	u.eofOff = u.acceptOff + int32(len(accept))
	u.tableEnd = u.eofOff + int32(len(eof))
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.transOff, trans)...)
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.acceptOff, accept)...)
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofOff, eof)...)
	u.dataSegs += 3
	return u
}

// unionUnroll is how many input bytes one iteration of the union scan's bulk
// loop steps. Four is what the task specifies: it takes
// the per-byte scaffolding from ~14 fuel to ~3.5 while adding three copies of
// a ~22-instruction step to two bodies per set.
const unionUnroll = 4

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

	// `from > len` yields the capability's "nothing" result. The loop guard
	// alone does NOT deliver that: the entry-state
	// accept below and the end-of-input accept after the loop both run
	// regardless of how the loop exited, so a `from` past the end still
	// reported every nullable and every `\z`-anchored pattern. `from == len`
	// is a REAL position and must still be evaluated, hence gt_u and not ge_u.
	b = append(b, 0x20, pFrom, 0x20, pInLen, 0x4B, 0x04, 0x40) // if from > len (u)
	switch mode {
	case capScan:
		b = append(b, 0x41, 0x00) // i32.const 0
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
	b = append(b, 0x20, lAcc)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.acceptOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x84, 0x21, lAcc)

	// One step over input[pos+k]: state = trans[state*512 + byte*2], then
	// acc |= accept[state]. k rides in the load's memarg offset.
	emitStep := func(b []byte, k byte) []byte {
		b = emitUnionTransition(b, u, lPos, lState, pInPtr, k, tableMemIdx)

		// acc |= accept[state]
		b = append(b, 0x20, lAcc)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, u.acceptOff)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A) // + state*8
		b = appendTableLoad64(b, tableMemIdx)
		return append(b, 0x84, 0x21, lAcc) // i64.or; set
	}

	// The mode's early exit, branching to $done at br depth `depth`.
	emitExit := func(b []byte, depth byte) []byte {
		switch mode {
		case capScan, capScanAny:
			// Any bit set answers the question: `scan` needs only that one
			// exists, and `scan_any` reports no start, so the first id found
			// is as good as any other (§3.5 leaves the id unspecified).
			b = append(b, 0x20, lAcc, 0x42, 0x00, 0x52, 0x0D, depth) // acc != 0
		case capScanAll:
			// Every id present: nothing further can change the answer.
			b = append(b, 0x20, lAcc, 0x42)
			b = utils.AppendSLEB128_64(b, int64(fullMask))
			b = append(b, 0x51, 0x0D, depth) // acc == fullMask
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
	b = append(b, 0x20, pInLen, 0x4B, 0x0D, 0x01) // gt_u → br $bulk_exit

	for k := byte(0); k < unionUnroll; k++ {
		b = emitStep(b, k)
	}
	b = append(b, 0x20, lPos, 0x41, unionUnroll, 0x6A, 0x21, lPos)
	b = emitExit(b, 0x02) // → $done, past $bulk and $bulk_exit
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $bulk
	b = append(b, 0x0B) // end block $bulk_exit

	b = append(b, 0x03, 0x40)                                 // loop $tail
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01) // pos >= len → br $done
	b = emitStep(b, 0)
	b = emitExit(b, 0x01) // → $done
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $tail
	b = append(b, 0x0B)       // end loop $tail
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

// unionScanDataLen / unionScanDataSegs report the union automaton's
// contribution to the module's data section, or zero when the set has none.
func (cs *compiledSet) unionScanDataLen() int {
	n := 0
	if cs.unionScan != nil {
		n += len(cs.unionScan.dataBytes)
	}
	if cs.phase2Union != nil {
		n += len(cs.phase2Union.dataBytes)
	}
	return n
}

func (cs *compiledSet) unionScanDataSegs() int {
	n := 0
	if cs.unionScan != nil {
		n += cs.unionScan.dataSegs
	}
	if cs.phase2Union != nil {
		n += cs.phase2Union.dataSegs
	}
	return n
}

// dataTop returns one past the highest address this set's tables occupy,
// derived from the segments actually emitted rather than from a running offset
// or a length sum.
//
// The blob list MUST stay in step with the one assembleModuleWithSets
// concatenates into rawData: a table missing here is a table the module writes
// but does not account for, which under-sizes the memory and relocates the
// NEXT set on top of this one.
func (cs *compiledSet) dataTop() int64 {
	blobs := [][]byte{
		cs.dataBytes, cs.prefixDataBytes, cs.acDataBytes,
		cs.teddyDataBytes, cs.anchoredDataBytes, cs.startableDataBytes,
	}
	if cs.unionScan != nil {
		blobs = append(blobs, cs.unionScan.dataBytes)
	}
	if cs.phase2Union != nil {
		blobs = append(blobs, cs.phase2Union.dataBytes)
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
// `scan_any` qualifies since decision (10) dropped its start: it needs no id
// space check of its own because buildUnionScanDFA already refuses any set with
// an id >= 64. The wide `scan_all` ABI is excluded because it writes a
// caller-provided bitmap.
func (cs *compiledSet) usesUnionScan(kind setCapKind) bool {
	if cs.unionScan == nil {
		return false
	}
	switch kind {
	case capScan, capScanAny:
		return true
	case capScanAll:
		// The walk answers with an i64 accumulator and takes no out_ptr, so it
		// implements the NARROW `_all` ABI and can only serve a capability
		// using it. Keyed on wideAll() rather than on the id space alone
		// because the id space is no longer the only thing that selects the
		// wide form: a Backtracking member forces it at any size (SETS_PLAN
		// item 20 decision 3). Testing the size here left the walk serving a
		// capability that had already moved to the memory form — an i64 pushed
		// where an i32 was expected, i.e. a module that does not validate.
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

// emitUnionAliveMask runs the start-anywhere union automaton over [from, len)
// and leaves in aliveLocal the i64 mask of pattern ids that match SOMEWHERE in
// that range.
//
// This is emitUnionScanBody's loop without the capability epilogue, and it
// keeps that body's entry-state rule: at from == 0 the
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

	b = emitUnionTransition(b, u, lPos, lState, pInPtr, 0, tableMemIdx)

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
// caller's gate array as a never-again sentinel.
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

// emitGatedFindPreflight emits B′.
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

// --------------------------------------------------------------------------
// Phase 2 of the two-phase scan (SETS_PLAN item 19)

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
// exactly what the scan trio asks. `scan` is not listed because TODO task 59
// decision (2) retires it.
func (cs *compiledSet) usesTwoPhaseScan(kind setCapKind) bool {
	if cs.phase2Union == nil {
		return false
	}
	switch kind {
	case capScanAny:
		return true
	case capScanAll:
		// Same reason as usesUnionScan: the wide ABI writes a caller bitmap,
		// which an accumulator-returning walk does not do. Keyed on wideAll()
		// for the same reason too — a Backtracking member selects the wide
		// form at any id space.
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
		pInPtr = 0
		pInLen = 1
		pFrom  = 2
	)
	phase2Idx := phase1Idx + 1
	var b []byte

	call := func(b []byte, idx int) []byte {
		b = append(b, 0x20, pInPtr, 0x20, pInLen, 0x20, pFrom)
		b = append(b, 0x10)
		return utils.AppendULEB128(b, uint32(idx))
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
func emitUnionTransition(b []byte, u *unionScanDFA, lPos, lState, pInPtr, k byte, tableMemIdx int) []byte {
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
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
		b = append(b, 0x2D, 0x00, k) // i32.load8_u offset=k (input, memory 0)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
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
