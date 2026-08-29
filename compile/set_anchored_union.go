package compile

import (
	"encoding/binary"
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// The ANCHORED union automaton — SETS_PLAN item 22 fix 1b.
//
// `match_any` and `match_all` ask one question of the whole input: which
// patterns match it from 0 to len. The bucket packer answers it with
// ceil(N/32) separate automata and a probe call each, so the cost grows with
// the pattern count — 60 fuel at 2 patterns, 700 at 128 — while
// regex-automata answers the same question with ONE anchored multi-pattern DFA
// at a flat 154. This builds the one automaton.
//
// WHY IT IS NOT THE BUCKET PACKER WITH A BIGGER BUDGET. The obvious cheaper
// route is to let the existing G17 sparse anchored merge take the whole set:
// it already produces one automaton with O(1) recording, which is why
// classchain-128 costs 139 fuel where keywords-128 costs 700. It is refused on
// table size, and the refusal is REAL, not an artefact of a pessimistic
// admission test:
//
//	keywords-64:  267 states -> 137,216 bytes    keywords-128: 530 -> 271,872
//
// because buildDFALayout compresses by byte class only while the table is u8
// (`useCompression = useU8 && ...`, engine_dfa.go), and both of those cross
// 256 states into u16 cells. The union-scan table format has no such coupling —
// it picks the cell width and the byte-class compression INDEPENDENTLY — and
// the same two automata cost 7,504 and 14,868 bytes in it. That format is the
// reason this file exists.
//
// WHAT IT SHARES with the start-anywhere union in set_union_scan.go: the
// unionScanDFA struct, the table layout (u8/u16 cells, byte-class map,
// emitUnionTransition, shiftForRow) and both accept representations. What it
// does NOT share:
//
//   - NO `.*?` prefix. The prog is buildUnionProg's, the same one
//     mergeAnchoredDFA feeds its per-bucket automata, with leftmostFirst OFF:
//     the question is which patterns match, so pruning to the highest-priority
//     thread would lose the lower-priority ones that also do.
//   - A DEAD STATE, which the scan automaton provably cannot have (its prefix
//     keeps a thread alive at every position; buildUnionScanDFA verifies this
//     and refuses if it fails). Here a mismatch kills the run, which is the
//     common case and wants the cheapest possible exit: dead is renumbered to
//     state 0 so the test is `i32.eqz`, and state 0's accept row is all zeros
//     so the walk needs no separate exit path at all — falling out of the loop
//     dead and reading the accept row gives exactly "nothing matched".
//   - NO mid-accept tables and no mid-accept-first renumbering. Both exist to
//     make "can a match END here" cheap on EVERY byte; an anchored run asks
//     only at the end, where set_union_scan.go's own comment already notes a
//     load costs nothing worth reordering for.
type anchoredUnion = unionScanDFA

// anchoredUnionBeatsBuckets reports whether replacing this anchored packing
// with one union automaton can pay.
//
// It cannot when the packing is ALREADY one automaton with constant-time
// recording — a single G17-sparse bucket, which reads its answer out of a
// per-state list (`emitRecordSparseCount`) rather than unrolling a test per
// pattern. There the union changes the table format and nothing else, and for
// `match_all` it changes it for the worse: the wide `_all` ABI makes it OR a
// bitmap row where the sparse bucket walks a short list. Measured on
// classchain-128, whose packing is exactly that shape: `match_all` 142 -> 167
// and 55 -> 86 fuel, against `match_any` 139 -> 119 — a wash at best, and the
// only sets in the corpus where the union did not win outright.
//
// Everything else benefits, including a single NON-sparse bucket: keywords-32
// is one bucket of 32 patterns and its 32-way recording chain is what makes it
// 181 fuel against the union's 38.
func anchoredUnionBeatsBuckets(buckets []*bucket) bool {
	// Named rather than inlined so the return reads as the doc above states
	// the rule: the union wins everywhere EXCEPT this one packing.
	singleSparseBucket := len(buckets) == 1 && buckets[0].sparse
	return !singleSparseBucket
}

// buildAnchoredUnionDFA builds the automaton described above, or returns nil to
// leave the set on its anchored buckets.
//
// wantAll controls only whether the `_all` bitmap rows are emitted, exactly as
// spec.ScanAll does for the scan automaton: a set that exports no `match_all`
// pays no table for it.
func buildAnchoredUnionDFA(spec SetSpec, tableBase int32, wantAll bool) *anchoredUnion {
	if len(spec.Patterns) == 0 {
		return nil
	}
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
	wide := idSpace > 64 || len(spec.Patterns) > 64

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

	var d *dfa
	var ok bool
	if wide {
		prog, patternIdx := buildUnionProgIndexed(progs)
		d, ok = newDFAWide(prog, false, maxUnionScanStates, patternIdx)
	} else {
		prog, patternBits := buildUnionProg(progs, 64)
		d, ok = newDFA(prog, false, false, maxUnionScanStates, patternBits)
	}
	if !ok {
		return nil
	}
	// Word and newline boundaries need the previous byte's class to decide an
	// accept, which this walk does not carry — the same refusal
	// buildUnionScanDFA makes, and for the same reason. Such a set keeps its
	// anchored buckets, whose probe body does carry it.
	if d.hasWordBoundary || d.hasNewlineBoundary {
		return nil
	}
	if d.numStates == 0 || d.numStates >= maxUnionScanStates {
		return nil
	}
	// A DOMINANT self-loop state is disqualifying, and this is the one
	// eligibility rule that came from measurement rather than from
	// representation limits.
	//
	// This walk steps one byte at a time. The per-bucket probe does not: it is
	// handed `dominantSkip` (genAnchoredWASM) and skips runs of self-looping
	// bytes 16 at a time under SIMD. For an automaton that DIES quickly — every
	// literal or counted-class set, where an anchored run is over within a byte
	// or two — that machinery never runs and the union's flat cost wins
	// outright. For one that stays alive across the whole input it is the
	// entire game: greedy-3 (`a+`, `[^\n]*ERROR` over newline-free text) walks
	// all 100 KB, and measured on this corpus the union cost it +1100% —
	// 205,168 fuel against 2,457,622 — while every set without such a state
	// improved by 40-94%.
	//
	// So the rule is structural, not a threshold: a set whose anchored
	// automaton can walk forever keeps the body that can skip.
	tbl := dfaTableFrom(d)
	if hasNeverDyingState(tbl) {
		return nil
	}

	// State 0 is DEAD; real state s becomes s+1.
	numStates := d.numStates + 1
	u := &anchoredUnion{
		numStates: numStates, startState: d.start + 1, midStartState: d.start + 1,
		maskWords: 1, acceptOff: -1, eofOff: -1,
		midReprOff: -1, eofReprOff: -1, midWordsOff: -1, eofWordsOff: -1,
		// No state can accept mid-string as far as this automaton is
		// concerned: nothing reads midAcceptLimit, and leaving it 0 keeps any
		// shared helper from emitting a mid-accept arm.
		midAcceptLimit: 0,
	}
	if wide {
		u.maskWords = (idSpace + 63) / 64
		u.rowBytes = u.maskWords * 8
		u.bitmapBytes = (idSpace + 7) / 8
		seen := make(map[int]bool, len(spec.PatternIDs))
		for _, id := range spec.PatternIDs {
			seen[id] = true
		}
		u.distinctIDs = len(seen)
	}

	u.stateWidth, u.numClasses = 2, 256
	var classMap [256]byte
	if numStates <= 256 {
		u.stateWidth = 1
	}
	if numStates*256*u.stateWidth > unionTableBudget {
		// Byte classes group BYTES every state treats alike, which is
		// unaffected by the dead-state renumbering below.
		//
		// Computed from the MINIMISED table while the transitions below are
		// built from the unminimised one, exactly as buildUnionScanDFA does.
		// That is sound, and for a sharper reason than "renumbering does not
		// matter": if two bytes agree on every minimised state then for each
		// original state their targets fall in the same class, i.e. are
		// EQUIVALENT states — so collapsing them into one column can change
		// which state id the walk visits but never which patterns it accepts.
		cm, _, nc := computeByteClasses(tbl)
		if nc < 256 {
			classMap, u.numClasses = cm, nc
		}
	}
	rowLen := u.numClasses * u.stateWidth
	trans := make([]byte, numStates*rowLen)
	for s := 0; s < d.numStates; s++ {
		for b := 0; b < 256; b++ {
			col := b
			if u.numClasses < 256 {
				col = int(classMap[b])
			}
			next := 0 // dead
			if n := d.transitions[s*256+b]; n >= 0 && n < d.numStates {
				next = n + 1
			}
			if u.stateWidth == 1 {
				trans[(s+1)*rowLen+col] = byte(next)
			} else {
				binary.LittleEndian.PutUint16(trans[(s+1)*rowLen+col*2:], uint16(next))
			}
		}
	}
	// Row 0 is the dead state: every byte keeps it dead. It is already all
	// zeros, which is exactly that.

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
		// Bit k of the accept mask is remapped to pattern k's GLOBAL id, so the
		// mask IS `match_all`'s answer and its lowest set bit IS a `match_any`
		// answer — no translation at runtime.
		remap := func(bits uint64) uint64 {
			var out uint64
			for k := 0; k < len(spec.Patterns) && k < 64; k++ {
				if bits&(1<<uint(k)) != 0 {
					out |= 1 << uint(spec.PatternIDs[k])
				}
			}
			return out
		}
		eof := make([]byte, numStates*8)
		for s := 0; s < d.numStates; s++ {
			binary.LittleEndian.PutUint64(eof[(s+1)*8:], remap(d.accepting[s]))
		}
		u.eofOff = off
		u.tableEnd = u.eofOff + int32(len(eof))
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofOff, eof)...)
		u.dataSegs++
		return u
	}

	wideRow := func(list []uint16) (int32, []byte) {
		row := make([]byte, u.rowBytes)
		repr := int32(0)
		for _, k := range list {
			if int(k) >= len(spec.PatternIDs) {
				continue
			}
			gid := spec.PatternIDs[k]
			row[gid/8] |= 1 << uint(gid%8)
			if repr == 0 {
				repr = int32(gid) + 1
			}
		}
		return repr, row
	}
	eofRepr := make([]byte, numStates*4)
	eofWords := make([]byte, numStates*u.rowBytes)
	for s := 0; s < d.numStates; s++ {
		er, erow := wideRow(d.acceptWide[s])
		binary.LittleEndian.PutUint32(eofRepr[(s+1)*4:], uint32(er))
		copy(eofWords[(s+1)*u.rowBytes:], erow)
	}
	u.eofReprOff = off
	u.tableEnd = u.eofReprOff + int32(len(eofRepr))
	u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofReprOff, eofRepr)...)
	u.dataSegs++
	if wantAll {
		// 8-aligned for the same reason the scan automaton's rows are: they are
		// read with i64 loads.
		u.tableEnd = (u.tableEnd + 7) &^ 7
		u.eofWordsOff = u.tableEnd
		u.tableEnd = u.eofWordsOff + int32(len(eofWords))
		u.dataBytes = append(u.dataBytes, appendDataSegment(nil, u.eofWordsOff, eofWords)...)
		u.dataSegs++
	}
	return u
}

// emitAnchoredUnionBody emits one anchored capability over the union automaton.
//
//	match_any (ptr, len)           -> i32   a global id, or -1
//	match_all (ptr, len)           -> i64   bitmask            (narrow)
//	match_all (ptr, len, out_ptr)  -> i32   count of patterns  (wide)
//
// The walk is the whole body: run from state 0 of the input to its end, and
// read the accept entry of wherever it stopped. A byte with no transition
// lands on state 0, whose accept entry is empty, so "died at byte 3" and "ran
// to the end matching nothing" leave the same answer and need no separate
// path.
func emitAnchoredUnionBody(u *anchoredUnion, kind setCapKind, wideAll bool, tableMemIdx int) []byte {
	const (
		pInPtr = 0
		pInLen = 1
		pOut   = 2 // wide match_all only
	)
	wideAllABI := kind == capMatchAll && wideAll
	base := byte(2)
	if wideAllABI {
		base = 3
	}
	// lState and an OFFSET cursor. Deliberately NOT the pointer form the scan
	// walks use: that trades +4 instructions of setup for -2 per byte, and this
	// walk dies within a byte or two by design, so it would never repay them —
	// measured +2 fuel on every anchored row. See emitUnionTransitionOffset.
	lState, lPos := base, base+1
	// Only the shapes that need them; see the local declarations below.
	lScratch := base + 2 // i32: the wide `_any` representative, the wide `_all` count
	lAddr, lOld32, lNew32 := base+3, base+4, base+5
	lAcc := base + 2   // i64, narrow `_any` only
	lOld64 := base + 6 // i64, wide `_all`
	lNew64 := base + 7 // i64, wide `_all`

	var b []byte
	switch {
	case wideAllABI:
		b = append(b, 0x02, 0x06, 0x7F, 0x02, 0x7E) // 6 i32, 2 i64
	case kind == capMatchAny && !u.isWide():
		b = append(b, 0x02, 0x02, 0x7F, 0x01, 0x7E) // 2 i32, 1 i64
	case kind == capMatchAny:
		b = append(b, 0x01, 0x03, 0x7F) // 3 i32
	default:
		b = append(b, 0x01, 0x02, 0x7F) // 2 i32
	}

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(u.startState))
	b = append(b, 0x21, lState)
	b = append(b, 0x41, 0x00, 0x21, lPos)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $scan
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)
	b = emitUnionTransitionOffset(b, u, pInPtr, lPos, lState, 0, tableMemIdx)
	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01) // dead: leave, state 0 answers "nothing"
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	switch {
	case kind == capMatchAny && u.isWide():
		// The representative id, stored as gid+1 so 0 means "accepts nothing"
		// — which is what state 0 holds, and what -1 reports.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, u.eofReprOff)
		b = append(b, 0x20, lState, 0x41, 0x02, 0x74, 0x6A)
		b = appendTableLoad32(b, tableMemIdx, 0)
		b = append(b, 0x21, lScratch)
		b = append(b, 0x20, lScratch, 0x45, 0x04, 0x7F) // if repr == 0 (result i32)
		b = append(b, 0x41, 0x7F)                       // -1
		b = append(b, 0x05)                             // else
		b = append(b, 0x20, lScratch, 0x41, 0x01, 0x6B) // repr - 1
		b = append(b, 0x0B)
	case kind == capMatchAny:
		b = emitAnchoredEOFMask(b, u, lState, tableMemIdx)
		b = append(b, 0x21, lAcc)
		b = append(b, 0x20, lAcc, 0x50, 0x04, 0x7F) // if i64.eqz (result i32)
		b = append(b, 0x41, 0x7F)                   // -1
		b = append(b, 0x05)                         // else
		b = append(b, 0x20, lAcc, 0x7A, 0xA7)       // i64.ctz; i32.wrap_i64
		b = append(b, 0x0B)
	case wideAllABI:
		b = append(b, 0x41, 0x00, 0x21, lScratch)
		b = emitAnchoredOrRow(b, u, lState, lAddr, lScratch, lOld32, lNew32, lOld64, lNew64, pOut, tableMemIdx)
		b = append(b, 0x20, lScratch)
	default:
		b = emitAnchoredEOFMask(b, u, lState, tableMemIdx)
	}
	b = append(b, 0x0B) // end function

	body := utils.AppendULEB128(nil, uint32(len(b)))
	return append(body, b...)
}

// emitAnchoredEOFMask pushes the u64 accept mask of lState — global ids
// already, so it is `match_all`'s answer as it stands.
func emitAnchoredEOFMask(b []byte, u *anchoredUnion, lState byte, tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.eofOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	return appendTableLoad64(b, tableMemIdx)
}

// emitAnchoredOrRow ORs lState's accept row into the caller's bitmap and leaves
// the number of bits that flipped 0->1 in lCount — the wide `_all` ABI, the
// same shape emitUnionScanWideBody writes.
func emitAnchoredOrRow(b []byte, u *anchoredUnion, lState, lAddr, lCount, lOld32, lNew32, lOld64, lNew64, pOutPtr byte, tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, u.eofWordsOff)
	b = append(b, 0x20, lState, 0x41)
	if sh := shiftForRow(u.rowBytes); sh >= 0 {
		b = utils.AppendSLEB128(b, int32(sh))
		b = append(b, 0x74, 0x6A)
	} else {
		b = utils.AppendSLEB128(b, int32(u.rowBytes))
		b = append(b, 0x6C, 0x6A)
	}
	b = append(b, 0x21, lAddr)

	full := (u.bitmapBytes / 8) * 8
	for o := 0; o < full; o += 8 {
		b = append(b, 0x20, pOutPtr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A, 0x29, 0x00, 0x00)
		b = append(b, 0x21, lOld64)
		b = append(b, 0x20, lOld64)
		b = append(b, 0x20, lAddr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A)
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0x84, 0x21, lNew64)
		b = append(b, 0x20, pOutPtr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A, 0x20, lNew64)
		b = append(b, 0x37, 0x00, 0x00)
		b = append(b, 0x20, lCount)
		b = append(b, 0x20, lNew64, 0x20, lOld64, 0x85)
		b = append(b, 0x7B, 0xA7)
		b = append(b, 0x6A, 0x21, lCount)
	}
	for o := full; o < u.bitmapBytes; o++ {
		b = append(b, 0x20, pOutPtr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, lOld32)
		b = append(b, 0x20, lOld32)
		b = append(b, 0x20, lAddr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
		b = append(b, 0x72, 0x21, lNew32)
		b = append(b, 0x20, pOutPtr, 0x41)
		b = utils.AppendSLEB128(b, int32(o))
		b = append(b, 0x6A, 0x20, lNew32)
		b = append(b, 0x3A, 0x00, 0x00)
		b = append(b, 0x20, lCount)
		b = append(b, 0x20, lNew32, 0x20, lOld32, 0x73)
		b = append(b, 0x69)
		b = append(b, 0x6A, 0x21, lCount)
	}
	return b
}
