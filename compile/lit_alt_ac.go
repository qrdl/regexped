package compile

import (
	"encoding/binary"
	"fmt"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// A FIND over an alternation of plain literals — a keyword list,
// `\b(?:select|insert|drop|…)\b` — walks an Aho-Corasick automaton of the
// literals instead of trying the pattern's DFA at every candidate byte.
//
// The general find's prefilter takes at most 8 distinct first bytes (the
// single-pattern Teddy tiers); a list whose words start with more falls to the
// scalar first-byte table, and over text where those letters are common every
// position starts a walk: 75-85 fuel/byte at 50 words, and at 500 words the DFA
// passes max_dfa_states and the find runs on Backtracking (110-125 fuel/byte,
// a 416 KB module). The same words as a SET cost 14 and 53, because the set
// compiler scans them with a literal frontend; this is that frontend's
// automaton (buildAC, aho_corasick.go) applied to the single pattern.
//
// THE ANSWER is the alternation's leftmost-first match, which over literals is
// the earliest START and, at that start, the LOWEST alternative — the first
// literal in the pattern's order that matches there. The automaton reports a
// literal where it ENDS, so the walk keeps the best (start, alternative) seen
// and stops once no literal ending later could start at or before it: past
// best start + longest literal − 1. A call therefore reads at most the longest
// literal past its answer, and a drive stays linear.
//
// Taken for a `find_func` whose pattern, captures stripped, is a finite set of
// non-empty literals — literals, classes, concatenations, alternations and
// `?` over them, each case-sensitive — with an optional `\b` before and after
// the whole, more than 8 distinct first bytes, and an automaton within the
// set frontend's table budget. `match_func` and `groups_func` keep their
// engines; an `anchor_literal:` keeps the general find it names.

// litAltMaxLiterals bounds the enumeration: a pattern whose literal set is
// larger keeps the general find. Far above any real keyword list, and below
// acMaxOutputs, which a nested family can reach first anyway (checked).
const litAltMaxLiterals = 16384

// litAltMaxLen bounds one literal's length: its length and two boundary flags
// share a u16 table entry (litAltLenMask).
const litAltMaxLen = 1 << 14

const (
	litAltLenMask       = litAltMaxLen - 1
	litAltFirstWordFlag = 1 << 14 // the literal's first byte is a word byte
	litAltLastWordFlag  = 1 << 15 // its last byte is
)

// litAltMinFirstBytes is the most distinct first bytes the general find's
// prefilter takes with its Teddy tiers (prefix_scan.go); a list within it keeps
// that find, which measured cheaper there (16 words: 5.88 fuel/byte against
// 10.25 through a literal frontend).
const litAltMinFirstBytes = 8

// litAltAC is a literal alternation's find, planned.
type litAltAC struct {
	lits            [][]byte // in the alternation's priority order
	maxLen          int
	wbLead, wbTrail bool
	ac              *acAutomaton
	compressed      bool
	// teddy, for at most teddyMaxLiterals literals, is the set frontend's
	// nibble tables over the literals' first bytes: at the automaton's root
	// the body skips 16 positions at a time where no literal can begin.
	teddy *teddyTables

	// Laid out by plan.
	l        *acLayout
	lenOff   int32 // u16 per literal: length | first/last-is-word flags
	wordOff  int32 // the pattern's word table, when a boundary is checked
	tableEnd int32
}

// analyseLitAltAC returns the plan for re's find, or nil when the find is not
// a literal alternation this path takes.
func analyseLitAltAC(rp resolvedPattern, anchorLiteral string, budget int) *litAltAC {
	if anchorLiteral != "" {
		return nil
	}
	t, err := rp.parse()
	if err != nil {
		return nil
	}
	re := t.re
	// A repeat makes a product, not a list: `[a-k][ab]{6}foo` is 704 strings
	// and an automaton of 3,510 nodes where the pattern's own DFA has nine
	// states. A keyword list has none (`?` is no repeat here: `colou?r`).
	if litAltHasRepeat(re) {
		return nil
	}
	stripCaptures(re)
	re = re.Simplify()
	a := &litAltAC{}
	parts := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		parts = re.Sub
	}
	if len(parts) > 0 && parts[0].Op == syntax.OpWordBoundary {
		a.wbLead, parts = true, parts[1:]
	}
	if len(parts) > 0 && parts[len(parts)-1].Op == syntax.OpWordBoundary {
		a.wbTrail, parts = true, parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return nil
	}
	strs := [][]byte{nil}
	for _, part := range parts {
		next, ok := litAltEnumerate(part, rp.unicode())
		if !ok {
			return nil
		}
		if strs = litAltProduct(strs, next); strs == nil {
			return nil
		}
	}
	seen := make(map[string]bool, len(strs))
	firsts := map[byte]bool{}
	for _, s := range strs {
		if len(s) == 0 || len(s) >= litAltMaxLen {
			return nil // the pattern can match empty, or a literal too long to encode
		}
		if seen[string(s)] {
			continue // a later copy never wins: the earlier has the higher priority
		}
		seen[string(s)] = true
		a.lits = append(a.lits, s)
		firsts[s[0]] = true
		a.maxLen = max(a.maxLen, len(s))
	}
	if len(a.lits) < 2 || len(firsts) <= litAltMinFirstBytes {
		return nil
	}
	a.ac = buildAC(a.lits)
	if len(a.ac.nodes) > acMaxNodes || acTotalOutputs(a.ac) > acMaxOutputs {
		return nil
	}
	// Uncompressed first, as the set frontend does: the class map costs a load
	// per input byte, so it is spent only to fit the budget.
	if buildACLayoutMode(a.ac, 0, false).bytes() > budget {
		packed := buildACLayoutMode(a.ac, 0, true)
		if !packed.compressed || packed.bytes() > budget {
			return nil
		}
		a.compressed = true
	}
	if t, ok := buildTeddyTablesMulti(a.lits); ok {
		a.teddy = t
	}
	return a
}

// litAltEnumerate lists the strings re matches, in leftmost-first priority
// order, or false when re is not a finite set of case-sensitive literals.
func litAltEnumerate(re *syntax.Regexp, unicode bool) ([][]byte, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch:
		return [][]byte{nil}, true
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil, false
		}
		b, ok := literalBytes(re.Rune, unicode)
		return [][]byte{b}, ok
	case syntax.OpCharClass:
		var out [][]byte
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				b, ok := literalBytes([]rune{r}, unicode)
				if !ok || len(out) >= litAltMaxLiterals {
					return nil, false
				}
				out = append(out, b)
			}
		}
		return out, len(out) > 0
	case syntax.OpConcat:
		out := [][]byte{nil}
		for _, sub := range re.Sub {
			next, ok := litAltEnumerate(sub, unicode)
			if !ok {
				return nil, false
			}
			if out = litAltProduct(out, next); out == nil {
				return nil, false
			}
		}
		return out, true
	case syntax.OpAlternate:
		var out [][]byte
		for _, sub := range re.Sub {
			next, ok := litAltEnumerate(sub, unicode)
			if !ok || len(out)+len(next) > litAltMaxLiterals {
				return nil, false
			}
			out = append(out, next...)
		}
		return out, true
	case syntax.OpQuest:
		sub, ok := litAltEnumerate(re.Sub[0], unicode)
		if !ok || len(sub)+1 > litAltMaxLiterals {
			return nil, false
		}
		if re.Flags&syntax.NonGreedy != 0 {
			return append([][]byte{nil}, sub...), true
		}
		return append(sub, nil), true
	}
	return nil, false
}

// litAltProduct is every string of a followed by one of b, in priority order
// (a's choice first), or nil past litAltMaxLiterals.
func litAltProduct(a, b [][]byte) [][]byte {
	if len(a)*len(b) > litAltMaxLiterals {
		return nil
	}
	out := make([][]byte, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			s := make([]byte, 0, len(x)+len(y))
			out = append(out, append(append(s, x...), y...))
		}
	}
	return out
}

// plan lays the automaton, the length table and (for a boundary) the
// pattern's word table out from base.
func (a *litAltAC) plan(base int32, wt *patternWordTable) {
	a.l = buildACLayoutMode(a.ac, base, a.compressed)
	a.lenOff = (a.l.tableEnd + 1) &^ 1
	a.tableEnd = a.lenOff + int32(2*len(a.lits)) //nolint:gosec // bounded by litAltMaxLiterals
	if a.wbLead || a.wbTrail {
		if wt == nil {
			panic("compile: a literal alternation with \\b has no word table (compilePattern reserves one)")
		}
		a.wordOff, wt.used = wt.off, true
	}
}

// dataSegments is the automaton's tables and the length table.
func (a *litAltAC) dataSegments() ([]byte, int) {
	ds := emitACDataSegments(a.l)
	lens := make([]byte, 2*len(a.lits))
	for i, s := range a.lits {
		v := uint16(len(s)) //nolint:gosec // bounded by litAltMaxLen
		if isWordByte(s[0]) {
			v |= litAltFirstWordFlag
		}
		if isWordByte(s[len(s)-1]) {
			v |= litAltLastWordFlag
		}
		binary.LittleEndian.PutUint16(lens[2*i:], v)
	}
	ds = appendDataSegment(ds, a.lenOff, lens)
	return ds, acDataSegments(a.l) + 1
}

// buildLitAltACFindBody emits the find body:
//
//	(ptr, len) -> i64   (start << 32 | end, or -1), `from` through the global
func buildLitAltACFindBody(a *litAltAC, tableMemIdx int) ([]byte, findFromMode) {
	const (
		pPtr = iota
		pLen
		nparams
	)
	al := newLocalAlloc(nparams)
	cur := al.ScanCursor()
	lPos := cur.Local()
	lState, lLimit, lOutIdx, lOutEnd := al.I32(), al.I32(), al.I32(), al.I32()
	lID, lEntry, lS, lE := al.I32(), al.I32(), al.I32(), al.I32()
	lBestS, lBestE, lBestID := al.I32(), al.I32(), al.I32()
	var lChunk [4]byte
	var lMask byte
	if a.teddy != nil {
		lMask = al.I32()
		for k := 0; k < a.teddy.MinLen; k++ {
			lChunk[k] = al.V128()
		}
	}
	l := a.l
	get := func(b []byte, x byte) []byte { return append(b, 0x20, x) }
	set := func(b []byte, x byte) []byte { return append(b, 0x21, x) }
	konst := func(b []byte, v int32) []byte { return utils.AppendSLEB128(append(b, 0x41), v) }

	var b []byte
	b = al.EmitDecls(b)
	b, mode := emitFindFromSeed(b, cur)
	b = konst(b, -1)
	b = set(b, lBestS)
	b = get(b, pLen)
	b = set(b, lLimit)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $scan
	b = get(b, lPos)
	b = get(b, lLimit)
	b = append(b, 0x4F, 0x0D, 0x01) // pos >= limit: br_if $done
	if a.teddy != nil {
		b = a.emitRootSkip(b, lPos, lState, lMask, lChunk, pPtr, pLen)
	}

	// state = goto[state][class(input[pos])]
	b = konst(b, l.gotoOff)
	b = get(b, lState)
	b = append(b, 0x41, byte(l.strideShift), 0x74, 0x6A) // + state << strideShift
	if l.compressed {
		b = konst(b, l.classMapOff)
		b = append(get(get(b, pPtr), lPos), 0x6A)
		b = appendInputLoad8u(b)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
	} else {
		b = append(get(get(b, pPtr), lPos), 0x6A)
		b = appendInputLoad8u(b)
	}
	b = append(b, 0x41, 0x01, 0x74, 0x6A) // * 2; add
	b = appendTableLoad16u(b, tableMemIdx)
	b = set(b, lState)

	// Output-bearing nodes are numbered 1..outLimit (acLayout.outLimit).
	if l.outLimit > 0 {
		b = get(b, lState)
		b = konst(b, 1)
		b = append(b, 0x6B) // state - 1
		b = konst(b, int32(l.outLimit))
		b = append(b, 0x49, 0x04, 0x40) // lt_u: if
		// [outIdx, outEnd) = nodeOut[state], nodeOut[state + 1]
		b = konst(b, l.nodeOutOff)
		b = append(get(b, lState), 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx)
		b = set(b, lOutIdx)
		b = konst(b, l.nodeOutOff+2)
		b = append(get(b, lState), 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx)
		b = set(b, lOutEnd)
		b = append(b, 0x02, 0x40) // block $outs_done
		b = append(b, 0x03, 0x40) // loop $outs
		b = get(get(b, lOutIdx), lOutEnd)
		b = append(b, 0x4F, 0x0D, 0x01) // ge_u: br_if $outs_done
		// id = output[outIdx]; outIdx++
		b = konst(b, l.outputOff)
		b = append(get(b, lOutIdx), 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx)
		b = set(b, lID)
		b = append(get(b, lOutIdx), 0x41, 0x01, 0x6A)
		b = set(b, lOutIdx)
		// entry = lens[id]; e = pos + 1; s = e - (entry & lenMask)
		b = konst(b, a.lenOff)
		b = append(get(b, lID), 0x41, 0x01, 0x74, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx)
		b = set(b, lEntry)
		b = append(get(b, lPos), 0x41, 0x01, 0x6A)
		b = set(b, lE)
		b = get(b, lE)
		b = get(b, lEntry)
		b = konst(b, litAltLenMask)
		b = append(b, 0x71, 0x6B) // and; sub
		b = set(b, lS)
		if a.wbLead {
			// A boundary before s: the byte before it (none at 0) differs in
			// wordness from the literal's first byte. Not one: next output.
			b = a.wordAt(b, lS, -1, pPtr, pLen, tableMemIdx)
			b = append(get(b, lEntry), 0x41)
			b = utils.AppendULEB128(b, 14)
			b = append(b, 0x76, 0x41, 0x01, 0x71) // shr_u 14; and 1
			b = append(b, 0x46, 0x0D, 0x00)       // eq: br_if $outs (no boundary)
		}
		if a.wbTrail {
			b = a.wordAt(b, lE, 0, pPtr, pLen, tableMemIdx)
			b = append(get(b, lEntry), 0x41)
			b = utils.AppendULEB128(b, 15)
			b = append(b, 0x76) // shr_u 15
			b = append(b, 0x46, 0x0D, 0x00)
		}
		// Better: no best yet, an earlier start, or the same start and a
		// lower alternative.
		b = get(b, lBestS)
		b = append(b, 0x41, 0x00, 0x48) // bestS < 0
		b = get(get(b, lS), lBestS)
		b = append(b, 0x48, 0x72) // s < bestS; or
		b = get(get(b, lS), lBestS)
		b = append(b, 0x46) // s == bestS
		b = get(get(b, lID), lBestID)
		b = append(b, 0x49, 0x71, 0x72) // id < bestID (unsigned); and; or
		b = append(b, 0x04, 0x40)       // if
		b = append(get(b, lS), 0x21, lBestS)
		b = append(get(b, lE), 0x21, lBestE)
		b = append(get(b, lID), 0x21, lBestID)
		// limit = min(len, s + maxLen): a literal ending later starts later.
		b = get(b, lS)
		b = konst(b, int32(a.maxLen)) //nolint:gosec // bounded by litAltMaxLen
		b = append(b, 0x6A, 0x21, lLimit)
		b = get(get(b, lLimit), pLen)
		b = append(b, 0x4B, 0x04, 0x40) // gt_u: if
		b = append(get(b, pLen), 0x21, lLimit)
		b = append(b, 0x0B)       // end if
		b = append(b, 0x0B)       // end if better
		b = append(b, 0x0C, 0x00) // br $outs
		b = append(b, 0x0B, 0x0B) // end loop $outs, block $outs_done
		b = append(b, 0x0B)       // end if output
	}
	b = append(get(b, lPos), 0x41, 0x01, 0x6A)
	b = set(b, lPos)
	b = append(b, 0x0C, 0x00) // br $scan
	b = append(b, 0x0B, 0x0B) // end loop, block

	// best < 0 ? -1 : start << 32 | end
	b = get(b, lBestS)
	b = append(b, 0x41, 0x00, 0x48, 0x04, 0x7E) // lt_s; if (result i64)
	b = append(b, 0x42, 0x7F)                   // i64.const -1
	b = append(b, 0x05)
	b = append(get(b, lBestS), 0xAD, 0x42, 0x20, 0x86) // extend_u; << 32
	b = append(get(b, lBestE), 0xAD, 0x84)             // extend_u; or
	b = append(b, 0x0B, 0x0B)                          // end if, end func
	return append(utils.AppendULEB128(nil, uint32(len(b))), b...), mode
}

// wordAt pushes whether input[i + add] is a word byte, 0 outside [0, len).
func (a *litAltAC) wordAt(b []byte, i byte, add int32, pPtr, pLen byte, tableMemIdx int) []byte {
	idx := func(b []byte) []byte {
		b = append(b, 0x20, i)
		if add != 0 {
			b = append(utils.AppendSLEB128(append(b, 0x41), add), 0x6A)
		}
		return b
	}
	b = idx(b)
	b = append(b, 0x20, pLen, 0x49, 0x04, 0x7F) // index u< len: if (result i32) — -1 wraps past it
	b = utils.AppendSLEB128(append(b, 0x41), a.wordOff)
	b = append(idx(append(b, 0x20, pPtr)), 0x6A)
	b = appendInputLoad8u(b)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x05, 0x41, 0x00, 0x0B) // else 0
	return b
}

// compileLitAltACFind builds an entry whose find is a literal alternation's
// (analyseLitAltAC): its match body, if it has one, comes from the general
// path with the find taken out, and the find's tables follow.
func compileLitAltACFind(re config.PatternEntry, rp resolvedPattern, a *litAltAC, tableBase int64,
	forceGroupsEngine EngineType, buildOpts CompileOptions) (*compiledPattern, error) {
	p := &compiledPattern{tableEnd: tableBase}
	if re.MatchFunc != "" {
		mre := re
		mre.FindFunc = ""
		mp, err := compilePatternBodies(mre, rp, tableBase, forceGroupsEngine, buildOpts, nil)
		if err != nil {
			return nil, err
		}
		p = mp
	}
	a.plan(int32(p.tableEnd), buildOpts.wordTable) //nolint:gosec // a table address
	ds, n := a.dataSegments()
	p.dataBytes = append(p.dataBytes, ds...)
	p.dataSegCount += n
	p.tableEnd = int64(a.tableEnd)
	p.findExport = re.FindFunc
	p.setFind(buildLitAltACFindBody(a, buildOpts.tableMemIdx))
	how := "uncompressed"
	if a.compressed {
		how = "byte-class compressed"
	}
	note := fmt.Sprintf("find: literal alternation — Aho-Corasick over %d literals (%d nodes, %s)",
		len(a.lits), len(a.ac.nodes), how)
	if re.MatchFunc == "" {
		buildOpts.report().Reason("specialised body — " + note[len("find: "):])
	} else {
		buildOpts.report().Note(note)
	}
	buildOpts.report().findKind(findKindSpecialised, "an alternation of literals: one Aho-Corasick walk")
	if a.teddy != nil {
		buildOpts.report().scan("Aho-Corasick + Teddy", fmt.Sprintf("Aho-Corasick walk with a Teddy skip at its root (%d literals)", len(a.lits)))
	} else {
		buildOpts.report().scan("Aho-Corasick", fmt.Sprintf("Aho-Corasick walk (%d literals)", len(a.lits)))
	}
	return p, nil
}

// emitRootSkip emits the Teddy skip at the automaton's root: while 16
// positions and the probe's bytes fit before len, a window where no literal
// can begin (no lane survives every probed column) is passed over whole, and
// otherwise the walk resumes at its first candidate. Only at the root: there
// no literal is in progress, so restarting the walk at a later position from
// the root finds every literal that begins there or after.
func (a *litAltAC) emitRootSkip(b []byte, lPos, lState, lMask byte, lChunk [4]byte, pPtr, pLen byte) []byte {
	t := a.teddy
	probe := t.MinLen
	b = append(b, 0x20, lState, 0x45, 0x04, 0x40) // state == root: if
	b = append(b, 0x20, lPos, 0x41)
	b = utils.AppendSLEB128(b, int32(16+probe-1))
	b = append(b, 0x6A, 0x20, pLen, 0x4D, 0x04, 0x40) // pos + 16 + probe - 1 <= len: if
	for k := 0; k < probe; k++ {
		b = append(b, 0x20, pPtr, 0x20, lPos, 0x6A)
		if k > 0 {
			b = append(b, 0x41, byte(k), 0x6A)
		}
		b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load (input, memory 0)
		b = append(b, 0x21, lChunk[k])
	}
	group := func(b []byte, lo, hi [4]*[16]byte) []byte {
		for k := 0; k < probe; k++ {
			b = append(b, 0xFD, 0x0C)
			b = append(b, lo[k][:]...)
			b = append(b, 0x20, lChunk[k], 0x41, 0x0F, 0xFD, 0x0F, 0xFD, 0x4E) // chunk & 0x0F
			b = append(b, 0xFD, 0x0E)                                          // swizzle
			b = append(b, 0xFD, 0x0C)
			b = append(b, hi[k][:]...)
			b = append(b, 0x20, lChunk[k], 0x41, 0x04, 0xFD, 0x6D) // chunk >> 4
			b = append(b, 0xFD, 0x0E, 0xFD, 0x4E)                  // swizzle; and
			if k > 0 {
				b = append(b, 0xFD, 0x4E) // and with the columns before
			}
		}
		return b
	}
	b = group(b, [4]*[16]byte{&t.T0Lo, &t.T1Lo, &t.T2Lo, &t.T3Lo}, [4]*[16]byte{&t.T0Hi, &t.T1Hi, &t.T2Hi, &t.T3Hi})
	if t.TwoGroups {
		b = group(b, [4]*[16]byte{&t.BT0Lo, &t.BT1Lo, &t.BT2Lo, &t.BT3Lo}, [4]*[16]byte{&t.BT0Hi, &t.BT1Hi, &t.BT2Hi, &t.BT3Hi})
		b = append(b, 0xFD, 0x50) // v128.or
	}
	b = append(b, 0x41, 0x00, 0xFD, 0x0F, 0xFD, 0x24, 0xFD, 0x64)  // ne 0; bitmask
	b = append(b, 0x22, lMask, 0x45, 0x04, 0x40)                   // tee; eqz: if
	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)        // pos += 16
	b = append(b, 0x0C, 0x03)                                      // br $scan
	b = append(b, 0x0B)                                            // end if
	b = append(b, 0x20, lPos, 0x20, lMask, 0x68, 0x6A, 0x21, lPos) // pos += ctz(mask)
	return append(b, 0x0B, 0x0B)                                   // end if fits, end if root
}

// litAltHasRepeat reports a `*`, `+` or `{n,m}` anywhere in re, as written.
func litAltHasRepeat(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		return true
	}
	for _, sub := range re.Sub {
		if litAltHasRepeat(sub) {
			return true
		}
	}
	return false
}
