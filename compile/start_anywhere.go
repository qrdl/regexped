package compile

import (
	"fmt"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// ── The start-anywhere find, and which find a pattern gets ─────────────────
//
// Today's general find tries start positions one at a time and walks the DFA
// from each until it dies, accepts or reaches the end. On a long run of bytes
// that keeps every attempt alive without ever matching (`a`×N for `a*b`), each
// attempt walks to the end: N²/2 steps. The literal-anchored find has the same
// shape once the part before its literal can itself contain the literal
// (`\w+abc\d` over `abc`×N).
//
// The START-ANYWHERE find is RE2's answer, and it is linear:
//
//   - FORWARD pass: the leftmost-first DFA of `(?s:.)*?(?:pat)`, walked once
//     from `from` until it dies or the input ends, remembering the last
//     accept. The lazy prefix gives every earlier start priority over a later
//     one, so the last accept is the END of the leftmost-first match. (Not
//     the match_func body: that one answers only for a match spanning the
//     WHOLE input.)
//   - BACKWARD pass: the whole pattern reversed, leftmost-longest, run from
//     that end down to the find-from floor. The smallest position it accepts
//     at is the leftmost start s with [s, end) in the language; no start left
//     of the leftmost match's start has any match, so s is that start.
//
// It costs ~29 fuel per byte, except in a forward state that loops on nearly
// every byte (l.dominantStates), whose runs emitDominantBulkSkip crosses at
// 2-4; input that enters and leaves such a state every byte costs up to 37.
// Today's find costs 1.4-8 on ordinary text that its SIMD skip can leap over,
// and this one walks every match twice. So it is not a replacement.
// classifyFind picks, at compile time:
//
//   - TODAY'S FIND, unchanged, where it is PROVABLY linear (group A): a failed
//     attempt walks a bounded number of bytes (failedWalkBound), both shape
//     detectors apply, or the literal-anchored find's parts around its literal
//     cannot contain that literal (litAnchorLinear). Also for anything the
//     start-anywhere find cannot serve: an empty-width assertion (the backward
//     pass does not mirror `\b`, `^`, `$`, `\A`, `\z`), a hinted pattern
//     outside the two shapes below, a pattern anchored at 0.
//   - THE START-ANYWHERE FIND ALONE for two shapes, both starting with an
//     unbounded repeat of a class common in prose (byte-rarity score ≥ 40, the
//     Shufti threshold): without the space byte and with no literal to scan
//     for (group B, `\w+@\w+`) unless `prefer-match` — today's find costs
//     100+ fuel per byte there even on ordinary text; with the space byte
//     (group C, `[^,]*,`) only under `prefer-no-match`.
//   - TODAY'S FIND PLUS A WORK COUNTER (findSwitch) for everything else: once
//     the bytes its failed attempts have walked pass N × (bytes advanced) +
//     64, the call hands over to the start-anywhere find. Ordinary text never
//     trips it, so it costs what today's find costs plus 0-6% (perftest).
//
// The start-anywhere find needs its forward automaton within max_dfa_states;
// a pattern whose automaton is larger keeps today's find.

// findStrategy is how one pattern's find is served.
type findStrategy uint8

const (
	findToday     findStrategy = iota // today's body, nothing added
	findNewSearch                     // the start-anywhere find alone
	findSwitch                        // today's body + the counter + the start-anywhere find
)

func (s findStrategy) String() string {
	switch s {
	case findNewSearch:
		return "start-anywhere"
	case findSwitch:
		return "switch"
	}
	return "today"
}

// defaultSwitchN is the counter's N: the same value serves every shape
// measured, and 8 and 16 behaved identically at 64 KB.
const defaultSwitchN = 4

// hasEmptyWidthAssertion reports whether re contains any assertion the
// backward pass would have to mirror.
func hasEmptyWidthAssertion(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	for _, s := range re.Sub {
		if hasEmptyWidthAssertion(s) {
			return true
		}
	}
	return false
}

// leadingRepeatBytes returns the byte set of re's leading UNBOUNDED repeat
// (`X*`, `X+`, `X{n,}` over a class, a dot or one literal byte), and whether
// re starts with one.
func leadingRepeatBytes(re *syntax.Regexp) (set [256]bool, ok bool) {
	for re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		re = re.Sub[0]
	}
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
	case syntax.OpRepeat:
		if re.Max != -1 {
			return set, false
		}
	default:
		return set, false
	}
	sub := re.Sub[0]
	switch sub.Op {
	case syntax.OpAnyChar:
		for i := range set {
			set[i] = true
		}
	case syntax.OpAnyCharNotNL:
		for i := range set {
			set[i] = i != '\n'
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(sub.Rune); i += 2 {
			for r := sub.Rune[i]; r <= sub.Rune[i+1] && r <= 0xFF; r++ {
				set[r] = true
			}
		}
	case syntax.OpLiteral:
		if len(sub.Rune) != 1 || sub.Rune[0] > 0xFF {
			return set, false
		}
		set[sub.Rune[0]] = true
		if sub.Flags&syntax.FoldCase != 0 {
			r := sub.Rune[0]
			if r >= 'a' && r <= 'z' {
				set[r-'a'+'A'] = true
			} else if r >= 'A' && r <= 'Z' {
				set[r-'A'+'a'] = true
			}
		}
	default:
		return set, false
	}
	return set, true
}

// setRaritySum is firstByteSetRaritySum over a byte set.
func setRaritySum(set [256]bool) int {
	var bytes []byte
	for i, in := range set {
		if in {
			bytes = append(bytes, byte(i))
		}
	}
	return firstByteSetRaritySum(bytes)
}

// wideClassThreshold is the rarity score at and above which a leading class is
// common in prose — the Shufti/scalar threshold of shuftiBeatsScalar, reused so
// the compiler has one notion of "common in text".
const wideClassThreshold = 40

// findClassInput is what classifyFind looks at.
type findClassInput struct {
	parsed  *syntax.Regexp // captures stripped
	table   *dfaTable      // the leftmost-first find DFA
	l       *dfaLayout     // its layout, with both shape detectors run
	lm      LikelyMode
	anchor  bool // today's body can only match at 0
	lap     *litAnchorPoint
	body    findBody // which body today's compiler builds
	literal bool     // today's body scans for a literal (prefix, mandatory literal, literal anchor)
	inSet   bool     // classifying a set member: only engine-independent proofs count
}

// findBody names today's body for a pattern.
type findBody uint8

const (
	bodyGeneral findBody = iota
	bodyLitAnchor
	bodyAltLitAnchor
)

// classifyFind decides how the pattern's find is served and why.
func classifyFind(in findClassInput) (findStrategy, string) {
	if hasEmptyWidthAssertion(in.parsed) {
		return findToday, "empty-width assertion"
	}
	if in.anchor {
		return findToday, "matches only at 0"
	}
	if k, ok := failedWalkBound(in.table); ok {
		return findToday, fmt.Sprintf("linear: a failed attempt walks at most %d bytes", k)
	}
	if !in.inSet {
		switch in.body {
		case bodyGeneral:
			if in.l.skipSafeOnDead && in.l.eofSkipSafe {
				return findToday, "linear: both shape detectors apply"
			}
		case bodyLitAnchor:
			if in.lap != nil && litAnchorLinear(in.lap) {
				return findToday, "linear: the parts around the literal cannot contain it"
			}
		}
	}
	if set, ok := leadingRepeatBytes(in.parsed); ok && setRaritySum(set) >= wideClassThreshold {
		if set[' '] {
			if in.lm == LikelyNoMatch {
				return findNewSearch, "leading repeat crosses words, prefer-no-match"
			}
			return findSwitch, "leading repeat crosses words"
		}
		if !in.literal {
			if in.lm == LikelyMatch {
				return findToday, "leading word repeat, prefer-match"
			}
			return findNewSearch, "leading word repeat, no literal to scan for"
		}
	}
	if in.lm != LikelyNeutral {
		return findToday, "hinted"
	}
	return findSwitch, "not provably linear"
}

// litAnchorLinear reports whether a literal-anchored find over lap is linear:
// every attempt starts at an occurrence of the literal, and when neither the
// part before it nor the part after it can contain the literal, the backward
// walk cannot cross the previous occurrence and the forward walk cannot cross
// the next, so each byte is walked a bounded number of times.
func litAnchorLinear(lap *litAnchorPoint) bool {
	after := &syntax.Regexp{Op: syntax.OpEmptyMatch}
	if lap.suffixRe.Op == syntax.OpConcat && len(lap.suffixRe.Sub) > 1 {
		after = &syntax.Regexp{Op: syntax.OpConcat, Sub: lap.suffixRe.Sub[1:], Flags: lap.suffixRe.Flags}
	}
	for _, lit := range lap.litSet {
		if regexpCanContain(lap.prefixRe, lit) || regexpCanContain(after, lit) {
			return false
		}
	}
	return true
}

// regexpCanContain reports whether a walk of re's automaton can read lit
// without dying — from any state it can reach. Unsure answers (the automaton
// cannot be built) are true, the safe direction.
func regexpCanContain(re *syntax.Regexp, lit []byte) bool {
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return true
	}
	d, ok := newDFA(prog, false, false, maxHelperDFAStates)
	if !ok {
		return true
	}
	t := dfaTableFrom(d)
	reach := make([]bool, t.numStates)
	stack := []int{t.startState}
	reach[t.startState] = true
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
	for s := 0; s < t.numStates; s++ {
		if !reach[s] {
			continue
		}
		q := s
		for _, c := range lit {
			q = t.transitions[q*256+int(c)]
			if q < 0 {
				break
			}
		}
		if q >= 0 {
			return true
		}
	}
	return false
}

// failedWalkBound reports the longest walk an attempt can make without ever
// being in an accepting state, from either find start state, and whether it
// is finite. It is finite exactly when no cycle of NON-accepting states is
// reachable at all — through accepting states included, because a successful
// attempt keeps walking after its last accept and the next search re-walks
// those bytes. A finite bound makes every attempt's wasted walk at most that
// many bytes, so any find that tries start positions one at a time is linear,
// whichever code does the walking.
func failedWalkBound(t *dfaTable) (int, bool) {
	accepting := func(s int) bool { return t.midAcceptStates[s] != 0 || t.acceptStates[s] != 0 }
	reach := make([]bool, t.numStates)
	var stack []int
	for _, r := range []int{t.startState, t.midStartState} {
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
	// Longest path through non-accepting reachable states, by an iterative
	// DFS with colours; a grey successor is a cycle.
	const white, grey, black = 0, 1, 2
	colour := make([]int, t.numStates)
	longest := make([]int, t.numStates)
	type frame struct{ s, c int }
	for root := 0; root < t.numStates; root++ {
		if !reach[root] || accepting(root) || colour[root] != white {
			continue
		}
		colour[root] = grey
		frames := []frame{{root, 0}}
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			if f.c == 256 {
				best := 0
				for c := 0; c < 256; c++ {
					if n := t.transitions[f.s*256+c]; n >= 0 && reach[n] && !accepting(n) && longest[n] > best {
						best = longest[n]
					}
				}
				longest[f.s] = best + 1
				colour[f.s] = black
				frames = frames[:len(frames)-1]
				continue
			}
			n := t.transitions[f.s*256+f.c]
			f.c++
			if n < 0 || !reach[n] || accepting(n) {
				continue
			}
			switch colour[n] {
			case grey:
				return 0, false
			case white:
				colour[n] = grey
				frames = append(frames, frame{n, 0})
			}
		}
	}
	bound := 0
	for s := 0; s < t.numStates; s++ {
		if reach[s] && longest[s] > bound {
			bound = longest[s]
		}
	}
	return bound, true
}

// buildStartAnywhereFind fills p with the two passes and reports whether it
// did. false leaves p untouched, and the caller keeps today's find.
func (p *compiledPattern) buildStartAnywhereFind(re config.RegexEntry, base int64, opts CompileOptions) bool {
	sa, ok := buildStartAnywherePasses(re.Pattern, opts, base, utils.PageAlign)
	if !ok {
		return false
	}
	p.saFwdBody, p.saRevBody = sa.fwdBody, sa.revBody
	p.dataBytes = append(p.dataBytes, sa.data...)
	p.dataSegCount += sa.segs
	p.tableEnd = sa.end
	return true
}

// startAnywherePasses is the start-anywhere find's two passes: their
// size-prefixed bodies and their tables' data segments.
type startAnywherePasses struct {
	fwdBody, revBody []byte
	data             []byte
	segs             int
	end              int64
}

// buildStartAnywherePasses builds both passes for pattern, the forward
// tables at base and the backward ones at align(the forward end). Refused
// (false) for an empty-width assertion, an unsupported rune, or an automaton
// over opts' state or memory limit.
func buildStartAnywherePasses(pattern string, opts CompileOptions, base int64, align func(int64) int64) (startAnywherePasses, bool) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return startAnywherePasses{}, false
	}
	stripCaptures(parsed)
	if hasEmptyWidthAssertion(parsed) {
		return startAnywherePasses{}, false
	}
	maxStates := resolveMaxDFAStates(&opts)
	memLimit := resolveMaxDFAMemory(&opts)
	build := func(re *syntax.Regexp, lf bool) *dfaTable {
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			return nil
		}
		if unsupportedRune(prog, opts.ByteMode) >= 0 && !opts.Unicode {
			return nil
		}
		d, ok := newDFA(prog, opts.Unicode, lf, max(maxHelperDFAStates, maxStates))
		if !ok {
			return nil
		}
		t := dfaTableFrom(d)
		if t.numStates > maxStates || (memLimit > 0 && dfaTableBytes(t) > memLimit) {
			return nil
		}
		return t
	}

	// Forward pass: the start-anywhere automaton, leftmost-first.
	fwdRe, err := syntax.Parse(`(?s:.)*?(?:`+parsed.String()+`)`, syntax.Perl)
	if err != nil {
		return startAnywherePasses{}, false
	}
	fwdTable := build(fwdRe, true)
	if fwdTable == nil {
		return startAnywherePasses{}, false
	}
	fwdL := buildDFALayout(dfaLayoutParams{t: fwdTable, tableBase: base, needFind: true, leftmostFirst: true})
	// Backward pass: the whole pattern reversed, leftmost-longest.
	revTable := build(reverseRegexp(parsed), false)
	if revTable == nil {
		return startAnywherePasses{}, false
	}
	revL := buildDFALayout(dfaLayoutParams{t: revTable, tableBase: align(fwdL.tableEnd), needFind: true})

	fwdRaw, fwdSegs := stripSegCount(dfaDataSegments(fwdL, true, false))
	revRaw, revSegs := stripSegCount(dfaDataSegments(revL, true, false))
	return startAnywherePasses{
		fwdBody: buildStartAnywhereForwardBody(fwdL, opts.tableMemIdx),
		revBody: buildStartAnywhereBackBody(revL, opts.tableMemIdx),
		data:    append(fwdRaw, revRaw...),
		segs:    fwdSegs + revSegs,
		end:     revL.tableEnd,
	}, true
}

// emitWalkerTransition emits one transition of state on the byte at ptr+pos,
// for a u8 (plain or class-compressed) or u16 layout. byteLocal is scratch.
func emitWalkerTransition(b []byte, l *dfaLayout, stateLocal, ptrLocal, posLocal, byteLocal byte, tableMemIdx int) []byte {
	switch {
	case l.useU8 && l.useCompression:
		return emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			stateLocal, byteLocal, ptrLocal, posLocal, 0xff, tableMemIdx)
	case l.useU8:
		return emitSimpleU8Transition(b, l.tableOff, stateLocal, ptrLocal, posLocal, 0xff, tableMemIdx)
	}
	b = append(b, 0x20, ptrLocal, 0x20, posLocal, 0x6A)
	b = appendInputLoad8u(b)
	b = append(b, 0x21, byteLocal)
	return emitU16Transition(b, l.tableOff, l.useRowDedup, l.rowMapOff, stateLocal, byteLocal, tableMemIdx)
}

// buildStartAnywhereForwardBody returns the size-prefixed forward pass,
// (ptr, len) → i32: it walks input[0:len) from the start state and returns
// the position after the last accept, or -1 when nothing accepted. The
// caller passes (ptr + from, len - from), so the answer is relative to from.
func buildStartAnywhereForwardBody(l *dfaLayout, tableMemIdx int) []byte {
	const (
		locPtr   = 0
		locLen   = 1
		locState = 2
		locPos   = 3
		locLast  = 4
		locByte  = 5
		locTmp   = 6 // bulk skip only
		locChunk = 7 // bulk skip only (v128)
	)
	// The states the SIMD bulk skip serves: a state that loops on nearly
	// every byte — `(?s:.)*?(?:[^\n]*ERROR)` sits in one looping on all but
	// `E` — is left 16 bytes at a time instead of one. Capped, since each
	// costs a compare on every byte.
	dominant := l.dominantStates
	if len(dominant) > maxForwardBulkSkipStates {
		dominant = dominant[:maxForwardBulkSkipStates]
	}
	b := []byte{0x01, 0x04, 0x7F} // four i32 locals
	if len(dominant) > 0 {
		b = []byte{0x02, 0x05, 0x7F, 0x01, 0x7B} // five i32, one v128
	}

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x21, locState)
	b = append(b, 0x41, 0x00, 0x21, locPos)  // pos = 0
	b = append(b, 0x41, 0x7F, 0x21, locLast) // last = -1

	// An empty match at the start.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40, 0x41, 0x00, 0x21, locLast, 0x0B) // if: last = 0

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $fwd

	// End of input: an accepting state accepts here, then stop.
	b = append(b, 0x20, locPos, 0x20, locLen, 0x4E) // pos >= len (signed)
	b = append(b, 0x04, 0x40)
	b = emitAcceptBitOnStack(b, locState, l.acceptLimit)
	b = append(b, 0x04, 0x40, 0x20, locLen, 0x21, locLast, 0x0B) // if: last = len
	b = append(b, 0x0C, 0x02)                                    // br $done
	b = append(b, 0x0B)

	b = emitWalkerTransition(b, l, locState, locPtr, locPos, locByte, tableMemIdx)

	// Dead: every thread is gone, so no later accept can come.
	b = append(b, 0x20, locState, 0x45, 0x04, 0x40, 0x0C, 0x02, 0x0B)

	// An accept after this byte ends a match at pos + 1.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locPos, 0x41, 0x01, 0x6A, 0x21, locLast)
	b = append(b, 0x0B)

	// In a looping state, skip the run of bytes that keeps it there: pos
	// ends on the last of them, and the loop resumes on the byte that leaves.
	for _, info := range dominant {
		b = append(b, 0x20, locState, 0x41)
		b = utils.AppendSLEB128(b, info.state)
		b = append(b, 0x46, 0x04, 0x40) // i32.eq; if
		b = emitDominantBulkSkip(b, info, info.isMidAccept, locPos, locLen, locLast, locPtr, locChunk, locTmp)
		b = append(b, 0x0B)
	}

	b = append(b, 0x20, locPos, 0x41, 0x01, 0x6A, 0x21, locPos) // pos++
	b = append(b, 0x0C, 0x00)                                   // br $fwd
	b = append(b, 0x0B, 0x0B)                                   // end loop, end block

	b = append(b, 0x20, locLast, 0x0B)
	sz := utils.AppendULEB128(nil, uint32(len(b)))
	return append(sz, b...)
}

// maxForwardBulkSkipStates caps how many looping states the forward pass
// tests for on every byte.
const maxForwardBulkSkipStates = 4

// buildStartAnywhereBackBody returns the size-prefixed backward pass,
// (ptr, scan_end) → i32: it walks input[scan_end], input[scan_end-1], … down
// to the find-from global on the reversed, leftmost-longest DFA and returns
// the lowest position it accepted at (the match start), or -1. It is the
// literal-anchored find's backward walker without the line-anchor handling —
// the start-anywhere find serves no pattern with an assertion — and on any
// table width.
func buildStartAnywhereBackBody(l *dfaLayout, tableMemIdx int) []byte {
	const (
		locPtr     = 0
		locScanEnd = 1
		locState   = 2
		locPos     = 3
		locLast    = 4
		locByte    = 5
	)
	b := []byte{0x01, 0x04, 0x7F} // four i32 locals
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x21, locState)
	b = append(b, 0x20, locScanEnd, 0x21, locPos)
	b = append(b, 0x41, 0x7F, 0x21, locLast)

	// The reversed pattern accepting the empty string: a match ending here
	// may start here.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locScanEnd, 0x41, 0x01, 0x6A, 0x21, locLast)
	b = append(b, 0x0B)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $rev
	// pos < floor: an accepting state accepts at the floor, then stop.
	b = append(b, 0x20, locPos, 0x23)
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if
	b = emitAcceptBitOnStack(b, locState, l.acceptLimit)
	b = append(b, 0x04, 0x40, 0x23)
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = append(b, 0x21, locLast, 0x0B)
	b = append(b, 0x0C, 0x02) // br $done
	b = append(b, 0x0B)

	b = emitWalkerTransition(b, l, locState, locPtr, locPos, locByte, tableMemIdx)
	b = append(b, 0x20, locState, 0x45, 0x04, 0x40, 0x0C, 0x02, 0x0B) // dead → $done

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40, 0x20, locPos, 0x21, locLast, 0x0B) // accept: last = pos

	b = append(b, 0x20, locPos, 0x41, 0x01, 0x6B, 0x21, locPos) // pos--
	b = append(b, 0x0C, 0x00)                                   // br $rev
	b = append(b, 0x0B, 0x0B)

	b = append(b, 0x20, locLast, 0x0B)
	sz := utils.AppendULEB128(nil, uint32(len(b)))
	return append(sz, b...)
}

// buildStartAnywhereFindBody joins the two passes into a find body,
// (ptr, len) → i64, returning (start << 32 | end) or -1. It is built at
// assembly time, when both passes' function indices are known. Unsized.
func buildStartAnywhereFindBody(fwdFuncIdx, revFuncIdx int) ([]byte, findFromMode) {
	const (
		locPtr = 0
		locLen = 1
	)
	a := newLocalAlloc(2)
	cur := a.ScanCursor()
	locFrom := cur.Local()
	locEnd := a.I32()
	locStart := a.I32()
	var b []byte
	b = a.EmitDecls(b)
	b, mode := emitFindFromSeed(b, cur)

	// end = forward(ptr + from, len - from); negative = no match.
	b = append(b, 0x20, locPtr, 0x20, locFrom, 0x6A) // ptr + from
	b = append(b, 0x20, locLen, 0x20, locFrom, 0x6B) // len - from
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(fwdFuncIdx))
	b = append(b, 0x22, locEnd)                                    // local.tee end
	b = append(b, 0x41, 0x00, 0x48)                                // i32.const 0; i32.lt_s
	b = append(b, 0x04, 0x40)                                      // if
	b = append(b, 0x42, 0x7F, 0x0F)                                // i64.const -1; return
	b = append(b, 0x0B)                                            // end if
	b = append(b, 0x20, locFrom, 0x20, locEnd, 0x6A, 0x21, locEnd) // end = from + end

	// start = backward(ptr, end - 1); the walker's floor is the find-from
	// global. The forward pass proved a match ends at `end`, so a negative
	// start is a defect in one of the passes: trap rather than answer.
	b = append(b, 0x20, locPtr, 0x20, locEnd, 0x41, 0x01, 0x6B) // ptr, end - 1
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(revFuncIdx))
	b = append(b, 0x22, locStart)   // local.tee start
	b = append(b, 0x41, 0x00, 0x48) // i32.const 0; i32.lt_s
	b = append(b, 0x04, 0x40)       // if
	b = append(b, 0x00)             // unreachable
	b = append(b, 0x0B)             // end if

	b = append(b, 0x20, locStart, 0xAD, 0x42, 0x20, 0x86) // i64(start) << 32
	b = append(b, 0x20, locEnd, 0xAD, 0x84)               // | i64(end)
	b = append(b, 0x0B)                                   // end function
	return b, mode
}

// buildStartAnywhereDispatchBody is the find function every caller reaches
// for a pattern carrying the switch — the exported wrapper, `groups` and the
// batch entries alike: today's body first, and the start-anywhere find when
// today's answers the sentinel (having already set the find-from global to
// where the search resumes). (ptr, len) → i64. Unsized.
func buildStartAnywhereDispatchBody(todayFuncIdx, startAnywhereFuncIdx int) []byte {
	const (
		locPtr = 0
		locLen = 1
		locR   = 2
	)
	b := []byte{0x01, 0x01, 0x7E} // one i64 local: r
	b = append(b, 0x20, locPtr, 0x20, locLen, 0x10)
	b = utils.AppendULEB128(b, uint32(todayFuncIdx))
	b = append(b, 0x22, locR, 0x42)
	b = utils.AppendSLEB128(b, startAnywhereSwitchSentinel)
	b = append(b, 0x51, 0x04, 0x40) // i64.eq; if
	b = append(b, 0x20, locPtr, 0x20, locLen, 0x10)
	b = utils.AppendULEB128(b, uint32(startAnywhereFuncIdx))
	b = append(b, 0x0F, 0x0B) // return; end if
	b = append(b, 0x20, locR, 0x0B)
	return b
}

// startAnywhereSwitchSentinel is what today's find body answers when its work
// counter trips: "hand the rest of this search over". It never leaves the
// module — the dispatcher consumes it.
const startAnywhereSwitchSentinel = -3

// switchCounter configures the work counter emitFindSwitchCheck adds to a find
// body's failed-attempt exits.
type switchCounter struct {
	walkedLocal byte
	n           int32
}

// startAnywhereSwitchSlack is the constant in the budget
// N × (bytes advanced) + slack, so the first attempts of a call cannot trip
// it on their own.
const startAnywhereSwitchSlack = 64

// emitFindSwitchCheck compares the walks of the EARLIER failed attempts with
// the budget — stores the next start position in the find-from global and
// returns the sentinel when they are over it — and then adds this attempt's
// walk. Checking before adding is what keeps ONE long failed walk from
// tripping it: that is linear (`X[a-zA-Z]+Y` over `X` + a long tail without
// `Y` walks once, and a literal skip passes every later start), and it is
// the second long walk that shows the quadratic case. It is placed where the
// attempt has already been proved to have no match, just before
// attempt_start moves on, so no answer is skipped. No-op when sw is empty.
func emitFindSwitchCheck(b []byte, posLocal, attemptStartLocal byte, sw []switchCounter) []byte {
	if len(sw) == 0 {
		return b
	}
	// The general body tries start positions in order, so every start up to
	// attempt_start is proved to have no match: resume one past it.
	return emitFindSwitchCharge(b, sw[0].walkedLocal, func(b []byte) []byte {
		return append(b, 0x20, posLocal, 0x20, attemptStartLocal, 0x6B) // pos - attempt_start
	}, attemptStartLocal, sw[0].n, true)
}

// switchShortWalk is the longest failed walk the counter does not charge. A
// failed attempt is usually a byte or two — a candidate that was not a match —
// and charging each one cost ~16 instructions, +14.5% on a log scan whose every
// line carries the mandatory literal. Skipping walks this short keeps the
// guarantee: each start position is tried once per call, so what goes uncounted
// is at most switchShortWalk bytes per position, which is linear; only long
// walks can make a find quadratic, and those are all counted.
const switchShortWalk = 32

// emitFindSwitchCharge charges one failed attempt's walk — pushed by walk,
// which must be free of side effects, since it is emitted twice — to the
// counter in w: the budget is checked against the EARLIER attempts (see
// emitFindSwitchCheck), then the walk is added. A walk of at most
// switchShortWalk bytes is not charged at all.
//
// Computing the walk ONCE into a scratch local was measured and rejected: it
// moved ~3,400 fuel from bt-find-mand-lit (long failed walks, which it saves
// two instructions each) onto bt-find-prefix (thousands of short ones, which it
// costs one each) and left the total unchanged.
func emitFindSwitchCharge(b []byte, w byte, walk func([]byte) []byte, attemptStartLocal byte, n int32, resumeNext bool) []byte {
	b = walk(b)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, switchShortWalk)
	b = append(b, 0x4B, 0x04, 0x40) // i32.gt_u; if
	b = emitFindSwitchBudget(b, w, attemptStartLocal, n, resumeNext)
	b = append(b, 0x20, w)
	b = walk(b)
	b = append(b, 0x6A, 0x21, w) // walked += walk
	return append(b, 0x0B)
}

// emitFindSwitchBudget compares the counter with N × (attempt_start - from)
// + slack and, when it is over, returns the sentinel. resumeNext moves the
// find-from global to attempt_start + 1 first; without it the start-anywhere
// find searches again from `from`, for a body (the literal-anchored ones)
// whose failed candidates do not prove every earlier start matchless.
func emitFindSwitchBudget(b []byte, w, attemptStartLocal byte, n int32, resumeNext bool) []byte {
	b = append(b, 0x20, w)
	// N × (attempt_start - from) + slack
	b = append(b, 0x20, attemptStartLocal, 0x23)
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = append(b, 0x6B, 0x41)
	b = utils.AppendSLEB128(b, n)
	b = append(b, 0x6C, 0x41)
	b = utils.AppendSLEB128(b, startAnywhereSwitchSlack)
	b = append(b, 0x6A)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	if resumeNext {
		b = append(b, 0x20, attemptStartLocal, 0x41, 0x01, 0x6A)
		b = emitFindFromSetFromStack(b)
	}
	b = append(b, 0x42)
	b = utils.AppendSLEB128(b, startAnywhereSwitchSentinel)
	b = append(b, 0x0F, 0x0B) // return; end if
	return b
}

// emitFindFromSetFromStack appends `global.set find_from` for a value
// already on the stack.
func emitFindFromSetFromStack(b []byte) []byte {
	b = append(b, 0x24)
	return utils.AppendULEB128(b, findFromGlobalIdx)
}

// appendStartAnywhereBodies appends the start-anywhere find's functions in
// funcLayout's order — the two passes, the glue, and a switch's dispatcher —
// and settles the pattern's findFromMode. Both assemblers call it, after
// today's find, so the two cannot lay the slots out differently.
func (p *compiledPattern) appendStartAnywhereBodies(cs []byte, base int) []byte {
	if p.saFwdBody == nil {
		return cs
	}
	cs = append(cs, p.saFwdBody...)
	cs = append(cs, p.saRevBody...)
	glue, glueMode := buildStartAnywhereFindBody(base+p.slotIndex(slotSAFwd), base+p.slotIndex(slotSARev))
	cs = utils.AppendULEB128(cs, uint32(len(glue)))
	cs = append(cs, glue...)
	if !p.saSwitch {
		p.findFromMode = glueMode
		return cs
	}
	// The dispatcher returns whichever body answered, so the two must read
	// `from` the same way — both seed from the find-from global.
	if glueMode != p.findFromMode {
		panic("compile: start-anywhere switch: today's find and the start-anywhere find read `from` differently")
	}
	d := buildStartAnywhereDispatchBody(base+p.todayFindOff(), base+p.slotIndex(slotSAGlue))
	cs = utils.AppendULEB128(cs, uint32(len(d)))
	return append(cs, d...)
}

// switchNFor is the counter's N: the test override, or defaultSwitchN.
func switchNFor(opts CompileOptions) int32 {
	if opts.StartAnywhereSwitchN > 0 {
		return int32(opts.StartAnywhereSwitchN) //nolint:gosec // a small test knob
	}
	return defaultSwitchN
}

// chooseFindStrategy applies the test overrides, else classifyFind, to a
// pattern whose today's find body has just been decided (p carries the
// literal-anchored artifacts when it is one of those).
func (p *compiledPattern) chooseFindStrategy(re config.RegexEntry, table *dfaTable, l *dfaLayout,
	lap *litAnchorPoint, mandLit *mandatoryLit, anchored bool, opts CompileOptions,
) (findStrategy, string) {
	switch {
	case opts.TodayFind:
		return findToday, "forced"
	case opts.StartAnywhereFind:
		return findNewSearch, "forced"
	case opts.StartAnywhereSwitchN > 0:
		return findSwitch, "forced"
	}
	parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
	if err != nil {
		return findToday, "unparseable"
	}
	stripCaptures(parsed)
	in := findClassInput{
		parsed:  parsed,
		table:   table,
		l:       l,
		lm:      opts.LikelyMode,
		anchor:  anchored,
		body:    bodyGeneral,
		literal: lap != nil || p.altLitAnchorBranches != nil || mandLit != nil || len(l.prefix) > 0,
	}
	switch {
	case p.litAnchorBackScanBody != nil:
		in.body, in.lap = bodyLitAnchor, lap
	case p.altLitAnchorBranches != nil:
		in.body = bodyAltLitAnchor
	}
	return classifyFind(in)
}

// stampAltLitAnchorBranches rebuilds every branch's backward walker and
// forward verifier to stamp where they stopped, for the switch's counter.
func (p *compiledPattern) stampAltLitAnchorBranches(tableMemIdx int) {
	g := p.backStampP1 - 1
	for i := range p.altLitAnchorBranches {
		br := &p.altLitAnchorBranches[i]
		br.backScanBody = buildLitAnchorBackScanBodyStamped(br.revL, br.revTable, tableMemIdx, true, false, g)
		br.forwardVerifyBody = buildAltLitAnchorForwardVerifyBodyStamped(br.fwdTable, br.fwdL, tableMemIdx, g)
	}
}
