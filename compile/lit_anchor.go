package compile

import "regexp/syntax"

// litAnchorPoint describes a three-way literal-anchored split of a regexp pattern:
//
//	PREFIX · LitSet · SUFFIX
//
// Every valid match must contain one of the literals in LitSet, preceded by a
// match of prefixRe and followed by a match of SuffixRe (which includes the
// literal itself so the forward DFA can be started at the match start and run
// to completion).
//
// anchored is true when prefixRe begins with ^ or (?m:^), which means the
// backward scan can stop at '\n' or pos 0 rather than running to a dead state.
type litAnchorPoint struct {
	prefixRe *syntax.Regexp
	litSet   [][]byte       // 1..8 literals of len >= 2, or ONE one-byte literal
	suffixRe *syntax.Regexp // includes the literal itself
	anchored bool
}

// simpleClassPrefix reports whether re is a bare `[class]{M}` exact-count
// repeat (no anchors, no nested concat — just a single class repeated a
// fixed number of times) with M in [1,16]. This is the shape
// buildSimplePrefixCheckBody can verify with a single SIMD chunk load
// instead of buildLitAnchorBackScanBody's generic scalar per-byte reverse
// walk. Returns the class's SIMD nibble-lookup
// table (same encoding as litChainBranchInfo.tlo — see analyseLitChainBranch
// in engine_dfa.go) and M on success.
//
// Deliberately narrower than analyseLitChainBranch's prefix handling: that
// function requires the pattern's *suffix* to also be a bounded class-chain
// (the mixed-prefix shape), which excludes any prefix ahead of an unbounded suffix like
// `[^\n]+` (parsed as OpPlus, not OpRepeat) — exactly the shape lit-anchor
// patterns commonly have. simpleClassPrefix only looks at the prefix, so it
// applies regardless of what the suffix looks like.
func simpleClassPrefix(re *syntax.Regexp) (tlo [16]byte, count int, ok bool) {
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpRepeat || re.Min != re.Max || re.Min < 1 || re.Min > 16 {
		return tlo, 0, false
	}
	if len(re.Sub) != 1 {
		return tlo, 0, false
	}
	child := re.Sub[0]
	for child.Op == syntax.OpCapture && len(child.Sub) == 1 {
		child = child.Sub[0]
	}
	var bitmap [32]byte
	switch child.Op {
	case syntax.OpCharClass:
		for i := 0; i+1 < len(child.Rune); i += 2 {
			lo, hi := child.Rune[i], child.Rune[i+1]
			if lo > 127 || hi > 127 {
				return tlo, 0, false
			}
			for r := lo; r <= hi; r++ {
				bitmap[r>>3] |= 1 << uint(r&7)
			}
		}
	case syntax.OpLiteral:
		if len(child.Rune) != 1 || child.Rune[0] > 127 {
			return tlo, 0, false
		}
		r := child.Rune[0]
		bitmap[r>>3] |= 1 << uint(r&7)
	default:
		return tlo, 0, false
	}
	empty := true
	for _, b := range bitmap {
		if b != 0 {
			empty = false
			break
		}
	}
	if empty {
		return tlo, 0, false
	}
	for b := 0; b < 128; b++ {
		if bitmap[b>>3]&(1<<uint(b&7)) != 0 {
			tlo[b&0xF] |= 1 << uint(b>>4)
		}
	}
	return tlo, re.Min, true
}

// extractLitSet returns the literal set encoded by re, or nil when re is not
// a qualifying literal or alternation of literals.
//
// Qualifying: no FoldCase, length >= 2 bytes, at most 8 alternatives, and
// runes the mode takes as bytes (literalBytes: ASCII in byte mode, UTF-8 in
// Unicode mode).
func extractLitSet(re *syntax.Regexp, unicode bool) [][]byte {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		bs, ok := literalBytes(re.Rune, unicode)
		if !ok || len(bs) < 2 {
			return nil
		}
		return [][]byte{bs}

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return extractLitSet(re.Sub[0], unicode)
		}
		return nil

	case syntax.OpAlternate:
		var result [][]byte
		for _, sub := range re.Sub {
			lits := extractLitSet(sub, unicode)
			if lits == nil || len(lits) != 1 {
				return nil
			}
			result = append(result, lits[0])
		}
		if len(result) == 0 {
			return nil
		}
		return result

	default:
		return nil
	}
}

// prefixStartsWithLineAnchor reports whether re starts with a line or text
// anchor: OpBeginLine ((?m:^)) or OpBeginText (^/\A).
func prefixStartsWithLineAnchor(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpBeginText:
		return true
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return prefixStartsWithLineAnchor(re.Sub[0])
		}
		return false
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return prefixStartsWithLineAnchor(re.Sub[0])
		}
		return false
	default:
		return false
	}
}

// reverseRegexp returns a deep-copied, direction-reversed form of re.
//
// The reversed regexp, when compiled to a DFA and driven backward (reading
// bytes from right to left), accepts exactly the positions where the forward
// regexp's match starts.  Anchors are flipped:
//
//	OpBeginLine  ↔  OpEndLine
//	OpBeginText  ↔  OpEndText
//
// All other ops are structurally mirrored: OpConcat children are reversed and
// each child reversed recursively; OpLiteral runes are reversed.  OpAlternate
// branches are individually reversed but kept in the original order.
func reverseRegexp(re *syntax.Regexp) *syntax.Regexp {
	n := &syntax.Regexp{
		Op:    re.Op,
		Flags: re.Flags,
		Min:   re.Min,
		Max:   re.Max,
		Cap:   re.Cap,
		Name:  re.Name,
	}
	switch re.Op {
	case syntax.OpConcat:
		n.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			n.Sub[len(re.Sub)-1-i] = reverseRegexp(sub)
		}

	case syntax.OpLiteral:
		n.Rune = make([]rune, len(re.Rune))
		for i, r := range re.Rune {
			n.Rune[len(re.Rune)-1-i] = r
		}

	case syntax.OpAlternate,
		syntax.OpCapture,
		syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		n.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			n.Sub[i] = reverseRegexp(sub)
		}

	case syntax.OpBeginText:
		n.Op = syntax.OpEndText
	case syntax.OpEndText:
		n.Op = syntax.OpBeginText
	case syntax.OpBeginLine:
		n.Op = syntax.OpEndLine
	case syntax.OpEndLine:
		n.Op = syntax.OpBeginLine

	default:
		// OpCharClass, OpAnyChar, OpAnyCharNotNL, OpWordBoundary,
		// OpNoWordBoundary, OpEmptyMatch, etc. — copy Rune slice unchanged.
		if len(re.Rune) > 0 {
			n.Rune = make([]rune, len(re.Rune))
			copy(n.Rune, re.Rune)
		}
	}
	return n
}

// oneByte reports whether lap anchors on a single one-byte literal.
func (lap *litAnchorPoint) oneByte() bool {
	return len(lap.litSet) == 1 && len(lap.litSet[0]) == 1
}

// findLitAnchorPoint parses pattern and returns the first litAnchorPoint where
// the top-level concat contains a qualifying literal set. Returns nil when no
// qualifying child is found. Failing a literal of two bytes or more, a pattern
// that begins with a wide repeat (wideLeadingRepeat) takes a ONE-byte literal
// at an inner position (oneByteLiteral): `@` in `[\w.]+@[\w.]+`, which no
// other route scans for. Such a find always carries the start-anywhere switch's
// counter, charging every failed candidate (litAnchorOneByte).
func findLitAnchorPoint(pattern string, unicode bool) *litAnchorPoint {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	// Strip outer OpCapture / flags-group wrappers.
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	return findLitAnchorPointInRegexp(re, unicode, oneByteInnerLiteral(pattern, unicode))
}

// wideLeadingRepeat reports whether pattern begins with an unbounded repeat of
// a class common in text that does not contain the space byte
// (leadingRepeatBytes judged by commonInText) — exactly the patterns
// classifyFind otherwise sends to the start-anywhere find for want of a literal
// to scan for, at ~29 fuel/byte. Only those take a one-byte inner literal.
// Where a pattern's first bytes are selective, scanning for them beats stopping
// at every occurrence of a common byte — `(\d+)-(\d+)…` over
// "not-a-log-line"×20 cost 777 fuel scanning for a digit and 5,282 stopping at
// each `-` (perftest log-fields-10g). A class with the space byte keeps today's
// find, whose SIMD run skip crosses a long field: `[^,]+,` over 500-byte fields
// cost 2.1 fuel/byte there and 36.4 with every `,` walked back over its field.
func wideLeadingRepeat(pattern string, unicode bool) bool {
	return oneByteInnerLiteral(pattern, unicode) != nil
}

// oneByteInnerLiteral returns which one-byte inner literals pattern may anchor
// on, or nil for none: any, behind a wide leading repeat (wideLeadingRepeat)
// whose ASCII bytes make it common in text; and behind one that is common only
// for its characters above 0x7F (Unicode mode, commonInText), only a byte not
// common in text itself (byteRarity below 3). Such a class is dense in its
// own script's text and rare in any other, and there a common literal is the
// worse stop: `\p{Han}+x` over English text cost 4.06 fuel per byte anchored on
// `x` against 2.13 without, while `@`, `=`, `-` and `;` win in every script.
func oneByteInnerLiteral(pattern string, unicode bool) func(byte) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	stripCaptures(re)
	set, ok := leadingRepeatBytes(re, unicode)
	if !ok || set[' '] || !commonInText(set, unicode) {
		return nil
	}
	if setRaritySum(set) >= wideClassThreshold {
		return func(byte) bool { return true }
	}
	return func(b byte) bool { return byteRarity[b] < 3 }
}

// findLitAnchorPointInRegexp is findLitAnchorPoint's body, operating on an
// already-parsed, already-capture-stripped node. Split out so the
// alternation-of-branches detector (findAltLitAnchorPoints) can apply the
// same single-branch qualification logic to each branch of an OpAlternate
// without re-parsing or re-stripping captures per branch. oneByteInner, when
// non-nil, admits the one-byte fallback for the bytes it accepts
// (oneByteInnerLiteral); the alternation form passes nil.
//
// The one-byte literal is taken only when no child carries a longer literal,
// so every pattern with one keeps the literal it had.
func findLitAnchorPointInRegexp(re *syntax.Regexp, unicode bool, oneByteInner func(byte) bool) *litAnchorPoint {
	if re.Op != syntax.OpConcat {
		return nil
	}
	children := re.Sub
	at := func(i int, lits [][]byte) *litAnchorPoint {
		lap := &litAnchorPoint{litSet: lits}

		// prefixRe: children [0, i)
		switch i {
		case 0:
			lap.prefixRe = &syntax.Regexp{Op: syntax.OpEmptyMatch}
		case 1:
			lap.prefixRe = children[0]
		default:
			lap.prefixRe = &syntax.Regexp{
				Op:    syntax.OpConcat,
				Sub:   children[:i],
				Flags: re.Flags,
			}
		}

		// suffixRe: children [i, N) — includes the literal itself so the
		// forward DFA can be started at the match start and run forward.
		remaining := children[i:]
		if len(remaining) == 1 {
			lap.suffixRe = remaining[0]
		} else {
			lap.suffixRe = &syntax.Regexp{
				Op:    syntax.OpConcat,
				Sub:   remaining,
				Flags: re.Flags,
			}
		}

		lap.anchored = prefixStartsWithLineAnchor(lap.prefixRe)
		return lap
	}
	for i, child := range children {
		lits := extractLitSet(child, unicode)
		if lits == nil || len(lits) > 8 {
			continue
		}
		return at(i, lits)
	}
	if oneByteInner != nil {
		for i := 1; i < len(children); i++ {
			if lit := oneByteLiteral(children[i], unicode); lit != nil && oneByteInner(lit[0]) {
				return at(i, [][]byte{lit})
			}
		}
	}
	return nil
}

// oneByteLiteral returns re's literal when it is exactly one byte — one
// unfolded rune the mode takes as a byte (literalBytes) — or nil.
func oneByteLiteral(re *syntax.Regexp, unicode bool) []byte {
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpLiteral || re.Flags&syntax.FoldCase != 0 || len(re.Rune) != 1 {
		return nil
	}
	if bs, ok := literalBytes(re.Rune, unicode); ok && len(bs) == 1 {
		return bs
	}
	return nil
}

// prefixContainsWordBoundary reports whether re (or any subtree) contains an
// OpWordBoundary (`\b`) or OpNoWordBoundary (`\B`) node. Used to gate the
// lit-anchor optimisation: the reversed-prefix DFA construction does not
// evaluate word boundaries in the backward direction and the backward-scan
// body does not verify them at candidate positions, so lit-anchor is unsafe
// for any prefix that mentions `\b`/`\B`. Added 2026-06-30 — makes the
// gate at compile.go's lit-anchor activation explicit; previously the
// rejection relied on the incidental behaviour that a reversed-`\b`-only DFA
// happens to have an accepting start state, which was fragile against future
// DFA-construction changes.
func prefixContainsWordBoundary(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	for _, sub := range re.Sub {
		if prefixContainsWordBoundary(sub) {
			return true
		}
	}
	return false
}

// prefixContainsLineAnchor reports whether re (or any subtree) contains an
// OpBeginLine (`(?m:^)`) or OpEndLine (`(?m:$)`) node.
//
// Gates the lit-anchor optimisation, roughly the way
// prefixContainsWordBoundary gates `\b`/`\B`, but for a different
// underlying reason: what a line anchor in the prefix endangers is the
// BACKWARD scan, not the forward continuation.
// buildLitAnchorBackScanBody's `revTable.hasNewlineBoundary` branch
// (engine_dfa.go) stops the reverse walk **unconditionally** at the first
// '\n' it reads. When the prefix can itself consume a '\n' that stop is
// premature and the real match start is never reached — a past defect’s
// repro `\D(?m:^)ab` on "\nab", where `\D` legitimately matches the very '\n'
// the scan halts at.
//
// NOT a forward-continuation problem, contrary to what this comment claimed
// before an earlier task (2026-08-17). The forward scan runs the WHOLE
// pattern's DFA, not a freshly-compiled `suffixRe` DFA
// (`p.litAnchorFindTable`/`p.litAnchorFindLayout` are the whole-pattern
// table/layout), and it does establish the preceding byte's newline context:
// buildLitAnchorFindBody's third step loads `ptr[rev_result-1]` and picks
// wasmStart / wasmMidStartNewline / wasmMidStart accordingly, and its forward
// loop calls emitNLPreAcceptCheck for a trailing `(?m:$)`. That has been true
// since lit-anchor's original landing.
//
// Consequently this predicate is NOT the whole gate: a true answer only
// forces a fallback when lineAnchoredPrefixSafe also says no. That helper
// admits the one shape the back-scan defect cannot touch — a prefix led by
// `^`/`(?m:^)` with nothing after the anchor able to consume a '\n', which
// makes the stop-at-'\n' exact rather than premature. This function is also
// reused inside lineAnchoredPrefixSafe to reject any FURTHER line anchor in
// the remainder past that leading one.
func prefixContainsLineAnchor(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpEndLine:
		return true
	}
	for _, sub := range re.Sub {
		if prefixContainsLineAnchor(sub) {
			return true
		}
	}
	return false
}

// stripLeadingLineAnchor returns the portion of re that follows a leading
// `^`/`\A`/`(?m:^)` anchor, together with whether re starts with one at all.
// The returned node is for analysis only (canConsumeNewline /
// prefixContainsLineAnchor) — the reverse-prefix DFA is still built from the
// original, unstripped prefixRe.
func stripLeadingLineAnchor(re *syntax.Regexp) (*syntax.Regexp, bool) {
	if re == nil {
		return nil, false
	}
	switch re.Op {
	case syntax.OpBeginLine, syntax.OpBeginText:
		return &syntax.Regexp{Op: syntax.OpEmptyMatch}, true

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return stripLeadingLineAnchor(re.Sub[0])
		}

	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			return nil, false
		}
		rest, ok := stripLeadingLineAnchor(re.Sub[0])
		if !ok {
			return nil, false
		}
		sub := make([]*syntax.Regexp, 0, len(re.Sub))
		sub = append(sub, rest)
		sub = append(sub, re.Sub[1:]...)
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: sub, Flags: re.Flags}, true
	}
	return nil, false
}

// canConsumeNewline reports whether re can consume a '\n' input byte.
// Unknown ops answer true (conservative): callers use this to prove that a
// stretch of pattern can NEVER cross a line boundary.
func canConsumeNewline(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return false

	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r == '\n' {
				return true
			}
		}
		return false

	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				return true
			}
		}
		return false

	case syntax.OpAnyCharNotNL:
		return false

	case syntax.OpAnyChar:
		return true

	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest,
		syntax.OpRepeat, syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range re.Sub {
			if canConsumeNewline(sub) {
				return true
			}
		}
		return false
	}
	return true
}

// lineAnchoredPrefixSafe reports whether a lit-anchor prefix that DOES contain
// a line anchor is nevertheless safe for the backward scan, so it need not be
// rejected outright by a past defect’s gate.
//
// The defect is in buildLitAnchorBackScanBody's `revTable.hasNewlineBoundary`
// branch, which stops the backward scan unconditionally at the first '\n' it
// meets. That is only sound when no match's prefix portion can contain a '\n'
// — otherwise the scan halts before reaching the real match start (the repro
// `\D(?m:^)ab` on "\nab": `\D` legitimately consumes the '\n' the scan stops
// at). It is exactly sound when:
//
//   - the prefix starts with `^`/`\A`/`(?m:^)`, so the match start is either
//     position 0 or the byte after a '\n' — the two positions the backward scan
//     terminates at and checks (accept[state] at pos<0, midAcceptNL[state] at
//     the '\n'), and
//   - nothing after that leading anchor can consume a '\n', so the '\n' the
//     scan stops at is provably the one the leading anchor refers to, and no
//     earlier (more leftmost) match start exists past it, and
//   - no further line anchor appears in the prefix, whose backward evaluation
//     would then depend on context the scan does not track.
//
// The forward continuation is already newline-aware independently of this:
// buildLitAnchorFindBody's third step selects wasmMidStartNewline from the byte
// preceding the recovered match start, and its forward loop calls
// emitNLPreAcceptCheck for any trailing `(?m:$)`.
func lineAnchoredPrefixSafe(re *syntax.Regexp) bool {
	rest, ok := stripLeadingLineAnchor(re)
	if !ok {
		return false
	}
	return !prefixContainsLineAnchor(rest) && !canConsumeNewline(rest)
}

// altLitAnchorBranch pairs one alternation branch's litAnchorPoint with the
// branch's own (capture-stripped) regexp node. compile.go uses branchRe to
// re-enter the standard compile() pipeline and build the branch's own
// forward LF DFA, independent of the whole alternation's combined DFA.
type altLitAnchorBranch struct {
	lap      *litAnchorPoint
	branchRe *syntax.Regexp
}

// maxAltLitAnchorBranches bounds the branch count to the same 8-alternative
// cap extractLitSet already applies to literal-alternation anchor points and
// the mixed-prefix layout planner applies to its own branch count — keeps 2-byte
// Teddy available for the common case and bounds compile-time work.
const maxAltLitAnchorBranches = 8

// findAltLitAnchorPoints parses pattern as a top-level OpAlternate (after
// stripping outer OpCapture) where EVERY branch independently qualifies for
// findLitAnchorPointInRegexp AND every branch's prefixRe has the SAME exact,
// finite length.
//
// The equal-fixed-prefix-length requirement is a v1 restriction, not a
// fundamental one (see the general
// bounded-lookahead version that lifts it). With every branch's prefix at
// the same fixed length P, match_start = literal_pos - P for every branch,
// so scan order (the order the shared Teddy frontend discovers branch
// literals in) and match-start order coincide — this is what makes it safe
// for the caller's dispatcher to return on the FIRST branch that verifies
// successfully. Without this restriction that isn't true in general: Go
// stdlib's `LITA|.{10}LITB` on "01234LITA0LITB" returns [0,14] (the
// `.{10}LITB` branch, matching from position 0), not [5,9] (the `LITA`
// branch, whose literal is discovered earlier in a left-to-right scan) —
// leftmost-first semantics are decided by match START position, not by
// which branch's anchor literal is found first while scanning.
//
// Returns (nil, false) on ANY rejection — callers must fall through cleanly
// to the standard combined-DFA find path, exactly as they already do when
// findLitAnchorPoint returns nil for the single-pattern case.
func findAltLitAnchorPoints(pattern resolvedPattern) ([]altLitAnchorBranch, bool) {
	t, err := pattern.parse()
	if err != nil {
		return nil, false
	}
	re := t.re
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 || len(re.Sub) > maxAltLitAnchorBranches {
		return nil, false
	}

	branches := make([]altLitAnchorBranch, 0, len(re.Sub))
	fixedPrefixLen := -1
	for _, sub := range re.Sub {
		branchRe := sub
		for branchRe.Op == syntax.OpCapture && len(branchRe.Sub) == 1 {
			branchRe = branchRe.Sub[0]
		}
		lap := findLitAnchorPointInRegexp(branchRe, t.unicode(), nil)
		if lap == nil {
			return nil, false
		}
		minLen, maxLen := t.tree(lap.prefixRe).minMaxLen()
		if minLen != maxLen || maxLen < 0 {
			return nil, false // not a fixed-length prefix
		}
		if fixedPrefixLen < 0 {
			fixedPrefixLen = minLen
		} else if minLen != fixedPrefixLen {
			return nil, false // prefix length differs from an earlier branch
		}
		branches = append(branches, altLitAnchorBranch{lap: lap, branchRe: branchRe})
	}
	return branches, true
}
