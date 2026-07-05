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
	litSet   [][]byte       // 1..8 ASCII literals, each len >= 2
	suffixRe *syntax.Regexp // includes the literal itself
	anchored bool
}

// extractLitSet returns the literal set encoded by re, or nil when re is not
// a qualifying literal or alternation of literals.
//
// Qualifying: ASCII only, no FoldCase, length >= 2, at most 8 alternatives.
func extractLitSet(re *syntax.Regexp) [][]byte {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		var bs []byte
		for _, r := range re.Rune {
			if r > 127 {
				return nil
			}
			bs = append(bs, byte(r))
		}
		if len(bs) < 2 {
			return nil
		}
		return [][]byte{bs}

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return extractLitSet(re.Sub[0])
		}
		return nil

	case syntax.OpAlternate:
		var result [][]byte
		for _, sub := range re.Sub {
			lits := extractLitSet(sub)
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

// findLitAnchorPoint parses pattern and returns the first litAnchorPoint where
// the top-level concat contains a qualifying literal set.  Returns nil when no
// qualifying child is found.
func findLitAnchorPoint(pattern string) *litAnchorPoint {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	// Strip outer OpCapture / flags-group wrappers.
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	return findLitAnchorPointInRegexp(re)
}

// findLitAnchorPointInRegexp is findLitAnchorPoint's body, operating on an
// already-parsed, already-capture-stripped node. Split out so the
// alternation-of-branches detector (findAltLitAnchorPoints) can apply the
// same single-branch qualification logic to each branch of an OpAlternate
// without re-parsing or re-stripping captures per branch.
func findLitAnchorPointInRegexp(re *syntax.Regexp) *litAnchorPoint {
	if re.Op != syntax.OpConcat {
		return nil
	}
	children := re.Sub
	for i, child := range children {
		lits := extractLitSet(child)
		if lits == nil || len(lits) > 8 {
			continue
		}
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
	return nil
}

// prefixContainsWordBoundary reports whether re (or any subtree) contains an
// OpWordBoundary (`\b`) or OpNoWordBoundary (`\B`) node. Used to gate the
// lit-anchor optimisation: the reversed-prefix DFA construction does not
// evaluate word boundaries in the backward direction and the backward-scan
// body does not verify them at candidate positions, so lit-anchor is unsafe
// for any prefix that mentions `\b`/`\B`. Task 10 (2026-06-30) — makes the
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
// Gap E's layout planner applies to its own branch count — keeps 2-byte
// Teddy available for the common case and bounds compile-time work.
const maxAltLitAnchorBranches = 8

// findAltLitAnchorPoints parses pattern as a top-level OpAlternate (after
// stripping outer OpCapture) where EVERY branch independently qualifies for
// findLitAnchorPointInRegexp AND every branch's prefixRe has the SAME exact,
// finite length.
//
// The equal-fixed-prefix-length requirement is a v1 restriction, not a
// fundamental one (see plans/TODO.md task 6 for the general
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
func findAltLitAnchorPoints(pattern string) ([]altLitAnchorBranch, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
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
		lap := findLitAnchorPointInRegexp(branchRe)
		if lap == nil {
			return nil, false
		}
		minLen, maxLen := regexpMinMaxLen(lap.prefixRe)
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
