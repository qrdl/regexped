package compile

import "regexp/syntax"

// LitAnchorPoint describes a three-way literal-anchored split of a regex pattern:
//
//	PREFIX · LitSet · SUFFIX
//
// Every valid match must contain one of the literals in LitSet, preceded by a
// match of PrefixRe and followed by a match of SuffixRe (which includes the
// literal itself so the forward DFA can be started at the match start and run
// to completion).
//
// Anchored is true when PrefixRe begins with ^ or (?m:^), which means the
// backward scan can stop at '\n' or pos 0 rather than running to a dead state.
type LitAnchorPoint struct {
	PrefixRe *syntax.Regexp
	LitSet   [][]byte       // 1..8 ASCII literals, each len >= 2
	SuffixRe *syntax.Regexp // includes the literal itself
	Anchored bool
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

// FindLitAnchorPoint parses pattern and returns the first LitAnchorPoint where
// the top-level concat contains a qualifying literal set.  Returns nil when no
// qualifying child is found.
func FindLitAnchorPoint(pattern string) *LitAnchorPoint {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	// Strip outer OpCapture / flags-group wrappers.
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat {
		return nil
	}
	children := re.Sub
	for i, child := range children {
		lits := extractLitSet(child)
		if lits == nil || len(lits) > 8 {
			continue
		}
		lap := &LitAnchorPoint{LitSet: lits}

		// PrefixRe: children [0, i)
		switch i {
		case 0:
			lap.PrefixRe = &syntax.Regexp{Op: syntax.OpEmptyMatch}
		case 1:
			lap.PrefixRe = children[0]
		default:
			lap.PrefixRe = &syntax.Regexp{
				Op:    syntax.OpConcat,
				Sub:   children[:i],
				Flags: re.Flags,
			}
		}

		// SuffixRe: children [i, N) — includes the literal itself so the
		// forward DFA can be started at the match start and run forward.
		remaining := children[i:]
		if len(remaining) == 1 {
			lap.SuffixRe = remaining[0]
		} else {
			lap.SuffixRe = &syntax.Regexp{
				Op:    syntax.OpConcat,
				Sub:   remaining,
				Flags: re.Flags,
			}
		}

		lap.Anchored = prefixStartsWithLineAnchor(lap.PrefixRe)
		return lap
	}
	return nil
}
