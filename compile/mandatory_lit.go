package compile

import (
	"regexp/syntax"
)

// splitFrame records one step of the AST path from the root to the mandatory
// literal found by findMandatoryLitRec. splitAtPath consumes the path to
// reconstruct the prefix and suffix sub-trees.
type splitFrame struct {
	op    syntax.Op // OpConcat, OpCapture, OpPlus, or OpRepeat
	index int       // for OpConcat: child index where the literal was found
}

// mandatoryLit describes a fixed byte sequence that must appear in every match,
// along with its offset range from the start of the match.
//
// Usage in find mode:
//   - The SIMD scan starts at input position minOff (not 0), because no match
//     can have the literal starting before minOff bytes into the match.
//     This safely skips the first minOff bytes of the input.
//   - When the literal is found at position litPos, the DFA is run from
//     max(0, litPos-maxOff) to determine the actual match start.
//     A match starting at position 0 is found correctly as long as the literal
//     appears at litPos >= minOff (which is guaranteed by the pattern structure).
type mandatoryLit struct {
	bytes  []byte
	minOff int32 // minimum byte distance from match start to literal start
	maxOff int32 // maximum byte distance from match start to literal start
}

// HasMandatoryLit reports whether pattern has a non-empty mandatory literal
// that can anchor it in set composition. Patterns without one go to the
// fallback bucket which is currently not scanned by emitSetMatchFnFinal.
func HasMandatoryLit(pattern string) bool {
	return findMandatoryLit(pattern) != nil
}

// HasTrivialPrefix reports whether the prefix before the mandatory literal is
// trivially empty (nil). Patterns with non-trivial prefixes (e.g. "(a|b)a$")
// require a backward prefix DFA check that the set scan does not yet perform.
func HasTrivialPrefix(pattern string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	lit, path := findMandatoryLitRec(re, 0, 0)
	if lit == nil {
		return false
	}
	prefixAST, _, ok := splitAtPath(re, path)
	if !ok {
		return false
	}
	return prefixAST == nil
}

// mandatory literal is found or if MaxOff > 256.
// Does NOT call Simplify() so that OpPlus/OpRepeat are preserved.
func findMandatoryLit(pattern string) *mandatoryLit {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	lit, _ := findMandatoryLitRec(re, 0, 0)
	return lit
}

// findMandatoryLitRec recursively searches for a mandatory literal in re,
// given that the match position is within [minOff, maxOff] bytes from the
// literal's potential start. Returns the literal and the AST path from re to
// the literal node (path[0] is the frame at re's level). Returns (nil, nil)
// when no mandatory literal is found.
func findMandatoryLitRec(re *syntax.Regexp, minOff, maxOff int32) (*mandatoryLit, []splitFrame) {
	if maxOff < 0 || maxOff > 256 {
		return nil, nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		// Only handle ASCII literals without FoldCase flag.
		if re.Flags&syntax.FoldCase != 0 {
			return nil, nil
		}
		var bs []byte
		for _, r := range re.Rune {
			if r > 127 {
				return nil, nil
			}
			bs = append(bs, byte(r))
		}
		if len(bs) == 0 {
			return nil, nil
		}
		return &mandatoryLit{bytes: bs, minOff: minOff, maxOff: maxOff}, nil

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(re.Sub[0], minOff, maxOff)
			if lit == nil {
				return nil, nil
			}
			return lit, append([]splitFrame{{op: syntax.OpCapture}}, path...)
		}
		return nil, nil

	case syntax.OpPlus:
		// re+ executes body at least once, so we can recurse into body.
		if len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(re.Sub[0], minOff, maxOff)
			if lit == nil {
				return nil, nil
			}
			return lit, append([]splitFrame{{op: syntax.OpPlus}}, path...)
		}
		return nil, nil

	case syntax.OpRepeat:
		// re{min,max} with min >= 1: body executes at least once.
		if re.Min >= 1 && len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(re.Sub[0], minOff, maxOff)
			if lit == nil {
				return nil, nil
			}
			return lit, append([]splitFrame{{op: syntax.OpRepeat}}, path...)
		}
		return nil, nil

	case syntax.OpConcat:
		// Walk children left to right. For each child, first try to find a lit.
		// If not found, accumulate the child's min/max length into the offset.
		curMin := minOff
		curMax := maxOff
		for i, sub := range re.Sub {
			if lit, path := findMandatoryLitRec(sub, curMin, curMax); lit != nil {
				return lit, append([]splitFrame{{op: syntax.OpConcat, index: i}}, path...)
			}
			childMin, childMax := regexpMinMaxLen(sub)
			curMin += int32(childMin)
			if childMax < 0 || curMax < 0 {
				curMax = -1
			} else {
				curMax += int32(childMax)
			}
			if curMax > 256 {
				return nil, nil
			}
		}
		return nil, nil

	default:
		// OpAlternate, OpStar, OpQuest, OpRepeat with Min=0, etc.
		return nil, nil
	}
}

// splitAtPath splits root around the mandatory literal recorded in path.
// path is produced by findMandatoryLitRec. Returns (prefixAST, suffixAST, true)
// where prefixAST is the sub-tree before the literal and suffixAST is the
// sub-tree after. Either may be nil when the literal is at the start/end.
// Returns (nil, nil, false) when the path passes through a quantifier or
// alternate that makes a clean split impossible.
func splitAtPath(root *syntax.Regexp, path []splitFrame) (prefixAST, suffixAST *syntax.Regexp, ok bool) {
	return splitAtPathRec(root, path)
}

func splitAtPathRec(re *syntax.Regexp, path []splitFrame) (*syntax.Regexp, *syntax.Regexp, bool) {
	if len(path) == 0 {
		// At the literal leaf: nothing on either side at this level.
		return nil, nil, true
	}
	frame := path[0]
	rest := path[1:]
	switch frame.op {
	case syntax.OpPlus, syntax.OpRepeat, syntax.OpAlternate:
		return nil, nil, false
	case syntax.OpCapture:
		if re.Op != syntax.OpCapture || len(re.Sub) != 1 {
			return nil, nil, false
		}
		return splitAtPathRec(re.Sub[0], rest)
	case syntax.OpConcat:
		if re.Op != syntax.OpConcat {
			return nil, nil, false
		}
		i := frame.index
		if i < 0 || i >= len(re.Sub) {
			return nil, nil, false
		}
		innerPre, innerSuf, ok := splitAtPathRec(re.Sub[i], rest)
		if !ok {
			return nil, nil, false
		}
		var preParts []*syntax.Regexp
		for j := 0; j < i; j++ {
			preParts = append(preParts, deepCopyRegexp(re.Sub[j]))
		}
		if innerPre != nil {
			preParts = append(preParts, innerPre)
		}
		var sufParts []*syntax.Regexp
		if innerSuf != nil {
			sufParts = append(sufParts, innerSuf)
		}
		for j := i + 1; j < len(re.Sub); j++ {
			sufParts = append(sufParts, deepCopyRegexp(re.Sub[j]))
		}
		return concatRegexp(preParts), concatRegexp(sufParts), true
	default:
		return nil, nil, false
	}
}

func deepCopyRegexp(re *syntax.Regexp) *syntax.Regexp {
	if re == nil {
		return nil
	}
	n := &syntax.Regexp{
		Op:    re.Op,
		Flags: re.Flags,
		Min:   re.Min,
		Max:   re.Max,
		Cap:   re.Cap,
		Name:  re.Name,
	}
	if len(re.Rune) > 0 {
		n.Rune = make([]rune, len(re.Rune))
		copy(n.Rune, re.Rune)
	}
	if len(re.Sub) > 0 {
		n.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			n.Sub[i] = deepCopyRegexp(sub)
		}
	}
	return n
}

func concatRegexp(parts []*syntax.Regexp) *syntax.Regexp {
	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	default:
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: parts}
	}
}

// regexpMinMaxLen returns the minimum and maximum byte lengths of strings
// matched by re. maxLen == -1 means unbounded.
func regexpMinMaxLen(re *syntax.Regexp) (minLen, maxLen int) {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			switch {
			case r <= 0x7F:
				n += 1
			case r <= 0x7FF:
				n += 2
			case r <= 0xFFFF:
				n += 3
			default:
				n += 4
			}
		}
		return n, n

	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 1, 1

	case syntax.OpCharClass:
		return 1, 1

	case syntax.OpRepeat:
		if len(re.Sub) == 0 {
			return 0, 0
		}
		childMin, childMax := regexpMinMaxLen(re.Sub[0])
		lo := re.Min * childMin
		if re.Max < 0 {
			return lo, -1
		}
		hi := re.Max * childMax
		if childMax < 0 {
			hi = -1
		}
		return lo, hi

	case syntax.OpStar:
		return 0, -1

	case syntax.OpPlus:
		if len(re.Sub) == 0 {
			return 0, -1
		}
		childMin, _ := regexpMinMaxLen(re.Sub[0])
		return childMin, -1

	case syntax.OpQuest:
		if len(re.Sub) == 0 {
			return 0, 0
		}
		_, childMax := regexpMinMaxLen(re.Sub[0])
		return 0, childMax

	case syntax.OpConcat:
		totMin := 0
		totMax := 0
		for _, sub := range re.Sub {
			sMin, sMax := regexpMinMaxLen(sub)
			totMin += sMin
			if totMax < 0 || sMax < 0 {
				totMax = -1
			} else {
				totMax += sMax
			}
		}
		return totMin, totMax

	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return 0, 0
		}
		totMin := -1
		totMax := 0
		for _, sub := range re.Sub {
			sMin, sMax := regexpMinMaxLen(sub)
			if totMin < 0 || sMin < totMin {
				totMin = sMin
			}
			if totMax < 0 || sMax < 0 {
				totMax = -1
			} else if sMax > totMax {
				totMax = sMax
			}
		}
		if totMin < 0 {
			totMin = 0
		}
		return totMin, totMax

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return regexpMinMaxLen(re.Sub[0])
		}
		return 0, 0

	case syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, 0

	case syntax.OpNoMatch, syntax.OpEmptyMatch:
		return 0, 0

	default:
		return 0, -1
	}
}
