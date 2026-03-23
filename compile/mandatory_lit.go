package compile

import "regexp/syntax"

// MandatoryLit describes a fixed byte sequence that must appear in every match,
// along with its offset range from the start of the match.
type MandatoryLit struct {
	Bytes  []byte
	MinOff int32 // minimum offset of the literal start from match start
	MaxOff int32 // maximum offset of the literal start from match start
}

// FindMandatoryLit analyzes the regex pattern and returns the first mandatory
// literal found (with its min/max offset from match start). Returns nil if no
// mandatory literal is found or if MaxOff > 256.
// Does NOT call Simplify() so that OpPlus/OpRepeat are preserved.
func FindMandatoryLit(pattern string) *MandatoryLit {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return findMandatoryLitRec(re, 0, 0)
}

// findMandatoryLitRec recursively searches for a mandatory literal in re,
// given that the match position is within [minOff, maxOff] bytes from the
// literal's potential start.
func findMandatoryLitRec(re *syntax.Regexp, minOff, maxOff int32) *MandatoryLit {
	if maxOff < 0 || maxOff > 256 {
		return nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		// Only handle ASCII literals without FoldCase flag.
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
		if len(bs) == 0 {
			return nil
		}
		return &MandatoryLit{Bytes: bs, MinOff: minOff, MaxOff: maxOff}

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return findMandatoryLitRec(re.Sub[0], minOff, maxOff)
		}
		return nil

	case syntax.OpPlus:
		// re+ executes body at least once, so we can recurse into body.
		if len(re.Sub) == 1 {
			return findMandatoryLitRec(re.Sub[0], minOff, maxOff)
		}
		return nil

	case syntax.OpRepeat:
		// re{min,max} with min >= 1: body executes at least once.
		if re.Min >= 1 && len(re.Sub) == 1 {
			return findMandatoryLitRec(re.Sub[0], minOff, maxOff)
		}
		return nil

	case syntax.OpConcat:
		// Walk children left to right. For each child, first try to find a lit.
		// If not found, accumulate the child's min/max length into the offset.
		curMin := minOff
		curMax := maxOff
		for _, sub := range re.Sub {
			if ml := findMandatoryLitRec(sub, curMin, curMax); ml != nil {
				return ml
			}
			childMin, childMax := regexpMinMaxLen(sub)
			curMin += int32(childMin)
			if childMax < 0 || curMax < 0 {
				curMax = -1
			} else {
				curMax += int32(childMax)
			}
			if curMax > 256 {
				return nil
			}
		}
		return nil

	default:
		// OpAlternate, OpStar, OpQuest, OpRepeat with Min=0, etc.
		return nil
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
