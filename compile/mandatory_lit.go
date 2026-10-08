package compile

import (
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
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

// HasMandatoryLit reports whether pattern contains a non-empty mandatory
// literal that the analyser can locate. This is a necessary but NOT
// sufficient condition for using the pattern as an anchor in set
// composition: the AST path to the literal must also be splittable
// (see splitAtPath), which excludes literals reached only through OpPlus,
// OpRepeat, or OpAlternate. The set router applies that additional check
// itself; callers that need a yes/no answer on "is this pattern usable as
// a set anchor?" must do the same.
// byteMode is OPTIONAL and defaults to false, and the pattern is resolved as
// a compile resolves it: byte_mode false and the pattern's own text deciding
// the mode. It is variadic rather than a second required parameter so that
// adding it did not break existing callers of this exported function — the
// same shape Compile uses for its options, and for the same reason. Pass true
// only for a pattern compiled with `byte_mode: true`, where a literal rune
// 0x80..0xFF is one byte rather than the two its UTF-8 encoding would take;
// the offsets this analysis produces are wrong by one byte per such rune
// otherwise.
func HasMandatoryLit(pattern string, byteMode ...bool) bool {
	bm := false
	if len(byteMode) > 0 {
		bm = byteMode[0]
	}
	// Resolution fails only on a contradicting `unicode:` key, and there is
	// none here.
	rp, _ := resolvePattern(pattern, nil, &CompileOptions{ByteMode: bm})
	return findMandatoryLit(rp) != nil
}

// findMandatoryLit returns pattern's mandatory literal, or nil when no
// mandatory literal is found or if MaxOff > 256.
// Does NOT call Simplify() so that OpPlus/OpRepeat are preserved.
func findMandatoryLit(pattern resolvedPattern) *mandatoryLit {
	t, err := pattern.parse()
	if err != nil {
		return nil
	}
	lit, _ := findMandatoryLitRec(t, 0, 0)
	return lit
}

// literalBytes is the byte sequence a literal's runes stand for in a program
// of the given mode, and false when the mode cannot take them as bytes. ASCII
// in either mode. In Unicode mode a non-ASCII rune is its UTF-8 encoding — the
// bytes the lowered program consumes for it, beginning at a character's first
// byte, so an offset counted in them is a byte offset. A surrogate is refused:
// lowering cuts it out (it matches nothing), and its encoding would be
// U+FFFD's, which a literal scan would then find. Byte mode refuses every rune
// above 0x7F.
func literalBytes(rs []rune, unicode bool) ([]byte, bool) {
	bs := make([]byte, 0, len(rs))
	for _, r := range rs {
		switch {
		case r <= 0x7F:
			bs = append(bs, byte(r))
		case unicode && utf8.ValidRune(r):
			bs = utf8.AppendRune(bs, r)
		default:
			return nil, false
		}
	}
	return bs, true
}

// findMandatoryLitRec recursively searches for a mandatory literal in t.re,
// given that the match position is within [minOff, maxOff] bytes from the
// literal's potential start, measured in t's mode. Returns the literal and the
// AST path from t.re to the literal node (path[0] is the frame at t.re's
// level). Returns (nil, nil) when no mandatory literal is found.
func findMandatoryLitRec(t resolvedTree, minOff, maxOff int32) (*mandatoryLit, []splitFrame) {
	re := t.re
	if maxOff < 0 || maxOff > 256 {
		return nil, nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		// No FoldCase literal: its bytes are not one sequence.
		if re.Flags&syntax.FoldCase != 0 {
			return nil, nil
		}
		bs, ok := literalBytes(re.Rune, t.unicode())
		if !ok || len(bs) == 0 {
			return nil, nil
		}
		return &mandatoryLit{bytes: bs, minOff: minOff, maxOff: maxOff}, nil

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(t.tree(re.Sub[0]), minOff, maxOff)
			if lit == nil {
				return nil, nil
			}
			return lit, append([]splitFrame{{op: syntax.OpCapture}}, path...)
		}
		return nil, nil

	case syntax.OpPlus:
		// re+ executes body at least once, so we can recurse into body.
		if len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(t.tree(re.Sub[0]), minOff, maxOff)
			if lit == nil {
				return nil, nil
			}
			return lit, append([]splitFrame{{op: syntax.OpPlus}}, path...)
		}
		return nil, nil

	case syntax.OpRepeat:
		// re{min,max} with min >= 1: body executes at least once.
		if re.Min >= 1 && len(re.Sub) == 1 {
			lit, path := findMandatoryLitRec(t.tree(re.Sub[0]), minOff, maxOff)
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
			if lit, path := findMandatoryLitRec(t.tree(sub), curMin, curMax); lit != nil {
				return lit, append([]splitFrame{{op: syntax.OpConcat, index: i}}, path...)
			}
			childMin, childMax := t.tree(sub).minMaxLen()
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

// minMaxLen returns the minimum and maximum byte lengths of strings t.re
// matches, in t's mode. maxLen == -1 means unbounded.
//
// Every caller reads the result as a true bound, so an OVER-estimate of the
// minimum or an UNDER-estimate of the maximum is a wrong answer, not a missed
// optimisation:
//
//   - the exported find wrapper turns minLen into an early exit, so an
//     over-estimate REFUSES an input that matches — `\xe9ab` under byte_mode
//     answered -1 for the 3-byte input "\xe9ab" when a high rune weighed two;
//   - the mandatory-literal analyser accumulates it as the literal's offset
//     from the match start, and the lit-anchor emitters as a fixed prefix
//     length, both of which are then wrong by the error.
//
// In BYTE mode a rune is a byte: every literal rune, class and `.` is one
// byte. That covers `byte_mode: true`, where runes 0x80-0xFF mean those
// bytes, and needs no flag for it: a byte-mode pattern compiles only when its
// literal runes are ASCII or, under byte_mode, at most 0xFF — a `(?i)`
// literal included, since the parser keeps the smallest rune of its fold
// orbit, which for a rune up to 0xFF is up to 0xFF too.
//
// In a UNICODE mode a rune is its UTF-8 encoding: a literal rune weighs 1 to 4
// bytes, a `(?i)` literal rune anything from its fold orbit's narrowest to its
// widest (`(?i)k` 1..3, through U+212A KELVIN SIGN), a class the width of its
// lowest rune to that of its highest, and `.` 1..4 — an invalid byte matches
// nothing in Unicode mode, so `.` never consumes a single high byte.
func (t resolvedTree) minMaxLen() (minLen, maxLen int) {
	re := t.re
	utf8Mode := t.unicode()
	switch re.Op {
	case syntax.OpLiteral:
		lo, hi := 0, 0
		for _, r := range re.Rune {
			rlo, rhi := 1, 1
			if utf8Mode {
				rlo, rhi = literalRuneWidths(r, re.Flags&syntax.FoldCase != 0)
			}
			lo += rlo
			hi += rhi
		}
		return lo, hi

	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		if utf8Mode {
			return 1, utf8.UTFMax
		}
		return 1, 1

	case syntax.OpCharClass:
		if utf8Mode {
			return classWidths(re.Rune)
		}
		return 1, 1

	case syntax.OpRepeat:
		if len(re.Sub) == 0 {
			return 0, 0
		}
		childMin, childMax := t.tree(re.Sub[0]).minMaxLen()
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
		childMin, _ := t.tree(re.Sub[0]).minMaxLen()
		return childMin, -1

	case syntax.OpQuest:
		if len(re.Sub) == 0 {
			return 0, 0
		}
		_, childMax := t.tree(re.Sub[0]).minMaxLen()
		return 0, childMax

	case syntax.OpConcat:
		totMin := 0
		totMax := 0
		for _, sub := range re.Sub {
			sMin, sMax := t.tree(sub).minMaxLen()
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
			sMin, sMax := t.tree(sub).minMaxLen()
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
			return t.tree(re.Sub[0]).minMaxLen()
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

// utf8Width is the length of r's UTF-8 encoding, by value alone: a surrogate
// counts 3 like its neighbours, which only matters for a class made of
// nothing else, and classWidths skips those.
func utf8Width(r rune) int {
	switch {
	case r < 0x80:
		return 1
	case r < 0x800:
		return 2
	case r < 0x10000:
		return 3
	}
	return 4
}

// literalRuneWidths is the narrowest and widest UTF-8 encoding a literal rune
// matches in Unicode mode: its own, or with fold the narrowest and widest of
// its simple fold orbit — the orbit Go's matcher and the lowering both use.
func literalRuneWidths(r rune, fold bool) (lo, hi int) {
	lo, hi = utf8Width(r), utf8Width(r)
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			lo, hi = min(lo, utf8Width(f)), max(hi, utf8Width(f))
		}
	}
	return lo, hi
}

// classWidths is the narrowest and widest UTF-8 encoding a class's runes have
// in Unicode mode. The ranges are sorted, and the width only grows with the
// rune, so the first range's low end and the last range's high end decide —
// after dropping ranges made only of surrogates, which no input encodes and
// the lowering cuts out. A class with nothing left matches nothing, and is
// measured like syntax.OpNoMatch.
func classWidths(ranges []rune) (lo, hi int) {
	var kept []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i] >= 0xD800 && ranges[i+1] <= 0xDFFF {
			continue
		}
		kept = append(kept, ranges[i], ranges[i+1])
	}
	if len(kept) == 0 {
		return 0, 0
	}
	return utf8Width(kept[0]), utf8Width(kept[len(kept)-1])
}
