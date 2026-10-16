package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// isWholePatternSingleCapture reports whether re's only capture group spans
// the entire match — group 0 and group 1 are therefore always identical in
// wrapper context, so a TDFA/Backtracking capture-body re-walk of [start,end)
// is pure waste. Accepts a single OpCapture at
// top level, optionally inside an OpConcat alongside zero-width assertions
// (^, $, \b, \B). Anything else — nested captures, additional captures,
// non-zero-width siblings, or multiline anchors (OpBeginLine/OpEndLine, which
// only appear under (?m)) — is rejected, matching the conservatism of the
// other lit-chain analysers.
func isWholePatternSingleCapture(re *syntax.Regexp) bool {
	if re.MaxCap() != 1 {
		return false
	}
	if re.Op == syntax.OpCapture {
		return true
	}
	if re.Op != syntax.OpConcat {
		return false
	}
	sawCapture := false
	for _, sub := range re.Sub {
		switch sub.Op {
		case syntax.OpCapture:
			if sawCapture {
				return false
			}
			sawCapture = true
		case syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			// zero-width, doesn't affect the capture's span
		default:
			return false
		}
	}
	return sawCapture
}

// buildTrivialSingleCaptureBody emits the WASM body for the trivial
// captureBody used by the whole-pattern single-capture shortcut. Signature (type 2):
//
//	(ptr i32, len i32, out_ptr i32) → i32
//
// Only reachable through buildGroupsWrapperBody's composition, whose
// contract guarantees ptr/len already denote the matched substring
// [start,end) — so group 0 and the sole capture (group 1) are both (0,len)
// relative to ptr. Writes both slot pairs and returns len, exactly the
// shape a TDFA/Backtracking captureBody would produce for this pattern
// family, without re-walking the substring.
func buildTrivialSingleCaptureBody() []byte {
	var b []byte
	b = append(b, 0x00) // no locals
	storeAt := func(offset uint32, valueLocal byte) {
		b = append(b, 0x20, 0x02) // local.get out_ptr
		if valueLocal == 0xFF {
			b = append(b, 0x41, 0x00) // i32.const 0
		} else {
			b = append(b, 0x20, valueLocal) // local.get len
		}
		b = append(b, 0x36, 0x02) // i32.store align=2
		b = utils.AppendULEB128(b, offset)
	}
	storeAt(0, 0xFF)          // group 0 start = 0
	storeAt(4, 0x01)          // group 0 end = len
	storeAt(8, 0xFF)          // group 1 start = 0
	storeAt(12, 0x01)         // group 1 end = len
	b = append(b, 0x20, 0x01) // local.get len (left on stack as the return value)
	b = append(b, 0x0B)       // end
	return b
}

// appendTrivialSingleCaptureCodeEntry appends a size-prefixed trivial
// captureBody to cs.
func appendTrivialSingleCaptureCodeEntry(cs []byte) []byte {
	body := buildTrivialSingleCaptureBody()
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// affixSingleCapture reports whether re is ONE capture between fixed
// literals — `([^,]+),`, `<([^>]+)>`, `key=(\w+)` — and how many bytes those
// literals take before and after it. The span of such a group follows from
// the match alone: group 1 is [start + pre, end - suf], since a match is the
// prefix, the group's text and the suffix, in that order. So, like the
// whole-pattern shortcut above, it needs no capture body walking the match:
// that walk was most of a groups call — `([^,]+),` over a 487-byte field cost
// 75,452 fuel with it and 16,243 without (Unicode mode; byte mode 38,740 →
// 1,524). A literal must be unfolded, so its byte length is fixed: UTF-8
// bytes in Unicode mode, one byte per rune in byte mode. At least one side has
// a literal; with neither, isWholePatternSingleCapture applies.
func affixSingleCapture(re *syntax.Regexp, unicode bool) (pre, suf int, ok bool) {
	if re.MaxCap() != 1 || re.Op != syntax.OpConcat || len(re.Sub) < 2 || len(re.Sub) > 3 {
		return 0, 0, false
	}
	litLen := func(r *syntax.Regexp) (int, bool) {
		if r.Op != syntax.OpLiteral || r.Flags&syntax.FoldCase != 0 {
			return 0, false
		}
		if unicode {
			return len(string(r.Rune)), true
		}
		return len(r.Rune), true
	}
	i := 0
	if n, ok := litLen(re.Sub[0]); ok {
		pre, i = n, 1
	}
	if re.Sub[i].Op != syntax.OpCapture {
		return 0, 0, false
	}
	i++
	if i < len(re.Sub) {
		n, ok := litLen(re.Sub[i])
		if !ok {
			return 0, 0, false
		}
		suf, i = n, i+1
	}
	if i != len(re.Sub) || pre+suf == 0 {
		return 0, 0, false
	}
	return pre, suf, true
}

// appendAffixSingleCaptureCodeEntry appends the size-prefixed captureBody of
// the affix shortcut (affixSingleCapture): the trivial body's shape, with
// group 1 at (pre, len - suf) of the matched substring.
func appendAffixSingleCaptureCodeEntry(cs []byte, pre, suf int) []byte {
	var b []byte
	b = append(b, 0x00) // no locals
	store := func(offset byte, value func([]byte) []byte) {
		b = append(b, 0x20, 0x02) // local.get out_ptr
		b = value(b)
		b = append(b, 0x36, 0x02, offset) // i32.store align=2
	}
	// group 0 = (0, len)
	store(0, func(b []byte) []byte { return append(b, 0x41, 0x00) })
	store(4, func(b []byte) []byte { return append(b, 0x20, 0x01) })
	// group 1 = (pre, len - suf)
	store(8, func(b []byte) []byte { return utils.AppendSLEB128(append(b, 0x41), int32(pre)) })
	store(12, func(b []byte) []byte {
		b = append(b, 0x20, 0x01, 0x41)
		b = utils.AppendSLEB128(b, int32(suf))
		return append(b, 0x6B) // i32.sub
	})
	b = append(b, 0x20, 0x01) // local.get len (the return value)
	b = append(b, 0x0B)       // end
	cs = utils.AppendULEB128(cs, uint32(len(b)))
	return append(cs, b...)
}
