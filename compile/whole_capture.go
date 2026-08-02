package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// isWholePatternSingleCapture reports whether re's only capture group spans
// the entire match — group 0 and group 1 are therefore always identical in
// wrapper context, so a TDFA/Backtracking capture-body re-walk of [start,end)
// is pure waste (see plans/TODO.md task 41). Accepts a single OpCapture at
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
// captureBody used by the task 41 shortcut. Signature (type 2):
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
