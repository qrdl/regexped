package compile

import (
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// WASM binary encoding helpers

func appendSection(out []byte, id byte, content []byte) []byte {
	out = append(out, id)
	out = utils.AppendULEB128(out, uint32(len(content)))
	return append(out, content...)
}

func appendDataSegment(out []byte, offset int32, data []byte) []byte {
	out = append(out, 0x00) // memory index 0
	out = append(out, 0x41) // i32.const
	out = utils.AppendSLEB128(out, offset)
	out = append(out, 0x0B) // end
	out = utils.AppendULEB128(out, uint32(len(data)))
	return append(out, data...)
}

func appendString(out []byte, s string) []byte {
	out = utils.AppendULEB128(out, uint32(len(s)))
	return append(out, s...)
}
