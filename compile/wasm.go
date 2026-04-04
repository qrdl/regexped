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

// appendDataSegment appends an active data segment (type 0, memory 0) to out.
// Used in standalone mode where the module owns its memory.
func appendDataSegment(out []byte, offset int32, data []byte) []byte {
	out = append(out, 0x00) // memory index 0
	out = append(out, 0x41) // i32.const
	out = utils.AppendSLEB128(out, offset)
	out = append(out, 0x0B) // end
	out = utils.AppendULEB128(out, uint32(len(data)))
	return append(out, data...)
}

// appendPassiveDataSegment appends a passive data segment (type 1) to out.
// Passive segments are not automatically initialized; the module's start
// function copies them into place using memory.init after growing memory.
func appendPassiveDataSegment(out []byte, data []byte) []byte {
	out = append(out, 0x01) // passive
	out = utils.AppendULEB128(out, uint32(len(data)))
	return append(out, data...)
}

// dataSegment holds one data segment's target address and raw bytes.
// Used when building the non-standalone init function (passive segments).
type dataSegment struct {
	offset int32
	data   []byte
}

// parseDataSegments extracts all type-0 (active, memory-0) data segments
// from a concatenation of segments encoded by appendDataSegment.
func parseDataSegments(rawData []byte) []dataSegment {
	var segs []dataSegment
	off := 0
	for off < len(rawData) {
		if rawData[off] != 0x00 { // type 0 (active, memory 0)
			break
		}
		off++
		if off >= len(rawData) || rawData[off] != 0x41 { // i32.const
			break
		}
		off++
		offset64, n := utils.DecodeSLEB128(rawData[off:])
		off += n
		off++ // 0x0b end
		size, n := utils.DecodeULEB128(rawData[off:])
		off += n
		data := make([]byte, size)
		copy(data, rawData[off:off+int(size)])
		off += int(size)
		segs = append(segs, dataSegment{int32(offset64), data})
	}
	return segs
}

// buildStartFunctionBody builds the WASM function body for the non-standalone
// memory-init start function. It grows memory by growPages pages and then uses
// memory.init to copy each passive segment to its target address, followed by
// data.drop to release the passive segment data.
func buildStartFunctionBody(segs []dataSegment, growPages int32) []byte {
	var body []byte
	body = append(body, 0x00) // no local variable declarations

	// memory.grow(growPages); drop result
	body = append(body, 0x41) // i32.const
	body = utils.AppendULEB128(body, uint32(growPages))
	body = append(body, 0x40, 0x00) // memory.grow memidx=0
	body = append(body, 0x1a)       // drop

	for i, seg := range segs {
		// destination address in memory
		body = append(body, 0x41) // i32.const
		body = utils.AppendSLEB128(body, seg.offset)
		// source offset within passive segment (always 0)
		body = append(body, 0x41, 0x00) // i32.const 0
		// byte count
		body = append(body, 0x41) // i32.const
		body = utils.AppendULEB128(body, uint32(len(seg.data)))
		// memory.init segidx memidx=0
		body = append(body, 0xfc, 0x08)
		body = utils.AppendULEB128(body, uint32(i))
		body = append(body, 0x00) // memidx
		// data.drop segidx
		body = append(body, 0xfc, 0x09)
		body = utils.AppendULEB128(body, uint32(i))
	}

	body = append(body, 0x0b) // end
	return body
}

func appendString(out []byte, s string) []byte {
	out = utils.AppendULEB128(out, uint32(len(s)))
	return append(out, s...)
}

// appendTableLoad8u emits i32.load8_u for a DFA table access.
// tableMemIdx 0: implicit memory 0 encoding (3 bytes: 0x2D 0x00 0x00).
// tableMemIdx 1: explicit memory 1 multi-memory encoding (4 bytes: 0x2D 0x40 0x01 0x00).
func appendTableLoad8u(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x2D, 0x00, 0x00)
	}
	return append(b, 0x2D, 0x40, byte(tableMemIdx), 0x00)
}

// appendTableLoad16u emits i32.load16_u align=1 for a DFA table access.
// tableMemIdx 0: 0x2F 0x01 0x00. tableMemIdx 1: 0x2F 0x41 0x01 0x00.
func appendTableLoad16u(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x2F, 0x01, 0x00)
	}
	return append(b, 0x2F, 0x41, byte(tableMemIdx), 0x00)
}

// appendTableLoad32 emits i32.load align=2 for a stack/table access at the given offset.
// tableMemIdx 0: 0x28 0x02 {offset}. tableMemIdx 1: 0x28 0x42 0x01 {offset}.
func appendTableLoad32(b []byte, tableMemIdx int, offset uint32) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0x28, 0x02)
	} else {
		b = append(b, 0x28, 0x42, byte(tableMemIdx))
	}
	return utils.AppendULEB128(b, offset)
}

// appendTableVLoad emits v128.load align=0 offset=0 for a Teddy table access.
// tableMemIdx 0: 0xFD 0x00 0x00 0x00. tableMemIdx 1: 0xFD 0x00 0x40 0x01 0x00.
func appendTableVLoad(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0xFD, 0x00, 0x00, 0x00)
	}
	return append(b, 0xFD, 0x00, 0x40, byte(tableMemIdx), 0x00)
}

// appendTableStore32 emits i32.store align=2 for a stack/table write at the given offset.
// tableMemIdx 0: 0x36 0x02 {offset}. tableMemIdx 1: 0x36 0x42 0x01 {offset}.
func appendTableStore32(b []byte, tableMemIdx int, offset uint32) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0x36, 0x02)
	} else {
		b = append(b, 0x36, 0x42, byte(tableMemIdx))
	}
	return utils.AppendULEB128(b, offset)
}

// appendTableStore8 emits i32.store8 align=0 offset=0 for a memo table byte write.
// tableMemIdx 0: 0x3A 0x00 0x00. tableMemIdx 1: 0x3A 0x40 0x01 0x00.
func appendTableStore8(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x3A, 0x00, 0x00)
	}
	return append(b, 0x3A, 0x40, byte(tableMemIdx), 0x00)
}

// appendDataSegmentMem1 appends an active data segment targeting memory index 1.
// Uses the multi-memory encoding (type 0x02 + memidx LEB128).
func appendDataSegmentMem1(out []byte, offset int32, data []byte) []byte {
	out = append(out, 0x02) // active segment with explicit memory index
	out = utils.AppendULEB128(out, 1) // memory index = 1
	out = append(out, 0x41) // i32.const
	out = utils.AppendSLEB128(out, offset)
	out = append(out, 0x0B) // end
	out = utils.AppendULEB128(out, uint32(len(data)))
	return append(out, data...)
}
