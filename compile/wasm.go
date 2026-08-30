package compile

import (
	"fmt"

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

// segAccum accumulates active data segments while tracking the highest address
// one past the end of everything appended. It exists so a pattern's tableEnd can
// be derived positively — from what was actually emitted — instead of being
// recomputed from an offset variable that a conditional branch may have left at
// its zero value.
//
// The recomputed form is fragile in a specific way: the lit-anchor and
// alt-lit-anchor paths emit a *variable* number of Teddy tables, and the
// invariant that decides how many (litSet is capped at 8 literals in
// lit_anchor.go) lives in a different file from the arithmetic that depends on
// it. Getting it wrong does not fail the build — it yields a tableEnd far below
// the real end of the tables, and since the next pattern is laid out from
// PageAlign(tableEnd), that pattern's tables would be written on top of this
// one's.
type segAccum struct {
	bytes []byte
	count int
	end   int64 // one past the highest byte written by any appended segment
}

// add appends one active data segment and extends end to cover it.
func (s *segAccum) add(offset int32, data []byte) {
	s.bytes = appendDataSegment(s.bytes, offset, data)
	s.count++
	if e := int64(offset) + int64(len(data)); e > s.end {
		s.end = e
	}
}

// dataSegment holds one data segment's target address and raw bytes.
// Used when building the non-standalone init function (passive segments).
type dataSegment struct {
	offset int32
	data   []byte
}

// parseDataSegments extracts all type-0 (active, memory-0) data segments
// from a concatenation of segments encoded by appendDataSegment.
//
// Like stripSegCount, rawData is always appendDataSegment's own output, so a
// LEB128 decode failure here is an internal invariant violation, not malformed
// user input — see the note on stripSegCount in compile.go
// B39.
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
		offset64, n, err := utils.DecodeSLEB128(rawData[off:])
		if err != nil {
			panic(fmt.Sprintf("parseDataSegments: malformed segment offset in self-emitted data: %v — invariant violation", err))
		}
		off += n
		off++ // 0x0b end
		size, n, err := utils.DecodeULEB128(rawData[off:])
		if err != nil {
			panic(fmt.Sprintf("parseDataSegments: malformed segment size in self-emitted data: %v — invariant violation", err))
		}
		off += n
		data := make([]byte, size)
		copy(data, rawData[off:off+int(size)])
		off += int(size)
		segs = append(segs, dataSegment{int32(offset64), data})
	}
	return segs
}

// dataSegmentsTop returns one past the highest address any segment in rawData
// writes, or 0 when there are none. It is segAccum's `end` recovered after the
// fact, for blobs that were already encoded by the time the caller needs their
// extent.
//
// Summing len(rawData) is NOT a substitute and never was: rawData holds ENCODED
// segments (memory index, offset, LEB128 size, payload), and the payloads are
// placed at explicit — not necessarily contiguous — offsets. A length sum both
// counts the encoding overhead and ignores the gaps, and can land either side
// of the truth.
func dataSegmentsTop(rawData []byte) int64 {
	var top int64
	for _, seg := range parseDataSegments(rawData) {
		if e := int64(seg.offset) + int64(len(seg.data)); e > top {
			top = e
		}
	}
	return top
}

func appendString(out []byte, s string) []byte {
	out = utils.AppendULEB128(out, uint32(len(s)))
	return append(out, s...)
}

// appendTableLoad8u emits i32.load8_u for a DFA table access.
// tableMemIdx 0: implicit memory 0 encoding (3 bytes: 0x2D 0x00 0x00).
// tableMemIdx > 0: explicit multi-memory encoding — align byte with the 0x40
// memidx flag set, then the memory index as LEB128, then the offset. For
// memidx 1 this is the same 4 bytes (0x2D 0x40 0x01 0x00) the fixed-width
// encoding produced; LEB128 removes the implicit memidx < 128 assumption.
func appendTableLoad8u(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x2D, 0x00, 0x00)
	}
	b = append(b, 0x2D, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return append(b, 0x00)
}

// appendTableLoad16u emits i32.load16_u align=1 for a DFA table access.
// tableMemIdx 0: 0x2F 0x01 0x00. tableMemIdx 1: 0x2F 0x41 0x01 0x00
// (memidx emitted as LEB128 — see appendTableLoad8u).
func appendTableLoad16u(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x2F, 0x01, 0x00)
	}
	b = append(b, 0x2F, 0x41)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return append(b, 0x00)
}

// appendTableLoad32 emits i32.load align=2 for a stack/table access at the given offset.
// tableMemIdx 0: 0x28 0x02 {offset}. tableMemIdx 1: 0x28 0x42 0x01 {offset}
// (memidx emitted as LEB128 — see appendTableLoad8u).
func appendTableLoad32(b []byte, tableMemIdx int, offset uint32) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0x28, 0x02)
	} else {
		b = append(b, 0x28, 0x42)
		b = utils.AppendULEB128(b, uint32(tableMemIdx))
	}
	return utils.AppendULEB128(b, offset)
}

// appendTableVLoad emits v128.load align=0 offset=0 for a Teddy table access.
// tableMemIdx 0: 0xFD 0x00 0x00 0x00. tableMemIdx 1: 0xFD 0x00 0x40 0x01 0x00
// (memidx emitted as LEB128 — see appendTableLoad8u).
func appendTableVLoad(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0xFD, 0x00, 0x00, 0x00)
	}
	b = append(b, 0xFD, 0x00, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return append(b, 0x00)
}

// appendTableLoad64 emits i64.load align=3 offset=0.
// tableMemIdx 0: 0x29 0x03 0x00. tableMemIdx 1: 0x29 0x43 0x01 0x00.
func appendTableLoad64(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x29, 0x03, 0x00)
	}
	return append(b, 0x29, 0x43, byte(tableMemIdx), 0x00)
}

// appendTableStore32 emits i32.store align=2 for a stack/table write at the given offset.
// tableMemIdx 0: 0x36 0x02 {offset}. tableMemIdx 1: 0x36 0x42 0x01 {offset}
// (memidx emitted as LEB128 — see appendTableLoad8u).
func appendTableStore32(b []byte, tableMemIdx int, offset uint32) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0x36, 0x02)
	} else {
		b = append(b, 0x36, 0x42)
		b = utils.AppendULEB128(b, uint32(tableMemIdx))
	}
	return utils.AppendULEB128(b, offset)
}

// appendTableStore16 emits i32.store16 against the table memory, matching
// appendTableLoad16u's alignment: the memarg align field is the LOG2 of the
// alignment in bytes, so the 0x00 below declares 1-byte (2^0) alignment, NOT
// 2-byte. That is deliberate — the sparse accept lists are packed u16 arrays
// with no padding, so declaring 2-byte alignment would be a lie the validator
// does not check but a host may. Do not "fix" the 0x00 to 0x01.
//
// tableMemIdx 0: 0x3B 0x00 0x00. tableMemIdx 1: 0x3B 0x40 <memidx LEB128> 0x00
// (the 0x40 bit flags an explicit memory index — see appendTableLoad8u).
func appendTableStore16(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x3B, 0x00, 0x00)
	}
	b = append(b, 0x3B, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return append(b, 0x00)
}

// appendTableStore8 emits i32.store8 align=0 offset=0 for a memo table byte
// write. tableMemIdx 0: 0x3A 0x00 0x00. tableMemIdx 1: 0x3A 0x40 0x01 0x00
// (memidx emitted as LEB128 — see appendTableLoad8u).
func appendTableStore8(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x3A, 0x00, 0x00)
	}
	b = append(b, 0x3A, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return append(b, 0x00)
}

// appendDataSegmentMem1 appends an active data segment targeting memory index 1.
// Uses the multi-memory encoding (type 0x02 + memidx LEB128).
func appendDataSegmentMem1(out []byte, offset int32, data []byte) []byte {
	out = append(out, 0x02)           // active segment with explicit memory index
	out = utils.AppendULEB128(out, 1) // memory index = 1
	out = append(out, 0x41)           // i32.const
	out = utils.AppendSLEB128(out, offset)
	out = append(out, 0x0B) // end
	out = utils.AppendULEB128(out, uint32(len(data)))
	return append(out, data...)
}
