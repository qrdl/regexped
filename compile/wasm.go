package compile

import (
	"fmt"
	"slices"

	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// WASM binary encoding helpers

// appendImportModuleSection appends the custom section naming the module's
// import_module (abi.ImportModuleSection). A custom section may stand anywhere
// in a module, so appending one leaves the rest of the bytes as they were.
func appendImportModuleSection(wasm []byte, name string) []byte {
	var content []byte
	content = utils.AppendULEB128(content, uint32(len(abi.ImportModuleSection))) //nolint:gosec // a short name
	content = append(content, abi.ImportModuleSection...)
	content = append(content, name...)
	return appendSection(wasm, 0, content)
}

func appendSection(out []byte, id byte, content []byte) []byte {
	out = append(out, id)
	out = utils.AppendULEB128(out, uint32(len(content)))
	return append(out, content...)
}

// appendCodeAndData closes a module: the code section, then — when there are
// data segments — the data section, re-encoded to target memory[1] in an
// embedded build (the module's own table memory). The two are most of a large
// module's bytes (a 339-set configuration's 69.7 MB), so out grows ONCE to
// hold both instead of reallocating, and copying everything before it, as
// each is appended.
//
// It is also where a table the code never reads is left out (keepUnread
// false): see dropUnaddressedTables.
func appendCodeAndData(out, code, rawData []byte, totalSegs int, standalone, keepUnread bool) []byte {
	var ds []byte
	if totalSegs > 0 {
		segs := dropUnaddressedTables(parseDataSegments(rawData), code, keepUnread)
		if standalone {
			ds = make([]byte, 0, 5+len(rawData))
		} else {
			// Each segment's header grows by its memory index: one byte.
			ds = make([]byte, 0, 5+len(rawData)+len(segs))
		}
		ds = utils.AppendULEB128(ds, uint32(len(segs))) //nolint:gosec // a segment count
		for _, seg := range segs {
			if standalone {
				ds = appendDataSegment(ds, seg.offset, seg.data)
			} else {
				ds = appendDataSegmentMem1(ds, seg.offset, seg.data)
			}
		}
	}
	out = slices.Grow(out, 2*(1+5)+len(code)+len(ds))
	out = appendSection(out, 10, code)
	if len(ds) > 0 {
		out = appendSection(out, 11, ds)
	}
	return out
}

// droppableSegFlag marks, in the compiler's own segment stream, an active
// memory-0 segment the module may leave out (appendDroppableDataSegment). It
// never reaches a module: appendCodeAndData re-encodes every segment.
const droppableSegFlag = 0x80

// appendDroppableDataSegment is appendDataSegment for a table some bodies over
// a layout read and others never do — the first-byte flags only the general
// find's prefix scan and the hinted twin route read, the word table only the
// word-boundary checks do — so that the module carries it only when its code
// addresses it (dropUnaddressedTables).
func appendDroppableDataSegment(out []byte, offset int32, data []byte) []byte {
	at := len(out)
	out = appendDataSegment(out, offset, data)
	out[at] = droppableSegFlag
	return out
}

// dropUnaddressedTables leaves out every droppable segment (droppableSegFlag)
// whose offset the module's code never ADDRESSES — no `i32.const <offset>` and
// no load or store whose offset immediate is <offset>, the two ways every
// reader of these tables addresses one. Anything else that merely holds the
// same bytes counts as addressing too, so the test errs towards keeping a
// table. Offsets do not move: a dropped table leaves its range unwritten,
// which is all its readers-that-are-not would have seen.
//
// One byte stands in at the old top when the highest segment is dropped:
// harnesses and utils.WasmMemTop take "where free memory starts" from the
// data segments.
//
// THE RULE THIS RESTS ON: a body reads such a table only through its offset as
// a constant or as a memarg offset. A reader that computed the address any
// other way would have its table dropped and read zeros; the differential test
// (compiled with keepUnread on and off, identical answers) is what catches it.
// keepUnread keeps every table (CompileOptions.KeepUnreadTables, test-only).
func dropUnaddressedTables(segs []dataSegment, code []byte, keepUnread bool) []dataSegment {
	addressed := map[int32]bool{}
	var top int64
	for _, s := range segs {
		if s.droppable {
			addressed[s.offset] = false
		}
		top = max(top, int64(s.offset)+int64(len(s.data)))
	}
	if len(addressed) == 0 || keepUnread {
		return segs
	}
	markAddressedOffsets(code, addressed)
	out := make([]dataSegment, 0, len(segs))
	var newTop int64
	for _, s := range segs {
		if s.droppable && !addressed[s.offset] {
			continue
		}
		out = append(out, s)
		newTop = max(newTop, int64(s.offset)+int64(len(s.data)))
	}
	if newTop < top {
		out = append(out, dataSegment{offset: int32(top - 1), data: []byte{0}}) //nolint:gosec // a table address
	}
	return out
}

// markAddressedOffsets sets addressed[o] for every key o that code holds as an
// i32.const's operand (SLEB128 after 0x41) or as an unsigned LEB128 anywhere —
// a memarg's offset immediate among others, which over-counts and so only
// ever keeps a table that could have gone.
func markAddressedOffsets(code []byte, addressed map[int32]bool) {
	uleb := func(i int) (uint32, bool) {
		var v uint32
		for k := 0; k < 5 && i+k < len(code); k++ {
			c := code[i+k]
			v |= uint32(c&0x7F) << (7 * k)
			if c&0x80 == 0 {
				return v, true
			}
		}
		return 0, false
	}
	for i := range code {
		if v, ok := uleb(i); ok {
			if _, want := addressed[int32(v)]; want { //nolint:gosec // compared, not used
				addressed[int32(v)] = true //nolint:gosec // compared, not used
			}
		}
		if code[i] == 0x41 && i+1 < len(code) {
			if v, n, err := utils.DecodeSLEB128(code[i+1:]); err == nil && n <= 5 {
				if _, want := addressed[int32(v)]; want { //nolint:gosec // compared, not used
					addressed[int32(v)] = true //nolint:gosec // compared, not used
				}
			}
		}
	}
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
	// droppable: encoded with droppableSegFlag (appendDroppableDataSegment).
	droppable bool
}

// parseDataSegments extracts all type-0 (active, memory-0) data segments
// from a concatenation of segments encoded by appendDataSegment.
//
// Like stripSegCount, rawData is always appendDataSegment's own output, so a
// LEB128 decode failure here is an internal invariant violation, not malformed
// user input — see the note on stripSegCount in compile.go.
func parseDataSegments(rawData []byte) []dataSegment {
	var segs []dataSegment
	off := 0
	for off < len(rawData) {
		// type 0 (active, memory 0), or the compiler's droppable mark for one
		droppable := rawData[off] == droppableSegFlag
		if rawData[off] != 0x00 && !droppable {
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
		// The size field is checked against what REMAINS, not trusted. Every
		// other malformation here panics with an invariant message naming the
		// problem; an oversized size was the one that instead sliced out of
		// range and died with Go's own message, which says nothing about where
		// the bad bytes came from. Same class as the truncation checks above,
		// same treatment.
		if int(size) > len(rawData)-off {
			panic(fmt.Sprintf("parseDataSegments: segment size %d exceeds the %d bytes remaining in self-emitted data — invariant violation",
				size, len(rawData)-off))
		}
		data := make([]byte, size)
		copy(data, rawData[off:off+int(size)])
		off += int(size)
		segs = append(segs, dataSegment{offset: int32(offset64), data: data, droppable: droppable})
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

// appendTableLoad8uAt is appendTableLoad8u with a static byte offset, for a
// table whose base is a compile-time constant and whose index is on the stack.
func appendTableLoad8uAt(b []byte, offset int32, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0x2D, 0x00)
		return utils.AppendULEB128(b, uint32(offset))
	}
	b = append(b, 0x2D, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return utils.AppendULEB128(b, uint32(offset))
}

// appendTableLoadV128At emits v128.load align=0 with a static byte offset,
// for a DFA table access whose base is on the stack. The offset immediate is
// what lets a runtime-chosen table base address the fixed sub-tables inside
// one record without a second add per access.
func appendTableLoadV128At(b []byte, offset int32, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		b = append(b, 0xFD, 0x00, 0x00)
		return utils.AppendULEB128(b, uint32(offset))
	}
	b = append(b, 0xFD, 0x00, 0x40)
	b = utils.AppendULEB128(b, uint32(tableMemIdx))
	return utils.AppendULEB128(b, uint32(offset))
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

// appendTableMemoryFill emits `memory.fill` against the TABLE memory.
//
// The immediate is a memory index, and it must be the same one the
// surrounding loads and stores use: an embedded module keeps its tables in
// memory[1] and reads the host's input from memory[0], so a hardcoded 0 here
// zeroes the CALLER's memory instead of the table it was meant to clear —
// silently, since both indices are valid. The BitState memo fill did exactly
// that until 2026-09-06, wiping up to 128 KB of host memory per call while
// leaving the memo itself dirty.
func appendTableMemoryFill(b []byte, tableMemIdx int) []byte {
	b = append(b, 0xFC, 0x0B)
	return utils.AppendULEB128(b, uint32(tableMemIdx))
}
