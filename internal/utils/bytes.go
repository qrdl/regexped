package utils

import (
	"fmt"
	"os"
)

const WasmPageSize = 65536 // 64 KB

// PageAlign rounds n up to the next WASM page boundary (64 KB).
func PageAlign(n int64) int64 {
	return (n + WasmPageSize - 1) &^ (WasmPageSize - 1)
}

// AppendULEB128 encodes v as an unsigned LEB128.
func AppendULEB128(out []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// AppendSLEB128 encodes v as a signed LEB128.
func AppendSLEB128(out []byte, v int32) []byte {
	more := true
	for more {
		b := byte(v & 0x7F)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			more = false
		} else {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

// DecodeULEB128 reads an unsigned LEB128 from data and returns the value and
// the number of bytes consumed.
func DecodeULEB128(data []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, b := range data {
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return v, len(data)
}

// DecodeSLEB128 reads a signed LEB128 from data and returns the value and the
// number of bytes consumed.
func DecodeSLEB128(data []byte) (int64, int) {
	var v int64
	var shift uint
	for i, b := range data {
		v |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && b&0x40 != 0 {
				v |= ^0 << shift
			}
			return v, i + 1
		}
	}
	return v, len(data)
}

// WasmMemTop scans the given WASM binary and returns the highest byte address
// that the module occupies: max of all active data-segment end addresses,
// the initial value of the mutable i32 global (the shadow-stack pointer in
// Rust/C outputs), and the memory section's minimum page count × 64 KiB.
// The memory minimum is included because runtimes like Go reserve the entire
// initial memory at startup for heap/stack use, so regex tables must be placed
// above that range even if the static data only occupies a fraction of it.
func WasmMemTop(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(raw) < 8 || string(raw[:4]) != "\x00asm" {
		return 0, fmt.Errorf("not a WASM file")
	}

	var top int64
	off := 8
	for off < len(raw) {
		if off >= len(raw) {
			break
		}
		sectionID := raw[off]
		off++
		secSize, n := DecodeULEB128(raw[off:])
		off += n
		secEnd := off + int(secSize)
		if secEnd > len(raw) {
			break
		}

		switch sectionID {
		case 5: // Memory section – the minimum page count bounds heap use.
			if v, err := ParseMemorySection(raw[off:secEnd]); err == nil && v > top {
				top = v
			}
		case 6: // Global section – find the stack-pointer initial value.
			if v, err := ParseGlobalSection(raw[off:secEnd]); err == nil && v > top {
				top = v
			}
		case 11: // Data section – find the end of each active segment.
			if v, err := ParseDataSection(raw[off:secEnd]); err == nil && v > top {
				top = v
			}
		}
		off = secEnd
	}
	return top, nil
}

// ParseDataSectionBytes scans a complete WASM binary (in memory) and returns
// the highest byte address across all active data segments. Unlike WasmMemTop
// it does not consult globals or the memory section — it is intended for
// measuring the table footprint of a freshly compiled regex WASM where there
// is no host stack/heap to account for.
func ParseDataSectionBytes(raw []byte) (int64, error) {
	if len(raw) < 8 || string(raw[:4]) != "\x00asm" {
		return 0, fmt.Errorf("not a WASM binary")
	}
	off := 8
	for off < len(raw) {
		sectionID := raw[off]
		off++
		secSize, n := DecodeULEB128(raw[off:])
		off += n
		secEnd := off + int(secSize)
		if secEnd > len(raw) {
			break
		}
		if sectionID == 11 {
			return ParseDataSection(raw[off:secEnd])
		}
		off = secEnd
	}
	return 0, nil
}

// ParseMemorySection returns the total byte size of the minimum memory
// reservation (minPages × 64 KiB) across all memories in the section.
// This represents the maximum address that the runtime may use at startup
// without calling memory.grow, so regex tables must be placed above it.
func ParseMemorySection(data []byte) (int64, error) {
	off := 0
	count, n := DecodeULEB128(data[off:])
	off += n

	var max int64
	for i := uint64(0); i < count && off < len(data); i++ {
		flags := uint64(data[off])
		off++
		minPages, n := DecodeULEB128(data[off:])
		off += n
		if flags&1 != 0 {
			_, n = DecodeULEB128(data[off:]) // skip max pages
			off += n
		}
		size := int64(minPages) * WasmPageSize
		if size > max {
			max = size
		}
	}
	return max, nil
}

// ParseGlobalSection returns the maximum i32 initial value among all mutable
// i32 globals. In a Rust WASM binary the shadow-stack pointer is the dominant
// one and marks the top of the pre-allocated stack area.
func ParseGlobalSection(data []byte) (int64, error) {
	off := 0
	count, n := DecodeULEB128(data[off:])
	off += n

	var max int64
	for i := uint64(0); i < count && off < len(data); i++ {
		// valtype (1 byte) + mutability (1 byte)
		if off+2 > len(data) {
			break
		}
		off += 2
		// init expression: expect i32.const (0x41) <sleb128> end (0x0b)
		if off >= len(data) {
			break
		}
		if data[off] == 0x41 {
			off++
			val, n := DecodeSLEB128(data[off:])
			off += n
			off++ // end
			if val > max {
				max = val
			}
		} else {
			// skip other init expressions
			for off < len(data) && data[off] != 0x0b {
				off++
			}
			off++ // end
		}
	}
	return max, nil
}

// ReservationMagic is the 8-byte sentinel placed at byte 0 of every regexped
// reservation variable in generated stubs.  WasmTableBase scans for it.
var ReservationMagic = [8]byte{0x52, 0x45, 0x47, 0x58, 0x50, 0x44, 0x01, 0x02} // "REGXPD\x01\x02"

// WasmTableBase scans the given WASM binary for the regexped reservation magic
// sentinel (ReservationMagic) at the start of an active data segment and returns
// that segment's memory offset.  Returns 0 if the sentinel is not present.
func WasmTableBase(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(raw) < 8 || string(raw[:4]) != "\x00asm" {
		return 0, fmt.Errorf("not a WASM file")
	}
	off := 8
	for off < len(raw) {
		sectionID := raw[off]
		off++
		secSize, n := DecodeULEB128(raw[off:])
		off += n
		secEnd := off + int(secSize)
		if secEnd > len(raw) {
			break
		}
		if sectionID == 11 { // data section
			base, err := findMagicInDataSection(raw[off:secEnd])
			return base, err
		}
		off = secEnd
	}
	return 0, nil
}

// findMagicInDataSection searches the data section payload for an active segment
// whose first bytes match ReservationMagic and returns its memory offset.
func findMagicInDataSection(data []byte) (int64, error) {
	off := 0
	count, n := DecodeULEB128(data[off:])
	off += n
	for i := uint64(0); i < count && off < len(data); i++ {
		segType, n := DecodeULEB128(data[off:])
		off += n
		switch segType {
		case 0: // active, memory 0
			if off >= len(data) || data[off] != 0x41 {
				return 0, fmt.Errorf("expected i32.const in data segment %d", i)
			}
			off++
			segOffset, n := DecodeSLEB128(data[off:])
			off += n
			off++ // end (0x0b)
			size, n := DecodeULEB128(data[off:])
			off += n
			if int(size) >= len(ReservationMagic) {
				match := true
				for j, b := range ReservationMagic {
					if data[off+j] != b {
						match = false
						break
					}
				}
				if match {
					return segOffset, nil
				}
			}
			off += int(size)
		case 1: // passive
			size, n := DecodeULEB128(data[off:])
			off += n
			off += int(size)
		case 2: // active, explicit memory index
			_, n := DecodeULEB128(data[off:]) // memory index
			off += n
			if off >= len(data) || data[off] != 0x41 {
				return 0, fmt.Errorf("expected i32.const in data segment %d", i)
			}
			off++
			segOffset, n := DecodeSLEB128(data[off:])
			off += n
			off++ // end
			size, n := DecodeULEB128(data[off:])
			off += n
			if int(size) >= len(ReservationMagic) {
				match := true
				for j, b := range ReservationMagic {
					if data[off+j] != b {
						match = false
						break
					}
				}
				if match {
					return segOffset, nil
				}
			}
			off += int(size)
		}
	}
	return 0, nil
}

// ParseDataSection returns the highest byte address (offset + size) across all
// active data segments (type 0 = active, memory 0).
func ParseDataSection(data []byte) (int64, error) {
	off := 0
	count, n := DecodeULEB128(data[off:])
	off += n

	var max int64
	for i := uint64(0); i < count && off < len(data); i++ {
		segType, n := DecodeULEB128(data[off:])
		off += n

		switch segType {
		case 0: // active, memory 0
			// offset expression: i32.const <sleb128> end
			if off >= len(data) || data[off] != 0x41 {
				return max, fmt.Errorf("expected i32.const in data segment at %d", off)
			}
			off++
			offset, n := DecodeSLEB128(data[off:])
			off += n
			off++ // end (0x0b)
			size, n := DecodeULEB128(data[off:])
			off += n
			end := offset + int64(size)
			if end > max {
				max = end
			}
			off += int(size)

		case 1: // passive – no offset
			size, n := DecodeULEB128(data[off:])
			off += n
			off += int(size)

		case 2: // active, explicit memory index
			_, n := DecodeULEB128(data[off:]) // memory index
			off += n
			if off >= len(data) || data[off] != 0x41 {
				return max, fmt.Errorf("expected i32.const in data segment at %d", off)
			}
			off++
			offset, n := DecodeSLEB128(data[off:])
			off += n
			off++ // end
			size, n := DecodeULEB128(data[off:])
			off += n
			end := offset + int64(size)
			if end > max {
				max = end
			}
			off += int(size)
		}
	}
	return max, nil
}
