package utils

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPageAlign(t *testing.T) {
	cases := []struct {
		in, want int64
	}{
		{0, 0},
		{1, 65536},
		{65535, 65536},
		{65536, 65536},
		{65537, 131072},
		{131072, 131072},
	}
	for _, c := range cases {
		if got := PageAlign(c.in); got != c.want {
			t.Errorf("PageAlign(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestAppendDecodeULEB128(t *testing.T) {
	cases := []uint32{0, 1, 63, 127, 128, 255, 256, 16383, 16384, 0xFFFFFFFF}
	for _, v := range cases {
		enc := AppendULEB128(nil, v)
		got, n, err := DecodeULEB128(enc)
		if err != nil {
			t.Errorf("ULEB128 roundtrip(%d): %v", v, err)
			continue
		}
		if uint64(v) != got {
			t.Errorf("ULEB128 roundtrip(%d): got %d", v, got)
		}
		if n != len(enc) {
			t.Errorf("ULEB128 roundtrip(%d): consumed %d bytes, encoded %d", v, n, len(enc))
		}
	}
}

func TestAppendDecodeSLEB128(t *testing.T) {
	cases := []int32{0, 1, -1, 63, -64, 64, -65, 127, -128, 0x7FFFFFFF, -0x80000000}
	for _, v := range cases {
		enc := AppendSLEB128(nil, v)
		got, n, err := DecodeSLEB128(enc)
		if err != nil {
			t.Errorf("SLEB128 roundtrip(%d): %v", v, err)
			continue
		}
		if int64(v) != got {
			t.Errorf("SLEB128 roundtrip(%d): got %d", v, got)
		}
		if n != len(enc) {
			t.Errorf("SLEB128 roundtrip(%d): consumed %d bytes, encoded %d", v, n, len(enc))
		}
	}
}

func TestParseGlobalSection(t *testing.T) {
	buildGlobal := func(val int32) []byte {
		var b []byte
		b = append(b, 0x7F, 0x01) // valtype=i32, mutable
		b = append(b, 0x41)       // i32.const
		b = AppendSLEB128(b, val)
		b = append(b, 0x0B) // end
		return b
	}
	g0 := buildGlobal(1000)
	g1 := buildGlobal(2000)
	var sec []byte
	sec = AppendULEB128(sec, 2)
	sec = append(sec, g0...)
	sec = append(sec, g1...)

	got, err := ParseGlobalSection(sec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2000 {
		t.Errorf("ParseGlobalSection: got %d, want 2000", got)
	}
}

// appendTestSection appends a WASM section (id + uleb128 size + payload) to b.
func appendTestSection(b []byte, id byte, payload []byte) []byte {
	b = append(b, id)
	b = AppendULEB128(b, uint32(len(payload)))
	b = append(b, payload...)
	return b
}

func TestParseMemorySection(t *testing.T) {
	// Two memories: 1 page and 3 pages. Max should be 3 * WasmPageSize.
	var sec []byte
	sec = AppendULEB128(sec, 2) // count
	sec = append(sec, 0x00)     // memory 0: flags=0 (no max)
	sec = AppendULEB128(sec, 1) // min=1 page
	sec = append(sec, 0x00)     // memory 1: flags=0
	sec = AppendULEB128(sec, 3) // min=3 pages

	got, err := ParseMemorySection(sec)
	if err != nil {
		t.Fatalf("ParseMemorySection: %v", err)
	}
	want := int64(3 * WasmPageSize)
	if got != want {
		t.Errorf("ParseMemorySection: got %d, want %d", got, want)
	}
}

func TestParseMemorySectionWithMax(t *testing.T) {
	// One memory with flags=1 (has max). Only min pages count.
	var sec []byte
	sec = AppendULEB128(sec, 1)  // count
	sec = append(sec, 0x01)      // flags = has max
	sec = AppendULEB128(sec, 2)  // min=2 pages
	sec = AppendULEB128(sec, 10) // max=10 pages (should be ignored)

	got, err := ParseMemorySection(sec)
	if err != nil {
		t.Fatalf("ParseMemorySection: %v", err)
	}
	want := int64(2 * WasmPageSize)
	if got != want {
		t.Errorf("ParseMemorySection: got %d, want %d", got, want)
	}
}

// buildWasm constructs a minimal WASM binary containing a single section with the given id and payload.
func buildWasm(sectionID byte, payload []byte) []byte {
	var b []byte
	b = append(b, 0x00, 0x61, 0x73, 0x6d) // magic
	b = append(b, 0x01, 0x00, 0x00, 0x00) // version
	b = append(b, sectionID)
	b = AppendULEB128(b, uint32(len(payload)))
	b = append(b, payload...)
	return b
}

func buildDataSegment(offset int32, size int) []byte {
	var b []byte
	b = AppendULEB128(b, 0) // type=0 (active, memory 0)
	b = append(b, 0x41)
	b = AppendSLEB128(b, offset)
	b = append(b, 0x0b) // end
	b = AppendULEB128(b, uint32(size))
	b = append(b, make([]byte, size)...)
	return b
}

func TestParseDataSectionBytes(t *testing.T) {
	var payload []byte
	payload = AppendULEB128(payload, 2) // 2 segments
	payload = append(payload, buildDataSegment(100, 50)...)
	payload = append(payload, buildDataSegment(200, 75)...)

	raw := buildWasm(11, payload)
	got, err := ParseDataSectionBytes(raw)
	if err != nil {
		t.Fatalf("ParseDataSectionBytes: %v", err)
	}
	if got != 275 {
		t.Errorf("ParseDataSectionBytes: got %d, want 275", got)
	}
}

func TestParseDataSectionBytesNoSection(t *testing.T) {
	// WASM binary with no sections at all.
	var b []byte
	b = append(b, 0x00, 0x61, 0x73, 0x6d)
	b = append(b, 0x01, 0x00, 0x00, 0x00)
	got, err := ParseDataSectionBytes(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("ParseDataSectionBytes (no section): got %d, want 0", got)
	}
}

func TestParseDataSectionBytesNotWasm(t *testing.T) {
	_, err := ParseDataSectionBytes([]byte("not a wasm binary"))
	if err == nil {
		t.Error("ParseDataSectionBytes: expected error for non-WASM input")
	}
}

func TestWasmTableBase(t *testing.T) {
	const magicOffset = int32(12345)

	// Build a data segment starting with ReservationMagic at the given offset.
	var seg []byte
	seg = AppendULEB128(seg, 0) // type=0
	seg = append(seg, 0x41)
	seg = AppendSLEB128(seg, magicOffset)
	seg = append(seg, 0x0b)
	data := make([]byte, 64)
	copy(data, ReservationMagic[:])
	seg = AppendULEB128(seg, uint32(len(data)))
	seg = append(seg, data...)

	var payload []byte
	payload = AppendULEB128(payload, 1)
	payload = append(payload, seg...)

	raw := buildWasm(11, payload)

	f, err := os.CreateTemp("", "regexped-test-*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got, err := WasmTableBase(f.Name())
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != int64(magicOffset) {
		t.Errorf("WasmTableBase: got %d, want %d", got, magicOffset)
	}
}

func TestWasmTableBaseNoMagic(t *testing.T) {
	// Segment without the magic sentinel.
	var seg []byte
	seg = AppendULEB128(seg, 0)
	seg = append(seg, 0x41)
	seg = AppendSLEB128(seg, int32(100))
	seg = append(seg, 0x0b)
	data := make([]byte, 16) // no magic
	seg = AppendULEB128(seg, uint32(len(data)))
	seg = append(seg, data...)

	var payload []byte
	payload = AppendULEB128(payload, 1)
	payload = append(payload, seg...)

	raw := buildWasm(11, payload)

	f, err := os.CreateTemp("", "regexped-test-*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(raw)
	f.Close()

	got, err := WasmTableBase(f.Name())
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != 0 {
		t.Errorf("WasmTableBase: got %d, want 0", got)
	}
}

func TestParseDataSection(t *testing.T) {
	buildSegment := func(offset int32, data []byte) []byte {
		var b []byte
		b = AppendULEB128(b, 0) // segType=0 (active, memory 0)
		b = append(b, 0x41)     // i32.const
		b = AppendSLEB128(b, offset)
		b = append(b, 0x0B) // end
		b = AppendULEB128(b, uint32(len(data)))
		b = append(b, data...)
		return b
	}
	s0 := buildSegment(100, make([]byte, 50))
	s1 := buildSegment(200, make([]byte, 100))
	var sec []byte
	sec = AppendULEB128(sec, 2)
	sec = append(sec, s0...)
	sec = append(sec, s1...)

	got, err := ParseDataSection(sec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 300 {
		t.Errorf("ParseDataSection: got %d, want 300", got)
	}
}

func TestParseDataSectionAllTypes(t *testing.T) {
	// type 0 at offset 100, size 50 → end=150
	var seg0 []byte
	seg0 = AppendULEB128(seg0, 0)
	seg0 = append(seg0, 0x41)
	seg0 = AppendSLEB128(seg0, 100)
	seg0 = append(seg0, 0x0b)
	seg0 = AppendULEB128(seg0, 50)
	seg0 = append(seg0, make([]byte, 50)...)

	// type 1 (passive): no offset, size=20 — ignored for max
	var seg1 []byte
	seg1 = AppendULEB128(seg1, 1)
	seg1 = AppendULEB128(seg1, 20)
	seg1 = append(seg1, make([]byte, 20)...)

	// type 2 (active, explicit memory index): offset=300, size=30 → end=330
	var seg2 []byte
	seg2 = AppendULEB128(seg2, 2)
	seg2 = AppendULEB128(seg2, 0) // memory index
	seg2 = append(seg2, 0x41)
	seg2 = AppendSLEB128(seg2, 300)
	seg2 = append(seg2, 0x0b)
	seg2 = AppendULEB128(seg2, 30)
	seg2 = append(seg2, make([]byte, 30)...)

	var sec []byte
	sec = AppendULEB128(sec, 3)
	sec = append(sec, seg0...)
	sec = append(sec, seg1...)
	sec = append(sec, seg2...)

	got, err := ParseDataSection(sec)
	if err != nil {
		t.Fatalf("ParseDataSection all types: %v", err)
	}
	if got != 330 {
		t.Errorf("ParseDataSection all types: got %d, want 330", got)
	}
}

func TestParseGlobalSectionNonI32Const(t *testing.T) {
	// global 0: i64 (valtype=0x7E), mutable, i64.const init → else branch, ignored
	// global 1: i32 (valtype=0x7F), mutable, i32.const = 100000 → captured
	var sec []byte
	sec = AppendULEB128(sec, 2)   // count
	sec = append(sec, 0x7E, 0x01) // i64, mutable
	sec = append(sec, 0x42, 0x00) // i64.const 0
	sec = append(sec, 0x0b)       // end
	sec = append(sec, 0x7F, 0x01) // i32, mutable
	sec = append(sec, 0x41)       // i32.const
	sec = AppendSLEB128(sec, 100000)
	sec = append(sec, 0x0b)

	got, err := ParseGlobalSection(sec)
	if err != nil {
		t.Fatalf("ParseGlobalSection non-i32: %v", err)
	}
	if got != 100000 {
		t.Errorf("ParseGlobalSection non-i32: got %d, want 100000", got)
	}
}

func TestWasmMemTop(t *testing.T) {
	// Memory section: 2 pages = 131072.
	var memPayload []byte
	memPayload = AppendULEB128(memPayload, 1)
	memPayload = append(memPayload, 0x00) // flags=0
	memPayload = AppendULEB128(memPayload, 2)

	// Global section: i32.const = 50000.
	var globalPayload []byte
	globalPayload = AppendULEB128(globalPayload, 1)
	globalPayload = append(globalPayload, 0x7F, 0x01)
	globalPayload = append(globalPayload, 0x41)
	globalPayload = AppendSLEB128(globalPayload, 50000)
	globalPayload = append(globalPayload, 0x0b)

	// Data section: offset=100, size=50 → end=150.
	var dataSeg []byte
	dataSeg = AppendULEB128(dataSeg, 0)
	dataSeg = append(dataSeg, 0x41)
	dataSeg = AppendSLEB128(dataSeg, 100)
	dataSeg = append(dataSeg, 0x0b)
	dataSeg = AppendULEB128(dataSeg, 50)
	dataSeg = append(dataSeg, make([]byte, 50)...)
	var dataPayload []byte
	dataPayload = AppendULEB128(dataPayload, 1)
	dataPayload = append(dataPayload, dataSeg...)

	var raw []byte
	raw = append(raw, 0x00, 0x61, 0x73, 0x6d)
	raw = append(raw, 0x01, 0x00, 0x00, 0x00)
	raw = appendTestSection(raw, 5, memPayload)
	raw = appendTestSection(raw, 6, globalPayload)
	raw = appendTestSection(raw, 11, dataPayload)

	f, err := os.CreateTemp("", "regexped-memtop-*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got, err := WasmMemTop(f.Name())
	if err != nil {
		t.Fatalf("WasmMemTop: %v", err)
	}
	if got != 131072 { // max(2*65536=131072, 50000, 150)
		t.Errorf("WasmMemTop: got %d, want 131072", got)
	}
}

func TestWasmTableBaseType2Segment(t *testing.T) {
	// type 2 (active, explicit memory) segment with ReservationMagic.
	const magicOffset = int32(77777)

	var seg []byte
	seg = AppendULEB128(seg, 2) // type=2
	seg = AppendULEB128(seg, 0) // memory index
	seg = append(seg, 0x41)
	seg = AppendSLEB128(seg, magicOffset)
	seg = append(seg, 0x0b)
	data := make([]byte, 64)
	copy(data, ReservationMagic[:])
	seg = AppendULEB128(seg, uint32(len(data)))
	seg = append(seg, data...)

	var payload []byte
	payload = AppendULEB128(payload, 1)
	payload = append(payload, seg...)

	raw := buildWasm(11, payload)

	f, err := os.CreateTemp("", "regexped-test-*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(raw)
	f.Close()

	got, err := WasmTableBase(f.Name())
	if err != nil {
		t.Fatalf("WasmTableBase type2: %v", err)
	}
	if got != int64(magicOffset) {
		t.Errorf("WasmTableBase type2: got %d, want %d", got, magicOffset)
	}
}

// TestDecodeLEB128Malformed covers the two rejection classes added for
// Truncated input (runs out of bytes with the continuation
// bit still set) and over-long input (more than ten bytes, whose payload would
// be shifted past bit 63 and silently disappear).
func TestDecodeLEB128Malformed(t *testing.T) {
	overlong := make([]byte, 12)
	for i := range overlong {
		overlong[i] = 0x80
	}
	overlong[11] = 0x01

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x80, 0x80}},
		{"single continuation byte", []byte{0x80}},
		{"over-long", overlong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v, n, err := DecodeULEB128(c.data); err == nil {
				t.Errorf("DecodeULEB128(%x) = (%d, %d, nil), want ErrMalformedLEB128", c.data, v, n)
			} else if !errors.Is(err, ErrMalformedLEB128) {
				t.Errorf("DecodeULEB128(%x): err = %v, want ErrMalformedLEB128", c.data, err)
			}
			if v, n, err := DecodeSLEB128(c.data); err == nil {
				t.Errorf("DecodeSLEB128(%x) = (%d, %d, nil), want ErrMalformedLEB128", c.data, v, n)
			} else if !errors.Is(err, ErrMalformedLEB128) {
				t.Errorf("DecodeSLEB128(%x): err = %v, want ErrMalformedLEB128", c.data, err)
			}
		})
	}
}

// TestDecodeLEB128MaxLength pins the boundary: a full ten-byte encoding is the
// longest legal one and must still decode.
func TestDecodeLEB128MaxLength(t *testing.T) {
	// 0xFFFFFFFFFFFFFFFF encodes as nine 0xFF bytes plus a final 0x01.
	enc := AppendULEB128(nil, 0xFFFFFFFF)
	tenByte := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}
	got, n, err := DecodeULEB128(tenByte)
	if err != nil {
		t.Fatalf("DecodeULEB128(ten-byte max): %v", err)
	}
	if n != 10 || got != ^uint64(0) {
		t.Errorf("DecodeULEB128(ten-byte max) = (%#x, %d), want (%#x, 10)", got, n, ^uint64(0))
	}
	if _, n, err := DecodeULEB128(enc); err != nil || n != len(enc) {
		t.Errorf("DecodeULEB128(%x) = (_, %d, %v), want (_, %d, nil)", enc, n, err, len(enc))
	}
}

// TestWasmMemTopInvalid exercises the not-a-WASM-file error path.
func TestWasmMemTopInvalid(t *testing.T) {
	f, err := os.CreateTemp("", "*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("not a wasm file"))
	f.Close()
	if _, err = WasmMemTop(f.Name()); err == nil {
		t.Error("WasmMemTop: expected error for non-WASM input")
	}
}

// TestWasmMemTopGlobalWins exercises the branch where the global section value
// is the maximum and updates top (line "top = v" for case 6).
func TestWasmMemTopGlobalWins(t *testing.T) {
	var globalPayload []byte
	globalPayload = AppendULEB128(globalPayload, 1)
	globalPayload = append(globalPayload, 0x7F, 0x01) // i32, mutable
	globalPayload = append(globalPayload, 0x41)
	globalPayload = AppendSLEB128(globalPayload, 999999)
	globalPayload = append(globalPayload, 0x0b)

	var raw []byte
	raw = append(raw, 0x00, 0x61, 0x73, 0x6d)
	raw = append(raw, 0x01, 0x00, 0x00, 0x00)
	raw = appendTestSection(raw, 6, globalPayload)

	f, err := os.CreateTemp("", "*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(raw)
	f.Close()

	got, err := WasmMemTop(f.Name())
	if err != nil {
		t.Fatalf("WasmMemTop global wins: %v", err)
	}
	if got != 999999 {
		t.Errorf("WasmMemTop global wins: got %d, want 999999", got)
	}
}

// TestWasmMemTopDataWins exercises the branch where the data section value
// is the maximum and updates top (line "top = v" for case 11).
func TestWasmMemTopDataWins(t *testing.T) {
	var dataSeg []byte
	dataSeg = AppendULEB128(dataSeg, 0) // type=0 active
	dataSeg = append(dataSeg, 0x41)
	dataSeg = AppendSLEB128(dataSeg, 900000)
	dataSeg = append(dataSeg, 0x0b)
	dataSeg = AppendULEB128(dataSeg, 1000)
	dataSeg = append(dataSeg, make([]byte, 1000)...)
	var dataPayload []byte
	dataPayload = AppendULEB128(dataPayload, 1)
	dataPayload = append(dataPayload, dataSeg...)

	var raw []byte
	raw = append(raw, 0x00, 0x61, 0x73, 0x6d)
	raw = append(raw, 0x01, 0x00, 0x00, 0x00)
	raw = appendTestSection(raw, 11, dataPayload)

	f, err := os.CreateTemp("", "*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(raw)
	f.Close()

	got, err := WasmMemTop(f.Name())
	if err != nil {
		t.Fatalf("WasmMemTop data wins: %v", err)
	}
	if got != 901000 { // offset 900000 + size 1000
		t.Errorf("WasmMemTop data wins: got %d, want 901000", got)
	}
}

// TestFindMagicInDataSectionType2Direct calls findMagicInDataSection directly with
// a type-2 segment containing ReservationMagic to cover the match-found return path.
func TestFindMagicInDataSectionType2Direct(t *testing.T) {
	const segOffset = int32(77777)
	var data []byte
	data = AppendULEB128(data, 1)         // count=1
	data = AppendULEB128(data, 2)         // segType=2
	data = AppendULEB128(data, 0)         // memory index
	data = append(data, 0x41)             // i32.const
	data = AppendSLEB128(data, segOffset) // offset
	data = append(data, 0x0b)             // end
	payload := make([]byte, 64)
	copy(payload, ReservationMagic[:])
	data = AppendULEB128(data, 64)
	data = append(data, payload...)

	got, err := findMagicInDataSection(data)
	if err != nil {
		t.Fatalf("findMagicInDataSection type2: %v", err)
	}
	if got != int64(segOffset) {
		t.Errorf("findMagicInDataSection type2: got %d, want %d", got, segOffset)
	}
}

func TestWasmTableBasePassiveSegment(t *testing.T) {
	// type 1 (passive) segment with magic — passive has no offset, ignored.
	var seg1 []byte
	seg1 = AppendULEB128(seg1, 1) // type=1 passive
	data := make([]byte, 64)
	copy(data, ReservationMagic[:])
	seg1 = AppendULEB128(seg1, uint32(len(data)))
	seg1 = append(seg1, data...)

	var payload []byte
	payload = AppendULEB128(payload, 1)
	payload = append(payload, seg1...)

	raw := buildWasm(11, payload)

	f, err := os.CreateTemp("", "regexped-test-*.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(raw)
	f.Close()

	got, err := WasmTableBase(f.Name())
	if err != nil {
		t.Fatalf("WasmTableBase passive: %v", err)
	}
	if got != 0 {
		t.Errorf("WasmTableBase passive: got %d, want 0", got)
	}
}

// A data segment that DECLARES a payload it does not carry must not PANIC.
//
// That is the whole contract, and the name says so: either answer is legal —
// an error, or (0, nil) because the magic genuinely is not there. Asserting
// one of them would pin an implementation detail instead of the guarantee.
//
// findMagicInDataSection tested the declared size against len(ReservationMagic)
// and then indexed data[off+j] on the strength of that promise. A file
// truncated after the size byte satisfied the test and read past the end:
// `index out of range [6] with length 6` on a 16-byte input. The existing
// `off > len(data)` guard above it does not help — that one covers the offset
// EXPRESSION running to the end, and by then off is still in range.
//
// Both segment encodings carry the same comparison, so both are driven here:
// segType 0 (active, memory 0) and segType 2 (active, explicit memory index).
//
// The inputs are hand-assembled rather than built with the helpers above,
// because what is under test is precisely a byte sequence the writers cannot
// produce.
func TestWasmTableBaseTruncatedPayloadDoesNotPanic(t *testing.T) {
	magic := len(ReservationMagic)
	for _, tc := range []struct {
		name string
		seg  []byte
	}{
		{
			// segType 0, i32.const 0, end, size = magic — then nothing.
			name: "segType0",
			seg:  append([]byte{0x00, 0x41, 0x00, 0x0b}, byte(magic)),
		},
		{
			// segType 2, memory index 0, i32.const 0, end, size = magic.
			name: "segType2",
			seg:  append([]byte{0x02, 0x00, 0x41, 0x00, 0x0b}, byte(magic)),
		},
		{
			// One byte of payload present where `magic` were promised: the
			// off-by-a-lot case above could be caught by a coarse test, this
			// one needs the exact bound.
			name: "oneBytePresent",
			seg:  append([]byte{0x00, 0x41, 0x00, 0x0b}, byte(magic), 0x00),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload []byte
			payload = AppendULEB128(payload, 1) // one segment
			payload = append(payload, tc.seg...)
			raw := buildWasm(11, payload)

			f, err := os.CreateTemp("", "regexped-truncated-*.wasm")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())
			if _, err := f.Write(raw); err != nil {
				t.Fatal(err)
			}
			f.Close()

			// The contract is only "does not panic". Returning 0 with no
			// error is a legal answer — the magic genuinely is not there —
			// and so is an error; asserting either would pin an
			// implementation detail rather than the guarantee.
			base, err := WasmTableBase(f.Name())
			t.Logf("WasmTableBase = %d, err = %v", base, err)
		})
	}
}

// TestAppendPaddedULEB128 pins the property the twin-call patch depends on:
// a fixed-width encoding that DecodeULEB128 reads back exactly, so an emitter
// can reserve space for a function index before it is known and overwrite the
// same bytes later without moving anything after them.
func TestAppendPaddedULEB128(t *testing.T) {
	for _, v := range []uint32{0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0xFFFFF, 0xFFFFFFF, 0xFFFFFFFF} {
		for n := 1; n <= 5; n++ {
			// Skip widths the value cannot fit in; those panic by design.
			if bits := 7 * n; n < 5 && v >= uint32(1)<<uint(bits) {
				continue
			}
			got := AppendPaddedULEB128(nil, v, n)
			if len(got) != n {
				t.Fatalf("AppendPaddedULEB128(%d, %d) is %d bytes, want %d", v, n, len(got), n)
			}
			back, used, err := DecodeULEB128(got)
			if err != nil || back != uint64(v) || used != n {
				t.Fatalf("AppendPaddedULEB128(%d, %d) = % x, decoded (%d, %d, %v)",
					v, n, got, back, used, err)
			}
		}
	}
	// Overwriting in place must not change the width.
	buf := AppendPaddedULEB128(nil, 0, 5)
	copy(buf, AppendPaddedULEB128(nil, 123456, 5))
	if back, used, err := DecodeULEB128(buf); err != nil || back != 123456 || used != 5 {
		t.Errorf("in-place overwrite decoded (%d, %d, %v), want (123456, 5, nil)", back, used, err)
	}
}

// TestAppendPaddedULEB128Guards covers the two refusals.
//
// The function exists so an emitter can reserve space for a value it does not
// yet know — a function index — and overwrite those same bytes later. Both
// guards protect that contract: a width outside 1..5 cannot hold a u32, and a
// value that does not fit would be TRUNCATED into a different index, producing
// a module that validates and calls the wrong function. Silence in either case
// is the failure this is meant to prevent.
func TestAppendPaddedULEB128Guards(t *testing.T) {
	for _, n := range []int{-1, 0, 6, 100} {
		t.Run("width "+strconv.Itoa(n), func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("width %d did not panic", n)
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, "width must be 1..5") {
					t.Errorf("panic %v does not name the width limit", r)
				}
			}()
			AppendPaddedULEB128(nil, 1, n)
		})
	}
	// A value past what the requested width can hold.
	for _, tc := range []struct {
		v uint32
		n int
	}{
		{0x80, 1},       // 8 bits into 7
		{0x4000, 2},     // 15 bits into 14
		{0xFFFFFFFF, 4}, // 32 bits into 28
	} {
		t.Run("overflow", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("v=%#x in %d bytes did not panic", tc.v, tc.n)
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, "does not fit") {
					t.Errorf("panic %v does not name the overflow", r)
				}
			}()
			AppendPaddedULEB128(nil, tc.v, tc.n)
		})
	}
}

// TestDataSectionParserRefusals covers parseSegmentHeader's and
// findMagicInDataSection's error arms.
//
// Both parsers walk a data section byte by byte, and both are reached through
// callers that decide where a merged module's tables may be placed. They are
// tested directly rather than through WasmMemTop, which deliberately IGNORES a
// data-section error (`if v, err := ParseDataSection(...); err == nil`) and
// falls back to the memory and global sections — so a malformed section that
// reached it would produce no error at all, and the arm would stay unreached.
func TestDataSectionParserRefusals(t *testing.T) {
	// An unterminated LEB128: every byte carries the continuation bit.
	unterminated := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}

	t.Run("unknown segment kind", func(t *testing.T) {
		var data []byte
		data = AppendULEB128(data, 1)
		data = AppendULEB128(data, 7) // no such data-segment kind
		if _, _, err := parseSegmentHeader(data, 1, 0); err == nil {
			t.Error("parseSegmentHeader accepted an unknown kind")
		} else if !strings.Contains(err.Error(), "unknown kind") {
			t.Errorf("error %q does not name the problem", err)
		}
		if _, err := ParseDataSection(data); err == nil {
			t.Error("ParseDataSection accepted an unknown kind")
		}
		if _, err := findMagicInDataSection(data); err == nil {
			t.Error("findMagicInDataSection accepted an unknown kind")
		}
	})

	t.Run("truncated segment kind", func(t *testing.T) {
		if _, _, err := parseSegmentHeader(unterminated, 0, 0); err == nil {
			t.Error("parseSegmentHeader accepted a truncated kind")
		}
	})

	t.Run("truncated memory index on an explicit-memory segment", func(t *testing.T) {
		// Kind 2 promises a memory index; give it one that never terminates.
		data := append(AppendULEB128(nil, 2), unterminated...)
		if _, _, err := parseSegmentHeader(data, 0, 0); err == nil {
			t.Error("parseSegmentHeader accepted a truncated memory index")
		}
	})

	t.Run("truncated segment count", func(t *testing.T) {
		if _, err := findMagicInDataSection(unterminated); err == nil {
			t.Error("findMagicInDataSection accepted a truncated segment count")
		}
		if _, err := ParseDataSection(unterminated); err == nil {
			t.Error("ParseDataSection accepted a truncated segment count")
		}
	})
}

// AppendSLEB128_64 was at 0%, which is a poor place for a gap: it exists
// BECAUSE the 32-bit encoder is wrong for the values it handles, and using the
// wrong one produces a module that validates and computes the wrong answer.
// That is not hypothetical — an earlier investigation found an emitter
// writing an i64.const through AppendULEB128 with a uint32 cast, so `1 << 6`
// became the single byte 0x40 and decoded as -64. Only an 8-pattern bucket
// could see it.
//
// So these tests check the property that matters: encode, decode, get the same
// value back, over the boundaries where a sign or width mistake shows.

func TestAppendSLEB128_64RoundTrips(t *testing.T) {
	values := []int64{
		0, 1, -1, 63, 64, -64, -65, 127, 128, -128, -129,
		1 << 6, 1 << 7, 1 << 13, 1 << 14, 1 << 31, 1 << 32, 1 << 62,
		-(1 << 6), -(1 << 31), -(1 << 32), -(1 << 62),
		math.MaxInt64, math.MinInt64,
	}
	// Every single-bit mask, which is how accept bitmasks are emitted. Bit 63
	// makes the value NEGATIVE as an int64, which is exactly what the 32-bit
	// encoder cannot express.
	for k := 0; k < 64; k++ {
		values = append(values, int64(uint64(1)<<uint(k)))
	}
	for _, v := range values {
		enc := AppendSLEB128_64(nil, v)
		if len(enc) == 0 {
			t.Fatalf("%d: encoded to nothing", v)
		}
		// Continuation bits must be set on every byte but the last.
		for i, b := range enc[:len(enc)-1] {
			if b&0x80 == 0 {
				t.Errorf("%d: byte %d (%#x) lacks its continuation bit", v, i, b)
			}
		}
		if enc[len(enc)-1]&0x80 != 0 {
			t.Errorf("%d: last byte %#x still has a continuation bit", v, enc[len(enc)-1])
		}
		got, n, err := DecodeSLEB128(enc)
		if err != nil {
			t.Fatalf("%d: decode: %v", v, err)
		}
		if n != len(enc) {
			t.Errorf("%d: decode consumed %d of %d bytes", v, n, len(enc))
		}
		if got != v {
			t.Errorf("%d: round-tripped to %d", v, got)
		}
	}
}

// TestSLEB128_64DiffersFrom32BitEncoding is the mistake stated directly: for a
// value whose low byte has bit 6 set, the UNSIGNED encoder produces a byte
// sequence the signed decoder reads as a different number.
func TestSLEB128_64DiffersFrom32BitEncoding(t *testing.T) {
	const v = int64(1) << 6 // 64 — the first value where this bites
	unsigned := AppendULEB128(nil, uint32(v))
	signed := AppendSLEB128_64(nil, v)
	if bytes.Equal(unsigned, signed) {
		t.Fatalf("the two encodings agree on %d; this test no longer guards anything", v)
	}
	// The unsigned form is one byte, 0x40, and a SIGNED reader takes bit 6 as
	// the sign bit.
	got, _, err := DecodeSLEB128(unsigned)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != -64 {
		t.Fatalf("expected the unsigned encoding of 64 to read back as -64, got %d", got)
	}
}

func TestAppendULEB128RoundTrips(t *testing.T) {
	for _, v := range []uint32{0, 1, 63, 64, 127, 128, 255, 256, 16383, 16384,
		1 << 21, 1 << 28, math.MaxUint32} {
		enc := AppendULEB128(nil, v)
		got, n, err := DecodeULEB128(enc)
		if err != nil {
			t.Fatalf("%d: decode: %v", v, err)
		}
		if n != len(enc) || got != uint64(v) {
			t.Errorf("%d: round-tripped to %d after %d/%d bytes", v, got, n, len(enc))
		}
	}
}

// TestLEB128DecodeRejectsMalformed covers the decoders' error paths, which is
// where a truncated or over-long encoding has to be REFUSED rather than
// silently turned into a plausible number: an eleventh continuation byte
// shifts its payload past bit 63, and Go defines that shift as 0.
func TestLEB128DecodeRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated: continuation with nothing after it", []byte{0x80}},
		{"truncated mid-sequence", []byte{0x80, 0x80}},
		{"over-long: eleven continuation bytes", bytes.Repeat([]byte{0x80}, 11)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := DecodeULEB128(c.in); err == nil {
				t.Errorf("DecodeULEB128(%v) accepted malformed input", c.in)
			}
			if _, _, err := DecodeSLEB128(c.in); err == nil {
				t.Errorf("DecodeSLEB128(%v) accepted malformed input", c.in)
			}
		})
	}
}

// The WASM readers in this package all answer the same question — where is it
// safe to put the regexp tables — from a module someone else produced. Their
// happy paths are exercised constantly by every harness that loads a compiled
// module; their REFUSALS were not exercised at all.
//
// That asymmetry matters more here than usual. These functions return an
// address, and every failure mode returns one too: a truncated section, a
// section length that runs off the end, a module that is not WASM. If a
// malformed input yields a plausible-looking address instead of an error, the
// caller places tables over live data and the corruption surfaces somewhere
// else entirely.

// wasmHeader is the eight-byte preamble every module starts with: magic then
// version.
func wasmHeader() []byte {
	return []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
}

// section appends one section with an id and a LEB128 length.
func section(out []byte, id byte, content []byte) []byte {
	out = append(out, id)
	out = AppendULEB128(out, uint32(len(content)))
	return append(out, content...)
}

func TestParseDataSectionBytesRejectsNonWasm(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"too short to hold a header", []byte{0x00, 'a', 's'}},
		{"right length, wrong magic", []byte("NOTWASM!")},
		{"ELF rather than WASM", []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseDataSectionBytes(c.in); err == nil {
				t.Error("accepted something that is not a WASM binary")
			}
		})
	}
}

// TestParseDataSectionBytesNoDataSection: a valid module with no data section
// is not an error — it has no tables to sit above — so the answer is zero and
// a nil error, not a refusal.
func TestParseDataSectionBytesNoDataSection(t *testing.T) {
	// A type section (id 1) holding an empty vector, and nothing else.
	mod := section(wasmHeader(), 1, []byte{0x00})
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("valid module with no data section: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// TestParseDataSectionBytesTruncatedSection: a section whose declared length
// runs past the end of the module must stop the walk rather than read beyond
// it.
func TestParseDataSectionBytesTruncatedSection(t *testing.T) {
	mod := append(wasmHeader(), 1)               // section id
	mod = append(mod, AppendULEB128(nil, 99)...) // claims 99 bytes
	mod = append(mod, 0x00, 0x01)                // but only two are present
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d from a truncated module, want 0", got)
	}
}

// TestParseDataSectionBytesFindsActiveSegment builds a data section with one
// active segment at a known offset and checks the reported top is the segment's
// end.
func TestParseDataSectionBytesFindsActiveSegment(t *testing.T) {
	const offset = 4096
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	var seg []byte
	seg = append(seg, 0x01)                        // one segment
	seg = append(seg, 0x00)                        // active, memory 0
	seg = append(seg, 0x41)                        // i32.const
	seg = AppendSLEB128(seg, offset)               // its operand
	seg = append(seg, 0x0B)                        // end
	seg = AppendULEB128(seg, uint32(len(payload))) // payload length
	seg = append(seg, payload...)

	mod := section(wasmHeader(), 11, seg)
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := int64(offset + len(payload)); got != want {
		t.Errorf("data top = %d, want %d", got, want)
	}
}

func TestParseMemorySectionShapes(t *testing.T) {
	const pageSize = 65536
	cases := []struct {
		name string
		in   []byte
		want int64
		bad  bool
	}{
		// One memory, flags=0 (min only), min = 2 pages.
		{"single memory, min only", []byte{0x01, 0x00, 0x02}, 2 * pageSize, false},
		// flags=1 means a max follows; the MINIMUM is still what matters,
		// because that is what the runtime reserves without growing.
		{"single memory with a maximum", []byte{0x01, 0x01, 0x03, 0x10}, 3 * pageSize, false},
		// Several memories yield the LARGEST minimum, not their sum: the
		// question being answered is "what address is reserved before anyone
		// grows", and each memory has its own address space.
		{"two memories take the largest minimum", []byte{0x02, 0x00, 0x01, 0x00, 0x02}, 2 * pageSize, false},
		{"no memories", []byte{0x00}, 0, false},
		{"truncated count", []byte{0x80}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMemorySection(c.in)
			if c.bad {
				if err == nil {
					t.Error("accepted a malformed memory section")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestParseGlobalSectionRejectsMalformed(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"truncated count", []byte{0x80}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseGlobalSection(c.in); err == nil {
				t.Errorf("accepted a malformed global section: %v", c.in)
			}
		})
	}
	// A count that promises more globals than the section holds is TOLERATED:
	// the walk simply stops and reports what it read. That is deliberate
	// leniency about a section this reader only consults for an upper bound,
	// so it is pinned as behaviour rather than asserted to be an error.
	if _, err := ParseGlobalSection([]byte{0x01}); err != nil {
		t.Errorf("a short global section should be tolerated, got %v", err)
	}
}

// TestWasmMemTopAndTableBaseOnMissingFile: both readers take a PATH, so "the
// file is not there" is a real caller mistake and has to be reported as one.
func TestWasmMemTopAndTableBaseOnMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.wasm")
	if _, err := WasmMemTop(missing); err == nil {
		t.Error("WasmMemTop accepted a path that does not exist")
	}
	if _, err := WasmTableBase(missing); err == nil {
		t.Error("WasmTableBase accepted a path that does not exist")
	}
}

// TestWasmMemTopOnNonWasmFile: a file that exists but is not a module.
func TestWasmMemTopOnNonWasmFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not.wasm")
	if err := os.WriteFile(path, []byte("this is not a wasm module"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WasmMemTop(path); err == nil {
		t.Error("WasmMemTop accepted a file that is not a WASM module")
	}
	if _, err := WasmTableBase(path); err == nil {
		t.Error("WasmTableBase accepted a file that is not a WASM module")
	}
}

// TestWasmMemTopReadsAModule drives the happy path from a file, which is how
// every caller actually uses it.
func TestWasmMemTopReadsAModule(t *testing.T) {
	const offset = 8192
	payload := []byte{9, 9, 9, 9}
	var seg []byte
	seg = append(seg, 0x01, 0x00, 0x41)
	seg = AppendSLEB128(seg, offset)
	seg = append(seg, 0x0B)
	seg = AppendULEB128(seg, uint32(len(payload)))
	seg = append(seg, payload...)
	// A memory section too, so the reader has to consider both and take the
	// higher.
	mod := section(wasmHeader(), 5, []byte{0x01, 0x00, 0x01}) // one memory, 1 page
	mod = section(mod, 11, seg)

	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmMemTop(path)
	if err != nil {
		t.Fatalf("WasmMemTop: %v", err)
	}
	// The data segment ends at 8196, above the single reserved page (65536)?
	// No — one page IS 65536, so the memory reservation wins. Either way the
	// answer must cover both, so assert that rather than a single source.
	if got < int64(offset+len(payload)) {
		t.Errorf("memTop %d is below the data segment end %d", got, offset+len(payload))
	}
	if got < 65536 {
		t.Errorf("memTop %d is below the reserved memory minimum 65536", got)
	}
}

// activeSegment builds one active data segment for memory 0 at `offset`.
func activeSegment(offset int32, payload []byte) []byte {
	var seg []byte
	seg = append(seg, 0x00) // segment type 0: active, memory 0
	seg = append(seg, 0x41) // i32.const
	seg = AppendSLEB128(seg, offset)
	seg = append(seg, 0x0B) // end
	seg = AppendULEB128(seg, uint32(len(payload)))
	return append(seg, payload...)
}

// TestWasmTableBaseFindsTheReservation covers the reservation sentinel: a
// regexped module marks where its tables may start by putting an 8-byte magic
// at the front of an active data segment, and WasmTableBase reports that
// segment's memory offset.
//
// The searcher has to WALK segments to find it, so a module whose reservation
// sits behind other segments — a passive one, an active one with an explicit
// memory index, a short one that cannot hold the magic — exercises the arms
// that a single-segment module never reaches.
func TestWasmTableBaseFindsTheReservation(t *testing.T) {
	const want = 262144
	magic := ReservationMagic[:]

	var segs []byte
	segs = AppendULEB128(segs, 4) // four segments
	// 1: an active segment TOO SHORT to hold the magic.
	segs = append(segs, activeSegment(16, []byte{1, 2, 3})...)
	// 2: an active segment of the right length whose bytes do not match.
	segs = append(segs, activeSegment(64, []byte("NOTMAGIC"))...)
	// 3: a PASSIVE segment, which carries no offset at all.
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 4)
	passive = append(passive, 9, 9, 9, 9)
	segs = append(segs, passive...)
	// 4: the real reservation.
	segs = append(segs, activeSegment(want, append(append([]byte{}, magic...), 0, 0))...)

	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmTableBase(path)
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != want {
		t.Errorf("table base = %d, want %d", got, want)
	}
}

// TestWasmTableBaseWithoutReservation: a module that carries no sentinel is
// not an error — it simply has no reserved base — so the answer is zero.
func TestWasmTableBaseWithoutReservation(t *testing.T) {
	segs := AppendULEB128(nil, 1)
	segs = append(segs, activeSegment(4096, []byte("ordinary data"))...)
	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmTableBase(path)
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d for a module with no reservation, want 0", got)
	}
}

// TestWasmTableBaseNoDataSection: likewise for a module with no data section
// to search at all.
func TestWasmTableBaseNoDataSection(t *testing.T) {
	mod := section(wasmHeader(), 1, []byte{0x00}) // an empty type section
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := WasmTableBase(path); err != nil || got != 0 {
		t.Errorf("got (%d, %v), want (0, nil)", got, err)
	}
}

// TestFindMagicRejectsMalformedSegment: an active segment must begin with an
// i32.const offset. Anything else is a module this reader cannot make sense
// of, and it has to say so rather than return a plausible address.
func TestFindMagicRejectsMalformedSegment(t *testing.T) {
	segs := AppendULEB128(nil, 1)
	segs = append(segs, 0x00) // active, memory 0
	segs = append(segs, 0x42) // i64.const — not what an active segment uses
	segs = AppendSLEB128(segs, 4096)
	segs = append(segs, 0x0B, 0x02, 0xAA, 0xBB)

	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WasmTableBase(path); err == nil {
		t.Error("accepted a data segment whose offset is not an i32.const")
	}
}

// TestParseDataSectionSegmentKinds drives the three segment kinds through
// ParseDataSection, whose answer is the highest address any ACTIVE segment
// reaches — passive segments have no address and must not contribute.
func TestParseDataSectionSegmentKinds(t *testing.T) {
	var segs []byte
	segs = AppendULEB128(segs, 3)
	segs = append(segs, activeSegment(1000, []byte{1, 2, 3, 4})...) // ends at 1004
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 8)
	passive = append(passive, make([]byte, 8)...)
	segs = append(segs, passive...) // no address at all
	// Active with an EXPLICIT memory index (type 2).
	explicit := []byte{0x02}
	explicit = AppendULEB128(explicit, 0) // memory 0
	explicit = append(explicit, 0x41)
	explicit = AppendSLEB128(explicit, 5000)
	explicit = append(explicit, 0x0B)
	explicit = AppendULEB128(explicit, 2)
	explicit = append(explicit, 7, 7)
	segs = append(segs, explicit...) // ends at 5002

	got, err := ParseDataSection(segs)
	if err != nil {
		t.Fatalf("ParseDataSection: %v", err)
	}
	if got != 5002 {
		t.Errorf("data top = %d, want 5002 (the explicit-memory segment's end)", got)
	}
}

// TestParsersSurviveEveryTruncation feeds each reader a valid module truncated
// at EVERY length.
//
// The readers walk untrusted bytes with explicit offsets, so every one of them
// has a scatter of bounds checks and `if err != nil` returns that no
// well-formed module reaches. Rather than hand-craft a corruption per branch,
// this cuts one good module at every possible point: a truncated section
// header, a length running past the end, a segment cut mid-operand, an
// operand cut mid-LEB128 — all of them, without having to enumerate which is
// which.
//
// The contract asserted is the one that matters for a reader of other
// people's bytes: return an answer or return an error, and NEVER panic.
// A panic here is an out-of-range read on attacker-shaped input.
func TestParsersSurviveEveryTruncation(t *testing.T) {
	// A module with the three sections these readers care about: memory (5),
	// global (6) and data (11), the last carrying the reservation sentinel.
	var segs []byte
	segs = AppendULEB128(segs, 2)
	segs = append(segs, activeSegment(4096, []byte("payload!"))...)
	segs = append(segs, activeSegment(262144, append(append([]byte{}, ReservationMagic[:]...), 0, 0))...)

	global := []byte{0x01, 0x7F, 0x00, 0x41} // one i32 global, mutable=0, i32.const
	global = AppendSLEB128(global, 131072)
	global = append(global, 0x0B)

	mod := section(wasmHeader(), 5, []byte{0x01, 0x00, 0x02}) // memory: min 2 pages
	mod = section(mod, 6, global)
	mod = section(mod, 11, segs)

	// The whole module must parse cleanly first, or the sweep below is
	// truncating something that was never right.
	if _, err := ParseDataSectionBytes(mod); err != nil {
		t.Fatalf("the intact module does not parse: %v", err)
	}

	dir := t.TempDir()
	for n := 0; n <= len(mod); n++ {
		prefix := mod[:n]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseDataSectionBytes panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = ParseDataSectionBytes(prefix)
		}()

		path := filepath.Join(dir, "t.wasm")
		if err := os.WriteFile(path, prefix, 0o644); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("WasmMemTop panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = WasmMemTop(path)
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("WasmTableBase panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = WasmTableBase(path)
		}()
	}
}

// TestSectionParsersSurviveEveryTruncation is the same sweep for the readers
// that take a section PAYLOAD rather than a whole module, which is how
// WasmMemTop reaches them.
func TestSectionParsersSurviveEveryTruncation(t *testing.T) {
	memory := []byte{0x02, 0x00, 0x01, 0x01, 0x03, 0x10} // two memories, one with a max
	global := []byte{0x02, 0x7F, 0x00, 0x41}
	global = AppendSLEB128(global, 65536)
	global = append(global, 0x0B, 0x7F, 0x01, 0x41)
	global = AppendSLEB128(global, 131072)
	global = append(global, 0x0B)

	var data []byte
	data = AppendULEB128(data, 3)
	data = append(data, activeSegment(1000, []byte{1, 2, 3, 4})...)
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 4)
	passive = append(passive, 5, 6, 7, 8)
	data = append(data, passive...)
	explicit := []byte{0x02}
	explicit = AppendULEB128(explicit, 0)
	explicit = append(explicit, 0x41)
	explicit = AppendSLEB128(explicit, 9000)
	explicit = append(explicit, 0x0B)
	explicit = AppendULEB128(explicit, 2)
	explicit = append(explicit, 1, 2)
	data = append(data, explicit...)

	for name, pair := range map[string]struct {
		payload []byte
		parse   func([]byte) (int64, error)
	}{
		"memory": {memory, ParseMemorySection},
		"global": {global, ParseGlobalSection},
		"data":   {data, ParseDataSection},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pair.parse(pair.payload); err != nil {
				t.Fatalf("the intact %s section does not parse: %v", name, err)
			}
			for n := 0; n <= len(pair.payload); n++ {
				prefix := pair.payload[:n]
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s parser panicked on a %d-byte prefix: %v", name, n, r)
						}
					}()
					_, _ = pair.parse(prefix)
				}()
			}
		})
	}
}

// hugeULEB is the 10-byte ULEB128 encoding of 1<<63 — a legal LEB128 whose
// value has bit 63 set. Converted to a Go `int` it is NEGATIVE, which is what
// made every `off + int(size)` bounds check fail open before
func hugeULEB() []byte {
	return []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
}

// TestParsersRejectOversizedLengths feeds each reader a module whose SECTION
// size, and then whose SEGMENT size, is that value.
//
// The contract is the truncation sweep's: an answer or an error, never a
// panic. Before the fix, section ids 5/6/11 sliced raw[off:secEnd] with
// secEnd < off (an inverted-bounds panic) and every other id set off negative
// (an out-of-range index).
func TestParsersRejectOversizedLengths(t *testing.T) {
	var segs []byte
	segs = AppendULEB128(segs, 1)
	segs = append(segs, activeSegment(4096, []byte("payload!"))...)

	cases := map[string][]byte{}

	// A data section whose declared size is 1<<63.
	m := wasmHeader()
	m = append(m, 11)
	m = append(m, hugeULEB()...)
	m = append(m, segs...)
	cases["section size 1<<63"] = m

	// A well-sized data section holding a segment whose payload length is 1<<63.
	var badSeg []byte
	badSeg = AppendULEB128(badSeg, 1)
	badSeg = append(badSeg, 0x00, 0x41)
	badSeg = AppendSLEB128(badSeg, 4096)
	badSeg = append(badSeg, 0x0B)
	badSeg = append(badSeg, hugeULEB()...)
	badSeg = append(badSeg, "payload!"...)
	cases["segment size 1<<63"] = section(wasmHeader(), 11, badSeg)

	// The same, on the explicit-memory-index segment flavour.
	var badSeg2 []byte
	badSeg2 = AppendULEB128(badSeg2, 1)
	badSeg2 = append(badSeg2, 0x02, 0x01, 0x41)
	badSeg2 = AppendSLEB128(badSeg2, 4096)
	badSeg2 = append(badSeg2, 0x0B)
	badSeg2 = append(badSeg2, hugeULEB()...)
	badSeg2 = append(badSeg2, "payload!"...)
	cases["segment size 1<<63, memidx form"] = section(wasmHeader(), 11, badSeg2)

	dir := t.TempDir()
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			_, _ = ParseDataSectionBytes(mod)
			path := filepath.Join(dir, "t.wasm")
			if err := os.WriteFile(path, mod, 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, _ = WasmMemTop(path)
			_, _ = WasmTableBase(path)
		})
	}
}

// TestLEBDecodersRejectOverlongPayloads pins the other half of K1: a tenth
// LEB128 byte whose payload bits would be shifted out of the 64-bit result is
// refused rather than silently truncated.
func TestLEBDecodersRejectOverlongPayloads(t *testing.T) {
	// 0x02 in the tenth byte carries bit 1, which lands at bit 64.
	bad := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	if _, _, err := DecodeULEB128(bad); err == nil {
		t.Error("DecodeULEB128 accepted a payload bit above 63")
	}
	if _, _, err := DecodeSLEB128(bad); err == nil {
		t.Error("DecodeSLEB128 accepted a payload bit above 63")
	}
	// The canonical 10-byte encodings still round-trip.
	for _, v := range []int64{math.MinInt64, math.MaxInt64, -1, 0, 1} {
		got, _, err := DecodeSLEB128(AppendSLEB128_64(nil, v))
		if err != nil || got != v {
			t.Errorf("DecodeSLEB128 round-trip of %d: got %d, %v", v, got, err)
		}
	}
	if got, _, err := DecodeULEB128(hugeULEB()); err != nil || got != 1<<63 {
		t.Errorf("DecodeULEB128(1<<63): got %d, %v", got, err)
	}
}
