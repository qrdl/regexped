package utils

import (
	"errors"
	"os"
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
