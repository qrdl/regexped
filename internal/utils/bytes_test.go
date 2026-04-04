package utils

import (
	"os"
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
		got, n := DecodeULEB128(enc)
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
		got, n := DecodeSLEB128(enc)
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
	sec = AppendULEB128(sec, 2)    // count
	sec = append(sec, 0x00)        // memory 0: flags=0 (no max)
	sec = AppendULEB128(sec, 1)    // min=1 page
	sec = append(sec, 0x00)        // memory 1: flags=0
	sec = AppendULEB128(sec, 3)    // min=3 pages

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
	sec = AppendULEB128(sec, 1)    // count
	sec = append(sec, 0x01)        // flags = has max
	sec = AppendULEB128(sec, 2)    // min=2 pages
	sec = AppendULEB128(sec, 10)   // max=10 pages (should be ignored)

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
	sec = AppendULEB128(sec, 2)       // count
	sec = append(sec, 0x7E, 0x01)     // i64, mutable
	sec = append(sec, 0x42, 0x00)     // i64.const 0
	sec = append(sec, 0x0b)           // end
	sec = append(sec, 0x7F, 0x01)     // i32, mutable
	sec = append(sec, 0x41)           // i32.const
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
