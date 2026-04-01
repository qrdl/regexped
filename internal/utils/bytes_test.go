package utils

import (
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
