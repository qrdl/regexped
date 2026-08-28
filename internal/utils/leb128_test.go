package utils

import (
	"bytes"
	"math"
	"testing"
)

// AppendSLEB128_64 was at 0%, which is a poor place for a gap: it exists
// BECAUSE the 32-bit encoder is wrong for the values it handles, and using the
// wrong one produces a module that validates and computes the wrong answer.
// That is not hypothetical — FUZZER_BUGS 63's investigation found an emitter
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
