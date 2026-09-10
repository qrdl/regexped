package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// parseDataSegments checked every malformation in its input EXCEPT a size field
// larger than the bytes that remain. Truncated LEB128 panicked with an
// invariant message naming the problem; an oversized size instead sliced out of
// range and died with Go's own message, which says nothing about where the bad
// bytes came from.
//
// Inputs here are always this compiler's own output microseconds earlier, so
// this is defence in depth rather than a live crash — the same standing the
// other checks in the function have.

func TestParseDataSegmentsRejectsOversizedSize(t *testing.T) {
	// A well-formed header — type 0, i32.const 0, end — followed by a size
	// claiming far more than the payload that follows.
	var seg []byte
	seg = append(seg, 0x00, 0x41)
	seg = utils.AppendSLEB128(seg, 0)
	seg = append(seg, 0x0B)
	seg = utils.AppendULEB128(seg, 64)
	seg = append(seg, 1, 2, 3) // only three bytes, not 64

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("parseDataSegments accepted a size larger than the remaining bytes")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "exceeds") {
			t.Fatalf("panic = %v, want one naming the oversized segment size", r)
		}
	}()
	parseDataSegments(seg)
}

// A segment whose size exactly consumes the rest of the input is legal and must
// still parse — the check is `>`, not `>=`.
func TestParseDataSegmentsAcceptsExactFit(t *testing.T) {
	payload := []byte{9, 8, 7, 6}
	var seg []byte
	seg = append(seg, 0x00, 0x41)
	seg = utils.AppendSLEB128(seg, 128)
	seg = append(seg, 0x0B)
	seg = utils.AppendULEB128(seg, uint32(len(payload)))
	seg = append(seg, payload...)

	got := parseDataSegments(seg)
	if len(got) != 1 {
		t.Fatalf("parsed %d segments, want 1", len(got))
	}
	if got[0].offset != 128 {
		t.Errorf("offset = %d, want 128", got[0].offset)
	}
	if string(got[0].data) != string(payload) {
		t.Errorf("data = %v, want %v", got[0].data, payload)
	}
}

// The round trip the function actually serves: what appendDataSegment writes,
// parseDataSegments must read back unchanged.
func TestParseDataSegmentsRoundTrip(t *testing.T) {
	want := []struct {
		off  int32
		data []byte
	}{
		{0, []byte{1, 2, 3}},
		{4096, []byte{0xFF}},
		{65536, make([]byte, 300)},
	}
	var raw []byte
	for _, w := range want {
		raw = appendDataSegment(raw, w.off, w.data)
	}
	got := parseDataSegments(raw)
	if len(got) != len(want) {
		t.Fatalf("parsed %d segments, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].offset != want[i].off {
			t.Errorf("segment %d offset = %d, want %d", i, got[i].offset, want[i].off)
		}
		if len(got[i].data) != len(want[i].data) {
			t.Errorf("segment %d length = %d, want %d", i, len(got[i].data), len(want[i].data))
		}
	}
}
