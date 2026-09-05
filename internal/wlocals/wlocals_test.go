package wlocals

import (
	"bytes"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
)

// decodeDecls reads back a locals declaration vector the way a WASM validator
// does, so the tests below assert against the DECODED shape rather than
// against the bytes an implementation happened to write.
func decodeDecls(t *testing.T, b []byte) []group {
	t.Helper()
	n, off, err := utils.DecodeULEB128(b)
	if err != nil {
		t.Fatalf("decode group count: %v", err)
	}
	var out []group
	for i := uint64(0); i < n; i++ {
		cnt, w, err := utils.DecodeULEB128(b[off:])
		if err != nil {
			t.Fatalf("decode group %d count: %v", i, err)
		}
		off += w
		if off >= len(b) {
			t.Fatalf("group %d has a count but no type byte", i)
		}
		out = append(out, group{n: uint32(cnt), ty: b[off]})
		off++
	}
	if off != len(b) {
		t.Errorf("%d trailing bytes after the declaration vector", len(b)-off)
	}
	return out
}

// TestAllocIndicesFollowParams pins the contract every emitter depends on:
// allocation starts AFTER the function's parameters, which occupy the low
// indices and are never declared.
//
// Getting this wrong does not fail validation — it produces a body that reads
// a parameter where it meant to read a local, or the reverse.
func TestAllocIndicesFollowParams(t *testing.T) {
	for _, nParams := range []uint32{0, 1, 5} {
		a := New(nParams)
		if got := a.Next(); got != nParams {
			t.Errorf("nParams=%d: first index = %d, want %d", nParams, got, nParams)
		}
		first := a.I32()
		if uint32(first) != nParams {
			t.Errorf("nParams=%d: I32() = %d, want %d", nParams, first, nParams)
		}
		second := a.V128()
		if uint32(second) != nParams+1 {
			t.Errorf("nParams=%d: second alloc = %d, want %d", nParams, second, nParams+1)
		}
		if got := a.Next(); got != nParams+2 {
			t.Errorf("nParams=%d: Next() after two allocs = %d, want %d",
				nParams, got, nParams+2)
		}
	}
}

// TestAllocCoalescesRuns pins the property that let the hand-numbered emitters
// be converted and PROVED by byte identity: allocation order is declaration
// order, and consecutive locals of one type collapse into a single group.
//
// A version that emitted one group per local would validate and run
// identically — and would change every byteident fixture, which is how the
// conversion would have stopped being provable.
func TestAllocCoalescesRuns(t *testing.T) {
	a := New(2)
	a.Reserve(ValI32, 3)
	a.Reserve(ValV128, 7)
	a.Reserve(ValI32, 2)

	got := decodeDecls(t, a.EmitDecls(nil))
	want := []group{{3, ValI32}, {7, ValV128}, {2, ValI32}}
	if len(got) != len(want) {
		t.Fatalf("got %d groups, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("group %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The exact bytes the hand-written emitters used to spell out.
	if wantBytes := []byte{0x03, 0x03, ValI32, 0x07, ValV128, 0x02, ValI32}; !bytes.Equal(a.EmitDecls(nil), wantBytes) {
		t.Errorf("EmitDecls = % x, want % x", a.EmitDecls(nil), wantBytes)
	}
}

// TestAllocEmptyDeclarations covers the body that allocates nothing: the
// vector is a single zero group count, not an empty slice, since a function
// body must always carry one.
func TestAllocEmptyDeclarations(t *testing.T) {
	a := New(3)
	got := a.EmitDecls(nil)
	if len(got) != 1 || got[0] != 0x00 {
		t.Errorf("EmitDecls with no locals = % x, want 00", got)
	}
	if n := a.Next(); n != 3 {
		t.Errorf("Next() with no locals = %d, want 3 (the parameter count)", n)
	}
}

// TestAllocAppendsToExistingBuffer checks EmitDecls appends rather than
// replaces, which is how every caller uses it.
func TestAllocAppendsToExistingBuffer(t *testing.T) {
	a := New(0)
	a.I64()
	prefix := []byte{0xAA, 0xBB}
	got := a.EmitDecls(append([]byte(nil), prefix...))
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("EmitDecls overwrote its buffer: % x", got)
	}
	if g := decodeDecls(t, got[len(prefix):]); len(g) != 1 || g[0].ty != ValI64 {
		t.Errorf("decoded %+v, want one i64 group", g)
	}
}

// TestAllocRefusesIndexPastAByte covers the ceiling.
//
// Every emitter addresses locals with a single byte, so an index past 255
// would be truncated into a DIFFERENT local — a module that validates and
// silently reads the wrong slot. The allocator panics instead.
func TestAllocRefusesIndexPastAByte(t *testing.T) {
	a := New(0)
	a.Reserve(ValI32, 256) // fills 0..255
	if a.Next() != 256 {
		t.Fatalf("Next() = %d, want 256", a.Next())
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("allocating a 257th local did not panic")
		}
		if msg, ok := r.(string); !ok || !contains(msg, "exceeds 255") {
			t.Errorf("panic %v does not name the limit", r)
		}
	}()
	a.I32()
}

// TestScanCursorSeal is the point of the Cursor type: a caller outside this
// package cannot construct one naming a local of its choosing, and the one it
// CAN write — the zero value — is refused.
//
// The defect this seals off shipped twice: seeding the find-from offset into
// the wrong local yields a module that validates, answers correctly for
// from == 0, and ignores the offset for ever after.
func TestScanCursorSeal(t *testing.T) {
	a := New(2)
	a.I32() // some other local, deliberately allocated first
	cur := a.ScanCursor()
	if cur.Local() != 3 {
		t.Errorf("ScanCursor().Local() = %d, want 3", cur.Local())
	}
	// The cursor is an ordinary i32 as far as the declaration is concerned.
	if g := decodeDecls(t, a.EmitDecls(nil)); len(g) != 1 || g[0].n != 2 || g[0].ty != ValI32 {
		t.Errorf("declarations = %+v, want one group of 2 i32", g)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("the zero Cursor answered instead of panicking")
		}
		if msg, ok := r.(string); !ok || !contains(msg, "zero Cursor") {
			t.Errorf("panic %v does not name the cause", r)
		}
	}()
	_ = Cursor{}.Local()
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
