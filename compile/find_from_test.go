package compile

import (
	"bytes"
	"testing"
)

// TestModuleGlobalsZeroValueIsOneGlobal pins the property that let the
// allocator be introduced without moving a single byteident fixture: its ZERO
// VALUE must describe exactly the module shape that existed before it — one
// mutable i32 global, the find-from channel, initialised to 0.
//
// If this drifts, every module in the compiler changes size and every fixture
// moves at once, which is a loud failure. The quiet one it also guards against
// is Count() disagreeing with Section(): the indices Alloc hands out are only
// meaningful because the same counter produces the declarations.
func TestModuleGlobalsZeroValueIsOneGlobal(t *testing.T) {
	var g moduleGlobals
	if got := g.Count(); got != 1 {
		t.Errorf("zero value Count() = %d, want 1 (the find-from channel)", got)
	}
	want := []byte{
		0x01,       // one global
		0x7F, 0x01, // mut i32
		0x41, 0x00, // i32.const 0
		0x0B, // end of init expr
	}
	if got := g.Section(); !bytes.Equal(got, want) {
		t.Errorf("zero value Section() = % x, want % x", got, want)
	}
	// The pre-allocator emitter must stay identical to it, since both are
	// still called and a difference would be a silent module-shape change.
	if got := findFromGlobalSection(); !bytes.Equal(got, want) {
		t.Errorf("findFromGlobalSection() = % x, want % x", got, want)
	}
}

// TestModuleGlobalsAlloc checks that indices start above the find-from channel,
// rise in allocation order, and that every one of them is backed by a
// declaration.
//
// The last part is the invariant that matters. An index without a declaration
// does not corrupt anything — the module fails WASM validation at load — but it
// fails for every caller at once, so it is worth catching here.
func TestModuleGlobalsAlloc(t *testing.T) {
	var g moduleGlobals
	var got []uint32
	for i := 0; i < 4; i++ {
		got = append(got, g.Alloc())
	}
	want := []uint32{1, 2, 3, 4}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Alloc #%d = %d, want %d (index 0 is find-from)", i, got[i], want[i])
		}
		if got[i] == findFromGlobalIdx {
			t.Fatalf("Alloc #%d returned the find-from index %d", i, findFromGlobalIdx)
		}
	}
	if c := g.Count(); c != 5 {
		t.Fatalf("Count() after 4 allocations = %d, want 5", c)
	}
	sec := g.Section()
	if sec[0] != 5 {
		t.Errorf("Section() declares %d globals, want 5", sec[0])
	}
	// One 5-byte declaration per global, after the count byte.
	if len(sec) != 1+5*5 {
		t.Errorf("Section() is %d bytes, want %d (count + 5 declarations)", len(sec), 1+5*5)
	}
	for i := uint32(0); i < g.Count(); i++ {
		off := 1 + 5*i
		decl := sec[off : off+5]
		want := []byte{0x7F, 0x01, 0x41, 0x00, 0x0B}
		if !bytes.Equal(decl, want) {
			t.Errorf("global %d declared as % x, want % x (mut i32, init 0)", i, decl, want)
		}
	}
}
