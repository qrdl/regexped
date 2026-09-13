package fuzz

import (
	"fmt"
	"strings"
	"testing"
)

// The scanner constructor TAKES OVER the block the canonical ABI lowered its
// input into, instead of copying it.
//
// The host copies a `list<u8>` into this component's memory through
// cabi_realloc before the constructor runs, and that block is linked on the
// per-call chain. The constructor used to copy it a SECOND time into a block of
// its own and leave the lowered one on the chain, where only some later call's
// post-return freed it: a host that built many scanners before driving any held
// every lowered input at once, and grown memory never shrinks. Unlinking the
// lowered block and keeping it as the scanner's input removes both the copy and
// the deferral. When that block is not the newest one on the chain the
// constructor falls back to the copy.

// ctorText and ctorOther are the same length and match at different places, and
// are long enough that their blocks sit in a size class of their own — no result
// area, gate array or representation competes for it, so free-list reuse is
// predictable.
var (
	ctorText  = pad300("ghp_ab12 AKIAZZZZZZ 123-45")
	ctorOther = pad300("AKIAZZZZZZ ghp_ab12 123-45")
	ctorWant  = [][3]uint32{{0, 0, 8}, {1, 9, 19}, {2, 20, 26}}
	otherWant = [][3]uint32{{1, 0, 10}, {0, 11, 19}, {2, 20, 26}}
)

func pad300(s string) string { return s + strings.Repeat(" ", 300-len(s)) }

// driveHandle runs `next` to exhaustion on a live handle, running each call's
// post-return as a host would, and leaves the handle for the caller to drop.
func (h *setHarness) driveHandle(handle int32) [][3]uint32 {
	h.t.Helper()
	var all [][3]uint32
	for {
		ret := h.call(h.pkg+"#[method]scan-it.next", handle)
		got, errored := h.matches(ret)
		if errored {
			h.t.Fatal("next reported an error")
		}
		h.call("cabi_post_"+h.pkg+"#[method]scan-it.next", ret)
		if len(got) == 0 {
			return all
		}
		all = append(all, got...)
	}
}

// Construct-and-drop with NO other call in between must not grow memory.
func TestComponentConstructorLeavesNoLoweredInputBehind(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	text := strings.Repeat("x", 4096)
	cycle := func() {
		ptr, n := h.writeInput(text)
		handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
		h.call(h.pkg+"#[dtor]scan-it", handle)
	}
	for i := 0; i < 50; i++ { // let the classes fill
		cycle()
	}
	before := len(h.mem.UnsafeData(h.store))
	for i := 0; i < 1000; i++ {
		cycle()
	}
	if after := len(h.mem.UnsafeData(h.store)); after != before {
		t.Errorf("memory grew over 1000 construct/drop pairs with no call between: %d → %d bytes (+%d)",
			before, after, after-before)
	}
}

// The scanner's input IS the lowered block, and it answers correctly from it.
func TestComponentConstructorAdoptsTheLoweredInput(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	ptr, n := h.writeInput(ctorText)
	handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
	// The handle is the representation here (see newSetHarness), and its first
	// word is the scanner's input pointer.
	if got := int32(h.u32(handle)); got != ptr {
		t.Errorf("the scanner reads its input at %d but the host lowered it at %d: it was copied", got, ptr)
	}
	if got := h.driveHandle(handle); fmt.Sprint(got) != fmt.Sprint(ctorWant) {
		t.Errorf("drive over the adopted input = %v, want %v", got, ctorWant)
	}
	h.call(h.pkg+"#[dtor]scan-it", handle)
}

// A block freed by one scanner's dtor and adopted by the next carries no state
// from the first.
func TestComponentAdoptedInputCarriesNoStaleState(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	pa, na := h.writeInput(ctorText)
	a := h.call(h.pkg+"#[constructor]scan-it", pa, na, int32(0))
	gotA := h.driveHandle(a)
	h.call(h.pkg+"#[dtor]scan-it", a)

	pb, nb := h.writeInput(ctorOther)
	if pb != pa {
		t.Fatalf("the second input was lowered at %d, not into the block the first scanner freed "+
			"(%d): the first scanner did not own the lowered block, so this proves nothing", pb, pa)
	}
	b := h.call(h.pkg+"#[constructor]scan-it", pb, nb, int32(0))
	gotB := h.driveHandle(b)
	h.call(h.pkg+"#[dtor]scan-it", b)

	if fmt.Sprint(gotA) != fmt.Sprint(ctorWant) {
		t.Errorf("first drive = %v, want %v", gotA, ctorWant)
	}
	if fmt.Sprint(gotB) != fmt.Sprint(otherWant) {
		t.Errorf("second drive, over the reused block = %v, want %v", gotB, otherWant)
	}
}

// GUARD — it passes before the change as well as after it. When the lowered
// input is NOT the newest block on the per-call chain the constructor copies, as
// it always did. Two ways in: another allocation after the lowering, and a
// zero-length input the host never allocated (pointer 0).
func TestComponentConstructorFallsBackToACopy(t *testing.T) {
	h := newSetHarness(t, narrowSetCfg)
	ptr, n := h.writeInput(ctorText)
	h.call("cabi_realloc", int32(0), int32(0), int32(4), int32(16)) // a newer block
	handle := h.call(h.pkg+"#[constructor]scan-it", ptr, n, int32(0))
	if got := int32(h.u32(handle)); got == ptr {
		t.Error("the constructor took over a lowered block that was not the newest on the chain")
	}
	if got := h.driveHandle(handle); fmt.Sprint(got) != fmt.Sprint(ctorWant) {
		t.Errorf("drive over the copied input = %v, want %v", got, ctorWant)
	}
	h.call(h.pkg+"#[dtor]scan-it", handle)

	empty := h.call(h.pkg+"#[constructor]scan-it", int32(0), int32(0), int32(0))
	if got := h.driveHandle(empty); len(got) != 0 {
		t.Errorf("a zero-length input reported %v, want nothing", got)
	}
	h.call(h.pkg+"#[dtor]scan-it", empty)
}
