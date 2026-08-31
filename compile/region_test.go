package compile

import (
	"strings"
	"testing"
)

// The allocator's contract, checked directly.
//
// The conversion of CompileSet is proved by byte identity — the nine set
// fixtures under testdata/byteident are unchanged by it — but byte identity
// says only that the addresses came out the same. It cannot show that the
// allocator REFUSES the mistakes it exists to refuse, because a correct input
// never triggers them. These do.

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("no panic; wanted one mentioning %q", want)
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, want) {
			t.Fatalf("panic %v, wanted one mentioning %q", r, want)
		}
	}()
	fn()
}

func TestRegionAllocBumpsSequentially(t *testing.T) {
	ra := newRegionAlloc(100)
	if got := ra.Bump("a", 10, 1); got != 100 {
		t.Errorf("first base = %d, want 100", got)
	}
	if got := ra.Bump("b", 10, 1); got != 110 {
		t.Errorf("second base = %d, want 110", got)
	}
	if got := ra.End(); got != 120 {
		t.Errorf("end = %d, want 120", got)
	}
}

func TestRegionAllocAligns(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 1, 1) // 100..101
	if got := ra.Reserve("b", 8); got != 104 {
		t.Errorf("8-aligned base = %d, want 104", got)
	}
	ra.Commit(112)
	if got := ra.End(); got != 112 {
		t.Errorf("end = %d, want 112", got)
	}
}

// A region that ends BELOW where it was reserved means the builder laid its
// table somewhere other than where it was told. Clamping would leave a region
// nobody owns while hiding the discrepancy.
func TestRegionAllocRefusesBackwardCommit(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "below the base", func() { ra.Commit(90) })
}

// Two regions in flight is the shape that produces an overlap: the second base
// would be handed out before the first block's extent is known.
func TestRegionAllocRefusesOverlappingReserve(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "still uncommitted", func() { ra.Reserve("b", 1) })
}

func TestRegionAllocRefusesStrayCommit(t *testing.T) {
	ra := newRegionAlloc(100)
	mustPanic(t, "no Reserve outstanding", func() { ra.Commit(120) })
}

func TestRegionAllocRefusesEndWhilePending(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "still uncommitted", func() { ra.End() })
}

// Skip is how a block that reserved a region and then found it unnecessary
// gives the address space back — the union-scan and phase-2 blocks both do it
// when their builder declines.
func TestRegionAllocSkipLeavesFrontier(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 10, 1)
	ra.Reserve("b", 8)
	ra.Skip()
	if got := ra.End(); got != 110 {
		t.Errorf("end after Skip = %d, want 110", got)
	}
	if got := ra.Bump("c", 4, 1); got != 110 {
		t.Errorf("base after Skip = %d, want 110", got)
	}
}
