package compile

import (
	"testing"

	"github.com/qrdl/regexped/internal/wlocals"
)

// TestLocalAllocReproducesHandWrittenGroups pins the property that let the
// conversion of the find emitters be proved by byte identity: allocation order
// is declaration order, and adjacent allocations of one type coalesce into a
// single group.
func TestLocalAllocReproducesHandWrittenGroups(t *testing.T) {
	cases := []struct {
		name string
		fill func(*localAlloc)
		want []byte
	}{
		{"3 i32 + 7 v128 (strict alt)", func(a *localAlloc) {
			a.Reserve(valI32, 3)
			a.Reserve(valV128, 7)
		}, []byte{0x02, 0x03, 0x7F, 0x07, 0x7B}},
		{"7 i32 + 5 v128 + 2 i32 (lenient alt)", func(a *localAlloc) {
			a.Reserve(valI32, 7)
			a.Reserve(valV128, 5)
			a.Reserve(valI32, 2)
		}, []byte{0x03, 0x07, 0x7F, 0x05, 0x7B, 0x02, 0x7F}},
		{"an i32 run split by a cursor still coalesces", func(a *localAlloc) {
			a.Reserve(valI32, 5)
			a.ScanCursor()
			a.Reserve(valI32, 1)
		}, []byte{0x01, 0x07, 0x7F}},
		{"zero-count groups are skipped", func(a *localAlloc) {
			a.Reserve(valI32, 7)
			a.Reserve(valV128, 0)
			a.Reserve(valI32, 0)
		}, []byte{0x01, 0x07, 0x7F}},
		{"no locals at all", func(a *localAlloc) {}, []byte{0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newLocalAlloc(2)
			c.fill(a)
			got := a.EmitDecls(nil)
			if string(got) != string(c.want) {
				t.Errorf("declaration vector\n got  % x\n want % x", got, c.want)
			}
		})
	}
}

// TestScanCursorIndicesFollowAllocation checks the cursor names the local the
// allocation actually gave it — the fact emitFindFromSeed now relies on.
func TestScanCursorIndicesFollowAllocation(t *testing.T) {
	a := newLocalAlloc(2)
	a.Reserve(valI32, 2) // 2, 3
	cur := a.ScanCursor()
	if got := cur.Local(); got != 4 {
		t.Errorf("cursor local = %d, want 4", got)
	}
	if next := a.I32(); next != 5 {
		t.Errorf("allocation after cursor = %d, want 5", next)
	}
}

// TestZeroScanCursorIsRefused is the seal.
//
// wlocals.Cursor's fields are unexported and the package exports no
// constructor, so the only cursor an emitter in this package can write down is
// the zero value — and that one is refused. Seeding a local of one's choosing
// is therefore not expressible, which is the whole point: naming the wrong
// local produced a module that validated, answered from == 0 correctly, and
// ignored `from` for ever after, twice.
func TestZeroScanCursorIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a zero scanCursor was accepted; the seal is not holding")
		}
	}()
	var forged wlocals.Cursor
	_, _ = emitFindFromSeed(nil, forged)
}
