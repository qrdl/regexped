package searchblock

import (
	"errors"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
)

func TestModeString(t *testing.T) {
	for m, want := range map[Mode]string{Off: "off", Fresh: "fresh", Armed: "armed"} {
		if got := m.String(); got != want {
			t.Errorf("%d: %q, want %q", m, got, want)
		}
	}
}

func TestOf(t *testing.T) {
	if got := Of(compile.SearchSize{}); got != nil {
		t.Errorf("no block: %v", got)
	}
	if got := Of(compile.SearchSize{NotesBytes: 2, BTMemoBytes: 3}); len(got) != 1 || got[0] != (Size{2, 3}) {
		t.Errorf("pattern: %v", got)
	}
	if got := Of(compile.SearchSize{BTBudget: true}); len(got) != 1 || got[0] != (Size{}) {
		t.Errorf("budget only: %v", got)
	}
	set := compile.SearchSize{Blocks: []compile.SearchSize{{NotesBytes: 1}, {}, {BTMemoBytes: 4}}}
	if got := Of(set); len(got) != 3 || got[0] != (Size{1, 0}) || got[1] != (Size{}) || got[2] != (Size{0, 4}) {
		t.Errorf("set: %v", got)
	}
}

func TestNeed(t *testing.T) {
	// (10 + 1) × 3 = 33 → 40; (10 + 1) × 1 = 11 → 16; 0.
	if got := Need([]Size{{3, 1}, {}}, 10); got != 56 {
		t.Errorf("Need = %d, want 56", got)
	}
}

func TestLayoutNil(t *testing.T) {
	if Layout(0, []Size{{1, 1}}, 8, Off) != nil || Layout(0, nil, 8, Fresh) != nil {
		t.Fatal("Off or no sizes must lay out nothing")
	}
	var b *Blocks
	if b.End() != 0 || b.Len() != 0 || b.Begin(nil, 0) != nil || b.After(nil) != nil {
		t.Fatal("nil Blocks must be a no-op")
	}
	b.Describe(nil, 0)
}

func mem(buf []byte) func() []byte { return func() []byte { return buf } }

func TestFreshDrive(t *testing.T) {
	sizes := []Size{{2, 0}, {0, 3}, {}}
	b := Layout(5, sizes, 9, Fresh)
	if b.At != 8 || b.Len() != 3 {
		t.Fatalf("At %d Len %d", b.At, b.Len())
	}
	if want := int64(8 + 3*abi.SearchBlockBytes + 24 + 32); b.End() != want {
		t.Fatalf("End %d, want %d", b.End(), want)
	}
	buf := make([]byte, b.End())
	for i := range buf {
		buf[i] = 0xEE
	}
	if err := b.Begin(mem(buf), 9); err != nil {
		t.Fatal(err)
	}
	for i := b.At; i < b.At+3*abi.SearchBlockBytes; i++ {
		if buf[i] != 0 {
			t.Fatalf("block byte %d not zeroed", i)
		}
	}
	// Nothing armed or tripped: nothing given.
	if err := b.After(mem(buf)); err != nil || b.NotesGiven != 0 || b.MemoGiven != 0 {
		t.Fatalf("given %d/%d err %v", b.NotesGiven, b.MemoGiven, err)
	}
	blk0, blk1 := int64(b.At), int64(b.At)+abi.SearchBlockBytes
	put(buf, blk0+abi.SearchArmedOff, 1)
	put(buf, blk1+abi.SearchBTStateOff, 2)
	if err := b.After(mem(buf)); err != nil {
		t.Fatal(err)
	}
	if b.NotesGiven != 1 || b.MemoGiven != 1 {
		t.Fatalf("given %d/%d", b.NotesGiven, b.MemoGiven)
	}
	np, nc := get(buf, blk0+abi.SearchNotesOff), get(buf, blk0+abi.SearchNotesCapOff)
	mp, mc := get(buf, blk1+abi.SearchBTMemoOff), get(buf, blk1+abi.SearchBTMemoCapOff)
	if nc != 20 || mc != 30 || np == 0 || mp < np+24 {
		t.Fatalf("notes %d/%d memo %d/%d", np, nc, mp, mc)
	}
	for i := np; i < np+nc; i++ {
		if buf[i] != 0 {
			t.Fatal("notes not zeroed")
		}
	}
	// Given once per drive.
	if err := b.After(mem(buf)); err != nil || b.NotesGiven != 1 || b.MemoGiven != 1 {
		t.Fatalf("given again: %d/%d err %v", b.NotesGiven, b.MemoGiven, err)
	}
	// A new drive rewinds the region: the same addresses again.
	if err := b.Begin(mem(buf), 9); err != nil {
		t.Fatal(err)
	}
	put(buf, blk0+abi.SearchArmedOff, 1)
	if err := b.After(mem(buf)); err != nil || get(buf, blk0+abi.SearchNotesOff) != np {
		t.Fatalf("rewound notes at %d, want %d (err %v)", get(buf, blk0+abi.SearchNotesOff), np, err)
	}
}

func TestArmedDrive(t *testing.T) {
	b := Layout(0, []Size{{1, 2}, {}}, 4, Armed)
	buf := make([]byte, b.End())
	if err := b.Begin(mem(buf), 4); err != nil {
		t.Fatal(err)
	}
	blk0, blk1 := int64(b.At), int64(b.At)+abi.SearchBlockBytes
	if get(buf, blk0+abi.SearchArmedOff) != 1 || get(buf, blk0+abi.SearchBTStateOff) != 2 ||
		get(buf, blk0+abi.SearchBTCapOff) != 2 || get(buf, blk1+abi.SearchBTCapOff) != 2 {
		t.Fatal("not armed and tripped")
	}
	if get(buf, blk0+abi.SearchNotesCapOff) != 5 || get(buf, blk0+abi.SearchBTMemoCapOff) != 10 {
		t.Fatal("wrong sizes")
	}
	if get(buf, blk1+abi.SearchArmedOff) != 0 || get(buf, blk1+abi.SearchNotesOff) != 0 {
		t.Fatal("a block that keeps nothing was armed")
	}
	if b.NotesGiven != 1 || b.MemoGiven != 1 {
		t.Fatalf("given %d/%d", b.NotesGiven, b.MemoGiven)
	}
}

// TestBeginBatch: a batch drive's notes are given at the start, armed or not;
// the memo still waits for a trip, and an Armed drive is Begin's own.
func TestBeginBatch(t *testing.T) {
	var nilBlocks *Blocks
	if err := nilBlocks.BeginBatch(nil, 0); err != nil {
		t.Fatal("nil Blocks must be a no-op")
	}
	b := Layout(0, []Size{{2, 3}, {}}, 9, Fresh)
	buf := make([]byte, b.End())
	if err := b.BeginBatch(mem(buf), 9); err != nil {
		t.Fatal(err)
	}
	blk0, blk1 := int64(b.At), int64(b.At)+abi.SearchBlockBytes
	if get(buf, blk0+abi.SearchNotesOff) == 0 || get(buf, blk0+abi.SearchNotesCapOff) != 20 {
		t.Fatal("no notes up front")
	}
	if get(buf, blk0+abi.SearchArmedOff) != 0 || get(buf, blk0+abi.SearchBTMemoOff) != 0 || get(buf, blk1+abi.SearchNotesOff) != 0 {
		t.Fatal("armed, a memo, or notes for a block that keeps none")
	}
	if b.NotesGiven != 1 || b.MemoGiven != 0 {
		t.Fatalf("given %d/%d", b.NotesGiven, b.MemoGiven)
	}
	// Arming afterwards gives nothing twice.
	put(buf, blk0+abi.SearchArmedOff, 1)
	if err := b.After(mem(buf)); err != nil || b.NotesGiven != 1 {
		t.Fatalf("given again: %d (err %v)", b.NotesGiven, err)
	}
	a := Layout(0, []Size{{1, 0}}, 4, Armed)
	abuf := make([]byte, a.End())
	if err := a.BeginBatch(mem(abuf), 4); err != nil || a.NotesGiven != 1 {
		t.Fatalf("armed: given %d (err %v)", a.NotesGiven, err)
	}
	over := Layout(0, []Size{{1, 0}}, 4, Fresh)
	if err := over.BeginBatch(mem(make([]byte, over.End()+64)), 40); err == nil {
		t.Fatal("an overrun must fail")
	}
}

func TestOverrun(t *testing.T) {
	for _, s := range []Size{{1, 0}, {0, 1}} {
		b := Layout(0, []Size{s}, 4, Armed)
		buf := make([]byte, b.End()+64)
		if err := b.Begin(mem(buf), 40); err == nil || !strings.Contains(err.Error(), "past the region") {
			t.Fatalf("%v: %v", s, err)
		}
		b.Mode = Fresh
		if err := b.Begin(mem(buf), 40); err != nil {
			t.Fatal(err)
		}
		put(buf, int64(b.At)+abi.SearchArmedOff, 1)
		put(buf, int64(b.At)+abi.SearchBTStateOff, 2)
		if err := b.After(mem(buf)); err == nil {
			t.Fatalf("%v: After must fail", s)
		}
	}
}

func TestCustomAlloc(t *testing.T) {
	buf := make([]byte, 1024)
	fail := errors.New("no")
	b := &Blocks{At: 0, Sizes: []Size{{1, 0}}, Mode: Armed,
		Alloc: func(n int64) (int32, error) { return 512, nil }}
	if err := b.Begin(mem(buf), 3); err != nil || get(buf, abi.SearchNotesOff) != 512 {
		t.Fatalf("custom alloc: %v", err)
	}
	b.Alloc = func(int64) (int32, error) { return 0, fail }
	if err := b.Begin(mem(buf), 3); !errors.Is(err, fail) {
		t.Fatalf("alloc error lost: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	b := Layout(64, []Size{{}, {}}, 1, Fresh)
	buf := make([]byte, 64)
	b.Describe(buf, 8)
	if get(buf, 8+abi.FindScratchMagicOff) != abi.FindScratchMagicBlocks ||
		get(buf, 8+abi.FindScratchBlocksOff) != 64 || get(buf, 8+abi.FindScratchBlocksCountOff) != 2 {
		t.Fatal("descriptor")
	}
}
