// Package searchblock is the harnesses' copy of what a generated stub does with
// the per-search block (internal/abi): where an export's blocks go, how a drive
// starts, and what is allocated after a call — notes once the module has armed
// the search, a Backtracking memo once its budget has tripped. Every harness
// that drives find, groups or a set's find takes it from here, so none of them
// can drift from the stubs on its own.
//
// It works over a []byte view of the module's memory and an allocator the
// harness supplies, so the root module stays free of a WASM runtime.
package searchblock

import (
	"encoding/binary"
	"fmt"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
)

// Mode is how a drive hands its blocks over.
type Mode int

const (
	// Off: no block. The search global stays 0 and a set's descriptor keeps
	// the plain magic; the searches run with no counter, notes or memo.
	Off Mode = iota
	// Fresh: as a generated stub — zeroed per drive, notes when the module
	// arms the search, a memo when its Backtracking budget trips.
	Fresh
	// Armed: armed and tripped before the first call, so the MARKED copy of
	// a find with notes, and the Backtracking fallback with the search's kept
	// memo, answer every call.
	Armed
)

func (m Mode) String() string {
	switch m {
	case Off:
		return "off"
	case Fresh:
		return "fresh"
	}
	return "armed"
}

// Size is what one block's search keeps per text position: the notes' bytes
// and the Backtracking memo's bytes (compile.SearchSize's NotesBytes and
// BTMemoBytes).
type Size struct{ Notes, Memo int }

// Of is the blocks an export takes, one Size per block: one for a pattern's
// find or groups export, one per entry of Blocks for a set's find. nil when
// it takes none.
func Of(s compile.SearchSize) []Size {
	if s.Blocks != nil {
		out := make([]Size, len(s.Blocks))
		for k, b := range s.Blocks {
			out[k] = Size{b.NotesBytes, b.BTMemoBytes}
		}
		return out
	}
	if !s.Block() {
		return nil
	}
	return []Size{{s.NotesBytes, s.BTMemoBytes}}
}

// Alloc returns the address of n bytes of the module's memory a drive may
// use; Blocks zeroes them. It may grow memory.
type Alloc func(n int64) (int32, error)

// Blocks is one export's blocks, contiguous from At, abi.SearchBlockBytes
// apart. Every method is a no-op on nil, so a harness can hold a nil Blocks
// for an export that takes none.
type Blocks struct {
	At    int32
	Sizes []Size
	Mode  Mode
	// Alloc places notes and memos. Reset, when set, runs at the start of
	// every drive (a bump allocator rewinding).
	Alloc Alloc
	Reset func()
	// NotesGiven and MemoGiven count, over every drive, the blocks given
	// notes and the blocks given a memo — a run whose count is 0 exercised
	// neither.
	NotesGiven, MemoGiven int

	textLen int
	end     int64
}

// Need is the most one drive over a text of textLen bytes allocates: every
// block's notes and memo, each rounded up to 8.
func Need(sizes []Size, textLen int) int64 {
	var n int64
	for _, s := range sizes {
		n += round8(int64(textLen+1) * int64(s.Notes))
		n += round8(int64(textLen+1) * int64(s.Memo))
	}
	return n
}

// Layout places the blocks at at (aligned up) and room for one drive's notes
// and memos over texts of up to maxLen bytes right after them; End is one past
// it. nil when mode is Off or sizes is empty.
func Layout(at int64, sizes []Size, maxLen int, mode Mode) *Blocks {
	if mode == Off || len(sizes) == 0 {
		return nil
	}
	at = round8(at)
	b := &Blocks{At: int32(at), Sizes: sizes, Mode: mode}
	bump := round8(at + int64(len(sizes))*abi.SearchBlockBytes)
	b.end = bump + Need(sizes, maxLen)
	cur := bump
	b.Reset = func() { cur = bump }
	b.Alloc = func(n int64) (int32, error) {
		if cur+n > b.end {
			return 0, fmt.Errorf("searchblock: %d bytes past the region laid out for %d-byte texts", cur+n-b.end, maxLen)
		}
		p := cur
		cur = round8(cur + n)
		return int32(p), nil
	}
	return b
}

// End is one past what Layout reserved: the harness grows memory to it and
// keeps the Backtracking scratch base above it.
func (b *Blocks) End() int64 {
	if b == nil {
		return 0
	}
	return b.end
}

// Len is the number of blocks.
func (b *Blocks) Len() int {
	if b == nil {
		return 0
	}
	return len(b.Sizes)
}

// Begin starts a drive over a text of textLen bytes: every block zeroed and,
// under Armed, every search armed with its notes and tripped with its memo
// from the first call — bt_cap too, so a Backtracking capture body takes the
// fallback at once.
func (b *Blocks) Begin(mem func() []byte, textLen int) error {
	if b == nil {
		return nil
	}
	if b.Reset != nil {
		b.Reset()
	}
	b.textLen = textLen
	buf := mem()
	clear(buf[b.At : int64(b.At)+int64(len(b.Sizes))*abi.SearchBlockBytes])
	if b.Mode != Armed {
		return nil
	}
	for k, s := range b.Sizes {
		blk := b.blk(k)
		put(mem(), blk+abi.SearchBTCapOff, abi.SearchBTTripped)
		if s.Notes > 0 {
			put(mem(), blk+abi.SearchArmedOff, 1)
			if err := b.give(mem, blk, abi.SearchNotesOff, abi.SearchNotesCapOff, s.Notes); err != nil {
				return err
			}
			b.NotesGiven++
		}
		if s.Memo > 0 {
			put(mem(), blk+abi.SearchBTStateOff, abi.SearchBTTripped)
			if err := b.give(mem, blk, abi.SearchBTMemoOff, abi.SearchBTMemoCapOff, s.Memo); err != nil {
				return err
			}
			b.MemoGiven++
		}
	}
	return nil
}

// BeginBatch is Begin for a drive through a BATCH entry, which runs many finds
// per call: every block that keeps notes gets them at once, armed or not, as a
// generated batching iterator gives them. Handed over only between calls, they
// would never reach a call large enough to hold every match.
func (b *Blocks) BeginBatch(mem func() []byte, textLen int) error {
	if err := b.Begin(mem, textLen); err != nil || b == nil || b.Mode == Armed {
		return err
	}
	for k, s := range b.Sizes {
		if s.Notes > 0 {
			if err := b.give(mem, b.blk(k), abi.SearchNotesOff, abi.SearchNotesCapOff, s.Notes); err != nil {
				return err
			}
			b.NotesGiven++
		}
	}
	return nil
}

// After runs after a call when the drive continues: every search that armed
// during it gets its notes and every one whose Backtracking budget tripped its
// memo, as a generated stub allocates them.
func (b *Blocks) After(mem func() []byte) error {
	if b == nil {
		return nil
	}
	for k, s := range b.Sizes {
		blk := b.blk(k)
		if s.Notes > 0 && get(mem(), blk+abi.SearchArmedOff) != 0 && get(mem(), blk+abi.SearchNotesOff) == 0 {
			if err := b.give(mem, blk, abi.SearchNotesOff, abi.SearchNotesCapOff, s.Notes); err != nil {
				return err
			}
			b.NotesGiven++
		}
		if s.Memo > 0 && get(mem(), blk+abi.SearchBTStateOff) == abi.SearchBTTripped && get(mem(), blk+abi.SearchBTMemoOff) == 0 {
			if err := b.give(mem, blk, abi.SearchBTMemoOff, abi.SearchBTMemoCapOff, s.Memo); err != nil {
				return err
			}
			b.MemoGiven++
		}
	}
	return nil
}

// Describe points a set's scratch descriptor at the blocks: the second magic,
// blocks_ptr and blocks_n. The gate and cache fields are the caller's.
func (b *Blocks) Describe(buf []byte, scratch int32) {
	if b == nil {
		return
	}
	put(buf, int64(scratch)+abi.FindScratchMagicOff, abi.FindScratchMagicBlocks)
	put(buf, int64(scratch)+abi.FindScratchBlocksOff, uint32(b.At))
	put(buf, int64(scratch)+abi.FindScratchBlocksCountOff, uint32(len(b.Sizes)))
}

func (b *Blocks) blk(k int) int64 { return int64(b.At) + int64(k)*abi.SearchBlockBytes }

// give allocates (len + 1) × per zeroed bytes and records them in the block.
func (b *Blocks) give(mem func() []byte, blk int64, ptrOff, capOff int64, per int) error {
	n := int64(b.textLen+1) * int64(per)
	p, err := b.Alloc(n)
	if err != nil {
		return err
	}
	buf := mem()
	clear(buf[p : int64(p)+n])
	put(buf, blk+ptrOff, uint32(p))
	put(buf, blk+capOff, uint32(n))
	return nil
}

func round8(n int64) int64 { return (n + 7) &^ 7 }

func put(buf []byte, at int64, v uint32) { binary.LittleEndian.PutUint32(buf[at:], v) }
func get(buf []byte, at int64) uint32    { return binary.LittleEndian.Uint32(buf[at:]) }
