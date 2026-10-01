package main

// The per-search block (internal/abi) as a generated stub keeps it: one block
// per drive, handed over before every find or groups call. The notes live in a
// region at the end of memory, sized once per instance for the longest text the
// pattern is tested on, with the Backtracking scratch base raised above it.

import (
	"encoding/binary"
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
)

// searchMode is --search-block: off, fresh or armed.
var searchMode string

type searchRegion struct {
	global     *wasmtime.Global
	mem        *wasmtime.Memory
	blk        int32
	notesBytes int
	capacity   int32 // bytes available for notes above the block
	textLen    int
	// The Backtracking memo a tripped search is given, after the notes.
	btBytes int
	btAt    int32
	btCap   int32
}

// curSearch is the instance being tested's region, nil when its exports take
// no block. Every method is a no-op on nil.
var curSearch *searchRegion

func beginSearchRegion(store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, sizes map[string]compile.SearchSize, texts []string) error {
	curSearch = nil
	if searchMode == "off" || mem == nil {
		return nil
	}
	exp := inst.GetExport(store, abi.SearchExport)
	if exp == nil || exp.Global() == nil {
		return nil
	}
	nb, bt, block := 0, 0, false
	for _, sz := range sizes {
		nb = max(nb, sz.NotesBytes)
		bt = max(bt, sz.BTMemoBytes)
		block = block || sz.Block()
	}
	if !block {
		return nil
	}
	maxLen := 0
	for _, t := range texts {
		maxLen = max(maxLen, len(t))
	}
	capacity := int64(maxLen+1) * int64(nb)
	btCap := int64(maxLen+1) * int64(bt)
	at := (int64(mem.DataSize(store)) + 65535) &^ 65535
	need := at + abi.SearchBlockBytes + capacity + btCap + 8
	if grow := (need - int64(mem.DataSize(store)) + 65535) / 65536; grow > 0 {
		if _, err := mem.Grow(store, uint64(grow)); err != nil {
			return fmt.Errorf("grow the search region: %w", err)
		}
	}
	curSearch = &searchRegion{global: exp.Global(), mem: mem, blk: int32(at), notesBytes: nb, capacity: int32(capacity),
		btBytes: bt, btAt: int32((at + abi.SearchBlockBytes + capacity + 7) &^ 7), btCap: int32(btCap)}
	// The Backtracking fallback's scratch goes above the region.
	return setScratchBase(store, inst, int32((need+65535)&^65535))
}

// searchDrives counts the drives that carried a block.
var searchDrives int

// begin starts a drive over a text of textLen bytes: a zeroed block, armed at
// once under --search-block=armed.
func (sr *searchRegion) begin(store *wasmtime.Store, textLen int) {
	if sr == nil {
		return
	}
	searchDrives++
	buf := sr.mem.UnsafeData(store)
	clear(buf[sr.blk : sr.blk+abi.SearchBlockBytes])
	sr.textLen = textLen
	if searchMode == "armed" {
		if sr.notesBytes > 0 {
			binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchArmedOff:], 1)
			sr.allocNotes(buf)
		}
		if sr.btBytes > 0 {
			// Tripped from the first call: the fallback with the search's
			// memo answers every call.
			binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchBTStateOff:], 2)
			sr.allocBTMemo(buf)
		}
	}
}

func (sr *searchRegion) allocBTMemo(buf []byte) {
	n := int32(sr.textLen+1) * int32(sr.btBytes)
	if n > sr.btCap {
		panic(fmt.Sprintf("re2test: a memo for a %d-byte text exceeds the region", sr.textLen))
	}
	clear(buf[sr.btAt : sr.btAt+n])
	binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchBTMemoOff:], uint32(sr.btAt))
	binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchBTMemoCapOff:], uint32(n))
}

func (sr *searchRegion) allocNotes(buf []byte) {
	n := int32(sr.textLen+1) * int32(sr.notesBytes)
	if n > sr.capacity {
		panic(fmt.Sprintf("re2test: notes for a %d-byte text exceed the region", sr.textLen))
	}
	notes := sr.blk + abi.SearchBlockBytes
	clear(buf[notes : notes+n])
	binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchNotesOff:], uint32(notes))
	binary.LittleEndian.PutUint32(buf[sr.blk+abi.SearchNotesCapOff:], uint32(n))
}

// before hands the block over for the next call.
func (sr *searchRegion) before(store *wasmtime.Store) {
	if sr == nil {
		return
	}
	if err := sr.global.Set(store, wasmtime.ValI32(sr.blk)); err != nil {
		panic(err)
	}
}

// after runs after a call that reported a match, when the drive continues: a
// search that armed during it gets its notes, as a stub allocates them.
func (sr *searchRegion) after(store *wasmtime.Store, textLen int) {
	if sr == nil {
		return
	}
	buf := sr.mem.UnsafeData(store)
	sr.textLen = textLen
	if sr.btBytes > 0 && binary.LittleEndian.Uint32(buf[sr.blk+abi.SearchBTStateOff:]) == 2 &&
		binary.LittleEndian.Uint32(buf[sr.blk+abi.SearchBTMemoOff:]) == 0 {
		sr.allocBTMemo(buf)
	}
	if sr.notesBytes == 0 || binary.LittleEndian.Uint32(buf[sr.blk+abi.SearchArmedOff:]) == 0 ||
		binary.LittleEndian.Uint32(buf[sr.blk+abi.SearchNotesOff:]) != 0 {
		return
	}
	sr.allocNotes(buf)
}

// ── A set's split member search blocks ─────────────────────────────────────
//
// A set whose split members keep notes takes their blocks through the second
// form of its scratch descriptor (abi.FindScratchMagicBlocks). The runner hands
// them over exactly as a generated set iterator does: zeroed when a drive
// starts (every drive begins with zeroGates), armed at once under
// --search-block=armed, given notes when one arms otherwise. Under
// --search-block=off the descriptor keeps the plain magic and the members run
// with no block.

type setBlocks struct {
	byFunc      map[*wasmtime.Func]blockList
	byName      map[string]blockList
	blocksPtr   int32 // the blocks, contiguous
	notesPtr    int32 // block k's notes at notesPtr + k × notesStride
	notesStride int32
	memoPtr     int32 // block k's Backtracking memo at memoPtr + k × memoStride
	memoStride  int32
	maxBlocks   int
	blocksFresh bool      // a drive started: the next call with blocks zeroes them
	cur         blockList // the blocks of the drive in flight
	textLen     int
}

// blockList is a set's blocks: per block, the notes bytes and the
// Backtracking memo bytes per text position (compile.SetDiag).
type blockList struct{ notes, memo []int }

func (l blockList) memoOf(k int) int {
	if l.memo == nil {
		return 0
	}
	return l.memo[k]
}

// newSetBlocks sizes the region every set's blocks share — one drive is in
// flight at a time — above *top, and raises *top past it.
func newSetBlocks(diags []compile.SetDiag, maxLen int, top *int64) setBlocks {
	sb := setBlocks{byFunc: map[*wasmtime.Func]blockList{}, byName: map[string]blockList{}}
	if searchMode == "off" {
		return sb
	}
	nb, mb := 0, 0
	for _, d := range diags {
		if len(d.SearchBlocks) == 0 {
			continue
		}
		sb.byName[d.Name] = blockList{notes: d.SearchBlocks, memo: d.SearchBlocksBTMemo}
		sb.maxBlocks = max(sb.maxBlocks, len(d.SearchBlocks))
		for _, n := range d.SearchBlocks {
			nb = max(nb, n)
		}
		for _, n := range d.SearchBlocksBTMemo {
			mb = max(mb, n)
		}
	}
	if sb.maxBlocks == 0 {
		return sb
	}
	at := (*top + abi.SearchBlockAlign - 1) &^ (abi.SearchBlockAlign - 1)
	sb.blocksPtr = int32(at)
	sb.notesPtr = int32(at) + int32(sb.maxBlocks*abi.SearchBlockBytes)
	sb.notesStride = int32((maxLen+1)*nb+7) &^ 7
	sb.memoPtr = sb.notesPtr + int32(sb.maxBlocks)*sb.notesStride
	sb.memoStride = int32((maxLen+1)*mb+7) &^ 7
	*top = int64(sb.memoPtr) + int64(sb.maxBlocks)*int64(sb.memoStride) + 16
	return sb
}

// bindBlocks records which blocks the export fn (a set's find or batch entry)
// takes.
func (sb *setBlocks) bindBlocks(fn *wasmtime.Func, setName string) {
	if l, ok := sb.byName[setName]; fn != nil && ok {
		sb.byFunc[fn] = l
	}
}

// blocksBefore runs before a call: when fn takes blocks and a drive has just
// started, it zeroes them (arming them under --search-block=armed) and points
// the descriptor at them. Reports whether the call takes blocks.
func (sb *setBlocks) blocksBefore(buf []byte, fn *wasmtime.Func, args []interface{}, scratchPtr int32) bool {
	bl, ok := sb.byFunc[fn]
	if !ok {
		return false
	}
	if sb.blocksFresh {
		sb.blocksFresh = false
		sb.cur = bl
		sb.textLen = int(args[1].(int32))
		searchDrives++
		clear(buf[sb.blocksPtr : sb.blocksPtr+int32(len(bl.notes)*abi.SearchBlockBytes)])
		if searchMode == "armed" {
			// Armed: notes from the first call, and a Backtracking member's
			// search tripped with its memo, so the kept memo answers it all.
			for k, nb := range bl.notes {
				blk := sb.blocksPtr + int32(k*abi.SearchBlockBytes)
				if nb > 0 {
					binary.LittleEndian.PutUint32(buf[blk+abi.SearchArmedOff:], 1)
					sb.giveNotes(buf, k, nb)
				}
				if mb := bl.memoOf(k); mb > 0 {
					binary.LittleEndian.PutUint32(buf[blk+abi.SearchBTStateOff:], 2)
					sb.giveMemo(buf, k, mb)
				}
			}
		}
	}
	binary.LittleEndian.PutUint32(buf[scratchPtr+abi.FindScratchMagicOff:], abi.FindScratchMagicBlocks)
	binary.LittleEndian.PutUint32(buf[scratchPtr+abi.FindScratchBlocksOff:], uint32(sb.blocksPtr))
	return true
}

// blocksAfter gives every member block that armed during the call its notes.
func (sb *setBlocks) blocksAfter(buf []byte) {
	for k, nb := range sb.cur.notes {
		blk := sb.blocksPtr + int32(k*abi.SearchBlockBytes)
		if nb > 0 && binary.LittleEndian.Uint32(buf[blk+abi.SearchArmedOff:]) != 0 &&
			binary.LittleEndian.Uint32(buf[blk+abi.SearchNotesOff:]) == 0 {
			sb.giveNotes(buf, k, nb)
		}
		if mb := sb.cur.memoOf(k); mb > 0 && binary.LittleEndian.Uint32(buf[blk+abi.SearchBTStateOff:]) == 2 &&
			binary.LittleEndian.Uint32(buf[blk+abi.SearchBTMemoOff:]) == 0 {
			sb.giveMemo(buf, k, mb)
		}
	}
}

func (sb *setBlocks) giveMemo(buf []byte, k, mb int) {
	n := int32(sb.textLen+1) * int32(mb)
	if n > sb.memoStride {
		panic(fmt.Sprintf("re2test: a split member's memo for a %d-byte text exceeds the region", sb.textLen))
	}
	memo := sb.memoPtr + int32(k)*sb.memoStride
	clear(buf[memo : memo+n])
	blk := sb.blocksPtr + int32(k*abi.SearchBlockBytes)
	binary.LittleEndian.PutUint32(buf[blk+abi.SearchBTMemoOff:], uint32(memo))
	binary.LittleEndian.PutUint32(buf[blk+abi.SearchBTMemoCapOff:], uint32(n))
}

func (sb *setBlocks) giveNotes(buf []byte, k, nb int) {
	n := int32(sb.textLen+1) * int32(nb)
	if n > sb.notesStride {
		panic(fmt.Sprintf("re2test: a split member's notes for a %d-byte text exceed the region", sb.textLen))
	}
	notes := sb.notesPtr + int32(k)*sb.notesStride
	clear(buf[notes : notes+n])
	blk := sb.blocksPtr + int32(k*abi.SearchBlockBytes)
	binary.LittleEndian.PutUint32(buf[blk+abi.SearchNotesOff:], uint32(notes))
	binary.LittleEndian.PutUint32(buf[blk+abi.SearchNotesCapOff:], uint32(n))
}
