package main

// The per-search block (internal/abi) as a generated stub keeps it, through
// the shared helper (internal/searchblock): one block per drive, handed over
// before every find or groups call. The notes and memo live in a region at the
// end of memory, sized once per instance for the longest text the pattern is
// tested on, with the Backtracking scratch base raised above it.

import (
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/searchblock"
)

// searchMode is --search-block: off, fresh or armed.
var searchMode string

type searchRegion struct {
	global *wasmtime.Global
	mem    *wasmtime.Memory
	blocks *searchblock.Blocks
}

// curSearch is the instance being tested's region, nil when its exports take
// no block. Every method is a no-op on nil.
var curSearch *searchRegion

// mode is --search-block as the shared helper's Mode.
func mode() searchblock.Mode {
	switch searchMode {
	case "off":
		return searchblock.Off
	case "armed":
		return searchblock.Armed
	}
	return searchblock.Fresh
}

func beginSearchRegion(store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, sizes map[string]compile.SearchSize, texts []string) error {
	curSearch = nil
	if searchMode == "off" || mem == nil {
		return nil
	}
	exp := inst.GetExport(store, abi.SearchExport)
	if exp == nil || exp.Global() == nil {
		return nil
	}
	// One block serves the instance's find and groups exports, so it keeps
	// the larger of what each needs.
	var sz searchblock.Size
	block := false
	for _, s := range sizes {
		sz.Notes = max(sz.Notes, s.NotesBytes)
		sz.Memo = max(sz.Memo, s.BTMemoBytes)
		block = block || s.Block()
	}
	if !block {
		return nil
	}
	maxLen := 0
	for _, t := range texts {
		maxLen = max(maxLen, len(t))
	}
	at := (int64(mem.DataSize(store)) + 65535) &^ 65535
	blocks := searchblock.Layout(at, []searchblock.Size{sz}, maxLen, mode())
	need := blocks.End() + 8
	if grow := (need - int64(mem.DataSize(store)) + 65535) / 65536; grow > 0 {
		if _, err := mem.Grow(store, uint64(grow)); err != nil {
			return fmt.Errorf("grow the search region: %w", err)
		}
	}
	curSearch = &searchRegion{global: exp.Global(), mem: mem, blocks: blocks}
	// The Backtracking fallback's scratch goes above the region.
	return setScratchBase(store, inst, int32((need+65535)&^65535))
}

// searchDrives counts the drives that carried a block; notesDrives and
// memoDrives the blocks given notes and a Backtracking memo. Under
// --search-block=armed a run whose relevant count is 0 checked neither copy and
// fails: a broken SearchSizes plumbing would otherwise pass silently.
var searchDrives, notesDrives, memoDrives int

// counted runs f and adds what it gave to the run's counts.
func counted(b *searchblock.Blocks, f func() error) {
	n, m := b.NotesGiven, b.MemoGiven
	if err := f(); err != nil {
		panic(fmt.Sprintf("re2test: %v", err))
	}
	notesDrives += b.NotesGiven - n
	memoDrives += b.MemoGiven - m
}

// begin starts a drive over a text of textLen bytes: a zeroed block, armed at
// once under --search-block=armed.
func (sr *searchRegion) begin(store *wasmtime.Store, textLen int) {
	if sr == nil {
		return
	}
	searchDrives++
	counted(sr.blocks, func() error { return sr.blocks.Begin(sr.data(store), textLen) })
}

func (sr *searchRegion) data(store *wasmtime.Store) func() []byte {
	return func() []byte { return sr.mem.UnsafeData(store) }
}

// before hands the block over for the next call.
func (sr *searchRegion) before(store *wasmtime.Store) {
	if sr == nil {
		return
	}
	if err := sr.global.Set(store, wasmtime.ValI32(sr.blocks.At)); err != nil {
		panic(err)
	}
}

// after runs after a call that reported a match, when the drive continues: a
// search that armed during it gets its notes, and one whose Backtracking
// budget tripped its memo, as a stub allocates them.
func (sr *searchRegion) after(store *wasmtime.Store) {
	if sr == nil {
		return
	}
	counted(sr.blocks, func() error { return sr.blocks.After(sr.data(store)) })
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
	byFunc      map[*wasmtime.Func]*searchblock.Blocks
	byName      map[string]*searchblock.Blocks
	blocksFresh bool                    // a drive started: the next call with blocks zeroes them
	cur         *searchblock.Blocks     // the blocks of the drive in flight
	batchFns    map[*wasmtime.Func]bool // the batch entries among byFunc's keys
}

// newSetBlocks lays out every set's blocks above *top — all at the same
// address, since one drive is in flight at a time — and raises *top past the
// largest.
func newSetBlocks(diags []compile.SetDiag, maxLen int, top *int64) setBlocks {
	sb := setBlocks{byFunc: map[*wasmtime.Func]*searchblock.Blocks{}, byName: map[string]*searchblock.Blocks{}}
	at, end := *top, *top
	for _, d := range diags {
		if len(d.SearchBlocks) == 0 {
			continue
		}
		sizes := make([]searchblock.Size, len(d.SearchBlocks))
		for k, n := range d.SearchBlocks {
			sizes[k].Notes = n
			if d.SearchBlocksBTMemo != nil {
				sizes[k].Memo = d.SearchBlocksBTMemo[k]
			}
		}
		if b := searchblock.Layout(at, sizes, maxLen, mode()); b != nil {
			sb.byName[d.Name] = b
			end = max(end, b.End()+16)
		}
	}
	*top = end
	return sb
}

// bindBlocks records which blocks the export fn (a set's find or batch entry)
// takes.
//
// batch: fn is the batch entry, whose drive gets its notes up front
// (searchblock.BeginBatch), as a generated batching iterator gives them.
func (sb *setBlocks) bindBlocks(fn *wasmtime.Func, setName string, batch bool) {
	if b, ok := sb.byName[setName]; fn != nil && ok {
		sb.byFunc[fn] = b
		if batch {
			if sb.batchFns == nil {
				sb.batchFns = map[*wasmtime.Func]bool{}
			}
			sb.batchFns[fn] = true
		}
	}
}

// blocksBefore runs before a call: when fn takes blocks and a drive has just
// started, it zeroes them (arming them under --search-block=armed) and points
// the descriptor at them. Reports whether the call takes blocks.
func (sb *setBlocks) blocksBefore(buf []byte, fn *wasmtime.Func, args []interface{}, scratchPtr int32) bool {
	b, ok := sb.byFunc[fn]
	if !ok {
		return false
	}
	if sb.blocksFresh {
		sb.blocksFresh = false
		sb.cur = b
		searchDrives++
		begin := b.Begin
		if sb.batchFns[fn] {
			begin = b.BeginBatch
		}
		counted(b, func() error { return begin(func() []byte { return buf }, int(args[1].(int32))) })
	}
	b.Describe(buf, scratchPtr)
	return true
}

// blocksAfter gives every member block that armed during the call its notes,
// and every one that tripped its memo.
func (sb *setBlocks) blocksAfter(buf []byte) {
	if sb.cur != nil {
		counted(sb.cur, func() error { return sb.cur.After(func() []byte { return buf }) })
	}
}
