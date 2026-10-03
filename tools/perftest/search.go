package main

// The per-search block (docs/wasm.md, "The search block"), handed to find and
// groups calls through the shared helper (internal/searchblock) exactly as a
// generated stub does: zeroed when a drive starts, handed over before every
// call, given notes once the module arms the search and a Backtracking memo
// once its budget trips. Without it a drive runs the no-block path, which
// skips the waste counter and would measure less than a stub pays.

import (
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/searchblock"
)

type searchBlock struct {
	global  *wasmtime.Global
	mem     *wasmtime.Memory
	blocks  *searchblock.Blocks
	textLen int
}

// newSearchBlock places a block and room for its notes and memo at the end of
// memory and raises the scratch base above them. sizes is what the export's
// searches keep (searchblock.Of). nil when the module takes no block.
func newSearchBlock(store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, textLen int, sizes []searchblock.Size) (*searchBlock, error) {
	exp := inst.GetExport(store, abi.SearchExport)
	if exp == nil || exp.Global() == nil {
		return nil, nil
	}
	at := (int64(mem.DataSize(store)) + 65535) &^ 65535
	blocks := searchblock.Layout(at, sizes, textLen, searchblock.Fresh)
	if blocks == nil {
		return nil, nil
	}
	need := blocks.End()
	if grow := (need - int64(mem.DataSize(store)) + 65535) / 65536; grow > 0 {
		if _, err := mem.Grow(store, uint64(grow)); err != nil {
			return nil, fmt.Errorf("grow the search region: %w", err)
		}
	}
	if g := inst.GetExport(store, abi.ScratchBaseExport); g != nil && g.Global() != nil {
		if err := g.Global().Set(store, wasmtime.ValI32(int32((need+65535)&^65535))); err != nil {
			return nil, err
		}
	}
	return &searchBlock{global: exp.Global(), mem: mem, blocks: blocks, textLen: textLen}, nil
}

func (s *searchBlock) data(store *wasmtime.Store) func() []byte {
	return func() []byte { return s.mem.UnsafeData(store) }
}

// begin starts a drive: a zeroed block.
func (s *searchBlock) begin(store *wasmtime.Store) {
	if s == nil {
		return
	}
	if err := s.blocks.Begin(s.data(store), s.textLen); err != nil {
		panic(err)
	}
}

// before hands the block over for the next call.
func (s *searchBlock) before(store *wasmtime.Store) {
	if s == nil {
		return
	}
	_ = s.global.Set(store, wasmtime.ValI32(s.blocks.At))
}

// after runs after a call that reported a match: an armed search gets notes,
// a tripped one its memo.
func (s *searchBlock) after(store *wasmtime.Store) {
	if s == nil {
		return
	}
	if err := s.blocks.After(s.data(store)); err != nil {
		panic(err)
	}
}
