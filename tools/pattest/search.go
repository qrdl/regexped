package main

// The per-search block (docs/wasm.md, "The search block"), handed to find and
// groups calls exactly as a generated stub does: zeroed when a drive starts,
// handed over before every call, given notes once the module arms the search.
// Without it a drive runs the no-block path, which skips the waste counter and
// would measure less than a stub pays.

import (
	"encoding/binary"
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/abi"
)

// maxNotesBytes over-allocates the notes: the module needs (len + 1) ×
// notes-bytes and checks the capacity it is given, so a larger region is only
// memory the harness never counts in fuel.
const maxNotesBytes = 8

type searchBlock struct {
	global   *wasmtime.Global
	mem      *wasmtime.Memory
	blk      int32
	notesCap int32
}

// newSearchBlock places a block and room for its notes at the end of memory and
// raises the scratch base above them. nil when the module takes no block.
func newSearchBlock(store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, textLen int) (*searchBlock, error) {
	exp := inst.GetExport(store, abi.SearchExport)
	if exp == nil || exp.Global() == nil {
		return nil, nil
	}
	capacity := int64(textLen+1) * maxNotesBytes
	at := (int64(mem.DataSize(store)) + 65535) &^ 65535
	need := at + abi.SearchBlockBytes + capacity
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
	return &searchBlock{global: exp.Global(), mem: mem, blk: int32(at), notesCap: int32(capacity)}, nil
}

// begin starts a drive: a zeroed block.
func (s *searchBlock) begin(store *wasmtime.Store) {
	if s == nil {
		return
	}
	buf := s.mem.UnsafeData(store)
	clear(buf[s.blk : s.blk+abi.SearchBlockBytes])
}

// before hands the block over for the next call.
func (s *searchBlock) before(store *wasmtime.Store) {
	if s == nil {
		return
	}
	_ = s.global.Set(store, wasmtime.ValI32(s.blk))
}

// after runs after a call that reported a match: an armed search gets notes.
func (s *searchBlock) after(store *wasmtime.Store) {
	if s == nil {
		return
	}
	buf := s.mem.UnsafeData(store)
	if binary.LittleEndian.Uint32(buf[s.blk+abi.SearchArmedOff:]) == 0 ||
		binary.LittleEndian.Uint32(buf[s.blk+abi.SearchNotesOff:]) != 0 {
		return
	}
	notes := s.blk + abi.SearchBlockBytes
	clear(buf[notes : notes+s.notesCap])
	binary.LittleEndian.PutUint32(buf[s.blk+abi.SearchNotesOff:], uint32(notes))
	binary.LittleEndian.PutUint32(buf[s.blk+abi.SearchNotesCapOff:], uint32(s.notesCap))
}
