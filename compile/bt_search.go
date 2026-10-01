package compile

import (
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ── Backtracking: one work budget per SEARCH ────────────────────────────────
//
// A Backtracking find's work budget used to last one CALL: a drive whose every
// call burns the budget before the fallback answers paid the burn per call,
// quadratic over the drive (`(?:a|b)*a(?:a|b){12}c|a` over `a`×n: 551 K → 1.1 M
// fuel/byte per doubling). With the caller's per-search block (search_notes.go)
// the budget lasts the search instead: the ordinary body loads what is left
// from the block and saves it back, and once it trips the search is TRIPPED —
// every later call goes straight to the fallback body, whose (pc, position)
// memo the stub then keeps for the search (bt_memo, sized (len + 1) × ⌈N/8⌉ by
// SearchSize.BTMemoBytes), so a mark one call made stops the next. Measured on
// a prototype: the first row 87.5 K fuel/byte flat, 1,500 once the stack
// overflows first; normal input +0.0% to +0.7%, no trip on any of 34 drives.
//
// The memo's marks are failures, so the marks on the path of a REPORTED match
// are cleared before it is returned — from the matching attempt's start, not
// from the call's `from`, which measured +22% to +45% dearer once tripped.
//
// The capture body (`groups`) needs only the tripped flag: its windows already
// sum to the input, so once one capture call of a search has tripped, the rest
// of the search's capture calls go to the fallback directly.
//
// With no block (0) every body runs as it always did: the budget per call.

// btSearch is a Backtracking body's view of the search block.
type btSearch struct {
	g uint32 // the module's search global
}

// btSearchFor is the search context for a Backtracking body compiled under o,
// nil when the module has no global allocator or the body is a set member's,
// whose search state lives in the set's drive regions instead.
func btSearchFor(o *CompileOptions) *btSearch {
	if o == nil || o.globals == nil || o.btNoSearch {
		return nil
	}
	return &btSearch{g: o.globals.Search()}
}

func (c *btSearch) blk(b []byte) []byte { return appendGlobalGet(b, c.g) }

// load32 / store32 / load64 / store64 address the block's field; the block's
// address must already be on the stack. The block lives in the memory the
// input does (memory 0).
func (c *btSearch) load32(b []byte, field uint32) []byte {
	b = append(b, 0x28, 0x02)
	return utils.AppendULEB128(b, field)
}
func (c *btSearch) store32(b []byte, field uint32) []byte {
	b = append(b, 0x36, 0x02)
	return utils.AppendULEB128(b, field)
}
func (c *btSearch) load64(b []byte, field uint32) []byte {
	b = append(b, 0x29, 0x03)
	return utils.AppendULEB128(b, field)
}
func (c *btSearch) store64(b []byte, field uint32) []byte {
	b = append(b, 0x37, 0x03)
	return utils.AppendULEB128(b, field)
}

const (
	btSearchState   = abi.SearchBTStateOff   // i32: 0 new, 1 budget live, 2 tripped
	btSearchWork    = abi.SearchBTBudgetOff  // i64: budget left
	btSearchMemo    = abi.SearchBTMemoOff    // i32: the memo (STUB), 0 = none yet
	btSearchMemoCap = abi.SearchBTMemoCapOff // i32: its size (STUB)
	btSearchCapSt   = abi.SearchBTCapOff     // i32: capture body: 2 once tripped
)

// emitFindEntry is the ordinary find body's budget set-up: from the block when
// there is one (straight to the fallback once the search has tripped), per call
// otherwise. blk and tmp are i32 locals.
func (c *btSearch) emitFindEntry(b []byte, blk, tmp, workLocal uint32, k, n int, callOffs *[]int) []byte {
	init := func(b []byte) []byte {
		return emitBTWorkInit(b, workLocal, k, n, func(b []byte) []byte { return append(b, 0x20, localLen) })
	}
	b = c.blk(b)
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, blk) // local.tee blk
	b = append(b, 0x04, 0x40)       // if blk
	b = btLocalGet(b, blk)
	b = c.load32(b, btSearchState)
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, tmp) // local.tee tmp
	b = append(b, 0x41, 0x02, 0x46) // == 2
	b = append(b, 0x04, 0x40)       // if tripped
	b = emitBTFallbackCall(b, 2, callOffs)
	b = append(b, 0x0B)
	b = btLocalGet(b, tmp)
	b = append(b, 0x04, 0x40) // if state == 1: the search's budget
	b = btLocalGet(b, blk)
	b = c.load64(b, btSearchWork)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, workLocal)
	b = append(b, 0x05) // else: a new search
	b = init(b)
	b = btLocalGet(b, blk)
	b = append(b, 0x41, 0x01)
	b = c.store32(b, btSearchState)
	b = append(b, 0x0B)
	b = append(b, 0x05) // else: no block, this call's budget
	b = init(b)
	return append(b, 0x0B)
}

// emitFindSave stores what is left of the budget, before a return.
func (c *btSearch) emitFindSave(b []byte, blk, workLocal uint32) []byte {
	b = btLocalGet(b, blk)
	b = append(b, 0x04, 0x40)
	b = btLocalGet(b, blk)
	b = btLocalGet(b, workLocal)
	b = c.store64(b, btSearchWork)
	return append(b, 0x0B)
}

// emitFindTripped marks the search tripped, before the fallback tail call.
func (c *btSearch) emitFindTripped(b []byte, blk uint32) []byte {
	b = btLocalGet(b, blk)
	b = append(b, 0x04, 0x40)
	b = btLocalGet(b, blk)
	b = append(b, 0x41, 0x02)
	b = c.store32(b, btSearchState)
	return append(b, 0x0B)
}

// emitFallbackPlace is the fallback find body's once-per-call region set-up
// with the search's memo: rows are absolute positions (origin 0), the stub
// zeroed the whole memo, so all of it counts as cleared; the frame stack is
// this call's, at the scratch base. It leaves 1 on the stack when it placed
// the search's memo, 0 when there is none to use (no memo yet, or one too
// small for this text) and the caller must place this call's own.
func (c *btSearch) emitFallbackPlace(b []byte, d *btDyn, blk, origin uint32, unknown func([]byte) []byte) []byte {
	b = btLocalGet(b, blk)
	b = append(b, 0x04, 0x7F) // if blk (result i32)
	b = btLocalGet(b, blk)
	b = c.load32(b, btSearchMemo)
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, d.memoBase) // tee memoBase
	b = append(b, 0x04, 0x7F)              // if memo (result i32)
	// cap >= (len + 1) × rowBytes, in i64
	b = btLocalGet(b, blk)
	b = c.load32(b, btSearchMemoCap)
	b = append(b, 0xAD, 0x20, localLen, 0xAD, 0x42, 0x01, 0x7C, 0x42)
	b = utils.AppendSLEB128_64(b, int64(d.rowBytes))
	b = append(b, 0x7E, 0x5A) // i64.mul; i64.ge_u
	b = append(b, 0x05, 0x41, 0x00, 0x0B)
	b = append(b, 0x05, 0x41, 0x00, 0x0B)
	b = append(b, 0x04, 0x7F) // if the search's memo serves (result i32)
	b = append(b, 0x41, 0x00, 0x21)
	b = utils.AppendULEB128(b, origin)
	// memoEnd = cleared = memo + (len + 1) × rowBytes
	b = btLocalGet(b, d.memoBase)
	b = append(b, 0x20, localLen, 0x41, 0x01, 0x6A, 0x41)
	b = utils.AppendSLEB128(b, d.rowBytes)
	b = append(b, 0x6C, 0x6A, 0x22)
	b = utils.AppendULEB128(b, d.memoEnd)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.cleared)
	// The frame stack: this call's, at the scratch base.
	b = emitBTScratchBase(b, d, d.stackBase)
	b = btLocalGet(b, d.stackBase)
	b = append(b, 0x41, 0x03, 0x6A, 0x41, 0x7C, 0x71)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.stackBase)
	b = emitBTEnsureStack(b, d, unknown)
	b = append(b, 0x41, 0x01)
	return append(b, 0x05, 0x41, 0x00, 0x0B)
}

// emitFallbackMatched clears the memo rows [attemptStart, pos] before a match
// is returned: the marks on the path of the match are not failures.
func (c *btSearch) emitFallbackMatched(b []byte, d *btDyn, blk, attemptStart, origin, tmp uint32) []byte {
	b = btLocalGet(b, blk)
	b = append(b, 0x04, 0x40)
	// tmp = min(memoBase + (pos - origin + 1) * rowBytes, cleared)
	b = btLocalGet(b, d.memoBase)
	b = append(b, 0x20, localPos)
	b = btLocalGet(b, origin)
	b = append(b, 0x6B, 0x41, 0x01, 0x6A)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, d.rowBytes)
	b = append(b, 0x6C, 0x6A)
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, tmp)
	b = btLocalGet(b, d.cleared)
	b = btLocalGet(b, tmp)
	b = btLocalGet(b, d.cleared)
	b = append(b, 0x49, 0x1B) // lt_u; select
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, tmp)
	start := func(b []byte) []byte {
		b = btLocalGet(b, d.memoBase)
		b = btLocalGet(b, attemptStart)
		b = btLocalGet(b, origin)
		b = append(b, 0x6B)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, d.rowBytes)
		return append(b, 0x6C, 0x6A)
	}
	b = btLocalGet(b, tmp)
	b = start(b)
	b = append(b, 0x4B)       // end > start
	b = append(b, 0x04, 0x40) // if
	b = start(b)              // dest
	b = append(b, 0x41, 0x00) // value
	b = btLocalGet(b, tmp)
	b = start(b)
	b = append(b, 0x6B) // size
	b = appendTableMemoryFill(b, d.memIdx)
	b = append(b, 0x0B)
	return append(b, 0x0B)
}

// emitCapEntry: the ordinary capture body goes straight to the fallback once
// a capture call of this search has tripped.
func (c *btSearch) emitCapEntry(b []byte, callOffs *[]int) []byte {
	b = c.blk(b)
	b = append(b, 0x04, 0x40)
	b = c.blk(b)
	b = c.load32(b, btSearchCapSt)
	b = append(b, 0x41, 0x02, 0x46)
	b = append(b, 0x04, 0x40)
	b = emitBTFallbackCall(b, 3, callOffs)
	b = append(b, 0x0B)
	return append(b, 0x0B)
}

// emitCapTripped marks the search's capture side tripped.
func (c *btSearch) emitCapTripped(b []byte) []byte {
	b = c.blk(b)
	b = append(b, 0x04, 0x40)
	b = c.blk(b)
	b = append(b, 0x41, 0x02)
	b = c.store32(b, btSearchCapSt)
	return append(b, 0x0B)
}

// btMemoBytes is the memo bytes per text position a search of bt keeps once it
// trips: one row of ⌈N/8⌉ bytes.
func btMemoBytes(bt *backtrack) int { return (len(bt.prog.Inst) + 7) / 8 }
