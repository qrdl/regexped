package compile

import (
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ── Per-search notes: linear drives for the DFA finds ──────────────────────
//
// A DRIVE — a stub calling `find` until the input is exhausted — reads the
// same bytes again when a call walks past the match it reports: `a*b|a` over
// `a`×n reads to the end of the input on every call, O(n²) for the drive
// although every call is linear. The switch counter and the shape detectors
// bound FAILED attempts inside one call; nothing bounded what the NEXT call
// reads again.
//
// The fix keeps notes for one search, in a block the stub owns (see
// internal/abi's "per-search block"): a walk that ends without an accept past
// its last accept has proved, for every (state, position) it visited after that
// accept, "no match lies ahead of here". Those facts are about the TEXT, not
// the call, so a later call reaching a noted (state, position) stops there
// and answers what the walk would have answered. Each point is noted once and
// hit once: a drive costs O(rows × n).
//
// Only a search that has gone bad pays for the notes. Every pattern whose find
// automaton has a CYCLE state (below) carries two copies of its find:
//
//   - the ORDINARY copy — today's body plus a waste counter in the block:
//     bytes read past each reported match, and failed reads over
//     switchShortWalk bytes. Where waste is added, it is judged against
//     abi.SearchRuleMult × progress + abi.SearchRuleSlack; over it, the search
//     ARMS. With no block handed over, the counter is skipped entirely.
//   - the MARKED copy — the same body testing the notes after every byte of
//     a state that has a row, and writing them by re-walking a wasted tail.
//     It serves every call of an armed search once the stub has allocated the
//     notes.
//
// Measured on the project's real patterns before this was built: no cost on
// 85 of 151 drives (no cycle state, so no notes code at all), median +0.1% on
// the rest, worst +5.2%; bad drives 250-380 fuel/byte, linear.

// dfaCycleStates reports, per DFA state, whether it is a NON-ACCEPTING state on
// a cycle of non-accepting states. Those are the only states an unboundedly
// long walk can sit in without accepting, so they are the only ones worth a
// row: a state on no such cycle is left within a bounded number of bytes, and
// a note missed there costs only speed.
func dfaCycleStates(t *dfaTable) []bool {
	n := t.numStates
	acc := func(s int) bool { return t.midAcceptStates[s] != 0 }
	succ := make([][]int, n)
	for s := 0; s < n; s++ {
		if acc(s) {
			continue
		}
		seen := map[int]bool{}
		for c := 0; c < 256; c++ {
			d := t.transitions[s*256+c]
			if d >= 0 && !acc(d) && !seen[d] {
				seen[d] = true
				succ[s] = append(succ[s], d)
			}
		}
	}
	// Tarjan's strongly connected components; a component is a cycle when it
	// has two states or one state with a self-loop.
	index := make([]int, n)
	low := make([]int, n)
	on := make([]bool, n)
	for i := range index {
		index[i] = -1
	}
	var stack []int
	next := 0
	out := make([]bool, n)
	var visit func(v int)
	visit = func(v int) {
		index[v], low[v] = next, next
		next++
		stack = append(stack, v)
		on[v] = true
		for _, w := range succ[v] {
			if index[w] < 0 {
				visit(w)
				low[v] = min(low[v], low[w])
			} else if on[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] != index[v] {
			return
		}
		var comp []int
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			on[w] = false
			comp = append(comp, w)
			if w == v {
				break
			}
		}
		cyc := len(comp) > 1
		for _, w := range succ[v] {
			cyc = cyc || w == v
		}
		if cyc {
			for _, w := range comp {
				out[w] = true
			}
		}
	}
	for s := 0; s < n; s++ {
		if !acc(s) && index[s] < 0 {
			visit(s)
		}
	}
	return out
}

// notesRows is which states of ONE automaton have a row in a search's notes,
// and where in a position's record those rows live.
type notesRows struct {
	// tabOff: two tables in table memory, numWASM bytes each — the row's bit
	// (1 << (row & 7), 0 for a state with no row), then its byte (row >> 3).
	tabOff  int32
	mask    []byte
	off     []byte
	rows    int
	bytes   int32 // ⌈rows/8⌉, this automaton's bytes per position
	numWASM int
	// at is this automaton's first byte within a position's record; stride is
	// the record's size — the pattern's notes bytes per position.
	at, stride int32
	// cond: an accept may depend on the NEXT byte (\b, (?m:$)), so the state
	// at a walk's last accept is not "no accept from here" even though it has
	// a row.
	cond bool
}

// maxNotesBytesPerPos caps one automaton's record: a row index must fit the
// byte-offset table's u8, and past 2,040 rows the notes are no longer "a few
// bits per input byte". A pattern's find with such an automaton is routed to
// the Backtracking find (notesRowsOverflow); anywhere else the automaton keeps
// its find without notes.
const maxNotesBytesPerPos = 255

// newNotesRows builds the row tables for t, placing them at l.tableEnd, or
// returns nil when t has no cycle state (the pattern keeps today's find,
// byte for byte).
func newNotesRows(t *dfaTable, l *dfaLayout) *notesRows {
	r := newNotesRowsAt(t, l.numWASM, l.tableEnd)
	if r != nil {
		l.tableEnd += r.tableBytes()
	}
	return r
}

// tableBytes is the size of the row tables in table memory.
func (r *notesRows) tableBytes() int64 { return int64(2 * r.numWASM) }

// newNotesRowsAt is newNotesRows with the tables placed at off, for an
// automaton whose layout's end is not where the pattern's tables end (the
// literal-anchored bodies lay theirs out after it). The caller reserves
// tableBytes() there.
func newNotesRowsAt(t *dfaTable, numWASM int, off int64) *notesRows {
	cyc := dfaCycleStates(t)
	r := &notesRows{numWASM: numWASM, cond: t.hasWordBoundary || t.hasNewlineBoundary}
	r.mask = make([]byte, numWASM)
	r.off = make([]byte, numWASM)
	for s := 0; s < t.numStates; s++ {
		if !cyc[s] {
			continue
		}
		r.mask[s+1] = 1 << uint(r.rows&7) // WASM state = DFA state + 1
		r.off[s+1] = byte(r.rows >> 3)
		r.rows++
	}
	if r.rows == 0 {
		return nil
	}
	r.bytes = int32((r.rows + 7) / 8)
	if r.bytes > maxNotesBytesPerPos {
		return nil
	}
	r.tabOff = int32(off)
	r.stride = r.bytes
	return r
}

// countCycleStates is how many rows a find automaton's notes would need.
func countCycleStates(t *dfaTable) int {
	n := 0
	for _, c := range dfaCycleStates(t) {
		if c {
			n++
		}
	}
	return n
}

// notesRowsOverflow reports a find automaton with more cycle states than a
// search's notes carry rows for: newNotesRows would refuse it, and the find
// would keep no notes at all.
func notesRowsOverflow(t *dfaTable) bool {
	return countCycleStates(t) > maxNotesBytesPerPos*8
}

// dataSegment is the two tables as one active data segment.
func (r *notesRows) dataSegment() []byte {
	data := append(append([]byte(nil), r.mask...), r.off...)
	return appendDataSegment(nil, r.tabOff, data)
}

// ── The search block, as the module sees it ─────────────────────────────────

// Search returns the module's search global, allocating it on the first call:
// the address of the current search's block, 0 for none. One per module —
// the host hands the block over before every call that uses it.
func (g *moduleGlobals) Search() uint32 {
	if g.searchP1 == 0 {
		g.searchP1 = g.Alloc() + 1
	}
	return g.searchP1 - 1
}

// searchGlobal reports the search global, if some body allocated it.
func (g *moduleGlobals) searchGlobal() (uint32, bool) {
	if g == nil || g.searchP1 == 0 {
		return 0, false
	}
	return g.searchP1 - 1, true
}

// Block field offsets as single-byte memargs. Every one is below 128, which
// is what lets the emitters write them as a raw byte.
const (
	blkWasted   = byte(abi.SearchWastedOff)
	blkFirst    = byte(abi.SearchFirstOff)
	blkArmed    = byte(abi.SearchArmedOff)
	blkResume   = byte(abi.SearchResumeOff)
	blkPtr      = byte(abi.SearchPtrOff)
	blkLen      = byte(abi.SearchLenOff)
	blkNotes    = byte(abi.SearchNotesOff)
	blkHigh     = byte(abi.SearchHighOff)
	blkSeen     = byte(abi.SearchSeenOff)
	blkFar      = byte(abi.SearchFarOff)
	blkNotesCap = byte(abi.SearchNotesCapOff)
)

// ── Emission ────────────────────────────────────────────────────────────────

// notesCopy selects which of a pattern's two find copies is being emitted.
type notesCopy uint8

const (
	notesOrdinary notesCopy = iota + 1 // today's body + the waste counter
	notesMarked                        // the notes read and written after every byte
)

// notesCtx is one find body's view of the notes while it is being emitted.
// A nil *notesCtx emits nothing: every hook is a no-op on it, which is what
// leaves a pattern without cycle states byte-identical to today.
type notesCtx struct {
	rows *notesRows
	// l is the automaton's layout: the recording re-walk transitions through
	// its tables.
	l           *dfaLayout
	copy        notesCopy
	tableMemIdx int
	search      uint32 // the search global
	// sw is the switch counter of the body, if it has one: a stop at a note
	// charges it, since notes make failed walks shorter than the counter's
	// switchShortWalk and would otherwise starve it.
	sw func() []switchCounter
	// base is the first of notesNumLocals i32 locals the body declares.
	base byte
	// callOff is where the call to the OTHER copy left a padded immediate:
	// the ordinary copy's handoff to the marked one, the marked copy's handback
	// on a text it does not recognise. -1 until emitted.
	callOff int
	// The emitting body's own locals: the input, the walk's state and
	// position, the attempt's start (the general body only) and the last
	// accept. bias, unless noBias, holds absolute − local position, for a
	// walker handed a slice of the input.
	ptr, ln, st, pos, start, last byte
	bias                          byte
}

// noBias marks a body whose positions are absolute.
const noBias = 0xFF

// notesNumLocals is the size of the i32 locals group a body with notes
// declares, laid out by the accessors below.
const notesNumLocals = 11

func (c *notesCtx) lAcc() byte   { return c.base }      // state at the walk's last accept
func (c *notesCtx) lStart() byte { return c.base + 1 }  // position the walk started from
func (c *notesCtx) lS() byte     { return c.base + 2 }  // recording: state
func (c *notesCtx) lP() byte     { return c.base + 3 }  // recording: position
func (c *notesCtx) lEnd() byte   { return c.base + 4 }  // recording: last position to note
func (c *notesCtx) lM() byte     { return c.base + 5 }  // a row's bit
func (c *notesCtx) lA() byte     { return c.base + 6 }  // a note's address
func (c *notesCtx) lV() byte     { return c.base + 7 }  // a note byte
func (c *notesCtx) lB() byte     { return c.base + 8 }  // transition scratch
func (c *notesCtx) lBlk() byte   { return c.base + 9 }  // the search block
func (c *notesCtx) lNotes() byte { return c.base + 10 } // this search's notes

func (c *notesCtx) marked() bool   { return c != nil && c.copy == notesMarked }
func (c *notesCtx) ordinary() bool { return c != nil && c.copy == notesOrdinary }

// The general find body's fixed locals (buildFindBody's layout).
const (
	nPtr   = 0x00
	nLen   = 0x01
	nState = 0x02
	nPos   = 0x03
	nStart = 0x04 // attempt_start
	nLast  = 0x05 // last_accept
)

// newBodyNotes is the notes context of one copy of the general find body.
func newBodyNotes(rows *notesRows, l *dfaLayout, copy notesCopy, tableMemIdx int, search uint32) *notesCtx {
	return &notesCtx{rows: rows, l: l, copy: copy, tableMemIdx: tableMemIdx, search: search, callOff: -1,
		ptr: nPtr, ln: nLen, st: nState, pos: nPos, start: nStart, last: nLast, bias: noBias}
}

// pushAbs pushes the ABSOLUTE position local + add.
func (c *notesCtx) pushAbs(b []byte, local byte, add int32) []byte {
	b = append(b, 0x20, local)
	if add != 0 {
		b = nConst(b, add)
		b = append(b, 0x6A)
	}
	if c.bias != noBias {
		b = append(b, 0x20, c.bias, 0x6A)
	}
	return b
}

func nConst(b []byte, v int32) []byte {
	b = append(b, 0x41)
	return utils.AppendSLEB128(b, v)
}

func (c *notesCtx) gget(b []byte) []byte {
	b = append(b, 0x23)
	return utils.AppendULEB128(b, c.search)
}

// ld pushes the i32 block field at off.
func (c *notesCtx) ld(b []byte, off byte) []byte {
	return append(b, 0x20, c.lBlk(), 0x28, 0x02, off)
}

func (c *notesCtx) stConst(b []byte, off byte, v int32) []byte {
	b = append(b, 0x20, c.lBlk())
	b = nConst(b, v)
	return append(b, 0x36, 0x02, off)
}

func (c *notesCtx) stLocal(b []byte, off byte, local byte) []byte {
	return append(b, 0x20, c.lBlk(), 0x20, local, 0x36, 0x02, off)
}

// emitMask pushes the row bit of the state in stateLocal (0: no row).
func (c *notesCtx) emitMask(b []byte, stateLocal byte) []byte {
	b = nConst(b, c.rows.tabOff)
	b = append(b, 0x20, stateLocal, 0x6A)
	return appendTableLoad8u(b, c.tableMemIdx)
}

// emitNoteAddr pushes the address of the note byte for (the state in
// stateLocal, the position in posLocal + posAdd).
func (c *notesCtx) emitNoteAddr(b []byte, posLocal byte, posAdd int32, stateLocal byte) []byte {
	r := c.rows
	b = append(b, 0x20, c.lNotes())
	if add := posAdd*r.stride + r.at; add != 0 {
		b = nConst(b, add)
		b = append(b, 0x6A)
	}
	b = c.pushAbs(b, posLocal, 0)
	if r.stride != 1 {
		b = nConst(b, r.stride)
		b = append(b, 0x6C) // i32.mul
	}
	b = append(b, 0x6A)
	if r.bytes == 1 {
		return b
	}
	b = nConst(b, r.tabOff+int32(r.numWASM))
	b = append(b, 0x20, stateLocal, 0x6A)
	b = appendTableLoad8u(b, c.tableMemIdx)
	return append(b, 0x6A)
}

// emitPrologue runs once per attempt, after state, pos and last_accept are set
// (after any prefix or chain the prologue consumed): the walk's own start.
func (c *notesCtx) emitPrologue(b []byte) []byte {
	if !c.marked() {
		return b
	}
	b = append(b, 0x20, c.pos, 0x21, c.lStart())
	return append(b, 0x20, c.st, 0x21, c.lAcc())
}

// emitAcceptHook goes wherever last_accept is set during a walk: the state in
// stateLocal is the one AT last_accept.
func (c *notesCtx) emitAcceptHook(b []byte, stateLocal byte) []byte {
	if !c.marked() {
		return b
	}
	return append(b, 0x20, stateLocal, 0x21, c.lAcc())
}

// emitRecord notes the walk's wasted tail: every (state, position) from its
// last accept — or its start, when it never accepted — to lEnd. It re-walks
// the tail (the second pass costs what the tail cost) because noting during
// the first pass would be wrong: a later accept in the same walk makes the
// earlier notes false, and a note cannot be taken back.
func (c *notesCtx) emitRecord(b []byte) []byte {
	if !c.marked() {
		return b
	}
	// high = max(high, end + 1): what a clear has to cover.
	b = c.pushAbs(b, c.lEnd(), 1)
	b = append(b, 0x22, c.lB()) // tee
	b = c.ld(b, blkHigh)
	b = append(b, 0x4A, 0x04, 0x40) // gt_s; if
	b = c.stLocal(b, blkHigh, c.lB())
	b = append(b, 0x0B)
	// p = last_accept >= 0 ? last_accept : start; s = state there
	b = append(b, 0x20, c.last, 0x20, c.lStart(), 0x20, c.last)
	b = nConst(b, 0)
	b = append(b, 0x4E, 0x1B, 0x21, c.lP()) // ge_s; select
	b = append(b, 0x20, c.lAcc(), 0x21, c.lS())
	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x20, c.lP(), 0x20, c.lEnd(), 0x4A, 0x0D, 0x00)
	b = append(b, 0x03, 0x40) // loop $r
	doneDepth := byte(3)      // if(row) → if(noted) … : if, if, loop, block
	if c.rows.cond {
		// The state AT the last accept accepted there on a condition; only the
		// positions after it are "no accept from here".
		b = append(b, 0x02, 0x40)
		b = append(b, 0x20, c.lP(), 0x20, c.last, 0x46, 0x0D, 0x00)
		doneDepth++
	}
	b = c.emitMask(b, c.lS())
	b = append(b, 0x22, c.lM(), 0x04, 0x40) // tee; if (the state has a row)
	b = c.emitNoteAddr(b, c.lP(), 0, c.lS())
	b = append(b, 0x22, c.lA(), 0x2D, 0x00, 0x00) // tee; load8_u
	b = append(b, 0x22, c.lV(), 0x20, c.lM(), 0x71)
	b = append(b, 0x0D, doneDepth-1) // already noted: so is everything after it
	b = append(b, 0x20, c.lA(), 0x20, c.lV(), 0x20, c.lM(), 0x72, 0x3A, 0x00, 0x00)
	b = append(b, 0x0B) // end if
	if c.rows.cond {
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, c.lP(), 0x20, c.lEnd(), 0x46, 0x0D, 0x01) // p == end: done
	b = emitWalkerTransition(b, c.l, c.lS(), c.ptr, c.lP(), c.lB(), c.tableMemIdx)
	b = append(b, 0x20, c.lP())
	b = nConst(b, 1)
	b = append(b, 0x6A, 0x21, c.lP(), 0x0C, 0x00)
	return append(b, 0x0B, 0x0B) // loop, block
}

// emitStop leaves a walk that reached a noted point: note its own tail, then
// return its last accept, or move on to the next start. extra is how many
// constructs deeper than the dead handler's single `if` it sits; endAdd puts
// the tail's end at pos + endAdd.
func (c *notesCtx) emitStop(b []byte, extra byte, endAdd int32) []byte {
	b = append(b, 0x20, nPos)
	if endAdd != 0 {
		b = nConst(b, endAdd)
		b = append(b, 0x6A)
	}
	b = append(b, 0x21, c.lEnd())
	b = c.emitRecord(b)
	b = append(b, 0x20, nLast)
	b = nConst(b, 0)
	b = append(b, 0x4E, 0x0D, 2+extra) // ge_s → $found
	if c.sw != nil {
		if sw := c.sw(); len(sw) > 0 {
			// A stop with no accept proves the call is re-reading failed
			// ground: charge it to the switch counter as a long walk, so the
			// counter still hands the rest of the call to the start-anywhere
			// find. Without this, notes cut failed walks below the
			// switchShortWalk bytes the counter ignores and starve it.
			w := sw[0].walkedLocal
			b = emitFindSwitchBudget(b, w, nStart, sw[0].n, true)
			b = emitAddWalk(b,
				func(b []byte) []byte { return append(b, 0x20, w) },
				func(b []byte) []byte { return append(b, 0x21, w) },
				func(b []byte) []byte { return nConst(b, 2*switchShortWalk) })
		}
	}
	b = append(b, 0x20, nStart)
	b = nConst(b, 1)
	b = append(b, 0x6A, 0x21, nStart)
	return append(b, 0x0C, 3+extra) // → $outer
}

// emitArrivalTest goes right after the dead check: state is the state at
// pos + 1. A noted (state, pos + 1) stops the walk.
func (c *notesCtx) emitArrivalTest(b []byte) []byte {
	if !c.marked() {
		return b
	}
	b = c.emitMask(b, nState)
	b = append(b, 0x22, c.lM(), 0x04, 0x40) // tee; if (row)
	b = c.emitNoteAddr(b, nPos, 1, nState)
	b = append(b, 0x2D, 0x00, 0x00, 0x20, c.lM(), 0x71, 0x04, 0x40) // load8_u; and; if
	b = c.emitStop(b, 1, 0)
	return append(b, 0x0B, 0x0B)
}

// emitDeadHook goes at the top of the dead handler: the byte at pos killed the
// walk, so its tail ends at pos.
func (c *notesCtx) emitDeadHook(b []byte) []byte {
	if !c.marked() {
		return b
	}
	b = append(b, 0x20, nPos, 0x21, c.lEnd())
	return c.emitRecord(b)
}

// emitEofHook goes after the end-of-input accept update: pos == len, and the
// last position a note can describe is len − 1.
func (c *notesCtx) emitEofHook(b []byte) []byte {
	if !c.marked() {
		return b
	}
	b = append(b, 0x20, nPos)
	b = nConst(b, 1)
	b = append(b, 0x6B, 0x21, c.lEnd())
	return c.emitRecord(b)
}

// addWasted adds the i32 delta pushes to the block's waste counter. The caller
// has established that there is a block.
func (c *notesCtx) addWasted(b []byte, delta func([]byte) []byte) []byte {
	b = append(b, 0x20, c.lBlk(), 0x20, c.lBlk(), 0x29, 0x03, blkWasted) // i64.load
	b = delta(b)
	return append(b, 0xAD, 0x7C, 0x37, 0x03, blkWasted) // extend_u; add; i64.store
}

// emitJudge arms the search right where waste was added. first is `from` + 1
// of the first call that wasted anything; the allowance is
// SearchRuleMult × (this call's from − that one's) + SearchRuleSlack. Judging
// here rather than at every call's entry is what keeps call-dense drives
// cheap: the entry then only reads the verdict.
func (c *notesCtx) emitJudge(b []byte) []byte {
	b = c.ld(b, blkFirst)
	b = append(b, 0x45, 0x04, 0x40) // eqz; if
	b = append(b, 0x20, c.lBlk(), 0x23)
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = nConst(b, 1)
	b = append(b, 0x6A, 0x36, 0x02, blkFirst, 0x0B)
	b = append(b, 0x20, c.lBlk(), 0x29, 0x03, blkWasted) // i64.load wasted
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = c.ld(b, blkFirst)
	b = append(b, 0x6B) // from - first
	b = nConst(b, 1)
	b = append(b, 0x6A, 0xAD, 0x42) // + 1; extend_u; i64.const
	b = utils.AppendSLEB128_64(b, abi.SearchRuleMult)
	b = append(b, 0x7E, 0x42) // i64.mul; i64.const
	b = utils.AppendSLEB128_64(b, abi.SearchRuleSlack)
	b = append(b, 0x7C, 0x56, 0x04, 0x40) // i64.add; i64.gt_u; if
	b = c.stConst(b, blkArmed, 1)
	b = c.stConst(b, blkSeen, 0)
	return append(b, 0x0B)
}

// emitReturnHook goes where a match is about to be returned.
func (c *notesCtx) emitReturnHook(b []byte) []byte {
	switch {
	case c.marked():
		// resume = max(match end, start + 1): where the host calls next.
		b = append(b, 0x20, c.lBlk(), 0x20, nLast, 0x20, nStart)
		b = nConst(b, 1)
		b = append(b, 0x6A, 0x20, nLast, 0x20, nStart)
		b = nConst(b, 1)
		b = append(b, 0x6A, 0x4A, 0x1B, 0x36, 0x02, blkResume) // gt_s; select; store
	case c.ordinary():
		// Bytes read past the match are waste. The cheap test first: most
		// calls read nothing past their match, and the block test then costs
		// nothing on them.
		b = append(b, 0x20, nPos, 0x20, nLast, 0x4A, 0x04, 0x40)
		b = append(b, 0x20, c.lBlk(), 0x04, 0x40) // if (block)
		b = c.addWasted(b, func(b []byte) []byte {
			return append(b, 0x20, nPos, 0x20, nLast, 0x6B)
		})
		b = c.emitJudge(b)
		b = append(b, 0x0B, 0x0B)
	}
	return b
}

// emitFailHook goes where an attempt has been proved to have no match. Of a
// failed read over switchShortWalk bytes, only the part BELOW the farthest
// position an earlier failed walk of this search read is waste — that part is
// read twice; the rest is ground no walk has covered. Charging the whole walk
// armed searches whose walks never overlap: `[a-z]+@` over
// `(a×40 ␠)×2000 b@ (a×40 ␠)×2000 c@` armed in its first call and paid the
// marked copy (+22.7%) for the rest of the search, re-reading nothing. The
// literal-anchored bodies use the same idea through lFar (emitFarCharge).
//
// waste += max(0, min(pos, far) − start); far = max(far, pos). lB is free
// here: the walk is over and the recording re-walk is not running.
func (c *notesCtx) emitFailHook(b []byte) []byte {
	if !c.ordinary() {
		return b
	}
	b = append(b, 0x20, nPos, 0x20, nStart, 0x6B)
	b = nConst(b, switchShortWalk)
	b = append(b, 0x4A, 0x04, 0x40)           // gt_s; if — the cheap test first
	b = append(b, 0x20, c.lBlk(), 0x04, 0x40) // if (block)
	// min(pos, far) − start, signed: negative when the walk began past far.
	b = append(b, 0x20, nPos)
	b = c.ld(b, blkFar)
	b = append(b, 0x20, nPos)
	b = c.ld(b, blkFar)
	b = append(b, 0x49, 0x1B) // lt_u; select: min(pos, far)
	b = append(b, 0x20, nStart, 0x6B, 0x22, c.lB())
	b = nConst(b, 0)
	b = append(b, 0x4A, 0x04, 0x40) // gt_s; if — something was read twice
	b = c.addWasted(b, func(b []byte) []byte { return append(b, 0x20, c.lB()) })
	b = c.emitJudge(b)
	b = append(b, 0x0B)
	// far = max(far, pos)
	b = append(b, 0x20, nPos)
	b = c.ld(b, blkFar)
	b = append(b, 0x4B, 0x04, 0x40) // gt_u; if
	b = c.stLocal(b, blkFar, nPos)
	return append(b, 0x0B, 0x0B, 0x0B)
}

// emitEntry goes right after the find-from seed.
//
// The ordinary copy loads the block and, when the search is armed and its
// notes cover this text, hands the call to the marked copy.
//
// The marked copy checks that the call continues the text its notes describe
// — same ptr and len, and `from` where its previous call said to resume — and
// otherwise drops the notes and the search's state and answers with the
// ordinary copy. Within one search that never happens; it catches a block
// reused for another text, which is the caller's mistake, where the harm
// would be wrong answers rather than slowness.
func (c *notesCtx) emitEntry(b []byte) []byte {
	switch {
	case c.ordinary():
		b = c.gget(b)
		b = append(b, 0x22, c.lBlk(), 0x04, 0x40) // tee; if (block)
		b = c.ld(b, blkArmed)
		b = append(b, 0x04, 0x40) // if (armed)
		b = c.ld(b, blkNotes)
		b = append(b, 0x04, 0x40) // if (notes)
		// notes_cap >= (len + 1) × stride, unsigned and in i64 so no text
		// length can wrap it.
		b = c.ld(b, blkNotesCap)
		b = append(b, 0xAD, 0x20, nLen, 0xAD, 0x42, 0x01, 0x7C, 0x42) // cap64; len64 + 1; i64.const
		b = utils.AppendSLEB128_64(b, int64(c.rows.stride))
		b = append(b, 0x7E, 0x5A, 0x04, 0x40) // i64.mul; i64.ge_u; if
		b = append(b, 0x20, nPtr, 0x20, nLen, 0x10)
		c.callOff = len(b)
		b = utils.AppendPaddedULEB128(b, 0, twinCallImmWidth)
		return append(b, 0x0F, 0x0B, 0x0B, 0x0B, 0x0B) // return; end ×4
	case c.marked():
		b = c.gget(b)
		b = append(b, 0x21, c.lBlk())
		b = c.ld(b, blkNotes)
		b = append(b, 0x21, c.lNotes())
		b = c.emitTextCheck(b,
			func(b []byte) []byte { return append(b, 0x20, nPtr) },
			func(b []byte) []byte { return append(b, 0x20, nLen) },
			func(b []byte) []byte { return append(b, 0x20, nStart) })
		b = append(b, 0x20, nPtr, 0x20, nLen, 0x10)
		c.callOff = len(b)
		b = utils.AppendPaddedULEB128(b, 0, twinCallImmWidth)
		return append(b, 0x0F, 0x0B) // return; end $ok
	}
	return b
}

// emitTextCheck opens `block $ok` and checks that a marked call continues the
// text its notes describe. The first marked call of an arming records the text
// — ptr and length — clearing what an earlier arming left, and branches to $ok;
// a later one branches to $ok when ptr, length and, when resume is non-nil, the
// call's start position (against the resume point the last marked call handed
// out) all match. Falling through means ANOTHER text, the caller's mistake: the
// notes and the search's state are dropped, and the caller emits what runs
// instead and closes the block. Shared by the general body's marked copy and
// the walkers, so the two cannot drift.
func (c *notesCtx) emitTextCheck(b []byte, ptr, length, resume func([]byte) []byte) []byte {
	b = append(b, 0x02, 0x40) // block $ok
	b = c.ld(b, blkSeen)
	b = append(b, 0x45, 0x04, 0x40) // eqz; if: the first marked call of this arming
	b = c.ld(b, blkHigh)
	b = append(b, 0x04, 0x40)
	b = c.emitClear(b)
	b = append(b, 0x0B)
	b = append(b, 0x20, c.lBlk())
	b = ptr(b)
	b = append(b, 0x36, 0x02, blkPtr)
	b = append(b, 0x20, c.lBlk())
	b = length(b)
	b = append(b, 0x36, 0x02, blkLen)
	b = c.stConst(b, blkSeen, 1)
	b = append(b, 0x0C, 0x01, 0x0B) // br $ok; end if
	b = ptr(b)
	b = c.ld(b, blkPtr)
	b = append(b, 0x46)
	b = length(b)
	b = c.ld(b, blkLen)
	b = append(b, 0x46, 0x71)
	if resume != nil {
		b = resume(b)
		b = c.ld(b, blkResume)
		b = append(b, 0x46, 0x71)
	}
	b = append(b, 0x0D, 0x00) // same text: br_if $ok
	// Another text: drop the notes and the search's state.
	b = c.emitClear(b)
	b = append(b, 0x20, c.lBlk(), 0x42, 0x00, 0x37, 0x03, blkWasted)
	b = c.stConst(b, blkFirst, 0)
	b = c.stConst(b, blkArmed, 0)
	b = c.stConst(b, blkSeen, 0)
	return c.stConst(b, blkFar, 0)
}

// emitClear zeroes the notes up to the high-water position — and never past
// notes_cap: a block reused for a SHORTER text with a fresh, smaller notes
// buffer still carries the old text's high, and `high × stride` would then
// write past the buffer the caller sized (host memory in an embedded build).
// lB is free here: every caller clears at entry, before any transition.
func (c *notesCtx) emitClear(b []byte) []byte {
	b = append(b, 0x20, c.lNotes())
	b = nConst(b, 0)
	b = c.ld(b, blkHigh)
	if c.rows.stride != 1 {
		b = nConst(b, c.rows.stride)
		b = append(b, 0x6C)
	}
	b = append(b, 0x22, c.lB()) // tee: high × stride
	b = c.ld(b, blkNotesCap)
	b = append(b, 0x20, c.lB())
	b = c.ld(b, blkNotesCap)
	b = append(b, 0x49, 0x1B)       // lt_u; select: min(high × stride, cap)
	b = append(b, 0xFC, 0x0B, 0x00) // memory.fill (the input's memory)
	return c.stConst(b, blkHigh, 0)
}

// notesPlan is a pattern's notes: what its bodies need to emit them, and the
// per-position size the stub allocates by.
type notesPlan struct {
	find *notesRows // the general find body's automaton, or the literal-anchored body's
	walk *notesRows // the start-anywhere forward pass's
	// alt: each alternation branch's forward verify, nil for a branch with no
	// cycle state; altMarked is the global the dispatcher hands the verifies
	// its verdict through.
	alt       []*notesRows
	altMarked uint32
	// altEnd: where a branch's plain verify stopped, for the dispatcher's lFar.
	altEnd uint32
	search uint32 // the module's search global
}

// altRows is any of the alternation branches' rows — they share the record
// size the dispatcher's entry checks against — or nil for none.
func (n *notesPlan) altRows() *notesRows {
	if n == nil {
		return nil
	}
	for _, r := range n.alt {
		if r != nil {
			return r
		}
	}
	return nil
}

// setStride gives every automaton's rows the pattern's record size.
func (n *notesPlan) setStride() {
	s := n.bytesPerPos()
	for _, r := range append([]*notesRows{n.find, n.walk}, n.alt...) {
		if r != nil {
			r.stride = s
		}
	}
}

// resource is what the pattern's component find/groups resources need to keep
// its notes; the zero value for none.
func (n *notesPlan) resource() resourceNotes {
	if n.bytesPerPos() == 0 {
		return resourceNotes{}
	}
	return resourceNotes{search: n.search, bytesPerPos: n.bytesPerPos()}
}

// patternResource is p's resources' search state: its notes and its
// Backtracking budget and memo (bt_search.go).
func (p *compiledPattern) patternResource() resourceNotes {
	r := p.notes.resource()
	if p.btSearch {
		r.search, r.bt, r.btMemoBytes = p.btSearchG, true, int32(p.btMemoBytes) //nolint:gosec // a small size
	}
	return r
}

// bytesPerPos is the pattern's notes bytes per text position — the constant a
// generated stub allocates by. 0: the pattern has no notes.
func (n *notesPlan) bytesPerPos() int32 {
	if n == nil {
		return 0
	}
	var s int32
	for _, r := range append([]*notesRows{n.find, n.walk}, n.alt...) {
		if r != nil {
			s = max(s, r.at+r.bytes)
		}
	}
	return s
}

// walkNotesReq asks buildStartAnywherePasses for notes in its forward pass:
// placed at byte `at` of a position's record (after the general body's rows,
// which a switch carries too), under the module's search global.
type walkNotesReq struct {
	at      int32
	globals *moduleGlobals // the search global is allocated only if a pass keeps notes
	// checkResume: the pass is the pattern's whole find, not a switch's
	// handover (see emitWalkEntry).
	checkResume bool
}

// emitStoreResume stores where the host resumes after the match (start, end)
// — max(end, start + 1) — in the block, when there is one. start and end are
// pushed by the callbacks; blk is an i32 scratch local.
func emitStoreResume(b []byte, search uint32, blk byte, start, end func([]byte) []byte) []byte {
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, search)
	b = append(b, 0x22, blk, 0x04, 0x40, 0x20, blk) // tee; if (block)
	b = end(b)
	b = start(b)
	b = nConst(b, 1)
	b = append(b, 0x6A)
	b = end(b)
	b = start(b)
	b = append(b, 0x4A, 0x1B, 0x36, 0x02, blkResume) // gt_s; select; store
	return append(b, 0x0B)
}

// ── The search export ───────────────────────────────────────────────────────

// searchExportKind is how a module hands its search global to the host; see
// abi.SearchExport for why it depends on the output kind.
type searchExportKind uint8

const (
	searchExportNone   searchExportKind = iota // no body reads a block, or a component
	searchExportGlobal                         // standalone: the mutable global itself
	searchExportSetter                         // embedded: a (blk i32) → () function
)

// searchExportFor reports the module's search global and how it is exported.
// A component exports neither: its find and groups resources hand the block
// over themselves, and `component new` exposes only what the WIT declares.
func searchExportFor(globals *moduleGlobals, standalone, component bool) (uint32, searchExportKind) {
	g, ok := globals.searchGlobal()
	switch {
	case !ok || component:
		return 0, searchExportNone
	case standalone:
		return g, searchExportGlobal
	}
	return g, searchExportSetter
}

// appendSearchExport appends the export entry: the global, or the setter at
// setterIdx.
func appendSearchExport(es []byte, kind searchExportKind, global uint32, setterIdx int) []byte {
	es = appendString(es, abi.SearchExport)
	if kind == searchExportGlobal {
		es = append(es, 0x03) // global
		return utils.AppendULEB128(es, global)
	}
	es = append(es, 0x00) // function
	return utils.AppendULEB128(es, uint32(setterIdx))
}

// searchSetterBody is the embedded setter: `global.set search, blk`.
func searchSetterBody(global uint32) []byte {
	b := []byte{0x00, 0x20, 0x00, 0x24} // no locals; local.get blk; global.set
	b = utils.AppendULEB128(b, global)
	return append(b, 0x0B)
}

// ── What a stub allocates ───────────────────────────────────────────────────

// SearchSize is what a generated stub needs to know about one export's
// searches.
type SearchSize struct {
	// NotesBytes is the notes' bytes per text position: a search that arms
	// gets (len + 1) × NotesBytes zeroed bytes. 0: the export keeps no notes.
	NotesBytes int
	// BTBudget: the export's Backtracking find or capture body keeps its work
	// budget per search in the block (bt_search.go), so a stub hands one over
	// even when the export keeps no notes. BTMemoBytes is the memo bytes per
	// text position a search that TRIPPED gets — (len + 1) × BTMemoBytes,
	// zeroed, written to bt_memo/bt_memo_cap — in an embedded build too,
	// whose second fallback body reads it from the input's memory.
	BTBudget    bool
	BTMemoBytes int
	// Blocks, for a set's `find` (and its batch entry), is one entry per
	// search block the set takes through the scratch descriptor
	// (abi.FindScratchMagicBlocks), in block order: what that block's search
	// keeps, as a pattern's search would — notes and a Backtracking memo; an
	// entry with neither is a block all the same (a member that keeps
	// nothing, a Backtracking bucket member's budget, the drive state of a
	// counted sparse bucket). nil: the set takes none.
	Blocks []SearchSize
}

// Block reports whether the export's searches use a per-search block at all.
// An export for which it is false never reads the search global, and a stub
// hands nothing over before calling it.
func (s SearchSize) Block() bool { return s.NotesBytes > 0 || s.BTBudget }

// SearchSizes compiles cfg exactly as CompileFile does and returns, for every
// find_func and groups_func name, what a stub allocates for its searches.
// The values are properties of the compiled bodies, so they must come from
// the same compile the module does: a stub that disagrees costs speed (the
// module checks notes_cap) but never memory safety.
func SearchSizes(cfg config.BuildConfig) (map[string]SearchSize, error) {
	m := map[string]SearchSize{}
	if _, _, _, err := compileFileComponentReport(cfg, "", CompileSetOptions{searchSizes: m}, nil, asmOpts{}); err != nil {
		return nil, err
	}
	return m, nil
}

// CompileWithSearchSizes is CompileForced plus SearchSizes for the same
// compile, for harnesses that drive raw exports with a search block.
func CompileWithSearchSizes(patterns []config.RegexEntry, tableBase int64, standalone bool, forceGroupsEngine EngineType, opts CompileOptions) ([]byte, int64, map[string]SearchSize, error) {
	opts.searchSizes = map[string]SearchSize{}
	w, top, err := CompileForced(patterns, tableBase, standalone, forceGroupsEngine, opts)
	return w, top, opts.searchSizes, err
}

// fillSearchSizes records each compiled pattern's SearchSize under its find
// and groups export names. into == nil records nothing.
func fillSearchSizes(patterns []*compiledPattern, into map[string]SearchSize) {
	if into == nil {
		return
	}
	for _, p := range patterns {
		sz := SearchSize{NotesBytes: int(p.notes.bytesPerPos()), BTBudget: p.btSearch, BTMemoBytes: p.btMemoBytes}
		for _, name := range []string{p.findExport, p.groupsExport} {
			if name != "" {
				into[name] = sz
			}
		}
	}
}

// ── Walkers: one walk per call ──────────────────────────────────────────────
//
// The start-anywhere forward pass (and, in time, the literal-anchored
// continuation) is a WALKER: one walk from a start, a last accept, stop at a
// dead byte or the end of the input. It carries both copies inside ONE body:
// a marked walk and a plain one, chosen at entry, with the plain walk's waste
// — the bytes it read past the end it reports — charged after it. A walk that
// never accepted ends the search, so nothing it read can be read again and
// its tail is not noted.

// newWalkNotes is the notes context of a walker whose locals are ptr, ln, st,
// pos and last, and whose positions are local + bias (noBias: absolute).
// base is the first of walkNotesLocals i32 locals it declares.
func newWalkNotes(rows *notesRows, l *dfaLayout, tableMemIdx int, search uint32,
	ptr, ln, st, pos, last, bias, base byte) *notesCtx {
	return &notesCtx{rows: rows, l: l, copy: notesMarked, tableMemIdx: tableMemIdx, search: search, callOff: -1,
		ptr: ptr, ln: ln, st: st, pos: pos, start: 0xFF, last: last, bias: bias, base: base}
}

// walkNotesLocals is the walker's notes locals group: notesNumLocals, then
// lMarked and lFar.
const walkNotesLocals = notesNumLocals + 2

// lMarked is a walker's choice of walk: 1 for the marked one. A local of its
// own, since lM is the walk's scratch.
func (c *notesCtx) lMarked() byte { return c.base + notesNumLocals }

// lFar is the farthest position a call's plain walks read (see emitFarCharge).
func (c *notesCtx) lFar() byte { return c.base + notesNumLocals + 1 }

// emitWalkEntry decides which walk runs, leaving 1 in lMarked for the marked one:
// a block, armed, whose notes cover this text. A marked search that meets a
// different text (ptr or len) drops its notes and state and walks plain.
//
// checkResume also requires `from` to be where the previous call said to
// resume, as the general body's marked copy does. A switch's walker leaves it
// to that copy: the switch hands a call over mid-call, with `from` already
// moved past the attempts it proved matchless.
func (c *notesCtx) emitWalkEntry(b []byte, checkResume bool) []byte {
	b = c.gget(b)
	b = append(b, 0x22, c.lBlk(), 0x04, 0x40) // if (block)
	b = c.ld(b, blkArmed)
	b = append(b, 0x04, 0x40) // if (armed)
	b = c.ld(b, blkNotes)
	b = append(b, 0x22, c.lNotes(), 0x04, 0x40) // if (notes)
	// The whole text: ptr − bias and len + bias for a walker handed a slice.
	absPtr := func(b []byte) []byte {
		b = append(b, 0x20, c.ptr)
		if c.bias != noBias {
			b = append(b, 0x20, c.bias, 0x6B)
		}
		return b
	}
	absLen := func(b []byte) []byte { return c.pushAbs(b, c.ln, 0) }
	b = c.ld(b, blkNotesCap)
	b = append(b, 0xAD)
	b = absLen(b)
	b = append(b, 0xAD, 0x42, 0x01, 0x7C, 0x42)
	b = utils.AppendSLEB128_64(b, int64(c.rows.stride))
	b = append(b, 0x7E, 0x5A, 0x04, 0x40) // cap >= (len + 1) × stride
	var resume func([]byte) []byte
	if checkResume {
		resume = func(b []byte) []byte {
			b = append(b, 0x23)
			return utils.AppendULEB128(b, findFromGlobalIdx)
		}
	}
	b = c.emitTextCheck(b, absPtr, absLen, resume)
	b = append(b, 0x0C, 0x04, 0x0B) // not ours: walk plain (out of the cap `if`); end $ok
	b = nConst(b, 1)
	b = append(b, 0x21, c.lMarked())
	return append(b, 0x0B, 0x0B, 0x0B, 0x0B) // cap, notes, armed, block
}

// emitWalkInit runs after the walk's state, pos and last are set.
func (c *notesCtx) emitWalkInit(b []byte) []byte {
	b = append(b, 0x20, c.st, 0x21, c.lAcc())
	b = append(b, 0x20, c.pos, 0x21, c.lStart())
	b = nConst(b, -2)
	return append(b, 0x21, c.lEnd())
}

// emitWalkArrival goes right after the dead check: st is the state at pos + 1.
// A noted (state, pos + 1) ends the walk as a dead byte would; doneDepth is
// the walk's exit depth from directly inside its loop.
func (c *notesCtx) emitWalkArrival(b []byte, doneDepth byte) []byte {
	return c.emitWalkArrivalStop(b, doneDepth, nil)
}

// emitWalkArrivalStop is emitWalkArrival with onStop emitted on a stop,
// before the walk ends — where a body with a switch counter charges it.
func (c *notesCtx) emitWalkArrivalStop(b []byte, doneDepth byte, onStop func([]byte) []byte) []byte {
	b = c.emitMask(b, c.st)
	b = append(b, 0x22, c.lM(), 0x04, 0x40) // tee; if (row)
	b = c.emitNoteAddr(b, c.pos, 1, c.st)
	b = append(b, 0x2D, 0x00, 0x00, 0x20, c.lM(), 0x71, 0x04, 0x40) // load8_u; and; if
	b = append(b, 0x20, c.pos, 0x21, c.lEnd())
	if onStop != nil {
		b = onStop(b)
	}
	b = append(b, 0x0C, doneDepth+2)
	return append(b, 0x0B, 0x0B)
}

// emitStopCharge is the onStop of a walk inside a body with a switch
// counter: a stop with no accept counts as a failed read of 2 ×
// switchShortWalk bytes (see emitStop), added to the i32 walk local.
func (c *notesCtx) emitStopCharge(walkLocal byte) func([]byte) []byte {
	return func(b []byte) []byte {
		b = append(b, 0x20, c.last, 0x41, 0x00, 0x48, 0x04, 0x40) // last < 0
		b = append(b, 0x20, walkLocal)
		b = nConst(b, 2*switchShortWalk)
		return append(b, 0x6A, 0x21, walkLocal, 0x0B)
	}
}

// emitWalkAfter notes the ended walk's wasted tail, when it accepted.
func (c *notesCtx) emitWalkAfter(b []byte) []byte {
	b = append(b, 0x20, c.last, 0x41, 0x00, 0x4E, 0x04, 0x40) // if last >= 0
	b = c.emitWalkAfterAll(b)
	return append(b, 0x0B)
}

// emitWalkEndDefault gives lEnd, when no stop set it, the last position the
// walk read: the byte that killed it, or len − 1.
func (c *notesCtx) emitWalkEndDefault(b []byte) []byte {
	b = append(b, 0x20, c.lEnd(), 0x41, 0x7E, 0x46, 0x04, 0x40)
	b = append(b, 0x20, c.ln, 0x41, 0x01, 0x6B, 0x20, c.pos)
	b = append(b, 0x20, c.pos, 0x20, c.ln, 0x4E, 0x1B, 0x21, c.lEnd()) // pos >= len ? len - 1 : pos
	return append(b, 0x0B)
}

// emitWalkAfterAll notes the ended walk's tail from its last accept — or from
// its start, when it failed. For a walker whose failed walks do not end the
// search (the literal-anchored bodies try the next candidate), a failed walk's
// ground is what a later one reads again.
func (c *notesCtx) emitWalkAfterAll(b []byte) []byte {
	b = c.emitWalkEndDefault(b)
	return c.emitRecord(b)
}

// emitFarUpdate records the plain walk's end — pos — in lFar when it is the
// farthest the call has read.
func (c *notesCtx) emitFarUpdate(b []byte) []byte {
	return append(b, 0x20, c.pos, 0x20, c.lFar(), 0x4A, 0x04, 0x40, 0x20, c.pos, 0x21, c.lFar(), 0x0B)
}

// emitFarCharge goes where a body that tries several candidates per call
// returns the match ending at endLocal from its plain walks: the bytes its
// walks read past that end are what the next call can read again, and they
// are the waste. Its failed walks are NOT charged one by one, as the general
// body's are: a literal-anchored body walks from each literal occurrence, and
// on text whose candidates fail line by line (`(\w+)\[(\d+)\] .*ERROR` over
// a log) those walks never overlap — charging them armed a search that never
// re-reads a byte (+252% fuel on such a drive). A failed walk that reaches
// past the match is still counted, through lFar.
func (c *notesCtx) emitFarCharge(b []byte, endLocal byte) []byte {
	b = append(b, 0x20, c.lFar(), 0x20, endLocal, 0x4A, 0x04, 0x40) // far > end
	b = c.gget(b)
	b = append(b, 0x22, c.lBlk(), 0x04, 0x40) // tee; if (block)
	b = c.addWasted(b, func(b []byte) []byte { return append(b, 0x20, c.lFar(), 0x20, endLocal, 0x6B) })
	b = c.emitJudge(b)
	return append(b, 0x0B, 0x0B)
}

// emitWalkWaste charges the plain walk's overrun — the bytes it read past the
// end it reports — to the block, and judges it.
func (c *notesCtx) emitWalkWaste(b []byte) []byte {
	b = append(b, 0x20, c.last, 0x41, 0x00, 0x4E, 0x20, c.pos, 0x20, c.last, 0x4A, 0x71, 0x04, 0x40)
	b = append(b, 0x20, c.lBlk(), 0x04, 0x40)
	b = c.addWasted(b, func(b []byte) []byte { return append(b, 0x20, c.pos, 0x20, c.last, 0x6B) })
	b = c.emitJudge(b)
	return append(b, 0x0B, 0x0B)
}

// handoverNotesReq asks a switch's start-anywhere handover for notes, placed
// at byte `at` of a position's record — after the rows today's body keeps.
// nil without the module's global allocator.
func handoverNotesReq(at int32, opts CompileOptions) *walkNotesReq {
	if opts.globals == nil {
		return nil
	}
	return &walkNotesReq{globals: opts.globals, at: at}
}

// resumeGlobal is the search global when the pattern keeps notes — the
// bodies that answer a call without its marked copy store the resume point
// through it — else nil.
func (n *notesPlan) resumeGlobal() *uint32 {
	if n.bytesPerPos() == 0 {
		return nil
	}
	g := n.search
	return &g
}

// buildLitNotes gives the literal-anchored bodies' forward walks per-search
// notes: the single literal's walk over the pattern automaton (table, l), or
// each alternation branch's verify over its own. Their row tables go at
// p.tableEnd, above the bodies' own tables.
func (p *compiledPattern) buildLitNotes(table *dfaTable, l *dfaLayout, opts CompileOptions) {
	n := &notesPlan{}
	var at int32
	add := func(t *dfaTable, numWASM int) *notesRows {
		r := newNotesRowsAt(t, numWASM, p.tableEnd)
		if r == nil {
			return nil
		}
		p.tableEnd += r.tableBytes()
		p.dataBytes = append(p.dataBytes, r.dataSegment()...)
		p.dataSegCount++
		r.at = at
		at += r.bytes
		return r
	}
	if p.litAnchorBackScanBody != nil {
		n.find = add(table, l.numWASM)
	} else {
		for i := range p.altLitAnchorBranches {
			br := &p.altLitAnchorBranches[i]
			n.alt = append(n.alt, add(br.fwdTable, br.fwdL.numWASM))
		}
	}
	if n.bytesPerPos() == 0 {
		return
	}
	n.search = opts.globals.Search()
	if n.alt != nil {
		n.altMarked = opts.globals.Alloc()
		n.altEnd = opts.globals.Alloc()
	}
	n.setStride()
	p.notes = n
}

// noteAltLitAnchorBranches rebuilds every alternation branch's forward verify
// with its notes (and the switch's stamp, when the pattern has one).
func (p *compiledPattern) noteAltLitAnchorBranches(tableMemIdx int) {
	stamp := int32(-1)
	if p.backStampP1 > 0 {
		stamp = p.backStampP1 - 1
	}
	for i := range p.altLitAnchorBranches {
		br := &p.altLitAnchorBranches[i]
		var vn *verifyNotes
		if r := p.notes.alt[i]; r != nil {
			vn = &verifyNotes{rows: r, search: p.notes.search, marked: p.notes.altMarked, end: p.notes.altEnd}
		}
		br.forwardVerifyBody = buildAltLitAnchorForwardVerifyBodyNotes(br.fwdTable, br.fwdL, tableMemIdx, stamp, vn)
	}
}

// fillSetSearchSizes records a set's split member blocks under its find and
// batch export names — the primary's, or, for an overlapping set the answer
// cache serves, its no-cache companion's: never both, since a set with a
// companion is not split itself. into == nil records nothing.
func fillSetSearchSizes(sc config.SetConfig, cs *compiledSet, into map[string]SearchSize) {
	if into == nil || sc.Find == "" {
		return
	}
	blocks := cs.searchBlocks()
	if blocks == nil {
		return
	}
	into[sc.Find] = SearchSize{Blocks: blocks}
	into[config.SetBatchExportName(sc.Find)] = SearchSize{Blocks: blocks}
}
