package compile

import (
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Backtracking NFA engine

// backtrack is a compiled backtracking NFA.
// It handles capture patterns that cannot be processed by TDFA.
type backtrack struct {
	prog      *syntax.Prog
	numGroups int          // prog.NumCap / 2 (includes group 0)
	numAlts   int          // count of InstAlt nodes — bounds stack depth
	loops     map[int]bool // set of InstAlt PCs that are loop back-edges
}

func (b *backtrack) Type() EngineType { return EngineBacktrack }

// newBacktrack builds the backtrack struct from a compiled NFA program.
func newBacktrack(prog *syntax.Prog) *backtrack {
	bt := &backtrack{
		prog:      prog,
		numGroups: prog.NumCap / 2,
		loops:     make(map[int]bool),
	}
	for pc, inst := range prog.Inst {
		if inst.Op == syntax.InstAlt {
			bt.numAlts++
			pcU32 := uint32(pc)
			// Loop back-edge: Out < PC (greedy body goes backward) OR Arg < PC (non-greedy body backward)
			if inst.Out < pcU32 || inst.Arg < pcU32 {
				bt.loops[pc] = true
			}
		}
	}
	return bt
}

// --------------------------------------------------------------------------
// WASM emission

// Local variable indices for the backtracking function body.
// Params: 0=ptr, 1=len, 2=out_ptr.
const (
	localPtr     = byte(0x00)
	localLen     = byte(0x01)
	localOutPtr  = byte(0x02)
	localPos     = byte(0x03)
	localSP      = byte(0x04)
	localState   = byte(0x05)
	localScratch = byte(0x06)
)

func capStartLocal(i int) uint32 { return uint32(7 + i*2) }
func capEndLocal(i int) uint32   { return uint32(8 + i*2) }

// isLoopPC returns true if pc is a loop back-edge (Out or Arg points backward).
func isLoopPC(prog *syntax.Prog, pc int) bool {
	inst := prog.Inst[pc]
	if inst.Op != syntax.InstAlt && inst.Op != syntax.InstAltMatch {
		return false
	}
	pcU32 := uint32(pc)
	return inst.Out < pcU32 || inst.Arg < pcU32
}

// loopBodyStart returns the PC of the first instruction inside the loop body
// at loopPC (the backward-pointing branch).
func loopBodyStart(prog *syntax.Prog, loopPC int) int {
	inst := prog.Inst[loopPC]
	pcU32 := uint32(loopPC)
	if inst.Out < pcU32 {
		return int(inst.Out) // greedy: body is Out (backward)
	}
	return int(inst.Arg) // non-greedy: body is Arg (backward)
}

// loopBodyCanMatchEmpty returns true if the body of the loop at loopPC can
// execute a full iteration without consuming any byte.  It BFS-traverses all
// NFA paths reachable from the body entry back to loopPC and returns true if
// at least one path contains no byte-consuming instruction.
func loopBodyCanMatchEmpty(prog *syntax.Prog, loopPC int) bool {
	bodyStart := loopBodyStart(prog, loopPC)
	visited := make([]bool, len(prog.Inst))
	type entry struct {
		pc    int
		empty bool
	}
	queue := []entry{{bodyStart, true}}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		pc := e.pc
		if pc == loopPC {
			if e.empty {
				return true // found a zero-byte path back to the loop head
			}
			continue
		}
		if visited[pc] {
			continue
		}
		visited[pc] = true
		i := prog.Inst[pc]
		switch i.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			queue = append(queue, entry{int(i.Out), false})
		case syntax.InstAlt, syntax.InstAltMatch:
			queue = append(queue, entry{int(i.Out), e.empty}, entry{int(i.Arg), e.empty})
		default:
			queue = append(queue, entry{int(i.Out), e.empty})
		}
	}
	return false
}

// needsBitState returns true if prog contains a non-greedy loop whose body can
// execute a full iteration without consuming a byte.  For such loops the
// existing zero-progress guard incorrectly takes the body branch again (instead
// of exiting), causing an infinite loop.  BitState memoisation breaks the cycle.
//
// Greedy loops are already handled correctly by the zero-progress guard
// (zero-progress → take exit), so they never need BitState.
func needsBitState(prog *syntax.Prog) bool {
	for pc, inst := range prog.Inst {
		if inst.Op != syntax.InstAlt && inst.Op != syntax.InstAltMatch {
			continue
		}
		// Non-greedy: Arg < PC (body is Arg, backward pointing).
		if inst.Arg < uint32(pc) && loopBodyCanMatchEmpty(prog, pc) {
			return true
		}
	}
	return false
}

// memoStateSet returns the set of NFA PCs that are reachable within the body
// of any non-greedy zero-matchable loop.  Only these states need a BitState
// bit check/set.  Returns nil if needsBitState is false.
func memoStateSet(prog *syntax.Prog) map[int]bool {
	states := make(map[int]bool)
	for pc, inst := range prog.Inst {
		if inst.Op != syntax.InstAlt && inst.Op != syntax.InstAltMatch {
			continue
		}
		if inst.Arg >= uint32(pc) || !loopBodyCanMatchEmpty(prog, pc) {
			continue // only non-greedy zero-matchable loops
		}
		bodyStart := loopBodyStart(prog, pc)
		visited := make([]bool, len(prog.Inst))
		queue := []int{bodyStart}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur == pc || visited[cur] {
				continue
			}
			visited[cur] = true
			states[cur] = true
			i := prog.Inst[cur]
			switch i.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				queue = append(queue, int(i.Out), int(i.Arg))
			default:
				queue = append(queue, int(i.Out))
			}
		}
		states[pc] = true // loop head itself needs the check
	}
	if len(states) == 0 {
		return nil
	}
	return states
}

// appendBacktrackCodeEntry appends a size-prefixed backtracking capture body to cs.
// loopCaptureLocals returns the capture local variable indices that are
// modified inside the loop body at loopPC (reachable from inst.Out before
// re-entering loopPC). Only those locals need snapshot save/restore.
// Returns nil if no captures are inside the loop.
func loopCaptureLocals(prog *syntax.Prog, loopPC int) []uint32 {
	visited := make([]bool, len(prog.Inst))
	queue := []int{loopBodyStart(prog, loopPC)}
	seen := make(map[uint32]bool)
	var locals []uint32
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		if pc == loopPC || visited[pc] {
			continue
		}
		visited[pc] = true
		i := prog.Inst[pc]
		if i.Op == syntax.InstCapture {
			g := int(i.Arg >> 1)
			var loc uint32
			if i.Arg&1 == 0 {
				loc = capStartLocal(g)
			} else {
				loc = capEndLocal(g)
			}
			if !seen[loc] {
				seen[loc] = true
				locals = append(locals, loc)
			}
		}
		switch i.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			queue = append(queue, int(i.Out), int(i.Arg))
		default:
			queue = append(queue, int(i.Out))
		}
	}
	return locals
}

func appendBacktrackCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase int32, memoMaxLen int32, useMemo bool) []byte {
	body := buildBacktrackBody(bt, stackBase, stackLimit, frameSize, memoTableBase, memoMaxLen, useMemo)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBacktrackBody emits the WASM function body for the backtracking NFA.
// The caller (wrapper) has already located the match extent via find_internal and
// passes a bounded slice (ptr=match_start, len=match_length). This function runs
// Phase 2 NFA only — no Phase 1 DFA traversal.
func buildBacktrackBody(bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase, memoMaxLen int32, useMemo bool) []byte {
	prog := bt.prog
	N := len(prog.Inst)
	numCaps := bt.numGroups
	numCapLocals := numCaps * 2

	// Build sorted list of loop PCs for deterministic local assignment.
	loopPCsSorted := make([]int, 0, len(bt.loops))
	for pc := range bt.loops {
		loopPCsSorted = append(loopPCsSorted, pc)
	}
	sort.Ints(loopPCsSorted)

	// loopLocalIdx[pc] = local variable index for that loop's pos tracker
	loopLocalIdx := make(map[int]uint32, len(loopPCsSorted))
	for j, pc := range loopPCsSorted {
		loopLocalIdx[pc] = uint32(7 + numCapLocals + j)
	}

	// Loop capture snapshot locals — only the specific capture locals modified
	// inside each loop's body, not all caps. Loops with no captures inside need
	// no snapshot at all.
	baseExtra := uint32(7 + numCapLocals + len(loopPCsSorted))
	loopSnapBase := make(map[int]uint32, len(loopPCsSorted))     // loop PC → first snapshot local
	loopSnapLocals := make(map[int][]uint32, len(loopPCsSorted)) // loop PC → which cap locals to snap
	snapTotal := 0
	for _, pc := range loopPCsSorted {
		locals := loopCaptureLocals(prog, pc)
		if len(locals) > 0 {
			loopSnapBase[pc] = baseExtra + uint32(snapTotal)
			loopSnapLocals[pc] = locals
			snapTotal += len(locals)
		}
	}

	// Memo locals (only when useMemo=true), placed after all existing locals.
	memoLocalsBase := baseExtra + uint32(snapTotal)
	var (
		memoLenPlus1 uint32 // localLen + 1, pre-computed at entry
		memoBitIdx   uint32 // state * lenPlus1 + pos
		memoByteAddr uint32 // memoTableBase + bitIdx/8
		memoMemoByte uint32 // loaded byte from bitset
		memoZeroLen  uint32 // (N * lenPlus1 + 7) / 8
		memoZeroIdx  uint32 // loop counter for zero-init
	)
	if useMemo {
		memoLenPlus1 = memoLocalsBase
		memoBitIdx = memoLocalsBase + 1
		memoByteAddr = memoLocalsBase + 2
		memoMemoByte = memoLocalsBase + 3
		memoZeroLen = memoLocalsBase + 4
		memoZeroIdx = memoLocalsBase + 5
	}

	// Total non-param locals: pos, sp, state, scratch, cap0s, cap0e, ...,
	// loop_pos..., loop_snap..., (memo locals when useMemo)
	memoLocalsCount := 0
	if useMemo {
		memoLocalsCount = 6
	}
	totalLocals := 4 + numCapLocals + len(loopPCsSorted) + snapTotal + memoLocalsCount

	var body []byte

	// ── Local declarations ────────────────────────────────────────────────────
	body = append(body, 0x01)
	body = utils.AppendULEB128(body, uint32(totalLocals))
	body = append(body, 0x7F)

	// ── Initialise pos=0, sp=stackBase, state=prog.Start ────────────────────
	body = append(body, 0x41, 0x00)     // i32.const 0
	body = append(body, 0x21, localPos) // local.set pos

	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, stackBase)
	body = append(body, 0x21, localSP) // local.set sp

	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(prog.Start))
	body = append(body, 0x21, localState) // local.set state

	// ── Initialise capture locals to -1 ─────────────────────────────────────
	for i := 0; i < numCapLocals; i++ {
		body = append(body, 0x41, 0x7F) // i32.const -1
		body = append(body, 0x21)       // local.set
		body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
	}

	// ── Initialise loop_pos locals to -1 ────────────────────────────────────
	for _, loopLocal := range loopLocalIdx {
		body = append(body, 0x41, 0x7F) // i32.const -1
		body = append(body, 0x21)       // local.set
		body = utils.AppendULEB128(body, loopLocal)
	}

	// ── Initialise loop snapshot locals to -1 ───────────────────────────────
	for pc, snapBase := range loopSnapBase {
		for k := range loopSnapLocals[pc] {
			body = append(body, 0x41, 0x7F) // i32.const -1
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, snapBase+uint32(k))
		}
	}

	// ── Part 3: Memo table zero-init and lenPlus1 pre-computation ───────────
	if useMemo {
		// lenPlus1 = localLen + 1
		body = append(body, 0x20, localLen)
		body = append(body, 0x41, 0x01) // i32.const 1
		body = append(body, 0x6A)       // i32.add
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, memoLenPlus1)

		// memoZeroLen = (N * lenPlus1 + 7) / 8
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, int32(N))
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoLenPlus1)
		body = append(body, 0x6C) // i32.mul
		body = append(body, 0x41, 0x07)
		body = append(body, 0x6A) // i32.add (+ 7)
		body = append(body, 0x41, 0x03)
		body = append(body, 0x76) // i32.shr_u (/ 8)
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, memoZeroLen)

		// memoZeroIdx = 0
		body = append(body, 0x41, 0x00)
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, memoZeroIdx)

		// block $zeroEnd / loop $zeroLoop: memset(memoTableBase, 0, memoZeroLen)
		body = append(body, 0x02, 0x40) // block void $zeroEnd
		body = append(body, 0x03, 0x40) // loop void $zeroLoop

		// if memoZeroIdx >= memoZeroLen: br $zeroEnd
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoZeroIdx)
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoZeroLen)
		body = append(body, 0x4F)       // i32.ge_u
		body = append(body, 0x0D, 0x01) // br_if 1 ($zeroEnd)

		// mem[memoTableBase + memoZeroIdx] = 0
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, memoTableBase)
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoZeroIdx)
		body = append(body, 0x6A)       // i32.add
		body = append(body, 0x41, 0x00) // i32.const 0
		body = append(body, 0x3A, 0x00) // i32.store8 align=0
		body = utils.AppendULEB128(body, 0)

		// memoZeroIdx += 1
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoZeroIdx)
		body = append(body, 0x41, 0x01)
		body = append(body, 0x6A) // i32.add
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, memoZeroIdx)

		body = append(body, 0x0C, 0x00) // br $zeroLoop
		body = append(body, 0x0B)       // end loop
		body = append(body, 0x0B)       // end block $zeroEnd
	}

	// ── Main loop $run ───────────────────────────────────────────────────────
	// loop $run   (br 0 from inside it = restart)
	body = append(body, 0x03, 0x40) // loop void

	// ── FAIL handler ─────────────────────────────────────────────────────────
	// if state == -1: pop backtrack stack or return -1
	// This is inside $run, so:
	//   br 0 = restart $run
	//   return -1 = return opcode (simpler than nested br)
	body = append(body, 0x20, localState) // local.get state
	body = append(body, 0x41, 0x7F)       // i32.const -1
	body = append(body, 0x46)             // i32.eq
	body = append(body, 0x04, 0x40)       // if void
	// if sp <= stackBase: empty stack → return -1
	body = append(body, 0x20, localSP) // local.get sp
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, stackBase)
	body = append(body, 0x4D)       // i32.le_u
	body = append(body, 0x04, 0x40) // if void
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x0F)       // return
	body = append(body, 0x0B)       // end if (empty)

	// Pop frame: sp -= frameSize
	body = append(body, 0x20, localSP) // local.get sp
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, frameSize)
	body = append(body, 0x6B)          // i32.sub
	body = append(body, 0x21, localSP) // local.set sp

	// Restore pos from mem[sp+0]
	body = append(body, 0x20, localSP)
	body = append(body, 0x28, 0x02) // i32.load align=2
	body = utils.AppendULEB128(body, 0)
	body = append(body, 0x21, localPos) // local.set pos

	// Restore captures from mem[sp+4..sp+4+numCapLocals*4)
	for i := 0; i < numCapLocals; i++ {
		body = append(body, 0x20, localSP)
		body = append(body, 0x28, 0x02) // i32.load align=2
		body = utils.AppendULEB128(body, uint32(4+i*4))
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
	}

	// Restore retry PC from mem[sp + 4 + numCapLocals*4]
	retryPCOffset := uint32(4 + numCapLocals*4)
	body = append(body, 0x20, localSP)
	body = append(body, 0x28, 0x02) // i32.load align=2
	body = utils.AppendULEB128(body, retryPCOffset)
	body = append(body, 0x21, localState) // local.set state

	// br 1: restart $run (depth 0=this if, 1=$run)
	body = append(body, 0x0C, 0x01) // br 1
	body = append(body, 0x0B)       // end if (state == -1)

	// ── Part 4: Bit check/set — at non-greedy zero-matchable loop head handlers ─
	// Do NOT emit an unconditional check at the top of $run: that would mark every
	// (pc, pos) as visited and prevent valid backtrack paths from executing.
	// Instead, the check is emitted only inside the specific loop head handlers
	// (see emitBTInstHandler).  That is sufficient to break the only infinite-loop
	// scenario: a non-greedy loop body that matches empty, returning to the same
	// loop head at the same pos.

	// ── N nested blocks for PC dispatch ──────────────────────────────────────
	// Emit N blocks (outermost first).
	for i := 0; i < N; i++ {
		body = append(body, 0x02, 0x40) // block void
	}

	// br_table: local.get state; br_table 0 1 2 ... N-1 (default=0)
	body = append(body, 0x20, localState)       // local.get state
	body = append(body, 0x0E)                   // br_table
	body = utils.AppendULEB128(body, uint32(N)) // N targets
	for i := 0; i < N; i++ {
		body = utils.AppendULEB128(body, uint32(i))
	}
	body = utils.AppendULEB128(body, 0) // default

	// ── Per-PC handlers ───────────────────────────────────────────────────────
	// After each end of block $pc_p, emit the handler for PC p.
	// brRun(p) = N-1-p  (depth from handler top level to restart $run)
	// brRunNested(p) = N-p  (depth from inside one extra if block)
	for p := 0; p < N; p++ {
		body = append(body, 0x0B) // end $pc_p

		inst := prog.Inst[p]
		brRun := uint32(N - 1 - p)

		body = emitBTInstHandler(body, bt, p, inst, brRun, loopLocalIdx, loopSnapBase, loopSnapLocals, stackBase, stackLimit, frameSize, numCapLocals, memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte, useMemo)
	}

	body = append(body, 0x00)       // unreachable (after all handlers, inside $run)
	body = append(body, 0x0B)       // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1 (unreachable fallthrough)
	body = append(body, 0x0B)       // end function
	return body
}

// emitBTInstHandler emits WASM for a single NFA instruction handler.
// brRun is the br depth (from handler top level) to restart $run.
// memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte are the
// memo locals/constants; useMemo enables bit check/set for non-greedy zero-
// matchable loop heads.
func emitBTInstHandler(
	body []byte,
	bt *backtrack,
	p int,
	inst syntax.Inst,
	brRun uint32,
	loopLocalIdx map[int]uint32,
	loopSnapBase map[int]uint32,
	loopSnapLocals map[int][]uint32,
	stackBase, stackLimit, frameSize int32,
	numCapLocals int,
	memoTableBase int32,
	memoLenPlus1Local, memoBitIdx, memoByteAddr, memoMemoByte uint32,
	useMemo bool,
) []byte {
	// brRunNested = br depth from inside one extra if/block to restart $run
	brRunNested := brRun + 1

	switch inst.Op {
	case syntax.InstRune1:
		body = btBoundsCheck(body, brRunNested)
		body = btCheckRune1(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstRune:
		body = btBoundsCheck(body, brRunNested)
		body = btCheckRuneRanges(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstRuneAny:
		body = btBoundsCheck(body, brRunNested)
		body = btAdvancePos(body)
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstRuneAnyNotNL:
		body = btBoundsCheck(body, brRunNested)
		// if input[pos] == '\n' → fail
		body = append(body, 0x20, localPtr)
		body = append(body, 0x20, localPos)
		body = append(body, 0x6A)             // i32.add
		body = append(body, 0x2D, 0x00, 0x00) // i32.load8_u
		body = append(body, 0x41, 0x0A)       // i32.const '\n'
		body = append(body, 0x46)             // i32.eq
		body = append(body, 0x04, 0x40)       // if void
		body = btFail(body, brRunNested)
		body = append(body, 0x0B) // end if
		body = btAdvancePos(body)
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstAlt, syntax.InstAltMatch:
		isLoop := bt.loops[p]
		if !isLoop {
			// Non-loop alternation: push retry=inst.Arg, continue with inst.Out
			body = btPushFrame(body, numCapLocals, inst.Arg, stackLimit, frameSize)
			body = btSetStateAndBr(body, int32(inst.Out), brRun)
		} else {
			// Loop alternation: zero-progress guard
			loopLocal := loopLocalIdx[p]

			// ── Part 4: BitState bit check/set ───────────────────────────────
			// Only for non-greedy loop heads with zero-matchable bodies.
			// Greedy loops are correctly handled by the zero-progress guard below.
			// From inside the if-block: depth 0 = this if, depth 1 = brRun depth.
			// So brRunNested is the correct depth to restart $run from here.
			if useMemo && inst.Arg < uint32(p) {
				// bitIdx = p * lenPlus1 + localPos
				// (p is the compile-time PC, baked as i32.const)
				body = append(body, 0x41)
				body = utils.AppendSLEB128(body, int32(p))
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, memoLenPlus1Local)
				body = append(body, 0x6C) // i32.mul
				body = append(body, 0x20, localPos)
				body = append(body, 0x6A) // i32.add
				body = append(body, 0x22) // local.tee
				body = utils.AppendULEB128(body, memoBitIdx)

				// byteAddr = memoTableBase + bitIdx / 8
				body = append(body, 0x41, 0x03)
				body = append(body, 0x76) // i32.shr_u (/ 8)
				body = append(body, 0x41)
				body = utils.AppendSLEB128(body, memoTableBase)
				body = append(body, 0x6A) // i32.add
				body = append(body, 0x22) // local.tee
				body = utils.AppendULEB128(body, memoByteAddr)

				// memoByte = mem[byteAddr]
				body = append(body, 0x2D, 0x00) // i32.load8_u align=0
				body = utils.AppendULEB128(body, 0)
				body = append(body, 0x22) // local.tee
				body = utils.AppendULEB128(body, memoMemoByte)

				// check bit: (memoByte >> (bitIdx & 7)) & 1
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, memoBitIdx)
				body = append(body, 0x41, 0x07)
				body = append(body, 0x71) // i32.and (&7)
				body = append(body, 0x76) // i32.shr_u
				body = append(body, 0x41, 0x01)
				body = append(body, 0x71)       // i32.and (&1)
				body = append(body, 0x04, 0x40) // if void
				// already visited → fail (brRunNested: depth 0=this if, +brRun=$run)
				body = btFail(body, brRunNested)
				body = append(body, 0x0B) // end if

				// set bit: mem[byteAddr] = memoByte | (1 << (bitIdx & 7))
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, memoByteAddr)
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, memoMemoByte)
				body = append(body, 0x41, 0x01) // i32.const 1  (value to shift)
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, memoBitIdx)
				body = append(body, 0x41, 0x07)
				body = append(body, 0x71)       // i32.and (&7) (shift amount)
				body = append(body, 0x74)       // i32.shl: 1 << (bitIdx & 7)
				body = append(body, 0x72)       // i32.or
				body = append(body, 0x3A, 0x00) // i32.store8 align=0
				body = utils.AppendULEB128(body, 0)
			}

			// For greedy: Out < PC means body=Out(backward), exit=Arg(forward)
			// For non-greedy: Arg < PC means body=Arg(backward), exit=Out(forward)
			// In both cases: preferred=inst.Out, retry=inst.Arg.
			// Zero-progress: if pos == loop_pos_local, take the EXIT branch directly.
			// Greedy (Out < PC): exit = Arg.  Non-greedy (Arg < PC): exit = Out.
			// Without this guard, non-greedy loops with zero-matchable bodies would
			// take the body again and loop infinitely.

			// if pos == loop_pos_local: take exit branch
			body = append(body, 0x20, localPos)
			body = append(body, 0x20)
			body = utils.AppendULEB128(body, loopLocal)
			body = append(body, 0x46)       // i32.eq
			body = append(body, 0x04, 0x40) // if void
			// Restore only the specific cap locals snapshotted for this loop.
			if snapBase, ok := loopSnapBase[p]; ok {
				for k, capLocal := range loopSnapLocals[p] {
					body = append(body, 0x20)
					body = utils.AppendULEB128(body, snapBase+uint32(k))
					body = append(body, 0x21)
					body = utils.AppendULEB128(body, capLocal)
				}
			}
			// Exit = Arg for greedy (Out < PC), Out for non-greedy (Arg < PC).
			exitPC := inst.Arg
			if inst.Arg < uint32(p) { // non-greedy: body=Arg, exit=Out
				exitPC = inst.Out
			}
			body = btSetStateAndBr(body, int32(exitPC), brRunNested)
			body = append(body, 0x0B) // end if

			// Progress: update loop_pos_local = pos
			body = append(body, 0x20, localPos)
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, loopLocal)

			// Save only the specific cap locals for this loop.
			if snapBase, ok := loopSnapBase[p]; ok {
				for k, capLocal := range loopSnapLocals[p] {
					body = append(body, 0x20)
					body = utils.AppendULEB128(body, capLocal)
					body = append(body, 0x21)
					body = utils.AppendULEB128(body, snapBase+uint32(k))
				}
			}

			// Push retry=inst.Arg, continue with inst.Out
			body = btPushFrame(body, numCapLocals, inst.Arg, stackLimit, frameSize)
			body = btSetStateAndBr(body, int32(inst.Out), brRun)
		}

	case syntax.InstCapture:
		// inst.Arg: even = open (store pos as group start), odd = close (store pos as group end)
		groupIdx := int(inst.Arg >> 1)
		isOpen := inst.Arg&1 == 0
		var local uint32
		if isOpen {
			local = capStartLocal(groupIdx)
		} else {
			local = capEndLocal(groupIdx)
		}
		body = append(body, 0x20, localPos) // local.get pos
		body = append(body, 0x21)           // local.set
		body = utils.AppendULEB128(body, local)
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstEmptyWidth:
		emptyOp := syntax.EmptyOp(inst.Arg)
		switch {
		case emptyOp&(syntax.EmptyBeginText|syntax.EmptyBeginLine) != 0:
			// fail if pos != 0
			body = append(body, 0x20, localPos)
			body = append(body, 0x45)       // i32.eqz
			body = append(body, 0x45)       // i32.eqz (NOT: nonzero = fail)
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = btSetStateAndBr(body, int32(inst.Out), brRun)

		case emptyOp&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0:
			// fail if pos != len
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
			body = append(body, 0x47)       // i32.ne
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = btSetStateAndBr(body, int32(inst.Out), brRun)

		case emptyOp&syntax.EmptyWordBoundary != 0:
			body = btWordBoundary(body, true, brRunNested)
			body = btSetStateAndBr(body, int32(inst.Out), brRun)

		case emptyOp&syntax.EmptyNoWordBoundary != 0:
			body = btWordBoundary(body, false, brRunNested)
			body = btSetStateAndBr(body, int32(inst.Out), brRun)

		default:
			body = btSetStateAndBr(body, int32(inst.Out), brRun)
		}

	case syntax.InstNop:
		body = btSetStateAndBr(body, int32(inst.Out), brRun)

	case syntax.InstMatch:
		// RE2 semantics: only accept if the full input slice is consumed.
		// The caller sets len = DFA-determined end, so pos must equal len.
		body = append(body, 0x20, localPos)
		body = append(body, 0x20, localLen)
		body = append(body, 0x47)       // i32.ne
		body = append(body, 0x04, 0x40) // if void
		body = btFail(body, brRunNested)
		body = append(body, 0x0B) // end if

		// Write captures to out_ptr and return pos.
		// Group 0: start = 0 (anchored), end = pos.
		body = append(body, 0x20, localOutPtr)
		body = append(body, 0x41, 0x00)     // i32.const 0 (group 0 start)
		body = append(body, 0x36, 0x02)     // i32.store align=2
		body = utils.AppendULEB128(body, 0) // offset=0

		body = append(body, 0x20, localOutPtr)
		body = append(body, 0x20, localPos)
		body = append(body, 0x36, 0x02)     // i32.store align=2
		body = utils.AppendULEB128(body, 4) // offset=4 (group 0 end)

		// Write capture groups 1..numCaps-1
		numCaps := bt.numGroups
		for i := 1; i < numCaps; i++ {
			startOffset := uint32(i * 8)
			endOffset := uint32(i*8 + 4)

			body = append(body, 0x20, localOutPtr)
			body = append(body, 0x20)
			body = utils.AppendULEB128(body, capStartLocal(i))
			body = append(body, 0x36, 0x02) // i32.store align=2
			body = utils.AppendULEB128(body, startOffset)

			body = append(body, 0x20, localOutPtr)
			body = append(body, 0x20)
			body = utils.AppendULEB128(body, capEndLocal(i))
			body = append(body, 0x36, 0x02) // i32.store align=2
			body = utils.AppendULEB128(body, endOffset)
		}

		body = append(body, 0x20, localPos)
		body = append(body, 0x0F) // return

	case syntax.InstFail:
		body = btFail(body, brRun)
	}

	return body
}

// ── Small WASM helpers ────────────────────────────────────────────────────────

// btFail emits: state = -1; br brDepth
func btFail(b []byte, brDepth uint32) []byte {
	b = append(b, 0x41, 0x7F)       // i32.const -1
	b = append(b, 0x21, localState) // local.set state
	b = append(b, 0x0C)             // br
	b = utils.AppendULEB128(b, brDepth)
	return b
}

// btSetStateAndBr emits: state = nextPC; br brDepth
func btSetStateAndBr(b []byte, nextPC int32, brDepth uint32) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, nextPC)
	b = append(b, 0x21, localState) // local.set state
	b = append(b, 0x0C)             // br
	b = utils.AppendULEB128(b, brDepth)
	return b
}

// btAdvancePos emits: pos = pos + 1
func btAdvancePos(b []byte) []byte {
	b = append(b, 0x20, localPos)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x21, localPos)
	return b
}

// btBoundsCheck emits: if pos >= len { fail(brDepth) }
func btBoundsCheck(b []byte, brDepth uint32) []byte {
	b = append(b, 0x20, localPos)
	b = append(b, 0x20, localLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if void
	b = btFail(b, brDepth)
	b = append(b, 0x0B) // end if
	return b
}

// btCheckRune1 emits a check: if input[pos] != r (and not fold-case match) → fail
func btCheckRune1(b []byte, inst syntax.Inst, brDepth uint32) []byte {
	r := inst.Rune[0]
	isFold := syntax.Flags(inst.Arg)&syntax.FoldCase != 0

	// Load byte into scratch local
	b = append(b, 0x20, localPtr)
	b = append(b, 0x20, localPos)
	b = append(b, 0x6A)               // i32.add
	b = append(b, 0x2D, 0x00, 0x00)   // i32.load8_u
	b = append(b, 0x21, localScratch) // local.set scratch

	if isFold {
		altR := btFoldRune(r)
		// (scratch == r || scratch == altR) → if NOT → fail
		b = append(b, 0x20, localScratch)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(r))
		b = append(b, 0x46) // i32.eq

		b = append(b, 0x20, localScratch)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(altR))
		b = append(b, 0x46) // i32.eq

		b = append(b, 0x72)       // i32.or
		b = append(b, 0x45)       // i32.eqz (NOT)
		b = append(b, 0x04, 0x40) // if void (no match)
		b = btFail(b, brDepth)
		b = append(b, 0x0B) // end if
	} else {
		b = append(b, 0x20, localScratch)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(r))
		b = append(b, 0x47)       // i32.ne
		b = append(b, 0x04, 0x40) // if void (no match)
		b = btFail(b, brDepth)
		b = append(b, 0x0B) // end if
	}
	return b
}

// btCheckRuneRanges emits a range check for InstRune.
// Fails (state=-1, br brDepth) if no range matches.
// Uses: block $matched (result i32) pattern.
func btCheckRuneRanges(b []byte, inst syntax.Inst, brDepth uint32) []byte {
	isFold := syntax.Flags(inst.Arg)&syntax.FoldCase != 0

	// Load byte into scratch
	b = append(b, 0x20, localPtr)
	b = append(b, 0x20, localPos)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, localScratch)

	// Use block $matched (result i32): emit 1 and br if matched, else 0 falls through.
	b = append(b, 0x02, 0x7F) // block (result i32)

	for i := 0; i < len(inst.Rune); i += 2 {
		var lo, hi rune
		if i+1 >= len(inst.Rune) {
			lo = inst.Rune[i]
			hi = inst.Rune[i] // single-rune element (e.g. FoldCase with one base rune)
		} else {
			lo = inst.Rune[i]
			hi = inst.Rune[i+1]
		}
		if lo > 0x7F {
			continue // skip non-ASCII ranges
		}
		if hi > 0x7F {
			hi = 0x7F
		}
		b = btEmitRangeMatch(b, lo, hi, isFold)
	}

	// No range matched: push 0 as block result
	b = append(b, 0x41, 0x00)
	b = append(b, 0x0B) // end block $matched — stack has 0 or 1

	// if result == 0 → fail
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if void
	b = btFail(b, brDepth)
	b = append(b, 0x0B) // end if
	return b
}

// btEmitRangeMatch emits code inside a block (result i32) that checks if scratch
// is in [lo, hi] and br_if 0 (to produce 1 and exit the block) on match.
func btEmitRangeMatch(b []byte, lo, hi rune, isFold bool) []byte {
	b = btEmitSingleRange(b, lo, hi)
	if isFold {
		lo2 := btFoldRune(lo)
		hi2 := btFoldRune(hi)
		if lo2 != lo || hi2 != hi {
			b = btEmitSingleRange(b, lo2, hi2)
		}
	}
	return b
}

// btEmitSingleRange emits: (scratch >= lo && scratch <= hi); br_if 0 with result 1
func btEmitSingleRange(b []byte, lo, hi rune) []byte {
	if lo > 0x7F {
		return b
	}
	if hi > 0x7F {
		hi = 0x7F
	}
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(lo))
	b = append(b, 0x4F) // i32.ge_u

	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(hi))
	b = append(b, 0x4D) // i32.le_u

	b = append(b, 0x71) // i32.and → 0 or 1

	// if this range matched: push 1 and br out of block
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x0C, 0x01) // br 1 (out of the result block; depth 0=this if, 1=block $matched)
	b = append(b, 0x0B)       // end if
	return b
}

// btPushFrame pushes a backtrack frame onto the stack:
// mem[sp+0]               = pos
// mem[sp+4..4+capLocals*4] = captures
// mem[sp+retryPCOff]       = retryPC
// btPushFrame pushes a backtrack frame. stackLimit and frameSize are passed
// so we can guard against stack overflow: if sp+frameSize > stackLimit, set
// state=-1 (fail) and return instead of writing past allocated memory.
func btPushFrame(b []byte, numCapLocals int, retryPC uint32, stackLimit, frameSize int32) []byte {
	// Guard: if sp + frameSize > stackLimit → fail (treat as no-match).
	b = append(b, 0x20, localSP)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, frameSize)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, stackLimit)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// pos at offset 0
	b = append(b, 0x20, localSP)
	b = append(b, 0x20, localPos)
	b = append(b, 0x36, 0x02)
	b = utils.AppendULEB128(b, 0)

	// captures at offsets 4, 8, ...
	for i := 0; i < numCapLocals; i++ {
		b = append(b, 0x20, localSP)
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, capStartLocal(0)+uint32(i))
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, uint32(4+i*4))
	}

	// retry PC at offset 4 + numCapLocals*4
	retryOff := uint32(4 + numCapLocals*4)
	b = append(b, 0x20, localSP)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(retryPC))
	b = append(b, 0x36, 0x02)
	b = utils.AppendULEB128(b, retryOff)

	// sp += frameSize
	b = append(b, 0x20, localSP)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, frameSize)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, localSP)
	return b
}

// btWordBoundary emits a word-boundary check.
// wantBoundary=true: fail if NOT a word boundary.
// wantBoundary=false: fail if IS a word boundary.
//
// Uses scratch local to hold loaded bytes.
// Computes: prevIsWord XOR nextIsWord; check against wantBoundary.
func btWordBoundary(b []byte, wantBoundary bool, brDepth uint32) []byte {
	// Compute prevIsWord (0 or 1) using block (result i32):
	//   if pos == 0: push 0
	//   else: load input[pos-1]; isWordChar → push 0 or 1
	b = append(b, 0x02, 0x7F) // block (result i32) $prevWord
	b = append(b, 0x20, localPos)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if void (pos == 0)
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x0C, 0x01) // br 1 → out of $prevWord
	b = append(b, 0x0B)       // end if
	// load input[pos-1]
	b = append(b, 0x20, localPtr)
	b = append(b, 0x20, localPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B)             // i32.sub
	b = append(b, 0x6A)             // i32.add (ptr + pos - 1)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, localScratch)
	b = emitIsWordCharFromScratch(b) // → 0 or 1 on stack
	b = append(b, 0x0B)              // end block $prevWord → prevIsWord on stack

	// Compute nextIsWord:
	b = append(b, 0x02, 0x7F) // block (result i32) $nextWord
	b = append(b, 0x20, localPos)
	b = append(b, 0x20, localLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if void (pos >= len)
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x0C, 0x01) // br 1 → out of $nextWord
	b = append(b, 0x0B)       // end if
	// load input[pos]
	b = append(b, 0x20, localPtr)
	b = append(b, 0x20, localPos)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, localScratch)
	b = emitIsWordCharFromScratch(b) // → 0 or 1 on stack
	b = append(b, 0x0B)              // end block $nextWord → nextIsWord on stack

	// boundary = prevIsWord XOR nextIsWord
	b = append(b, 0x73) // i32.xor

	// After both result blocks close, we are back at handler top level.
	// brDepth = brRunNested = brRun+1 (passed from caller as depth to restart $run
	// from inside one extra block).  Inside the if void here we are inside one extra
	// block, so depth to $run = brDepth.
	if wantBoundary {
		// fail if boundary == 0 (no boundary when we want one)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if void
		b = btFail(b, brDepth)
		b = append(b, 0x0B) // end if
	} else {
		// fail if boundary != 0 (boundary present when we want none)
		b = append(b, 0x04, 0x40) // if void (nonzero = boundary)
		b = btFail(b, brDepth)
		b = append(b, 0x0B) // end if
	}
	return b
}

// emitIsWordCharFromScratch emits code that reads scratch local and pushes
// 1 if it is a word character [a-zA-Z0-9_], 0 otherwise.
// Uses block (result i32) pattern with early exits.
func emitIsWordCharFromScratch(b []byte) []byte {
	// block $isword (result i32)
	//   scratch >= 'a' && scratch <= 'z' → 1; br out
	//   scratch >= 'A' && scratch <= 'Z' → 1; br out
	//   scratch >= '0' && scratch <= '9' → 1; br out
	//   scratch == '_' → 1; br out
	//   0 (fallthrough)
	// end
	b = append(b, 0x02, 0x7F) // block (result i32) $isword

	// [a-z]
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('a'))
	b = append(b, 0x4F) // i32.ge_u
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('z'))
	b = append(b, 0x4E)       // i32.le_u
	b = append(b, 0x71)       // i32.and
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x0C, 0x01) // br 1 → out of $isword
	b = append(b, 0x0B)       // end if

	// [A-Z]
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('A'))
	b = append(b, 0x4F)
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('Z'))
	b = append(b, 0x4E)
	b = append(b, 0x71)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x0B)

	// [0-9]
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('0'))
	b = append(b, 0x4F)
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('9'))
	b = append(b, 0x4E)
	b = append(b, 0x71)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x0B)

	// '_'
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32('_'))
	b = append(b, 0x46) // i32.eq
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x0B)

	// not a word char
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x0B)       // end $isword
	return b
}

// btFoldRune returns the case-folded version of an ASCII rune.
func btFoldRune(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}
