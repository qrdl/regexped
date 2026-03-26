package compile

import (
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Backtracking NFA engine

// backtrack is a compiled backtracking NFA.
// It handles capture patterns that fail the OnePass test.
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
	localPtr      = byte(0x00)
	localLen      = byte(0x01)
	localOutPtr   = byte(0x02)
	localPos      = byte(0x03)
	localSP       = byte(0x04)
	localState    = byte(0x05)
	localScratch  = byte(0x06)
)

func capStartLocal(i int) uint32 { return uint32(7 + i*2) }
func capEndLocal(i int) uint32   { return uint32(8 + i*2) }

// appendBacktrackCodeEntry appends a size-prefixed backtracking capture body to cs.
// loopCaptureLocals returns the capture local variable indices that are
// modified inside the loop body at loopPC (reachable from inst.Out before
// re-entering loopPC). Only those locals need snapshot save/restore.
// Returns nil if no captures are inside the loop.
func loopCaptureLocals(prog *syntax.Prog, loopPC int) []uint32 {
	inst := prog.Inst[loopPC]
	visited := make([]bool, len(prog.Inst))
	queue := []int{int(inst.Out)}
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

func appendBacktrackCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize int32) []byte {
	body := buildBacktrackBody(bt, stackBase, stackLimit, frameSize)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBacktrackBody emits the WASM function body for the backtracking NFA.
// The caller (wrapper) has already located the match extent via find_internal and
// passes a bounded slice (ptr=match_start, len=match_length). This function runs
// Phase 2 NFA only — no Phase 1 DFA traversal.
func buildBacktrackBody(bt *backtrack, stackBase, stackLimit, frameSize int32) []byte {
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
	loopSnapBase    := make(map[int]uint32,   len(loopPCsSorted)) // loop PC → first snapshot local
	loopSnapLocals  := make(map[int][]uint32, len(loopPCsSorted)) // loop PC → which cap locals to snap
	snapTotal := 0
	for _, pc := range loopPCsSorted {
		locals := loopCaptureLocals(prog, pc)
		if len(locals) > 0 {
			loopSnapBase[pc]   = baseExtra + uint32(snapTotal)
			loopSnapLocals[pc] = locals
			snapTotal += len(locals)
		}
	}

	// Total non-param locals: pos, sp, state, scratch, cap0s, cap0e, ...,
	// loop_pos..., loop_snap... (only specific cap locals for loops that need it)
	totalLocals := 4 + numCapLocals + len(loopPCsSorted) + snapTotal

	var body []byte

	// ── Local declarations ────────────────────────────────────────────────────
	body = append(body, 0x01)
	body = utils.AppendULEB128(body, uint32(totalLocals))
	body = append(body, 0x7F)

	// ── Initialise pos=0, sp=stackBase, state=prog.Start ────────────────────
	body = append(body, 0x41, 0x00) // i32.const 0
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
	body = append(body, 0x4D)             // i32.le_u
	body = append(body, 0x04, 0x40)       // if void
	body = append(body, 0x41, 0x7F)       // i32.const -1
	body = append(body, 0x0F)             // return
	body = append(body, 0x0B)             // end if (empty)

	// Pop frame: sp -= frameSize
	body = append(body, 0x20, localSP) // local.get sp
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, frameSize)
	body = append(body, 0x6B)             // i32.sub
	body = append(body, 0x21, localSP)    // local.set sp

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

	// ── N nested blocks for PC dispatch ──────────────────────────────────────
	// Emit N blocks (outermost first).
	for i := 0; i < N; i++ {
		body = append(body, 0x02, 0x40) // block void
	}

	// br_table: local.get state; br_table 0 1 2 ... N-1 (default=0)
	body = append(body, 0x20, localState) // local.get state
	body = append(body, 0x0E)             // br_table
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

		body = emitBTInstHandler(body, bt, p, inst, brRun, loopLocalIdx, loopSnapBase, loopSnapLocals, stackBase, stackLimit, frameSize, numCapLocals)
	}

	body = append(body, 0x00) // unreachable (after all handlers, inside $run)
	body = append(body, 0x0B) // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1 (unreachable fallthrough)
	body = append(body, 0x0B) // end function
	return body
}

// emitBTInstHandler emits WASM for a single NFA instruction handler.
// brRun is the br depth (from handler top level) to restart $run.
func emitBTInstHandler(
	body []byte,
	bt *backtrack,
	p int,
	inst syntax.Inst,
	brRun uint32,
	loopLocalIdx  map[int]uint32,
	loopSnapBase  map[int]uint32,
	loopSnapLocals map[int][]uint32,
	stackBase, stackLimit, frameSize int32,
	numCapLocals int,
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
			pcU32 := uint32(p)
			// For greedy: Out < PC means body=Out(backward), exit=Arg(forward)
			// preferred=Out(body), retry=Arg(exit)
			// For non-greedy: Arg < PC means body=Arg(backward), exit=Out(forward)
			// preferred=Out(exit), retry=Arg(body)
			// In both cases: preferred=inst.Out, retry=inst.Arg.
			// Zero-progress: if pos == loop_pos_local, take retry directly (avoid infinite loop).
			_ = pcU32

			// if pos == loop_pos_local: take retry branch
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
			body = btSetStateAndBr(body, int32(inst.Arg), brRunNested)
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
			body = append(body, 0x45)             // i32.eqz
			body = append(body, 0x45)             // i32.eqz (NOT: nonzero = fail)
			body = append(body, 0x04, 0x40)       // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = btSetStateAndBr(body, int32(inst.Out), brRun)

		case emptyOp&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0:
			// fail if pos != len
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
			body = append(body, 0x47)             // i32.ne
			body = append(body, 0x04, 0x40)       // if void
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
		body = append(body, 0x47)             // i32.ne
		body = append(body, 0x04, 0x40)       // if void
		body = btFail(body, brRunNested)
		body = append(body, 0x0B)             // end if

		// Write captures to out_ptr and return pos.
		// Group 0: start = 0 (anchored), end = pos.
		body = append(body, 0x20, localOutPtr)
		body = append(body, 0x41, 0x00) // i32.const 0 (group 0 start)
		body = append(body, 0x36, 0x02) // i32.store align=2
		body = utils.AppendULEB128(body, 0) // offset=0

		body = append(body, 0x20, localOutPtr)
		body = append(body, 0x20, localPos)
		body = append(body, 0x36, 0x02) // i32.store align=2
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
	b = append(b, 0x41, 0x7F)    // i32.const -1
	b = append(b, 0x21, localState) // local.set state
	b = append(b, 0x0C)          // br
	b = utils.AppendULEB128(b, brDepth)
	return b
}

// btSetStateAndBr emits: state = nextPC; br brDepth
func btSetStateAndBr(b []byte, nextPC int32, brDepth uint32) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, nextPC)
	b = append(b, 0x21, localState) // local.set state
	b = append(b, 0x0C)            // br
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
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
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
	b = append(b, 0x0B) // end block $prevWord → prevIsWord on stack

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
	b = append(b, 0x0B) // end block $nextWord → nextIsWord on stack

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
	b = append(b, 0x4E) // i32.le_u
	b = append(b, 0x71) // i32.and
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


