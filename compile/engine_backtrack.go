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

// CompileBacktrackGroups compiles a pattern to a backtracking WASM module
// exporting a non-anchored groups function: (ptr i32, len i32, out_ptr i32) → i32.
// The module contains find_internal (LF DFA find), capture_internal (LL DFA + NFA),
// and a groups_exported wrapper that calls find_internal then capture_internal.
func CompileBacktrackGroups(pattern, exportName string, tableBase int64, standalone bool) ([]byte, int64, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, 0, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, 0, err
	}
	bt := newBacktrack(prog)

	// Re-parse to get stripped program (stripCaptures mutates in place).
	reStripped, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, 0, err
	}
	stripCaptures(reStripped)
	progStripped, err := syntax.Compile(reStripped.Simplify())
	if err != nil {
		return nil, 0, err
	}

	// Find DFA (LF, find mode) — only needed for non-anchored patterns.
	dFind := newDFA(progStripped, false, true) // unicode=false, leftmostFirst=true
	tFind := dfaTableFrom(dFind)

	var findDFAL *dfaLayout
	captureDFABase := tableBase
	if !isAnchoredFind(tFind) {
		// Non-anchored: include find DFA tables; capture DFA follows.
		findDFAL = buildDFALayout(tFind, tableBase, true, true)
		captureDFABase = utils.PageAlign(findDFAL.tableEnd)
	}

	// Phase 1 DFA (LL, match mode) for capture_internal.
	captureDFAL := compileDFAForBacktrack(progStripped, captureDFABase)

	// Backtrack stack after all DFA tables.
	btTableBase := utils.PageAlign(captureDFAL.tableEnd)

	wasmBytes, tableEnd := genBacktrackWASM(bt, btTableBase, exportName, standalone, captureDFAL, findDFAL)
	return wasmBytes, tableEnd, nil
}

// compileDFAForBacktrack builds a dfaLayout for the captures-stripped pattern,
// used as Phase 1 in the hybrid backtracking function.
// tableBase is the memory offset where DFA tables are placed.
func compileDFAForBacktrack(progStripped *syntax.Prog, tableBase int64) *dfaLayout {
	// leftmostFirst=false: standard leftmost-longest DFA semantics for anchored match.
	// Phase 1 uses LL semantics to determine the correct RE2 match extent for Phase 2.
	d := newDFA(progStripped, false, false)
	t := dfaTableFrom(d)
	return buildDFALayout(t, tableBase, false, false)
}

// genBacktrackWASM generates a WASM module exporting a groups function.
//
// When findDFAL is nil: emits a single anchored groups function (1 function):
//
//	(ptr: i32, len: i32, out_ptr: i32) → i32
//
// When findDFAL is non-nil: emits three functions:
//
//	func 0: find_internal (i32,i32)→i64       — not exported, LF DFA find
//	func 1: capture_internal (i32,i32,i32)→i32 — not exported, Phase 1 LL + NFA
//	func 2: groups_exported (i32,i32,i32)→i32  — exported as exportName, calls 0 then 1
//
// dfaL is the layout for the Phase 1 LL match DFA used inside capture_internal.
// findDFAL (when non-nil) is the layout for the LF find DFA used inside find_internal.
// tableBase is the start of the backtracking stack (after all DFA data).
func genBacktrackWASM(bt *backtrack, tableBase int64, exportName string, standalone bool, dfaL *dfaLayout, findDFAL *dfaLayout) ([]byte, int64) {
	numCapLocals := bt.numGroups * 2
	// frameSize = 4 (pos) + numCapLocals*4 (captures) + 4 (retry PC)
	frameSize := 4 + numCapLocals*4 + 4
	// Stack depth: each InstAlt can push one frame per input byte in the worst
	// case (loop iterates once per byte). Use numAlts * 4096 as a generous bound;
	// minimum 4096 frames to handle short-but-complex nested-loop patterns.
	maxFrames := bt.numAlts * 4096
	if maxFrames < 4096 {
		maxFrames = 4096
	}
	stackSize := maxFrames * frameSize
	tableEnd := utils.PageAlign(tableBase + int64(stackSize))
	memPages := int32(tableEnd / 65536)
	stackBase := int32(tableBase)
	stackLimit := stackBase + int32(stackSize)

	captureBody := buildBacktrackBody(bt, stackBase, stackLimit, int32(frameSize), dfaL)

	var typeContent, funcContent, exportContent, codeContent []byte

	if findDFAL != nil {
		// 3-function module: find_internal (0), capture_internal (1), groups_exported (2).
		typeContent = []byte{
			0x02,                                        // 2 types
			0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E,         // type 0: (i32,i32)→i64
			0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,   // type 1: (i32,i32,i32)→i32
		}
		funcContent = []byte{0x03, 0x00, 0x01, 0x01} // 3 funcs: type0, type1, type1

		numExports := byte(1)
		if standalone {
			numExports = 2
		}
		exportContent = append(exportContent, numExports)
		exportContent = append(exportContent, btExportEntry(exportName, 2)...) // export func 2
		if standalone {
			exportContent = appendString(exportContent, "memory")
			exportContent = append(exportContent, 0x02, 0x00)
		}

		findBody := buildFindBody(
			findDFAL.wasmStart, findDFAL.wasmMidStart, findDFAL.wasmMidStartWord,
			findDFAL.wasmPrefixEnd, findDFAL.tableOff, findDFAL.acceptOff, findDFAL.midAcceptOff,
			findDFAL.firstByteOff, findDFAL.prefix, findDFAL.classMapOff, findDFAL.numClasses,
			findDFAL.useU8, findDFAL.useCompression, findDFAL.startBeginAccept,
			findDFAL.immediateAcceptOff, findDFAL.hasImmAccept,
			findDFAL.wordCharTableOff, findDFAL.needWordCharTable,
			findDFAL.midAcceptNWOff, findDFAL.midAcceptWOff,
			findDFAL.firstByteFlags, findDFAL.firstBytes,
			findDFAL.teddyLoOff, findDFAL.teddyHiOff,
			findDFAL.teddyT1LoOff, findDFAL.teddyT1HiOff, len(findDFAL.teddyT1LoBytes) > 0,
			findDFAL.teddyT2LoOff, findDFAL.teddyT2HiOff, len(findDFAL.teddyT2LoBytes) > 0,
			nil, findDFAL.rowMapOff, findDFAL.useRowDedup)
		wrapperBody := buildGroupsWrapperBody(0, 1, bt.numGroups, false)

		var fe, ce, we []byte
		fe = utils.AppendULEB128(fe, uint32(len(findBody))); fe = append(fe, findBody...)
		ce = utils.AppendULEB128(ce, uint32(len(captureBody))); ce = append(ce, captureBody...)
		we = utils.AppendULEB128(we, uint32(len(wrapperBody))); we = append(we, wrapperBody...)
		codeContent = append(append(append([]byte{0x03}, fe...), ce...), we...)
	} else {
		// 1-function module: anchored groups only.
		typeContent = []byte{0x01, 0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F}
		funcContent = []byte{0x01, 0x00}

		numExports := byte(1)
		if standalone {
			numExports = 2
		}
		exportContent = append(exportContent, numExports)
		exportContent = append(exportContent, btExportEntry(exportName, 0)...)
		if standalone {
			exportContent = appendString(exportContent, "memory")
			exportContent = append(exportContent, 0x02, 0x00)
		}

		var codeEntry []byte
		codeEntry = utils.AppendULEB128(codeEntry, uint32(len(captureBody)))
		codeEntry = append(codeEntry, captureBody...)
		codeContent = append([]byte{0x01}, codeEntry...)
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D) // magic
	out = append(out, 0x01, 0x00, 0x00, 0x00) // version

	out = appendSection(out, 1, typeContent)

	if !standalone {
		var importContent []byte
		importContent = append(importContent, 0x01)
		importContent = appendString(importContent, "main")
		importContent = appendString(importContent, "memory")
		importContent = append(importContent, 0x02)
		importContent = append(importContent, 0x00)
		importContent = utils.AppendULEB128(importContent, 0x00)
		out = appendSection(out, 2, importContent)
	}

	out = appendSection(out, 3, funcContent)

	if standalone {
		var memContent []byte
		memContent = append(memContent, 0x01, 0x00)
		memContent = utils.AppendULEB128(memContent, uint32(memPages))
		out = appendSection(out, 5, memContent)
	}

	out = appendSection(out, 7, exportContent)
	out = appendSection(out, 10, codeContent)

	// Data section.
	var dfaDS []byte
	if findDFAL != nil {
		// find DFA tables + capture DFA tables.
		findDS := dfaDataSegments(findDFAL, true)
		capDS := dfaDataSegments(dfaL, false)
		findDS[0] += capDS[0]
		dfaDS = append(findDS, capDS[1:]...)
		if !standalone {
			dfaDS[0]++
			dfaDS = appendDataSegment(dfaDS, int32(tableEnd-1), []byte{0x00})
		}
	} else {
		// Capture DFA tables only + sentinel for non-standalone.
		dfaDS = dfaDataSegments(dfaL, false)
		if !standalone {
			dfaDS[0]++
			dfaDS = appendDataSegment(dfaDS, int32(tableEnd-1), []byte{0x00})
		}
	}
	out = appendSection(out, 11, dfaDS)

	return out, tableEnd
}

// btExportEntry returns the export entry for the groups function.
func btExportEntry(name string, funcIdx int) []byte {
	var b []byte
	b = appendString(b, name)
	b = append(b, 0x00) // func kind
	b = utils.AppendULEB128(b, uint32(funcIdx))
	return b
}

// --------------------------------------------------------------------------
// Local variable layout
//
// Index  Purpose
//   0    ptr      (param)
//   1    len      (param)
//   2    out_ptr  (param)
//   3    pos      i32
//   4    sp       i32  (stack pointer)
//   5    state    i32  (current NFA PC; -1 = FAIL)
//   6    scratch  i32  (temporary, e.g. for word-char byte)
//   7 + i*2      cap_i_start  (i = 0..numGroups-1)
//   8 + i*2      cap_i_end
//   7 + numGroups*2 + j   loop_pos for j-th loop PC (sorted)
//
// capStartLocal(i) = 7 + i*2
// capEndLocal(i)   = 8 + i*2
// loopPosLocal(j)  = 7 + numGroups*2 + j

const (
	localPtr     = 0
	localLen     = 1
	localOutPtr  = 2
	localPos     = 3
	localSP      = 4
	localState   = 5
	localScratch = 6
)

func capStartLocal(i int) uint32 { return uint32(7 + i*2) }
func capEndLocal(i int) uint32   { return uint32(8 + i*2) }

// buildBacktrackBody emits the WASM function body for the backtracking NFA.
// dfaL is the layout for the captures-stripped DFA used in Phase 1.
func buildBacktrackBody(bt *backtrack, stackBase, stackLimit, frameSize int32, dfaL *dfaLayout) []byte {
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

	// Phase 1 DFA locals: dfaStateLocal, dfaPosLocal, btEndLocal.
	// They follow after all existing locals.
	baseExtra := uint32(7 + numCapLocals + len(loopPCsSorted))
	dfaStateLocal := baseExtra         // DFA state scratch for Phase 1
	dfaPosLocal   := baseExtra + 1     // DFA position scratch for Phase 1
	btEndLocal    := baseExtra + 2     // DFA-determined match end (or -1)
	dfaClassLocal := baseExtra + 3

	// Loop capture snapshot locals: for each loop PC, numCapLocals snapshot slots.
	// When a loop makes progress, we save all cap locals here.
	// When zero-progress is detected, we restore from here before taking retry.
	// This ensures inner groups retain their last non-empty match value.
	loopSnapBase := make(map[int]uint32, len(loopPCsSorted))
	for j, pc := range loopPCsSorted {
		loopSnapBase[pc] = baseExtra + 4 + uint32(j*numCapLocals)
	}

	// Total non-param locals: pos, sp, state, scratch, cap0s, cap0e, ...,
	// loop_pos..., dfaState, dfaPos, btEnd, dfaClass, loop_snap...
	totalLocals := 4 + numCapLocals + len(loopPCsSorted) + 4 + len(loopPCsSorted)*numCapLocals

	var body []byte

	// ── Local declarations ────────────────────────────────────────────────────
	// Declare all as a single group of i32s.
	body = append(body, 0x01)                              // 1 declaration entry
	body = utils.AppendULEB128(body, uint32(totalLocals))  // count
	body = append(body, 0x7F)                              // type: i32

	// ── Phase 1: DFA anchored match to determine extent ──────────────────────
	// Initialise dfaPos = 0 (dfaState is set inside buildMatchBodyInline).
	body = append(body, 0x41, 0x00) // i32.const 0
	body = append(body, 0x21)       // local.set
	body = utils.AppendULEB128(body, dfaPosLocal)

	body = buildMatchBodyInline(body,
		dfaL.wasmStart,
		dfaL.tableOff, dfaL.acceptOff, dfaL.classMapOff,
		dfaL.numClasses,
		dfaL.useU8, dfaL.useCompression,
		dfaL.immediateAcceptOff, dfaL.hasImmAccept,
		uint32(localPtr), uint32(localLen),
		dfaStateLocal, dfaPosLocal, dfaClassLocal,
		dfaL.rowMapOff, dfaL.useRowDedup,
	)
	// buildMatchBodyInline leaves result (pos or -1) on stack — store to btEndLocal.
	body = append(body, 0x21)
	body = utils.AppendULEB128(body, btEndLocal)

	// If btEndLocal == -1: return -1 immediately (no DFA match).
	body = append(body, 0x20)
	body = utils.AppendULEB128(body, btEndLocal)
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x46)       // i32.eq
	body = append(body, 0x04, 0x40) // if void
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x0F)       // return
	body = append(body, 0x0B)       // end if

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
	for _, snapBase := range loopSnapBase {
		for i := 0; i < numCapLocals; i++ {
			body = append(body, 0x41, 0x7F) // i32.const -1
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, snapBase+uint32(i))
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

		body = emitBTInstHandler(body, bt, p, inst, brRun, loopLocalIdx, loopSnapBase, stackBase, stackLimit, frameSize, numCapLocals)
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
	loopLocalIdx map[int]uint32,
	loopSnapBase map[int]uint32,
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
			// Restore cap locals from snapshot (last non-empty iteration).
			if snapBase, ok := loopSnapBase[p]; ok {
				for i := 0; i < numCapLocals; i++ {
					body = append(body, 0x20)
					body = utils.AppendULEB128(body, snapBase+uint32(i))
					body = append(body, 0x21)
					body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
				}
			}
			body = btSetStateAndBr(body, int32(inst.Arg), brRunNested)
			body = append(body, 0x0B) // end if

			// Progress: update loop_pos_local = pos
			body = append(body, 0x20, localPos)
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, loopLocal)

			// Save cap locals to snapshot.
			if snapBase, ok := loopSnapBase[p]; ok {
				for i := 0; i < numCapLocals; i++ {
					body = append(body, 0x20)
					body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
					body = append(body, 0x21)
					body = utils.AppendULEB128(body, snapBase+uint32(i))
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

	for i := 0; i+1 < len(inst.Rune); i += 2 {
		lo := inst.Rune[i]
		hi := inst.Rune[i+1]
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

// genHybridWASMWithBacktrack generates a WASM module combining a DFA (match and/or
// find) with a backtracking NFA (groups), all sharing one memory.
// When groups are needed, three functions are emitted:
//   - find_internal (not exported): locates leftmost match start
//   - capture_internal (not exported): Phase 1 DFA + Phase 2 NFA for captures
//   - groups_wrapper (exported as groupsExport): calls find_internal then capture_internal
//
// captureDFAL is the Phase 1 DFA layout (LL match semantics, captures stripped).
func genHybridWASMWithBacktrack(
	t *dfaTable, dfaTableBase int64, matchExport, findExport string,
	bt *backtrack, btTableBase int64, groupsExport string,
	standalone bool, memPages int32, leftmostFirst bool, mandatoryLit *MandatoryLit,
	captureDFAL *dfaLayout,
) []byte {
	needFind := findExport != ""
	needMatch := matchExport != ""
	needGroups := bt != nil && groupsExport != ""
	// For non-anchored groups the wrapper needs find_internal; for anchored groups it doesn't.
	anchored := isAnchoredFind(t)
	needFindInternal := needFind || (needGroups && !anchored)

	l := buildDFALayout(t, dfaTableBase, needFindInternal, leftmostFirst)

	// Count types and functions
	numTypes := 0
	matchTypeIdx, findTypeIdx, groupsTypeIdx := -1, -1, -1
	var ts []byte
	if needMatch {
		matchTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F)
	}
	if needFindInternal {
		findTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E)
	}
	if needGroups {
		groupsTypeIdx = numTypes
		numTypes++
		ts = append(ts, onePassTypeEntry()...)
	}
	numDeclaredTypes := numTypes

	// Functions: match?, find_internal?, capture_internal?, groups_wrapper?
	numFuncs := numDeclaredTypes
	captureInternalIdx := -1
	if needGroups {
		captureInternalIdx = numFuncs
		numFuncs++ // capture_internal always added
		if !anchored {
			numFuncs++ // groups_wrapper only for non-anchored
		}
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)
	out = appendSection(out, 1, append(utils.AppendULEB128(nil, uint32(numDeclaredTypes)), ts...))

	if !standalone {
		var is []byte
		is = append(is, 0x01)
		is = appendString(is, "main")
		is = appendString(is, "memory")
		is = append(is, 0x02, 0x00)
		is = utils.AppendULEB128(is, 0x00)
		out = appendSection(out, 2, is)
	}

	// Function section
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(numFuncs))
	if needMatch {
		fs = utils.AppendULEB128(fs, uint32(matchTypeIdx))
	}
	if needFindInternal {
		fs = utils.AppendULEB128(fs, uint32(findTypeIdx))
	}
	if needGroups {
		fs = utils.AppendULEB128(fs, uint32(groupsTypeIdx)) // captureInternal
		if !anchored {
			fs = utils.AppendULEB128(fs, uint32(groupsTypeIdx)) // groupsWrapper
		}
	}
	out = appendSection(out, 3, fs)

	if standalone {
		var ms []byte
		ms = append(ms, 0x01, 0x00)
		ms = utils.AppendULEB128(ms, uint32(memPages))
		out = appendSection(out, 5, ms)
	}

	// Export section
	numExports := 0
	if standalone {
		numExports++
	}
	if needMatch {
		numExports++
	}
	if needFind {
		numExports++
	}
	if needGroups {
		numExports++
	}
	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02)
		es = utils.AppendULEB128(es, 0x00)
	}
	fIdx := 0
	if needMatch {
		es = appendString(es, matchExport)
		es = append(es, 0x00)
		es = utils.AppendULEB128(es, uint32(fIdx))
		fIdx++
	}
	if needFindInternal {
		if needFind {
			es = appendString(es, findExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(fIdx))
		}
		fIdx++
	}
	if needGroups {
		if anchored {
			// Anchored: export capture_internal directly (same as before).
			es = append(es, btExportEntry(groupsExport, fIdx)...)
			fIdx++
		} else {
			// Non-anchored: capture_internal is internal; export wrapper.
			fIdx++ // skip captureInternal
			es = append(es, btExportEntry(groupsExport, fIdx)...)
			fIdx++
		}
	}
	out = appendSection(out, 7, es)

	// Find function index for wrapper
	findFuncIdx := -1
	{
		cf := 0
		if needMatch {
			cf++
		}
		if needFindInternal {
			findFuncIdx = cf
			cf++
		}
		_ = cf
	}

	// Code section
	var cs []byte
	cs = utils.AppendULEB128(cs, uint32(numFuncs))
	if needMatch {
		body := buildMatchBody(l.wasmStart, l.tableOff, l.acceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.immediateAcceptOff, l.hasImmAccept, l.rowMapOff, l.useRowDedup)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needFindInternal {
		var body []byte
		if isAnchoredFind(t) {
			body = buildAnchoredFindBody(l.wasmStart, l.tableOff, l.acceptOff, l.midAcceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.rowMapOff, l.useRowDedup)
		} else {
			body = buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff, l.firstByteOff, l.prefix, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.firstByteFlags, l.firstBytes, l.teddyLoOff, l.teddyHiOff, l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0, l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0, mandatoryLit, l.rowMapOff, l.useRowDedup)
		}
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needGroups {
		numCapLocals := bt.numGroups * 2
		frameSize := int32(4 + numCapLocals*4 + 4)
		maxFrames := bt.numAlts * 4096
		if maxFrames < 4096 {
			maxFrames = 4096
		}
		btStackLimit := int32(btTableBase) + int32(maxFrames)*frameSize
		// capture_internal uses captureDFAL (separate LL match DFA)
		capBody := buildBacktrackBody(bt, int32(btTableBase), btStackLimit, frameSize, captureDFAL)
		cs = utils.AppendULEB128(cs, uint32(len(capBody)))
		cs = append(cs, capBody...)
		if !anchored {
			// groups_wrapper only for non-anchored patterns
			wrapBody := buildGroupsWrapperBody(findFuncIdx, captureInternalIdx, bt.numGroups, false)
			cs = utils.AppendULEB128(cs, uint32(len(wrapBody)))
			cs = append(cs, wrapBody...)
		}
	}
	out = appendSection(out, 10, cs)

	// Data section: main DFA tables + capture DFA tables
	dfaDS := dfaDataSegments(l, needFindInternal)
	if needGroups && captureDFAL != nil {
		capDS := dfaDataSegments(captureDFAL, false)
		dfaDS[0] += capDS[0]
		dfaDS = append(dfaDS, capDS[1:]...)
	}
	out = appendSection(out, 11, dfaDS)

	return out
}


