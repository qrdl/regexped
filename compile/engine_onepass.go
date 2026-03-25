package compile

import (
	"regexp/syntax"
	"unicode"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// OnePass automaton

// captureOp records an open or close event for a capture group.
type captureOp struct {
	open  bool // true=open (record start), false=close (record end)
	group int  // capture group index (0 = whole match)
}

// onePass is a compiled one-pass NFA.
// States are NFA instruction PCs (0..numStates-1).
// The transition table maps (pc*256+byte) → next_pc (0xFF = dead).
type onePass struct {
	numStates   int
	numGroups   int // prog.NumCap / 2  (includes group 0)
	startPC     int
	acceptPC    int // PC of InstMatch

	// transitions[pc*256+byte] = next_pc (u8; 0xFF = dead)
	transitions []byte

	// captureOps[pc*256+byte] = capture ops to apply before transitioning.
	// nil slice means no ops for this (pc, byte) pair.
	captureOps [][]captureOp

	// eofAccept[pc] = (canAccept, opsToApply) at end of input.
	eofAccept    []bool
	eofAcceptOps [][]captureOp

	hasBeginAnchor bool
	hasEndAnchor   bool
}

func (o *onePass) Type() EngineType { return EngineOnePass }

// newOnePass builds the OnePass automaton from a compiled NFA program.
// The caller must have verified isOnePass(prog) == true.
func newOnePass(prog *syntax.Prog) *onePass {
	n := len(prog.Inst)
	op := &onePass{
		numStates:    n,
		numGroups:    prog.NumCap / 2,
		startPC:      prog.Start,
		acceptPC:     -1,
		transitions:  make([]byte, n*256),
		captureOps:   make([][]captureOp, n*256),
		eofAccept:    make([]bool, n),
		eofAcceptOps: make([][]captureOp, n),
	}

	// Initialise all transitions to 0xFF (dead).
	for i := range op.transitions {
		op.transitions[i] = 0xFF
	}

	// Find acceptPC and detect anchors.
	for pc, inst := range prog.Inst {
		if inst.Op == syntax.InstMatch {
			op.acceptPC = pc
		}
		if inst.Op == syntax.InstEmptyWidth {
			ew := syntax.EmptyOp(inst.Arg)
			if ew&(syntax.EmptyBeginText|syntax.EmptyBeginLine) != 0 {
				op.hasBeginAnchor = true
			}
			if ew&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0 {
				op.hasEndAnchor = true
			}
		}
	}

	// Build transition table and capture ops.
	for pc := 0; pc < n; pc++ {
		for bv := 0; bv < 256; bv++ {
			visited := make(map[int]bool)
			nextPC, cops := transFromPC(prog, pc, byte(bv), visited)
			if nextPC >= 0 && nextPC < 256 {
				op.transitions[pc*256+bv] = byte(nextPC)
				if len(cops) > 0 {
					op.captureOps[pc*256+bv] = cops
				}
			}
		}
	}

	// Build EOF-accept table.
	for pc := 0; pc < n; pc++ {
		visited := make(map[int]bool)
		ok, cops := eofAcceptFromPC(prog, pc, visited)
		op.eofAccept[pc] = ok
		if ok {
			op.eofAcceptOps[pc] = cops
		}
	}

	return op
}

// transFromPC: given current NFA state pc and input byte b, returns
// (nextPC, captureOps). Returns (-1, nil) if b cannot be consumed from pc.
func transFromPC(prog *syntax.Prog, pc int, b byte, visited map[int]bool) (int, []captureOp) {
	if pc < 0 || pc >= len(prog.Inst) {
		return -1, nil
	}
	if visited[pc] {
		return -1, nil
	}
	visited[pc] = true

	inst := prog.Inst[pc]
	switch inst.Op {
	case syntax.InstRune1:
		r := inst.Rune[0]
		matches := rune(b) == r
		if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
			matches = matches || unicode.ToLower(rune(b)) == unicode.ToLower(r)
		}
		if matches {
			return int(inst.Out), nil
		}
		return -1, nil

	case syntax.InstRune:
		if matchesRuneInstOP(&inst, rune(b)) {
			return int(inst.Out), nil
		}
		return -1, nil

	case syntax.InstRuneAny:
		return int(inst.Out), nil

	case syntax.InstRuneAnyNotNL:
		if b != '\n' {
			return int(inst.Out), nil
		}
		return -1, nil

	case syntax.InstCapture:
		var op captureOp
		if inst.Arg&1 == 0 {
			op = captureOp{open: true, group: int(inst.Arg >> 1)}
		} else {
			op = captureOp{open: false, group: int(inst.Arg >> 1)}
		}
		nextPC, ops := transFromPC(prog, int(inst.Out), b, visited)
		if nextPC < 0 {
			return -1, nil
		}
		return nextPC, append([]captureOp{op}, ops...)

	case syntax.InstNop:
		return transFromPC(prog, int(inst.Out), b, visited)

	case syntax.InstAlt, syntax.InstAltMatch:
		nextPC, ops := transFromPC(prog, int(inst.Out), b, visited)
		if nextPC >= 0 {
			return nextPC, ops
		}
		return transFromPC(prog, int(inst.Arg), b, visited)

	case syntax.InstEmptyWidth:
		emptyOp := syntax.EmptyOp(inst.Arg)
		// End anchors ($, \z) fire only at end of input — block mid-stream.
		if emptyOp&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0 {
			return -1, nil
		}
		// Begin anchors (^, \A) were satisfied at position 0 — follow through.
		return transFromPC(prog, int(inst.Out), b, visited)

	case syntax.InstMatch:
		return -1, nil // no byte consumed on path to InstMatch
	}
	return -1, nil
}

// eofAcceptFromPC reports whether the NFA can accept at EOF from state pc.
func eofAcceptFromPC(prog *syntax.Prog, pc int, visited map[int]bool) (bool, []captureOp) {
	if pc < 0 || pc >= len(prog.Inst) {
		return false, nil
	}
	if visited[pc] {
		return false, nil
	}
	visited[pc] = true

	inst := prog.Inst[pc]
	switch inst.Op {
	case syntax.InstMatch:
		return true, nil

	case syntax.InstCapture:
		var op captureOp
		if inst.Arg&1 == 0 {
			op = captureOp{open: true, group: int(inst.Arg >> 1)}
		} else {
			op = captureOp{open: false, group: int(inst.Arg >> 1)}
		}
		ok, ops := eofAcceptFromPC(prog, int(inst.Out), visited)
		if ok {
			return true, append([]captureOp{op}, ops...)
		}
		return false, nil

	case syntax.InstNop:
		return eofAcceptFromPC(prog, int(inst.Out), visited)

	case syntax.InstAlt, syntax.InstAltMatch:
		ok, ops := eofAcceptFromPC(prog, int(inst.Out), visited)
		if ok {
			return true, ops
		}
		return eofAcceptFromPC(prog, int(inst.Arg), visited)

	case syntax.InstEmptyWidth:
		return eofAcceptFromPC(prog, int(inst.Out), visited)
	}
	return false, nil
}

// matchesRuneInstOP reports whether rune r (ASCII) matches an InstRune instruction.
func matchesRuneInstOP(inst *syntax.Inst, r rune) bool {
	if r > 127 {
		return false
	}
	isFold := syntax.Flags(inst.Arg)&syntax.FoldCase != 0
	for i := 0; i+1 < len(inst.Rune); i += 2 {
		lo, hi := inst.Rune[i], inst.Rune[i+1]
		if hi > 0x7F {
			hi = 0x7F
		}
		if lo > hi {
			continue
		}
		if lo <= r && r <= hi {
			return true
		}
		if isFold {
			lr := unicode.ToLower(r)
			if unicode.ToLower(lo) <= lr && lr <= unicode.ToLower(hi) {
				return true
			}
		}
	}
	return false
}

// --------------------------------------------------------------------------
// WASM emission

// onePassTypeEntry returns the raw type entry bytes for the groups function type:
// (i32, i32, i32) → i32. Does not include the count prefix.
func onePassTypeEntry() []byte {
	return []byte{
		0x60,                   // func
		0x03, 0x7F, 0x7F, 0x7F, // 3 i32 params
		0x01, 0x7F,             // 1 i32 result
	}
}

// onePassExportEntry returns the raw export entry bytes for an export of the
// groups function. funcIdx is the 0-based function index in the module.
func onePassExportEntry(name string, funcIdx int) []byte {
	var b []byte
	b = appendString(b, name)
	b = append(b, 0x00) // func kind
	b = utils.AppendULEB128(b, uint32(funcIdx))
	return b
}

// onePassCodeEntry returns a complete code-section body for the groups function
// (size-prefixed, ready to append to the code section payload).
func onePassCodeEntry(op *onePass, transOff int32) []byte {
	body := buildOnePassBody(op, transOff)
	var b []byte
	b = utils.AppendULEB128(b, uint32(len(body)))
	b = append(b, body...)
	return b
}

// appendOnePassCodeEntry appends a size-prefixed OnePass capture body to cs.
func appendOnePassCodeEntry(cs []byte, op *onePass, transOff int32) []byte {
	return append(cs, onePassCodeEntry(op, transOff)...)
}

// onePassDataEntry returns the raw data segment for the OnePass transition table
// (no count prefix — caller manages the segment count).
func onePassDataEntry(op *onePass, tableBase int64) []byte {
	var b []byte
	return appendDataSegment(b, int32(tableBase), op.transitions)
}

// genOnePassWASM generates a WASM module exporting a groups function.
//
// When findDFAL is nil: emits a single anchored groups function (1 function).
//
// When findDFAL is non-nil: emits three functions:
//
//	func 0: find_internal (i32,i32)→i64       — not exported, LF DFA find
//	func 1: capture_internal (i32,i32,i32)→i32 — not exported, OnePass body
//	func 2: groups_exported (i32,i32,i32)→i32  — exported as exportName
func genOnePassWASM(op *onePass, tableBase int64, exportName string, standalone bool, memPages int32, findDFAL *dfaLayout) []byte {
	transOff := int32(tableBase)

	var typeContent, funcContent, exportContent, codeContent, dataContent []byte

	if findDFAL != nil {
		// 3-function module.
		typeContent = []byte{
			0x02,
			0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E,      // type 0: (i32,i32)→i64
			0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 1: (i32,i32,i32)→i32
		}
		funcContent = []byte{0x03, 0x00, 0x01, 0x01}

		numExports := byte(1)
		if standalone {
			numExports = 2
		}
		exportContent = append(exportContent, numExports)
		exportContent = append(exportContent, onePassExportEntry(exportName, 2)...)
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
		capBody := buildOnePassBody(op, transOff)
		wrapBody := buildGroupsWrapperBody(0, 1, op.numGroups, true)

		var fe, ce, we []byte
		fe = utils.AppendULEB128(fe, uint32(len(findBody))); fe = append(fe, findBody...)
		ce = utils.AppendULEB128(ce, uint32(len(capBody))); ce = append(ce, capBody...)
		we = utils.AppendULEB128(we, uint32(len(wrapBody))); we = append(we, wrapBody...)
		codeContent = append(append(append([]byte{0x03}, fe...), ce...), we...)

		// Data: find DFA tables + OnePass transition table.
		findDS := dfaDataSegments(findDFAL, true)
		findDS[0]++
		findDS = append(findDS, onePassDataEntry(op, tableBase)...)
		dataContent = findDS
	} else {
		// 1-function module: anchored groups only.
		typeContent = append(typeContent, 0x01)
		typeContent = append(typeContent, onePassTypeEntry()...)
		funcContent = []byte{0x01, 0x00}

		if standalone {
			exportContent = append(exportContent, 0x02)
			exportContent = append(exportContent, onePassExportEntry(exportName, 0)...)
			exportContent = appendString(exportContent, "memory")
			exportContent = append(exportContent, 0x02, 0x00)
		} else {
			exportContent = append(exportContent, 0x01)
			exportContent = append(exportContent, onePassExportEntry(exportName, 0)...)
		}

		codeContent = append([]byte{0x01}, onePassCodeEntry(op, transOff)...)
		dataContent = append([]byte{0x01}, onePassDataEntry(op, tableBase)...)
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)
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
	out = appendSection(out, 11, dataContent)

	return out
}


// buildOnePassBody emits the WASM function body.
//
// Locals: 0=ptr(param), 1=len(param), 2=out_ptr(param),
//         3=pc(i32), 4=pos(i32), 5=byte(i32), 6=next_pc(i32)
func buildOnePassBody(op *onePass, transOff int32) []byte {
	var b []byte

	// Declare 4 i32 locals (params are not re-declared).
	b = append(b, 0x01, 0x04, 0x7F)

	// ── Initialise capture slots to -1 ──────────────────────────────────────
	for i := 0; i < op.numGroups*2; i++ {
		b = append(b, 0x20, 0x02) // local.get out_ptr
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x36, 0x00) // i32.store align=0
		b = utils.AppendULEB128(b, uint32(i*4))
	}

	// ── Set initial pc and pos ───────────────────────────────────────────────
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(op.startPC))
	b = append(b, 0x21, 0x03) // local.set pc

	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x21, 0x04) // local.set pos

	// Group 0 (full match) always starts at position 0 for anchored match.
	// Go's NFA may not emit InstCapture for group 0 before prog.Start,
	// so we hardcode it here rather than relying on NFA op tracking.
	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x36, 0x00) // i32.store align=0
	b = utils.AppendULEB128(b, 0) // offset=0 (group 0 start)

	// ── Main loop ────────────────────────────────────────────────────────────
	b = append(b, 0x03, 0x40) // loop $scan

	// EOF check: if pos >= len
	b = append(b, 0x20, 0x04) // local.get pos
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitOnePassEofHandler(op, b)
	b = append(b, 0x0B) // end if

	// Load byte.
	b = append(b, 0x20, 0x00)       // local.get ptr
	b = append(b, 0x20, 0x04)       // local.get pos
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, 0x05)       // local.set byte

	// Table lookup: next_pc = transitions[transOff + pc*256 + byte]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, transOff)
	b = append(b, 0x20, 0x03) // local.get pc
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 256)
	b = append(b, 0x6C)       // i32.mul
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x20, 0x05) // local.get byte
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, 0x06)       // local.set next_pc

	// Dead state: if next_pc == 0xFF → return -1
	b = append(b, 0x20, 0x06) // local.get next_pc
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 255)
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// Apply capture ops for (pc, byte).
	b = emitOnePassCaptureOps(op, b)

	// Accept: if next_pc == acceptPC → write group 0 end = pos+1 and return
	if op.acceptPC >= 0 {
		b = append(b, 0x20, 0x06) // local.get next_pc
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(op.acceptPC))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)
		// group 0 end = pos+1
		b = append(b, 0x20, 0x02) // local.get out_ptr
		b = append(b, 0x20, 0x04) // local.get pos
		b = append(b, 0x41, 0x01) // i32.const 1
		b = append(b, 0x6A)       // i32.add
		b = append(b, 0x36, 0x00) // i32.store align=0
		b = utils.AppendULEB128(b, 4) // offset=4 (group 0 end)
		b = append(b, 0x20, 0x04) // local.get pos
		b = append(b, 0x41, 0x01) // i32.const 1
		b = append(b, 0x6A)       // i32.add
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	}

	// Advance.
	b = append(b, 0x20, 0x06) // local.get next_pc
	b = append(b, 0x21, 0x03) // local.set pc
	b = append(b, 0x20, 0x04) // local.get pos
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x21, 0x04) // local.set pos
	b = append(b, 0x0C, 0x00) // br 0 → $scan

	b = append(b, 0x0B)       // end loop $scan
	b = append(b, 0x41, 0x7F) // i32.const -1 (unreachable fallthrough)
	b = append(b, 0x0B)       // end function
	return b
}

// emitOnePassEofHandler emits the EOF branch body (inside an if block).
func emitOnePassEofHandler(op *onePass, b []byte) []byte {
	for pc := 0; pc < op.numStates; pc++ {
		if !op.eofAccept[pc] {
			continue
		}
		b = append(b, 0x20, 0x03) // local.get pc
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(pc))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)
		for _, cop := range op.eofAcceptOps[pc] {
			// Skip group 0 close — handled by hardcoded write below.
			if !cop.open && cop.group == 0 {
				continue
			}
			b = emitOnePassCaptureOp(cop, b)
		}
		// Write group 0 end = pos (end of match at EOF).
		b = append(b, 0x20, 0x02) // local.get out_ptr
		b = append(b, 0x20, 0x04) // local.get pos
		b = append(b, 0x36, 0x00) // i32.store align=0
		b = utils.AppendULEB128(b, 4) // offset=4 (group 0 end)
		b = append(b, 0x20, 0x04) // local.get pos
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	}
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	return b
}

// emitOnePassCaptureOps emits the inline capture op if-chain.
func emitOnePassCaptureOps(op *onePass, b []byte) []byte {
	for pc := 0; pc < op.numStates; pc++ {
		// Collect (byte, ops) pairs with non-empty ops for this pc.
		type byteOps struct {
			bv  int
			ops []captureOp
		}
		var entries []byteOps
		for bv := 0; bv < 256; bv++ {
			if cops := op.captureOps[pc*256+bv]; len(cops) > 0 {
				entries = append(entries, byteOps{bv, cops})
			}
		}
		if len(entries) == 0 {
			continue
		}

		b = append(b, 0x20, 0x03) // local.get pc
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(pc))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)

		// Check if all entries have identical ops (common for character classes).
		allSame := true
		for i := 1; i < len(entries); i++ {
			if !captureOpsEqual(entries[0].ops, entries[i].ops) {
				allSame = false
				break
			}
		}

		if allSame {
			// All valid bytes for this pc have the same ops — no byte check needed.
			for _, cop := range entries[0].ops {
				b = emitOnePassCaptureOp(cop, b)
			}
		} else {
			// Different ops per byte: emit per-byte checks.
			for _, e := range entries {
				b = append(b, 0x20, 0x05) // local.get byte
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(e.bv))
				b = append(b, 0x46)       // i32.eq
				b = append(b, 0x04, 0x40) // if (void)
				for _, cop := range e.ops {
					b = emitOnePassCaptureOp(cop, b)
				}
				b = append(b, 0x0B) // end if
			}
		}

		b = append(b, 0x0B) // end if pc == X
	}
	return b
}

// emitOnePassCaptureOp emits: i32.store(out_ptr + offset, pos)
// where offset = group*8 for open, group*8+4 for close.
func emitOnePassCaptureOp(cop captureOp, b []byte) []byte {
	offset := uint32(cop.group * 8)
	if !cop.open {
		offset += 4
	}
	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x20, 0x04) // local.get pos
	b = append(b, 0x36, 0x00) // i32.store align=0
	b = utils.AppendULEB128(b, offset)
	return b
}

func captureOpsEqual(a, b []captureOp) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
