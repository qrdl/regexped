package compile

import (
	"errors"
	"fmt"
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Backtracking NFA engine

// backtrack is a compiled backtracking NFA.
// It handles capture patterns that cannot be processed by TDFA.
type backtrack struct {
	prog      *syntax.Prog
	numGroups int // prog.NumCap / 2 (includes group 0)
	numAlts   int // count of InstAlt nodes — bounds stack depth

	// zeroWidthCycle: the program can go round a cycle without consuming a
	// byte (progHasZeroWidthCycle). Such a program gets no ordinary body —
	// see planBT.
	zeroWidthCycle bool
}

func (b *backtrack) Type() EngineType { return EngineBacktrack }

// progHasZeroWidthCycle reports whether prog has a cycle made only of
// instructions that consume no byte: Alt, AltMatch, Capture, Nop and
// EmptyWidth. An assertion on the cycle may fail at run time; the cycle is
// still there structurally, which is what matters below.
//
// It decides whether the ORDINARY Backtracking body may run the program at
// all. Without such a cycle a (pc, pos) can only be reached again after its
// first visit has finished and failed — a revisit nested inside the first visit
// would be a path from (pc, pos) back to itself consuming nothing — so the
// search terminates with no loop guard of any kind, every revisit repeats a
// failure, and the body is Go's bitstate search without the bits: exact. With
// one, a loop can go round forever at one position, so the program runs on the
// memoised fallback body alone (planBT), under every budget setting.
//
// The ordinary body used to carry per-loop zero-progress trackers for these
// programs instead. They only approximated Go's "a thread that reaches an
// occupied (pc, pos) is dropped", and the approximation was wrong on a whole
// class: `(a*?)*?b` over "aab" reported group 1 as [1,2) where Go reports
// [0,2). A differential against Go found it wrong on 306 of 3,072 systematic
// nestings and 159 of 12,000 random nested patterns, every one with a
// zero-width cycle and none without.
func progHasZeroWidthCycle(prog *syntax.Prog) bool {
	const (
		unseen = iota
		onPath
		done
	)
	state := make([]byte, len(prog.Inst))
	var visit func(pc int) bool
	visit = func(pc int) bool {
		state[pc] = onPath
		inst := prog.Inst[pc]
		var next [2]int
		n := 0
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			next[0], next[1], n = int(inst.Out), int(inst.Arg), 2
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			next[0], n = int(inst.Out), 1
		}
		for _, to := range next[:n] {
			if state[to] == onPath || (state[to] == unseen && visit(to)) {
				return true
			}
		}
		state[pc] = done
		return false
	}
	for pc := range prog.Inst {
		if state[pc] == unseen && visit(pc) {
			return true
		}
	}
	return false
}

// newBacktrack builds the backtrack struct from a compiled NFA program.
func newBacktrack(prog *syntax.Prog) *backtrack {
	bt := &backtrack{prog: prog, numGroups: prog.NumCap / 2}
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstAlt {
			bt.numAlts++
		}
	}
	bt.zeroWidthCycle = progHasZeroWidthCycle(prog)
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

// btHasWordBoundary reports whether prog contains a \b/\B assertion —
// used to decide whether a non-anchored captureBody needs the edge-scratch
// mechanism: patterns without any \b/\B never emit
// btWordBoundary at all, so there's nothing for the scratch slot to fix and
// reserving/writing it would be pure overhead.
func btHasWordBoundary(prog *syntax.Prog) bool {
	for _, inst := range prog.Inst {
		if inst.Op != syntax.InstEmptyWidth {
			continue
		}
		emptyOp := syntax.EmptyOp(inst.Arg)
		if emptyOp&(syntax.EmptyWordBoundary|syntax.EmptyNoWordBoundary) != 0 {
			return true
		}
	}
	return false
}

// btHasTextLineAnchors reports whether prog contains a \A, \z, (?m:^) or
// (?m:$) assertion. Like btHasWordBoundary, these four assertions are
// defined against the true input edges, which a captureBody handed a
// narrowed match slice cannot see. Their presence is what switches the
// groups wrappers into window mode — see
// buildBacktrackBody's winGlobal.
func btHasTextLineAnchors(prog *syntax.Prog) bool {
	const mask = syntax.EmptyBeginText | syntax.EmptyEndText |
		syntax.EmptyBeginLine | syntax.EmptyEndLine
	for _, inst := range prog.Inst {
		if inst.Op != syntax.InstEmptyWidth {
			continue
		}
		if syntax.EmptyOp(inst.Arg)&mask != 0 {
			return true
		}
	}
	return false
}

// btLocalGet appends `local.get idx` for an arbitrary local index.
// Byte-identical to the hand-written `append(b, 0x20, localX)` form for
// every index below 128.
func btLocalGet(b []byte, idx uint32) []byte {
	b = append(b, 0x20)
	return utils.AppendULEB128(b, idx)
}

// appendBacktrackCodeEntry appends a size-prefixed capture body. callOffs are
// the byte offsets, within the returned slice, of the fallback calls'
// placeholder immediates (none when the body makes no such call).
func appendBacktrackCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize int32, nativeAnchored bool, tableMemIdx int, winGlobal int32, capStartGlobal int32, workK int, tripCalls bool, fallback *btScratch, member *btDriveMember) (out []byte, callOffs []int) {
	body, offs := buildBacktrackBody(bt, stackBase, stackLimit, frameSize, nativeAnchored, tableMemIdx, winGlobal, capStartGlobal, workK, tripCalls, fallback, member)
	sized, offs := btSizePrefix(body, offs)
	return append(cs, sized...), btShiftOffs(offs, len(cs))
}

// buildBacktrackBody emits the WASM function body for the backtracking NFA.
// The caller (wrapper) has already located the match extent via find_internal and
// passes a bounded slice (ptr=match_start, len=match_length). This function runs
// Phase 2 NFA only — no Phase 1 DFA traversal.
//
// nativeAnchored is true when this captureBody is exported directly as the
// pattern's groups function (compiledPattern.anchored, isAnchoredFind) instead
// of being composed behind a find wrapper — in that case len is the caller's
// full input length, not a DFA-narrowed match extent (see engine_tdfa.go's
// identically-named parameter for the TDFA-side counterpart of this fix).
//
// winGlobal (-1 = off) switches this body into WINDOW MODE, the fix for
// a past defect. In window mode the wrapper stops
// narrowing: it passes the caller's real (ptr,len) and stashes the match
// window as an (startOff,endOff) pair at this table-memory offset. This
// body then starts at pos=startOff, accepts at pos==endOff, and records
// capture positions already relative to the true ptr — so \b/\B, \A, \z,
// (?m:^) and (?m:$) all see the real input edges and need no side-channel
// fix-up, and the wrapper needs no per-slot rebasing pass afterwards.
// Byte consumption is still bounded by endOff (limitLocal), so window mode
// explores exactly the same positions the narrowed slice used to.
//
// workK > 0 adds the work budget (btWorkK): an i64 local, set once per call
// from the span the search ranges over, charged on every frame pop. tripCalls
// makes the body tail-call the fallback body (emitBTFallbackCall) wherever it
// would otherwise answer -2 — an exhausted budget or an overflowed frame stack
// — and callOffs report where those calls' indices go.
//
// fallback non-nil builds the FALLBACK body instead: the same emitter,
// memoised at every Alt (see emitBTInstHandler), with no budget of its own,
// whose frame stack and memo are sized from the input at call time and found
// through the globals fallback names (bt_scratch.go). stackBase and stackLimit
// are then unused.
//
// Neither body carries a loop guard. The ordinary body runs only programs
// without a zero-width cycle (planBT), where no guard can fire; the fallback's
// memo is what terminates it on the others.
func buildBacktrackBody(bt *backtrack, stackBase, stackLimit, frameSize int32, nativeAnchored bool, tableMemIdx int, winGlobal int32, capStartGlobal int32, workK int, tripCalls bool, fallback *btScratch, member *btDriveMember) (_ []byte, callOffs []int) {
	if member != nil && winGlobal < 0 {
		panic("compile: a set member's Backtracking body runs in window mode")
	}
	if fallback != nil {
		workK = 0
		tripCalls = false
	}

	prog := bt.prog
	N := len(prog.Inst)
	numCaps := bt.numGroups
	numCapLocals := numCaps * 2

	// A fallback memoises every Alt on (pc, pos) over its run-time memo; the
	// ordinary body memoises nothing. The fallback's memo locals follow the
	// captures: five slots, of which the guard reads byteAddr and memoByte.
	useMemo := fallback != nil
	memoLocalsBase := uint32(7 + numCapLocals)
	var memoByteAddr, memoMemoByte uint32
	memoLocalsCount := 0
	if useMemo {
		memoByteAddr = memoLocalsBase + 2
		memoMemoByte = memoLocalsBase + 3
		memoLocalsCount = 5
	}

	// Window-mode locals (see winGlobal): the match window's start and
	// end offsets, loaded once from scratch at entry. Placed last so no
	// existing local index shifts.
	useWindow := winGlobal >= 0
	winStartLocal := memoLocalsBase + uint32(memoLocalsCount)
	winEndLocal := winStartLocal + 1
	limitLocal := uint32(localLen)
	winLocalsCount := 0
	if useWindow {
		limitLocal = winEndLocal
		winLocalsCount = 2
	}

	// Total non-param locals: pos, sp, state, scratch, cap0s, cap0e, ...,
	// (memo locals when a fallback), (window locals when useWindow), (the
	// run-time region's four when a fallback)
	totalLocals := 4 + numCapLocals + memoLocalsCount + winLocalsCount
	var dyn *btDyn
	if fallback != nil {
		dyn = newBTDyn(*fallback, tableMemIdx, frameSize, N)
		dynBase := uint32(3 + totalLocals)
		dyn.memoBase, dyn.cleared, dyn.stackBase, dyn.stackTop = dynBase, dynBase+1, dynBase+2, dynBase+3
		totalLocals += 4
		if member != nil {
			dyn.member = member
			dyn.origin, dyn.memoEnd = dynBase+4, dynBase+5
			totalLocals += 2
		}
	}

	var body []byte

	// ── Local declarations ────────────────────────────────────────────────────
	// The work counter is the one i64, in a group of its own after every i32,
	// so no existing index moves and a body without it declares exactly what
	// it always did. A fallback has no counter and takes the slot for its entry
	// arithmetic instead.
	useWork := workK > 0
	workLocal := uint32(3 + totalLocals) // after the three params and every i32
	if dyn != nil {
		dyn.tmp64 = workLocal
	}
	if useWork || dyn != nil {
		body = append(body, 0x02)
	} else {
		body = append(body, 0x01)
	}
	body = utils.AppendULEB128(body, uint32(totalLocals))
	body = append(body, 0x7F)
	if useWork || dyn != nil {
		body = append(body, 0x01, 0x7E) // one i64
	}

	// ── Window offsets (window mode only) ───────────────────────────────────
	// Loaded once; winStart also seeds pos, and winEnd is the consumption
	// limit every bounds check and InstMatch tests against.
	if useWindow {
		body = append(body, 0x23) // global.get startOff
		body = utils.AppendULEB128(body, uint32(winGlobal))
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, winStartLocal)

		body = append(body, 0x23) // global.get endOff
		body = utils.AppendULEB128(body, uint32(winGlobal+1))
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, winEndLocal)
	}

	// ── Initialise pos=startOff, sp=stackBase, state=prog.Start ─────────────
	if useWindow {
		body = btLocalGet(body, winStartLocal)
	} else {
		body = append(body, 0x41, 0x00) // i32.const 0
	}
	body = append(body, 0x21, localPos) // local.set pos

	// A fallback's stack does not exist until the scratch init below.
	if dyn == nil {
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, stackBase)
		body = append(body, 0x21, localSP) // local.set sp
	}

	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(prog.Start))
	body = append(body, 0x21, localState) // local.set state

	// ── Initialise capture locals ───────────────────────────────────────────
	//
	// -1, or `-1 - start` when this body writes ABSOLUTE slots: the bias lets
	// the write site add `start` unconditionally and still produce exactly -1
	// for a group that never captured. Sound because a capture local is only
	// ever initialised here, assigned `pos`, or saved/restored verbatim through
	// the frame stack — nothing compares one against zero.
	for i := 0; i < numCapLocals; i++ {
		body = append(body, 0x41, 0x7F) // i32.const -1
		if capStartGlobal >= 0 {
			body = append(body, 0x23)
			body = utils.AppendULEB128(body, uint32(capStartGlobal))
			body = append(body, 0x6B) // i32.sub
		}
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
	}

	// ── Work budget ─────────────────────────────────────────────────────────
	// Over the WINDOW in window mode, not the input: a composed groups call
	// runs this body once per match, and a budget sized from the whole input
	// would let one pathological window burn k·N·len pops before tripping.
	workSpan := func(b []byte) []byte {
		if useWindow {
			b = btLocalGet(b, winEndLocal)
			b = btLocalGet(b, winStartLocal)
			return append(b, 0x6B) // i32.sub
		}
		return append(b, 0x20, localLen)
	}
	if useWork && member != nil {
		// A set member's budget lasts the host call (btDriveMember).
		body = emitBTWorkInitMember(body, member, workK, N, workSpan)
	} else if useWork {
		body = emitBTWorkInit(body, workLocal, workK, N, workSpan)
	}

	// ── Part 3: Memo table lazy clear ──────────────────────────────────────
	// The span the memo's positions cover: the WINDOW in window mode, not the
	// input — the window is what the indices are rebased into.
	span := func(b []byte) []byte {
		if useWindow {
			b = btLocalGet(b, winEndLocal)
			b = btLocalGet(b, winStartLocal)
			return append(b, 0x6B) // i32.sub
		}
		return append(b, 0x20, localLen)
	}
	if dyn != nil {
		if dyn.member != nil {
			body = emitBTScratchInitMember(body, dyn, winStartLocal, winEndLocal, btWorkTripI32)
		} else {
			body = emitBTScratchInit(body, dyn, span, btWorkTripI32)
		}
		body = btLocalGet(body, dyn.stackBase)
		body = append(body, 0x21, localSP) // local.set sp
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
	body = emitBTStackBase(body, stackBase, dyn)
	body = append(body, 0x4D)       // i32.le_u
	body = append(body, 0x04, 0x40) // if void
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x0F)       // return
	body = append(body, 0x0B)       // end if (empty)

	if useWork && member != nil {
		body = emitBTWorkChargeMember(body, member, workLocal, btGiveUp(tripCalls, 3, &callOffs, btWorkTripI32))
	} else if useWork {
		// ptr, len, out_ptr
		body = emitBTWorkCharge(body, workLocal, btGiveUp(tripCalls, 3, &callOffs, btWorkTripI32))
	}

	// Pop frame: sp -= frameSize
	body = append(body, 0x20, localSP) // local.get sp
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, frameSize)
	body = append(body, 0x6B)          // i32.sub
	body = append(body, 0x21, localSP) // local.set sp

	// Restore pos from mem[sp+0]
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, 0)
	body = append(body, 0x21, localPos) // local.set pos

	// Restore captures from mem[sp+4..sp+4+numCapLocals*4)
	for i := 0; i < numCapLocals; i++ {
		body = append(body, 0x20, localSP)
		body = appendTableLoad32(body, tableMemIdx, uint32(4+i*4))
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
	}

	// Restore retry PC from mem[sp + 4 + numCapLocals*4]
	retryPCOffset := uint32(4 + numCapLocals*4)
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, retryPCOffset)
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
	body = append(body, 0x20, localState)       // local.get state
	body = append(body, 0x0E)                   // br_table
	body = utils.AppendULEB128(body, uint32(N)) // N targets
	for i := 0; i < N; i++ {
		body = utils.AppendULEB128(body, uint32(i))
	}
	body = utils.AppendULEB128(body, 0) // default

	// ── Per-PC handlers ───────────────────────────────────────────────────────
	// The capture body's memo origin is its window start — or, for a set
	// member's fallback, the first row of a memo that outlives the call.
	memoOrigin := winStartLocal
	if dyn != nil && dyn.member != nil {
		memoOrigin = dyn.origin
	}
	overflow := btOverflowAction(useWork && tripCalls, workLocal, nil)
	if useWork && tripCalls && member != nil {
		overflow = btArmTripMember(member)
	}

	// After each end of block $pc_p, emit the handler for PC p.
	// brRun(p) = N-1-p  (depth from handler top level to restart $run)
	// brRunNested(p) = N-p  (depth from inside one extra if block)
	for p := 0; p < N; p++ {
		body = append(body, 0x0B) // end $pc_p

		inst := prog.Inst[p]
		brRun := uint32(N - 1 - p)

		body = emitBTInstHandler(body, bt, p, inst, brRun, stackLimit, frameSize, numCapLocals, memoByteAddr, memoMemoByte, false, nativeAnchored, nil, overflow, tableMemIdx, limitLocal, winStartLocal, useWindow, capStartGlobal,
			memoOrigin, useWindow, dyn)
	}

	body = append(body, 0x00)       // unreachable (after all handlers, inside $run)
	body = append(body, 0x0B)       // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1 (unreachable fallthrough)
	body = append(body, 0x0B)       // end function
	return body, callOffs
}

// emitBTStackBase pushes the frame stack's base: a constant, or a fallback's
// run-time local.
func emitBTStackBase(b []byte, stackBase int32, dyn *btDyn) []byte {
	if dyn != nil {
		return btLocalGet(b, dyn.stackBase)
	}
	b = append(b, 0x41)
	return utils.AppendSLEB128(b, stackBase)
}

// btOverflowAction is a body's frame-stack overflow: arm the budget so the next
// pop calls the fallback (btArmTrip) when the body has one, else unknown — nil
// meaning the default i32 -2.
func btOverflowAction(armTrip bool, workLocal uint32, unknown func([]byte, uint32) []byte) func([]byte, uint32) []byte {
	if armTrip {
		return btArmTrip(workLocal)
	}
	return unknown
}

// emitAddCapStart appends `+ start` to the i32 already on the stack, for a
// capture body writing ABSOLUTE slot positions. A no-op when capStartGlobal is
// -1, which is every body whose slots stay relative to its own ptr.
//
// See compiledPattern.capStartGlobal for the channel and why it is a global.
func emitAddCapStart(b []byte, capStartGlobal int32) []byte {
	if capStartGlobal < 0 {
		return b
	}
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, uint32(capStartGlobal))
	return append(b, 0x6A) // i32.add
}

// emitBTInstHandler emits WASM for a single NFA instruction handler.
// brRun is the br depth (from handler top level) to restart $run; brRunNested,
// one more, is the depth from inside one extra if-block.
// memoByteAddr and memoMemoByte are a fallback body's memo scratch locals,
// unused when dyn is nil.
// noCaptures: when true, InstCapture is treated as NOP and InstMatch calls
// instMatchFn, whose second argument is brRunNested.
// overflowFn: emits stack-overflow return code for btPushFrame (nil = i32.const -1; return).
func emitBTInstHandler(
	body []byte,
	bt *backtrack,
	p int,
	inst syntax.Inst,
	brRun uint32,
	stackLimit, frameSize int32,
	numCapLocals int,
	memoByteAddr, memoMemoByte uint32,
	noCaptures bool,
	nativeAnchored bool,
	instMatchFn func([]byte, uint32) []byte,
	overflowFn func([]byte, uint32) []byte,
	tableMemIdx int,
	limitLocal, winStartLocal uint32,
	useWindow bool,
	capStartGlobal int32,
	// The memo origin, SEPARATE from window mode: the capture body's origin is
	// its window start, but the no-capture find body has an origin (the call's
	// `from`) without being in window mode at all.
	memoOriginLocal uint32,
	hasMemoOrigin bool,
	// A FALLBACK body's run-time memory (bt_scratch.go), or nil for a body
	// whose stack is a compile-time region.
	dyn *btDyn,
) []byte {
	// brRunNested = br depth from inside one extra if/block to restart $run
	brRunNested := brRun + 1

	contOut := func(b []byte) []byte {
		return btSetStateAndBr(b, int32(inst.Out), brRun)
	}

	switch inst.Op {
	case syntax.InstRune1:
		body = btBoundsCheck(body, brRunNested, limitLocal)
		body = btCheckRune1(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = contOut(body)

	case syntax.InstRune:
		body = btBoundsCheck(body, brRunNested, limitLocal)
		body = btCheckRuneRanges(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = contOut(body)

	case syntax.InstRuneAny:
		body = btBoundsCheck(body, brRunNested, limitLocal)
		body = btAdvancePos(body)
		body = contOut(body)

	case syntax.InstRuneAnyNotNL:
		body = btBoundsCheck(body, brRunNested, limitLocal)
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
		body = contOut(body)

	case syntax.InstAlt, syntax.InstAltMatch:
		// Push retry=inst.Arg, continue with inst.Out. Loop heads are no
		// different from any other alternation: the ordinary body runs only
		// programs without a zero-width cycle, where every cycle consumes a
		// byte and so needs no guard.
		//
		// A FALLBACK body memoises every Alt on (pc, pos) instead, which is
		// Go regexp's bitstate discipline and what terminates it on a program
		// with a zero-width cycle. (pc, pos) is the complete machine state —
		// the program is a graph with no return addresses — so the first
		// visit to one explores every path out of it in priority order; if
		// any succeeds the call returns, so a second arrival can only follow a
		// first that failed, and cutting it loses nothing. Checking at Alts
		// alone is equivalent to Go's check at every instruction: from a
		// non-Alt the path is deterministic up to the next Alt, Match or Fail,
		// so a revisit is cut there, and it cannot reach Match because the
		// first visit would already have returned. Every cycle in a
		// syntax.Prog passes through an Alt, and an Alt is entered at a given
		// pos at most once per call.
		if dyn != nil {
			body = emitBitStateGuardDyn(body, dyn, p, memoByteAddr, memoMemoByte, brRunNested, memoOriginLocal, hasMemoOrigin)
		}
		body = btPushFrame(body, numCapLocals, inst.Arg, stackLimit, frameSize, brRunNested, overflowFn, tableMemIdx, dyn)
		body = contOut(body)

	case syntax.InstCapture:
		if noCaptures {
			// No capture tracking — treat as NOP, follow inst.Out.
			body = contOut(body)
			break
		}
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
		body = contOut(body)

	case syntax.InstEmptyWidth:
		emptyOp := syntax.EmptyOp(inst.Arg)
		switch {
		case emptyOp&syntax.EmptyBeginLine != 0:
			// (?m:^): fires at pos==0 or when prev byte is '\n'
			// Fail if: pos != 0 AND mem[ptr + pos - 1] != '\n'
			// pos is a true input offset under window mode, so this needs no
			// edge fix-up.
			body = append(body, 0x20, localPos)
			body = append(body, 0x45)       // i32.eqz
			body = append(body, 0x04, 0x40) // if void (pos == 0): ok
			body = append(body, 0x05)       // else (pos > 0): check prev byte
			body = append(body, 0x20, localPtr)
			body = append(body, 0x20, localPos)
			body = append(body, 0x6A)             // i32.add
			body = append(body, 0x41, 0x01)       // i32.const 1
			body = append(body, 0x6B)             // i32.sub (ptr + pos - 1)
			body = append(body, 0x2D, 0x00, 0x00) // i32.load8_u (prev byte)
			body = append(body, 0x41, 0x0A)       // i32.const '\n'
			body = append(body, 0x47)             // i32.ne
			body = append(body, 0x04, 0x40)       // if void (prev != '\n'): fail
			body = btFail(body, brRunNested+1)    // +1: nested inside the outer if/else too
			body = append(body, 0x0B)             // end if prev != '\n'
			body = append(body, 0x0B)             // end if pos == 0
			body = contOut(body)

		case emptyOp&syntax.EmptyBeginText != 0:
			// \A: fires only at pos==0, which under window mode is the true
			// start of the input.
			body = append(body, 0x20, localPos)
			body = append(body, 0x45)       // i32.eqz
			body = append(body, 0x45)       // i32.eqz (NOT: nonzero = fail)
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = contOut(body)

		case emptyOp&syntax.EmptyEndLine != 0:
			// (?m:$): fires at pos==len or when next byte is '\n'
			// Fail if: pos != len AND mem[ptr + pos] != '\n'
			// len is the true input length under window mode.
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
			body = append(body, 0x46)       // i32.eq
			body = append(body, 0x04, 0x40) // if void (pos == len): ok
			body = append(body, 0x05)       // else (pos < len): check next byte
			body = append(body, 0x20, localPtr)
			body = append(body, 0x20, localPos)
			body = append(body, 0x6A)             // i32.add (ptr + pos)
			body = append(body, 0x2D, 0x00, 0x00) // i32.load8_u (next byte)
			body = append(body, 0x41, 0x0A)       // i32.const '\n'
			body = append(body, 0x47)             // i32.ne
			body = append(body, 0x04, 0x40)       // if void (next != '\n'): fail
			body = btFail(body, brRunNested+1)    // +1: nested inside the outer if/else too
			body = append(body, 0x0B)             // end if next != '\n'
			body = append(body, 0x0B)             // end if pos == len
			body = contOut(body)

		case emptyOp&syntax.EmptyEndText != 0:
			// \z: fires only at pos==len, which under window mode is the true
			// end of the input.
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
			body = append(body, 0x47)       // i32.ne
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = contOut(body)

		case emptyOp&syntax.EmptyWordBoundary != 0:
			body = btWordBoundary(body, true, brRunNested)
			body = contOut(body)

		case emptyOp&syntax.EmptyNoWordBoundary != 0:
			body = btWordBoundary(body, false, brRunNested)
			body = contOut(body)
		}

	case syntax.InstNop:
		body = contOut(body)

	case syntax.InstMatch:
		if noCaptures && instMatchFn != nil {
			// No capture tracking — caller-provided match action.
			body = instMatchFn(body, brRunNested)
			break
		}
		if !nativeAnchored {
			// RE2 semantics: only accept if the whole match window is
			// consumed. limitLocal is localLen when the caller narrowed the
			// slice, and the window end loaded from scratch under window
			// mode.
			body = append(body, 0x20, localPos)
			body = btLocalGet(body, limitLocal)
			body = append(body, 0x47)       // i32.ne
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
		}
		// nativeAnchored: len is the caller's full, un-narrowed input length
		// (no independent find pass has bounded it), so InstMatch must accept
		// unconditionally here — any $/\z the pattern actually has was already
		// enforced by the EmptyEndText/EmptyEndLine handlers earlier in this
		// derivation, and BT's stack always explores the highest-priority
		// (leftmost-first) derivation first, so the first InstMatch reached is
		// the correct answer regardless of how much input remains unconsumed.

		// Write captures to out_ptr and return pos.
		// Group 0: start = where this attempt began (0 when the caller
		// narrowed the slice, the window start under window mode), end = pos.
		body = append(body, 0x20, localOutPtr)
		if useWindow {
			body = btLocalGet(body, winStartLocal)
		} else {
			body = append(body, 0x41, 0x00)              // i32.const 0 (group 0 start)
			body = emitAddCapStart(body, capStartGlobal) // ... = start, when absolute
		}
		body = append(body, 0x36, 0x02)     // i32.store align=2
		body = utils.AppendULEB128(body, 0) // offset=0

		body = append(body, 0x20, localOutPtr)
		body = append(body, 0x20, localPos)
		body = emitAddCapStart(body, capStartGlobal)
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
			body = emitAddCapStart(body, capStartGlobal)
			body = append(body, 0x36, 0x02) // i32.store align=2
			body = utils.AppendULEB128(body, startOffset)

			body = append(body, 0x20, localOutPtr)
			body = append(body, 0x20)
			body = utils.AppendULEB128(body, capEndLocal(i))
			body = emitAddCapStart(body, capStartGlobal)
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
func btBoundsCheck(b []byte, brDepth uint32, limitLocal uint32) []byte {
	b = append(b, 0x20, localPos)
	b = btLocalGet(b, limitLocal)
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
		b = utils.AppendSLEB128(b, r)
		b = append(b, 0x46) // i32.eq

		b = append(b, 0x20, localScratch)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, altR)
		b = append(b, 0x46) // i32.eq

		b = append(b, 0x72)       // i32.or
		b = append(b, 0x45)       // i32.eqz (NOT)
		b = append(b, 0x04, 0x40) // if void (no match)
		b = btFail(b, brDepth)
		b = append(b, 0x0B) // end if
	} else {
		b = append(b, 0x20, localScratch)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, r)
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
		// SATURATE at 0xFF, exactly as the DFA's nfaBuildInputMap does. This
		// engine consumes one BYTE per InstRune, and `.` / a negated class
		// matching one byte is documented semantics (docs/engines.md), so
		// `[^,]` — which the parser writes as a range to U+10FFFF — must admit
		// 0x80..0xFF. Truncating to 0x7F here made the capture pass disagree
		// with the DFA that had just found the extent, and the whole match was
		// lost. A range entirely above the byte space contributes nothing.
		if lo > 0xFF {
			continue
		}
		if hi > 0xFF {
			hi = 0xFF
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
	// Same saturation as btCheckRuneRanges — see the comment there. scratch is
	// an i32.load8_u, so it is 0..255 and the ge_u/le_u pair below compares
	// correctly against a bound anywhere in that space.
	if lo > 0xFF {
		return b
	}
	if hi > 0xFF {
		hi = 0xFF
	}
	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, lo)
	b = append(b, 0x4F) // i32.ge_u

	b = append(b, 0x20, localScratch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, hi)
	b = append(b, 0x4D) // i32.le_u

	b = append(b, 0x71) // i32.and → 0 or 1

	// if this range matched: push 1 and br out of block
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x0C, 0x01) // br 1 (out of the result block; depth 0=this if, 1=block $matched)
	b = append(b, 0x0B)       // end if
	return b
}

// btOverflowFindReturn is the overflowFn for the i64-returning BT find bodies:
// it returns abi.BTStackOverflow instead of a packed (start << 32 | end).
//
// It replaced a `br $run_exit` that abandoned only the current attempt_start
// and let the scan continue. That could not produce a truthful answer. find
// reports the *leftmost* match and scans attempt_start upward, so an overflow
// at position k is only ever reached after every earlier start has already
// failed: a match subsequently found at some start > k is not provably
// leftmost, and running off the end of the input reports no-match, which is a
// false negative. Every exit reachable after an overflow would therefore have
// to report -2 anyway, so returning here is equivalent and far simpler.
//
// It also keeps the property the old `br` was chosen for over a pop-and-retry
// (which could oscillate forever at the stack ceiling for nested nullable-loop
// patterns): a `return` cannot be re-entered at all, so it is trivially
// bounded. brDepth is unused — a return needs no branch depth.
func btOverflowFindReturn(bb []byte, _ uint32) []byte {
	bb = append(bb, 0x42) // i64.const abi.BTStackOverflow
	bb = utils.AppendSLEB128(bb, abi.BTStackOverflow)
	return append(bb, 0x0F) // return
}

// BTWorkBudgetOff is the CompileOptions.BTWorkBudget value that emits no work
// counter and no fallback, so the ordinary body answers every call alone — a
// TEST knob, the one way to drive that body on its own. A program with a
// zero-width cycle is the exception: it has no ordinary body under any
// setting (planBT), so Off still gives it the fallback alone and cannot build
// a matcher that never returns.
const BTWorkBudgetOff = -1

// BTWorkBudgetForceFallback is the CompileOptions.BTWorkBudget value that makes
// a Backtracking program's fast body a bare tail call into its fallback body, so
// the fallback alone answers every call. A TEST knob: the fallback otherwise
// runs only after a trip, which the corpus reaches a handful of times, and it is
// a general bitstate body that has to be right for everything a program can
// contain.
const BTWorkBudgetForceFallback = -2

// defaultBTWorkK is the budget multiplier when CompileOptions.BTWorkBudget is 0.
const defaultBTWorkK = 8

// btWorkK returns the work-budget multiplier a body for bt must carry, or 0 for
// no counter.
//
// # Why a budget, and why every program
//
// A backtracker without memoisation is exponential whenever a loop can split
// the same input more than one way, and nothing in this engine's ordinary body
// cuts that off. `^(\w*|)*c` — a loop whose body can match empty through an
// alternation branch — took 3 ms at 12 bytes, 783 ms at 22, and never returned
// at 40; `^(aa|a)*b` — overlapping branches in a loop whose body always
// consumes — took 238 ms at 32 bytes and never returned at 40. The frame budget
// is not exhausted on either, because the stack is popped as the search goes.
//
// So the body counts instead. Every such blowup is made of backtracking, and
// every backtrack is a frame POP, so the counter is decremented on the pop path
// and costs nothing on a call that never backtracks.
//
// EVERY Backtracking program carries it. The first version was scoped to
// programs with an empty-body greedy loop, on the premise that every other
// program was bounded — and `^(aa|a)*b` refutes the premise. No syntactic rule
// for "can blow up" is known to be complete, so there is no rule here.
//
// # Why (span+1)·k·N pops, and why that bounds TIME
//
// A search that never revisits a (pc, pos) pushes at most N·(span+1) frames,
// hence pops at most that many. A run past k times that bound is no longer in
// the polynomial regime, so the body gives up. k is a knob, not a proof
// obligation: a trip answers "unknown", never a wrong answer.
//
// Counting pops bounds time as well, not just backtracks. Every cycle in a
// syntax.Prog passes through an Alt, and in the ordinary body every Alt pushes a
// frame, so the stretch between two consecutive push or pop events is acyclic:
// at most N instructions. A call is therefore at most N·(2·pops + stack depth +
// 1) instructions — linear in the input, since pops are bounded by the budget
// and depth by the static stack.
func btWorkK(_ *backtrack, budget int) int {
	if budget < 0 {
		return 0
	}
	if budget == 0 {
		return defaultBTWorkK
	}
	return budget
}

// errBTWorkBudget is what compileAll and CompileFile answer for a negative
// CompileOptions.BTWorkBudget that is neither named knob.
var errBTWorkBudget = errors.New("BTWorkBudget: a negative value must be BTWorkBudgetOff or BTWorkBudgetForceFallback")

// validateBTWorkBudget refuses a negative budget other than the two named
// knobs. btWorkK reads every negative value as "no counter", so a stale
// constant would otherwise compile a module with no work budget and no
// fallback body — and `^(aa|a)*b` would hang again with nothing saying why. An
// error rather than a panic: the options are the caller's.
func validateBTWorkBudget(budget int) error {
	if budget < 0 && budget != BTWorkBudgetOff && budget != BTWorkBudgetForceFallback {
		return fmt.Errorf("%w, got %d", errBTWorkBudget, budget)
	}
	return nil
}

// btPlan is how one Backtracking program is emitted under a work budget.
type btPlan struct {
	// k is the fast body's pop-budget multiplier; 0 means no counter.
	k int
	// fallback: the program also gets a fallback body, laid out right after
	// its fast body, and a trip TAIL-CALLS it instead of answering -2.
	fallback bool
	// force: the fast body is nothing but that tail call
	// (BTWorkBudgetForceFallback).
	force bool
}

// planBT resolves CompileOptions.BTWorkBudget for one program.
//
// Every budgeted program gets a fallback, and a fallback exists only behind a
// counter or the force knob: a trip that answered -2 where a fallback could
// have answered would lose an answer the engine is able to give. The one
// exception is BTWorkBudgetOff, which emits neither, so tests can drive the
// ordinary body alone.
//
// A program with a zero-width cycle is planned as if forced under EVERY
// budget, Off included: the ordinary body carries no loop guard, so it could
// go round such a cycle forever (progHasZeroWidthCycle), and the fallback
// answers every call. A forced plan reserves no compile-time stack either —
// nothing reads it. Measured on the
// one perftest row it reaches, html-tags: fuel +2.6% and −3.9% on its two
// inputs, module −31%; on `^(\w*|)*c` over `w`×4000, +7% when it matches and
// −97% when it does not, since the ordinary body used to burn its whole budget
// first.
func planBT(bt *backtrack, budget int) btPlan {
	if budget == BTWorkBudgetForceFallback || bt.zeroWidthCycle {
		return btPlan{fallback: true, force: true}
	}
	k := btWorkK(bt, budget)
	return btPlan{k: k, fallback: k > 0}
}

// btFallbackCallPlaceholder is the immediate a fast body's call to its fallback
// carries until the assembler knows the fallback's function index: five
// zero-padded LEB128 bytes, so the real index overwrites it in place and
// nothing moves. Same width and mechanism as the neutral find twin's handoff.
var btFallbackCallPlaceholder = utils.AppendPaddedULEB128(nil, 0, twinCallImmWidth)

// emitBTFallbackCall emits the tail call a fast body makes when it gives up:
// `local.get 0 … local.get nParams-1; call <placeholder>; return`, forwarding
// the fast body's own arguments. The fallback reads every global the fast body
// read — the find-from position, the window offsets, the capture start — and
// the fast body writes none of them, so it restarts the call from scratch on
// exactly the inputs the caller gave. The placeholder's byte offset within b is
// appended to *callOffs.
//
// A body has one such site, the work-budget trip on the pop path. A
// frame-stack overflow needs none of its own — it arms the budget to trip on
// the next pop (btArmTrip).
func emitBTFallbackCall(b []byte, nParams int, callOffs *[]int) []byte {
	for i := 0; i < nParams; i++ {
		b = append(b, 0x20, byte(i)) // local.get param
	}
	b = append(b, 0x10) // call
	*callOffs = append(*callOffs, len(b))
	b = append(b, btFallbackCallPlaceholder...)
	return append(b, 0x0F) // return
}

// btArmTrip is a fast body's frame-stack overflow when the budget calls a
// fallback: set the work counter to 1 and fail. The FAIL handler's pop then
// finds the budget exhausted and makes the one fallback call the body already
// has, so the overflow needs no call site — and no patch offset — of its own.
// The stack is never empty here: a push overflowed it.
func btArmTrip(workLocal uint32) func([]byte, uint32) []byte {
	return func(b []byte, brDepth uint32) []byte {
		b = append(b, 0x42, 0x01) // i64.const 1
		b = append(b, 0x21)       // local.set work
		b = utils.AppendULEB128(b, workLocal)
		return btFail(b, brDepth)
	}
}

// btTailCallBody is the whole fast body under BTWorkBudgetForceFallback: no
// locals, one forwarding call. Returned size-prefixed, with the offset counted
// from the start of the size prefix.
func btTailCallBody(nParams int) (body []byte, callOffs []int) {
	b := []byte{0x00} // no locals
	b = emitBTFallbackCall(b, nParams, &callOffs)
	b = append(b, 0x0B) // end (the return above makes this unreachable)
	return btSizePrefix(b, callOffs)
}

// btSizePrefix size-prefixes a body and moves the recorded offsets past the
// prefix.
func btSizePrefix(body []byte, offs []int) ([]byte, []int) {
	prefix := utils.AppendULEB128(nil, uint32(len(body)))
	for i := range offs {
		offs[i] += len(prefix)
	}
	return append(prefix, body...), offs
}

// btShiftOffs moves recorded offsets by delta, for a body appended after delta
// bytes of other code.
func btShiftOffs(offs []int, delta int) []int {
	for i := range offs {
		offs[i] += delta
	}
	return offs
}

// patchBTFallbackCall returns a copy of a size-prefixed fast body with every
// fallback call pointing at fallbackIdx. It checks each placeholder is still
// where the emitter recorded it, so an offset that went stale fails the compile
// instead of calling some other function — and that a body that has a fallback
// calls it at least once.
func patchBTFallbackCall(body []byte, offs []int, fallbackIdx int) []byte {
	if len(offs) == 0 {
		panic("compile: a Backtracking body with a fallback never calls it")
	}
	out := append([]byte(nil), body...)
	for _, off := range offs {
		if off < 1 || off+twinCallImmWidth > len(out) || out[off-1] != 0x10 ||
			string(out[off:off+twinCallImmWidth]) != string(btFallbackCallPlaceholder) {
			panic("compile: Backtracking fallback call patch offset does not name the placeholder")
		}
		copy(out[off:off+twinCallImmWidth], utils.AppendPaddedULEB128(nil, uint32(fallbackIdx), twinCallImmWidth))
	}
	return out
}

// emitBTWorkInit emits `work = (span + 1) * (k * N)` in i64, where span pushes
// the i32 length the search ranges over: the window in window mode, the input
// otherwise. i64 because N·(span+1)·k overflows i32 at 1 MB for N ≥ 256.
//
// Set once per CALL. A find body's attempts share it, and it is never saved
// into a frame: it is a bound on the whole call's work, not per-path state.
func emitBTWorkInit(b []byte, workLocal uint32, k, n int, span func([]byte) []byte) []byte {
	b = span(b)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x42)       // i64.const k*N
	b = utils.AppendSLEB128_64(b, int64(k)*int64(n))
	b = append(b, 0x7E) // i64.mul
	b = append(b, 0x21) // local.set work
	return utils.AppendULEB128(b, workLocal)
}

// emitBTWorkCharge emits the pop-path decrement: `if (--work == 0) trip`. It
// belongs AFTER the empty-stack test, so only a real pop is charged. trip must
// leave the function — a return needs no branch depth, which is why this helper
// takes none.
func emitBTWorkCharge(b []byte, workLocal uint32, trip func([]byte) []byte) []byte {
	b = btLocalGet(b, workLocal)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7D)       // i64.sub
	b = append(b, 0x22)       // local.tee work
	b = utils.AppendULEB128(b, workLocal)
	b = append(b, 0x50)       // i64.eqz
	b = append(b, 0x04, 0x40) // if void
	b = trip(b)
	return append(b, 0x0B) // end if
}

// btWorkTrip returns what an exhausted budget runs in a body with nParams
// parameters: the fallback tail call when tripCalls, else unknown — the -2 the
// body's frame-stack overflow already answers. nil when the body carries no
// counter.
func btWorkTrip(useWork, tripCalls bool, nParams int, callOffs *[]int, unknown func([]byte) []byte) func([]byte) []byte {
	if !useWork {
		return nil
	}
	return btGiveUp(tripCalls, nParams, callOffs, unknown)
}

// btGiveUp is what a body runs where it cannot go on: the fallback tail call
// when it has one, else unknown.
func btGiveUp(tripCalls bool, nParams int, callOffs *[]int, unknown func([]byte) []byte) func([]byte) []byte {
	return func(b []byte) []byte {
		if tripCalls {
			return emitBTFallbackCall(b, nParams, callOffs)
		}
		return unknown(b)
	}
}

// btUnknownI64 is abi.BTStackOverflow returned from an i64-returning body.
func btUnknownI64(b []byte) []byte { return btOverflowFindReturn(b, 0) }

// btWorkTripI32 is the trip for the i32-returning bodies (capture and match):
// the same abi.BTStackOverflow a frame-stack overflow answers.
func btWorkTripI32(b []byte) []byte {
	b = append(b, 0x41) // i32.const abi.BTStackOverflow
	b = utils.AppendSLEB128(b, abi.BTStackOverflow)
	return append(b, 0x0F) // return
}

// btPushFrame pushes a backtrack frame onto the stack:
// mem[sp+0]                  = pos
// mem[sp+4..4+capLocals*4]   = captures
// mem[sp+retryPCOff]         = retryPC
// stackLimit and frameSize are passed so we can guard against stack overflow:
// if sp+frameSize > stackLimit, bail out instead of writing past allocated
// memory.
//
// The default bail-out (overflowFn == nil) returns abi.BTStackOverflow (-2),
// NOT abi.NoMatch (-1). Overflow means the engine abandoned part of the search
// space, so it does not know whether a match exists; returning -1 would report
// a definite "no" it has not established. That was a real defect: a
// false negative that appears once the input crosses numAlts*4096 bytes and is
// indistinguishable from a real no-match at every layer above. Callers that
// compose this body (the groups wrapper, the batch wrappers) must propagate -2
// rather than folding it into their own "< 0 means no match" test.
//
// dyn non-nil is a FALLBACK body's run-time stack: the guard grows memory
// instead of giving up, and overflowFn runs only when memory cannot grow — it
// must then leave the function by `return`, since the branch depth it is handed
// does not count the guard's own nesting.
func btPushFrame(b []byte, numCapLocals int, retryPC uint32, stackLimit, frameSize int32, brDepth uint32, overflowFn func([]byte, uint32) []byte, tableMemIdx int, dyn *btDyn) []byte {
	overflow := func(b []byte) []byte {
		if overflowFn != nil {
			return overflowFn(b, brDepth)
		}
		b = append(b, 0x41) // i32.const abi.BTStackOverflow
		b = utils.AppendSLEB128(b, abi.BTStackOverflow)
		return append(b, 0x0F) // return
	}
	if dyn != nil {
		b = emitBTDynPushCheck(b, dyn, overflow)
	} else {
		// Guard: if sp + frameSize > stackLimit → fail (treat as no-match).
		b = append(b, 0x20, localSP)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, frameSize)
		b = append(b, 0x6A) // i32.add
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, stackLimit)
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x04, 0x40) // if void
		b = overflow(b)
		b = append(b, 0x0B) // end if
	}

	// pos at offset 0
	b = append(b, 0x20, localSP)
	b = append(b, 0x20, localPos)
	b = appendTableStore32(b, tableMemIdx, 0)

	// captures at offsets 4, 8, ...
	for i := 0; i < numCapLocals; i++ {
		b = append(b, 0x20, localSP)
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, capStartLocal(0)+uint32(i))
		b = appendTableStore32(b, tableMemIdx, uint32(4+i*4))
	}

	// retry PC at offset 4 + numCapLocals*4
	retryOff := uint32(4 + numCapLocals*4)
	b = append(b, 0x20, localSP)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(retryPC))
	b = appendTableStore32(b, tableMemIdx, retryOff)

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
//
// The captureBody's (ptr,len) are always the caller's true input under
// window mode (see buildBacktrackBody's winGlobal), so pos==0 / pos==len
// are true input edges here and no side-channel edge context is needed —
// this is what a past defect’s (origPtr,origEnd) scratch used to
// reconstruct for a narrowed slice.
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
	b = append(b, 0x4D)       // i32.le_u
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
	b = append(b, 0x4D) // i32.le_u
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
	b = append(b, 0x4D) // i32.le_u
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

// --------------------------------------------------------------------------
// No-capture BT match and find bodies

// compileBTProg parses pattern, strips captures, and compiles the NFA for use
// in a no-capture BT match/find body.
// compileBTProg re-parses pattern into an NFA program with captures stripped.
// Both call sites reach this only after the caller already parsed the same
// pattern string successfully (via compile()/syntax.Parse earlier in
// compilePattern), so the parse here cannot fail; syntax.Compile never
// returns a non-nil error (see its stdlib source).
func compileBTProg(pattern string) *syntax.Prog {
	re, _ := syntax.Parse(pattern, syntax.Perl)
	stripCaptures(re)
	prog, _ := syntax.Compile(re.Simplify())
	return prog
}

// btAllocSizes returns the frame stack size in bytes for a no-capture BT
// engine's ordinary body: frames are 8 bytes, pos and retryPC.
func btAllocSizes(bt *backtrack) (stackSize int) {
	maxFrames := bt.numAlts * 4096
	if maxFrames < 4096 {
		maxFrames = 4096
	}
	return maxFrames * btNoCaptureFrameSize
}

// btNoCaptureFrameSize is a no-capture body's frame: pos and retryPC.
const btNoCaptureFrameSize = 8

// nfaFirstBytes walks the NFA from prog.Start via epsilon transitions and
// collects the set of bytes that can begin a match.
// Returns (firstBytes, flags, allBytes) where allBytes is true when any byte
// is possible (InstRuneAny / InstRuneAnyNotNL reachable).
func nfaFirstBytes(prog *syntax.Prog) (firstBytes []byte, flags [256]byte, allBytes bool) {
	visited := make([]bool, len(prog.Inst))
	queue := []int{prog.Start}
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		if visited[pc] {
			continue
		}
		visited[pc] = true
		inst := prog.Inst[pc]
		switch inst.Op {
		case syntax.InstRune1:
			r := inst.Rune[0]
			// 0xFF, not 127: this set feeds a PREFILTER, so omitting a byte
			// that can begin a match skips valid start positions outright —
			// an under-approximation loses matches, where an over-approximation
			// only costs a wasted attempt. The fold twin below stays ASCII,
			// which is the documented byte-mode rule.
			if r >= 0 && r <= 0xFF {
				b := byte(r)
				if flags[b] == 0 {
					flags[b] = 1
					firstBytes = append(firstBytes, b)
				}
				if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
					var alt byte
					if b >= 'a' && b <= 'z' {
						alt = b - 32
					} else if b >= 'A' && b <= 'Z' {
						alt = b + 32
					}
					if alt != 0 && alt != b && flags[alt] == 0 {
						flags[alt] = 1
						firstBytes = append(firstBytes, alt)
					}
				}
			}
		case syntax.InstRune:
			isFold := syntax.Flags(inst.Arg)&syntax.FoldCase != 0
			for i := 0; i < len(inst.Rune); i += 2 {
				var lo, hi rune
				if i+1 < len(inst.Rune) {
					lo, hi = inst.Rune[i], inst.Rune[i+1]
				} else {
					lo = inst.Rune[i]
					hi = inst.Rune[i] // single-rune entry at odd position
				}
				// See the InstRune1 arm: 0xFF, so a negated class (which the
				// parser writes as a range to U+10FFFF) contributes every byte
				// that can actually begin a match.
				for r := lo; r <= hi && r <= 0xFF; r++ {
					b := byte(r)
					if flags[b] == 0 {
						flags[b] = 1
						firstBytes = append(firstBytes, b)
					}
					if isFold {
						var alt byte
						if b >= 'a' && b <= 'z' {
							alt = b - 32
						} else if b >= 'A' && b <= 'Z' {
							alt = b + 32
						}
						if alt != 0 && alt != b && flags[alt] == 0 {
							flags[alt] = 1
							firstBytes = append(firstBytes, alt)
						}
					}
				}
			}
		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL, syntax.InstMatch:
			return nil, [256]byte{}, true
		default:
			queue = append(queue, int(inst.Out))
			if inst.Op == syntax.InstAlt || inst.Op == syntax.InstAltMatch {
				queue = append(queue, int(inst.Arg))
			}
		}
	}
	return firstBytes, flags, false
}

// buildBTScanTables computes the SIMD scan tables for BT find from the NFA first
// bytes and returns (prefixScanParams, raw data segment bytes (no count prefix), segCount).
// tableBase is the memory address where the tables will be stored.
func buildBTScanTables(firstBytes []byte, firstByteFlags [256]byte, allBytes bool, tableBase int64) (prefixScanParams, []byte, int) {
	if allBytes || len(firstBytes) == 0 {
		// Scalar fallback: store 256-byte flag table.
		off := int32(tableBase)
		var segs []byte
		var fb [256]byte
		if allBytes {
			for i := range fb {
				fb[i] = 1
			}
		} else {
			fb = firstByteFlags
		}
		segs = appendDataSegment(segs, off, fb[:])
		params := prefixScanParams{
			FirstByteSet:   firstBytes,
			FirstByteFlags: firstByteFlags,
			FirstByteOff:   off,
			Locals:         btScanLocalsOnly(),
			EngineDepth:    2,
		}
		return params, segs, 1
	}

	firstByteOff := int32(tableBase)
	teddyLoOff := firstByteOff + 256
	teddyHiOff := teddyLoOff + 16

	var segs []byte
	segCnt := 1
	segs = appendDataSegment(segs, firstByteOff, firstByteFlags[:])

	var teddyLoBytes, teddyHiBytes []byte
	if len(firstBytes) <= 8 {
		teddyLoBytes = make([]byte, 16)
		teddyHiBytes = make([]byte, 16)
		for i, fb := range firstBytes {
			teddyLoBytes[fb&0x0F] |= byte(1 << uint(i))
			teddyHiBytes[fb>>4] |= byte(1 << uint(i))
		}
		segs = appendDataSegment(segs, teddyLoOff, teddyLoBytes)
		segs = appendDataSegment(segs, teddyHiOff, teddyHiBytes)
		segCnt += 2
	}

	params := prefixScanParams{
		FirstByteSet:   firstBytes,
		FirstByteFlags: firstByteFlags,
		FirstByteOff:   firstByteOff,
		TeddyLoOff:     teddyLoOff,
		TeddyHiOff:     teddyHiOff,
		TeddyTwoByte:   false,
		Locals:         btScanLocalsOnly(),
		EngineDepth:    2,
	}

	return params, segs, segCnt
}

// --------------------------------------------------------------------------
// buildBTInnerDisp emits the NFA dispatch body (FAIL handler + N blocks + br_table +
// per-PC handlers) for insertion inside a pre-opened "loop $run".
//
// The caller is responsible for opening "loop $run" (0x03, 0x40) before calling
// and closing "end $run" (0x0B) after the returned bytes.
//
// memoByteAddr and memoMemoByte are a fallback body's memo scratch locals,
// unused when dyn is nil.
//
// failEmptyStack: emits WASM for when the backtrack stack is exhausted.
//   - For match: append(b, 0x41, 0x7F, 0x0F)  // i32.const -1; return
//   - For find:  append(b, 0x0C, 0x03)          // br 3 → exit $run_exit
//
// instMatchFn: emits WASM for when InstMatch is reached.
//
//	second arg is brRunNested (depth from inside one if-block to restart $run).
//
// overflowFn: emits the return code when the BT stack overflows (nil = i32.const -1; return).
func buildBTInnerDisp(
	body []byte,
	bt *backtrack,
	stackBase, stackLimit, frameSize int32,
	memoByteAddr, memoMemoByte uint32,
	failEmptyStack func([]byte) []byte,
	instMatchFn func([]byte, uint32) []byte,
	overflowFn func([]byte, uint32) []byte,
	tableMemIdx int,
	// The memo origin for the body being built: the find body's call `from`,
	// or (0, false) for the match body, which visits absolute positions and
	// rebases nothing.
	memoOriginLocal uint32,
	hasMemoOrigin bool,
	// The work budget (btWorkK): when workTrip is non-nil, every frame pop
	// charges workLocal and an exhausted budget runs workTrip, which must leave
	// the function — a fallback tail call, or the -2 a frame-stack overflow
	// answers.
	workLocal uint32,
	workTrip func([]byte) []byte,
	// A FALLBACK body's run-time memory, or nil — see emitBTInstHandler.
	dyn *btDyn,
) []byte {
	numCapLocals := 0
	prog := bt.prog
	N := len(prog.Inst)

	// ── FAIL handler (state == -1) ──
	body = append(body, 0x20, localState, 0x41, 0x7F, 0x46, 0x04, 0x40) // state==-1; if void
	body = append(body, 0x20, localSP)
	body = emitBTStackBase(body, stackBase, dyn)
	body = append(body, 0x4D, 0x04, 0x40) // i32.le_u; if void (empty stack)
	body = failEmptyStack(body)
	body = append(body, 0x0B) // end of (empty stack) if
	if workTrip != nil {
		body = emitBTWorkCharge(body, workLocal, workTrip)
	}
	// Pop frame: sp -= frameSize
	body = append(body, 0x20, localSP, 0x41)
	body = utils.AppendSLEB128(body, frameSize)
	body = append(body, 0x6B, 0x21, localSP) // i32.sub; local.set sp
	// Restore pos = mem[sp+0]
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, 0)
	body = append(body, 0x21, localPos)
	// Restore retryPC = mem[sp+4+numCapLocals*4]
	retryOff := uint32(4 + numCapLocals*4)
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, retryOff)
	body = append(body, 0x21, localState)
	body = append(body, 0x0C, 0x01) // br 1 → restart $run
	body = append(body, 0x0B)       // end of (state==-1) if

	// ── N nested blocks for PC dispatch ──
	for i := 0; i < N; i++ {
		body = append(body, 0x02, 0x40)
	}
	// br_table on state
	body = append(body, 0x20, localState, 0x0E)
	body = utils.AppendULEB128(body, uint32(N))
	for i := 0; i < N; i++ {
		body = utils.AppendULEB128(body, uint32(i))
	}
	body = utils.AppendULEB128(body, 0) // default

	// ── Per-PC handlers ──
	for p := 0; p < N; p++ {
		body = append(body, 0x0B) // end block $pc_p
		inst := prog.Inst[p]
		brRun := uint32(N - 1 - p)
		body = emitBTInstHandler(
			body, bt, p, inst, brRun,
			stackLimit, frameSize, numCapLocals,
			memoByteAddr, memoMemoByte,
			true,
			false,
			instMatchFn,
			overflowFn,
			tableMemIdx,
			uint32(localLen), 0,
			false,
			// No-capture bodies write no slots, so there is nothing to rebase.
			-1,
			memoOriginLocal, hasMemoOrigin,
			dyn,
		)
	}
	return body
}

// --------------------------------------------------------------------------
// appendBTMatchCodeEntry / buildBTMatchBody

// appendBTMatchCodeEntry appends a size-prefixed no-capture BT match body.
// Signature: (ptr i32, len i32) → i32
// Returns match end position (≥ 0) on success, -1 on failure.
func appendBTMatchCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize int32, tableMemIdx int, workK int, tripCalls bool, fallback *btScratch) (out []byte, callOffs []int) {
	body, offs := buildBTMatchBody(bt, stackBase, stackLimit, frameSize, tableMemIdx, workK, tripCalls, fallback)
	sized, offs := btSizePrefix(body, offs)
	return append(cs, sized...), btShiftOffs(offs, len(cs))
}

// buildBTMatchBody emits the full WASM function body for a no-capture BT match.
//
// Local layout (function type: (i32,i32)→i32):
//
//	Params:  ptr(0), len(1)
//	Locals:  fake_out_ptr(2) [aligns pkg constants], pos(3), sp(4), state(5),
//	         scratch(6), memo(7..11, a fallback only)
//
// The fake_out_ptr at index 2 aligns the remaining locals with the package-level
// constants (localPos=3, localSP=4, localState=5, localScratch=6) so all
// existing helper functions (btFail, btSetStateAndBr, etc.) can be reused.
//
// workK, tripCalls and fallback are buildBacktrackBody's, for this body.
func buildBTMatchBody(bt *backtrack, stackBase, stackLimit, frameSize int32, tableMemIdx int, workK int, tripCalls bool, fallback *btScratch) (_ []byte, callOffs []int) {
	if fallback != nil {
		workK = 0
		tripCalls = false
	}
	prog := bt.prog

	// A fallback's memo locals: five slots, of which the guard reads byteAddr
	// and memoByte. The ordinary body memoises nothing.
	useMemo := fallback != nil
	memoLocalsCount := 0
	var memoByteAddr, memoMemoByte uint32
	if useMemo {
		memoLocalsCount = 5
		memoByteAddr = 7 + 2
		memoMemoByte = 7 + 3
	}

	// +1 for fake out_ptr at index 2
	totalLocals := 4 + memoLocalsCount + 1
	var dyn *btDyn
	if fallback != nil {
		dyn = newBTDyn(*fallback, tableMemIdx, frameSize, len(prog.Inst))
		dynBase := uint32(2 + totalLocals)
		dyn.memoBase, dyn.cleared, dyn.stackBase, dyn.stackTop = dynBase, dynBase+1, dynBase+2, dynBase+3
		totalLocals += 4
	}

	// The work counter (btWorkK) is the one i64, in its own group after every
	// i32, so no existing index moves. A fallback takes the slot for its entry
	// arithmetic.
	useWork := workK > 0
	workLocal := uint32(2 + totalLocals) // after the two params and every i32
	if dyn != nil {
		dyn.tmp64 = workLocal
	}

	var body []byte
	if useWork || dyn != nil {
		body = append(body, 0x02)
	} else {
		body = append(body, 0x01)
	}
	body = utils.AppendULEB128(body, uint32(totalLocals))
	body = append(body, 0x7F)
	if useWork || dyn != nil {
		body = append(body, 0x01, 0x7E) // one i64
	}

	// pos=0, sp=stackBase, state=prog.Start — a fallback's sp once its stack
	// exists, below.
	body = append(body, 0x41, 0x00, 0x21, localPos)
	if dyn == nil {
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, stackBase)
		body = append(body, 0x21, localSP)
	}
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(prog.Start))
	body = append(body, 0x21, localState)

	if dyn != nil {
		body = emitBTScratchInit(body, dyn, func(b []byte) []byte {
			return append(b, 0x20, localLen)
		}, btWorkTripI32)
		body = btLocalGet(body, dyn.stackBase)
		body = append(body, 0x21, localSP)
	}

	if useWork {
		body = emitBTWorkInit(body, workLocal, workK, len(prog.Inst), func(b []byte) []byte {
			return append(b, 0x20, localLen)
		})
	}

	// loop $run
	body = append(body, 0x03, 0x40)

	failEmpty := func(b []byte) []byte { return append(b, 0x41, 0x7F, 0x0F) } // i32.const -1; return
	// matchFn: RE2 semantics — match_func requires full-input consumption,
	// so only accept an InstMatch reached with pos == len; otherwise keep
	// backtracking for a derivation that does consume the whole input.
	matchFn := func(b []byte, brDepth uint32) []byte {
		b = append(b, 0x20, localPos)
		b = append(b, 0x20, localLen)
		b = append(b, 0x47)       // i32.ne
		b = append(b, 0x04, 0x40) // if void
		b = btFail(b, brDepth)
		b = append(b, 0x0B)                 // end if
		b = append(b, 0x20, localPos, 0x0F) // local.get pos; return
		return b
	}

	body = buildBTInnerDisp(body, bt,
		stackBase, stackLimit, frameSize,
		memoByteAddr, memoMemoByte,
		failEmpty, matchFn, btOverflowAction(useWork && tripCalls, workLocal, nil), tableMemIdx,
		// The anchored match body starts at 0 and has no origin to rebase onto.
		0, false,
		workLocal, btWorkTrip(useWork, tripCalls, 2, &callOffs, btWorkTripI32),
		dyn)

	body = append(body, 0x00)       // unreachable
	body = append(body, 0x0B)       // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x0B)       // end function
	return body, callOffs
}

// emitBTOncePerCall runs prepare the first time control reaches it in a call,
// behind the flag local ready. WASM zero-initialises locals per call, so the
// flag needs no reset.
func emitBTOncePerCall(b []byte, ready uint32, prepare func([]byte) []byte) []byte {
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, ready)
	b = append(b, 0x45)       // i32.eqz — not yet prepared this call
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x01, 0x21)
	b = utils.AppendULEB128(b, ready)
	b = prepare(b)
	b = append(b, 0x0B) // end if
	return b
}

// --------------------------------------------------------------------------
// appendBTFindCodeEntry / buildBTFindBody

// appendBTFindCodeEntry appends a size-prefixed no-capture BT find body.
// Signature: (ptr i32, len i32) → i64
// Returns (start << 32 | end) on match, -1 on no match.
func appendBTFindCodeEntry(cs []byte, bt *backtrack, scanParams prefixScanParams,
	stackBase, stackLimit, frameSize int32, mandLit *mandatoryLit, tableMemIdx int, workK int, tripCalls bool, fallback *btScratch) (out []byte, mode findFromMode, callOffs []int) {
	body, mode, offs := buildBTFindBody(bt, scanParams, mandLit, stackBase, stackLimit, frameSize, tableMemIdx, workK, tripCalls, fallback)
	sized, offs := btSizePrefix(body, offs)
	return append(cs, sized...), mode, btShiftOffs(offs, len(cs))
}

// buildBTFindBody emits the full WASM function body for a no-capture BT find.
//
// Local layout (function type: (i32,i32)→i64):
//
//	Params:   ptr(0), len(1)
//	i32 fixed: fake_out_ptr(2), pos(3), sp(4), state(5), scratch(6),
//	           attempt_start(7), simd_mask(8)
//	v128:     chunk(9), tLo(10), tHi(11), [chunk1(12), t1Lo(13), t1Hi(14)] if T1
//	i32 rest: memo(9+numV128 .., seven, a fallback only), [lit_pos, scan_start] if mandLit
//
// When mandLit != nil: uses a two-level outer loop — outer loop scans for the
// mandatory literal, inner loop runs BT attempts in the resulting window.
// scanParams is ignored when mandLit != nil (the mandatory-lit prefix scan replaces it).
// btScanLocals is the prefix-scan local layout of buildBTFindBody's body,
// derived from the SAME allocation the body emits its declarations from.
//
// It exists because these indices used to be written out by hand at four call
// sites — three here and one in compile.go's Backtracking fallback — none of
// them the place that decides them. They agreed only by coincidence, and a
// wrong index is not a validation error: WASM locals are zero-initialised, so
// naming the wrong one yields a module that runs and scans from somewhere
// unintended.
//
// The v128 group is fixed at six here because that is the widest shape the
// scan can ask for (two-byte Teddy); a body with fewer simply never names the
// tail. buildBTFindBody asserts its own allocation agrees with this one.
func btScanLocals() (prefixScanLocals, scanCursor) {
	a := newLocalAlloc(2) // ptr, len
	a.Reserve(valI32, 5)  // 2..6 — state, pos and friends
	cur := a.ScanCursor() // 7 — the scan start
	simdMask := a.I32()   // 8 — completes the 7 fixed i32s
	chunk, tLo, tHi := a.V128(), a.V128(), a.V128()
	chunk1, t1Lo, t1Hi := a.V128(), a.V128(), a.V128()
	return prefixScanLocals{
		Ptr: 0, Len: 1, AttemptStart: cur.Local(), SimdMask: simdMask,
		Chunk: chunk, TLo: tLo, THi: tHi, Chunk1: chunk1, T1Lo: t1Lo, T1Hi: t1Hi,
	}, cur
}

// btScanLocalsOnly is btScanLocals without the cursor, for the call sites that
// only need the layout.
func btScanLocalsOnly() prefixScanLocals {
	l, _ := btScanLocals()
	return l
}

func buildBTFindBody(bt *backtrack, scanParams prefixScanParams, mandLit *mandatoryLit,
	stackBase, stackLimit, frameSize int32, tableMemIdx int, workK int, tripCalls bool, fallback *btScratch) (_ []byte, _ findFromMode, callOffs []int) {
	if fallback != nil {
		workK = 0
		tripCalls = false
	}
	useMemo := fallback != nil
	var findFrom findFromMode
	prog := bt.prog

	// Number of v128 locals needed by emitPrefixScan.
	var numV128Locals int
	if mandLit != nil {
		numV128Locals = 1 // chunk for the mandatory-lit prefix scan
	} else if len(scanParams.Prefix) >= 1 {
		numV128Locals = 1
	} else if scanParams.TeddyTwoByte {
		numV128Locals = 6
	} else if len(scanParams.FirstByteSet) > 0 && len(scanParams.FirstByteSet) <= 8 {
		numV128Locals = 3
	} else if n := len(scanParams.FirstByteSet); n > 0 && n <= 16 {
		// 9..16: Shufti unconditionally. Only needs the single "chunk" v128
		// local; emitShuftiPrefixCheck inlines its nibble tables as v128.const
		// operands.
		numV128Locals = 1
	} else if useShufti, _ := shuftiPrefixPlan(scanParams.FirstByteSet,
		scanParams.LikelyNoMatch, false); useShufti {
		// Above 16, ask the SAME predicate the emitter asks instead of
		// restating its ceiling. This site is why that predicate exists: it
		// was capped at 16 after the band had already been widened to 64,
		// which left FirstByteSet 17..64 emitting zero v128 locals while
		// emitShuftiPrefixCheck still used one — invalid WASM, "expected
		// i32, found v128". A shared predicate cannot drift that way.
		//
		// canAdapt is FALSE here: this body reserves no dense-switch locals,
		// so BT stays at the 64-byte ceiling rather than being forced into
		// the wide band with nothing to bound a wrong assertion.
		numV128Locals = 1
	}

	// The i32 locals after the v128 group start at index 9+numV128Locals.
	restBase := uint32(9 + numV128Locals)

	// A fallback's memo locals: seven slots, of which it reads byteAddr and
	// memoByte (the guard), ready (the once-per-call flag that places its
	// run-time region at the first ATTEMPT rather than at the head of the
	// call) and origin (the input position bit index 0 stands for). The
	// ordinary body memoises nothing.
	memoLocalsCount := 0
	var memoByteAddr, memoMemoByte, memoReady, memoOrigin uint32
	if useMemo {
		memoLocalsCount = 7
		memoByteAddr = restBase + 2
		memoMemoByte = restBase + 3
		memoReady = restBase + 5
		memoOrigin = restBase + 6
	}

	// Declare three local groups so that v128 indices are stable regardless of
	// how many memo i32 locals follow:
	//   Group 1: 7 fixed i32s (fake, pos, sp, state, scratch, attempt_start, simd_mask) → idx 2..8
	//   Group 2: numV128Locals v128s → idx 9..9+numV128-1
	//   Group 3: memo i32s (+ lit_pos + scan_start when mandLit != nil) → idx 9+numV128..
	numRestLocals := memoLocalsCount
	// When using mandatory-lit two-level loop, two extra i32 locals are appended:
	//   lit_pos       = restBase + memoLocalsCount
	//   scan_start    = lit_pos + 1
	var litPosLocal, scanStartLocal uint32
	if mandLit != nil {
		litPosLocal = restBase + uint32(memoLocalsCount)
		scanStartLocal = litPosLocal + 1
		numRestLocals += 2
	}
	var body []byte
	// 7 fixed i32s, then the v128 scan locals, then the loop/memo i32s. The
	// allocator coalesces adjacent runs of one type, which reproduces both of
	// the shapes this used to emit by hand: with v128 locals the trailing i32s
	// form a third group, and without them they merge into the leading run —
	// the same "skip the group entirely when the count is 0" convention.
	a := newLocalAlloc(2)
	a.Reserve(valI32, 5)            // 2..6
	attemptCursor := a.ScanCursor() // 7 — the scan start
	a.Reserve(valI32, 1)            // 8, completing the 7 fixed i32s
	// The scan layout is published by btScanLocals for the four call sites
	// that build prefixScanParams for this body; they must agree with what is
	// allocated here, and this is where that is checked.
	if sl, sc := btScanLocals(); sl.AttemptStart != attemptCursor.Local() ||
		sc.Local() != attemptCursor.Local() {
		panic("compile: btScanLocals disagrees with buildBTFindBody's allocation")
	}
	a.Reserve(valV128, numV128Locals)
	a.Reserve(valI32, numRestLocals)
	// A fallback's run-time region, after every index the body names by
	// arithmetic.
	var dyn *btDyn
	if fallback != nil {
		dyn = newBTDyn(*fallback, tableMemIdx, frameSize, len(prog.Inst))
		dyn.memoBase, dyn.cleared = uint32(a.I32()), uint32(a.I32())
		dyn.stackBase, dyn.stackTop = uint32(a.I32()), uint32(a.I32())
		dyn.tmp64 = uint32(a.I64())
	}
	// The work counter (btWorkK) is allocated LAST, so it is the only local a
	// budgeted body adds and no index above moves.
	useWork := workK > 0
	var workLocal uint32
	if useWork {
		workLocal = uint32(a.I64())
	}
	body = a.EmitDecls(body)

	locAttemptStart := attemptCursor.Local()

	// The find-from seed. Placed here because everything above is
	// the locals declaration and everything below reads attempt_start. This
	// body already handles a nonzero start — its memo-skip computes
	// `attempt_start >> 3` precisely so earlier bytes are not revisited — it
	// was simply never told where to start.
	body, findFrom = emitFindFromSeed(body, attemptCursor)

	// The work budget, once per CALL: every attempt this call makes shares
	// it. Sized from the whole input rather than len - from — a larger budget
	// only delays a trip, and the bound stays linear in the input.
	if useWork {
		body = emitBTWorkInit(body, workLocal, workK, len(prog.Inst), func(b []byte) []byte {
			return append(b, 0x20, localLen)
		})
	}

	// ── A fallback's memo: placed ONCE per call, not once per attempt ────────
	//
	// This is the difference between a linear search and a quadratic one, and
	// it is the whole cost of this body on a no-match input. The memo covers
	// every position the call can reach, and re-zeroing it at every
	// attempt_start makes the search O(N*len^2). Measured on `(?:a?)+?xyz`
	// over a no-match input, fuel per doubling of length:
	//
	//	len       64      128      256      512     1024     2048     4096
	//	per-att  x---    x3.86    x3.93    x3.96    x3.98    x3.99    x4.00
	//	per-call x---    x1.98    x1.99    x1.99    x2.00    x2.00    x2.00
	//
	// x4.00 per doubling is quadratic; x2.00 is linear. At 4,096 bytes that is
	// 1,796,155,500 fuel against 1,811,052 — a factor of 992, and the factor
	// grows with length.
	//
	// Sharing the marks across attempts is sound HERE and only here, because
	// this body tracks no captures: the state that can DISTINGUISH two visits
	// to the same instruction is (pc, pos). A pair marked during a failed
	// attempt has no accepting continuation, and that fact does not depend on
	// which start position reached it — so a later attempt may prune it. The
	// CAPTURE body (buildBacktrackBody) must not share them: its state includes
	// the capture registers, so the same (pc, pos) can carry a different
	// answer.
	//
	// The region is placed at the head of the first ATTEMPT rather than here,
	// so a call that finds no candidate never touches memory. `memoPrepare` is
	// that emission; both branches below open their attempt with it.
	//
	// The memo is also REBASED onto the call's `from`. Bit index 0 stands for
	// that position rather than for position 0, which is sound because no
	// attempt in this call ever starts before it — attempt_start is seeded
	// from it and only advances, and the mandatory-literal branch's own
	// `max(..., attempt_start)` keeps it there. The memory the call needs is
	// then sized from len-from rather than from len.
	if useMemo {
		body = append(body, 0x20, locAttemptStart, 0x21)
		body = utils.AppendULEB128(body, memoOrigin)
	}
	// len - from: the span the rebased bit indices cover.
	memoSpan := func(bb []byte) []byte {
		bb = append(bb, 0x20, localLen)
		bb = append(bb, 0x20)
		bb = utils.AppendULEB128(bb, memoOrigin)
		return append(bb, 0x6B) // i32.sub
	}
	memoPrepare := func(b []byte) []byte {
		if dyn == nil {
			return b
		}
		return emitBTOncePerCall(b, memoReady, func(b []byte) []byte {
			return emitBTScratchInit(b, dyn, memoSpan, btUnknownI64)
		})
	}

	// ── Mandatory-literal two-level outer loop ────────────────────────────────
	// When mandLit != nil: outer loop $lit_outer scans for the mandatory literal
	// using an SIMD prefix scan, inner loop $outer runs BT from each candidate
	// window [attempt_start, lit_pos−minOff].  scanParams is not used in this path.
	if mandLit != nil {
		// block $no_match
		body = append(body, 0x02, 0x40)

		// scan_start = attempt_start + minOff.
		//
		// This cursor is an ABSOLUTE position into the whole buffer, so it has
		// to begin at the find-from position rather than at 0; minOff is the
		// earliest the literal can sit relative to a match start. When from is
		// 0 this is exactly the old value. Same correction the DFA
		// mandatory-literal path needed.
		body = append(body, 0x20, locAttemptStart)
		if mandLit.minOff > 0 {
			body = append(body, 0x41)
			body = utils.AppendSLEB128(body, mandLit.minOff)
			body = append(body, 0x6A) // i32.add
		}
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, scanStartLocal) // local.set scan_start

		// loop $lit_outer
		body = append(body, 0x03, 0x40)

		// Emit mandatory-literal SIMD prefix scan.
		// On match: scan_start points to the literal position; OnMatch computes
		//   lit_pos = scan_start
		//   attempt_start = max(0, max(lit_pos − maxOff, attempt_start))
		// On exhaustion: br 1 (ed−1) → exits $no_match → falls through to −1 return.
		//
		// NOTE: scanStartLocal and litPosLocal are < 128 in all practical cases
		// (bounded by loop-PC count + 9 extra locals), so byte-casting is safe.
		mlScan := prefixScanParams{
			Prefix:      mandLit.bytes,
			EngineDepth: 2,
			// AttemptStart is the mandatory-literal scan's OWN cursor, not
			// the body's: this scan restarts from scanStartLocal per literal
			// hit. Everything else is the shared layout.
			Locals: func() prefixScanLocals {
				l := btScanLocalsOnly()
				l.AttemptStart = byte(scanStartLocal)
				return l
			}(),
			OnMatch: func(b []byte) []byte {
				// lit_pos = scan_start
				b = append(b, 0x20)
				b = utils.AppendULEB128(b, scanStartLocal) // local.get scan_start
				b = append(b, 0x21)
				b = utils.AppendULEB128(b, litPosLocal) // local.set lit_pos

				// simd_mask (temp) = lit_pos − maxOff; clamp to 0
				b = append(b, 0x20)
				b = utils.AppendULEB128(b, litPosLocal) // local.get lit_pos
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, mandLit.maxOff)
				b = append(b, 0x6B)       // i32.sub
				b = append(b, 0x22, 0x08) // local.tee simd_mask
				b = append(b, 0x41, 0x00)
				b = append(b, 0x48)       // i32.lt_s: temp < 0?
				b = append(b, 0x04, 0x40) // if void
				b = append(b, 0x41, 0x00)
				b = append(b, 0x21, 0x08) // simd_mask = 0
				b = append(b, 0x0B)       // end if

				// attempt_start = max(simd_mask, attempt_start)
				b = append(b, 0x20, 0x08)            // local.get simd_mask
				b = append(b, 0x20, locAttemptStart) // local.get attempt_start
				b = append(b, 0x4A)                  // i32.gt_s
				b = append(b, 0x04, 0x40)            // if void
				b = append(b, 0x20, 0x08)            // local.get simd_mask
				b = append(b, 0x21, locAttemptStart) // local.set attempt_start
				b = append(b, 0x0B)                  // end if
				return b
			},
		}
		body, _ = emitPrefixScan(body, mlScan)

		// loop $outer: try BT at each position in [attempt_start, lit_pos−minOff].
		body = append(body, 0x03, 0x40) // loop $outer

		// Range check: if attempt_start > lit_pos − minOff:
		//   scan_start = lit_pos + 1; br 2 → $lit_outer (continue outer scan)
		// Depths from inside if block: 0=if, 1=$outer, 2=$lit_outer.
		body = append(body, 0x20, locAttemptStart) // local.get attempt_start
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, litPosLocal) // local.get lit_pos
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, mandLit.minOff)
		body = append(body, 0x6B)       // i32.sub: lit_pos − minOff
		body = append(body, 0x4A)       // i32.gt_s
		body = append(body, 0x04, 0x40) // if void
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, litPosLocal) // local.get lit_pos
		body = append(body, 0x41, 0x01)
		body = append(body, 0x6A) // i32.add
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, scanStartLocal) // local.set scan_start
		body = append(body, 0x0C, 0x02)                  // br 2 → $lit_outer
		body = append(body, 0x0B)                        // end if

		// Re-init BT state for this attempt_start.
		body = memoPrepare(body)
		body = append(body, 0x20, locAttemptStart, 0x21, localPos)
		body = emitBTStackBase(body, stackBase, dyn)
		body = append(body, 0x21, localSP)
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, int32(prog.Start))
		body = append(body, 0x21, localState)

		// block $run_exit / loop $run / dispatch
		failEmpty := func(bb []byte) []byte {
			return append(bb, 0x0C, 0x03) // br 3 → exit $run_exit
		}
		matchFn := func(bb []byte, _ uint32) []byte {
			bb = append(bb, 0x20, locAttemptStart)
			bb = append(bb, 0xAD)       // i64.extend_i32_u
			bb = append(bb, 0x42, 0x20) // i64.const 32
			bb = append(bb, 0x86)       // i64.shl
			bb = append(bb, 0x20, localPos)
			bb = append(bb, 0xAD) // i64.extend_i32_u
			bb = append(bb, 0x84) // i64.or
			bb = append(bb, 0x0F) // return
			return bb
		}
		// Stack overflow: report abi.BTStackOverflow and stop. See
		// btOverflowFindReturn's doc for why abandoning just this
		// attempt_start (what this used to do) cannot produce a truthful
		// answer.
		overflowFind := btOverflowAction(useWork && tripCalls, workLocal, btOverflowFindReturn)
		body = append(body, 0x02, 0x40) // block $run_exit
		body = append(body, 0x03, 0x40) // loop $run
		body = buildBTInnerDisp(body, bt,
			stackBase, stackLimit, frameSize,
			memoByteAddr, memoMemoByte,
			failEmpty, matchFn, overflowFind, tableMemIdx,
			memoOrigin, useMemo,
			workLocal, btWorkTrip(useWork, tripCalls, 2, &callOffs, btUnknownI64),
			dyn)
		body = append(body, 0x00) // unreachable
		body = append(body, 0x0B) // end loop $run
		body = append(body, 0x0B) // end block $run_exit

		// attempt_start++; br $outer
		body = append(body, 0x20, locAttemptStart, 0x41, 0x01, 0x6A, 0x21, locAttemptStart)
		body = append(body, 0x0C, 0x00) // br 0 → $outer

		body = append(body, 0x0B)       // end loop $outer (unreachable)
		body = append(body, 0x0B)       // end loop $lit_outer (unreachable)
		body = append(body, 0x0B)       // end block $no_match (unreachable)
		body = append(body, 0x42, 0x7F) // i64.const -1
		body = append(body, 0x0F)       // return
		body = append(body, 0x0B)       // end function
		return body, findFrom, callOffs
	}

	// ── Standard first-byte / prefix scan path ────────────────────────────────
	// block $no_match / loop $outer
	body = append(body, 0x02, 0x40)
	body = append(body, 0x03, 0x40)

	scanParams.EngineDepth = 2
	scanParams.OnMatch = func(b []byte) []byte {
		// Re-init BT state.
		b = memoPrepare(b)
		b = append(b, 0x20, locAttemptStart, 0x21, localPos)
		b = emitBTStackBase(b, stackBase, dyn)
		b = append(b, 0x21, localSP)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(prog.Start))
		b = append(b, 0x21, localState)

		// block $run_exit
		b = append(b, 0x02, 0x40)
		// loop $run
		b = append(b, 0x03, 0x40)

		failEmpty := func(bb []byte) []byte {
			return append(bb, 0x0C, 0x03) // br 3: exit $run_exit
		}
		// Find matchFn: accept immediately (non-anchored, first match from attempt_start).
		matchFn := func(bb []byte, _ uint32) []byte {
			bb = append(bb, 0x20, locAttemptStart)
			bb = append(bb, 0xAD)       // i64.extend_i32_u
			bb = append(bb, 0x42, 0x20) // i64.const 32
			bb = append(bb, 0x86)       // i64.shl
			bb = append(bb, 0x20, localPos)
			bb = append(bb, 0xAD) // i64.extend_i32_u
			bb = append(bb, 0x84) // i64.or
			bb = append(bb, 0x0F) // return
			return bb
		}

		// Stack overflow: report abi.BTStackOverflow and stop — see the
		// mandLit branch's identical comment above.
		overflowFind := btOverflowAction(useWork && tripCalls, workLocal, btOverflowFindReturn)
		b = buildBTInnerDisp(b, bt,
			stackBase, stackLimit, frameSize,
			memoByteAddr, memoMemoByte,
			failEmpty, matchFn, overflowFind, tableMemIdx,
			memoOrigin, useMemo,
			workLocal, btWorkTrip(useWork, tripCalls, 2, &callOffs, btUnknownI64),
			dyn)

		b = append(b, 0x00) // unreachable
		b = append(b, 0x0B) // end loop $run
		b = append(b, 0x0B) // end block $run_exit
		return b
	}
	body, _ = emitPrefixScan(body, scanParams)

	// attempt_start++; br $outer
	body = append(body, 0x20, locAttemptStart, 0x41, 0x01, 0x6A, 0x21, locAttemptStart)
	body = append(body, 0x0C, 0x00)

	body = append(body, 0x0B)       // end loop $outer
	body = append(body, 0x0B)       // end block $no_match
	body = append(body, 0x42, 0x7F) // i64.const -1
	body = append(body, 0x0F)       // return
	body = append(body, 0x0B)       // end function
	return body, findFrom, callOffs
}
