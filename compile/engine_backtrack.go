package compile

import (
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Backtracking NFA engine

// backtrack is a compiled backtracking NFA.
// It handles capture patterns that cannot be processed by TDFA.
type backtrack struct {
	prog          *syntax.Prog
	numGroups     int          // prog.NumCap / 2 (includes group 0)
	numAlts       int          // count of InstAlt nodes — bounds stack depth
	loops         map[int]bool // set of InstAlt PCs that are genuine loop heads
	nonGreedyLoop map[int]bool // loops[pc] subset: true if the loop body is inst.Arg (non-greedy)
	idom          []int        // immediate-dominator PC per PC, from computeDominators

	// emptyBodyGreedyLoop is the loops[] subset of greedy loops whose body can
	// complete with zero width, e.g. the outer `*` in (?:a*|b*)*. See
	// emitBTInstHandler's InstAlt case for why these need different
	// zero-progress handling than every other loop.
	emptyBodyGreedyLoop map[int]bool

	// memoInnerLoop is a set of Alt/AltMatch PCs that are NOT genuine loop
	// heads by altLoopBody's dominance-based test (so bt.loops[pc] is
	// false and they're compiled as ordinary non-loop alternations), but
	// that nonetheless cycle back to themselves — reached when a back edge
	// lands on an instruction with more than one predecessor path, which
	// dominance can't recognize (e.g. prog.Start itself, or a duplicate
	// "first entry vs. loop-back" instruction Go's compiler emits — see
	// nestedLoopPC's doc). Left as an ordinary non-loop alternation, such a
	// PC re-pushes a fresh retry frame on every entry with no bound,
	// because it has no zero-progress guard of any kind.
	//
	// That's harmless in isolation (each entry still corresponds to a
	// distinct, legitimate backtracking choice), but becomes unbounded
	// when this PC is *also* the sole, unconditional body of an enclosing
	// emptyBodyGreedyLoop (FUZZER_BUGS.md #18, e.g. the inner `a*` inside
	// the outer `+` in `(?:a*)+^`): the outer loop's own zero-progress
	// scalar can be clobbered by an intervening re-entry at a different
	// position before the outer loop is revisited at the position that
	// would let it detect "no progress" — so this inner PC keeps
	// re-pushing frames faster than the outer loop can ever converge,
	// growing the backtrack stack without bound until it overflows and the
	// whole attempt is silently abandoned.
	//
	// These PCs get BitState memoisation instead — memoising the INNER PC
	// specifically, not the outer loop head. An earlier attempt memoised
	// the outer loop head directly and was confirmed live to break both
	// directions: (a) `(?:a*|b*)*` on "b" started returning a wrong
	// non-empty match, because the outer loop's own re-entry at the same
	// position is *also* how the "still-pending sibling branch" mechanism
	// (task 20) works, and blocking it suppressed that sibling; (b) even
	// where it produced the right answer (`(?:a*)+^`), it did so by
	// accident — the trace showed it only worked because it happened not
	// to disturb the specific revisit the zero-progress guard needed.
	// Memoising the inner PC instead leaves the outer loop's own re-entry
	// mechanism completely untouched, and only stops the true source of
	// unbounded growth. See nestedLoopPC for the precise, narrow shape
	// this is restricted to (deliberately excludes `(?:a*|b*)*`, where the
	// outer body branches into multiple sibling alternatives rather than
	// leading unconditionally into one inner self-looping PC).
	memoInnerLoop map[int]bool

	// loopEntryOf maps a loop's first-entry twin PC to its registered loop
	// head PC, for every emptyBodyGreedyLoop head. Go's compiler emits a
	// separate, non-cyclic InstAlt for a captured star's very first entry
	// (identical Out/Arg to the genuine, back-edged loop head, but not
	// itself reached via a back edge, hence bt.loops[pc]==false for it) —
	// see FUZZER_BUGS.md #20. The entry twin is the only place that knows
	// the position at which THIS SPECIFIC loop instance began; the loop
	// head's own zero-progress guard needs that value (not the global
	// attempt start, and not "unconditionally exit") to decide whether an
	// empty-matching iteration is this loop's very first (nothing to
	// resurrect) or came after real progress (a same-iteration sibling must
	// still get its turn). See emitBTInstHandler's InstAlt case.
	loopEntryOf map[int]int

	// loopEntryAtStart is the emptyBodyGreedyLoop[] subset whose body starts
	// at prog.Start itself — e.g. `(?:a??){1,}` with nothing preceding the
	// loop at all. There, no instruction "flows into" the body from
	// outside (loopEntryOf has no entry for this head): the very first
	// dispatch sets state=prog.Start directly, entirely outside
	// emitBTInstHandler's per-instruction logic, so there is no PC to
	// instrument. For these heads the loop's own entry position is simply
	// wherever this match attempt itself began (0 for match/groups bodies,
	// the find engine's attempt_start local otherwise) — so their
	// loopEntryLocalIdx local must be seeded with that value at
	// declaration time instead of the usual -1 sentinel. See
	// emitBTInstHandler's InstAlt case and FUZZER_BUGS.md #20.
	loopEntryAtStart map[int]bool
}

func (b *backtrack) Type() EngineType { return EngineBacktrack }

// newBacktrack builds the backtrack struct from a compiled NFA program.
func newBacktrack(prog *syntax.Prog) *backtrack {
	idom := computeDominators(prog)
	bt := &backtrack{
		prog:                prog,
		numGroups:           prog.NumCap / 2,
		loops:               make(map[int]bool),
		nonGreedyLoop:       make(map[int]bool),
		idom:                idom,
		emptyBodyGreedyLoop: make(map[int]bool),
		memoInnerLoop:       make(map[int]bool),
	}
	for pc, inst := range prog.Inst {
		if inst.Op == syntax.InstAlt {
			bt.numAlts++
			if bodyPC, _, isLoop := altLoopBody(prog, idom, pc); isLoop {
				bt.loops[pc] = true
				bt.nonGreedyLoop[pc] = bodyPC == int(inst.Arg)
				if !bt.nonGreedyLoop[pc] && loopBodyCanMatchEmpty(prog, idom, pc) {
					bt.emptyBodyGreedyLoop[pc] = true
					if innerPC, found := nestedLoopPC(prog, idom, pc); found {
						bt.memoInnerLoop[innerPC] = true
					}
				}
			}
		}
	}

	// Find each emptyBodyGreedyLoop head's external entry point(s): any PC
	// outside the loop body whose successor edge targets the body's start.
	// For a `*`/`?`-shaped loop this is Go's compiler-duplicated "first
	// entry" twin InstAlt (identical Out/Arg to the genuine, back-edged
	// loop head, reached only once per attempt at this loop). For a
	// `+`-shaped loop there is no such twin — the body's mandatory first
	// iteration is reached directly from whatever instruction precedes the
	// repetition (of any Op, not necessarily InstAlt) — so this searches
	// generically by successor-edge target rather than by instruction
	// shape. A PC only counts as an external entry if it is NOT itself
	// reachable from the body's start without first passing back through
	// the loop head (i.e. it isn't one of the loop's own internal PCs
	// re-entering via some other path). See loopEntryOf's doc.
	bt.loopEntryOf = make(map[int]int, len(bt.emptyBodyGreedyLoop))
	bt.loopEntryAtStart = make(map[int]bool)
	for headPC := range bt.emptyBodyGreedyLoop {
		bodyStart := loopBodyStart(prog, idom, headPC)
		if bodyStart == prog.Start {
			// The loop's body IS the very first thing in the program (e.g.
			// `(?:a??){1,}` with nothing preceding it) — there is no
			// predecessor PC to instrument at all; the initial dispatch
			// sets state=prog.Start directly. See loopEntryAtStart's doc.
			bt.loopEntryAtStart[headPC] = true
			continue
		}
		for cand, inst := range prog.Inst {
			if cand == headPC {
				continue
			}
			var targetsBody bool
			switch inst.Op {
			case syntax.InstFail, syntax.InstMatch:
			case syntax.InstAlt, syntax.InstAltMatch:
				targetsBody = int(inst.Out) == bodyStart || int(inst.Arg) == bodyStart
			default:
				targetsBody = int(inst.Out) == bodyStart
			}
			if targetsBody && !pcReachesBounded(prog, bodyStart, cand, headPC) {
				bt.loopEntryOf[cand] = headPC
			}
		}
	}
	return bt
}

// computeDominators returns, for each PC reachable from prog.Start, its
// immediate dominator (idom[pc]); idom[prog.Start] == prog.Start, and
// unreachable PCs get idom == -1. Uses the standard Cooper-Harvey-Kennedy
// iterative algorithm.
func computeDominators(prog *syntax.Prog) []int {
	n := len(prog.Inst)
	successors := func(pc int) []int {
		inst := prog.Inst[pc]
		switch inst.Op {
		case syntax.InstFail, syntax.InstMatch:
			return nil
		case syntax.InstAlt, syntax.InstAltMatch:
			return []int{int(inst.Out), int(inst.Arg)}
		default:
			return []int{int(inst.Out)}
		}
	}

	start := prog.Start
	visited := make([]bool, n)
	visited[start] = true
	var order []int // postorder
	type frame struct {
		pc    int
		idx   int
		succs []int
	}
	stack := []frame{{pc: start, succs: successors(start)}}
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		if f.idx < len(f.succs) {
			w := f.succs[f.idx]
			f.idx++
			if !visited[w] {
				visited[w] = true
				stack = append(stack, frame{pc: w, succs: successors(w)})
			}
			continue
		}
		order = append(order, f.pc)
		stack = stack[:len(stack)-1]
	}

	postNum := make([]int, n)
	for i := range postNum {
		postNum[i] = -1
	}
	for i, pc := range order {
		postNum[pc] = i
	}
	rpo := make([]int, len(order))
	for i, pc := range order {
		rpo[len(order)-1-i] = pc
	}

	var preds [][]int
	preds = make([][]int, n)
	for pc := 0; pc < n; pc++ {
		if !visited[pc] {
			continue
		}
		for _, s := range successors(pc) {
			preds[s] = append(preds[s], pc)
		}
	}

	idom := make([]int, n)
	for i := range idom {
		idom[i] = -1
	}
	idom[start] = start

	intersect := func(a, b int) int {
		for a != b {
			for postNum[a] < postNum[b] {
				a = idom[a]
			}
			for postNum[b] < postNum[a] {
				b = idom[b]
			}
		}
		return a
	}

	for changed := true; changed; {
		changed = false
		for _, b := range rpo {
			if b == start {
				continue
			}
			newIdom := -1
			for _, p := range preds[b] {
				if idom[p] == -1 {
					continue
				}
				if newIdom == -1 {
					newIdom = p
				} else {
					newIdom = intersect(newIdom, p)
				}
			}
			if newIdom != -1 && idom[b] != newIdom {
				idom[b] = newIdom
				changed = true
			}
		}
	}
	return idom
}

// dominates reports whether v dominates u: every path from prog.Start to u
// passes through v. Both must be reachable (idom != -1).
func dominates(idom []int, v, u int) bool {
	if idom[u] == -1 || idom[v] == -1 {
		return false
	}
	for {
		if u == v {
			return true
		}
		if idom[u] == u {
			return false // reached the root without finding v
		}
		u = idom[u]
	}
}

// altLoopBody reports whether the InstAlt at pc is a genuine loop head, and if
// so which branch is the body (the back edge, closing a real cycle) and
// which is the exit. idom is the dominator tree from computeDominators.
//
// A branch pc→w is a back edge — and thus pc a loop head with body=w — when w
// dominates pc: every path from the program's start to pc necessarily passes
// through w, which is exactly the condition for pc→w to close a cycle back to
// an enclosing point rather than merely happening to reach it via some other
// route. This is the standard compiler technique for identifying natural
// loops and is precise even under arbitrary nesting, unlike two simpler tests
// that were tried and both misfire:
//   - A pure numeric PC comparison (Out<pc or Arg<pc) misidentifies unrolled
//     bounded repeats (a{1,300}) as loops: the chain's "keep matching" edges
//     point to numerically lower PCs purely as an artifact of how the
//     unrolled instructions are numbered, with no actual cycle. This
//     previously inflated the per-loop WASM local count (one dedicated local
//     per misidentified "loop") past 256, silently corrupting an unrelated
//     local index used by the BT find path's mandatory-literal scan
//     (prefixScanLocals's byte-typed fields) and crashing with an OOB memory
//     access.
//   - A same-strongly-connected-component test (do pc and w lie on a shared
//     cycle at all?) misidentifies plain forks nested inside a loop's body as
//     loop heads, AND — the opposite failure — merges distinct nested loop
//     levels into one component, making the true inner loop head look
//     "ambiguous" (both branches "in the component") and get rejected. E.g.
//     for (?:(?:(?:^)*)+), the inner star's Alt and the outer plus's Alt end
//     up in the same SCC, so the inner one's own back edge is invisible to a
//     component-level test; only edge-level dominance sees it.
func altLoopBody(prog *syntax.Prog, idom []int, pc int) (bodyPC, exitPC int, isLoop bool) {
	inst := prog.Inst[pc]
	outIsBack := dominates(idom, int(inst.Out), pc)
	argIsBack := dominates(idom, int(inst.Arg), pc)
	switch {
	case outIsBack && !argIsBack:
		return int(inst.Out), int(inst.Arg), true
	case argIsBack && !outIsBack:
		return int(inst.Arg), int(inst.Out), true
	case outIsBack && argIsBack:
		// Both branches test as back edges: pc is simultaneously an inner
		// loop's own back edge and, via the other branch, an enclosing
		// loop's continuation point (FUZZER_BUGS.md #26 — first found when
		// the enclosing loop's continuation happened to be prog.Start
		// itself, which trivially dominates everything). Discriminate by
		// dominance between the two targets directly: whichever target
		// dominates the OTHER target closes the more enclosing loop
		// relative to this Alt, so the other, dominated target is the
		// true, more-local inner-loop body (FUZZER_BUGS.md #29 — the
		// original prog.Start-equality check was only a special case of
		// this and misfires once a prefix construct pushes prog.Start
		// outside the affected group).
		if dominates(idom, int(inst.Arg), int(inst.Out)) {
			return int(inst.Out), int(inst.Arg), true
		}
		if dominates(idom, int(inst.Out), int(inst.Arg)) {
			return int(inst.Arg), int(inst.Out), true
		}
		return 0, 0, false
	default:
		return 0, 0, false
	}
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

// loopBodyStart returns the PC of the first instruction inside the loop body
// at loopPC (the branch that cycles back to loopPC). Only meaningful when
// loopPC is a genuine loop head — callers must have already established that
// via altLoopBody/bt.loops.
func loopBodyStart(prog *syntax.Prog, idom []int, loopPC int) int {
	bodyPC, _, _ := altLoopBody(prog, idom, loopPC)
	return bodyPC
}

// loopBodyCanMatchEmpty returns true if the body of the loop at loopPC can
// execute a full iteration without consuming any byte.  It BFS-traverses all
// NFA paths reachable from the body entry back to loopPC and returns true if
// at least one path contains no byte-consuming instruction.
func loopBodyCanMatchEmpty(prog *syntax.Prog, idom []int, loopPC int) bool {
	bodyStart := loopBodyStart(prog, idom, loopPC)
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

// nestedLoopPC looks for a single, unconditional nested loop directly inside
// loopPC's body — the specific shape FUZZER_BUGS.md #18 needs memoised. It
// walks the body linearly from bodyStart, following only non-branching
// instructions (Capture/Nop), and stops at the FIRST Alt/AltMatch it finds:
// if that instruction cycles back to itself, its PC is returned as the
// nested loop; otherwise — including the case where it's a plain
// (non-cycling) branch choosing between multiple sibling alternatives, e.g.
// the top-level `a*|b*` choice in `(?:a*|b*)*` — this stops and reports
// found=false rather than searching deeper.
//
// This conservatism is required, not just cautious: an earlier, broader
// attempt (memoising the OUTER loop head itself whenever its body contained
// any nested loop, transitively) was confirmed live to break `(?:a*|b*)*` on
// "b" (wrongly returning end=1 instead of the correct end=0) — see
// bt.memoInnerLoop's doc for the full trace of why. Restricting to the
// single-unconditional-path shape, and memoising the inner PC rather than
// the outer, avoids that failure mode entirely: `(?:a*|b*)*`'s outer body
// (a plain branch between the a* and b* sub-loops) never matches this
// shape, so it's never touched.
//
// The returned PC need NOT be a registered loop head in bt.loops:
// altLoopBody's back-edge test is dominance-based (dominates(idom,
// branchTarget, pc)), and dominance can never hold against a PC reached via
// more than one distinct predecessor path — prog.Start itself (nothing but
// start can "dominate" the root), or the duplicate "first entry vs.
// loop-back re-entry" instruction Go's compiler sometimes emits for a
// loop's true first iteration. `(?:a*)+^` produces the former (the inner
// `a*`'s own Alt IS prog.Start); `(?:(?:(a)*?){0,})`-shaped patterns
// produce the latter. Using pcReachesBounded's plain forward reachability
// instead of dominates sidesteps both gaps without touching altLoopBody's
// existing classification (used elsewhere for
// bt.loops/nonGreedyLoop/emptyBodyGreedyLoop) at all. The reachability
// check is bounded at loopPC so it doesn't "leak" through loopPC's own back
// edge and false-positive on every enclosing loop.
func nestedLoopPC(prog *syntax.Prog, idom []int, loopPC int) (innerPC int, found bool) {
	pc := loopBodyStart(prog, idom, loopPC)
	visited := make([]bool, len(prog.Inst))
	for {
		if pc == loopPC || visited[pc] {
			return 0, false
		}
		visited[pc] = true
		inst := prog.Inst[pc]
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			if pcReachesBounded(prog, int(inst.Out), pc, loopPC) || pcReachesBounded(prog, int(inst.Arg), pc, loopPC) {
				return pc, true
			}
			return 0, false
		case syntax.InstCapture, syntax.InstNop:
			pc = int(inst.Out)
		default:
			// Fail/Match/byte-consumer reached before any branching — no
			// nested loop on this linear prefix.
			return 0, false
		}
	}
}

// pcReachesBounded reports whether `target` is reachable from `from` via a
// forward path through the NFA graph that never crosses `boundary` (reaching
// boundary is treated as a dead end, not expanded further) — see
// nestedLoopPC for why the bound is required.
func pcReachesBounded(prog *syntax.Prog, from, target, boundary int) bool {
	visited := make([]bool, len(prog.Inst))
	queue := []int{from}
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		if pc == target {
			return true
		}
		if pc == boundary || visited[pc] {
			continue
		}
		visited[pc] = true
		inst := prog.Inst[pc]
		switch inst.Op {
		case syntax.InstFail, syntax.InstMatch:
			// no successors
		case syntax.InstAlt, syntax.InstAltMatch:
			queue = append(queue, int(inst.Out), int(inst.Arg))
		default:
			queue = append(queue, int(inst.Out))
		}
	}
	return false
}

// btHasWordBoundary reports whether prog contains a \b/\B assertion —
// used to decide whether a non-anchored captureBody needs the edge-scratch
// mechanism (FUZZER_BUGS.md #26): patterns without any \b/\B never emit
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

// needsBitState returns true if prog contains a loop that the scalar
// zero-progress guard alone cannot handle correctly, requiring BitState
// memoisation to break a cycle:
//
//   - A non-greedy loop whose body can execute a full iteration without
//     consuming a byte. For such loops the existing zero-progress guard
//     incorrectly takes the body branch again (instead of exiting), causing
//     an infinite loop.
//   - A PC that nestedLoopPC finds nested, unconditionally and alone, inside
//     an emptyBodyGreedyLoop's body (bt.memoInnerLoop — FUZZER_BUGS.md #18,
//     e.g. the inner `a*` inside the outer `+` in `(?:a*)+^`). Such a PC is
//     never itself a registered loop head (altLoopBody's dominance-based
//     back-edge test can't recognize it — see nestedLoopPC's doc), so it's
//     compiled as an ordinary non-loop alternation with no zero-progress
//     guard of any kind, re-pushing a fresh retry frame on every entry
//     without bound. Left unmemoised, that unbounded growth outpaces the
//     enclosing loop's own (otherwise-correct) zero-progress detection
//     until the backtrack stack overflows and the whole attempt is silently
//     abandoned.
//
// A greedy loop whose empty-matchable body does NOT have this shape (e.g.
// the canonical "catastrophic backtracking" pattern (?:a?)*, or the
// multi-branch (?:a*|b*)*) is already correctly handled by the scalar guard
// alone and does not need BitState — see bt.memoInnerLoop's and
// nestedLoopPC's docs for why memoising the OUTER loop head instead (an
// earlier, broader attempt) is unsound in general.
func needsBitState(prog *syntax.Prog) bool {
	bt := newBacktrack(prog)
	for pc, nonGreedy := range bt.nonGreedyLoop {
		if nonGreedy && loopBodyCanMatchEmpty(prog, bt.idom, pc) {
			return true
		}
	}
	return len(bt.memoInnerLoop) > 0
}

// appendBacktrackCodeEntry appends a size-prefixed backtracking capture body to cs.
// loopCaptureLocals returns the capture local variable indices that are
// modified inside the loop body at loopPC (reachable from inst.Out before
// re-entering loopPC). Only those locals need snapshot save/restore.
// Returns nil if no captures are inside the loop.
func loopCaptureLocals(prog *syntax.Prog, idom []int, loopPC int) []uint32 {
	visited := make([]bool, len(prog.Inst))
	queue := []int{loopBodyStart(prog, idom, loopPC)}
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

func appendBacktrackCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, nativeAnchored bool, tableMemIdx int, edgeScratchOff int32) []byte {
	body := buildBacktrackBody(bt, stackBase, stackLimit, frameSize, memoTableBase, useMemo, nativeAnchored, tableMemIdx, edgeScratchOff)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
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
// edgeScratchOff (-1 when nativeAnchored, or when not applicable) is the
// table-memory offset of an (origPtr,origEnd) pair the wrapper stashes
// before calling this function, letting \b/\B checks (btWordBoundary) see
// past the narrowed slice's edges into the true original input — see
// FUZZER_BUGS.md #26.
func buildBacktrackBody(bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, nativeAnchored bool, tableMemIdx int, edgeScratchOff int32) []byte {
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
		locals := loopCaptureLocals(prog, bt.idom, pc)
		if len(locals) > 0 {
			loopSnapBase[pc] = baseExtra + uint32(snapTotal)
			loopSnapLocals[pc] = locals
			snapTotal += len(locals)
		}
	}

	// loopEntryLocalIdx[headPC] = local variable index holding the position
	// at which that loop instance was entered — see loopEntryOf's doc and
	// FUZZER_BUGS.md #20. Placed after the snapshot locals.
	entryPCsSorted := entryLoopPCsSorted(bt)
	entryBase := baseExtra + uint32(snapTotal)
	loopEntryLocalIdx := make(map[int]uint32, len(entryPCsSorted))
	for j, pc := range entryPCsSorted {
		loopEntryLocalIdx[pc] = entryBase + uint32(j)
	}

	// extraFrameLocals: every loop_pos/loop_entry tracker, plus every
	// per-loop capture snapshot slot (loopSnapBase/loopSnapLocals), saved
	// into and restored from every backtrack frame like captures already
	// are — see btPushFrame's and btNumLoopFrameLocals's docs and
	// FUZZER_BUGS.md #28. The snapshot slots are included here (and not for
	// the no-capture bodies, which have none) because they're per-loop-
	// instance state read by the very same zero-progress guard
	// (restoreLoopSnap) as the trackers, and go stale the same way.
	//
	// Narrowing this to only bt.emptyBodyGreedyLoop heads was tried and
	// reverted: it broke non-greedy loops (e.g. `^(?:(?:(?:a*?){0,}))$`)
	// and other loop shapes outside bug 28's specific repro class — see
	// FUZZER_BUGS.md #28's "Confidence"/investigation notes. All bt.loops
	// heads need this, not just the empty-body-greedy subset.
	extraFrameLocals := make([]uint32, 0, len(loopPCsSorted)+len(entryPCsSorted)+snapTotal)
	for _, pc := range loopPCsSorted {
		extraFrameLocals = append(extraFrameLocals, loopLocalIdx[pc])
	}
	for _, pc := range entryPCsSorted {
		extraFrameLocals = append(extraFrameLocals, loopEntryLocalIdx[pc])
	}
	for _, pc := range loopPCsSorted {
		if snapBase, ok := loopSnapBase[pc]; ok {
			for k := range loopSnapLocals[pc] {
				extraFrameLocals = append(extraFrameLocals, snapBase+uint32(k))
			}
		}
	}

	// Memo locals (only when useMemo=true), placed after all existing locals.
	memoLocalsBase := entryBase + uint32(len(entryPCsSorted))
	var (
		memoLenPlus1 uint32 // localLen + 1, pre-computed at entry
		memoBitIdx   uint32 // state * lenPlus1 + pos
		memoByteAddr uint32 // memoTableBase + bitIdx/8
		memoMemoByte uint32 // loaded byte from bitset
		memoZeroLen  uint32 // (N * lenPlus1 + 7) / 8
	)
	if useMemo {
		memoLenPlus1 = memoLocalsBase
		memoBitIdx = memoLocalsBase + 1
		memoByteAddr = memoLocalsBase + 2
		memoMemoByte = memoLocalsBase + 3
		memoZeroLen = memoLocalsBase + 4
	}

	// Total non-param locals: pos, sp, state, scratch, cap0s, cap0e, ...,
	// loop_pos..., loop_snap..., loop_entry..., (memo locals when useMemo)
	memoLocalsCount := 0
	if useMemo {
		memoLocalsCount = 5
	}
	totalLocals := 4 + numCapLocals + len(loopPCsSorted) + snapTotal + len(entryPCsSorted) + memoLocalsCount

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
	// Iterate loopPCsSorted, not loopLocalIdx directly — map iteration order
	// is randomized per-process and would make the emitted WASM bytes
	// non-deterministic (the instructions themselves are order-independent,
	// but byte-for-byte reproducibility matters for caching/testing).
	for _, pc := range loopPCsSorted {
		body = append(body, 0x41, 0x7F) // i32.const -1
		body = append(body, 0x21)       // local.set
		body = utils.AppendULEB128(body, loopLocalIdx[pc])
	}

	// ── Initialise loop snapshot locals to -1 ───────────────────────────────
	for _, pc := range loopPCsSorted {
		snapBase, ok := loopSnapBase[pc]
		if !ok {
			continue
		}
		for k := range loopSnapLocals[pc] {
			body = append(body, 0x41, 0x7F) // i32.const -1
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, snapBase+uint32(k))
		}
	}

	// ── Initialise loop entry-pos locals ────────────────────────────────────
	// -1 sentinel normally; loopEntryAtStart heads (no external entry PC —
	// see its doc) get this attempt's own start position (0 — pos is
	// initialised to 0 above) instead, since there's no instruction to
	// write it for them at runtime.
	for _, pc := range entryPCsSorted {
		if bt.loopEntryAtStart[pc] {
			body = append(body, 0x41, 0x00) // i32.const 0
		} else {
			body = append(body, 0x41, 0x7F) // i32.const -1
		}
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, loopEntryLocalIdx[pc])
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

		// memory.fill(memoTableBase, 0, memoZeroLen) — single bulk-memory instruction
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, memoTableBase) // i32.const memoTableBase (dst)
		body = append(body, 0x41, 0x00)                 // i32.const 0 (val)
		body = append(body, 0x20)
		body = utils.AppendULEB128(body, memoZeroLen) // local.get memoZeroLen (len)
		body = append(body, 0xFC, 0x0B, 0x00)         // memory.fill memory_idx=0
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
	body = appendTableLoad32(body, tableMemIdx, 0)
	body = append(body, 0x21, localPos) // local.set pos

	// Restore captures from mem[sp+4..sp+4+numCapLocals*4)
	for i := 0; i < numCapLocals; i++ {
		body = append(body, 0x20, localSP)
		body = appendTableLoad32(body, tableMemIdx, uint32(4+i*4))
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, capStartLocal(0)+uint32(i))
	}

	// Restore extraFrameLocals (loop_pos/loop_entry trackers) from
	// mem[sp+4+numCapLocals*4 ..] — see btPushFrame's doc and
	// FUZZER_BUGS.md #28.
	extraOff := uint32(4 + numCapLocals*4)
	for i, localIdx := range extraFrameLocals {
		body = append(body, 0x20, localSP)
		body = appendTableLoad32(body, tableMemIdx, extraOff+uint32(i*4))
		body = append(body, 0x21) // local.set
		body = utils.AppendULEB128(body, localIdx)
	}

	// Restore retry PC from mem[sp + 4 + numCapLocals*4 + len(extraFrameLocals)*4]
	retryPCOffset := extraOff + uint32(len(extraFrameLocals)*4)
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, retryPCOffset)
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

		body = emitBTInstHandler(body, bt, p, inst, brRun, loopLocalIdx, loopEntryLocalIdx, loopSnapBase, loopSnapLocals, extraFrameLocals, stackLimit, frameSize, numCapLocals, memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte, useMemo, false, nativeAnchored, nil, nil, tableMemIdx, edgeScratchOff)
	}

	body = append(body, 0x00)       // unreachable (after all handlers, inside $run)
	body = append(body, 0x0B)       // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1 (unreachable fallthrough)
	body = append(body, 0x0B)       // end function
	return body
}

// emitBitStateGuard emits the shared BitState "already visited (p, pos)?
// fail : mark visited" check — used both for non-greedy empty-body loop
// heads (bt.nonGreedyLoop) and for bt.memoInnerLoop PCs (FUZZER_BUGS.md
// #18). brDepth is the br depth to restart $run from inside this one
// WASM-level if-block (callers pass brRunNested; the enclosing Go-level
// `if useMemo && ...` around the call site is compile-time only and adds no
// WASM nesting).
func emitBitStateGuard(body []byte, p int, memoLenPlus1Local, memoBitIdx, memoByteAddr, memoMemoByte uint32, memoTableBase int32, tableMemIdx int, brDepth uint32) []byte {
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
	body = appendTableLoad8u(body, tableMemIdx) // i32.load8_u (memo byte)
	body = append(body, 0x22)                   // local.tee
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
	// already visited → fail
	body = btFail(body, brDepth)
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
	body = append(body, 0x71)                   // i32.and (&7) (shift amount)
	body = append(body, 0x74)                   // i32.shl: 1 << (bitIdx & 7)
	body = append(body, 0x72)                   // i32.or
	body = appendTableStore8(body, tableMemIdx) // i32.store8 to memo table
	return body
}

// emitBTInstHandler emits WASM for a single NFA instruction handler.
// brRun is the br depth (from handler top level) to restart $run.
// memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte are the
// memo locals/constants; useMemo enables bit check/set for non-greedy zero-
// matchable loop heads.
// noCaptures: when true, InstCapture is treated as NOP and InstMatch calls instMatchFn.
// instMatchFn: emits match action for InstMatch when noCaptures is true.
//
//	second arg is brRunNested (depth from inside one if-block to restart $run).
//
// overflowFn: emits stack-overflow return code for btPushFrame (nil = i32.const -1; return).
func emitBTInstHandler(
	body []byte,
	bt *backtrack,
	p int,
	inst syntax.Inst,
	brRun uint32,
	loopLocalIdx map[int]uint32,
	loopEntryLocalIdx map[int]uint32,
	loopSnapBase map[int]uint32,
	loopSnapLocals map[int][]uint32,
	extraFrameLocals []uint32,
	stackLimit, frameSize int32,
	numCapLocals int,
	memoTableBase int32,
	memoLenPlus1Local, memoBitIdx, memoByteAddr, memoMemoByte uint32,
	useMemo bool,
	noCaptures bool,
	nativeAnchored bool,
	instMatchFn func([]byte, uint32) []byte,
	overflowFn func([]byte, uint32) []byte,
	tableMemIdx int,
	edgeScratchOff int32,
) []byte {
	// brRunNested = br depth from inside one extra if/block to restart $run
	brRunNested := brRun + 1

	// bt.loopEntryOf[p]: this PC is an external entry point into an
	// emptyBodyGreedyLoop's body (its first-entry twin for a `*`/`?`-shaped
	// loop, or the mandatory predecessor for a `+`-shaped loop) — record
	// the position at which this loop instance began, for that loop's own
	// zero-progress guard to consult (FUZZER_BUGS.md #20). See
	// loopEntryOf's doc.
	//
	// The write must happen at the point control actually transfers to
	// inst.Out (bodyStart), not unconditionally at handler entry: p may
	// fail its own check (bounds/rune/assertion) and btFail instead of
	// reaching Out at all, in which case the loop is never entered on this
	// path and writing early would leave a stale, wrong value behind for
	// whenever the loop's own guard next reads it. contOut is the single
	// choke point every case already uses to branch to inst.Out via brRun
	// (never brRunNested — that's a different, nested exit), so gating the
	// write there is exact regardless of instruction type.
	contOut := func(b []byte) []byte {
		if headPC, ok := bt.loopEntryOf[p]; ok {
			b = append(b, 0x20, localPos) // local.get pos (already past any consumed byte)
			b = append(b, 0x21)           // local.set
			b = utils.AppendULEB128(b, loopEntryLocalIdx[headPC])
		}
		return btSetStateAndBr(b, int32(inst.Out), brRun)
	}

	switch inst.Op {
	case syntax.InstRune1:
		body = btBoundsCheck(body, brRunNested)
		body = btCheckRune1(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = contOut(body)

	case syntax.InstRune:
		body = btBoundsCheck(body, brRunNested)
		body = btCheckRuneRanges(body, inst, brRunNested)
		body = btAdvancePos(body)
		body = contOut(body)

	case syntax.InstRuneAny:
		body = btBoundsCheck(body, brRunNested)
		body = btAdvancePos(body)
		body = contOut(body)

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
		body = contOut(body)

	case syntax.InstAlt, syntax.InstAltMatch:
		isLoop := bt.loops[p]
		if !isLoop {
			// Non-loop alternation: push retry=inst.Arg, continue with inst.Out.
			//
			// bt.memoInnerLoop[p]: this PC nonetheless cycles back to itself
			// (FUZZER_BUGS.md #18) but isn't a registered loop head, so it has
			// no zero-progress guard at all — memoise it the same way a
			// non-greedy empty-body loop head is memoised below, to bound the
			// otherwise-unlimited retry growth. See bt.memoInnerLoop's doc.
			if useMemo && bt.memoInnerLoop[p] {
				body = emitBitStateGuard(body, p, memoLenPlus1Local, memoBitIdx, memoByteAddr, memoMemoByte, memoTableBase, tableMemIdx, brRunNested)
			}
			body = btPushFrame(body, numCapLocals, extraFrameLocals, inst.Arg, stackLimit, frameSize, brRunNested, overflowFn, tableMemIdx)
			body = contOut(body)
		} else {
			// Loop alternation: zero-progress guard
			loopLocal := loopLocalIdx[p]

			// ── Part 4: BitState bit check/set ───────────────────────────────
			// Only for non-greedy loop heads with zero-matchable bodies.
			// Greedy loops are correctly handled by the zero-progress guard below.
			if useMemo && bt.nonGreedyLoop[p] {
				body = emitBitStateGuard(body, p, memoLenPlus1Local, memoBitIdx, memoByteAddr, memoMemoByte, memoTableBase, tableMemIdx, brRunNested)
			}

			// For greedy loops: body=Out, exit=Arg. For non-greedy: body=Arg, exit=Out.
			// bt.nonGreedyLoop[p] was determined in newBacktrack via altLoopBody
			// (an actual reachability check), not by comparing PC numbers.
			// In both cases: preferred=inst.Out, retry=inst.Arg.
			// Zero-progress: if pos == loop_pos_local, the preferred branch (Out)
			// matched zero bytes and retrying it would loop forever.
			restoreLoopSnap := func(b []byte) []byte {
				if snapBase, ok := loopSnapBase[p]; ok {
					for k, capLocal := range loopSnapLocals[p] {
						b = append(b, 0x20)
						b = utils.AppendULEB128(b, snapBase+uint32(k))
						b = append(b, 0x21)
						b = utils.AppendULEB128(b, capLocal)
					}
				}
				return b
			}

			// if pos == loop_pos_local: take exit branch
			body = append(body, 0x20, localPos)
			body = append(body, 0x20)
			body = utils.AppendULEB128(body, loopLocal)
			body = append(body, 0x46)       // i32.eq
			body = append(body, 0x04, 0x40) // if void
			if bt.nonGreedyLoop[p] {
				// Exit is Out, which is never pushed as a retry candidate (only
				// Arg=body is) — nothing to pop back to, branch directly.
				body = restoreLoopSnap(body)
				body = btSetStateAndBr(body, int32(inst.Out), brRunNested)
			} else if bt.emptyBodyGreedyLoop[p] {
				// Greedy loop whose body can match empty (e.g. the outer `*`
				// in (?:a*|b*)*, or ` (\B|0)*`/` (\b|0*)*` —
				// FUZZER_BUGS.md #19/#20). Go stdlib's actual leftmost-first
				// answer here depends on whether THIS SPECIFIC LOOP has made
				// any real forward progress since it was entered — not since
				// the whole match attempt began (a mandatory prefix before
				// the loop makes those two positions differ — #20), and not
				// "never, unconditionally" (a body with no nested loop can
				// still have made real progress in an earlier iteration
				// before a later one resolves via a zero-width leaf
				// assertion — #19). loopEntryLocalIdx[p] holds the position
				// at which this loop's first-entry twin instruction last ran
				// (see loopEntryOf's doc) — the correct, per-loop-instance
				// reference point, in place of both the old unconditional
				// exit and the old attempt_start comparison:
				//
				//   - pos == loopEntry (no bytes consumed by this loop
				//     instance at all yet): the loop's own exit legitimately
				//     wins outright — branch directly, same as the
				//     non-greedy case.
				//   - pos != loopEntry (real progress happened at some point
				//     during this loop instance, even though *this*
				//     iteration was zero-width): fail into the normal
				//     backtrack-stack pop instead of exiting directly, so a
				//     still-pending sibling alternative from within this same
				//     doomed iteration (e.g. the "b*"/"0"/"0*" side, pushed
				//     by the inner alternation just before the zero-width
				//     branch ran) gets tried before the loop gives up.
				//     Branching straight to exit here discarded that
				//     candidate. btFail's own restore already recovers
				//     captures from whichever frame it lands on, so no
				//     manual snapshot restore is needed on this path.
				body = append(body, 0x20, localPos)
				body = append(body, 0x20)
				body = utils.AppendULEB128(body, loopEntryLocalIdx[p])
				body = append(body, 0x46)       // i32.eq
				body = append(body, 0x04, 0x40) // if void
				body = restoreLoopSnap(body)
				body = btSetStateAndBr(body, int32(inst.Arg), brRunNested+1)
				body = append(body, 0x05) // else
				body = btFail(body, brRunNested+1)
				body = append(body, 0x0B) // end if (pos == loopEntry)
			} else {
				// Greedy loop whose body can never match empty: this branch
				// can't actually be reached (every completed iteration
				// consumed ≥1 byte, so pos always differs from loop_local),
				// kept for structural symmetry with the general case.
				body = restoreLoopSnap(body)
				body = btSetStateAndBr(body, int32(inst.Arg), brRunNested)
			}
			body = append(body, 0x0B) // end if (pos == loop_local)

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
			body = btPushFrame(body, numCapLocals, extraFrameLocals, inst.Arg, stackLimit, frameSize, brRunNested, overflowFn, tableMemIdx)
			body = contOut(body)
		}

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
			body = append(body, 0x0B) // end if prev != '\n'
			body = append(body, 0x0B) // end if pos == 0
			body = contOut(body)

		case emptyOp&syntax.EmptyBeginText != 0:
			// \A: fires only at pos==0 (beginning of match slice)
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
			body = append(body, 0x0B) // end if next != '\n'
			body = append(body, 0x0B) // end if pos == len
			body = contOut(body)

		case emptyOp&syntax.EmptyEndText != 0:
			// \z: fires only at pos==len (end of match slice)
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
			body = append(body, 0x47)       // i32.ne
			body = append(body, 0x04, 0x40) // if void
			body = btFail(body, brRunNested)
			body = append(body, 0x0B) // end if
			body = contOut(body)

		case emptyOp&syntax.EmptyWordBoundary != 0:
			body = btWordBoundary(body, true, brRunNested, tableMemIdx, edgeScratchOff)
			body = contOut(body)

		case emptyOp&syntax.EmptyNoWordBoundary != 0:
			body = btWordBoundary(body, false, brRunNested, tableMemIdx, edgeScratchOff)
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
			// RE2 semantics: only accept if the full input slice is consumed.
			// The caller sets len = DFA-determined end, so pos must equal len.
			body = append(body, 0x20, localPos)
			body = append(body, 0x20, localLen)
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

// btPushFrame pushes a backtrack frame onto the stack:
// mem[sp+0]                  = pos
// mem[sp+4..4+capLocals*4]   = captures
// mem[sp+extraOff..+extra*4] = extraLocals (loop_pos/loop_entry trackers)
// mem[sp+retryPCOff]         = retryPC
// btPushFrame pushes a backtrack frame. stackLimit and frameSize are passed
// so we can guard against stack overflow: if sp+frameSize > stackLimit, set
// state=-1 (fail) and return instead of writing past allocated memory.
//
// extraLocals: local indices of every loop_pos/loop_entry tracker in the
// program (in the same fixed order the caller uses everywhere else), saved
// into and restored from every frame exactly like captures already are.
// These are per-loop-instance state (FUZZER_BUGS.md #28): once a loop head
// has updated its tracker, popping back to a frame pushed *before* that
// update must undo it too, or the loop head's zero-progress guard compares
// the restored `pos` against a stale tracker value left over from an
// abandoned deeper attempt and misclassifies a fresh loop entry as "already
// made progress," discarding the correct backtrack continuation.
func btPushFrame(b []byte, numCapLocals int, extraLocals []uint32, retryPC uint32, stackLimit, frameSize int32, brDepth uint32, overflowFn func([]byte, uint32) []byte, tableMemIdx int) []byte {
	// Guard: if sp + frameSize > stackLimit → fail (treat as no-match).
	b = append(b, 0x20, localSP)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, frameSize)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, stackLimit)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if void
	if overflowFn != nil {
		b = overflowFn(b, brDepth)
	} else {
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
	}
	b = append(b, 0x0B) // end if

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

	// extraLocals (loop_pos/loop_entry trackers) at offsets 4+numCapLocals*4, ...
	extraOff := uint32(4 + numCapLocals*4)
	for i, localIdx := range extraLocals {
		b = append(b, 0x20, localSP)
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, localIdx)
		b = appendTableStore32(b, tableMemIdx, extraOff+uint32(i*4))
	}

	// retry PC at offset 4 + numCapLocals*4 + len(extraLocals)*4
	retryOff := extraOff + uint32(len(extraLocals)*4)
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
// edgeScratchOff (-1 = not applicable) is the table-memory offset of an
// (origPtr,origEnd) pair stashed by the caller's wrapper before invoking
// this captureBody. When the captureBody is composed behind a find
// wrapper, its own (ptr,len) are already narrowed to the match slice, so
// pos==0/pos==len here are edges of that slice, not necessarily the true
// start/end of the original input — treating them as such silently drops
// real \b context on the other side of the edge (FUZZER_BUGS.md #26).
// When edgeScratchOff >= 0, pos==0 only counts as "no predecessor" if the
// slice's ptr also equals the original ptr (i.e., the slice starts at true
// position 0); otherwise it falls through to the normal ptr+pos-1 load,
// which correctly reads the real preceding byte. Symmetric for pos==len
// against origEnd.
func btWordBoundary(b []byte, wantBoundary bool, brDepth uint32, tableMemIdx int, edgeScratchOff int32) []byte {
	useEdge := edgeScratchOff >= 0

	// Compute prevIsWord (0 or 1) using block (result i32):
	//   if pos == 0 (and, if useEdge, ptr == origPtr): push 0
	//   else: load input[pos-1]; isWordChar → push 0 or 1
	b = append(b, 0x02, 0x7F) // block (result i32) $prevWord
	b = append(b, 0x20, localPos)
	b = append(b, 0x45) // i32.eqz
	if useEdge {
		b = append(b, 0x20, localPtr)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = appendTableLoad32(b, tableMemIdx, 0) // origPtr
		b = append(b, 0x46)                      // i32.eq (ptr == origPtr)
		b = append(b, 0x71)                      // i32.and
	}
	b = append(b, 0x04, 0x40) // if void (pos == 0 [&& ptr == origPtr])
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
	b = append(b, 0x4F) // i32.ge_u
	if useEdge {
		b = append(b, 0x20, localPtr)
		b = append(b, 0x20, localLen)
		b = append(b, 0x6A) // ptr + len
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = appendTableLoad32(b, tableMemIdx, 4) // origEnd
		b = append(b, 0x46)                      // i32.eq (ptr+len == origEnd)
		b = append(b, 0x71)                      // i32.and
	}
	b = append(b, 0x04, 0x40) // if void (pos >= len [&& ptr+len == origEnd])
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

// btAllocSizes returns (stackSize, memoSize) in bytes for a no-capture BT engine.
// frameSize is 8 (pos + retryPC, no cap slots) plus 4 bytes per loop_pos/
// loop_entry tracker (FUZZER_BUGS.md #28) — see btNumLoopFrameLocals.
// memoBudget is the maximum bytes to allocate for the BitState bitset.
func btAllocSizes(bt *backtrack, useMemo bool, _ int, memoBudget int) (stackSize, memoSize int) {
	frameSize := 8 + btNumLoopFrameLocals(bt, false)*4 // pos(4) + extraLocals + retryPC(4)
	maxFrames := bt.numAlts * 4096
	if maxFrames < 4096 {
		maxFrames = 4096
	}
	stackSize = maxFrames * frameSize
	if useMemo && memoBudget > 0 {
		memoSize = memoBudget
	}
	return
}

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
			if r <= 127 {
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
				for r := lo; r <= hi && r <= 127; r++ {
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
			Locals: prefixScanLocals{
				Ptr: 0, Len: 1, AttemptStart: 7, SimdMask: 8,
				Chunk: 9, TLo: 10, THi: 11, Chunk1: 12, T1Lo: 13, T1Hi: 14,
			},
			EngineDepth: 2,
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
		Locals: prefixScanLocals{
			Ptr: 0, Len: 1, AttemptStart: 7, SimdMask: 8,
			Chunk: 9, TLo: 10, THi: 11, Chunk1: 12, T1Lo: 13, T1Hi: 14,
		},
		EngineDepth: 2,
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
// loopLocalIdx maps loop-PC → WASM local index (computed by the caller with the
// correct local layout for the enclosing function).
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
	loopLocalIdx map[int]uint32,
	loopEntryLocalIdx map[int]uint32,
	stackBase, stackLimit, frameSize int32,
	memoTableBase int32,
	memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte uint32,
	useMemo bool,
	failEmptyStack func([]byte) []byte,
	instMatchFn func([]byte, uint32) []byte,
	overflowFn func([]byte, uint32) []byte,
	tableMemIdx int,
) []byte {
	numCapLocals := 0
	prog := bt.prog
	N := len(prog.Inst)

	// extraFrameLocals: every loop_pos/loop_entry tracker, saved into and
	// restored from every backtrack frame like captures already are — see
	// btPushFrame's doc and FUZZER_BUGS.md #28. Order must match the caller's
	// loopLocalIdx/loopEntryLocalIdx local assignment: loopPCsSorted first
	// (bt.loops keys, sorted), then entryLoopPCsSorted(bt).
	//
	// Narrowing this to only bt.emptyBodyGreedyLoop heads was tried and
	// reverted: it broke non-greedy loops and other loop shapes outside
	// bug 28's specific repro class — see buildBacktrackBody's matching note.
	loopPCsSorted := make([]int, 0, len(bt.loops))
	for pc := range bt.loops {
		loopPCsSorted = append(loopPCsSorted, pc)
	}
	sort.Ints(loopPCsSorted)
	entryPCsSorted := entryLoopPCsSorted(bt)
	extraFrameLocals := make([]uint32, 0, len(loopPCsSorted)+len(entryPCsSorted))
	for _, pc := range loopPCsSorted {
		extraFrameLocals = append(extraFrameLocals, loopLocalIdx[pc])
	}
	for _, pc := range entryPCsSorted {
		extraFrameLocals = append(extraFrameLocals, loopEntryLocalIdx[pc])
	}

	// ── FAIL handler (state == -1) ──
	body = append(body, 0x20, localState, 0x41, 0x7F, 0x46, 0x04, 0x40) // state==-1; if void
	body = append(body, 0x20, localSP, 0x41)
	body = utils.AppendSLEB128(body, stackBase)
	body = append(body, 0x4D, 0x04, 0x40) // i32.le_u; if void (empty stack)
	body = failEmptyStack(body)
	body = append(body, 0x0B) // end of (empty stack) if
	// Pop frame: sp -= frameSize
	body = append(body, 0x20, localSP, 0x41)
	body = utils.AppendSLEB128(body, frameSize)
	body = append(body, 0x6B, 0x21, localSP) // i32.sub; local.set sp
	// Restore pos = mem[sp+0]
	body = append(body, 0x20, localSP)
	body = appendTableLoad32(body, tableMemIdx, 0)
	body = append(body, 0x21, localPos)
	// Restore extraFrameLocals from mem[sp+4+numCapLocals*4 ..]
	extraOff := uint32(4 + numCapLocals*4)
	for i, localIdx := range extraFrameLocals {
		body = append(body, 0x20, localSP)
		body = appendTableLoad32(body, tableMemIdx, extraOff+uint32(i*4))
		body = append(body, 0x21)
		body = utils.AppendULEB128(body, localIdx)
	}
	// Restore retryPC = mem[sp+4+numCapLocals*4+len(extraFrameLocals)*4]
	retryOff := extraOff + uint32(len(extraFrameLocals)*4)
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
	emptySnapBase := map[int]uint32{}
	emptySnapLocals := map[int][]uint32{}
	for p := 0; p < N; p++ {
		body = append(body, 0x0B) // end block $pc_p
		inst := prog.Inst[p]
		brRun := uint32(N - 1 - p)
		body = emitBTInstHandler(
			body, bt, p, inst, brRun,
			loopLocalIdx, loopEntryLocalIdx, emptySnapBase, emptySnapLocals, extraFrameLocals,
			stackLimit, frameSize, numCapLocals,
			memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte,
			useMemo,
			true,
			false,
			instMatchFn,
			overflowFn,
			tableMemIdx,
			-1,
		)
	}
	return body
}

// --------------------------------------------------------------------------
// appendBTMatchCodeEntry / buildBTMatchBody

// appendBTMatchCodeEntry appends a size-prefixed no-capture BT match body.
// Signature: (ptr i32, len i32) → i32
// Returns match end position (≥ 0) on success, -1 on failure.
func appendBTMatchCodeEntry(cs []byte, bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, tableMemIdx int) []byte {
	body := buildBTMatchBody(bt, stackBase, stackLimit, frameSize, memoTableBase, useMemo, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBTMatchBody emits the full WASM function body for a no-capture BT match.
//
// Local layout (function type: (i32,i32)→i32):
//
//	Params:  ptr(0), len(1)
//	Locals:  fake_out_ptr(2) [aligns pkg constants], pos(3), sp(4), state(5),
//	         scratch(6), loop_pos(7+), memo(7+numLoops+)
//
// The fake_out_ptr at index 2 aligns the remaining locals with the package-level
// constants (localPos=3, localSP=4, localState=5, localScratch=6) so all
// existing helper functions (btFail, btSetStateAndBr, etc.) can be reused.
func buildBTMatchBody(bt *backtrack, stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, tableMemIdx int) []byte {
	prog := bt.prog
	N := len(prog.Inst)

	loopPCsSorted := make([]int, 0, len(bt.loops))
	for pc := range bt.loops {
		loopPCsSorted = append(loopPCsSorted, pc)
	}
	sort.Ints(loopPCsSorted)
	loopLocalIdx := make(map[int]uint32, len(loopPCsSorted))
	for j, pc := range loopPCsSorted {
		loopLocalIdx[pc] = uint32(7 + j)
	}

	entryPCsSorted := entryLoopPCsSorted(bt)
	entryBase := uint32(7 + len(loopPCsSorted))
	loopEntryLocalIdx := make(map[int]uint32, len(entryPCsSorted))
	for j, pc := range entryPCsSorted {
		loopEntryLocalIdx[pc] = entryBase + uint32(j)
	}

	memoLocalsCount := 0
	var memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte, memoZeroLen uint32
	if useMemo {
		memoLocalsCount = 5
		base := entryBase + uint32(len(entryPCsSorted))
		memoLenPlus1 = base
		memoBitIdx = base + 1
		memoByteAddr = base + 2
		memoMemoByte = base + 3
		memoZeroLen = base + 4
	}

	// +1 for fake out_ptr at index 2
	totalLocals := 4 + len(loopPCsSorted) + len(entryPCsSorted) + memoLocalsCount + 1

	var body []byte
	body = append(body, 0x01)
	body = utils.AppendULEB128(body, uint32(totalLocals))
	body = append(body, 0x7F)

	// pos=0, sp=stackBase, state=prog.Start
	body = append(body, 0x41, 0x00, 0x21, localPos)
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, stackBase)
	body = append(body, 0x21, localSP)
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(prog.Start))
	body = append(body, 0x21, localState)

	// Iterate loopPCsSorted, not loopLocalIdx directly, for deterministic emission.
	for _, pc := range loopPCsSorted {
		body = append(body, 0x41, 0x7F, 0x21)
		body = utils.AppendULEB128(body, loopLocalIdx[pc])
	}
	// loopEntryAtStart heads (no external entry PC — see its doc) are
	// seeded with this attempt's start position (0, for match) instead of
	// the usual -1 sentinel.
	for _, pc := range entryPCsSorted {
		if bt.loopEntryAtStart[pc] {
			body = append(body, 0x41, 0x00, 0x21)
		} else {
			body = append(body, 0x41, 0x7F, 0x21)
		}
		body = utils.AppendULEB128(body, loopEntryLocalIdx[pc])
	}

	if useMemo {
		body = emitBTMemoZeroInit(body, memoTableBase, N, memoLenPlus1, memoZeroLen)
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

	body = buildBTInnerDisp(body, bt, loopLocalIdx, loopEntryLocalIdx,
		stackBase, stackLimit, frameSize,
		memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte,
		useMemo, failEmpty, matchFn, nil, tableMemIdx)

	body = append(body, 0x00)       // unreachable
	body = append(body, 0x0B)       // end loop $run
	body = append(body, 0x41, 0x7F) // i32.const -1
	body = append(body, 0x0B)       // end function
	return body
}

// entryLoopPCsSorted returns bt.emptyBodyGreedyLoop's keys in sorted order,
// for deterministic local assignment — see loopEntryOf's doc.
func entryLoopPCsSorted(bt *backtrack) []int {
	pcs := make([]int, 0, len(bt.emptyBodyGreedyLoop))
	for pc := range bt.emptyBodyGreedyLoop {
		pcs = append(pcs, pc)
	}
	sort.Ints(pcs)
	return pcs
}

// btNumLoopFrameLocals returns the number of extra i32 locals (loop_pos +
// loop_entry trackers, plus per-loop capture snapshot slots when
// withCaptureSnapshots is true) that every backtrack stack frame must
// reserve space for, alongside pos/captures/retryPC — see btPushFrame's doc
// and FUZZER_BUGS.md #28. Callers computing frameSize/stackSize before the
// WASM body itself is built (compile.go, btAllocSizes) use this to stay in
// sync with the per-loop-head local count each body builder actually emits.
//
// withCaptureSnapshots must be true only for the capture-tracking body
// (buildBacktrackBody's loopSnapBase/loopSnapLocals) — the no-capture
// bodies (buildBTMatchBody/buildBTFindBody via buildBTInnerDisp) never
// allocate snapshot locals since there are no captures to snapshot.
// loopSnapLocals are themselves per-loop-instance state read only by the
// same zero-progress guard as loop_pos/loop_entry (restoreLoopSnap on the
// direct "pos == loopEntry" exit branch) — like those, they go stale across
// a backtrack pop if not saved/restored the same way.
//
// Narrowing this to only count bt.emptyBodyGreedyLoop heads was tried and
// reverted (breaks non-greedy loops and other loop shapes outside bug 28's
// specific repro class) — must count every bt.loops head.
func btNumLoopFrameLocals(bt *backtrack, withCaptureSnapshots bool) int {
	n := len(bt.loops) + len(bt.emptyBodyGreedyLoop)
	if withCaptureSnapshots {
		for pc := range bt.loops {
			n += len(loopCaptureLocals(bt.prog, bt.idom, pc))
		}
	}
	return n
}

// emitBTMemoZeroInit emits a memory.fill instruction to zero the memo bitset.
func emitBTMemoZeroInit(body []byte, memoTableBase int32, N int,
	memoLenPlus1, memoZeroLen uint32) []byte {

	// lenPlus1 = localLen + 1
	body = append(body, 0x20, localLen, 0x41, 0x01, 0x6A, 0x21)
	body = utils.AppendULEB128(body, memoLenPlus1)
	// memoZeroLen = (N * lenPlus1 + 7) / 8
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(N))
	body = append(body, 0x20)
	body = utils.AppendULEB128(body, memoLenPlus1)
	body = append(body, 0x6C, 0x41, 0x07, 0x6A, 0x41, 0x03, 0x76, 0x21)
	body = utils.AppendULEB128(body, memoZeroLen)
	// memory.fill(memoTableBase, 0, memoZeroLen) — single bulk-memory instruction
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, memoTableBase) // i32.const memoTableBase (dst)
	body = append(body, 0x41, 0x00)                 // i32.const 0 (val)
	body = append(body, 0x20)
	body = utils.AppendULEB128(body, memoZeroLen) // local.get memoZeroLen (len)
	body = append(body, 0xFC, 0x0B, 0x00)         // memory.fill memory_idx=0
	return body
}

// emitBTMemoZeroInitTrimmed is like emitBTMemoZeroInit but avoids zeroing bytes
// before the current attempt window. Because the BT engine uses absolute positions
// (localPos starts at attempt_start), bits at absolute position p land in byte
// p/8 of the memo. Positions 0..attempt_start-1 are never visited by this
// attempt, so bytes 0..attempt_start/8-1 are guaranteed clean and can be skipped.
//
//	skip = attempt_start >> 3
//	memory.fill(memoTableBase + skip, 0, memoZeroLen - skip)
//
// simd_mask (local 8) is used as a scratch register — it is always free at the
// two find-path call sites (outer retry loop and OnMatch callback).
func emitBTMemoZeroInitTrimmed(body []byte, memoTableBase int32, N int,
	memoLenPlus1, memoZeroLen uint32) []byte {

	// lenPlus1 = localLen + 1
	body = append(body, 0x20, localLen, 0x41, 0x01, 0x6A, 0x21)
	body = utils.AppendULEB128(body, memoLenPlus1)
	// memoZeroLen = (N * lenPlus1 + 7) / 8
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, int32(N))
	body = append(body, 0x20)
	body = utils.AppendULEB128(body, memoLenPlus1)
	body = append(body, 0x6C, 0x41, 0x07, 0x6A, 0x41, 0x03, 0x76, 0x21)
	body = utils.AppendULEB128(body, memoZeroLen)
	// skip = attempt_start(7) >> 3; store in simd_mask(8)
	body = append(body, 0x20, 0x07) // local.get attempt_start
	body = append(body, 0x41, 0x03) // i32.const 3
	body = append(body, 0x76)       // i32.shr_u
	body = append(body, 0x22, 0x08) // local.tee simd_mask (scratch)
	// dst = memoTableBase + skip
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, memoTableBase)
	body = append(body, 0x20, 0x08) // local.get simd_mask
	body = append(body, 0x6A)       // i32.add
	// val = 0
	body = append(body, 0x41, 0x00)
	// clearLen = memoZeroLen - skip
	body = append(body, 0x20)
	body = utils.AppendULEB128(body, memoZeroLen)
	body = append(body, 0x20, 0x08) // local.get simd_mask
	body = append(body, 0x6B)       // i32.sub
	// memory.fill memory_idx=0
	body = append(body, 0xFC, 0x0B, 0x00)
	return body
}

// --------------------------------------------------------------------------
// appendBTFindCodeEntry / buildBTFindBody

// appendBTFindCodeEntry appends a size-prefixed no-capture BT find body.
// Signature: (ptr i32, len i32) → i64
// Returns (start << 32 | end) on match, -1 on no match.
func appendBTFindCodeEntry(cs []byte, bt *backtrack, scanParams prefixScanParams,
	stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, mandLit *mandatoryLit, tableMemIdx int) []byte {
	body := buildBTFindBody(bt, scanParams, mandLit, stackBase, stackLimit, frameSize, memoTableBase, useMemo, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBTFindBody emits the full WASM function body for a no-capture BT find.
//
// Local layout (function type: (i32,i32)→i64):
//
//	Params:   ptr(0), len(1)
//	i32 fixed: fake_out_ptr(2), pos(3), sp(4), state(5), scratch(6),
//	           attempt_start(7), simd_mask(8)
//	v128:     chunk(9), tLo(10), tHi(11), [chunk1(12), t1Lo(13), t1Hi(14)] if T1
//	i32 rest: loop_pos(9+numV128+j ...), memo(...), [lit_pos, scan_start] if mandLit
//
// When mandLit != nil: uses a two-level outer loop — outer loop scans for the
// mandatory literal, inner loop runs BT attempts in the resulting window.
// scanParams is ignored when mandLit != nil (the mandatory-lit prefix scan replaces it).
func buildBTFindBody(bt *backtrack, scanParams prefixScanParams, mandLit *mandatoryLit,
	stackBase, stackLimit, frameSize, memoTableBase int32, useMemo bool, tableMemIdx int) []byte {
	prog := bt.prog
	N := len(prog.Inst)

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
	} else if len(scanParams.FirstByteSet) > 0 && len(scanParams.FirstByteSet) <= 64 {
		// 9..64: Shufti (emitPrefixScan's useSIMD gate — either unconditional
		// for 9..16, or shuftiBeatsScalar/LikelyNoMatch-gated for 17..64).
		// Only needs the single "chunk" v128 local; emitShuftiPrefixCheck
		// inlines its nibble tables as v128.const operands. This upper bound
		// must track emitPrefixScan's own useSIMD ceiling (prefix_scan.go) —
		// previously capped at 16, a stale bound from before LNM Action 3
		// extended Shufti coverage to 64 bytes, which left FirstByteSet
		// 17..64 emitting zero v128 locals while emitShuftiPrefixCheck still
		// used one, producing invalid WASM ("expected i32, found v128").
		numV128Locals = 1
	}

	// loop_pos locals start at index 9+numV128Locals.
	loopLocalsBase := uint32(9 + numV128Locals)

	loopPCsSorted := make([]int, 0, len(bt.loops))
	for pc := range bt.loops {
		loopPCsSorted = append(loopPCsSorted, pc)
	}
	sort.Ints(loopPCsSorted)
	loopLocalIdx := make(map[int]uint32, len(loopPCsSorted))
	for j, pc := range loopPCsSorted {
		loopLocalIdx[pc] = loopLocalsBase + uint32(j)
	}

	// Entry-pos locals follow the loop_pos locals — see loopEntryOf's doc
	// and FUZZER_BUGS.md #20.
	entryPCsSorted := entryLoopPCsSorted(bt)
	entryBase := loopLocalsBase + uint32(len(loopPCsSorted))
	loopEntryLocalIdx := make(map[int]uint32, len(entryPCsSorted))
	for j, pc := range entryPCsSorted {
		loopEntryLocalIdx[pc] = entryBase + uint32(j)
	}

	memoLocalsCount := 0
	var memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte, memoZeroLen uint32
	if useMemo {
		memoLocalsCount = 5
		base := entryBase + uint32(len(entryPCsSorted))
		memoLenPlus1 = base
		memoBitIdx = base + 1
		memoByteAddr = base + 2
		memoMemoByte = base + 3
		memoZeroLen = base + 4
	}

	// Declare three local groups so that v128 indices are stable regardless of
	// how many loop or memo i32 locals follow:
	//   Group 1: 7 fixed i32s (fake, pos, sp, state, scratch, attempt_start, simd_mask) → idx 2..8
	//   Group 2: numV128Locals v128s → idx 9..9+numV128-1
	//   Group 3: loop + entry + memo i32s (+ lit_pos + scan_start when mandLit != nil) → idx 9+numV128..
	// This matches loopLocalsBase = 9 + numV128Locals exactly.
	numLoopAndMemoLocals := len(loopPCsSorted) + len(entryPCsSorted) + memoLocalsCount
	// When using mandatory-lit two-level loop, two extra i32 locals are appended:
	//   lit_pos       = loopLocalsBase + len(loopPCsSorted) + len(entryPCsSorted) + memoLocalsCount
	//   scan_start    = lit_pos + 1
	var litPosLocal, scanStartLocal uint32
	if mandLit != nil {
		litPosLocal = loopLocalsBase + uint32(len(loopPCsSorted)) + uint32(len(entryPCsSorted)) + uint32(memoLocalsCount)
		scanStartLocal = litPosLocal + 1
		numLoopAndMemoLocals += 2
	}
	var body []byte
	if numV128Locals > 0 {
		numGroups := byte(2)
		if numLoopAndMemoLocals > 0 {
			numGroups = 3
		}
		body = append(body, numGroups)
		body = utils.AppendULEB128(body, 7)
		body = append(body, 0x7F) // 7 fixed i32s
		body = utils.AppendULEB128(body, uint32(numV128Locals))
		body = append(body, 0x7B) // numV128 v128s
		if numLoopAndMemoLocals > 0 {
			body = utils.AppendULEB128(body, uint32(numLoopAndMemoLocals))
			body = append(body, 0x7F) // loop+memo (+ lit_pos+scan_start) i32s
		}
	} else {
		body = append(body, 0x01)
		body = utils.AppendULEB128(body, uint32(7+numLoopAndMemoLocals))
		body = append(body, 0x7F)
	}

	const locAttemptStart = byte(0x07)

	// ── Mandatory-literal two-level outer loop ────────────────────────────────
	// When mandLit != nil: outer loop $lit_outer scans for the mandatory literal
	// using an SIMD prefix scan, inner loop $outer runs BT from each candidate
	// window [attempt_start, lit_pos−minOff].  scanParams is not used in this path.
	if mandLit != nil {
		// block $no_match
		body = append(body, 0x02, 0x40)

		// Initialise scan_start = minOff (skip positions where lit can't appear).
		if mandLit.minOff > 0 {
			body = append(body, 0x41)
			body = utils.AppendSLEB128(body, mandLit.minOff)
			body = append(body, 0x21)
			body = utils.AppendULEB128(body, scanStartLocal) // local.set scan_start
		}

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
			Locals: prefixScanLocals{
				Ptr:          0,
				Len:          1,
				AttemptStart: byte(scanStartLocal),
				SimdMask:     8,
				Chunk:        9,
			},
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
		body = emitPrefixScan(body, mlScan)

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
		body = append(body, 0x20, locAttemptStart, 0x21, localPos)
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, stackBase)
		body = append(body, 0x21, localSP)
		body = append(body, 0x41)
		body = utils.AppendSLEB128(body, int32(prog.Start))
		body = append(body, 0x21, localState)
		for _, pc := range loopPCsSorted {
			body = append(body, 0x41, 0x7F, 0x21)
			body = utils.AppendULEB128(body, loopLocalIdx[pc])
		}
		// loopEntryAtStart heads (no external entry PC — see its doc) are
		// seeded with this attempt's own start position instead of the
		// usual -1 sentinel.
		for _, pc := range entryPCsSorted {
			if bt.loopEntryAtStart[pc] {
				body = append(body, 0x20, locAttemptStart, 0x21)
			} else {
				body = append(body, 0x41, 0x7F, 0x21)
			}
			body = utils.AppendULEB128(body, loopEntryLocalIdx[pc])
		}
		if useMemo {
			body = emitBTMemoZeroInitTrimmed(body, memoTableBase, N, memoLenPlus1, memoZeroLen)
		}

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
		// Stack overflow: abandon this attempt_start entirely (branch straight
		// out to $run_exit) rather than aborting the whole find. A "treat like
		// any other failed alternative" pop-and-retry was tried first but can
		// oscillate forever right at the stack ceiling for nested nullable-loop
		// patterns backtracking through a mismatch — this exit is bounded by
		// construction (at most one stack-fill per attempt) since it can never
		// be re-entered from within the same attempt.
		overflowFind := func(bb []byte, brDepth uint32) []byte {
			bb = append(bb, 0x0C) // br
			return utils.AppendULEB128(bb, brDepth+1)
		}
		body = append(body, 0x02, 0x40) // block $run_exit
		body = append(body, 0x03, 0x40) // loop $run
		body = buildBTInnerDisp(body, bt, loopLocalIdx, loopEntryLocalIdx,
			stackBase, stackLimit, frameSize,
			memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte,
			useMemo, failEmpty, matchFn, overflowFind, tableMemIdx)
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
		return body
	}

	// ── Standard first-byte / prefix scan path ────────────────────────────────
	// block $no_match / loop $outer
	body = append(body, 0x02, 0x40)
	body = append(body, 0x03, 0x40)

	scanParams.EngineDepth = 2
	scanParams.OnMatch = func(b []byte) []byte {
		// Re-init BT state.
		b = append(b, 0x20, locAttemptStart, 0x21, localPos)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, stackBase)
		b = append(b, 0x21, localSP)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(prog.Start))
		b = append(b, 0x21, localState)
		for _, pc := range loopPCsSorted {
			b = append(b, 0x41, 0x7F, 0x21)
			b = utils.AppendULEB128(b, loopLocalIdx[pc])
		}
		// loopEntryAtStart heads (no external entry PC — see its doc) are
		// seeded with this attempt's own start position instead of the
		// usual -1 sentinel.
		for _, pc := range entryPCsSorted {
			if bt.loopEntryAtStart[pc] {
				b = append(b, 0x20, locAttemptStart, 0x21)
			} else {
				b = append(b, 0x41, 0x7F, 0x21)
			}
			b = utils.AppendULEB128(b, loopEntryLocalIdx[pc])
		}
		if useMemo {
			b = emitBTMemoZeroInitTrimmed(b, memoTableBase, N, memoLenPlus1, memoZeroLen)
		}

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

		// Stack overflow: abandon this attempt_start entirely — see the
		// mandLit branch's identical comment above for why (bounded vs. a
		// pop-and-retry that can oscillate forever at the stack ceiling).
		overflowFind := func(bb []byte, brDepth uint32) []byte {
			bb = append(bb, 0x0C) // br
			return utils.AppendULEB128(bb, brDepth+1)
		}
		b = buildBTInnerDisp(b, bt, loopLocalIdx, loopEntryLocalIdx,
			stackBase, stackLimit, frameSize,
			memoTableBase, memoLenPlus1, memoBitIdx, memoByteAddr, memoMemoByte,
			useMemo, failEmpty, matchFn, overflowFind, tableMemIdx)

		b = append(b, 0x00) // unreachable
		b = append(b, 0x0B) // end loop $run
		b = append(b, 0x0B) // end block $run_exit
		return b
	}
	body = emitPrefixScan(body, scanParams)

	// attempt_start++; br $outer
	body = append(body, 0x20, locAttemptStart, 0x41, 0x01, 0x6A, 0x21, locAttemptStart)
	body = append(body, 0x0C, 0x00)

	body = append(body, 0x0B)       // end loop $outer
	body = append(body, 0x0B)       // end block $no_match
	body = append(body, 0x42, 0x7F) // i64.const -1
	body = append(body, 0x0F)       // return
	body = append(body, 0x0B)       // end function
	return body
}
