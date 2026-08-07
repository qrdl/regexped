package compile

import (
	"fmt"
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// TDFA (Tagged DFA) engine
//
// Implements Laurikari's algorithm: subset construction of a tagged NFA into a
// DFA that tracks capture group boundaries via register operations on transitions.
// Each register is a WASM local (i32) holding a byte position.
//
// Tag operations on a transition are one of:
//   reg = pos        — record current input position into register
//   reg = other_reg  — copy (register reconciliation on loop back-edges)

// captureOp records an open or close event for a capture group.
type captureOp struct {
	open  bool // true=open (record start), false=close (record end)
	group int  // capture group index (0 = whole match)
}

//
// The TDFA transition table shares the same format as dfaTable and reuses
// minimizeDFA, buildDFALayout, and dfaDataSegments unchanged.

// --------------------------------------------------------------------------
// Data structures

// tdfaTagOp is a single register operation emitted on a TDFA transition.
type tdfaTagOp struct {
	dst int // destination register index
	src int // -1 = assign pos; ≥0 = copy from register src
}

// tdfaTable wraps *dfaTable (transition integers + accept sets) and adds
// parallel slices for tag operations, known at compile time.
type tdfaTable struct {
	*dfaTable
	// tagOps[prevState*256+byte] = ops emitted after the transition from prevState on byte.
	// nil = no ops on this (prevState, byte) pair.
	tagOps [][]tdfaTagOp
	// acceptOps[state] = ops emitted when state accepts at end-of-input.
	acceptOps [][]tdfaTagOp
	// acceptRegMap[state] maps group*2 (start) and group*2+1 (end) to register index.
	// Used by WASM emitter to write capture slots to out_ptr at accept time.
	acceptRegMap [][]int
	numRegs      int         // total WASM locals allocated for capture registers
	numGroups    int         // number of capture groups (including group 0)
	entryOps     []tdfaTagOp // ops emitted at function entry (before first byte is consumed)

	// bulkSkip describes a single dominant self-loop state eligible for SIMD
	// bulk-skip in the match body (Gap F); nil when no qualifying state exists.
	bulkSkip *tdfaBulkSkipInfo
}

// --------------------------------------------------------------------------
// Internal subset-construction types

// tdfaThread is one NFA thread inside a TDFA state.
// regMap[tagIdx] = register index holding that tag (canonical numbering).
type tdfaThread struct {
	pc     int
	regMap []int // len = numTags; -1 = unset
}

// tdfaStateKey is the canonical form of a TDFA state: sorted threads by pc,
// each with a canonical regMap, plus the prevWasWord context bit.
type tdfaStateKey struct {
	threads     []tdfaThread
	prevWasWord bool
}

// scratchRegSentinel marks a dst/src slot that refers to the cycle-breaking
// scratch register (see sequentializeCopies). It is resolved to a concrete
// register index in a fixup pass once nextReg's final value is known — see
// the "resolve scratch register" step at the end of newTDFA. It must not
// collide with -1 (tdfaTagOp's own "assign from pos" marker) or any real
// (non-negative) register index.
const scratchRegSentinel = -2

// sequentializeCopies orders a set of register-to-register copies (each
// produced from a bijective rename map, so every dst is distinct and every
// src is distinct) so that executing them in the returned order reproduces
// the effect of one atomic parallel assignment: every op reads its source's
// pre-transition value, never a value some earlier op in this same batch
// already overwrote.
//
// This is the classic "parallel copy" (a.k.a. "parallel move") sequencing
// problem from register-allocation theory. A single fixed sort direction
// (e.g. descending dst) only produces a correct order for chains that happen
// to run in that direction; a chain running the other way silently reads an
// already-clobbered value. This instead walks the actual dst→src dependency
// graph: an op is safe to emit once no other still-pending op needs to read
// its destination first. When only cycles remain (A needs B's slot, B needs
// A's), one is broken by spilling to a scratch register.
func sequentializeCopies(copyOps []tdfaTagOp) []tdfaTagOp {
	if len(copyOps) <= 1 {
		return append([]tdfaTagOp(nil), copyOps...)
	}

	srcOf := make(map[int]int, len(copyOps))
	dsts := make([]int, 0, len(copyOps))
	for _, op := range copyOps {
		srcOf[op.dst] = op.src
		dsts = append(dsts, op.dst)
	}
	sort.Ints(dsts) // deterministic iteration/tie-break order

	remaining := make(map[int]bool, len(dsts))
	for _, d := range dsts {
		remaining[d] = true
	}

	result := make([]tdfaTagOp, 0, len(copyOps)+2)
	for len(remaining) > 0 {
		needed := make(map[int]bool, len(remaining))
		for _, d := range dsts {
			if remaining[d] {
				needed[srcOf[d]] = true
			}
		}

		progressed := false
		for _, d := range dsts {
			if !remaining[d] || needed[d] {
				continue
			}
			result = append(result, tdfaTagOp{dst: d, src: srcOf[d]})
			delete(remaining, d)
			progressed = true
		}
		if progressed {
			continue
		}

		// Only cycles remain: nothing is currently safe to overwrite. Break
		// the lowest-numbered pending one via the scratch register, then
		// redirect whichever op depended on its original value to read the
		// scratch register instead. The now-freed slot becomes safe next round.
		var breakDst int
		for _, d := range dsts {
			if remaining[d] {
				breakDst = d
				break
			}
		}
		result = append(result, tdfaTagOp{dst: scratchRegSentinel, src: breakDst})
		result = append(result, tdfaTagOp{dst: breakDst, src: srcOf[breakDst]})
		delete(remaining, breakDst)
		for _, d := range dsts {
			if remaining[d] && srcOf[d] == breakDst {
				srcOf[d] = scratchRegSentinel
			}
		}
	}
	return result
}

// keyString serialises a tdfaStateKey to a map-friendly string.
func (k *tdfaStateKey) keyString() string {
	// Format: repeated "(pc:[r0,r1,...])W?" sorted by pc.
	b := make([]byte, 0, 64)
	for _, t := range k.threads {
		b = fmt.Appendf(b, "(%d:[", t.pc)
		for i, r := range t.regMap {
			if i > 0 {
				b = append(b, ',')
			}
			b = fmt.Appendf(b, "%d", r)
		}
		b = append(b, ']', ')')
	}
	if k.prevWasWord {
		b = append(b, 'W')
	}
	return string(b)
}

// --------------------------------------------------------------------------
// tdfaEpsCapOps follows epsilon transitions from fromPC (just after a byte
// consumer's Out), collecting InstCapture ops until the first byte consumer
// or InstMatch. Used for entry-path op collection (linear paths only).
func tdfaEpsCapOps(prog *syntax.Prog, fromPC int, visited map[int]bool) (targetPC int, ops []captureOp) {
	if fromPC < 0 || fromPC >= len(prog.Inst) || visited[fromPC] {
		return -1, nil
	}
	visited[fromPC] = true
	inst := prog.Inst[fromPC]
	switch inst.Op {
	case syntax.InstMatch:
		return fromPC, nil
	case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return fromPC, nil // byte consumer — stop here
	case syntax.InstCapture:
		var op captureOp
		if inst.Arg&1 == 0 {
			op = captureOp{open: true, group: int(inst.Arg >> 1)}
		} else {
			op = captureOp{open: false, group: int(inst.Arg >> 1)}
		}
		tPC, rest := tdfaEpsCapOps(prog, int(inst.Out), visited)
		return tPC, append([]captureOp{op}, rest...)
	case syntax.InstNop:
		return tdfaEpsCapOps(prog, int(inst.Out), visited)
	case syntax.InstAlt, syntax.InstAltMatch:
		tPC, ops := tdfaEpsCapOps(prog, int(inst.Out), visited)
		if tPC >= 0 {
			return tPC, ops
		}
		return tdfaEpsCapOps(prog, int(inst.Arg), visited)
	case syntax.InstEmptyWidth:
		return tdfaEpsCapOps(prog, int(inst.Out), visited)
	}
	return -1, nil
}

// tdfaEpsCapOpsTo follows epsilon transitions from fromPC looking for targetPC,
// collecting InstCapture ops along the way. Tries Alt.Out then Alt.Arg.
// Returns (true, ops) if targetPC is found, (false, nil) otherwise.
// Used in processTransition to correctly find capture ops through Alt loops.
func tdfaEpsCapOpsTo(prog *syntax.Prog, fromPC, targetPC int, visited map[int]bool) (bool, []captureOp) {
	if fromPC < 0 || fromPC >= len(prog.Inst) || visited[fromPC] {
		return false, nil
	}
	if fromPC == targetPC {
		return true, nil
	}
	visited[fromPC] = true
	inst := prog.Inst[fromPC]
	switch inst.Op {
	case syntax.InstMatch, syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return false, nil // byte consumer or terminal — not the target
	case syntax.InstCapture:
		var op captureOp
		if inst.Arg&1 == 0 {
			op = captureOp{open: true, group: int(inst.Arg >> 1)}
		} else {
			op = captureOp{open: false, group: int(inst.Arg >> 1)}
		}
		ok, rest := tdfaEpsCapOpsTo(prog, int(inst.Out), targetPC, visited)
		if !ok {
			return false, nil
		}
		return true, append([]captureOp{op}, rest...)
	case syntax.InstNop:
		return tdfaEpsCapOpsTo(prog, int(inst.Out), targetPC, visited)
	case syntax.InstAlt, syntax.InstAltMatch:
		if ok, ops := tdfaEpsCapOpsTo(prog, int(inst.Out), targetPC, visited); ok {
			return true, ops
		}
		return tdfaEpsCapOpsTo(prog, int(inst.Arg), targetPC, visited)
	case syntax.InstEmptyWidth:
		return tdfaEpsCapOpsTo(prog, int(inst.Out), targetPC, visited)
	}
	return false, nil
}

// --------------------------------------------------------------------------
// TDFA construction

// newTDFA builds a tdfaTable from a compiled NFA program using Laurikari's algorithm.
// Returns (table, true) on success, (nil, false) if the state limit is exceeded.
// Always uses leftmostFirst=true (RE2/Perl semantics).
func newTDFA(prog *syntax.Prog, limit int) (*tdfaTable, bool) {
	const leftmostFirst = true

	numGroups := prog.NumCap / 2 // includes group 0
	numTags := prog.NumCap       // open tag for group i = tag i*2, close tag = i*2+1

	// isWordChar used locally for \b/\B handling.
	isWordChar := isWordCharByte

	// epsilonClosure and expandWithWB via shared helpers.
	epsilonClosure := func(states []uint32, ctx int) []uint32 {
		return nfaEpsilonClosure(prog, states, ctx, leftmostFirst)
	}
	expandWithWB := func(closedSet []uint32, wbCtx int) []uint32 {
		return nfaExpandWithWB(prog, closedSet, wbCtx, leftmostFirst)
	}

	// filterTerminalPCs removes epsilon-transparent NFA instructions (InstAlt,
	// InstCapture, InstNop, InstEmptyWidth) from an epsilon-closed PC set, keeping
	// only byte consumers (InstRune*) and InstMatch. Epsilon nodes are redundant in
	// TDFA thread sets because their descendants are already present in the closure.
	filterTerminalPCs := func(pcs []uint32) []uint32 {
		out := pcs[:0:len(pcs)]
		for _, pc := range pcs {
			switch prog.Inst[pc].Op {
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL, syntax.InstMatch:
				out = append(out, pc)
			}
		}
		return out
	}

	// isAccepting reports whether any state in set reaches InstMatch via epsilon under ctx.
	isAccepting := func(states []uint32, ctx int) bool {
		expanded := epsilonClosure(states, ctx)
		for _, pc := range expanded {
			if prog.Inst[pc].Op == syntax.InstMatch {
				return true
			}
		}
		return false
	}

	// ---- state management ----
	stateMap := make(map[string]int) // keyString → state id
	nextStateID := 0
	nextReg := 0 // monotonically allocated register counter
	// usedScratchReg is true once any transition's copy sequencing needed the
	// cycle-breaking scratch register (see sequentializeCopies). Resolved to
	// a concrete register index in a fixup pass once nextReg is final.
	usedScratchReg := false

	// Per-state data accumulated during construction.
	type stateData struct {
		key         tdfaStateKey
		nfaPCs      []uint32 // bare NFA PCs (for epsilonClosure / accept checks)
		prevWasWord bool
	}
	var states []stateData

	// DFA-compatible accept/transition tables — built in parallel with tag data.
	// We build the dfaTable fields manually so we can pass the result to minimizeDFA.
	dfaAccepting := make(map[int]uint64)
	dfaMidAccepting := make(map[int]uint64)
	dfaMidAcceptNW := make(map[int]uint64)
	dfaMidAcceptW := make(map[int]uint64)
	dfaImmediateAccepting := make(map[int]uint64)
	var dfaTransitions []int // allocated after construction

	// Tag operation tables.
	var tagOpTable [][]tdfaTagOp    // tagOpTable[state*256+byte]
	var acceptOpTable [][]tdfaTagOp // acceptOpTable[state]
	var acceptRegMapTable [][]int   // acceptRegMapTable[state][tagIdx] = register

	// ---- helper: derive bare NFA PCs from a tdfaStateKey ----
	keyToPCs := func(k tdfaStateKey) []uint32 {
		pcs := make([]uint32, len(k.threads))
		for i, t := range k.threads {
			pcs[i] = uint32(t.pc)
		}
		return pcs
	}

	// ---- helper: canonical numbering ----
	// Given a set of (pc, {tagIdx→reg}) threads, produce a canonical form by:
	// 1. Sorting threads by pc (leftmostFirst order is already sorted by priority;
	//    we sort by pc for a deterministic canonical key).
	// 2. Renaming registers to 0, 1, 2, … in order of first appearance
	//    scanning threads left-to-right, tags 0…numTags-1.
	// Returns the canonical threads and a rename map: oldReg → newCanonicalReg.
	// Newly allocated canonical registers (not yet backed by real registers) are
	// assigned new indices from allocReg().
	canonicalise := func(threads []tdfaThread) (canonical []tdfaThread, rename map[int]int, newRegs int) {
		sorted := make([]tdfaThread, len(threads))
		copy(sorted, threads)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].pc < sorted[j].pc })

		rename = make(map[int]int)
		counter := 0
		for i := range sorted {
			newMap := make([]int, numTags)
			for tag := 0; tag < numTags; tag++ {
				old := sorted[i].regMap[tag]
				if old < 0 {
					newMap[tag] = -1
					continue
				}
				if c, ok := rename[old]; ok {
					newMap[tag] = c
				} else {
					rename[old] = counter
					newMap[tag] = counter
					counter++
				}
			}
			sorted[i].regMap = newMap
		}
		return sorted, rename, counter
	}

	// ---- helper: getOrAddState ----
	// Given a set of (pc, regMap) threads and a prevWasWord context, find or
	// create the corresponding TDFA state. Returns (stateID, opsToEmitOnTransition).
	//
	// Register design: canonical register index = real WASM local index. No per-state
	// allocation. Thread regMap values entering this function must be:
	//   -1  : tag not yet captured
	//   -2  : tag captured at current position (sentinel; replaced internally)
	//   >= 0: canonical register index from the source state holding this tag's value
	//
	// nextReg is the global high-water mark of canonical register indices used so far.
	getOrAddState := func(threads []tdfaThread, prevWasWord bool) (int, []tdfaTagOp) {
		// Replace -2 (captured-at-pos) sentinels with unique IDs >= nextReg so that
		// canonicalise can tell them apart and from real source register indices.
		// TAG MINIMISATION: all threads that capture the same tag on the same
		// transition record the same position. Share one sentinel per tagIdx so
		// that canonicalise assigns them the same canonical register index, which
		// prevents the state explosion that occurs with repeated optional groups.
		sentinelBase := nextReg
		sentinelNext := sentinelBase
		tagSentinels := make(map[int]int) // tagIdx → shared sentinel
		workThreads := make([]tdfaThread, len(threads))
		for i, t := range threads {
			rm := make([]int, numTags)
			copy(rm, t.regMap)
			for j, v := range rm {
				if v == -2 {
					if s, ok := tagSentinels[j]; ok {
						rm[j] = s
					} else {
						tagSentinels[j] = sentinelNext
						rm[j] = sentinelNext
						sentinelNext++
					}
				}
			}
			workThreads[i] = tdfaThread{pc: t.pc, regMap: rm}
		}

		canonical, rename, counter := canonicalise(workThreads)

		// Compute ops for this transition:
		//   orig >= sentinelBase → was a freshly-captured tag → reg[can] = pos
		//   orig <  sentinelBase, orig != can → inherited but renumbered → reg[can] = reg[orig]
		// Copies are ordered by sequentializeCopies (dependency-safe — a fixed
		// sort direction is NOT sufficient here, see its doc comment and
		// plans/TODO.md task 13's investigation). Set-ops are sorted by
		// ascending dst to ensure deterministic WASM emission independent of
		// Go's non-deterministic map iteration order over `rename`.
		var copyOps, setOps []tdfaTagOp
		for orig, can := range rename {
			if orig >= sentinelBase {
				setOps = append(setOps, tdfaTagOp{dst: can, src: -1}) // set from pos
			} else if orig != can {
				copyOps = append(copyOps, tdfaTagOp{dst: can, src: orig}) // copy
			}
		}
		copyOps = sequentializeCopies(copyOps)
		if !usedScratchReg {
			for _, op := range copyOps {
				if op.dst == scratchRegSentinel || op.src == scratchRegSentinel {
					usedScratchReg = true
					break
				}
			}
		}
		sort.Slice(setOps, func(i, j int) bool { return setOps[i].dst < setOps[j].dst })
		copyOps = append(copyOps, setOps...)
		ops := copyOps

		// Update global register high-water mark (canonical indices ARE WASM locals).
		if counter > nextReg {
			nextReg = counter
		}

		key := tdfaStateKey{threads: canonical, prevWasWord: prevWasWord}
		ks := key.keyString()

		if id, exists := stateMap[ks]; exists {
			return id, ops
		}

		// New state.
		id := nextStateID
		nextStateID++
		stateMap[ks] = id

		pcs := keyToPCs(key)
		var eofWBCtx int
		if prevWasWord {
			eofWBCtx = ecWordBoundary
		} else {
			eofWBCtx = ecNoWordBoundary
		}
		if isAccepting(pcs, ecEnd|eofWBCtx) {
			dfaAccepting[id] = 1
		}
		if isAccepting(pcs, 0) {
			dfaMidAccepting[id] = 1
		}
		var nwCtx, wCtx int
		if prevWasWord {
			nwCtx = ecWordBoundary
			wCtx = ecNoWordBoundary
		} else {
			nwCtx = ecNoWordBoundary
			wCtx = ecWordBoundary
		}
		if isAccepting(pcs, nwCtx) {
			dfaMidAcceptNW[id] = 1
		}
		if isAccepting(pcs, wCtx) {
			dfaMidAcceptW[id] = 1
		}
		if isImmediateAccepting(pcs, prog) {
			dfaImmediateAccepting[id] = 1
		}

		// Build acceptRegMap: which register holds each tag in the highest-priority
		// accepting thread at accept time.
		regMap := make([]int, numTags)
		for i := range regMap {
			regMap[i] = -1
		}
		for _, t := range canonical {
			if isAccepting([]uint32{uint32(t.pc)}, ecEnd|eofWBCtx) ||
				isAccepting([]uint32{uint32(t.pc)}, 0) {
				copy(regMap, t.regMap)
				break
			}
		}

		states = append(states, stateData{
			key:         key,
			nfaPCs:      pcs,
			prevWasWord: prevWasWord,
		})

		// Extend tables.
		for len(tagOpTable) <= id*256+255 {
			tagOpTable = append(tagOpTable, nil)
		}
		for len(acceptOpTable) <= id {
			acceptOpTable = append(acceptOpTable, nil)
		}
		for len(acceptRegMapTable) <= id {
			acceptRegMapTable = append(acceptRegMapTable, nil)
		}
		acceptRegMapTable[id] = regMap

		return id, ops
	}

	// ---- build start state ----
	// Determine which tags fire on the initial epsilon path from prog.Start
	// to the first byte-consuming NFA state. These become entry ops (fired
	// at function entry before any byte is consumed, at position 0).
	startPCSet := filterTerminalPCs(epsilonClosure([]uint32{uint32(prog.Start)}, ecBegin))
	startRegMap := make([]int, numTags)
	for i := range startRegMap {
		startRegMap[i] = -1
	}
	// Collect entry-path ops: tdfaEpsCapOps from prog.Start gives the capture
	// ops on the path to the first byte consumer.
	entryVisited := make(map[int]bool)
	entryTargetPC, entryCapOps := tdfaEpsCapOps(prog, prog.Start, entryVisited)
	entryRegMap := append([]int(nil), startRegMap...)
	if entryTargetPC >= 0 {
		for _, cop := range entryCapOps {
			tagIdx := cop.group * 2
			if !cop.open {
				tagIdx++
			}
			if tagIdx < numTags {
				entryRegMap[tagIdx] = -2 // captured at entry (pos=0)
			}
		}
	}
	// Apply regMaps to threads: each terminal PC in startPCSet gets the capture ops
	// on the epsilon path from prog.Start to that PC. For the first byte consumer
	// (entryTargetPC), these are the entry ops (fired before the loop). For other
	// terminal PCs (e.g. InstMatch reachable without consuming bytes, as in (a*)),
	// we also discover captures via tdfaEpsCapOpsTo.
	startThreads := make([]tdfaThread, len(startPCSet))
	for i, pc := range startPCSet {
		var rm []int
		if int(pc) == entryTargetPC {
			rm = append([]int(nil), entryRegMap...)
		} else {
			rm = append([]int(nil), startRegMap...)
			// Find captures on the epsilon path from Start to this PC (e.g. close caps
			// for patterns that can match empty string, like (a*) reaching InstMatch).
			epsV := make(map[int]bool)
			if found, epsCops := tdfaEpsCapOpsTo(prog, prog.Start, int(pc), epsV); found && len(epsCops) > 0 {
				for _, cop := range epsCops {
					tagIdx := cop.group * 2
					if !cop.open {
						tagIdx++
					}
					if tagIdx < numTags {
						rm[tagIdx] = -2
					}
				}
			}
		}
		startThreads[i] = tdfaThread{pc: int(pc), regMap: rm}
	}
	// getOrAddState's first call always lands on state 0 (stateMap starts empty,
	// nextStateID starts at 0).
	_, entryOps := getOrAddState(startThreads, false)

	// ---- main BFS ----
	for si := 0; si < len(states); si++ {
		if nextStateID > limit {
			return nil, false
		}

		sd := states[si]
		pcSet := sd.nfaPCs

		// Expand for word/non-word contexts (same as newDFA).
		var expandedWord, expandedNonWord []uint32
		if sd.prevWasWord {
			expandedWord = expandWithWB(pcSet, ecNoWordBoundary)
			expandedNonWord = expandWithWB(pcSet, ecWordBoundary)
		} else {
			expandedWord = expandWithWB(pcSet, ecWordBoundary)
			expandedNonWord = expandWithWB(pcSet, ecNoWordBoundary)
		}

		buildInputMap := func(expanded []uint32) map[rune][]uint32 {
			return nfaBuildInputMap(prog, expanded, leftmostFirst, nil)
		}

		inputMapWord := buildInputMap(expandedWord)
		inputMapNonWord := buildInputMap(expandedNonWord)

		// For each byte, compute the set of (nextPC, tagOps) pairs.
		// We process all 256 bytes; word/non-word uses appropriate inputMap.
		processTransition := func(b byte, inputMap map[rune][]uint32) {
			nextNFAPCs, ok := inputMap[rune(b)]
			if !ok || len(nextNFAPCs) == 0 {
				return
			}

			// Build the set of Out-pointers that actually fired for byte b.
			// A source thread srcThread.pc is only a valid source if its byte consumer
			// matched b, i.e. prog.Inst[srcThread.pc].Out ∈ firedOutSet.
			// This prevents a thread that cannot match b from claiming as source via an
			// epsilon exit path (e.g. letter-loop thread misidentified as source for
			// a space transition when [a-z] and \s are disjoint but share an Alt exit).
			firedOutSet := make(map[int]bool, len(nextNFAPCs))
			for _, outPC := range nextNFAPCs {
				firedOutSet[int(outPC)] = true
			}

			// Epsilon-close the successor NFA states.
			nextClosed := epsilonClosure(nextNFAPCs, 0)

			// Build new threads: for each closed NFA PC, find the highest-priority
			// source thread that transitions to it and apply any InstCapture ops.
			// Only create threads for "terminal" NFA instructions (byte consumers and
			// InstMatch). Epsilon-transparent nodes (InstAlt, InstCapture, InstNop,
			// InstEmptyWidth) are skipped — their descendants are already in nextClosed.
			nextThreads := make([]tdfaThread, 0, len(nextClosed))
			for _, nextPC := range nextClosed {
				// Skip epsilon-transparent NFA nodes; only include byte consumers and InstMatch.
				switch prog.Inst[nextPC].Op {
				case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL, syntax.InstMatch:
					// keep
				default:
					continue
				}
				var sourceRM []int
				for _, srcThread := range sd.key.threads {
					// Only consider source threads whose byte consumer actually fired for b.
					if !firedOutSet[int(prog.Inst[srcThread.pc].Out)] {
						continue
					}
					// srcThread.pc is a byte-consuming NFA state (from epsilonClosure).
					// Check if consuming byte b from srcThread.pc leads to nextPC via epsilon.
					// Use tdfaEpsCapOpsTo to correctly traverse Alt branches (e.g. loop exits).
					outPC := int(prog.Inst[srcThread.pc].Out)
					visited := make(map[int]bool)
					found, cops := tdfaEpsCapOpsTo(prog, outPC, int(nextPC), visited)
					if !found {
						continue
					}
					// This source thread contributes to nextPC.
					sourceRM = append([]int(nil), srcThread.regMap...)
					for _, cop := range cops {
						tagIdx := cop.group * 2
						if !cop.open {
							tagIdx++
						}
						if tagIdx < numTags {
							sourceRM[tagIdx] = -2 // sentinel: captured at current position
						}
					}
					break // LeftmostFirst: first contributing thread wins
				}
				if sourceRM == nil {
					// No source thread found (shouldn't happen; use unset regMap).
					sourceRM = make([]int, numTags)
					for i := range sourceRM {
						sourceRM[i] = -1
					}
				}
				nextThreads = append(nextThreads, tdfaThread{
					pc:     int(nextPC),
					regMap: sourceRM,
				})
			}

			if len(nextThreads) == 0 {
				return
			}

			nextPrevWasWord := isWordChar(b)
			nextStateIDVal, ops := getOrAddState(nextThreads, nextPrevWasWord)

			// Store DFA transition.
			for len(dfaTransitions) <= si*256+int(b) {
				dfaTransitions = append(dfaTransitions, -1)
			}
			dfaTransitions[si*256+int(b)] = nextStateIDVal

			// Store tag ops (pos + reconcile ops are all returned by getOrAddState).
			idx := si*256 + int(b)
			for len(tagOpTable) <= idx {
				tagOpTable = append(tagOpTable, nil)
			}
			if len(ops) > 0 {
				tagOpTable[idx] = ops
			}
		}

		for bi := 0; bi < 256; bi++ {
			b := byte(bi)
			if isWordChar(b) {
				processTransition(b, inputMapWord)
			} else {
				processTransition(b, inputMapNonWord)
			}
		}
	}

	// ---- build dfaTable ----
	n := nextStateID
	finalTrans := make([]int, n*256)
	for i := range finalTrans {
		finalTrans[i] = -1
	}
	for i, v := range dfaTransitions {
		if i < len(finalTrans) {
			finalTrans[i] = v
		}
	}

	// Pad tag op tables to full size.
	for len(tagOpTable) < n*256 {
		tagOpTable = append(tagOpTable, nil)
	}
	for len(acceptOpTable) < n {
		acceptOpTable = append(acceptOpTable, nil)
	}
	for len(acceptRegMapTable) < n {
		acceptRegMapTable = append(acceptRegMapTable, nil)
	}

	// Resolve the scratch register: sequentializeCopies may have used
	// scratchRegSentinel as a placeholder for a cycle-break (see its doc
	// comment) before nextReg's final value was known. Give it one concrete
	// register beyond every real capture register and rewrite every
	// occurrence. acceptOpTable is never populated (always nil) so it needs
	// no fixup; entryOps goes through the same getOrAddState machinery as
	// tagOpTable so it can in principle contain the sentinel too.
	if usedScratchReg {
		scratchReg := nextReg
		nextReg++
		resolve := func(ops []tdfaTagOp) {
			for i := range ops {
				if ops[i].dst == scratchRegSentinel {
					ops[i].dst = scratchReg
				}
				if ops[i].src == scratchRegSentinel {
					ops[i].src = scratchReg
				}
			}
		}
		for _, ops := range tagOpTable {
			resolve(ops)
		}
		resolve(entryOps)
	}

	dt := &dfaTable{
		startState:            0,
		midStartState:         0, // TDFA is always called anchored; mid-start states are unused
		midStartWordState:     0,
		numStates:             n,
		acceptStates:          dfaAccepting,
		midAcceptStates:       dfaMidAccepting,
		midAcceptNWStates:     dfaMidAcceptNW,
		midAcceptWStates:      dfaMidAcceptW,
		immediateAcceptStates: dfaImmediateAccepting,
		transitions:           finalTrans,
	}
	// Note: minimizeDFA is intentionally NOT called here. TDFA states with identical
	// DFA transitions may have different tag ops and must not be merged.

	tt := &tdfaTable{
		dfaTable:     dt,
		tagOps:       tagOpTable,
		acceptOps:    acceptOpTable,
		acceptRegMap: acceptRegMapTable,
		numRegs:      nextReg,
		numGroups:    numGroups,
		entryOps:     entryOps,
	}
	tt = minimizeTDFARegisters(tt)
	tt.bulkSkip = detectTDFABulkSkip(tt)
	return tt, true
}

// --------------------------------------------------------------------------
// WASM emission

// appendTDFACodeEntry appends a size-prefixed TDFA anchored-match function body
// to cs. The function has signature (ptr i32, len i32, out_ptr i32) → i32.
// nativeAnchored must be true only when this body is exported directly as the
// caller-facing groups function (compile.go:1568, p.anchored) — see
// buildTDFAMatchBody's doc comment for why that changes what "len" means and
// what code gets emitted.
func appendTDFACodeEntry(cs []byte, tt *tdfaTable, l *dfaLayout, tableMemIdx int, nativeAnchored bool) []byte {
	body := buildTDFAMatchBody(tt, l, tableMemIdx, nativeAnchored)
	var b []byte
	b = utils.AppendULEB128(b, uint32(len(body)))
	b = append(b, body...)
	return append(cs, b...)
}

// buildTDFAMatchBody emits the WASM function body for anchored TDFA matching.
//
// Locals:
//
//	0 = ptr           (param i32)
//	1 = len           (param i32)
//	2 = out_ptr       (param i32)
//	3 = pos           (i32)
//	4 = state         (i32)
//	5 = prevState     (i32)
//	6 = byte          (i32, the current input byte — saved before pos++)
//	7 = lastAcceptPos (i32, -1 = none; see hasMidAccept below)
//	[8 .. 8+numRegs-1] = capture registers (i32), initialised to -1
//
// Loop structure (pos++ BEFORE tag ops so that pos = exclusive end when ops fire):
//
//	entry_ops (at pos=0, before loop)
//	lastAcceptPos = -1; midAcceptCheck(wasmStart, 0)   [eager write, see below]
//	block $done:
//	  loop $main:
//	    if pos >= len: br $done
//	    prevState = state
//	    byte = mem[ptr+pos]
//	    pos++
//	    state = table[prevState<<8 + byte]
//	    if dead: return lastAcceptPos (or -1 if never set)
//	    emitTagOps(prevState, byte)   ← pos = byte_index+1 = exclusive end
//	    immediateAcceptCheck
//	    midAcceptCheck(state, pos)
//	    br $main
//	  end loop
//	end block $done
//	EOF accept, or lastAcceptPos fallback, or return -1
//
// midAcceptCheck(state, pos): if midAccept[state], EAGERLY write captures
// via emitTDFAWriteCaptures(state, pos) (same as an immediate/EOF accept
// would) and record lastAcceptPos=pos, but keep scanning instead of
// returning. This mirrors the plain DFA find-loop's `last_accept` mechanism
// (buildAnchoredFindBody) — needed because this body also serves as the
// *native/anchored* exported groups function (compile.go:1568, no find-pass
// narrowing `len` first), where a byte consumer can have higher priority
// than an already-reachable Match (e.g. `^(a)?` vs "b", or `^(?:(a){2})?`
// vs a string with fewer than 2 'a's) and the correct leftmost-first answer
// is the earlier, lower-priority accept, not "no match". See
// plans/FUZZER_BUGS.md §10.2/§10.2-followup.
//
// The write must happen EAGERLY (not deferred to whenever the fallback is
// actually needed) because capture registers are live, mutable WASM locals:
// a later, ultimately-failed continuation (e.g. attempting a 2nd iteration
// of a `(a){2}*` loop that only gets 1 more 'a') runs its own tag ops on the
// SAME registers (TDFA reuses registers across loop iterations by design)
// before the dead-transition is even detected — reading them only at the
// fallback point would return the failed attempt's partial values, not the
// ones that were correct when this position was actually valid. Writing
// eagerly to out_ptr (stable memory, not a register that keeps getting
// overwritten) and simply re-reading/overwriting it on every subsequent
// eager write sidesteps that entirely: whichever write happened last is
// necessarily the most recent valid accept, exactly the invariant we want.
//
// Word-boundary/line-anchor context never applies here — TDFA is never
// selected for patterns with \b/\B or (?m) anchors
// (compile/selector.go's hasWordBoundary/hasLineAnchors gates route those to
// Backtracking) — so a single ctx=0 midAccept table, with no NW/W/NL
// variants, is sufficient.
func buildTDFAMatchBody(tt *tdfaTable, l *dfaLayout, tableMemIdx int, nativeAnchored bool) []byte {
	var b []byte

	numCapRegs := tt.numRegs
	// The lastAccept fallback machinery only matters for the native/anchored
	// call convention (see doc comment above) — for the wrapper-composed
	// convention (nativeAnchored=false), `len` is already narrowed to the
	// exact match end by an independent find pass, so a dead transition or
	// non-accepting EOF state within that convention doesn't need — and
	// shouldn't pay the per-byte cost for — this fallback. Skipping it
	// entirely there keeps wrapper-composed capture bodies byte-identical to
	// (and as fast as) before this fix.
	hasMidAccept := nativeAnchored && len(tt.midAcceptStates) > 0
	// Locals: pos(1) + state(1) + prevState(1) + byte(1) [+ lastAcceptPos(1)
	// when hasMidAccept] + capture regs
	// [+ bulk-skip locals: chunk(v128) + mask(i32) + skipStart(i32)].
	extraLocals := 4 + numCapRegs
	if hasMidAccept {
		extraLocals++
	}
	hasBulkSkip := enableTDFABulkSkip && tt.bulkSkip != nil

	if hasBulkSkip {
		b = utils.AppendULEB128(b, uint32(3)) // 3 local declaration groups
	} else {
		b = utils.AppendULEB128(b, uint32(1)) // 1 local declaration group
	}
	b = utils.AppendULEB128(b, uint32(extraLocals))
	b = append(b, 0x7F) // i32

	const (
		localPos       = uint32(3)
		localState     = uint32(4)
		localPrevState = uint32(5)
		localByte      = uint32(6)
	)
	// localLastAcceptPos only exists (and localCapBase only shifts up to make
	// room for it) when hasMidAccept; otherwise capBase stays at 7, exactly
	// matching this function's shape before this fix.
	localLastAcceptPos := uint32(7)
	localCapBase := uint32(7)
	if hasMidAccept {
		localCapBase = 8
	}
	localChunk := localCapBase + uint32(numCapRegs)
	localMask := localChunk + 1
	localSkipStart := localMask + 1

	if hasBulkSkip {
		b = utils.AppendULEB128(b, uint32(1))
		b = append(b, 0x7B) // v128
		b = utils.AppendULEB128(b, uint32(2))
		b = append(b, 0x7F) // i32
	}

	// midAcceptCheck: if midAccept[state], eagerly write captures for
	// (state, pos) and record lastAcceptPos=pos. No-op when !hasMidAccept.
	midAcceptCheck := func(b []byte, stateLocal, posLocal uint32) []byte {
		if !hasMidAccept {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.midAcceptOff)
		b = append(b, 0x20, byte(stateLocal))
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)             // if midAccept[state]
		b = emitTDFAWriteCaptures(tt, b, stateLocal, posLocal, localCapBase)
		b = append(b, 0x20, byte(posLocal))
		b = append(b, 0x21, byte(localLastAcceptPos))
		b = append(b, 0x0B) // end if
		return b
	}

	// Initialise capture registers to -1.
	for i := 0; i < numCapRegs; i++ {
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x21)
		b = utils.AppendULEB128(b, localCapBase+uint32(i))
	}

	// Emit entry ops (open tags from the initial epsilon path, using pos=0).
	// These fire before the main loop; pos is 0 at this point.
	for _, op := range tt.entryOps {
		b = emitTDFATagOp(op, b, localPos, localCapBase)
	}

	// Initialise state = wasmStart, pos = 0.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x21, byte(localState))
	b = append(b, 0x41, 0x00)
	b = append(b, 0x21, byte(localPos))

	// lastAcceptPos = -1, then check wasmStart itself (pos=0) for mid-accept.
	// (Guarded by hasMidAccept: when false, localLastAcceptPos aliases the
	// first capture register — see its declaration above — so writing to it
	// unconditionally here would corrupt that register's initial value.)
	if hasMidAccept {
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x21, byte(localLastAcceptPos))
	}
	b = midAcceptCheck(b, localState, localPos)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br $done
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if $done

	if hasBulkSkip {
		// if state == bulkSkip.wasmState: SIMD-skip the self-loop run (Gap F)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tt.bulkSkip.wasmState)
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)
		b = emitTDFABulkSkip(b, tt.bulkSkip, localPos, localChunk, localMask, localSkipStart, localCapBase)
		b = append(b, 0x0B) // end if
	}

	// prevState = state
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x21, byte(localPrevState))

	// byte = mem[ptr + pos]
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, byte(localByte))

	// pos++ (BEFORE tag ops so that pos = exclusive end when tag ops fire)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, byte(localPos))

	// state = table[tableOff + prevState<<8 + byte] (u8) or table[tableOff + (prevState*256+byte)*2] (u16)
	if l.useU8 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localPrevState))
		b = append(b, 0x41, 0x08)
		b = append(b, 0x74) // i32.shl (prevState<<8)
		b = append(b, 0x6A)
		b = append(b, 0x20, byte(localByte))
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // table load → next+1 == state
		b = append(b, 0x21, byte(localState))
	} else {
		// u16: addr = tableOff + (prevState*256 + byte) * 2
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localPrevState))
		b = append(b, 0x41, 0x08)
		b = append(b, 0x74) // i32.shl (prevState<<8)
		b = append(b, 0x6A)
		b = append(b, 0x20, byte(localByte))
		b = append(b, 0x6A)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x74) // i32.shl (*2)
		b = append(b, 0x6A)
		b = appendTableLoad16u(b, tableMemIdx) // cell (u16, next+1, == state)
		b = append(b, 0x21, byte(localState))
	}

	// if state == 0 (dead): the byte just read has no valid transition. Fall
	// back to the most recently, eagerly-written mid-accept (lastAcceptPos)
	// if any, else -1 — e.g. `^(a)?` vs "b": state 0's threads are
	// [Rune('a'), Match]; byte 'b' kills the Rune thread, but Match was
	// already reachable from state 0 at pos=0, so the correct leftmost-first
	// answer is an empty match at 0, not "no match". Or `^(?:(a){2})?` vs a
	// string with fewer than 2 'a's: the dead transition can be several
	// bytes past the last valid accept, not just one — hence tracking
	// lastAcceptPos continuously through the scan (via midAcceptCheck)
	// rather than only checking prevState. (This only matters for the
	// native/anchored capture-body call convention — compile.go:1568 —
	// where `len` is the caller's full input, not a find-pass-narrowed match
	// end; see plans/FUZZER_BUGS.md §10.2.)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40) // if state==0 (void)
	if hasMidAccept {
		b = append(b, 0x20, byte(localLastAcceptPos))
	} else {
		b = append(b, 0x41, 0x7F) // i32.const -1
	}
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if state==0

	// Emit tag ops keyed on (prevState, byte).
	// At this point pos = exclusive end of consumed byte.
	b = emitTDFATagOps(tt, b, localPrevState, localByte, localPos, localCapBase)

	// Immediate-accept check.
	if l.hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // immediateAccept[state]
		b = append(b, 0x04, 0x40)
		// Accept here: write captures and return pos (pos already = exclusive end).
		b = emitTDFAAccept(tt, b, localState, localPos, localCapBase)
		b = append(b, 0x0B)
	}

	// Record a fallback accept (eagerly writing captures) if the state we
	// just transitioned into is mid-accepting. Only reached when
	// immediateAccept didn't already fire and return above, so this never
	// overrides a higher-priority immediate accept — it only ever matters if
	// every higher-priority continuation from here eventually dies.
	b = midAcceptCheck(b, localState, localPos)

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	// EOF accept check (TDFA): read per-state side table at l.acceptOff.
	// (State-ID partitioning is not applied to TDFA tables because state IDs
	// are tied to tag-op indices.) If the final state itself isn't an
	// EOF-accept, fall back to the last recorded mid-accept before giving up
	// — e.g. `^(?:(?:(?:(a){2})?))` vs "a": the final state (mid-way through
	// the required 2 a's) never becomes EOF-accepting, but the outer `?`'s
	// skip branch was mid-accepting back at position 0.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x6A) // i32.add
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x7F) // if [i32]: then-branch returns, else-branch leaves i32
	b = emitTDFAAcceptEOF(tt, b, localState, localPos, localCapBase)
	b = append(b, 0x05) // else
	if hasMidAccept {
		b = append(b, 0x20, byte(localLastAcceptPos)) // captures already written eagerly
	} else {
		b = append(b, 0x41, 0x7F) // -1
	}
	b = append(b, 0x0B) // end if — i32 on stack becomes implicit return value

	b = append(b, 0x0B) // end function
	return b
}

// emitTDFATagOps emits br_table dispatch for (prevState, byte) tag ops.
// Dispatches on prevState-1 (0-based) via br_table for O(1) per-byte overhead.
// localByte holds the current input byte (already saved in a local).
// localPos holds the current position (after pos++, = exclusive end of consumed byte).
func emitTDFATagOps(tt *tdfaTable, b []byte,
	localPrevState, localByte, localPos, localCapBase uint32) []byte {

	// tt.numStates is always ≥ 1 for a table built by newTDFA (the start
	// state alone guarantees this).
	n := tt.numStates

	// Precompute per-state entries (bytes with non-empty ops).
	type byteOps struct {
		bv  int
		ops []tdfaTagOp
	}
	type stateInfo struct {
		entries          []byteOps
		allSame          bool
		sameOps          []tdfaTagOp
		majorityOps      []tdfaTagOp // majority-group ops (non-nil iff !allSame && majority exists)
		minorityBytewise []byteOps   // minority entries (bytes whose ops ≠ majorityOps)
	}
	infos := make([]stateInfo, n)
	anyHasOps := false
	for gs := 0; gs < n; gs++ {
		var entries []byteOps
		for bv := 0; bv < 256; bv++ {
			idx := gs*256 + bv
			if idx < len(tt.tagOps) && len(tt.tagOps[idx]) > 0 {
				entries = append(entries, byteOps{bv, tt.tagOps[idx]})
			}
		}
		if len(entries) == 0 {
			continue
		}
		anyHasOps = true

		// Expand entries to include non-dead transitions with empty ops.
		// Without this, the allSame path would emit ops unconditionally for
		// ALL non-dead transitions from this state — including those that
		// have no ops — producing incorrect results.
		// Example: state with valid bytes 's' (ops: [{1,-1}]) and ':' (no ops);
		// allSame=true would fire the op on ':' too, overwriting the register.
		{
			inEntries := make([]bool, 256)
			for _, e := range entries {
				inEntries[e.bv] = true
			}
			for bv := 0; bv < 256; bv++ {
				if inEntries[bv] {
					continue
				}
				transIdx := gs*256 + bv
				if transIdx < len(tt.transitions) && tt.transitions[transIdx] >= 0 {
					entries = append(entries, byteOps{bv, nil}) // nil = no ops
				}
			}
		}

		// Check allSame.
		allSame := true
		for i := 1; i < len(entries); i++ {
			if !tdfaTagOpsEqual(entries[0].ops, entries[i].ops) {
				allSame = false
				break
			}
		}
		if allSame {
			infos[gs] = stateInfo{entries: entries, allSame: true, sameOps: entries[0].ops}
			continue
		}

		// Not all same: find the majority ops group (most bytes share the same ops).
		// Use a simple frequency count keyed by ops serialisation.
		type opsGroup struct {
			ops   []tdfaTagOp
			count int
		}
		var groups []opsGroup
		keyFor := func(ops []tdfaTagOp) string {
			s := make([]byte, 0, len(ops)*8)
			for _, op := range ops {
				s = fmt.Appendf(s, "%d:%d,", op.dst, op.src)
			}
			return string(s)
		}
		groupIdx := make(map[string]int)
		for _, e := range entries {
			k := keyFor(e.ops)
			if i, ok := groupIdx[k]; ok {
				groups[i].count++
			} else {
				groupIdx[k] = len(groups)
				groups = append(groups, opsGroup{ops: e.ops, count: 1})
			}
		}
		// Pick the group with the highest count.
		majIdx := 0
		for i, g := range groups {
			if g.count > groups[majIdx].count {
				majIdx = i
			}
		}
		majorityOps := groups[majIdx].ops
		majKey := keyFor(majorityOps)
		var minority []byteOps
		for _, e := range entries {
			if keyFor(e.ops) != majKey {
				minority = append(minority, e)
			}
		}
		infos[gs] = stateInfo{
			entries:          entries,
			allSame:          false,
			majorityOps:      majorityOps,
			minorityBytewise: minority,
		}
	}
	if !anyHasOps {
		return b
	}

	// br_table dispatch on prevState-1 (0-based DFA state index).
	//
	// Block layout (n+1 blocks total):
	//   block $exit       ← outermost wrapper; default target (index ≥ n)
	//     block B[0]      ← case block for gs=n-1
	//       ...
	//         block B[n-1] ← innermost; case block for gs=0
	//           local.get prevState
	//           i32.const 1
	//           i32.sub
	//           br_table 0 1 ... n-1 n   (n entries + default=n)
	//         end B[n-1]   ← handler for gs=0
	//         [ops] br n-1 ← exit $exit (depth n-1 from here)
	//       ...
	//     end B[0]         ← handler for gs=n-1
	//     [ops] br 0       ← exit $exit
	//   end $exit
	//
	// From handler gs: $exit is at depth (n-1-gs).

	// Emit $exit + n case blocks.
	b = append(b, 0x02, 0x40) // block $exit
	for i := 0; i < n; i++ {
		b = append(b, 0x02, 0x40) // block B[i]
	}

	// Dispatch: prevState - 1
	b = append(b, 0x20, byte(localPrevState)) // local.get prevState
	b = append(b, 0x41, 0x01)                 // i32.const 1
	b = append(b, 0x6B)                       // i32.sub

	// br_table: n entries (depths 0..n-1) + default=n (breaks $exit directly).
	b = append(b, 0x0E)
	b = utils.AppendULEB128(b, uint32(n))
	for i := 0; i < n; i++ {
		b = utils.AppendULEB128(b, uint32(i))
	}
	b = utils.AppendULEB128(b, uint32(n)) // default → break $exit

	// Per-state handlers: gs=0..n-1.
	for gs := 0; gs < n; gs++ {
		b = append(b, 0x0B) // end B[n-1-gs] → handler gs starts here

		info := infos[gs]
		if len(info.entries) > 0 {
			if info.allSame {
				for _, op := range info.sameOps {
					b = emitTDFATagOp(op, b, localPos, localCapBase)
				}
			} else {
				// Majority-group optimisation: emit minority byte checks as
				// guarded blocks; emit majority ops unconditionally at the end.
				//
				// WASM structure:
				//   block $maj_done:
				//     for each minority group (byte B, ops O):
				//       local.get byte; i32.const B; i32.eq
				//       if
				//         emit O
				//         br $maj_done+1   ; skip majority ops
				//       end
				//     emit majority_ops
				//   end $maj_done
				//
				// "br $maj_done+1" from inside the `if` block: the if block is
				// at depth 0, $maj_done is at depth 1, so we need br 1.
				b = append(b, 0x02, 0x40) // block $maj_done
				for _, e := range info.minorityBytewise {
					b = append(b, 0x20, byte(localByte))
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(e.bv))
					b = append(b, 0x46)       // i32.eq
					b = append(b, 0x04, 0x40) // if
					for _, op := range e.ops {
						b = emitTDFATagOp(op, b, localPos, localCapBase)
					}
					b = append(b, 0x0C, 0x01) // br 1 → exit $maj_done (skip majority)
					b = append(b, 0x0B)       // end if
				}
				// majority ops (fire when no minority byte matched)
				for _, op := range info.majorityOps {
					b = emitTDFATagOp(op, b, localPos, localCapBase)
				}
				b = append(b, 0x0B) // end $maj_done
			}
		}

		// Break out of $exit. From handler gs, $exit is at depth (n-1-gs).
		exitDepth := uint32(n - 1 - gs)
		b = append(b, 0x0C) // br
		b = utils.AppendULEB128(b, exitDepth)
	}

	b = append(b, 0x0B) // end $exit
	return b
}

// emitTDFATagOp emits a single tag operation.
func emitTDFATagOp(op tdfaTagOp, b []byte, localPos, localCapBase uint32) []byte {
	if op.src < 0 {
		// reg = pos
		b = append(b, 0x20, byte(localPos)) // local.get pos
	} else {
		// reg = other_reg
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, localCapBase+uint32(op.src))
	}
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, localCapBase+uint32(op.dst))
	return b
}

// emitTDFAAccept emits accept ops + capture write + return for immediate-accept.
// pos has already been incremented, so it equals the exclusive end of the match.
func emitTDFAAccept(tt *tdfaTable, b []byte, localState, localPos, localCapBase uint32) []byte {
	b = emitTDFAWriteCaptures(tt, b, localState, localPos, localCapBase)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x0F) // return pos (= exclusive end)
	return b
}

// emitTDFAAcceptEOF emits accept ops + capture write + return for EOF accept.
// pos = len = exclusive end of the full input.
func emitTDFAAcceptEOF(tt *tdfaTable, b []byte, localState, localPos, localCapBase uint32) []byte {
	b = emitTDFAWriteCaptures(tt, b, localState, localPos, localCapBase)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x0F) // return pos
	return b
}

// emitTDFAWriteCaptures emits br_table dispatch that writes capture registers
// to out_ptr. Dispatches on state-1 (0-based) for O(1) per-accept overhead.
// For each accepting state, acceptRegMap tells which local holds each group
// start/end. pos already equals the exclusive end.
func emitTDFAWriteCaptures(tt *tdfaTable, b []byte, localState, localPos, localCapBase uint32) []byte {
	// tt.numStates is always ≥ 1 (see emitTDFATagOps), and getOrAddState
	// unconditionally assigns every state a non-nil acceptRegMap entry (even
	// non-accepting states get an all -1 slice), so at least state 0 always
	// has capture info here.
	n := tt.numStates

	// br_table dispatch on state-1 (0-based). Same block layout as emitTDFATagOps.
	b = append(b, 0x02, 0x40) // block $exit
	for i := 0; i < n; i++ {
		b = append(b, 0x02, 0x40) // block B[i]
	}

	// Dispatch: state - 1
	b = append(b, 0x20, byte(localState)) // local.get state
	b = append(b, 0x41, 0x01)             // i32.const 1
	b = append(b, 0x6B)                   // i32.sub

	b = append(b, 0x0E)
	b = utils.AppendULEB128(b, uint32(n))
	for i := 0; i < n; i++ {
		b = utils.AppendULEB128(b, uint32(i))
	}
	b = utils.AppendULEB128(b, uint32(n)) // default → break $exit

	for gs := 0; gs < n; gs++ {
		b = append(b, 0x0B) // end B[n-1-gs] → handler gs starts here

		if gs < len(tt.acceptRegMap) && tt.acceptRegMap[gs] != nil {
			regMap := tt.acceptRegMap[gs]

			// Apply accept ops for this state.
			if gs < len(tt.acceptOps) && len(tt.acceptOps[gs]) > 0 {
				for _, op := range tt.acceptOps[gs] {
					b = emitTDFATagOp(op, b, localPos, localCapBase)
				}
			}

			// Write group 0 start = 0.
			b = append(b, 0x20, 0x02) // local.get out_ptr
			b = append(b, 0x41, 0x00) // i32.const 0
			b = append(b, 0x36, 0x00)
			b = utils.AppendULEB128(b, 0) // offset 0 = group 0 start

			// Write group 0 end = pos (exclusive end; pos already incremented).
			b = append(b, 0x20, 0x02) // local.get out_ptr
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x36, 0x00)
			b = utils.AppendULEB128(b, 4) // offset 4 = group 0 end

			// Write remaining groups from registers.
			for group := 1; group < tt.numGroups; group++ {
				startTag := group * 2
				endTag := group*2 + 1
				if startTag >= len(regMap) {
					break
				}
				startReg := regMap[startTag]
				endReg := regMap[endTag]

				// Write start.
				b = append(b, 0x20, 0x02) // local.get out_ptr
				if startReg >= 0 {
					b = append(b, 0x20)
					b = utils.AppendULEB128(b, localCapBase+uint32(startReg))
				} else {
					b = append(b, 0x41, 0x7F) // -1
				}
				b = append(b, 0x36, 0x00)
				b = utils.AppendULEB128(b, uint32(group*8)) // offset

				// Write end.
				b = append(b, 0x20, 0x02) // local.get out_ptr
				if endReg >= 0 {
					b = append(b, 0x20)
					b = utils.AppendULEB128(b, localCapBase+uint32(endReg))
				} else {
					b = append(b, 0x41, 0x7F) // -1
				}
				b = append(b, 0x36, 0x00)
				b = utils.AppendULEB128(b, uint32(group*8+4)) // offset
			}
		}

		// Break out of $exit. From handler gs, $exit is at depth (n-1-gs).
		exitDepth := uint32(n - 1 - gs)
		b = append(b, 0x0C) // br
		b = utils.AppendULEB128(b, exitDepth)
	}

	b = append(b, 0x0B) // end $exit
	return b
}

func tdfaTagOpsEqual(a, b []tdfaTagOp) bool {
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

// --------------------------------------------------------------------------
// Register minimisation (liveness-based coloring)

// minimizeTDFARegisters reduces the number of WASM capture-register locals by
// computing which registers are simultaneously live and merging those that never
// are.  It does not alter observable capture semantics.
//
// Algorithm:
//  1. Compute per-state liveness via a backwards dataflow fixpoint.
//  2. Build an interference graph: edge (r1,r2) if both live at the same state
//     OR if both appear as dst in the same op batch (prevents ordering hazards
//     after renaming where two ops would write the same local in sequence).
//  3. Greedily colour the graph.
//  4. Remap all register references and remove trivial self-copies.
func minimizeTDFARegisters(tt *tdfaTable) *tdfaTable {
	n := tt.numStates
	numRegs := tt.numRegs
	if numRegs <= 1 {
		return tt
	}
	transitions := tt.transitions

	// ---- Step 1: backwards liveness ----
	// live[s][r] = register r may be needed on a future path from state s.
	live := make([][]bool, n)
	for i := range live {
		live[i] = make([]bool, numRegs)
	}

	// Seed: registers referenced in acceptRegMap are live at their accepting state.
	for s := 0; s < n; s++ {
		if s >= len(tt.acceptRegMap) || tt.acceptRegMap[s] == nil {
			continue
		}
		for _, r := range tt.acceptRegMap[s] {
			if r >= 0 && r < numRegs {
				live[s][r] = true
			}
		}
	}

	// Propagate backwards until stable.
	for changed := true; changed; {
		changed = false
		for s := 0; s < n; s++ {
			for b := 0; b < 256; b++ {
				idx := s*256 + b
				if idx >= len(transitions) {
					continue
				}
				next := transitions[idx]
				if next < 0 || next >= n {
					continue
				}
				var ops []tdfaTagOp
				if idx < len(tt.tagOps) {
					ops = tt.tagOps[idx]
				}
				// Registers killed (written) by ops on this transition.
				killed := make([]bool, numRegs)
				for _, op := range ops {
					if op.dst >= 0 && op.dst < numRegs {
						killed[op.dst] = true
					}
				}
				// Propagate: r alive at next and not killed → alive at s.
				for r := 0; r < numRegs; r++ {
					if live[next][r] && !killed[r] && !live[s][r] {
						live[s][r] = true
						changed = true
					}
				}
				// Registers read (as src) by ops are live at s.
				for _, op := range ops {
					if op.src >= 0 && op.src < numRegs && !live[s][op.src] {
						live[s][op.src] = true
						changed = true
					}
				}
			}
		}
	}

	// ---- Step 2: interference graph ----
	interfere := make([][]bool, numRegs)
	for i := range interfere {
		interfere[i] = make([]bool, numRegs)
	}
	addEdge := func(r1, r2 int) {
		if r1 != r2 && r1 >= 0 && r1 < numRegs && r2 >= 0 && r2 < numRegs {
			interfere[r1][r2] = true
			interfere[r2][r1] = true
		}
	}

	// Simultaneous-liveness edges.
	for s := 0; s < n; s++ {
		for r1 := 0; r1 < numRegs; r1++ {
			if !live[s][r1] {
				continue
			}
			for r2 := r1 + 1; r2 < numRegs; r2++ {
				if live[s][r2] {
					addEdge(r1, r2)
				}
			}
		}
	}
	// Per-batch dst edges: two registers written in the same op batch cannot
	// share a physical register—merging them would produce two writes to the
	// same local in the same batch and the surviving value would be wrong.
	addBatchEdges := func(ops []tdfaTagOp) {
		for i := 0; i < len(ops); i++ {
			for j := i + 1; j < len(ops); j++ {
				addEdge(ops[i].dst, ops[j].dst)
			}
		}
	}
	for idx := range tt.tagOps {
		addBatchEdges(tt.tagOps[idx])
	}
	for _, ops := range tt.acceptOps {
		addBatchEdges(ops)
	}

	// ---- Step 3: greedy colouring ----
	// Sort registers by interference degree descending (most-constrained first).
	// Coloring high-degree nodes first minimises the number of colors used
	// (= WASM locals), which shrinks the emitted module.  This ordering is
	// also deterministic, unlike the raw allocation order.
	degree := make([]int, numRegs)
	for r := 0; r < numRegs; r++ {
		for r2 := 0; r2 < numRegs; r2++ {
			if interfere[r][r2] {
				degree[r]++
			}
		}
	}
	order := make([]int, numRegs)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		if degree[order[i]] != degree[order[j]] {
			return degree[order[i]] > degree[order[j]] // higher degree first
		}
		return order[i] < order[j] // stable tie-break by register index
	})

	color := make([]int, numRegs)
	for i := range color {
		color[i] = -1
	}
	forbidden := make([]bool, numRegs)
	for _, r := range order {
		for i := range forbidden {
			forbidden[i] = false
		}
		for r2 := 0; r2 < numRegs; r2++ {
			if interfere[r][r2] && color[r2] >= 0 {
				c2 := color[r2]
				if c2 < numRegs {
					forbidden[c2] = true
				}
			}
		}
		c := 0
		for c < numRegs && forbidden[c] {
			c++
		}
		color[r] = c
	}

	newNumRegs := 0
	for _, c := range color {
		if c+1 > newNumRegs {
			newNumRegs = c + 1
		}
	}
	if newNumRegs >= numRegs {
		return tt // no improvement
	}

	// ---- Step 4: apply colouring ----
	remap := func(r int) int {
		if r < 0 {
			return r
		}
		return color[r]
	}
	remapOps := func(ops []tdfaTagOp) []tdfaTagOp {
		if len(ops) == 0 {
			return ops
		}
		out := ops[:0:len(ops)]
		for _, op := range ops {
			newDst := color[op.dst]
			newSrc := op.src
			if op.src >= 0 {
				newSrc = color[op.src]
			}
			if newSrc == newDst {
				continue // trivial self-copy; drop
			}
			out = append(out, tdfaTagOp{dst: newDst, src: newSrc})
		}
		return out
	}

	newTagOps := make([][]tdfaTagOp, len(tt.tagOps))
	for i, ops := range tt.tagOps {
		newTagOps[i] = remapOps(ops)
	}
	newAcceptOps := make([][]tdfaTagOp, len(tt.acceptOps))
	for i, ops := range tt.acceptOps {
		newAcceptOps[i] = remapOps(ops)
	}
	newAcceptRegMap := make([][]int, len(tt.acceptRegMap))
	for i, rm := range tt.acceptRegMap {
		if rm == nil {
			continue
		}
		newRM := make([]int, len(rm))
		for j, r := range rm {
			newRM[j] = remap(r)
		}
		newAcceptRegMap[i] = newRM
	}

	return &tdfaTable{
		dfaTable:     tt.dfaTable,
		tagOps:       newTagOps,
		acceptOps:    newAcceptOps,
		acceptRegMap: newAcceptRegMap,
		numRegs:      newNumRegs,
		numGroups:    tt.numGroups,
		entryOps:     remapOps(tt.entryOps),
	}
}
