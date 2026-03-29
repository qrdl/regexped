package compile

import (
	"fmt"
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/utils"
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
}

func (t *tdfaTable) Type() EngineType { return EngineTDFA }

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

	// Per-state data accumulated during construction.
	type stateData struct {
		key         tdfaStateKey
		nfaPCs      []uint32 // bare NFA PCs (for epsilonClosure / accept checks)
		prevWasWord bool
	}
	var states []stateData

	// DFA-compatible accept/transition tables — built in parallel with tag data.
	// We build the dfaTable fields manually so we can pass the result to minimizeDFA.
	dfaAccepting := make(map[int]bool)
	dfaMidAccepting := make(map[int]bool)
	dfaMidAcceptNW := make(map[int]bool)
	dfaMidAcceptW := make(map[int]bool)
	dfaImmediateAccepting := make(map[int]bool)
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
		// Copies are sorted by descending dst to avoid clobbering chains (A←B←C emits C←B first).
		var copyOps, setOps []tdfaTagOp
		for orig, can := range rename {
			if orig >= sentinelBase {
				setOps = append(setOps, tdfaTagOp{dst: can, src: -1}) // set from pos
			} else if orig != can {
				copyOps = append(copyOps, tdfaTagOp{dst: can, src: orig}) // copy
			}
		}
		sort.Slice(copyOps, func(i, j int) bool { return copyOps[i].dst > copyOps[j].dst })
		ops := append(copyOps, setOps...)

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
			dfaAccepting[id] = true
		}
		if isAccepting(pcs, 0) {
			dfaMidAccepting[id] = true
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
			dfaMidAcceptNW[id] = true
		}
		if isAccepting(pcs, wCtx) {
			dfaMidAcceptW[id] = true
		}
		if isImmediateAccepting(pcs, prog) {
			dfaImmediateAccepting[id] = true
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
	startID, entryOps := getOrAddState(startThreads, false)
	if startID != 0 {
		return nil, false // should always be 0
	}

	// Also build mid-start (no begin-anchor expansion, prevWasWord=false and true).
	midStartPCSet := filterTerminalPCs(epsilonClosure([]uint32{uint32(prog.Start)}, 0))
	midThreads := make([]tdfaThread, len(midStartPCSet))
	for i, pc := range midStartPCSet {
		midThreads[i] = tdfaThread{pc: int(pc), regMap: append([]int(nil), startRegMap...)}
	}
	midStartID, _ := getOrAddState(midThreads, false)

	midThreadsW := make([]tdfaThread, len(midStartPCSet))
	for i, pc := range midStartPCSet {
		midThreadsW[i] = tdfaThread{pc: int(pc), regMap: append([]int(nil), startRegMap...)}
	}
	midStartWordID, _ := getOrAddState(midThreadsW, true)

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
			return nfaBuildInputMap(prog, expanded, leftmostFirst)
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

	dt := &dfaTable{
		startState:            0,
		midStartState:         midStartID,
		midStartWordState:     midStartWordID,
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
	return tt, true
}

// --------------------------------------------------------------------------
// WASM emission

// appendTDFACodeEntry appends a size-prefixed TDFA anchored-match function body
// to cs. The function has signature (ptr i32, len i32, out_ptr i32) → i32.
func appendTDFACodeEntry(cs []byte, tt *tdfaTable, l *dfaLayout) []byte {
	body := buildTDFAMatchBody(tt, l)
	var b []byte
	b = utils.AppendULEB128(b, uint32(len(body)))
	b = append(b, body...)
	return append(cs, b...)
}

// buildTDFAMatchBody emits the WASM function body for anchored TDFA matching.
//
// Locals:
//
//	0 = ptr       (param i32)
//	1 = len       (param i32)
//	2 = out_ptr   (param i32)
//	3 = pos       (i32)
//	4 = state     (i32)
//	5 = prevState (i32)
//	6 = byte      (i32, the current input byte — saved before pos++)
//	[7 .. 7+numRegs-1] = capture registers (i32), initialised to -1
//
// Loop structure (pos++ BEFORE tag ops so that pos = exclusive end when ops fire):
//
//	entry_ops (at pos=0, before loop)
//	block $done:
//	  loop $main:
//	    if pos >= len: br $done
//	    prevState = state
//	    byte = mem[ptr+pos]
//	    pos++
//	    state = table[prevState<<8 + byte]
//	    if dead: return -1
//	    emitTagOps(prevState, byte)   ← pos = byte_index+1 = exclusive end
//	    immediateAcceptCheck
//	    br $main
//	  end loop
//	end block $done
//	EOF accept or return -1
func buildTDFAMatchBody(tt *tdfaTable, l *dfaLayout) []byte {
	var b []byte

	numCapRegs := tt.numRegs
	// Locals: pos(1) + state(1) + prevState(1) + byte(1) + capture regs.
	extraLocals := 4 + numCapRegs
	b = utils.AppendULEB128(b, uint32(1)) // 1 local declaration
	b = utils.AppendULEB128(b, uint32(extraLocals))
	b = append(b, 0x7F) // i32

	const (
		localPos       = uint32(3)
		localState     = uint32(4)
		localPrevState = uint32(5)
		localByte      = uint32(6)
		localCapBase   = uint32(7)
	)

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

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br $done
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if $done

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

	// state = table[tableOff + prevState<<8 + byte]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.tableOff)
	b = append(b, 0x20, byte(localPrevState))
	b = append(b, 0x41, 0x08)
	b = append(b, 0x74) // i32.shl (prevState<<8)
	b = append(b, 0x6A)
	b = append(b, 0x20, byte(localByte))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // table load → new state
	b = append(b, 0x21, byte(localState))

	// if state == 0: return -1 (dead)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F) // return -1
	b = append(b, 0x0B)

	// Emit tag ops keyed on (prevState, byte).
	// At this point pos = exclusive end of consumed byte.
	b = emitTDFATagOps(tt, l, b, localPrevState, localByte, localPos, localState, localCapBase)

	// Immediate-accept check.
	if l.hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		// Accept here: write captures and return pos (pos already = exclusive end).
		b = emitTDFAAccept(tt, b, localState, localPos, localCapBase)
		b = append(b, 0x0B)
	}

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	// EOF accept check.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // accept[state]
	b = append(b, 0x04, 0x7F)       // if [i32]: then-branch returns, else-branch leaves i32
	b = emitTDFAAcceptEOF(tt, b, localState, localPos, localCapBase)
	b = append(b, 0x05)       // else
	b = append(b, 0x41, 0x7F) // -1
	b = append(b, 0x0B)       // end if — i32 on stack becomes implicit return value

	b = append(b, 0x0B) // end function
	return b
}

// emitTDFATagOps emits br_table dispatch for (prevState, byte) tag ops.
// Dispatches on prevState-1 (0-based) via br_table for O(1) per-byte overhead.
// localByte holds the current input byte (already saved in a local).
// localPos holds the current position (after pos++, = exclusive end of consumed byte).
func emitTDFATagOps(tt *tdfaTable, l *dfaLayout, b []byte,
	localPrevState, localByte, localPos, localState, localCapBase uint32) []byte {

	n := tt.dfaTable.numStates
	if n == 0 {
		return b
	}

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
	n := tt.dfaTable.numStates
	if n == 0 {
		return b
	}

	// Check if any state has capture info.
	anyHasCaptures := false
	for gs := 0; gs < n; gs++ {
		if gs < len(tt.acceptRegMap) && tt.acceptRegMap[gs] != nil {
			anyHasCaptures = true
			break
		}
	}
	if !anyHasCaptures {
		return b
	}

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

// TDFAStats compiles pattern to TDFA and returns state/register/op counts.
// Uses a high state limit (2000) so it never returns (0,0,0,false) due to the cap.
// Returns (0,0,0,false) only if the pattern fails to parse or compile as NFA.
func TDFAStats(pattern string) (numStates, numRegs, totalTagOps int, ok bool) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return
	}
	tt, success := newTDFA(prog, 2000)
	if !success {
		numStates = -1
		ok = false
		return
	}
	numStates = tt.numStates
	numRegs = tt.numRegs
	for _, ops := range tt.tagOps {
		totalTagOps += len(ops)
	}
	ok = true
	return
}

// DFAStateCount returns the number of LF DFA states for the given pattern
// after stripping capture groups. Used for diagnostics.
func DFAStateCount(pattern string) (int, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, err
	}
	// Re-parse a fresh copy so stripCaptures (which mutates in-place) doesn't
	// affect what the caller might use for TDFA stats.
	re2, _ := syntax.Parse(pattern, syntax.Perl)
	stripCaptures(re2)
	prog, err := syntax.Compile(re2.Simplify())
	if err != nil {
		return 0, err
	}
	_ = re
	d := newDFA(prog, false, true) // leftmostFirst
	t := dfaTableFrom(d)
	return t.numStates, nil
}

// TDFADetailStats compiles pattern to TDFA and returns detailed stats:
//
//	numStates, numRegs, totalTagOps
//	allSameStates  — number of states where all bytes with ops share identical ops (fast path)
//	diffStates     — number of states where bytes have differing ops (slow: linear byte scan)
//	diffTotalBytes — total number of (state,byte) entries in diffStates (= size of linear scan)
func TDFADetailStats(pattern string) (numStates, numRegs, totalTagOps, allSameStates, diffStates, diffTotalBytes int) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return
	}
	tt, ok := newTDFA(prog, 2000)
	if !ok {
		numStates = -1
		return
	}
	numStates = tt.numStates
	numRegs = tt.numRegs
	for gs := 0; gs < tt.numStates; gs++ {
		var entries []int
		for b := 0; b < 256; b++ {
			idx := gs*256 + b
			if idx < len(tt.tagOps) && len(tt.tagOps[idx]) > 0 {
				totalTagOps += len(tt.tagOps[idx])
				entries = append(entries, idx)
			}
		}
		if len(entries) == 0 {
			continue
		}
		allSame := true
		for i := 1; i < len(entries); i++ {
			if !tdfaTagOpsEqual(tt.tagOps[entries[0]], tt.tagOps[entries[i]]) {
				allSame = false
				break
			}
		}
		if allSame {
			allSameStates++
		} else {
			diffStates++
			diffTotalBytes += len(entries)
		}
	}
	return
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
	transitions := tt.dfaTable.transitions

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
	color := make([]int, numRegs)
	for i := range color {
		color[i] = -1
	}
	forbidden := make([]bool, numRegs)
	for r := 0; r < numRegs; r++ {
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
