package compile

import (
	"encoding/binary"
	"regexp/syntax"
	"unicode"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// DFA construction

// dfa represents a compiled DFA with optimised transition tables.
type dfa struct {
	start        int
	midStart     int // start state for mid-string positions (attempt_start > 0) with prev=non-word
	midStartWord int // start state for mid-string positions with prev=word (new for word boundary support)
	// differs from start when pattern has begin anchors (^/\A) — those are not followed here.
	numStates        int
	accepting        map[int]bool // eofAccepting: accepts when at end of input (via $ or \z)
	midAccepting     map[int]bool // accepts at any position (no end-anchor expansion needed)
	// midAcceptingNW and midAcceptingW are for word-boundary patterns (find mode only).
	// midAcceptingNW[s]: state s accepts BEFORE consuming the next byte, when that byte is non-word.
	// midAcceptingW[s]:  state s accepts BEFORE consuming the next byte, when that byte is word.
	// These cover trailing \b/\B assertions that fire based on the upcoming byte.
	midAcceptingNW   map[int]bool
	midAcceptingW    map[int]bool
	startBeginAccept bool // true if start state accepts with ecBegin only (e.g. a*^)

	// transitions[state*256 + byte] = nextState (-1 = no transition)
	transitions  []int                // Flat array: [numStates * 256]
	unicodeTrans map[int]map[rune]int // state -> (unicode rune -> next state)

	hasEndAnchor      bool
	hasWordBoundary   bool
	needsUnicode      bool
	immediateAccepting map[int]bool // leftmost-first: accept without scanning further
}

func (d *dfa) Type() EngineType {
	return EngineDFA
}

// isImmediateAccepting returns true when, in the priority-ordered NFA state list,
// InstMatch appears before any byte-consuming state. With leftmost-first suppression,
// DFA states that have higher-priority byte transitions don't reach this condition
// (those transitions are preserved). This only fires for states where the first
// alternative can only match empty — lower-priority byte-consumers were suppressed.
//
// Examples (after suppression):
//   |a start: [InstMatch, rune_a_suppressed_was_here] -> but NFA set = [InstMatch] after
//             suppression means just InstMatch first -> true
//   a?|b start: NFA = [rune_a, InstMatch] (rune_b suppressed) -> rune_a before match -> false
func isImmediateAccepting(states []uint32, prog *syntax.Prog) bool {
	for _, pc := range states {
		switch prog.Inst[pc].Op {
		case syntax.InstMatch:
			return true // InstMatch before any byte consumer -> immediate accept
		case syntax.InstRune, syntax.InstRune1,
			syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			return false // byte consumer before match -> not immediate
		}
	}
	return false
}

// newDFA converts syntax.Prog (NFA bytecode) to DFA using subset construction.
func newDFA(prog *syntax.Prog, needsUnicode bool, leftmostFirst bool) *dfa {
	dfa := &dfa{
		accepting:          make(map[int]bool),
		midAccepting:       make(map[int]bool),
		midAcceptingNW:     make(map[int]bool),
		midAcceptingW:      make(map[int]bool),
		unicodeTrans:       make(map[int]map[rune]int),
		needsUnicode:       needsUnicode,
		immediateAccepting: make(map[int]bool),
	}

	// Detect if pattern has begin/end anchors or word boundary assertions
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstEmptyWidth {
			emptyOp := syntax.EmptyOp(inst.Arg)
			if emptyOp&syntax.EmptyEndLine != 0 || emptyOp&syntax.EmptyEndText != 0 {
				dfa.hasEndAnchor = true
			}
			if emptyOp&syntax.EmptyWordBoundary != 0 || emptyOp&syntax.EmptyNoWordBoundary != 0 {
				dfa.hasWordBoundary = true
			}
		}
	}

	// Map from set of NFA states to DFA state ID
	stateMap := make(map[string]int)
	nextStateID := 0

	type workItem struct {
		dfaState    int
		nfaSet      []uint32
		prevWasWord bool
	}
	queue := []workItem{}

	// Context flags for epsilon closure: controls which empty-width assertions are followed.
	// ecBegin:          follow EmptyBeginText (\A) and EmptyBeginLine (^) — valid only at start of input.
	// ecEnd:            follow EmptyEndText (\z) and EmptyEndLine ($)   — valid only at end of input.
	// ecWordBoundary:   follow EmptyWordBoundary (\b) — prev != curr (crossing word/non-word boundary).
	// ecNoWordBoundary: follow EmptyNoWordBoundary (\B) — prev == curr (same class).
	// Mid-string transitions use ctx=0 so no anchors are followed, which prevents impossible
	// sequences like (?:\z)(?:.+) or (?:.+)(?:\A) from appearing reachable.
	const (
		ecBegin          = 1
		ecEnd            = 2
		ecWordBoundary   = 4
		ecNoWordBoundary = 8
	)

	// Compute epsilon closure of NFA states, respecting anchor context.
	epsilonClosure := func(states []uint32, ctx int) []uint32 {
		visited := make(map[uint32]bool)
		result := []uint32{}
		// For leftmostFirst: push initial states in reverse so the first element
		// ends up on top of the LIFO stack (processed first = highest priority).
		var stack []uint32
		if leftmostFirst {
			for i := len(states) - 1; i >= 0; i-- {
				stack = append(stack, states[i])
			}
		} else {
			stack = append([]uint32{}, states...)
		}

		for len(stack) > 0 {
			pc := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			if visited[pc] {
				continue
			}
			visited[pc] = true
			result = append(result, pc)

			inst := &prog.Inst[pc]
			switch inst.Op {
			case syntax.InstAlt:
				if leftmostFirst {
					// Priority-ordered: Out (higher priority) on top of stack → processed first
					stack = append(stack, inst.Arg, inst.Out)
				} else {
					stack = append(stack, inst.Out, inst.Arg)
				}
			case syntax.InstCapture, syntax.InstNop:
				stack = append(stack, inst.Out)
			case syntax.InstEmptyWidth:
				emptyOp := syntax.EmptyOp(inst.Arg)
				follow := true
				if emptyOp&(syntax.EmptyBeginText|syntax.EmptyBeginLine) != 0 {
					follow = follow && (ctx&ecBegin) != 0
				}
				if emptyOp&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0 {
					follow = follow && (ctx&ecEnd) != 0
				}
				if emptyOp&syntax.EmptyWordBoundary != 0 {
					follow = follow && (ctx&ecWordBoundary) != 0
				}
				if emptyOp&syntax.EmptyNoWordBoundary != 0 {
					follow = follow && (ctx&ecNoWordBoundary) != 0
				}
				if follow {
					stack = append(stack, inst.Out)
				}
			}
		}
		return result
	}

	// isWordChar reports whether b is a word character ([A-Za-z0-9_]).
	// Used during DFA construction to resolve \b / \B assertions.
	isWordChar := func(b byte) bool {
		return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '_'
	}

	// expandWithWB extends an already-closed NFA set by following word-boundary
	// assertions that fire given wbCtx, then fully expanding epsilon transitions
	// from newly reached states. The input set is appended to as-is; new states
	// are inserted directly after the WB instruction they originate from.
	// This preserves leftmostFirst ordering of the original set.
	expandWithWB := func(closedSet []uint32, wbCtx int) []uint32 {
		visited := make(map[uint32]bool)
		for _, s := range closedSet {
			visited[s] = true
		}

		// Build result starting with the original set.
		result := append([]uint32{}, closedSet...)

		// For each state in the original set, if it is an EmptyWordBoundary or
		// EmptyNoWordBoundary that fires, expand from its Out state.
		// We insert new states right after the firing instruction (maintaining order).
		var insertions []struct{ afterIdx int; newStates []uint32 }

		for i, pc := range closedSet {
			inst := &prog.Inst[pc]
			if inst.Op != syntax.InstEmptyWidth {
				continue
			}
			emptyOp := syntax.EmptyOp(inst.Arg)
			fires := false
			if emptyOp&syntax.EmptyWordBoundary != 0 && (wbCtx&ecWordBoundary) != 0 {
				fires = true
			}
			if emptyOp&syntax.EmptyNoWordBoundary != 0 && (wbCtx&ecNoWordBoundary) != 0 {
				fires = true
			}
			if !fires || visited[inst.Out] {
				continue
			}
			// Perform a plain epsilon closure from inst.Out (leftmostFirst ordering).
			// These new states are fully expanded and inserted after position i.
			var newStates []uint32
			var stack []uint32
			if leftmostFirst {
				stack = []uint32{inst.Out}
			} else {
				stack = []uint32{inst.Out}
			}
			for len(stack) > 0 {
				s2 := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if visited[s2] {
					continue
				}
				visited[s2] = true
				newStates = append(newStates, s2)
				inst2 := &prog.Inst[s2]
				switch inst2.Op {
				case syntax.InstAlt:
					if leftmostFirst {
						stack = append(stack, inst2.Arg, inst2.Out)
					} else {
						stack = append(stack, inst2.Out, inst2.Arg)
					}
				case syntax.InstCapture, syntax.InstNop:
					stack = append(stack, inst2.Out)
				case syntax.InstEmptyWidth:
					// For begin/end/WB assertions in newly reached states, use wbCtx.
					emptyOp2 := syntax.EmptyOp(inst2.Arg)
					follow2 := true
					if emptyOp2&(syntax.EmptyBeginText|syntax.EmptyBeginLine) != 0 {
						follow2 = follow2 && (wbCtx&ecBegin) != 0
					}
					if emptyOp2&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0 {
						follow2 = follow2 && (wbCtx&ecEnd) != 0
					}
					if emptyOp2&syntax.EmptyWordBoundary != 0 {
						follow2 = follow2 && (wbCtx&ecWordBoundary) != 0
					}
					if emptyOp2&syntax.EmptyNoWordBoundary != 0 {
						follow2 = follow2 && (wbCtx&ecNoWordBoundary) != 0
					}
					if follow2 {
						stack = append(stack, inst2.Out)
					}
				}
			}
			if len(newStates) > 0 {
				insertions = append(insertions, struct{ afterIdx int; newStates []uint32 }{i, newStates})
			}
		}

		if len(insertions) == 0 {
			return result
		}

		// Rebuild result with insertions in order.
		out := make([]uint32, 0, len(result)+32)
		insertIdx := 0
		for i, pc := range result {
			out = append(out, pc)
			// Insert any new states after this position.
			for insertIdx < len(insertions) && insertions[insertIdx].afterIdx == i {
				out = append(out, insertions[insertIdx].newStates...)
				insertIdx++
			}
		}
		return out
	}

	// Convert NFA state set + prevWasWord context to unique string key.
	// Two states with identical NFA sets but different prevWasWord values are
	// distinct DFA states because they resolve word boundary assertions differently.
	setToKey := func(states []uint32, prevWasWord bool) string {
		key := ""
		seen := make(map[uint32]bool)
		for _, s := range states {
			if !seen[s] {
				seen[s] = true
				key += string(rune(s)) + ","
			}
		}
		if prevWasWord {
			key += "W"
		}
		return key
	}

	// Check if any state in set is accepting when at end of input.
	// ctx controls which anchor types are expanded:
	//   ecEnd        — for states reached after consuming bytes (only end-anchors valid)
	//   ecBegin|ecEnd — for the start state (empty string satisfies both begin and end)
	isAccepting := func(states []uint32, ctx int) bool {
		expanded := epsilonClosure(states, ctx)
		for _, pc := range expanded {
			if prog.Inst[pc].Op == syntax.InstMatch {
				return true
			}
		}
		return false
	}

	// Start state: epsilon closure of NFA start, following begin-anchors (^ and \A).
	// At beginning of input, prev is always non-word.
	startSet := epsilonClosure([]uint32{uint32(prog.Start)}, ecBegin)
	startKey := setToKey(startSet, false)
	dfa.start = 0
	stateMap[startKey] = 0
	nextStateID++

	// Start state is at position 0 with prevWasWord=false (start-of-input = non-word).
	// EOF from start = end-of-input after consuming nothing: use ecNoWordBoundary for WB check.
	if isAccepting(startSet, ecBegin|ecEnd|ecNoWordBoundary) {
		dfa.accepting[0] = true
	}
	if isAccepting(startSet, 0) {
		dfa.midAccepting[0] = true
	}
	// Pre-transition accept for start state (prevWasWord=false):
	// midAcceptNW: before non-word byte → \B fires (prev=non-word, next=non-word)
	if isAccepting(startSet, ecNoWordBoundary) {
		dfa.midAcceptingNW[0] = true
	}
	// midAcceptW: before word byte → \b fires (prev=non-word, next=word)
	if isAccepting(startSet, ecWordBoundary) {
		dfa.midAcceptingW[0] = true
	}
	// startBeginAccept: pattern matches empty at position 0 due to begin anchor (^/\A).
	// Distinct from acceptStates (ecBegin|ecEnd) and midAcceptStates (ctx=0).
	dfa.startBeginAccept = isAccepting(startSet, ecBegin)

	if leftmostFirst && isImmediateAccepting(startSet, prog) {
		dfa.immediateAccepting[0] = true
	}

	queue = append(queue, workItem{dfaState: 0, nfaSet: startSet, prevWasWord: false})

	// Mid-string start state (prev=non-word): epsilon closure WITHOUT begin-anchors,
	// used for attempt_start > 0 in find mode when prev byte was not a word char.
	midStartSet := epsilonClosure([]uint32{uint32(prog.Start)}, 0)
	midStartKey := setToKey(midStartSet, false)
	if id, exists := stateMap[midStartKey]; exists {
		dfa.midStart = id
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			dfa.immediateAccepting[dfa.midStart] = true
		}
	} else {
		dfa.midStart = nextStateID
		stateMap[midStartKey] = nextStateID
		nextStateID++
		// midStart is prevWasWord=false: end-of-input → \B fires
		if isAccepting(midStartSet, ecEnd|ecNoWordBoundary) {
			dfa.accepting[dfa.midStart] = true
		}
		if isAccepting(midStartSet, 0) {
			dfa.midAccepting[dfa.midStart] = true
		}
		// midAcceptNW for midStart (prevWasWord=false): before non-word → \B fires
		if isAccepting(midStartSet, ecNoWordBoundary) {
			dfa.midAcceptingNW[dfa.midStart] = true
		}
		// midAcceptW for midStart (prevWasWord=false): before word → \b fires
		if isAccepting(midStartSet, ecWordBoundary) {
			dfa.midAcceptingW[dfa.midStart] = true
		}
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			dfa.immediateAccepting[dfa.midStart] = true
		}
		queue = append(queue, workItem{dfaState: dfa.midStart, nfaSet: midStartSet, prevWasWord: false})
	}

	// Mid-string start state (prev=word): used when attempt_start > 0 and prev byte was a word char.
	// Same NFA set as midStart but different prevWasWord context → different DFA state.
	midStartWordKey := setToKey(midStartSet, true)
	if id, exists := stateMap[midStartWordKey]; exists {
		dfa.midStartWord = id
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			dfa.immediateAccepting[dfa.midStartWord] = true
		}
	} else {
		dfa.midStartWord = nextStateID
		stateMap[midStartWordKey] = nextStateID
		nextStateID++
		// midStartWord is prevWasWord=true: end-of-input → \b fires
		if isAccepting(midStartSet, ecEnd|ecWordBoundary) {
			dfa.accepting[dfa.midStartWord] = true
		}
		if isAccepting(midStartSet, 0) {
			dfa.midAccepting[dfa.midStartWord] = true
		}
		// midAcceptNW for midStartWord (prevWasWord=true): before non-word → \b fires
		if isAccepting(midStartSet, ecWordBoundary) {
			dfa.midAcceptingNW[dfa.midStartWord] = true
		}
		// midAcceptW for midStartWord (prevWasWord=true): before word → \B fires
		if isAccepting(midStartSet, ecNoWordBoundary) {
			dfa.midAcceptingW[dfa.midStartWord] = true
		}
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			dfa.immediateAccepting[dfa.midStartWord] = true
		}
		queue = append(queue, workItem{dfaState: dfa.midStartWord, nfaSet: midStartSet, prevWasWord: true})
	}

	// Process work queue
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Pre-expand the NFA set through word boundary epsilon transitions.
		// Since \b/\B resolution depends only on whether the current byte is a word char
		// (not the byte value itself), we compute two expansions per work item:
		//   expandedForWordChar:    NFA set after expanding through word boundary assertions
		//                          for bytes where isWordChar(byte)==true
		//   expandedForNonWordChar: NFA set after expanding through word boundary assertions
		//                          for bytes where isWordChar(byte)==false
		// Pre-expand the NFA set through word boundary epsilon transitions.
		// Use expandWithWB to preserve the original state ordering (critical for
		// leftmostFirst suppression) while appending WB-reachable states.
		var expandedForWordChar, expandedForNonWordChar []uint32
		if item.prevWasWord {
			// prev=word, curr=word    → \B fires (no boundary) → ecNoWordBoundary
			// prev=word, curr=non-word → \b fires (boundary)   → ecWordBoundary
			expandedForWordChar = expandWithWB(item.nfaSet, ecNoWordBoundary)
			expandedForNonWordChar = expandWithWB(item.nfaSet, ecWordBoundary)
		} else {
			// prev=non-word, curr=word    → \b fires (boundary)   → ecWordBoundary
			// prev=non-word, curr=non-word → \B fires (no boundary) → ecNoWordBoundary
			expandedForWordChar = expandWithWB(item.nfaSet, ecWordBoundary)
			expandedForNonWordChar = expandWithWB(item.nfaSet, ecNoWordBoundary)
		}

		// buildInputMap builds the rune→nextNFAStates map from an expanded NFA set.
		buildInputMap := func(expanded []uint32) map[rune][]uint32 {
			m := make(map[rune][]uint32)
			seenMatch := false
			for _, pc := range expanded {
				inst := &prog.Inst[pc]
				// leftmostFirst suppression: skip byte-consumers after InstMatch.
				if leftmostFirst && seenMatch {
					switch inst.Op {
					case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
						continue
					}
				}
				if inst.Op == syntax.InstMatch {
					seenMatch = true
				}
				switch inst.Op {
				case syntax.InstRune1:
					r := inst.Rune[0]
					m[r] = append(m[r], inst.Out)
					if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
						seen := make(map[rune]bool)
						seen[r] = true
						for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
							if !seen[folded] {
								seen[folded] = true
								m[folded] = append(m[folded], inst.Out)
							}
						}
					}
				case syntax.InstRune:
					isFoldCase := syntax.Flags(inst.Arg)&syntax.FoldCase != 0
					for i := 0; i < len(inst.Rune); i += 2 {
						var minRune, maxRune rune
						if i+1 >= len(inst.Rune) {
							minRune = inst.Rune[i]
							maxRune = inst.Rune[i]
						} else {
							minRune = inst.Rune[i]
							maxRune = inst.Rune[i+1]
						}
						lo := minRune
						hi := maxRune
						if hi > 0xFF {
							hi = 0xFF
						}
						for r := lo; r <= hi; r++ {
							m[r] = append(m[r], inst.Out)
							if isFoldCase {
								seen := make(map[rune]bool)
								seen[r] = true
								for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
									if !seen[folded] && (folded < minRune || folded > maxRune) {
										seen[folded] = true
										m[folded] = append(m[folded], inst.Out)
									}
								}
							}
						}
					}
				case syntax.InstRuneAny:
					for b := 0; b < 256; b++ {
						m[rune(b)] = append(m[rune(b)], inst.Out)
					}
				case syntax.InstRuneAnyNotNL:
					for b := 0; b < 256; b++ {
						if b != '\n' {
							m[rune(b)] = append(m[rune(b)], inst.Out)
						}
					}
				}
			}
			return m
		}

		inputMapWord := buildInputMap(expandedForWordChar)
		inputMapNonWord := buildInputMap(expandedForNonWordChar)

		// Collect transitions for all 256 bytes, using the appropriate inputMap.
		// Two bytes with the same isWordChar class and identical next-NFA-states map
		// to the same next DFA state naturally via setToKey.
		getOrAddState := func(nextSet []uint32, nextPrevWasWord bool) int {
			nextKey := setToKey(nextSet, nextPrevWasWord)
			nextDFAState, exists := stateMap[nextKey]
			if !exists {
				nextDFAState = nextStateID
				stateMap[nextKey] = nextStateID
				nextStateID++
				// EOF acceptance: end-of-input is treated as a non-word context.
				// If prevWasWord=true then prev=word, next=end-of-input(non-word) → \b fires.
				// If prevWasWord=false then prev=non-word, next=end-of-input(non-word) → \B fires.
				var eofWBCtx int
				if nextPrevWasWord {
					eofWBCtx = ecWordBoundary
				} else {
					eofWBCtx = ecNoWordBoundary
				}
				if isAccepting(nextSet, ecEnd|eofWBCtx) {
					dfa.accepting[nextDFAState] = true
				}
				if isAccepting(nextSet, 0) {
					dfa.midAccepting[nextDFAState] = true
				}
				// midAcceptingNW[s]: state s accepts before consuming the next byte,
				// when that byte is a non-word character.
				// Context = what fires when prev=nextPrevWasWord, next=non-word.
				var nwCtx int
				if nextPrevWasWord {
					nwCtx = ecWordBoundary // prev=word, next=non-word → \b
				} else {
					nwCtx = ecNoWordBoundary // prev=non-word, next=non-word → \B
				}
				if isAccepting(nextSet, nwCtx) {
					dfa.midAcceptingNW[nextDFAState] = true
				}
				// midAcceptingW[s]: state s accepts before consuming the next byte,
				// when that byte is a word character.
				var wCtx int
				if nextPrevWasWord {
					wCtx = ecNoWordBoundary // prev=word, next=word → \B
				} else {
					wCtx = ecWordBoundary // prev=non-word, next=word → \b
				}
				if isAccepting(nextSet, wCtx) {
					dfa.midAcceptingW[nextDFAState] = true
				}
				if leftmostFirst && isImmediateAccepting(nextSet, prog) {
					dfa.immediateAccepting[nextDFAState] = true
				}
				queue = append(queue, workItem{
					dfaState:    nextDFAState,
					nfaSet:      nextSet,
					prevWasWord: nextPrevWasWord,
				})
			}
			return nextDFAState
		}

		if dfa.unicodeTrans[item.dfaState] == nil {
			dfa.unicodeTrans[item.dfaState] = make(map[rune]int)
		}

		// Process word-char bytes using inputMapWord
		for r, nextNFAStates := range inputMapWord {
			if isWordChar(byte(r)) {
				nextSet := epsilonClosure(nextNFAStates, 0)
				nextDFAState := getOrAddState(nextSet, true)
				dfa.unicodeTrans[item.dfaState][r] = nextDFAState
			}
		}
		// Process non-word-char bytes using inputMapNonWord
		for r, nextNFAStates := range inputMapNonWord {
			if !isWordChar(byte(r)) {
				nextSet := epsilonClosure(nextNFAStates, 0)
				nextDFAState := getOrAddState(nextSet, false)
				dfa.unicodeTrans[item.dfaState][r] = nextDFAState
			}
		}
	}

	dfa.numStates = nextStateID

	// Build flat transition table
	dfa.transitions = make([]int, nextStateID*256)
	for i := range dfa.transitions {
		dfa.transitions[i] = -1
	}

	for state := 0; state < nextStateID; state++ {
		if trans, ok := dfa.unicodeTrans[state]; ok {
			for r, nextState := range trans {
				if r < 256 {
					dfa.transitions[state*256+int(r)] = nextState
				}
			}
		}
	}

	// Remove ASCII transitions from unicodeTrans to save memory
	for state := range dfa.unicodeTrans {
		for r := range dfa.unicodeTrans[state] {
			if r < 256 {
				delete(dfa.unicodeTrans[state], r)
			}
		}
		if len(dfa.unicodeTrans[state]) == 0 {
			delete(dfa.unicodeTrans, state)
		}
	}

	return dfa
}

// isWordCharByte reports whether b is a \w word character ([A-Za-z0-9_]).
// Used at WASM-generation time to compute firstByteFlags for WB patterns.
func isWordCharByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '_'
}

// --------------------------------------------------------------------------
// DFA table

// dfaTable holds the DFA state transition table.
type dfaTable struct {
	startState            int
	midStartState         int          // start state for attempt_start>0 in find mode (prev=non-word)
	midStartWordState     int          // start state for attempt_start>0 in find mode (prev=word)
	numStates             int
	acceptStates          map[int]bool // eofAccept: accepting at end of input
	midAcceptStates       map[int]bool // midAccept: accepting at any position (no WB context)
	midAcceptNWStates     map[int]bool // midAcceptNW: accepts before non-word byte (WB triggered)
	midAcceptWStates      map[int]bool // midAcceptW: accepts before word byte (WB triggered)
	immediateAcceptStates map[int]bool // leftmost-first: accept without scanning further
	transitions           []int        // flat [state*256+byte] = nextState; -1 = dead
	startBeginAccept      bool         // true if startState accepts with ecBegin only (e.g. a*^)
	hasWordBoundary       bool         // true if pattern contains \b or \B
}

// dfaTableFrom builds a dfaTable directly from a compiled dfa struct.
func dfaTableFrom(d *dfa) *dfaTable {
	return &dfaTable{
		startState:            d.start,
		midStartState:         d.midStart,
		midStartWordState:     d.midStartWord,
		numStates:             d.numStates,
		acceptStates:          d.accepting,
		midAcceptStates:       d.midAccepting,
		midAcceptNWStates:     d.midAcceptingNW,
		midAcceptWStates:      d.midAcceptingW,
		immediateAcceptStates: d.immediateAccepting,
		transitions:           d.transitions,
		startBeginAccept:      d.startBeginAccept,
		hasWordBoundary:       d.hasWordBoundary,
	}
}

// computeByteClasses groups the 256 possible byte values into equivalence
// classes: two bytes are in the same class if they produce identical
// transitions from every DFA state.
//
// Returns:
//   - classMap[256]: classMap[byte] = class ID (0-based)
//   - classRep[numClasses]: one representative byte per class
//   - numClasses: total number of distinct classes
func computeByteClasses(t *dfaTable) (classMap [256]byte, classRep []int, numClasses int) {
	sigToClass := map[string]int{}
	sig := make([]byte, t.numStates)

	for b := 0; b < 256; b++ {
		for gs := 0; gs < t.numStates; gs++ {
			next := t.transitions[gs*256+b]
			if next >= 0 {
				sig[gs] = byte(next + 1) // WASM state encoding: 0=dead, 1..N=valid
			} else {
				sig[gs] = 0
			}
		}
		key := string(sig)
		if id, ok := sigToClass[key]; ok {
			classMap[b] = byte(id)
		} else {
			id = len(sigToClass)
			sigToClass[key] = id
			classRep = append(classRep, b)
			classMap[b] = byte(id)
		}
	}
	numClasses = len(sigToClass)
	return
}

// --------------------------------------------------------------------------
// WASM generation

// genWASM emits a WASM 1.0 module with a single exported function:
//
//	(func (export "<exportName>") (param ptr i32) (param len i32) (result i32))
//
// Returns the end position (0..len) on a match, -1 on no match.
// The match is anchored at ptr and checks the full input [ptr, ptr+len).
//
// The module imports memory as (import "main" "memory" (memory 0)) so that
// wasm-merge can resolve it against the host module's exported memory.
// dfaLayout captures all computed DFA table data and offsets needed to emit
// WASM function bodies and data sections. Built once, shared between match and
// find functions in single-DFA and hybrid modules.
type dfaLayout struct {
	// Basic DFA state encoding
	numWASM        int
	wasmStart      uint32
	useU8          bool
	useCompression bool

	// Transition table
	tableOff   int32
	tableBytes []byte
	classMapOff int32
	classMap    [256]byte
	classRep    []int
	numClasses  int

	// Accept flags
	acceptOff    int32
	acceptBytes  []byte

	// Find-mode flags
	midAcceptOff   int32
	midAcceptBytes []byte

	// LeftmostFirst immediate-accept flags (both match and find)
	immediateAcceptOff   int32
	immediateAcceptBytes []byte
	hasImmAccept         bool

	// Word-boundary tables (find mode only)
	needWordCharTable  bool
	wordCharTableOff   int32
	wordCharTableBytes [256]byte
	midAcceptNWOff     int32
	midAcceptWOff      int32
	midAcceptNWBytes   []byte
	midAcceptWBytes    []byte

	// Fast-skip / SIMD (find mode only)
	prefix        []byte
	firstByteOff  int32
	firstByteFlags [256]byte
	firstBytes    []byte
	teddyLoOff    int32
	teddyHiOff    int32
	teddyLoBytes  []byte
	teddyHiBytes  []byte
	teddyT1LoOff  int32
	teddyT1HiOff  int32
	teddyT1LoBytes []byte
	teddyT1HiBytes []byte
	teddyT2LoOff  int32
	teddyT2HiOff  int32
	teddyT2LoBytes []byte
	teddyT2HiBytes []byte

	// Find-mode DFA states
	wasmMidStart     uint32
	wasmMidStartWord uint32
	wasmPrefixEnd    uint32
	startBeginAccept bool
}

// buildDFALayout computes all DFA table data and offsets. needFind must be true
// when a find function will be emitted (computes extra tables for find mode).
func buildDFALayout(t *dfaTable, tableBase int64, needFind, leftmostFirst bool) *dfaLayout {
	l := &dfaLayout{}
	l.numWASM = t.numStates + 1
	l.wasmStart = uint32(t.startState + 1)
	l.useU8 = l.numWASM <= 256
	l.useCompression = l.useU8 && l.numWASM*256 > 32*1024

	// Word char table (find + word boundary only).
	l.needWordCharTable = needFind && t.hasWordBoundary
	wordCharTableSize := int32(0)
	if l.needWordCharTable {
		l.wordCharTableOff = int32(tableBase)
		wordCharTableSize = 256
		for b := 0; b < 256; b++ {
			bb := byte(b)
			if (bb >= 'A' && bb <= 'Z') || (bb >= 'a' && bb <= 'z') ||
				(bb >= '0' && bb <= '9') || bb == '_' {
				l.wordCharTableBytes[b] = 1
			}
		}
	}

	// Transition table.
	if l.useCompression {
		l.classMapOff = int32(tableBase) + wordCharTableSize
		l.tableOff = int32(tableBase) + wordCharTableSize + 256
		l.classMap, l.classRep, l.numClasses = computeByteClasses(t)
		l.tableBytes = make([]byte, l.numWASM*l.numClasses)
		for gs := 0; gs < t.numStates; gs++ {
			ws := gs + 1
			for c, rep := range l.classRep {
				next := t.transitions[gs*256+rep]
				if next >= 0 {
					l.tableBytes[ws*l.numClasses+c] = byte(next + 1)
				}
			}
		}
	} else {
		l.tableOff = int32(tableBase) + wordCharTableSize
		if l.useU8 {
			l.tableBytes = make([]byte, l.numWASM*256)
			for gs := 0; gs < t.numStates; gs++ {
				ws := gs + 1
				for b := 0; b < 256; b++ {
					next := t.transitions[gs*256+b]
					if next >= 0 {
						l.tableBytes[ws*256+b] = byte(next + 1)
					}
				}
			}
		} else {
			l.tableBytes = make([]byte, l.numWASM*256*2)
			for gs := 0; gs < t.numStates; gs++ {
				ws := gs + 1
				for b := 0; b < 256; b++ {
					next := t.transitions[gs*256+b]
					var wn uint16
					if next >= 0 {
						wn = uint16(next + 1)
					}
					binary.LittleEndian.PutUint16(l.tableBytes[(ws*256+b)*2:], wn)
				}
			}
		}
	}

	// EOF accept flags.
	l.acceptOff = l.tableOff + int32(len(l.tableBytes))
	l.acceptBytes = make([]byte, l.numWASM)
	for gs := range t.acceptStates {
		l.acceptBytes[gs+1] = 1
	}

	// Mid-scan accept flags.
	l.midAcceptOff = l.acceptOff + int32(l.numWASM)
	l.midAcceptBytes = make([]byte, l.numWASM)
	for gs := range t.midAcceptStates {
		l.midAcceptBytes[gs+1] = 1
	}

	// Immediate-accept flags (LeftmostFirst, both match and find).
	if leftmostFirst && len(t.immediateAcceptStates) > 0 {
		l.hasImmAccept = true
		l.immediateAcceptOff = l.midAcceptOff + int32(l.numWASM)
		l.immediateAcceptBytes = make([]byte, l.numWASM)
		for gs := range t.immediateAcceptStates {
			l.immediateAcceptBytes[gs+1] = 1
		}
	}

	immAcceptSize := int32(0)
	if l.hasImmAccept {
		immAcceptSize = int32(l.numWASM)
	}

	// Word-boundary pre-transition accept flags (find mode only).
	if needFind && t.hasWordBoundary {
		l.midAcceptNWOff = l.midAcceptOff + int32(l.numWASM) + immAcceptSize
		l.midAcceptWOff = l.midAcceptNWOff + int32(l.numWASM)
		l.midAcceptNWBytes = make([]byte, l.numWASM)
		l.midAcceptWBytes = make([]byte, l.numWASM)
		for gs := range t.midAcceptNWStates {
			l.midAcceptNWBytes[gs+1] = 1
		}
		for gs := range t.midAcceptWStates {
			l.midAcceptWBytes[gs+1] = 1
		}
	}
	wbAcceptSize := int32(0)
	if needFind && t.hasWordBoundary {
		wbAcceptSize = int32(l.numWASM) * 2
	}

	// Find-mode fast-skip: literal prefix or firstByteFlags + Teddy tables.
	l.prefix = computePrefix(t)
	if needFind && len(l.prefix) == 0 {
		l.firstByteOff = l.midAcceptOff + int32(l.numWASM) + immAcceptSize + wbAcceptSize
		wbAcceptNWMid := t.hasWordBoundary && t.midAcceptNWStates[t.midStartState]
		wbAcceptWMid := t.hasWordBoundary && t.midAcceptWStates[t.midStartState]
		wbAcceptNWStart0 := t.hasWordBoundary && t.midAcceptNWStates[t.startState]
		wbAcceptWStart0 := t.hasWordBoundary && t.midAcceptWStates[t.startState]
		if t.midAcceptStates[t.midStartState] || t.midAcceptStates[t.startState] || t.acceptStates[t.startState] ||
			(wbAcceptNWMid && wbAcceptWMid) || (wbAcceptNWStart0 && wbAcceptWStart0) {
			for b := 0; b < 256; b++ {
				l.firstByteFlags[b] = 1
			}
		} else {
			for b := 0; b < 256; b++ {
				if t.transitions[t.startState*256+b] >= 0 || t.transitions[t.midStartState*256+b] >= 0 {
					l.firstByteFlags[b] = 1
				}
				if wbAcceptWMid && isWordCharByte(byte(b)) {
					l.firstByteFlags[b] = 1
				}
				if wbAcceptNWMid && !isWordCharByte(byte(b)) {
					l.firstByteFlags[b] = 1
				}
				if wbAcceptWStart0 && isWordCharByte(byte(b)) {
					l.firstByteFlags[b] = 1
				}
				if wbAcceptNWStart0 && !isWordCharByte(byte(b)) {
					l.firstByteFlags[b] = 1
				}
			}
		}

		for bv := 0; bv < 256; bv++ {
			if l.firstByteFlags[bv] != 0 {
				l.firstBytes = append(l.firstBytes, byte(bv))
			}
		}
		if len(l.firstBytes) <= 8 {
			l.teddyLoOff = l.firstByteOff + 256
			l.teddyHiOff = l.teddyLoOff + 16
			l.teddyLoBytes = make([]byte, 16)
			l.teddyHiBytes = make([]byte, 16)
			for i, fb := range l.firstBytes {
				l.teddyLoBytes[fb&0x0F] |= byte(1 << uint(i))
				l.teddyHiBytes[fb>>4] |= byte(1 << uint(i))
			}
			t1Lo := make([]byte, 16)
			t1Hi := make([]byte, 16)
			useTwoByte := true
			for i, fb := range l.firstBytes {
				stateAfterFB := t.transitions[t.midStartState*256+int(fb)]
				if stateAfterFB < 0 {
					useTwoByte = false
					break
				}
				validCount := 0
				for b2 := 0; b2 < 256; b2++ {
					if t.transitions[stateAfterFB*256+b2] >= 0 {
						validCount++
						t1Lo[b2&0x0F] |= byte(1 << uint(i))
						t1Hi[b2>>4] |= byte(1 << uint(i))
					}
				}
				if validCount > 64 {
					useTwoByte = false
					break
				}
			}
			if useTwoByte {
				l.teddyT1LoBytes = t1Lo
				l.teddyT1HiBytes = t1Hi
				l.teddyT1LoOff = l.teddyHiOff + 16
				l.teddyT1HiOff = l.teddyT1LoOff + 16

				// Try T2 tables (third byte).
				t2Lo := make([]byte, 16)
				t2Hi := make([]byte, 16)
				useThreeByte := true
			outerThreeByte:
				for i, fb := range l.firstBytes {
					stateAfterFB := t.transitions[t.midStartState*256+int(fb)]
					if stateAfterFB < 0 {
						useThreeByte = false
						break
					}
					for b2 := 0; b2 < 256; b2++ {
						stateAfterFB2 := t.transitions[stateAfterFB*256+b2]
						if stateAfterFB2 < 0 {
							continue
						}
						validCount3 := 0
						for b3 := 0; b3 < 256; b3++ {
							if t.transitions[stateAfterFB2*256+b3] >= 0 {
								validCount3++
								t2Lo[b3&0x0F] |= byte(1 << uint(i))
								t2Hi[b3>>4] |= byte(1 << uint(i))
							}
						}
						if validCount3 > 64 {
							useThreeByte = false
							break outerThreeByte
						}
					}
				}
				if useThreeByte {
					l.teddyT2LoBytes = t2Lo
					l.teddyT2HiBytes = t2Hi
					l.teddyT2LoOff = l.teddyT1HiOff + 16
					l.teddyT2HiOff = l.teddyT2LoOff + 16
				}
			}
		}
	}

	// Find-mode DFA state constants.
	if needFind {
		l.wasmMidStart = uint32(t.midStartState + 1)
		l.wasmMidStartWord = uint32(t.midStartWordState + 1)
		prefixEndState := t.midStartState
		for _, ch := range l.prefix {
			prefixEndState = t.transitions[prefixEndState*256+int(ch)]
		}
		l.wasmPrefixEnd = uint32(prefixEndState + 1)
		l.startBeginAccept = t.startBeginAccept
	}

	return l
}

// dfaDataSegments builds the raw data-section payload (count byte + segments)
// for a DFA layout. needFind controls whether find-mode-only tables are emitted.
func dfaDataSegments(l *dfaLayout, needFind bool) []byte {
	emitFindSegs := func(ds, transSegs []byte) []byte {
		if l.needWordCharTable {
			ds = appendDataSegment(ds, l.wordCharTableOff, l.wordCharTableBytes[:])
		}
		ds = append(ds, transSegs...)
		ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
		ds = appendDataSegment(ds, l.midAcceptOff, l.midAcceptBytes)
		if l.hasImmAccept {
			ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
		}
		if l.needWordCharTable {
			ds = appendDataSegment(ds, l.midAcceptNWOff, l.midAcceptNWBytes)
			ds = appendDataSegment(ds, l.midAcceptWOff, l.midAcceptWBytes)
		}
		return ds
	}
	findSegCount := func(base int) byte {
		n := byte(base)
		if l.hasImmAccept {
			n++
		}
		if l.needWordCharTable {
			n += 3
		}
		return n
	}
	teddyExtraSegs := byte(0)
	if len(l.teddyLoBytes) > 0 {
		teddyExtraSegs = 2
		if len(l.teddyT1LoBytes) > 0 {
			teddyExtraSegs = 4
			if len(l.teddyT2LoBytes) > 0 {
				teddyExtraSegs = 6
			}
		}
	}

	var ds []byte
	if l.useCompression {
		if needFind {
			var transSegs []byte
			transSegs = appendDataSegment(transSegs, l.classMapOff, l.classMap[:])
			transSegs = appendDataSegment(transSegs, l.tableOff, l.tableBytes)
			if len(l.prefix) == 0 {
				ds = append(ds, findSegCount(5)+teddyExtraSegs)
				ds = emitFindSegs(ds, transSegs)
				ds = appendDataSegment(ds, l.firstByteOff, l.firstByteFlags[:])
				if len(l.teddyLoBytes) > 0 {
					ds = appendDataSegment(ds, l.teddyLoOff, l.teddyLoBytes)
					ds = appendDataSegment(ds, l.teddyHiOff, l.teddyHiBytes)
					if len(l.teddyT1LoBytes) > 0 {
						ds = appendDataSegment(ds, l.teddyT1LoOff, l.teddyT1LoBytes)
						ds = appendDataSegment(ds, l.teddyT1HiOff, l.teddyT1HiBytes)
						if len(l.teddyT2LoBytes) > 0 {
							ds = appendDataSegment(ds, l.teddyT2LoOff, l.teddyT2LoBytes)
							ds = appendDataSegment(ds, l.teddyT2HiOff, l.teddyT2HiBytes)
						}
					}
				}
			} else {
				ds = append(ds, findSegCount(4))
				ds = emitFindSegs(ds, transSegs)
			}
		} else {
			count := byte(3)
			if l.hasImmAccept {
				count++
			}
			ds = append(ds, count)
			ds = appendDataSegment(ds, l.classMapOff, l.classMap[:])
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			if l.hasImmAccept {
				ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
			}
		}
	} else {
		if needFind {
			var transSegs []byte
			transSegs = appendDataSegment(transSegs, l.tableOff, l.tableBytes)
			if len(l.prefix) == 0 {
				ds = append(ds, findSegCount(4)+teddyExtraSegs)
				ds = emitFindSegs(ds, transSegs)
				ds = appendDataSegment(ds, l.firstByteOff, l.firstByteFlags[:])
				if len(l.teddyLoBytes) > 0 {
					ds = appendDataSegment(ds, l.teddyLoOff, l.teddyLoBytes)
					ds = appendDataSegment(ds, l.teddyHiOff, l.teddyHiBytes)
					if len(l.teddyT1LoBytes) > 0 {
						ds = appendDataSegment(ds, l.teddyT1LoOff, l.teddyT1LoBytes)
						ds = appendDataSegment(ds, l.teddyT1HiOff, l.teddyT1HiBytes)
						if len(l.teddyT2LoBytes) > 0 {
							ds = appendDataSegment(ds, l.teddyT2LoOff, l.teddyT2LoBytes)
							ds = appendDataSegment(ds, l.teddyT2HiOff, l.teddyT2HiBytes)
						}
					}
				}
			} else {
				ds = append(ds, findSegCount(3))
				ds = emitFindSegs(ds, transSegs)
			}
		} else {
			count := byte(2)
			if l.hasImmAccept {
				count++
			}
			ds = append(ds, count)
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			if l.hasImmAccept {
				ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
			}
		}
	}
	return ds
}

// genWASM generates a WASM module with up to two DFA functions sharing one table.
// matchExport and findExport are the exported function names; either may be empty
// to omit that function. At least one must be non-empty.
// The public API of CompileRegex is unchanged — it maps exportName+mode internally.
func genWASM(t *dfaTable, tableBase int64, matchExport, findExport string, standalone bool, memPages int32, leftmostFirst bool) []byte {
	needFind := findExport != ""
	needMatch := matchExport != ""

	l := buildDFALayout(t, tableBase, needFind, leftmostFirst)

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D) // magic
	out = append(out, 0x01, 0x00, 0x00, 0x00) // version

	// ── Type section ─────────────────────────────────────────────────────────
	// match: (i32,i32)→i32  type index 0 (if present)
	// find:  (i32,i32)→i64  type index 0 or 1
	numTypes := 0
	matchTypeIdx := -1
	findTypeIdx := -1
	var ts []byte
	if needMatch {
		matchTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F) // (i32,i32)→i32
	}
	if needFind {
		findTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E) // (i32,i32)→i64
	}
	out = appendSection(out, 1, append(utils.AppendULEB128(nil, uint32(numTypes)), ts...))

	// ── Import section ───────────────────────────────────────────────────────
	if !standalone {
		var is []byte
		is = append(is, 0x01)
		is = appendString(is, "main")
		is = appendString(is, "memory")
		is = append(is, 0x02)
		is = append(is, 0x00)
		is = utils.AppendULEB128(is, 0x00)
		out = appendSection(out, 2, is)
	}

	// ── Function section ─────────────────────────────────────────────────────
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(numTypes)) // numFuncs == numTypes here
	if needMatch {
		fs = utils.AppendULEB128(fs, uint32(matchTypeIdx))
	}
	if needFind {
		fs = utils.AppendULEB128(fs, uint32(findTypeIdx))
	}
	out = appendSection(out, 3, fs)

	// ── Memory section (standalone only) ─────────────────────────────────────
	if standalone {
		var ms []byte
		ms = append(ms, 0x01, 0x00)
		ms = utils.AppendULEB128(ms, uint32(memPages))
		out = appendSection(out, 5, ms)
	}

	// ── Export section ───────────────────────────────────────────────────────
	numExports := numTypes
	if standalone {
		numExports++ // memory
	}
	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02)
		es = utils.AppendULEB128(es, 0x00)
	}
	funcIdx := 0
	if needMatch {
		es = appendString(es, matchExport)
		es = append(es, 0x00)
		es = utils.AppendULEB128(es, uint32(funcIdx))
		funcIdx++
	}
	if needFind {
		es = appendString(es, findExport)
		es = append(es, 0x00)
		es = utils.AppendULEB128(es, uint32(funcIdx))
	}
	out = appendSection(out, 7, es)

	// ── Code section ─────────────────────────────────────────────────────────
	var cs []byte
	cs = utils.AppendULEB128(cs, uint32(numTypes))
	if needMatch {
		body := buildMatchBody(l.wasmStart, l.tableOff, l.acceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.immediateAcceptOff, l.hasImmAccept)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needFind {
		body := buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff, l.firstByteOff, l.prefix, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.firstByteFlags, l.firstBytes, l.teddyLoOff, l.teddyHiOff, l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0, l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	out = appendSection(out, 10, cs)

	// ── Data section ─────────────────────────────────────────────────────────
	out = appendSection(out, 11, dfaDataSegments(l, needFind))

	return out
}

// genHybridWASM generates a single WASM module containing up to three functions:
//   - matchExport: DFA anchored match (i32,i32)→i32  — omitted if ""
//   - findExport:  DFA non-anchored find (i32,i32)→i64 — omitted if ""
//   - groupsExport: OnePass anchored groups (i32,i32,i32)→i32 — omitted if op==nil
//
// DFA tables are placed at dfaTableBase; OnePass table at opTableBase.
// Both share a single memory.
func genHybridWASM(
	t *dfaTable, dfaTableBase int64, matchExport, findExport string,
	op *onePass, opTableBase int64, groupsExport string,
	standalone bool, memPages int32, leftmostFirst bool,
) []byte {
	needFind := findExport != ""
	needMatch := matchExport != ""
	needGroups := op != nil && groupsExport != ""

	l := buildDFALayout(t, dfaTableBase, needFind, leftmostFirst)

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// ── Type section ─────────────────────────────────────────────────────────
	// Assign type indices in the order: match, find, groups.
	numTypes := 0
	matchTypeIdx := -1
	findTypeIdx := -1
	groupsTypeIdx := -1
	var ts []byte
	if needMatch {
		matchTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F) // (i32,i32)→i32
	}
	if needFind {
		findTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E) // (i32,i32)→i64
	}
	if needGroups {
		groupsTypeIdx = numTypes
		numTypes++
		ts = append(ts, onePassTypeEntry()...)                 // (i32,i32,i32)→i32
	}
	out = appendSection(out, 1, append(utils.AppendULEB128(nil, uint32(numTypes)), ts...))

	// ── Import section ───────────────────────────────────────────────────────
	if !standalone {
		var is []byte
		is = append(is, 0x01)
		is = appendString(is, "main")
		is = appendString(is, "memory")
		is = append(is, 0x02, 0x00)
		is = utils.AppendULEB128(is, 0x00)
		out = appendSection(out, 2, is)
	}

	// ── Function section ─────────────────────────────────────────────────────
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(numTypes))
	if needMatch {
		fs = utils.AppendULEB128(fs, uint32(matchTypeIdx))
	}
	if needFind {
		fs = utils.AppendULEB128(fs, uint32(findTypeIdx))
	}
	if needGroups {
		fs = utils.AppendULEB128(fs, uint32(groupsTypeIdx))
	}
	out = appendSection(out, 3, fs)

	// ── Memory section (standalone only) ─────────────────────────────────────
	if standalone {
		var ms []byte
		ms = append(ms, 0x01, 0x00)
		ms = utils.AppendULEB128(ms, uint32(memPages))
		out = appendSection(out, 5, ms)
	}

	// ── Export section ───────────────────────────────────────────────────────
	numExports := numTypes
	if standalone {
		numExports++ // memory
	}
	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02)
		es = utils.AppendULEB128(es, 0x00)
	}
	funcIdx := 0
	if needMatch {
		es = appendString(es, matchExport)
		es = append(es, 0x00)
		es = utils.AppendULEB128(es, uint32(funcIdx))
		funcIdx++
	}
	if needFind {
		es = appendString(es, findExport)
		es = append(es, 0x00)
		es = utils.AppendULEB128(es, uint32(funcIdx))
		funcIdx++
	}
	if needGroups {
		es = append(es, onePassExportEntry(groupsExport, funcIdx)...)
	}
	out = appendSection(out, 7, es)

	// ── Code section ─────────────────────────────────────────────────────────
	var cs []byte
	cs = utils.AppendULEB128(cs, uint32(numTypes))
	if needMatch {
		body := buildMatchBody(l.wasmStart, l.tableOff, l.acceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.immediateAcceptOff, l.hasImmAccept)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needFind {
		body := buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff, l.firstByteOff, l.prefix, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.firstByteFlags, l.firstBytes, l.teddyLoOff, l.teddyHiOff, l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0, l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needGroups {
		cs = append(cs, onePassCodeEntry(op, int32(opTableBase))...)
	}
	out = appendSection(out, 10, cs)

	// ── Data section ─────────────────────────────────────────────────────────
	// DFA segments (count byte already included), then OnePass segment appended.
	dfaDS := dfaDataSegments(l, needFind)
	if needGroups {
		// Increment the count byte (first byte of dfaDS) by 1 for the OnePass segment.
		dfaDS[0]++
		dfaDS = append(dfaDS, onePassDataEntry(op, opTableBase)...)
	}
	out = appendSection(out, 11, dfaDS)

	return out
}

// buildMatchBody returns the WASM function body bytes (locals + instructions + end).
//
// u8 compressed (useU8=true, useCompression=true):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=class
//
// u8 simple (useU8=true, useCompression=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos
//
// u16 (useU8=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=byte
func buildMatchBody(startState uint32, tableOff, acceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, immediateAcceptOff int32, hasImmAccept bool) []byte {
	var b []byte

	// emitImmAcceptCheck emits: if immediateAccept[state]: return pos
	emitImmAcceptCheck := func(b []byte) []byte {
		if !hasImmAccept {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, immediateAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x0F)             // return
		b = append(b, 0x0B)             // end if
		return b
	}

	if useU8 && useCompression {
		// ── u8 compressed path ────────────────────────────────────────────────
		// 3 locals: state (local 2), pos (local 3), class (local 4)
		b = append(b, 0x01, 0x03, 0x7F)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02) // state = startState

		b = append(b, 0x02, 0x40) // block $done
		b = append(b, 0x03, 0x40) // loop $main

		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x0D, 0x01) // br_if $done

		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, classMapOff)
		b = append(b, 0x20, 0x00)       // local.get ptr
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)             // i32.add (classMapOff + byte)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (class)
		b = append(b, 0x21, 0x04)       // local.set class

		// state = u8(mem[tableOff + state*numClasses + class])
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C)             // i32.mul
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x20, 0x04)       // local.get class
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x21, 0x02)       // local.set state

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheck(b)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00) // br $main
		b = append(b, 0x0B)       // end loop
		b = append(b, 0x0B)       // end block $done

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, acceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // accept check
		b = append(b, 0x04, 0x7F)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x05)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0B)
		b = append(b, 0x0B) // end function
		return b
	}

	if useU8 {
		// ── u8 simple path ────────────────────────────────────────────────────
		// 2 locals: state (local 2), pos (local 3)
		b = append(b, 0x01, 0x02, 0x7F)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02) // state = startState

		b = append(b, 0x02, 0x40) // block $done
		b = append(b, 0x03, 0x40) // loop $main

		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x0D, 0x01) // if pos >= len: br_if $done

		// state = u8(mem[tableOff + state*256 + mem[ptr+pos]])
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x41, 0x08)       // i32.const 8
		b = append(b, 0x74)             // i32.shl (state * 256)
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)       // local.get ptr
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (table entry)
		b = append(b, 0x21, 0x02)       // local.set state

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheck(b)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop
		b = append(b, 0x0B) // end block $done

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, acceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // accept check
		b = append(b, 0x04, 0x7F)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x05)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0B)
		b = append(b, 0x0B) // end function
		return b
	}

	// ── u16 path ─────────────────────────────────────────────────────────────
	// 3 locals: state (local 2), pos (local 3), byte (local 4)
	b = append(b, 0x01, 0x03, 0x7F)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(startState))
	b = append(b, 0x21, 0x02) // state = startState

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	b = append(b, 0x20, 0x03)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x0D, 0x01) // if pos >= len: br_if $done

	// byte = mem[ptr + pos]
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, 0x04)       // local.set byte

	// state = u16(mem[tableOff + state*512 + byte*2])
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, 0x02)       // local.get state
	b = append(b, 0x41, 0x09)       // i32.const 9
	b = append(b, 0x74)             // i32.shl (state * 512)
	b = append(b, 0x6A)
	b = append(b, 0x20, 0x04)       // local.get byte
	b = append(b, 0x41, 0x01)       // i32.const 1
	b = append(b, 0x74)             // i32.shl (byte * 2)
	b = append(b, 0x6A)
	b = append(b, 0x2F, 0x01, 0x00) // i32.load16_u
	b = append(b, 0x21, 0x02)       // local.set state

	b = append(b, 0x20, 0x02)
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40) // if state == 0: return -1
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	b = emitImmAcceptCheck(b)

	b = append(b, 0x20, 0x03) // pos++
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x03)

	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block $done

	// accept check: mem[acceptOff + state] != 0 ? pos : -1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acceptOff)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x05)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B)

	b = append(b, 0x0B) // end function
	return b
}

// buildMatchBodyInline emits inline DFA match code without a function
// prologue/epilogue and without local declarations. The caller must have
// already declared the necessary locals. It uses the provided local indices
// instead of hardcoded 0,1,2,3,4.
//
// localPtr  — i32 local holding the input pointer (param 0, always fits in 1 byte)
// localLen  — i32 local holding the input length (used as end boundary)
// localSt   — i32 local used as DFA state scratch
// localPo   — i32 local used as DFA position scratch (must be pre-initialised to 0)
// localCl   — i32 local used as byte-class/byte scratch (compressed and u16 paths)
//
// On match:   leaves end position (i32) on the value stack.
// On no match: leaves -1 (i32) on the value stack.
//
// The code uses `return` (0x0F) for the dead-state early exit inside the loop.
// All local.get/set use LEB128-encoded indices so indices > 63 are safe.
func buildMatchBodyInline(b []byte,
	startState uint32,
	tableOff, acceptOff, classMapOff int32,
	numClasses int,
	useU8, useCompression bool,
	immediateAcceptOff int32, hasImmAccept bool,
	localPtr, localLen, localSt, localPo, localCl uint32,
) []byte {
	lget := func(b []byte, idx uint32) []byte {
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, idx)
		return b
	}
	lset := func(b []byte, idx uint32) []byte {
		b = append(b, 0x21)
		b = utils.AppendULEB128(b, idx)
		return b
	}

	emitImmAcceptCheck := func(b []byte) []byte {
		if !hasImmAccept {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, immediateAcceptOff)
		b = lget(b, localSt)        // local.get state
		b = append(b, 0x6A)         // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)   // if (void)
		b = lget(b, localPo)        // local.get pos
		b = append(b, 0x0F)         // return
		b = append(b, 0x0B)         // end if
		return b
	}

	// Initialise state = startState
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(startState))
	b = lset(b, localSt)

	// block $dfa_done
	b = append(b, 0x02, 0x40)
	// loop $dfa_loop
	b = append(b, 0x03, 0x40)

	// if pos >= len: br_if $dfa_done
	b = lget(b, localPo)
	b = lget(b, localLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if $dfa_done

	if useU8 && useCompression {
		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, classMapOff)
		b = lget(b, localPtr)
		b = lget(b, localPo)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (class)
		b = lset(b, localCl)

		// state = table[state*numClasses + class]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = lget(b, localSt)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C) // i32.mul
		b = append(b, 0x6A)
		b = lget(b, localCl)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = lset(b, localSt)
	} else if useU8 {
		// state = table[state*256 + mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = lget(b, localSt)
		b = append(b, 0x41, 0x08) // i32.const 8
		b = append(b, 0x74)       // i32.shl (state * 256)
		b = append(b, 0x6A)
		b = lget(b, localPtr)
		b = lget(b, localPo)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (table entry)
		b = lset(b, localSt)
	} else {
		// u16: byte = mem[ptr+pos]; state = table[state*512 + byte*2]
		b = lget(b, localPtr)
		b = lget(b, localPo)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = lset(b, localCl)             // reuse localCl as byte

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = lget(b, localSt)
		b = append(b, 0x41, 0x09) // i32.const 9
		b = append(b, 0x74)       // i32.shl (state * 512)
		b = append(b, 0x6A)
		b = lget(b, localCl)
		b = append(b, 0x41, 0x01) // i32.const 1
		b = append(b, 0x74)       // i32.shl (byte * 2)
		b = append(b, 0x6A)
		b = append(b, 0x2F, 0x01, 0x00) // i32.load16_u
		b = lset(b, localSt)
	}

	// if state == 0: return -1 (dead)
	b = lget(b, localSt)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	b = emitImmAcceptCheck(b)

	// pos++
	b = lget(b, localPo)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = lset(b, localPo)

	b = append(b, 0x0C, 0x00) // br $dfa_loop
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $dfa_done

	// accept check: accept[state] != 0 ? pos : -1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acceptOff)
	b = lget(b, localSt)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x04, 0x7F)       // if (result i32)
	b = lget(b, localPo)
	b = append(b, 0x05)       // else
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0B)       // end if

	return b
}

// computePrefix returns the longest literal byte prefix shared by all matches,
// found by walking the DFA from midStartState while exactly one byte leads to a
// non-dead state. Returns nil when the start state is accepting (pattern can
// match empty string — no positions can safely be skipped).
func computePrefix(t *dfaTable) []byte {
	state := t.midStartState
	if t.acceptStates[state] || t.midAcceptStates[state] {
		return nil // accepting start state: pattern matches empty → can't skip
	}
	if t.startBeginAccept {
		return nil // pattern matches empty at position 0 via begin anchor (e.g. a*^)
	}
	visited := map[int]bool{state: true}
	var prefix []byte
	for {
		var only int = -1
		count := 0
		for b := 0; b < 256; b++ {
			if t.transitions[state*256+b] >= 0 {
				count++
				only = b
			}
		}
		if count != 1 {
			break // ambiguous or dead → stop
		}
		prefix = append(prefix, byte(only))
		state = t.transitions[state*256+only]
		if visited[state] || t.acceptStates[state] || t.midAcceptStates[state] {
			break // cycle or accepting state — prefix cannot extend further
		}
		visited[state] = true
	}
	return prefix
}


// buildFindBody returns the WASM function body for find mode.
// The function scans for the leftmost-longest match and returns a packed i64:
//
//	(start << 32) | end   on match
//	-1 (as i64)           on no match
//
// Locals: 0=ptr 1=len 2=state 3=pos 4=attempt_start 5=last_accept
//
// Control flow (br depths counted from innermost):
//
//	block $no_match
//	  loop $outer              ; retry loop – advances attempt_start
//	    block $found           ; exit here when end position is known
//	      loop $scan           ; inner DFA scan
//	        if pos >= len      ; depth from if: 0=if,1=$scan,2=$found,3=$outer,4=$no_match
//	          ...br 2→$found or br 3→$outer
//	        transition
//	        if dead            ; depth from if: same as above
//	          ...br 2→$found or br 3→$outer
//	        update last_accept ; pos++; br 0→$scan
//	      end $scan
//	    end $found
//	    return packed i64      ; (unreachable end follows)
//	  end $outer
//	end $no_match
//	i64.const -1
//	end function
func buildFindBody(startState, midStartState, midStartWordState, prefixEndState uint32, tableOff, eofAcceptOff, midAcceptOff, firstByteOff int32, prefix []byte, classMapOff int32, numClasses int, useU8, useCompression bool, startBeginAccept bool, immediateAcceptOff int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, firstByteFlags [256]byte, firstBytes []byte, teddyLoOff, teddyHiOff, teddyT1LoOff, teddyT1HiOff int32, teddyTwoByte bool, teddyT2LoOff, teddyT2HiOff int32, teddyThreeByte bool) []byte {
	var b []byte

	// emitImmAcceptCheckFind emits: if immediateAccept[state]: last_accept=pos+1; br 2→$found
	// Called inside $scan loop (br 2 exits $found).
	emitImmAcceptCheckFind := func(b []byte) []byte {
		if !hasImmAccept {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, immediateAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x41, 0x01)       // i32.const 1
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0C, 0x02)       // br 2 → exit $found
		b = append(b, 0x0B)             // end if
		return b
	}

	// emitImmAcceptCheckFindStart emits: if immediateAccept[state]: last_accept=pos; br 1→$found
	// Called inside $found block, before $scan loop (br 1 exits $found).
	emitImmAcceptCheckFindStart := func(b []byte) []byte {
		if !hasImmAccept {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, immediateAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0C, 0x01)       // br 1 → exit $found
		b = append(b, 0x0B)             // end if
		return b
	}

	// ── helper: emit the "pos >= len" handler ───────────────────────────────
	// Called while inside $scan (depths from if body: 0=if,1=$scan,2=$found,3=$outer)
	emitEofHandler := func(b []byte) []byte {
		// if eofAccept[state]: last_accept = pos  (state accepts at end of input)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, eofAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)  [nested]
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end nested if
		// if last_accept >= 0: br $found
		b = append(b, 0x20, 0x05) // local.get last_accept
		b = append(b, 0x41, 0x00) // i32.const 0
		b = append(b, 0x4E)       // i32.ge_s
		b = append(b, 0x0D, 0x02) // br_if 2 → exit $found
		// attempt_start++; br $outer
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0x41, 0x01) // i32.const 1
		b = append(b, 0x6A)       // i32.add
		b = append(b, 0x21, 0x04) // local.set attempt_start
		b = append(b, 0x0C, 0x03) // br 3 → top of $outer
		return b
	}

	// ── helper: emit the dead-state handler ─────────────────────────────────
	// Called while inside $scan (depths from if body: 0=if,1=$scan,2=$found,3=$outer)
	emitDeadHandler := func(b []byte) []byte {
		// if last_accept >= 0: br $found
		b = append(b, 0x20, 0x05) // local.get last_accept
		b = append(b, 0x41, 0x00) // i32.const 0
		b = append(b, 0x4E)       // i32.ge_s
		b = append(b, 0x0D, 0x02) // br_if 2 → exit $found
		// attempt_start++; br $outer
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0x41, 0x01) // i32.const 1
		b = append(b, 0x6A)       // i32.add
		b = append(b, 0x21, 0x04) // local.set attempt_start
		b = append(b, 0x0C, 0x03) // br 3 → top of $outer
		return b
	}

	// ── helper: word-boundary pre-transition accept check ────────────────────
	// Called at the start of the $scan body, BEFORE taking the byte transition.
	// If the current byte (at ptr+pos) is a word char, checks midAcceptW[state].
	// If non-word, checks midAcceptNW[state].
	// On a hit, records last_accept = pos (the match ends before this byte).
	// No-op when hasWordBoundary is false.
	emitWBPreAcceptCheck := func(b []byte) []byte {
		if !hasWordBoundary {
			return b
		}
		// isWC = wordCharTable[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wordCharTableOff)
		b = append(b, 0x20, 0x00)       // local.get ptr
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x6A)             // i32.add  (ptr + pos)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (input byte)
		b = append(b, 0x6A)             // i32.add  (wordCharTableOff + byte)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (isWC flag)
		b = append(b, 0x04, 0x40)       // if (void): isWC
		// word char → check midAcceptW[state]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptWOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void): midAcceptW
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if midAcceptW
		b = append(b, 0x05)             // else: non-word char
		// non-word char → check midAcceptNW[state]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptNWOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void): midAcceptNW
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if midAcceptNW
		b = append(b, 0x0B)             // end if isWC
		return b
	}

	// simdMaskLocal: index of the i32 local for the combined bitmask.
	// chunkLocal:    index of the v128 local for the loaded 16-byte chunk (byte 0).
	// tLoLocal:      index of the v128 local for T0_lo (pre-loaded, 1-byte Teddy).
	// tHiLocal:      index of the v128 local for T0_hi (pre-loaded, 1-byte Teddy).
	// chunk1Local:   index of the v128 local for chunk at offset+1 (2-byte Teddy).
	// t1LoLocal:     index of the v128 local for T1_lo (pre-loaded, 2-byte Teddy).
	// t1HiLocal:     index of the v128 local for T1_hi (pre-loaded, 2-byte Teddy).
	// chunk2Local:   index of the v128 local for chunk at offset+2 (3-byte Teddy).
	// t2LoLocal:     index of the v128 local for T2_lo (pre-loaded, 3-byte Teddy).
	// t2HiLocal:     index of the v128 local for T2_hi (pre-loaded, 3-byte Teddy).
	// All set before each emitOuterPrologue call.
	var simdMaskLocal byte
	var chunkLocal byte
	var tLoLocal byte
	var tHiLocal byte
	var chunk1Local byte
	var t1LoLocal byte
	var t1HiLocal byte
	var chunk2Local byte
	var t2LoLocal byte
	var t2HiLocal byte

	// ── helper: outer loop prologue ──────────────────────────────────────────
	// Emits: if attempt_start >= len: br $no_match
	//        state=startState, pos=attempt_start, last_accept=-1
	//        if accept[state]: last_accept=pos  (start-state empty-match check)
	emitOuterPrologue := func(b []byte) []byte {
		params := PrefixScanParams{
			Prefix:         prefix,
			FirstByteSet:   firstBytes,
			FirstByteFlags: firstByteFlags,
			FirstByteOff:   firstByteOff,
			TeddyLoOff:     teddyLoOff,
			TeddyHiOff:     teddyHiOff,
			TeddyT1LoOff:   teddyT1LoOff,
			TeddyT1HiOff:   teddyT1HiOff,
			TeddyTwoByte:   teddyTwoByte,
			TeddyT2LoOff:   teddyT2LoOff,
			TeddyT2HiOff:   teddyT2HiOff,
			TeddyThreeByte: teddyThreeByte,
			EngineDepth:    2, // loop $outer + block $no_match
			Locals: PrefixScanLocals{
				Ptr:          0,
				Len:          1,
				AttemptStart: 4,
				SimdMask:     simdMaskLocal,
				Chunk:        chunkLocal,
				TLo:          tLoLocal,
				THi:          tHiLocal,
				Chunk1:       chunk1Local,
				T1Lo:         t1LoLocal,
				T1Hi:         t1HiLocal,
				Chunk2:       chunk2Local,
				T2Lo:         t2LoLocal,
				T2Hi:         t2HiLocal,
			},
			OnMatch: func(b []byte) []byte {
				if len(prefix) >= 1 {
					// Prefix scan consumed prefix bytes: start DFA from prefixEndState
					// at pos = attempt_start + len(prefix).
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(prefixEndState))
					b = append(b, 0x21, 0x02) // state = prefixEndState
					b = append(b, 0x20, 0x04) // local.get attempt_start
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(len(prefix)))
					b = append(b, 0x6A)       // i32.add
					b = append(b, 0x21, 0x03) // pos = attempt_start + prefix_len
				} else {
					// state = startState / midStartState / midStartWordState
					if startState == midStartState && (!hasWordBoundary || midStartState == midStartWordState) {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(startState))
					} else if !hasWordBoundary {
						b = append(b, 0x20, 0x04) // local.get attempt_start
						b = append(b, 0x45)       // i32.eqz
						b = append(b, 0x04, 0x7F) // if (result i32)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(startState))
						b = append(b, 0x05) // else
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(midStartState))
						b = append(b, 0x0B) // end if
					} else {
						// Word boundary: check previous byte.
						b = append(b, 0x20, 0x04) // local.get attempt_start
						b = append(b, 0x45)       // i32.eqz
						b = append(b, 0x04, 0x7F) // if (result i32)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(startState))
						b = append(b, 0x05) // else
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, wordCharTableOff)
						b = append(b, 0x20, 0x00)       // local.get ptr
						b = append(b, 0x20, 0x04)       // local.get attempt_start
						b = append(b, 0x6A)             // i32.add
						b = append(b, 0x41, 0x01)       // i32.const 1
						b = append(b, 0x6B)             // i32.sub
						b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (prev byte)
						b = append(b, 0x6A)             // wordCharTableOff + prev_byte
						b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (isWordChar)
						b = append(b, 0x04, 0x7F)       // if (result i32)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(midStartWordState))
						b = append(b, 0x05) // else
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(midStartState))
						b = append(b, 0x0B) // end if isWordChar
						b = append(b, 0x0B) // end if attempt_start == 0
					}
					b = append(b, 0x21, 0x02) // local.set state
					b = append(b, 0x20, 0x04) // local.get attempt_start
					b = append(b, 0x21, 0x03) // local.set pos
				}
				// last_accept = -1
				b = append(b, 0x41, 0x7F) // i32.const -1
				b = append(b, 0x21, 0x05) // local.set last_accept
				// if midAccept[state]: last_accept = pos
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, midAcceptOff)
				b = append(b, 0x20, 0x02)       // local.get state
				b = append(b, 0x6A)             // i32.add
				b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
				b = append(b, 0x04, 0x40)       // if (void)
				b = append(b, 0x20, 0x03)       // local.get pos
				b = append(b, 0x21, 0x05)       // local.set last_accept
				b = append(b, 0x0B)             // end if
				if startBeginAccept {
					b = append(b, 0x20, 0x04) // local.get attempt_start
					b = append(b, 0x45)       // i32.eqz
					b = append(b, 0x04, 0x40) // if (void)
					b = append(b, 0x20, 0x03) // local.get pos
					b = append(b, 0x21, 0x05) // local.set last_accept
					b = append(b, 0x0B)       // end if
				}
				return b
			},
		}
		return EmitPrefixScan(b, params)
	}

	// ── helper: emit the packed-i64 return and close loops ──────────────────
	emitReturn := func(b []byte) []byte {
		// return (attempt_start << 32) | last_accept
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x42, 0x20) // i64.const 32
		b = append(b, 0x86)       // i64.shl
		b = append(b, 0x20, 0x05) // local.get last_accept
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x84)       // i64.or
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end loop $outer  (unreachable)
		b = append(b, 0x0B)       // end block $no_match  (unreachable)
		// no-match path falls through here
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0B)       // end function
		return b
	}

	if useU8 && useCompression {
		// ── u8 compressed find path ───────────────────────────────────────────
		// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
		b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x03, 0x40) // loop $outer
		simdMaskLocal = 7
		chunkLocal = 8
		tLoLocal = 9
		tHiLocal = 10
		chunk1Local = 11
		t1LoLocal = 12
		t1HiLocal = 13
		chunk2Local = 14
		t2LoLocal = 15
		t2HiLocal = 16
		b = emitOuterPrologue(b)
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b)

		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, classMapOff)
		b = append(b, 0x20, 0x00)       // local.get ptr
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)             // i32.add (classMapOff + byte)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (class)
		b = append(b, 0x21, 0x06)       // local.set class

		// state = table[state*numClasses + class]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C)             // i32.mul
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x20, 0x06)       // local.get class
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x21, 0x02)       // local.set state

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b)
		b = append(b, 0x0B) // end if

		// if midAccept[state]: last_accept = pos + 1
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x41, 0x01)       // i32.const 1
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if

		b = emitImmAcceptCheckFind(b)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00) // br 0 → top of $scan
		b = append(b, 0x0B)       // end loop $scan
		b = append(b, 0x0B)       // end block $found
		b = emitReturn(b)
		return b
	}

	if useU8 {
		// ── u8 simple find path ───────────────────────────────────────────────
		// 5 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),simdMask(6),chunk(7),...,chunk2(13),t2Lo(14),t2Hi(15)
		b = append(b, 0x02, 0x05, 0x7F, 0x09, 0x7B)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x03, 0x40) // loop $outer
		simdMaskLocal = 6
		chunkLocal = 7
		tLoLocal = 8
		tHiLocal = 9
		chunk1Local = 10
		t1LoLocal = 11
		t1HiLocal = 12
		chunk2Local = 13
		t2LoLocal = 14
		t2HiLocal = 15
		b = emitOuterPrologue(b)
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b)

		// state = table[state*256 + mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x41, 0x08)       // i32.const 8
		b = append(b, 0x74)             // i32.shl
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)       // local.get ptr
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (table entry)
		b = append(b, 0x21, 0x02)       // local.set state

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b)
		b = append(b, 0x0B) // end if

		// if midAccept[state]: last_accept = pos + 1
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05) // local.set last_accept
		b = append(b, 0x0B)       // end if

		b = emitImmAcceptCheckFind(b)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00) // br 0 → top of $scan
		b = append(b, 0x0B)       // end loop $scan
		b = append(b, 0x0B)       // end block $found
		b = emitReturn(b)
		return b
	}

	// ── u16 find path ─────────────────────────────────────────────────────────
	// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),byte(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
	b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $outer
	simdMaskLocal = 7
	chunkLocal = 8
	tLoLocal = 9
	tHiLocal = 10
	chunk1Local = 11
	t1LoLocal = 12
	t1HiLocal = 13
	chunk2Local = 14
	t2LoLocal = 15
	t2HiLocal = 16
	b = emitOuterPrologue(b)
	b = append(b, 0x02, 0x40) // block $found
	b = emitImmAcceptCheckFindStart(b)
	b = append(b, 0x03, 0x40) // loop $scan

	// pos >= len?
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitEofHandler(b)
	b = append(b, 0x0B) // end if

	b = emitWBPreAcceptCheck(b)

	// byte = mem[ptr+pos]
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x21, 0x06)       // local.set byte

	// state = u16(mem[tableOff + state*512 + byte*2])
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, 0x02)       // local.get state
	b = append(b, 0x41, 0x09)       // i32.const 9
	b = append(b, 0x74)             // i32.shl
	b = append(b, 0x6A)
	b = append(b, 0x20, 0x06)       // local.get byte
	b = append(b, 0x41, 0x01)       // i32.const 1
	b = append(b, 0x74)             // i32.shl
	b = append(b, 0x6A)
	b = append(b, 0x2F, 0x01, 0x00) // i32.load16_u
	b = append(b, 0x21, 0x02)       // local.set state

	// dead state?
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = emitDeadHandler(b)
	b = append(b, 0x0B) // end if

	// if midAccept[state]: last_accept = pos + 1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, 0x02)       // local.get state
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x04, 0x40)       // if (void)
	b = append(b, 0x20, 0x03)       // local.get pos
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x05) // local.set last_accept
	b = append(b, 0x0B)       // end if

	b = emitImmAcceptCheckFind(b)

	b = append(b, 0x20, 0x03) // pos++
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x03)

	b = append(b, 0x0C, 0x00) // br 0 → top of $scan
	b = append(b, 0x0B)       // end loop $scan
	b = append(b, 0x0B)       // end block $found
	b = emitReturn(b)
	return b
}
