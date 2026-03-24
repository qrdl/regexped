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

// dfaTableFrom builds a dfaTable directly from a compiled dfa struct,
// then applies Hopcroft DFA minimization.
func dfaTableFrom(d *dfa) *dfaTable {
	t := &dfaTable{
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
	minimizeDFA(t)
	return t
}

// minimizeDFA applies Hopcroft's DFA minimization algorithm, merging
// equivalent states (states that are indistinguishable from any starting
// point). Modifies t in place.
func minimizeDFA(t *dfaTable) {
	n := t.numStates
	if n <= 1 {
		return
	}

	// ── Initial partition: group states by accept-flag signature ─────────────
	// Two states must be in different classes if they differ in any accept flag.
	type sigKey struct{ a, ma, maw, manw, imm bool }
	sigToClass := make(map[sigKey]int, 8)
	classOf := make([]int, n)
	numClasses := 0
	for s := 0; s < n; s++ {
		sk := sigKey{
			t.acceptStates[s],
			t.midAcceptStates[s],
			t.midAcceptWStates[s],
			t.midAcceptNWStates[s],
			t.immediateAcceptStates[s],
		}
		c, ok := sigToClass[sk]
		if !ok {
			c = numClasses
			sigToClass[sk] = c
			numClasses++
		}
		classOf[s] = c
	}

	// ── Iterative partition refinement ────────────────────────────────────────
	// Two states stay in the same class only if, for every input byte, their
	// transitions land in the same class.  Repeat until stable.
	// Dead state (-1 in transitions) is treated as its own implicit class (-1).
	buf := make([]byte, 256*4) // reusable key buffer: 4 bytes per byte position
	for {
		// Bucket states by current class.
		classes := make([][]int, numClasses)
		for s := 0; s < n; s++ {
			classes[classOf[s]] = append(classes[classOf[s]], s)
		}

		newClassOf := make([]int, n)
		newNumClasses := 0
		changed := false

		for _, members := range classes {
			if len(members) == 1 {
				newClassOf[members[0]] = newNumClasses
				newNumClasses++
				continue
			}
			// For each member compute its transition-class fingerprint.
			// Encode: 4 bytes per byte position; dead→0, class c→c+1 (uint32 LE).
			keyToNew := make(map[string]int, 4)
			for _, s := range members {
				for b := 0; b < 256; b++ {
					next := t.transitions[s*256+b]
					var cv uint32
					if next >= 0 {
						cv = uint32(classOf[next]) + 1
					}
					buf[b*4] = byte(cv)
					buf[b*4+1] = byte(cv >> 8)
					buf[b*4+2] = byte(cv >> 16)
					buf[b*4+3] = byte(cv >> 24)
				}
				key := string(buf)
				nc, ok := keyToNew[key]
				if !ok {
					nc = newNumClasses
					newNumClasses++
					keyToNew[key] = nc
				}
				newClassOf[s] = nc
			}
			if len(keyToNew) > 1 {
				changed = true
			}
		}

		classOf = newClassOf
		numClasses = newNumClasses
		if !changed {
			break
		}
	}

	if numClasses >= n {
		return // No states merged — nothing to do.
	}

	// ── Build minimized DFA ──────────────────────────────────────────────────
	// Representative of each class: state with the smallest index.
	rep := make([]int, numClasses)
	for i := range rep {
		rep[i] = -1
	}
	for s := 0; s < n; s++ {
		c := classOf[s]
		if rep[c] < 0 || s < rep[c] {
			rep[c] = s
		}
	}

	// Transition table for the minimized DFA.
	newTrans := make([]int, numClasses*256)
	for i := range newTrans {
		newTrans[i] = -1
	}
	for c := 0; c < numClasses; c++ {
		r := rep[c]
		for b := 0; b < 256; b++ {
			next := t.transitions[r*256+b]
			if next >= 0 {
				newTrans[c*256+b] = classOf[next]
			}
		}
	}

	// Accept maps for the minimized DFA.
	newAccept    := make(map[int]bool)
	newMidAccept := make(map[int]bool)
	newMidAcceptNW := make(map[int]bool)
	newMidAcceptW  := make(map[int]bool)
	newImmAccept   := make(map[int]bool)
	for s := 0; s < n; s++ {
		c := classOf[s]
		if t.acceptStates[s]          { newAccept[c]      = true }
		if t.midAcceptStates[s]       { newMidAccept[c]   = true }
		if t.midAcceptNWStates[s]     { newMidAcceptNW[c] = true }
		if t.midAcceptWStates[s]      { newMidAcceptW[c]  = true }
		if t.immediateAcceptStates[s] { newImmAccept[c]   = true }
	}

	// Remap special state indices.
	t.startState        = classOf[t.startState]
	t.midStartState     = classOf[t.midStartState]
	t.midStartWordState = classOf[t.midStartWordState]
	t.numStates         = numClasses
	t.transitions       = newTrans
	t.acceptStates      = newAccept
	t.midAcceptStates   = newMidAccept
	t.midAcceptNWStates = newMidAcceptNW
	t.midAcceptWStates  = newMidAcceptW
	t.immediateAcceptStates = newImmAccept
	// hasWordBoundary and startBeginAccept are pattern-level flags, unchanged.
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

	// Row deduplication (u8 paths only)
	useRowDedup   bool
	rowMapOff     int32
	rowMapBytes   []byte // numWASM bytes: wasm-state → row index
	numUniqueRows int

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

	// tableEnd is the highest memory address used by any table in this layout.
	tableEnd int64
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

	// Row deduplication for u16: states with identical transition rows share one row.
	// u16 tables can be 100s of KB (e.g. 1000 states × 512 bytes = 512KB), well beyond
	// L1 cache, so dedup meaningfully reduces cache pressure.  u8 tables are ≤ 32KB and
	// typically L1-resident, so the extra indirection would hurt more than it helps.
	// rowMap is u8 (1 byte per state → row index), so we only dedup when uniqueRows ≤ 255.
	if !l.useU8 {
		const rowWidth = 512 // 256 entries × 2 bytes (u16)
		seen := make(map[string]int, l.numWASM)
		rowOf := make([]int, l.numWASM)
		var uniqueRows [][]byte
		for ws := 0; ws < l.numWASM; ws++ {
			row := l.tableBytes[ws*rowWidth : (ws+1)*rowWidth]
			key := string(row)
			idx, ok := seen[key]
			if !ok {
				idx = len(uniqueRows)
				seen[key] = idx
				uniqueRows = append(uniqueRows, append([]byte(nil), row...))
			}
			rowOf[ws] = idx
		}
		if len(uniqueRows) < l.numWASM && len(uniqueRows) <= 255 {
			l.useRowDedup = true
			l.numUniqueRows = len(uniqueRows)
			l.rowMapOff = l.tableOff
			l.rowMapBytes = make([]byte, l.numWASM)
			for ws, idx := range rowOf {
				l.rowMapBytes[ws] = byte(idx)
			}
			l.tableOff = l.rowMapOff + int32(l.numWASM)
			dedup := make([]byte, l.numUniqueRows*rowWidth)
			for i, row := range uniqueRows {
				copy(dedup[i*rowWidth:], row)
			}
			l.tableBytes = dedup
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

	// Compute tableEnd: highest memory address used by any table.
	tableEnd := int64(l.acceptOff) + int64(l.numWASM)
	maxEnd := func(off int32, size int64) {
		if e := int64(off) + size; e > tableEnd {
			tableEnd = e
		}
	}
	if l.hasImmAccept {
		maxEnd(l.immediateAcceptOff, int64(l.numWASM))
	}
	if needFind {
		maxEnd(l.midAcceptOff, int64(l.numWASM))
		if l.needWordCharTable {
			maxEnd(l.midAcceptNWOff, int64(l.numWASM))
			maxEnd(l.midAcceptWOff, int64(l.numWASM))
		}
		if len(l.prefix) == 0 {
			maxEnd(l.firstByteOff, 256)
			if len(l.teddyLoBytes) > 0 {
				maxEnd(l.teddyHiOff, 16)
				if len(l.teddyT1LoBytes) > 0 {
					maxEnd(l.teddyT1HiOff, 16)
					if len(l.teddyT2LoBytes) > 0 {
						maxEnd(l.teddyT2HiOff, 16)
					}
				}
			}
		}
	}
	l.tableEnd = tableEnd

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
		if l.useRowDedup {
			n++
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
			if l.useRowDedup {
				transSegs = appendDataSegment(transSegs, l.rowMapOff, l.rowMapBytes)
			}
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
			if l.useRowDedup {
				count++
			}
			ds = append(ds, count)
			ds = appendDataSegment(ds, l.classMapOff, l.classMap[:])
			if l.useRowDedup {
				ds = appendDataSegment(ds, l.rowMapOff, l.rowMapBytes)
			}
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			if l.hasImmAccept {
				ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
			}
		}
	} else {
		if needFind {
			var transSegs []byte
			if l.useRowDedup {
				transSegs = appendDataSegment(transSegs, l.rowMapOff, l.rowMapBytes)
			}
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
			if l.useRowDedup {
				count++
			}
			ds = append(ds, count)
			if l.useRowDedup {
				ds = appendDataSegment(ds, l.rowMapOff, l.rowMapBytes)
			}
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
func genWASM(t *dfaTable, tableBase int64, matchExport, findExport string, standalone bool, memPages int32, leftmostFirst bool, mandatoryLit *MandatoryLit) []byte {
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
		body := buildMatchBody(l.wasmStart, l.tableOff, l.acceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.immediateAcceptOff, l.hasImmAccept, l.rowMapOff, l.useRowDedup)
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	if needFind {
		var body []byte
		if isAnchoredFind(t) {
			body = buildAnchoredFindBody(l.wasmStart, l.tableOff, l.acceptOff, l.midAcceptOff, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.rowMapOff, l.useRowDedup)
		} else {
			body = buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff, l.firstByteOff, l.prefix, l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept, l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff, l.firstByteFlags, l.firstBytes, l.teddyLoOff, l.teddyHiOff, l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0, l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0, mandatoryLit, l.rowMapOff, l.useRowDedup)
		}
		cs = utils.AppendULEB128(cs, uint32(len(body)))
		cs = append(cs, body...)
	}
	out = appendSection(out, 10, cs)

	// ── Data section ─────────────────────────────────────────────────────────
	out = appendSection(out, 11, dfaDataSegments(l, needFind))

	return out
}

// genHybridWASM generates a single WASM module containing up to five functions:
//   - matchExport: DFA anchored match (i32,i32)→i32  — omitted if ""
//   - findExport:  DFA non-anchored find (i32,i32)→i64 — omitted if "" (but always emitted internally when groups needed)
//   - find_internal: not exported, locates leftmost match start — only when needGroups and !needFind
//   - capture_internal: not exported, OnePass body for anchored capture
//   - groups_exported: exported as groupsExport, wrapper calling find_internal then capture_internal
//
// DFA tables are placed at dfaTableBase; OnePass table at opTableBase.
// Both share a single memory.
func genHybridWASM(
	t *dfaTable, dfaTableBase int64, matchExport, findExport string,
	op *onePass, opTableBase int64, groupsExport string,
	standalone bool, memPages int32, leftmostFirst bool, mandatoryLit *MandatoryLit,
) []byte {
	needFind := findExport != ""
	needMatch := matchExport != ""
	needGroups := op != nil && groupsExport != ""
	anchored := isAnchoredFind(t)
	// needFindInternal: find function needed internally only for non-anchored groups.
	needFindInternal := needFind || (needGroups && !anchored)

	l := buildDFALayout(t, dfaTableBase, needFindInternal, leftmostFirst)

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// ── Type section ─────────────────────────────────────────────────────────
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
	if needFindInternal {
		findTypeIdx = numTypes
		numTypes++
		ts = append(ts, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E) // (i32,i32)→i64
	}
	if needGroups {
		groupsTypeIdx = numTypes
		numTypes++
		ts = append(ts, onePassTypeEntry()...) // (i32,i32,i32)→i32
	}
	// Total declared types
	numDeclaredTypes := numTypes

	// ── Count functions (may exceed numDeclaredTypes due to shared types) ──────
	numFuncs := numTypes
	if needGroups {
		numFuncs++ // capture_internal
		if !anchored {
			numFuncs++ // groups_wrapper only for non-anchored
		}
	}

	out = appendSection(out, 1, append(utils.AppendULEB128(nil, uint32(numDeclaredTypes)), ts...))

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
	fs = utils.AppendULEB128(fs, uint32(numFuncs))
	if needMatch {
		fs = utils.AppendULEB128(fs, uint32(matchTypeIdx))
	}
	if needFindInternal {
		fs = utils.AppendULEB128(fs, uint32(findTypeIdx))
	}
	if needGroups {
		fs = utils.AppendULEB128(fs, uint32(groupsTypeIdx)) // capture_internal
		if !anchored {
			fs = utils.AppendULEB128(fs, uint32(groupsTypeIdx)) // groups_wrapper
		}
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
	// Count only publicly exported entries.
	numExports := 0
	if standalone {
		numExports++ // memory
	}
	if needMatch {
		numExports++
	}
	if needFind {
		numExports++ // only if user asked for find export
	}
	if needGroups {
		numExports++ // capture_internal (anchored) or groups_wrapper (non-anchored)
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
	if needFindInternal {
		if needFind {
			es = appendString(es, findExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(funcIdx))
		}
		funcIdx++ // advance past find (whether exported or not)
	}
	if needGroups {
		if anchored {
			// Anchored: export capture_internal directly.
			es = append(es, onePassExportEntry(groupsExport, funcIdx)...)
			funcIdx++
		} else {
			// Non-anchored: capture_internal is internal; export wrapper.
			funcIdx++ // skip captureInternal
			es = append(es, onePassExportEntry(groupsExport, funcIdx)...)
			funcIdx++
		}
	}
	out = appendSection(out, 7, es)

	// ── Code section ─────────────────────────────────────────────────────────
	// findFuncIdx: index of find_internal in the function table
	findFuncIdx := -1
	cf := 0
	if needMatch {
		cf++
	}
	if needFindInternal {
		findFuncIdx = cf
		cf++
	}
	capFuncIdx := cf // captureInternal

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
		capBody := buildOnePassBody(op, int32(opTableBase))
		cs = utils.AppendULEB128(cs, uint32(len(capBody)))
		cs = append(cs, capBody...)
		if !anchored {
			wrapBody := buildGroupsWrapperBody(findFuncIdx, capFuncIdx, op.numGroups, true)
			cs = utils.AppendULEB128(cs, uint32(len(wrapBody)))
			cs = append(cs, wrapBody...)
		}
	}
	out = appendSection(out, 10, cs)

	// ── Data section ─────────────────────────────────────────────────────────
	dfaDS := dfaDataSegments(l, needFindInternal)
	if needGroups {
		dfaDS[0]++
		dfaDS = append(dfaDS, onePassDataEntry(op, opTableBase)...)
	}
	out = appendSection(out, 11, dfaDS)

	return out
}

// buildGroupsWrapperBody emits the WASM body for the exported groups wrapper function.
//
// Signature: (ptr i32, len i32, out_ptr i32) → i32
//
// The wrapper:
//  1. Calls find_internal(ptr, len) → i64; if -1, returns -1.
//  2. Extracts start = high-32 of result, end_LF = low-32 of result.
//  3. Calls capture_internal(ptr+start, end_LF-start, out_ptr).
//     Both OnePass and Backtracking receive the exact LF match extent.
//     Phase 1 LL DFA inside capture_internal finds the LL extent within that slice.
//  4. If capture returns -1, returns -1.
//  5. Adds start to every non-negative slot in out_ptr.
//  6. Returns captureResult + start (absolute end position).
//
// isOnePass is retained for caller documentation but no longer affects code generation.
//
// Locals (after 3 i32 params):
//
//	3: startLocal  (i32)
//	4: captureResult (i32)
//	5: slotScratch  (i32)
//	6: findResult   (i64)
func buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups int, isOnePass bool) []byte {
	var b []byte

	// Local declarations: 3 × i32, 1 × i64
	b = append(b, 0x02)       // 2 declaration groups
	b = append(b, 0x03, 0x7F) // 3 × i32  (startLocal=3, captureResult=4, slotScratch=5)
	b = append(b, 0x01, 0x7E) // 1 × i64  (findResult=6)

	// call find_internal(ptr, len) → i64
	b = append(b, 0x20, 0x00) // local.get ptr (param 0)
	b = append(b, 0x20, 0x01) // local.get len (param 1)
	b = append(b, 0x10)       // call
	b = utils.AppendULEB128(b, uint32(findFuncIdx))

	// local.tee findResult(6), compare with -1
	b = append(b, 0x22, 0x06) // local.tee findResult (i64 local)
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x51)       // i64.eq → i32
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x41, 0x7F) // i32.const -1  [no match branch]
	b = append(b, 0x05)       // else

	// Extract start = (findResult >> 32) as i32
	b = append(b, 0x20, 0x06) // local.get findResult
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x88)       // i64.shr_u
	b = append(b, 0xA7)       // i32.wrap_i64
	b = append(b, 0x21, 0x03) // local.set startLocal(3)

	// Build call to capture_internal(ptr+start, captureLen, out_ptr)
	// ptr + start
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x03) // local.get startLocal
	b = append(b, 0x6A)       // i32.add

	// captureLen = end_LF - start (both OnePass and Backtracking)
	b = append(b, 0x20, 0x06) // local.get findResult
	b = append(b, 0xA7)       // i32.wrap_i64 → end_LF (low 32 bits)
	b = append(b, 0x20, 0x03) // local.get startLocal
	b = append(b, 0x6B)       // i32.sub

	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x10)       // call
	b = utils.AppendULEB128(b, uint32(captureFuncIdx))
	b = append(b, 0x22, 0x04) // local.tee captureResult(4)

	// if captureResult == -1: return -1
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x05)       // else

	// Adjust slots: slot[i] += startLocal for each i in [0, numGroups*2)
	for i := 0; i < numGroups*2; i++ {
		offset := uint32(i * 4)

		// load slot[i]
		b = append(b, 0x20, 0x02)   // local.get out_ptr
		b = append(b, 0x28, 0x02)   // i32.load align=2
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x22, 0x05) // local.tee slotScratch(5)

		// if slot >= 0: store slot + start back
		b = append(b, 0x41, 0x00) // i32.const 0
		b = append(b, 0x4E)       // i32.ge_s
		b = append(b, 0x04, 0x40) // if void
		b = append(b, 0x20, 0x02) // local.get out_ptr
		b = append(b, 0x20, 0x05) // local.get slotScratch
		b = append(b, 0x20, 0x03) // local.get startLocal
		b = append(b, 0x6A)       // i32.add
		b = append(b, 0x36, 0x02) // i32.store align=2
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x0B) // end if
	}

	// return captureResult + startLocal
	b = append(b, 0x20, 0x04) // local.get captureResult
	b = append(b, 0x20, 0x03) // local.get startLocal
	b = append(b, 0x6A)       // i32.add

	b = append(b, 0x0B) // end if (captureResult == -1)
	b = append(b, 0x0B) // end if (find == -1)
	b = append(b, 0x0B) // end function
	return b
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
func buildMatchBody(startState uint32, tableOff, acceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, immediateAcceptOff int32, hasImmAccept bool, rowMapOff int32, useRowDedup bool) []byte {
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

		// state = u8(mem[tableOff + row*numClasses + class])
		// where row = rowMap[state] when useRowDedup, else row = state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02)       // local.get state
			b = append(b, 0x6A)             // rowMapOff + state
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
		} else {
			b = append(b, 0x20, 0x02) // local.get state
		}
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

		// state = u8(mem[tableOff + row*256 + mem[ptr+pos]])
		// where row = rowMap[state] when useRowDedup, else row = state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02)       // local.get state
			b = append(b, 0x6A)             // rowMapOff + state
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
		} else {
			b = append(b, 0x20, 0x02) // local.get state
		}
		b = append(b, 0x41, 0x08)       // i32.const 8
		b = append(b, 0x74)             // i32.shl (row * 256)
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

	// state = u16(mem[tableOff + row*512 + byte*2]) where row = rowMap[state] or state
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	if useRowDedup {
		b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
		b = append(b, 0x20, 0x02); b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
	} else {
		b = append(b, 0x20, 0x02)       // local.get state
	}
	b = append(b, 0x41, 0x09)       // i32.const 9
	b = append(b, 0x74)             // i32.shl (row/state * 512)
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
	rowMapOff int32, useRowDedup bool,
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

		// state = table[row*numClasses + class] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, rowMapOff)
			b = lget(b, localSt)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
		} else {
			b = lget(b, localSt)
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C) // i32.mul
		b = append(b, 0x6A)
		b = lget(b, localCl)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = lset(b, localSt)
	} else if useU8 {
		// state = table[row*256 + mem[ptr+pos]] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, rowMapOff)
			b = lget(b, localSt)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
		} else {
			b = lget(b, localSt)
		}
		b = append(b, 0x41, 0x08) // i32.const 8
		b = append(b, 0x74)       // i32.shl (row * 256)
		b = append(b, 0x6A)
		b = lget(b, localPtr)
		b = lget(b, localPo)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (table entry)
		b = lset(b, localSt)
	} else {
		// u16: byte = mem[ptr+pos]; state = table[row*512 + byte*2] (row = rowMap[state] or state)
		b = lget(b, localPtr)
		b = lget(b, localPo)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = lset(b, localCl)             // reuse localCl as byte

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
			b = lget(b, localSt); b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
		} else {
			b = lget(b, localSt)
		}
		b = append(b, 0x41, 0x09) // i32.const 9
		b = append(b, 0x74)       // i32.shl (row/state * 512)
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


// isAnchoredFind reports whether the DFA can only match starting at position 0.
// This is true when midStartState (and midStartWordState for WB patterns) have
// no live outgoing transitions and are not accepting. Patterns with a leading ^
// or \A anchor always satisfy this.
func isAnchoredFind(t *dfaTable) bool {
	// midStartState must be a complete dead-end: no live transitions, not accepting
	// in any mode (mid, eof, or immediate). If midStartState can accept, the pattern
	// matches from non-zero positions (e.g. `$` matches at end-of-input).
	if t.midAcceptStates[t.midStartState] ||
		t.acceptStates[t.midStartState] ||
		t.immediateAcceptStates[t.midStartState] {
		return false
	}
	for b := 0; b < 256; b++ {
		if t.transitions[t.midStartState*256+b] >= 0 {
			return false
		}
	}
	if t.hasWordBoundary {
		if t.midAcceptStates[t.midStartWordState] ||
			t.acceptStates[t.midStartWordState] ||
			t.immediateAcceptStates[t.midStartWordState] ||
			t.midAcceptNWStates[t.midStartState] ||
			t.midAcceptWStates[t.midStartWordState] {
			return false
		}
		for b := 0; b < 256; b++ {
			if t.transitions[t.midStartWordState*256+b] >= 0 {
				return false
			}
		}
	}
	return true
}

// buildAnchoredFindBody returns the WASM function body for anchored find mode.
// Used when isAnchoredFind is true: the pattern can only match at position 0,
// so no scan loop is needed — we run the DFA once from pos=0 and return.
//
// Function signature: (ptr i32, len i32) → i64
//   Returns (0 << 32 | end) on match, -1 on no match.
//
// Control flow:
//   block $no_match
//     block $found
//       [DFA prologue: state=startState, pos=0, last_accept=-1]
//       loop $scan
//         if pos >= len  → eofAccept check; br 2→$found
//         [WB pre-accept; transition; dead → br 2→$found; midAccept; immAccept; pos++]
//       end $scan
//     end $found
//     if last_accept >= 0: return packed i64
//   end $no_match
//   i64.const -1
func buildAnchoredFindBody(startState uint32, tableOff, eofAcceptOff, midAcceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, startBeginAccept bool, immediateAcceptOff int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, rowMapOff int32, useRowDedup bool) []byte {
	var b []byte

	// emitImmAcceptCheckFind emits: if immediateAccept[state]: last_accept=pos+1; br 2→$found
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

	// emitEofHandler: check eofAccept, maybe update last_accept, exit $found.
	// Depths from inside if body: 0=if, 1=$scan, 2=$found.
	emitEofHandler := func(b []byte) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, eofAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void): eofAccept
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if
		b = append(b, 0x0C, 0x02)       // br 2 → exit $found (anchored: no retry)
		return b
	}

	// emitDeadHandler: exit $found (no retry in anchored mode).
	// Depths from inside if body: 0=if, 1=$scan, 2=$found.
	emitDeadHandler := func(b []byte) []byte {
		b = append(b, 0x0C, 0x02) // br 2 → exit $found
		return b
	}

	// emitWBPreAcceptCheck: same as regular find — checks midAcceptW/NW inside $scan.
	emitWBPreAcceptCheck := func(b []byte) []byte {
		if !hasWordBoundary {
			return b
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wordCharTableOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40) // if isWordChar
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptWOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)
		b = append(b, 0x05) // else: non-word
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptNWOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)
		b = append(b, 0x0B) // end if isWordChar
		return b
	}

	// emitPrologue: state=startState, pos=0 (default), last_accept=-1, midAccept check.
	emitPrologue := func(b []byte) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02) // local.set state
		// pos = 0: already 0 (default local value)
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x21, 0x05) // local.set last_accept
		// if midAccept[startState]: last_accept = 0
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x41, 0x00)       // i32.const 0
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if
		if startBeginAccept {
			// pattern matches empty at position 0
			b = append(b, 0x41, 0x00) // i32.const 0
			b = append(b, 0x21, 0x05) // local.set last_accept
		}
		return b
	}

	// emitReturn: if last_accept >= 0, return (0 << 32 | last_accept), else fall through.
	emitReturn := func(b []byte) []byte {
		b = append(b, 0x20, 0x05) // local.get last_accept
		b = append(b, 0x41, 0x00) // i32.const 0
		b = append(b, 0x4E)       // i32.ge_s
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, 0x04) // local.get attempt_start (= 0)
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x42, 0x20) // i64.const 32
		b = append(b, 0x86)       // i64.shl
		b = append(b, 0x20, 0x05) // local.get last_accept
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x84)       // i64.or
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
		b = append(b, 0x0B)       // end block $no_match
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0B)       // end function
		return b
	}

	if useU8 && useCompression {
		// 5 i32: state(2),pos(3),attempt_start(4)=0,last_accept(5),class(6)
		b = append(b, 0x01, 0x05, 0x7F)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x02, 0x40) // block $found
		b = emitPrologue(b)
		b = emitImmAcceptCheckFindStart(b)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03) // pos
		b = append(b, 0x20, 0x01) // len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b)

		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, classMapOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, 0x06) // local.set class

		// state = table[row*numClasses + class] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02); b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
		} else {
			b = append(b, 0x20, 0x02)
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C) // i32.mul
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x06)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, 0x02) // local.set state

		b = append(b, 0x20, 0x02) // dead?
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b)
		b = append(b, 0x0B)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckFind(b)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)
		b = append(b, 0x0C, 0x00) // br 0 → $scan
		b = append(b, 0x0B)       // end loop $scan
		b = append(b, 0x0B)       // end block $found
		b = emitReturn(b)
		return b
	}

	if useU8 {
		// 4 i32: state(2),pos(3),attempt_start(4)=0,last_accept(5)
		b = append(b, 0x01, 0x04, 0x7F)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x02, 0x40) // block $found
		b = emitPrologue(b)
		b = emitImmAcceptCheckFindStart(b)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x04, 0x40)
		b = emitEofHandler(b)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b)

		// state = table[row*256 + mem[ptr+pos]] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02); b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
		} else {
			b = append(b, 0x20, 0x02)
		}
		b = append(b, 0x41, 0x08)
		b = append(b, 0x74) // i32.shl
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, 0x02) // local.set state

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b)
		b = append(b, 0x0B)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckFind(b)

		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)
		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop $scan
		b = append(b, 0x0B) // end block $found
		b = emitReturn(b)
		return b
	}

	// u16 path
	// 5 i32: state(2),pos(3),attempt_start(4)=0,last_accept(5),byte(6)
	b = append(b, 0x01, 0x05, 0x7F)
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x02, 0x40) // block $found
	b = emitPrologue(b)
	b = emitImmAcceptCheckFindStart(b)
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, 0x03)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x04, 0x40)
	b = emitEofHandler(b)
	b = append(b, 0x0B)

	b = emitWBPreAcceptCheck(b)

	// byte = mem[ptr+pos]
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x21, 0x06) // local.set byte

	// state = u16(table[state*512 + byte*2])
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x41, 0x09)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A)
	b = append(b, 0x20, 0x06)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A)
	b = append(b, 0x2F, 0x01, 0x00) // i32.load16_u
	b = append(b, 0x21, 0x02)

	b = append(b, 0x20, 0x02)
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40)
	b = emitDeadHandler(b)
	b = append(b, 0x0B)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x05)
	b = append(b, 0x0B)

	b = emitImmAcceptCheckFind(b)

	b = append(b, 0x20, 0x03)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x03)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $scan
	b = append(b, 0x0B) // end block $found
	b = emitReturn(b)
	return b
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
func buildFindBody(startState, midStartState, midStartWordState, prefixEndState uint32, tableOff, eofAcceptOff, midAcceptOff, firstByteOff int32, prefix []byte, classMapOff int32, numClasses int, useU8, useCompression bool, startBeginAccept bool, immediateAcceptOff int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, firstByteFlags [256]byte, firstBytes []byte, teddyLoOff, teddyHiOff, teddyT1LoOff, teddyT1HiOff int32, teddyTwoByte bool, teddyT2LoOff, teddyT2HiOff int32, teddyThreeByte bool, mandatoryLit *MandatoryLit, rowMapOff int32, useRowDedup bool) []byte {
	var b []byte

	// useMandatoryLit is true when we have a mandatory literal and no existing prefix scan.
	useMandatoryLit := mandatoryLit != nil && len(prefix) == 0

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
		b = append(b, 0x20, 0x05)       // local.get last_accept
		b = append(b, 0x41, 0x00)       // i32.const 0
		b = append(b, 0x4E)             // i32.ge_s
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

	// Mandatory-lit locals (set in each path branch when useMandatoryLit):
	var litPosLocal, scanStartLocal, simdMaskScanLocal, chunkScanLocal byte

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
		if useMandatoryLit {
			b = append(b, 0x0B) // end loop $lit_outer  (unreachable)
		}
		b = append(b, 0x0B)       // end block $no_match  (unreachable)
		// no-match path falls through here
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0B)       // end function
		return b
	}

	// emitDFAPrologue emits: state=..., pos=attempt_start, last_accept=-1, midAccept check.
	// Used only for the mandatory-lit code path (which has no prefix scan).
	emitDFAPrologue := func(b []byte) []byte {
		if startState == midStartState && (!hasWordBoundary || midStartState == midStartWordState) {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
		} else if !hasWordBoundary {
			b = append(b, 0x20, 0x04)
			b = append(b, 0x45)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
			b = append(b, 0x05)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			b = append(b, 0x0B)
		} else {
			b = append(b, 0x20, 0x04)
			b = append(b, 0x45)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
			b = append(b, 0x05)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, wordCharTableOff)
			b = append(b, 0x20, 0x00)
			b = append(b, 0x20, 0x04)
			b = append(b, 0x6A)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B)
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartWordState))
			b = append(b, 0x05)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			b = append(b, 0x0B)
			b = append(b, 0x0B)
		}
		b = append(b, 0x21, 0x02) // local.set state
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0x21, 0x03) // local.set pos
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x21, 0x05) // local.set last_accept
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)
		if startBeginAccept {
			b = append(b, 0x20, 0x04)
			b = append(b, 0x45)
			b = append(b, 0x04, 0x40)
			b = append(b, 0x20, 0x03)
			b = append(b, 0x21, 0x05)
			b = append(b, 0x0B)
		}
		return b
	}

	// emitMLRangeCheck emits the range check at the top of $outer.
	// If attempt_start > lit_pos - MinOff: scan_start = lit_pos + 1; br 2 → $lit_outer.
	// Depths from inside if block: 0=if, 1=$outer, 2=$lit_outer.
	emitMLRangeCheck := func(b []byte) []byte {
		b = append(b, 0x20, 0x04)                       // local.get attempt_start
		b = append(b, 0x20, litPosLocal)                 // local.get lit_pos
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, mandatoryLit.MinOff)
		b = append(b, 0x6B)                              // i32.sub: lit_pos - MinOff
		b = append(b, 0x4A)                              // i32.gt_s: attempt_start > lit_pos-MinOff?
		b = append(b, 0x04, 0x40)                        // if (void)
		b = append(b, 0x20, litPosLocal)                 // local.get lit_pos
		b = append(b, 0x41, 0x01)                        // i32.const 1
		b = append(b, 0x6A)                              // i32.add
		b = append(b, 0x21, scanStartLocal)              // scan_start = lit_pos + 1
		b = append(b, 0x0C, 0x02)                        // br 2 → $lit_outer
		b = append(b, 0x0B)                              // end if
		return b
	}

	// emitMLOuterSetup emits: [init scan_start if MinOff>0]; loop $lit_outer; EmitPrefixScan(lit);
	// OnMatch: set lit_pos, adjust attempt_start; loop $outer; range check; DFA prologue.
	emitMLOuterSetup := func(b []byte) []byte {
		if mandatoryLit.MinOff > 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, mandatoryLit.MinOff)
			b = append(b, 0x21, scanStartLocal)
		}
		b = append(b, 0x03, 0x40) // loop $lit_outer
		b = EmitPrefixScan(b, PrefixScanParams{
			Prefix:      mandatoryLit.Bytes,
			EngineDepth: 2, // loop $lit_outer + block $no_match
			Locals: PrefixScanLocals{
				Ptr:          0,
				Len:          1,
				AttemptStart: scanStartLocal,
				SimdMask:     simdMaskScanLocal,
				Chunk:        chunkScanLocal,
			},
			OnMatch: func(b []byte) []byte {
				// lit_pos = scan_start (AttemptStart was advanced to the found position)
				b = append(b, 0x20, scanStartLocal)
				b = append(b, 0x21, litPosLocal)
				// attempt_start = max(max(lit_pos - MaxOff, 0), attempt_start)
				// Step 1: adj = lit_pos - MaxOff
				b = append(b, 0x20, litPosLocal)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, mandatoryLit.MaxOff)
				b = append(b, 0x6B)                     // i32.sub
				b = append(b, 0x21, simdMaskScanLocal)  // temp = adj
				// Step 2: clamp temp to >= 0
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x48)                     // i32.lt_s: temp < 0?
				b = append(b, 0x04, 0x40)               // if (void)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x21, simdMaskScanLocal)  // temp = 0
				b = append(b, 0x0B)
				// Step 3: take max with attempt_start
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x20, 0x04)
				b = append(b, 0x4A)                     // i32.gt_s: temp > attempt_start?
				b = append(b, 0x04, 0x40)               // if (void)
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x21, 0x04)               // attempt_start = temp
				b = append(b, 0x0B)
				return b
			},
		})
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitMLRangeCheck(b)
		b = emitDFAPrologue(b)
		return b
	}
	_ = emitMLOuterSetup // used in path branches below

	if useU8 && useCompression {
		// ── u8 compressed find path ───────────────────────────────────────────
		if useMandatoryLit {
			// 8 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),lit_pos(7),scan_start(8),simdMask_scan(9),chunk_scan(10)
			litPosLocal = 7; scanStartLocal = 8; simdMaskScanLocal = 9; chunkScanLocal = 10
			b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7B)
		} else {
			// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
			simdMaskLocal = 7; chunkLocal = 8; tLoLocal = 9; tHiLocal = 10
			chunk1Local = 11; t1LoLocal = 12; t1HiLocal = 13; chunk2Local = 14; t2LoLocal = 15; t2HiLocal = 16
			b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
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

		// state = table[row*numClasses + class] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02); b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
		} else {
			b = append(b, 0x20, 0x02) // local.get state
		}
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
		if useMandatoryLit {
			// 7 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),lit_pos(6),scan_start(7),simdMask_scan(8),chunk_scan(9)
			litPosLocal = 6; scanStartLocal = 7; simdMaskScanLocal = 8; chunkScanLocal = 9
			b = append(b, 0x02, 0x07, 0x7F, 0x01, 0x7B)
		} else {
			// 5 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),simdMask(6),chunk(7),...,chunk2(13),t2Lo(14),t2Hi(15)
			simdMaskLocal = 6; chunkLocal = 7; tLoLocal = 8; tHiLocal = 9
			chunk1Local = 10; t1LoLocal = 11; t1HiLocal = 12; chunk2Local = 13; t2LoLocal = 14; t2HiLocal = 15
			b = append(b, 0x02, 0x05, 0x7F, 0x09, 0x7B)
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
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

		// state = table[row*256 + mem[ptr+pos]] where row = rowMap[state] or state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		if useRowDedup {
			b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
			b = append(b, 0x20, 0x02); b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
		} else {
			b = append(b, 0x20, 0x02)       // local.get state
		}
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
	if useMandatoryLit {
		// 8 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),byte(6),lit_pos(7),scan_start(8),simdMask_scan(9),chunk_scan(10)
		litPosLocal = 7; scanStartLocal = 8; simdMaskScanLocal = 9; chunkScanLocal = 10
		b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7B)
	} else {
		// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),byte(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
		simdMaskLocal = 7; chunkLocal = 8; tLoLocal = 9; tHiLocal = 10
		chunk1Local = 11; t1LoLocal = 12; t1HiLocal = 13; chunk2Local = 14; t2LoLocal = 15; t2HiLocal = 16
		b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
	}
	b = append(b, 0x02, 0x40) // block $no_match
	if useMandatoryLit {
		b = emitMLOuterSetup(b)
	} else {
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitOuterPrologue(b)
	}
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

	// state = u16(mem[tableOff + row*512 + byte*2]) where row = rowMap[state] or state
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	if useRowDedup {
		b = append(b, 0x41); b = utils.AppendSLEB128(b, rowMapOff)
		b = append(b, 0x20, 0x02); b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → row
	} else {
		b = append(b, 0x20, 0x02)       // local.get state
	}
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
