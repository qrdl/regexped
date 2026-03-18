package compile

import (
	"regexp/syntax"
	"unicode"
)

// dfa represents a compiled DFA with optimised transition tables.
type dfa struct {
	start     int
	numStates int
	accepting map[int]bool // which states are accepting

	// transitions[state*256 + byte] = nextState (-1 = no transition)
	transitions  []int                // Flat array: [numStates * 256]
	unicodeTrans map[int]map[rune]int // state -> (unicode rune -> next state)

	hasBeginAnchor bool
	hasEndAnchor   bool
	needsUnicode   bool
}

func (d *dfa) Type() EngineType {
	return EngineDFA
}

// newDFA converts syntax.Prog (NFA bytecode) to DFA using subset construction.
func newDFA(prog *syntax.Prog, needsUnicode bool) *dfa {
	dfa := &dfa{
		accepting:    make(map[int]bool),
		unicodeTrans: make(map[int]map[rune]int),
		needsUnicode: needsUnicode,
	}

	// Detect if pattern has begin/end anchors
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstEmptyWidth {
			emptyOp := syntax.EmptyOp(inst.Arg)
			if emptyOp&syntax.EmptyBeginLine != 0 || emptyOp&syntax.EmptyBeginText != 0 {
				dfa.hasBeginAnchor = true
			}
			if emptyOp&syntax.EmptyEndLine != 0 || emptyOp&syntax.EmptyEndText != 0 {
				dfa.hasEndAnchor = true
			}
		}
	}

	// Map from set of NFA states to DFA state ID
	stateMap := make(map[string]int)
	nextStateID := 0

	// Work queue: DFA states to process
	type workItem struct {
		dfaState int
		nfaSet   []uint32 // Set of NFA program counters
	}
	queue := []workItem{}

	// Helper: compute epsilon closure of NFA states
	epsilonClosure := func(states []uint32) []uint32 {
		visited := make(map[uint32]bool)
		result := []uint32{}
		stack := append([]uint32{}, states...)

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
				stack = append(stack, inst.Out, inst.Arg)
			case syntax.InstCapture, syntax.InstNop:
				stack = append(stack, inst.Out)
			case syntax.InstEmptyWidth:
				stack = append(stack, inst.Out)
			}
		}
		return result
	}

	// Helper: convert NFA state set to unique string key
	setToKey := func(states []uint32) string {
		key := ""
		seen := make(map[uint32]bool)
		for _, s := range states {
			if !seen[s] {
				seen[s] = true
				key += string(rune(s)) + ","
			}
		}
		return key
	}

	// Helper: check if any state in set is accepting
	isAccepting := func(states []uint32) bool {
		for _, pc := range states {
			if prog.Inst[pc].Op == syntax.InstMatch {
				return true
			}
		}
		return false
	}

	// Start state: epsilon closure of NFA start
	startSet := epsilonClosure([]uint32{uint32(prog.Start)})
	startKey := setToKey(startSet)
	dfa.start = 0
	stateMap[startKey] = 0
	nextStateID++

	if isAccepting(startSet) {
		dfa.accepting[0] = true
	}

	queue = append(queue, workItem{dfaState: 0, nfaSet: startSet})

	// Process work queue
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		inputMap := make(map[rune][]uint32) // rune -> set of next NFA states

		for _, pc := range item.nfaSet {
			inst := &prog.Inst[pc]

			switch inst.Op {
			case syntax.InstRune1:
				r := inst.Rune[0]
				inputMap[r] = append(inputMap[r], inst.Out)

				if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
					seen := make(map[rune]bool)
					seen[r] = true
					for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
						if !seen[folded] {
							seen[folded] = true
							inputMap[folded] = append(inputMap[folded], inst.Out)
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
					if maxRune-minRune < 256 {
						for r := minRune; r <= maxRune; r++ {
							inputMap[r] = append(inputMap[r], inst.Out)

							if isFoldCase {
								seen := make(map[rune]bool)
								seen[r] = true
								for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
									if !seen[folded] && (folded < minRune || folded > maxRune) {
										seen[folded] = true
										inputMap[folded] = append(inputMap[folded], inst.Out)
									}
								}
							}
						}
					}
				}

			case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				// Not supported by DFA subset construction
			}
		}

		for r, nextNFAStates := range inputMap {
			nextSet := epsilonClosure(nextNFAStates)
			nextKey := setToKey(nextSet)

			nextDFAState, exists := stateMap[nextKey]
			if !exists {
				nextDFAState = nextStateID
				stateMap[nextKey] = nextStateID
				nextStateID++

				if isAccepting(nextSet) {
					dfa.accepting[nextDFAState] = true
				}

				queue = append(queue, workItem{
					dfaState: nextDFAState,
					nfaSet:   nextSet,
				})
			}

			if dfa.unicodeTrans[item.dfaState] == nil {
				dfa.unicodeTrans[item.dfaState] = make(map[rune]int)
			}
			dfa.unicodeTrans[item.dfaState][r] = nextDFAState
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
