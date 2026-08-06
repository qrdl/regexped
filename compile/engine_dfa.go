package compile

import (
	"encoding/binary"
	"regexp/syntax"
	"sort"
	"unicode"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// DFA construction

// dfa represents a compiled DFA with optimised transition tables.
type dfa struct {
	start           int
	midStart        int // start state for mid-string positions (attempt_start > 0) with prev=non-word
	midStartWord    int // start state for mid-string positions with prev=word
	midStartNewline int // start state for mid-string positions with prev=newline (for (?m:^))
	// differs from start when pattern has begin anchors (^/\A) — those are not followed here.
	numStates    int
	accepting    map[int]uint64 // eofAccepting: bitmask of accepting patterns per state
	midAccepting map[int]uint64 // mid-string accept bitmask (no end-anchor context)
	// midAcceptingNW and midAcceptingW are for word-boundary patterns (find mode only).
	midAcceptingNW map[int]uint64
	midAcceptingW  map[int]uint64
	// midAcceptingNL[s]: state s accepts BEFORE consuming the next byte when prev was '\n' (for (?m:^)).
	midAcceptingNL   map[int]uint64
	startBeginAccept bool   // true if start state accepts with ecBegin only (e.g. a*^)
	startAcceptEnd   uint64 // acceptBitsFor(startSet, ecEnd|ecNoWordBoundary) — ecEnd-only accept at start state

	// transitions[state*256 + byte] = nextState (-1 = no transition)
	transitions  []int                // Flat array: [numStates * 256]
	unicodeTrans map[int]map[rune]int // state -> (unicode rune -> next state)

	hasEndAnchor       bool
	hasWordBoundary    bool
	hasNewlineBoundary bool // true when pattern contains (?m:^) or (?m:$)
	needsUnicode       bool
	immediateAccepting map[int]uint64 // leftmost-first: accept without scanning further (bitmask)
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
//
//	|a start: [InstMatch, rune_a_suppressed_was_here] -> but NFA set = [InstMatch] after
//	          suppression means just InstMatch first -> true
//	a?|b start: NFA = [rune_a, InstMatch] (rune_b suppressed) -> rune_a before match -> false
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

// Context flags for epsilon closure: controls which empty-width assertions are followed.
// Used by epsilonClosure and expandWithWB (shared between newDFA and newTDFA).
const (
	ecBegin          = 1
	ecEnd            = 2
	ecWordBoundary   = 4
	ecNoWordBoundary = 8
	ecBeginLine      = 16 // prev byte was '\n' (or start of text): (?m:^) fires
	ecEndLine        = 32 // next byte is '\n' (or end of text):   (?m:$) fires
)

// nfaEpsilonClosure computes the epsilon closure of a set of NFA states,
// respecting anchor context flags (ec* constants above).
// With leftmostFirst=true, states are ordered by priority (lower PC = higher priority).
func nfaEpsilonClosure(prog *syntax.Prog, states []uint32, ctx int, leftmostFirst bool) []uint32 {
	visited := make(map[uint32]bool)
	result := []uint32{}
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
				stack = append(stack, inst.Arg, inst.Out)
			} else {
				stack = append(stack, inst.Out, inst.Arg)
			}
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, inst.Out)
		case syntax.InstEmptyWidth:
			emptyOp := syntax.EmptyOp(inst.Arg)
			follow := true
			if emptyOp&syntax.EmptyBeginText != 0 {
				follow = follow && (ctx&ecBegin) != 0
			}
			if emptyOp&syntax.EmptyBeginLine != 0 {
				follow = follow && (ctx&(ecBegin|ecBeginLine)) != 0
			}
			if emptyOp&syntax.EmptyEndText != 0 {
				follow = follow && (ctx&ecEnd) != 0
			}
			if emptyOp&syntax.EmptyEndLine != 0 {
				follow = follow && (ctx&(ecEnd|ecEndLine)) != 0
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

// nfaExpandWithWB extends an already-closed NFA set by following word-boundary
// assertions that fire given wbCtx, then fully expanding epsilon transitions
// from newly reached states. Preserves leftmostFirst ordering of the original set.
func nfaExpandWithWB(prog *syntax.Prog, closedSet []uint32, wbCtx int, leftmostFirst bool) []uint32 {
	visited := make(map[uint32]bool)
	for _, s := range closedSet {
		visited[s] = true
	}
	result := append([]uint32{}, closedSet...)
	var insertions []struct {
		afterIdx  int
		newStates []uint32
	}
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
		if emptyOp&syntax.EmptyEndLine != 0 && (wbCtx&(ecEnd|ecEndLine)) != 0 {
			fires = true
		}
		if !fires || visited[inst.Out] {
			continue
		}
		var newStates []uint32
		stack := []uint32{inst.Out}
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
				emptyOp2 := syntax.EmptyOp(inst2.Arg)
				follow2 := true
				if emptyOp2&syntax.EmptyBeginText != 0 {
					follow2 = follow2 && (wbCtx&ecBegin) != 0
				}
				if emptyOp2&syntax.EmptyBeginLine != 0 {
					follow2 = follow2 && (wbCtx&(ecBegin|ecBeginLine)) != 0
				}
				if emptyOp2&syntax.EmptyEndText != 0 {
					follow2 = follow2 && (wbCtx&ecEnd) != 0
				}
				if emptyOp2&syntax.EmptyEndLine != 0 {
					follow2 = follow2 && (wbCtx&(ecEnd|ecEndLine)) != 0
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
			insertions = append(insertions, struct {
				afterIdx  int
				newStates []uint32
			}{i, newStates})
		}
	}
	if len(insertions) == 0 {
		return result
	}
	out := make([]uint32, 0, len(result)+32)
	insertIdx := 0
	for i, pc := range result {
		out = append(out, pc)
		for insertIdx < len(insertions) && insertions[insertIdx].afterIdx == i {
			out = append(out, insertions[insertIdx].newStates...)
			insertIdx++
		}
	}
	return out
}

// nfaBuildInputMap builds a rune→nextNFAStates map from an expanded NFA set,
// applying leftmostFirst suppression (skip byte-consumers after InstMatch).
//
// In single-pattern mode (pBits == nil) suppression is global: once any
// InstMatch is seen, all subsequent byte-consumers are skipped.
//
// In multi-pattern mode (pBits != nil) suppression is per-pattern: a
// byte-consumer at PC p is skipped only when pBits[p] != 0 and all of its
// pattern bits have already seen their InstMatch.  This prevents one
// pattern's early match from suppressing transitions for other patterns.
func nfaBuildInputMap(prog *syntax.Prog, expanded []uint32, leftmostFirst bool, pBits []uint64) map[rune][]uint32 {
	m := make(map[rune][]uint32)
	seenMatch := false       // single-pattern mode
	var seenMatchBits uint64 // multi-pattern mode
	multiPattern := leftmostFirst && pBits != nil
	for _, pc := range expanded {
		inst := &prog.Inst[pc]
		if leftmostFirst {
			if multiPattern {
				// Per-pattern suppression: skip this byte-consumer only if ALL
				// of its pattern bits have already matched.
				if bits := pBits[pc]; bits != 0 && seenMatchBits&bits == bits {
					switch inst.Op {
					case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
						continue
					}
				}
			} else if seenMatch {
				switch inst.Op {
				case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
					continue
				}
			}
		}
		if inst.Op == syntax.InstMatch {
			if multiPattern {
				seenMatchBits |= pBits[pc]
			} else {
				seenMatch = true
			}
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

// newDFA converts syntax.Prog (NFA bytecode) to DFA using subset construction.
// patternBitsArg is optional: if provided, patternBitsArg[0][pc] gives the bitmask
// for NFA instruction pc; InstMatch instructions accumulate their bits into the accept maps.
// When absent, any InstMatch contributes bit 1 (single-pattern mode).
//
// maxStates bounds subset-construction cost: the BFS bails out and returns
// (nil, false) once the number of distinct DFA states discovered exceeds it,
// mirroring newTDFA's limit parameter. This is not optional — some patterns
// (e.g. two independent bounded-repetition inverted classes straddling an
// ambiguous split point, like `[^,]{250,}X[^;]{250,}`) make the subset
// construction produce tens of thousands of states with no plateau in
// sight; without an internal cap, CompileOptions.MaxDFAStates cannot do its
// documented job of bounding compile-time cost, because it was previously
// only checked on newDFA's *output*, after the unbounded construction had
// already run to completion (or exhausted memory/CPU trying to).
func newDFA(prog *syntax.Prog, needsUnicode bool, leftmostFirst bool, maxStates int, patternBitsArg ...[]uint64) (*dfa, bool) {
	dfa := &dfa{
		accepting:          make(map[int]uint64),
		midAccepting:       make(map[int]uint64),
		midAcceptingNW:     make(map[int]uint64),
		midAcceptingW:      make(map[int]uint64),
		midAcceptingNL:     make(map[int]uint64),
		unicodeTrans:       make(map[int]map[rune]int),
		needsUnicode:       needsUnicode,
		immediateAccepting: make(map[int]uint64),
	}

	var pBits []uint64
	if len(patternBitsArg) > 0 {
		pBits = patternBitsArg[0]
	}

	// Detect if pattern has begin/end anchors, word boundary, or multiline assertions
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstEmptyWidth {
			emptyOp := syntax.EmptyOp(inst.Arg)
			if emptyOp&syntax.EmptyEndLine != 0 || emptyOp&syntax.EmptyEndText != 0 {
				dfa.hasEndAnchor = true
			}
			if emptyOp&syntax.EmptyWordBoundary != 0 || emptyOp&syntax.EmptyNoWordBoundary != 0 {
				dfa.hasWordBoundary = true
			}
			if emptyOp&syntax.EmptyBeginLine != 0 || emptyOp&syntax.EmptyEndLine != 0 {
				dfa.hasNewlineBoundary = true
			}
		}
	}

	// Map from set of NFA states to DFA state ID
	stateMap := make(map[string]int)
	nextStateID := 0

	type workItem struct {
		dfaState       int
		nfaSet         []uint32
		prevWasWord    bool
		prevWasNewline bool // true when previous byte was '\n' (for (?m:^) context)
	}
	queue := []workItem{}

	// Context flags for epsilon closure: controls which empty-width assertions are followed.
	// ecBegin:          follow EmptyBeginText (\A) and EmptyBeginLine (^) — valid only at start of input.
	// ecEnd:            follow EmptyEndText (\z) and EmptyEndLine ($)   — valid only at end of input.
	// ecWordBoundary:   follow EmptyWordBoundary (\b) — prev != curr (crossing word/non-word boundary).
	// ecNoWordBoundary: follow EmptyNoWordBoundary (\B) — prev == curr (same class).
	// ecBeginLine:       follow EmptyBeginLine ((?m:^)) — prev was '\n' or start-of-text.
	// ecEndLine:         follow EmptyEndLine ((?m:$))   — next byte is '\n' or end-of-text.
	// Mid-string transitions use ctx=0 so no anchors are followed.

	// Compute epsilon closure of NFA states, respecting anchor context.
	epsilonClosure := func(states []uint32, ctx int) []uint32 {
		return nfaEpsilonClosure(prog, states, ctx, leftmostFirst)
	}

	// isWordChar reports whether b is a word character ([A-Za-z0-9_]).
	// Used during DFA construction to resolve \b / \B assertions.
	isWordChar := isWordCharByte

	// expandWithWB extends an already-closed NFA set by following word-boundary
	// assertions that fire given wbCtx, then fully expanding epsilon transitions
	// from newly reached states. This preserves leftmostFirst ordering of the original set.
	expandWithWB := func(closedSet []uint32, wbCtx int) []uint32 {
		return nfaExpandWithWB(prog, closedSet, wbCtx, leftmostFirst)
	}

	// acceptBitsFor returns the combined accept bitmask for the epsilon closure of states
	// under the given context. Each InstMatch instruction contributes its bits from pBits
	// (or bit 1 when pBits is nil / index out of range / zero).
	acceptBitsFor := func(states []uint32, ctx int) uint64 {
		expanded := epsilonClosure(states, ctx)
		var bits uint64
		for _, pc := range expanded {
			if prog.Inst[pc].Op == syntax.InstMatch {
				if pBits == nil || int(pc) >= len(pBits) || pBits[pc] == 0 {
					bits |= 1
				} else {
					bits |= pBits[pc]
				}
			}
		}
		return bits
	}

	// nfaAcceptBits returns the combined bitmask for a set of NFA states at ctx=0.
	nfaAcceptBits := func(states []uint32) uint64 {
		return acceptBitsFor(states, 0)
	}

	// orAccept writes bits into m[state] only when bits != 0, preventing spurious
	// 0-value insertions that would corrupt len(map) checks (e.g. hasImmAccept).
	orAccept := func(m map[int]uint64, state int, bits uint64) {
		if bits != 0 {
			m[state] |= bits
		}
	}

	// Convert NFA state set + prevWasWord context to unique string key.
	// Two states with identical NFA sets but different prevWasWord values are
	// distinct DFA states because they resolve word boundary assertions differently.
	// acceptBits is included so that states with different accept bitmasks get
	// distinct keys (required for multi-pattern suffix DFA correctness).
	setToKey := func(states []uint32, prevWasWord bool, acceptBits uint64, prevWasNewline ...bool) string {
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
		if len(prevWasNewline) > 0 && prevWasNewline[0] {
			key += "N"
		}
		// Only include bitmask in multi-pattern mode (pBits != nil).
		// For single-pattern callers (pBits == nil), the bitmask is uniquely
		// determined by the NFA state set and including it would alter key strings,
		// changing DFA state ordering and breaking fuel/size baselines.
		if acceptBits != 0 && pBits != nil {
			var b8 [8]byte
			binary.LittleEndian.PutUint64(b8[:], acceptBits)
			key += string(b8[:])
		}
		return key
	}

	// isAccepting reports whether any state in the epsilon closure is an accept state.
	// Used only for startBeginAccept (bool result needed).
	isAccepting := func(states []uint32, ctx int) bool {
		return acceptBitsFor(states, ctx) != 0
	}

	// Start state: epsilon closure of NFA start, following begin-anchors (^ and \A).
	// At beginning of input, prev is always non-word.
	startSet := epsilonClosure([]uint32{uint32(prog.Start)}, ecBegin)
	startKey := setToKey(startSet, false, nfaAcceptBits(startSet))
	dfa.start = 0
	stateMap[startKey] = 0
	nextStateID++

	// Start state is at position 0 with prevWasWord=false (start-of-input = non-word).
	// EOF from start = end-of-input after consuming nothing: use ecNoWordBoundary for WB check.
	orAccept(dfa.accepting, 0, acceptBitsFor(startSet, ecBegin|ecEnd|ecNoWordBoundary))
	orAccept(dfa.midAccepting, 0, acceptBitsFor(startSet, 0))
	// Pre-transition accept for start state (prevWasWord=false):
	// midAcceptNW: before non-word byte → \B fires (prev=non-word, next=non-word)
	orAccept(dfa.midAcceptingNW, 0, acceptBitsFor(startSet, ecNoWordBoundary))
	// midAcceptW: before word byte → \b fires (prev=non-word, next=word)
	orAccept(dfa.midAcceptingW, 0, acceptBitsFor(startSet, ecWordBoundary))
	// midAcceptNL: before '\n' byte → (?m:$) fires (ecEndLine | \B since prev=non-word)
	if dfa.hasNewlineBoundary {
		orAccept(dfa.midAcceptingNL, 0, acceptBitsFor(startSet, ecNoWordBoundary|ecEndLine))
	}
	// startBeginAccept: pattern matches empty at position 0 due to begin anchor (^/\A).
	// Distinct from acceptStates (ecBegin|ecEnd) and midAcceptStates (ctx=0).
	dfa.startBeginAccept = isAccepting(startSet, ecBegin)
	dfa.startAcceptEnd = acceptBitsFor(startSet, ecEnd|ecNoWordBoundary)

	if leftmostFirst && isImmediateAccepting(startSet, prog) {
		bits := nfaAcceptBits(startSet)
		if bits == 0 {
			bits = 1
		}
		dfa.immediateAccepting[0] |= bits
	}

	queue = append(queue, workItem{dfaState: 0, nfaSet: startSet, prevWasWord: false})

	// Mid-string start state (prev=non-word): epsilon closure WITHOUT begin-anchors,
	// used for attempt_start > 0 in find mode when prev byte was not a word char.
	midStartSet := epsilonClosure([]uint32{uint32(prog.Start)}, 0)
	midStartKey := setToKey(midStartSet, false, nfaAcceptBits(midStartSet))
	if id, exists := stateMap[midStartKey]; exists {
		dfa.midStart = id
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			bits := nfaAcceptBits(midStartSet)
			if bits == 0 {
				bits = 1
			}
			dfa.immediateAccepting[dfa.midStart] |= bits
		}
	} else {
		dfa.midStart = nextStateID
		stateMap[midStartKey] = nextStateID
		nextStateID++
		// midStart is prevWasWord=false: end-of-input → \B fires
		orAccept(dfa.accepting, dfa.midStart, acceptBitsFor(midStartSet, ecEnd|ecNoWordBoundary))
		orAccept(dfa.midAccepting, dfa.midStart, acceptBitsFor(midStartSet, 0))
		// midAcceptNW for midStart (prevWasWord=false): before non-word → \B fires
		orAccept(dfa.midAcceptingNW, dfa.midStart, acceptBitsFor(midStartSet, ecNoWordBoundary))
		// midAcceptW for midStart (prevWasWord=false): before word → \b fires
		orAccept(dfa.midAcceptingW, dfa.midStart, acceptBitsFor(midStartSet, ecWordBoundary))
		// midAcceptNL for midStart (prevWasWord=false): before '\n' → (?m:$) fires
		if dfa.hasNewlineBoundary {
			orAccept(dfa.midAcceptingNL, dfa.midStart, acceptBitsFor(midStartSet, ecNoWordBoundary|ecEndLine))
		}
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			bits := nfaAcceptBits(midStartSet)
			if bits == 0 {
				bits = 1
			}
			dfa.immediateAccepting[dfa.midStart] |= bits
		}
		queue = append(queue, workItem{dfaState: dfa.midStart, nfaSet: midStartSet, prevWasWord: false})
	}

	// Mid-string start state (prev=word): used when attempt_start > 0 and prev byte was a word char.
	// Same NFA set as midStart but different prevWasWord context → different DFA state.
	midStartWordKey := setToKey(midStartSet, true, nfaAcceptBits(midStartSet))
	if id, exists := stateMap[midStartWordKey]; exists {
		dfa.midStartWord = id
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			bits := nfaAcceptBits(midStartSet)
			if bits == 0 {
				bits = 1
			}
			dfa.immediateAccepting[dfa.midStartWord] |= bits
		}
	} else {
		dfa.midStartWord = nextStateID
		stateMap[midStartWordKey] = nextStateID
		nextStateID++
		// midStartWord is prevWasWord=true: end-of-input → \b fires
		orAccept(dfa.accepting, dfa.midStartWord, acceptBitsFor(midStartSet, ecEnd|ecWordBoundary))
		orAccept(dfa.midAccepting, dfa.midStartWord, acceptBitsFor(midStartSet, 0))
		// midAcceptNW for midStartWord (prevWasWord=true): before non-word → \b fires
		orAccept(dfa.midAcceptingNW, dfa.midStartWord, acceptBitsFor(midStartSet, ecWordBoundary))
		// midAcceptW for midStartWord (prevWasWord=true): before word → \B fires
		orAccept(dfa.midAcceptingW, dfa.midStartWord, acceptBitsFor(midStartSet, ecNoWordBoundary))
		// midAcceptNL for midStartWord (prevWasWord=true): before '\n' → (?m:$) fires (\b since prev=word)
		if dfa.hasNewlineBoundary {
			orAccept(dfa.midAcceptingNL, dfa.midStartWord, acceptBitsFor(midStartSet, ecWordBoundary|ecEndLine))
		}
		if leftmostFirst && isImmediateAccepting(midStartSet, prog) {
			bits := nfaAcceptBits(midStartSet)
			if bits == 0 {
				bits = 1
			}
			dfa.immediateAccepting[dfa.midStartWord] |= bits
		}
		queue = append(queue, workItem{dfaState: dfa.midStartWord, nfaSet: midStartSet, prevWasWord: true})
	}

	// Mid-string start state (prev=newline): used when attempt_start > 0 and prev byte was '\n'.
	// NFA set uses ecBeginLine context so (?m:^) assertions fire.
	if dfa.hasNewlineBoundary {
		midStartNewlineSet := epsilonClosure([]uint32{uint32(prog.Start)}, ecBeginLine)
		midStartNewlineKey := setToKey(midStartNewlineSet, false, nfaAcceptBits(midStartNewlineSet), true) // prevWasWord=false, prevWasNewline=true
		if id, exists := stateMap[midStartNewlineKey]; exists {
			dfa.midStartNewline = id
			if leftmostFirst && isImmediateAccepting(midStartNewlineSet, prog) {
				bits := nfaAcceptBits(midStartNewlineSet)
				if bits == 0 {
					bits = 1
				}
				dfa.immediateAccepting[dfa.midStartNewline] |= bits
			}
		} else {
			dfa.midStartNewline = nextStateID
			stateMap[midStartNewlineKey] = nextStateID
			nextStateID++
			// midStartNewline is prevWasNewline=true: ecBeginLine fires, ecNoWordBoundary fires (newline is non-word).
			orAccept(dfa.accepting, dfa.midStartNewline, acceptBitsFor(midStartNewlineSet, ecEnd|ecNoWordBoundary))
			orAccept(dfa.midAccepting, dfa.midStartNewline, acceptBitsFor(midStartNewlineSet, 0))
			orAccept(dfa.midAcceptingNW, dfa.midStartNewline, acceptBitsFor(midStartNewlineSet, ecNoWordBoundary))
			orAccept(dfa.midAcceptingW, dfa.midStartNewline, acceptBitsFor(midStartNewlineSet, ecWordBoundary))
			// midAcceptNL for midStartNewline (prevWasWord=false): before '\n' → (?m:$) fires (\B since prev=newline=non-word)
			orAccept(dfa.midAcceptingNL, dfa.midStartNewline, acceptBitsFor(midStartNewlineSet, ecNoWordBoundary|ecEndLine))
			if leftmostFirst && isImmediateAccepting(midStartNewlineSet, prog) {
				bits := nfaAcceptBits(midStartNewlineSet)
				if bits == 0 {
					bits = 1
				}
				dfa.immediateAccepting[dfa.midStartNewline] |= bits
			}
			queue = append(queue, workItem{dfaState: dfa.midStartNewline, nfaSet: midStartNewlineSet, prevWasNewline: true})
		}
	}

	// Process work queue
	for len(queue) > 0 {
		if nextStateID > maxStates {
			return nil, false
		}
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
			return nfaBuildInputMap(prog, expanded, leftmostFirst, pBits)
		}

		// expandedForNewline: expansion for '\n' bytes.
		// When reading '\n': it is non-word (use word/non-word boundary context),
		// and ecEndLine fires ((?m:$) assertions follow).
		var expandedForNewline []uint32
		if dfa.hasNewlineBoundary {
			var nlWBCtx int
			if item.prevWasWord {
				nlWBCtx = ecWordBoundary | ecEndLine
			} else {
				nlWBCtx = ecNoWordBoundary | ecEndLine
			}
			expandedForNewline = expandWithWB(item.nfaSet, nlWBCtx)
		}

		inputMapWord := buildInputMap(expandedForWordChar)
		inputMapNonWord := buildInputMap(expandedForNonWordChar)
		var inputMapNewline map[rune][]uint32
		if dfa.hasNewlineBoundary {
			inputMapNewline = buildInputMap(expandedForNewline)
		}

		// Collect transitions for all 256 bytes, using the appropriate inputMap.
		// Two bytes with the same isWordChar class and identical next-NFA-states map
		// to the same next DFA state naturally via setToKey.
		getOrAddState := func(nextSet []uint32, nextPrevWasWord bool, nextPrevWasNewline ...bool) int {
			nlFlag := len(nextPrevWasNewline) > 0 && nextPrevWasNewline[0]
			nextKey := setToKey(nextSet, nextPrevWasWord, nfaAcceptBits(nextSet), nlFlag)
			nextDFAState, exists := stateMap[nextKey]
			if !exists {
				nextDFAState = nextStateID
				stateMap[nextKey] = nextStateID
				nextStateID++
				var eofWBCtx int
				if nextPrevWasWord {
					eofWBCtx = ecWordBoundary
				} else {
					eofWBCtx = ecNoWordBoundary
				}
				orAccept(dfa.accepting, nextDFAState, acceptBitsFor(nextSet, ecEnd|eofWBCtx))
				orAccept(dfa.midAccepting, nextDFAState, acceptBitsFor(nextSet, 0))
				var nwCtx int
				if nextPrevWasWord {
					nwCtx = ecWordBoundary
				} else {
					nwCtx = ecNoWordBoundary
				}
				orAccept(dfa.midAcceptingNW, nextDFAState, acceptBitsFor(nextSet, nwCtx))
				var wCtx int
				if nextPrevWasWord {
					wCtx = ecNoWordBoundary
				} else {
					wCtx = ecWordBoundary
				}
				orAccept(dfa.midAcceptingW, nextDFAState, acceptBitsFor(nextSet, wCtx))
				if dfa.hasNewlineBoundary {
					orAccept(dfa.midAcceptingNL, nextDFAState, acceptBitsFor(nextSet, nwCtx|ecEndLine))
				}
				if leftmostFirst {
					if pBits != nil {
						// Multi-pattern: per-pattern immediate acceptance.
						// Bit k is immediately accepting iff pattern k's InstMatch
						// appears before any of k's byte-consumers in the priority
						// ordered NFA set.  Patterns with ongoing byte-consumers
						// (a+, a*) are NOT marked immediately accepting here.
						var seenByteConsumers uint64
						var immBits uint64
						for _, pc := range nextSet {
							var pkBits uint64
							if int(pc) < len(pBits) {
								pkBits = pBits[pc]
							}
							switch prog.Inst[pc].Op {
							case syntax.InstMatch:
								immBits |= pkBits &^ seenByteConsumers
							case syntax.InstRune, syntax.InstRune1,
								syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
								seenByteConsumers |= pkBits
							}
						}
						dfa.immediateAccepting[nextDFAState] |= immBits
					} else if isImmediateAccepting(nextSet, prog) {
						bits := nfaAcceptBits(nextSet)
						if bits == 0 {
							bits = 1
						}
						dfa.immediateAccepting[nextDFAState] |= bits
					}
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

		// Process all 256 bytes in fixed order to ensure deterministic DFA state
		// numbering. Iterating inputMapWord/inputMapNonWord as maps would create
		// states in non-deterministic order (Go map iteration is randomised).
		for b := 0; b < 256; b++ {
			r := rune(b)
			if isWordChar(byte(r)) {
				nextNFAStates, ok := inputMapWord[r]
				if !ok {
					continue
				}
				nextSet := epsilonClosure(nextNFAStates, 0)
				nextDFAState := getOrAddState(nextSet, true)
				dfa.unicodeTrans[item.dfaState][r] = nextDFAState
			} else if dfa.hasNewlineBoundary && r == '\n' {
				// '\n' is non-word; if newline-boundary is active, handle it separately
				// so ecEndLine fires ((?m:$) assertions follow).
				if inputMapNewline != nil {
					if nextNFAStates, ok := inputMapNewline['\n']; ok {
						nextSet := epsilonClosure(nextNFAStates, ecBeginLine)
						nextDFAState := getOrAddState(nextSet, false, true) // nextPrevWasNewline=true
						dfa.unicodeTrans[item.dfaState]['\n'] = nextDFAState
					}
				}
			} else {
				nextNFAStates, ok := inputMapNonWord[r]
				if !ok {
					continue
				}
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

	return dfa, true
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
	midStartState         int // start state for attempt_start>0 in find mode (prev=non-word)
	midStartWordState     int // start state for attempt_start>0 in find mode (prev=word)
	midStartNewlineState  int // start state for attempt_start>0 in find mode (prev=newline)
	numStates             int
	acceptStates          map[int]uint64 // eofAccept: bitmask of accepting patterns at end of input
	midAcceptStates       map[int]uint64 // midAccept: bitmask for any-position accept (no WB context)
	midAcceptNWStates     map[int]uint64 // midAcceptNW: accepts before non-word byte (WB triggered)
	midAcceptWStates      map[int]uint64 // midAcceptW: accepts before word byte (WB triggered)
	midAcceptNLStates     map[int]uint64 // midAcceptNL: accepts before '\n' byte ((?m:$) triggered)
	immediateAcceptStates map[int]uint64 // leftmost-first: accept without scanning further
	transitions           []int          // flat [state*256+byte] = nextState; -1 = dead
	startBeginAccept      bool           // true if startState accepts with ecBegin only (e.g. a*^)
	startAcceptEnd        uint64         // acceptBitsFor(startSet, ecEnd|ecNoWordBoundary) — ecEnd-only
	hasWordBoundary       bool           // true if pattern contains \b or \B
	hasNewlineBoundary    bool           // true if pattern contains (?m:^) or (?m:$)
}

// dfaTableFrom builds a dfaTable directly from a compiled dfa struct,
// then applies Hopcroft DFA minimization.
func dfaTableFrom(d *dfa) *dfaTable {
	t := &dfaTable{
		startState:            d.start,
		midStartState:         d.midStart,
		midStartWordState:     d.midStartWord,
		midStartNewlineState:  d.midStartNewline,
		numStates:             d.numStates,
		acceptStates:          d.accepting,
		midAcceptStates:       d.midAccepting,
		midAcceptNWStates:     d.midAcceptingNW,
		midAcceptWStates:      d.midAcceptingW,
		midAcceptNLStates:     d.midAcceptingNL,
		immediateAcceptStates: d.immediateAccepting,
		transitions:           d.transitions,
		startBeginAccept:      d.startBeginAccept,
		startAcceptEnd:        d.startAcceptEnd,
		hasWordBoundary:       d.hasWordBoundary,
		hasNewlineBoundary:    d.hasNewlineBoundary,
	}
	minimizeDFA(t)
	reorderAcceptFirst(t)
	return t
}

// dfaTableFromCanonical builds a dfaTable, applies Hopcroft minimization, then
// BFS-relabels states so that structurally equivalent DFAs get identical state
// numbering. Used by the set composition path (compile/set.go) to produce
// canonical DFAs for fingerprinting and dedup. The per-pattern path continues
// to use dfaTableFrom (no relabel) so single-pattern fuel/size baselines are
// unchanged.
func dfaTableFromCanonical(d *dfa) *dfaTable {
	t := dfaTableFrom(d)
	bfsRelabelDFA(t)
	// Re-apply accept-first ordering: bfs reshuffles by discovery order, and we
	// want accepting states at the bottom of the ID range so the runtime can
	// check "is accept?" with a single state-ID compare.
	reorderAcceptFirst(t)
	return t
}

// bfsRelabelDFA renumbers DFA states in BFS discovery order starting from
// the canonical start states (startState first, then mid-start states).
// After relabelling, startState == 0 and structurally identical DFAs have
// identical state numberings — a precondition for dfaFingerprint.
func bfsRelabelDFA(t *dfaTable) {
	n := t.numStates
	if n <= 1 {
		return
	}

	oldToNew := make([]int, n)
	for i := range oldToNew {
		oldToNew[i] = -1
	}
	newID := 0
	queue := make([]int, 0, n)

	assign := func(s int) {
		if s >= 0 && s < n && oldToNew[s] < 0 {
			oldToNew[s] = newID
			newID++
			queue = append(queue, s)
		}
	}

	// Seed BFS in canonical order so start states get the lowest IDs.
	assign(t.startState)
	assign(t.midStartState)
	assign(t.midStartWordState)
	if t.hasNewlineBoundary {
		assign(t.midStartNewlineState)
	}

	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for b := 0; b < 256; b++ {
			if next := t.transitions[s*256+b]; next >= 0 {
				assign(next)
			}
		}
	}

	// Assign IDs to any unreachable states (defensive; shouldn't occur after minimization).
	for s := 0; s < n; s++ {
		if oldToNew[s] < 0 {
			oldToNew[s] = newID
			newID++
		}
	}

	applyStateRemap(t, oldToNew)
}

// reorderAcceptFirst partitions DFA states into three contiguous ID ranges:
//
//	[0 .. immK-1]      : immediate-accepting states (subset of accepting)
//	[immK .. accK-1]   : accepting but not immediate-accepting
//	[accK .. n-1]      : non-accepting
//
// In WASM-ID space (state = goID + 1, 0 = dead) this becomes:
//
//	1 .. immK            : immediate-accepting
//	immK+1 .. accK       : accepting (non-immediate)
//	accK+1 .. numWASM-1  : non-accepting
//
// This enables two compile-time-encoded runtime checks:
//   - EOF accept:        (state - 1) u< acceptLimit   (acceptLimit = accK)
//   - Immediate-accept:  state u<= immAcceptLimit     (immAcceptLimit = immK)
func reorderAcceptFirst(t *dfaTable) {
	n := t.numStates
	if n <= 1 {
		return
	}
	oldToNew := make([]int, n)
	for s := range oldToNew {
		oldToNew[s] = -1
	}
	newID := 0
	// Pass 1: immediate-accepting (subset of accepting).
	for s := 0; s < n; s++ {
		if t.immediateAcceptStates[s] != 0 {
			oldToNew[s] = newID
			newID++
		}
	}
	// Pass 2: accepting but not immediate.
	for s := 0; s < n; s++ {
		if oldToNew[s] < 0 && t.acceptStates[s] != 0 {
			oldToNew[s] = newID
			newID++
		}
	}
	// Pass 3: non-accepting.
	for s := 0; s < n; s++ {
		if oldToNew[s] < 0 {
			oldToNew[s] = newID
			newID++
		}
	}
	applyStateRemap(t, oldToNew)
}

// applyStateRemap rewrites every state-ID reference inside t using oldToNew.
// oldToNew must be a permutation of [0, t.numStates).
func applyStateRemap(t *dfaTable, oldToNew []int) {
	n := t.numStates
	newTrans := make([]int, n*256)
	for i := range newTrans {
		newTrans[i] = -1
	}
	for s := 0; s < n; s++ {
		ns := oldToNew[s]
		for b := 0; b < 256; b++ {
			if next := t.transitions[s*256+b]; next >= 0 {
				newTrans[ns*256+b] = oldToNew[next]
			}
		}
	}

	remapMap := func(m map[int]uint64) map[int]uint64 {
		out := make(map[int]uint64, len(m))
		for s, v := range m {
			if v != 0 {
				out[oldToNew[s]] |= v
			}
		}
		return out
	}

	t.startState = oldToNew[t.startState]
	t.midStartState = oldToNew[t.midStartState]
	t.midStartWordState = oldToNew[t.midStartWordState]
	if t.hasNewlineBoundary {
		t.midStartNewlineState = oldToNew[t.midStartNewlineState]
	}
	t.transitions = newTrans
	t.acceptStates = remapMap(t.acceptStates)
	t.midAcceptStates = remapMap(t.midAcceptStates)
	t.midAcceptNWStates = remapMap(t.midAcceptNWStates)
	t.midAcceptWStates = remapMap(t.midAcceptWStates)
	t.midAcceptNLStates = remapMap(t.midAcceptNLStates)
	t.immediateAcceptStates = remapMap(t.immediateAcceptStates)
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
	type sigKey struct{ a, ma, maw, manw, manl, imm uint64 }
	sigToClass := make(map[sigKey]int, 8)
	classOf := make([]int, n)
	numClasses := 0
	for s := 0; s < n; s++ {
		sk := sigKey{
			t.acceptStates[s],
			t.midAcceptStates[s],
			t.midAcceptWStates[s],
			t.midAcceptNWStates[s],
			t.midAcceptNLStates[s],
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

	// Accept maps for the minimized DFA (OR-merge bitmasks for merged states).
	// Only store nonzero values: inserting 0-value entries via "|= 0" would make
	// len(map) > 0 for all-zero maps, which would break the hasImmAccept check in
	// buildDFALayout (it tests len(t.immediateAcceptStates) > 0).
	newAccept := make(map[int]uint64)
	newMidAccept := make(map[int]uint64)
	newMidAcceptNW := make(map[int]uint64)
	newMidAcceptW := make(map[int]uint64)
	newMidAcceptNL := make(map[int]uint64)
	newImmAccept := make(map[int]uint64)
	for s := 0; s < n; s++ {
		c := classOf[s]
		if v := t.acceptStates[s]; v != 0 {
			newAccept[c] |= v
		}
		if v := t.midAcceptStates[s]; v != 0 {
			newMidAccept[c] |= v
		}
		if v := t.midAcceptNWStates[s]; v != 0 {
			newMidAcceptNW[c] |= v
		}
		if v := t.midAcceptWStates[s]; v != 0 {
			newMidAcceptW[c] |= v
		}
		if v := t.midAcceptNLStates[s]; v != 0 {
			newMidAcceptNL[c] |= v
		}
		if v := t.immediateAcceptStates[s]; v != 0 {
			newImmAccept[c] |= v
		}
	}

	// Remap special state indices.
	t.startState = classOf[t.startState]
	t.midStartState = classOf[t.midStartState]
	t.midStartWordState = classOf[t.midStartWordState]
	if t.hasNewlineBoundary {
		t.midStartNewlineState = classOf[t.midStartNewlineState]
	}
	t.numStates = numClasses
	t.transitions = newTrans
	t.acceptStates = newAccept
	t.midAcceptStates = newMidAccept
	t.midAcceptNWStates = newMidAcceptNW
	t.midAcceptWStates = newMidAcceptW
	t.midAcceptNLStates = newMidAcceptNL
	t.immediateAcceptStates = newImmAccept
	// hasWordBoundary, hasNewlineBoundary and startBeginAccept are pattern-level flags, unchanged.
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
	// useAcceptSideTable selects the EOF accept-check strategy:
	//   false (DFA): WASM state IDs are partitioned (states 1..acceptLimit are
	//                accepting) — accept check is `(state-1) u< acceptLimit`.
	//   true  (TDFA): state IDs cannot be repartitioned (tied to tag-op tables),
	//                so a per-state side table `acceptBytes[state]` is emitted
	//                at acceptOff and read at EOF.
	useAcceptSideTable bool

	// Transition table
	tableOff    int32
	tableBytes  []byte
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
	acceptOff   int32
	acceptBytes []byte

	// acceptLimit is the largest WASM state ID that is eof-accepting. After
	// reorderAcceptFirst, WASM states 1..acceptLimit are accepting and states
	// (acceptLimit+1)..(numWASM-1) are not. State 0 is the implicit dead state.
	// Enables runtime accept checks via a single state-ID compare ("state ≤ K"
	// in WASM-ID space). Mirrors regex-automata's special-state ID partition
	// and Hyperscan mcclellan's accept_limit.
	acceptLimit int32

	// Find-mode flags
	midAcceptOff   int32
	midAcceptBytes []byte

	// LeftmostFirst immediate-accept flags (both match and find).
	// The side table (immediateAcceptOff/Bytes) is kept populated for TDFA
	// (whose state IDs are not partitioned). DFA + CompiledDFA paths use
	// immAcceptLimit instead: after reorderAcceptFirst, WASM states
	// 1..immAcceptLimit are exactly the immediate-accepting states, so the
	// per-byte check becomes `state u<= immAcceptLimit` — one fewer op than
	// the side-table load.
	immediateAcceptOff   int32
	immediateAcceptBytes []byte
	hasImmAccept         bool
	immAcceptLimit       int32

	// Word-boundary tables (find mode only)
	needWordCharTable  bool
	wordCharTableOff   int32
	wordCharTableBytes [256]byte
	midAcceptNWOff     int32
	midAcceptWOff      int32
	midAcceptNLOff     int32
	midAcceptNWBytes   []byte
	midAcceptWBytes    []byte
	midAcceptNLBytes   []byte

	// lmBareShufti (LM_TODO.md LM-4) lifts detectShuftiSelfLoop's
	// len(l.prefix)==0 bail for bare (no literal-anchor) moderately-wide
	// self-loop bodies, e.g. `[A-Z]{8,}`. Set from
	// buildOpts.LikelyMode == LikelyMatch at the find/groups DFA layout
	// call site only — see detectShuftiSelfLoop's doc comment for why the
	// gate exists and why LikelyMatch is the right scope for lifting it.
	lmBareShufti bool

	// lmNonMidShufti (LM_TODO.md LM-3) enables detectShuftiSelfLoop's
	// non-mid-accept detection branch — moderately-wide (9..64 byte)
	// self-loop bodies that are NOT accept states themselves (a mandatory
	// trailing literal/class follows, e.g. `KEY=[a-z0-9/+]+;`). Set from
	// buildOpts.LikelyMode == LikelyMatch at the match and find/groups DFA
	// layout call sites. Gated separately from lmBareShufti because the
	// non-mid channel shares the 254/255 encoded-byte space with
	// detectDominantSelfLoop's own non-mid channel (cap 2 total) — see
	// detectShuftiSelfLoop's doc comment.
	lmNonMidShufti bool

	// lmWideShufti (LM_TODO.md LM-5) widens detectShuftiSelfLoop's self-loop
	// class-width cap from 64 to 239 bytes. Set from
	// buildOpts.LikelyMode == LikelyMatch at the match and find/groups DFA
	// layout call sites — same scope as lmNonMidShufti. Sized with pattest
	// on a hand-built `:[ -~]{10,}` pattern (95-byte class) before
	// implementation, per the task's own instruction: dense/long runs
	// measured -41%..-55% fuel; a run right at the pattern's own minimum
	// length measured +12% (bounded "LM contract cost" residual, same shape
	// as LM-3/LM-4's short-run guard cases, covered by the shared task-38
	// hysteresis).
	lmWideShufti bool

	// Fast-skip / SIMD (find mode only)
	prefix         []byte
	firstByteOff   int32
	firstByteFlags [256]byte
	firstBytes     []byte
	teddyLoOff     int32
	teddyHiOff     int32
	teddyLoBytes   []byte
	teddyHiBytes   []byte
	teddyT1LoOff   int32
	teddyT1HiOff   int32
	teddyT1LoBytes []byte
	teddyT1HiBytes []byte
	teddyT2LoOff   int32
	teddyT2HiOff   int32
	teddyT2LoBytes []byte
	teddyT2HiBytes []byte
	teddyT3LoOff   int32
	teddyT3HiOff   int32
	teddyT3LoBytes []byte
	teddyT3HiBytes []byte

	// Find-mode DFA states
	wasmMidStart        uint32
	wasmMidStartWord    uint32
	wasmMidStartNewline uint32
	wasmPrefixEnd       uint32 // state after walking the prefix from midStartState (prev=non-word)
	wasmPrefixEndWord   uint32 // state after walking the prefix from midStartWordState (prev=word).
	//                     Only populated when hasWordBoundary; otherwise == wasmPrefixEnd.
	//                     Used in the prefix-scan shortcut to honour `\b` at the pattern start.
	startBeginAccept bool

	// tableEnd is the highest memory address used by any table in this layout.
	tableEnd int64

	// useHybridDispatch is true when the hybrid path is chosen: table-driven
	// state transitions combined with compiled self-loop inner blocks.
	useHybridDispatch bool

	// Opt 1 — LikelyNoMatch dominant self-loop detection (Phases 1–3).
	//
	// dominantStates lists every DFA state that qualifies for SIMD bulk-skip:
	//   - ≥ 240/256 byte classes self-loop;
	//   - exit set has exactly 1 byte (Phase 2 constraint; Phase 5 lifts);
	//   - state is mid-accepting (Option 1 piggyback requires it).
	//
	// Slice order matches the encoded midAccept byte value: the i-th entry
	// has `midAcceptBytes[entry.state] == byte(2 + i)`. Non-dominant
	// accepting states stay at 1; non-accepting stay at 0. The find-body
	// emitter reads the cached midAccept value and dispatches via a chain
	// of `i32.const K + i32.eq` tests inside the already-taken
	// `if midAccept != 0` branch — so no per-iteration overhead is added
	// on the no-match path.
	//
	// Cap: detection stops after `maxDominantStates` (defined locally) to
	// bound WASM growth.
	dominantStates []dominantInfo

	// Non-mid-accept dominant dispatch uses pure state-ID compares in the
	// emitted WASM (no side-table lookup) as a workaround for the +47%
	// Cranelift no-match regression observed when a memory-table lookup
	// was added to the hot loop. So no separate per-state side table is
	// needed — the dominantInfo.state value is embedded directly into the
	// emitted `i32.const + i32.eq + if` chain.

	// lnmAction5 (LNM Action 5 — impossible-byte SIMD skip): set by
	// compilePattern when buildOpts.LikelyMode == LikelyNoMatch. Threaded
	// into prefixScanParams.LikelyNoMatch by appendFindCodeEntry so the
	// 17..64-byte first-byte set Shufti gate ignores the density heuristic.
	lnmAction5 bool

	// skipSafeOnDead (Task 8 — dead-state skip): true when every byte that
	// causes a dead transition from any DFA state also causes a dead
	// transition from midStart. Under this condition, when the find loop's
	// scan dies at position p starting from attempt position k, all
	// intermediate attempts from k+1..p-1 would either die at or before p
	// — so we can safely set attempt_start = p+1 instead of advancing by
	// one. Collapses O(N²) find-mode worst case on near-miss greedy
	// patterns to O(N). See plans/TODO.md task 8.
	skipSafeOnDead bool

	// eofSkipSafe (Task 8 follow-up #2 — min-length quantifier skip): true
	// when reaching EOF mid-scan without ever recording an accept proves no
	// later start position can match either (see detectEOFSkipSafe). When
	// true, the find body's EOF handler branches straight to $no_match
	// instead of advancing attempt_start by one and retrying. Collapses the
	// O(N²) worst case for counted-quantifier patterns like
	// `[a-z]{50,}[0-9]` whose body class runs to EOF without ever
	// containing the suffix. See plans/TODO.md task 8 follow-up #2.
	eofSkipSafe bool
}

// dominantInfo describes one dominant self-loop state recorded by
// detectDominantSelfLoop.
//
// `exitBytes` holds 1..8 bytes (Shufti cap; see Phase 5 below). When
// len(exitBytes) == 1 the emitter uses the Phase 2 splat+eq fast path;
// when 2..8 it uses a Shufti-style nibble-table lookup.
//
// The non-mid-accept extension (LNM.md Action 2, archived in
// plans/non_mid_extension.go.archive) added an `isMidAccept bool` field
// to differentiate mid- from non-mid-accept dominants. With non-mid
// emission archived, all entries are mid-accept and the flag is
// unnecessary. Reinstatement must restore the field (Section 3 of the
// archive) along with the filter conditionals in the dispatch loops
// (Sections 7-8).
type dominantInfo struct {
	state     int32  // WASM state ID (> 0)
	exitBytes []byte // 1..8 exit bytes (Shufti cap); mutually exclusive with selfLoopSet
	// selfLoopSet (task 26, plans/TODO.md): 9..64 bytes — the self-loop
	// membership set itself, for states recorded by detectShuftiSelfLoop
	// rather than detectDominantSelfLoop. Used instead of exitBytes when
	// the SELF-LOOP side is the small (≤64, Shufti-cap) side rather than
	// the exit side — e.g. a 62-byte `[a-zA-Z0-9]` self-loop with a huge
	// (194-byte) exit set, which detectDominantSelfLoop's ≤8-exit-byte gate
	// can never reach. emitDominantBulkSkip tests membership in this set
	// directly and inverts the mask (stop at the first byte NOT a member)
	// instead of testing membership in exitBytes directly. Mid-accept by
	// default; LM_TODO.md LM-3 adds a LikelyMatch-gated non-mid-accept
	// channel (see detectShuftiSelfLoop).
	selfLoopSet []byte
	encodedByte byte // the value stored in midAcceptBytes[state] (mid) or nonMidDominantBytes[state] (non-mid)
	isMidAccept bool // true → encodedByte in midAcceptBytes; false → in nonMidDominantBytes
}

// dfaTableBytes returns the upper-bound byte footprint of the runtime transition
// tables for a minimised DFA. Encodings (Option D, always unpacked):
//   - numWASM ≤ 256 : u8  → n*256
//   - numWASM > 256 : u16 → n*512
//
// Used to enforce MaxDFAMemory before committing to a DFA layout.
func dfaTableBytes(t *dfaTable) int {
	n := t.numStates + 1 // +1 for the implicit dead state at index 0
	if n <= 256 {
		return n * 256
	}
	return n * 512
}

// buildDFALayout computes all DFA table data and offsets. needFind must be true
// when a find function will be emitted (computes extra tables for find mode).
// compiledDFAThreshold is the resolved threshold (0 = disabled, 1..256 = active).
// useAcceptSideTable: when true, emit a per-state accept side table at acceptOff
// (used by TDFA, whose state IDs are not partitioned and cannot use acceptLimit).
// forceWordChar (optional): force word-char table computation even when needFind=false.
func buildDFALayout(t *dfaTable, tableBase int64, needFind, leftmostFirst bool, compiledDFAThreshold int, useAcceptSideTable bool, lmBareShufti bool, lmNonMidShufti bool, lmWideShufti bool, forceWordChar ...bool) *dfaLayout {
	wantWordChar := needFind || (len(forceWordChar) > 0 && forceWordChar[0])
	l := &dfaLayout{}
	l.lmBareShufti = lmBareShufti
	l.lmNonMidShufti = lmNonMidShufti
	l.lmWideShufti = lmWideShufti
	l.numWASM = t.numStates + 1
	l.wasmStart = uint32(t.startState + 1)
	// acceptLimit: WASM-state ID K such that "state in [1, K]" iff the DFA state
	// is eof-accepting. Relies on reorderAcceptFirst having placed accepting DFA
	// states at the low end of the ID range. Used to replace the per-cell
	// accept-bit (Option A1/B) with a single state-ID compare in emit code.
	{
		k := 0
		for s := 0; s < t.numStates; s++ {
			if t.acceptStates[s] != 0 {
				k++
			}
		}
		l.acceptLimit = int32(k)
	}
	// Cell encoding (Option D): all cells store the raw destination WASM state
	// as next+1 (zero = dead). The eof-accept partition is encoded in the
	// state-ID ordering itself (reorderAcceptFirst) for DFA-built tables, so
	// the per-byte transition has no shift/tee overhead.
	//
	// TDFA-built tables are not partitioned (state IDs are tied to tag-op
	// indices), so they fall back to a per-state accept side table at
	// l.acceptOff (useAcceptSideTable=true).
	l.useU8 = l.numWASM <= 256
	l.useAcceptSideTable = useAcceptSideTable
	// Byte-class compression applies when the u8 table would exceed 32 KB.
	l.useCompression = l.useU8 && l.numWASM*256 > 32*1024

	// Hybrid dispatch (compiled-DFA chain): active for the u8 path.
	if l.useU8 && compiledDFAThreshold > 0 && l.numWASM <= compiledDFAThreshold {
		l.useHybridDispatch = true
		if !l.useCompression {
			// Pre-compute class info needed by literalChain at Go compile time.
			l.classMap, l.classRep, l.numClasses = computeByteClasses(t)
		}
	}

	// Word char table (find + word boundary, or when forceWordChar is set).
	l.needWordCharTable = wantWordChar && t.hasWordBoundary
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

	// Transition table. Cell encoding (Option D, always unpacked):
	//   u8  (n ≤ 256, no compression):  cell = byte(next+1)
	//   u8  (n ≤ 256, byte-class compressed): cell = byte(next+1) at row*numClasses+class
	//   u16 (n > 256):                  cell = uint16(next+1) (little-endian)
	// Dead transitions store 0.
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

	// Row deduplication for u16 only (compiled dispatch never reaches here).
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
		if len(uniqueRows) < l.numWASM && len(uniqueRows) <= 255 && !l.useHybridDispatch {
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

	// Accept side table.
	//   DFA-built tables: not emitted; accept check uses the state-ID partition
	//     and acceptLimit (one-compare runtime cost).
	//   TDFA-built tables (useAcceptSideTable): one byte per WASM state encoding
	//     acceptance, read at EOF only.
	l.acceptOff = l.tableOff + int32(len(l.tableBytes))
	if l.useAcceptSideTable {
		l.acceptBytes = make([]byte, l.numWASM)
		for gs := 0; gs < t.numStates; gs++ {
			if t.acceptStates[gs] != 0 {
				l.acceptBytes[gs+1] = 1
			}
		}
	}

	// Mid-scan accept flags (first standalone table after transitions+accept).
	l.midAcceptOff = l.acceptOff + int32(len(l.acceptBytes))
	l.midAcceptBytes = make([]byte, l.numWASM)
	for gs, bits := range t.midAcceptStates {
		if bits != 0 {
			l.midAcceptBytes[gs+1] = 1
		}
	}

	// Immediate-accept flags (LeftmostFirst, both match and find).
	//
	// hasImmAccept and immAcceptLimit are runtime-essential (consumed by
	// emitImmAcceptCheck*); they must be set regardless of dispatch path.
	// The immediateAcceptBytes side table is only consulted by TDFA-built
	// tables (useAcceptSideTable=true). For DFA-only patterns the accept
	// check uses the state-ID partition (Option D) and the bytes/offset are
	// never read, so we skip both the allocation and the memory reservation.
	if leftmostFirst && len(t.immediateAcceptStates) > 0 {
		l.hasImmAccept = true
		l.immediateAcceptOff = l.midAcceptOff + int32(l.numWASM)
		k := 0
		if l.useAcceptSideTable {
			l.immediateAcceptBytes = make([]byte, l.numWASM)
			for gs, bits := range t.immediateAcceptStates {
				if bits != 0 {
					l.immediateAcceptBytes[gs+1] = 1
					k++
				}
			}
		} else {
			for _, bits := range t.immediateAcceptStates {
				if bits != 0 {
					k++
				}
			}
		}
		l.immAcceptLimit = int32(k)
	}

	immAcceptSize := int32(0)
	if l.hasImmAccept && l.useAcceptSideTable {
		immAcceptSize = int32(l.numWASM)
	}

	// Word-boundary pre-transition accept flags.
	if wantWordChar && t.hasWordBoundary {
		l.midAcceptNWOff = l.midAcceptOff + int32(l.numWASM) + immAcceptSize
		l.midAcceptWOff = l.midAcceptNWOff + int32(l.numWASM)
		l.midAcceptNWBytes = make([]byte, l.numWASM)
		l.midAcceptWBytes = make([]byte, l.numWASM)
		for gs, bits := range t.midAcceptNWStates {
			if bits != 0 {
				l.midAcceptNWBytes[gs+1] = 1
			}
		}
		for gs, bits := range t.midAcceptWStates {
			if bits != 0 {
				l.midAcceptWBytes[gs+1] = 1
			}
		}
	}
	wbAcceptSize := int32(0)
	if wantWordChar && t.hasWordBoundary {
		wbAcceptSize = int32(l.numWASM) * 2
	}

	// Newline-boundary pre-transition accept flag (find mode only).
	if needFind && t.hasNewlineBoundary {
		l.midAcceptNLOff = l.midAcceptOff + int32(l.numWASM) + immAcceptSize + wbAcceptSize
		l.midAcceptNLBytes = make([]byte, l.numWASM)
		for gs, bits := range t.midAcceptNLStates {
			if bits != 0 {
				l.midAcceptNLBytes[gs+1] = 1
			}
		}
	}
	nlAcceptSize := int32(0)
	if needFind && t.hasNewlineBoundary {
		nlAcceptSize = int32(l.numWASM)
	}

	// Find-mode fast-skip: literal prefix or firstByteFlags + Teddy tables.
	l.prefix = computePrefix(t)
	if needFind && len(l.prefix) == 0 {
		l.firstByteOff = l.midAcceptOff + int32(l.numWASM) + immAcceptSize + wbAcceptSize + nlAcceptSize
		wbAcceptNWMid := t.hasWordBoundary && t.midAcceptNWStates[t.midStartState] != 0
		wbAcceptWMid := t.hasWordBoundary && t.midAcceptWStates[t.midStartState] != 0
		wbAcceptNWStart0 := t.hasWordBoundary && t.midAcceptNWStates[t.startState] != 0
		wbAcceptWStart0 := t.hasWordBoundary && t.midAcceptWStates[t.startState] != 0
		if t.midAcceptStates[t.midStartState] != 0 || t.midAcceptStates[t.startState] != 0 || t.acceptStates[t.startState] != 0 ||
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
				if validCount == 0 || validCount > 64 {
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
						if validCount3 == 0 || validCount3 > 64 {
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

					// Try T3 tables (fourth byte).
					t3Lo := make([]byte, 16)
					t3Hi := make([]byte, 16)
					useFourByte := true
				outerFourByte:
					for i, fb := range l.firstBytes {
						stateAfterFB := t.transitions[t.midStartState*256+int(fb)]
						if stateAfterFB < 0 {
							useFourByte = false
							break
						}
						for b2 := 0; b2 < 256; b2++ {
							stateAfterFB2 := t.transitions[stateAfterFB*256+b2]
							if stateAfterFB2 < 0 {
								continue
							}
							for b3 := 0; b3 < 256; b3++ {
								stateAfterFB3 := t.transitions[stateAfterFB2*256+b3]
								if stateAfterFB3 < 0 {
									continue
								}
								validCount4 := 0
								for b4 := 0; b4 < 256; b4++ {
									if t.transitions[stateAfterFB3*256+b4] >= 0 {
										validCount4++
										t3Lo[b4&0x0F] |= byte(1 << uint(i))
										t3Hi[b4>>4] |= byte(1 << uint(i))
									}
								}
								if validCount4 == 0 || validCount4 > 64 {
									useFourByte = false
									break outerFourByte
								}
							}
						}
					}
					if useFourByte {
						l.teddyT3LoBytes = t3Lo
						l.teddyT3HiBytes = t3Hi
						l.teddyT3LoOff = l.teddyT2HiOff + 16
						l.teddyT3HiOff = l.teddyT3LoOff + 16
					}
				}
			}
		}
	}

	// Find-mode DFA state constants (also needed for word-boundary suffix DFAs).
	if needFind || (wantWordChar && t.hasWordBoundary) {
		l.wasmMidStart = uint32(t.midStartState + 1)
		l.wasmMidStartWord = uint32(t.midStartWordState + 1)
		l.wasmMidStartNewline = uint32(t.midStartNewlineState + 1)
		prefixEndState := t.midStartState
		for _, ch := range l.prefix {
			prefixEndState = t.transitions[prefixEndState*256+int(ch)]
		}
		l.wasmPrefixEnd = uint32(prefixEndState + 1)
		// Compute the equivalent end state when prev byte was a word char
		// (prevWasWord=true). For patterns with a leading `\b`/`\B` the walk
		// from midStartWordState may die early (no valid boundary), giving a
		// different prefixEndState. The find body's prefix-scan shortcut uses
		// this when attempt_start>0 and the previous byte is a word char.
		// t.transitions stores -1 for "no transition" (dead) → WASM state 0.
		if t.hasWordBoundary {
			prefixEndWord := t.midStartWordState
			for _, ch := range l.prefix {
				prefixEndWord = t.transitions[prefixEndWord*256+int(ch)]
				if prefixEndWord < 0 { // dead state — no path through prefix
					break
				}
			}
			l.wasmPrefixEndWord = uint32(prefixEndWord + 1)
		} else {
			l.wasmPrefixEndWord = l.wasmPrefixEnd
		}
		l.startBeginAccept = t.startBeginAccept
	}

	// Compute tableEnd: highest memory address used by any table.
	// DFA paths: no accept side table — accept is encoded via the state-ID partition.
	// TDFA paths: acceptBytes side table (useAcceptSideTable=true) follows transitions.
	// midAccept is the first standalone find-mode table after transitions (and after
	// the optional TDFA acceptBytes table).
	tableEnd := int64(l.midAcceptOff) + int64(l.numWASM)
	maxEnd := func(off int32, size int64) {
		if e := int64(off) + size; e > tableEnd {
			tableEnd = e
		}
	}
	if l.hasImmAccept && l.useAcceptSideTable {
		maxEnd(l.immediateAcceptOff, int64(l.numWASM))
	}
	if l.needWordCharTable {
		maxEnd(l.midAcceptNWOff, int64(l.numWASM))
		maxEnd(l.midAcceptWOff, int64(l.numWASM))
	}
	if needFind {
		maxEnd(l.midAcceptOff, int64(l.numWASM))
		if l.midAcceptNLBytes != nil {
			maxEnd(l.midAcceptNLOff, int64(l.numWASM))
		}
		if len(l.prefix) == 0 {
			maxEnd(l.firstByteOff, 256)
			if len(l.teddyLoBytes) > 0 {
				maxEnd(l.teddyHiOff, 16)
				if len(l.teddyT1LoBytes) > 0 {
					maxEnd(l.teddyT1HiOff, 16)
					if len(l.teddyT2LoBytes) > 0 {
						maxEnd(l.teddyT2HiOff, 16)
						if len(l.teddyT3LoBytes) > 0 {
							maxEnd(l.teddyT3HiOff, 16)
						}
					}
				}
			}
		}
	}
	l.tableEnd = tableEnd

	// Opt 1 — LikelyNoMatch dominant self-loop detection (Phase 1).
	// Detection is unconditional and cheap (one pass over the WASM transition
	// table); emission is gated separately at the call site.
	detectDominantSelfLoop(l)

	// Task 26 — Shufti-membership self-loop detection. Complements the
	// above (states it claims are skipped by detectShuftiSelfLoop); also
	// unconditional and cheap, appends into the same l.dominantStates.
	detectShuftiSelfLoop(l)

	// Task 8 — dead-state skip safety analysis. Sets l.skipSafeOnDead.
	// Only meaningful in find mode (needFind=true); for non-find layouts
	// the value is computed but never read.
	if needFind {
		detectSkipSafeOnDead(l)
		detectEOFSkipSafe(l)
	}

	return l
}

// detectSkipSafeOnDead computes l.skipSafeOnDead via a conservative
// "single-successor self-loop" condition. Task 8's safety argument requires
// that intermediate attempts (starting between attempt_start and the dead
// position) also die at or before the same position. The conservative
// sufficient condition: starting at midStart and consuming any sequence of
// midStart-accepted bytes stays in a single, stable "scanning" state.
//
// Concrete check:
//
//	(a) midStart's accept class is non-empty.
//	(b) For every byte b in midStart's accept class, transition(midStart, b)
//	    is the same state `succ` (or `succ == midStart`).
//	(c) For every byte b in midStart's accept class,
//	    transition(succ, b) == succ — i.e. succ self-loops on the same class.
//	(d) Neither midStart nor succ is mid-accept. (A mid-accept state would
//	    have set last_accept ≥ 0 by the time the dead handler runs, sending
//	    the find body to $found instead of the skip path — but we only
//	    need to verify safety along the path the skip optimization controls,
//	    which is the no-accept-yet path.)
//
// If these hold, intermediate attempts from positions K+1..P-1 follow the
// same trajectory as the original attempt: midStart → succ → succ → ...
// → dead at P. The "skip to P+1" advance is sound.
//
// Patterns this accepts:
//   - `[a-zA-Z]+\d` — letters loop on succ, digit transitions to accept.
//   - `[a-z]+@` — letters loop on succ, '@' transitions to accept.
//   - `\w+;` — word chars loop on succ.
//
// Patterns this rejects (correctly):
//   - `(a.)*$` — midStart on 'a' goes to X; X on 'a' goes back to midStart,
//     not self-loop. Different trajectories from intermediate positions.
//   - `[ab][cd]\d` — succ doesn't self-loop on midStart's accept class;
//     intermediate attempts can reach further than the original.
//   - `abc|d` — midStart accepts 'a' and 'd' but they have different
//     successors, so (b) fails.
//
// The check is intentionally conservative: it's easier to add more patterns
// to the skip-safe set later than to debug a wrong-answer regression.
func detectSkipSafeOnDead(l *dfaLayout) {
	if l.numWASM <= 1 {
		return
	}
	cellsPerState := 256
	if l.useCompression {
		cellsPerState = l.numClasses
	}
	readCell := func(state, idx int) int32 {
		row := state
		if l.useRowDedup {
			row = int(l.rowMapBytes[state])
		}
		off := row*cellsPerState + idx
		if l.useU8 {
			return int32(l.tableBytes[off])
		}
		return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
	}
	transitionOn := func(state int, b int) int32 {
		cell := b
		if l.useCompression {
			cell = int(l.classMap[b])
		}
		return readCell(state, cell)
	}

	midStartIdx := int(l.wasmMidStart)
	if midStartIdx <= 0 || midStartIdx >= l.numWASM {
		return
	}

	// (a) midStart's accept class.
	var midStartAccepts [256]bool
	anyAccept := false
	for b := 0; b < 256; b++ {
		if transitionOn(midStartIdx, b) != 0 {
			midStartAccepts[b] = true
			anyAccept = true
		}
	}
	if !anyAccept {
		return
	}

	// (b) Single successor for every midStart-accepted byte.
	succ := int32(-1)
	for b := 0; b < 256; b++ {
		if !midStartAccepts[b] {
			continue
		}
		t := transitionOn(midStartIdx, b)
		if succ < 0 {
			succ = t
		} else if t != succ {
			return // multiple successors → not stable
		}
	}
	if succ <= 0 || int(succ) >= l.numWASM {
		return
	}

	// (c) succ self-loops on midStart's accept class.
	for b := 0; b < 256; b++ {
		if !midStartAccepts[b] {
			continue
		}
		if transitionOn(int(succ), b) != succ {
			return // not self-loop → not stable
		}
	}

	// (d) Neither midStart nor succ is mid-accept on the path before any
	// match has been recorded.
	if midStartIdx < len(l.midAcceptBytes) && l.midAcceptBytes[midStartIdx] != 0 {
		return
	}
	if int(succ) < len(l.midAcceptBytes) && l.midAcceptBytes[succ] != 0 {
		return
	}

	// (e) For non-class bytes (those midStart REJECTS), both midStart and
	// succ must transition to either dead or a mid-accept state. Any
	// transition into a third scanning (non-mid-accept, non-dead) state
	// means the DFA can leave the "midStart → succ → succ → ..." stable
	// trajectory on a non-class byte and reach an accept later (via EOF or
	// further bytes) at a position the original attempt's trajectory did
	// not visit — breaking the safety invariant. See e.g. `(.+)\n$`, where
	// succ='consuming-non-newline' transitions on '\n' to a non-mid-accept
	// state that later EOF-accepts; attempts starting mid-run can reach
	// that accept while the original attempt died.
	isAcceptingExit := func(target int32) bool {
		if target == 0 {
			return true // dead is fine
		}
		if int(target) < len(l.midAcceptBytes) && l.midAcceptBytes[target] != 0 {
			return true // mid-accept is fine (sets last_accept → $found)
		}
		return false
	}
	for b := 0; b < 256; b++ {
		if midStartAccepts[b] {
			continue
		}
		if !isAcceptingExit(transitionOn(midStartIdx, b)) {
			return
		}
		if !isAcceptingExit(transitionOn(int(succ), b)) {
			return
		}
	}

	l.skipSafeOnDead = true
}

// detectEOFSkipSafe computes l.eofSkipSafe via a conservative multi-hop
// generalisation of detectSkipSafeOnDead's single-hop "stable scanning
// chain" check (Task 8 follow-up #2 — min-length quantifier skip).
//
// detectSkipSafeOnDead proves "positions K+1..P-1 also die at P" when
// midStart's accept class self-loops in a SINGLE hop. Counted quantifiers
// like `[a-z]{50,}[0-9]` don't self-loop in one hop — they walk a chain of
// N distinct "still counting" states before reaching a self-loop-capable
// state, so midStart's own successor (state1's successor on 'a' is state2,
// which doesn't self-loop on 'a') already fails detectSkipSafeOnDead's
// condition (c). That check is about SKIPPING PAST a dead byte, though —
// a different question from this one, which is about what to do when the
// scan runs out of input (EOF) without a dead byte ever appearing.
//
// This function walks the full chain (midStart → state1 → ... → terminal
// self-loop state) and verifies, at every hop, the same three conditions
// detectSkipSafeOnDead verifies for its single hop, plus one more this
// function needs that detectSkipSafeOnDead doesn't (see below):
//   - no chain state — including midStart and the terminal state — is
//     EOF-accepting;
//   - every state's accept class matches the same fixed set C (midStart's),
//     with a single, predictable successor for every byte in C (the next
//     chain hop, or — at the terminal state — itself);
//   - no chain state is mid-accept;
//   - every byte NOT in C, from every chain state, transitions to dead or
//     to a mid-accept state (never to a third, unanalysed scanning state).
//
// Why this makes EOF-without-match safe to terminate immediately: the find
// body's EOF handler only takes the "no match yet" branch when
// last_accept is still < 0, meaning no mid-accept transition has fired
// during this ENTIRE attempt. Given the conditions above, the only way to
// still be on the chain with last_accept < 0 is if every byte consumed
// from attempt_start to EOF belonged to C (any off-class byte would have
// gone to dead — Task 8's existing handler — or to mid-accept, which
// would have set last_accept and taken the $found branch instead). A
// later start position s consumes a suffix of that same homogeneous run,
// follows the identical chain, and also reaches EOF without ever seeing
// an off-class byte — so no later attempt can succeed either. The find
// body can skip straight to $no_match instead of retrying attempt_start
// +1, +2, ... one byte at a time (O(N²) on a homogeneous near-miss run).
//
// Why every chain state (not just the terminal one) must be checked for
// EOF-acceptance: a later start position s doesn't necessarily walk the
// SAME NUMBER of hops before hitting EOF — it has less remaining input,
// so it may reach EOF at an EARLIER point in the chain than the original
// attempt did. For patterns whose EOF-acceptance depends on the exact
// remaining length rather than merely "far enough into the chain" —
// bounded-repeat shapes like `(?:a{3,4})+$`, where whether $ can fire
// depends on whether the remaining length is expressible as a sum of 3s
// and 4s — an intermediate chain state can be EOF-accepting even though
// the terminal self-loop state is not (5 remaining a's fails, but 4
// remaining a's — one hop earlier in the SAME chain — succeeds). The
// original attempt's own EOF-accept check (emitAcceptBitOnStack, which
// runs before this optimization's branch) already covers ITS OWN
// terminating state; this per-hop check exists to protect every OTHER
// attempt this optimization would otherwise skip without ever running.
//
// Conservative bail-outs: word-boundary/newline-boundary patterns are
// excluded outright (their pre-accept side-tables can set last_accept
// without leaving the chain, which this analysis doesn't model). The walk
// also bails on: empty accept class, non-uniform successors, non-trivial
// cycles, mid-accept chain states, any EOF-accepting chain state, or any
// off-class byte leading to a third scanning state. `[a-zA-Z]+\d` (chain
// length 1) and `[a-z]{50,}[0-9]` (chain length 50) both qualify;
// alternations, patterns with multiple distinct first-byte successors,
// and bounded-repeat-group patterns like `(?:a{3,4})+$` do not.
func detectEOFSkipSafe(l *dfaLayout) {
	if l.numWASM <= 1 {
		return
	}
	if l.needWordCharTable || l.midAcceptNLBytes != nil {
		return
	}
	cellsPerState := 256
	if l.useCompression {
		cellsPerState = l.numClasses
	}
	readCell := func(state, idx int) int32 {
		row := state
		if l.useRowDedup {
			row = int(l.rowMapBytes[state])
		}
		off := row*cellsPerState + idx
		if l.useU8 {
			return int32(l.tableBytes[off])
		}
		return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
	}
	transitionOn := func(state int, b int) int32 {
		cell := b
		if l.useCompression {
			cell = int(l.classMap[b])
		}
		return readCell(state, cell)
	}
	isMidAccept := func(state int) bool {
		return state < len(l.midAcceptBytes) && l.midAcceptBytes[state] != 0
	}
	isAcceptingExit := func(target int32) bool {
		if target == 0 {
			return true // dead is fine
		}
		return isMidAccept(int(target)) // mid-accept is fine (sets last_accept → $found)
	}
	// isEofAccept mirrors emitAcceptBitOnStack's (state-1) u< acceptLimit
	// check: true when reaching EOF in this state alone (no mid-accept
	// ever recorded) still succeeds.
	isEofAccept := func(state int) bool {
		return state-1 < int(l.acceptLimit)
	}

	midStartIdx := int(l.wasmMidStart)
	if midStartIdx <= 0 || midStartIdx >= l.numWASM {
		return
	}
	if isMidAccept(midStartIdx) {
		return
	}

	// Class C: bytes midStart accepts (non-dead transition).
	var classC [256]bool
	anyAccept := false
	for b := 0; b < 256; b++ {
		if transitionOn(midStartIdx, b) != 0 {
			classC[b] = true
			anyAccept = true
		}
	}
	if !anyAccept {
		return
	}

	visited := map[int]bool{midStartIdx: true}
	cur := midStartIdx
	for steps := 0; steps <= l.numWASM; steps++ {
		// No chain state may be EOF-accepting. Every later start position
		// restarts fresh at midStart and re-walks this SAME chain, but the
		// LENGTH of its own remaining input may put it at a DIFFERENT
		// chain state when it reaches EOF (e.g. bounded-repeat patterns
		// like `(a{3,4})+$`, where whether $ can fire at EOF depends on
		// the exact remaining length, not just "far enough into the
		// chain"). If any state along the chain — not just midStart — can
		// accept at EOF, a later attempt reaching exactly that state must
		// still be allowed to run; bail rather than risk skipping it.
		if isEofAccept(cur) {
			return
		}

		// Uniform successor for every C byte.
		succ := int32(-1)
		for b := 0; b < 256; b++ {
			if !classC[b] {
				continue
			}
			t := transitionOn(cur, b)
			if succ < 0 {
				succ = t
			} else if t != succ {
				return // non-uniform successor → chain doesn't hold
			}
		}
		if succ <= 0 || int(succ) >= l.numWASM {
			return
		}

		// Off-class bytes must be dead or mid-accept — never a third state.
		for b := 0; b < 256; b++ {
			if classC[b] {
				continue
			}
			if !isAcceptingExit(transitionOn(cur, b)) {
				return
			}
		}

		if int(succ) == cur {
			l.eofSkipSafe = true // terminal self-loop state found
			return
		}
		if visited[int(succ)] {
			return // non-trivial cycle, unsupported
		}
		if isMidAccept(int(succ)) {
			return
		}
		visited[int(succ)] = true
		cur = int(succ)
	}
}

// detectDominantSelfLoop scans the WASM-space transition table for states
// whose byte-class transitions self-loop on ≥ 240/256 bytes. Records each
// qualifying state in `l.dominantStates` and encodes its slice index in
// `l.midAcceptBytes[state]` as `byte(2 + idx)` so the find-body emitter
// can dispatch via the already-loaded midAccept value.
//
// Phase 2 emission constraints applied at detection time:
//   - exit set must be exactly 1 byte (Phase 5 will lift to ≤ 16 via nibble);
//   - state must be mid-accepting (every byte while in it is a valid
//     match end — required by the bulk-skip's `last_accept = pos + 1`).
//
// Non-eligible states (multi-byte exit, non-mid-accept) keep their
// existing midAccept value (1 if accepting, 0 otherwise) and are not
// added to the slice. Detection caps at `maxDominantStates` per DFA.
func detectDominantSelfLoop(l *dfaLayout) {
	const threshold = 240
	const maxExitBytes = 8 // Shufti nibble-lookup cap (Phase 5)

	if l.numWASM <= 1 {
		return
	}

	// Cell width and stride.
	cellsPerState := 256
	if l.useCompression {
		cellsPerState = l.numClasses
	}

	// Byte count per class (needed when compression is on; otherwise 1:1).
	var classByteCount [256]int
	if l.useCompression {
		for b := 0; b < 256; b++ {
			classByteCount[l.classMap[b]]++
		}
	}

	// Reader for the table cell (u8 or u16) at a given (state, classOrByte).
	readCell := func(state, idx int) int32 {
		// When row dedup is on, map state → row index first.
		row := state
		if l.useRowDedup {
			row = int(l.rowMapBytes[state])
		}
		off := row*cellsPerState + idx
		if l.useU8 {
			return int32(l.tableBytes[off])
		}
		// u16, little-endian.
		return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
	}

	for state := int32(1); state < int32(l.numWASM); state++ {
		selfBytes := 0
		var exitBytes []byte
		hitCap := false
		for c := 0; c < cellsPerState; c++ {
			next := readCell(int(state), c)
			bytesInClass := 1
			if l.useCompression {
				bytesInClass = classByteCount[c]
			}
			if next == state {
				selfBytes += bytesInClass
			} else {
				if l.useCompression {
					for b := 0; b < 256; b++ {
						if int(l.classMap[b]) == c {
							exitBytes = append(exitBytes, byte(b))
							if len(exitBytes) > maxExitBytes {
								hitCap = true
								break
							}
						}
					}
					if hitCap {
						break
					}
				} else {
					exitBytes = append(exitBytes, byte(c))
					if len(exitBytes) > maxExitBytes {
						hitCap = true
						break
					}
				}
			}
		}
		if selfBytes < threshold || hitCap {
			continue
		}
		// Phase 5: 1..8 exit bytes (Shufti cap). The maxExitBytes loop
		// guard ensures we never reach here with more.
		if len(exitBytes) < 1 || len(exitBytes) > maxExitBytes {
			continue
		}
		// Dual-channel detection: accept BOTH mid-accept and non-mid-accept
		// dominants. The encoding pass (applyDominantStateEncoding) writes
		// each into its appropriate channel (midAcceptBytes piggyback for
		// mid; nonMidDominantBytes side table for non-mid).
		if int(state) >= len(l.midAcceptBytes) {
			continue
		}
		isMidAccept := l.midAcceptBytes[state] != 0
		sort.Slice(exitBytes, func(i, j int) bool { return exitBytes[i] < exitBytes[j] })
		l.dominantStates = append(l.dominantStates, dominantInfo{
			state:       state,
			exitBytes:   exitBytes,
			isMidAccept: isMidAccept,
		})
	}

	// Dual-channel encoding pass. All channels share the single
	// midAcceptBytes value space (task 38 v2):
	//   0         — nothing
	//   1         — plain mid-accept (no dominant)
	//   2..127    — mid-accept dominant idx (this pass)
	//   128..253  — Shufti self-loop idx (detectShuftiSelfLoop, mid-only)
	//   254..255  — NON-mid-accept dominant idx (this pass; cap 2)
	// Non-mid entries are written into the table only by
	// applyDominantStateEncoding(l, true) — call sites whose emitted body
	// decodes the `>= 254` sub-range (buildFindBody, emitPhase4Dispatch).
	// Everywhere else (sets suffix, lit-anchor forward scan, alt-lit
	// branches) passes false and keeps state-ID-compare dispatch, so their
	// plain `midAccept[state] != 0 → accept` reads stay correct.
	const maxMid = 126
	const maxNonMid = 2
	midIdx, nonMidIdx := 0, 0
	out := l.dominantStates[:0]
	for _, info := range l.dominantStates {
		if info.isMidAccept {
			if midIdx >= maxMid {
				continue
			}
			info.encodedByte = byte(2 + midIdx)
			midIdx++
		} else {
			if nonMidIdx >= maxNonMid {
				continue
			}
			info.encodedByte = byte(254 + nonMidIdx)
			nonMidIdx++
		}
		out = append(out, info)
	}
	l.dominantStates = out
}

// detectShuftiSelfLoop (task 26, plans/TODO.md) scans the WASM-space
// transition table for mid-accept states whose self-loop set is 9..64
// bytes — below detectDominantSelfLoop's 240-byte/≤8-exit-byte gate (which
// requires the EXIT set to be the small side), but within
// emitShuftiPrefixCheck's ≤64-byte Shufti membership cap on the SELF-LOOP
// set directly. Complements detectDominantSelfLoop rather than overlapping
// it: states it already claimed are skipped, and matches are appended
// directly into l.dominantStates using the same dominantInfo type (with
// selfLoopSet set instead of exitBytes), so every existing consumer of
// l.dominantStates (buildMatchBody, buildFindBody, buildLitAnchorFindBody,
// genSuffixWASM, alt_lit_anchor.go) picks these up for free via
// emitDominantBulkSkip's selfLoopSet branch — no separate dispatch wiring
// needed.
//
// v1 scope: mid-accept only (reuses the same midAcceptBytes piggyback as
// detectDominantSelfLoop's mid channel; every state this project's Task 20
// audit identified as a motivating case — e.g. `ID:[a-zA-Z0-9]{10,}`'s
// self-loop state — is mid-accept).
//
// LM_TODO.md LM-3 adds a non-mid-accept channel (delimited bodies whose
// loop state cannot accept until a mandatory trailing literal/class arrives,
// e.g. `KEY=[a-z0-9/+]+;`), gated on l.lmNonMidShufti (set from
// buildOpts.LikelyMode == LikelyMatch at the match/find DFA layout call
// sites). Non-mid entries piggyback on detectDominantSelfLoop's own 254/255
// reserved-value non-mid channel (see applyDominantStateEncoding's doc
// comment) rather than the mid-accept 128..253 sub-range, so they share that
// channel's hard cap of 2 total non-mid entries per DFA — detection here
// continues the index from however many detectDominantSelfLoop already
// claimed (it always runs first; see buildDFALayout).
//
// Encoding: midAcceptBytes[state] = 128 + idx, a third sub-range alongside
// detectDominantSelfLoop's own 2..127 (mid dominants) — 0 = nothing,
// 1 = plain mid-accept, 2..127 = exit-based dominant idx, 128..253 = Shufti
// self-loop idx, 254..255 = non-mid dominant (exit-based OR, under LM-3,
// Shufti self-loop). Mid channel capped at 126 entries, matching the
// existing per-kind cap; non-mid channel capped at 2 (shared with
// detectDominantSelfLoop, task 38's encoding constraint).
//
// Task 34 (plans/TODO.md): gated on len(l.prefix) > 0 — the same
// computePrefix-derived signal buildFindBody already uses to decide between
// the literal-chain Teddy scan and the broader firstByteFlags scan. A
// non-empty l.prefix means this DFA is only entered (in the byte-by-byte
// sense that matters for this state) after a Teddy/literal front-end has
// already consumed a required byte chain — the "genuinely post-literal-
// anchor" scope this optimisation was designed for (motivating case
// `ID:[a-zA-Z0-9]{10,}`, l.prefix = "ID:"). An empty l.prefix means the
// pattern has no literal gate at all, so any wide self-loop state is
// reachable directly from a scan restart — bare, high-frequency entry,
// where the fixed SIMD chunk-scan overhead costs more than the scalar loop
// it replaces (measured: `shufti-upper-find-100kb`, bare `[A-Z]{8,}`, -49%
// wall time vs main before this gate).
//
// LM_TODO.md LM-4: task 34's own investigation found the regression that
// motivated this gate was actually caused by patternMinLen (removed in
// task 37), not by this detector — the gate itself "did not recover the
// case at all". Under LikelyMatch (l.lmBareShufti), the bail is lifted:
// dense/long-run match input is exactly what LM promises to bias for, and
// task 38's hysteresis (shared by every l.dominantStates consumer) bounds
// the damage if a run turns out short.
//
// l.lmBareShufti is only set true (see lmBareShuftiEligible) when the
// pattern additionally has a compile-time-guaranteed minimum match length
// — `[A-Z]{8,}` (min 8) measured a clean -39% dense-match fuel win, but
// `(\w+)` (min 1, no lower bound at all) measured a +7% dense-match fuel
// REGRESSION: the fixed SIMD chunk-scan setup this lifts costs more than
// it saves when the typical match is a handful of bytes, exactly the
// frequency argument the original (pre-LM-4) gate's doc comment made.
// minLMBareShuftiLen draws the line between those two measured outcomes.
func detectShuftiSelfLoop(l *dfaLayout) {
	const minWidth = 9
	const maxWidth = 64
	const maxWidthLM = 239 // LM_TODO.md LM-5, gated on l.lmWideShufti
	const maxStates = 126
	const maxNonMid = 2 // shared 254/255 encoding space with detectDominantSelfLoop

	width := maxWidth
	if l.lmWideShufti {
		width = maxWidthLM
	}

	if l.numWASM <= 1 {
		return
	}
	if len(l.prefix) == 0 && !l.lmBareShufti {
		return
	}

	already := make(map[int32]bool, len(l.dominantStates))
	nonMidIdx := 0
	for _, info := range l.dominantStates {
		already[info.state] = true
		if !info.isMidAccept {
			nonMidIdx++
		}
	}

	cellsPerState := 256
	if l.useCompression {
		cellsPerState = l.numClasses
	}
	var classByteCount [256]int
	if l.useCompression {
		for b := 0; b < 256; b++ {
			classByteCount[l.classMap[b]]++
		}
	}
	readCell := func(state, idx int) int32 {
		row := state
		if l.useRowDedup {
			row = int(l.rowMapBytes[state])
		}
		off := row*cellsPerState + idx
		if l.useU8 {
			return int32(l.tableBytes[off])
		}
		return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
	}

	idx := 0
	for state := int32(1); state < int32(l.numWASM); state++ {
		if already[state] {
			continue
		}
		isMid := int(state) < len(l.midAcceptBytes) && l.midAcceptBytes[state] != 0
		if !isMid {
			// LM-3: non-mid-accept channel, LikelyMatch-gated, shares the
			// 254/255 encoding space with detectDominantSelfLoop's non-mid
			// entries.
			if !l.lmNonMidShufti || nonMidIdx >= maxNonMid {
				continue
			}
		}
		var selfSet []byte
		for c := 0; c < cellsPerState; c++ {
			if readCell(int(state), c) != state {
				continue
			}
			if l.useCompression {
				for b := 0; b < 256; b++ {
					if int(l.classMap[b]) == c {
						selfSet = append(selfSet, byte(b))
					}
				}
			} else {
				selfSet = append(selfSet, byte(c))
			}
		}
		if len(selfSet) < minWidth || len(selfSet) > width {
			continue
		}
		sort.Slice(selfSet, func(i, j int) bool { return selfSet[i] < selfSet[j] })
		if isMid {
			if idx >= maxStates {
				continue
			}
			l.dominantStates = append(l.dominantStates, dominantInfo{
				state:       state,
				selfLoopSet: selfSet,
				encodedByte: byte(128 + idx),
				isMidAccept: true,
			})
			idx++
		} else {
			l.dominantStates = append(l.dominantStates, dominantInfo{
				state:       state,
				selfLoopSet: selfSet,
				encodedByte: byte(254 + nonMidIdx),
				isMidAccept: false,
			})
			nonMidIdx++
		}
	}
}

// minLMBareShuftiLen is the compile-time-guaranteed minimum match length
// (regexpMinMaxLen) required before lmBareShuftiEligible allows LM-4's
// bare-prefix gate to lift. See detectShuftiSelfLoop's doc comment for the
// measurements behind this threshold: 8 keeps the confirmed win
// (`[A-Z]{8,}`, min 8) while excluding the confirmed regression
// (`(\w+)`, min 1).
const minLMBareShuftiLen = 8

// lmBareShuftiEligible reports whether pattern has a compile-time-guaranteed
// minimum match length of at least minLMBareShuftiLen bytes — the
// additional per-pattern check gating l.lmBareShufti (LM_TODO.md LM-4)
// beyond LikelyMode alone. An unparseable pattern is conservatively
// ineligible (this recomputes syntax.Parse; compilePattern's caller has
// already validated the pattern earlier in the pipeline, so failure here
// should not happen in practice).
func lmBareShuftiEligible(pattern string) bool {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	minLen, _ := regexpMinMaxLen(parsed)
	return minLen >= minLMBareShuftiLen
}

// applyDominantStateEncoding writes each mid-accept dominantInfo's encoded
// byte into l.midAcceptBytes (the find-body hot loop reads this for the
// last_accept update and dispatches via the cached value).
//
// encodeNonMid (task 38 v2) additionally writes non-mid-accept dominants
// as reserved values 254..255 into the SAME table, so the non-mid dispatch
// can piggyback on the midAccept[state] load the scan loop already
// performs every byte — eliminating the per-scanned-byte `state == K`
// compare chain that was measured as the dominant fuel cost of the
// old state-ID-compare emission (perftest html-tags: the compare alone
// was +5,470 fuel on input whose dominant state is never entered).
//
// Pass encodeNonMid=true ONLY when every emitted body that reads this
// layout's midAcceptBytes decodes the `>= 254` sub-range (buildFindBody,
// buildMatchBody/buildHybridMatchBody via emitPhase4Dispatch). Sites whose
// bodies do a plain `midAccept[state] != 0 → accept` (sets suffix,
// lit-anchor forward scan, alt-lit branches) MUST pass false — their
// non-mid dispatch stays on state-ID compares and a 254 value in the
// table would corrupt their accept tracking.
func applyDominantStateEncoding(l *dfaLayout, encodeNonMid bool) {
	for _, info := range l.dominantStates {
		if int(info.state) >= len(l.midAcceptBytes) {
			continue
		}
		if info.isMidAccept || encodeNonMid {
			l.midAcceptBytes[info.state] = info.encodedByte
		}
	}
}

// dfaDataSegments builds the raw data-section payload (count byte + segments)
// for a DFA layout. needFind controls whether find-mode-only tables are emitted.
func dfaDataSegments(l *dfaLayout, needFind bool) []byte {
	// DFA paths (useAcceptSideTable=false): no accept side table; acceptLimit
	// partitions state IDs so the runtime check is `(state-1) u< acceptLimit`.
	// TDFA path (useAcceptSideTable=true): state IDs are not partitioned, so a
	// per-state side table is emitted at acceptOff and read at EOF.
	emitFindSegs := func(ds, transSegs []byte) []byte {
		if l.needWordCharTable {
			ds = appendDataSegment(ds, l.wordCharTableOff, l.wordCharTableBytes[:])
		}
		ds = append(ds, transSegs...)
		if l.useAcceptSideTable {
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
		}
		ds = appendDataSegment(ds, l.midAcceptOff, l.midAcceptBytes)
		if l.hasImmAccept && l.useAcceptSideTable {
			ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
		}
		if l.needWordCharTable {
			ds = appendDataSegment(ds, l.midAcceptNWOff, l.midAcceptNWBytes)
			ds = appendDataSegment(ds, l.midAcceptWOff, l.midAcceptWBytes)
		}
		if l.midAcceptNLBytes != nil {
			ds = appendDataSegment(ds, l.midAcceptNLOff, l.midAcceptNLBytes)
		}
		return ds
	}
	findSegCount := func(base int) byte {
		n := byte(base)
		if l.hasImmAccept && l.useAcceptSideTable {
			n++
		}
		if l.needWordCharTable {
			n += 3
		}
		if l.midAcceptNLBytes != nil {
			n++
		}
		if l.useRowDedup {
			n++
		}
		if l.useAcceptSideTable {
			n++ // accept side table (TDFA only)
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
				if len(l.teddyT3LoBytes) > 0 {
					teddyExtraSegs = 8
				}
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
				ds = append(ds, findSegCount(4)+teddyExtraSegs) // classMap+table+midAccept+firstByte
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
							if len(l.teddyT3LoBytes) > 0 {
								ds = appendDataSegment(ds, l.teddyT3LoOff, l.teddyT3LoBytes)
								ds = appendDataSegment(ds, l.teddyT3HiOff, l.teddyT3HiBytes)
							}
						}
					}
				}
			} else {
				ds = append(ds, findSegCount(3)) // classMap+table+midAccept (prefix path)
				ds = emitFindSegs(ds, transSegs)
			}
		} else {
			// Non-find path: transitions + (optional) midAccept for Phase 4
			// match-body bulk-skip dispatch + TDFA accept tables. The non-mid
			// channel uses state-ID compares (no side table) so no extra
			// emission is needed here.
			emitMidAccept := len(l.dominantStates) > 0
			count := byte(2) // classMap + transitions
			if emitMidAccept {
				count++
			}
			if l.hasImmAccept && l.useAcceptSideTable {
				count++
			}
			if l.useAcceptSideTable {
				count++ // accept side table (TDFA only)
			}
			if l.useRowDedup {
				count++
			}
			if l.needWordCharTable {
				count += 3 // wordCharTable + midAcceptNW + midAcceptW
			}
			ds = append(ds, count)
			if l.needWordCharTable {
				ds = appendDataSegment(ds, l.wordCharTableOff, l.wordCharTableBytes[:])
			}
			ds = appendDataSegment(ds, l.classMapOff, l.classMap[:])
			if l.useRowDedup {
				ds = appendDataSegment(ds, l.rowMapOff, l.rowMapBytes)
			}
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			if l.useAcceptSideTable {
				ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			}
			if emitMidAccept {
				ds = appendDataSegment(ds, l.midAcceptOff, l.midAcceptBytes)
			}
			if l.hasImmAccept && l.useAcceptSideTable {
				ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
			}
			if l.needWordCharTable {
				ds = appendDataSegment(ds, l.midAcceptNWOff, l.midAcceptNWBytes)
				ds = appendDataSegment(ds, l.midAcceptWOff, l.midAcceptWBytes)
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
				ds = append(ds, findSegCount(3)+teddyExtraSegs) // table+midAccept+firstByte
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
							if len(l.teddyT3LoBytes) > 0 {
								ds = appendDataSegment(ds, l.teddyT3LoOff, l.teddyT3LoBytes)
								ds = appendDataSegment(ds, l.teddyT3HiOff, l.teddyT3HiBytes)
							}
						}
					}
				}
			} else {
				ds = append(ds, findSegCount(2)) // table+midAccept (prefix path)
				ds = emitFindSegs(ds, transSegs)
			}
		} else {
			// Non-find path: transitions + (optional) midAccept for Phase 4
			// match-body bulk-skip + (optional) nonMidDominantBytes for the
			// LM-gated non-mid match-body dispatch + TDFA accept tables.
			emitMidAccept := len(l.dominantStates) > 0
			count := byte(1) // transitions
			if emitMidAccept {
				count++
			}
			if l.useAcceptSideTable {
				count++ // accept side table
			}
			if l.hasImmAccept && l.useAcceptSideTable {
				count++
			}
			if l.useRowDedup {
				count++
			}
			if l.needWordCharTable {
				count += 3 // wordCharTable + midAcceptNW + midAcceptW
			}
			ds = append(ds, count)
			if l.needWordCharTable {
				ds = appendDataSegment(ds, l.wordCharTableOff, l.wordCharTableBytes[:])
			}
			if l.useRowDedup {
				ds = appendDataSegment(ds, l.rowMapOff, l.rowMapBytes)
			}
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			if l.useAcceptSideTable {
				ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			}
			if emitMidAccept {
				ds = appendDataSegment(ds, l.midAcceptOff, l.midAcceptBytes)
			}
			if l.hasImmAccept && l.useAcceptSideTable {
				ds = appendDataSegment(ds, l.immediateAcceptOff, l.immediateAcceptBytes)
			}
			if l.needWordCharTable {
				ds = appendDataSegment(ds, l.midAcceptNWOff, l.midAcceptNWBytes)
				ds = appendDataSegment(ds, l.midAcceptWOff, l.midAcceptWBytes)
			}
		}
	}
	return ds
}

// genSuffixWASM generates a size-prefixed WASM function body and data segments
// for a set suffix DFA that writes match tuples directly to the caller's output buffer.
//
// Function signature: (ptr i32, start i32, len i32, lPos i32, out_ptr i32, out_cap i32) → i32
//
// For each matching pattern k, writes a (patternID, matchStart, matchLength) tuple
// to out_ptr[outCount*12] and returns the total count written.  All patterns are
// handled independently: fixed-length patterns write on immediateAccept, greedy
// patterns write after the scan ends.  This eliminates shared-endPos contamination.
//
// Three 8-byte-per-state bitmask tables are stored at tableBase:
//
//	midBitmask: midAcceptStates — any-position accept
//	eofBitmask: acceptStates   — end-of-input accept ($ anchors)
//	immBitmask: immediateAcceptStates — leftmost-first stop per pattern
//
// patternIDs[k] is the global pattern ID written into the output tuple for bit k.
// tableBase is the memory address at which this DFA's data will be placed.
// tableMemIdx is 0 for standalone modules (single memory).
func genSuffixWASM(t *dfaTable, tableBase int64, tableMemIdx int, patternIDs, prefixFixedLens []int) (funcBody []byte, dataBytes []byte, dataSegCount int, nextTableOffset int32) {
	nextTableOffset = int32(tableBase)
	if t == nil || t.numStates == 0 {
		// Empty DFA: return 0 (no matches).
		body := []byte{0x01, 0x01, 0x7F} // 1 local i32
		body = append(body, 0x41, 0x00)  // i32.const 0
		body = append(body, 0x0B)        // end
		funcBody = utils.AppendULEB128(nil, uint32(len(body)))
		funcBody = append(funcBody, body...)
		return
	}

	// Task 5 (LIKELY.md opt 2 / Hyperscan "SoME"): a pure counted linear
	// class chain doesn't need a DFA table walk at all — verify the whole
	// suffix via SIMD in one shot. Scoped to single-pattern buckets for now
	// (see isCountedClassChain's doc comment).
	if len(patternIDs) == 1 {
		if class, n, ok := isCountedClassChain(t); ok {
			prefixMaxLen := 0
			if len(prefixFixedLens) == 1 {
				prefixMaxLen = prefixFixedLens[0]
			}
			body := buildCountedChainSuffixBody(class, n, patternIDs[0], prefixMaxLen)
			funcBody = utils.AppendULEB128(nil, uint32(len(body)))
			funcBody = append(funcBody, body...)
			return funcBody, nil, 0, int32(tableBase)
		}
	}

	l := buildDFALayout(t, tableBase, false, true, 0, false, false, false, false, t.hasWordBoundary)

	// LIKELY.md Gap H.2: both mid-accept and non-mid-accept dominants are
	// always kept for the buildSetSuffixBody bulk-skip dispatch (default-on
	// for every LikelyMode — task 7 step 1 precedent for mid-accept; task 27
	// promoted non-mid-accept to the same default-on treatment, 2026-07-19,
	// after fuel-verifying it's a pure win with zero regressions across
	// single- and multi-pattern buckets, and re2test-verifying full
	// exhaustive-corpus correctness under the two modes this newly
	// exercises. No LikelyMode filtering needed — detectDominantSelfLoop
	// already ran inside buildDFALayout above and recorded everything we
	// use here as-is.
	//
	// encodeNonMid=false: buildSetSuffixBody dispatches non-mid via
	// state-ID compares and reads midAccept[state] with plain `!= 0`
	// accept semantics — reserved 254+ values would corrupt it (sets stay
	// on the state-ID-compare shape task 38's 254+ encoding never touched).
	applyDominantStateEncoding(l, false)

	// Four 8-byte-per-state bitmask tables placed after all layout data.
	midBitmaskOff := int32(l.tableEnd)
	eofBitmaskOff := midBitmaskOff + int32(l.numWASM)*8
	immBitmaskOff := eofBitmaskOff + int32(l.numWASM)*8
	eofMidBitmaskOff := immBitmaskOff + int32(l.numWASM)*8

	writeBitmask := func(m map[int]uint64) []byte {
		bs := make([]byte, l.numWASM*8)
		for gs, bits := range m {
			if bits != 0 {
				off := (gs + 1) * 8
				for i := 0; i < 8; i++ {
					bs[off+i] = byte(bits >> uint(i*8))
				}
			}
		}
		return bs
	}

	// eofMidBitmask: like eofBitmask but with ecEnd-only acceptance at startState.
	// Used when paramLPos != 0 (not at text start) to avoid false accepts for
	// patterns like \z^ whose startState acceptance includes ecBegin.
	writeMidEofBitmask := func() []byte {
		bs := writeBitmask(t.acceptStates)
		startOff := (t.startState + 1) * 8
		if startOff >= 0 && startOff+8 <= len(bs) {
			v := t.startAcceptEnd
			for i := 0; i < 8; i++ {
				bs[startOff+i] = byte(v >> uint(i*8))
			}
		}
		return bs
	}

	// Word-boundary bitmask tables (8 bytes per state, per-pattern bitmasks).
	// Only present when t.hasWordBoundary; placed after the standard 4 bitmask tables.
	wbNWBitmaskOff := eofMidBitmaskOff + int32(l.numWASM)*8
	wbWBitmaskOff := wbNWBitmaskOff + int32(l.numWASM)*8

	layoutRaw, layoutCount := stripSegCount(dfaDataSegments(l, false))
	dataBytes = append(dataBytes, layoutRaw...)
	dataBytes = append(dataBytes, appendDataSegment(nil, midBitmaskOff, writeBitmask(t.midAcceptStates))...)
	dataBytes = append(dataBytes, appendDataSegment(nil, eofBitmaskOff, writeBitmask(t.acceptStates))...)
	dataBytes = append(dataBytes, appendDataSegment(nil, immBitmaskOff, writeBitmask(t.immediateAcceptStates))...)
	dataBytes = append(dataBytes, appendDataSegment(nil, eofMidBitmaskOff, writeMidEofBitmask())...)
	dataSegCount = layoutCount + 4
	nextTableOffset = eofMidBitmaskOff + int32(l.numWASM)*8
	if t.hasWordBoundary {
		dataBytes = append(dataBytes, appendDataSegment(nil, wbNWBitmaskOff, writeBitmask(t.midAcceptNWStates))...)
		dataBytes = append(dataBytes, appendDataSegment(nil, wbWBitmaskOff, writeBitmask(t.midAcceptWStates))...)
		dataSegCount += 2
		nextTableOffset = wbWBitmaskOff + int32(l.numWASM)*8
	}

	// Use wasmStart for lPos==0 (allows ^ anchors to fire), wasmMidStart otherwise.
	wasmMidStart := uint32(t.midStartState + 1)
	wasmStart := uint32(t.startState + 1)
	body := buildSetSuffixBody(l, midBitmaskOff, eofBitmaskOff, eofMidBitmaskOff, immBitmaskOff, wasmStart, wasmMidStart, patternIDs, prefixFixedLens, tableMemIdx,
		l.wordCharTableOff, wbNWBitmaskOff, wbWBitmaskOff)
	funcBody = utils.AppendULEB128(nil, uint32(len(body)))
	funcBody = append(funcBody, body...)
	return
}

// buildSetSuffixBody generates the WASM function body for per-pattern set suffix scanning.
// Signature: (ptr i32, start i32, len i32, lPos i32, out_ptr i32, out_cap i32, validMask i32) → i32
//
// validMask: bitmask of patterns whose prefix check passed. Only bits set here can produce output.
// Writes (patternID, matchStart, matchLength) tuples directly to the output buffer.
// Returns the count written.
//
// Uses per-pattern endPos tracking to eliminate shared-endPos contamination.
func buildSetSuffixBody(l *dfaLayout, midBitmaskOff, eofBitmaskOff, eofMidBitmaskOff, immBitmaskOff int32, wasmStart, wasmMidStart uint32, patternIDs, prefixFixedLens []int, tableMemIdx int, wordCharOff ...int32) []byte {
	hasWordChar := len(wordCharOff) == 3 && l.needWordCharTable
	n := len(patternIDs)
	if n > 32 {
		n = 32
	}

	// Param indices 0..6; local indices start at 7.
	const (
		paramPtr       = byte(0)
		paramStart     = byte(1)
		paramLen       = byte(2)
		paramLPos      = byte(3)
		paramOutPtr    = byte(4)
		paramOutCap    = byte(5)
		paramValidMask = byte(6) // bitmask of patterns that passed prefix check
		// Fixed i32 locals: 7..13
		lState       = byte(7)
		lScanPos     = byte(8)
		lByteClass   = byte(9)
		lDoneMask    = byte(10)
		lOutCount    = byte(11)
		lBitsScratch = byte(12) // i32: low32 of bitmask
		lOutBase     = byte(13) // i32: output tuple base ptr
	)
	// Per-pattern endPos locals: 14..14+n-1 (i32 each)
	// i64 locals after: 14+n, 14+n+1, 14+n+2
	endPosBase := byte(14)
	endPosK := func(k int) byte { return endPosBase + byte(k) }
	lBits := byte(14 + n)
	lResult := byte(15 + n)
	lStartResult := byte(16 + n)
	// Bulk-skip chunk local (v128); only declared when dominants exist.
	lBulkChunk := byte(17 + n)
	haveDominants := len(l.dominantStates) > 0

	var b []byte
	// Local declaration: (7 + n) × i32, 3 × i64, optionally 1 × v128.
	if haveDominants {
		b = append(b, 0x03) // 3 groups
	} else {
		b = append(b, 0x02) // 2 groups
	}
	b = utils.AppendULEB128(b, uint32(7+n))
	b = append(b, 0x7F)       // i32
	b = append(b, 0x03, 0x7E) // 3 × i64
	if haveDominants {
		b = append(b, 0x01, 0x7B) // 1 × v128
	}

	// Initial state: wasmStart when lPos==0; for word-boundary DFAs also select
	// wasmMidStartWord when the previous byte was a word char.
	b = append(b, 0x20, paramLPos)
	b = append(b, 0x45)       // i32.eqz (lPos == 0)
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(wasmStart))
	b = append(b, 0x05) // else: paramLPos != 0
	if hasWordChar {
		// prevWasWord = wordChar[input[paramPtr + paramLPos - 1]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wordCharOff[0])
		b = append(b, 0x20, paramPtr, 0x20, paramLPos, 0x41, 0x01, 0x6B, 0x6A) // paramPtr + paramLPos - 1
		b = appendTableLoad8u(b, tableMemIdx)                                  // input[prev]
		b = append(b, 0x6A)                                                    // wordCharOff + input[prev]
		b = appendTableLoad8u(b, tableMemIdx)                                  // wordChar[prev]
		b = append(b, 0x04, 0x7F)                                              // if prevWasWord (result i32)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.wasmMidStartWord))
		b = append(b, 0x05)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wasmMidStart))
		b = append(b, 0x0B) // end inner if
	} else {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wasmMidStart))
	}
	b = append(b, 0x0B) // end outer if → i32 on stack
	b = append(b, 0x21, lState)
	b = append(b, 0x20, paramStart, 0x21, lScanPos)

	// emitWBPreAcceptCheck emits the word-boundary pre-transition bitmask check.
	// Reads current byte, selects wbWBitmask or wbNWBitmask, ORs into lResult, updates endPos_k.
	emitWBCheck := func(b []byte) []byte {
		if !hasWordChar {
			return b
		}
		wbNW := wordCharOff[1]
		wbW := wordCharOff[2]
		// Read wordChar[input[paramPtr + lScanPos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wordCharOff[0])
		b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A) // paramPtr + lScanPos
		b = appendTableLoad8u(b, tableMemIdx)               // input[lScanPos]
		b = append(b, 0x6A)                                 // wordCharOff + byte
		b = appendTableLoad8u(b, tableMemIdx)               // wordChar[byte] (isWord)
		b = append(b, 0x04, 0x40)                           // if isWord (void)
		// isWord: wbBits = wbWBitmask[lState]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wbW)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0x21, lBits)
		b = append(b, 0x05) // else: !isWord
		// !isWord: wbBits = wbNWBitmask[lState]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, wbNW)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0x21, lBits)
		b = append(b, 0x0B) // end if isWord
		// lResult |= lBits
		b = append(b, 0x20, lResult, 0x20, lBits, 0x84, 0x21, lResult)
		// lBitsScratch = low32(lBits) & validMask
		b = append(b, 0x20, lBits, 0xA7, 0x21, lBitsScratch)
		b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch)
		// For each bit k: if fires, set endPos_k = lScanPos (pre-transition boundary)
		for k := range patternIDs {
			if k >= 32 {
				break
			}
			bit := uint32(1) << uint(k)
			b = append(b, 0x20, lBitsScratch, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x71, 0x04, 0x40)
			b = append(b, 0x20, lScanPos, 0x21, endPosK(k))
			b = append(b, 0x0B)
		}
		return b
	}

	// emitWriteMatchK: write match tuple for pattern k with compile-time prefix length.
	// prefixMaxLen: max prefix length (0 = trivial, >0 = fixed, -1 = variable/unknown).
	// matchStart = paramLPos - prefixMaxLen (for fixed-len prefix), else paramLPos.
	emitWriteMatchK := func(b []byte, bit uint32, globalID, k, prefixMaxLen int) []byte {
		b = append(b, 0x20, lOutCount, 0x20, paramOutCap, 0x49, 0x04, 0x40) // if outCount < cap
		b = append(b, 0x20, paramOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A, 0x21, lOutBase)
		b = append(b, 0x20, lOutBase, 0x41)
		b = utils.AppendSLEB128(b, int32(globalID))
		b = append(b, 0x36, 0x02, 0x00)
		if prefixMaxLen > 0 {
			// match start = paramLPos - prefixMaxLen
			b = append(b, 0x20, lOutBase, 0x20, paramLPos, 0x41)
			b = utils.AppendSLEB128(b, int32(prefixMaxLen))
			b = append(b, 0x6B, 0x36, 0x02, 0x04) // i32.sub; i32.store
			// length = endPos_k - (paramLPos - prefixMaxLen) = endPos_k - paramLPos + prefixMaxLen
			b = append(b, 0x20, lOutBase, 0x20, endPosK(k), 0x20, paramLPos, 0x6B, 0x41)
			b = utils.AppendSLEB128(b, int32(prefixMaxLen))
			b = append(b, 0x6A, 0x36, 0x02, 0x08) // + prefixMaxLen; i32.store
		} else {
			// match start = paramLPos (trivial or variable-length prefix)
			b = append(b, 0x20, lOutBase, 0x20, paramLPos, 0x36, 0x02, 0x04)
			b = append(b, 0x20, lOutBase, 0x20, endPosK(k), 0x20, paramLPos, 0x6B, 0x36, 0x02, 0x08)
		}
		b = append(b, 0x20, lOutCount, 0x41, 0x01, 0x6A, 0x21, lOutCount)
		b = append(b, 0x20, lDoneMask, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x72, 0x21, lDoneMask)
		b = append(b, 0x0B) // end if
		return b
	}

	// emitCheckAndWriteK: if (bitsLocal & bit) && !(doneMask & bit): write using endPos_k.
	emitCheckAndWriteK := func(b []byte, bitsLocal byte, bit uint32, globalID, k, prefixMaxLen int) []byte {
		b = append(b, 0x20, bitsLocal, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x04, 0x40) // i32.and; if
		b = append(b, 0x20, lDoneMask, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x45, 0x04, 0x40) // i32.and; i32.eqz; if
		b = emitWriteMatchK(b, bit, globalID, k, prefixMaxLen)
		b = append(b, 0x0B) // end if not done
		b = append(b, 0x0B) // end if bit set
		return b
	}

	// --- Start-state check: record bits + set per-pattern endPos = paramStart ---
	// Start-state check: use lState (set above to wasmStart or wasmMidStart).
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midBitmaskOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A) // lState*8; midBitmaskOff + lState*8
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)
	b = append(b, 0x20, lStartResult, 0x20, lBits, 0x84, 0x21, lStartResult)
	b = append(b, 0x20, lBits, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	// For each bit k in start-state midAccept: set endPos_k = paramStart
	// (matchStart_k already initialized to paramLPos above)
	for k := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = append(b, 0x20, lBitsScratch, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x04, 0x40) // if (lBitsScratch & bit) != 0
		b = append(b, 0x20, paramStart, 0x21, endPosK(k))
		b = append(b, 0x0B)
	}

	// --- Main scan loop ---
	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x4F, 0x0D, 0x01) // pos>=len: br $done

	// Word-boundary pre-transition accept check (before consuming current byte).
	b = emitWBCheck(b)

	// DFA transition
	if l.useU8 && l.useCompression {
		b = emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			lState, lByteClass, paramPtr, lScanPos, 0xff, tableMemIdx)
	} else if l.useU8 {
		b = emitSimpleU8Transition(b, l.tableOff,
			lState, paramPtr, lScanPos, 0xff, tableMemIdx)
	} else {
		b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A, 0x2D, 0x00, 0x00, 0x21, lByteClass)
		b = emitU16Transition(b, l.tableOff, l.useRowDedup, l.rowMapOff, lState, lByteClass, tableMemIdx)
	}

	// Load midBitmask and update per-pattern endPos for each bit that fires.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midBitmaskOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)
	b = append(b, 0x20, lBits, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	b = append(b, 0x20, lResult, 0x20, lBits, 0x84, 0x21, lResult)
	// Per-pattern: if bit k in midAccept, update endPos_k = scanPos+1
	for k := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = append(b, 0x20, lBitsScratch, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x04, 0x40)                                   // if bit k fired
		b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, endPosK(k)) // endPos_k = scanPos+1
		b = append(b, 0x0B)
	}

	// LIKELY.md Gap H.2: dominant-state SIMD bulk-skip dispatch.
	// Mirrors emitPhase4Dispatch's mid-accept channel but operates on
	// per-pattern endPos. The encoded byte in midAcceptBytes[state] is
	// 2+idx for dominant states (0/1 for non-dominant); we dispatch via
	// state-compare against each dominant's encoded byte.
	//
	// After bulk-skip advances lScanPos by k bytes, every pattern whose
	// midAccept bit is set at the dominant state has its endPos_k bumped
	// to lScanPos+1 — the position right after the last self-loop byte,
	// matching the per-byte update the elided iterations would have done.
	// lBitsScratch is preserved across emitDominantBulkSkip (it only
	// clobbers lByteClass/lBulkChunk), so we re-read it for the update.
	if haveDominants {
		// tmp = midAcceptBytes[state]; if (tmp != 0) { ... }
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.midAcceptOff)
		b = append(b, 0x20, lState)
		b = append(b, 0x6A) // i32.add
		b = appendTableLoad8u(b, tableMemIdx)
		b = append(b, 0x22, lByteClass) // local.tee lByteClass (reused as tmp)
		b = append(b, 0x04, 0x40)       // if (midAccept != 0)
		for _, info := range l.dominantStates {
			if !info.isMidAccept {
				continue
			}
			b = append(b, 0x20, lByteClass)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(info.encodedByte))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (encoded byte match)
			b = emitDominantBulkSkip(b, info, false,
				lScanPos, paramLen, 0x00, paramPtr,
				lBulkChunk, lByteClass)
			// Re-update endPos_k for each pattern in lBitsScratch.
			for k := range patternIDs {
				if k >= 32 {
					break
				}
				bit := uint32(1) << uint(k)
				b = append(b, 0x20, lBitsScratch, 0x41)
				b = utils.AppendSLEB128(b, int32(bit))
				b = append(b, 0x71, 0x04, 0x40)                                   // if bit k set
				b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, endPosK(k)) // endPos_k = scanPos+1
				b = append(b, 0x0B)
			}
			b = append(b, 0x0B) // end if encoded byte match
		}
		b = append(b, 0x0B) // end if midAccept != 0

		// Task 17 (Gap H.2 remainder): non-mid-accept dominant dispatch,
		// default-on for every LikelyMode since task 27 (2026-07-19). Pure
		// state-ID compare (Task 7 step 2 precedent — no side-table load),
		// and pure position advancement: updateLastAccept=false, no
		// per-pattern endPos update here. These states aren't accept points
		// for any pattern, so bulk-skipping through them doesn't complete
		// anyone's match — it just moves lScanPos forward faster. Whichever
		// pattern's match actually completes later (mid/eof/imm-accept,
		// already handled elsewhere in this loop) picks up the advanced
		// position naturally.
		for _, info := range l.dominantStates {
			if info.isMidAccept {
				continue
			}
			b = append(b, 0x20, lState)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, info.state)
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (state == K)
			b = emitDominantBulkSkip(b, info, false,
				lScanPos, paramLen, 0x00, paramPtr,
				lBulkChunk, lByteClass)
			b = append(b, 0x0B) // end if
		}
	}

	// Per-pattern immediateAccept: write immediately when pattern k is done.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immBitmaskOff)
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	pmlFor := func(k int) int {
		if k < len(prefixFixedLens) && prefixFixedLens[k] > 0 {
			return prefixFixedLens[k]
		}
		return 0
	}
	for k, gid := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = emitCheckAndWriteK(b, lBitsScratch, bit, gid, k, pmlFor(k))
	}

	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01)                   // dead: br $done
	b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, lScanPos) // scanPos++
	b = append(b, 0x0C, 0x00)                                       // br $main

	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	// --- EOF check ---
	// At text start (paramLPos==0), use eofBitmaskOff which includes ecBegin acceptance.
	// At mid-string (paramLPos!=0), use eofMidBitmaskOff (ecEnd-only) to avoid false
	// EOF matches for patterns like \z^ whose startState acceptance includes ecBegin.
	b = append(b, 0x20, paramLPos, 0x45, 0x04, 0x7F) // if paramLPos == 0 (result i32)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, eofBitmaskOff)
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, eofMidBitmaskOff)
	b = append(b, 0x0B) // end if → bitmask base on stack
	b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)
	b = append(b, 0x20, lBits, 0x42, 0x00, 0x52, 0x04, 0x40) // if lBits != 0
	// For eof-only patterns (no midAccept), set endPos_k = lScanPos
	b = append(b, 0x20, lBits, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	for k := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = append(b, 0x20, lBitsScratch, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x04, 0x40)                   // if eof bit k fired
		b = append(b, 0x20, endPosK(k), 0x45, 0x04, 0x40) // if endPos_k == 0
		b = append(b, 0x20, lScanPos, 0x21, endPosK(k))   // endPos_k = lScanPos
		b = append(b, 0x0B)                               // end if endPos_k==0
		b = append(b, 0x0B)                               // end if eof bit k
	}
	b = append(b, 0x20, lResult, 0x20, lBits, 0x84, 0x21, lResult)
	b = append(b, 0x0B) // end if lBits != 0

	// --- Post-loop: write scan+eof bits with per-pattern endPos ---
	b = append(b, 0x20, lResult, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	for k, gid := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = emitCheckAndWriteK(b, lBitsScratch, bit, gid, k, pmlFor(k))
	}

	// --- Post-loop: write start-only bits (used paramStart as endPos_k) ---
	b = append(b, 0x20, lStartResult, 0xA7, 0x21, lBitsScratch)
	b = append(b, 0x20, lBitsScratch, 0x20, paramValidMask, 0x71, 0x21, lBitsScratch) // mask with validMask
	for k, gid := range patternIDs {
		if k >= 32 {
			break
		}
		bit := uint32(1) << uint(k)
		b = emitCheckAndWriteK(b, lBitsScratch, bit, gid, k, pmlFor(k))
	}

	b = append(b, 0x20, lOutCount, 0x0B) // return lOutCount
	return b
}

// appendMatchCodeEntry appends a size-prefixed match function body to cs.
// Uses the hybrid dispatch path when l.useHybridDispatch is true.
func appendMatchCodeEntry(cs []byte, l *dfaLayout, t *dfaTable, hasImmAccept bool, tableMemIdx int) []byte {
	var body []byte
	if l.useHybridDispatch {
		body = buildHybridMatchBody(t, l, hasImmAccept, tableMemIdx)
	} else {
		body = buildMatchBody(l.wasmStart, l.tableOff, l.classMapOff,
			l.numClasses, l.useU8, l.useCompression, l.acceptLimit,
			l.immAcceptLimit, hasImmAccept, l.rowMapOff, l.useRowDedup, tableMemIdx,
			l.midAcceptOff, l.dominantStates)
	}
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// emitAcceptBitOnStack pushes the accept indicator (0 or 1 i32) on the WASM stack.
//
// Option D: accept-status is encoded into the state-ID partition by
// reorderAcceptFirst. A WASM state s is eof-accepting iff 1 ≤ s ≤ acceptLimit.
// We emit ((stateLocal-1) u< acceptLimit), which correctly returns 0 for the
// dead state (state == 0 underflows to 0xFFFFFFFF, which is not u< acceptLimit)
// and 1 for any state in the accepting partition.
func emitAcceptBitOnStack(b []byte, stateLocal byte, acceptLimit int32) []byte {
	b = append(b, 0x20, stateLocal) // local.get state
	b = append(b, 0x41, 0x01)       // i32.const 1
	b = append(b, 0x6B)             // i32.sub
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acceptLimit) // i32.const acceptLimit
	b = append(b, 0x49)                     // i32.lt_u
	return b
}

// appendFindCodeEntry appends a size-prefixed find function body to cs.
// Uses buildAnchoredFindBody when isAnchoredFind(t), else buildFindBody.
//
// The non-mid-accept-dispatch variant (which also returned the list of
// call-site offsets for assembleModule-time patching of the helper
// function index) was extracted to plans/non_mid_extension.go.archive
// (Section 9). To reinstate, change the signature to
// `([]byte, []int)`, restore the `callSites` plumbing, and update both
// callers.
func appendFindCodeEntry(cs []byte, l *dfaLayout, t *dfaTable, mandatoryLit *mandatoryLit, tableMemIdx int) []byte {
	var body []byte
	if l.useHybridDispatch {
		if isAnchoredFind(t) {
			body = buildHybridAnchoredFindBody(t, l, tableMemIdx)
		} else {
			body = buildHybridFindBody(t, l, mandatoryLit, tableMemIdx)
		}
	} else if isAnchoredFind(t) {
		body = buildAnchoredFindBody(l.wasmStart, l.tableOff, l.midAcceptOff,
			l.classMapOff, l.numClasses, l.useU8, l.useCompression, l.acceptLimit,
			l.startBeginAccept, l.immAcceptLimit, l.hasImmAccept,
			l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff,
			l.midAcceptNLOff, t.hasNewlineBoundary, tableMemIdx)
	} else {
		body = buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord,
			l.wasmMidStartNewline, l.wasmPrefixEnd, l.wasmPrefixEndWord,
			l.tableOff, l.midAcceptOff,
			l.firstByteOff, l.prefix, l.classMapOff, l.numClasses,
			l.useU8, l.useCompression, l.acceptLimit, l.startBeginAccept,
			l.immAcceptLimit, l.hasImmAccept,
			l.wordCharTableOff, l.needWordCharTable,
			l.midAcceptNWOff, l.midAcceptWOff, t.hasNewlineBoundary,
			l.firstByteFlags, l.firstBytes,
			l.teddyLoOff, l.teddyHiOff,
			l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0,
			l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0,
			l.teddyT3LoOff, l.teddyT3HiOff, len(l.teddyT3LoBytes) > 0,
			mandatoryLit, l.rowMapOff, l.useRowDedup, l.midAcceptNLOff,
			tableMemIdx,
			l.dominantStates, l.lnmAction5, l.skipSafeOnDead, l.eofSkipSafe)
	}
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// emitCompressedU8Transition emits the compressed u8 DFA transition:
//
//	class = classMap[classMapOff + byte]
//	state = table[tableOff + row*numClasses + class]  (raw next+1; 0 = dead)
//
// where byte is loaded from mem[ptrLocal+posLocal] when byteLocal==0xff,
// or taken from byteLocal otherwise (byte already in a local).
// row = state (row dedup applies only to u16 tables; see emitU16Transition).
// classLocal receives the class value; stateLocal is updated with the loaded state.
func emitCompressedU8Transition(b []byte,
	tableOff, classMapOff int32, numClasses int,
	stateLocal, classLocal byte,
	ptrLocal, posLocal byte,
	byteLocal byte,
	tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, classMapOff)
	if byteLocal == 0xff {
		b = append(b, 0x20, ptrLocal)
		b = append(b, 0x20, posLocal)
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	} else {
		b = append(b, 0x20, byteLocal)
	}
	b = append(b, 0x6A)                   // classMapOff + byte
	b = appendTableLoad8u(b, tableMemIdx) // class = classMap[...]
	b = append(b, 0x21, classLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(numClasses))
	b = append(b, 0x6C)                   // i32.mul
	b = append(b, 0x6A)                   // i32.add
	b = append(b, 0x20, classLocal)       // local.get class
	b = append(b, 0x6A)                   // i32.add
	b = appendTableLoad8u(b, tableMemIdx) // cell = table[row*numClasses+class] (== state)
	b = append(b, 0x21, stateLocal)
	return b
}

// buildNonMidBulkSkipHelperBody was extracted to
// plans/non_mid_extension.go.archive (Section 6) along with the rest of
// the LNM non-mid-accept dispatch infrastructure.

// emitSimpleU8Transition emits the simple u8 DFA transition:
//
//	cell = table[..]; state = cell (cell value is the destination state)
//
// where byte is loaded from mem[ptrLocal+posLocal] when byteLocal==0xff,
// or taken from byteLocal otherwise.
// row = state (row dedup applies only to u16 tables; see emitU16Transition).
// stateLocal is updated with the loaded state.
func emitSimpleU8Transition(b []byte,
	tableOff int32,
	stateLocal byte,
	ptrLocal, posLocal byte,
	byteLocal byte,
	tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x41, 0x08) // i32.const 8
	b = append(b, 0x74)       // i32.shl (row * 256)
	b = append(b, 0x6A)
	if byteLocal == 0xff {
		b = append(b, 0x20, ptrLocal)
		b = append(b, 0x20, posLocal)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	} else {
		b = append(b, 0x20, byteLocal)
	}
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // cell = table[row*256+byte] (== state)
	b = append(b, 0x21, stateLocal)
	return b
}

// emitU16Transition emits the u16 DFA transition:
//
//	cell = u16(table[tableOff + row*512 + byteLocal*2])  (cell value is the destination state)
//
// byteLocal must be a pre-loaded i32 local containing the input byte.
// row = rowMap[state] when useRowDedup, otherwise row = state.
// stateLocal is updated with the loaded state.
func emitU16Transition(b []byte,
	tableOff int32,
	useRowDedup bool, rowMapOff int32,
	stateLocal, byteLocal byte,
	tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, tableOff)
	if useRowDedup {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, rowMapOff)
		b = append(b, 0x20, stateLocal)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // rowMap[state] → row
	} else {
		b = append(b, 0x20, stateLocal)
	}
	b = append(b, 0x41, 0x09) // i32.const 9
	b = append(b, 0x74)       // i32.shl (row * 512)
	b = append(b, 0x6A)
	b = append(b, 0x20, byteLocal)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x74)       // i32.shl (byte * 2)
	b = append(b, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx) // cell = i32.load16_u (== state)
	b = append(b, 0x21, stateLocal)
	return b
}

// emitImmAcceptCheckMatch emits: if state u<= immAcceptLimit: return pos.
// Used in match mode. No-op when hasImmAccept is false.
//
// Relies on reorderAcceptFirst placing immediate-accepting states at WASM IDs
// 1..immAcceptLimit. The state==0 (dead) case is guarded by an earlier check
// in the caller, so we use u<= (not <) here.
func emitImmAcceptCheckMatch(b []byte, immAcceptLimit int32,
	hasImmAccept bool, tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	_ = tableMemIdx
	const stateLocal = 0x02
	const posLocal = 0x03
	b = append(b, 0x20, stateLocal)            // local.get state
	b = append(b, 0x41)                        // i32.const immAcceptLimit
	b = utils.AppendSLEB128(b, immAcceptLimit) //
	b = append(b, 0x4D)                        // i32.le_u
	b = append(b, 0x04, 0x40)                  // if (void)
	b = append(b, 0x20, posLocal)              // local.get pos
	b = append(b, 0x0F)                        // return
	b = append(b, 0x0B)                        // end if
	return b
}

// emitDominantBulkSkip emits the LikelyNoMatch SIMD bulk-skip block for a
// dominant self-loop state. Inserts INSIDE the find-mode inner scan loop,
// AFTER the per-byte transition and midAccept update, BEFORE pos++.
//
// Three emission paths, chosen by which of `info.selfLoopSet` /
// `info.exitBytes` is populated (mutually exclusive):
//
//   - Task 26 — self-loop-set Shufti (info.selfLoopSet, 9..64 bytes):
//     the self-loop set itself is the small side. Tests membership in it
//     directly via the shared emitShuftiPrefixCheck primitive and inverts
//     the resulting bitmask (XOR 0xFFFF) so "stop" bits mark bytes NOT in
//     the self-loop class. Used when the exit set is too large for the
//     paths below (e.g. a 62-byte `[a-zA-Z0-9]` self-loop with a 194-byte
//     exit set — detectDominantSelfLoop's ≤8-exit-byte gate can never
//     reach this shape). See detectShuftiSelfLoop.
//
//   - Single exit byte (Phase 2, info.exitBytes len 1):
//     `i8x16.splat + i8x16.eq + i8x16.bitmask`. Three SIMD ops; the splat
//     constant is folded by JIT into the loop preamble. Fast path for
//     patterns like `//[^\n]+`.
//
//   - Multi exit byte (Phase 5, info.exitBytes len 2..8): Shufti-style
//     nibble lookup on the EXIT set (the small side in this case).
//     Build two 16-byte tables T_lo and T_hi where bit i of T_lo[lo]
//     (resp. T_hi[hi]) is set iff exit byte i has low (resp. high)
//     nibble equal to lo (resp. hi). Per chunk:
//     lo_bits = swizzle(T_lo, chunk & 0x0F)
//     hi_bits = swizzle(T_hi, chunk >> 4)
//     match  = lo_bits & hi_bits        ; non-zero lanes = exit bytes
//     mask   = bitmask(match != 0)
//     Eight SIMD ops; tables inlined as v128.const. Unlocks patterns
//     like `https?://[^\s]+` (6-byte `\s` exit) and `<[^>]+>` if
//     a future revisit broadens.
//
// All three paths converge on the same "stop" bitmask semantics (bit k set
// ⇔ lane k is where the self-loop run ends), so the ctz/pos-advance tail
// below is shared regardless of which path built the mask.
//
// Contract:
//   - Caller MUST guard the call so it only runs when state == dominantState.
//     Option 1 piggybacks on the midAccept[state] lookup; the dominant
//     state's `midAcceptBytes` value is encoded uniquely and the caller
//     branches on the cached value.
//   - Requires the dominant state to be mid-accepting: every byte while
//     in it is a valid match end. Detection sets the encoding only when
//     this holds.
//   - exitBytes length is 1..8 (Shufti cap); selfLoopSet length is 9..64
//     (emitShuftiPrefixCheck's cap) when used instead. Detection enforces
//     both bounds and their mutual exclusivity.
//   - Uses 1 i32 scratch local (`tmpLocal`) and 1 v128 scratch (`chunkLocal`),
//     both must be safe to clobber at this point (e.g. the Teddy-scan-phase
//     locals which are unused inside the DFA scan loop).
//
// Layout (caller has already gated on state being dominant; `pos` is the
// position of the byte just consumed):
//
//	block $bulk_done:
//	  loop $bulk_outer:
//	    if pos + 17 > len: br $bulk_done   // not enough room for 16-byte SIMD
//	    chunk = v128.load(ptr + pos + 1)
//	    m = <single-byte or Shufti match → i32 bitmask>
//	    if m == 0:
//	      pos += 16
//	      br $bulk_outer  // continue loop
//	    else:
//	      pos += i32.ctz(m)
//	      last_accept = pos + 1
//	      br $bulk_done
//	  end loop
//	end block
//
// After the block, pos is positioned so the next pos++ takes execution
// past the self-loop bytes and onto the first exit byte (which the next
// scan iteration will transition on).
// nonMidHystStreak is the task 38 hysteresis threshold: after this many
// CONSECUTIVE non-mid bulk-skip attempts that each advanced < 16 bytes
// (i.e. the exit byte was already inside the first SIMD chunk — the
// attempt bought less than one chunk's worth of skipping), the non-mid
// dispatch stops trying for the rest of the call. A single productive
// attempt (advance ≥ 16) resets the streak. This converts the non-mid
// channel's bimodal run-length behaviour — −90% fuel on long runs,
// +27% and worse on dense short runs — into "long-run win kept, short-run
// harm bounded at N wasted attempts per call", making it safe to emit
// under every LikelyMode instead of LikelyMatch-only (task 36's gate).
const nonMidHystStreak = 2

// emitHystBulkSkip emits one non-mid-accept dominant's bulk-skip attempt,
// wrapped in the task 38 runtime hysteresis. The caller has already
// established that the current state IS this dominant (via the 254+
// midAcceptBytes value dispatch — see emitNonMidValDispatch), so no state
// compare is emitted here:
//
//	if hystCounter < N:           ; still enabled this call
//	  hystPos = pos
//	  <emitDominantBulkSkip>
//	  if pos - hystPos < 16: hystCounter++ else: hystCounter = 0
//
// hystCounter is a per-call i32 local (zero-initialised by WASM), shared
// across all non-mid dominants of the function; hystPos is scratch. Once
// the counter reaches nonMidHystStreak the gate never passes again
// (nothing resets the counter once dispatch stops running), so the
// channel stays off for the rest of the call. The gate runs only on
// dominant-state bytes — everything else pays nothing at all.
//
// The bounds-exit path of emitDominantBulkSkip (pos+17 > len) can bump
// the counter with advance < 16 even though nothing was learned about
// run length; it fires at most once per call, at EOF, and is harmless.
func emitHystBulkSkip(b []byte, info dominantInfo,
	posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
	hystCounterLocal, hystPosLocal byte) []byte {
	// if hystCounter < N (channel still enabled)
	b = append(b, 0x20, hystCounterLocal)
	b = append(b, 0x41, nonMidHystStreak)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x04, 0x40) // if (void)
	// hystPos = pos
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, hystPosLocal)
	b = emitDominantBulkSkip(b, info, false,
		posLocal, lenLocal /*lastAccept=*/, 0x00, ptrLocal,
		chunkLocal, tmpLocal)
	// hystCounter = (pos - hystPos < 16) ? hystCounter + 1 : 0
	b = append(b, 0x20, posLocal)
	b = append(b, 0x20, hystPosLocal)
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, hystCounterLocal)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, hystCounterLocal)
	b = append(b, 0x05) // else
	b = append(b, 0x41, 0x00)
	b = append(b, 0x21, hystCounterLocal)
	b = append(b, 0x0B) // end if (counter update)
	b = append(b, 0x0B) // end if (hystCounter < N)
	return b
}

// emitNonMidValDispatch emits the non-mid dominant dispatch bodies. The
// caller has already branched on `val >= 254` (val = the cached
// midAcceptBytes[state] load), so with a single non-mid entry no further
// compare is needed; with two entries (the encoding cap) a single
// `val == 254` if/else discriminates them. This is what makes the task 38
// v2 design free on the hot path: bytes in states with midAccept == 0
// never reach here, and the load they DO pay was already emitted for the
// mid-accept last_accept update.
func emitNonMidValDispatch(b []byte, nonMid []dominantInfo,
	valLocal, posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
	hystCounterLocal, hystPosLocal byte) []byte {
	switch len(nonMid) {
	case 1:
		b = emitHystBulkSkip(b, nonMid[0],
			posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
			hystCounterLocal, hystPosLocal)
	case 2:
		// val is 254 or 255 here; one compare discriminates. The else
		// branch runs before any tmp/val clobber can happen, so the
		// discrimination is safe.
		b = append(b, 0x20, valLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(nonMid[0].encodedByte))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x04, 0x40) // if (void)
		b = emitHystBulkSkip(b, nonMid[0],
			posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
			hystCounterLocal, hystPosLocal)
		b = append(b, 0x05) // else
		b = emitHystBulkSkip(b, nonMid[1],
			posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
			hystCounterLocal, hystPosLocal)
		b = append(b, 0x0B) // end if
	}
	return b
}

// emitFindMidAcceptDispatch emits the find-scan-loop midAccept block shared
// by buildFindBody's u8 paths: the last_accept update plus both dominant
// dispatch channels, all fed by ONE midAcceptBytes[state] load (task 38 v2):
//
//	val = midAccept[state]
//	if val != 0:
//	  if val < 254:                  ; only when non-mid values are in the table
//	    last_accept = pos + 1
//	    [mid dominant dispatch — per-entry val==enc compares]
//	  else:                          ; val is a reserved 254+ non-mid encoding
//	    [non-mid dispatch — emitNonMidValDispatch + hysteresis; NO last_accept]
//
// When the pattern has no non-mid entries the split is not emitted and the
// sequence is byte-identical to the pre-task-38 mid-only emission. Under
// useMandatoryLit the dominant dispatches are suppressed (pre-existing
// behaviour) but the val < 254 split is still REQUIRED whenever non-mid
// values are present in the table — without it a plain `!= 0` check would
// treat the 254+ encodings as accepting states and corrupt last_accept.
//
// valLocal doubles as the bulk-skip scratch (tmp), matching the previous
// emission's reuse of the class/simdMask local.
func emitFindMidAcceptDispatch(b []byte, dominantStates []dominantInfo,
	useMandatoryLit bool, midAcceptOff int32, tableMemIdx int,
	stateLocal, posLocal, lenLocal, lastAcceptLocal, ptrLocal,
	chunkLocal, valLocal, hystCounterLocal, hystPosLocal byte) []byte {

	var mid, nonMid []dominantInfo
	for _, info := range dominantStates {
		if info.isMidAccept {
			mid = append(mid, info)
		} else {
			nonMid = append(nonMid, info)
		}
	}
	emitMidDom := !useMandatoryLit && len(mid) > 0
	dispatchNonMid := !useMandatoryLit && len(nonMid) > 0
	hasNonMidVals := len(nonMid) > 0

	emitAccept := func(b []byte) []byte {
		b = append(b, 0x20, posLocal)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)                  // pos + 1
		b = append(b, 0x21, lastAcceptLocal) // local.set last_accept
		return b
	}
	emitMidChain := func(b []byte) []byte {
		for _, info := range mid {
			b = append(b, 0x20, valLocal)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(info.encodedByte))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, true,
				posLocal, lenLocal, lastAcceptLocal, ptrLocal,
				chunkLocal, valLocal)
			b = append(b, 0x0B) // end if (per-dominant gate)
		}
		return b
	}

	// val = midAccept[state]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	if emitMidDom || hasNonMidVals {
		b = append(b, 0x22, valLocal) // local.tee — cache val
	}
	b = append(b, 0x04, 0x40) // if (val != 0)
	if hasNonMidVals {
		b = append(b, 0x20, valLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, 254)
		b = append(b, 0x49)       // i32.lt_u
		b = append(b, 0x04, 0x40) // if (val < 254)
		b = emitAccept(b)
		if emitMidDom {
			b = emitMidChain(b)
		}
		if dispatchNonMid {
			b = append(b, 0x05) // else — val >= 254: non-mid dominant
			b = emitNonMidValDispatch(b, nonMid,
				valLocal, posLocal, lenLocal, ptrLocal, chunkLocal, valLocal,
				hystCounterLocal, hystPosLocal)
		}
		b = append(b, 0x0B) // end if (val < 254)
	} else {
		b = emitAccept(b)
		if emitMidDom {
			b = emitMidChain(b)
		}
	}
	b = append(b, 0x0B) // end if (val != 0)
	return b
}

// emitPhase4Dispatch emits the Phase 4 match-body bulk-skip dispatch.
// One table load feeds both channels (task 38 v2):
//
//	val = midAcceptBytes[state]
//	if val != 0:
//	  if val < 254:  [mid dispatch — per-entry val==enc compares]
//	  else:          [non-mid dispatch — emitNonMidValDispatch + hysteresis]
//
// The val < 254 split exists only when both channels are present; with a
// single channel the branch collapses to that channel's body. Bytes in
// states with midAccept == 0 (the vast majority on harm-shaped inputs)
// pay only the load+branch — which the mid channel always required — and
// nothing for the non-mid channel; this replaces the per-byte `state == K`
// compare chain that was measured as the dominant fuel cost of the old
// emission (perftest html-tags +474% with zero attempts executed).
//
// updateLastAccept is always false in match mode.
//
// Uses 1 v128 local (chunk) and 1 i32 local (tmp). Callers that already
// have a scratch i32 (e.g. class/byte locals) reuse it as tmp. When any
// non-mid dominant is present, callers must additionally declare 2 i32
// locals (hysteresis counter + scratch) and pass their indices; both are
// ignored when every entry is mid-accept.
func emitPhase4Dispatch(b []byte, dominantStates []dominantInfo,
	midAcceptOff int32, tableMemIdx int) []byte {
	if len(dominantStates) == 0 {
		return b
	}
	const stateLocal = 0x02
	const posLocal = 0x03
	const lenLocal = 0x01
	const ptrLocal = 0x00
	const chunkLocal = 0x05
	const tmpLocal = 0x04
	const hystCounterLocal = 0x06
	const hystPosLocal = 0x07
	var mid, nonMid []dominantInfo
	for _, info := range dominantStates {
		if info.isMidAccept {
			mid = append(mid, info)
		} else {
			nonMid = append(nonMid, info)
		}
	}
	emitMidChain := func(b []byte) []byte {
		for _, info := range mid {
			b = append(b, 0x20, tmpLocal)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(info.encodedByte))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, false,
				posLocal, lenLocal /*lastAccept=*/, 0x00, ptrLocal,
				chunkLocal, tmpLocal)
			b = append(b, 0x0B) // end if (per-dominant gate)
		}
		return b
	}
	// val = midAccept[state] (tee'd into tmp)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A) // i32.add
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x22, tmpLocal) // local.tee tmp
	b = append(b, 0x04, 0x40)     // if (val != 0)
	switch {
	case len(mid) > 0 && len(nonMid) > 0:
		b = append(b, 0x20, tmpLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, 254)
		b = append(b, 0x49)       // i32.lt_u
		b = append(b, 0x04, 0x40) // if (val < 254)
		b = emitMidChain(b)
		b = append(b, 0x05) // else — val >= 254: non-mid dominant
		b = emitNonMidValDispatch(b, nonMid,
			tmpLocal, posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
			hystCounterLocal, hystPosLocal)
		b = append(b, 0x0B) // end if (val < 254)
	case len(mid) > 0:
		b = emitMidChain(b)
	default:
		// Only non-mid entries. Table values for accept states are 1
		// (plain mid-accept) — the val >= 254 check below excludes them.
		b = append(b, 0x20, tmpLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, 254)
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (val >= 254)
		b = emitNonMidValDispatch(b, nonMid,
			tmpLocal, posLocal, lenLocal, ptrLocal, chunkLocal, tmpLocal,
			hystCounterLocal, hystPosLocal)
		b = append(b, 0x0B) // end if (val >= 254)
	}
	b = append(b, 0x0B) // end if (val != 0)
	return b
}

func emitDominantBulkSkip(b []byte, info dominantInfo, updateLastAccept bool,
	posLocal, lenLocal, lastAcceptLocal,
	ptrLocal, chunkLocal, tmpLocal byte) []byte {
	exitBytes := info.exitBytes

	// block $bulk_done
	b = append(b, 0x02, 0x40)
	// loop $bulk_outer
	b = append(b, 0x03, 0x40)

	// if pos + 17 > len: br $bulk_done (depth 1)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x41, 0x11) // i32.const 17
	b = append(b, 0x6A)
	b = append(b, 0x20, lenLocal)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x0D, 0x01) // br_if $bulk_done

	// chunk = v128.load(ptr + pos + 1)
	b = append(b, 0x20, ptrLocal)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x6A)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0xFD, 0x00, 0x00, 0x00)
	b = append(b, 0x21, chunkLocal)

	if len(info.selfLoopSet) > 0 {
		// Task 26: self-loop set is the small (≤64, Shufti-cap) side, not
		// the exit side. Test membership in it directly via the shared
		// Shufti primitive (leaves an i32 bitmask, bit k set ⇔ lane k IS a
		// member) and invert: a "stop" bit means the byte is NOT a member
		// — the first byte outside the self-loop class, which is exactly
		// what the ctz/pos-advance logic below needs.
		b = emitShuftiPrefixCheck(b, info.selfLoopSet, chunkLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(0xFFFF))
		b = append(b, 0x73) // i32.xor — invert the 16 relevant bits
	} else if len(exitBytes) == 1 {
		// Phase 2 single-byte: m = bitmask(eq(chunk, splat(exit))).
		b = append(b, 0x20, chunkLocal)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(exitBytes[0]))
		b = append(b, 0xFD, 0x0F) // i8x16.splat
		b = append(b, 0xFD, 0x23) // i8x16.eq
		b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
	} else {
		// Phase 5 multi-byte: Shufti nibble lookup.
		// Build T_lo and T_hi: bit i is set in T_lo[lo] iff exitBytes[i] has low nibble lo.
		var tLo, tHi [16]byte
		for i, eb := range exitBytes {
			bit := byte(1) << uint(i)
			tLo[eb&0x0F] |= bit
			tHi[eb>>4] |= bit
		}
		// v128.const T_lo (16 bytes inline) then swizzle(T_lo, chunk & 0x0F).
		b = append(b, 0xFD, 0x0C) // v128.const
		b = append(b, tLo[:]...)
		b = append(b, 0x20, chunkLocal)
		b = append(b, 0x41, 0x0F) // i32.const 0x0F
		b = append(b, 0xFD, 0x0F) // i8x16.splat
		b = append(b, 0xFD, 0x4E) // v128.and  → chunk & 0x0F
		b = append(b, 0xFD, 0x0E) // i8x16.swizzle → T_lo[chunk & 0x0F]

		// swizzle(T_hi, chunk >> 4).
		b = append(b, 0xFD, 0x0C) // v128.const
		b = append(b, tHi[:]...)
		b = append(b, 0x20, chunkLocal)
		b = append(b, 0x41, 0x04) // i32.const 4
		b = append(b, 0xFD, 0x6D) // i8x16.shr_u → chunk >> 4
		b = append(b, 0xFD, 0x0E) // i8x16.swizzle → T_hi[chunk >> 4]

		// match = lo_bits & hi_bits.
		b = append(b, 0xFD, 0x4E) // v128.and

		// m = bitmask(match != 0).
		b = append(b, 0x41, 0x00) // i32.const 0
		b = append(b, 0xFD, 0x0F) // i8x16.splat
		b = append(b, 0xFD, 0x24) // i8x16.ne
		b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
	}

	// local.tee tmpLocal (keep mask on stack)
	b = append(b, 0x22, tmpLocal)
	b = append(b, 0x45)       // i32.eqz: 1 if m == 0
	b = append(b, 0x04, 0x40) // if (void) — "no exit found in this chunk"
	//   pos += 16
	b = append(b, 0x20, posLocal)
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6A)
	b = append(b, 0x21, posLocal)
	//   continue loop: br $bulk_outer (depth 1 from inside if)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x05) // else
	//   pos += ctz(m); [optionally last_accept = pos + 1]; break to $bulk_done
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x68) // i32.ctz
	b = append(b, 0x20, posLocal)
	b = append(b, 0x6A) // i32.add
	if updateLastAccept {
		b = append(b, 0x22, posLocal) // local.tee posLocal (keep on stack)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A) // pos + 1
		b = append(b, 0x21, lastAcceptLocal)
	} else {
		b = append(b, 0x21, posLocal) // local.set posLocal (no last_accept update)
	}
	//   br $bulk_done (depth 2 from inside if-else)
	b = append(b, 0x0C, 0x02)
	b = append(b, 0x0B) // end if

	b = append(b, 0x0B) // end loop $bulk_outer
	b = append(b, 0x0B) // end block $bulk_done
	return b
}

// emitImmAcceptCheckFindMid emits: if state u<= immAcceptLimit: last_accept=pos+1; br brDepth.
// Used mid-scan in find mode. No-op when hasImmAccept is false.
//
// Relies on reorderAcceptFirst placing immediate-accepting WASM state IDs at
// 1..immAcceptLimit. The state==0 (dead) case is excluded by an upstream
// dead-state guard: every caller of this helper runs `emitDeadHandler` (which
// br's out of the current scan iteration on state==0) after the DFA
// transition, so by the time we reach this check, state != 0 is guaranteed.
//
// If a new caller is added that doesn't have such a guard upstream, use the
// `(state-1) u< immAcceptLimit` unsigned-underflow pattern instead (compare
// emitImmAcceptCheckFindStart, which needed exactly that fix for Task 9).
func emitImmAcceptCheckFindMid(b []byte, immAcceptLimit int32,
	hasImmAccept bool, stateLocal, posLocal byte,
	tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	_ = tableMemIdx
	const lastAcceptLocal = 0x05
	const brDepth = 2
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immAcceptLimit)
	b = append(b, 0x4D)                  // i32.le_u
	b = append(b, 0x04, 0x40)            // if (void)
	b = append(b, 0x20, posLocal)        //
	b = append(b, 0x41, 0x01)            // i32.const 1
	b = append(b, 0x6A)                  // i32.add (pos + 1)
	b = append(b, 0x21, lastAcceptLocal) //
	b = append(b, 0x0C, brDepth)         // br brDepth
	b = append(b, 0x0B)                  // end if
	return b
}

// emitImmAcceptCheckFindStart emits: if (state-1) u< immAcceptLimit: last_accept=pos; br brDepth.
// Used at the start of each attempt in find mode. No-op when hasImmAccept is false.
//
// The check must reject state=0 (dead). A naive `state u<= immAcceptLimit` is
// TRUE for state=0 whenever immAcceptLimit >= 0 (always), which incorrectly
// fires the imm-accept branch for a dead state — this happens in find mode
// when the SIMD prefix scan's OnMatch sets state=prefixEndStateWord=0 for
// `\b<wordchar>` patterns where the previous byte is a word char (Task 9).
// The unsigned-underflow trick `(state-1) u< immAcceptLimit` matches
// emitAcceptBitOnStack and handles state=0 correctly: state-1 underflows to
// 0xFFFFFFFF which is NOT u< immAcceptLimit.
func emitImmAcceptCheckFindStart(b []byte, immAcceptLimit int32,
	hasImmAccept bool,
	tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	_ = tableMemIdx
	const stateLocal = 0x02
	const posLocal = 0x03
	const lastAcceptLocal = 0x05
	const brDepth = 1
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B) // i32.sub → state - 1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immAcceptLimit)
	b = append(b, 0x49)                  // i32.lt_u (unsigned)
	b = append(b, 0x04, 0x40)            // if (void)
	b = append(b, 0x20, posLocal)        //
	b = append(b, 0x21, lastAcceptLocal) //
	b = append(b, 0x0C, brDepth)         // br brDepth
	b = append(b, 0x0B)                  // end if
	return b
}

// emitEofHandler emits the EOF (pos >= len) handler inside the DFA scan loop.
// Checks eofAccept[state]; if set, updates last_accept = pos.
// When hasRetry is false (anchored mode): unconditionally br foundDepth → $found.
// When hasRetry is true (full find mode): br_if foundDepth → $found if last_accept>=0,
// otherwise:
//   - eofSkipSafe (Task 8 follow-up #2): br directly to $no_match (depth
//     outerDepth+1) — reaching EOF without ever recording an accept proves
//     no later start position can match either (see detectEOFSkipSafe).
//   - otherwise: increment attemptStartLocal and br outerDepth → $outer.
func emitEofHandler(b []byte,
	hasRetry bool, outerDepth byte,
	acceptLimit int32, eofSkipSafe bool) []byte {
	const stateLocal = 0x02
	const posLocal = 0x03
	const lastAcceptLocal = 0x05
	const attemptStartLocal = 0x04
	const foundDepth = 2
	b = emitAcceptBitOnStack(b, stateLocal, acceptLimit)
	b = append(b, 0x04, 0x40) // if eofAccept
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0B) // end if
	if !hasRetry {
		b = append(b, 0x0C, foundDepth) // br → $found (unconditional, anchored)
	} else {
		b = append(b, 0x20, lastAcceptLocal)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4E)             // i32.ge_s
		b = append(b, 0x0D, foundDepth) // br_if → $found
		if eofSkipSafe {
			b = append(b, 0x0C, outerDepth+1) // br → $no_match
		} else {
			b = append(b, 0x20, attemptStartLocal)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, attemptStartLocal)
			b = append(b, 0x0C, outerDepth) // br → $outer
		}
	}
	return b
}

// emitDeadHandler emits the dead-state handler inside the DFA scan loop.
// When hasRetry is false (anchored mode): unconditionally br foundDepth → $found.
// When hasRetry is true (full find mode): br_if foundDepth → $found if last_accept>=0,
// otherwise advance attemptStartLocal and br outerDepth → $outer. Advance
// is `pos + 1` when skipSafeOnDead (Task 8 dead-state skip) or `+1` otherwise.
// posLocal is ignored when skipSafeOnDead is false.
func emitDeadHandler(b []byte,
	hasRetry bool, outerDepth byte,
	posLocal byte, skipSafeOnDead bool) []byte {
	const attemptStartLocal = 0x04
	const lastAcceptLocal = 0x05
	const foundDepth = 2
	if !hasRetry {
		b = append(b, 0x0C, foundDepth) // br → $found (unconditional, anchored)
	} else {
		b = append(b, 0x20, lastAcceptLocal)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4E)             // i32.ge_s
		b = append(b, 0x0D, foundDepth) // br_if → $found
		if skipSafeOnDead {
			// Task 8: attempt_start = pos + 1. Skips intermediate attempts
			// from K+1..pos-1 since they would also die at pos (or earlier).
			b = append(b, 0x20, posLocal)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, attemptStartLocal)
		} else {
			b = append(b, 0x20, attemptStartLocal)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, attemptStartLocal)
		}
		b = append(b, 0x0C, outerDepth) // br → $outer
	}
	return b
}

// emitWBPreAcceptCheck emits: before the DFA transition, check wordChar/non-wordChar
// and update last_accept from midAcceptW or midAcceptNW accordingly.
// No-op when hasWordBoundary is false.
func emitWBPreAcceptCheck(b []byte, wordCharTableOff, midAcceptWOff, midAcceptNWOff int32,
	hasWordBoundary bool,
	tableMemIdx int) []byte {
	if !hasWordBoundary {
		return b
	}
	const ptrLocal = 0x00
	const posLocal = 0x03
	const stateLocal = 0x02
	const lastAcceptLocal = 0x05
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, wordCharTableOff)
	b = append(b, 0x20, ptrLocal)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // wordCharTable[byte]
	b = append(b, 0x04, 0x40)             // if isWordChar
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptWOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAcceptW[state]
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0B)
	b = append(b, 0x05) // else: non-word
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptNWOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAcceptNW[state]
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0B)
	b = append(b, 0x0B) // end if isWordChar
	return b
}

// emitNLPreAcceptCheck emits: if current byte == '\n', check midAcceptNL[state]
// and update last_accept = pos. No-op when hasNewlineBoundary is false.
func emitNLPreAcceptCheck(b []byte, midAcceptNLOff int32,
	hasNewlineBoundary bool,
	posLocal, stateLocal byte,
	tableMemIdx int) []byte {
	if !hasNewlineBoundary {
		return b
	}
	const ptrLocal = 0x00
	const lastAcceptLocal = 0x05
	b = append(b, 0x20, ptrLocal)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x41, 0x0A)       // i32.const '\n'
	b = append(b, 0x46)             // i32.eq
	b = append(b, 0x04, 0x40)       // if (void)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptNLOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAcceptNL[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0B) // end if midAcceptNL
	b = append(b, 0x0B) // end if '\n'
	return b
}

// buildMatchBody returns the WASM function body bytes (locals + instructions + end).
//
// u8 compressed (useU8=true, useCompression=true):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=class 5=cell
//
// u8 simple (useU8=true, useCompression=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=cell
//
// u16 (useU8=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=byte 5=cell
//
// startStateAccept: true when the DFA start state itself is an accepting state
// (handles the empty-input case where no transition is ever taken).
func buildMatchBody(startState uint32, tableOff, classMapOff int32, numClasses int, useU8, useCompression bool, acceptLimit int32, immAcceptLimit int32, hasImmAccept bool, rowMapOff int32, useRowDedup bool, tableMemIdx int, midAcceptOff int32, dominantStates []dominantInfo) []byte {
	var b []byte

	// emitAcceptCheck emits the final post-loop accept check:
	//   accept != 0 ? return pos : return -1
	// Option D: accept = (state-1) u< acceptLimit (state-ID partition).
	emitAcceptCheck := func(b []byte, stateLocal, posLocal byte) []byte {
		b = emitAcceptBitOnStack(b, stateLocal, acceptLimit)
		b = append(b, 0x04, 0x7F)     // if (result i32): accept
		b = append(b, 0x20, posLocal) // local.get pos
		b = append(b, 0x05)           // else
		b = append(b, 0x41, 0x7F)     // i32.const -1
		b = append(b, 0x0B)           // end if
		b = append(b, 0x0B)           // end function
		return b
	}

	emitMidDom := len(dominantStates) > 0
	// Task 38: non-mid dominants need 2 extra i32 locals (hysteresis
	// counter + scratch, locals 6/7 in every path below).
	hystDom := false
	for _, info := range dominantStates {
		if !info.isMidAccept {
			hystDom = true
		}
	}

	// appendMatchLocals appends the locals declaration shared by all three
	// paths: i32Count i32 locals, then (only with dominants) 1 v128, then
	// (only with non-mid dominants) the 2 hysteresis i32 locals.
	appendMatchLocals := func(b []byte, i32Count byte) []byte {
		switch {
		case hystDom:
			b = append(b, 0x03, i32Count, 0x7F, 0x01, 0x7B, 0x02, 0x7F)
		case emitMidDom:
			b = append(b, 0x02, i32Count, 0x7F, 0x01, 0x7B)
		default:
			b = append(b, 0x01, i32Count, 0x7F)
		}
		return b
	}

	// startCellInit emits: cell = startStateAccept ? 1 : 0 (packed paths only).
	// This seeds the accept bit for the empty-input case. For the unpacked path
	// the EOF check reads accept from the side table indexed by state, so cell
	// initialisation is unnecessary.

	if useU8 && useCompression {
		// ── u8 compressed path ────────────────────────────────────────────────
		// Locals: state (2), pos (3), class (4). Phase 4 adds chunk (v128, 5);
		// non-mid dominants add hystCounter (6) + hystPos (7).
		b = appendMatchLocals(b, 0x03)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02) // state = startState

		b = append(b, 0x02, 0x40) // block $done
		b = append(b, 0x03, 0x40) // loop $main

		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x0D, 0x01) // br_if $done

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			0x02, 0x04, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckMatch(b, immAcceptLimit, hasImmAccept, tableMemIdx)

		// Phase 4 dispatch: chunk=local 5, tmp=local 4 (reuse class),
		// hysteresis counter/scratch = locals 6/7 (only with non-mid).
		b = emitPhase4Dispatch(b, dominantStates, midAcceptOff, tableMemIdx)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00) // br $main
		b = append(b, 0x0B)       // end loop
		b = append(b, 0x0B)       // end block $done

		return emitAcceptCheck(b, 0x02, 0x03)
	}

	if useU8 {
		// ── u8 simple path ────────────────────────────────────────────────────
		// Locals: state (2), pos (3). Phase 4 adds tmp (4, i32) + chunk (5, v128);
		// non-mid dominants add hystCounter (6) + hystPos (7).
		if emitMidDom {
			b = appendMatchLocals(b, 0x03)
		} else {
			b = append(b, 0x01, 0x02, 0x7F)
		}

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02) // state = startState

		b = append(b, 0x02, 0x40) // block $done
		b = append(b, 0x03, 0x40) // loop $main

		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x0D, 0x01) // if pos >= len: br_if $done

		b = emitSimpleU8Transition(b, tableOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckMatch(b, immAcceptLimit, hasImmAccept, tableMemIdx)

		// Phase 4 dispatch: tmp=local 4, chunk=local 5, hyst=6/7.
		b = emitPhase4Dispatch(b, dominantStates, midAcceptOff, tableMemIdx)

		b = append(b, 0x20, 0x03) // pos++
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop
		b = append(b, 0x0B) // end block $done

		return emitAcceptCheck(b, 0x02, 0x03)
	}

	// ── u16 path ─────────────────────────────────────────────────────────────
	// Locals: state (2), pos (3), byte (4). Phase 4 adds chunk (v128, 5);
	// non-mid dominants add hystCounter (6) + hystPos (7).
	b = appendMatchLocals(b, 0x03)

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
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x21, 0x04)       // local.set byte

	b = emitU16Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x04, tableMemIdx)

	b = append(b, 0x20, 0x02)
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40) // if state == 0: return -1
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	b = emitImmAcceptCheckMatch(b, immAcceptLimit, hasImmAccept, tableMemIdx)

	// Phase 4 dispatch: chunk=local 5, tmp=local 4 (reuse byte), hyst=6/7.
	b = emitPhase4Dispatch(b, dominantStates, midAcceptOff, tableMemIdx)

	b = append(b, 0x20, 0x03) // pos++
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x03)

	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block $done

	return emitAcceptCheck(b, 0x02, 0x03)
}

// computePrefix returns the longest literal byte prefix shared by all matches,
// found by walking the DFA from midStartState while exactly one byte leads to a
// non-dead state. Returns nil when the start state is accepting (pattern can
// match empty string — no positions can safely be skipped).
func computePrefix(t *dfaTable) []byte {
	state := t.midStartState
	if t.acceptStates[state] != 0 || t.midAcceptStates[state] != 0 {
		return nil // accepting start state: pattern matches empty → can't skip
	}
	if t.startBeginAccept {
		return nil // pattern matches empty at position 0 via begin anchor (e.g. a*^)
	}
	visited := map[int]bool{state: true}
	var prefix []byte
	for {
		only := -1
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
		if visited[state] || t.acceptStates[state] != 0 || t.midAcceptStates[state] != 0 {
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
	if t.midAcceptStates[t.midStartState] != 0 ||
		t.acceptStates[t.midStartState] != 0 ||
		t.immediateAcceptStates[t.midStartState] != 0 {
		return false
	}
	for b := 0; b < 256; b++ {
		if t.transitions[t.midStartState*256+b] >= 0 {
			return false
		}
	}
	if t.hasNewlineBoundary {
		if t.midAcceptStates[t.midStartNewlineState] != 0 ||
			t.acceptStates[t.midStartNewlineState] != 0 ||
			t.immediateAcceptStates[t.midStartNewlineState] != 0 {
			return false
		}
		for b := 0; b < 256; b++ {
			if t.transitions[t.midStartNewlineState*256+b] >= 0 {
				return false
			}
		}
	}
	if t.hasWordBoundary {
		if t.midAcceptStates[t.midStartWordState] != 0 ||
			t.acceptStates[t.midStartWordState] != 0 ||
			t.immediateAcceptStates[t.midStartWordState] != 0 ||
			t.midAcceptNWStates[t.midStartState] != 0 ||
			t.midAcceptWStates[t.midStartWordState] != 0 {
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
//
//	Returns (0 << 32 | end) on match, -1 on no match.
//
// Control flow:
//
//	block $no_match
//	  block $found
//	    [DFA prologue: state=startState, pos=0, last_accept=-1]
//	    loop $scan
//	      if pos >= len  → eofAccept check; br 2→$found
//	      [WB pre-accept; transition; dead → br 2→$found; midAccept; immAccept; pos++]
//	    end $scan
//	  end $found
//	  if last_accept >= 0: return packed i64
//	end $no_match
//	i64.const -1
func buildAnchoredFindBody(startState uint32, tableOff, midAcceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, acceptLimit int32, startBeginAccept bool, immAcceptLimit int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, midAcceptNLOff int32, hasNewlineBoundary bool, tableMemIdx int) []byte {
	var b []byte

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
		b = append(b, 0x20, 0x02)             // local.get state
		b = append(b, 0x6A)                   // i32.add
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)             // if (void)
		b = append(b, 0x41, 0x00)             // i32.const 0
		b = append(b, 0x21, 0x05)             // local.set last_accept
		b = append(b, 0x0B)                   // end if
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
		b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03) // pos
		b = append(b, 0x20, 0x01) // len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, false, 0, acceptLimit, false)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			0x02, 0x06, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02) // dead?
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b, false, 0, 0x00, false)
		b = append(b, 0x0B)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
		b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x04, 0x40)
		b = emitEofHandler(b, false, 0, acceptLimit, false)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

		b = emitSimpleU8Transition(b, tableOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b, false, 0, 0x00, false)
		b = append(b, 0x0B)

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
	b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, 0x03)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x04, 0x40)
	b = emitEofHandler(b, false, 0, acceptLimit, false)
	b = append(b, 0x0B)

	b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
	b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

	// byte = mem[ptr+pos]
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x21, 0x06)       // local.set byte

	b = emitU16Transition(b, tableOff, false, 0, 0x02, 0x06, tableMemIdx)

	b = append(b, 0x20, 0x02)
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40)
	b = emitDeadHandler(b, false, 0, 0x00, false)
	b = append(b, 0x0B)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x05)
	b = append(b, 0x0B)

	b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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

// buildLitAnchorBackScanBody returns the size-prefixed WASM function body for the
// backward scan helper used by the literal-anchored find optimisation.
//
// Signature: (ptr i32, scan_end i32) → i32
//
//   - ptr:      base address of the input buffer (same as the outer find function)
//   - scan_end: index of the last byte to check, scanning leftward (= lit_pos - 1)
//
// Returns the forward match-start position (>= 0) or -1 on no match.
//
// The function runs the reversed-prefix DFA backward through the input, reading
// bytes at positions scan_end, scan_end-1, … 0.  When the DFA accepts or a
// newline boundary is hit, it records last_accept and terminates.
//
// Locals: ptr(0), scan_end(1), state(2), pos(3), last_accept(4), byte_or_class(5)
func buildLitAnchorBackScanBody(revL *dfaLayout, revTable *dfaTable, tableMemIdx int) []byte {
	var b []byte

	// ── local declarations ────────────────────────────────────────────────────
	// 4 extra i32 locals beyond the 2 params: state(2), pos(3), last_accept(4), byte/class(5)
	b = append(b, 0x01, 0x04, 0x7F)

	// state = revL.wasmStart
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(revL.wasmStart))
	b = append(b, 0x21, 0x02) // local.set state

	// pos = scan_end (param 1)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x21, 0x03) // local.set pos

	// last_accept = -1
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x21, 0x04) // local.set last_accept

	// Initial midAccept check: if revMidAccept[wasmStart], the reversed prefix
	// matches the empty string, so the forward match starts at scan_end + 1.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, revL.midAcceptOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(revL.wasmStart))
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[wasmStart]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, 0x01)             // local.get scan_end
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)       // scan_end + 1
	b = append(b, 0x21, 0x04) // local.set last_accept
	b = append(b, 0x0B)       // end if

	// ── main scan loop ────────────────────────────────────────────────────────
	// Control flow depths (from inside $rev loop):
	//   depth 0 = $rev (loop)
	//   depth 1 = $done (block)  — br exits $done
	// From inside an if block inside $rev:
	//   depth 0 = if, depth 1 = $rev (loop), depth 2 = $done (block)
	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $rev

	// if pos < 0 (signed): check EOF accept, then exit.
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if (void) — depth 0
	// if accept[state] != 0: last_accept = 0 (match starts at text start)
	b = emitAcceptBitOnStack(b, 0x02, revL.acceptLimit)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x21, 0x04) // local.set last_accept
	b = append(b, 0x0B)       // end if
	b = append(b, 0x0C, 0x02) // br 2 → $done (0=outer_if, 1=$rev, 2=$done)
	b = append(b, 0x0B)       // end if pos<0

	// byte = mem[ptr + pos]; local.tee byte(5) leaves it on stack for '\n' check.
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x22, 0x05)       // local.tee byte(5) — also leaves value on stack

	if revTable.hasNewlineBoundary {
		// if byte == '\n': check midAcceptNL, record match start, always stop.
		b = append(b, 0x41, 0x0A) // i32.const '\n'
		b = append(b, 0x46)       // i32.eq — depth 0 = this if
		b = append(b, 0x04, 0x40) // if (void)
		// if midAcceptNL[state]: last_accept = pos + 1
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, revL.midAcceptNLOff)
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // midAcceptNL[state]
		b = append(b, 0x04, 0x40)             // if (void)
		b = append(b, 0x20, 0x03)             // local.get pos
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)       // pos + 1
		b = append(b, 0x21, 0x04) // local.set last_accept
		b = append(b, 0x0B)       // end if midAcceptNL
		// Always stop at '\n' for anchored patterns.
		// Depths: 0=nl_if, 1=$rev, 2=$done → br 2 exits $done
		b = append(b, 0x0C, 0x02) // br 2 → $done
		b = append(b, 0x0B)       // end if byte=='\n'
		// Stack now has: nothing (the local.tee result was consumed by i32.eq)
	} else {
		b = append(b, 0x1A) // drop the stacked byte value (local.tee leftover)
	}

	// ── DFA transition ────────────────────────────────────────────────────────
	if revL.useCompression {
		b = emitCompressedU8Transition(b, revL.tableOff, revL.classMapOff, revL.numClasses,
			0x02, 0x05, 0, 0, 0x05, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, revL.tableOff, 0x02, 0, 0, 0x05, tableMemIdx)
	}

	// if state == 0 (dead state): exit $done
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x0C, 0x02) // br 2 → $done (0=dead_if, 1=$rev, 2=$done)
	b = append(b, 0x0B)       // end if dead

	// if midAccept[state]: last_accept = pos (= current position before decrement)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, revL.midAcceptOff)
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, 0x03)             // local.get pos
	b = append(b, 0x21, 0x04)             // local.set last_accept
	b = append(b, 0x0B)                   // end if midAccept

	// pos--
	b = append(b, 0x20, 0x03)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x21, 0x03) // local.set pos

	b = append(b, 0x0C, 0x00) // br 0 → $rev (restart loop)
	b = append(b, 0x0B)       // end loop $rev
	b = append(b, 0x0B)       // end block $done

	// return last_accept
	b = append(b, 0x20, 0x04) // local.get last_accept
	b = append(b, 0x0B)       // end function

	// Prepend size-prefix (required by WASM code section).
	sz := utils.AppendULEB128(nil, uint32(len(b)))
	return append(sz, b...)
}

// buildSimplePrefixCheckBody is a drop-in replacement for
// buildLitAnchorBackScanBody, used when the lit-anchor prefix qualifies as
// simpleClassPrefix (a bare `[class]{M}`, M in [1,16] — see lit_anchor.go).
// Same signature and return semantics as buildLitAnchorBackScanBody —
// (ptr i32, scan_end i32) → i32, returning the match-start position on
// success or -1 on failure — so callers (buildLitAnchorFindBody's `call
// revFuncIdx`) don't need to know which implementation they're calling.
//
// Instead of walking backward one byte at a time through a reverse DFA,
// this verifies all M bytes in one shot with the same SIMD nibble-lookup
// technique Gap E's emitPrefixClassVerify already uses for
// `<class>{M}<literal><class>{N}` patterns — reused here unchanged, just
// reached from the generic lit-anchor path instead of Gap E's bespoke one
// (see simpleClassPrefix's doc comment for why Gap E's own analyser can't
// reach this shape when the suffix is unbounded, e.g. `[^\n]+`).
//
// LikelyNoMatch-gated at the call site (compile.go) rather than always-on:
// this is a strict improvement over the generic walk with no runtime
// trade-off, but it's new code on a path re2test exercises comparatively
// rarely, so it ships gated first and can be promoted to default-on later
// once measured across more of the corpus (same rollout precedent as Opt 1).
func buildSimplePrefixCheckBody(tlo [16]byte, count int) []byte {
	var b []byte

	// Locals beyond the 2 params: base(2) i32; chunk(3), prefixTlo(4), pow2(5) v128.
	const (
		locPtr       = 0
		locScanEnd   = 1
		locBase      = 2
		locChunk     = 3
		locPrefixTlo = 4
		locPow2      = 5
	)
	b = append(b, 0x02, 0x01, 0x7F, 0x03, 0x7B)

	// base = scan_end + 1  (the position right after the last byte to verify —
	// same role as `attempt_start` in emitPrefixClassVerify's other caller).
	b = append(b, 0x20, locScanEnd)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locBase)

	// Hoist v128 tables.
	b = emitV128Const(b, tlo)
	b = append(b, 0x21, locPrefixTlo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	// Bounds: base < count → not enough room for the prefix → -1.
	b = append(b, 0x20, locBase)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(count))
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Class verify (single SIMD chunk); non-zero bad_mask → -1.
	b = emitPrefixClassVerify(b, count, locPtr, locBase, locChunk, locPrefixTlo, locPow2)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Match — return base - count (start of the M-byte prefix window).
	b = append(b, 0x20, locBase)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(count))
	b = append(b, 0x6B)
	b = append(b, 0x0B) // end function

	sz := utils.AppendULEB128(nil, uint32(len(b)))
	return append(sz, b...)
}

// buildLitAnchorFindBody returns the WASM function body for the literal-anchored find
// optimisation.  It performs three phases for each candidate position:
//
//  1. SIMD scan for the first byte of any literal in the literal set.
//  2. Backward DFA scan (call to backward_scan) to find the match start.
//  3. Forward DFA scan from the match start to find the match end.
//
// Signature: (ptr i32, len i32) → i64
// Returns (match_start << 32 | match_end) on success, -1 on no match.
//
// Locals:
//
//	ptr(0), len(1)                                  — params
//	state(2), pos(3), attempt_start(4), last_accept(5) — i32
//	rev_result(6)                                   — i32 (backward_scan result)
//	simdMask_or_class(7)                            — i32 (reused across phases)
//	chunk(8)                                        — v128
//	tLo(9), tHi(10)                                 — v128 (T0 Teddy, if applicable)
//	chunk1(11), t1Lo(12), t1Hi(13)                  — v128 (T1 Teddy, if applicable)
func buildLitAnchorFindBody(t *dfaTable, l *dfaLayout, p *compiledPattern, revFuncIdx int, tableMemIdx int) []byte {
	var b []byte

	// ── local declarations ────────────────────────────────────────────────────
	// When there is a single literal use the hybrid prefix scan (one v128.load
	// per iteration, fast-path skip when the first byte is absent).  For multiple
	// literals fall back to Teddy (two v128.load per iteration) as before.
	usePrefixScan := len(p.litAnchorLitSet) == 1
	hasT0 := !usePrefixScan && len(p.litAnchorTeddyLoBytes) > 0
	hasT1 := !usePrefixScan && len(p.litAnchorTeddyT1LoBytes) > 0
	numI32Locals := 6 // state(2), pos(3), attempt_start(4), last_accept(5), rev_result(6), simdMask_or_class(7)
	var numV128Locals int
	if hasT1 {
		numV128Locals = 6 // chunk(8), tLo(9), tHi(10), chunk1(11), t1Lo(12), t1Hi(13)
	} else if hasT0 {
		numV128Locals = 3 // chunk(8), tLo(9), tHi(10)
	} else if usePrefixScan || (len(p.litAnchorFirstBytes) > 0 && len(p.litAnchorFirstBytes) <= 16) {
		numV128Locals = 1 // chunk(8)
	} else {
		numV128Locals = 0
	}

	// Local group count  (groups share the same type).
	if numV128Locals > 0 {
		b = append(b, 0x02)                      // 2 local groups
		b = append(b, byte(numI32Locals), 0x7F)  // 6 × i32
		b = append(b, byte(numV128Locals), 0x7B) // N × v128
	} else {
		b = append(b, 0x01)                     // 1 local group
		b = append(b, byte(numI32Locals), 0x7F) // 6 × i32
	}

	// Local indices for the DFA locals (also used by emitPrefixScan).
	const (
		locPtr          = 0
		locLen          = 1
		locState        = 2
		locPos          = 3
		locAttemptStart = 4
		locLastAccept   = 5
		locRevResult    = 6
		locSimdOrClass  = 7
		locChunk        = 8
		locTLo          = 9
		locTHi          = 10
		locChunk1       = 11
		locT1Lo         = 12
		locT1Hi         = 13
	)

	// ── outer control flow ────────────────────────────────────────────────────
	// block $no_match (depth 1 from inside $lit_outer)
	// loop $lit_outer (depth 0 from inside the loop body)
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	// ── Phase 1: SIMD scan ───────────────────────────────────────────────────
	// emitPrefixScan uses EngineDepth=2 (loop $lit_outer + block $no_match).
	// OnMatch: nothing — attempt_start is set to the candidate position, fall through.
	//
	// Single-literal case: use hybrid prefix scan (one v128.load per iteration,
	// immediate 16-byte advance when first byte absent — same strategy as the
	// mandatory-lit DFA find path).  The prefix scan fully verifies all bytes of
	// the literal, so the separate scalar verification below is skipped.
	//
	// Multi-literal case: use Teddy as before (first-byte and optional second-byte
	// nibble tables); scalar verification is needed to eliminate Teddy false positives.
	var simdParams prefixScanParams
	if usePrefixScan {
		simdParams = prefixScanParams{
			Prefix:      p.litAnchorLitSet[0],
			EngineDepth: 2,
			TableMemIdx: tableMemIdx,
			Locals: prefixScanLocals{
				Ptr:          locPtr,
				Len:          locLen,
				AttemptStart: locAttemptStart,
				SimdMask:     locSimdOrClass,
				Chunk:        locChunk,
			},
			OnMatch: nil,
		}
	} else {
		simdParams = prefixScanParams{
			FirstByteSet:   p.litAnchorFirstBytes,
			FirstByteFlags: p.litAnchorFirstByteFlags,
			FirstByteOff:   p.litAnchorFirstByteOff,
			TeddyLoOff:     p.litAnchorTeddyLoOff,
			TeddyHiOff:     p.litAnchorTeddyHiOff,
			TeddyTwoByte:   hasT1,
			TeddyT1LoOff:   p.litAnchorTeddyT1LoOff,
			TeddyT1HiOff:   p.litAnchorTeddyT1HiOff,
			EngineDepth:    2,
			TableMemIdx:    tableMemIdx,
			Locals: prefixScanLocals{
				Ptr:          locPtr,
				Len:          locLen,
				AttemptStart: locAttemptStart,
				SimdMask:     locSimdOrClass,
				Chunk:        locChunk,
				TLo:          locTLo,
				THi:          locTHi,
				Chunk1:       locChunk1,
				T1Lo:         locT1Lo,
				T1Hi:         locT1Hi,
			},
			OnMatch: nil,
		}
	}
	b = emitPrefixScan(b, simdParams)

	// ── Scalar literal verification (multi-literal / Teddy only) ─────────────
	// After Teddy places a candidate in attempt_start, verify that one of the
	// literals in litAnchorLitSet actually matches byte-for-byte (Teddy is
	// approximate — nibble tables can produce false positives).
	// Skipped for the single-literal case: the prefix scan above already verified
	// all bytes of the literal exactly.
	//
	// Control-flow depths at this point (outside any nested block):
	//   0 = $lit_outer (loop — br 0 restarts it)
	//   1 = $no_match  (block — br 1 exits it)
	//
	// Inside block $lit_ok:
	//   0 = $lit_ok, 1 = $lit_outer, 2 = $no_match
	// Inside block $try_litN:
	//   0 = $try_litN, 1 = $lit_ok, 2 = $lit_outer, 3 = $no_match
	if !usePrefixScan && len(p.litAnchorLitSet) > 0 {
		b = append(b, 0x02, 0x40) // block $lit_ok
		for _, lit := range p.litAnchorLitSet {
			b = append(b, 0x02, 0x40) // block $try_litN
			for k, byt := range lit {
				// load input[ptr + attempt_start + k]
				b = append(b, 0x20, locPtr)           // local.get ptr
				b = append(b, 0x20, locAttemptStart)  // local.get attempt_start
				b = append(b, 0x6A)                   // i32.add
				b = append(b, 0x2D, 0x00)             // i32.load8_u align=0
				b = utils.AppendULEB128(b, uint32(k)) // offset = k
				// i32.const byt — must use SLEB128 since bytes 64-127 have bit 6 set
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(byt))
				b = append(b, 0x47)       // i32.ne
				b = append(b, 0x0D, 0x00) // br_if 0 → exit $try_litN (try next literal)
			}
			b = append(b, 0x0C, 0x01) // br 1 → exit $lit_ok (literal matched)
			b = append(b, 0x0B)       // end $try_litN
		}
		// No literal matched: advance attempt_start by 1 and restart $lit_outer.
		b = append(b, 0x20, locAttemptStart) // local.get attempt_start
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)                  // i32.add (attempt_start + 1)
		b = append(b, 0x21, locAttemptStart) // local.set attempt_start
		b = append(b, 0x0C, 0x01)            // br 1 → restart $lit_outer (0=$lit_ok, 1=$lit_outer)
		b = append(b, 0x0B)                  // end $lit_ok
		// Literal verified at attempt_start — fall through to backward scan.
	}

	// ── Phase 2: backward scan ────────────────────────────────────────────────
	// Call backward_scan(ptr, attempt_start - 1).
	b = append(b, 0x20, locPtr)          // local.get ptr
	b = append(b, 0x20, locAttemptStart) // local.get attempt_start
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B) // i32.sub  (attempt_start - 1)
	b = append(b, 0x10) // call
	b = utils.AppendULEB128(b, uint32(revFuncIdx))
	b = append(b, 0x21, locRevResult) // local.set rev_result

	// if rev_result < 0 (backward scan failed): advance attempt_start++; restart $lit_outer
	b = append(b, 0x20, locRevResult) // local.get rev_result
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart) // attempt_start++
	b = append(b, 0x0C, 0x01)            // br 1 → $lit_outer (0=if, 1=$lit_outer loop)
	b = append(b, 0x0B)                  // end if

	// ── Phase 3: forward DFA scan from rev_result ─────────────────────────────
	// Initial state:
	//   rev_result == 0              → wasmStart (match starts at input begin)
	//   ptr[rev_result-1] == '\n'    → wasmMidStartNewline
	//   otherwise                    → wasmMidStart
	// For patterns without word boundaries wasmMidStart == wasmMidStartNewline;
	// the byte check is still emitted for correctness and future-proofing.
	b = append(b, 0x20, locRevResult) // local.get rev_result
	b = append(b, 0x45)               // i32.eqz
	b = append(b, 0x04, 0x7F)         // if (result i32) — start of input
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x05) // else
	// load byte at ptr + rev_result - 1
	b = append(b, 0x20, locPtr)       // local.get ptr
	b = append(b, 0x20, locRevResult) // local.get rev_result
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B)             // i32.sub (rev_result - 1)
	b = append(b, 0x6A)             // i32.add (ptr + rev_result - 1)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x41, 0x0A)       // i32.const '\n'
	b = append(b, 0x46)             // i32.eq
	b = append(b, 0x04, 0x7F)       // if (result i32) — preceded by '\n'
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmMidStartNewline))
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmMidStart))
	b = append(b, 0x0B)           // end if newline
	b = append(b, 0x0B)           // end if start
	b = append(b, 0x21, locState) // local.set state

	b = append(b, 0x20, locRevResult)
	b = append(b, 0x21, locPos) // local.set pos = rev_result

	b = append(b, 0x41, 0x7F)
	b = append(b, 0x21, locLastAccept) // last_accept = -1

	// Initial midAccept check at start position.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x21, locLastAccept) // last_accept = pos
	b = append(b, 0x0B)                // end if

	// Optional immediateAccept check at start position.
	// br depth: 0=if, 1=$fwd_done (block, opened just below)
	// We open $fwd_done first, then emit the start immAccept check inside it.
	b = append(b, 0x02, 0x40) // block $fwd_done
	if l.hasImmAccept {
		// state-ID partition: WASM states 1..immAcceptLimit are imm-accepting.
		b = append(b, 0x20, locState) // local.get state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immAcceptLimit) // i32.const immAcceptLimit
		b = append(b, 0x4D)                          // i32.le_u
		b = append(b, 0x04, 0x40)                    // if (void)
		b = append(b, 0x0C, 0x01)                    // br 1 → $fwd_done
		b = append(b, 0x0B)                          // end if
	}

	// Inner forward DFA scan loop.
	// Control flow depths inside $fwd_scan (relative to inner if blocks):
	//   depth 0=if, depth 1=$fwd_scan(loop), depth 2=$fwd_done(block)
	b = append(b, 0x03, 0x40) // loop $fwd_scan

	// if pos >= len: EOF check, then exit $fwd_done.
	b = append(b, 0x20, locPos)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	// if accept[state] != 0: last_accept = pos (EOF accept)
	b = emitAcceptBitOnStack(b, locState, l.acceptLimit)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x21, locLastAccept) // last_accept = pos
	b = append(b, 0x0B)                // end if accept
	b = append(b, 0x0C, 0x02)          // br 2 → $fwd_done (0=eof_if, 1=$fwd_scan, 2=$fwd_done)
	b = append(b, 0x0B)                // end if pos>=len

	b = emitNLPreAcceptCheck(b, l.midAcceptNLOff, t.hasNewlineBoundary, locPos, locState, tableMemIdx)

	// DFA transition.
	if l.useCompression {
		b = emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			locState, locSimdOrClass, locPtr, locPos, 0xff, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, l.tableOff, locState, locPtr, locPos, 0xff, tableMemIdx)
	}

	// if state == 0 (dead): exit $fwd_done.
	b = append(b, 0x20, locState)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x0C, 0x02) // br 2 → $fwd_done (0=dead_if, 1=$fwd_scan, 2=$fwd_done)
	b = append(b, 0x0B)       // end if dead

	// if midAccept[state]: last_accept = pos + 1
	// Suggestion 3: dispatch dominant bulk-skip from inside lit-anchor's
	// forward DFA scan. Mid-accept entries piggyback on the midAccept load
	// (same shape as buildFindBody). Non-mid entries use state-ID compares
	// outside the midAccept block (LM-gated via dominantStates filtering
	// in compile.go).
	hasMidDom := false
	hasNonMidDom := false
	for _, info := range l.dominantStates {
		if info.isMidAccept {
			hasMidDom = true
		} else {
			hasNonMidDom = true
		}
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	if hasMidDom {
		b = append(b, 0x22, locSimdOrClass) // local.tee — cache value
	}
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // pos + 1
	b = append(b, 0x21, locLastAccept)
	if hasMidDom {
		for _, info := range l.dominantStates {
			if !info.isMidAccept {
				continue
			}
			b = append(b, 0x20, locSimdOrClass)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(info.encodedByte))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, true,
				locPos, locLen, locLastAccept, locPtr,
				locChunk, locSimdOrClass)
			b = append(b, 0x0B) // end if (per-dominant gate)
		}
	}
	b = append(b, 0x0B) // end if midAccept
	if hasNonMidDom {
		for _, info := range l.dominantStates {
			if info.isMidAccept {
				continue
			}
			b = append(b, 0x20, locState)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, info.state)
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, false,
				locPos, locLen, locLastAccept, locPtr,
				locChunk, locSimdOrClass)
			b = append(b, 0x0B) // end if (state == K)
		}
	}

	b = emitImmAcceptCheckFindMid(b, l.immAcceptLimit, l.hasImmAccept, locState, locPos, tableMemIdx)

	// pos++; restart scan.
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locPos) // pos++
	b = append(b, 0x0C, 0x00)   // br 0 → $fwd_scan
	b = append(b, 0x0B)         // end loop $fwd_scan
	b = append(b, 0x0B)         // end block $fwd_done

	// if last_accept >= 0: return packed i64 (rev_result << 32 | last_accept).
	b = append(b, 0x20, locLastAccept)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locRevResult)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, locLastAccept)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = append(b, 0x84) // i64.or
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if last_accept >= 0

	// No match from this candidate: advance attempt_start and restart.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart) // attempt_start++
	b = append(b, 0x0C, 0x00)            // br 0 → $lit_outer (restart from here)
	b = append(b, 0x0B)                  // end loop $lit_outer (unreachable)
	b = append(b, 0x0B)                  // end block $no_match

	// No match at all: return -1.
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)       // end function

	return b
}

// altLitAnchorFuncIdx holds one alternation branch's function indices
// (Task 6 v1), resolved at assembleModule time once all prior patterns'
// function counts are known.
type altLitAnchorFuncIdx struct {
	backScan      int
	forwardVerify int
}

// buildAltLitAnchorForwardVerifyBody is buildLitAnchorFindBody's Phase 3
// (forward DFA scan from a confirmed match start) extracted into its own
// function, for the alternation lit-anchor path (Task 6 v1). Unlike the
// single-pattern case, rev_result arrives as a PARAMETER (the caller — the
// shared dispatcher in buildAltLitAnchorFindBody — already called this
// branch's own backward_scan and confirmed rev_result >= 0) rather than
// being produced by an inline backward_scan call inside this function.
//
// Signature: (ptr i32, len i32, rev_result i32) → i64
// Returns (rev_result << 32 | match_end) on success, -1 (no match from this
// rev_result) on failure. Unlike buildLitAnchorFindBody's Phase 3, failure
// here does NOT retry at a later attempt_start — that retry loop lives in
// the caller (the dispatcher tries the next literal/branch, or advances
// attempt_start itself), since this function only verifies ONE candidate.
func buildAltLitAnchorForwardVerifyBody(t *dfaTable, l *dfaLayout, tableMemIdx int) []byte {
	var b []byte

	const (
		locPtr         = 0
		locLen         = 1
		locRevResult   = 2
		locState       = 3
		locPos         = 4
		locLastAccept  = 5
		locSimdOrClass = 6
		locChunk       = 7 // v128; only declared/used when dominant-state bulk-skip applies
	)

	hasMidDom := false
	hasNonMidDom := false
	for _, info := range l.dominantStates {
		if info.isMidAccept {
			hasMidDom = true
		} else {
			hasNonMidDom = true
		}
	}
	needChunk := hasMidDom || hasNonMidDom

	// ── local declarations ────────────────────────────────────────────────
	if needChunk {
		b = append(b, 0x02)       // 2 local groups
		b = append(b, 0x04, 0x7F) // 4 × i32: state, pos, last_accept, simdOrClass
		b = append(b, 0x01, 0x7B) // 1 × v128: chunk
	} else {
		b = append(b, 0x01)       // 1 local group
		b = append(b, 0x04, 0x7F) // 4 × i32
	}

	// Initial state, from rev_result (parameter, not a local computation):
	//   rev_result == 0           → wasmStart (match starts at input begin)
	//   ptr[rev_result-1] == '\n' → wasmMidStartNewline
	//   otherwise                 → wasmMidStart
	b = append(b, 0x20, locRevResult) // local.get rev_result
	b = append(b, 0x45)               // i32.eqz
	b = append(b, 0x04, 0x7F)         // if (result i32) — start of input
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x05)               // else
	b = append(b, 0x20, locPtr)       // local.get ptr
	b = append(b, 0x20, locRevResult) // local.get rev_result
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B)             // i32.sub (rev_result - 1)
	b = append(b, 0x6A)             // i32.add (ptr + rev_result - 1)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x41, 0x0A)       // i32.const '\n'
	b = append(b, 0x46)             // i32.eq
	b = append(b, 0x04, 0x7F)       // if (result i32) — preceded by '\n'
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmMidStartNewline))
	b = append(b, 0x05) // else
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmMidStart))
	b = append(b, 0x0B)           // end if newline
	b = append(b, 0x0B)           // end if start
	b = append(b, 0x21, locState) // local.set state

	b = append(b, 0x20, locRevResult)
	b = append(b, 0x21, locPos) // local.set pos = rev_result

	b = append(b, 0x41, 0x7F)
	b = append(b, 0x21, locLastAccept) // last_accept = -1

	// Initial midAccept check at start position.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x21, locLastAccept) // last_accept = pos
	b = append(b, 0x0B)                // end if

	// Optional immediateAccept check at start position.
	b = append(b, 0x02, 0x40) // block $fwd_done
	if l.hasImmAccept {
		b = append(b, 0x20, locState) // local.get state
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immAcceptLimit) // i32.const immAcceptLimit
		b = append(b, 0x4D)                          // i32.le_u
		b = append(b, 0x04, 0x40)                    // if (void)
		b = append(b, 0x0C, 0x01)                    // br 1 → $fwd_done
		b = append(b, 0x0B)                          // end if
	}

	// Inner forward DFA scan loop.
	b = append(b, 0x03, 0x40) // loop $fwd_scan

	// if pos >= len: EOF check, then exit $fwd_done.
	b = append(b, 0x20, locPos)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitAcceptBitOnStack(b, locState, l.acceptLimit)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x21, locLastAccept) // last_accept = pos
	b = append(b, 0x0B)                // end if accept
	b = append(b, 0x0C, 0x02)          // br 2 → $fwd_done
	b = append(b, 0x0B)                // end if pos>=len

	b = emitNLPreAcceptCheck(b, l.midAcceptNLOff, t.hasNewlineBoundary, locPos, locState, tableMemIdx)

	// DFA transition.
	if l.useCompression {
		b = emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			locState, locSimdOrClass, locPtr, locPos, 0xff, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, l.tableOff, locState, locPtr, locPos, 0xff, tableMemIdx)
	}

	// if state == 0 (dead): exit $fwd_done.
	b = append(b, 0x20, locState)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x0C, 0x02) // br 2 → $fwd_done
	b = append(b, 0x0B)       // end if dead

	// if midAccept[state]: last_accept = pos + 1 (+ dominant bulk-skip dispatch)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	if hasMidDom {
		b = append(b, 0x22, locSimdOrClass) // local.tee — cache value
	}
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // pos + 1
	b = append(b, 0x21, locLastAccept)
	if hasMidDom {
		for _, info := range l.dominantStates {
			if !info.isMidAccept {
				continue
			}
			b = append(b, 0x20, locSimdOrClass)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(info.encodedByte))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, true,
				locPos, locLen, locLastAccept, locPtr,
				locChunk, locSimdOrClass)
			b = append(b, 0x0B) // end if (per-dominant gate)
		}
	}
	b = append(b, 0x0B) // end if midAccept
	if hasNonMidDom {
		for _, info := range l.dominantStates {
			if info.isMidAccept {
				continue
			}
			b = append(b, 0x20, locState)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, info.state)
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = emitDominantBulkSkip(b, info, false,
				locPos, locLen, locLastAccept, locPtr,
				locChunk, locSimdOrClass)
			b = append(b, 0x0B) // end if (state == K)
		}
	}

	b = emitImmAcceptCheckFindMid(b, l.immAcceptLimit, l.hasImmAccept, locState, locPos, tableMemIdx)

	// pos++; restart scan.
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locPos) // pos++
	b = append(b, 0x0C, 0x00)   // br 0 → $fwd_scan
	b = append(b, 0x0B)         // end loop $fwd_scan
	b = append(b, 0x0B)         // end block $fwd_done

	// if last_accept >= 0: return packed i64 (rev_result << 32 | last_accept).
	b = append(b, 0x20, locLastAccept)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locRevResult)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, locLastAccept)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = append(b, 0x84) // i64.or
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if last_accept >= 0

	// No accept found from this rev_result: fail. The caller (the shared
	// dispatcher) tries the next literal/branch or advances attempt_start —
	// this function never retries on its own.
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)       // end function

	sz := utils.AppendULEB128(nil, uint32(len(b)))
	return append(sz, b...)
}

// buildAltLitAnchorFindBody is the shared dispatcher for the alternation
// lit-anchor path (Task 6 v1). It runs ONE Teddy/first-byte scan over the
// union of all branches' literals, and on each candidate position tries
// every branch's literal in declaration order (byte-for-byte verify →
// branch's own backward_scan_i → branch's own forward_verify_i), returning
// on the first branch that verifies successfully.
//
// Returning on first success is correct ONLY because findAltLitAnchorPoints
// requires every branch to share the same fixed prefix length: with a
// shared prefix length P, match_start = literal_pos - P for every branch,
// so the scan order (the order the shared frontend discovers candidate
// positions in) and match-start order coincide. See findAltLitAnchorPoints'
// doc comment for the counterexample this restriction avoids. A future
// generalisation to unequal prefix lengths (TODO.md task 6 follow-up) would
// need a bounded-lookahead/best-of-window loop here instead.
//
// Signature: (ptr i32, len i32) → i64. Returns -1 on no match.
func buildAltLitAnchorFindBody(p *compiledPattern, branchFuncIdxs []altLitAnchorFuncIdx, tableMemIdx int) []byte {
	var b []byte

	hasT0 := len(p.altLitAnchorTeddyLoBytes) > 0
	hasT1 := len(p.altLitAnchorTeddyT1LoBytes) > 0
	numI32Locals := 3 // attempt_start(2), simdMask_or_class(3), rev_result(4)
	var numV128Locals int
	switch {
	case hasT1:
		numV128Locals = 6 // chunk, tLo, tHi, chunk1, t1Lo, t1Hi
	case hasT0:
		numV128Locals = 3 // chunk, tLo, tHi
	case len(p.altLitAnchorFirstBytes) > 0 && len(p.altLitAnchorFirstBytes) <= 64:
		numV128Locals = 1 // chunk (multi-eq SIMD or Shufti, per emitPrefixScan's useSIMD gate)
	default:
		numV128Locals = 0
	}

	const (
		locPtr          = 0
		locLen          = 1
		locAttemptStart = 2
		locSimdOrClass  = 3
		locRevResult    = 4
		locPacked       = 5 // i64
		locChunk        = 6
		locTLo          = 7
		locTHi          = 8
		locChunk1       = 9
		locT1Lo         = 10
		locT1Hi         = 11
	)

	// ── local declarations ────────────────────────────────────────────────
	if numV128Locals > 0 {
		b = append(b, 0x03)                      // 3 local groups
		b = append(b, byte(numI32Locals), 0x7F)  // i32 × numI32Locals
		b = append(b, 0x01, 0x7E)                // i64 × 1 (packed)
		b = append(b, byte(numV128Locals), 0x7B) // v128 × numV128Locals
	} else {
		b = append(b, 0x02)                     // 2 local groups
		b = append(b, byte(numI32Locals), 0x7F) // i32 × numI32Locals
		b = append(b, 0x01, 0x7E)               // i64 × 1 (packed)
	}

	// ── outer control flow ────────────────────────────────────────────────
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $outer

	// ── Shared Teddy/first-byte scan over the union of all literals ───────
	simdParams := prefixScanParams{
		FirstByteSet:   p.altLitAnchorFirstBytes,
		FirstByteFlags: p.altLitAnchorFirstByteFlags,
		FirstByteOff:   p.altLitAnchorFirstByteOff,
		TeddyLoOff:     p.altLitAnchorTeddyLoOff,
		TeddyHiOff:     p.altLitAnchorTeddyHiOff,
		TeddyTwoByte:   hasT1,
		TeddyT1LoOff:   p.altLitAnchorTeddyT1LoOff,
		TeddyT1HiOff:   p.altLitAnchorTeddyT1HiOff,
		EngineDepth:    2, // loop $outer + block $no_match
		TableMemIdx:    tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdOrClass,
			Chunk:        locChunk,
			TLo:          locTLo,
			THi:          locTHi,
			Chunk1:       locChunk1,
			T1Lo:         locT1Lo,
			T1Hi:         locT1Hi,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, simdParams)

	// ── Per-branch verify chain ─────────────────────────────────────────────
	// Teddy has false positives, so every candidate is verified byte-for-byte
	// against every branch's literal(s) before trusting it. Declaration
	// order is the same-position tie-break (mirrors the existing $try_litN
	// chain in buildLitAnchorFindBody and Gap E's $next_branch_i chain).
	//
	// Control-flow depths at this point (outside any nested block):
	//   0 = $outer (loop — br 0 restarts it), 1 = $no_match (block)
	// Inside block $try_lit:
	//   0 = $try_lit, 1 = $outer, 2 = $no_match
	for bi, br := range p.altLitAnchorBranches {
		funcIdx := branchFuncIdxs[bi]
		for _, lit := range br.litSet {
			b = append(b, 0x02, 0x40) // block $try_lit
			for k, byt := range lit {
				b = append(b, 0x20, locPtr)           // local.get ptr
				b = append(b, 0x20, locAttemptStart)  // local.get attempt_start
				b = append(b, 0x6A)                   // i32.add
				b = append(b, 0x2D, 0x00)             // i32.load8_u align=0
				b = utils.AppendULEB128(b, uint32(k)) // offset = k
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(byt))
				b = append(b, 0x47)       // i32.ne
				b = append(b, 0x0D, 0x00) // br_if 0 → exit $try_lit (mismatch, try next literal/branch)
			}

			// Literal matched at attempt_start — call this branch's own
			// backward_scan(ptr, attempt_start - 1).
			b = append(b, 0x20, locPtr)
			b = append(b, 0x20, locAttemptStart)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B) // i32.sub (attempt_start - 1)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(funcIdx.backScan))
			b = append(b, 0x21, locRevResult) // local.set rev_result

			// if rev_result < 0: br_if 0 → exit $try_lit
			b = append(b, 0x20, locRevResult)
			b = append(b, 0x41, 0x00)
			b = append(b, 0x48)       // i32.lt_s
			b = append(b, 0x0D, 0x00) // br_if 0

			// Call this branch's own forward_verify(ptr, len, rev_result).
			b = append(b, 0x20, locPtr)
			b = append(b, 0x20, locLen)
			b = append(b, 0x20, locRevResult)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(funcIdx.forwardVerify))
			b = append(b, 0x22, locPacked) // local.tee packed

			// if packed == -1 (i64 fail sentinel): br_if 0 → exit $try_lit
			b = append(b, 0x42, 0x7F) // i64.const -1
			b = append(b, 0x51)       // i64.eq
			b = append(b, 0x0D, 0x00) // br_if 0

			// Success: return packed.
			b = append(b, 0x20, locPacked)
			b = append(b, 0x0F) // return
			b = append(b, 0x0B) // end $try_lit
		}
	}

	// No branch verified at this candidate: advance attempt_start and retry.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart) // attempt_start++
	b = append(b, 0x0C, 0x00)            // br 0 → restart $outer
	b = append(b, 0x0B)                  // end loop $outer (unreachable)
	b = append(b, 0x0B)                  // end block $no_match

	// No match at all: return -1.
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)       // end function

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
func buildFindBody(startState, midStartState, midStartWordState, midStartNewlineState, prefixEndState, prefixEndStateWord uint32, tableOff, midAcceptOff, firstByteOff int32, prefix []byte, classMapOff int32, numClasses int, useU8, useCompression bool, acceptLimit int32, startBeginAccept bool, immAcceptLimit int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, hasNewlineBoundary bool, firstByteFlags [256]byte, firstBytes []byte, teddyLoOff, teddyHiOff, teddyT1LoOff, teddyT1HiOff int32, teddyTwoByte bool, teddyT2LoOff, teddyT2HiOff int32, teddyThreeByte bool, teddyT3LoOff, teddyT3HiOff int32, teddyFourByte bool, mandatoryLit *mandatoryLit, rowMapOff int32, useRowDedup bool, midAcceptNLOff int32, tableMemIdx int, dominantStates []dominantInfo, lnmAction5 bool, skipSafeOnDead bool, eofSkipSafe bool) []byte {
	// The non-mid-accept dispatch tracked call-site offsets for later
	// patching at assembleModule time. That extension (along with the
	// `nonMidDominantOff` parameter and the `[]int` return slot) was
	// extracted to plans/non_mid_extension.go.archive (Sections 7-9).
	var b []byte

	// useMandatoryLit is true when we have a mandatory literal and no existing prefix scan.
	useMandatoryLit := mandatoryLit != nil && len(prefix) == 0

	// ── helper: word-boundary pre-transition accept check ────────────────────
	// Called at the start of the $scan body, BEFORE taking the byte transition.
	// If the current byte (at ptr+pos) is a word char, checks midAcceptW[state].
	// If non-word, checks midAcceptNW[state].
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
	var chunk3Local byte
	var t3LoLocal byte
	var t3HiLocal byte

	// numV128ForScan computes how many v128 locals emitPrefixScan will
	// actually reference for this pattern's scan strategy, plus whether
	// Opt 1's dominant-self-loop bulk-skip needs its own `chunk` register
	// independent of the scan. buildFindBody previously reserved up to 12
	// v128 locals unconditionally (the full Teddy shape) even when the
	// Shufti/multi-eq or literal-prefix strategies — which reference only
	// `chunk` — were what actually got emitted, or when no SIMD scan ran
	// at all. Declaring dead v128 locals is pure register-allocator noise;
	// this mirrors emitPrefixScan's own strategy-selection logic exactly
	// (prefix_scan.go's useSIMD gate) so the two stay in sync — if that
	// logic changes, this must change with it.
	numV128ForScan := 0
	switch {
	case len(prefix) >= 1:
		numV128ForScan = 1 // hybrid SIMD prefix scan: only `chunk`
	case len(firstBytes) >= 1 && len(firstBytes) <= 8:
		// Teddy: chunk,tLo,tHi always; +3 per extra byte tier.
		numV128ForScan = 3
		if teddyTwoByte {
			numV128ForScan = 6
		}
		if teddyThreeByte {
			numV128ForScan = 9
		}
		if teddyFourByte {
			numV128ForScan = 12
		}
	case len(firstBytes) > 8 && len(firstBytes) <= 16:
		numV128ForScan = 1 // Shufti, unconditional for 9..16
	case len(firstBytes) > 16 && len(firstBytes) <= 64:
		if lnmAction5 || shuftiBeatsScalar(firstBytes) {
			numV128ForScan = 1 // Shufti: density-gated or LikelyNoMatch-forced
		}
		// else: scalar firstByteFlags — no SIMD locals needed
	}
	if len(dominantStates) > 0 && numV128ForScan == 0 {
		numV128ForScan = 1 // Opt 1 bulk-skip needs its own `chunk` register
	}
	// needsDenseSwitch (TODO.md task 25): this pattern hits the exact
	// LikelyNoMatch-forced override task 25 targets (17..64-byte
	// first-byte set, static heuristic would otherwise pick scalar) —
	// always implies numV128ForScan==1 (the Shufti branch above fires
	// whenever lnmAction5 is true in that byte range).
	needsDenseSwitch := lnmAction5 && len(firstBytes) > 16 && len(firstBytes) <= 64 && !shuftiBeatsScalar(firstBytes)
	var denseCounterLocal, denseSkipFlagLocal byte

	// needsBulkHyst (TODO.md task 38): any non-mid-accept dominant present
	// → the dispatch below wraps its bulk-skip in the runtime hysteresis,
	// which needs 2 extra i32 locals (streak counter + pos scratch). The
	// non-mid dispatch is skipped entirely under useMandatoryLit, so no
	// locals are needed there either.
	needsBulkHyst := false
	if !useMandatoryLit {
		for _, info := range dominantStates {
			if !info.isMidAccept {
				needsBulkHyst = true
			}
		}
	}
	var bulkHystCounterLocal, bulkHystPosLocal byte

	// assignV128Locals assigns sequential indices starting at base to
	// exactly the v128 locals numV128ForScan implies are live, leaving
	// the rest at their zero value (never referenced, so never declared).
	// When needsDenseSwitch, also assigns the 2 dense-switch i32 locals
	// immediately after the v128 group; when needsBulkHyst, the 2
	// hysteresis i32 locals follow.
	assignV128Locals := func(base byte) {
		next := base
		if numV128ForScan >= 1 {
			chunkLocal = next
			next++
		}
		if numV128ForScan >= 3 {
			tLoLocal = next
			next++
			tHiLocal = next
			next++
		}
		if numV128ForScan >= 6 {
			chunk1Local = next
			next++
			t1LoLocal = next
			next++
			t1HiLocal = next
			next++
		}
		if numV128ForScan >= 9 {
			chunk2Local = next
			next++
			t2LoLocal = next
			next++
			t2HiLocal = next
			next++
		}
		if numV128ForScan >= 12 {
			chunk3Local = next
			next++
			t3LoLocal = next
			next++
			t3HiLocal = next
			next++
		}
		if needsDenseSwitch {
			denseCounterLocal = next
			next++
			denseSkipFlagLocal = next
			next++
		}
		if needsBulkHyst {
			bulkHystCounterLocal = next
			next++
			bulkHystPosLocal = next
		}
	}
	// appendLocalGroups appends the i32 group (count i32Count), then, only
	// if numV128ForScan > 0, a v128 group, then, only if needsDenseSwitch
	// or needsBulkHyst, a third i32 group (2 or 4 locals) for the
	// dense-switch counter/flag and/or the task 38 hysteresis
	// counter/scratch — matching the existing "skip the group entirely
	// when count is 0" convention used elsewhere in this codebase (e.g.
	// buildBTFindBody in engine_backtrack.go).
	appendLocalGroups := func(b []byte, i32Count byte) []byte {
		trailingI32 := byte(0)
		if needsDenseSwitch {
			trailingI32 += 2
		}
		if needsBulkHyst {
			trailingI32 += 2
		}
		numGroups := byte(1)
		if numV128ForScan > 0 {
			numGroups++
		}
		if trailingI32 > 0 {
			numGroups++
		}
		b = append(b, numGroups, i32Count, 0x7F)
		if numV128ForScan > 0 {
			b = append(b, byte(numV128ForScan), 0x7B)
		}
		if trailingI32 > 0 {
			b = append(b, trailingI32, 0x7F)
		}
		return b
	}

	// Mandatory-lit locals (set in each path branch when useMandatoryLit):
	var litPosLocal, scanStartLocal, simdMaskScanLocal, chunkScanLocal byte

	// ── helper: outer loop prologue ──────────────────────────────────────────
	// Emits: if attempt_start >= len: br $no_match
	//        state=startState, pos=attempt_start, last_accept=-1
	//        if accept[state]: last_accept=pos  (start-state empty-match check)
	emitOuterPrologue := func(b []byte) []byte {
		lenForScan := byte(1) // raw len param
		params := prefixScanParams{
			Prefix:           prefix,
			FirstByteSet:     firstBytes,
			FirstByteFlags:   firstByteFlags,
			FirstByteOff:     firstByteOff,
			TeddyLoOff:       teddyLoOff,
			TeddyHiOff:       teddyHiOff,
			TeddyT1LoOff:     teddyT1LoOff,
			TeddyT1HiOff:     teddyT1HiOff,
			TeddyTwoByte:     teddyTwoByte,
			TeddyT2LoOff:     teddyT2LoOff,
			TeddyT2HiOff:     teddyT2HiOff,
			TeddyThreeByte:   teddyThreeByte,
			TeddyT3LoOff:     teddyT3LoOff,
			TeddyT3HiOff:     teddyT3HiOff,
			TeddyFourByte:    teddyFourByte,
			TableMemIdx:      tableMemIdx,
			LikelyNoMatch:    lnmAction5,
			AllowDenseSwitch: needsDenseSwitch,
			EngineDepth:      2, // loop $outer + block $no_match
			Locals: prefixScanLocals{
				Ptr:           0,
				Len:           lenForScan,
				AttemptStart:  4,
				SimdMask:      simdMaskLocal,
				Chunk:         chunkLocal,
				TLo:           tLoLocal,
				THi:           tHiLocal,
				Chunk1:        chunk1Local,
				T1Lo:          t1LoLocal,
				T1Hi:          t1HiLocal,
				Chunk2:        chunk2Local,
				T2Lo:          t2LoLocal,
				T2Hi:          t2HiLocal,
				Chunk3:        chunk3Local,
				T3Lo:          t3LoLocal,
				T3Hi:          t3HiLocal,
				DenseCounter:  denseCounterLocal,
				DenseSkipFlag: denseSkipFlagLocal,
			},
			OnMatch: func(b []byte) []byte {
				if len(prefix) >= 1 {
					// Prefix scan consumed prefix bytes: start DFA from prefixEndState
					// at pos = attempt_start + len(prefix).
					//
					// For patterns with leading word boundary (`\b` / `\B`), the
					// walk through the prefix differs depending on whether the
					// previous byte was a word char: jumping to prefixEndState
					// (computed from midStartState, prevWasWord=false) skips the
					// boundary check when prev is actually a word char. Select
					// prefixEndStateWord (computed from midStartWordState) in
					// that case — it will be the dead state (0) if `\b` fails
					// at this position, causing the DFA loop to exit immediately
					// and the find loop to advance to the next candidate.
					if hasWordBoundary && prefixEndState != prefixEndStateWord {
						b = append(b, 0x20, 0x04) // local.get attempt_start
						b = append(b, 0x45)       // i32.eqz
						b = append(b, 0x04, 0x7F) // if (result i32)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(prefixEndState))
						b = append(b, 0x05) // else
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, wordCharTableOff)
						b = append(b, 0x20, 0x00) // local.get ptr
						b = append(b, 0x20, 0x04) // local.get attempt_start
						b = append(b, 0x6A)       // ptr + attempt_start
						b = append(b, 0x41, 0x01)
						b = append(b, 0x6B)                   // ... - 1
						b = append(b, 0x2D, 0x00, 0x00)       // i32.load8_u prev byte
						b = append(b, 0x6A)                   // wordCharTableOff + prev_byte
						b = appendTableLoad8u(b, tableMemIdx) // wordChar[prev_byte]
						b = append(b, 0x04, 0x7F)             // if (result i32) prev is word
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(prefixEndStateWord))
						b = append(b, 0x05) // else
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(prefixEndState))
						b = append(b, 0x0B) // end if prev-is-word
						b = append(b, 0x0B) // end if attempt_start == 0
					} else {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(prefixEndState))
					}
					b = append(b, 0x21, 0x02) // state = ...
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
						b = append(b, 0x20, 0x00)             // local.get ptr
						b = append(b, 0x20, 0x04)             // local.get attempt_start
						b = append(b, 0x6A)                   // i32.add
						b = append(b, 0x41, 0x01)             // i32.const 1
						b = append(b, 0x6B)                   // i32.sub
						b = append(b, 0x2D, 0x00, 0x00)       // i32.load8_u (prev byte)
						b = append(b, 0x6A)                   // wordCharTableOff + prev_byte
						b = appendTableLoad8u(b, tableMemIdx) // wordCharTable[prev_byte] (isWordChar)
						b = append(b, 0x04, 0x7F)             // if (result i32)
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
				// Initialise last_accept for the start state before entering the scan loop.
				// Handles empty-input and immediate-accept cases: if midAccept[startState]
				// is set the pattern can match starting here; startBeginAccept covers
				// patterns that accept at the very beginning of the input.
				// last_accept = -1
				b = append(b, 0x41, 0x7F) // i32.const -1
				b = append(b, 0x21, 0x05) // local.set last_accept
				// if midAccept[state]: last_accept = pos
				//
				// Task 38 v2 fix: non-mid dominants are encoded as reserved
				// values 254/255 in this SAME table (see
				// applyDominantStateEncoding / emitFindMidAcceptDispatch) —
				// the plain `val != 0` check this site used to have (a
				// leftover from the pre-v2 design, where non-mid dominants
				// lived in a separate side table) wrongly treated a non-mid-
				// dominant start state as already-accepting, recording a
				// spurious empty match at the attempt's start position.
				// Found via `(?:(?:(?:(?:^)|.)*))$` on inputs containing
				// `\n`: the pattern's single DFA state is simultaneously the
				// start state and a non-mid dominant (midAccept[state]=254),
				// so the old check fired at attempt_start=0 when it should
				// only fire at true EOF. Guard with the same `(val-1) u<
				// 253` idiom already used by the u16 accept path — true iff
				// 1<=val<=253 (plain mid-accept, mid dominant, or Shufti
				// self-loop, all genuinely accepting; false for 0=nothing
				// and 254/255=non-mid dominant). Only emitted when non-mid
				// values can appear in the table at all (mirrors
				// emitFindMidAcceptDispatch's hasNonMidVals gate) — for
				// every other pattern this is byte-identical to the
				// pre-fix emission.
				hasNonMidValsAtStart := false
				for _, info := range dominantStates {
					if !info.isMidAccept {
						hasNonMidValsAtStart = true
						break
					}
				}
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, midAcceptOff)
				b = append(b, 0x20, 0x02)             // local.get state
				b = append(b, 0x6A)                   // i32.add
				b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
				if hasNonMidValsAtStart {
					b = append(b, 0x41, 0x01)
					b = append(b, 0x6B) // val - 1
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(253))
					b = append(b, 0x49) // (val-1) u< 253
				}
				b = append(b, 0x04, 0x40) // if (void)
				b = append(b, 0x20, 0x03) // local.get pos
				b = append(b, 0x21, 0x05) // local.set last_accept
				b = append(b, 0x0B)       // end if
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
		return emitPrefixScan(b, params)
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
		b = append(b, 0x0B) // end block $no_match  (unreachable)
		// no-match path falls through here
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0B)       // end function
		return b
	}

	// emitDFAPrologue emits: state=..., pos=attempt_start, last_accept=-1, midAccept check.
	// Used only for the mandatory-lit code path (which has no prefix scan).
	emitDFAPrologue := func(b []byte) []byte {
		if startState == midStartState && (!hasWordBoundary || midStartState == midStartWordState) && (!hasNewlineBoundary || midStartState == midStartNewlineState) {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
		} else if !hasWordBoundary && !hasNewlineBoundary {
			b = append(b, 0x20, 0x04)
			b = append(b, 0x45)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
			b = append(b, 0x05)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			b = append(b, 0x0B)
		} else if hasNewlineBoundary && !hasWordBoundary {
			b = append(b, 0x20, 0x04)
			b = append(b, 0x45)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
			b = append(b, 0x05)
			b = append(b, 0x20, 0x00)
			b = append(b, 0x20, 0x04)
			b = append(b, 0x6A)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B)
			b = append(b, 0x2D, 0x00, 0x00) // prev byte
			b = append(b, 0x41, 0x0A)       // '\n'
			b = append(b, 0x46)             // i32.eq
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartNewlineState))
			b = append(b, 0x05)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			b = append(b, 0x0B)
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
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (prev byte)
			b = append(b, 0x6A)
			b = appendTableLoad8u(b, tableMemIdx) // wordCharTable[prev_byte]
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartWordState))
			b = append(b, 0x05)
			if hasNewlineBoundary {
				b = append(b, 0x20, 0x00)
				b = append(b, 0x20, 0x04)
				b = append(b, 0x6A)
				b = append(b, 0x41, 0x01)
				b = append(b, 0x6B)
				b = append(b, 0x2D, 0x00, 0x00) // prev byte
				b = append(b, 0x41, 0x0A)       // '\n'
				b = append(b, 0x46)             // i32.eq
				b = append(b, 0x04, 0x7F)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(midStartNewlineState))
				b = append(b, 0x05)
			}
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			if hasNewlineBoundary {
				b = append(b, 0x0B)
			}
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
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
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
	// If attempt_start > lit_pos - minOff: scan_start = lit_pos + 1; br 2 → $lit_outer.
	// Depths from inside if block: 0=if, 1=$outer, 2=$lit_outer.
	emitMLRangeCheck := func(b []byte) []byte {
		b = append(b, 0x20, 0x04)        // local.get attempt_start
		b = append(b, 0x20, litPosLocal) // local.get lit_pos
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, mandatoryLit.minOff)
		b = append(b, 0x6B)                 // i32.sub: lit_pos - MinOff
		b = append(b, 0x4A)                 // i32.gt_s: attempt_start > lit_pos-MinOff?
		b = append(b, 0x04, 0x40)           // if (void)
		b = append(b, 0x20, litPosLocal)    // local.get lit_pos
		b = append(b, 0x41, 0x01)           // i32.const 1
		b = append(b, 0x6A)                 // i32.add
		b = append(b, 0x21, scanStartLocal) // scan_start = lit_pos + 1
		b = append(b, 0x0C, 0x02)           // br 2 → $lit_outer
		b = append(b, 0x0B)                 // end if
		return b
	}

	// emitMLOuterSetup emits: [init scan_start if MinOff>0]; loop $lit_outer; emitPrefixScan(lit);
	// OnMatch: set lit_pos, adjust attempt_start; loop $outer; range check; DFA prologue.
	emitMLOuterSetup := func(b []byte) []byte {
		if mandatoryLit.minOff > 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, mandatoryLit.minOff)
			b = append(b, 0x21, scanStartLocal)
		}
		b = append(b, 0x03, 0x40) // loop $lit_outer
		b = emitPrefixScan(b, prefixScanParams{
			Prefix:      mandatoryLit.bytes,
			EngineDepth: 2, // loop $lit_outer + block $no_match
			// MinPatternLen NOT set: scanStartLocal is a mandatory-lit scan
			// cursor (not attempt_start), so the tightened check would use
			// the wrong operand. Task 8 follow-up #1 fires only via
			// emitOuterPrologue where AttemptStart is the true attempt_start.
			Locals: prefixScanLocals{
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
				b = utils.AppendSLEB128(b, mandatoryLit.maxOff)
				b = append(b, 0x6B)                    // i32.sub
				b = append(b, 0x21, simdMaskScanLocal) // temp = adj
				// Step 2: clamp temp to >= 0
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x48)       // i32.lt_s: temp < 0?
				b = append(b, 0x04, 0x40) // if (void)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x21, simdMaskScanLocal) // temp = 0
				b = append(b, 0x0B)
				// Step 3: take max with attempt_start
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x20, 0x04)
				b = append(b, 0x4A)       // i32.gt_s: temp > attempt_start?
				b = append(b, 0x04, 0x40) // if (void)
				b = append(b, 0x20, simdMaskScanLocal)
				b = append(b, 0x21, 0x04) // attempt_start = temp
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
			// 9 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),lit_pos(7),scan_start(8),simdMask_scan(9),simdMask(10),chunk_scan(11)
			//
			// simdMaskLocal (task 38 v2 fix): emitFindMidAcceptDispatch's
			// hasNonMidVals gate is independent of useMandatoryLit (it only
			// checks whether the pattern has a non-mid dominant state at
			// all), so the "cache midAccept[state] into valLocal" sequence
			// still gets emitted even though the actual dominant dispatch
			// bodies are suppressed here. Without this assignment
			// simdMaskLocal stayed at its Go zero-value (0 = the `ptr`
			// parameter), so every DFA transition on a dominant-state
			// pattern clobbered `ptr` with the loaded table value —
			// corrupting every subsequent ptr+pos memory address for the
			// rest of the scan. Found via `(?m:^(foo.*)$)`: the match ran
			// past the newline to EOF instead of stopping at the line
			// boundary, because `ptr` got overwritten mid-scan.
			litPosLocal = 7
			scanStartLocal = 8
			simdMaskScanLocal = 9
			simdMaskLocal = 10
			chunkScanLocal = 11
			b = append(b, 0x02, 0x09, 0x7F, 0x01, 0x7B)
		} else {
			// 6 i32 + N v128 (N sized to what's actually used — see
			// numV128ForScan)
			simdMaskLocal = 7
			v128Base := byte(8)
			i32Count := byte(6)
			assignV128Locals(v128Base)
			b = appendLocalGroups(b, i32Count)
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, true, 3, acceptLimit, eofSkipSafe)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			0x02, 0x06, 0x00, 0x03, 0xff, tableMemIdx)

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b, true, 3, 0x03, skipSafeOnDead)
		b = append(b, 0x0B) // end if

		// Opt 1 (task 38 v2): one midAccept[state] load feeds the accept
		// update AND both dominant channels via the value ranges written
		// by applyDominantStateEncoding(l, true):
		//   val == 0       → nothing
		//   1 <= val < 254 → mid-accept: last_accept = pos+1 (+ mid dispatch)
		//   val >= 254     → non-mid dominant dispatch (NO last_accept)
		// The val < 254 split is emitted only when non-mid values are in
		// the table, so mid-only patterns keep the exact pre-task-38
		// instruction sequence.
		b = emitFindMidAcceptDispatch(b, dominantStates, useMandatoryLit,
			midAcceptOff, tableMemIdx,
			/*state=*/ 0x02 /*pos=*/, 0x03 /*len=*/, 0x01,
			/*lastAccept=*/ 0x05 /*ptr=*/, 0x00,
			chunkLocal /*val+tmp=*/, 0x06,
			bulkHystCounterLocal, bulkHystPosLocal)

		b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
			// 8 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),lit_pos(6),scan_start(7),simdMask_scan(8),simdMask(9),chunk_scan(10)
			//
			// simdMaskLocal: see the identical fix + explanation in the
			// u8-compressed path above (task 38 v2 fix, `ptr`-clobber bug).
			litPosLocal = 6
			scanStartLocal = 7
			simdMaskScanLocal = 8
			simdMaskLocal = 9
			chunkScanLocal = 10
			b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7B)
		} else {
			// 5 i32 + N v128 (N sized to what's actually used — see
			// numV128ForScan)
			simdMaskLocal = 6
			v128Base := byte(7)
			i32Count := byte(5)
			assignV128Locals(v128Base)
			b = appendLocalGroups(b, i32Count)
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, true, 3, acceptLimit, eofSkipSafe)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

		b = emitSimpleU8Transition(b, tableOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b, true, 3, 0x03, skipSafeOnDead)
		b = append(b, 0x0B) // end if

		// Opt 1 (task 38 v2): one midAccept[state] load feeds the accept
		// update and both dominant channels — see the u8+compressed path
		// above and emitFindMidAcceptDispatch for the value-range scheme.
		b = emitFindMidAcceptDispatch(b, dominantStates, useMandatoryLit,
			midAcceptOff, tableMemIdx,
			/*state=*/ 0x02 /*pos=*/, 0x03 /*len=*/, 0x01,
			/*lastAccept=*/ 0x05 /*ptr=*/, 0x00,
			chunkLocal /*val+tmp=*/, simdMaskLocal,
			bulkHystCounterLocal, bulkHystPosLocal)

		b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
		litPosLocal = 7
		scanStartLocal = 8
		simdMaskScanLocal = 9
		chunkScanLocal = 10
		b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7B)
	} else {
		// 6 i32 + N v128 (N sized to what's actually used — see
		// numV128ForScan)
		simdMaskLocal = 7
		v128Base := byte(8)
		i32Count := byte(6)
		assignV128Locals(v128Base)
		b = appendLocalGroups(b, i32Count)
	}
	b = append(b, 0x02, 0x40) // block $no_match
	if useMandatoryLit {
		b = emitMLOuterSetup(b)
	} else {
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitOuterPrologue(b)
	}
	b = append(b, 0x02, 0x40) // block $found
	b = emitImmAcceptCheckFindStart(b, immAcceptLimit, hasImmAccept, tableMemIdx)
	b = append(b, 0x03, 0x40) // loop $scan

	// pos >= len?
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitEofHandler(b, true, 3, acceptLimit, eofSkipSafe)
	b = append(b, 0x0B) // end if

	b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, tableMemIdx)
	b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x03, 0x02, tableMemIdx)

	// byte = mem[ptr+pos]
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x21, 0x06)       // local.set byte

	b = emitU16Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x06, tableMemIdx)

	// dead state?
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = emitDeadHandler(b, true, 3, 0x03, skipSafeOnDead)
	b = append(b, 0x0B) // end if

	// if midAccept[state]: last_accept = pos + 1
	// The u16 path emits no dominant dispatch, but when non-mid entries
	// exist the table carries their reserved 254+ encodings (task 38 v2),
	// which must NOT be treated as accepting: `(val-1) u< 253` accepts
	// exactly the 1..253 range in a single unsigned compare.
	hasNonMidU16 := false
	for _, info := range dominantStates {
		if !info.isMidAccept {
			hasNonMidU16 = true
		}
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	if hasNonMidU16 {
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6B) // i32.sub (val - 1)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, 253)
		b = append(b, 0x49) // i32.lt_u — true iff val in 1..253
	}
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x05) // local.set last_accept
	b = append(b, 0x0B)       // end if

	b = emitImmAcceptCheckFindMid(b, immAcceptLimit, hasImmAccept, 0x02, 0x03, tableMemIdx)

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

// ============================================================================
// Lit-chain optimisation (LIKELY.md Opt 2 — counted linear chain)
//
// Detects patterns of shape  <literal_prefix><charclass>{N,N}  and emits a
// specialised match/find body that:
//   - uses the existing SIMD hybrid prefix scan to locate the literal (find mode),
//   - then verifies the N class bytes with a single nibble-table lookup per byte
//     in 16-byte SIMD chunks, bypassing the per-byte DFA loop entirely.
//
// All SIMD lookup tables (Tlo, Pow2, lane mask) are materialised inline as
// v128.const — the lit-chain bodies emit zero data segments.
//
// Gated by CompileOptions.LikelyMode == LikelyMatch in compilePattern.
// ============================================================================

// litChainPattern is the structural shape recognised by analyseLitChain.
type litChainPattern struct {
	literal  []byte   // K-byte literal prefix (K >= 1)
	tlo      [16]byte // nibble table: bit h of Tlo[l] set iff byte (h<<4|l) ∈ class
	count    int      // N — minimum chain length (N >= 1, K+N >= 16)
	countMax int      // M — maximum chain length (M >= N). Equals count for {N,N}.
	greedy   bool     // false for `{N,M}?`; only matters when count < countMax
	// Gap E: optional class prefix `<class>{prefixCount}` BEFORE the literal.
	prefixCount  int      // 0 = no prefix (classic shape)
	prefixBitmap [32]byte // scalar prefix verify
	prefixTlo    [16]byte // SIMD prefix verify
	startAnchor  anchorType
	endAnchor    anchorType
}

// litChainBranchInfo is the analysis result for a single lit-chain branch.
// Returned by analyseLitChainBranch *without* applying the N≥24 single-pattern
// gate — callers decide per-context (single-pattern gate vs. per-branch gate
// inside an alternation).
//
// Gap E: optional class prefix `<class>{prefixCount}` BEFORE the literal.
// prefixCount == 0 → original `<literal><class>{N,N}` shape.
// prefixCount > 0  → mixed-prefix shape `<class>{prefixCount}<literal><class>{N,N}`.
type litChainBranchInfo struct {
	literal  []byte
	bitmap   [32]byte // 256-bit byte-class bitmap (for scalar SUFFIX verify)
	tlo      [16]byte // nibble table (for SIMD SUFFIX verify)
	count    int      // N (min)
	countMax int      // M (max); equals count for {N,N}
	greedy   bool     // false for `{N,M}?`

	// Gap E: prefix-class fields. prefixCount == 0 means no prefix.
	prefixCount  int      // M_prefix (fixed; ranges deferred)
	prefixBitmap [32]byte // 256-bit byte-class bitmap (scalar prefix verify)
	prefixTlo    [16]byte // nibble table (SIMD prefix verify)

	// Optional anchors. `(?m)^` / `(?m)$` (multiline) are NOT supported and
	// cause analyseLitChainBranch to reject. `\A`/`\z` and (default-Perl) `^`/`$`
	// both map to anchorBeginText/anchorEndText.
	startAnchor anchorType // anchor BEFORE the prefix (or literal if prefixCount==0)
	endAnchor   anchorType // anchor AFTER the suffix class chain
}

// anchorType represents the kind of boundary anchor attached to a lit-chain branch.
type anchorType int

const (
	anchorNone           anchorType = iota
	anchorBeginText                 // ^ (default Perl OneLine) or \A → match start position == 0
	anchorEndText                   // $ (default Perl OneLine) or \z → match end position == len
	anchorWordBoundary              // \b
	anchorNoWordBoundary            // \B
)

// analyseLitChain parses the pattern and returns a litChainPattern when the
// pattern matches the strict shape <literal><charclass>{N,N} with all of:
//   - literal is ASCII (no FoldCase, no rune > 127), K >= 1
//   - class is OpCharClass / OpLiteral / OpAnyCharNotNL / OpAnyChar, ASCII-only
//   - N >= 1 (counted, not range)
//   - K + N >= 16 (so the SIMD overlap-load tail covers all class bytes)
//   - N >= minCount (LM-1: callers pass 24 under neutral/LikelyNoMatch, 1
//     under LikelyMatch — see plans/LM_TODO.md LM-1)
func analyseLitChain(pattern string, minCount int) (*litChainPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	return analyseLitChainRe(re, minCount)
}

func analyseLitChainRe(re *syntax.Regexp, minCount int) (*litChainPattern, bool) {
	info, ok := analyseLitChainBranch(re)
	if !ok || info.prefixCount > 0 {
		return nil, false
	}
	// Existing {N,N} emission only — ranges (countMax > count) handled by the
	// range-aware analyser. Non-greedy {N,N} (degenerate) is fine.
	if info.countMax != info.count {
		return nil, false
	}
	// N≥24 single-pattern gate (neutral/LikelyNoMatch). Empirically (wasmtime
	// 42 / Cranelift), inline SIMD class verify pessimises register
	// allocation for the scan loop when the verify is small — a ~70%
	// wall-time regression appears at N=16 despite fuel parity. The win
	// flips clearly positive by N=36 and grows with N. 24 is the empirical
	// threshold. (Per-branch gate inside alternations applies separately in
	// analyseLitChainAlt.) LM-1: under LikelyMatch, the wall-time-only
	// regression that justified 24 is suspected to be placement noise (see
	// plans/LM_TODO.md LM-1) rather than a fuel cost, so callers pass a lower
	// minCount to trade a possible sparse-input wall-time cost for a large
	// dense-input fuel win.
	if info.count < minCount {
		return nil, false
	}
	return &litChainPattern{
		literal:     info.literal,
		tlo:         info.tlo,
		count:       info.count,
		countMax:    info.countMax,
		greedy:      info.greedy,
		startAnchor: info.startAnchor,
		endAnchor:   info.endAnchor,
	}, true
}

// litChainAltBranch is one branch inside a lit-chain alternation, plus a
// per-branch decision about whether to use SIMD or scalar class verify.
type litChainAltBranch struct {
	literal  []byte
	bitmap   [32]byte // 256-bit byte-class bitmap (for scalar verify when useSIMD=false)
	tlo      [16]byte // nibble table (for SIMD verify when useSIMD=true)
	count    int      // N (min)
	countMax int      // M (max); equals count for {N,N}
	greedy   bool     // false for `{N,M}?`
	useSIMD  bool     // N >= 24 → SIMD chunks; else scalar byte-by-byte
	// Gap E: optional class prefix.
	prefixCount  int
	prefixBitmap [32]byte
	prefixTlo    [16]byte
	startAnchor  anchorType
	endAnchor    anchorType
}

// litChainAltPattern is an alternation of lit-chain branches recognised by
// analyseLitChainAlt. All branches qualify under analyseLitChainBranch; the
// per-branch useSIMD bit selects the verify kernel for each branch.
type litChainAltPattern struct {
	branches []litChainAltBranch
}

// analyseLitChainRange parses pattern as a single lit-chain branch with a
// range count `{N,M}` where N < M. Only **greedy** ranges qualify here; non-
// greedy `{N,M}?` collapses to `{N,N}` in find/groups context and is handled
// by the standard analyser. Anchored match treats greedy and non-greedy the
// same; callers requesting the anchored path use this analyser for both.
//
// Gate: N ≥ minCount (same scan-loop register-pressure concern as {N,N};
// callers pass 24 under neutral/LikelyNoMatch, 1 under LikelyMatch — LM-1,
// see plans/LM_TODO.md).
func analyseLitChainRange(pattern string, minCount int) (*litChainPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	info, ok := analyseLitChainBranch(re)
	if !ok || info.prefixCount > 0 {
		return nil, false
	}
	if info.countMax <= info.count {
		return nil, false // not a range
	}
	if info.count < minCount {
		return nil, false
	}
	return &litChainPattern{
		literal:     info.literal,
		tlo:         info.tlo,
		count:       info.count,
		countMax:    info.countMax,
		greedy:      info.greedy,
		startAnchor: info.startAnchor,
		endAnchor:   info.endAnchor,
	}, true
}

// analyseLitChainAltRange parses pattern as an OpAlternate of lit-chain
// branches, where at least one branch is a range `{N,M}`. All branches must
// qualify under analyseLitChainBranch (count ≥ 1, K+min ≥ 16, ASCII class).
// For non-greedy branches in find/groups context, callers normalise per
// branch via the existing collapse-to-{N,N} mechanism.
func analyseLitChainAltRange(pattern string) (*litChainAltPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return nil, false
	}
	branches := make([]litChainAltBranch, 0, len(re.Sub))
	hasRange := false
	for _, sub := range re.Sub {
		info, ok := analyseLitChainBranch(sub)
		if !ok || info.prefixCount > 0 {
			return nil, false
		}
		if info.countMax > info.count {
			hasRange = true
		}
		branches = append(branches, litChainAltBranch{
			literal:     info.literal,
			bitmap:      info.bitmap,
			tlo:         info.tlo,
			count:       info.count,
			countMax:    info.countMax,
			greedy:      info.greedy,
			useSIMD:     info.count >= 24,
			startAnchor: info.startAnchor,
			endAnchor:   info.endAnchor,
		})
	}
	if !hasRange {
		return nil, false // pure {N,N} alternation — handled by analyseLitChainAlt
	}
	return &litChainAltPattern{branches: branches}, true
}

// analyseLitChainAltPrefixed parses pattern as a strict alternation where
// every branch matches Gap E mixed-prefix shape `<class>{M}<literal><class>{N,N}`.
// All branches must have prefixCount > 0 (otherwise the classic strict-alt
// path handles it).
func analyseLitChainAltPrefixed(pattern string) (*litChainAltPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return nil, false
	}
	branches := make([]litChainAltBranch, 0, len(re.Sub))
	allPrefixed := true
	for _, sub := range re.Sub {
		info, ok := analyseLitChainBranch(sub)
		if !ok {
			return nil, false
		}
		if info.countMax != info.count {
			return nil, false // ranges not supported with prefix yet
		}
		if info.prefixCount == 0 {
			allPrefixed = false
			break
		}
		branches = append(branches, litChainAltBranch{
			literal:      info.literal,
			bitmap:       info.bitmap,
			tlo:          info.tlo,
			count:        info.count,
			countMax:     info.countMax,
			greedy:       info.greedy,
			useSIMD:      info.count >= 24,
			prefixCount:  info.prefixCount,
			prefixBitmap: info.prefixBitmap,
			prefixTlo:    info.prefixTlo,
			startAnchor:  info.startAnchor,
			endAnchor:    info.endAnchor,
		})
	}
	if !allPrefixed || len(branches) < 2 {
		return nil, false
	}
	return &litChainAltPattern{branches: branches}, true
}

// shouldTryLitChainAlt reports whether the lit-chain-alt/lenient family of
// analysis functions (analyseLitChainAlt/Range/Lenient) should even be
// attempted for pattern, when it's a strict find-mode alternation. Returns
// false only for the one shape measured to regress badly there: every
// branch is a SIMPLE chain (literal/class/repeat concatenation, no internal
// alternation or optionality) AND at least one such branch is unbounded
// (`+`, `*`, or open `{N,}`) — e.g. a JWT-style `<lit><class>+.<lit>
// <class>+...` branch. For that shape, falling through to the classic DFA
// below is measured to be cheaper. Returns true (try lit-chain-alt as
// before) in every other case, including when it doesn't apply at all.
//
// Measured via perftest (secrets-combined-range / probe-sparse-allbounded
// vs. secrets-combined / probe-sparse-hasunbounded, a dense- and a
// sparse-first-byte variant of each): when every branch is a bounded {N,M}
// simple chain, lit-chain-alt/lenient costs 74-175% LESS fuel than the
// classic DFA (a clear win), regardless of first-byte density. When at
// least one SIMPLE-chain branch is unbounded, the classic DFA is cheaper on
// dense first-byte sets (~29% less fuel) and roughly tied on sparse ones
// (~3% less) — DFA is never worse there.
//
// The "simple chain" restriction is load-bearing, not cosmetic: an earlier
// version of this check flagged a branch as "unbounded" the moment it found
// ANY unbounded repeat anywhere in the subtree, with no regard for what
// else was in that branch. sql-inject's first branch,
// `'\s*(?:OR|AND)\s+[0-9]+\s*=\s*[0-9]+`, has an unbounded `\s*` sitting
// right next to an internal `(?:OR|AND)` alternation — the naive check
// found the `\s*` first and flagged the whole pattern as "route to DFA",
// which regressed sql-inject +126-140% fuel (it was already correctly
// matching analyseLitChainAltLenient and winning there). sql-inject's
// branches are a structurally different, more complex shape (internal
// alternation/optionality) than the validated JWT-chain case, and were
// never part of the measurement that justified this gate — hence the
// explicit hasComplexStructure check below, which disqualifies a branch
// from the "route to DFA" decision the moment it contains its own
// OpAlternate or OpQuest anywhere, before ever looking for unbounded
// repeats. An earlier, unrelated attempt to gate on first-byte rarity
// (mirroring compile/byte_rarity.go's shuftiBeatsScalar) also gave the
// wrong answer on secrets-combined-range specifically — density isn't the
// signal here, branch shape is.
//
// Returns true for anything that isn't a plain top-level alternation (so
// the caller behaves exactly as before) — harmless, since
// analyseLitChainAlt/Range/Lenient all require OpAlternate themselves and
// would refuse such patterns anyway; this never affects single-branch
// lit-chain patterns or non-alternation shapes.
func shouldTryLitChainAlt(pattern string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return true
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return true
	}

	var hasComplexStructure func(*syntax.Regexp) bool
	hasComplexStructure = func(n *syntax.Regexp) bool {
		if n.Op == syntax.OpAlternate || n.Op == syntax.OpQuest {
			return true
		}
		for _, sub := range n.Sub {
			if hasComplexStructure(sub) {
				return true
			}
		}
		return false
	}
	var hasUnbounded func(*syntax.Regexp) bool
	hasUnbounded = func(n *syntax.Regexp) bool {
		switch n.Op {
		case syntax.OpStar, syntax.OpPlus:
			return true
		case syntax.OpRepeat:
			if n.Max < 0 {
				return true
			}
		}
		for _, sub := range n.Sub {
			if hasUnbounded(sub) {
				return true
			}
		}
		return false
	}

	for _, branch := range re.Sub {
		if hasComplexStructure(branch) {
			// Not the validated simple-chain shape — don't force DFA,
			// leave the existing analysis to decide as before.
			return true
		}
		if hasUnbounded(branch) {
			return false // simple chain, unbounded — route to classic DFA
		}
	}
	return true // every branch is a simple, fully-bounded chain — keep lit-chain-alt eligible
}

// analyseLitChainAlt parses pattern and returns a litChainAltPattern when the
// pattern is an OpAlternate of two or more <literal><class>{N,N} branches
// (strict mode — every branch must qualify). Returns nil otherwise.
func analyseLitChainAlt(pattern string) (*litChainAltPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return nil, false
	}
	branches := make([]litChainAltBranch, 0, len(re.Sub))
	for _, sub := range re.Sub {
		info, ok := analyseLitChainBranch(sub)
		if !ok || info.prefixCount > 0 {
			return nil, false // strict: every branch must qualify
		}
		if info.countMax != info.count {
			return nil, false // ranges handled by analyseLitChainAltRange
		}
		branches = append(branches, litChainAltBranch{
			literal:     info.literal,
			bitmap:      info.bitmap,
			tlo:         info.tlo,
			count:       info.count,
			countMax:    info.countMax,
			greedy:      info.greedy,
			useSIMD:     info.count >= 24,
			startAnchor: info.startAnchor,
			endAnchor:   info.endAnchor,
		})
	}
	return &litChainAltPattern{branches: branches}, true
}

// analyseLitChainBranch inspects a single <literal><class>{N,N} sub-expression
// (after stripping any OpCapture wrapper) and returns full per-branch info.
// Does NOT apply the N≥24 gate — that decision belongs to the caller.
// Constraints enforced: ASCII-only class, K>=1, N>=1 (fixed count), K+N>=16.
func analyseLitChainBranch(re *syntax.Regexp) (*litChainBranchInfo, bool) {
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return nil, false
	}

	// Peel optional start anchor (Sub[0]) and end anchor (Sub[N-1]).
	subs := re.Sub
	startAnchor := anchorNone
	endAnchor := anchorNone

	classifyAnchor := func(n *syntax.Regexp) (anchorType, bool) {
		switch n.Op {
		case syntax.OpBeginText:
			return anchorBeginText, true
		case syntax.OpEndText:
			return anchorEndText, true
		case syntax.OpWordBoundary:
			return anchorWordBoundary, true
		case syntax.OpNoWordBoundary:
			return anchorNoWordBoundary, true
		case syntax.OpBeginLine, syntax.OpEndLine:
			// (?m)^ or (?m)$ — multiline anchors are out of scope.
			return anchorNone, false
		}
		return anchorNone, false
	}
	// Reject if a multiline anchor appears anywhere in subs.
	for _, sub := range subs {
		if sub.Op == syntax.OpBeginLine || sub.Op == syntax.OpEndLine {
			return nil, false
		}
	}
	// Strip leading anchor.
	if a, ok := classifyAnchor(subs[0]); ok {
		startAnchor = a
		subs = subs[1:]
	}
	// Strip trailing anchor.
	if len(subs) > 0 {
		if a, ok := classifyAnchor(subs[len(subs)-1]); ok {
			endAnchor = a
			subs = subs[:len(subs)-1]
		}
	}
	// Patterns like `\b(literal class{N})\b` leave a single OpCapture wrapping
	// the inner OpConcat after the anchors are peeled. Unwrap so the shape
	// check below sees the [OpLiteral, OpRepeat] children directly.
	if len(subs) == 1 && subs[0].Op == syntax.OpCapture && len(subs[0].Sub) == 1 &&
		subs[0].Sub[0].Op == syntax.OpConcat {
		subs = subs[0].Sub[0].Sub
	}
	// Accepted shapes (after anchor strip + capture unwrap):
	//   2 elements: [OpLiteral, OpRepeat(class)]                    — classic lit-chain
	//   3 elements: [OpRepeat(class), OpLiteral, OpRepeat(class)]   — Gap E mixed-prefix
	if len(subs) != 2 && len(subs) != 3 {
		return nil, false
	}
	hasPrefix := len(subs) == 3
	var prefixNode *syntax.Regexp
	var litIdx int
	if hasPrefix {
		prefixNode = subs[0]
		for prefixNode.Op == syntax.OpCapture && len(prefixNode.Sub) == 1 {
			prefixNode = prefixNode.Sub[0]
		}
		if prefixNode.Op != syntax.OpRepeat {
			return nil, false
		}
		litIdx = 1
	}
	litNode := subs[litIdx]
	for litNode.Op == syntax.OpCapture && len(litNode.Sub) == 1 {
		litNode = litNode.Sub[0]
	}
	if litNode.Op != syntax.OpLiteral {
		return nil, false
	}
	if litNode.Flags&syntax.FoldCase != 0 {
		return nil, false
	}
	literal := make([]byte, 0, len(litNode.Rune))
	for _, r := range litNode.Rune {
		if r > 127 {
			return nil, false
		}
		literal = append(literal, byte(r))
	}
	if len(literal) == 0 {
		return nil, false
	}

	chainNode := subs[litIdx+1]
	for chainNode.Op == syntax.OpCapture && len(chainNode.Sub) == 1 {
		chainNode = chainNode.Sub[0]
	}
	if chainNode.Op != syntax.OpRepeat {
		return nil, false
	}
	if chainNode.Min < 1 || chainNode.Max < chainNode.Min {
		return nil, false
	}
	greedy := (chainNode.Flags & syntax.NonGreedy) == 0
	if len(chainNode.Sub) != 1 {
		return nil, false
	}
	child := chainNode.Sub[0]
	for child.Op == syntax.OpCapture && len(child.Sub) == 1 {
		child = child.Sub[0]
	}

	var bitmap [32]byte
	switch child.Op {
	case syntax.OpCharClass:
		for i := 0; i+1 < len(child.Rune); i += 2 {
			lo, hi := child.Rune[i], child.Rune[i+1]
			if lo > 127 || hi > 127 {
				return nil, false
			}
			for r := lo; r <= hi; r++ {
				bitmap[r>>3] |= 1 << uint(r&7)
			}
		}
	case syntax.OpLiteral:
		if len(child.Rune) != 1 || child.Rune[0] > 127 {
			return nil, false
		}
		r := child.Rune[0]
		bitmap[r>>3] |= 1 << uint(r&7)
	default:
		return nil, false
	}

	empty := true
	for _, b := range bitmap {
		if b != 0 {
			empty = false
			break
		}
	}
	if empty {
		return nil, false
	}
	for i := 16; i < 32; i++ {
		if bitmap[i] != 0 {
			return nil, false
		}
	}

	count := chainNode.Min
	countMax := chainNode.Max
	if len(literal)+count < 16 {
		// Overlap-load tail requires K+N >= 16. Tiny patterns: defer.
		return nil, false
	}

	var tlo [16]byte
	for b := 0; b < 128; b++ {
		if bitmap[b>>3]&(1<<uint(b&7)) != 0 {
			tlo[b&0xF] |= 1 << uint(b>>4)
		}
	}

	info := &litChainBranchInfo{
		literal:     literal,
		bitmap:      bitmap,
		tlo:         tlo,
		count:       count,
		countMax:    countMax,
		greedy:      greedy,
		startAnchor: startAnchor,
		endAnchor:   endAnchor,
	}

	// Gap E: parse the prefix class chain if present.
	if hasPrefix {
		// Fixed count `{M,M}` only for now; ranges deferred.
		if prefixNode.Min != prefixNode.Max || prefixNode.Min < 1 {
			return nil, false
		}
		// Non-greedy on the prefix is degenerate when Min==Max; accept either.
		if len(prefixNode.Sub) != 1 {
			return nil, false
		}
		prefChild := prefixNode.Sub[0]
		for prefChild.Op == syntax.OpCapture && len(prefChild.Sub) == 1 {
			prefChild = prefChild.Sub[0]
		}
		var prefixBitmap [32]byte
		switch prefChild.Op {
		case syntax.OpCharClass:
			for i := 0; i+1 < len(prefChild.Rune); i += 2 {
				lo, hi := prefChild.Rune[i], prefChild.Rune[i+1]
				if lo > 127 || hi > 127 {
					return nil, false
				}
				for r := lo; r <= hi; r++ {
					prefixBitmap[r>>3] |= 1 << uint(r&7)
				}
			}
		case syntax.OpLiteral:
			if len(prefChild.Rune) != 1 || prefChild.Rune[0] > 127 {
				return nil, false
			}
			r := prefChild.Rune[0]
			prefixBitmap[r>>3] |= 1 << uint(r&7)
		default:
			return nil, false
		}
		emptyP := true
		for _, b := range prefixBitmap {
			if b != 0 {
				emptyP = false
				break
			}
		}
		if emptyP {
			return nil, false
		}
		for i := 16; i < 32; i++ {
			if prefixBitmap[i] != 0 {
				return nil, false
			}
		}
		// Prefix length M: keep small enough that a single SIMD chunk verifies
		// it. M ≤ 16 is the simplest case.
		if prefixNode.Min > 16 {
			return nil, false
		}
		var prefixTlo [16]byte
		for b := 0; b < 128; b++ {
			if prefixBitmap[b>>3]&(1<<uint(b&7)) != 0 {
				prefixTlo[b&0xF] |= 1 << uint(b>>4)
			}
		}
		info.prefixCount = prefixNode.Min
		info.prefixBitmap = prefixBitmap
		info.prefixTlo = prefixTlo
	}

	return info, true
}

// isWordByte reports whether byte b is in [A-Za-z0-9_] (Perl \w semantics for ASCII).
func isWordByte(b byte) bool {
	return ('A' <= b && b <= 'Z') ||
		('a' <= b && b <= 'z') ||
		('0' <= b && b <= '9') ||
		b == '_'
}

// emitIsWordByte expects an i32 byte value on the stack and replaces it with
// 1 (word char) or 0 (non-word char). Uses tmpLocal (i32) as scratch.
//
// All i32.const values use AppendSLEB128 — values 0x40..0x7F have bit 6 set
// and would otherwise be sign-extended into negative numbers by single-byte
// SLEB128.
func emitIsWordByte(b []byte, tmpLocal byte) []byte {
	// Stack: byte_val
	b = append(b, 0x22, tmpLocal) // local.tee tmp (byte stays on stack)

	// (byte - 'A') < 26 → upper case
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 'A')
	b = append(b, 0x6B) // i32.sub
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 26)
	b = append(b, 0x49) // i32.lt_u

	// OR with (byte - 'a') < 26 → lower case
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 'a')
	b = append(b, 0x6B)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 26)
	b = append(b, 0x49)
	b = append(b, 0x72) // i32.or

	// OR with (byte - '0') < 10 → digit
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, '0')
	b = append(b, 0x6B)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 10)
	b = append(b, 0x49)
	b = append(b, 0x72)

	// OR with (byte == '_')
	b = append(b, 0x20, tmpLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, '_')
	b = append(b, 0x46) // i32.eq
	b = append(b, 0x72)
	return b
}

// emitStartAnchorCheck emits a check at the start position (attempt_start) and
// br_if's to failBrDepth on anchor failure. Falls through on success.
//   - anchorBeginText: requires attempt_start == 0.
//   - anchorWordBoundary / anchorNoWordBoundary: requires (or rejects) a word
//     boundary between input[attempt_start-1] (or non-word if at start) and
//     literalFirstByte (known at compile time).
//   - anchorEndText as start anchor is impossible for a non-empty match;
//     emits an unconditional fail.
func emitStartAnchorCheck(b []byte, anchor anchorType, literalFirstByte byte,
	locPtr, locAttemptStart, tmpLocal byte) []byte {
	const failBrDepth = 0
	switch anchor {
	case anchorNone:
		return b
	case anchorBeginText:
		// br_if (attempt_start != 0) → fail
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x0D, failBrDepth)
		return b
	case anchorEndText:
		// Impossible — match has at least 1 byte. Unconditional fail.
		b = append(b, 0x41, 0x01)
		b = append(b, 0x0D, failBrDepth)
		return b
	case anchorWordBoundary, anchorNoWordBoundary:
		// Push leftWord = (attempt_start > 0) ? is_word(input[attempt_start-1]) : 0
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x7F) // if (result i32)
		b = append(b, 0x41, 0x00) // attempt_start == 0 → 0
		b = append(b, 0x05)       // else
		b = append(b, 0x20, locPtr)
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6B) // attempt_start - 1
		b = append(b, 0x6A) // ptr + ...
		b = append(b, 0x2D, 0x00, 0x00)
		b = emitIsWordByte(b, tmpLocal)
		b = append(b, 0x0B) // end if

		// XOR with compile-time is_word(literalFirstByte)
		var rightWord int32
		if isWordByte(literalFirstByte) {
			rightWord = 1
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, rightWord)
		b = append(b, 0x73) // i32.xor → boundary (0 or 1)

		if anchor == anchorWordBoundary {
			b = append(b, 0x45) // i32.eqz: fail if !boundary
		}
		b = append(b, 0x0D, failBrDepth)
		return b
	}
	return b
}

// emitEndAnchorCheck emits a check at end_pos = attempt_start + total and
// br_if's to failBrDepth on anchor failure.
//   - anchorEndText: requires end_pos == len.
//   - anchorWordBoundary / anchorNoWordBoundary: checks boundary between
//     input[end_pos-1] (last class byte, loaded at runtime) and input[end_pos]
//     (or non-word if end_pos == len).
//   - anchorBeginText as end anchor is impossible for a non-empty match;
//     emits an unconditional fail.
func emitEndAnchorCheck(b []byte, anchor anchorType,
	locPtr, locAttemptStart byte, total int32,
	locLen, tmpLocal byte) []byte {
	const failBrDepth = 0
	switch anchor {
	case anchorNone:
		return b
	case anchorBeginText:
		b = append(b, 0x41, 0x01)
		b = append(b, 0x0D, failBrDepth)
		return b
	case anchorEndText:
		// br_if (attempt_start + total != len) → fail
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x6A)
		b = append(b, 0x20, locLen)
		b = append(b, 0x47) // i32.ne
		b = append(b, 0x0D, failBrDepth)
		return b
	case anchorWordBoundary, anchorNoWordBoundary:
		// leftWord = is_word(input[attempt_start + total - 1])
		b = append(b, 0x20, locPtr)
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total-1)
		b = append(b, 0x6A)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = emitIsWordByte(b, tmpLocal)

		// rightWord = (end_pos < len) ? is_word(input[end_pos]) : 0
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x6A)
		b = append(b, 0x20, locLen)
		b = append(b, 0x49)       // i32.lt_u
		b = append(b, 0x04, 0x7F) // if (result i32)
		b = append(b, 0x20, locPtr)
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x6A)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = emitIsWordByte(b, tmpLocal)
		b = append(b, 0x05) // else
		b = append(b, 0x41, 0x00)
		b = append(b, 0x0B) // end if

		b = append(b, 0x73) // i32.xor → boundary

		if anchor == anchorWordBoundary {
			b = append(b, 0x45) // i32.eqz: fail if !boundary
		}
		b = append(b, 0x0D, failBrDepth)
		return b
	}
	return b
}

// litChainBranchLocals identifies the WASM local indices used by the shared
// lit-chain branch dispatch emission. Each emission site (single-pattern find,
// strict-alt, lenient-alt) declares locals at different indices and supplies a
// populated struct to `emitLitChainAltLitBranchBody`.
type litChainBranchLocals struct {
	Ptr          byte // i32 param: input base address
	Len          byte // i32 param: input length
	AttemptStart byte // i32: candidate position from the frontend scan
	SimdMask     byte // i32: scan bitmask AND scalar-verify byte tmp
	ScalarIdx    byte // i32: scalar-verify counter AND anchor-check word-byte tmp
	Chunk        byte // v128: SIMD class-verify chunk
	VerifyTlo    byte // v128: per-branch tLo nibble table
	VerifyPow2   byte // v128: power-of-two table for hi nibble
}

// emitLiteralByteVerify emits scalar byte compares for literal bytes
// [startK..len(literal)-1] against input[posLocal+k]. On any mismatch, br_if
// failBrDepth. Used by alternation branch dispatch (start byte is dispatched
// separately via the first-byte filter).
func emitLiteralByteVerify(b []byte, literal []byte,
	ptrLocal, posLocal byte) []byte {
	const startK = 1
	const failBrDepth = 0
	for k := startK; k < len(literal); k++ {
		b = append(b, 0x20, ptrLocal)
		b = append(b, 0x20, posLocal)
		b = append(b, 0x6A) // i32.add
		b = append(b, 0x2D, 0x00)
		b = utils.AppendULEB128(b, uint32(k))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(literal[k]))
		b = append(b, 0x47) // i32.ne
		b = append(b, 0x0D, failBrDepth)
	}
	return b
}

// emitReturnPackedI64 emits the WASM sequence to return packed (start<<32|end)
// where end = startLocal + endOffset (constant).
func emitReturnPackedI64(b []byte, startLocal byte, endOffset int32) []byte {
	b = append(b, 0x20, startLocal)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, startLocal)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, endOffset)
	b = append(b, 0x6A) // i32.add → end pos
	b = append(b, 0xAD) // i64.extend_i32_u
	b = append(b, 0x84) // i64.or
	b = append(b, 0x0F) // return
	return b
}

// emitReturnPackedI64FromLocal emits the WASM sequence to return packed
// (startLocal<<32 | endLocal).
func emitReturnPackedI64FromLocal(b []byte, startLocal, endLocal byte) []byte {
	b = append(b, 0x20, startLocal)
	b = append(b, 0xAD)
	b = append(b, 0x42, 0x20)
	b = append(b, 0x86)
	b = append(b, 0x20, endLocal)
	b = append(b, 0xAD)
	b = append(b, 0x84)
	b = append(b, 0x0F)
	return b
}

// emitScalarBitmapVerify emits the scalar class-verify loop for an alternation
// branch where useSIMD=false. Reads N bytes after the literal, indexes into
// the bitmap data segment, and br_if's to branchFailDepth on the first byte
// out of class. Returns with stack unchanged (falls through on success).
//
// Block + loop nesting (depths from inside loop body):
//
//	0 = $vloop (loop), 1 = $loop_done (block), 2..N = caller's blocks.
//
// branchFailDepth is the caller-block depth that should be reached on
// verification failure (typically 0 = $next_branch_i from the alt dispatch).
func emitScalarBitmapVerify(b []byte, literal []byte, count int,
	branchBitmapOff int32, locals litChainBranchLocals,
	tableMemIdx int, branchFailDepth byte) []byte {

	b = append(b, 0x02, 0x40) // block $loop_done

	b = append(b, 0x41, 0x00)
	b = append(b, 0x21, locals.ScalarIdx)

	b = append(b, 0x03, 0x40) // loop $vloop

	// if scalarIdx >= N: br 1 → $loop_done (success)
	b = append(b, 0x20, locals.ScalarIdx)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(count))
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x0D, 0x01) // br_if 1

	// byte_val = input[attempt_start + K + scalarIdx]
	b = append(b, 0x20, locals.Ptr)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6A)
	b = append(b, 0x20, locals.ScalarIdx)
	b = append(b, 0x6A)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(len(literal)))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x22, locals.SimdMask) // save byte_val

	// bit = (bitmap[byte>>3] >> (byte&7)) & 1
	b = append(b, 0x41, 0x03)
	b = append(b, 0x76)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, branchBitmapOff)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)

	b = append(b, 0x20, locals.SimdMask)
	b = append(b, 0x41, 0x07)
	b = append(b, 0x71)
	b = append(b, 0x76)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x71)
	b = append(b, 0x45) // eqz: 1 if NOT in class

	// br_if (branchFailDepth + 2) → caller's branchFail target
	b = append(b, 0x0D, branchFailDepth+2)

	// scalarIdx++; br 0 → restart $vloop
	b = append(b, 0x20, locals.ScalarIdx)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locals.ScalarIdx)
	b = append(b, 0x0C, 0x00)

	b = append(b, 0x0B) // end loop $vloop
	b = append(b, 0x0B) // end block $loop_done
	return b
}

// emitLitChainAltLitBranchBody emits the body of an alternation lit-chain
// branch (everything inside `block $next_branch_i` from first-byte dispatch
// through return-packed). The caller has already opened the block and
// supplies the per-branch bitmap data-segment offset (for scalar verify).
// All failure paths br_if 0 → $next_branch_i (the enclosing block).
func emitLitChainAltLitBranchBody(b []byte, br litChainAltBranch,
	branchBitmapOff int32, locals litChainBranchLocals,
	tableMemIdx int) []byte {

	const failDepth byte = 0 // = $next_branch_i, the enclosing block

	total := int32(len(br.literal) + br.count)

	// First-byte dispatch: input[attempt_start] != literal[0] → next branch.
	b = append(b, 0x20, locals.Ptr)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(br.literal[0]))
	b = append(b, 0x47)
	b = append(b, 0x0D, failDepth)

	// Bounds check: attempt_start + K + N > len → next branch.
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A)
	b = append(b, 0x20, locals.Len)
	b = append(b, 0x4B)
	b = append(b, 0x0D, failDepth)

	// Start anchor (runs before literal/class verify to skip expensive work).
	if br.startAnchor != anchorNone {
		b = emitStartAnchorCheck(b, br.startAnchor, br.literal[0],
			locals.Ptr, locals.AttemptStart, locals.ScalarIdx)
	}

	// Literal verify (bytes 1..K-1; byte 0 already covered by first-byte dispatch).
	b = emitLiteralByteVerify(b, br.literal, locals.Ptr, locals.AttemptStart)

	// Class verify. Caller must pre-load locals.VerifyPow2 with pow2VecConst
	// (hoisted out of the scan loop for Cranelift JIT codegen).
	if br.useSIMD {
		b = emitV128Const(b, br.tlo)
		b = append(b, 0x21, locals.VerifyTlo)
		lcp := &litChainPattern{literal: br.literal, tlo: br.tlo, count: br.count}
		b = emitLitChainClassVerify(b, lcp,
			locals.Ptr, locals.AttemptStart, locals.Chunk, locals.VerifyTlo, locals.VerifyPow2)
		b = append(b, 0x0D, failDepth)
	} else {
		b = emitScalarBitmapVerify(b, br.literal, br.count, branchBitmapOff, locals, tableMemIdx, failDepth)
	}

	// End anchor.
	if br.endAnchor != anchorNone {
		b = emitEndAnchorCheck(b, br.endAnchor,
			locals.Ptr, locals.AttemptStart, total, locals.Len, locals.ScalarIdx)
	}

	// Success — return packed (attempt_start << 32 | attempt_start + total).
	b = emitReturnPackedI64(b, locals.AttemptStart, total)
	return b
}

// emitLitChainAltLitBranchBodyRange is the range-counted counterpart of
// emitLitChainAltLitBranchBody. Same per-branch verify shape, but the class
// verify uses the branch-free range algorithm (computes match_len in
// [count..countMax]). On success, returns packed (attempt_start, attempt_start
// + K + match_len).
func emitLitChainAltLitBranchBodyRange(b []byte, br litChainAltBranch,
	locals litChainBranchLocals,
	locMatchLen, locTmp byte) []byte {

	const failDepth byte = 0
	k := int32(len(br.literal))
	countMin := int32(br.count)

	// First-byte dispatch.
	b = append(b, 0x20, locals.Ptr)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(br.literal[0]))
	b = append(b, 0x47)
	b = append(b, 0x0D, failDepth)

	// Bounds: attempt_start + K + countMin > len → fail.
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k+countMin)
	b = append(b, 0x6A)
	b = append(b, 0x20, locals.Len)
	b = append(b, 0x4B)
	b = append(b, 0x0D, failDepth)

	// Start anchor.
	if br.startAnchor != anchorNone {
		b = emitStartAnchorCheck(b, br.startAnchor, br.literal[0],
			locals.Ptr, locals.AttemptStart, locals.ScalarIdx)
	}

	// Literal verify (bytes 1..K-1).
	b = emitLiteralByteVerify(b, br.literal, locals.Ptr, locals.AttemptStart)

	// Range class verify (branch-free). Caller pre-loaded VerifyPow2.
	b = emitV128Const(b, br.tlo)
	b = append(b, 0x21, locals.VerifyTlo)
	lcp := &litChainPattern{literal: br.literal, tlo: br.tlo, count: br.count, countMax: br.countMax, greedy: br.greedy}
	b = emitRangeClassVerify(b, lcp,
		locals.Ptr, locals.AttemptStart, locals.Chunk, locals.VerifyTlo, locals.VerifyPow2, locMatchLen, locTmp)

	// Runtime cap: max_avail = len - attempt_start - K. match_len = min(match_len, max_avail).
	b = append(b, 0x20, locals.Len)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6B)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6B)
	b = append(b, 0x21, locTmp) // max_avail

	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locTmp)
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locTmp)
	b = append(b, 0x49)
	b = append(b, 0x1B) // select
	b = append(b, 0x21, locMatchLen)

	// If match_len < countMin → fail this branch.
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, countMin)
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x0D, failDepth)

	// End anchor at end_pos = attempt_start + K + match_len.
	if br.endAnchor != anchorNone {
		// Compute end_pos into locTmp.
		b = append(b, 0x20, locals.AttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, k)
		b = append(b, 0x6A)
		b = append(b, 0x20, locMatchLen)
		b = append(b, 0x6A)
		b = append(b, 0x21, locTmp)

		switch br.endAnchor {
		case anchorBeginText:
			// end_pos == 0 — impossible (countMin >= 1, K >= 1).
			b = append(b, 0x0C, failDepth)
		case anchorEndText:
			b = append(b, 0x20, locTmp)
			b = append(b, 0x20, locals.Len)
			b = append(b, 0x47)
			b = append(b, 0x0D, failDepth)
		case anchorWordBoundary, anchorNoWordBoundary:
			// leftWord = is_word(input[end_pos-1])
			b = append(b, 0x20, locals.Ptr)
			b = append(b, 0x20, locTmp)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = emitIsWordByte(b, locals.ScalarIdx)
			// rightWord = (end_pos < len) ? is_word(input[end_pos]) : 0
			b = append(b, 0x20, locTmp)
			b = append(b, 0x20, locals.Len)
			b = append(b, 0x49)
			b = append(b, 0x04, 0x7F)
			b = append(b, 0x20, locals.Ptr)
			b = append(b, 0x20, locTmp)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = emitIsWordByte(b, locals.ScalarIdx)
			b = append(b, 0x05)
			b = append(b, 0x41, 0x00)
			b = append(b, 0x0B)
			b = append(b, 0x73) // boundary
			if br.endAnchor == anchorWordBoundary {
				b = append(b, 0x45)
			}
			b = append(b, 0x0D, failDepth)
		}
	}

	// Success — return packed (attempt_start, attempt_start + K + match_len).
	// end_pos = attempt_start + K + match_len → store in locTmp (or recompute).
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6A)
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x6A)
	b = append(b, 0x21, locTmp)
	b = emitReturnPackedI64FromLocal(b, locals.AttemptStart, locTmp)
	return b
}

// emitLitChainAltLitBranchBodyPrefixed is the Gap E counterpart of
// emitLitChainAltLitBranchBody for mixed-prefix branches `<class>{M}<literal><class>{N}`.
// Caller pre-loads VerifyPow2; this function loads br.prefixTlo for prefix
// verify, then br.tlo for suffix verify, into locVerifyTlo.
func emitLitChainAltLitBranchBodyPrefixed(b []byte, br litChainAltBranch,
	locals litChainBranchLocals) []byte {

	const failDepth byte = 0
	k := int32(len(br.literal))
	m := int32(br.prefixCount)
	n := int32(br.count)
	suffixEnd := k + n

	// First-byte dispatch (literal[0] at attempt_start).
	b = append(b, 0x20, locals.Ptr)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(br.literal[0]))
	b = append(b, 0x47)
	b = append(b, 0x0D, failDepth)

	// Bounds: attempt_start < M → fail (no prefix room).
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, m)
	b = append(b, 0x49)
	b = append(b, 0x0D, failDepth)

	// Bounds: attempt_start + K + N > len → fail.
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, suffixEnd)
	b = append(b, 0x6A)
	b = append(b, 0x20, locals.Len)
	b = append(b, 0x4B)
	b = append(b, 0x0D, failDepth)

	// Literal verify (bytes 1..K-1; byte 0 already covered).
	b = emitLiteralByteVerify(b, br.literal, locals.Ptr, locals.AttemptStart)

	// Prefix verify: load br.prefixTlo, single SIMD chunk at attempt_start-M.
	b = emitV128Const(b, br.prefixTlo)
	b = append(b, 0x21, locals.VerifyTlo)
	b = emitPrefixClassVerify(b, int(m), locals.Ptr, locals.AttemptStart, locals.Chunk, locals.VerifyTlo, locals.VerifyPow2)

	// Suffix verify: load br.tlo, multi-chunk via emitLitChainClassVerify.
	b = emitV128Const(b, br.tlo)
	b = append(b, 0x21, locals.VerifyTlo)
	lcp := &litChainPattern{literal: br.literal, tlo: br.tlo, count: br.count}
	b = emitLitChainClassVerify(b, lcp, locals.Ptr, locals.AttemptStart, locals.Chunk, locals.VerifyTlo, locals.VerifyPow2)

	// OR prefix and suffix bad-masks.
	b = append(b, 0x72) // i32.or
	b = append(b, 0x0D, failDepth)

	// Success — return packed (attempt_start - M, attempt_start + K + N).
	// Compute end into locals.ScalarIdx as a scratch (reused; alt has it).
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, m)
	b = append(b, 0x6B) // i32.sub → fullStart
	b = append(b, 0x21, locals.ScalarIdx)

	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, suffixEnd)
	b = append(b, 0x6A) // i32.add → end
	b = append(b, 0x21, locals.SimdMask)

	b = emitReturnPackedI64FromLocal(b, locals.ScalarIdx, locals.SimdMask)
	return b
}

// emitLitChainAltLitBranchGroupsBody is the groups-mode counterpart of
// emitLitChainAltLitBranchBody. Same per-branch verify; on success writes
// captures via slot writes (absolute positions) and returns end position
// as i32.
func emitLitChainAltLitBranchGroupsBody(b []byte, br litChainAltBranch,
	branchBitmapOff int32, locals litChainBranchLocals,
	lcc *litChainCaptures, outPtrLocal byte,
	tableMemIdx int) []byte {

	const failDepth byte = 0
	total := int32(len(br.literal) + br.count)

	// First-byte dispatch.
	b = append(b, 0x20, locals.Ptr)
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(br.literal[0]))
	b = append(b, 0x47)
	b = append(b, 0x0D, failDepth)

	// Bounds.
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A)
	b = append(b, 0x20, locals.Len)
	b = append(b, 0x4B)
	b = append(b, 0x0D, failDepth)

	if br.startAnchor != anchorNone {
		b = emitStartAnchorCheck(b, br.startAnchor, br.literal[0],
			locals.Ptr, locals.AttemptStart, locals.ScalarIdx)
	}

	b = emitLiteralByteVerify(b, br.literal, locals.Ptr, locals.AttemptStart)

	// Class verify. Caller must pre-load locals.VerifyPow2 with pow2VecConst.
	if br.useSIMD {
		b = emitV128Const(b, br.tlo)
		b = append(b, 0x21, locals.VerifyTlo)
		lcp := &litChainPattern{literal: br.literal, tlo: br.tlo, count: br.count}
		b = emitLitChainClassVerify(b, lcp,
			locals.Ptr, locals.AttemptStart, locals.Chunk, locals.VerifyTlo, locals.VerifyPow2)
		b = append(b, 0x0D, failDepth)
	} else {
		b = emitScalarBitmapVerify(b, br.literal, br.count, branchBitmapOff, locals, tableMemIdx, failDepth)
	}

	if br.endAnchor != anchorNone {
		b = emitEndAnchorCheck(b, br.endAnchor,
			locals.Ptr, locals.AttemptStart, total, locals.Len, locals.ScalarIdx)
	}

	// Success — write slots (absolute) and return attempt_start + total as i32.
	b = emitLitChainGroupSlotWrites(b, lcc, outPtrLocal, locals.AttemptStart, int(total))
	b = append(b, 0x20, locals.AttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x0F) // return
	return b
}

// pow2VecConst is the v128.const payload for the high-nibble power-of-two lookup.
// Pow2[h] = 1<<h for h in 0..7; 0 for h in 8..15 (would mean byte > 127).
var pow2VecConst = [16]byte{1, 2, 4, 8, 16, 32, 64, 128, 0, 0, 0, 0, 0, 0, 0, 0}

// litChainChunk describes one 16-byte SIMD chunk in the class-verify span.
//   - offset: position in the match (from match start) where the chunk loads.
//   - laneMask: which lanes carry class bytes that must be checked (0xFFFF =
//     all 16 lanes; reduced for the overlap chunk in K+N<16 fallback paths).
type litChainChunk struct {
	offset   int
	laneMask uint16
}

// planLitChainChunks returns the chunk plan covering bytes [K, K+N-1] of the
// match. Strategy: full 16-byte chunks aligned at K; if N%16 != 0 add one
// overlap chunk anchored at the end of the match (which re-checks some bytes
// already verified by prior chunks — guaranteed in-class).
//
// Precondition (enforced by analyseLitChain): K+N >= 16.
func planLitChainChunks(k, n int) []litChainChunk {
	var chunks []litChainChunk
	if n >= 16 {
		nFull := n / 16
		for i := 0; i < nFull; i++ {
			chunks = append(chunks, litChainChunk{offset: k + i*16, laneMask: 0xFFFF})
		}
		if n%16 != 0 {
			chunks = append(chunks, litChainChunk{offset: k + n - 16, laneMask: 0xFFFF})
		}
		return chunks
	}
	// N < 16 with K+N >= 16: single chunk anchored at end of match. The first
	// 16-N lanes hold trailing literal bytes (not class); mask them out.
	firstClassLane := 16 - n
	mask := uint16(0xFFFF) << uint(firstClassLane)
	return []litChainChunk{{offset: k + n - 16, laneMask: mask}}
}

// emitV128Const appends a v128.const instruction with the given 16-byte value.
func emitV128Const(b []byte, value [16]byte) []byte {
	b = append(b, 0xFD, 0x0C)
	return append(b, value[:]...)
}

// emitLitChainChunkLoadAndCompare appends WASM that pushes onto the stack an
// i32 bitmask where bit i is set iff byte i of the chunk is NOT in the class.
// Inputs: ptrLocal, baseLocal (match start), chunkOff (compile-time byte
// offset of this chunk from the match start), chunkLocal (v128 scratch),
// tLoLocal, pow2Local (v128 locals pre-loaded with the lookup tables).
func emitLitChainChunkLoadAndCompare(b []byte,
	ptrLocal, baseLocal byte, chunkOff int,
	chunkLocal, tLoLocal, pow2Local byte) []byte {

	// chunk = v128.load(ptr + base + chunkOff)
	b = append(b, 0x20, ptrLocal)
	b = append(b, 0x20, baseLocal)
	b = append(b, 0x6A) // i32.add
	if chunkOff != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(chunkOff))
		b = append(b, 0x6A)
	}
	b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
	b = append(b, 0x21, chunkLocal)       // local.set chunk

	// tlo_picks = swizzle(tLo, chunk & 0x0F)
	b = append(b, 0x20, tLoLocal)
	b = append(b, 0x20, chunkLocal)
	b = append(b, 0x41, 0x0F)
	b = append(b, 0xFD, 0x0F) // i8x16.splat 0x0F
	b = append(b, 0xFD, 0x4E) // v128.and  → lo_nibbles
	b = append(b, 0xFD, 0x0E) // i8x16.swizzle  → tlo_picks

	// pow_picks = swizzle(pow2, chunk >>u 4)
	b = append(b, 0x20, pow2Local)
	b = append(b, 0x20, chunkLocal)
	b = append(b, 0x41, 0x04)
	b = append(b, 0xFD, 0x6D) // i8x16.shr_u
	b = append(b, 0xFD, 0x0E) // i8x16.swizzle  → pow_picks

	b = append(b, 0xFD, 0x4E) // v128.and  → intersect (nonzero lane = in class)
	b = append(b, 0x41, 0x00)
	b = append(b, 0xFD, 0x0F) // i8x16.splat 0
	b = append(b, 0xFD, 0x23) // i8x16.eq      → out-of-class lanes = 0xFF
	b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32 (bit i set if byte i NOT in class)
	return b
}

// emitLitChainClassVerify appends WASM that pushes onto the stack an i32 that
// is 0 iff every class byte in the match span is in the class, and non-zero
// if any class byte is out of class.
//
// Stack effect: net +1 (i32).
func emitLitChainClassVerify(b []byte, lcp *litChainPattern,
	ptrLocal, baseLocal, chunkLocal, tLoLocal, pow2Local byte) []byte {

	chunks := planLitChainChunks(len(lcp.literal), lcp.count)
	for i, ch := range chunks {
		b = emitLitChainChunkLoadAndCompare(b, ptrLocal, baseLocal, ch.offset,
			chunkLocal, tLoLocal, pow2Local)
		if ch.laneMask != 0xFFFF {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.laneMask))
			b = append(b, 0x71) // i32.and
		}
		if i > 0 {
			b = append(b, 0x72) // i32.or with previous chunks' bad-mask
		}
	}
	return b
}

// emitPrefixClassVerify emits the SIMD class verify for a `<class>{M}`
// prefix (M ≤ 16). Loads 16 bytes from `ptr + base - M`, checks the first
// M lanes against the prefix nibble table, leaves prefix bad_mask (i32) on
// stack. Lanes ≥ M are masked off.
//
// `base` is the i32 local holding the literal-hit position (attempt_start
// in the find body). The full-match start is at `base - M`.
func emitPrefixClassVerify(b []byte, m int,
	locPtr, locBase, locChunk, locPrefixTlo, locPow2 byte) []byte {

	// chunk = v128.load(ptr + base - M)
	b = append(b, 0x20, locPtr)
	b = append(b, 0x20, locBase)
	b = append(b, 0x6A) // i32.add → ptr + base
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(-m))
	b = append(b, 0x6A) // i32.add → ptr + base - M
	b = append(b, 0xFD, 0x00, 0x00, 0x00)
	b = append(b, 0x21, locChunk)

	// SIMD class check (same shape as the suffix verify).
	b = append(b, 0x20, locPrefixTlo)
	b = append(b, 0x20, locChunk)
	b = append(b, 0x41, 0x0F)
	b = append(b, 0xFD, 0x0F)
	b = append(b, 0xFD, 0x4E)
	b = append(b, 0xFD, 0x0E)

	b = append(b, 0x20, locPow2)
	b = append(b, 0x20, locChunk)
	b = append(b, 0x41, 0x04)
	b = append(b, 0xFD, 0x6D)
	b = append(b, 0xFD, 0x0E)

	b = append(b, 0xFD, 0x4E)
	b = append(b, 0x41, 0x00)
	b = append(b, 0xFD, 0x0F)
	b = append(b, 0xFD, 0x23)
	b = append(b, 0xFD, 0x64) // bitmask → i32

	// Mask off lanes ≥ M.
	laneMask := int32((1 << uint(m)) - 1)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, laneMask)
	b = append(b, 0x71) // i32.and

	return b
}

// buildLitChainPrefixedFindBody emits the find body for a Gap E mixed-prefix
// pattern `<class>{M}<literal><class>{N}`. Signature: (ptr,len) → i64.
//
// The Teddy frontend scans for the literal; on hit, attempt_start is at the
// literal's position. The full match starts at (attempt_start - M). Verify
// pulls the M prefix bytes (single SIMD chunk) AND the N suffix bytes
// (existing multi-chunk verify), ORs the bad-masks, advances on mismatch.
func buildLitChainPrefixedFindBody(lcp *litChainPattern, tableMemIdx int) []byte {
	var b []byte

	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locChunk        byte = 4
		locTLo          byte = 5 // suffix class table
		locPow2         byte = 6
		locPrefixTlo    byte = 7
	)

	// 2 × i32 + 4 × v128.
	b = append(b, 0x02)
	b = append(b, 0x02, 0x7F)
	b = append(b, 0x04, 0x7B)

	// Hoist all three v128 tables.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)
	b = emitV128Const(b, lcp.prefixTlo)
	b = append(b, 0x21, locPrefixTlo)

	k := int32(len(lcp.literal))
	m := int32(lcp.prefixCount)
	n := int32(lcp.count)
	suffixEnd := k + n

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	scan := prefixScanParams{
		Prefix:      lcp.literal,
		EngineDepth: 2,
		TableMemIdx: tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// Bounds A: attempt_start < M → no prefix room, advance & retry.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, m)
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x01) // br $lit_outer
	b = append(b, 0x0B)

	// Bounds B: attempt_start + K + N > len → $no_match.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, suffixEnd)
	b = append(b, 0x6A)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4B) // i32.gt_u
	b = append(b, 0x0D, 0x01)

	// Prefix verify (single SIMD chunk).
	b = emitPrefixClassVerify(b, int(m), locPtr, locAttemptStart, locChunk, locPrefixTlo, locPow2)
	// Suffix verify (existing multi-chunk helper).
	b = emitLitChainClassVerify(b, lcp, locPtr, locAttemptStart, locChunk, locTLo, locPow2)
	// OR the two bad-masks → final bad_mask on stack.
	b = append(b, 0x72) // i32.or

	// On bad: advance attempt_start, restart loop.
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x0B)

	// Match — return packed (attempt_start - M, attempt_start + K + N).
	// Compute start = attempt_start - M (i32), end = attempt_start + K + N (i32).
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, m)
	b = append(b, 0x6B)       // i32.sub → start
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl

	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, suffixEnd)
	b = append(b, 0x6A) // i32.add → end
	b = append(b, 0xAD) // i64.extend_i32_u
	b = append(b, 0x84) // i64.or
	b = append(b, 0x0F) // return

	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)
	return b
}

// appendLitChainPrefixedFindCodeEntry appends a size-prefixed mixed-prefix
// find body (Gap E single-pattern, find mode).
func appendLitChainPrefixedFindCodeEntry(cs []byte, lcp *litChainPattern, tableMemIdx int) []byte {
	body := buildLitChainPrefixedFindBody(lcp, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainPrefixedMatchBody emits the anchored full-input match body
// for a Gap E mixed-prefix pattern. Signature: (ptr,len) → i32. Requires
// `len == M + K + N` and the entire input to verify against `<class>{M}<lit><class>{N}`.
func buildLitChainPrefixedMatchBody(lcp *litChainPattern) []byte {
	var b []byte

	const (
		locPtr       byte = 0
		locLen       byte = 1
		locBase      byte = 2 // holds M; gives the "attempt_start" frame for shared helpers
		locChunk     byte = 3
		locTLo       byte = 4
		locPow2      byte = 5
		locPrefixTlo byte = 6
	)

	// 1 × i32 + 4 × v128.
	b = append(b, 0x02)
	b = append(b, 0x01, 0x7F)
	b = append(b, 0x04, 0x7B)

	k := int32(len(lcp.literal))
	m := int32(lcp.prefixCount)
	n := int32(lcp.count)
	total := m + k + n

	// locBase = M (constant; shared with helpers).
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, m)
	b = append(b, 0x21, locBase)

	// Hoist v128 tables.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)
	b = emitV128Const(b, lcp.prefixTlo)
	b = append(b, 0x21, locPrefixTlo)

	// Bounds: len != total → -1.
	b = append(b, 0x20, locLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x47)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Literal verify at offset M.
	for kk, byt := range lcp.literal {
		b = append(b, 0x20, locPtr)
		b = append(b, 0x2D, 0x00)
		b = utils.AppendULEB128(b, uint32(int(m)+kk))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(byt))
		b = append(b, 0x47)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)
	}

	// Prefix + suffix verify (base = M; emitPrefixClassVerify reads ptr+base-M
	// = ptr+0; emitLitChainClassVerify reads ptr+base+K+i*16 = ptr+M+K+i*16).
	b = emitPrefixClassVerify(b, int(m), locPtr, locBase, locChunk, locPrefixTlo, locPow2)
	b = emitLitChainClassVerify(b, lcp, locPtr, locBase, locChunk, locTLo, locPow2)
	b = append(b, 0x72) // i32.or

	// If non-zero → -1.
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Match — return total.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x0B)
	return b
}

// appendLitChainPrefixedMatchCodeEntry appends a size-prefixed match body.
func appendLitChainPrefixedMatchCodeEntry(cs []byte, lcp *litChainPattern) []byte {
	body := buildLitChainPrefixedMatchBody(lcp)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// analyseLitChainPrefixed parses pattern and returns the lit-chain pattern
// when it has shape `<class>{M}<literal><class>{N,N}`. Reuses
// analyseLitChainBranch (which accepts the 3-element mixed-prefix form);
// adds the N≥24 gate and rejects non-mixed-prefix patterns (they go through
// the classic path).
func analyseLitChainPrefixed(pattern string) (*litChainPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	info, ok := analyseLitChainBranch(re)
	if !ok {
		return nil, false
	}
	if info.prefixCount == 0 {
		return nil, false // classic shape → existing path
	}
	if info.countMax != info.count {
		return nil, false // ranges not yet supported on Gap E
	}
	if info.count < 24 {
		return nil, false
	}
	return &litChainPattern{
		literal:      info.literal,
		tlo:          info.tlo,
		count:        info.count,
		countMax:     info.countMax,
		greedy:       info.greedy,
		prefixCount:  info.prefixCount,
		prefixBitmap: info.prefixBitmap,
		prefixTlo:    info.prefixTlo,
		startAnchor:  info.startAnchor,
		endAnchor:    info.endAnchor,
	}, true
}

// buildLitChainMatchBody emits the WASM body for an anchored match against a
// lit-chain pattern. Signature: (ptr i32, len i32) → i32 (end pos, or -1).
//
// Locals:  0=ptr 1=len  2=chunk 3=tLo 4=pow2 (v128)
func buildLitChainMatchBody(lcp *litChainPattern) []byte {
	var b []byte

	hasAnchors := lcp.startAnchor != anchorNone || lcp.endAnchor != anchorNone

	// Local declarations. Add i32 locals (attempt_start=0 sentinel + tmp) only
	// when end-anchor check needs the helpers, to keep the no-anchor WASM
	// byte-identical to the pre-anchor emission.
	const (
		locPtr   byte = 0
		locLen   byte = 1
		locChunk byte = 2
		locTLo   byte = 3
		locPow2  byte = 4
		// When hasAnchors:
		locAttemptZero byte = 5
		locTmp         byte = 6
	)
	// Declare v128 group first so existing local indices (locChunk=2..) stay
	// stable whether or not the anchor i32 locals are present.
	if hasAnchors {
		b = append(b, 0x02)
		b = append(b, 0x03, 0x7B) // 3 × v128
		b = append(b, 0x02, 0x7F) // 2 × i32 (attempt-zero sentinel + tmp)
	} else {
		b = append(b, 0x01)
		b = append(b, 0x03, 0x7B)
	}

	// Materialise tLo and pow2 from inline v128.const into locals.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	k := int32(len(lcp.literal))
	total := k + int32(lcp.count)

	// Bounds: anchored match must consume the entire input — len != total → -1.
	// (Lit-chain patterns are fixed-length K+N; any other length cannot match.)
	b = append(b, 0x20, locLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x47)       // i32.ne
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// Start anchor at pos 0 — fully resolvable at compile time.
	// anchorBeginText: pos==0, always pass.
	// anchorEndText: pos==len at start requires K+N==0, impossible — emit fail.
	// anchorWordBoundary: leftWord=0 (no prev), rightWord=is_word(literal[0]).
	//   boundary = rightWord. \b passes iff literal[0] is a word char.
	// anchorNoWordBoundary: \B passes iff literal[0] is NOT a word char.
	startFailsAtCompileTime := false
	switch lcp.startAnchor {
	case anchorEndText:
		startFailsAtCompileTime = true
	case anchorWordBoundary:
		if !isWordByte(lcp.literal[0]) {
			startFailsAtCompileTime = true
		}
	case anchorNoWordBoundary:
		if isWordByte(lcp.literal[0]) {
			startFailsAtCompileTime = true
		}
	}
	if startFailsAtCompileTime {
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
	}

	// Literal verify: K scalar byte compares against input[0..K-1].
	for kk, byt := range lcp.literal {
		b = append(b, 0x20, locPtr)
		b = append(b, 0x2D, 0x00) // i32.load8_u align=0
		b = utils.AppendULEB128(b, uint32(kk))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(byt))
		b = append(b, 0x47)       // i32.ne
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	}

	// Class verify: SIMD chunks. Push i32 bad_mask. Use baseLocal = ptr (we want
	// chunks starting at ptr + chunkOff, where chunkOff already includes K).
	// emitLitChainClassVerify uses (ptrLocal, baseLocal) = (ptr, len-K-N start),
	// but for anchored match, base = 0. We achieve that by passing a synthetic
	// zero base via a const-offset add. Simpler: temporarily use locLen as base
	// — no, that breaks. Instead emit chunks with ptrLocal + chunkOff directly
	// by inlining a base-zero path. Re-use the helper with a literal-0 base
	// requires a free i32 local; declare one.
	//
	// To avoid adding another local: emit chunks inline here using a fixed
	// match-start of 0 (chunks address = ptr + chunkOff).
	chunks := planLitChainChunks(int(k), lcp.count)
	for i, ch := range chunks {
		// chunk = v128.load(ptr + chunkOff)
		b = append(b, 0x20, locPtr)
		if ch.offset != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.offset))
			b = append(b, 0x6A) // i32.add
		}
		b = append(b, 0xFD, 0x00, 0x00, 0x00)
		b = append(b, 0x21, locChunk)

		b = append(b, 0x20, locTLo)
		b = append(b, 0x20, locChunk)
		b = append(b, 0x41, 0x0F)
		b = append(b, 0xFD, 0x0F)
		b = append(b, 0xFD, 0x4E)
		b = append(b, 0xFD, 0x0E)

		b = append(b, 0x20, locPow2)
		b = append(b, 0x20, locChunk)
		b = append(b, 0x41, 0x04)
		b = append(b, 0xFD, 0x6D)
		b = append(b, 0xFD, 0x0E)

		b = append(b, 0xFD, 0x4E)
		b = append(b, 0x41, 0x00)
		b = append(b, 0xFD, 0x0F)
		b = append(b, 0xFD, 0x23)
		b = append(b, 0xFD, 0x64) // bitmask → i32

		if ch.laneMask != 0xFFFF {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.laneMask))
			b = append(b, 0x71)
		}
		if i > 0 {
			b = append(b, 0x72)
		}
	}

	// bad_mask on stack. If non-zero → return -1.
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// End anchor check at end_pos = total. Wrap in `block $bad` so a failing
	// br_if (depth 0) lands at the post-block "return -1" path; success falls
	// through to the success return inside the block.
	if lcp.endAnchor != anchorNone {
		b = append(b, 0x02, 0x40) // block $bad
		switch lcp.endAnchor {
		case anchorBeginText:
			// end_pos must be 0, impossible — unconditionally fail.
			b = append(b, 0x41, 0x01)
			b = append(b, 0x0D, 0x00) // br_if 0 → $bad (true)
		default:
			// Use the helper with a 0-initialised attempt_start sentinel.
			// (locAttemptZero is zero by virtue of WASM locals init.)
			b = emitEndAnchorCheck(b, lcp.endAnchor,
				locPtr, locAttemptZero, total, locLen, locTmp)
		}
		// Anchor passed — return total.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end $bad
		b = append(b, 0x41, 0x7F) // i32.const -1 (anchor failed path)
		b = append(b, 0x0B)       // end function
		return b
	}

	// All good — return K+N as the end position.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x0B) // end function
	return b
}

// appendLitChainMatchCodeEntry appends a size-prefixed lit-chain match body.
func appendLitChainMatchCodeEntry(cs []byte, lcp *litChainPattern) []byte {
	body := buildLitChainMatchBody(lcp)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// captureGroup describes one capture group whose extent is fully determined at
// compile time by the lit-chain shape. Offsets are relative to the candidate
// match start position.
type captureGroup struct {
	group       int    // 1-based group index
	name        string // empty if unnamed
	startOffset int    // bytes from match start (≥ 0)
	endOffset   int    // bytes from match start (> startOffset for non-empty)
}

// litChainCaptures attaches capture-group information to a lit-chain branch.
// numGroups is the total group count for the WHOLE pattern (including group 0
// and unmatched groups from sibling branches); groups holds only the groups
// populated when this branch matches.
type litChainCaptures struct {
	numGroups int            // total groups in pattern (incl. group 0)
	groups    []captureGroup // groups this branch populates (excludes group 0)
}

// hasOpCapture reports whether the subtree contains any OpCapture node.
func hasOpCapture(re *syntax.Regexp) bool {
	if re.Op == syntax.OpCapture {
		return true
	}
	for _, sub := range re.Sub {
		if hasOpCapture(sub) {
			return true
		}
	}
	return false
}

// extractLitChainCaptures walks a lit-chain parse tree and records each
// OpCapture's compile-time offset. Returns (captures, maxGroup, ok). Rejects
// captures inside an OpRepeat body (capture-the-last-occurrence semantics
// cannot be reconstructed from compile-time offsets).
func extractLitChainCaptures(re *syntax.Regexp) ([]captureGroup, int, bool) {
	var caps []captureGroup
	maxGroup := 0
	ok := true

	var walk func(node *syntax.Regexp, offset int) int
	walk = func(node *syntax.Regexp, offset int) int {
		if !ok {
			return 0
		}
		switch node.Op {
		case syntax.OpCapture:
			startOff := offset
			w := walk(node.Sub[0], offset)
			caps = append(caps, captureGroup{
				group:       node.Cap,
				name:        node.Name,
				startOffset: startOff,
				endOffset:   startOff + w,
			})
			if node.Cap > maxGroup {
				maxGroup = node.Cap
			}
			return w
		case syntax.OpConcat:
			total := 0
			for _, child := range node.Sub {
				total += walk(child, offset+total)
			}
			return total
		case syntax.OpLiteral:
			return len(node.Rune)
		case syntax.OpRepeat:
			if hasOpCapture(node.Sub[0]) {
				ok = false
				return 0
			}
			childW := 0
			child := node.Sub[0]
			switch child.Op {
			case syntax.OpLiteral:
				childW = len(child.Rune)
			case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
				childW = 1
			}
			return node.Min * childW
		case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			return 1
		case syntax.OpBeginText, syntax.OpEndText,
			syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			return 0
		case syntax.OpBeginLine, syntax.OpEndLine:
			ok = false
			return 0
		}
		return 0
	}
	_ = walk(re, 0)
	if !ok {
		return nil, 0, false
	}
	return caps, maxGroup, true
}

// analyseLitChainGroups parses pattern and verifies it as a single lit-chain
// branch with compile-time-resolvable captures. The N≥24 single-pattern gate
// applies here too: groups now composes find_internal + captureBody via the
// standard wrapper, so the find-mode scan-loop codegen quirk that motivated
// the gate still affects this path.
func analyseLitChainGroups(pattern string) (*litChainPattern, *litChainCaptures, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, nil, false
	}
	info, ok := analyseLitChainBranch(re)
	if !ok || info.prefixCount > 0 {
		return nil, nil, false
	}
	if info.countMax != info.count {
		return nil, nil, false // ranges handled by analyseLitChainGroupsRange
	}
	if info.count < 24 {
		return nil, nil, false
	}
	caps, maxGroup, ok := extractLitChainCaptures(re)
	if !ok {
		return nil, nil, false
	}
	if maxGroup == 0 {
		// Pattern has groups_func set but no actual capture groups. Fall through
		// to the standard pipeline.
		return nil, nil, false
	}
	lcp := &litChainPattern{
		literal:     info.literal,
		tlo:         info.tlo,
		count:       info.count,
		countMax:    info.countMax,
		greedy:      info.greedy,
		startAnchor: info.startAnchor,
		endAnchor:   info.endAnchor,
	}
	lcc := &litChainCaptures{
		numGroups: maxGroup + 1, // +1 for group 0 (whole match)
		groups:    caps,
	}
	return lcp, lcc, true
}

// analyseLitChainGroupsRange parses pattern as a single lit-chain branch with
// a range count and compile-time-resolvable captures. Mirrors
// analyseLitChainGroups but accepts countMax > count (greedy ranges only;
// non-greedy in find/groups collapses to {N,N}).
func analyseLitChainGroupsRange(pattern string) (*litChainPattern, *litChainCaptures, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, nil, false
	}
	info, ok := analyseLitChainBranch(re)
	if !ok || info.prefixCount > 0 {
		return nil, nil, false
	}
	if info.countMax <= info.count {
		return nil, nil, false // not a range
	}
	if !info.greedy {
		return nil, nil, false // collapse to {N,N} via existing path
	}
	if info.count < 24 {
		return nil, nil, false
	}
	caps, maxGroup, ok := extractLitChainCaptures(re)
	if !ok {
		return nil, nil, false
	}
	if maxGroup == 0 {
		return nil, nil, false
	}
	lcp := &litChainPattern{
		literal:     info.literal,
		tlo:         info.tlo,
		count:       info.count,
		countMax:    info.countMax,
		greedy:      info.greedy,
		startAnchor: info.startAnchor,
		endAnchor:   info.endAnchor,
	}
	lcc := &litChainCaptures{
		numGroups: maxGroup + 1,
		groups:    caps,
	}
	return lcp, lcc, true
}

// analyseLitChainAltGroups parses pattern as an OpAlternate of lit-chain
// branches, each potentially carrying its own captures. Captures are
// numbered globally across branches (Go regexp convention). Each entry in
// branchCaptures corresponds to the same index in altp.branches.
//
// Per-branch anchors (`\b`, `\B`, `^`/`\A`, `$`/`\z`) are accepted: the
// lit-chain alt findBody verifies anchors during scan, so by the time the
// wrapper passes the matched substring to captureBody, the anchors are
// already satisfied. captureBody only needs to identify the winning branch
// via literal + class verify.
func analyseLitChainAltGroups(pattern string) (*litChainAltPattern, []*litChainCaptures, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, nil, false
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		// Outer capture wrapping the alternation — record it separately later.
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return nil, nil, false
	}
	branches := make([]litChainAltBranch, 0, len(re.Sub))
	branchCaps := make([]*litChainCaptures, 0, len(re.Sub))
	maxGroup := 0
	hasAnyCap := false
	for _, sub := range re.Sub {
		info, ok := analyseLitChainBranch(sub)
		if !ok || info.prefixCount > 0 {
			return nil, nil, false
		}
		if info.countMax != info.count {
			return nil, nil, false // ranges handled by range-aware analyser
		}
		caps, m, ok := extractLitChainCaptures(sub)
		if !ok {
			return nil, nil, false
		}
		if m > maxGroup {
			maxGroup = m
		}
		if len(caps) > 0 {
			hasAnyCap = true
		}
		branches = append(branches, litChainAltBranch{
			literal:     info.literal,
			bitmap:      info.bitmap,
			tlo:         info.tlo,
			count:       info.count,
			countMax:    info.countMax,
			greedy:      info.greedy,
			useSIMD:     true, // groups path always SIMD (no scan-loop pressure)
			startAnchor: info.startAnchor,
			endAnchor:   info.endAnchor,
		})
		branchCaps = append(branchCaps, &litChainCaptures{
			groups: caps,
		})
	}
	if !hasAnyCap {
		return nil, nil, false
	}
	numGroups := maxGroup + 1
	for _, bc := range branchCaps {
		bc.numGroups = numGroups
	}
	return &litChainAltPattern{branches: branches}, branchCaps, true
}

// emitLitChainGroupSlotWrites emits WASM that writes capture slots to
// out_ptr (param 2) at compile-time offsets, given attempt_start in a local.
// Writes:
//   - group 0: (attemptStart, attemptStart + total)
//   - each capture in lcc.groups: (attemptStart + startOffset, attemptStart + endOffset)
//   - other groups (gaps in [1..numGroups-1]): (-1, -1)
//
// outPtrLocal: WASM local holding out_ptr (param 2 in groups signature).
// attemptStartLocal: WASM local holding the attempt-start byte offset.
// total: K+N (the full lit-chain length).
func emitLitChainGroupSlotWrites(b []byte, lcc *litChainCaptures,
	outPtrLocal, attemptStartLocal byte, total int) []byte {

	// Build a map of group → captureGroup for fast lookup of populated groups.
	populated := make(map[int]captureGroup, len(lcc.groups))
	for _, cg := range lcc.groups {
		populated[cg.group] = cg
	}

	// Helper: write (attemptStart + offset) to out_ptr at slotOff.
	writeAttemptPlus := func(b []byte, slotOff uint32, offset int) []byte {
		b = append(b, 0x20, outPtrLocal)
		b = append(b, 0x20, attemptStartLocal)
		if offset != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(offset))
			b = append(b, 0x6A) // i32.add
		}
		b = append(b, 0x36, 0x00) // i32.store align=0
		b = utils.AppendULEB128(b, slotOff)
		return b
	}

	// Helper: write -1 (unmatched group sentinel) to out_ptr at slotOff.
	writeMinusOne := func(b []byte, slotOff uint32) []byte {
		b = append(b, 0x20, outPtrLocal)
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x36, 0x00)
		b = utils.AppendULEB128(b, slotOff)
		return b
	}

	// Group 0: whole match. start = attemptStart, end = attemptStart + total.
	b = writeAttemptPlus(b, 0, 0)
	b = writeAttemptPlus(b, 4, total)

	// Groups 1..numGroups-1.
	for g := 1; g < lcc.numGroups; g++ {
		startSlot := uint32(g * 8)
		endSlot := uint32(g*8 + 4)
		if cg, ok := populated[g]; ok {
			b = writeAttemptPlus(b, startSlot, cg.startOffset)
			b = writeAttemptPlus(b, endSlot, cg.endOffset)
		} else {
			b = writeMinusOne(b, startSlot)
			b = writeMinusOne(b, endSlot)
		}
	}
	return b
}

// emitLitChainRangeGroupSlotWrites emits slot writes for range patterns
// where the chain length is determined at runtime by locMatchLen. Captures
// whose endOffset coincides with K + countMax (i.e., end at the chain end)
// use attemptStart + K + match_len; other endOffsets are compile-time.
func emitLitChainRangeGroupSlotWrites(b []byte, lcc *litChainCaptures,
	outPtrLocal, attemptStartLocal, matchLenLocal byte, k, countMax int) []byte {

	populated := make(map[int]captureGroup, len(lcc.groups))
	for _, cg := range lcc.groups {
		populated[cg.group] = cg
	}

	chainEnd := k + countMax

	// Helper: write (attemptStart + offset) to out_ptr at slotOff.
	writeAttemptPlus := func(b []byte, slotOff uint32, offset int) []byte {
		b = append(b, 0x20, outPtrLocal)
		b = append(b, 0x20, attemptStartLocal)
		if offset != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(offset))
			b = append(b, 0x6A)
		}
		b = append(b, 0x36, 0x00)
		b = utils.AppendULEB128(b, slotOff)
		return b
	}

	// Helper: write (attemptStart + K + match_len) to out_ptr at slotOff.
	writeAttemptPlusKPlusMatchLen := func(b []byte, slotOff uint32) []byte {
		b = append(b, 0x20, outPtrLocal)
		b = append(b, 0x20, attemptStartLocal)
		if k != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(k))
			b = append(b, 0x6A)
		}
		b = append(b, 0x20, matchLenLocal)
		b = append(b, 0x6A)
		b = append(b, 0x36, 0x00)
		b = utils.AppendULEB128(b, slotOff)
		return b
	}

	writeMinusOne := func(b []byte, slotOff uint32) []byte {
		b = append(b, 0x20, outPtrLocal)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x36, 0x00)
		b = utils.AppendULEB128(b, slotOff)
		return b
	}

	// Group 0: whole match. start = attemptStart, end = attemptStart + K + match_len.
	b = writeAttemptPlus(b, 0, 0)
	b = writeAttemptPlusKPlusMatchLen(b, 4)

	for g := 1; g < lcc.numGroups; g++ {
		startSlot := uint32(g * 8)
		endSlot := uint32(g*8 + 4)
		if cg, ok := populated[g]; ok {
			b = writeAttemptPlus(b, startSlot, cg.startOffset)
			if cg.endOffset == chainEnd {
				b = writeAttemptPlusKPlusMatchLen(b, endSlot)
			} else {
				b = writeAttemptPlus(b, endSlot, cg.endOffset)
			}
		} else {
			b = writeMinusOne(b, startSlot)
			b = writeMinusOne(b, endSlot)
		}
	}
	return b
}

// buildLitChainAltMatchBody emits the anchored-full-input match body for a
// strict alternation of lit-chain branches. Signature: (ptr, len) → i32.
// Each branch is tried in order at pos 0; on the first branch where the
// input length matches and literal + class + anchors verify, returns
// total = K+N. Otherwise returns -1.
//
// Gap B target: replaces the DFA path for `match_func` on lit-chain
// alternation patterns.
func buildLitChainAltMatchBody(altp *litChainAltPattern) []byte {
	var b []byte

	anyAnchor := false
	for _, br := range altp.branches {
		if br.startAnchor != anchorNone || br.endAnchor != anchorNone {
			anyAnchor = true
			break
		}
	}

	const (
		locPtr         byte = 0
		locLen         byte = 1
		locChunk       byte = 2
		locTLo         byte = 3
		locPow2        byte = 4
		locAttemptZero byte = 5 // attempt_start sentinel (init 0); used by emitEndAnchorCheck
		locTmp         byte = 6 // is_word scratch
	)

	if anyAnchor {
		b = append(b, 0x02)
		b = append(b, 0x03, 0x7B) // 3 × v128
		b = append(b, 0x02, 0x7F) // 2 × i32
	} else {
		b = append(b, 0x01)
		b = append(b, 0x03, 0x7B)
	}

	// Materialise pow2 once.
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	for _, br := range altp.branches {
		k := int32(len(br.literal))
		total := k + int32(br.count)

		// Compile-time start anchor failure → skip emitting this branch entirely.
		// At pos 0: BeginText always passes; EndText needs K+N==0 (impossible);
		// \b passes iff literal[0] is a word char (text-start = non-word);
		// \B passes iff literal[0] is NOT a word char.
		skipBranch := false
		switch br.startAnchor {
		case anchorEndText:
			skipBranch = true
		case anchorWordBoundary:
			if !isWordByte(br.literal[0]) {
				skipBranch = true
			}
		case anchorNoWordBoundary:
			if isWordByte(br.literal[0]) {
				skipBranch = true
			}
		}
		if skipBranch {
			continue
		}

		b = append(b, 0x02, 0x40) // block $next_branch_i

		// Strict anchored: len must equal total exactly.
		b = append(b, 0x20, locLen)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x47)       // i32.ne
		b = append(b, 0x0D, 0x00) // br_if $next_branch_i

		// Literal verify.
		for kk, byt := range br.literal {
			b = append(b, 0x20, locPtr)
			b = append(b, 0x2D, 0x00)
			b = utils.AppendULEB128(b, uint32(kk))
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(byt))
			b = append(b, 0x47)
			b = append(b, 0x0D, 0x00) // br_if $next_branch_i
		}

		// Load this branch's tlo.
		b = emitV128Const(b, br.tlo)
		b = append(b, 0x21, locTLo)

		// SIMD class verify (always; match body has no scan loop).
		chunks := planLitChainChunks(int(k), br.count)
		for ci, ch := range chunks {
			b = append(b, 0x20, locPtr)
			if ch.offset != 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(ch.offset))
				b = append(b, 0x6A)
			}
			b = append(b, 0xFD, 0x00, 0x00, 0x00)
			b = append(b, 0x21, locChunk)

			b = append(b, 0x20, locTLo)
			b = append(b, 0x20, locChunk)
			b = append(b, 0x41, 0x0F)
			b = append(b, 0xFD, 0x0F)
			b = append(b, 0xFD, 0x4E)
			b = append(b, 0xFD, 0x0E)

			b = append(b, 0x20, locPow2)
			b = append(b, 0x20, locChunk)
			b = append(b, 0x41, 0x04)
			b = append(b, 0xFD, 0x6D)
			b = append(b, 0xFD, 0x0E)

			b = append(b, 0xFD, 0x4E)
			b = append(b, 0x41, 0x00)
			b = append(b, 0xFD, 0x0F)
			b = append(b, 0xFD, 0x23)
			b = append(b, 0xFD, 0x64)

			if ch.laneMask != 0xFFFF {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(ch.laneMask))
				b = append(b, 0x71)
			}
			if ci > 0 {
				b = append(b, 0x72)
			}
		}
		b = append(b, 0x0D, 0x00) // br_if $next_branch_i on bad

		// End anchor.
		if br.endAnchor != anchorNone {
			switch br.endAnchor {
			case anchorBeginText:
				// At end_pos = total, must equal 0 — impossible since K+N ≥ 16.
				b = append(b, 0x0C, 0x00) // br $next_branch_i (unconditional)
			default:
				b = emitEndAnchorCheck(b, br.endAnchor,
					locPtr, locAttemptZero, total, locLen, locTmp)
			}
		}

		// Success — return total.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, total)
		b = append(b, 0x0F) // return

		b = append(b, 0x0B) // end $next_branch_i
	}

	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0B)       // end function
	return b
}

// appendLitChainAltMatchCodeEntry appends a size-prefixed strict-alt match body.
func appendLitChainAltMatchCodeEntry(cs []byte, altp *litChainAltPattern) []byte {
	body := buildLitChainAltMatchBody(altp)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLenAltMatchBody emits the anchored full-input match body for a lenient
// alternation (mixed lit-chain + DFA branches). Signature: (ptr,len) → i32.
// Each branch is tried at pos 0; lit-chain branches use SIMD/scalar verify
// with strict len == K+N, DFA branches run an inline anchored DFA and accept
// iff last_accept == len. Gap B lenient target.
func buildLenAltMatchBody(altp *lenAltPattern, l lenAltLayout, tableMemIdx int) []byte {
	var b []byte

	const (
		locPtr         byte = 0
		locLen         byte = 1
		locChunk       byte = 2
		locTLo         byte = 3
		locPow2        byte = 4
		locState       byte = 5 // DFA verify
		locPos         byte = 6 // DFA verify
		locClass       byte = 7 // DFA verify
		locOutEnd      byte = 8 // DFA verify last_accept
		locScalarIdx   byte = 9 // scalar bitmap verify counter / is_word scratch
		locAttemptZero byte = 10
	)

	// 3 × v128 + 6 × i32 locals.
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7B)
	b = append(b, 0x06, 0x7F)

	// Materialise pow2 once.
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	branchLocals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptZero,
		SimdMask: locScalarIdx, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locTLo, VerifyPow2: locPow2,
	}

	for i, br := range altp.branches {
		if br.isLitChain {
			k := int32(len(br.literal))
			total := k + int32(br.count)

			skipBranch := false
			switch br.startAnchor {
			case anchorEndText:
				skipBranch = true
			case anchorWordBoundary:
				if !isWordByte(br.literal[0]) {
					skipBranch = true
				}
			case anchorNoWordBoundary:
				if isWordByte(br.literal[0]) {
					skipBranch = true
				}
			}
			if skipBranch {
				continue
			}

			b = append(b, 0x02, 0x40) // block $next_branch_i

			// Strict anchored: len must equal total.
			b = append(b, 0x20, locLen)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, total)
			b = append(b, 0x47)
			b = append(b, 0x0D, 0x00) // br_if $next_branch_i

			// Literal verify.
			for kk, byt := range br.literal {
				b = append(b, 0x20, locPtr)
				b = append(b, 0x2D, 0x00)
				b = utils.AppendULEB128(b, uint32(kk))
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(byt))
				b = append(b, 0x47)
				b = append(b, 0x0D, 0x00)
			}

			// Class verify: SIMD if useSIMD else scalar bitmap.
			if br.useSIMD {
				b = emitV128Const(b, br.tlo)
				b = append(b, 0x21, locTLo)
				chunks := planLitChainChunks(int(k), br.count)
				for ci, ch := range chunks {
					b = append(b, 0x20, locPtr)
					if ch.offset != 0 {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(ch.offset))
						b = append(b, 0x6A)
					}
					b = append(b, 0xFD, 0x00, 0x00, 0x00)
					b = append(b, 0x21, locChunk)

					b = append(b, 0x20, locTLo)
					b = append(b, 0x20, locChunk)
					b = append(b, 0x41, 0x0F)
					b = append(b, 0xFD, 0x0F)
					b = append(b, 0xFD, 0x4E)
					b = append(b, 0xFD, 0x0E)

					b = append(b, 0x20, locPow2)
					b = append(b, 0x20, locChunk)
					b = append(b, 0x41, 0x04)
					b = append(b, 0xFD, 0x6D)
					b = append(b, 0xFD, 0x0E)

					b = append(b, 0xFD, 0x4E)
					b = append(b, 0x41, 0x00)
					b = append(b, 0xFD, 0x0F)
					b = append(b, 0xFD, 0x23)
					b = append(b, 0xFD, 0x64)

					if ch.laneMask != 0xFFFF {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(ch.laneMask))
						b = append(b, 0x71)
					}
					if ci > 0 {
						b = append(b, 0x72)
					}
				}
				b = append(b, 0x0D, 0x00) // br_if $next_branch_i on bad_mask
			} else {
				b = emitScalarBitmapVerify(b, br.literal, br.count,
					l.branchBitmapOff[i], branchLocals, tableMemIdx, 0)
			}

			// End anchor.
			if br.endAnchor != anchorNone {
				switch br.endAnchor {
				case anchorBeginText:
					b = append(b, 0x0C, 0x00) // br $next_branch_i (impossible)
				default:
					b = emitEndAnchorCheck(b, br.endAnchor,
						locPtr, locAttemptZero, total, locLen, locScalarIdx)
				}
			}

			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, total)
			b = append(b, 0x0F) // return total

			b = append(b, 0x0B) // end $next_branch_i
		} else {
			// DFA branch.
			b = append(b, 0x02, 0x40) // block $next_branch_i

			// First-byte dispatch.
			b = append(b, 0x20, locPtr)
			b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u offset=0 align=0
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(br.literal[0]))
			b = append(b, 0x47)
			b = append(b, 0x0D, 0x00) // br_if $next_branch_i

			// Cheap reject on the rest of the literal before the (relatively
			// expensive) per-byte inline DFA verify below — see the matching
			// comment in buildLitChainAltLenientFindBody (task 24 regression).
			if len(br.literal) > 1 {
				b = append(b, 0x20, locLen)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(len(br.literal)))
				b = append(b, 0x4B)       // i32.lt_u
				b = append(b, 0x0D, 0x00) // br_if $next_branch_i (literal can't fit)

				b = emitLiteralByteVerify(b, br.literal, locPtr, locAttemptZero)
			}

			// pos = 0; run inline anchored DFA verify (on no-accept br to depth 0).
			b = append(b, 0x41, 0x00)
			b = append(b, 0x21, locPos)
			b = emitInlineAnchoredDFAVerify(b, br.dfaLayout,
				locPtr, locLen, locState, locPos, locClass, locOutEnd,
				tableMemIdx, 0)

			// Anchored match: require last_accept == len for full input consumption.
			b = append(b, 0x20, locOutEnd)
			b = append(b, 0x20, locLen)
			b = append(b, 0x47)       // i32.ne
			b = append(b, 0x0D, 0x00) // br_if $next_branch_i

			b = append(b, 0x20, locOutEnd)
			b = append(b, 0x0F) // return last_accept (== len)

			b = append(b, 0x0B) // end $next_branch_i
		}
	}

	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0B)       // end function
	return b
}

// appendLenAltMatchCodeEntry appends a size-prefixed lenient-alt match body.
func appendLenAltMatchCodeEntry(cs []byte, altp *lenAltPattern, l lenAltLayout, tableMemIdx int) []byte {
	body := buildLenAltMatchBody(altp, l, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainFindBody emits the WASM body for non-anchored find against a
// lit-chain pattern. Signature: (ptr i32, len i32) → i64 (packed start<<32|end, or -1).
//
// Structure:
//
//	block $no_match
//	  loop $lit_outer
//	    emitPrefixScan with Prefix=literal, EngineDepth=2  // scan exits on exhaust
//	    ; attempt_start = candidate position (literal already verified by scan)
//	    ; bounds check: attempt_start + K + N <= len, else $no_match
//	    ; SIMD class verify of next N bytes
//	    ; if mismatch: attempt_start++; br $lit_outer
//	    ; return packed (attempt_start << 32 | attempt_start + K + N)
//	  end loop
//	end block $no_match
//	return -1
func buildLitChainFindBody(lcp *litChainPattern, tableMemIdx int) []byte {
	var b []byte

	hasAnchors := lcp.startAnchor != anchorNone || lcp.endAnchor != anchorNone

	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locTmp          byte = 4 // word-byte check scratch (only used when anchors present)
		locChunk        byte = 5 // shared between prefix scan and class verify
		locTLo          byte = 6
		locPow2         byte = 7
	)

	// Local declarations: 3 i32 + 3 v128.
	// locTmp is declared regardless (cheap) so the local indices stay stable
	// across hasAnchors variants.
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F) // 3 × i32
	b = append(b, 0x03, 0x7B) // 3 × v128

	k := int32(len(lcp.literal))
	total := k + int32(lcp.count)

	// Hoist nibble-table materialisation outside the scan loop — loop-invariant
	// values do not need to be re-loaded on every iteration. (Cranelift JIT
	// regression workaround: keeping these out of the loop body reduces scan-
	// loop register pressure.)
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	scan := prefixScanParams{
		Prefix:      lcp.literal,
		EngineDepth: 2,
		TableMemIdx: tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// Bounds check: attempt_start + K + N > len → $no_match.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x20, locLen)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x0D, 0x01) // br_if 1 → $no_match

	// When anchors are present, wrap the post-scan path in a $next_attempt
	// block: anchor/verify failures br to depth 0 and the code after the block
	// advances attempt_start and restarts. Without anchors, the existing
	// if-then structure for class verify is kept (byte-identical to the
	// pre-anchor emission for those patterns).
	if hasAnchors {
		b = append(b, 0x02, 0x40) // block $next_attempt

		b = emitStartAnchorCheck(b, lcp.startAnchor, lcp.literal[0],
			locPtr, locAttemptStart, locTmp)
	}

	b = emitLitChainClassVerify(b, lcp,
		locPtr, locAttemptStart, locChunk, locTLo, locPow2)

	if hasAnchors {
		// bad_mask on stack → br_if 0 → $next_attempt on failure.
		b = append(b, 0x0D, 0x00)

		b = emitEndAnchorCheck(b, lcp.endAnchor,
			locPtr, locAttemptStart, total, locLen, locTmp)
	} else {
		// Existing if-then structure: on bad, advance & restart.
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, locAttemptStart)
		b = append(b, 0x0C, 0x01) // br 1 → $lit_outer (0=if, 1=$lit_outer)
		b = append(b, 0x0B)       // end if
	}

	// Match — return packed (attempt_start << 32 | attempt_start + K + N).
	b = emitReturnPackedI64(b, locAttemptStart, total)

	if hasAnchors {
		b = append(b, 0x0B) // end $next_attempt
		// advance + restart
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, locAttemptStart)
		b = append(b, 0x0C, 0x00) // br 0 → $lit_outer
	}

	b = append(b, 0x0B) // end loop $lit_outer
	b = append(b, 0x0B) // end block $no_match

	// No match.
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)       // end function
	return b
}

// buildLitChainFindGroupsBody emits the WASM body for non-anchored
// find-with-captures against a lit-chain pattern. Signature:
// `(ptr i32, len i32, out_ptr i32) → i32` returning end position on match
// or -1 on no match.
//
// Native single-function variant of Gap A.3: combines the find body's
// SIMD scan + verify with inline slot writes. Eliminates the function-call
// boundary and redundant verify of the wrapper-composition path.
func buildLitChainFindGroupsBody(lcp *litChainPattern, lcc *litChainCaptures, tableMemIdx int) []byte {
	var b []byte

	hasAnchors := lcp.startAnchor != anchorNone || lcp.endAnchor != anchorNone

	// out_ptr is param 2, so all locals from the find-body shift by +1.
	const (
		locPtr          byte = 0
		locLen          byte = 1
		locOutPtr       byte = 2
		locAttemptStart byte = 3
		locSimdMask     byte = 4
		locTmp          byte = 5 // word-byte scratch (only used when anchors present)
		locChunk        byte = 6
		locTLo          byte = 7
		locPow2         byte = 8
	)

	// 3 × i32 + 3 × v128 (locTmp declared regardless for stable indices).
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F) // 3 × i32
	b = append(b, 0x03, 0x7B) // 3 × v128

	k := int32(len(lcp.literal))
	total := k + int32(lcp.count)

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	scan := prefixScanParams{
		Prefix:      lcp.literal,
		EngineDepth: 2,
		TableMemIdx: tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// Bounds: attempt_start + K + N > len → $no_match.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4B)
	b = append(b, 0x0D, 0x01) // br_if 1 → $no_match

	if hasAnchors {
		b = append(b, 0x02, 0x40) // block $next_attempt
		b = emitStartAnchorCheck(b, lcp.startAnchor, lcp.literal[0],
			locPtr, locAttemptStart, locTmp)
	}

	// SIMD class verify.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)
	b = emitLitChainClassVerify(b, lcp,
		locPtr, locAttemptStart, locChunk, locTLo, locPow2)

	if hasAnchors {
		b = append(b, 0x0D, 0x00) // br_if 0 → $next_attempt on bad
		b = emitEndAnchorCheck(b, lcp.endAnchor,
			locPtr, locAttemptStart, total, locLen, locTmp)
	} else {
		// On bad: advance attempt_start, restart loop.
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, locAttemptStart)
		b = append(b, 0x0C, 0x01) // br 1 → $lit_outer
		b = append(b, 0x0B)       // end if
	}

	// Match — write slots (absolute positions) and return end position.
	b = emitLitChainGroupSlotWrites(b, lcc, locOutPtr, locAttemptStart, int(total))
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, total)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x0F) // return

	if hasAnchors {
		b = append(b, 0x0B) // end $next_attempt
		// Advance + restart.
		b = append(b, 0x20, locAttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, locAttemptStart)
		b = append(b, 0x0C, 0x00) // br 0 → $lit_outer
	}

	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block $no_match

	// No match.
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0B)       // end function
	return b
}

// appendLitChainFindGroupsCodeEntry appends a size-prefixed lit-chain
// find-with-captures body.
func appendLitChainFindGroupsCodeEntry(cs []byte, lcp *litChainPattern, lcc *litChainCaptures, tableMemIdx int) []byte {
	body := buildLitChainFindGroupsBody(lcp, lcc, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainRangeFindGroupsBody emits the find-with-captures body for a
// single lit-chain with range `{N,M}` greedy. Signature: (ptr,len,out_ptr) → i32.
// Combines the range-find SIMD scan + branch-free verify with inline slot
// writes (chain-end slots use runtime match_len).
func buildLitChainRangeFindGroupsBody(lcp *litChainPattern, lcc *litChainCaptures, tableMemIdx int) []byte {
	var b []byte

	const (
		locPtr          byte = 0
		locLen          byte = 1
		locOutPtr       byte = 2
		locAttemptStart byte = 3
		locSimdMask     byte = 4
		locMatchLen     byte = 5
		locTmp          byte = 6
		locChunk        byte = 7
		locTLo          byte = 8
		locPow2         byte = 9
	)

	// 4 × i32 + 3 × v128.
	b = append(b, 0x02)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x03, 0x7B)

	k := int32(len(lcp.literal))
	countMin := int32(lcp.count)

	// Hoist nibble tables.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)

	scan := prefixScanParams{
		Prefix:      lcp.literal,
		EngineDepth: 2,
		TableMemIdx: tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// Bounds: attempt_start + K + countMin > len → $no_match.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k+countMin)
	b = append(b, 0x6A)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4B)
	b = append(b, 0x0D, 0x01)

	// Range class verify.
	b = emitRangeClassVerify(b, lcp, locPtr, locAttemptStart, locChunk, locTLo, locPow2, locMatchLen, locTmp)

	// Runtime cap: max_avail = len - attempt_start - K.
	b = append(b, 0x20, locLen)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x6B)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6B)
	b = append(b, 0x21, locSimdMask)

	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locSimdMask)
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locSimdMask)
	b = append(b, 0x49)
	b = append(b, 0x1B) // select
	b = append(b, 0x21, locMatchLen)

	// If match_len < countMin → advance attempt_start, restart.
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, countMin)
	b = append(b, 0x49)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x01)
	b = append(b, 0x0B)

	// Match — write slots and return end position (attempt_start + K + match_len).
	b = emitLitChainRangeGroupSlotWrites(b, lcc, locOutPtr, locAttemptStart, locMatchLen, int(k), lcp.countMax)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6A)
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x6A)
	b = append(b, 0x0F) // return

	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B)
	return b
}

// appendLitChainRangeFindGroupsCodeEntry appends a size-prefixed range groups body.
func appendLitChainRangeFindGroupsCodeEntry(cs []byte, lcp *litChainPattern, lcc *litChainCaptures, tableMemIdx int) []byte {
	body := buildLitChainRangeFindGroupsBody(lcp, lcc, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// rangeChunk is the chunk plan for range `{N,M}` class verify: chunks are
// disjoint (non-overlapping, unlike the {N,N} overlap-tail plan), so ctz on
// each chunk's bad_mask gives a position monotonically increasing across
// chunks — the first non-zero chunk pins down the first bad byte.
type rangeChunk struct {
	offset      int    // byte offset from match start (attempt_start + offset = chunk address)
	offsetFromK int    // byte offset from end of literal (position in chain)
	laneMask    uint16 // bits 0..lane-1 active (lane = bytes-in-chain covered by this chunk)
}

// planRangeChunks plans disjoint SIMD chunks covering [K..K+countMax).
func planRangeChunks(k, countMax int) []rangeChunk {
	var chunks []rangeChunk
	nFull := countMax / 16
	for i := 0; i < nFull; i++ {
		chunks = append(chunks, rangeChunk{
			offset:      k + i*16,
			offsetFromK: i * 16,
			laneMask:    0xFFFF,
		})
	}
	tail := countMax % 16
	if tail != 0 {
		chunks = append(chunks, rangeChunk{
			offset:      k + nFull*16,
			offsetFromK: nFull * 16,
			laneMask:    uint16(1<<uint(tail)) - 1,
		})
	}
	return chunks
}

// emitRangeClassVerify emits WASM that runs class verify on `countMax` bytes
// and writes the match length (count of class-matching bytes from K, in
// [0..countMax]) to `locMatchLen`.
//
// Branch-free algorithm: each chunk's bad_mask is OR'd with a sentinel
// (bit 16) before `i32.ctz`, so the per-chunk match length is either the
// real first-bad index (`< lane_count`) or 16 (no bad in this chunk).
// Chunks are folded in REVERSE order via `select`: earlier chunks override
// later ones. Avoids per-chunk `block`+`if`+`br` patterns that Cranelift's
// register allocator handles poorly across the surrounding scan loop.
func emitRangeClassVerify(b []byte, lcp *litChainPattern,
	locPtr, locBase, locChunk, locTLo, locPow2, locMatchLen, locTmp byte) []byte {

	chunks := planRangeChunks(len(lcp.literal), lcp.countMax)
	countMax := int32(lcp.countMax)

	// Initialise accumulator (final match_len) to countMax sentinel.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, countMax)
	b = append(b, 0x21, locMatchLen)

	// Iterate in REVERSE so earlier chunks' results override later ones via
	// the cascading select-fold.
	for i := len(chunks) - 1; i >= 0; i-- {
		ch := chunks[i]
		// Lane count (real chain bytes covered by this chunk).
		laneCount := int32(0)
		for m := ch.laneMask; m != 0; m &= m - 1 {
			laneCount++
		}

		// Load chunk.
		b = append(b, 0x20, locPtr)
		b = append(b, 0x20, locBase)
		b = append(b, 0x6A)
		if ch.offset != 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.offset))
			b = append(b, 0x6A)
		}
		b = append(b, 0xFD, 0x00, 0x00, 0x00)
		b = append(b, 0x21, locChunk)

		b = append(b, 0x20, locTLo)
		b = append(b, 0x20, locChunk)
		b = append(b, 0x41, 0x0F)
		b = append(b, 0xFD, 0x0F)
		b = append(b, 0xFD, 0x4E)
		b = append(b, 0xFD, 0x0E)

		b = append(b, 0x20, locPow2)
		b = append(b, 0x20, locChunk)
		b = append(b, 0x41, 0x04)
		b = append(b, 0xFD, 0x6D)
		b = append(b, 0xFD, 0x0E)

		b = append(b, 0xFD, 0x4E)
		b = append(b, 0x41, 0x00)
		b = append(b, 0xFD, 0x0F)
		b = append(b, 0xFD, 0x23)
		b = append(b, 0xFD, 0x64) // i32 bad_mask

		if ch.laneMask != 0xFFFF {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.laneMask))
			b = append(b, 0x71)
		}

		// OR with sentinel 0x10000 (bit 16), then ctz → ml_i in [0..16].
		b = append(b, 0x41, 0x80, 0x80, 0x04) // i32.const 0x10000 (SLEB128)
		b = append(b, 0x72)                   // i32.or
		b = append(b, 0x68)                   // i32.ctz
		b = append(b, 0x22, locTmp)           // local.tee tmp (ml_i)

		// Push (offsetFromK + ml_i) — v1.
		if ch.offsetFromK > 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(ch.offsetFromK))
			b = append(b, 0x6A) // i32.add
		}

		// v2 = current acc.
		b = append(b, 0x20, locMatchLen)

		// cond = ml_i < laneCount.
		b = append(b, 0x20, locTmp)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, laneCount)
		b = append(b, 0x49) // i32.lt_u

		b = append(b, 0x1B) // select
		b = append(b, 0x21, locMatchLen)
	}
	_ = countMax
	return b
}

// buildLitChainRangeFindBody emits the find body for a single-pattern lit-chain
// with a greedy range count `{N,M}`. Signature: (ptr,len) → i64.
//
// Algorithm:
//
//	loop $lit_outer:
//	  prefix scan for literal → attempt_start
//	  if attempt_start + K + N > len: $no_match
//	  SIMD range class verify → match_len (count of class-matching bytes in [K..K+M))
//	  match_len = min(match_len, len - attempt_start - K)   // runtime cap
//	  if match_len < N: advance attempt_start; restart
//	  return packed (attempt_start, attempt_start + K + match_len)
func buildLitChainRangeFindBody(lcp *litChainPattern, tableMemIdx int) []byte {
	var b []byte

	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locMatchLen     byte = 4
		locChunk        byte = 5
		locTLo          byte = 6
		locPow2         byte = 7
	)

	// 3 × i32 + 3 × v128.
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F)
	b = append(b, 0x03, 0x7B)

	k := int32(len(lcp.literal))
	countMin := int32(lcp.count)
	totalMin := k + countMin

	// Hoist nibble tables outside the scan loop (Cranelift JIT regression
	// workaround — keeping these out of the loop body reduces scan-loop
	// register pressure).
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	scan := prefixScanParams{
		Prefix:      lcp.literal,
		EngineDepth: 2,
		TableMemIdx: tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// Bounds: attempt_start + K + countMin > len → $no_match.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, totalMin)
	b = append(b, 0x6A)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4B) // i32.gt_u
	b = append(b, 0x0D, 0x01)

	// match_len = chain class verify (writes locMatchLen).
	// Use attempt_start as base.
	b = emitRangeClassVerify(b, lcp, locPtr, locAttemptStart, locChunk, locTLo, locPow2, locMatchLen, locSimdMask)

	// Runtime cap: max_avail = len - attempt_start - K. Use locSimdMask as scratch.
	b = append(b, 0x20, locLen)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x6B)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6B)
	b = append(b, 0x21, locSimdMask)

	// match_len = min(match_len, max_avail) via select.
	b = append(b, 0x20, locMatchLen) // v1
	b = append(b, 0x20, locSimdMask) // v2
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locSimdMask)
	b = append(b, 0x49) // match_len < max_avail
	b = append(b, 0x1B) // select
	b = append(b, 0x21, locMatchLen)

	// If match_len < countMin → advance attempt_start, restart.
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, countMin)
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x01) // br $lit_outer
	b = append(b, 0x0B)

	// Match — return packed (attempt_start, attempt_start + K + match_len).
	// end_pos = attempt_start + K + match_len
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6A)
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x6A) // attempt_start + K + match_len
	b = append(b, 0x21, locMatchLen)
	b = emitReturnPackedI64FromLocal(b, locAttemptStart, locMatchLen)

	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block $no_match

	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0B)
	return b
}

// appendLitChainRangeFindCodeEntry appends a size-prefixed range find body.
func appendLitChainRangeFindCodeEntry(cs []byte, lcp *litChainPattern, tableMemIdx int) []byte {
	body := buildLitChainRangeFindBody(lcp, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainRangeMatchBody emits the anchored full-input match body for a
// single lit-chain with range count `{N,M}` (greedy or non-greedy — both have
// identical semantics for anchored match because the input length forces
// the count). Signature: (ptr,len) → i32.
//
// Algorithm:
//   - Bounds: len in [K+N, K+M], else return -1.
//   - Literal verify, start/end anchors.
//   - SIMD class verify (branch-free, same as range find).
//   - Require match_len >= (len - K) for full input consumption.
//   - Return len (= K + match_len, but match_len is at least len-K).
func buildLitChainRangeMatchBody(lcp *litChainPattern) []byte {
	var b []byte

	hasAnchors := lcp.startAnchor != anchorNone || lcp.endAnchor != anchorNone

	const (
		locPtr         byte = 0
		locLen         byte = 1
		locMatchLen    byte = 2
		locScratch     byte = 3 // for tmp in verify
		locAttemptZero byte = 4 // zero-init; used by emitEndAnchorCheck
		locTmp         byte = 5 // is_word scratch
		locChunk       byte = 6
		locTLo         byte = 7
		locPow2        byte = 8
	)

	// 4 × i32 (locMatchLen, locScratch, locAttemptZero, locTmp) + 3 × v128.
	b = append(b, 0x02)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x03, 0x7B)

	k := int32(len(lcp.literal))
	countMin := int32(lcp.count)
	countMax := int32(lcp.countMax)

	// Materialise nibble tables.
	b = emitV128Const(b, lcp.tlo)
	b = append(b, 0x21, locTLo)
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locPow2)

	// Bounds: len < K+N → -1.
	b = append(b, 0x20, locLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k+countMin)
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)
	// Bounds: len > K+M → -1.
	b = append(b, 0x20, locLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k+countMax)
	b = append(b, 0x4B) // i32.gt_u
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Compile-time start anchor check (at pos 0).
	startFailsAtCompileTime := false
	switch lcp.startAnchor {
	case anchorEndText:
		startFailsAtCompileTime = true
	case anchorWordBoundary:
		if !isWordByte(lcp.literal[0]) {
			startFailsAtCompileTime = true
		}
	case anchorNoWordBoundary:
		if isWordByte(lcp.literal[0]) {
			startFailsAtCompileTime = true
		}
	}
	if startFailsAtCompileTime {
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
	}

	// Literal verify (K bytes).
	for kk, byt := range lcp.literal {
		b = append(b, 0x20, locPtr)
		b = append(b, 0x2D, 0x00)
		b = utils.AppendULEB128(b, uint32(kk))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(byt))
		b = append(b, 0x47)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)
	}

	// SIMD range class verify (branch-free).
	b = emitRangeClassVerify(b, lcp, locPtr, locAttemptZero, locChunk, locTLo, locPow2, locMatchLen, locScratch)

	// Require match_len >= (len - K) for full input consumption.
	b = append(b, 0x20, locMatchLen)
	b = append(b, 0x20, locLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, k)
	b = append(b, 0x6B) // i32.sub → required = len - K
	b = append(b, 0x49) // match_len < required
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// End anchor check.
	if lcp.endAnchor != anchorNone {
		b = append(b, 0x02, 0x40) // block $bad
		switch lcp.endAnchor {
		case anchorBeginText:
			b = append(b, 0x41, 0x01)
			b = append(b, 0x0D, 0x00)
		default:
			// end_pos = len (we consumed full input). For emitEndAnchorCheck,
			// total = len - attempt_start_zero = len. But the helper takes a
			// compile-time `total`. Inline the check instead.
			switch lcp.endAnchor {
			case anchorEndText:
				// Always pass (end_pos = len).
			case anchorWordBoundary, anchorNoWordBoundary:
				// leftWord = is_word(input[len-1])
				b = append(b, 0x20, locPtr)
				b = append(b, 0x20, locLen)
				b = append(b, 0x41, 0x01)
				b = append(b, 0x6B)
				b = append(b, 0x6A)
				b = append(b, 0x2D, 0x00, 0x00)
				b = emitIsWordByte(b, locTmp)
				// rightWord = 0 (end_pos == len)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x73) // i32.xor → boundary
				if lcp.endAnchor == anchorWordBoundary {
					b = append(b, 0x45) // i32.eqz: fail if !boundary
				}
				b = append(b, 0x0D, 0x00) // br_if 0 → $bad
			}
		}
		// Success.
		b = append(b, 0x20, locLen)
		b = append(b, 0x0F)
		b = append(b, 0x0B) // end $bad
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0B)
		return b
	}

	_ = hasAnchors

	// No end anchor: return len.
	b = append(b, 0x20, locLen)
	b = append(b, 0x0B)
	return b
}

// appendLitChainRangeMatchCodeEntry appends a size-prefixed range match body.
func appendLitChainRangeMatchCodeEntry(cs []byte, lcp *litChainPattern) []byte {
	body := buildLitChainRangeMatchBody(lcp)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// appendLitChainFindCodeEntry appends a size-prefixed lit-chain find body.
func appendLitChainFindCodeEntry(cs []byte, lcp *litChainPattern, tableMemIdx int) []byte {
	body := buildLitChainFindBody(lcp, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// ============================================================================
// Lit-chain alternation (Phase 2 of LIKELY.md Opt 2).
//
// Recognises OpAlternate of strict <literal><class>{N,N} branches; each branch
// independently uses SIMD class verify (when N≥24) or scalar bitmap verify
// (when N<24). All branches share a single SIMD first-byte scan (Teddy 1-byte
// table built from the per-branch first bytes).
//
// Output layout (data segments, in this order, starting at tableBase):
//   firstByteFlags : 256-byte flag table (1 if byte is a first-byte of some branch)
//   teddyLo        : 16-byte Teddy low-nibble table
//   teddyHi        : 16-byte Teddy high-nibble table
//   For each scalar branch i (useSIMD=false), in branch order:
//     classBitmap_i : 32-byte byte-class bitmap
// ============================================================================

// litChainAltLayout holds the data-segment offsets computed for an alternation
// pattern. branchBitmapOff[i] is the bitmap offset for branch i (only valid when
// !branches[i].useSIMD; -1 otherwise).
type litChainAltLayout struct {
	firstByteOff    int32
	teddyLoOff      int32
	teddyHiOff      int32
	teddyT1LoOff    int32 // 2-byte Teddy second-byte tables (0 if useTwoByteTeddy=false)
	teddyT1HiOff    int32
	useTwoByteTeddy bool // true when all branches have K≥2 (so second byte is fixed literal)
	branchBitmapOff []int32
	tableEnd        int64
}

// planLitChainAltLayout computes data-segment offsets for the alternation
// tables starting at tableBase, in the order described above.
func planLitChainAltLayout(altp *litChainAltPattern, tableBase int64) litChainAltLayout {
	l := litChainAltLayout{
		branchBitmapOff: make([]int32, len(altp.branches)),
	}
	// 2-byte Teddy needs a fixed second byte per branch — only applicable when
	// every branch's literal has K ≥ 2 AND branch count ≤ 8 (Teddy-bit limit).
	useTwoByteTeddy := len(altp.branches) <= 8
	if useTwoByteTeddy {
		for _, br := range altp.branches {
			if len(br.literal) < 2 {
				useTwoByteTeddy = false
				break
			}
		}
	}
	l.useTwoByteTeddy = useTwoByteTeddy
	cur := tableBase
	l.firstByteOff = int32(cur)
	cur += 256
	l.teddyLoOff = int32(cur)
	cur += 16
	l.teddyHiOff = int32(cur)
	cur += 16
	if useTwoByteTeddy {
		l.teddyT1LoOff = int32(cur)
		cur += 16
		l.teddyT1HiOff = int32(cur)
		cur += 16
	}
	for i, br := range altp.branches {
		if br.useSIMD {
			l.branchBitmapOff[i] = -1
			continue
		}
		l.branchBitmapOff[i] = int32(cur)
		cur += 32
	}
	l.tableEnd = cur
	return l
}

// buildLitChainAltDataSegments returns the raw data-segment bytes (no count
// prefix) for the alternation layout, plus the segment count.
func buildLitChainAltDataSegments(altp *litChainAltPattern, l litChainAltLayout) ([]byte, int) {
	// firstByteFlags table (256 bytes).
	var fb [256]byte
	for _, br := range altp.branches {
		fb[br.literal[0]] = 1
	}
	// Teddy 1-byte tables.
	var teddyLo, teddyHi [16]byte
	for i, br := range altp.branches {
		if i >= 8 {
			break // Teddy 1-byte supports up to 8 patterns
		}
		first := br.literal[0]
		teddyLo[first&0x0F] |= byte(1 << uint(i))
		teddyHi[first>>4] |= byte(1 << uint(i))
	}
	// 2-byte Teddy tables (when all branches have K ≥ 2): T1 indexes the
	// literal's second byte per branch.
	var teddyT1Lo, teddyT1Hi [16]byte
	if l.useTwoByteTeddy {
		for i, br := range altp.branches {
			if i >= 8 {
				break
			}
			second := br.literal[1]
			teddyT1Lo[second&0x0F] |= byte(1 << uint(i))
			teddyT1Hi[second>>4] |= byte(1 << uint(i))
		}
	}

	var segs []byte
	segCount := 0
	segs = appendDataSegment(segs, l.firstByteOff, fb[:])
	segCount++
	segs = appendDataSegment(segs, l.teddyLoOff, teddyLo[:])
	segCount++
	segs = appendDataSegment(segs, l.teddyHiOff, teddyHi[:])
	segCount++
	if l.useTwoByteTeddy {
		segs = appendDataSegment(segs, l.teddyT1LoOff, teddyT1Lo[:])
		segCount++
		segs = appendDataSegment(segs, l.teddyT1HiOff, teddyT1Hi[:])
		segCount++
	}
	for i, br := range altp.branches {
		if br.useSIMD {
			continue
		}
		segs = appendDataSegment(segs, l.branchBitmapOff[i], br.bitmap[:])
		segCount++
	}
	return segs, segCount
}

// buildLitChainAltFindBody emits the find body for an alternation of
// lit-chain branches. Signature: (ptr i32, len i32) → i64.
//
// Locals layout:
//
//	0  ptr            (param i32)
//	1  len            (param i32)
//	2  attempt_start  (i32)
//	3  simdMask       (i32) — scan
//	4  scalarIdx      (i32) — scalar verify loop counter
//	5  chunk          (v128) — scan + SIMD verify (reused)
//	6  teddyLo        (v128) — scan
//	7  teddyHi        (v128) — scan
//	8  verifyTlo      (v128) — SIMD verify (loaded per branch)
//	9  verifyPow2     (v128) — SIMD verify (loaded once)
func buildLitChainAltFindBody(altp *litChainAltPattern, l litChainAltLayout, tableMemIdx int) []byte {
	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locScalarIdx    byte = 4
		locChunk        byte = 5
		locTeddyLo      byte = 6
		locTeddyHi      byte = 7
		locTeddyT1Lo    byte = 8
		locTeddyT1Hi    byte = 9
		// locVerifyTlo doubles as locTeddyChunk1 during scan (different phases).
		locVerifyTlo   byte = 10
		locTeddyChunk1 byte = 10
		locVerifyPow2  byte = 11
	)

	var b []byte

	// Local declarations: 3 i32 + 7 v128 (T0/T1 Teddy + chunk + chunk1/verifyTlo + verifyPow2).
	b = append(b, 0x02)       // 2 local groups
	b = append(b, 0x03, 0x7F) // 3 × i32
	b = append(b, 0x07, 0x7B) // 7 × v128

	// Hoist pow2 outside the scan loop (Cranelift JIT workaround). Per-branch
	// tlo stays inline.
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locVerifyPow2)

	// Outer control flow.
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	// Build the FirstByteSet (deduplicated) for emitPrefixScan.
	seen := [256]bool{}
	var firstByteSet []byte
	var firstByteFlags [256]byte
	for _, br := range altp.branches {
		firstByteFlags[br.literal[0]] = 1
		if !seen[br.literal[0]] {
			seen[br.literal[0]] = true
			firstByteSet = append(firstByteSet, br.literal[0])
		}
	}

	scan := prefixScanParams{
		FirstByteSet:   firstByteSet,
		FirstByteFlags: firstByteFlags,
		FirstByteOff:   l.firstByteOff,
		TeddyLoOff:     l.teddyLoOff,
		TeddyHiOff:     l.teddyHiOff,
		TeddyT1LoOff:   l.teddyT1LoOff,
		TeddyT1HiOff:   l.teddyT1HiOff,
		TeddyTwoByte:   l.useTwoByteTeddy,
		EngineDepth:    2,
		TableMemIdx:    tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
			TLo:          locTeddyLo,
			THi:          locTeddyHi,
			T1Lo:         locTeddyT1Lo,
			T1Hi:         locTeddyT1Hi,
			Chunk1:       locTeddyChunk1,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	// attempt_start = candidate position. Try each branch in turn.
	locals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptStart,
		SimdMask: locSimdMask, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locVerifyTlo, VerifyPow2: locVerifyPow2,
	}
	for i, br := range altp.branches {
		b = append(b, 0x02, 0x40) // block $next_branch_i
		b = emitLitChainAltLitBranchBody(b, br, l.branchBitmapOff[i], locals, tableMemIdx)
		b = append(b, 0x0B) // end $next_branch_i
	}

	// All branches failed at this position — advance and restart.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x00) // br 0 → $lit_outer

	b = append(b, 0x0B) // end loop $lit_outer
	b = append(b, 0x0B) // end block $no_match

	// No match.
	b = append(b, 0x42, 0x7F)
	b = append(b, 0x0B) // end function
	return b
}

// buildLitChainAltFindGroupsBody emits the WASM body for non-anchored
// find-with-captures over a strict lit-chain alternation. Signature:
// `(ptr, len, out_ptr) → i32`. Native single-function variant — combines the
// Teddy frontend scan with per-branch verify and inline slot writes.
func buildLitChainAltFindGroupsBody(altp *litChainAltPattern, branchCaps []*litChainCaptures,
	l litChainAltLayout, tableMemIdx int) []byte {

	const (
		locPtr          byte = 0
		locLen          byte = 1
		locOutPtr       byte = 2
		locAttemptStart byte = 3
		locSimdMask     byte = 4
		locScalarIdx    byte = 5
		locChunk        byte = 6
		locTeddyLo      byte = 7
		locTeddyHi      byte = 8
		locTeddyT1Lo    byte = 9
		locTeddyT1Hi    byte = 10
		locVerifyTlo    byte = 11
		locTeddyChunk1  byte = 11 // alias: doubles as Chunk1 during scan
		locVerifyPow2   byte = 12
	)

	var b []byte

	// 3 i32 + 7 v128.
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F)
	b = append(b, 0x07, 0x7B)

	// Hoist pow2 outside the scan loop (Cranelift JIT workaround).
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locVerifyPow2)

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	seen := [256]bool{}
	var firstByteSet []byte
	var firstByteFlags [256]byte
	for _, br := range altp.branches {
		firstByteFlags[br.literal[0]] = 1
		if !seen[br.literal[0]] {
			seen[br.literal[0]] = true
			firstByteSet = append(firstByteSet, br.literal[0])
		}
	}

	scan := prefixScanParams{
		FirstByteSet:   firstByteSet,
		FirstByteFlags: firstByteFlags,
		FirstByteOff:   l.firstByteOff,
		TeddyLoOff:     l.teddyLoOff,
		TeddyHiOff:     l.teddyHiOff,
		TeddyT1LoOff:   l.teddyT1LoOff,
		TeddyT1HiOff:   l.teddyT1HiOff,
		TeddyTwoByte:   l.useTwoByteTeddy,
		EngineDepth:    2,
		TableMemIdx:    tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
			TLo:          locTeddyLo,
			THi:          locTeddyHi,
			T1Lo:         locTeddyT1Lo,
			T1Hi:         locTeddyT1Hi,
			Chunk1:       locTeddyChunk1,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	locals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptStart,
		SimdMask: locSimdMask, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locVerifyTlo, VerifyPow2: locVerifyPow2,
	}
	for i, br := range altp.branches {
		b = append(b, 0x02, 0x40) // block $next_branch_i
		b = emitLitChainAltLitBranchGroupsBody(b, br, l.branchBitmapOff[i], locals,
			branchCaps[i], locOutPtr, tableMemIdx)
		b = append(b, 0x0B) // end $next_branch_i
	}

	// All branches failed at this position — advance and restart.
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x00) // br 0 → $lit_outer

	b = append(b, 0x0B) // end loop $lit_outer
	b = append(b, 0x0B) // end block $no_match

	// No match.
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B) // end function
	return b
}

// appendLitChainAltFindGroupsCodeEntry appends a size-prefixed alt
// find-with-captures body.
func appendLitChainAltFindGroupsCodeEntry(cs []byte, altp *litChainAltPattern,
	branchCaps []*litChainCaptures, l litChainAltLayout, tableMemIdx int) []byte {
	body := buildLitChainAltFindGroupsBody(altp, branchCaps, l, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainAltPrefixedFindBody emits the find body for a strict
// alternation where every branch is mixed-prefix shape (Gap E). Signature:
// (ptr,len) → i64. Per-branch dispatch uses emitLitChainAltLitBranchBodyPrefixed.
func buildLitChainAltPrefixedFindBody(altp *litChainAltPattern, l litChainAltLayout, tableMemIdx int) []byte {
	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locScalarIdx    byte = 4
		locChunk        byte = 5
		locTeddyLo      byte = 6
		locTeddyHi      byte = 7
		locTeddyT1Lo    byte = 8
		locTeddyT1Hi    byte = 9
		locVerifyTlo    byte = 10
		locTeddyChunk1  byte = 10
		locVerifyPow2   byte = 11
	)

	var b []byte
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F)
	b = append(b, 0x07, 0x7B)

	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locVerifyPow2)

	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)

	seen := [256]bool{}
	var firstByteSet []byte
	var firstByteFlags [256]byte
	for _, br := range altp.branches {
		firstByteFlags[br.literal[0]] = 1
		if !seen[br.literal[0]] {
			seen[br.literal[0]] = true
			firstByteSet = append(firstByteSet, br.literal[0])
		}
	}

	scan := prefixScanParams{
		FirstByteSet:   firstByteSet,
		FirstByteFlags: firstByteFlags,
		FirstByteOff:   l.firstByteOff,
		TeddyLoOff:     l.teddyLoOff,
		TeddyHiOff:     l.teddyHiOff,
		TeddyT1LoOff:   l.teddyT1LoOff,
		TeddyT1HiOff:   l.teddyT1HiOff,
		TeddyTwoByte:   l.useTwoByteTeddy,
		EngineDepth:    2,
		TableMemIdx:    tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
			TLo:          locTeddyLo,
			THi:          locTeddyHi,
			T1Lo:         locTeddyT1Lo,
			T1Hi:         locTeddyT1Hi,
			Chunk1:       locTeddyChunk1,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	locals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptStart,
		SimdMask: locSimdMask, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locVerifyTlo, VerifyPow2: locVerifyPow2,
	}
	for _, br := range altp.branches {
		b = append(b, 0x02, 0x40) // block $next_branch_i
		b = emitLitChainAltLitBranchBodyPrefixed(b, br, locals)
		b = append(b, 0x0B)
	}

	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x00)

	b = append(b, 0x0B)
	b = append(b, 0x0B)

	b = append(b, 0x42, 0x7F)
	b = append(b, 0x0B)
	return b
}

// appendLitChainAltPrefixedFindCodeEntry appends a size-prefixed body.
func appendLitChainAltPrefixedFindCodeEntry(cs []byte, altp *litChainAltPattern, l litChainAltLayout, tableMemIdx int) []byte {
	body := buildLitChainAltPrefixedFindBody(altp, l, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildLitChainAltRangeFindBody emits the find body for a strict alternation
// where at least one branch is a range `{N,M}`. Per-branch dispatch uses the
// branch-free range verify when the branch is range, the {N,N} verify
// otherwise. Signature: (ptr,len) → i64.
func buildLitChainAltRangeFindBody(altp *litChainAltPattern, l litChainAltLayout, tableMemIdx int) []byte {
	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locSimdMask     byte = 3
		locScalarIdx    byte = 4
		locMatchLen     byte = 5
		locTmp          byte = 6
		locChunk        byte = 7
		locTeddyLo      byte = 8
		locTeddyHi      byte = 9
		locTeddyT1Lo    byte = 10
		locTeddyT1Hi    byte = 11
		locVerifyTlo    byte = 12
		locTeddyChunk1  byte = 12 // alias: doubles as Chunk1 during scan
		locVerifyPow2   byte = 13
	)

	var b []byte
	b = append(b, 0x02)
	b = append(b, 0x05, 0x7F)
	b = append(b, 0x07, 0x7B)

	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locVerifyPow2)

	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)

	seen := [256]bool{}
	var firstByteSet []byte
	var firstByteFlags [256]byte
	for _, br := range altp.branches {
		firstByteFlags[br.literal[0]] = 1
		if !seen[br.literal[0]] {
			seen[br.literal[0]] = true
			firstByteSet = append(firstByteSet, br.literal[0])
		}
	}

	scan := prefixScanParams{
		FirstByteSet:   firstByteSet,
		FirstByteFlags: firstByteFlags,
		FirstByteOff:   l.firstByteOff,
		TeddyLoOff:     l.teddyLoOff,
		TeddyHiOff:     l.teddyHiOff,
		TeddyT1LoOff:   l.teddyT1LoOff,
		TeddyT1HiOff:   l.teddyT1HiOff,
		TeddyTwoByte:   l.useTwoByteTeddy,
		EngineDepth:    2,
		TableMemIdx:    tableMemIdx,
		Locals: prefixScanLocals{
			Ptr:          locPtr,
			Len:          locLen,
			AttemptStart: locAttemptStart,
			SimdMask:     locSimdMask,
			Chunk:        locChunk,
			TLo:          locTeddyLo,
			THi:          locTeddyHi,
			T1Lo:         locTeddyT1Lo,
			T1Hi:         locTeddyT1Hi,
			Chunk1:       locTeddyChunk1,
		},
		OnMatch: nil,
	}
	b = emitPrefixScan(b, scan)

	locals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptStart,
		SimdMask: locSimdMask, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locVerifyTlo, VerifyPow2: locVerifyPow2,
	}
	for i, br := range altp.branches {
		b = append(b, 0x02, 0x40)
		useBr := br
		// Non-greedy in find: treat as {N,N}.
		if !useBr.greedy && useBr.countMax > useBr.count {
			useBr.countMax = useBr.count
		}
		if useBr.countMax > useBr.count {
			b = emitLitChainAltLitBranchBodyRange(b, useBr, locals, locMatchLen, locTmp)
		} else {
			b = emitLitChainAltLitBranchBody(b, useBr, l.branchBitmapOff[i], locals, tableMemIdx)
		}
		b = append(b, 0x0B)
	}

	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locAttemptStart)
	b = append(b, 0x0C, 0x00)

	b = append(b, 0x0B)
	b = append(b, 0x0B)

	b = append(b, 0x42, 0x7F)
	b = append(b, 0x0B)
	return b
}

// appendLitChainAltRangeFindCodeEntry appends a size-prefixed alt-range find body.
func appendLitChainAltRangeFindCodeEntry(cs []byte, altp *litChainAltPattern, l litChainAltLayout, tableMemIdx int) []byte {
	body := buildLitChainAltRangeFindBody(altp, l, tableMemIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// ============================================================================
// Phase 2a — Lenient lit-chain alternation: literal-first DFA branches.
//
// Lenient mode accepts alternations where every branch starts with an
// OpLiteral, but the trailing structure need not be a counted class chain.
// Non-lit-chain branches compile to a small anchored DFA that runs inline
// from the candidate position after the frontend scan locates the literal.
//
// Coverage example: AKIA[A-Z0-9]{16}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}
//   - Branch 1: lit-chain shape          → SIMD/scalar bitmap verify
//   - Branch 2: starts with literal      → inline anchored DFA from candidate
// ============================================================================

// lenAltBranch is one branch of a lenient alternation. Exactly one of the
// two-mode flags is true: isLitChain (use the existing lit-chain verify) or
// !isLitChain (use the inline DFA verify).
type lenAltBranch struct {
	literal []byte // literal prefix; required (used as frontend scan trigger)

	// Lit-chain branch fields (valid when isLitChain == true).
	isLitChain  bool
	bitmap      [32]byte
	tlo         [16]byte
	count       int  // N for {N,N}
	useSIMD     bool // count >= 24
	startAnchor anchorType
	endAnchor   anchorType

	// DFA branch fields (valid when isLitChain == false). The DFA already
	// encodes any anchors inside the compiled branch, so startAnchor/endAnchor
	// above are not used for DFA branches.
	dfaTable     *dfaTable
	dfaLayout    *dfaLayout
	dfaDataBytes []byte // size-counted: data segments for this branch's DFA
	dfaSegCount  int
}

// lenAltPattern is a lenient alternation recognised by analyseLitChainAltLenient.
// At least one branch is a DFA branch — otherwise analyseLitChainAlt (strict)
// would already have matched and lenient should not engage.
type lenAltPattern struct {
	branches []lenAltBranch
}

// analyseLitChainAltLenient detects an OpAlternate whose every branch begins
// with an OpLiteral and where at least one branch is NOT lit-chain shape (else
// the strict path is preferred). Each non-lit-chain branch is compiled as an
// anchored DFA (leftmost-longest, leftmostFirst=false), capped at 256 states.
//
// Caller still gates by LikelyMatch + no-captures.
func analyseLitChainAltLenient(pattern string) (*lenAltPattern, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) < 2 {
		return nil, false
	}

	branches := make([]lenAltBranch, 0, len(re.Sub))
	dfaCount := 0
	for _, sub := range re.Sub {
		if info, ok := analyseLitChainBranch(sub); ok && info.countMax == info.count && info.prefixCount == 0 {
			branches = append(branches, lenAltBranch{
				literal:     info.literal,
				isLitChain:  true,
				bitmap:      info.bitmap,
				tlo:         info.tlo,
				count:       info.count,
				useSIMD:     info.count >= 24,
				startAnchor: info.startAnchor,
				endAnchor:   info.endAnchor,
			})
			continue
		}
		// Phase 2a: require OpConcat starting with OpLiteral.
		cur := sub
		for cur.Op == syntax.OpCapture && len(cur.Sub) == 1 {
			cur = cur.Sub[0]
		}
		if cur.Op != syntax.OpConcat || len(cur.Sub) < 2 {
			return nil, false
		}
		litNode := cur.Sub[0]
		if litNode.Op != syntax.OpLiteral {
			return nil, false
		}
		if litNode.Flags&syntax.FoldCase != 0 {
			return nil, false
		}
		literal := make([]byte, 0, len(litNode.Rune))
		for _, r := range litNode.Rune {
			if r > 127 {
				return nil, false
			}
			literal = append(literal, byte(r))
		}
		if len(literal) == 0 {
			return nil, false
		}
		// Compile the FULL branch (including literal) to an anchored DFA.
		simplified := cur.Simplify()
		prog, err := syntax.Compile(simplified)
		if err != nil {
			return nil, false
		}
		if needsUnicodeSupport(prog) {
			return nil, false
		}
		d, dOk := newDFA(prog, false, false, maxHelperDFAStates)
		if !dOk {
			return nil, false
		}
		dt := dfaTableFrom(d)
		if dt.numStates+1 > 256 {
			return nil, false // keep inline DFA small (u8 table)
		}
		branches = append(branches, lenAltBranch{
			literal:    literal,
			isLitChain: false,
			dfaTable:   dt,
		})
		dfaCount++
	}
	if dfaCount == 0 {
		// All branches lit-chain — let the strict path handle it.
		return nil, false
	}
	return &lenAltPattern{branches: branches}, true
}

// planLenAltLayout computes data-segment offsets for a lenient alternation:
//
//	firstByteFlags, teddyLo, teddyHi, then per-branch tables (lit-chain bitmaps
//	for scalar branches OR full DFA tables for DFA branches).
type lenAltLayout struct {
	firstByteOff int32
	teddyLoOff   int32
	teddyHiOff   int32
	// Per-branch: bitmap offset for scalar lit-chain branches; -1 otherwise.
	branchBitmapOff []int32
	tableEnd        int64
}

func planLenAltLayout(altp *lenAltPattern, tableBase int64) lenAltLayout {
	l := lenAltLayout{
		branchBitmapOff: make([]int32, len(altp.branches)),
	}
	cur := tableBase
	l.firstByteOff = int32(cur)
	cur += 256
	l.teddyLoOff = int32(cur)
	cur += 16
	l.teddyHiOff = int32(cur)
	cur += 16
	for i, br := range altp.branches {
		l.branchBitmapOff[i] = -1
		if br.isLitChain {
			if !br.useSIMD {
				l.branchBitmapOff[i] = int32(cur)
				cur += 32
			}
			continue
		}
		// DFA branch: build its layout starting at cur.
		br.dfaLayout = buildDFALayout(br.dfaTable, cur, false, false, 0, false, false, false, false)
		// dfaDataSegments returns size-prefixed bytes; strip the count for our use.
		raw, segCount := stripSegCount(dfaDataSegments(br.dfaLayout, false))
		br.dfaDataBytes = raw
		br.dfaSegCount = segCount
		cur = br.dfaLayout.tableEnd
		// Persist back to the pattern.
		altp.branches[i] = br
	}
	l.tableEnd = cur
	return l
}

// buildLenAltDataSegments emits the raw data-segment bytes (no count prefix)
// for a lenient alternation, plus the segment count.
func buildLenAltDataSegments(altp *lenAltPattern, l lenAltLayout) ([]byte, int) {
	var fb [256]byte
	for _, br := range altp.branches {
		fb[br.literal[0]] = 1
	}
	var teddyLo, teddyHi [16]byte
	for i, br := range altp.branches {
		if i >= 8 {
			break
		}
		first := br.literal[0]
		teddyLo[first&0x0F] |= byte(1 << uint(i))
		teddyHi[first>>4] |= byte(1 << uint(i))
	}

	var segs []byte
	segCount := 0
	segs = appendDataSegment(segs, l.firstByteOff, fb[:])
	segCount++
	segs = appendDataSegment(segs, l.teddyLoOff, teddyLo[:])
	segCount++
	segs = appendDataSegment(segs, l.teddyHiOff, teddyHi[:])
	segCount++
	for i, br := range altp.branches {
		if br.isLitChain {
			if !br.useSIMD {
				segs = appendDataSegment(segs, l.branchBitmapOff[i], br.bitmap[:])
				segCount++
			}
			continue
		}
		// DFA branch — append its data segments (already encoded).
		segs = append(segs, br.dfaDataBytes...)
		segCount += br.dfaSegCount
	}
	return segs, segCount
}

// emitInlineAnchoredDFAVerify emits the WASM bytes for an inline anchored DFA
// verifier: it runs the DFA over the input starting at posLocal (initially set
// to attempt_start), and:
//   - on accept (some input position causes accept): writes the end position
//     to locOutEnd and returns; fall-through reaches the success path.
//   - on dead state / EOF without accept: br to nextBranchDepth → $next_branch_i.
//
// Locals used (must be declared in caller):
//
//	locPtr, locLen      — outer i32
//	locState            — i32 scratch (state)
//	locPos              — i32 scratch (pos, init to attempt_start)
//	locClass            — i32 scratch (class lookup)
//	locOutEnd           — i32 (output: position one past last accepted byte)
//
// Constraint: dfaLayout.useU8 must be true (we capped DFA at 256 states).
func emitInlineAnchoredDFAVerify(b []byte, dl *dfaLayout,
	locPtr, locLen, locState, locPos, locClass, locOutEnd byte,
	tableMemIdx int, nextBranchDepth byte) []byte {

	// Initialize: state = wasmStart; last_accept (locOutEnd) = -1.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(dl.wasmStart))
	b = append(b, 0x21, locState)
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x21, locOutEnd)

	// loop $dfa
	//   if pos >= len: break (check accept and finish)
	//   state = transition(state, input[pos])
	//   if state == 0 (dead): break
	//   if accept[state]: last_accept = pos + 1
	//   pos++; br $dfa
	//
	// Structure: block $dfa_done { loop $dfa { ... } }
	b = append(b, 0x02, 0x40) // block $dfa_done
	b = append(b, 0x03, 0x40) // loop $dfa

	// if pos >= len: br 1 → $dfa_done
	b = append(b, 0x20, locPos)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1 → $dfa_done

	// Transition: state = table[state * numClasses + class(input[pos])].
	if dl.useCompression {
		b = emitCompressedU8Transition(b, dl.tableOff, dl.classMapOff, dl.numClasses,
			locState, locClass, locPtr, locPos, 0xff, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, dl.tableOff,
			locState, locPtr, locPos, 0xff, tableMemIdx)
	}

	// if state == 0 (dead): br 1 → $dfa_done
	b = append(b, 0x20, locState)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x0D, 0x01) // br_if 1 → $dfa_done

	// if accept[state]: last_accept = pos + 1
	b = emitAcceptBitOnStack(b, locState, dl.acceptLimit)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locOutEnd)
	b = append(b, 0x0B) // end if

	// pos++; br 0 → $dfa
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locPos)
	b = append(b, 0x0C, 0x00) // br 0 → $dfa

	b = append(b, 0x0B) // end loop $dfa
	b = append(b, 0x0B) // end block $dfa_done

	// If last_accept < 0: branch failed → br to $next_branch_i.
	b = append(b, 0x20, locOutEnd)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48) // i32.lt_s
	// Depth from here: nextBranchDepth refers to $next_branch_i.
	b = append(b, 0x0D, nextBranchDepth)
	return b
}

// buildLitChainAltLenientFindBody emits the find body for a lenient alternation.
// Same scan + dispatch structure as the strict path, with extra DFA-verify
// branches inlined.
// buildLitChainAltLenientFindBody's frontend persists the SIMD candidate
// bitmask across a 16-byte window instead of recomputing it (and reloading
// an overlapping chunk) on every failed candidate. Originally this function
// called the shared emitPrefixScan once per $lit_outer iteration — correct,
// but on every branch-dispatch failure it restarted the ENTIRE scan from
// attempt_start+1, reloading a mostly-identical 16-byte chunk and
// recomputing the whole SIMD candidate mask from scratch. For a corpus
// with a dense first-byte set (e.g. 'e','g','A' in ordinary English/config
// text — ~1 candidate every 9-10 bytes), that per-candidate restart cost
// dominated: measured at ~45 fuel/candidate, accounting for most of the
// task-24 promotion regression on `secrets-combined` even after fixing the
// separate per-branch DFA-verify cost (see that fix a few lines below).
// See plans/TODO.md task 24's promotion-regression writeup for the full
// investigation.
func buildLitChainAltLenientFindBody(altp *lenAltPattern, l lenAltLayout, tableMemIdx int) []byte {
	const (
		locPtr          byte = 0
		locLen          byte = 1
		locAttemptStart byte = 2
		locMask         byte = 3 // persistent SIMD candidate bitmask for the current 16-byte window
		locScalarIdx    byte = 4
		locDFAState     byte = 5
		locDFAPos       byte = 6
		locDFAClass     byte = 7
		locDFAOutEnd    byte = 8
		locChunk        byte = 9
		locVerifyTlo    byte = 12
		locVerifyPow2   byte = 13
		locWindowBase   byte = 14 // base of the currently-loaded 16-byte SIMD window
	)

	var b []byte
	// Local declarations: 7 i32 + 5 v128 + 1 i32 (locWindowBase, added on top
	// to avoid renumbering the existing i32/v128 groups above).
	b = append(b, 0x03)       // 3 local groups
	b = append(b, 0x07, 0x7F) // 7 × i32
	b = append(b, 0x05, 0x7B) // 5 × v128 (indices 10,11 — formerly Teddy table
	// locals — are now unused: emitShuftiPrefixCheck below inlines its
	// nibble tables as v128.const, so no pre-loaded per-call Teddy table is
	// needed. Left declared to avoid renumbering locVerifyTlo/locVerifyPow2.)
	b = append(b, 0x01, 0x7F) // 1 × i32 (locWindowBase)

	// Hoist the power-of-two lookup vector once, shared by every lit-chain
	// branch's class verify (emitLitChainAltLitBranchBody requires the
	// caller to pre-load VerifyPow2 with pow2VecConst — see its doc
	// comment). Each branch's VerifyTlo differs per-class and is set
	// inside emitLitChainAltLitBranchBody itself; VerifyPow2 is the same
	// constant for all of them, so it belongs here, not per-branch.
	b = emitV128Const(b, pow2VecConst)
	b = append(b, 0x21, locVerifyPow2)

	// Union of branches' first bytes (compile-time only).
	seen := [256]bool{}
	var firstByteSet []byte
	for _, br := range altp.branches {
		if !seen[br.literal[0]] {
			seen[br.literal[0]] = true
			firstByteSet = append(firstByteSet, br.literal[0])
		}
	}

	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $lit_outer

	b = append(b, 0x02, 0x40) // block $mask_ready
	// if mask != 0: br 0 → $mask_ready (skip refill, a candidate is already queued)
	b = append(b, 0x20, locMask)
	b = append(b, 0x0D, 0x00)

	// ---- refill: scan forward in 16-byte windows for the next nonzero mask ----
	b = append(b, 0x03, 0x40) // loop $window_scan
	// if windowBase + 15 >= len: br 3 → exit $no_match entirely (go to tail scan)
	// Depths from here: 0=$window_scan 1=$mask_ready 2=$lit_outer 3=$no_match.
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x41, 0x0F) // 15
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x20, locLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x03) // br_if 3 → exits $no_match, lands at tail scan below

	// Load chunk @ windowBase.
	b = append(b, 0x20, locPtr)
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x6A)
	b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
	b = append(b, 0x21, locChunk)

	// mask = per-lane bitmask of candidate bytes in this chunk (bit k set ⇔
	// chunk byte k is in firstByteSet). Tables inlined as v128.const —
	// nothing to pre-load per call, unlike the old Teddy-locals approach.
	b = emitShuftiPrefixCheck(b, firstByteSet, locChunk)
	b = append(b, 0x21, locMask)

	// if mask != 0: br 1 → $mask_ready (candidate found in this window)
	b = append(b, 0x20, locMask)
	b = append(b, 0x0D, 0x01)

	// else: windowBase += 16; keep scanning
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x41, 0x10) // 16
	b = append(b, 0x6A)
	b = append(b, 0x21, locWindowBase)
	b = append(b, 0x0C, 0x00) // br 0 → continue $window_scan

	b = append(b, 0x0B) // end loop $window_scan
	b = append(b, 0x0B) // end block $mask_ready

	// mask != 0 guaranteed here (either carried over from a prior iteration,
	// or just found by the refill above).
	// attempt_start = windowBase + ctz(mask)
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x20, locMask)
	b = append(b, 0x68) // i32.ctz
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, locAttemptStart)

	// mask &= mask - 1 (clear the lowest set bit — next iteration either
	// finds the next candidate in this same window for free, or refills).
	b = append(b, 0x20, locMask)
	b = append(b, 0x20, locMask)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6B) // i32.sub
	b = append(b, 0x71) // i32.and
	b = append(b, 0x21, locMask)

	// If that was the last candidate in this window, advance windowBase past
	// it now. Without this, a subsequent refill (triggered by mask==0) would
	// reload the SAME window at the SAME windowBase, recompute the identical
	// mask, and loop forever on the same already-tried candidates.
	b = append(b, 0x20, locMask)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x41, 0x10) // 16
	b = append(b, 0x6A)
	b = append(b, 0x21, locWindowBase)
	b = append(b, 0x0B) // end if

	// Per-branch dispatch on locAttemptStart (unchanged from the original
	// per-branch bodies — factored into a closure since the tail scan below
	// needs the identical dispatch code).
	locals := litChainBranchLocals{
		Ptr: locPtr, Len: locLen, AttemptStart: locAttemptStart,
		SimdMask: locScalarIdx, ScalarIdx: locScalarIdx,
		Chunk: locChunk, VerifyTlo: locVerifyTlo, VerifyPow2: locVerifyPow2,
	}
	// emitBranch emits the dispatch code for exactly one branch (its own
	// first-byte check included — cheap enough to leave in place even when
	// the caller already knows the byte matches via the group dispatch
	// below, and keeping it means this function needn't change shape
	// between its two call sites).
	emitBranch := func(b []byte, idx int) []byte {
		br := altp.branches[idx]
		b = append(b, 0x02, 0x40) // block $next_branch_i

		if br.isLitChain {
			chainBr := litChainAltBranch{
				literal: br.literal, bitmap: br.bitmap, tlo: br.tlo,
				count: br.count, useSIMD: br.useSIMD,
				startAnchor: br.startAnchor, endAnchor: br.endAnchor,
			}
			b = emitLitChainAltLitBranchBody(b, chainBr, l.branchBitmapOff[idx], locals, tableMemIdx)
		} else {
			// DFA branch: first-byte dispatch + inline DFA from attempt_start.
			b = append(b, 0x20, locPtr)
			b = append(b, 0x20, locAttemptStart)
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(br.literal[0]))
			b = append(b, 0x47)
			b = append(b, 0x0D, 0x00) // br_if 0 → $next_branch_i

			// Cheap reject on the rest of the literal before the (relatively
			// expensive) per-byte inline DFA verify below. Without this, a
			// false hit on just literal[0] (e.g. 'e' for "eyJ...", one of the
			// most common bytes in ordinary text) pays for a full DFA
			// simulation every time instead of a couple of byte compares —
			// see plans/TODO.md task 24's promotion-regression writeup.
			if len(br.literal) > 1 {
				b = append(b, 0x20, locAttemptStart)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(len(br.literal)))
				b = append(b, 0x6A)
				b = append(b, 0x20, locLen)
				b = append(b, 0x4B)       // i32.gt_u
				b = append(b, 0x0D, 0x00) // br_if 0 → $next_branch_i (literal can't fit)

				b = emitLiteralByteVerify(b, br.literal, locPtr, locAttemptStart)
			}

			b = append(b, 0x20, locAttemptStart)
			b = append(b, 0x21, locDFAPos)
			b = emitInlineAnchoredDFAVerify(b, br.dfaLayout,
				locPtr, locLen, locDFAState, locDFAPos, locDFAClass, locDFAOutEnd,
				tableMemIdx, 0)
			// Success — return packed (attempt_start, locDFAOutEnd).
			b = emitReturnPackedI64FromLocal(b, locAttemptStart, locDFAOutEnd)
		}

		b = append(b, 0x0B) // end $next_branch_i
		return b
	}
	emitDispatch := func(b []byte) []byte {
		for i := range altp.branches {
			b = emitBranch(b, i)
		}
		return b
	}

	// Group branches by literal[0] (almost always one branch per group —
	// distinct literals rarely share a first byte) and dispatch straight to
	// the matching group via br_table on the candidate byte value, instead
	// of trying every branch's first-byte check in sequence. This is the
	// second half of the task-24 fix: fix #1 (cheap literal pre-check) and
	// fix #2 (mask persistence) address the cost of a false-positive
	// candidate; this addresses the cost of a TRUE-positive one still
	// having to walk past every other branch's first-byte compare before
	// reaching the right one. See plans/TODO.md task 24.
	type group struct {
		firstByte byte
		branches  []int
	}
	var groups []group
	groupOf := [256]int{}
	for i := range groupOf {
		groupOf[i] = -1
	}
	for i, br := range altp.branches {
		fb := br.literal[0]
		if gi := groupOf[fb]; gi >= 0 {
			groups[gi].branches = append(groups[gi].branches, i)
			continue
		}
		groupOf[fb] = len(groups)
		groups = append(groups, group{firstByte: fb, branches: []int{i}})
	}
	n := len(groups)

	// Open n nested blocks: group 0 innermost (closest to br_table), group
	// n-1 outermost. Label i (from br_table's position) exits block i,
	// landing exactly at group i's dispatch code; label n reaches past all
	// of them to $lit_outer (used as br_table's default — unreachable in
	// practice, since Shufti's candidate test is exact, not approximate).
	for i := 0; i < n; i++ {
		b = append(b, 0x02, 0x40) // block $group_i
	}

	b = append(b, 0x20, locPtr)
	b = append(b, 0x20, locAttemptStart)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u — candidate byte value
	b = append(b, 0x0E)             // br_table
	b = utils.AppendULEB128(b, 256)
	for v := 0; v < 256; v++ {
		target := n
		if gi := groupOf[v]; gi >= 0 {
			target = gi
		}
		b = utils.AppendULEB128(b, uint32(target))
	}
	b = utils.AppendULEB128(b, uint32(n)) // default (unreachable)

	for i := 0; i < n; i++ {
		b = append(b, 0x0B) // end block $group_i — lands here for label i
		for _, idx := range groups[i].branches {
			b = emitBranch(b, idx)
		}
		if i < n-1 {
			// Skip the remaining (definitely-wrong-first-byte) groups —
			// without this, falling through would wrongly re-try this
			// candidate against a group whose first byte doesn't match.
			b = append(b, 0x0C, byte(n-1-i)) // br (n-1-i) → continue $lit_outer
		}
		// i == n-1: natural fallthrough into the existing "br 0 →
		// $lit_outer" below reaches the same place.
	}

	// All groups failed at this candidate — loop back. mask was already
	// advanced above, so the next iteration either tries the next candidate
	// bit in the same window for free, or refills once mask is exhausted.
	b = append(b, 0x0C, 0x00) // br 0 → $lit_outer

	b = append(b, 0x0B) // end loop $lit_outer
	b = append(b, 0x0B) // end block $no_match

	// ---- tail: scalar scan of the remaining <16 bytes ----
	// Reached when the SIMD window scan ran out of room for a full 16-byte
	// load. At most 15 bytes remain, so a plain scalar scan (not
	// perf-critical) suffices — reuses the same firstByteFlags data segment
	// the old emitPrefixScan-based scalar tail used. locWindowBase is
	// repurposed here as the scalar scan cursor.
	b = append(b, 0x02, 0x40) // block $tail_done
	b = append(b, 0x03, 0x40) // loop $tail_scan

	// if windowBase >= len: br 1 → $tail_done (exhausted, no match)
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x20, locLen)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1 → $tail_done

	b = append(b, 0x02, 0x40) // block $not_a_candidate
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.firstByteOff)
	b = append(b, 0x20, locPtr)
	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x6A)                   // i32.add
	b = append(b, 0x2D, 0x00, 0x00)       // i32.load8_u (input byte)
	b = append(b, 0x6A)                   // firstByteOff + byte
	b = appendTableLoad8u(b, tableMemIdx) // i32.load8_u (flag)
	b = append(b, 0x45)                   // i32.eqz
	b = append(b, 0x0D, 0x00)             // br_if 0 → $not_a_candidate (skip dispatch)

	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x21, locAttemptStart)
	b = emitDispatch(b)
	// (falls through here only if every branch failed at this position)

	b = append(b, 0x0B) // end block $not_a_candidate

	b = append(b, 0x20, locWindowBase)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, locWindowBase)
	b = append(b, 0x0C, 0x00) // br 0 → continue $tail_scan

	b = append(b, 0x0B) // end loop $tail_scan
	b = append(b, 0x0B) // end block $tail_done

	b = append(b, 0x42, 0x7F)
	b = append(b, 0x0B)
	return b
}
