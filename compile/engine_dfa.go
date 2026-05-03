package compile

import (
	"encoding/binary"
	"regexp/syntax"
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
func newDFA(prog *syntax.Prog, needsUnicode bool, leftmostFirst bool, patternBitsArg ...[]uint64) *dfa {
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
	midAcceptNLOff     int32
	midAcceptNWBytes   []byte
	midAcceptWBytes    []byte
	midAcceptNLBytes   []byte

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
	wasmPrefixEnd       uint32
	startBeginAccept    bool

	// tableEnd is the highest memory address used by any table in this layout.
	tableEnd int64

	// useHybridDispatch is true when the hybrid path is chosen: table-driven
	// state transitions combined with compiled self-loop inner blocks.
	useHybridDispatch bool
}

// dfaTableBytes returns the upper-bound byte footprint of the runtime transition
// and accept tables for a minimised DFA (uncompressed size for u8 tables, exact
// for u16). Used to enforce MaxDFAMemory before committing to a DFA layout.
func dfaTableBytes(t *dfaTable) int {
	n := t.numStates + 1 // +1 for the implicit dead state at index 0
	if n <= 256 {
		return n * 257 // u8: transitions(n*256) + accept(n)
	}
	return n * 513 // u16: transitions(n*256*2) + accept(n)
}

// buildDFALayout computes all DFA table data and offsets. needFind must be true
// when a find function will be emitted (computes extra tables for find mode).
// compiledDFAThreshold is the resolved threshold (0 = disabled, 1..256 = active).
// forceWordChar (optional): force word-char table computation even when needFind=false.
func buildDFALayout(t *dfaTable, tableBase int64, needFind, leftmostFirst bool, compiledDFAThreshold int, forceWordChar ...bool) *dfaLayout {
	wantWordChar := needFind || (len(forceWordChar) > 0 && forceWordChar[0])
	l := &dfaLayout{}
	l.numWASM = t.numStates + 1
	l.wasmStart = uint32(t.startState + 1)
	l.useU8 = l.numWASM <= 256
	l.useCompression = l.useU8 && l.numWASM*256 > 32*1024

	// Hybrid dispatch: active when useU8 and state count fits within threshold.
	// Uses the natural compression decision (does NOT force compression).
	// When the table is uncompressed, classMap is still computed at Go time for
	// literalChain analysis but is not emitted to the WASM data segment.
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

	// EOF accept flags — u8 per state (1 = any pattern accepts, 0 = none).
	// Multi-pattern wider encoding (u32/u64) is deferred to Phase 4c.
	l.acceptOff = l.tableOff + int32(len(l.tableBytes))
	l.acceptBytes = make([]byte, l.numWASM)
	for gs, bits := range t.acceptStates {
		if bits != 0 {
			l.acceptBytes[gs+1] = 1
		}
	}

	// Mid-scan accept flags.
	l.midAcceptOff = l.acceptOff + int32(l.numWASM)
	l.midAcceptBytes = make([]byte, l.numWASM)
	for gs, bits := range t.midAcceptStates {
		if bits != 0 {
			l.midAcceptBytes[gs+1] = 1
		}
	}

	// Immediate-accept flags (LeftmostFirst, both match and find).
	if leftmostFirst && len(t.immediateAcceptStates) > 0 {
		l.hasImmAccept = true
		l.immediateAcceptOff = l.midAcceptOff + int32(l.numWASM)
		l.immediateAcceptBytes = make([]byte, l.numWASM)
		for gs, bits := range t.immediateAcceptStates {
			if bits != 0 {
				l.immediateAcceptBytes[gs+1] = 1
			}
		}
	}

	immAcceptSize := int32(0)
	if l.hasImmAccept {
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
								if validCount4 > 64 {
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
		if l.midAcceptNLBytes != nil {
			ds = appendDataSegment(ds, l.midAcceptNLOff, l.midAcceptNLBytes)
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
		if l.midAcceptNLBytes != nil {
			n++
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
							if len(l.teddyT3LoBytes) > 0 {
								ds = appendDataSegment(ds, l.teddyT3LoOff, l.teddyT3LoBytes)
								ds = appendDataSegment(ds, l.teddyT3HiOff, l.teddyT3HiBytes)
							}
						}
					}
				}
			} else {
				ds = append(ds, findSegCount(4))
				ds = emitFindSegs(ds, transSegs)
			}
		} else {
			count := byte(4) // classMap + transitions + accept + midAccept
			if l.hasImmAccept {
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
			ds = appendDataSegment(ds, l.classMapOff, l.classMap[:])
			if l.useRowDedup {
				ds = appendDataSegment(ds, l.rowMapOff, l.rowMapBytes)
			}
			ds = appendDataSegment(ds, l.tableOff, l.tableBytes)
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			ds = appendDataSegment(ds, l.midAcceptOff, l.midAcceptBytes)
			if l.hasImmAccept {
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
							if len(l.teddyT3LoBytes) > 0 {
								ds = appendDataSegment(ds, l.teddyT3LoOff, l.teddyT3LoBytes)
								ds = appendDataSegment(ds, l.teddyT3HiOff, l.teddyT3HiBytes)
							}
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
			ds = appendDataSegment(ds, l.acceptOff, l.acceptBytes)
			if l.hasImmAccept {
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
func genSuffixWASM(t *dfaTable, tableBase int64, tableMemIdx int, patternIDs, prefixFixedLens []int) (funcBody []byte, dataBytes []byte, dataSegCount int) {
	if t == nil || t.numStates == 0 {
		// Empty DFA: return 0 (no matches).
		body := []byte{0x01, 0x01, 0x7F} // 1 local i32
		body = append(body, 0x41, 0x00)  // i32.const 0
		body = append(body, 0x0B)        // end
		funcBody = utils.AppendULEB128(nil, uint32(len(body)))
		funcBody = append(funcBody, body...)
		return
	}

	l := buildDFALayout(t, tableBase, false, true, 0, t.hasWordBoundary)

	// Four 8-byte-per-state bitmask tables placed after all layout data.
	midBitmaskOff    := int32(l.tableEnd)
	eofBitmaskOff    := midBitmaskOff + int32(l.numWASM)*8
	immBitmaskOff    := eofBitmaskOff + int32(l.numWASM)*8
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
	if t.hasWordBoundary {
		dataBytes = append(dataBytes, appendDataSegment(nil, wbNWBitmaskOff, writeBitmask(t.midAcceptNWStates))...)
		dataBytes = append(dataBytes, appendDataSegment(nil, wbWBitmaskOff, writeBitmask(t.midAcceptWStates))...)
		dataSegCount += 2
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

// buildSuffixBody generates the WASM function body for suffix DFA scanning.
// Signature: (ptr i32, start i32, len i32) → i64
//
// midBitmaskOff: 8-byte-per-state table of midAcceptStates (any-position accept).
// eofBitmaskOff: 8-byte-per-state table of acceptStates (end-of-input accept, $ anchors).
//
// endPos is updated greedily on every mid-accept (not just the first), giving
// correct leftmost-first match lengths for a*, a+, a?, etc.
func buildSuffixBody(l *dfaLayout, midBitmaskOff, eofBitmaskOff int32, tableMemIdx int) []byte {
	const (
		paramPtr   = byte(0)
		paramStart = byte(1)
		paramLen   = byte(2)
		lState     = byte(3)
		lPos       = byte(4)
		lEndPos    = byte(5)
		lByteClass = byte(6)
		lBits      = byte(7)
		lResult    = byte(8)
	)
	var b []byte
	// 2 local groups: (4 × i32: state, pos, endPos, byteOrClass), (2 × i64: bits, result)
	b = append(b, 0x02, 0x04, 0x7F, 0x02, 0x7E)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x21, lState)                 // state = wasmStart
	b = append(b, 0x20, paramStart, 0x21, lPos) // pos = start
	// lEndPos, lBits, lResult = 0 (default)

	// Check start-state midAccept: handles patterns whose suffix accepts empty
	// (e.g. mandatory literal IS the whole pattern, or a* / b? at suffix start).
	// Uses midBitmaskOff so $ patterns (acceptStates only) are excluded here.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midBitmaskOff)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(l.wasmStart))
	b = append(b, 0x41, 0x03, 0x74, 0x6A) // wasmStart*8; midBitmaskOff + wasmStart*8
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)                     // lBits = midBitmask[wasmStart]
	b = append(b, 0x20, lBits, 0x42, 0x00, 0x52)   // bits != 0
	b = append(b, 0x04, 0x40)                      // if
	b = append(b, 0x20, paramStart, 0x21, lEndPos) // endPos = paramStart
	b = append(b, 0x20, lBits, 0x21, lResult)      // result = bits
	b = append(b, 0x0B)                            // end if

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br $done
	b = append(b, 0x20, lPos, 0x20, paramLen, 0x4F, 0x0D, 0x01)

	// DFA transition
	if l.useU8 && l.useCompression {
		b = emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			l.useRowDedup, l.rowMapOff, lState, lByteClass, paramPtr, lPos, 0xff, tableMemIdx)
	} else if l.useU8 {
		b = emitSimpleU8Transition(b, l.tableOff, l.useRowDedup, l.rowMapOff,
			lState, paramPtr, lPos, 0xff, tableMemIdx)
	} else {
		// u16: load input byte into lByteClass first
		b = append(b, 0x20, paramPtr, 0x20, lPos, 0x6A, 0x2D, 0x00, 0x00) // mem[ptr+pos]
		b = append(b, 0x21, lByteClass)
		b = emitU16Transition(b, l.tableOff, l.useRowDedup, l.rowMapOff, lState, lByteClass, tableMemIdx)
	}

	// lBits = midBitmask[state * 8] — fires at any position (no $ context)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midBitmaskOff)
	b = append(b, 0x20, lState)
	b = append(b, 0x41, 0x03, 0x74, 0x6A) // state*8; midBitmaskOff + state*8
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)

	// if bits!=0: endPos = pos+1 (greedy — update on every accept, not just first)
	b = append(b, 0x20, lBits, 0x42, 0x00, 0x52)               // bits != 0
	b = append(b, 0x04, 0x40)                                  // if (void)
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lEndPos) // endPos = pos+1
	b = append(b, 0x0B)                                        // end if

	// result |= bits
	b = append(b, 0x20, lResult, 0x20, lBits, 0x84, 0x21, lResult) // i64.or

	// if immediateAccept[state]: br $done (LeftmostFirst early exit)
	if l.hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, lState)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx)
		b = append(b, 0x0D, 0x01) // br_if $done
	}

	// if state == 0 (dead): br $done
	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01) // i32.eqz + br_if $done

	// pos++; br $main
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br $main

	b = append(b, 0x0B) // end loop $main
	b = append(b, 0x0B) // end block $done

	// EOF accept: load eofBitmask[state] for $ anchors and patterns accepting at EOF.
	// If endPos still 0 (no mid-accept), set endPos = lPos (scan position at EOF).
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, eofBitmaskOff)
	b = append(b, 0x20, lState)
	b = append(b, 0x41, 0x03, 0x74, 0x6A) // state*8; eofBitmaskOff + state*8
	b = appendTableLoad64(b, tableMemIdx)
	b = append(b, 0x21, lBits)
	b = append(b, 0x20, lBits, 0x42, 0x00, 0x52)                   // lBits != 0
	b = append(b, 0x04, 0x40)                                      // if
	b = append(b, 0x20, lEndPos, 0x45)                             // i32.eqz endPos
	b = append(b, 0x04, 0x40)                                      // if endPos == 0
	b = append(b, 0x20, lPos, 0x21, lEndPos)                       // endPos = lPos
	b = append(b, 0x0B)                                            // end if
	b = append(b, 0x20, lResult, 0x20, lBits, 0x84, 0x21, lResult) // result |= lBits
	b = append(b, 0x0B)                                            // end if lBits != 0

	// return (i64(endPos) << 32) | (result & 0xFFFFFFFF)
	b = append(b, 0x20, lEndPos)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, lResult)
	b = append(b, 0xA7) // i32.wrap_i64
	b = append(b, 0xAD) // i64.extend_i32_u
	b = append(b, 0x84) // i64.or
	b = append(b, 0x0B) // end function
	return b
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
	endPosK    := func(k int) byte { return endPosBase + byte(k) }
	lBits        := byte(14 + n)
	lResult      := byte(15 + n)
	lStartResult := byte(16 + n)

	var b []byte
	// Local declaration: (7 + n) × i32, 3 × i64
	b = append(b, 0x02)
	b = utils.AppendULEB128(b, uint32(7+n))
	b = append(b, 0x7F)       // i32
	b = append(b, 0x03, 0x7E) // 3 × i64

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
		b = utils.AppendSLEB128(b, int32(wordCharOff[0]))
		b = append(b, 0x20, paramPtr, 0x20, paramLPos, 0x41, 0x01, 0x6B, 0x6A) // paramPtr + paramLPos - 1
		b = appendTableLoad8u(b, tableMemIdx)                                    // input[prev]
		b = append(b, 0x6A)                                                      // wordCharOff + input[prev]
		b = appendTableLoad8u(b, tableMemIdx)                                    // wordChar[prev]
		b = append(b, 0x04, 0x7F)                                               // if prevWasWord (result i32)
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
	b = append(b, 0x0B)      // end outer if → i32 on stack
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
		b = utils.AppendSLEB128(b, int32(wordCharOff[0]))
		b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A)  // paramPtr + lScanPos
		b = appendTableLoad8u(b, tableMemIdx)                  // input[lScanPos]
		b = append(b, 0x6A)                                    // wordCharOff + byte
		b = appendTableLoad8u(b, tableMemIdx)                  // wordChar[byte] (isWord)
		b = append(b, 0x04, 0x40)                             // if isWord (void)
		// isWord: wbBits = wbWBitmask[lState]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wbW))
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0x21, lBits)
		b = append(b, 0x05) // else: !isWord
		// !isWord: wbBits = wbNWBitmask[lState]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wbNW))
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
			l.useRowDedup, l.rowMapOff, lState, lByteClass, paramPtr, lScanPos, 0xff, tableMemIdx)
	} else if l.useU8 {
		b = emitSimpleU8Transition(b, l.tableOff, l.useRowDedup, l.rowMapOff,
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
		body = buildMatchBody(l.wasmStart, l.tableOff, l.acceptOff, l.classMapOff,
			l.numClasses, l.useU8, l.useCompression,
			l.immediateAcceptOff, hasImmAccept, l.rowMapOff, l.useRowDedup, tableMemIdx)
	}
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// appendFindCodeEntry appends a size-prefixed find function body to cs.
// Uses buildAnchoredFindBody when isAnchoredFind(t), else buildFindBody.
func appendFindCodeEntry(cs []byte, l *dfaLayout, t *dfaTable, mandatoryLit *mandatoryLit, tableMemIdx int) []byte {
	var body []byte
	if l.useHybridDispatch {
		if isAnchoredFind(t) {
			body = buildHybridAnchoredFindBody(t, l, tableMemIdx)
		} else {
			body = buildHybridFindBody(t, l, mandatoryLit, tableMemIdx)
		}
	} else if isAnchoredFind(t) {
		body = buildAnchoredFindBody(l.wasmStart, l.tableOff, l.acceptOff, l.midAcceptOff,
			l.classMapOff, l.numClasses, l.useU8, l.useCompression,
			l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept,
			l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff,
			l.rowMapOff, l.useRowDedup, l.midAcceptNLOff, t.hasNewlineBoundary, tableMemIdx)
	} else {
		body = buildFindBody(l.wasmStart, l.wasmMidStart, l.wasmMidStartWord,
			l.wasmMidStartNewline, l.wasmPrefixEnd, l.tableOff, l.acceptOff, l.midAcceptOff,
			l.firstByteOff, l.prefix, l.classMapOff, l.numClasses,
			l.useU8, l.useCompression, l.startBeginAccept,
			l.immediateAcceptOff, l.hasImmAccept,
			l.wordCharTableOff, l.needWordCharTable,
			l.midAcceptNWOff, l.midAcceptWOff, t.hasNewlineBoundary,
			l.firstByteFlags, l.firstBytes,
			l.teddyLoOff, l.teddyHiOff,
			l.teddyT1LoOff, l.teddyT1HiOff, len(l.teddyT1LoBytes) > 0,
			l.teddyT2LoOff, l.teddyT2HiOff, len(l.teddyT2LoBytes) > 0,
			l.teddyT3LoOff, l.teddyT3HiOff, len(l.teddyT3LoBytes) > 0,
			mandatoryLit, l.rowMapOff, l.useRowDedup, l.midAcceptNLOff, tableMemIdx)
	}
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// emitCompressedU8Transition emits the compressed u8 DFA transition:
//
//	class = classMap[classMapOff + byte]
//	state = table[tableOff + row*numClasses + class]
//
// where byte is loaded from mem[ptrLocal+posLocal] when byteLocal==0xff,
// or taken from byteLocal otherwise (byte already in a local).
// row = rowMap[state] when useRowDedup, otherwise row = state.
// classLocal receives the class value; stateLocal is updated with the new state.
func emitCompressedU8Transition(b []byte,
	tableOff, classMapOff int32, numClasses int,
	useRowDedup bool, rowMapOff int32,
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
	if useRowDedup {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, rowMapOff)
		b = append(b, 0x20, stateLocal)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // rowMap[state] → row
	} else {
		b = append(b, 0x20, stateLocal)
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(numClasses))
	b = append(b, 0x6C)                   // i32.mul
	b = append(b, 0x6A)                   // i32.add
	b = append(b, 0x20, classLocal)       // local.get class
	b = append(b, 0x6A)                   // i32.add
	b = appendTableLoad8u(b, tableMemIdx) // table[row*numClasses+class]
	b = append(b, 0x21, stateLocal)
	return b
}

// emitSimpleU8Transition emits the simple u8 DFA transition:
//
//	state = table[tableOff + row*256 + byte]
//
// where byte is loaded from mem[ptrLocal+posLocal] when byteLocal==0xff,
// or taken from byteLocal otherwise.
// row = rowMap[state] when useRowDedup, otherwise row = state.
// stateLocal is updated with the new state.
func emitSimpleU8Transition(b []byte,
	tableOff int32,
	useRowDedup bool, rowMapOff int32,
	stateLocal byte,
	ptrLocal, posLocal byte,
	byteLocal byte,
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
	b = appendTableLoad8u(b, tableMemIdx) // table[row*256+byte]
	b = append(b, 0x21, stateLocal)
	return b
}

// emitU16Transition emits the u16 DFA transition:
//
//	state = u16(table[tableOff + row*512 + byteLocal*2])
//
// byteLocal must be a pre-loaded i32 local containing the input byte.
// row = rowMap[state] when useRowDedup, otherwise row = state.
// stateLocal is updated with the new state.
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
	b = appendTableLoad16u(b, tableMemIdx) // i32.load16_u
	b = append(b, 0x21, stateLocal)
	return b
}

// emitImmAcceptCheckMatch emits: if immediateAccept[state]: return pos.
// Used in match mode. No-op when hasImmAccept is false.
func emitImmAcceptCheckMatch(b []byte, immediateAcceptOff int32,
	hasImmAccept bool, stateLocal, posLocal byte, tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immediateAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if
	return b
}

// emitImmAcceptCheckFindMid emits: if immediateAccept[state]: last_accept=pos+1; br brDepth.
// Used mid-scan in find mode. No-op when hasImmAccept is false.
func emitImmAcceptCheckFindMid(b []byte, immediateAcceptOff int32,
	hasImmAccept bool, stateLocal, posLocal, lastAcceptLocal byte,
	brDepth byte, tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immediateAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // pos + 1
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0C, brDepth) // br brDepth
	b = append(b, 0x0B)          // end if
	return b
}

// emitImmAcceptCheckFindStart emits: if immediateAccept[state]: last_accept=pos; br brDepth.
// Used at the start of each attempt in find mode. No-op when hasImmAccept is false.
func emitImmAcceptCheckFindStart(b []byte, immediateAcceptOff int32,
	hasImmAccept bool, stateLocal, posLocal, lastAcceptLocal byte,
	brDepth byte, tableMemIdx int) []byte {
	if !hasImmAccept {
		return b
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, immediateAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, posLocal)
	b = append(b, 0x21, lastAcceptLocal)
	b = append(b, 0x0C, brDepth) // br brDepth
	b = append(b, 0x0B)          // end if
	return b
}

// emitEofHandler emits the EOF (pos >= len) handler inside the DFA scan loop.
// Checks eofAccept[state]; if set, updates last_accept = pos.
// When hasRetry is false (anchored mode): unconditionally br foundDepth → $found.
// When hasRetry is true (full find mode): br_if foundDepth → $found if last_accept>=0,
// otherwise increment attemptStartLocal and br outerDepth → $outer.
func emitEofHandler(b []byte, eofAcceptOff int32,
	stateLocal, posLocal, lastAcceptLocal, attemptStartLocal byte,
	foundDepth byte, hasRetry bool, outerDepth byte,
	tableMemIdx int) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, eofAcceptOff)
	b = append(b, 0x20, stateLocal)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx)
	b = append(b, 0x04, 0x40) // if eofAccept[state]
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
		b = append(b, 0x20, attemptStartLocal)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, attemptStartLocal)
		b = append(b, 0x0C, outerDepth) // br → $outer
	}
	return b
}

// emitDeadHandler emits the dead-state handler inside the DFA scan loop.
// When hasRetry is false (anchored mode): unconditionally br foundDepth → $found.
// When hasRetry is true (full find mode): br_if foundDepth → $found if last_accept>=0,
// otherwise increment attemptStartLocal and br outerDepth → $outer.
func emitDeadHandler(b []byte,
	lastAcceptLocal, attemptStartLocal byte,
	foundDepth byte, hasRetry bool, outerDepth byte) []byte {
	if !hasRetry {
		b = append(b, 0x0C, foundDepth) // br → $found (unconditional, anchored)
	} else {
		b = append(b, 0x20, lastAcceptLocal)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4E)             // i32.ge_s
		b = append(b, 0x0D, foundDepth) // br_if → $found
		b = append(b, 0x20, attemptStartLocal)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, attemptStartLocal)
		b = append(b, 0x0C, outerDepth) // br → $outer
	}
	return b
}

// emitWBPreAcceptCheck emits: before the DFA transition, check wordChar/non-wordChar
// and update last_accept from midAcceptW or midAcceptNW accordingly.
// No-op when hasWordBoundary is false.
func emitWBPreAcceptCheck(b []byte, wordCharTableOff, midAcceptWOff, midAcceptNWOff int32,
	hasWordBoundary bool,
	ptrLocal, posLocal, stateLocal, lastAcceptLocal byte,
	tableMemIdx int) []byte {
	if !hasWordBoundary {
		return b
	}
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
	ptrLocal, posLocal, stateLocal, lastAcceptLocal byte,
	tableMemIdx int) []byte {
	if !hasNewlineBoundary {
		return b
	}
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
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=class
//
// u8 simple (useU8=true, useCompression=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos
//
// u16 (useU8=false):
//
//	Local indices: 0=ptr 1=len 2=state 3=pos 4=byte
func buildMatchBody(startState uint32, tableOff, acceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, immediateAcceptOff int32, hasImmAccept bool, rowMapOff int32, useRowDedup bool, tableMemIdx int) []byte {
	var b []byte

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

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			useRowDedup, rowMapOff, 0x02, 0x04, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckMatch(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
		b = appendTableLoad8u(b, tableMemIdx) // accept check
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

		b = emitSimpleU8Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40) // if state == 0: return -1
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		b = emitImmAcceptCheckMatch(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
		b = appendTableLoad8u(b, tableMemIdx) // accept check
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
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x21, 0x04)       // local.set byte

	b = emitU16Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x04, tableMemIdx)

	b = append(b, 0x20, 0x02)
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40) // if state == 0: return -1
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	b = emitImmAcceptCheckMatch(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, tableMemIdx)

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
	b = appendTableLoad8u(b, tableMemIdx) // i32.load8_u
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x05)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B)

	b = append(b, 0x0B) // end function
	return b
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
func buildAnchoredFindBody(startState uint32, tableOff, eofAcceptOff, midAcceptOff, classMapOff int32, numClasses int, useU8, useCompression bool, startBeginAccept bool, immediateAcceptOff int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, rowMapOff int32, useRowDedup bool, midAcceptNLOff int32, hasNewlineBoundary bool, tableMemIdx int) []byte {
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
		b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03) // pos
		b = append(b, 0x20, 0x01) // len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, false, 0, tableMemIdx)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			useRowDedup, rowMapOff, 0x02, 0x06, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02) // dead?
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b, 0x05, 0x04, 2, false, 0)
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

		b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
		b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x04, 0x40)
		b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, false, 0, tableMemIdx)
		b = append(b, 0x0B)

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

		b = emitSimpleU8Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = emitDeadHandler(b, 0x05, 0x04, 2, false, 0)
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

		b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
	b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, 0x03)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x04, 0x40)
	b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, false, 0, tableMemIdx)
	b = append(b, 0x0B)

	b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
	b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

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
	b = emitDeadHandler(b, 0x05, 0x04, 2, false, 0)
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

	b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
	// if acceptOff[state] != 0: last_accept = 0 (match starts at text start)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, revL.acceptOff)
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // accept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x41, 0x00)             // i32.const 0
	b = append(b, 0x21, 0x04)             // local.set last_accept
	b = append(b, 0x0B)                   // end if
	b = append(b, 0x0C, 0x02)             // br 2 → $done (0=outer_if, 1=$rev, 2=$done)
	b = append(b, 0x0B)                   // end if pos<0

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
			false, 0, 0x02, 0x05, 0, 0, 0x05, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, revL.tableOff, false, 0, 0x02, 0, 0, 0x05, tableMemIdx)
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
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, locState)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // immediateAccept[state]
		b = append(b, 0x04, 0x40)             // if (void)
		b = append(b, 0x0C, 0x01)             // br 1 → $fwd_done (0=if, 1=$fwd_done)
		b = append(b, 0x0B)                   // end if
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
	// if acceptOff[state]: last_accept = pos (EOF accept)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // accept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x21, locLastAccept) // last_accept = pos
	b = append(b, 0x0B)                // end if accept
	b = append(b, 0x0C, 0x02)          // br 2 → $fwd_done (0=eof_if, 1=$fwd_scan, 2=$fwd_done)
	b = append(b, 0x0B)                // end if pos>=len

	b = emitNLPreAcceptCheck(b, l.midAcceptNLOff, t.hasNewlineBoundary, locPtr, locPos, locState, locLastAccept, tableMemIdx)

	// DFA transition.
	if l.useCompression {
		b = emitCompressedU8Transition(b, l.tableOff, l.classMapOff, l.numClasses,
			false, 0, locState, locSimdOrClass, locPtr, locPos, 0xff, tableMemIdx)
	} else {
		b = emitSimpleU8Transition(b, l.tableOff, false, 0, locState, locPtr, locPos, 0xff, tableMemIdx)
	}

	// if state == 0 (dead): exit $fwd_done.
	b = append(b, 0x20, locState)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x0C, 0x02) // br 2 → $fwd_done (0=dead_if, 1=$fwd_scan, 2=$fwd_done)
	b = append(b, 0x0B)       // end if dead

	// if midAccept[state]: last_accept = pos + 1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.midAcceptOff)
	b = append(b, 0x20, locState)
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, locPos)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // pos + 1
	b = append(b, 0x21, locLastAccept)
	b = append(b, 0x0B) // end if midAccept

	b = emitImmAcceptCheckFindMid(b, l.immediateAcceptOff, l.hasImmAccept, locState, locPos, locLastAccept, 2, tableMemIdx)

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
func buildFindBody(startState, midStartState, midStartWordState, midStartNewlineState, prefixEndState uint32, tableOff, eofAcceptOff, midAcceptOff, firstByteOff int32, prefix []byte, classMapOff int32, numClasses int, useU8, useCompression bool, startBeginAccept bool, immediateAcceptOff int32, hasImmAccept bool, wordCharTableOff int32, hasWordBoundary bool, midAcceptNWOff, midAcceptWOff int32, hasNewlineBoundary bool, firstByteFlags [256]byte, firstBytes []byte, teddyLoOff, teddyHiOff, teddyT1LoOff, teddyT1HiOff int32, teddyTwoByte bool, teddyT2LoOff, teddyT2HiOff int32, teddyThreeByte bool, teddyT3LoOff, teddyT3HiOff int32, teddyFourByte bool, mandatoryLit *mandatoryLit, rowMapOff int32, useRowDedup bool, midAcceptNLOff int32, tableMemIdx int) []byte {
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

	// Mandatory-lit locals (set in each path branch when useMandatoryLit):
	var litPosLocal, scanStartLocal, simdMaskScanLocal, chunkScanLocal byte

	// ── helper: outer loop prologue ──────────────────────────────────────────
	// Emits: if attempt_start >= len: br $no_match
	//        state=startState, pos=attempt_start, last_accept=-1
	//        if accept[state]: last_accept=pos  (start-state empty-match check)
	emitOuterPrologue := func(b []byte) []byte {
		params := prefixScanParams{
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
			TeddyT3LoOff:   teddyT3LoOff,
			TeddyT3HiOff:   teddyT3HiOff,
			TeddyFourByte:  teddyFourByte,
			TableMemIdx:    tableMemIdx,
			EngineDepth:    2, // loop $outer + block $no_match
			Locals: prefixScanLocals{
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
				Chunk3:       chunk3Local,
				T3Lo:         t3LoLocal,
				T3Hi:         t3HiLocal,
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
				// last_accept = -1
				b = append(b, 0x41, 0x7F) // i32.const -1
				b = append(b, 0x21, 0x05) // local.set last_accept
				// if midAccept[state]: last_accept = pos
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, midAcceptOff)
				b = append(b, 0x20, 0x02)             // local.get state
				b = append(b, 0x6A)                   // i32.add
				b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
				b = append(b, 0x04, 0x40)             // if (void)
				b = append(b, 0x20, 0x03)             // local.get pos
				b = append(b, 0x21, 0x05)             // local.set last_accept
				b = append(b, 0x0B)                   // end if
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
			// 8 i32 + 1 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),lit_pos(7),scan_start(8),simdMask_scan(9),chunk_scan(10)
			litPosLocal = 7
			scanStartLocal = 8
			simdMaskScanLocal = 9
			chunkScanLocal = 10
			b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7B)
		} else {
			// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),class(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
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
			if teddyFourByte {
				// 6 i32 + 12 v128: adds chunk3(17),t3Lo(18),t3Hi(19)
				chunk3Local = 17
				t3LoLocal = 18
				t3HiLocal = 19
				b = append(b, 0x02, 0x06, 0x7F, 0x0C, 0x7B)
			} else {
				b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
			}
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, true, 3, tableMemIdx)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

		b = emitCompressedU8Transition(b, tableOff, classMapOff, numClasses,
			useRowDedup, rowMapOff, 0x02, 0x06, 0x00, 0x03, 0xff, tableMemIdx)

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b, 0x05, 0x04, 2, true, 3)
		b = append(b, 0x0B) // end if

		// if midAccept[state]: last_accept = pos + 1
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)             // local.get state
		b = append(b, 0x6A)                   // i32.add
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)             // if (void)
		b = append(b, 0x20, 0x03)             // local.get pos
		b = append(b, 0x41, 0x01)             // i32.const 1
		b = append(b, 0x6A)                   // i32.add
		b = append(b, 0x21, 0x05)             // local.set last_accept
		b = append(b, 0x0B)                   // end if

		b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
			litPosLocal = 6
			scanStartLocal = 7
			simdMaskScanLocal = 8
			chunkScanLocal = 9
			b = append(b, 0x02, 0x07, 0x7F, 0x01, 0x7B)
		} else {
			// 5 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),simdMask(6),chunk(7),...,chunk2(13),t2Lo(14),t2Hi(15)
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
			if teddyFourByte {
				// 5 i32 + 12 v128: adds chunk3(16),t3Lo(17),t3Hi(18)
				chunk3Local = 16
				t3LoLocal = 17
				t3HiLocal = 18
				b = append(b, 0x02, 0x05, 0x7F, 0x0C, 0x7B)
			} else {
				b = append(b, 0x02, 0x05, 0x7F, 0x09, 0x7B)
			}
		}
		b = append(b, 0x02, 0x40) // block $no_match
		if useMandatoryLit {
			b = emitMLOuterSetup(b)
		} else {
			b = append(b, 0x03, 0x40) // loop $outer
			b = emitOuterPrologue(b)
		}
		b = append(b, 0x02, 0x40) // block $found
		b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, true, 3, tableMemIdx)
		b = append(b, 0x0B) // end if

		b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
		b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

		b = emitSimpleU8Transition(b, tableOff, useRowDedup, rowMapOff, 0x02, 0x00, 0x03, 0xff, tableMemIdx)

		// dead state?
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = emitDeadHandler(b, 0x05, 0x04, 2, true, 3)
		b = append(b, 0x0B) // end if

		// if midAccept[state]: last_accept = pos + 1
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02) // local.get state
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
		b = append(b, 0x04, 0x40)             // if (void)
		b = append(b, 0x20, 0x03)             // local.get pos
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x05) // local.set last_accept
		b = append(b, 0x0B)       // end if

		b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
		// 6 i32 + 9 v128: state(2),pos(3),attempt_start(4),last_accept(5),byte(6),simdMask(7),chunk(8),...,chunk2(14),t2Lo(15),t2Hi(16)
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
		if teddyFourByte {
			// 6 i32 + 12 v128: adds chunk3(17),t3Lo(18),t3Hi(19)
			chunk3Local = 17
			t3LoLocal = 18
			t3HiLocal = 19
			b = append(b, 0x02, 0x06, 0x7F, 0x0C, 0x7B)
		} else {
			b = append(b, 0x02, 0x06, 0x7F, 0x09, 0x7B)
		}
	}
	b = append(b, 0x02, 0x40) // block $no_match
	if useMandatoryLit {
		b = emitMLOuterSetup(b)
	} else {
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitOuterPrologue(b)
	}
	b = append(b, 0x02, 0x40) // block $found
	b = emitImmAcceptCheckFindStart(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 1, tableMemIdx)
	b = append(b, 0x03, 0x40) // loop $scan

	// pos >= len?
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitEofHandler(b, eofAcceptOff, 0x02, 0x03, 0x05, 0x04, 2, true, 3, tableMemIdx)
	b = append(b, 0x0B) // end if

	b = emitWBPreAcceptCheck(b, wordCharTableOff, midAcceptWOff, midAcceptNWOff, hasWordBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)
	b = emitNLPreAcceptCheck(b, midAcceptNLOff, hasNewlineBoundary, 0x00, 0x03, 0x02, 0x05, tableMemIdx)

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
	b = emitDeadHandler(b, 0x05, 0x04, 2, true, 3)
	b = append(b, 0x0B) // end if

	// if midAccept[state]: last_accept = pos + 1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, midAcceptOff)
	b = append(b, 0x20, 0x02) // local.get state
	b = append(b, 0x6A)
	b = appendTableLoad8u(b, tableMemIdx) // midAccept[state]
	b = append(b, 0x04, 0x40)             // if (void)
	b = append(b, 0x20, 0x03)             // local.get pos
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, 0x05) // local.set last_accept
	b = append(b, 0x0B)       // end if

	b = emitImmAcceptCheckFindMid(b, immediateAcceptOff, hasImmAccept, 0x02, 0x03, 0x05, 2, tableMemIdx)

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
