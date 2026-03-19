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
	start    int
	midStart int // start state for mid-string positions (attempt_start > 0) in find mode;
	// differs from start when pattern has begin anchors (^/\A) — those are not followed here.
	numStates    int
	accepting    map[int]bool // eofAccepting: accepts when at end of input (via $ or \z)
	midAccepting map[int]bool // accepts at any position (no end-anchor expansion needed)

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
		midAccepting: make(map[int]bool),
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

	type workItem struct {
		dfaState int
		nfaSet   []uint32
	}
	queue := []workItem{}

	// Context flags for epsilon closure: controls which empty-width assertions are followed.
	// ecBegin: follow EmptyBeginText (\A) and EmptyBeginLine (^) — valid only at start of input.
	// ecEnd:   follow EmptyEndText (\z) and EmptyEndLine ($)   — valid only at end of input.
	// Mid-string transitions use ctx=0 so no anchors are followed, which prevents impossible
	// sequences like (?:\z)(?:.+) or (?:.+)(?:\A) from appearing reachable.
	const (
		ecBegin = 1
		ecEnd   = 2
	)

	// Compute epsilon closure of NFA states, respecting anchor context.
	epsilonClosure := func(states []uint32, ctx int) []uint32 {
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
				emptyOp := syntax.EmptyOp(inst.Arg)
				follow := false
				if emptyOp&(syntax.EmptyBeginText|syntax.EmptyBeginLine) != 0 {
					follow = (ctx & ecBegin) != 0
				}
				if emptyOp&(syntax.EmptyEndText|syntax.EmptyEndLine) != 0 {
					follow = (ctx & ecEnd) != 0
				}
				// EmptyWordBoundary / EmptyNoWordBoundary: never follow in DFA construction.
				if follow {
					stack = append(stack, inst.Out)
				}
			}
		}
		return result
	}

	// Convert NFA state set to unique string key
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
	startSet := epsilonClosure([]uint32{uint32(prog.Start)}, ecBegin)
	startKey := setToKey(startSet)
	dfa.start = 0
	stateMap[startKey] = 0
	nextStateID++

	if isAccepting(startSet, ecBegin|ecEnd) {
		dfa.accepting[0] = true
	}
	if isAccepting(startSet, 0) {
		dfa.midAccepting[0] = true
	}

	queue = append(queue, workItem{dfaState: 0, nfaSet: startSet})

	// Mid-string start state: epsilon closure WITHOUT begin-anchors, used for
	// attempt_start > 0 in find mode so that ^ and \A don't fire mid-string.
	midStartSet := epsilonClosure([]uint32{uint32(prog.Start)}, 0)
	midStartKey := setToKey(midStartSet)
	if id, exists := stateMap[midStartKey]; exists {
		dfa.midStart = id
	} else {
		dfa.midStart = nextStateID
		stateMap[midStartKey] = nextStateID
		nextStateID++
		if isAccepting(midStartSet, ecEnd) {
			dfa.accepting[dfa.midStart] = true
		}
		if isAccepting(midStartSet, 0) {
			dfa.midAccepting[dfa.midStart] = true
		}
		queue = append(queue, workItem{dfaState: dfa.midStart, nfaSet: midStartSet})
	}

	// Process work queue
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		inputMap := make(map[rune][]uint32)

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
					// Clamp to byte range: ranges like 0x62-0x10FFFF still cover
					// bytes 0x62-0xFF that belong in the DFA transition table.
					lo := minRune
					hi := maxRune
					if hi > 0xFF {
						hi = 0xFF
					}
					for r := lo; r <= hi; r++ {
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

			case syntax.InstRuneAny:
				for b := 0; b < 256; b++ {
					inputMap[rune(b)] = append(inputMap[rune(b)], inst.Out)
				}
			case syntax.InstRuneAnyNotNL:
				for b := 0; b < 256; b++ {
					if b != '\n' {
						inputMap[rune(b)] = append(inputMap[rune(b)], inst.Out)
					}
				}
			}
		}

		for r, nextNFAStates := range inputMap {
			nextSet := epsilonClosure(nextNFAStates, 0)
			nextKey := setToKey(nextSet)

			nextDFAState, exists := stateMap[nextKey]
			if !exists {
				nextDFAState = nextStateID
				stateMap[nextKey] = nextStateID
				nextStateID++

				if isAccepting(nextSet, ecEnd) {
					dfa.accepting[nextDFAState] = true
				}
				if isAccepting(nextSet, 0) {
					dfa.midAccepting[nextDFAState] = true
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

// --------------------------------------------------------------------------
// DFA table

// dfaTable holds the DFA state transition table.
type dfaTable struct {
	startState      int
	midStartState   int          // start state for attempt_start>0 in find mode
	numStates       int
	acceptStates    map[int]bool // eofAccept: accepting at end of input
	midAcceptStates map[int]bool // midAccept: accepting at any position
	transitions     []int        // flat [state*256+byte] = nextState; -1 = dead
}

// dfaTableFrom builds a dfaTable directly from a compiled dfa struct.
func dfaTableFrom(d *dfa) *dfaTable {
	return &dfaTable{
		startState:      d.start,
		midStartState:   d.midStart,
		numStates:       d.numStates,
		acceptStates:    d.accepting,
		midAcceptStates: d.midAccepting,
		transitions:     d.transitions,
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
func genWASM(t *dfaTable, tableBase int64, exportName string, standalone bool, memPages int32, mode MatchMode) []byte {
	// WASM states: 0 = dead/sink, 1..N = Go states 0..N-1
	numWASM := t.numStates + 1
	wasmStart := uint32(t.startState + 1)

	// Use u8 state IDs when all state IDs fit in a single byte.
	// Use byte class compression when the uncompressed u8 table exceeds L1 cache.
	useU8          := numWASM <= 256
	useCompression := useU8 && numWASM*256 > 32*1024

	// Memory layout:
	//   compressed:   classMap(256B) | table(numWASM*numClasses) | accept(numWASM)
	//   u8 simple:    table(numWASM*256) | accept(numWASM)
	//   u16:          table(numWASM*512) | accept(numWASM)
	var (
		classMapOff int32
		tableOff    int32
		classMap    [256]byte
		classRep    []int
		numClasses  int
	)
	if useCompression {
		classMapOff = int32(tableBase)
		tableOff = int32(tableBase) + 256
		classMap, classRep, numClasses = computeByteClasses(t)
	} else {
		tableOff = int32(tableBase)
	}

	// Build transition table.
	var tableBytes []byte
	if useCompression {
		tableBytes = make([]byte, numWASM*numClasses)
		for gs := 0; gs < t.numStates; gs++ {
			ws := gs + 1
			for c, rep := range classRep {
				next := t.transitions[gs*256+rep]
				if next >= 0 {
					tableBytes[ws*numClasses+c] = byte(next + 1)
				}
			}
		}
	} else if useU8 {
		tableBytes = make([]byte, numWASM*256)
		for gs := 0; gs < t.numStates; gs++ {
			ws := gs + 1
			for b := 0; b < 256; b++ {
				next := t.transitions[gs*256+b]
				if next >= 0 {
					tableBytes[ws*256+b] = byte(next + 1)
				}
			}
		}
	} else {
		tableBytes = make([]byte, numWASM*256*2)
		for gs := 0; gs < t.numStates; gs++ {
			ws := gs + 1
			for b := 0; b < 256; b++ {
				next := t.transitions[gs*256+b]
				var wn uint16
				if next >= 0 {
					wn = uint16(next + 1)
				}
				binary.LittleEndian.PutUint16(tableBytes[(ws*256+b)*2:], wn)
			}
		}
	}
	// Dead state row (row 0) stays all-zeros in all cases.

	// EOF accept flags: 1 if state is accepting at end of input (via $ or \z).
	acceptOff := tableOff + int32(len(tableBytes))
	acceptBytes := make([]byte, numWASM)
	for gs := range t.acceptStates {
		acceptBytes[gs+1] = 1
	}

	// Mid-scan accept flags (find mode only): 1 if state accepts at any position.
	midAcceptOff := acceptOff + int32(numWASM)
	midAcceptBytes := make([]byte, numWASM)
	for gs := range t.midAcceptStates {
		midAcceptBytes[gs+1] = 1
	}

	var out []byte

	// ── Magic + version ──────────────────────────────────────────────────────
	out = append(out, 0x00, 0x61, 0x73, 0x6D) // \0asm
	out = append(out, 0x01, 0x00, 0x00, 0x00) // version 1

	// ── Type section (id=1) ─────────────────────────────────────────────────
	// anchored_match: (i32,i32)->i32   find: (i32,i32)->i64
	resultType := byte(0x7F) // i32
	if mode == ModeFind {
		resultType = 0x7E // i64
	}
	ts := []byte{
		0x01,             // 1 type
		0x60,             // functype
		0x02, 0x7F, 0x7F, // 2 params: i32, i32
		0x01, resultType, // 1 result
	}
	out = appendSection(out, 1, ts)

	if !standalone {
		// ── Import section (id=2): (import "main" "memory" (memory 0)) ───────
		var is []byte
		is = append(is, 0x01) // 1 import
		is = appendString(is, "main")
		is = appendString(is, "memory")
		is = append(is, 0x02)              // memory
		is = append(is, 0x00)              // limit type: min only (no max)
		is = utils.AppendULEB128(is, 0x00) // min 0 pages
		out = appendSection(out, 2, is)
	}

	// ── Function section (id=3): 1 function using type 0 ────────────────────
	out = appendSection(out, 3, []byte{0x01, 0x00})

	if standalone {
		// ── Memory section (id=5): define own memory ─────────────────────────
		var ms []byte
		ms = append(ms, 0x01)                         // 1 memory
		ms = append(ms, 0x00)                         // limit type: min only
		ms = utils.AppendULEB128(ms, uint32(memPages)) // min N pages
		out = appendSection(out, 5, ms)
	}

	// ── Export section (id=7) ────────────────────────────────────────────────
	var es []byte
	if standalone {
		es = append(es, 0x02)              // 2 exports: memory + func
		es = appendString(es, "memory")    // export memory so host can write inputs
		es = append(es, 0x02)              // memory kind
		es = utils.AppendULEB128(es, 0x00) // memory index 0
	} else {
		es = append(es, 0x01) // 1 export: func only
	}
	es = appendString(es, exportName)
	es = append(es, 0x00) // func kind
	es = utils.AppendULEB128(es, 0x00)
	out = appendSection(out, 7, es)

	// ── Code section (id=10): function body ─────────────────────────────────
	var body []byte
	wasmMidStart := uint32(t.midStartState + 1)
	if mode == ModeFind {
		body = buildFindBody(wasmStart, wasmMidStart, tableOff, acceptOff, midAcceptOff, classMapOff, numClasses, useU8, useCompression)
	} else {
		body = buildMatchBody(wasmStart, tableOff, acceptOff, classMapOff, numClasses, useU8, useCompression)
	}
	var cs []byte
	cs = append(cs, 0x01) // 1 function
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	cs = append(cs, body...)
	out = appendSection(out, 10, cs)

	// ── Data section (id=11) ─────────────────────────────────────────────────
	var ds []byte
	if useCompression {
		if mode == ModeFind {
			ds = append(ds, 0x04) // classMap + table + eofAccept + midAccept
			ds = appendDataSegment(ds, classMapOff, classMap[:])
			ds = appendDataSegment(ds, tableOff, tableBytes)
			ds = appendDataSegment(ds, acceptOff, acceptBytes)
			ds = appendDataSegment(ds, midAcceptOff, midAcceptBytes)
		} else {
			ds = append(ds, 0x03) // classMap + table + eofAccept
			ds = appendDataSegment(ds, classMapOff, classMap[:])
			ds = appendDataSegment(ds, tableOff, tableBytes)
			ds = appendDataSegment(ds, acceptOff, acceptBytes)
		}
	} else {
		if mode == ModeFind {
			ds = append(ds, 0x03) // table + eofAccept + midAccept
			ds = appendDataSegment(ds, tableOff, tableBytes)
			ds = appendDataSegment(ds, acceptOff, acceptBytes)
			ds = appendDataSegment(ds, midAcceptOff, midAcceptBytes)
		} else {
			ds = append(ds, 0x02) // table + eofAccept
			ds = appendDataSegment(ds, tableOff, tableBytes)
			ds = appendDataSegment(ds, acceptOff, acceptBytes)
		}
	}
	out = appendSection(out, 11, ds)

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
func buildMatchBody(startState uint32, tableOff, acceptOff, classMapOff int32, numClasses int, useU8, useCompression bool) []byte {
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
func buildFindBody(startState, midStartState uint32, tableOff, eofAcceptOff, midAcceptOff, classMapOff int32, numClasses int, useU8, useCompression bool) []byte {
	var b []byte

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

	// ── helper: outer loop prologue ──────────────────────────────────────────
	// Emits: if attempt_start >= len: br $no_match
	//        state=startState, pos=attempt_start, last_accept=-1
	//        if accept[state]: last_accept=pos  (start-state empty-match check)
	emitOuterPrologue := func(b []byte) []byte {
		// if attempt_start > len: br $no_match (depth 1 from $outer)
		// Note: allow attempt_start == len for patterns that match empty string at end.
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x0D, 0x01) // br_if 1 → exit $no_match
		// state = (attempt_start == 0) ? startState : midStartState
		// midStartState was computed without ecBegin so ^ and \A don't fire mid-string.
		if startState == midStartState {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
		} else {
			b = append(b, 0x20, 0x04) // local.get attempt_start
			b = append(b, 0x45)       // i32.eqz
			b = append(b, 0x04, 0x7F) // if (result i32)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(startState))
			b = append(b, 0x05)       // else
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(midStartState))
			b = append(b, 0x0B) // end if
		}
		b = append(b, 0x21, 0x02) // local.set state
		// pos = attempt_start
		b = append(b, 0x20, 0x04) // local.get attempt_start
		b = append(b, 0x21, 0x03) // local.set pos
		// last_accept = -1
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x21, 0x05) // local.set last_accept
		// if midAccept[startState]: last_accept = pos  (empty-string match at attempt_start)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, midAcceptOff)
		b = append(b, 0x20, 0x02)       // local.get state
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, 0x03)       // local.get pos
		b = append(b, 0x21, 0x05)       // local.set last_accept
		b = append(b, 0x0B)             // end if
		return b
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
		// 5 locals: state(2), pos(3), attempt_start(4), last_accept(5), class(6)
		b = append(b, 0x01, 0x05, 0x7F)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitOuterPrologue(b)
		b = append(b, 0x02, 0x40) // block $found
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b)
		b = append(b, 0x0B) // end if

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
		// 4 locals: state(2), pos(3), attempt_start(4), last_accept(5)
		b = append(b, 0x01, 0x04, 0x7F)
		b = append(b, 0x02, 0x40) // block $no_match
		b = append(b, 0x03, 0x40) // loop $outer
		b = emitOuterPrologue(b)
		b = append(b, 0x02, 0x40) // block $found
		b = append(b, 0x03, 0x40) // loop $scan

		// pos >= len?
		b = append(b, 0x20, 0x03) // local.get pos
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x04, 0x40) // if (void)
		b = emitEofHandler(b)
		b = append(b, 0x0B) // end if

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
	// 5 locals: state(2), pos(3), attempt_start(4), last_accept(5), byte(6)
	b = append(b, 0x01, 0x05, 0x7F)
	b = append(b, 0x02, 0x40) // block $no_match
	b = append(b, 0x03, 0x40) // loop $outer
	b = emitOuterPrologue(b)
	b = append(b, 0x02, 0x40) // block $found
	b = append(b, 0x03, 0x40) // loop $scan

	// pos >= len?
	b = append(b, 0x20, 0x03) // local.get pos
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if (void)
	b = emitEofHandler(b)
	b = append(b, 0x0B) // end if

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
