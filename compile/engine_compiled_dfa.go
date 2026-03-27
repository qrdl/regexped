package compile

import (
	"sort"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Compiled DFA engine
//
// Instead of a generic table-lookup loop, each state's transitions are baked
// into WASM bytecode as i32.const immediates, dispatched via per-state logic
// chosen at compile time based on the number of live transitions:
//
//   dead (0 live classes):  i32.const -1; return  (no class load)
//   single (1 live class):  class == c0 ? state=ns : dead
//   sparse (2..sparseCutoff): chain of if/else comparisons against class index
//   full (> sparseCutoff):  inner br_table over class index
//
// classMap (256 B) is still loaded for all non-dead states — it maps each byte
// to its equivalence class index (always L1-resident after first access).
// The transitions table is eliminated entirely regardless of strategy.
// The benefit of single/sparse over full is removing the inner br_table and
// its K nested blocks, replacing with 1 or a few direct i32.eq comparisons.
//
// Phase 1: anchored match only (buildCompiledMatchBody).
// Phase 2 (future): find mode variants.

// sparseCutoff is the maximum number of live classes for which the
// sparse if/else chain strategy is used. States with more live classes
// use the full two-level br_table. Tunable; 4 is a good default.
const sparseCutoff = 4

// selfLoopMinClasses is the minimum number of self-loop class transitions
// required for a state to receive an inner self-loop mini-loop optimisation.
// States below this threshold have few enough self-loop bytes that the outer
// dispatch overhead does not justify the per-iteration state check cost.
const selfLoopMinClasses = 3

// maxSelfLoopStates caps the number of self-loop inner loops emitted to bound
// code size and the per-outer-iteration overhead of the state-identity checks.
const maxSelfLoopStates = 4

// DeadBranchMode controls how emitCompiledTransition handles the dead state.
type DeadBranchMode int

const (
	// DeadReturn emits "i32.const -1; return" — used in the anchored match path.
	DeadReturn DeadBranchMode = iota
	// DeadBranchOut emits "br <depth_to_found>" — used in find mode paths.
	DeadBranchOut
)

// stateDispatchInfo holds the pre-computed transition summary for one DFA state.
type stateDispatchInfo struct {
	liveClasses     []int    // class indices that have a live transition
	nextState       []uint32 // nextState[j] = WASM next state for liveClasses[j] (1-based)
	selfLoopClasses []int    // subset of liveClasses where nextState[j] == this state
}

// buildStateDispatch pre-computes dispatch info for every live DFA state.
func buildStateDispatch(t *dfaTable, l *dfaLayout) []stateDispatchInfo {
	N := l.numWASM - 1
	K := l.numClasses
	info := make([]stateDispatchInfo, N)
	for i := 0; i < N; i++ {
		gs := i
		var liveC []int
		ns := make([]uint32, K)
		for c, rep := range l.classRep {
			next := t.transitions[gs*256+rep]
			if next >= 0 {
				ns[c] = uint32(next + 1) // WASM 1-based
				liveC = append(liveC, c)
			}
		}
		var liveNS []uint32
		for _, c := range liveC {
			liveNS = append(liveNS, ns[c])
		}
		wasmSt := uint32(i + 1)
		var selfLoop []int
		for j, c := range liveC {
			if liveNS[j] == wasmSt {
				selfLoop = append(selfLoop, c)
			}
		}
		info[i] = stateDispatchInfo{
			liveClasses:     liveC,
			nextState:       liveNS,
			selfLoopClasses: selfLoop,
		}
	}
	return info
}

// emitCompiledTransition emits the per-byte DFA transition step for the compiled path.
//
// Preconditions:
//   - localCl holds the byte class index from classMap[mem[ptr+pos]] (i32, always set)
//   - localSt holds the current WASM DFA state (1..N; 0 = dead) (i32)
//
// Postconditions:
//   - localSt holds the next WASM state (1..N)
//   - On dead transition: either returned -1 (DeadReturn) or branched (DeadBranchOut)
//
// depthOffset: number of outer block/loop constructs surrounding this call site
// (added to all br depths so the same emitter works in match and find contexts).
//
// deadDepth: used only when deadMode == DeadBranchOut. br depth on dead transition
// measured from *outside* the per-state block emitted here.
//
// Structure emitted (full-dispatch path inside outer state br_table):
//
//	block $dispatch_done (void)
//	  block $state_{N-1} ... block $state_0
//	    local.get $state; i32.const 1; i32.sub
//	    br_table 0 1 … N-1 N-1
//	  end $state_i
//	    [per-state emit: dead / single / sparse / full inner br_table]
//	    ...
//	end $dispatch_done
func emitCompiledTransition(
	b []byte,
	t *dfaTable,
	l *dfaLayout,
	localSt, localCl uint32,
	depthOffset int,
	deadMode DeadBranchMode,
	deadDepth int,
) []byte {
	N := l.numWASM - 1 // number of live states
	K := l.numClasses

	disp := buildStateDispatch(t, l)

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
	emitDead := func(b []byte) []byte {
		switch deadMode {
		case DeadReturn:
			b = append(b, 0x41, 0x7F) // i32.const -1
			b = append(b, 0x0F)       // return
		case DeadBranchOut:
			b = append(b, 0x0C)
			b = utils.AppendULEB128(b, uint32(deadDepth))
		}
		return b
	}

	// emitStateBody emits the transition body for one state.
	// When called from the full-dispatch path, outerBlocks is the number of
	// state-handler blocks still open above this state (N-1-i).
	// For the $dispatch_done branch we also need to jump over those + depthOffset.
	emitStateBody := func(b []byte, i int, outerStateBlocks int) []byte {
		d := disp[i]
		live := len(d.liveClasses)

		switch {
		case live == 0:
			// Dead state: all transitions dead.
			b = emitDead(b)

		case live == 1:
			// Single live transition: compare class index, no inner br_table needed.
			// if class == c0 { state = ns; br $dispatch_done } else { dead }
			b = lget(b, localCl)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(d.liveClasses[0]))
			b = append(b, 0x46)       // i32.eq
			b = append(b, 0x04, 0x40) // if (void)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(d.nextState[0]))
			b = lset(b, localSt)
			// br depth to $dispatch_done from inside the if body:
			// label 0=if, 1..outerStateBlocks=state blocks, outerStateBlocks+1=$dispatch_done
			depth := outerStateBlocks + depthOffset + 1
			b = append(b, 0x0C)
			b = utils.AppendULEB128(b, uint32(depth))
			b = append(b, 0x0B) // end if
			b = emitDead(b)

		case live <= sparseCutoff:
			// Sparse: chain of if/else comparisons against class index.
			// if class==c0 { state=ns0 } else if class==c1 ... else { dead }
			// Depth to $dispatch_done from inside the body of the j-th if block:
			//   label 0   = current if_j block
			//   label 1..j = j enclosing if blocks (entered through else)
			//   label j+1..j+outerStateBlocks = remaining open state blocks
			//   label j+1+outerStateBlocks = $dispatch_done
			// Plus depthOffset for surrounding caller blocks.
			for j, c := range d.liveClasses {
				b = lget(b, localCl)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(c))
				b = append(b, 0x46)       // i32.eq
				b = append(b, 0x04, 0x40) // if (void)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(d.nextState[j]))
				b = lset(b, localSt)
				depth := j + 1 + outerStateBlocks + depthOffset
				b = append(b, 0x0C)
				b = utils.AppendULEB128(b, uint32(depth))
				b = append(b, 0x05) // else
			}
			b = emitDead(b)
			for j := 0; j < live; j++ {
				b = append(b, 0x0B) // end if (one per if block)
			}

		default:
			// Full dispatch: inner br_table over class index.
			// Requires localCl pre-loaded with classMap[byte].
			nextState := make([]uint32, K)
			for j, c := range d.liveClasses {
				nextState[c] = d.nextState[j]
			}

			// Emit K nested blocks for classes K-1 down to 0.
			for j := 0; j < K; j++ {
				b = append(b, 0x02, 0x40)
			}

			// Inner br_table: class → block index
			b = lget(b, localCl)
			b = append(b, 0x0E)
			b = utils.AppendULEB128(b, uint32(K))
			for j := 0; j < K; j++ {
				b = utils.AppendULEB128(b, uint32(j))
			}
			b = utils.AppendULEB128(b, uint32(K-1))

			// Per-class handlers.
			for j := 0; j < K; j++ {
				b = append(b, 0x0B) // end $class_j

				ns := nextState[j]
				if ns == 0 {
					b = emitDead(b)
					continue
				}
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(ns))
				b = lset(b, localSt)
				// Depth to $dispatch_done from inside class block j of state i:
				//   (K-1-j) class blocks above + outerStateBlocks state blocks + $dispatch_done
				// Then add depthOffset for surrounding blocks in the call site.
				depth := (K - 1 - j) + outerStateBlocks + depthOffset
				b = append(b, 0x0C)
				b = utils.AppendULEB128(b, uint32(depth))
			}
		}
		return b
	}

	if N == 1 {
		// Single live state: no outer br_table needed, just emit the body directly.
		// Wrap in $dispatch_done so br depths work uniformly.
		b = append(b, 0x02, 0x40) // block $dispatch_done
		b = emitStateBody(b, 0, 0)
		b = append(b, 0x0B) // end $dispatch_done
		return b
	}

	// Open block $dispatch_done (void).
	b = append(b, 0x02, 0x40)

	// Emit N nested blocks for states N-1 down to 0.
	for i := 0; i < N; i++ {
		b = append(b, 0x02, 0x40)
	}

	// Outer br_table: (state-1) → handler index. O(1) indirect jump.
	b = lget(b, localSt)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x0E)       // br_table
	b = utils.AppendULEB128(b, uint32(N))
	for i := 0; i < N; i++ {
		b = utils.AppendULEB128(b, uint32(i))
	}
	b = utils.AppendULEB128(b, uint32(N-1)) // default

	// Per-state handlers.
	for i := 0; i < N; i++ {
		b = append(b, 0x0B) // end $state_i
		// outerStateBlocks: state blocks still open above this handler.
		// After end $state_i, blocks $state_{i+1}...$state_{N-1} are still open = N-1-i.
		outerStateBlocks := N - 1 - i
		b = emitStateBody(b, i, outerStateBlocks)
	}

	// Close block $dispatch_done.
	b = append(b, 0x0B)

	return b
}

// emitSelfLoopBlock emits an inner self-loop mini-loop for DFA state i (WASM state i+1).
// Must be called after emitCompiledTransition + immAcceptCheck + pos++ in the outer loop,
// with no other blocks open between the call site and the enclosing loop $main / block $done.
//
// Logic: if state == wasmState, spin in a tight inner loop consuming self-loop bytes until
// an exit byte is found or input is exhausted, then fall through to br $main so the outer
// dispatch handles the exit byte normally.
//
// WASM structure (depths counted from inside $do_selfloop):
//
//	block $after_sl                                 ; skip if state ≠ wasmState
//	  if state != wasmState: br $after_sl (br 0)
//	  loop $sl
//	    if pos >= len: br $after_sl (br 1)          ; let outer loop handle EOF
//	    class = classMap[mem[ptr+pos]]
//	    block $sl_is_selfloop                       ; (depth 1 from $do_selfloop)
//	      block $do_selfloop                        ; (depth 0)
//	        for each self-loop class c:
//	          if class == c: br 1                   ; → exit $do_selfloop, reach immAccept code
//	        br 3                                    ; no self-loop match → exit $after_sl
//	      end $do_selfloop
//	    end $sl_is_selfloop
//	    [if immediateAccept[i]: return pos]
//	    pos++
//	    br 0                                        ; continue $sl
//	  end $sl
//	end $after_sl
func emitSelfLoopBlock(
	b []byte,
	i int,
	d stateDispatchInfo,
	t *dfaTable,
	l *dfaLayout,
	hasImmAccept bool,
	localState, localClass, localPos uint32,
) []byte {
	wasmState := uint32(i + 1)

	// block $after_sl
	b = append(b, 0x02, 0x40)

	// if state != wasmState: br $after_sl (= br 0)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, localState)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(wasmState))
	b = append(b, 0x47)       // i32.ne
	b = append(b, 0x0D, 0x00) // br_if 0

	// loop $sl
	b = append(b, 0x03, 0x40)

	// if pos >= len: br $after_sl (= br 1 from inside $sl)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, localPos)
	b = append(b, 0x20, 0x01) // local.get len (param 1)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1

	// class = classMap[mem[ptr+pos]]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.classMapOff)
	b = append(b, 0x20, 0x00) // local.get ptr (param 0)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, localPos)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x6A)             // classMapOff + byte
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (class index)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, localClass)

	// block $sl_is_selfloop — br_if 1 from $do_selfloop lands after this block's end,
	// at the immAccept + pos++ + br 0 code below.
	b = append(b, 0x02, 0x40)
	// block $do_selfloop — fall-through triggers br 3 to $after_sl (exit byte found).
	b = append(b, 0x02, 0x40)

	// For each self-loop class: if class == c → br 1 (exits $do_selfloop, continues to
	// the $sl_is_selfloop exit, reaching immAccept code).
	// Depths here: 0=$do_selfloop, 1=$sl_is_selfloop, 2=$sl(loop), 3=$after_sl.
	for _, c := range d.selfLoopClasses {
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, localClass)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(c))
		b = append(b, 0x46)       // i32.eq
		b = append(b, 0x0D, 0x01) // br_if 1 → $sl_is_selfloop
	}

	// No self-loop class matched: exit the self-loop entirely.
	// br 3 → $after_sl; outer loop will re-dispatch on the exit byte.
	b = append(b, 0x0C, 0x03) // br 3

	b = append(b, 0x0B) // end $do_selfloop
	b = append(b, 0x0B) // end $sl_is_selfloop

	// A self-loop class matched.
	// Immediate-accept check: if this state is immediateAccept, return pos now
	// (before increment), mirroring the outer loop's emitImmAcceptCheck semantics.
	if hasImmAccept && t.immediateAcceptStates[i] {
		b = append(b, 0x20)
		b = utils.AppendULEB128(b, localPos)
		b = append(b, 0x0F) // return
	}

	// pos++
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, localPos)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, localPos)

	// br 0 — continue $sl loop
	b = append(b, 0x0C, 0x00)

	b = append(b, 0x0B) // end $sl
	b = append(b, 0x0B) // end $after_sl

	return b
}

// literalChain returns the sequence of (raw byte, nextWasmState) for a chain
// of single-transition, single-byte-class states starting from wasmState ws.
// A chain step is valid only when:
//   - exactly one live class for that state
//   - that class maps to exactly one raw byte (classByteCount[c] == 1)
//   - the current state is not an accept or immediateAccept state
//   - the next state has not been visited already (no cycles)
//
// The chain ends as soon as any condition fails. Returns nil if no chain exists.
func literalChain(t *dfaTable, l *dfaLayout, disp []stateDispatchInfo, hasImmAccept bool, startWS uint32) []struct {
	rawByte byte
	nextWS  uint32
} {
	// classByteCount[c] = number of raw bytes mapping to class c.
	classByteCount := make([]int, l.numClasses)
	for _, c := range l.classMap {
		classByteCount[c]++
	}

	visited := make(map[uint32]bool)
	var chain []struct {
		rawByte byte
		nextWS  uint32
	}
	ws := startWS
	for {
		if visited[ws] {
			break // cycle detected
		}
		visited[ws] = true
		gs := int(ws) - 1 // WASM state to DFA state
		// Stop if accept or immediateAccept — we can't skip the accept check.
		if t.acceptStates[gs] {
			break
		}
		if hasImmAccept && t.immediateAcceptStates[gs] {
			break
		}
		d := disp[gs]
		if len(d.liveClasses) != 1 {
			break
		}
		c := d.liveClasses[0]
		if classByteCount[c] != 1 {
			break
		}
		// Find the unique byte for this class.
		var raw byte
		for bi, cls := range l.classMap {
			if int(cls) == c {
				raw = byte(bi)
				break
			}
		}
		nextWS := d.nextState[0]
		chain = append(chain, struct {
			rawByte byte
			nextWS  uint32
		}{raw, nextWS})
		ws = nextWS
		if ws == 0 { // dead next state
			break
		}
	}
	return chain
}

// buildCompiledMatchBody returns the WASM function body bytes for the compiled
// DFA anchored-match path (useCompiledDispatch = true).
//
// Locals layout:
//
//	0 = ptr   (i32 param)
//	1 = len   (i32 param)
//	2 = state (i32)
//	3 = pos   (i32)
//	4 = class (i32) — classMap[mem[ptr+pos]], loaded once per byte for all strategies
//
// Optimizations applied:
//  1. Outer if/else chain replaces N nested blocks + br_table for state dispatch.
//  2. Linear-chain literal folding: a run of single-byte-class single-transition
//     states starting from startState is unrolled as straight-line byte comparisons
//     before the main loop, eliminating loop overhead for literal prefixes.
//
// Loop structure:
//
//	[literal chain pre-check if chain len >= 2]
//	block $done (void)
//	  loop $main (void)
//	    if pos >= len: br_if $done
//	    class = classMap[mem[ptr+pos]]
//	    emitCompiledTransition(depthOffset=0)
//	    [emitImmAcceptCheck]
//	    pos++
//	    br $main
//	  end $main
//	end $done
//	accept[state] != 0 ? pos : -1
func buildCompiledMatchBody(
	t *dfaTable,
	l *dfaLayout,
	hasImmAccept bool,
) []byte {
	var b []byte

	// locals: state (i32), pos (i32), class (i32)
	b = append(b, 0x01, 0x03, 0x7F)
	// locals: 0=ptr 1=len 2=state 3=pos 4=class
	const localState = uint32(2)
	const localPos = uint32(3)
	const localClass = uint32(4)

	disp := buildStateDispatch(t, l)

	// Select self-loop-eligible states (most self-loop classes first, capped at max).
	type slState struct{ idx, count int }
	var slStates []slState
	for i, d := range disp {
		if len(d.selfLoopClasses) >= selfLoopMinClasses {
			slStates = append(slStates, slState{i, len(d.selfLoopClasses)})
		}
	}
	sort.Slice(slStates, func(x, y int) bool { return slStates[x].count > slStates[y].count })
	if len(slStates) > maxSelfLoopStates {
		slStates = slStates[:maxSelfLoopStates]
	}

	// Detect literal chain from start state.
	chain := literalChain(t, l, disp, hasImmAccept, l.wasmStart)

	// Emit literal chain prefix (straight-line byte comparisons, no loop).
	// Only worthwhile for chains of length >= 2; length 1 is fast enough in the loop.
	if len(chain) >= 2 {
		// Bounds check: need at least len(chain) bytes.
		b = append(b, 0x20, byte(localPos)) // local.get pos (== 0 at entry)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(len(chain)))
		b = append(b, 0x6A)       // i32.add  (pos + chainLen)
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4B)       // i32.gt_u (pos+chainLen > len)
		b = append(b, 0x04, 0x40) // if (void) → not enough bytes
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if

		for _, step := range chain {
			// if mem[ptr+pos] != rawByte: return -1
			b = append(b, 0x20, 0x00)           // local.get ptr
			b = append(b, 0x20, byte(localPos)) // local.get pos
			b = append(b, 0x6A)                 // i32.add
			b = append(b, 0x2D, 0x00, 0x00)     // i32.load8_u
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(step.rawByte))
			b = append(b, 0x47)       // i32.ne
			b = append(b, 0x04, 0x40) // if (void)
			b = append(b, 0x41, 0x7F) // i32.const -1
			b = append(b, 0x0F)       // return
			b = append(b, 0x0B)       // end if
			// pos++
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, byte(localPos))
		}
		// Set state to the state after the chain.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(chain[len(chain)-1].nextWS))
		b = append(b, 0x21, byte(localState))
	} else {
		// No chain (or length 1): initialize state normally in the loop.
		// state = startState
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.wasmStart))
		b = append(b, 0x21, byte(localState))
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br_if $done
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1 → $done

	// class = classMap[mem[ptr+pos]]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.classMapOff)
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (input byte)
	b = append(b, 0x6A)             // classMapOff + byte
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u (class)
	b = append(b, 0x21, byte(localClass))

	// Compiled transition. depthOffset=0: $dispatch_done is the nearest outer block.
	b = emitCompiledTransition(b, t, l, localState, localClass, 0, DeadReturn, 0)

	// Immediate-accept check (leftmost-first): if immediateAccept[state]: return pos
	if hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x04, 0x40)       // if (void)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x0F) // return
		b = append(b, 0x0B) // end if
	}

	// pos++
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, byte(localPos))

	// Self-loop mini-loops for eligible states.
	// Each block exits cleanly to here (br $after_sl → fall-through to br $main).
	for _, sl := range slStates {
		b = emitSelfLoopBlock(b, sl.idx, disp[sl.idx], t, l, hasImmAccept, localState, localClass, localPos)
	}

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop $main
	b = append(b, 0x0B)       // end block $done

	// accept[state] != 0 ? pos : -1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
	b = append(b, 0x04, 0x7F)       // if (result i32)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x05)       // else
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0B)       // end if

	b = append(b, 0x0B) // end function
	return b
}

// buildHybridMatchBody returns the WASM function body for the hybrid DFA path:
// pure table-driven state transitions (no br_table dispatch, no self-loop blocks)
// combined with a literal-chain prefix optimisation when applicable.
//
// When l.useCompression is true the inner loop uses the compressed table:
//
//	class = classMap[mem[ptr+pos]];  state = table[state*numClasses + class]
//
// When l.useCompression is false the inner loop uses the uncompressed table:
//
//	state = table[(state<<8) + mem[ptr+pos]]   (multiply replaced by bit-shift)
//
// This eliminates both the br_table overhead of the pure compiled path and the
// forced-multiply overhead of the compressed-only previous hybrid implementation.
func buildHybridMatchBody(t *dfaTable, l *dfaLayout, hasImmAccept bool) []byte {
	var b []byte

	// Class info must have been pre-computed in buildDFALayout for literalChain.
	disp := buildStateDispatch(t, l)
	chain := literalChain(t, l, disp, hasImmAccept, l.wasmStart)

	const localState = uint32(2)
	const localPos = uint32(3)
	const localClass = uint32(4)

	if l.useCompression {
		b = append(b, 0x01, 0x03, 0x7F) // 3 locals: state, pos, class
	} else {
		b = append(b, 0x01, 0x02, 0x7F) // 2 locals: state, pos
	}

	// Literal chain prefix.
	if len(chain) >= 2 {
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(len(chain)))
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F) // return -1
		b = append(b, 0x0B)
		for _, step := range chain {
			b = append(b, 0x20, 0x00)
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x6A)
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(step.rawByte))
			b = append(b, 0x47) // i32.ne
			b = append(b, 0x04, 0x40)
			b = append(b, 0x41, 0x7F)
			b = append(b, 0x0F) // return -1
			b = append(b, 0x0B)
			b = append(b, 0x20, byte(localPos))
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, byte(localPos))
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(chain[len(chain)-1].nextWS))
		b = append(b, 0x21, byte(localState))
	} else {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.wasmStart))
		b = append(b, 0x21, byte(localState))
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $main

	// if pos >= len: br_if $done
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01)
	b = append(b, 0x4F)
	b = append(b, 0x0D, 0x01) // br_if 1

	if l.useCompression {
		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.classMapOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, byte(localClass))

		// state = table[tableOff + state*numClasses + class]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(l.numClasses))
		b = append(b, 0x6C) // i32.mul
		b = append(b, 0x6A)
		b = append(b, 0x20, byte(localClass))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x21, byte(localState))
	} else {
		// state = table[tableOff + (state<<8) + mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.tableOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x41, 0x08) // i32.const 8
		b = append(b, 0x74)       // i32.shl
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // mem[ptr+pos]
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u → new state
		b = append(b, 0x21, byte(localState))
	}

	// if state == 0: return -1
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x45)
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Immediate-accept check.
	if hasImmAccept {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, l.immediateAcceptOff)
		b = append(b, 0x20, byte(localState))
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, byte(localPos))
		b = append(b, 0x0F)
		b = append(b, 0x0B)
	}

	// pos++
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)
	b = append(b, 0x21, byte(localPos))

	b = append(b, 0x0C, 0x00) // br $main
	b = append(b, 0x0B)       // end loop $main
	b = append(b, 0x0B)       // end block $done

	// accept[state] != 0 ? pos : -1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.acceptOff)
	b = append(b, 0x20, byte(localState))
	b = append(b, 0x6A)
	b = append(b, 0x2D, 0x00, 0x00)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x05)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x0B)

	b = append(b, 0x0B) // end function
	return b
}

// buildHybridAnchoredFindBody returns the WASM function body for the hybrid find path
// when the pattern is anchored (starts with ^). It is a thin wrapper that delegates to
// buildAnchoredFindBody with parameters taken from the pre-computed dfaLayout.
//
// Row deduplication is guaranteed to be disabled for the hybrid path (enforced in
// buildDFALayout), so rowMapOff/useRowDedup are always the zero values.
func buildHybridAnchoredFindBody(t *dfaTable, l *dfaLayout) []byte {
	return buildAnchoredFindBody(
		l.wasmStart, l.tableOff, l.acceptOff, l.midAcceptOff,
		l.classMapOff, l.numClasses, l.useU8, l.useCompression,
		l.startBeginAccept, l.immediateAcceptOff, l.hasImmAccept,
		l.wordCharTableOff, l.needWordCharTable, l.midAcceptNWOff, l.midAcceptWOff,
		l.rowMapOff, l.useRowDedup, l.midAcceptNLOff, t.hasNewlineBoundary,
	)
}

// buildHybridFindBody returns the WASM function body for the hybrid find path when the
// pattern is non-anchored. It is a thin wrapper that delegates to buildFindBody with
// parameters taken from the pre-computed dfaLayout.
//
// The SIMD prefix scan (EmitPrefixScan) is already table/SIMD-only with no br_table
// dispatch, so no restructuring is required for the find hot path.
// Row deduplication is guaranteed disabled for the hybrid path.
func buildHybridFindBody(t *dfaTable, l *dfaLayout, mandatoryLit *MandatoryLit) []byte {
	return buildFindBody(
		l.wasmStart, l.wasmMidStart, l.wasmMidStartWord,
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
		mandatoryLit, l.rowMapOff, l.useRowDedup, l.midAcceptNLOff,
	)
}
