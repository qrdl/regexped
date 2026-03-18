package compile

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/qrdl/regexped/utils"
)

// --------------------------------------------------------------------------
// Byte class compression

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
	sig := make([]byte, t.numStates) // transition signature for one byte value

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
// DFA binary decode

// dfaTable holds the DFA state transition table decoded from regexped's
// Marshal binary format.
type dfaTable struct {
	startState   int
	numStates    int
	acceptStates map[int]bool
	transitions  []int // flat [state*256+byte] = nextState; -1 = dead
}

// dfaTableFrom builds a dfaTable directly from a compiled dfa struct.
func dfaTableFrom(d *dfa) *dfaTable {
	return &dfaTable{
		startState:   d.start,
		numStates:    d.numStates,
		acceptStates: d.accepting,
		transitions:  d.transitions,
	}
}

// --------------------------------------------------------------------------
// WASM binary generation

// genWASM emits a WASM 1.0 module with a single exported function:
//
//	(func (export "<exportName>") (param ptr i32) (param len i32) (result i32))
//
// Returns the end position (0..len) on a match, -1 on no match.
// The match is anchored at ptr and checks the full input [ptr, ptr+len).
//
// Memory layout in the imported linear memory:
//
//	[tableBase .. tableBase + numWASMStates*256*2)  – u16 transition table
//	[acceptBase .. acceptBase + numWASMStates)       – u8 accept flags
//
// The module imports memory as (import "main" "memory" (memory 0)) so that
// wasm-merge can resolve it against the host module's exported memory.
func genWASM(t *dfaTable, tableBase int64, exportName string) []byte {
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
		fmt.Fprintf(os.Stderr, "    Byte classes: %d (compressed)\n", numClasses)
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
		// Dead state row (row 0) stays all-zeros.
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
		// Dead state row (row 0) stays all-zeros.
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
		// Dead state row (row 0) stays all-zeros.
	}

	// Accept flags: acceptFlags[wasmState] = 1 if accepting.
	acceptOff := tableOff + int32(len(tableBytes))
	acceptBytes := make([]byte, numWASM)
	for gs := range t.acceptStates {
		acceptBytes[gs+1] = 1
	}

	var out []byte

	// ── Magic + version ──────────────────────────────────────────────────────
	out = append(out, 0x00, 0x61, 0x73, 0x6D) // \0asm
	out = append(out, 0x01, 0x00, 0x00, 0x00) // version 1

	// ── Type section (id=1): one func type (i32,i32)->i32 ───────────────────
	ts := []byte{
		0x01,             // 1 type
		0x60,             // functype
		0x02, 0x7F, 0x7F, // 2 params: i32, i32
		0x01, 0x7F, // 1 result: i32
	}
	out = appendSection(out, 1, ts)

	// ── Import section (id=2): (import "main" "memory" (memory 0)) ───────────
	var is []byte
	is = append(is, 0x01) // 1 import
	is = appendString(is, "main")
	is = appendString(is, "memory")
	is = append(is, 0x02)        // memory
	is = append(is, 0x00)        // limit type: min only (no max)
	is = utils.AppendULEB128(is, 0x00) // min 0 pages
	out = appendSection(out, 2, is)

	// ── Function section (id=3): 1 function using type 0 ────────────────────
	out = appendSection(out, 3, []byte{0x01, 0x00})

	// ── Export section (id=7): export function as func 0 ────────────────────
	var es []byte
	es = append(es, 0x01) // 1 export
	es = appendString(es, exportName)
	es = append(es, 0x00) // func
	es = utils.AppendULEB128(es, 0x00)
	out = appendSection(out, 7, es)

	// ── Code section (id=10): function body ─────────────────────────────────
	body := buildMatchBody(wasmStart, tableOff, acceptOff, classMapOff, numClasses, useU8, useCompression)
	var cs []byte
	cs = append(cs, 0x01) // 1 function
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	cs = append(cs, body...)
	out = appendSection(out, 10, cs)

	// ── Data section (id=11) ──────────────────────────────────────────────────
	var ds []byte
	if useCompression {
		ds = append(ds, 0x03) // 3 segments: classMap + table + accept flags
		ds = appendDataSegment(ds, classMapOff, classMap[:])
		ds = appendDataSegment(ds, tableOff, tableBytes)
		ds = appendDataSegment(ds, acceptOff, acceptBytes)
	} else {
		ds = append(ds, 0x02) // 2 segments: table + accept flags
		ds = appendDataSegment(ds, tableOff, tableBytes)
		ds = appendDataSegment(ds, acceptOff, acceptBytes)
	}

	out = appendSection(out, 11, ds)

	return out
}

// buildMatchBody returns the WASM function body bytes (locals + instructions + end).
//
// u8 compressed (useU8=true, useCompression=true) — #1 + #2 + #4:
//
//	for pos < len {
//	    class = classMap[mem[ptr+pos]]
//	    state = u8(mem[tableOff + state*numClasses + class])
//	    ...
//	}
//
// Local indices: 0=ptr 1=len 2=state 3=pos 4=class
//
// u8 simple (useU8=true, useCompression=false) — #2 + #4:
//
//	for pos < len {
//	    state = u8(mem[tableOff + state*256 + mem[ptr+pos]])
//	    ...
//	}
//
// Local indices: 0=ptr 1=len 2=state 3=pos
//
// u16 (useU8=false) — original:
//
//	for pos < len {
//	    b   = mem[ptr+pos]
//	    state = u16(mem[tableOff + state*512 + b*2])
//	    ...
//	}
//
// Local indices: 0=ptr 1=len 2=state 3=pos 4=byte
func buildMatchBody(startState uint32, tableOff, acceptOff, classMapOff int32, numClasses int, useU8, useCompression bool) []byte {
	var b []byte

	if useU8 && useCompression {
		// ── u8 compressed path (#1 + #2 + #4) ───────────────────────────────
		// 3 locals: state (local 2), pos (local 3), class (local 4)
		b = append(b, 0x01, 0x03, 0x7F)

		// state = startState
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02)

		// block $done / loop $main
		b = append(b, 0x02, 0x40)
		b = append(b, 0x03, 0x40)

		// if pos >= len: br_if $done
		b = append(b, 0x20, 0x03) // local.get 3 (pos)
		b = append(b, 0x20, 0x01) // local.get 1 (len)
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x0D, 0x01) // br_if 1

		// class = classMap[mem[ptr+pos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, classMapOff)
		b = append(b, 0x20, 0x00)       // local.get 0 (ptr)
		b = append(b, 0x20, 0x03)       // local.get 3 (pos)
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (input byte)
		b = append(b, 0x6A)             // i32.add  (classMapOff + byte)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (class)
		b = append(b, 0x21, 0x04)       // local.set 4 (class)

		// state = u8( mem[ tableOff + state*numClasses + class ] )
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02) // local.get 2 (state)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(numClasses))
		b = append(b, 0x6C)             // i32.mul
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x20, 0x04)       // local.get 4 (class)
		b = append(b, 0x6A)             // i32.add
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
		b = append(b, 0x21, 0x02)       // local.set 2 (state)

		// if state == 0: return -1
		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if

		// pos++
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00) // br $main
		b = append(b, 0x0B)       // end loop
		b = append(b, 0x0B)       // end block $done

		// Accept check
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

	if useU8 {
		// ── u8 simple path (#2 + #4) ─────────────────────────────────────────
		// 2 locals: state (local 2), pos (local 3)
		b = append(b, 0x01, 0x02, 0x7F)

		// state = startState
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(startState))
		b = append(b, 0x21, 0x02)

		// block $done / loop $main
		b = append(b, 0x02, 0x40)
		b = append(b, 0x03, 0x40)

		// if pos >= len: br_if $done
		b = append(b, 0x20, 0x03)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x4F)
		b = append(b, 0x0D, 0x01)

		// state = u8( mem[ tableOff + state*256 + mem[ptr+pos] ] )
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, tableOff)
		b = append(b, 0x20, 0x02)       // local.get 2 (state)
		b = append(b, 0x41, 0x08)       // i32.const 8
		b = append(b, 0x74)             // i32.shl  (state * 256)
		b = append(b, 0x6A)
		b = append(b, 0x20, 0x00)       // local.get 0 (ptr)
		b = append(b, 0x20, 0x03)       // local.get 3 (pos)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (input byte)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u  (table entry)
		b = append(b, 0x21, 0x02)

		// if state == 0: return -1
		b = append(b, 0x20, 0x02)
		b = append(b, 0x45)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)

		// pos++
		b = append(b, 0x20, 0x03)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, 0x03)

		b = append(b, 0x0C, 0x00)
		b = append(b, 0x0B) // end loop
		b = append(b, 0x0B) // end block $done

		// Accept check
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, acceptOff)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x6A)
		b = append(b, 0x2D, 0x00, 0x00)
		b = append(b, 0x04, 0x7F)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x05)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0B)
		b = append(b, 0x0B) // end function
		return b
	}

	// ── u16 path (original) ───────────────────────────────────────────────────

	// Local declarations: 3 locals of type i32
	b = append(b, 0x01) // 1 group
	b = append(b, 0x03) // count: 3
	b = append(b, 0x7F) // type: i32

	// state = startState
	b = append(b, 0x41) // i32.const
	b = utils.AppendSLEB128(b, int32(startState))
	b = append(b, 0x21, 0x02) // local.set 2 (state)

	// block $done (void)
	b = append(b, 0x02, 0x40)
	// loop $main (void)
	b = append(b, 0x03, 0x40)

	// br_if $done  if pos >= len
	b = append(b, 0x20, 0x03) // local.get 3 (pos)
	b = append(b, 0x20, 0x01) // local.get 1 (len)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x0D, 0x01) // br_if 1 (break out of $done block)

	// byte = mem[ptr + pos]
	b = append(b, 0x20, 0x00)       // local.get 0 (ptr)
	b = append(b, 0x20, 0x03)       // local.get 3 (pos)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u align=0 offset=0
	b = append(b, 0x21, 0x04)       // local.set 4 (byte)

	// state = u16( mem[ tableOff + state*512 + byte*2 ] )
	b = append(b, 0x41) // i32.const tableOff
	b = utils.AppendSLEB128(b, tableOff)
	b = append(b, 0x20, 0x02)       // local.get 2 (state)
	b = append(b, 0x41, 0x09)       // i32.const 9
	b = append(b, 0x74)             // i32.shl   (state << 9 = state * 512)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x20, 0x04)       // local.get 4 (byte)
	b = append(b, 0x41, 0x01)       // i32.const 1
	b = append(b, 0x74)             // i32.shl   (byte << 1 = byte * 2)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2F, 0x01, 0x00) // i32.load16_u align=1 offset=0
	b = append(b, 0x21, 0x02)       // local.set 2 (state)

	// if state == 0: return -1
	b = append(b, 0x20, 0x02) // local.get 2 (state)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if void
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// pos++
	b = append(b, 0x20, 0x03) // local.get 3 (pos)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x21, 0x03) // local.set 3 (pos)

	// br $main
	b = append(b, 0x0C, 0x00) // br 0
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	// accept check: mem[acceptOff + state] != 0 ? pos : -1
	b = append(b, 0x41) // i32.const acceptOff
	b = utils.AppendSLEB128(b, acceptOff)
	b = append(b, 0x20, 0x02)       // local.get 2 (state)
	b = append(b, 0x6A)             // i32.add
	b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u align=0 offset=0

	b = append(b, 0x04, 0x7F) // if (result i32)
	b = append(b, 0x20, 0x03) //   local.get 3 (pos)
	b = append(b, 0x05)       // else
	b = append(b, 0x41, 0x7F) //   i32.const -1
	b = append(b, 0x0B)       // end

	b = append(b, 0x0B) // end function
	return b
}

