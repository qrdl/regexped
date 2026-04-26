package compile

import (
	"encoding/binary"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Aho-Corasick automaton
//
// Used as the literal-scan frontend when there are more than 8 literals in a
// set (or when any literal is longer than 4 bytes, making Teddy ineligible).

// acNode is one node in the Aho-Corasick goto graph.
type acNode struct {
	gotoTable [256]int // gotoTable[b] = next node ID; -1 = no explicit edge
	failure   int      // failure-link node ID
	output    []int    // list of literal IDs that match at this node
}

// acAutomaton is the compiled Aho-Corasick automaton.
type acAutomaton struct {
	nodes []acNode
}

// buildAC constructs an Aho-Corasick automaton for the given set of literals.
// literals[i] is the byte string for literal ID i.
func buildAC(literals [][]byte) *acAutomaton {
	ac := &acAutomaton{}
	// Node 0 is the root.
	ac.nodes = append(ac.nodes, newACNode())

	// Phase 1: build goto graph (trie).
	for litID, lit := range literals {
		cur := 0
		for _, b := range lit {
			next := ac.nodes[cur].gotoTable[b]
			if next < 0 {
				// Create a new node.
				next = len(ac.nodes)
				ac.nodes = append(ac.nodes, newACNode())
				ac.nodes[cur].gotoTable[b] = next
			}
			cur = next
		}
		ac.nodes[cur].output = append(ac.nodes[cur].output, litID)
	}

	// Root: missing edges loop back to root.
	root := &ac.nodes[0]
	for b := 0; b < 256; b++ {
		if root.gotoTable[b] < 0 {
			root.gotoTable[b] = 0
		}
	}

	// Phase 2: compute failure links (BFS).
	queue := make([]int, 0, len(ac.nodes))
	// Depth-1 nodes: failure = root.
	for b := 0; b < 256; b++ {
		child := ac.nodes[0].gotoTable[b]
		if child != 0 {
			ac.nodes[child].failure = 0
			queue = append(queue, child)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for b := 0; b < 256; b++ {
			t := ac.nodes[s].gotoTable[b]
			if t < 0 {
				// Follow failure link.
				ac.nodes[s].gotoTable[b] = ac.nodes[ac.nodes[s].failure].gotoTable[b]
				continue
			}
			queue = append(queue, t)
			// Failure for t = goto(failure(s), b).
			f := ac.nodes[s].failure
			ac.nodes[t].failure = ac.nodes[f].gotoTable[b]
			// Propagate output.
			failOut := ac.nodes[ac.nodes[t].failure].output
			if len(failOut) > 0 {
				ac.nodes[t].output = append(ac.nodes[t].output, failOut...)
			}
		}
	}
	return ac
}

func newACNode() acNode {
	n := acNode{failure: 0}
	for i := range n.gotoTable {
		n.gotoTable[i] = -1
	}
	return n
}

// --------------------------------------------------------------------------
// AC data layout for WASM

// acLayout describes the memory layout of the AC tables.
type acLayout struct {
	gotoOff    int32 // offset of goto table: [numNodes][256]int16 (little-endian)
	failureOff int32 // offset of failure table: [numNodes]int16
	outputOff  int32 // offset of output table: [numOutputPairs*2]int16 (litID, nodeStart/count)
	nodeOutOff int32 // offset of per-node output start indices: [numNodes]int16

	gotoBytes    []byte
	failureBytes []byte
	outputBytes  []byte // flat (nodeID, litID) pairs preceded by per-node offsets

	numNodes int
	tableEnd int32
}

// buildACLayout computes the WASM data layout for an acAutomaton.
func buildACLayout(ac *acAutomaton, tableBase int32) *acLayout {
	n := len(ac.nodes)
	l := &acLayout{numNodes: n}

	// Goto table: [n][256]int16 = n*512 bytes.
	l.gotoOff = tableBase
	l.gotoBytes = make([]byte, n*512)
	for i, node := range ac.nodes {
		for b, next := range node.gotoTable {
			binary.LittleEndian.PutUint16(l.gotoBytes[(i*256+b)*2:], uint16(next))
		}
	}

	// Failure table: [n]int16 = n*2 bytes.
	l.failureOff = l.gotoOff + int32(len(l.gotoBytes))
	l.failureBytes = make([]byte, n*2)
	for i, node := range ac.nodes {
		binary.LittleEndian.PutUint16(l.failureBytes[i*2:], uint16(node.failure))
	}

	// Per-node output start offsets: [n+1]int16 (last entry = total output count).
	l.nodeOutOff = l.failureOff + int32(len(l.failureBytes))
	startOffsets := make([]int, n+1)
	total := 0
	for i, node := range ac.nodes {
		startOffsets[i] = total
		total += len(node.output)
	}
	startOffsets[n] = total

	nodeOutBytes := make([]byte, (n+1)*2)
	for i, off := range startOffsets {
		binary.LittleEndian.PutUint16(nodeOutBytes[i*2:], uint16(off))
	}

	// Output array: flat list of litID values in node order.
	l.outputOff = l.nodeOutOff + int32(len(nodeOutBytes))
	outputBytes := make([]byte, total*2)
	for i, node := range ac.nodes {
		for j, litID := range node.output {
			idx := startOffsets[i] + j
			binary.LittleEndian.PutUint16(outputBytes[idx*2:], uint16(litID))
		}
	}

	// Combine nodeOut + output into one contiguous block for simplicity.
	l.outputBytes = append(nodeOutBytes, outputBytes...)
	l.tableEnd = l.outputOff + int32(len(l.outputBytes))
	return l
}

// --------------------------------------------------------------------------
// AC WASM emission

// emitACDataSegments emits WASM data segments for the AC tables.
func emitACDataSegments(l *acLayout) []byte {
	var ds []byte
	ds = appendDataSegment(ds, l.gotoOff, l.gotoBytes)
	ds = appendDataSegment(ds, l.failureOff, l.failureBytes)
	ds = appendDataSegment(ds, l.nodeOutOff, l.outputBytes)
	return ds
}

// acScanLocals holds the WASM local indices used by emitACScan.
// The indices are absolute within the enclosing function; the caller must
// declare them (emitACScan does not emit a locals-declaration header).
type acScanLocals struct {
	State   byte // i32: current AC state
	Pos     byte // i32: current scan position
	ByteTmp byte // i32: current input byte (scratch for goto-table address)
	LitID   byte // i32: matched literal ID from output array
	OutIdx  byte // i32: current index into flat output array
	OutEnd  byte // i32: end index for current node's output entries
}

// emitACScan emits WASM for an Aho-Corasick byte-at-a-time scan loop.
// When a literal match is found, onHit is called with locals already set:
// locals.LitID holds the matched literal ID, locals.Pos holds the current
// position (1 past the last byte of the match).
//
// The caller is responsible for declaring locals.State/Pos/ByteTmp/LitID/
// OutIdx/OutEnd as i32 locals in the enclosing function. This function does
// NOT emit a locals-declaration header — it emits only executable instructions.
//
// On return, b is extended with the scan instructions.
func emitACScan(
	b []byte,
	l *acLayout,
	locals acScanLocals,
	ptrLocal, lenLocal byte,
	inputMemIdx, tableMemIdx int,
	onHit func(b []byte) []byte,
) []byte {
	// state = 0
	b = append(b, 0x41, 0x00, 0x21, locals.State)
	// pos = 0
	b = append(b, 0x41, 0x00, 0x21, locals.Pos)

	// block $exit
	b = append(b, 0x02, 0x40)
	// loop $outer
	b = append(b, 0x03, 0x40)

	// if pos >= len: br $exit
	b = append(b, 0x20, locals.Pos, 0x20, lenLocal, 0x4D, 0x0D, 0x01)

	// byte_tmp = mem[ptr + pos]
	b = append(b, 0x20, ptrLocal, 0x20, locals.Pos, 0x6A)
	b = appendACInputLoad8u(b)
	b = append(b, 0x21, locals.ByteTmp)

	// state = goto[state][byte_tmp]
	// addr = gotoOff + state*512 + byte_tmp*2  (state*512 = state<<9, byte*2 = byte<<1)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.gotoOff)
	b = append(b, 0x20, locals.State, 0x41, 0x09, 0x74)   // state << 9
	b = append(b, 0x6A)                                   // + gotoOff
	b = append(b, 0x20, locals.ByteTmp, 0x41, 0x01, 0x74) // byte << 1
	b = append(b, 0x6A)                                   // + byte*2
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, locals.State)

	// outIdx = nodeOut[state];  outEnd = nodeOut[state+1]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.nodeOutOff)
	b = append(b, 0x20, locals.State, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, locals.OutIdx)

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.nodeOutOff)
	b = append(b, 0x20, locals.State, 0x41, 0x01, 0x6A, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, locals.OutEnd)

	// if outIdx < outEnd: iterate output entries
	b = append(b, 0x20, locals.OutIdx, 0x20, locals.OutEnd, 0x4B, 0x04, 0x40)

	// loop $output
	b = append(b, 0x03, 0x40)

	// litID = output[outIdx]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, l.outputOff)
	b = append(b, 0x20, locals.OutIdx, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, locals.LitID)

	b = onHit(b)

	// outIdx++; if outIdx < outEnd: br $output
	b = append(b, 0x20, locals.OutIdx, 0x41, 0x01, 0x6A, 0x21, locals.OutIdx)
	b = append(b, 0x20, locals.OutIdx, 0x20, locals.OutEnd, 0x4B, 0x0D, 0x00)

	b = append(b, 0x0B) // end loop $output
	b = append(b, 0x0B) // end if

	// pos++; br $outer
	b = append(b, 0x20, locals.Pos, 0x41, 0x01, 0x6A, 0x21, locals.Pos)
	b = append(b, 0x0C, 0x00) // br $outer

	b = append(b, 0x0B) // end loop $outer
	b = append(b, 0x0B) // end block $exit
	return b
}

// appendACInputLoad8u emits i32.load8_u for an input byte (always memory[0]).
func appendACInputLoad8u(b []byte) []byte {
	return append(b, 0x2D, 0x00, 0x00) // i32.load8_u align=0 offset=0
}
