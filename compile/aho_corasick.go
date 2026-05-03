package compile

import (
	"encoding/binary"
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
