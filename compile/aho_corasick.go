package compile

import (
	"encoding/binary"
)

// --------------------------------------------------------------------------
// Aho-Corasick automaton
//
// Used as the literal-scan frontend above Teddy's literal count, subject to a
// table-byte budget (CompileSetOptions.acBudgetBytes). Teddy handles 1–16
// literals (any length, probing first 4 bytes).

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

// acMaxNodes is the largest automaton buildACLayout can encode: node ids are
// written as u16 into the goto table, so ids 0..65535 are addressable.
//
// Uncompressed this is unreachable — acBudgetBytes runs out ~65x sooner (512
// KB / 512 B per node ≈ 1024 nodes). Byte-class compression changes that: a
// row can shrink to as little as 4 bytes, so the same budget would hold
// ~131,000 nodes, and a set of tens of thousands of long literals over a
// narrow alphabet could genuinely reach the id limit. It is therefore a
// demotion case, not an assertion.
const acMaxNodes = 65536

// acMaxOutputs is the largest total propagated-output count buildACLayout can
// encode: a node's output range is a pair of adjacent entries in the
// nodeOut array, written as u16, with entry numNodes carrying the total as the
// end sentinel. Index values 0..65535 are therefore addressable.
//
// Node count is not a proxy for this. buildAC copies every suffix literal's id
// into each node that ends with it, so a nested family (`a`, `aa`, `aaa`, ...)
// of L literals produces L*(L+1)/2 outputs from only L+1 nodes: ~362 such
// literals overflow the offsets while passing both acMaxNodes and
// acBudgetBytes with room to spare. Like acMaxNodes this is a demotion case,
// not an assertion — the alternative, widening the whole output layout to u32,
// would cost every AC set table bytes to serve a shape none of them has.
const acMaxOutputs = 65535

// acTotalOutputs counts the propagated outputs over every node — the length of
// the flat output array buildACLayoutMode lays down, and the value its last
// nodeOut entry has to hold.
func acTotalOutputs(ac *acAutomaton) int {
	total := 0
	for i := range ac.nodes {
		total += len(ac.nodes[i].output)
	}
	return total
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
	gotoOff    int32 // offset of goto table: [numNodes][stride]int16 (little-endian)
	nodeOutOff int32 // offset of per-node output start offsets: [numNodes+1]int16
	// (entry i = start index into the output array for node i;
	//  entry numNodes = total output count = end sentinel)
	outputOff int32 // offset of flat output array: [total]int16 of literal IDs,
	// indexed by [nodeOut[i] .. nodeOut[i+1]) for node i

	gotoBytes   []byte
	outputBytes []byte // concatenation of nodeOut offsets and flat litID array

	// Byte-class compression. When compressed, a goto
	// row is indexed by the byte's EQUIVALENCE CLASS rather than by the byte,
	// which shrinks the row from 512 bytes to stride*2 at the cost of one
	// extra table load per input byte to map byte→class.
	//
	// It is engaged only when the uncompressed automaton does not fit
	// acBudgetBytes: for a set that already fits, paying a load per byte to
	// save bytes would trade the project's first-priority metric for its
	// second. Compression is what lets a set that would otherwise lose its
	// literal frontend entirely (and run 86-414x slower) keep it.
	compressed  bool
	classMapOff int32 // offset of byte→class table [256]u8; valid iff compressed
	classMap    [256]byte
	numClasses  int
	stride      int // goto entries per node: numClasses rounded up to a power of 2, or 256
	strideShift int // log2(stride*2) — the shift that turns a node id into a row offset

	numNodes int
	// outLimit is the highest node id that carries OUTPUT. Nodes are
	// renumbered so that the root is 0 (it can never carry output — every
	// literal is non-empty) and every output-bearing node falls in
	// [1, outLimit]; the rest follow.
	//
	// That turns "does this node report anything" from two u16 table loads
	// per input byte into one unsigned compare against a constant —
	// `(state - 1) u< outLimit` — with the loads moved inside the branch. It
	// is the same MID-ACCEPT-FIRST trick the union automaton uses, applied to
	// the AC walk, where output is rare and the loads were paid every byte.
	//
	// 0 means NO node carries output, and the body then emits no output arm
	// at all.
	outLimit int
	tableEnd int32
}

// bytes reports the total memory the AC frontend reserves for this layout,
// including the 256-byte firstByteFlags table emitted immediately after it.
func (l *acLayout) bytes() int {
	return int(l.tableEnd-l.gotoOff) + 256
}

// computeACByteClasses groups bytes that are indistinguishable to the
// automaton: b1 and b2 share a class iff every node's goto edge for b1 equals
// its edge for b2. Keyword alphabets typically collapse 256 bytes into a few
// dozen classes, since most bytes lead every node straight back to the root.
//
// This is the same construction computeByteClasses (engine_dfa.go) performs
// for DFA tables, over the AC goto graph instead.
func computeACByteClasses(ac *acAutomaton) (classMap [256]byte, numClasses int) {
	n := len(ac.nodes)
	sigToClass := make(map[string]int, 64)
	sig := make([]byte, n*2)
	for b := 0; b < 256; b++ {
		for i := range ac.nodes {
			binary.LittleEndian.PutUint16(sig[i*2:], uint16(ac.nodes[i].gotoTable[b]))
		}
		key := string(sig) // copies; sig is reused across iterations
		id, ok := sigToClass[key]
		if !ok {
			id = len(sigToClass)
			sigToClass[key] = id
		}
		classMap[b] = byte(id)
	}
	return classMap, len(sigToClass)
}

// nextPow2 rounds n up to a power of two, so a goto row index is a shift
// rather than a multiply.
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// log2Exact returns k such that 1<<k == n. n must be a power of two.
func log2Exact(n int) int {
	k := 0
	for 1<<k < n {
		k++
	}
	return k
}

// buildACLayout computes the WASM data layout for an acAutomaton.
func buildACLayout(ac *acAutomaton, tableBase int32) *acLayout {
	return buildACLayoutMode(ac, tableBase, false)
}

// buildACLayoutMode builds the AC layout, optionally byte-class compressed.
// See acLayout.compressed for when compression is worth its per-byte cost.
func buildACLayoutMode(ac *acAutomaton, tableBase int32, compress bool) *acLayout {
	n := len(ac.nodes)
	// OUTPUT-BEARING NODES FIRST (after the root). See acLayout.outLimit.
	//
	// oldToNew[i] is node i's emitted id; newToOld is its inverse. The root
	// keeps id 0 both because the walk starts there (lACState is
	// zero-initialised) and because it is the one node guaranteed to have no
	// output.
	oldToNew := make([]int, n)
	newToOld := make([]int, n)
	next := 1
	if n > 0 {
		if len(ac.nodes[0].output) != 0 {
			panic("compile: the Aho-Corasick root carries output — an empty literal reached buildAC")
		}
		oldToNew[0], newToOld[0] = 0, 0
	}
	for i := 1; i < n; i++ {
		if len(ac.nodes[i].output) != 0 {
			oldToNew[i], newToOld[next] = next, i
			next++
		}
	}
	outLimit := next - 1
	for i := 1; i < n; i++ {
		if len(ac.nodes[i].output) == 0 {
			oldToNew[i], newToOld[next] = next, i
			next++
		}
	}
	l := &acLayout{numNodes: n, stride: 256, outLimit: outLimit}
	for b := 0; b < 256; b++ {
		l.classMap[b] = byte(b) // identity, unused unless compressed
	}
	l.numClasses = 256
	if compress {
		l.classMap, l.numClasses = computeACByteClasses(ac)
		if s := nextPow2(l.numClasses); s < 256 {
			l.stride = s
			l.compressed = true
		}
	}
	l.strideShift = log2Exact(l.stride * 2)

	// Goto table: [n][stride]int16. buildAC has already filled in failure
	// transitions on every missing edge, so the goto table is a fully
	// completed DFA — the WASM matcher needs no separate failure table.
	//
	// When compressed, a row is indexed by byte CLASS. Every byte of a class
	// has, by construction, the same target from every node, so writing the
	// row from any representative byte of the class is exact — this is a
	// re-indexing, not an approximation, and cannot change what matches.
	// Rows are written at the node's NEW id and their targets are remapped
	// through oldToNew — a pure renumbering, so nothing about what the
	// automaton accepts changes.
	l.gotoOff = tableBase
	l.gotoBytes = make([]byte, n*l.stride*2)
	for newID := 0; newID < n; newID++ {
		node := ac.nodes[newToOld[newID]]
		if l.compressed {
			for b := 0; b < 256; b++ {
				binary.LittleEndian.PutUint16(l.gotoBytes[(newID*l.stride+int(l.classMap[b]))*2:], uint16(oldToNew[node.gotoTable[b]]))
			}
		} else {
			for b, tgt := range node.gotoTable {
				binary.LittleEndian.PutUint16(l.gotoBytes[(newID*256+b)*2:], uint16(oldToNew[tgt]))
			}
		}
	}

	// Per-node output start offsets: [n+1]int16 (last entry = total output count).
	l.nodeOutOff = l.gotoOff + int32(len(l.gotoBytes))
	startOffsets := make([]int, n+1)
	total := 0
	for newID := 0; newID < n; newID++ {
		startOffsets[newID] = total
		total += len(ac.nodes[newToOld[newID]].output)
	}
	startOffsets[n] = total

	nodeOutBytes := make([]byte, (n+1)*2)
	for i, off := range startOffsets {
		binary.LittleEndian.PutUint16(nodeOutBytes[i*2:], uint16(off))
	}

	// Output array: flat list of litID values in node order.
	l.outputOff = l.nodeOutOff + int32(len(nodeOutBytes))
	outputBytes := make([]byte, total*2)
	for newID := 0; newID < n; newID++ {
		for j, litID := range ac.nodes[newToOld[newID]].output {
			idx := startOffsets[newID] + j
			binary.LittleEndian.PutUint16(outputBytes[idx*2:], uint16(litID))
		}
	}

	// Combine nodeOut + output into one contiguous block, emitted as a single
	// data segment based at nodeOutOff.
	//
	// tableEnd is therefore nodeOutOff + len(block), NOT outputOff +
	// len(block): outputOff already points PAST the nodeOut array, so adding
	// the whole concatenation to it counted nodeOut twice and left a
	// (numNodes+1)*2-byte hole before whatever sits at tableEnd. That is what
	// acBudgetBytes was measuring, so the budget held fewer literals than it
	// was sized for.
	nodeOutLen := int32(len(nodeOutBytes))
	nodeOutBytes = append(nodeOutBytes, outputBytes...)
	l.outputBytes = nodeOutBytes
	l.tableEnd = l.nodeOutOff + nodeOutLen + int32(len(outputBytes))
	if l.compressed {
		l.classMapOff = l.tableEnd
		l.tableEnd += 256
	}
	return l
}

// --------------------------------------------------------------------------
// AC WASM emission

// emitACDataSegments emits WASM data segments for the AC tables.
// Returns the segments; acDataSegCount in CompileSet must match what this
// emits, so use acDataSegments() for the count rather than a literal.
func emitACDataSegments(l *acLayout) []byte {
	var ds []byte
	ds = appendDataSegment(ds, l.gotoOff, l.gotoBytes)
	ds = appendDataSegment(ds, l.nodeOutOff, l.outputBytes)
	if l.compressed {
		ds = appendDataSegment(ds, l.classMapOff, l.classMap[:])
	}
	return ds
}

// acDataSegments is the number of segments emitACDataSegments produces, which
// CompileSet must add to its running total. Derived rather than written out
// twice, since a mismatch corrupts the data section count.
func acDataSegments(l *acLayout) int {
	if l.compressed {
		return 3 // goto, nodeOut+output, classMap
	}
	return 2 // goto, nodeOut+output
}
