package compile

// LEVER C — columns over PROJECTED states (plans §19.8).
//
// THE OBSERVATION. The sweep's column holds one cell per (state, pattern). But
// the cell g(q, p, t) depends on q only through what pattern p's own threads
// are doing inside q: the recurrence reads whether q mid-accepts p, whether it
// accepts p at EOF, and the cell of q's successor. Two union states whose
// p-behaviour is identical under EVERY future therefore hold the same cell for
// p, at every position, and storing both is storing the same number twice.
//
// HOW IT IS COMPUTED HERE, and why not the way §19.8 sketched it. The plan's
// route was to retain each DFA state's NFA set through the subset construction
// and three renumberings, then project those sets onto each pattern's threads.
// That is surgery on `engine_dfa.go`, which every engine shares. It is not
// needed: "same p-behaviour under every future" is exactly the equivalence a
// MOORE PARTITION REFINEMENT computes, and refinement needs only the
// transition table and the two accept masks — both of which the bucket already
// has. So this file touches nothing outside the set path, and the result is
// the same partition: §19.4 measured that the distinct projections of a
// pattern number exactly its minimized single-pattern DFA's states, which is
// what refinement produces by construction.
//
// WHAT A CLASS IS WORTH. cells falls from states x patterns to the sum over
// patterns of that pattern's class count, plus ONE shared dead cell. Both the
// checkpoint size and the per-position update count fall with it.

// overlapProj is one bucket's projection: for each pattern, which cell each
// WASM state reads.
type overlapProj struct {
	// cellOf[p][w] is the cell index pattern p's answer for WASM state w lives
	// in. Cell 0 is the shared DEAD cell — the class of states from which p can
	// never match again — and is never written, so a read through it needs no
	// branch.
	cellOf [][]int32
	// cells counts every cell including the dead one.
	cells int
	// rep[c] is a representative WASM state for cell c, which is what the
	// emitter reads accept bits and transitions from. rep[0] is 0 (dead).
	rep []int32
}

// buildOverlapProj computes the projection for a bucket, or nil when it would
// not pay — when no two states share a class there is nothing to merge and the
// indirection would be pure cost.
func buildOverlapProj(dp overlapDPTables, numPat int) *overlapProj {
	if !dp.ok || dp.l == nil || dp.midMasks == nil || dp.eofMasks == nil {
		return nil
	}
	n := dp.numWASM
	if n < 2 || numPat < 1 {
		return nil
	}
	cellsPerState := 256
	if dp.l.useCompression {
		cellsPerState = dp.l.numClasses
	}
	// delta(w, c) over the SAME table the forward body and the sweep read.
	delta := func(w, c int) int {
		row := w
		if dp.l.useRowDedup {
			row = int(dp.l.rowMapBytes[w])
		}
		i := int(dp.l.tableOff) + row*cellsPerState + c
		_ = i
		idx := row*cellsPerState + c
		if idx < 0 || idx >= len(dp.l.tableBytes) {
			return 0
		}
		return int(dp.l.tableBytes[idx])
	}

	p := &overlapProj{cellOf: make([][]int32, numPat)}
	p.rep = append(p.rep, 0) // cell 0: dead
	p.cells = 1

	for pat := 0; pat < numPat; pat++ {
		bit := uint64(1) << uint(pat)
		// Initial partition: the dead class (0), then states split by their own
		// accept bits. State 0 is the DFA's dead state and is dead for every
		// pattern by definition.
		cls := make([]int32, n)
		key := map[[2]bool]int32{}
		next := int32(1)
		for w := 1; w < n; w++ {
			k := [2]bool{dp.midMasks[w]&bit != 0, dp.eofMasks[w]&bit != 0}
			id, ok := key[k]
			if !ok {
				id = next
				next++
				key[k] = id
			}
			cls[w] = id
		}
		// Refine until stable: two states stay together only while every
		// transition leads to the same class.
		for {
			sig := map[string]int32{}
			ncls := make([]int32, n)
			nnext := int32(1)
			changed := false
			for w := 1; w < n; w++ {
				var sb []byte
				sb = append(sb, byte(cls[w]), byte(cls[w]>>8))
				for c := 0; c < cellsPerState; c++ {
					t := delta(w, c)
					sb = append(sb, byte(cls[t]), byte(cls[t]>>8))
				}
				id, ok := sig[string(sb)]
				if !ok {
					id = nnext
					nnext++
					sig[string(sb)] = id
				}
				ncls[w] = id
			}
			if nnext != next {
				changed = true
			}
			cls, next = ncls, nnext
			if !changed {
				break
			}
		}
		// A class is DEAD for this pattern when it can never accept and every
		// transition stays dead. Compute by fixpoint from "accepts nothing".
		alive := make([]bool, next)
		for w := 1; w < n; w++ {
			if dp.midMasks[w]&bit != 0 || dp.eofMasks[w]&bit != 0 {
				alive[cls[w]] = true
			}
		}
		for {
			grew := false
			for w := 1; w < n; w++ {
				if alive[cls[w]] {
					continue
				}
				for c := 0; c < cellsPerState; c++ {
					if t := delta(w, c); t != 0 && alive[cls[t]] {
						alive[cls[w]] = true
						grew = true
						break
					}
				}
			}
			if !grew {
				break
			}
		}

		col := make([]int32, n)
		remap := make([]int32, next)
		for i := range remap {
			remap[i] = -1
		}
		for w := 1; w < n; w++ {
			c := cls[w]
			if !alive[c] {
				col[w] = 0 // the shared dead cell
				continue
			}
			if remap[c] < 0 {
				remap[c] = int32(p.cells)
				p.rep = append(p.rep, int32(w))
				p.cells++
			}
			col[w] = remap[c]
		}
		p.cellOf[pat] = col
	}

	// No saving: every (state, pattern) got its own live cell anyway.
	if p.cells >= n*numPat {
		return nil
	}
	return p
}
