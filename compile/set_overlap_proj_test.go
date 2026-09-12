package compile

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"
)

// LEVER C's projection, checked against the recurrence it replaces and against
// Go itself.
//
// WHAT THIS PINS. The sweep's column holds one cell per (state, pattern) pair
// in its plain form. Lever C narrows it to one cell per PROJECTION: states with
// identical per-pattern behaviour share a cell, which a Moore partition
// refinement over the bucket's own transition table and accept masks computes.
// The saving is 1.7x to 3.3x and grows with the state count — and a projection
// that merged two states it should not have would report a WRONG EXTENT, or no
// match at all, with nothing to signal it.
//
// WHY IT IS CORRECT, since the file it tests once claimed something else: the
// cell g(q, p, .) is a function of the Moore OUTPUT SEQUENCE (mid_p, eof_p)
// along the remaining input, so two Moore-equivalent states hold equal cells at
// every position. That is the whole argument. It is NOT that the classes of one
// pattern number its minimized single-pattern DFA's states — measured false on
// three of the shapes below.
//
// THREE models, all over the SAME layout the emitted sweep reads (the bucket's
// tableBytes, classMap, midMasks and eofMasks, so a table change moves all of
// them together):
//
//   - the projected recurrence, which is what the sweep does;
//   - the unprojected one, which is what it did before lever C;
//   - Go's own regexp, through the whole-input probe \A(?s:.{s})(?:pat) — the
//     same technique re2test's set mode uses, so left-context assertions see
//     the real preceding byte rather than a slice edge.
//
// The Go oracle is what makes this more than a self-consistency check: two
// models derived from the same tables can agree and both be wrong.

// overlapProjModel: the projected recurrence in Go over the SAME layout the
// emitted sweep reads (dp.l.tableBytes, dp.midMasks, dp.eofMasks, proj).
func overlapProjModel(dp overlapDPTables, pr *overlapProj, numPat int, input []byte) [][]int {
	l := dp.l
	n := dp.numWASM
	cps := 256
	if l.useCompression {
		cps = l.numClasses
	}
	if l.useRowDedup || !l.useU8 {
		panic("unexpected layout")
	}
	delta := func(w, c int) int { return int(l.tableBytes[w*cps+c]) }
	classOf := func(b byte) int {
		if l.useCompression {
			return int(l.classMap[b])
		}
		return int(b)
	}
	owner := make([]int, pr.cells)
	for c := 1; c < pr.cells; c++ {
		owner[c] = -1
		w := int(pr.rep[c])
		for p := 0; p < numPat; p++ {
			if pr.cellOf[p][w] == int32(c) {
				if owner[c] >= 0 {
					panic("cell owned twice")
				}
				owner[c] = p
			}
		}
		if owner[c] < 0 {
			panic("cell with no owner")
		}
	}
	cur := make([]int, pr.cells)
	prev := make([]int, pr.cells)
	cur[0], prev[0] = -1, -1
	N := len(input)
	for c := 1; c < pr.cells; c++ {
		w := int(pr.rep[c])
		if dp.eofMasks[w]&(1<<uint(owner[c])) != 0 {
			cur[c] = N
		} else {
			cur[c] = -1
		}
	}
	ext := make([][]int, N+1)
	rec := func(pos int) {
		start := int(dp.wasmMidStart)
		if pos == 0 {
			start = int(dp.wasmStart)
		}
		row := make([]int, numPat)
		for k := 0; k < numPat; k++ {
			row[k] = cur[pr.cellOf[k][start]]
		}
		ext[pos] = row
	}
	rec(N)
	succ := make([]int, n)
	for pos := N - 1; pos >= 0; pos-- {
		cur, prev = prev, cur
		cl := classOf(input[pos])
		for w := 1; w < n; w++ {
			succ[w] = delta(w, cl)
		}
		for c := 1; c < pr.cells; c++ {
			w := int(pr.rep[c])
			p := owner[c]
			v := prev[pr.cellOf[p][succ[w]]]
			if v != -1 {
				cur[c] = v
			} else if dp.midMasks[w]&(1<<uint(p)) != 0 {
				cur[c] = pos
			} else {
				cur[c] = -1
			}
		}
		if cur[0] != -1 || prev[0] != -1 {
			panic("dead cell written")
		}
		rec(pos)
	}
	return ext
}

// overlapPlainModel: the unprojected recurrence over the same layout — what
// the sweep computed before lever C, and the reference the projection must
// agree with cell for cell.
func overlapPlainModel(dp overlapDPTables, numPat int, input []byte) [][]int {
	l := dp.l
	n := dp.numWASM
	cps := 256
	if l.useCompression {
		cps = l.numClasses
	}
	delta := func(w, c int) int { return int(l.tableBytes[w*cps+c]) }
	classOf := func(b byte) int {
		if l.useCompression {
			return int(l.classMap[b])
		}
		return int(b)
	}
	cur := make([]int, n*numPat)
	prev := make([]int, n*numPat)
	N := len(input)
	for w := 0; w < n; w++ {
		for k := 0; k < numPat; k++ {
			if w > 0 && dp.eofMasks[w]&(1<<uint(k)) != 0 {
				cur[w*numPat+k] = N
			} else {
				cur[w*numPat+k] = -1
			}
		}
	}
	ext := make([][]int, N+1)
	rec := func(pos int) {
		start := int(dp.wasmMidStart)
		if pos == 0 {
			start = int(dp.wasmStart)
		}
		row := make([]int, numPat)
		for k := 0; k < numPat; k++ {
			row[k] = cur[start*numPat+k]
		}
		ext[pos] = row
	}
	rec(N)
	for pos := N - 1; pos >= 0; pos-- {
		cur, prev = prev, cur
		cl := classOf(input[pos])
		for w := 0; w < n; w++ {
			to := 0
			if w > 0 {
				to = delta(w, cl)
			}
			for k := 0; k < numPat; k++ {
				switch {
				case to != 0 && prev[to*numPat+k] != -1:
					cur[w*numPat+k] = prev[to*numPat+k]
				case w > 0 && dp.midMasks[w]&(1<<uint(k)) != 0:
					cur[w*numPat+k] = pos
				default:
					cur[w*numPat+k] = -1
				}
			}
		}
		rec(pos)
	}
	return ext
}

// overlapProjClassChain is setperf's classchain family: the widest column any
// fixture here produces, and the shape whose ratio the projection is measured
// on.
func overlapProjClassChain(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
	}
	return out
}

func TestOverlapProjectionMatchesTheRecurrenceAndGo(t *testing.T) {
	shapes := []struct {
		name string
		pats []string
		// nonDead, when > 0, pins the class count: the cells MINUS the shared
		// dead cell 0, which every column reserves.
		nonDead int
	}{
		{"greedy-3", []string{`a+`, `[^\n]*ERROR`, `x?y`}, 11},
		{"overlap-shape-3", []string{`[a-z]+`, `[0-9]+`, `[A-Z]+`}, 6},
		{"classchain-32", overlapProjClassChain(32), 352},
		// A COMPRESSED table (byte classes), which changes how the model and
		// the sweep index the transition table and nothing else.
		{"compressed", []string{`(?:[0-9][a-c]){70}`}, 0},
		{"compressed-multi", []string{`(?:[0-9][a-c]){40}`, `[0-9]+`, `[a-c]+`}, 0},
		// Empty matches, aliases and anchors: the shapes where a merged class
		// is most tempting and most wrong.
		{"empty-and-aliases", []string{`a*`, `a+`, ``, `b?`, `(?:)`, `a|`, `[ab]{0,2}`}, 0},
		{"non-greedy", []string{`a+?`, `a+`}, 0},
		{"prefix-pair", []string{`ab|abc`, `b`, `c`}, 0},
		{"anchors", []string{`^a+`, `a+$`, `^$`}, 0},
		{"lazy-alternation", []string{`(?:ab|cd)*?x`, `a|ab`, `(a|b)*?c`}, 0},
	}
	// Bytes drawn from every shape's alphabet plus a newline, so `[^\n]*` and
	// `(?m:^)` see what they are about.
	alphabet := []byte("aabbxyERRO0129Zc\nd")
	rng := rand.New(rand.NewSource(1))

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}
			cs := setEmitCovCompileSet(t, spec, shape.pats, CompileSetOptions{})
			bi := cs.overlapDPBucket()
			if bi < 0 {
				t.Skip("this shape gets no sweep, so there is no column to project")
			}
			bkt := cs.buckets[bi]
			numPat := len(bkt.patterns)
			pr := buildOverlapProj(bkt.dp, numPat)
			if pr == nil {
				t.Skip("the projection saved nothing here and was declined")
			}
			if shape.nonDead > 0 && pr.cells-1 != shape.nonDead {
				t.Errorf("%d non-dead classes, want %d (cells %d, which counts the dead cell)",
					pr.cells-1, shape.nonDead, pr.cells)
			}
			// The ceiling: a column can hold at most one live cell per
			// (live state, pattern) pair, and one more for the dead cell.
			if max := (bkt.dp.numWASM - 1) * numPat; pr.cells-1 > max {
				t.Fatalf("%d live cells for %d states x %d patterns: the projection "+
					"invented cells rather than merging them", pr.cells-1, bkt.dp.numWASM, numPat)
			}

			for iter := 0; iter < 300; iter++ {
				in := make([]byte, rng.Intn(40))
				for i := range in {
					in[i] = alphabet[rng.Intn(len(alphabet))]
				}
				got := overlapProjModel(bkt.dp, pr, numPat, in)
				want := overlapPlainModel(bkt.dp, numPat, in)
				for s := 0; s <= len(in); s++ {
					for k := 0; k < numPat; k++ {
						if got[s][k] != want[s][k] {
							t.Fatalf("input %q start %d pattern %d: projected %d, unprojected %d",
								in, s, k, got[s][k], want[s][k])
						}
						pat := bkt.patterns[k].fullPattern
						re := regexp.MustCompile(fmt.Sprintf(`\A(?s:.{%d})(?:%s)`, s, pat))
						oracle := -1
						if m := re.FindIndex(in); m != nil {
							oracle = m[1]
						}
						if oracle != got[s][k] {
							t.Fatalf("input %q start %d pattern %d (%s): projected %d, Go %d",
								in, s, k, pat, got[s][k], oracle)
						}
					}
				}
			}
		})
	}
}
