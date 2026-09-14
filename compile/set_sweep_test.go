package compile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// The overlapping backward sweep rests on ONE claim: that the leftmost-first extent
// of a match from start s satisfies a right-to-left recurrence, so a single
// backward sweep answers every start at once.
//
// Stage B was BUILT on that claim and then refuted — not because the
// recurrence was wrong, but because delivering its answer needed a buffer that
// could never be large enough. The recurrence itself was never independently
// checked; it was checked only through the WASM that implemented it, which
// means a bug in either would have looked like a bug in both.
//
// So this file checks the RECURRENCE FIRST, in Go, against Go's own regexp.
// If it is right here, porting it to emitted WASM is mechanical and the
// differential test on the emitted body has a known-good oracle to fail
// against. If it is wrong here, no amount of WASM debugging would have found
// that out.

// overlapDPReference is the stage C recurrence, in Go, over the same dfaTable
// the emitted sweep reads.
//
// Returns extents[start][patternIdx]: the end position of the leftmost-first
// match of pattern patternIdx beginning at `start`, or -1 for no match.
//
// It keeps only the CURRENT COLUMN, exactly as the emitted sweep does, so a
// mistake in the column's shape shows up here rather than only in WASM.
func overlapDPReference(t *dfaTable, input []byte, numPatterns int) [][]int {
	n := len(input)
	numStates := t.numStates + 1 // WASM ids are 1-based; 0 is dead

	// bitAt reports whether `state` accepts for pattern k in the given map.
	bitAt := func(m map[int]uint64, state, k int) bool {
		if state <= 0 {
			return false
		}
		return m[state-1]&(uint64(1)<<uint(k)) != 0
	}
	// next is delta(state, byte) in WASM ids: 0 stays 0 (dead).
	next := func(state int, b byte) int {
		if state <= 0 {
			return 0
		}
		to := t.transitions[(state-1)*256+int(b)]
		if to < 0 {
			return 0
		}
		return to + 1
	}

	const dead = -1
	// column[state*numPatterns + k]
	cur := make([]int, numStates*numPatterns)
	prev := make([]int, numStates*numPatterns)

	// t == n: g(q,n) = n if q accepts at EOF, else DEAD.
	for state := 0; state < numStates; state++ {
		for k := 0; k < numPatterns; k++ {
			if bitAt(t.acceptStates, state, k) {
				cur[state*numPatterns+k] = n
			} else {
				cur[state*numPatterns+k] = dead
			}
		}
	}

	extents := make([][]int, n+1)
	record := func(pos int) {
		row := make([]int, numPatterns)
		start := t.startState + 1
		if pos > 0 {
			start = t.midStartState + 1
		}
		for k := 0; k < numPatterns; k++ {
			row[k] = cur[start*numPatterns+k]
		}
		extents[pos] = row
	}
	record(n)

	for pos := n - 1; pos >= 0; pos-- {
		cur, prev = prev, cur
		b := input[pos]
		for state := 0; state < numStates; state++ {
			to := next(state, b)
			for k := 0; k < numPatterns; k++ {
				switch {
				// THERE IS NO immediateAccept BRANCH — see the recurrence in
				// set_overlap_dp.go for why its absence is deliberate.
				//
				// This file used to open with one, mirroring the forward
				// engine's early stop, and this test could not refute it:
				// mutation over every non-greedy shape here changed no
				// answer, so it was kept and documented as unproven. The
				// CORPUS refuted it — `{a*, ""}` over "a" reported a* as 0-0
				// instead of its greedy 0-1 — which is the shape a
				// hand-picked list did not contain: a pattern that matches
				// empty AND longer, sharing a bucket with one that matches
				// only empty. Both such sets are in the table below now, so
				// the gap cannot reopen here either.
				//
				// The recursion, when the suffix answered.
				case prev[to*numPatterns+k] != dead && to != 0:
					cur[state*numPatterns+k] = prev[to*numPatterns+k]
				// Otherwise the last accept seen, which is here or nowhere.
				case bitAt(t.midAcceptStates, state, k):
					cur[state*numPatterns+k] = pos
				default:
					cur[state*numPatterns+k] = dead
				}
			}
		}
		record(pos)
	}
	return extents
}

// TestOverlapDPRecurrenceMatchesGo is the check stage B never had.
//
// The oracle is `overlapping: true`'s contract stated directly: at every start
// position, every pattern that matches THERE, with its leftmost-first extent.
// That is an anchored probe per start, which is how the corpus harness builds its own
// expectations — and deliberately NOT FindAllIndex, which is the GATED rule.
func TestOverlapDPRecurrenceMatchesGo(t *testing.T) {
	patternSets := [][]string{
		{`a+`},
		{`a+`, `x?y`},
		{`[^\n]*ERROR`},
		{`a+`, `[^\n]*ERROR`, `x?y`},
		{`ab|abc`},        // leftmost-first: the FIRST alternative wins
		{`a*`},            // matches empty everywhere
		{`abc`, `b`, `c`}, // overlapping literals
		{`[0-9]+`, `[a-z]+`},
		{`a`, `aa`, `aaa`}, // nested extents from one start

		// EMPTY-CAPABLE patterns sharing a bucket with empty-ONLY ones. This
		// is the shape that refuted the immediateAccept branch: `a*` must
		// report its GREEDY extent even though `""` accepts immediately at the
		// same state. Found by the corpus, pinned here.
		{`a*`, ``},
		{`a*`, `a+`, ``, `b?`, `(?:)`, `a|`, `[ab]{0,2}`},

		// NON-GREEDY shapes. These are the ones that actually put states in
		// immediateAcceptStates and so exercise the recurrence's FIRST branch:
		// without them, disabling that branch entirely changed no answer here,
		// because for greedy patterns the DFA's own leftmost-first pruning has
		// already stopped the walk. Checked by mutation, not assumed.
		{`a+?`},
		{`a*?b`},
		{`.*?b`},
		{`(?:ab|cd)*?x`},
		{`a|ab`},
		{`(a|b)*?c`},
		{`a+?`, `a+`}, // the same shape greedy and non-greedy, together
	}
	inputs := []string{
		"",
		"a",
		"aa",
		"aaa",
		"abc",
		"ababab",
		"xy xy",
		"ERROR",
		"aaa ERROR bbb",
		"no match here",
		"123abc456",
		"aXbXc",
		"the end",
		"aab",
		"abcabc",
		"cdabx",
		"bbb",
	}

	for si, pats := range patternSets {
		for _, input := range inputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				table := buildOverlapTestTable(t, pats)
				if table == nil {
					t.Skip("patterns did not compile to a single set DFA")
				}
				got := overlapDPReference(table, []byte(input), len(pats))

				for start := 0; start <= len(input); start++ {
					for k, pat := range pats {
						anchored := regexp.MustCompile(`\A(?:` + pat + `)`)
						wantEnd := -1
						if m := anchored.FindStringIndex(input[start:]); m != nil {
							wantEnd = start + m[1]
						}
						gotEnd := got[start][k]
						if gotEnd != wantEnd {
							t.Errorf("start %d, pattern %d (%s): recurrence says %d, Go says %d",
								start, k, pat, gotEnd, wantEnd)
						}
					}
				}
			})
		}
	}
}

// buildOverlapTestTable compiles the patterns into ONE merged set DFA — the
// shape the sweep runs over — through the same mergeSuffixDFA the set path
// uses, so the recurrence is checked against the real table rather than a
// stand-in.
func buildOverlapTestTable(t *testing.T, pats []string) *dfaTable {
	t.Helper()
	asts := make([]*syntax.Regexp, 0, len(pats))
	for _, p := range pats {
		parsed, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", p, err)
		}
		asts = append(asts, parsed)
	}
	table, _, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		return nil
	}
	return table
}

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
		// decline is the outcome a shape is EXPECTED to have when it is not
		// projected: "nosweep" when the set gets no sweep at all, "nosaving"
		// when the projection would save nothing and is declined. Empty means
		// the shape must project. A skip here used to let a shape that stopped
		// projecting pass as a shape that never could.
		decline string
	}{
		{"greedy-3", []string{`a+`, `[^\n]*ERROR`, `x?y`}, 11, ""},
		{"overlap-shape-3", []string{`[a-z]+`, `[0-9]+`, `[A-Z]+`}, 6, ""},
		{"classchain-32", overlapProjClassChain(32), 352, ""},
		// A COMPRESSED table (byte classes), which changes how the model and
		// the sweep index the transition table and nothing else.
		{"compressed", []string{`(?:[0-9][a-c]){70}`}, 0, "nosaving"},
		{"compressed-multi", []string{`(?:[0-9][a-c]){40}`, `[0-9]+`, `[a-c]+`}, 0, ""},
		// Empty matches, aliases and anchors: the shapes where a merged class
		// is most tempting and most wrong.
		{"empty-and-aliases", []string{`a*`, `a+`, ``, `b?`, `(?:)`, `a|`, `[ab]{0,2}`}, 0, ""},
		{"non-greedy", []string{`a+?`, `a+`}, 0, ""},
		{"prefix-pair", []string{`ab|abc`, `b`, `c`}, 0, "nosweep"},
		{"anchors", []string{`^a+`, `a+$`, `^$`}, 0, ""},
		{"lazy-alternation", []string{`(?:ab|cd)*?x`, `a|ab`, `(a|b)*?c`}, 0, "nosweep"},
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
				if shape.decline != "nosweep" {
					t.Fatalf("this shape gets no sweep; want %q", shape.decline)
				}
				return
			}
			bkt := cs.buckets[bi]
			numPat := len(bkt.patterns)
			pr := buildOverlapProj(bkt.dp, numPat)
			if pr == nil {
				if shape.decline != "nosaving" {
					t.Fatalf("the projection saved nothing and was declined; want %q", shape.decline)
				}
				return
			}
			if shape.decline != "" {
				t.Fatalf("the shape projected; it was expected to decline (%s)", shape.decline)
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

// noSweepSet is a set whose `find` gets no backward sweep: gated rather than
// overlapping. Every accessor below must answer the ORDINARY way for it.
func noSweepSet(t *testing.T) *compiledSet {
	t.Helper()
	spec := SetSpec{Name: "s", Find: "s_find"}
	cs := setEmitCovCompileSet(t, spec, []string{`[0-9][a-c][0-9]`}, CompileSetOptions{})
	if bi := cs.overlapDPBucket(); bi >= 0 {
		t.Fatalf("a gated find got a sweep bucket (%d); this fixture no longer isolates the no-sweep path", bi)
	}
	return cs
}

// TestOverlapAccessorsWithoutSweep covers every derived quantity on a set that
// has no sweep. They are asked for unconditionally by the emitters, so each one
// has to answer rather than assume a bucket exists — and the answers have to be
// the ones that mean "reserve nothing", not zero-sized versions of real ones.
func TestOverlapAccessorsWithoutSweep(t *testing.T) {
	cs := noSweepSet(t)

	if got := cs.overlapCells(); got != 0 {
		t.Errorf("overlapCells() = %d, want 0", got)
	}
	if got := cs.overlapProjFor(); got != nil {
		t.Errorf("overlapProjFor() = %+v, want nil", got)
	}
	// Twice: the memo is set before the bucket is looked up, and a nil pinned by
	// the first call must not be mistaken for a computed projection.
	if got := cs.overlapProjFor(); got != nil {
		t.Errorf("overlapProjFor() on the second call = %+v, want nil", got)
	}
	if got := cs.overlapProjTabBytes(); got != nil {
		t.Errorf("overlapProjTabBytes() = %d bytes, want nil", len(got))
	}
	if got := cs.overlapDPColumnBytes(); got != 0 {
		t.Errorf("overlapDPColumnBytes() = %d, want 0", got)
	}
	// 1, not 0: the trigger DIVIDES by this, and it is compared against work the
	// walk has done, so a zero would either trap or make every drive trigger.
	if got := cs.overlapSweepCostPerByte(); got != 1 {
		t.Errorf("overlapSweepCostPerByte() = %d, want 1", got)
	}
}

// TestBuildOverlapProjDeclines covers each guard on the projection builder.
//
// Every one of them returns the PLAIN column, which is correct at every width —
// declining is the safe direction, and a guard that stopped firing would read a
// table it cannot read and merge states that are not equivalent, which is a
// wrong extent with nothing to signal it.
func TestBuildOverlapProjDeclines(t *testing.T) {
	// A real, projectable bucket to degrade from, so each case below differs
	// from a WORKING one in exactly the field it names.
	spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}
	cs := setEmitCovCompileSet(t, spec, []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}, CompileSetOptions{})
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("the reference bucket gets no sweep; nothing here degrades from a working case")
	}
	good := cs.buckets[bi].dp
	numPat := len(cs.buckets[bi].patterns)
	if buildOverlapProj(good, numPat) == nil {
		t.Fatal("the reference bucket declined the projection; the guards below prove nothing")
	}

	for _, tc := range []struct {
		name string
		dp   func(overlapDPTables) overlapDPTables
		pats int
	}{
		{"not-ok", func(d overlapDPTables) overlapDPTables { d.ok = false; return d }, numPat},
		{"no-layout", func(d overlapDPTables) overlapDPTables { d.l = nil; return d }, numPat},
		{"no-mid-masks", func(d overlapDPTables) overlapDPTables { d.midMasks = nil; return d }, numPat},
		{"no-eof-masks", func(d overlapDPTables) overlapDPTables { d.eofMasks = nil; return d }, numPat},
		{"one-state", func(d overlapDPTables) overlapDPTables { d.numWASM = 1; return d }, numPat},
		{"no-patterns", func(d overlapDPTables) overlapDPTables { return d }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildOverlapProj(tc.dp(good), tc.pats); got != nil {
				t.Errorf("buildOverlapProj declined nothing: got %d cells", got.cells)
			}
		})
	}

	// The two LAYOUT refusals need their own copy: dfaLayout is shared by
	// pointer, so flipping a flag in place would corrupt the reference bucket.
	for _, tc := range []struct {
		name  string
		mutex func(*dfaLayout)
	}{
		{"row-dedup", func(l *dfaLayout) { l.useRowDedup = true }},
		{"u16-ids", func(l *dfaLayout) { l.useU8 = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := *good.l
			tc.mutex(&layout)
			d := good
			d.l = &layout
			if got := buildOverlapProj(d, numPat); got != nil {
				t.Errorf("buildOverlapProj read a layout it cannot read: got %d cells", got.cells)
			}
		})
	}
}

// TestBuildOverlapProjPanicsOnGeometryMismatch pins the transition-table bounds
// check. It is not recoverable and must not be guessed at: answering "dead" for
// an out-of-range cell would turn a geometry mismatch into MISSING MATCHES.
func TestBuildOverlapProjPanicsOnGeometryMismatch(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}
	cs := setEmitCovCompileSet(t, spec, []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}, CompileSetOptions{})
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("no sweep bucket to mismatch")
	}
	good := cs.buckets[bi].dp

	// A table SHORTER than numWASM x cellsPerState: the same disagreement a
	// layout change would introduce.
	layout := *good.l
	layout.tableBytes = layout.tableBytes[:len(layout.tableBytes)/2]
	d := good
	d.l = &layout

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("buildOverlapProj read past the transition table without panicking")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "overlap projection") {
			t.Errorf("panic = %q, want it to name the projection", msg)
		}
	}()
	buildOverlapProj(d, len(cs.buckets[bi].patterns))
}

// overlapShapeCfg is a set whose `find` gets the backward sweep: overlapping,
// one fallback bucket, literal-less members so no frontend claims them.
func overlapShapeCfg() (config.SetConfig, config.BuildConfig) {
	patterns := []string{`[0-9][a-c][0-9]`, `[a-c][0-9][a-c]`}
	cfg := config.BuildConfig{Regexps: setEmitCovEntries(patterns)}
	sc := config.SetConfig{
		Name:        "s",
		Find:        "s_find",
		Overlapping: true,
		Patterns:    config.PatternSelector{All: true},
	}
	cfg.Sets = []config.SetConfig{sc}
	return sc, cfg
}

// TestSetOverlapCacheShapeEligible pins the sizing API a stub generator reads.
// It RECOMPILES the set, so what it reports has to be the automaton the real
// build gets — the numbers are cross-checked against the compiled set here for
// that reason, not because either one is interesting on its own.
func TestSetOverlapCacheShapeEligible(t *testing.T) {
	sc, cfg := overlapShapeCfg()
	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible {
		t.Fatal("the sweep refused a literal-less overlapping set; the sizing path is unreachable")
	}

	cs, err := compileSetForInspection(sc, cfg, CompileSetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("inspection and SetOverlapCacheShape disagree about eligibility")
	}
	if got, want := sh.Cells, cs.overlapCells(); got != want {
		t.Errorf("Cells = %d, want the column width %d", got, want)
	}
	if got, want := sh.Patterns, len(cs.buckets[bi].patterns); got != want {
		t.Errorf("Patterns = %d, want the BUCKET's count %d", got, want)
	}

	// And the pair a caller actually asks for: the region is sized FROM the
	// stride, so the two must come from the same shape or the sweep rejects the
	// descriptor it is handed.
	const inputLen = 4096
	bytes, stride, err := SetOverlapCacheSizing(sc, cfg, inputLen)
	if err != nil {
		t.Fatal(err)
	}
	if want := config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns); stride != want {
		t.Errorf("stride = %d, want %d", stride, want)
	}
	if want := config.SetOverlapCheckpointBytes(inputLen, sh.Cells, sh.Patterns); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}
	if bytes <= config.SetOverlapCheckpointHeaderBytes {
		t.Errorf("bytes = %d, which is no more than the header: nothing was reserved", bytes)
	}
}

// TestSetOverlapCacheShapeIneligible covers the ORDINARY answer. A set with no
// sweep is not an error, and the nominal (header, 1) sizing keeps the
// descriptor's shape identical on both paths so a stub has one code path.
func TestSetOverlapCacheShapeIneligible(t *testing.T) {
	// Not overlapping: gated `find` gets no sweep.
	cfg := config.BuildConfig{Regexps: setEmitCovEntries([]string{`[0-9][a-c][0-9]`})}
	sc := config.SetConfig{Name: "s", Find: "s_find", Patterns: config.PatternSelector{All: true}}
	cfg.Sets = []config.SetConfig{sc}

	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Eligible {
		t.Fatal("a gated find reported a sweep")
	}
	if sh.Cells != 0 || sh.Patterns != 0 {
		t.Errorf("ineligible shape carries sizing: %+v", sh)
	}

	bytes, stride, err := SetOverlapCacheSizing(sc, cfg, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != config.SetOverlapCheckpointHeaderBytes || stride != 1 {
		t.Errorf("sizing = (%d, %d), want the nominal (%d, 1)",
			bytes, stride, config.SetOverlapCheckpointHeaderBytes)
	}
}

// TestSetOverlapCacheShapeCompileError covers the error arm of both. A set the
// compiler refuses must report, not answer with a zero shape a caller would
// read as "no cache needed".
func TestSetOverlapCacheShapeCompileError(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "bad", Pattern: `(?P<x>`}},
	}
	sc := config.SetConfig{
		Name: "s", Find: "s_find", Overlapping: true,
		Patterns: config.PatternSelector{All: true},
	}
	cfg.Sets = []config.SetConfig{sc}

	if _, err := SetOverlapCacheShape(sc, cfg); err == nil {
		t.Error("SetOverlapCacheShape accepted an unparseable member")
	}
	if _, _, err := SetOverlapCacheSizing(sc, cfg, 4096); err == nil {
		t.Error("SetOverlapCacheSizing accepted an unparseable member")
	}
}

// TestSetOverlapCacheShapeNamedSubset covers the NAMED selector arm of the
// inspection compile. It is the only configuration in which the set's pattern
// count and its id space differ, and sizing a region off the wrong one is a
// memory-safety fault rather than a wrong answer.
func TestSetOverlapCacheShapeNamedSubset(t *testing.T) {
	patterns := []string{`[0-9][a-c][0-9]`, `[a-c][0-9][a-c]`, `[0-9][0-9][a-c]`}
	cfg := config.BuildConfig{Regexps: setEmitCovEntries(patterns)}
	// The LAST two, so the ids the set reports are 1 and 2 while it holds two
	// patterns.
	sc := config.SetConfig{
		Name: "s", Find: "s_find", Overlapping: true,
		Patterns: config.PatternSelector{Names: []string{"p01", "p02"}},
	}
	cfg.Sets = []config.SetConfig{sc}

	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible {
		t.Fatal("the sweep refused the named subset")
	}
	if sh.Patterns != 2 {
		t.Errorf("Patterns = %d, want the 2 the bucket holds (not the 3-wide id space)", sh.Patterns)
	}

	// An unknown name is an error, not an empty set: an empty set would size a
	// region for a sweep the module does not have.
	bad := sc
	bad.Patterns = config.PatternSelector{Names: []string{"p01", "nope"}}
	if _, err := SetOverlapCacheShape(bad, cfg); err == nil {
		t.Error("SetOverlapCacheShape accepted an unknown pattern name")
	}
}

// TestSetOverlapCacheShapeHandComputed pins one shape by hand. The test above
// compares SetOverlapCacheShape with compileSetForInspection, which is where the
// shape reads its own numbers, so it cannot notice both drifting together:
// {a+, [^\n]*ERROR} is 9 cells over a 2-pattern bucket, and sweeping a byte
// costs two cells' worth.
func TestSetOverlapCacheShapeHandComputed(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p0", Pattern: `a+`}, {Name: "p1", Pattern: `[^\n]*ERROR`}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Overlapping: true,
			Patterns: config.PatternSelector{All: true},
		}},
	}
	sh, err := SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible || sh.Cells != 9 || sh.Patterns != 2 || sh.CostPerByte != 18 {
		t.Errorf("shape = %+v, want eligible, 9 cells, 2 patterns, cost 18 per byte", sh)
	}
}

// A WIDE sweep over pattern shapes, capture shapes and set configurations.
//
// The curated matrices next door name the path each case selects, which keeps
// them readable and makes a stale case obvious. This one does the opposite: it
// enumerates a large product and makes no claim about which arm each element
// reaches, because several arms turn on properties invisible in the pattern
// text. `\bERROR[a-z]*` and `\bERROR:[a-z]*` select different resume-state
// arms purely because a colon is not a word character; `AKIA[A-Z0-9]{16,20}`
// reaches the ranged literal-chain emitter only when it also carries captures.
// Both took several wrong guesses to find by hand and fell out of enumeration
// immediately.
//
// What it ASSERTS is modest and uniform: the compiler either produces a
// well-formed module or declines cleanly, for every shape, under every option
// combination and both link modes. A pattern it declines is fine — the list is
// generated, not curated — but a malformed module or a panic is not.
func sweepPatterns() []string {
	lead := []string{"", `\b`, `\B`, `(?m:^)`, `\A`, `(?m:^)\b`, `\b(?m:^)`}
	body := []string{
		"ERROR", "AB", "Q", "abc_", "KEY:", "x", "alpha|beta", "(?:ab)+",
		"a{10,20}", "[0-9]{30}", "ghp_[A-Za-z0-9]{36}", "AKIA[A-Z0-9]{16}",
		"[a-p][0-9]{4}END", "[^\n]*END", ".*END", "a+?b", "(?:a|b|c)[0-9]{4}X",
		"[a-z]+@example\\.com", "[0-9]{3}MIDDLE[0-9]{3}", "x*", "(?:[a-z]{4}[0-9]{4}){3}",
		"(?:cat|car|cab|cap)", "(?:a|bb|ccc|dddd)X", "(?:[ab]{2}[cd]{2}){8}",
		"(?:[a-c]xyz){40}", "START[^Z]{20,}END", "[0-9]{8}ghp_[^\\s]+|[a-f]{8}sec_[^\\s]+",
	}
	tail := []string{"", "[a-z]*", "[0-9]+", `\b`, "(?m:$)", `\z`, ".*"}
	var out []string
	for _, l := range lead {
		for _, b := range body {
			for _, t := range tail {
				out = append(out, l+b+t)
			}
		}
	}
	return out
}

func sweepCapturePatterns() []string {
	base := []string{
		`(a+)(b+)`, `(a+?)(b+)`, `(\w+)`, `([^,]+),`, `(a|b)*c`, `((a)(b))`,
		`(?P<x>[0-9]{2})-(?P<y>[0-9]{2})`, `(a)(b)(c)(d)(e)`, `(.*?)END`,
		`\b(\w+)\b`, `(?m:^)(\w+)(?m:$)`, `(a{2,4})b`, `((?:ab)+)c`,
		`ghp_([A-Za-z0-9]{24,32})`, `x([a-z]{24,30})`, `\A(\w+)\z`,
		`\B(\w+)\B`, `<([^>]+)>`, `(?s)(.*)`, `((a|b)+)(c|d)`,
	}
	wrap := []string{"%s", `x%s`, `%sy`, `(?:%s)+`, `(?:%s)?`, `\b%s\b`, `(?m:^)%s`}
	var out []string
	for _, b := range base {
		for _, w := range wrap {
			out = append(out, fmt.Sprintf(w, b))
		}
	}
	return out
}

func TestWideSweepSinglePattern(t *testing.T) {
	opts := []struct{ dfa, tdfa, fallback int }{
		{0, 0, 0}, {4, 1, 0}, {0, 0, 1}, {64, 8, 0},
	}
	for _, pat := range sweepPatterns() {
		if _, err := syntax.Parse(pat, syntax.Perl); err != nil {
			continue
		}
		for _, standalone := range []bool{true, false} {
			e := config.RegexEntry{Name: "p", Pattern: pat, MatchFunc: "m", FindFunc: "f"}
			w, _, err := Compile([]config.RegexEntry{e}, 65536, standalone)
			if err != nil {
				continue // a declined shape, not a failure
			}
			assertWasm(t, w, pat)
		}
	}
	for _, pat := range sweepCapturePatterns() {
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil || parsed.MaxCap() == 0 {
			continue
		}
		for _, o := range opts {
			w, _, err := CompileFile(config.BuildConfig{
				Regexps: []config.RegexEntry{{
					Name: "p", Pattern: pat,
					GroupsFunc: "g", FindFunc: "f", MatchFunc: "m",
				}},
				MaxDFAStates: o.dfa, MaxTDFARegs: o.tdfa,
				MaxFallbackStates: o.fallback,
			}, "")
			if err != nil {
				continue
			}
			assertWasm(t, w, pat)
		}
		// Both capture engines over the same pattern: the override exists so a
		// differential test can compare them, which is only meaningful if it
		// is honoured.
		for _, forced := range []EngineType{EngineTDFA, EngineBacktrack} {
			w, _, err := CompileForced(
				[]config.RegexEntry{{Name: "p", Pattern: pat, GroupsFunc: "g", FindFunc: "f"}},
				65536, true, forced)
			if err != nil {
				continue
			}
			assertWasm(t, w, pat)
		}
	}
}

func TestWideSweepSets(t *testing.T) {
	families := [][]string{
		{`a+`, `[^\n]*ERROR`, `x?y`},
		{`alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`},
		manyPatterns(24, "keyword%02d"),
		manyPatterns(70, "pat_%02d_tail"),
		sharedLiteral(40),
		sharedLiteral(80),
		diverseFirstBytes(40),
		{`\bcat\b`, `\bdog`, `\b|0*`},
		{`(?m:^)alpha`, `beta(?m:$)`, `(?m:^)gamma(?m:$)`},
		{`\Aabc`, `xyz\z`, `\Aq\z`},
		{`a*`, ``, `(?:)`, `[ab]{0,2}`},
		{`alpha`, `bravo`, `a+`, `[^\n]*END`},
		{`ghp_[A-Za-z0-9]{36}`, `AKIA[A-Z0-9]{16}`, `[a-z]+@example\.com`},
	}
	capSets := []setMatrixCaps{
		capsAll, capsFind, capsAnchored, capsScan,
		{matchAny: true}, {matchAll: true}, {scanAny: true}, {scanAll: true},
		{find: true, scanAny: true}, {matchAll: true, find: true},
	}
	for fi, fam := range families {
		for ci, caps := range capSets {
			for _, overlapping := range []bool{false, true} {
				for _, batch := range []bool{false, true} {
					for _, mfs := range []int{0, 1} {
						for _, out := range []string{"", "merged.wasm"} {
							c := setMatrixCase{
								name:     fmt.Sprintf("f%d/c%d", fi, ci),
								patterns: fam, caps: caps,
								overlapping: overlapping, batch: batch,
								maxFallbackStates: mfs,
							}
							if !caps.find && (overlapping || batch) {
								continue
							}
							// ASSERTED, not discarded. This sweep compiles
							// every capability shape the emitters have, and
							// throwing away both returns meant a shape that
							// failed to compile — or produced nothing —
							// passed. It is why U1's always-empty match_all
							// body compiled green here.
							w, _, err := CompileFile(c.build(), out)
							if err != nil {
								t.Errorf("%s (overlapping=%v batch=%v mfs=%d out=%q): %v",
									c.name, overlapping, batch, mfs, out, err)
								continue
							}
							assertWasm(t, w, fmt.Sprintf("%s (overlapping=%v batch=%v mfs=%d out=%q)",
								c.name, overlapping, batch, mfs, out))
						}
					}
				}
			}
		}
	}
}

// assertWasm checks a compiled module is at least a WASM module. Cheap, and it
// is what catches an emitter that starts producing truncated or empty output
// for a shape nobody looks at directly.
func assertWasm(t *testing.T, w []byte, what string) {
	t.Helper()
	if len(w) < 8 || string(w[:4]) != "\x00asm" {
		t.Fatalf("%s: malformed module (%d bytes)", what, len(w))
	}
}

// ── The start-anywhere union automaton ─────────────────────────────────────
//
// A literal-less set's scan pair compiles to ONE pass over the input rather
// than a per-position bucket walk, and that pass has three shapes the ordinary
// set tests never select together:
//
//   - the NARROW body, which accumulates an i64 id bitmask (<= 64 ids);
//   - the WIDE body, where each state instead carries a representative id plus
//     a bitmap row OR'd into the caller's `_all` bitmap (up to 256 ids);
//   - the SIMD stride, emitted only under prefer-no-match, which walks a
//     state's self-loop run 16 bytes at a time.
//
// Past 256 ids the set keeps the per-position walk instead, so the width
// boundaries are decisions worth pinning rather than incidental.

// unionScanSet builds a literal-less set of n patterns declaring both scan
// capabilities, compiled under the given hint.
func unionScanSet(t *testing.T, n int, hints []string) ([]byte, []SetDiag) {
	t.Helper()
	entries := make([]config.RegexEntry, n)
	for i := range entries {
		// Literal-less by construction: a class chain with no fixed substring
		// long enough to anchor on, and a per-pattern digit span so the
		// patterns stay distinguishable.
		entries[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 3+i%4, 1+i%3),
		}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name:     "s",
			ScanAny:  "s_scan_any",
			ScanAll:  "s_scan_all",
			Patterns: config.PatternSelector{All: true},
			Hints:    hints,
		}},
	}
	w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
	if err != nil {
		t.Fatalf("n=%d hints=%v: %v", n, hints, err)
	}
	return w, diags
}

// TestUnionScanWidthsAndHints drives the union pass across the accept-form
// boundary and both hint settings.
//
// 64 ids is where the i64 accumulator stops fitting and the per-state
// representative-plus-bitmap form takes over; the two are different emitters
// reading differently-shaped tables, and a set that silently took the wrong
// one would still compile.
func TestUnionScanWidthsAndHints(t *testing.T) {
	for _, n := range []int{4, 64, 65, 100} {
		for _, hints := range [][]string{nil, {"prefer-no-match"}, {"prefer-match"}} {
			name := fmt.Sprintf("n=%d/hints=%v", n, hints)
			t.Run(name, func(t *testing.T) {
				w, diags := unionScanSet(t, n, hints)
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("not a WASM module (%d bytes)", len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("got %d set diagnostics, want 1", len(diags))
				}
				// A literal-less set must have no literal frontend to choose:
				// if one appears, these patterns stopped being literal-less
				// and this test is no longer driving the union pass.
				if d := diags[0]; d.Frontend != "scalar" && d.Frontend != "" {
					t.Skipf("frontend %q selected; the set is no longer literal-less", d.Frontend)
				}
				for _, want := range []string{"s_scan_any", "s_scan_all"} {
					if !containsExport(w, want) {
						t.Errorf("module does not export %q", want)
					}
				}
			})
		}
	}
}

func containsExport(w []byte, name string) bool {
	return len(w) > 0 && len(name) > 0 && bytesContains(w, []byte(name))
}

func bytesContains(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if h[i+j] != n[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestWideAcceptSparseBucket drives a single bucket past 64 patterns, which is
// where the DFA's accept representation changes shape.
//
// Up to 64 ids a state's accept set is a u64 BITMASK; past it, construction
// switches to per-state LISTS of pattern indices — a different code path in
// newDFA (acceptWideFor and the wide maps it fills) that a set of 40, which is
// what the sparse fixtures use, never reaches. It is also the only form that
// lets one bucket hold a whole shared-literal group instead of ceil(N/32) of
// them, so it is the shape a large real set actually compiles to.
func TestWideAcceptSparseBucket(t *testing.T) {
	for _, n := range []int{40, 65, 90} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			entries := make([]config.RegexEntry, n)
			for i := range entries {
				// The literal must be SHARED, not merely similar: distinct
				// literals pack into distinct buckets and no bucket ever
				// crosses the width the wide form exists for. The varying
				// part therefore goes AFTER a run that breaks the literal.
				entries[i] = config.RegexEntry{
					Name:    fmt.Sprintf("p%d", i),
					Pattern: fmt.Sprintf(`shared[ \t]+k%03d[a-z]+`, i),
				}
			}
			cfg := config.BuildConfig{
				Regexps: entries,
				Sets: []config.SetConfig{{
					Name:     "s",
					Find:     "s_find",
					MatchAny: "s_match_any",
					MatchAll: "s_match_all",
					ScanAny:  "s_scan_any",
					Patterns: config.PatternSelector{All: true},
				}},
			}
			for _, hints := range [][]string{nil, {"prefer-match"}} {
				cfg.Sets[0].Hints = hints
				w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("n=%d hints=%v: %v", n, hints, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("not a WASM module (%d bytes)", len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("got %d set diagnostics, want 1", len(diags))
				}
				// Past 64 ids the accept kind must have changed; asserting it
				// is what keeps this test pointed at the path it names.
				if n > 64 {
					sawSparse := false
					for _, b := range diags[0].Buckets {
						if b.AcceptKind != "bitmask" {
							sawSparse = true
						}
					}
					if !sawSparse {
						t.Errorf("n=%d: every bucket still reports a bitmask accept; "+
							"this test no longer reaches the wide form", n)
					}
				}
			}
		})
	}
}

// TestOverlapDPRefusals drives the overlapping-find DP sweep into each of its
// refusals.
//
// The sweep is an optimisation that reports every start position in one pass,
// and it declines whenever a bucket's accept representation is something it
// cannot read: a SPARSE bucket keeps per-state lists rather than an i64 mask,
// a Backtracking member has no DFA to sweep at all, and past 64 patterns the
// mask cannot express the answer. Each refusal returns -1 and the set falls
// back to the ordinary per-position walk — correct, just slower — so a refusal
// that stopped working would show up as a wrong answer rather than a slow one.
func TestOverlapDPRefusals(t *testing.T) {
	cases := []struct {
		name    string
		build   func() []config.RegexEntry
		wantSet bool
	}{
		{
			// Past the sparse promotion threshold on one shared literal.
			name: "sparse bucket",
			build: func() []config.RegexEntry {
				out := make([]config.RegexEntry, 50)
				for i := range out {
					out[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`shared[ \t]+k%03d[a-z]+`, i),
					}
				}
				return out
			},
		},
		{
			// A capture-bearing member routes to Backtracking, which has no
			// DFA for the sweep to read.
			name: "backtracking member",
			build: func() []config.RegexEntry {
				return []config.RegexEntry{
					{Name: "a", Pattern: `alpha[0-9]{3}`},
					{Name: "b", Pattern: `bravo[0-9]{3}`},
					{Name: "c", Pattern: `charlie(a.*?b)(c+)`},
				}
			},
		},
		{
			// More patterns than an i64 mask can hold.
			name: "past the mask width",
			build: func() []config.RegexEntry {
				out := make([]config.RegexEntry, 80)
				for i := range out {
					out[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`lit%03dx[a-z]+`, i),
					}
				}
				return out
			},
		},
		{
			// A word boundary changes which start state a position gets, which
			// the sweep would have to reproduce.
			name: "word boundary member",
			build: func() []config.RegexEntry {
				return []config.RegexEntry{
					{Name: "a", Pattern: `alpha[0-9]{3}`},
					{Name: "b", Pattern: `\bbravo\b[0-9]{3}`},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.BuildConfig{
				Regexps: tc.build(),
				Sets: []config.SetConfig{{
					Name:        "s",
					Find:        "s_find",
					Overlapping: true,
					Patterns:    config.PatternSelector{All: true},
				}},
			}
			w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if len(w) < 8 || string(w[:4]) != "\x00asm" {
				t.Fatalf("%s: not a WASM module (%d bytes)", tc.name, len(w))
			}
			if len(diags) != 1 || !diags[0].Overlapping {
				t.Fatalf("%s: the set did not compile as overlapping", tc.name)
			}
			if !containsExport(w, "s_find") {
				t.Errorf("%s: module does not export s_find", tc.name)
			}
		})
	}
}

// TestFindPreflightPredicatesOnWideSets covers the WIDE refusals in both
// find-preflight predicates.
//
// A wide union automaton emits no acceptOff/eofOff u64 pair — it carries
// per-state accept ROWS instead — so a preflight that read the narrow tables
// would be reading something that was never emitted. The failure direction is
// the bad one: a pattern wrongly declared dead stops reporting matches
// entirely, silently. Both predicates therefore refuse the wide form, and both
// refusals are reachable only from a set past 64 ids.
func TestFindPreflightPredicatesOnWideSets(t *testing.T) {
	for _, overlapping := range []bool{false, true} {
		for _, n := range []int{8, 90} {
			name := fmt.Sprintf("n=%d/overlapping=%v", n, overlapping)
			t.Run(name, func(t *testing.T) {
				entries := make([]config.RegexEntry, n)
				for i := range entries {
					// Literal-less, so a union automaton is built at all.
					entries[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`[a-z]{%d}[0-9]{%d}x`, 2+i%3, 1+i%2),
					}
				}
				cfg := config.BuildConfig{
					Regexps: entries,
					Sets: []config.SetConfig{{
						Name:        "s",
						Find:        "s_find",
						ScanAll:     "s_scan_all",
						Overlapping: overlapping,
						Patterns:    config.PatternSelector{All: true},
					}},
				}
				w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("%s: not a WASM module (%d bytes)", name, len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("%s: got %d diagnostics, want 1", name, len(diags))
				}
				if diags[0].Overlapping != overlapping {
					t.Errorf("%s: set reports overlapping=%v", name, diags[0].Overlapping)
				}
				for _, want := range []string{"s_find", "s_scan_all"} {
					if !containsExport(w, want) {
						t.Errorf("%s: module does not export %q", name, want)
					}
				}
			})
		}
	}
}

// The mid-accept-first partition.
//
// Both scan bodies and the gated/overlapping find preflight replace a per-byte
// accept LOAD with the compare `state < midAcceptLimit`. That is only sound if
// the partition means exactly what the bodies assume: states below the limit
// are precisely the ones whose MID-STRING accept entry is non-empty. Nothing
// downstream re-checks it — a state on the wrong side of the line is a wrong
// answer with no trap and no diagnostic.
//
// It is tested as an INVARIANT rather than through a witness input on purpose.
// Mutation testing showed why: partitioning by the END-OF-INPUT accepts instead
// (`d.accepting` / `d.acceptWide` in place of `d.midAccepting` /
// `d.midAcceptWide`) survived every behavioural suite in the project. The two
// sets coincide for any pattern without an end anchor, which is nearly every
// pattern anyone writes, so finding an input that separates them is luck. The
// invariant separates them by construction.
func TestUnionScanMidAcceptPartition(t *testing.T) {
	shapes := []struct {
		name string
		pats []string
	}{
		{"classes", []string{`[a-z]{2}[0-9]{3}`, `[p-r]+`, `[^\n]*[0-2]`}},
		{"end-anchored", []string{`[a-z]+$`, `[0-9]\z`, `[a-c]+`}},
		{"nullable", []string{`[0-9]*`, `\A`, `[^\n]*[3-5]`}},
		{"begin-anchored", []string{`^[0-9]`, `[a-z]{3}`, `[q]+`}},
		{"mixed-anchors", []string{`^[a-z]+$`, `[0-9]{2}`, `\A[a-c]`}},
		// The two DEGENERATE limits, which are not variations of the general
		// case but SEPARATE emitted code: at 0 the bodies emit no mid-accept
		// arm at all, and at numStates they emit it with no guard, because the
		// compare could never be false. Each is one `if` in three emitters, and
		// a branch nothing exercises is a branch nobody has checked.
		{"limit-zero", []string{`[a-z]+\z`, `[0-9]{2}\z`}},
		{"limit-full", []string{`[0-9]*`, `[a-c]{2}`}},
		{"wide", nil}, // filled below: 96 patterns, the >64-id accept form
	}
	// The wide fixture needs END-ANCHORED members for the same reason the
	// narrow ones do: without them a state's mid-accept set and its
	// end-of-input set are identical, and a partition built from the wrong one
	// is indistinguishable. Every fourth pattern carries `\z`.
	wide := make([]string, 96)
	for i := range wide {
		wide[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%8, 1+i/8%8)
		if i%4 == 0 {
			wide[i] += `\z`
		}
	}
	shapes[len(shapes)-1].pats = wide

	// Which of the three emission cases each shape reached. Asserted at the end
	// rather than assumed: a fixture that stops reaching a case turns its
	// branch back into untested code silently.
	var sawZero, sawFull, sawGuarded bool

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			infos, ids, _, _ := setEmitCovInfos(t, sh.pats)
			spec := SetSpec{
				Name: "s", ScanAny: "s_scan_any", ScanAll: "s_scan_all",
				Patterns: infos, PatternIDs: ids,
				DeclaredPatternCount: len(infos), IDSpaceSize: len(infos),
			}
			u := buildUnionScanDFA(spec, 0, false)
			if u == nil {
				t.Skip("union automaton refused for this shape")
			}

			// midAccepts(newState) read back from the EMITTED tables, which is
			// what the bodies actually index — not from the dfa the partition
			// was computed on. That is the point: this compares the two.
			midAccepts := func(s int) bool {
				if u.isWide() {
					return binary.LittleEndian.Uint32(
						unionSegBytes(t, u, u.midReprOff)[s*4:]) != 0
				}
				return binary.LittleEndian.Uint64(
					unionSegBytes(t, u, u.acceptOff)[s*8:]) != 0
			}

			if u.midAcceptLimit < 0 || u.midAcceptLimit > u.numStates {
				t.Fatalf("midAcceptLimit %d out of range for %d states",
					u.midAcceptLimit, u.numStates)
			}
			switch {
			case u.midAcceptLimit == 0:
				sawZero = true
			case u.midAcceptLimit >= u.numStates:
				sawFull = true
			default:
				sawGuarded = true
			}
			t.Logf("%s: %d states, midAcceptLimit %d", sh.name, u.numStates, u.midAcceptLimit)
			for s := 0; s < u.numStates; s++ {
				want := s < u.midAcceptLimit
				if got := midAccepts(s); got != want {
					t.Fatalf("state %d: mid-accepting = %v, but the partition says %v "+
						"(midAcceptLimit = %d, states = %d). Every body tests "+
						"`state < midAcceptLimit` INSTEAD of loading the accept "+
						"entry, so a state on the wrong side is a silently wrong answer.",
						s, got, want, u.midAcceptLimit, u.numStates)
				}
			}

			// The start states are indices into the same partitioned space, so a
			// permutation that forgot them points at another state's row.
			for _, st := range []struct {
				name string
				id   int
			}{{"startState", u.startState}, {"midStartState", u.midStartState}} {
				if st.id < 0 || st.id >= u.numStates {
					t.Fatalf("%s = %d is outside 0..%d", st.name, st.id, u.numStates-1)
				}
			}
		})
	}

	if !sawZero || !sawFull || !sawGuarded {
		t.Errorf("the fixtures no longer cover all three emission cases "+
			"(limit==0: %v, limit==numStates: %v, guarded: %v). Each is separate "+
			"emitted code in three bodies, so an uncovered one is a branch nobody "+
			"has checked.", sawZero, sawFull, sawGuarded)
	}
}

// unionSegBytes returns the payload of the emitted data segment that starts at
// `off`, so a test can read a table exactly as the WASM body will.
func unionSegBytes(t *testing.T, u *unionScanDFA, off int32) []byte {
	t.Helper()
	for _, s := range parseDataSegments(u.dataBytes) {
		if s.offset == off {
			return s.data
		}
	}
	t.Fatalf("no data segment at offset %d", off)
	return nil
}

// TestCacheEmittersWithoutWalkEnd: a context carrying no walk-extent global emits
// nothing for the seed and the charge, and the past-end check differs between
// the i32 `find` return and the batch entry's i64 cursor.
func TestCacheEmittersWithoutWalkEnd(t *testing.T) {
	none := overlapCacheCtx{walkEndGlobal: -1}
	if got := none.emitSeedWalkEnd([]byte{0xAA}, 3); !bytes.Equal(got, []byte{0xAA}) {
		t.Errorf("seed without a global emitted %x", got)
	}
	if got := none.emitChargeWalkExtent([]byte{0xAA}, 3, 4); !bytes.Equal(got, []byte{0xAA}) {
		t.Errorf("charge without a global emitted %x", got)
	}
	with := overlapCacheCtx{walkEndGlobal: 2}
	if got := with.emitSeedWalkEnd(nil, 3); len(got) == 0 {
		t.Error("seed with a global emitted nothing")
	}
	i32 := overlapCacheCtx{pInLen: 1}.emitPastEndCheck(nil, 2)
	i64 := overlapCacheCtx{pInLen: 1, i64Ret: true}.emitPastEndCheck(nil, 2)
	if bytes.Equal(i32, i64) {
		t.Error("the past-end check must answer differently for find (0) and the batch entry (the done cursor)")
	}
}
