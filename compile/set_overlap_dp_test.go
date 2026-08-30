package compile

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"testing"
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
