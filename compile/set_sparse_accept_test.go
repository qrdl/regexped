package compile

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// G17 foundation: one merged DFA over MORE than 64 patterns, with
// per-state accept LISTS instead of a u64 bitmask.
//
// The bitmask caps a bucket at 64 (32 in practice, since every mask on the
// per-candidate path is an i32), so 128 patterns sharing one literal split into
// four buckets and cost four suffix-DFA calls at every candidate position —
// measured at 3.33x one bucket's work on a literal-dense input.
func sparseTestASTs(t *testing.T, n int) ([]*syntax.Regexp, []string) {
	t.Helper()
	asts := make([]*syntax.Regexp, n)
	pats := make([]string, n)
	for i := 0; i < n; i++ {
		// Distinct, non-literal suffixes: the shape a shared-literal bucket
		// actually holds once the literal is stripped.
		pats[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		re, err := syntax.Parse(pats[i], syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pats[i], err)
		}
		asts[i] = re
	}
	return asts, pats
}

// TestSparseSetMergeExceeds64 is the ceiling this exists to lift: the bitmask
// merge refuses, the sparse merge does not.
func TestSparseSetMergeExceeds64(t *testing.T) {
	asts, _ := sparseTestASTs(t, 128)
	opts := CompileSetOptions{}

	if _, _, err := mergeSuffixDFA(asts, opts); err == nil {
		t.Fatal("mergeSuffixDFA accepted 128 patterns; the 32-pattern bitmask cap is the premise of G17")
	}

	tab, d, err := mergeSuffixDFASparseSet(asts, opts)
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if tab == nil || d == nil {
		t.Fatal("sparse merge returned no table or no dfa")
	}
	if d.midAcceptWide == nil {
		t.Fatal("sparse merge produced no wide accept lists")
	}
	// The construction budgets, re-asserted here so a future change that
	// blows them fails loudly rather than silently splitting the bucket again.
	if tab.numStates > opts.budgetStates() || dfaTableBytes(tab) > opts.budgetBytes() {
		t.Errorf("merged 128-pattern DFA is over budget: %d states / %d bytes "+
			"(budgets %d / %d) — the bucket would split anyway and sparse accept buys nothing",
			tab.numStates, dfaTableBytes(tab), opts.budgetStates(), opts.budgetBytes())
	}
	t.Logf("128 patterns merged: %d states, %d bytes, %d states carry accept lists",
		tab.numStates, dfaTableBytes(tab), len(d.midAcceptWide))
}

// TestSparseSetAcceptListsAreCorrect is the substance: every accept list must
// name exactly the patterns Go says match, for inputs that reach that state.
// Checked against Go rather than against the bitmask path, so a shared
// misunderstanding cannot pass.
func TestSparseSetAcceptListsAreCorrect(t *testing.T) {
	asts, pats := sparseTestASTs(t, 128)
	_, d, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("sparse merge: %v", err)
	}
	res := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		res[i] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	// Walk the DFA over inputs and compare the accept list at the landing state
	// with the patterns Go says match the whole input.
	inputs := []string{"a1", "ab12", "abc123", "z9", "abcdefgh1234567890",
		"qq77", "a", "", "abcdefghi1", "aa11", "zzz999"}
	for _, in := range inputs {
		st := d.start
		ok := true
		for i := 0; i < len(in); i++ {
			next := d.transitions[st*256+int(in[i])]
			if next < 0 {
				ok = false
				break
			}
			st = next
		}
		var want []int
		for i, re := range res {
			if re.MatchString(in) {
				want = append(want, i)
			}
		}
		if !ok {
			if len(want) != 0 {
				t.Errorf("input %q: DFA died but Go says patterns %v match", in, want)
			}
			continue
		}
		got := map[int]bool{}
		for _, id := range d.acceptWide[st] {
			got[int(id)] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("input %q: pattern %d (%q) matches per Go but is missing from the accept list %v",
					in, w, pats[w], d.acceptWide[st])
			}
		}
		if len(got) != len(want) {
			t.Errorf("input %q: accept list has %d ids, Go says %d match (%v)",
				in, len(got), len(want), want)
		}
	}
}

// TestSparseSetLeavesBitmaskPathAlone guards the additive claim: with no
// pattern index supplied, construction is unchanged. `make byteident` covers
// the emitted bytes; this covers the accept maps directly.
func TestSparseSetLeavesBitmaskPathAlone(t *testing.T) {
	asts, _ := sparseTestASTs(t, 8)
	tab, _, err := mergeSuffixDFA(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("bitmask merge: %v", err)
	}
	prog, err := syntax.Compile(asts[0].Simplify())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := newDFA(prog, false, true, maxHelperDFAStates)
	if !ok {
		t.Fatal("newDFA failed")
	}
	if d.acceptWide != nil || d.midAcceptWide != nil || d.immAcceptWide != nil {
		t.Error("newDFA populated wide accept maps; they must stay nil off the sparse path")
	}
	if tab == nil {
		t.Error("bitmask merge returned no table")
	}
}

// TestSparseSetTableAcceptListsAreCorrect is the one that matters for the
// emitter: it walks the EMITTED TABLE — post-Hopcroft, post-BFS-relabel,
// post-accept-first-reorder — and checks the accept list at the landing state
// against Go.
//
// The pre-minimisation check above passed even when the table was unusable,
// because it walked the dfa the lists were built on. Two things had to be true
// for this one to pass: the lists must be carried through every remap, and
// minimisation must PARTITION on them — on this path the u64 signature is bit 0
// for every accepting state, so without that it merged states whose accept
// lists differed. The symptom was a 25-state table where 137 is correct.
func TestSparseSetTableAcceptListsAreCorrect(t *testing.T) {
	asts, pats := sparseTestASTs(t, 128)
	tab, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("sparse merge: %v", err)
	}
	if tab.acceptWide == nil {
		t.Fatal("emitted table carries no wide accept lists")
	}
	if len(tab.acceptWide) > tab.numStates {
		t.Fatalf("%d accept entries against %d states: lists are not keyed by table ids",
			len(tab.acceptWide), tab.numStates)
	}
	res := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		res[i] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	// Exercise every pattern's own shape plus shared prefixes and near-misses.
	var inputs []string
	for i := 0; i < len(pats); i += 7 {
		inputs = append(inputs, strings.Repeat("q", 1+i/16)+strings.Repeat("7", 1+i%16))
	}
	inputs = append(inputs, "", "q", "7", "q7", "qqq777", "qqqqqqqqq1234567890123")
	for _, in := range inputs {
		st := tab.startState
		ok := true
		for i := 0; i < len(in); i++ {
			next := tab.transitions[st*256+int(in[i])]
			if next < 0 {
				ok = false
				break
			}
			st = next
		}
		var want []int
		for i, re := range res {
			if re.MatchString(in) {
				want = append(want, i)
			}
		}
		if !ok {
			if len(want) != 0 {
				t.Errorf("input %q: table died but Go says %v match", in, want)
			}
			continue
		}
		got := map[int]bool{}
		for _, id := range tab.acceptWide[st] {
			got[int(id)] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("input %q: pattern %d (%q) matches per Go but is missing from the table's accept list %v",
					in, w, pats[w], tab.acceptWide[st])
			}
		}
		if len(got) != len(want) {
			t.Errorf("input %q: table accept list has %d ids, Go says %d (%v)",
				in, len(got), len(want), want)
		}
	}
	t.Logf("table: %d states, %d bytes, %d carry accept lists", tab.numStates,
		dfaTableBytes(tab), len(tab.acceptWide))
}
