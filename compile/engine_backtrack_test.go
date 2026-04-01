package compile

import (
	"regexp/syntax"
	"testing"
)

func compileBTTestProg(t *testing.T, pattern string) *syntax.Prog {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	return prog
}

func TestNeedsBitState(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
		note    string
	}{
		{"a*", false, ""},
		{"a+", false, ""},
		{"a+?", false, ""},
		// (?:a?)* is the canonical "catastrophic backtracking" pattern, yet it
		// does NOT need BitState.  The outer loop is greedy, so its InstAlt has
		// Out < PC (body) and Arg > PC (exit).  The zero-progress guard in the
		// emitted WASM takes the exit branch whenever pos == loop_pos_local,
		// preventing infinite re-entry without consuming BitState bits.
		{"(?:a?)*", false, "greedy outer loop — zero-progress guard is sufficient"},
		{"(?:a?)*?", true, ""},
	}
	for _, c := range cases {
		prog := compileBTTestProg(t, c.pattern)
		if got := needsBitState(prog); got != c.want {
			t.Errorf("needsBitState(%q) = %v, want %v (%s)", c.pattern, got, c.want, c.note)
		}
	}
}

func TestNfaFirstBytes(t *testing.T) {
	cases := []struct {
		pattern      string
		wantAllBytes bool
		wantFirst    []byte
	}{
		{"abc", false, []byte{'a'}},
		{"[abc]", false, []byte{'a', 'b', 'c'}},
		{"(?s).", true, nil},
		{"cat|dog", false, []byte{'c', 'd'}},
	}
	for _, c := range cases {
		prog := compileBTTestProg(t, c.pattern)
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes != c.wantAllBytes {
			t.Errorf("nfaFirstBytes(%q).allBytes = %v, want %v", c.pattern, allBytes, c.wantAllBytes)
			continue
		}
		if c.wantAllBytes {
			continue
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range c.wantFirst {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes(%q): missing byte %q in first set", c.pattern, b)
			}
		}
	}
}

func TestBtMemoMaxLenFor(t *testing.T) {
	prog := compileBTTestProg(t, "(?:a?)*")
	budget := 128 * 1024
	maxLen := btMemoMaxLenFor(prog, budget)
	if maxLen <= 0 {
		t.Errorf("btMemoMaxLenFor: got %d, want > 0", maxLen)
	}
	N := len(prog.Inst)
	expected := budget*8/N - 1
	if maxLen != expected {
		t.Errorf("btMemoMaxLenFor: got %d, want %d", maxLen, expected)
	}
}

func TestBtAllocSizes(t *testing.T) {
	prog := compileBTTestProg(t, "(a)(b)(c)")
	bt := newBacktrack(prog)
	stackSize, memoSize := btAllocSizes(bt, false, 0, 128*1024)
	if stackSize <= 0 {
		t.Errorf("btAllocSizes: stackSize = %d, want > 0", stackSize)
	}
	if memoSize != 0 {
		t.Errorf("btAllocSizes(useMemo=false): memoSize = %d, want 0", memoSize)
	}
	_, memoSize2 := btAllocSizes(bt, true, 0, 128*1024)
	if memoSize2 != 128*1024 {
		t.Errorf("btAllocSizes(useMemo=true): memoSize = %d, want 131072", memoSize2)
	}
}
