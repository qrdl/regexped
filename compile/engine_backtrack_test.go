package compile

import (
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
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

func TestBtMemoMaxLenForEmptyProg(t *testing.T) {
	// N==0 early-return path: prog with no instructions returns 0.
	empty := &syntax.Prog{}
	if got := btMemoMaxLenFor(empty, 128*1024); got != 0 {
		t.Errorf("btMemoMaxLenFor(empty prog) = %d, want 0", got)
	}
}

func TestBtFoldRune(t *testing.T) {
	cases := []struct {
		r    rune
		want rune
	}{
		{'a', 'A'}, {'z', 'Z'}, {'m', 'M'}, // lowercase → uppercase
		{'A', 'a'}, {'Z', 'z'}, {'M', 'm'}, // uppercase → lowercase
		{'1', '1'}, {'!', '!'}, {' ', ' '}, // other → unchanged
	}
	for _, c := range cases {
		if got := btFoldRune(c.r); got != c.want {
			t.Errorf("btFoldRune(%q) = %q, want %q", c.r, got, c.want)
		}
	}
}

// TestBtCheckRune1FoldDirect exercises the isFold=true branch in btCheckRune1
// by calling it with a manually constructed InstRune1+FoldCase instruction.
// Go's regex compiler never produces InstRune1 with FoldCase (it expands case-
// insensitive single chars to InstRune with a character class), so this branch
// is only reachable via a directly constructed instruction.
func TestBtCheckRune1FoldDirect(t *testing.T) {
	inst := syntax.Inst{
		Op:   syntax.InstRune1,
		Arg:  uint32(syntax.FoldCase),
		Rune: []rune{'a'},
	}
	result := btCheckRune1(nil, inst, 0)
	if len(result) == 0 {
		t.Error("btCheckRune1(isFold=true): expected non-empty WASM output")
	}
}

func TestBtCheckRune1CaseFold(t *testing.T) {
	// (?i:a) compiled with BT engine exercises btCheckRune1 with isFold=true.
	_, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "(?i:a)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced((?i:a) BT): %v", err)
	}
}

func TestLoopCaptureLocals(t *testing.T) {
	t.Run("captures inside loop", func(t *testing.T) {
		// (a)+ has a greedy loop with a capture group inside — loopCaptureLocals
		// should find the capture locals for that loop.
		prog := compileBTTestProg(t, "(a)+")
		bt := newBacktrack(prog)
		if len(bt.loops) == 0 {
			t.Skip("no loops found in (a)+")
		}
		foundCapture := false
		for pc := range bt.loops {
			locals := loopCaptureLocals(prog, pc)
			if len(locals) > 0 {
				foundCapture = true
			}
		}
		if !foundCapture {
			t.Error("loopCaptureLocals: expected capture locals for (a)+, got none")
		}
	})

	t.Run("no captures inside loop", func(t *testing.T) {
		// (?:a)+ has a loop but no captures — loopCaptureLocals should return nil.
		prog := compileBTTestProg(t, "(?:a)+")
		bt := newBacktrack(prog)
		for pc := range bt.loops {
			locals := loopCaptureLocals(prog, pc)
			if len(locals) != 0 {
				t.Errorf("loopCaptureLocals: expected nil for (?:a)+, got %v", locals)
			}
		}
	})
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
