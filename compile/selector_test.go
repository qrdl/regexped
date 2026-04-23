package compile

import (
	"regexp/syntax"
	"testing"
)

func TestResolveMaxDFAStates(t *testing.T) {
	cases := []struct {
		opts *CompileOptions
		want int
	}{
		{nil, 1024},
		{&CompileOptions{}, 1024},
		{&CompileOptions{MaxDFAStates: 512}, 512},
		{&CompileOptions{MaxDFAStates: -1}, 0},
	}
	for _, c := range cases {
		if got := resolveMaxDFAStates(c.opts); got != c.want {
			t.Errorf("resolveMaxDFAStates(%v) = %d, want %d", c.opts, got, c.want)
		}
	}
}

func TestResolveMaxTDFARegs(t *testing.T) {
	cases := []struct {
		opts *CompileOptions
		want int
	}{
		{nil, 32},
		{&CompileOptions{}, 32},
		{&CompileOptions{MaxTDFARegs: 16}, 16},
		{&CompileOptions{MaxTDFARegs: -1}, 0},
	}
	for _, c := range cases {
		if got := resolveMaxTDFARegs(c.opts); got != c.want {
			t.Errorf("resolveMaxTDFARegs(%v) = %d, want %d", c.opts, got, c.want)
		}
	}
}

func TestResolveCompiledDFAThreshold(t *testing.T) {
	cases := []struct {
		opts *CompileOptions
		want int
	}{
		{nil, 256},
		{&CompileOptions{}, 256},
		{&CompileOptions{CompiledDFAThreshold: 128}, 128},
		{&CompileOptions{CompiledDFAThreshold: 512}, 256}, // clamped
		{&CompileOptions{CompiledDFAThreshold: -1}, 0},
	}
	for _, c := range cases {
		if got := resolveCompiledDFAThreshold(c.opts); got != c.want {
			t.Errorf("resolveCompiledDFAThreshold(%v) = %d, want %d", c.opts, got, c.want)
		}
	}
}

func TestMaybeCompiledDFA(t *testing.T) {
	threshold := &CompileOptions{CompiledDFAThreshold: 10}
	cases := []struct {
		engine EngineType
		states int
		opts   *CompileOptions
		want   EngineType
	}{
		{EngineDFA, 5, threshold, EngineCompiledDFA},
		{EngineDFA, 9, threshold, EngineCompiledDFA}, // 9+1=10 <= 10
		{EngineDFA, 10, threshold, EngineDFA},        // 10+1=11 > 10
		{EngineBacktrack, 5, threshold, EngineBacktrack},
		{EngineTDFA, 5, threshold, EngineTDFA},
		{EngineDFA, 5, nil, EngineCompiledDFA}, // default threshold=256
	}
	for _, c := range cases {
		if got := maybeCompiledDFA(c.engine, c.states, c.opts); got != c.want {
			t.Errorf("maybeCompiledDFA(%v, %d) = %v, want %v", c.engine, c.states, got, c.want)
		}
	}
}

func TestSelectEngine(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
	}{
		// Simple literal: should be Compiled DFA (small DFA).
		{"foo", EngineCompiledDFA},
		// Pattern with capture groups eligible for TDFA.
		{"(foo)+", EngineTDFA},
		// (a|ab) is TDFA-eligible by the selector.
		{"(a|ab)", EngineTDFA},
		// Non-greedy quantifier in capture: Backtracking.
		{"(a+?)", EngineBacktrack},
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, CompileOptions{})
		if err != nil {
			t.Errorf("SelectEngine(%q): error %v", c.pattern, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectEngine(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestResolveMaxDFAMemory(t *testing.T) {
	cases := []struct {
		opts *CompileOptions
		want int
	}{
		{nil, 0},
		{&CompileOptions{}, 0},
		{&CompileOptions{MaxDFAMemory: 1024}, 1024},
	}
	for _, c := range cases {
		if got := resolveMaxDFAMemory(c.opts); got != c.want {
			t.Errorf("resolveMaxDFAMemory(%v) = %d, want %d", c.opts, got, c.want)
		}
	}
}

func TestResolveMemoBudget(t *testing.T) {
	cases := []struct {
		opts *CompileOptions
		want int
	}{
		{nil, 128 * 1024},
		{&CompileOptions{}, 128 * 1024},
		{&CompileOptions{MemoBudget: 65536}, 65536},
	}
	for _, c := range cases {
		if got := resolveMemoBudget(c.opts); got != c.want {
			t.Errorf("resolveMemoBudget(%v) = %d, want %d", c.opts, got, c.want)
		}
	}
}

func TestPrintAnalysis(t *testing.T) {
	a := &patternAnalysis{
		NumInstructions:         42,
		NumCaptures:             3,
		NumAlternations:         2,
		HasLargeCharClass:       true,
		HasUnicode:              false,
		HasAnyRune:              true,
		EstimatedDFAStates:      100,
		EstimatedDFATransitions: 25600,
		DFAMemoryEstimateKB:     25,
	}
	printAnalysis(a) // must not panic
}

// TestSelectEngineLineAnchorCapture verifies that capture patterns with line anchors
// or word boundaries are routed to Backtrack (not TDFA).
func TestSelectEngineLineAnchorCapture(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
	}{
		{"(?m:^(foo)$)", EngineBacktrack}, // multiline begin/end-line + capture
		{"^(foo)$", EngineBacktrack},       // EmptyEndText counts as line anchor
		{`(\bfoo\b)`, EngineBacktrack},    // word boundary + capture
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, CompileOptions{})
		if err != nil {
			t.Errorf("SelectEngine(%q): %v", c.pattern, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectEngine(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestGetFirstRuneSet(t *testing.T) {
	compile := func(pattern string) *syntax.Prog {
		t.Helper()
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		return prog
	}

	t.Run("single rune", func(t *testing.T) {
		prog := compile("a")
		got := getFirstRuneSet(prog, prog.Start)
		if !got['a'] || len(got) != 1 {
			t.Errorf("getFirstRuneSet(a) = %v, want {a}", got)
		}
	})

	t.Run("alternation", func(t *testing.T) {
		prog := compile("a|b")
		got := getFirstRuneSet(prog, prog.Start)
		if !got['a'] || !got['b'] {
			t.Errorf("getFirstRuneSet(a|b) = %v, want {a,b}", got)
		}
	})

	t.Run("char class", func(t *testing.T) {
		prog := compile("[abc]")
		got := getFirstRuneSet(prog, prog.Start)
		if !got['a'] || !got['b'] || !got['c'] {
			t.Errorf("getFirstRuneSet([abc]) = %v, want {a,b,c}", got)
		}
	})

	t.Run("any rune returns empty", func(t *testing.T) {
		prog := compile(".")
		got := getFirstRuneSet(prog, prog.Start)
		if len(got) != 0 {
			t.Errorf("getFirstRuneSet(.) = %v, want empty (wildcard)", got)
		}
	})

	t.Run("out of bounds pc returns empty", func(t *testing.T) {
		prog := compile("a")
		got := getFirstRuneSet(prog, len(prog.Inst)+99)
		if len(got) != 0 {
			t.Errorf("getFirstRuneSet(out-of-bounds) = %v, want empty", got)
		}
	})
}
