package compile

import (
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
