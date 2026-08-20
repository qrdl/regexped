package compile

import (
	"regexp/syntax"
	"strings"
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

// TestSelectEngineNonCapturePaths exercises selectBestEngine branches that only fire
// for non-capture patterns and are not covered by the existing capture-group tests.
func TestSelectEngineNonCapturePaths(t *testing.T) {
	// Non-capture user alternation → sets LeftmostFirst=true.
	t.Run("user_alternation", func(t *testing.T) {
		got, err := SelectEngine("a|b", CompileOptions{})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got == EngineBacktrack || got == EngineTDFA {
			t.Errorf("SelectEngine(%q) = %v, want DFA or CompiledDFA (no captures)", "a|b", got)
		}
	})
	// Anchor + word boundary → both hasAnchor and hasWordBoundary set → early break in detection loop.
	t.Run("anchor_and_word_boundary", func(t *testing.T) {
		got, err := SelectEngine(`^\bfoo`, CompileOptions{})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got == EngineBacktrack || got == EngineTDFA {
			t.Errorf("SelectEngine(%q) = %v, want DFA or CompiledDFA (no captures)", `^\bfoo`, got)
		}
	})
	// Mixed ASCII+non-ASCII char class → HasUnicode=true in analysePattern → complexity="Unicode".
	// [a-é] has hasASCII=true so needsUnicodeSupport returns false, but the last rune (0xe9) > 127
	// sets analysis.HasUnicode=true.
	t.Run("unicode", func(t *testing.T) {
		got, err := SelectEngine("[a-é]+", CompileOptions{})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got == EngineBacktrack || got == EngineTDFA {
			t.Errorf("SelectEngine(%q) = %v, want DFA or CompiledDFA (no captures)", "[a-é]+", got)
		}
	})
	// Long pattern: EstimatedDFAStates > 100, no Unicode, no alternations → complexity="Complex".
	t.Run("complex_dfa_estimate", func(t *testing.T) {
		got, err := SelectEngine("a{101}", CompileOptions{})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got == EngineBacktrack || got == EngineTDFA {
			t.Errorf("SelectEngine(%q) = %v, want DFA or CompiledDFA (no captures)", "a{101}", got)
		}
	})
}

// TestIsAlternationDeterministicPaths exercises specific branches in
// isAlternationDeterministic, isEpsilonAccept, and getFirstRuneSet that are called
// when hasAmbiguousCaptures evaluates whether captures need the BT engine.
func TestIsAlternationDeterministicPaths(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
		note    string
	}{
		// Each branch in its own capture prevents prefix factoring, so both start with 'c'
		// and getFirstRuneSet returns overlapping sets → not deterministic → BT.
		{"((cat)|(car))", EngineBacktrack, "overlapping first rune"},
		// Left branch is empty capture (epsilon), right is rune 'a' → disjoint → TDFA-eligible.
		{"(()|a)", EngineTDFA, "one epsilon branch"},
		// Both branches epsilon-accepting: () and (a?) both reach Match without consuming
		// a byte → ambiguous → BT.
		{"(()|(?:a?))", EngineBacktrack, "both epsilon branches"},
		// Large char class >256 chars in left branch → getFirstRuneSet returns empty set
		// → treated as undetermined → not deterministic → BT.
		{"(([\x00-Ā])|(b))", EngineBacktrack, "large char class first rune set"},
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, CompileOptions{})
		if err != nil {
			t.Errorf("SelectEngine(%q) [%s]: %v", c.pattern, c.note, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectEngine(%q) [%s] = %v, want %v", c.pattern, c.note, got, c.want)
		}
	}
}

// TestIsAlternationDeterministicQuantifierLoop exercises the quantifierLoop=true
// branch added by task 13 (commit c9436b8): a quantifier-loop InstAlt whose
// continuation and exit first-byte sets overlap is now TDFA-eligible (the
// overlap alone no longer forces Backtracking, since TDFA's LeftmostFirst
// priority always prefers the loop body over the exit regardless of overlap).
// This branch had 0 direct test coverage — the pre-task-13 exclusion this
// replaced was itself only ever exercised via re2test, not `go test`.
func TestIsAlternationDeterministicQuantifierLoop(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
		note    string
	}{
		// ([a-z]+)(er)([a-z]+): the first loop's continuation ([a-z]) and its
		// own exit (into "er", which starts with 'e' — itself in [a-z]) overlap.
		// Pre-task-13 this was forced to Backtracking; the fix's own example.
		{`([a-z]+)(er)([a-z]+)`, EngineTDFA, "overlapping-terminator loop now TDFA-eligible"},
		// (cat|car)+: a genuine user alternation NESTED INSIDE a quantifier
		// loop is still a separate InstAlt, checked in full (non-quantifier
		// path) — must remain unaffected by the quantifier-loop relaxation.
		{`(cat|car)+`, EngineTDFA, "nested user alternation inside a loop, no captures inside it"},
		// Gap I (CLAUDE.md "Load-bearing engine-selection gates"): an inverted
		// class wider than 256 codepoints inside a quantifier loop still has an
		// INDETERMINATE (empty) first-rune-set for getFirstRuneSet, so it must
		// remain ambiguous → Backtracking, even though it's a quantifier loop.
		// This must NOT be relaxed — see CLAUDE.md's explicit warning.
		{`<([^>]+)>`, EngineBacktrack, "Gap I: indeterminate branch inside quantifier loop stays ambiguous"},
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, CompileOptions{})
		if err != nil {
			t.Errorf("SelectEngine(%q) [%s]: %v", c.pattern, c.note, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectEngine(%q) [%s] = %v, want %v", c.pattern, c.note, got, c.want)
		}
	}
}

// TestSelectEngineLineAnchorCapture verifies that capture patterns with line anchors
// or word boundaries are routed to Backtrack (not TDFA).
func TestSelectEngineLineAnchorCapture(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
	}{
		{"(?m:^(foo)$)", EngineBacktrack}, // multiline begin/end-line + capture
		{"^(foo)$", EngineBacktrack},      // EmptyEndText counts as line anchor
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

	// Synthetic InstRune with odd-length Rune slice → returns empty.
	t.Run("odd rune len", func(t *testing.T) {
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstRune, Rune: []rune{'a'}}, // odd length
				{Op: syntax.InstMatch},
			},
			Start: 0,
		}
		got := getFirstRuneSet(prog, 0)
		if len(got) != 0 {
			t.Errorf("getFirstRuneSet(odd len) = %v, want empty", got)
		}
	})

	// InstRune with totalChars > 256 → returns empty (covers selector.go:557).
	t.Run("rune range too wide", func(t *testing.T) {
		// One range spanning > 256 runes.
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstRune, Rune: []rune{0x100, 0x300}},
				{Op: syntax.InstMatch},
			},
			Start: 0,
		}
		got := getFirstRuneSet(prog, 0)
		if len(got) != 0 {
			t.Errorf("getFirstRuneSet(wide range) = %v, want empty", got)
		}
	})

	// InstMatch directly → collect returns false → empty.
	t.Run("direct match inst", func(t *testing.T) {
		prog := &syntax.Prog{
			Inst:  []syntax.Inst{{Op: syntax.InstMatch}},
			Start: 0,
		}
		got := getFirstRuneSet(prog, 0)
		if len(got) != 0 {
			t.Errorf("getFirstRuneSet(InstMatch) = %v, want empty", got)
		}
	})

	// InstNop chain to InstRune1 → succeeds (covers InstNop branch).
	t.Run("nop chain", func(t *testing.T) {
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstNop, Out: 1},
				{Op: syntax.InstRune1, Rune: []rune{'z'}, Out: 2},
				{Op: syntax.InstMatch},
			},
			Start: 0,
		}
		got := getFirstRuneSet(prog, 0)
		if !got['z'] || len(got) != 1 {
			t.Errorf("getFirstRuneSet(nop→z) = %v, want {z}", got)
		}
	})
}

func TestSelectEngine_HighAlternations(t *testing.T) {
	// 12 alternations: hits both the "High alternations" branch (>5) and the
	// estimateDFAComplexity multiplier cap (1 + n*0.2 > 3.0 → n > 10).
	got, err := SelectEngine("a|b|c|d|e|f|g|h|i|j|k|l", CompileOptions{})
	if err != nil {
		t.Fatalf("SelectEngine: %v", err)
	}
	if got != EngineDFA && got != EngineCompiledDFA {
		t.Errorf("SelectEngine(many alts) = %v, want DFA/CompiledDFA", got)
	}
}

func TestSelectEngine_ParseError(t *testing.T) {
	if _, err := SelectEngine("[invalid", CompileOptions{}); err == nil {
		t.Error("SelectEngine(invalid): expected parse error, got nil")
	}
}

func TestSelectEngine_UnicodeWithoutOpt(t *testing.T) {
	// \p{Greek} compiles to a non-ASCII-only InstRune → needsUnicode=true.
	_, err := SelectEngine(`\p{Greek}`, CompileOptions{})
	if err == nil || !strings.Contains(err.Error(), "Unicode") {
		t.Errorf("SelectEngine(\\p{Greek}): want Unicode error, got %v", err)
	}
}

func TestSelectEngine_UnicodeWithOpt(t *testing.T) {
	if _, err := SelectEngine(`\p{Greek}`, CompileOptions{Unicode: true}); err != nil {
		t.Errorf("SelectEngine(\\p{Greek}, Unicode=true): unexpected error %v", err)
	}
}

// TestSelectBestEngineWithTDFA_TableReuse pins plans/OPUS.md §N8b's contract:
// the selector hands back the TDFA table it had to build to answer the
// eligibility question, and it does so exactly when it answers EngineTDFA.
// compilePattern reuses that table instead of rebuilding it; a nil return on a
// TDFA answer (or a non-nil return on any other answer) would silently
// reintroduce the double build, or worse, hand a rejected table to the emitter.
func TestSelectBestEngineWithTDFA_TableReuse(t *testing.T) {
	cases := []struct {
		pattern  string
		wantTDFA bool
		why      string
	}{
		{`([0-9]{4})-([0-9]{2})-([0-9]{2})`, true, "plain greedy captures"},
		{`(?P<scheme>https?)://(?P<host>[^/:?#]+)`, true, "named captures"},
		{`(a*)(a*)b`, true, "adjacent greedy stars are still TDFA-eligible"},
		{`^([^,]*),([^,]*)$`, false, "line anchors excluded from TDFA"},
		{`\b(\w+)@(\w+)\b`, false, "word boundary excluded from TDFA"},
		{`<(.+?)>`, false, "non-greedy excluded from TDFA"},
		{`([^,]+),`, false, "inverted-class ambiguity → Backtracking (CLAUDE.md Gap I)"},
		{`[a-z]+`, false, "no captures at all — DFA path"},
	}
	for _, c := range cases {
		parsed, err := syntax.Parse(c.pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", c.pattern, err)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", c.pattern, err)
		}
		opts := CompileOptions{}
		engine, tt := selectBestEngineWithTDFA(prog, &opts)
		if c.wantTDFA {
			if engine != EngineTDFA {
				t.Errorf("%q (%s): engine = %v, want EngineTDFA", c.pattern, c.why, engine)
				continue
			}
			if tt == nil {
				t.Errorf("%q (%s): engine is TDFA but table is nil — compilePattern would rebuild it", c.pattern, c.why)
			}
		} else {
			if engine == EngineTDFA {
				t.Errorf("%q (%s): engine = EngineTDFA, want anything else", c.pattern, c.why)
				continue
			}
			if tt != nil {
				t.Errorf("%q (%s): non-TDFA engine %v returned a non-nil table; only an accepted table may be handed back", c.pattern, c.why, engine)
			}
		}
	}
}

// TestSelectBestEngineWithTDFA_MatchesWrapper guards the thin wrapper: the
// one-value selectBestEngine must keep answering exactly what the two-value
// form does, since ~5 call sites still use it.
func TestSelectBestEngineWithTDFA_MatchesWrapper(t *testing.T) {
	for _, pat := range []string{
		`([0-9]{4})-([0-9]{2})`, `^([^,]*),([^,]*)$`, `\b(\w+)\b`, `[a-z]+`,
		`foo|bar`, `(?:a{3,4}){0,}`, `<(.+?)>`,
	} {
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		o1, o2 := CompileOptions{}, CompileOptions{}
		want := selectBestEngine(prog, &o1)
		got, _ := selectBestEngineWithTDFA(prog, &o2)
		if got != want {
			t.Errorf("%q: wrapper = %v, direct = %v", pat, want, got)
		}
		if o1.LeftmostFirst != o2.LeftmostFirst {
			t.Errorf("%q: wrapper left LeftmostFirst=%v, direct left %v", pat, o1.LeftmostFirst, o2.LeftmostFirst)
		}
	}
}
