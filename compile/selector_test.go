package compile

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
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
	// Compiled in BYTE MODE since 2026-09-01: the default mode now rejects a
	// rune the pattern wrote above 127 (é is 0xE9), which is the silent
	// leak this test used to depend on. Byte mode keeps the pattern legal —
	// é means the single byte 0xE9 — so analysis.HasUnicode is still set and
	// the selector path under test is unchanged.
	t.Run("unicode", func(t *testing.T) {
		got, err := SelectEngine("[a-é]+", CompileOptions{ByteMode: true})
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
		opts    CompileOptions
	}{
		// Each branch in its own capture prevents prefix factoring, so both start with 'c'
		// and getFirstRuneSet returns overlapping sets → not deterministic → BT.
		{"((cat)|(car))", EngineBacktrack, "overlapping first rune", CompileOptions{}},
		// Left branch is empty capture (epsilon), right is rune 'a' → disjoint → TDFA-eligible.
		{"(()|a)", EngineTDFA, "one epsilon branch", CompileOptions{}},
		// Both branches epsilon-accepting: () and (a?) both reach Match without consuming
		// a byte → ambiguous → BT.
		{"(()|(?:a?))", EngineBacktrack, "both epsilon branches", CompileOptions{}},
		// Large char class >256 chars in left branch → getFirstRuneSet returns empty set
		// → treated as undetermined → not deterministic → BT.
		//
		// Ā is U+0100, so no mode can represent it and byte_mode would not
		// help — the class has to be >256 codepoints for getFirstRuneSet to
		// give up, which is the whole point of the case. `Unicode: true` is
		// the compile-anyway bypass, used here to reach the SELECTOR with a
		// pattern the gate would otherwise refuse.
		{"(([\x00-Ā])|(b))", EngineBacktrack, "large char class first rune set",
			CompileOptions{Unicode: true}},
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, c.opts)
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
// branch added in commit c9436b8: a quantifier-loop InstAlt whose
// continuation and exit first-byte sets overlap is now TDFA-eligible (the
// overlap alone no longer forces Backtracking, since TDFA's LeftmostFirst
// priority always prefers the loop body over the exit regardless of overlap).
// This branch had 0 direct test coverage — the earlier exclusion this
// replaced was itself only ever exercised via re2test, not `go test`.
func TestIsAlternationDeterministicQuantifierLoop(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
		note    string
	}{
		// ([a-z]+)(er)([a-z]+): the first loop's continuation ([a-z]) and its
		// own exit (into "er", which starts with 'e' — itself in [a-z]) overlap.
		// This used to be forced to Backtracking; the fix's own example.
		{`([a-z]+)(er)([a-z]+)`, EngineTDFA, "overlapping-terminator loop now TDFA-eligible"},
		// (cat|car)+: a genuine user alternation NESTED INSIDE a quantifier
		// loop is still a separate InstAlt, checked in full (non-quantifier
		// path) — must remain unaffected by the quantifier-loop relaxation.
		{`(cat|car)+`, EngineTDFA, "nested user alternation inside a loop, no captures inside it"},
		// CLAUDE.md "Load-bearing engine-selection gates": an inverted
		// class wider than 256 codepoints inside a quantifier loop still has an
		// INDETERMINATE (empty) first-rune-set for getFirstRuneSet, so it must
		// remain ambiguous → Backtracking, even though it's a quantifier loop.
		// This must NOT be relaxed — see CLAUDE.md's explicit warning.
		{`<([^>]+)>`, EngineBacktrack, "inverted-class gate: indeterminate branch inside quantifier loop stays ambiguous"},
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

// TestSelectBestEngineWithTDFA_TableReuse pins the table-reuse contract:
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
		{`([^,]+),`, false, "inverted-class ambiguity → Backtracking (CLAUDE.md load-bearing gate)"},
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

// TestSelectorTDFALimitReasons pins which limit --verbose names when a capture
// pattern is demoted to Backtracking. The two are reported from opposite sides
// of one `ok` flag and were swapped: a register-limit pattern was told to raise
// max_dfa_states (while its own report showed the state count comfortably under
// that limit), and a state-limit pattern was told nothing at all, because the
// branch was guarded on the non-nil table newTDFA does not return in that case.
func TestSelectorTDFALimitReasons(t *testing.T) {
	cases := []struct {
		label, pattern     string
		maxStates, maxRegs int
		wantReason         string
		wantLimit          string
		unwantLimit        string
	}{
		{
			label: "register limit", pattern: strings.Repeat("(x)", 25),
			maxStates: 1024, maxRegs: 8,
			wantReason: "TDFA register limit exceeded",
			wantLimit:  "TDFA registers",
			// The state count is not the reason and must not be quoted as it.
			unwantLimit: "TDFA states",
		},
		{
			label: "state limit", pattern: `((a|b|c)+(d|e)+(f|g)+)+`,
			maxStates: 4, maxRegs: 64,
			wantReason: "TDFA state limit exceeded",
			// No table was built, so there is no count to report.
			unwantLimit: "TDFA states",
		},
	}
	for _, c := range cases {
		re, err := syntax.Parse(c.pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("%s: parse: %v", c.label, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("%s: compile: %v", c.label, err)
		}
		rep := &Reporter{}
		rep.Begin(c.label, c.pattern)
		eng, _ := selectBestEngineWithTDFA(prog, &CompileOptions{
			Report: rep, MaxDFAStates: c.maxStates, MaxTDFARegs: c.maxRegs})
		rep.End()
		if eng != EngineBacktrack {
			t.Fatalf("%s: engine = %v, want Backtracking", c.label, eng)
		}
		if len(rep.Patterns) != 1 {
			t.Fatalf("%s: reported %d patterns, want 1", c.label, len(rep.Patterns))
		}
		got := rep.Patterns[0]
		if got.Engine != EngineBacktrack {
			t.Errorf("%s: reported engine = %v, want Backtracking", c.label, got.Engine)
		}
		if !strings.Contains(got.Reason, c.wantReason) {
			t.Errorf("%s: reason = %q, want it to contain %q", c.label, got.Reason, c.wantReason)
		}
		limits := strings.Join(got.Limits, " | ")
		if c.wantLimit != "" && !strings.Contains(limits, c.wantLimit) {
			t.Errorf("%s: limits = %q, want a %q line", c.label, limits, c.wantLimit)
		}
		if c.unwantLimit != "" && strings.Contains(limits, c.unwantLimit) {
			t.Errorf("%s: limits = %q, must not quote %q", c.label, limits, c.unwantLimit)
		}
	}
}

// TestDFAStateLimitBailsOutFast guards against a real compile-time DoS found
// 2026-08-06: newDFA's subset-construction BFS had no internal state cap.
// [^,]{250,}X[^;]{250,} — two independent bounded-repetition inverted
// classes straddling an ambiguous split point (any 'X' byte is valid inside
// both classes too) — makes the number of distinct reachable NFA-state
// subsets explode with no plateau in sight (confirmed live: 40,000+ DFA
// states generated in 12s with no sign of leveling off, driven entirely by
// map/string-key allocation in the subset-construction worklist).
// CompileOptions.MaxDFAStates was completely ineffective against this,
// because it was only ever checked on newDFA's *output*, after the
// unbounded construction already ran (or hung trying to). This test must
// complete quickly and either succeed with a small compiled pattern or
// cleanly fall back to Backtracking — never hang.
func TestDFAStateLimitBailsOutFast(t *testing.T) {
	const pattern = `[^,]{250,}X[^;]{250,}`
	t.Run("newDFA_bails_out_internally", func(t *testing.T) {
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if _, ok := newDFA(prog, false, true, 1024); ok {
			t.Fatalf("newDFA(%q, maxStates=1024): expected state-limit bail-out (ok=false), got ok=true", pattern)
		}
	})
	t.Run("compile_falls_back_to_backtracking", func(t *testing.T) {
		// End-to-end: MaxDFAStates left at its default (1024) — the pattern
		// must compile successfully (falling back to Backtracking), not
		// hang and not hard-error.
		mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "f"}})
	})
}

func TestRegexpMinMaxLen(t *testing.T) {
	parse := func(pattern string) *syntax.Regexp {
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		return re // NOT simplified — preserves OpRepeat
	}

	cases := []struct {
		pattern string
		wantMin int
		wantMax int
	}{
		// OpLiteral
		{"abc", 3, 3},
		{"a", 1, 1},
		// OpAnyCharNotNL
		{".", 1, 1},
		// OpCharClass
		{"[a-z]", 1, 1},
		// OpStar
		{"a*", 0, -1},
		// OpPlus
		{"a+", 1, -1},
		// OpQuest
		{"a?", 0, 1},
		// OpRepeat finite
		{"a{2,5}", 2, 5},
		// OpRepeat infinite upper
		{"a{3,}", 3, -1},
		// OpConcat
		{"ab", 2, 2},
		{"abc", 3, 3},
		// OpConcat with unbounded part
		{"ab*", 1, -1},
		// OpAlternate
		{"a|bb", 1, 2},
		// OpCapture
		{"(abc)", 3, 3},
		// Anchors/boundaries → (0,0)
		{"^", 0, 0},
		{`\b`, 0, 0},
		// 2-byte UTF-8 literal (é = U+00E9): OpPlus recurses into Literal → n += 2
		{"é+", 2, -1},
		// 3-byte UTF-8 literal (中 = U+4E2D): n += 3
		{"中+", 3, -1},
		// 4-byte UTF-8 literal (𐀀 = U+10000): n += 4
		{"𐀀+", 4, -1},
		// OpRepeat with unbounded child max → hi = -1
		{"(?:[a-z]+){2,3}", 2, -1},
		// OpAlternate with unbounded branch → totMax = -1
		{"a+|b", 1, -1},
	}
	for _, c := range cases {
		re := parse(c.pattern)
		gotMin, gotMax := regexpMinMaxLen(re, false)
		if gotMin != c.wantMin || gotMax != c.wantMax {
			t.Errorf("regexpMinMaxLen(%q, false) = (%d,%d), want (%d,%d)",
				c.pattern, gotMin, gotMax, c.wantMin, c.wantMax)
		}
	}
}

// TestFindMandatoryLitRecDegenerate covers defensive branches in findMandatoryLitRec
// that the parser never triggers (empty literal rune slice, captures/plus with wrong
// sub count). Called directly to reach these guards.
func TestFindMandatoryLitRecDegenerate(t *testing.T) {
	cases := []struct {
		name string
		re   *syntax.Regexp
	}{
		// OpLiteral with empty Rune slice → len(bs)==0 → nil.
		{"literal_empty_rune", &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{}}},
		// OpCapture with 0 subs → len(re.Sub)!=1 → nil.
		{"capture_no_sub", &syntax.Regexp{Op: syntax.OpCapture}},
		// OpPlus with 0 subs → len(re.Sub)!=1 → nil.
		{"plus_no_sub", &syntax.Regexp{Op: syntax.OpPlus}},
	}
	for _, c := range cases {
		got, _ := findMandatoryLitRec(c.re, 0, 0, false)
		if got != nil {
			t.Errorf("findMandatoryLitRec(%s, false): got %v, want nil", c.name, got)
		}
	}
}

// TestRegexpMinMaxLenDegenerate covers edge cases that the parser never produces
// (empty Sub slices, OpNoMatch/OpEmptyMatch, unknown Op) by constructing Regexp
// nodes directly.
func TestRegexpMinMaxLenDegenerate(t *testing.T) {
	cases := []struct {
		name    string
		re      *syntax.Regexp
		wantMin int
		wantMax int
	}{
		{"OpRepeat_no_sub", &syntax.Regexp{Op: syntax.OpRepeat, Min: 1, Max: 3}, 0, 0},
		{"OpPlus_no_sub", &syntax.Regexp{Op: syntax.OpPlus}, 0, -1},
		{"OpQuest_no_sub", &syntax.Regexp{Op: syntax.OpQuest}, 0, 0},
		{"OpAlternate_no_sub", &syntax.Regexp{Op: syntax.OpAlternate}, 0, 0},
		{"OpCapture_no_sub", &syntax.Regexp{Op: syntax.OpCapture}, 0, 0},
		{"OpNoMatch", &syntax.Regexp{Op: syntax.OpNoMatch}, 0, 0},
		{"OpEmptyMatch", &syntax.Regexp{Op: syntax.OpEmptyMatch}, 0, 0},
		{"unknown_op", &syntax.Regexp{Op: syntax.Op(99)}, 0, -1},
	}
	for _, c := range cases {
		min, max := regexpMinMaxLen(c.re, false)
		if min != c.wantMin || max != c.wantMax {
			t.Errorf("regexpMinMaxLen(%s, false) = (%d,%d), want (%d,%d)", c.name, min, max, c.wantMin, c.wantMax)
		}
	}
}

func TestFindMandatoryLit(t *testing.T) {
	cases := []struct {
		pattern string
		wantNil bool
		wantLit string
		wantMin int32
	}{
		// Simple literal: the whole thing is mandatory.
		{"foo", false, "foo", 0},
		// Literal inside a non-capturing group.
		{"(?:foo)", false, "foo", 0},
		// Literal after a mandatory prefix — minOff reflects prefix length.
		{"bar://", false, "bar://", 0},
		// Alternation: no guaranteed literal.
		{"a|b", true, "", 0},
		// Kleene star: body not mandatory.
		{"a*", true, "", 0},
		// Plus: body mandatory at least once.
		{"a+b", false, "a", 0},
		// Sequence: first literal is mandatory at offset 0.
		{"foo.*bar", false, "foo", 0},
		// Invalid pattern: returns nil.
		{"[invalid", true, "", 0},
		// Empty pattern: returns nil.
		{"", true, "", 0},
		// URL-like: mandatory literal ://, minOff=2 (minimum 2 chars before it).
		{`[a-zA-Z]{2,8}://[^\s]+`, false, "://", 2},
		// Non-ASCII literal: r > 127 → returns nil.
		{"é", true, "", 0},
		// OpRepeat with Min=0: not mandatory → skipped; foo found after.
		{"[a-z]{0,3}foo", false, "foo", 0},
	}
	for _, c := range cases {
		got := findMandatoryLit(c.pattern, false)
		if c.wantNil {
			if got != nil {
				t.Errorf("findMandatoryLit(%q, false): got %v, want nil", c.pattern, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("findMandatoryLit(%q, false): got nil, want lit=%q", c.pattern, c.wantLit)
			continue
		}
		if string(got.bytes) != c.wantLit {
			t.Errorf("findMandatoryLit(%q, false): lit=%q, want %q", c.pattern, got.bytes, c.wantLit)
		}
		if got.minOff != c.wantMin {
			t.Errorf("findMandatoryLit(%q, false): minOff=%d, want %d", c.pattern, got.minOff, c.wantMin)
		}
		if got.maxOff < got.minOff {
			t.Errorf("findMandatoryLit(%q, false): maxOff %d < minOff %d", c.pattern, got.maxOff, got.minOff)
		}
	}
}

func TestHasMandatoryLit(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"foo", true},
		{"foo.*bar", true},
		{`[a-z]{0,3}foo`, true}, // bounded prefix; literal still mandatory
		{`\d+foo`, false},       // unbounded prefix → maxOff -1 rejects literal
		{"a|b", false},
		{"a*", false},
		{"(?i)foo", false}, // FoldCase strips the literal
		{"[a-z]+", false},
		{"[invalid", false}, // parse error
	}
	for _, c := range cases {
		if got := HasMandatoryLit(c.pattern, false); got != c.want {
			t.Errorf("HasMandatoryLit(%q, false) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func chainTable(t *testing.T, pat string) *dfaTable {
	t.Helper()
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		t.Fatalf("pattern=%q parse: %v", pat, err)
	}
	table, _, err := mergeSuffixDFA([]*syntax.Regexp{re}, CompileSetOptions{})
	if err != nil {
		t.Fatalf("pattern=%q mergeSuffixDFA: %v", pat, err)
	}
	return table
}

func TestIsCountedClassChain_Accepts(t *testing.T) {
	cases := []struct {
		pat     string
		wantN   int
		classSz int
	}{
		{`[A-Z0-9]{16}`, 16, 36},
		{`[A-Za-z0-9]{36}`, 36, 62},
		{`[0-9]{4}`, 4, 10},
		{`[a-f]{24}`, 24, 6},
	}
	for _, c := range cases {
		table := chainTable(t, c.pat)
		class, n, ok := isCountedClassChain(table)
		if !ok {
			t.Errorf("pattern=%q: expected chain detected, got ok=false", c.pat)
			continue
		}
		if n != c.wantN {
			t.Errorf("pattern=%q: n=%d, want %d", c.pat, n, c.wantN)
		}
		if len(class) != c.classSz {
			t.Errorf("pattern=%q: classSz=%d, want %d", c.pat, len(class), c.classSz)
		}
	}
}

func TestIsCountedClassChain_Rejects(t *testing.T) {
	cases := []string{
		`[A-Z0-9]{16,20}`,    // range, not exact — intermediate states also accept
		`[A-Z0-9]{16,}`,      // open-ended
		`[A-Z0-9]+`,          // unbounded self-loop (cycle)
		`[A-Z]{8}[0-9]{8}`,   // class changes partway — not uniform C
		`(?:AB|CD)[A-Z]{16}`, // branching before the chain
		`[A-Z0-9]{16}\b`,     // word boundary
	}
	for _, pat := range cases {
		table := chainTable(t, pat)
		_, _, ok := isCountedClassChain(table)
		if ok {
			t.Errorf("pattern=%q: expected rejection, got ok=true", pat)
		}
	}
}

func TestIsCountedClassChain_RealPatterns(t *testing.T) {
	for _, pat := range []string{`AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9]{36}`} {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		// Mirror analyzePattern's literal/suffix split for a rough check:
		// simplest way is to just check the FULL DFA fails (has the literal
		// prefix baked in) but the SUFFIX (class only) succeeds — already
		// covered by TestIsCountedClassChain_Accepts. Here just sanity check
		// the full pattern's own DFA does NOT spuriously look like a chain
		// (it has more states due to the literal prefix).
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		d, dOk := newDFA(prog, false, true, maxHelperDFAStates)
		if !dOk {
			t.Fatalf("newDFA: state limit exceeded")
		}
		full := dfaTableFrom(d)
		_, n, ok := isCountedClassChain(full)
		if ok {
			t.Errorf("pattern=%q: full DFA (with literal prefix) unexpectedly detected as a chain, n=%d", pat, n)
		}
	}
}

func TestCountedChainEmission(t *testing.T) {
	// End-to-end: does genSuffixWASM actually take the fast path (small,
	// table-free body) for the target patterns vs. a plain repeated class
	// with no literal (used as a suffix, single pattern)?
	table := chainTable(t, `[A-Z0-9]{16}`)
	art, dataBytes, dataSegCount, _ := genSuffixWASM(table, 0, 0, []int{5}, []int{0}, LikelyNeutral, false, false, nil)
	body := art.fnBody
	fmt.Printf("counted-chain suffix: bodyLen=%d dataBytesLen=%d dataSegCount=%d\n", len(body), len(dataBytes), dataSegCount)
	if dataSegCount != 0 {
		t.Errorf("expected 0 data segments (pure SIMD, no table), got %d", dataSegCount)
	}
}
