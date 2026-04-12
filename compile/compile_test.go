package compile

import (
	"bytes"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

// compileForced is like Compile but forces the given engine for the capture path
// of every entry that requests capture groups. Used in tests only.
func compileForced(patterns []config.RegexEntry, tableBase int64, standalone bool, forceGroupsEngine EngineType, userOpts ...CompileOptions) ([]byte, int64, error) {
	var opts CompileOptions
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	return compileAll(patterns, tableBase, standalone, forceGroupsEngine, opts)
}

func parseTestRe(t *testing.T, pattern string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	return re
}

func hasCapture(re *syntax.Regexp) bool {
	if re.Op == syntax.OpCapture {
		return true
	}
	for _, sub := range re.Sub {
		if hasCapture(sub) {
			return true
		}
	}
	return false
}

func TestStripCaptures(t *testing.T) {
	cases := []struct {
		pattern string
	}{
		{"(a)(b)"},
		{"(?P<x>foo)(?P<y>bar)"},
		{"(a|(b|c))"},
		{"abc"}, // no captures — should be a no-op
	}
	for _, c := range cases {
		re := parseTestRe(t, c.pattern)
		stripCaptures(re)
		if hasCapture(re) {
			t.Errorf("stripCaptures(%q): capture groups remain after stripping", c.pattern)
		}
	}
}

func TestExtractGroupNames(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		// Named groups: first slot is group 0 (unnamed whole match).
		{"(?P<x>a)(?P<y>b)", []string{"x", "y"}},
		// Mix of named and unnamed.
		{"(a)(?P<z>b)(c)", []string{"", "z", ""}},
		// No captures.
		{"abc", nil},
	}
	for _, c := range cases {
		re := parseTestRe(t, c.pattern)
		got := extractGroupNames(re)
		if len(got) != len(c.want) {
			t.Errorf("extractGroupNames(%q): got %v, want %v", c.pattern, got, c.want)
			continue
		}
		for i, name := range got {
			if name != c.want[i] {
				t.Errorf("extractGroupNames(%q)[%d]: got %q, want %q", c.pattern, i, name, c.want[i])
			}
		}
	}
}

func TestSelectEnginePublic(t *testing.T) {
	cases := []struct {
		pattern string
		want    EngineType
	}{
		{"abc", EngineCompiledDFA},
		{"(a)(b)", EngineTDFA},
		{"(a+?)(b)", EngineBacktrack},
	}
	for _, c := range cases {
		got, err := SelectEngine(c.pattern, CompileOptions{})
		if err != nil {
			t.Errorf("SelectEngine(%q): unexpected error: %v", c.pattern, err)
			continue
		}
		if got != c.want {
			t.Errorf("SelectEngine(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

// wasmMagic is the 4-byte WASM magic header.
var wasmMagic = []byte{0x00, 0x61, 0x73, 0x6d}

// mustCompileEntries calls Compile with standalone=true and fails on error.
func mustCompileEntries(t *testing.T, entries []config.RegexEntry, opts ...CompileOptions) {
	t.Helper()
	wasm, _, err := Compile(entries, 0, true, opts...)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatalf("Compile: output is not a valid WASM module (len=%d)", len(wasm))
	}
}

func TestCompileIntegrationDFA(t *testing.T) {
	t.Run("match_only", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}})
	})
	t.Run("find_only", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", FindFunc: "f"}})
	})
	t.Run("match_and_find", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", MatchFunc: "m", FindFunc: "f"}})
	})
	t.Run("find_word_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `\bfoo\b`, FindFunc: "f"}})
	})
	t.Run("find_lit_anchor", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `.*foo.*`, FindFunc: "f"}})
	})
	// Alternation with 2 first bytes and selective tails → T1/T2/T3 Teddy tables.
	t.Run("find_teddy_t3", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(http|ftp)://[^\s]+`, FindFunc: "f"}})
	})
	t.Run("no_func_entry", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc"}})
	})
	t.Run("multiple_entries", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{
			{Pattern: "abc", MatchFunc: "m1"},
			{Pattern: "def", FindFunc: "f2"},
		})
	})
}

func TestCompileIntegrationTDFA(t *testing.T) {
	t.Run("groups", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}})
	})
	t.Run("named_groups", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?P<x>a)(?P<y>b)", NamedGroupsFunc: "ng"}})
	})
	t.Run("groups_and_named", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?P<x>a)(?P<y>b)", GroupsFunc: "g", NamedGroupsFunc: "ng"}})
	})
	t.Run("find_and_groups", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a+)(b+)", FindFunc: "f", GroupsFunc: "g"}})
	})
	t.Run("match_and_groups", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a)(b)", MatchFunc: "m", GroupsFunc: "g"}})
	})
	t.Run("anchored_groups", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "^(a)(b)$", GroupsFunc: "g"}})
	})
}

func TestCompileIntegrationBacktrack(t *testing.T) {
	t.Run("groups_forced", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(BT groups): %v", err)
		}
	})
	t.Run("named_groups_forced", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "(?P<x>a)(?P<y>b)", NamedGroupsFunc: "ng"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(BT named_groups): %v", err)
		}
	})
	t.Run("natural_bt_nongreedy", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a+?)(b)", GroupsFunc: "g"}})
	})
	t.Run("match_dfa_overflow", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}}, CompileOptions{MaxDFAStates: 1})
	})
	t.Run("find_dfa_overflow", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", FindFunc: "f"}}, CompileOptions{MaxDFAStates: 1})
	})
	// btCheckRuneRanges: char-class range in backtracking engine.
	t.Run("bt_char_range", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "([a-z]+)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(BT char range): %v", err)
		}
	})
	// btWordBoundary: word-boundary assertion in backtracking engine.
	t.Run("bt_word_boundary", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: `(\bfoo\b)`, GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(BT word boundary): %v", err)
		}
	})
	// btFoldRune: case-insensitive single-character match in backtracking engine.
	t.Run("bt_case_fold_char", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "((?i:a)+)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(BT case-fold): %v", err)
		}
	})
	// buildBTScanTables: BT find mode (no-capture find path).
	t.Run("bt_find_mode", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]+", FindFunc: "f"}}, CompileOptions{MaxDFAStates: 1})
	})
	// emitBTMemoZeroInit: non-greedy loop with zero-matchable body forces BitState memo.
	t.Run("bt_memo_nongreedy_loop", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "((?:a*?)+)", GroupsFunc: "g"}})
	})
}

// noHybridOpts returns CompileOptions that disable the hybrid/compiled-DFA dispatch,
// forcing buildMatchBody and buildAnchoredFindBody / buildFindBody to be exercised.
func noHybridOpts() CompileOptions {
	return CompileOptions{CompiledDFAThreshold: -1}
}

func TestCompileIntegrationNonHybridDFA(t *testing.T) {
	// buildMatchBody: non-hybrid match path (u8 simple).
	t.Run("match_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}}, noHybridOpts())
	})
	// buildAnchoredFindBody: non-hybrid anchored find (^ pattern).
	t.Run("find_anchored_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "^abc", FindFunc: "f"}}, noHybridOpts())
	})
	// buildFindBody: non-hybrid non-anchored find.
	t.Run("find_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", FindFunc: "f"}}, noHybridOpts())
	})
	// Non-hybrid match+find combined.
	t.Run("match_and_find_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "abc", MatchFunc: "m", FindFunc: "f"}}, noHybridOpts())
	})
	// buildAnchoredFindBody with word boundary.
	t.Run("find_anchored_word_boundary_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `^\bfoo`, FindFunc: "f"}}, noHybridOpts())
	})
	// buildLitAnchorFindBody / buildLitAnchorBackScanBody: literal-anchor find path.
	t.Run("find_lit_anchor_non_hybrid", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `.*foo.*`, FindFunc: "f"}}, noHybridOpts())
	})
}

func TestSelectEngineOptions(t *testing.T) {
	// MaxDFAStates: -1 disables TDFA → falls back to Backtrack for capture patterns.
	t.Run("max_dfa_states_disabled_forces_bt", func(t *testing.T) {
		got, err := SelectEngine("(a)(b)", CompileOptions{MaxDFAStates: -1})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got != EngineBacktrack {
			t.Errorf("SelectEngine with MaxDFAStates=-1 = %v, want Backtrack", got)
		}
	})
	// MaxTDFARegs: -1 disables TDFA → falls back to Backtrack.
	t.Run("max_tdfa_regs_disabled_forces_bt", func(t *testing.T) {
		got, err := SelectEngine("(a)(b)", CompileOptions{MaxTDFARegs: -1})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got != EngineBacktrack {
			t.Errorf("SelectEngine with MaxTDFARegs=-1 = %v, want Backtrack", got)
		}
	})
	// Negative CompiledDFAThreshold disables compiled dispatch → plain DFA.
	t.Run("compiled_dfa_threshold_disabled", func(t *testing.T) {
		got, err := SelectEngine("abc", CompileOptions{CompiledDFAThreshold: -1})
		if err != nil {
			t.Fatalf("SelectEngine: %v", err)
		}
		if got != EngineDFA {
			t.Errorf("SelectEngine with CompiledDFAThreshold=-1 = %v, want DFA", got)
		}
	})
}
