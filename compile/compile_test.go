package compile

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestReverseRegexp(t *testing.T) {
	parse := func(pattern string) *syntax.Regexp {
		t.Helper()
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		return re
	}

	t.Run("literal reversed", func(t *testing.T) {
		re := parse("abc")
		rev := reverseRegexp(re)
		// Traversal: find the OpLiteral node and check its runes are reversed.
		var check func(*syntax.Regexp)
		check = func(r *syntax.Regexp) {
			if r.Op == syntax.OpLiteral {
				runes := r.Rune
				if len(runes) >= 2 && runes[0] != 'c' {
					t.Errorf("reversed literal runes[0] = %c, want c", runes[0])
				}
			}
			for _, sub := range r.Sub {
				check(sub)
			}
		}
		check(rev)
	})

	t.Run("concat reversed", func(t *testing.T) {
		// a[bc] → OpConcat{OpLiteral['a'], OpCharClass}
		// reversed → OpConcat{OpCharClass, OpLiteral['a']}
		re := parse("a[bc]")
		rev := reverseRegexp(re)
		if rev.Op != syntax.OpConcat {
			t.Fatalf("expected OpConcat, got %v", rev.Op)
		}
		if len(rev.Sub) != 2 {
			t.Fatalf("expected 2 subs, got %d", len(rev.Sub))
		}
		if rev.Sub[0].Op != syntax.OpCharClass {
			t.Errorf("sub[0] = %v, want OpCharClass", rev.Sub[0].Op)
		}
		if rev.Sub[1].Op != syntax.OpLiteral {
			t.Errorf("sub[1] = %v, want OpLiteral", rev.Sub[1].Op)
		}
	})

	t.Run("begin text becomes end text", func(t *testing.T) {
		re := parse(`\A`)
		rev := reverseRegexp(re)
		var found bool
		var check func(*syntax.Regexp)
		check = func(r *syntax.Regexp) {
			if r.Op == syntax.OpEndText {
				found = true
			}
			for _, sub := range r.Sub {
				check(sub)
			}
		}
		check(rev)
		if !found {
			t.Error("expected OpEndText after reversing OpBeginText, not found")
		}
	})

	t.Run("end text becomes begin text", func(t *testing.T) {
		re := parse(`\z`)
		rev := reverseRegexp(re)
		var found bool
		var check func(*syntax.Regexp)
		check = func(r *syntax.Regexp) {
			if r.Op == syntax.OpBeginText {
				found = true
			}
			for _, sub := range r.Sub {
				check(sub)
			}
		}
		check(rev)
		if !found {
			t.Error("expected OpBeginText after reversing OpEndText, not found")
		}
	})

	t.Run("star sub reversed", func(t *testing.T) {
		re := parse("(ab)*")
		rev := reverseRegexp(re)
		_ = rev // must not panic; sub structure recursively reversed
	})

	t.Run("char class unchanged", func(t *testing.T) {
		re := parse("[a-z]")
		rev := reverseRegexp(re)
		var check func(*syntax.Regexp)
		check = func(r *syntax.Regexp) {
			if r.Op == syntax.OpCharClass {
				if len(r.Rune) != len(re.Rune) {
					t.Errorf("char class runes changed after reverse: got %v", r.Rune)
				}
			}
			for _, sub := range r.Sub {
				check(sub)
			}
		}
		check(rev)
	})
}

func TestCompileEmbeddedMode(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: "abc", MatchFunc: "m"},
		{Pattern: "(x)(y)", GroupsFunc: "g"},
	}
	wasm, _, err := Compile(entries, 0, false)
	if err != nil {
		t.Fatalf("Compile(embedded): %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatalf("Compile(embedded): output is not a valid WASM module")
	}
	// Embedded mode must import memory from "main".
	if !bytes.Contains(wasm, []byte("main")) {
		t.Error(`Compile(embedded): missing "main" import module name`)
	}
	if !bytes.Contains(wasm, []byte("memory")) {
		t.Error(`Compile(embedded): missing "memory" import field name`)
	}
	// Standalone mode must NOT have the "main" import.
	wasmSA, _, err := Compile(entries, 0, true)
	if err != nil {
		t.Fatalf("Compile(standalone): %v", err)
	}
	if bytes.Contains(wasmSA, []byte("main")) {
		t.Error(`Compile(standalone): unexpected "main" import`)
	}
}

func TestCompileInvalidPattern(t *testing.T) {
	cases := []string{
		"[invalid",  // unclosed character class
		"(?P<>foo)", // empty group name
		"(?Pfoo)",   // malformed named group
	}
	for _, pat := range cases {
		_, _, err := Compile([]config.RegexEntry{{Pattern: pat, MatchFunc: "m"}}, 0, true)
		if err == nil {
			t.Errorf("Compile(%q): expected error, got nil", pat)
		}
	}
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

func TestEngineTypeString(t *testing.T) {
	cases := []struct {
		e    EngineType
		want string
	}{
		{EngineDFA, "DFA"},
		{EngineCompiledDFA, "Compiled DFA"},
		{EngineTDFA, "TDFA"},
		{EngineBacktrack, "Backtracking"},
	}
	for _, c := range cases {
		if got := c.e.String(); got != c.want {
			t.Errorf("EngineType(%d).String() = %q, want %q", c.e, got, c.want)
		}
	}
}

func TestEngineTypeMethod(t *testing.T) {
	dfaEngine, err := compile("abc", CompileOptions{ForceEngine: EngineDFA})
	if err != nil {
		t.Fatalf("compile DFA: %v", err)
	}
	if dfaEngine.Type() != EngineDFA {
		t.Errorf("dfa.Type() = %v, want DFA", dfaEngine.Type())
	}

	btEngine, err := compile("(a+?)", CompileOptions{ForceEngine: EngineBacktrack})
	if err != nil {
		t.Fatalf("compile BT: %v", err)
	}
	if btEngine.Type() != EngineBacktrack {
		t.Errorf("backtrack.Type() = %v, want Backtracking", btEngine.Type())
	}
}

func TestCmdCompile(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}}

	t.Run("file output standalone", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.wasm")
		cfg := config.BuildConfig{Regexes: entries} // no Output field → standalone
		if err := CmdCompile(cfg, out); err != nil {
			t.Fatalf("CmdCompile: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.HasPrefix(data, wasmMagic) {
			t.Error("output is not valid WASM")
		}
	})

	t.Run("file output embedded", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.wasm")
		cfg := config.BuildConfig{Regexes: entries, Output: "final.wasm"} // Output set → embedded
		if err := CmdCompile(cfg, out); err != nil {
			t.Fatalf("CmdCompile: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.HasPrefix(data, wasmMagic) {
			t.Error("output is not valid WASM")
		}
	})

	t.Run("stdout", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdout
		os.Stdout = w

		cfg := config.BuildConfig{Regexes: entries}
		compErr := CmdCompile(cfg, "-")

		w.Close()
		os.Stdout = orig

		if compErr != nil {
			t.Fatalf("CmdCompile stdout: %v", compErr)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(buf.Bytes(), wasmMagic) {
			t.Error("stdout output is not valid WASM")
		}
	})
}

// TestCompileHybridAnchoredFind exercises buildHybridAnchoredFindBody —
// anchored (^) find with compiled DFA dispatch (default options, small DFA).
// ^[a-z]+ has no interior literal anchor so findLitAnchorPoint returns nil,
// falling through to appendFindCodeEntry which picks buildHybridAnchoredFindBody.
func TestCompileHybridAnchoredFind(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `^[a-z]+`, FindFunc: "f"}})
}

// TestCompileU16DFA exercises the u16 DFA table path (appendTableLoad16u) by
// compiling a pattern whose DFA has > 256 states.
func TestCompileU16DFA(t *testing.T) {
	// a{512} produces a linear DFA with 514 states (> 256 → u16 table).
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "a{512}", MatchFunc: "m"}},
		CompileOptions{MaxDFAStates: 100000})
}

// TestCompileBTMatchMemo exercises emitBTMemoZeroInit — BT fallback for the
// match path when the DFA is forced too large and needsBitState is true.
// The trailing `b` forces the LL DFA to have >1 states (preventing the
// (?:a?)+? part from collapsing to a single state), while the (?:a?)+?
// prefix still gives needsBitState=true. MaxDFAStates=1 forces BT fallback.
func TestCompileBTMatchMemo(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?:a?)+?b", MatchFunc: "m"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestCompileBTFindMemo exercises emitBTMemoZeroInitTrimmed — BT fallback for
// the find path when the LF DFA is forced too large and needsBitState is true.
func TestCompileBTFindMemo(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?:a?)+?", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestCompileMatchBodyCompressed exercises the u8 compressed path in buildMatchBody.
// a{130} produces ~132 DFA states: 132*256 = 33792 > 32KB → useCompression=true.
// noHybridOpts forces the non-hybrid (non-compiled-DFA) match body path.
func TestCompileMatchBodyCompressed(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "a{130}", MatchFunc: "m"}},
		CompileOptions{MaxDFAStates: 100000, CompiledDFAThreshold: -1})
}

// TestCompileMatchBodyImmediateAccept exercises the hasImmAccept branch in buildMatchBody.
// a* matches empty at start; the LL DFA start state has immediateAccept=true.
func TestCompileMatchBodyImmediateAccept(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "a*", MatchFunc: "m"}},
		CompileOptions{CompiledDFAThreshold: -1})
}

// TestCompileDFADataSegmentsNewlineBoundary exercises the midAcceptNLBytes path
// in dfaDataSegments. (?m:foo$) has hasNewlineBoundary=true.
func TestCompileDFADataSegmentsNewlineBoundary(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m:foo$)`, FindFunc: "f"}})
}

// TestCompileBTInstHandlerAnyRune exercises InstRuneAny and InstRuneAnyNotNL
// in emitBTInstHandler. (?s:.+) uses InstRuneAny (DOTALL), .+ uses InstRuneAnyNotNL.
func TestCompileBTInstHandlerAnyRune(t *testing.T) {
	_, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "(?s:.+)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced((?s:.+) BT): %v", err)
	}
	_, _, err = compileForced(
		[]config.RegexEntry{{Pattern: ".+", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced(.+ BT): %v", err)
	}
}

// TestCompileBTInstHandlerNonLoopAlt exercises the non-loop alternation path
// (btPushFrame) in emitBTInstHandler. (a|b) has an Alt that is not a loop.
func TestCompileBTInstHandlerNonLoopAlt(t *testing.T) {
	_, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "(a|b)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced((a|b) BT): %v", err)
	}
}

// TestCompileAnchoredFindBodyNLBoundary exercises the hasNewlineBoundary path in
// buildAnchoredFindBody (u8 simple path). ^[a-z]+(?m:$): ^ anchors the find,
// (?m:$) sets hasNewlineBoundary=true; [a-z] has no fixed literal so
// findLitAnchorPoint returns nil and appendFindCodeEntry reaches buildAnchoredFindBody.
func TestCompileAnchoredFindBodyNLBoundary(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `^[a-z]+(?m:$)`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileAnchoredFindBodyCompressedNL exercises the useU8&&useCompression path in
// buildAnchoredFindBody. ^[a-z]{130}(?m:$): ~132 DFA states → table >32KB → useCompression=true.
func TestCompileAnchoredFindBodyCompressedNL(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `^[a-z]{130}(?m:$)`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileAnchoredFindBodyU16NL exercises the u16 path in buildAnchoredFindBody.
// ^[a-z]{512}(?m:$): ~513 DFA states > 256 → useU8=false → u16 table path.
func TestCompileAnchoredFindBodyU16NL(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `^[a-z]{512}(?m:$)`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileFindBodyFlags exercises flag-dependent branches in buildFindBody
// (non-hybrid mode), each requiring a specific DFA property.
func TestCompileFindBodyFlags(t *testing.T) {
	// hasImmAccept: a* accepts the empty string → immediateAccept at start state.
	t.Run("imm_accept", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "a*", FindFunc: "f"}}, noHybridOpts())
	})
	// hasWordBoundary: non-anchored find with \b emits word-char table and midAcceptW/NW.
	t.Run("word_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `\bfoo\b`, FindFunc: "f"}}, noHybridOpts())
	})
	// hasNewlineBoundary: (?m:$) emits midAcceptNL table.
	t.Run("newline_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m:foo$)`, FindFunc: "f"}}, noHybridOpts())
	})
	// useMandatoryLit: pattern has a mandatory interior literal ("://") with no fixed prefix.
	t.Run("mandatory_lit", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `[a-z]+://\S+`, FindFunc: "f"}}, noHybridOpts())
	})
}

// TestCompileAnchoredFindBodyFlags exercises flag-dependent branches in buildAnchoredFindBody
// (non-hybrid mode).
func TestCompileAnchoredFindBodyFlags(t *testing.T) {
	// hasImmAccept: ^a* is anchored and has immediateAccept at the start state.
	t.Run("imm_accept", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "^a*", FindFunc: "f"}}, noHybridOpts())
	})
	// hasNewlineBoundary: \A anchors the find; (?m:$) adds EmptyEndLine → midAcceptNL.
	// midStartNewline is dead because \A requires ecBeginText which ecBeginLine cannot satisfy.
	t.Run("newline_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `\Afoo(?m:$)`, FindFunc: "f"}}, noHybridOpts())
	})
}

// TestCompileHybridMatchBodyCompressed exercises the useCompression branch in buildHybridMatchBody.
// a{130} produces ~132 states: 132×256 = 33 792 > 32 KB → useCompression=true;
// 133 states ≤ default threshold 256 → useHybridDispatch=true.
func TestCompileHybridMatchBodyCompressed(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "a{130}", MatchFunc: "m"}},
		CompileOptions{MaxDFAStates: 100000})
}

// TestCompileHybridMatchBodyImmAccept exercises the hasImmAccept branch in buildHybridMatchBody.
// a* accepts the empty string → immediateAccept at start state → hybrid match with hasImmAccept=true.
func TestCompileHybridMatchBodyImmAccept(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "a*", MatchFunc: "m"}})
}

// TestCompileEmbeddedFindPaths exercises tableMemIdx=1 branches in the DFA find WASM emitter.
func TestCompileEmbeddedFindPaths(t *testing.T) {
	embed := func(t *testing.T, entries []config.RegexEntry, opts ...CompileOptions) {
		t.Helper()
		var o CompileOptions
		if len(opts) > 0 {
			o = opts[0]
		}
		wasm, _, err := Compile(entries, 0, false, o)
		if err != nil {
			t.Fatalf("Compile(embedded): %v", err)
		}
		if !bytes.HasPrefix(wasm, wasmMagic) {
			t.Fatal("output is not a valid WASM module")
		}
	}
	// appendTableLoad16u tableMemIdx=1: u16 find (>256 states) in embedded mode.
	t.Run("u16_find", func(t *testing.T) {
		embed(t, []config.RegexEntry{{Pattern: "a{512}", FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 100000})
	})
	// appendTableVLoad tableMemIdx=1: Teddy find in embedded mode.
	// (foo|bar)[0-9]+ has 2 first bytes (f/b), no mandatory interior literal →
	// useMandatoryLit=false → emitOuterPrologue → Teddy VLoad with tableMemIdx=1.
	t.Run("teddy_find", func(t *testing.T) {
		embed(t, []config.RegexEntry{{Pattern: `(foo|bar)[0-9]+`, FindFunc: "f"}})
	})
	// word char table with tableMemIdx=1: word boundary find in embedded mode.
	t.Run("word_boundary_find", func(t *testing.T) {
		embed(t, []config.RegexEntry{{Pattern: `\bfoo\b`, FindFunc: "f"}})
	})
	// appendTableStore32/Store8 tableMemIdx=1: BT find fallback in embedded mode.
	t.Run("bt_find", func(t *testing.T) {
		embed(t, []config.RegexEntry{{Pattern: "(?:a?)+?", FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 1})
	})
}

// TestCompileEmbeddedBTMatch exercises appendTableStore32/Load32 with tableMemIdx=1
// in the BT match (groups) path when compiled in embedded mode.
func TestCompileEmbeddedBTMatch(t *testing.T) {
	wasm, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
		0, false, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced(embedded BT match): %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatal("output is not a valid WASM module")
	}
}

// TestStripSegCountEmpty exercises the len(data)==0 early return in stripSegCount.
func TestStripSegCountEmpty(t *testing.T) {
	data, n := stripSegCount(nil)
	if data != nil || n != 0 {
		t.Errorf("stripSegCount(nil) = (%v, %d), want (nil, 0)", data, n)
	}
}

// TestEngineTypeStringUnknown exercises the default case of EngineType.String().
func TestEngineTypeStringUnknown(t *testing.T) {
	if got := EngineType(99).String(); got == "" {
		t.Error("EngineType(99).String() returned empty string, want non-empty")
	}
}

// TestCompileBTInstHandlerEmptyWidth exercises the EmptyWidth cases in emitBTInstHandler
// that are only reached when captures are compiled with the BT engine.
func TestCompileBTInstHandlerEmptyWidth(t *testing.T) {
	// EmptyBeginLine: (?m:^) routes captures to BT via hasLineAnchors.
	t.Run("begin_line", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `((?m:^)a)`, GroupsFunc: "g"}})
	})
	// EmptyEndLine: (?m:$) routes captures to BT via hasLineAnchors.
	t.Run("end_line", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a(?m:$))`, GroupsFunc: "g"}})
	})
	// EmptyNoWordBoundary: \B routes captures to BT via hasWordBoundary.
	t.Run("no_word_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a\Bb)`, GroupsFunc: "g"}})
	})
}

// TestCompileBTLoopCaptureSnapshot exercises the loopSnapBase/loopSnapLocals path
// in buildBacktrackBody. ((a?)+) has a greedy + loop containing inner capture (a?);
// loopCaptureLocals finds that capture, setting loopSnapBase. On zero-progress
// (a? matches empty) the snapshot is restored.
func TestCompileBTLoopCaptureSnapshot(t *testing.T) {
	_, _, err := compileForced(
		[]config.RegexEntry{{Pattern: "((a?)+)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("compileForced(((a?)+) BT): %v", err)
	}
}

// TestCompileBTLoopBodyCanMatchEmpty exercises uncovered branches in loopBodyCanMatchEmpty,
// which is called by needsBitState to detect non-greedy loops with empty-matchable bodies.
func TestCompileBTLoopBodyCanMatchEmpty(t *testing.T) {
	// ((a|b)+?): inner alternation causes both 'a' and 'b' paths to enqueue the
	// same merge-point PC, triggering the visited-cache path in loopBodyCanMatchEmpty.
	t.Run("visited_cache", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "((a|b)+?)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(((a|b)+?) BT): %v", err)
		}
	})
	// ((a)+?): non-greedy + loop whose body contains an InstCapture instruction,
	// which hits the default case in loopBodyCanMatchEmpty's switch.
	t.Run("default_case", func(t *testing.T) {
		_, _, err := compileForced(
			[]config.RegexEntry{{Pattern: "((a)+?)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("compileForced(((a)+?) BT): %v", err)
		}
	})
}

// TestCompileFindBodyWBNoPrefix exercises the word-boundary prev-byte state-selection
// path in buildFindBody's emitOuterPrologue. \b[a-z] has hasWordBoundary=true and an
// empty computePrefix (char class has many first bytes), so the OnMatch callback takes
// the "check previous byte" branch rather than the fixed-prefix branch.
func TestCompileFindBodyWBNoPrefix(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `\b[a-z]`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileFindBodyMandLitWBNL exercises the mandatory-literal DFA prologue
// (emitDFAPrologue) when both hasWordBoundary and hasNewlineBoundary are true.
// (?m:\b[a-z]{1,5}foo$) finds "foo" as mandatory literal (minOff=1, maxOff=5),
// has an empty prefix (char class first bytes), and sets both flag bits.
func TestCompileFindBodyMandLitWBNL(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m:\b[a-z]{1,5}foo$)`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileFindBodyCompressed exercises the u8-compressed non-anchored find path in
// buildFindBody. [a-z]{130} produces 131 DFA states: 131×256 = 33 536 B > 32 KB →
// useCompression=true, useU8=true. No fixed literal or prefix → non-mandatory-lit path.
func TestCompileFindBodyCompressed(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{130}", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 100000, CompiledDFAThreshold: -1})
}

// TestCompileMultiEqSIMD exercises the multi-eq SIMD path in emitPrefixScan.
// [a-i]+ has exactly 9 distinct first bytes, which puts it in the 9–16 range
// that uses multi-eq rather than Teddy tables.
func TestCompileMultiEqSIMD(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-i]+", FindFunc: "f"}}, noHybridOpts())
}

// TestCompileLitAnchorFindCompressed exercises the useCompression branch in
// buildLitAnchorFindBody. .*[a-z]{130}foo.* has "foo" as a lit-anchor point and a
// forward DFA with ~134 states (131 for [a-z]{130} + a few for foo), making the
// forward-scan table exceed 32 KB → useCompression=true in the forward layout.
func TestCompileLitAnchorFindCompressed(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `.*[a-z]{130}foo.*`, FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 100000, CompiledDFAThreshold: -1})
}

// TestCompileFindBodyU16 exercises the u16 (>256 states) non-anchored find path in
// buildFindBody. [a-z]{512} produces ~513 DFA states → useU8=false → u16 table path.
func TestCompileFindBodyU16(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{512}", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 100000, CompiledDFAThreshold: -1})
}

// TestCompileFindBodyWBAndNL exercises buildFindBody when both hasWordBoundary and
// hasNewlineBoundary are true simultaneously. (?m:\bfoo$) has \b (word boundary)
// and (?m:$) (EmptyEndLine), causing both emitWBPreAcceptCheck and emitNLPreAcceptCheck
// to emit code in the same find loop body.
func TestCompileFindBodyWBAndNL(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m:\bfoo$)`, FindFunc: "f"}}, noHybridOpts())
}

// TestCompileBTCaptureWithMemo exercises the useMemo=true initialization block in
// buildBacktrackBody for the capture path. ((?:a?)+?) selects BT (non-greedy +?)
// and needsBitState returns true (non-greedy loop with zero-matchable body a?),
// so useMemo=true and the memo locals and zero-init code are emitted.
func TestCompileBTCaptureWithMemo(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "((?:a?)+?)", GroupsFunc: "g"}})
}

// TestCompileNFAFirstBytesFold exercises the fold-case alternative byte path
// in nfaFirstBytes. (?i:abc) has first byte 'a' with fold alternative 'A'.
func TestCompileNFAFirstBytesFold(t *testing.T) {
	// FindFunc + MaxDFAStates=1 forces BT find fallback, which calls nfaFirstBytes.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?i:abc)", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestCompileBTScanTablesTeddy exercises Teddy nibble-table generation in
// buildBTScanTables. (a|b|c) has 3 first bytes (≤8) → 1-byte Teddy tables.
func TestCompileBTScanTablesTeddy(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "(a|b|c)x", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestCompileBTFindBodyMandatoryLit exercises the mandatory-literal path in
// buildBTFindBody. [a-z]+://[^\s]+ has mandatory literal "://" with minOff=2.
func TestCompileBTFindBodyMandatoryLit(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `[a-z]+://[^\s]+`, FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestT3Triggered verifies that 4-byte Teddy tables are generated for patterns
// where the first-byte set is ≤8 and each successive byte is also selective.
// Patterns with a single unambiguous literal prefix use the hybrid-SIMD prefix
// scan instead (computePrefix returns a non-empty slice → Teddy is skipped).
func TestT3Triggered(t *testing.T) {
	cases := []struct {
		pattern string
		wantT1  bool
		wantT2  bool
		wantT3  bool
		desc    string
	}{
		// Two first bytes (h/f), then each has selective tails → T1, T2, T3 expected.
		{`(http|ftp)://[^\s]+`, true, true, true, "http|ftp alternation"},
		// Single-prefix patterns use computePrefix, not Teddy → no T* tables.
		{`ghp_[a-zA-Z0-9]{36}`, false, false, false, "single literal prefix ghp_"},
		{`AKIA[0-9A-Z]{16}`, false, false, false, "single literal prefix AKIA"},
		// Many first bytes → no Teddy at all.
		{`[a-z]+@[a-z]+`, false, false, false, "many first bytes"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			re, err := syntax.Parse(tc.pattern, syntax.Perl|syntax.OneLine)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			re = re.Simplify()
			prog, err := syntax.Compile(re)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			dfa := newDFA(prog, false, true)
			tbl := dfaTableFrom(dfa)
			l := buildDFALayout(tbl, 0, true, true, 0)

			gotT1 := len(l.teddyT1LoBytes) > 0
			gotT2 := len(l.teddyT2LoBytes) > 0
			gotT3 := len(l.teddyT3LoBytes) > 0

			t.Logf("prefix=%q firstBytes=%d T1=%v T2=%v T3=%v", l.prefix, len(l.firstBytes), gotT1, gotT2, gotT3)

			if gotT1 != tc.wantT1 {
				t.Errorf("T1: got %v, want %v", gotT1, tc.wantT1)
			}
			if gotT2 != tc.wantT2 {
				t.Errorf("T2: got %v, want %v", gotT2, tc.wantT2)
			}
			if gotT3 != tc.wantT3 {
				t.Errorf("T3: got %v, want %v", gotT3, tc.wantT3)
			}
		})
	}
}
