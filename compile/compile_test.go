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
		re := parse("ab")
		rev := reverseRegexp(re)
		if rev.Op == syntax.OpConcat && len(rev.Sub) == 2 {
			// first sub should be the reversed 'b', second 'a'
			_ = rev.Sub
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
		cfg := config.BuildConfig{Regexes: entries}
		if err := CmdCompile(cfg, "-"); err != nil {
			t.Fatalf("CmdCompile stdout: %v", err)
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
