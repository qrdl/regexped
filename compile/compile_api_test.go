package compile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qrdl/regexped/config"
)

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

// wasmValidator locates a WASM validator once per test binary.
//
// This whole file used to accept any byte string starting
// with the magic header as "a valid WASM module", which is how a u16 TDFA
// table addressing — an operand order that never once produced a well-typed
// function — sat behind a green TestTDFAU16TableAddressing. Compiling a module
// nothing can instantiate is exactly the failure a compiler test suite exists
// to catch, and the magic-prefix check cannot catch any of it.
//
// The main module deliberately has no wasmtime dependency (CLAUDE.md lists it
// under tools/ only), so validation shells out instead. `wasm-tools validate`
// is preferred; `wasmtime compile` is accepted as a fallback since it type-
// checks the module on the way to Cranelift. Everything the emitters use —
// simd, bulk-memory, multi-memory — is enabled by default in both, so no
// feature flags are needed.
var wasmValidator = sync.OnceValue(func() []string {
	if p, err := exec.LookPath("wasm-tools"); err == nil {
		return []string{p, "validate"}
	}
	if p, err := exec.LookPath("wasmtime"); err == nil {
		return []string{p, "compile", "-o", os.DevNull}
	}
	return nil
})

// validateWASM type-checks a compiled module. Missing validator → the test
// still runs, with a warning, rather than failing on a toolchain gap; the
// point is that a machine which HAS the tool cannot miss an invalid module.
func validateWASM(t *testing.T, wasm []byte) {
	t.Helper()
	argv := wasmValidator()
	if argv == nil {
		t.Log("neither wasm-tools nor wasmtime found in PATH: skipping WASM validation")
		return
	}
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, wasm, 0o600); err != nil {
		t.Fatalf("write module for validation: %v", err)
	}
	cmd := exec.Command(argv[0], append(append([]string{}, argv[1:]...), path)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("emitted module fails %s: %v\n%s", argv[0], err, out)
	}
}

// mustCompileEntries calls Compile with standalone=true, fails on error, and
// validates the emitted module.
func mustCompileEntries(t *testing.T, entries []config.RegexEntry, opts ...CompileOptions) {
	t.Helper()
	wasm, _, err := Compile(entries, 0, true, opts...)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatalf("Compile: output is not a valid WASM module (len=%d)", len(wasm))
	}
	validateWASM(t, wasm)
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
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "(?P<x>a)(?P<y>b)", GroupsFunc: "g"}})
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
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(BT groups): %v", err)
		}
	})
	t.Run("named_groups_forced", func(t *testing.T) {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "(?P<x>a)(?P<y>b)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(BT named_groups): %v", err)
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
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "([a-z]+)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(BT char range): %v", err)
		}
	})
	// btWordBoundary: word-boundary assertion in backtracking engine.
	t.Run("bt_word_boundary", func(t *testing.T) {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: `(\bfoo\b)`, GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(BT word boundary): %v", err)
		}
	})
	// btFoldRune: case-insensitive single-character match in backtracking engine.
	t.Run("bt_case_fold_char", func(t *testing.T) {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "((?i:a)+)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(BT case-fold): %v", err)
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
		cfg := config.BuildConfig{Regexps: entries} // no Output field → standalone
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
		cfg := config.BuildConfig{Regexps: entries, Output: "final.wasm"} // Output set → embedded
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

		cfg := config.BuildConfig{Regexps: entries}
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

// TestCompileMatchBodyImmediateAccept compiles a pattern whose start state is
// immediate-accepting (a* matches empty at position 0) through the non-hybrid
// match body.
//
// It does NOT exercise an immediate-accept check, despite the name: match mode
// is compiled LL, and buildDFALayout raises hasImmAccept only under LF, so the
// match body has never emitted one. (The original comment here claimed the
// opposite; coverage showed the branch at 0.) The dead plumbing was removed in
// 2026-08-18. Kept as a compile smoke test
// for the empty-match-at-start shape.
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
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(?s:.+)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced((?s:.+) BT): %v", err)
	}
	_, _, err = CompileForced(
		[]config.RegexEntry{{Pattern: ".+", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced(.+ BT): %v", err)
	}
}

// TestCompileBTInstHandlerNonLoopAlt exercises the non-loop alternation path
// (btPushFrame) in emitBTInstHandler. (a|b) has an Alt that is not a loop.
func TestCompileBTInstHandlerNonLoopAlt(t *testing.T) {
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(a|b)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced((a|b) BT): %v", err)
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
	wasm, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
		0, false, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced(embedded BT match): %v", err)
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
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "((a?)+)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced(((a?)+) BT): %v", err)
	}
}

// TestCompileBTLoopBodyCanMatchEmpty exercises uncovered branches in loopBodyCanMatchEmpty,
// which is called by needsBitState to detect non-greedy loops with empty-matchable bodies.
func TestCompileBTLoopBodyCanMatchEmpty(t *testing.T) {
	// ((a|b)+?): inner alternation causes both 'a' and 'b' paths to enqueue the
	// same merge-point PC, triggering the visited-cache path in loopBodyCanMatchEmpty.
	t.Run("visited_cache", func(t *testing.T) {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "((a|b)+?)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(((a|b)+?) BT): %v", err)
		}
	})
	// ((a)+?): non-greedy + loop whose body contains an InstCapture instruction,
	// which hits the default case in loopBodyCanMatchEmpty's switch.
	t.Run("default_case", func(t *testing.T) {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "((a)+?)", GroupsFunc: "g"}},
			0, true, EngineBacktrack,
		)
		if err != nil {
			t.Fatalf("CompileForced(((a)+?) BT): %v", err)
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
			dfa, ok := newDFA(prog, false, true, maxHelperDFAStates)
			if !ok {
				t.Fatalf("newDFA: state limit exceeded")
			}
			tbl := dfaTableFrom(dfa)
			l := buildDFALayout(dfaLayoutParams{
				t:                    tbl,
				tableBase:            0,
				needFind:             true,
				leftmostFirst:        true,
				compiledDFAThreshold: 0,
				useAcceptSideTable:   false,
				lmBareShufti:         false,
				lmNonMidShufti:       false,
				lmWideShufti:         false,
			})

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

func TestCompile_ParseError(t *testing.T) {
	if _, err := compile("[invalid"); err == nil {
		t.Error("compile(invalid): expected parse error, got nil")
	}
}

func TestCompile_UnicodeWithoutOpt(t *testing.T) {
	if _, err := compile(`\p{Greek}`); err == nil {
		t.Error("compile(\\p{Greek}): want Unicode error, got nil")
	}
}

func TestCompile_EngineNotSupported(t *testing.T) {
	// Force TDFA / CompiledDFA via ForceEngine → compile() switch falls through
	// to the "not yet supported" error path.
	_, err := compile("abc", CompileOptions{ForceEngine: EngineTDFA})
	if err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("compile(force TDFA): want 'not yet supported' error, got %v", err)
	}
	_, err = compile("abc", CompileOptions{ForceEngine: EngineCompiledDFA})
	if err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("compile(force CompiledDFA): want 'not yet supported' error, got %v", err)
	}
}

func TestNeedsUnicodeSupport(t *testing.T) {
	mkProg := func(t *testing.T, p string) *syntax.Prog {
		t.Helper()
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", p, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("Compile(%q): %v", p, err)
		}
		return prog
	}

	// Non-ASCII only → rejected.
	if !needsUnicodeSupport(mkProg(t, `\p{Greek}`)) {
		t.Error("needsUnicodeSupport(\\p{Greek}) = false, want true")
	}
	// Pure ASCII → accepted.
	if needsUnicodeSupport(mkProg(t, `[a-z]`)) {
		t.Error("needsUnicodeSupport([a-z]) = true, want false")
	}
	// MIXED ASCII + non-ASCII → rejected. This case asserted `false` until
	// 2026-09-01, which is precisely the silent divergence it hid: `[a-zé]+`
	// on "zzé" returned [0,2) where Go returns [0,4), because the engine
	// truncated é to a byte and the old `hasNonASCII && !hasASCII` gate let
	// the pattern through. Such a pattern now needs byte_mode.
	if !needsUnicodeSupport(mkProg(t, `[a-é]`)) {
		t.Error("needsUnicodeSupport([a-é]) = false, want true")
	}
	// The fold artifact, which must NOT be rejected: Go's parser expands
	// `(?i)` over a class eagerly, so this arrives carrying U+017F and
	// U+212A — runes the pattern never wrote, manufactured from its own
	// ASCII `s` and `k`. Rejecting it would reject `(?i)` over any letter
	// class.
	if needsUnicodeSupport(mkProg(t, `(?i:[a-z])`)) {
		t.Error("needsUnicodeSupport((?i:[a-z])) = true, want false")
	}
	// The same phenomenon reached through inst.Arg's FoldCase rather than an
	// expanded class.
	if needsUnicodeSupport(mkProg(t, `(?i)k`)) {
		t.Error("needsUnicodeSupport((?i)k) = true, want false")
	}
	// Byte mode moves the limit to 0xFF, not beyond it.
	if unsupportedRune(mkProg(t, `[a\x80]`), true) >= 0 {
		t.Error("unsupportedRune([a\\x80], byteMode) rejected, want accepted")
	}
	if got := unsupportedRune(mkProg(t, `[α-ω]`), true); got < 0 {
		t.Error("unsupportedRune([α-ω], byteMode) accepted, want rejected")
	}
	// A negated class names every rune up to U+0010FFFF and must stay legal
	// in both modes — rejecting it would reject `.` too.
	if needsUnicodeSupport(mkProg(t, `[^,]`)) {
		t.Error("needsUnicodeSupport([^,]) = true, want false")
	}
}

func TestCmdCompile_WithSets(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.wasm")
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `foo\w+`}},
		Sets: []config.SetConfig{
			{Name: "s", Find: "s_all", Patterns: config.PatternSelector{All: true}},
		},
	}
	if err := CmdCompile(cfg, out); err != nil {
		t.Fatalf("CmdCompile(sets): %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.HasPrefix(data, wasmMagic) {
		t.Error("output is not valid WASM")
	}
}

func TestCmdWriteDiagJSON(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p1", Pattern: `foo\w+`},
			{Name: "p2", Pattern: `bar\d+`},
			// Capture-bearing pattern, must be dropped from sets.
			{Name: "p3", Pattern: `(quux)`, GroupsFunc: "qg"},
		},
		Sets: []config.SetConfig{
			{Name: "s1", Find: "s1_all", Patterns: config.PatternSelector{All: true}},
			{Name: "s2", Find: "s2_any", Patterns: config.PatternSelector{Names: []string{"p1", "p2"}}},
		},
	}

	t.Run("no_sets_is_an_error", func(t *testing.T) {
		// It used to return nil: `--diag-json=out.json` on a set-less config
		// wrote no file and said nothing, leaving the user with a missing
		// file and no explanation.
		empty := config.BuildConfig{Regexps: cfg.Regexps}
		err := CmdWriteDiagJSON(empty, "", "")
		if err == nil {
			t.Fatal("expected an error for a config with no sets")
		}
		if !strings.Contains(err.Error(), "no sets") {
			t.Errorf("the error does not say why: %v", err)
		}
	})

	t.Run("file_output", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "diag.json")
		if err := CmdWriteDiagJSON(cfg, "", path); err != nil {
			t.Fatalf("CmdWriteDiagJSON: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Contains(data, []byte(`"patterns_total"`)) {
			t.Errorf("diag JSON missing expected key, got: %s", data)
		}
		if !bytes.Contains(data, []byte(`"capture_bearing"`)) {
			t.Errorf("diag JSON missing capture_bearing key: %s", data)
		}
	})

	t.Run("stdout_output", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdout
		os.Stdout = w
		writeErr := CmdWriteDiagJSON(cfg, "", "-")
		w.Close()
		os.Stdout = orig
		if writeErr != nil {
			t.Fatalf("CmdWriteDiagJSON(stdout): %v", writeErr)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`"patterns_total"`)) {
			t.Errorf("stdout diag missing key: %s", buf.Bytes())
		}
	})
}

// TestCompileLenientAltFindBody exercises the Phase 2a lenient-alternation
// find body in compilePattern, reached when analyseLitChainAltLenient
// succeeds after the strict analysers fail, gated by
// shouldTryLitChainAlt(pattern). The real sql-inject perftest
// pattern's first branch contains a nested (?:OR|AND) alternation
// (OpAlternate), which makes shouldTryLitChainAlt bail out early and keep
// the pattern lit-chain-alt-eligible; confirmed live that
// compile_matrix_test.go's "lenient_alt_find_only" case does NOT trip this
// gate (its second branch's \s* is unbounded with no nested OpAlternate/
// OpQuest, so shouldTryLitChainAlt short-circuits to false first).
func TestCompileLenientAltFindBody(t *testing.T) {
	const pattern = `'\s*(?:OR|AND)\s+[0-9]+\s*=\s*[0-9]+|UNION\s+(?:ALL\s+)?SELECT|'\s*;\s*(?:DROP|TRUNCATE)\s+TABLE`
	if !shouldTryLitChainAlt(pattern) {
		t.Fatalf("shouldTryLitChainAlt(%q) = false, want true (test pattern no longer trips the lit-chain-alt gate)", pattern)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "sql_inject_find"}})
}

// TestCompileTDFARegLimitExceededForced exercises the
// "ok && tt.numRegs > resolveMaxTDFARegs(&buildOpts)" fallback-to-Backtrack
// re-check in compilePattern. Only reachable when
// forceGroupsEngine bypasses the selector's own register estimate (unlike
// TestCompileTDFARegLimit, which goes through the normal, unforced
// selectBestEngine path and so never reaches TDFA construction at all for a
// register-starved MaxTDFARegs).
func TestCompileTDFARegLimitExceededForced(t *testing.T) {
	_, err := compilePattern(
		config.RegexEntry{Pattern: "(a)(b)(c)(d)(e)(f)", GroupsFunc: "g"},
		0, EngineTDFA, CompileOptions{MaxTDFARegs: 1},
	)
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
}

// TestCompileBTStackTooLarge — a past defect. A no-capture find
// pattern shaped like N sequential `(?:(?:$|l)*<literal>)` groups drives the
// Backtracking find-fallback's DFA past MaxDFAStates (the DFA-too-large
// gate that routes it to Backtracking), and btAllocSizes' stackSize formula
// (65536·N·(N+1) for this exact shape) past WASM32's 4GiB linear-memory
// ceiling at N=256. Before the fix this silently returned a WASM module
// whose memory section was already invalid (fails at
// wasmtime.NewModule/instantiation time); Compile must now reject it.
//
// Superseded by a past defect (checkBTLoopCount): this exact pattern
// shape's stackSize growth is driven by the same per-loop frameSize term
// that also drives its Backtracking-JIT cost, so N=256's 256 loop-frame
// locals now trip the earlier, more specific ErrBTLoopCountTooLarge before
// the stack-size arithmetic in checkBTMemoryBudget is even reached — not
// ErrBTStackTooLarge anymore. checkBTMemoryBudget's own mechanism is
// unchanged and still guards other pattern shapes that reach a large
// stackSize without a large loop count.
func TestCompileBTStackTooLarge(t *testing.T) {
	pattern := strings.Repeat(`(?:(?:$|l)*llllllll0)`, 256)
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true)
	if !errors.Is(err, ErrBTLoopCountTooLarge) {
		t.Fatalf("Compile: err = %v, want ErrBTLoopCountTooLarge", err)
	}
}

// TestCompileBTStackWithinBudget — originally confirmed the same pattern
// shape at a size just under the 4GiB ceiling (N=255) still compiled
// successfully. a past defect supersedes that expectation: N=255 has
// 255 loop-frame locals, an isolated live measurement of which cost ~12s of
// wasmtime JIT time (see checkBTLoopCount's doc) — legitimately fitting
// under WASM32's memory ceiling does not mean it is safe to compile, and
// checkBTLoopCount now correctly rejects it for that independent reason
// before checkBTMemoryBudget's arithmetic is reached.
func TestCompileBTStackWithinBudget(t *testing.T) {
	pattern := strings.Repeat(`(?:(?:$|l)*llllllll0)`, 255)
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true)
	if !errors.Is(err, ErrBTLoopCountTooLarge) {
		t.Fatalf("Compile: err = %v, want ErrBTLoopCountTooLarge", err)
	}
}

// TestCompileBTLoopCountTooLarge — a past defect
// (tools/fuzz/testdata/fuzz/FuzzCorrectness/092700-8c386fe83b176a61, itself
// a bug-31 regression-corpus entry that still crashed real `-fuzz` fuzzing
// via an unbounded wasmtime JIT-time cost). N=114 sequential repeats is the
// natural boundary — N=113 still compiles, N=114 falls to Backtracking, whose
// loop-frame locals trip checkBTLoopCount before wasmtime ever sees the
// module.
//
// The loop is `(?:$|l)*`, not the fuzz repro's `$*`: a repeat whose body only
// asserts is removed before any engine sees the pattern
// (collapseZeroWidthRepeats), so `$*` no longer reaches Backtracking at all.
// `(?:$|l)*` keeps the nullable loop and the boundary, measured live at
// 113/114.
func TestCompileBTLoopCountTooLarge(t *testing.T) {
	pattern := strings.Repeat(`(?:(?:$|l)*llllllll0)`, 114)
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true)
	if !errors.Is(err, ErrBTLoopCountTooLarge) {
		t.Fatalf("Compile: err = %v, want ErrBTLoopCountTooLarge", err)
	}
}

// TestCompileBTLoopCountWithinBudget confirms N=113 of the same pattern
// shape — one repeat short of the DFA-state-cap crossing — still compiles
// successfully via the primary DFA path, unaffected by checkBTLoopCount
// (which only runs once a pattern actually reaches Backtracking
// construction).
func TestCompileBTLoopCountWithinBudget(t *testing.T) {
	pattern := strings.Repeat(`(?:(?:$|l)*llllllll0)`, 113)
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

// TestCompileBTEmptyBodyLoopChainTooLarge — a past defect
// (tools/fuzz/found/20260815-142901, five repros of
// `(?m:$*$*...$*0$)`-shaped patterns). 16 chained `$*` compiles fine (well
// under checkBTLoopCount's JIT-time cap) but takes over a second of
// wasmtime *runtime* find-call time on a single-byte non-matching input —
// checkBTEmptyBodyLoopChain now rejects it at Compile() time instead.
//
// The witness loop is `(?:$|a)*`: that repro's `$*` is now removed by
// collapseZeroWidthRepeats (see TestCompileFuzzRepro143548), and a body that
// can also consume a byte keeps the chain in front of the guard.
func TestCompileBTEmptyBodyLoopChainTooLarge(t *testing.T) {
	pattern := `(?m:` + strings.Repeat(`(?:$|a)*`, 16) + `0$)`
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 65536, true)
	if !errors.Is(err, ErrBTEmptyBodyLoopChainTooLarge) {
		t.Fatalf("Compile: err = %v, want ErrBTEmptyBodyLoopChainTooLarge", err)
	}
}

// TestCompileBTEmptyBodyLoopChainWithinBudget confirms a chain of the same
// loops exactly at maxBTEmptyBodyGreedyLoops still compiles successfully.
func TestCompileBTEmptyBodyLoopChainWithinBudget(t *testing.T) {
	pattern := `(?m:` + strings.Repeat(`(?:$|a)*`, maxBTEmptyBodyGreedyLoops) + `0$)`
	_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 65536, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

// TestCompileFuzzRepro143548 directly regression-tests the fuzz-discovered
// hang:
// tools/fuzz/found/20260815-142901/143548-4c06db1f6419e310 and four
// byte-identical-root-cause siblings all hung `go test -fuzz` on
// `(?m:$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*0$)` (16 chained `$*`) against a
// single-byte input, because compiling it succeeded but each `find` call
// took over a second — with no bound, since this project's "runtime over
// compile time" design principle means find-mode calls have no watchdog in
// production. checkBTEmptyBodyLoopChain first rejected it at Compile() time.
//
// It now COMPILES: every `$*` repeats a body that only asserts, so
// collapseZeroWidthRepeats removes the whole chain and the pattern is `0$`,
// which never reaches Backtracking. The refusal was the mitigation; this is
// the fix, and the find call it produces costs 48 fuel on the repro's input.
func TestCompileFuzzRepro143548(t *testing.T) {
	pattern := `(?m:$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*$*0$)`
	if _, _, err := Compile([]config.RegexEntry{{Pattern: pattern, FindFunc: "find"}}, 65536, true); err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

// TestCompileFuzzRepro092700 directly regression-tests the fuzz-discovered
// crash: tools/fuzz/testdata/fuzz/FuzzCorrectness/
// 092700-8c386fe83b176a61 crashed `go test -fuzz` because compiling
// `(?:$*llllllll0){200}` succeeded but took ~6s of wasmtime JIT time with
// no bound, exceeding the fuzz worker's hang-classification threshold under
// coverage-instrumentation and multi-worker CPU contention. checkBTLoopCount
// now rejects it at Compile() time instead, which tools/fuzz's existing
// ErrBTProgramTooLarge/ErrBTStackTooLarge skip (fuzz_targets_test.go) is extended to
// also skip on. The loop is `(?:$|l)*` for TestCompileBTLoopCountTooLarge's
// reason: the repro's own `$*` is now collapsed before any engine sees it.
func TestCompileFuzzRepro092700(t *testing.T) {
	_, _, err := Compile([]config.RegexEntry{{Pattern: `(?:(?:$|l)*llllllll0){200}`, FindFunc: "find"}}, 65536, true)
	if !errors.Is(err, ErrBTLoopCountTooLarge) {
		t.Fatalf("Compile: err = %v, want ErrBTLoopCountTooLarge", err)
	}
}

// TestCollapseZeroWidthRepeats pins the rewrite that keeps a chain of repeated
// assertions off Backtracking's exponential empty-body-loop path. It asserts
// meaning rather than the printed form: Regexp.String owns the spelling, and a
// rewrite that prints differently but finds the same matches is still right.
func TestCollapseZeroWidthRepeats(t *testing.T) {
	collapsible := []string{
		`(?m:$*$*$*$*$*$*$*$*$*$*)*0$`,
		"(?m:$*$*$*$*$*$*$*$*$*$*<*)*\t$*$",
		"(?m:$*$*$*$*$*$*$*$*)*$*$*$*\x01*\x01$",
		`(?m:$*$*$*$*$*$*$*$*$*$*)*$dd*`,
		`(?m:$*0*$*\x01*$*$*$*$$*0*$*$*)*$*$* $*$`,
		`(?m:$*$*$*$*$*$*$+$+$*$*)*$*0$`,
		`a\b*b`,
		`a\b+b`,
		`x(?:^|$)+y`,
		`(?:\b\B)?z`,
		`(?:(?:)*)+q`,
		`a$*?b`,
		`a\b{2,5}\w`,
		`a\b{0,3}\w`,
	}
	kept := []string{
		`(\b)*a`,     // a capture group records where it matched
		`(?:$|a)*b`,  // the body can consume a byte
		`a*`,         // nothing zero-width at all
		`\b\w+\b`,    // assertions, but none repeated
		`(?:\b|x?)+`, // x? consumes
	}
	inputs := []string{"", "0", "D", "0\n", "\n0\n", "ab", "a b", "xy", "x\ny", "q", "z", "a\x01\n", "\t$", "dd", "a0b\n0"}

	for _, pat := range collapsible {
		out := collapseZeroWidthRepeats(pat)
		if out == pat {
			t.Errorf("%q: not rewritten", pat)
			continue
		}
		re, err := syntax.Parse(out, syntax.Perl)
		if err != nil {
			t.Errorf("%q -> %q: does not parse: %v", pat, out, err)
			continue
		}
		if collapseZeroWidthRepeatsRe(re) {
			t.Errorf("%q -> %q: still holds a repeat of a zero-width body", pat, out)
		}
		want, got := regexp.MustCompile(pat), regexp.MustCompile(out)
		for _, in := range inputs {
			if w, g := want.FindAllStringIndex(in, -1), got.FindAllStringIndex(in, -1); !slices.EqualFunc(w, g, slices.Equal) {
				t.Errorf("%q -> %q over %q: matches %v, want %v", pat, out, in, g, w)
			}
		}
	}
	for _, pat := range kept {
		if out := collapseZeroWidthRepeats(pat); out != pat {
			t.Errorf("%q: rewritten to %q, want it untouched", pat, out)
		}
	}
}

// TestCompileNestedEmptyBodyLoopChain is the fuzz-found shape: a chain of `$*`
// under an outer `*`. Bug 34's cap counts the loops but was calibrated on a
// flat chain, and nesting made the same count exponential again; with the
// repeats collapsed the pattern is `0$` and must compile without reaching
// Backtracking's loop guards at all.
func TestCompileNestedEmptyBodyLoopChain(t *testing.T) {
	pattern := `(?m:$*$*$*$*$*$*$*$*$*$*$*)*0$`
	for _, entry := range []config.RegexEntry{
		{Pattern: pattern, FindFunc: "f"},
		{Pattern: pattern, MatchFunc: "m"},
	} {
		if _, _, err := Compile([]config.RegexEntry{entry}, 65536, true); err != nil {
			t.Errorf("Compile(%+v): %v", entry, err)
		}
	}
}

// TestCompileBTCaptureWithMemoTwoGroups exercises the useMemo=true
// initialization block in buildBacktrackBody for the capture path.
// TestCompileBTCaptureWithMemo's pattern ((?:a?)+?) has a
// single capture spanning the whole pattern (MaxCap()==1) and is not
// itself ^-anchored, so the whole-pattern-single-capture shortcut
// (compile.go, isWholePatternSingleCapture) now intercepts it before it
// ever reaches TDFA/BT selection — confirmed live via isAnchoredFind/
// isWholePatternSingleCapture probing. ((?:a?)+?)(b) has two capture
// groups, so the shortcut's MaxCap()==1 requirement fails and the pattern
// reaches Backtracking's needsBitState=true memo-init path as originally
// intended.
func TestCompileBTCaptureWithMemoTwoGroups(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "((?:a?)+?)(b)", GroupsFunc: "g"}})
}

// TestCompileEmbeddedLitAnchorTableMemIdx exercises the tableMemIdx = 1
// branch (!standalone) inside both the single-pattern lit-anchor and the
// alt-lit-anchor dispatch-body-generation paths in assembleModule.
// All existing lit-anchor/alt-lit-anchor tests use
// standalone=true; this compiles the same pattern shapes with
// standalone=false.
func TestCompileEmbeddedLitAnchorTableMemIdx(t *testing.T) {
	wasm, _, err := Compile([]config.RegexEntry{
		{Pattern: `[0-9]{8}ghp_[^\s]+`, FindFunc: "f1"},
		{Pattern: `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`, FindFunc: "f2"},
	}, 0, false)
	if err != nil {
		t.Fatalf("Compile(embedded lit-anchor): %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatal("output is not a valid WASM module")
	}
}

// TestCmdCompile_ErrorPaths exercises the four distinct error/IO branches in
// CmdCompile.
func TestCmdCompile_ErrorPaths(t *testing.T) {
	t.Run("compile_file_error_with_sets", func(t *testing.T) {
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{{Name: "bad", Pattern: `[`}},
			Sets: []config.SetConfig{
				{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
			},
		}
		if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "out.wasm")); err == nil {
			t.Fatal("expected CompileFile error, got nil")
		}
	})
	t.Run("compile_error_no_sets", func(t *testing.T) {
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{{Pattern: "[", MatchFunc: "m"}},
		}
		if err := CmdCompile(cfg, filepath.Join(t.TempDir(), "out.wasm")); err == nil {
			t.Fatal("expected Compile error, got nil")
		}
	})
	t.Run("stdout_write_failure", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		w.Close() // both ends closed before use — write to w now fails safely, no SIGPIPE
		orig := os.Stdout
		os.Stdout = w
		cfg := config.BuildConfig{Regexps: []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}}}
		compErr := CmdCompile(cfg, "-")
		os.Stdout = orig
		if compErr == nil {
			t.Fatal("expected stdout write error, got nil")
		}
	})
	t.Run("write_file_failure", func(t *testing.T) {
		cfg := config.BuildConfig{Regexps: []config.RegexEntry{{Pattern: "abc", MatchFunc: "m"}}}
		badPath := filepath.Join(t.TempDir(), "nonexistent-dir", "out.wasm")
		if err := CmdCompile(cfg, badPath); err == nil {
			t.Fatal("expected os.WriteFile error, got nil")
		}
	})
}

// TestCmdWriteDiagJSON_DroppedPatternError exercises the analyzePattern
// error path in CmdWriteDiagJSON, propagated as `continue` (silently
// dropping the pattern from the set's diagnostics).
func TestCmdWriteDiagJSON_DroppedPatternError(t *testing.T) {
	// This test asserted the DEFECT until 2026-09-09. It required
	// CmdWriteDiagJSON to skip an unparseable pattern and write a clean
	// diagnostics file anyway, while CompileFile treats the same pattern as
	// FATAL — so a config that cannot build produced a diagnostics file
	// describing a set with the broken pattern quietly missing from it.
	//
	// The property is AGREEMENT: whatever the build does with a pattern, the
	// file describing that build must do the same. Both now fail, with the
	// same message, because both go through setPatternInfos.
	t.Run("unbuildable pattern fails BOTH", func(t *testing.T) {
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Name: "bad", Pattern: `[`},
				{Name: "good", Pattern: `foo`},
			},
			Sets: []config.SetConfig{
				{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
			},
		}
		_, _, buildErr := CompileFile(cfg, "")
		if buildErr == nil {
			t.Fatal("CompileFile accepted an unparseable set member; " +
				"this case no longer tests the divergence it is named for")
		}
		dir := t.TempDir()
		diagErr := CmdWriteDiagJSON(cfg, "", filepath.Join(dir, "diag.json"))
		if diagErr == nil {
			t.Fatal("CmdWriteDiagJSON succeeded where CompileFile failed: a config " +
				"that cannot build must not produce a clean diagnostics file")
		}
		if diagErr.Error() != buildErr.Error() {
			t.Errorf("diag error %q differs from build error %q; they share "+
				"setPatternInfos precisely so they cannot diverge", diagErr, buildErr)
		}
	})

	// A pattern legitimately DROPPED from a set — capture-bearing members are
	// excluded by design — must still produce a diagnostics file, and say so.
	t.Run("capture-bearing pattern is dropped, not fatal", func(t *testing.T) {
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Name: "caps", Pattern: `(foo)(bar)`, GroupsFunc: "g"},
				{Name: "good", Pattern: `foo`},
			},
			Sets: []config.SetConfig{
				{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}},
			},
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "diag.json")
		if err := CmdWriteDiagJSON(cfg, "", path); err != nil {
			t.Fatalf("CmdWriteDiagJSON: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Contains(data, []byte(`"patterns_total": 2`)) {
			t.Errorf("diag JSON missing expected patterns_total: %s", data)
		}
	})
}

// TestCompileAutoSelectEngine exercises the `else { engineType =
// selectBestEngine(prog, &options) }` branch in compile() — calling the
// private compile() helper WITHOUT an explicit ForceEngine, unlike every
// production caller (which always sets ForceEngine: EngineDFA).
func TestCompileAutoSelectEngine(t *testing.T) {
	t.Run("backtrack_via_inverted_class_gate", func(t *testing.T) {
		// <([^>]+)> routes to Backtrack via the inverted-class ambiguity gate
		// (see CLAUDE.md "Load-bearing engine-selection gates").
		if _, err := compile(`<([^>]+)>`); err != nil {
			t.Fatalf("compile: %v", err)
		}
	})
	t.Run("plain_dfa", func(t *testing.T) {
		if _, err := compile(`a{500}`); err != nil {
			t.Fatalf("compile: %v", err)
		}
	})
}

// TestCompileBTCaptureBudgetIncludesMemoTable — a past defect. The BT
// capture path checked only the stack against WASM32's 4GiB ceiling, then
// went on to reserve the BitState memo table (up to MemoBudget) and, for
// patterns needing true-input edge context, an 8-byte (origPtr,origEnd)
// scratch. A reservation whose stack ended just below the ceiling therefore
// passed the check yet declared memory past it — a past defect’s
// failure mode again (a generic wasmtime instantiation error instead of a
// clear compile error).
//
// 245 `((a|b)*)` repeats put the BT capture stack at ~4.02GB, which alone
// still fits under the ceiling; the trailing `(a*)*` is the only part that
// makes needsBitState true, so the 512MB memo table is exactly what pushes
// the reservation over. MemoBudget is raised from its 128KB default purely
// to make that window wide enough to hit with a pattern that stays under
// checkBTLoopCount and maxBTFallbackInstructions.
func TestCompileBTCaptureBudgetIncludesMemoTable(t *testing.T) {
	const stackOnly = 245 // repeats; ~4.02GB of BT capture stack
	// BTWorkBudgetOff: with the work budget on, EVERY Backtracking program
	// reserves the memo for its fallback body, so the control below would
	// carry a memo table too and there would be nothing to contrast. Off, the
	// memo is reserved only where the fast body needs it (needsBitState), which
	// is the distinction this test is about.
	opts := CompileOptions{MemoBudget: 512 << 20, BTWorkBudget: BTWorkBudgetOff}

	// Control: identical stack, but no zero-width loop → no memo table →
	// the reservation fits and compilation succeeds.
	ctrl := config.RegexEntry{Pattern: strings.Repeat(`((a|b)*)`, stackOnly), GroupsFunc: "g"}
	if _, err := compilePattern(ctrl, 0, EngineBacktrack, opts); err != nil {
		t.Fatalf("control (no memo table): %v", err)
	}

	// Same stack plus a memo-requiring tail: the memo table takes it past
	// the ceiling and compilation must say so.
	entry := config.RegexEntry{Pattern: ctrl.Pattern + `(a*)*`, GroupsFunc: "g"}
	if _, err := compilePattern(entry, 0, EngineBacktrack, opts); !errors.Is(err, ErrBTStackTooLarge) {
		t.Fatalf("compilePattern: err = %v, want ErrBTStackTooLarge", err)
	}
}

// TestUnsupportedRuneRejection pins the contract the byte-mode parameter and
// its gate were built for.
//
// regexped is a byte engine, so a rune it cannot hold in a byte used to be
// silently truncated — five verified divergences from Go, of which four were
// reachable through the old `hasNonASCII && !hasASCII` gate. The rule now is:
//
//   - a rune NAMED AS A MEMBER above the mode's limit is a compile error;
//   - the limit is 127 by default and 0xFF under byte_mode;
//   - runes above 0xFF are rejected in both modes, since no byte holds one;
//   - case-fold artifacts of ASCII, and a range whose top endpoint is
//     U+10FFFF, name no member above the limit and stay legal.
func TestUnsupportedRuneRejection(t *testing.T) {
	cases := []struct {
		pattern              string
		rejectDef, rejectByt bool
		why                  string
	}{
		// Written non-ASCII: rejected by default, legal as bytes.
		{`[a-zé]+`, true, false, "é truncated to a byte, [0,2) where Go gives [0,4)"},
		{`\xe9`, true, false, "matched a raw Latin-1 byte where Go matched nothing"},
		{`[a\x80]+`, true, false, "mixed byte escape riding along with ASCII"},
		{`[\x80-\xff]+`, true, false, "a byte range: the capability byte_mode exists to allow"},
		{`[\xc0-\xdf]`, true, false, "UTF-8 two-byte lead range"},

		// Above 0xFF: no byte can hold it, so no mode accepts it.
		{`\p{Greek}+`, true, true, "\\p classes compiled and dropped their runes"},
		{`[α-ω]+`, true, true, "explicit codepoints past the byte range"},
		{`\pL+`, true, true, "reaches past 0xFF even though its low members fit"},

		// Not "written" runes — must stay legal in both modes.
		{`(?i:[a-z]+)`, false, false, "Go expands (?i) classes eagerly: U+017F and U+212A are its artifacts"},
		{`(?i:([a-z]+)@([a-z]+))`, false, false, "same, with captures"},
		{`(?i)^\s*SELECT\b`, false, false, "fold orbit escaping 0xFF from an ASCII literal"},
		{`(?i)k`, false, false, "the Kelvin sign, declared byte semantics"},
		{`(?i)abc`, false, false, "plain ASCII folding"},
		{`[^,]+`, false, false, "a negated class names every rune; rejecting it would reject `.`"},
		// The same class in both spellings. See TestOpenEndedTailSpellings for
		// why no rule can separate them, and the one below for where the line
		// actually falls.
		{`[a-\x{10ffff}]+`, false, false, "an explicit range to U+10FFFF IS the complement of everything below"},
		{"[^\\x00-`]+", false, false, "the same class, spelled as a complement"},
		{`[a-\x{ffff}]+`, true, true, "a top endpoint below U+10FFFF names members no byte holds"},
		{`a.c`, false, false, "dot is one byte, declared byte semantics"},
		{`[a-z]+`, false, false, "plain ASCII"},
		{`\w+`, false, false, "plain ASCII class"},
	}

	compileWith := func(pattern string, byteMode bool) error {
		e := config.RegexEntry{Pattern: pattern, FindFunc: "find", ByteMode: byteMode}
		_, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
		return err
	}

	for _, c := range cases {
		if err := compileWith(c.pattern, false); (err != nil) != c.rejectDef {
			t.Errorf("default mode %q: rejected=%v, want %v (%s) [%v]",
				c.pattern, err != nil, c.rejectDef, c.why, err)
		}
		if err := compileWith(c.pattern, true); (err != nil) != c.rejectByt {
			t.Errorf("byte mode %q: rejected=%v, want %v (%s) [%v]",
				c.pattern, err != nil, c.rejectByt, c.why, err)
		}
	}
}

// TestUnsupportedRuneErrorText checks that a rejection tells the reader which
// of the two situations they are in. The distinction is the whole point: one
// is a flag away, the other is not supported at all, and a single "contains
// Unicode features" message (what this replaced) said neither.
func TestUnsupportedRuneErrorText(t *testing.T) {
	e := config.RegexEntry{Pattern: `[a\x80]+`, FindFunc: "find"}
	_, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), "byte_mode") || !strings.Contains(err.Error(), "U+0080") {
		t.Errorf("a byte-range rejection must name the rune and the way out, got: %v", err)
	}

	e = config.RegexEntry{Pattern: `[α-ω]+`, FindFunc: "find"}
	_, _, err = Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), "byte_mode") {
		t.Errorf("a rune above U+00FF must NOT suggest byte_mode, which cannot help: %v", err)
	}
	if !strings.Contains(err.Error(), "above U+00FF") {
		t.Errorf("expected the above-U+00FF phrasing, got: %v", err)
	}
}

// TestUnicodeOptionStillBypasses guards the escape hatch several selector
// tests depend on. CompileOptions.Unicode does not enable Unicode support —
// nothing implements it — it suppresses the rejection so a Unicode-bearing
// pattern can reach the code under test.
func TestUnicodeOptionStillBypasses(t *testing.T) {
	if _, err := SelectEngine(`[α-ω]+`, CompileOptions{}); err == nil {
		t.Error("SelectEngine([α-ω]+) accepted without the bypass, want rejected")
	}
	if _, err := SelectEngine(`[α-ω]+`, CompileOptions{Unicode: true}); err != nil {
		t.Errorf("SelectEngine([α-ω]+) with Unicode bypass: %v", err)
	}
}

// TestByteModeGateAppliesBeforeFastPaths pins the placement of the gate rather
// than only its rule.
//
// compilePattern chooses between a dozen emitters, and only some of them route
// through compile(), where the gate used to live alone. A literal-chain shape
// carrying a written non-ASCII rune therefore has to be rejected by the check
// at the top of compilePattern — otherwise a pattern's acceptability would
// depend on which emitter it happened to qualify for, which is exactly the
// kind of difference nobody would think to test for.
func TestByteModeGateAppliesBeforeFastPaths(t *testing.T) {
	// A literal chain (analyseLitChain territory) with a byte escape in it.
	for _, p := range []string{`caf\xe9[0-9]{8}`, `\xe9[0-9]{8}`, `AKIA[0-9A-Z\xe9]{16}`} {
		e := config.RegexEntry{Pattern: p, FindFunc: "find"}
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err == nil {
			t.Errorf("default mode %q: accepted, want rejected before the fast path", p)
		}
		e.ByteMode = true
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err != nil {
			t.Errorf("byte mode %q: %v", p, err)
		}
	}
}

// TestOpenEndedTailSpellings pins the boundary of the U+10FFFF exemption and
// the reason it cannot be drawn any tighter.
//
// A review asked for explicit range endpoints (`[a-\x{10ffff}]`) to be
// separated from parser-generated negated-class tails, on the grounds that the
// first is a rune the user wrote. They cannot be separated: Go applies negation
// while PARSING, so the complement spelling and the explicit spelling produce
// one identical AST and one identical rune pair long before this gate runs. A
// rule rejecting the explicit form would reject every negated class with it.
//
// Nor is anything lost by accepting them. The tail SATURATES at 0xFF in both
// modes rather than truncating at the mode's limit, so the class means "every
// byte from the low endpoint up" — exactly what the complement means to a byte
// engine. The accepted byte set is asserted, not just the acceptance: a change
// that truncated the tail at 0x7F would still compile, and would be a silent
// wrong answer.
//
// Where the line DOES fall is the top endpoint. `[a-\x{ffff}]` names members
// no byte can hold and is rejected in both modes.
func TestOpenEndedTailSpellings(t *testing.T) {
	const explicit = `[a-\x{10ffff}]`
	const complement = "[^\\x00-`]"

	// Same AST, so nothing downstream can tell them apart.
	pe, err := syntax.Parse(explicit, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", explicit, err)
	}
	pc, err := syntax.Parse(complement, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", complement, err)
	}
	if pe.String() != pc.String() {
		t.Errorf("%q and %q parse differently (%q vs %q) — the exemption could be narrowed after all",
			explicit, complement, pe.String(), pc.String())
	}

	// Same accepted bytes, saturating at 0xFF, in both modes.
	for _, byteMode := range []bool{false, true} {
		gotE := acceptedByteRange(t, explicit, byteMode)
		gotC := acceptedByteRange(t, complement, byteMode)
		if gotE != gotC {
			t.Errorf("byteMode=%v: %q accepts %s but %q accepts %s — one spelling compiles differently",
				byteMode, explicit, gotE, complement, gotC)
		}
		if want := "61..ff"; gotE != want {
			t.Errorf("byteMode=%v: %q accepts %s, want %s (the tail must saturate, not truncate)",
				byteMode, explicit, gotE, want)
		}
	}

	// And the endpoint below U+10FFFF is still rejected.
	for _, byteMode := range []bool{false, true} {
		e := config.RegexEntry{Pattern: `[a-\x{ffff}]+`, FindFunc: "find", ByteMode: byteMode}
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err == nil {
			t.Errorf("byteMode=%v: [a-\\x{ffff}] accepted, want rejected", byteMode)
		}
	}
}

// acceptedByteRange reports the span of single bytes that reach an accepting
// state from the start state, as "lo..hi".
func acceptedByteRange(t *testing.T, pattern string, byteMode bool) string {
	t.Helper()
	m, err := compile(pattern, CompileOptions{ForceEngine: EngineDFA, LeftmostFirst: true, ByteMode: byteMode})
	if err != nil {
		t.Fatalf("compile %q (byteMode=%v): %v", pattern, byteMode, err)
	}
	tbl := dfaTableFrom(m.(*dfa))
	lo, hi := -1, -1
	for b := 0; b < 256; b++ {
		ns := tbl.transitions[tbl.startState*256+b]
		if ns < 0 {
			continue
		}
		if _, ok := tbl.acceptStates[ns]; !ok {
			continue
		}
		if lo < 0 {
			lo = b
		}
		hi = b
	}
	if lo < 0 {
		return "none"
	}
	return fmt.Sprintf("%02x..%02x", lo, hi)
}

// regexpMinMaxLen's byteMode parameter decides what a literal rune above
// U+007F WEIGHS. Under `byte_mode: true` such a rune means exactly that BYTE
// and consumes one; without it, the rune's UTF-8 encoding is what lands in the
// input and the width is 2, 3 or 4.
//
// Getting it wrong makes the function an OVER-estimate, and every caller reads
// it as a true bound — the exported find wrapper turns the minimum into an
// early exit, so an over-estimate refuses an input that matches.
//
// The end-to-end consequence is pinned in tools/fuzz (TestByteModeLengths-
// AcrossEmitters); this pins the function, so a caller added later cannot be
// misled by a value that was wrong before it ever reached them.
func TestRegexpMinMaxLenByteMode(t *testing.T) {
	for _, tc := range []struct {
		pattern          string
		byteMin, byteMax int
		utf8Min, utf8Max int
		note             string
	}{
		{`\xe9ab`, 3, 3, 4, 4, "one high rune plus two ASCII"},
		{`\xe9\xe9`, 2, 2, 4, 4, "two high runes"},
		{`abc`, 3, 3, 3, 3, "pure ASCII is mode-independent"},
		{`\xe9{2}xy`, 4, 4, 6, 6, "counted repeat multiplies the width"},
		{`\xe9?ab`, 2, 3, 2, 4, "optional high rune moves only the maximum"},
		{`(?:\xe9ab|cd)`, 2, 3, 2, 4, "alternation takes min of mins, max of maxes"},
		// A CLASS is one byte in both modes: the engine consumes a byte per
		// class regardless, so no arm of this function varies for it.
		{`[\x80-\xff]ab`, 3, 3, 3, 3, "class arm is mode-independent"},
		{`[a-z]+`, 1, -1, 1, -1, "unbounded stays unbounded"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			re, err := syntax.Parse(tc.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.pattern, err)
			}
			if gotMin, gotMax := regexpMinMaxLen(re, true); gotMin != tc.byteMin || gotMax != tc.byteMax {
				t.Errorf("byteMode=true: got (%d,%d), want (%d,%d) — %s",
					gotMin, gotMax, tc.byteMin, tc.byteMax, tc.note)
			}
			if gotMin, gotMax := regexpMinMaxLen(re, false); gotMin != tc.utf8Min || gotMax != tc.utf8Max {
				t.Errorf("byteMode=false: got (%d,%d), want (%d,%d) — %s",
					gotMin, gotMax, tc.utf8Min, tc.utf8Max, tc.note)
			}
		})
	}
}

// A pattern's minLen must be attached by compilePattern itself, not by one of
// its callers: CompileFile compiles a set config's per-pattern entries through
// the same function, and while minLen was set in compileAll only, those
// entries' find exports silently lost the early exit — the same pattern
// behaving differently depending on whether the config happened to declare a
// set.
func TestCompilePatternAttachesMinLen(t *testing.T) {
	for _, tc := range []struct {
		pattern  string
		byteMode bool
		want     int32
	}{
		{`foobar`, false, 6},
		{`\xe9ab`, true, 3},
		{`[a-z]{4}`, false, 4},
		{`a*`, false, 0}, // matches empty: no early exit to emit
	} {
		entry := configRegexEntryForMinLen(tc.pattern, tc.byteMode)
		p, err := compilePattern(entry, 0, 0, CompileOptions{})
		if err != nil {
			t.Fatalf("compile %q: %v", tc.pattern, err)
		}
		if p == nil {
			t.Fatalf("compile %q: no pattern", tc.pattern)
		}
		if p.minLen != tc.want {
			t.Errorf("%q (byteMode=%v): minLen = %d, want %d",
				tc.pattern, tc.byteMode, p.minLen, tc.want)
		}
	}
}

func configRegexEntryForMinLen(pattern string, byteMode bool) config.RegexEntry {
	return config.RegexEntry{Pattern: pattern, FindFunc: "find", ByteMode: byteMode}
}

// TestParseHints covers parseHints directly (40% covered without this — only
// one of the three outcomes was reached via existing tests).
func TestParseHints(t *testing.T) {
	cases := []struct {
		hints   []string
		want    LikelyMode
		wantSet bool
	}{
		{[]string{"prefer-match"}, LikelyMatch, true},
		{[]string{"prefer-no-match"}, LikelyNoMatch, true},
		{nil, LikelyNeutral, false},
		{[]string{}, LikelyNeutral, false},
		// Unrecognised entries fall through to the neutral/unset default —
		// config.ValidHints is what actually rejects bad YAML at load time.
		{[]string{"unknown"}, LikelyNeutral, false},
	}
	for _, c := range cases {
		mode, set := parseHints(c.hints)
		if mode != c.want || set != c.wantSet {
			t.Errorf("parseHints(%v) = (%v, %v), want (%v, %v)", c.hints, mode, set, c.want, c.wantSet)
		}
	}
}

// TestResolveHints covers resolveHints' precedence chain (75% covered
// without this): the first entry in the chain that expresses an explicit
// choice wins, regardless of position.
func TestResolveHints(t *testing.T) {
	t.Run("first_link_wins", func(t *testing.T) {
		got := resolveHints([]string{"prefer-match"}, []string{"prefer-no-match"})
		if got != LikelyMatch {
			t.Errorf("resolveHints(pattern=match, set=no-match) = %v, want LikelyMatch", got)
		}
	})
	t.Run("falls_through_to_second_link", func(t *testing.T) {
		got := resolveHints(nil, []string{"prefer-no-match"})
		if got != LikelyNoMatch {
			t.Errorf("resolveHints(pattern=unset, set=no-match) = %v, want LikelyNoMatch", got)
		}
	})
	t.Run("neutral_when_nothing_set", func(t *testing.T) {
		got := resolveHints(nil, nil)
		if got != LikelyNeutral {
			t.Errorf("resolveHints(unset, unset) = %v, want LikelyNeutral", got)
		}
	})
	t.Run("no_chain_links", func(t *testing.T) {
		if got := resolveHints(); got != LikelyNeutral {
			t.Errorf("resolveHints() = %v, want LikelyNeutral", got)
		}
	})
}

// TestPatternHintsOverridesCallerLikelyMode verifies the actual wiring in
// compilePattern (compile.go): a pattern's own `hints:` YAML field takes
// precedence over whatever LikelyMode the caller passed in CompileOptions.
// Observed via the same LikelyNoMatch-gated
// buildSimplePrefixCheckBody shortcut TestCompileLikelyNoMatchSimpleClassPrefix
// uses, but this time the mode comes from re.Hints, not CompileOptions,
// which is what's actually under test here.
func TestPatternHintsOverridesCallerLikelyMode(t *testing.T) {
	pattern := `[0-9]{8}ghp_[^\s]+`

	// Caller says neutral, but the pattern's own hint says no-match — the
	// hint must win and take the SIMD-verify shortcut.
	entry := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{"prefer-no-match"}}
	p, err := compilePattern(entry, 0, 0, CompileOptions{LikelyMode: LikelyNeutral})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.litAnchorBackScanBody == nil {
		t.Fatal("expected the lit-anchor path to fire")
	}

	// The reverse: caller says no-match, but the pattern's own hint says
	// neutral — the hint must still win, so the shortcut must NOT fire.
	entryNeutralHint := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{}}
	pNeutral, err := compilePattern(entryNeutralHint, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern (caller no-match, no pattern hint): %v", err)
	}
	// An empty hints list doesn't "set" anything (parseHints returns set=false),
	// so the caller's LikelyNoMatch should still apply here — both bodies
	// should therefore match (this is the non-override case, not
	// a mismatch check like the block above).
	if len(p.litAnchorBackScanBody) == 0 || len(pNeutral.litAnchorBackScanBody) == 0 {
		t.Fatal("expected both compiles to produce a lit-anchor backscan body")
	}

	entryOverride := config.RegexEntry{Pattern: pattern, FindFunc: "f", Hints: []string{"prefer-match"}}
	pOverride, err := compilePattern(entryOverride, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern (caller no-match, pattern hint=match): %v", err)
	}
	if string(pOverride.litAnchorBackScanBody) == string(p.litAnchorBackScanBody) {
		t.Error("pattern hint 'prefer-match' should override the caller's LikelyNoMatch, but the shortcut still fired")
	}
}

// TestSetHintsSelectsShuftiFrontend verifies the wiring in CompileFile
// (set_emit.go): a set's own `hints: [prefer-no-match]` resolves through
// resolveHints(sc.Hints) into CompileSetOptions.LikelyMode, which is what
// TestCompileFile_ShuftiFrontend's "prefer-no-match" hint actually depends
// on. This test isolates that dependency by comparing hinted vs unhinted
// compiles of the identical pattern set directly through CompileSet, reading
// back the chosen frontend (cs.fe) rather than only checking the module
// compiles. The chosen literals' first-byte rarity sum is 66 (> the 40
// shuftiBeatsScalar threshold — digits and uppercase letters are "mid"
// rarity), so density alone would NOT select Shufti; only the LikelyNoMatch
// hint does.
//
// Shufti is only ever reachable through the SCALAR branch, so this test has
// to keep both literal frontends off the table to exercise the hint at all.
// It originally reached Shufti by accident: 33 literals blew the old 32-NODE
// AC cap and were silently demoted to scalar. Two
// measured changes have since taken that route away — the budget now holds a
// real automaton, and above the first-byte crossover bucketed Teddy
// beats AC outright — so the set is built with more literals than
// teddyMaxLiterals and compiled with ACBudgetBytes pinned to 1. What is
// asserted is the hint→LikelyMode→Shufti wiring, not a frontend ranking that
// measurement has overturned twice.
func TestSetHintsSelectsShuftiFrontend(t *testing.T) {
	// LOWERCASE on purpose. This alphabet was digits-and-uppercase until the
	// byte-rarity weights were corrected, at which point the density heuristic
	// started selecting Shufti for it unaided and the "unhinted" arm below
	// stopped asserting anything — rightly, since forcing Shufti on `[A-Z0-9]`
	// measures -79% on prose, so picking it unhinted is the correct call, not
	// a bug. What this test needs is a set the heuristic genuinely declines,
	// and dense lowercase is that set: sum 78 against a threshold of 40, and
	// measured at +13% if Shufti is forced on it.
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	// Above teddyMaxLiterals so Teddy declines; first bytes cycle the 26-char
	// alphabet, keeping the union inside Shufti's 17..64 band.
	n := teddyMaxLiterals + 1
	buildSpec := func(t *testing.T) (SetSpec, *dfaPool, *dfaPool) {
		t.Helper()
		var prefixPool, suffixPool dfaPool
		var patterns []*PatternInfo
		var patternIDs []int
		for i := 0; i < n; i++ {
			pat := fmt.Sprintf("%cq%02dx[a-z]+", alphabet[i%len(alphabet)], i)
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Fatalf("analyzePattern(%q): %v", pat, err)
			}
			patterns = append(patterns, info)
			patternIDs = append(patternIDs, i)
		}
		return SetSpec{Name: "s", Find: "find_all", Patterns: patterns, PatternIDs: patternIDs}, &prefixPool, &suffixPool
	}

	// ACBudgetBytes: 1 puts AC out of budget so the scalar branch — the only
	// place Shufti is selected — is reached. See the doc comment above.
	noAC := func(lm LikelyMode) CompileSetOptions {
		return CompileSetOptions{LikelyMode: lm, ACBudgetBytes: 1}
	}

	specHinted, prefixPool, suffixPool := buildSpec(t)
	csHinted := CompileSet(specHinted, prefixPool, suffixPool, noAC(LikelyNoMatch))
	if csHinted.fe != frontendShufti {
		t.Errorf("CompileSet with LikelyNoMatch: fe = %v, want frontendShufti", csHinted.fe)
	}

	specUnhinted, prefixPool2, suffixPool2 := buildSpec(t)
	csUnhinted := CompileSet(specUnhinted, prefixPool2, suffixPool2, noAC(LikelyNeutral))
	if csUnhinted.fe == frontendShufti {
		t.Error("CompileSet without a LikelyNoMatch hint unexpectedly selected frontendShufti (density heuristic alone shouldn't for this byte set)")
	}

	// The default build takes AC for this set (it is past teddyMaxLiterals),
	// and the hint does not change that. Asserted explicitly so a future
	// change to the budget or to chooseLiteralFrontend surfaces here rather
	// than as a silent frontend downgrade.
	specDefault, prefixPool3, suffixPool3 := buildSpec(t)
	csDefault := CompileSet(specDefault, prefixPool3, suffixPool3, CompileSetOptions{LikelyMode: LikelyNoMatch})
	if csDefault.fe != frontendAC {
		t.Errorf("CompileSet with default budget: fe = %v, want frontendAC", csDefault.fe)
	}
}

// ── The --verbose reporter ─────────────────────────────────────────────────
//
// This is the only output that tells a user their pattern was DEMOTED to
// Backtracking by a state limit, or DROPPED from a set entirely. A dropped
// pattern is the expensive one: a set that does not contain a pattern does not
// report its matches, and nothing else says so.
//
// It is pure formatting over structs, so it is exactly testable — and it was
// almost entirely uncovered, because the unit tests never pass --verbose and
// the harnesses that do never assert on what it prints.

// TestReporterNilSafety pins the contract the compile path depends on: every
// method is nil-safe, so the emitters call them unconditionally and pay one
// nil check when reporting is off. A panic here is a panic in every compile
// that does NOT ask for a report.
func TestReporterNilSafety(t *testing.T) {
	var r *Reporter // nil
	r.Begin("n", "p")
	r.Engine(EngineDFA, "why")
	r.Limit("states", 1, 2)
	r.Note("note")
	r.Reason("reason")
	r.End()
	r.Render(&bytes.Buffer{})
	if r.HasEngine() {
		t.Error("nil Reporter reports HasEngine")
	}

	// Non-nil but with no scope open: same requirement, different branch.
	r2 := &Reporter{}
	r2.Engine(EngineDFA, "why")
	r2.Limit("states", 1, 2)
	r2.Note("note")
	r2.Reason("reason")
	r2.End()
	if r2.HasEngine() {
		t.Error("Reporter with no open scope reports HasEngine")
	}
	if len(r2.Patterns) != 0 {
		t.Errorf("closing an unopened scope recorded %d patterns", len(r2.Patterns))
	}
	// Render on an empty reporter must produce nothing at all, not a header.
	var b bytes.Buffer
	r2.Render(&b)
	if b.Len() != 0 {
		t.Errorf("empty Reporter rendered %q, want nothing", b.String())
	}
	// A nil writer is tolerated too.
	r2.Render(nil)
}

// TestReporterBeginFlushesOpenScope pins the property Begin's comment promises:
// a compile path that returns early between two Begins must not LOSE the first
// record. That is the whole reason Begin calls End.
func TestReporterBeginFlushesOpenScope(t *testing.T) {
	r := &Reporter{}
	r.Begin("first", "a+")
	r.Engine(EngineDFA, "no captures")
	r.Begin("second", "b+") // no End between them
	r.Engine(EngineBacktrack, "captures")
	r.End()
	if len(r.Patterns) != 2 {
		t.Fatalf("got %d patterns, want 2 — an open scope was dropped", len(r.Patterns))
	}
	if r.Patterns[0].Name != "first" || r.Patterns[1].Name != "second" {
		t.Errorf("scopes recorded out of order: %q, %q",
			r.Patterns[0].Name, r.Patterns[1].Name)
	}
}

// TestReporterHasEngine covers the predicate compilePattern uses to decide
// whether a later, more specific gate already named the engine.
func TestReporterHasEngine(t *testing.T) {
	r := &Reporter{}
	r.Begin("n", "p")
	if r.HasEngine() {
		t.Error("HasEngine before any Engine call")
	}
	r.Engine(EngineTDFA, "captures")
	if !r.HasEngine() {
		t.Error("HasEngine false after Engine")
	}
}

// TestReporterRenderPatterns walks every branch of the per-pattern half of
// Render: a named and an unnamed pattern, an engine with and without a reason,
// the no-engine arm in both its spellings, limits, and notes (which are sorted,
// so the emitters need not agree on an order).
func TestReporterRenderPatterns(t *testing.T) {
	r := &Reporter{}
	r.Begin("url", "https?://[^/]+/.*")
	r.Engine(EngineDFA, "no capture groups")
	r.Limit("dfa states", 1030, 1024)
	r.Note("zebra")
	r.Note("alpha")
	r.End()

	r.Begin("", strings.Repeat("x", 80)) // unnamed, and over the 60-col truncation
	r.Engine(EngineBacktrack, "")        // engine with no reason
	r.End()

	r.Begin("litchain", "AKIA[A-Z0-9]{16}")
	r.Reason("literal chain body") // no engine, but a reason
	r.End()

	r.Begin("skipped", "(?:)") // no engine and no reason
	r.End()

	var b bytes.Buffer
	r.Render(&b)
	out := b.String()

	for _, want := range []string{
		"Patterns (4)",
		"url",
		"engine: DFA — no capture groups",
		"limit:  dfa states 1030 of 1024",
		"opts:   alpha, zebra", // sorted, not insertion order
		"(unnamed)",
		"engine: Backtracking\n", // no reason, no em dash
		"engine: literal chain body",
		"engine: none",
		"…", // the truncation marker
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n--- got ---\n%s", want, out)
		}
	}
	// Truncation must cap the pattern column, not merely mark it.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "xxxx") && len(strings.TrimSpace(line)) > 90 {
			t.Errorf("pattern column not truncated: %q", line)
		}
	}
}

// TestReporterRenderSets covers the set half, including the drop lines that
// are the reason this reporter exists.
func TestReporterRenderSets(t *testing.T) {
	r := &Reporter{
		Sets: []SetDiag{{
			Name:         "creds",
			Frontend:     "teddy",
			Capabilities: []string{"find", "scan_any"},
			Overlapping:  true,
			IDSpaceSize:  9, // deliberately != len(Buckets), so the line prints
			Buckets: []BucketDiag{
				{
					ID: 0, Type: "merged", AcceptKind: "bitmask", Literal: "AKIA",
					Patterns: []PatternRef{{ID: 0, Name: "aws"}}, SuffixStates: 12, TableBytes: 340,
				},
				{
					ID: 1, Type: "fallback", AcceptKind: "bitmask", Literal: "",
					Patterns: []PatternRef{{ID: 1}}, SuffixStates: 4, TableBytes: 80,
				},
			},
			StateLimitDropped:     []PatternRef{{ID: 7, Name: "huge"}},
			CaptureBearingDropped: []PatternRef{{ID: 8}}, // unnamed → "#8"
			UnparseableDropped:    []PatternRef{{ID: 9, Name: "bad"}},
			FrontendDemotion:      &FrontendDemotionDiag{From: "ac", To: "shufti", Reason: "budget"},
		}},
	}
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()

	for _, want := range []string{
		`Set "creds"`,
		"frontend:   teddy",
		"capabilities: find, scan_any",
		"overlapping: true",
		"buckets:    2",
		"AKIA",
		"(fallback — no lite…", // truncated to the 24-col bucket-literal width
		"dropped (fallback DFA over max_fallback_states): huge",
		"dropped (capture-bearing): #8", // the unnamed spelling
		"dropped (unparseable): bad",
		"id space:   9",
		"DOWNGRADED frontend:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestReporterRenderSetOmissions is the negative half: the optional lines must
// be ABSENT when they have nothing to say, or the report becomes noise and the
// drop lines stop standing out.
func TestReporterRenderSetOmissions(t *testing.T) {
	r := &Reporter{
		Sets: []SetDiag{{
			Name: "plain", Frontend: "scalar",
			IDSpaceSize: 1,
			Buckets:     []BucketDiag{{ID: 0, Type: "singleton", AcceptKind: "bitmask", Literal: "x"}},
		}},
	}
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()
	for _, unwanted := range []string{
		"capabilities:", "overlapping:", "dropped", "id space:", "DOWNGRADED",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("render includes %q with nothing to report\n--- got ---\n%s", unwanted, out)
		}
	}
}

// TestTruncate pins the helper's boundary, since it decides a column width the
// two Render halves share.
func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcde", 5, "abcde"}, // exactly n is not truncated
		{"abcdef", 5, "ab…"},  // "…" is 3 bytes, so only 2 fit under n=5
		{"", 3, ""},
		// The cut must land on a RUNE boundary. Slicing by byte index here
		// produced "αα\xce…" — a lone lead byte, invalid UTF-8, printed
		// straight to the terminal.
		{"ααααα", 6, "α…"},
		{"日本語です", 9, "日本…"},
		// No room for anything but the marker.
		{"abcdef", 3, "…"},
		{"abcdef", 1, "…"},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// TestVerboseDFAConstructionLimit pins the one --verbose path with no table to
// report on. When newDFA's own ceiling fires, compilePattern holds a nil
// *dfaTable and only the demotion is knowable; reading numStates off it to fill
// the "DFA states N of M" line panicked, so `compile --verbose` crashed on
// exactly the pattern the flag exists to explain.
func TestVerboseDFAConstructionLimit(t *testing.T) {
	// Exponential subset construction: `.*a.{14}b` needs a state per
	// 15-byte window, far past newDFA's internal ceiling.
	re := config.RegexEntry{Name: "blowup", Pattern: `(?s).*a.{14}b`, FindFunc: "find"}
	rep := &Reporter{}
	if _, err := compilePattern(re, 0, 0, CompileOptions{Report: rep, MaxDFAStates: 64}); err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if len(rep.Patterns) != 1 {
		t.Fatalf("reported %d patterns, want 1", len(rep.Patterns))
	}
	got := rep.Patterns[0]
	if got.Engine != EngineBacktrack {
		t.Errorf("engine = %v, want Backtracking", got.Engine)
	}
	if !strings.Contains(got.Reason, "state limit") {
		t.Errorf("reason = %q, want it to name the state limit", got.Reason)
	}
	// No table means no measurement: the limit line must be omitted rather
	// than invented.
	for _, l := range got.Limits {
		if strings.HasPrefix(l, "DFA states") {
			t.Errorf("reported %q with no table constructed", l)
		}
	}
}

func TestIsWholePatternSingleCapture_Accepts(t *testing.T) {
	cases := []string{
		`(\w+)`,
		`\b([a-z]+)\b`,
		`^(.*)$`,
		`(a+)`,
		`^(a+)`,
		`(a+)$`,
	}
	for _, pat := range cases {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("pattern=%q parse: %v", pat, err)
		}
		if !isWholePatternSingleCapture(re) {
			t.Errorf("pattern=%q: expected accept, got reject", pat)
		}
	}
}

func TestIsWholePatternSingleCapture_Rejects(t *testing.T) {
	cases := []string{
		`(a)(b)`,
		`((a))`,
		`x(a+)`,
		`(a+)x`,
		`(?m)^(a)$`,
		`a+`,      // no captures at all
		`(a)x(b)`, // multiple captures, neither spans the whole match
		`x(a+)y`,  // capture sandwiched between non-zero-width literals
	}
	for _, pat := range cases {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("pattern=%q parse: %v", pat, err)
		}
		if isWholePatternSingleCapture(re) {
			t.Errorf("pattern=%q: expected reject, got accept", pat)
		}
	}
}

// A groups export whose capture group can never participate — `(?:(a){0})` —
// gets NO capture body, so there is nothing for the exported
// (ptr, len, out_ptr, from) wrapper to call. Emitting one anyway produced a
// call to function index -1, which wasm-tools rejects as "function index out
// of bounds".
//
// Found by `make groupsonly` on the RE2 corpus, at case 3931250 — the only
// configuration that compiles capture patterns with groups_func alone. Kept
// because the guard it checks is easy to drop again: three places (funcCount,
// the layout, the export/code sections) all have to agree that the wrapper is
// absent, and disagreeing produces a module that only fails at load.
// The guard is not optional politeness. Without it, `exec.Command` fails with
// "executable file not found in $PATH", CombinedOutput returns EMPTY, and every
// case reports `INVALID: ` with nothing after the colon — a module the compiler
// never got wrong, condemned by a missing validator. That is exactly how this
// read in GitHub Actions, where wasm-tools is not preinstalled: ten identical
// failures including plain `(a)`. The same guard is in the matrix sweeps and
// tools/fuzz/set_caps_test.go, and this was the one place in compile/
// that shelled out without it.
func TestGroupsWrapperValidWithoutCaptureBody(t *testing.T) {
	if _, err := exec.LookPath("wasm-tools"); err != nil {
		t.Skip("wasm-tools not in PATH: cannot validate the emitted modules")
	}
	// The two identical entries this loop used to build were a leftover from
	// `named_groups_func`, now retired — every pattern was
	// compiled and validated twice with the same config.
	pats := []string{`(?:(a){0})`, `(a){0}`, `(a)`, `\A(a)(b)`, `\b(?P<x>a)`}
	validated := 0
	for _, pat := range pats {
		w, _, err := Compile([]config.RegexEntry{{Pattern: pat, GroupsFunc: "groups"}}, 65536, true)
		if err != nil {
			// A FAILURE, not a logged note. These are fixtures the compiler is
			// expected to handle; treating a compile error as "skip this one"
			// let a regression take every fixture out of the run while the
			// test still passed.
			t.Errorf("%-12q compile: %v", pat, err)
			continue
		}
		f := t.TempDir() + "/m.wasm"
		if err := writeFile(f, w); err != nil {
			t.Fatal(err)
		}
		out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
		if vErr != nil {
			// vErr as well as out: a validation failure puts its
			// diagnostic in out, but a failure to RUN the validator
			// leaves out empty and says everything in vErr. Reporting
			// only out is what made the CI failure unreadable.
			t.Errorf("%-12q INVALID: %v\n%s", pat, vErr, out)
			continue
		}
		validated++
	}
	// The coverage this test claims, asserted rather than assumed: without it
	// a run that validated NOTHING is indistinguishable from a clean one.
	if validated != len(pats) {
		t.Errorf("validated %d of %d fixtures; the wrapper-validity coverage is incomplete",
			validated, len(pats))
	}
}

func writeFile(p string, b []byte) error {
	return os.WriteFile(p, b, 0644)
}

// twinLayout builds a find layout the way compilePattern does, with
// lnmAction5 set as a prefer-no-match compile would set it.
func twinLayout(t *testing.T, pattern string, lnm bool) (*dfaLayout, *dfaTable) {
	t.Helper()
	m, err := compile(pattern, CompileOptions{
		MaxDFAStates: 4096, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile(%q): %v", pattern, err)
	}
	table := dfaTableFrom(m.(*dfa))
	l := buildDFALayout(dfaLayoutParams{
		t: table, tableBase: 0, needFind: true, leftmostFirst: true,
		compiledDFAThreshold: resolveCompiledDFAThreshold(&CompileOptions{}),
	})
	l.lnmAction5 = lnm
	return l, table
}

// TestFindNeutralTwinEmission pins WHEN a neutral twin is emitted and, just as
// importantly, when it is not.
//
// The twin exists so the adaptive dense switch can hand the rest of a call to a
// body with no gate at all, rather than paying two instructions per attempt for
// the remainder — ~40,000 of them on a 50 KB scan. It is worth emitting only
// where that switch exists, so the predicate here and the one inside
// emitPrefixScan have to agree; they are the same call to shuftiPrefixPlan for
// that reason.
//
// Both DISPATCH SHAPES are covered on purpose. `[a-zA-Z]{20,}` stays under the
// 256-state threshold and compiles through the hybrid (Compiled DFA) body;
// `[a-zA-Z]{300,}` does not, and takes the plain table-driven one. The two are
// separate emitters with separate params literals, and a field filled in only
// one of them is exactly how the chain probe and soleMidDominant each went
// silently dead on their own target pattern earlier.
func TestFindNeutralTwinEmission(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		lnm      bool
		wantTwin bool
		hybrid   bool
	}{
		{"hybrid, hinted", `[a-zA-Z]{20,}`, true, true, true},
		{"hybrid, neutral", `[a-zA-Z]{20,}`, false, false, true},
		{"plain dfa, hinted", `[a-zA-Z]{300,}`, true, true, false},
		{"plain dfa, neutral", `[a-zA-Z]{300,}`, false, false, false},
		// A mandatory literal fronts the scan, so there is no dense switch to
		// escape from and nothing to hand off to.
		{"mandatory literal", `ERROR[a-zA-Z]{20,}`, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, table := twinLayout(t, tc.pattern, tc.lnm)
			if l.useHybridDispatch != tc.hybrid {
				t.Fatalf("useHybridDispatch = %v, want %v — the case no longer "+
					"covers the dispatch shape it was written for",
					l.useHybridDispatch, tc.hybrid)
			}
			_, _, twin, patch := appendFindCodeEntryTwinned(
				nil, l, table, findMandatoryLit(tc.pattern, false), 0)
			if (twin != nil) != tc.wantTwin {
				t.Errorf("twin emitted = %v, want %v", twin != nil, tc.wantTwin)
			}
			// The twin and its handoff call-site patch are emitted together or
			// not at all; compilePattern panics on the mismatch, so the pairing
			// is worth asserting where it is cheap to.
			if (twin != nil) != (patch >= 0) {
				t.Errorf("twin=%v but patch offset=%d — the two must agree",
					twin != nil, patch)
			}
			if twin != nil && len(twin) == 0 {
				t.Error("twin is non-nil but empty")
			}
		})
	}
}
