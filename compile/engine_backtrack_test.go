package compile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp/syntax"
	"strconv"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
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
// Go's regexp compiler never produces InstRune1 with FoldCase (it expands case-
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
	// (?i:a) compiled with BT engine exercises btCheckRune1 with isFold=true;
	// the empty group gives groups_func a capture group.
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(?i:a)()", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
	)
	if err != nil {
		t.Fatalf("CompileForced((?i:a) BT): %v", err)
	}
}

// TestBTCompileDeterminism guards against a class of bug found and fixed
// 2026-08-06: the Backtracking bodies emitted per-loop instructions by ranging
// over a map, and Go randomizes map iteration order per process, so the same
// pattern could compile to different (same-length) WASM bytes across runs —
// mirrors TestTDFACompileDeterminism, which guards the equivalent fix already
// made in the TDFA engine. The per-loop state is gone; the test stays as a
// guard on every Backtracking body shape.
func TestBTCompileDeterminism(t *testing.T) {
	cases := []struct {
		name string
		re   config.RegexEntry
		opts []CompileOptions
	}{
		// buildBacktrackBody (capture path): a non-greedy loop wrapping a
		// capture — a zero-width cycle, so the fallback body alone.
		{"capture_loop_snapshot", config.RegexEntry{Pattern: "((a?)*?)", GroupsFunc: "g"}, nil},
		// buildBacktrackBody: 4 quantified sub-expressions.
		{"capture_multi_loop", config.RegexEntry{Pattern: `(?i)(\bOR\b|\bAND\b)\s+[0-9]+\s*=\s*[0-9]+`, GroupsFunc: "g"}, nil},
		// buildBTMatchBody (no-capture match, forced via DFA-too-large
		// fallback): 2 independent loops.
		{"match_bt_multi_loop", config.RegexEntry{Pattern: "[a-z]+[0-9]+", MatchFunc: "m"}, []CompileOptions{{MaxDFAStates: 1}}},
		// buildBTFindBody, mandatory-literal branch (no-capture find,
		// forced via DFA-too-large fallback): loops on both sides of a
		// mandatory interior literal.
		{"find_bt_mandlit", config.RegexEntry{Pattern: "[a-z]+SECRET[0-9]+", FindFunc: "f"}, []CompileOptions{{MaxDFAStates: 1}}},
		// buildBTFindBody, general-scan (OnMatch closure) branch: same
		// loop shape but no mandatory literal to anchor the scan.
		{"find_bt_no_mandlit", config.RegexEntry{Pattern: "[a-z]+[0-9]+", FindFunc: "f"}, []CompileOptions{{MaxDFAStates: 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first, _, err := Compile([]config.RegexEntry{c.re}, 0, true, c.opts...)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			const iterations = 20
			for i := 0; i < iterations; i++ {
				got, _, err := Compile([]config.RegexEntry{c.re}, 0, true, c.opts...)
				if err != nil {
					t.Fatalf("iteration %d: Compile: %v", i+1, err)
				}
				if !bytes.Equal(first, got) {
					t.Errorf("iteration %d: WASM output differs from first (BT emission non-deterministic)", i+1)
				}
			}
		})
	}
}

// TestBTZeroWidthCycleGroupsCompile compiles a capture program with a
// zero-width cycle, which gets the fallback body alone. ((a?)*?) has a nested
// capture group ((a?) inside the outer capture), so MaxCap()==2 — the
// whole-pattern-single-capture shortcut (which requires MaxCap()==1) does not
// intercept it, unlike its close cousin ((?:a?)+?).
func TestBTZeroWidthCycleGroupsCompile(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "((a?)*?)", GroupsFunc: "g"}})
}

// TestBTNonLoopAltPushContinue exercises the plain-alternation (non-loop
// InstAlt) push-frame-and-continue path in emitBTInstHandler.
// (a)\B(?:x|y): the capture plus \B word-boundary force Backtracking (both
// are TDFA-exclusion gates in selectBestEngine); (?:x|y) is a non-loop
// InstAlt.
func TestBTNonLoopAltPushContinue(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a)\B(?:x|y)`, GroupsFunc: "g"}})
}

// TestBTWordBoundaryFalse exercises the \B case dispatch and the
// wantBoundary=false fail-if-boundary-present logic in btWordBoundary.
// A second capture group ((c)) is added to the doc's original
// (a)\B suggestion: confirmed live that (a)\B alone (MaxCap==1, one capture
// spanning past a zero-width-only assertion) trips the whole-pattern-
// single-capture shortcut and never reaches BT capture compilation at all;
// the second group makes isWholePatternSingleCapture reject it.
func TestBTWordBoundaryFalse(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a)\B(c)`, GroupsFunc: "g"}})
}

// TestBTInstNop exercises the InstNop case in emitBTInstHandler, only
// reachable when the NFA program contains an InstNop (emitted by
// regexp/syntax.Compile for an empty alternation branch). As
// with the previous test, a second capture group is added: (a|)\B alone (MaxCap==1) trips
// the whole-pattern shortcut (confirmed live), so (a|)\B(c) is used instead —
// confirmed live to still produce an InstNop instruction and route to
// Backtracking.
func TestBTInstNop(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(a|)\B(c)`, GroupsFunc: "g"}})
}

// TestBTInvertedClassNonASCIISkip exercises the Unicode-range skip
// (if lo > 0x7F { continue/return }) in btCheckRuneRanges/btEmitSingleRange,
// triggered by an inverted class whose compiled ranges include a
// [0xE000, 0x10FFFF]-style tail. This is exactly the pattern
// family CLAUDE.md's "Load-bearing engine-selection gates" section
// documents (hasAmbiguousCaptures routes inverted-class captures to
// Backtracking, deliberately, not a bug).
func TestBTInvertedClassNonASCIISkip(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `<([^>]+)>`, GroupsFunc: "g"}})
}

// TestBTInstCaptureNoCapturesFallback exercises the InstCapture no-captures
// branch end-to-end via the no-capture match/find BT fallback path
// (compilePattern's DFA-too-large fallback). Go's
// syntax.Compile always emits an implicit group-0 InstCapture even though
// no user captures are requested (MatchFunc/FindFunc only); MaxDFAStates: 1
// forces the DFA-too-large fallback to Backtracking.
func TestBTInstCaptureNoCapturesFallback(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[^a]+", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// TestNfaFirstBytesCaseFold exercises the case-insensitive alt-byte
// computation in nfaFirstBytes, for both a singleton (InstRune1) and a
// class (InstRune) instruction, plus the len(firstBytes)==0 && !allBytes
// branch for an entirely-non-ASCII first-byte set. Existing
// TestNfaFirstBytes cases have no (?i) at all.
func TestNfaFirstBytesCaseFold(t *testing.T) {
	t.Run("singleton_fold", func(t *testing.T) {
		prog := compileBTTestProg(t, "(?i)cat|dog")
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Fatalf("nfaFirstBytes((?i)cat|dog): allBytes = true, want false")
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range []byte{'c', 'C', 'd', 'D'} {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes((?i)cat|dog): missing fold byte %q", b)
			}
		}
	})
	t.Run("class_fold", func(t *testing.T) {
		prog := compileBTTestProg(t, "(?i)[a-c]+")
		first, _, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Fatalf("nfaFirstBytes((?i)[a-c]+): allBytes = true, want false")
		}
		firstSet := make(map[byte]bool)
		for _, b := range first {
			firstSet[b] = true
		}
		for _, b := range []byte{'a', 'A', 'b', 'B', 'c', 'C'} {
			if !firstSet[b] {
				t.Errorf("nfaFirstBytes((?i)[a-c]+): missing fold byte %q", b)
			}
		}
	})
	t.Run("all_non_ascii", func(t *testing.T) {
		// This subtest asserted `want empty` until 2026-09-09, which was
		// asserting the defect. An empty set with allBytes == false makes
		// buildBTScanTables emit an all-zero 256-byte flag table — "no byte
		// can begin a match" — so the pattern could never match anything at
		// all. The set feeds a PREFILTER, where omitting a byte skips valid
		// start positions; 0x80..0xFF is the honest answer for a class that
		// admits exactly those bytes.
		prog := compileBTTestProg(t, `[^\x00-\x7F]+`)
		first, flags, allBytes := nfaFirstBytes(prog)
		if allBytes {
			t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): allBytes = true, want false (first-byte set entirely non-ASCII)")
		}
		if len(first) != 128 {
			t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): got %d first bytes, want 128 (0x80..0xFF)", len(first))
		}
		for b := 0; b < 0x80; b++ {
			if flags[b] != 0 {
				t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): ASCII byte %#02x flagged, want unflagged", b)
			}
		}
		for b := 0x80; b < 0x100; b++ {
			if flags[b] == 0 {
				t.Errorf("nfaFirstBytes([^\\x00-\\x7F]+): byte %#02x unflagged, want flagged", b)
			}
		}
	})
}

// TestBTFindMandatoryLitCluster exercises the per-attempt reset, the memo
// placement and the overflowFind closure inside buildBTFindBody's
// mandLit != nil branch. [a-z]{1,3}SECRET(?:b?)*? has: a
// variable-offset mandatory literal "SECRET" (minOff=1, maxOff=3, so it
// isn't a trivial fixed-offset literal-chain prefix), a loop on both sides,
// and a zero-width cycle (a non-greedy loop over an optional body), so the
// body built is the memoised fallback.
// MaxDFAStates: 1 forces the DFA-too-large fallback to BT find.
func TestBTFindMandatoryLitCluster(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{1,3}SECRET(?:b?)*?", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// ---------------------------------------------------------------------------
// Shared helpers for this file. All prefixed enginesCov so they cannot collide
// with helpers other coverage files add to package compile.
// ---------------------------------------------------------------------------

// enginesCovParse parses pattern with Perl flags, exactly as compilePattern
// does, so a helper under test sees the same AST the compiler would hand it.
func enginesCovParse(t *testing.T, pattern string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	return re
}

// enginesCovProg parses and compiles pattern to NFA bytecode the same way
// compilePattern/SelectEngine do (Simplify before Compile), so PC numbering in
// a test matches what the selector actually analyses.
func enginesCovProg(t *testing.T, pattern string) *syntax.Prog {
	t.Helper()
	prog, err := syntax.Compile(enginesCovParse(t, pattern).Simplify())
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	return prog
}

// enginesCovFindInst returns the PC of the first instruction with op, failing
// the test when there is none. Tests use it instead of a hardcoded PC so a
// change in Go's NFA layout does not silently make a case test nothing.
func enginesCovFindInst(t *testing.T, prog *syntax.Prog, op syntax.InstOp) int {
	t.Helper()
	for pc, inst := range prog.Inst {
		if inst.Op == op {
			return pc
		}
	}
	t.Fatalf("no %v instruction in prog:\n%v", op, prog)
	return -1
}

// ---------------------------------------------------------------------------
// lit_anchor.go — prefix-shape predicates
//
// These four predicates gate the lit-anchor find optimisation. They are pure
// functions over the parsed AST, and every one of them is a SAFETY gate: a
// false negative only costs speed, but a false positive emits a backward scan
// that stops at the wrong byte. Testing them directly is
// the only way to reach the branches that no perftest/re2 corpus pattern
// happens to have the shape for.
// ---------------------------------------------------------------------------

func TestEnginesCovCanConsumeNewline(t *testing.T) {
	// A nil subtree is what stripLeadingLineAnchor returns on rejection; the
	// caller feeds that straight back in, so nil must answer "cannot consume".
	if canConsumeNewline(nil) {
		t.Error("canConsumeNewline(nil) = true, want false")
	}

	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		// Assertions consume nothing at all.
		{"begin_text", `^`, false},
		{"word_boundary", `\b`, false},
		// A literal only consumes '\n' when it literally contains one. Both
		// halves matter: the loop must scan every rune, not just the first.
		{"literal_without_nl", `abc`, false},
		{"literal_with_nl_last", "ab\n", true},
		// Char classes are tested by range containment, so a class whose range
		// straddles '\n' (0x0a) counts even though it never spells it out.
		{"class_excluding_nl", `[a-z]`, false},
		{"class_spanning_nl", `[\x09-\x0b]`, true},
		{"negated_class_includes_nl", `[^a]`, true},
		// `.` is OpAnyCharNotNL by default and OpAnyChar under (?s) — the
		// entire point of the distinction for this predicate.
		{"dot_default", `.`, false},
		{"dot_dotall", `(?s).`, true},
		// Containers recurse into their subexpressions.
		{"star_of_safe_class", `[a-z]*`, false},
		{"alternate_with_nl_branch", "(?:a|\n)", true},
		{"capture_of_safe_literal", `(abc)`, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			re := enginesCovParse(t, testCase.pattern)
			if got := canConsumeNewline(re); got != testCase.want {
				t.Errorf("canConsumeNewline(%q) = %v, want %v (parsed as %v)",
					testCase.pattern, got, testCase.want, re.Op)
			}
		})
	}

	// Unknown ops answer true (conservative). The switch names every op the
	// parser can produce, so the default arm is only reachable from a node
	// whose Op is not a valid syntax.Op at all — a zero-valued *syntax.Regexp
	// being the realistic way that happens. "Might consume a newline" is the
	// answer that keeps the caller from claiming a stretch never crosses a
	// line boundary on the strength of a node it did not understand.
	unknown := &syntax.Regexp{}
	if !canConsumeNewline(unknown) {
		t.Error("canConsumeNewline(unhandled op) = false, want true (must stay conservative)")
	}
}

func TestEnginesCovStripLeadingLineAnchor(t *testing.T) {
	if rest, ok := stripLeadingLineAnchor(nil); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(nil) = (%v, %v), want (nil, false)", rest, ok)
	}

	// A bare anchor strips to OpEmptyMatch — the "nothing follows it" case
	// lineAnchoredPrefixSafe then declares safe.
	rest, ok := stripLeadingLineAnchor(enginesCovParse(t, `^`))
	if !ok || rest == nil || rest.Op != syntax.OpEmptyMatch {
		t.Fatalf("stripLeadingLineAnchor(`^`) = (%v, %v), want (OpEmptyMatch, true)", rest, ok)
	}

	// A capture wrapping the anchor must be seen through: `(^)` is the same
	// prefix shape as `^` for the backward scan.
	captured := &syntax.Regexp{
		Op:  syntax.OpCapture,
		Sub: []*syntax.Regexp{{Op: syntax.OpBeginLine}},
	}
	rest, ok = stripLeadingLineAnchor(captured)
	if !ok || rest == nil || rest.Op != syntax.OpEmptyMatch {
		t.Fatalf("stripLeadingLineAnchor(capture of ^) = (%v, %v), want (OpEmptyMatch, true)", rest, ok)
	}

	// Concat: the anchor is replaced by OpEmptyMatch and the tail preserved,
	// so canConsumeNewline can be asked about the tail alone.
	rest, ok = stripLeadingLineAnchor(enginesCovParse(t, `^ab`))
	if !ok || rest == nil || rest.Op != syntax.OpConcat {
		t.Fatalf("stripLeadingLineAnchor(`^ab`) = (%v, %v), want (OpConcat, true)", rest, ok)
	}
	if canConsumeNewline(rest) {
		t.Error("stripped `^ab` tail reports it can consume a newline")
	}

	// An empty concat has no leading element to inspect; rejecting it keeps
	// the caller from indexing Sub[0] on nothing.
	if rest, ok := stripLeadingLineAnchor(&syntax.Regexp{Op: syntax.OpConcat}); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(empty concat) = (%v, %v), want (nil, false)", rest, ok)
	}

	// No leading anchor at all → rejected.
	if rest, ok := stripLeadingLineAnchor(enginesCovParse(t, `ab`)); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(`ab`) = (%v, %v), want (nil, false)", rest, ok)
	}
}

func TestEnginesCovPrefixContainsWordBoundary(t *testing.T) {
	if prefixContainsWordBoundary(nil) {
		t.Error("prefixContainsWordBoundary(nil) = true, want false")
	}
	cases := []struct {
		pattern string
		want    bool
	}{
		{`\b`, true},            // the node itself
		{`\B`, true},            // the negated form counts too
		{`a\bb`, true},          // found by recursing into a concat
		{`(?:x(?:y\Bz))`, true}, // found several levels down
		{`abc`, false},
		{`[a-z]+`, false},
	}
	for _, testCase := range cases {
		re := enginesCovParse(t, testCase.pattern)
		if got := prefixContainsWordBoundary(re); got != testCase.want {
			t.Errorf("prefixContainsWordBoundary(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
}

func TestEnginesCovPrefixContainsLineAnchor(t *testing.T) {
	if prefixContainsLineAnchor(nil) {
		t.Error("prefixContainsLineAnchor(nil) = true, want false")
	}
	cases := []struct {
		pattern string
		want    bool
	}{
		{`(?m:^)`, true},
		{`(?m:$)`, true},
		{`(?m:a^b)`, true}, // reached by recursion, not at the root
		{`^abc`, false},    // \A is OpBeginText, not a LINE anchor
		{`abc`, false},
	}
	for _, testCase := range cases {
		re := enginesCovParse(t, testCase.pattern)
		if got := prefixContainsLineAnchor(re); got != testCase.want {
			t.Errorf("prefixContainsLineAnchor(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
}

func TestEnginesCovSimpleClassPrefix(t *testing.T) {
	// The shape simpleClassPrefix exists for: a fixed-count class run.
	tlo, count, ok := simpleClassPrefix(enginesCovParse(t, `[a-f]{3}`))
	if !ok || count != 3 {
		t.Fatalf("simpleClassPrefix(`[a-f]{3}`) = (_, %d, %v), want (_, 3, true)", count, ok)
	}
	// 'a' = 0x61 → low nibble 1, high nibble 6, so bit 6 of tlo[1] must be set.
	if tlo[0x1]&(1<<6) == 0 {
		t.Errorf("simpleClassPrefix(`[a-f]{3}`) Teddy low table missing 'a': tlo = %v", tlo)
	}

	// A capture around the whole repeat, and around the repeated element, are
	// both transparent — the emitted scan is identical either way.
	if _, count, ok := simpleClassPrefix(enginesCovParse(t, `([a-f]{3})`)); !ok || count != 3 {
		t.Errorf("simpleClassPrefix(capture of repeat) = (_, %d, %v), want (_, 3, true)", count, ok)
	}
	capturedChild := &syntax.Regexp{
		Op: syntax.OpRepeat, Min: 2, Max: 2,
		Sub: []*syntax.Regexp{{
			Op:  syntax.OpCapture,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'z'}}},
		}},
	}
	if _, count, ok := simpleClassPrefix(capturedChild); !ok || count != 2 {
		t.Errorf("simpleClassPrefix(repeat of captured literal) = (_, %d, %v), want (_, 2, true)", count, ok)
	}

	rejects := []struct {
		name string
		re   *syntax.Regexp
	}{
		// Unbounded / mismatched counts are not a fixed-width prefix.
		{"open_ended", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 1, Max: -1,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}},
		}},
		// A repeat node with no child cannot be inspected; the guard keeps
		// re.Sub[0] from panicking on a malformed/synthesised tree.
		{"repeat_without_child", &syntax.Regexp{Op: syntax.OpRepeat, Min: 2, Max: 2}},
		// An empty char class sets no bits, so there is no byte the SIMD
		// prefix scan could ever match — emitting a scan for it would make
		// every position a candidate.
		{"empty_char_class", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpCharClass}},
		}},
		// Non-ASCII is out of scope: the tables are 128-entry.
		{"non_ascii_class", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpCharClass, Rune: []rune{0x100, 0x200}}},
		}},
		{"multi_rune_literal", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a', 'b'}}},
		}},
		{"unsupported_child_op", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpAnyChar}},
		}},
	}
	for _, testCase := range rejects {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, ok := simpleClassPrefix(testCase.re); ok {
				t.Errorf("simpleClassPrefix(%s) accepted, want rejected", testCase.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// counted_chain.go — isCountedClassChain
//
// The detector runs over an already-built *dfaTable, so a synthetic table is
// both the cheapest and the most precise way to test each rejection: it pins
// the exact table property being rejected instead of hoping some pattern
// compiles to it.
// ---------------------------------------------------------------------------

// enginesCovChainTable builds a linear N-step chain over byteClass starting at
// state 0, ending in an accepting terminal state N with no live transitions —
// the exact shape isCountedClassChain is meant to accept.
func enginesCovChainTable(steps int, byteClass []byte) *dfaTable {
	numStates := steps + 1
	transitions := make([]int, numStates*256)
	for slot := range transitions {
		transitions[slot] = -1
	}
	for state := 0; state < steps; state++ {
		for _, classByte := range byteClass {
			transitions[state*256+int(classByte)] = state + 1
		}
	}
	return &dfaTable{
		startState:            0,
		numStates:             numStates,
		acceptStates:          map[int]uint64{steps: 1},
		midAcceptStates:       map[int]uint64{steps: 1},
		midAcceptNWStates:     map[int]uint64{},
		midAcceptWStates:      map[int]uint64{},
		midAcceptNLStates:     map[int]uint64{},
		immediateAcceptStates: map[int]uint64{},
		transitions:           transitions,
	}
}

func TestEnginesCovIsCountedClassChain(t *testing.T) {
	class := []byte{'a', 'b', 'c'}

	t.Run("accepts_exact_chain", func(t *testing.T) {
		got, n, ok := isCountedClassChain(enginesCovChainTable(4, class))
		if !ok || n != 4 {
			t.Fatalf("isCountedClassChain(4-step chain) = (_, %d, %v), want (_, 4, true)", n, ok)
		}
		if !bytes.Equal(got, class) {
			t.Errorf("recovered class = %v, want %v", got, class)
		}
	})

	// The accept channels are NOT interchangeable, and the split below is the
	// whole point of the split (tools/fuzz FuzzSet; custom-sets.txt Category
	// S10). The emitted body verifies N class bytes with SIMD and reports a
	// match with no end-of-input test and no knowledge of the preceding byte —
	// so it is sound only for a terminal that accepts at an ARBITRARY
	// position. midAccept and immediateAccept mean exactly that. acceptStates
	// (end-of-input only) and the three boundary-gated channels do not: `.$`
	// accepted through the EOF channel reported a match at EVERY position,
	// yielding [0-1] and [1-2] over "00" where Go yields [1-2] alone.
	acceptsAnywhereChannels := []struct {
		name string
		set  func(*dfaTable, int)
	}{
		{"midAccept", func(table *dfaTable, s int) { table.midAcceptStates[s] = 1 }},
		{"immediateAccept", func(table *dfaTable, s int) { table.immediateAcceptStates[s] = 1 }},
	}
	for _, channel := range acceptsAnywhereChannels {
		t.Run("terminal_accepts_via_"+channel.name, func(t *testing.T) {
			table := enginesCovChainTable(3, class)
			delete(table.acceptStates, 3)
			delete(table.midAcceptStates, 3)
			channel.set(table, 3)
			if _, n, ok := isCountedClassChain(table); !ok || n != 3 {
				t.Errorf("chain accepting only via %s = (_, %d, %v), want (_, 3, true)", channel.name, n, ok)
			}
		})
	}

	positionDependentChannels := []struct {
		name string
		set  func(*dfaTable, int)
	}{
		{"acceptStates_eof_only", func(table *dfaTable, s int) { table.acceptStates[s] = 1 }},
		{"midAcceptNW", func(table *dfaTable, s int) { table.midAcceptNWStates[s] = 1 }},
		{"midAcceptW", func(table *dfaTable, s int) { table.midAcceptWStates[s] = 1 }},
		{"midAcceptNL", func(table *dfaTable, s int) { table.midAcceptNLStates[s] = 1 }},
	}
	for _, channel := range positionDependentChannels {
		t.Run("rejects_terminal_accepting_only_via_"+channel.name, func(t *testing.T) {
			table := enginesCovChainTable(3, class)
			delete(table.acceptStates, 3)
			delete(table.midAcceptStates, 3)
			channel.set(table, 3)
			if _, _, ok := isCountedClassChain(table); ok {
				t.Errorf("a terminal accepting only via %s was accepted; the fixed-N "+
					"SIMD body has no end-of-input test and cannot see the preceding "+
					"byte, so it would report this match at every position", channel.name)
			}
		})
	}

	t.Run("rejects_no_accept_bits", func(t *testing.T) {
		// bits == 0: nothing accepts anywhere, so there is no chain length to
		// report and the walk would run to the terminal and claim success.
		table := enginesCovChainTable(3, class)
		delete(table.acceptStates, 3)
		delete(table.midAcceptStates, 3)
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("table with no accepting state accepted, want rejected")
		}
	})

	t.Run("rejects_multi_pattern_bucket", func(t *testing.T) {
		// Two distinct pattern bits means a merged bucket: the detector does
		// not track per-pattern chains, so it must decline.
		table := enginesCovChainTable(3, class)
		table.acceptStates[3] = 0b11
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("two-pattern accept mask accepted, want rejected")
		}
	})

	t.Run("rejects_cycle", func(t *testing.T) {
		// A self-loop is `{N,}`, not `{N}` — walking it would never terminate
		// without the visited check.
		table := enginesCovChainTable(2, class)
		for _, classByte := range class {
			table.transitions[1*256+int(classByte)] = 1
		}
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("self-looping table accepted, want rejected")
		}
	})

	t.Run("rejects_chain_over_maxchain", func(t *testing.T) {
		// The 256-step cap bounds both the walk and the unrolled emission the
		// caller would produce from the result.
		if _, _, ok := isCountedClassChain(enginesCovChainTable(300, class)); ok {
			t.Error("300-step chain accepted, want rejected (maxChain is 256)")
		}
	})

	t.Run("rejects_word_boundary_table", func(t *testing.T) {
		table := enginesCovChainTable(3, class)
		table.hasWordBoundary = true
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("hasWordBoundary table accepted, want rejected")
		}
	})
}

// ---------------------------------------------------------------------------
// wasm.go — parseDataSegments
//
// Every one of these guards fires only on bytes this compiler did not itself
// emit. They are the difference between an attributable panic and a silent
// mis-parse that hands a later stage the wrong table offsets, so they are
// worth pinning even though the public API cannot reach them.
// ---------------------------------------------------------------------------

func TestEnginesCovParseDataSegments(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		var raw []byte
		raw = appendDataSegment(raw, 4096, []byte{1, 2, 3})
		raw = appendDataSegment(raw, 8192, []byte{9})
		segs := parseDataSegments(raw)
		if len(segs) != 2 {
			t.Fatalf("parseDataSegments: got %d segments, want 2", len(segs))
		}
		if segs[0].offset != 4096 || !bytes.Equal(segs[0].data, []byte{1, 2, 3}) {
			t.Errorf("segment 0 = %+v, want offset 4096 data [1 2 3]", segs[0])
		}
		if segs[1].offset != 8192 || !bytes.Equal(segs[1].data, []byte{9}) {
			t.Errorf("segment 1 = %+v, want offset 8192 data [9]", segs[1])
		}
	})

	t.Run("stops_at_non_active_segment", func(t *testing.T) {
		// Only type-0 (active, memory 0) segments are understood; anything
		// else ends the scan rather than being misread as one.
		raw := append(appendDataSegment(nil, 16, []byte{7}), 0x01)
		segs := parseDataSegments(raw)
		if len(segs) != 1 {
			t.Fatalf("parseDataSegments: got %d segments, want 1 (trailing type-1 must end the scan)", len(segs))
		}
	})

	t.Run("stops_when_offset_opcode_missing", func(t *testing.T) {
		// A type byte with no i32.const behind it is truncated input, not a
		// segment: the scan stops instead of decoding whatever follows.
		if segs := parseDataSegments([]byte{0x00}); segs != nil {
			t.Errorf("parseDataSegments(truncated) = %v, want nil", segs)
		}
		if segs := parseDataSegments([]byte{0x00, 0x42}); segs != nil {
			t.Errorf("parseDataSegments(wrong offset opcode) = %v, want nil", segs)
		}
	})

	t.Run("panics_on_malformed_offset", func(t *testing.T) {
		// 0x80 with no continuation byte is an unterminated SLEB128.
		defer func() {
			if recover() == nil {
				t.Error("parseDataSegments(malformed offset): no panic, want invariant-violation panic")
			}
		}()
		parseDataSegments([]byte{0x00, 0x41, 0x80})
	})

	t.Run("panics_on_malformed_size", func(t *testing.T) {
		// Well-formed offset (0), well-formed 0x0b terminator, unterminated
		// ULEB128 size.
		defer func() {
			if recover() == nil {
				t.Error("parseDataSegments(malformed size): no panic, want invariant-violation panic")
			}
		}()
		parseDataSegments([]byte{0x00, 0x41, 0x00, 0x0b, 0x80})
	})
}

// ---------------------------------------------------------------------------
// compile.go — small public/internal surface
// ---------------------------------------------------------------------------

func TestEnginesCovNeedsUnicodeSupport(t *testing.T) {
	// tools/fuzz pre-filters with this exact predicate, so a wrong answer here
	// silently changes what the fuzzer is allowed to feed the compiler.
	cases := []struct {
		pattern string
		want    bool
	}{
		{`abc`, false},
		{`[a-z]+`, false},
		{`\x80`, true}, // pure-ASCII source text, non-ASCII codepoint
		{`[\x{100}-\x{200}]`, true},
	}
	for _, testCase := range cases {
		got, err := NeedsUnicodeSupport(testCase.pattern)
		if err != nil {
			t.Errorf("NeedsUnicodeSupport(%q): %v", testCase.pattern, err)
			continue
		}
		if got != testCase.want {
			t.Errorf("NeedsUnicodeSupport(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
	if _, err := NeedsUnicodeSupport(`(`); err == nil {
		t.Error("NeedsUnicodeSupport(`(`): no error, want a parse error")
	}
}

func TestEnginesCovCompileForcedRejectsBadEngine(t *testing.T) {
	// forceGroupsEngine only ever selects between the two capture engines;
	// accepting EngineDFA here would silently compile as if nothing had been
	// forced, which is exactly the confusion the guard exists to prevent.
	for _, bad := range []EngineType{EngineDFA, EngineCompiledDFA, EngineType(99)} {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "(a)", GroupsFunc: "g"}}, 0, true, bad)
		if err == nil {
			t.Errorf("CompileForced(forceGroupsEngine=%v): no error, want rejection", bad)
		}
	}
}

func TestEnginesCovCompileForcedHonoursUserOpts(t *testing.T) {
	// The variadic userOpts is how callers combine forcing with a limit; if it
	// were dropped, MaxDFAStates below would be ignored and the pattern would
	// compile on the TDFA path instead of the forced Backtracking one.
	wasm, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
		CompileOptions{MaxDFAStates: 512},
	)
	if err != nil {
		t.Fatalf("CompileForced with userOpts: %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatal("CompileForced with userOpts: output is not a WASM module")
	}
	validateWASM(t, wasm)
}

func TestEnginesCovStripSegCount(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if raw, count := stripSegCount(nil); raw != nil || count != 0 {
			t.Errorf("stripSegCount(nil) = (%v, %d), want (nil, 0)", raw, count)
		}
	})
	t.Run("panics_on_malformed_count", func(t *testing.T) {
		// Only reachable if a caller hands stripSegCount something other than
		// appendDataSegment's own output; the panic is deliberate (see its doc
		// comment) so that a compiler bug cannot degrade into a silent nil.
		defer func() {
			if recover() == nil {
				t.Error("stripSegCount(unterminated LEB128): no panic, want invariant-violation panic")
			}
		}()
		stripSegCount([]byte{0x80})
	})
}

// ---------------------------------------------------------------------------
// selector.go — engine-selection predicates
//
// CLAUDE.md calls these gates load-bearing: relaxing one has caused measured
// regressions. Direct tests pin the exact answer for shapes the corpus does
// not produce, so a future "obviously this is deterministic" edit fails loudly.
// ---------------------------------------------------------------------------

func TestEnginesCovIsAlternationDeterministic(t *testing.T) {
	prog := enginesCovProg(t, `(a)|(b)`)

	// Out-of-range PC: callers index prog.Inst with the value they pass, so a
	// bad PC must be rejected rather than panic.
	if isAlternationDeterministic(prog, len(prog.Inst), false, false) {
		t.Error("isAlternationDeterministic(out-of-range PC) = true, want false")
	}
	// A PC that is not an alternation at all cannot be "deterministic".
	runePC := enginesCovFindInst(t, prog, syntax.InstRune1)
	if isAlternationDeterministic(prog, runePC, false, false) {
		t.Error("isAlternationDeterministic(non-Alt PC) = true, want false")
	}
}

func TestEnginesCovIsEpsilonAccept(t *testing.T) {
	// `(?:\b)?x` puts an InstEmptyWidth on the path to InstMatch; without the
	// InstEmptyWidth arm the walk would stop early and report "not an epsilon
	// accept", which is what feeds isAlternationDeterministic's one-branch-
	// accepts-empty rule.
	prog := enginesCovProg(t, `\b|x`)
	emptyPC := enginesCovFindInst(t, prog, syntax.InstEmptyWidth)
	if !isEpsilonAccept(prog, emptyPC) {
		t.Errorf("isEpsilonAccept(InstEmptyWidth leading to Match) = false, want true\n%v", prog)
	}
}

func TestEnginesCovGetFirstRuneSet(t *testing.T) {
	t.Run("empty_width_is_transparent", func(t *testing.T) {
		// `\bab` — the first-rune set must see through the boundary assertion
		// to 'a', or every word-boundary alternation looks indeterminate.
		prog := enginesCovProg(t, `\bab`)
		emptyPC := enginesCovFindInst(t, prog, syntax.InstEmptyWidth)
		runes := getFirstRuneSet(prog, emptyPC)
		if !runes['a'] {
			t.Errorf("getFirstRuneSet through InstEmptyWidth = %v, want to contain 'a'", runes)
		}
	})

	t.Run("alt_with_unbounded_branch_fails", func(t *testing.T) {
		// The Out branch is InstRuneAny, which cannot be enumerated. The Alt
		// arm must propagate that failure instead of returning just the
		// enumerable half: a partial set would make the alternation look
		// disjoint and route an ambiguous pattern to TDFA (CLAUDE.md, "Load-bearing engine-selection gates").
		// Built by hand because the parser folds every `.|x` spelling of this
		// down to a bare `any` before an InstAlt is ever emitted.
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 2},
				{Op: syntax.InstRuneAny},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		if runes := getFirstRuneSet(prog, 0); len(runes) != 0 {
			t.Errorf("getFirstRuneSet(Alt with un-enumerable branch) = %v, want the empty set", runes)
		}
	})

	t.Run("terminal_ops_fail", func(t *testing.T) {
		// InstFail has no successor and no runes; the default arm answers
		// "cannot enumerate", which the caller reads as the empty set — and an
		// empty set is never treated as disjoint by isAlternationDeterministic.
		failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
		if runes := getFirstRuneSet(failProg, 0); len(runes) != 0 {
			t.Errorf("getFirstRuneSet(InstFail) = %v, want the empty set", runes)
		}
	})

	t.Run("cycle_terminates", func(t *testing.T) {
		// A self-referential Alt must be stopped by the visited set; without
		// it this recurses forever.
		cyclic := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 0},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		runes := getFirstRuneSet(cyclic, 0)
		if !runes['a'] {
			t.Errorf("getFirstRuneSet(self-referential Alt) = %v, want to contain 'a'", runes)
		}
	})
}

func TestEnginesCovEstimateDFAComplexityClampsMultiplier(t *testing.T) {
	// The 3.0 clamp is what keeps a many-branch alternation from producing an
	// absurd state estimate and being rejected before the real DFA is tried.
	analysis := &patternAnalysis{NumInstructions: 100, NumAlternations: 50}
	analysis.estimateDFAComplexity()
	if analysis.EstimatedDFAStates != 300 {
		t.Errorf("EstimatedDFAStates = %d, want 300 (100 instructions × clamped 3.0)",
			analysis.EstimatedDFAStates)
	}
}

func TestEnginesCovSelectBestEngineDebugLogging(t *testing.T) {
	// The debug branch calls printAnalysis and builds a slog record; it is
	// skipped entirely at the default level, so nothing else ever runs it.
	// A wrong field name or a nil deref in there would only ever surface for a
	// user who turned debug logging on.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug logging not enabled after SetDefault; test would not reach the branch")
	}

	// A program with a rune above 0x7F also picks the "Unicode" complexity
	// label, which is only computed on this path. The program is built here,
	// not through the resolver, so its class keeps those runes.
	prog := enginesCovProg(t, `[\x{100}-\x{200}](a)`)
	var opts CompileOptions
	if engine, _ := selectBestEngineWithTDFA(byteProg(prog), &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

// ---------------------------------------------------------------------------
// engine_tdfa.go — epsilon capture walks
//
// Both walks are pure and take an explicit visited set, so the guards can be
// driven exactly. They decide which capture registers a transition writes;
// a walk that returns the wrong ops writes the wrong span, silently.
// ---------------------------------------------------------------------------

func TestEnginesCovTDFAEpsCapOps(t *testing.T) {
	t.Run("falls_back_to_alt_arg", func(t *testing.T) {
		// Out leads to InstFail (no target), so the walk must try Arg. A
		// non-recursing implementation would report "no target" for the whole
		// alternation and lose the Arg branch's capture entirely.
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 2},
				{Op: syntax.InstFail},
				{Op: syntax.InstCapture, Arg: 2, Out: 3},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		target, ops := tdfaEpsCapOps(prog, 0, map[int]bool{})
		if target != 3 {
			t.Fatalf("tdfaEpsCapOps target = %d, want 3 (via Alt.Arg)", target)
		}
		if len(ops) != 1 || !ops[0].open || ops[0].group != 1 {
			t.Errorf("tdfaEpsCapOps ops = %+v, want one open of group 1", ops)
		}
	})

	t.Run("unhandled_op_has_no_target", func(t *testing.T) {
		failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
		if target, ops := tdfaEpsCapOps(failProg, 0, map[int]bool{}); target != -1 || ops != nil {
			t.Errorf("tdfaEpsCapOps(InstFail) = (%d, %v), want (-1, nil)", target, ops)
		}
	})
}

func TestEnginesCovTDFAEpsCapOpsTo(t *testing.T) {
	// InstEmptyWidth on the way to the target must be walked through, and the
	// capture recorded — this is the `\b(x)` shape.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstCapture, Arg: 2, Out: 1},
			{Op: syntax.InstEmptyWidth, Out: 2},
			{Op: syntax.InstRune1, Rune: []rune{'x'}},
		},
		Start: 0,
	}
	ok, ops := tdfaEpsCapOpsTo(prog, 0, 2, map[int]bool{})
	if !ok {
		t.Fatalf("tdfaEpsCapOpsTo through InstEmptyWidth = false, want true")
	}
	if len(ops) != 1 || !ops[0].open || ops[0].group != 1 {
		t.Errorf("tdfaEpsCapOpsTo ops = %+v, want one open of group 1", ops)
	}

	// Already-visited and out-of-range starts must both answer "not found"
	// rather than recursing or indexing out of bounds.
	if ok, _ := tdfaEpsCapOpsTo(prog, 0, 2, map[int]bool{0: true}); ok {
		t.Error("tdfaEpsCapOpsTo(already visited) = true, want false")
	}
	if ok, _ := tdfaEpsCapOpsTo(prog, -1, 2, map[int]bool{}); ok {
		t.Error("tdfaEpsCapOpsTo(negative PC) = true, want false")
	}

	// An op the switch does not handle is not a path to the target.
	failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
	if ok, ops := tdfaEpsCapOpsTo(failProg, 0, 5, map[int]bool{}); ok || ops != nil {
		t.Errorf("tdfaEpsCapOpsTo(InstFail) = (%v, %v), want (false, nil)", ok, ops)
	}

	// A path with no capture on it is found with no ops: from the assertion
	// straight to the consumer.
	if ok, ops := tdfaEpsCapOpsTo(prog, 1, 2, map[int]bool{}); !ok || ops != nil {
		t.Errorf("tdfaEpsCapOpsTo(capture-free path) = (%v, %v), want (true, nil)", ok, ops)
	}
}

// The walker's visited array is stamped with a generation counter rather than
// cleared per call. When the counter wraps, a stamp left by an old generation
// can equal the new one, so every stamp must be cleared first — otherwise the
// PC it names reads as already visited and a reachable target is missed.
func TestEnginesCovEpsWalkerGenerationWrap(t *testing.T) {
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstCapture, Arg: 2, Out: 1},
			{Op: syntax.InstEmptyWidth, Out: 2},
			{Op: syntax.InstRune1, Rune: []rune{'x'}},
		},
		Start: 0,
	}
	w := newEpsWalker(prog)
	w.gen = ^uint32(0) // the next find wraps it
	w.seen[1] = 1      // a stamp from generation 1, the one the wrap lands on
	found, ops := w.find(0, 2)
	if !found {
		t.Fatal("find after the generation wrap missed a reachable target: a stale stamp read as visited")
	}
	if len(ops) != 1 || !ops[0].open || ops[0].group != 1 {
		t.Errorf("ops = %+v, want one open of group 1", ops)
	}
	if w.gen != 1 {
		t.Errorf("generation after the wrap = %d, want 1", w.gen)
	}
}

// ---------------------------------------------------------------------------
// whole_capture.go / mandatory_lit.go / prefix_scan.go — small helpers
// ---------------------------------------------------------------------------

// TestAffixSingleCapture pins the affix shortcut's shape: one capture between
// unfolded literals, and the literals' byte lengths in each mode.
func TestAffixSingleCapture(t *testing.T) {
	for _, c := range []struct {
		pat      string
		unicode  bool
		pre, suf int
		ok       bool
	}{
		{`([^,]+),`, false, 0, 1, true},
		{`<([^>]*)>`, false, 1, 1, true},
		{`key=(\w+)`, false, 4, 0, true},
		{`ab(c*)de`, false, 2, 2, true},
		{`ж(\pL+)жж`, true, 2, 4, true},
		{`(a)`, false, 0, 0, false},       // the whole-pattern shortcut's
		{`x(a)(b)`, false, 0, 0, false},   // two captures
		{`(?i:k)(a)`, false, 0, 0, false}, // a folded literal has no fixed length
		{`(a)b*`, false, 0, 0, false},     // not a literal
		{`a?(b)`, false, 0, 0, false},
		{`x(a)y(b)z`, false, 0, 0, false},
		{`xy`, false, 0, 0, false},
	} {
		re := enginesCovParse(t, c.pat)
		pre, suf, ok := affixSingleCapture(re, c.unicode)
		if ok != c.ok || pre != c.pre || suf != c.suf {
			t.Errorf("affixSingleCapture(%q) = %d, %d, %v; want %d, %d, %v", c.pat, pre, suf, ok, c.pre, c.suf, c.ok)
		}
	}
}

func TestEnginesCovIsWholePatternSingleCapture(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"bare_capture", `(abc)`, true},
		{"anchored_capture", `^(abc)$`, true},
		{"boundary_wrapped_capture", `\b(abc)\b`, true},
		// One capture, but the pattern's root is a quantifier rather than the
		// capture or a concat — the capture's span is then not the whole
		// match, so the shortcut must decline.
		{"starred_capture", `(abc)*`, false},
		// A non-zero-width sibling means the capture is a proper substring.
		{"capture_with_literal_sibling", `x(abc)`, false},
		{"two_captures", `(a)(b)`, false},
		{"no_capture", `abc`, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			re := enginesCovParse(t, testCase.pattern)
			if got := isWholePatternSingleCapture(re); got != testCase.want {
				t.Errorf("isWholePatternSingleCapture(%q) = %v, want %v (root op %v)",
					testCase.pattern, got, testCase.want, re.Op)
			}
		})
	}

	// Two OpCapture siblings that share a group number cannot come from the
	// parser, but the sawCapture guard is what makes the "one capture spans
	// the match" claim safe for any tree the analysers may hand it.
	duplicated := &syntax.Regexp{
		Op: syntax.OpConcat,
		Sub: []*syntax.Regexp{
			{Op: syntax.OpCapture, Cap: 1, Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}}},
			{Op: syntax.OpCapture, Cap: 1, Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'b'}}}},
		},
	}
	if isWholePatternSingleCapture(duplicated) {
		t.Error("isWholePatternSingleCapture(two capture siblings) = true, want false")
	}
}

func TestEnginesCovEmitShuftiPrefixCheckEmptySet(t *testing.T) {
	// The caller's useSIMD gate makes an empty candidate set unreachable in
	// the compiler, but the emitter must still leave a well-typed i32 on the
	// stack — returning nothing would produce a module that fails validation.
	got := emitShuftiPrefixCheck(nil, nil, 9)
	if !bytes.Equal(got, []byte{0x41, 0x00}) {
		t.Errorf("emitShuftiPrefixCheck(empty set) = % x, want 41 00 (i32.const 0)", got)
	}
}

// ---------------------------------------------------------------------------
// engine_backtrack.go — rune-range emission
// ---------------------------------------------------------------------------

func TestEnginesCovBTEmitSingleRangeClampsAboveByteRange(t *testing.T) {
	// btCheckRuneRanges filters lo>0xFF and clamps hi before calling in, so
	// these guards are btEmitSingleRange's own contract rather than a live
	// path. They matter because the emitted comparison runs against a single
	// input BYTE: a lo above 0xFF can never match, and an unclamped hi would
	// emit an SLEB128 constant wider than the byte it is compared with.
	//
	// The bound was 0x7F until 2026-09-09, which truncated every negated class
	// to ASCII on the capture path and lost the whole match for input carrying
	// a byte >= 0x80. It is 0xFF now, which is what the DFA's nfaBuildInputMap
	// has always saturated to.
	if got := btEmitSingleRange(nil, 0x100, 0x200); got != nil {
		t.Errorf("btEmitSingleRange(lo=0x100) emitted % x, want nothing", got)
	}
	clamped := btEmitSingleRange(nil, 'a', 0x200)
	reference := btEmitSingleRange(nil, 'a', 0xFF)
	if !bytes.Equal(clamped, reference) {
		t.Errorf("btEmitSingleRange(hi=0x200) = % x, want the hi=0xFF emission % x", clamped, reference)
	}
	// 0x80..0xFF must survive rather than be clamped away.
	if hi := btEmitSingleRange(nil, 0x80, 0xFF); hi == nil {
		t.Error("btEmitSingleRange(0x80, 0xFF) emitted nothing, want a range check")
	}
	// An empty range matches nothing. The test is one unsigned compare,
	// scratch - lo <= hi - lo, and lo > hi would wrap hi - lo to a bound every
	// byte is under.
	if got := btEmitSingleRange(nil, 'z', 'a'); got != nil {
		t.Errorf("btEmitSingleRange('z', 'a') emitted % x, want nothing", got)
	}
}

// TestBacktrackBodiesHaveNoValueTypedBlocks pins that a Backtracking body's
// per-instruction checks — the byte-range test and the word-boundary test —
// produce no value through a block. wasmtime makes every value-typed block a
// Cranelift variable whose SSA table keeps a slot per block of the function,
// so one per instruction made its compile memory grow with the square of the
// body: a Unicode-mode find of `^..(S........(S)+){70}` (2.8 MB) took 3.4 GB to
// compile. Every shape must have none, the word-boundary one at two sizes.
func TestBacktrackBodiesHaveNoValueTypedBlocks(t *testing.T) {
	uni := CompileOptions{Unicode: true}
	byteMode := CompileOptions{ForceByteMode: true}
	cases := []struct {
		name  string
		entry config.RegexEntry
		opts  CompileOptions
	}{
		{"unicode groups classes", config.RegexEntry{Pattern: `(\pL+)\s(\pN+)`, GroupsFunc: "g"}, uni},
		{"unicode groups dot", config.RegexEntry{Pattern: `(.+)=(.+)`, GroupsFunc: "g"}, uni},
		{"unicode groups fold", config.RegexEntry{Pattern: `(?i)(привет)\s+(мир)`, GroupsFunc: "g"}, uni},
		{"unicode groups word boundary x5", config.RegexEntry{Pattern: `^(?:\b(.)\b ){5}`, GroupsFunc: "g"}, uni},
		{"unicode groups word boundary x40", config.RegexEntry{Pattern: `^(?:\b(.)\b ){40}`, GroupsFunc: "g"}, uni},
		{"unicode find x10", config.RegexEntry{Pattern: `^..(S........(S)+){10}`, FindFunc: "f"}, uni},
		{"byte groups classes and boundaries", config.RegexEntry{Pattern: `([a-z]+)\b(\d+)\B(x)`, GroupsFunc: "g"}, byteMode},
	}
	for _, c := range cases {
		var w []byte
		var err error
		if c.entry.GroupsFunc != "" {
			w, _, err = CompileForced([]config.RegexEntry{c.entry}, 65536, true, EngineBacktrack, c.opts)
		} else {
			w, _, err = Compile([]config.RegexEntry{c.entry}, 65536, true, c.opts)
		}
		if err != nil {
			t.Fatalf("%s: compile %q: %v", c.name, c.entry.Pattern, err)
		}
		if n := wasmValueTypedBlocks(t, w); n != 0 {
			t.Errorf("%s: %q has %d value-typed blocks, want none", c.name, c.entry.Pattern, n)
		}
	}
}

// wasmValueTypedBlocks counts, over every function body of a module, the
// `block` and `loop` instructions whose block type is a value type. It
// decodes every instruction regexped emits and fails the test unless each
// body ends exactly where its size says — a decoding slip must not pass for a
// zero count.
func wasmValueTypedBlocks(t *testing.T, wasm []byte) int {
	t.Helper()
	uleb := func(p *int) uint64 {
		v, n, err := utils.DecodeULEB128(wasm[*p:])
		if err != nil {
			t.Fatalf("bad ULEB128 at %d: %v", *p, err)
		}
		*p += n
		return v
	}
	sleb := func(p *int) {
		_, n, err := utils.DecodeSLEB128(wasm[*p:])
		if err != nil {
			t.Fatalf("bad SLEB128 at %d: %v", *p, err)
		}
		*p += n
	}
	memarg := func(p *int) {
		if uleb(p)&0x40 != 0 { // multi-memory: a memory index follows
			uleb(p)
		}
		uleb(p)
	}
	count := 0
	for pos := 8; pos < len(wasm); {
		id := wasm[pos]
		pos++
		size := int(uleb(&pos))
		end := pos + size
		if id != 10 {
			pos = end
			continue
		}
		for n := uleb(&pos); n > 0; n-- {
			bodyEnd := int(uleb(&pos))
			bodyEnd += pos
			for groups := uleb(&pos); groups > 0; groups-- {
				uleb(&pos)
				pos++
			}
			for pos < bodyEnd {
				op := wasm[pos]
				pos++
				switch {
				case op == 0x02 || op == 0x03 || op == 0x04: // block, loop, if
					bt := wasm[pos]
					switch {
					case bt == 0x40:
						pos++
					case bt >= 0x6F: // a value type
						if op != 0x04 {
							count++
						}
						pos++
					default: // a type index
						sleb(&pos)
						if op != 0x04 {
							count++
						}
					}
				case op == 0x0C || op == 0x0D || op == 0x10 || op == 0xD2 || (op >= 0x20 && op <= 0x26):
					uleb(&pos)
				case op == 0x0E: // br_table
					for k := uleb(&pos) + 1; k > 0; k-- {
						uleb(&pos)
					}
				case op == 0x11: // call_indirect
					uleb(&pos)
					uleb(&pos)
				case op == 0x1C: // select t*
					pos += int(uleb(&pos))
				case op >= 0x28 && op <= 0x3E:
					memarg(&pos)
				case op == 0x3F || op == 0x40:
					uleb(&pos)
				case op == 0x41 || op == 0x42:
					sleb(&pos)
				case op == 0x43:
					pos += 4
				case op == 0x44:
					pos += 8
				case op == 0xD0:
					pos++
				case op == 0xFC:
					switch sub := uleb(&pos); {
					case sub == 8 || sub == 10 || sub == 12 || sub == 14:
						uleb(&pos)
						uleb(&pos)
					case sub == 9 || sub == 11 || sub == 13 || (sub >= 15 && sub <= 17):
						uleb(&pos)
					}
				case op == 0xFD:
					switch sub := uleb(&pos); {
					case sub <= 11 || sub == 92 || sub == 93:
						memarg(&pos)
					case sub == 12 || sub == 13:
						pos += 16
					case sub >= 21 && sub <= 34:
						pos++
					case sub >= 84 && sub <= 91:
						memarg(&pos)
						pos++
					}
				}
			}
			if pos != bodyEnd {
				t.Fatalf("function body decoded past its end: at %d, want %d", pos, bodyEnd)
			}
		}
		if pos != end {
			t.Fatalf("code section decoded to %d, want %d", pos, end)
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// compile.go — Backtracking fallback limits on the ANCHORED-match and
// capture paths.
//
// The match and groups paths carry their own copies of the program-size and
// stack-reservation checks, and an omission there is not hypothetical: it
// produces a module that declares invalid memory or will not load, with no
// attribution.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// engine_backtrack.go — first-byte extraction for the BT find prologue
// ---------------------------------------------------------------------------

func TestEnginesCovNFAFirstBytesCaseFold(t *testing.T) {
	// Go's compiler encodes a case-insensitive literal as InstRune with an
	// ODD-length Rune slice plus the FoldCase flag, so the scan tables are
	// only correct if nfaFirstBytes adds the opposite-case byte itself. Miss
	// it and BT find skips every position whose first byte is the uppercase
	// spelling.
	prog := enginesCovProg(t, `(?i)abc`)
	firstBytes, flags, allBytes := nfaFirstBytes(prog)
	if allBytes {
		t.Fatal("nfaFirstBytes((?i)abc) reported allBytes, want a concrete set")
	}
	if flags['a'] == 0 || flags['A'] == 0 {
		t.Errorf("nfaFirstBytes((?i)abc) = %q, want both cases of 'a'", string(firstBytes))
	}

	// A range spanning both cases folds every member, and folding a byte that
	// is already present must not duplicate it.
	prog = enginesCovProg(t, `(?i)[a-c]x`)
	firstBytes, flags, _ = nfaFirstBytes(prog)
	for _, want := range []byte{'a', 'b', 'c', 'A', 'B', 'C'} {
		if flags[want] == 0 {
			t.Errorf("nfaFirstBytes((?i)[a-c]x) = %q, missing %q", string(firstBytes), string(want))
		}
	}
	seen := map[byte]bool{}
	for _, firstByte := range firstBytes {
		if seen[firstByte] {
			t.Errorf("nfaFirstBytes returned %q twice in %q", string(firstByte), string(firstBytes))
		}
		seen[firstByte] = true
	}
}

func TestEnginesCovNFAFirstBytesFoldedRune1(t *testing.T) {
	// Go's own compiler never emits InstRune1 with FoldCase set (it downgrades
	// to InstRune first), so this arm is only reachable from a hand-built
	// program — but nfaFirstBytes takes any *syntax.Prog, and the arm is the
	// single-rune twin of the InstRune folding above. If it ever stopped
	// folding, a caller supplying such a program would get scan tables that
	// silently skip the opposite case.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstRune1, Rune: []rune{'q'}, Arg: uint32(syntax.FoldCase), Out: 1},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	_, flags, allBytes := nfaFirstBytes(prog)
	if allBytes {
		t.Fatal("nfaFirstBytes(folded InstRune1) reported allBytes")
	}
	if flags['q'] == 0 || flags['Q'] == 0 {
		t.Errorf("nfaFirstBytes(folded InstRune1 'q') did not set both cases: flags['q']=%d flags['Q']=%d",
			flags['q'], flags['Q'])
	}

	// Upper-case input folds the other direction.
	prog.Inst[0].Rune = []rune{'Q'}
	if _, flags, _ = nfaFirstBytes(prog); flags['q'] == 0 || flags['Q'] == 0 {
		t.Errorf("nfaFirstBytes(folded InstRune1 'Q') did not set both cases")
	}

	// A non-letter has no opposite case; the fold must add nothing rather
	// than the byte 32 positions away.
	prog.Inst[0].Rune = []rune{'5'}
	if _, flags, _ = nfaFirstBytes(prog); flags['5'] == 0 || flags['5'-32] != 0 || flags['5'+32] != 0 {
		t.Error("nfaFirstBytes(folded InstRune1 '5') folded a non-letter")
	}
}

func TestEnginesCovBuildBTScanTablesScalarFallback(t *testing.T) {
	var flags [256]byte
	flags['x'] = 1

	// allBytes: every byte can start a match, so the emitted flag table must
	// be all-ones regardless of what the (meaningless) flags argument says.
	_, segs, segCount := buildBTScanTables(nil, flags, true, 0)
	if segCount != 1 || len(segs) == 0 {
		t.Fatalf("buildBTScanTables(allBytes): segCount = %d, len(segs) = %d, want 1 and non-empty", segCount, len(segs))
	}
	parsed := parseDataSegments(segs)
	if len(parsed) != 1 || len(parsed[0].data) != 256 {
		t.Fatalf("buildBTScanTables(allBytes): emitted %d segments, want one 256-byte table", len(parsed))
	}
	for candidate, flag := range parsed[0].data {
		if flag != 1 {
			t.Fatalf("buildBTScanTables(allBytes): table[%d] = %d, want 1", candidate, flag)
		}
	}

	// The other scalar case: no candidate bytes at all. The caller's own
	// flags must be emitted verbatim — synthesising all-ones here would turn
	// a never-matching prefix into a scan that stops at every position.
	params, segs, segCount := buildBTScanTables(nil, flags, false, 0)
	if segCount != 1 {
		t.Fatalf("buildBTScanTables(empty set): segCount = %d, want 1", segCount)
	}
	if params.TeddyLoOff != 0 || params.TeddyHiOff != 0 {
		t.Errorf("buildBTScanTables(empty set) allocated Teddy tables: %+v", params)
	}
	parsed = parseDataSegments(segs)
	if len(parsed) != 1 || len(parsed[0].data) != 256 {
		t.Fatalf("buildBTScanTables(empty set): emitted %d segments, want one 256-byte table", len(parsed))
	}
	if parsed[0].data['x'] != 1 {
		t.Error("buildBTScanTables(empty set) did not emit the caller's flag table")
	}
	if parsed[0].data['y'] != 0 {
		t.Error("buildBTScanTables(empty set) set a byte the caller's flags did not")
	}
}

// TestProgHasZeroWidthCycleRoutesToFallback pins the predicate that decides
// whether a Backtracking program gets an ordinary body, and planBT's use of it:
// under every budget, BTWorkBudgetOff included, a program with a zero-width
// cycle is planned exactly as BTWorkBudgetForceFallback plans every program —
// the ordinary body carries no loop guard, so it could go round such a cycle
// forever. Off gives every other program the ordinary body alone.
func TestProgHasZeroWidthCycleRoutesToFallback(t *testing.T) {
	for _, c := range []struct {
		pattern string
		cycle   bool
	}{
		{`(a*?)*?b`, true},  // the reported shape
		{`^(\w*|)*c`, true}, // loop body matches empty through `|`
		{`(?:(a*?|b))*(b*)b`, true},
		{`((\b)*)*`, true}, // an assertion on the cycle still counts
		{`(a|)+`, true},
		{`^(aa|a)*b`, false}, // every iteration consumes a byte
		{`(a.*?b)(c+)`, false},
		{`([a-zA-Z]+?)\d`, false},
		{`x{3}(y|z)`, false},
	} {
		re, err := syntax.Parse(c.pattern, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		if got := progHasZeroWidthCycle(prog); got != c.cycle {
			t.Errorf("%s: progHasZeroWidthCycle = %v, want %v", c.pattern, got, c.cycle)
			continue
		}
		bt := newBacktrack(byteProg(prog))
		for _, budget := range []int{0, 8} {
			plan := planBT(bt, budget)
			if plan.force != c.cycle || !plan.fallback {
				t.Errorf("%s budget %d: plan = %+v, want force=%v with a fallback", c.pattern, budget, plan, c.cycle)
			}
		}
		plan := planBT(bt, BTWorkBudgetOff)
		if c.cycle && (!plan.force || !plan.fallback) {
			t.Errorf("%s under BTWorkBudgetOff: plan = %+v, want the fallback alone", c.pattern, plan)
		}
		if !c.cycle && (plan.force || plan.fallback) {
			t.Errorf("%s under BTWorkBudgetOff: plan = %+v, want neither", c.pattern, plan)
		}
	}
}

func TestEnginesCovBTWindowedBitState(t *testing.T) {
	// Window mode and the fallback's BitState memo are independent features
	// that meet in one place: the memo row has to be rebased by the window
	// start, or the guard indexes the memo with an absolute position and
	// either aliases another row or runs off the end.
	//
	// `\b` forces Backtracking and window mode (the capture body is composed
	// behind a find wrapper, so it does not see the caller's real ptr/len);
	// the `(?:a*)+` nest is a zero-width cycle, so the body is the fallback.
	pattern := `(\b(?:a*)+b)`
	if !progHasZeroWidthCycle(enginesCovProg(t, pattern)) {
		t.Fatalf("%s has no zero-width cycle — witness pattern no longer has the shape", pattern)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})

	// The same nest with a multiline anchor instead of a word boundary — the
	// other trigger for window mode.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `((?m:^)(?:a*)+b)`, GroupsFunc: "g"}})
}

func TestEnginesCovNFAFirstBytesFoldedRuneRange(t *testing.T) {
	// Go's parser normalises a folded ASCII letter to its UPPERCASE spelling
	// (the minimum of the fold orbit), so the lowercase→uppercase half of
	// nfaFirstBytes' InstRune folding is only reachable from a program built
	// by hand. Both halves have to work: this is the table that decides which
	// positions BT find is allowed to skip, and a missing case means skipping
	// a position where a match really starts.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			// Odd-length Rune slice: the single-rune-at-odd-position shape
			// Go itself emits for `(?i)a`, but spelled lowercase.
			{Op: syntax.InstRune, Rune: []rune{'m'}, Arg: uint32(syntax.FoldCase), Out: 1},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if _, flags, _ := nfaFirstBytes(prog); flags['m'] == 0 || flags['M'] == 0 {
		t.Error("nfaFirstBytes(folded lowercase InstRune) did not set both cases")
	}

	// A digit range under FoldCase must not gain phantom bytes.
	prog.Inst[0].Rune = []rune{'0', '9'}
	_, flags, _ := nfaFirstBytes(prog)
	for candidate := 0; candidate < 256; candidate++ {
		want := byte(0)
		if candidate >= '0' && candidate <= '9' {
			want = 1
		}
		if flags[candidate] != want {
			t.Fatalf("nfaFirstBytes(folded digit range): flags[%d] = %d, want %d",
				candidate, flags[candidate], want)
		}
	}
}

func TestEnginesCovBTComposedCaptureBodyWindowAndMemo(t *testing.T) {
	// Same features as TestEnginesCovBTWindowedBitState, but the capture must
	// NOT span the whole pattern: a whole-pattern single capture takes the
	// whole-capture shortcut and never reaches the composed find+capture body where
	// window mode and the fallback's memo actually meet.
	pattern := `(\b(?:a*)+b)c`
	if !progHasZeroWidthCycle(enginesCovProg(t, pattern)) {
		t.Fatalf("%s has no zero-width cycle — witness pattern no longer has the shape", pattern)
	}
	if isWholePatternSingleCapture(enginesCovParse(t, pattern)) {
		t.Fatalf("%s is a whole-pattern single capture — it would bypass the composed body", pattern)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `((?m:^)(?:a*)+b)c`, GroupsFunc: "g"}})
}

func TestEnginesCovBTNonASCIIRuneRange(t *testing.T) {
	// The BT rune-range check compares a single input BYTE, so a class range
	// that starts above the byte space can never match and must be skipped
	// rather than emitted with a truncated constant that would match the wrong
	// bytes. Only byte mode can hand Backtracking such a range — Unicode mode
	// lowers every class to bytes first — and it does through case folding:
	// `(?i)[k-s]` arrives carrying U+017F (ſ, a fold of s) and U+212A (the
	// Kelvin sign, a fold of k), which the byte gate tolerates as artifacts.
	pattern := `((?i)[k-s]+)x`
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}},
		0, true, EngineBacktrack, CompileOptions{ForceByteMode: true})
	if err != nil {
		t.Fatalf("CompileForced(BT groups, folded class with ranges past 0xFF): %v", err)
	}
}

// ---------------------------------------------------------------------------
// compile.go — remaining dispatch and fallback branches
// ---------------------------------------------------------------------------

func TestEnginesCovLitChainRangeNonGreedyFind(t *testing.T) {
	// A non-greedy `{N,M}?` find collapses to the fixed `{N,N}` emission: the
	// shortest match always takes exactly N repetitions. A trailing anchor can
	// make `{N,M}?` extend past N, which is why the
	// anchored spellings are excluded from this path, so the witness must be
	// unanchored.
	// The range analyser also gates on N >= 24 outside LikelyMatch, so the
	// witness has to clear that too or it never reaches the greedy split.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `AKIA[A-Z0-9]{24,40}?`,
		FindFunc: "akia_nongreedy_find",
	}})
	// Greedy sibling, for contrast: same shape, different emitter.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `AKIA[A-Z0-9]{24,40}`,
		FindFunc: "akia_greedy_find",
	}})
}

// enginesCovHugeBTPattern returns a pattern whose NFA exceeds
// maxBTFallbackInstructions. A long literal is the cheapest shape that gets
// there: one instruction per byte, and its DFA is a linear chain that hits
// the state ceiling almost immediately, so the fallback is reached without
// paying for a large subset construction first.
func enginesCovHugeBTPattern(t *testing.T, suffix string) string {
	t.Helper()
	pattern := strings.Repeat("abcdefghij", 2100) + suffix
	if got := len(enginesCovProg(t, pattern).Inst); got <= maxBTFallbackInstructions {
		t.Skipf("witness pattern produces %d instructions, need > %d", got, maxBTFallbackInstructions)
	}
	return pattern
}

func TestEnginesCovBTProgramTooLarge(t *testing.T) {
	// maxBTFallbackInstructions bounds the br_table dispatch every
	// Backtracking body emits. Each of the four construction sites carries
	// its own copy of the check; an omission there emits a module with a
	// dispatch table large enough to make wasmtime's JIT the bottleneck.
	t.Run("match_fallback", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `x`)
		_, _, err := Compile(
			[]config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}}, 0, true,
			CompileOptions{MaxDFAStates: 1})
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(match): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
	t.Run("find_fallback", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `x`)
		_, _, err := Compile(
			[]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true,
			CompileOptions{MaxDFAStates: 1})
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(find): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
	t.Run("groups", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `(x)`)
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
}

func TestEnginesCovGroupsPathInputErrors(t *testing.T) {
	// The capture path parses the pattern itself rather than reusing an
	// earlier parse, so it needs its own error handling for both a syntax
	// error and a Unicode construct the engines cannot represent.
	t.Run("parse_error", func(t *testing.T) {
		_, _, err := Compile([]config.RegexEntry{{Pattern: `(`, GroupsFunc: "g"}}, 0, true)
		if err == nil {
			t.Fatal("Compile(groups, unbalanced paren): no error")
		}
	})
	t.Run("unicode_unsupported", func(t *testing.T) {
		// Byte mode, as a harness forces it: a rune above U+00FF has no byte.
		_, _, err := Compile([]config.RegexEntry{{Pattern: `(\x{100})`, GroupsFunc: "g"}}, 0, true, CompileOptions{ForceByteMode: true})
		if err == nil {
			t.Fatal("Compile(groups, non-ASCII class): no error")
		}
		if !strings.Contains(err.Error(), "U+0100") {
			t.Fatalf("Compile(groups, non-ASCII class): err = %v, want the rune named", err)
		}
	})
}

func TestEnginesCovFindPathDFACompileError(t *testing.T) {
	// The find path tolerates exactly one error from its DFA build — the
	// state-limit sentinel, which just means "fall back to Backtracking".
	// Any other error is a real failure and must be reported, not swallowed
	// into a silent Backtracking compile of a pattern the DFA rejected.
	_, _, err := Compile([]config.RegexEntry{{Pattern: `[\x{100}-\x{200}]x`, FindFunc: "f"}}, 0, true, CompileOptions{ForceByteMode: true})
	if err == nil {
		t.Fatal("Compile(find, non-ASCII class): no error")
	}
}

func TestEnginesCovAltLitAnchorWithMatchBody(t *testing.T) {
	// The per-branch function indices are offset by one when a match body
	// occupies the first slot. Getting that offset wrong points the
	// dispatcher's calls at the wrong functions — a wrong answer, not a
	// crash, since the signatures happen to line up.
	pattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`
	entry := config.RegexEntry{Pattern: pattern, MatchFunc: "m", FindFunc: "f"}

	compiled, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if compiled.altLitAnchorBranches == nil {
		t.Fatalf("compilePattern did not take the alt-lit-anchor path for %q", pattern)
	}
	if compiled.matchBody == nil {
		t.Fatal("match_func was set but no match body was emitted; the offset case is not exercised")
	}
	back, fwd := compiled.altLitAnchorBranchFuncIdx(0)
	if back != 1 || fwd != 2 {
		t.Errorf("altLitAnchorBranchFuncIdx(0) = (%d, %d), want (1, 2) — slot 0 is the match body", back, fwd)
	}
	mustCompileEntries(t, []config.RegexEntry{entry})
}

func TestEnginesCovFindAltLitAnchorPointsUnwrapsBranchCaptures(t *testing.T) {
	// Branch-level captures are transparent to the anchor analysis: the same
	// alternation written with or without them must produce the same
	// branches, or a capture-bearing pattern silently loses the optimisation.
	plain, okPlain := findAltLitAnchorPoints(bytePat(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`))
	captured, okCaptured := findAltLitAnchorPoints(bytePat(`([0-9]{8}ghp_[A-Za-z0-9]{36})|([a-f]{8}secret_[A-Za-z0-9]{36})`))
	if !okPlain || !okCaptured {
		t.Fatalf("findAltLitAnchorPoints: plain ok = %v, captured ok = %v, want both true", okPlain, okCaptured)
	}
	if len(plain) != len(captured) {
		t.Errorf("branch count: plain = %d, captured = %d", len(plain), len(captured))
	}
}

func TestEnginesCovCanConsumeNewlineRecursesIntoContainers(t *testing.T) {
	// A container's answer is its children's: `(?s)x.` cannot be decided from
	// the concat node itself, only from the OpAnyChar inside it. Char classes
	// that spell a newline get folded into a single OpCharClass by the parser,
	// so a container with a genuinely newline-consuming CHILD needs `(?s).`.
	if !canConsumeNewline(enginesCovParse(t, `(?s)x.`)) {
		t.Error("canConsumeNewline(`(?s)x.`) = false, want true (the concat's `.` matches '\\n')")
	}
	if canConsumeNewline(enginesCovParse(t, `x.y`)) {
		t.Error("canConsumeNewline(`x.y`) = true, want false (`.` is OpAnyCharNotNL)")
	}
}

func TestEnginesCovHasAmbiguousCapturesAltMatch(t *testing.T) {
	// InstAltMatch is a one-pass optimisation Go's own regexp package
	// installs; syntax.Compile never emits it, so this arm only guards
	// against a caller handing the selector such a program. It has to be
	// treated exactly like InstAlt: missing it would route an ambiguous
	// pattern to TDFA, where overlapping branches produce wrong capture
	// spans rather than a slower match.
	ambiguous := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstAltMatch, Out: 1, Arg: 2},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if !hasAmbiguousCaptures(ambiguous, false) {
		t.Error("hasAmbiguousCaptures(InstAltMatch with overlapping branches) = false, want true")
	}

	// Disjoint branches through the same instruction are not ambiguous.
	disjoint := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstAltMatch, Out: 1, Arg: 2},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstRune1, Rune: []rune{'b'}, Out: 3},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if hasAmbiguousCaptures(disjoint, false) {
		t.Error("hasAmbiguousCaptures(InstAltMatch with disjoint branches) = true, want false")
	}
}

func TestEnginesCovAnalysePatternUnicodeLabel(t *testing.T) {
	// The "Unicode" complexity label is only computed when the alternation
	// count stays under the "High alternations" threshold, and it is only
	// read on the debug-logging path.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prog := enginesCovProg(t, `[\x{100}-\x{200}](a)`)
	analysis := analysePattern(prog)
	if !analysis.HasUnicode {
		t.Fatalf("analysePattern did not flag Unicode for a >0x7F class: %+v", analysis)
	}
	if analysis.NumAlternations > 5 {
		t.Fatalf("witness pattern has %d alternations; the Unicode label is only chosen below 6",
			analysis.NumAlternations)
	}
	var opts CompileOptions
	if engine, _ := selectBestEngineWithTDFA(byteProg(prog), &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

func TestEnginesCovShuftiRareFirstByteBand(t *testing.T) {
	// 17..64 candidate first bytes is the band where Shufti is chosen only if
	// the bytes are RARE enough that scalar cannot exit a chunk early. Control
	// bytes have rarity 0, so `[\x01-\x1f]` (31 bytes) is on the Shufti side
	// even without the LikelyNoMatch override — the one route into that arm.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[\x01-\x1f]xyz", FindFunc: "f"}})
	// The dense counterpart stays scalar: 52 letters, rarity sum far over the
	// threshold.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `[a-zA-Z]xyz`, FindFunc: "f2"}})
}

// ---------------------------------------------------------------------------
// compile.go — fallback branches that need the DFA and the Backtracking
// construction to disagree about the SAME pattern.
// ---------------------------------------------------------------------------

func TestEnginesCovGroupsOnlyBTLimits(t *testing.T) {
	// The find half of a groups compile normally trips the Backtracking
	// guards first, which is why the capture path's own copies stayed
	// unreached. Both witnesses here have a TINY DFA — so the find half stays
	// on the DFA path and never constructs a Backtracking engine — while
	// their Backtracking construction blows a limit. That is the only
	// configuration in which the capture path's copies decide the outcome.
	t.Run("program_too_large", func(t *testing.T) {
		// 7000 captured zero-width assertions: a huge NFA whose DFA is a couple
		// of states, and `\b` also keeps the capture path off TDFA. The group
		// is what keeps collapseZeroWidthRepeats from reducing the repeat to a
		// single `\b`, as it now does for the uncaptured `(?:\b){1000}`.
		pattern := strings.Repeat(`(\b){1000}`, 7) + `(x)`
		if got := len(enginesCovProg(t, pattern).Inst); got <= maxBTFallbackInstructions {
			t.Skipf("witness pattern produces %d instructions, need > %d", got, maxBTFallbackInstructions)
		}
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
}

func TestEnginesCovBTStackReservationOverCeiling(t *testing.T) {
	// A Backtracking stack reserved above WASM32's 4GiB
	// linear-memory ceiling used to produce a module whose memory section was
	// already invalid — a failure that only surfaced at instantiation time,
	// with no attribution to the pattern that caused it. The match and find
	// bodies reserve no stack any more (their frame stack grows at call time),
	// so a table base close to the ceiling no longer trips the check through
	// them: what they need is not decided at compile time.
	const nearCeiling = int64(1)<<32 - 4096
	for _, testCase := range []struct {
		name  string
		entry config.RegexEntry
	}{
		{"match_fallback", config.RegexEntry{Pattern: `abc`, MatchFunc: "m"}},
		{"find_fallback", config.RegexEntry{Pattern: `abc`, FindFunc: "f"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := Compile(
				[]config.RegexEntry{testCase.entry}, nearCeiling, true,
				CompileOptions{MaxDFAStates: 1})
			if errors.Is(err, ErrBTStackTooLarge) {
				t.Fatalf("Compile: err = %v, want no stack reservation to refuse", err)
			}
		})
	}
}

func TestEnginesCovBTFallbackPrefixTruncation(t *testing.T) {
	// The Backtracking find fallback lifts the DFA's common prefix to drive a
	// SIMD scan, but the emitted scan compares a bounded window: a prefix
	// longer than maxBTFallbackPrefixLen must be truncated, not emitted whole.
	pattern := strings.Repeat("ab", 40) + `[0-9]`
	compiled, err := compilePattern(
		config.RegexEntry{Pattern: pattern, FindFunc: "f"}, 0, 0,
		CompileOptions{MaxDFAStates: 1, globals: &moduleGlobals{}})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if compiled.findBody == nil {
		t.Fatal("no find body emitted")
	}
	mustCompileEntries(t,
		[]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// ---------------------------------------------------------------------------
// compile.go — batch groups wrapper
// ---------------------------------------------------------------------------

func TestEnginesCovBatchGroupsWrapperWindowMode(t *testing.T) {
	// The batch groups wrapper writes each match's extent into the window
	// scratch slot and then calls the capture body with the caller's REAL
	// (ptr,len) — the same window-mode contract the single-match wrapper has
	//. A Backtracking capture body with a
	// word boundary is what turns that on; a TDFA one never does.
	entry := config.RegexEntry{
		Pattern:    `(\b(?:a*)+b)c`,
		FindFunc:   "wf",
		GroupsFunc: "wg",
		Hints:      []string{"batch-find"},
	}
	t.Run("standalone", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{entry})
	})
	t.Run("embedded", func(t *testing.T) {
		// Embedded mode puts the tables in memory[1], which the batch
		// wrapper's scratch stores have to address explicitly.
		wasm, _, err := Compile([]config.RegexEntry{entry}, 0, false)
		if err != nil {
			t.Fatalf("Compile(embedded batch groups): %v", err)
		}
		if !bytes.HasPrefix(wasm, wasmMagic) {
			t.Fatal("Compile(embedded batch groups): output is not a WASM module")
		}
		validateWASM(t, wasm)
	})
}

// ---------------------------------------------------------------------------
// alt_lit_anchor.go — per-branch rejection gates
//
// compileAltLitAnchorBranches is all-or-nothing: one branch failing any gate
// must reject the whole alternation so the caller falls back to the combined
// DFA. Reaching each gate needs a pattern that PASSES findAltLitAnchorPoints
// (equal fixed prefixes, a qualifying anchor literal per branch) and then
// fails the specific later check, which is why these drive the function
// directly rather than through Compile.
// ---------------------------------------------------------------------------

func enginesCovAltBranches(t *testing.T, pattern string) []altLitAnchorBranch {
	t.Helper()
	branches, ok := findAltLitAnchorPoints(bytePat(pattern))
	if !ok {
		t.Fatalf("findAltLitAnchorPoints(%q) rejected the pattern before the gate under test", pattern)
	}
	return branches
}

func TestEnginesCovCompileAltLitAnchorRejections(t *testing.T) {
	goodPattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+`

	t.Run("known_good_is_accepted", func(t *testing.T) {
		// Baseline, so the rejections below are attributable to the gate
		// under test rather than to a fixture that never qualified.
		branches := enginesCovAltBranches(t, goodPattern)
		if _, ok := compileAltLitAnchorBranches(bytePat(goodPattern), branches, 0, CompileOptions{}); !ok {
			t.Fatal("compileAltLitAnchorBranches rejected the known-good alternation")
		}
	})

	t.Run("forward_dfa_needs_u16_state_ids", func(t *testing.T) {
		// A 1000-byte fixed prefix builds fine but needs more than 256 DFA
		// states, and the backward scan addresses its table with u8 state
		// ids. Accepting it would emit a dispatcher whose per-branch scan
		// functions read a table indexed with a truncated state.
		branches := enginesCovAltBranches(t, `[0-9]{1000}ghp_[^\s]+|[a-f]{1000}secret_[^\s]+`)
		if result, ok := compileAltLitAnchorBranches(bytePat(`[0-9]{1000}ghp_[^\s]+|[a-f]{1000}secret_[^\s]+`), branches, 0, CompileOptions{}); ok {
			t.Errorf("compileAltLitAnchorBranches accepted a DFA needing u16 state ids: %+v", result)
		}
	})

	t.Run("forward_dfa_over_helper_ceiling", func(t *testing.T) {
		// 3000 bytes of fixed prefix pushes the per-branch forward DFA past
		// the helper ceiling, so construction itself fails and the whole
		// alternation has to be abandoned rather than half-built.
		pattern := `[0-9]{1000}[a-f]{1000}[g-m]{1000}ghp_[^\s]+|` +
			`[n-s]{1000}[t-z]{1000}[0-4]{1000}secret_[^\s]+`
		branches := enginesCovAltBranches(t, pattern)
		if result, ok := compileAltLitAnchorBranches(bytePat(pattern), branches, 0, CompileOptions{}); ok {
			t.Errorf("compileAltLitAnchorBranches accepted a 3000-byte prefix: %+v", result)
		}
	})

	t.Run("teddy_t1_collision_still_compiles", func(t *testing.T) {
		// Two anchor literals sharing a first byte but differing in the
		// second make a 2-byte Teddy table lossy. T1 is only an accelerator
		// (every hit is verified scalar-side), so the right answer is to skip
		// T1 and keep the alternation, not to reject it. The prefix classes
		// differ so the parser does not factor the shared 'g' out and change
		// the top-level shape.
		branches := enginesCovAltBranches(t, `[0-9]{8}ghp_[^\s]+|[a-f]{8}gzz_[^\s]+`)
		result, ok := compileAltLitAnchorBranches(bytePat(`[0-9]{8}ghp_[^\s]+|[a-f]{8}gzz_[^\s]+`), branches, 0, CompileOptions{})
		if !ok {
			t.Fatal("compileAltLitAnchorBranches rejected a T1-colliding alternation; it should skip T1 instead")
		}
		if result == nil || len(result.branches) != 2 {
			t.Fatalf("compileAltLitAnchorBranches returned %+v, want 2 branches", result)
		}
	})
}

func TestEnginesCovAnalysePatternHighAlternationLabel(t *testing.T) {
	// The other complexity label, chosen ahead of "Unicode" once the
	// alternation count passes 5. Only the debug-logging path reads it.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prog := enginesCovProg(t, `(?:aa|bb|cc|dd|ee|ff|gg)(x)`)
	analysis := analysePattern(prog)
	if analysis.NumAlternations <= 5 {
		t.Fatalf("witness pattern has %d alternations, need more than 5", analysis.NumAlternations)
	}
	opts := CompileOptions{}
	if engine, _ := selectBestEngineWithTDFA(byteProg(prog), &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

func TestEnginesCovCountedChainSuffixPrefixRebase(t *testing.T) {
	// A counted-chain suffix reports the match START, not the position the
	// suffix itself began at. When the bucket's patterns share a FIXED-length
	// prefix the prefix was matched by a separate stage, so the suffix has to
	// subtract that length from the reported start and add it to the length.
	// Emitting the un-rebased form instead yields a match that begins in the
	// middle of the real one.
	class := []byte{'0', '1', '2'}
	plain := buildCountedChainSuffixBody(class, 4, 0, 0, false, false)
	rebased := buildCountedChainSuffixBody(class, 4, 0, 7, false, false)
	if len(plain) == 0 || len(rebased) == 0 {
		t.Fatal("buildCountedChainSuffixBody emitted an empty body")
	}
	if bytes.Equal(plain, rebased) {
		t.Fatal("buildCountedChainSuffixBody ignored prefixMaxLen: both bodies are byte-identical")
	}
	if len(rebased) <= len(plain) {
		t.Errorf("rebased body is %d bytes and the plain one %d; the rebase adds a sub/add pair and must be longer",
			len(rebased), len(plain))
	}
	// The prefix length is baked in as an SLEB128 constant, twice (once for
	// the start, once for the length).
	if !bytes.Contains(rebased, []byte{0x41, 0x07}) {
		t.Errorf("rebased body does not contain the i32.const 7 the rebase needs: % x", rebased)
	}
}

func TestEnginesCovMandatoryLitSplitsNestedConcat(t *testing.T) {
	// Set composition lifts a pattern's mandatory literal out of the AST by
	// splitting at the literal's path, and the split has to rebuild BOTH
	// sides at every concat level it passes through — here an inner concat
	// reached through a capture, which has material on both sides of the
	// literal. Dropping either side would give the bucket a prefix or suffix
	// automaton that matches something other than the original pattern.
	pattern := `[0-9]{2}([a-z]MANDATORYLIT[0-9]b)[0-9]`
	parsed := enginesCovParse(t, pattern)
	mandLit, path := findMandatoryLitRec(byteTree(parsed), 0, 0)
	if mandLit == nil {
		t.Fatalf("findMandatoryLitRec(%q) = nil; the witness no longer has a liftable literal", pattern)
	}
	if string(mandLit.bytes) != "MANDATORYLIT" {
		t.Fatalf("findMandatoryLitRec(%q) lifted %q, want %q", pattern, mandLit.bytes, "MANDATORYLIT")
	}

	prefixAST, suffixAST, ok := splitAtPath(parsed, path)
	if !ok {
		t.Fatalf("splitAtPath(%q) refused to split", pattern)
	}
	if prefixAST == nil {
		t.Fatal("splitAtPath dropped the prefix; `[0-9]{2}` and the capture's leading `[a-z]` precede the literal")
	}
	if suffixAST == nil {
		t.Fatal("splitAtPath dropped the suffix; `[0-9]b` inside the capture and `[0-9]` after it follow the literal")
	}
	// Both sides must still account for the inner-concat material, which is
	// exactly what the two branches under test contribute.
	prefixMin, prefixMax := byteTree(prefixAST).minMaxLen()
	if prefixMin != 3 || prefixMax != 3 {
		t.Errorf("prefix length = [%d, %d], want [3, 3] (two digits plus the capture's leading class)", prefixMin, prefixMax)
	}
	suffixMin, suffixMax := byteTree(suffixAST).minMaxLen()
	if suffixMin != 3 || suffixMax != 3 {
		t.Errorf("suffix length = [%d, %d], want [3, 3] (digit, 'b', trailing digit)", suffixMin, suffixMax)
	}
}

// TestBacktrackHasZeroWidthCycle covers the exported predicate tools/fuzz uses
// to decide whether a program ships an ordinary body at all.
func TestBacktrackHasZeroWidthCycle(t *testing.T) {
	for _, c := range []struct {
		pat  string
		want bool
	}{
		{`(a|)*b`, true},
		{`(a*)*b`, true},
		{`(a??)*?b`, true},
		{`abc`, false},
		{`(a+)(b)`, false},
		{`[a-z]+x`, false},
	} {
		got, err := BacktrackHasZeroWidthCycle(c.pat, CompileOptions{})
		if err != nil {
			t.Fatalf("%q: %v", c.pat, err)
		}
		if got != c.want {
			t.Errorf("BacktrackHasZeroWidthCycle(%q) = %v, want %v", c.pat, got, c.want)
		}
	}
	if _, err := BacktrackHasZeroWidthCycle(`(`, CompileOptions{}); err == nil {
		t.Error("BacktrackHasZeroWidthCycle on an unparsable pattern returned no error")
	}
}

// forcedBTPatterns are capture patterns the selector routes to Backtracking of
// its own accord. That is what makes them usable below: forcing the engine the
// selector would have picked anyway must not change one byte of the output.
var forcedBTPatterns = []string{
	// The three filed as fuzz crashers for compile TIME alone: the first is 41
	// NFA instructions and took 5.36 s to replay, of
	// which 5.0 s was three tagged DFAs that no leg of the target used.
	`[0]+0()00.{31}`,
	`((.(1)*)11){11}`,
	// Ordinary shapes, so the invariant is not pinned by pathological patterns
	// alone. Each is documented as Backtracking's territory: an inverted class
	// reads as an ambiguous capture, `(?m:$)` is a line anchor, `\b` is a word
	// boundary, and `*?` is a non-greedy quantifier.
	`<([^>]+)>`,
	`([^,]+),`,
	`(?m:(foo)$)`,
	`(\b\w+\b)`,
	`(a*?)*?b`,
}

// TestForcedBacktrackMatchesSelectedBacktrack pins that forcing the groups
// engine onto Backtracking produces exactly the module the selector's own
// choice produces.
//
// It is the gate for the skip in compilePatternBody that stops a forced
// Backtracking compile building a tagged DFA it then discards. The saving is
// real — 94% to 98% of such a compile — but it is only sound if the discarded
// table had no other effect, and byte identity is the only evidence strong
// enough for that.
func TestForcedBacktrackMatchesSelectedBacktrack(t *testing.T) {
	for _, pat := range forcedBTPatterns {
		entry := []config.RegexEntry{{Pattern: pat, GroupsFunc: "groups"}}

		eng, err := SelectEngine(pat, CompileOptions{})
		if err != nil {
			t.Fatalf("SelectEngine(%q): %v", pat, err)
		}
		if eng != EngineBacktrack {
			// Not a failure of the invariant, but of this test's premise: the
			// pattern no longer reaches Backtracking on its own, so it can no
			// longer tell the two paths apart. Say so rather than passing
			// silently, which is how a gate quietly stops gating.
			t.Errorf("premise broken: SelectEngine(%q) = %v, want Backtracking — "+
				"pick a different pattern or drop this one", pat, eng)
			continue
		}

		selected, _, err := Compile(entry, 0, true)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pat, err)
		}
		forced, _, err := CompileForced(entry, 0, true, EngineBacktrack)
		if err != nil {
			t.Fatalf("CompileForced(%q, Backtracking): %v", pat, err)
		}
		if !bytes.Equal(selected, forced) {
			t.Errorf("%q: forced Backtracking module differs from the selected one (%d vs %d bytes)",
				pat, len(selected), len(forced))
		}
	}
}

// TestBTWorkBudgetOffCyclicIsFallbackAlone pins what BTWorkBudgetOff does to a
// program with a zero-width cycle: nothing. The ordinary body carries no loop
// guard, so such a program gets the fallback body alone under every budget,
// Off included — the module must be byte-identical to the one
// BTWorkBudgetForceFallback builds. Without that, Off would build a matcher
// that goes round `(?:a*|b*)*` forever on "b".
func TestBTWorkBudgetOffCyclicIsFallbackAlone(t *testing.T) {
	// Every witness has the cycle in BOTH of its programs: the capture one and
	// the capture-stripped one match and find compile. `(a*)*b` is not a
	// witness — stripping its captures lets Go's simplifier collapse the
	// cycle, so its match and find programs are ordinary and Off rightly gives
	// them the ordinary body.
	for _, p := range []string{`(?:a?)+b`, `(?:a??){1,}b`, `(?:a|)+b`, `(a?)+b`, `x(?:a|b?)+y`,
		`(?:(a?)|b)+c`, `(?:ab|a?)+c`, `(a??)*?b`, `(a*b*)*c`, `(?:a*|b*)*`} {
		if cyc, err := BacktrackHasZeroWidthCycle(p, CompileOptions{}); err != nil || !cyc {
			t.Fatalf("%s: BacktrackHasZeroWidthCycle = %v, %v — witness no longer has the shape", p, cyc, err)
		}
		if !progHasZeroWidthCycle(compileBTProg(bytePat(p)).prog) {
			t.Fatalf("%s: the capture-stripped program has no zero-width cycle — witness no longer has the shape", p)
		}
		entries := []config.RegexEntry{{Pattern: p, MatchFunc: "m"}, {Pattern: p, FindFunc: "f"}}
		// groups_func needs a capture group (ErrNoCaptureGroup).
		if !(config.RegexEntry{Pattern: p, GroupsFunc: "g"}).GroupsWithoutCaptures() {
			entries = append(entries, config.RegexEntry{Pattern: p, GroupsFunc: "g"},
				config.RegexEntry{Pattern: p, FindFunc: "f", GroupsFunc: "g"})
		}
		for _, e := range entries {
			off, _, err := Compile([]config.RegexEntry{e}, 65536, true,
				CompileOptions{MaxDFAStates: 1, BTWorkBudget: BTWorkBudgetOff})
			if err != nil {
				t.Fatalf("Compile(%q, Off): %v", p, err)
			}
			forced, _, err := Compile([]config.RegexEntry{e}, 65536, true,
				CompileOptions{MaxDFAStates: 1, BTWorkBudget: BTWorkBudgetForceFallback})
			if err != nil {
				t.Fatalf("Compile(%q, ForceFallback): %v", p, err)
			}
			if !bytes.Equal(off, forced) {
				t.Errorf("%q %+v: BTWorkBudgetOff built a different module from BTWorkBudgetForceFallback", p, e)
			}
			validateWASM(t, off)
		}
	}
}

// TestBTWorkBudgetOffAcyclicDropsTheFallback is the other half: a program with
// no zero-width cycle keeps its ordinary body under BTWorkBudgetOff, with no
// work counter and no fallback body behind it — so the module is smaller than
// the default one, which carries both. That holds for the no-capture match and
// find bodies and for a set's Backtracking bucket driver, whose frame stack
// is a fixed region rather than one grown at run time.
func TestBTWorkBudgetOffAcyclicDropsTheFallback(t *testing.T) {
	for _, p := range []string{`^(aa|a)*b`, `x(?:ab|a)*y`} {
		if cyc, err := BacktrackHasZeroWidthCycle(p, CompileOptions{}); err != nil || cyc {
			t.Fatalf("%s: BacktrackHasZeroWidthCycle = %v, %v — witness no longer acyclic", p, cyc, err)
		}
		for _, e := range []config.RegexEntry{{Pattern: p, MatchFunc: "m"}, {Pattern: p, FindFunc: "f"}} {
			def, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{MaxDFAStates: 1})
			if err != nil {
				t.Fatalf("Compile(%q): %v", p, err)
			}
			off, _, err := Compile([]config.RegexEntry{e}, 65536, true,
				CompileOptions{MaxDFAStates: 1, BTWorkBudget: BTWorkBudgetOff})
			if err != nil {
				t.Fatalf("Compile(%q, Off): %v", p, err)
			}
			if len(off) >= len(def) {
				t.Errorf("%q %+v: Off module is %d bytes, default %d; want it smaller (no counter, no fallback)",
					p, e, len(off), len(def))
			}
			validateWASM(t, off)
		}
	}

	// A set member whose DFA would lose the `\B` branch's priority goes to a
	// Backtracking bucket.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p", Pattern: `(?:\B|a|)a`}},
		Sets:    []config.SetConfig{{Name: "s", Find: "f", Patterns: config.PatternSelector{All: true}}},
	}
	if !SetAdmitsBacktracking(cfg.Sets[0], cfg) {
		t.Fatal("the member is not on Backtracking; this case needs a Backtracking bucket")
	}
	def, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	off, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{BTWorkBudget: BTWorkBudgetOff})
	if err != nil {
		t.Fatal(err)
	}
	if len(off) >= len(def) {
		t.Errorf("set: Off module is %d bytes, default %d; want it smaller (no counter, no fallback)", len(off), len(def))
	}
	validateWASM(t, off)
}

// TestBTStackStartResolution pins how CompileOptions.BTStackStart becomes the
// bytes a capture body's growing frame stack starts with: the default page when
// unset or out of range, the option otherwise, and never less than one frame.
func TestBTStackStartResolution(t *testing.T) {
	for _, c := range []struct {
		opt       int
		frameSize int32
		want      int32
	}{
		{0, 40, defaultBTStackStart},
		{4096, 40, 4096},
		{8, 40, 40}, // below one frame
		{btScratchMaxEnd, 40, defaultBTStackStart},
	} {
		if got := btStackStart(c.opt, c.frameSize); got != c.want {
			t.Errorf("btStackStart(%d, %d) = %d, want %d", c.opt, c.frameSize, got, c.want)
		}
	}
	// Through Compile: the start is a constant in the capture body, so a
	// different start builds a different, still valid, module.
	e := []config.RegexEntry{{Pattern: `(a|ab)(c|bcd)(d*)`, GroupsFunc: "g"}}
	def, _, err := CompileForced(e, 65536, true, EngineBacktrack)
	if err != nil {
		t.Fatal(err)
	}
	small, _, err := CompileForced(e, 65536, true, EngineBacktrack, CompileOptions{BTStackStart: 8})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(def, small) {
		t.Error("BTStackStart: 8 built the default module; the option did not reach the capture body")
	}
	validateWASM(t, small)
}

// ---------------------------------------------------------------------------
// The capture body's frame stack is placed at call time, and max_memory is the
// memory's declared maximum.

// testMemoryLimits decodes a module's own memory declaration: the minimum, and
// the maximum when one is declared.
func testMemoryLimits(t *testing.T, w []byte) (minPages, maxPages uint64, hasMax bool) {
	t.Helper()
	off := 8
	for off < len(w) {
		id := w[off]
		size, n, err := utils.DecodeULEB128(w[off+1:])
		if err != nil {
			t.Fatalf("section size: %v", err)
		}
		body := w[off+1+n : off+1+n+int(size)]
		off += 1 + n + int(size)
		if id != 5 {
			continue
		}
		count, n, _ := utils.DecodeULEB128(body)
		if count != 1 {
			t.Fatalf("memory section declares %d memories, want 1", count)
		}
		flags := body[n]
		minPages, m, _ := utils.DecodeULEB128(body[n+1:])
		if flags&1 == 0 {
			return minPages, 0, false
		}
		maxPages, _, _ = utils.DecodeULEB128(body[n+1+m:])
		return minPages, maxPages, true
	}
	t.Fatal("module declares no memory of its own")
	return 0, 0, false
}

func mustMemorySize(t *testing.T, s string) config.MemorySize {
	t.Helper()
	m, err := config.ParseMemorySize(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestBTCaptureStackNotReservedAtLoad: a capture pattern's memory no longer
// scales with its branch count. Before, a capture pattern reserved numAlts ×
// 4,096 frames in its tables, claimed at load whatever the input.
func TestBTCaptureStackNotReservedAtLoad(t *testing.T) {
	pattern := `((?:a|bc){1,60}?)x`
	if eng, err := SelectEngine(pattern, CompileOptions{}); err != nil || eng != EngineBacktrack {
		t.Fatalf("SelectEngine = %v, %v; want Backtracking — witness no longer has the shape", eng, err)
	}
	numAlts := newBacktrack(byteProg(compileBTTestProg(t, pattern))).numAlts
	if numAlts < 60 {
		t.Fatalf("witness has %d Alts, want at least 60", numAlts)
	}
	w, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	validateWASM(t, w)
	// numAlts × 4,096 frames of 24 bytes was over 90 pages; the tables are a
	// page or two.
	if minPages, _, _ := testMemoryLimits(t, w); minPages > 2 {
		t.Errorf("module declares %d pages at load for %d Alts, want the tables alone", minPages, numAlts)
	}
}

// TestBTStacksNotReservedAtLoad: no Backtracking body claims a frame stack when
// the module loads. TestBTCaptureStackNotReservedAtLoad pinned it for capture
// bodies; the match and find bodies and a set's members still reserved
// numAlts × 4,096 frames of 8 bytes each, per set — 596 of the 643 MB a
// 339-set WAF module claimed before its first call, against 47 MB of tables.
func TestBTStacksNotReservedAtLoad(t *testing.T) {
	pattern := `(?:a|bc){1,60}?x`
	numAlts := newBacktrack(byteProg(compileBTTestProg(t, pattern))).numAlts
	if numAlts < 60 {
		t.Fatalf("witness has %d Alts, want at least 60", numAlts)
	}
	// numAlts × 4,096 × 8 bytes is over 30 pages; the tables are a page or two.
	const maxPages = 3
	forceBT := CompileOptions{MaxDFAStates: -1}
	for _, c := range []struct {
		name  string
		entry config.RegexEntry
	}{
		{"match", config.RegexEntry{Pattern: pattern, MatchFunc: "m"}},
		{"find", config.RegexEntry{Pattern: pattern, FindFunc: "f"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, _, err := Compile([]config.RegexEntry{c.entry}, 0, true, forceBT)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			validateWASM(t, w)
			if minPages, _, _ := testMemoryLimits(t, w); minPages > maxPages {
				t.Errorf("module declares %d pages at load for %d Alts, want the tables alone", minPages, numAlts)
			}
		})
	}
	t.Run("set", func(t *testing.T) {
		// The same member in three sets reserved three stacks.
		var sets []config.SetConfig
		for i := 0; i < 3; i++ {
			n := "s" + strconv.Itoa(i)
			sets = append(sets, config.SetConfig{Name: n, ScanAny: n + "_any", Find: n + "_find",
				Patterns: config.PatternSelector{All: true}})
		}
		cfg := config.BuildConfig{
			MaxFallbackStates: 1, // every member's suffix DFA is over it: Backtracking
			Regexps:           []config.RegexEntry{{Name: "a", Pattern: pattern}, {Name: "b", Pattern: `(?:c|de){1,60}?y`}},
			Sets:              sets,
		}
		w, _, diags, err := CompileFileDiag(cfg, "")
		if err != nil {
			t.Fatalf("CompileFile: %v", err)
		}
		validateWASM(t, w)
		bt := 0
		for _, d := range diags {
			for _, b := range d.Buckets {
				if b.Type == "bt-fallback" {
					bt++
				}
			}
		}
		if bt == 0 {
			t.Fatal("no set member runs on Backtracking — the witness no longer has the shape")
		}
		if minPages, _, _ := testMemoryLimits(t, w); minPages > maxPages {
			t.Errorf("module declares %d pages at load for %d Backtracking members, want the tables alone", minPages, bt)
		}
	})
}

// TestMaxMemoryDeclaredAsMaximum: max_memory becomes the memory's declared
// maximum on every assembly path, rounded down to pages; unset declares none,
// which is the bytes every module had before.
func TestMaxMemoryDeclaredAsMaximum(t *testing.T) {
	entries := []config.RegexEntry{{Pattern: `(a.*?b)(c+)`, GroupsFunc: "g"}, {Pattern: `foo`, FindFunc: "f"}}
	capped := CompileOptions{MaxMemory: mustMemorySize(t, "1.5MiB")} // 24 pages
	for _, c := range []struct {
		name       string
		standalone bool
		opts       CompileOptions
	}{
		{"standalone", true, capped},
		{"embedded", false, capped},
		{"component", true, func() CompileOptions { o := componentOpts(entries); o.MaxMemory = capped.MaxMemory; return o }()},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, _, err := Compile(entries, 0, c.standalone, c.opts)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			validateWASM(t, w)
			if _, max, has := testMemoryLimits(t, w); !has || max != 24 {
				t.Errorf("declared maximum = %d (declared %v), want 24 pages", max, has)
			}
			uncapped := c.opts
			uncapped.MaxMemory = config.MemorySize{}
			w, _, err = Compile(entries, 0, c.standalone, uncapped)
			if err != nil {
				t.Fatalf("Compile (no cap): %v", err)
			}
			if _, _, has := testMemoryLimits(t, w); has {
				t.Error("no max_memory, but the memory declares a maximum")
			}
		})
	}
	t.Run("sets", func(t *testing.T) {
		cfg := config.BuildConfig{
			MaxMemory: capped.MaxMemory,
			Regexps:   []config.RegexEntry{{Name: "a", Pattern: `foo[0-9]+`}, {Name: "b", Pattern: `bar`}},
			Sets:      []config.SetConfig{{Name: "s", ScanAny: "s_any", Patterns: config.PatternSelector{All: true}}},
		}
		w, _, err := CompileFile(cfg, "")
		if err != nil {
			t.Fatalf("CompileFile: %v", err)
		}
		validateWASM(t, w)
		if _, max, has := testMemoryLimits(t, w); !has || max != 24 {
			t.Errorf("declared maximum = %d (declared %v), want 24 pages", max, has)
		}
	})
}

// TestMaxMemoryBelowStaticSizeIsCompileError: a cap below what the module
// declares before any call is refused at compile time, naming the cap and the
// size — its tables, and a component's extra allocator page.
func TestMaxMemoryBelowStaticSizeIsCompileError(t *testing.T) {
	// A large DFA table is static memory: (a|b)*a(a|b){10} needs 2^11 states,
	// u16 ids and 256 columns — 1 MB, several pages. (Backtracking reserves
	// nothing at compile time any more; its frame stacks grow at call time.)
	entries := []config.RegexEntry{{Pattern: `(a|b)*a(a|b){10}`, MatchFunc: "m"}}
	opts := CompileOptions{MaxDFAStates: 1 << 13}
	w, _, err := Compile(entries, 0, true, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	static, _, _ := testMemoryLimits(t, w)
	if static < 3 {
		t.Fatalf("witness declares %d pages; want a table region several pages long", static)
	}
	at := func(pages uint64) config.MemorySize {
		return mustMemorySize(t, itoa(pages*65536+65535)) // rounds down to pages
	}

	opts.MaxMemory = at(static)
	if _, _, err := Compile(entries, 0, true, opts); err != nil {
		t.Errorf("a cap equal to the static size must compile: %v", err)
	}
	opts.MaxMemory = at(static - 1)
	_, _, err = Compile(entries, 0, true, opts)
	if !errors.Is(err, ErrMemoryCapTooSmall) {
		t.Fatalf("a cap one page below the static size: err = %v, want ErrMemoryCapTooSmall", err)
	}
	for _, want := range []string{opts.MaxMemory.String(), itoa(static * 65536)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}

	t.Run("below_one_page", func(t *testing.T) {
		_, _, err := Compile([]config.RegexEntry{{Pattern: `foo`, FindFunc: "f"}}, 0, true,
			CompileOptions{MaxMemory: mustMemorySize(t, "60KB")})
		if !errors.Is(err, ErrMemoryCapTooSmall) {
			t.Errorf("60KB rounds down to 0 pages: err = %v, want ErrMemoryCapTooSmall", err)
		}
	})
	t.Run("component_allocator_page", func(t *testing.T) {
		e := []config.RegexEntry{{Pattern: `foo`, FindFunc: "f"}}
		w, _, err := Compile(e, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pages, _, _ := testMemoryLimits(t, w)
		o := componentOpts(e)
		o.MaxMemory = at(pages)
		if _, _, err := Compile(e, 0, true, o); !errors.Is(err, ErrMemoryCapTooSmall) {
			t.Errorf("a component needs one page more than its module: err = %v, want ErrMemoryCapTooSmall", err)
		}
		o.MaxMemory = at(pages + 1)
		if _, _, err := Compile(e, 0, true, o); err != nil {
			t.Errorf("Compile(component at its size): %v", err)
		}
	})
	t.Run("sets", func(t *testing.T) {
		cfg := config.BuildConfig{
			MaxMemory: mustMemorySize(t, "1KB"),
			Regexps:   []config.RegexEntry{{Name: "a", Pattern: `foo[0-9]+`}, {Name: "b", Pattern: `bar`}},
			Sets:      []config.SetConfig{{Name: "s", ScanAny: "s_any", Patterns: config.PatternSelector{All: true}}},
		}
		if _, _, err := CompileFile(cfg, ""); !errors.Is(err, ErrMemoryCapTooSmall) {
			t.Errorf("CompileFile: err = %v, want ErrMemoryCapTooSmall", err)
		}
	})
}

// TestMaxMemoryAbove4GiBWarns: past what a 32-bit memory holds the cap is 4
// GiB, declared as such, with a warning that says so.
func TestMaxMemoryAbove4GiBWarns(t *testing.T) {
	buf, restore := captureWarnings(t)
	defer restore()
	w, _, err := Compile([]config.RegexEntry{{Pattern: `foo`, FindFunc: "f"}}, 0, true,
		CompileOptions{MaxMemory: mustMemorySize(t, "8GB")})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, max, has := testMemoryLimits(t, w); !has || max != config.MaxWasmMemoryPages {
		t.Errorf("declared maximum = %d (declared %v), want %d", max, has, config.MaxWasmMemoryPages)
	}
	if !strings.Contains(buf.String(), "4 GiB") || !strings.Contains(buf.String(), "8GB") {
		t.Errorf("no warning naming the value and 4 GiB: %q", buf.String())
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

// TestBTDispatchPlan pins the first-byte dispatch over an alternation chain
// (bt_dispatch.go): which arms each byte tries, in priority order; one
// dispatch per chain, its inner Alts dead; the compact encoding where the
// direct one would push more than the chain has arms; and the budget charge.
func TestBTDispatchPlan(t *testing.T) {
	plan := func(t *testing.T, pat string) *btDispatchPlan {
		t.Helper()
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		return buildBTDispatchPlan(prog)
	}
	only := func(t *testing.T, p *btDispatchPlan) *btAltDispatch {
		t.Helper()
		if len(p.heads) != 1 {
			t.Fatalf("%d dispatched chains, want 1", len(p.heads))
		}
		for _, d := range p.heads {
			return d
		}
		return nil
	}
	expect := func(t *testing.T, d *btAltDispatch, want map[int][]int) {
		t.Helper()
		for c, w := range want {
			got := d.cases[d.caseOf[c]]
			if len(got) != len(w) {
				t.Errorf("byte %d: arms %v, want %v", c, got, w)
				continue
			}
			for i := range w {
				if got[i] != w[i] {
					t.Errorf("byte %d: arms %v, want %v", c, got, w)
					break
				}
			}
		}
	}
	const eof = 256

	t.Run("keywords", func(t *testing.T) {
		p := plan(t, `(?:get|head|post|delete)`)
		d := only(t, p)
		expect(t, d, map[int][]int{'g': {0}, 'h': {1}, 'p': {2}, 'd': {3}, 'x': {}, eof: {}})
		if len(p.dead) != 2 || d.compact {
			t.Errorf("inner Alts %d (want 2), compact %v (want false)", len(p.dead), d.compact)
		}
	})
	t.Run("fold", func(t *testing.T) {
		expect(t, only(t, plan(t, `(?i)(?:get|head|post)`)), map[int][]int{'g': {0}, 'G': {0}, 'P': {2}})
	})
	t.Run("overlapping first bytes keep priority", func(t *testing.T) {
		expect(t, only(t, plan(t, `(?:a1|[ab]2|b3)`)), map[int][]int{'a': {0, 1}, 'b': {1, 2}, 'c': {}})
	})
	t.Run("an arm that can match empty is in every case", func(t *testing.T) {
		expect(t, only(t, plan(t, `(?:ab|cd|e*)`)), map[int][]int{'a': {0, 2}, 'x': {2}, eof: {2}})
	})
	t.Run("a chain every byte starts is left alone", func(t *testing.T) {
		if p := plan(t, `(?:.a|.b|.c)`); len(p.heads) != 0 {
			t.Errorf("%d dispatched chains, want 0", len(p.heads))
		}
	})
	t.Run("compact", func(t *testing.T) {
		d := only(t, plan(t, `(?:\w+a|[a-z]+b|[0-9a-z]+c|x)`))
		if !d.compact {
			t.Error("compact = false: the direct encoding would push 6 frames for 4 arms")
		}
		expect(t, d, map[int][]int{'a': {0, 1, 2}, 'x': {0, 1, 2, 3}, '5': {0, 2}, '_': {0}, '-': {}})
	})
	t.Run("charge", func(t *testing.T) {
		d := only(t, plan(t, `(?:get|head|post|delete)`))
		for _, c := range []struct {
			list []int
			want int
		}{{nil, 3}, {[]int{0}, 3}, {[]int{1, 2}, 2}} {
			if got := btDispatchCharge(d, c.list); got != c.want {
				t.Errorf("charge for %v = %d, want %d", c.list, got, c.want)
			}
		}
	})
}

// TestBTFirstSets pins the first-byte supersets the dispatch reads, one per
// instruction kind, and the budget charge's amount forms.
func TestBTFirstSets(t *testing.T) {
	firstOf := func(t *testing.T, pat string) *btFirst {
		t.Helper()
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		return btFirstSets(prog)(uint32(prog.Start))
	}
	count := func(f *btFirst) int {
		n := 0
		for _, b := range f.bytes {
			if b {
				n++
			}
		}
		return n
	}
	for _, c := range []struct {
		pat      string
		bytes    int
		has      []byte
		nullable bool
	}{
		{`(?s).x`, 256, []byte{'\n'}, false},
		{`.x`, 255, []byte{'a'}, false},
		{`(?i)k`, 2, []byte{'k', 'K'}, false},           // one folded rune
		{`[a-c\x{100}-\x{200}]`, 3, []byte{'b'}, false}, // a range above the byte space adds nothing
		{`[^\x00-\x{10FFFF}]`, 0, nil, false},           // Fail
		{`(a*)*b`, 256, nil, true},                      // a zero-width cycle: anything
		{`\bfoo`, 1, []byte{'f'}, false},                // an assertion is looked through
		{`x*`, 1, []byte{'x'}, true},
	} {
		f := firstOf(t, c.pat)
		if got := count(f); got != c.bytes || f.nullable != c.nullable {
			t.Errorf("%s: %d bytes, nullable %v; want %d, %v", c.pat, got, f.nullable, c.bytes, c.nullable)
		}
		for _, b := range c.has {
			if !f.bytes[b] {
				t.Errorf("%s: misses %q", c.pat, b)
			}
		}
	}
	trip := func(b []byte) []byte { return append(b, 0x00) }
	if !bytes.Equal(emitBTWorkChargeN(nil, 7, 1, trip), emitBTWorkCharge(nil, 7, trip)) {
		t.Error("emitBTWorkChargeN(1) is not emitBTWorkCharge")
	}
	m := &btDriveMember{budget: 3}
	if !bytes.Equal(emitBTWorkChargeMemberN(nil, m, 7, 1, trip), emitBTWorkChargeMember(nil, m, 7, trip)) {
		t.Error("emitBTWorkChargeMemberN(1) is not emitBTWorkChargeMember")
	}
	if bytes.Equal(emitBTWorkChargeMemberN(nil, m, 7, 2, trip), emitBTWorkChargeMember(nil, m, 7, trip)) {
		t.Error("emitBTWorkChargeMemberN(2) charges 1")
	}
}
