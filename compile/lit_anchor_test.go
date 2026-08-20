package compile

import (
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

func TestPrefixStartsWithLineAnchor(t *testing.T) {
	parse := func(pattern string) *syntax.Regexp {
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		return re
	}

	cases := []struct {
		pattern string
		want    bool
	}{
		{"^abc", true},   // OpConcat starting with OpBeginLine
		{`\Aabc`, true},  // OpConcat starting with OpBeginText
		{"abc", false},   // no anchor
		{"[a-z]", false}, // OpCharClass
		{"(^abc)", true}, // OpCapture containing anchor concat
		{"(abc)", false}, // OpCapture without anchor
		{"a|^b", false},  // OpAlternate — not handled, returns false
	}
	for _, c := range cases {
		re := parse(c.pattern)
		if got := prefixStartsWithLineAnchor(re); got != c.want {
			t.Errorf("prefixStartsWithLineAnchor(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestPrefixStartsWithLineAnchor_Edges(t *testing.T) {
	// Empty OpConcat: no Sub → returns false.
	t.Run("empty_concat", func(t *testing.T) {
		re := &syntax.Regexp{Op: syntax.OpConcat}
		if prefixStartsWithLineAnchor(re) {
			t.Error("empty concat should not be a line anchor")
		}
	})
	// Empty OpCapture: no Sub → returns false.
	t.Run("empty_capture", func(t *testing.T) {
		re := &syntax.Regexp{Op: syntax.OpCapture}
		if prefixStartsWithLineAnchor(re) {
			t.Error("empty capture should not be a line anchor")
		}
	})
}

func TestExtractLitSet_RejectionPaths(t *testing.T) {
	parse := func(p string) *syntax.Regexp {
		t.Helper()
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", p, err)
		}
		return re
	}

	// FoldCase literal → nil.
	t.Run("fold_case_literal", func(t *testing.T) {
		re := parse(`(?i:foo)`)
		var lit *syntax.Regexp
		var walk func(*syntax.Regexp)
		walk = func(r *syntax.Regexp) {
			if r.Op == syntax.OpLiteral {
				lit = r
				return
			}
			for _, s := range r.Sub {
				walk(s)
			}
		}
		walk(re)
		if lit == nil {
			t.Fatal("no OpLiteral node found")
		}
		if got := extractLitSet(lit); got != nil {
			t.Errorf("extractLitSet(foldcase literal) = %v, want nil", got)
		}
	})

	// Non-ASCII rune in literal → nil.
	t.Run("non_ascii_literal", func(t *testing.T) {
		re := parse(`café`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(non-ASCII) = %v, want nil", got)
		}
	})

	// Single-byte literal → nil (len(bs) < 2 path).
	t.Run("single_byte_literal", func(t *testing.T) {
		re := parse(`x`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(single byte) = %v, want nil", got)
		}
	})

	// Alternation with non-literal branch → nil.
	t.Run("alternation_with_non_literal_branch", func(t *testing.T) {
		re := parse(`foo|[a-z]+`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(mixed alt) = %v, want nil", got)
		}
	})

	// Alternation where one branch yields a multi-literal set → nil.
	t.Run("alternation_with_nested_alt_branch", func(t *testing.T) {
		inner := parse(`ab|cd`)
		outer := parse(`ef`)
		alt := &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{inner, outer}}
		if got := extractLitSet(alt); got != nil {
			t.Errorf("extractLitSet(nested alt) = %v, want nil", got)
		}
	})

	// Capture wrapping a literal → recurses and succeeds.
	t.Run("capture_single_sub", func(t *testing.T) {
		re := parse(`(foo)`)
		got := extractLitSet(re)
		if len(got) != 1 || string(got[0]) != "foo" {
			t.Errorf("extractLitSet((foo)) = %v, want [foo]", got)
		}
	})

	// Capture with zero subs (defensive) → nil.
	t.Run("capture_zero_subs", func(t *testing.T) {
		cap := &syntax.Regexp{Op: syntax.OpCapture}
		if got := extractLitSet(cap); got != nil {
			t.Errorf("extractLitSet(empty capture) = %v, want nil", got)
		}
	})

	// Empty alternation → nil because result is empty.
	t.Run("empty_alternation", func(t *testing.T) {
		alt := &syntax.Regexp{Op: syntax.OpAlternate}
		if got := extractLitSet(alt); got != nil {
			t.Errorf("extractLitSet(empty alt) = %v, want nil", got)
		}
	})

	// Unsupported op (default) → nil.
	t.Run("char_class", func(t *testing.T) {
		re := parse(`[a-z]`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(charclass) = %v, want nil", got)
		}
	})
}

func TestReverseRegexp_LineAnchors(t *testing.T) {
	// OpBeginLine ↔ OpEndLine.
	beginLine := &syntax.Regexp{Op: syntax.OpBeginLine}
	if rev := reverseRegexp(beginLine); rev.Op != syntax.OpEndLine {
		t.Errorf("reverse(OpBeginLine) = %v, want OpEndLine", rev.Op)
	}
	endLine := &syntax.Regexp{Op: syntax.OpEndLine}
	if rev := reverseRegexp(endLine); rev.Op != syntax.OpBeginLine {
		t.Errorf("reverse(OpEndLine) = %v, want OpBeginLine", rev.Op)
	}
}

func TestFindLitAnchorPoint_ParseError(t *testing.T) {
	if got := findLitAnchorPoint("[invalid"); got != nil {
		t.Errorf("findLitAnchorPoint(invalid) = %+v, want nil", got)
	}
	if got := findLitAnchorPoint("[a-z]"); got != nil {
		t.Errorf("findLitAnchorPoint([a-z]) = %+v, want nil", got)
	}
}

// TestSimpleClassPrefix exercises simpleClassPrefix directly (0% covered
// without this) across its qualifying and rejecting shapes.
func TestSimpleClassPrefix(t *testing.T) {
	parse := func(t *testing.T, p string) *syntax.Regexp {
		t.Helper()
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", p, err)
		}
		return re
	}

	t.Run("char_class_exact_count", func(t *testing.T) {
		re := parse(t, `[0-9]{8}`)
		tlo, count, ok := simpleClassPrefix(re)
		if !ok {
			t.Fatal("expected ok=true for [0-9]{8}")
		}
		if count != 8 {
			t.Errorf("count = %d, want 8", count)
		}
		// Every digit '0'-'9' should set its bit in the nibble-lookup table.
		for _, r := range "0123456789" {
			lo, hi := byte(r)&0xF, byte(r)>>4
			if tlo[lo]&(1<<hi) == 0 {
				t.Errorf("tlo table missing bit for %q", r)
			}
		}
	})

	t.Run("literal_char_exact_count", func(t *testing.T) {
		// A repeated single-char literal ("aaa") folds to OpLiteral under Repeat's child.
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 3, Max: 3,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}},
		}
		tlo, count, ok := simpleClassPrefix(re)
		if !ok || count != 3 {
			t.Fatalf("simpleClassPrefix(literal 'a'{3}) = (ok=%v, count=%d), want (true, 3)", ok, count)
		}
		if tlo['a'&0xF]&(1<<('a'>>4)) == 0 {
			t.Error("tlo table missing bit for 'a'")
		}
	})

	t.Run("capture_wrapped", func(t *testing.T) {
		re := parse(t, `([a-f]{4})`)
		_, count, ok := simpleClassPrefix(re)
		if !ok || count != 4 {
			t.Fatalf("simpleClassPrefix((capture)) = (ok=%v, count=%d), want (true, 4)", ok, count)
		}
	})

	t.Run("rejects_ranged_count", func(t *testing.T) {
		re := parse(t, `[0-9]{4,8}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a ranged {M,N} repeat")
		}
	})

	t.Run("rejects_count_above_16", func(t *testing.T) {
		re := parse(t, `[0-9]{17}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a repeat count > 16")
		}
	})

	t.Run("rejects_non_repeat", func(t *testing.T) {
		re := parse(t, `[0-9]`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a non-OpRepeat node")
		}
	})

	t.Run("rejects_non_class_child", func(t *testing.T) {
		// Repeat of a concat body (nested structure) is neither OpCharClass nor OpLiteral.
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{
				Op:  syntax.OpConcat,
				Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}, {Op: syntax.OpLiteral, Rune: []rune{'b'}}},
			}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a non-class, non-literal repeat body")
		}
	})

	t.Run("rejects_non_ascii_class", func(t *testing.T) {
		re := parse(t, `[\x{100}-\x{200}]{4}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a class with runes above ASCII")
		}
	})

	t.Run("rejects_non_ascii_literal", func(t *testing.T) {
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'Ā'}}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a literal rune above ASCII")
		}
	})

	t.Run("rejects_multi_rune_literal", func(t *testing.T) {
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a', 'b'}}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a multi-rune OpLiteral child")
		}
	})
}

// TestBuildSimplePrefixCheckBody calls buildSimplePrefixCheckBody directly
// (0% covered without this): verifies the returned bytes are a well-formed
// LEB128-size-prefixed WASM function body ending in the `end` opcode.
func TestBuildSimplePrefixCheckBody(t *testing.T) {
	re, err := syntax.Parse(`[0-9]{8}`, syntax.Perl)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tlo, count, ok := simpleClassPrefix(re)
	if !ok {
		t.Fatal("simpleClassPrefix rejected [0-9]{8}")
	}
	body := buildSimplePrefixCheckBody(tlo, count)

	sz, n, err := utils.DecodeULEB128(body)
	if err != nil {
		t.Fatalf("decode body size prefix: %v", err)
	}
	if int(sz) != len(body)-n {
		t.Fatalf("size prefix = %d, want %d (len(body)-%d)", sz, len(body)-n, n)
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("body does not end with the `end` opcode (0x0B): got 0x%02X", body[len(body)-1])
	}
}

// TestCompileLikelyNoMatchSimpleClassPrefix exercises the integration path
// (compile.go) that gates buildSimplePrefixCheckBody on
// LikelyMode == LikelyNoMatch: a bare `[class]{M}` prefix ahead of an
// UNBOUNDED literal-anchored suffix. A bounded suffix (e.g. `{36}`) is
// instead caught earlier by Gap E's analyseLitChainPrefixed and never
// reaches this path — see the alt-lit-anchor dispatch test for the analogous
// alternation case.
func TestCompileLikelyNoMatchSimpleClassPrefix(t *testing.T) {
	entry := config.RegexEntry{Pattern: `[0-9]{8}ghp_[^\s]+`, FindFunc: "f"}

	p, err := compilePattern(entry, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.litAnchorBackScanBody == nil {
		t.Fatal("compilePattern did not take the lit-anchor path")
	}
	re, _ := syntax.Parse(entry.Pattern, syntax.Perl)
	lap := findLitAnchorPointInRegexp(re)
	if lap == nil {
		t.Fatal("findLitAnchorPointInRegexp returned nil")
	}
	tlo, count, ok := simpleClassPrefix(lap.prefixRe)
	if !ok {
		t.Fatal("simpleClassPrefix rejected the pattern's prefix")
	}
	want := buildSimplePrefixCheckBody(tlo, count)
	if string(p.litAnchorBackScanBody) != string(want) {
		t.Error("litAnchorBackScanBody does not match buildSimplePrefixCheckBody's output")
	}

	// LikelyNeutral must NOT take the SIMD-verify shortcut (falls back to the
	// generic scalar backward-scan body instead).
	pNeutral, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern (neutral): %v", err)
	}
	if string(pNeutral.litAnchorBackScanBody) == string(want) {
		t.Error("LikelyNeutral unexpectedly took the buildSimplePrefixCheckBody shortcut")
	}

	mustCompileEntries(t, []config.RegexEntry{entry}, CompileOptions{LikelyMode: LikelyNoMatch})
}
