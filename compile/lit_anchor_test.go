package compile

import (
	"regexp/syntax"
	"testing"
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
