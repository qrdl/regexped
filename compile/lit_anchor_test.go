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
