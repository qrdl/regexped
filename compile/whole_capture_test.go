package compile

import (
	"regexp/syntax"
	"testing"
)

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
