package compile

import (
	"regexp/syntax"
	"testing"
)

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
	}
	for _, c := range cases {
		re := parse(c.pattern)
		gotMin, gotMax := regexpMinMaxLen(re)
		if gotMin != c.wantMin || gotMax != c.wantMax {
			t.Errorf("regexpMinMaxLen(%q) = (%d,%d), want (%d,%d)",
				c.pattern, gotMin, gotMax, c.wantMin, c.wantMax)
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
	}
	for _, c := range cases {
		got := findMandatoryLit(c.pattern)
		if c.wantNil {
			if got != nil {
				t.Errorf("findMandatoryLit(%q): got %v, want nil", c.pattern, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("findMandatoryLit(%q): got nil, want lit=%q", c.pattern, c.wantLit)
			continue
		}
		if string(got.bytes) != c.wantLit {
			t.Errorf("findMandatoryLit(%q): lit=%q, want %q", c.pattern, got.bytes, c.wantLit)
		}
		if got.minOff != c.wantMin {
			t.Errorf("findMandatoryLit(%q): minOff=%d, want %d", c.pattern, got.minOff, c.wantMin)
		}
		if got.maxOff < got.minOff {
			t.Errorf("findMandatoryLit(%q): maxOff %d < minOff %d", c.pattern, got.maxOff, got.minOff)
		}
	}
}
