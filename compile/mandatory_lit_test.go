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
		// 2-byte UTF-8 literal (é = U+00E9): OpPlus recurses into Literal → n += 2
		{"é+", 2, -1},
		// 3-byte UTF-8 literal (中 = U+4E2D): n += 3
		{"中+", 3, -1},
		// 4-byte UTF-8 literal (𐀀 = U+10000): n += 4
		{"𐀀+", 4, -1},
		// OpRepeat with unbounded child max → hi = -1
		{"(?:[a-z]+){2,3}", 2, -1},
		// OpAlternate with unbounded branch → totMax = -1
		{"a+|b", 1, -1},
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

// TestFindMandatoryLitRecDegenerate covers defensive branches in findMandatoryLitRec
// that the parser never triggers (empty literal rune slice, captures/plus with wrong
// sub count). Called directly to reach these guards.
func TestFindMandatoryLitRecDegenerate(t *testing.T) {
	cases := []struct {
		name string
		re   *syntax.Regexp
	}{
		// OpLiteral with empty Rune slice → len(bs)==0 → nil.
		{"literal_empty_rune", &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{}}},
		// OpCapture with 0 subs → len(re.Sub)!=1 → nil.
		{"capture_no_sub", &syntax.Regexp{Op: syntax.OpCapture}},
		// OpPlus with 0 subs → len(re.Sub)!=1 → nil.
		{"plus_no_sub", &syntax.Regexp{Op: syntax.OpPlus}},
	}
	for _, c := range cases {
		got := findMandatoryLitRec(c.re, 0, 0)
		if got != nil {
			t.Errorf("findMandatoryLitRec(%s): got %v, want nil", c.name, got)
		}
	}
}

// TestRegexpMinMaxLenDegenerate covers edge cases that the parser never produces
// (empty Sub slices, OpNoMatch/OpEmptyMatch, unknown Op) by constructing Regexp
// nodes directly.
func TestRegexpMinMaxLenDegenerate(t *testing.T) {
	cases := []struct {
		name    string
		re      *syntax.Regexp
		wantMin int
		wantMax int
	}{
		{"OpRepeat_no_sub", &syntax.Regexp{Op: syntax.OpRepeat, Min: 1, Max: 3}, 0, 0},
		{"OpPlus_no_sub", &syntax.Regexp{Op: syntax.OpPlus}, 0, -1},
		{"OpQuest_no_sub", &syntax.Regexp{Op: syntax.OpQuest}, 0, 0},
		{"OpAlternate_no_sub", &syntax.Regexp{Op: syntax.OpAlternate}, 0, 0},
		{"OpCapture_no_sub", &syntax.Regexp{Op: syntax.OpCapture}, 0, 0},
		{"OpNoMatch", &syntax.Regexp{Op: syntax.OpNoMatch}, 0, 0},
		{"OpEmptyMatch", &syntax.Regexp{Op: syntax.OpEmptyMatch}, 0, 0},
		{"unknown_op", &syntax.Regexp{Op: syntax.Op(99)}, 0, -1},
	}
	for _, c := range cases {
		min, max := regexpMinMaxLen(c.re)
		if min != c.wantMin || max != c.wantMax {
			t.Errorf("regexpMinMaxLen(%s) = (%d,%d), want (%d,%d)", c.name, min, max, c.wantMin, c.wantMax)
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
		// Non-ASCII literal: r > 127 → returns nil.
		{"é", true, "", 0},
		// OpRepeat with Min=0: not mandatory → skipped; foo found after.
		{"[a-z]{0,3}foo", false, "foo", 0},
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
