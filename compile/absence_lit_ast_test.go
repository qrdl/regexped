package compile

import (
	"regexp"
	"regexp/syntax"
	"testing"
)

// ── The absence-literal prefilter's AST walk ───────────────────────────────
//
// findAbsenceLit answers "does every match of this pattern contain this exact
// byte string?", which the G12 prefilter uses to retire a pattern from the
// alive mask without walking it. The direction of any error matters
// asymmetrically: claiming a literal that is NOT mandatory under-approximates
// alive and silently loses matches, while missing one merely costs a walk.
//
// It is a pure function of the parsed AST, so the refusals — the interesting
// half — are testable directly rather than through a compiled set.
func TestFindAbsenceLit(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    string // "" = no literal claimed
	}{
		{"plain literal", `abcd`, "abcd"},
		{"literal inside a concat", `[a-z]+MIDDLE[0-9]+`, "MIDDLE"},
		{"longest child of a concat wins", `xy[0-9]LONGEST[a-z]ab`, "LONGEST"},
		{"plus body is mandatory", `(?:abc)+`, "abc"},
		{"repeat with min >= 1", `(?:abc){2,4}`, "abc"},

		// Refusals. Each is a case where claiming the literal would be wrong.
		{"alternation: mandatory in one branch only", `abc|xyz`, ""},
		{"star: the body may be skipped", `(?:abc)*`, ""},
		{"quest: the body may be skipped", `(?:abc)?`, ""},
		{"repeat with min 0", `(?:abc){0,3}`, ""},
		{"case-folded literal needs a case-insensitive search", `(?i)abcd`, ""},
		{"non-ASCII literal needs UTF-8 encoding", `caf\x{e9}xx`, ""},
		{"a class is not a literal", `[a-z]+`, ""},
		{"empty", `(?:)`, ""},

		// A capture is transparent: its body's literal is still mandatory.
		// Reached only when captures are NOT stripped first, which is how
		// findAbsenceLit is called from analyses that run before stripping.
		{"capture is transparent", `(abcd)`, "abcd"},
		{"capture inside a concat", `x(MIDDLE)y`, "MIDDLE"},

		// A literal longer than absenceLitMax is TRUNCATED rather than
		// refused: a prefix of a mandatory literal is still mandatory, and a
		// shorter needle is only weaker, never wrong.
		{"over the length cap", `abcdefghijklmnopqrstuvwxyz0123456789`, "abcdefghijklmnop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re, err := syntax.Parse(tc.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.pattern, err)
			}
			got := string(findAbsenceLit(re.Simplify()))
			if got != tc.want {
				t.Errorf("findAbsenceLit(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
	// A nil AST is reachable from the recursive walk over a malformed subtree.
	if got := findAbsenceLit(nil); got != nil {
		t.Errorf("findAbsenceLit(nil) = %q, want nil", got)
	}
}

// TestFindAbsenceLitIsSound is the property behind the whole prefilter: any
// literal it claims must appear in EVERY string the pattern matches.
//
// Checked against Go's own engine over generated inputs, because the walk is
// an approximation and the cheap way to be wrong is to claim a literal from a
// branch that some match does not take.
func TestFindAbsenceLitIsSound(t *testing.T) {
	patterns := []string{
		`abcd`, `[a-z]+MIDDLE[0-9]+`, `(?:abc)+`, `(?:abc){2,4}`,
		`x[0-9]{2}KEY[a-f]*`, `PRE(?:a|b)POST`, `[0-9]+-[0-9]+`,
		`abc|xyz`, `(?:abc)*def`, `(?i)abcd`,
	}
	inputs := []string{
		"", "abcd", "abcdabcd", "zzMIDDLE99", "x12KEYaf", "PREaPOST", "PREbPOST",
		"12-34", "xyz", "def", "abcdef", "ABCD", "MIDDLE", "abc",
		"qqqabcdqqq", "  abcd  ", "aMIDDLEb", "x99KEY",
	}
	for _, pat := range patterns {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		lit := findAbsenceLit(re.Simplify())
		if len(lit) == 0 {
			continue
		}
		goRe, gerr := regexp.Compile(pat)
		if gerr != nil {
			t.Fatalf("Go rejects %q: %v", pat, gerr)
		}
		for _, in := range inputs {
			if !goRe.MatchString(in) {
				continue
			}
			// The pattern matched, so the claimed literal must be present.
			if !containsBytes(in, string(lit)) {
				t.Errorf("%q claims mandatory literal %q, but it matches %q, "+
					"which does not contain it — the prefilter would drop a real match",
					pat, lit, in)
			}
		}
	}
}

func containsBytes(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
