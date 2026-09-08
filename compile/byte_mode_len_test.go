package compile

import (
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

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
