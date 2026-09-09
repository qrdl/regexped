package main

import "testing"

func TestAsciiTwinBasics(t *testing.T) {
	cases := []struct{ text, pattern string }{
		{"\xc2\x80", "."},
		{"caf\xe9", "<([^>]+)>"},
		{"\xc2\x80\xc2\x81", "^(?:.)$"},
		{"abc", "abc"},
	}
	for _, c := range cases {
		twin, ok := asciiTwin(c.text, c.pattern)
		if !ok {
			t.Errorf("asciiTwin(%q, %q): not ok", c.text, c.pattern)
			continue
		}
		if len(twin) != len(c.text) {
			t.Errorf("asciiTwin(%q) len %d, want %d (offsets must be preserved)", c.text, len(twin), len(c.text))
		}
		if hasHighByte(twin) {
			t.Errorf("asciiTwin(%q) = %q, still has a high byte", c.text, twin)
		}
		// Distinctness: equal source bytes map to equal twin bytes and
		// different source bytes to different twin bytes.
		for i := range c.text {
			for j := range c.text {
				if (c.text[i] == c.text[j]) != (twin[i] == twin[j]) {
					t.Errorf("asciiTwin(%q) = %q: byte %d/%d correspondence broken", c.text, twin, i, j)
				}
			}
		}
		// A substitute must not collide with the pattern.
		for i := range twin {
			if c.text[i] >= 0x80 {
				for k := 0; k < len(c.pattern); k++ {
					if c.pattern[k] == twin[i] {
						t.Errorf("asciiTwin(%q, %q) = %q: substitute %q occurs in the pattern",
							c.text, c.pattern, twin, twin[i])
					}
				}
			}
		}
	}
}

func TestHighByteColsDotIsOneByte(t *testing.T) {
	// The row that shows why the corpus columns cannot be used: RE2 answers
	// 0-2 for `.` over a 2-byte codepoint; a byte engine answers 0-1.
	col0, col1, _, ok := highByteCols(".", "\xc2\x80")
	if !ok {
		t.Fatal("highByteCols refused a plain dot row")
	}
	if col1 != "0-1" {
		t.Errorf("col1 = %q, want %q (dot consumes ONE BYTE)", col1, "0-1")
	}
	if col0 != "-" {
		t.Errorf("col0 = %q, want %q (dot cannot consume both bytes)", col0, "-")
	}
}

// The substitute must be a byte the pattern cannot distinguish from the high
// byte it replaces. The first version of this file picked letters, and `\w`
// over "±" then reported two matches against a twin of "QZ" — the oracle
// lying, not the engine failing. This is that regression.
func TestTwinSubstituteIsNotAWordChar(t *testing.T) {
	for _, pat := range []string{`\w`, `\w+`, `[a-z]`, `[[:alpha:]]`, `\d`, `\s`, `[^,]`, `.`} {
		twin, ok := asciiTwin("\xc2\xb1", pat)
		if !ok {
			continue
		}
		for i := 0; i < len(twin); i++ {
			c := twin[i]
			if c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				t.Errorf("asciiTwin(%q, %q) = %q: substitute %#02x is a word character; "+
					"a high byte is not, so \\w and \\b would answer differently", "\xc2\xb1", pat, twin, c)
			}
		}
	}
}

// The property the whole oracle rests on, checked directly against Go: for a
// pattern with no high bytes, matching the twin must agree with matching the
// original under BYTE semantics. Go cannot be asked about the original, so this
// checks the weaker but sufficient thing — that no substitute changes which of
// the pattern's classes the byte falls into.
func TestTwinSubstitutesAreInterchangeable(t *testing.T) {
	pats := []string{`\w`, `[^,]+`, `.`, `(?s).`, `[a-z]+`, `\S`, `\b\w+\b`, `[^>]`, `x`}
	for _, pat := range pats {
		ranges, dotNotNL, ok := patternByteRanges(pat)
		if !ok {
			t.Fatalf("patternByteRanges(%q) failed", pat)
		}
		for _, h := range []byte{0x80, 0xC2, 0xB1, 0xE9, 0xFF} {
			twin, tok := asciiTwin(string([]byte{h}), pat)
			if !tok {
				continue
			}
			if !interchangeable(twin[0], h, ranges, dotNotNL) {
				t.Errorf("asciiTwin(%#02x, %q) chose %#02x, which is NOT interchangeable",
					h, pat, twin[0])
			}
		}
	}
}
