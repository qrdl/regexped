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

// Membership must be compared per CLASS, not per range.
//
// A negated class is several ranges: `[^a]` compiles to [0x00-0x60] plus
// [0x62-U+10FFFF]. A control character lies in the first and a high byte in the
// second, so a range-by-range comparison calls them distinguishable when the
// automaton — which branches on the class as a whole — cannot tell them apart.
// The first version compared per range and so refused a twin for every negated
// class, which is exactly the family this exists to cover: measured on the set
// corpus, 674 of 778 high-byte inputs fell back to the pinned path.
func TestTwinAcceptsNegatedClasses(t *testing.T) {
	for _, pat := range []string{`[^a]`, `[^a]+`, `[^>]+`, `<[^>]+>`, `[^,]+,`, `\S+`, `[^\x00]`} {
		for _, in := range []string{"a\xe9", "\xe9a", "a\xc3\xa2b", "\xe9\xe9"} {
			twin, ok := asciiTwin(in, pat)
			if !ok {
				t.Errorf("asciiTwin(%q, %q): no twin; a negated class admits both a "+
					"control character and a high byte, so one must exist", in, pat)
				continue
			}
			if len(twin) != len(in) {
				t.Errorf("asciiTwin(%q, %q) = %q: length changed, offsets would move", in, pat, twin)
			}
		}
	}
}

// Whatever the grouping, a twin must never be accepted where the pattern really
// can distinguish the two bytes.
//
// `[\x00-\x7f]` is the clean case: it contains EVERY ASCII byte and no high
// byte, so no substitute can behave like 0xE9 and the row must fall back.
//
// The near-misses matter as much. `[\x00-\x1f]` looks like it should refuse a
// twin, and must not: 0x7F is outside that class and so is 0xE9, which makes
// them interchangeable under it. An earlier version of this test asserted the
// opposite and was simply wrong about the contract.
func TestTwinRejectsDistinguishingPatterns(t *testing.T) {
	if twin, ok := asciiTwin("\xe9", `[\x00-\x7f]`); ok {
		t.Errorf("asciiTwin(%q, %q) = %q: every ASCII byte is in that class and no "+
			"high byte is, so no substitute can be interchangeable", "\xe9", `[\x00-\x7f]`, twin)
	}
	// Accepted, and the substitute must genuinely sit outside the class.
	for _, pat := range []string{`[\x00-\x1f]`, `[\x01\x02]+`} {
		twin, ok := asciiTwin("\xe9", pat)
		if !ok {
			t.Errorf("asciiTwin(%q, %q): no twin, but a byte outside the class exists", "\xe9", pat)
			continue
		}
		classes, dotNotNL, pok := patternByteRanges(pat)
		if !pok {
			t.Fatalf("patternByteRanges(%q) failed", pat)
		}
		if !interchangeable(twin[0], 0xE9, classes, dotNotNL) {
			t.Errorf("asciiTwin(%q, %q) = %q: chosen substitute is not interchangeable",
				"\xe9", pat, twin)
		}
	}
}

// A pattern naming the control characters AS A CLASS must not exhaust the pool.
//
// `(?:[[:cntrl:]])$` contains every byte of the control-character tier and no
// high byte, so under it no first-tier candidate is interchangeable. Measured
// on the shuffled 70-pattern set chunks, that ONE pattern pinned all 674
// high-byte inputs of every chunk it landed in. The punctuation tier exists for
// it: a punctuation byte is outside [[:cntrl:]] exactly as a high byte is.
func TestTwinSurvivesControlCharClass(t *testing.T) {
	for _, pat := range []string{`(?:[[:cntrl:]])$`, `[[:cntrl:]]`, `[\x00-\x1f\x7f]`} {
		twin, ok := asciiTwin("\xc2\x80", pat)
		if !ok {
			t.Errorf("asciiTwin(%q, %q): no twin; a byte outside [[:cntrl:]] is "+
				"interchangeable with a high byte under it", "\xc2\x80", pat)
			continue
		}
		classes, dotNotNL, pok := patternByteRanges(pat)
		if !pok {
			t.Fatalf("patternByteRanges(%q) failed", pat)
		}
		for i := range twin {
			if !interchangeable(twin[i], "\xc2\x80"[i], classes, dotNotNL) {
				t.Errorf("asciiTwin(%q, %q) = %q: byte %d not interchangeable", "\xc2\x80", pat, twin, i)
			}
		}
	}
}

// Every candidate, in both tiers, must be non-word and non-space. `\b`, `\B`
// and `\s` are empty-width assertions rather than classes, so they contribute
// no ranges for interchangeable() to compare — the pool itself has to carry the
// guarantee.
func TestTwinCandidatesAreNonWordNonSpace(t *testing.T) {
	for _, c := range twinCandidates {
		if c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			t.Errorf("candidate %#02x is a word character; \\b and \\w would differ on the twin", c)
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' {
			t.Errorf("candidate %#02x is a space character; \\s would differ on the twin", c)
		}
		if c >= 0x80 {
			t.Errorf("candidate %#02x is not ASCII", c)
		}
	}
}
