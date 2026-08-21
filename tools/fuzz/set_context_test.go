package fuzz

import (
	"regexp"
	"testing"
)

// Context-sensitive assertions inside sets (plans/SETS.md §3.2, §3.21;
// plans/FABLE.md B40 and B43).
//
// The whole-input oracle here is the §9.6 "context-sensitive" technique:
// `\A(?s:.{p})(?:pat)` hands `pat` position p with its REAL left context, so
// `\b` and `(?m:^)` judge actual neighbours rather than a slice boundary. The
// `.{p}` prefix counts runes, so every input below is ASCII.
func contextOracle(t *testing.T, pat, input string) [][2]int {
	t.Helper()
	var out [][2]int
	for p := 0; p <= len(input); p++ {
		re := regexp.MustCompile(`\A(?s:.{` + itoa(p) + `})(?:` + pat + `)`)
		if m := re.FindStringIndex(input); m != nil {
			out = append(out, [2]int{p, m[1]})
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// runSetOne compiles a one-pattern `overlapping: true` set and drives its find
// to exhaustion.
func runSetOne(t *testing.T, pat, input string) [][2]int {
	t.Helper()
	w, err := compileSet([]string{pat})
	if err != nil {
		t.Fatalf("compile %q: %v", pat, err)
	}
	got, hang, err := runWasmSetFind(w, input, 1)
	if err != nil {
		t.Fatalf("run %q on %q: %v", pat, input, err)
	}
	if hang {
		t.Fatalf("hang on %q / %q", pat, input)
	}
	out := make([][2]int, 0, len(got))
	for _, m := range got {
		out = append(out, [2]int{m.Start, m.End})
	}
	sortSpans(out)
	return out
}

func checkSetContext(t *testing.T, pat, input string) {
	t.Helper()
	want := contextOracle(t, pat, input)
	sortSpans(want)
	got := runSetOne(t, pat, input)
	if len(want) != len(got) {
		t.Fatalf("%q on %q: expected %d matches %v, got %d %v", pat, input, len(want), want, len(got), got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%q on %q: match %d expected %v, got %v", pat, input, i, want[i], got[i])
		}
	}
}

// TestSetLineAnchors closes plans/FABLE.md B43: (?m:^) in a set used to
// collapse to "position 0 only", so every match after the first line was lost.
func TestSetLineAnchors(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`(?m:^)foo`, "foo\nfoo\nxfoo"},
		{`(?m:^)foo`, "xfoo\nfoo"},
		{`(?m:^)a+`, "aa\nbaa\naa"},
		{`foo(?m:$)`, "foo\nfoox\nfoo"},
		{`(?m:^)foo(?m:$)`, "foo\nfoox\nfoo"},
		{`\Afoo`, "foo\nfoo"},
		{`(?m:^)`, "a\nb\n"},
		{`(?m:^)x?`, "x\nx"},
	}
	for _, c := range cases {
		t.Run(c.pat+" on "+c.input, func(t *testing.T) { checkSetContext(t, c.pat, c.input) })
	}
}

// TestSetTextAnchorIgnoresFrom pins §4.2: \A is anchored to real input
// position 0 whatever `from` the caller passed. Driving find to exhaustion
// covers every from value in turn.
func TestSetTextAnchorIgnoresFrom(t *testing.T) {
	got := runSetOne(t, `\Aab`, "abab")
	if len(got) != 1 || got[0] != [2]int{0, 2} {
		t.Fatalf(`\Aab on "abab": expected exactly [[0 2]], got %v`, got)
	}
}

// TestSetWordBoundaries closes plans/FABLE.md B40: \b patterns in a set used
// to match nothing at all.
func TestSetWordBoundaries(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`\bfoo\b`, "foo bar foo"},
		{`\bfoo`, "foo foofoo xfoo"},
		{`foo\b`, "foo foofoo foox"},
		{`\Bfoo`, "xfoo foo"},
		{`\bcat|\bdog`, "cat dog concat"},
		{`\b\w+\b`, "ab cd"},
	}
	for _, c := range cases {
		t.Run(c.pat+" on "+c.input, func(t *testing.T) { checkSetContext(t, c.pat, c.input) })
	}
}
