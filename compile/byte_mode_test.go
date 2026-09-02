package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestUnsupportedRuneRejection pins the contract the byte-mode parameter and
// its gate were built for (TODO 57 / FABLE B29).
//
// regexped is a byte engine, so a rune it cannot hold in a byte used to be
// silently truncated — five verified divergences from Go, of which four were
// reachable through the old `hasNonASCII && !hasASCII` gate. The rule now is:
//
//   - a rune the pattern WROTE above the mode's limit is a compile error;
//   - the limit is 127 by default and 0xFF under byte_mode;
//   - runes above 0xFF are rejected in both modes, since no byte holds one;
//   - case-fold artifacts of ASCII, and the open-ended tail of a negated
//     class, are not "written" runes and stay legal.
func TestUnsupportedRuneRejection(t *testing.T) {
	cases := []struct {
		pattern              string
		rejectDef, rejectByt bool
		why                  string
	}{
		// Written non-ASCII: rejected by default, legal as bytes.
		{`[a-zé]+`, true, false, "B29 row 1 — é truncated to a byte, [0,2) where Go gives [0,4)"},
		{`\xe9`, true, false, "B29 row 2 — matched a raw Latin-1 byte where Go matched nothing"},
		{`[a\x80]+`, true, false, "mixed byte escape riding along with ASCII"},
		{`[\x80-\xff]+`, true, false, "a byte range: the capability byte_mode exists to allow"},
		{`[\xc0-\xdf]`, true, false, "UTF-8 two-byte lead range"},

		// Above 0xFF: no byte can hold it, so no mode accepts it.
		{`\p{Greek}+`, true, true, "B29 row 3 — \\p classes compiled and dropped their runes"},
		{`[α-ω]+`, true, true, "explicit codepoints past the byte range"},
		{`\pL+`, true, true, "reaches past 0xFF even though its low members fit"},

		// Not "written" runes — must stay legal in both modes.
		{`(?i:[a-z]+)`, false, false, "Go expands (?i) classes eagerly: U+017F and U+212A are its artifacts"},
		{`(?i:([a-z]+)@([a-z]+))`, false, false, "same, with captures"},
		{`(?i)^\s*SELECT\b`, false, false, "fold orbit escaping 0xFF from an ASCII literal"},
		{`(?i)k`, false, false, "B29 row 5 — the Kelvin sign, declared byte semantics"},
		{`(?i)abc`, false, false, "plain ASCII folding"},
		{`[^,]+`, false, false, "a negated class names every rune; rejecting it would reject `.`"},
		{`a.c`, false, false, "B29 row 4 — dot is one byte, declared byte semantics"},
		{`[a-z]+`, false, false, "plain ASCII"},
		{`\w+`, false, false, "plain ASCII class"},
	}

	compileWith := func(pattern string, byteMode bool) error {
		e := config.RegexEntry{Pattern: pattern, FindFunc: "find", ByteMode: byteMode}
		_, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
		return err
	}

	for _, c := range cases {
		if err := compileWith(c.pattern, false); (err != nil) != c.rejectDef {
			t.Errorf("default mode %q: rejected=%v, want %v (%s) [%v]",
				c.pattern, err != nil, c.rejectDef, c.why, err)
		}
		if err := compileWith(c.pattern, true); (err != nil) != c.rejectByt {
			t.Errorf("byte mode %q: rejected=%v, want %v (%s) [%v]",
				c.pattern, err != nil, c.rejectByt, c.why, err)
		}
	}
}

// TestUnsupportedRuneErrorText checks that a rejection tells the reader which
// of the two situations they are in. The distinction is the whole point: one
// is a flag away, the other is not supported at all, and a single "contains
// Unicode features" message (what this replaced) said neither.
func TestUnsupportedRuneErrorText(t *testing.T) {
	e := config.RegexEntry{Pattern: `[a\x80]+`, FindFunc: "find"}
	_, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), "byte_mode") || !strings.Contains(err.Error(), "U+0080") {
		t.Errorf("a byte-range rejection must name the rune and the way out, got: %v", err)
	}

	e = config.RegexEntry{Pattern: `[α-ω]+`, FindFunc: "find"}
	_, _, err = Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), "byte_mode") {
		t.Errorf("a rune above U+00FF must NOT suggest byte_mode, which cannot help: %v", err)
	}
	if !strings.Contains(err.Error(), "above U+00FF") {
		t.Errorf("expected the above-U+00FF phrasing, got: %v", err)
	}
}

// TestUnicodeOptionStillBypasses guards the escape hatch several selector
// tests depend on. CompileOptions.Unicode does not enable Unicode support —
// nothing implements it — it suppresses the rejection so a Unicode-bearing
// pattern can reach the code under test.
func TestUnicodeOptionStillBypasses(t *testing.T) {
	if _, err := SelectEngine(`[α-ω]+`, CompileOptions{}); err == nil {
		t.Error("SelectEngine([α-ω]+) accepted without the bypass, want rejected")
	}
	if _, err := SelectEngine(`[α-ω]+`, CompileOptions{Unicode: true}); err != nil {
		t.Errorf("SelectEngine([α-ω]+) with Unicode bypass: %v", err)
	}
}

// TestByteModeGateAppliesBeforeFastPaths pins the placement of the gate rather
// than only its rule.
//
// compilePattern chooses between a dozen emitters, and only some of them route
// through compile(), where the gate used to live alone. A literal-chain shape
// carrying a written non-ASCII rune therefore has to be rejected by the check
// at the top of compilePattern — otherwise a pattern's acceptability would
// depend on which emitter it happened to qualify for, which is exactly the
// kind of difference nobody would think to test for.
func TestByteModeGateAppliesBeforeFastPaths(t *testing.T) {
	// A literal chain (analyseLitChain territory) with a byte escape in it.
	for _, p := range []string{`caf\xe9[0-9]{8}`, `\xe9[0-9]{8}`, `AKIA[0-9A-Z\xe9]{16}`} {
		e := config.RegexEntry{Pattern: p, FindFunc: "find"}
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err == nil {
			t.Errorf("default mode %q: accepted, want rejected before the fast path", p)
		}
		e.ByteMode = true
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err != nil {
			t.Errorf("byte mode %q: %v", p, err)
		}
	}
}
