package compile

import (
	"fmt"
	"regexp/syntax"
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
//   - a rune NAMED AS A MEMBER above the mode's limit is a compile error;
//   - the limit is 127 by default and 0xFF under byte_mode;
//   - runes above 0xFF are rejected in both modes, since no byte holds one;
//   - case-fold artifacts of ASCII, and a range whose top endpoint is
//     U+10FFFF, name no member above the limit and stay legal.
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
		// The same class in both spellings. See TestOpenEndedTailSpellings for
		// why no rule can separate them, and the one below for where the line
		// actually falls.
		{`[a-\x{10ffff}]+`, false, false, "an explicit range to U+10FFFF IS the complement of everything below"},
		{"[^\\x00-`]+", false, false, "the same class, spelled as a complement"},
		{`[a-\x{ffff}]+`, true, true, "a top endpoint below U+10FFFF names members no byte holds"},
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

// TestOpenEndedTailSpellings pins the boundary of the U+10FFFF exemption and
// the reason it cannot be drawn any tighter.
//
// A review asked for explicit range endpoints (`[a-\x{10ffff}]`) to be
// separated from parser-generated negated-class tails, on the grounds that the
// first is a rune the user wrote. They cannot be separated: Go applies negation
// while PARSING, so the complement spelling and the explicit spelling produce
// one identical AST and one identical rune pair long before this gate runs. A
// rule rejecting the explicit form would reject every negated class with it.
//
// Nor is anything lost by accepting them. The tail SATURATES at 0xFF in both
// modes rather than truncating at the mode's limit, so the class means "every
// byte from the low endpoint up" — exactly what the complement means to a byte
// engine. The accepted byte set is asserted, not just the acceptance: a change
// that truncated the tail at 0x7F would still compile, and would be a silent
// wrong answer.
//
// Where the line DOES fall is the top endpoint. `[a-\x{ffff}]` names members
// no byte can hold and is rejected in both modes.
func TestOpenEndedTailSpellings(t *testing.T) {
	const explicit = `[a-\x{10ffff}]`
	const complement = "[^\\x00-`]"

	// Same AST, so nothing downstream can tell them apart.
	pe, err := syntax.Parse(explicit, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", explicit, err)
	}
	pc, err := syntax.Parse(complement, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", complement, err)
	}
	if pe.String() != pc.String() {
		t.Errorf("%q and %q parse differently (%q vs %q) — the exemption could be narrowed after all",
			explicit, complement, pe.String(), pc.String())
	}

	// Same accepted bytes, saturating at 0xFF, in both modes.
	for _, byteMode := range []bool{false, true} {
		gotE := acceptedByteRange(t, explicit, byteMode)
		gotC := acceptedByteRange(t, complement, byteMode)
		if gotE != gotC {
			t.Errorf("byteMode=%v: %q accepts %s but %q accepts %s — one spelling compiles differently",
				byteMode, explicit, gotE, complement, gotC)
		}
		if want := "61..ff"; gotE != want {
			t.Errorf("byteMode=%v: %q accepts %s, want %s (the tail must saturate, not truncate)",
				byteMode, explicit, gotE, want)
		}
	}

	// And the endpoint below U+10FFFF is still rejected.
	for _, byteMode := range []bool{false, true} {
		e := config.RegexEntry{Pattern: `[a-\x{ffff}]+`, FindFunc: "find", ByteMode: byteMode}
		if _, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{}); err == nil {
			t.Errorf("byteMode=%v: [a-\\x{ffff}] accepted, want rejected", byteMode)
		}
	}
}

// acceptedByteRange reports the span of single bytes that reach an accepting
// state from the start state, as "lo..hi".
func acceptedByteRange(t *testing.T, pattern string, byteMode bool) string {
	t.Helper()
	m, err := compile(pattern, CompileOptions{ForceEngine: EngineDFA, LeftmostFirst: true, ByteMode: byteMode})
	if err != nil {
		t.Fatalf("compile %q (byteMode=%v): %v", pattern, byteMode, err)
	}
	tbl := dfaTableFrom(m.(*dfa))
	lo, hi := -1, -1
	for b := 0; b < 256; b++ {
		ns := tbl.transitions[tbl.startState*256+b]
		if ns < 0 {
			continue
		}
		if _, ok := tbl.acceptStates[ns]; !ok {
			continue
		}
		if lo < 0 {
			lo = b
		}
		hi = b
	}
	if lo < 0 {
		return "none"
	}
	return fmt.Sprintf("%02x..%02x", lo, hi)
}
