package compile

import (
	"regexp/syntax"
	"testing"
)

func compileTestDFA(t *testing.T, pattern string, leftmostFirst bool) *dfaTable {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	re = re.Simplify()
	prog, err := syntax.Compile(re)
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	d := newDFA(prog, false, leftmostFirst)
	return dfaTableFrom(d)
}

// dfaStateCount returns the number of LF DFA states for the given pattern
// after stripping capture groups. Used for diagnostics in tests.
func dfaStateCount(pattern string) (int, error) {
	re2, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, err
	}
	stripCaptures(re2)
	prog, err := syntax.Compile(re2.Simplify())
	if err != nil {
		return 0, err
	}
	d := newDFA(prog, false, true) // leftmostFirst
	t := dfaTableFrom(d)
	return t.numStates, nil
}

func TestDFAStateCount(t *testing.T) {
	cases := []struct {
		pattern string
		wantMin int
		wantMax int
	}{
		// Single literal: very small DFA.
		{"a", 1, 5},
		// Longer literal: still small.
		{"foobar", 1, 10},
		// Simple character class.
		{"[a-z]+", 1, 10},
	}
	for _, c := range cases {
		got, err := dfaStateCount(c.pattern)
		if err != nil {
			t.Errorf("dfaStateCount(%q): %v", c.pattern, err)
			continue
		}
		if got < c.wantMin || got > c.wantMax {
			t.Errorf("dfaStateCount(%q) = %d, want [%d, %d]", c.pattern, got, c.wantMin, c.wantMax)
		}
	}
}

func TestComputeByteClasses(t *testing.T) {
	// Pattern [a-z]+ should produce equivalence classes that group
	// a-z together and all other bytes together.
	tab := compileTestDFA(t, "[a-z]+", false)
	classMap, classRep, numClasses := computeByteClasses(tab)

	if numClasses < 2 {
		t.Errorf("expected at least 2 classes, got %d", numClasses)
	}
	// All a-z bytes should map to the same class.
	azClass := classMap['a']
	for b := byte('b'); b <= 'z'; b++ {
		if classMap[b] != azClass {
			t.Errorf("byte %c not in same class as 'a': got %d, want %d", b, classMap[b], azClass)
		}
	}
	// classRep length should equal numClasses.
	if len(classRep) != numClasses {
		t.Errorf("classRep len %d != numClasses %d", len(classRep), numClasses)
	}
	_ = classRep
}

func TestIsAnchoredFind(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"^foo", true},
		{"\\Afoo", true},
		{"foo", false},
		{"foo.*bar", false},
		// Multiline ^ matches at start-of-line (after \n), not just start-of-input →
		// hasNewlineBoundary=true and midStartNewline can match → not anchored.
		{"(?m:^foo)", false},
		// Word boundary: \bfoo can match anywhere after a word boundary → not anchored.
		{`\bfoo`, false},
	}
	for _, c := range cases {
		tab := compileTestDFA(t, c.pattern, false)
		if got := isAnchoredFind(tab); got != c.want {
			t.Errorf("isAnchoredFind(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestDFATableBytes(t *testing.T) {
	cases := []struct {
		numStates int
		want      int
	}{
		{1, 2 * 257},     // u8: n=2
		{5, 6 * 257},     // u8: n=6
		{255, 256 * 257}, // u8: n=256, boundary
		{256, 257 * 513}, // u16: n=257, just over boundary
		{300, 301 * 513}, // u16: n=301
	}
	for _, c := range cases {
		got := dfaTableBytes(&dfaTable{numStates: c.numStates})
		if got != c.want {
			t.Errorf("dfaTableBytes(numStates=%d) = %d, want %d", c.numStates, got, c.want)
		}
	}
}

func TestComputePrefix(t *testing.T) {
	cases := []struct {
		pattern    string
		wantPrefix string
	}{
		{"foobar.*", "foobar"},
		{"[a-z]+", ""},
		{"a", "a"},
	}
	for _, c := range cases {
		tab := compileTestDFA(t, c.pattern, false)
		prefix := computePrefix(tab)
		if string(prefix) != c.wantPrefix {
			t.Errorf("computePrefix(%q) = %q, want %q", c.pattern, prefix, c.wantPrefix)
		}
	}
}
