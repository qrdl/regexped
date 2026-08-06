package compile

import (
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
)

// TestEmitImmAcceptCheckMatch exercises emitImmAcceptCheckMatch directly
// (16.7% covered without this — only the hasImmAccept=false no-op branch
// was reached via the general match-body test suite). Verifies both the
// no-op path and the emitted `if state u<= limit: return pos` structure.
func TestEmitImmAcceptCheckMatch(t *testing.T) {
	t.Run("no_op_when_disabled", func(t *testing.T) {
		before := []byte{0xAA, 0xBB}
		got := emitImmAcceptCheckMatch(append([]byte(nil), before...), 5, false, 0)
		if string(got) != string(before) {
			t.Errorf("emitImmAcceptCheckMatch(hasImmAccept=false) modified input: got %v, want %v", got, before)
		}
	})

	t.Run("emits_check_when_enabled", func(t *testing.T) {
		const (
			stateLocal = 2
			posLocal   = 3
			limit      = 7
		)
		got := emitImmAcceptCheckMatch(nil, limit, true, 0)
		want := []byte{0x20, stateLocal}
		want = append(want, 0x41)
		want = utils.AppendSLEB128(want, limit)
		want = append(want, 0x4D)       // i32.le_u
		want = append(want, 0x04, 0x40) // if (void)
		want = append(want, 0x20, posLocal)
		want = append(want, 0x0F) // return
		want = append(want, 0x0B) // end if
		if string(got) != string(want) {
			t.Errorf("emitImmAcceptCheckMatch(hasImmAccept=true) =\n  %#v\nwant\n  %#v", got, want)
		}
	})
}

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
		{1, 2 * 256},     // u8: numWASM=2
		{5, 6 * 256},     // u8: numWASM=6
		{127, 128 * 256}, // u8: numWASM=128
		{128, 129 * 256}, // u8: numWASM=129 (no accept side table any more)
		{255, 256 * 256}, // u8: numWASM=256, upper boundary
		{256, 257 * 512}, // u16: numWASM=257, just over u8 limit
		{300, 301 * 512}, // u16: numWASM=301
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
