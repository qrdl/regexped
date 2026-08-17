package compile

import (
	"fmt"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
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
	d, ok := newDFA(prog, false, leftmostFirst, maxHelperDFAStates)
	if !ok {
		t.Fatalf("newDFA(%q): state limit exceeded", pattern)
	}
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
	d, ok := newDFA(prog, false, true, maxHelperDFAStates) // leftmostFirst
	if !ok {
		return 0, fmt.Errorf("newDFA(%q): state limit exceeded", pattern)
	}
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

		// TODO task 47: multi-step dead-end chains. A mid-position ^ / \A gives
		// midStartState live outgoing transitions (so the old one-step check
		// said "not anchored"), but every state reachable through them needs a
		// begin-of-text assertion that can never hold after a byte has been
		// consumed, so none of them can ever accept.
		{"a^b", true},     // midStart --a--> dead-end, one step past midStart
		{`a\Ab`, true},    // same via \A
		{"^ab|a^b", true}, // real match only via the ^ branch
		{`0*^0`, true},    // FUZZER_BUGS.md §23's repro
		{`a$00|^0`, true}, // task 48's fuzzer seed
		{`[a-z]^x`, true}, // dead-end reached through a byte class
		{`(?:\Aa|b\Ac)`, true},
		{"a^", true},
		// Still not anchored: the literal branch matches at any position, so
		// midStart reaches a genuinely accepting state.
		{"x|^0", false},
		{`\Aa|b`, false},
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

// TestDFAU16RowDedup exercises the u16 transition-table row-dedup path
// (buildDFALayout's rowMap, emitU16Transition, dfaDataSegments) — TEST.md T1.
// [a-z]{300} produces 301 states (> 256 -> u16 table); the uniform class-run
// body means nearly all rows are identical, so numUniqueRows <= 255 and
// useRowDedup triggers.
func TestDFAU16RowDedup(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{300}", MatchFunc: "m"}},
			CompileOptions{MaxDFAStates: 100000})
	})
	t.Run("find", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: "[a-z]{300}", FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 100000})
	})
}

// TestDFAMandLitFindWordNewlineBoundary exercises the mandatory-lit find
// prologue combined with word/newline boundary handling in buildFindBody —
// TEST.md T2. This area has a documented historical bug (simdMaskLocal
// clobbering ptr, found via (?m:^(foo.*)$)).
func TestDFAMandLitFindWordNewlineBoundary(t *testing.T) {
	t.Run("newline_boundary_u8_compressed", func(t *testing.T) {
		// (?m)^[a-z]{150}FOOBAR$: >128 states, u8-compressed table, mandatory
		// literal "FOOBAR" with no fixed prefix, newline-boundary anchors.
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m)^[a-z]{150}FOOBAR$`, FindFunc: "f"}})
	})
	t.Run("word_boundary_u16", func(t *testing.T) {
		// \b[a-z]{300}FOOBAR\b: > 256 states forces u16, mandatory literal +
		// word-boundary variant.
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `\b[a-z]{300}FOOBAR\b`, FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 100000})
	})
}

// TestDFANonMidDominantU16Sentinel exercises the reserved-value (254+)
// sentinel check in the u16 find dispatcher for a non-accepting dominant
// self-loop (emitFindMidAcceptDispatch's hasNonMidVals/"val < 254" branch) —
// TEST.md T3. [^,]{300,}XYZ forces > 256 states (u16) via the bounded-then-
// unbounded repetition, and the unbounded [^,] tail state is a genuine
// non-mid dominant (self-loops on 254 of 256 bytes, exits on ',' and 'X',
// not itself accepting since "XYZ" must still follow). Confirmed live via
// direct buildDFALayout probing: numWASM=305, useU8=false, one dominant with
// isMidAccept=false. The literal is too long for lit-anchor's forward table
// (useU8 required, and 305 states exceeds 256) and findMandatoryLit returns
// nil for it (no fixed prefix on either side), so this reaches the general
// (non-mandatory-lit) dispatch branch rather than T2's mandatory-lit path.
func TestDFANonMidDominantU16Sentinel(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[^,]{300,}XYZ", FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 100000})
}

// TestDFATeddyThreeFourBytePrefix exercises the Teddy T2/T3 (3-byte/4-byte
// literal prefix) SIMD table construction and emission — TEST.md T4. An
// alternation with >= 3 branches, each with a distinct >= 4-byte fixed
// literal prefix, reaches the general DFA find path (not the lit-chain-alt
// frontend) and has few enough distinct first bytes for Teddy.
func TestDFATeddyThreeFourBytePrefix(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:cat|dog|bird|frog)[0-9]+`, FindFunc: "f"}})
}

// TestDFACaseFoldUnicodeOrbit exercises the full-Unicode SimpleFold orbit
// expansion for a case-insensitive single rune in nfaBuildInputMap
// (InstRune1) — TEST.md T5. (?i)k folds across a 3-way orbit: Kelvin sign
// U+212A <-> 'K' <-> 'k' — not just ASCII upper/lower.
func TestDFACaseFoldUnicodeOrbit(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?i)k`, MatchFunc: "m"}})
}

// TestDFAImmAcceptMidStartSinglePattern exercises the bits==0 -> bits=1
// sentinel fallback on midStart/midStartWord/midStartNewline for a nullable,
// immediate-accepting pattern in single-pattern (non-set) mode, where
// nfaAcceptBits is always 0 — TEST.md T6.
func TestDFAImmAcceptMidStartSinglePattern(t *testing.T) {
	t.Run("word_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:x)?\b`, FindFunc: "f"}})
	})
	t.Run("newline_boundary", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?m)(?:x)?$`, FindFunc: "f"}})
	})
}

// TestDFALitAnchorNonMidDominant exercises the dominant bulk-skip dispatch
// for lit-anchor find (buildLitAnchorFindBody) when the dominant self-loop
// state is not an accept state — TEST.md T7. .*bar has a wide non-accepting
// self-loop ('.' excludes only '\n', minus the 'b' exit byte that starts the
// literal) confirmed live via buildDFALayout probing (isMidAccept=false),
// and findLitAnchorPoint/l.useU8 both qualify (numWASM=5) so the pattern
// reaches the lit-anchor path rather than the general find dispatch.
func TestDFALitAnchorNonMidDominant(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `.*bar`, FindFunc: "f"}})
}

// TestDFAAltLitAnchorNoSIMDFallback exercises the default (scalar-scan, no
// Teddy/multi-eq SIMD) case in buildAltLitAnchorFindBody, reached when the
// alt-lit-anchor union of candidate first bytes is empty or exceeds 64 —
// TEST.md T8. Each branch below has an equal-length fixed literal prefix (a
// distinct upper-case letter, required for the alt-lit-anchor equal-prefix
// restriction) followed by a wide character class, giving > 64 distinct
// candidate first bytes across all branches combined.
func TestDFAAltLitAnchorNoSIMDFallback(t *testing.T) {
	var pattern string
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
	for i, c := range letters {
		if i > 0 {
			pattern += "|"
		}
		pattern += string(c) + `[a-z]+end`
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "f"}})
}

// TestDFAMixedMidNonMidDominant exercises the mixed mid-accept +
// non-mid-accept dominant dispatch in emitPhase4Dispatch (buildMatchBody) —
// TEST.md T9. [^,]*bar[^\n]* produces (confirmed live via buildDFALayout
// probing with the LL/leftmostFirst=false DFA that match mode actually
// uses) two mid-accept dominants and one non-mid-accept dominant: the
// trailing [^\n]* run can end the match at any point (mid-accept, wide
// self-loop), while the leading [^,]* run before the mandatory "bar" cannot
// (non-mid-accept).
func TestDFAMixedMidNonMidDominant(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `[^,]*bar[^\n]*`, MatchFunc: "m"}})
}

// TestDFALenAltAnchorSkipPartialLane exercises the lenAlt (length-
// discriminated alternation) frontend's compile-time branch elision for
// anchor incompatibilities plus partial (<16-byte) SIMD lane masking in
// buildLenAltMatchBody — TEST.md T10. Branches have mixed \b anchors and
// non-16-multiple literal lengths.
func TestDFALenAltAnchorSkipPartialLane(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `\bfoo[0-9]{3}|bar[0-9]{5}`, MatchFunc: "m"}})
}

// TestDFASetsEmptyFallbackStrictPrefix exercises the constant "no match"
// body returned by genSuffixWASM when a set bucket's literal has no
// required suffix chars (i.e. one literal is a strict prefix of another in
// the same bucket) — TEST.md T11.
func TestDFASetsEmptyFallbackStrictPrefix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p_cat", Pattern: "cat"},
			{Name: "p_catalog", Pattern: "catalog"},
		},
		Sets: []config.SetConfig{
			{Name: "s1", FindAny: "s1_find", Patterns: config.PatternSelector{All: true}},
		},
	}
	if _, _, err := CompileFile(cfg, ""); err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
}

// TestExpandWithWBIgnoresWordBitsWithoutWordBoundary pins the invariant
// plans/OPUS.md §N9's optimisation rests on: when a program contains no
// \b/\B instruction, expanding an NFA set under ecWordBoundary and under
// ecNoWordBoundary produces identical results, so newDFA computes one
// expansion (and one input map) instead of two.
//
// If a future change makes either context bit observable without an
// EmptyWordBoundary/EmptyNoWordBoundary instruction being present, this test
// fails here rather than silently producing a wrong DFA for every
// word-boundary-free pattern in the corpus.
func TestExpandWithWBIgnoresWordBitsWithoutWordBoundary(t *testing.T) {
	// Every shape that reaches the loop: literals, classes, alternation,
	// quantifiers, line anchors, text anchors, captures. None contains \b/\B.
	patterns := []string{
		`abc`,
		`[a-z]+@[a-z]+\.[a-z]{2,}`,
		`foo|bar|baz`,
		`(?m:^foo$)`,
		`^abc$`,
		`(a)(b)?`,
		`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`,
		`<(.+?)>`,
		`(?i)select\s+.*\s+from`,
		`a*b+c?`,
	}
	for _, pat := range patterns {
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		// Sanity: the pattern really has no word-boundary instruction, so the
		// test is exercising the branch it claims to.
		for _, inst := range prog.Inst {
			if inst.Op == syntax.InstEmptyWidth {
				op := syntax.EmptyOp(inst.Arg)
				if op&(syntax.EmptyWordBoundary|syntax.EmptyNoWordBoundary) != 0 {
					t.Fatalf("%q unexpectedly contains \\b/\\B — pick a different pattern", pat)
				}
			}
		}
		for _, lf := range []bool{false, true} {
			for _, beginCtx := range []int{0, ecBegin, ecBeginLine} {
				set := nfaEpsilonClosure(prog, []uint32{uint32(prog.Start)}, beginCtx, lf)
				word := nfaExpandWithWB(prog, set, ecWordBoundary|beginCtx, lf)
				nonWord := nfaExpandWithWB(prog, set, ecNoWordBoundary|beginCtx, lf)
				if nfaStatesKey(word) != nfaStatesKey(nonWord) {
					t.Errorf("%q (leftmostFirst=%v, beginCtx=%d): word/non-word expansions differ:\n  word=%v\n  nonWord=%v",
						pat, lf, beginCtx, word, nonWord)
					continue
				}
				// The ambiguity probes must also be inert, since newDFA skips
				// both of them on this branch.
				if nfaBoundaryTargetIsAmbiguous(prog, set, beginCtx, ecWordBoundary|beginCtx, lf) ||
					nfaBoundaryTargetIsAmbiguous(prog, set, beginCtx, ecNoWordBoundary|beginCtx, lf) {
					t.Errorf("%q (leftmostFirst=%v, beginCtx=%d): boundary-ambiguity probe fired without any \\b/\\B",
						pat, lf, beginCtx)
				}
			}
		}
	}
}
