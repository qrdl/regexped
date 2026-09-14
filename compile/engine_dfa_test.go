package compile

import (
	"fmt"
	"reflect"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
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

		// Multi-step dead-end chains. A mid-position ^ / \A gives
		// midStartState live outgoing transitions (so the old one-step check
		// said "not anchored"), but every state reachable through them needs a
		// begin-of-text assertion that can never hold after a byte has been
		// consumed, so none of them can ever accept.
		{"a^b", true},     // midStart --a--> dead-end, one step past midStart
		{`a\Ab`, true},    // same via \A
		{"^ab|a^b", true}, // real match only via the ^ branch
		{`0*^0`, true},    // a past defect’s repro
		{`a$00|^0`, true}, // a fuzzer seed
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
// (buildDFALayout's rowMap, emitU16Transition, dfaDataSegments) — the test plan T1.
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
// the test plan T2. This area has a documented historical bug (simdMaskLocal
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
// the test plan T3. [^,]{300,}XYZ forces > 256 states (u16) via the bounded-then-
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
// literal prefix) SIMD table construction and emission — the test plan T4. An
// alternation with >= 3 branches, each with a distinct >= 4-byte fixed
// literal prefix, reaches the general DFA find path (not the lit-chain-alt
// frontend) and has few enough distinct first bytes for Teddy.
func TestDFATeddyThreeFourBytePrefix(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:cat|dog|bird|frog)[0-9]+`, FindFunc: "f"}})
}

// TestDFACaseFoldUnicodeOrbit exercises the full-Unicode SimpleFold orbit
// expansion for a case-insensitive single rune in nfaBuildInputMap
// (InstRune1) — the test plan T5. (?i)k folds across a 3-way orbit: Kelvin sign
// U+212A <-> 'K' <-> 'k' — not just ASCII upper/lower.
func TestDFACaseFoldUnicodeOrbit(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?i)k`, MatchFunc: "m"}})
}

// TestDFAImmAcceptMidStartSinglePattern exercises the bits==0 -> bits=1
// sentinel fallback on midStart/midStartWord/midStartNewline for a nullable,
// immediate-accepting pattern in single-pattern (non-set) mode, where
// nfaAcceptBits is always 0 — the test plan T6.
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
// state is not an accept state — the test plan T7..*bar has a wide non-accepting
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
// the test plan T8. Each branch below has an equal-length fixed literal prefix (a
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
// the test plan T9. [^,]*bar[^\n]* produces (confirmed live via buildDFALayout
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
// buildLenAltMatchBody — the test plan T10. Branches have mixed \b anchors and
// non-16-multiple literal lengths.
func TestDFALenAltAnchorSkipPartialLane(t *testing.T) {
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `\bfoo[0-9]{3}|bar[0-9]{5}`, MatchFunc: "m"}})
}

// TestDFASetsEmptyFallbackStrictPrefix exercises the constant "no match"
// body returned by genSuffixWASM when a set bucket's literal has no
// required suffix chars (i.e. one literal is a strict prefix of another in
// the same bucket) — the test plan T11.
func TestDFASetsEmptyFallbackStrictPrefix(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "p_cat", Pattern: "cat"},
			{Name: "p_catalog", Pattern: "catalog"},
		},
		Sets: []config.SetConfig{
			{Name: "s1", Find: "s1_find", Patterns: config.PatternSelector{All: true}},
		},
	}
	if _, _, err := CompileFile(cfg, ""); err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
}

// TestExpandWithWBIgnoresWordBitsWithoutWordBoundary pins the invariant
// The optimisation this pins rests on: when a program contains no
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

// dfaLayoutCovTable compiles pattern to a leftmost-first dfaTable, the exact
// shape buildDFALayout consumes in production. Kept separate from
// compileTestDFA so this file's cases can be read without cross-referencing
// another file's leftmostFirst argument.
func dfaLayoutCovTable(t *testing.T, pattern string) *dfaTable {
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
	dfa, ok := newDFA(prog, false, true, maxHelperDFAStates)
	if !ok {
		t.Fatalf("newDFA(%q): state limit exceeded", pattern)
	}
	return dfaTableFrom(dfa)
}

// dfaLayoutCovBuild builds a find-mode layout for pattern. params carries the
// knobs under test; its t field is filled in here so cases only have to name
// the flags they actually care about.
func dfaLayoutCovBuild(t *testing.T, pattern string, params dfaLayoutParams) (*dfaTable, *dfaLayout) {
	t.Helper()
	table := dfaLayoutCovTable(t, pattern)
	params.t = table
	return table, buildDFALayout(params)
}

// dfaLayoutCovFindParams mirrors appendFindCodeEntry's find-mode defaults:
// needFind and leftmostFirst on, no compiled-DFA promotion (which would route
// emission to the hybrid dispatch bodies instead of buildFindBody).
func dfaLayoutCovFindParams() dfaLayoutParams {
	return dfaLayoutParams{needFind: true, leftmostFirst: true, compiledDFAThreshold: 0}
}

// TestDFALayoutTeddyTiers pins how deep the Teddy prefilter is built for
// shapes the rest of the corpus does not produce: word-boundary patterns
// (where the filter must union the prev-is-word and prev-is-non-word
// continuations) and patterns whose continuation set is
// too wide for a 64-bit filter lane.
//
// A regression here is silent: an over-narrow filter drops real matches, an
// over-deep tier is unsound the moment a match can end inside the tier.
func TestDFALayoutTeddyTiers(t *testing.T) {
	cases := []struct {
		pattern                string
		wantT1, wantT2, wantT3 bool
		why                    string
	}{
		// Both start contexts stay alive through four bytes: `\b` fires from
		// midStart (prev non-word) and `\B` from midStartWord (prev word), so
		// every tier has to walk the midStartWordState chain alongside the
		// midStartState one.
		{`(?:\b|\B)(?:abcde|xyzwv)`, true, true, true, "word-context union at all three tiers"},
		// From the word context `\Bx` completes the match on the first byte
		// while the non-word context still needs a 'y', so no second-byte
		// requirement is sound at all and even T1 has to give up.
		{`\Bx|xy|wv`, false, false, false, "word context accepts at depth 1"},
		// One byte deeper: 'a' is dead in the non-word context but completes
		// `\Bxa` in the word one, and 'a' is reached before the non-word
		// context's own accept on 'y', so T2 is the tier that gives up. The
		// third branch is three bytes long so it does not itself accept at
		// depth 2 and shortcut the case.
		{`\Bxa|x+y|wvu`, true, false, false, "word context accepts at depth 2"},
		// Same again at depth 3: only `\Bxyz` finishes there, and only in the
		// word context, so T1 and T2 are sound and T3 is not.
		{`\Bxyz|xyab|wvuts`, true, true, false, "word context accepts at depth 3"},
		// 82 possible second bytes blows the 64-bit filter lane at T1.
		{`(?:q|w)[\x20-\x71]`, false, false, false, "second-byte set wider than 64"},
		{`(?:qa|wb)[\x20-\x71]`, true, false, false, "third-byte set wider than 64"},
		{`(?:qax|wby)[\x20-\x71]`, true, true, false, "fourth-byte set wider than 64"},
		{`(?:qaxm|wbyn)[\x20-\x71]`, true, true, true, "fifth byte is where it gets wide"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if len(layout.prefix) != 0 {
				t.Fatalf("%q: prefix %q is non-empty, so the Teddy tiers are never built — case is not testing what it claims",
					tc.pattern, layout.prefix)
			}
			gotT1 := len(layout.teddyT1LoBytes) > 0
			gotT2 := len(layout.teddyT2LoBytes) > 0
			gotT3 := len(layout.teddyT3LoBytes) > 0
			if gotT1 != tc.wantT1 || gotT2 != tc.wantT2 || gotT3 != tc.wantT3 {
				t.Errorf("%q: T1/T2/T3 = %v/%v/%v, want %v/%v/%v",
					tc.pattern, gotT1, gotT2, gotT3, tc.wantT1, tc.wantT2, tc.wantT3)
			}
		})
	}
}

// TestDFALayoutFirstByteFlagsWordContext covers the fast-skip first-byte set
// for a pattern that can match zero-width under a word-boundary context.
//
// This test asserted the DEFECT until 2026-09-09. It required that ' ' NOT be
// a candidate first byte for `\b|x+y`, reasoning that "\b cannot fire before it
// from a non-word context". True, and beside the point: firstByteFlags is ONE
// table consulted at every position, so it has to be the union over every
// start context, and from the prev=WORD context `\b` fires before a space
// exactly as it fires before 'a' from the prev=non-word one.
//
// Encoding the narrower claim is what let the emitter ship with the union over
// midStartWordState missing entirely, so `\b` over "a b" skipped the boundary
// at position 1 and reported only 0, 2 and 3.
//
// For a wholly empty-width boundary pattern the honest answer is that EVERY
// byte is a candidate — before a word byte from a non-word context, before a
// non-word byte from a word context — so the prefilter cannot narrow anything
// and must not pretend to. The narrowing case is a pattern that consumes a
// byte, which is what the second half below pins.
func TestDFALayoutFirstByteFlagsWordContext(t *testing.T) {
	table, layout := dfaLayoutCovBuild(t, `\b|x+y`, dfaLayoutCovFindParams())
	if !table.hasWordBoundary {
		t.Fatal(`\b|x+y: expected hasWordBoundary`)
	}
	// Both directions of the boundary, which is the whole point.
	if layout.firstByteFlags['a'] == 0 {
		t.Error(`\b|x+y: word byte 'a' must be a candidate — \b fires before it when the previous byte is not a word char`)
	}
	if layout.firstByteFlags[' '] == 0 {
		t.Error(`\b|x+y: non-word byte ' ' must be a candidate — \b fires before it when the previous byte IS a word char, which is the union that was missing`)
	}
	if layout.firstByteFlags[0xE9] == 0 {
		t.Error(`\b|x+y: high byte 0xE9 must be a candidate — it is not a word char, so \b fires before it after one`)
	}

	// A pattern that must CONSUME a byte still narrows: the candidates come
	// from the transitions out of the start states, not from an empty-width
	// accept, so the union above must not widen this to everything.
	// A class start, so there is no literal prefix and the firstByteFlags
	// path is the one actually exercised.
	_, narrow := dfaLayoutCovBuild(t, `\b[xy]+`, dfaLayoutCovFindParams())
	if len(narrow.prefix) != 0 {
		t.Fatalf(`\b[xy]+: prefix %q is non-empty, so firstByteFlags is never built — case is not testing what it claims`, narrow.prefix)
	}
	if narrow.firstByteFlags['x'] == 0 || narrow.firstByteFlags['y'] == 0 {
		t.Error(`\b[xy]+: 'x' and 'y' must be candidate first bytes`)
	}
	if narrow.firstByteFlags[' '] != 0 {
		t.Error(`\b[xy]+: ' ' must NOT be a candidate — no match can begin at a space`)
	}
	if len(narrow.firstBytes) == 256 {
		t.Error(`\b[xy]+: all 256 bytes flagged; a byte-consuming pattern must still narrow the scan`)
	}
}

// TestDFALayoutRowDedup covers u16 transition-row deduplication. Two distinct
// all-dead terminal states (one EOF-only accepting, one accepting anywhere)
// keep minimization from merging them while their 512-byte rows are
// identical, which is what pushes uniqueRows below the 255-entry rowMap cap.
//
// Everything downstream of the layout reads transitions through a rowMap
// indirection once this is on, so the detectors are re-run here as well.
func TestDFALayoutRowDedup(t *testing.T) {
	// 1 start + 127 x-chain + 128 y-chain = 256 DFA states = 257 WASM states,
	// one over the u8 limit. `$` makes the x terminal EOF-accept-only.
	const pattern = `x{127}$|y{128}`
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
	if layout.useU8 {
		t.Fatalf("%s: expected a u16 table (got %d WASM states) — row dedup is u16-only", pattern, layout.numWASM)
	}
	if !layout.useRowDedup {
		t.Fatalf("%s: expected row dedup (numWASM=%d)", pattern, layout.numWASM)
	}
	if layout.numUniqueRows >= layout.numWASM || layout.numUniqueRows > 255 {
		t.Errorf("%s: uniqueRows=%d, want < numWASM=%d and <= 255", pattern, layout.numUniqueRows, layout.numWASM)
	}
	if len(layout.rowMapBytes) != layout.numWASM {
		t.Errorf("%s: rowMap has %d entries, want one per WASM state (%d)", pattern, len(layout.rowMapBytes), layout.numWASM)
	}
	if len(layout.tableBytes) != layout.numUniqueRows*512 {
		t.Errorf("%s: table is %d bytes, want %d (uniqueRows * 512)", pattern, len(layout.tableBytes), layout.numUniqueRows*512)
	}

	// The rowMap must be an emitted segment in both find and match layouts,
	// otherwise the runtime indirection reads uninitialised memory.
	for _, needFind := range []bool{true, false} {
		segments := dfaDataSegments(layout, needFind, false)
		if len(segments) == 0 {
			t.Fatalf("%s: dfaDataSegments(needFind=%v) produced nothing", pattern, needFind)
		}
		raw, count := stripSegCount(segments)
		if count == 0 || len(raw) == 0 {
			t.Errorf("%s: dfaDataSegments(needFind=%v) declared %d segments over %d bytes", pattern, needFind, count, len(raw))
		}
	}

	// A deduped table plus an accelerable self-loop state: the Shufti detector
	// reads the same transition rows and must go through the rowMap too, or it
	// records a self-loop set belonging to some other state entirely. The third
	// alternative supplies both the extra all-dead terminal that keeps
	// uniqueRows under the cap and the 16-byte hex run to accelerate.
	const shuftiPattern = `x{100}$|y{153}|[0-9a-f]{2,}q`
	shuftiParams := dfaLayoutCovFindParams()
	shuftiParams.lmBareShufti = true
	shuftiParams.lmNonMidShufti = true
	_, shuftiLayout := dfaLayoutCovBuild(t, shuftiPattern, shuftiParams)
	if !shuftiLayout.useRowDedup {
		t.Fatalf("%s: expected row dedup (numWASM=%d)", shuftiPattern, shuftiLayout.numWASM)
	}
	found := false
	for _, info := range shuftiLayout.dominantStates {
		if len(info.selfLoopSet) > 0 {
			found = true
			if int(info.state) >= shuftiLayout.numWASM {
				t.Errorf("%s: Shufti state %d outside [0,%d)", shuftiPattern, info.state, shuftiLayout.numWASM)
			}
		}
	}
	if !found {
		t.Errorf("%s: no Shufti self-loop state detected in a row-deduped table", shuftiPattern)
	}
}

// TestDFALayoutSkipSafeOnDead covers the dead-state skip-safety analysis,
// including condition (f) — the alternative entry states an intermediate
// attempt can begin in when the previous byte was a word char or a newline
// . Wrongly returning true here makes the
// find loop jump over real matches.
func TestDFALayoutSkipSafeOnDead(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
		why     string
	}{
		// midStartWord has an empty accept class (`\b` wants a non-word byte,
		// `[a-z]+` wants a letter), so an attempt entering there dies on its
		// first byte having recorded nothing — condition (f) case 1.
		{`\b[a-z]+\b`, true, "alternative entry state cannot consume anything"},
		// succ's off-class exit on '\n' reaches a state that is neither dead
		// nor mid-accepting — it EOF-accepts later, at a position the original
		// attempt's trajectory never visited. Condition (e) has to reject it.
		{`[a-z]+\n$`, false, "successor leaves the trajectory into a later-accepting state"},
		// From midStartWord `\B` resolves before the word char 'z' and the
		// attempt consumes it into Match: an off-class byte reaching a live
		// state, which case 2 must reject.
		{`\Bz|x+y`, false, "off-class byte leaves the stable trajectory"},
		// Same idea one byte deeper: from midStartWord the class byte 'x'
		// leads to a state that is not midStart's single successor.
		{`\Bxz|x+y`, false, "class byte reaches a different successor"},
		// midStartNewline records a zero-width `(?m:^)` match that the skip
		// would jump straight over.
		{`(?m:^)|x+y`, false, "alternative entry state is mid-accepting"},
		// Condition (d)'s per-channel checks on midStart itself: each of these
		// records a zero-width match through one context channel only.
		{`\B|11*0`, false, "midStart mid-accepts through the non-word channel"},
		{`\b|x+y`, false, "midStart mid-accepts through the word channel"},
		{`(?m:$)|x+y`, false, "midStart mid-accepts through the newline channel"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if layout.skipSafeOnDead != tc.want {
				t.Errorf("%q: skipSafeOnDead = %v, want %v (%s)", tc.pattern, layout.skipSafeOnDead, tc.want, tc.why)
			}
		})
	}
}

// TestDFALayoutDominantSelfLoopNewlineExit covers the '\n' carve-out
// carve-out: a state that records matches only through the newline
// channel looks non-mid-accepting, so the bulk skip would stride over every
// '\n' without ever running the newline pre-accept check. '\n' therefore has
// to leave the self-loop set — and when there is no room left in the 8-byte
// Shufti exit set, the state must not be accelerated at all.
func TestDFALayoutDominantSelfLoopNewlineExit(t *testing.T) {
	cases := []struct {
		pattern       string
		wantDominant  bool
		wantExitBytes string
		why           string
	}{
		{`a[^b]*(?m:$)`, true, "\nb", "one exit byte plus the carved '\\n' fits the 8-byte cap"},
		{`a[^bcdefghi]*(?m:$)`, false, "", "8 exit bytes already — no room to carve '\\n' out"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			var got []dominantInfo
			for _, info := range layout.dominantStates {
				if len(info.exitBytes) > 0 {
					got = append(got, info)
				}
			}
			if !tc.wantDominant {
				if len(got) != 0 {
					t.Errorf("%q: got %d dominant states, want none (%s)", tc.pattern, len(got), tc.why)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%q: got %d dominant states, want exactly 1", tc.pattern, len(got))
			}
			if string(got[0].exitBytes) != tc.wantExitBytes {
				t.Errorf("%q: exit bytes = %q, want %q", tc.pattern, got[0].exitBytes, tc.wantExitBytes)
			}
		})
	}
}

// TestDFALayoutShuftiSelfLoop covers detectShuftiSelfLoop's LikelyMatch-gated
// channels: the non-mid-accept branch (LM-3), the same '\n' carve-out as the
// dominant detector, and the byte-class-compressed table reader.
func TestDFALayoutShuftiSelfLoop(t *testing.T) {
	cases := []struct {
		pattern      string
		wantMid      bool
		wantSelfSize int
		wantCompress bool
		why          string
	}{
		// 10 digits + '\n' self-loop, `(?m:$)` accept: non-mid by the ctx=0
		// read, so '\n' is carved back out and 10 bytes remain.
		{`a[0-9\n]*(?m:$)`, false, 10, false, "non-mid shufti with '\\n' carved out"},
		// Trailing 'b' keeps the digit-run state non-accepting; no boundary
		// channel fires, so the whole 10-byte set survives.
		{`a[0-9]+b`, false, 10, false, "non-mid shufti, no boundary channel"},
		// >128 states forces byte-class compression, so the self-loop set has
		// to be recovered from classMap rather than read byte-for-byte.
		{`a[0-9]{140}[a-z]+`, true, 26, true, "mid-accept shufti over a compressed table"},
		{`[a-z]{140}[0-9a-f]+q`, false, 16, true, "non-mid shufti over a compressed table"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			params := dfaLayoutCovFindParams()
			// LM-4 lifts the "needs a literal anchor" bail and LM-3 enables the
			// non-mid channel; both are LikelyMatch-only in production.
			params.lmBareShufti = true
			params.lmNonMidShufti = true
			_, layout := dfaLayoutCovBuild(t, tc.pattern, params)
			if layout.useCompression != tc.wantCompress {
				t.Fatalf("%q: useCompression = %v, want %v (numWASM=%d)", tc.pattern, layout.useCompression, tc.wantCompress, layout.numWASM)
			}
			var found *dominantInfo
			for idx := range layout.dominantStates {
				if len(layout.dominantStates[idx].selfLoopSet) > 0 {
					found = &layout.dominantStates[idx]
				}
			}
			if found == nil {
				t.Fatalf("%q: no Shufti self-loop state detected", tc.pattern)
			}
			if found.isMidAccept != tc.wantMid {
				t.Errorf("%q: isMidAccept = %v, want %v", tc.pattern, found.isMidAccept, tc.wantMid)
			}
			if len(found.selfLoopSet) != tc.wantSelfSize {
				t.Errorf("%q: self-loop set has %d bytes, want %d", tc.pattern, len(found.selfLoopSet), tc.wantSelfSize)
			}
			for _, selfByte := range found.selfLoopSet {
				if selfByte == '\n' && !tc.wantMid {
					t.Errorf("%q: '\\n' left in a non-mid self-loop set — the skip would stride past a newline accept", tc.pattern)
				}
			}
		})
	}
}

// TestDFALayoutDataSegmentsAcceptSideTable covers the TDFA-flavoured segment
// emission (useAcceptSideTable) on the find path. The declared segment count
// leads the blob, so a table emitted without being counted — or counted
// without being emitted — corrupts every module that embeds it.
func TestDFALayoutDataSegmentsAcceptSideTable(t *testing.T) {
	// Leftmost-first stops at the first alternative, so `ab` is an immediate
	// accept and the layout carries an immediate-accept side table too — the
	// second thing the TDFA flavour has to count and emit.
	const pattern = `ab|abc`
	params := dfaLayoutCovFindParams()
	_, plain := dfaLayoutCovBuild(t, pattern, params)
	params.useAcceptSideTable = true
	_, sideTable := dfaLayoutCovBuild(t, pattern, params)
	if !sideTable.hasImmAccept {
		t.Fatalf("%q: expected an immediate-accept state — case is not testing what it claims", pattern)
	}

	if len(sideTable.acceptBytes) != sideTable.numWASM {
		t.Fatalf("%q: acceptBytes has %d entries, want one per WASM state (%d)", pattern, len(sideTable.acceptBytes), sideTable.numWASM)
	}
	if len(plain.acceptBytes) != 0 {
		t.Fatalf("%q: DFA layouts must not emit an accept side table (state IDs are partitioned instead)", pattern)
	}

	_, plainCount := stripSegCount(dfaDataSegments(plain, true, false))
	rawSide, sideCount := stripSegCount(dfaDataSegments(sideTable, true, false))
	wantExtra := 1
	if sideTable.hasImmAccept {
		wantExtra = 2 // accept side table + immediate-accept side table
	}
	if int(sideCount) != int(plainCount)+wantExtra {
		t.Errorf("%q: side-table layout declares %d segments, want %d (%d + %d)", pattern, sideCount, int(plainCount)+wantExtra, plainCount, wantExtra)
	}
	if len(rawSide) == 0 {
		t.Errorf("%q: side-table layout emitted no segment bytes", pattern)
	}
}

// TestDFALayoutDataSegmentsCompressedTeddy covers segment emission for a
// byte-class-compressed find layout that also carries all three Teddy tiers —
// the deepest nesting in dfaDataSegments, and the one whose segment count is
// assembled from the most independent pieces.
func TestDFALayoutDataSegmentsCompressedTeddy(t *testing.T) {
	// 143 WASM states pushes the u8 table past 32 KB (compression on); the
	// leading class means there is no mandatory literal prefix, so the Teddy
	// tables are built and emitted.
	const pattern = `[ab][0-9]{140}`
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
	if !layout.useCompression {
		t.Fatalf("%q: expected byte-class compression (numWASM=%d)", pattern, layout.numWASM)
	}
	if len(layout.prefix) != 0 {
		t.Fatalf("%q: expected no literal prefix, got %q — the Teddy segments are only emitted on the prefix-less path", pattern, layout.prefix)
	}
	if len(layout.teddyT3LoBytes) == 0 {
		t.Fatalf("%q: expected all four Teddy tiers", pattern)
	}
	raw, count := stripSegCount(dfaDataSegments(layout, true, false))
	// classMap + table + midAccept + firstByte + 8 Teddy tables.
	if count < 12 {
		t.Errorf("%q: declared %d segments, want at least 12 (classMap+table+midAccept+firstByte+8 Teddy)", pattern, count)
	}
	if len(raw) == 0 {
		t.Errorf("%q: no segment bytes emitted", pattern)
	}

	// The same compressed find layout WITH a literal prefix takes the other
	// arm: the prefix scan replaces the first-byte and Teddy tables entirely,
	// so those segments must be neither counted nor emitted.
	const prefixed = `a[0-9]{140}[a-z]+`
	_, prefixedLayout := dfaLayoutCovBuild(t, prefixed, dfaLayoutCovFindParams())
	if !prefixedLayout.useCompression || len(prefixedLayout.prefix) == 0 {
		t.Fatalf("%q: want compression with a literal prefix, got useCompression=%v prefix=%q",
			prefixed, prefixedLayout.useCompression, prefixedLayout.prefix)
	}
	prefixedRaw, prefixedCount := stripSegCount(dfaDataSegments(prefixedLayout, true, false))
	if prefixedCount >= count {
		t.Errorf("%q: declared %d segments, want fewer than the prefix-less layout's %d", prefixed, prefixedCount, count)
	}
	if len(prefixedRaw) == 0 {
		t.Errorf("%q: no segment bytes emitted", prefixed)
	}
}

// TestDFALayoutSuffixWASMEmptyDFA covers genSuffixWASM's degenerate input.
// A bucket whose suffix DFA came back empty must still produce a callable
// function body that reports "no matches" rather than an empty body the
// module validator would reject.
func TestDFALayoutSuffixWASMEmptyDFA(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table *dfaTable
	}{
		{"nil table", nil},
		{"zero-state table", &dfaTable{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodyArt, data, segCount, nextOff := genSuffixWASM(tc.table, 4096, 0, []int{7}, []int{0}, LikelyNeutral, false, false, nil)
			body := bodyArt.fnBody
			if len(body) == 0 {
				t.Fatal("empty function body")
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("body does not end with the WASM `end` opcode: % x", body)
			}
			if len(data) != 0 || segCount != 0 {
				t.Errorf("empty DFA emitted %d data bytes in %d segments, want none", len(data), segCount)
			}
			if nextOff != 4096 {
				t.Errorf("nextTableOffset = %d, want the unchanged base 4096", nextOff)
			}
		})
	}
}

// TestDFALayoutSuffixWASMWideBucket covers the 32-pattern ceiling in
// buildSetSuffixBody. The per-pattern endPos locals are indexed by bit
// position in a 32-bit mask, so a bucket carrying more patterns than that has
// to stop emitting per-pattern code at bit 32 rather than run off the end of
// the local space.
func TestDFALayoutSuffixWASMWideBucket(t *testing.T) {
	// A word-boundary suffix also exercises the wbNW/wbW bitmask tables, which
	// only genSuffixWASM emits.
	table := dfaLayoutCovTable(t, `\b[a-z]+\b`)
	const wide = 40
	patternIDs := make([]int, wide)
	prefixFixedLens := make([]int, wide)
	for idx := range patternIDs {
		patternIDs[idx] = 100 + idx
	}
	bodyArt, data, segCount, nextOff := genSuffixWASM(table, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false, nil)
	body := bodyArt.fnBody
	if len(body) == 0 {
		t.Fatal("empty function body for a 40-pattern bucket")
	}
	if segCount < 5 {
		t.Errorf("segCount = %d, want at least 5 (layout + mid/eof/imm bitmasks + word-boundary bitmasks)", segCount)
	}
	if len(data) == 0 || nextOff <= 0 {
		t.Errorf("data=%d bytes nextTableOffset=%d, want a non-empty table region", len(data), nextOff)
	}

	// The same bucket at exactly 32 patterns must emit strictly less code:
	// bits 32..39 contribute nothing, so the two bodies cannot be equal in
	// size unless the ceiling silently dropped earlier bits too.
	narrowBodyArt, _, _, _ := genSuffixWASM(table, 0, 0, patternIDs[:32], prefixFixedLens[:32], LikelyNeutral, false, false, nil)
	narrowBody := narrowBodyArt.fnBody
	if len(narrowBody) != len(body) {
		t.Errorf("32-pattern body is %d bytes and 40-pattern body is %d; patterns past bit 32 must contribute no code", len(narrowBody), len(body))
	}

	// The same ceiling applies inside the dominant-state bulk skip, which only
	// a suffix carrying a mid-accepting dominant state emits: `[^b]*` accepts
	// at every position and self-loops on all but one byte.
	dominantTable := dfaLayoutCovTable(t, `a[^b]*`)
	_, dominantLayout := dfaLayoutCovBuild(t, `a[^b]*`, dfaLayoutParams{leftmostFirst: true})
	midDominant := false
	for _, info := range dominantLayout.dominantStates {
		if info.isMidAccept && len(info.exitBytes) > 0 {
			midDominant = true
		}
	}
	if !midDominant {
		t.Fatalf(`a[^b]*: expected a mid-accepting dominant state — case is not testing what it claims`)
	}
	if dominantBodyArt, _, _, _ := genSuffixWASM(dominantTable, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false, nil); len(dominantBodyArt.fnBody) == 0 {
		t.Error(`a[^b]*: empty function body for a 40-pattern bucket`)
	}

	// A suffix DFA over 256 states switches the transition emitter to the u16
	// table shape, which is a different instruction sequence entirely.
	wideTable := dfaLayoutCovTable(t, `x{127}$|y{128}`)
	_, wideLayout := dfaLayoutCovBuild(t, `x{127}$|y{128}`, dfaLayoutParams{leftmostFirst: true})
	if wideLayout.useU8 {
		t.Fatalf(`x{127}$|y{128}: expected a u16 suffix table (numWASM=%d)`, wideLayout.numWASM)
	}
	if wideBodyArt, _, _, _ := genSuffixWASM(wideTable, 0, 0, []int{1, 2}, []int{0, 0}, LikelyNeutral, false, false, nil); len(wideBodyArt.fnBody) == 0 {
		t.Error(`x{127}$|y{128}: empty function body for a u16 suffix table`)
	}
}

// TestDFALayoutSuffixWASMCompressed covers buildSetSuffixBody's compressed-u8
// transition emitter, which only a bucket suffix of more than 128 states
// reaches.
func TestDFALayoutSuffixWASMCompressed(t *testing.T) {
	// The trailing `+` keeps this off isCountedClassChain's SIMD shortcut,
	// which would return before a transition table is ever emitted.
	const pattern = `[a-z]{140}[0-9]+x`
	table := dfaLayoutCovTable(t, pattern)
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutParams{leftmostFirst: true})
	if !layout.useCompression {
		t.Fatalf("%q: expected byte-class compression (numWASM=%d)", pattern, layout.numWASM)
	}
	// 40 patterns also drives the 32-bit ceiling on this path.
	const wide = 40
	patternIDs := make([]int, wide)
	prefixFixedLens := make([]int, wide)
	for idx := range patternIDs {
		patternIDs[idx] = 200 + idx
	}
	bodyArt, _, _, _ := genSuffixWASM(table, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false, nil)
	body := bodyArt.fnBody
	if len(body) == 0 {
		t.Fatal("empty function body")
	}
	singleArt, _, _, _ := genSuffixWASM(table, 0, 0, []int{3}, []int{0}, LikelyNeutral, false, false, nil)
	single := singleArt.fnBody
	if len(single) == 0 {
		t.Fatal("empty function body for a single-pattern bucket")
	}
	if len(single) >= len(body) {
		t.Errorf("single-pattern body is %d bytes and 40-pattern body is %d; the wider bucket must emit more per-pattern code", len(single), len(body))
	}
}

// TestDFALayoutFindBodyStartContexts covers buildFindBody's per-attempt entry
// selection. Which state an attempt starts in depends on the byte before it,
// and each divergence (begin-of-text vs mid-string, prev-is-word,
// prev-is-newline) gets its own emitted branch. Two past bugs were missing
// branches here, and both silently lost matches.
func TestDFALayoutFindBodyStartContexts(t *testing.T) {
	cases := []struct {
		pattern string
		why     string
	}{
		// No literal prefix, and the anchored branch gives state 0 transitions
		// midStart does not have → attempt_start == 0 needs its own entry.
		{`^ab|xab`, "begin-of-text entry differs from mid-string"},
		// Same divergence reached through the mandatory-literal path (the
		// literal is not at the match start, so there is no prefix to scan).
		{`(?:^|z)[a-z]+@example\.com`, "mandatory-literal path with a begin-of-text entry"},
		// (?m:^) adds a third entry state selected by "previous byte was \n".
		{`(?m:^)ab|xab`, "newline entry state"},
		// \b and (?m:^) together: word and newline entries plus begin-of-text.
		{`(?m:^)\bab|xab`, "word and newline entry states"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody, not buildFindBody — case is not testing what it claims", tc.pattern)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(tc.pattern, false), 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("%q: find body does not end with the WASM `end` opcode", tc.pattern)
			}
		})
	}
}

// TestDFALayoutFindBodyPrefixWalkDivergence covers the prefix-scan shortcut's
// four-way choice of where the DFA stands after the literal prefix. The walk
// is context-dependent: `(?m:^)` and `\b` in front of the prefix can leave the
// automaton in a different state depending on the byte before the attempt, and
// attempt_start == 0 is different again.
func TestDFALayoutFindBodyPrefixWalkDivergence(t *testing.T) {
	cases := []struct {
		pattern string
		why     string
	}{
		// Every match starts with "abc", so "abc" is the scanned prefix. The
		// anchored branch is only live at position 0, so the walk from the
		// begin-of-text state ends somewhere the mid-string walk does not.
		{`^abc|abcd`, "begin-of-text walk diverges"},
		// Same, with the anchored branch also live after a '\n'.
		{`(?m:^)abc|abcd`, "newline walk diverges"},
		// `\b` and `(?m:^)` gate different branches, so all four walks — mid,
		// prev-is-word, prev-is-newline and begin-of-text — end differently.
		{`(?:\babcz|(?m:^)abce)|abcd`, "word and newline walks diverge"},
		// The prev-is-word walk dies on the prefix's first byte: `\b` cannot
		// fire between a word char and 'f'. The walk has to stop at the dead
		// state rather than keep indexing transitions from it.
		{`\bfoobar`, "prev-is-word walk dies inside the prefix"},
		// The begin-of-text walk dies instead: at position 0 the higher-priority
		// `^f` branch completes on the first prefix byte, so leftmost-first
		// drops the `foobar` thread and the second byte has nowhere to go.
		{`^f|foobar`, "begin-of-text walk dies inside the prefix"},
		// Same shape through the prev-is-newline entry.
		{`(?m:^)f|foobar`, "prev-is-newline walk dies inside the prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody — case is not testing what it claims", tc.pattern)
			}
			if len(layout.prefix) == 0 {
				t.Fatalf("%q: no literal prefix, so the prefix-walk shortcut is never emitted", tc.pattern)
			}
			diverges := layout.wasmPrefixEndStart != layout.wasmPrefixEnd ||
				layout.wasmPrefixEndWord != layout.wasmPrefixEnd ||
				layout.wasmPrefixEndNewline != layout.wasmPrefixEnd
			if !diverges {
				t.Fatalf("%q: all four prefix-end states agree (%d) — nothing diverges to emit",
					tc.pattern, layout.wasmPrefixEnd)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(tc.pattern, false), 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
		})
	}
}

// TestDFALayoutFindBodyU16NonMidDominant covers the u16 scan loop's accept
// test when the pattern carries a non-mid-accept dominant state. Those states
// occupy the reserved 254/255 values in midAccept's shared value space (task
// 38 v2), so a plain `!= 0` read would treat them as accepting; the emitted
// check has to be the `(val-1) u< 253` range compare instead.
func TestDFALayoutFindBodyU16NonMidDominant(t *testing.T) {
	// 300+ states forces the u16 path; the 62-byte `[0-9a-zA-Z ]+` run is a
	// self-loop that is not itself an accept state (the closing quote is still
	// required), which is what makes it a NON-mid dominant.
	const pattern = `x{300}[0-9a-zA-Z ]+"`
	params := dfaLayoutCovFindParams()
	params.lmNonMidShufti = true // LM-3: the non-mid channel is LikelyMatch-gated
	table, layout := dfaLayoutCovBuild(t, pattern, params)
	if layout.useU8 {
		t.Fatalf("%q: expected a u16 table (numWASM=%d)", pattern, layout.numWASM)
	}
	nonMid := 0
	for _, info := range layout.dominantStates {
		if !info.isMidAccept {
			nonMid++
		}
	}
	if nonMid == 0 {
		t.Fatalf("%q: expected at least one non-mid dominant state", pattern)
	}
	body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(pattern, false), 0)
	if len(body) == 0 {
		t.Fatalf("%q: empty find body", pattern)
	}
}

// TestDFALayoutFindBodyMandatoryLit covers the mandatory-literal find path —
// the one taken when the pattern's guaranteed literal is NOT at the match
// start, so there is no prefix to scan and the DFA restarts from the literal's
// possible match origins instead.
func TestDFALayoutFindBodyMandatoryLit(t *testing.T) {
	cases := []struct {
		pattern      string
		wantCompress bool
		why          string
	}{
		// The anchored branch gives the begin-of-text state transitions
		// midStart lacks, so the per-attempt prologue needs both entries.
		{`(?:^x|y)[a-z]{0,20}@example\.com`, false, "begin-of-text entry on the mandatory-literal path"},
		// 154 states push the u8 table past 32 KB, so the same path has to be
		// emitted with byte-class-compressed transitions and its own local
		// layout (the SIMD literal scan needs four extra locals).
		{`[a-z]{140}@example\.com`, true, "compressed transitions on the mandatory-literal path"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody — case is not testing what it claims", tc.pattern)
			}
			if len(layout.prefix) != 0 {
				t.Fatalf("%q: literal prefix %q present, so the mandatory-literal path is not taken", tc.pattern, layout.prefix)
			}
			lit := findMandatoryLit(tc.pattern, false)
			if lit == nil || len(lit.bytes) == 0 {
				t.Fatalf("%q: no mandatory literal found — case is not testing what it claims", tc.pattern)
			}
			if layout.useCompression != tc.wantCompress {
				t.Fatalf("%q: useCompression = %v, want %v (numWASM=%d)", tc.pattern, layout.useCompression, tc.wantCompress, layout.numWASM)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, lit, 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("%q: find body does not end with the WASM `end` opcode", tc.pattern)
			}
		})
	}
}

// dfaLayoutCovSynthLayout hand-builds a u8 layout: numWASM WASM states where
// every state self-loops on byte values below selfWidth and dies on the rest.
//
// The detectors carry guards no compiled pattern can reach — a state id past
// the end of midAcceptBytes, an entry state past numWASM, more accelerable
// states than the encoding has room for. A table built to order is the only
// way to exercise them, and leaving them uncovered is worse: they are the
// checks that keep a malformed layout from indexing out of bounds.
func dfaLayoutCovSynthLayout(numWASM, selfWidth int) *dfaLayout {
	layout := &dfaLayout{
		numWASM:             numWASM,
		useU8:               true,
		tableBytes:          make([]byte, numWASM*256),
		midAcceptBytes:      make([]byte, numWASM),
		wasmStart:           1,
		wasmMidStart:        1,
		wasmMidStartWord:    1,
		wasmMidStartNewline: 1,
	}
	for state := 1; state < numWASM; state++ {
		for byteValue := 0; byteValue < selfWidth; byteValue++ {
			layout.tableBytes[state*256+byteValue] = byte(state)
		}
	}
	return layout
}

// TestDFALayoutDetectorGuards covers the detectors' defensive bail-outs and
// their encoding-space ceilings.
func TestDFALayoutDetectorGuards(t *testing.T) {
	t.Run("single state", func(t *testing.T) {
		// numWASM == 1 means nothing but the dead state: every detector must
		// bail before it indexes a row that does not exist.
		layout := dfaLayoutCovSynthLayout(1, 250)
		layout.lmBareShufti = true
		detectDominantSelfLoop(layout)
		detectShuftiSelfLoop(layout)
		detectSkipSafeOnDead(layout)
		if len(layout.dominantStates) != 0 || layout.skipSafeOnDead {
			t.Errorf("single-state layout: dominantStates=%d skipSafeOnDead=%v, want 0/false",
				len(layout.dominantStates), layout.skipSafeOnDead)
		}
	})

	t.Run("mid-start state out of range", func(t *testing.T) {
		layout := dfaLayoutCovSynthLayout(4, 10)
		layout.wasmMidStart = 99
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set from an unanalysable mid-start state")
		}
	})

	t.Run("successor out of range", func(t *testing.T) {
		// midStart accepts bytes 0..9 but they all lead to a state id past the
		// end of the table — nothing about that trajectory can be proven.
		layout := dfaLayoutCovSynthLayout(3, 0)
		for byteValue := 0; byteValue < 10; byteValue++ {
			layout.tableBytes[1*256+byteValue] = 5
		}
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set from an out-of-range successor")
		}
	})

	t.Run("entry state out of range", func(t *testing.T) {
		// midStart → succ → succ is a textbook stable trajectory, so
		// conditions (a)-(e) all pass; only the unanalysable begin-of-text
		// entry state stops it.
		layout := dfaLayoutCovSynthLayout(3, 0)
		for byteValue := 0; byteValue < 10; byteValue++ {
			layout.tableBytes[1*256+byteValue] = 2 // midStart -> succ
			layout.tableBytes[2*256+byteValue] = 2 // succ self-loop
		}
		layout.wasmStart = 99
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set despite an out-of-range entry state")
		}
	})

	t.Run("state past the mid-accept table", func(t *testing.T) {
		layout := dfaLayoutCovSynthLayout(3, 250)
		layout.midAcceptBytes = make([]byte, 1) // shorter than numWASM
		detectDominantSelfLoop(layout)
		if len(layout.dominantStates) != 0 {
			t.Errorf("recorded %d dominant states whose mid-accept status is unknown", len(layout.dominantStates))
		}
	})

	t.Run("dominant encoding space exhausted", func(t *testing.T) {
		// 250-byte self-loops with 6 exits make every state dominant. The
		// shared midAccept value space has room for 126 mid-accept dominants
		// and 2 non-mid ones; the rest must be dropped, not encoded on top of
		// the Shufti or plain-accept ranges.
		const numWASM = 200
		const firstNonMid = 151
		layout := dfaLayoutCovSynthLayout(numWASM, 250)
		for state := 1; state < firstNonMid; state++ {
			layout.midAcceptBytes[state] = 1
		}
		detectDominantSelfLoop(layout)
		mid, nonMid := 0, 0
		for _, info := range layout.dominantStates {
			if info.isMidAccept {
				mid++
				if info.encodedByte < 2 || info.encodedByte > 127 {
					t.Errorf("mid dominant state %d encoded as %d, outside the 2..127 range", info.state, info.encodedByte)
				}
			} else {
				nonMid++
				if info.encodedByte < 254 {
					t.Errorf("non-mid dominant state %d encoded as %d, outside the 254..255 range", info.state, info.encodedByte)
				}
			}
		}
		if mid != 126 {
			t.Errorf("kept %d mid-accept dominants, want the 126 the encoding has room for", mid)
		}
		if nonMid != 2 {
			t.Errorf("kept %d non-mid dominants, want the 2 the encoding has room for", nonMid)
		}
	})

	t.Run("shufti encoding space exhausted", func(t *testing.T) {
		// 30-byte self-loops are too narrow for the dominant detector (and
		// their 226 exit bytes blow its 8-byte Shufti cap), so every state
		// falls to detectShuftiSelfLoop, which has room for 126.
		const numWASM = 200
		layout := dfaLayoutCovSynthLayout(numWASM, 30)
		layout.lmBareShufti = true // no literal anchor in a hand-built layout
		for state := 1; state < numWASM; state++ {
			layout.midAcceptBytes[state] = 1
		}
		detectDominantSelfLoop(layout)
		detectShuftiSelfLoop(layout)
		if len(layout.dominantStates) != 126 {
			t.Errorf("kept %d Shufti states, want the 126 the 128..253 encoding range has room for", len(layout.dominantStates))
		}
		for _, info := range layout.dominantStates {
			if info.encodedByte < 128 || info.encodedByte > 253 {
				t.Errorf("Shufti state %d encoded as %d, outside the 128..253 range", info.state, info.encodedByte)
			}
		}
	})
}

// TestDFALayoutDataSegmentsRowDedupWithCompression covers dfaDataSegments'
// handling of a layout carrying BOTH byte-class compression and row dedup.
// buildDFALayout never produces one — compression is u8-only and dedup is
// u16-only — but the serializer accepts the combination, and its segment
// COUNT and its segment BODIES are computed in two separate places. A layout
// that counts the rowMap without emitting it (or the reverse) desynchronises
// every data segment after it in the module.
func TestDFALayoutDataSegmentsRowDedupWithCompression(t *testing.T) {
	build := func() *dfaLayout {
		layout := dfaLayoutCovSynthLayout(4, 250)
		layout.useCompression = true
		layout.numClasses = 4
		layout.tableBytes = make([]byte, 4*4)
		layout.classMapOff = 0
		layout.tableOff = 256
		layout.midAcceptOff = 512
		return layout
	}
	for _, needFind := range []bool{true, false} {
		plain := build()
		deduped := build()
		deduped.useRowDedup = true
		deduped.rowMapOff = 1024
		deduped.rowMapBytes = make([]byte, deduped.numWASM)

		_, plainCount := stripSegCount(dfaDataSegments(plain, needFind, true))
		dedupedRaw, dedupedCount := stripSegCount(dfaDataSegments(deduped, needFind, true))
		if int(dedupedCount) != int(plainCount)+1 {
			t.Errorf("needFind=%v: row-dedup layout declares %d segments, want %d (one more than %d)",
				needFind, dedupedCount, plainCount+1, plainCount)
		}
		if len(dedupedRaw) == 0 {
			t.Errorf("needFind=%v: no segment bytes emitted", needFind)
		}
	}
}

// TestDFALayoutAnchorContextTables walks a battery of zero-width and
// anchor-heavy patterns through DFA construction and layout. These are the
// shapes where the four start contexts (begin-of-text, mid-string,
// prev-is-word, prev-is-newline) genuinely differ, and where the accept
// bitmask can come back empty for a state the leftmost-first pass still
// considers an immediate accept.
//
// The assertions are structural on purpose: a start-context state id or a
// transition target outside the table is a memory-safety bug in every emitted
// body that indexes with it, and it is silent until the WASM traps.
func TestDFALayoutAnchorContextTables(t *testing.T) {
	patterns := []string{
		`^`, `$`, `(?m:^)`, `(?m:$)`, `\b`, `\B`,
		`a*?`, `^x|a*?`, `\Ax|a*?`, `(?m:^)x|a*?`,
		`\b|a*?`, `\B|a*?`, `(?m:$)|a*?`,
		`^ab|xab`, `(?m:^)ab|xab`, `\bab|xab`,
		`x*^x`, `x*\b`, `x*\B`, `(?m:^)x*`, `\b(?m:^)`, `\B\A`,
		`(?m:^)(?m:$)`, `\b\B|x`, `(?:^|\b)x*`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			table := dfaLayoutCovTable(t, pattern)
			starts := map[string]int{
				"start":           table.startState,
				"midStart":        table.midStartState,
				"midStartWord":    table.midStartWordState,
				"midStartNewline": table.midStartNewlineState,
			}
			for name, state := range starts {
				if state < 0 || state >= table.numStates {
					t.Fatalf("%q: %s state %d outside [0,%d)", pattern, name, state, table.numStates)
				}
			}
			for i, target := range table.transitions {
				if target < -1 || target >= table.numStates {
					t.Fatalf("%q: transition[%d] = %d, outside [-1,%d)", pattern, i, target, table.numStates)
				}
			}
			_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
			if layout.tableEnd <= int64(layout.tableOff) {
				t.Errorf("%q: tableEnd %d is not past tableOff %d", pattern, layout.tableEnd, layout.tableOff)
			}
		})
	}
}

// TestDFALayoutNFAInputMapFolding covers nfaBuildInputMap's two byte-fanout
// cases the rest of the corpus leaves alone: a case-folded single-rune
// instruction, and a `(?s).` wildcard sharing a state with bytes that already
// have private transition lists.
func TestDFALayoutNFAInputMapFolding(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
		why     string
	}{
		{`(?i)k`, "K", "case-folded single rune (K/k/Kelvin sign fold chain)"},
		{`(?i)s+`, "SsS", "case-folded rune class"},
		{`(?s)x.y`, "x\ny", "wildcard with no competing named byte"},
		// After 'a' both the `.*` wildcard and the literal 'b' are live, so 'b'
		// gets a private transition list the wildcard must be added to as well
		// — miss that and `a.*b` loses every match whose wildcard run contains
		// a 'b'.
		{`(?s)a.*b`, "azbzb", "wildcard alongside a private byte transition"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table := dfaLayoutCovTable(t, tc.pattern)
			if table.numStates == 0 {
				t.Fatalf("%q: empty DFA", tc.pattern)
			}
			// Walk the input through the table from the start state; a
			// mis-built input map shows up as a dead transition here.
			state := table.startState
			for pos := 0; pos < len(tc.input); pos++ {
				next := table.transitions[state*256+int(tc.input[pos])]
				if next < 0 {
					t.Fatalf("%q: died on byte %d (%q) of %q", tc.pattern, pos, tc.input[pos], tc.input)
				}
				state = next
			}
			if table.acceptStates[state] == 0 {
				t.Errorf("%q: state after %q is not accepting", tc.pattern, tc.input)
			}
		})
	}
}

// TestSoleMidDominant pins the predicate that lets the mid-accept dispatch drop
// its `local.tee` and its `val == encodedByte` compare.
//
// The property is about the TABLE, not about len(dominantStates): a layout can
// carry exactly one dominant and still hold a 1 for some ordinary accept state,
// and that makes a nonzero load ambiguous again. Getting this wrong emits a
// dispatch that treats every accepting state as the dominant and bulk-skips
// from states whose self-loop set it was never given — a wrong answer, not a
// slow one, which is why the false cases below matter more than the true one.
func TestSoleMidDominant(t *testing.T) {
	layoutWith := func(numWASM int, midAccept map[int32]byte, doms []dominantInfo) *dfaLayout {
		l := &dfaLayout{numWASM: numWASM}
		l.midAcceptBytes = make([]byte, numWASM)
		for st, v := range midAccept {
			l.midAcceptBytes[st] = v
		}
		l.dominantStates = doms
		return l
	}
	mid := func(state int32, enc byte) dominantInfo {
		return dominantInfo{state: state, encodedByte: enc, isMidAccept: true}
	}
	nonMid := func(state int32, enc byte) dominantInfo {
		return dominantInfo{state: state, encodedByte: enc, isMidAccept: false}
	}

	cases := []struct {
		name string
		l    *dfaLayout
		want bool
	}{
		{
			// The alpha-run shape: one dominant, its encoding the only
			// nonzero byte in the table.
			name: "sole mid dominant",
			l:    layoutWith(4, map[int32]byte{2: 128}, []dominantInfo{mid(2, 128)}),
			want: true,
		},
		{
			// One dominant, but state 3 also accepts. A nonzero load can be
			// either, so the compare is load-bearing.
			name: "dominant plus a plain accept state",
			l:    layoutWith(4, map[int32]byte{2: 128, 3: 1}, []dominantInfo{mid(2, 128)}),
			want: false,
		},
		{
			name: "two dominants",
			l: layoutWith(5, map[int32]byte{2: 128, 3: 129},
				[]dominantInfo{mid(2, 128), mid(3, 129)}),
			want: false,
		},
		{
			// A non-mid dominant reaches the dispatch through the 254+
			// sub-range and its own channel; the shortcut must not claim it.
			name: "sole non-mid dominant",
			l:    layoutWith(4, map[int32]byte{2: 254}, []dominantInfo{nonMid(2, 254)}),
			want: false,
		},
		{
			name: "no dominants",
			l:    layoutWith(4, map[int32]byte{2: 1}, nil),
			want: false,
		},
		{
			// applyDominantStateEncoding never ran, so the table does not
			// carry the encoding this predicate is about to promise.
			name: "encoding not applied",
			l:    layoutWith(4, nil, []dominantInfo{mid(2, 128)}),
			want: false,
		},
		{
			// The state index is past the table — the same out-of-range guard
			// applyDominantStateEncoding itself carries.
			name: "dominant state out of range",
			l:    layoutWith(3, map[int32]byte{2: 128}, []dominantInfo{mid(9, 128)}),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := soleMidDominant(tc.l); got != tc.want {
				t.Errorf("soleMidDominant = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSoleMidDominantOnRealPatterns checks the predicate against layouts the
// compiler actually builds, so a change to the detectors or to the encoding
// pass cannot leave the unit table above testing a shape that no longer occurs.
func TestSoleMidDominantOnRealPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		mode    LikelyMode
		want    bool
	}{
		// The alpha-run shape: state 20 is the only accepting state and it is
		// the dominant. This is the case the optimisation exists for.
		{`[a-zA-Z]{20,}`, LikelyMatch, true},
		// Neutral compiles no dominant at all for it.
		{`[a-zA-Z]{20,}`, LikelyNeutral, false},
		// A non-mid dominant: the body needs `>` before it accepts.
		{`<[a-z]+>`, LikelyMatch, false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"/"+tc.mode.String(), func(t *testing.T) {
			table := compileTestDFA(t, tc.pattern, true)
			l := buildDFALayout(dfaLayoutParams{
				t:              table,
				tableBase:      0,
				needFind:       true,
				leftmostFirst:  true,
				lmBareShufti:   tc.mode == LikelyMatch,
				lmNonMidShufti: tc.mode == LikelyMatch,
				lmWideShufti:   tc.mode == LikelyMatch,
			})
			applyDominantStateEncoding(l, true)
			if got := soleMidDominant(l); got != tc.want {
				t.Errorf("soleMidDominant = %v, want %v (dominants=%d)",
					got, tc.want, len(l.dominantStates))
			}
		})
	}
}

// Coverage for the long tail of small guards in engine_dfa.go — the anchor
// emitters, the boundary-priority analyses, the lit-chain alternation family
// and the DFA minimiser's degenerate case. Each is only a handful of
// statements, but they are the branches that decide whether a pattern is
// ROUTED somewhere safe, and a routing decision that silently stops firing is
// the failure mode this package has been bitten by most often.

// TestDFATailMinimizeSingleState covers minimizeDFA's degenerate guard. A
// pattern that matches the empty string everywhere compiles to a single state,
// and the partition refinement below the guard divides by the number of
// distinct accept signatures — so entering it with one state is what the guard
// is there to prevent.
func TestDFATailMinimizeSingleState(t *testing.T) {
	for _, pattern := range []string{``, `(?:)`} {
		matcher, err := compile(pattern, CompileOptions{
			MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
		})
		if err != nil {
			t.Fatalf("compile %q: %v", pattern, err)
		}
		table := dfaTableFrom(matcher.(*dfa))
		if table.numStates > 1 {
			t.Fatalf("%q compiled to %d states; the single-state guard is no longer "+
				"reachable through this pattern and this test measures nothing",
				pattern, table.numStates)
		}
		minimizeDFA(table)
		if table.numStates != 1 {
			t.Errorf("%q: minimizeDFA changed a single-state table to %d states",
				pattern, table.numStates)
		}
	}
}

// TestDFATailBoundaryOutranked covers boundaryOutranksCtx0 via its public
// consumer. `0*\b|0*` is the shape the function's own doc comment names: the
// boundary-gated mid-accept channel resolves to a HIGHER-priority Match than
// the state's own unconditional one, which the find-mode scan loop cannot
// represent — it has no priority concept and would let the later, lower
// priority hit overwrite the correct one. The pattern must therefore be routed
// away from the DFA find path entirely.
func TestDFATailBoundaryOutranked(t *testing.T) {
	const pattern = `0*\b|0*`
	matcher, err := compile(pattern, CompileOptions{
		MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	table := dfaTableFrom(matcher.(*dfa))
	if !dfaHasOutrankedState(table) {
		t.Errorf("%q no longer reports an outranked state, so nothing routes it "+
			"away from the DFA find path; if this is intentional the scan loop "+
			"must first have gained a way to honour Match priority", pattern)
	}
	// It still has to COMPILE — the routing sends it to Backtracking rather
	// than rejecting it.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "outranked_find"}})
}

// TestDFATailAmbiguousBoundaryTarget covers the sibling analysis
// boundaryTargetReachesLaterState / nfaBoundaryTargetIsAmbiguous. Its doc
// comment names ` (\b|0*)0`: resolving the assertion needs one more mandatory
// byte, and that byte's own Rune is ALSO reachable via a lower-priority path
// already live in the same NFA set, so the transition table permanently loses
// the higher-priority derivation with no dominant bit left to catch it.
func TestDFATailAmbiguousBoundaryTarget(t *testing.T) {
	const pattern = ` (\b|0*)0`
	matcher, err := compile(stripCapturesFromPattern(t, pattern), CompileOptions{
		MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	table := dfaTableFrom(matcher.(*dfa))
	if !dfaHasAmbiguousBoundaryTarget(table) {
		t.Errorf("%q no longer reports an ambiguous boundary target; the DFA find "+
			"path would then be used for a shape whose higher-priority derivation "+
			"it cannot represent", pattern)
	}
}

// stripCapturesFromPattern renders the capture-free spelling of a pattern, so
// a shape whose documented example happens to use a group can still be driven
// down the plain-DFA path the analysis under test lives on.
func stripCapturesFromPattern(t *testing.T, pattern string) string {
	t.Helper()
	parsed := parseTestRe(t, pattern)
	stripCaptures(parsed)
	return parsed.String()
}

// TestDFATailAnchorShapes drives the anchor-check emitters. Each row pairs an
// anchor with a literal-plus-counted-class body, which is the shape that
// reaches the specialised chain emitters rather than the generic DFA loop, so
// the anchor check is emitted as its own guard instead of being folded into
// the transition table.
func TestDFATailAnchorShapes(t *testing.T) {
	patterns := []string{
		`\Aabc[a-z]{20}`,
		`abc[a-z]{20}\z`,
		`abc[a-z]{20}$`,
		`(?m:^)abc[a-z]{20}`,
		`abc[a-z]{20}(?m:$)`,
		`\babc[a-z]{20}`,
		`abc[a-z]{20}\b`,
		`\Babc[a-z]{20}`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, MatchFunc: "anchor_match", FindFunc: "anchor_find"},
			})
		})
	}
}

// TestDFATailLitChainAltGroups covers the capture-bearing half of the
// lit-chain alternation family. Without a groups export these shapes take the
// plain match emitter; with one they take a separate body that has to write
// each branch's capture slots, and the two must agree about which branch won.
func TestDFATailLitChainAltGroups(t *testing.T) {
	patterns := []string{
		`(abc[a-z]{20})|(qq[0-9]z)`,
		`(abc[a-z]{20,24})|(qq[0-9]z)`,
		`abc([a-z]{20})|qq([0-9])z`,
		`(abc)([a-z]{20})`,
		`(abc[a-z]{20})`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, GroupsFunc: "chain_groups"},
			})
		})
	}
}

// TestDFATailComputePrefixWordWalk exercises computePrefix's word-context
// bail-outs. A leading \b/\B makes the mandatory first byte itself
// context-dependent, and a single literal fast-skip cannot represent "look for
// X or Y depending on what preceded" — so the prefix must be REFUSED rather
// than derived from the non-word walk alone, which would drop every match
// reached through the other context.
func TestDFATailComputePrefixWordWalk(t *testing.T) {
	cases := []struct {
		pattern    string
		wantPrefix bool
		why        string
	}{
		{`\b[-0]`, false, "midStartState wants '0', midStartWordState wants '-'"},
		{`1*\b$`, false, "midStartWordState is accepting outright, so no byte is mandatory"},
		{`\babc[a-z]{4}`, true, "both contexts force the same bytes, so the fast-skip is sound"},
	}
	for _, testCase := range cases {
		t.Run(testCase.pattern, func(t *testing.T) {
			matcher, err := compile(testCase.pattern, CompileOptions{
				MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
			})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			table := dfaTableFrom(matcher.(*dfa))
			prefix := computePrefix(table)
			if got := len(prefix) > 0; got != testCase.wantPrefix {
				t.Errorf("prefix %q (non-empty=%v), want non-empty=%v — %s",
					prefix, got, testCase.wantPrefix, testCase.why)
			}
		})
	}
}

// TestDFATailUnparseablePatternGuards covers the two helpers that re-parse a
// pattern string and must fail CLOSED. Both are called after the pipeline has
// already validated the pattern, so no config-level input can reach their
// error arm — but "cannot happen today" is exactly the kind of assumption that
// silently stops holding, and the cost of being wrong differs between them:
// shouldTryLitChainAlt must return true (try the general path) while
// lmBareShuftiEligible must return false (decline the optimisation). Getting
// either backwards turns an unparseable pattern into a miscompile rather than
// a clean refusal.
func TestDFATailUnparseablePatternGuards(t *testing.T) {
	const unparseable = `(` // an unclosed group: syntax.Parse rejects it
	if !shouldTryLitChainAlt(unparseable) {
		t.Error("shouldTryLitChainAlt failed OPEN on an unparseable pattern: it must " +
			"fall back to the general path, not claim the alternation shape was ruled out")
	}
	if lmBareShuftiEligible(unparseable, false) {
		t.Error("lmBareShuftiEligible failed OPEN on an unparseable pattern: it must " +
			"decline the bare-Shufti optimisation rather than assert a minimum length " +
			"it could not compute")
	}
}

// TestDFATailShouldTryLitChainAltUnbounded covers the unbounded-repeat refusal.
// The lit-chain alternation analyses all key on a COUNTED tail, so a branch
// carrying an unbounded quantifier has no fixed length to plan chunks against.
func TestDFATailShouldTryLitChainAltUnbounded(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
		why     string
	}{
		{`abc[a-z]{20}|qq[0-9]z`, true, "both branches counted — the shape the analyses want"},
		{`a{2,}|bcd[a-z]{20}`, false, "OpRepeat with no maximum is unbounded"},
		{`a*|bcd[a-z]{20}`, false, "OpStar is unbounded"},
		{`a+|bcd[a-z]{20}`, false, "OpPlus is unbounded"},
	}
	for _, testCase := range cases {
		t.Run(testCase.pattern, func(t *testing.T) {
			if got := shouldTryLitChainAlt(testCase.pattern); got != testCase.want {
				t.Errorf("shouldTryLitChainAlt = %v, want %v — %s",
					got, testCase.want, testCase.why)
			}
		})
	}
}

// TestDFATailLeadingEndTextAnchor covers emitStartAnchorCheck's anchorEndText
// arm. A leading \z is contradictory — the match still has to consume at least
// one byte after it — so the emitter answers with an UNCONDITIONAL fail rather
// than a runtime comparison. The pattern is legal input, so a compiler that
// merely ignored the anchor would report matches that must not exist.
func TestDFATailLeadingEndTextAnchor(t *testing.T) {
	for _, pattern := range []string{`\zabc[a-z]{20}`, `\zabc[a-z]{20,24}`} {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, MatchFunc: "endtext_match"},
			})
		})
	}
}

// TestDFATailEOFSkipSafe drives detectEOFSkipSafe's classification. Its doc
// comment names both sides: a single mandatory chain like `[a-z]{50,}[0-9]`
// qualifies for the end-of-input skip, while a bounded-repeat GROUP such as
// `(?:a{3,4})+$` does not, because its automaton has a non-trivial cycle the
// analysis will not reason about. Declaring the second one safe would skip
// straight to end-of-input past a position where a match really starts.
func TestDFATailEOFSkipSafe(t *testing.T) {
	patterns := []string{
		`[a-z]{50,}[0-9]$`,
		`(?:a{3,4})+$`,
		`abc$`,
		`a$`,
		`(?:abc|de)$`,
		`[a-z]+\z`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, FindFunc: "eofskip_find"},
			})
		})
	}
}

// TestDFATailEmptyPatternFind covers the degenerate layouts: a pattern that
// matches empty produces a single-state automaton, which several analyses
// guard against before indexing anything.
func TestDFATailEmptyPatternFind(t *testing.T) {
	for _, pattern := range []string{``, `(?:)`, `a*`} {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, MatchFunc: "empty_match", FindFunc: "empty_find"},
			})
		})
	}
}

// TestDFATailAnchorCheckEmittersCoverEveryAnchorType exercises both anchor-check
// emitters across the whole anchorType enum, directly rather than through a
// pattern.
//
// Why directly: anchorEndText as a START anchor has no pattern-level witness —
// a leading \z contradicts a match that must still consume a byte, so the
// analyser never hands the emitter that combination. The arm exists anyway
// because the emitter takes an enum and must answer for every value of it, and
// the answer it gives (an UNCONDITIONAL fail) is the safe one: a silent
// fallthrough would emit a body that reports matches the anchor forbids. That
// is a contract worth pinning even with no route to it today, and pinning it
// here is honest about there being no route — an assertion that it is
// unreachable would not be, since exactly that claim was recently made about
// three other branches in this file and proved wrong.
func TestDFATailAnchorCheckEmittersCoverEveryAnchorType(t *testing.T) {
	everyAnchor := []struct {
		anchor anchorType
		name   string
	}{
		{anchorNone, "none"},
		{anchorBeginText, "beginText"},
		{anchorEndText, "endText"},
		{anchorWordBoundary, "wordBoundary"},
		{anchorNoWordBoundary, "noWordBoundary"},
	}
	const (
		locPtr          = byte(0)
		locAttemptStart = byte(4)
		locLen          = byte(1)
		tmpLocal        = byte(5)
		literalFirst    = byte('a')
	)
	for _, entry := range everyAnchor {
		t.Run(entry.name, func(t *testing.T) {
			startBody := emitStartAnchorCheck(nil, entry.anchor, literalFirst,
				locPtr, locAttemptStart, tmpLocal)
			endBody := emitEndAnchorCheck(nil, entry.anchor,
				locPtr, locAttemptStart, 8, locLen, tmpLocal)
			// anchorNone is the only value that may legitimately emit nothing;
			// every other value must emit a guard, or the anchor it stands for
			// is silently not being enforced at runtime.
			if entry.anchor == anchorNone {
				if len(startBody) != 0 || len(endBody) != 0 {
					t.Errorf("anchorNone emitted %d start / %d end bytes; an absent "+
						"anchor must cost nothing", len(startBody), len(endBody))
				}
				return
			}
			if len(startBody) == 0 && len(endBody) == 0 {
				t.Errorf("%s emitted no check at either end: the anchor would not be "+
					"enforced at runtime", entry.name)
			}
		})
	}
}

// TestDFATailLitChainGroupsRequireRealCaptures covers the "groups export was
// requested but the pattern has no capture groups" refusals in the three
// group-aware lit-chain analysers.
//
// This is a real configuration, not a contrived one: `groups_func` is set per
// entry in the config, and nothing stops it being set on a pattern that has no
// groups. The analysers must decline so the pattern falls through to the
// standard pipeline — accepting it would build a capture plan with zero slots
// and then emit slot writes against it.
func TestDFATailLitChainGroupsRequireRealCaptures(t *testing.T) {
	// A counted tail of at least 24 is required before the analysers look at
	// captures at all, so each pattern below is long enough to get that far and
	// be refused for the capture reason specifically.
	t.Run("fixed count", func(t *testing.T) {
		if _, _, ok := analyseLitChainGroups(`abc[a-z]{24}`); ok {
			t.Error("accepted a fixed-count chain with no capture groups")
		}
	})
	t.Run("counted range", func(t *testing.T) {
		if _, _, ok := analyseLitChainGroupsRange(`abc[a-z]{24,30}`); ok {
			t.Error("accepted a counted-range chain with no capture groups")
		}
	})
	t.Run("alternation", func(t *testing.T) {
		if _, _, ok := analyseLitChainAltGroups(`abc[a-z]{24}|qq[0-9]{24}`); ok {
			t.Error("accepted an alternation in which no branch captures anything")
		}
	})
}

// TestDFATailLitChainAltGroupsUnparseable covers the parse guard on the
// alternation analyser. Like its siblings it re-parses the pattern string
// rather than receiving an AST, so it owns the failure case itself and must
// decline rather than proceed with a nil tree.
func TestDFATailLitChainAltGroupsUnparseable(t *testing.T) {
	if _, _, ok := analyseLitChainAltGroups(`(`); ok {
		t.Error("accepted an unparseable pattern instead of declining")
	}
}

// TestDFATailLitChainGroupsAcceptsTheRealShape is the control for the two
// tests above. If the analysers ever start refusing everything — say because
// the counted-tail threshold moved — the refusal assertions would keep passing
// while the optimisation quietly stopped applying to any pattern at all.
func TestDFATailLitChainGroupsAcceptsTheRealShape(t *testing.T) {
	if _, _, ok := analyseLitChainGroups(`abc([a-z]{24})`); !ok {
		t.Error("refused a fixed-count chain that does capture; the group-aware " +
			"lit-chain path is no longer reachable by any pattern")
	}
	if _, _, ok := analyseLitChainGroupsRange(`abc([a-z]{24,30})`); !ok {
		t.Error("refused a counted-range chain that does capture")
	}
}

// TestDFATailAltBranchAnchorsResolvedAtCompileTime covers the per-branch anchor
// handling in the lit-chain ALTERNATION emitters.
//
// An anchor sits on one branch of the alternation, and some combinations are
// decidable without running anything: an \z at a branch's start can never hold
// (the branch still has to consume K+N bytes), a \b at position 0 holds only if
// the branch's first literal byte is a word char (text-start counts as
// non-word), and \B is its exact complement. The emitter resolves those at
// compile time and drops the branch entirely rather than emitting a runtime
// check that can only ever fail.
//
// Dropping a branch is a correctness-critical shortcut in the wrong direction:
// drop one that CAN match and matches vanish silently, so each row below pairs
// a droppable branch with a live sibling that must survive.
func TestDFATailAltBranchAnchorsResolvedAtCompileTime(t *testing.T) {
	patterns := []struct {
		pattern string
		why     string
	}{
		{`\zabc[a-z]{24}|qqqq[0-9]{24}`,
			"leading \\z on branch 0 can never hold; branch 1 must still be emitted"},
		{`\Babc[a-z]{24}|qqqq[0-9]{24}`,
			"\\B at text start fails because 'a' is a word char"},
		{`\b-bc[a-z]{24}|qqqq[0-9]{24}`,
			"\\b at text start fails because '-' is not a word char"},
		{`\babc[a-z]{24}|qqqq[0-9]{24}`,
			"the live counterpart: \\b holds at text start for a word first byte"},
		{`\B-bc[a-z]{24}|qqqq[0-9]{24}`,
			"the live counterpart: \\B holds for a non-word first byte"},
		{`abc[a-z]{24}\A|qqqq[0-9]{24}`,
			"\\A as an END anchor needs end_pos==0, impossible once K+N bytes are consumed"},
	}
	for _, testCase := range patterns {
		t.Run(testCase.pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: testCase.pattern, MatchFunc: "altanchor_match"},
			})
		})
	}
}

// TestDFATailAltBranchAnchorsWithCaptures is the same matrix through the
// capture-bearing emitter, which is a SEPARATE body: it has to apply the same
// compile-time anchor resolution and then still write each surviving branch's
// slots. A branch dropped in one emitter but not the other would make the
// groups export disagree with the match export about whether there is a match.
func TestDFATailAltBranchAnchorsWithCaptures(t *testing.T) {
	patterns := []string{
		`(\zabc[a-z]{24})|(qqqq[0-9]{24})`,
		`(\Babc[a-z]{24})|(qqqq[0-9]{24})`,
		`(\b-bc[a-z]{24})|(qqqq[0-9]{24})`,
		`(\babc[a-z]{24})|(qqqq[0-9]{24})`,
		`(abc[a-z]{24}\b)|(qqqq[0-9]{24})`,
		`(abc[a-z]{24}\z)|(qqqq[0-9]{24})`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, GroupsFunc: "altanchor_groups"},
			})
		})
	}
}

// TestDFATailAltBranchRangeCounts covers the counted-RANGE spelling of the same
// alternation family, which routes to its own analyser and its own branch body
// (a range has no single total length, so the class verify is emitted
// differently from the fixed-count case).
func TestDFATailAltBranchRangeCounts(t *testing.T) {
	patterns := []string{
		`abc[a-z]{24,30}|qqqq[0-9]{24}`,
		`(abc[a-z]{24,30})|(qqqq[0-9]{24,28})`,
		`\babc[a-z]{24,30}|qqqq[0-9]{24}`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: pattern, MatchFunc: "altrange_match", GroupsFunc: "altrange_groups"},
			})
		})
	}
}

// TestDFATailSingleBranchAnchorsResolvedAtCompileTime is the non-alternation
// counterpart of the per-branch anchor resolution above. A single lit-chain
// pattern gets the same treatment through its own emitter, and the two must
// agree: a pattern whose anchor cannot hold has to be recognised as such
// whether or not it happens to sit inside an alternation.
func TestDFATailSingleBranchAnchorsResolvedAtCompileTime(t *testing.T) {
	patterns := []struct {
		pattern string
		why     string
	}{
		{`\Babc[a-z]{24}`, "\\B at text start fails: 'a' is a word char"},
		{`\b-bc[a-z]{24}`, "\\b at text start fails: '-' is not a word char"},
		{`\babc[a-z]{24}`, "the live counterpart of the \\B case"},
		{`\B-bc[a-z]{24}`, "the live counterpart of the \\b case"},
		{`abc[a-z]{24}\A`, "\\A as an end anchor is unsatisfiable after K+N bytes"},
	}
	for _, testCase := range patterns {
		t.Run(testCase.pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{
				{Pattern: testCase.pattern, MatchFunc: "chainanchor_match"},
			})
		})
	}
}

// relocateProg returns a copy of prog whose instructions all live at PCs >= off,
// by prepending off unreachable InstFail padding instructions and shifting every
// PC-valued field. The relocated program is behaviourally identical to the
// original: only the numeric values of its PCs change.
//
// Arg is a PC only for InstAlt/InstAltMatch. For InstCapture it is a capture
// slot index and for InstEmptyWidth it is an EmptyOp bitmask, so it must not be
// shifted for those.
func relocateProg(prog *syntax.Prog, off uint32) *syntax.Prog {
	out := &syntax.Prog{
		Inst:   make([]syntax.Inst, off, off+uint32(len(prog.Inst))),
		Start:  prog.Start + int(off),
		NumCap: prog.NumCap,
	}
	for i := range out.Inst {
		out.Inst[i] = syntax.Inst{Op: syntax.InstFail}
	}
	for _, in := range prog.Inst {
		cp := in
		if len(in.Rune) > 0 {
			cp.Rune = append([]rune(nil), in.Rune...)
		}
		switch in.Op {
		case syntax.InstFail, syntax.InstMatch:
			// Out is unused.
		default:
			cp.Out = in.Out + off
		}
		if in.Op == syntax.InstAlt || in.Op == syntax.InstAltMatch {
			cp.Arg = in.Arg + off
		}
		out.Inst = append(out.Inst, cp)
	}
	return out
}

// TestDFA_HighPCsDoNotCollide pins the fixed-width NFA-PC key encoding in
// setToKey. The previous encoding used strings.Builder.WriteRune, which maps
// every PC in the UTF-16 surrogate window 0xD800-0xDFFF (2048 distinct values)
// — and PC 0xFFFD — onto utf8.RuneError's three bytes. Distinct NFA state sets
// then produced equal map keys, were merged into one DFA state, and the emitted
// table was silently wrong: no error, no fallback to another engine.
//
// Relocating a program to high PCs cannot change its language, so its DFA must
// be identical instruction-for-instruction. Under the old encoding the
// relocated DFA collapses to fewer states.
func TestDFA_HighPCsDoNotCollide(t *testing.T) {
	pats := []string{
		"ab",
		"a[bc]d|ae",
		"[0-9]+x",
		"a*b",
	}
	// 0xD800 puts every reachable PC inside the surrogate window; 0xFFFB places
	// PC 0xFFFD (RuneError itself) among the reachable ones.
	offsets := []uint32{0xD800, 0xFFFB}

	for _, pat := range pats {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		base, ok := newDFA(prog, false, false, 1024)
		if !ok {
			t.Fatalf("%q: baseline DFA construction failed", pat)
		}

		for _, off := range offsets {
			moved, ok := newDFA(relocateProg(prog, off), false, false, 1024)
			if !ok {
				t.Fatalf("%q @ off=%#x: relocated DFA construction failed", pat, off)
			}
			if moved.numStates != base.numStates {
				t.Errorf("%q @ off=%#x: numStates = %d, want %d (distinct NFA state sets were merged)",
					pat, off, moved.numStates, base.numStates)
				continue
			}
			if !reflect.DeepEqual(moved.transitions, base.transitions) {
				t.Errorf("%q @ off=%#x: transition table differs from the same program at low PCs", pat, off)
			}
			if !reflect.DeepEqual(moved.accepting, base.accepting) {
				t.Errorf("%q @ off=%#x: accept map differs from the same program at low PCs", pat, off)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// parseDataSegments checked every malformation in its input EXCEPT a size field
// larger than the bytes that remain. Truncated LEB128 panicked with an
// invariant message naming the problem; an oversized size instead sliced out of
// range and died with Go's own message, which says nothing about where the bad
// bytes came from.
//
// Inputs here are always this compiler's own output microseconds earlier, so
// this is defence in depth rather than a live crash — the same standing the
// other checks in the function have.

func TestParseDataSegmentsRejectsOversizedSize(t *testing.T) {
	// A well-formed header — type 0, i32.const 0, end — followed by a size
	// claiming far more than the payload that follows.
	var seg []byte
	seg = append(seg, 0x00, 0x41)
	seg = utils.AppendSLEB128(seg, 0)
	seg = append(seg, 0x0B)
	seg = utils.AppendULEB128(seg, 64)
	seg = append(seg, 1, 2, 3) // only three bytes, not 64

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("parseDataSegments accepted a size larger than the remaining bytes")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "exceeds") {
			t.Fatalf("panic = %v, want one naming the oversized segment size", r)
		}
	}()
	parseDataSegments(seg)
}

// A segment whose size exactly consumes the rest of the input is legal and must
// still parse — the check is `>`, not `>=`.
func TestParseDataSegmentsAcceptsExactFit(t *testing.T) {
	payload := []byte{9, 8, 7, 6}
	var seg []byte
	seg = append(seg, 0x00, 0x41)
	seg = utils.AppendSLEB128(seg, 128)
	seg = append(seg, 0x0B)
	seg = utils.AppendULEB128(seg, uint32(len(payload)))
	seg = append(seg, payload...)

	got := parseDataSegments(seg)
	if len(got) != 1 {
		t.Fatalf("parsed %d segments, want 1", len(got))
	}
	if got[0].offset != 128 {
		t.Errorf("offset = %d, want 128", got[0].offset)
	}
	if string(got[0].data) != string(payload) {
		t.Errorf("data = %v, want %v", got[0].data, payload)
	}
}

// The round trip the function actually serves: what appendDataSegment writes,
// parseDataSegments must read back unchanged.
func TestParseDataSegmentsRoundTrip(t *testing.T) {
	want := []struct {
		off  int32
		data []byte
	}{
		{0, []byte{1, 2, 3}},
		{4096, []byte{0xFF}},
		{65536, make([]byte, 300)},
	}
	var raw []byte
	for _, w := range want {
		raw = appendDataSegment(raw, w.off, w.data)
	}
	got := parseDataSegments(raw)
	if len(got) != len(want) {
		t.Fatalf("parsed %d segments, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].offset != want[i].off {
			t.Errorf("segment %d offset = %d, want %d", i, got[i].offset, want[i].off)
		}
		if len(got[i].data) != len(want[i].data) {
			t.Errorf("segment %d length = %d, want %d", i, len(got[i].data), len(want[i].data))
		}
	}
}
