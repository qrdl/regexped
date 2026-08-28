package compile

import (
	"testing"

	"github.com/qrdl/regexped/config"
)

// The three prefix-resume DIVERGENCE arms of buildFindBody.
//
// After the SIMD prefix scan matches, the find body must resume the DFA in the
// state the prefix walk ends in — but there are up to four such states, one per
// context the scan can land in: the ordinary mid-string walk, the walk from the
// true start (attempt_start==0), the walk taken when the preceding byte was a
// word character, and the walk taken when it was '\n'. buildFindBody picks
// between them with three flags, and three of its arms exist only for the cases
// where those walks DISAGREE.
//
// The shape that makes them disagree is an alternation where only ONE branch
// carries the anchor while BOTH branches share the mandatory literal prefix.
// computePrefix truncates to the common BYTE prefix of the start and mid-start
// walks, but consuming the same bytes can still land in DIFFERENT STATES: from
// startState the anchored branch is still alive, from midStartState it is dead.
// `^AB\d|AB[a-z]` forces "AB" either way, yet the start walk ends somewhere
// that still accepts \d while the mid walk ends somewhere that only accepts
// [a-z].
//
// Why this test exists at all: these arms were once measured "unreachable" and
// came within a decision of being deleted. The corpus that reached that verdict
// generated only SINGLE-BRANCH shapes ({literal} x {leading assertion} x
// {tail}), where an anchor gates the whole match and therefore suppresses
// prefix extraction outright — so it never built the one shape that fires the
// flags. Deleting the arms would have silently lost every match at position 0,
// after a '\n', or after a word/non-word byte for this pattern family. The
// assertions below are therefore two-directional: they fail if a flag stops
// firing (the arm goes quietly dead again) as well as if the wrong arm is
// chosen. See plans/TODO.md task 63.
//
// SCOPE, stated plainly so this file is not over-trusted: it pins the LAYOUT
// (the four resume states really do diverge) and the SELECTION (which arm a
// given divergence picks), and it emits each arm so the bytecode-building
// statements execute and the module is validated. It does NOT observe what
// buildFindBody does with its own flags — forcing newlineDiverges and
// startDiverges to false inside buildFindBody leaves every assertion here
// passing while 48 behavioral rows go red. The behavioral net is the
// PrefixResumeDivergence block in tools/re2test/custom-tests.txt, which runs
// the emitted WASM against Go-stdlib expectations; the two layers are
// complementary and neither substitutes for the other.
//
// Note the asymmetry this pins down: computePrefix has an explicit
// word-boundary divergence bail-out — it returns nil and disables the fast-skip
// entirely — but NO newline analogue. That makes the newline arm the only thing
// standing between these patterns and the lost-match bug its own comment in
// engine_dfa.go records.

// prefixResumeArm names the branch of buildFindBody's switch that a given flag
// combination selects, so a failure says which arm went missing rather than
// only which boolean moved.
type prefixResumeArm string

const (
	armConstant       prefixResumeArm = "constant (no divergence)"
	armStartOnly      prefixResumeArm = "start-divergence only"
	armWordOnly       prefixResumeArm = "word divergence"
	armNewlineOnly    prefixResumeArm = "newline divergence"
	armWordAndNewline prefixResumeArm = "word and newline divergence"
)

// selectPrefixResumeArm mirrors buildFindBody's own switch (engine_dfa.go
// ~8982) so the table below can state which arm a pattern must reach.
func selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges bool) prefixResumeArm {
	needsByteRead := wordDiverges || newlineDiverges
	switch {
	case !needsByteRead && !startDiverges:
		return armConstant
	case !needsByteRead && startDiverges:
		return armStartOnly
	case wordDiverges && !newlineDiverges:
		return armWordOnly
	case !wordDiverges && newlineDiverges:
		return armNewlineOnly
	default:
		return armWordAndNewline
	}
}

func TestPrefixResumeDivergenceArms(t *testing.T) {
	cases := []struct {
		pattern             string
		wantWordDiverges    bool
		wantNewlineDiverges bool
		wantStartDiverges   bool
		wantArm             prefixResumeArm
		why                 string
	}{
		{
			pattern:           `^A|AB`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why: "single-byte prefix 'A': from startState the ^A branch can accept " +
				"immediately, from midStartState only the AB branch survives",
		},
		{
			pattern:           `^AB\d|AB[a-z]`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why: "two-byte prefix 'AB': the start walk still admits \\d, the mid walk " +
				"only [a-z]",
		},
		{
			pattern:           `\AAB\d|AB[a-z]`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why:               "\\A is the same divergence as ^ under OneLine parsing",
		},
		{
			pattern:          `\bAB`,
			wantWordDiverges: true,
			wantArm:          armWordOnly,
			why: "single branch, leading word boundary: the word-context walk dies " +
				"because \\b cannot hold after a word byte, while the mid-string walk " +
				"survives. The only row where a byte must be read but the start walk " +
				"agrees, so it is also what covers the inner !startDiverges leg",
		},
		{
			pattern:             `(?m:^)AB\d|AB[a-z]`,
			wantNewlineDiverges: true,
			wantStartDiverges:   true,
			wantArm:             armNewlineOnly,
			why: "the multiline anchor makes the after-'\\n' walk diverge the same way " +
				"the begin-of-text walk does",
		},
		{
			pattern:             `(?m:^AB\d)|\bAB[a-z]`,
			wantWordDiverges:    true,
			wantNewlineDiverges: true,
			wantStartDiverges:   true,
			wantArm:             armWordAndNewline,
			why:                 "one branch anchored to a line start, the other to a word boundary",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.pattern, func(t *testing.T) {
			// Build the DFA exactly as compile.go's LF-DFA find path does; a
			// different option set here would prove nothing about the code that
			// actually ships.
			matcher, err := compile(testCase.pattern, CompileOptions{
				MaxDFAStates:  1024,
				ForceEngine:   EngineDFA,
				LeftmostFirst: true,
			})
			if err != nil {
				t.Fatalf("compile %q: %v", testCase.pattern, err)
			}
			table := dfaTableFrom(matcher.(*dfa))
			layout := buildDFALayout(dfaLayoutParams{
				t:                    table,
				tableBase:            0,
				needFind:             true,
				leftmostFirst:        true,
				compiledDFAThreshold: 256,
			})

			// The pattern has to actually REACH buildFindBody's prefix path.
			// Each of these routes elsewhere, and each has silently absorbed a
			// witness pattern before: `0*^0` diverges exactly as intended but
			// isAnchoredFind sends it to buildAnchoredFindBody instead, which
			// is how the arms came to look unreachable in the first place.
			if len(layout.prefix) == 0 {
				t.Fatalf("no mandatory literal prefix: the prefix-scan resume path is "+
					"never emitted, so this pattern cannot exercise any arm (%s)", testCase.why)
			}
			if isAnchoredFind(table) {
				t.Fatalf("isAnchoredFind routes this to buildAnchoredFindBody, " +
					"bypassing the arms under test")
			}
			if dfaHasOutrankedState(table) || dfaHasAmbiguousBoundaryTarget(table) {
				t.Fatalf("routed to Backtracking (outranked=%v ambiguousBoundary=%v), "+
					"bypassing the arms under test",
					dfaHasOutrankedState(table), dfaHasAmbiguousBoundaryTarget(table))
			}

			// Recomputed exactly as buildFindBody does (engine_dfa.go ~8978).
			wordDiverges := layout.needWordCharTable &&
				layout.wasmPrefixEnd != layout.wasmPrefixEndWord
			newlineDiverges := table.hasNewlineBoundary &&
				layout.wasmPrefixEnd != layout.wasmPrefixEndNewline
			startDiverges := layout.wasmPrefixEnd != layout.wasmPrefixEndStart

			if wordDiverges != testCase.wantWordDiverges ||
				newlineDiverges != testCase.wantNewlineDiverges ||
				startDiverges != testCase.wantStartDiverges {
				t.Errorf("divergence flags = word:%v newline:%v start:%v, "+
					"want word:%v newline:%v start:%v\n"+
					"  prefix=%q resume states: mid=%d word=%d newline=%d start=%d\n"+
					"  %s",
					wordDiverges, newlineDiverges, startDiverges,
					testCase.wantWordDiverges, testCase.wantNewlineDiverges, testCase.wantStartDiverges,
					layout.prefix, layout.wasmPrefixEnd, layout.wasmPrefixEndWord,
					layout.wasmPrefixEndNewline, layout.wasmPrefixEndStart,
					testCase.why)
			}

			if arm := selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges); arm != testCase.wantArm {
				t.Errorf("selects the %q arm, want %q", arm, testCase.wantArm)
			}

			// Emit for real: this is what executes the arm's bytecode-building
			// statements and validates that what it built is a legal module.
			mustCompileEntries(t, []config.RegexEntry{{
				Pattern:  testCase.pattern,
				FindFunc: "diverge_find",
			}})
		})
	}
}

// TestPrefixResumeConstantArmStillReached is the control. The three divergence
// arms are only interesting relative to the ordinary case, and a change that
// broke prefix extraction outright would otherwise make the test above fail in
// a way that looks like the arms disappearing rather than the prefix machinery
// disappearing underneath them.
func TestPrefixResumeConstantArmStillReached(t *testing.T) {
	// A plain literal, deliberately: it is the shape whose find body reaches
	// the no-divergence arm through the public pipeline. A prefixed pattern
	// with a long counted tail (`ghp_[a-zA-Z0-9]{36}`) does not — it routes to
	// the literal-anchor find body instead and would emit none of this switch.
	const pattern = `abc`
	matcher, err := compile(pattern, CompileOptions{
		MaxDFAStates:  1024,
		ForceEngine:   EngineDFA,
		LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	table := dfaTableFrom(matcher.(*dfa))
	layout := buildDFALayout(dfaLayoutParams{
		t:                    table,
		tableBase:            0,
		needFind:             true,
		leftmostFirst:        true,
		compiledDFAThreshold: 256,
	})
	if len(layout.prefix) == 0 {
		t.Fatalf("a plain literal-prefixed pattern lost its prefix; the divergence " +
			"tests above are measuring nothing")
	}
	wordDiverges := layout.needWordCharTable && layout.wasmPrefixEnd != layout.wasmPrefixEndWord
	newlineDiverges := table.hasNewlineBoundary && layout.wasmPrefixEnd != layout.wasmPrefixEndNewline
	startDiverges := layout.wasmPrefixEnd != layout.wasmPrefixEndStart
	if arm := selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges); arm != armConstant {
		t.Errorf("an unanchored literal-prefix pattern selects the %q arm, want %q",
			arm, armConstant)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "constant_find"}})
}
