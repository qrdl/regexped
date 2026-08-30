package compile

import (
	"testing"

	"github.com/qrdl/regexped/config"
)

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
	if lmBareShuftiEligible(unparseable) {
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
