package compile

import (
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// Set-composition core: the branches CompileSet reaches only at its edges.
//
// The set matrix in set_matrix_coverage_test.go compiles whole sets and so
// covers the HAPPY paths of set.go, set_caps.go, set_probe.go, startable.go and
// set_sparse.go thoroughly. What it cannot reach are the refusals: a merge that
// blows the helper DFA state limit, a pattern the Backtracking fallback also
// declines, a promotion candidate disqualified by one member, an emitter arm
// selected by a flag no YAML config can currently set. Those are exactly the
// paths whose regression is silent — a dropped set member is a missing match,
// not a build error — so they are driven here by calling the composition
// functions directly with the shape that selects them.
//
// Each case names the branch it exists for. Where a shape cannot arise from a
// config today, the comment says so explicitly rather than implying the test
// proves reachability.

// setCoreCovAnalyze runs analyzePattern over fresh dedup pools, which is how
// every set packer receives its PatternInfos.
func setCoreCovAnalyze(t *testing.T, pattern string) *PatternInfo {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: pattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern(%q): %v", pattern, err)
	}
	return info
}

// setCoreCovAnalyzeAll shares ONE pair of pools across the patterns, the way
// CompileSet does, so suffix dedup behaves as it would in a real set.
func setCoreCovAnalyzeAll(t *testing.T, patterns ...string) []*PatternInfo {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, len(patterns))
	for i, pattern := range patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: pattern}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pattern, err)
		}
		infos[i] = info
	}
	return infos
}

// setCoreCovIDs returns 0..n-1, the id vector a bucket of n patterns gets when
// the set selects every pattern.
func setCoreCovIDs(n int) []int {
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i
	}
	return ids
}

// setCoreCovOversizedPair is two patterns that each compile to a ~1500-state
// DFA on their own — comfortably inside maxHelperDFAStates (2048) — but whose
// UNION needs ~3000, because their first bytes are disjoint so the merged
// automaton can share nothing. That is the only way to make a merge fail while
// both members remain individually admissible, which is what every
// "merge returned an error, keep looking" branch needs.
var setCoreCovOversizedPair = []string{
	`[a-z]{1000}[0-9]{500}`,
	`[0-9]{1000}[a-z]{500}`,
}

// --------------------------------------------------------------------------
// Small predicates and option accessors

func TestSetCoreOptionMaxPatternsPerBucket(t *testing.T) {
	// The sparse packers reject a promotion whose total exceeds this, so an
	// explicit override has to win over the 4096 default or a caller cannot
	// bound a WAF-scale bucket at all.
	if got := (CompileSetOptions{MaxPatternsPerBucket: 77}).maxPatternsPerBucket(); got != 77 {
		t.Errorf("maxPatternsPerBucket with override = %d, want 77", got)
	}
	if got := (CompileSetOptions{}).maxPatternsPerBucket(); got != 4096 {
		t.Errorf("maxPatternsPerBucket default = %d, want 4096", got)
	}
}

func TestSetCoreDFATableEqualTransitionLength(t *testing.T) {
	// dfaPool.Add treats a fingerprint collision as "compare byte for byte",
	// and the comparison must not index past the shorter table. Two tables
	// agreeing on every scalar header field but differing in transition-slice
	// length is the shape that reaches that guard.
	left := &dfaTable{numStates: 1, transitions: make([]int, 256)}
	right := &dfaTable{numStates: 1, transitions: make([]int, 512)}
	if dfaTableEqual(left, right) {
		t.Error("dfaTableEqual returned true for tables of different transition length")
	}
}

func TestSetCoreStrippedAnchorKind(t *testing.T) {
	// strippedAnchorKind classifies a prefix that is about to be REPLACED by
	// an eligibility mask, so both degenerate answers matter: a nil prefix
	// (nothing was stripped) and a prefix carrying no begin-anchor at all must
	// both yield "no restriction", never a mask that forbids positions.
	if got := strippedAnchorKind(nil); got != beginAnchorNone {
		t.Errorf("strippedAnchorKind(nil) = %v, want beginAnchorNone", got)
	}
	if got := strippedAnchorKind(mustParse(t, `[a-z]`)); got != beginAnchorNone {
		t.Errorf("strippedAnchorKind([a-z]) = %v, want beginAnchorNone", got)
	}
	if got := strippedAnchorKind(mustParse(t, `\Aabc`)); got != beginAnchorText {
		t.Errorf(`strippedAnchorKind(\Aabc) = %v, want beginAnchorText`, got)
	}
}

func TestSetCoreSetTopLevelAnchor(t *testing.T) {
	// The \A arm: a top-level begin-text anchor restricts the pattern to
	// position 0, and emitGroupMask reads startAnchor to build that mask. The
	// (?m:^) arm is covered by the set matrix; this is its stricter sibling.
	var info PatternInfo
	info.setTopLevelAnchor(mustParse(t, `\Aabc`))
	if !info.startAnchor {
		t.Error(`setTopLevelAnchor(\Aabc) did not set startAnchor`)
	}
	if info.lineAnchor {
		t.Error(`setTopLevelAnchor(\Aabc) set lineAnchor; \A is not a line anchor`)
	}

	// The (?m:^) arm must NOT collapse to startAnchor. Doing so made the
	// eligibility mask STRICTER than the assertion — position 0 only, where
	// the pattern also matches after any newline — which is FUZZER_BUGS 43.
	var lineInfo PatternInfo
	lineInfo.setTopLevelAnchor(mustParse(t, `(?m:^)abc`))
	if !lineInfo.lineAnchor {
		t.Error("setTopLevelAnchor((?m:^)abc) did not set lineAnchor")
	}
	if lineInfo.startAnchor {
		t.Error("setTopLevelAnchor((?m:^)abc) set startAnchor; that forbids every position but 0")
	}
}

func TestSetCoreAssertionScans(t *testing.T) {
	// Both scans guard a SPLIT decision — a prefix carrying either assertion
	// cannot be verified by the backward prefix DFA — so a false negative
	// silently loses or invents matches. The nil and recursive arms are what
	// a real AST walk hits on every non-leaf node.
	if regexpHasWordBoundary(nil) {
		t.Error("regexpHasWordBoundary(nil) = true")
	}
	if regexpHasEndAssertion(nil) {
		t.Error("regexpHasEndAssertion(nil) = true")
	}
	if !regexpHasEndAssertion(mustParse(t, `abc$`)) {
		t.Error("regexpHasEndAssertion(abc$) = false")
	}
	if !regexpHasEndAssertion(mustParse(t, `(?:abc(?:d\z))`)) {
		t.Error(`regexpHasEndAssertion of a nested \z = false`)
	}
	if regexpHasEndAssertion(mustParse(t, `abc`)) {
		t.Error("regexpHasEndAssertion(abc) = true")
	}
}

func TestSetCorePatternASTHelpersOnUnparseablePattern(t *testing.T) {
	// Both helpers re-parse PatternInfo.fullPattern from scratch, and both are
	// called from packers that must not panic on the result. analyzePattern
	// parsed it once already, so a failure here means the string was rewritten
	// between the two — the helpers answer nil and the packers drop the
	// pattern with a diagnostic rather than dereferencing.
	broken := &PatternInfo{fullPattern: `(unclosed`}
	if got := patternSuffixAST(broken); got != nil {
		t.Errorf("patternSuffixAST on an unparseable pattern = %v, want nil", got)
	}
	if got := patternFullAST(broken); got != nil {
		t.Errorf("patternFullAST on an unparseable pattern = %v, want nil", got)
	}
}

func TestSetCoreAssignTeddyLanesShortLiteral(t *testing.T) {
	// Above 16 literals the lanes are shared by low-nibble key, and the key is
	// truncated to the literal's own length when it is shorter than the probe
	// window. Without that clamp a 1-byte literal in a 3-byte-probe set reads
	// past its own bytes.
	literals := make([][]byte, 0, 20)
	literals = append(literals, []byte("a")) // shorter than minProbe
	for i := 0; i < 19; i++ {
		literals = append(literals, []byte{byte('b' + i), 'x', 'y', 'z'})
	}
	lanes := assignTeddyLanes(literals, 3)
	if len(lanes) != len(literals) {
		t.Fatalf("assignTeddyLanes returned %d lanes for %d literals", len(lanes), len(literals))
	}
	for i, lane := range lanes {
		if lane < 0 || lane > 15 {
			t.Errorf("literal %d assigned lane %d, outside 0..15", i, lane)
		}
	}
}

// --------------------------------------------------------------------------
// Merge refusals
//
// All four merge entry points share the same three refusals — empty input, too
// many patterns for the accept form, and a union DFA over maxHelperDFAStates —
// and every caller treats an error as "do not pack here". A refusal that
// stopped being an error would instead return a nil table the caller then
// dereferences.

func TestSetCoreMergeSuffixDFASparseSetRejects(t *testing.T) {
	if _, _, err := mergeSuffixDFASparseSet(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeSuffixDFASparseSet(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	// maxPatternsPerBucket is the sparse form's own ceiling; the u16 accept
	// lists cannot address past it.
	if _, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{MaxPatternsPerBucket: 2}); err == nil {
		t.Error("mergeSuffixDFASparseSet past maxPatternsPerBucket returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, _, err := mergeSuffixDFASparseSet(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeSuffixDFASparseSet over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

func TestSetCoreMergeAnchoredDFARejects(t *testing.T) {
	if _, err := mergeAnchoredDFA(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeAnchoredDFA(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	// The anchored bitmask form is capped by bitmaskWidth exactly as the find
	// one is: bit k of the returned mask IS bucket-local index k.
	if _, err := mergeAnchoredDFA(asts, CompileSetOptions{BitmaskWidth: 2}); err == nil {
		t.Error("mergeAnchoredDFA past bitmaskWidth returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, err := mergeAnchoredDFA(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeAnchoredDFA over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

func TestSetCoreMergeAnchoredDFASparseSetRejects(t *testing.T) {
	if _, _, err := mergeAnchoredDFASparseSet(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeAnchoredDFASparseSet(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	if _, _, err := mergeAnchoredDFASparseSet(asts, CompileSetOptions{MaxPatternsPerBucket: 2}); err == nil {
		t.Error("mergeAnchoredDFASparseSet past maxPatternsPerBucket returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, _, err := mergeAnchoredDFASparseSet(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeAnchoredDFASparseSet over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

// --------------------------------------------------------------------------
// analyzePattern refusals

func TestSetCoreAnalyzePatternPrefixAssertionsRouteToFallback(t *testing.T) {
	// The backward prefix DFA carries no word-boundary context and drops
	// end-of-text assertions outright, so a prefix containing either cannot be
	// verified by it. Both must therefore lose the split entirely — keeping
	// prefixAST while clearing splittable is what made a set member silently
	// never match.
	cases := []struct {
		pattern string
		why     string
	}{
		{`[a-z]\bkeyword`, `a \b at the prefix's right edge: the backward walk cannot see input[start-1]`},
		{`[a-z]$keyword`, `an end assertion in the prefix: reverseRegexp drops it and the walk INVENTS matches`},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			info := setCoreCovAnalyze(t, tc.pattern)
			if info.splittable {
				t.Errorf("%s: splittable = true; %s", tc.pattern, tc.why)
			}
			if info.prefixAST != nil || info.suffixAST != nil {
				t.Errorf("%s: split ASTs retained (prefix=%v suffix=%v) after the split was rejected",
					tc.pattern, info.prefixAST, info.suffixAST)
			}
		})
	}
}

func TestSetCoreAnalyzePatternStateLimits(t *testing.T) {
	// A set member whose own helper DFA cannot be built is an ERROR, not a
	// silent drop: CompileFile reports it and the pattern stays out of the
	// set. Three chained {1000} repeats give a 3001-state chain against
	// maxHelperDFAStates == 2048.
	//
	// This covers the SUFFIX direction only. The matching prefix branch could
	// not be reached: findMandatoryLitRec refuses any literal past offset 256,
	// so a prefix is at most 256 bytes, and the prefix DFA is built by
	// determinising the REVERSED prefix — which by Brzozowski's theorem yields
	// the MINIMAL DFA of the reversed prefix language. Every natural
	// fixed-length prefix (chains, counted classes, keyword alternations)
	// therefore minimises well below 2048: a 2730-word 12-byte alternation
	// measured 705 states. Reaching the limit needs a language deliberately
	// built to have thousands of distinct residuals, not a pattern anyone
	// would write, so the branch is left uncovered rather than faked.
	const chain = `[a-z]{1000}[0-9]{1000}[a-z]{1000}`

	var prefixPool, suffixPool dfaPool
	_, err := analyzePattern(config.RegexEntry{Pattern: chain}, &prefixPool, &suffixPool)
	if err == nil {
		t.Fatal("analyzePattern with an over-limit SUFFIX returned no error")
	}
	if !strings.Contains(err.Error(), "suffix") {
		t.Errorf("suffix state-limit error should name the suffix; got %v", err)
	}
}

// --------------------------------------------------------------------------
// compileFallback: the drop and re-pack branches

// setCoreCovIsolatedUnbuildable is non-greedy — so analyzePattern isolates it
// and returns EARLY, leaving suffixDFA nil for compileFallback to build — and
// its own merge then fails too. Dereferencing the nil that results was a crash.
// The 13 chained nullable loops are what make the Backtracking fallback refuse
// it as well (maxBTEmptyBodyGreedyLoops == 12), so it reaches the warn-and-drop
// rather than being admitted on BT.
var setCoreCovIsolatedUnbuildable = `a*?` + strings.Repeat(`(?:a|)*`, 13) +
	`[a-z]{1000}[0-9]{1000}[a-z]{1000}`

// setCoreCovIsolatedBTRefused is non-greedy and BT-refused like the above, but
// its DFA is small enough to BUILD — it is only over an artificially low
// max_fallback_states. That separates the two isolated-bucket drop branches:
// "no DFA at all" and "a DFA that is too big".
var setCoreCovIsolatedBTRefused = `a*?` + strings.Repeat(`(?:a|)*`, 13) + `[a-z]{20}`

func TestSetCoreCompileFallbackIsolatedDropsWhenDFAUnbuildable(t *testing.T) {
	info := setCoreCovAnalyze(t, setCoreCovIsolatedUnbuildable)
	if !info.isolatedFallback {
		t.Fatalf("pattern is not isolated; the non-greedy detection this case depends on has moved")
	}
	if info.suffixDFA != nil {
		t.Fatal("an isolated pattern should reach compileFallback with suffixDFA nil")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "isolated-unbuildable"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileFallbackIsolatedOverStateLimit(t *testing.T) {
	// Same isolated branch, one step further along: the DFA builds but exceeds
	// max_fallback_states. BT is offered the pattern first and refuses, so the
	// warn-and-drop arm runs.
	info := setCoreCovAnalyze(t, setCoreCovIsolatedBTRefused)
	if !info.isolatedFallback {
		t.Fatalf("pattern is not isolated; the non-greedy detection this case depends on has moved")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "isolated-over-limit"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	out := buf.String()
	if !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
	if !strings.Contains(out, "limit=8") {
		t.Errorf("warning should name the limit that was exceeded; got %q", out)
	}
}

func TestSetCoreCompileFallbackIsolatedAdmittedToBT(t *testing.T) {
	// The positive half of both isolated drop branches: a non-greedy member
	// the DFA path cannot serve is ADMITTED on Backtracking rather than
	// dropped, so it keeps behaving like the same pattern compiled alone.
	// Which branch offers it to BT depends on why the DFA path failed, and
	// both offers have to exist — an admission wired into only one of them
	// leaves the other silently dropping members.
	cases := []struct {
		name    string
		pattern string
		opts    CompileSetOptions
		why     string
	}{
		{
			name:    "own-dfa-unbuildable",
			pattern: `a*?[a-z0-9]{200}`,
			opts:    CompileSetOptions{},
			why:     "the isolated merge exceeds maxHelperDFAStates, so there is no table to size",
		},
		{
			name:    "over-max-fallback-states",
			pattern: `a*?bcdefghijkl`,
			opts:    CompileSetOptions{MaxFallbackStates: 8},
			why:     "the isolated DFA builds but is larger than max_fallback_states",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := setCoreCovAnalyze(t, tc.pattern)
			if !info.isolatedFallback {
				t.Fatalf("%q is not isolated; the non-greedy detection this case depends on has moved",
					tc.pattern)
			}

			buf, restore := captureWarnings(t)
			defer restore()

			buckets := compileFallback([]*PatternInfo{info}, tc.opts, nil)
			if len(buckets) != 1 || buckets[0].btFallback == nil {
				t.Fatalf("%s: expected one Backtracking bucket, got %d buckets (%s)",
					tc.name, len(buckets), tc.why)
			}
			// A BT bucket answers for patternIDs[bi][0] and validMask bit 0
			// alone, so a second member packed into it would have no emitted
			// code at all in any bucketed capability.
			if n := len(buckets[0].patterns); n != 1 {
				t.Errorf("%s: BT bucket holds %d patterns, want exactly 1", tc.name, n)
			}
			if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
				t.Errorf("%s: a BT-admitted pattern must not warn about being dropped; got %q", tc.name, out)
			}
		})
	}
}

// setCoreCovNullableUnbuildable has minLen 0, so analyzePattern returns early
// with suffixDFA nil — the NON-isolated twin of the case above. Its own merge
// then fails and BT refuses it, which is the sibling guard that was missing for
// years while the isolated branch carried it.
var setCoreCovNullableUnbuildable = strings.Repeat(`(?:a|)*`, 13) +
	`(?:[a-z]{1000}[0-9]{1000}[a-z]{1000})?`

func TestSetCoreCompileFallbackNewBucketDFAUnbuildable(t *testing.T) {
	info := setCoreCovAnalyze(t, setCoreCovNullableUnbuildable)
	if info.isolatedFallback {
		t.Fatal("pattern took the ISOLATED branch; this case exists for the non-isolated one")
	}
	if info.suffixDFA != nil {
		t.Fatal("a minLen==0 pattern should reach compileFallback with suffixDFA nil")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "nullable-unbuildable"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileFallbackMergeRefusalStartsNewBucket(t *testing.T) {
	// Two fallback patterns that cannot share a bucket because their union DFA
	// is unbuildable. The packer must keep looking and open a second bucket —
	// treating the merge error as "unpackable, drop it" would lose a member.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	opts := CompileSetOptions{MaxFallbackStates: 2048}
	buckets := compileFallback(infos, opts, nil)

	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets (the merge must be refused), got %d", len(buckets))
	}
	for i, bkt := range buckets {
		if len(bkt.patterns) != 1 {
			t.Errorf("bucket %d holds %d patterns, want 1", i, len(bkt.patterns))
		}
		if !bkt.isFallback {
			t.Errorf("bucket %d is not marked isFallback", i)
		}
	}
}

// --------------------------------------------------------------------------
// binPack

func TestSetCoreBinPackCountedChainConflictUnderLikelyMatch(t *testing.T) {
	// LM-6: under LikelyMatch two counted-class-chain patterns must NOT share
	// a bucket, because isCountedClassChain needs a single-pattern suffix DFA
	// and merging them costs both the SIMD-verify suffix body. The conflict is
	// recorded in --diag-json so the split is explainable.
	infos := setCoreCovAnalyzeAll(t, `KEY[0-9]{4}`, `KEY[A-Z0-9]{16}`)
	for _, info := range infos {
		if _, _, ok := isCountedClassChain(info.suffixDFA); !ok {
			t.Fatalf("%q: suffix is not a counted class chain; this case no longer selects LM-6",
				info.fullPattern)
		}
	}

	diag := &SetDiag{Name: "lm-counted-chain"}
	buckets := binPack(infos, CompileSetOptions{LikelyMode: LikelyMatch}, diag)

	if len(buckets) != 2 {
		t.Fatalf("expected the two chains kept apart (2 buckets), got %d", len(buckets))
	}
	found := false
	for _, conflict := range diag.Conflicts {
		if conflict.Reason == "lm_counted_chain_split" {
			found = true
		}
	}
	if !found {
		t.Errorf("no lm_counted_chain_split conflict recorded; conflicts = %+v", diag.Conflicts)
	}

	// Without the hint the same two patterns share one bucket, which is what
	// makes the split above attributable to LikelyMode rather than to the
	// budgets.
	neutral := binPack(setCoreCovAnalyzeAll(t, `KEY[0-9]{4}`, `KEY[A-Z0-9]{16}`),
		CompileSetOptions{}, nil)
	if len(neutral) != 1 {
		t.Errorf("without LikelyMatch the two chains should merge into 1 bucket, got %d", len(neutral))
	}
}

func TestSetCoreBinPackMergeRefusalStartsNewBucket(t *testing.T) {
	// The same merge refusal as the fallback packer's, in the literal-group
	// packer: both patterns share the mandatory literal "KEY" but their suffix
	// union is unbuildable, so the group must split rather than lose a member.
	infos := setCoreCovAnalyzeAll(t,
		`KEY`+setCoreCovOversizedPair[0],
		`KEY`+setCoreCovOversizedPair[1],
	)
	for _, info := range infos {
		if info.mandLit == nil || !info.splittable {
			t.Fatalf("%q did not split at a mandatory literal; this case no longer reaches binPack's literal group",
				info.fullPattern)
		}
	}
	buckets := binPack(infos, CompileSetOptions{}, nil)
	if len(buckets) != 2 {
		t.Fatalf("expected the shared-literal group to split (2 buckets), got %d", len(buckets))
	}
	for i, bkt := range buckets {
		if bkt.literal != "KEY" {
			t.Errorf("bucket %d literal = %q, want %q", i, bkt.literal, "KEY")
		}
	}
}

// --------------------------------------------------------------------------
// G17 promotion policy

func TestSetCorePromoteSharedLiteralBucketsDeclines(t *testing.T) {
	// Two shapes gain nothing and must be returned untouched: no buckets at
	// all, and a group whose first bucket has an empty literal — which means
	// the caller handed over the FALLBACK group, whose own promotion call site
	// passes isFallback and must not be reached through this one.
	if got := promoteSharedLiteralBuckets(nil, CompileSetOptions{AllowSparseAccept: true}); got != nil {
		t.Errorf("promoteSharedLiteralBuckets(nil) = %v, want nil", got)
	}
	fallbackGroup := []*bucket{{literal: "", isFallback: true}, {literal: "", isFallback: true}}
	got := promoteSharedLiteralBuckets(fallbackGroup, CompileSetOptions{AllowSparseAccept: true})
	if len(got) != 2 {
		t.Errorf("a fallback group must be returned unchanged; got %d buckets, want 2", len(got))
	}
}

// setCoreCovFallbackPromotion is the promotion strategy the FALLBACK packer
// uses, which is the one whose refusals matter most: a fallback bucket runs at
// every input position, so a refused promotion costs a full extra walk per byte.
var setCoreCovFallbackPromotion = sparsePromotion{
	astFor:     patternSuffixAST,
	merge:      mergeSuffixDFASparseSet,
	isFallback: true,
}

// setCoreCovBucketOf wraps one analyzed pattern in a literal-less bucket, the
// shape compileFallback hands to promoteSparseBuckets.
func setCoreCovBucketOf(info *PatternInfo) *bucket {
	return &bucket{literal: "", patterns: []*PatternInfo{info}, isFallback: true}
}

func TestSetCorePromoteSparseBucketsKeepsIneligibleMembers(t *testing.T) {
	// Every disqualifier here is a SILENT wrong answer if lifted without also
	// teaching the sparse body the per-pattern rule, so each is pinned
	// separately. The two plain patterns are what make the promotion happen at
	// all, and the ineligible bucket must survive in the output beside the
	// promoted one.
	cases := []struct {
		name    string
		pattern string
		why     string
	}{
		{
			name:    "isolated-non-greedy",
			pattern: `a*?bcd`,
			why:     "an isolated pattern got its own bucket precisely so its DFA would not be merged",
		},
		{
			name:    "non-trivial-prefix",
			pattern: `[a-z]{3}marker`,
			why:     "the sparse body carries ONE prefix length for the whole bucket",
		},
		{
			name:    "start-anchored",
			pattern: `\Amarker`,
			why:     "a sparse body ignores validMask, so an anchored member would match at every position",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plainOne := setCoreCovAnalyze(t, `alpha[0-9]`)
			plainTwo := setCoreCovAnalyze(t, `beta[0-9]`)
			odd := setCoreCovAnalyze(t, tc.pattern)

			in := []*bucket{
				setCoreCovBucketOf(plainOne),
				setCoreCovBucketOf(odd),
				setCoreCovBucketOf(plainTwo),
			}
			out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
				setCoreCovFallbackPromotion)

			if len(out) != 2 {
				t.Fatalf("%s: got %d buckets, want 2 (one promoted + the ineligible one kept): %s",
					tc.name, len(out), tc.why)
			}
			sparseCount, keptOdd := 0, false
			for _, bkt := range out {
				if bkt.sparse {
					sparseCount++
					if len(bkt.patterns) != 2 {
						t.Errorf("%s: promoted bucket holds %d patterns, want 2", tc.name, len(bkt.patterns))
					}
				}
				if len(bkt.patterns) == 1 && bkt.patterns[0] == odd {
					keptOdd = true
				}
			}
			if sparseCount != 1 {
				t.Errorf("%s: %d sparse buckets in the output, want exactly 1", tc.name, sparseCount)
			}
			if !keptOdd {
				t.Errorf("%s: the ineligible bucket was dropped rather than kept; %s", tc.name, tc.why)
			}
		})
	}
}

func TestSetCorePromoteSparseBucketsRefusesUnbuildableMerge(t *testing.T) {
	// The promotion is only worth taking if the merged DFA exists and fits the
	// budgets; otherwise the packer would have split it again and the input is
	// returned untouched.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	in := []*bucket{setCoreCovBucketOf(infos[0]), setCoreCovBucketOf(infos[1])}
	out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
		setCoreCovFallbackPromotion)
	if len(out) != 2 {
		t.Fatalf("an unbuildable merge must leave the buckets alone; got %d, want 2", len(out))
	}
	for _, bkt := range out {
		if bkt.sparse {
			t.Error("a bucket was marked sparse despite the merge failing")
		}
	}
}

func TestSetCorePromoteSparseBucketsRefusesNewlineBoundary(t *testing.T) {
	// The sparse bodies do not serialise the (?m) accept channel, so a merged
	// table carrying one must be refused. This is checked on the TABLE rather
	// than the AST because the channel is a property of the merge: the
	// per-pattern AST scan above it only rejects word boundaries.
	infos := setCoreCovAnalyzeAll(t, `alpha(?m:$)`, `beta(?m:$)`)
	in := []*bucket{setCoreCovBucketOf(infos[0]), setCoreCovBucketOf(infos[1])}

	merged, _, err := mergeSuffixDFASparseSet(
		[]*syntax.Regexp{patternSuffixAST(infos[0]), patternSuffixAST(infos[1])},
		CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if !merged.hasNewlineBoundary {
		t.Fatal("the merged table carries no newline boundary; this case no longer selects the refusal")
	}

	out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
		setCoreCovFallbackPromotion)
	if len(out) != 2 {
		t.Fatalf("a (?m) merge must be refused; got %d buckets, want 2", len(out))
	}
	for _, bkt := range out {
		if bkt.sparse {
			t.Error("a (?m)-bearing bucket was promoted to sparse accept")
		}
	}
}

// --------------------------------------------------------------------------
// compileAnchoredBuckets

func TestSetCoreCompileAnchoredBucketsDropsUnparseable(t *testing.T) {
	// Defensive, but not silent: analyzePattern parsed the string once, so a
	// failure here means it was rewritten. A bare `continue` would drop the
	// pattern from the anchored trio while `find` kept it, with nothing in
	// --diag-json to explain the disagreement.
	broken := &PatternInfo{fullPattern: `(unclosed`}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "anchored-unparseable"}
	buckets, members := compileAnchoredBuckets([]*PatternInfo{broken}, CompileSetOptions{}, diag)

	if len(buckets) != 0 || len(members) != 0 {
		t.Fatalf("expected the pattern dropped; got %d buckets / %d member lists", len(buckets), len(members))
	}
	if len(diag.UnparseableDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: UnparseableDropped = %v", diag.UnparseableDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileAnchoredBucketsMergeRefusalStartsNewBucket(t *testing.T) {
	// The anchored packer's own merge refusal. It packs in DECLARATION order
	// because a bucket's bit k must map to a stable global id, so a refused
	// merge has to open a new bucket rather than reorder anything.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	opts := CompileSetOptions{MaxFallbackStates: 2048, BudgetStates: 2048, BudgetBytes: 1 << 20}
	buckets, members := compileAnchoredBuckets(infos, opts, nil)

	if len(buckets) != 2 {
		t.Fatalf("expected the anchored merge refused (2 buckets), got %d", len(buckets))
	}
	if len(members) != len(buckets) {
		t.Fatalf("members (%d) and buckets (%d) disagree", len(members), len(buckets))
	}
	for i, group := range members {
		if len(group) != 1 {
			t.Errorf("bucket %d holds %d patterns, want 1", i, len(group))
		}
	}
}

// --------------------------------------------------------------------------
// set_caps.go: the shared bit-recording emitters

func TestSetCoreRecordEmittersStopAtBit32(t *testing.T) {
	// Both emitters unroll one compare per bucket-local bit into an i32 mask,
	// so they must stop at 32 whatever the caller passes. A sparse bucket
	// holds more patterns than that and reaches these emitters through
	// genAnchoredWASM's id map, where an unbounded loop would emit compares
	// against bits the mask cannot hold.
	ids := setCoreCovIDs(40)
	anyBody := emitSetAnyID(nil, ids, 7 /* bitsLocal */, 8 /* dst */, -1 /* no escape */)
	if len(anyBody) == 0 {
		t.Fatal("emitSetAnyID emitted nothing")
	}
	capped := emitSetAnyID(nil, setCoreCovIDs(32), 7, 8, -1)
	if len(anyBody) != len(capped) {
		t.Errorf("emitSetAnyID emitted %d bytes for 40 ids but %d for 32; the k>=32 stop is gone",
			len(anyBody), len(capped))
	}

	allBody := emitSetAllBits(nil, ids, 7, false /* narrow */, 0, 5, 6)
	allCapped := emitSetAllBits(nil, setCoreCovIDs(32), 7, false, 0, 5, 6)
	if len(allBody) != len(allCapped) {
		t.Errorf("emitSetAllBits emitted %d bytes for 40 ids but %d for 32; the k>=32 stop is gone",
			len(allBody), len(allCapped))
	}
}

func TestSetCoreCapAccumulatorBooleanArms(t *testing.T) {
	// capMatch is the boolean anchored arm: any bit at all settles the answer,
	// so it emits a flag store and a branch out rather than any id handling.
	// The `match:` CONFIG KEY that used to select it is retired (TODO task 59
	// decision (2)), so no YAML reaches these arms today — they are driven
	// directly, and stay because match_any/match_all share the same emitter
	// dispatch and would break together.
	accumulator := capAccumulator{kind: capMatch, lCount: 5, lAnyID: 6, lAcc: 7}

	bits := accumulator.emitRecordBits(nil, 8 /* bitsLocal */, setCoreCovIDs(4), 1 /* escapeDepth */)
	if len(bits) == 0 {
		t.Fatal("emitRecordBits(capMatch) emitted nothing")
	}

	// The sparse flavour answers from a COUNT rather than bucket-local bits,
	// because a sparse bucket has more patterns than a mask has bits. For the
	// boolean arm the count alone is enough and no id map is read, which is
	// why an id-map-less bucket is a legitimate argument here.
	sparseBits := accumulator.emitRecordSparseCount(nil, 4 /* countLocal */, &bucket{},
		0 /* tableMemIdx */, 9, 10, 1)
	if len(sparseBits) == 0 {
		t.Fatal("emitRecordSparseCount(capMatch) emitted nothing")
	}

	body := finishAnchoredCapBody(nil, capMatch, false, 7, 5, 6)
	if len(body) == 0 {
		t.Fatal("finishAnchoredCapBody(capMatch) emitted nothing")
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("finishAnchoredCapBody did not terminate the function (last byte %#x)", body[len(body)-1])
	}
}

func TestSetCoreCheckIDSpacePanicsOnOutOfRangeID(t *testing.T) {
	// Every gate offset and `_all` bit position IS a pattern id, and the
	// caller's arrays are sized by the id space the STUBS were told about. A
	// divergence writes out of bounds into host memory — silent and
	// data-dependent — so it is turned into a build failure. Reaching it needs
	// a compiledSet whose ids disagree with its declared space, which
	// CompileFile cannot produce: both sides call config.SetConfig.IDSpaceSize.
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("checkIDSpace did not panic on an id outside the declared space")
		}
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "id space") {
			t.Errorf("panic message does not explain the bound: %v", recovered)
		}
	}()
	cs := &compiledSet{
		name:            "over-declared",
		declaredIDSpace: 2,
		patternIDs:      [][]int{{0, 1, 5}},
	}
	cs.checkIDSpace()
}

func TestSetCoreNumPatternsSkipsFallbackUnderPhase1(t *testing.T) {
	// Under the two-phase scan split the phase-1 body answers for the LITERAL
	// buckets only; the fallback patterns belong to phase 2's union walk. Its
	// "every pattern has been seen" exit therefore has to count the phase-1
	// view, not the set.
	//
	// CompileSet cannot currently reach this combination: numPatterns is read
	// only by the wide-bitmap scan_all drain check, and usesTwoPhaseScan
	// refuses scan_all exactly when wideAll() is true. The field is set
	// directly here to exercise the accessor's own contract; if the split ever
	// serves a wide scan_all, this is the behaviour it will get.
	cs := &compiledSet{
		buckets:    []*bucket{{isFallback: false}, {isFallback: true}},
		patternIDs: [][]int{{0, 1}, {2, 3, 4}},
	}
	if got := cs.numPatterns(); got != 5 {
		t.Errorf("numPatterns() = %d, want 5 (the whole set)", got)
	}
	cs.phase1Only = true
	if got := cs.numPatterns(); got != 2 {
		t.Errorf("numPatterns() under phase1Only = %d, want 2 (literal buckets only)", got)
	}
}

// --------------------------------------------------------------------------
// set_probe.go

func TestSetCoreProbeBodyRejectsAnchoredFirstHit(t *testing.T) {
	// An anchored answer is not monotone: a mid-walk accept says nothing about
	// reaching `len`, so there is no first bit to stop on. Combining the two
	// would silently report patterns that match a proper prefix, which is the
	// opposite of the anchored contract, so it is a build-time panic.
	defer func() {
		if recover() == nil {
			t.Fatal("buildSetProbeBodyExit accepted a first-hit exit on an ANCHORED probe")
		}
	}()
	buildSetProbeBodyExit(setSuffixParams{}, true /* anchored */, probeExitFirstHit)
}

func TestSetCoreProbeBodyClampsBucketWidthTo32(t *testing.T) {
	// The probe returns a bucket-local bitmask in an i32, so the "every
	// eligible pattern seen" mask must be capped at 32 bits however many ids
	// the bucket carries. binPack caps a bucket at 32 today, so this is
	// reached by handing genAnchoredWASM a wider id vector directly.
	table, err := mergeAnchoredDFA([]*syntax.Regexp{mustParse(t, `alpha`), mustParse(t, `beta`)},
		CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeAnchoredDFA: %v", err)
	}
	body, _, _, _, sparse := genAnchoredWASM(table, 0, 0, setCoreCovIDs(40))
	if len(body) == 0 {
		t.Fatal("genAnchoredWASM emitted no body for a 40-id bucket")
	}
	if sparse != nil {
		t.Fatal("a bitmask table must not report sparse anchored info")
	}
}

func TestSetCoreGenAnchoredWASMEmptyTable(t *testing.T) {
	// An empty bucket DFA still needs a callable probe: the anchored capability
	// bodies call every bucket in turn with no nil check, so the degenerate
	// case has to be a function returning 0, not a missing one.
	body, dataBytes, segCount, next, sparse := genAnchoredWASM(nil, 4096, 0, setCoreCovIDs(2))
	if len(body) == 0 {
		t.Fatal("genAnchoredWASM(nil) emitted no body")
	}
	if len(dataBytes) != 0 || segCount != 0 {
		t.Errorf("an empty table needs no data segments; got %d bytes / %d segments", len(dataBytes), segCount)
	}
	if next != 4096 {
		t.Errorf("nextTableOffset = %d, want the unchanged base 4096", next)
	}
	if sparse != nil {
		t.Error("an empty table must not report sparse anchored info")
	}
}

func TestSetCoreCountedChainProbeAnchoredFlavour(t *testing.T) {
	// The counted-class-chain bucket is one pattern of exactly N bytes of one
	// class, so "does it match" is a SIMD verification and needs no DFA walk.
	// The anchored flavour differs by one opcode — full consumption is
	// `endPos != len` rather than `endPos > len` — and that single difference
	// is the whole anchored contract for this body. Only the scan flavour has
	// a caller today (genSuffixWASM), so the anchored one is driven directly.
	class := make([]byte, 0, 10)
	for digit := byte('0'); digit <= '9'; digit++ {
		class = append(class, digit)
	}
	scanBody := buildCountedChainProbeBody(class, 6, false)
	anchoredBody := buildCountedChainProbeBody(class, 6, true)
	if len(scanBody) == 0 || len(anchoredBody) == 0 {
		t.Fatal("buildCountedChainProbeBody emitted nothing")
	}
	if len(scanBody) != len(anchoredBody) {
		t.Errorf("the two flavours differ by more than the length test: %d vs %d bytes",
			len(scanBody), len(anchoredBody))
	}
	// 0x47 is i32.ne (anchored: exact length) and 0x4B is i32.gt_u (scan: fits).
	if !bytesContain(anchoredBody, 0x47) {
		t.Error("anchored counted-chain probe does not test for EXACT length (i32.ne missing)")
	}
	if !bytesContain(scanBody, 0x4B) {
		t.Error("scan counted-chain probe does not test for a fitting length (i32.gt_u missing)")
	}
}

func bytesContain(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// startable.go: the first-byte eligibility table

func TestSetCoreFirstByteSetGivesUpSafely(t *testing.T) {
	// The table must OVER-approximate: a pattern wrongly cleared is a lost
	// match. Both give-up paths therefore answer nil ("assume every byte")
	// rather than an empty or partial set.
	if got := firstByteSet(`(unclosed`); got != nil {
		t.Error("firstByteSet on an unparseable pattern returned a set; it must give up")
	}
	// A non-ASCII first rune is encoded as several bytes and what leads it is
	// a UTF-8 lead byte, not the rune. Deriving that is out of scope for a
	// byte-oriented engine, so the whole pattern gives up.
	if got := firstByteSet("étude"); got != nil {
		t.Error("firstByteSet on a non-ASCII first rune returned a set; it must give up")
	}
	// The positive control: a plain ASCII first byte is derivable, and only
	// that byte may be set.
	set := firstByteSet(`keyword`)
	if set == nil {
		t.Fatal("firstByteSet(keyword) gave up on a derivable ASCII first byte")
	}
	for b := 0; b < 256; b++ {
		if want := b == 'k'; set[b] != want {
			t.Errorf("firstByteSet(keyword)[%d] = %v, want %v", b, set[b], want)
		}
	}
}

func TestSetCoreBuildStartableTableDeclines(t *testing.T) {
	// The table is bucket-local pattern BITS in a uint32, so it cannot serve a
	// bucket past 32 patterns; and an empty bucket has nothing to clear. Both
	// answer nil, which the emitter reads as "no eligibility mask" rather than
	// as an all-zero table that would clear every pattern.
	if got := buildStartableTable(&bucket{}); got != nil {
		t.Error("buildStartableTable on an empty bucket returned a table")
	}

	wide := &bucket{patterns: make([]*PatternInfo, 33)}
	for i := range wide.patterns {
		wide.patterns[i] = &PatternInfo{fullPattern: `keyword`}
	}
	if got := buildStartableTable(wide); got != nil {
		t.Error("buildStartableTable on a 33-pattern bucket returned a table; bits past 31 have no home")
	}

	// The positive control, so the two nils above cannot pass for the table
	// having been switched off entirely.
	narrow := &bucket{patterns: []*PatternInfo{{fullPattern: `keyword`}, {fullPattern: `[0-9]+`}}}
	tab := buildStartableTable(narrow)
	if tab == nil {
		t.Fatal("buildStartableTable declined a bucket with a derivable first byte")
	}
	if tab['k'] != 0b01 {
		t.Errorf("startable['k'] = %#b, want 0b01 (only the literal pattern)", tab['k'])
	}
	if tab['5'] != 0b10 {
		t.Errorf("startable['5'] = %#b, want 0b10 (only the digit pattern)", tab['5'])
	}
	if tab['@'] != 0 {
		t.Errorf("startable['@'] = %#b, want 0 (neither pattern can begin there)", tab['@'])
	}
}

// --------------------------------------------------------------------------
// set_sparse.go

func TestSetCoreSparseSuffixBodySubtractsFixedPrefix(t *testing.T) {
	// A sparse bucket carries ONE prefix length for the whole bucket and
	// subtracts it from every tuple's start. promoteSparseBuckets refuses any
	// bucket whose members do not ALL have a trivial prefix, so the value is
	// 0 for every bucket a config can produce today — the emitter arm is
	// driven here by handing genSuffixWASM a non-zero fixed length directly.
	//
	// It is not dead: relaxing that refusal is a documented follow-up, and the
	// last time a bucket with mixed prefix lengths reached this body 285 of
	// its 288 patterns reported starts off by 1 or 2, going NEGATIVE near
	// position 0.
	const numPatterns = 40
	asts := make([]*syntax.Regexp, numPatterns)
	for i := range asts {
		asts[i] = mustParse(t, `suffix`+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	table, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if table.midAcceptWide == nil {
		t.Fatal("the merged table has no wide accept lists; this case no longer selects the sparse body")
	}

	prefixFixedLens := make([]int, numPatterns)
	prefixFixedLens[0] = 3 // the bucket-wide fixed prefix length

	withPrefix, _, _, _ := genSuffixWASM(table, 0, 0, setCoreCovIDs(numPatterns), prefixFixedLens,
		false /* needProbes */, false /* gated */)
	withoutPrefix, _, _, _ := genSuffixWASM(table, 0, 0, setCoreCovIDs(numPatterns), make([]int, numPatterns),
		false, false)

	if len(withPrefix.fnBody) == 0 {
		t.Fatal("genSuffixWASM emitted no sparse suffix body")
	}
	if len(withPrefix.fnBody) <= len(withoutPrefix.fnBody) {
		t.Errorf("a non-zero prefix length emitted no extra instructions: %d bytes vs %d",
			len(withPrefix.fnBody), len(withoutPrefix.fnBody))
	}
}

// --------------------------------------------------------------------------
// Branches in these files this test file does NOT reach, and what blocks each.
// Recorded so the next reader does not spend the same afternoon on them, and
// so none of them is mistaken for dead code — every one is a live guard.
//
//  1. Every `if err != nil` arm after a regexp/syntax.Compile call:
//     analyzePattern's prefix and suffix compiles, mergeSuffixDFA,
//     mergeSuffixDFASparseSet, mergeAnchoredDFA, mergeAnchoredDFASparseSet and
//     firstByteSet. syntax.Compile returns a nil error unconditionally
//     (go1.25.9 regexp/syntax/compile.go:71) — it panics on an unhandled Op
//     instead — so no *syntax.Regexp reaches those arms. They are the correct
//     thing to write against an (error) signature and must stay.
//
//  2. analyzePattern's PREFIX state limit. findMandatoryLitRec refuses a
//     literal past offset 256, so a prefix is at most 256 bytes; and the
//     prefix DFA is built by determinising the REVERSED prefix, which by
//     Brzozowski's theorem yields the MINIMAL DFA of the reversed prefix
//     language. Natural fixed-length prefixes therefore land far below
//     maxHelperDFAStates (2048): a 2730-word 12-byte keyword alternation
//     measured 705 states, and plain counted classes are linear chains.
//     Reaching 2048 needs a language built to have thousands of distinct
//     residuals. The SUFFIX limit next to it is covered.
//
//  3. genAnchoredWASM's `bits == 0` skip over the EOF accept map. The map is
//     only ever written through engine_dfa.go's orAccept, which refuses a zero
//     mask outright, and every relabel filters zeros — so no construction puts
//     a zero-valued entry in it, and reaching the skip means inserting one by
//     hand. Left alone rather than faked.
//
//  4. buildStartableTable's `k >= 32` return. The function has already
//     returned nil for any bucket with more than 32 patterns, so k tops out at
//     31. It is a second lock on the same door; removing it would leave the
//     table's uint32 bits depending on the caller's guard alone.
