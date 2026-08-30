package compile

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// captureWarnings installs a temporary slog handler at Warn level and returns
// the captured output plus a restore func.
func captureWarnings(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	return &buf, func() { slog.SetDefault(prev) }
}

// btRefusedPattern is a pattern the Backtracking fallback engine REFUSES, so
// a set member over maxFallbackStates is still dropped rather than admitted.
//
// The refusal is checkBTEmptyBodyLoopChain's: 13 chained nullable loops against
// maxBTEmptyBodyGreedyLoops == 12 (measured live — the chain is only 87 NFA
// instructions, so this is a cheap pattern, not a pathological one). The
// `[a-z]{20}` tail is what puts the suffix DFA over the small limits used
// below; without it the pattern fits in a DFA bucket and never reaches a drop
// branch at all.
//
// Using the instruction cap (maxBTFallbackInstructions, 20000) instead is NOT
// a workable alternative: every pattern big enough to exceed it fails earlier,
// inside analyzePattern, with "DFA state limit exceeded during construction",
// so it never reaches compileFallback.
var btRefusedPattern = strings.Repeat(`(?:a|)*`, 13) + `[a-z]{20}`

// TestCompileFallback_AdmitsToBTOverStateLimit is the positive half of the
// Backtracking-member contract: a pattern whose suffix DFA exceeds
// maxFallbackStates is no longer dropped, it is admitted on the Backtracking
// engine, so the set member behaves like the same pattern compiled alone.
//
// Before item 20 this pattern produced 0 buckets and a warning; that older
// assertion is now TestCompileFallback_WarnsWhenBTAlsoRefuses's job.
func TestCompileFallback_AdmitsToBTOverStateLimit(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	// No literal anywhere, so this lands in the fallback bucket rather than a
	// literal bucket. ~200 suffix DFA states, comfortably over the limit below.
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	opts := CompileSetOptions{MaxFallbackStates: 8}
	buckets := compileFallback([]*PatternInfo{info}, opts, nil)

	if len(buckets) != 1 {
		t.Fatalf("expected the pattern admitted to BT (1 bucket), got %d", len(buckets))
	}
	if buckets[0].btFallback == nil {
		t.Errorf("bucket is not a Backtracking bucket; suffixDFA=%v", buckets[0].suffixDFA != nil)
	}
	// A BT bucket holds exactly one pattern: buildSetBTSuffixBody answers for
	// patternIDs[bi][0] and validMask bit 0 alone. compileFallback's bin-packer
	// used to merge later fallback patterns into it, and every merged-in
	// pattern then vanished from every bucketed capability with no error
	// anywhere.
	if n := len(buckets[0].patterns); n != 1 {
		t.Errorf("BT bucket holds %d patterns, want exactly 1", n)
	}
	if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("a BT-admitted pattern must not warn about being dropped; got %q", out)
	}
}

// TestCompileFallback_WarnsWhenBTAlsoRefuses covers the drop warning, which
// still exists: BT NARROWS the drop set, it does not empty it. A pattern that
// exceeds maxFallbackStates AND that BT refuses must be reported at warning
// level, not dropped silently.
//
// The branch is driven via CompileSetOptions.MaxFallbackStates rather than by
// finding a pathological pattern: the reachable window for the default limit is
// only (1024, maxHelperDFAStates] == (1024, 2048], and DFA state counts for the
// exponential-blowup pattern families that get anywhere near it jump in powers
// of the class size, so they skip straight over the window. Lowering the limit
// exercises exactly the same branch with an ordinary pattern.
func TestCompileFallback_WarnsWhenBTAlsoRefuses(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	opts := CompileSetOptions{MaxFallbackStates: 8}
	buckets := compileFallback([]*PatternInfo{info}, opts, nil)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern to be dropped (0 buckets), got %d", len(buckets))
	}
	out := buf.String()
	if !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("dropped pattern produced no warning; slog output was %q", out)
	}
	if !strings.Contains(out, "limit=8") {
		t.Errorf("warning should report the limit that was exceeded; got %q", out)
	}
}

// TestAdmitBTFallback_RefusesUnsupported pins WHY btRefusedPattern is refused,
// so the two tests above cannot silently start passing for a different reason
// (e.g. a pattern that stops reaching the drop branch at all).
func TestAdmitBTFallback_RefusesUnsupported(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if got := admitBTFallback(patternSuffixAST(info), resolveMemoBudget(nil)); got != nil {
		t.Fatalf("admitBTFallback accepted %q; the drop-path tests depend on it refusing", btRefusedPattern)
	}
	// And the admitted control, so this test fails if admitBTFallback starts
	// refusing everything.
	okInfo, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if got := admitBTFallback(patternSuffixAST(okInfo), resolveMemoBudget(nil)); got == nil {
		t.Fatal("admitBTFallback refused [a-z0-9]{200}; the admit-path test depends on it accepting")
	}
}

// TestCompileFallback_NoWarnWhenAdmitted guards the other direction: a pattern
// that fits must not emit the warning. Without this, a future change that warns
// unconditionally would still pass the test above.
func TestCompileFallback_NoWarnWhenAdmitted(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, nil)

	if len(buckets) != 1 {
		t.Fatalf("expected the pattern to be admitted (1 bucket), got %d", len(buckets))
	}
	if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("admitted pattern must not warn; got %q", out)
	}
}

// TestCompileFallback_WarnsWithNilDiag is the specific regression for the
// nil-diag warning mechanism. The warning must not be nested inside the
// `if diag != nil` bookkeeping guards: CompileSet always allocates a SetDiag so
// those guards always pass, but the struct is discarded unless --diag-json was
// requested. Passing an explicitly nil diag here asserts the warning is
// independent of diagnostics being collected.
func TestCompileFallback_WarnsWithNilDiag(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	// Must be a pattern BT also refuses, or there is no drop left to warn
	// about.
	info, err := analyzePattern(config.RegexEntry{Pattern: btRefusedPattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, nil /* diag */)

	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("warning must fire with a nil diag; got %q", out)
	}
}

// TestMaxFallbackStatesReachesCompiler pins the wiring, not the branch.
//
// The tests above drive the drop through CompileSetOptions directly, which
// proves the branch works but says nothing about whether a user can reach it.
// They could not: CompileSetOptions was constructed in two places and NEITHER
// set MaxFallbackStates, so the hardcoded default of 1024 always won — and the
// drop warning's own hint said "raise max_dfa_states", a field that feeds a
// different budget entirely. A pattern dropped from a set was therefore
// unfixable through the remedy it was told to use.
//
// This drives the real entry point, CompileFile, so a future refactor that
// rebuilds CompileSetOptions without the field fails here rather than silently
// restoring the unreachable knob.
//
// Since sets gained Backtracking members the observable effect of the budget
// being reached is
// only a DROP for a pattern BT also refuses — an ordinary over-limit pattern is
// now admitted to BT instead, and warns about nothing. So the pattern here is
// btRefusedPattern: the budget is still what decides its fate, and the warning
// is still how that decision is observed.
func TestMaxFallbackStatesReachesCompiler(t *testing.T) {
	cfg := func(limit int) config.BuildConfig {
		return config.BuildConfig{
			MaxFallbackStates: limit,
			Regexps: []config.RegexEntry{
				// No usable literal, so it lands in a fallback bucket, and
				// enough states to clear a small limit and not a large one.
				{Name: "big", Pattern: btRefusedPattern},
			},
			Sets: []config.SetConfig{{
				Name:     "s",
				Find:     "s_find",
				Patterns: config.PatternSelector{All: true},
			}},
		}
	}

	for _, tc := range []struct {
		limit       int
		wantDropped bool
	}{
		{8, true},        // below the pattern's state count: dropped
		{1 << 20, false}, // far above it: admitted
	} {
		buf, restore := captureWarnings(t)
		if _, _, err := CompileFile(cfg(tc.limit), ""); err != nil {
			restore()
			t.Fatalf("max_fallback_states=%d: CompileFile: %v", tc.limit, err)
		}
		out := buf.String()
		restore()

		got := strings.Contains(out, "Pattern dropped from set")
		if got != tc.wantDropped {
			t.Errorf("max_fallback_states=%d: dropped=%v, want %v (slog output %q)",
				tc.limit, got, tc.wantDropped, out)
		}
		if tc.wantDropped && !strings.Contains(out, "limit=8") {
			t.Errorf("max_fallback_states=8: warning reported a different limit: %q", out)
		}
		// The hint must name a key that actually feeds this budget.
		if tc.wantDropped && !strings.Contains(out, "raise max_fallback_states") {
			t.Errorf("drop hint should name max_fallback_states; got %q", out)
		}
	}
}

// TestCompileFallback_NilSuffixDFANoPanic is a crash regression:
// compileFallback's non-isolated `!placed` branch dereferenced
// nbDFA with no nil check and CRASHED.
//
// analyzePattern returns early for this shape leaving p.suffixDFA nil, and the
// mergeSuffixDFA call that would replace it then fails its own state limit, so
// nbDFA reaches the state-limit test still nil. The ISOLATED branch a few lines
// above has carried this guard, and a comment about the same crash, for some
// time — it was simply never added to the sibling branch.
//
// The assertion is only "does not panic": whether the pattern ends up admitted
// to BT or dropped is the surrounding branches' business and is covered above.
func TestCompileFallback_NilSuffixDFANoPanic(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(
		config.RegexEntry{Pattern: strings.Repeat(`(?:[a-z]*[0-9]*)`, 3000)},
		&prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}
	if info.suffixDFA != nil {
		t.Skip("suffixDFA is no longer nil for this shape; the branch is unreachable from here")
	}
	if info.isolatedFallback {
		t.Skip("routed to the isolated branch, which already had the guard")
	}
	// Panics fail the test by default; no assertion needed beyond returning.
	compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, nil)
}
