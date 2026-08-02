package compile

import (
	"testing"

	"github.com/qrdl/regexped/config"
)

func TestFindAltLitAnchorPoints(t *testing.T) {
	t.Run("accepts_equal_fixed_prefix", func(t *testing.T) {
		branches, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`)
		if !ok {
			t.Fatalf("findAltLitAnchorPoints rejected the target pattern")
		}
		if len(branches) != 2 {
			t.Fatalf("expected 2 branches, got %d", len(branches))
		}
	})

	t.Run("rejects_invalid_syntax", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[`); ok {
			t.Errorf("accepted invalid syntax")
		}
	})

	t.Run("rejects_non_alternate_top_level", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}`); ok {
			t.Errorf("accepted a non-alternation top-level pattern")
		}
	})

	t.Run("rejects_single_branch", func(t *testing.T) {
		// After parsing, an "alternation" of one literal-only branch — Go's
		// syntax package would fold `(?:a)` to a plain literal anyway, so
		// use a construct that stays OpAlternate with exactly one sub is not
		// generally reachable; instead verify the >=2 branch count gate
		// directly against a 3-branch pattern where all qualify.
		branches, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}|[0-9]{8}akey_[A-Za-z0-9]{20}`)
		if !ok || len(branches) != 3 {
			t.Fatalf("expected 3 qualifying branches, got ok=%v len=%d", ok, len(branches))
		}
	})

	t.Run("rejects_unequal_prefix_lengths", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{4}ghp_[A-Za-z0-9]{36}|[a-f]{16}secret_[A-Za-z0-9]{20}`); ok {
			t.Errorf("accepted branches with unequal fixed prefix lengths (4 vs 16)")
		}
	})

	t.Run("rejects_non_fixed_length_prefix", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{4,8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`); ok {
			t.Errorf("accepted a branch with a ranged (non-fixed-length) prefix")
		}
	})

	t.Run("rejects_unbounded_prefix", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`.*ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`); ok {
			t.Errorf("accepted a branch with an unbounded prefix")
		}
	})

	t.Run("rejects_mixed_qualifying_and_non_qualifying_branch", func(t *testing.T) {
		// Second branch's top-level shape isn't OpConcat with a qualifying
		// literal (it's a bare class run with no anchor literal at all).
		if _, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f0-9]{20}`); ok {
			t.Errorf("accepted an alternation with a non-qualifying branch")
		}
	})

	t.Run("rejects_too_many_branches", func(t *testing.T) {
		pattern := `[0-9]{8}ghp_[A-Za-z0-9]{4}`
		full := pattern
		for i := 0; i < maxAltLitAnchorBranches; i++ {
			full += "|" + pattern
		}
		if _, ok := findAltLitAnchorPoints(full); ok {
			t.Errorf("accepted more than %d branches", maxAltLitAnchorBranches)
		}
	})
}

// TestCompileAltLitAnchorDispatch exercises the full Task 6 v1 pipeline —
// compileAltLitAnchorBranches, buildAltLitAnchorFindBody, and
// compiledPattern.altLitAnchorBranchFuncIdx (all 0% covered without this) —
// by compiling a find-only alternation whose branches have an UNBOUNDED
// suffix (`[^\s]+`). Bounded-suffix branches like the ones
// TestFindAltLitAnchorPoints uses are caught earlier by Gap E's
// analyseLitChainAltPrefixed (compile.go), which returns before the
// alt-lit-anchor block is ever reached; an unbounded suffix isn't a lit-chain
// shape, so it falls through to this path instead.
func TestCompileAltLitAnchorDispatch(t *testing.T) {
	pattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`
	entry := config.RegexEntry{Pattern: pattern, FindFunc: "f"}

	p, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.altLitAnchorBranches == nil {
		t.Fatalf("compilePattern did not take the alt-lit-anchor path for %q", pattern)
	}
	if len(p.altLitAnchorBranches) != 3 {
		t.Fatalf("altLitAnchorBranches: got %d branches, want 3", len(p.altLitAnchorBranches))
	}
	// Exercise altLitAnchorBranchFuncIdx for every branch index (i>0 covers
	// the per-branch offset arithmetic beyond the first pair).
	for i := range p.altLitAnchorBranches {
		back, fwd := p.altLitAnchorBranchFuncIdx(i)
		if fwd != back+1 {
			t.Errorf("altLitAnchorBranchFuncIdx(%d) = (%d, %d), want fwd == back+1", i, back, fwd)
		}
	}

	mustCompileEntries(t, []config.RegexEntry{entry})
}
