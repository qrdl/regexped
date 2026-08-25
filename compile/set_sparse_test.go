package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// sparseGroup is 128 distinct patterns sharing ONE mandatory literal — the WAF
// shape G17 exists for. The distinct part must be NON-LITERAL: mandatory-literal
// extraction takes the LONGEST literal, so `unionkw000` would give each pattern
// its own literal and its own bucket, and nothing would be shared.
func sparseGroup(t *testing.T, n int, opts CompileSetOptions) []*bucket {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, 0, n)
	for i := 0; i < n; i++ {
		p := fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		info, err := analyzePattern(config.RegexEntry{Pattern: p}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern %q: %v", p, err)
		}
		info.globalID = i
		infos = append(infos, info)
	}
	return binPack(infos, opts, nil)
}

// TestSparsePromotionMergesSharedLiteralBuckets is G17's premise and its result
// in one: without promotion 128 patterns behind one literal split into four
// buckets — costing four suffix-DFA walks at every candidate position — and
// with it they are one.
//
// Measured end to end on a literal-dense 100 KB input, gated find, identical
// match counts: 25,739,575,028 fuel and a 149,918-byte module before, against
// 1,936,377,723 and 11,642 bytes after. 13.3x less fuel, 92% smaller.
func TestSparsePromotionMergesSharedLiteralBuckets(t *testing.T) {
	off := sparseGroup(t, 128, CompileSetOptions{})
	if len(off) != 4 {
		t.Fatalf("expected 128 patterns to split into 4 bitmask buckets, got %d "+
			"— the 32-pattern bitmask width is G17's premise", len(off))
	}
	for _, b := range off {
		if b.sparse {
			t.Error("promotion fired without AllowSparseAccept")
		}
	}

	on := sparseGroup(t, 128, CompileSetOptions{AllowSparseAccept: true})
	if len(on) != 1 {
		t.Fatalf("expected one sparse bucket, got %d", len(on))
	}
	if !on[0].sparse {
		t.Error("merged bucket is not marked sparse")
	}
	if got := len(on[0].patterns); got != 128 {
		t.Errorf("sparse bucket holds %d patterns, want all 128", got)
	}
	if on[0].suffixDFA.midAcceptWide == nil {
		t.Error("sparse bucket's DFA carries no wide accept lists")
	}
	// §23.2: a promotion that then misses the budgets is worse than the split
	// it replaced, because binPack would have split it again.
	o := CompileSetOptions{}
	if on[0].suffixStates > o.budgetStates() || on[0].tableBytes > o.budgetBytes() {
		t.Errorf("promoted bucket is over budget: %d states / %d bytes (budgets %d / %d)",
			on[0].suffixStates, on[0].tableBytes, o.budgetStates(), o.budgetBytes())
	}
}

// TestSparsePromotionIsConservative pins the refusals. Each is a case where
// promoting would be wrong or pointless, and a wrong promotion is worse than
// none: it would produce a bucket the emitter cannot serve correctly.
func TestSparsePromotionIsConservative(t *testing.T) {
	opts := CompileSetOptions{AllowSparseAccept: true}

	// One bucket already: nothing to merge.
	if got := sparseGroup(t, 32, opts); len(got) != 1 || got[0].sparse {
		t.Errorf("32 patterns are already one bucket; promotion must not fire (buckets=%d)", len(got))
	}

	// Word boundaries carry accept channels the sparse tables do not
	// serialise, so such a group must keep its bitmask buckets.
	var prefixPool, suffixPool dfaPool
	var infos []*PatternInfo
	for i := 0; i < 128; i++ {
		p := fmt.Sprintf(`union[ \t]+\b[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
		info, err := analyzePattern(config.RegexEntry{Pattern: p}, &prefixPool, &suffixPool)
		if err != nil {
			continue
		}
		info.globalID = i
		infos = append(infos, info)
	}
	if len(infos) > 64 {
		for _, b := range binPack(infos, opts, nil) {
			if b.sparse {
				t.Error("promoted a word-boundary group; its \\b accept channels are not serialised")
			}
		}
	}
}
