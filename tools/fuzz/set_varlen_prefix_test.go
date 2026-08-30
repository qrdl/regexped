package fuzz

import (
	"fmt"
	"regexp"
	"testing"
)

// TestVarLenPrefixMustRouteToFallback pins the counterexamples behind
// analyzePattern's variable-length-prefix guard, and with them the reason
//
// The split representation prefix.literal.suffix recovers a match start from a
// literal candidate at c as `c - L` for ONE compile-time L (prefixMaxLen). That
// is exact only while the prefix has a single length. Every pattern below has a
// BOUNDED, ACYCLIC variable-length prefix — `a?`, `a{0,2}`, `(?:xy)?` — so each
// one satisfies the "deferred tier" criterion, under which an acyclic
// backward prefix DFA yields a computable maximum lookback M and the pattern
// may keep its literal frontend.
//
// Measured with the guard lifted, every one of them LOSES matches: `a?a` on
// "a", `a{0,2}b` on "b" and `(?:xy)?Q` on "Q" all report nothing where the
// answer is 0-1. The lost cases are exactly those where the prefix takes a
// length other than its maximum, because `c - prefixMaxLen` cannot address
// them — for the empty-prefix case it is negative.
//
// So boundedness is necessary but NOT sufficient: it fixes the drain bound and
// does nothing for start recovery. Making these patterns work needs the
// backward DFA to report the start it actually reached (not a constant), plus a
// rule for choosing between several starts recoverable from one candidate —
// and that choice follows the prefix's GREEDY structure, which a plain backward
// DFA cannot express (`a?a` and `a??a` on "aa" want different answers from the
// same automaton).
//
// This test asserts the OUTCOME, not the mechanism: whatever routing is chosen,
// these answers must match Go. It therefore stays valid if item 13 is ever
// built properly.
func TestVarLenPrefixMustRouteToFallback(t *testing.T) {
	cases := []struct {
		pats   []string
		inputs []string
	}{
		{[]string{`a?a`, `zz`}, []string{"a", "aa", "aaa"}},
		{[]string{`a{0,2}b`, `zz`}, []string{"b", "ab", "aab", "aaab"}},
		{[]string{`(?:xy)?Q`, `zz`}, []string{"Q", "xyQ", "xyxyQ"}},
		// Lazy twin of the first case: same automaton, different answer, which
		// is why an extent tie-break cannot substitute for greedy structure.
		{[]string{`a??a`, `zz`}, []string{"a", "aa"}},
	}
	for _, tc := range cases {
		for _, input := range tc.inputs {
			t.Run(fmt.Sprintf("%s/%s", tc.pats[0], input), func(t *testing.T) {
				r := newCapRunner(t, tc.pats, input, true) // overlapping: every start
				defer r.Close()
				total := int(r.call(t, "cap_find",
					r.inBase, int32(len(input)), 0, r.gatePtr, r.outPtr, int32(r.npat)).(int32))
				buf := r.mem.UnsafeData(r.store)
				var got [][3]int
				for i := 0; i < total && i < int(r.npat); i++ {
					b := int(r.outPtr) + i*12
					rd := func(o int) int32 {
						return int32(buf[b+o]) | int32(buf[b+o+1])<<8 |
							int32(buf[b+o+2])<<16 | int32(buf[b+o+3])<<24
					}
					got = append(got, [3]int{int(rd(0)), int(rd(4)), int(rd(8))})
				}
				// Oracle: the first start position at which anything matches,
				// and every pattern matching there — `find`'s contract.
				var want [][3]int
				for s := 0; s <= len(input) && len(want) == 0; s++ {
					for k, p := range tc.pats {
						re := regexp.MustCompile(`\A(?:` + p + `)`)
						if m := re.FindStringIndex(input[s:]); m != nil {
							want = append(want, [3]int{k, s, s + m[1]})
						}
					}
				}
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("find(%q) = %v, want %v", input, got, want)
				}
			})
		}
	}
}
