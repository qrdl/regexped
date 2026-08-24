package fuzz

import (
	"regexp"
	"sort"
	"testing"
)

// TestTwoPhaseMixedSets drives the SETS_PLAN item 19 split: sets holding BOTH
// literal-bearing and literal-less patterns, which is the only shape that
// reaches phase 2.
func TestTwoPhaseMixedSets(t *testing.T) {
	cases := []struct {
		name string
		pats []string
	}{
		{"kw2+card", []string{`error`, `warning`, `[0-9]{16}`}},
		{"kw1+dotstar", []string{`ERROR`, `[^\n]*QQQ`}},
		{"secrets+num", []string{`AKIA[A-Z0-9]{4}`, `ghp_[A-Za-z0-9]{6}`, `[0-9]{8}`}},
		{"many+2fallback", []string{`alpha`, `bravo`, `charlie`, `delta`, `[0-9]{5}`, `[a-c]{4}z`}},
		{"anchored-fallback", []string{`foo`, `^[0-9]+`}},
		{"empty-fallback", []string{`bar`, `[0-9]*`}},
	}
	inputs := []string{
		"", "x", "error here", "warning: 1234567890123456", "1234567890123456",
		"no match at all", "AKIAZZZZ and ghp_abc123", "12345678", "alphabravo",
		"aabbz 99999", "foo", "0123", "\nQQQ", "ERRORQQQ", "abc",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dropped, err := compileCaps(tc.pats, false)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) != 0 {
				t.Fatalf("patterns dropped: %v", dropped)
			}
			res := make([]*regexp.Regexp, len(tc.pats))
			for i, p := range tc.pats {
				res[i] = regexp.MustCompile(p)
			}
			for _, input := range inputs {
				r := newCapRunner(t, tc.pats, input, false)
				n := int32(len(input))
				for from := 0; from <= len(input); from++ {
					var want []int
					for i, re := range res {
						if loc := re.FindStringIndex(input[from:]); loc != nil {
							_ = loc
							want = append(want, i)
						}
					}
					// Recompute with real left context via the whole-input probe.
					want = want[:0]
					for i, p := range tc.pats {
						probe := regexp.MustCompile(`(?s)\A.{` + itoa2(from) + `,}?(?:` + p + `)`)
						if probe.MatchString(input) {
							want = append(want, i)
						}
					}
					sort.Ints(want)

					gotAll := idsFromMask(uint64(r.call(t, "cap_scan_all", r.inBase, n, int32(from)).(int64)), len(tc.pats))
					if !eqIDs(append([]int(nil), want...), gotAll) {
						t.Fatalf("scan_all(%q, from=%d) = %v, want %v", input, from, gotAll, want)
					}
					gotAny := r.call(t, "cap_scan_any", r.inBase, n, int32(from)).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(%q, from=%d) = %d, want -1", input, from, gotAny)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(%q, from=%d) = %d, not among %v", input, from, gotAny, want)
					}
				}
				r.Close()
			}
		})
	}
}

func itoa2(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
