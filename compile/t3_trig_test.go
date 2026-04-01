package compile

import (
	"regexp/syntax"
	"testing"
)

// TestT3Triggered verifies that 4-byte Teddy tables are generated for patterns
// where the first-byte set is ≤8 and each successive byte is also selective.
// Patterns with a single unambiguous literal prefix use the hybrid-SIMD prefix
// scan instead (computePrefix returns a non-empty slice → Teddy is skipped).
func TestT3Triggered(t *testing.T) {
	cases := []struct {
		pattern string
		wantT1  bool
		wantT2  bool
		wantT3  bool
		desc    string
	}{
		// Two first bytes (h/f), then each has selective tails → T1, T2, T3 expected.
		{`(http|ftp)://[^\s]+`, true, true, true, "http|ftp alternation"},
		// Single-prefix patterns use computePrefix, not Teddy → no T* tables.
		{`ghp_[a-zA-Z0-9]{36}`, false, false, false, "single literal prefix ghp_"},
		{`AKIA[0-9A-Z]{16}`, false, false, false, "single literal prefix AKIA"},
		// Many first bytes → no Teddy at all.
		{`[a-z]+@[a-z]+`, false, false, false, "many first bytes"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			re, err := syntax.Parse(tc.pattern, syntax.Perl|syntax.OneLine)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			re = re.Simplify()
			prog, err := syntax.Compile(re)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			dfa := newDFA(prog, false, true)
			tbl := dfaTableFrom(dfa)
			l := buildDFALayout(tbl, 0, true, true, 0)

			gotT1 := len(l.teddyT1LoBytes) > 0
			gotT2 := len(l.teddyT2LoBytes) > 0
			gotT3 := len(l.teddyT3LoBytes) > 0

			t.Logf("prefix=%q firstBytes=%d T1=%v T2=%v T3=%v", l.prefix, len(l.firstBytes), gotT1, gotT2, gotT3)

			if gotT1 != tc.wantT1 {
				t.Errorf("T1: got %v, want %v", gotT1, tc.wantT1)
			}
			if gotT2 != tc.wantT2 {
				t.Errorf("T2: got %v, want %v", gotT2, tc.wantT2)
			}
			if gotT3 != tc.wantT3 {
				t.Errorf("T3: got %v, want %v", gotT3, tc.wantT3)
			}
		})
	}
}
