package fuzz

import (
	"regexp"
	"testing"
)

// x{3}abcdef|y{3}ghijkl routes to the ALT-LIT-ANCHOR emitter (a dispatcher plus
// a backward-scan/forward-verify pair per branch). It is the last find emitter
// still on ffLegacyNarrow, so this pins its behaviour while it is legacy and
// becomes its acceptance test when it is converted.
func TestAltLitAnchorIteration(t *testing.T) {
	for _, c := range []struct{ pat, input string }{
		{`x{3}abcdef|y{3}ghijkl`, "xxxabcdef yyyghijkl xxxabcdef"},
		{`x{3}abcdef|y{3}ghijkl`, "zzz yyyghijkl"},
		{`x{3}abcdef|y{3}ghijkl`, "no match here at all"},
	} {
		t.Run(c.input, func(t *testing.T) {
			w, err := compileFind(c.pat)
			if err != nil {
				// A fixed, valid fixture whose whole purpose is to keep the
				// alt-lit-anchor emitter covered. Skipping here would turn the
				// loss of that entire path into a green test.
				t.Fatalf("compile: %v", err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog")
			}
			want := goFindAll(regexp.MustCompile(c.pat), c.input)
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("alt-lit-anchor iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpans(got), fmtSpans(want))
			}
		})
	}
}
