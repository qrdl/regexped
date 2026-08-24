package fuzz

import (
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// compileFindBT compiles with MaxDFAStates = -1, which makes every DFA
// overflow so find is emitted by the BACKTRACKING engine — the same mechanism
// re2test's --force-backtrack uses. Nothing else in this package reaches
// appendBTFindCodeEntry's find path, so without this the BT find emitter has
// no iteration coverage at all.
func compileFindBT(pat string) ([]byte, error) {
	w, _, err := compile.Compile([]config.RegexEntry{{Pattern: pat, FindFunc: "find"}},
		tableBase, true, compile.CompileOptions{MaxDFAStates: -1})
	return w, err
}

// btIterSeeds are shapes with a LEADING zero-width assertion, driven through
// the BT find emitter. A pattern without one answers the same whether the
// engine sees the whole buffer or a narrowed slice, so only these can show
// whether BT is reading real left context.
var btIterSeeds = []struct{ pat, input string }{
	{`\bfoo`, "foofoo"},
	{`\Bfoo`, "xfoofoo"},
	{`\Ba`, "aaa"},
	{`(?m:^)a`, "a\naa"},
	{`\B|a+b`, "1112"},
	{`a+`, "xaayaaa"}, // no assertion: guards against the conversion
	{`a*`, "bab"},     // breaking the ordinary cases
	{`(?:cat|car)`, "the cat in a car"},
}

func TestBTFindIterationMatchesGo(t *testing.T) {
	for _, c := range btIterSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindBT(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goFindAll(re, c.input)
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("BT find iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpans(got), fmtSpans(want))
			}
		})
	}
}
