package fuzz

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// Regressions that need a RUNNING module:
// each one compiles green and answers wrongly, so only driving it can tell.

// litChainGroupsSeeds are the lit-chain "A.3" groups shapes.
//
// analyseLitChainGroups and its two siblings set compiledPattern.anchored on
// patterns that are NOT anchored — there the flag means "captureBody IS the
// export, no wrapper composition". assembleModule read it as "can only match
// at 0" and emitted the anchoredOnly groups wrapper, which answers -1 for
// EVERY from != 0 without calling the body. The body scans, so a second
// occurrence exists and iteration reported one match where Go reports two.
//
// The gate needs count >= 24, which is why the corpus never hit this.
var litChainGroupsSeeds = []struct{ pat, input string }{
	{`x([a-z]{24})`, "xabcdefghijklmnopqrstuvwx xabcdefghijklmnopqrstuvwx"},
	{`x([a-z]{24})`, "-- xabcdefghijklmnopqrstuvwx"},
	{`A([0-9]{24,30})`, "A012345678901234567890123 A012345678901234567890123"},
	{`(?:foo|bar)([a-z]{24})`, "fooabcdefghijklmnopqrstuvwx barabcdefghijklmnopqrstuvwx"},
}

// TestLitChainGroupsIterate drives the groups export past position 0.
func TestLitChainGroupsIterate(t *testing.T) {
	for _, c := range litChainGroupsSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileGroups(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := runGroupsIter(t, w, c.input, re.NumSubexp()+1)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}

// TestSimplePrefixCheckHonoursFrom covers G3.
//
// buildSimplePrefixCheckBody replaces the generic backward scan under
// LikelyNoMatch when the lit-anchor prefix is a bare [class]{M}. The rework gave
// the generic scan a find-from FLOOR; this body checked only `base < count`
// against the whole buffer and returned `base - count` unconditionally, so a
// literal at litpos in [from, from+M) yielded a reported start BEFORE `from` —
// which the phase-3 forward verify then genuinely confirms.
//
// The shapes below put two matches within M bytes of each other, so the second
// iteration's candidate sits inside the first's window.
func TestSimplePrefixCheckHonoursFrom(t *testing.T) {
	seeds := []struct{ pat, input string }{
		{`[0-9]{4}MARKER`, "1234MARKER5678MARKER"},
		{`[0-9]{4}MARKER`, "xx1234MARKER5678MARKERyy"},
		{`[a-f]{6}TAIL`, "abcdefTAILabcdefTAIL"},
	}
	for _, c := range seeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindLNM(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			var want [][2]int
			for _, m := range re.FindAllStringIndex(c.input, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			if fmtSpanList(got) != fmtSpanList(want) {
				t.Errorf("find iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpanList(got), fmtSpanList(want))
			}
			// The stronger property the floor exists for: no reported start may
			// precede the position it was asked to search from. runFindIter
			// resumes at end (or start+1), so a violation shows as a
			// non-increasing start.
			for i := 1; i < len(got); i++ {
				if got[i][0] <= got[i-1][0] {
					t.Errorf("match %d starts at %d, not past match %d's start %d: "+
						"the find-from floor is not being honoured",
						i, got[i][0], i-1, got[i-1][0])
				}
			}
		})
	}
}

func fmtSpanList(v [][2]int) string {
	if len(v) == 0 {
		return "(none)"
	}
	parts := make([]string, len(v))
	for i, sp := range v {
		parts[i] = fmt.Sprintf("%d-%d", sp[0], sp[1])
	}
	return strings.Join(parts, ",")
}

// compileFindLNM compiles pat with a find export under LikelyNoMatch, which is
// what gates buildSimplePrefixCheckBody's substitution (compile.go).
func compileFindLNM(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true,
		compile.CompileOptions{LikelyMode: compile.LikelyNoMatch})
	return w, err
}
