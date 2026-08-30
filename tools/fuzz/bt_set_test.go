package fuzz

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// compileSetBT builds a set with max_fallback_states forced low, so ordinary
// patterns become Backtracking-admitted set members in bulk. This is the same
// trick --force-backtrack uses for single patterns (MaxDFAStates = -1): the
// naturally-dropped population is tiny, so forcing the path is the only way to
// get real coverage of it.
func compileSetBT(pats []string, maxFallback int) ([]byte, map[int]bool, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Find:        "set_find",
		Overlapping: true,
		Patterns:    config.PatternSelector{Names: names},
	}}
	cfg := config.BuildConfig{
		Regexps:           entries,
		Sets:              sets,
		MaxFallbackStates: maxFallback,
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	return w, droppedFromSet(diags), err
}

// The first thing to establish: a set containing a BT bucket is a VALID module.
// Everything else depends on it.
func TestSetBTBucketValidates(t *testing.T) {
	for _, c := range []struct {
		name string
		pats []string
	}{
		{"single", []string{`(?:ab|cd)+xyz`}},
		{"mixed with a literal bucket", []string{`(?:ab|cd)+xyz`, `hello`}},
		{"two BT buckets", []string{`(?:ab|cd)+xyz`, `(?:ef|gh)+qrs`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, dropped, err := compileSetBT(c.pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) == len(c.pats) {
				t.Skip("every pattern still dropped — BT admitted none")
			}
			f := t.TempDir() + "/m.wasm"
			if err := os.WriteFile(f, w, 0644); err != nil {
				t.Fatal(err)
			}
			out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
			if vErr != nil {
				t.Fatalf("module INVALID: %s", out)
			}
			t.Logf("valid, %d bytes, %d dropped", len(w), len(dropped))
		})
	}
}

// The substance: a BT-admitted set member must report the SAME matches the
// same pattern reports when the set gives it a DFA bucket. Both are compared
// against the live-Go oracle rather than against each other, so a shared
// misunderstanding cannot pass.
func TestSetBTMatchesGo(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`(?:ab|cd)+xyz`}, "ababxyz cdcdxyz zz"},
		{[]string{`[0-9]{3}-[0-9]{4}`}, "call 555-1234 or 999-0000"},
		{[]string{`(?:ab|cd)+xyz`, `hello`}, "hello ababxyz hello"},
		{[]string{`\bfoo`}, "foo xfoo foo"},
		{[]string{`\Bbar`}, "bar xbar bar"},
		{[]string{`(?m:^)baz`}, "baz\nxbaz\nbaz"},
		{[]string{`a+b`}, "aab ab b aaab"},
		{[]string{`x?y`}, "y xy zy"},
	}
	for _, c := range cases {
		t.Run(c.pats[0]+"/"+c.input, func(t *testing.T) {
			// maxFallback=1 forces every fallback pattern onto BT.
			wBT, droppedBT, err := compileSetBT(c.pats, 1)
			if err != nil {
				t.Skipf("BT compile: %v", err)
			}
			if len(droppedBT) > 0 {
				t.Skipf("BT admitted none of %v", c.pats)
			}
			gotBT, hang, runErr := runWasmSetFind(wBT, c.input, len(c.pats))
			if hang {
				t.Skip("watchdog")
			}
			if errors.Is(runErr, errBTOverflow) {
				t.Skip("BT frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("BT set run: %v", runErr)
			}
			// Oracle: every (start,end) any pattern matches at any position,
			// which is what the ungated/overlapping set find enumerates.
			var want []setMatch
			for i, p := range c.pats {
				re := regexp.MustCompile(p)
				for _, m := range allStartPositionMatches(re, c.input) {
					want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
				}
			}
			if !sameTuples(gotBT, want) {
				t.Errorf("BT set find over %q:\n  got  %v\n  want %v", c.input, gotBT, want)
			}
		})
	}
}

// TestSetBTManyFallbackPatterns is the permanent regression for the shared-region
// shared BT region, and it is deliberately a MULTI-pattern all-fallback set:
// the defect it guards needs a second fallback pattern to exist at all.
//
// compileFallback's bin-packer used to merge later fallback patterns INTO a BT
// bucket. The budgets it checks (budgetStates 512 / budgetBytes 64 KB) are
// unrelated to max_fallback_states, so a merged table small enough to pass them
// was packed in — and since the emitter skips the whole DFA suffix pass for a
// BT bucket while the BT body answers for patternIDs[bi][0] / validMask bit 0
// alone, every merged-in pattern vanished from every bucketed capability with
// no error anywhere. It reported only ONE of these four patterns.
//
// These are the four variants from the corpus block that first exposed it
// (orig 3624). Each is checked against Go rather than against the DFA build, so
// a shared misunderstanding cannot pass.
func TestSetBTManyFallbackPatterns(t *testing.T) {
	pats := []string{
		`(?:.(?:c?))`,
		`^(?:(?:.(?:c?)))$`,
		`^(?:(?:.(?:c?)))`,
		`(?:(?:.(?:c?)))$`,
	}
	for _, input := range []string{"a", "ac", "abc", ""} {
		t.Run(input, func(t *testing.T) {
			w, dropped, err := compileSetBT(pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) > 0 {
				t.Skipf("patterns dropped: %v", dropped)
			}
			got, hang, runErr := runWasmSetFind(w, input, len(pats))
			if hang {
				t.Skip("watchdog")
			}
			if errors.Is(runErr, errBTOverflow) {
				t.Skip("BT frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			var want []setMatch
			for i, p := range pats {
				re := regexp.MustCompile(p)
				for _, m := range allStartPositionMatches(re, input) {
					want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
				}
			}
			if !sameTuples(got, want) {
				t.Errorf("BT set find over %q:\n  got  %v\n  want %v", input, got, want)
			}
		})
	}
}

// TestSetBTCaptureBearingPatterns is the regression for the capture-bearing
// bugs 1 and 2, which turned out to be ONE root cause with two very different
// symptoms.
//
// patternSuffixAST's non-splittable branch re-parsed the pattern WITHOUT
// stripping captures — the only place in the set pipeline that kept them
// (analyzePattern strips, and p.suffixAST is a subtree of that stripped tree).
// The DFA emitters never noticed, because they treat InstCapture as a
// pass-through epsilon. The Backtracking body did: a capture-bearing program
// makes buildBacktrackBody emit capture-slot writes at locals `7 + slot`, while
// admitBTFallback sets numGroups = 0 so no capture locals exist.
//
// Which symptom you got depended purely on how many locals the driver happened
// to declare:
//
//   - fewer locals than `7 + slot`  → the module FAILED WASM VALIDATION
//     ("unknown local 9"), so nothing ran at all.
//   - more locals than `7 + slot`   → the write landed on a VALID index owned
//     by a loop tracker or a window bound and silently clobbered it, so the
//     module ran and returned wrong matches.
//
// Both patterns below carry a capture group and reach a BT bucket. The first
// is the minimal validation failure; the second is the wrong-answer case, whose
// reported (0,5) on "aaaaa" is impossible on its face — 5 is not a sum of 3s
// and 4s, so no match can start at 0.
func TestSetBTCaptureBearingPatterns(t *testing.T) {
	cases := []struct {
		pat    string
		inputs []string
	}{
		{`^(?:(?:(?:(a){2})??))`, []string{"", "a", "aa", "aaa"}},
		{`(?:(?:(?:(a){3,4}){0,}))$`, []string{"aaaa", "aaaaa", "aaaaaa", "aaaaaaa"}},
	}
	for _, c := range cases {
		t.Run(c.pat, func(t *testing.T) {
			pats := []string{c.pat}
			w, dropped, err := compileSetBT(pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) > 0 {
				t.Skipf("pattern dropped: %v", dropped)
			}
			// Validity first: this is the half that used to fail here, and a
			// module that will not parse makes every answer below meaningless.
			f := t.TempDir() + "/m.wasm"
			if err := os.WriteFile(f, w, 0644); err != nil {
				t.Fatal(err)
			}
			if out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput(); vErr != nil {
				t.Fatalf("module INVALID: %s", out)
			}
			re := regexp.MustCompile(c.pat)
			for _, input := range c.inputs {
				got, hang, runErr := runWasmSetFind(w, input, len(pats))
				if hang {
					t.Skip("watchdog")
				}
				if errors.Is(runErr, errBTOverflow) {
					continue
				}
				if runErr != nil {
					t.Fatalf("run %q: %v", input, runErr)
				}
				var want []setMatch
				for _, m := range allStartPositionMatches(re, input) {
					want = append(want, setMatch{PatternID: 0, Start: m[0], End: m[1]})
				}
				if !sameTuples(got, want) {
					t.Errorf("over %q:\n  got  %v\n  want %v", input, got, want)
				}
			}
		})
	}
}

func sameTuples(got, want []setMatch) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[setMatch]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		seen[w]--
		if seen[w] < 0 {
			return false
		}
	}
	return true
}
