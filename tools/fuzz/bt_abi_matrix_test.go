package fuzz

// A Backtracking member moves a set's `_all` capabilities to the
// out_ptr/count form whenever the set has a Backtracking member, at ANY id
// space. That switch has to reach every emitter that answers an `_all`
// question, and two of them were missed on the first pass — both of which
// implement the NARROW ABI only and so cannot serve a wide capability:
//
//   - the pure union scan, used by a literal-less set
//   - phase 2 of the two-phase split, used by a mixed set
//
// Neither produced a wrong answer: they produced a MODULE THAT DOES NOT LOAD
// ("type mismatch: expected i32, found i64"), which the unit tests could not
// see because they never validated a literal-less BT set with scan_all.
//
// This matrix crosses the shapes that select each frontend and body against the
// capability combinations that select each `_all` path, and validates every
// module. It is deliberately about VALIDITY rather than answers — answers are
// the corpus's job, and a module that will not parse never gets that far.

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

func TestBTSetABIMatrixValidates(t *testing.T) {
	shapes := map[string][]string{
		// No literal anywhere: the union-scan path.
		"literal-less": {`(?:ab|cd)+`, `(?:ef|gh)+`},
		// Literal + literal-less: the two-phase split's shape.
		"mixed": {`hello[0-9]{3}`, `(?:ab|cd)+`},
		// All literal-bearing: the ordinary bucketed frontend.
		"literals": {`hello[0-9]{3}`, `world[a-z]{2}`, `foo[0-9]+`},
		// Nullable and anchored members, which reach different suffix paths.
		"nullable": {`(?:ab)*`, `(?:ab)*(?:cd)*`},
		"anchored": {`^(?:ab|cd)+$`, `(?:ef|gh)+$`},
		// Wider, to cross more than one bucket.
		"wide-mix": {`hello[0-9]{3}`, `(?:ab|cd)+`, `world[a-z]{2}`,
			`(?:ef|gh)+xyz`, `foo[0-9]+`, `[a-z]{3}bar`, `(?:ij|kl)+`, `baz[0-9]`},
	}
	caps := []struct {
		name string
		set  config.SetConfig
	}{
		{"scan-pair", config.SetConfig{ScanAny: "g_scan_any", ScanAll: "g_scan_all"}},
		{"scan-all-only", config.SetConfig{ScanAll: "g_scan_all"}},
		{"anchored-pair", config.SetConfig{MatchAny: "g_match_any", MatchAll: "g_match_all"}},
		{"find", config.SetConfig{Find: "g_find"}},
		{"find-batch", config.SetConfig{Find: "g_find", Hints: []string{"batch-find"}}},
		{"everything", config.SetConfig{
			MatchAny: "g_match_any", MatchAll: "g_match_all",
			ScanAny: "g_scan_any", ScanAll: "g_scan_all", Find: "g_find",
			Hints: []string{"batch-find"}}},
	}

	for shapeName, pats := range shapes {
		for _, c := range caps {
			for _, mf := range []int{0, 1} {
				name := fmt.Sprintf("%s/%s/mf=%d", shapeName, c.name, mf)
				t.Run(name, func(t *testing.T) {
					entries := make([]config.RegexEntry, len(pats))
					for i, p := range pats {
						entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
					}
					sc := c.set
					sc.Name = "g"
					sc.Patterns = config.PatternSelector{All: true}
					cfg := config.BuildConfig{
						Regexps: entries, MaxFallbackStates: mf,
						Sets: []config.SetConfig{sc},
					}
					w, _, diags, err := compile.CompileFileDiag(cfg, "")
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					nBT := 0
					for _, d := range diags {
						for _, b := range d.Buckets {
							if b.Type == "bt-fallback" {
								nBT++
							}
						}
					}
					// The stub side must agree with what was emitted, since a
					// disagreement there is a wrong signature rather than a
					// failed load.
					if got := compile.SetAdmitsBacktracking(sc, cfg); got != (nBT > 0) {
						t.Errorf("SetAdmitsBacktracking=%v but %d bt-fallback buckets emitted", got, nBT)
					}
					f := t.TempDir() + "/m.wasm"
					if err := os.WriteFile(f, w, 0644); err != nil {
						t.Fatal(err)
					}
					out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
					if vErr != nil {
						t.Fatalf("module INVALID (%d bt buckets): %s", nBT, out)
					}
				})
			}
		}
	}
}
