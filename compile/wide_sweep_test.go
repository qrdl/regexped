package compile

import (
	"fmt"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

// A WIDE sweep over pattern shapes, capture shapes and set configurations.
//
// The curated matrices next door name the path each case selects, which keeps
// them readable and makes a stale case obvious. This one does the opposite: it
// enumerates a large product and makes no claim about which arm each element
// reaches, because several arms turn on properties invisible in the pattern
// text. `\bERROR[a-z]*` and `\bERROR:[a-z]*` select different resume-state
// arms purely because a colon is not a word character; `AKIA[A-Z0-9]{16,20}`
// reaches the ranged literal-chain emitter only when it also carries captures.
// Both took several wrong guesses to find by hand and fell out of enumeration
// immediately.
//
// What it ASSERTS is modest and uniform: the compiler either produces a
// well-formed module or declines cleanly, for every shape, under every option
// combination and both link modes. A pattern it declines is fine — the list is
// generated, not curated — but a malformed module or a panic is not.
func sweepPatterns() []string {
	lead := []string{"", `\b`, `\B`, `(?m:^)`, `\A`, `(?m:^)\b`, `\b(?m:^)`}
	body := []string{
		"ERROR", "AB", "Q", "abc_", "KEY:", "x", "alpha|beta", "(?:ab)+",
		"a{10,20}", "[0-9]{30}", "ghp_[A-Za-z0-9]{36}", "AKIA[A-Z0-9]{16}",
		"[a-p][0-9]{4}END", "[^\n]*END", ".*END", "a+?b", "(?:a|b|c)[0-9]{4}X",
		"[a-z]+@example\\.com", "[0-9]{3}MIDDLE[0-9]{3}", "x*", "(?:[a-z]{4}[0-9]{4}){3}",
		"(?:cat|car|cab|cap)", "(?:a|bb|ccc|dddd)X", "(?:[ab]{2}[cd]{2}){8}",
		"(?:[a-c]xyz){40}", "START[^Z]{20,}END", "[0-9]{8}ghp_[^\\s]+|[a-f]{8}sec_[^\\s]+",
	}
	tail := []string{"", "[a-z]*", "[0-9]+", `\b`, "(?m:$)", `\z`, ".*"}
	var out []string
	for _, l := range lead {
		for _, b := range body {
			for _, t := range tail {
				out = append(out, l+b+t)
			}
		}
	}
	return out
}

func sweepCapturePatterns() []string {
	base := []string{
		`(a+)(b+)`, `(a+?)(b+)`, `(\w+)`, `([^,]+),`, `(a|b)*c`, `((a)(b))`,
		`(?P<x>[0-9]{2})-(?P<y>[0-9]{2})`, `(a)(b)(c)(d)(e)`, `(.*?)END`,
		`\b(\w+)\b`, `(?m:^)(\w+)(?m:$)`, `(a{2,4})b`, `((?:ab)+)c`,
		`ghp_([A-Za-z0-9]{24,32})`, `x([a-z]{24,30})`, `\A(\w+)\z`,
		`\B(\w+)\B`, `<([^>]+)>`, `(?s)(.*)`, `((a|b)+)(c|d)`,
	}
	wrap := []string{"%s", `x%s`, `%sy`, `(?:%s)+`, `(?:%s)?`, `\b%s\b`, `(?m:^)%s`}
	var out []string
	for _, b := range base {
		for _, w := range wrap {
			out = append(out, fmt.Sprintf(w, b))
		}
	}
	return out
}

func TestWideSweepSinglePattern(t *testing.T) {
	opts := []struct{ dfa, tdfa, fallback int }{
		{0, 0, 0}, {4, 1, 0}, {0, 0, 1}, {64, 8, 0},
	}
	for _, pat := range sweepPatterns() {
		if _, err := syntax.Parse(pat, syntax.Perl); err != nil {
			continue
		}
		for _, standalone := range []bool{true, false} {
			e := config.RegexEntry{Name: "p", Pattern: pat, MatchFunc: "m", FindFunc: "f"}
			w, _, err := Compile([]config.RegexEntry{e}, 65536, standalone)
			if err != nil {
				continue // a declined shape, not a failure
			}
			assertWasm(t, w, pat)
		}
	}
	for _, pat := range sweepCapturePatterns() {
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil || parsed.MaxCap() == 0 {
			continue
		}
		for _, o := range opts {
			w, _, err := CompileFile(config.BuildConfig{
				Regexps: []config.RegexEntry{{
					Name: "p", Pattern: pat,
					GroupsFunc: "g", FindFunc: "f", MatchFunc: "m",
				}},
				MaxDFAStates: o.dfa, MaxTDFARegs: o.tdfa,
				MaxFallbackStates: o.fallback,
			}, "")
			if err != nil {
				continue
			}
			assertWasm(t, w, pat)
		}
		// Both capture engines over the same pattern: the override exists so a
		// differential test can compare them, which is only meaningful if it
		// is honoured.
		for _, forced := range []EngineType{EngineTDFA, EngineBacktrack} {
			w, _, err := CompileForced(
				[]config.RegexEntry{{Name: "p", Pattern: pat, GroupsFunc: "g", FindFunc: "f"}},
				65536, true, forced)
			if err != nil {
				continue
			}
			assertWasm(t, w, pat)
		}
	}
}

func TestWideSweepSets(t *testing.T) {
	families := [][]string{
		{`a+`, `[^\n]*ERROR`, `x?y`},
		{`alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`},
		manyPatterns(24, "keyword%02d"),
		manyPatterns(70, "pat_%02d_tail"),
		sharedLiteral(40),
		sharedLiteral(80),
		diverseFirstBytes(40),
		{`\bcat\b`, `\bdog`, `\b|0*`},
		{`(?m:^)alpha`, `beta(?m:$)`, `(?m:^)gamma(?m:$)`},
		{`\Aabc`, `xyz\z`, `\Aq\z`},
		{`a*`, ``, `(?:)`, `[ab]{0,2}`},
		{`alpha`, `bravo`, `a+`, `[^\n]*END`},
		{`ghp_[A-Za-z0-9]{36}`, `AKIA[A-Z0-9]{16}`, `[a-z]+@example\.com`},
	}
	capSets := []setMatrixCaps{
		capsAll, capsFind, capsAnchored, capsScan,
		{matchAny: true}, {matchAll: true}, {scanAny: true}, {scanAll: true},
		{find: true, scanAny: true}, {matchAll: true, find: true},
	}
	for fi, fam := range families {
		for ci, caps := range capSets {
			for _, overlapping := range []bool{false, true} {
				for _, batch := range []bool{false, true} {
					for _, mfs := range []int{0, 1} {
						for _, out := range []string{"", "merged.wasm"} {
							c := setMatrixCase{
								name:     fmt.Sprintf("f%d/c%d", fi, ci),
								patterns: fam, caps: caps,
								overlapping: overlapping, batch: batch,
								maxFallbackStates: mfs,
							}
							if !caps.find && (overlapping || batch) {
								continue
							}
							CompileFile(c.build(), out)
						}
					}
				}
			}
		}
	}
}

// assertWasm checks a compiled module is at least a WASM module. Cheap, and it
// is what catches an emitter that starts producing truncated or empty output
// for a shape nobody looks at directly.
func assertWasm(t *testing.T, w []byte, what string) {
	t.Helper()
	if len(w) < 8 || string(w[:4]) != "\x00asm" {
		t.Fatalf("%s: malformed module (%d bytes)", what, len(w))
	}
}
