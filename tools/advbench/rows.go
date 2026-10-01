package main

import (
	"fmt"
	"strings"
)

// maxLinearRatio is the largest fuel ratio per input doubling a LINEAR row may
// show at its last doubling. A linear drive measures ×2.0 plus whatever its
// fixed costs shed (so a little under 2 at small sizes); a quadratic one ×4.
const maxLinearRatio = 2.5

type expectation int

const (
	// linear: the drive must stay linear; a last ratio over maxLinearRatio
	// fails the suite.
	linear expectation = iota
	// quadratic: a known open drive. Reported with its ratio; turning linear
	// is printed as a note (flip the row), never a failure.
	quadratic
	// report: memory or correctness evidence, printed only.
	report
)

// row is one entry of the suite.
type row struct {
	Name   string
	Expect expectation
	Why    string // what the row demonstrates, in one line
	spec
}

func sz(n ...int) []int { return n }

// rows: every adversarial shape found so far, and the drives measured linear
// that a change to a shared emitter must not make quadratic.
//
// Sizes are chosen so a QUADRATIC row stays affordable (a few G fuel at its
// largest size); a row that turns linear keeps the same sizes.
var rows = []row{
	// ---- Linear today: the bodies and rules that already bound a drive.
	{Name: "linear/find a*b", Expect: linear, Why: "failed attempts bounded by the shape detectors",
		spec: spec{Pattern: `a*b`, Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: `linear/find \ba*b`, Expect: linear, Why: "the same with a word-boundary context bit",
		spec: spec{Pattern: `\ba*b`, Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/find (?m:^)a*b", Expect: linear, Why: "the same with a line anchor",
		spec: spec{Pattern: `(?m:^)a*b`, Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/find foo[^x]*bar", Expect: linear, Why: "a literal fences every walk",
		spec: spec{Pattern: `foo[^x]*bar`, Fn: "find", Gen: "rep:foo", Sizes: sz(4096, 8192, 16384)}},
	{Name: `linear/find [a-z]+foo\d`, Expect: linear, Why: "the switch hands a failing leading repeat to the start-anywhere find",
		spec: spec{Pattern: `[a-z]+foo\d`, Fn: "find", Gen: "rep:afoo", Sizes: sz(4096, 8192, 16384)}},
	{Name: `linear/find [^,]+@[^,]+\.com`, Expect: linear, Why: "the switch on a literal-anchored shape",
		spec: spec{Pattern: `[^,]+@[^,]+\.com`, Fn: "find", Gen: "rep:a@a", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/find a*?b no match", Expect: linear, Why: "a non-greedy repeat that never matches",
		spec: spec{Pattern: `a*?b`, Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/set find {a*b, a}", Expect: linear, Why: "per-pattern gates retire a pattern below its last end",
		spec: spec{Config: "cfg/g108.yaml", Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: `linear/set find {foo\w+bar, foo}`, Expect: linear, Why: "the literal clause keeps a shared-literal bucket linear",
		spec: spec{Config: "cfg/set108lit2.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/set find sparse 35 sharing foo", Expect: linear, Why: "a sparse bucket whose members all die",
		spec: spec{Config: "cfg/sparse.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(4096, 8192, 16384)}},
	{Name: `linear/set overlapping {foo\w+, bar\w+} cache`, Expect: linear, Why: "the overlapping answer cache",
		spec: spec{Config: "cfg/ovl.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/set overlapping 30 unbounded cache", Expect: linear, Why: "the whole-set sweep at 30 members",
		spec: spec{Config: "cfg/unb30.yaml", Fn: "find", Gen: "rep:a|suf:0", Sizes: sz(1024, 2048, 4096)}},
	{Name: "linear/set batch cap 1", Expect: linear, Why: "the batch cursor resumes inside a position",
		spec: spec{Config: "cfg/batch.yaml", Fn: "batch", Cap: 1, Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/set find Backtracking member (aa|a)*bx", Expect: linear, Why: "a Backtracking member whose branch dies early",
		spec: spec{Config: "cfg/setbt2.yaml", Fn: "find", Gen: "rep:a|suf:b", Sizes: sz(4096, 8192, 16384)}},
	{Name: "linear/set find Backtracking member under max_fallback_states 64", Expect: linear, Why: "the same, forced onto Backtracking",
		spec: spec{Config: "cfg/setbt3.yaml", Fn: "find", Gen: "rep:a", Sizes: sz(4096, 8192, 16384)}},

	// ---- Overrun: a call reads past the match it reports, the next call
	// reads the same bytes again. Linear through the per-search notes.
	{Name: "overrun/find a*b|a", Expect: linear, Why: "a lower-priority short ending after a long failed walk",
		spec: spec{Pattern: `a*b|a`, Fn: "find", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/find (?:a*b)?", Expect: linear, Why: "an empty match at every byte after the walk",
		spec: spec{Pattern: `(?:a*b)?`, Fn: "find", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/find (?:a*b)*", Expect: linear, Why: "the same with a star",
		spec: spec{Pattern: `(?:a*b)*`, Fn: "find", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/groups TDFA (x)(?:[a-z]*y)?", Expect: linear, Why: "the find step of a TDFA groups drive",
		spec: spec{Pattern: `(x)(?:[a-z]*y)?`, Fn: "groups", Gen: "rep:x", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/groups_batch TDFA (x)(?:[a-z]*y)?", Expect: linear, Why: "the same through the batch entry",
		spec: spec{Pattern: `(x)(?:[a-z]*y)?`, Fn: "batchgroups", NGroups: 2, Gen: "rep:x", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/groups Backtracking (a*)b|(a)", Expect: linear, Why: "the find step of a Backtracking groups drive",
		spec: spec{Pattern: `(a*)b|(a)`, Fn: "groups", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overrun/groups Backtracking ((?:a*)*c)|(a)", Expect: linear, Why: "the same with a nested star",
		spec: spec{Pattern: `((?:a*)*c)|(a)`, Fn: "groups", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},
	{Name: `overrun/set find {foo\w+bar|foo}`, Expect: linear, Why: "a set member that keeps matching cannot be retired",
		spec: spec{Config: "cfg/set108lit.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find comment-or-word`, Expect: linear, Why: "an earlier start fails far away, a short match follows",
		spec: spec{Pattern: `/\*[\s\S]*?\*/|\w+`, Fn: "find", Gen: "rep:/*a", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find tag-or-entity`, Expect: linear, Why: "the same through the general body",
		spec: spec{Pattern: `<[^>]*>|&[a-z]+;`, Fn: "find", Gen: "rep:<&lt;", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find url-guard xss`, Expect: linear, Why: "a shipped example pattern",
		spec: spec{Pattern: `(?i)(?:<\s*(?:script|iframe|object|embed)\b[^>]*>|\bon\w{1,30}\s*=|(?:javascript|vbscript)\s*:|eval\s*\()`,
			Fn: "find", Gen: "rep:<embed on1=", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find url-guard shell_injection`, Expect: linear, Why: "a shipped example pattern",
		spec: spec{Pattern: "(?:;\\s*(?:wget|curl|bash|sh\\b|cmd\\.exe)|`[^`]+`|\\$\\([^)]+\\))",
			Fn: "find", Gen: "rep:$(;sh", Sizes: sz(4096, 8192, 16384)}},
	{Name: `overrun/find literal-anchored \w+abc(?:[^;]*;)?`, Expect: linear, Why: "the literal-anchored body's forward walk reads past its match",
		spec: spec{Pattern: `\w+abc(?:[^;]*;)?`, Fn: "find", Gen: "rep:xabc ", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find literal-anchored \w+abc(?:[^;]*;|\d)`, Expect: linear, Why: "a candidate's failed forward walk, then a short match",
		spec: spec{Pattern: `\w+abc(?:[^;]*;|\d)`, Fn: "find", Gen: "rep:xabc xabc1 ", Sizes: sz(4096, 8192, 16384)}},
	{Name: `overrun/find alternation-anchored [a-m]abc(?:[^;]*;)?|[n-z]ghi`, Expect: linear, Why: "a branch's forward verify reads past its match",
		spec: spec{Pattern: `[a-m]abc(?:[^;]*;)?|[n-z]ghi`, Fn: "find", Gen: "rep:babc ", Sizes: sz(4096, 8192, 16384)}},
	{Name: `earlier-start/find alternation-anchored [a-m]abc[^;]*;|[n-z]ghi`, Expect: linear, Why: "a branch's failed forward verify, then another branch's short match",
		spec: spec{Pattern: `[a-m]abc[^;]*;|[n-z]ghi`, Fn: "find", Gen: "rep:babc zghi ", Sizes: sz(4096, 8192, 16384)}},
	{Name: `overrun/find start-anywhere \w+(?:;[^!]*!)?`, Expect: linear, Why: "the start-anywhere forward pass reads past its match",
		spec: spec{Pattern: `\w+(?:;[^!]*!)?`, Fn: "find", Gen: "rep:a;", Sizes: sz(4096, 8192, 16384)}},
	{Name: `greedy-optional/find [a-z]+@(?:[a-z@]*X)?`, Expect: linear, Why: "a greedy optional group walks past the match",
		spec: spec{Pattern: `[a-z]+@(?:[a-z@]*X)?`, Fn: "find", Gen: "rep:a@", Sizes: sz(4096, 8192, 16384)}},
	{Name: `greedy-optional/find \w+(?:\([^)]*\))?`, Expect: linear, Why: "the same, start-anywhere find",
		spec: spec{Pattern: `\w+(?:\([^)]*\))?`, Fn: "find", Gen: "rep:a(", Sizes: sz(4096, 8192, 16384)}},

	// ---- Backtracking: the work budget lasts the SEARCH (the per-search
	// block), so a drive that would burn it on every call burns it once.
	{Name: "bt-budget/find (?:a|b)*a(?:a|b){12}c|a", Expect: linear, Why: "the full budget, then the fallback, on every call",
		spec: spec{Pattern: `(?:a|b)*a(?:a|b){12}c|a`, Fn: "find", Gen: "rep:a", Sizes: sz(512, 1024, 2048)}},
	{Name: "bt-budget/groups ((?:a|b)*a(?:a|b){12}c)|(a)", Expect: linear, Why: "the same through groups",
		spec: spec{Pattern: `((?:a|b)*a(?:a|b){12}c)|(a)`, Fn: "groups", Gen: "rep:a", Sizes: sz(512, 1024, 2048)}},
	// Larger than the row's first sizes (32, 64, 128): the fallback's
	// per-call cost is constant but large, and below ~256 bytes the drive is
	// still approaching it (×2.76, ×2.20, ×2.09 from 64; ×4.7 with no block).
	// A zero-width cycle: the fallback alone serves every call, so nothing
	// but the stub-facing tail call can trip the search and get its memo.
	{Name: `bt-budget/find zero-width cycle (?:0*\b|)*0`, Expect: linear, Why: "the fallback alone, a fresh memo every call",
		spec: spec{Pattern: `(?:0*\b|)*0`, Fn: "find", Gen: "rep:0", Sizes: sz(1024, 2048, 4096)}},
	{Name: `bt-budget/groups zero-width cycle (0*\b|)*0`, Expect: linear, Why: "the same through groups",
		spec: spec{Pattern: `(0*\b|)*0`, Fn: "groups", Gen: "rep:0", Sizes: sz(1024, 2048, 4096)}},
	{Name: "bt-budget/set find member (?:aa|a){0,40}b|a", Expect: linear, Why: "a set member's budget lasts one host call",
		spec: spec{Config: "cfg/setbt4.yaml", Fn: "find", Gen: "rep:a", Sizes: sz(256, 512, 1024)}},

	// ---- Overlapping sets the answer cache does not serve.
	{Name: "overlap/40 unbounded members", Expect: quadratic, Why: "over the whole-set sweep's member limit",
		spec: spec{Config: "cfg/unb40.yaml", Fn: "find", Gen: "rep:a|suf:0", Sizes: sz(256, 512, 1024)}},
	{Name: "overlap/35 members sharing foo", Expect: quadratic, Why: "the same through a literal bucket",
		spec: spec{Config: "cfg/ovl35.yaml", Fn: "find", Gen: "rep:foo|suf:0", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overlap/cache declined", Expect: quadratic, Why: "the host offers no cache",
		spec: spec{Config: "cfg/ovl.yaml", Fn: "find", NoCache: true, Gen: "rep:foo", Sizes: sz(2048, 4096, 8192)}},
	{Name: "overlap/scan pair forces a split", Expect: quadratic, Why: "a split compile gets no whole-set sweep",
		spec: spec{Config: "cfg/ovlsplit.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(2048, 4096, 8192)}},

	// ---- Set walks a retired or recorded sibling keeps alive.
	{Name: "shared-walk/set find {[A-Z], [A-Za-z]+}", Expect: linear, Why: "a gated-out sibling keeps a fallback bucket's walk alive",
		spec: spec{Config: "cfg/merged1.yaml", Fn: "find", Gen: "rep:A", Sizes: sz(2048, 4096, 8192)}},
	{Name: "shared-walk/set find {[0-9]+, [0-9][a-z]}", Expect: linear, Why: "the same, quadratic in ONE call",
		spec: spec{Config: "cfg/merged2.yaml", Fn: "find", Gen: "rep:0|suf:0a", Sizes: sz(2048, 4096, 8192)}},
	{Name: "shared-walk/set find sparse 33", Expect: linear, Why: "a sparse bucket has no exit",
		spec: spec{Config: "cfg/sparse3.yaml", Fn: "find", Gen: "rep:foo", Sizes: sz(2048, 4096, 8192)}},
	{Name: "shared-walk/set scan_all sparse 33", Expect: linear, Why: "the same through scan_all, one call",
		spec: spec{Config: "cfg/sparse3.yaml", Fn: "scan_all", Gen: "rep:foo", Sizes: sz(2048, 4096, 8192)}},
	{Name: `shared-walk/set scan_all {[a-z]+, \b[a-z][0-9]}`, Expect: linear, Why: "a recorded member keeps the probe walking, one call",
		spec: spec{Config: "cfg/scanwb.yaml", Fn: "scan_all", Gen: "rep:a", Sizes: sz(2048, 4096, 8192)}},

	// ---- Evidence rows: printed, never judged.
	{Name: "report/groups_batch anchored ^([a-z]+)=([0-9]+)", Expect: report, Why: "Go reports ONE record here; more is the anchored-resume bug",
		spec: spec{Pattern: `^([a-z]+)=([0-9]+)`, Fn: "batchgroups", NGroups: 3, Gen: "rep:a=1", Sizes: sz(300)}},
	{Name: `report/memory fallback memo ^(\w*|)*c`, Expect: report, Why: "pages the Backtracking fallback grows with the input",
		spec: spec{Pattern: `^(\w*|)*c`, Fn: "groups", Gen: "rep:w", Sizes: sz(1<<20, 4<<20)}},
	{Name: "report/memory load-time reservation, 1,000 alternations", Expect: report, Why: "pages a Backtracking find reserves at load",
		spec: spec{Pattern: `(?:ab|cd){1000}z`, Fn: "find", MaxDFA: 16, Gen: "rep:ab", Sizes: sz(64)}},
}

func (e expectation) String() string {
	switch e {
	case linear:
		return "linear"
	case quadratic:
		return "quadratic"
	}
	return "report"
}

// runSuite runs the rows and returns the process exit status.
func runSuite() int {
	if *list {
		for _, r := range rows {
			fmt.Printf("%-10s %-60s %s\n", r.Expect, r.Name, r.Why)
		}
		return 0
	}
	failed, ran := 0, 0
	var notes []string
	for _, r := range rows {
		if *only != "" && !strings.Contains(r.Name, *only) {
			continue
		}
		ran++
		res, _, err := runSpec(r.spec)
		if err != nil {
			fmt.Printf("FAIL  %-58s %v\n", r.Name, err)
			failed++
			continue
		}
		var ratios []string
		last := 0.0
		errS := ""
		for i, s := range res {
			if i > 0 && res[i-1].Fuel > 0 {
				last = float64(s.Fuel) / float64(res[i-1].Fuel)
				ratios = append(ratios, fmt.Sprintf("x%.2f", last))
			}
			if s.Err != "" {
				errS = s.Err
			}
		}
		// The block must never change an answer: drive the first size again
		// without one and compare every reported position.
		if nb := r.spec; !nb.NoBlock && res[0].Err == "" {
			nb.NoBlock = true
			nb.Sizes = nb.Sizes[:1]
			if ref, _, err := runSpec(nb); err == nil && ref[0].Err == "" &&
				(ref[0].Sum != res[0].Sum || ref[0].Matches != res[0].Matches) {
				errS += fmt.Sprintf(" MISMATCH with no block: %d matches / sum %016x, block %d / %016x",
					ref[0].Matches, ref[0].Sum, res[0].Matches, res[0].Sum)
				if r.Expect != linear {
					failed++
				}
			}
		}
		end := res[len(res)-1]
		detail := fmt.Sprintf("n=%d %.1f fuel/byte %s calls=%d matches=%d pages=%d(+%d)%s",
			end.N, end.fuelPerByte(), strings.Join(ratios, " "), end.Calls, end.Matches,
			end.Pages, end.Pages-end.StartPages, errS)
		verdict := "info"
		switch r.Expect {
		case linear:
			verdict = "ok"
			if errS != "" || len(res) < 2 || last > maxLinearRatio {
				verdict = "FAIL"
				failed++
			}
		case quadratic:
			verdict = "open"
			if errS == "" && len(res) >= 2 && last <= maxLinearRatio {
				verdict = "LINEAR"
				notes = append(notes, r.Name)
			}
		}
		fmt.Printf("%-5s %-58s %s\n", verdict, r.Name, detail)
	}
	for _, n := range notes {
		fmt.Printf("note: %q is expected quadratic but measured linear — flip the row to linear\n", n)
	}
	fmt.Printf("%d rows, %d failed\n", ran, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
