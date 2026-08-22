// Layer 2 of the fuzzer (plans/OPUS.md §N7): the four compiled paths
// FuzzCorrectness never reaches.
//
// FuzzCorrectness only ever sets FindFunc, so it exercises exactly one of the
// five compiled paths — the no-capture DFA/CompiledDFA find body. Thirty-nine
// fuzzer bugs came out of that single path; anchored match, the two capture
// backends, and the whole set pipeline had no coverage at all. §N1 (Backtracking
// silently returning "no match" once the input passes numAlts*4096 bytes) was
// found by hand-pointing a harness at the BT capture path, which is the direct
// argument for this file existing.
//
// Run one target:
//
//	go test -fuzz=FuzzMatch -fuzztime=10m
//
// or without -fuzz to replay the seed corpus as a normal test.
package fuzz

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"testing"

	"github.com/qrdl/regexped/compile"
)

// skipPattern applies the shared "is this pattern in scope at all?" gate, in the
// same order and for the same reasons as FuzzCorrectness. Returns a non-empty
// reason when the case should be skipped.
//
// Kept as one helper so all four Layer-2 targets stay consistent: a skip rule
// that exists in one target but not another produces failures that look like
// engine bugs but are really harness gaps.
func skipPattern(pat, input string) string {
	if hasUnsupportedUnicode(input) {
		return "input has non-ASCII: the byte-oriented engines are out of scope for Unicode (CLAUDE.md)"
	}
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return "not a regexp"
	}
	if prog, err := syntax.Compile(parsed.Simplify()); err == nil && len(prog.Inst) > maxNFAInsts() {
		return "NFA too large for the fuzz worker's hang deadline (see maxNFAInsts)"
	}
	// The compiler's own predicate, not a raw-string scan: escapes like \x80 are
	// pure ASCII text but denote a non-ASCII codepoint once parsed.
	if needsUnicode, err := compile.NeedsUnicodeSupport(pat); err != nil || needsUnicode {
		return "needs Unicode support"
	}
	if _, err := regexp.Compile(pat); err != nil {
		return "Go stdlib rejects it too — no oracle"
	}
	return ""
}

// isResourceCeiling reports whether a compile error is a legitimate, documented
// resource ceiling rather than a bug. These are surfaced as typed errors on
// purpose (contrast §N1, whose *runtime* ceiling is silent).
func isResourceCeiling(err error) bool {
	return errors.Is(err, compile.ErrBTProgramTooLarge) ||
		errors.Is(err, compile.ErrBTStackTooLarge) ||
		errors.Is(err, compile.ErrBTLoopCountTooLarge) ||
		errors.Is(err, compile.ErrBTEmptyBodyLoopChainTooLarge)
}

// hasCaptures reports whether pat contains at least one capture group.
//
// A groups export is only emitted for patterns with MaxCap() > 0: setting
// groups_func on a capture-less pattern yields a module with no groups export at
// all. tools/re2test gates on exactly this (`parsed.MaxCap() > 0`) before
// setting GroupsFunc, so the Layer-2 groups targets must too — otherwise every
// capture-less seed fails with "module missing groups export", which is a
// harness gap wearing an engine bug's clothes.
func hasCaptures(pat string) bool {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	return err == nil && parsed.MaxCap() > 0
}

// ---------------------------------------------------------------------------
// Path 1: anchored match (match_func) — DFA / CompiledDFA / lit-chain bodies.

// FuzzMatch checks the match export against a full-consumption oracle.
//
// The contract was established empirically, not from the docs: match_func
// matches only when the pattern consumes the ENTIRE input, and returns
// len(input) when it does. Probed cases that pin this down — `a` vs "ab" is NO
// match, `a+` vs "aab" is NO match, `abc` vs "abcdef" is NO match, `.*` vs "xyz"
// returns 3. So the oracle is `\A(?:pat)\z`, NOT FindStringIndex.
//
// Note this is also why tools/re2test compares match results against col0 (the
// RE2 full-match column) and skips col0 entirely for capturing patterns.
func FuzzMatch(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}

		wasmBytes, compErr := compileMatch(pat)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("compile error on a pattern Go stdlib accepts: pat=%q: %v", pat, compErr)
		}

		// Full-consumption oracle. Wrapping in \A(?:...)\z is safe for any
		// pattern Go already accepted, and (?: ) keeps alternation from
		// re-associating across the anchors.
		full, err := regexp.Compile(`\A(?:` + pat + `)\z`)
		if err != nil {
			t.Skip("pattern cannot be anchor-wrapped for the oracle")
		}
		want := full.MatchString(input)

		end, ok, hang, runErr := runWasmMatch(wasmBytes, input)
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pat=%q input=%q: %v", pat, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog timeout after %s): pat=%q input=%q", wasmCallTimeout, pat, input)
		}
		if ok != want {
			t.Fatalf("match mismatch: pat=%q input=%q expected match=%v got match=%v (end=%d)",
				pat, input, want, ok, end)
		}
		// On a match the returned end must be the full input length — that IS
		// the full-consumption contract, and a wrong end would otherwise pass
		// the boolean check above unnoticed.
		if ok && end != len(input) {
			t.Fatalf("match end mismatch: pat=%q input=%q full-consumption implies end=%d, got %d",
				pat, input, len(input), end)
		}
	})
}

// ---------------------------------------------------------------------------
// Path 2/3: captures (groups_func) — TDFA when eligible, Backtracking otherwise.

// FuzzGroups checks the groups export against Go's FindStringSubmatchIndex.
//
// groups_func is NON-anchored despite CLAUDE.md describing it as "anchored +
// captures" — verified empirically ((a)(b) vs "xxab" returns [2 4 2 3 3 4], and
// re2test's col0 handling filters on slots[0] != 0 for exactly this reason). So
// the oracle is plain FindStringSubmatchIndex with no anchoring.
func FuzzGroups(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}
		if !hasCaptures(pat) {
			t.Skip("no capture groups: no groups export is emitted for such patterns")
		}
		ref := regexp.MustCompile(pat)
		numGroups := ref.NumSubexp() + 1
		if numGroups > maxFuzzGroups {
			t.Skip("too many capture groups for the harness slot buffer")
		}

		wasmBytes, compErr := compileGroups(pat)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("compile error on a pattern Go stdlib accepts: pat=%q: %v", pat, compErr)
		}

		want := ref.FindStringSubmatchIndex(input)
		got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, input, numGroups)
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pat=%q input=%q: %v", pat, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog timeout after %s): pat=%q input=%q", wasmCallTimeout, pat, input)
		}
		if msg := compareSlots(want, got, ok); msg != "" {
			eng, _ := compile.SelectEngine(pat, compile.CompileOptions{})
			t.Fatalf("groups mismatch (%s): pat=%q input=%q engine=%v\n  expected %v\n  got      %v (ok=%v)",
				msg, pat, input, eng, want, got, ok)
		}
	})
}

// FuzzGroupsBothEngines runs the same pattern through TDFA and Backtracking and
// checks both against the oracle.
//
// Without this, the selector decides which capture backend ever gets fuzzed for
// a given pattern shape, so whichever engine it does not pick stays dark. It
// also cross-checks the two engines against each other, which catches the case
// where both are self-consistent but disagree — the shape CLAUDE.md's
// "load-bearing gates" section warns about when moving patterns between
// backends.
func FuzzGroupsBothEngines(f *testing.F) {
	for _, c := range seedCorpus(seedFile) {
		f.Add(c.pattern, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		if reason := skipPattern(pat, input); reason != "" {
			t.Skip(reason)
		}
		if !hasCaptures(pat) {
			t.Skip("no capture groups: no groups export is emitted for such patterns")
		}
		ref := regexp.MustCompile(pat)
		numGroups := ref.NumSubexp() + 1
		if numGroups > maxFuzzGroups {
			t.Skip("too many capture groups for the harness slot buffer")
		}
		want := ref.FindStringSubmatchIndex(input)

		type result struct {
			slots []int
			ok    bool
			ran   bool
		}
		results := map[compile.EngineType]result{}

		// Which engines is it legitimate to run this pattern on?
		//
		// CompileForced bypasses selectBestEngine's eligibility gate, and TDFA
		// is documented as INVALID for whole pattern families — non-greedy
		// quantifiers, line anchors, word boundaries, ambiguous captures
		// (CLAUDE.md, compile/selector.go). Forcing TDFA on `(?m:(foo)$)` and
		// then calling the wrong answer a bug is garbage-in: the compiler never
		// claimed TDFA handles it. So TDFA is only exercised when the selector
		// itself would pick it; Backtracking is the general fallback and is
		// always fair game.
		selected, _ := compile.SelectEngine(pat, compile.CompileOptions{})
		engines := []compile.EngineType{compile.EngineBacktrack}
		if selected == compile.EngineTDFA {
			engines = append(engines, compile.EngineTDFA)
		}

		for _, eng := range engines {
			wasmBytes, compErr := compileGroupsForced(pat, eng)
			if compErr != nil {
				// A forced engine can still legitimately refuse (BT resource
				// ceilings). Not a bug — just no coverage from it here.
				continue
			}
			got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, input, numGroups)
			if errors.Is(runErr, errBTOverflow) {
				// One engine can hit its frame ceiling while the other
				// answers fine, so the cross-engine comparison below is not
				// meaningful for this input — skip the whole case, not just
				// this engine.
				t.Skip("backtracking frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("wasm error (engine=%v): pat=%q input=%q: %v", eng, pat, input, runErr)
			}
			if hang {
				t.Fatalf("hang (engine=%v, watchdog %s): pat=%q input=%q", eng, wasmCallTimeout, pat, input)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Fatalf("groups mismatch (%s) on engine=%v: pat=%q input=%q\n  expected %v\n  got      %v (ok=%v)",
					msg, eng, pat, input, want, got, ok)
			}
			results[eng] = result{slots: got, ok: ok, ran: true}
		}

		// Cross-engine agreement, when both actually compiled.
		tr, tok := results[compile.EngineTDFA]
		br, bok := results[compile.EngineBacktrack]
		if tok && bok && tr.ran && br.ran {
			if tr.ok != br.ok || !slotsEqual(tr.slots, br.slots) {
				t.Fatalf("TDFA and Backtracking disagree: pat=%q input=%q\n  TDFA %v (ok=%v)\n  BT   %v (ok=%v)",
					pat, input, tr.slots, tr.ok, br.slots, br.ok)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Path 4: sets (find_all).

// FuzzSet checks a two-pattern `overlapping: true` set's find against
// per-start-position anchored matching.
//
// Comparison is per pattern and by MULTISET, not by sequence: plans/SETS.md
// §3.10 leaves the order of the tuples within one call unspecified. Patterns
// carrying capture groups are skipped: the set pipeline drops capture-bearing
// patterns (SetDiag.CaptureBearingDropped), so including one would produce an
// oracle mismatch that is expected behaviour rather than a bug.
func FuzzSet(f *testing.F) {
	// Seed with pattern pairs drawn from consecutive corpus entries, so the
	// seeds contain patterns that actually share literals and inputs.
	corpus := seedCorpus(seedFile)
	for i := 0; i+1 < len(corpus) && i < 400; i += 2 {
		f.Add(corpus[i].pattern, corpus[i+1].pattern, corpus[i].input)
	}
	f.Add(`abc`, `abd`, "xxabcabd")
	f.Add(`a+`, `b+`, "aabbaa")
	// plans/SETS.md §9.4 first-position inversions: literal-candidate order is
	// not match-start order once prefixes vary in length.
	f.Add(`bX`, `.+Y`, "abXY")         // unbounded prefix recovers an earlier start
	f.Add(`(?:ab)+Y`, `cX`, "abcXabY") // variable-length prefix, state-dependent
	f.Add(`xxxFOO`, `FOO`, "yxxxFOOy") // fixed-vs-fixed prefix skew (non-zero drain)
	f.Add(`a.{3}Z`, `Z`, "qaqqqZ")     // fixed prefix 4 vs trivial

	f.Fuzz(func(t *testing.T, pat1, pat2, input string) {
		if len(input) >= pathsInputCap {
			t.Skip()
		}
		// The whole-input oracle below counts RUNES in its `.{p}` prefix, so
		// it is only exact on single-byte-rune input (plans/SETS.md §9.6).
		for i := 0; i < len(input); i++ {
			if input[i] >= 0x80 {
				t.Skip("non-ASCII input: the rune-counted whole-input oracle would misalign")
			}
		}
		pats := []string{pat1, pat2}
		refs := make([]*regexp.Regexp, len(pats))
		for i, p := range pats {
			if reason := skipPattern(p, input); reason != "" {
				t.Skip(reason)
			}
			re := regexp.MustCompile(p)
			if re.NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
			refs[i] = re
		}

		wasmBytes, compErr := compileSet(pats)
		if compErr != nil {
			if isResourceCeiling(compErr) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("set compile error on patterns Go stdlib accepts: %q + %q: %v", pat1, pat2, compErr)
		}

		got, hang, runErr := runWasmSetFind(wasmBytes, input, len(pats))
		if errors.Is(runErr, errSetOutputTruncated) {
			t.Fatalf("set find overflowed a patterns_in_set-sized buffer: pats=%q,%q input=%q: %v",
				pat1, pat2, input, runErr)
		}
		if errors.Is(runErr, errBTOverflow) {
			t.Skip("backtracking frame budget exhausted")
		}
		if runErr != nil {
			t.Fatalf("wasm error: pats=%q,%q input=%q: %v", pat1, pat2, input, runErr)
		}
		if hang {
			t.Fatalf("hang (watchdog %s): pats=%q,%q input=%q", wasmCallTimeout, pat1, pat2, input)
		}

		byID := map[int][][2]int{}
		for _, m := range got {
			byID[m.PatternID] = append(byID[m.PatternID], [2]int{m.Start, m.End})
		}
		for i, re := range refs {
			want := allStartPositionMatches(re, input)
			gotI := byID[i]
			sortSpans(want)
			sortSpans(gotI)
			if len(want) != len(gotI) {
				t.Fatalf("set pattern[%d]=%q match count: input=%q expected %d %v, got %d %v",
					i, pats[i], input, len(want), want, len(gotI), gotI)
			}
			for k := range want {
				if want[k][0] != gotI[k][0] || want[k][1] != gotI[k][1] {
					t.Fatalf("set pattern[%d]=%q match %d: input=%q expected %v, got %v",
						i, pats[i], k, input, want[k], gotI[k])
				}
			}
		}
	})
}

// sortSpans orders spans by (start, end) so two multisets can be compared
// element-wise. plans/SETS.md §3.10 leaves within-call tuple order
// unspecified, so the comparison must be multiset-based.
func sortSpans(v [][2]int) {
	sort.Slice(v, func(i, j int) bool {
		if v[i][0] != v[j][0] {
			return v[i][0] < v[j][0]
		}
		return v[i][1] < v[j][1]
	})
}

// allStartPositionMatches is the oracle for an `overlapping: true` set find.
//
// It reports, for every start position, the match beginning exactly at that
// position — so its results OVERLAP, where Go's FindAll skips forward past each
// match. Measured difference, which is how this was caught:
//
//	a{2,5}? vs "aaaaaa"  Go FindAll: [0-2] [2-4] [4-6]
//	                     find:       [0-2] [1-3] [2-4] [3-5] [4-6]
//	.*?end  vs "xyzend"  Go FindAll: [0-6]
//	                     find:       [0-6] [1-6] [2-6] [3-6]
//	a*      vs "a"       Go FindAll: [0-1]
//	                     find:       [0-1] [1-1]
//
// tools/re2test compares against the corpus's col4 column rather than computing
// this, so it never had to state the rule explicitly.
//
// Implemented with the §9.6 whole-input technique: `\A(?s:.{p})(?:pat)` over
// the WHOLE input hands `pat` position p with its real left context, so `\b`,
// `\B` and `(?m:^)` judge actual neighbours. The slice technique it replaces
// (`\A(?:pat)` over input[p:]) judged them against a slice boundary instead
// and forced every context-sensitive pattern to be skipped — which is exactly
// how plans/FABLE.md B40 and B43 stayed invisible to this target.
//
// `.{p}` counts runes, so callers must restrict the corpus to ASCII.
//
// The pattern is re-serialised through regexp/syntax before being embedded:
// the raw source may contain `\Q`, which quotes everything after it and would
// swallow the closing paren of the `(?:...)` wrapper, silently building a
// DIFFERENT regexp and blaming the engine for the difference.
func allStartPositionMatches(re *regexp.Regexp, input string) [][2]int {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		panic("oracle: pattern Go already accepted failed to re-parse: " + err.Error())
	}
	body := parsed.String()
	var out [][2]int
	for p := 0; p <= len(input); p++ {
		anchored, err := regexp.Compile(`\A` + dotPrefix(p) + `(?:` + body + `)`)
		if err != nil {
			// Never return "no matches" here: a broken oracle expression
			// would read as "the engine over-reported" and blame the
			// compiler for a harness bug. This is exactly how the
			// maxRepeat ceiling below first showed up.
			panic("oracle: could not build the position-" + strconv.Itoa(p) + " probe: " + err.Error())
		}
		if m := anchored.FindStringIndex(input); m != nil {
			out = append(out, [2]int{p, m[1]})
		}
	}
	return out
}

// dotPrefix builds a regexp matching exactly p bytes of anything.
//
// The obvious `(?s:.{p})` hits regexp/syntax's maxRepeat ceiling of 1000 and
// fails to compile for any longer input — silently, if the caller treats a
// compile error as "no matches".
//
// NESTING a repeat inside another repeat does NOT lift that ceiling, contrary
// to what this comment claimed until 2026-08-21: Go rejects on the PRODUCT of
// nested counts, so `(?:.{1000}){2}` is an error just as `.{2000}` is, and the
// oracle panicked on every input of 2000 bytes or more while `pathsInputCap`
// admits 128 KB. Found by FuzzSet on a 3,282-byte input (plans/SETS.md §18.7).
//
// CONCATENATION has no such limit — each term is independently under the
// ceiling — so p/1000 copies of `.{1000}` plus a remainder term is correct for
// any length the fuzzer can produce, at the cost of a longer pattern string.
func dotPrefix(p int) string {
	q, r := p/1000, p%1000
	out := "(?s:"
	for i := 0; i < q; i++ {
		out += ".{1000}"
	}
	if r > 0 {
		out += ".{" + strconv.Itoa(r) + "}"
	}
	return out + ")"
}

// hasContextAssertion reports whether pat contains an assertion whose meaning
// depends on text outside the matched span: ^ $ \A \z \b \B, including the
// multiline forms. allStartPositionMatches evaluates each start position against
// a SLICE of the input, so such an assertion would be judged against the slice
// boundary instead of the real one and the oracle would be wrong — a harness bug
// masquerading as an engine bug.
func hasContextAssertion(pat string) bool {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return true // unparseable: treat as unsafe
	}
	var walk func(*syntax.Regexp) bool
	walk = func(re *syntax.Regexp) bool {
		switch re.Op {
		case syntax.OpBeginLine, syntax.OpEndLine,
			syntax.OpBeginText, syntax.OpEndText,
			syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			return true
		}
		for _, sub := range re.Sub {
			if walk(sub) {
				return true
			}
		}
		return false
	}
	return walk(parsed)
}

// ---------------------------------------------------------------------------
// Slot comparison helpers.

// compareSlots compares a Go FindStringSubmatchIndex result against the WASM
// slot buffer. Returns "" when they agree, else a short reason.
func compareSlots(want []int, got []int, ok bool) string {
	if want == nil {
		if ok {
			return "expected no match"
		}
		return ""
	}
	if !ok {
		return "expected a match, got none"
	}
	if len(got) < len(want) {
		return "fewer slots than groups"
	}
	for i := range want {
		if want[i] != got[i] {
			return "slot value differs"
		}
	}
	return ""
}

func slotsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
