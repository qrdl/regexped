package fuzz

import (
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine's BitState memo is a bitset of
// N*(len+1) bits zeroed by one memory.fill at the head of every attempt, but
// the region reserved for it is sized from a COMPILE-TIME ceiling
// (memoBudget*8/N - 1, compile.go's memoMaxLen). Until 2026-09-05 that ceiling
// was computed and never emitted: the fill's length came straight from the
// runtime `len` with nothing clamping it.
//
// The memo is the LAST reservation in a module that declares exactly
// PageAlign(tableEnd) pages, so the overrun has no slack to land in. What it
// does depends on the memory layout, and every outcome is bad:
//
//   - standalone, input at page 0 (this harness, and tools/re2test): the fill
//     runs off the end of declared memory and TRAPS.
//   - the JS/TS stubs' layout, input staged AFTER the tables
//     (generate/js_stub.go): the fill zeroes the caller's own input and the
//     call then answers NoMatch for an input that matches — silent, and a
//     wrong answer rather than a crash.
//   - embedded or multi-pattern: it lands in the next pattern's tables
//     (compile.go chains them), corrupting an unrelated matcher.
//
// The guard is emitted in every body that fills a memo — the capture body
// (buildBacktrackBody, which set BT buckets also use), the no-capture match
// body, and BOTH branches of the no-capture find body (mandatory-literal and
// general scan).
//
// These tests assert the CONTRACT, not the threshold: at every length the call
// must return either the answer Go gives or abi.BTStackOverflow, and must never
// trap. That way they keep working when memoBudget, N, or the frame budget
// move, none of which are pinned here.

// btMemoCall is btRawCall's variant that surfaces a trap instead of failing the
// test on it — the trap IS the regression, so it has to be observable.
func btMemoCall(t *testing.T, wasmBytes []byte, export, input string, extraArgs ...int32) (int64, error) {
	t.Helper()
	store, inst, mem, release, err := instantiate(wasmBytes)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, export)
	if fn == nil {
		t.Fatalf("module has no %q export", export)
	}
	buf := mem.UnsafeData(store)
	if len(input) > int(pathsOutBase-pathsInputBase) {
		t.Fatalf("input of %d bytes runs into the output window at %d", len(input), pathsOutBase)
	}
	copy(buf[pathsInputBase:], input)
	args := []any{any(pathsInputBase), any(int32(len(input)))}
	for _, a := range extraArgs {
		args = append(args, any(a))
	}
	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, args...)
	wd.Disarm()
	if callErr != nil {
		return 0, callErr
	}
	switch v := res.(type) {
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	default:
		t.Fatalf("%s returned unexpected type %T", export, res)
		return 0, nil
	}
}

// btMemoPatterns covers every body that fills a memo. All four need
// needsBitState (a non-greedy loop whose body can match empty); the no-capture
// ones additionally need the DFA squeezed past its limit or they never reach
// Backtracking at all.
//
// MemoBudget is deliberately SMALL on three of them: it moves the ceiling down
// to a few thousand bytes so the sweep crosses it in milliseconds. htmlTags
// keeps the default budget and reproduces the original report exactly — its
// ceiling sits at a 41,942-byte extent.
const htmlTagsPattern = `<(?P<tag>\w+)(?:\s*(?P<attr>\w+)?(?:="(?P<val>[^"]*)")?)*?>`

func TestBTMemoOverflowIsGuarded(t *testing.T) {
	small := compile.CompileOptions{MemoBudget: 4096}
	squeezedSmall := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096}

	cases := []struct {
		name   string
		entry  config.RegexEntry
		opts   []compile.CompileOptions
		export string
		extra  []int32
		// wrap turns a run of n 'a's into the actual input.
		wrap func(string) string
		// answer maps a Go match to the raw i64 the export returns, so a
		// non-sentinel result can be checked rather than merely accepted.
		answer func(in string, loc []int) int64
	}{
		{
			// buildBacktrackBody — the capture body, shared with set BT buckets.
			name:   "groups/html-tags/default-budget",
			entry:  config.RegexEntry{Pattern: htmlTagsPattern, GroupsFunc: "groups"},
			export: "groups", extra: []int32{pathsOutBase, 0},
			wrap:   func(a string) string { return "<" + a + ">" },
			answer: func(_ string, loc []int) int64 { return int64(loc[1]) },
		},
		{
			name:   "groups/small-budget",
			entry:  config.RegexEntry{Pattern: htmlTagsPattern, GroupsFunc: "groups"},
			opts:   []compile.CompileOptions{small},
			export: "groups", extra: []int32{pathsOutBase, 0},
			wrap:   func(a string) string { return "<" + a + ">" },
			answer: func(_ string, loc []int) int64 { return int64(loc[1]) },
		},
		{
			// buildBTMatchBody.
			name:   "match",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?b`, MatchFunc: "match"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "match",
			wrap:   func(a string) string { return a + "b" },
			answer: func(in string, _ []int) int64 { return int64(len(in)) },
		},
		{
			// buildBTFindBody, general-scan branch.
			name:   "find/general-scan",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?`, FindFunc: "find"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "find", extra: []int32{0},
			wrap:   func(a string) string { return a },
			answer: func(_ string, loc []int) int64 { return int64(loc[0])<<32 | int64(loc[1]) },
		},
		{
			// buildBTFindBody, mandatory-literal branch — a separate emission
			// site with its own copy of the fill.
			name:   "find/mandatory-literal",
			entry:  config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"},
			opts:   []compile.CompileOptions{squeezedSmall},
			export: "find", extra: []int32{0},
			wrap:   func(a string) string { return a + "xyz" },
			answer: func(_ string, loc []int) int64 { return int64(loc[0])<<32 | int64(loc[1]) },
		},
	}

	// Spans every ceiling above: 4096-byte budgets put it in the low
	// thousands, the default budget puts it at 41,942.
	lengths := []int{0, 1, 100, 4095, 4096, 4097, 20000, 41940, 41941, 41942, 41943, 60000, 120000}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _, err := compile.Compile([]config.RegexEntry{tc.entry}, pathsTableBase, true, tc.opts...)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			re := regexp.MustCompile(tc.entry.Pattern)

			answered := 0
			for _, n := range lengths {
				in := tc.wrap(strings.Repeat("a", n))
				if len(in) > int(pathsOutBase-pathsInputBase) {
					continue
				}
				got, err := btMemoCall(t, w, tc.export, in, tc.extra...)
				if err != nil {
					t.Fatalf("len=%d: %v\nthe memo fill ran past its reservation — "+
						"the guard is missing from this body", len(in), err)
				}
				if got == abi.BTStackOverflow {
					continue // a resource ceiling; the answer is unknown, which is allowed
				}
				loc := re.FindStringIndex(in)
				var want int64 = abi.NoMatch
				if loc != nil {
					want = tc.answer(in, loc)
				}
				if got != want {
					t.Fatalf("len=%d: got %d, want %d (or BTStackOverflow)", len(in), got, want)
				}
				answered++
			}
			// Guards that reject everything would satisfy the loop above
			// vacuously; at least the short inputs must still get real answers.
			if answered == 0 {
				t.Fatalf("every length returned BTStackOverflow — the guard has "+
					"replaced all results rather than bounding them (%d lengths tried)", len(lengths))
			}
		})
	}
}

// The memo's length guard REFUSES: past the ceiling the body returns
// abi.BTStackOverflow, which means "the answer is unknown". Emitted at the head
// of a call, that verdict was reached before the find body had looked at the
// input at all — so a long input whose prefilter finds no candidate anywhere
// was told "unknown" when the engine could have answered "no match" for free,
// without ever touching the memo.
//
// The guard and the clear now sit at the head of the first ATTEMPT instead, so
// a call that never attempts never pays and never refuses.
//
// The test drives ONE pattern at ONE length over two inputs that differ only in
// which byte they repeat, and requires the two arms to differ:
//
//	quiet — no byte can begin a match, so no attempt runs → NoMatch
//	busy  — every position is a candidate, attempts run, the memo is filled
//	        past its ceiling → BTStackOverflow
//
// Both arms matter. Without the busy one the test would pass just as well
// against a build with no memo at all, or one whose ceiling was never reached,
// and would stop being evidence for anything.
func TestBTMemoGuardDoesNotRefuseWhatThePrefilterAnswers(t *testing.T) {
	// MaxDFAStates squeezes the pattern onto Backtracking; the small budget
	// puts the memo ceiling in the low thousands so a 60 KB input is well past
	// it either way.
	opts := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096}

	// Leading `Z` gives the prefilter something to reject on; `(?:a?)+?` is
	// what makes needsBitState fire.
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000

	entry := config.RegexEntry{Pattern: pattern, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	quiet := strings.Repeat("m", length) // no `Z`: nothing can begin a match
	busy := strings.Repeat("Z", length)  // every position is a candidate

	if regexp.MustCompile(pattern).MatchString(quiet) ||
		regexp.MustCompile(pattern).MatchString(busy) {
		t.Fatal("an input matches after all — the case is not testing what it claims")
	}

	got, err := btMemoCall(t, w, "find", quiet, 0)
	if err != nil {
		t.Fatalf("quiet: %v", err)
	}
	if got != abi.NoMatch {
		t.Errorf("quiet input of %d bytes: got %d, want NoMatch(%d) — the memo guard is "+
			"refusing a call the prefilter answers without ever touching the memo",
			length, got, abi.NoMatch)
	}

	got, err = btMemoCall(t, w, "find", busy, 0)
	if err != nil {
		t.Fatalf("busy: %v", err)
	}
	if got != abi.BTStackOverflow {
		t.Errorf("busy input of %d bytes: got %d, want BTStackOverflow(%d) — this arm is "+
			"what proves the memo path is reached at all, so the quiet arm above is "+
			"evidence of a moved guard rather than of an absent one",
			length, got, abi.BTStackOverflow)
	}
}

// The memo is REBASED onto the call's `from`: bit index 0 stands for that
// position, not for position 0. No attempt in a call ever starts before `from`
// — attempt_start is seeded from it and only advances — so the bitset a call
// needs covers the REMAINDER it is searching, and the ceiling is checked
// against that rather than against the whole buffer.
//
// Without the rebase a host walking a long buffer got BTStackOverflow from
// every call in the walk, including the ones with only a handful of bytes left
// to search, because each was measured against the buffer's full length.
//
// Both arms again: `from` at 0 must still refuse (the remainder really is past
// the ceiling), and a late `from` must answer. A build that simply lost its
// ceiling would pass the second arm and fail the first.
func TestBTMemoCeilingAppliesToTheRemainder(t *testing.T) {
	opts := compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096}
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000

	entry := config.RegexEntry{Pattern: pattern, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Every position is a candidate, so every call reaches an attempt and the
	// memo is genuinely used.
	input := strings.Repeat("Z", length)
	if regexp.MustCompile(pattern).MatchString(input) {
		t.Fatal("the input matches after all — the case is not testing what it claims")
	}

	got, err := btMemoCall(t, w, "find", input, 0)
	if err != nil {
		t.Fatalf("from=0: %v", err)
	}
	if got != abi.BTStackOverflow {
		t.Errorf("from=0: got %d, want BTStackOverflow(%d) — the whole %d-byte remainder "+
			"is past the memo ceiling, so this call must still refuse",
			got, abi.BTStackOverflow, length)
	}

	// Only 100 bytes remain to search, which fits the memo comfortably.
	const late = length - 100
	got, err = btMemoCall(t, w, "find", input, int32(late))
	if err != nil {
		t.Fatalf("from=%d: %v", late, err)
	}
	if got != abi.NoMatch {
		t.Errorf("from=%d: got %d, want NoMatch(%d) — only %d bytes remain, so the memo "+
			"ceiling must be measured against those and not against the whole buffer",
			late, got, abi.NoMatch, length-late)
	}
}
