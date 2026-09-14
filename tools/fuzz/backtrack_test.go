package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// Regression: the no-capture Backtracking FIND body must cost time LINEAR in
// input length, not quadratic.
//
// The BitState memo is a bitset of N*(len+1) bits, sized from the whole input.
// Until 2026-09-06 it was re-zeroed with one memory.fill at the head of every
// ATTEMPT — every candidate start position the find loop tries — which makes
// the search O(N*len^2). wasmtime charges memory.fill about 1 fuel per byte, so
// the memset alone dominated everything else the engine did:
//
//	len          64      128      256      512     1024     2048     4096
//	per-attempt x---    x3.86    x3.93    x3.96    x3.98    x3.99    x4.00
//	per-call    x---    x1.98    x1.99    x1.99    x2.00    x2.00    x2.00
//
// x4.00 per doubling is quadratic. At 4,096 bytes that was 1,796,155,500 fuel
// against 1,696,356 — a factor of 1,059, growing with length.
//
// The fix hoists the fill to once per CALL. It is sound in this body and only
// this body: it tracks no captures, so its entire NFA state is (pc, pos), and a
// pair marked during a failed attempt has no accepting continuation regardless
// of which start position reached it. The CAPTURE body keeps its per-attempt
// fill — its state includes the capture registers, so the same (pc, pos) can
// carry a different answer.
//
// This test pins the COMPLEXITY rather than any fuel number, so it keeps
// working when the constants move: re-introducing a per-attempt fill sends the
// growth ratio back to ~4 and fails it, while ordinary tuning does not.

// TestBTFindMemoIsLinearInInputLength doubles the input and requires the fuel
// to roughly double with it.
func TestBTFindMemoIsLinearInInputLength(t *testing.T) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	engine := wasmtime.NewEngineWithConfig(cfg)

	// Needs all three: a non-greedy loop with an empty-matchable body (so
	// needsBitState fires), a DFA squeezed past its limit (so the pattern
	// reaches Backtracking for find at all), and a no-match input (so every
	// start position is attempted).
	entry := config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"}
	opts := compile.CompileOptions{MaxDFAStates: 1}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(engine)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		copy(mem.UnsafeData(store)[pathsInputBase:], strings.Repeat("a", n))
		fn := inst.GetFunc(store, "find")
		before, _ := store.GetFuel()
		if _, err := fn.Call(store, pathsInputBase, int32(n), int32(0)); err != nil {
			t.Fatalf("len=%d: %v", n, err)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	// 3.0 sits well clear of both regimes — linear measures ~2.00, the
	// quadratic form measured 3.86 at the first doubling and rose from there.
	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{256, 512, 1024, 2048, 4096} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the BitState memo fill looks per-attempt again, which makes "+
					"this search quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}

// ---------------------------------------------------------------------------
// The same property for a SET's Backtracking bucket, which the hoist above
// does NOT cover.
//
// A set BT bucket is a suffix function called once per CANDIDATE position, and
// each call ran one memory.fill over the whole remaining window — so the drive
// was O(N*len^2) with the memset again the entire quadratic term. Measured on
// the case below, before the position-major memo layout and its lazy clear:
//
//	len          256      512     1024     2048     4096     8192    16384    32768
//	per-call   x---    x2.27    x2.47    x2.75    x3.09    x3.41    x3.65    x3.81
//	lazy       x---    x2.01    x2.00    x2.00    x2.00    x2.00    x2.00    x2.00
//
// 247,139,555 fuel against 12,483,789 at 32 KB — a factor of 19.8, growing
// with length. Neutralising the fill entirely measured 12,238,053, so what
// remains of the clear is 2.0% rather than 95% of the call.
//
// The fix is not the find body's hoist, which is unsound here: a set bucket is
// a separate WASM function per candidate and cannot share marks across calls
// without a per-drive clear no exported body is obliged to perform. Instead
// the memo is indexed POSITION-major, which makes the bytes one attempt dirties
// a contiguous run from the base, and each call clears exactly the run the
// previous call recorded in the memo header word.
func TestSetBTMemoIsLinearInInputLength(t *testing.T) {
	// Needs all of: a member forced onto BT (max_fallback_states = 1), a
	// non-greedy loop with an empty-matchable body (needsBitState), a rare
	// leading byte so most positions are candidates that FAIL fast, and a
	// match at the very end so the drive scans the whole input.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p0", Pattern: `q(?:a?)+?z`}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{Names: []string{"p0"}},
		}},
		MaxFallbackStates: 1,
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := droppedFromSet(diags); len(d) > 0 {
		t.Fatalf("the pattern was dropped from the set: %v", d)
	}

	wcfg := wasmtime.NewConfig()
	wcfg.SetConsumeFuel(true)
	wcfg.SetWasmSIMD(true)
	eng := wasmtime.NewEngineWithConfig(wcfg)
	mod, err := wasmtime.NewModule(eng, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	const pageSize = 65536
	dataTop, dtErr := utils.ParseDataSectionBytes(w)
	if dtErr != nil {
		t.Fatalf("parse data section: %v", dtErr)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(eng)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		inputSpan := int32((n + pageSize - 1) / pageSize * pageSize)
		gateBase := inBase + inputSpan
		outBase := gateBase + pageSize
		need := uint64((int64(outBase) + pageSize + pageSize - 1) / pageSize)
		if cur := mem.Size(store); need > cur {
			if _, gErr := mem.Grow(store, need-cur); gErr != nil {
				t.Fatal(gErr)
			}
		}
		in := strings.Repeat("qa", n/2-2) + "qaz"
		for len(in) < n {
			in = "a" + in
		}
		copy(mem.UnsafeData(store)[inBase:], in[:n])
		fn := inst.GetFunc(store, "set_find")
		before, _ := store.GetFuel()
		scratchBase := gateBase + 64
		abi.WriteFindScratch(mem.UnsafeData(store), scratchBase, gateBase, 0, 0)
		res, callErr := fn.Call(store, inBase, int32(n), int32(0), scratchBase, outBase, int32(1))
		if callErr != nil {
			t.Fatalf("len=%d: %v", n, callErr)
		}
		if got := res.(int32); got != 1 {
			t.Fatalf("len=%d: set_find returned %d, want 1 tuple — the drive is not "+
				"scanning the whole input and the growth curve means nothing", n, got)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{2048, 4096, 8192, 16384, 32768} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the set BT bucket's memo clear looks input-sized again, which "+
					"makes this drive quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}

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

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine's frame stack is sized
// from a compile-time constant (btAllocSizes: numAlts*4096 frames) while the
// real requirement scales with input length. Exhausting it used to return
// abi.NoMatch, i.e. a false negative that switches on somewhere past
// numAlts*4096 bytes and is indistinguishable from a genuine no-match at every
// layer above. It must return abi.BTStackOverflow instead.
//
// These tests are deliberately written against the raw WASM return code rather
// than through a helper that folds negatives into an ok bool — the whole point
// is that the two negatives stay distinguishable, so a helper that erases the
// difference cannot be the thing under test.
//
// Pattern-shape notes, which are the fiddly part of reproducing this at all:
//
//   - The pattern must push a backtrack frame that STAYS live as input is
//     consumed. A non-greedy loop alone does not: its preferred branch (exit
//     the loop) fails immediately against the next byte, so the frame is pushed
//     and popped straight back. What accumulates is an untried *alternation*
//     branch — after `ab` matches, the frame holding "try `cd` here instead"
//     is still live.
//   - The alternation must survive regexp/syntax's simplification. `a|b`
//     becomes the char class `[ab]` and `aa|ab` is factored to `a[ab]`; neither
//     leaves an Alt instruction, so neither overflows. Branches with no common
//     prefix (`ab|cd`) do.
//   - For the no-capture paths the DFA has to be pushed over its state limit
//     first, or they never reach Backtracking at all — hence MaxDFAStates and
//     a literal tail long enough to blow it.
const (
	// btCapturePattern reaches BT via the capture path (the selector rejects
	// TDFA for the non-greedy quantifier). numAlts = 2 → 8192 frames, and the
	// inner (a)|(b) leaves one live frame per input byte.
	btCapturePattern = `(?:(a)|(b))*?c`
	btCaptureGroups  = 3 // whole match + 2 groups

	// btNoCapturePattern reaches BT for match/find once the DFA state limit is
	// squeezed. Each iteration consumes 2 bytes and leaves one live frame.
	btNoCapturePattern = `(?:ab|cd)*?xyzuvw`
)

// btRawCall calls export with (ptr, len, extraArgs...) and returns its raw
// result widened to int64, so an i32 -2 and an i64 -2 compare the same way.
func btRawCall(t *testing.T, wasmBytes []byte, export, input string, extraArgs ...int32) int64 {
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
		t.Fatalf("input of %d bytes would run into the output window at %d", len(input), pathsOutBase)
	}
	copy(buf[pathsInputBase:], input)
	// Poison the output window so a stale read cannot masquerade as a result.
	for i := 0; i < 1024; i++ {
		binary.LittleEndian.PutUint32(buf[int(pathsOutBase)+i*4:], 0xFFFFFFFF)
	}

	args := []any{any(pathsInputBase), any(int32(len(input)))}
	for _, a := range extraArgs {
		args = append(args, any(a))
	}
	_, wd := sharedEngine()
	wd.Arm(store)
	res, callErr := fn.Call(store, args...)
	wd.Disarm()
	if callErr != nil {
		t.Fatalf("call %s: %v", export, callErr)
	}
	switch v := res.(type) {
	case int32:
		return int64(v)
	case int64:
		return v
	default:
		t.Fatalf("%s returned unexpected type %T", export, res)
		return 0
	}
}

// TestBTStackOverflowIsDistinguishable is the core assertion: on an input
// past the frame ceiling every BT-hosting export reports BTStackOverflow, and
// critically NOT NoMatch — while the same pattern on a shorter input still
// answers correctly, so the sentinel has not simply replaced all results.
func TestBTStackOverflowIsDistinguishable(t *testing.T) {
	if eng, err := compile.SelectEngine(btCapturePattern, compile.CompileOptions{}); err != nil {
		t.Fatalf("SelectEngine: %v", err)
	} else if eng != compile.EngineBacktrack {
		t.Fatalf("%s selects %v, not Backtracking — this test no longer exercises the BT capture path",
			btCapturePattern, eng)
	}

	capIn := func(n int) string { return strings.Repeat("a", n) + "c" }
	noCapIn := func(n int) string { return strings.Repeat("ab", n) + "xyzuvw" }
	squeezed := compile.CompileOptions{MaxDFAStates: 2}

	cases := []struct {
		name    string
		entry   config.RegexEntry
		opts    []compile.CompileOptions
		export  string
		extra   []int32
		ok      string // input the engine can still answer
		wantOK  int64  // its expected result
		blown   string // input past the frame ceiling
		numCaps int
	}{
		{
			name:    "groups",
			entry:   config.RegexEntry{Pattern: btCapturePattern, GroupsFunc: "groups"},
			export:  "groups",
			extra:   []int32{pathsOutBase, 0}, // out_ptr, from
			ok:      capIn(8191),
			wantOK:  8192, // match end position
			blown:   capIn(8192),
			numCaps: btCaptureGroups,
		},
		{
			name:   "groups_batch",
			entry:  config.RegexEntry{Pattern: btCapturePattern, GroupsFunc: "groups", Hints: []string{"batch-find"}},
			export: "groups_batch",
			extra:  []int32{pathsOutBase, 16, 0},
			ok:     capIn(8191),
			wantOK: 1, // one match collected
			blown:  capIn(8192),
		},
		{
			name:   "match",
			entry:  config.RegexEntry{Pattern: btNoCapturePattern, MatchFunc: "match"},
			opts:   []compile.CompileOptions{squeezed},
			export: "match",
			ok:     noCapIn(4000),
			wantOK: 8006,
			blown:  noCapIn(8192),
		},
		{
			name:   "find",
			entry:  config.RegexEntry{Pattern: btNoCapturePattern, FindFunc: "find"},
			opts:   []compile.CompileOptions{squeezed},
			export: "find",
			extra:  []int32{0}, // `from` — find is (ptr, len, from)
			ok:     noCapIn(4000),
			wantOK: 8006, // packed 0<<32|8006
			blown:  noCapIn(8192),
		},
		{
			name:   "find_batch",
			entry:  config.RegexEntry{Pattern: btNoCapturePattern, FindFunc: "find", Hints: []string{"batch-find"}},
			opts:   []compile.CompileOptions{squeezed},
			export: "find_batch",
			extra:  []int32{pathsOutBase, 16, 0},
			ok:     noCapIn(4000),
			wantOK: 1,
			blown:  noCapIn(8192),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _, err := compile.Compile([]config.RegexEntry{tc.entry}, pathsTableBase, true, tc.opts...)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			// Both inputs genuinely match, so NoMatch is the wrong answer for
			// either one — which is what made the old behaviour a false
			// negative rather than a merely imprecise one.
			re := regexp.MustCompile(tc.entry.Pattern)
			for _, in := range []string{tc.ok, tc.blown} {
				if !re.MatchString(in) {
					t.Fatalf("test input of %d bytes does not match %s — fixture is wrong",
						len(in), tc.entry.Pattern)
				}
			}

			if got := btRawCall(t, w, tc.export, tc.ok, tc.extra...); got != tc.wantOK {
				t.Errorf("%s on %d-byte input = %d, want %d (below the frame ceiling it must still answer)",
					tc.export, len(tc.ok), got, tc.wantOK)
			}
			got := btRawCall(t, w, tc.export, tc.blown, tc.extra...)
			if got == abi.NoMatch {
				t.Errorf("%s on %d-byte input = %d (NoMatch) — regression: "+
					"stack overflow reported as a definite no-match",
					tc.export, len(tc.blown), got)
			}
			if got != abi.BTStackOverflow {
				t.Errorf("%s on %d-byte input = %d, want %d (BTStackOverflow)",
					tc.export, len(tc.blown), got, abi.BTStackOverflow)
			}
		})
	}
}

// TestBTStackOverflowThreshold pins the ceiling to numAlts*4096 frames. If a
// future change to btAllocSizes moves it, this fails loudly rather than
// silently shifting the input size at which callers start seeing errors.
func TestBTStackOverflowThreshold(t *testing.T) {
	w, _, err := compile.Compile(
		[]config.RegexEntry{{Pattern: btCapturePattern, GroupsFunc: "groups"}},
		pathsTableBase, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	const wantLast = 8191 // numAlts(2) * 4096 == 8192 frames, one per input byte
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast)+"c", pathsOutBase, 0); got < 0 {
		t.Errorf("%d-byte input already overflows (= %d); ceiling moved down", wantLast+1, got)
	}
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast+1)+"c", pathsOutBase, 0); got != abi.BTStackOverflow {
		t.Errorf("%d-byte input = %d, want BTStackOverflow; ceiling moved up", wantLast+2, got)
	}
}

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine dropped every input byte >= 0x80 from a
// rune RANGE, so a capture pattern over a negated class silently failed to
// match input containing such a byte.
//
// `.` and negated classes consuming ONE BYTE is documented byte semantics
// (docs/engines.md, "Bytes, not codepoints"), so `[^>]` must match 0xE9. The
// DFA agrees: nfaBuildInputMap SATURATES a range at 0xFF. Backtracking
// TRUNCATED at 0x7F instead — `if lo > 0x7F { continue }` in btCheckRuneRanges
// and btEmitSingleRange — and nfaFirstBytes gated its scan prefilter the same
// way, so a match STARTING with a high byte was skipped outright.
//
// Backtracking is a hybrid: the DFA finds the match extent, the NFA fills the
// captures. That is why the defect showed only through `groups` — `find` took
// the DFA's answer and was right, then `groups` re-walked the same input with
// the truncated ranges and reported no match at all.
//
// The affected family is precisely the one the engine-selection gate exists to
// route here: `<([^>]+)>`, `([^,]+),`, `KEY=([^&]+)&` (see CLAUDE.md's
// load-bearing gates section). An inverted class is what sends a capture
// pattern to Backtracking, and an inverted class is what carries the high
// bytes.
//
// ORACLE. An isomorphism, for the same reason single_pattern_test.go uses
// one: Go reads its input as UTF-8, so it cannot be asked about a raw 0xE9. A
// byte engine treats 0xE9 exactly like any other byte absent from the pattern,
// so mapping it to an ASCII stand-in that also appears nowhere gives a
// question Go can answer. That is an independent oracle, not a transcript of
// engine output.
//
// NOTE ON COVERAGE. tools/re2test cannot host this case: it skips every input
// containing a byte above 127 (hasUnicode), so no corpus row ever feeds a high
// byte to any engine. That blind spot is why this survived.

const (
	btHiByte   = "\xe9"
	btHiStandI = "Q"
)

func TestBTHighByteInRanges(t *testing.T) {
	shapes := []struct {
		name, pat, input string
		groups           int
	}{
		// The canonical Backtracking family, high byte INSIDE the match.
		{"angle", `<([^>]+)>`, "<caf\xe9>", 1},
		{"comma", `([^,]+),`, "caf\xe9,", 1},
		{"kv", `KEY=([^&]+)&`, "KEY=caf\xe9&", 1},
		{"quoted", `"([^"]*)"`, "\"caf\xe9\"", 1},
		{"nonspace", `(\S+)!`, "caf\xe9!", 1},
		{"two-groups", `<([^>]+)>=([^;]+);`, "<caf\xe9>=va\xe9l;", 2},

		// High byte at the START of the match — the nfaFirstBytes prefilter.
		{"first-byte", `([^,]+),`, "\xe9ab,", 1},
		{"first-byte-only", `([^,]+),`, "\xe9,", 1},

		// High byte at both ends.
		{"both-ends", `([^,]+),`, "\xe9a\xe9,", 1},

		// Pure-ASCII controls: these must not change.
		{"ascii-angle", `<([^>]+)>`, "<cafe>", 1},
		{"ascii-comma", `([^,]+),`, "cafe,", 1},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			eng, serr := compile.SelectEngine(sh.pat, compile.CompileOptions{})
			if serr != nil {
				t.Fatalf("select: %v", serr)
			}
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}

			// The isomorphic twin: 0xE9 -> 'Q' in the input only. No shape
			// here names a high byte in the PATTERN.
			oracleIn := strings.ReplaceAll(sh.input, btHiByte, btHiStandI)
			re := regexp.MustCompile(`(?s)` + sh.pat)
			want := re.FindStringSubmatchIndex(oracleIn)

			got := res.(int32)
			if want == nil {
				if got >= 0 {
					t.Errorf("engine %v: pattern %q over %q matched, want no match", eng, sh.pat, sh.input)
				}
				return
			}
			if got < 0 {
				t.Fatalf("engine %v: pattern %q over %q returned %d (no match), want spans %v\n"+
					"  a negated class must match a byte >= 0x80: `.` and negated classes "+
					"consume ONE BYTE (docs/engines.md)", eng, sh.pat, sh.input, got, want)
			}

			buf := mem.UnsafeData(store)
			slots := (sh.groups + 1) * 2
			for i := 0; i < slots; i++ {
				v := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
				wantV := int32(want[i])
				if v != wantV {
					t.Errorf("engine %v: pattern %q over %q slot %d: got %d, want %d (all spans %v)",
						eng, sh.pat, sh.input, i, v, wantV, want)
				}
			}
		})
	}
}

// The same defect under byte_mode, where the pattern names the high bytes
// itself rather than admitting them through a negated class.
func TestBTHighByteByteMode(t *testing.T) {
	shapes := []struct{ name, pat, input string }{
		{"hi-class-plus", `([\x80-\xff]+)x`, "\xe9\xeax"},
		{"hi-class-one", `a([\x80-\xff])b`, "a\xe9b"},
		{"hi-range-mixed", `([a-\xff]+)!`, "ca\xe9!"},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups", ByteMode: true}
			// Forced, because auto-selection sends these to TDFA today. The
			// clamp is Backtracking's, so Backtracking is what must be asked.
			w, _, err := compile.CompileForced([]config.RegexEntry{entry},
				pathsTableBase, true, compile.EngineBacktrack)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}
			if got := res.(int32); got < 0 {
				t.Errorf("Backtracking: pattern %q over %q returned %d, want a match\n"+
					"  byte_mode declares runes 0x80-0xFF to mean those BYTES",
					sh.pat, sh.input, got)
			}
		})
	}
}

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
				// btIterSeeds are hardcoded and valid, so Go cannot reject one.
				// If it does, something is wrong that a skip would hide behind
				// a green test.
				t.Fatalf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindBT(c.pat)
			if err != nil {
				// btIterSeeds are fixed shapes chosen to exercise the forced-BT
				// path, and nothing else in this package reaches it. A skip
				// here would let an emitter regression pass by deleting the
				// only coverage of the path under test.
				t.Fatalf("compile %q: %v", c.pat, err)
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
