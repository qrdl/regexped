package fuzz

import (
	"encoding/binary"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// ---------------------------------------------------------------------------
// plans/OPUS.md §N1 regression: the Backtracking engine's frame stack is sized
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
	store, inst, mem, err := instantiate(wasmBytes)
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

// TestBTStackOverflowIsDistinguishable is the core §N1 assertion: on an input
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
			extra:   []int32{pathsOutBase},
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
				t.Errorf("%s on %d-byte input = %d (NoMatch) — §N1 regression: "+
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
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast)+"c", pathsOutBase); got < 0 {
		t.Errorf("%d-byte input already overflows (= %d); ceiling moved down", wantLast+1, got)
	}
	if got := btRawCall(t, w, "groups", strings.Repeat("a", wantLast+1)+"c", pathsOutBase); got != abi.BTStackOverflow {
		t.Errorf("%d-byte input = %d, want BTStackOverflow; ceiling moved up", wantLast+2, got)
	}
}
