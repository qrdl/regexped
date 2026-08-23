package fuzz

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
)

// ---------------------------------------------------------------------------
// Regressions on the TDFA capture path.
//
// All three are silent wrong-answer bugs on patterns the selector itself routes
// to TDFA, so every case here asserts the selector's own choice first: forcing
// TDFA on a pattern the compiler never claimed to handle would be garbage-in,
// exactly as FuzzGroupsBothEngines argues.

// tdfaCase is one (pattern, input) pair checked against Go's
// FindStringSubmatchIndex through the TDFA groups export.
type tdfaCase struct {
	pattern string
	input   string
	desc    string
}

// checkTDFAGroups compiles each case on TDFA and compares the capture slots
// against the stdlib oracle. It fails (rather than skips) when the selector
// would not pick TDFA: these patterns are the bugs' repros, and a selector
// change that quietly routes them elsewhere would turn the regression test into
// a no-op that still reports PASS.
func checkTDFAGroups(t *testing.T, cases []tdfaCase) {
	t.Helper()
	for _, c := range cases {
		name := c.desc
		if name == "" {
			name = c.pattern
		}
		t.Run(name, func(t *testing.T) {
			eng, err := compile.SelectEngine(c.pattern, compile.CompileOptions{})
			if err != nil {
				t.Fatalf("SelectEngine(%q): %v", c.pattern, err)
			}
			if eng != compile.EngineTDFA {
				t.Fatalf("pat=%q: selector picked %v, want TDFA — this repro no longer covers the TDFA path",
					c.pattern, eng)
			}

			wasmBytes, err := compileGroupsForced(c.pattern, compile.EngineTDFA)
			if err != nil {
				t.Fatalf("pat=%q compile: %v", c.pattern, err)
			}

			ref := regexp.MustCompile(c.pattern)
			numGroups := ref.NumSubexp() + 1
			want := ref.FindStringSubmatchIndex(c.input)

			got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, c.input, numGroups)
			if runErr != nil {
				t.Fatalf("pat=%q input=%q: wasm error: %v", c.pattern, abbrev(c.input), runErr)
			}
			if hang {
				t.Fatalf("pat=%q input=%q: hang (watchdog %s)", c.pattern, abbrev(c.input), wasmCallTimeout)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Fatalf("groups mismatch (%s): pat=%q input=%q\n  expected %v\n  got      %v (ok=%v)",
					msg, c.pattern, abbrev(c.input), want, got, ok)
			}
		})
	}
}

// abbrev shortens long inputs in failure messages — several repros need
// hundreds of bytes to trip, and dumping them verbatim buries the diff.
func abbrev(s string) string {
	if len(s) <= 64 {
		return s
	}
	return fmt.Sprintf("%q...%q (len %d)", s[:32], s[len(s)-16:], len(s))
}

// B14: register-coloring coalescing (minimizeTDFARegisters/remapOps) can map two
// registers in the same parallel-copy batch onto one local, creating a
// read-after-write dependency that did not exist before coloring. The batch was
// correctly sequentialized pre-coloring and is never re-sequentialized after, so
// one op clobbers the value the next op reads.
//
// `(b+){2}c` on "bbbc" is the minimal witness: group 1 must report the LAST
// iteration ([2 3]), and the pre-coloring batch [{0 3} {1 2}] becomes [{1 2}
// {0 1}] once r0 and r2 are coalesced, yielding [0 4 2 2].
func TestTDFARegisterCoalescingOrdering(t *testing.T) {
	checkTDFAGroups(t, []tdfaCase{
		{pattern: `(b+){2}c`, input: "bbbc", desc: "b_plus_rep2"},
		{pattern: `(b+){2}c`, input: "bbbbbc", desc: "b_plus_rep2_longer"},
		{pattern: `(a+){2}(b+){2}c`, input: "aabbbc", desc: "two_coalescing_batches"},
		{pattern: `(ab+){2}c`, input: "abbabc", desc: "multi_byte_body"},
		{pattern: `(b+){3}c`, input: "bbbbc", desc: "rep3"},
		{pattern: `x(a+){2}y`, input: "xaaay", desc: "prefixed"},
	})
}

// B15: the TDFA body hand-rolls its transition load instead of using the shared
// emitU8Transition / emitCompressedU8Transition / emitU16Transition, so it
// diverges from whatever encoding buildDFALayout actually picked.
//
//  1. >256 states → u16 encoding → the hand-rolled operand order produced an
//     invalid module ("expected i32 but nothing on stack"), i.e. instantiation
//     fails outright.
//  2. ≥ ~128 states → byte-class compression kicks in (numWASM*256 > 32KB) and
//     the emitted classMap is never read: the body still indexes
//     tableOff + state<<8 + byte, so transitions come from the wrong cells and
//     the match silently disappears.
//
// The a{N} ladder walks straight through both thresholds; N=120 was the last
// value that agreed with stdlib before the fix, N=125 the first that did not.
func TestTDFATableAddressingEncodings(t *testing.T) {
	var cases []tdfaCase
	for _, n := range []int{100, 120, 125, 130, 200, 260, 300} {
		cases = append(cases, tdfaCase{
			pattern: fmt.Sprintf(`x(a{%d})y`, n),
			input:   "x" + strings.Repeat("a", n) + "y",
			desc:    fmt.Sprintf("a_rep_%d", n),
		})
	}
	// Same thresholds with a non-trivial byte class, so compression has real
	// equivalence classes to collapse rather than a two-symbol alphabet.
	for _, n := range []int{130, 300} {
		cases = append(cases, tdfaCase{
			pattern: fmt.Sprintf(`x([a-f]{%d})y`, n),
			input:   "x" + strings.Repeat("cafe", (n+3)/4)[:n] + "y",
			desc:    fmt.Sprintf("class_rep_%d", n),
		})
	}
	checkTDFAGroups(t, cases)
}

// B16: emitTDFABulkSkip advances over a run of same-state bytes without running
// the per-byte mid-accept bookkeeping the scalar loop does, so lastAcceptPos and
// the eagerly-written captures stay frozen at the value they had when the run
// started. A dead exit byte inside a full 16-byte chunk then reports the stale
// position.
//
// `^([a-z]+)` on 20 a's + "!" + 20 a's returned [0 1 0 1] instead of [0 20 0 20]:
// the very first byte was the last one the scalar loop saw. The run must be long
// enough that the exit byte lands inside a full 16-byte SIMD chunk — a
// scalar-tail exit masks the bug entirely, which is why the short variants below
// are included as controls rather than as repros.
func TestTDFABulkSkipMidAccept(t *testing.T) {
	var cases []tdfaCase
	for _, n := range []int{4, 16, 17, 20, 33, 64, 100} {
		cases = append(cases, tdfaCase{
			pattern: `^([a-z]+)`,
			input:   strings.Repeat("a", n) + "!" + strings.Repeat("a", 20),
			desc:    fmt.Sprintf("lower_run_%d", n),
		})
	}
	cases = append(cases,
		tdfaCase{pattern: `^([a-z]+)`, input: strings.Repeat("a", 40), desc: "no_exit_byte"},
		tdfaCase{pattern: `^([0-9]+)`, input: strings.Repeat("7", 50) + "x", desc: "digits"},
		tdfaCase{pattern: `^([a-z]+)([0-9]*)`, input: strings.Repeat("q", 40) + "!", desc: "two_groups"},
	)
	checkTDFAGroups(t, cases)
}
