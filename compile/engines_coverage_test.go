package compile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// Shared helpers for this file. All prefixed enginesCov so they cannot collide
// with helpers other coverage files add to package compile.
// ---------------------------------------------------------------------------

// enginesCovParse parses pattern with Perl flags, exactly as compilePattern
// does, so a helper under test sees the same AST the compiler would hand it.
func enginesCovParse(t *testing.T, pattern string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	return re
}

// enginesCovProg parses and compiles pattern to NFA bytecode the same way
// compilePattern/SelectEngine do (Simplify before Compile), so PC numbering in
// a test matches what the selector actually analyses.
func enginesCovProg(t *testing.T, pattern string) *syntax.Prog {
	t.Helper()
	prog, err := syntax.Compile(enginesCovParse(t, pattern).Simplify())
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	return prog
}

// enginesCovFindInst returns the PC of the first instruction with op, failing
// the test when there is none. Tests use it instead of a hardcoded PC so a
// change in Go's NFA layout does not silently make a case test nothing.
func enginesCovFindInst(t *testing.T, prog *syntax.Prog, op syntax.InstOp) int {
	t.Helper()
	for pc, inst := range prog.Inst {
		if inst.Op == op {
			return pc
		}
	}
	t.Fatalf("no %v instruction in prog:\n%v", op, prog)
	return -1
}

// ---------------------------------------------------------------------------
// lit_anchor.go — prefix-shape predicates
//
// These four predicates gate the lit-anchor find optimisation. They are pure
// functions over the parsed AST, and every one of them is a SAFETY gate: a
// false negative only costs speed, but a false positive emits a backward scan
// that stops at the wrong byte. Testing them directly is
// the only way to reach the branches that no perftest/re2 corpus pattern
// happens to have the shape for.
// ---------------------------------------------------------------------------

func TestEnginesCovCanConsumeNewline(t *testing.T) {
	// A nil subtree is what stripLeadingLineAnchor returns on rejection; the
	// caller feeds that straight back in, so nil must answer "cannot consume".
	if canConsumeNewline(nil) {
		t.Error("canConsumeNewline(nil) = true, want false")
	}

	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		// Assertions consume nothing at all.
		{"begin_text", `^`, false},
		{"word_boundary", `\b`, false},
		// A literal only consumes '\n' when it literally contains one. Both
		// halves matter: the loop must scan every rune, not just the first.
		{"literal_without_nl", `abc`, false},
		{"literal_with_nl_last", "ab\n", true},
		// Char classes are tested by range containment, so a class whose range
		// straddles '\n' (0x0a) counts even though it never spells it out.
		{"class_excluding_nl", `[a-z]`, false},
		{"class_spanning_nl", `[\x09-\x0b]`, true},
		{"negated_class_includes_nl", `[^a]`, true},
		// `.` is OpAnyCharNotNL by default and OpAnyChar under (?s) — the
		// entire point of the distinction for this predicate.
		{"dot_default", `.`, false},
		{"dot_dotall", `(?s).`, true},
		// Containers recurse into their subexpressions.
		{"star_of_safe_class", `[a-z]*`, false},
		{"alternate_with_nl_branch", "(?:a|\n)", true},
		{"capture_of_safe_literal", `(abc)`, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			re := enginesCovParse(t, testCase.pattern)
			if got := canConsumeNewline(re); got != testCase.want {
				t.Errorf("canConsumeNewline(%q) = %v, want %v (parsed as %v)",
					testCase.pattern, got, testCase.want, re.Op)
			}
		})
	}

	// Unknown ops answer true (conservative). The switch names every op the
	// parser can produce, so the default arm is only reachable from a node
	// whose Op is not a valid syntax.Op at all — a zero-valued *syntax.Regexp
	// being the realistic way that happens. "Might consume a newline" is the
	// answer that keeps the caller from claiming a stretch never crosses a
	// line boundary on the strength of a node it did not understand.
	unknown := &syntax.Regexp{}
	if !canConsumeNewline(unknown) {
		t.Error("canConsumeNewline(unhandled op) = false, want true (must stay conservative)")
	}
}

func TestEnginesCovStripLeadingLineAnchor(t *testing.T) {
	if rest, ok := stripLeadingLineAnchor(nil); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(nil) = (%v, %v), want (nil, false)", rest, ok)
	}

	// A bare anchor strips to OpEmptyMatch — the "nothing follows it" case
	// lineAnchoredPrefixSafe then declares safe.
	rest, ok := stripLeadingLineAnchor(enginesCovParse(t, `^`))
	if !ok || rest == nil || rest.Op != syntax.OpEmptyMatch {
		t.Fatalf("stripLeadingLineAnchor(`^`) = (%v, %v), want (OpEmptyMatch, true)", rest, ok)
	}

	// A capture wrapping the anchor must be seen through: `(^)` is the same
	// prefix shape as `^` for the backward scan.
	captured := &syntax.Regexp{
		Op:  syntax.OpCapture,
		Sub: []*syntax.Regexp{{Op: syntax.OpBeginLine}},
	}
	rest, ok = stripLeadingLineAnchor(captured)
	if !ok || rest == nil || rest.Op != syntax.OpEmptyMatch {
		t.Fatalf("stripLeadingLineAnchor(capture of ^) = (%v, %v), want (OpEmptyMatch, true)", rest, ok)
	}

	// Concat: the anchor is replaced by OpEmptyMatch and the tail preserved,
	// so canConsumeNewline can be asked about the tail alone.
	rest, ok = stripLeadingLineAnchor(enginesCovParse(t, `^ab`))
	if !ok || rest == nil || rest.Op != syntax.OpConcat {
		t.Fatalf("stripLeadingLineAnchor(`^ab`) = (%v, %v), want (OpConcat, true)", rest, ok)
	}
	if canConsumeNewline(rest) {
		t.Error("stripped `^ab` tail reports it can consume a newline")
	}

	// An empty concat has no leading element to inspect; rejecting it keeps
	// the caller from indexing Sub[0] on nothing.
	if rest, ok := stripLeadingLineAnchor(&syntax.Regexp{Op: syntax.OpConcat}); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(empty concat) = (%v, %v), want (nil, false)", rest, ok)
	}

	// No leading anchor at all → rejected.
	if rest, ok := stripLeadingLineAnchor(enginesCovParse(t, `ab`)); ok || rest != nil {
		t.Errorf("stripLeadingLineAnchor(`ab`) = (%v, %v), want (nil, false)", rest, ok)
	}
}

func TestEnginesCovPrefixContainsWordBoundary(t *testing.T) {
	if prefixContainsWordBoundary(nil) {
		t.Error("prefixContainsWordBoundary(nil) = true, want false")
	}
	cases := []struct {
		pattern string
		want    bool
	}{
		{`\b`, true},            // the node itself
		{`\B`, true},            // the negated form counts too
		{`a\bb`, true},          // found by recursing into a concat
		{`(?:x(?:y\Bz))`, true}, // found several levels down
		{`abc`, false},
		{`[a-z]+`, false},
	}
	for _, testCase := range cases {
		re := enginesCovParse(t, testCase.pattern)
		if got := prefixContainsWordBoundary(re); got != testCase.want {
			t.Errorf("prefixContainsWordBoundary(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
}

func TestEnginesCovPrefixContainsLineAnchor(t *testing.T) {
	if prefixContainsLineAnchor(nil) {
		t.Error("prefixContainsLineAnchor(nil) = true, want false")
	}
	cases := []struct {
		pattern string
		want    bool
	}{
		{`(?m:^)`, true},
		{`(?m:$)`, true},
		{`(?m:a^b)`, true}, // reached by recursion, not at the root
		{`^abc`, false},    // \A is OpBeginText, not a LINE anchor
		{`abc`, false},
	}
	for _, testCase := range cases {
		re := enginesCovParse(t, testCase.pattern)
		if got := prefixContainsLineAnchor(re); got != testCase.want {
			t.Errorf("prefixContainsLineAnchor(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
}

func TestEnginesCovSimpleClassPrefix(t *testing.T) {
	// The shape simpleClassPrefix exists for: a fixed-count class run.
	tlo, count, ok := simpleClassPrefix(enginesCovParse(t, `[a-f]{3}`))
	if !ok || count != 3 {
		t.Fatalf("simpleClassPrefix(`[a-f]{3}`) = (_, %d, %v), want (_, 3, true)", count, ok)
	}
	// 'a' = 0x61 → low nibble 1, high nibble 6, so bit 6 of tlo[1] must be set.
	if tlo[0x1]&(1<<6) == 0 {
		t.Errorf("simpleClassPrefix(`[a-f]{3}`) Teddy low table missing 'a': tlo = %v", tlo)
	}

	// A capture around the whole repeat, and around the repeated element, are
	// both transparent — the emitted scan is identical either way.
	if _, count, ok := simpleClassPrefix(enginesCovParse(t, `([a-f]{3})`)); !ok || count != 3 {
		t.Errorf("simpleClassPrefix(capture of repeat) = (_, %d, %v), want (_, 3, true)", count, ok)
	}
	capturedChild := &syntax.Regexp{
		Op: syntax.OpRepeat, Min: 2, Max: 2,
		Sub: []*syntax.Regexp{{
			Op:  syntax.OpCapture,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'z'}}},
		}},
	}
	if _, count, ok := simpleClassPrefix(capturedChild); !ok || count != 2 {
		t.Errorf("simpleClassPrefix(repeat of captured literal) = (_, %d, %v), want (_, 2, true)", count, ok)
	}

	rejects := []struct {
		name string
		re   *syntax.Regexp
	}{
		// Unbounded / mismatched counts are not a fixed-width prefix.
		{"open_ended", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 1, Max: -1,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}},
		}},
		// A repeat node with no child cannot be inspected; the guard keeps
		// re.Sub[0] from panicking on a malformed/synthesised tree.
		{"repeat_without_child", &syntax.Regexp{Op: syntax.OpRepeat, Min: 2, Max: 2}},
		// An empty char class sets no bits, so there is no byte the SIMD
		// prefix scan could ever match — emitting a scan for it would make
		// every position a candidate.
		{"empty_char_class", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpCharClass}},
		}},
		// Non-ASCII is out of scope: the tables are 128-entry.
		{"non_ascii_class", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpCharClass, Rune: []rune{0x100, 0x200}}},
		}},
		{"multi_rune_literal", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a', 'b'}}},
		}},
		{"unsupported_child_op", &syntax.Regexp{
			Op: syntax.OpRepeat, Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpAnyChar}},
		}},
	}
	for _, testCase := range rejects {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, ok := simpleClassPrefix(testCase.re); ok {
				t.Errorf("simpleClassPrefix(%s) accepted, want rejected", testCase.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// counted_chain.go — isCountedClassChain
//
// The detector runs over an already-built *dfaTable, so a synthetic table is
// both the cheapest and the most precise way to test each rejection: it pins
// the exact table property being rejected instead of hoping some pattern
// compiles to it.
// ---------------------------------------------------------------------------

// enginesCovChainTable builds a linear N-step chain over byteClass starting at
// state 0, ending in an accepting terminal state N with no live transitions —
// the exact shape isCountedClassChain is meant to accept.
func enginesCovChainTable(steps int, byteClass []byte) *dfaTable {
	numStates := steps + 1
	transitions := make([]int, numStates*256)
	for slot := range transitions {
		transitions[slot] = -1
	}
	for state := 0; state < steps; state++ {
		for _, classByte := range byteClass {
			transitions[state*256+int(classByte)] = state + 1
		}
	}
	return &dfaTable{
		startState:            0,
		numStates:             numStates,
		acceptStates:          map[int]uint64{steps: 1},
		midAcceptStates:       map[int]uint64{steps: 1},
		midAcceptNWStates:     map[int]uint64{},
		midAcceptWStates:      map[int]uint64{},
		midAcceptNLStates:     map[int]uint64{},
		immediateAcceptStates: map[int]uint64{},
		transitions:           transitions,
	}
}

func TestEnginesCovIsCountedClassChain(t *testing.T) {
	class := []byte{'a', 'b', 'c'}

	t.Run("accepts_exact_chain", func(t *testing.T) {
		got, n, ok := isCountedClassChain(enginesCovChainTable(4, class))
		if !ok || n != 4 {
			t.Fatalf("isCountedClassChain(4-step chain) = (_, %d, %v), want (_, 4, true)", n, ok)
		}
		if !bytes.Equal(got, class) {
			t.Errorf("recovered class = %v, want %v", got, class)
		}
	})

	// The accept channels are NOT interchangeable, and the split below is the
	// whole point of the S10 fix (tools/fuzz FuzzSet; custom-sets.txt Category
	// S10). The emitted body verifies N class bytes with SIMD and reports a
	// match with no end-of-input test and no knowledge of the preceding byte —
	// so it is sound only for a terminal that accepts at an ARBITRARY
	// position. midAccept and immediateAccept mean exactly that. acceptStates
	// (end-of-input only) and the three boundary-gated channels do not: `.$`
	// accepted through the EOF channel reported a match at EVERY position,
	// yielding [0-1] and [1-2] over "00" where Go yields [1-2] alone.
	acceptsAnywhereChannels := []struct {
		name string
		set  func(*dfaTable, int)
	}{
		{"midAccept", func(table *dfaTable, s int) { table.midAcceptStates[s] = 1 }},
		{"immediateAccept", func(table *dfaTable, s int) { table.immediateAcceptStates[s] = 1 }},
	}
	for _, channel := range acceptsAnywhereChannels {
		t.Run("terminal_accepts_via_"+channel.name, func(t *testing.T) {
			table := enginesCovChainTable(3, class)
			delete(table.acceptStates, 3)
			delete(table.midAcceptStates, 3)
			channel.set(table, 3)
			if _, n, ok := isCountedClassChain(table); !ok || n != 3 {
				t.Errorf("chain accepting only via %s = (_, %d, %v), want (_, 3, true)", channel.name, n, ok)
			}
		})
	}

	positionDependentChannels := []struct {
		name string
		set  func(*dfaTable, int)
	}{
		{"acceptStates_eof_only", func(table *dfaTable, s int) { table.acceptStates[s] = 1 }},
		{"midAcceptNW", func(table *dfaTable, s int) { table.midAcceptNWStates[s] = 1 }},
		{"midAcceptW", func(table *dfaTable, s int) { table.midAcceptWStates[s] = 1 }},
		{"midAcceptNL", func(table *dfaTable, s int) { table.midAcceptNLStates[s] = 1 }},
	}
	for _, channel := range positionDependentChannels {
		t.Run("rejects_terminal_accepting_only_via_"+channel.name, func(t *testing.T) {
			table := enginesCovChainTable(3, class)
			delete(table.acceptStates, 3)
			delete(table.midAcceptStates, 3)
			channel.set(table, 3)
			if _, _, ok := isCountedClassChain(table); ok {
				t.Errorf("a terminal accepting only via %s was accepted; the fixed-N "+
					"SIMD body has no end-of-input test and cannot see the preceding "+
					"byte, so it would report this match at every position", channel.name)
			}
		})
	}

	t.Run("rejects_no_accept_bits", func(t *testing.T) {
		// bits == 0: nothing accepts anywhere, so there is no chain length to
		// report and the walk would run to the terminal and claim success.
		table := enginesCovChainTable(3, class)
		delete(table.acceptStates, 3)
		delete(table.midAcceptStates, 3)
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("table with no accepting state accepted, want rejected")
		}
	})

	t.Run("rejects_multi_pattern_bucket", func(t *testing.T) {
		// Two distinct pattern bits means a merged bucket: the detector does
		// not track per-pattern chains, so it must decline.
		table := enginesCovChainTable(3, class)
		table.acceptStates[3] = 0b11
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("two-pattern accept mask accepted, want rejected")
		}
	})

	t.Run("rejects_cycle", func(t *testing.T) {
		// A self-loop is `{N,}`, not `{N}` — walking it would never terminate
		// without the visited check.
		table := enginesCovChainTable(2, class)
		for _, classByte := range class {
			table.transitions[1*256+int(classByte)] = 1
		}
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("self-looping table accepted, want rejected")
		}
	})

	t.Run("rejects_chain_over_maxchain", func(t *testing.T) {
		// The 256-step cap bounds both the walk and the unrolled emission the
		// caller would produce from the result.
		if _, _, ok := isCountedClassChain(enginesCovChainTable(300, class)); ok {
			t.Error("300-step chain accepted, want rejected (maxChain is 256)")
		}
	})

	t.Run("rejects_word_boundary_table", func(t *testing.T) {
		table := enginesCovChainTable(3, class)
		table.hasWordBoundary = true
		if _, _, ok := isCountedClassChain(table); ok {
			t.Error("hasWordBoundary table accepted, want rejected")
		}
	})
}

// ---------------------------------------------------------------------------
// wasm.go — parseDataSegments
//
// Every one of these guards fires only on bytes this compiler did not itself
// emit. They are the difference between an attributable panic and a silent
// mis-parse that hands a later stage the wrong table offsets, so they are
// worth pinning even though the public API cannot reach them.
// ---------------------------------------------------------------------------

func TestEnginesCovParseDataSegments(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		var raw []byte
		raw = appendDataSegment(raw, 4096, []byte{1, 2, 3})
		raw = appendDataSegment(raw, 8192, []byte{9})
		segs := parseDataSegments(raw)
		if len(segs) != 2 {
			t.Fatalf("parseDataSegments: got %d segments, want 2", len(segs))
		}
		if segs[0].offset != 4096 || !bytes.Equal(segs[0].data, []byte{1, 2, 3}) {
			t.Errorf("segment 0 = %+v, want offset 4096 data [1 2 3]", segs[0])
		}
		if segs[1].offset != 8192 || !bytes.Equal(segs[1].data, []byte{9}) {
			t.Errorf("segment 1 = %+v, want offset 8192 data [9]", segs[1])
		}
	})

	t.Run("stops_at_non_active_segment", func(t *testing.T) {
		// Only type-0 (active, memory 0) segments are understood; anything
		// else ends the scan rather than being misread as one.
		raw := append(appendDataSegment(nil, 16, []byte{7}), 0x01)
		segs := parseDataSegments(raw)
		if len(segs) != 1 {
			t.Fatalf("parseDataSegments: got %d segments, want 1 (trailing type-1 must end the scan)", len(segs))
		}
	})

	t.Run("stops_when_offset_opcode_missing", func(t *testing.T) {
		// A type byte with no i32.const behind it is truncated input, not a
		// segment: the scan stops instead of decoding whatever follows.
		if segs := parseDataSegments([]byte{0x00}); segs != nil {
			t.Errorf("parseDataSegments(truncated) = %v, want nil", segs)
		}
		if segs := parseDataSegments([]byte{0x00, 0x42}); segs != nil {
			t.Errorf("parseDataSegments(wrong offset opcode) = %v, want nil", segs)
		}
	})

	t.Run("panics_on_malformed_offset", func(t *testing.T) {
		// 0x80 with no continuation byte is an unterminated SLEB128.
		defer func() {
			if recover() == nil {
				t.Error("parseDataSegments(malformed offset): no panic, want invariant-violation panic")
			}
		}()
		parseDataSegments([]byte{0x00, 0x41, 0x80})
	})

	t.Run("panics_on_malformed_size", func(t *testing.T) {
		// Well-formed offset (0), well-formed 0x0b terminator, unterminated
		// ULEB128 size.
		defer func() {
			if recover() == nil {
				t.Error("parseDataSegments(malformed size): no panic, want invariant-violation panic")
			}
		}()
		parseDataSegments([]byte{0x00, 0x41, 0x00, 0x0b, 0x80})
	})
}

// ---------------------------------------------------------------------------
// compile.go — small public/internal surface
// ---------------------------------------------------------------------------

func TestEnginesCovNeedsUnicodeSupport(t *testing.T) {
	// tools/fuzz pre-filters with this exact predicate, so a wrong answer here
	// silently changes what the fuzzer is allowed to feed the compiler.
	cases := []struct {
		pattern string
		want    bool
	}{
		{`abc`, false},
		{`[a-z]+`, false},
		{`\x80`, true}, // pure-ASCII source text, non-ASCII codepoint
		{`[\x{100}-\x{200}]`, true},
	}
	for _, testCase := range cases {
		got, err := NeedsUnicodeSupport(testCase.pattern)
		if err != nil {
			t.Errorf("NeedsUnicodeSupport(%q): %v", testCase.pattern, err)
			continue
		}
		if got != testCase.want {
			t.Errorf("NeedsUnicodeSupport(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
	if _, err := NeedsUnicodeSupport(`(`); err == nil {
		t.Error("NeedsUnicodeSupport(`(`): no error, want a parse error")
	}
}

func TestEnginesCovCompileForcedRejectsBadEngine(t *testing.T) {
	// forceGroupsEngine only ever selects between the two capture engines;
	// accepting EngineDFA here would silently compile as if nothing had been
	// forced, which is exactly the confusion the guard exists to prevent.
	for _, bad := range []EngineType{EngineDFA, EngineCompiledDFA, EngineType(99)} {
		_, _, err := CompileForced(
			[]config.RegexEntry{{Pattern: "(a)", GroupsFunc: "g"}}, 0, true, bad)
		if err == nil {
			t.Errorf("CompileForced(forceGroupsEngine=%v): no error, want rejection", bad)
		}
	}
}

func TestEnginesCovCompileForcedHonoursUserOpts(t *testing.T) {
	// The variadic userOpts is how callers combine forcing with a limit; if it
	// were dropped, MaxDFAStates below would be ignored and the pattern would
	// compile on the TDFA path instead of the forced Backtracking one.
	wasm, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: "(a)(b)", GroupsFunc: "g"}},
		0, true, EngineBacktrack,
		CompileOptions{MaxDFAStates: 512},
	)
	if err != nil {
		t.Fatalf("CompileForced with userOpts: %v", err)
	}
	if !bytes.HasPrefix(wasm, wasmMagic) {
		t.Fatal("CompileForced with userOpts: output is not a WASM module")
	}
	validateWASM(t, wasm)
}

func TestEnginesCovStripSegCount(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if raw, count := stripSegCount(nil); raw != nil || count != 0 {
			t.Errorf("stripSegCount(nil) = (%v, %d), want (nil, 0)", raw, count)
		}
	})
	t.Run("panics_on_malformed_count", func(t *testing.T) {
		// Only reachable if a caller hands stripSegCount something other than
		// appendDataSegment's own output; the panic is deliberate (see its doc
		// comment) so that a compiler bug cannot degrade into a silent nil.
		defer func() {
			if recover() == nil {
				t.Error("stripSegCount(unterminated LEB128): no panic, want invariant-violation panic")
			}
		}()
		stripSegCount([]byte{0x80})
	})
}

// ---------------------------------------------------------------------------
// selector.go — engine-selection predicates
//
// CLAUDE.md calls these gates load-bearing: relaxing one has caused measured
// regressions. Direct tests pin the exact answer for shapes the corpus does
// not produce, so a future "obviously this is deterministic" edit fails loudly.
// ---------------------------------------------------------------------------

func TestEnginesCovIsAlternationDeterministic(t *testing.T) {
	prog := enginesCovProg(t, `(a)|(b)`)

	// Out-of-range PC: callers index prog.Inst with the value they pass, so a
	// bad PC must be rejected rather than panic.
	if isAlternationDeterministic(prog, len(prog.Inst), false) {
		t.Error("isAlternationDeterministic(out-of-range PC) = true, want false")
	}
	// A PC that is not an alternation at all cannot be "deterministic".
	runePC := enginesCovFindInst(t, prog, syntax.InstRune1)
	if isAlternationDeterministic(prog, runePC, false) {
		t.Error("isAlternationDeterministic(non-Alt PC) = true, want false")
	}
}

func TestEnginesCovIsEpsilonAccept(t *testing.T) {
	// `(?:\b)?x` puts an InstEmptyWidth on the path to InstMatch; without the
	// InstEmptyWidth arm the walk would stop early and report "not an epsilon
	// accept", which is what feeds isAlternationDeterministic's one-branch-
	// accepts-empty rule.
	prog := enginesCovProg(t, `\b|x`)
	emptyPC := enginesCovFindInst(t, prog, syntax.InstEmptyWidth)
	if !isEpsilonAccept(prog, emptyPC) {
		t.Errorf("isEpsilonAccept(InstEmptyWidth leading to Match) = false, want true\n%v", prog)
	}
}

func TestEnginesCovGetFirstRuneSet(t *testing.T) {
	t.Run("empty_width_is_transparent", func(t *testing.T) {
		// `\bab` — the first-rune set must see through the boundary assertion
		// to 'a', or every word-boundary alternation looks indeterminate.
		prog := enginesCovProg(t, `\bab`)
		emptyPC := enginesCovFindInst(t, prog, syntax.InstEmptyWidth)
		runes := getFirstRuneSet(prog, emptyPC)
		if !runes['a'] {
			t.Errorf("getFirstRuneSet through InstEmptyWidth = %v, want to contain 'a'", runes)
		}
	})

	t.Run("alt_with_unbounded_branch_fails", func(t *testing.T) {
		// The Out branch is InstRuneAny, which cannot be enumerated. The Alt
		// arm must propagate that failure instead of returning just the
		// enumerable half: a partial set would make the alternation look
		// disjoint and route an ambiguous pattern to TDFA (CLAUDE.md Gap I).
		// Built by hand because the parser folds every `.|x` spelling of this
		// down to a bare `any` before an InstAlt is ever emitted.
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 2},
				{Op: syntax.InstRuneAny},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		if runes := getFirstRuneSet(prog, 0); len(runes) != 0 {
			t.Errorf("getFirstRuneSet(Alt with un-enumerable branch) = %v, want the empty set", runes)
		}
	})

	t.Run("terminal_ops_fail", func(t *testing.T) {
		// InstFail has no successor and no runes; the default arm answers
		// "cannot enumerate", which the caller reads as the empty set — and an
		// empty set is never treated as disjoint by isAlternationDeterministic.
		failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
		if runes := getFirstRuneSet(failProg, 0); len(runes) != 0 {
			t.Errorf("getFirstRuneSet(InstFail) = %v, want the empty set", runes)
		}
	})

	t.Run("cycle_terminates", func(t *testing.T) {
		// A self-referential Alt must be stopped by the visited set; without
		// it this recurses forever.
		cyclic := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 0},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		runes := getFirstRuneSet(cyclic, 0)
		if !runes['a'] {
			t.Errorf("getFirstRuneSet(self-referential Alt) = %v, want to contain 'a'", runes)
		}
	})
}

func TestEnginesCovEstimateDFAComplexityClampsMultiplier(t *testing.T) {
	// The 3.0 clamp is what keeps a many-branch alternation from producing an
	// absurd state estimate and being rejected before the real DFA is tried.
	analysis := &patternAnalysis{NumInstructions: 100, NumAlternations: 50}
	analysis.estimateDFAComplexity()
	if analysis.EstimatedDFAStates != 300 {
		t.Errorf("EstimatedDFAStates = %d, want 300 (100 instructions × clamped 3.0)",
			analysis.EstimatedDFAStates)
	}
}

func TestEnginesCovSelectBestEngineDebugLogging(t *testing.T) {
	// The debug branch calls printAnalysis and builds a slog record; it is
	// skipped entirely at the default level, so nothing else ever runs it.
	// A wrong field name or a nil deref in there would only ever surface for a
	// user who turned debug logging on.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug logging not enabled after SetDefault; test would not reach the branch")
	}

	// A Unicode pattern also picks the "Unicode" complexity label, which is
	// only computed on this path.
	prog := enginesCovProg(t, `[\x{100}-\x{200}](a)`)
	opts := CompileOptions{Unicode: true}
	if engine, _ := selectBestEngineWithTDFA(prog, &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

// ---------------------------------------------------------------------------
// engine_tdfa.go — epsilon capture walks
//
// Both walks are pure and take an explicit visited set, so the guards can be
// driven exactly. They decide which capture registers a transition writes;
// a walk that returns the wrong ops writes the wrong span, silently.
// ---------------------------------------------------------------------------

func TestEnginesCovTDFAEpsCapOps(t *testing.T) {
	t.Run("falls_back_to_alt_arg", func(t *testing.T) {
		// Out leads to InstFail (no target), so the walk must try Arg. A
		// non-recursing implementation would report "no target" for the whole
		// alternation and lose the Arg branch's capture entirely.
		prog := &syntax.Prog{
			Inst: []syntax.Inst{
				{Op: syntax.InstAlt, Out: 1, Arg: 2},
				{Op: syntax.InstFail},
				{Op: syntax.InstCapture, Arg: 2, Out: 3},
				{Op: syntax.InstRune1, Rune: []rune{'a'}},
			},
			Start: 0,
		}
		target, ops := tdfaEpsCapOps(prog, 0, map[int]bool{})
		if target != 3 {
			t.Fatalf("tdfaEpsCapOps target = %d, want 3 (via Alt.Arg)", target)
		}
		if len(ops) != 1 || !ops[0].open || ops[0].group != 1 {
			t.Errorf("tdfaEpsCapOps ops = %+v, want one open of group 1", ops)
		}
	})

	t.Run("unhandled_op_has_no_target", func(t *testing.T) {
		failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
		if target, ops := tdfaEpsCapOps(failProg, 0, map[int]bool{}); target != -1 || ops != nil {
			t.Errorf("tdfaEpsCapOps(InstFail) = (%d, %v), want (-1, nil)", target, ops)
		}
	})
}

func TestEnginesCovTDFAEpsCapOpsTo(t *testing.T) {
	// InstEmptyWidth on the way to the target must be walked through, and the
	// capture recorded — this is the `\b(x)` shape.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstCapture, Arg: 2, Out: 1},
			{Op: syntax.InstEmptyWidth, Out: 2},
			{Op: syntax.InstRune1, Rune: []rune{'x'}},
		},
		Start: 0,
	}
	ok, ops := tdfaEpsCapOpsTo(prog, 0, 2, map[int]bool{})
	if !ok {
		t.Fatalf("tdfaEpsCapOpsTo through InstEmptyWidth = false, want true")
	}
	if len(ops) != 1 || !ops[0].open || ops[0].group != 1 {
		t.Errorf("tdfaEpsCapOpsTo ops = %+v, want one open of group 1", ops)
	}

	// Already-visited and out-of-range starts must both answer "not found"
	// rather than recursing or indexing out of bounds.
	if ok, _ := tdfaEpsCapOpsTo(prog, 0, 2, map[int]bool{0: true}); ok {
		t.Error("tdfaEpsCapOpsTo(already visited) = true, want false")
	}
	if ok, _ := tdfaEpsCapOpsTo(prog, -1, 2, map[int]bool{}); ok {
		t.Error("tdfaEpsCapOpsTo(negative PC) = true, want false")
	}

	// An op the switch does not handle is not a path to the target.
	failProg := &syntax.Prog{Inst: []syntax.Inst{{Op: syntax.InstFail}}, Start: 0}
	if ok, ops := tdfaEpsCapOpsTo(failProg, 0, 5, map[int]bool{}); ok || ops != nil {
		t.Errorf("tdfaEpsCapOpsTo(InstFail) = (%v, %v), want (false, nil)", ok, ops)
	}
}

// ---------------------------------------------------------------------------
// whole_capture.go / mandatory_lit.go / prefix_scan.go — small helpers
// ---------------------------------------------------------------------------

func TestEnginesCovIsWholePatternSingleCapture(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"bare_capture", `(abc)`, true},
		{"anchored_capture", `^(abc)$`, true},
		{"boundary_wrapped_capture", `\b(abc)\b`, true},
		// One capture, but the pattern's root is a quantifier rather than the
		// capture or a concat — the capture's span is then not the whole
		// match, so the shortcut must decline.
		{"starred_capture", `(abc)*`, false},
		// A non-zero-width sibling means the capture is a proper substring.
		{"capture_with_literal_sibling", `x(abc)`, false},
		{"two_captures", `(a)(b)`, false},
		{"no_capture", `abc`, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			re := enginesCovParse(t, testCase.pattern)
			if got := isWholePatternSingleCapture(re); got != testCase.want {
				t.Errorf("isWholePatternSingleCapture(%q) = %v, want %v (root op %v)",
					testCase.pattern, got, testCase.want, re.Op)
			}
		})
	}

	// Two OpCapture siblings that share a group number cannot come from the
	// parser, but the sawCapture guard is what makes the "one capture spans
	// the match" claim safe for any tree the analysers may hand it.
	duplicated := &syntax.Regexp{
		Op: syntax.OpConcat,
		Sub: []*syntax.Regexp{
			{Op: syntax.OpCapture, Cap: 1, Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}}},
			{Op: syntax.OpCapture, Cap: 1, Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'b'}}}},
		},
	}
	if isWholePatternSingleCapture(duplicated) {
		t.Error("isWholePatternSingleCapture(two capture siblings) = true, want false")
	}
}

func TestEnginesCovEmitShuftiPrefixCheckEmptySet(t *testing.T) {
	// The caller's useSIMD gate makes an empty candidate set unreachable in
	// the compiler, but the emitter must still leave a well-typed i32 on the
	// stack — returning nothing would produce a module that fails validation.
	got := emitShuftiPrefixCheck(nil, nil, 9)
	if !bytes.Equal(got, []byte{0x41, 0x00}) {
		t.Errorf("emitShuftiPrefixCheck(empty set) = % x, want 41 00 (i32.const 0)", got)
	}
}

// ---------------------------------------------------------------------------
// engine_backtrack.go — dominator-based loop classification
// ---------------------------------------------------------------------------

func TestEnginesCovDominatesUnreachable(t *testing.T) {
	// idom == -1 marks a PC the dominator pass never reached. Answering "true"
	// for such a node would register a phantom back edge and allocate a loop
	// local for a loop that does not exist.
	idom := []int{0, -1, 0}
	if dominates(idom, 0, 1) {
		t.Error("dominates(v=0, unreachable u=1) = true, want false")
	}
	if dominates(idom, 1, 2) {
		t.Error("dominates(unreachable v=1, u=2) = true, want false")
	}
	if !dominates(idom, 0, 2) {
		t.Error("dominates(root v=0, u=2) = false, want true")
	}
	if dominates(idom, 2, 0) {
		t.Error("dominates(v=2, root u=0) = true, want false (walk must stop at the root)")
	}
}

func TestEnginesCovBTEmitSingleRangeClampsNonASCII(t *testing.T) {
	// btCheckRuneRanges filters lo>0x7F and clamps hi before calling in, so
	// these guards are btEmitSingleRange's own contract rather than a live
	// path. They matter because the emitted comparison runs against a single
	// input BYTE: a lo above 0x7F can never match, and an unclamped hi would
	// emit an SLEB128 constant wider than the byte it is compared with.
	if got := btEmitSingleRange(nil, 0x100, 0x200); got != nil {
		t.Errorf("btEmitSingleRange(lo=0x100) emitted % x, want nothing", got)
	}
	clamped := btEmitSingleRange(nil, 'a', 0x200)
	reference := btEmitSingleRange(nil, 'a', 0x7F)
	if !bytes.Equal(clamped, reference) {
		t.Errorf("btEmitSingleRange(hi=0x200) = % x, want the hi=0x7F emission % x", clamped, reference)
	}
}

// ---------------------------------------------------------------------------
// compile.go — Backtracking fallback limits on the ANCHORED-match and
// capture paths.
//
// compile_test.go already covers each of these limits on the find path. The
// match and groups paths carry their own copies of the same four checks, and
// an omission there is not hypothetical: it produces a module that either
// declares invalid memory or takes seconds per call, with no attribution.
// ---------------------------------------------------------------------------

func TestEnginesCovMatchPathBTLimits(t *testing.T) {
	t.Run("loop_count", func(t *testing.T) {
		// Same shape as TestCompileBTLoopCountTooLarge, reached through
		// match_func instead of find_func.
		pattern := strings.Repeat(`(?:$*llllllll0)`, 114)
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}}, 0, true)
		if !errors.Is(err, ErrBTLoopCountTooLarge) {
			t.Fatalf("Compile(match): err = %v, want ErrBTLoopCountTooLarge", err)
		}
	})

	t.Run("empty_body_loop_chain", func(t *testing.T) {
		// The anchored DFA for this shape fits comfortably under the default
		// state cap, so unlike the find path it has to be pushed onto the
		// Backtracking fallback explicitly before the chain guard is reached.
		pattern := `(?m:` + strings.Repeat(`$*`, 16) + `0$)`
		_, _, err := Compile(
			[]config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}}, 65536, true,
			CompileOptions{MaxDFAStates: 1},
		)
		if !errors.Is(err, ErrBTEmptyBodyLoopChainTooLarge) {
			t.Fatalf("Compile(match): err = %v, want ErrBTEmptyBodyLoopChainTooLarge", err)
		}
	})
}

// ---------------------------------------------------------------------------
// engine_backtrack.go — first-byte extraction for the BT find prologue
// ---------------------------------------------------------------------------

func TestEnginesCovNFAFirstBytesCaseFold(t *testing.T) {
	// Go's compiler encodes a case-insensitive literal as InstRune with an
	// ODD-length Rune slice plus the FoldCase flag, so the scan tables are
	// only correct if nfaFirstBytes adds the opposite-case byte itself. Miss
	// it and BT find skips every position whose first byte is the uppercase
	// spelling.
	prog := enginesCovProg(t, `(?i)abc`)
	firstBytes, flags, allBytes := nfaFirstBytes(prog)
	if allBytes {
		t.Fatal("nfaFirstBytes((?i)abc) reported allBytes, want a concrete set")
	}
	if flags['a'] == 0 || flags['A'] == 0 {
		t.Errorf("nfaFirstBytes((?i)abc) = %q, want both cases of 'a'", string(firstBytes))
	}

	// A range spanning both cases folds every member, and folding a byte that
	// is already present must not duplicate it.
	prog = enginesCovProg(t, `(?i)[a-c]x`)
	firstBytes, flags, _ = nfaFirstBytes(prog)
	for _, want := range []byte{'a', 'b', 'c', 'A', 'B', 'C'} {
		if flags[want] == 0 {
			t.Errorf("nfaFirstBytes((?i)[a-c]x) = %q, missing %q", string(firstBytes), string(want))
		}
	}
	seen := map[byte]bool{}
	for _, firstByte := range firstBytes {
		if seen[firstByte] {
			t.Errorf("nfaFirstBytes returned %q twice in %q", string(firstByte), string(firstBytes))
		}
		seen[firstByte] = true
	}
}

func TestEnginesCovNFAFirstBytesFoldedRune1(t *testing.T) {
	// Go's own compiler never emits InstRune1 with FoldCase set (it downgrades
	// to InstRune first), so this arm is only reachable from a hand-built
	// program — but nfaFirstBytes takes any *syntax.Prog, and the arm is the
	// single-rune twin of the InstRune folding above. If it ever stopped
	// folding, a caller supplying such a program would get scan tables that
	// silently skip the opposite case.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstRune1, Rune: []rune{'q'}, Arg: uint32(syntax.FoldCase), Out: 1},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	_, flags, allBytes := nfaFirstBytes(prog)
	if allBytes {
		t.Fatal("nfaFirstBytes(folded InstRune1) reported allBytes")
	}
	if flags['q'] == 0 || flags['Q'] == 0 {
		t.Errorf("nfaFirstBytes(folded InstRune1 'q') did not set both cases: flags['q']=%d flags['Q']=%d",
			flags['q'], flags['Q'])
	}

	// Upper-case input folds the other direction.
	prog.Inst[0].Rune = []rune{'Q'}
	if _, flags, _ = nfaFirstBytes(prog); flags['q'] == 0 || flags['Q'] == 0 {
		t.Errorf("nfaFirstBytes(folded InstRune1 'Q') did not set both cases")
	}

	// A non-letter has no opposite case; the fold must add nothing rather
	// than the byte 32 positions away.
	prog.Inst[0].Rune = []rune{'5'}
	if _, flags, _ = nfaFirstBytes(prog); flags['5'] == 0 || flags['5'-32] != 0 || flags['5'+32] != 0 {
		t.Error("nfaFirstBytes(folded InstRune1 '5') folded a non-letter")
	}
}

func TestEnginesCovBuildBTScanTablesScalarFallback(t *testing.T) {
	var flags [256]byte
	flags['x'] = 1

	// allBytes: every byte can start a match, so the emitted flag table must
	// be all-ones regardless of what the (meaningless) flags argument says.
	_, segs, segCount := buildBTScanTables(nil, flags, true, 0)
	if segCount != 1 || len(segs) == 0 {
		t.Fatalf("buildBTScanTables(allBytes): segCount = %d, len(segs) = %d, want 1 and non-empty", segCount, len(segs))
	}
	parsed := parseDataSegments(segs)
	if len(parsed) != 1 || len(parsed[0].data) != 256 {
		t.Fatalf("buildBTScanTables(allBytes): emitted %d segments, want one 256-byte table", len(parsed))
	}
	for candidate, flag := range parsed[0].data {
		if flag != 1 {
			t.Fatalf("buildBTScanTables(allBytes): table[%d] = %d, want 1", candidate, flag)
		}
	}

	// The other scalar case: no candidate bytes at all. The caller's own
	// flags must be emitted verbatim — synthesising all-ones here would turn
	// a never-matching prefix into a scan that stops at every position.
	params, segs, segCount := buildBTScanTables(nil, flags, false, 0)
	if segCount != 1 {
		t.Fatalf("buildBTScanTables(empty set): segCount = %d, want 1", segCount)
	}
	if params.TeddyLoOff != 0 || params.TeddyHiOff != 0 {
		t.Errorf("buildBTScanTables(empty set) allocated Teddy tables: %+v", params)
	}
	parsed = parseDataSegments(segs)
	if len(parsed) != 1 || len(parsed[0].data) != 256 {
		t.Fatalf("buildBTScanTables(empty set): emitted %d segments, want one 256-byte table", len(parsed))
	}
	if parsed[0].data['x'] != 1 {
		t.Error("buildBTScanTables(empty set) did not emit the caller's flag table")
	}
	if parsed[0].data['y'] != 0 {
		t.Error("buildBTScanTables(empty set) set a byte the caller's flags did not")
	}
}

// ---------------------------------------------------------------------------
// engine_backtrack.go — loop classification and the WASM it drives
// ---------------------------------------------------------------------------

func TestEnginesCovAltLoopBodyBothBranchesBackEdges(t *testing.T) {
	// An Alt where BOTH targets dominate it is at once
	// an inner loop's back edge and an enclosing loop's continuation. The
	// classifier must pick the more-local (dominated) target as the body; a
	// naive "ambiguous, give up" answer loses the inner loop's zero-progress
	// guard entirely. `(?:(?:a)+)*` is the smallest shape that produces it.
	for _, pattern := range []string{`(?:(?:a)+)*`, `(?:(?:a)+?)*`, `(?:(?:a){1,})*`} {
		prog := enginesCovProg(t, pattern)
		idom := computeDominators(prog)
		sawBothBack := false
		for pc, inst := range prog.Inst {
			if inst.Op != syntax.InstAlt && inst.Op != syntax.InstAltMatch {
				continue
			}
			if !dominates(idom, int(inst.Out), pc) || !dominates(idom, int(inst.Arg), pc) {
				continue
			}
			sawBothBack = true
			bodyPC, exitPC, isLoop := altLoopBody(prog, idom, pc)
			if !isLoop {
				t.Errorf("%s: altLoopBody(pc=%d) rejected an Alt whose branches are both back edges", pattern, pc)
				continue
			}
			if bodyPC == exitPC {
				t.Errorf("%s: altLoopBody(pc=%d) returned body == exit == %d", pattern, pc, bodyPC)
			}
			if bodyPC != int(inst.Out) && bodyPC != int(inst.Arg) {
				t.Errorf("%s: altLoopBody(pc=%d) body %d is neither branch target", pattern, pc, bodyPC)
			}
		}
		if !sawBothBack {
			t.Errorf("%s: no Alt with two back edges — the witness pattern no longer has the shape", pattern)
		}
	}
}

func TestEnginesCovAltLoopBodyStartAltArgBackEdge(t *testing.T) {
	// prog.Start is its own immediate dominator, so a loop
	// whose head IS the entry has no dominance-visible back edge and needs the
	// forward-reachability fallback. `(?:a)*?` puts a NON-greedy loop there,
	// which makes Arg (not Out) the back edge — the mirror of the greedy case.
	prog := enginesCovProg(t, `(?:a)*?`)
	idom := computeDominators(prog)
	inst := prog.Inst[prog.Start]
	if inst.Op != syntax.InstAlt && inst.Op != syntax.InstAltMatch {
		t.Fatalf("prog.Start (pc=%d) is %v, not an Alt — witness pattern no longer has the shape", prog.Start, inst.Op)
	}
	bodyPC, _, isLoop := altLoopBody(prog, idom, prog.Start)
	if !isLoop {
		t.Fatalf("altLoopBody(prog.Start) = not a loop, want the Arg branch recognised as the body")
	}
	if bodyPC != int(inst.Arg) {
		t.Errorf("altLoopBody(prog.Start) body = %d, want Arg = %d (non-greedy loop)", bodyPC, inst.Arg)
	}
}

func TestEnginesCovNestedLoopPCRejectsImmediateHead(t *testing.T) {
	// `(?:^)*`'s loop body is the head itself: the walk must stop instead of
	// reporting the head as its own nested inner loop, which would memoise a
	// PC that already has a zero-progress guard.
	// `(?:())*` is the tightest case: the walk from the body start passes
	// only through capture instructions and arrives back at the head itself.
	// `(?:^)*` is the other shape — an assertion stops the walk before any
	// branch is seen.
	for _, pattern := range []string{`(?:())*`, `(?:^)*`} {
		prog := enginesCovProg(t, pattern)
		backtracker := newBacktrack(prog)
		if len(backtracker.emptyBodyGreedyLoop) == 0 {
			t.Fatalf("%s produced no empty-body greedy loop — witness pattern no longer has the shape", pattern)
		}
		for headPC := range backtracker.emptyBodyGreedyLoop {
			if innerPC, found := nestedLoopPC(prog, backtracker.idom, headPC); found {
				t.Errorf("%s: nestedLoopPC(head=%d) = (%d, true), want not found", pattern, headPC, innerPC)
			}
		}
		if len(backtracker.memoInnerLoop) != 0 {
			t.Errorf("%s: memoInnerLoop = %v, want empty", pattern, backtracker.memoInnerLoop)
		}
	}
}

func TestEnginesCovBTLoopEntryAtStart(t *testing.T) {
	// A loop head whose body starts at prog.Start has no predecessor
	// instruction to record the entry position, so every body that tracks
	// loop entries has to seed it from the attempt's own start instead of the
	// usual -1 sentinel. There are four such bodies (capture, capture in
	// window mode, BT match, BT find) and each carries its own copy.
	prog := enginesCovProg(t, `(?:a??)+(x)`)
	if len(newBacktrack(prog).loopEntryAtStart) == 0 {
		t.Fatal("`(?:a??)+(x)` has no loopEntryAtStart head — witness pattern no longer has the shape")
	}

	t.Run("capture_body", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:a??)+(x)`, GroupsFunc: "g"}})
	})
	t.Run("capture_body_window_mode", func(t *testing.T) {
		// The word boundary is what turns on window mode, where the seed is
		// the window start rather than 0.
		mustCompileEntries(t, []config.RegexEntry{{Pattern: `(?:a??)+\b(x)`, GroupsFunc: "g"}})
	})
	t.Run("bt_match_body", func(t *testing.T) {
		mustCompileEntries(t,
			[]config.RegexEntry{{Pattern: `(?:a??)+x`, MatchFunc: "m"}},
			CompileOptions{MaxDFAStates: 1})
	})
	t.Run("bt_find_body", func(t *testing.T) {
		mustCompileEntries(t,
			[]config.RegexEntry{{Pattern: `(?:a??)+x`, FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 1})
	})
}

func TestEnginesCovBTLoopEntryViaArgEdge(t *testing.T) {
	// The instruction that enters a loop body can reach it through its Arg
	// branch as easily as through Out (`(?:x|(?:a*)+)`).
	// Recording only the Out edge corrupted loopEntryLocalIdx for exactly
	// this shape, so both maps and both emitters have to exist.
	pattern := `((?:x|(?:a*)+)y)`
	backtracker := newBacktrack(enginesCovProg(t, pattern))
	if len(backtracker.loopEntryArgOf) == 0 {
		t.Fatalf("%s has no loopEntryArgOf edge — witness pattern no longer has the shape", pattern)
	}
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true, EngineBacktrack)
	if err != nil {
		t.Fatalf("CompileForced(BT groups, arg-entry loop): %v", err)
	}
}

func TestEnginesCovBTWindowedBitState(t *testing.T) {
	// Window mode and BitState memoisation are independent features that meet
	// in one place: the memo bit index has to be rebased by the window start,
	// or the guard indexes the table with an absolute position and either
	// aliases another PC's bits or runs off the end.
	//
	// `\b` forces Backtracking and window mode (the capture body is composed
	// behind a find wrapper, so it does not see the caller's real ptr/len);
	// the `(?:a*)+` nest is what needsBitState answers true for.
	pattern := `(\b(?:a*)+b)`
	prog := enginesCovProg(t, pattern)
	if !needsBitState(prog) {
		t.Fatalf("%s does not need BitState — witness pattern no longer has the shape", pattern)
	}
	if len(newBacktrack(prog).memoInnerLoop) == 0 {
		t.Fatalf("%s has no memoInnerLoop PC — witness pattern no longer has the shape", pattern)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})

	// The same nest with a multiline anchor instead of a word boundary — the
	// other trigger for window mode.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `((?m:^)(?:a*)+b)`, GroupsFunc: "g"}})
}

func TestEnginesCovNFAFirstBytesFoldedRuneRange(t *testing.T) {
	// Go's parser normalises a folded ASCII letter to its UPPERCASE spelling
	// (the minimum of the fold orbit), so the lowercase→uppercase half of
	// nfaFirstBytes' InstRune folding is only reachable from a program built
	// by hand. Both halves have to work: this is the table that decides which
	// positions BT find is allowed to skip, and a missing case means skipping
	// a position where a match really starts.
	prog := &syntax.Prog{
		Inst: []syntax.Inst{
			// Odd-length Rune slice: the single-rune-at-odd-position shape
			// Go itself emits for `(?i)a`, but spelled lowercase.
			{Op: syntax.InstRune, Rune: []rune{'m'}, Arg: uint32(syntax.FoldCase), Out: 1},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if _, flags, _ := nfaFirstBytes(prog); flags['m'] == 0 || flags['M'] == 0 {
		t.Error("nfaFirstBytes(folded lowercase InstRune) did not set both cases")
	}

	// A digit range under FoldCase must not gain phantom bytes.
	prog.Inst[0].Rune = []rune{'0', '9'}
	_, flags, _ := nfaFirstBytes(prog)
	for candidate := 0; candidate < 256; candidate++ {
		want := byte(0)
		if candidate >= '0' && candidate <= '9' {
			want = 1
		}
		if flags[candidate] != want {
			t.Fatalf("nfaFirstBytes(folded digit range): flags[%d] = %d, want %d",
				candidate, flags[candidate], want)
		}
	}
}

func TestEnginesCovBTLoopEntrySentinelBodies(t *testing.T) {
	// The counterpart to TestEnginesCovBTLoopEntryAtStart: a loop head that
	// DOES have an external entry instruction gets the -1 sentinel, and the
	// entry instruction writes the real position at runtime. `a(?:b*)+` has
	// the loop body one instruction in, so its head is entered from outside.
	prog := enginesCovProg(t, `a(?:b*)+`)
	backtracker := newBacktrack(prog)
	if len(backtracker.loopEntryOutOf) == 0 || len(backtracker.loopEntryAtStart) != 0 {
		t.Fatalf("`a(?:b*)+` classification changed: outOf=%v atStart=%v",
			backtracker.loopEntryOutOf, backtracker.loopEntryAtStart)
	}
	t.Run("bt_match_body", func(t *testing.T) {
		mustCompileEntries(t,
			[]config.RegexEntry{{Pattern: `a(?:b*)+`, MatchFunc: "m"}},
			CompileOptions{MaxDFAStates: 1})
	})
	t.Run("bt_find_body", func(t *testing.T) {
		mustCompileEntries(t,
			[]config.RegexEntry{{Pattern: `a(?:b*)+`, FindFunc: "f"}},
			CompileOptions{MaxDFAStates: 1})
	})
}

func TestEnginesCovBTFindMandatoryLiteralLoopEntry(t *testing.T) {
	// BT find has TWO attempt loops — a flat one, and a two-level one used
	// when a mandatory interior literal gives the scan something rare to look
	// for. Each re-initialises the loop-entry locals itself, so the
	// loopEntryAtStart seeding has to be right in both. `(?:a??)+` supplies
	// the at-start loop head and `xyzzy` the mandatory literal.
	pattern := `(?:a??)+xyzzy`
	if len(newBacktrack(enginesCovProg(t, pattern)).loopEntryAtStart) == 0 {
		t.Fatalf("%s has no loopEntryAtStart head — witness pattern no longer has the shape", pattern)
	}
	mustCompileEntries(t,
		[]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

func TestEnginesCovBTComposedCaptureBodyWindowAndMemo(t *testing.T) {
	// Same features as TestEnginesCovBTWindowedBitState, but the capture must
	// NOT span the whole pattern: a whole-pattern single capture takes the
	// task-41 shortcut and never reaches the composed find+capture body where
	// window mode and the memo table actually meet.
	pattern := `(\b(?:a*)+b)c`
	prog := enginesCovProg(t, pattern)
	if !needsBitState(prog) {
		t.Fatalf("%s does not need BitState — witness pattern no longer has the shape", pattern)
	}
	if isWholePatternSingleCapture(enginesCovParse(t, pattern)) {
		t.Fatalf("%s is a whole-pattern single capture — it would bypass the composed body", pattern)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `((?m:^)(?:a*)+b)c`, GroupsFunc: "g"}})
}

func TestEnginesCovBTComposedCaptureBodyArgEntry(t *testing.T) {
	// The Arg-edge loop entry reached through the
	// composed capture body rather than the whole-pattern shortcut.
	pattern := `((?:x|(?:a*)+)y)z`
	if len(newBacktrack(enginesCovProg(t, pattern)).loopEntryArgOf) == 0 {
		t.Fatalf("%s has no loopEntryArgOf edge — witness pattern no longer has the shape", pattern)
	}
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true, EngineBacktrack)
	if err != nil {
		t.Fatalf("CompileForced(BT groups, arg-entry loop): %v", err)
	}
}

func TestEnginesCovBTNonASCIIRuneRange(t *testing.T) {
	// The BT rune-range check compares a single input BYTE, so a class range
	// that starts above 0x7F can never match and must be skipped rather than
	// emitted with a truncated constant that would match the wrong bytes.
	pattern := `([a-c\x{100}-\x{200}]+)x`
	_, _, err := CompileForced(
		[]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}},
		0, true, EngineBacktrack, CompileOptions{Unicode: true})
	if err != nil {
		t.Fatalf("CompileForced(BT groups, mixed ASCII/non-ASCII class): %v", err)
	}
}

// ---------------------------------------------------------------------------
// compile.go — remaining dispatch and fallback branches
// ---------------------------------------------------------------------------

func TestEnginesCovLitChainRangeNonGreedyFind(t *testing.T) {
	// A non-greedy `{N,M}?` find collapses to the fixed `{N,N}` emission: the
	// shortest match always takes exactly N repetitions. FABLE B10 is why the
	// anchored spellings are excluded from this path, so the witness must be
	// unanchored.
	// The range analyser also gates on N >= 24 outside LikelyMatch, so the
	// witness has to clear that too or it never reaches the greedy split.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `AKIA[A-Z0-9]{24,40}?`,
		FindFunc: "akia_nongreedy_find",
	}})
	// Greedy sibling, for contrast: same shape, different emitter.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `AKIA[A-Z0-9]{24,40}`,
		FindFunc: "akia_greedy_find",
	}})
}

// enginesCovHugeBTPattern returns a pattern whose NFA exceeds
// maxBTFallbackInstructions. A long literal is the cheapest shape that gets
// there: one instruction per byte, and its DFA is a linear chain that hits
// the state ceiling almost immediately, so the fallback is reached without
// paying for a large subset construction first.
func enginesCovHugeBTPattern(t *testing.T, suffix string) string {
	t.Helper()
	pattern := strings.Repeat("abcdefghij", 2100) + suffix
	if got := len(enginesCovProg(t, pattern).Inst); got <= maxBTFallbackInstructions {
		t.Skipf("witness pattern produces %d instructions, need > %d", got, maxBTFallbackInstructions)
	}
	return pattern
}

func TestEnginesCovBTProgramTooLarge(t *testing.T) {
	// maxBTFallbackInstructions bounds the br_table dispatch every
	// Backtracking body emits. Each of the four construction sites carries
	// its own copy of the check; an omission there emits a module with a
	// dispatch table large enough to make wasmtime's JIT the bottleneck.
	t.Run("match_fallback", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `x`)
		_, _, err := Compile(
			[]config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}}, 0, true,
			CompileOptions{MaxDFAStates: 1})
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(match): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
	t.Run("find_fallback", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `x`)
		_, _, err := Compile(
			[]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}, 0, true,
			CompileOptions{MaxDFAStates: 1})
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(find): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
	t.Run("groups", func(t *testing.T) {
		pattern := enginesCovHugeBTPattern(t, `(x)`)
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
	t.Run("compile_forced_engine", func(t *testing.T) {
		// The internal compile() entry point applies the same bound when a
		// caller asks for Backtracking directly.
		pattern := enginesCovHugeBTPattern(t, `x`)
		_, err := compile(pattern, CompileOptions{ForceEngine: EngineBacktrack})
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("compile(ForceEngine=Backtrack): err = %v, want ErrBTProgramTooLarge", err)
		}
	})
}

func TestEnginesCovGroupsPathBTLimits(t *testing.T) {
	// The capture path's own copies of the two Backtracking cost guards.
	// The trailing literal keeps each pattern off the whole-pattern
	// single-capture shortcut, which would bypass the guards entirely.
	t.Run("loop_count", func(t *testing.T) {
		pattern := strings.Repeat(`(?:$*llllllll0)`, 114) + `(x)y`
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTLoopCountTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTLoopCountTooLarge", err)
		}
	})
	t.Run("empty_body_loop_chain", func(t *testing.T) {
		pattern := `(?m:` + strings.Repeat(`$*`, 16) + `0$)(x)y`
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 65536, true)
		if !errors.Is(err, ErrBTEmptyBodyLoopChainTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTEmptyBodyLoopChainTooLarge", err)
		}
	})
}

func TestEnginesCovGroupsPathInputErrors(t *testing.T) {
	// The capture path parses the pattern itself rather than reusing an
	// earlier parse, so it needs its own error handling for both a syntax
	// error and a Unicode construct the engines cannot represent.
	t.Run("parse_error", func(t *testing.T) {
		_, _, err := Compile([]config.RegexEntry{{Pattern: `(`, GroupsFunc: "g"}}, 0, true)
		if err == nil {
			t.Fatal("Compile(groups, unbalanced paren): no error")
		}
	})
	t.Run("unicode_unsupported", func(t *testing.T) {
		_, _, err := Compile([]config.RegexEntry{{Pattern: `(\x{100})`, GroupsFunc: "g"}}, 0, true)
		if err == nil {
			t.Fatal("Compile(groups, non-ASCII class): no error")
		}
		if !strings.Contains(err.Error(), "Unicode") {
			t.Fatalf("Compile(groups, non-ASCII class): err = %v, want a Unicode-support error", err)
		}
	})
}

func TestEnginesCovFindPathDFACompileError(t *testing.T) {
	// The find path tolerates exactly one error from its DFA build — the
	// state-limit sentinel, which just means "fall back to Backtracking".
	// Any other error is a real failure and must be reported, not swallowed
	// into a silent Backtracking compile of a pattern the DFA rejected.
	_, _, err := Compile([]config.RegexEntry{{Pattern: `[\x{100}-\x{200}]x`, FindFunc: "f"}}, 0, true)
	if err == nil {
		t.Fatal("Compile(find, non-ASCII class): no error")
	}
}

func TestEnginesCovAltLitAnchorWithMatchBody(t *testing.T) {
	// The per-branch function indices are offset by one when a match body
	// occupies the first slot. Getting that offset wrong points the
	// dispatcher's calls at the wrong functions — a wrong answer, not a
	// crash, since the signatures happen to line up.
	pattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`
	entry := config.RegexEntry{Pattern: pattern, MatchFunc: "m", FindFunc: "f"}

	compiled, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if compiled.altLitAnchorBranches == nil {
		t.Fatalf("compilePattern did not take the alt-lit-anchor path for %q", pattern)
	}
	if compiled.matchBody == nil {
		t.Fatal("match_func was set but no match body was emitted; the offset case is not exercised")
	}
	back, fwd := compiled.altLitAnchorBranchFuncIdx(0)
	if back != 1 || fwd != 2 {
		t.Errorf("altLitAnchorBranchFuncIdx(0) = (%d, %d), want (1, 2) — slot 0 is the match body", back, fwd)
	}
	mustCompileEntries(t, []config.RegexEntry{entry})
}

func TestEnginesCovFindAltLitAnchorPointsUnwrapsBranchCaptures(t *testing.T) {
	// Branch-level captures are transparent to the anchor analysis: the same
	// alternation written with or without them must produce the same
	// branches, or a capture-bearing pattern silently loses the optimisation.
	plain, okPlain := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`)
	captured, okCaptured := findAltLitAnchorPoints(`([0-9]{8}ghp_[A-Za-z0-9]{36})|([a-f]{8}secret_[A-Za-z0-9]{36})`)
	if !okPlain || !okCaptured {
		t.Fatalf("findAltLitAnchorPoints: plain ok = %v, captured ok = %v, want both true", okPlain, okCaptured)
	}
	if len(plain) != len(captured) {
		t.Errorf("branch count: plain = %d, captured = %d", len(plain), len(captured))
	}
}

func TestEnginesCovCanConsumeNewlineRecursesIntoContainers(t *testing.T) {
	// A container's answer is its children's: `(?s)x.` cannot be decided from
	// the concat node itself, only from the OpAnyChar inside it. Char classes
	// that spell a newline get folded into a single OpCharClass by the parser,
	// so a container with a genuinely newline-consuming CHILD needs `(?s).`.
	if !canConsumeNewline(enginesCovParse(t, `(?s)x.`)) {
		t.Error("canConsumeNewline(`(?s)x.`) = false, want true (the concat's `.` matches '\\n')")
	}
	if canConsumeNewline(enginesCovParse(t, `x.y`)) {
		t.Error("canConsumeNewline(`x.y`) = true, want false (`.` is OpAnyCharNotNL)")
	}
}

func TestEnginesCovHasAmbiguousCapturesAltMatch(t *testing.T) {
	// InstAltMatch is a one-pass optimisation Go's own regexp package
	// installs; syntax.Compile never emits it, so this arm only guards
	// against a caller handing the selector such a program. It has to be
	// treated exactly like InstAlt: missing it would route an ambiguous
	// pattern to TDFA, where overlapping branches produce wrong capture
	// spans rather than a slower match.
	ambiguous := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstAltMatch, Out: 1, Arg: 2},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if !hasAmbiguousCaptures(ambiguous) {
		t.Error("hasAmbiguousCaptures(InstAltMatch with overlapping branches) = false, want true")
	}

	// Disjoint branches through the same instruction are not ambiguous.
	disjoint := &syntax.Prog{
		Inst: []syntax.Inst{
			{Op: syntax.InstAltMatch, Out: 1, Arg: 2},
			{Op: syntax.InstRune1, Rune: []rune{'a'}, Out: 3},
			{Op: syntax.InstRune1, Rune: []rune{'b'}, Out: 3},
			{Op: syntax.InstMatch},
		},
		Start: 0,
	}
	if hasAmbiguousCaptures(disjoint) {
		t.Error("hasAmbiguousCaptures(InstAltMatch with disjoint branches) = true, want false")
	}
}

func TestEnginesCovAnalysePatternUnicodeLabel(t *testing.T) {
	// The "Unicode" complexity label is only computed when the alternation
	// count stays under the "High alternations" threshold, and it is only
	// read on the debug-logging path.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prog := enginesCovProg(t, `[\x{100}-\x{200}](a)`)
	analysis := analysePattern(prog)
	if !analysis.HasUnicode {
		t.Fatalf("analysePattern did not flag Unicode for a >0x7F class: %+v", analysis)
	}
	if analysis.NumAlternations > 5 {
		t.Fatalf("witness pattern has %d alternations; the Unicode label is only chosen below 6",
			analysis.NumAlternations)
	}
	opts := CompileOptions{Unicode: true}
	if engine, _ := selectBestEngineWithTDFA(prog, &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

func TestEnginesCovShuftiRareFirstByteBand(t *testing.T) {
	// 17..64 candidate first bytes is the band where Shufti is chosen only if
	// the bytes are RARE enough that scalar cannot exit a chunk early. Control
	// bytes have rarity 0, so `[\x01-\x1f]` (31 bytes) is on the Shufti side
	// even without the LikelyNoMatch override — the one route into that arm.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: "[\x01-\x1f]xyz", FindFunc: "f"}})
	// The dense counterpart stays scalar: 52 letters, rarity sum far over the
	// threshold.
	mustCompileEntries(t, []config.RegexEntry{{Pattern: `[a-zA-Z]xyz`, FindFunc: "f2"}})
}

// ---------------------------------------------------------------------------
// compile.go — fallback branches that need the DFA and the Backtracking
// construction to disagree about the SAME pattern.
// ---------------------------------------------------------------------------

func TestEnginesCovGroupsOnlyBTLimits(t *testing.T) {
	// The find half of a groups compile normally trips the Backtracking
	// guards first, which is why the capture path's own copies stayed
	// unreached. Both witnesses here have a TINY DFA — so the find half stays
	// on the DFA path and never constructs a Backtracking engine — while
	// their Backtracking construction blows a limit. That is the only
	// configuration in which the capture path's copies decide the outcome.
	t.Run("program_too_large", func(t *testing.T) {
		// 21000 zero-width assertions: a huge NFA whose DFA is a couple of
		// states, and `\b` also keeps the capture path off TDFA.
		pattern := strings.Repeat(`(?:\b){1000}`, 21) + `(x)`
		if got := len(enginesCovProg(t, pattern).Inst); got <= maxBTFallbackInstructions {
			t.Skipf("witness pattern produces %d instructions, need > %d", got, maxBTFallbackInstructions)
		}
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTProgramTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTProgramTooLarge", err)
		}
	})

	t.Run("loop_count", func(t *testing.T) {
		// 40 `$*` loops separated by single literals: 80 loop-frame locals,
		// but the DFA is just `a{40}`. The trailing literal keeps it off the
		// whole-pattern single-capture shortcut.
		pattern := strings.Repeat(`(?:$*a)`, 40) + `(x)y`
		backtracker := newBacktrack(enginesCovProg(t, pattern))
		if got := btNumLoopFrameLocals(backtracker, true); got <= maxBTLoopFrameLocals {
			t.Skipf("witness pattern has %d loop-frame locals, need > %d", got, maxBTLoopFrameLocals)
		}
		_, _, err := Compile([]config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}}, 0, true)
		if !errors.Is(err, ErrBTLoopCountTooLarge) {
			t.Fatalf("Compile(groups): err = %v, want ErrBTLoopCountTooLarge", err)
		}
	})
}

func TestEnginesCovBTStackReservationOverCeiling(t *testing.T) {
	// A Backtracking stack reserved above WASM32's 4GiB
	// linear-memory ceiling used to produce a module whose memory section was
	// already invalid — a failure that only surfaced at instantiation time,
	// with no attribution to the pattern that caused it. A table base close
	// to the ceiling reaches the check without needing a pathological
	// pattern, and both the match and the find fallback carry their own copy.
	const nearCeiling = int64(1)<<32 - 4096
	for _, testCase := range []struct {
		name  string
		entry config.RegexEntry
	}{
		{"match_fallback", config.RegexEntry{Pattern: `abc`, MatchFunc: "m"}},
		{"find_fallback", config.RegexEntry{Pattern: `abc`, FindFunc: "f"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := Compile(
				[]config.RegexEntry{testCase.entry}, nearCeiling, true,
				CompileOptions{MaxDFAStates: 1})
			if !errors.Is(err, ErrBTStackTooLarge) {
				t.Fatalf("Compile: err = %v, want ErrBTStackTooLarge", err)
			}
		})
	}
}

func TestEnginesCovBTFallbackPrefixTruncation(t *testing.T) {
	// The Backtracking find fallback lifts the DFA's common prefix to drive a
	// SIMD scan, but the emitted scan compares a bounded window: a prefix
	// longer than maxBTFallbackPrefixLen must be truncated, not emitted whole.
	pattern := strings.Repeat("ab", 40) + `[0-9]`
	compiled, err := compilePattern(
		config.RegexEntry{Pattern: pattern, FindFunc: "f"}, 0, 0,
		CompileOptions{MaxDFAStates: 1})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if compiled.findBody == nil {
		t.Fatal("no find body emitted")
	}
	mustCompileEntries(t,
		[]config.RegexEntry{{Pattern: pattern, FindFunc: "f"}},
		CompileOptions{MaxDFAStates: 1})
}

// ---------------------------------------------------------------------------
// compile.go — batch groups wrapper
// ---------------------------------------------------------------------------

func TestEnginesCovBatchGroupsWrapperWindowMode(t *testing.T) {
	// The batch groups wrapper writes each match's extent into the window
	// scratch slot and then calls the capture body with the caller's REAL
	// (ptr,len) — the same window-mode contract the single-match wrapper has
	//. A Backtracking capture body with a
	// word boundary is what turns that on; a TDFA one never does.
	entry := config.RegexEntry{
		Pattern:    `(\b(?:a*)+b)c`,
		FindFunc:   "wf",
		GroupsFunc: "wg",
		Hints:      []string{"batch-find"},
	}
	t.Run("standalone", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{entry})
	})
	t.Run("embedded", func(t *testing.T) {
		// Embedded mode puts the tables in memory[1], which the batch
		// wrapper's scratch stores have to address explicitly.
		wasm, _, err := Compile([]config.RegexEntry{entry}, 0, false)
		if err != nil {
			t.Fatalf("Compile(embedded batch groups): %v", err)
		}
		if !bytes.HasPrefix(wasm, wasmMagic) {
			t.Fatal("Compile(embedded batch groups): output is not a WASM module")
		}
		validateWASM(t, wasm)
	})
}

// ---------------------------------------------------------------------------
// alt_lit_anchor.go — per-branch rejection gates
//
// compileAltLitAnchorBranches is all-or-nothing: one branch failing any gate
// must reject the whole alternation so the caller falls back to the combined
// DFA. Reaching each gate needs a pattern that PASSES findAltLitAnchorPoints
// (equal fixed prefixes, a qualifying anchor literal per branch) and then
// fails the specific later check, which is why these drive the function
// directly rather than through Compile.
// ---------------------------------------------------------------------------

func enginesCovAltBranches(t *testing.T, pattern string) []altLitAnchorBranch {
	t.Helper()
	branches, ok := findAltLitAnchorPoints(pattern)
	if !ok {
		t.Fatalf("findAltLitAnchorPoints(%q) rejected the pattern before the gate under test", pattern)
	}
	return branches
}

func TestEnginesCovCompileAltLitAnchorRejections(t *testing.T) {
	goodPattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+`

	t.Run("known_good_is_accepted", func(t *testing.T) {
		// Baseline, so the rejections below are attributable to the gate
		// under test rather than to a fixture that never qualified.
		branches := enginesCovAltBranches(t, goodPattern)
		if _, ok := compileAltLitAnchorBranches(branches, 0, CompileOptions{}); !ok {
			t.Fatal("compileAltLitAnchorBranches rejected the known-good alternation")
		}
	})

	t.Run("forward_dfa_needs_u16_state_ids", func(t *testing.T) {
		// A 1000-byte fixed prefix builds fine but needs more than 256 DFA
		// states, and the backward scan addresses its table with u8 state
		// ids. Accepting it would emit a dispatcher whose per-branch scan
		// functions read a table indexed with a truncated state.
		branches := enginesCovAltBranches(t, `[0-9]{1000}ghp_[^\s]+|[a-f]{1000}secret_[^\s]+`)
		if result, ok := compileAltLitAnchorBranches(branches, 0, CompileOptions{}); ok {
			t.Errorf("compileAltLitAnchorBranches accepted a DFA needing u16 state ids: %+v", result)
		}
	})

	t.Run("forward_dfa_over_helper_ceiling", func(t *testing.T) {
		// 3000 bytes of fixed prefix pushes the per-branch forward DFA past
		// the helper ceiling, so construction itself fails and the whole
		// alternation has to be abandoned rather than half-built.
		pattern := `[0-9]{1000}[a-f]{1000}[g-m]{1000}ghp_[^\s]+|` +
			`[n-s]{1000}[t-z]{1000}[0-4]{1000}secret_[^\s]+`
		branches := enginesCovAltBranches(t, pattern)
		if result, ok := compileAltLitAnchorBranches(branches, 0, CompileOptions{}); ok {
			t.Errorf("compileAltLitAnchorBranches accepted a 3000-byte prefix: %+v", result)
		}
	})

	t.Run("teddy_t1_collision_still_compiles", func(t *testing.T) {
		// Two anchor literals sharing a first byte but differing in the
		// second make a 2-byte Teddy table lossy. T1 is only an accelerator
		// (every hit is verified scalar-side), so the right answer is to skip
		// T1 and keep the alternation, not to reject it. The prefix classes
		// differ so the parser does not factor the shared 'g' out and change
		// the top-level shape.
		branches := enginesCovAltBranches(t, `[0-9]{8}ghp_[^\s]+|[a-f]{8}gzz_[^\s]+`)
		result, ok := compileAltLitAnchorBranches(branches, 0, CompileOptions{})
		if !ok {
			t.Fatal("compileAltLitAnchorBranches rejected a T1-colliding alternation; it should skip T1 instead")
		}
		if result == nil || len(result.branches) != 2 {
			t.Fatalf("compileAltLitAnchorBranches returned %+v, want 2 branches", result)
		}
	})
}

func TestEnginesCovAnalysePatternHighAlternationLabel(t *testing.T) {
	// The other complexity label, chosen ahead of "Unicode" once the
	// alternation count passes 5. Only the debug-logging path reads it.
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prog := enginesCovProg(t, `(?:aa|bb|cc|dd|ee|ff|gg)(x)`)
	analysis := analysePattern(prog)
	if analysis.NumAlternations <= 5 {
		t.Fatalf("witness pattern has %d alternations, need more than 5", analysis.NumAlternations)
	}
	opts := CompileOptions{}
	if engine, _ := selectBestEngineWithTDFA(prog, &opts); engine == 0 {
		t.Error("selectBestEngineWithTDFA returned no engine")
	}
}

func TestEnginesCovCountedChainSuffixPrefixRebase(t *testing.T) {
	// A counted-chain suffix reports the match START, not the position the
	// suffix itself began at. When the bucket's patterns share a FIXED-length
	// prefix the prefix was matched by a separate stage, so the suffix has to
	// subtract that length from the reported start and add it to the length.
	// Emitting the un-rebased form instead yields a match that begins in the
	// middle of the real one.
	class := []byte{'0', '1', '2'}
	plain := buildCountedChainSuffixBody(class, 4, 0, 0, false, false)
	rebased := buildCountedChainSuffixBody(class, 4, 0, 7, false, false)
	if len(plain) == 0 || len(rebased) == 0 {
		t.Fatal("buildCountedChainSuffixBody emitted an empty body")
	}
	if bytes.Equal(plain, rebased) {
		t.Fatal("buildCountedChainSuffixBody ignored prefixMaxLen: both bodies are byte-identical")
	}
	if len(rebased) <= len(plain) {
		t.Errorf("rebased body is %d bytes and the plain one %d; the rebase adds a sub/add pair and must be longer",
			len(rebased), len(plain))
	}
	// The prefix length is baked in as an SLEB128 constant, twice (once for
	// the start, once for the length).
	if !bytes.Contains(rebased, []byte{0x41, 0x07}) {
		t.Errorf("rebased body does not contain the i32.const 7 the rebase needs: % x", rebased)
	}
}

func TestEnginesCovMandatoryLitSplitsNestedConcat(t *testing.T) {
	// Set composition lifts a pattern's mandatory literal out of the AST by
	// splitting at the literal's path, and the split has to rebuild BOTH
	// sides at every concat level it passes through — here an inner concat
	// reached through a capture, which has material on both sides of the
	// literal. Dropping either side would give the bucket a prefix or suffix
	// automaton that matches something other than the original pattern.
	pattern := `[0-9]{2}([a-z]MANDATORYLIT[0-9]b)[0-9]`
	parsed := enginesCovParse(t, pattern)
	mandLit, path := findMandatoryLitRec(parsed, 0, 0)
	if mandLit == nil {
		t.Fatalf("findMandatoryLitRec(%q) = nil; the witness no longer has a liftable literal", pattern)
	}
	if string(mandLit.bytes) != "MANDATORYLIT" {
		t.Fatalf("findMandatoryLitRec(%q) lifted %q, want %q", pattern, mandLit.bytes, "MANDATORYLIT")
	}

	prefixAST, suffixAST, ok := splitAtPath(parsed, path)
	if !ok {
		t.Fatalf("splitAtPath(%q) refused to split", pattern)
	}
	if prefixAST == nil {
		t.Fatal("splitAtPath dropped the prefix; `[0-9]{2}` and the capture's leading `[a-z]` precede the literal")
	}
	if suffixAST == nil {
		t.Fatal("splitAtPath dropped the suffix; `[0-9]b` inside the capture and `[0-9]` after it follow the literal")
	}
	// Both sides must still account for the inner-concat material, which is
	// exactly what the two branches under test contribute.
	prefixMin, prefixMax := regexpMinMaxLen(prefixAST)
	if prefixMin != 3 || prefixMax != 3 {
		t.Errorf("prefix length = [%d, %d], want [3, 3] (two digits plus the capture's leading class)", prefixMin, prefixMax)
	}
	suffixMin, suffixMax := regexpMinMaxLen(suffixAST)
	if suffixMin != 3 || suffixMax != 3 {
		t.Errorf("suffix length = [%d, %d], want [3, 3] (digit, 'b', trailing digit)", suffixMin, suffixMax)
	}
}
