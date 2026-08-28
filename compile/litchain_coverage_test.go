package compile

import (
	"bytes"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// Guard-level tests for the literal-chain family in engine_dfa.go:
// analyseLitChainBranch, extractLitChainCaptures, buildLitChainRangeMatchBody,
// emitLitChainRangeGroupSlotWrites, analyseLitChainAltLenient and
// buildLenAltMatchBody.
//
// Every one of those is an *emitter or its gate*: when a gate wrongly accepts a
// shape, the emitter silently produces a body that cannot express it, and the
// pattern matches wrongly rather than failing to compile (that is the whole of
// plans/FABLE.md wave 3 — B7, B8, B10, B11). Each case below therefore pins one
// specific reason a shape is refused or accepted, so a relaxed gate shows up
// here instead of in the RE2 corpus.
//
// Two deliberate conventions:
//
//   - analyseLitChainBranch is fed the RAW parse (parseTestRe, no Simplify).
//     Simplify rewrites `x{20}` into an unrolled concat, which destroys the
//     OpRepeat the analyser keys on, so a simplified tree can never reach these
//     branches at all.
//   - Where a guard covers a tree that syntax.Parse cannot produce (an
//     OpLiteral with no runes, an OpRepeat with two children, an empty
//     OpCharClass), the tree is hand-built. Those are defence-in-depth guards
//     against a malformed tree reaching the emitter, and a hand-built node is
//     the only witness for them.

// ---------------------------------------------------------------------------
// AST construction helpers for the hand-built (unparseable) shapes.
// ---------------------------------------------------------------------------

func litChainLiteralNode(text string) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune(text)}
}

// litChainClassNode builds an OpCharClass from lo/hi rune pairs. Passing no
// pairs yields the empty class, which is the witness for the "class matches
// nothing" guards.
func litChainClassNode(loHiPairs ...rune) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpCharClass, Rune: append([]rune(nil), loHiPairs...)}
}

func litChainRepeatNode(minCount, maxCount int, subs ...*syntax.Regexp) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpRepeat, Min: minCount, Max: maxCount, Sub: subs}
}

func litChainConcatNode(subs ...*syntax.Regexp) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
}

// litChainAsciiClassNode is the well-formed `[a-z]` used as filler wherever a
// case is about some *other* node being malformed.
func litChainAsciiClassNode() *syntax.Regexp {
	return litChainClassNode('a', 'z')
}

// ---------------------------------------------------------------------------
// analyseLitChainBranch
// ---------------------------------------------------------------------------

// TestLitChainBranchRejects pins the shapes analyseLitChainBranch must refuse.
// Every one of them would otherwise reach an emitter that assumes a single
// ASCII-only literal followed by a single ASCII-only class chain: a folded or
// multi-byte literal would be compared byte-for-byte against the wrong bytes,
// and a class carrying runes above 127 cannot be represented in the 128-bit
// nibble table the SIMD verify uses at all.
func TestLitChainBranchRejects(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		why     string
	}{
		{
			name:    "fold_case_literal",
			pattern: `(?i)abc[a-z]{20}`,
			why:     "the literal verify compares raw bytes, so a FoldCase literal would only ever match one of its two cases",
		},
		{
			name:    "non_ascii_literal",
			pattern: `éabc[a-z]{20}`,
			why:     "literal bytes are emitted one rune per byte; a rune above 127 would be truncated",
		},
		{
			name:    "non_ascii_class_range",
			pattern: `abc[\x{100}-\x{200}]{20}`,
			why:     "the class bitmap and nibble table only address bytes 0..127",
		},
		{
			name:    "non_ascii_repeat_literal",
			pattern: `abcé{20}`,
			why:     "a single-rune repeat body above 127 has no byte to set in the bitmap",
		},
		{
			name:    "prefix_is_a_range",
			pattern: `[a-z]{2,3}abc[a-z]{20}`,
			why:     "the Gap E prefix is verified at a fixed offset from the literal, which a {M,N} prefix does not have",
		},
		{
			name:    "prefix_non_ascii_class_range",
			pattern: `[\x{100}-\x{200}]{3}abc[a-z]{20}`,
			why:     "same 0..127 addressing limit as the suffix class, applied to the prefix table",
		},
		{
			name:    "prefix_non_ascii_literal",
			pattern: `é{3}abc[a-z]{20}`,
			why:     "single-rune prefix body above 127 has no byte to set in the prefix bitmap",
		},
		{
			name:    "prefix_neither_class_nor_literal",
			pattern: `(?:ab|cd){3}abc[a-z]{20}`,
			why:     "an alternation prefix body is not a byte set, so no prefix bitmap exists for it",
		},
		{
			name:    "prefix_longer_than_one_simd_chunk",
			pattern: `[a-z]{17}abc[a-z]{20}`,
			why:     "the prefix verify is a single 16-byte SIMD chunk; M>16 would leave bytes unchecked",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if info, ok := analyseLitChainBranch(parseTestRe(t, testCase.pattern)); ok {
				t.Errorf("analyseLitChainBranch(%q) accepted (literal=%q count=%d prefix=%d); %s",
					testCase.pattern, info.literal, info.count, info.prefixCount, testCase.why)
			}
		})
	}
}

// TestLitChainBranchAccepts pins the neighbouring shapes that must keep taking
// the fast path. An over-broad rejection is invisible at runtime — the pattern
// just quietly falls back to the classic DFA and loses the SIMD verify — so
// only a test like this catches it.
func TestLitChainBranchAccepts(t *testing.T) {
	cases := []struct {
		name        string
		pattern     string
		wantLiteral string
		wantCount   int
		wantPrefix  int
		wantStart   anchorType
		wantEnd     anchorType
		why         string
	}{
		{
			name:        "anchors_wrapping_a_capture",
			pattern:     `\b(abc[a-z]{20})\b`,
			wantLiteral: "abc",
			wantCount:   20,
			wantStart:   anchorWordBoundary,
			wantEnd:     anchorWordBoundary,
			why:         "peeling both anchors leaves one OpCapture around the concat, which must be unwrapped before the shape check",
		},
		{
			name:        "capture_around_the_repeat_body",
			pattern:     `abc([a-z]){20}`,
			wantLiteral: "abc",
			wantCount:   20,
			why:         "the capture sits between the repeat and its class and must be transparent to the class scan",
		},
		{
			name:        "repeat_of_a_single_literal",
			pattern:     `abcx{20}`,
			wantLiteral: "abc",
			wantCount:   20,
			why:         "a one-rune repeat body is a one-element byte set, not a char class, and still has a valid bitmap",
		},
		{
			name:        "prefix_capture_around_the_class",
			pattern:     `([a-z]){3}abc[a-z]{20}`,
			wantLiteral: "abc",
			wantCount:   20,
			wantPrefix:  3,
			why:         "same capture transparency as the suffix, on the Gap E prefix",
		},
		{
			name:        "prefix_of_a_single_literal",
			pattern:     `x{3}abc[a-z]{20}`,
			wantLiteral: "abc",
			wantCount:   20,
			wantPrefix:  3,
			why:         "a one-rune prefix body is a one-element byte set",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			info, ok := analyseLitChainBranch(parseTestRe(t, testCase.pattern))
			if !ok {
				t.Fatalf("analyseLitChainBranch(%q) rejected; %s", testCase.pattern, testCase.why)
			}
			if string(info.literal) != testCase.wantLiteral {
				t.Errorf("literal = %q, want %q", info.literal, testCase.wantLiteral)
			}
			if info.count != testCase.wantCount {
				t.Errorf("count = %d, want %d", info.count, testCase.wantCount)
			}
			if info.prefixCount != testCase.wantPrefix {
				t.Errorf("prefixCount = %d, want %d", info.prefixCount, testCase.wantPrefix)
			}
			if info.startAnchor != testCase.wantStart {
				t.Errorf("startAnchor = %v, want %v", info.startAnchor, testCase.wantStart)
			}
			if info.endAnchor != testCase.wantEnd {
				t.Errorf("endAnchor = %v, want %v", info.endAnchor, testCase.wantEnd)
			}
		})
	}
}

// TestLitChainBranchRejectsMalformedTrees covers the guards whose witness
// syntax.Parse cannot build: an empty literal, a repeat with a child count
// other than one, and a class that matches no byte. They are structural
// preconditions of the emitters (a zero-length literal would make the K+N
// overlap-load arithmetic address bytes before the match start; an empty class
// bitmap would make every SIMD verify fail while the scan loop still ran), so
// they must stay refusals even though today's parser never produces them.
func TestLitChainBranchRejectsMalformedTrees(t *testing.T) {
	validSuffix := litChainRepeatNode(20, 20, litChainAsciiClassNode())

	cases := []struct {
		name string
		tree *syntax.Regexp
		why  string
	}{
		{
			name: "empty_literal",
			tree: litChainConcatNode(litChainLiteralNode(""), validSuffix),
			why:  "K=0 breaks the K+N>=16 overlap-load precondition the chunk planner relies on",
		},
		{
			name: "suffix_repeat_with_two_children",
			tree: litChainConcatNode(
				litChainLiteralNode("abc"),
				litChainRepeatNode(20, 20, litChainAsciiClassNode(), litChainAsciiClassNode()),
			),
			why: "the class scan reads Sub[0] only, so a second child would be silently dropped from the match",
		},
		{
			name: "suffix_class_matches_nothing",
			tree: litChainConcatNode(litChainLiteralNode("abc"), litChainRepeatNode(20, 20, litChainClassNode())),
			why:  "an all-zero bitmap makes the verify reject unconditionally; the pattern belongs on the DFA path",
		},
		{
			name: "prefix_repeat_with_two_children",
			tree: litChainConcatNode(
				litChainRepeatNode(3, 3, litChainAsciiClassNode(), litChainAsciiClassNode()),
				litChainLiteralNode("abc"),
				validSuffix,
			),
			why: "same Sub[0]-only read on the Gap E prefix",
		},
		{
			name: "prefix_class_matches_nothing",
			tree: litChainConcatNode(
				litChainRepeatNode(3, 3, litChainClassNode()),
				litChainLiteralNode("abc"),
				validSuffix,
			),
			why: "an all-zero prefix bitmap makes the prefix verify reject unconditionally",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, ok := analyseLitChainBranch(testCase.tree); ok {
				t.Errorf("analyseLitChainBranch accepted a malformed tree; %s", testCase.why)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildLitChainRangeMatchBody
// ---------------------------------------------------------------------------

// litChainRangeBody analyses pattern as a single greedy `{N,M}` lit-chain and
// returns the anchored-match body the compiler would emit for it.
func litChainRangeBody(t *testing.T, pattern string) []byte {
	t.Helper()
	lcp, ok := analyseLitChainRange(pattern, 24)
	if !ok {
		t.Fatalf("analyseLitChainRange(%q) rejected the shape", pattern)
	}
	return buildLitChainRangeMatchBody(lcp)
}

// TestLitChainRangeMatchBodyStartAnchors covers the compile-time start-anchor
// verdicts. The body matches the WHOLE input, so the match always starts at
// position 0 and every start anchor is decidable at compile time: `\z` can
// never hold there, and `\b`/`\B` reduce to whether the literal's first byte is
// a word byte. Getting this wrong is not a slow path but a wrong answer — the
// body would report a match for a pattern that cannot match anywhere.
func TestLitChainRangeMatchBodyStartAnchors(t *testing.T) {
	// The only difference a compile-time refusal makes is a three-byte
	// `i32.const -1; return` inserted after the bounds checks.
	const refusalBytes = 3

	// Each case carries its own unanchored control with the SAME literal: the
	// literal verify encodes each byte as SLEB128, so 'a' (2 bytes) and '-'
	// (1 byte) do not cost the same and a shared control would not be
	// comparable.
	cases := []struct {
		name     string
		pattern  string
		control  string
		wantFail bool
		why      string
	}{
		{
			name:     "end_text_at_the_start",
			pattern:  `\zabc[A-Z]{24,30}`,
			control:  `abc[A-Z]{24,30}`,
			wantFail: true,
			why:      `\z at position 0 can only hold on empty input, which the K+N bounds check already excluded`,
		},
		{
			name:     "word_boundary_before_a_non_word_byte",
			pattern:  `\b-bc[A-Z]{24,30}`,
			control:  `-bc[A-Z]{24,30}`,
			wantFail: true,
			why:      `\b at position 0 needs a word byte to its right; '-' is not one`,
		},
		{
			name:     "no_word_boundary_before_a_word_byte",
			pattern:  `\Babc[A-Z]{24,30}`,
			control:  `abc[A-Z]{24,30}`,
			wantFail: true,
			why:      `\B at position 0 needs a non-word byte to its right; 'a' is one`,
		},
		{
			name:     "word_boundary_before_a_word_byte",
			pattern:  `\babc[A-Z]{24,30}`,
			control:  `abc[A-Z]{24,30}`,
			wantFail: false,
			why:      `\b is satisfied at position 0 by the word byte 'a', so no runtime check and no refusal is needed`,
		},
		{
			name:     "no_word_boundary_before_a_non_word_byte",
			pattern:  `\B-bc[A-Z]{24,30}`,
			control:  `-bc[A-Z]{24,30}`,
			wantFail: false,
			why:      `\B is satisfied at position 0 by the non-word byte '-'`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			control := litChainRangeBody(t, testCase.control)
			body := litChainRangeBody(t, testCase.pattern)
			wantLen := len(control)
			if testCase.wantFail {
				wantLen += refusalBytes
			}
			if len(body) != wantLen {
				t.Errorf("body length = %d, want %d (control %q is %d, wantFail=%v); %s",
					len(body), wantLen, testCase.control, len(control), testCase.wantFail, testCase.why)
			}
		})
	}
}

// TestLitChainRangeMatchBodyEndAnchors covers the end-anchor emission. The
// match consumes the whole input, so the end position is always len: `\z`
// always holds, `\A` never does, and `\b`/`\B` reduce to a single is_word probe
// of the last byte. FABLE B7 is exactly this half going missing — an emitter
// that ignores endAnchor reports matches that Go's regexp does not.
func TestLitChainRangeMatchBodyEndAnchors(t *testing.T) {
	control := litChainRangeBody(t, `abc[A-Z]{24,30}`)

	t.Run("begin_text_at_the_end_is_impossible", func(t *testing.T) {
		body := litChainRangeBody(t, `abc[A-Z]{24,30}\A`)
		// `i32.const 1; br_if $bad` — an unconditional jump to the failure arm.
		if !bytes.Contains(body, []byte{0x41, 0x01, 0x0D, 0x00}) {
			t.Errorf("body has no unconditional branch to the failure arm for a trailing \\A")
		}
		if len(body) <= len(control) {
			t.Errorf("body length = %d, control = %d: trailing \\A emitted no extra code",
				len(body), len(control))
		}
	})

	t.Run("end_text_at_the_end_always_holds", func(t *testing.T) {
		body := litChainRangeBody(t, `abc[A-Z]{24,30}\z`)
		// The check itself is free, but the success/failure arms of the
		// end-anchor block are not, so the body still grows.
		if len(body) <= len(control) {
			t.Errorf("body length = %d, control = %d: trailing \\z emitted no anchor block",
				len(body), len(control))
		}
	})

	t.Run("word_boundary_probes_the_last_byte", func(t *testing.T) {
		wordBoundary := litChainRangeBody(t, `abc[A-Z]{24,30}\b`)
		noWordBoundary := litChainRangeBody(t, `abc[A-Z]{24,30}\B`)
		// Both probe the last byte; only `\b` inverts the result with i32.eqz,
		// so the two bodies must differ by exactly that one byte. Equal lengths
		// would mean one of the two senses was dropped.
		if len(wordBoundary) != len(noWordBoundary)+1 {
			t.Errorf("\\b body = %d bytes, \\B body = %d: expected \\b to carry exactly one extra i32.eqz",
				len(wordBoundary), len(noWordBoundary))
		}
		if len(noWordBoundary) <= len(control) {
			t.Errorf("body length = %d, control = %d: trailing \\B emitted no is_word probe",
				len(noWordBoundary), len(control))
		}
	})
}

// TestLitChainRangeMatchBodyCompiles drives the same shapes through the public
// Compile API so the routing into this body — and the validity of the module
// it lands in — is checked, not just the emitter in isolation.
func TestLitChainRangeMatchBodyCompiles(t *testing.T) {
	patterns := []string{
		`\zabc[A-Z]{24,30}`,
		`\Babc[A-Z]{24,30}`,
		`abc[A-Z]{24,30}\A`,
		`abc[A-Z]{24,30}\z`,
		`abc[A-Z]{24,30}\b`,
		`abc[A-Z]{24,30}\B`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			// Match-only: the find half of this path deliberately rejects
			// anchored ranges (FABLE B7/B10) and falls back to the DFA.
			mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}})
		})
	}
}

// ---------------------------------------------------------------------------
// extractLitChainCaptures
// ---------------------------------------------------------------------------

// TestLitChainExtractCaptures pins the walk's per-node arithmetic and its two
// refusal reasons. The offsets it returns are baked into the emitted slot
// writes as compile-time constants, so a node type mis-measured here becomes a
// capture span that is silently off by that many bytes.
func TestLitChainExtractCaptures(t *testing.T) {
	cases := []struct {
		name         string
		pattern      string
		wantOK       bool
		wantMaxGroup int
		wantGroups   []captureGroup
		why          string
	}{
		{
			name:         "repeat_of_a_literal_counts_rune_width",
			pattern:      `(Ax{24})`,
			wantOK:       true,
			wantMaxGroup: 1,
			wantGroups:   []captureGroup{{group: 1, startOffset: 0, endOffset: 25}},
			why:          "a repeat over a one-rune literal is 24 bytes wide, not 24 repetitions of an unknown width",
		},
		{
			name:         "bare_class_outside_a_repeat_is_one_byte",
			pattern:      `(A[0-9]x{24})`,
			wantOK:       true,
			wantMaxGroup: 1,
			wantGroups:   []captureGroup{{group: 1, startOffset: 0, endOffset: 26}},
			why:          "a class node consumes exactly one byte, so the capture ends at 1+1+24",
		},
		{
			name:    "capture_inside_a_repeat_is_refused",
			pattern: `((a){24})b`,
			wantOK:  false,
			why:     "capture-the-last-occurrence cannot be reconstructed from a compile-time offset, and the refusal must survive the sibling walked after it",
		},
		{
			name:    "multiline_anchor_is_refused",
			pattern: `(?m)(A[0-9]{24})^`,
			wantOK:  false,
			why:     "(?m)^ matches at every line start, so no single compile-time offset describes the match",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			caps, maxGroup, ok := extractLitChainCaptures(parseTestRe(t, testCase.pattern))
			if ok != testCase.wantOK {
				t.Fatalf("extractLitChainCaptures(%q) ok = %v, want %v; %s",
					testCase.pattern, ok, testCase.wantOK, testCase.why)
			}
			if !testCase.wantOK {
				if caps != nil || maxGroup != 0 {
					t.Errorf("refusal returned caps=%v maxGroup=%d, want nil/0", caps, maxGroup)
				}
				return
			}
			if maxGroup != testCase.wantMaxGroup {
				t.Errorf("maxGroup = %d, want %d", maxGroup, testCase.wantMaxGroup)
			}
			if len(caps) != len(testCase.wantGroups) {
				t.Fatalf("got %d captures, want %d: %+v", len(caps), len(testCase.wantGroups), caps)
			}
			for capIndex, want := range testCase.wantGroups {
				got := caps[capIndex]
				if got.group != want.group || got.startOffset != want.startOffset ||
					got.endOffset != want.endOffset {
					t.Errorf("capture %d = {group %d, %d..%d}, want {group %d, %d..%d}; %s",
						capIndex, got.group, got.startOffset, got.endOffset,
						want.group, want.startOffset, want.endOffset, testCase.why)
				}
			}
		})
	}
}

// TestLitChainExtractCapturesZeroWidthFallthrough pins the walk's final
// fallthrough. OpStar has no compile-time width, and the walk neither measures
// it nor refuses it — it returns zero, so a capture closing after one would end
// at the wrong offset. That is sound only because analyseLitChainBranch has
// already refused the shape (OpStar is not the OpRepeat the lit-chain emitters
// need), which makes the two functions load-bearing as a PAIR. Both halves are
// asserted here rather than assumed: relaxing the shape gate to admit OpStar
// would silently corrupt capture offsets, and this is the test that would say so.
func TestLitChainExtractCapturesZeroWidthFallthrough(t *testing.T) {
	const pattern = `(A[0-9]*)`
	tree := parseTestRe(t, pattern)

	if _, ok := analyseLitChainBranch(tree); ok {
		t.Fatalf("analyseLitChainBranch(%q) accepted an OpStar shape; the zero-width "+
			"fallthrough in extractLitChainCaptures is only sound while this gate refuses it",
			pattern)
	}

	caps, maxGroup, ok := extractLitChainCaptures(tree)
	if !ok || maxGroup != 1 || len(caps) != 1 {
		t.Fatalf("extractLitChainCaptures(%q) = (%+v, %d, %v), want one capture",
			pattern, caps, maxGroup, ok)
	}
	if caps[0].endOffset != 1 {
		t.Errorf("capture end offset = %d, want 1: the OpStar must contribute zero width "+
			"rather than a guessed one", caps[0].endOffset)
	}
}

// TestLitChainExtractCapturesVariableTail pins the endsAtVariableTail flag that
// FABLE B8 added. `A([0-9]{24,30})` closes its group on the range chain, so its
// end is a runtime value; `(A)[0-9]{24,30}` closes before the chain and its end
// really is compile-time. Confusing the two freezes the capture end at
// attemptStart+K+Min, which is the exact B8 symptom.
func TestLitChainExtractCapturesVariableTail(t *testing.T) {
	cases := []struct {
		pattern      string
		wantVariable bool
	}{
		{pattern: `A([0-9]{24,30})`, wantVariable: true},
		{pattern: `(A)[0-9]{24,30}`, wantVariable: false},
		{pattern: `A([0-9]{24})`, wantVariable: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.pattern, func(t *testing.T) {
			caps, _, ok := extractLitChainCaptures(parseTestRe(t, testCase.pattern))
			if !ok || len(caps) != 1 {
				t.Fatalf("extractLitChainCaptures(%q) = %v, ok=%v; want exactly one capture",
					testCase.pattern, caps, ok)
			}
			if caps[0].endsAtVariableTail != testCase.wantVariable {
				t.Errorf("endsAtVariableTail = %v, want %v",
					caps[0].endsAtVariableTail, testCase.wantVariable)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// emitLitChainRangeGroupSlotWrites
// ---------------------------------------------------------------------------

// TestLitChainRangeGroupSlotWrites covers the three slot-writing shapes the
// range emitter has to distinguish, driven directly because one of them — a
// group index that no capture populates — is not reachable from any pattern
// today's analysers accept (see the note on the sparse case below).
func TestLitChainRangeGroupSlotWrites(t *testing.T) {
	const (
		outPtrLocal       byte = 1
		attemptStartLocal byte = 2
		matchLenLocal     byte = 3
		literalWidth           = 4
	)

	// A group whose end is compile-time must be written as attemptStart+offset,
	// NOT as attemptStart+K+match_len. Mixing the two up is FABLE B8 in reverse:
	// a fixed-width capture would stretch to the end of the range chain.
	t.Run("compile_time_end_offset", func(t *testing.T) {
		lcc := &litChainCaptures{
			numGroups: 2,
			groups: []captureGroup{
				{group: 1, startOffset: 1, endOffset: 3, endsAtVariableTail: false},
			},
		}
		body := emitLitChainRangeGroupSlotWrites(nil, lcc, outPtrLocal, attemptStartLocal,
			matchLenLocal, literalWidth)

		wantStart := litChainAttemptPlusStore(outPtrLocal, attemptStartLocal, 1, 8)
		wantEnd := litChainAttemptPlusStore(outPtrLocal, attemptStartLocal, 3, 12)
		if !bytes.Contains(body, wantStart) {
			t.Errorf("group 1 start slot is not written as attemptStart+1: % x", body)
		}
		if !bytes.Contains(body, wantEnd) {
			t.Errorf("group 1 end slot is not written as attemptStart+3: % x", body)
		}
		// match_len must not appear for this group's end; it only belongs to
		// group 0's end, which is emitted before the loop.
		if bytes.Count(body, []byte{0x20, matchLenLocal}) != 1 {
			t.Errorf("match_len is read %d times, want exactly once (group 0's end)",
				bytes.Count(body, []byte{0x20, matchLenLocal}))
		}
	})

	t.Run("runtime_end_offset", func(t *testing.T) {
		lcc := &litChainCaptures{
			numGroups: 2,
			groups: []captureGroup{
				{group: 1, startOffset: 0, endOffset: 28, endsAtVariableTail: true},
			},
		}
		body := emitLitChainRangeGroupSlotWrites(nil, lcc, outPtrLocal, attemptStartLocal,
			matchLenLocal, literalWidth)
		// Group 0's end plus group 1's end — both attemptStart+K+match_len.
		if got := bytes.Count(body, []byte{0x20, matchLenLocal}); got != 2 {
			t.Errorf("match_len is read %d times, want 2 (group 0 end and group 1 end)", got)
		}
		// The Min-based compile-time end must not be baked in anywhere.
		if bytes.Contains(body, litChainAttemptPlusStore(outPtrLocal, attemptStartLocal, 28, 12)) {
			t.Errorf("group 1 end slot froze at the compile-time offset 28 (FABLE B8)")
		}
	})

	// A group index inside [1, numGroups) that no capture populates must be
	// filled with -1 rather than left holding whatever the caller's buffer had.
	// No pattern reaches this today: numGroups is maxGroup+1 and maxGroup is
	// derived from the very captures the walk recorded, so the set is dense.
	// It is still the emitter's contract for a numGroups that comes from
	// somewhere else (a sibling branch of an alternation, which is how the
	// alt-groups analyser fills litChainCaptures), so it is pinned directly.
	t.Run("unpopulated_group_is_filled_with_minus_one", func(t *testing.T) {
		lcc := &litChainCaptures{
			numGroups: 3,
			groups: []captureGroup{
				{group: 2, startOffset: 4, endOffset: 5, endsAtVariableTail: false},
			},
		}
		body := emitLitChainRangeGroupSlotWrites(nil, lcc, outPtrLocal, attemptStartLocal,
			matchLenLocal, literalWidth)
		for _, slotOff := range []uint32{8, 12} {
			want := litChainMinusOneStore(outPtrLocal, slotOff)
			if !bytes.Contains(body, want) {
				t.Errorf("slot %d of the unpopulated group 1 is not written as -1: % x", slotOff, body)
			}
		}
		if !bytes.Contains(body, litChainAttemptPlusStore(outPtrLocal, attemptStartLocal, 4, 16)) {
			t.Errorf("group 2 start slot was not written past the unpopulated group 1")
		}
	})
}

// litChainAttemptPlusStore rebuilds the `out_ptr[slot] = attemptStart + offset`
// sequence the emitter produces, so the assertions above compare against the
// encoding rather than against a hand-transcribed byte string.
func litChainAttemptPlusStore(outPtrLocal, attemptStartLocal byte, offset int32, slotOff uint32) []byte {
	seq := []byte{0x20, outPtrLocal, 0x20, attemptStartLocal}
	if offset != 0 {
		seq = append(seq, 0x41)
		seq = utils.AppendSLEB128(seq, offset)
		seq = append(seq, 0x6A)
	}
	seq = append(seq, 0x36, 0x00)
	return utils.AppendULEB128(seq, slotOff)
}

func litChainMinusOneStore(outPtrLocal byte, slotOff uint32) []byte {
	seq := []byte{0x20, outPtrLocal, 0x41, 0x7F, 0x36, 0x00}
	return utils.AppendULEB128(seq, slotOff)
}

// TestLitChainRangeGroupsCompiles drives the two capture shapes through
// Compile: `(A)[0-9]{24,30}` is the compile-time-end case (a capture that
// closes before the range chain) and `A([0-9]{24,30})` the runtime-end one.
func TestLitChainRangeGroupsCompiles(t *testing.T) {
	for _, pattern := range []string{`(A)[0-9]{24,30}`, `A([0-9]{24,30})`} {
		t.Run(pattern, func(t *testing.T) {
			if _, _, ok := analyseLitChainGroupsRange(pattern); !ok {
				t.Fatalf("analyseLitChainGroupsRange(%q) rejected the shape, so the "+
					"range groups body is not the path under test", pattern)
			}
			mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
		})
	}
}

// ---------------------------------------------------------------------------
// analyseLitChainAltLenient
// ---------------------------------------------------------------------------

// TestLitChainAltLenientRejects pins the reasons a lenient alternation is
// refused. Each branch that is not lit-chain shaped is compiled to an inline
// anchored DFA whose table is emitted with u8 state ids and read without any
// Unicode decoding, so a branch that needs more than 256 states or any rune
// above 255 has no representation in the emitted body at all.
func TestLitChainAltLenientRejects(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		why     string
	}{
		{
			name:    "fold_case_literal_on_the_dfa_branch",
			pattern: `(?i)ab[0-9]c|xy[a-z]{24}`,
			why:     "the branch's literal doubles as the frontend scan trigger and is compared raw, so FoldCase would miss half its inputs",
		},
		{
			name:    "non_ascii_literal_on_the_dfa_branch",
			pattern: `é[0-9]x|xy[a-z]{24}`,
			why:     "the frontend trigger is a byte sequence; a rune above 127 has no single-byte form",
		},
		{
			name:    "unicode_class_on_the_dfa_branch",
			pattern: `ab[α-ω]c|xy[a-z]{24}`,
			why:     "the inline DFA verify reads bytes, not runes, so a program needing Unicode support cannot run in it",
		},
		{
			name:    "dfa_branch_over_the_u8_table_limit",
			pattern: `ab[0-9]{300}c|xy[a-z]{24}`,
			why:     "state ids are emitted as u8, so a 300-state branch cannot be addressed",
		},
		{
			name: "dfa_branch_over_the_helper_state_ceiling",
			// `[01]*1[01]{12}` is the classic subset-construction blowup: the
			// DFA has to remember the last 13 bits, so it needs 2^13 states.
			pattern: `ab[01]*1[01]{12}|xy[a-z]{24}`,
			why:     "the subset construction blows past maxHelperDFAStates and newDFA must refuse rather than run away",
		},
		{
			name:    "every_branch_is_a_lit_chain",
			pattern: `abc[a-z]{24}|xyz[0-9]{24}`,
			why:     "the strict analyser emits a better body for this, so the lenient path must decline it",
		},
		{
			name:    "single_branch_is_not_an_alternation",
			pattern: `abc[a-z]{24}`,
			why:     "there is no alternation to dispatch over",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			for _, leftmostFirst := range []bool{false, true} {
				if _, ok := analyseLitChainAltLenient(testCase.pattern, leftmostFirst); ok {
					t.Errorf("analyseLitChainAltLenient(%q, leftmostFirst=%v) accepted; %s",
						testCase.pattern, leftmostFirst, testCase.why)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildLenAltMatchBody
// ---------------------------------------------------------------------------

// litChainLenAltBody analyses pattern as a lenient alternation and returns the
// anchored-match body for it, in the leftmost-longest flavour the anchored
// caller uses (see the analyser's doc comment and FUZZER_BUGS bug 35).
func litChainLenAltBody(t *testing.T, pattern string) []byte {
	t.Helper()
	altp, ok := analyseLitChainAltLenient(pattern, false)
	if !ok {
		t.Fatalf("analyseLitChainAltLenient(%q) rejected the shape", pattern)
	}
	return buildLenAltMatchBody(altp, planLenAltLayout(altp, 0), 0)
}

// TestLenAltMatchBodySkipsImpossibleBranches covers the compile-time start
// anchor verdict for a lit-chain branch of a lenient alternation. The body is
// anchored at position 0, so a branch whose start anchor cannot hold there
// contributes no code at all — and if it were emitted anyway it would report
// matches the pattern does not have.
func TestLenAltMatchBodySkipsImpossibleBranches(t *testing.T) {
	control := litChainLenAltBody(t, `abc[A-Z]{24}|qq[0-9]z`)

	cases := []struct {
		name    string
		pattern string
		why     string
	}{
		{
			name:    "end_text_at_the_start",
			pattern: `\zabc[A-Z]{24}|qq[0-9]z`,
			why:     `\z cannot hold at position 0 of a non-empty match`,
		},
		{
			name:    "word_boundary_before_a_non_word_byte",
			pattern: `\b-bc[A-Z]{24}|qq[0-9]z`,
			why:     `\b at position 0 needs a word byte to its right; '-' is not one`,
		},
		{
			name:    "no_word_boundary_before_a_word_byte",
			pattern: `\Babc[A-Z]{24}|qq[0-9]z`,
			why:     `\B at position 0 needs a non-word byte to its right; 'a' is one`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := litChainLenAltBody(t, testCase.pattern)
			if len(body) >= len(control) {
				t.Errorf("body = %d bytes, control = %d: the impossible branch was still emitted; %s",
					len(body), len(control), testCase.why)
			}
		})
	}
}

// TestLenAltMatchBodyEndAnchors covers the end-anchor arm of a lit-chain branch
// inside a lenient alternation — the sibling of the single-pattern case above,
// and the same FABLE B7 failure mode if it goes missing.
func TestLenAltMatchBodyEndAnchors(t *testing.T) {
	control := litChainLenAltBody(t, `abc[A-Z]{24}|qq[0-9]z`)

	t.Run("begin_text_at_the_end_is_impossible", func(t *testing.T) {
		body := litChainLenAltBody(t, `abc[A-Z]{24}\A|qq[0-9]z`)
		// A trailing \A costs exactly one `br $next_branch` (0x0C 0x00): the
		// branch is entered, then abandoned unconditionally.
		if len(body) != len(control)+2 {
			t.Errorf("body = %d bytes, control = %d: want exactly two more (br $next_branch)",
				len(body), len(control))
		}
	})

	t.Run("end_text_at_the_end_is_checked_at_runtime", func(t *testing.T) {
		body := litChainLenAltBody(t, `abc[A-Z]{24}\z|qq[0-9]z`)
		if len(body) <= len(control) {
			t.Errorf("body = %d bytes, control = %d: trailing \\z emitted no end-anchor check",
				len(body), len(control))
		}
	})

	t.Run("word_boundary_at_the_end_is_checked_at_runtime", func(t *testing.T) {
		body := litChainLenAltBody(t, `abc[A-Z]{24}\b|qq[0-9]z`)
		if len(body) <= len(control) {
			t.Errorf("body = %d bytes, control = %d: trailing \\b emitted no is_word probe",
				len(body), len(control))
		}
	})
}

// TestLenAltMatchBodyScalarBranch covers the non-SIMD class verify. A lit-chain
// branch shorter than 24 class bytes verifies through a bitmap table in memory
// instead of a nibble-table SIMD chunk, which is why the layout has to allocate
// a per-branch bitmap for it at all.
func TestLenAltMatchBodyScalarBranch(t *testing.T) {
	const pattern = `abcdefghij[a-z]{6}|qq[0-9]z`
	altp, ok := analyseLitChainAltLenient(pattern, false)
	if !ok {
		t.Fatalf("analyseLitChainAltLenient(%q) rejected the shape", pattern)
	}
	if altp.branches[0].useSIMD {
		t.Fatalf("branch 0 (N=6) chose the SIMD verify; the scalar path is what this test covers")
	}
	layout := planLenAltLayout(altp, 0)
	if layout.branchBitmapOff[0] < 0 {
		t.Fatalf("no bitmap allocated for the scalar branch: the verify has nothing to read")
	}
	if len(buildLenAltMatchBody(altp, layout, 0)) == 0 {
		t.Fatalf("empty match body")
	}
}

// TestLenAltMatchBodyMasksPartialSimdChunk covers the partial-lane arm of the
// SIMD class verify. It is white-box on purpose: today's analyser only sets
// useSIMD when N>=24, and planLitChainChunks only produces a reduced lane mask
// when N<16, so the two conditions cannot meet through any pattern. The guard
// is still the thing that keeps a K+N<16+K overlap chunk from validating the
// trailing LITERAL bytes as if they were class bytes, so it is pinned here
// against a future analyser that lowers the SIMD threshold.
func TestLenAltMatchBodyMasksPartialSimdChunk(t *testing.T) {
	const pattern = `abcdefghij[a-z]{6}|qq[0-9]z`
	altp, ok := analyseLitChainAltLenient(pattern, false)
	if !ok {
		t.Fatalf("analyseLitChainAltLenient(%q) rejected the shape", pattern)
	}
	altp.branches[0].useSIMD = true

	chunks := planLitChainChunks(len(altp.branches[0].literal), altp.branches[0].count)
	if len(chunks) != 1 || chunks[0].laneMask == 0xFFFF {
		t.Fatalf("chunk plan = %+v, want a single partial-lane chunk", chunks)
	}

	body := buildLenAltMatchBody(altp, planLenAltLayout(altp, 0), 0)
	// `i32.const <laneMask>; i32.and` — the lanes holding literal bytes are
	// cleared out of the bad-byte mask before it is branched on.
	wantMask := utils.AppendSLEB128([]byte{0x41}, int32(chunks[0].laneMask))
	wantMask = append(wantMask, 0x71)
	if !bytes.Contains(body, wantMask) {
		t.Errorf("partial chunk's lane mask % x is not applied to the bad-byte mask", wantMask)
	}
}

// TestLenAltMatchBodyCompiles drives the anchored lenient-alt shapes through
// the public API, so the routing into buildLenAltMatchBody and the validity of
// the resulting module are checked too. Match-only: the find half of a lenient
// alternation is a different body.
func TestLenAltMatchBodyCompiles(t *testing.T) {
	patterns := []string{
		`\zabc[A-Z]{24}|qq[0-9]z`,
		`\Babc[A-Z]{24}|qq[0-9]z`,
		`abc[A-Z]{24}\A|qq[0-9]z`,
		`abc[A-Z]{24}\z|qq[0-9]z`,
		`abc[A-Z]{24}\b|qq[0-9]z`,
		`abcdefghij[a-z]{6}|qq[0-9]z`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, MatchFunc: "m"}})
		})
	}
}
