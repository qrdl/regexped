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
// pattern matches wrongly rather than failing to compile — several past bugs
// in this family were exactly that. Each case below therefore pins one
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
			why:     "the mixed-prefix shape's prefix is verified at a fixed offset from the literal, which a {M,N} prefix does not have",
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
			why:         "same capture transparency as the suffix, on the mixed-prefix shape's prefix",
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
			why: "same Sub[0]-only read on the mixed-prefix shape's prefix",
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
// of the last byte. The defect pinned here is this half going missing — an emitter
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
			// anchored ranges and falls back to the DFA.
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

// TestLitChainExtractCapturesVariableTail pins the endsAtVariableTail flag.
// `A([0-9]{24,30})` closes its group on the range chain, so its
// end is a runtime value; `(A)[0-9]{24,30}` closes before the chain and its end
// really is compile-time. Confusing the two freezes the capture end at
// attemptStart+K+Min, which is the exact frozen-end symptom.
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
	// NOT as attemptStart+K+match_len. Mixing the two up is the frozen-end bug in reverse:
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
			t.Errorf("group 1 end slot froze at the compile-time offset 28")
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

// TestLitChainAltLayoutOneByteLiteral: 2-byte Teddy reads each branch's
// SECOND literal byte as fixed, so one branch whose literal is a single byte
// must switch it off for the whole alternation — that branch's second byte is
// its class, not a constant. The two-byte control keeps it on, so the
// assertion cannot pass because the tables were never built at all.
func TestLitChainAltLayoutOneByteLiteral(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		twoByte bool
	}{
		{`x[0-9]{20}|yz[0-9]{20}`, false},
		{`xy[0-9]{20}|yz[0-9]{20}`, true},
	} {
		altp, ok := analyseLitChainAlt(tc.pattern)
		if !ok {
			t.Fatalf("%q is not a lit-chain alternation; this test no longer reaches the layout", tc.pattern)
		}
		l := planLitChainAltLayout(altp, 0)
		if l.useTwoByteTeddy != tc.twoByte {
			t.Errorf("%q: useTwoByteTeddy = %v, want %v", tc.pattern, l.useTwoByteTeddy, tc.twoByte)
		}
		if !tc.twoByte && (l.teddyT1LoOff != 0 || l.teddyT1HiOff != 0) {
			t.Errorf("%q: second-byte tables placed at %d/%d without 2-byte Teddy",
				tc.pattern, l.teddyT1LoOff, l.teddyT1HiOff)
		}
		wasm, _, err := Compile([]config.RegexEntry{{Pattern: tc.pattern, MatchFunc: "m", FindFunc: "f"}}, 0, true)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		validateWASM(t, wasm)
	}
}

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
// caller uses (see the analyser's doc comment).
func litChainLenAltBody(t *testing.T, pattern string) []byte {
	t.Helper()
	altp, ok := analyseLitChainAltLenient(pattern, false)
	if !ok {
		t.Fatalf("analyseLitChainAltLenient(%q) rejected the shape", pattern)
	}
	return buildLenAltMatchBody(altp, planLenAltLayout(altp, 0, false), 0)
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
// and the same failure mode if it goes missing.
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
	layout := planLenAltLayout(altp, 0, false)
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

	body := buildLenAltMatchBody(altp, planLenAltLayout(altp, 0, false), 0)
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

// Regression tests for the lit-chain anchored/find body defects.
//
// Every fix in that wave is a *gate*: the emitter it protects cannot express
// the shape, so the analyser must refuse it and let the pattern fall through
// to the classic DFA. These tests pin both halves — the shapes that must be
// rejected and the neighbouring shapes that must keep taking the fast path,
// since an over-broad gate silently costs the fast path on patterns that were
// always correct. End-to-end behaviour is covered by
// tools/re2test/custom-tests.txt category 36,
// which needs `make findonly` for the alternation halves.

// The three mixed-prefix emitters never referenced
// startAnchor/endAnchor, so anchored `<class>{M}<literal><class>{N}` patterns
// matched as if unanchored.
func TestAnalyseLitChainPrefixed_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^[ab]{4}XY[0-9]{24}`,
		`\A[ab]{4}XY[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}$`,
		`[ab]{4}XY[0-9]{24}\z`,
		`\b[!-,]{4}XY[0-9]{24}`,
		`\B[!-,]{4}XY[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}\b`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainPrefixed(pat); ok {
			t.Errorf("analyseLitChainPrefixed(%q) accepted an anchored shape", pat)
		}
	}
	if _, ok := analyseLitChainPrefixed(`[ab]{4}XY[0-9]{24}`); !ok {
		t.Errorf("analyseLitChainPrefixed rejected the unanchored control")
	}
}

func TestAnalyseLitChainAltPrefixed_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^[ab]{4}XY[0-9]{24}|^[cd]{4}ZW[0-9]{24}`,
		`[ab]{4}XY[0-9]{24}$|[cd]{4}ZW[0-9]{24}$`,
		// Only one branch anchored is enough to disqualify the whole alt.
		`[ab]{4}XY[0-9]{24}|^[cd]{4}ZW[0-9]{24}`,
		`\b[!-,]{4}XY[0-9]{24}|[cd]{4}ZW[0-9]{24}`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainAltPrefixed(pat); ok {
			t.Errorf("analyseLitChainAltPrefixed(%q) accepted an anchored branch", pat)
		}
	}
	if _, ok := analyseLitChainAltPrefixed(`[ab]{4}XY[0-9]{24}|[cd]{4}ZW[0-9]{24}`); !ok {
		t.Errorf("analyseLitChainAltPrefixed rejected the unanchored control")
	}
}

// Branches whose prefix lengths differ make the candidate-scan order
// (literal position) diverge from the match-start order (attempt_start minus
// prefixCount), so a later-starting match can be reported over an earlier one.
func TestAnalyseLitChainAltPrefixed_RequiresEqualPrefixCount(t *testing.T) {
	if _, ok := analyseLitChainAltPrefixed(
		`[0-9]{2}a[A-Za-z]{15}|[0-9a]{4}ZW[A-Za-z]{14}`); ok {
		t.Errorf("analyseLitChainAltPrefixed accepted unequal prefix lengths (2 vs 4)")
	}
	if _, ok := analyseLitChainAltPrefixed(
		`[0-9]{4}a[A-Za-z]{15}|[0-9a]{4}ZW[A-Za-z]{14}`); !ok {
		t.Errorf("analyseLitChainAltPrefixed rejected equal prefix lengths (4 vs 4)")
	}
}

// Capture half: buildLitChainRangeFindGroupsBody has no anchor handling,
// unlike its fixed-count sibling.
func TestAnalyseLitChainGroupsRange_RejectsAnchors(t *testing.T) {
	rejected := []string{
		`^A([0-9]{24,30})`,
		`A([0-9]{24,30})$`,
		`\bA([0-9]{24,30})`,
		`A([0-9]{24,30})\b`,
	}
	for _, pat := range rejected {
		if _, _, ok := analyseLitChainGroupsRange(pat); ok {
			t.Errorf("analyseLitChainGroupsRange(%q) accepted an anchored shape", pat)
		}
	}
	if _, _, ok := analyseLitChainGroupsRange(`A([0-9]{24,30})`); !ok {
		t.Errorf("analyseLitChainGroupsRange rejected the unanchored control")
	}
}

// emitLitChainAltLitBranchBodyRange checks the end anchor only at the
// maximal match length, with no backoff.
func TestAnalyseLitChainAltRange_EndAnchorBackoff(t *testing.T) {
	rejected := []string{
		// \b with a class mixing word and non-word bytes: backing off to a
		// shorter length can create a boundary the maximal length lacks.
		`q[a ]{24,26}\b|zz[0-9]{24}`,
		`q[a.]{24,26}\b|zz[0-9]{24}`,
		// \B is never safe at-max-only: every interior length satisfies it.
		`q[a-z]{24,26}\B|zz[0-9]{24}`,
		`q[a ]{24,26}\B|zz[0-9]{24}`,
	}
	for _, pat := range rejected {
		if _, ok := analyseLitChainAltRange(pat); ok {
			t.Errorf("analyseLitChainAltRange(%q) accepted an at-max-only end anchor", pat)
		}
	}
	// Alternation sibling of the non-greedy collapse: buildLitChainAltRangeFindBody collapses a
	// non-greedy branch to {N,N}, freezing the length the end anchor is
	// checked at. Start anchors are position-based and stay allowed.
	nonGreedyRejected := []string{
		`A[0-9]{24,30}?$|zz[0-9]{24}`,
		`A[0-9]{24,30}?\b|zz[0-9]{24}`,
		`A[0-9]{24,30}?\z|zz[0-9]{24}`,
	}
	for _, pat := range nonGreedyRejected {
		if _, ok := analyseLitChainAltRange(pat); ok {
			t.Errorf("analyseLitChainAltRange(%q) accepted a non-greedy range with an end anchor", pat)
		}
	}

	accepted := []string{
		// Non-greedy range with only a START anchor — the collapse is safe.
		`^A[0-9]{24,30}?|zz[0-9]{24}`,
		// Non-greedy range, no anchors.
		`A[0-9]{24,30}?|zz[0-9]{24}`,
		// Homogeneous all-word class + \b — the realistic secrets shape.
		`AKIA[A-Z0-9]{16,32}\b|zz[0-9]{24}`,
		// Homogeneous all-non-word class + \b.
		`q[!-,]{24,26}\b|zz[0-9]{24}`,
		// $ is monotone in match length.
		`q[a ]{24,26}$|zz[0-9]{24}`,
		// No end anchor at all.
		`q[a ]{24,26}|zz[0-9]{24}`,
		// \b on a FIXED-count branch is immune — no length to back off to.
		`q[a ]{24}\b|zz[0-9]{24,30}`,
	}
	for _, pat := range accepted {
		if _, ok := analyseLitChainAltRange(pat); !ok {
			t.Errorf("analyseLitChainAltRange(%q) rejected a safe end anchor", pat)
		}
	}
}

func TestClassWordHomogeneous(t *testing.T) {
	mk := func(bytes string) [32]byte {
		var bm [32]byte
		for i := 0; i < len(bytes); i++ {
			b := bytes[i]
			bm[b>>3] |= 1 << uint(b&7)
		}
		return bm
	}
	cases := []struct {
		name  string
		class string
		want  bool
	}{
		{"all word", "abzAZ09_", true},
		{"all non-word", " .,!-", true},
		{"mixed", "a ", false},
		{"mixed underscore vs dot", "_.", false},
		{"empty", "", true},
	}
	for _, c := range cases {
		if got := classWordHomogeneous(mk(c.class)); got != c.want {
			t.Errorf("classWordHomogeneous(%s=%q) = %v, want %v", c.name, c.class, got, c.want)
		}
	}
}

func TestRangeEndAnchorSafe(t *testing.T) {
	var word, mixed [32]byte
	for _, b := range []byte("abz09_") {
		word[b>>3] |= 1 << uint(b&7)
	}
	for _, b := range []byte("ab ") {
		mixed[b>>3] |= 1 << uint(b&7)
	}
	cases := []struct {
		anchor anchorType
		bitmap [32]byte
		want   bool
	}{
		{anchorNone, mixed, true},
		{anchorEndText, mixed, true},
		{anchorBeginText, mixed, true},
		{anchorWordBoundary, word, true},
		{anchorWordBoundary, mixed, false},
		{anchorNoWordBoundary, word, false},
		{anchorNoWordBoundary, mixed, false},
	}
	for _, c := range cases {
		if got := rangeEndAnchorSafe(c.anchor, c.bitmap); got != c.want {
			t.Errorf("rangeEndAnchorSafe(%v, ...) = %v, want %v", c.anchor, got, c.want)
		}
	}
}

// planRangeChunks covers [K, K+countMax) rounded up to 16, while callers
// only bounds-check K+countMin, so chunks past that window need the load
// clamp. This pins which chunks emitRangeClassVerify must guard; the trap it
// prevents is exercised end-to-end by tools/fuzz's
// TestRangeVerifyNoOverreadAtMemoryEnd.
func TestPlanRangeChunks_ClampWindow(t *testing.T) {
	cases := []struct {
		k, countMin, countMax int
		wantClamped           int // chunks with offsetFromK+16 > countMin
	}{
		{1, 24, 30, 1}, // chunk [0,16) safe, chunk [16,32) clamped
		{1, 24, 24, 1}, // exact: chunk [16,32) still reaches past 24
		{1, 32, 60, 2}, // chunks [0,16) [16,32) safe; [32,48) [48,64) clamped
		{4, 48, 48, 0}, // every chunk ends within countMin
		{1, 24, 900, 56},
	}
	for _, c := range cases {
		chunks := planRangeChunks(c.k, c.countMax)
		got := 0
		for _, ch := range chunks {
			if ch.offsetFromK+16 > c.countMin {
				got++
			}
		}
		if got != c.wantClamped {
			t.Errorf("k=%d countMin=%d countMax=%d: %d chunks need clamping, want %d",
				c.k, c.countMin, c.countMax, got, c.wantClamped)
		}
	}
}

// extractLitChainCaptures gave every OpRepeat a Min-based width, and the
// range slot-write emitter re-derived "this capture ends at the chain" by
// testing `endOffset == K + countMax`. For a true range Min ≠ Max, so that
// equality can never hold and every chain-covering capture got a frozen
// `attemptStart + K + Min` end. The walk now records the fact structurally.
func TestExtractLitChainCaptures_VariableTail(t *testing.T) {
	cases := []struct {
		pat string
		// want[group] = endsAtVariableTail
		want map[int]bool
	}{
		// Range: the chain-covering captures end at a variable tail.
		{`A([0-9]{24,30})`, map[int]bool{1: true}},
		{`(A[0-9]{24,30})`, map[int]bool{1: true}},
		{`(A)([0-9]{24,30})`, map[int]bool{1: false, 2: true}},
		{`((A)[0-9]{24,30})`, map[int]bool{1: true, 2: false}},
		{`(A([0-9]{24,30}))`, map[int]bool{1: true, 2: true}},
		// A trailing zero-width assertion must not clear the flag.
		{`(A[0-9]{24,30})\b`, map[int]bool{1: true}},
		// Fixed count: nothing is variable, so every offset stays compile-time
		// and the fixed-count emitter keeps its byte-identical output.
		{`A([0-9]{24})`, map[int]bool{1: false}},
		{`(A[0-9]{24})`, map[int]bool{1: false}},
		{`(A)([0-9]{24})`, map[int]bool{1: false, 2: false}},
	}
	for _, c := range cases {
		re, err := syntax.Parse(c.pat, syntax.Perl)
		if err != nil {
			t.Fatalf("pattern=%q parse: %v", c.pat, err)
		}
		caps, _, ok := extractLitChainCaptures(re)
		if !ok {
			t.Errorf("pattern=%q: extractLitChainCaptures rejected", c.pat)
			continue
		}
		got := make(map[int]bool, len(caps))
		for _, cg := range caps {
			got[cg.group] = cg.endsAtVariableTail
		}
		for g, want := range c.want {
			if got[g] != want {
				t.Errorf("pattern=%q group %d: endsAtVariableTail=%v, want %v",
					c.pat, g, got[g], want)
			}
		}
		if len(got) != len(c.want) {
			t.Errorf("pattern=%q: %d captures, want %d", c.pat, len(got), len(c.want))
		}
	}
}

func TestPrefixStartsWithLineAnchor(t *testing.T) {
	parse := func(pattern string) *syntax.Regexp {
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", pattern, err)
		}
		return re
	}

	cases := []struct {
		pattern string
		want    bool
	}{
		{"^abc", true},   // OpConcat starting with OpBeginLine
		{`\Aabc`, true},  // OpConcat starting with OpBeginText
		{"abc", false},   // no anchor
		{"[a-z]", false}, // OpCharClass
		{"(^abc)", true}, // OpCapture containing anchor concat
		{"(abc)", false}, // OpCapture without anchor
		{"a|^b", false},  // OpAlternate — not handled, returns false
	}
	for _, c := range cases {
		re := parse(c.pattern)
		if got := prefixStartsWithLineAnchor(re); got != c.want {
			t.Errorf("prefixStartsWithLineAnchor(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestPrefixStartsWithLineAnchor_Edges(t *testing.T) {
	// Empty OpConcat: no Sub → returns false.
	t.Run("empty_concat", func(t *testing.T) {
		re := &syntax.Regexp{Op: syntax.OpConcat}
		if prefixStartsWithLineAnchor(re) {
			t.Error("empty concat should not be a line anchor")
		}
	})
	// Empty OpCapture: no Sub → returns false.
	t.Run("empty_capture", func(t *testing.T) {
		re := &syntax.Regexp{Op: syntax.OpCapture}
		if prefixStartsWithLineAnchor(re) {
			t.Error("empty capture should not be a line anchor")
		}
	})
}

func TestExtractLitSet_RejectionPaths(t *testing.T) {
	parse := func(p string) *syntax.Regexp {
		t.Helper()
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", p, err)
		}
		return re
	}

	// FoldCase literal → nil.
	t.Run("fold_case_literal", func(t *testing.T) {
		re := parse(`(?i:foo)`)
		var lit *syntax.Regexp
		var walk func(*syntax.Regexp)
		walk = func(r *syntax.Regexp) {
			if r.Op == syntax.OpLiteral {
				lit = r
				return
			}
			for _, s := range r.Sub {
				walk(s)
			}
		}
		walk(re)
		if lit == nil {
			t.Fatal("no OpLiteral node found")
		}
		if got := extractLitSet(lit); got != nil {
			t.Errorf("extractLitSet(foldcase literal) = %v, want nil", got)
		}
	})

	// Non-ASCII rune in literal → nil.
	t.Run("non_ascii_literal", func(t *testing.T) {
		re := parse(`café`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(non-ASCII) = %v, want nil", got)
		}
	})

	// Single-byte literal → nil (len(bs) < 2 path).
	t.Run("single_byte_literal", func(t *testing.T) {
		re := parse(`x`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(single byte) = %v, want nil", got)
		}
	})

	// Alternation with non-literal branch → nil.
	t.Run("alternation_with_non_literal_branch", func(t *testing.T) {
		re := parse(`foo|[a-z]+`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(mixed alt) = %v, want nil", got)
		}
	})

	// Alternation where one branch yields a multi-literal set → nil.
	t.Run("alternation_with_nested_alt_branch", func(t *testing.T) {
		inner := parse(`ab|cd`)
		outer := parse(`ef`)
		alt := &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{inner, outer}}
		if got := extractLitSet(alt); got != nil {
			t.Errorf("extractLitSet(nested alt) = %v, want nil", got)
		}
	})

	// Capture wrapping a literal → recurses and succeeds.
	t.Run("capture_single_sub", func(t *testing.T) {
		re := parse(`(foo)`)
		got := extractLitSet(re)
		if len(got) != 1 || string(got[0]) != "foo" {
			t.Errorf("extractLitSet((foo)) = %v, want [foo]", got)
		}
	})

	// Capture with zero subs (defensive) → nil.
	t.Run("capture_zero_subs", func(t *testing.T) {
		cap := &syntax.Regexp{Op: syntax.OpCapture}
		if got := extractLitSet(cap); got != nil {
			t.Errorf("extractLitSet(empty capture) = %v, want nil", got)
		}
	})

	// Empty alternation → nil because result is empty.
	t.Run("empty_alternation", func(t *testing.T) {
		alt := &syntax.Regexp{Op: syntax.OpAlternate}
		if got := extractLitSet(alt); got != nil {
			t.Errorf("extractLitSet(empty alt) = %v, want nil", got)
		}
	})

	// Unsupported op (default) → nil.
	t.Run("char_class", func(t *testing.T) {
		re := parse(`[a-z]`)
		if got := extractLitSet(re); got != nil {
			t.Errorf("extractLitSet(charclass) = %v, want nil", got)
		}
	})
}

func TestReverseRegexp_LineAnchors(t *testing.T) {
	// OpBeginLine ↔ OpEndLine.
	beginLine := &syntax.Regexp{Op: syntax.OpBeginLine}
	if rev := reverseRegexp(beginLine); rev.Op != syntax.OpEndLine {
		t.Errorf("reverse(OpBeginLine) = %v, want OpEndLine", rev.Op)
	}
	endLine := &syntax.Regexp{Op: syntax.OpEndLine}
	if rev := reverseRegexp(endLine); rev.Op != syntax.OpBeginLine {
		t.Errorf("reverse(OpEndLine) = %v, want OpBeginLine", rev.Op)
	}
}

func TestFindLitAnchorPoint_ParseError(t *testing.T) {
	if got := findLitAnchorPoint("[invalid"); got != nil {
		t.Errorf("findLitAnchorPoint(invalid) = %+v, want nil", got)
	}
	if got := findLitAnchorPoint("[a-z]"); got != nil {
		t.Errorf("findLitAnchorPoint([a-z]) = %+v, want nil", got)
	}
}

// TestSimpleClassPrefix exercises simpleClassPrefix directly (0% covered
// without this) across its qualifying and rejecting shapes.
func TestSimpleClassPrefix(t *testing.T) {
	parse := func(t *testing.T, p string) *syntax.Regexp {
		t.Helper()
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", p, err)
		}
		return re
	}

	t.Run("char_class_exact_count", func(t *testing.T) {
		re := parse(t, `[0-9]{8}`)
		tlo, count, ok := simpleClassPrefix(re)
		if !ok {
			t.Fatal("expected ok=true for [0-9]{8}")
		}
		if count != 8 {
			t.Errorf("count = %d, want 8", count)
		}
		// Every digit '0'-'9' should set its bit in the nibble-lookup table.
		for _, r := range "0123456789" {
			lo, hi := byte(r)&0xF, byte(r)>>4
			if tlo[lo]&(1<<hi) == 0 {
				t.Errorf("tlo table missing bit for %q", r)
			}
		}
	})

	t.Run("literal_char_exact_count", func(t *testing.T) {
		// A repeated single-char literal ("aaa") folds to OpLiteral under Repeat's child.
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 3, Max: 3,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}},
		}
		tlo, count, ok := simpleClassPrefix(re)
		if !ok || count != 3 {
			t.Fatalf("simpleClassPrefix(literal 'a'{3}) = (ok=%v, count=%d), want (true, 3)", ok, count)
		}
		if tlo['a'&0xF]&(1<<('a'>>4)) == 0 {
			t.Error("tlo table missing bit for 'a'")
		}
	})

	t.Run("capture_wrapped", func(t *testing.T) {
		re := parse(t, `([a-f]{4})`)
		_, count, ok := simpleClassPrefix(re)
		if !ok || count != 4 {
			t.Fatalf("simpleClassPrefix((capture)) = (ok=%v, count=%d), want (true, 4)", ok, count)
		}
	})

	t.Run("rejects_ranged_count", func(t *testing.T) {
		re := parse(t, `[0-9]{4,8}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a ranged {M,N} repeat")
		}
	})

	t.Run("rejects_count_above_16", func(t *testing.T) {
		re := parse(t, `[0-9]{17}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a repeat count > 16")
		}
	})

	t.Run("rejects_non_repeat", func(t *testing.T) {
		re := parse(t, `[0-9]`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a non-OpRepeat node")
		}
	})

	t.Run("rejects_non_class_child", func(t *testing.T) {
		// Repeat of a concat body (nested structure) is neither OpCharClass nor OpLiteral.
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{
				Op:  syntax.OpConcat,
				Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a'}}, {Op: syntax.OpLiteral, Rune: []rune{'b'}}},
			}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a non-class, non-literal repeat body")
		}
	})

	t.Run("rejects_non_ascii_class", func(t *testing.T) {
		re := parse(t, `[\x{100}-\x{200}]{4}`)
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a class with runes above ASCII")
		}
	})

	t.Run("rejects_non_ascii_literal", func(t *testing.T) {
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'Ā'}}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a literal rune above ASCII")
		}
	})

	t.Run("rejects_multi_rune_literal", func(t *testing.T) {
		re := &syntax.Regexp{
			Op:  syntax.OpRepeat,
			Min: 2, Max: 2,
			Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune{'a', 'b'}}},
		}
		if _, _, ok := simpleClassPrefix(re); ok {
			t.Error("accepted a multi-rune OpLiteral child")
		}
	})
}

// TestBuildSimplePrefixCheckBody calls buildSimplePrefixCheckBody directly
// (0% covered without this): verifies the returned bytes are a well-formed
// LEB128-size-prefixed WASM function body ending in the `end` opcode.
func TestBuildSimplePrefixCheckBody(t *testing.T) {
	re, err := syntax.Parse(`[0-9]{8}`, syntax.Perl)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tlo, count, ok := simpleClassPrefix(re)
	if !ok {
		t.Fatal("simpleClassPrefix rejected [0-9]{8}")
	}
	body := buildSimplePrefixCheckBody(tlo, count)

	sz, n, err := utils.DecodeULEB128(body)
	if err != nil {
		t.Fatalf("decode body size prefix: %v", err)
	}
	if int(sz) != len(body)-n {
		t.Fatalf("size prefix = %d, want %d (len(body)-%d)", sz, len(body)-n, n)
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("body does not end with the `end` opcode (0x0B): got 0x%02X", body[len(body)-1])
	}
}

// TestCompileLikelyNoMatchSimpleClassPrefix exercises the integration path
// (compile.go) that gates buildSimplePrefixCheckBody on
// LikelyMode == LikelyNoMatch: a bare `[class]{M}` prefix ahead of an
// UNBOUNDED literal-anchored suffix. A bounded suffix (e.g. `{36}`) is
// instead caught earlier by analyseLitChainPrefixed and never
// reaches this path — see the alt-lit-anchor dispatch test for the analogous
// alternation case.
func TestCompileLikelyNoMatchSimpleClassPrefix(t *testing.T) {
	entry := config.RegexEntry{Pattern: `[0-9]{8}ghp_[^\s]+`, FindFunc: "f"}

	p, err := compilePattern(entry, 0, 0, CompileOptions{LikelyMode: LikelyNoMatch})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.litAnchorBackScanBody == nil {
		t.Fatal("compilePattern did not take the lit-anchor path")
	}
	re, _ := syntax.Parse(entry.Pattern, syntax.Perl)
	lap := findLitAnchorPointInRegexp(re)
	if lap == nil {
		t.Fatal("findLitAnchorPointInRegexp returned nil")
	}
	tlo, count, ok := simpleClassPrefix(lap.prefixRe)
	if !ok {
		t.Fatal("simpleClassPrefix rejected the pattern's prefix")
	}
	want := buildSimplePrefixCheckBody(tlo, count)
	if string(p.litAnchorBackScanBody) != string(want) {
		t.Error("litAnchorBackScanBody does not match buildSimplePrefixCheckBody's output")
	}

	// LikelyNeutral must NOT take the SIMD-verify shortcut (falls back to the
	// generic scalar backward-scan body instead).
	pNeutral, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern (neutral): %v", err)
	}
	if string(pNeutral.litAnchorBackScanBody) == string(want) {
		t.Error("LikelyNeutral unexpectedly took the buildSimplePrefixCheckBody shortcut")
	}

	mustCompileEntries(t, []config.RegexEntry{entry}, CompileOptions{LikelyMode: LikelyNoMatch})
}

func TestFindAltLitAnchorPoints(t *testing.T) {
	t.Run("accepts_equal_fixed_prefix", func(t *testing.T) {
		branches, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`, false)
		if !ok {
			t.Fatalf("findAltLitAnchorPoints rejected the target pattern")
		}
		if len(branches) != 2 {
			t.Fatalf("expected 2 branches, got %d", len(branches))
		}
	})

	t.Run("rejects_invalid_syntax", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[`, false); ok {
			t.Errorf("accepted invalid syntax")
		}
	})

	t.Run("rejects_non_alternate_top_level", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}`, false); ok {
			t.Errorf("accepted a non-alternation top-level pattern")
		}
	})

	t.Run("rejects_single_branch", func(t *testing.T) {
		// After parsing, an "alternation" of one literal-only branch — Go's
		// syntax package would fold `(?:a)` to a plain literal anyway, so
		// use a construct that stays OpAlternate with exactly one sub is not
		// generally reachable; instead verify the >=2 branch count gate
		// directly against a 3-branch pattern where all qualify.
		branches, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}|[0-9]{8}akey_[A-Za-z0-9]{20}`, false)
		if !ok || len(branches) != 3 {
			t.Fatalf("expected 3 qualifying branches, got ok=%v len=%d", ok, len(branches))
		}
	})

	t.Run("rejects_unequal_prefix_lengths", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{4}ghp_[A-Za-z0-9]{36}|[a-f]{16}secret_[A-Za-z0-9]{20}`, false); ok {
			t.Errorf("accepted branches with unequal fixed prefix lengths (4 vs 16)")
		}
	})

	t.Run("rejects_non_fixed_length_prefix", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`[0-9]{4,8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`, false); ok {
			t.Errorf("accepted a branch with a ranged (non-fixed-length) prefix")
		}
	})

	t.Run("rejects_unbounded_prefix", func(t *testing.T) {
		if _, ok := findAltLitAnchorPoints(`.*ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`, false); ok {
			t.Errorf("accepted a branch with an unbounded prefix")
		}
	})

	t.Run("rejects_mixed_qualifying_and_non_qualifying_branch", func(t *testing.T) {
		// Second branch's top-level shape isn't OpConcat with a qualifying
		// literal (it's a bare class run with no anchor literal at all).
		if _, ok := findAltLitAnchorPoints(`[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f0-9]{20}`, false); ok {
			t.Errorf("accepted an alternation with a non-qualifying branch")
		}
	})

	t.Run("rejects_too_many_branches", func(t *testing.T) {
		pattern := `[0-9]{8}ghp_[A-Za-z0-9]{4}`
		full := pattern
		for i := 0; i < maxAltLitAnchorBranches; i++ {
			full += "|" + pattern
		}
		if _, ok := findAltLitAnchorPoints(full, false); ok {
			t.Errorf("accepted more than %d branches", maxAltLitAnchorBranches)
		}
	})
}

// TestCompileAltLitAnchorDispatch exercises the full alt-lit-anchor pipeline —
// compileAltLitAnchorBranches, buildAltLitAnchorFindBody, and
// compiledPattern.altLitAnchorBranchFuncIdx (all 0% covered without this) —
// by compiling a find-only alternation whose branches have an UNBOUNDED
// suffix (`[^\s]+`). Bounded-suffix branches like the ones
// TestFindAltLitAnchorPoints uses are caught earlier by
// analyseLitChainAltPrefixed (compile.go), which returns before the
// alt-lit-anchor block is ever reached; an unbounded suffix isn't a lit-chain
// shape, so it falls through to this path instead.
func TestCompileAltLitAnchorDispatch(t *testing.T) {
	pattern := `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`
	entry := config.RegexEntry{Pattern: pattern, FindFunc: "f"}

	p, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.altLitAnchorBranches == nil {
		t.Fatalf("compilePattern did not take the alt-lit-anchor path for %q", pattern)
	}
	if len(p.altLitAnchorBranches) != 3 {
		t.Fatalf("altLitAnchorBranches: got %d branches, want 3", len(p.altLitAnchorBranches))
	}
	// Exercise altLitAnchorBranchFuncIdx for every branch index (i>0 covers
	// the per-branch offset arithmetic beyond the first pair).
	for i := range p.altLitAnchorBranches {
		back, fwd := p.altLitAnchorBranchFuncIdx(i)
		if fwd != back+1 {
			t.Errorf("altLitAnchorBranchFuncIdx(%d) = (%d, %d), want fwd == back+1", i, back, fwd)
		}
	}

	mustCompileEntries(t, []config.RegexEntry{entry})
}

// ccpLayout builds a find-mode layout the way appendFindCodeEntry's callers do,
// so the detector is asked about the same tables the emitter would read.
// ccpLayout builds the layout AND the table the way compilePattern does, and —
// critically — applies the dominant-state encoding first, because that is the
// state the detector actually runs in.
//
// Skipping that step is what made this harness disagree with production:
// applyDominantStateEncoding overloads midAcceptBytes with dominant markers,
// and a detector that read those bytes saw accepts that were not there. The
// detector now reads the table's accept maps instead, so the two agree — but
// the harness still applies the encoding, so a future reader of the wrong
// field is caught here rather than in a corpus run.
func ccpLayout(t *testing.T, pattern string) (*dfaLayout, *dfaTable) {
	t.Helper()
	m, err := compile(pattern, CompileOptions{
		MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile(%q): %v", pattern, err)
	}
	table := dfaTableFrom(m.(*dfa))
	l := buildDFALayout(dfaLayoutParams{
		t: table, tableBase: 0, needFind: true, leftmostFirst: true,
		compiledDFAThreshold: resolveCompiledDFAThreshold(&CompileOptions{}),
		// The LikelyMatch flags are what put dominants in the layout at all,
		// and dominants are what overload midAcceptBytes below.
		lmBareShufti: true, lmNonMidShufti: true, lmWideShufti: true,
		lmClassChain: true,
	})
	applyDominantStateEncoding(l, true)
	return l, table
}

// TestDetectClassChainPrefix pins both halves of the detector: the shapes it
// must find, and — more importantly — the shapes it must REFUSE.
//
// Every refusal below is a case where the emitted probe would be unsound
// rather than merely unhelpful, because it jumps the walk forward without
// consulting the byte before the candidate or the positions it skips over.
func TestDetectClassChainPrefix(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantOK  bool
		wantN   int
		wantLen int // len(class), 0 = don't check
	}{
		{"open tail 20", `[a-zA-Z]{20,}`, true, 20, 52},
		{"open tail 8", `[A-Z]{8,}`, true, 8, 26},
		{"exact count", `[a-z]{5}`, true, 5, 26},

		// Below minClassChainPrefix the probe loses on BOTH arms: it replaces
		// one scalar step with a chunk load, and its range-retirement argument
		// is empty because a non-member at offset 0 retires only the position
		// the scalar scan was about to abandon anyway. These two are the
		// patterns that measured +3.7% and +1.3% against neutral before the
		// floor existed.
		{"single step is refused", `[a-z]+`, false, 0, 0},
		{"inverted single step is refused", `[^,]+`, false, 0, 0},
		{"word single step is refused", `\w+`, false, 0, 0},
		{"just below the floor", `[a-z]{3,}`, false, 0, 0},
		{"exactly at the floor", `[a-z]{4,}`, true, 4, 26},

		// The `{N,}`-followed-by-something shape. Its chain end SELF-LOOPS on
		// the class and exits on a different one, so it accepts nowhere and
		// has two destinations — the single-destination rule alone refuses it.
		// Reaching that state still proves 50 class bytes were consumed, which
		// is all the probe needs.
		{"open tail then another class", `[a-z]{50,}[0-9]`, true, 50, 26},
		{"open tail then a literal", `[a-z]{6,}END`, true, 6, 26},

		// A bounded range is a chain of its MINIMUM length: {5,9} accepts
		// after 5, so the chain ends there and the scalar walk extends it.
		// The skip stays exact — a start at p+i has r-i class bytes ahead, and
		// r < 5 makes r-i < 5 for every i in [0,r].
		{"bounded range is a chain of its minimum", `[a-z]{5,9}`, true, 5, 26},
		// The class changes mid-chain, so it is not one chain.
		{"class changes", `[a-z]{3}[0-9]{3}`, false, 0, 0},
		// A literal prefix is a different (and already handled) shape.
		{"literal prefix", `abc[a-z]{5,}`, false, 0, 0},
		// Word boundaries make the start state depend on the preceding byte,
		// which the probe never reads.
		{"word boundary", `\b[a-z]{5,}`, false, 0, 0},
		// Same, for newline context.
		{"line anchor", `(?m:^)[a-z]{5,}`, false, 0, 0},
		// The start state accepts, so the empty match makes the chain moot.
		{"start accepts", `[a-z]*`, false, 0, 0},
		// Alternation: the start state has two destinations.
		{"alternation", `[a-z]{3}|[0-9]{5}`, false, 0, 0},

		// A chain longer than maxClassChainPrefix. Also the u16 table form:
		// 301 states puts the ids past a byte, so readCell takes its two-byte
		// arm — the only case in this table that does.
		{"past the chain cap", `[a-z]{300,}`, false, 0, 0},

		// wasmStart != wasmMidStart: position 0 and a mid-input candidate walk
		// DIFFERENT automata, and the probe consults neither the preceding byte
		// nor which of the two it is in. Both spellings must be refused.
		{"begin-anchored", `\A[a-z]{5,}`, false, 0, 0},
		{"begin-anchored via star", `0*^0[a-z]{5,}`, false, 0, 0},

		// An END anchor leaves both start states equal, so it stays eligible:
		// the chain is the same, only its continuation differs.
		{"end-anchored is still a chain", `[a-z]{5,}\z`, true, 5, 26},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, tb := ccpLayout(t, tc.pattern)
			got, ok := detectClassChainPrefix(l, tb)
			if ok != tc.wantOK {
				t.Fatalf("detectClassChainPrefix(%q) ok = %v, want %v (n=%d)",
					tc.pattern, ok, tc.wantOK, got.n)
			}
			if !ok {
				return
			}
			if got.n != tc.wantN {
				t.Errorf("n = %d, want %d", got.n, tc.wantN)
			}
			if tc.wantLen > 0 && len(got.class) != tc.wantLen {
				t.Errorf("len(class) = %d, want %d", len(got.class), tc.wantLen)
			}
			if len(got.states) > 16 {
				t.Errorf("states has %d entries, want at most 16", len(got.states))
			}
			if len(got.states) != min(got.n, 16) {
				t.Errorf("states has %d entries, want min(n,16) = %d",
					len(got.states), min(got.n, 16))
			}
		})
	}
}

// TestClassChainPrefixStatesWalk checks the recorded state ids really are the
// states the DFA reaches after k class bytes. A wrong id here produces a module
// that resumes the walk in a plausible but incorrect state — the failure this
// whole mechanism is most exposed to, and one no validator would catch.
func TestClassChainPrefixStatesWalk(t *testing.T) {
	for _, pattern := range []string{`[a-zA-Z]{20,}`, `[A-Z]{8,}`, `[a-z]{5}`} {
		t.Run(pattern, func(t *testing.T) {
			l, tb := ccpLayout(t, pattern)
			got, ok := detectClassChainPrefix(l, tb)
			if !ok {
				t.Fatalf("detectClassChainPrefix(%q) refused", pattern)
			}
			cellsPerState := 256
			if l.useCompression {
				cellsPerState = l.numClasses
			}
			read := func(state, b int) int32 {
				row := state
				if l.useRowDedup {
					row = int(l.rowMapBytes[state])
				}
				cell := b
				if l.useCompression {
					cell = int(l.classMap[b])
				}
				off := row*cellsPerState + cell
				if l.useU8 {
					return int32(l.tableBytes[off])
				}
				return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
			}
			// Walk the class bytes one at a time and compare against states[].
			cur := int32(l.wasmStart)
			for k := range got.states {
				cur = read(int(cur), int(got.class[0]))
				if cur != got.states[k] {
					t.Fatalf("after %d class bytes the DFA is in state %d, "+
						"but states[%d] records %d", k+1, cur, k, got.states[k])
				}
			}
			// Every class byte must lead to the same place at every step.
			cur = int32(l.wasmStart)
			for k := range got.states {
				for _, c := range got.class {
					if next := read(int(cur), int(c)); next != got.states[k] {
						t.Fatalf("step %d: class byte %#02x goes to %d, want %d",
							k, c, next, got.states[k])
					}
				}
				cur = got.states[k]
			}
		})
	}
}
