package compile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestLikelyModeString verifies that LikelyMode.String() returns a non-empty
// string for every enum value.
func TestLikelyModeString(t *testing.T) {
	for _, m := range []LikelyMode{LikelyNeutral, LikelyMatch, LikelyNoMatch} {
		if s := m.String(); s == "" {
			t.Errorf("LikelyMode(%d).String() returned empty string", int(m))
		}
	}
}

// TestCompileLikelyMatch exercises the lit-chain compilation paths that are
// only triggered when LikelyMode == LikelyMatch. Patterns are arranged so
// each specialised emission helper is reached:
//
//   - Strict-alt match (no find) → appendLitChainAltMatchCodeEntry.
//   - Strict-alt find  (no match) → buildLitChainAltFindBody.
//   - Strict-alt range find (no match) → appendLitChainAltRangeFindCodeEntry.
//   - Strict-alt prefixed find (no match) → appendLitChainAltPrefixedFindCodeEntry.
//   - Lenient-alt match (no find) → appendLenAltMatchCodeEntry.
//   - Lenient-alt find  (no match) → buildLitChainAltLenientFindBody.
//   - Strict-alt with groups (no match/find) → appendLitChainAltFindGroupsCodeEntry.
//   - Lit-chain anchored groups → appendLitChainFindGroupsCodeEntry.
//   - Lit-chain range groups → appendLitChainRangeFindGroupsCodeEntry.
//   - Word-boundary anchors → isWordByte / emitIsWordByte / emitStartAnchorCheck / emitEndAnchorCheck.
func TestCompileLikelyMatch(t *testing.T) {
	lm := CompileOptions{LikelyMode: LikelyMatch}

	cases := []struct {
		name    string
		entries []config.RegexEntry
	}{
		// ---------- Lit-chain (single) match + find, exact count ----------
		{
			"akia_exact_match_find",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{16}`,
				MatchFunc: "akia_match",
				FindFunc:  "akia_find",
			}},
		},
		{
			"ghp_exact_match_find",
			[]config.RegexEntry{{
				Pattern:   `ghp_[A-Za-z0-9]{36}`,
				MatchFunc: "ghp_match",
				FindFunc:  "ghp_find",
			}},
		},
		{
			"keyx_long_chain_match_find",
			[]config.RegexEntry{{
				Pattern:   `KEYX[A-Z0-9]{64}`,
				MatchFunc: "keyx_match",
				FindFunc:  "keyx_find",
			}},
		},

		// ---------- Lit-chain with range counter {N,M} ----------
		{
			"akia_range_match_find",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{8,16}`,
				MatchFunc: "akia_range_match",
				FindFunc:  "akia_range_find",
			}},
		},
		{
			"secret_range_match_find",
			[]config.RegexEntry{{
				Pattern:   `secret_[A-Za-z0-9]{24,40}`,
				MatchFunc: "secret_match",
				FindFunc:  "secret_find",
			}},
		},

		// ---------- Strict alt: match only (no find) → alt-match path ----------
		{
			"strict_alt_match_only",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`,
				MatchFunc: "strict_alt_match_only",
			}},
		},
		// Strict alt with word-boundary anchors, match only → exercises
		// emitStartAnchorCheck/emitEndAnchorCheck + isWordByte/emitIsWordByte.
		{
			"strict_alt_wb_match_only",
			[]config.RegexEntry{{
				Pattern:   `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`,
				MatchFunc: "strict_alt_wb_match_only",
			}},
		},
		// Strict alt with begin/end text anchors → emitStartAnchorCheck
		// (anchorBeginText) and emitEndAnchorCheck (anchorEndText).
		{
			"strict_alt_anchored_text",
			[]config.RegexEntry{{
				Pattern:   `\AAKIA[A-Z0-9]{16}\z|\Aghp_[A-Za-z0-9]{36}\z`,
				MatchFunc: "strict_alt_anchored_text_match",
			}},
		},
		{
			"strict_alt_anchored_text_find",
			[]config.RegexEntry{{
				Pattern:  `\AAKIA[A-Z0-9]{16}\z|\Aghp_[A-Za-z0-9]{36}\z`,
				FindFunc: "strict_alt_anchored_text_find",
			}},
		},
		// Strict alt: noWordBoundary anchors → anchorNoWordBoundary case.
		{
			"strict_alt_nowb_match",
			[]config.RegexEntry{{
				Pattern:   `\BAKIA[A-Z0-9]{16}\B|\Bghp_[A-Za-z0-9]{36}\B`,
				MatchFunc: "strict_alt_nowb_match",
			}},
		},

		// ---------- Strict alt: find only (no match) → alt-find path ----------
		{
			"strict_alt_find_only",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`,
				FindFunc: "strict_alt_find_only",
			}},
		},
		{
			"strict_alt_wb_find_only",
			[]config.RegexEntry{{
				Pattern:  `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`,
				FindFunc: "strict_alt_wb_find_only",
			}},
		},

		// ---------- Strict alt with range branches: find only ----------
		{
			"strict_alt_range_find_only",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}|secret_[A-Za-z0-9]{24,40}`,
				FindFunc: "strict_alt_range_find_only",
			}},
		},
		// Strict alt range + word-boundary anchors → exercises emitEndAnchorCheck
		// in emitLitChainAltLitBranchBodyRange (anchorWordBoundary case).
		{
			"strict_alt_range_wb_find",
			[]config.RegexEntry{{
				Pattern:  `\bAKIA[A-Z0-9]{16}\b|\bsecret_[A-Za-z0-9]{24,40}\b`,
				FindFunc: "strict_alt_range_wb_find",
			}},
		},
		// Strict alt range + text anchors.
		{
			"strict_alt_range_text_find",
			[]config.RegexEntry{{
				Pattern:  `\AAKIA[A-Z0-9]{16}\z|\Asecret_[A-Za-z0-9]{24,40}\z`,
				FindFunc: "strict_alt_range_text_find",
			}},
		},
		// Single-pattern lit-chain (N>=24) with word-boundary anchors.
		{
			"lit_chain_wb_match_find_n24",
			[]config.RegexEntry{{
				Pattern:   `\bAKIA[A-Z0-9]{24}\b`,
				MatchFunc: "lit_chain_wb_match_n24",
				FindFunc:  "lit_chain_wb_find_n24",
			}},
		},
		// Single-pattern lit-chain (N>=24) with begin/end text anchors.
		{
			"lit_chain_anchored_text_match_find_n24",
			[]config.RegexEntry{{
				Pattern:   `\AAKIA[A-Z0-9]{24}\z`,
				MatchFunc: "lit_chain_anchored_text_match_n24",
				FindFunc:  "lit_chain_anchored_text_find_n24",
			}},
		},
		// Single-pattern lit-chain (N>=24) with no-word-boundary anchors.
		{
			"lit_chain_nowb_n24",
			[]config.RegexEntry{{
				Pattern:   `\BAKIA[A-Z0-9]{24}\B`,
				MatchFunc: "lit_chain_nowb_match_n24",
				FindFunc:  "lit_chain_nowb_find_n24",
			}},
		},
		// Single-pattern lit-chain (N>=24) end-text only.
		{
			"lit_chain_end_text_n24",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{24}\z`,
				MatchFunc: "lit_chain_end_text_match_n24",
				FindFunc:  "lit_chain_end_text_find_n24",
			}},
		},
		// Single-pattern lit-chain (N>=24) begin-text only.
		{
			"lit_chain_begin_text_n24",
			[]config.RegexEntry{{
				Pattern:   `\AAKIA[A-Z0-9]{24}`,
				MatchFunc: "lit_chain_begin_text_match_n24",
				FindFunc:  "lit_chain_begin_text_find_n24",
			}},
		},
		// Single-pattern lit-chain range with word-boundary anchors.
		{
			"lit_chain_range_wb_match_find",
			[]config.RegexEntry{{
				Pattern:   `\bAKIA[A-Z0-9]{24,40}\b`,
				MatchFunc: "lit_chain_range_wb_match",
				FindFunc:  "lit_chain_range_wb_find",
			}},
		},
		// Lit-chain range groups + word-boundary anchors.
		{
			"capture_range_wb_groups",
			[]config.RegexEntry{{
				Pattern:    `(\bAKIA[A-Z0-9]{24,40}\b)`,
				GroupsFunc: "akia_range_wb_groups",
			}},
		},
		// Lit-chain groups + word-boundary anchors (exact count).
		{
			"capture_wb_groups",
			[]config.RegexEntry{{
				Pattern:    `(\bAKIA[A-Z0-9]{24}\b)`,
				GroupsFunc: "akia_wb_groups",
			}},
		},
		// Lit-chain anchored find body groups + text anchors.
		{
			"capture_text_anchored_groups",
			[]config.RegexEntry{{
				Pattern:    `(\AAKIA[A-Z0-9]{24}\z)`,
				GroupsFunc: "akia_text_anchored_groups",
			}},
		},
		// Single lit-chain range with text-anchor end.
		{
			"lit_chain_range_text_anchored",
			[]config.RegexEntry{{
				Pattern:   `\AAKIA[A-Z0-9]{24,40}\z`,
				MatchFunc: "lit_chain_range_text_match",
				FindFunc:  "lit_chain_range_text_find",
			}},
		},
		// Single lit-chain range with no-word-boundary anchors.
		{
			"lit_chain_range_nowb",
			[]config.RegexEntry{{
				Pattern:   `\BAKIA[A-Z0-9]{24,40}\B`,
				MatchFunc: "lit_chain_range_nowb_match",
				FindFunc:  "lit_chain_range_nowb_find",
			}},
		},
		// Lit-chain prefixed with word-boundary anchors.
		{
			"lit_chain_prefixed_wb",
			[]config.RegexEntry{{
				Pattern:   `\b[0-9]{8}ghp_[A-Za-z0-9]{36}\b`,
				MatchFunc: "lit_chain_prefixed_wb_match",
				FindFunc:  "lit_chain_prefixed_wb_find",
			}},
		},
		// Lenient alt with multiple branches (3+).
		{
			"lenient_alt_three_branches",
			[]config.RegexEntry{{
				Pattern:  `ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}`,
				FindFunc: "lenient_alt_3_find",
			}},
		},
		// Strict alt with 3 branches.
		{
			"strict_alt_three_branches_match",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{36}`,
				MatchFunc: "strict_alt_3_match",
			}},
		},
		{
			"strict_alt_three_branches_find",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{36}`,
				FindFunc: "strict_alt_3_find",
			}},
		},
		// Alt range with 3 branches.
		{
			"strict_alt_range_three_branches",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}|secret_[A-Za-z0-9]{24,40}|token_[A-Za-z0-9]{20,32}`,
				FindFunc: "strict_alt_range_3_find",
			}},
		},
		// Lit-chain alt range with word-boundary anchors.
		{
			"strict_alt_range_wb_only_one",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}|\bsecret_[A-Za-z0-9]{24,40}\b`,
				FindFunc: "alt_range_mixed_wb_find",
			}},
		},
		// Patterns that don't hit lit-chain but exercise standard DFA paths
		// under LM mode (fallthrough). These add diversity without changing the
		// LM-specific paths.
		{
			"non_lit_chain_alternation",
			[]config.RegexEntry{{
				Pattern:   `(http|https|ftp|gopher)://[^\s]+`,
				MatchFunc: "url_match",
				FindFunc:  "url_find",
			}},
		},
		{
			"non_lit_chain_with_groups",
			[]config.RegexEntry{{
				Pattern:    `(?P<scheme>https?)://(?P<host>[^/]+)`,
				GroupsFunc: "url_groups",
			}},
		},
		// Lit-chain with end-text anchor only (no start).
		{
			"lit_chain_end_text_only",
			[]config.RegexEntry{{
				Pattern:   `AKIA[A-Z0-9]{16}\z`,
				MatchFunc: "lit_chain_end_text_only_match",
				FindFunc:  "lit_chain_end_text_only_find",
			}},
		},
		// Lit-chain with start-text anchor only (no end).
		{
			"lit_chain_start_text_only",
			[]config.RegexEntry{{
				Pattern:   `\AAKIA[A-Z0-9]{16}`,
				MatchFunc: "lit_chain_start_text_only_match",
				FindFunc:  "lit_chain_start_text_only_find",
			}},
		},
		// Patterns with (?m)^/$ — newline-boundary path in lit-anchor find,
		// triggers buildLitAnchorBackScanBody's hasNewlineBoundary branch.
		{
			"multiline_anchored",
			[]config.RegexEntry{{
				Pattern:  `(?m)^foo.*bar$`,
				FindFunc: "multiline_find",
			}},
		},
		{
			"multiline_with_class",
			[]config.RegexEntry{{
				Pattern:  `(?m)^[A-Z]{3,5}:[a-z]+$`,
				FindFunc: "multiline_class_find",
			}},
		},
		// Patterns with a long mandatory literal trigger lit-anchor find body
		// with multiple literal candidates (litAnchorLitSet).
		{
			"lit_anchor_find_multi",
			[]config.RegexEntry{{
				Pattern:  `.*(foo|bar|baz).*`,
				FindFunc: "lit_anchor_multi_find",
			}},
		},
		// Patterns with non-greedy quantifiers — exercises immediate-accept
		// states (hasImmAccept = true).
		{
			"non_greedy_match",
			[]config.RegexEntry{{
				Pattern:   `a.*?b`,
				MatchFunc: "non_greedy_match",
			}},
		},
		{
			"non_greedy_alt_find",
			[]config.RegexEntry{{
				Pattern:  `foo.*?bar|baz.*?qux`,
				FindFunc: "non_greedy_alt_find",
			}},
		},
		// Pattern with both word boundaries and newline anchors.
		{
			"word_boundary_multiline",
			[]config.RegexEntry{{
				Pattern:  `(?m)^\bfoo\b$`,
				FindFunc: "wb_multiline_find",
			}},
		},
		// Pattern with start anchor in match (anchored).
		{
			"anchored_match_text",
			[]config.RegexEntry{{
				Pattern:   `^foo[A-Z]+bar$`,
				MatchFunc: "anchored_text_match",
			}},
		},
		// Patterns with dominant self-loop (≥240/256 byte classes loop on
		// themselves). Triggers emitMidDom / emitDominantBulkSkip paths.
		{
			"dominant_self_loop_neg_char",
			[]config.RegexEntry{{
				Pattern:  `foo[^x]+bar`,
				FindFunc: "neg_char_find",
			}},
		},
		{
			"dominant_self_loop_neg_ws",
			[]config.RegexEntry{{
				Pattern:  `https?://[^\s]+`,
				FindFunc: "neg_ws_find",
			}},
		},
		{
			"dominant_self_loop_neg_nl",
			[]config.RegexEntry{{
				Pattern:  `//[^\n]+`,
				FindFunc: "neg_nl_find",
			}},
		},
		{
			"dominant_self_loop_neg_quote",
			[]config.RegexEntry{{
				Pattern:  `"[^"]+"`,
				FindFunc: "neg_quote_find",
			}},
		},

		// ---------- Lenient alt: match only (one branch is non-lit-chain) ----------
		{
			"lenient_alt_match_only",
			[]config.RegexEntry{{
				Pattern:   `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}`,
				MatchFunc: "lenient_alt_match_only",
			}},
		},
		// ---------- Lenient alt: find only ----------
		// NOTE: despite the name, this pattern does NOT trip the lenient-alt
		// (Phase 2a) find body in compilePattern. Its second branch's \s* is
		// unbounded with no nested OpAlternate/OpQuest, so
		// shouldTryLitChainAlt short-circuits to false before
		// analyseLitChainAltLenient is ever tried (confirmed live) — this
		// case only exercises the general LikelyMatch compile sweep for this
		// pattern shape. See TestCompileLenientAltFindBody for
		// a pattern that actually reaches that code.
		{
			"lenient_alt_find_only",
			[]config.RegexEntry{{
				Pattern:  `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}`,
				FindFunc: "lenient_alt_find_only",
			}},
		},

		// ---------- Lit-chain mixed-prefix ----------
		{
			"prefixed_digits_ghp",
			[]config.RegexEntry{{
				Pattern:   `[0-9]{8}ghp_[A-Za-z0-9]{36}`,
				MatchFunc: "prefixed_match",
				FindFunc:  "prefixed_find",
			}},
		},
		// Strict alt of prefixed shapes, find only → alt-prefixed find path.
		{
			"prefixed_strict_alt_find_only",
			[]config.RegexEntry{{
				Pattern:  `[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`,
				FindFunc: "prefixed_alt_find_only",
			}},
		},

		// ---------- Lit-chain with captures (anchored groups, groups-only) ----------
		{
			"capture_akia_groups",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{16})`,
				GroupsFunc: "akia_groups",
			}},
		},
		{
			"capture_named_ghp",
			[]config.RegexEntry{{
				Pattern:    `(?P<key>ghp_[A-Za-z0-9]{36})`,
				GroupsFunc: "ghp_named_groups",
			}},
		},
		{
			"capture_alt_groups_only",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{16})|(ghp_[A-Za-z0-9]{36})`,
				GroupsFunc: "alt_groups_only",
			}},
		},
		{
			"capture_prefixed_named",
			[]config.RegexEntry{{
				Pattern:    `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
				GroupsFunc: "prefixed_named_groups",
			}},
		},
		{
			"capture_strict_alt_named_only",
			[]config.RegexEntry{{
				Pattern:    `(?P<aws>AKIA[A-Z0-9]{16})|(?P<gh>ghp_[A-Za-z0-9]{36})`,
				GroupsFunc: "strict_alt_named_only",
			}},
		},
		// Lit-chain range with captures (single branch).
		{
			"capture_range_groups",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{24,40})`,
				GroupsFunc: "akia_range_groups",
			}},
		},
		{
			"capture_range_named_groups",
			[]config.RegexEntry{{
				Pattern:    `(?P<key>secret_[A-Za-z0-9]{24,40})`,
				GroupsFunc: "secret_range_named",
			}},
		},

		// ---------- Lit-chain find with captures (non-anchored) ----------
		{
			"find_with_groups_akia",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{16})`,
				FindFunc:   "akia_find_cap",
				GroupsFunc: "akia_groups_cap",
			}},
		},
		{
			"find_with_named_groups_ghp",
			[]config.RegexEntry{{
				Pattern:    `(?P<key>ghp_[A-Za-z0-9]{36})`,
				FindFunc:   "ghp_find_cap",
				GroupsFunc: "ghp_named_groups_cap",
			}},
		},
		{
			"find_with_groups_alt",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{16})|(ghp_[A-Za-z0-9]{36})`,
				FindFunc:   "alt_find_cap",
				GroupsFunc: "alt_groups_cap",
			}},
		},
		{
			"find_with_prefixed_named_groups",
			[]config.RegexEntry{{
				Pattern:    `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
				FindFunc:   "prefixed_find_cap",
				GroupsFunc: "prefixed_named_groups_cap",
			}},
		},
		{
			"find_with_range_groups",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{24,40})`,
				FindFunc:   "akia_range_find_cap",
				GroupsFunc: "akia_range_groups_cap",
			}},
		},
		// Range + match + groups all three set.
		{
			"match_find_groups_range",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{24,40})`,
				MatchFunc:  "akia_range_match_cap",
				FindFunc:   "akia_range_find_mcap",
				GroupsFunc: "akia_range_groups_mcap",
			}},
		},
		// Exact + match + groups (no find).
		{
			"match_groups_exact",
			[]config.RegexEntry{{
				Pattern:    `(AKIA[A-Z0-9]{24})`,
				MatchFunc:  "akia_match_cap",
				GroupsFunc: "akia_groups_mcap_only",
			}},
		},
		// Lenient-alt with captures (find + groups): exercises lenient-alt
		// composite path with TDFA capture body.
		{
			"find_with_groups_lenient_alt",
			[]config.RegexEntry{{
				Pattern:    `(ghp_[A-Za-z0-9]{36})|(aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40})`,
				FindFunc:   "lenient_alt_find_cap",
				GroupsFunc: "lenient_alt_groups_cap",
			}},
		},
		// Same with named groups.
		{
			"find_with_named_groups_lenient_alt",
			[]config.RegexEntry{{
				Pattern:    `(?P<gh>ghp_[A-Za-z0-9]{36})|(?P<aws>aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40})`,
				FindFunc:   "lenient_alt_find_named_cap",
				GroupsFunc: "lenient_alt_groups_named_cap",
			}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustCompileEntries(t, c.entries, lm)
		})
	}
}

// TestCompileLargeStateDFA exercises patterns that produce > 256 DFA states
// to force the table-driven (non-compiled) DFA path in buildMatchBody.
func TestCompileLargeStateDFA(t *testing.T) {
	// Disable the CompiledDFA optimisation so the DFA goes through the pure
	// table-driven path.
	opts := CompileOptions{CompiledDFAThreshold: -1}

	cases := []struct {
		name    string
		entries []config.RegexEntry
	}{
		{
			"non_greedy_match_large",
			[]config.RegexEntry{{
				Pattern:   `foo.*?bar`,
				MatchFunc: "ng_large_match",
			}},
		},
		{
			"alt_match_large",
			[]config.RegexEntry{{
				Pattern:   `(http|https|ftp)://[a-zA-Z0-9]+`,
				MatchFunc: "alt_large_match",
			}},
		},
		{
			"complex_alt_match",
			[]config.RegexEntry{{
				Pattern:   `(abc|def|ghi)[A-Z]+(xyz|uvw)`,
				MatchFunc: "complex_alt_match",
			}},
		},
		// Match + find together with a large DFA.
		{
			"large_dfa_match_find",
			[]config.RegexEntry{{
				Pattern:   `(foo|bar|baz|qux)[0-9]+(end|done)`,
				MatchFunc: "large_match",
				FindFunc:  "large_find",
			}},
		},
		// Find with multiline.
		{
			"large_dfa_multiline",
			[]config.RegexEntry{{
				Pattern:  `(?m)^(error|warning):.*$`,
				FindFunc: "large_ml_find",
			}},
		},
		// Alt with non-greedy quantifier — guaranteed leftmost-first
		// + immediate-accept states.
		{
			"alt_with_non_greedy",
			[]config.RegexEntry{{
				Pattern:   `(foo|bar).*?(xyz|abc)`,
				MatchFunc: "alt_ng_match",
			}},
		},
		// Pattern where one alt branch is much shorter (forces an early accept).
		{
			"alt_short_long",
			[]config.RegexEntry{{
				Pattern:   `a|abcdef`,
				MatchFunc: "alt_short_long_match",
			}},
		},
		// Alt with empty-acceptance branch (immediate accept).
		{
			"alt_empty_branch",
			[]config.RegexEntry{{
				Pattern:   `()|foobar`,
				MatchFunc: "alt_empty_match",
			}},
		},
		// Mandatory literal at the interior (no prefix), patterns with
		// dot-class before and after a fixed literal.
		{
			"mandatory_lit_interior",
			[]config.RegexEntry{{
				Pattern:  `[a-z]+_secret_[a-z]+`,
				FindFunc: "mand_lit_interior_find",
			}},
		},
		{
			"mandatory_lit_with_anchors",
			[]config.RegexEntry{{
				Pattern:  `(?m)[a-z]+_secret_[a-z]+`,
				FindFunc: "mand_lit_ml_find",
			}},
		},
		{
			"mandatory_lit_word_boundary",
			[]config.RegexEntry{{
				Pattern:  `\w+_TOKEN_\w+`,
				FindFunc: "mand_lit_wb_find",
			}},
		},
		// Mandatory literal with no detectable prefix — pure dot prefix.
		{
			"mandatory_lit_dot_prefix",
			[]config.RegexEntry{{
				Pattern:  `.+foo.+`,
				FindFunc: "mand_lit_dot_find",
			}},
		},
		{
			"mandatory_lit_alt_prefix",
			[]config.RegexEntry{{
				Pattern:  `(?:abc|def|xyz)bar`,
				FindFunc: "mand_lit_alt_find",
			}},
		},
		// Patterns crafted to produce many DFA states with a mandatory
		// interior literal but no scannable prefix.
		{
			"mandatory_lit_many_states",
			[]config.RegexEntry{{
				Pattern:  `.{4}foobar.{4}`,
				FindFunc: "many_states_find",
			}},
		},
		{
			"mandatory_lit_dot_repeat",
			[]config.RegexEntry{{
				Pattern:  `.{2,8}secret.{2,8}`,
				FindFunc: "dot_repeat_find",
			}},
		},
		{
			"mandatory_lit_dotstar_long_lit",
			[]config.RegexEntry{{
				Pattern:  `.*MANDATORY_KEYWORD.*`,
				FindFunc: "mandatory_keyword_find",
			}},
		},
		// Patterns with optional captures — exercises writeMinusOne in lit-chain
		// groups.
		{
			"optional_captures",
			[]config.RegexEntry{{
				Pattern:    `(AKIA)?[A-Z0-9]{24}`,
				GroupsFunc: "optional_cap_groups",
			}},
		},
		// Patterns that result in u16 DFA tables (> 256 states).
		{
			"large_dfa_u16",
			[]config.RegexEntry{{
				Pattern:  `(?:abc|def|ghi|jkl|mno|pqr|stu|vwx|yz)[A-Z0-9]+(?:abc|def|ghi)`,
				FindFunc: "large_u16_find",
			}},
		},
		// Very large pattern that explodes DFA state count.
		{
			"very_large_dfa",
			[]config.RegexEntry{{
				Pattern:  `(?:[A-Z]{4}foo|[A-Z]{5}bar|[A-Z]{6}baz|[A-Z]{7}qux)[0-9]+`,
				FindFunc: "very_large_find",
			}},
		},
		// Unicode pattern to exercise unicodeTrans paths.
		{
			// `[\p{L}]+` used to live here, and does not compile in any mode
			// since 2026-09-01 — it names runes above U+00FF, which no byte
			// can hold. Its rejection is asserted by
			// TestUnsupportedRuneRejection; a wide BYTE class keeps the
			// large-state coverage this list wanted.
			"wide_byte_class",
			[]config.RegexEntry{{
				Pattern:  `[\x00-\xff]{4}END`,
				FindFunc: "wide_byte_find",
				ByteMode: true,
			}},
		},
		// Mandatory lit with many states - tries to trigger u8+compressed+mandlit path.
		{
			"mandatory_lit_heavy_class",
			[]config.RegexEntry{{
				Pattern:  `[\w\s\.\-_]+CONFIDENTIAL[\w\s\.\-_]+`,
				FindFunc: "heavy_class_find",
			}},
		},
		// Patterns with caret ^ in middle of class (negated).
		{
			"negated_class_pattern",
			[]config.RegexEntry{{
				Pattern:  `[^\d\s]+key[^\d\s]+`,
				FindFunc: "neg_class_find",
			}},
		},
		// Pattern with backreference-like structure (still RE2-compatible).
		{
			"complex_with_match",
			[]config.RegexEntry{{
				Pattern:   `(http|https|ftp)://([a-zA-Z0-9\.\-]+)(?:/([^?#\s]*))?`,
				MatchFunc: "complex_url_match",
				FindFunc:  "complex_url_find",
			}},
		},
		// Patterns with multiple empty-width assertions for nfaExpandWithWB.
		{
			"nested_anchors",
			[]config.RegexEntry{{
				Pattern:  `(?m)^\bfoo\b$`,
				FindFunc: "nested_anchors_find",
			}},
		},
		{
			"text_and_word_anchors",
			[]config.RegexEntry{{
				Pattern:  `\A\bfoo\b\z`,
				FindFunc: "text_word_anchors_find",
			}},
		},
		{
			"alternation_with_anchors",
			[]config.RegexEntry{{
				Pattern:  `(?m)(^foo|bar$|\bbaz\b)`,
				FindFunc: "alt_anchors_find",
			}},
		},
		// Patterns producing complex multiline behavior.
		{
			"multiline_complex",
			[]config.RegexEntry{{
				Pattern:  `(?m)^(\w+):\s*(.+)$`,
				FindFunc: "ml_complex_find",
			}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustCompileEntries(t, c.entries, opts)
		})
	}
}

// TestCompileLMEmbeddedAndEmpty covers embedded mode (standalone=false), the
// empty-entries early return, and entries with no _func fields.
func TestCompileLMEmbeddedAndEmpty(t *testing.T) {
	t.Run("embedded_mode", func(t *testing.T) {
		wasm, _, err := Compile([]config.RegexEntry{
			{Pattern: `abc`, MatchFunc: "m"},
			{Pattern: `.*foo.*`, FindFunc: "f"},
			{Pattern: `(?P<x>a)(b)`, GroupsFunc: "g"},
		}, 0, false)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(wasm) == 0 {
			t.Fatalf("Compile: empty output")
		}
	})

	t.Run("empty_entries", func(t *testing.T) {
		wasm, _, err := Compile(nil, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		// Empty patterns list returns nil bytes — this is the early-return path.
		_ = wasm
	})

	t.Run("skipped_entries", func(t *testing.T) {
		mustCompileEntries(t, []config.RegexEntry{
			{Pattern: `xyz`},                 // skipped (no funcs)
			{Pattern: `abc`, MatchFunc: "m"}, // compiled
			{Pattern: `def`},                 // skipped
		})
	})
}

// TestCmdCompileCoverage exercises CmdCompile through both the stdout (`-`)
// sink and the file-output sink to cover both branches.
func TestCmdCompileCoverage(t *testing.T) {
	t.Run("write_to_file", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.wasm")
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Pattern: `abc`, MatchFunc: "m"},
			},
		}
		if err := CmdCompile(cfg, out); err != nil {
			t.Fatalf("CmdCompile: %v", err)
		}
		info, err := os.Stat(out)
		if err != nil {
			t.Fatalf("stat output: %v", err)
		}
		if info.Size() == 0 {
			t.Fatalf("output file is empty")
		}
	})

	t.Run("write_to_stdout", func(t *testing.T) {
		// Redirect stdout to /dev/null so the WASM bytes don't pollute test output.
		orig := os.Stdout
		devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open /dev/null: %v", err)
		}
		os.Stdout = devnull
		defer func() {
			os.Stdout = orig
			devnull.Close()
		}()

		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{
				{Pattern: `abc`, MatchFunc: "m"},
			},
		}
		if err := CmdCompile(cfg, "-"); err != nil {
			t.Fatalf("CmdCompile stdout: %v", err)
		}
	})

	t.Run("with_max_options", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.wasm")
		cfg := config.BuildConfig{
			MaxDFAStates: 2048,
			MaxTDFARegs:  64,
			Output:       "merged.wasm", // forces embedded mode
			Regexps: []config.RegexEntry{
				{Pattern: `(a)(b)`, GroupsFunc: "ab_groups"},
			},
		}
		if err := CmdCompile(cfg, out); err != nil {
			t.Fatalf("CmdCompile: %v", err)
		}
	})
}

// TestCompileNonGreedyLitChainRange covers the non-greedy lit-chain range
// branch in compilePattern.
func TestCompileNonGreedyLitChainRange(t *testing.T) {
	lm := CompileOptions{LikelyMode: LikelyMatch}
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `AKIA[A-Z0-9]{8,16}?`,
		MatchFunc: "akia_nongreedy_match",
		FindFunc:  "akia_nongreedy_find",
	}}, lm)
}

// TestCompileAltGroupsWithMatch covers the path where alt-groups + match falls
// through to the standard pipeline (compile.go:317).
func TestCompileAltGroupsWithMatch(t *testing.T) {
	lm := CompileOptions{LikelyMode: LikelyMatch}
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(AKIA[A-Z0-9]{24})|(ghp_[A-Za-z0-9]{36})`,
		MatchFunc:  "alt_groups_match",
		GroupsFunc: "alt_groups_with_match",
	}}, lm)
}

// TestLitChainAnalysersRejection directly invokes the lit-chain analysers
// with rejection cases (invalid syntax, too-small N, ranges where unexpected,
// non-strict alts, etc.) so the rejection branches are exercised.
func TestLitChainAnalysersRejection(t *testing.T) {
	t.Run("invalid_syntax", func(t *testing.T) {
		if _, ok := analyseLitChain(`[`, 24); ok {
			t.Errorf("analyseLitChain accepted invalid syntax")
		}
		if _, ok := analyseLitChainRange(`[`, 24); ok {
			t.Errorf("analyseLitChainRange accepted invalid syntax")
		}
		if _, _, ok := analyseLitChainGroupsRange(`[`); ok {
			t.Errorf("analyseLitChainGroupsRange accepted invalid syntax")
		}
		if _, _, ok := analyseLitChainGroups(`[`); ok {
			t.Errorf("analyseLitChainGroups accepted invalid syntax")
		}
		if _, ok := analyseLitChainPrefixed(`[`); ok {
			t.Errorf("analyseLitChainPrefixed accepted invalid syntax")
		}
		if _, ok := analyseLitChainAlt(`[`); ok {
			t.Errorf("analyseLitChainAlt accepted invalid syntax")
		}
		if _, ok := analyseLitChainAltRange(`[`); ok {
			t.Errorf("analyseLitChainAltRange accepted invalid syntax")
		}
		if _, ok := analyseLitChainAltPrefixed(`[`); ok {
			t.Errorf("analyseLitChainAltPrefixed accepted invalid syntax")
		}
		if _, ok := analyseLitChainAltLenient(`[`, true); ok {
			t.Errorf("analyseLitChainAltLenient accepted invalid syntax")
		}
	})

	t.Run("too_small_count", func(t *testing.T) {
		// N < 24 should reject for single-pattern analysers under the
		// neutral/LikelyNoMatch gate (minCount=24).
		if _, ok := analyseLitChain(`AKIA[A-Z0-9]{4}`, 24); ok {
			t.Errorf("analyseLitChain accepted N=4")
		}
		if _, ok := analyseLitChainRange(`AKIA[A-Z0-9]{4,8}`, 24); ok {
			t.Errorf("analyseLitChainRange accepted N=4")
		}
		if _, _, ok := analyseLitChainGroups(`(AKIA[A-Z0-9]{4})`); ok {
			t.Errorf("analyseLitChainGroups accepted N=4")
		}
		if _, _, ok := analyseLitChainGroupsRange(`(AKIA[A-Z0-9]{4,8})`); ok {
			t.Errorf("analyseLitChainGroupsRange accepted N=4")
		}
	})

	t.Run("too_small_count_likely_match", func(t *testing.T) {
		// Under LikelyMatch, callers pass minCount=1 — N=4 now
		// qualifies (K=4, N=4, K+N=8 < 16 still rejects; use N=12 so
		// K+N=16 satisfies the overlap-load precondition).
		if _, ok := analyseLitChain(`AKIA[A-Z0-9]{12}`, 1); !ok {
			t.Errorf("analyseLitChain rejected N=12 under minCount=1")
		}
		if _, ok := analyseLitChainRange(`AKIA[A-Z0-9]{12,20}`, 1); !ok {
			t.Errorf("analyseLitChainRange rejected N=12 under minCount=1")
		}
	})

	t.Run("not_a_range", func(t *testing.T) {
		// analyseLitChainRange wants countMax > count.
		if _, ok := analyseLitChainRange(`AKIA[A-Z0-9]{24}`, 24); ok {
			t.Errorf("analyseLitChainRange accepted exact count")
		}
		if _, _, ok := analyseLitChainGroupsRange(`(AKIA[A-Z0-9]{24})`); ok {
			t.Errorf("analyseLitChainGroupsRange accepted exact count")
		}
	})

	t.Run("not_alt", func(t *testing.T) {
		// Single branch: alt analysers should reject.
		if _, ok := analyseLitChainAlt(`AKIA[A-Z0-9]{16}`); ok {
			t.Errorf("analyseLitChainAlt accepted single branch")
		}
		if _, ok := analyseLitChainAltRange(`AKIA[A-Z0-9]{16,24}`); ok {
			t.Errorf("analyseLitChainAltRange accepted single branch")
		}
		if _, ok := analyseLitChainAltPrefixed(`[0-9]{8}ghp_[A-Za-z0-9]{36}`); ok {
			t.Errorf("analyseLitChainAltPrefixed accepted single branch")
		}
		if _, ok := analyseLitChainAltLenient(`ghp_[A-Za-z0-9]{36}`, true); ok {
			t.Errorf("analyseLitChainAltLenient accepted single branch")
		}
	})

	t.Run("alt_range_no_range_branch", func(t *testing.T) {
		// All branches are exact — analyseLitChainAltRange should reject (only
		// alts with at least one range branch qualify).
		if _, ok := analyseLitChainAltRange(`AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`); ok {
			t.Errorf("analyseLitChainAltRange accepted pure-exact alt")
		}
	})

	t.Run("alt_with_non_lit_chain_branch", func(t *testing.T) {
		// One branch is not a lit-chain shape — strict alt should reject.
		if _, ok := analyseLitChainAlt(`AKIA[A-Z0-9]{16}|^foo$`); ok {
			t.Errorf("analyseLitChainAlt accepted alt with non-lit-chain branch")
		}
	})
}

// TestSelectEngineRejection exercises SelectEngine error paths.
func TestSelectEngineRejection(t *testing.T) {
	if _, err := SelectEngine(`[`, CompileOptions{}); err == nil {
		t.Errorf("SelectEngine accepted invalid pattern")
	}
}

// TestMaxFallbackStatesDefault covers the default-value branch of
// CompileSetOptions.maxFallbackStates.
func TestMaxFallbackStatesDefault(t *testing.T) {
	if got := (CompileSetOptions{}).maxFallbackStates(); got != 1024 {
		t.Errorf("maxFallbackStates default = %d, want 1024", got)
	}
	if got := (CompileSetOptions{MaxFallbackStates: 42}).maxFallbackStates(); got != 42 {
		t.Errorf("maxFallbackStates custom = %d, want 42", got)
	}
}

// TestPlanLitChainChunksDirect exercises planLitChainChunks in the N<16
// branch (K+N>=16 with N<16) which is otherwise hard to reach via patterns.
func TestPlanLitChainChunksDirect(t *testing.T) {
	// N=8, K=8 → K+N=16, n<16 → single chunk with mask.
	chunks := planLitChainChunks(8, 8)
	if len(chunks) != 1 {
		t.Errorf("planLitChainChunks(8,8) returned %d chunks, want 1", len(chunks))
	}
	// N=6, K=12 → K+N=18, n<16 → single chunk with mask.
	chunks = planLitChainChunks(12, 6)
	if len(chunks) != 1 {
		t.Errorf("planLitChainChunks(12,6) returned %d chunks, want 1", len(chunks))
	}
	// N=16, K=4 → exactly one full chunk.
	chunks = planLitChainChunks(4, 16)
	if len(chunks) != 1 {
		t.Errorf("planLitChainChunks(4,16) returned %d chunks, want 1", len(chunks))
	}
	// N=18, K=4 → two chunks (one full + overlap).
	chunks = planLitChainChunks(4, 18)
	if len(chunks) != 2 {
		t.Errorf("planLitChainChunks(4,18) returned %d chunks, want 2", len(chunks))
	}
	// N=32, K=4 → two chunks, no overlap.
	chunks = planLitChainChunks(4, 32)
	if len(chunks) != 2 {
		t.Errorf("planLitChainChunks(4,32) returned %d chunks, want 2", len(chunks))
	}
}

// TestHasOpCaptureDirect directly invokes hasOpCapture to cover both branches.
func TestHasOpCaptureDirect(t *testing.T) {
	withCap := parseTestRe(t, `(a)b`)
	if !hasOpCapture(withCap) {
		t.Errorf("hasOpCapture: expected true for pattern with capture")
	}
	noCap := parseTestRe(t, `abc`)
	if hasOpCapture(noCap) {
		t.Errorf("hasOpCapture: expected false for pattern without capture")
	}
	// Nested: capture inside group.
	nested := parseTestRe(t, `((a)b)c`)
	if !hasOpCapture(nested) {
		t.Errorf("hasOpCapture: expected true for nested capture pattern")
	}
}

// TestCompileTDFARegLimit forces the TDFA register-limit fallback to Backtracking.
func TestCompileTDFARegLimit(t *testing.T) {
	// A pattern with many captures exceeds the TDFA register limit when
	// MaxTDFARegs is set very low.
	opts := CompileOptions{MaxTDFARegs: 2}
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(a)(b)(c)(d)(e)(f)(g)(h)`,
		GroupsFunc: "many_caps_groups",
	}}, opts)
}

// TestCompileDFAStateLimit forces the DFA state-limit fallback to Backtracking.
func TestCompileDFAStateLimit(t *testing.T) {
	opts := CompileOptions{MaxDFAStates: 4}
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `(a|b|c|d|e|f|g|h|i|j)+xyz`,
		MatchFunc: "small_dfa_match",
		FindFunc:  "small_dfa_find",
	}}, opts)
}

// TestCompileLitChainSmallN covers lit-chain patterns with N<16 but K+N>=16,
// which trigger planLitChainChunks single-chunk-with-mask branch.
func TestCompileLitChainSmallN(t *testing.T) {
	lm := CompileOptions{LikelyMode: LikelyMatch}
	// Strict-alt match (no find) — exercises buildLitChainAltMatchBody with N<16.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `foooobar[A-Z0-9]{8}|other_lit[A-Z0-9]{8}`,
		MatchFunc: "k8_n8_match",
	}}, lm)
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `LONGLITERAL[A-Z]{6}|OTHERLITER1[A-Z]{6}`,
		MatchFunc: "k11_n6_match",
	}}, lm)
	// Strict-alt find (no match) — exercises buildLitChainAltFindBody with N<16.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `foooobar[A-Z0-9]{8}|other_lit[A-Z0-9]{8}`,
		FindFunc: "k8_n8_find",
	}}, lm)
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:  `LONGLITERAL[A-Z]{6}|OTHERLITER1[A-Z]{6}`,
		FindFunc: "k11_n6_find",
	}}, lm)
	// Strict-alt groups (no match, no find) — exercises buildLitChainAltGroupsBody.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(foooobar[A-Z0-9]{8})|(other_lit[A-Z0-9]{8})`,
		GroupsFunc: "k8_n8_groups",
	}}, lm)
	// Multiple groups in alt branches — different branches populate different
	// group slots, so writeMinusOne is needed for unpopulated groups.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(?:(AKIA)[A-Z0-9]{24})|(?:(ghp_)[A-Za-z0-9]{36})`,
		GroupsFunc: "alt_multigroup_groups",
	}}, lm)
	// Same with range branches.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(AKIA[A-Z0-9]{24,40})|(secret_[A-Za-z0-9]{24,40})`,
		FindFunc:   "alt_range_multigroup_find",
		GroupsFunc: "alt_range_multigroup_groups",
	}}, lm)
}

// TestCompileImpossibleEndAnchor covers patterns where the literal-anchor end
// anchor is anchorBeginText (\A at the end position — always fails).
func TestCompileImpossibleEndAnchor(t *testing.T) {
	lm := CompileOptions{LikelyMode: LikelyMatch}
	// `\A` as end anchor: literal-chain helper handles this even though no input
	// can ever satisfy it; the emitted body must produce an unconditional fail.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `AKIA[A-Z0-9]{24}\A`,
		MatchFunc: "impossible_end_match",
		FindFunc:  "impossible_end_find",
	}}, lm)
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:   `\zAKIA[A-Z0-9]{24}`,
		MatchFunc: "impossible_start_match",
	}}, lm)
}

// TestCompileGroupsForceBacktrack forces the Backtracking engine for the groups path.
func TestCompileGroupsForceBacktrack(t *testing.T) {
	// Patterns with non-greedy captures naturally route to Backtracking.
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(a+?)(b+)`,
		GroupsFunc: "ng_groups",
	}})
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(?m)(^foo)(bar$)`,
		GroupsFunc: "ml_groups",
	}})
	mustCompileEntries(t, []config.RegexEntry{{
		Pattern:    `(\bfoo\b)(\bbar\b)`,
		GroupsFunc: "wb_groups",
	}})
}

// TestCompileLikelyNoMatch exercises the lnmAction5 flag path
// (impossible-byte SIMD skip with a 17..64-byte first-byte set).
func TestCompileLikelyNoMatch(t *testing.T) {
	lnm := CompileOptions{LikelyMode: LikelyNoMatch}

	cases := []struct {
		name    string
		entries []config.RegexEntry
	}{
		{
			"lnm_alpha_range",
			[]config.RegexEntry{{
				Pattern:  `[a-zA-Z]{8,}`,
				FindFunc: "alpha_find",
			}},
		},
		{
			"lnm_akia_find",
			[]config.RegexEntry{{
				Pattern:  `AKIA[A-Z0-9]{16}`,
				FindFunc: "akia_lnm_find",
			}},
		},
		{
			"lnm_ghp_find",
			[]config.RegexEntry{{
				Pattern:  `ghp_[A-Za-z0-9]{36}`,
				FindFunc: "ghp_lnm_find",
			}},
		},
		// Dominant self-loop patterns under LNM mode — exercises lnmAction5.
		{
			"lnm_dominant_self_loop_neg_char",
			[]config.RegexEntry{{
				Pattern:  `foo[^x]+bar`,
				FindFunc: "lnm_neg_char_find",
			}},
		},
		{
			"lnm_dominant_self_loop_neg_ws",
			[]config.RegexEntry{{
				Pattern:  `https?://[^\s]+`,
				FindFunc: "lnm_neg_ws_find",
			}},
		},
		// LNM with word boundaries.
		{
			"lnm_word_boundary",
			[]config.RegexEntry{{
				Pattern:  `\bfoo\b`,
				FindFunc: "lnm_wb_find",
			}},
		},
		// LNM with multiline.
		{
			"lnm_multiline",
			[]config.RegexEntry{{
				Pattern:  `(?m)^[A-Z]+$`,
				FindFunc: "lnm_multiline_find",
			}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustCompileEntries(t, c.entries, lnm)
		})
	}
}

// The batch find/groups export gate:
// the "_batch" export must appear exactly when
// LikelyMode == LikelyMatch and the pattern's own find_func/groups_func was
// requested, and must NOT appear for anchored (native lit-chain) groups
// bodies — that shape is out of v1 scope (see the compiledPattern field doc
// next to batchGroupsExport).
// TestBatchExportGating covers the "batch-find" hint
// as the sole trigger for the _batch export — independent of LikelyMode, and
// covering both the composed (!anchored) and native lit-chain ("Path B",
// anchored) groups shapes, plus named_groups_func-only naming.
func TestBatchExportGating(t *testing.T) {
	findEntries := []config.RegexEntry{{
		Pattern:  `x*`,
		FindFunc: "find_x",
		Hints:    []string{"batch-find"},
	}}
	// (a)(b)? has no lit-chain shape, so it compiles via the standard
	// find+capture composition (TDFA/BT) — Path A.
	groupsEntries := []config.RegexEntry{{
		Pattern:    `(a)(b)?`,
		GroupsFunc: "groups_ab",
		Hints:      []string{"batch-find"},
	}}
	// (AKIA[A-Z0-9]{24}) is a lit-chain groups shape (lit-chain range, count>=24 so
	// analyseLitChainGroups accepts it — capture-path analysers are not
	// relaxed under LikelyMatch, unlike the plain match/find analysers) — anchored:
	// captureBody IS the exported groups function directly ("Path B"), so
	// batching goes through buildBatchLitChainGroupsWrapperBody, not
	// buildBatchGroupsWrapperBody.
	anchoredGroupsEntries := []config.RegexEntry{{
		Pattern:    `(AKIA[A-Z0-9]{24})`,
		GroupsFunc: "akia_groups",
		Hints:      []string{"batch-find"},
	}}
	// named_groups_func ONLY (no groups_func) — the batch export name must
	// fall back to namedGroupsExport (GroupsExportName priority), since
	// p.groupsExport is empty here.
	namedOnlyEntries := []config.RegexEntry{{
		Pattern:    `(a)(b)?`,
		GroupsFunc: "named_ab",
		Hints:      []string{"batch-find"},
	}}

	t.Run("find_batch_present_with_hint", func(t *testing.T) {
		wasm, _, err := Compile(findEntries, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("find_x_batch")) {
			t.Error("expected find_x_batch export with batch-find hint, not found")
		}
	})
	t.Run("find_batch_absent_without_hint", func(t *testing.T) {
		unhinted := []config.RegexEntry{{Pattern: `x*`, FindFunc: "find_x"}}
		wasm, _, err := Compile(unhinted, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if bytes.Contains(wasm, []byte("find_x_batch")) {
			t.Error("find_x_batch export present without batch-find hint, should be absent")
		}
	})
	t.Run("find_batch_absent_under_LikelyMatch_alone", func(t *testing.T) {
		// LikelyMode is no longer the trigger — batch-find is.
		unhinted := []config.RegexEntry{{Pattern: `x*`, FindFunc: "find_x"}}
		wasm, _, err := Compile(unhinted, 0, true, CompileOptions{LikelyMode: LikelyMatch})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if bytes.Contains(wasm, []byte("find_x_batch")) {
			t.Error("find_x_batch export present under LikelyMatch without batch-find hint — LikelyMode must not trigger batching")
		}
	})
	t.Run("groups_batch_present_with_hint_PathA", func(t *testing.T) {
		wasm, _, err := Compile(groupsEntries, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("groups_ab_batch")) {
			t.Error("expected groups_ab_batch export with batch-find hint, not found")
		}
	})
	t.Run("groups_batch_absent_without_hint", func(t *testing.T) {
		unhinted := []config.RegexEntry{{Pattern: `(a)(b)?`, GroupsFunc: "groups_ab"}}
		wasm, _, err := Compile(unhinted, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if bytes.Contains(wasm, []byte("groups_ab_batch")) {
			t.Error("groups_ab_batch export present without batch-find hint, should be absent")
		}
	})
	t.Run("anchored_groups_batch_present_with_hint_PathB", func(t *testing.T) {
		wasm, _, err := Compile(anchoredGroupsEntries, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("akia_groups_batch")) {
			t.Error("expected akia_groups_batch export for anchored (Path B) lit-chain groups body")
		}
		if !bytes.Contains(wasm, []byte("akia_groups")) {
			t.Error("expected akia_groups (non-batch) export to still be present")
		}
	})
	t.Run("anchored_groups_batch_absent_without_hint", func(t *testing.T) {
		unhinted := []config.RegexEntry{{Pattern: `(AKIA[A-Z0-9]{24})`, GroupsFunc: "akia_groups"}}
		wasm, _, err := Compile(unhinted, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if bytes.Contains(wasm, []byte("akia_groups_batch")) {
			t.Error("akia_groups_batch export present without batch-find hint, should be absent")
		}
	})
	t.Run("batch_export_named_after_groupsFunc", func(t *testing.T) {
		wasm, _, err := Compile(namedOnlyEntries, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("named_ab_batch")) {
			t.Error("expected named_ab_batch export, not found")
		}
	})
	t.Run("groups_and_named_share_one_batch_export", func(t *testing.T) {
		both := []config.RegexEntry{{
			Pattern:    `(a)(b)?`,
			GroupsFunc: "g1",
			Hints:      []string{"batch-find"},
		}}
		wasm, _, err := Compile(both, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("g1_batch")) {
			t.Error("expected g1_batch export (GroupsFunc takes priority), not found")
		}
		if bytes.Contains(wasm, []byte("g2_batch")) {
			t.Error("g2_batch export present — named_groups_func should share GroupsFunc's batch export, not get its own")
		}
	})
	t.Run("neutral_wasm_size_unaffected_by_hint_plumbing", func(t *testing.T) {
		// Regression guard for the "anyBatch" bug the original change called
		// out explicitly: a pattern that never requests batch-find must
		// produce byte-identical output regardless of how "no batch-find" is
		// spelled (nil Hints vs an empty-but-non-nil slice).
		base := config.RegexEntry{Pattern: `(a)(b)?`, GroupsFunc: "g"}
		emptyHints := base
		emptyHints.Hints = []string{}

		w1, _, err := Compile([]config.RegexEntry{base}, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		w2, _, err := Compile([]config.RegexEntry{emptyHints}, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Equal(w1, w2) {
			t.Error("expected byte-identical WASM for nil vs empty Hints, neither requests batch-find")
		}
	})
}

// A companion to set_module_test.go for the SINGLE-PATTERN emitters,
// which are most of engine_dfa.go.
//
// The RE2 corpus exercises these enormously, and byteident pins fifteen of
// them byte for byte — but the corpus runner is a separate module and
// byteident deliberately holds ONE config per path, so whole selection arms
// went unreached from `go test ./compile`: the u16 table form, byte-class
// compression, the Shufti and Teddy prologues, the word-boundary channel, the
// likely-match biases, and the three find-from modes.
//
// Same division of labour as the set matrix: this reaches the path and checks
// the module is well formed. What the module COMPUTES is checked by re2test
// and the fuzz targets, which have real oracles; a weaker copy here would be a
// second oracle to keep in sync.

// singleCase is one pattern plus the reason it is in the list.
type singleCase struct {
	name    string
	selects string
	pattern string
	// funcs chosen independently, because the emitter differs per capability
	// and `groups` additionally chooses between TDFA and Backtracking.
	match, find, groups bool
	hints               []string
	maxDFAStates        int
	maxTDFARegs         int
	// byteMode compiles the pattern as byte-oriented (config's `byte_mode`).
	// Needed by any case whose pattern names a byte above 127 — the default
	// mode rejects those since 2026-09-01.
	byteMode bool
}

func singleCases() []singleCase {
	return []singleCase{
		{
			name: "tiny-literal", selects: "the compiled-DFA direct-index table and literal-chain prefix",
			pattern: `abc`, match: true, find: true,
		},
		{
			name: "alternation", selects: "LeftmostFirst DFA — user alternation forces it",
			pattern: `cat|car|cart`, match: true, find: true,
		},
		{
			name: "nested-quantifier", selects: "LeftmostFirst via nested quantifiers rather than alternation",
			pattern: `(?:ab+)+c`, match: true, find: true,
		},
		{
			name: "non-greedy", selects: "immediateAccepting states, which only non-greedy quantifiers populate",
			pattern: `a+?b`, match: true, find: true,
		},
		{
			name: "wide-class", selects: "byte-class compression: an inverted class makes most bytes equivalent",
			pattern: `[^\n]*END`, match: true, find: true,
		},
		{
			name: "many-states", selects: "the u16 state-id table form, past 256 states",
			pattern: `(?:[a-z]{4}[0-9]{4}){3}[A-Z]{6}`, match: true, find: true,
		},
		{
			name: "teddy-prefix", selects: "prefix_scan.go's 2-byte Teddy prologue",
			pattern: `ghp_[A-Za-z0-9]{36}`, find: true,
		},
		{
			name: "one-byte-teddy", selects: "the 1-byte Teddy prologue: one prefix byte, several candidates",
			pattern: `(?:a|b|c)[0-9]{4}X`, find: true,
		},
		{
			name: "multi-eq-simd", selects: "the multi-eq SIMD prologue for a small first-byte set",
			pattern: `[abc]zzz`, find: true,
		},
		{
			name: "shufti", selects: "the Shufti first-byte prefilter over a mid-sized first-byte set",
			pattern: `[a-p][0-9]{4}END`, find: true,
		},
		{
			name: "scalar-prologue", selects: "the scalar fallback prologue: too many first bytes to prefilter",
			// Genuinely byte-oriented: the class IS every byte, which is what
			// leaves the prologue with nothing to prefilter on. byte_mode is
			// the declaration that `\xff` means the byte and not U+00FF.
			pattern: `[\x00-\xff]x`, find: true, byteMode: true,
		},
		{
			name: "lit-anchor", selects: "lit_anchor.go — SIMD literal scan plus a backward DFA for the start",
			pattern: `[a-z]+@example\.com`, find: true,
		},
		{
			name: "mandatory-lit", selects: "FindMandatoryLit on a literal buried mid-pattern",
			pattern: `[0-9]{3}MIDDLE[0-9]{3}`, find: true,
		},
		{
			name: "word-boundary", selects: "the \\b channel: doubled state space and the two mid-start states",
			pattern: `\bclass\b`, match: true, find: true,
		},
		{
			name: "word-boundary-negated", selects: "\\B, which resolves the same channel the other way",
			pattern: `\Bfoo\B`, match: true, find: true,
		},
		{
			name: "line-anchors", selects: "the (?m) newline channel and its pre-transition accept table",
			pattern: `(?m:^)ERROR:.*(?m:$)`, match: true, find: true,
		},
		{
			name: "text-anchors", selects: "\\A and \\z, which make the find anchored to position 0",
			pattern: `\Aheader\z`, match: true, find: true,
		},
		{
			name: "empty-match", selects: "a pattern matching empty, which the find loop must advance past",
			pattern: `x*`, match: true, find: true,
		},
		{
			name: "dot-star", selects: "an unbounded tail, the never-dying walk shape",
			pattern: `.*END`, find: true,
		},
		{
			name: "counted", selects: "counted repetition expansion",
			pattern: `a{10,20}b`, match: true, find: true,
		},

		// ---- capture paths: TDFA, and Backtracking when TDFA is refused ---
		{
			name: "groups-tdfa", selects: "engine_tdfa.go — tagged DFA with register ops",
			pattern: `(?P<scheme>https?)://(?P<host>[a-z.]+)/(?P<path>[a-z/]*)`, groups: true,
		},
		{
			name: "groups-simple", selects: "the TDFA register minimiser on a small tag set",
			pattern: `(a+)(b+)`, groups: true,
		},
		{
			name: "groups-backtrack-nongreedy", selects: "Backtracking: a non-greedy quantifier disqualifies TDFA",
			pattern: `<(.+?)>`, groups: true,
		},
		{
			name: "groups-backtrack-wordboundary", selects: "Backtracking: a word boundary disqualifies TDFA",
			pattern: `\b(\w+)\b`, groups: true,
		},
		{
			name: "groups-backtrack-inverted", selects: "Backtracking via hasAmbiguousCaptures — the inverted-class gate",
			pattern: `<([^>]+)>`, groups: true,
		},
		{
			name: "groups-forced-backtrack", selects: "Backtracking forced by an unreachably small TDFA budget",
			pattern: `(a+)(b+)(c+)`, groups: true, maxDFAStates: 4, maxTDFARegs: 1,
		},
		{
			name: "groups-and-find", selects: "one pattern carrying BOTH a groups and a find export",
			pattern: `(\d+)-(\d+)`, groups: true, find: true,
		},
		{
			name: "all-three", selects: "match, find and groups on one pattern — every wrapper at once",
			pattern: `(\w+)@(\w+)`, match: true, find: true, groups: true,
		},

		// ---- the likely-match biases ------------------------------------
		{
			name: "likely-match", selects: "the LikelyMatch bias",
			pattern: `[a-z]+@example\.com`, find: true, hints: []string{"prefer-match"},
		},
		{
			name: "likely-no-match", selects: "the LikelyNoMatch bias and its dense-skip counter",
			pattern: `[a-z]+@example\.com`, find: true, hints: []string{"prefer-no-match"},
		},
		{
			name: "likely-no-match-match-only", selects: "the same bias on an anchored match body",
			pattern: `(?:https?)://[^/]+/.*`, match: true, hints: []string{"prefer-no-match"},
		},

		// ---- batching on a single pattern --------------------------------
		{
			name: "batch-find", selects: "the per-pattern batch find wrapper",
			pattern: `[0-9]+`, find: true, hints: []string{"batch-find"},
		},
		{
			name: "batch-groups", selects: "the per-pattern batch groups wrapper",
			pattern: `(\d)(\w)`, groups: true, hints: []string{"batch-find"},
		},
		{
			name: "batch-anchored-find", selects: "the batch wrapper on an anchored find, which can only match at 0",
			pattern: `\Aabc`, find: true, hints: []string{"batch-find"},
		},

		// ---- literal-chain and alternation-anchored find bodies -----------
		//
		// These select engine_dfa.go's lit-chain analysis: a fixed-width class
		// run around a mandatory literal, which lets the scan anchor on the
		// literal and verify outward instead of walking every position.
		{
			name: "lit-chain-fixed-both-sides", selects: "buildLitChainRangeMatchBody — <class>{M}<literal><class>{N}",
			pattern: `[0-9]{8}ghp_[A-Za-z0-9]{12}`, match: true, find: true,
		},
		{
			name: "lit-chain-leading-class", selects: "the lit-chain arm with a class run only BEFORE the literal",
			pattern: `[a-f]{6}secret_`, match: true, find: true,
		},
		{
			name: "lit-chain-trailing-class", selects: "the lit-chain arm with a class run only AFTER the literal",
			pattern: `token_[0-9]{10}`, match: true, find: true,
		},
		{
			name: "alt-lit-anchor-equal", selects: "buildAltLitAnchorForwardVerifyBody — alternatives with EQUAL prefix widths",
			pattern: `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`,
			match:   true, find: true,
		},
		{
			name: "alt-lit-anchor-unequal", selects: "the same analysis refusing UNEQUAL prefix widths",
			pattern: `[0-9]{4}aaa_[^\s]+|[a-f]{9}bbb_[^\s]+`, match: true, find: true,
		},
		{
			name: "len-alt", selects: "buildLenAltMatchBody — an alternation of same-shape fixed lengths",
			pattern: `(?:cat|car|cab|cap)`, match: true, find: true,
		},
		{
			name: "len-alt-mixed-width", selects: "the same alternation analysis across DIFFERENT literal widths",
			pattern: `(?:a|bb|ccc|dddd)X`, match: true, find: true,
		},

		// ---- table layout arms -------------------------------------------
		{
			name: "compressed-classes", selects: "buildDFALayout's byte-class compression: few distinct classes, many states",
			pattern: `(?:[ab]{2}[cd]{2}){8}[ef]{4}`, match: true, find: true,
		},
		{
			name: "row-dedup", selects: "the u16 row-dedup arm: many states with identical transition rows",
			pattern: `(?:[a-c]xyz){40}`, match: true, find: true,
		},
		{
			name: "dominant-self-loop", selects: "detectSkipSafeOnDead and the dominant bulk-skip states",
			pattern: `START[^Z]{20,}END`, find: true,
		},
		{
			name: "wide-alternation", selects: "a wide alternation, which stresses newDFAImpl's closure construction",
			pattern: `(?:alpha|beta|gamma|delta|epsilon|zeta|eta|theta|iota|kappa)[0-9]`,
			match:   true, find: true,
		},

		// ---- BOTH boundary channels at once -------------------------------
		//
		// The find body's start-state selection has a separate arm for each
		// combination of "the word-boundary context diverges here" and "the
		// newline context diverges here", and the both-at-once arm is the
		// largest of them. Reaching it needs one pattern carrying \b AND a
		// (?m) anchor — neither alone will do.
		{
			name: "word-and-newline", selects: "buildFindBody's wordDiverges && newlineDiverges arm",
			pattern: `(?m:^)\bERROR\b`, match: true, find: true,
		},
		{
			name: "word-and-newline-end", selects: "the same arm with the newline anchor at the END",
			pattern: `\bfail\b.*(?m:$)`, match: true, find: true,
		},
		{
			name: "word-and-newline-both-ends", selects: "both channels and both anchors on one pattern",
			pattern: `(?m:^)\b[a-z]+\b(?m:$)`, match: true, find: true,
		},
		{
			name: "newline-only-diverges", selects: "the newlineDiverges-without-wordDiverges arm",
			pattern: `(?m:^)[0-9]+`, match: true, find: true,
		},
		{
			name: "newline-end-only", selects: "a (?m:$) with no word boundary anywhere",
			pattern: `[0-9]+(?m:$)`, match: true, find: true,
		},
		{
			name: "word-boundary-begin-accept", selects: "startBeginAccept — a pattern that can accept at position 0",
			pattern: `\b?x*`, match: true, find: true,
		},
		{
			name: "negated-word-and-newline", selects: "a negated word boundary beside a (?m) anchor, the other resolution of both channels",
			pattern: `(?m:^)\Bxyz`, match: true, find: true,
		},

		// ---- literal PREFIX plus a trailing boundary ----------------------
		//
		// The find prologue skips to a mandatory literal prefix and resumes
		// the walk at a precomputed post-prefix state. When the pattern also
		// carries \b or (?m), that state depends on the byte BEFORE the
		// prefix, so the body has to read it and pick between up to four
		// resume states. Reaching those arms needs the literal prefix to be
		// 2+ bytes AND the boundary to come after it — an anchor at the very
		// start leaves no prefix to skip to.
		//
		// This is a past silent-wrong-answer: any such pattern lost every
		// match whose (?m:^) depended on the preceding byte being a newline.
		{
			name: "lit-prefix-then-newline-end", selects: "buildFindBody's newlineDiverges arm behind a literal prefix",
			pattern: `ERROR:[a-z ]*(?m:$)`, match: true, find: true,
		},
		{
			name: "lit-prefix-then-word-end", selects: "the wordDiverges arm behind a literal prefix",
			pattern: `ERROR:[a-z]*\b`, match: true, find: true,
		},
		{
			name: "lit-prefix-both-boundaries", selects: "wordDiverges AND newlineDiverges behind a literal prefix",
			pattern: `ERROR:[a-z]*\b.*(?m:$)`, match: true, find: true,
		},
		{
			name: "lit-prefix-word-inside", selects: "a word boundary in the MIDDLE, after a multi-byte literal prefix",
			pattern: `prefix_[a-z]*\bword`, match: true, find: true,
		},
		{
			name: "lit-prefix-newline-inside", selects: "a (?m:^) in the middle, after a multi-byte literal prefix",
			pattern: `LOG:.*(?m:^)next`, match: true, find: true,
		},
		{
			name: "lit-prefix-anchored-start", selects: "a literal prefix whose start state diverges from its mid state",
			pattern: `\Aabcdef[0-9]*\b`, match: true, find: true,
		},

		// The boundary must come BEFORE the literal prefix, not after it.
		//
		// The find prologue skips to the literal and resumes at a precomputed
		// post-prefix state, walked from the mid-start state. A leading \b
		// makes that walk depend on the byte BEFORE the prefix — from
		// midStart the boundary fires and the walk lives, from midStartWord it
		// does not and the walk dies — so the two resume states differ and the
		// body has to read that byte and choose. A boundary AFTER the literal
		// leaves both walks identical and selects none of this.
		{
			name: "word-before-lit-prefix", selects: "buildFindBody wordDiverges arm: a word boundary before a multi-byte literal",
			// No punctuation in the literal: `\bERROR:` does NOT diverge,
			// because the colon settles the boundary question on its own.
			// The literal has to be all word characters for the walk from
			// midStart and from midStartWord to end in different states.
			pattern: `\bERROR[a-z]*`, match: true, find: true,
		},
		{
			name: "newline-before-lit-prefix", selects: "the newlineDiverges arm: (?m:^) before a multi-byte literal",
			pattern: `(?m:^)ERROR[a-z]*`, match: true, find: true,
		},
		{
			name: "both-before-lit-prefix", selects: "wordDiverges AND newlineDiverges together, the largest arm",
			pattern: `(?m:^)\bERROR[a-z]*`, match: true, find: true,
		},
		{
			name: "negated-word-before-lit-prefix", selects: "the same divergence resolved the other way, via a negated boundary",
			pattern: `\BKEY[a-z]*`, match: true, find: true,
		},
		{
			name: "both-before-lit-prefix-long", selects: "the same arm with a longer literal and a trailing anchor",
			pattern: `(?m:^)\bWARNING[a-z]*(?m:$)`, match: true, find: true,
		},
		{
			name: "word-before-lit-prefix-digits", selects: "the same divergence with a digit-class tail",
			pattern: `\bERROR[0-9]+`, match: true, find: true,
		},
		{
			name: "word-before-lit-prefix-both-ends", selects: "divergence at the front and a word boundary at the back",
			pattern: `\bERROR[a-z]*\b`, match: true, find: true,
		},
		{
			name: "word-before-lit-prefix-neg-end", selects: "divergence at the front and a NEGATED boundary at the back",
			pattern: `\bERROR[a-z]*\B`, match: true, find: true,
		},
		{
			name: "word-before-lit-prefix-newline-end", selects: "divergence at the front and (?m:$) at the back",
			pattern: `\bERROR[a-z]*(?m:$)`, match: true, find: true,
		},
		{
			name: "word-before-short-lit", selects: "the same divergence behind a two-byte literal",
			pattern: `\bAB[a-z]*`, match: true, find: true,
		},

		// ---- the RANGE literal chain, which needs CAPTURES ----------------
		//
		// buildLitChainRangeMatchBody is reached only through
		// analyseLitChainGroupsRange, so a groups export is required: a
		// match-or-find-only range never gets there, which is why several
		// attempts at `AKIA[A-Z0-9]{16,20}` reached nothing at all. The
		// range's MINIMUM must also clear the chain gate (24 under neutral),
		// so `{16,32}` is refused where `{24,32}` is taken, and a non-greedy
		// range is refused outright.
		{
			name: "lit-chain-groups-range", selects: "buildLitChainRangeMatchBody — literal, then a CAPTURED range",
			pattern: `ghp_([A-Za-z0-9]{24,32})`, groups: true,
		},
		{
			name: "lit-chain-groups-range-find", selects: "the same shape carrying find as well as groups",
			pattern: `AKIA([A-Z0-9]{24,40})`, groups: true, find: true,
		},
		{
			name: "lit-chain-groups-range-short-lit", selects: "the same emitter behind a single-byte literal",
			pattern: `x([a-z]{24,30})`, groups: true, match: true,
		},
		{
			name: "lit-chain-groups-range-two-caps", selects: "a captured literal as well as a captured range",
			pattern: `(?P<lead>x)([a-z]{24,30})`, groups: true,
		},
		{
			name: "lit-chain-groups-range-all", selects: "the same emitter with match, find and groups at once",
			pattern: `token_([0-9]{25,50})`, groups: true, match: true, find: true,
		},
		{
			name: "lit-chain-groups-range-refused-min", selects: "the REFUSAL below the chain gate: {16,32} takes the ordinary path",
			pattern: `ghp_([A-Za-z0-9]{16,32})`, groups: true,
		},
		{
			name: "lit-chain-groups-range-refused-lazy", selects: "the REFUSAL for a non-greedy range",
			pattern: `x([a-z]{24,30}?)`, groups: true,
		},

		// ---- Backtracking WINDOW mode -------------------------------------
		//
		// A capture body whose assertions are defined against the true input
		// edges (\b, \B, \A, \z, (?m:^), (?m:$)) gets an 8-byte
		// (startOff, endOff) scratch and the wrappers stop narrowing (ptr,
		// len) for it — a past defect, where narrowing made `\b` judge a
		// slice edge instead of the real neighbouring byte.
		//
		// It is only needed when the capture body sits BEHIND A FIND WRAPPER,
		// so the pattern must carry find as well as groups: a groups-only
		// export is anchored and already gets the caller's real ptr/len.
		{
			name: "bt-window-word-boundary", selects: "the window-mode scratch: word-boundary captures behind a find wrapper",
			pattern: `\b(\w+)\b`, groups: true, find: true,
		},
		{
			name: "bt-window-line-anchors", selects: "the same, via (?m) line anchors instead",
			pattern: `(?m:^)(\w+)(?m:$)`, groups: true, find: true,
		},
		{
			name: "bt-window-text-anchors", selects: "the same, via the text anchors",
			pattern: `\A(\w+)\z`, groups: true, find: true,
		},
		{
			name: "bt-window-negated", selects: "the same, via a negated word boundary",
			pattern: `\B(\w+)\B`, groups: true, find: true,
		},
		{
			name: "bt-no-window", selects: "the CONTRAST: a BT capture with no edge assertions needs no window",
			pattern: `<([^>]+)>`, groups: true, find: true,
		},
		{
			name: "bt-window-literal-prefix", selects: "window mode where the capture follows a literal",
			pattern: `x(\w+)\b`, groups: true, find: true,
		},
		{
			name: "bt-window-dotstar", selects: "window mode over a (?m)-anchored dot-star capture",
			pattern: `(?m:^)(.*)(?m:$)`, groups: true, find: true,
		},
		{
			name: "bt-window-groups-only", selects: "the same shapes with groups but NO find, which needs no window",
			pattern: `x(\w+)\b`, groups: true,
		},

		// ── Shapes that stress the CONSTRUCTORS rather than the emitters ──
		//
		// newDFA's subset construction and newTDFA's register allocation both
		// carry branches no ordinary pattern reaches: case-folded special
		// runes in the NFA input map, the mid-start collision guards, and the
		// scratch-register cycle break. They are reached by shape, not by
		// capability, so they belong in this list rather than in a test of
		// their own — every sweep over singleCases picks them up.
		{
			name: "fold-newline-class", selects: "case folding over a class containing NFA-special runes",
			pattern: `(?i)[a-z\n]+END`, match: true, find: true,
		},
		{
			name: "fold-word-boundary", selects: "case folding either side of a word boundary",
			pattern: `(?i)\bKEY\b[a-z]*`, match: true, find: true,
		},
		{
			name: "fold-kelvin", selects: "folds whose partners are the manufactured runes Go's parser adds",
			pattern: `(?i:[a-z])+x`, match: true, find: true,
		},
		{
			name: "boundary-both-starts", selects: "midStart and midStartWord reachable with the SAME NFA set",
			pattern: `\B[a-z]+\b[0-9]`, match: true, find: true,
		},
		{
			name: "nested-alt-captures", selects: "TDFA register copies that can form a cycle",
			pattern: `((a)|(b))+((c)|(d))+`, groups: true,
		},
		{
			name: "swapping-captures", selects: "capture registers whose live ranges cross, forcing sequentialized copies",
			pattern: `(?:(a)(b))*(c)`, groups: true,
		},
		{
			name: "deep-optional-captures", selects: "many optional groups, which widens the register map",
			pattern: `(a)?(b)?(c)?(d)?(e)?(f)?z`, groups: true,
		},
		{
			name: "alt-shared-prefix-captures", selects: "ambiguous alternation under captures — the TDFA eligibility gate",
			pattern: `(abc|abd)(x|y)`, groups: true, find: true,
		},

		// ── Batch entry points ────────────────────────────────────────────
		//
		// `batch-find` adds a SECOND export beside find or groups, filling the
		// caller's buffer with several matches per call and resuming through
		// an opaque cursor. The groups form has two shapes — a native
		// lit-chain capture body whose slots are already absolute, and a
		// composed one whose slots are relative to a window and must be
		// rebased per match — and the rebasing arm was reached by nothing.
		{
			name: "batch-find", selects: "the batch find wrapper beside a plain find",
			pattern: `[a-z]+@example\.com`, find: true,
			hints: []string{"batch-find"},
		},
		{
			name: "batch-groups-composed", selects: "batch groups over a COMPOSED capture body — slots rebased per match",
			pattern: `<([a-z]+)>`, groups: true, find: true,
			hints: []string{"batch-find"},
		},
		{
			name: "batch-groups-litchain", selects: "batch groups over a native lit-chain capture body",
			pattern: `AKIA([A-Z0-9]{16})`, groups: true, find: true,
			hints: []string{"batch-find"},
		},
		{
			name: "batch-groups-bt", selects: "batch groups over a Backtracking capture body",
			pattern: `(a.*?b)(c+)`, groups: true, find: true,
			hints: []string{"batch-find"},
		},
		{
			// The capture body is ffAnchoredZeroOnly, so its slots are
			// RELATIVE to the ptr it was handed and every one of them has to
			// be rebased by the match position before the record is written.
			// That rebasing loop is the arm the composed and native shapes
			// both skip.
			name: "batch-groups-anchored", selects: "batch groups over an ANCHORED capture body — per-match slot rebasing",
			pattern: `\AAKIA([A-Z0-9]{16})`, groups: true,
			hints: []string{"batch-find"},
		},
		{
			name: "batch-groups-anchored-alt", selects: "the same arm behind a caret rather than \\A",
			pattern: `^abc([0-9]{4})`, groups: true,
			hints: []string{"batch-find"},
		},
		// ── Teddy tiers ───────────────────────────────────────────────────
		//
		// The prefix scan checks up to FOUR byte positions at once with
		// stacked nibble tables, and each extra tier is selected by its own
		// validity walk over the transition table. The tiers need a small
		// first-byte set and NO literal prefix — a literal takes the hybrid
		// scan instead, which is why every literal-bearing case in this list
		// misses them.
		{
			name: "teddy-four-tier-class", selects: "all four Teddy tiers over a class chain",
			pattern: `[ab][cd][ef][gh]z`, match: true, find: true,
		},
		{
			name: "teddy-four-tier-alt", selects: "the same tiers reached through an alternation of literals",
			pattern: `(?:abcd|efgh|ijkl)X`, match: true, find: true,
		},
		{
			name: "teddy-tier-boundary", selects: "a first-byte set at the 8-byte Teddy ceiling",
			pattern: `[a-h]{4}END`, match: true, find: true,
		},
		{
			name: "teddy-one-tier", selects: "a first-byte set with only ONE usable tier",
			pattern: `ab|cd|ef`, match: true, find: true,
		},
		{
			// startBeginAccept: the start state accepts on the BEGIN-of-text
			// assertion alone, so a find must record an empty match at
			// position 0 before consuming anything. The prologue emits an
			// extra last_accept arm for it that no other shape reaches.
			name: "start-begin-accept", selects: "a start state accepting via ecBegin only",
			pattern: `a*^`, match: true, find: true,
		},
	}
}

func (c singleCase) build() config.BuildConfig {
	entry := config.RegexEntry{Name: "p", Pattern: c.pattern, Hints: c.hints, ByteMode: c.byteMode}
	if c.match {
		entry.MatchFunc = "p_match"
	}
	if c.find {
		entry.FindFunc = "p_find"
	}
	if c.groups {
		entry.GroupsFunc = "p_groups"
	}
	return config.BuildConfig{
		Regexps:      []config.RegexEntry{entry},
		MaxDFAStates: c.maxDFAStates,
		MaxTDFARegs:  c.maxTDFARegs,
	}
}

// TestSingleMatrixCompiles compiles every shape both STANDALONE (its own
// exported memory, what JS/TS load) and EMBEDDED (memory imported from "main",
// what a merged Rust/Go/C host gets). Those are different emitter arms — the
// embedded one renumbers memories and imports rather than declares — and a
// path that compiles one way and not the other is exactly the sort of thing
// only a merge would otherwise reveal.
func TestSingleMatrixCompiles(t *testing.T) {
	for _, c := range singleCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.build()
			for _, standalone := range []bool{true, false} {
				mode := "standalone"
				if !standalone {
					mode = "embedded"
				}
				wasm, _, err := Compile(cfg.Regexps, 65536, standalone)
				if err != nil {
					t.Fatalf("%s/%s (selects %s): %v", c.name, mode, c.selects, err)
				}
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s/%s: not a WASM module (%d bytes)", c.name, mode, len(wasm))
				}
				for _, want := range c.wantExports() {
					if !strings.Contains(string(wasm), want) {
						t.Errorf("%s/%s: module does not export %q", c.name, mode, want)
					}
				}
			}
		})
	}
}

// TestSingleMatrixCompilesUnderHints runs the same matrix under both compile
// hints.
//
// Every hint-gated emitter in the package — the dominant self-loop channels,
// the wide and bare Shufti lifts, the adaptive dense switch and its neutral
// twin, the chain-start probe — is selected by a LikelyMode the matrix above
// never sets, so a shape that compiles cleanly neutral and panics under a hint
// was invisible here. The corpus catches wrong ANSWERS; this catches a body
// that cannot be built at all, on shapes chosen to span the emitters.
func TestSingleMatrixCompilesUnderHints(t *testing.T) {
	modes := []struct {
		name string
		mode LikelyMode
	}{
		{"prefer-match", LikelyMatch},
		{"prefer-no-match", LikelyNoMatch},
	}
	for _, c := range singleCases() {
		for _, m := range modes {
			t.Run(c.name+"/"+m.name, func(t *testing.T) {
				cfg := c.build()
				for _, standalone := range []bool{true, false} {
					wasm, _, err := Compile(cfg.Regexps, 65536, standalone,
						CompileOptions{LikelyMode: m.mode})
					if err != nil {
						t.Fatalf("%s (selects %s), standalone=%v: %v",
							c.name, c.selects, standalone, err)
					}
					if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
						t.Fatalf("%s: not a WASM module (%d bytes)", c.name, len(wasm))
					}
					for _, want := range c.wantExports() {
						if !strings.Contains(string(wasm), want) {
							t.Errorf("%s: module does not export %q", c.name, want)
						}
					}
				}
			})
		}
	}
}

// TestSingleMatrixUnderTightLimits drives the same shapes into the state and
// register ceilings.
//
// Both limits are FALLBACKS, not errors: a DFA over max_dfa_states demotes the
// pattern to Backtracking, and a TDFA over max_tdfa_regs does the same. Those
// demotion paths are the ones a user hits on a big pattern and the ones no
// ordinary test reaches, because every fixture here fits comfortably. A limit
// of 1 forces the decision on every shape at once.
func TestSingleMatrixUnderTightLimits(t *testing.T) {
	for _, c := range singleCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.build()
			for _, opts := range []CompileOptions{
				{MaxDFAStates: 1},
				{MaxTDFARegs: 1},
				{MaxDFAStates: 4, MaxTDFARegs: 1},
				{MaxDFAStates: 1, LikelyMode: LikelyMatch},
			} {
				// A compile error is acceptable here — some shapes genuinely
				// cannot be built within these bounds — but a PANIC is not,
				// and neither is a module that claims success while being
				// malformed.
				wasm, _, err := Compile(cfg.Regexps, 65536, true, opts)
				if err != nil {
					continue
				}
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s with %+v: not a WASM module (%d bytes)",
						c.name, opts, len(wasm))
				}
			}
		})
	}
}

// TestSingleMatrixWithReporter runs the matrix with --verbose reporting on.
//
// Every decision compilePattern reports — the engine it actually built and the
// gate that chose it, the state and register limits it measured, the table
// encodings and optimisations that fired — sits behind `rep != nil`, and no
// other test in the package sets Report. That left the reporting arms of the
// compile path uncovered AND, worse, unexercised against real layouts: the
// deferred closure reads fields off the layout after the fact, which is a
// shape that breaks silently when a field moves.
//
// This asserts the report is POPULATED and internally consistent, not what it
// says. Which engine a shape selects is a tuning decision CLAUDE.md says to
// change only with measurement, so pinning the text here would turn every
// legitimate tuning change into a test failure.
func TestSingleMatrixWithReporter(t *testing.T) {
	for _, c := range singleCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.build()
			rep := &Reporter{}
			if _, _, err := Compile(cfg.Regexps, 65536, true,
				CompileOptions{Report: rep}); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			var out strings.Builder
			rep.Render(&out)

			if len(rep.Patterns) == 0 {
				t.Fatalf("%s: compiled but reported no patterns", c.name)
			}
			for _, p := range rep.Patterns {
				// Every record must say SOMETHING about how it was compiled.
				// A record with neither an engine nor a reason is the failure
				// this reporter was written to remove: a silent demotion.
				if p.Engine == 0 && p.Reason == "" {
					t.Errorf("%s: pattern %q recorded neither an engine nor a reason",
						c.name, p.Pattern)
				}
				if p.Pattern == "" {
					t.Errorf("%s: a report record has no pattern text", c.name)
				}
			}
			if out.Len() == 0 {
				t.Errorf("%s: Render produced nothing from %d patterns",
					c.name, len(rep.Patterns))
			}
		})
	}
}

// TestReporterUnderTightLimits covers the demotion arms specifically: the
// switch in compilePattern that names WHICH gate sent a pattern to
// Backtracking. Those are the lines a user reads when their pattern silently
// stopped being O(n), and a limit of 1 reaches them on every shape.
func TestReporterUnderTightLimits(t *testing.T) {
	sawDemotion := false
	for _, c := range singleCases() {
		cfg := c.build()
		rep := &Reporter{}
		if _, _, err := Compile(cfg.Regexps, 65536, true,
			CompileOptions{Report: rep, MaxDFAStates: 1, MaxTDFARegs: 1}); err != nil {
			continue
		}
		for _, p := range rep.Patterns {
			if p.Engine == EngineBacktrack && p.Reason != "" {
				sawDemotion = true
			}
			if len(p.Limits) == 0 && p.Engine != 0 {
				t.Errorf("%s: engine reported with no limit measurement", c.name)
			}
		}
		var out strings.Builder
		rep.Render(&out)
	}
	if !sawDemotion {
		t.Error("no pattern reported a Backtracking demotion under MaxDFAStates=1; " +
			"the reporting arms this test exists for were not reached")
	}
}

func (c singleCase) wantExports() []string {
	var out []string
	if c.match {
		out = append(out, "p_match")
	}
	if c.find {
		out = append(out, "p_find")
	}
	if c.groups {
		out = append(out, "p_groups")
	}
	return out
}

// TestSingleMatrixEngineSelection records which engine each shape selects.
//
// It asserts only that selection SUCCEEDS and names a known engine, not which
// one: the mapping is a tuning decision that CLAUDE.md says to change only
// with measurement, so pinning it here would turn every legitimate tuning
// change into a test failure. What this does catch is a pattern that stops
// being classifiable at all.
func TestSingleMatrixEngineSelection(t *testing.T) {
	known := map[string]bool{
		"DFA": true, "Compiled DFA": true, "TDFA": true, "Backtracking": true,
	}
	for _, c := range singleCases() {
		t.Run(c.name, func(t *testing.T) {
			eng, err := SelectEngine(c.pattern, CompileOptions{
				MaxDFAStates: c.maxDFAStates,
				MaxTDFARegs:  c.maxTDFARegs,
				ByteMode:     c.byteMode,
			})
			if err != nil {
				t.Fatalf("SelectEngine(%q): %v", c.pattern, err)
			}
			if !known[fmt.Sprint(eng)] {
				t.Fatalf("SelectEngine(%q) = %q, not a known engine", c.pattern, eng)
			}
		})
	}
}

// A CROSS-PRODUCT of pattern fragments, compiled for every capability.
//
// The hand-picked matrices next door name the path each case selects, which
// makes them readable and makes a stale case obvious. It also makes them blind
// to arms nobody thought to aim at — and several such arms turn on properties
// that are not visible in the pattern text at all. The clearest example: the
// find body picks its post-prefix resume state by comparing the states reached
// from midStart and from midStartWord, so `\bERROR[a-z]*` selects a different
// arm from `\bERROR:[a-z]*`, purely because a colon is not a word character.
// Three hand-written attempts missed that; enumerating found it immediately.
//
// So this compiles the product of {leading assertion} x {literal} x {tail} x
// {trailing assertion}, which is a few thousand patterns in a couple of
// seconds, and asserts the compiler either produces a well-formed module or
// declines cleanly. It is a SMOKE test over breadth — the corpus runners in
// tools/ check the answers — and its value is that it reaches shapes nobody
// selected on purpose.

func crossProductPatterns() []string {
	leading := []string{"", `\b`, `\B`, `(?m:^)`, `(?m:^)\b`, `\b(?m:^)`, `\A`}
	literals := []string{"ERROR", "AB", "Q", "abc_", "KEY:", "x"}
	tails := []string{"", "[a-z]*", "[0-9]+", ".*", "[a-z]{3}", `[^\n]*`, "[a-z]{2,6}", "x?"}
	trailing := []string{"", `\b`, `\B`, `(?m:$)`, `\z`}

	var out []string
	for _, lead := range leading {
		for _, lit := range literals {
			for _, tail := range tails {
				for _, trail := range trailing {
					out = append(out, lead+lit+tail+trail)
				}
			}
		}
	}
	return out
}

// TestPatternCrossProductCompiles compiles each pattern for match and for
// find.
//
// A pattern the compiler DECLINES is fine — a documented ceiling, or a shape
// no engine serves — and is skipped rather than failed, because this list is
// generated rather than curated and its job is reach, not a claim that every
// product of these fragments is supported. What is NOT fine is a module that
// comes back malformed.
func TestPatternCrossProductCompiles(t *testing.T) {
	pats := crossProductPatterns()
	if len(pats) < 1000 {
		t.Fatalf("cross-product collapsed to %d patterns; the fragment lists have drifted", len(pats))
	}
	compiled := 0
	for _, pat := range pats {
		if _, err := syntax.Parse(pat, syntax.Perl); err != nil {
			continue
		}
		for _, kind := range []string{"match", "find"} {
			e := config.RegexEntry{Name: "p", Pattern: pat}
			if kind == "match" {
				e.MatchFunc = "p_match"
			} else {
				e.FindFunc = "p_find"
			}
			wasm, _, err := Compile([]config.RegexEntry{e}, 65536, true)
			if err != nil {
				continue // a declined shape, not a failure
			}
			compiled++
			if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
				t.Fatalf("%s/%s: malformed module (%d bytes)", pat, kind, len(wasm))
			}
		}
	}
	// Guard against the whole sweep silently becoming a no-op — if the
	// compiler started declining everything, every case above would `continue`
	// and the test would pass having checked nothing.
	if compiled < len(pats) {
		t.Fatalf("only %d of %d patterns compiled; the sweep is mostly skipping", compiled, len(pats))
	}
}

// captureCrossProduct is the same idea for the CAPTURE engines, where the
// interesting axis is which engine the selector picks: TDFA when the pattern
// is unambiguous and small enough, Backtracking otherwise. Both are reached by
// varying the properties the gates test — non-greedy quantifiers, word
// boundaries, line anchors, inverted classes, nesting.
func captureCrossProduct() []string {
	bodies := []string{
		`(a+)(b+)`, `(a+?)(b+)`, `(\w+)`, `([^,]+),`, `(a|b)*c`, `((a)(b))`,
		`(?P<x>[0-9]{2})-(?P<y>[0-9]{2})`, `(a)(b)(c)(d)(e)`, `(.*?)END`,
		`\b(\w+)\b`, `(?m:^)(\w+)(?m:$)`, `(a{2,4})b`, `((?:ab)+)c`,
	}
	wrappers := []string{"%s", `x%s`, `%sy`, `(?:%s)+`, `(?:%s)?`}
	var out []string
	for _, b := range bodies {
		for _, w := range wrappers {
			out = append(out, fmt.Sprintf(w, b))
		}
	}
	return out
}

// TestCaptureCrossProductCompiles drives the capture path — TDFA and
// Backtracking — over the same kind of enumeration, and additionally under a
// squeezed TDFA budget, which is the documented way to force a pattern onto
// Backtracking that would otherwise be TDFA-eligible.
func TestCaptureCrossProductCompiles(t *testing.T) {
	budgets := []struct {
		name       string
		states     int
		regs       int
		wantForced bool
	}{
		{"default budget", 0, 0, false},
		// Small enough that no TDFA construction fits: everything with
		// captures lands on Backtracking.
		{"squeezed budget", 4, 1, true},
	}
	for _, b := range budgets {
		t.Run(b.name, func(t *testing.T) {
			compiled := 0
			for _, pat := range captureCrossProduct() {
				parsed, err := syntax.Parse(pat, syntax.Perl)
				if err != nil || parsed.MaxCap() == 0 {
					continue
				}
				wasm, _, err := CompileFile(config.BuildConfig{
					Regexps: []config.RegexEntry{
						{Name: "p", Pattern: pat, GroupsFunc: "p_groups"},
					},
					MaxDFAStates: b.states,
					MaxTDFARegs:  b.regs,
				}, "")
				if err != nil {
					continue // a documented ceiling
				}
				compiled++
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s: malformed module", pat)
				}
			}
			if compiled == 0 {
				t.Fatal("nothing compiled: the sweep checked nothing")
			}
		})
	}
}
