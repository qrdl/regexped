package compile

import (
	"bytes"
	"os"
	"path/filepath"
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
		{
			"lenient_alt_find_only",
			[]config.RegexEntry{{
				Pattern:  `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}`,
				FindFunc: "lenient_alt_find_only",
			}},
		},

		// ---------- Lit-chain prefixed (Gap E) ----------
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
				Pattern:         `(?P<key>ghp_[A-Za-z0-9]{36})`,
				NamedGroupsFunc: "ghp_named_groups",
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
				Pattern:         `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
				NamedGroupsFunc: "prefixed_named_groups",
			}},
		},
		{
			"capture_strict_alt_named_only",
			[]config.RegexEntry{{
				Pattern:         `(?P<aws>AKIA[A-Z0-9]{16})|(?P<gh>ghp_[A-Za-z0-9]{36})`,
				NamedGroupsFunc: "strict_alt_named_only",
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
				Pattern:         `(?P<key>secret_[A-Za-z0-9]{24,40})`,
				NamedGroupsFunc: "secret_range_named",
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
				Pattern:         `(?P<key>ghp_[A-Za-z0-9]{36})`,
				FindFunc:        "ghp_find_cap",
				NamedGroupsFunc: "ghp_named_groups_cap",
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
				Pattern:         `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
				FindFunc:        "prefixed_find_cap",
				NamedGroupsFunc: "prefixed_named_groups_cap",
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
				Pattern:         `(?P<gh>ghp_[A-Za-z0-9]{36})|(?P<aws>aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40})`,
				FindFunc:        "lenient_alt_find_named_cap",
				GroupsFunc:      "lenient_alt_groups_named_cap",
				NamedGroupsFunc: "lenient_alt_named_groups_cap",
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
// to force the table-driven (non-compiled) DFA path with emitImmAcceptCheckMatch.
func TestCompileLargeStateDFA(t *testing.T) {
	// Disable the CompiledDFA optimisation so the DFA goes through the pure
	// table-driven path (which calls emitImmAcceptCheckMatch).
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
			"unicode_pattern",
			[]config.RegexEntry{{
				Pattern:  `[\p{L}]+`,
				FindFunc: "unicode_find",
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
		if _, ok := analyseLitChainAltLenient(`[`); ok {
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

	t.Run("too_small_count_lm1", func(t *testing.T) {
		// LM-1: under LikelyMatch, callers pass minCount=1 — N=4 now
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
		if _, ok := analyseLitChainAltLenient(`ghp_[A-Za-z0-9]{36}`); ok {
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

// TestCompileLikelyNoMatch exercises the LNM Action 5 / lnmAction5 flag path
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

// TestLM2BatchExportGating exercises the LM-2 batch find/groups export gate
// (plans/LM_TODO.md LM-2): the "_batch" export must appear exactly when
// LikelyMode == LikelyMatch and the pattern's own find_func/groups_func was
// requested, and must NOT appear for anchored (native lit-chain) groups
// bodies — that shape is out of v1 scope (see the compiledPattern field doc
// next to batchGroupsExport).
// TestBatchExportGating covers the "batch-find" hint (plans/TODO.md task 44)
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
	// (AKIA[A-Z0-9]{24}) is a lit-chain groups shape (Gap C, count>=24 so
	// analyseLitChainGroups accepts it — capture-path analysers are not
	// LM-1-relaxed, unlike the plain match/find analysers) — anchored:
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
		Pattern:         `(a)(b)?`,
		NamedGroupsFunc: "named_ab",
		Hints:           []string{"batch-find"},
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
			t.Error("expected akia_groups_batch export for anchored (Path B) lit-chain groups body — task 44 goal 4")
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
	t.Run("named_only_batch_export_named_after_namedGroupsFunc", func(t *testing.T) {
		wasm, _, err := Compile(namedOnlyEntries, 0, true)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !bytes.Contains(wasm, []byte("named_ab_batch")) {
			t.Error("expected named_ab_batch export (GroupsExportName falls back to NamedGroupsFunc), not found")
		}
	})
	t.Run("groups_and_named_share_one_batch_export", func(t *testing.T) {
		both := []config.RegexEntry{{
			Pattern:         `(a)(b)?`,
			GroupsFunc:      "g1",
			NamedGroupsFunc: "g2",
			Hints:           []string{"batch-find"},
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
		// Regression guard for the LM-2 "anyBatch" bug this task's doc calls
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
