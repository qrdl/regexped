// likelytest is a focused benchmark harness that compares regexped's WASM output
// across the three LikelyMode compile modes (neutral, likely-match, likely-nomatch)
// for a hand-picked set of patterns where the LIKELY.md structural optimisations
// (SIMD counted-chain verify, SIMD dominant-self-loop skip) are expected to
// move the needle.
//
// For each test case it produces a per-pattern matrix:
//
//	mode             match-input        no-match-input
//	neutral          time / fuel        time / fuel
//	likely-match     time / fuel (Δ%)   time / fuel (Δ%)
//	likely-nomatch   time / fuel (Δ%)   time / fuel (Δ%)
//
// Δ% is the gain/loss vs the neutral row.
//
// Note: LikelyMode is a stub today — all three modes produce identical WASM. The
// columns will only diverge once the LIKELY.md optimisations land in compile/.
// Run via `make run` from this directory.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// --------------------------------------------------------------------------
// Memory layout (same scheme as perftest)

const (
	inputBase  = int32(0)
	slotsBase  = int32(65536) // page 1: keep clear of input (up to 64 KiB at offset 0)
	tableBase  = int64(131072) // page 2; pages 0-1 reserved for input + slots
	benchIters = 10_000
	fuelBudget = uint64(10_000_000_000)
)

// --------------------------------------------------------------------------
// Test cases

type matchMode int

const (
	modeFind matchMode = iota
	modeAnchored
	modeGroups
)

func (m matchMode) String() string {
	switch m {
	case modeAnchored:
		return "anchored"
	case modeGroups:
		return "groups"
	}
	return "find"
}

type testCase struct {
	name         string
	pattern      string
	mode         matchMode
	notes        string // one-line description of which optimisation it targets
	matchInput   string
	nomatchInput string
}

var tests = []testCase{
	{
		// Counted chain: AKIA + [A-Z0-9]{16}. 17-state linear chain — textbook Opt 2.
		// Expected once Opt 2 lands: likely-match faster on match-input; no effect on
		// no-match (Teddy frontend never fires there).
		name:         "secrets-aws",
		pattern:      `AKIA[A-Z0-9]{16}`,
		mode:         modeFind,
		notes:        "17-state counted chain after literal — Opt 2 target",
		matchInput:   configInput([]string{"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}),
		nomatchInput: configInput(nil),
	},
	{
		// Counted chain: ghp_ + [A-Za-z0-9]{36}. 37-state chain — Opt 2 target.
		name:         "secrets-github",
		pattern:      `ghp_[A-Za-z0-9]{36}`,
		mode:         modeFind,
		notes:        "37-state counted chain after literal — Opt 2 target",
		matchInput:   configInput([]string{"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Long synthetic counted chain — amplifies Opt 2's win as N grows.
		// 65-state chain after a 4-byte literal.
		name:         "long-counted-chain",
		pattern:      `KEYX[A-Z0-9]{64}`,
		mode:         modeFind,
		notes:        "65-state counted chain — Opt 2 amplification",
		matchInput:   configInput([]string{"KEYXABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWX1234"}),
		nomatchInput: configInput(nil),
	},
	{
		// Alternation of two counted chains. AC frontend buckets by literal prefix,
		// then each bucket dispatches to its own counted-chain verifier.
		name:         "secrets-combined",
		pattern:      `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`,
		mode:         modeFind,
		notes:        "alternation of two counted chains — Opt 2 via bucket dispatch",
		matchInput:   configInput([]string{"AKIAIOSFODNN7EXAMPLE", "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Word-boundary anchored lit-chain — canonical secret-detection idiom.
		// Tests start \b + end \b on the single-pattern find path.
		name:         "secrets-github-bounded",
		pattern:      `\bghp_[A-Za-z0-9]{36}\b`,
		mode:         modeFind,
		notes:        "ghp_ secret with \\b at both ends — anchor support target",
		matchInput:   configInput([]string{"see ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 here"}),
		nomatchInput: configInput([]string{"Xghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Y"}),
	},
	{
		// Strict alternation of two word-boundary anchored secrets. Exercises
		// the anchor checks in buildLitChainAltFindBody.
		name:    "secrets-combined-bounded",
		pattern: `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`,
		mode:    modeFind,
		notes:   "alternation of two \\b-bounded counted chains — strict-alt anchor target",
		matchInput: configInput([]string{
			"see AKIAIOSFODNN7EXAMPLE here",
			"and ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab next",
		}),
		nomatchInput: configInput([]string{
			"XAKIAIOSFODNN7EXAMPLEY",
			"Xghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Y",
		}),
	},
	{
		// Mixed-shape alternation: one branch is lit-chain shape (ghp_...{36}),
		// the other is NOT (has \s* between literal segments). Under strict
		// alternation detection (current behaviour) this falls through to the
		// DFA entirely — none of the 3 modes will diverge. Under lenient
		// alternation (Phase 2.5, not yet implemented) the ghp_ branch would
		// use lit-chain SIMD verify while the aws_secret_access_key branch
		// would fall back to a per-branch DFA verifier inside the bucket
		// dispatch. Test case here to document the gap.
		name:    "secrets-mixed-alt",
		pattern: `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[0-9a-zA-Z/+]{40}`,
		mode:    modeFind,
		notes:   "mixed alternation: lit-chain branch + non-lit-chain branch — needs lenient mode",
		matchInput: configInput([]string{
			"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Pure dominant self-loop after a literal prefix: [^\n]+ self-loops on
		// 255/256 byte classes — Opt 1 should bulk-skip those bytes via SIMD.
		// Match input has many comment lines; no-match has none.
		name:         "comment-line",
		pattern:      `//[^\n]+`,
		mode:         modeFind,
		notes:        "dominant-self-loop suffix [^\\n]+ — Opt 1 target",
		matchInput:   sourceInput(true),
		nomatchInput: sourceInput(false),
	},
	{
		// LNM amplifier: ~50 KB with a handful of very long comment lines.
		// Each `//` hit enters the [^\n]+ self-loop state and must scan
		// hundreds of bytes before the next \n. Bulk-skip should turn each
		// in-comment scan from per-byte DFA into 16-byte SIMD strides.
		name:         "comment-line-large",
		pattern:      `//[^\n]+`,
		mode:         modeFind,
		notes:        "long-line comments — Opt 1 bulk-skip amplifier",
		matchInput:   longCommentLineInput(true),
		nomatchInput: longCommentLineInput(false),
	},
	{
		// URL find: [^\s]+ self-loop after https?://. Slightly less dominant
		// than [^\n]+ but still ~250/256 transitions self-loop.
		name:         "url-suffix",
		pattern:      `https?://[^\s]+`,
		mode:         modeFind,
		notes:        "self-loop suffix [^\\s]+ after literal — Opt 1 target",
		matchInput:   proseInput([]string{"https://example.com/path/to/resource?x=1", "http://api.internal/v2/users/42"}),
		nomatchInput: proseInput(nil),
	},
	{
		// Mixed: comment-line OR block-comment. Both branches have self-loop
		// suffix states; block comment can be hundreds of bytes long. Stresses
		// both Opt 1 (self-loop bulk skip) and Teddy frontend.
		name:    "comments-mixed",
		pattern: `//[^\n]+|/\*(?s:.*?)\*/`,
		mode:    modeFind,
		notes:   "two dominant self-loop states — Opt 1 target (mixed)",
		matchInput: sourceWithBlockComments(true,
			"/*\n * Copyright 2026 Example Corp.\n * Licensed under the Apache License, Version 2.0.\n */",
			"/* TODO: replace with proper error handling once the new\n   error framework is merged into main branch */"),
		nomatchInput: sourceWithBlockComments(false),
	},
	{
		// Phase 3 amplifier: long-line comments AND multi-KB block comments
		// in the same input. The block-comment body sits in the second
		// dominant self-loop state (`.*?` until `*/`); Phase 2 only
		// accelerates the line-comment state, so this case demonstrates
		// the gap that Phase 3 (multi-state dispatch) closes.
		name:         "comments-mixed-large",
		pattern:      `//[^\n]+|/\*(?s:.*?)\*/`,
		mode:         modeFind,
		notes:        "long line + long block comments — Phase 3 multi-state amplifier",
		matchInput:   longCommentsMixedInput(true),
		nomatchInput: longCommentsMixedInput(false),
	},
	// ── First-byte selectivity sweep (LNM smarter-gate research) ────────
	// Five patterns sharing the shape `<lit><non-mid body><lit>` so the
	// DFA has a non-mid-accept dominant body state. The first byte of the
	// literal prefix varies from very-rare to very-common; the question
	// the smarter-gate research wants answered is "where on this spectrum
	// does the bulk-skip win exceed the per-iter dispatch cost on no-match
	// input?"
	{
		// Very rare: control character first byte. Never appears in ASCII
		// prose, so Teddy false-positives on no-match input are ~zero.
		// Bulk-skip should win on match, no regression possible on no-match.
		name:         "ctrl-delim",
		pattern:      `\x01[^\x02]+\x02`,
		mode:         modeFind,
		notes:        "very-rare first byte (\\x01) — Teddy false-positives ≈ 0",
		matchInput:   delimitedBodyInput(true, 0x01, 0x02, 5, 9000),
		nomatchInput: delimitedBodyInput(false, 0x01, 0x02, 0, 0),
	},
	{
		// Rare-ish: `<` is mid-rare in prose, common in HTML/XML. On prose
		// no-match input Teddy fires occasionally; on HTML it fires often.
		name:         "xml-tag",
		pattern:      `<[^>]+>`,
		mode:         modeFind,
		notes:        "rare first byte (<) — moderate Teddy false-positives on prose",
		matchInput:   delimitedBodyInput(true, '<', '>', 5, 9000),
		nomatchInput: delimitedBodyInput(false, '<', '>', 0, 0),
	},
	{
		// Mid-frequency: `[` appears occasionally in prose (citations,
		// brackets). Borderline case.
		name:         "bracket-content",
		pattern:      `\[[^\]]+\]`,
		mode:         modeFind,
		notes:        "mid-rare first byte ([) — borderline selectivity",
		matchInput:   delimitedBodyInput(true, '[', ']', 5, 9000),
		nomatchInput: delimitedBodyInput(false, '[', ']', 0, 0),
	},
	{
		// Common: `(` is moderately common in prose. Expect non-mid
		// dispatch to be lossy here.
		name:         "paren-block",
		pattern:      `\([^)]+\)`,
		mode:         modeFind,
		notes:        "common first byte (() — Teddy false-positives expected",
		matchInput:   delimitedBodyInput(true, '(', ')', 5, 9000),
		nomatchInput: delimitedBodyInput(false, '(', ')', 0, 0),
	},
	{
		// Very common: ASCII letter `a`. Fires Teddy on nearly every word.
		// Should be the worst-case regression if non-mid is emitted.
		name:         "letter-delim",
		pattern:      `a[^b]+b`,
		mode:         modeFind,
		notes:        "very-common first byte (a) — worst-case false-positive rate",
		matchInput:   delimitedBodyInput(true, 'a', 'b', 5, 9000),
		nomatchInput: delimitedBodyInput(false, 'a', 'b', 0, 0),
	},
	{
		// Capture variant of secrets-github: whole-match named group around the
		// lit-chain. Anchored captures (groups_func semantics). matchInput leads
		// with the secret so the anchored call succeeds once per outer iteration.
		// Gap A target: single-pattern, whole-match capture.
		name:         "secrets-github-grouped",
		pattern:      `(?P<key>ghp_[A-Za-z0-9]{36})`,
		mode:         modeGroups,
		notes:        "lit-chain with named whole-match capture — Gap A target",
		matchInput:   "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab" + configInput(nil),
		nomatchInput: configInput(nil),
	},
	{
		// Capture variant with multi-piece captures: literal and chain captured
		// separately. Exercises the multi-group write path on the lit-chain.
		// Gap A target: single-pattern, any captures.
		name:         "secrets-aws-pieces",
		pattern:      `(AKIA)([A-Z0-9]{16})`,
		mode:         modeGroups,
		notes:        "lit-chain with two captures (literal, chain) — Gap A target",
		matchInput:   "AKIAIOSFODNN7EXAMPLE" + configInput(nil),
		nomatchInput: configInput(nil),
	},
	{
		// Capture variant of secrets-combined: strict alternation of two
		// lit-chain branches, each wrapped in a named capture. Exercises the
		// per-branch group layout with unmatched groups set to (-1, -1).
		// Gap A target: strict alternation with captures.
		name:         "secrets-combined-grouped",
		pattern:      `(?P<aws>AKIA[A-Z0-9]{16})|(?P<ghp>ghp_[A-Za-z0-9]{36})`,
		mode:         modeGroups,
		notes:        "strict-alt of two captured lit-chains — Gap A target",
		matchInput:   "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab" + configInput(nil),
		nomatchInput: configInput(nil),
	},
	{
		// Strict-alt of \b-bounded lit-chains, each carrying a named capture.
		// Currently rejected by analyseLitChainAltGroups (anchor check) — falls
		// through to TDFA. Gap A.2: extend alt-groups emitter to handle per-
		// branch anchors. matchInput leads with the ghp_ secret followed by a
		// newline so the trailing \b on that branch matches.
		name:    "secrets-combined-bounded-grouped",
		pattern: `\b(?P<aws>AKIA[A-Z0-9]{16})\b|\b(?P<ghp>ghp_[A-Za-z0-9]{36})\b`,
		mode:    modeGroups,
		notes:   "strict-alt with per-branch \\b anchors + captures — Gap A.2 target",
		matchInput: "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab\n" +
			configInput(nil),
		nomatchInput: configInput(nil),
	},
	{
		// Same pattern shape as secrets-github-grouped, but with the secret
		// buried mid-buffer instead of at offset 0. Anchored groups_func
		// returns -1 immediately today (no scan). Gap A.3 adds find-with-
		// captures so the function locates the buried secret itself. Baseline
		// numbers here will be artificially fast on both inputs (anchored
		// short-circuit) — the post-A.3 numbers reflect real scan work.
		name:    "secrets-github-grouped-buried",
		pattern: `(?P<key>ghp_[A-Za-z0-9]{36})`,
		mode:    modeGroups,
		notes:   "buried secret needs find-with-captures — Gap A.3 target",
		matchInput: configInput([]string{
			"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Mixed-shape alt with captures on BOTH branches: one lit-chain branch
		// (ghp_) plus one DFA branch (aws_secret_access_key = ...). Currently
		// rejected by both analyseLitChainAltGroups (mixed shapes) and lenient-
		// alt (no capture support). Falls through to TDFA. Gap A.4 adds lit-
		// chain SIMD slot writes for the lit-chain branch and an inline tagged-
		// DFA trace for the DFA branch. matchInput starts with the DFA-branch
		// shape to exercise the harder path.
		name:    "secrets-mixed-alt-grouped",
		pattern: `(?P<ghp>ghp_[A-Za-z0-9]{36})|aws_secret_access_key\s*=\s*(?P<aws>[0-9a-zA-Z/+]{40})`,
		mode:    modeGroups,
		notes:   "lenient-alt (lit-chain + DFA branches) with captures — Gap A.4 target",
		matchInput: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12" +
			configInput(nil),
		nomatchInput: configInput(nil),
	},
	{
		// Same mixed-shape alt as above, but with the secret buried mid-buffer
		// instead of at offset 0. Today the TDFA wrapper scans the full ~10 KB
		// buffer to locate the match. Gap A.4 should replace that scan with the
		// lenient-alt Teddy frontend (much faster) while still producing correct
		// captures.
		name:    "secrets-mixed-alt-grouped-buried",
		pattern: `(?P<ghp>ghp_[A-Za-z0-9]{36})|aws_secret_access_key\s*=\s*(?P<aws>[0-9a-zA-Z/+]{40})`,
		mode:    modeGroups,
		notes:   "lenient-alt buried secret needs Teddy scan + captures — Gap A.4 target",
		matchInput: configInput([]string{
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Anchored full-input match on a strict lit-chain alternation. Today
		// match_func on `lit1|lit2` falls through to DFA. Gap B should give us
		// per-branch SIMD verify at pos 0 + strict len == K+N check.
		name:         "secrets-combined-anchored",
		pattern:      `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`,
		mode:         modeAnchored,
		notes:        "anchored match on strict-alt — Gap B target",
		matchInput:   "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		nomatchInput: "this_is_not_a_secret_value_at_all_42_chr",
	},
	{
		// Same as above but with per-branch \b anchors. At pos 0 the leading
		// \b is satisfied (text-start is non-word, literal[0] is word); at pos
		// K+N the trailing \b is satisfied (last char is word, text-end is
		// non-word). Gap B should handle per-branch anchors in the alt path.
		name:         "secrets-combined-bounded-anchored",
		pattern:      `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`,
		mode:         modeAnchored,
		notes:        "anchored match on strict-alt with \\b anchors — Gap B target",
		matchInput:   "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		nomatchInput: "this_is_not_a_secret_value_at_all_42_chr",
	},
	{
		// Lenient-alt anchored match: one lit-chain branch (ghp_) plus one
		// DFA-shape branch (aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}).
		// Today match_func falls through to DFA. Gap B lenient should give
		// lit-chain SIMD verify for the lit-chain branch + inline anchored
		// DFA for the DFA branch, checking last_accept == len for full
		// input consumption.
		name:         "secrets-mixed-alt-anchored",
		pattern:      `ghp_[A-Za-z0-9]{36}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}`,
		mode:         modeAnchored,
		notes:        "anchored match on lenient-alt — Gap B lenient target",
		matchInput:   "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		nomatchInput: "this_is_not_a_secret_value_at_all_42_chr",
	},
	{
		// Gap C: range-counted chain `{N,M}` with N < M. Greedy find — should
		// match the longest valid chain (up to M bytes) when literal hits.
		// Today: falls through to DFA. After C: SIMD verify up to M bytes,
		// rightmost-zero in bad-mask gives match length.
		name:         "range-find-greedy",
		pattern:      `secret_[A-Za-z0-9]{24,40}`,
		mode:         modeFind,
		notes:        "range-counted chain {24,40} — Gap C greedy find",
		matchInput:   configInput([]string{"secret_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap C non-greedy: returns shortest valid chain (exactly N bytes
		// after literal). Same pattern as above but with `?`.
		name:         "range-find-nongreedy",
		pattern:      `secret_[A-Za-z0-9]{24,40}?`,
		mode:         modeFind,
		notes:        "range-counted chain {24,40}? — Gap C non-greedy find",
		matchInput:   configInput([]string{"secret_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap C anchored: input length must be in [K+N, K+M] AND class match.
		// matchInput is 39 bytes (K=7 + 32 chars in class) — in range.
		name:         "range-anchored",
		pattern:      `secret_[A-Za-z0-9]{24,40}`,
		mode:         modeAnchored,
		notes:        "range-counted chain {24,40} — Gap C anchored",
		matchInput:   "secret_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
		nomatchInput: "not_a_secret_value_at_all_x_y_z_a_b_c__",
	},
	{
		// Gap C groups: range-counted chain with capture. Group 1's end
		// position depends on runtime match length, not a compile-time
		// offset.
		name:         "range-groups",
		pattern:      `(?P<key>secret_[A-Za-z0-9]{24,40})`,
		mode:         modeGroups,
		notes:        "range-counted chain with capture — Gap C groups",
		matchInput:   configInput([]string{"secret_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap C strict-alt with range counts on each branch.
		name:         "range-strict-alt-find",
		pattern:      `secret_[A-Za-z0-9]{24,40}|token_[a-z0-9]{24,32}`,
		mode:         modeFind,
		notes:        "strict-alt of range-counted chains — Gap C strict-alt find",
		matchInput:   configInput([]string{"secret_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap E: mixed prefix shape `<class>{M}<literal><class>{N}`. Today
		// detection requires literal at position 0 — patterns like this fall
		// through to DFA. After Gap E: scan for literal, back up M bytes,
		// verify class-prefix, verify class-suffix.
		name:    "gap-e-find",
		pattern: `[0-9]{8}ghp_[A-Za-z0-9]{36}`,
		mode:    modeFind,
		notes:   "class prefix + literal + class suffix — Gap E target",
		matchInput: configInput([]string{
			"12345678ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap E anchored: input length must equal M+K+N exactly. matchInput
		// is exactly 48 bytes (8+4+36).
		name:         "gap-e-anchored",
		pattern:      `[0-9]{8}ghp_[A-Za-z0-9]{36}`,
		mode:         modeAnchored,
		notes:        "anchored mixed-prefix shape — Gap E anchored target",
		matchInput:   "12345678ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		nomatchInput: "12345678not_a_secret_at_all_value_or_anything_x",
	},
	{
		// Gap E groups: captures wrap class-prefix and class-suffix pieces.
		// Group offsets must account for the prefix (group d at 0..8, group
		// k at 12..48 after the K=4 ghp_ literal).
		name:    "gap-e-groups",
		pattern: `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
		mode:    modeGroups,
		notes:   "mixed-prefix shape with captures — Gap E groups target",
		matchInput: configInput([]string{
			"12345678ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// Gap E strict-alt: alternation of two mixed-prefix branches. Both
		// branches have a class prefix + literal + class suffix. Different
		// literals and different prefix classes.
		name:    "gap-e-strict-alt-find",
		pattern: `[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`,
		mode:    modeFind,
		notes:   "strict-alt of mixed-prefix shapes — Gap E strict-alt target",
		matchInput: configInput([]string{
			"12345678ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		}),
		nomatchInput: configInput(nil),
	},
}

// --------------------------------------------------------------------------
// Input generators

// configInput returns ~10KB of env-config-style text. Secrets are spread
// evenly through the file if provided; otherwise the output contains none.
func configInput(secrets []string) string {
	const block = `# Application Configuration
export APP_ENV=production
export DATABASE_URL=postgres://appuser:secure_password@db.example.com:5432/appdb
export REDIS_URL=redis://cache.example.com:6379/0
export EMAIL_HOST=smtp.example.com
export EMAIL_FROM=noreply@example.com
export ENABLE_METRICS=true
export METRICS_ENDPOINT=http://metrics.example.com:9090/metrics
export LOG_LEVEL=error
export LOG_FORMAT=json
export API_BASE_URL=https://api.example.com/v2
export API_TIMEOUT=30000
export MAX_CONNECTIONS=100
export SESSION_SECRET=change_me_in_production
export GITHUB_ORG=example-org
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=example-data-bucket
`
	base := strings.Repeat(block, (10*1024)/len(block))
	return spread(base, secrets, "\n")
}

// sourceInput returns ~10KB of C-style source code, with optional `// comment` lines.
func sourceInput(withComments bool) string {
	const block = `int processRequest(Request *req, Response *resp) {
    if (req == NULL || resp == NULL) return ERR_INVALID_ARG;
    int status = validateHeaders(req->headers, req->headerCount);
    if (status != OK) { resp->statusCode = 400; return status; }
    Connection *conn = poolAcquire(globalPool, POOL_TIMEOUT_MS);
    if (conn == NULL) { resp->statusCode = 503; return ERR_NO_CONNECTION; }
    QueryResult result = executeQuery(conn, req->path, req->params);
    poolRelease(globalPool, conn);
    resp->statusCode = 200;
    resp->body = result.data;
    return OK;
}

`
	base := strings.Repeat(block, (10*1024)/len(block))
	if !withComments {
		return base
	}
	comments := []string{
		"// initialise connection pool",
		"// retry with exponential backoff",
		"// validate request parameters",
		"// guard against null pointer access",
		"// release pooled connection back to the manager",
	}
	return spread(base, comments, "\n")
}

// longCommentLineInput returns ~50 KB of source-like text. When withComments
// is true, the buffer contains a handful of VERY long single-line `// …`
// comments (~5–10 KB each, no embedded newlines) — designed to amplify
// the [^\n]+ bulk-skip path. When false, no `//` substring appears.
func longCommentLineInput(withComments bool) string {
	const targetSize = 50 * 1024
	if !withComments {
		// Plain text without "//" anywhere.
		var b []byte
		filler := []byte("The quick brown fox jumps over the lazy dog. ")
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	// Five very-long comment lines, each ~9 KB of non-newline characters.
	var b []byte
	for i := 0; i < 5; i++ {
		b = append(b, '/', '/')
		filler := []byte(" lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua")
		for j := 0; j < 75; j++ { // ~9 KB per comment
			b = append(b, filler...)
		}
		b = append(b, '\n')
	}
	// Pad with non-`//` filler to reach target.
	filler := []byte("plain text with no slashes at all and certainly nothing resembling a comment marker here\n")
	for len(b) < targetSize {
		b = append(b, filler...)
	}
	return string(b[:targetSize])
}

// longCommentsMixedInput returns ~50 KB of source-like text containing BOTH
// very long single-line `//` comments AND multi-KB `/* … */` block comments.
// Phase 2 of Opt 1 bulk-skips the line-comment self-loop only; Phase 3 must
// also bulk-skip the block-comment self-loop. When withMatches is false,
// neither `//` nor `/*` appears.
func longCommentsMixedInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		var b []byte
		filler := []byte("The quick brown fox jumps over the lazy dog. ")
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	// Two ~9 KB single-line comments.
	for i := 0; i < 2; i++ {
		b = append(b, '/', '/')
		filler := []byte(" lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua")
		for j := 0; j < 75; j++ {
			b = append(b, filler...)
		}
		b = append(b, '\n')
	}
	// Two ~9 KB block comments (newlines inside are fine — `.*?` is DOTALL).
	for i := 0; i < 2; i++ {
		b = append(b, '/', '*')
		filler := []byte(" Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam,\n feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper.\n")
		for j := 0; j < 45; j++ {
			b = append(b, filler...)
		}
		b = append(b, '*', '/', '\n')
	}
	// Pad with non-comment filler.
	filler := []byte("plain text with no slashes at all and certainly nothing resembling a comment marker here\n")
	for len(b) < targetSize {
		b = append(b, filler...)
	}
	return string(b[:targetSize])
}

// delimitedBodyInput builds an input for the first-byte selectivity sweep.
//
// When withMatches is true, the buffer contains `bodies` × (`bodyLen` bytes)
// matches shaped `<open>[non-close-byte body]<close>`. The body byte fills
// repeatedly using a "lorem ipsum"-style filler with the close byte
// stripped out, so the match length actually reaches `bodyLen`. Total
// buffer is padded with plain ASCII prose to ~50 KB.
//
// When withMatches is false, the buffer is pure ASCII prose (lorem ipsum
// + the quick-brown-fox sentence) with the `open` byte stripped out so
// no Teddy false-positives from the literal can occur EXCEPT when `open`
// is a natural ASCII letter (in which case stripping it would change the
// prose; for those we accept the natural occurrence rate as the test
// signal). Total buffer ~50 KB.
//
// This produces:
//   - matchInput: bulk-skip-friendly. Each match has a long body where
//     the dominant self-loop fires repeatedly.
//   - nomatchInput: stresses Teddy at the natural frequency of `open` in
//     prose. Whether non-mid bulk-skip helps or hurts here is exactly
//     the question the smarter gate must answer.
func delimitedBodyInput(withMatches bool, open, close byte, bodies, bodyLen int) string {
	const targetSize = 50 * 1024
	filler := []byte(" lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua quisque vel libero")
	stripBytes := func(s []byte, drop byte) []byte {
		out := s[:0:len(s)]
		for _, c := range s {
			if c != drop {
				out = append(out, c)
			}
		}
		return out
	}
	bodyFiller := stripBytes(append([]byte(nil), filler...), close)
	if !withMatches {
		var b []byte
		prose := stripBytes(append([]byte(nil), filler...), open)
		// Also strip the close byte so a stray pair can't form unintended matches.
		prose = stripBytes(prose, close)
		// If both bytes happen to be ASCII letters that gut the prose, fall
		// back to a different sentence.
		if len(prose) < 20 {
			prose = []byte("The quick brown fox jumps over the lazy dog. ")
			prose = stripBytes(prose, open)
			prose = stripBytes(prose, close)
		}
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	for i := 0; i < bodies; i++ {
		b = append(b, open)
		for len(b)%bodyLen != bodyLen-1 && len(b) < targetSize-2 {
			// Inner loop bound is approximate; we just want roughly bodyLen
			// bytes of body before the close.
			b = append(b, bodyFiller...)
			if len(b) >= bodyLen*(i+1) {
				break
			}
		}
		b = append(b, close)
		b = append(b, '\n')
	}
	// Pad with prose (stripped of `open` so we don't accidentally start new
	// matches mid-pad).
	pad := stripBytes(append([]byte(nil), filler...), open)
	pad = stripBytes(pad, close)
	if len(pad) < 20 {
		pad = []byte("plain padding text without delimiters here at all\n")
		pad = stripBytes(pad, open)
		pad = stripBytes(pad, close)
	}
	for len(b) < targetSize {
		b = append(b, pad...)
	}
	return string(b[:targetSize])
}

// sourceWithBlockComments returns ~10KB of C-style source code with optional
// `// comments` and optional `/* block comments */`.
func sourceWithBlockComments(withMatches bool, blockComments ...string) string {
	const block = `int processRequest(Request *req, Response *resp) {
    if (req == NULL || resp == NULL) return ERR_INVALID_ARG;
    int status = validateHeaders(req->headers, req->headerCount);
    if (status != OK) { resp->statusCode = 400; return status; }
    Connection *conn = poolAcquire(globalPool, POOL_TIMEOUT_MS);
    if (conn == NULL) { resp->statusCode = 503; return ERR_NO_CONNECTION; }
    QueryResult result = executeQuery(conn, req->path, req->params);
    poolRelease(globalPool, conn);
    resp->statusCode = 200;
    return OK;
}

`
	base := strings.Repeat(block, (10*1024)/len(block))
	if !withMatches {
		return base
	}
	all := []string{
		"// initialise connection pool",
		"// retry with exponential backoff",
		"// validate request parameters",
	}
	all = append(all, blockComments...)
	return spread(base, all, "\n")
}

// proseInput returns ~10KB of natural-language prose, optionally interleaved with URLs.
func proseInput(urls []string) string {
	const block = `The application encountered an error while processing the request from the
client. The server returned status code four hundred and three, indicating that
the user does not have permission to access the requested resource. Please
contact your system administrator if you believe this is a mistake. The event
has been logged for review by the security team. Timestamp of the failure was
recorded along with the originating address and the affected service name.
`
	base := strings.Repeat(block, (10*1024)/len(block))
	if len(urls) == 0 {
		return base
	}
	wrapped := make([]string, len(urls))
	for i, u := range urls {
		wrapped[i] = "See " + u + " for details."
	}
	return spread(base, wrapped, "\n")
}

// spread inserts `items` evenly through `base`, separated by `sep`.
func spread(base string, items []string, sep string) string {
	if len(items) == 0 {
		return base
	}
	result := []byte(base)
	step := len(result) / (len(items) + 1)
	offset := 0
	for i, it := range items {
		pos := (i+1)*step + offset
		if pos > len(result) {
			pos = len(result)
		}
		line := []byte(it + sep)
		result = append(result[:pos], append(line, result[pos:]...)...)
		offset += len(line)
	}
	return string(result)
}

// --------------------------------------------------------------------------
// Bench shim WASM modules (reuse perftest's shim builders)

var (
	matchBenchShim  = buildMatchBenchShim()
	findBenchShim   = buildFindBenchShim()
	groupsBenchShim = buildGroupsBenchShim()
)

// --------------------------------------------------------------------------
// Per-cell measurement

type cell struct {
	// p50 over the shim's 10k inner timing samples — already statistically tight.
	timeP50 time.Duration
	fuel    uint64
	size    int
}

// compileMode compiles tc.pattern under the given LikelyMode and returns the WASM bytes.
func compileMode(tc testCase, mode compile.LikelyMode) ([]byte, error) {
	re := config.RegexEntry{Pattern: tc.pattern}
	switch tc.mode {
	case modeAnchored:
		re.MatchFunc = "match"
	case modeFind:
		re.FindFunc = "find"
	case modeGroups:
		re.GroupsFunc = "groups"
	}
	opts := compile.CompileOptions{LikelyMode: mode}
	wasm, _, err := compile.Compile([]config.RegexEntry{re}, tableBase, true, opts)
	return wasm, err
}

// benchTime times benchIters calls via the WASM shim and returns the p50 of
// those 10k internal samples — already statistically tight.
func benchTime(wasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine) (time.Duration, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return 0, fmt.Errorf("module: %w", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetWasi(wasmtime.NewWasiConfig())
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, fmt.Errorf("instance: %w", err)
	}
	var fnExport string
	switch tc.mode {
	case modeAnchored:
		fnExport = "match"
	case modeFind:
		fnExport = "find"
	case modeGroups:
		fnExport = "groups"
	}
	mem := inst.GetExport(store, "memory").Memory()
	rpdFn := inst.GetFunc(store, fnExport)
	if rpdFn == nil || mem == nil {
		return 0, fmt.Errorf("missing exports")
	}

	var shimBytes []byte
	switch tc.mode {
	case modeAnchored:
		shimBytes = matchBenchShim
	case modeFind:
		shimBytes = findBenchShim
	case modeGroups:
		shimBytes = groupsBenchShim
	}
	shimMod, err := wasmtime.NewModule(engine, shimBytes)
	if err != nil {
		return 0, fmt.Errorf("shim module: %w", err)
	}
	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return 0, fmt.Errorf("linker wasi: %w", err)
	}
	if err := linker.Define(store, "regexped", fnExport, rpdFn); err != nil {
		return 0, fmt.Errorf("linker define: %w", err)
	}
	shimInst, err := linker.Instantiate(store, shimMod)
	if err != nil {
		return 0, fmt.Errorf("shim instantiate: %w", err)
	}
	shimMem := shimInst.GetExport(store, "memory").Memory()
	benchFn := shimInst.GetFunc(store, "bench")

	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	// 50 ms warmup.
	warmupEnd := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(warmupEnd) {
		if tc.mode == modeGroups {
			benchFn.Call(store, inputBase, inputLen, slotsBase, int32(benchIters)) //nolint:errcheck
		} else {
			benchFn.Call(store, inputBase, inputLen, int32(benchIters)) //nolint:errcheck
		}
	}

	var benchErr error
	if tc.mode == modeGroups {
		_, benchErr = benchFn.Call(store, inputBase, inputLen, slotsBase, int32(benchIters))
	} else {
		_, benchErr = benchFn.Call(store, inputBase, inputLen, int32(benchIters))
	}
	if benchErr != nil {
		return 0, fmt.Errorf("bench call: %w", benchErr)
	}
	shimBuf := shimMem.UnsafeData(store)
	return computeStat(shimBuf[:timingsBytes], 50), nil
}

// benchFuel measures fuel for a single call.
func benchFuel(wasmBytes []byte, tc testCase, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
	mod, err := wasmtime.NewModule(fuelEngine, wasmBytes)
	if err != nil {
		return 0, err
	}
	store := wasmtime.NewStore(fuelEngine)
	if err := store.SetFuel(fuelBudget); err != nil {
		return 0, err
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return 0, err
	}
	var fnExport string
	switch tc.mode {
	case modeAnchored:
		fnExport = "match"
	case modeFind:
		fnExport = "find"
	case modeGroups:
		fnExport = "groups"
	}
	mem := inst.GetExport(store, "memory").Memory()
	fn := inst.GetFunc(store, fnExport)
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	before, _ := store.GetFuel()
	var callErr error
	if tc.mode == modeGroups {
		_, callErr = fn.Call(store, inputBase, inputLen, slotsBase)
	} else {
		_, callErr = fn.Call(store, inputBase, inputLen)
	}
	if callErr != nil {
		return 0, callErr
	}
	after, _ := store.GetFuel()
	return before - after, nil
}

// measure compiles + runs (tc, mode, input) and returns one cell.
func measure(tc testCase, mode compile.LikelyMode, input string, engine, fuelEngine *wasmtime.Engine) (cell, error) {
	wasm, err := compileMode(tc, mode)
	if err != nil {
		return cell{}, fmt.Errorf("compile %s: %w", mode, err)
	}
	t, err := benchTime(wasm, tc, input, engine)
	if err != nil {
		return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
	}
	f, err := benchFuel(wasm, tc, input, fuelEngine)
	if err != nil {
		return cell{}, fmt.Errorf("bench fuel %s: %w", mode, err)
	}
	return cell{timeP50: t, fuel: f, size: len(wasm)}, nil
}

// --------------------------------------------------------------------------
// Formatting

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "n/a"
	}
	if d >= time.Millisecond {
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	}
	if d >= time.Microsecond {
		return fmt.Sprintf("%.1f µs", float64(d)/float64(time.Microsecond))
	}
	return fmt.Sprintf("%d ns", d.Nanoseconds())
}

func fmtFuel(n uint64) string {
	s := fmt.Sprintf("%d", n)
	var b []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// gain returns "  —" for the baseline row, or a signed percentage like "-23%"/"+8%".
// Negative = faster/cheaper than neutral; positive = slower/more expensive.
func gain(cur, base float64) string {
	if base == 0 {
		return "   —"
	}
	pct := (cur - base) / base * 100
	if pct > -0.5 && pct < 0.5 {
		return "  0%"
	}
	return fmt.Sprintf("%+4.0f%%", pct)
}


// printMatrix prints the 3x{2 inputs × 2 metrics} table for one pattern.
// rows: neutral, likely-match, likely-nomatch.
func printMatrix(tc testCase, rows [3]cell, rowsNo [3]cell) {
	fmt.Printf("\n=== %s  [%s, %q] ===\n", tc.name, tc.mode, tc.pattern)
	fmt.Printf("  %s\n", tc.notes)
	fmt.Printf("  match input: %d bytes, no-match input: %d bytes\n", len(tc.matchInput), len(tc.nomatchInput))
	fmt.Printf("  wasm size:  neutral=%d B  likely-match=%d B  likely-nomatch=%d B\n",
		rows[0].size, rows[1].size, rows[2].size)

	modes := [3]string{"neutral", "likely-match", "likely-nomatch"}
	header := fmt.Sprintf("  %-16s  %18s %5s  %14s %5s   %18s %5s  %14s %5s",
		"mode",
		"time(match)", "Δ%", "fuel(match)", "Δ%",
		"time(no-m)", "Δ%", "fuel(no-m)", "Δ%")
	fmt.Println(header)
	fmt.Println("  " + strings.Repeat("─", len(header)-2))

	baseT, baseF := float64(rows[0].timeP50), float64(rows[0].fuel)
	baseTn, baseFn := float64(rowsNo[0].timeP50), float64(rowsNo[0].fuel)

	for i := 0; i < 3; i++ {
		rT, rF := float64(rows[i].timeP50), float64(rows[i].fuel)
		nT, nF := float64(rowsNo[i].timeP50), float64(rowsNo[i].fuel)
		gT, gF := "   —", "   —"
		gTn, gFn := "   —", "   —"
		if i > 0 {
			gT, gF = gain(rT, baseT), gain(rF, baseF)
			gTn, gFn = gain(nT, baseTn), gain(nF, baseFn)
		}
		fmt.Printf("  %-16s  %12s %5s  %14s %5s   %12s %5s  %14s %5s\n",
			modes[i],
			fmtDur(rows[i].timeP50), gT,
			fmtFuel(rows[i].fuel), gF,
			fmtDur(rowsNo[i].timeP50), gTn,
			fmtFuel(rowsNo[i].fuel), gFn,
		)
	}
}

// --------------------------------------------------------------------------
// Warmup (matches perftest's behaviour)

var minimalWASM = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

func warmup(engine *wasmtime.Engine) {
	mod, err := wasmtime.NewModule(engine, minimalWASM)
	if err != nil {
		return
	}
	store := wasmtime.NewStore(engine)
	_, _ = wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
}

// --------------------------------------------------------------------------
// Main

func main() {
	// Silence regexped's slog output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	engine := wasmtime.NewEngine()
	warmup(engine)

	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := wasmtime.NewEngineWithConfig(fuelCfg)

	modes := [3]compile.LikelyMode{compile.LikelyNeutral, compile.LikelyMatch, compile.LikelyNoMatch}

	fmt.Println("likelytest — LikelyMode 3x3 matrix (p50 over 10k inner iterations per cell)")

	for _, tc := range tests {
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)
		var rowsMatch, rowsNoMatch [3]cell
		for i, m := range modes {
			c, err := measure(tc, m, tc.matchInput, engine, fuelEngine)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  measure %s match: %v\n", m, err)
				continue
			}
			rowsMatch[i] = c
			c, err = measure(tc, m, tc.nomatchInput, engine, fuelEngine)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  measure %s no-match: %v\n", m, err)
				continue
			}
			rowsNoMatch[i] = c
		}
		printMatrix(tc, rowsMatch, rowsNoMatch)
	}
	fmt.Println()
}
