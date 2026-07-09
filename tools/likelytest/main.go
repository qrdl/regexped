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
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
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
	modeSet // CompileFile with cfg.Sets; driven via find_all exhaustion loop
)

func (m matchMode) String() string {
	switch m {
	case modeAnchored:
		return "anchored"
	case modeGroups:
		return "groups"
	case modeSet:
		return "set"
	}
	return "find"
}

type testCase struct {
	name         string
	pattern      string   // unset when mode == modeSet
	setPatterns  []string // only set when mode == modeSet; passed as separate RegexEntry per pattern
	mode         matchMode
	notes        string // one-line description of which optimisation it targets
	matchInput   string
	nomatchInput string
}

var tests = []testCase{
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
	// ── Shufti prefix-scan targets (LNM Action 3) ───────────────────────
	// Patterns with no usable literal anchor (no mandatoryLit) and a
	// first-byte set of varying size. Today these fall to multi-eq SIMD
	// (set size 5..16) or the scalar firstByteFlags loop (set > 16).
	// Shufti should accelerate the prefix scan in both cases.
	{
		// 52-byte first-set (letters) — currently scalar firstByteFlags
		// (1 byte/cycle). Shufti should be ~16 bytes/cycle.
		name:         "alpha-run",
		pattern:      `[a-zA-Z]{20,}`,
		mode:         modeFind,
		notes:        "52-byte first-set (letters) — scalar → Shufti target",
		matchInput:   classRunInput(true, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 20, 5),
		nomatchInput: classRunInput(false, "", 0, 0),
	},
	{
		// 63-byte first-set (word chars + underscore). Same shape as
		// alpha-run but slightly broader; scalar today.
		name:         "word-run",
		pattern:      `[a-zA-Z0-9_]{20,}`,
		mode:         modeFind,
		notes:        "63-byte first-set (word chars) — scalar → Shufti target",
		matchInput:   classRunInput(true, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", 20, 5),
		nomatchInput: classRunInput(false, "", 0, 0),
	},
	// ── First-byte selectivity sweep (LNM smarter-gate research) ────────
	// Five patterns sharing the shape `<lit><non-mid body><lit>` so the
	// DFA has a non-mid-accept dominant body state. The first byte of the
	// literal prefix varies from very-rare to very-common; the question
	// the smarter-gate research wants answered is "where on this spectrum
	// does the bulk-skip win exceed the per-iter dispatch cost on no-match
	// input?"
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
	{
		// Task 6 v1 target: same pattern shape as gap-e-strict-alt-find
		// (both branches share the {8} fixed prefix length), but this case
		// exists to demonstrate the NEUTRAL/LikelyNoMatch path specifically
		// — findAltLitAnchorPoints' alt-lit-anchor mechanism fires for every
		// LikelyMode unconditionally (no flag required), unlike Gap E which
		// stays LikelyMatch-only. The LikelyMatch column here should be
		// unchanged (still hitting Gap E, since Gap E's own check runs
		// first and returns early on success) — only neutral/LikelyNoMatch
		// should show the win.
		name:    "alt-lit-anchor-neutral",
		pattern: `[0-9]{8}ghp_[A-Za-z0-9]{36}|[a-f]{8}secret_[A-Za-z0-9]{36}`,
		mode:    modeFind,
		notes:   "per-branch lit-anchor alternation, equal 8-char prefixes — Task 6 v1 (neutral/LNM path; see gap-e-strict-alt-find for the LikelyMatch analogue)",
		matchInput: configInput([]string{
			"12345678ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		}),
		nomatchInput: configInput(nil),
	},
	{
		// LNM Action 5 amplifier: pattern accepts only [a-zA-Z] (52-byte
		// set, routed to scalar by Action 3 density heuristic). Input is
		// dominated by digits/punctuation/whitespace — bytes that no
		// state can consume ("impossible bytes"). Scalar firstByteFlags
		// pays 1 byte/cycle through long impossible runs; Action 5's
		// SIMD impossible-byte skip should cut that to ~16 bytes/cycle.
		name:         "alpha-run-impossible-bytes",
		pattern:      `[a-zA-Z]{8,}`,
		mode:         modeFind,
		notes:        "52-byte first-set in mostly-impossible-byte input — LNM Action 5 target",
		matchInput:   impossibleRunInput(true),
		nomatchInput: impossibleRunInput(false),
	},
	{
		// Suggestion 3 target (RESOLVED — see plans/TODO.md task 23,
		// retracted 2026-07-08): lit-anchored find with a dominant
		// self-loop body. Lit-anchor (`findLitAnchorPoint`) requires a 2+
		// byte literal CHILD with a non-empty prefix whose reverse DFA's
		// start state is non-accepting. Counted-chain `{4}` qualifies;
		// unbounded `+` does not (reverse accepts empty). Pattern shape:
		//   prefix `[0-9]{4}` (non-empty, fixed-length) + literal `INFO:`
		//   (5 bytes) + body `[^\n]+` (mid-accept dominant self-loop).
		// buildLitAnchorFindBody already dispatches dominant bulk-skip
		// inside its forward DFA (unconditionally, all LikelyMode values) —
		// that's why the match-side columns below are flat across modes,
		// not because the optimisation is missing. The genuinely open gap
		// on this pattern is the no-match side: verifying the `[0-9]{4}`
		// prefix after an `INFO:` literal hit still walks backward one byte
		// at a time with no SIMD (plans/TODO.md task 22).
		name:         "lit-anchor-dominant-body",
		pattern:      `[0-9]{4}INFO:[^\n]+`,
		mode:         modeFind,
		notes:        "lit-anchor + mid-accept dominant body — task 22 (backward prefix-scan) target",
		matchInput:   litAnchorDominantBodyInput(true),
		nomatchInput: litAnchorDominantBodyInput(false),
	},
	{
		// Task 22 target: a bounded-but-larger class-count prefix
		// (`{16}`, a trace-ID-style sequence number) before the same
		// `INFO:` literal + dominant-body suffix shape. A SHORT bounded
		// count like lit-anchor-dominant-body's `{4}` doesn't actually
		// stress buildLitAnchorBackScanBody's scalar reverse walk — its
		// reverse DFA dies after at most 5 steps regardless of how much
		// digit-class text precedes it, so there's no scaling cost to
		// show. `{16}` plus a no-match input with 15-digit near-misses
		// (one short of the required 16) forces the walk through its
		// full length on every failed candidate before dying.
		name:         "lit-anchor-false-positive-literal",
		pattern:      `[0-9]{16}INFO:[^\n]+`,
		mode:         modeFind,
		notes:        "lit-anchor backward prefix-scan, 15-digit near-miss false-positives — task 22 target",
		matchInput:   litAnchorLongPrefixMatchInput(),
		nomatchInput: litAnchorFalsePositiveInput(),
	},
	{
		// Gap G target: BT find body with a 17..64-byte first-byte set on
		// impossible-byte-heavy input. Pattern requirements to exercise
		// the right BT path:
		//   - non-greedy capture → ambiguous, TDFA-ineligible → BT
		//   - no mandatory literal substring → BT uses the
		//     nfaFirstBytes/Teddy/Shufti fallback (where Action 5 lives),
		//     not the mlScan literal-prefix path
		//   - 17..64-byte first-byte set → Action 5 has something to act on
		// `([a-zA-Z]+?)\d` satisfies all three: `\d` exit is a class
		// (no literal), capture is non-greedy, first-byte set is 52.
		//
		// Match input: digit/punct/space filler with embedded letter runs
		// each followed by a digit (so the BT body completes a match).
		// No-match input: pure impossible bytes (no letters at all) —
		// prefix scan loop runs the whole input, never enters BT body.
		name:         "bt-action5-target",
		pattern:      `([a-zA-Z]+?)\d`,
		mode:         modeGroups,
		notes:        "BT find + 17..64-byte first-byte set — Gap G (LNM Action 5 for BT) target",
		matchInput:   btAction5Input(true),
		nomatchInput: btAction5Input(false),
	},
	{
		// Task 17 target: non-mid-accept dominant body in a set. `<[^>]+>`'s
		// suffix DFA has one dominant self-loop state (on non-'>') that is
		// NOT itself an accept point — you need the closing '>' before any
		// match completes, unlike set-log-line-bodies' `[^\n]+` (mid-accept,
		// already unconditional per Gap H.2's mid path). This is the
		// LikelyMatch-gated remainder: buildSetSuffixBody's non-mid dispatch
		// only fires when at least one pattern in the bucket resolves to
		// LikelyMatch.
		name:         "set-nonmid-dominant-tags",
		setPatterns:  []string{`<[^>]+>`},
		mode:         modeSet,
		notes:        "set with non-mid-accept dominant body — task 17 (Gap H.2 non-mid remainder) target",
		matchInput:   setNonMidDominantInput(true),
		nomatchInput: setNonMidDominantInput(false),
	},
	{
		// Task 8 target: pattern with greedy class quantifier followed by a
		// required suffix that doesn't appear anywhere. From every starting
		// position the DFA self-loops through the same letter run and dies
		// at the same delimiter — O(N²) work without dead-state skip.
		//
		// Pattern is non-capture-bearing → plain DFA find body (or hybrid
		// CompiledDFA which delegates to buildFindBody). Skip-safe by the
		// disjoint-byte-class check: midStart accepts [a-zA-Z]; dead
		// triggers happen on bytes that aren't letters or digits.
		name:         "deadskip-near-miss",
		pattern:      `[a-zA-Z]+\d`,
		mode:         modeFind,
		notes:        "near-miss greedy quantifier — Task 8 (dead-state skip) target",
		matchInput:   deadSkipNearMissInput(true),
		nomatchInput: deadSkipNearMissInput(false),
	},
	{
		// Task 8 follow-up #2 target: min-length quantifier skip. Pattern
		// requires >=50 lowercase letters followed by a digit. Suffix is a
		// character CLASS, not a literal, so no mandatory-literal frontend
		// applies (confirmed by probe: fuel scales linearly for an
		// equivalent literal-suffix pattern like `x{500}y`, but quadratically
		// here) — the find loop falls through to the naive per-position DFA
		// retry path.
		//
		// No-match input is 2000 lowercase letters with no digit anywhere:
		// the DFA never dies (stays in-class the whole way) and never runs
		// short of input (Task 8's dead-state skip and follow-up #1's
		// EOF-without-match check both stay silent), so every attempt from
		// position k scans forward to EOF before failing — the pattern is
		// entirely captured by neither prior fix. Confirmed via direct fuel
		// probe (bypassing likelytest's benchIters wall-clock loop): fuel
		// quadruples with each doubling of N (500→4.1M, 1000→16.5M,
		// 2000→66M, 4000→264M fuel) — textbook O(N²). With the fix,
		// attempt_start should jump by (scanned - minBodyLen + 1) on each
		// EOF-without-match failure instead of by 1, collapsing this to
		// O(N).
		//
		// Match input has a real digit early (1500 letters + digit + 500
		// filler letters) — found on the very first attempt already, so
		// this is a same-cost regression guard rather than a perf target;
		// the important thing is the fix must not disturb it.
		name:         "minlen-quantifier-skip",
		pattern:      `[a-z]{50,}[0-9]`,
		mode:         modeFind,
		notes:        "no mandatory literal, never dies, never runs short — Task 8 follow-up #2 target",
		matchInput:   minLenQuantifierSkipInput(true),
		nomatchInput: minLenQuantifierSkipInput(false),
	},
	{
		// H.3 target: 21 literal-prefixed patterns with distinct uppercase
		// first bytes [A..U]. AC builds ~63 nodes which exceeds the 32-node
		// cap → frontend falls back to scalar. With H.3, set-level
		// LikelyNoMatch forces Shufti (rarity sum = 42 > 40 threshold, so
		// the density heuristic alone would keep scalar — LNM is the
		// trigger here). Under neutral/LM the set stays on scalar.
		//
		// No-match input is pure lowercase prose — Shufti never finds a
		// candidate, SIMD-skips the entire 50 KB in 16-byte chunks. Match
		// input has letter density too high for SIMD to help much.
		name: "set-shufti-lnm",
		setPatterns: []string{
			`A1:[^\n]+`, `B1:[^\n]+`, `C1:[^\n]+`, `D1:[^\n]+`, `E1:[^\n]+`,
			`F1:[^\n]+`, `G1:[^\n]+`, `H1:[^\n]+`, `I1:[^\n]+`, `J1:[^\n]+`,
			`K1:[^\n]+`, `L1:[^\n]+`, `M1:[^\n]+`, `N1:[^\n]+`, `O1:[^\n]+`,
			`P1:[^\n]+`, `Q1:[^\n]+`, `R1:[^\n]+`, `S1:[^\n]+`, `T1:[^\n]+`,
			`U1:[^\n]+`,
		},
		mode:         modeSet,
		notes:        "set with 21 [A-U]-prefixed literals — H.3 (LNM forces Shufti over scalar)",
		matchInput:   setShuftiLNMInput(true),
		nomatchInput: setShuftiLNMInput(false),
	},
	{
		// Gap F target: (\w+) TDFA capture body is a single state that
		// self-loops on 63 of 256 bytes with a uniform set-to-pos tag op.
		// matchInput anchors a 10 KB run of \w bytes so the SIMD bulk-skip
		// dominates the scan; nomatchInput starts with a non-word byte so
		// the anchored capture fails immediately at pos 0.
		name:         "tdfa-bulk-skip-word-class",
		pattern:      `(\w+)`,
		mode:         modeGroups,
		notes:        "TDFA dominant self-loop on \\w (63 bytes) — Gap F target",
		matchInput:   strings.Repeat("aB3_", 2560) + "!",
		nomatchInput: "!" + strings.Repeat("aB3_", 2560),
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

// classRunInput builds ~50 KB of input for the Shufti prefix-scan sweep.
//
// When withMatches is true, the buffer contains `runs` × (`runLen`
// consecutive chars from `class`) embedded in prose so the pattern
// `[class]{runLen,}` matches. When false, pure prose (no run of `runLen`
// consecutive class chars).
//
// The no-match input intentionally contains plenty of letters/digits
// that ARE in many classes (so Teddy/firstByte filters fire often) but
// without the run length needed to complete a match. That stresses the
// prefix-scan throughput end of the engine: scan-rate dominates, DFA
// verification trips early.
func classRunInput(withMatches bool, class string, runLen, runs int) string {
	const targetSize = 50 * 1024
	prose := []byte("The quick brown fox jumps over the lazy dog. ")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	classBytes := []byte(class)
	for i := 0; i < runs; i++ {
		// Embed a leading word boundary (space) so the run is clearly
		// delimited.
		b = append(b, ' ')
		for j := 0; j < runLen; j++ {
			b = append(b, classBytes[j%len(classBytes)])
		}
		b = append(b, ' ')
	}
	for len(b) < targetSize {
		b = append(b, prose...)
	}
	return string(b[:targetSize])
}

// btAction5Input builds a ~50 KB input for `([a-zA-Z]+?)\d`. The
// pattern compiles to Backtracking (non-greedy quantifier inside a
// capture = TDFA-ineligible). The first-byte set is `[a-zA-Z]` (52
// bytes), placing it in the 17..64-byte band where Action 5
// (force-Shufti) helps.
//
// When withMatches is true: 5 letter runs immediately followed by a
// digit, embedded in punct/space filler (digits stripped from filler
// so the embedded run is the only digit per neighbourhood — keeps the
// BT body cost predictable).
// When false: pure non-letter filler (digits/punct/space), no letters
// → prefix scan loop runs the entire input without entering the BT
// body.
func btAction5Input(withMatches bool) string {
	const targetSize = 50 * 1024
	// Filler contains no letters. Includes digits, punctuation, whitespace.
	filler := []byte("0123456789.,;:!?@#$%^&*()-+=[]{}|\\/<> \t01234567")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	chunkSize := targetSize / 6
	// Letters-then-digit shape so the pattern `([a-zA-Z]+?)\d` matches.
	run := []byte("alpha7")
	for i := 0; i < 5; i++ {
		for len(b) < (i+1)*chunkSize {
			b = append(b, filler...)
		}
		b = append(b, ' ')
		b = append(b, run...)
		b = append(b, ' ')
	}
	for len(b) < targetSize {
		b = append(b, filler...)
	}
	return string(b[:targetSize])
}

// litAnchorDominantBodyInput builds a ~50 KB input for `[0-9]{4}INFO:[^\n]+`.
// Goes through the lit-anchor find path: Teddy scans for `INFO:`, reverse
// DFA verifies preceding digits, forward DFA scans the long body.
//
// When withMatches is true: 2 long matches embedded:
//   `0001INFO:` + ~24 KB non-newline body + `\n` + filler +
//   `0002INFO:` + ~24 KB non-newline body + `\n`.
// When false: pure prose with no `INFO:` substring (no Teddy hits).
func litAnchorDominantBodyInput(withMatches bool) string {
	const targetSize = 50 * 1024
	prose := []byte("The quick brown fox jumps over the lazy dog. ")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	bodyFiller := []byte("abcdefghijklmpqrstuvwxyz0123456789 ,.;:-_/=+*<>()[]{}|")
	for i := 0; i < 2; i++ {
		b = append(b, '0', '0', '0', '0'+byte(i+1)) // 4 digits, matches [0-9]{4}
		b = append(b, []byte("INFO:")...)
		bodyStart := len(b)
		for len(b)-bodyStart < 24*1024 {
			b = append(b, bodyFiller...)
		}
		b = append(b, '\n')
	}
	for len(b) < targetSize {
		b = append(b, prose...)
	}
	return string(b[:targetSize])
}

// litAnchorLongPrefixMatchInput builds ~50 KB of match input for
// `[0-9]{16}INFO:[^\n]+` (task 22): 2 long matches, each with a full
// 16-digit prefix immediately before "INFO:".
func litAnchorLongPrefixMatchInput() string {
	const targetSize = 50 * 1024
	prose := []byte("The quick brown fox jumps over the lazy dog. ")
	bodyFiller := []byte("abcdefghijklmpqrstuvwxyz0123456789 ,.;:-_/=+*<>()[]{}|")
	var b []byte
	for i := 0; i < 2; i++ {
		b = append(b, []byte(fmt.Sprintf("%016d", i+1))...) // 16 digits, matches [0-9]{16}
		b = append(b, []byte("INFO:")...)
		bodyStart := len(b)
		for len(b)-bodyStart < 24*1024 {
			b = append(b, bodyFiller...)
		}
		b = append(b, '\n')
	}
	for len(b) < targetSize {
		b = append(b, prose...)
	}
	return string(b[:targetSize])
}

// litAnchorFalsePositiveInput builds ~50 KB of no-match input for
// `[0-9]{16}INFO:[^\n]+` (task 22). Scatters "INFO:" occurrences through
// digit-free filler, each preceded by exactly 15 consecutive digits — one
// short of the 16 required, so [0-9]{16}INFO: never actually matches, but
// buildLitAnchorBackScanBody's scalar reverse walk must still consume all 15
// digit bytes before hitting the non-digit filler and dying. Filler is
// digit-free so an inserted 15-digit run can never accidentally extend to
// length >= 16 at a concatenation boundary (which would flip it to a real
// match — same class of bug as an over-long run always containing a valid
// trailing window).
func litAnchorFalsePositiveInput() string {
	const targetSize = 50 * 1024
	filler := []byte("the quick brown fox jumps over the lazy dog and other filler words go here forever ")
	nearMissPrefix := []byte("123456789012345") // 15 digits, one short of 16
	var b []byte
	for len(b) < targetSize {
		b = append(b, filler...)
		b = append(b, nearMissPrefix...)
		b = append(b, []byte("INFO:")...)
	}
	return string(b[:targetSize])
}

// setNonMidDominantInput builds ~50 KB of mixed text for the task 17 set
// test case (`<[^>]+>`).
// When withMatches is true: many small HTML-ish tags interleaved with
// prose, so the dominant non-mid-accept body (self-loop on non-'>') has
// bytes to bulk-skip across many separate tags.
// When false: prose with no '<' at all, so the DFA never enters the
// dominant state — used to confirm the no-match path's cost (a real,
// small, expected regression per Task 7 step 2 precedent) is measured
// accurately, not accidentally masked by matches.
func setNonMidDominantInput(withMatches bool) string {
	const targetSize = 50 * 1024
	prose := "the quick brown fox jumps over the lazy dog. "
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	for len(b) < targetSize {
		b = append(b, prose...)
		b = append(b, `<div class="container-fluid-wrapper">`...)
	}
	return string(b[:targetSize])
}

// deadSkipNearMissInput builds ~10 KB of letter runs separated by spaces.
// Pattern `[a-zA-Z]+\d` is the find target.
//
// When withMatches is true: same letter-run layout but with a single digit
// at the end of the LAST block — find returns the (start,end) of that
// match. Without dead-state skip the path-to-match still does O(N²) work
// for every preceding block; with skip, each block is touched once.
// When false: pure letter runs + spaces, no digits anywhere. Find returns
// -1 (no match). Without skip: O(N²) per block scanning. With skip:
// each block scanned once then jumped past the delimiter.
func deadSkipNearMissInput(withMatches bool) string {
	const blockLen = 100
	const numBlocks = 100
	letters := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var b []byte
	for blk := 0; blk < numBlocks; blk++ {
		for i := 0; i < blockLen; i++ {
			b = append(b, letters[(blk*blockLen+i)%len(letters)])
		}
		if withMatches && blk == numBlocks-1 {
			b = append(b, '7') // single digit at the end of the last block
		}
		b = append(b, ' ')
	}
	return string(b)
}


// minLenQuantifierSkipInput builds inputs for the Task 8 follow-up #2
// target (pattern `[a-z]{50,}[0-9]`, no-match input never dies and never
// runs short of input — see likelytest case "minlen-quantifier-skip").
func minLenQuantifierSkipInput(withMatches bool) string {
	if withMatches {
		var b []byte
		for i := 0; i < 1500; i++ {
			b = append(b, 'a')
		}
		b = append(b, '5')
		for i := 0; i < 500; i++ {
			b = append(b, 'a')
		}
		return string(b)
	}
	var b []byte
	for i := 0; i < 2000; i++ {
		b = append(b, 'a')
	}
	return string(b)
}

// setShuftiLNMInput builds ~50 KB for the H.3 set-shufti-lnm case.
//
// When withMatches is true: lowercase prose with occasional uppercase
// "<Letter>1:<body>\n" log lines mixed in. Shufti finds a candidate in
// roughly every chunk so SIMD skip rarely fires; scalar/Shufti perform
// similarly.
// When withMatches is false: pure lowercase prose, ZERO uppercase letters.
// Under LNM the forced Shufti SIMD-skips all 50 KB in 16-byte chunks
// without ever finding a candidate — clean win vs scalar's byte-by-byte
// per-bucket comparison loop.
func setShuftiLNMInput(withMatches bool) string {
	const targetSize = 50 * 1024
	prose := []byte("the quick brown fox jumps over the lazy dog and they all live happily ever after. ")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	bodyFiller := []byte("the operation completed normally with no observable side effects on subsystem state. ")
	letters := []byte("ABCDEFGHIJKLMNOPQRSTU")
	var b []byte
	idx := 0
	for len(b) < targetSize {
		// Periodic match: "<Letter>1:<200-byte body>\n"
		b = append(b, letters[idx%len(letters)])
		b = append(b, '1', ':')
		bodyStart := len(b)
		for len(b)-bodyStart < 200 {
			b = append(b, bodyFiller...)
		}
		b = append(b, '\n')
		b = append(b, prose...)
		idx++
	}
	return string(b[:targetSize])
}

// impossibleRunInput builds ~50 KB of input dominated by bytes outside
// the [a-zA-Z] class — digits, punctuation, whitespace. For the LNM
// Action 5 (impossible-byte SIMD skip) demonstration.
//
// When withMatches is true: 5 letter runs (≥8 chars) embedded between
// long blocks of impossible bytes. The scalar prefix scan crawls
// through the impossible runs byte-by-byte; Action 5 should
// SIMD-skip them.
// When withMatches is false: pure impossible bytes, no letter runs.
func impossibleRunInput(withMatches bool) string {
	const targetSize = 50 * 1024
	filler := []byte("0123456789.,;:!?@#$%^&*()-+=[]{}|\\/<> \t01234567")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	var b []byte
	run := []byte("ABCDEFGHIJKLMN")
	chunkSize := targetSize / 6
	for i := 0; i < 5; i++ {
		for len(b) < (i+1)*chunkSize {
			b = append(b, filler...)
		}
		b = append(b, ' ')
		b = append(b, run...)
		b = append(b, ' ')
	}
	for len(b) < targetSize {
		b = append(b, filler...)
	}
	return string(b[:targetSize])
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
	// identical is true when this mode's compiled wasm is byte-identical to
	// neutral's — the compiler emitted the same code regardless of the
	// LikelyMode hint, so any wall-time difference between them can only be
	// measurement noise (see TODO.md task 25 investigation: identical wasm
	// still showed swings up to +137% run to run on sub-microsecond cases).
	// Benchmarking is skipped entirely for these; printMatrix shows a single
	// "identical WASM" message instead of numbers.
	identical bool
}

// compileMode compiles tc.pattern under the given LikelyMode and returns the WASM bytes.
func compileMode(tc testCase, mode compile.LikelyMode) ([]byte, error) {
	if tc.mode == modeSet {
		return compileSetMode(tc, mode)
	}
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

// compileSetMode compiles tc.setPatterns as a regexped set under the given
// LikelyMode and returns standalone WASM exporting find_all. The mode is
// applied at the global config level — H.1 plumbing routes it through both
// per-pattern (effective default) and per-set (frontend hint) fallbacks.
func compileSetMode(tc testCase, mode compile.LikelyMode) ([]byte, error) {
	entries := make([]config.RegexEntry, len(tc.setPatterns))
	for i, p := range tc.setPatterns {
		entries[i] = config.RegexEntry{Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps:    entries,
		LikelyMode: likelyModeYAML(mode),
		Sets: []config.SetConfig{
			{
				Name:     "bench_set",
				FindAll:  "find_all",
				Patterns: config.PatternSelector{All: true},
			},
		},
	}
	// Output empty → standalone.
	wasm, _, err := compile.CompileFile(cfg, "")
	return wasm, err
}

// likelyModeYAML maps the compile.LikelyMode enum back to its YAML string form
// so compileSetMode can stuff it into a BuildConfig field. Empty string ⇒
// caller-side neutral default.
func likelyModeYAML(m compile.LikelyMode) string {
	switch m {
	case compile.LikelyMatch:
		return "match"
	case compile.LikelyNoMatch:
		return "nomatch"
	}
	return ""
}

// benchTime times benchIters calls via the WASM shim and returns the p50 of
// those 10k internal samples — already statistically tight.
func benchTime(wasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine, debugMode ...string) (time.Duration, error) {
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
	if os.Getenv("DEBUG_STATS") != "" {
		p50 := computeStat(shimBuf[:timingsBytes], 50)
		p90 := computeStat(shimBuf[:timingsBytes], 90)
		p99 := computeStat(shimBuf[:timingsBytes], 99)
		mean := computeStat(shimBuf[:timingsBytes], 0)
		m := ""
		if len(debugMode) > 0 {
			m = debugMode[0]
		}
		fmt.Fprintf(os.Stderr, "    [%s mode=%s len=%d] p50=%s p90=%s p99=%s mean=%s\n", tc.name, m, len(input), p50, p90, p99, mean)
	}
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

// measureWasm runs (tc, input) against an already-compiled wasm module and
// returns one cell. Split out from measure so callers that already know the
// mode's wasm is byte-identical to neutral's (see main's identical-WASM gate)
// can skip compiling twice and skip benchmarking a module they've already
// measured under a different mode label.
func measureWasm(tc testCase, wasm []byte, mode compile.LikelyMode, input string, engine, fuelEngine *wasmtime.Engine) (cell, error) {
	if tc.mode == modeSet {
		t, err := benchTimeSet(wasm, input, engine)
		if err != nil {
			return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
		}
		f, err := benchFuelSet(wasm, input, fuelEngine)
		if err != nil {
			return cell{}, fmt.Errorf("bench fuel %s: %w", mode, err)
		}
		return cell{timeP50: t, fuel: f, size: len(wasm)}, nil
	}
	t, err := benchTime(wasm, tc, input, engine, mode.String())
	if err != nil {
		return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
	}
	f, err := benchFuel(wasm, tc, input, fuelEngine)
	if err != nil {
		return cell{}, fmt.Errorf("bench fuel %s: %w", mode, err)
	}
	return cell{timeP50: t, fuel: f, size: len(wasm)}, nil
}

// Set bench layout: tables live at the bottom of memory (CompileFile places
// them starting at offset 0). Input is written AFTER all table data, with the
// output buffer further past the input. Without this gap the input write
// silently overwrites the frontend Teddy/AC tables and the set match function
// produces garbage.
const (
	setOutCap   = int32(256)  // output capacity in tuples (12 B each)
	setIterTime = 1000        // exhaustion passes per p50 sample
)

// setMemPlan holds the resolved memory offsets for one set's bench.
type setMemPlan struct {
	inputBase  int32
	outputBase int32
}

// planSetMem computes input/output offsets that don't overlap with the set's
// data segments. Mirrors perftest's approach.
func planSetMem(wasmBytes []byte, inputLen int) (setMemPlan, error) {
	const pageSize = 65536
	actualTop := int64(0)
	if top, err := utils.ParseDataSectionBytes(wasmBytes); err == nil && top > actualTop {
		actualTop = top
	}
	inBase := int32((actualTop + pageSize - 1) / pageSize * pageSize)
	outBase := inBase + int32(inputLen) + 4096
	return setMemPlan{inputBase: inBase, outputBase: outBase}, nil
}

// benchTimeSet times the cost of one full find_all exhaustion pass over
// `input` and returns the p50 over setIterTime samples.
func benchTimeSet(wasmBytes []byte, input string, engine *wasmtime.Engine) (time.Duration, error) {
	plan, err := planSetMem(wasmBytes, len(input))
	if err != nil {
		return 0, err
	}
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
	mem := inst.GetExport(store, "memory").Memory()
	findFn := inst.GetFunc(store, "find_all")
	if mem == nil || findFn == nil {
		return 0, fmt.Errorf("missing exports")
	}
	if err := writeSetInput(store, mem, plan, input); err != nil {
		return 0, err
	}

	// Warmup: a few exhaustion passes.
	for warmupEnd := time.Now().Add(50 * time.Millisecond); time.Now().Before(warmupEnd); {
		runSetExhaust(store, findFn, mem, plan, int32(len(input)))
	}

	timings := make([]time.Duration, setIterTime)
	for i := range timings {
		t0 := time.Now()
		runSetExhaust(store, findFn, mem, plan, int32(len(input)))
		timings[i] = time.Since(t0)
	}
	// p50.
	ns := make([]byte, setIterTime*4)
	for i, d := range timings {
		v := uint32(d.Nanoseconds())
		ns[i*4] = byte(v)
		ns[i*4+1] = byte(v >> 8)
		ns[i*4+2] = byte(v >> 16)
		ns[i*4+3] = byte(v >> 24)
	}
	return computeStat(ns, 50), nil
}

// benchFuelSet measures fuel for one full find_all exhaustion pass.
func benchFuelSet(wasmBytes []byte, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
	plan, err := planSetMem(wasmBytes, len(input))
	if err != nil {
		return 0, err
	}
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
	mem := inst.GetExport(store, "memory").Memory()
	findFn := inst.GetFunc(store, "find_all")
	if mem == nil || findFn == nil {
		return 0, fmt.Errorf("missing exports")
	}
	if err := writeSetInput(store, mem, plan, input); err != nil {
		return 0, err
	}
	before, _ := store.GetFuel()
	runSetExhaust(store, findFn, mem, plan, int32(len(input)))
	after, _ := store.GetFuel()
	return before - after, nil
}

func writeSetInput(store *wasmtime.Store, mem *wasmtime.Memory, plan setMemPlan, input string) error {
	const pageSize = 65536
	needTop := uint64(plan.outputBase) + uint64(setOutCap)*12 + 4096
	neededPages := (needTop + pageSize - 1) / pageSize
	curPages := mem.Size(store)
	if neededPages > curPages {
		if _, err := mem.Grow(store, neededPages-curPages); err != nil {
			return fmt.Errorf("mem grow: %w", err)
		}
	}
	buf := mem.UnsafeData(store)
	copy(buf[plan.inputBase:], []byte(input))
	return nil
}

// runSetExhaust drives find_all in a loop until it returns 0 (no more matches),
// advancing startPos past the last match each iteration.
func runSetExhaust(store *wasmtime.Store, findFn *wasmtime.Func, mem *wasmtime.Memory, plan setMemPlan, inputLen int32) {
	startPos := int32(0)
	for {
		n, err := findFn.Call(store, plan.inputBase, inputLen, plan.outputBase, setOutCap, startPos)
		if err != nil {
			return
		}
		count := n.(int32)
		if count <= 0 {
			return
		}
		buf := mem.UnsafeData(store)
		last := int(count - 1)
		base := int(plan.outputBase) + last*12
		s := int32(buf[base+4]) | int32(buf[base+5])<<8 | int32(buf[base+6])<<16 | int32(buf[base+7])<<24
		l := int32(buf[base+8]) | int32(buf[base+9])<<8 | int32(buf[base+10])<<16 | int32(buf[base+11])<<24
		if l <= 0 {
			l = 1
		}
		startPos = s + l
	}
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
		if rows[i].identical {
			// TODO.md task 25 investigation: identical wasm still showed
			// wall-time swings up to +137% run to run on sub-microsecond
			// cases — comparing timings across byte-identical code is pure
			// noise, so skip the run entirely rather than report it.
			fmt.Printf("  %-16s  identical WASM — same as neutral, timing/fuel run skipped\n", modes[i])
			continue
		}
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

	filter := os.Getenv("LIKELYTEST_FILTER")
	for _, tc := range tests {
		if filter != "" && !strings.Contains(tc.name, filter) {
			continue
		}
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)
		var rowsMatch, rowsNoMatch [3]cell
		var neutralWasm []byte
		for i, m := range modes {
			wasm, err := compileMode(tc, m)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  compile %s: %v\n", m, err)
				continue
			}
			if i == 0 {
				neutralWasm = wasm
			}
			// Identical-WASM gate (TODO.md task 25 investigation): if this
			// mode compiled to byte-identical wasm to neutral, the compiler
			// ignored the LikelyMode hint for this pattern entirely — any
			// wall-time delta we'd measure is guaranteed noise, not signal.
			// Skip benchmarking, reuse nothing (deliberately re-derive size
			// from this mode's own wasm rather than assuming it), and mark
			// both rows so printMatrix shows a message instead of numbers.
			if i > 0 && bytes.Equal(wasm, neutralWasm) {
				rowsMatch[i] = cell{size: len(wasm), identical: true}
				rowsNoMatch[i] = cell{size: len(wasm), identical: true}
				continue
			}
			c, err := measureWasm(tc, wasm, m, tc.matchInput, engine, fuelEngine)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  measure %s match: %v\n", m, err)
				continue
			}
			rowsMatch[i] = c
			c, err = measureWasm(tc, wasm, m, tc.nomatchInput, engine, fuelEngine)
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
