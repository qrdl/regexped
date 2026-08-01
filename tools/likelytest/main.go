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
	"runtime"
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
	slotsBase  = int32(65536)  // page 1: keep clear of input (up to 64 KiB at offset 0)
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
	// exhaustive drives the single-pattern find/groups export to exhaustion
	// (advance past each match, repeat until EOF or no match — see
	// runFindExhaust/runGroupsExhaust) instead of measuring one call. A
	// single find()/groups() call only scans to the FIRST match — bytes
	// after it are never touched — so "match-dense" inputs (LM_TODO.md
	// LM-0) are meaningless under single-call measurement; this flag is
	// what makes them actually exercise the whole buffer. modeSet cases
	// always exhaust via find_all regardless of this flag.
	exhaustive bool
}

var tests = []testCase{
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
		// Task 28 target: same 21-pattern [A-U] set as set-shufti-lnm, but
		// the no-match input is DENSE in the tracked first-byte set instead
		// of sparse — the "rarely matches" assumption LikelyNoMatch bakes
		// into forcing Shufti doesn't hold here. Mirrors alpha-run/word-run
		// (task 25's single-pattern version of this same footgun), which
		// EmitPrefixScan's DenseCounter/DenseSkipFlag adaptive switch
		// already protects against — buildSetSuffixBody's Shufti frontend
		// (emitSetMatchFnFinalShufti) has no equivalent protection yet.
		//
		// No-match input is solid A-U letters with no gaps at all: every
		// SIMD chunk's bitmask is all-1s, so ctz always returns 0 and the
		// skip loop can never advance by more than one position per
		// attempt — forcing the scalar membership-check tail on literally
		// every position, on top of the SIMD overhead itself. None of the
		// letters are ever followed by "1:" so nothing matches.
		name: "set-shufti-dense-harm",
		setPatterns: []string{
			`A1:[^\n]+`, `B1:[^\n]+`, `C1:[^\n]+`, `D1:[^\n]+`, `E1:[^\n]+`,
			`F1:[^\n]+`, `G1:[^\n]+`, `H1:[^\n]+`, `I1:[^\n]+`, `J1:[^\n]+`,
			`K1:[^\n]+`, `L1:[^\n]+`, `M1:[^\n]+`, `N1:[^\n]+`, `O1:[^\n]+`,
			`P1:[^\n]+`, `Q1:[^\n]+`, `R1:[^\n]+`, `S1:[^\n]+`, `T1:[^\n]+`,
			`U1:[^\n]+`,
		},
		mode:         modeSet,
		notes:        "set with 21 [A-U]-prefixed literals, DENSE no-match data — task 28 (Shufti dense-data harm) target",
		matchInput:   setShuftiDenseHarmInput(true),
		nomatchInput: setShuftiDenseHarmInput(false),
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
	{
		// Task 41 BT-routed sibling of tdfa-bulk-skip-word-class above:
		// `([^,]+)` is also a whole-pattern single capture, but the
		// inverted class trips hasAmbiguousCaptures (task 13) and routes
		// to Backtracking instead of TDFA. Same shape (10 KB self-loop
		// run + one-byte offset between match/nomatch inputs) confirms
		// the task 41 shortcut's fuel win isn't TDFA-specific — it should
		// eliminate BT's ~40 fuel/byte captureBody re-walk here too.
		name:         "bt-groups-whole-capture-inverted-class",
		pattern:      `([^,]+)`,
		mode:         modeGroups,
		notes:        "BT-routed whole-pattern single capture (inverted class) — task 41 BT sibling",
		matchInput:   strings.Repeat("aB3_", 2560) + ",",
		nomatchInput: "," + strings.Repeat("aB3_", 2560),
	},

	// ── LM-0: match-dense cases (plans/LM_TODO.md) ──────────────────────
	// All prior cases above bury a single match in 10-50 KB — scan-to-first-
	// match dominates total fuel, so any per-hit/per-run optimisation is
	// diluted to ~0% in the matrix. These cases exhaust the whole buffer
	// (exhaustive: true) so per-match cost actually shows up in the total.
	{
		// LM-1 companion / regression guard: N=36 already clears the
		// existing N>=24 lit-chain SIMD-verify gate, so this is NOT an LM-1
		// win case — it's a dense-workload guard for whatever already
		// applies to this shape today, and a target for LM-2 (host-call
		// amortisation via batched find).
		name:         "dense-secrets",
		pattern:      `ghp_[A-Za-z0-9]{36}`,
		mode:         modeFind,
		notes:        "dense ghp_ tokens (N=36, already >=24 lit-chain gate) — dense-workload guard / LM-2 target",
		matchInput:   denseSecretsInput(true),
		nomatchInput: denseSecretsInput(false),
		exhaustive:   true,
	},
	{
		// LM-1 primary target: N=16 < 24, currently rejected by
		// analyseLitChain's single-pattern gate (compile/engine_dfa.go),
		// falls back to plain DFA. This is the case LM-1's measurement plan
		// names as primary.
		name:         "dense-akia",
		pattern:      `AKIA[A-Z0-9]{16}`,
		mode:         modeFind,
		notes:        "dense AKIA tokens (N=16 < 24) — LM-1 primary target (lit-chain SIMD-verify gate relaxation)",
		matchInput:   denseAkiaInput(true),
		nomatchInput: denseAkiaInput(false),
		exhaustive:   true,
	},
	{
		// Many short \w+ runs per pass (a word every ~6 bytes) instead of
		// tdfa-bulk-skip-word-class's one long homogeneous run — stresses
		// TDFA bulk-skip entry/exit frequency and, once batched find lands,
		// is a natural LM-2 host-call-amortisation target.
		name:         "dense-words-grouped",
		pattern:      `(\w+)`,
		mode:         modeGroups,
		notes:        "dense short \\w+ runs (word every ~6 bytes) — TDFA bulk-skip entry/exit frequency, LM-2 target",
		matchInput:   denseWordsInput(true),
		nomatchInput: denseWordsInput(false),
		exhaustive:   true,
	},
	{
		// LM-3 target: non-mid-accept 9-64-byte self-loop body
		// (`[^>]+` after a 1-byte literal `<`), dense tags every ~20 bytes.
		// Today's Shufti self-loop bulk-skip (task 26) is mid-accept only;
		// this shape's accept state sits at `>`, one byte AFTER the
		// self-loop, i.e. non-mid — uncovered until LM-3.
		name:         "dense-tags",
		pattern:      `<[^>]+>`,
		mode:         modeFind,
		notes:        "dense HTML-ish tags every ~20 bytes, non-mid-accept self-loop — LM-3 target",
		matchInput:   denseTagsInput(true),
		nomatchInput: denseTagsInput(false),
		exhaustive:   true,
	},
	{
		// LM-3 primary target: non-mid-accept self-loop with LONG runs
		// (20-50 bytes per token, well over the 16-byte SIMD chunk width),
		// unlike dense-tags above whose ~14-byte tag bodies are short enough
		// to trip the task-38 hysteresis (advance < 16 -> unproductive) on
		// nearly every attempt. This is the case expected to show the actual
		// win from lifting the non-mid gate on a 9-64-byte class.
		name:         "dense-quoted",
		pattern:      `"[a-z0-9]+"`,
		mode:         modeFind,
		notes:        "dense quoted alnum tokens, 20-50 bytes each — LM-3 primary target (long non-mid self-loop runs)",
		matchInput:   denseQuotedInput(true, false),
		nomatchInput: denseQuotedInput(false, false),
		exhaustive:   true,
	},
	{
		// LM-3 harm/guard case: same pattern, but tokens are 3-6 bytes —
		// every attempt advances < 16 bytes, so the task-38 hysteresis
		// should self-disable the channel after nonMidHystStreak wasted
		// attempts and hold fuel roughly flat vs neutral for the rest of
		// the buffer.
		name:         "dense-quoted-short",
		pattern:      `"[a-z0-9]+"`,
		mode:         modeFind,
		notes:        "dense quoted alnum tokens, 3-6 bytes each — LM-3 harm/hysteresis guard (short non-mid self-loop runs)",
		matchInput:   denseQuotedInput(true, true),
		nomatchInput: denseQuotedInput(false, true),
		exhaustive:   true,
	},
	{
		// LM-4 target: bare (no literal prefix) 9-64-byte-class self-loop —
		// detectShuftiSelfLoop bails on len(l.prefix)==0 today (task 34's
		// gate). Runs vary 10-30 bytes so the self-loop is exercised
		// repeatedly rather than as one giant run.
		name:         "dense-bare-upper",
		pattern:      `[A-Z]{8,}`,
		mode:         modeFind,
		notes:        "dense bare uppercase runs, 10-30 bytes, no literal prefix — LM-4 target",
		matchInput:   denseBareUpperInput(true),
		nomatchInput: denseBareUpperInput(false),
		exhaustive:   true,
	},
	{
		// LM-5 target: 65-239-byte-class self-loop, above Shufti's
		// pre-LM-5 64-byte cap. `:[ -~]{10,}` after a literal `:` — a
		// 95-byte printable class. Sized with pattest before
		// implementation (`:[ -~]{10,}` over 20-60 and 100-200-byte runs
		// measured -41%/-55% fuel); this case uses long runs (65-150
		// bytes) to land solidly inside the newly-widened band.
		name:         "dense-printable",
		pattern:      `:[ -~]{10,}`,
		mode:         modeFind,
		notes:        "dense printable runs, 65-150 bytes, 95-byte class width — LM-5 target (widened Shufti band)",
		matchInput:   densePrintableInput(true, false),
		nomatchInput: densePrintableInput(false, false),
		exhaustive:   true,
	},
	{
		// LM-5 harm/guard case: same pattern, runs 10-15 bytes (right at
		// the pattern's own `{10,}` minimum) — pattest measured +12% here,
		// the bounded "LM contract cost" residual task-38's hysteresis is
		// meant to contain, same shape as dense-quoted-short/alpha-run.
		name:         "dense-printable-short",
		pattern:      `:[ -~]{10,}`,
		mode:         modeFind,
		notes:        "dense printable runs, 10-15 bytes (at pattern minimum) — LM-5 harm/hysteresis guard",
		matchInput:   densePrintableInput(true, true),
		nomatchInput: densePrintableInput(false, true),
		exhaustive:   true,
	},
	{
		// LM-6 primary target: two counted-chain-eligible patterns that
		// DO share a mandatory literal ("eyJ", a base64 JSON-header
		// prefix — two JWT-segment-length variants). An AKIA/ghp_ variant
		// of this case (patterns sharing no literal) was tried and removed:
		// binPack never even considers merging disjoint-literal patterns,
		// confirmed via diag JSON sizing — always two singleton buckets
		// regardless of LikelyMode, so that shape produces byte-identical
		// WASM across all three modes and exercises nothing. This pair, by
		// contrast, lands in the same bucketByLiteral group and binPack's
		// constraint checks merge them under neutral, losing task 5's
		// single-pattern SIMD suffix body for both. LM-6 gates a refusal on
		// this exact shape.
		name: "dense-set-shared-prefix",
		setPatterns: []string{
			`eyJ[A-Za-z0-9_-]{20}`,
			`eyJ[A-Za-z0-9_-]{40}`,
		},
		mode:         modeSet,
		notes:        "eyJ-prefixed set, two counted-chain lengths sharing a literal — LM-6 primary target (binPack merge refusal)",
		matchInput:   denseSetSharedPrefixInput(true),
		nomatchInput: denseSetSharedPrefixInput(false),
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
//
//	`0001INFO:` + ~24 KB non-newline body + `\n` + filler +
//	`0002INFO:` + ~24 KB non-newline body + `\n`.
//
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

// secretsFalsePositiveInput builds ~50 KB of no-match input for
// `ghp_[A-Za-z0-9]{36}` (task 24: promoting the Opt 2 counted-chain SIMD
// verifier from LikelyMatch-gated to unconditional). Scatters "ghp_"
// occurrences through filler text, each followed by exactly 35 valid
// [A-Za-z0-9] bytes — one short of the 36 required — so the pattern never
// actually matches, but both the plain DFA's counted-chain walk and Opt 2's
// SIMD chain-verify must consume all 35 valid bytes before the 36th
// (non-alnum) byte proves failure. This is the worst case for Opt 2: unlike
// a false positive that dies within the first byte or two, this one forces
// the full chain-length comparison every time, which is exactly the
// scenario where a regression from unconditional promotion would show up
// if one exists. Filler is alnum-free so a 35-byte near-miss run can never
// accidentally extend past 36 bytes at a concatenation boundary.
func secretsFalsePositiveInput() string {
	const targetSize = 50 * 1024
	filler := []byte(", the quick brown fox jumps over the lazy dog - filler text goes here forever; ")
	nearMissSuffix := []byte("AbCdEfGhIjKlMnOpQrStUvWxYz012345678") // 35 chars, one short of 36
	var b []byte
	for len(b) < targetSize {
		b = append(b, filler...)
		b = append(b, []byte("ghp_")...)
		b = append(b, nearMissSuffix...)
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

// postLiteralWideSelfLoopInput builds ~50 KB for `ID:[a-zA-Z0-9]{10,}`
// (task 26). `find` returns on the FIRST match, so repeating "ID:<value> "
// many times would only exercise the self-loop walk once (the first hit) —
// no good as a cumulative stress test. Instead, when withMatches is true:
// a single "ID:" followed by one alnum run spanning almost the entire
// buffer, forcing the greedy `{10,}` self-loop to scalar-walk the full
// ~50 KB to find where the run ends (no trailing non-alnum byte, so it
// walks to EOF) — directly measuring the per-byte cost this task targets.
// When false: plain "ID:"-free prose of the same size — the literal never
// fires, so the post-hit self-loop scan never runs at all (the floor; see
// the case's own comment for why the no-match side can't otherwise stress
// this gap for an open-ended `{10,}` quantifier).
func postLiteralWideSelfLoopInput(withMatches bool) string {
	const targetSize = 50 * 1024
	prose := []byte("the quick brown fox jumps over the lazy dog and other filler text goes here. ")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	alnum := []byte("aB3xR9mLq2ZpW7cD5nE8fH1jK4sT6vU0")
	b := []byte("ID:")
	for len(b) < targetSize {
		b = append(b, alnum...)
	}
	return string(b[:targetSize])
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

// setShuftiDenseHarmInput builds ~50 KB for the task 28 set-shufti-dense-harm
// case — the harm-side counterpart to setShuftiLNMInput's win-side prose.
//
// When withMatches is false: solid A-U letters with no gaps at all (no
// spaces, no other bytes) — every byte in the buffer is a Shufti
// candidate, so the SIMD skip loop's bitmask is always all-1s and ctz
// always returns 0, forcing the scalar membership-check tail on every
// single position. None of the letters are followed by "1:" so nothing
// ever matches.
// When withMatches is true: the same dense A-U filler with a handful of
// real "<Letter>1:<body>\n" matches spliced in, so the match path is
// exercised under the same dense-first-byte-set conditions.
func setShuftiDenseHarmInput(withMatches bool) string {
	const targetSize = 50 * 1024
	letters := []byte("ABCDEFGHIJKLMNOPQRSTU")
	if !withMatches {
		var b []byte
		for len(b) < targetSize {
			b = append(b, letters...)
		}
		return string(b[:targetSize])
	}
	bodyFiller := []byte("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV")
	var b []byte
	idx := 0
	for len(b) < targetSize {
		for i := 0; i < 400; i++ {
			b = append(b, letters...)
		}
		// Real match: "<Letter>1:<200-byte body>\n" — body uses 'V' (not
		// in the tracked A-U set) so it can't itself extend a neighbouring
		// dense run into a spurious match.
		b = append(b, letters[idx%len(letters)])
		b = append(b, '1', ':')
		bodyStart := len(b)
		for len(b)-bodyStart < 200 {
			b = append(b, bodyFiller...)
		}
		b = append(b, '\n')
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

// denseSecretsInput builds ~50 KB for LM-0's dense-secrets case
// (`ghp_[A-Za-z0-9]{36}`). When withMatches, packs back-to-back valid
// tokens separated by ", " so an exhaustion-driven find() pass visits
// hundreds of matches instead of scanning past just one. When false, the
// same size of "ghp_"-free filler.
func denseSecretsInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte(", the quick brown fox jumps over the lazy dog and other filler text goes here forever")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	alnum := []byte("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
	var b []byte
	for i := 0; len(b) < targetSize; i++ {
		b = append(b, "ghp_"...)
		for j := 0; j < 36; j++ {
			b = append(b, alnum[(i+j)%len(alnum)])
		}
		b = append(b, ',', ' ')
	}
	return string(b[:targetSize])
}

// denseAkiaInput builds ~50 KB for LM-0's dense-akia case
// (`AKIA[A-Z0-9]{16}`) — LM-1's primary measurement target (N=16 < 24).
// Same shape as denseSecretsInput, sized for this token's length.
func denseAkiaInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte(", the quick brown fox jumps over the lazy dog and other filler text goes here forever")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	alnum := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	var b []byte
	for i := 0; len(b) < targetSize; i++ {
		b = append(b, "AKIA"...)
		for j := 0; j < 16; j++ {
			b = append(b, alnum[(i+j)%len(alnum)])
		}
		b = append(b, ',', ' ')
	}
	return string(b[:targetSize])
}

// denseWordsInput builds ~50 KB for LM-0's dense-words-grouped case
// (`(\w+)` groups mode). When withMatches, English-like prose (a word
// every ~6 bytes on average); when false, 50 KB of punctuation with no
// \w byte at all, so the internal find() never has anything to report.
func denseWordsInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		punct := []byte(",;.! ")
		var b []byte
		for len(b) < targetSize {
			b = append(b, punct...)
		}
		return string(b[:targetSize])
	}
	prose := []byte("the quick brown fox jumps over lazy dogs while owls sit near old oak trees at dusk and count stars above quiet fields ")
	var b []byte
	for len(b) < targetSize {
		b = append(b, prose...)
	}
	return string(b[:targetSize])
}

// denseTagsInput builds ~50 KB for LM-0's dense-tags case (`<[^>]+>`) —
// LM-3's target (non-mid-accept self-loop: the accept state sits at `>`,
// one byte after the self-loop body). Tags every ~20 bytes when
// withMatches; no-match input has no `<` byte anywhere.
func denseTagsInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte("the quick brown fox jumps over the lazy dog with no angle brackets anywhere here ")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	tags := []string{"div", "span", "p", "a", "b", "i", "ul", "li", "h1", "h2"}
	var b []byte
	for i := 0; len(b) < targetSize; i++ {
		b = append(b, '<')
		b = append(b, tags[i%len(tags)]...)
		b = append(b, ` class="x">`...)
	}
	return string(b[:targetSize])
}

// denseQuotedInput builds ~50 KB for the dense-quoted / dense-quoted-short
// cases (`"[a-z0-9]+"`) — LM-3's target and harm/hysteresis guard. When
// short is false, tokens cycle 20..50 bytes (multiple 16-byte SIMD chunks
// per run); when short is true, tokens cycle 3..6 bytes (every bulk-skip
// attempt advances < 16 bytes, exercising the task-38 hysteresis). No-match
// input contains no `"` at all.
func denseQuotedInput(withMatches, short bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte("the quick brown fox jumps over the lazy dog with no quotes anywhere in here ")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	alnum := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	minLen, maxLen := 20, 50
	if short {
		minLen, maxLen = 3, 6
	}
	var b []byte
	runLen := minLen
	for len(b) < targetSize {
		b = append(b, '"')
		for j := 0; j < runLen; j++ {
			b = append(b, alnum[j%len(alnum)])
		}
		b = append(b, '"', ' ')
		runLen++
		if runLen > maxLen {
			runLen = minLen
		}
	}
	return string(b[:targetSize])
}

// densePrintableInput builds ~50 KB for the dense-printable /
// dense-printable-short cases (`:[ -~]{10,}`) — LM-5's target (65-239-byte
// Shufti band). Tokens are a literal ':' followed by a run cycling over
// the full printable range 0x20..0x7e; run length cycles 65..150 bytes
// (long, short=false) or 10..15 bytes (at the pattern's own minimum,
// short=true). Tokens are separated by '\n' (0x0A) — NOT '\x20' — since
// the class itself includes the space character; a space separator would
// let the match run straight through into the next token instead of
// terminating, collapsing "many dense tokens" into one giant match. No-match
// input has no ':' anywhere.
func densePrintableInput(withMatches, short bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte("the quick brown fox jumps over the lazy dog with no colon anywhere in here\n")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	minLen, maxLen := 65, 150
	if short {
		minLen, maxLen = 10, 15
	}
	var b []byte
	runLen := minLen
	for len(b) < targetSize {
		b = append(b, ':')
		for j := 0; j < runLen; j++ {
			b = append(b, byte(0x20+j%(0x7f-0x20)))
		}
		b = append(b, '\n')
		runLen++
		if runLen > maxLen {
			runLen = minLen
		}
	}
	return string(b[:targetSize])
}

// denseBareUpperInput builds ~50 KB for LM-0's dense-bare-upper case
// (`[A-Z]{8,}`) — LM-4's target (bare self-loop, no literal prefix; today
// detectShuftiSelfLoop bails on len(l.prefix)==0). Run lengths cycle
// 10..30 bytes, separated by single spaces, when withMatches; no-match
// input is plain lowercase prose.
func denseBareUpperInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		prose := []byte("the quick brown fox jumps over the lazy dog and other filler text goes here. ")
		var b []byte
		for len(b) < targetSize {
			b = append(b, prose...)
		}
		return string(b[:targetSize])
	}
	upper := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var b []byte
	runLen := 10
	for len(b) < targetSize {
		for j := 0; j < runLen; j++ {
			b = append(b, upper[j%len(upper)])
		}
		b = append(b, ' ')
		runLen++
		if runLen > 30 {
			runLen = 10
		}
	}
	return string(b[:targetSize])
}

// denseSetSharedPrefixInput builds ~50 KB for the dense-set-shared-prefix
// case (two eyJ-prefixed counted-chain patterns, N=20 and N=40) — LM-6's
// primary measurement target. Alternates the two token lengths when
// withMatches; token-free filler of the same size otherwise.
func denseSetSharedPrefixInput(withMatches bool) string {
	const targetSize = 50 * 1024
	if !withMatches {
		filler := []byte(", the quick brown fox jumps over the lazy dog and other filler text goes here forever")
		var b []byte
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	alnum := []byte("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-")
	var b []byte
	for i := 0; len(b) < targetSize; i++ {
		n := 20
		if i%2 == 1 {
			n = 40
		}
		b = append(b, "eyJ"...)
		for j := 0; j < n; j++ {
			b = append(b, alnum[(i+j)%len(alnum)])
		}
		b = append(b, ',', ' ')
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
	result := computeStat(shimBuf[:timingsBytes], 50)
	// shimBuf is a raw pointer into wasmtime's native memory (UnsafeData), not
	// a Go-tracked reference to store — without this, store (and the
	// wasmtime.Memory it owns) becomes GC-eligible as soon as it's no longer
	// referenced by name above, and a GC cycle landing between that point and
	// the last shimBuf read can free the backing memory out from under a
	// still-in-flight read, causing a segfault (observed intermittently,
	// especially under DEBUG_STATS's extra computeStat calls).
	runtime.KeepAlive(store)
	return result, nil
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

// findExhaustIterTime is the timing-sample count for exhaustive find/groups
// measurement (LM_TODO.md LM-0). Lower than setIterTime (1000): a dense
// find/groups pass can visit far more matches per pass than the set cases
// do (e.g. dense-words-grouped's ~8k words), so fewer reps keeps wall-clock
// reasonable while still giving a stable p50.
const findExhaustIterTime = 200

// runFindExhaust drives a single-pattern find() export to exhaustion over
// inputLen bytes at inputBase, mirroring the host stubs' iteration loop
// (generate/js_stub.go genJSFindFunc): re-call with a shrinking window
// (inputBase+off, inputLen-off), advance off past each match (or by 1 for
// a zero-length match) until no match or EOF.
func runFindExhaust(store *wasmtime.Store, fn *wasmtime.Func, inputLen int32) {
	off := int32(0)
	for off <= inputLen {
		r, err := fn.Call(store, inputBase+off, inputLen-off)
		if err != nil {
			return
		}
		packed := r.(int64)
		if packed < 0 {
			return
		}
		relStart := int32(packed >> 32)
		relEnd := int32(packed & 0xFFFFFFFF)
		if relEnd > relStart {
			off += relEnd
		} else {
			off += relStart + 1
		}
	}
}

// runGroupsExhaust drives a single-pattern groups() export to exhaustion,
// mirroring generate/js_stub.go genJSGroupsFunc's advance-by-matchEnd
// logic. Unlike the JS stub, this stops immediately when no match is
// found rather than retrying at off+1: the groups wrapper calls find()
// internally first, so a negative result already means no match exists
// anywhere in the remaining window — retrying smaller windows would only
// re-derive the same answer, which is stub-loop waste, not engine cost
// this benchmark should measure.
func runGroupsExhaust(store *wasmtime.Store, fn *wasmtime.Func, mem *wasmtime.Memory, slotsPtr, inputLen int32) {
	off := int32(0)
	for off <= inputLen {
		r, err := fn.Call(store, inputBase+off, inputLen-off, slotsPtr)
		if err != nil {
			return
		}
		if r.(int32) < 0 {
			return
		}
		buf := mem.UnsafeData(store)
		matchEnd := int32(buf[slotsPtr+4]) | int32(buf[slotsPtr+5])<<8 | int32(buf[slotsPtr+6])<<16 | int32(buf[slotsPtr+7])<<24
		runtime.KeepAlive(store)
		if matchEnd > 0 {
			off += matchEnd
		} else {
			off++
		}
	}
}

// benchTimeExhaust times findExhaustIterTime full exhaustion passes (Go-level
// loop, mirrors benchTimeSet's approach for sets) and returns the p50.
func benchTimeExhaust(wasmBytes []byte, tc testCase, input string, engine *wasmtime.Engine) (time.Duration, error) {
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
	case modeFind:
		fnExport = "find"
	case modeGroups:
		fnExport = "groups"
	}
	mem := inst.GetExport(store, "memory").Memory()
	fn := inst.GetFunc(store, fnExport)
	if mem == nil || fn == nil {
		return 0, fmt.Errorf("missing exports")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	runtime.KeepAlive(store)
	inputLen := int32(len(input))

	run := func() {
		if tc.mode == modeGroups {
			runGroupsExhaust(store, fn, mem, slotsBase, inputLen)
		} else {
			runFindExhaust(store, fn, inputLen)
		}
	}

	for warmupEnd := time.Now().Add(50 * time.Millisecond); time.Now().Before(warmupEnd); {
		run()
	}

	timings := make([]time.Duration, findExhaustIterTime)
	for i := range timings {
		t0 := time.Now()
		run()
		timings[i] = time.Since(t0)
	}
	ns := make([]byte, findExhaustIterTime*4)
	for i, d := range timings {
		v := uint32(d.Nanoseconds())
		ns[i*4] = byte(v)
		ns[i*4+1] = byte(v >> 8)
		ns[i*4+2] = byte(v >> 16)
		ns[i*4+3] = byte(v >> 24)
	}
	result := computeStat(ns, 50)
	runtime.KeepAlive(store)
	return result, nil
}

// benchFuelExhaust measures fuel for one full exhaustion pass.
func benchFuelExhaust(wasmBytes []byte, tc testCase, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
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
	case modeFind:
		fnExport = "find"
	case modeGroups:
		fnExport = "groups"
	}
	mem := inst.GetExport(store, "memory").Memory()
	fn := inst.GetFunc(store, fnExport)
	if mem == nil || fn == nil {
		return 0, fmt.Errorf("missing exports")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	runtime.KeepAlive(store)
	inputLen := int32(len(input))

	before, _ := store.GetFuel()
	if tc.mode == modeGroups {
		runGroupsExhaust(store, fn, mem, slotsBase, inputLen)
	} else {
		runFindExhaust(store, fn, inputLen)
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
	if tc.exhaustive {
		t, err := benchTimeExhaust(wasm, tc, input, engine)
		if err != nil {
			return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
		}
		f, err := benchFuelExhaust(wasm, tc, input, fuelEngine)
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
	setOutCap   = int32(256) // output capacity in tuples (12 B each)
	setIterTime = 1000       // exhaustion passes per p50 sample
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
	// See benchTime's comment on the same pattern: buf is a raw pointer into
	// wasmtime's native memory, not a Go reference to store, so store must be
	// kept alive explicitly through the last use of buf.
	runtime.KeepAlive(store)
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
		// See benchTime's comment on the same pattern: buf is a raw pointer
		// into wasmtime's native memory, not a Go reference to store.
		runtime.KeepAlive(store)
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
