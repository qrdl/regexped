// likelytest is a focused benchmark harness that compares regexped's WASM output
// across the three LikelyMode compile modes (neutral, likely-match, likely-nomatch)
// for a hand-picked set of patterns where the LikelyMode design's structural optimisations
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
// Before a case's numbers are trusted, every (pattern, mode, input)
// combination is also checked against Go's regexp package as ground truth
// (see the "Correctness checking against Go stdlib regexp" section below) —
// a mismatch prints CORRECTNESS FAIL to stderr and the run exits non-zero.
//
// Note: LikelyMode is a stub today — all three modes produce identical WASM. The
// columns will only diverge once the LikelyMode design's optimisations land in compile/.
// Run via `make run` from this directory.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
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
	fuelBudget = uint64(10_000_000_000)
)

// --------------------------------------------------------------------------
// Test cases

type matchMode int

const (
	modeFind matchMode = iota
	modeAnchored
	modeGroups
	modeSet // CompileFile with cfg.Sets; driven via the `find` exhaustion loop
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
	// after it are never touched — so "match-dense" inputs are meaningless
	// under single-call measurement; this flag is
	// what makes them actually exercise the whole buffer. modeSet cases
	// always exhaust via the set `find` regardless of this flag.
	exhaustive bool

	// setCap selects which capability a modeSet case declares and drives.
	// Empty (the default) is `find`, driven to exhaustion — the only shape
	// this harness had before.
	//
	// The scan pair exists here because it is the ONLY way to reach the union
	// automaton (compile/set_union_scan.go): `find` never enters it except
	// through a preflight. A set-level optimisation to the union scan is
	// invisible to a `find`-only harness, which is what this field fixes.
	// Values: setCapFind, setCapScanAny, setCapScanAll.
	setCap string

	// forceScalarFrontend pins the set's literal frontend to scalar, which is
	// the ONLY way these cases can reach the Shufti frontend: Shufti is
	// selected out of the scalar branch, and 21 short literals with 21
	// distinct first bytes now satisfy chooseLiteralFrontend's Teddy branch
	// instead. Without it the two set-shufti-* cases silently measure Teddy
	// and print "identical WASM" in every mode — which is what they had been
	// doing.
	//
	// The measured BODY is the real Shufti emission either way; what forcing
	// misrepresents is bucket count (21, where a set that reaches Shufti
	// naturally has hundreds), which inflates the prefilter's share of total
	// cost. That cancels for a 3-mode comparison, since every arm carries the
	// same buckets — but it makes the Δ% an UPPER BOUND, not a production
	// figure. See TODO task 73.
	forceScalarFrontend bool
}

// The capabilities a modeSet case can drive. Kept as the export names
// themselves so the config field, the WASM export and the row label cannot
// drift apart.
const (
	setCapFind    = ""         // `find`, driven to exhaustion
	setCapScanAny = "scan_any" // one call; returns a bare id or -1
	setCapScanAll = "scan_all" // one call; returns an i64 id bitmask
)

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
		// The 65..128 first-byte band, which single patterns leave on the
		// scalar path: prefix_scan.go caps Shufti at 64 while the SET path
		// goes to 128 under the hint. `[!-~]` is 94 bytes and carries no
		// literal, so nothing else can prefilter it.
		//
		// WIN half: input dominated by whitespace, which is outside the
		// class, so the prefilter has long runs to stride over. Its twin
		// below is the harm half; both are needed or the pair measures only
		// the flattering side.
		name:         "printable-run",
		pattern:      `[!-~]{12,}`,
		mode:         modeFind,
		notes:        "94-byte first-set, whitespace-sparse input — the 65..128 band win case",
		matchInput:   printableRunInput(true, false),
		nomatchInput: printableRunInput(false, false),
	},
	{
		// HARM half of the pair above: printable bytes everywhere, so every
		// SIMD chunk finds a candidate at once and the prefilter's nibble
		// tables are pure overhead. Runs are capped one byte short of the
		// pattern's {12,} so the buffer stays dense without matching.
		name:         "printable-run-dense-harm",
		pattern:      `[!-~]{12,}`,
		mode:         modeFind,
		notes:        "94-byte first-set, DENSE input — the 65..128 band harm case",
		matchInput:   printableRunInput(true, true),
		nomatchInput: printableRunInput(false, true),
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
		// Suggestion 3 target (RESOLVED —
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
		// at a time with no SIMD.
		name:         "lit-anchor-dominant-body",
		pattern:      `[0-9]{4}INFO:[^\n]+`,
		mode:         modeFind,
		notes:        "lit-anchor + mid-accept dominant body — backward prefix-scan target",
		matchInput:   litAnchorDominantBodyInput(true),
		nomatchInput: litAnchorDominantBodyInput(false),
	},
	{
		// a bounded-but-larger class-count prefix
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
		notes:        "lit-anchor backward prefix-scan, 15-digit near-miss false-positives — backward prefix-scan target",
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
		// pattern with greedy class quantifier followed by a
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
		notes:        "near-miss greedy quantifier — dead-state skip target",
		matchInput:   deadSkipNearMissInput(true),
		nomatchInput: deadSkipNearMissInput(false),
	},
	{
		// Min-length quantifier skip. Pattern
		// requires >=50 lowercase letters followed by a digit. Suffix is a
		// character CLASS, not a literal, so no mandatory-literal frontend
		// applies (confirmed by probe: fuel scales linearly for an
		// equivalent literal-suffix pattern like `x{500}y`, but quadratically
		// here) — the find loop falls through to the naive per-position DFA
		// retry path.
		//
		// No-match input is 2000 lowercase letters with no digit anywhere:
		// the DFA never dies (stays in-class the whole way) and never runs
		// short of input (the dead-state skip and follow-up #1's
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
		notes:        "no mandatory literal, never dies, never runs short — min-length quantifier skip target",
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
		//
		// SELECTION IS FORCED (forceScalarFrontend, task 73). Between this
		// case being written and 2026-08-31 it drifted onto **Teddy** and
		// printed "identical WASM" in all three modes, measuring nothing
		// hint-related: 21 literals of length 3 with 21 distinct first bytes
		// satisfy chooseLiteralFrontend's Teddy branch (<=64 literals,
		// minLen >= 2, distinctFirst >= 4), and Shufti is reachable ONLY out
		// of the scalar branch — in production only after Aho-Corasick
		// declines over its 512 KB budget, which takes hundreds of long
		// literals.
		//
		// Pinning the frontend to scalar restores the intended A/B: neutral
		// stays scalar (these literals' rarity sum is 42 against the 40
		// threshold) and only prefer-no-match flips to Shufti. Verified by
		// direct compile before this was written.
		//
		// Read the Δ% as an UPPER BOUND — see forceScalarFrontend's comment
		// for why 21 buckets inflate the prefilter's share. Absolute fuel
		// here models no real workload.
		name:                "set-shufti-lnm",
		forceScalarFrontend: true,
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
		// same 21-pattern [A-U] set as set-shufti-lnm, but the no-match
		// input is DENSE in the tracked first-byte set instead of sparse —
		// the "rarely matches" assumption LikelyNoMatch bakes into forcing
		// Shufti doesn't hold here. Solid A-U letters with no gaps at all:
		// every SIMD chunk's bitmask is all-1s, so ctz always returns 0 and
		// the skip loop can never advance more than one position per
		// attempt, forcing the scalar membership-check tail on literally
		// EVERY position, on top of the SIMD overhead itself. None of the
		// letters is ever followed by "1:" so nothing matches. That tail is
		// the per-first-byte compare chain whose cost is the reason task 70's
		// Shufti band is capped at 128 rather than 239 — so this is the
		// instrument task 70's step B measures with.
		//
		// Selection forced to scalar for the same reason as its sibling above
		// (task 73).
		//
		// WHAT IT DOES NOT MEASURE (task 74, settled 2026-09-01). This case
		// used to be cited as the guard for `shuftiAdaptive`, the runtime
		// density switch emitSetMatchFnFinalShufti carries — the set port of
		// EmitPrefixScan's DenseCounter/DenseSkipFlag, which alpha-run and
		// word-run guard for the single-pattern path. It cannot be: its axis
		// is the three hint modes, and the switch's verdict
		// (`prefer-no-match && !rare`) is deterministic per set, so BOTH arms
		// of the comparison compile the switch identically. What moves here
		// is Shufti against scalar, and that now reads as a large WIN even on
		// this adversarial input.
		//
		// The switch is nonetheless load-bearing — worth 16-17% of the Shufti
		// body's fuel on exactly this input, against 3-9% overhead where it
		// never fires. Measured by compiling both arms directly, which needs
		// a compiler override rather than a hint:
		// `tools/settest/examples/dense_harm.yaml` plus
		// `settest -force-frontend scalar -adaptive on|off`
		// (`make example-adaptive` there).
		name:                "set-shufti-dense-harm",
		forceScalarFrontend: true,
		setPatterns: []string{
			`A1:[^\n]+`, `B1:[^\n]+`, `C1:[^\n]+`, `D1:[^\n]+`, `E1:[^\n]+`,
			`F1:[^\n]+`, `G1:[^\n]+`, `H1:[^\n]+`, `I1:[^\n]+`, `J1:[^\n]+`,
			`K1:[^\n]+`, `L1:[^\n]+`, `M1:[^\n]+`, `N1:[^\n]+`, `O1:[^\n]+`,
			`P1:[^\n]+`, `Q1:[^\n]+`, `R1:[^\n]+`, `S1:[^\n]+`, `T1:[^\n]+`,
			`U1:[^\n]+`,
		},
		mode:         modeSet,
		notes:        "set with 21 [A-U]-prefixed literals, DENSE no-match data — Shufti-vs-scalar on adversarial input (NOT the shuftiAdaptive guard; see settest)",
		matchInput:   setShuftiDenseHarmInput(true),
		nomatchInput: setShuftiDenseHarmInput(false),
	},
	{
		// NOT a Gap F target, despite its name and its original comment.
		// `(\w+)` is a whole-pattern single capture, so it takes the
		// capture-stripping shortcut and compiles to a **Compiled DFA** —
		// `compile --verbose` reports "no captures; promoted to direct-index
		// dispatch". It never reaches the TDFA capture body, and the DFA it
		// does reach already has the self-loop bulk skip, so any movement
		// here is the shortcut's, not Gap F's. Verified 2026-09-01, also by
		// CompileForced producing byte-identical TDFA and BT modules for it.
		//
		// Kept because it still guards the shortcut. The real Gap F targets
		// are the two cases below.
		name:         "tdfa-bulk-skip-word-class",
		pattern:      `(\w+)`,
		mode:         modeGroups,
		notes:        "whole-pattern single-capture shortcut → Compiled DFA (NOT the TDFA body; see comment)",
		matchInput:   strings.Repeat("aB3_", 2560) + "!",
		nomatchInput: "!" + strings.Repeat("aB3_", 2560),
	},
	{
		// Member self-loop skip, WIN half. Forty patterns behind one shared
		// literal pack into a single SPARSE bucket whose forty accepting body
		// states each self-loop on one byte — the shape the skip exists for,
		// and the only shape in this file that produces one.
		//
		// Without a case here the mechanism is measurable only in setperf,
		// whose baselines are gitignored and whose check is not in `make
		// test`, so nothing on demand would notice it silently ceasing to
		// fire. That is exactly how set-shufti-dense-harm guarded nothing for
		// a month.
		name:         "sparse-member-skip",
		setPatterns:  memberSkipPatterns(40),
		mode:         modeSet,
		notes:        "40 shared-literal patterns with one-byte self-loop tails — member skip win case",
		matchInput:   memberSkipInput(true, true),
		nomatchInput: memberSkipInput(false, true),
	},
	{
		// HARM half: same set, but the input carries no runs for the skip to
		// stride over, so every candidate pays the per-byte member load and
		// gains nothing. A win case alone would show only the flattering side
		// of a trade whose whole design question is how much the other side
		// costs.
		name:         "sparse-member-skip-norun",
		setPatterns:  memberSkipPatterns(40),
		mode:         modeSet,
		notes:        "the same set on run-free input — member skip harm case",
		matchInput:   memberSkipInput(true, false),
		nomatchInput: memberSkipInput(false, false),
	},
	{
		// Gap F target, WIN half. `<([a-z]+)>` is a partial capture, so the
		// shortcut does not apply and it genuinely compiles to TDFA
		// (verified with `compile --verbose`). Its body state self-loops on
		// [a-z] with a uniform set-to-pos tag op, which is the shape a
		// tag-aware bulk skip can collapse.
		//
		// Measured before implementation: TDFA costs 37.81 fuel/byte on this
		// body, of which the plain walk is 33.00 — so tag tracking is only
		// ~13% and the walk is what a skip attacks. The same body with the
		// capture removed drops to 4.88 fuel/byte once the DFA's skip
		// engages, i.e. the skip is worth ~85% of the walk.
		name:         "tdfa-capture-body-long",
		pattern:      `<([a-z]+)>`,
		mode:         modeGroups,
		notes:        "TDFA capture body, 10 KB uniform [a-z] run — Gap F win case",
		matchInput:   "<" + strings.Repeat("a", 10240) + ">",
		nomatchInput: "!" + strings.Repeat("a", 10240),
	},
	{
		// Gap F target, HARM half. Same pattern and engine, but the captured
		// bodies are 3 bytes, far below the 16-byte SIMD chunk — so the skip
		// can never amortise its setup and this is where it costs rather
		// than pays. A win case alone would measure only the flattering
		// side, which is how two cases in this file drifted into measuring
		// nothing at all.
		name:         "tdfa-capture-body-short",
		pattern:      `<([a-z]+)>`,
		mode:         modeGroups,
		notes:        "TDFA capture body, 3-byte run — Gap F harm case (below the SIMD chunk)",
		matchInput:   "<abc>",
		nomatchInput: "!abc>",
	},
	{
		// BT-routed sibling of tdfa-bulk-skip-word-class above:
		// `([^,]+)` is also a whole-pattern single capture, but the
		// inverted class trips hasAmbiguousCaptures and routes
		// to Backtracking instead of TDFA. Same shape (10 KB self-loop
		// run + one-byte offset between match/nomatch inputs) confirms
		// the shortcut's fuel win isn't TDFA-specific — it should
		// eliminate BT's ~40 fuel/byte captureBody re-walk here too.
		name:         "bt-groups-whole-capture-inverted-class",
		pattern:      `([^,]+)`,
		mode:         modeGroups,
		notes:        "BT-routed whole-pattern single capture (inverted class) — BT sibling",
		matchInput:   strings.Repeat("aB3_", 2560) + ",",
		nomatchInput: "," + strings.Repeat("aB3_", 2560),
	},

	// ── LM-0: match-dense cases ──────────────────────
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
		// Today's Shufti self-loop bulk-skip is mid-accept only;
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
		// detectShuftiSelfLoop bails on len(l.prefix)==0 today (the
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
		// constraint checks merge them under neutral, losing the
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
	{
		// Task 68 primary target: the LM-3 shape inside a SET. Each pattern's
		// mandatory literal (`A="`) is split off by the packer, leaving the
		// suffix `[a-z0-9]+"` — a 36-byte NON-mid-accept self-loop, since the
		// body cannot accept until the closing quote arrives.
		//
		// Before task 68 no set could reach that channel at all: a suffix DFA
		// has an empty l.prefix by construction, so detectShuftiSelfLoop's
		// bare-prefix bail refused every bucket body regardless of hint.
		// Long runs (20-50 bytes) so a 16-byte chunk skip is productive.
		name: "set-dense-quoted",
		setPatterns: []string{
			`A="[a-z0-9]+"`, `B="[a-z0-9]+"`, `C="[a-z0-9]+"`, `D="[a-z0-9]+"`,
			`E="[a-z0-9]+"`, `F="[a-z0-9]+"`, `G="[a-z0-9]+"`, `H="[a-z0-9]+"`,
		},
		mode:         modeSet,
		notes:        "8-pattern set, quoted alnum bodies 20-50 bytes — task 68 primary target (non-mid Shufti self-loop in a bucket suffix body)",
		matchInput:   setQuotedInput(true, false),
		nomatchInput: setQuotedInput(false, false),
	},
	{
		// Task 68 harm/hysteresis guard: same set, 3-6-byte bodies. Every
		// bulk-skip attempt advances < 16 bytes, so the task-38 hysteresis
		// should self-disable the channel and hold fuel near neutral. This is
		// the case that decides whether task 68 needs a minimum-length gate
		// of its own (the single-pattern LM-4 precedent) or whether the
		// hysteresis is enough — a suffix DFA has no pattern string to
		// re-parse for a min-length check, so "enough" is the better answer.
		name: "set-dense-quoted-short",
		setPatterns: []string{
			`A="[a-z0-9]+"`, `B="[a-z0-9]+"`, `C="[a-z0-9]+"`, `D="[a-z0-9]+"`,
			`E="[a-z0-9]+"`, `F="[a-z0-9]+"`, `G="[a-z0-9]+"`, `H="[a-z0-9]+"`,
		},
		mode:         modeSet,
		notes:        "same 8-pattern set, bodies 3-6 bytes — task 68 harm/hysteresis guard",
		matchInput:   setQuotedInput(true, true),
		nomatchInput: setQuotedInput(false, true),
	},
	{
		// Task 69 target: a LITERAL-LESS set driving scan_any, which is the
		// only way into the union automaton (compile/set_union_scan.go) —
		// `find` never enters it except through a preflight, so a find-only
		// harness cannot see a union-scan change at all.
		//
		// Every pattern starts with [a-z], so the union automaton's entry
		// state self-loops on the other 230 bytes. The no-match input is
		// SPARSE in [a-z] (digits and punctuation), which is the run-skipping
		// win case; the match input is dense prose, the harm case.
		name: "set-scan-classchain-sparse",
		setPatterns: []string{
			`[a-z]{4}[0-9]{1}`, `[a-z]{4}[0-9]{2}`, `[a-z]{4}[0-9]{3}`,
			`[a-z]{5}[0-9]{1}`, `[a-z]{5}[0-9]{2}`, `[a-z]{5}[0-9]{3}`,
			`[a-z]{6}[0-9]{2}`, `[a-z]{6}[0-9]{3}`,
		},
		mode:         modeSet,
		setCap:       setCapScanAny,
		notes:        "literal-less 8-pattern set, scan_any over the union automaton — task 69 target (entry-state self-loop skip)",
		matchInput:   setClassChainInput(true),
		nomatchInput: setClassChainInput(false),
	},
	{
		// The scan_all twin of the case above. Both walk every byte the same
		// way (our scan_any and scan_all do identical per-byte work — the
		// documented reason the setperf board loses classchain scan_any to
		// regex-automata while winning scan_all), so a union-scan change must
		// move both or neither.
		name: "set-scan-all-classchain-sparse",
		setPatterns: []string{
			`[a-z]{4}[0-9]{1}`, `[a-z]{4}[0-9]{2}`, `[a-z]{4}[0-9]{3}`,
			`[a-z]{5}[0-9]{1}`, `[a-z]{5}[0-9]{2}`, `[a-z]{5}[0-9]{3}`,
			`[a-z]{6}[0-9]{2}`, `[a-z]{6}[0-9]{3}`,
		},
		mode:         modeSet,
		setCap:       setCapScanAll,
		notes:        "same literal-less set driving scan_all — task 69 twin (no early exit until every id is seen)",
		matchInput:   setClassChainInput(true),
		nomatchInput: setClassChainInput(false),
	},
	{
		// Task 70 target: a set whose first-byte union is WIDER than the
		// 17..64 Shufti band, which neutral mode therefore leaves on the
		// scalar per-position walk.
		//
		// Reaching it takes all three of: enough long literals that the
		// Aho-Corasick table blows its 512 KB budget (the only route from a
		// literal set to frontendScalar), 65+ distinct first bytes, and no
		// fallback bucket. 80 patterns over a 79-byte alphabet does it.
		//
		// The no-match input is built from bytes OUTSIDE the union — the
		// "impossible bytes" workload LNM.md's Action 5 was written for, and
		// the only shape where a 79-byte prefilter can skip anything. The
		// match input is dense in the union, where it cannot.
		name:         "set-wide-union-shufti",
		setPatterns:  wideUnionSetPatterns(80),
		mode:         modeSet,
		notes:        "80 long literals, 79 distinct first bytes — task 70 target (Shufti band widened past 64 under LNM)",
		matchInput:   wideUnionInput(true),
		nomatchInput: wideUnionInput(false),
	},
}

// wideUnionAlphabet is the 79 bytes the task-70 case's literals start with:
// every alphanumeric plus the punctuation that needs no regexp escaping. Its
// COMPLEMENT is what the no-match input is built from, so the two must be
// derived from one place.
const wideUnionAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
	"_~!@#%&=:;,<>/'\"`"

// wideUnionSetPatterns builds n literals long enough to push the AC table over
// its budget, each starting with a distinct byte of wideUnionAlphabet.
func wideUnionSetPatterns(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		body := ""
		for j := 0; j < 24; j++ {
			body += string(rune('a' + (i/len(wideUnionAlphabet)+j)%26))
		}
		out = append(out, fmt.Sprintf("%s%s%04d[0-9]+", string(wideUnionAlphabet[i%len(wideUnionAlphabet)]), body, i))
	}
	return out
}

// wideUnionInput builds ~50 KB for the task-70 case.
//
// The no-match half uses ONLY bytes outside wideUnionAlphabet, which is what
// makes it the case a wide prefilter can serve at all; anything else and a
// 79-byte union finds a candidate in nearly every 16-byte chunk. The match
// half is dense in the alphabet and carries real needles.
func wideUnionInput(withMatches bool) string {
	const targetSize = 50 * 1024
	var b []byte
	if !withMatches {
		var outside []byte
		for c := 0; c < 256; c++ {
			if !strings.ContainsRune(wideUnionAlphabet, rune(c)) && c != 0 {
				outside = append(outside, byte(c))
			}
		}
		for i := 0; len(b) < targetSize; i++ {
			b = append(b, outside[i%len(outside)])
		}
		return string(b[:targetSize])
	}
	pats := wideUnionSetPatterns(80)
	for i := 0; len(b) < targetSize; i++ {
		// The literal prefix of pattern i, then a digit run to complete it.
		lit := pats[i%len(pats)]
		lit = lit[:len(lit)-len("[0-9]+")]
		b = append(b, lit...)
		b = append(b, "123 "...)
	}
	return string(b[:targetSize])
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
// memberSkipPatterns builds the shared-literal family the member self-loop
// skip serves: one mandatory literal so they pack into a single bucket, a
// per-pattern discriminator so they stay distinct, and a one-byte `a+` tail
// that becomes an accepting state self-looping on exactly one byte.
func memberSkipPatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`union[ \t]+k%02da+`, i)
	}
	return out
}

// memberSkipInput builds ~50 KB for the two member-skip cases.
//
// withRuns=true gives each needle a 64-byte `a` run — the stride the skip
// collapses. withRuns=false caps the run at one byte, so the same literal
// hits happen and the same buckets are entered, but there is nothing to
// stride over: that isolates the skip's COST from its benefit, which is the
// half both previous attempts at this optimisation failed to price.
func memberSkipInput(withMatches, withRuns bool) string {
	const targetSize = 50 * 1024
	run := 1
	if withRuns {
		run = 64
	}
	filler := "..... filler ..... "
	var b []byte
	for i := 0; len(b) < targetSize; i++ {
		b = append(b, filler...)
		if withMatches {
			b = append(b, fmt.Sprintf("union k%02d", i%40)...)
			b = append(b, strings.Repeat("a", run)...)
			b = append(b, ' ')
			continue
		}
		// No-match: the literal is absent, so the frontend never fires and
		// the suffix body is never entered.
		b = append(b, "onion k00"...)
		b = append(b, strings.Repeat("a", run)...)
		b = append(b, ' ')
	}
	return string(b[:targetSize])
}

// printableRunInput builds ~50 KB for the 94-byte-first-set cases.
//
// `[!-~]` is every printable ASCII byte EXCEPT space, which is what makes the
// two halves separable: whitespace is outside the class, so a
// whitespace-dominated buffer is genuinely SPARSE in the tracked first bytes
// while still being ordinary-looking input.
//
// dense=false is the win case — long whitespace runs the SIMD prefilter can
// stride over. dense=true is the harm case: printable bytes everywhere, so
// every chunk finds a candidate immediately and the nibble-table work is pure
// overhead. Runs are capped at 11 bytes there, one short of the pattern's
// {12,}, so the buffer stays dense without ever matching.
func printableRunInput(withMatches, dense bool) string {
	const targetSize = 50 * 1024
	// A deterministic, dependency-free byte source: the cases must produce the
	// same buffer on every run or the baseline means nothing.
	next := uint32(2463534242)
	rnd := func(n int) int {
		next ^= next << 13
		next ^= next >> 17
		next ^= next << 5
		return int(next % uint32(n))
	}
	printable := make([]byte, 0, 94)
	for c := byte('!'); c <= '~'; c++ {
		printable = append(printable, c)
	}
	gap := []byte(" \t \t\t   ")

	var b []byte
	emitFiller := func() {
		if dense {
			// 4..11 printable bytes, then one space. Dense in the class,
			// never long enough to match.
			n := 4 + rnd(8)
			for i := 0; i < n; i++ {
				b = append(b, printable[rnd(len(printable))])
			}
			b = append(b, ' ')
			return
		}
		b = append(b, gap...)
	}
	for i := 0; len(b) < targetSize; i++ {
		emitFiller()
		if withMatches && i%64 == 0 {
			for j := 0; j < 16; j++ {
				b = append(b, printable[rnd(len(printable))])
			}
			b = append(b, ' ')
		}
	}
	return string(b[:targetSize])
}

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
// `[0-9]{16}INFO:[^\n]+`: 2 long matches, each with a full
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
// `[0-9]{16}INFO:[^\n]+`. Scatters "INFO:" occurrences through
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

// minLenQuantifierSkipInput builds inputs for the min-length quantifier-skip
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

// setShuftiDenseHarmInput builds ~50 KB for the set-shufti-dense-harm
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

// setQuotedInput builds ~50 KB for the set-dense-quoted / -short cases: an
// 8-pattern set of `<K>="[a-z0-9]+"`. Each token is prefixed with one of the
// set's literals so the frontend produces a real candidate, and the body
// length selects the win case (20-50 bytes, several SIMD chunks per run) or
// the harm case (3-6 bytes, every attempt advancing < 16).
//
// The no-match input carries the literals' first bytes but never the `="`
// that completes them, so the frontend still does its work and the suffix
// bodies still run — a no-match input with no candidate at all would measure
// the frontend alone and say nothing about the suffix channel this targets.
func setQuotedInput(withMatches, short bool) string {
	const targetSize = 50 * 1024
	keys := "ABCDEFGH"
	alnum := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	minLen, maxLen := 20, 50
	if short {
		minLen, maxLen = 3, 6
	}
	var b []byte
	runLen := minLen
	for i := 0; len(b) < targetSize; i++ {
		b = append(b, keys[i%len(keys)])
		if withMatches {
			b = append(b, '=', '"')
		} else {
			// Same first byte, no `="`: a frontend candidate that dies at the
			// second byte of the literal.
			b = append(b, '-', ' ')
		}
		for j := 0; j < runLen; j++ {
			b = append(b, alnum[j%len(alnum)])
		}
		if withMatches {
			b = append(b, '"')
		}
		b = append(b, ' ')
		runLen++
		if runLen > maxLen {
			runLen = minLen
		}
	}
	return string(b[:targetSize])
}

// setClassChainInput builds ~50 KB for the literal-less scan cases.
//
// The two inputs differ in the axis task 69 turns on, not just in whether
// they match: the no-match input is SPARSE in [a-z] (the byte class every
// pattern starts with), so the union automaton's entry state sits in a long
// self-loop run that a SIMD skip can stride over. The match input is dense
// lowercase prose carrying real needles, where the same skip finds an exit in
// nearly every chunk — the harm side the adaptive switch has to bound.
func setClassChainInput(withMatches bool) string {
	const targetSize = 50 * 1024
	var b []byte
	if !withMatches {
		filler := []byte("0123456789 ,.;:!?()[]{}<>/@#$%^&*-_=+|~ 9876543210 ")
		for len(b) < targetSize {
			b = append(b, filler...)
		}
		return string(b[:targetSize])
	}
	words := []string{
		"the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
	}
	for i := 0; len(b) < targetSize; i++ {
		if i%17 == 0 {
			// A real needle: six lowercase, a digit in 0..7, three digits.
			b = append(b, "abcdef"...)
			b = append(b, byte('0'+i%8))
			b = append(b, "123"...)
		} else {
			b = append(b, words[i%len(words)]...)
		}
		b = append(b, ' ')
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
	// measurement noise (see an earlier task investigation: identical wasm
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
// LikelyMode and returns standalone WASM exporting the set `find`. The mode is
// applied via the set's own `hints:` field — the set's resolveHints(sc.Hints)
// call is what actually consumes it (H.3 frontend density gate); none of
// these entries carry their own _func fields, so there is no per-pattern
// fallback to plumb.
func compileSetMode(tc testCase, mode compile.LikelyMode) ([]byte, error) {
	entries := make([]config.RegexEntry, len(tc.setPatterns))
	for i, p := range tc.setPatterns {
		entries[i] = config.RegexEntry{Pattern: p}
	}
	sc := config.SetConfig{
		Name:     "bench_set",
		Patterns: config.PatternSelector{All: true},
		Hints:    hintsYAML(mode),
	}
	// Exactly ONE capability per case, on purpose: the compiler emits only the
	// machinery the declared capabilities need, so a set that also declared
	// `find` would carry a literal frontend the scan measurement is not
	// driving — and the module-size column would report the union of both.
	switch tc.setCap {
	case setCapScanAny:
		sc.ScanAny = "set_scan_any"
	case setCapScanAll:
		sc.ScanAll = "set_scan_all"
	default:
		sc.Find = "set_find"
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets:    []config.SetConfig{sc},
	}
	// Output empty → standalone.
	if tc.forceScalarFrontend {
		// CompileFileOpts reads only ACBudgetBytes/ForceFrontend off the
		// override, so an otherwise-zero value is CompileFile plus the pin.
		opts := compile.CompileSetOptions{}.WithForcedFrontend(compile.SetFrontendScalar)
		wasm, _, _, err := compile.CompileFileOpts(cfg, "", opts)
		return wasm, err
	}
	wasm, _, err := compile.CompileFile(cfg, "")
	return wasm, err
}

// hintsYAML maps the compile.LikelyMode enum back to its YAML `hints:` list
// form so compileSetMode can stuff it into a SetConfig field. Nil ⇒
// caller-side neutral default.
func hintsYAML(m compile.LikelyMode) []string {
	switch m {
	case compile.LikelyMatch:
		return []string{"prefer-match"}
	case compile.LikelyNoMatch:
		return []string{"prefer-no-match"}
	}
	return nil
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
			wcall(benchFn, store, inputBase, inputLen, slotsBase, int32(benchIters)) //nolint:errcheck
		} else {
			wcall(benchFn, store, inputBase, inputLen, int32(benchIters)) //nolint:errcheck
		}
	}

	var benchErr error
	if tc.mode == modeGroups {
		_, benchErr = wcall(benchFn, store, inputBase, inputLen, slotsBase, int32(benchIters))
	} else {
		_, benchErr = wcall(benchFn, store, inputBase, inputLen, int32(benchIters))
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
	switch tc.mode {
	case modeGroups:
		_, callErr = wcall(fn, store, inputBase, inputLen, slotsBase, int32(0))
	case modeFind:
		// find is (ptr, len, from); a one-shot find starts at 0.
		_, callErr = wcall(fn, store, inputBase, inputLen, int32(0))
	default:
		_, callErr = wcall(fn, store, inputBase, inputLen)
	}
	if callErr != nil {
		return 0, callErr
	}
	after, _ := store.GetFuel()
	return before - after, nil
}

// findExhaustIterTime is the timing-sample count for exhaustive find/groups
// measurement. Lower than setIterTime (1000): a dense
// find/groups pass can visit far more matches per pass than the set cases
// do (e.g. dense-words-grouped's ~8k words), so fewer reps keeps wall-clock
// reasonable while still giving a stable p50.
const findExhaustIterTime = 200

// runFindExhaust drives a single-pattern find() export to exhaustion over
// inputLen bytes at inputBase, mirroring the host stubs' iteration loop
// (generate/js_stub.go genJSFindFunc): re-call with the whole buffer and a
// rising start position, advancing past each match (or by 1 for a zero-length
// match) until no match or EOF.
func runFindExhaust(store *wasmtime.Store, fn *wasmtime.Func, inputLen int32) {
	off := int32(0)
	for off <= inputLen {
		r, err := wcall(fn, store, inputBase, inputLen, off)
		if err != nil {
			return
		}
		packed := r.(int64)
		if packed < 0 {
			return
		}
		// ABSOLUTE, not relative. the export takes the whole
		// buffer plus a start position, and the packed halves are positions in
		// that buffer — so the advance is an ASSIGNMENT, not an increment.
		// `off += absEnd` roughly DOUBLED off every iteration, so a
		// match-dense 50 KB input "exhausted" in ~17 calls instead of ~8000
		// and every exhaustive find row measured a logarithmic sliver of the
		// drive. checkFindExhaust has always converted correctly, which is why
		// the correctness gate could not see it.
		absStart := int32(packed >> 32)
		absEnd := int32(packed & 0xFFFFFFFF)
		if absEnd > absStart {
			off = absEnd
		} else {
			off = absStart + 1
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
		r, err := wcall(fn, store, inputBase, inputLen, slotsPtr, off)
		if err != nil {
			return
		}
		if r.(int32) < 0 {
			return
		}
		buf := mem.UnsafeData(store)
		// Slots are ABSOLUTE now: the whole buffer is passed and `off` only
		// bounds where the search starts.
		absStart := int32(buf[slotsPtr]) | int32(buf[slotsPtr+1])<<8 | int32(buf[slotsPtr+2])<<16 | int32(buf[slotsPtr+3])<<24
		absEnd := int32(buf[slotsPtr+4]) | int32(buf[slotsPtr+5])<<8 | int32(buf[slotsPtr+6])<<16 | int32(buf[slotsPtr+7])<<24
		runtime.KeepAlive(store)
		if absEnd > absStart {
			off = absEnd
		} else {
			off = absStart + 1
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
		t, err := benchTimeSet(tc, wasm, input, engine)
		if err != nil {
			return cell{}, fmt.Errorf("bench time %s: %w", mode, err)
		}
		f, err := benchFuelSet(tc, wasm, input, fuelEngine)
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

// --------------------------------------------------------------------------
// Correctness checking against Go stdlib regexp
//
// likelytest's corpus is hand-picked to stress specific compiler
// optimisation gates, not for correctness — that's tools/re2test's job, run
// over millions of RE2-corpus patterns. But a LikelyMode-specific
// correctness bug can hide in exactly this corpus's blind spot: a "good"
// fuel/time number looks identical whether the compiled WASM took a
// legitimately cheaper path or is silently returning the wrong answer
// (a past defect’s gap-e-groups case is exactly this — a false
// negative that went unnoticed here because nothing checked the return
// value, only its cost). So every (pattern, mode, input) combination that
// gets a fuel/time number here also gets checked against Go's regexp
// package first — same RE2/Perl leftmost-first semantics as this project's
// own engines (CLAUDE.md "Design Principles"), and the same ground-truth
// source tools/re2test uses for its own --validate-go checks.
//
// modeSet is intentionally not checked here: tools/re2test's own --sets
// mode already exhaustively validates set-composition correctness, and
// decoding the set `find`'s per-pattern tuple output against the right member
// of a multi-pattern set is a different, more involved job than the
// single-pattern checks below. Only 3 of this suite's cases use modeSet.

// newPlainInstance instantiates wasmBytes on a fuel-free store and returns
// its exported memory, ready for a single correctness call.
func newPlainInstance(engine *wasmtime.Engine, wasmBytes []byte) (*wasmtime.Store, *wasmtime.Instance, *wasmtime.Memory, error) {
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("module: %w", err)
	}
	store := wasmtime.NewStore(engine)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("instance: %w", err)
	}
	mem := inst.GetExport(store, "memory").Memory()
	if mem == nil {
		return nil, nil, nil, fmt.Errorf("missing memory export")
	}
	return store, inst, mem, nil
}

func readSlots(buf []byte, base int32, totalGroups int) []int {
	slots := make([]int, totalGroups*2)
	for i := range slots {
		off := int(base) + i*4
		v := int32(buf[off]) | int32(buf[off+1])<<8 | int32(buf[off+2])<<16 | int32(buf[off+3])<<24
		slots[i] = int(v)
	}
	return slots
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalPairs(a, b [][2]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalSlotSets(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalIntSlices(a[i], b[i]) {
			return false
		}
	}
	return true
}

func fmtPacked(v int64) string {
	if v < 0 {
		return "no-match"
	}
	return fmt.Sprintf("[%d,%d)", int32(v>>32), int32(v&0xFFFFFFFF))
}

// expectedMatch is the ground truth for a match_func call: buildMatchBody
// (compile/engine_dfa.go) requires the WHOLE input to be consumed starting
// at position 0 ("Bounds: anchored match must consume the entire input —
// len != total → -1"), not just a leftmost-first prefix match. Mirrors
// tools/re2test's own --validate-go col0 check.
func expectedMatch(re *regexp.Regexp, input string) int32 {
	loc := re.FindStringIndex(input)
	if loc != nil && loc[0] == 0 && loc[1] == len(input) {
		return int32(loc[1])
	}
	return -1
}

// checkMatch calls match() once and compares it against expectedMatch.
func checkMatch(engine *wasmtime.Engine, wasmBytes []byte, input string, re *regexp.Regexp) error {
	store, inst, mem, err := newPlainInstance(engine, wasmBytes)
	if err != nil {
		return err
	}
	fn := inst.GetExport(store, "match").Func()
	if fn == nil {
		return fmt.Errorf("missing match export")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	r, err := wcall(fn, store, inputBase, int32(len(input)))
	if err != nil {
		return fmt.Errorf("call: %w", err)
	}
	got := r.(int32)
	runtime.KeepAlive(store)
	if want := expectedMatch(re, input); got != want {
		return fmt.Errorf("match(%q) = %d, want %d", input, got, want)
	}
	return nil
}

// expectedFind is the ground truth for a single find_func call: plain
// leftmost-first search, no anchoring requirement — mirrors tools/re2test's
// col1 check. Packed as (start<<32|end), matching find_func's own return
// convention (see runFindExhaust's unpacking).
func expectedFind(re *regexp.Regexp, input string) int64 {
	loc := re.FindStringIndex(input)
	if loc == nil {
		return -1
	}
	return int64(loc[0])<<32 | int64(uint32(loc[1]))
}

func checkFind(engine *wasmtime.Engine, wasmBytes []byte, input string, re *regexp.Regexp) error {
	store, inst, mem, err := newPlainInstance(engine, wasmBytes)
	if err != nil {
		return err
	}
	fn := inst.GetExport(store, "find").Func()
	if fn == nil {
		return fmt.Errorf("missing find export")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	r, err := wcall(fn, store, inputBase, int32(len(input)), int32(0))
	if err != nil {
		return fmt.Errorf("call: %w", err)
	}
	got := r.(int64)
	runtime.KeepAlive(store)
	if want := expectedFind(re, input); got != want {
		return fmt.Errorf("find(%q) = %s, want %s", input, fmtPacked(got), fmtPacked(want))
	}
	return nil
}

// expectedFindAll mirrors runFindExhaust's exact advance rule (advance past
// a non-empty match's end, or past a zero-length match's start+1) so a
// mismatch here reflects a real product bug, not a harness assumption gap.
//
// It also applies Go's FindAllIndex suppression rule — an EMPTY match
// beginning exactly where the previous reported match ended is not reported —
// because the emitters do. This harness re-implements
// the iteration rather than driving a stub, so the rule has to be here too, or
// it disagrees with the product and blames the engine.
func expectedFindAll(re *regexp.Regexp, input string) [][2]int {
	var all [][2]int
	off := 0
	prevEnd := -1
	for off <= len(input) {
		m := re.FindStringIndex(input[off:])
		if m == nil {
			break
		}
		s, e := m[0]+off, m[1]+off
		if !(s == e && s == prevEnd) {
			all = append(all, [2]int{s, e})
			prevEnd = e
		}
		if e > s {
			off = e
		} else {
			off = s + 1
		}
	}
	return all
}

func checkFindExhaust(engine *wasmtime.Engine, wasmBytes []byte, input string, re *regexp.Regexp) error {
	store, inst, mem, err := newPlainInstance(engine, wasmBytes)
	if err != nil {
		return err
	}
	fn := inst.GetExport(store, "find").Func()
	if fn == nil {
		return fmt.Errorf("missing find export")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	var got [][2]int
	off := int32(0)
	for off <= inputLen {
		// Whole buffer plus a start position; positions come back absolute.
		r, err := wcall(fn, store, inputBase, inputLen, off)
		if err != nil {
			return fmt.Errorf("call at off=%d: %w", off, err)
		}
		packed := r.(int64)
		if packed < 0 {
			break
		}
		absStart := int32(packed >> 32)
		absEnd := int32(packed & 0xFFFFFFFF)
		relStart, relEnd := absStart-off, absEnd-off
		got = append(got, [2]int{int(absStart), int(absEnd)})
		if relEnd > relStart {
			off += relEnd
		} else {
			off += relStart + 1
		}
	}
	runtime.KeepAlive(store)
	if want := expectedFindAll(re, input); !equalPairs(got, want) {
		return fmt.Errorf("find-exhaust(%d bytes) = %v, want %v", len(input), got, want)
	}
	return nil
}

// expectedGroups is the ground truth for a single groups_func call. The
// composition documented at compile.go's "Capture path" comment performs an
// internal find (not a strict anchored-at-ptr check) for any shape that
// doesn't hit the native lit-chain fast path — confirmed empirically for
// a past defect’s gap-e-groups repro, where a ptr=0 call over a 10KB
// buffer found a match starting mid-buffer. Mirrors tools/re2test's col5
// check: plain FindStringSubmatchIndex, no anchoring requirement.
func expectedGroups(re *regexp.Regexp, input string) []int {
	return re.FindStringSubmatchIndex(input)
}

func checkGroups(engine *wasmtime.Engine, wasmBytes []byte, input string, re *regexp.Regexp) error {
	totalGroups := re.NumSubexp() + 1
	store, inst, mem, err := newPlainInstance(engine, wasmBytes)
	if err != nil {
		return err
	}
	fn := inst.GetExport(store, "groups").Func()
	if fn == nil {
		return fmt.Errorf("missing groups export")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	for i := 0; i < totalGroups*2*4; i++ {
		buf[int(slotsBase)+i] = 0xFF // pre-init to -1, matching re2test's callGroups
	}
	r, err := wcall(fn, store, inputBase, int32(len(input)), slotsBase, int32(0))
	if err != nil {
		return fmt.Errorf("call: %w", err)
	}
	got := r.(int32)
	buf = mem.UnsafeData(store)
	slots := readSlots(buf, slotsBase, totalGroups)
	runtime.KeepAlive(store)

	want := expectedGroups(re, input)
	if want == nil {
		if got != -1 {
			return fmt.Errorf("groups(%q) = %d (slots %v), want no match", input, got, slots)
		}
		return nil
	}
	if got != int32(want[1]) {
		return fmt.Errorf("groups(%q) end = %d, want %d", input, got, want[1])
	}
	if !equalIntSlices(slots, want) {
		return fmt.Errorf("groups(%q) slots = %v, want %v", input, slots, want)
	}
	return nil
}

// expectedGroupsAll mirrors runGroupsExhaust's exact advance rule, on the
// the ABSOLUTE positions the export reports: advance to the match end,
// or one past the start when the match is empty.
//
// It used to model the pre-task-54 relative rule (advance by slots[1], off++
// when that is zero) and shift the oracle's own spans by `off` — both of which
// are now wrong twice over, since the export is handed the whole buffer and
// returns positions in it.
func expectedGroupsAll(re *regexp.Regexp, input string) [][]int {
	var all [][]int
	off := 0
	for off <= len(input) {
		sub := re.FindStringSubmatchIndex(input[off:])
		if sub == nil {
			break
		}
		shifted := make([]int, len(sub))
		for i, v := range sub {
			if v < 0 {
				shifted[i] = -1
			} else {
				shifted[i] = v + off
			}
		}
		all = append(all, shifted)
		if absStart, absEnd := shifted[0], shifted[1]; absEnd > absStart {
			off = absEnd
		} else {
			off = absStart + 1
		}
	}
	return all
}

func checkGroupsExhaust(engine *wasmtime.Engine, wasmBytes []byte, input string, re *regexp.Regexp) error {
	totalGroups := re.NumSubexp() + 1
	store, inst, mem, err := newPlainInstance(engine, wasmBytes)
	if err != nil {
		return err
	}
	fn := inst.GetExport(store, "groups").Func()
	if fn == nil {
		return fmt.Errorf("missing groups export")
	}
	buf := mem.UnsafeData(store)
	copy(buf[inputBase:], []byte(input))
	inputLen := int32(len(input))

	var got [][]int
	off := int32(0)
	for off <= inputLen {
		buf = mem.UnsafeData(store)
		for i := 0; i < totalGroups*2*4; i++ {
			buf[int(slotsBase)+i] = 0xFF
		}
		// FOUR arguments, and the WHOLE buffer: the groups export has taken
		// (ptr, len, out_ptr, from) The three-argument
		// shrinking-window call this replaced was an ARITY error wasmtime
		// rejected outright, so the exhaustive modeGroups case failed and the
		// run exited non-zero.
		r, err := wcall(fn, store, inputBase, inputLen, slotsBase, off)
		if err != nil {
			return fmt.Errorf("call at off=%d: %w", off, err)
		}
		if r.(int32) < 0 {
			break
		}
		buf = mem.UnsafeData(store)
		slots := readSlots(buf, slotsBase, totalGroups)
		// Slots are ABSOLUTE: no +off shift, only the -1 mapping for a group
		// that did not participate.
		abs := make([]int, len(slots))
		for i, v := range slots {
			if v < 0 {
				abs[i] = -1
			} else {
				abs[i] = v
			}
		}
		got = append(got, abs)
		if absStart, absEnd := abs[0], abs[1]; absEnd > absStart {
			off = int32(absEnd)
		} else {
			off = int32(absStart) + 1
		}
	}
	runtime.KeepAlive(store)
	if want := expectedGroupsAll(re, input); !equalSlotSets(got, want) {
		return fmt.Errorf("groups-exhaust(%d bytes) = %v, want %v", len(input), got, want)
	}
	return nil
}

// checkCorrectness validates one (tc, wasm, input) combination against Go
// stdlib regexp, dispatching on tc.mode/tc.exhaustive exactly the way
// measureWasm dispatches for performance measurement — every combination
// that gets a fuel/time number also gets a correctness check using the
// identical call convention. modeSet is not checked here (see the package
// comment above this section).
func checkCorrectness(tc testCase, wasm []byte, input string, re *regexp.Regexp, engine *wasmtime.Engine) error {
	switch tc.mode {
	case modeAnchored:
		return checkMatch(engine, wasm, input, re)
	case modeFind:
		if tc.exhaustive {
			return checkFindExhaust(engine, wasm, input, re)
		}
		return checkFind(engine, wasm, input, re)
	case modeGroups:
		if tc.exhaustive {
			return checkGroupsExhaust(engine, wasm, input, re)
		}
		return checkGroups(engine, wasm, input, re)
	}
	return nil
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

// setDriver resolves the export a modeSet case drives and returns a closure
// that performs ONE unit of work — a full `find` exhaustion, or a single scan
// call over the whole input.
//
// Both bench paths (time and fuel) go through this so they can never end up
// measuring different work for the same case, which is the failure a second
// hand-written export lookup invites.
//
// The closure reports the call error rather than swallowing it: a trap or a
// watchdog timeout must abort the case, not be published as a timing and fuel
// figure for work that never finished.
func setDriver(tc testCase, store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, plan setMemPlan, inputLen int32) (func() error, error) {
	switch tc.setCap {
	case setCapScanAny, setCapScanAll:
		name := "set_" + tc.setCap
		fn := inst.GetFunc(store, name)
		if fn == nil {
			return nil, fmt.Errorf("missing export %q", name)
		}
		// The scan pair takes (ptr, len, offset) and reports no position:
		// one call consumes the whole input, so there is nothing to exhaust.
		//
		// scan_all's i64-bitmask return is assumed, which holds while a case
		// stays at or below 64 patterns; past that the ABI changes to an
		// out_ptr bitmap and this call would be wrong. Enforced in main's
		// case validation rather than here, where a per-iteration check would
		// be measured.
		return func() error {
			_, err := wcall(fn, store, plan.inputBase, inputLen, int32(0))
			return err
		}, nil
	default:
		fn := inst.GetFunc(store, "set_find")
		if fn == nil {
			return nil, fmt.Errorf("missing export %q", "set_find")
		}
		return func() error {
			return runSetExhaust(store, fn, mem, plan, inputLen)
		}, nil
	}
}

// benchTimeSet times the cost of one full set capability pass over `input`
// (a `find` exhaustion, or one scan call) and returns the p50 over
// setIterTime samples.
func benchTimeSet(tc testCase, wasmBytes []byte, input string, engine *wasmtime.Engine) (time.Duration, error) {
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
	if mem == nil {
		return 0, fmt.Errorf("missing exports")
	}
	if err := writeSetInput(store, mem, plan, input); err != nil {
		return 0, err
	}
	drive, err := setDriver(tc, store, inst, mem, plan, int32(len(input)))
	if err != nil {
		return 0, err
	}

	timings := make([]time.Duration, setIterTime)
	// One arm for the whole series, not one per call: unlike every other bench
	// here, a modeSet pass is driven from the HOST, so wcall's per-call arming
	// would land inside each sample. See watchedSeries.
	if err := watchedSeries(store, func() error {
		// Warmup: a few passes.
		for warmupEnd := time.Now().Add(50 * time.Millisecond); time.Now().Before(warmupEnd); {
			if err := drive(); err != nil {
				return err
			}
		}
		for i := range timings {
			t0 := time.Now()
			err := drive()
			timings[i] = time.Since(t0)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, err
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

// benchFuelSet measures fuel for one full set capability pass (see setDriver).
func benchFuelSet(tc testCase, wasmBytes []byte, input string, fuelEngine *wasmtime.Engine) (uint64, error) {
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
	if mem == nil {
		return 0, fmt.Errorf("missing exports")
	}
	if err := writeSetInput(store, mem, plan, input); err != nil {
		return 0, err
	}
	drive, err := setDriver(tc, store, inst, mem, plan, int32(len(input)))
	if err != nil {
		return 0, err
	}
	before, _ := store.GetFuel()
	if err := drive(); err != nil {
		return 0, err
	}
	after, _ := store.GetFuel()
	return before - after, nil
}

func writeSetInput(store *wasmtime.Store, mem *wasmtime.Memory, plan setMemPlan, input string) error {
	const pageSize = 65536
	// Tuples, then the gate array, both above outputBase.
	needTop := uint64(plan.outputBase) + uint64(setOutCap)*16 + 4096
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

// runSetExhaust drives the set `find` export to exhaustion, the way a
// generated iterator does: zero the gate array, then call
//
//	find(ptr, len, from, gate_ptr, out_ptr, out_cap) -> total at that position
//
// advancing `from` to start+1 each time. Every tuple in one call shares a
// start, so reading the first tuple is enough to resume.
func runSetExhaust(store *wasmtime.Store, findFn *wasmtime.Func, mem *wasmtime.Memory, plan setMemPlan, inputLen int32) error {
	gatePtr := plan.outputBase + setOutCap*12
	buf := mem.UnsafeData(store)
	for i := int32(0); i < setOutCap*4; i++ {
		buf[gatePtr+i] = 0
	}
	runtime.KeepAlive(store)
	from := int32(0)
	for {
		n, err := wcall(findFn, store, plan.inputBase, inputLen, from, gatePtr, plan.outputBase, setOutCap)
		if err != nil {
			return err
		}
		count := n.(int32)
		if count <= 0 {
			return nil
		}
		buf := mem.UnsafeData(store)
		base := int(plan.outputBase)
		s := int32(buf[base+4]) | int32(buf[base+5])<<8 | int32(buf[base+6])<<16 | int32(buf[base+7])<<24
		// See benchTime's comment on the same pattern: buf is a raw pointer
		// into wasmtime's native memory, not a Go reference to store.
		runtime.KeepAlive(store)
		from = s + 1
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
			// an earlier task investigation: identical wasm still showed
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
	setsOnly := flag.Bool("sets", false, "run only the set-composition cases (mode == modeSet)")
	flag.Parse()

	// Silence regexped's slog output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	engine := newWatchedEngine(nil)
	warmup(engine)

	fuelCfg := wasmtime.NewConfig()
	fuelCfg.SetConsumeFuel(true)
	fuelEngine := newWatchedEngine(fuelCfg)

	modes := [3]compile.LikelyMode{compile.LikelyNeutral, compile.LikelyMatch, compile.LikelyNoMatch}

	fmt.Println("likelytest — LikelyMode 3x3 matrix (p50 over 10k inner iterations per cell)")

	// Case-table validation, before any measurement: a case that measures the
	// wrong thing is worse than one that refuses to run (the same rule
	// setperf's sampleNeedles default arm now enforces, after three incidents
	// shared that one cause).
	for _, tc := range tests {
		if tc.mode != modeSet && tc.setCap != setCapFind {
			fmt.Fprintf(os.Stderr, "case %q: setCap is meaningful only for modeSet\n", tc.name)
			os.Exit(1)
		}
		// scan_all returns an i64 bitmask only while the id space fits 64;
		// above that the ABI takes an out_ptr and writes a bitmap, and
		// setDriver's three-argument call would be wrong. Refuse rather than
		// silently measure a trap.
		if tc.setCap == setCapScanAll && len(tc.setPatterns) > 64 {
			fmt.Fprintf(os.Stderr, "case %q: scan_all with %d patterns exceeds the i64-bitmask ABI setDriver calls\n",
				tc.name, len(tc.setPatterns))
			os.Exit(1)
		}
	}

	filter := os.Getenv("LIKELYTEST_FILTER")
	totalChecks, totalFailures := 0, 0
	for _, tc := range tests {
		// -sets selects on the case's mode, not on its name: a modeSet case
		// is free to be named for the shape it measures (dense-set-shared-prefix)
		// rather than carrying a "set-" prefix for the filter's benefit.
		if *setsOnly && tc.mode != modeSet {
			continue
		}
		if filter != "" && !strings.Contains(tc.name, filter) {
			continue
		}
		wcallCase = tc.name
		fmt.Fprintf(os.Stderr, "==> %s\n", tc.name)

		// Ground truth for the correctness checks below. modeSet isn't
		// checked here (see the "Correctness checking" section's package
		// comment), and a handful of patterns may use RE2-only syntax Go's
		// regexp package rejects — skip validation for those rather than
		// failing the whole run, matching tools/re2test's --validate-go
		// guard for the same situation.
		var re *regexp.Regexp
		if tc.mode != modeSet {
			var reErr error
			re, reErr = regexp.Compile(tc.pattern)
			if reErr != nil {
				fmt.Fprintf(os.Stderr, "  correctness: pattern rejected by Go stdlib, skipping validation: %v\n", reErr)
			}
		}

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
			// Identical-WASM gate: if this
			// mode compiled to byte-identical wasm to neutral, the compiler
			// ignored the LikelyMode hint for this pattern entirely — any
			// wall-time delta we'd measure is guaranteed noise, not signal.
			// Skip benchmarking, reuse nothing (deliberately re-derive size
			// from this mode's own wasm rather than assuming it), and mark
			// both rows so printMatrix shows a message instead of numbers.
			// Correctness is skipped too: byte-identical WASM to an
			// already-checked neutral build can't behave differently.
			if i > 0 && bytes.Equal(wasm, neutralWasm) {
				rowsMatch[i] = cell{size: len(wasm), identical: true}
				rowsNoMatch[i] = cell{size: len(wasm), identical: true}
				continue
			}
			if re != nil {
				for _, in := range [2]struct {
					label, input string
				}{{"match-input", tc.matchInput}, {"no-match-input", tc.nomatchInput}} {
					totalChecks++
					if cErr := checkCorrectness(tc, wasm, in.input, re, engine); cErr != nil {
						totalFailures++
						fmt.Fprintf(os.Stderr, "  CORRECTNESS FAIL [%s/%s]: %v\n", m, in.label, cErr)
					}
				}
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
	fmt.Fprintf(os.Stderr, "correctness: %d checks, %d failures\n", totalChecks, totalFailures)
	if totalFailures > 0 {
		os.Exit(1)
	}
}
