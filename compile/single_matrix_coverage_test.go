package compile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// A companion to set_matrix_coverage_test.go for the SINGLE-PATTERN emitters,
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
			name: "groups-backtrack-inverted", selects: "Backtracking via hasAmbiguousCaptures — the Gap I gate",
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
