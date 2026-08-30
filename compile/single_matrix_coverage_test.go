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
			pattern: `[\x00-\xff]x`, find: true,
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
	}
}

func (c singleCase) build() config.BuildConfig {
	entry := config.RegexEntry{Name: "p", Pattern: c.pattern, Hints: c.hints}
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
