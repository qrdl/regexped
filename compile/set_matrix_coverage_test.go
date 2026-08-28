package compile

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// The set emitters are reached by COMPILING, not by running, and until this
// file existed almost none of them were reached from this package at all.
//
// The correctness of what they emit is checked elsewhere and at far greater
// depth — `make setcaps` drives every capability over the RE2 corpus,
// `tools/fuzz` runs differential targets against Go's regexp. Both live in
// SEPARATE MODULES, so neither contributes a single statement to this
// package's coverage, and the gap that hid was total: `set_overlap_dp.go`,
// 314 statements of backward sweep, sat at 2.5% while being exercised
// thousands of times a second by a fuzz target one directory away.
//
// So this file's job is DIFFERENT from theirs: reach every emitter with a
// configuration that selects it, and assert the compile succeeded and
// produced a plausible module. Think of it as a smoke matrix — it is what
// notices when a shape stops compiling at all, which is a failure mode the
// corpus runners report far more slowly and a `go test ./compile` run should
// report immediately.
//
// Each case documents WHICH path it is there to select, because that is the
// only thing making it worth its runtime; a case whose comment no longer
// matches what the compiler does should be re-aimed rather than deleted.

// setMatrixCase is one set configuration plus the reason it exists.
type setMatrixCase struct {
	name string
	// selects names the emitter path this case is here to reach.
	selects  string
	patterns []string
	// subset, when non-empty, makes the set select those pattern NAMES rather
	// than all of them — the only configuration where ID_SPACE and
	// PATTERN_COUNT differ (docs/sets.md "Pattern ids and the two emitted
	// constants").
	subset      []string
	caps        setMatrixCaps
	overlapping bool
	batch       bool
	hints       []string
	// maxFallbackStates, when non-zero, caps the fallback suffix DFA. Setting
	// it to 1 is how a member is forced onto the BACKTRACKING engine
	// (SETS_PLAN item 20): no fallback DFA can be built that small, so the
	// pattern is admitted on BT instead of dropped.
	maxFallbackStates int
	// perPattern gives each pattern its OWN exports alongside the set.
	// A config may carry both, and the assembly then has to lay out the
	// single-pattern bodies — lit-anchor scans, groups wrappers, batch
	// wrappers — beside the set's, which is a different arm from a
	// sets-only config.
	perPattern perPatternExports
}

type perPatternExports struct {
	match, find, groups, batch bool
}

// setMatrixCaps says which capabilities the set declares. The compiler emits
// only the machinery the declared capabilities need, so this is a real axis:
// an anchored-only set emits no literal frontend at all.
type setMatrixCaps struct {
	matchAny, matchAll, scanAny, scanAll, find bool
}

var (
	capsAll      = setMatrixCaps{true, true, true, true, true}
	capsFind     = setMatrixCaps{find: true}
	capsAnchored = setMatrixCaps{matchAny: true, matchAll: true}
	capsScan     = setMatrixCaps{scanAny: true, scanAll: true}
)

// manyPatterns builds n distinct patterns sharing no literal, for the
// bucket-count and id-space axes.
func manyPatterns(n int, shape string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(shape, i)
	}
	return out
}

func setMatrixCases() []setMatrixCase {
	greedy := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	keywords := []string{`alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`}
	return []setMatrixCase{
		{
			name: "greedy-all-caps", selects: "scalar frontend, fallback buckets, every capability",
			patterns: greedy, caps: capsAll,
		},
		{
			name: "greedy-overlapping-batch", selects: "set_overlap_dp.go — the backward sweep and its answer cache",
			patterns: greedy, caps: capsFind, overlapping: true, batch: true,
		},
		{
			name: "greedy-overlapping", selects: "the ungated find body and its once-per-drive preflight",
			patterns: greedy, caps: capsFind, overlapping: true,
		},
		{
			name: "greedy-batch-gated", selects: "set_batch.go's gated resume path",
			patterns: greedy, caps: capsFind, batch: true,
		},
		{
			name: "greedy-scan-only", selects: "set_union_scan.go — the start-anywhere union automaton",
			patterns: greedy, caps: capsScan,
		},
		{
			name: "greedy-anchored-only", selects: "set_caps.go's anchored bodies, with NO literal frontend emitted",
			patterns: greedy, caps: capsAnchored,
		},
		{
			name: "keywords-literal-frontend", selects: "packed-pair / Teddy literal frontend over shared literals",
			patterns: keywords, caps: capsAll,
		},
		{
			name: "keywords-overlapping-batch", selects: "a literal frontend under the batching overlapping entry",
			patterns: keywords, caps: capsFind, overlapping: true, batch: true,
		},
		{
			name: "many-literals-ac", selects: "aho_corasick.go — >16 literals with low first-byte diversity",
			patterns: manyPatterns(24, "keyword%02d"), caps: capsAll,
		},
		{
			name: "diverse-literals", selects: "byte_rank.go's two-column probe and the Shufti prefilter",
			patterns: manyPatterns(20, "%c-marker-x"), caps: capsAll,
		},
		{
			name: "sparse-bucket", selects: "set_sparse.go — per-state accept LISTS once a bucket passes 32 patterns",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsAll,
		},
		{
			name: "wide-id-space", selects: "the WIDE `_all` form: a memory bitmap instead of an i64 mask",
			patterns: manyPatterns(70, "pat_%02d_tail"), caps: capsAll,
		},
		{
			name: "named-subset", selects: "ID_SPACE > PATTERN_COUNT, the §11 R1 memory-safety hazard",
			patterns: manyPatterns(12, "sub%02d"), subset: []string{"p00", "p05", "p11"}, caps: capsAll,
		},
		{
			name: "word-boundary", selects: "the \\b channel: wordChar table, wbNW/wbW accept and dominant tables",
			patterns: []string{`\bcat\b`, `\bdog`, `\b|0*`}, caps: capsAll,
		},
		{
			name: "word-boundary-overlapping", selects: "the same channel under the ungated find body",
			patterns: []string{`\bcat\b`, `\bdog`}, caps: capsFind, overlapping: true,
		},
		{
			name: "multiline", selects: "the (?m) newline channel and its pre-transition accept table",
			patterns: []string{`(?m:^)alpha`, `beta(?m:$)`, `(?m:^)gamma(?m:$)`}, caps: capsAll,
		},
		{
			name: "anchored-members", selects: "begin/end-anchored members, eligible only at position 0 or EOF",
			patterns: []string{`\Aabc`, `xyz\z`, `\Aq\z`}, caps: capsAll,
		},
		{
			name: "empty-capable", selects: "patterns matching empty beside ones that also extend",
			patterns: []string{`a*`, ``, `(?:)`, `[ab]{0,2}`}, caps: capsAll,
		},
		{
			name: "mixed-literal-and-not", selects: "the two-phase scan split: literal buckets in phase 1, the union pass in phase 2",
			patterns: []string{`alpha`, `bravo`, `a+`, `[^\n]*END`}, caps: capsAll,
		},
		{
			name: "counted-repetition", selects: "large counted repetitions, which stress the suffix DFA budget",
			patterns: []string{`a{4,8}b`, `[0-9]{6}`, `x{2,3}y{2,3}`}, caps: capsAll,
		},
		{
			name: "prefer-match-hint", selects: "the set-level LikelyMatch bias",
			patterns: greedy, caps: capsAll, hints: []string{"prefer-match"},
		},
		{
			name: "prefer-no-match-hint", selects: "the set-level LikelyNoMatch bias and its adaptive density counter",
			patterns: keywords, caps: capsAll, hints: []string{"prefer-no-match"},
		},

		// ---- Backtracking members (SETS_PLAN item 20) --------------------
		//
		// maxFallbackStates = 1 admits every fallback member on BT, which is
		// the whole of set_bt.go plus the ABI switch it forces: a BT member
		// can answer "unknown", and the narrow i64 `_all` form has no value
		// free to say so, so the bitmap moves into MEMORY whatever the id
		// space.
		{
			name: "bt-all-caps", selects: "set_bt.go — the Backtracking set body and the wide `_all` it forces",
			patterns: greedy, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-find-batch", selects: "a BT member under the batching find, including its overflow sentinel",
			patterns: greedy, caps: capsFind, batch: true, maxFallbackStates: 1,
		},
		{
			name: "bt-overlapping", selects: "a BT member under the ungated find body",
			patterns: greedy, caps: capsFind, overlapping: true, maxFallbackStates: 1,
		},
		{
			name: "bt-with-literals", selects: "a mixed set: literal buckets beside a BT fallback member",
			patterns: []string{`alpha`, `bravo`, `a+`, `[^\n]*END`}, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-captures-stripped", selects: "capture-bearing members, whose groups are stripped before the set sees them",
			patterns: []string{`(a+)(b+)`, `(?:x|y)+z`}, caps: capsAll, maxFallbackStates: 1,
		},
		{
			name: "bt-anchored-only", selects: "the ANCHORED Backtracking set body: full consumption, no find machinery",
			patterns: greedy, caps: capsAnchored, maxFallbackStates: 1,
		},
		{
			name: "bt-match-any-only", selects: "a single anchored capability over Backtracking members",
			patterns: greedy, caps: setMatrixCaps{matchAny: true}, maxFallbackStates: 1,
		},
		{
			name: "bt-scan-only", selects: "the scan pair over Backtracking members",
			patterns: greedy, caps: capsScan, maxFallbackStates: 1,
		},

		// ---- more sparse and scan shapes ---------------------------------
		{
			name: "sparse-overlapping-batch", selects: "a sparse bucket under the batching overlapping entry",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsFind,
			overlapping: true, batch: true,
		},
		{
			name: "sparse-scan", selects: "the sparse bucket's probe bodies, which scan_any/scan_all drive",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsScan,
		},
		{
			name: "sparse-anchored", selects: "compileAnchoredBuckets with a sparse promotion",
			patterns: manyPatterns(40, "shared_prefix_%02d"), caps: capsAnchored,
		},
		{
			name: "scan-any-literal-less", selects: "scan_any alone on a literal-less set — one union-automaton pass",
			patterns: greedy, caps: setMatrixCaps{scanAny: true},
		},
		{
			name: "scan-all-only", selects: "scan_all alone, which must keep the full probe rather than a first-hit exit",
			patterns: greedy, caps: setMatrixCaps{scanAll: true},
		},
		{
			name: "match-any-only", selects: "match_any alone over the dedicated anchored automaton",
			patterns: keywords, caps: setMatrixCaps{matchAny: true},
		},
		{
			name: "wide-subset-scan", selects: "a wide id space reached through a NAMED subset, scan capabilities only",
			patterns: manyPatterns(70, "pat_%02d_tail"),
			subset:   []string{"p00", "p33", "p69"}, caps: capsScan,
		},

		// ---- one bucket, many patterns: G17's sparse accept ---------------
		//
		// Sparse needs >32 patterns in ONE bucket, which means they must share
		// the SAME mandatory literal and differ only after it. Distinct
		// literals give distinct SINGLETON buckets and never promote — which
		// is what an earlier version of this matrix did, sitting at 40
		// singletons while claiming to test sparse.
		{
			name: "sparse-shared-literal", selects: "set_sparse.go — 40 patterns behind ONE shared literal",
			patterns: sharedLiteral(40), caps: capsAll,
		},
		{
			name: "sparse-shared-scan", selects: "buildSparseProbeBody — the sparse bucket's scan probes",
			patterns: sharedLiteral(40), caps: capsScan,
		},
		{
			name: "sparse-shared-find-batch", selects: "a sparse bucket under the batching find",
			patterns: sharedLiteral(40), caps: capsFind, batch: true,
		},
		{
			name: "sparse-shared-overlapping", selects: "a sparse bucket under the ungated find body",
			patterns: sharedLiteral(40), caps: capsFind, overlapping: true,
		},
		{
			name: "sparse-shared-anchored", selects: "a sparse promotion in the ANCHORED packer",
			patterns: sharedLiteral(40), caps: capsAnchored,
		},
		{
			name: "sparse-very-wide", selects: "a sparse bucket past 64 patterns, forcing the wide `_all` too",
			patterns: sharedLiteral(80), caps: capsAll,
		},

		// A LARGE Aho-Corasick automaton: many literals with diverse first
		// bytes, which is the AC frontend's own scaling axis.
		//
		// NOT a Shufti case, though it was written as one. Shufti is selected
		// only from the SCALAR branch, and reaching that needs Aho-Corasick to
		// decline first — which `hints_test.go` arranges with
		// `ACBudgetBytes: 1`, an option `BuildConfig` does not expose. AC still
		// took a 220-literal set comfortably inside its 512 KB budget, so no
		// YAML config appears able to select the Shufti frontend at all, and
		// `emitSetMatchFnFinalShufti` is unreachable through `CompileFile`.
		// Recorded rather than papered over with a case that does not do what
		// its name claims.
		{
			name: "large-ac", selects: "aho_corasick.go at scale — 90 literals, diverse first bytes",
			patterns: diverseFirstBytes(90), caps: capsAll, hints: []string{"prefer-no-match"},
		},

		// ---- a config carrying BOTH a set and per-pattern exports ---------
		//
		// The two are laid out together, so the assembly has to place
		// single-pattern bodies — lit-anchor back-scans, groups wrappers,
		// batch wrappers — beside the set's own functions and keep every
		// function index straight across both. A sets-only config never
		// reaches those arms.
		{
			name: "set-plus-pattern-exports", selects: "assembleModuleWithSets laying out per-pattern bodies beside a set",
			patterns: []string{`[a-z]+@example\.com`, `ghp_[A-Za-z0-9]{36}`},
			caps:     capsAll, perPattern: perPatternExports{match: true, find: true},
		},
		{
			name: "set-plus-groups", selects: "a groups wrapper beside a set — capture patterns are dropped FROM the set but keep their own export",
			patterns: []string{`(?P<user>[a-z]+)@(?P<host>[a-z.]+)`, `plain[0-9]+`},
			caps:     capsAll, perPattern: perPatternExports{groups: true, find: true},
		},
		{
			name: "set-plus-batch-groups", selects: "the per-pattern BATCH groups wrapper beside a set",
			patterns: []string{`(?P<a>[a-z])(?P<b>[0-9])`, `lit[0-9]+`},
			caps:     capsFind, perPattern: perPatternExports{groups: true, find: true, batch: true},
		},
		{
			name: "set-plus-lit-anchor", selects: "a lit-anchor back-scan body beside a set",
			patterns: []string{`[a-z]+@example\.com`, `[0-9]+-suffix`},
			caps:     capsFind, perPattern: perPatternExports{find: true},
		},
		{
			name: "set-plus-everything", selects: "match, find, groups and batching per pattern, all beside a set",
			patterns: []string{`(?P<w>[a-z]+)@(?P<h>[a-z.]+)`, `[a-z]+@example\.com`},
			caps:     capsAll, perPattern: perPatternExports{match: true, find: true, groups: true, batch: true},
		},
	}
}

// sharedLiteral builds n patterns that all carry the SAME mandatory literal
// and differ only in the suffix after it, so the packer puts them in one
// bucket — the precondition for G17's sparse promotion.
func sharedLiteral(n int) []string {
	out := make([]string, n)
	for i := range out {
		// The literal is "SHAREDKEY" in every one of them: the distinguishing
		// part is the SUFFIX. Putting it before the literal, or inside it,
		// makes each pattern's mandatory literal distinct and lands them in n
		// singleton buckets instead of one.
		out[i] = fmt.Sprintf("SHAREDKEY[0-9]{%d}", i+1)
	}
	return out
}

// diverseFirstBytes builds n literal-bearing patterns whose FIRST bytes cycle a
// 36-character alphabet, keeping the union inside Shufti's 17..64 band while
// the literals stay long enough to matter.
func diverseFirstBytes(n int) []string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := make([]string, n)
	for i := range out {
		// Long literals so the Aho-Corasick table exceeds its budget and
		// declines, which is what leaves the scalar branch — the only place
		// Shufti is selected — to take them.
		out[i] = fmt.Sprintf("%cqqqqqqqq%04dxxxxxxxx[a-z]+", alphabet[i%len(alphabet)], i)
	}
	return out
}

func (c setMatrixCase) build() config.BuildConfig {
	entries := make([]config.RegexEntry, len(c.patterns))
	for i, p := range c.patterns {
		e := config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: p}
		if c.perPattern.match {
			e.MatchFunc = fmt.Sprintf("p%02d_match", i)
		}
		if c.perPattern.find {
			e.FindFunc = fmt.Sprintf("p%02d_find", i)
		}
		// Only where the pattern HAS capture groups: a groups export is
		// emitted for MaxCap() > 0 alone, so setting it elsewhere asks for a
		// function the compiler will not produce.
		if c.perPattern.groups {
			if parsed, err := syntax.Parse(p, syntax.Perl); err == nil && parsed.MaxCap() > 0 {
				e.GroupsFunc = fmt.Sprintf("p%02d_groups", i)
			}
		}
		if c.perPattern.batch {
			e.Hints = append(e.Hints, "batch-find")
		}
		entries[i] = e
	}
	sel := config.PatternSelector{All: true}
	if len(c.subset) > 0 {
		sel = config.PatternSelector{Names: c.subset}
	}
	set := config.SetConfig{
		Name:        "s",
		Patterns:    sel,
		Overlapping: c.overlapping,
		Hints:       c.hints,
	}
	if c.caps.matchAny {
		set.MatchAny = "cap_match_any"
	}
	if c.caps.matchAll {
		set.MatchAll = "cap_match_all"
	}
	if c.caps.scanAny {
		set.ScanAny = "cap_scan_any"
	}
	if c.caps.scanAll {
		set.ScanAll = "cap_scan_all"
	}
	if c.caps.find {
		set.Find = "cap_find"
	}
	if c.batch {
		set.Hints = append(append([]string(nil), set.Hints...), "batch-find")
	}
	return config.BuildConfig{
		Regexps:           entries,
		Sets:              []config.SetConfig{set},
		MaxFallbackStates: c.maxFallbackStates,
	}
}

// TestSetMatrixCompiles compiles every shape in the matrix and checks the
// module is well formed enough to be worth emitting.
//
// It deliberately does NOT check match results: that is the corpus runners'
// job, they do it far more thoroughly, and duplicating a weaker version here
// would be a second oracle to keep in sync. What this asserts is that the path
// still compiles, still exports what it promised, and still looks like a WASM
// module.
func TestSetMatrixCompiles(t *testing.T) {
	for _, c := range setMatrixCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.build()
			// STANDALONE (its own exported memory, what JS/TS load) and
			// EMBEDDED (memory imported from "main", what a merged Rust/Go/C
			// host gets) are different assembly arms: the embedded one imports
			// rather than declares, and renumbers every memory index after it.
			// A set shape that assembles one way and not the other would
			// otherwise surface only at merge time.
			for _, output := range []string{"", "merged.wasm"} {
				mode := "standalone"
				if output != "" {
					mode = "embedded"
				}
				wasm, _, err := CompileFile(cfg, output)
				if err != nil {
					t.Fatalf("%s/%s (selects %s): %v", c.name, mode, c.selects, err)
				}
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s/%s: not a WASM module (%d bytes)", c.name, mode, len(wasm))
				}
				// Every declared capability must appear as an export name. The
				// export section stores names as plain bytes, so a substring
				// search over the module is enough to catch a capability that
				// silently stopped being emitted.
				for _, want := range c.wantExports() {
					if !strings.Contains(string(wasm), want) {
						t.Errorf("%s/%s: module does not export %q", c.name, mode, want)
					}
				}
			}
		})
	}
}

func (c setMatrixCase) wantExports() []string {
	var out []string
	if c.caps.matchAny {
		out = append(out, "cap_match_any")
	}
	if c.caps.matchAll {
		out = append(out, "cap_match_all")
	}
	if c.caps.scanAny {
		out = append(out, "cap_scan_any")
	}
	if c.caps.scanAll {
		out = append(out, "cap_scan_all")
	}
	if c.caps.find {
		out = append(out, "cap_find")
	}
	if c.batch {
		out = append(out, config.SetBatchExportName("cap_find"))
	}
	return out
}

// TestSetMatrixDiagnostics runs the same matrix through the diagnostics entry
// point, which is a separate code path from CompileFile and reports the
// composition decisions — bucket kinds, frontend choice, dropped patterns.
//
// Worth its own pass because a diagnostics build that disagrees with the real
// one is how `--diag-json` would start describing a module nobody compiled.
func TestSetMatrixDiagnostics(t *testing.T) {
	for _, c := range setMatrixCases() {
		t.Run(c.name, func(t *testing.T) {
			_, _, diags, err := CompileFileDiag(c.build(), "")
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(diags) != 1 {
				t.Fatalf("%s: expected one set diagnostic, got %d", c.name, len(diags))
			}
			// A set can legitimately end up with NO buckets when every member
			// was excluded — capture-bearing patterns are dropped from sets by
			// design. Say which it is rather than treating both as the same
			// failure.
			if len(diags[0].Buckets) == 0 {
				allCaptures := true
				for _, pat := range c.patterns {
					if parsed, err := syntax.Parse(pat, syntax.Perl); err == nil && parsed.MaxCap() == 0 {
						allCaptures = false
					}
				}
				if !allCaptures {
					t.Errorf("%s: no buckets, though not every pattern is capture-bearing", c.name)
				}
			}
		})
	}
}
