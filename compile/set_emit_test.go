package compile

import (
	"bytes"
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// Set-emission paths that the compile matrices next door do not select.
//
// `set_module_test.go` sweeps the shapes a YAML config can ASK for.
// What is left over after it are three different kinds of gap, and this file
// is aimed at each of them separately:
//
//   - ARMS CHOSEN BY A FLAG THE MATRIX PINS. `standalone` is the loudest:
//     every case there compiles both "standalone" and "embedded", but it
//     varies CompileFile's `output` ARGUMENT (an output path) rather than
//     cfg.Output, and it is cfg.Output that picks the arm. So the whole
//     `!standalone` half of assembleModuleWithSets — the memory renumbering
//     every merged Rust/Go/C host gets — was never emitted from this package.
//
//   - SHAPES THAT NEED A PATTERN FAMILY, not a capability. The union-walk
//     preflight only runs when the absence prefilter DECLINES, which needs
//     patterns carrying no mandatory literal at all; the Aho-Corasick body's
//     no-prefilter arm needs AC to be chosen ALONGSIDE a fallback bucket.
//     Neither follows from any capability combination.
//
//   - PREDICATES AND EMITTERS WHOSE ONLY CALLER ASKS ONE QUESTION. A
//     capability dispatcher that only ever asks `usesUnionScan` about the scan
//     kinds leaves its "no" answer for `find` untested, and that answer is a
//     contract: `find` reports positions, and a forward union pass knows only
//     where matches END.
//
// Where a path genuinely cannot be selected through CompileFile, it is called
// directly and the comment says so plainly. Nothing here asserts that a path
// is unreachable — the ones this file could not reach are listed in the task
// report instead, with the gate suspected of diverting them.

// setEmitCovInfos resolves patterns into the PatternInfos CompileSet works
// from, giving each its declaration index as its global id — the same
// numbering CompileFileDiag assigns.
func setEmitCovInfos(t *testing.T, patterns []string) ([]*PatternInfo, []int, *dfaPool, *dfaPool) {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, 0, len(patterns))
	globalIDs := make([]int, 0, len(patterns))
	for i, pattern := range patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: pattern}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pattern, err)
		}
		info.globalID = i
		infos = append(infos, info)
		globalIDs = append(globalIDs, i)
	}
	return infos, globalIDs, &prefixPool, &suffixPool
}

// setEmitCovCompileSet is the shortest route from a list of patterns to a
// compiledSet, for the predicates that are answered from one.
func setEmitCovCompileSet(t *testing.T, spec SetSpec, patterns []string, opts CompileSetOptions) *compiledSet {
	t.Helper()
	infos, globalIDs, prefixPool, suffixPool := setEmitCovInfos(t, patterns)
	spec.Patterns = infos
	spec.PatternIDs = globalIDs
	if spec.DeclaredPatternCount == 0 {
		spec.DeclaredPatternCount = len(infos)
	}
	if spec.IDSpaceSize == 0 {
		spec.IDSpaceSize = len(infos)
	}
	return CompileSet(spec, prefixPool, suffixPool, opts)
}

// setEmitCovEntries turns patterns into named config entries p00, p01, ... so
// a set can select them by name.
func setEmitCovEntries(patterns []string) []config.RegexEntry {
	entries := make([]config.RegexEntry, len(patterns))
	for i, pattern := range patterns {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: pattern}
	}
	return entries
}

// setEmitCovMustCompile compiles cfg and insists on a well-formed module.
// cfg.Output decides the standalone/embedded arm, so it is left to the caller.
func setEmitCovMustCompile(t *testing.T, cfg config.BuildConfig) []byte {
	t.Helper()
	wasm, _, err := CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
		t.Fatalf("not a WASM module (%d bytes)", len(wasm))
	}
	return wasm
}

// litLessNeverDying are patterns with NO mandatory literal whose automaton
// never dies: the leading `[^\n]*` self-loops over 252 of 256 bytes, which is
// past dominantSelfLoopMin with only four exceptions.
//
// Both properties are load-bearing and they pull in opposite directions, which
// is why the family is spelled out once here:
//
//   - never-dying is what makes usesGatedFindPreflight / overlapPreflightShape
//     say yes at all. Without it a preflight is the reverted Candidate A — a pass
//     over the whole input that retires nothing.
//   - literal-LESS is what makes the absence prefilter DECLINE
//     (buildAbsenceLits needs at least one pattern with a mandatory literal),
//     which is the only way the UNION-walk arm of either preflight runs.
//
// greedy-3's `[^\n]*ERROR`, which the matrix next door uses, has both a
// never-dying automaton and the literal "ERROR" — so it always takes the
// absence arm and never the union one.
var litLessNeverDying = []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}

// TestSetEmitEmbeddedModuleWithPerPatternExports compiles a set BESIDE
// per-pattern exports into an EMBEDDED module — cfg.Output non-empty, which is
// what a merged Rust/Go/C host loads.
//
// Embedded modules import "main" memory as memory[0] and keep their own tables
// in memory[1], so every table access in a per-pattern body emitted by
// assembleModuleWithSets has to be renumbered. Each of the wrappers below
// carries its own copy of that decision (`tableMemIdx = 1` when not
// standalone), and a copy that stopped being made would produce a module that
// reads the HOST's memory as if it were the table — silently wrong answers
// rather than a validation error.
func TestSetEmitEmbeddedModuleWithPerPatternExports(t *testing.T) {
	entries := []config.RegexEntry{
		// A literal-anchored find: emits a backward-scan body plus a find body
		// built around it, the pair that carries the lit-anchor table index.
		{
			Name: "lit_anchor", Pattern: `[a-z]+@example\.com`,
			FindFunc: "lit_anchor_find",
		},
		// Captures the selector routes to BACKTRACKING, not TDFA: an inverted
		// class wider than 256 codepoints makes getFirstRuneSet report
		// ambiguity (CLAUDE.md, "Load-bearing engine-selection gates"). That is what makes p.isTDFA false, so
		// the composed wrapper has to pass the BT window scratch offset rather
		// than -1. Non-anchored, so the wrapper composes find + capture.
		{
			Name: "bt_groups", Pattern: `<([^>]+)>`,
			GroupsFunc: "bt_groups_groups", FindFunc: "bt_groups_find",
			Hints: []string{"batch-find"},
		},
		// A literal chain: literal then a fixed-count class run. Its groups
		// body is ANCHORED, which selects the other batch-groups wrapper —
		// the native lit-chain one, with no find body to compose.
		{
			Name: "lit_chain", Pattern: `ghp_(?P<id>[A-Za-z0-9]{36})`,
			GroupsFunc: "lit_chain_groups",
			Hints:      []string{"batch-find"},
		},
		// A plain member so the set has something left after the
		// capture-bearing entries are dropped from it.
		{Name: "plain", Pattern: `plain[0-9]+`},
	}
	cfg := config.BuildConfig{
		// The only thing that selects the embedded arm. CompileFile's second
		// argument is an output PATH and does not affect it.
		Output:  "merged.wasm",
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", MatchAny: "s_match_any",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	wasm := setEmitCovMustCompile(t, cfg)

	// Each per-pattern export must survive being laid out beside a set: the
	// function indices of the set's own bodies are interleaved with these, and
	// a mis-numbered one is a call to the wrong function.
	for _, export := range []string{
		"lit_anchor_find", "bt_groups_groups", "bt_groups_find",
		"bt_groups_find_batch", "bt_groups_groups_batch",
		"lit_chain_groups", "lit_chain_groups_batch", "s_find", "s_match_any",
	} {
		if !strings.Contains(string(wasm), export) {
			t.Errorf("embedded module does not export %q", export)
		}
	}

	// The same config compiled STANDALONE must still work; the two arms differ
	// only in memory numbering, so a shape that assembles one way and not the
	// other is exactly the merge-time failure this test exists to pre-empt.
	standalone := cfg
	standalone.Output = ""
	setEmitCovMustCompile(t, standalone)
}

// TestSetEmitFindPreflightTakesUnionWalk drives the two `find` preflights down
// their UNION-AUTOMATON arm.
//
// Both preflights have two ways to compute "this pattern matches nowhere at or
// after `from`": the literal-absence scan, and a pass over the start-anywhere
// union automaton. The absence scan wins whenever any member carries a
// mandatory literal, which is nearly every set anyone writes — so the union arm
// (and with it the wider local frame emitSetMatchFnFinalScalar declares for it)
// only runs on a literal-LESS set. See litLessNeverDying.
func TestSetEmitFindPreflightTakesUnionWalk(t *testing.T) {
	// The GATED body's preflight additionally needs the union automaton to
	// have been built at all, and CompileSet only builds it for a scan
	// capability or for an overlapping find — a find-only gated set leaves the
	// preflight dormant on purpose (set_emit.go's "byte-identical" note). So
	// scan_any is declared alongside.
	gated := config.BuildConfig{
		Regexps: setEmitCovEntries(litLessNeverDying),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", ScanAny: "s_scan_any",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	setEmitCovMustCompile(t, gated)

	// The OVERLAPPING body's preflight requests the automaton itself: an
	// overlapping find-only set has no scan capability to have built one, and
	// without the alive verdict there is nothing to retire a never-dying
	// pattern from validMask with — which is the difference between one
	// overlapping call and a quadratic one.
	overlapping := config.BuildConfig{
		Regexps: setEmitCovEntries(litLessNeverDying),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Overlapping: true,
			Patterns: config.PatternSelector{All: true},
		}},
	}
	setEmitCovMustCompile(t, overlapping)

	// And with batching, so the shared worker is the body carrying the
	// preflight rather than the exported find.
	batched := overlapping
	batched.Sets = []config.SetConfig{{
		Name: "s", Find: "s_find", Overlapping: true,
		Hints:    []string{"batch-find"},
		Patterns: config.PatternSelector{All: true},
	}}
	setEmitCovMustCompile(t, batched)
}

// TestSetEmitOverlapPreflightIDSpaceExceedsMembers covers the id-space widening
// in overlapCanPreflight: the set's ID SPACE, not its surviving members, is
// what the gate array and the i64 alive mask must both fit.
//
// The two differ whenever the LAST declared pattern is dropped from the set —
// here by carrying capture groups, which sets never report. The ids of the
// survivors then stop below the declared space, and taking the maximum
// SURVIVING id as the bound would let a set through whose caller-supplied gate
// array is indexed past the mask the preflight can express.
func TestSetEmitOverlapPreflightIDSpaceExceedsMembers(t *testing.T) {
	entries := setEmitCovEntries(litLessNeverDying)
	// Declared last, dropped from the set, and its index is what IDSpaceSize
	// is computed from.
	entries = append(entries, config.RegexEntry{
		Name: "dropped", Pattern: `(?P<g>[^\n]*[6-8])`, GroupsFunc: "dropped_groups",
	})
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Overlapping: true,
			Patterns: config.PatternSelector{All: true},
		}},
	}
	wasm, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("CompileFileDiag: %v", err)
	}
	if len(wasm) < 8 {
		t.Fatalf("module too short: %d bytes", len(wasm))
	}
	if len(diags) != 1 {
		t.Fatalf("expected one set diagnostic, got %d", len(diags))
	}
	// The id space must still cover the dropped entry's id: the stubs size the
	// gate array from the same number, and a set that shrank it here would
	// hand the compiler and the stub two different array lengths.
	if diags[0].IDSpaceSize != len(entries) {
		t.Errorf("ID space = %d, want %d (one past the LAST declared pattern, dropped or not)",
			diags[0].IDSpaceSize, len(entries))
	}
}

// TestSetEmitACFrontendWithFallbackBucket puts an Aho-Corasick frontend and a
// fallback bucket in ONE set.
//
// Teddy and packed-pair refuse that combination outright — a fallback pattern
// must be tried at every position and a prefilter that skips positions cannot
// serve it, so both fall through to the scalar body. AC does NOT fall through:
// it keeps its automaton and instead drops its SIMD first-byte prefilter and
// runs the fallback buckets at every position. That is a whole arm of
// emitSetMatchFnFinalAC, and no set with fewer than 17 literals can reach it.
//
// Low first-byte diversity is what keeps AC in front of Teddy above 16
// literals, hence the shared "keyword" stem.
func TestSetEmitACFrontendWithFallbackBucket(t *testing.T) {
	patterns := make([]string, 0, 25)
	for i := 0; i < 24; i++ {
		patterns = append(patterns, fmt.Sprintf("keyword%02d", i))
	}
	// No mandatory literal: this one lands in a fallback bucket and is what
	// takes AC's prefilter away.
	patterns = append(patterns, `[0-9]{4,}`)

	cfg := config.BuildConfig{
		Regexps: setEmitCovEntries(patterns),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", ScanAll: "s_scan_all", MatchAll: "s_match_all",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	_, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("CompileFileDiag: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("expected one set diagnostic, got %d", len(diags))
	}
	// Asserted rather than assumed: if a future frontend ranking sends this
	// shape to Teddy or scalar, the test still passes its compile check while
	// silently no longer reaching the arm it is named for.
	if diags[0].Frontend != frontendAC.String() {
		t.Fatalf("frontend = %q, want %q — this set no longer reaches the "+
			"Aho-Corasick body's no-prefilter arm", diags[0].Frontend, frontendAC.String())
	}
	fallbacks := 0
	for _, bucket := range diags[0].Buckets {
		if strings.Contains(bucket.Type, "fallback") {
			fallbacks++
		}
	}
	if fallbacks == 0 {
		t.Error("no fallback bucket: the AC prefilter would still be emitted and the arm is not reached")
	}
}

// TestSetEmitACFrontendSingleByteLiteral gives an AC set a ONE-BYTE literal.
//
// The AC body computes each candidate's match start as `pos - (litLen - 1)`,
// and a one-byte literal is the case where that subtraction must not be
// emitted at all. Getting it wrong is off-by-one on every match of that
// pattern, not a crash — so it needs a set that actually contains one, and
// every literal in the matrix next door is several bytes long.
func TestSetEmitACFrontendSingleByteLiteral(t *testing.T) {
	patterns := make([]string, 0, 22)
	for i := 0; i < 20; i++ {
		patterns = append(patterns, fmt.Sprintf("keyword%02d", i))
	}
	// Mandatory literal "k", one byte. Shares the first byte with the rest so
	// the set stays on the low-diversity side of the AC/Teddy crossover; the
	// minimum literal length of 1 also puts it below teddyMinLenForBucketing,
	// which is a second reason Teddy declines.
	patterns = append(patterns, `k[0-9]{3}`)

	cfg := config.BuildConfig{
		Regexps: setEmitCovEntries(patterns),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", ScanAll: "s_scan_all",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	_, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("CompileFileDiag: %v", err)
	}
	if diags[0].Frontend != frontendAC.String() {
		t.Fatalf("frontend = %q, want %q — the one-byte-literal arm of the AC "+
			"body is not reached", diags[0].Frontend, frontendAC.String())
	}
}

// TestSetEmitOverlapDPRefusals pins the shapes the backward sweep must REFUSE.
//
// The sweep is a second implementation of buildSetSuffixBody's per-position
// stopping rule, and every refusal here is a shape whose rule it would have to
// reproduce a second time. A refusal that stopped firing does not fail to
// compile — it produces a module that answers a different question, which is
// how an earlier copy diverged — so the predicate is asserted directly rather than through
// the emitted bytes.
func TestSetEmitOverlapDPRefusals(t *testing.T) {
	// The sweep needs all of: find, overlapping, batching, and exactly one
	// fallback bucket. Everything else about a case below is what disqualifies
	// it.
	baseSpec := SetSpec{
		Name: "s", Find: "s_find", BatchFind: true, Overlapping: true,
	}
	for _, testCase := range []struct {
		name     string
		patterns []string
		opts     CompileSetOptions
		wantDP   bool
		why      string
	}{
		{
			name: "accepted", patterns: []string{`[^\n]*[0-2]`}, wantDP: true,
			why: "one literal-less bucket, u8 ids, column well inside the bound",
		},
		{
			name: "backtracking-member", patterns: []string{`[0-9]+`},
			opts: CompileSetOptions{MaxFallbackStates: 1}, wantDP: false,
			why: "a Backtracking member has no DFA to sweep",
		},
		{
			// Alternating classes rather than one repeated class: a pure
			// counted chain of ONE class is verified by SIMD in a single shot
			// and never gets a transition table at all, so it is refused a
			// step earlier and would not reach the u8/u16 test.
			name: "u16-state-ids", patterns: []string{`(?:[0-9][a-c]){150}`}, wantDP: false,
			why: "past 255 states the layout switches to u16, and the sweep loads u8",
		},
		{
			name: "counted-class-chain", patterns: []string{`[0-9]{40}`}, wantDP: false,
			why: "a counted class chain has no transition table for the sweep to read",
		},
		{
			name: "several-buckets", patterns: []string{`alpha`, `bravo`}, wantDP: false,
			why: "with several buckets a position's tuples come from several DFAs",
		},
		{
			name: "literal-bucket", patterns: []string{`a$`}, wantDP: false,
			why: "a literal bucket's DFA matches only what follows its literal, and the sweep has no frontend",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spec := baseSpec
			compiled := setEmitCovCompileSet(t, spec, testCase.patterns, testCase.opts)
			if got := compiled.usesOverlapDP(); got != testCase.wantDP {
				t.Errorf("usesOverlapDP() = %v, want %v (%s)", got, testCase.wantDP, testCase.why)
			}
		})
	}
}

// TestSetEmitOverlapDPCompressedTable runs the backward sweep over a
// BYTE-CLASS COMPRESSED transition table.
//
// The sweep's single most important property is that it reads the forward
// body's table rather than emitting one of its own — so it has to honour every
// layout decision that table was built with. Compression kicks in above 32 KB,
// which for a u8 table means roughly 128 states or more; every DP case in the
// matrix next door is far smaller than that and reads the byte directly as the
// column index.
func TestSetEmitOverlapDPCompressedTable(t *testing.T) {
	// ~142 states over 256 columns is 36 KB uncompressed, past the threshold,
	// while staying inside the u8 id space the sweep requires. The classes
	// ALTERNATE on purpose: a counted chain of one repeated class is verified
	// by SIMD in one shot and never gets a transition table, so it would be
	// refused before the layout is even consulted.
	const wideButU8 = `(?:[0-9][a-c]){70}`
	spec := SetSpec{Name: "s", Find: "s_find", BatchFind: true, Overlapping: true}
	compiled := setEmitCovCompileSet(t, spec, []string{wideButU8}, CompileSetOptions{})
	bucket := compiled.overlapDPBucket()
	if bucket < 0 {
		t.Fatalf("the sweep refused %s; it no longer reaches the compressed-table arm", wideButU8)
	}
	if !compiled.buckets[bucket].dp.l.useCompression {
		t.Fatalf("%s produced an UNCOMPRESSED table (%d states): the compressed "+
			"column arithmetic is not reached", wideButU8, compiled.buckets[bucket].dp.numWASM)
	}

	// And the whole config compiles: the sweep body is emitted at assembly
	// time, so the predicate agreeing is only half the check.
	cfg := config.BuildConfig{
		Regexps: setEmitCovEntries([]string{wideButU8}),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Overlapping: true,
			Hints:    []string{"batch-find"},
			Patterns: config.PatternSelector{All: true},
		}},
	}
	setEmitCovMustCompile(t, cfg)
}

// TestSetEmitUnionScanRefusals covers buildUnionScanDFA's refusals.
//
// Every one of them is a case where a single forward pass cannot answer the
// question, and a refusal that stopped firing would not fail to compile: the
// set would silently get a walk that under-reports. They are asserted here
// through the constructor directly because a set that is refused simply takes
// the per-position path, leaving nothing in the module to observe.
func TestSetEmitUnionScanRefusals(t *testing.T) {
	buildFor := func(t *testing.T, patterns []string) *unionScanDFA {
		t.Helper()
		infos, globalIDs, _, _ := setEmitCovInfos(t, patterns)
		spec := SetSpec{
			Name: "s", ScanAny: "s_scan_any",
			Patterns: infos, PatternIDs: globalIDs,
			DeclaredPatternCount: len(infos), IDSpaceSize: len(infos),
		}
		return buildUnionScanDFA(spec, 0, false)
	}

	// A start-anywhere determinisation is `.*`-prefixed, so it is bigger than
	// the plain union — measured at 1.6x to 4.2x — and this shape explodes it
	// outright: `.*a.{13}b` has to remember which of the last 13 positions
	// carried an `a`, one state per subset. Over maxUnionScanStates the set
	// keeps its per-position path rather than compiling a table it cannot
	// address.
	//
	// A counted run of ONE class would NOT do it: `[0-9]{14}` start-anywhere
	// needs only the length of the current digit run, 15 states.
	if got := buildFor(t, []string{`a.{13}b`}); got != nil {
		t.Errorf("a union automaton past the %d-state budget was accepted (%d states); "+
			"the budget no longer refuses it", maxUnionScanStates, got.numStates)
	}

	// The id-space ceiling. It was 64 — one u64 accept mask — until the
	// automaton gained a wide accept form; the refusal now
	// sits at maxUnionScanIDs, which bounds the per-state accept ROW and the
	// straight-line WASM that ORs it into the caller's bitmap.
	//
	// Both sides are asserted, because a ceiling is only a ceiling if
	// something below it is admitted: a 66-pattern set must now BUILD, and
	// build wide.
	wide := make([]string, 66)
	for i := range wide {
		wide[i] = fmt.Sprintf("[0-9]{%d}", i+1)
	}
	got := buildFor(t, wide)
	if got == nil {
		t.Error("a 66-pattern set was refused; the wide accept form should serve it")
	} else if !got.isWide() || got.maskWords != 2 {
		t.Errorf("66 ids: wide=%v maskWords=%d, want a 2-word wide form",
			got.isWide(), got.maskWords)
	}

	over := make([]string, maxUnionScanIDs+1)
	for i := range over {
		over[i] = fmt.Sprintf("[0-9]{%d}", i+1)
	}
	if got := buildFor(t, over); got != nil {
		t.Errorf("a %d-pattern set was accepted; the id space exceeds maxUnionScanIDs (%d)",
			len(over), maxUnionScanIDs)
	}

	// A pattern whose AST cannot be recovered is skipped everywhere else in
	// the compiler, and a union missing one would under-report the same way.
	// PatternInfo is built by analyzePattern, which parses, so an
	// unparseable fullPattern cannot arrive here from a config — it is set by
	// hand to reach the guard.
	broken := &PatternInfo{fullPattern: `(unclosed`, globalID: 0}
	unparseable := SetSpec{
		Name: "s", ScanAny: "s_scan_any",
		Patterns: []*PatternInfo{broken}, PatternIDs: []int{0},
		DeclaredPatternCount: 1, IDSpaceSize: 1,
	}
	if got := buildUnionScanDFA(unparseable, 0, false); got != nil {
		t.Error("a pattern whose AST could not be recovered was admitted to the union automaton")
	}
}

// TestSetEmitUnionScanWideSetCompiles is the id ceiling reached the way a
// config reaches it: a literal-less set of 66 patterns declaring the scan pair.
//
// Before the wide accept form this set fell back to the per-position
// bucket walk, and the test's point was that the ceiling is a routing decision
// rather than a build error. It now takes the WIDE union body instead, and the
// point is the same one from the other side — the routing changed and the
// module still assembles, with the `_all` pair on its out_ptr/count ABI (66 ids
// is over wideBitmapThreshold) served by a body that writes the bitmap itself.
func TestSetEmitUnionScanWideSetCompiles(t *testing.T) {
	patterns := make([]string, 66)
	for i := range patterns {
		patterns[i] = fmt.Sprintf(`[0-9]{%d}[a-c]`, i+1)
	}
	cfg := config.BuildConfig{
		Regexps: setEmitCovEntries(patterns),
		Sets: []config.SetConfig{{
			Name: "s", ScanAny: "s_scan_any", ScanAll: "s_scan_all",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	setEmitCovMustCompile(t, cfg)

	_, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(diags) != 1 || diags[0].UnionScan == nil || !diags[0].UnionScan.Wide {
		t.Errorf("want a wide union automaton in --diag-json, got %+v", diags)
	}
}

// TestSetEmitCapabilityPredicatesRefuseFind covers the "no" answers of three
// predicates whose only production caller asks them about the SCAN kinds only.
//
// Each "no" is a real contract rather than a fallthrough:
//   - a forward union pass knows where matches END, so it can never serve
//     `find`, which reports starts and extents;
//   - the two-phase split has no phase-1 index to hand a capability it does
//     not split;
//   - an all-fallback set has no literal half for phase 1 to serve at all.
func TestSetEmitCapabilityPredicatesRefuseFind(t *testing.T) {
	// A literal-less set with both scan capabilities and a find: the union
	// automaton is built (scan_any asked for it), so the predicate has
	// something to say no ABOUT.
	spec := SetSpec{Name: "s", Find: "s_find", ScanAny: "s_scan_any", ScanAll: "s_scan_all"}
	compiled := setEmitCovCompileSet(t, spec, litLessNeverDying, CompileSetOptions{})
	if compiled.unionScan == nil {
		t.Fatal("no union automaton was built; the predicate has nothing to refuse")
	}
	if compiled.usesUnionScan(capScanAny) != true {
		t.Error("scan_any on a literal-less set must take the union walk")
	}
	if compiled.usesUnionScan(capFind) {
		t.Error("find was routed to the union walk; a forward pass cannot report a match START")
	}
	if compiled.usesUnionScan(capMatchAny) {
		t.Error("an ANCHORED capability was routed to the non-anchored union walk")
	}
	// No literal buckets at all: phase 1 would have nothing to serve.
	if hasLiteralBuckets(compiled.buckets) {
		t.Error("a set of literal-less patterns reported a literal bucket")
	}

	// A MIXED set is the one the two-phase split exists for: literal buckets
	// in phase 1, the union pass over the fallback patterns in phase 2.
	mixedSpec := SetSpec{Name: "s", ScanAny: "s_scan_any"}
	mixed := setEmitCovCompileSet(t, mixedSpec,
		[]string{`alpha`, `bravo`, `charlie`, `[^\n]*[0-2]`}, CompileSetOptions{})
	if !mixed.usesTwoPhaseScan(capScanAny) {
		t.Skip("this set no longer takes the two-phase split; the offset predicate has nothing to refuse")
	}
	if off := mixed.twoPhaseFnOffset(capScanAny); off < 0 {
		t.Errorf("scan_any is split but has no phase-1 offset (%d)", off)
	}
	if off := mixed.twoPhaseFnOffset(capFind); off != -1 {
		t.Errorf("twoPhaseFnOffset(find) = %d, want -1: find is never split", off)
	}
}

// TestSetTwoPhaseScanAllWideBody covers the WIDE arm of emitTwoPhaseScanBody:
// a mixed set whose `_all` answer is a caller-owned BITMAP rather than an i64
// mask, which is what more than 64 pattern ids forces.
//
// The arm is short and its correctness argument is entirely in a comment — the
// two phases write the same bitmap and each returns how many bits it set, so
// the answer is their sum, and they cannot double-count because a pattern
// lives in exactly one bucket. That is the kind of claim worth having a test
// behind, and it was reached by nothing: every other two-phase set in the
// suite is narrow.
func TestSetTwoPhaseScanAllWideBody(t *testing.T) {
	// Enough literal patterns to push the id space past 64, plus literal-less
	// ones so the set is MIXED and actually splits into two phases.
	var pats []string
	for i := 0; i < 70; i++ {
		pats = append(pats, fmt.Sprintf("lit%03dx", i))
	}
	pats = append(pats, `[^
]*[0-2]`, `[^
]*[3-5]`)

	spec := SetSpec{Name: "s", ScanAll: "s_scan_all"}
	cs := setEmitCovCompileSet(t, spec, pats, CompileSetOptions{})
	if !cs.wideAll() {
		t.Skipf("id space %d did not select the wide _all ABI", cs.idSpaceSize())
	}
	if !cs.usesTwoPhaseScan(capScanAll) {
		t.Skip("this set no longer takes the two-phase split")
	}
	body := emitTwoPhaseScanBody(cs, capScanAll, cs.twoPhaseFnOffset(capScanAll))
	if len(body) == 0 {
		t.Fatal("wide two-phase scan_all emitted an empty body")
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("body does not end with `end` (0x0B), got %#x", body[len(body)-1])
	}
	// The wide arm declares no locals and sums two calls; the narrow arms all
	// declare at least one. Byte 1 is the locals-group count, after the
	// size prefix — a cheap way to confirm which arm ran.
	if _, n, err := utils.DecodeULEB128(body); err == nil && body[n] != 0x00 {
		t.Errorf("wide arm declared %d locals groups, want 0 — the narrow arm ran",
			body[n])
	}
}

// TestSetEmitFindInnerFnOffsetWithoutWrapping covers the "not wrapped" answer
// of findInnerFnOffset.
//
// The offset is the index of the hidden body the exported `find` forwards
// into, and on a set whose `find` IS that body there is nothing to point at.
// -1 rather than a plausible index is what keeps a caller from emitting a call
// to whatever function happens to sit at len(capFns()).
//
// The set below is non-batching AND non-overlapping, which is what makes it
// unwrapped: an overlapping set whose shape qualifies for the answer cache is
// wrapped too, batching or not.
func TestSetEmitFindInnerFnOffsetWithoutWrapping(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find"}
	compiled := setEmitCovCompileSet(t, spec, []string{`alpha`, `bravo`}, CompileSetOptions{})
	if got := compiled.findInnerFnOffset(); got != -1 {
		t.Errorf("findInnerFnOffset() = %d on an unwrapped set, want -1", got)
	}

	batching := SetSpec{Name: "s", Find: "s_find", BatchFind: true}
	batched := setEmitCovCompileSet(t, batching, []string{`alpha`, `bravo`}, CompileSetOptions{})
	if got := batched.findInnerFnOffset(); got != len(batched.capFns()) {
		t.Errorf("findInnerFnOffset() = %d, want %d (immediately after the exported capabilities)",
			got, len(batched.capFns()))
	}
}

// TestSetEmitAssembleWithNoSetsMatchesAssembleModule pins the documented
// contract of assembleModuleWithSets: with no sets it produces the same bytes
// as assembleModule.
//
// Nothing reaches it through CompileFile — CompileFileDiag returns early to
// Compile when cfg.Sets is empty, precisely so the no-sets output stays
// byte-identical — so the delegation inside the sets assembler is only ever
// exercised from here. It is the safety net for that early return: if the
// early return were ever removed, this is what would catch the sets assembler
// producing different bytes.
func TestSetEmitAssembleWithNoSetsMatchesAssembleModule(t *testing.T) {
	for _, standalone := range []bool{true, false} {
		viaSets := assembleModuleWithSets(nil, nil, 1, standalone, nil, asmOpts{})
		direct := assembleModule(nil, 1, standalone, nil, asmOpts{})
		if string(viaSets) != string(direct) {
			t.Errorf("standalone=%v: assembleModuleWithSets(sets=nil) produced %d bytes, "+
				"assembleModule %d — the delegation no longer matches",
				standalone, len(viaSets), len(direct))
		}
	}
}

// setEmitCovShuftiSet builds a set whose frontend is Shufti with the ADAPTIVE
// density counter OFF.
//
// Shufti is selected from the scalar branch by either of two triggers, and
// which one fired decides whether the emitted body carries the adaptive
// counter: `shuftiAdaptive = likelyNoMatch && !rare`. The neighbouring
// coverage file reaches the LikelyNoMatch trigger; this one reaches the RARITY
// trigger, which turns the counter off. Control bytes have rarity 0, so a
// first-byte union drawn from them sums to 0 — far under the threshold of 40 —
// whereas the digits-and-uppercase union used next door sums to 66 and only
// ever arrives through the hint.
//
// Getting to the scalar branch at all needs both literal frontends to decline:
// past teddyMaxLiterals for Teddy, and ACBudgetBytes pinned to 1 for
// Aho-Corasick — an option BuildConfig does not expose, which is why this is
// built through CompileSet rather than through a config.
func setEmitCovShuftiSet(t *testing.T) *compiledSet {
	t.Helper()
	patterns := make([]string, teddyMaxLiterals+1)
	for i := range patterns {
		// First bytes cycle \x01..\x1f: 31 distinct, inside Shufti's 17..64
		// band, and every one of them rarity 0.
		patterns[i] = fmt.Sprintf("\\x%02xqq%02dxx[a-z]+", 1+i%31, i)
	}
	spec := SetSpec{Name: "s", Find: "s_find", MatchAny: "s_match_any", MatchAll: "s_match_all"}
	compiled := setEmitCovCompileSet(t, spec, patterns, CompileSetOptions{ACBudgetBytes: 1})
	if compiled.fe != frontendShufti {
		t.Fatalf("frontend = %v, want Shufti — this set no longer reaches the Shufti body", compiled.fe)
	}
	if compiled.shuftiAdaptive {
		t.Fatalf("Shufti was selected ADAPTIVELY; the rarity trigger, which is what " +
			"turns the density counter off, is not being reached")
	}
	return compiled
}

// TestSetEmitShuftiNonAdaptiveBody emits the Shufti body in its non-adaptive
// form, and reaches it through the frontend DISPATCHER rather than by calling
// the Shufti emitter directly.
//
// Two different things are pinned. The dispatcher's Shufti arm is one: it
// guards on there being no fallback bucket, and falling through to the scalar
// body when that guard misfires is a silent 17x fuel regression rather than a
// failure. The non-adaptive local frame is the other — it declares four local
// groups where the adaptive form declares five, and every branch depth in the
// body below is offset by one between the two, so mixing them up is an
// out-of-range br rather than a wrong answer.
func TestSetEmitShuftiNonAdaptiveBody(t *testing.T) {
	compiled := setEmitCovShuftiSet(t)
	base := compiled.funcCount()
	for _, mode := range []setCapKind{capFind, capScanAll, capScanAny} {
		body := emitSetMatchFnFinal(compiled, base, base, 0, mode, base)
		if len(body) == 0 {
			t.Fatalf("mode %v: the dispatcher produced an empty body", mode)
		}
		if body[len(body)-1] != 0x0B {
			t.Errorf("mode %v: body does not end with `end` (0x0B), got %#x",
				mode, body[len(body)-1])
		}
		// Fourteen i32 locals, not sixteen: the adaptive form's dense-gate
		// counter and its skip flag are absent.
		//
		// The count is of i32s, not of GROUPS, and that is a consequence of
		// allocating locals: the allocator coalesces adjacent same-type
		// runs, so both frames now declare five groups and the group count no
		// longer tells them apart. The i32 total does — it is exactly the two
		// locals the dense switch adds.
		if got := setEmitCovLocalsOfType(t, body, 0x7F); got != 14 {
			t.Errorf("mode %v: %d i32 locals, want 14 (the non-adaptive frame)", mode, got)
		}
	}
}

// setEmitCovLocalsOfType counts the locals of one value type declared by a
// size-prefixed WASM function body. It sums across groups on purpose: the
// allocator coalesces adjacent same-type runs, so which GROUP a local lands in
// is an encoding detail while how many of each type exist is the frame.
func setEmitCovLocalsOfType(t *testing.T, body []byte, ty byte) int {
	t.Helper()
	i := 0
	for i < len(body) && body[i]&0x80 != 0 {
		i++
	}
	i++ // the last size byte
	if i >= len(body) {
		t.Fatalf("body of %d bytes has no local declarations", len(body))
	}
	groups := int(body[i])
	i++
	n := 0
	for g := 0; g < groups; g++ {
		if i+1 >= len(body) {
			t.Fatalf("local group %d runs past the end of a %d-byte body", g, len(body))
		}
		count := int(body[i])
		if body[i+1] == ty {
			n += count
		}
		i += 2
	}
	return n
}

// TestSetEmitBTAdmissionRefusals covers admitBTFallback's refusals.
//
// Backtracking NARROWS the set of patterns a set has to drop; it does not
// empty it. Each refusal below leaves the caller's existing warn-and-drop in
// place, and a refusal that stopped firing would admit a pattern whose body
// cannot be built — so they are asserted at the predicate rather than through
// a compile that would merely lose the pattern either way.
func TestSetEmitBTAdmissionRefusals(t *testing.T) {
	if got := admitBTFallback(nil, 0); got != nil {
		t.Error("a nil AST was admitted to the Backtracking fallback")
	}

	// Past maxBTFallbackInstructions. A literal of N runes compiles to about N
	// instructions, which is the cheapest way to build a program of a known
	// size without tripping the parser's repeat limits.
	long := parseForBTFallback(t, strings.Repeat("a", maxBTFallbackInstructions+500))
	if got := admitBTFallback(long, 0); got != nil {
		t.Errorf("a %d-instruction program was admitted; the NFA size cap no longer refuses it",
			maxBTFallbackInstructions+500)
	}

	// A pattern the cap does admit, so the refusals above are not passing for
	// the wrong reason.
	ok := parseForBTFallback(t, `[0-9]+x`)
	if got := admitBTFallback(ok, 0); got == nil {
		t.Error("an ordinary pattern was refused; the cases above prove nothing")
	}
}

// parseForBTFallback parses a pattern into the AST shape admitBTFallback is
// given: captures stripped, since sets never report them.
//
// Parsed directly rather than through analyzePattern, because analyzePattern
// builds a DFA and refuses the very patterns this is used to test — the point
// of the Backtracking fallback is that it takes patterns no DFA budget will.
func parseForBTFallback(t *testing.T, pattern string) *syntax.Regexp {
	t.Helper()
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%.40q...): %v", pattern, err)
	}
	stripCaptures(parsed)
	return parsed
}

// TestSetEmitSetAdmitsBacktrackingSelection covers the predicate's NAMED
// selection and its error path.
//
// The predicate exists so the stub generators can decide which `_all` ABI a
// set exports WITHOUT compiling it, and getting it wrong is not a wrong answer
// but a wrong ARITY — a stub calling a three-parameter export with two. Its
// only production callers live in other modules, so the named-selection branch
// and the "this set cannot even be resolved" branch had nothing pinning them.
func TestSetEmitSetAdmitsBacktrackingSelection(t *testing.T) {
	entries := setEmitCovEntries([]string{`a+`, `[^\n]*ERROR`})
	byName := config.SetConfig{
		Name: "s", MatchAll: "s_match_all", Find: "s_find",
		Patterns: config.PatternSelector{Names: []string{"p00", "p01"}},
	}
	cramped := config.BuildConfig{
		Regexps: entries, Sets: []config.SetConfig{byName}, MaxFallbackStates: 1,
	}
	if !SetAdmitsBacktracking(byName, cramped) {
		t.Error("a NAMED selection of members that all land on Backtracking reported none")
	}

	// An unknown name cannot be resolved to a pattern, so the set cannot be
	// predicted at all. False is the safe answer: it says "narrow ABI", and
	// the compile that follows will fail on the same unknown name.
	unknown := byName
	unknown.Patterns = config.PatternSelector{Names: []string{"p00", "no_such_pattern"}}
	if SetAdmitsBacktracking(unknown, cramped) {
		t.Error("a set naming a pattern that does not exist was predicted to admit Backtracking")
	}

	// A pattern that cannot be analysed at all. The entry is deliberately
	// UNNAMED so the error path labels it by its pattern text instead — the
	// only branch where the label falls back that way.
	unparseable := config.BuildConfig{
		Regexps: []config.RegexEntry{{Pattern: `(unclosed`}},
		Sets: []config.SetConfig{{
			Name: "s", MatchAll: "s_match_all",
			Patterns: config.PatternSelector{All: true},
		}},
		MaxFallbackStates: 1,
	}
	if SetAdmitsBacktracking(unparseable.Sets[0], unparseable) {
		t.Error("a set whose only member does not parse was predicted to admit Backtracking")
	}
}

// TestSetEmitPlanBTRegionsMemo covers the BitState memo region.
//
// The shared regions are laid out as the MAX over every Backtracking bucket,
// and the memo is the one that may be absent: a program the engine can run
// without memoization gets no region at all, and one that needs it gets a
// region sized for the largest such program. Two buckets with different memo
// sizes is what distinguishes "took the max" from "took the first".
func TestSetEmitPlanBTRegionsMemo(t *testing.T) {
	// Nothing to lay out: no BT bucket, no regions.
	if got := planBTRegions([]*bucket{{isFallback: true}}, 0, &moduleGlobals{}); got != nil {
		t.Error("regions were planned for a set with no Backtracking bucket")
	}

	var withMemo []*bucket
	for _, pattern := range []string{`(?:a|ab)+c`, `(?:[0-9]|[0-9][0-9])+x`} {
		info := admitBTFallback(parseForBTFallback(t, pattern), 0)
		if info == nil {
			t.Fatalf("%q was refused by the Backtracking fallback", pattern)
		}
		withMemo = append(withMemo, &bucket{isFallback: true, btFallback: info})
	}
	regions := planBTRegions(withMemo, 0, &moduleGlobals{})
	if regions == nil {
		t.Fatal("no regions planned for two Backtracking buckets")
	}
	if regions.stackLimit <= regions.stackBase {
		t.Errorf("empty stack region: base %d, limit %d", regions.stackBase, regions.stackLimit)
	}
	// Everything above the stack must be laid out in order and inside `end`,
	// or two regions share an address and one silently overwrites the other.
	// The window pair is no longer among them: it is two module globals, so it
	// has no address to collide with.
	if regions.slotScratch < regions.stackLimit || regions.end <= regions.slotScratch {
		t.Errorf("regions overlap or run backwards: %+v", *regions)
	}
	if regions.winGlobal < 0 {
		t.Errorf("no window globals allocated for a BT bucket: %+v", *regions)
	}
	memoUsed := false
	for _, bkt := range withMemo {
		if bkt.btFallback.memoSize > 0 {
			memoUsed = true
		}
	}
	if memoUsed && regions.memoBase == 0 {
		t.Error("a bucket asked for a BitState memo but no memo region was placed")
	}
}

// TestSetEmitBTSuffixBodyRejectsBothTrailingParams: the gated and
// skip-carrying forms of a Backtracking suffix body each add ONE trailing
// parameter, and both want the same slot.
//
// They are mutually exclusive by construction — gating is `find && !overlapping`
// and the skip is `batch && overlapping` — so this panic is a promise about a
// combination the caller must never build. An unexercised promise is one
// nobody has checked, and the failure it prevents is a "local index out of
// bounds" at module validation, which is how it was originally caught.
func TestSetEmitBTSuffixBodyRejectsBothTrailingParams(t *testing.T) {
	info := admitBTFallback(parseForBTFallback(t, `[0-9]+x`), 0)
	if info == nil {
		t.Fatal("the witness pattern was refused by the Backtracking fallback")
	}
	regions := planBTRegions([]*bucket{{isFallback: true, btFallback: info}}, 0, &moduleGlobals{})
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("a body that is both gated and skip-carrying was accepted; " +
				"both forms want the same parameter slot")
		}
		if message, ok := recovered.(string); ok &&
			!strings.Contains(message, "gated") {
			t.Errorf("panic message %q does not say what was wrong", message)
		}
	}()
	buildSetBTSuffixBody(regions, 0, 0, 0, true, true, 0)
}

// TestSetEmitBTProbeBody emits a Backtracking bucket's probe.
//
// It used to drive an ANCHORED form as well — a full-consumption check for
// `match_*`. No caller ever passed it: compileAnchoredBuckets admits no BT
// bucket at all, so a BT-rescued pattern is simply absent from the anchored
// pair (docs/sets.md "Backtracking members and the anchored pair"). The
// parameter and its arm are gone, because dead machinery made a documented
// exclusion look like an oversight.
func TestSetEmitBTProbeBody(t *testing.T) {
	info := admitBTFallback(parseForBTFallback(t, `[0-9]+x`), 0)
	if info == nil {
		t.Fatal("the witness pattern was refused by the Backtracking fallback")
	}
	regions := planBTRegions([]*bucket{{isFallback: true, btFallback: info}}, 0, &moduleGlobals{})
	body := buildSetBTProbeBody(regions, 7, 0)
	if len(body) == 0 {
		t.Fatal("the Backtracking probe emitted nothing")
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("the probe does not end with `end` (0x0B), got %#x", body[len(body)-1])
	}
}

// TestSetEmitSuffixCallSkipDefault covers the constant-zero `skip` a non-batch
// caller passes.
//
// Once a set's suffix functions carry the batch skip parameter, EVERY caller
// passes one — the batch worker passes the real value, and anything else
// passes 0, which the suffix reads as "no tuple is skipped" because local tuple
// indices are never negative. Today the shared-worker rewrite (decision (11a))
// leaves the batching set with only the worker as a capFind caller, so the
// constant-zero arm has no production caller; it is emitted here directly
// because the arm is what makes adding a second caller safe.
func TestSetEmitSuffixCallSkipDefault(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find", BatchFind: true, Overlapping: true}
	compiled := setEmitCovCompileSet(t, spec, litLessNeverDying, CompileSetOptions{})
	if !compiled.suffixHasSkip {
		t.Fatal("this set's suffix functions carry no skip parameter; there is no arm to reach")
	}
	// batchPos is the transient flag emitSetWorkerBody sets around the worker;
	// with it clear, the context is an ordinary find caller.
	if compiled.batchPos {
		t.Fatal("batchPos is set outside worker emission")
	}
	ctx := newSetFindCtx(compiled, 0, 0, 0, capFind, 0)
	if ctx.hasSkip {
		t.Fatal("the context claims to carry a skip; the constant-zero arm is not reached")
	}
	withSkip := newSetFindCtxWithSkip(t, compiled)
	plain := ctx.emitSuffixCall(nil, 0, 0, ctx.lPos, 0x1)
	real := withSkip.emitSuffixCall(nil, 0, 0, withSkip.lPos, 0x1)
	if len(plain) == 0 || len(real) == 0 {
		t.Fatal("emitSuffixCall produced nothing")
	}
	if string(plain) == string(real) {
		t.Error("the constant-zero skip and the real one emitted identical bytes")
	}
}

// newSetFindCtxWithSkip builds the batch worker's context — the one that does
// carry a real skip — by setting the same transient flag emitSetWorkerBody
// sets.
func newSetFindCtxWithSkip(t *testing.T, compiled *compiledSet) *setFindCtx {
	t.Helper()
	compiled.batchPos = true
	defer func() { compiled.batchPos = false }()
	ctx := newSetFindCtx(compiled, 0, 0, 0, capFind, 0)
	if !ctx.hasSkip {
		t.Fatal("the worker context carries no skip")
	}
	return ctx
}

// TestSetEmitGateHelpersEmptySelection covers the two gate emitters' "this
// group selects nothing" answers.
//
// Both walk a bucket's patterns and act on the ones a mask selects. A mask
// that selects none of them is not a shape a compiled set produces — the
// groups are built FROM the masks — but the guards are what keep a future
// caller from emitting a gate load for a pattern index that is not in the
// bucket, which reads whatever i32 happens to sit at gate[garbage].
func TestSetEmitGateHelpersEmptySelection(t *testing.T) {
	// A gated find set: without it the emitters return immediately and the
	// per-pattern arms are never reached at all.
	spec := SetSpec{Name: "s", Find: "s_find"}
	compiled := setEmitCovCompileSet(t, spec, []string{`alpha`, `bravo`}, CompileSetOptions{})
	ctx := newSetFindCtx(compiled, 0, 0, 0, capFind, 0)
	if !ctx.readsGate() {
		t.Fatal("this set's find body reads no gate array; the emitters return early")
	}

	// An empty mask selects no pattern, so nothing is emitted.
	if got := ctx.emitGateMask(nil, 0, 0); len(got) != 0 {
		t.Errorf("emitGateMask with an empty mask emitted %d bytes", len(got))
	}
	if got := ctx.emitGateSkipSingle(nil, 0, prefixLenGroup{L: 0, mask: 0}); len(got) != 0 {
		t.Errorf("emitGateSkipSingle with an empty mask emitted %d bytes", len(got))
	}
	// A mask selecting a real pattern must emit something, so the checks above
	// are not passing because the emitters do nothing at all.
	if got := ctx.emitGateMask(nil, 0, 1); len(got) == 0 {
		t.Error("emitGateMask emitted nothing for a mask selecting pattern 0")
	}
	if got := ctx.emitGateSkipSingle(nil, 0, prefixLenGroup{L: 0, mask: 1}); len(got) == 0 {
		t.Error("emitGateSkipSingle emitted nothing for a mask selecting pattern 0")
	}
}

// TestSetEmitUnionScanTableLayouts drives the union automaton's transition
// emitter over the layouts a SMALL automaton never produces.
//
// One shared emitter serves both the scan body and the preflight's alive-mask
// pass, and it has to reproduce whatever geometry buildUnionScanDFA chose:
// byte-class compression above 32 KB, u16 state ids above 256 states, and a
// row length that is not a power of two (a multiply instead of a shift). Every
// union automaton in the matrix next door is single-digit states, uncompressed
// and u8 — so all three arms read the table with the wrong stride and nothing
// noticed.
//
// The shapes are chosen for the SIZE of their start-anywhere determinisation.
// `[ab].{6}[cd]` needs one state per subset of the last six positions that
// carried an `a` or `b`; a counted run of one class (`[0-9]{14}`) would not do
// it, since only the run length has to be remembered.
func TestSetEmitUnionScanTableLayouts(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		patterns       []string
		wantWidth      int
		wantCompressed bool
		wantShift      bool // true = power-of-two row, emitted as a shift
	}{
		{
			name: "compressed-u8", patterns: []string{`[ab].{6}[cd]`},
			wantWidth: 1, wantCompressed: true, wantShift: true,
		},
		{
			// Past 256 states, so ids are u16 and every entry is loaded two
			// bytes wide; five byte classes, so the row length is 10 and the
			// index needs a multiply.
			//
			// The repeat is {7}, not {6}: minimization made buildUnionScanDFA
			// MINIMIZE its automaton, and {6} drops from >256 states to 200 —
			// u8, which is not the layout this case exists to cover. {7}
			// minimizes to 496 and still exercises it. Any future change that
			// shrinks the automaton further will trip this same assertion,
			// which is the assertion working.
			name: "u16-and-non-power-of-two-row", patterns: []string{`[ab].{7}[cd]|[0-9]`},
			wantWidth: 2, wantCompressed: true, wantShift: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spec := SetSpec{Name: "s", ScanAny: "s_scan_any", ScanAll: "s_scan_all"}
			compiled := setEmitCovCompileSet(t, spec, testCase.patterns, CompileSetOptions{})
			automaton := compiled.unionScan
			if automaton == nil {
				t.Fatalf("no union automaton was built for %v (frontend %v)",
					testCase.patterns, compiled.fe)
			}
			if automaton.stateWidth != testCase.wantWidth {
				t.Errorf("state width %d, want %d (%d states): the layout this case "+
					"exists for is not being produced",
					automaton.stateWidth, testCase.wantWidth, automaton.numStates)
			}
			if compressed := automaton.numClasses < 256; compressed != testCase.wantCompressed {
				t.Errorf("compressed = %v (%d classes), want %v",
					compressed, automaton.numClasses, testCase.wantCompressed)
			}
			rowLen := automaton.numClasses * automaton.stateWidth
			if shift := shiftForRow(rowLen) >= 0; shift != testCase.wantShift {
				t.Errorf("row length %d: shift = %v, want %v", rowLen, shift, testCase.wantShift)
			}

			// And the module built from it: the emitter runs at assembly time,
			// so the geometry agreeing is only half the check.
			cfg := config.BuildConfig{
				Regexps: setEmitCovEntries(testCase.patterns),
				Sets: []config.SetConfig{{
					Name: "s", ScanAny: "s_scan_any", ScanAll: "s_scan_all",
					Find:     "s_find",
					Patterns: config.PatternSelector{All: true},
				}},
			}
			setEmitCovMustCompile(t, cfg)
		})
	}
}

// TestSetEmitOverlapPreflightShapeRefusals covers the two structural refusals
// of the overlapping `find` preflight.
//
// Both are about what the verdict is APPLIED through. It is written into the
// caller's gate array and read back as an i32 validMask, so:
//
//   - a SPARSE bucket is refused outright, because the sparse rule is that nothing
//     on the candidate path may read an i32 mask as authoritative for one;
//   - an id space past 64 is refused because the alive verdict itself is an
//     i64 mask, and an id with no bit in it could never be retired.
//
// Both refusals are silent — the set simply keeps the per-position walk — so
// they are asserted at the predicate.
func TestSetEmitOverlapPreflightShapeRefusals(t *testing.T) {
	// A literal-less family that packs into ONE bucket. Past 32 patterns the
	// packer promotes it to a per-state accept LIST, which is the sparse form.
	litLessFamily := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(`[0-9]{%d}[a-c]`, i+1)
		}
		return out
	}
	spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}

	sparse := setEmitCovCompileSet(t, spec, litLessFamily(40), CompileSetOptions{})
	sparseBuckets := 0
	for _, bkt := range sparse.buckets {
		if bkt.sparse {
			sparseBuckets++
		}
	}
	if sparseBuckets == 0 {
		t.Fatal("no sparse bucket: this set no longer reaches the sparse refusal")
	}
	if sparse.idSpaceSize() > 64 {
		t.Fatalf("id space %d: the WIDER refusal fires first and the sparse one is not reached",
			sparse.idSpaceSize())
	}
	if sparse.overlapPreflightShape() {
		t.Error("a sparse bucket was admitted to the preflight; its verdict is applied through an i32 mask")
	}

	wide := setEmitCovCompileSet(t, spec, litLessFamily(70), CompileSetOptions{})
	if wide.idSpaceSize() <= 64 {
		t.Fatalf("id space %d: this set no longer reaches the i64-mask refusal", wide.idSpaceSize())
	}
	if wide.overlapPreflightShape() {
		t.Error("an id space past 64 was admitted; the alive verdict is an i64 mask")
	}
}

// TestSetEmitOverlapDPColumnBound covers the sweep's per-byte cost bound.
//
// The DP column is states x patterns and is swept TWICE per input position, so
// it is the sweep's per-byte constant as much as its memory. A bucket that
// passes every structural test can still be far too expensive to sweep, and
// this is the only check that says so — the ones before it are all about
// whether the sweep would be CORRECT.
func TestSetEmitOverlapDPColumnBound(t *testing.T) {
	// Thirty patterns that pack into one bucket, each a distinct-length run of
	// alternating classes. Under 32 so the bucket stays a bitmask one (a
	// sparse promotion is refused earlier), but 30 x ~196 states is well past
	// the bound.
	patterns := make([]string, 30)
	for i := range patterns {
		patterns[i] = fmt.Sprintf(`(?:[0-9][a-c]){%d}`, 10+i*3)
	}
	spec := SetSpec{Name: "s", Find: "s_find", BatchFind: true, Overlapping: true}
	compiled := setEmitCovCompileSet(t, spec, patterns, CompileSetOptions{})
	if len(compiled.buckets) != 1 {
		t.Fatalf("%d buckets: the sweep is refused for a reason other than the column bound",
			len(compiled.buckets))
	}
	bkt := compiled.buckets[0]
	if bkt.sparse || !bkt.dp.ok || !bkt.dp.l.useU8 {
		t.Fatalf("bucket is sparse=%v dp.ok=%v useU8=%v: an earlier refusal fires first",
			bkt.sparse, bkt.dp.ok, bkt.dp.ok && bkt.dp.l.useU8)
	}
	if column := bkt.dp.numWASM * len(bkt.patterns); column <= overlapDPMaxColumn {
		t.Fatalf("column is %d, inside the bound of %d: this set no longer reaches the check",
			column, overlapDPMaxColumn)
	}
	if compiled.usesOverlapDP() {
		t.Error("a column past the bound was accepted; the sweep pays it on every input byte")
	}
}

// TestSetEmitPrefixCheckPerPatternGuard covers emitPrefixChecks over a bucket
// where the per-pattern parts actually differ.
//
// Three things only happen when one bucket holds patterns that disagree about
// their prefix:
//
//   - the per-BIT gate guard, emitted only when a group carries more than one
//     pattern and the body reads gates — without it a gated pattern's prefix
//     DFA is still called at a position it was excluded from;
//   - skipping a pattern that belongs to a DIFFERENT length group;
//   - skipping a pattern with no prefix function at all (trivial prefix).
//
// Every bucket in the matrix next door is either single-pattern or shares one
// prefix length, so none of the three is reached there. The shape needed is
// several patterns behind ONE shared mandatory literal, disagreeing about how
// many bytes come before it.
func TestSetEmitPrefixCheckPerPatternGuard(t *testing.T) {
	patterns := []string{
		`[a-c][d-f]SHAREDLIT`,      // prefix length 2
		`[g-i][j-l]SHAREDLIT`,      // prefix length 2 — same group, so the guard is per-bit
		`[m-o][p-r][s-u]SHAREDLIT`, // prefix length 3 — a second group
		`SHAREDLIT[0-9]`,           // trivial prefix: no prefix function to call
	}
	// GATED find: the per-bit guard is emitted only for a body that reads the
	// gate array.
	spec := SetSpec{Name: "s", Find: "s_find"}
	compiled := setEmitCovCompileSet(t, spec, patterns, CompileSetOptions{})

	target := -1
	for bi := range compiled.buckets {
		if len(compiled.buckets[bi].patterns) >= 3 {
			target = bi
			break
		}
	}
	if target < 0 {
		t.Fatal("no bucket holds three patterns; the shared-literal packing this test needs did not happen")
	}
	groups := compiled.prefixLenGroups[target]
	if len(groups) < 2 {
		t.Fatalf("bucket %d has %d prefix-length group(s); the cross-group skip is not reached",
			target, len(groups))
	}
	trivial := false
	for _, fnIdx := range compiled.prefixFnIdx[target] {
		if fnIdx < 0 {
			trivial = true
		}
	}
	if !trivial {
		t.Error("no trivial-prefix pattern in the bucket; the missing-prefix-function skip is not reached")
	}

	ctx := newSetFindCtx(compiled, 0, 0, 0, capFind, 0)
	if !ctx.readsGate() {
		t.Fatal("this find body reads no gate array; the per-bit guard is not emitted")
	}
	for _, group := range groups {
		if group.L == 0 {
			continue
		}
		if got := ctx.emitPrefixChecks(nil, target, group, ctx.lPos); len(got) == 0 {
			t.Errorf("group L=%d mask=%#x emitted no prefix checks", group.L, group.mask)
		}
	}

	// And the module: the emitter runs at assembly time.
	cfg := config.BuildConfig{
		Regexps: setEmitCovEntries(patterns),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	setEmitCovMustCompile(t, cfg)
}

// TestSetEmitBTLoopFrameRefusal covers the loop-frame-local cap.
//
// Backtracking narrows the set of patterns a set must drop; it does not empty
// it, and this is one of the two checks that keeps a pattern on the drop list.
// Every pushed backtrack frame snapshots ALL loop trackers, so the count is a
// per-frame cost the JIT pays — sixty-five chained non-greedy loops is well
// past what that can carry.
func TestSetEmitBTLoopFrameRefusal(t *testing.T) {
	// Non-greedy PLUS loops: each needs its own tracker. Greedy stars collapse
	// to a single tracker and would not reach the cap at any length.
	pattern := strings.Repeat(`(?:[a-z]+?)`, maxBTLoopFrameLocals+6) + `0`
	if got := admitBTFallback(parseForBTFallback(t, pattern), 0); got != nil {
		t.Errorf("a pattern with more than %d loop frame locals was admitted to Backtracking",
			maxBTLoopFrameLocals)
	}
}

// TestSetEmitPlanBTRegionsWithMemo places the BitState memo region.
//
// The memo is the one shared region that may be absent: a program the engine
// can run without memoization gets none. Two buckets that both want one is
// what distinguishes "took the max over the buckets" from "took the first" —
// and an under-sized memo is a silent out-of-bounds write into whatever
// follows it, not a validation error.
func TestSetEmitPlanBTRegionsWithMemo(t *testing.T) {
	// A non-greedy loop whose body can match empty is what needsBitState looks
	// for; the budget has to be non-zero or btAllocSizes has nothing to
	// allocate from.
	const memoBudget = 1 << 16
	var buckets []*bucket
	for _, pattern := range []string{`(?:a*?)+b`, `(?:.*?)+xyz`} {
		info := admitBTFallback(parseForBTFallback(t, pattern), memoBudget)
		if info == nil {
			t.Fatalf("%q was refused by the Backtracking fallback", pattern)
		}
		if !info.useMemo || info.memoSize == 0 {
			t.Fatalf("%q needs no BitState memo (useMemo=%v size=%d); the memo region is not reached",
				pattern, info.useMemo, info.memoSize)
		}
		buckets = append(buckets, &bucket{isFallback: true, btFallback: info})
	}
	regions := planBTRegions(buckets, 0, &moduleGlobals{})
	if regions == nil {
		t.Fatal("no regions planned for two Backtracking buckets")
	}
	if regions.memoBase == 0 {
		t.Fatal("both buckets asked for a BitState memo but no memo region was placed")
	}
	largest := 0
	for _, bkt := range buckets {
		if bkt.btFallback.memoSize > largest {
			largest = bkt.btFallback.memoSize
		}
	}
	// memoBase points past the header word, so the region starts one header
	// below it — that is what has to hold the largest bucket's reservation.
	// slotScratch is what follows the memo now that the window pair is two
	// globals rather than eight table bytes.
	if int(regions.slotScratch-(regions.memoBase-btMemoHeaderBytes)) < largest {
		t.Errorf("memo region is %d bytes, smaller than the largest bucket's %d",
			regions.slotScratch-(regions.memoBase-btMemoHeaderBytes), largest)
	}
}

// TestSetEmitPreflightWithNoPatterns covers the empty-set guard in the
// preflight emitter.
//
// The pass writes one gate slot per pattern id, and with no ids there is
// nothing to write — but it also READS slot ids[0] to decide whether the drive
// is fresh, so without this guard an empty set indexes gate[-1]. A set with no
// surviving members is not something a config produces today (the shape
// predicates refuse it earlier), so the emitter is called on an empty
// compiledSet directly.
//
// One emitter, not two: the gated body was given the overlapping
// body's alive-marking write-back, at which point the two were the same code.
func TestSetEmitPreflightWithNoPatterns(t *testing.T) {
	empty := &compiledSet{}
	if got := emitFindPreflight(nil, empty, 8, 9, 10, 3, 1, 2, 13, 0, false, 11, 12, 14); len(got) != 0 {
		t.Errorf("the preflight emitted %d bytes for a set with no patterns", len(got))
	}
}

// TestSetEmitScanAnyCapabilityArms emits the bodies for capScanAny.
//
// It used to drive capScan — the retired boolean `scan:` key's kind (TODO task
// 59 decision (2)). That kind, and its arms in five files, are gone:
// capFns() never produced it, so the arms were unreachable code the reader had
// to disprove. Retargeted at capScanAny, which is the
// capability those switches really serve, so the coverage of each switch
// survives the deletion.
func TestSetEmitScanAnyCapabilityArms(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find", ScanAny: "s_scan_any", ScanAll: "s_scan_all"}
	compiled := setEmitCovCompileSet(t, spec, litLessNeverDying, CompileSetOptions{})
	if compiled.unionScan == nil {
		t.Fatal("no union automaton was built; the union body cannot be emitted")
	}
	body := emitUnionScanBody(compiled.unionScan, capScanAny, compiled.fullIDMask(), 0, false)
	if len(body) == 0 || body[len(body)-1] != 0x0B {
		t.Errorf("the capScanAny union body is empty or unterminated (%d bytes)", len(body))
	}

	ctx := newSetFindCtx(compiled, 0, 0, 0, capScanAny, 0)
	if got := ctx.emitRecordProbe(nil, 0); len(got) == 0 {
		t.Error("emitRecordProbe emitted nothing for capScanAny")
	}
	if got := ctx.emitEpilogue(nil); len(got) == 0 {
		t.Error("emitEpilogue emitted nothing for capScanAny")
	}
	if got := ctx.emitDrainCheck(nil, ctx.lPos, 1); len(got) == 0 {
		t.Error("emitDrainCheck emitted nothing for capScanAny")
	}

	// The SPARSE probe recorder is a separate switch with its own arm,
	// and it needs a bucket whose accept is a per-state list rather than a
	// mask — which needs more than 32 patterns behind one literal.
	sparsePatterns := make([]string, 40)
	for i := range sparsePatterns {
		sparsePatterns[i] = fmt.Sprintf(`SHAREDKEY[0-9]{%d}`, i+1)
	}
	sparseSpec := SetSpec{Name: "s", Find: "s_find", ScanAny: "s_scan_any", ScanAll: "s_scan_all"}
	sparseSet := setEmitCovCompileSet(t, sparseSpec, sparsePatterns, CompileSetOptions{})
	sparseBucket := -1
	for bi := range sparseSet.buckets {
		if sparseSet.buckets[bi].sparse {
			sparseBucket = bi
			break
		}
	}
	if sparseBucket < 0 {
		t.Fatal("no sparse bucket: the sparse probe recorder is not reached")
	}
	sparseCtx := newSetFindCtx(sparseSet, 0, 0, 0, capScanAny, 0)
	if got := sparseCtx.emitRecordProbe(nil, sparseBucket); len(got) == 0 {
		t.Error("emitRecordProbe emitted nothing for a sparse bucket under capScanAny")
	}
}

// TestSetEmitACNodeIDSpaceDemotion covers the Aho-Corasick node-count ceiling.
//
// Node ids are u16 in the goto table, and COMPRESSION can fit far more nodes
// into the byte budget than that id space can address — so the two limits are
// checked separately, and this is the one no ordinary set reaches. Passing the
// budget while failing this would emit a table whose ids wrap: a goto to node
// 65537 lands on node 1, which is a silently wrong scan rather than a build
// error.
//
// The demotion to scalar must also be RECORDED. A frontend that silently
// downgrades is the silent-downgrade failure mode — the set still answers correctly, it
// just answers many times slower, and nothing says why.
//
// This case costs a few seconds because there is no cheaper way to build
// 65,536 automaton nodes: the ceiling is a property of the literal bytes, and
// the literals have to be really compiled to get there.
func TestSetEmitACNodeIDSpaceDemotion(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 69,000-node Aho-Corasick automaton")
	}
	// Enough total literal bytes to pass acMaxNodes with the shortest literals
	// that get there — per-pattern cost grows faster in literal LENGTH than in
	// pattern count, so many short literals is the cheap corner.
	const patternCount, literalLen = 1600, 48
	patterns := make([]string, patternCount)
	for i := range patterns {
		// A shared first byte keeps first-byte diversity below the crossover,
		// so Aho-Corasick is chosen over Teddy in the first place.
		patterns[i] = fmt.Sprintf("k%05d", i) + strings.Repeat("q", literalLen-6)
	}
	spec := SetSpec{Name: "s", ScanAny: "s_scan_any"}
	compiled := setEmitCovCompileSet(t, spec, patterns, CompileSetOptions{})
	if compiled.fe != frontendScalar {
		t.Fatalf("frontend = %v, want scalar: the node ceiling did not demote", compiled.fe)
	}
	demotion := compiled.diag.FrontendDemotion
	if demotion == nil {
		t.Fatal("the frontend was downgraded with no diagnostic — a silent downgrade is the failure mode")
	}
	if demotion.Reason != "ac_nodes_exceed_u16" {
		t.Errorf("demotion reason = %q, want \"ac_nodes_exceed_u16\" (got %v nodes); "+
			"this set now trips a different limit and the u16 id-space check is unreached",
			demotion.Reason, demotion.Detail["ac_nodes"])
	}
}

// TestSetEmitJumpProfitabilityIgnoresUnrecoverablePattern covers the
// "cannot recover this pattern's AST" arm of jumpIsProfitable.
//
// The predicate decides whether the gate-jump prologue is worth emitting by
// asking each member how long a match it can produce, and a pattern it cannot
// re-parse has no answer. Skipping it is the only safe reading: the jump only
// fires when EVERY pattern is gated past `from`, so treating an unknown as
// "no opinion" cannot make the scan skip a position a match could start at.
//
// A PatternInfo whose pattern does not parse cannot arrive from a config —
// analyzePattern parses first — so the bucket list is built by hand here. It
// is the shape a future caller of this predicate could produce, not a state
// the compiler reaches today.
func TestSetEmitJumpProfitabilityIgnoresUnrecoverablePattern(t *testing.T) {
	unrecoverable := &compiledSet{
		fe: frontendScalar,
		buckets: []*bucket{{
			isFallback: true,
			patterns:   []*PatternInfo{{fullPattern: `(unclosed`, globalID: 0}},
		}},
	}
	if unrecoverable.jumpIsProfitable() {
		t.Error("a pattern whose AST could not be recovered was counted as evidence for the gate jump")
	}
}

// Set-composition core: the branches CompileSet reaches only at its edges.
//
// The set matrix in set_module_test.go compiles whole sets and so
// covers the HAPPY paths of set.go, set_caps.go, set_probe.go, startable.go and
// set_sparse.go thoroughly. What it cannot reach are the refusals: a merge that
// blows the helper DFA state limit, a pattern the Backtracking fallback also
// declines, a promotion candidate disqualified by one member, an emitter arm
// selected by a flag no YAML config can currently set. Those are exactly the
// paths whose regression is silent — a dropped set member is a missing match,
// not a build error — so they are driven here by calling the composition
// functions directly with the shape that selects them.
//
// Each case names the branch it exists for. Where a shape cannot arise from a
// config today, the comment says so explicitly rather than implying the test
// proves reachability.

// setCoreCovAnalyze runs analyzePattern over fresh dedup pools, which is how
// every set packer receives its PatternInfos.
func setCoreCovAnalyze(t *testing.T, pattern string) *PatternInfo {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: pattern}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern(%q): %v", pattern, err)
	}
	return info
}

// setCoreCovAnalyzeAll shares ONE pair of pools across the patterns, the way
// CompileSet does, so suffix dedup behaves as it would in a real set.
func setCoreCovAnalyzeAll(t *testing.T, patterns ...string) []*PatternInfo {
	t.Helper()
	var prefixPool, suffixPool dfaPool
	infos := make([]*PatternInfo, len(patterns))
	for i, pattern := range patterns {
		info, err := analyzePattern(config.RegexEntry{Pattern: pattern}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pattern, err)
		}
		infos[i] = info
	}
	return infos
}

// setCoreCovIDs returns 0..n-1, the id vector a bucket of n patterns gets when
// the set selects every pattern.
func setCoreCovIDs(n int) []int {
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i
	}
	return ids
}

// setCoreCovOversizedPair is two patterns that each compile to a ~1500-state
// DFA on their own — comfortably inside maxHelperDFAStates (2048) — but whose
// UNION needs ~3000, because their first bytes are disjoint so the merged
// automaton can share nothing. That is the only way to make a merge fail while
// both members remain individually admissible, which is what every
// "merge returned an error, keep looking" branch needs.
var setCoreCovOversizedPair = []string{
	`[a-z]{1000}[0-9]{500}`,
	`[0-9]{1000}[a-z]{500}`,
}

// --------------------------------------------------------------------------
// Small predicates and option accessors

func TestSetCoreOptionMaxPatternsPerBucket(t *testing.T) {
	// The sparse packers reject a promotion whose total exceeds this, so an
	// explicit override has to win over the 4096 default or a caller cannot
	// bound a WAF-scale bucket at all.
	if got := (CompileSetOptions{MaxPatternsPerBucket: 77}).maxPatternsPerBucket(); got != 77 {
		t.Errorf("maxPatternsPerBucket with override = %d, want 77", got)
	}
	if got := (CompileSetOptions{}).maxPatternsPerBucket(); got != 4096 {
		t.Errorf("maxPatternsPerBucket default = %d, want 4096", got)
	}
}

func TestSetCoreDFATableEqualTransitionLength(t *testing.T) {
	// dfaPool.Add treats a fingerprint collision as "compare byte for byte",
	// and the comparison must not index past the shorter table. Two tables
	// agreeing on every scalar header field but differing in transition-slice
	// length is the shape that reaches that guard.
	left := &dfaTable{numStates: 1, transitions: make([]int, 256)}
	right := &dfaTable{numStates: 1, transitions: make([]int, 512)}
	if dfaTableEqual(left, right) {
		t.Error("dfaTableEqual returned true for tables of different transition length")
	}
}

func TestSetCoreStrippedAnchorKind(t *testing.T) {
	// strippedAnchorKind classifies a prefix that is about to be REPLACED by
	// an eligibility mask, so both degenerate answers matter: a nil prefix
	// (nothing was stripped) and a prefix carrying no begin-anchor at all must
	// both yield "no restriction", never a mask that forbids positions.
	if got := strippedAnchorKind(nil); got != beginAnchorNone {
		t.Errorf("strippedAnchorKind(nil) = %v, want beginAnchorNone", got)
	}
	if got := strippedAnchorKind(mustParse(t, `[a-z]`)); got != beginAnchorNone {
		t.Errorf("strippedAnchorKind([a-z]) = %v, want beginAnchorNone", got)
	}
	if got := strippedAnchorKind(mustParse(t, `\Aabc`)); got != beginAnchorText {
		t.Errorf(`strippedAnchorKind(\Aabc) = %v, want beginAnchorText`, got)
	}
}

func TestSetCoreSetTopLevelAnchor(t *testing.T) {
	// The \A arm: a top-level begin-text anchor restricts the pattern to
	// position 0, and emitGroupMask reads startAnchor to build that mask. The
	// (?m:^) arm is covered by the set matrix; this is its stricter sibling.
	var info PatternInfo
	info.setTopLevelAnchor(mustParse(t, `\Aabc`))
	if !info.startAnchor {
		t.Error(`setTopLevelAnchor(\Aabc) did not set startAnchor`)
	}
	if info.lineAnchor {
		t.Error(`setTopLevelAnchor(\Aabc) set lineAnchor; \A is not a line anchor`)
	}

	// The (?m:^) arm must NOT collapse to startAnchor. Doing so made the
	// eligibility mask STRICTER than the assertion — position 0 only, where
	// the pattern also matches after any newline — which is
	var lineInfo PatternInfo
	lineInfo.setTopLevelAnchor(mustParse(t, `(?m:^)abc`))
	if !lineInfo.lineAnchor {
		t.Error("setTopLevelAnchor((?m:^)abc) did not set lineAnchor")
	}
	if lineInfo.startAnchor {
		t.Error("setTopLevelAnchor((?m:^)abc) set startAnchor; that forbids every position but 0")
	}
}

func TestSetCoreAssertionScans(t *testing.T) {
	// Both scans guard a SPLIT decision — a prefix carrying either assertion
	// cannot be verified by the backward prefix DFA — so a false negative
	// silently loses or invents matches. The nil and recursive arms are what
	// a real AST walk hits on every non-leaf node.
	if regexpHasWordBoundary(nil) {
		t.Error("regexpHasWordBoundary(nil) = true")
	}
	if regexpHasEndAssertion(nil) {
		t.Error("regexpHasEndAssertion(nil) = true")
	}
	if !regexpHasEndAssertion(mustParse(t, `abc$`)) {
		t.Error("regexpHasEndAssertion(abc$) = false")
	}
	if !regexpHasEndAssertion(mustParse(t, `(?:abc(?:d\z))`)) {
		t.Error(`regexpHasEndAssertion of a nested \z = false`)
	}
	if regexpHasEndAssertion(mustParse(t, `abc`)) {
		t.Error("regexpHasEndAssertion(abc) = true")
	}
}

func TestSetCorePatternASTHelpersOnUnparseablePattern(t *testing.T) {
	// Both helpers re-parse PatternInfo.fullPattern from scratch, and both are
	// called from packers that must not panic on the result. analyzePattern
	// parsed it once already, so a failure here means the string was rewritten
	// between the two — the helpers answer nil and the packers drop the
	// pattern with a diagnostic rather than dereferencing.
	broken := &PatternInfo{fullPattern: `(unclosed`}
	if got := patternSuffixAST(broken); got != nil {
		t.Errorf("patternSuffixAST on an unparseable pattern = %v, want nil", got)
	}
	if got := patternFullAST(broken); got != nil {
		t.Errorf("patternFullAST on an unparseable pattern = %v, want nil", got)
	}
}

func TestSetCoreAssignTeddyLanesShortLiteral(t *testing.T) {
	// Above 16 literals the lanes are shared by low-nibble key, and the key is
	// truncated to the literal's own length when it is shorter than the probe
	// window. Without that clamp a 1-byte literal in a 3-byte-probe set reads
	// past its own bytes.
	literals := make([][]byte, 0, 20)
	literals = append(literals, []byte("a")) // shorter than minProbe
	for i := 0; i < 19; i++ {
		literals = append(literals, []byte{byte('b' + i), 'x', 'y', 'z'})
	}
	lanes := assignTeddyLanes(literals, 3)
	if len(lanes) != len(literals) {
		t.Fatalf("assignTeddyLanes returned %d lanes for %d literals", len(lanes), len(literals))
	}
	for i, lane := range lanes {
		if lane < 0 || lane > 15 {
			t.Errorf("literal %d assigned lane %d, outside 0..15", i, lane)
		}
	}
}

// --------------------------------------------------------------------------
// Merge refusals
//
// All four merge entry points share the same three refusals — empty input, too
// many patterns for the accept form, and a union DFA over maxHelperDFAStates —
// and every caller treats an error as "do not pack here". A refusal that
// stopped being an error would instead return a nil table the caller then
// dereferences.

func TestSetCoreMergeSuffixDFASparseSetRejects(t *testing.T) {
	if _, _, err := mergeSuffixDFASparseSet(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeSuffixDFASparseSet(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	// maxPatternsPerBucket is the sparse form's own ceiling; the u16 accept
	// lists cannot address past it.
	if _, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{MaxPatternsPerBucket: 2}); err == nil {
		t.Error("mergeSuffixDFASparseSet past maxPatternsPerBucket returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, _, err := mergeSuffixDFASparseSet(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeSuffixDFASparseSet over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

func TestSetCoreMergeAnchoredDFARejects(t *testing.T) {
	if _, err := mergeAnchoredDFA(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeAnchoredDFA(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	// The anchored bitmask form is capped by bitmaskWidth exactly as the find
	// one is: bit k of the returned mask IS bucket-local index k.
	if _, err := mergeAnchoredDFA(asts, CompileSetOptions{BitmaskWidth: 2}); err == nil {
		t.Error("mergeAnchoredDFA past bitmaskWidth returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, err := mergeAnchoredDFA(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeAnchoredDFA over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

func TestSetCoreMergeAnchoredDFASparseSetRejects(t *testing.T) {
	if _, _, err := mergeAnchoredDFASparseSet(nil, CompileSetOptions{}); err == nil {
		t.Error("mergeAnchoredDFASparseSet(nil) returned no error")
	}

	asts := make([]*syntax.Regexp, 4)
	for i := range asts {
		asts[i] = mustParse(t, `a`)
	}
	if _, _, err := mergeAnchoredDFASparseSet(asts, CompileSetOptions{MaxPatternsPerBucket: 2}); err == nil {
		t.Error("mergeAnchoredDFASparseSet past maxPatternsPerBucket returned no error")
	}

	big := []*syntax.Regexp{
		mustParse(t, setCoreCovOversizedPair[0]),
		mustParse(t, setCoreCovOversizedPair[1]),
	}
	if _, _, err := mergeAnchoredDFASparseSet(big, CompileSetOptions{}); err != ErrDFAStateLimit {
		t.Errorf("mergeAnchoredDFASparseSet over the helper state limit: err = %v, want ErrDFAStateLimit", err)
	}
}

// --------------------------------------------------------------------------
// analyzePattern refusals

func TestSetCoreAnalyzePatternPrefixAssertionsRouteToFallback(t *testing.T) {
	// The backward prefix DFA carries no word-boundary context and drops
	// end-of-text assertions outright, so a prefix containing either cannot be
	// verified by it. Both must therefore lose the split entirely — keeping
	// prefixAST while clearing splittable is what made a set member silently
	// never match.
	cases := []struct {
		pattern string
		why     string
	}{
		{`[a-z]\bkeyword`, `a \b at the prefix's right edge: the backward walk cannot see input[start-1]`},
		{`[a-z]$keyword`, `an end assertion in the prefix: reverseRegexp drops it and the walk INVENTS matches`},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			info := setCoreCovAnalyze(t, tc.pattern)
			if info.splittable {
				t.Errorf("%s: splittable = true; %s", tc.pattern, tc.why)
			}
			if info.prefixAST != nil || info.suffixAST != nil {
				t.Errorf("%s: split ASTs retained (prefix=%v suffix=%v) after the split was rejected",
					tc.pattern, info.prefixAST, info.suffixAST)
			}
		})
	}
}

func TestSetCoreAnalyzePatternStateLimits(t *testing.T) {
	// A set member whose own helper DFA cannot be built is an ERROR, not a
	// silent drop: CompileFile reports it and the pattern stays out of the
	// set. Three chained {1000} repeats give a 3001-state chain against
	// maxHelperDFAStates == 2048.
	//
	// This covers the SUFFIX direction only. The matching prefix branch could
	// not be reached: findMandatoryLitRec refuses any literal past offset 256,
	// so a prefix is at most 256 bytes, and the prefix DFA is built by
	// determinising the REVERSED prefix — which by Brzozowski's theorem yields
	// the MINIMAL DFA of the reversed prefix language. Every natural
	// fixed-length prefix (chains, counted classes, keyword alternations)
	// therefore minimises well below 2048: a 2730-word 12-byte alternation
	// measured 705 states. Reaching the limit needs a language deliberately
	// built to have thousands of distinct residuals, not a pattern anyone
	// would write, so the branch is left uncovered rather than faked.
	const chain = `[a-z]{1000}[0-9]{1000}[a-z]{1000}`

	var prefixPool, suffixPool dfaPool
	_, err := analyzePattern(config.RegexEntry{Pattern: chain}, &prefixPool, &suffixPool)
	if err == nil {
		t.Fatal("analyzePattern with an over-limit SUFFIX returned no error")
	}
	if !strings.Contains(err.Error(), "suffix") {
		t.Errorf("suffix state-limit error should name the suffix; got %v", err)
	}
}

// --------------------------------------------------------------------------
// compileFallback: the drop and re-pack branches

// setCoreCovIsolatedUnbuildable is non-greedy — so analyzePattern isolates it
// and returns EARLY, leaving suffixDFA nil for compileFallback to build — and
// its own merge then fails too. Dereferencing the nil that results was a crash.
// The 13 chained nullable loops are what make the Backtracking fallback refuse
// it as well (maxBTEmptyBodyGreedyLoops == 12), so it reaches the warn-and-drop
// rather than being admitted on BT.
var setCoreCovIsolatedUnbuildable = `a*?` + strings.Repeat(`(?:a|)*`, 13) +
	`[a-z]{1000}[0-9]{1000}[a-z]{1000}`

// setCoreCovIsolatedBTRefused is non-greedy and BT-refused like the above, but
// its DFA is small enough to BUILD — it is only over an artificially low
// max_fallback_states. That separates the two isolated-bucket drop branches:
// "no DFA at all" and "a DFA that is too big".
var setCoreCovIsolatedBTRefused = `a*?` + strings.Repeat(`(?:a|)*`, 13) + `[a-z]{20}`

func TestSetCoreCompileFallbackIsolatedDropsWhenDFAUnbuildable(t *testing.T) {
	info := setCoreCovAnalyze(t, setCoreCovIsolatedUnbuildable)
	if !info.isolatedFallback {
		t.Fatalf("pattern is not isolated; the non-greedy detection this case depends on has moved")
	}
	if info.suffixDFA != nil {
		t.Fatal("an isolated pattern should reach compileFallback with suffixDFA nil")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "isolated-unbuildable"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileFallbackIsolatedOverStateLimit(t *testing.T) {
	// Same isolated branch, one step further along: the DFA builds but exceeds
	// max_fallback_states. BT is offered the pattern first and refuses, so the
	// warn-and-drop arm runs.
	info := setCoreCovAnalyze(t, setCoreCovIsolatedBTRefused)
	if !info.isolatedFallback {
		t.Fatalf("pattern is not isolated; the non-greedy detection this case depends on has moved")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "isolated-over-limit"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	out := buf.String()
	if !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
	if !strings.Contains(out, "limit=8") {
		t.Errorf("warning should name the limit that was exceeded; got %q", out)
	}
}

func TestSetCoreCompileFallbackIsolatedAdmittedToBT(t *testing.T) {
	// The positive half of both isolated drop branches: a non-greedy member
	// the DFA path cannot serve is ADMITTED on Backtracking rather than
	// dropped, so it keeps behaving like the same pattern compiled alone.
	// Which branch offers it to BT depends on why the DFA path failed, and
	// both offers have to exist — an admission wired into only one of them
	// leaves the other silently dropping members.
	cases := []struct {
		name    string
		pattern string
		opts    CompileSetOptions
		why     string
	}{
		{
			name:    "own-dfa-unbuildable",
			pattern: `a*?[a-z0-9]{200}`,
			opts:    CompileSetOptions{},
			why:     "the isolated merge exceeds maxHelperDFAStates, so there is no table to size",
		},
		{
			name:    "over-max-fallback-states",
			pattern: `a*?bcdefghijkl`,
			opts:    CompileSetOptions{MaxFallbackStates: 8},
			why:     "the isolated DFA builds but is larger than max_fallback_states",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := setCoreCovAnalyze(t, tc.pattern)
			if !info.isolatedFallback {
				t.Fatalf("%q is not isolated; the non-greedy detection this case depends on has moved",
					tc.pattern)
			}

			buf, restore := captureWarnings(t)
			defer restore()

			buckets := compileFallback([]*PatternInfo{info}, tc.opts, nil)
			if len(buckets) != 1 || buckets[0].btFallback == nil {
				t.Fatalf("%s: expected one Backtracking bucket, got %d buckets (%s)",
					tc.name, len(buckets), tc.why)
			}
			// A BT bucket answers for patternIDs[bi][0] and validMask bit 0
			// alone, so a second member packed into it would have no emitted
			// code at all in any bucketed capability.
			if n := len(buckets[0].patterns); n != 1 {
				t.Errorf("%s: BT bucket holds %d patterns, want exactly 1", tc.name, n)
			}
			if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
				t.Errorf("%s: a BT-admitted pattern must not warn about being dropped; got %q", tc.name, out)
			}
		})
	}
}

// setCoreCovNullableUnbuildable has minLen 0, so analyzePattern returns early
// with suffixDFA nil — the NON-isolated twin of the case above. Its own merge
// then fails and BT refuses it, which is the sibling guard that was missing for
// years while the isolated branch carried it.
var setCoreCovNullableUnbuildable = strings.Repeat(`(?:a|)*`, 13) +
	`(?:[a-z]{1000}[0-9]{1000}[a-z]{1000})?`

func TestSetCoreCompileFallbackNewBucketDFAUnbuildable(t *testing.T) {
	info := setCoreCovAnalyze(t, setCoreCovNullableUnbuildable)
	if info.isolatedFallback {
		t.Fatal("pattern took the ISOLATED branch; this case exists for the non-isolated one")
	}
	if info.suffixDFA != nil {
		t.Fatal("a minLen==0 pattern should reach compileFallback with suffixDFA nil")
	}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "nullable-unbuildable"}
	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, diag)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern dropped (0 buckets), got %d", len(buckets))
	}
	if len(diag.StateLimitDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: StateLimitDropped = %v", diag.StateLimitDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileFallbackMergeRefusalStartsNewBucket(t *testing.T) {
	// Two fallback patterns that cannot share a bucket because their union DFA
	// is unbuildable. The packer must keep looking and open a second bucket —
	// treating the merge error as "unpackable, drop it" would lose a member.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	opts := CompileSetOptions{MaxFallbackStates: 2048}
	buckets := compileFallback(infos, opts, nil)

	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets (the merge must be refused), got %d", len(buckets))
	}
	for i, bkt := range buckets {
		if len(bkt.patterns) != 1 {
			t.Errorf("bucket %d holds %d patterns, want 1", i, len(bkt.patterns))
		}
		if !bkt.isFallback {
			t.Errorf("bucket %d is not marked isFallback", i)
		}
	}
}

// --------------------------------------------------------------------------
// binPack

func TestSetCoreBinPackCountedChainConflictUnderLikelyMatch(t *testing.T) {
	// Under LikelyMatch two counted-class-chain patterns must NOT share
	// a bucket, because isCountedClassChain needs a single-pattern suffix DFA
	// and merging them costs both the SIMD-verify suffix body. The conflict is
	// recorded in --diag-json so the split is explainable.
	infos := setCoreCovAnalyzeAll(t, `KEY[0-9]{4}`, `KEY[A-Z0-9]{16}`)
	for _, info := range infos {
		if _, _, ok := isCountedClassChain(info.suffixDFA); !ok {
			t.Fatalf("%q: suffix is not a counted class chain; this case no longer selects the counted-chain split",
				info.fullPattern)
		}
	}

	diag := &SetDiag{Name: "lm-counted-chain"}
	buckets := binPack(infos, CompileSetOptions{LikelyMode: LikelyMatch}, diag)

	if len(buckets) != 2 {
		t.Fatalf("expected the two chains kept apart (2 buckets), got %d", len(buckets))
	}
	found := false
	for _, conflict := range diag.Conflicts {
		if conflict.Reason == "lm_counted_chain_split" {
			found = true
		}
	}
	if !found {
		t.Errorf("no lm_counted_chain_split conflict recorded; conflicts = %+v", diag.Conflicts)
	}

	// Without the hint the same two patterns share one bucket, which is what
	// makes the split above attributable to LikelyMode rather than to the
	// budgets.
	neutral := binPack(setCoreCovAnalyzeAll(t, `KEY[0-9]{4}`, `KEY[A-Z0-9]{16}`),
		CompileSetOptions{}, nil)
	if len(neutral) != 1 {
		t.Errorf("without LikelyMatch the two chains should merge into 1 bucket, got %d", len(neutral))
	}
}

func TestSetCoreBinPackMergeRefusalStartsNewBucket(t *testing.T) {
	// The same merge refusal as the fallback packer's, in the literal-group
	// packer: both patterns share the mandatory literal "KEY" but their suffix
	// union is unbuildable, so the group must split rather than lose a member.
	infos := setCoreCovAnalyzeAll(t,
		`KEY`+setCoreCovOversizedPair[0],
		`KEY`+setCoreCovOversizedPair[1],
	)
	for _, info := range infos {
		if info.mandLit == nil || !info.splittable {
			t.Fatalf("%q did not split at a mandatory literal; this case no longer reaches binPack's literal group",
				info.fullPattern)
		}
	}
	buckets := binPack(infos, CompileSetOptions{}, nil)
	if len(buckets) != 2 {
		t.Fatalf("expected the shared-literal group to split (2 buckets), got %d", len(buckets))
	}
	for i, bkt := range buckets {
		if bkt.literal != "KEY" {
			t.Errorf("bucket %d literal = %q, want %q", i, bkt.literal, "KEY")
		}
	}
}

// --------------------------------------------------------------------------
// Sparse promotion policy

func TestSetCorePromoteSharedLiteralBucketsDeclines(t *testing.T) {
	// Two shapes gain nothing and must be returned untouched: no buckets at
	// all, and a group whose first bucket has an empty literal — which means
	// the caller handed over the FALLBACK group, whose own promotion call site
	// passes isFallback and must not be reached through this one.
	if got := promoteSharedLiteralBuckets(nil, CompileSetOptions{AllowSparseAccept: true}); got != nil {
		t.Errorf("promoteSharedLiteralBuckets(nil) = %v, want nil", got)
	}
	fallbackGroup := []*bucket{{literal: "", isFallback: true}, {literal: "", isFallback: true}}
	got := promoteSharedLiteralBuckets(fallbackGroup, CompileSetOptions{AllowSparseAccept: true})
	if len(got) != 2 {
		t.Errorf("a fallback group must be returned unchanged; got %d buckets, want 2", len(got))
	}
}

// setCoreCovFallbackPromotion is the promotion strategy the FALLBACK packer
// uses, which is the one whose refusals matter most: a fallback bucket runs at
// every input position, so a refused promotion costs a full extra walk per byte.
var setCoreCovFallbackPromotion = sparsePromotion{
	astFor:     patternSuffixAST,
	merge:      mergeSuffixDFASparseSet,
	isFallback: true,
}

// setCoreCovBucketOf wraps one analyzed pattern in a literal-less bucket, the
// shape compileFallback hands to promoteSparseBuckets.
func setCoreCovBucketOf(info *PatternInfo) *bucket {
	return &bucket{literal: "", patterns: []*PatternInfo{info}, isFallback: true}
}

func TestSetCorePromoteSparseBucketsKeepsIneligibleMembers(t *testing.T) {
	// Every disqualifier here is a SILENT wrong answer if lifted without also
	// teaching the sparse body the per-pattern rule, so each is pinned
	// separately. The two plain patterns are what make the promotion happen at
	// all, and the ineligible bucket must survive in the output beside the
	// promoted one.
	cases := []struct {
		name    string
		pattern string
		why     string
	}{
		{
			name:    "isolated-non-greedy",
			pattern: `a*?bcd`,
			why:     "an isolated pattern got its own bucket precisely so its DFA would not be merged",
		},
		{
			name:    "non-trivial-prefix",
			pattern: `[a-z]{3}marker`,
			why:     "the sparse body carries ONE prefix length for the whole bucket",
		},
		{
			name:    "start-anchored",
			pattern: `\Amarker`,
			why:     "a sparse body ignores validMask, so an anchored member would match at every position",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Enough eligible patterns that the merged bucket is over the
			// bitmask width. Below it the promotion is refused outright — a
			// group the bitmask form could have held gains nothing from the
			// slowest body shape there is — so two plain
			// patterns no longer reach the refusals this test is about.
			var in []*bucket
			eligibleCount := bucketMaskBits + 1
			for i := 0; i < eligibleCount; i++ {
				in = append(in, setCoreCovBucketOf(setCoreCovAnalyze(t, fmt.Sprintf(`kw%03d[0-9]`, i))))
			}
			odd := setCoreCovAnalyze(t, tc.pattern)
			in = append(in, setCoreCovBucketOf(odd))
			out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
				setCoreCovFallbackPromotion)

			if len(out) != 2 {
				t.Fatalf("%s: got %d buckets, want 2 (one promoted + the ineligible one kept): %s",
					tc.name, len(out), tc.why)
			}
			sparseCount, keptOdd := 0, false
			for _, bkt := range out {
				if bkt.sparse {
					sparseCount++
					if len(bkt.patterns) != eligibleCount {
						t.Errorf("%s: promoted bucket holds %d patterns, want %d", tc.name, len(bkt.patterns), eligibleCount)
					}
				}
				if len(bkt.patterns) == 1 && bkt.patterns[0] == odd {
					keptOdd = true
				}
			}
			if sparseCount != 1 {
				t.Errorf("%s: %d sparse buckets in the output, want exactly 1", tc.name, sparseCount)
			}
			if !keptOdd {
				t.Errorf("%s: the ineligible bucket was dropped rather than kept; %s", tc.name, tc.why)
			}
		})
	}
}

func TestSetCorePromoteSparseBucketsRefusesUnbuildableMerge(t *testing.T) {
	// The promotion is only worth taking if the merged DFA exists and fits the
	// budgets; otherwise the packer would have split it again and the input is
	// returned untouched.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	in := []*bucket{setCoreCovBucketOf(infos[0]), setCoreCovBucketOf(infos[1])}
	out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
		setCoreCovFallbackPromotion)
	if len(out) != 2 {
		t.Fatalf("an unbuildable merge must leave the buckets alone; got %d, want 2", len(out))
	}
	for _, bkt := range out {
		if bkt.sparse {
			t.Error("a bucket was marked sparse despite the merge failing")
		}
	}
}

func TestSetCorePromoteSparseBucketsRefusesNewlineBoundary(t *testing.T) {
	// The sparse bodies do not serialise the (?m) accept channel, so a merged
	// table carrying one must be refused. This is checked on the TABLE rather
	// than the AST because the channel is a property of the merge: the
	// per-pattern AST scan above it only rejects word boundaries.
	infos := setCoreCovAnalyzeAll(t, `alpha(?m:$)`, `beta(?m:$)`)
	in := []*bucket{setCoreCovBucketOf(infos[0]), setCoreCovBucketOf(infos[1])}

	merged, _, err := mergeSuffixDFASparseSet(
		[]*syntax.Regexp{patternSuffixAST(infos[0]), patternSuffixAST(infos[1])},
		CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if !merged.hasNewlineBoundary {
		t.Fatal("the merged table carries no newline boundary; this case no longer selects the refusal")
	}

	out := promoteSparseBuckets(in, CompileSetOptions{AllowSparseAccept: true},
		setCoreCovFallbackPromotion)
	if len(out) != 2 {
		t.Fatalf("a (?m) merge must be refused; got %d buckets, want 2", len(out))
	}
	for _, bkt := range out {
		if bkt.sparse {
			t.Error("a (?m)-bearing bucket was promoted to sparse accept")
		}
	}
}

// --------------------------------------------------------------------------
// compileAnchoredBuckets

func TestSetCoreCompileAnchoredBucketsDropsUnparseable(t *testing.T) {
	// Defensive, but not silent: analyzePattern parsed the string once, so a
	// failure here means it was rewritten. A bare `continue` would drop the
	// pattern from the anchored trio while `find` kept it, with nothing in
	// --diag-json to explain the disagreement.
	broken := &PatternInfo{fullPattern: `(unclosed`}

	buf, restore := captureWarnings(t)
	defer restore()

	diag := &SetDiag{Name: "anchored-unparseable"}
	buckets, members := compileAnchoredBuckets([]*PatternInfo{broken}, CompileSetOptions{}, diag)

	if len(buckets) != 0 || len(members) != 0 {
		t.Fatalf("expected the pattern dropped; got %d buckets / %d member lists", len(buckets), len(members))
	}
	if len(diag.UnparseableDropped) != 1 {
		t.Errorf("drop not recorded in --diag-json: UnparseableDropped = %v", diag.UnparseableDropped)
	}
	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("silent drop: slog output was %q", out)
	}
}

func TestSetCoreCompileAnchoredBucketsMergeRefusalStartsNewBucket(t *testing.T) {
	// The anchored packer's own merge refusal. It packs in DECLARATION order
	// because a bucket's bit k must map to a stable global id, so a refused
	// merge has to open a new bucket rather than reorder anything.
	infos := setCoreCovAnalyzeAll(t, setCoreCovOversizedPair...)
	opts := CompileSetOptions{MaxFallbackStates: 2048, BudgetStates: 2048, BudgetBytes: 1 << 20}
	buckets, members := compileAnchoredBuckets(infos, opts, nil)

	if len(buckets) != 2 {
		t.Fatalf("expected the anchored merge refused (2 buckets), got %d", len(buckets))
	}
	if len(members) != len(buckets) {
		t.Fatalf("members (%d) and buckets (%d) disagree", len(members), len(buckets))
	}
	for i, group := range members {
		if len(group) != 1 {
			t.Errorf("bucket %d holds %d patterns, want 1", i, len(group))
		}
	}
}

// --------------------------------------------------------------------------
// set_caps.go: the shared bit-recording emitters

func TestSetCoreRecordEmittersStopAtBit32(t *testing.T) {
	// Both emitters unroll one compare per bucket-local bit into an i32 mask,
	// so they must stop at 32 whatever the caller passes. A sparse bucket
	// holds more patterns than that and reaches these emitters through
	// genAnchoredWASM's id map, where an unbounded loop would emit compares
	// against bits the mask cannot hold.
	ids := setCoreCovIDs(40)
	anyBody := emitSetAnyID(nil, ids, 7 /* bitsLocal */, 8 /* dst */, -1 /* no escape */)
	if len(anyBody) == 0 {
		t.Fatal("emitSetAnyID emitted nothing")
	}
	capped := emitSetAnyID(nil, setCoreCovIDs(32), 7, 8, -1)
	if len(anyBody) != len(capped) {
		t.Errorf("emitSetAnyID emitted %d bytes for 40 ids but %d for 32; the k>=32 stop is gone",
			len(anyBody), len(capped))
	}

	allBody := emitSetAllBits(nil, ids, 7, false /* narrow */, 0, 5, 6)
	allCapped := emitSetAllBits(nil, setCoreCovIDs(32), 7, false, 0, 5, 6)
	if len(allBody) != len(allCapped) {
		t.Errorf("emitSetAllBits emitted %d bytes for 40 ids but %d for 32; the k>=32 stop is gone",
			len(allBody), len(allCapped))
	}
}

func TestSetCoreCapAccumulatorBooleanArms(t *testing.T) {
	// Retargeted at capMatchAny. The boolean capMatch kind this used to drive
	// was deleted with the retired `match:` key it existed for — no YAML could
	// select it, capFns() never produced it, and its arms were unreachable
	// code in five files. What the test is really for is the
	// anchored emitter DISPATCH, which match_any and match_all share.
	accumulator := capAccumulator{kind: capMatchAny, lCount: 5, lAnyID: 6, lAcc: 7}

	bits := accumulator.emitRecordBits(nil, 8 /* bitsLocal */, setCoreCovIDs(4), 1 /* escapeDepth */)
	if len(bits) == 0 {
		t.Fatal("emitRecordBits(capMatchAny) emitted nothing")
	}

	// The sparse flavour answers from a COUNT rather than bucket-local bits,
	// because a sparse bucket has more patterns than a mask has bits.
	sparseBits := accumulator.emitRecordSparseCount(nil, 4 /* countLocal */, &bucket{sparseIDMapOff: 64},
		0 /* tableMemIdx */, 9, 10, 1)
	if len(sparseBits) == 0 {
		t.Fatal("emitRecordSparseCount(capMatchAny) emitted nothing")
	}

	body := finishAnchoredCapBody(nil, capMatchAny, false, 7, 5, 6)
	if len(body) == 0 {
		t.Fatal("finishAnchoredCapBody(capMatchAny) emitted nothing")
	}
	if body[len(body)-1] != 0x0B {
		t.Errorf("finishAnchoredCapBody did not terminate the function (last byte %#x)", body[len(body)-1])
	}
}

func TestSetCoreCheckIDSpacePanicsOnOutOfRangeID(t *testing.T) {
	// Every gate offset and `_all` bit position IS a pattern id, and the
	// caller's arrays are sized by the id space the STUBS were told about. A
	// divergence writes out of bounds into host memory — silent and
	// data-dependent — so it is turned into a build failure. Reaching it needs
	// a compiledSet whose ids disagree with its declared space, which
	// CompileFile cannot produce: both sides call config.SetConfig.IDSpaceSize.
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("checkIDSpace did not panic on an id outside the declared space")
		}
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "id space") {
			t.Errorf("panic message does not explain the bound: %v", recovered)
		}
	}()
	cs := &compiledSet{
		name:            "over-declared",
		declaredIDSpace: 2,
		patternIDs:      [][]int{{0, 1, 5}},
	}
	cs.checkIDSpace()
}

func TestSetCoreNumPatternsSkipsFallbackUnderPhase1(t *testing.T) {
	// Under the two-phase scan split the phase-1 body answers for the LITERAL
	// buckets only; the fallback patterns belong to phase 2's union walk. Its
	// "every pattern has been seen" exit therefore has to count the phase-1
	// view, not the set.
	//
	// CompileSet cannot currently reach this combination: numPatterns is read
	// only by the wide-bitmap scan_all drain check, and usesTwoPhaseScan
	// refuses scan_all exactly when wideAll() is true. The field is set
	// directly here to exercise the accessor's own contract; if the split ever
	// serves a wide scan_all, this is the behaviour it will get.
	cs := &compiledSet{
		buckets:    []*bucket{{isFallback: false}, {isFallback: true}},
		patternIDs: [][]int{{0, 1}, {2, 3, 4}},
	}
	if got := cs.numPatterns(); got != 5 {
		t.Errorf("numPatterns() = %d, want 5 (the whole set)", got)
	}
	cs.phase1Only = true
	if got := cs.numPatterns(); got != 2 {
		t.Errorf("numPatterns() under phase1Only = %d, want 2 (literal buckets only)", got)
	}
}

// --------------------------------------------------------------------------
// set_probe.go

func TestSetCoreProbeBodyRejectsAnchoredFirstHit(t *testing.T) {
	// An anchored answer is not monotone: a mid-walk accept says nothing about
	// reaching `len`, so there is no first bit to stop on. Combining the two
	// would silently report patterns that match a proper prefix, which is the
	// opposite of the anchored contract, so it is a build-time panic.
	defer func() {
		if recover() == nil {
			t.Fatal("buildSetProbeBodyExit accepted a first-hit exit on an ANCHORED probe")
		}
	}()
	buildSetProbeBodyExit(setSuffixParams{}, true /* anchored */, probeExitFirstHit)
}

func TestSetCoreProbeBodyClampsBucketWidthTo32(t *testing.T) {
	// The probe returns a bucket-local bitmask in an i32, so the "every
	// eligible pattern seen" mask must be capped at 32 bits however many ids
	// the bucket carries. binPack caps a bucket at 32 today, so this is
	// reached by handing genAnchoredWASM a wider id vector directly.
	table, err := mergeAnchoredDFA([]*syntax.Regexp{mustParse(t, `alpha`), mustParse(t, `beta`)},
		CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeAnchoredDFA: %v", err)
	}
	body, _, _, _, sparse := genAnchoredWASM(table, 0, 0, setCoreCovIDs(40))
	if len(body) == 0 {
		t.Fatal("genAnchoredWASM emitted no body for a 40-id bucket")
	}
	if sparse != nil {
		t.Fatal("a bitmask table must not report sparse anchored info")
	}
}

func TestSetCoreGenAnchoredWASMEmptyTable(t *testing.T) {
	// An empty bucket DFA still needs a callable probe: the anchored capability
	// bodies call every bucket in turn with no nil check, so the degenerate
	// case has to be a function returning 0, not a missing one.
	body, dataBytes, segCount, next, sparse := genAnchoredWASM(nil, 4096, 0, setCoreCovIDs(2))
	if len(body) == 0 {
		t.Fatal("genAnchoredWASM(nil) emitted no body")
	}
	if len(dataBytes) != 0 || segCount != 0 {
		t.Errorf("an empty table needs no data segments; got %d bytes / %d segments", len(dataBytes), segCount)
	}
	if next != 4096 {
		t.Errorf("nextTableOffset = %d, want the unchanged base 4096", next)
	}
	if sparse != nil {
		t.Error("an empty table must not report sparse anchored info")
	}
}

func TestSetCoreCountedChainProbeAnchoredFlavour(t *testing.T) {
	// The counted-class-chain bucket is one pattern of exactly N bytes of one
	// class, so "does it match" is a SIMD verification and needs no DFA walk.
	// The anchored flavour differs by one opcode — full consumption is
	// `endPos != len` rather than `endPos > len` — and that single difference
	// is the whole anchored contract for this body. Only the scan flavour has
	// a caller today (genSuffixWASM), so the anchored one is driven directly.
	class := make([]byte, 0, 10)
	for digit := byte('0'); digit <= '9'; digit++ {
		class = append(class, digit)
	}
	scanBody := buildCountedChainProbeBody(class, 6, false)
	anchoredBody := buildCountedChainProbeBody(class, 6, true)
	if len(scanBody) == 0 || len(anchoredBody) == 0 {
		t.Fatal("buildCountedChainProbeBody emitted nothing")
	}
	if len(scanBody) != len(anchoredBody) {
		t.Errorf("the two flavours differ by more than the length test: %d vs %d bytes",
			len(scanBody), len(anchoredBody))
	}
	// 0x47 is i32.ne (anchored: exact length) and 0x4B is i32.gt_u (scan: fits).
	if !bytesContain(anchoredBody, 0x47) {
		t.Error("anchored counted-chain probe does not test for EXACT length (i32.ne missing)")
	}
	if !bytesContain(scanBody, 0x4B) {
		t.Error("scan counted-chain probe does not test for a fitting length (i32.gt_u missing)")
	}
}

func bytesContain(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// startable.go: the first-byte eligibility table

func TestSetCoreFirstByteSetGivesUpSafely(t *testing.T) {
	// The table must OVER-approximate: a pattern wrongly cleared is a lost
	// match. Both give-up paths therefore answer nil ("assume every byte")
	// rather than an empty or partial set.
	if got := firstByteSet(`(unclosed`); got != nil {
		t.Error("firstByteSet on an unparseable pattern returned a set; it must give up")
	}
	// A non-ASCII first rune is encoded as several bytes and what leads it is
	// a UTF-8 lead byte, not the rune. Deriving that is out of scope for a
	// byte-oriented engine, so the whole pattern gives up.
	if got := firstByteSet("étude"); got != nil {
		t.Error("firstByteSet on a non-ASCII first rune returned a set; it must give up")
	}
	// The positive control: a plain ASCII first byte is derivable, and only
	// that byte may be set.
	set := firstByteSet(`keyword`)
	if set == nil {
		t.Fatal("firstByteSet(keyword) gave up on a derivable ASCII first byte")
	}
	for b := 0; b < 256; b++ {
		if want := b == 'k'; set[b] != want {
			t.Errorf("firstByteSet(keyword)[%d] = %v, want %v", b, set[b], want)
		}
	}
}

func TestSetCoreBuildStartableTableDeclines(t *testing.T) {
	// The table is bucket-local pattern BITS in a uint32, so it cannot serve a
	// bucket past 32 patterns; and an empty bucket has nothing to clear. Both
	// answer nil, which the emitter reads as "no eligibility mask" rather than
	// as an all-zero table that would clear every pattern.
	if got := buildStartableTable(&bucket{}); got != nil {
		t.Error("buildStartableTable on an empty bucket returned a table")
	}

	wide := &bucket{patterns: make([]*PatternInfo, 33)}
	for i := range wide.patterns {
		wide.patterns[i] = &PatternInfo{fullPattern: `keyword`}
	}
	if got := buildStartableTable(wide); got != nil {
		t.Error("buildStartableTable on a 33-pattern bucket returned a table; bits past 31 have no home")
	}

	// The positive control, so the two nils above cannot pass for the table
	// having been switched off entirely.
	narrow := &bucket{patterns: []*PatternInfo{{fullPattern: `keyword`}, {fullPattern: `[0-9]+`}}}
	tab := buildStartableTable(narrow)
	if tab == nil {
		t.Fatal("buildStartableTable declined a bucket with a derivable first byte")
	}
	if tab['k'] != 0b01 {
		t.Errorf("startable['k'] = %#b, want 0b01 (only the literal pattern)", tab['k'])
	}
	if tab['5'] != 0b10 {
		t.Errorf("startable['5'] = %#b, want 0b10 (only the digit pattern)", tab['5'])
	}
	if tab['@'] != 0 {
		t.Errorf("startable['@'] = %#b, want 0 (neither pattern can begin there)", tab['@'])
	}
}

// --------------------------------------------------------------------------
// set_sparse.go

func TestSetCoreSparseSuffixBodySubtractsFixedPrefix(t *testing.T) {
	// A sparse bucket carries ONE prefix length for the whole bucket and
	// subtracts it from every tuple's start. promoteSparseBuckets refuses any
	// bucket whose members do not ALL have a trivial prefix, so the value is
	// 0 for every bucket a config can produce today — the emitter arm is
	// driven here by handing genSuffixWASM a non-zero fixed length directly.
	//
	// It is not dead: relaxing that refusal is a documented follow-up, and the
	// last time a bucket with mixed prefix lengths reached this body 285 of
	// its 288 patterns reported starts off by 1 or 2, going NEGATIVE near
	// position 0.
	const numPatterns = 40
	asts := make([]*syntax.Regexp, numPatterns)
	for i := range asts {
		asts[i] = mustParse(t, `suffix`+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	table, _, err := mergeSuffixDFASparseSet(asts, CompileSetOptions{})
	if err != nil {
		t.Fatalf("mergeSuffixDFASparseSet: %v", err)
	}
	if table.midAcceptWide == nil {
		t.Fatal("the merged table has no wide accept lists; this case no longer selects the sparse body")
	}

	prefixFixedLens := make([]int, numPatterns)
	prefixFixedLens[0] = 3 // the bucket-wide fixed prefix length

	withPrefix, _, _, _ := genSuffixWASM(table, 0, 0, setCoreCovIDs(numPatterns), prefixFixedLens, LikelyNeutral,
		false /* needProbes */, false /* gated */, nil)
	withoutPrefix, _, _, _ := genSuffixWASM(table, 0, 0, setCoreCovIDs(numPatterns), make([]int, numPatterns), LikelyNeutral,
		false, false, nil)

	if len(withPrefix.fnBody) == 0 {
		t.Fatal("genSuffixWASM emitted no sparse suffix body")
	}
	if len(withPrefix.fnBody) <= len(withoutPrefix.fnBody) {
		t.Errorf("a non-zero prefix length emitted no extra instructions: %d bytes vs %d",
			len(withPrefix.fnBody), len(withoutPrefix.fnBody))
	}
}

// --------------------------------------------------------------------------
// Branches in these files this test file does NOT reach, and what blocks each.
// Recorded so the next reader does not spend the same afternoon on them, and
// so none of them is mistaken for dead code — every one is a live guard.
//
//  1. Every `if err != nil` arm after a regexp/syntax.Compile call:
//     analyzePattern's prefix and suffix compiles, mergeSuffixDFA,
//     mergeSuffixDFASparseSet, mergeAnchoredDFA, mergeAnchoredDFASparseSet and
//     firstByteSet. syntax.Compile returns a nil error unconditionally
//     (go1.25.9 regexp/syntax/compile.go:71) — it panics on an unhandled Op
//     instead — so no *syntax.Regexp reaches those arms. They are the correct
//     thing to write against an (error) signature and must stay.
//
//  2. analyzePattern's PREFIX state limit. findMandatoryLitRec refuses a
//     literal past offset 256, so a prefix is at most 256 bytes; and the
//     prefix DFA is built by determinising the REVERSED prefix, which by
//     Brzozowski's theorem yields the MINIMAL DFA of the reversed prefix
//     language. Natural fixed-length prefixes therefore land far below
//     maxHelperDFAStates (2048): a 2730-word 12-byte keyword alternation
//     measured 705 states, and plain counted classes are linear chains.
//     Reaching 2048 needs a language built to have thousands of distinct
//     residuals. The SUFFIX limit next to it is covered.
//
//  3. genAnchoredWASM's `bits == 0` skip over the EOF accept map. The map is
//     only ever written through engine_dfa.go's orAccept, which refuses a zero
//     mask outright, and every relabel filters zeros — so no construction puts
//     a zero-valued entry in it, and reaching the skip means inserting one by
//     hand. Left alone rather than faked.
//
//  4. buildStartableTable's `k >= 32` return. The function has already
//     returned nil for any bucket with more than 32 patterns, so k tops out at
//     31. It is a second lock on the same door; removing it would leave the
//     table's uint32 bits depending on the caller's guard alone.

// ── Per-pattern emitters inside the SET assembler ──────────────────────────
//
// assembleModuleWithSets carries its own copy of the per-pattern function and
// export emission, because a set module lays out functions differently from a
// plain one. That copy has arms for every specialised single-pattern body —
// alt-lit-anchor with its deferred dispatcher, lit-anchor's backward/forward
// pair, batch wrappers — and none of them was reached, because every set test
// in the package uses a set ALONE and every single-pattern test uses
// assembleModule instead.
//
// The combination is ordinary in a real config: a `sets:` block beside
// per-pattern `find_func` entries. The dispatcher arm is the one that matters
// most, since it patches function indices that only exist at assembly time —
// exactly the shape that produces a module calling the wrong function.

// setPlusPatternsConfig is a BuildConfig with BOTH a set and standalone
// patterns chosen to select the specialised emitters.
func setPlusPatternsConfig(extra []config.RegexEntry, hints []string) config.BuildConfig {
	base := []config.RegexEntry{
		{Name: "s0", Pattern: `alpha[0-9]{3}`},
		{Name: "s1", Pattern: `bravo[0-9]{3}`},
		{Name: "s2", Pattern: `charlie[0-9]{3}`},
	}
	return config.BuildConfig{
		Regexps: append(base, extra...),
		Sets: []config.SetConfig{{
			Name:     "s",
			Find:     "s_find",
			Patterns: config.PatternSelector{Names: []string{"s0", "s1", "s2"}},
			Hints:    hints,
		}},
	}
}

func TestSetAssemblerPerPatternBodies(t *testing.T) {
	cases := []struct {
		name    string
		entries []config.RegexEntry
		exports []string
	}{
		{
			// Alt-lit-anchor: N backward_scan + N forward_verify functions
			// plus ONE dispatcher built at assembly time from indices that do
			// not exist before then.
			name: "alt lit anchor dispatcher",
			entries: []config.RegexEntry{{
				Name: "alt",
				// The branches need an UNBOUNDED suffix. A bounded one is
				// caught earlier by analyseLitChainAltPrefixed and never
				// reaches the alt-lit-anchor block at all — see
				// TestCompileAltLitAnchorDispatch, which learned the same
				// thing the same way.
				Pattern:  `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`,
				FindFunc: "alt_find",
			}},
			exports: []string{"alt_find", "s_find"},
		},
		{
			// Lit-anchor: a backward DFA recovers the match start, and the
			// forward half is generated at assembly time too.
			name: "lit anchor pair",
			entries: []config.RegexEntry{{
				Name:     "mail",
				Pattern:  `[a-z]+@example\.com`,
				FindFunc: "mail_find",
			}},
			exports: []string{"mail_find", "s_find"},
		},
		{
			// A capture body beside a set: the groups wrapper composes a find
			// and a capture function, both indexed by the set assembler.
			name: "groups wrapper",
			entries: []config.RegexEntry{{
				Name:       "grp",
				Pattern:    `<([a-z]+)>`,
				GroupsFunc: "grp_groups",
			}},
			exports: []string{"grp_groups", "s_find"},
		},
		{
			// An anchored match body, which takes the assembler's matchBody
			// arm rather than any find arm.
			name: "match only",
			entries: []config.RegexEntry{{
				Name:      "m",
				Pattern:   `[0-9]{4}-[0-9]{2}`,
				MatchFunc: "m_match",
			}},
			exports: []string{"m_match", "s_find"},
		},
		{
			// A prefer-no-match find whose adaptive Shufti scan emits a
			// NEUTRAL TWIN: two functions from one findBody, the first
			// handing off to the second. funcLayout gained the twin's slot
			// and both assemblers therefore declared it, while only the
			// single-pattern one had a type index for it — so this
			// combination panicked in the set module's function section.
			//
			// The pattern needs a first-byte set in the adaptive band and no
			// mandatory literal, or there is no dense switch to escape and no
			// twin to emit (TestFindNeutralTwinEmission pins that predicate).
			name: "prefer-no-match find twin",
			entries: []config.RegexEntry{{
				Name:     "tw",
				Pattern:  `[a-zA-Z]{20,}`,
				FindFunc: "tw_find",
				Hints:    []string{"prefer-no-match"},
			}},
			exports: []string{"tw_find", "s_find"},
		},
		{
			// Batch wrappers beside a set: a second entry point over the same
			// body, whose index the assembler also has to resolve.
			name: "batch find",
			entries: []config.RegexEntry{{
				Name:     "b",
				Pattern:  `[a-z]+@example\.com`,
				FindFunc: "b_find",
				Hints:    []string{"batch-find"},
			}},
			exports: []string{"b_find", "b_find_batch", "s_find"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, hints := range [][]string{nil, {"prefer-match"}, {"prefer-no-match"}} {
				cfg := setPlusPatternsConfig(tc.entries, hints)
				w, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("hints %v: %v", hints, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("hints %v: not a WASM module (%d bytes)", hints, len(w))
				}
				// The export names are the cheapest proof the assembler
				// resolved every function it laid out: a missing arm drops
				// the export rather than producing a bad one.
				for _, want := range tc.exports {
					if !strings.Contains(string(w), want) {
						t.Errorf("hints %v: module does not export %q", hints, want)
					}
				}
			}
		})
	}
}

// TestSetAssemblerWithReporter drives the same combination with --verbose on,
// which is the set half of the reporting path: SetDiag records rendered beside
// per-pattern ones.
func TestSetAssemblerWithReporter(t *testing.T) {
	cfg := setPlusPatternsConfig([]config.RegexEntry{{
		Name: "mail", Pattern: `[a-z]+@example\.com`, FindFunc: "mail_find",
	}}, nil)
	rep := &Reporter{}
	if _, _, diags, err := CompileFileDiag(cfg, ""); err != nil {
		t.Fatalf("compile: %v", err)
	} else {
		rep.Sets = diags
	}
	if len(rep.Sets) == 0 {
		t.Fatal("compiled a set but reported no SetDiag")
	}
	var out strings.Builder
	rep.Render(&out)
	got := out.String()
	for _, want := range []string{`Set "s"`, "frontend:", "buckets:"} {
		if !strings.Contains(got, want) {
			t.Errorf("set report missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestSetAssemblerFindTwinHandoff pins that the set assembler emits the neutral
// twin AND patches the handoff call that reaches it.
//
// The export check above cannot see either. A missing twin body leaves the
// module declaring one more function than it emits, which is a section-length
// error rather than a missing export; an unpatched handoff leaves the call
// immediate at its placeholder 0 — the find body itself, whose type matches, so
// the module still validates and merely recurses for ever. Comparing against
// the bytes the shared emitter produces at the pattern's real function index
// catches both, without a WASM parser.
func TestSetAssemblerFindTwinHandoff(t *testing.T) {
	entry := config.RegexEntry{
		Name:     "tw",
		Pattern:  `[a-zA-Z]{20,}`,
		FindFunc: "tw_find",
		Hints:    []string{"prefer-no-match"},
	}
	cfg := setPlusPatternsConfig([]config.RegexEntry{entry}, nil)
	w, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// The same pattern through the same front end, to learn what its find
	// body and twin should look like and where the twin sits.
	p, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.findNeutralBody == nil {
		t.Fatal("pattern emitted no neutral twin — the case no longer covers " +
			"the path it was written for")
	}
	// The twin pattern is the LAST entry, so its base is every earlier
	// pattern's function count. The set members declare no _func fields, so
	// they compile to nothing here and the twin is the module's first — and
	// only — standalone pattern.
	base := 0
	for _, e := range cfg.Regexps[:len(cfg.Regexps)-1] {
		q, cErr := compilePattern(e, 0, 0, CompileOptions{})
		if cErr != nil {
			t.Fatalf("compilePattern(%s): %v", e.Name, cErr)
		}
		if q != nil {
			base += len(q.funcLayout())
		}
	}
	// Being first is also what makes tableBase 0 for it, which is the base the
	// reference build above used. A table-bearing pattern added ahead of it
	// would shift the twin's data offsets and the reconstruction below would
	// no longer be the bytes the assembler emits — so say so here rather than
	// letting the comparison fail as if the assembler were at fault.
	if base != 0 {
		t.Fatalf("twin pattern is no longer the module's first compiled "+
			"pattern (base=%d): rebuild the reference at its real tableBase", base)
	}
	_, _, findOff, _, _ := p.offsets()
	want := p.appendFindBodyWithTwin(nil, base+findOff)
	if !bytes.Contains(w, want) {
		t.Errorf("set module does not contain the find body and its patched "+
			"twin handoff (find at function %d, twin at %d)",
			base+findOff, base+findOff+1)
	}
	// And the unpatched form must NOT appear: that is the placeholder the
	// assembler is responsible for overwriting.
	unpatched := append([]byte(nil), p.findBody...)
	copy(unpatched[p.findTwinCallOff:p.findTwinCallOff+twinCallImmWidth],
		utils.AppendPaddedULEB128(nil, 0, twinCallImmWidth))
	if bytes.Contains(w, unpatched) {
		t.Error("set module contains the find body with an UNPATCHED twin " +
			"handoff — the call still targets function 0")
	}
}

// btABISet builds a one-set config declaring the capabilities the `_all` ABI
// switch touches. maxFallback = 1 forces its fallback members onto BT.
func btABISet(pats []string, maxFallback int) (config.SetConfig, config.BuildConfig) {
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sc := config.SetConfig{
		Name: "s", MatchAll: "s_match_all", ScanAll: "s_scan_all",
		ScanAny: "s_scan_any", Find: "s_find",
		Patterns: config.PatternSelector{All: true},
	}
	return sc, config.BuildConfig{
		Regexps: entries, MaxFallbackStates: maxFallback,
		Sets: []config.SetConfig{sc},
	}
}

// compileBTABISet compiles the set and hands back the artefact, so a test can
// ask what the emitter actually decided rather than infer it.
func compileBTABISet(t *testing.T, pats []string, maxFallback int) *compiledSet {
	t.Helper()
	sc, cfg := btABISet(pats, maxFallback)
	var prefixPool, suffixPool dfaPool
	idxs := make([]int, len(cfg.Regexps))
	for i := range idxs {
		idxs[i] = i
	}
	infos, gids, err := setPatternInfos(sc, cfg, idxs, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("setPatternInfos: %v", err)
	}
	spec := SetSpec{
		Name: sc.Name, MatchAll: sc.MatchAll, ScanAll: sc.ScanAll,
		ScanAny: sc.ScanAny, Find: sc.Find,
		DeclaredPatternCount: len(cfg.Regexps), IDSpaceSize: len(cfg.Regexps),
		Patterns: infos, PatternIDs: gids,
	}
	return CompileSet(spec, &prefixPool, &suffixPool,
		CompileSetOptions{MaxFallbackStates: maxFallback})
}

// TestSetBTForcesMemoryAllABI pins the Backtracking `_all` ABI: admitting a
// Backtracking member moves the `_all` bitmap into MEMORY and frees the return
// value to carry a count, whatever the id space.
//
// The narrow form is the only capability shape with no room for "unknown": its
// i64 return IS the bitmask, so -2 there reads as "everything matched except
// pattern 0" and no stub can tell the two apart.
//
// CONDITIONAL is half the contract — a set with no BT member must keep the
// cheap i64 form, so this asserts both directions on the same patterns.
func TestSetBTForcesMemoryAllABI(t *testing.T) {
	pats := []string{`(?:ab|cd)+xyz`, `hello`}

	plain := compileBTABISet(t, pats, 0)
	if plain.hasBTMember() {
		t.Fatal("no BT member expected at the default limit; the rest of this test is meaningless")
	}
	if plain.wideAll() {
		t.Error("a set with no BT member and a 2-id space must keep the narrow i64 _all form")
	}

	bt := compileBTABISet(t, pats, 1)
	if !bt.hasBTMember() {
		// Failing to build the required fixture is a failure, not a skip:
		// without a BT member there is no wide-_all arm left to assert, and a
		// skip would make this ABI regression test silently vacuous.
		t.Fatal("max_fallback_states=1 admitted no BT member; the forced-BT " +
			"fixture no longer builds and the wide-_all arm is untested")
	}
	if !bt.wideAll() {
		t.Error("a set with a BT member must use the memory _all form even at a 2-id space")
	}
}

// TestSetBTDisablesTwoPhaseSplit pins the other half of that decision.
//
// Phase 2 of the scan split is a union walk that answers with an i64
// accumulator and has no out_ptr at all — the NARROW _all ABI only. A BT member
// forces the wide form, so taking the split would compose two phases of
// different shapes, which is a module that does not validate.
func TestSetBTDisablesTwoPhaseSplit(t *testing.T) {
	// A literal-bearing pattern and a literal-less one: the mixed shape the
	// split exists for.
	pats := []string{`hello[0-9]{3}`, `(?:ab|cd)+`}
	bt := compileBTABISet(t, pats, 1)
	if !bt.hasBTMember() {
		t.Fatal("max_fallback_states=1 admitted no BT member; the forced-BT " +
			"fixture no longer builds and the split-suppression arm is untested")
	}
	if bt.phase2Union != nil {
		t.Error("a set with a BT member must not take the two-phase scan split: " +
			"phase 2 implements the narrow _all ABI only")
	}
}

// TestMemberSkipIsVisibleAndHintGated pins the mechanism's VISIBILITY and its
// gate, which is the guard the two drifted cases in this project lacked.
//
// `set-shufti-dense-harm` was labelled a Shufti target while compiling to
// Teddy, and `tdfa-bulk-skip-word-class` was labelled a TDFA target while
// compiling to a Compiled DFA. Both sat wrong for weeks because nothing
// asserted which body they got. --diag-json now reports the member-skip
// counts, and this test asserts they say what the emitter did:
//
//   - hinted, eligible shape -> a non-zero count;
//   - neutral, same shape     -> zero, because the skip is hint-gated;
//   - hinted, WIDE self-loop  -> also non-zero, since the rectangle-cover
//     encoding serves any width (this used to be the refusal case).
//
// A future change that silently stops emitting the skip fails the first case
// rather than merely getting slower.
func TestMemberSkipIsVisibleAndHintGated(t *testing.T) {
	// 40 patterns behind one shared literal, each with a one-byte self-loop
	// tail — the shape that packs into a single sparse bucket.
	eligible := make([]config.RegexEntry, 40)
	for i := range eligible {
		eligible[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`union[ \t]+k%02da+`, i),
		}
	}
	// Same shape, but the tail self-loop is \w — 63 bytes. Under the old
	// one-bit-per-member encoding the forty BODY states were REFUSED as
	// oversized and only the shared `[ \t]+` run stayed eligible. The
	// rectangle cover spends a bit per nibble ROW instead, so \w is one pair
	// like every other class and those forty states are now served too.
	wide := make([]config.RegexEntry, 40)
	for i := range wide {
		wide[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`union[ \t]+k%02d\w+`, i),
		}
	}

	count := func(entries []config.RegexEntry, hints []string) int {
		cfg := config.BuildConfig{
			Regexps: entries,
			Sets: []config.SetConfig{{
				Name:     "s",
				Find:     "s_find",
				Patterns: config.PatternSelector{All: true},
				Hints:    hints,
			}},
		}
		_, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		n := 0
		for _, d := range diags {
			for _, b := range d.Buckets {
				n += b.MemberSkipStates
			}
		}
		return n
	}

	if got := count(eligible, []string{"prefer-match"}); got == 0 {
		t.Error("hinted eligible set reports no member-skip states — either the skip stopped " +
			"being emitted, or it stopped being reported; both are silent failures")
	}
	if got := count(eligible, nil); got != 0 {
		t.Errorf("neutral set reports %d member-skip states, want 0 — the skip must stay "+
			"hint-gated, since it costs a few percent on buckets with no runs to skip", got)
	}
	elig, wideN := count(eligible, []string{"prefer-match"}), count(wide, []string{"prefer-match"})
	if wideN < elig {
		t.Errorf("the \\w-tailed set reports %d member-skip states against %d for the "+
			"one-byte-tailed set — a 63-byte self-loop is one nibble pair under the "+
			"rectangle cover, so it must be served, not refused", wideN, elig)
	}
}

// TestMemberSetEncodingIsExact checks encodeMemberSet's claim that its
// nibble tables are EXACT, not approximate.
//
// The Shufti family is usually a prefilter where a false positive is merely
// wasted work. Here it decides whether a byte keeps the walk in the same
// state, so a false positive skips a byte that should have left the state —
// a wrong answer, not a slow one.
//
// The last three sets are ones the former one-bit-per-member encoding could
// not express at all: \w (63), a `[^\n]`-style tail (255) and one byte in
// every nibble row (16 distinct rows, the cover's worst case, two pairs).
func TestMemberSetEncodingIsExact(t *testing.T) {
	wordClass := func() []byte {
		var out []byte
		for c := 0; c < 256; c++ {
			b := byte(c)
			if b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
				out = append(out, b)
			}
		}
		return out
	}()
	notNewline := func() []byte {
		var out []byte
		for c := 0; c < 256; c++ {
			if byte(c) != '\n' {
				out = append(out, byte(c))
			}
		}
		return out
	}()
	sets := [][]byte{
		{'a'},
		{'a', 'b', 'c'},
		[]byte("0123456789"),
		[]byte("abcdefghijklmnop"),
		{0x00, 0xFF, 0x0F, 0xF0},
		{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98},
		wordClass,
		notNewline,
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}
	for _, set := range sets {
		tab := encodeMemberSet(set)
		in := map[byte]bool{}
		for _, m := range set {
			in[m] = true
		}
		for b := 0; b < 256; b++ {
			by := byte(b)
			var hit bool
			for pair := 0; pair < memberSetPairs; pair++ {
				lo := tab[pair*32+int(by&0x0F)]
				hi := tab[pair*32+16+int(by>>4)]
				if lo&hi != 0 {
					hit = true
				}
			}
			if hit != in[by] {
				t.Errorf("set of %d bytes: %#02x reported member=%v, want %v",
					len(set), by, hit, in[by])
			}
		}
	}
}

// TestMemberSetsAdmitWide confirms a state with a wide self-loop set is now
// SERVED, and served exactly.
//
// This is the inverse of the assertion that stood here while the encoding
// spent one bit per member: a set of more than sixteen bytes then had to be
// refused, because truncating it would have strided over bytes that are NOT
// members and left the state without noticing — the silent-wrong-answer
// version of this feature. The rectangle cover removes the ceiling rather
// than the danger, so the exactness check below is the part that matters.
func TestMemberSetsAdmitWide(t *testing.T) {
	for _, width := range []int{20, 63, 200, 255} {
		tbl := &dfaTable{numStates: 2, transitions: make([]int, 2*256)}
		for i := range tbl.transitions {
			tbl.transitions[i] = -1
		}
		for b := 0; b < width; b++ {
			tbl.transitions[1*256+b] = 1 // global state 1 self-loops on `width` bytes
		}
		idTab, setTab := buildMemberSets(tbl, 3)
		if len(setTab) != memberSetBytes {
			t.Fatalf("width %d: got %d table bytes, want one set of %d",
				width, len(setTab), memberSetBytes)
		}
		// idTab is indexed by WASM state, which is the global state plus one
		// (state 0 is dead), so global state 1 is entry 2.
		if idTab == nil || idTab[2] != 1 {
			t.Fatalf("width %d: the self-loop state was not given set id 1: idTab=%v", width, idTab)
		}
		for b := 0; b < 256; b++ {
			by := byte(b)
			var hit bool
			for pair := 0; pair < memberSetPairs; pair++ {
				if setTab[pair*32+int(by&0x0F)]&setTab[pair*32+16+int(by>>4)] != 0 {
					hit = true
				}
			}
			if want := b < width; hit != want {
				t.Fatalf("width %d: byte %#02x reported member=%v, want %v",
					width, by, hit, want)
			}
		}
	}

	// A state with no self-loop at all still produces nothing, so a bucket
	// that can never skip pays no per-byte dispatch.
	tbl := &dfaTable{numStates: 2, transitions: make([]int, 2*256)}
	for i := range tbl.transitions {
		tbl.transitions[i] = -1
	}
	if idTab, setTab := buildMemberSets(tbl, 3); idTab != nil || setTab != nil {
		t.Error("a table with no self-loop state produced member tables")
	}
}

// ---------------------------------------------------------------------------
// `--diag-json` reported the frontend SELECTION
// chose, while the emitted body could still be the scalar one.
//
// A fallback bucket has no literal gating it, so it must be tried at EVERY
// input position and a prefilter that skips positions cannot serve it.
// chooseLiteralFrontend does not know that — it sees only the literals — so a
// set with literals AND a fallback pattern was selected as Teddy or
// packed-pair and emitted as scalar, with the diagnostics file naming a
// frontend the module did not contain.
//
// Selection and emission now answer through emittedFrontend, so they cannot
// disagree. These tests pin BOTH directions: the downgrade is reported, and a
// set with no fallback bucket still reports its real literal frontend.

func diagFrontendEntries(pats []string) []config.RegexEntry {
	out := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		out[i] = config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: p}
	}
	return out
}

func diagFrontendFor(t *testing.T, pats []string) string {
	t.Helper()
	cfg := config.BuildConfig{
		Regexps: diagFrontendEntries(pats),
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find",
			Patterns: config.PatternSelector{All: true},
		}},
	}
	_, _, diags, err := CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("CompileFileDiag: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("expected one set diagnostic, got %d", len(diags))
	}
	return diags[0].Frontend
}

func TestDiagFrontendReportsTheEmittedBody(t *testing.T) {
	// Literals only: a real literal frontend, and the diagnostic says so.
	litOnly := []string{"alpha", "bravo", "charlie", "delta"}
	pure := diagFrontendFor(t, litOnly)
	if pure == frontendScalar.String() {
		t.Fatalf("frontend = %q for a literal-only set; this case no longer "+
			"tests the downgrade because there is nothing to downgrade FROM", pure)
	}

	// The same literals plus one pattern with no mandatory literal, which
	// lands in a fallback bucket and forces the scalar body.
	withFallback := append(append([]string{}, litOnly...), `[0-9]{4,}`)
	got := diagFrontendFor(t, withFallback)
	if got != frontendScalar.String() {
		t.Errorf("frontend = %q, want %q: a fallback bucket forces the scalar body, "+
			"so the diagnostic must not keep naming %q",
			got, frontendScalar.String(), pure)
	}
}

// emittedFrontend is the single source of truth; the emitter dispatches on it.
// If a future arm is added to one and not the other they drift apart again,
// so the mapping is asserted directly for every frontend a set can select.
func TestEmittedFrontendMatchesSelectionWithoutFallback(t *testing.T) {
	cases := []struct {
		name string
		pats []string
	}{
		{"literals", []string{"alpha", "bravo", "charlie", "delta"}},
		{"many-literals", func() []string {
			var p []string
			for i := 0; i < 24; i++ {
				p = append(p, fmt.Sprintf("keyword%02d", i))
			}
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// With no fallback bucket the emitted frontend IS the selected one.
			if got := diagFrontendFor(t, c.pats); got == frontendScalar.String() {
				t.Errorf("frontend = %q; this shape should keep its literal frontend "+
					"when no fallback bucket is present", got)
			}
		})
	}
}
