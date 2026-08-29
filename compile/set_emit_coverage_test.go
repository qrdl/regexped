package compile

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// Set-emission paths that the compile matrices next door do not select.
//
// `set_matrix_coverage_test.go` sweeps the shapes a YAML config can ASK for.
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
//     preflight only runs when the G12 absence prefilter DECLINES, which needs
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
//     say yes at all. Without it a preflight is §16.5.2's Candidate A — a pass
//     over the whole input that retires nothing.
//   - literal-LESS is what makes the G12 absence prefilter DECLINE
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
		// ambiguity (CLAUDE.md "Gap I"). That is what makes p.isTDFA false, so
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
// after `from`": G12's literal-absence scan, and a pass over the start-anywhere
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
// literals (§14.11), hence the shared "keyword" stem.
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
// how R4 diverged — so the predicate is asserted directly rather than through
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
		return buildUnionScanDFA(spec, CompileSetOptions{}, 0)
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

	// The id-space ceiling. It was 64 — one u64 accept mask — until SETS_PLAN
	// item 21 phase 1 gave the automaton a wide accept form; the refusal now
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
	if got := buildUnionScanDFA(unparseable, CompileSetOptions{}, 0); got != nil {
		t.Error("a pattern whose AST could not be recovered was admitted to the union automaton")
	}
}

// TestSetEmitUnionScanWideSetCompiles is the id ceiling reached the way a
// config reaches it: a literal-less set of 66 patterns declaring the scan pair.
//
// Before SETS_PLAN item 21 phase 1 this set fell back to the per-position
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

// TestSetEmitBatchPosFnOffsetWithoutBatching covers the "not batching" answer
// of batchPosFnOffset.
//
// The offset is the index of the shared per-position worker, and on a set that
// does not batch there is no worker to point at. -1 rather than a plausible
// index is what keeps a caller from emitting a call to whatever function
// happens to sit at len(capFns()).
func TestSetEmitBatchPosFnOffsetWithoutBatching(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find"}
	compiled := setEmitCovCompileSet(t, spec, []string{`alpha`, `bravo`}, CompileSetOptions{})
	if got := compiled.batchPosFnOffset(); got != -1 {
		t.Errorf("batchPosFnOffset() = %d on a non-batching set, want -1", got)
	}

	batching := SetSpec{Name: "s", Find: "s_find", BatchFind: true}
	batched := setEmitCovCompileSet(t, batching, []string{`alpha`, `bravo`}, CompileSetOptions{})
	if got := batched.batchPosFnOffset(); got != len(batched.capFns()) {
		t.Errorf("batchPosFnOffset() = %d, want %d (immediately after the exported capabilities)",
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
		viaSets := assembleModuleWithSets(nil, nil, 1, standalone)
		direct := assembleModule(nil, 1, standalone)
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
		// Four local groups, not five: the adaptive form's dense-gate counter
		// is absent. The count is the second byte — the first is the body's
		// LEB128 size prefix, which is single-byte only for tiny bodies, so
		// the check reads it back through the same size prefix the emitter
		// wrote.
		if got := setEmitCovLocalGroups(t, body); got != 4 {
			t.Errorf("mode %v: %d local groups, want 4 (the non-adaptive frame)", mode, got)
		}
	}
}

// setEmitCovLocalGroups reads the local-group count out of a size-prefixed
// WASM function body.
func setEmitCovLocalGroups(t *testing.T, body []byte) int {
	t.Helper()
	// Skip the ULEB128 size prefix: continuation bit set means another byte.
	i := 0
	for i < len(body) && body[i]&0x80 != 0 {
		i++
	}
	i++ // the last size byte
	if i >= len(body) {
		t.Fatalf("body of %d bytes has no local declarations", len(body))
	}
	return int(body[i])
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
	if got := planBTRegions([]*bucket{{isFallback: true}}, 0); got != nil {
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
	regions := planBTRegions(withMemo, 0)
	if regions == nil {
		t.Fatal("no regions planned for two Backtracking buckets")
	}
	if regions.stackLimit <= regions.stackBase {
		t.Errorf("empty stack region: base %d, limit %d", regions.stackBase, regions.stackLimit)
	}
	// Everything above the stack must be laid out in order and inside `end`,
	// or two regions share an address and one silently overwrites the other.
	if regions.winScratch < regions.stackLimit || regions.slotScratch <= regions.winScratch ||
		regions.end <= regions.slotScratch {
		t.Errorf("regions overlap or run backwards: %+v", *regions)
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
	regions := planBTRegions([]*bucket{{isFallback: true, btFallback: info}}, 0)
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
	buildSetBTSuffixBody(info, regions, 0, 0, 0, true, true, 0)
}

// TestSetEmitBTProbeBodyAnchored emits a Backtracking bucket's probe in its
// ANCHORED form.
//
// The anchored probe adds one check the non-anchored one does not have: a
// match that ends before `len` is not an anchored match, since `match_*` must
// span the whole input. No caller passes anchored=true today — the anchored
// capabilities reach their Backtracking members another way — so this is
// called directly, and what it establishes is that the arm still builds and
// still produces a longer body than the non-anchored one.
func TestSetEmitBTProbeBodyAnchored(t *testing.T) {
	info := admitBTFallback(parseForBTFallback(t, `[0-9]+x`), 0)
	if info == nil {
		t.Fatal("the witness pattern was refused by the Backtracking fallback")
	}
	regions := planBTRegions([]*bucket{{isFallback: true, btFallback: info}}, 0)
	loose := buildSetBTProbeBody(regions, 7, false, 0)
	anchored := buildSetBTProbeBody(regions, 7, true, 0)
	if len(anchored) <= len(loose) {
		t.Errorf("the anchored probe emitted %d bytes and the non-anchored %d: "+
			"the full-consumption check is missing", len(anchored), len(loose))
	}
	if anchored[len(anchored)-1] != 0x0B {
		t.Errorf("the anchored probe does not end with `end` (0x0B), got %#x",
			anchored[len(anchored)-1])
	}
}

// TestSetEmitSuffixCallSkipDefault covers the constant-zero `skip` a non-batch
// caller passes.
//
// Once a set's suffix functions carry the §19 skip parameter, EVERY caller
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
			name: "u16-and-non-power-of-two-row", patterns: []string{`[ab].{6}[cd]|[0-9]`},
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
//   - a SPARSE bucket is refused outright, because G17's rule is that nothing
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
	regions := planBTRegions(buckets, 0)
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
	if int(regions.winScratch-regions.memoBase) < largest {
		t.Errorf("memo region is %d bytes, smaller than the largest bucket's %d",
			regions.winScratch-regions.memoBase, largest)
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
// One emitter, not two: item 22 fix 2a gave the gated body the overlapping
// body's alive-marking write-back, at which point the two were the same code.
func TestSetEmitPreflightWithNoPatterns(t *testing.T) {
	empty := &compiledSet{}
	if got := emitFindPreflight(nil, empty, 8, 9, 10, 3, 1, 2, 13, 0, false, 11, 12); len(got) != 0 {
		t.Errorf("the preflight emitted %d bytes for a set with no patterns", len(got))
	}
}

// TestSetEmitRetiredScanCapabilityArms emits the bodies for capScan.
//
// `scan:` was RETIRED as a config key (TODO task 59 decision (2)): its answer
// is `scan_any(...) >= 0`, and the redundancy measured at 1-3% of module size.
// No YAML config can select it, so nothing below is reachable through
// CompileFile — but capScan is still a value of the internal setCapKind enum
// and every one of these switches still carries an arm for it. They are
// emitted here so that an arm which stops building is a test failure rather
// than something discovered when the kind is next used.
//
// This is a deliberate white-box call on a kind the config layer rejects; it
// asserts that the arms produce bodies, and nothing about what a `scan`
// capability would mean.
func TestSetEmitRetiredScanCapabilityArms(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find", ScanAny: "s_scan_any", ScanAll: "s_scan_all"}
	compiled := setEmitCovCompileSet(t, spec, litLessNeverDying, CompileSetOptions{})
	if compiled.unionScan == nil {
		t.Fatal("no union automaton was built; the union body cannot be emitted")
	}
	body := emitUnionScanBody(compiled.unionScan, capScan, compiled.fullIDMask(), 0)
	if len(body) == 0 || body[len(body)-1] != 0x0B {
		t.Errorf("the capScan union body is empty or unterminated (%d bytes)", len(body))
	}

	ctx := newSetFindCtx(compiled, 0, 0, 0, capScan, 0)
	if got := ctx.emitRecordProbe(nil, 0); len(got) == 0 {
		t.Error("emitRecordProbe emitted nothing for capScan")
	}
	if got := ctx.emitEpilogue(nil); len(got) == 0 {
		t.Error("emitEpilogue emitted nothing for capScan")
	}
	if got := ctx.emitDrainCheck(nil, ctx.lPos, 1); len(got) == 0 {
		t.Error("emitDrainCheck emitted nothing for capScan")
	}

	// The SPARSE probe recorder is a separate switch with its own capScan arm,
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
	sparseCtx := newSetFindCtx(sparseSet, 0, 0, 0, capScan, 0)
	if got := sparseCtx.emitRecordProbe(nil, sparseBucket); len(got) == 0 {
		t.Error("emitRecordProbe emitted nothing for a sparse bucket under capScan")
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
// downgrades is the §13 F1 failure mode — the set still answers correctly, it
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
		t.Fatal("the frontend was downgraded with no diagnostic — a silent downgrade is the §13 F1 failure mode")
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
