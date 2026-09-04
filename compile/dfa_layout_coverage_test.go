package compile

import (
	"regexp/syntax"
	"testing"
)

// dfaLayoutCovTable compiles pattern to a leftmost-first dfaTable, the exact
// shape buildDFALayout consumes in production. Kept separate from
// compileTestDFA so this file's cases can be read without cross-referencing
// another file's leftmostFirst argument.
func dfaLayoutCovTable(t *testing.T, pattern string) *dfaTable {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("syntax.Parse(%q): %v", pattern, err)
	}
	re = re.Simplify()
	prog, err := syntax.Compile(re)
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	dfa, ok := newDFA(prog, false, true, maxHelperDFAStates)
	if !ok {
		t.Fatalf("newDFA(%q): state limit exceeded", pattern)
	}
	return dfaTableFrom(dfa)
}

// dfaLayoutCovBuild builds a find-mode layout for pattern. params carries the
// knobs under test; its t field is filled in here so cases only have to name
// the flags they actually care about.
func dfaLayoutCovBuild(t *testing.T, pattern string, params dfaLayoutParams) (*dfaTable, *dfaLayout) {
	t.Helper()
	table := dfaLayoutCovTable(t, pattern)
	params.t = table
	return table, buildDFALayout(params)
}

// dfaLayoutCovFindParams mirrors appendFindCodeEntry's find-mode defaults:
// needFind and leftmostFirst on, no compiled-DFA promotion (which would route
// emission to the hybrid dispatch bodies instead of buildFindBody).
func dfaLayoutCovFindParams() dfaLayoutParams {
	return dfaLayoutParams{needFind: true, leftmostFirst: true, compiledDFAThreshold: 0}
}

// TestDFALayoutTeddyTiers pins how deep the Teddy prefilter is built for
// shapes the rest of the corpus does not produce: word-boundary patterns
// (where the filter must union the prev-is-word and prev-is-non-word
// continuations) and patterns whose continuation set is
// too wide for a 64-bit filter lane.
//
// A regression here is silent: an over-narrow filter drops real matches, an
// over-deep tier is unsound the moment a match can end inside the tier.
func TestDFALayoutTeddyTiers(t *testing.T) {
	cases := []struct {
		pattern                string
		wantT1, wantT2, wantT3 bool
		why                    string
	}{
		// Both start contexts stay alive through four bytes: `\b` fires from
		// midStart (prev non-word) and `\B` from midStartWord (prev word), so
		// every tier has to walk the midStartWordState chain alongside the
		// midStartState one.
		{`(?:\b|\B)(?:abcde|xyzwv)`, true, true, true, "word-context union at all three tiers"},
		// From the word context `\Bx` completes the match on the first byte
		// while the non-word context still needs a 'y', so no second-byte
		// requirement is sound at all and even T1 has to give up.
		{`\Bx|xy|wv`, false, false, false, "word context accepts at depth 1"},
		// One byte deeper: 'a' is dead in the non-word context but completes
		// `\Bxa` in the word one, and 'a' is reached before the non-word
		// context's own accept on 'y', so T2 is the tier that gives up. The
		// third branch is three bytes long so it does not itself accept at
		// depth 2 and shortcut the case.
		{`\Bxa|x+y|wvu`, true, false, false, "word context accepts at depth 2"},
		// Same again at depth 3: only `\Bxyz` finishes there, and only in the
		// word context, so T1 and T2 are sound and T3 is not.
		{`\Bxyz|xyab|wvuts`, true, true, false, "word context accepts at depth 3"},
		// 82 possible second bytes blows the 64-bit filter lane at T1.
		{`(?:q|w)[\x20-\x71]`, false, false, false, "second-byte set wider than 64"},
		{`(?:qa|wb)[\x20-\x71]`, true, false, false, "third-byte set wider than 64"},
		{`(?:qax|wby)[\x20-\x71]`, true, true, false, "fourth-byte set wider than 64"},
		{`(?:qaxm|wbyn)[\x20-\x71]`, true, true, true, "fifth byte is where it gets wide"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if len(layout.prefix) != 0 {
				t.Fatalf("%q: prefix %q is non-empty, so the Teddy tiers are never built — case is not testing what it claims",
					tc.pattern, layout.prefix)
			}
			gotT1 := len(layout.teddyT1LoBytes) > 0
			gotT2 := len(layout.teddyT2LoBytes) > 0
			gotT3 := len(layout.teddyT3LoBytes) > 0
			if gotT1 != tc.wantT1 || gotT2 != tc.wantT2 || gotT3 != tc.wantT3 {
				t.Errorf("%q: T1/T2/T3 = %v/%v/%v, want %v/%v/%v",
					tc.pattern, gotT1, gotT2, gotT3, tc.wantT1, tc.wantT2, tc.wantT3)
			}
		})
	}
}

// TestDFALayoutFirstByteFlagsWordContext covers the fast-skip first-byte set
// for a pattern that can match zero-width at the start state under a word
// context only. Miss the wbAccept*Start0 unions and the prefix scan never
// looks at bytes that are valid only in that context — the position-0
// sibling of the mid-string case.
func TestDFALayoutFirstByteFlagsWordContext(t *testing.T) {
	// `\b` alone accepts zero-width at the start state exactly when the next
	// byte is a word char, so every word byte must be a candidate first byte
	// while non-word bytes stay out (the `x+y` branch contributes 'x' only).
	table, layout := dfaLayoutCovBuild(t, `\b|x+y`, dfaLayoutCovFindParams())
	if !table.hasWordBoundary {
		t.Fatal(`\b|x+y: expected hasWordBoundary`)
	}
	if len(layout.firstBytes) == 256 {
		t.Fatal(`\b|x+y: all 256 bytes flagged — the zero-width start accept took the "everything" branch, not the per-context union`)
	}
	if !isWordCharByte('a') || layout.firstByteFlags['a'] == 0 {
		t.Error(`\b|x+y: word byte 'a' must be a candidate first byte (\b fires before it at position 0)`)
	}
	if layout.firstByteFlags[' '] != 0 {
		t.Error(`\b|x+y: non-word byte ' ' must not be a candidate — \b cannot fire before it from a non-word context`)
	}
}

// TestDFALayoutRowDedup covers u16 transition-row deduplication. Two distinct
// all-dead terminal states (one EOF-only accepting, one accepting anywhere)
// keep minimization from merging them while their 512-byte rows are
// identical, which is what pushes uniqueRows below the 255-entry rowMap cap.
//
// Everything downstream of the layout reads transitions through a rowMap
// indirection once this is on, so the detectors are re-run here as well.
func TestDFALayoutRowDedup(t *testing.T) {
	// 1 start + 127 x-chain + 128 y-chain = 256 DFA states = 257 WASM states,
	// one over the u8 limit. `$` makes the x terminal EOF-accept-only.
	const pattern = `x{127}$|y{128}`
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
	if layout.useU8 {
		t.Fatalf("%s: expected a u16 table (got %d WASM states) — row dedup is u16-only", pattern, layout.numWASM)
	}
	if !layout.useRowDedup {
		t.Fatalf("%s: expected row dedup (numWASM=%d)", pattern, layout.numWASM)
	}
	if layout.numUniqueRows >= layout.numWASM || layout.numUniqueRows > 255 {
		t.Errorf("%s: uniqueRows=%d, want < numWASM=%d and <= 255", pattern, layout.numUniqueRows, layout.numWASM)
	}
	if len(layout.rowMapBytes) != layout.numWASM {
		t.Errorf("%s: rowMap has %d entries, want one per WASM state (%d)", pattern, len(layout.rowMapBytes), layout.numWASM)
	}
	if len(layout.tableBytes) != layout.numUniqueRows*512 {
		t.Errorf("%s: table is %d bytes, want %d (uniqueRows * 512)", pattern, len(layout.tableBytes), layout.numUniqueRows*512)
	}

	// The rowMap must be an emitted segment in both find and match layouts,
	// otherwise the runtime indirection reads uninitialised memory.
	for _, needFind := range []bool{true, false} {
		segments := dfaDataSegments(layout, needFind, false)
		if len(segments) == 0 {
			t.Fatalf("%s: dfaDataSegments(needFind=%v) produced nothing", pattern, needFind)
		}
		raw, count := stripSegCount(segments)
		if count == 0 || len(raw) == 0 {
			t.Errorf("%s: dfaDataSegments(needFind=%v) declared %d segments over %d bytes", pattern, needFind, count, len(raw))
		}
	}

	// A deduped table plus an accelerable self-loop state: the Shufti detector
	// reads the same transition rows and must go through the rowMap too, or it
	// records a self-loop set belonging to some other state entirely. The third
	// alternative supplies both the extra all-dead terminal that keeps
	// uniqueRows under the cap and the 16-byte hex run to accelerate.
	const shuftiPattern = `x{100}$|y{153}|[0-9a-f]{2,}q`
	shuftiParams := dfaLayoutCovFindParams()
	shuftiParams.lmBareShufti = true
	shuftiParams.lmNonMidShufti = true
	_, shuftiLayout := dfaLayoutCovBuild(t, shuftiPattern, shuftiParams)
	if !shuftiLayout.useRowDedup {
		t.Fatalf("%s: expected row dedup (numWASM=%d)", shuftiPattern, shuftiLayout.numWASM)
	}
	found := false
	for _, info := range shuftiLayout.dominantStates {
		if len(info.selfLoopSet) > 0 {
			found = true
			if int(info.state) >= shuftiLayout.numWASM {
				t.Errorf("%s: Shufti state %d outside [0,%d)", shuftiPattern, info.state, shuftiLayout.numWASM)
			}
		}
	}
	if !found {
		t.Errorf("%s: no Shufti self-loop state detected in a row-deduped table", shuftiPattern)
	}
}

// TestDFALayoutSkipSafeOnDead covers the dead-state skip-safety analysis,
// including condition (f) — the alternative entry states an intermediate
// attempt can begin in when the previous byte was a word char or a newline
// . Wrongly returning true here makes the
// find loop jump over real matches.
func TestDFALayoutSkipSafeOnDead(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
		why     string
	}{
		// midStartWord has an empty accept class (`\b` wants a non-word byte,
		// `[a-z]+` wants a letter), so an attempt entering there dies on its
		// first byte having recorded nothing — condition (f) case 1.
		{`\b[a-z]+\b`, true, "alternative entry state cannot consume anything"},
		// succ's off-class exit on '\n' reaches a state that is neither dead
		// nor mid-accepting — it EOF-accepts later, at a position the original
		// attempt's trajectory never visited. Condition (e) has to reject it.
		{`[a-z]+\n$`, false, "successor leaves the trajectory into a later-accepting state"},
		// From midStartWord `\B` resolves before the word char 'z' and the
		// attempt consumes it into Match: an off-class byte reaching a live
		// state, which case 2 must reject.
		{`\Bz|x+y`, false, "off-class byte leaves the stable trajectory"},
		// Same idea one byte deeper: from midStartWord the class byte 'x'
		// leads to a state that is not midStart's single successor.
		{`\Bxz|x+y`, false, "class byte reaches a different successor"},
		// midStartNewline records a zero-width `(?m:^)` match that the skip
		// would jump straight over.
		{`(?m:^)|x+y`, false, "alternative entry state is mid-accepting"},
		// Condition (d)'s per-channel checks on midStart itself: each of these
		// records a zero-width match through one context channel only.
		{`\B|11*0`, false, "midStart mid-accepts through the non-word channel"},
		{`\b|x+y`, false, "midStart mid-accepts through the word channel"},
		{`(?m:$)|x+y`, false, "midStart mid-accepts through the newline channel"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if layout.skipSafeOnDead != tc.want {
				t.Errorf("%q: skipSafeOnDead = %v, want %v (%s)", tc.pattern, layout.skipSafeOnDead, tc.want, tc.why)
			}
		})
	}
}

// TestDFALayoutDominantSelfLoopNewlineExit covers the '\n' carve-out
// carve-out: a state that records matches only through the newline
// channel looks non-mid-accepting, so the bulk skip would stride over every
// '\n' without ever running the newline pre-accept check. '\n' therefore has
// to leave the self-loop set — and when there is no room left in the 8-byte
// Shufti exit set, the state must not be accelerated at all.
func TestDFALayoutDominantSelfLoopNewlineExit(t *testing.T) {
	cases := []struct {
		pattern       string
		wantDominant  bool
		wantExitBytes string
		why           string
	}{
		{`a[^b]*(?m:$)`, true, "\nb", "one exit byte plus the carved '\\n' fits the 8-byte cap"},
		{`a[^bcdefghi]*(?m:$)`, false, "", "8 exit bytes already — no room to carve '\\n' out"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			_, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			var got []dominantInfo
			for _, info := range layout.dominantStates {
				if len(info.exitBytes) > 0 {
					got = append(got, info)
				}
			}
			if !tc.wantDominant {
				if len(got) != 0 {
					t.Errorf("%q: got %d dominant states, want none (%s)", tc.pattern, len(got), tc.why)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%q: got %d dominant states, want exactly 1", tc.pattern, len(got))
			}
			if string(got[0].exitBytes) != tc.wantExitBytes {
				t.Errorf("%q: exit bytes = %q, want %q", tc.pattern, got[0].exitBytes, tc.wantExitBytes)
			}
		})
	}
}

// TestDFALayoutShuftiSelfLoop covers detectShuftiSelfLoop's LikelyMatch-gated
// channels: the non-mid-accept branch (LM-3), the same '\n' carve-out as the
// dominant detector, and the byte-class-compressed table reader.
func TestDFALayoutShuftiSelfLoop(t *testing.T) {
	cases := []struct {
		pattern      string
		wantMid      bool
		wantSelfSize int
		wantCompress bool
		why          string
	}{
		// 10 digits + '\n' self-loop, `(?m:$)` accept: non-mid by the ctx=0
		// read, so '\n' is carved back out and 10 bytes remain.
		{`a[0-9\n]*(?m:$)`, false, 10, false, "non-mid shufti with '\\n' carved out"},
		// Trailing 'b' keeps the digit-run state non-accepting; no boundary
		// channel fires, so the whole 10-byte set survives.
		{`a[0-9]+b`, false, 10, false, "non-mid shufti, no boundary channel"},
		// >128 states forces byte-class compression, so the self-loop set has
		// to be recovered from classMap rather than read byte-for-byte.
		{`a[0-9]{140}[a-z]+`, true, 26, true, "mid-accept shufti over a compressed table"},
		{`[a-z]{140}[0-9a-f]+q`, false, 16, true, "non-mid shufti over a compressed table"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			params := dfaLayoutCovFindParams()
			// LM-4 lifts the "needs a literal anchor" bail and LM-3 enables the
			// non-mid channel; both are LikelyMatch-only in production.
			params.lmBareShufti = true
			params.lmNonMidShufti = true
			_, layout := dfaLayoutCovBuild(t, tc.pattern, params)
			if layout.useCompression != tc.wantCompress {
				t.Fatalf("%q: useCompression = %v, want %v (numWASM=%d)", tc.pattern, layout.useCompression, tc.wantCompress, layout.numWASM)
			}
			var found *dominantInfo
			for idx := range layout.dominantStates {
				if len(layout.dominantStates[idx].selfLoopSet) > 0 {
					found = &layout.dominantStates[idx]
				}
			}
			if found == nil {
				t.Fatalf("%q: no Shufti self-loop state detected", tc.pattern)
			}
			if found.isMidAccept != tc.wantMid {
				t.Errorf("%q: isMidAccept = %v, want %v", tc.pattern, found.isMidAccept, tc.wantMid)
			}
			if len(found.selfLoopSet) != tc.wantSelfSize {
				t.Errorf("%q: self-loop set has %d bytes, want %d", tc.pattern, len(found.selfLoopSet), tc.wantSelfSize)
			}
			for _, selfByte := range found.selfLoopSet {
				if selfByte == '\n' && !tc.wantMid {
					t.Errorf("%q: '\\n' left in a non-mid self-loop set — the skip would stride past a newline accept", tc.pattern)
				}
			}
		})
	}
}

// TestDFALayoutDataSegmentsAcceptSideTable covers the TDFA-flavoured segment
// emission (useAcceptSideTable) on the find path. The declared segment count
// leads the blob, so a table emitted without being counted — or counted
// without being emitted — corrupts every module that embeds it.
func TestDFALayoutDataSegmentsAcceptSideTable(t *testing.T) {
	// Leftmost-first stops at the first alternative, so `ab` is an immediate
	// accept and the layout carries an immediate-accept side table too — the
	// second thing the TDFA flavour has to count and emit.
	const pattern = `ab|abc`
	params := dfaLayoutCovFindParams()
	_, plain := dfaLayoutCovBuild(t, pattern, params)
	params.useAcceptSideTable = true
	_, sideTable := dfaLayoutCovBuild(t, pattern, params)
	if !sideTable.hasImmAccept {
		t.Fatalf("%q: expected an immediate-accept state — case is not testing what it claims", pattern)
	}

	if len(sideTable.acceptBytes) != sideTable.numWASM {
		t.Fatalf("%q: acceptBytes has %d entries, want one per WASM state (%d)", pattern, len(sideTable.acceptBytes), sideTable.numWASM)
	}
	if len(plain.acceptBytes) != 0 {
		t.Fatalf("%q: DFA layouts must not emit an accept side table (state IDs are partitioned instead)", pattern)
	}

	_, plainCount := stripSegCount(dfaDataSegments(plain, true, false))
	rawSide, sideCount := stripSegCount(dfaDataSegments(sideTable, true, false))
	wantExtra := 1
	if sideTable.hasImmAccept {
		wantExtra = 2 // accept side table + immediate-accept side table
	}
	if int(sideCount) != int(plainCount)+wantExtra {
		t.Errorf("%q: side-table layout declares %d segments, want %d (%d + %d)", pattern, sideCount, int(plainCount)+wantExtra, plainCount, wantExtra)
	}
	if len(rawSide) == 0 {
		t.Errorf("%q: side-table layout emitted no segment bytes", pattern)
	}
}

// TestDFALayoutDataSegmentsCompressedTeddy covers segment emission for a
// byte-class-compressed find layout that also carries all three Teddy tiers —
// the deepest nesting in dfaDataSegments, and the one whose segment count is
// assembled from the most independent pieces.
func TestDFALayoutDataSegmentsCompressedTeddy(t *testing.T) {
	// 143 WASM states pushes the u8 table past 32 KB (compression on); the
	// leading class means there is no mandatory literal prefix, so the Teddy
	// tables are built and emitted.
	const pattern = `[ab][0-9]{140}`
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
	if !layout.useCompression {
		t.Fatalf("%q: expected byte-class compression (numWASM=%d)", pattern, layout.numWASM)
	}
	if len(layout.prefix) != 0 {
		t.Fatalf("%q: expected no literal prefix, got %q — the Teddy segments are only emitted on the prefix-less path", pattern, layout.prefix)
	}
	if len(layout.teddyT3LoBytes) == 0 {
		t.Fatalf("%q: expected all four Teddy tiers", pattern)
	}
	raw, count := stripSegCount(dfaDataSegments(layout, true, false))
	// classMap + table + midAccept + firstByte + 8 Teddy tables.
	if count < 12 {
		t.Errorf("%q: declared %d segments, want at least 12 (classMap+table+midAccept+firstByte+8 Teddy)", pattern, count)
	}
	if len(raw) == 0 {
		t.Errorf("%q: no segment bytes emitted", pattern)
	}

	// The same compressed find layout WITH a literal prefix takes the other
	// arm: the prefix scan replaces the first-byte and Teddy tables entirely,
	// so those segments must be neither counted nor emitted.
	const prefixed = `a[0-9]{140}[a-z]+`
	_, prefixedLayout := dfaLayoutCovBuild(t, prefixed, dfaLayoutCovFindParams())
	if !prefixedLayout.useCompression || len(prefixedLayout.prefix) == 0 {
		t.Fatalf("%q: want compression with a literal prefix, got useCompression=%v prefix=%q",
			prefixed, prefixedLayout.useCompression, prefixedLayout.prefix)
	}
	prefixedRaw, prefixedCount := stripSegCount(dfaDataSegments(prefixedLayout, true, false))
	if prefixedCount >= count {
		t.Errorf("%q: declared %d segments, want fewer than the prefix-less layout's %d", prefixed, prefixedCount, count)
	}
	if len(prefixedRaw) == 0 {
		t.Errorf("%q: no segment bytes emitted", prefixed)
	}
}

// TestDFALayoutSuffixWASMEmptyDFA covers genSuffixWASM's degenerate input.
// A bucket whose suffix DFA came back empty must still produce a callable
// function body that reports "no matches" rather than an empty body the
// module validator would reject.
func TestDFALayoutSuffixWASMEmptyDFA(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table *dfaTable
	}{
		{"nil table", nil},
		{"zero-state table", &dfaTable{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodyArt, data, segCount, nextOff := genSuffixWASM(tc.table, 4096, 0, []int{7}, []int{0}, LikelyNeutral, false, false)
			body := bodyArt.fnBody
			if len(body) == 0 {
				t.Fatal("empty function body")
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("body does not end with the WASM `end` opcode: % x", body)
			}
			if len(data) != 0 || segCount != 0 {
				t.Errorf("empty DFA emitted %d data bytes in %d segments, want none", len(data), segCount)
			}
			if nextOff != 4096 {
				t.Errorf("nextTableOffset = %d, want the unchanged base 4096", nextOff)
			}
		})
	}
}

// TestDFALayoutSuffixWASMWideBucket covers the 32-pattern ceiling in
// buildSetSuffixBody. The per-pattern endPos locals are indexed by bit
// position in a 32-bit mask, so a bucket carrying more patterns than that has
// to stop emitting per-pattern code at bit 32 rather than run off the end of
// the local space.
func TestDFALayoutSuffixWASMWideBucket(t *testing.T) {
	// A word-boundary suffix also exercises the wbNW/wbW bitmask tables, which
	// only genSuffixWASM emits.
	table := dfaLayoutCovTable(t, `\b[a-z]+\b`)
	const wide = 40
	patternIDs := make([]int, wide)
	prefixFixedLens := make([]int, wide)
	for idx := range patternIDs {
		patternIDs[idx] = 100 + idx
	}
	bodyArt, data, segCount, nextOff := genSuffixWASM(table, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false)
	body := bodyArt.fnBody
	if len(body) == 0 {
		t.Fatal("empty function body for a 40-pattern bucket")
	}
	if segCount < 5 {
		t.Errorf("segCount = %d, want at least 5 (layout + mid/eof/imm bitmasks + word-boundary bitmasks)", segCount)
	}
	if len(data) == 0 || nextOff <= 0 {
		t.Errorf("data=%d bytes nextTableOffset=%d, want a non-empty table region", len(data), nextOff)
	}

	// The same bucket at exactly 32 patterns must emit strictly less code:
	// bits 32..39 contribute nothing, so the two bodies cannot be equal in
	// size unless the ceiling silently dropped earlier bits too.
	narrowBodyArt, _, _, _ := genSuffixWASM(table, 0, 0, patternIDs[:32], prefixFixedLens[:32], LikelyNeutral, false, false)
	narrowBody := narrowBodyArt.fnBody
	if len(narrowBody) != len(body) {
		t.Errorf("32-pattern body is %d bytes and 40-pattern body is %d; patterns past bit 32 must contribute no code", len(narrowBody), len(body))
	}

	// The same ceiling applies inside the dominant-state bulk skip, which only
	// a suffix carrying a mid-accepting dominant state emits: `[^b]*` accepts
	// at every position and self-loops on all but one byte.
	dominantTable := dfaLayoutCovTable(t, `a[^b]*`)
	_, dominantLayout := dfaLayoutCovBuild(t, `a[^b]*`, dfaLayoutParams{leftmostFirst: true})
	midDominant := false
	for _, info := range dominantLayout.dominantStates {
		if info.isMidAccept && len(info.exitBytes) > 0 {
			midDominant = true
		}
	}
	if !midDominant {
		t.Fatalf(`a[^b]*: expected a mid-accepting dominant state — case is not testing what it claims`)
	}
	if dominantBodyArt, _, _, _ := genSuffixWASM(dominantTable, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false); len(dominantBodyArt.fnBody) == 0 {
		t.Error(`a[^b]*: empty function body for a 40-pattern bucket`)
	}

	// A suffix DFA over 256 states switches the transition emitter to the u16
	// table shape, which is a different instruction sequence entirely.
	wideTable := dfaLayoutCovTable(t, `x{127}$|y{128}`)
	_, wideLayout := dfaLayoutCovBuild(t, `x{127}$|y{128}`, dfaLayoutParams{leftmostFirst: true})
	if wideLayout.useU8 {
		t.Fatalf(`x{127}$|y{128}: expected a u16 suffix table (numWASM=%d)`, wideLayout.numWASM)
	}
	if wideBodyArt, _, _, _ := genSuffixWASM(wideTable, 0, 0, []int{1, 2}, []int{0, 0}, LikelyNeutral, false, false); len(wideBodyArt.fnBody) == 0 {
		t.Error(`x{127}$|y{128}: empty function body for a u16 suffix table`)
	}
}

// TestDFALayoutSuffixWASMCompressed covers buildSetSuffixBody's compressed-u8
// transition emitter, which only a bucket suffix of more than 128 states
// reaches.
func TestDFALayoutSuffixWASMCompressed(t *testing.T) {
	// The trailing `+` keeps this off isCountedClassChain's SIMD shortcut,
	// which would return before a transition table is ever emitted.
	const pattern = `[a-z]{140}[0-9]+x`
	table := dfaLayoutCovTable(t, pattern)
	_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutParams{leftmostFirst: true})
	if !layout.useCompression {
		t.Fatalf("%q: expected byte-class compression (numWASM=%d)", pattern, layout.numWASM)
	}
	// 40 patterns also drives the 32-bit ceiling on this path.
	const wide = 40
	patternIDs := make([]int, wide)
	prefixFixedLens := make([]int, wide)
	for idx := range patternIDs {
		patternIDs[idx] = 200 + idx
	}
	bodyArt, _, _, _ := genSuffixWASM(table, 0, 0, patternIDs, prefixFixedLens, LikelyNeutral, false, false)
	body := bodyArt.fnBody
	if len(body) == 0 {
		t.Fatal("empty function body")
	}
	singleArt, _, _, _ := genSuffixWASM(table, 0, 0, []int{3}, []int{0}, LikelyNeutral, false, false)
	single := singleArt.fnBody
	if len(single) == 0 {
		t.Fatal("empty function body for a single-pattern bucket")
	}
	if len(single) >= len(body) {
		t.Errorf("single-pattern body is %d bytes and 40-pattern body is %d; the wider bucket must emit more per-pattern code", len(single), len(body))
	}
}

// TestDFALayoutFindBodyStartContexts covers buildFindBody's per-attempt entry
// selection. Which state an attempt starts in depends on the byte before it,
// and each divergence (begin-of-text vs mid-string, prev-is-word,
// prev-is-newline) gets its own emitted branch. Two past bugs were missing
// branches here, and both silently lost matches.
func TestDFALayoutFindBodyStartContexts(t *testing.T) {
	cases := []struct {
		pattern string
		why     string
	}{
		// No literal prefix, and the anchored branch gives state 0 transitions
		// midStart does not have → attempt_start == 0 needs its own entry.
		{`^ab|xab`, "begin-of-text entry differs from mid-string"},
		// Same divergence reached through the mandatory-literal path (the
		// literal is not at the match start, so there is no prefix to scan).
		{`(?:^|z)[a-z]+@example\.com`, "mandatory-literal path with a begin-of-text entry"},
		// (?m:^) adds a third entry state selected by "previous byte was \n".
		{`(?m:^)ab|xab`, "newline entry state"},
		// \b and (?m:^) together: word and newline entries plus begin-of-text.
		{`(?m:^)\bab|xab`, "word and newline entry states"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody, not buildFindBody — case is not testing what it claims", tc.pattern)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(tc.pattern), 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("%q: find body does not end with the WASM `end` opcode", tc.pattern)
			}
		})
	}
}

// TestDFALayoutFindBodyPrefixWalkDivergence covers the prefix-scan shortcut's
// four-way choice of where the DFA stands after the literal prefix. The walk
// is context-dependent: `(?m:^)` and `\b` in front of the prefix can leave the
// automaton in a different state depending on the byte before the attempt, and
// attempt_start == 0 is different again.
func TestDFALayoutFindBodyPrefixWalkDivergence(t *testing.T) {
	cases := []struct {
		pattern string
		why     string
	}{
		// Every match starts with "abc", so "abc" is the scanned prefix. The
		// anchored branch is only live at position 0, so the walk from the
		// begin-of-text state ends somewhere the mid-string walk does not.
		{`^abc|abcd`, "begin-of-text walk diverges"},
		// Same, with the anchored branch also live after a '\n'.
		{`(?m:^)abc|abcd`, "newline walk diverges"},
		// `\b` and `(?m:^)` gate different branches, so all four walks — mid,
		// prev-is-word, prev-is-newline and begin-of-text — end differently.
		{`(?:\babcz|(?m:^)abce)|abcd`, "word and newline walks diverge"},
		// The prev-is-word walk dies on the prefix's first byte: `\b` cannot
		// fire between a word char and 'f'. The walk has to stop at the dead
		// state rather than keep indexing transitions from it.
		{`\bfoobar`, "prev-is-word walk dies inside the prefix"},
		// The begin-of-text walk dies instead: at position 0 the higher-priority
		// `^f` branch completes on the first prefix byte, so leftmost-first
		// drops the `foobar` thread and the second byte has nowhere to go.
		{`^f|foobar`, "begin-of-text walk dies inside the prefix"},
		// Same shape through the prev-is-newline entry.
		{`(?m:^)f|foobar`, "prev-is-newline walk dies inside the prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody — case is not testing what it claims", tc.pattern)
			}
			if len(layout.prefix) == 0 {
				t.Fatalf("%q: no literal prefix, so the prefix-walk shortcut is never emitted", tc.pattern)
			}
			diverges := layout.wasmPrefixEndStart != layout.wasmPrefixEnd ||
				layout.wasmPrefixEndWord != layout.wasmPrefixEnd ||
				layout.wasmPrefixEndNewline != layout.wasmPrefixEnd
			if !diverges {
				t.Fatalf("%q: all four prefix-end states agree (%d) — nothing diverges to emit",
					tc.pattern, layout.wasmPrefixEnd)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(tc.pattern), 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
		})
	}
}

// TestDFALayoutFindBodyU16NonMidDominant covers the u16 scan loop's accept
// test when the pattern carries a non-mid-accept dominant state. Those states
// occupy the reserved 254/255 values in midAccept's shared value space (task
// 38 v2), so a plain `!= 0` read would treat them as accepting; the emitted
// check has to be the `(val-1) u< 253` range compare instead.
func TestDFALayoutFindBodyU16NonMidDominant(t *testing.T) {
	// 300+ states forces the u16 path; the 62-byte `[0-9a-zA-Z ]+` run is a
	// self-loop that is not itself an accept state (the closing quote is still
	// required), which is what makes it a NON-mid dominant.
	const pattern = `x{300}[0-9a-zA-Z ]+"`
	params := dfaLayoutCovFindParams()
	params.lmNonMidShufti = true // LM-3: the non-mid channel is LikelyMatch-gated
	table, layout := dfaLayoutCovBuild(t, pattern, params)
	if layout.useU8 {
		t.Fatalf("%q: expected a u16 table (numWASM=%d)", pattern, layout.numWASM)
	}
	nonMid := 0
	for _, info := range layout.dominantStates {
		if !info.isMidAccept {
			nonMid++
		}
	}
	if nonMid == 0 {
		t.Fatalf("%q: expected at least one non-mid dominant state", pattern)
	}
	body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, findMandatoryLit(pattern), 0)
	if len(body) == 0 {
		t.Fatalf("%q: empty find body", pattern)
	}
}

// TestDFALayoutFindBodyMandatoryLit covers the mandatory-literal find path —
// the one taken when the pattern's guaranteed literal is NOT at the match
// start, so there is no prefix to scan and the DFA restarts from the literal's
// possible match origins instead.
func TestDFALayoutFindBodyMandatoryLit(t *testing.T) {
	cases := []struct {
		pattern      string
		wantCompress bool
		why          string
	}{
		// The anchored branch gives the begin-of-text state transitions
		// midStart lacks, so the per-attempt prologue needs both entries.
		{`(?:^x|y)[a-z]{0,20}@example\.com`, false, "begin-of-text entry on the mandatory-literal path"},
		// 154 states push the u8 table past 32 KB, so the same path has to be
		// emitted with byte-class-compressed transitions and its own local
		// layout (the SIMD literal scan needs four extra locals).
		{`[a-z]{140}@example\.com`, true, "compressed transitions on the mandatory-literal path"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table, layout := dfaLayoutCovBuild(t, tc.pattern, dfaLayoutCovFindParams())
			if isAnchoredFind(table) {
				t.Fatalf("%q routes to buildAnchoredFindBody — case is not testing what it claims", tc.pattern)
			}
			if len(layout.prefix) != 0 {
				t.Fatalf("%q: literal prefix %q present, so the mandatory-literal path is not taken", tc.pattern, layout.prefix)
			}
			lit := findMandatoryLit(tc.pattern)
			if lit == nil || len(lit.bytes) == 0 {
				t.Fatalf("%q: no mandatory literal found — case is not testing what it claims", tc.pattern)
			}
			if layout.useCompression != tc.wantCompress {
				t.Fatalf("%q: useCompression = %v, want %v (numWASM=%d)", tc.pattern, layout.useCompression, tc.wantCompress, layout.numWASM)
			}
			body, _, _, _ := appendFindCodeEntryTwinned(nil, layout, table, lit, 0)
			if len(body) == 0 {
				t.Fatalf("%q: empty find body", tc.pattern)
			}
			if body[len(body)-1] != 0x0B {
				t.Errorf("%q: find body does not end with the WASM `end` opcode", tc.pattern)
			}
		})
	}
}

// dfaLayoutCovSynthLayout hand-builds a u8 layout: numWASM WASM states where
// every state self-loops on byte values below selfWidth and dies on the rest.
//
// The detectors carry guards no compiled pattern can reach — a state id past
// the end of midAcceptBytes, an entry state past numWASM, more accelerable
// states than the encoding has room for. A table built to order is the only
// way to exercise them, and leaving them uncovered is worse: they are the
// checks that keep a malformed layout from indexing out of bounds.
func dfaLayoutCovSynthLayout(numWASM, selfWidth int) *dfaLayout {
	layout := &dfaLayout{
		numWASM:             numWASM,
		useU8:               true,
		tableBytes:          make([]byte, numWASM*256),
		midAcceptBytes:      make([]byte, numWASM),
		wasmStart:           1,
		wasmMidStart:        1,
		wasmMidStartWord:    1,
		wasmMidStartNewline: 1,
	}
	for state := 1; state < numWASM; state++ {
		for byteValue := 0; byteValue < selfWidth; byteValue++ {
			layout.tableBytes[state*256+byteValue] = byte(state)
		}
	}
	return layout
}

// TestDFALayoutDetectorGuards covers the detectors' defensive bail-outs and
// their encoding-space ceilings.
func TestDFALayoutDetectorGuards(t *testing.T) {
	t.Run("single state", func(t *testing.T) {
		// numWASM == 1 means nothing but the dead state: every detector must
		// bail before it indexes a row that does not exist.
		layout := dfaLayoutCovSynthLayout(1, 250)
		layout.lmBareShufti = true
		detectDominantSelfLoop(layout)
		detectShuftiSelfLoop(layout)
		detectSkipSafeOnDead(layout)
		if len(layout.dominantStates) != 0 || layout.skipSafeOnDead {
			t.Errorf("single-state layout: dominantStates=%d skipSafeOnDead=%v, want 0/false",
				len(layout.dominantStates), layout.skipSafeOnDead)
		}
	})

	t.Run("mid-start state out of range", func(t *testing.T) {
		layout := dfaLayoutCovSynthLayout(4, 10)
		layout.wasmMidStart = 99
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set from an unanalysable mid-start state")
		}
	})

	t.Run("successor out of range", func(t *testing.T) {
		// midStart accepts bytes 0..9 but they all lead to a state id past the
		// end of the table — nothing about that trajectory can be proven.
		layout := dfaLayoutCovSynthLayout(3, 0)
		for byteValue := 0; byteValue < 10; byteValue++ {
			layout.tableBytes[1*256+byteValue] = 5
		}
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set from an out-of-range successor")
		}
	})

	t.Run("entry state out of range", func(t *testing.T) {
		// midStart → succ → succ is a textbook stable trajectory, so
		// conditions (a)-(e) all pass; only the unanalysable begin-of-text
		// entry state stops it.
		layout := dfaLayoutCovSynthLayout(3, 0)
		for byteValue := 0; byteValue < 10; byteValue++ {
			layout.tableBytes[1*256+byteValue] = 2 // midStart -> succ
			layout.tableBytes[2*256+byteValue] = 2 // succ self-loop
		}
		layout.wasmStart = 99
		detectSkipSafeOnDead(layout)
		if layout.skipSafeOnDead {
			t.Error("skipSafeOnDead set despite an out-of-range entry state")
		}
	})

	t.Run("state past the mid-accept table", func(t *testing.T) {
		layout := dfaLayoutCovSynthLayout(3, 250)
		layout.midAcceptBytes = make([]byte, 1) // shorter than numWASM
		detectDominantSelfLoop(layout)
		if len(layout.dominantStates) != 0 {
			t.Errorf("recorded %d dominant states whose mid-accept status is unknown", len(layout.dominantStates))
		}
	})

	t.Run("dominant encoding space exhausted", func(t *testing.T) {
		// 250-byte self-loops with 6 exits make every state dominant. The
		// shared midAccept value space has room for 126 mid-accept dominants
		// and 2 non-mid ones; the rest must be dropped, not encoded on top of
		// the Shufti or plain-accept ranges.
		const numWASM = 200
		const firstNonMid = 151
		layout := dfaLayoutCovSynthLayout(numWASM, 250)
		for state := 1; state < firstNonMid; state++ {
			layout.midAcceptBytes[state] = 1
		}
		detectDominantSelfLoop(layout)
		mid, nonMid := 0, 0
		for _, info := range layout.dominantStates {
			if info.isMidAccept {
				mid++
				if info.encodedByte < 2 || info.encodedByte > 127 {
					t.Errorf("mid dominant state %d encoded as %d, outside the 2..127 range", info.state, info.encodedByte)
				}
			} else {
				nonMid++
				if info.encodedByte < 254 {
					t.Errorf("non-mid dominant state %d encoded as %d, outside the 254..255 range", info.state, info.encodedByte)
				}
			}
		}
		if mid != 126 {
			t.Errorf("kept %d mid-accept dominants, want the 126 the encoding has room for", mid)
		}
		if nonMid != 2 {
			t.Errorf("kept %d non-mid dominants, want the 2 the encoding has room for", nonMid)
		}
	})

	t.Run("shufti encoding space exhausted", func(t *testing.T) {
		// 30-byte self-loops are too narrow for the dominant detector (and
		// their 226 exit bytes blow its 8-byte Shufti cap), so every state
		// falls to detectShuftiSelfLoop, which has room for 126.
		const numWASM = 200
		layout := dfaLayoutCovSynthLayout(numWASM, 30)
		layout.lmBareShufti = true // no literal anchor in a hand-built layout
		for state := 1; state < numWASM; state++ {
			layout.midAcceptBytes[state] = 1
		}
		detectDominantSelfLoop(layout)
		detectShuftiSelfLoop(layout)
		if len(layout.dominantStates) != 126 {
			t.Errorf("kept %d Shufti states, want the 126 the 128..253 encoding range has room for", len(layout.dominantStates))
		}
		for _, info := range layout.dominantStates {
			if info.encodedByte < 128 || info.encodedByte > 253 {
				t.Errorf("Shufti state %d encoded as %d, outside the 128..253 range", info.state, info.encodedByte)
			}
		}
	})
}

// TestDFALayoutDataSegmentsRowDedupWithCompression covers dfaDataSegments'
// handling of a layout carrying BOTH byte-class compression and row dedup.
// buildDFALayout never produces one — compression is u8-only and dedup is
// u16-only — but the serializer accepts the combination, and its segment
// COUNT and its segment BODIES are computed in two separate places. A layout
// that counts the rowMap without emitting it (or the reverse) desynchronises
// every data segment after it in the module.
func TestDFALayoutDataSegmentsRowDedupWithCompression(t *testing.T) {
	build := func() *dfaLayout {
		layout := dfaLayoutCovSynthLayout(4, 250)
		layout.useCompression = true
		layout.numClasses = 4
		layout.tableBytes = make([]byte, 4*4)
		layout.classMapOff = 0
		layout.tableOff = 256
		layout.midAcceptOff = 512
		return layout
	}
	for _, needFind := range []bool{true, false} {
		plain := build()
		deduped := build()
		deduped.useRowDedup = true
		deduped.rowMapOff = 1024
		deduped.rowMapBytes = make([]byte, deduped.numWASM)

		_, plainCount := stripSegCount(dfaDataSegments(plain, needFind, true))
		dedupedRaw, dedupedCount := stripSegCount(dfaDataSegments(deduped, needFind, true))
		if int(dedupedCount) != int(plainCount)+1 {
			t.Errorf("needFind=%v: row-dedup layout declares %d segments, want %d (one more than %d)",
				needFind, dedupedCount, plainCount+1, plainCount)
		}
		if len(dedupedRaw) == 0 {
			t.Errorf("needFind=%v: no segment bytes emitted", needFind)
		}
	}
}

// TestDFALayoutAnchorContextTables walks a battery of zero-width and
// anchor-heavy patterns through DFA construction and layout. These are the
// shapes where the four start contexts (begin-of-text, mid-string,
// prev-is-word, prev-is-newline) genuinely differ, and where the accept
// bitmask can come back empty for a state the leftmost-first pass still
// considers an immediate accept.
//
// The assertions are structural on purpose: a start-context state id or a
// transition target outside the table is a memory-safety bug in every emitted
// body that indexes with it, and it is silent until the WASM traps.
func TestDFALayoutAnchorContextTables(t *testing.T) {
	patterns := []string{
		`^`, `$`, `(?m:^)`, `(?m:$)`, `\b`, `\B`,
		`a*?`, `^x|a*?`, `\Ax|a*?`, `(?m:^)x|a*?`,
		`\b|a*?`, `\B|a*?`, `(?m:$)|a*?`,
		`^ab|xab`, `(?m:^)ab|xab`, `\bab|xab`,
		`x*^x`, `x*\b`, `x*\B`, `(?m:^)x*`, `\b(?m:^)`, `\B\A`,
		`(?m:^)(?m:$)`, `\b\B|x`, `(?:^|\b)x*`,
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			table := dfaLayoutCovTable(t, pattern)
			starts := map[string]int{
				"start":           table.startState,
				"midStart":        table.midStartState,
				"midStartWord":    table.midStartWordState,
				"midStartNewline": table.midStartNewlineState,
			}
			for name, state := range starts {
				if state < 0 || state >= table.numStates {
					t.Fatalf("%q: %s state %d outside [0,%d)", pattern, name, state, table.numStates)
				}
			}
			for i, target := range table.transitions {
				if target < -1 || target >= table.numStates {
					t.Fatalf("%q: transition[%d] = %d, outside [-1,%d)", pattern, i, target, table.numStates)
				}
			}
			_, layout := dfaLayoutCovBuild(t, pattern, dfaLayoutCovFindParams())
			if layout.tableEnd <= int64(layout.tableOff) {
				t.Errorf("%q: tableEnd %d is not past tableOff %d", pattern, layout.tableEnd, layout.tableOff)
			}
		})
	}
}

// TestDFALayoutNFAInputMapFolding covers nfaBuildInputMap's two byte-fanout
// cases the rest of the corpus leaves alone: a case-folded single-rune
// instruction, and a `(?s).` wildcard sharing a state with bytes that already
// have private transition lists.
func TestDFALayoutNFAInputMapFolding(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
		why     string
	}{
		{`(?i)k`, "K", "case-folded single rune (K/k/Kelvin sign fold chain)"},
		{`(?i)s+`, "SsS", "case-folded rune class"},
		{`(?s)x.y`, "x\ny", "wildcard with no competing named byte"},
		// After 'a' both the `.*` wildcard and the literal 'b' are live, so 'b'
		// gets a private transition list the wildcard must be added to as well
		// — miss that and `a.*b` loses every match whose wildcard run contains
		// a 'b'.
		{`(?s)a.*b`, "azbzb", "wildcard alongside a private byte transition"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			table := dfaLayoutCovTable(t, tc.pattern)
			if table.numStates == 0 {
				t.Fatalf("%q: empty DFA", tc.pattern)
			}
			// Walk the input through the table from the start state; a
			// mis-built input map shows up as a dead transition here.
			state := table.startState
			for pos := 0; pos < len(tc.input); pos++ {
				next := table.transitions[state*256+int(tc.input[pos])]
				if next < 0 {
					t.Fatalf("%q: died on byte %d (%q) of %q", tc.pattern, pos, tc.input[pos], tc.input)
				}
				state = next
			}
			if table.acceptStates[state] == 0 {
				t.Errorf("%q: state after %q is not accepting", tc.pattern, tc.input)
			}
		})
	}
}

// TestSoleMidDominant pins the predicate that lets the mid-accept dispatch drop
// its `local.tee` and its `val == encodedByte` compare.
//
// The property is about the TABLE, not about len(dominantStates): a layout can
// carry exactly one dominant and still hold a 1 for some ordinary accept state,
// and that makes a nonzero load ambiguous again. Getting this wrong emits a
// dispatch that treats every accepting state as the dominant and bulk-skips
// from states whose self-loop set it was never given — a wrong answer, not a
// slow one, which is why the false cases below matter more than the true one.
func TestSoleMidDominant(t *testing.T) {
	layoutWith := func(numWASM int, midAccept map[int32]byte, doms []dominantInfo) *dfaLayout {
		l := &dfaLayout{numWASM: numWASM}
		l.midAcceptBytes = make([]byte, numWASM)
		for st, v := range midAccept {
			l.midAcceptBytes[st] = v
		}
		l.dominantStates = doms
		return l
	}
	mid := func(state int32, enc byte) dominantInfo {
		return dominantInfo{state: state, encodedByte: enc, isMidAccept: true}
	}
	nonMid := func(state int32, enc byte) dominantInfo {
		return dominantInfo{state: state, encodedByte: enc, isMidAccept: false}
	}

	cases := []struct {
		name string
		l    *dfaLayout
		want bool
	}{
		{
			// The alpha-run shape: one dominant, its encoding the only
			// nonzero byte in the table.
			name: "sole mid dominant",
			l:    layoutWith(4, map[int32]byte{2: 128}, []dominantInfo{mid(2, 128)}),
			want: true,
		},
		{
			// One dominant, but state 3 also accepts. A nonzero load can be
			// either, so the compare is load-bearing.
			name: "dominant plus a plain accept state",
			l:    layoutWith(4, map[int32]byte{2: 128, 3: 1}, []dominantInfo{mid(2, 128)}),
			want: false,
		},
		{
			name: "two dominants",
			l: layoutWith(5, map[int32]byte{2: 128, 3: 129},
				[]dominantInfo{mid(2, 128), mid(3, 129)}),
			want: false,
		},
		{
			// A non-mid dominant reaches the dispatch through the 254+
			// sub-range and its own channel; the shortcut must not claim it.
			name: "sole non-mid dominant",
			l:    layoutWith(4, map[int32]byte{2: 254}, []dominantInfo{nonMid(2, 254)}),
			want: false,
		},
		{
			name: "no dominants",
			l:    layoutWith(4, map[int32]byte{2: 1}, nil),
			want: false,
		},
		{
			// applyDominantStateEncoding never ran, so the table does not
			// carry the encoding this predicate is about to promise.
			name: "encoding not applied",
			l:    layoutWith(4, nil, []dominantInfo{mid(2, 128)}),
			want: false,
		},
		{
			// The state index is past the table — the same out-of-range guard
			// applyDominantStateEncoding itself carries.
			name: "dominant state out of range",
			l:    layoutWith(3, map[int32]byte{2: 128}, []dominantInfo{mid(9, 128)}),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := soleMidDominant(tc.l); got != tc.want {
				t.Errorf("soleMidDominant = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSoleMidDominantOnRealPatterns checks the predicate against layouts the
// compiler actually builds, so a change to the detectors or to the encoding
// pass cannot leave the unit table above testing a shape that no longer occurs.
func TestSoleMidDominantOnRealPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		mode    LikelyMode
		want    bool
	}{
		// The alpha-run shape: state 20 is the only accepting state and it is
		// the dominant. This is the case the optimisation exists for.
		{`[a-zA-Z]{20,}`, LikelyMatch, true},
		// Neutral compiles no dominant at all for it.
		{`[a-zA-Z]{20,}`, LikelyNeutral, false},
		// A non-mid dominant: the body needs `>` before it accepts.
		{`<[a-z]+>`, LikelyMatch, false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"/"+tc.mode.String(), func(t *testing.T) {
			table := compileTestDFA(t, tc.pattern, true)
			l := buildDFALayout(dfaLayoutParams{
				t:              table,
				tableBase:      0,
				needFind:       true,
				leftmostFirst:  true,
				lmBareShufti:   tc.mode == LikelyMatch,
				lmNonMidShufti: tc.mode == LikelyMatch,
				lmWideShufti:   tc.mode == LikelyMatch,
			})
			applyDominantStateEncoding(l, true)
			if got := soleMidDominant(l); got != tc.want {
				t.Errorf("soleMidDominant = %v, want %v (dominants=%d)",
					got, tc.want, len(l.dominantStates))
			}
		})
	}
}
