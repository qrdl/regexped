package compile

import (
	"bytes"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// decodeShuftiPairs reproduces, in Go, exactly what the emitted SIMD does to
// one byte: swizzle both nibble tables of every pair, AND them, OR the pairs,
// and report whether anything survived. Testing against this rather than
// against buildShuftiPairs' own internals is the point — it is the emitted
// arithmetic that has to be exact, not the bookkeeping that produced it.
func decodeShuftiPairs(pairs [][2][16]byte, c byte) bool {
	var merged byte
	for _, p := range pairs {
		merged |= p[0][c&0x0F] & p[1][c>>4]
	}
	return merged != 0
}

// TestBuildShuftiPairsExact is the correctness contract for the rectangle
// cover: for EVERY byte 0..255 the emitted test must agree with real set
// membership. A false positive here is not wasted work — the same primitive
// decides whether a byte keeps a set walk in its state (see
// encodeMemberSet), where a false positive skips a byte that should have
// left the state and reports the wrong extent, silently.
func TestBuildShuftiPairsExact(t *testing.T) {
	check := func(t *testing.T, name string, set []byte) {
		t.Helper()
		var want [256]bool
		for _, c := range set {
			want[c] = true
		}
		pairs := buildShuftiPairs(set)
		if len(pairs) > 2 {
			t.Fatalf("%s: got %d pairs, want <= 2 (16 rows cannot need more)", name, len(pairs))
		}
		for c := 0; c < 256; c++ {
			if got := decodeShuftiPairs(pairs, byte(c)); got != want[c] {
				t.Fatalf("%s: byte %#02x membership = %v, want %v", name, c, got, want[c])
			}
		}
	}

	rangeSet := func(lo, hi byte) []byte {
		var out []byte
		for c := int(lo); c <= int(hi); c++ {
			out = append(out, byte(c))
		}
		return out
	}
	union := func(sets ...[]byte) []byte {
		var out []byte
		for _, s := range sets {
			out = append(out, s...)
		}
		return out
	}

	// The classes this compiler actually meets, plus the structural edges.
	named := map[string][]byte{
		"empty":            nil,
		"single":           {'a'},
		"a-z":              rangeSet('a', 'z'),
		"A-Za-z":           union(rangeSet('A', 'Z'), rangeSet('a', 'z')),
		"word":             union(rangeSet('0', '9'), rangeSet('A', 'Z'), rangeSet('a', 'z'), []byte{'_'}),
		"printable-nosp":   rangeSet('!', '~'),
		"printable":        rangeSet(' ', '~'),
		"a-z0-9":           union(rangeSet('0', '9'), rangeSet('a', 'z')),
		"control":          rangeSet(0x00, 0x1f),
		"high":             rangeSet(0x80, 0xff),
		"all":              rangeSet(0x00, 0xff),
		"nul-only":         {0x00},
		"ff-only":          {0xff},
		"nibble-corners":   {0x00, 0x0f, 0xf0, 0xff},
		"punct":            []byte("<>{}[]|`"),
		"one-per-row":      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"eight-rows-alike": {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70},
	}
	for name, set := range named {
		check(t, name, set)
	}

	// "one-per-row" above is the worst case for the cover: 16 rows, every mask
	// distinct, so it must use both pairs. If a future change made the cover
	// coarser this assertion is what notices.
	if n := len(buildShuftiPairs(named["one-per-row"])); n != 2 {
		t.Errorf("16 distinct row masks used %d pairs, want exactly 2", n)
	}
	// The everyday classes must all collapse to one pair — that IS the
	// optimisation, and a regression to two would silently halve it.
	for _, name := range []string{"a-z", "A-Za-z", "word", "printable", "printable-nosp", "a-z0-9", "all"} {
		if n := len(buildShuftiPairs(named[name])); n != 1 {
			t.Errorf("%s used %d pairs, want 1", name, n)
		}
	}

	// Random sets, including sets far wider than the old one-bit-per-member
	// encoding could express at all.
	rng := rand.New(rand.NewSource(20260902))
	for i := 0; i < 500; i++ {
		n := 1 + rng.Intn(256)
		perm := rng.Perm(256)[:n]
		set := make([]byte, n)
		for j, v := range perm {
			set[j] = byte(v)
		}
		check(t, "random", set)
	}
}

// TestEmitShuftiPrefixCheckEmpty pins the empty-set early return: the emitter
// must leave an i32 on the stack even with nothing to test, or the enclosing
// body fails WASM validation rather than merely answering wrongly.
func TestEmitShuftiPrefixCheckEmpty(t *testing.T) {
	got := emitShuftiPrefixCheck(nil, nil, 9)
	if len(got) != 2 || got[0] != 0x41 || got[1] != 0x00 {
		t.Errorf("emitShuftiPrefixCheck(empty set) = % x, want 41 00 (i32.const 0)", got)
	}
}

// TestShuftiMaskPolarities pins the contract between the two emitters: they
// must differ in the final lane comparison and in NOTHING else.
//
// The stop polarity replaced a member mask followed by `i32.const 0xFFFF;
// i32.xor`. That the xor is redundant rests on i8x16.bitmask zero-extending
// its result, so the complement over the 16 relevant lanes is exactly what
// `lane == 0` produces. If someone reintroduces the xor, or flips the compare
// in the wrong emitter, every bulk skip in the compiler advances to the first
// byte that IS a member — a walk that stops immediately and never strides,
// which costs performance silently rather than failing.
func TestShuftiMaskPolarities(t *testing.T) {
	const (
		opEq = 0x23 // i8x16.eq, after the 0xFD prefix
		opNe = 0x24 // i8x16.ne
	)
	for _, set := range [][]byte{
		[]byte("abcdefghijklmnopqrstuvwxyz"),
		[]byte("0123456789"),
		{0x00, 0x7F, 0x80, 0xFF},
	} {
		member := emitShuftiPrefixCheck(nil, set, 7)
		stop := emitShuftiStopMask(nil, set, 7)
		if len(member) != len(stop) {
			t.Fatalf("polarities differ in length: member %d, stop %d — the stop "+
				"mask must be the same emission with one opcode changed",
				len(member), len(stop))
		}
		diffs := 0
		for i := range member {
			if member[i] != stop[i] {
				diffs++
				if member[i] != opNe || stop[i] != opEq {
					t.Fatalf("byte %d differs as %#02x/%#02x, want the compare "+
						"opcode %#02x/%#02x", i, member[i], stop[i], opNe, opEq)
				}
			}
		}
		if diffs != 1 {
			t.Fatalf("polarities differ in %d bytes, want exactly 1 (the compare)", diffs)
		}
		// No 0xFFFF constant may survive in either emission: its presence is
		// the signature of the inversion this replaced.
		for i := 0; i+3 < len(stop); i++ {
			if stop[i] == 0x41 && stop[i+1] == 0xFF && stop[i+2] == 0xFF && stop[i+3] == 0x03 {
				t.Fatalf("stop mask still emits i32.const 0xFFFF at byte %d", i)
			}
		}
	}
}

// TestShuftiStopMaskEmptySet pins the empty-set constant, which is the one
// place the two polarities legitimately differ by more than an opcode: with no
// members every lane is a non-member, so the stop mask's honest answer is
// 0xFFFF and the member mask's is 0.
func TestShuftiStopMaskEmptySet(t *testing.T) {
	if got := emitShuftiPrefixCheck(nil, nil, 7); len(got) != 2 || got[0] != 0x41 || got[1] != 0x00 {
		t.Errorf("member mask on empty set = % x, want i32.const 0", got)
	}
	got := emitShuftiStopMask(nil, nil, 7)
	if len(got) == 0 || got[0] != 0x41 {
		t.Fatalf("stop mask on empty set = % x, want an i32.const", got)
	}
	if v, _, err := utils.DecodeSLEB128(got[1:]); err != nil || v != 0xFFFF {
		t.Errorf("stop mask on empty set = i32.const %d (err %v), want 65535", v, err)
	}
}

// The three prefix-resume DIVERGENCE arms of buildFindBody.
//
// After the SIMD prefix scan matches, the find body must resume the DFA in the
// state the prefix walk ends in — but there are up to four such states, one per
// context the scan can land in: the ordinary mid-string walk, the walk from the
// true start (attempt_start==0), the walk taken when the preceding byte was a
// word character, and the walk taken when it was '\n'. buildFindBody picks
// between them with three flags, and three of its arms exist only for the cases
// where those walks DISAGREE.
//
// The shape that makes them disagree is an alternation where only ONE branch
// carries the anchor while BOTH branches share the mandatory literal prefix.
// computePrefix truncates to the common BYTE prefix of the start and mid-start
// walks, but consuming the same bytes can still land in DIFFERENT STATES: from
// startState the anchored branch is still alive, from midStartState it is dead.
// `^AB\d|AB[a-z]` forces "AB" either way, yet the start walk ends somewhere
// that still accepts \d while the mid walk ends somewhere that only accepts
// [a-z].
//
// Why this test exists at all: these arms were once measured "unreachable" and
// came within a decision of being deleted. The corpus that reached that verdict
// generated only SINGLE-BRANCH shapes ({literal} x {leading assertion} x
// {tail}), where an anchor gates the whole match and therefore suppresses
// prefix extraction outright — so it never built the one shape that fires the
// flags. Deleting the arms would have silently lost every match at position 0,
// after a '\n', or after a word/non-word byte for this pattern family. The
// assertions below are therefore two-directional: they fail if a flag stops
// firing (the arm goes quietly dead again) as well as if the wrong arm is
// chosen.
//
// SCOPE, stated plainly so this file is not over-trusted: it pins the LAYOUT
// (the four resume states really do diverge) and the SELECTION (which arm a
// given divergence picks), and it emits each arm so the bytecode-building
// statements execute and the module is validated. It does NOT observe what
// buildFindBody does with its own flags — forcing newlineDiverges and
// startDiverges to false inside buildFindBody leaves every assertion here
// passing while 48 behavioral rows go red. The behavioral net is the
// PrefixResumeDivergence block in tools/re2test/custom-tests.txt, which runs
// the emitted WASM against Go-stdlib expectations; the two layers are
// complementary and neither substitutes for the other.
//
// Note the asymmetry this pins down: computePrefix has an explicit
// word-boundary divergence bail-out — it returns nil and disables the fast-skip
// entirely — but NO newline analogue. That makes the newline arm the only thing
// standing between these patterns and the lost-match bug its own comment in
// engine_dfa.go records.

// prefixResumeArm names the branch of buildFindBody's switch that a given flag
// combination selects, so a failure says which arm went missing rather than
// only which boolean moved.
type prefixResumeArm string

const (
	armConstant       prefixResumeArm = "constant (no divergence)"
	armStartOnly      prefixResumeArm = "start-divergence only"
	armWordOnly       prefixResumeArm = "word divergence"
	armNewlineOnly    prefixResumeArm = "newline divergence"
	armWordAndNewline prefixResumeArm = "word and newline divergence"
)

// selectPrefixResumeArm mirrors buildFindBody's own switch (engine_dfa.go
// ~8982) so the table below can state which arm a pattern must reach.
func selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges bool) prefixResumeArm {
	needsByteRead := wordDiverges || newlineDiverges
	switch {
	case !needsByteRead && !startDiverges:
		return armConstant
	case !needsByteRead && startDiverges:
		return armStartOnly
	case wordDiverges && !newlineDiverges:
		return armWordOnly
	case !wordDiverges && newlineDiverges:
		return armNewlineOnly
	default:
		return armWordAndNewline
	}
}

func TestPrefixResumeDivergenceArms(t *testing.T) {
	cases := []struct {
		pattern             string
		wantWordDiverges    bool
		wantNewlineDiverges bool
		wantStartDiverges   bool
		wantArm             prefixResumeArm
		why                 string
	}{
		{
			pattern:           `^A|AB`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why: "single-byte prefix 'A': from startState the ^A branch can accept " +
				"immediately, from midStartState only the AB branch survives",
		},
		{
			pattern:           `^AB\d|AB[a-z]`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why: "two-byte prefix 'AB': the start walk still admits \\d, the mid walk " +
				"only [a-z]",
		},
		{
			pattern:           `\AAB\d|AB[a-z]`,
			wantStartDiverges: true,
			wantArm:           armStartOnly,
			why:               "\\A is the same divergence as ^ under OneLine parsing",
		},
		{
			pattern:          `\bAB`,
			wantWordDiverges: true,
			wantArm:          armWordOnly,
			why: "single branch, leading word boundary: the word-context walk dies " +
				"because \\b cannot hold after a word byte, while the mid-string walk " +
				"survives. The only row where a byte must be read but the start walk " +
				"agrees, so it is also what covers the inner !startDiverges leg",
		},
		{
			pattern:             `(?m:^)AB\d|AB[a-z]`,
			wantNewlineDiverges: true,
			wantStartDiverges:   true,
			wantArm:             armNewlineOnly,
			why: "the multiline anchor makes the after-'\\n' walk diverge the same way " +
				"the begin-of-text walk does",
		},
		{
			pattern:             `(?m:^AB\d)|\bAB[a-z]`,
			wantWordDiverges:    true,
			wantNewlineDiverges: true,
			wantStartDiverges:   true,
			wantArm:             armWordAndNewline,
			why:                 "one branch anchored to a line start, the other to a word boundary",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.pattern, func(t *testing.T) {
			// Build the DFA exactly as compile.go's LF-DFA find path does; a
			// different option set here would prove nothing about the code that
			// actually ships.
			matcher, err := compile(testCase.pattern, CompileOptions{
				MaxDFAStates:  1024,
				ForceEngine:   EngineDFA,
				LeftmostFirst: true,
			})
			if err != nil {
				t.Fatalf("compile %q: %v", testCase.pattern, err)
			}
			table := dfaTableFrom(matcher.(*dfa))
			layout := buildDFALayout(dfaLayoutParams{
				t:                    table,
				tableBase:            0,
				needFind:             true,
				leftmostFirst:        true,
				compiledDFAThreshold: 256,
			})

			// The pattern has to actually REACH buildFindBody's prefix path.
			// Each of these routes elsewhere, and each has silently absorbed a
			// witness pattern before: `0*^0` diverges exactly as intended but
			// isAnchoredFind sends it to buildAnchoredFindBody instead, which
			// is how the arms came to look unreachable in the first place.
			if len(layout.prefix) == 0 {
				t.Fatalf("no mandatory literal prefix: the prefix-scan resume path is "+
					"never emitted, so this pattern cannot exercise any arm (%s)", testCase.why)
			}
			if isAnchoredFind(table) {
				t.Fatalf("isAnchoredFind routes this to buildAnchoredFindBody, " +
					"bypassing the arms under test")
			}
			if dfaHasOutrankedState(table) || dfaHasAmbiguousBoundaryTarget(table) {
				t.Fatalf("routed to Backtracking (outranked=%v ambiguousBoundary=%v), "+
					"bypassing the arms under test",
					dfaHasOutrankedState(table), dfaHasAmbiguousBoundaryTarget(table))
			}

			// Recomputed exactly as buildFindBody does (engine_dfa.go ~8978).
			wordDiverges := layout.needWordCharTable &&
				layout.wasmPrefixEnd != layout.wasmPrefixEndWord
			newlineDiverges := table.hasNewlineBoundary &&
				layout.wasmPrefixEnd != layout.wasmPrefixEndNewline
			startDiverges := layout.wasmPrefixEnd != layout.wasmPrefixEndStart

			if wordDiverges != testCase.wantWordDiverges ||
				newlineDiverges != testCase.wantNewlineDiverges ||
				startDiverges != testCase.wantStartDiverges {
				t.Errorf("divergence flags = word:%v newline:%v start:%v, "+
					"want word:%v newline:%v start:%v\n"+
					"  prefix=%q resume states: mid=%d word=%d newline=%d start=%d\n"+
					"  %s",
					wordDiverges, newlineDiverges, startDiverges,
					testCase.wantWordDiverges, testCase.wantNewlineDiverges, testCase.wantStartDiverges,
					layout.prefix, layout.wasmPrefixEnd, layout.wasmPrefixEndWord,
					layout.wasmPrefixEndNewline, layout.wasmPrefixEndStart,
					testCase.why)
			}

			if arm := selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges); arm != testCase.wantArm {
				t.Errorf("selects the %q arm, want %q", arm, testCase.wantArm)
			}

			// Emit for real: this is what executes the arm's bytecode-building
			// statements and validates that what it built is a legal module.
			mustCompileEntries(t, []config.RegexEntry{{
				Pattern:  testCase.pattern,
				FindFunc: "diverge_find",
			}})
		})
	}
}

// TestPrefixResumeConstantArmStillReached is the control. The three divergence
// arms are only interesting relative to the ordinary case, and a change that
// broke prefix extraction outright would otherwise make the test above fail in
// a way that looks like the arms disappearing rather than the prefix machinery
// disappearing underneath them.
func TestPrefixResumeConstantArmStillReached(t *testing.T) {
	// A plain literal, deliberately: it is the shape whose find body reaches
	// the no-divergence arm through the public pipeline. A prefixed pattern
	// with a long counted tail (`ghp_[a-zA-Z0-9]{36}`) does not — it routes to
	// the literal-anchor find body instead and would emit none of this switch.
	const pattern = `abc`
	matcher, err := compile(pattern, CompileOptions{
		MaxDFAStates:  1024,
		ForceEngine:   EngineDFA,
		LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	table := dfaTableFrom(matcher.(*dfa))
	layout := buildDFALayout(dfaLayoutParams{
		t:                    table,
		tableBase:            0,
		needFind:             true,
		leftmostFirst:        true,
		compiledDFAThreshold: 256,
	})
	if len(layout.prefix) == 0 {
		t.Fatalf("a plain literal-prefixed pattern lost its prefix; the divergence " +
			"tests above are measuring nothing")
	}
	wordDiverges := layout.needWordCharTable && layout.wasmPrefixEnd != layout.wasmPrefixEndWord
	newlineDiverges := table.hasNewlineBoundary && layout.wasmPrefixEnd != layout.wasmPrefixEndNewline
	startDiverges := layout.wasmPrefixEnd != layout.wasmPrefixEndStart
	if arm := selectPrefixResumeArm(wordDiverges, newlineDiverges, startDiverges); arm != armConstant {
		t.Errorf("an unanchored literal-prefix pattern selects the %q arm, want %q",
			arm, armConstant)
	}
	mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "constant_find"}})
}

// Unit coverage for the small routers and pure helpers that decide what the
// emitters emit. They are cheap to reach directly and expensive to reach
// through a compile, because each needs a DFA of a particular shape — so the
// end-to-end corpora exercise the common answer and never the tie-breaks.

// dwTable builds a synthetic dfaTable with the given per-state self-loop byte
// counts. State s self-loops on the first selfLoops[s] bytes and leaves on the
// rest, which is exactly the shape both walk routers score.
func dwTable(selfLoops []int, accepting bool) *dfaTable {
	n := len(selfLoops)
	t := &dfaTable{
		numStates:       n,
		transitions:     make([]int, n*256),
		acceptStates:    map[int]uint64{},
		midAcceptStates: map[int]uint64{},
	}
	for s := 0; s < n; s++ {
		for b := 0; b < 256; b++ {
			if b < selfLoops[s] {
				t.transitions[s*256+b] = s // self-loop
			} else {
				t.transitions[s*256+b] = (s + 1) % n // leaves
			}
		}
		if accepting {
			t.acceptStates[s] = 1
		}
	}
	return t
}

// dominantWalkStates ranks candidate states by self-loop coverage, widest
// first, and keeps at most dominantMaxStates of them. Both the ordering and
// the cap decide which state the emitted bulk skip is built around, so a wrong
// answer is a silent performance loss rather than a failure — the kind nothing
// else notices.
func TestDominantWalkStatesOrdersAndCaps(t *testing.T) {
	// Three qualifying states, deliberately in ASCENDING coverage order, so
	// the result is only right if the ranking actually reorders them.
	tab := dwTable([]int{250, 252, 254}, false)
	got := dominantWalkStates(tab)

	if len(got) != dominantMaxStates {
		t.Fatalf("got %d states, want %d (the cap) — three qualified",
			len(got), dominantMaxStates)
	}
	if got[0].Coverage < got[1].Coverage {
		t.Errorf("states came back widest-last: %d then %d",
			got[0].Coverage, got[1].Coverage)
	}
	// The widest is state index 2, emitted as WASM state 3.
	if got[0].WASMState != 3 || got[0].Coverage != 254 {
		t.Errorf("widest state = WASM %d coverage %d, want 3 / 254",
			got[0].WASMState, got[0].Coverage)
	}
	// Below the self-loop floor nothing qualifies at all. Two states, because
	// with one the "leaves" edge wraps back to the same state and every byte
	// would self-loop.
	if s := dominantWalkStates(dwTable([]int{dominantSelfLoopMin - 1, 0}, false)); len(s) != 0 {
		t.Errorf("a state with %d self-loops qualified; the floor is %d",
			dominantSelfLoopMin-1, dominantSelfLoopMin)
	}
	if s := dominantWalkStates(nil); s != nil {
		t.Error("a nil table produced states")
	}
	if s := dominantWalkStates(&dfaTable{}); s != nil {
		t.Error("a zero-state table produced states")
	}
}

// memberWalkStates is the same router one level down, for the sparse member
// self-loop skip: it looks only at ACCEPTING states and only at narrow
// self-loops (memberSelfLoopMax), because the skip's whole premise is that a
// run through such a state changes nothing but the position.
func TestMemberWalkStatesOrdersAndGuards(t *testing.T) {
	if s := memberWalkStates(nil); s != nil {
		t.Error("a nil table produced states")
	}
	if s := memberWalkStates(&dfaTable{}); s != nil {
		t.Error("a zero-state table produced states")
	}

	// Two accepting states with 1 and 2 self-loop bytes, ascending, so the
	// ranking has to reorder them. Both are inside memberSelfLoopMax.
	tab := dwTable([]int{1, 2}, true)
	got := memberWalkStates(tab)
	if len(got) != 2 {
		t.Fatalf("got %d states, want 2", len(got))
	}
	if got[0].Coverage < got[1].Coverage {
		t.Errorf("states came back widest-last: %d then %d",
			got[0].Coverage, got[1].Coverage)
	}

	// A NON-accepting state is not a member-skip candidate however narrow its
	// self-loop: the skip suppresses per-byte recording, and there is nothing
	// to suppress where nothing accepts.
	if s := memberWalkStates(dwTable([]int{1, 2}, false)); len(s) != 0 {
		t.Errorf("%d non-accepting states qualified for the member skip", len(s))
	}
	// And a self-loop wider than the cap is refused.
	if s := memberWalkStates(dwTable([]int{memberSelfLoopMax + 1}, true)); len(s) != 0 {
		t.Errorf("a %d-byte self-loop qualified; the cap is %d",
			memberSelfLoopMax+1, memberSelfLoopMax)
	}
}

// emitOverlapDPTransition reads the transition table two ways, and which one it
// emits is a property of the LAYOUT rather than of the set: a u16 table with
// duplicate rows carries a rowMap, and the walk must go through it. Emitting
// the direct form against a deduplicated table indexes by state into a table
// indexed by row — a valid module reading the wrong cells.
func TestEmitOverlapDPTransitionRowDedup(t *testing.T) {
	base := &dfaLayout{tableOff: 4096}
	direct := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: base}, 0, 3, 4, 5)

	deduped := &dfaLayout{tableOff: 4096, useRowDedup: true, rowMapOff: 2048}
	viaRowMap := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: deduped}, 0, 3, 4, 5)

	if len(viaRowMap) <= len(direct) {
		t.Errorf("the rowMap form is %d bytes and the direct one %d; the extra "+
			"indirection must emit strictly more", len(viaRowMap), len(direct))
	}
	// The rowMap base appears only in the deduplicated form.
	rowMapConst := []byte{0x41, 0x80, 0x10} // i32.const 2048, SLEB128
	if !bytes.Contains(viaRowMap, rowMapConst) {
		t.Error("the rowMap form never loads rowMapOff")
	}
	if bytes.Contains(direct, rowMapConst) {
		t.Error("the direct form loads a rowMap it was not given")
	}

	// Byte-class compression narrows the stride from 256 to numClasses, which
	// is the other half of the address computation.
	compressed := &dfaLayout{tableOff: 4096, useCompression: true, numClasses: 7}
	comp := emitOverlapDPTransition(nil, overlapDPTables{ok: true, l: compressed}, 0, 3, 4, 5)
	if bytes.Equal(comp, direct) {
		t.Error("compression did not change the emitted stride")
	}
}

// shuftiPrefixPlan is the frontend chooser for the first-byte prefilter. The
// widest band exists only under prefer-no-match AND only where the caller has
// reserved the dense-switch locals, because the switch is what bounds a wrong
// bet — so `canAdapt` is a promise about the frame, not a preference.
func TestShuftiPrefixPlanBands(t *testing.T) {
	set := func(n int) []byte {
		s := make([]byte, n)
		for i := range s {
			s[i] = byte(i)
		}
		return s
	}

	// At or below 16 the scalar compare chain wins outright.
	if use, dense := shuftiPrefixPlan(set(16), true, true); use || dense {
		t.Errorf("16 first bytes selected Shufti (use=%v dense=%v)", use, dense)
	}
	// The wide band: past maxShuftiFirstBytes, only with both flags.
	wide := set(maxShuftiFirstBytes + 1)
	if use, dense := shuftiPrefixPlan(wide, true, true); !use || !dense {
		t.Errorf("the wide band was refused with both flags (use=%v dense=%v)", use, dense)
	}
	if use, _ := shuftiPrefixPlan(wide, true, false); use {
		t.Error("the wide band was taken without the dense-switch locals reserved")
	}
	if use, _ := shuftiPrefixPlan(wide, false, true); use {
		t.Error("the wide band was taken without prefer-no-match")
	}
	// Past even the widened ceiling, nothing.
	if use, _ := shuftiPrefixPlan(set(maxShuftiFirstBytesLNM+1), true, true); use {
		t.Errorf("a set of %d first bytes selected Shufti", maxShuftiFirstBytesLNM+1)
	}
}

// firstByteSet powers the per-pattern eligibility masks, and its contract is
// "nil means undetermined, assume every byte". A non-ASCII rune is led by a
// UTF-8 lead byte rather than by the rune, so deriving a first BYTE from it
// would be wrong — the function gives up instead, and a caller that took a
// derived answer here would skip positions where a match can begin.
func TestFirstByteSetGivesUpOnNonASCII(t *testing.T) {
	if got := firstByteSet(`\x{00e9}cafe`); got != nil {
		t.Error("a pattern starting with a non-ASCII rune produced a first-byte set")
	}
	if got := firstByteSet(`[`); got != nil {
		t.Error("an unparseable pattern produced a first-byte set")
	}
	// The positive control: an ordinary ASCII pattern resolves, and only to
	// the bytes that can actually lead it.
	got := firstByteSet(`abc`)
	if got == nil {
		t.Fatal("an ASCII literal produced no first-byte set")
	}
	if !got['a'] {
		t.Error("'a' is not marked startable for /abc/")
	}
	for _, b := range []byte{'b', 'c', 'z'} {
		if got[b] {
			t.Errorf("%q is marked startable for /abc/", b)
		}
	}
}

// Small helpers whose second branch no ordinary compile selects. Each is one
// or two statements, but each is also a decision the emitted module depends on
// — a memory index, a released region, a test-only override — and an untested
// branch in any of them fails silently rather than loudly.

// TestAppendTableLoadV128At covers both memory forms of the v128 table load.
//
// Standalone modules keep their tables in memory 0 and use the short encoding;
// embedded ones import the host's memory as 0 and their tables become memory 1
// after wasm-merge, which needs the multi-memory form with an explicit index.
// Emitting the short form for an embedded module would read the HOST's memory
// at the table's offset.
func TestAppendTableLoadV128At(t *testing.T) {
	standalone := appendTableLoadV128At(nil, 0x1234, 0)
	embedded := appendTableLoadV128At(nil, 0x1234, 1)

	// v128.load is 0xFD 0x00; then the memarg. The standalone form has align
	// 0 and no memory index; the embedded one sets the multi-memory flag.
	if len(standalone) < 3 || standalone[0] != 0xFD || standalone[1] != 0x00 {
		t.Fatalf("standalone form does not start with v128.load: % x", standalone)
	}
	if standalone[2] != 0x00 {
		t.Errorf("standalone align byte = %#x, want 0x00", standalone[2])
	}
	if len(embedded) < 4 || embedded[2] != 0x40 {
		t.Fatalf("embedded form does not set the multi-memory flag: % x", embedded)
	}
	if embedded[3] != 0x01 {
		t.Errorf("embedded memory index = %d, want 1", embedded[3])
	}
	// Both must encode the same offset, so the only difference is the memarg.
	if off, _, err := utils.DecodeULEB128(standalone[3:]); err != nil || off != 0x1234 {
		t.Errorf("standalone offset = %d (%v), want 0x1234", off, err)
	}
	if off, _, err := utils.DecodeULEB128(embedded[4:]); err != nil || off != 0x1234 {
		t.Errorf("embedded offset = %d (%v), want 0x1234", off, err)
	}
	if bytes.Equal(standalone, embedded) {
		t.Error("both memory forms emitted identical bytes")
	}
}

// TestRegionAllocSkip covers the release path: a region reserved and then not
// needed must leave the frontier exactly where it was, alignment included, or
// every later region shifts and the tables overlap.
func TestRegionAllocSkip(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 10, 1)
	before := ra.End()

	ra.Reserve("maybe", 64)
	ra.Skip()
	if got := ra.End(); got != before {
		t.Errorf("End() after Skip = %d, want %d — a skipped region moved the frontier",
			got, before)
	}
	// The allocator must be usable again immediately.
	if got := ra.Bump("b", 8, 1); got != before {
		t.Errorf("next Bump after Skip = %d, want %d", got, before)
	}

	// Skipping with nothing outstanding is an emitter bug, not a no-op.
	ra2 := newRegionAlloc(0)
	mustPanic(t, "Skip with no Reserve", func() { ra2.Skip() })
}

// TestCompileSetOptionsOverrides covers the two test-only knobs.
//
// Both exist because `false` is simultaneously a meaningful setting and the
// zero value, so each carries a separate "was it asked for" flag. A With
// method that forgot to set that flag would look like it worked and change
// nothing.
func TestCompileSetOptionsOverrides(t *testing.T) {
	var zero CompileSetOptions
	if zero.forceFrontend || zero.forceShuftiAdaptive {
		t.Fatal("the zero value already claims an override")
	}

	fe := zero.WithForcedFrontend(frontendShufti)
	if !fe.forceFrontend || fe.ForceFrontend != frontendShufti {
		t.Errorf("WithForcedFrontend: flag=%v value=%v", fe.forceFrontend, fe.ForceFrontend)
	}
	// Forcing the ZERO frontend kind must still register as an override.
	fe0 := zero.WithForcedFrontend(0)
	if !fe0.forceFrontend {
		t.Error("WithForcedFrontend(0) did not record that an override was asked for")
	}

	for _, on := range []bool{true, false} {
		sa := zero.WithShuftiAdaptive(on)
		if !sa.forceShuftiAdaptive || sa.ForceShuftiAdaptive != on {
			t.Errorf("WithShuftiAdaptive(%v): flag=%v value=%v",
				on, sa.forceShuftiAdaptive, sa.ForceShuftiAdaptive)
		}
	}
	// The receiver is a value, so the original must be untouched.
	if zero.forceFrontend || zero.forceShuftiAdaptive {
		t.Error("a With method mutated its receiver")
	}
}

// TestDominantWalkStatesEdges covers the empty-table guard, which is the arm a
// caller reaches when a pattern compiled to nothing at all.
func TestDominantWalkStatesEdges(t *testing.T) {
	if got := dominantWalkStates(nil); got != nil {
		t.Errorf("dominantWalkStates(nil) = %v, want nil", got)
	}
	if got := dominantWalkStates(&dfaTable{}); got != nil {
		t.Errorf("dominantWalkStates(empty) = %v, want nil", got)
	}
	// A real table must report at least one state, or this test is passing on
	// the guards alone. The shape has to be a state that self-loops on nearly
	// EVERY byte with a handful of exceptions — the polarity this detector
	// wants — rather than a narrow class like [a-z], whose 230 exceptions put
	// it far past dominantMaxExceptions.
	tbl := compileTestDFA(t, `"[^"]*"`, true)
	if got := dominantWalkStates(tbl); len(got) == 0 {
		t.Error("a pattern with a wide self-loop reported no dominant walk states")
	}
}

// ── The absence-literal prefilter's AST walk ───────────────────────────────
//
// findAbsenceLit answers "does every match of this pattern contain this exact
// byte string?", which the absence prefilter uses to retire a pattern from the
// alive mask without walking it. The direction of any error matters
// asymmetrically: claiming a literal that is NOT mandatory under-approximates
// alive and silently loses matches, while missing one merely costs a walk.
//
// It is a pure function of the parsed AST, so the refusals — the interesting
// half — are testable directly rather than through a compiled set.
func TestFindAbsenceLit(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    string // "" = no literal claimed
	}{
		{"plain literal", `abcd`, "abcd"},
		{"literal inside a concat", `[a-z]+MIDDLE[0-9]+`, "MIDDLE"},
		{"longest child of a concat wins", `xy[0-9]LONGEST[a-z]ab`, "LONGEST"},
		{"plus body is mandatory", `(?:abc)+`, "abc"},
		{"repeat with min >= 1", `(?:abc){2,4}`, "abc"},

		// Refusals. Each is a case where claiming the literal would be wrong.
		{"alternation: mandatory in one branch only", `abc|xyz`, ""},
		{"star: the body may be skipped", `(?:abc)*`, ""},
		{"quest: the body may be skipped", `(?:abc)?`, ""},
		{"repeat with min 0", `(?:abc){0,3}`, ""},
		{"case-folded literal needs a case-insensitive search", `(?i)abcd`, ""},
		{"non-ASCII literal needs UTF-8 encoding", `caf\x{e9}xx`, ""},
		{"a class is not a literal", `[a-z]+`, ""},
		{"empty", `(?:)`, ""},

		// A capture is transparent: its body's literal is still mandatory.
		// Reached only when captures are NOT stripped first, which is how
		// findAbsenceLit is called from analyses that run before stripping.
		{"capture is transparent", `(abcd)`, "abcd"},
		{"capture inside a concat", `x(MIDDLE)y`, "MIDDLE"},

		// A literal longer than absenceLitMax is TRUNCATED rather than
		// refused: a prefix of a mandatory literal is still mandatory, and a
		// shorter needle is only weaker, never wrong.
		{"over the length cap", `abcdefghijklmnopqrstuvwxyz0123456789`, "abcdefghijklmnop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re, err := syntax.Parse(tc.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.pattern, err)
			}
			got := string(findAbsenceLit(re.Simplify()))
			if got != tc.want {
				t.Errorf("findAbsenceLit(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
	// A nil AST is reachable from the recursive walk over a malformed subtree.
	if got := findAbsenceLit(nil); got != nil {
		t.Errorf("findAbsenceLit(nil) = %q, want nil", got)
	}
}

// TestFindAbsenceLitIsSound is the property behind the whole prefilter: any
// literal it claims must appear in EVERY string the pattern matches.
//
// Checked against Go's own engine over generated inputs, because the walk is
// an approximation and the cheap way to be wrong is to claim a literal from a
// branch that some match does not take.
func TestFindAbsenceLitIsSound(t *testing.T) {
	patterns := []string{
		`abcd`, `[a-z]+MIDDLE[0-9]+`, `(?:abc)+`, `(?:abc){2,4}`,
		`x[0-9]{2}KEY[a-f]*`, `PRE(?:a|b)POST`, `[0-9]+-[0-9]+`,
		`abc|xyz`, `(?:abc)*def`, `(?i)abcd`,
	}
	inputs := []string{
		"", "abcd", "abcdabcd", "zzMIDDLE99", "x12KEYaf", "PREaPOST", "PREbPOST",
		"12-34", "xyz", "def", "abcdef", "ABCD", "MIDDLE", "abc",
		"qqqabcdqqq", "  abcd  ", "aMIDDLEb", "x99KEY",
	}
	for _, pat := range patterns {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		lit := findAbsenceLit(re.Simplify())
		if len(lit) == 0 {
			continue
		}
		goRe, gerr := regexp.Compile(pat)
		if gerr != nil {
			t.Fatalf("Go rejects %q: %v", pat, gerr)
		}
		for _, in := range inputs {
			if !goRe.MatchString(in) {
				continue
			}
			// The pattern matched, so the claimed literal must be present.
			if !containsBytes(in, string(lit)) {
				t.Errorf("%q claims mandatory literal %q, but it matches %q, "+
					"which does not contain it — the prefilter would drop a real match",
					pat, lit, in)
			}
		}
	}
}

func containsBytes(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
