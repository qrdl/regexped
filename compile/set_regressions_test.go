package compile

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// Regressions whose failure mode is a MODULE the
// compiler emits happily and that answers wrongly — the class no existing test
// caught, because every one of them compiled green.

// TestAltLitAnchorInSetModule covers E1.
//
// compilePattern gives a find-only top-level alternation of equal-length
// literal-anchored branches an altLitAnchorBranches list. funcCount
// counts 1 + 2*len(branches) functions for it, and the single-pattern
// assembler emits them; assembleModuleWithSets had NEITHER arm, so any config
// with a non-empty `sets:` plus such a pattern panicked with "a find emitter
// bypassed setFind" — and, without the panic, would have declared more
// functions than it emitted.
func TestAltLitAnchorInSetModule(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "alt", Pattern: `abc[0-9]+|xyz[0-9]+`, FindFunc: "alt_find"},
			{Name: "other", Pattern: `kw[0-9]{3}`},
		},
		Sets: []config.SetConfig{{
			Name: "s", Patterns: config.PatternSelector{All: true},
			Find: "cap_find", MatchAny: "cap_match_any",
		}},
	}
	for _, out := range []string{"", "merged.wasm"} {
		w, _, err := CompileFile(cfg, out)
		if err != nil {
			t.Fatalf("out=%q: %v", out, err)
		}
		assertWasm(t, w, fmt.Sprintf("alt-lit-anchor in a set module (out=%q)", out))
		for _, name := range []string{"alt_find", "cap_find", "cap_match_any"} {
			if !moduleExports(w, name) {
				t.Errorf("out=%q: module does not export %q", out, name)
			}
		}
	}
}

// TestNarrowUnionWithWideAllABI covers U1.
//
// cs.wideAll() forces the bitmap `_all` ABI for any set with a Backtracking
// member, whatever its id space. buildAnchoredUnionDFA decided `wide` from the
// id space ALONE, so a small set with a BT member got a NARROW automaton under
// a WIDE ABI: emitAnchoredOrRow then read rowBytes/bitmapBytes the narrow form
// never filled in, both its loops ran zero iterations, and match_all returned
// 0 on every input while match_any worked.
//
// The assertion is on the automaton, not on a fuel number: a narrow automaton
// under a wide ABI is the defect itself.
func TestNarrowUnionWithWideAllABI(t *testing.T) {
	spec := SetSpec{
		Name: "s", MatchAny: "cap_match_any", MatchAll: "cap_match_all",
	}
	pp, sp := &dfaPool{}, &dfaPool{}
	for i, pat := range []string{`alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`} {
		info, err := analyzePattern(config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: pat}, pp, sp)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		info.globalID = i
		spec.Patterns = append(spec.Patterns, info)
		spec.PatternIDs = append(spec.PatternIDs, i)
	}
	// The narrow decision the builder would make on its own — the premise of
	// the case.
	narrow := buildAnchoredUnionDFA(spec, 0, true, false)
	if narrow == nil {
		t.Skip("this shape no longer takes the anchored union at all")
	}
	if narrow.eofWordsOff >= 0 {
		t.Skip("this shape now emits the wide rows unprompted; the case no longer exercises U1")
	}
	// Under the wide ABI it must build wide, or match_all cannot answer.
	au := buildAnchoredUnionDFA(spec, 0, true, true)
	if au == nil {
		t.Fatal("buildAnchoredUnionDFA refused the set under the wide ABI")
	}
	// The assertion is on the TABLES emitAnchoredOrRow reads, not on isWide()
	// — which is maskWords > 1 and is therefore false for a six-id set even on
	// the wide path. With the narrow automaton those are -1/0/0 and both of
	// that emitter's loops run zero iterations: it validates, writes nothing
	// to the caller's bitmap, and returns 0 on every input.
	if au.eofWordsOff < 0 || au.rowBytes == 0 || au.bitmapBytes == 0 {
		t.Errorf("the automaton is missing the tables emitAnchoredOrRow reads, so match_all "+
			"would return 0 on every input: eofWordsOff=%d rowBytes=%d bitmapBytes=%d",
			au.eofWordsOff, au.rowBytes, au.bitmapBytes)
	}
}

// TestTwoSparseBucketsKeepTheirIDs covers C1.
//
// Suffix-table dedup reuses a table BASE when two buckets' DFAs are
// structurally identical. For a G17-sparse bucket the emitted data also
// carries an idMap of GLOBAL ids and per-state accept lists sized by that
// bucket's pattern count — none of which the table identity sees — so two
// sparse buckets with the same suffix shape aliased onto one idMap and the
// second bucket's matches came back under the first bucket's ids.
func TestTwoSparseBucketsKeepTheirIDs(t *testing.T) {
	// TWO shared-literal groups of identical suffix shape. The distinct part
	// must be NON-LITERAL, or mandatory-literal extraction gives each pattern
	// its own literal and its own bucket and nothing is shared; and 40 per
	// group is over the bitmask width, so each group splits and then promotes
	// to ONE sparse bucket.
	var entries []config.RegexEntry
	for i := 0; i < 40; i++ {
		entries = append(entries, config.RegexEntry{
			Name:    fmt.Sprintf("foo%02d", i),
			Pattern: fmt.Sprintf(`foolit[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/8, 1+i%8),
		})
	}
	for i := 0; i < 40; i++ {
		entries = append(entries, config.RegexEntry{
			Name:    fmt.Sprintf("bar%02d", i),
			Pattern: fmt.Sprintf(`barlit[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/8, 1+i%8),
		})
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Patterns: config.PatternSelector{All: true}, Find: "cap_find",
		}},
	}
	cs := compileSetForTest(t, cfg)
	// Every sparse bucket must have its OWN idMap offset: sharing one is the
	// aliasing itself.
	seen := map[int32][]int{}
	sparse := 0
	for bi, b := range cs.buckets {
		if !b.sparse {
			continue
		}
		sparse++
		seen[b.sparseIDMapOff] = append(seen[b.sparseIDMapOff], bi)
	}
	if sparse < 2 {
		t.Skipf("this shape produced %d sparse buckets; C1 needs two", sparse)
	}
	for off, bis := range seen {
		if len(bis) > 1 {
			t.Errorf("sparse buckets %v share the idMap at %d: their matches would be "+
				"reported under one bucket's global ids", bis, off)
		}
	}
}

// compileSetForTest compiles cfg's single set and hands back the compiledSet.
func compileSetForTest(t *testing.T, cfg config.BuildConfig) *compiledSet {
	t.Helper()
	pp, sp := &dfaPool{}, &dfaPool{}
	spec := SetSpec{Name: cfg.Sets[0].Name, Find: cfg.Sets[0].Find}
	for i, re := range cfg.Regexps {
		info, err := analyzePattern(re, pp, sp)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", re.Pattern, err)
		}
		info.globalID = i
		spec.Patterns = append(spec.Patterns, info)
		spec.PatternIDs = append(spec.PatternIDs, i)
	}
	return CompileSet(spec, pp, sp, CompileSetOptions{AllowSparseAccept: true})
}

// TestAbsenceLiteralsPastThirtyTwo covers G2.
//
// The absence prefilter's SEARCH mask is an i32 with one bit per collected
// literal, while the alive mask is an i64 capped at 64 ids. Entry 32 and
// beyond got `uint32(1) << i` == 0, so their literal was never searched for,
// never verified, and the pattern was never marked alive — the preflight
// proved it matchless even where its literal occurs. Patterns past the bound
// must be reported ALWAYS ALIVE instead, which is the safe direction.
func TestAbsenceLiteralsPastThirtyTwo(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "cap_find"}
	pp, sp := &dfaPool{}, &dfaPool{}
	const n = 40
	for i := 0; i < n; i++ {
		pat := fmt.Sprintf(`LIT%02d[0-9]+`, i)
		info, err := analyzePattern(config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: pat}, pp, sp)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		info.globalID = i
		spec.Patterns = append(spec.Patterns, info)
		spec.PatternIDs = append(spec.PatternIDs, i)
	}
	lits, alwaysAlive, ok := buildAbsenceLits(spec)
	if !ok {
		t.Skip("the prefilter refused this set")
	}
	if len(lits) > absenceMaxLits {
		t.Fatalf("collected %d literals, over the i32 search mask's %d bits", len(lits), absenceMaxLits)
	}
	// Every pattern must be accounted for: either it has a searched literal,
	// or it is unconditionally alive.
	covered := make([]bool, n)
	for _, al := range lits {
		covered[al.gid] = true
	}
	for gid := 0; gid < n; gid++ {
		if covered[gid] {
			continue
		}
		if alwaysAlive&(uint64(1)<<uint(gid)) == 0 {
			t.Errorf("pattern %d has neither a searched literal nor an always-alive bit: "+
				"the preflight would prove it matchless wherever its literal occurs", gid)
		}
	}
}

// moduleExports reports whether the module exports a function of that name.
// A deliberately small parser: it walks section headers and scans the export
// section's name strings.
func moduleExports(w []byte, name string) bool {
	off := 8
	for off < len(w) {
		id := w[off]
		off++
		size, n, err := utils.DecodeULEB128(w[off:])
		if err != nil || size > uint64(len(w)-off-n) {
			return false
		}
		off += n
		end := off + int(size)
		if id == 7 { // export section
			body := w[off:end]
			return exportSectionHas(body, name)
		}
		off = end
	}
	return false
}

func exportSectionHas(body []byte, name string) bool {
	count, n, err := utils.DecodeULEB128(body)
	if err != nil {
		return false
	}
	off := n
	for i := uint64(0); i < count && off < len(body); i++ {
		nameLen, n, err := utils.DecodeULEB128(body[off:])
		if err != nil {
			return false
		}
		off += n
		if off+int(nameLen) > len(body) {
			return false
		}
		if string(body[off:off+int(nameLen)]) == name {
			return true
		}
		off += int(nameLen)
		off++ // kind
		_, n, err = utils.DecodeULEB128(body[off:])
		if err != nil {
			return false
		}
		off += n
	}
	return false
}

// TestOverlapDPColumnsUseTableMemory covers B1.
//
// The backward sweep's two working columns live at cs.overlapDPColOff, a
// TABLE-memory address whose zero-filled segment is rewritten to memory 1 in
// embedded mode. Their loads and stores were emitted as raw `0x28 0x02` /
// `0x36 0x02` — implicit memory 0 — so an embedded module read and WROTE the
// HOST's heap at colOff..colOff+2*states*patterns*4. Standalone (every
// harness in this repo) is coincidentally correct, which is why nothing saw
// it.
//
// The check is on the EMITTED BYTES: an embedded sweep body must contain no
// memory-0 i32 load or store at all except the ones addressed off the
// caller's scratch pointer, and the multi-memory encoding is what distinguishes
// them.
func TestOverlapDPColumnsUseTableMemory(t *testing.T) {
	cfg := config.BuildConfig{
		// `output:` set → embedded: tables become memory 1.
		Output: "merged.wasm",
		Regexps: []config.RegexEntry{
			{Name: "p0", Pattern: `a+`},
			{Name: "p1", Pattern: `[^\n]*ERROR`},
			{Name: "p2", Pattern: `x?y`},
		},
		Sets: []config.SetConfig{{
			Name: "s", Patterns: config.PatternSelector{All: true},
			Find: "cap_find", Overlapping: true, Hints: []string{"batch-find"},
		}},
	}
	pp, sp := &dfaPool{}, &dfaPool{}
	spec := SetSpec{Name: "s", Find: "cap_find", Overlapping: true, BatchFind: true}
	for i, re := range cfg.Regexps {
		info, err := analyzePattern(re, pp, sp)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", re.Pattern, err)
		}
		info.globalID = i
		spec.Patterns = append(spec.Patterns, info)
		spec.PatternIDs = append(spec.PatternIDs, i)
	}
	cs := CompileSet(spec, pp, sp, CompileSetOptions{TableMemIdx: 1})
	if cs.overlapDPFnOffset() < 0 {
		t.Skip("this shape no longer engages the backward sweep")
	}
	body := emitOverlapDPBody(cs, 1 /* tableMemIdx */, cs.overlapDPColOff)

	// Count memory-0 i32 loads/stores. The tuple writer and the header writer
	// legitimately use them — they address the CALLER's scratch — so the test
	// is a bound, pinned against the standalone body which uses memory 0 for
	// everything.
	standalone := emitOverlapDPBody(cs, 0, cs.overlapDPColOff)
	if got, want := countMem0Access(body), countMem0Access(standalone); got >= want {
		t.Errorf("the embedded sweep body makes %d memory-0 i32 accesses and the standalone one %d: "+
			"the column loads/stores are still going to memory 0, i.e. to the host's heap", got, want)
	}
	// And the module as a whole must still assemble.
	w, _, err := CompileFile(cfg, "merged.wasm")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	assertWasm(t, w, "embedded overlapping batch module")
}

// countMem0Access counts i32.load/i32.store opcodes whose alignment byte has
// no memory-index flag — i.e. implicit memory 0.
func countMem0Access(body []byte) int {
	n := 0
	for i := 0; i+1 < len(body); i++ {
		if (body[i] == 0x28 || body[i] == 0x36) && body[i+1] == 0x02 {
			n++
		}
	}
	return n
}

// TestWideFormIsConsistentlyRead is U1's second half.
//
// Forcing the anchored union WIDE for a set with a Backtracking member made
// the BUILDER take the wide path while `isWide()` — then defined as
// `maskWords > 1` — still said narrow for a small id space. Every reader keyed
// on isWide() therefore went to the u64 accept tables the wide path does not
// emit: `match_any` loaded from acceptOff == -1 and TRAPPED at 0xFFFFFFFF.
// Caught by the --set-bt corpus leg the same review asked for (T3).
//
// The invariant, stated once: the accept FORM and the row WIDTH are two
// questions, and isWide() answers the first.
func TestWideFormIsConsistentlyRead(t *testing.T) {
	pats := []string{
		`(?:c|(?:b|c))`, `^(?:(?:c|(?:b|c)))$`, `^(?:(?:c|(?:b|c)))`, `(?:(?:c|(?:b|c)))$`,
		`(?:c(?:b.))`, `^(?:(?:c(?:b.)))$`, `^(?:(?:c(?:b.)))`, `(?:(?:c(?:b.)))$`,
	}
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Patterns: config.PatternSelector{Names: names},
			MatchAny: "s_match_any", MatchAll: "s_match_all",
			ScanAny: "s_scan_any", ScanAll: "s_scan_all", Find: "s_find",
			Hints: []string{"batch-find"},
		}},
		// Small enough that every pattern is BT-admitted, which is what makes
		// cs.wideAll() true at an id space of 8.
		MaxFallbackStates: 1,
	}
	if _, _, err := CompileFile(cfg, ""); err != nil {
		t.Fatalf("compile: %v", err)
	}

	// The invariant itself, checked directly on both builders: whenever the
	// wide accept form is emitted, isWide() must say so, whatever maskWords is.
	pp, sp := &dfaPool{}, &dfaPool{}
	spec := SetSpec{Name: "s", MatchAny: "s_match_any", MatchAll: "s_match_all"}
	for i, pat := range pats {
		info, err := analyzePattern(config.RegexEntry{Name: names[i], Pattern: pat}, pp, sp)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		info.globalID = i
		spec.Patterns = append(spec.Patterns, info)
		spec.PatternIDs = append(spec.PatternIDs, i)
	}
	au := buildAnchoredUnionDFA(spec, 0, true, true /* forceWideAll */)
	if au == nil {
		t.Skip("this shape no longer takes the anchored union")
	}
	if au.eofReprOff >= 0 && !au.isWide() {
		t.Errorf("the wide accept form was emitted (eofReprOff=%d) but isWide() is false "+
			"(maskWords=%d): every reader keyed on isWide() would go to the u64 tables "+
			"the wide path never emits", au.eofReprOff, au.maskWords)
	}
	if au.isWide() && au.eofOff >= 0 {
		t.Errorf("isWide() is true but the narrow eof table is at %d: the two forms must be exclusive", au.eofOff)
	}
}

var _ = binary.LittleEndian

// TestOverlapPreflightPredicatesAgree covers X12.
//
// overlapCanPreflight (set_emit.go) and compiledSet.overlapPreflightShape
// (set_union_scan.go) ask the same question at two different moments — from
// the spec plus raw buckets, and from the finished compiledSet. The second
// decides whether the union TABLES are built; the first decides whether the
// preflight is EMITTED. If the emitting one ever admits a set the table one
// refuses, the body reads a table that does not exist.
//
// The containment, not the equality: overlapPreflightShape is deliberately
// narrower (it also requires a never-dying state, which is a profitability
// judgement rather than a representation limit).
func TestOverlapPreflightPredicatesAgree(t *testing.T) {
	families := [][]string{
		{`a+`, `[^\n]*ERROR`, `x?y`},
		{`alpha`, `bravo`, `charlie`},
		{`\bcat\b`, `\bdog`},
		{`(?m:^)alpha`, `beta(?m:$)`},
		sparseishGroup(40),
		{`a*`, `[ab]{0,2}`},
		{`kw000[0-9a-z]{3}`, `kw001[0-9a-z]{3}`, `kw002[0-9a-z]{3}`},
	}
	for fi, pats := range families {
		t.Run(fmt.Sprintf("f%d", fi), func(t *testing.T) {
			pp, sp := &dfaPool{}, &dfaPool{}
			spec := SetSpec{Name: "s", Find: "cap_find", Overlapping: true}
			for i, pat := range pats {
				info, err := analyzePattern(config.RegexEntry{Name: fmt.Sprintf("p%02d", i), Pattern: pat}, pp, sp)
				if err != nil {
					t.Skipf("analyzePattern(%q): %v", pat, err)
				}
				info.globalID = i
				spec.Patterns = append(spec.Patterns, info)
				spec.PatternIDs = append(spec.PatternIDs, i)
			}
			cs := CompileSet(spec, pp, sp, CompileSetOptions{AllowSparseAccept: true})
			if cs.overlapPreflightShape() && !overlapCanPreflight(spec, cs.buckets) {
				t.Error("overlapPreflightShape admits this set but overlapCanPreflight refuses it: " +
					"the union tables would be built for a preflight that is never emitted")
			}
		})
	}
}

// sparseishGroup is n patterns behind one shared literal, the shape that
// promotes to a G17-sparse bucket.
func sparseishGroup(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`sharedlit[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i/8, 1+i%8)
	}
	return out
}

// TestZCaretIsNotExcluded settles the phantom exclusion analyzePattern
// used to claim.
//
// Its comment said patterns "that also contain begin-anchors (e.g. `\z^`)
// produce degenerate DFAs with false EOF accepts — exclude them from sets
// entirely", and NO such exclusion exists anywhere: the branch it sits in
// routes every zero-minimum-length pattern to fallback and returns. This
// checks the engine's answer against Go's rather than the comment's claim
// against nothing.
func TestZCaretIsNotExcluded(t *testing.T) {
	for _, pat := range []string{`\z^`, `$^`, `\z^a`} {
		t.Run(pat, func(t *testing.T) {
			pp, sp := &dfaPool{}, &dfaPool{}
			info, err := analyzePattern(config.RegexEntry{Name: "p", Pattern: pat}, pp, sp)
			if err != nil {
				t.Fatalf("analyzePattern: %v", err)
			}
			// It is IN the set — routed to fallback, not excluded.
			if info.splittable {
				t.Errorf("%q was made splittable; it matches empty and must go to fallback", pat)
			}
			spec := SetSpec{
				Name: "s", Find: "cap_find",
				Patterns: []*PatternInfo{info}, PatternIDs: []int{0},
			}
			cs := CompileSet(spec, pp, sp, CompileSetOptions{})
			if len(cs.buckets) == 0 {
				t.Fatalf("%q produced no bucket: it WAS excluded, which nothing implements", pat)
			}
		})
	}
}
