package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The gated (default) `find` body — plans/SETS.md §3.14-3.16, stage S5.
//
// The oracle is deliberately NOT a Go reimplementation of §3.16's biased gate
// encoding. §9.6.1 explains why at length: a reference derived from the same
// spec paragraph as the emitter proves the two agree, not that either is
// right, and this project has already been bitten by exactly that (FABLE B42,
// where re2test's comparison AND its oracle narrowed the input the same way).
//
// Instead Go computes the WHOLE answer: the complete gated output of a set is
// the union, over every pattern k, of `FindAllIndex(pk, input)` tagged with k.
// That holds because pattern k's gate depends only on k's own reported
// matches, the scan visits every position, and the caller advances by exactly
// one position — so each pattern independently performs "first eligible match,
// gate, repeat", which is the definition of FindAllIndex.

// compileGatedSet compiles pats into a standalone module whose `find` is the
// default gated body (no `overlapping:` key).
func compileGatedSet(pats []string) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:     "s",
		Find:     "gated_find",
		Patterns: config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	return w, err
}

// gatedRun drives the gated find to exhaustion with a zeroed gate array, the
// way a generated iterator does, and returns every reported match plus the
// per-call batches for the structural invariants of §9.6.1.
type gatedRun struct {
	matches []setMatch
	batches [][]setMatch
}

func runGatedFind(t *testing.T, pats []string, input string) gatedRun {
	t.Helper()
	w, err := compileGatedSet(pats)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, err := instantiate(w)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "gated_find")
	if fn == nil {
		t.Fatal("module missing gated_find export")
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr := inBase + span
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	if len(input) > 0 {
		copy(buf[inBase:], input)
	}
	// The stub's job: allocate the gate array and zero it. Nothing else.
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}

	var run gatedRun
	from := int32(0)
	outCap := int32(len(pats))
	prevStart := -1
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), from, gatePtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("gated_find: %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		if n > int(outCap) {
			t.Fatalf("gated_find reported %d tuples at one position, buffer holds %d", n, outCap)
		}
		buf := mem.UnsafeData(store)
		var batch []setMatch
		start := -1
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
			s := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
			e := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
			if i == 0 {
				start = s
			} else if s != start {
				t.Fatalf("tuples in one call disagree on start: %d vs %d", start, s)
			}
			batch = append(batch, setMatch{PatternID: id, Start: s, End: e})
		}
		if start <= prevStart {
			t.Fatalf("start did not advance: %d after %d", start, prevStart)
		}
		prevStart = start
		run.batches = append(run.batches, batch)
		run.matches = append(run.matches, batch...)
		from = int32(start) + 1
	}
	return run
}

// gatedOracle is §9.6.1's union of Go FindAllIndex, tagged with the pattern id.
func gatedOracle(pats []string, input string) []setMatch {
	var out []setMatch
	for k, p := range pats {
		for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
			out = append(out, setMatch{PatternID: k, Start: x[0], End: x[1]})
		}
	}
	return out
}

func sortMatches(v []setMatch) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].PatternID != v[j].PatternID {
			return v[i].PatternID < v[j].PatternID
		}
		if v[i].Start != v[j].Start {
			return v[i].Start < v[j].Start
		}
		return v[i].End < v[j].End
	})
}

func checkGated(t *testing.T, pats []string, input string) {
	t.Helper()
	run := runGatedFind(t, pats, input)
	want := gatedOracle(pats, input)
	got := append([]setMatch(nil), run.matches...)
	sortMatches(want)
	sortMatches(got)
	if len(want) != len(got) {
		t.Fatalf("%v on %q: expected %d matches %v, got %d %v", pats, input, len(want), want, len(got), got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%v on %q: match %d expected %+v, got %+v", pats, input, i, want[i], got[i])
		}
	}

	// Encoding-independent invariants (§9.6.1). These hold whatever the gate
	// formula says, and a wrong bias direction violates them immediately.
	byID := map[int][]setMatch{}
	for _, m := range run.matches {
		byID[m.PatternID] = append(byID[m.PatternID], m)
	}
	for id, ms := range byID {
		sortMatches(ms)
		for i := 1; i < len(ms); i++ {
			if ms[i].Start < ms[i-1].End {
				t.Fatalf("%v on %q: pattern %d reported overlapping matches %+v and %+v",
					pats, input, id, ms[i-1], ms[i])
			}
			if ms[i].Start <= ms[i-1].Start {
				t.Fatalf("%v on %q: pattern %d starts not strictly increasing: %+v then %+v",
					pats, input, id, ms[i-1], ms[i])
			}
		}
	}

	// Re-zeroing the gates and rescanning reproduces the identical sequence.
	again := runGatedFind(t, pats, input)
	if len(again.matches) != len(run.matches) {
		t.Fatalf("%v on %q: rescan produced %d matches, first scan %d", pats, input, len(again.matches), len(run.matches))
	}
	for i := range run.matches {
		if again.matches[i] != run.matches[i] {
			t.Fatalf("%v on %q: rescan differs at %d: %+v vs %+v", pats, input, i, again.matches[i], run.matches[i])
		}
	}
}

// TestGatedFindOneSet runs the corpus of every pattern as a ONE-pattern set,
// where the union oracle degenerates to plain FindAllIndex — the cheapest and
// sharpest check of the gate encoding across empty-match shapes and extents.
func TestGatedFindOneSet(t *testing.T) {
	pats := []string{
		`a*`, `a+`, `a`, `ab`, `[a-z]+X`, `x?`, `(?:)`, `a{2,5}`, `\d+`,
		`foo|foobar`, `(?:ab)+`, `\bcat\b`, `(?m:^)a`, `a(?m:$)`, `\Aab`, `ab\z`,
	}
	inputs := []string{"", "a", "aa", "aaa", "bab", "abcX", "cat cat", "a\nba\n", "abab", "foobar"}
	for _, p := range pats {
		for _, in := range inputs {
			t.Run(p+"|"+in, func(t *testing.T) { checkGated(t, []string{p}, in) })
		}
	}
}

// TestGatedFindInterleaving covers the multi-pattern case the union oracle is
// really for: two patterns whose gates advance independently.
func TestGatedFindInterleaving(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`[a-z]+X`, `b`}, "abXbX"},
		{[]string{`a*`, `b`}, "bab"},
		{[]string{`foo`, `foobar`}, "foobarfoo"},
		{[]string{`a+`, `aa`}, "aaaa"},
		{[]string{`\bcat\b`, `cat`}, "cat concat cat"},
		{[]string{`(?m:^)x`, `x`}, "x\nxx"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) { checkGated(t, c.pats, c.input) })
	}
}

// TestGatedSubsetOfUngated pins the §9.6.1 invariant that the gated output is
// a subset of the ungated one for the same set and input.
func TestGatedSubsetOfUngated(t *testing.T) {
	pats := []string{`[a-z]+X`, `b`}
	input := "abXbX"
	gated := runGatedFind(t, pats, input).matches

	w, err := compileSet(pats)
	if err != nil {
		t.Fatal(err)
	}
	ungated, hang, err := runWasmSetFind(w, input, len(pats))
	if err != nil || hang {
		t.Fatalf("ungated run: err=%v hang=%v", err, hang)
	}
	inUngated := map[setMatch]bool{}
	for _, m := range ungated {
		inUngated[m] = true
	}
	for _, m := range gated {
		if !inUngated[m] {
			t.Fatalf("gated reported %+v, which the ungated body does not produce", m)
		}
	}
}

// TestGatedOverflowStoresNoState pins §3.11 / D2: an overflowing call must
// leave the gate array byte-for-byte as it found it, so a grown retry sees the
// identical world. Probing with out_cap 0 then 1 then the full size must give
// the same answer as calling at full size first.
func TestGatedOverflowStoresNoState(t *testing.T) {
	pats := []string{"ab", "a", "abc"}
	input := "abcabc"

	full := runGatedFind(t, pats, input).matches

	// Same scan, but each position is first probed with undersized buffers.
	w, err := compileGatedSet(pats)
	if err != nil {
		t.Fatal(err)
	}
	store, inst, mem, err := instantiate(w)
	if err != nil {
		t.Fatal(err)
	}
	fn := inst.GetFunc(store, "gated_find")
	const pageSize = 65536
	dataTop, _ := utils.ParseDataSectionBytes(w)
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		mem.Grow(store, needed-cur) //nolint:errcheck
	}
	copy(mem.UnsafeData(store)[inBase:], input)

	var got []setMatch
	from := int32(0)
	for {
		// Undersized probes first — these must not touch the gate array.
		for _, cap := range []int32{0, 1} {
			if _, err := fn.Call(store, inBase, int32(len(input)), from, gatePtr, outPtr, cap); err != nil {
				t.Fatal(err)
			}
		}
		res, err := fn.Call(store, inBase, int32(len(input)), from, gatePtr, outPtr, int32(len(pats)))
		if err != nil {
			t.Fatal(err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf := mem.UnsafeData(store)
		start := 0
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			m := setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			}
			start = m.Start
			got = append(got, m)
		}
		from = int32(start) + 1
	}
	sortMatches(full)
	sortMatches(got)
	if len(full) != len(got) {
		t.Fatalf("undersized probes changed the scan: %d matches vs %d", len(got), len(full))
	}
	for i := range full {
		if full[i] != got[i] {
			t.Fatalf("undersized probes changed match %d: %+v vs %+v", i, got[i], full[i])
		}
	}
}

// TestGatedLadder is plans/SETS.md §9.8's first measurement obligation: the
// `a+`-in-a-set n-ladder that made the case for gating in the first place.
// §3.14 measured the ungated scan at a textbook O(n^2) (x4 per doubling);
// gating must make it linear. Run with -v to see the table.
func TestGatedLadder(t *testing.T) {
	if testing.Short() {
		t.Skip("ladder measurement")
	}
	for _, n := range []int{500, 1000, 2000, 4000, 8000} {
		input := ""
		for i := 0; i < n; i++ {
			input += "a"
		}
		run := runGatedFind(t, []string{`a+`}, input)
		if len(run.matches) != 1 {
			t.Fatalf("n=%d: gated `a+` should report exactly one match, got %d", n, len(run.matches))
		}
		if run.matches[0] != (setMatch{PatternID: 0, Start: 0, End: n}) {
			t.Fatalf("n=%d: expected 0..%d, got %+v", n, n, run.matches[0])
		}
		t.Logf("n=%-5d calls=%d matches=%d", n, len(run.batches), len(run.matches))
	}
}

// TestGatedLadderFuel is the complexity assertion TestGatedLadder above is
// NOT — and the omission mattered.
//
// TestGatedLadder counts calls and matches, both of which are 1 at every n, so
// it read as "linear, as predicted" (§10.5) while the gated body was in fact
// still quadratic in WORK: §3.14's mask skip and jump were never emitted, so
// the terminating call ran each suffix DFA to its full extent at every gated
// position — 7.8M fuel at n=500 rising x4 per doubling to 1.98B at n=8000
// (plans/SETS.md §11 R5).
//
// The lesson generalised in R-TESTS(3): when the CLAIM is a complexity bound,
// the test has to measure work, not iterations. Fuel is deterministic, so this
// is an exact assertion rather than a timing heuristic.
func TestGatedLadderFuel(t *testing.T) {
	if testing.Short() {
		t.Skip("ladder measurement")
	}
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(cfg)

	w, err := compileGatedSet([]string{`a+`})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(engine)
		if err := store.SetFuel(1 << 42); err != nil {
			t.Fatalf("set fuel: %v", err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatalf("instantiate: %v", err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		const pageSize = 65536
		inBase := int32(1 << 20)
		gatePtr := inBase + int32((n/pageSize+2)*pageSize)
		outPtr := gatePtr + pageSize
		need := uint64((int64(outPtr) + 2*pageSize) / pageSize)
		if cur := mem.Size(store); need > cur {
			if _, err := mem.Grow(store, need-cur); err != nil {
				t.Fatalf("grow: %v", err)
			}
		}
		buf := mem.UnsafeData(store)
		for i := 0; i < n; i++ {
			buf[int(inBase)+i] = 'a'
		}
		for i := int32(0); i < 4; i++ {
			buf[gatePtr+i] = 0
		}
		fn := inst.GetFunc(store, "gated_find")
		var total uint64
		from := int32(0)
		for {
			before, _ := store.GetFuel()
			res, err := fn.Call(store, inBase, int32(n), from, gatePtr, outPtr, int32(1))
			if err != nil {
				t.Fatalf("gated_find: %v", err)
			}
			after, _ := store.GetFuel()
			total += before - after
			got := int(res.(int32))
			if got <= 0 {
				break
			}
			buf = mem.UnsafeData(store)
			from = le32(buf[int(outPtr)+4:]) + 1
		}
		return total
	}

	prev := uint64(0)
	prevN := 0
	for _, n := range []int{500, 1000, 2000, 4000, 8000} {
		f := fuelAt(n)
		if prev != 0 {
			// Linear would be x2 per doubling; quadratic x4. Assert well below
			// the quadratic line so this catches a regression without being
			// brittle about the exact constant.
			ratio := float64(f) / float64(prev)
			t.Logf("n=%-5d fuel=%-12d ratio vs n=%d: %.2fx", n, f, prevN, ratio)
			if ratio > 3.0 {
				t.Errorf("fuel grew %.2fx from n=%d to n=%d — that is the quadratic "+
					"behaviour §3.14's mask skip and jump exist to remove "+
					"(plans/SETS.md §11 R5)", ratio, prevN, n)
			}
		} else {
			t.Logf("n=%-5d fuel=%d", n, f)
		}
		prev, prevN = f, n
	}
}
