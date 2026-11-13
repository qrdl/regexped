package fuzz

// FuzzSetRoutes: one generated set and one long input driven through every
// route a set's `find` can answer by, each required to give Go's tuples. An
// overlapping drive can be served by the per-position walk or by the answer
// cache's sweep — the natural trigger, a forced first-call sweep, the
// checkpointed sweep at strides 1, 3 and 7, a region too small to use — and by
// the batch entry at capacities 1, 2 and P with and without a cache; a gated
// drive by `find` and by the batch entry. The routes are separate code over
// one contract, and they have disagreed: the double SIMD skip lived in the
// walk's bucket bodies only, so on 23+ bytes the walk answered wrong where the
// forced sweep was right, and the drive's answer depended on whether the
// trigger fired. An answer that matches Go says nothing about which route gave
// it, so every route runs.
//
// The set's members come from FuzzLongInput's grammar (longGen), 2-6 of them,
// over an input of witnesses of random members mixed with runs; the fuzz
// engine supplies the seed and the mode.
//
//	make -C tools/fuzz fuzz-set-routes                 # 5 minutes
//	make -C tools/fuzz fuzz-set-routes FUZZTIME=8h

import (
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qrdl/regexped/config"
)

func FuzzSetRoutes(f *testing.F) {
	for _, seed := range []int64{2, 12, 22, 34, 45, 56} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, seed int64, uni bool) {
		defer func(v bool) { *unicodeMode = v }(*unicodeMode)
		*unicodeMode = uni
		// Each module is built once and serves every route (keepModules).
		defer func(v bool) { keepModules = v }(keepModules)
		keepModules = true
		// Byte-mode inputs are budgeted too: one ran to 16 s, past the
		// worker's 10 s, and was reported as a hang (budgetByteMode).
		defer func(v bool) { budgetByteMode = v }(budgetByteMode)
		budgetByteMode = true
		beginFuzzInput()
		g := longGen{r: rand.New(rand.NewSource(seed)), uni: uni}
		pats, parsed := routeMembers(g)
		if len(pats) < 2 {
			t.Skip()
		}
		input := routeInput(g, parsed)
		batch, ok := routesCompile(pats)
		if !ok {
			t.Skip()
		}
		checkSetRoutes(t, pats, input, batch)
	})
}

// routeMembers draws 2-6 distinct members that Go accepts, each within the
// instruction budget a set compile stays inside the fuzz deadline with.
func routeMembers(g longGen) ([]string, []*syntax.Regexp) {
	n := 2 + g.r.Intn(5)
	seen := map[string]bool{}
	var pats []string
	var parsed []*syntax.Regexp
	for tries := 0; len(pats) < n && tries < 4*n; tries++ {
		p := g.alt(1)
		if len(p) > 40 || seen[p] {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			continue
		}
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			continue
		}
		if prog, err := syntax.Compile(re.Simplify()); err != nil || len(prog.Inst) > maxSetCapsNFAInsts() {
			continue
		}
		seen[p] = true
		pats = append(pats, p)
		parsed = append(parsed, re)
	}
	return pats, parsed
}

// routeInput is 17-250 bytes of witnesses of random members mixed with runs
// over their joint alphabet.
func routeInput(g longGen, parsed []*syntax.Regexp) string {
	alpha := g.alphabet(&syntax.Regexp{Op: syntax.OpConcat, Sub: parsed})
	n := 17 + g.r.Intn(184)
	var b strings.Builder
	for b.Len() < n {
		if g.r.Intn(2) == 0 {
			g.witness(parsed[g.r.Intn(len(parsed))], &b, alpha)
			continue
		}
		c := alpha[g.r.Intn(len(alpha))]
		for k := 1 + g.r.Intn(20); k > 0; k-- {
			b.WriteRune(c)
		}
	}
	s := b.String()
	for len(s) > 250 {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// routesBigModule is the overlapping module size past which the batch-entry
// routes and two of the three strides are left out: a set of Unicode members
// compiles to ~3 MB, each such module costs about a second to compile and
// another to build, a forced sweep over it about a second more, and all of
// them ran one fuzz input to 9.7 s of the worker's 10.
const routesBigModule = 1 << 20

// routesCompile reports whether every set the routes drive compiles — through
// the drivers' own cached builders, so each compiles once: a set over a
// documented construction ceiling, or a compile past the fuzz harness's
// deadline, is no defect, and the drivers treat a compile error as a failure.
// It learns the overlapping cache's two shapes here too (cachedOverlapShape,
// overlapShapeFor), so a shape too slow for the input's budget skips the
// input before any drive rather than in the middle of one. batch is false
// when the batch entry's routes are left out (routesBigModule).
func routesCompile(pats []string) (batch, ok bool) {
	w, err := compileCacheDriveSet(pats, false, 0)
	if err != nil {
		return false, false
	}
	if _, err := compileGatedSet(pats); err != nil {
		return false, false
	}
	if _, err := cachedOverlapShape(pats); errors.Is(err, errCompileTooSlow) {
		return false, false
	}
	if _, err := overlapShapeFor(pats); errors.Is(err, errCompileTooSlow) {
		return false, false
	}
	if len(w) > routesBigModule {
		return false, true
	}
	for _, overlapping := range []bool{true, false} {
		if _, err := compileBatchSet(pats, overlapping); err != nil {
			return false, false
		}
	}
	return true, true
}

// checkSetRoutes drives pats over input through every route and compares each
// with Go; batch includes the batch entry's routes and every stride (false for
// a big module, routesBigModule).
func checkSetRoutes(t *testing.T, pats []string, input string, batch bool) {
	t.Helper()
	var want []setMatch
	for k, p := range pats {
		for _, m := range allStartPositionMatches(regexp.MustCompile(p), input) {
			want = append(want, setMatch{PatternID: k, Start: m[0], End: m[1]})
		}
	}
	sortMatches(want)
	compare := func(route string, got []setMatch) {
		sortMatches(got)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("overlapping find, route %s, unicode=%v\n  set   %q\n  input %q\n  got   %v\n  want  %v",
				route, *unicodeMode, pats, input, got, want)
		}
	}
	tuples := func(v [][3]int) []setMatch {
		out := make([]setMatch, len(v))
		for i, x := range v {
			out[i] = setMatch{PatternID: x[0], Start: x[1], End: x[2]}
		}
		return out
	}
	p := int32(len(pats))
	full := cacheFindScratchLen(input, pats)
	compare("walk / default state",
		tuples(driveCacheFind(t, pats, input, 0, p, false, full, engageAny)))
	compare("cache, natural trigger",
		tuples(driveCacheFind(t, pats, input, 0, p, true, full, engageAny)))
	compare("cache, forced first-call sweep",
		tuples(driveCacheFindOpt(t, pats, input, 0, p, true, full, engageAny, &cacheDriveOpt{preArmWork: true})))
	strides := []int32{1, 3, 7}
	if !batch { // a big module: a forced sweep over it costs ~1 s, one stride will do
		strides = []int32{3}
	}
	for _, k := range strides {
		compare(fmt.Sprintf("cache, forced sweep at stride %d", k), tuples(driveCacheFindOpt(t, pats, input, 0, p, true,
			overlapCacheForK(input, pats, k), engageAny, &cacheDriveOpt{stride: &k, preArmWork: true})))
	}
	compare("cache, region too small",
		tuples(driveCacheFind(t, pats, input, 0, p, true, int32(config.SetOverlapCheckpointHeaderBytes), engageAny)))
	// The gated drive through `find`.
	checkGated(t, pats, input)
	if !batch {
		return
	}
	for _, outCap := range []int32{1, 2, p} {
		for _, withCache := range []bool{false, true} {
			compare(fmt.Sprintf("batch, capacity %d, cache %v", outCap, withCache),
				runBatchFind(t, pats, input, outCap, true, withCache))
		}
	}
	// The gated batch entry at five capacities.
	checkBatch(t, pats, input)
}

// TestSetRoutesShapes runs the routes over the set shapes they disagreed on
// before, so a route that drifts fails here without a fuzz run: two looping
// states that can end a match (the double skip, on 23+ bytes), a \B member
// beside a literal, an overlapping set whose cache serves a member the walk
// splits.
func TestSetRoutesShapes(t *testing.T) {
	for _, c := range []struct {
		pats  []string
		input string
	}{
		{[]string{`key=[^ ]+(?: [^\n]*)?`, `zzzzq`}, "key=a  \n" + strings.Repeat("z", 30)},
		{[]string{`[^ ]+(?: [^\n]*)?`, `a[^b]*(?:b[^c]*)?`}, "a  \n" + strings.Repeat("z", 40) + " ab" + strings.Repeat("c", 20)},
		{[]string{`key=[a-z]+\B`, `zz`}, "key=" + strings.Repeat("a", 18) + "  \n" + strings.Repeat("z", 20)},
		{[]string{`\bselect\b`, `\Bing\b`, `ab`}, "select singing abab select_ ring"},
	} {
		t.Run(strings.Join(c.pats, "+"), func(t *testing.T) {
			checkSetRoutes(t, c.pats, c.input, true)
		})
	}
}
