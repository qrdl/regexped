package fuzz

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// SETS_PLAN item 11 stage C: the batching overlapping `find` may sweep the
// input ONCE into a caller-owned tuple cache and then serve each call by
// copying from it — but only once the drive's own walk has cost more than the
// sweep would.
//
// This is the test stage B never had. Its sweep was checked only through the
// same WASM that implemented it, so a bug in the recurrence and a bug in the
// emission would have looked identical. Here the oracle is Go's own regexp,
// and the recurrence has ALREADY been checked separately in Go
// (compile/set_overlap_dp_test.go), so a failure here points at the EMISSION.
//
// Four things are asserted that a correctness-only test would miss:
//
//   - The same drive run with and WITHOUT scratch must agree. The no-scratch
//     path is the ordinary walk, so this pins the cache against the engine it
//     is meant to replace, not only against Go.
//   - The cache must survive being resumed at every capacity, including 1,
//     because the whole point is that the answer is Theta(n) tuples and no
//     single call can hold it.
//   - Cheap drives must NOT engage. Sweeping when the walk is already fast is
//     precisely the regression stage B was reverted for, so "it did not
//     sweep" is an assertion here, not an absence of one.
//   - Expensive drives MUST engage, and must agree across the seam where the
//     walk hands over to the cache mid-drive.

// overlapCacheSets are shapes whose drives are CHEAP: the walk finishes them
// for far less than a sweep would cost, so the engine must decline to sweep.
//
// `engage` is therefore false for all of them, and asserted. A set whose
// patterns carry mandatory literals is refused earlier still — a literal
// bucket's DFA matches only what follows its literal, and the sweep has no
// frontend to find that literal with.
var overlapCacheSets = []struct {
	pats []string
}{
	{[]string{`a+`, `[^\n]*ERROR`, `x?y`}}, // greedy-3, on inputs too short to trigger
	{[]string{`a+`}},
	{[]string{`[^\n]*ERROR`}},
	{[]string{`a+`, `b+`}},
	{[]string{`abc`, `b`, `c`}},
	{[]string{`a*`}},
	{[]string{`[0-9]+`, `[a-z]+`}},
	{[]string{`a`, `aa`, `aaa`}},

	// Shapes the CORPUS found while the cache was still swept
	// unconditionally, kept so they cannot regress:
	//   - a pattern that matches empty AND longer beside one that matches only
	//     empty (this refuted the immediateAccept branch),
	//   - begin- and end-anchored patterns, whose start state differs at
	//     position 0 and whose empty-input case the sweep loop cannot reach.
	{[]string{`a*`, ``}},
	{[]string{`a*`, `a+`, ``, `b?`, `(?:)`, `a|`, `[ab]{0,2}`}},
	{[]string{
		`^(?:(?:.(?:c?)))`, `^(?:^(?:(?:.(?:c?)))$)`, `^(?:^(?:(?:.(?:c?))))`,
		`^(?:(?:(?:.(?:c?)))$)`, `^(?:(?:.|(?:c?)))`, `^(?:^(?:(?:.|(?:c?)))$)`,
		`^(?:^(?:(?:.|(?:c?))))`, `^(?:(?:(?:.|(?:c?)))$)`,
	}},
}

var overlapCacheInputs = []string{
	"",
	"a",
	"aaa",
	"abc",
	"aaa ERROR bbb",
	"ERROR",
	"xy xy xy",
	"123abc456",
	"bbbb",
	"the quick brown fox",
}

func TestOverlapCacheMatchesGo(t *testing.T) {
	for si, tc := range overlapCacheSets {
		pats := tc.pats
		for _, input := range overlapCacheInputs {
			for _, outCap := range []int32{1, 3, 256} {
				name := fmt.Sprintf("set%d/%q/cap%d", si, input, outCap)
				t.Run(name, func(t *testing.T) {
					want := overlapCacheOracle(pats, input)
					// engage=cheap: these drives must DECLINE to sweep.
					withCache := driveOverlapCacheEngage(t, pats, input, 0, outCap, true, engageNever)
					withoutCache := driveOverlapCache(t, pats, input, outCap, false)

					if got := canonCache(withCache); fmt.Sprint(got) != fmt.Sprint(want) {
						t.Fatalf("cache path over %q:\n  got  %v\n  want %v", input, got, want)
					}
					// The walk is the engine the cache replaces; if they ever
					// disagree, one of them is wrong regardless of what Go says.
					if a, b := canonCache(withCache), canonCache(withoutCache); fmt.Sprint(a) != fmt.Sprint(b) {
						t.Fatalf("cache and walk disagree over %q:\n  cache %v\n  walk  %v", input, a, b)
					}
				})
			}
		}
	}
}

// quadraticShapes are drives the walk CANNOT finish cheaply: a pattern whose
// automaton never dies, over an input long enough that walking from every
// start is quadratic. These are the drives stage C exists for, and the ones
// that must engage.
//
// 4000 bytes is chosen to be comfortably past the trigger (which is
// numStates x patterns per input byte) while keeping the test fast.
func quadraticShapes() []struct {
	name  string
	pats  []string
	input string
} {
	return []struct {
		name  string
		pats  []string
		input string
	}{
		{"all-a", []string{`a+`, `[^\n]*ERROR`, `x?y`}, strings.Repeat("a", 4000)},
		{"late-error", []string{`a+`, `[^\n]*ERROR`, `x?y`},
			strings.Repeat("the quick brown fox ", 200) + "ERROR"},

		// Long runs that END, so every answer comes from the recurrence's
		// MID-ACCEPT arm — the walk dies on the 'b' and the last accept seen
		// is the answer — rather than from the recursion reaching EOF.
		//
		// Added because mutation testing caught the gap: breaking that arm
		// changed nothing while the only engaging drives were ones whose
		// matches all ran to the end of the input.
		{"runs", []string{`a+`}, strings.Repeat(strings.Repeat("a", 500)+"b", 8)},
		{"runs-mixed", []string{`a+`, `b+`, `[ab]+`},
			strings.Repeat(strings.Repeat("a", 200)+strings.Repeat("b", 60), 12)},
	}
}

// TestOverlapCacheEngagesOnQuadraticDrives is the other half of the
// engagement rule. The drives here MUST sweep, and their answers must be
// identical to the walk's across the seam where the switch happens
// mid-drive — the walk delivers a prefix, the cache serves the rest, and the
// two halves have to meet in ascending order with nothing dropped or repeated.
func TestOverlapCacheEngagesOnQuadraticDrives(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, outCap := range []int32{1, 3, 256} {
			for _, offset := range []int32{0, 7} {
				name := fmt.Sprintf("%s/cap%d/off%d", shape.name, outCap, offset)
				t.Run(name, func(t *testing.T) {
					withCache := driveOverlapCacheEngage(t, shape.pats, shape.input, offset, outCap, true, engageAlways)
					withoutCache := driveOverlapCache2(t, shape.pats, shape.input, offset, outCap, false)
					if a, b := canonCache(withCache), canonCache(withoutCache); fmt.Sprint(a) != fmt.Sprint(b) {
						t.Fatalf("cache and walk disagree (%d vs %d tuples)", len(a), len(b))
					}
					if len(withCache) == 0 {
						t.Fatal("no matches at all: this shape cannot exercise the switch")
					}
					assertAscending(t, withCache)
				})
			}
		}
	}
}

// TestOverlapCacheFallsBackWhenScratchTooSmall pins the rule that makes the
// cache safe to offer at all: too little scratch is a SLOWER answer, never a
// wrong or partial one. Driven on a QUADRATIC shape, because a cheap one
// would never ask for the sweep and the fallback would go untested.
func TestOverlapCacheFallsBackWhenScratchTooSmall(t *testing.T) {
	shape := quadraticShapes()[0]
	want := canonCache(driveOverlapCache2(t, shape.pats, shape.input, 0, 8, false))
	// 32 bytes holds the header and at most one tuple: the sweep must refuse
	// and the drive must still be complete and correct.
	got := canonCache(driveOverlapCacheScratch(t, shape.pats, shape.input, 0, 8, true, 32, engageNever))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("undersized scratch changed the answer: %d tuples vs %d", len(got), len(want))
	}
}

// assertAscending checks the ACROSS-position contract: starts never go
// backwards over a drive. This is what a mid-drive switch could break, and no
// per-call check would catch it.
func assertAscending(t *testing.T, tuples [][3]int) {
	t.Helper()
	prev := -1
	for _, tuple := range tuples {
		if tuple[1] < prev {
			t.Fatalf("start went backwards: %d after %d", tuple[1], prev)
		}
		prev = tuple[1]
	}
}

// engageWant says what the drive must do about the sweep.
type engageWant int

const (
	engageAny engageWant = iota
	// engageNever: the walk is cheap here, so sweeping would be the stage-B
	// regression. Asserted, not merely allowed.
	engageNever
	// engageAlways: the walk is quadratic here, so the sweep must take over.
	engageAlways
)

// canonCache sorts by (start, id, end): docs/sets.md says the order of matches
// WITHIN one position is unspecified, so asserting it would test an
// implementation detail. The ACROSS-position order is a real contract and is
// checked by the drive loop itself.
func canonCache(in [][3]int) [][3]int {
	out := append([][3]int(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][2] < out[j][2]
	})
	return out
}

// overlapCacheOracle is `overlapping: true`'s contract stated directly: at
// every start position, every pattern that matches there, with its
// leftmost-first extent.
//
// The probe is §9.6's WHOLE-INPUT one, `\A(?s:.{start})(?:pat)`, not the
// pattern against a slice. `^` is \A and can only match at absolute position
// 0, so a slice would let an anchored pattern match at every start and the
// oracle would be wrong in exactly the cases the anchored sets above exist to
// check.
func overlapCacheOracle(pats []string, input string) [][3]int {
	var out [][3]int
	for start := 0; start <= len(input); start++ {
		for k, p := range pats {
			re := regexp.MustCompile(fmt.Sprintf(`\A(?s:.{%d})(?:%s)`, start, p))
			if m := re.FindStringIndex(input); m != nil {
				out = append(out, [3]int{k, start, m[1]})
			}
		}
	}
	return canonCache(out)
}

func driveOverlapCache(t *testing.T, pats []string, input string, outCap int32, useCache bool) [][3]int {
	t.Helper()
	return driveOverlapCache2(t, pats, input, 0, outCap, useCache)
}

func driveOverlapCache2(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool) [][3]int {
	t.Helper()
	return driveOverlapCacheEngage(t, pats, input, offset, outCap, useCache, engageAny)
}

func driveOverlapCacheEngage(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool, want engageWant) [][3]int {
	t.Helper()
	// Generous scratch: one tuple per pattern per start, which is the worst
	// case the sweep can produce.
	scratchLen := int32(config.SetOverlapCacheBytes(len(input), len(pats)))
	return driveOverlapCacheScratch(t, pats, input, offset, outCap, useCache, scratchLen, want)
}

func driveOverlapCacheScratch(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool, scratchLen int32, want engageWant) [][3]int {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name:        "s",
			Find:        "set_find",
			Patterns:    config.PatternSelector{All: true},
			Overlapping: true,
			Hints:       []string{"batch-find"},
		}},
	}
	w, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "set_find_batch")
	if fn == nil {
		t.Fatal("module missing set_find_batch export")
	}

	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	scratchPtr := outPtr + pageSize
	needed := uint64((int64(scratchPtr) + int64(scratchLen) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	copy(buf[inBase:], input)
	// The caller zeroes BOTH regions to start a drive — that is the whole
	// contract, for the gates and for the cache header alike.
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	for i := int32(0); i < scratchLen; i++ {
		buf[scratchPtr+i] = 0
	}

	passScratch, passLen := scratchPtr, scratchLen
	if !useCache {
		passScratch, passLen = 0, 0
	}

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out [][3]int
	cursor := int64(offset) << 32
	for calls := 0; ; calls++ {
		if calls > 4*(len(input)+2)*len(pats)+16 {
			t.Fatalf("drive did not terminate over %q (cap %d)", input, outCap)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, gatePtr, outPtr, outCap, passScratch, passLen)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		ret := res.(int64)
		n := int32(ret & countMask)
		buf = mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, [3]int{
				int(int32(readU32(buf, base))),
				int(int32(readU32(buf, base+4))),
				int(int32(readU32(buf, base+8))),
			})
		}
		if uint32(ret>>32) == 0xFFFFFFFF {
			// The guard against a VACUOUS pass in BOTH directions. A drive
			// that quietly fell back to the walk still matches Go — the walk
			// is correct too — so "the answer was right" is no evidence about
			// which engine produced it. `ready` says which did: 1 swept, 0
			// never asked, -1 asked and was refused.
			ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset))
			switch want {
			case engageAlways:
				if ready != 1 {
					t.Fatalf("cache was never engaged (ready=%d): this drive tested the walk, not the sweep", ready)
				}
			case engageNever:
				if ready == 1 {
					t.Fatalf("cache engaged (ready=1) on a drive the walk handles cheaply: " +
						"sweeping here is the regression SETS_PLAN item 11 stage B was reverted for")
				}
			}
			return out
		}
		cursor = ret
	}
}

// overlapDPReadyOffset is the byte offset of the cache header's "ready" slot.
// Stated here rather than imported because compile/ keeps it unexported; the
// header width itself is config.SetOverlapCacheHeaderBytes, which the drive
// zeroes.
const overlapDPReadyOffset = 8
