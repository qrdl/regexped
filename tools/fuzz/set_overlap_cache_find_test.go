package fuzz

import (
	"fmt"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The answer cache is COMMON code, called from `find` as well as from the
// batching entry. These tests drive `find` — the ONE-position-per-call export —
// and none of the sets below declares `hints: [batch-find]`, which is the
// second half of the same decision: the sweep is emitted for any overlapping
// set whose shape qualifies, because requiring the hint would mean requiring a
// second entry point nobody asked for in order to make the first one linear.
//
// What is checked here and nowhere else:
//
//   - `find` engages the cache on a quadratic drive and declines on a cheap
//     one, with the SAME adaptive rule the batching entry uses. `ready` is read
//     out of the caller's scratch, so a drive that quietly fell back to the
//     walk cannot pass by being merely correct.
//   - The cache path obeys `find`'s protocol, not the batch entry's. That is
//     precisely where forwarding `find` into `find_batch` would have lost
//     matches: `find` returns the position's TOTAL and writes nothing when it
//     does not fit, so the documented "grow the buffer and retry from the same
//     position" has to keep working when the answer comes from the cache.
//   - The run served is ONE position: every tuple of a call shares a start.

// driveCacheFind runs a whole `find` drive from `offset`, returning every
// tuple. useCache decides whether the descriptor offers a cache at all, so the
// same drive can be compared against the walk it replaces.
//
// wantEngage is asserted at the END of the drive against the header's `ready`
// slot, for the reason the batching test states: a correct answer is no
// evidence about which engine produced it.
func driveCacheFind(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen int32, want engageWant,
) [][3]int {
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
			// No `hints: [batch-find]`: this set exports find and nothing else.
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
	if inst.GetFunc(store, "set_find_batch") != nil {
		t.Fatal("the set declared no batch hint but a batch entry was exported")
	}
	fn := inst.GetFunc(store, "set_find")
	if fn == nil {
		t.Fatal("module missing set_find export")
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
	descPtr := writeFindScratch(store, mem, gatePtr, int32(len(pats)), passScratch, passLen)

	var out [][3]int
	from := offset
	for calls := 0; ; calls++ {
		if calls > 4*(len(input)+2)*len(pats)+16 {
			t.Fatalf("drive did not terminate over %d bytes (cap %d)", len(input), outCap)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), from, descPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find: %v", err)
		}
		n := res.(int32)
		if n <= 0 {
			break
		}
		// `find`'s transactional rule: a position that does not fit writes
		// nothing and reports its total. Grow and retry from the SAME `from`.
		callCap := outCap
		if n > outCap {
			callCap = int32(len(pats))
			res, err = fn.Call(store, inBase, int32(len(input)), from, descPtr, outPtr, callCap)
			if err != nil {
				t.Fatalf("set_find retry: %v", err)
			}
			if got := res.(int32); got != n {
				t.Fatalf("retry at the same position reported %d tuples, the probe said %d", got, n)
			}
		}
		if n > callCap {
			t.Fatalf("a position reported %d tuples for a %d-pattern set", n, len(pats))
		}
		buf = mem.UnsafeData(store)
		start := int32(-1)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			st := int32(readU32(buf, base+4))
			if i == 0 {
				start = st
			} else if st != start {
				t.Fatalf("tuples of one call disagree on start: %d vs %d", start, st)
			}
			out = append(out, [3]int{
				int(int32(readU32(buf, base))),
				int(st),
				int(int32(readU32(buf, base+8))),
			})
		}
		from = start + 1
	}

	buf = mem.UnsafeData(store)
	ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset))
	switch want {
	case engageAlways:
		if ready != 1 {
			t.Fatalf("cache was never engaged (ready=%d): this drive tested the walk, not the sweep", ready)
		}
	case engageNever:
		if ready == 1 {
			t.Fatal("cache engaged on a drive the walk handles cheaply: " +
				"sweeping here is the regression an earlier attempt was reverted for")
		}
	}
	return out
}

func cacheFindScratchLen(input string, pats []string) int32 {
	return int32(config.SetOverlapCacheBytes(len(input), len(pats)))
}

// TestOverlapCacheFindEngagesOnQuadraticDrives is the reason the refactor
// happened: before it, `find` was handed a cache in its descriptor and ignored
// it, so an overlapping drive through the one-position-per-call export stayed
// quadratic no matter what the caller offered.
//
// Both halves are asserted — the cache's answer against the walk's, and that
// the switch actually happened — and the drive crosses the seam mid-flight, so
// the walk-delivered prefix and the cache-served tail have to meet in
// ascending order with nothing dropped or repeated.
func TestOverlapCacheFindEngagesOnQuadraticDrives(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, offset := range []int32{0, 7} {
			t.Run(fmt.Sprintf("%s/off%d", shape.name, offset), func(t *testing.T) {
				outCap := int32(len(shape.pats))
				scratch := cacheFindScratchLen(shape.input, shape.pats)
				withCache := driveCacheFind(t, shape.pats, shape.input, offset, outCap, true, scratch, engageAlways)
				withoutCache := driveCacheFind(t, shape.pats, shape.input, offset, outCap, false, scratch, engageAny)
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

// TestOverlapCacheFindMatchesGoAndDeclines is the cheap-drive half. The walk
// finishes these for far less than a sweep would cost, so `find` must decline
// to sweep and still agree with Go.
func TestOverlapCacheFindMatchesGoAndDeclines(t *testing.T) {
	for si, tc := range overlapCacheSets {
		pats := tc.pats
		for _, input := range overlapCacheInputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				scratch := cacheFindScratchLen(input, pats)
				got := canonCache(driveCacheFind(t, pats, input, 0, int32(len(pats)), true, scratch, engageNever))
				want := overlapCacheOracle(pats, input)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("cache path over %q:\n  got  %v\n  want %v", input, got, want)
				}
			})
		}
	}
}

// TestOverlapCacheFindHonoursTheTransactionalRule drives the cache path at
// capacity 1 on a set whose positions carry SEVERAL tuples.
//
// This is the failure that forwarding `find` into `find_batch` would have
// produced, and it is silent: the batch entry returns what it WROTE, so a
// caller applying `find`'s rule — a return greater than out_cap means grow and
// retry — would read the truncated count as complete and lose the rest of the
// position. Here the undersized call must report the total and write NOTHING,
// and the retry must produce the whole run.
func TestOverlapCacheFindHonoursTheTransactionalRule(t *testing.T) {
	pats := []string{`a+`, `a*`, `[ab]+`}
	input := strings.Repeat("ab", 2000)
	scratch := cacheFindScratchLen(input, pats)
	// The drive helper performs the grow-and-retry itself, so a body that
	// truncated instead of refusing shows up as a mismatch against the walk.
	got := canonCache(driveCacheFind(t, pats, input, 0, 1, true, scratch, engageAlways))
	want := canonCache(driveCacheFind(t, pats, input, 0, int32(len(pats)), false, scratch, engageAny))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("capacity-1 cache drive lost matches: %d tuples vs %d", len(got), len(want))
	}
}

// TestOverlapCacheFindFallsBackWhenScratchTooSmall pins the rule that makes
// the cache safe to offer at all: too little scratch is a SLOWER answer, never
// a wrong or partial one. Driven on a quadratic shape, because a cheap one
// would never ask for the sweep and the refusal would go untested.
func TestOverlapCacheFindFallsBackWhenScratchTooSmall(t *testing.T) {
	shape := quadraticShapes()[0]
	outCap := int32(len(shape.pats))
	full := cacheFindScratchLen(shape.input, shape.pats)
	want := canonCache(driveCacheFind(t, shape.pats, shape.input, 0, outCap, false, full, engageAny))
	// 32 bytes holds the header and at most one tuple: the sweep must refuse
	// and the drive must still be complete and correct.
	got := canonCache(driveCacheFind(t, shape.pats, shape.input, 0, outCap, true, 32, engageNever))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("undersized scratch changed the answer: %d tuples vs %d", len(got), len(want))
	}
}
