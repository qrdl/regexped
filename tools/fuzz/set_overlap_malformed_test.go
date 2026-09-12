package fuzz

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// A cache header the caller got WRONG must be REPORTED, not degraded into a
// silent walk (plans §9.2 decision 3).
//
// The distinction this pins is the whole reason the sentinel exists. A region
// that is merely too small is a legitimate answer — the drive walks, the answer
// is identical, only slower — and a header whose stride is nonsense is a
// mistake. Both look the same from inside the sweep, and left alike the mistake
// is indistinguishable from the engine legitimately declining the shape, on
// exactly the never-dying inputs the cache exists for.
func TestOverlapCacheMalformedHeaderIsReported(t *testing.T) {
	// A shape the corpus already knows drives the trigger: the cache only
	// engages once the walk has proven expensive, and a header nobody looks at
	// reports nothing.
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, stride := overlapCacheFor(input, pats)

	// A stride of ZERO is what a caller who zeroed the header and forgot to
	// fill it in leaves behind, and it is the likeliest form of the mistake.
	got := driveCacheFindStride(t, pats, input, 0, int32(len(pats)), true, full, 0)
	if got != abi.OverlapCacheMalformed {
		t.Fatalf("stride 0: find returned %d, want %d (the malformed-cache error)",
			got, abi.OverlapCacheMalformed)
	}

	// A NEGATIVE stride would index the region backwards.
	if got := driveCacheFindStride(t, pats, input, 0, int32(len(pats)), true, full, -7); got != abi.OverlapCacheMalformed {
		t.Fatalf("stride -7: find returned %d, want %d", got, abi.OverlapCacheMalformed)
	}

	// A CORRECT header must not trip it — otherwise the test above passes for
	// the wrong reason and every drive is an error.
	if got := driveCacheFindStride(t, pats, input, 0, int32(len(pats)), true, full, stride); got < 0 {
		t.Fatalf("a correct header returned %d; the drive should have answered normally", got)
	}
}

// driveCacheFindStride makes ONE `find` call with a caller-chosen stride in the
// cache header, and returns the raw result.
//
// Deliberately one call and raw: the malformed case is about what the FIRST
// call reports, and the collecting drivers interpret a negative return as "the
// drive ended" rather than handing it back.
func driveCacheFindStride(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen, stride int32,
) int32 {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
		}},
	}
	w, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
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
	desc := writeFindScratchStride(store, mem, gatePtr, int32(len(pats)), scratchPtr, scratchLen, stride)

	// The trigger is adaptive: a cache is only consulted once the walk has
	// proven expensive, so the drive has to run until it engages. A malformed
	// header is reported at that moment, not before.
	from := offset
	for calls := 0; calls < 4*(len(input)+2)*len(pats)+16; calls++ {
		res, err := fn.Call(store, inBase, int32(len(input)), from, desc, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find: %v", err)
		}
		n := res.(int32)
		if n < 0 {
			return n
		}
		if n == 0 {
			return 0
		}
		// ONE position at a time: an overlapping drive enumerates every start,
		// and advancing by the match extent would skip most of them — and with
		// them the work that makes the trigger fire at all.
		start := int32(readU32(mem.UnsafeData(store), int(outPtr)+4))
		from = start + 1
	}
	t.Fatal("drive did not terminate")
	return 0
}
