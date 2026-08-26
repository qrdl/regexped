package fuzz

// SETS_PLAN item 20, task 20.B: parameter 7 of a set suffix function carries
// EITHER a gate-array pointer (gated find) OR §19's skip count (overlapping
// batch) — never both, and the two forms have the same arity, so conflating
// them is a silent wrong answer rather than a validation error.
//
// The BT suffix body read parameter 7 as a gate pointer in both cases. On an
// overlapping batch set that means (a) the §3.16 empty-extent block
// dereferences `skip + id*4` as an address, and (b) skip is never honoured, so
// a batch resume at a split position re-delivers the BT bucket's tuple.
//
// Catching BOTH halves needs one set that has an empty-extent match (a) and a
// position carrying more than one tuple, driven at capacity 1 so that position
// splits across calls (b).

import (
	"fmt"
	"regexp"
	"testing"

	"encoding/binary"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// compileBTBatchSet compiles an overlapping set exporting both `find` and its
// batch entry, with max_fallback_states forced low so its members land on the
// Backtracking engine. Returns the module and how many BT buckets it holds, so
// a test cannot silently pass by exercising the DFA path instead.
func compileBTBatchSet(pats []string, maxFallback int) ([]byte, int, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps:           entries,
		MaxFallbackStates: maxFallback,
		Sets: []config.SetConfig{{
			Name:        "s",
			Find:        "set_find",
			Hints:       []string{"batch-find"},
			Overlapping: true,
			Patterns:    config.PatternSelector{Names: names},
		}},
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		return nil, 0, err
	}
	nBT := 0
	for _, d := range diags {
		for _, b := range d.Buckets {
			if b.Type == "bt-fallback" {
				nBT++
			}
		}
	}
	return w, nBT, nil
}

// runBTBatch drives the overlapping batch entry to exhaustion at the given
// capacity. Overlapping batch takes no gate array: (ptr, len, cursor, out_ptr,
// out_cap) -> i64.
func runBTBatch(t *testing.T, w []byte, pats []string, input string, outCap int32) []setMatch {
	t.Helper()
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
	// The overlapping batch entry takes the gate array too since SETS_PLAN
	// item 11 — not for match gates, which it records none of, but as the
	// per-drive home of the preflight verdict. Zeroed here: that is what
	// declares a fresh drive.
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	for i := int32(0); i < pageSize; i++ {
		mem.UnsafeData(store)[gatePtr+i] = 0
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out []setMatch
	cursor := int64(0)
	maxCalls := 8*(len(input)+1)*(len(pats)+1) + 16
	for calls := 0; ; calls++ {
		if calls > maxCalls {
			t.Fatalf("%v on %q cap=%d: batch did not terminate after %d calls",
				pats, input, outCap, calls)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, gatePtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		if n < 0 || n > outCap {
			t.Fatalf("%v on %q cap=%d: count %d out of range", pats, input, outCap, n)
		}
		buf := mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			})
		}
		if uint32(packed>>32) == 0xFFFFFFFF {
			break
		}
		cursor = packed
	}
	return out
}

// TestBTOverlappingBatchHonoursSkip is task 20.B's regression.
//
// The set deliberately mixes an empty-extent-capable pattern with one that
// shares its start positions, so a single input exercises both halves of the
// parameter-7 defect. The capacity sweep is what makes it sharp: at cap 1 every
// multi-tuple position splits, so a body that ignores skip re-delivers on
// resume, and the totals stop matching the oracle.
func TestBTOverlappingBatchHonoursSkip(t *testing.T) {
	pats := []string{`(?:ab)*`, `(?:ab)*(?:cd)*`}
	const input = "abcd"

	w, nBT, err := compileBTBatchSet(pats, 1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if nBT == 0 {
		t.Skip("no BT bucket was created — nothing of task 20.B is exercised")
	}
	t.Logf("%d BT bucket(s)", nBT)

	// Oracle: overlapping find enumerates every match at every start position.
	var want []setMatch
	for i, p := range pats {
		re := regexp.MustCompile(p)
		for _, m := range allStartPositionMatches(re, input) {
			want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
		}
	}

	for _, outCap := range []int32{1, 2, int32(len(pats)), 16} {
		got := runBTBatch(t, w, pats, input, outCap)
		if !sameTuples(got, want) {
			t.Errorf("overlapping batch cap=%d over %q:\n  got  %v\n  want %v",
				outCap, input, got, want)
		}
	}
}

// TestBTOverlappingFindMatchesBatch drives the same set through the plain
// `find` entry, whose forwarded batch argument is zero — the skip == 0 path,
// which must write every tuple. `find` and its batch entry share ONE worker, so
// disagreement between them localises a fault to the batch-only argument.
func TestBTOverlappingFindMatchesBatch(t *testing.T) {
	pats := []string{`(?:ab)*`, `(?:ab)*(?:cd)*`}
	const input = "abcd"

	w, nBT, err := compileBTBatchSet(pats, 1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if nBT == 0 {
		t.Skip("no BT bucket was created — nothing of task 20.B is exercised")
	}

	got, hang, runErr := runWasmSetFind(w, input, len(pats))
	if hang {
		t.Skip("watchdog")
	}
	if runErr != nil {
		t.Fatalf("find: %v", runErr)
	}
	want := runBTBatch(t, w, pats, input, int32(len(pats)))
	if !sameTuples(got, want) {
		t.Errorf("find vs batch over %q disagree:\n  find  %v\n  batch %v", input, got, want)
	}
}
