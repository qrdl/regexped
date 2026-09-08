package fuzz

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// Regression: the BATCH groups wrapper and the plain groups wrapper call the
// SAME capture body, so they must agree on how that body reports slots.
//
// The absolute-slot channel (compiledPattern.capStartGlobal) hands the capture
// body the match's start through a module global; the body then adds it to
// every slot it writes and the wrapper skips its per-slot rebasing pass. The
// plain groups wrapper sets the global. The batch wrapper did not — it kept
// its own `+adj` pass while calling a body that was already adding whatever the
// global happened to hold. On a fresh instance the global is 0 and the answer
// is right by accident; after ANY groups() call it holds that call's match
// start, and every slot of every batch record comes back shifted by it:
//
//	(\w+)@(\w+) over "xx a@b yy c@d", record 0 (start end g0s g0e g1s g1e g2s g2e)
//	  fresh instance:        3 6 3 6 3 4 5 6   (correct)
//	  after one groups():    6 9 6 9 6 7 8 9   (every value +3)
//
// Both capture engines are covered: the greedy pattern selects TDFA, the
// non-greedy one Backtracking, and each has its own biased register/local init
// and its own slot-write site.
//
// The test drives the batch export BEFORE and AFTER a groups() call and
// requires the two to agree, and separately checks both against Go — so it
// fails on a stale channel (the bug) and on a double rebase (the fix applied
// in one place only).

// batchGroupsRecord is one (start, end, slots...) record of the batch groups
// output, decoded from the module's memory.
type batchGroupsRecord struct {
	start, end int32
	slots      []int32
}

func (r batchGroupsRecord) String() string {
	return fmt.Sprintf("[%d,%d) slots=%v", r.start, r.end, r.slots)
}

func TestBatchGroupsAbsoluteSlotsSurviveAGroupsCall(t *testing.T) {
	const input = "xx a@b yy c@d"

	for _, tc := range []struct {
		name string
		pat  string
	}{
		// Greedy, no word boundaries, no line anchors → TDFA.
		{"tdfa", `(\w+)@(\w+)`},
		// A non-greedy quantifier disqualifies TDFA → Backtracking.
		{"backtracking", `(\w+?)@(\w+)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := config.RegexEntry{
				Pattern:    tc.pat,
				GroupsFunc: "groups",
				Hints:      []string{"batch-find"},
			}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			eng, _ := compile.SelectEngine(tc.pat, compile.CompileOptions{})
			t.Logf("%s → %v", tc.pat, eng)

			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], input)

			numGroups := regexp.MustCompile(tc.pat).NumSubexp() + 1
			recordSize := 8 + numGroups*8
			// The batch buffer sits above the plain groups slot buffer so one
			// call cannot overwrite the other's output.
			batchOut := pathsOutBase + 1024

			readRecords := func(n int) []batchGroupsRecord {
				buf := mem.UnsafeData(store)
				out := make([]batchGroupsRecord, 0, n)
				for i := 0; i < n; i++ {
					base := int(batchOut) + i*recordSize
					rd := func(off int) int32 {
						o := base + off
						return int32(uint32(buf[o]) | uint32(buf[o+1])<<8 |
							uint32(buf[o+2])<<16 | uint32(buf[o+3])<<24)
					}
					rec := batchGroupsRecord{start: rd(0), end: rd(4)}
					for g := 0; g < numGroups*2; g++ {
						rec.slots = append(rec.slots, rd(8+g*4))
					}
					out = append(out, rec)
				}
				return out
			}

			callBatch := func() []batchGroupsRecord {
				fn := inst.GetFunc(store, "groups_batch")
				if fn == nil {
					t.Fatal("module has no groups_batch export")
				}
				res, err := fn.Call(store, pathsInputBase, int32(len(input)),
					batchOut, int32(4), int32(0))
				if err != nil {
					t.Fatalf("groups_batch: %v", err)
				}
				return readRecords(int(res.(int32)))
			}

			// What Go says, as the independent oracle for both wrappers.
			re := regexp.MustCompile(tc.pat)
			var want []batchGroupsRecord
			for _, m := range re.FindAllSubmatchIndex([]byte(input), -1) {
				rec := batchGroupsRecord{start: int32(m[0]), end: int32(m[1])}
				for _, v := range m {
					rec.slots = append(rec.slots, int32(v))
				}
				want = append(want, rec)
			}

			check := func(when string, got []batchGroupsRecord) {
				t.Helper()
				if len(got) != len(want) {
					t.Fatalf("%s: %d records, want %d\ngot  %v\nwant %v",
						when, len(got), len(want), got, want)
				}
				for i := range got {
					if got[i].start != want[i].start || got[i].end != want[i].end {
						t.Errorf("%s: record %d extent = [%d,%d), want [%d,%d)",
							when, i, got[i].start, got[i].end, want[i].start, want[i].end)
					}
					for s := range want[i].slots {
						if got[i].slots[s] != want[i].slots[s] {
							t.Errorf("%s: record %d slot %d = %d, want %d\ngot  %v\nwant %v",
								when, i, s, got[i].slots[s], want[i].slots[s], got[i], want[i])
							break
						}
					}
				}
			}

			before := callBatch()
			check("fresh instance", before)

			// One ordinary groups() call, which is what leaves the absolute-slot
			// channel holding a non-zero start.
			gfn := inst.GetFunc(store, "groups")
			if gfn == nil {
				t.Fatal("module has no groups export")
			}
			if _, err := gfn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(0)); err != nil {
				t.Fatalf("groups: %v", err)
			}

			after := callBatch()
			check("after a groups() call", after)

			for i := range before {
				if before[i].String() != after[i].String() {
					t.Fatalf("record %d differs across a groups() call:\n  before %v\n  after  %v\n"+
						"the batch wrapper and the capture body disagree about who rebases slots",
						i, before[i], after[i])
				}
			}

			// And twice in a row, so a channel left stale BETWEEN the batch
			// loop's own iterations would show up too.
			check("second batch call", callBatch())
		})
	}
}
