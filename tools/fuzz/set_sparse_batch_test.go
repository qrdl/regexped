package fuzz

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// TestSparseGatedBatchDeliversEveryPattern is the regression for the second
// defect this work uncovered: every mask-based shortcut on the candidate path
// is an i32, so none of them can describe a G17 sparse bucket's patterns past
// the 32nd.
//
// emitGateMask clears a bit per pattern for the first 32 only, and
// emitEmptyMaskSkip then leaves the whole group when the mask comes out empty.
// For a sparse bucket that is wrong twice over: the mask never described the
// later patterns, so "empty" means "the first 32 are done", not "there is
// nothing left". A gated batch driven to exhaustion therefore delivered
// EXACTLY 32 tuples of 40 — the bitmask width, which is what makes the symptom
// recognisable.
//
// Capacity 1 is what exposes it: every tuple of the position needs its own
// call, so the gate array really does fill up mid-position and the pre-mask
// really does go empty before the bucket is finished. At capacity N the whole
// position is delivered in one call and the shortcut never fires.
func TestSparseGatedBatchDeliversEveryPattern(t *testing.T) {
	for _, n := range []int{8, 40, 64} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			pats := make([]string, n)
			for i := range pats {
				// Empty-matchable, and deliberately NOT anchored: an anchored
				// pattern is refused promotion (its "only at position 0" rule
				// lives in the i32 group mask, which a sparse body ignores), so
				// anchoring these would test the ordinary bucketed path.
				// On the empty input each still reports exactly one 0-0 tuple,
				// so any loss shows up directly as a count.
				pats[i] = fmt.Sprintf(`(?:(?:)|a%d)*`, i)
			}
			entries := make([]config.RegexEntry, n)
			names := make([]string, n)
			for i, p := range pats {
				names[i] = fmt.Sprintf("p%d", i)
				entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
			}
			cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{{
				Name: "s", Find: "set_find", Hints: []string{"batch-find"},
				Patterns: config.PatternSelector{Names: names},
			}}}
			w, _, diags, err := compile.CompileFileDiag(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			sparse := false
			for _, d := range diags {
				for _, b := range d.Buckets {
					if b.Type == "sparse-set" {
						sparse = true
					}
				}
			}
			if n > 32 && !sparse {
				t.Fatalf("n=%d did not produce a sparse bucket; the test would prove nothing", n)
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
			const pg = 65536
			dataTop, err := utils.ParseDataSectionBytes(w)
			if err != nil {
				t.Fatal(err)
			}
			inBase := int32((dataTop + pg - 1) / pg * pg)
			gatePtr := inBase + pg
			outPtr := gatePtr + pg
			needed := uint64((int64(outPtr) + 2*pg + pg - 1) / pg)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatal(err)
				}
			}
			countBits := uint(config.SetCursorCountBits(n))
			countMask := int64(1)<<countBits - 1

			for _, outCap := range []int32{1, 2, int32(n)} {
				d := mem.UnsafeData(store)
				for i := 0; i < n*4; i++ {
					d[int(gatePtr)+i] = 0
				}
				seen := map[int]int{}
				total := 0
				cursor := int64(0)
				maxCalls := 8*(n+1) + 16
				for calls := 0; ; calls++ {
					if calls > maxCalls {
						t.Fatalf("cap=%d: batch did not terminate after %d calls", outCap, calls)
					}
					res, err := fn.Call(store, inBase, int32(0), cursor, gatePtr, outPtr, outCap)
					if err != nil {
						t.Fatalf("cap=%d: %v", outCap, err)
					}
					packed := res.(int64)
					cnt := int32(packed & countMask)
					if cnt < 0 || cnt > outCap {
						t.Fatalf("cap=%d: count %d out of range", outCap, cnt)
					}
					buf := mem.UnsafeData(store)
					for i := int32(0); i < cnt; i++ {
						base := int(outPtr) + int(i)*12
						id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
						st := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
						en := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
						if st != 0 || en != 0 {
							t.Fatalf("cap=%d: pattern %d reported %d-%d, want 0-0", outCap, id, st, en)
						}
						seen[id]++
						total++
					}
					if uint32(packed>>32) == 0xFFFFFFFF {
						break
					}
					cursor = packed
				}
				if total != n {
					t.Fatalf("cap=%d: %d tuples, want %d (sparse=%v)", outCap, total, n, sparse)
				}
				for id := 0; id < n; id++ {
					if seen[id] != 1 {
						t.Fatalf("cap=%d: pattern %d delivered %d times, want 1", outCap, id, seen[id])
					}
				}
			}
		})
	}
}
