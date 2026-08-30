package fuzz

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// TestBatchZeroCapTerminates pins the raw-ABI zero-capacity contract.
//
// find_batch returns a packed i64: bits 63..32 are the resume position, or
// 0xFFFFFFFF when the scan is finished. A caller driving the export directly,
// with no generated stub, loops until it sees that sentinel.
//
// out_cap = 0 is the case that could break the loop: a buffer with no room
// delivers nothing, and returning the caller's own resume position unchanged
// would make such a loop spin forever. set_batch.go therefore reports the scan
// FINISHED at zero capacity. Plain `find` keeps treating out_cap = 0 as a size
// probe instead, which it can because it returns a count rather than a
// resumable cursor — a different function with a different contract, covered by
// make setcaps.
//
// Both the gated and the overlapping entries are checked: they take different
// parameter lists (the gated one carries a gate array) and reach the sentinel
// through different arms.
func TestBatchZeroCapTerminates(t *testing.T) {
	pats := []string{`ab`, `b`}
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	for _, overlapping := range []bool{false, true} {
		t.Run(fmt.Sprintf("overlapping=%v", overlapping), func(t *testing.T) {
			cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{{
				Name: "s", Find: "set_find", Hints: []string{"batch-find"},
				Overlapping: overlapping,
				Patterns:    config.PatternSelector{Names: names},
			}}}
			w, _, _, err := compile.CompileFileDiag(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
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
			gate := inBase + pg
			out := gate + pg
			needed := uint64((int64(out) + 2*pg + pg - 1) / pg)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatal(err)
				}
			}
			input := "abab" // deliberately HAS matches: the point is that a
			// full buffer's worth of work is still reported as finished when
			// there is nowhere to put it.
			copy(mem.UnsafeData(store)[inBase:], input)

			// Both flavours take the gate array.
			res, err := fn.Call(store, inBase, int32(len(input)), int64(0), gate, out, int32(0), int32(0), int32(0))
			if err != nil {
				t.Fatalf("set_find_batch: %v", err)
			}
			packed := uint64(res.(int64))
			if hi := uint32(packed >> 32); hi != 0xFFFFFFFF {
				t.Fatalf("out_cap=0 returned position %#08x, want the 0xFFFFFFFF done "+
					"sentinel — a raw-ABI caller looping on this cursor would spin", hi)
			}
			countBits := uint(config.SetCursorCountBits(len(pats)))
			if n := packed & (1<<countBits - 1); n != 0 {
				t.Fatalf("out_cap=0 reported %d tuples, but nothing can be written", n)
			}
		})
	}
}
