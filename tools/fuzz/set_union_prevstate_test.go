package fuzz

import (
	"fmt"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/utils"
)

// Coverage from the PREV-STATE SKIP episode (an optimisation refuted on fuel
// option B — BUILT AND REVERTED 2026-08-28).
//
// The skip made the mid-accept recording conditional on `state != lastOr` and
// was refuted by measurement: the union automaton's parity copies mean a
// saturated run ALTERNATES between two accepting states, so the skip never
// fired and cost +20.9% on its own target row. The code is gone; these tests
// stay, because the shapes were chosen to break any conditional-recording
// change to the union scan's accept arms and none of them existed before:
//
//   - nullable-entry: the ENTRY state's accepts, recorded before any byte is
//     consumed — and after the mid-accept-first renumbering that state can be
//     state 0, which is what a zero-initialised bookkeeping local would alias.
//   - eof-differs: members whose mid-string and end-of-input accept sets
//     differ, so an optimisation of the mid arm wrongly applied to the EOF arm
//     loses `\z`-anchored accepts.
//   - saturated-run / alternating-accepts: the two shapes a per-byte
//     optimisation confuses — one state repeated, and two states alternating,
//     which the union automaton makes of a run of identical bytes.
//
// TestUnionScanSaturatedRunCost is the FUEL pin on the saturated shape, the
// only guard that can see a change which answers correctly at a different
// per-byte cost — in either direction.
//
// Every case asserts through --diag-json that a union automaton served the
// scan pair, and at which width, before it asserts anything else: these bodies
// are reached only by literal-less sets, and one stray mandatory literal routes
// the whole fixture to the bucket walk while still passing.

// prevStateShapes are the four families described above. Each is literal-less,
// which is what keeps the set on the union path at all.
var prevStateShapes = []struct {
	name string
	pats []string
	ins  []string
}{
	{
		// NULLABLE: `[0-9]*` matches empty at every position, so the ENTRY
		// state accepts before a byte is consumed. On an input with no digit
		// p0's empty match is the whole answer, so losing that one recording
		// loses everything — and after the mid-accept-first renumbering the
		// entry state can be state 0, the value a zero-initialised local
		// would alias.
		name: "nullable-entry",
		pats: []string{`[0-9]*`, `[a-c]{2}`},
		ins:  []string{"", "x", "xyz", "abz", "q1q", "aab", "zzzz", "1"},
	},
	{
		// EOF DIFFERS FROM MID: after "abc" the state records p0 mid-string
		// and p0+p1 at end of input. The mid arm runs first on the same state,
		// so mid-arm bookkeeping wrongly applied to the EOF arm drops p1 —
		// while every input NOT ending in the class still passes.
		name: "eof-differs",
		pats: []string{`[a-c]+`, `[a-c]+\z`, `[0-9]$`},
		ins:  []string{"", "a", "abc", "xabc", "abcx", "abc7", "7", "x7", "cba"},
	},
	{
		// SATURATED: `[a-c]+` accepts on every byte of a run — the shape that
		// tempts a conditional-recording change in the first place.
		// Interleaved with bytes that leave the run, so per-drive bookkeeping
		// would have to re-establish itself mid-input rather than only at
		// entry.
		name: "saturated-run",
		pats: []string{`[a-c]+`, `[0-9]{2}`},
		ins: []string{
			"aaaaaaaaaaaaaaaa",
			"aaaa11aaaa",
			"abcabcabcabc",
			"aaaa bbbb cccc",
			strings.Repeat("a", 300),
			strings.Repeat("ab", 150) + "99",
		},
	},
	{
		// ALTERNATING: two DIFFERENT accepting states in succession, and both
		// recordings must happen. This is also what the union automaton's
		// parity copies make of a plain run — the fact that refuted option B —
		// so anything keyed on "the previous byte's state" is exercised here
		// on the shape that actually occurs.
		name: "alternating-accepts",
		pats: []string{`[a-c]`, `[0-9]`, `[a-c][0-9]`},
		ins:  []string{"a1a1a1a1", "1a1a1a1a", "a1", "1a", "abc123", "a1b2c3"},
	},
}

// TestUnionScanAcceptArmsMatchGo drives the four shapes through the NARROW
// scan pair (the i64-accumulator body) against Go.
func TestUnionScanAcceptArmsMatchGo(t *testing.T) {
	for _, sh := range prevStateShapes {
		w, diags := wideUnionSet(t, sh.pats, nil, false)
		assertUnionScan(t, diags, false)
		dropped := droppedFromSet(diags)

		for _, input := range sh.ins {
			t.Run(fmt.Sprintf("%s/%d", sh.name, len(input)), func(t *testing.T) {
				r := newWideRunner(t, w, input, len(sh.pats))
				defer r.Close()
				n := int32(len(input))

				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(sh.pats, input, from, dropped)
					f := int32(from)

					gotAny := r.call(t, "cap_scan_any", r.inBase, n, f).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1 on %q",
								from, gotAny, input)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v on %q",
							from, gotAny, want, input)
					}

					got := idsFromMask(
						uint64(r.call(t, "cap_scan_all", r.inBase, n, f).(int64)),
						len(sh.pats))
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						t.Fatalf("scan_all(from=%d) = %v, want %v on %q",
							from, got, want, input)
					}
				}
			})
		}
	}
}

// TestUnionScanAcceptArmsWide is the same four shapes above 64 ids, where the
// recording is an OR of a bitmap ROW into caller memory plus a popcnt of what
// flipped — so the returned count and the bitmap can drift apart separately,
// and the count is asserted, not just the bitmap.
func TestUnionScanAcceptArmsWide(t *testing.T) {
	for _, sh := range prevStateShapes {
		// Pad to 70 ids with literal-less filler that cannot itself match the
		// shape's inputs, so the shape's own patterns still decide the answer.
		pats := append([]string(nil), sh.pats...)
		for len(pats) < 70 {
			pats = append(pats, fmt.Sprintf(`[p-r]{%d}[5-9]{%d}`,
				1+len(pats)%7, 1+len(pats)/7%5))
		}
		w, diags := wideUnionSet(t, pats, nil, false)
		assertUnionScan(t, diags, true)
		dropped := droppedFromSet(diags)

		for _, input := range sh.ins {
			t.Run(fmt.Sprintf("%s/%d", sh.name, len(input)), func(t *testing.T) {
				r := newWideRunner(t, w, input, len(pats))
				defer r.Close()
				n := int32(len(input))

				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(pats, input, from, dropped)
					f := int32(from)

					gotAny := r.call(t, "cap_scan_any", r.inBase, n, f).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1 on %q",
								from, gotAny, input)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v on %q",
							from, gotAny, want, input)
					}

					r.clear()
					count := int(r.call(t, "cap_scan_all",
						r.inBase, n, f, r.outPtr).(int32))
					r.checkCanary(t, "scan_all")
					got := r.bitmapIDs()
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						t.Fatalf("scan_all(from=%d) = %v, want %v on %q",
							from, got, want, input)
					}
					if count != len(want) {
						t.Fatalf("scan_all(from=%d) count = %d, want %d on %q: "+
							"a count that drifts from the bitmap means a "+
							"recording was skipped or double-counted where it "+
							"could still have contributed",
							from, count, len(want), input)
					}
				}
			})
		}
	}
}

// TestUnionScanSaturatedRunCost measures the union scan on a long run that
// keeps the automaton in ACCEPTING states — greedy-3 / 50K a's in miniature,
// the row that episode was about.
//
// It exists as a COST guard because that row has now moved twice on emitter
// changes that no oracle could see, and because measuring it here is what
// refuted the prev-state skip's premise. The skip assumed a saturated run sits
// in ONE accepting state. It does not: the start-anywhere subset construction
// emits PARITY COPIES — greedy-3 steps 0 -> 4 -> 0 -> 4 on a run of a's, both
// accepting — so the state differs on every byte, the skip never fires, and its
// test plus update are pure cost. Measured on greedy-3 / 50K a's / `scan_all`:
// 28.75 fuel/byte without the skip, 34.75 with it.
//
// The bound is a ceiling over both, so this test states the cost rather than
// taking a side on that decision; it fails only on drift far beyond either.
func TestUnionScanSaturatedRunCost(t *testing.T) {
	pats := []string{`[a-c]+`, `[0-9]{2}`}
	w, diags := wideUnionSet(t, pats, nil, false)
	assertUnionScan(t, diags, false)

	const n = 20000
	input := strings.Repeat("a", n)

	// A fuel-metered engine of its own: the shared one is not metered, and
	// turning metering on there would tax every other test in the package.
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	cfg.SetWasmBulkMemory(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	defer engine.Close()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("compile module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	mem := inst.GetExport(store, "memory").Memory()

	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	needed := uint64((int64(inBase) + n + 2*pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	copy(mem.UnsafeData(store)[inBase:], input)

	// scan_all rather than scan_any: scan_any returns at the first accepting
	// state and never reaches the run at all.
	fn := inst.GetFunc(store, "cap_scan_all")
	if fn == nil {
		t.Fatal("module missing cap_scan_all export")
	}
	if err := store.SetFuel(1 << 40); err != nil {
		t.Fatalf("set fuel: %v", err)
	}
	before, err := store.GetFuel()
	if err != nil {
		t.Fatalf("get fuel: %v", err)
	}
	if _, err := fn.Call(store, inBase, int32(n), int32(0)); err != nil {
		t.Fatalf("cap_scan_all: %v", err)
	}
	after, err := store.GetFuel()
	if err != nil {
		t.Fatalf("get fuel: %v", err)
	}
	perByte := float64(before-after) / float64(n)

	// Measured 2026-08-28 on this fixture: 28.75 fuel/byte without the
	// prev-state skip, 34.75 with it. 45 clears both with margin.
	const bound = 45.0
	if perByte > bound {
		t.Fatalf("saturated scan_all costs %.2f fuel/byte, over the %.1f bound. "+
			"A run of bytes inside accepting states is the union scan's worst "+
			"shape and the one the refuted skip targeted; a cost this "+
			"far above either recorded figure means the per-byte arm grew.",
			perByte, bound)
	}
	t.Logf("saturated scan_all: %.2f fuel/byte over %d bytes", perByte, n)
}
