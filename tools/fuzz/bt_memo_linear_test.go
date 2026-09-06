package fuzz

import (
	"fmt"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// Regression: the no-capture Backtracking FIND body must cost time LINEAR in
// input length, not quadratic.
//
// The BitState memo is a bitset of N*(len+1) bits, sized from the whole input.
// Until 2026-09-06 it was re-zeroed with one memory.fill at the head of every
// ATTEMPT — every candidate start position the find loop tries — which makes
// the search O(N*len^2). wasmtime charges memory.fill about 1 fuel per byte, so
// the memset alone dominated everything else the engine did:
//
//	len          64      128      256      512     1024     2048     4096
//	per-attempt x---    x3.86    x3.93    x3.96    x3.98    x3.99    x4.00
//	per-call    x---    x1.98    x1.99    x1.99    x2.00    x2.00    x2.00
//
// x4.00 per doubling is quadratic. At 4,096 bytes that was 1,796,155,500 fuel
// against 1,696,356 — a factor of 1,059, growing with length.
//
// The fix hoists the fill to once per CALL. It is sound in this body and only
// this body: it tracks no captures, so its entire NFA state is (pc, pos), and a
// pair marked during a failed attempt has no accepting continuation regardless
// of which start position reached it. The CAPTURE body keeps its per-attempt
// fill — its state includes the capture registers, so the same (pc, pos) can
// carry a different answer.
//
// This test pins the COMPLEXITY rather than any fuel number, so it keeps
// working when the constants move: re-introducing a per-attempt fill sends the
// growth ratio back to ~4 and fails it, while ordinary tuning does not.

// TestBTFindMemoIsLinearInInputLength doubles the input and requires the fuel
// to roughly double with it.
func TestBTFindMemoIsLinearInInputLength(t *testing.T) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	engine := wasmtime.NewEngineWithConfig(cfg)

	// Needs all three: a non-greedy loop with an empty-matchable body (so
	// needsBitState fires), a DFA squeezed past its limit (so the pattern
	// reaches Backtracking for find at all), and a no-match input (so every
	// start position is attempted).
	entry := config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"}
	opts := compile.CompileOptions{MaxDFAStates: 1}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(engine)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		copy(mem.UnsafeData(store)[pathsInputBase:], strings.Repeat("a", n))
		fn := inst.GetFunc(store, "find")
		before, _ := store.GetFuel()
		if _, err := fn.Call(store, pathsInputBase, int32(n), int32(0)); err != nil {
			t.Fatalf("len=%d: %v", n, err)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	// 3.0 sits well clear of both regimes — linear measures ~2.00, the
	// quadratic form measured 3.86 at the first doubling and rose from there.
	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{256, 512, 1024, 2048, 4096} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the BitState memo fill looks per-attempt again, which makes "+
					"this search quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}
