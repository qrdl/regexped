package fuzz

import (
	"fmt"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
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

// ---------------------------------------------------------------------------
// The same property for a SET's Backtracking bucket, which the hoist above
// does NOT cover.
//
// A set BT bucket is a suffix function called once per CANDIDATE position, and
// each call ran one memory.fill over the whole remaining window — so the drive
// was O(N*len^2) with the memset again the entire quadratic term. Measured on
// the case below, before the position-major memo layout and its lazy clear:
//
//	len          256      512     1024     2048     4096     8192    16384    32768
//	per-call   x---    x2.27    x2.47    x2.75    x3.09    x3.41    x3.65    x3.81
//	lazy       x---    x2.01    x2.00    x2.00    x2.00    x2.00    x2.00    x2.00
//
// 247,139,555 fuel against 12,483,789 at 32 KB — a factor of 19.8, growing
// with length. Neutralising the fill entirely measured 12,238,053, so what
// remains of the clear is 2.0% rather than 95% of the call.
//
// The fix is not the find body's hoist, which is unsound here: a set bucket is
// a separate WASM function per candidate and cannot share marks across calls
// without a per-drive clear no exported body is obliged to perform. Instead
// the memo is indexed POSITION-major, which makes the bytes one attempt dirties
// a contiguous run from the base, and each call clears exactly the run the
// previous call recorded in the memo header word.
func TestSetBTMemoIsLinearInInputLength(t *testing.T) {
	// Needs all of: a member forced onto BT (max_fallback_states = 1), a
	// non-greedy loop with an empty-matchable body (needsBitState), a rare
	// leading byte so most positions are candidates that FAIL fast, and a
	// match at the very end so the drive scans the whole input.
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p0", Pattern: `q(?:a?)+?z`}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{Names: []string{"p0"}},
		}},
		MaxFallbackStates: 1,
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if d := droppedFromSet(diags); len(d) > 0 {
		t.Fatalf("the pattern was dropped from the set: %v", d)
	}

	wcfg := wasmtime.NewConfig()
	wcfg.SetConsumeFuel(true)
	wcfg.SetWasmSIMD(true)
	eng := wasmtime.NewEngineWithConfig(wcfg)
	mod, err := wasmtime.NewModule(eng, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	const pageSize = 65536
	dataTop, dtErr := utils.ParseDataSectionBytes(w)
	if dtErr != nil {
		t.Fatalf("parse data section: %v", dtErr)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(eng)
		defer store.Close()
		if err := store.SetFuel(1 << 62); err != nil {
			t.Fatal(err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		inputSpan := int32((n + pageSize - 1) / pageSize * pageSize)
		gateBase := inBase + inputSpan
		outBase := gateBase + pageSize
		need := uint64((int64(outBase) + pageSize + pageSize - 1) / pageSize)
		if cur := mem.Size(store); need > cur {
			if _, gErr := mem.Grow(store, need-cur); gErr != nil {
				t.Fatal(gErr)
			}
		}
		in := strings.Repeat("qa", n/2-2) + "qaz"
		for len(in) < n {
			in = "a" + in
		}
		copy(mem.UnsafeData(store)[inBase:], in[:n])
		fn := inst.GetFunc(store, "set_find")
		before, _ := store.GetFuel()
		res, callErr := fn.Call(store, inBase, int32(n), int32(0), gateBase, outBase, int32(1))
		if callErr != nil {
			t.Fatalf("len=%d: %v", n, callErr)
		}
		if got := res.(int32); got != 1 {
			t.Fatalf("len=%d: set_find returned %d, want 1 tuple — the drive is not "+
				"scanning the whole input and the growth curve means nothing", n, got)
		}
		after, _ := store.GetFuel()
		return before - after
	}

	const maxRatio = 3.0

	var prev uint64
	var report strings.Builder
	for _, n := range []int{2048, 4096, 8192, 16384, 32768} {
		f := fuelAt(n)
		if prev > 0 {
			r := float64(f) / float64(prev)
			fmt.Fprintf(&report, "  len=%-6d fuel=%-12d x%.2f vs half\n", n, f, r)
			if r > maxRatio {
				t.Errorf("fuel grew x%.2f from len=%d to len=%d, want <= x%.1f "+
					"— the set BT bucket's memo clear looks input-sized again, which "+
					"makes this drive quadratic\n%s", r, n/2, n, maxRatio, report.String())
			}
		}
		prev = f
	}
	t.Logf("growth per doubling:\n%s", report.String())
}
