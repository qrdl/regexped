package fuzz

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// An OVERLAPPING component set, which until now was the only output kind left
// quadratic.
//
// A component consumer has no pointer to hand in and nothing to free, so the
// answer cache can only come from the resource's own constructor. That was
// deferred while the region was over a hundred megabytes; checkpointed it is a
// small fraction of that, and the constructor now reserves it.
const overlapSetCfg = `
wasm_format: component
wit_package: t
import_module: t
regexps:
  - pattern: '[a-z]+'
  - pattern: '[0-9]+'
  - pattern: '[A-Z]+'
sets:
  - name: s
    patterns: all
    overlapping: true
    find: scan_it
`

// TestComponentOverlapCacheAnswersCorrectly drives the resource to exhaustion
// over an input long enough for the cache to engage, and checks the answer
// against the enumeration the contract promises: every start position, in
// order, with every pattern that matches there.
//
// The cache engaging is the point. Below the work threshold the drive walks and
// this test would pass without the constructor reserving anything at all, which
// is why the input is long and dense rather than a handful of bytes.
func TestComponentOverlapCacheAnswersCorrectly(t *testing.T) {
	h := newSetHarness(t, overlapSetCfg)
	text := strings.Repeat("abcdefgh", 512) // 4096 bytes, every position matches
	p, n := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, n, int32(0))
	defer h.call(h.pkg+"#[dtor]scan-it", sc)

	var starts []uint32
	for i := 0; i < len(text)+8; i++ {
		got, _ := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc))
		if len(got) == 0 {
			break
		}
		starts = append(starts, got[0][1])
	}
	if len(starts) != len(text) {
		t.Fatalf("reported %d positions over %d bytes; an overlapping drive reports every start",
			len(starts), len(text))
	}
	for i, s := range starts {
		if s != uint32(i) {
			t.Fatalf("position %d reported start %d: the enumeration is not in order", i, s)
		}
	}
}

// The gate, from the other side of it. The test above uses 4 KB, where the
// region is a SINGLE BLOCK — the stride is the whole span, nothing is ever
// re-swept, and the square-root arm, the 16 floor and the over-budget decline
// have never run at all.
//
// This input crosses into the checkpointed regime, which for a 3-pattern set
// (16 bytes a row) is a little over 4 MB. What is checked is the arithmetic the
// constructor does and the engagement that follows it, not the enumeration: a
// drive of four and a half million positions through one component call each is
// not a unit test, so the first hundred positions are checked against the
// contract and the rest is left to the corpus.
func TestComponentOverlapCacheCrossesTheGate(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 4.5 MB input; skipped in -short")
	}
	h := newSetHarness(t, overlapSetCfg)
	// One long lowercase run: `[a-z]+` then matches at every position with an
	// extent running to the end, so the work counter — which charges MATCHED
	// BYTES — crosses the sweep's threshold within the first handful of calls
	// rather than needing the whole drive.
	const n = 4_500_000
	text := strings.Repeat("a", n)
	p, ln := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, ln, int32(0))
	defer h.call(h.pkg+"#[dtor]scan-it", sc)

	// The handle IS the representation here (see newSetHarness), so the
	// descriptor is readable: cache pointer at +20, its length at +24.
	cachePtr := int32(h.u32(sc + 20))
	cacheLen := h.u32(sc + 24)
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no cache for a 4.5 MB input")
	}
	sh, err := compile.SetOverlapCacheShape(overlapSetCfgSet(t), overlapSetCfgBuild(t))
	if err != nil || !sh.Eligible {
		t.Fatalf("shape: %v %+v", err, sh)
	}
	want := uint32(config.SetOverlapCheckpointBytes(n, sh.Cells, sh.Patterns))
	if cacheLen != want {
		t.Fatalf("cache_len = %d, config says %d: the constructor's arithmetic and "+
			"config's have diverged, and the sweep validates against config's", cacheLen, want)
	}
	// Past the gate the stride is NOT the whole span any more, which is the
	// arm this test exists for.
	if k := config.SetOverlapCheckpointStride(n, sh.Cells, sh.Patterns); k >= n+1 {
		t.Fatalf("stride %d is still the whole span: this input no longer crosses the gate", k)
	}

	for i := 0; i < 100; i++ {
		got, errored := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc))
		if errored {
			t.Fatalf("position %d: the scanner reported an error", i)
		}
		if len(got) != 1 || got[0][1] != uint32(i) || got[0][2] != uint32(n) {
			t.Fatalf("position %d: got %v, want one match [0 %d %d]", i, got, i, n)
		}
	}
	// And it engaged: `ready` is the one header field a caller may read, and
	// without this the test passes on a drive that quietly walked.
	if ready := int32(h.u32(cachePtr + 8)); ready != 1 {
		t.Fatalf("ready = %d after 100 positions of a quadratic drive, want 1", ready)
	}
}

// A scanner that reported an ERROR keeps reporting it.
//
// `next` set a done flag on the error and then answered "ok, no more matches"
// for ever after — the silent degradation the sentinels exist to prevent,
// reachable by any raw WIT consumer. The Rust and C stubs latch a `done` of
// their own and never observe it, which is why nothing caught it.
//
// The error is provoked through the CACHE HEADER rather than a Backtracking
// overflow, because the constructor owns that header and the harness can reach
// it: the handle is the representation here, so zeroing the stride between two
// calls is exactly the "one region, two scanners" mistake the -4 sentinel
// exists for. It also checks the other half — that the component adapter maps
// -4 to `malformed-cache` and not to `backtrack-overflow`, which the C
// consumer got wrong by reading only the result discriminant.
func TestComponentScannerRepeatsItsError(t *testing.T) {
	h := newSetHarness(t, overlapSetCfg)
	// Quadratic enough for the sweep to engage within a few calls, so there is
	// a live cache to corrupt.
	text := strings.Repeat("a", 200000)
	p, ln := h.writeInput(text)
	sc := h.call(h.pkg+"#[constructor]scan-it", p, ln, int32(0))

	cachePtr := int32(h.u32(sc + 20))
	if cachePtr == 0 {
		t.Fatal("the constructor reserved no cache, so there is no header to corrupt")
	}
	for i := 0; i < 200; i++ {
		if _, errored := h.matches(h.call(h.pkg+"#[method]scan-it.next", sc)); errored {
			t.Fatalf("position %d errored before the header was touched", i)
		}
		if int32(h.u32(cachePtr+8)) == 1 {
			break
		}
	}
	if int32(h.u32(cachePtr+8)) != 1 {
		t.Fatal("the sweep never engaged, so the header being corrupted proves nothing")
	}

	// A stride of zero: the likeliest form of the mistake, and the one that
	// would divide by zero rather than answer.
	binary.LittleEndian.PutUint32(h.mem.UnsafeData(h.store)[cachePtr+16:], 0)

	code, errored := h.nextErr(sc)
	if !errored {
		t.Fatal("a malformed header was accepted: the call answered normally")
	}
	// error-code { backtrack-overflow = 0, malformed-cache = 1 }
	if code != 1 {
		t.Fatalf("error-code %d, want 1 (malformed-cache); 0 would be reporting a "+
			"cache mistake as a backtracking overflow", code)
	}
	for i := 0; i < 3; i++ {
		again, stillErrored := h.nextErr(sc)
		if !stillErrored {
			t.Fatalf("call %d after the error answered OK: a scanner that could not "+
				"finish must not become 'no more matches'", i+2)
		}
		if again != code {
			t.Fatalf("call %d reported error-code %d, the first reported %d", i+2, again, code)
		}
	}
	// And the dtor still works on an errored scanner: it owns an input copy, a
	// gate array, a cache and the representation, whatever state it stopped in.
	h.call(h.pkg+"#[dtor]scan-it", sc)
}

// nextErr calls next and reports the error-code discriminant beside the result
// discriminant, which `matches` folds into a bool.
func (h *setHarness) nextErr(sc int32) (code byte, errored bool) {
	h.t.Helper()
	ret := h.call(h.pkg+"#[method]scan-it.next", sc)
	data := h.mem.UnsafeData(h.store)
	if data[ret] != 1 {
		return 0, false
	}
	return data[ret+4], true
}

// overlapSetCfgBuild and overlapSetCfgSet parse overlapSetCfg the way the
// generator would, so the region the test expects comes from the same shape the
// constructor was emitted from rather than a constant repeated here.
func overlapSetCfgBuild(t *testing.T) config.BuildConfig {
	t.Helper()
	var cfg config.BuildConfig
	if err := yaml.Unmarshal([]byte(overlapSetCfg), &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func overlapSetCfgSet(t *testing.T) config.SetConfig {
	t.Helper()
	return overlapSetCfgBuild(t).Sets[0]
}
