package fuzz

import (
	"strings"
	"testing"
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
