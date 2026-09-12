package fuzz

import (
	"fmt"
	"strings"
	"testing"
)

// The BLOCK-BOUNDARY paths of the checkpointed cache, which the sizing formula
// makes unreachable on a test-sized input.
//
// At the stride the formula picks, a few-kilobyte input is a SINGLE BLOCK: the
// pass materialises it on its way through, nothing is ever re-swept, no
// checkpoint is loaded and no block is skipped. Every bug the checkpointed
// design can have lives in the paths that only appear once there are several
// blocks, so these tests force tiny strides and drive the same shapes the
// corpus already trusts.
//
// Three of the five bugs found while building this were boundary bugs: the
// block holding the final position never closed, a resume offset wiped at a
// block's first row, and a cursor recording bits examined rather than
// delivered. None of them is visible at one block.
func TestOverlapCacheBlockBoundaries(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, k := range []int32{1, 2, 3, 7, 64} {
			for _, off := range []int32{0, 1, 7} {
				name := fmt.Sprintf("%s/k%d/off%d", shape.name, k, off)
				t.Run(name, func(t *testing.T) {
					if off > int32(len(shape.input)) {
						t.Skip("offset past the input")
					}
					full := cacheFindScratchLen(shape.input, shape.pats)
					walk := driveCacheFindK(t, shape.pats, shape.input, off,
						int32(len(shape.pats)), false, full, engageAny, k)
					cached := driveCacheFindK(t, shape.pats, shape.input, off,
						int32(len(shape.pats)), true, full, engageAny, k)
					if len(walk) != len(cached) {
						t.Fatalf("walk %d tuples, cache %d", len(walk), len(cached))
					}
					for i := range walk {
						if walk[i] != cached[i] {
							t.Fatalf("tuple %d: walk %v, cache %v", i, walk[i], cached[i])
						}
					}
				})
			}
		}
	}
}

// A drive whose matches are ALL in the last block, so every earlier block is
// skipped on its cumulative count without being materialised.
//
// That skip is what keeps a sparse drive from re-sweeping the whole input one
// block at a time, and it is invisible in a corpus where matches are everywhere.
func TestOverlapCacheSkipsEmptyBlocks(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`}
	input := strings.Repeat("...................", 300) + strings.Repeat("a", 200)
	full := cacheFindScratchLen(input, pats)
	for _, k := range []int32{1, 5, 32} {
		walk := driveCacheFindK(t, pats, input, 0, int32(len(pats)), false, full, engageAny, k)
		cached := driveCacheFindK(t, pats, input, 0, int32(len(pats)), true, full, engageAny, k)
		if len(walk) != len(cached) {
			t.Fatalf("k=%d: walk %d tuples, cache %d", k, len(walk), len(cached))
		}
		for i := range walk {
			if walk[i] != cached[i] {
				t.Fatalf("k=%d tuple %d: walk %v, cache %v", k, i, walk[i], cached[i])
			}
		}
	}
}

// Degenerate inputs at a forced stride: empty input, a resume AT the end, and a
// resume PAST it. The last is defined by the ABI as "nothing found" rather than
// an error, and the sweep has to produce an empty block 0 for it rather than
// computing a negative span.
func TestOverlapCacheDegenerateAtForcedStride(t *testing.T) {
	pats := []string{`a*`, `b+`}
	for _, in := range []string{"", "a", "aaab"} {
		full := cacheFindScratchLen(in, pats)
		for _, k := range []int32{1, 3} {
			for _, off := range []int32{0, int32(len(in)), int32(len(in)) + 1} {
				walk := driveCacheFindK(t, pats, in, off, int32(len(pats)), false, full, engageAny, k)
				cached := driveCacheFindK(t, pats, in, off, int32(len(pats)), true, full, engageAny, k)
				if len(walk) != len(cached) {
					t.Fatalf("%q k=%d off=%d: walk %d, cache %d", in, k, off, len(walk), len(cached))
				}
				for i := range walk {
					if walk[i] != cached[i] {
						t.Fatalf("%q k=%d off=%d tuple %d: walk %v, cache %v", in, k, off, i, walk[i], cached[i])
					}
				}
			}
		}
	}
}
