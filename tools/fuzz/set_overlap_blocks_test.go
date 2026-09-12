package fuzz

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
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
					// Sized for THIS stride, not the formula's. At k = 1 the
					// checkpoint array is one column per position — for these
					// inputs three times the single-block region — so a region
					// sized the other way was refused, the drive walked, and
					// the test compared the walk with itself at every stride
					// below 5.
					full := overlapCacheForK(shape.input, shape.pats, k)
					walk := canonByPosition(driveCacheFindK(t, shape.pats, shape.input, off,
						int32(len(shape.pats)), false, full, engageNever, k))
					cached := canonByPosition(driveCacheFindK(t, shape.pats, shape.input, off,
						int32(len(shape.pats)), true, full, engageAlways, k))
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
	// The leading run is what CROSSES THE TRIGGER, and it has to be long
	// enough to: `engageAlways` asserts engagement, it cannot force it, and the
	// rule is `work > len * numWASM * P` where work is the delivered match
	// bytes. With this shape (numWASM 9, P 2) a 300-byte run delivers 45,150
	// against a threshold of 99,000 and the sweep never runs — which is how the
	// earlier version of this test drove the walk at every stride and compared
	// it with itself. 500 delivers 125,250 and crosses inside the run, so the
	// span the sweep then covers contains the empty middle.
	const lead, tail = 500, 200
	input := strings.Repeat("a", lead) + strings.Repeat(".", 5000) + strings.Repeat("a", tail)
	work := lead*(lead+1)/2 + tail*(tail+1)/2
	if threshold := len(input) * 9 * len(pats); work <= threshold {
		t.Fatalf("this shape can no longer cross the trigger: %d delivered bytes against a "+
			"threshold of %d — lengthen the leading run", work, threshold)
	}
	for _, k := range []int32{1, 5, 32} {
		full := overlapCacheForK(input, pats, k)
		walk := canonByPosition(driveCacheFindK(t, pats, input, 0, int32(len(pats)), false, full, engageNever, k))
		opt := &cacheDriveOpt{stride: &k}
		cached := canonByPosition(driveCacheFindOpt(t, pats, input, 0, int32(len(pats)), true, full, engageAlways, opt))
		if len(walk) != len(cached) {
			t.Fatalf("k=%d: walk %d tuples, cache %d", k, len(walk), len(cached))
		}
		for i := range walk {
			if walk[i] != cached[i] {
				t.Fatalf("k=%d tuple %d: walk %v, cache %v", k, i, walk[i], cached[i])
			}
		}
		// The point of the test: an INTERIOR block with no tuples in it, which
		// is what the skip-on-cumulative-count path exists to pass over without
		// materialising. cum[] is the prefix sum, so an empty block j is
		// cum[j+1] == cum[j].
		if len(opt.cum) < 3 {
			t.Fatalf("k=%d: the span is %d block(s); this test needs several", k, len(opt.cum)-1)
		}
		empty := 0
		for j := 0; j+1 < len(opt.cum); j++ {
			if opt.cum[j+1] == opt.cum[j] {
				empty++
			}
		}
		if empty == 0 {
			t.Fatalf("k=%d: no block in the swept span is empty, so the skip path never ran", k)
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
		for _, k := range []int32{1, 3} {
			full := overlapCacheForK(in, pats, k)
			for _, off := range []int32{0, int32(len(in)), int32(len(in)) + 1} {
				// WORK IS PRE-ARMED, and without it these inputs test the
				// walk. They are a few bytes long, so the drive cannot deliver
				// enough matched bytes to cross the trigger — every one of
				// these cases ran with ready == 0, and the degenerate spans the
				// test is named for (from == len, from == len + 1) were never
				// swept at all.
				walk := canonByPosition(driveCacheFindK(t, pats, in, off, int32(len(pats)), false, full, engageNever, k))
				opt := &cacheDriveOpt{stride: &k, preArmWork: true}
				cached := canonByPosition(driveCacheFindOpt(t, pats, in, off, int32(len(pats)), true, full, engageAlways, opt))
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

// classChain32 is setperf's classchain-32 family: 32 patterns over one merged
// automaton, and the widest sweep column any fixture here has.
//
// It is the shape the layout arithmetic's 32-bit edges are reachable with,
// which is why the same patterns appear in two tests below.
func classChain32() []string {
	out := make([]string, 32)
	for i := range out {
		out[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i/16, 1+i%16)
	}
	return out
}

// oracleFrom is the overlapping contract restricted to starts at or after
// `from`, which is what a drive resuming there is owed.
func oracleFrom(pats []string, input string, from int) [][3]int {
	var out [][3]int
	for _, m := range overlapCacheOracle(pats, input) {
		if m[1] >= from {
			out = append(out, m)
		}
	}
	return out
}

// A sweep whose span is a SINGLE POSITION, which is what a drive that crosses
// the trigger on the last position of the input asks for.
//
// The checkpoint indices are 1-based — checkpoint j lives at (j-1)*cellBytes —
// because block 0's lower boundary is the floor and nothing re-sweeps from it.
// At nb == 1 the pre-loop bookkeeping ran with block index 0, so the column was
// copied BELOW the region: over the header for a narrow column, and a page and
// a half below `cache_ptr` for a wide one, which in embedded mode is the host's
// own heap. The block was then also "closed", which decremented the index to -1
// and wrote the count over the last checkpoint cell while resetting the counter
// the drive publishes.
//
// Nothing reached it before: the degenerate-input test never engaged the sweep
// at all (its inputs are far too cheap to cross the trigger), so the whole
// m == 1 path was unexecuted.
func TestOverlapCacheSweepAtEndOfInput(t *testing.T) {
	narrow := []string{`a*`, `b+`}
	for _, in := range []string{"", "aaab"} {
		t.Run("narrow/"+in, func(t *testing.T) {
			full := cacheFindScratchLen(in, narrow)
			opt := &cacheDriveOpt{preArmWork: true, canaryBytes: 16 << 10}
			got := driveCacheFindOpt(t, narrow, in, int32(len(in)), int32(len(narrow)),
				true, full, engageAlways, opt)
			want := oracleFrom(narrow, in, len(in))
			if a, b := fmt.Sprint(canonCache(got)), fmt.Sprint(canonCache(want)); a != b {
				t.Fatalf("from==len: got %s, want %s", a, b)
			}
			// `a*` matches the empty string at EOF, so the span holds exactly
			// one tuple — and with nb == 1 the drive's total IS block 0's.
			if opt.cum == nil || len(opt.cum) != 2 {
				t.Fatalf("cum[] not published (%v); header %v", opt.cum, opt.header)
			}
			if n := opt.cum[1] - opt.cum[0]; n != 1 {
				t.Fatalf("block 0 holds %d tuples, want 1 (the empty match at EOF)", n)
			}
			if opt.canaryBad != 0 {
				t.Fatalf("%d bytes below the region were overwritten", opt.canaryBad)
			}
		})
	}

	// A WIDE column, where the same underflow lands outside the region
	// entirely rather than merely over the header.
	wide := classChain32()
	in := "ab12cd34"
	t.Run("wide", func(t *testing.T) {
		full := cacheFindScratchLen(in, wide)
		opt := &cacheDriveOpt{preArmWork: true, canaryBytes: 16 << 10}
		got := driveCacheFindOpt(t, wide, in, int32(len(in)), int32(len(wide)),
			true, full, engageAlways, opt)
		want := oracleFrom(wide, in, len(in))
		if a, b := fmt.Sprint(canonCache(got)), fmt.Sprint(canonCache(want)); a != b {
			t.Fatalf("from==len: got %s, want %s", a, b)
		}
		if opt.canaryBad != 0 {
			t.Fatalf("%d bytes below the region were overwritten", opt.canaryBad)
		}
	})
}

// The region-fits check has to be done in 64 bits, because the quantities it
// compares pass 2^31 on inputs that are otherwise perfectly legal.
//
// At a stride of 1 the checkpoint array is one column per position, so
// nb*cellBytes is (len+1) * cells * 4 — 2.27e9 for classchain-32 at 1.6 MB.
// In i32 that product wraps NEGATIVE, a signed "does it fit" test reads the
// negative as "yes", and every checkpoint then lands at a wrapped address
// somewhere else in the caller's memory.
//
// TWO constraints have to hold at once for this to test anything, and both are
// asserted from the compiled shape rather than assumed, so a change to the
// automaton fails loudly instead of quietly testing the walk:
//
//   - len*cells*4 must exceed 2^31, or the layout does not wrap;
//   - len*numWASM*P must stay below 2^31, or the work counter — an i32 that
//     saturates at 0x7FFFFFFF — can never exceed the trigger's threshold and
//     the sweep is never even attempted.
func TestOverlapCacheRefusesWrappedLayout(t *testing.T) {
	pats := classChain32()
	sh := overlapShapeOf(t, pats)
	const inputLen = 1600000
	unit := "the quick brown fox " // no digit follows a letter run: nothing matches
	input := strings.Repeat(unit, inputLen/len(unit)+1)[:inputLen]

	layout := int64(len(input)+1) * int64(sh.Cells*4+4)
	if layout <= 1<<31 {
		t.Fatalf("the layout does not wrap: (len+1)*cellBytes = %d, need > %d "+
			"(cells=%d — raise the input length)", layout, int64(1)<<31, sh.Cells)
	}
	one := int32(1)
	opt := &cacheDriveOpt{stride: &one, preArmWork: true, canaryAfter: 64 << 10}
	got := driveCacheFindOpt(t, pats, input, 0, int32(len(pats)),
		// engageNever, not engageAny: the sweep must NOT come back having
		// succeeded. Which of the two non-success outcomes it was — never
		// asked, or asked and refused — is asserted from `ready` below, and
		// the difference is the whole test.
		true, 1<<20, engageNever, opt)
	if len(got) != 0 {
		t.Fatalf("the corpus matches nothing, but the drive returned %d tuples", len(got))
	}
	// The second constraint is read off the RESULT rather than recomputed: the
	// work counter saturates at 0x7FFFFFFF, so if len*numWASM*P ever passes
	// that the pre-armed counter cannot cross the threshold and the sweep is
	// never attempted at all. `ready` tells the two apart — 0 is "never
	// asked", -1 is "asked and refused" — so a shape that drifts out of range
	// fails here with its own message instead of quietly testing the walk.
	ready := int32(opt.header[2])
	if ready == 0 {
		t.Fatal("the sweep was never attempted: the pre-armed work counter no longer " +
			"exceeds len*numWASM*P for this shape — lower the input length")
	}
	if ready != -1 {
		t.Fatalf("ready=%d, want -1: a region this much too small must be REFUSED, "+
			"and before the i64 rewrite the wrapped comparison accepted it", ready)
	}
	if opt.canaryBad != 0 {
		t.Fatalf("%d bytes above the region were overwritten", opt.canaryBad)
	}
}

// overlapShapeOf is what a stub generator learns about a set: the sweep
// column's width and the bucket's pattern count.
func overlapShapeOf(t *testing.T, pats []string) compile.OverlapCacheShape {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sc := config.SetConfig{
		Name: "s", Find: "set_find",
		Patterns: config.PatternSelector{All: true}, Overlapping: true,
	}
	sh, err := compile.SetOverlapCacheShape(sc, config.BuildConfig{
		Regexps: entries, Sets: []config.SetConfig{sc},
	})
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	if !sh.Eligible {
		t.Fatal("the set is not cache-eligible, so this test would drive the walk")
	}
	return sh
}

// canonByPosition sorts the tuples of each POSITION by pattern id and leaves
// the positions in the order they were delivered.
//
// docs/sets.md says the order of matches within one position is unspecified,
// and the cache's is genuinely different from the walk's — it reads a row's
// mask from bit 0 up, where the walk reports in bucket order. The order ACROSS
// positions is a real contract, so it is not sorted away: canonCache, which
// sorts everything by id first, would hide a drive that delivered position 9
// before position 3.
func canonByPosition(in [][3]int) [][3]int {
	out := append([][3]int(nil), in...)
	for i := 0; i < len(out); {
		j := i
		for j < len(out) && out[j][1] == out[i][1] {
			j++
		}
		run := out[i:j]
		sort.Slice(run, func(a, b int) bool {
			if run[a][0] != run[b][0] {
				return run[a][0] < run[b][0]
			}
			return run[a][2] < run[b][2]
		})
		i = j
	}
	return out
}

// The BATCH entry across block boundaries, at capacity ONE.
//
// `find` and `find_batch` share the cache and share nothing else about serving
// it: `find` answers one position's total, the batch entry fills a buffer and
// resumes through a cursor. All three of the batch entry's own boundary
// hazards live here and nowhere else — the resume offset at a block's FIRST
// row (which an `r <= 0` test wiped, so a capacity-1 drive re-delivered the
// same tuple for ever), the ordinal-versus-delivered counters, and telling
// "the drive is finished" from "the buffer is full" when a block runs out.
//
// At capacity 1 every multi-match position splits across calls, which is what
// makes the resume path the thing under test rather than an edge of it.
func TestOverlapCacheBatchAtForcedStrides(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, k := range []int32{1, 3, 7} {
			t.Run(fmt.Sprintf("%s/k%d", shape.name, k), func(t *testing.T) {
				full := overlapCacheForK(shape.input, shape.pats, k)
				stride := k
				want := canonByPosition(driveOverlapCacheStride(t, shape.pats, shape.input, 0,
					int32(len(shape.pats)), false, full, engageNever, &stride))
				got := canonByPosition(driveOverlapCacheStride(t, shape.pats, shape.input, 0,
					1, true, full, engageAlways, &stride))
				if len(want) != len(got) {
					t.Fatalf("walk %d tuples, cache at capacity 1 %d", len(want), len(got))
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("tuple %d: walk %v, cache %v", i, want[i], got[i])
					}
				}
			})
		}
	}
}

// A region ONE BYTE under what the sweep needs is refused, and the drive walks.
//
// The minimum is not the layout for the whole input: the sweep runs over
// [from, len] and engages only once the walk has proven expensive, so what it
// needs is the layout for the span it is actually handed. That span is read
// back out of the header — `floor` is the `from` the pass used — and the region
// is then sized one byte under it.
//
// The tests this replaces used 32 bytes, which is smaller than the header and
// so was refused before any layout was computed at all.
func TestOverlapCacheRefusesOneByteUnderTheMinimum(t *testing.T) {
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input

	// First, an engaged drive, to learn where the sweep started and how many
	// blocks it made.
	full, k := overlapCacheFor(input, pats)
	opt := &cacheDriveOpt{}
	want := canonByPosition(driveCacheFindOpt(t, pats, input, 0, int32(len(pats)),
		true, full, engageAlways, opt))
	floor := int(opt.header[overlapHdrFloorWord])
	sh := overlapShapeOf(t, pats)

	// The layout for THAT span, one byte short.
	span := len(input) - floor
	minimum := config.SetOverlapCheckpointBytesForStride(span, sh.Cells, sh.Patterns, int(k))
	short := &cacheDriveOpt{}
	got := canonByPosition(driveCacheFindOpt(t, pats, input, 0, int32(len(pats)),
		true, int32(minimum-1), engageNever, short))
	if ready := int32(short.header[2]); ready != -1 {
		t.Fatalf("ready = %d for a region one byte under the minimum, want -1 (refused)", ready)
	}
	if len(want) != len(got) {
		t.Fatalf("the walk answered %d tuples, the engaged drive %d", len(got), len(want))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("tuple %d: engaged %v, walked %v", i, want[i], got[i])
		}
	}
	// And the minimum ITSELF is accepted, or the test above passes for the
	// wrong reason — any region would be "one byte too small".
	exact := &cacheDriveOpt{}
	driveCacheFindOpt(t, pats, input, 0, int32(len(pats)), true, int32(minimum), engageAlways, exact)
}
