package fuzz

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// The answer cache is COMMON code, called from `find` as well as from the
// batching entry. These tests drive `find` — the ONE-position-per-call export —
// and none of the sets below declares `hints: [batch-find]`, which is the
// second half of the same decision: the sweep is emitted for any overlapping
// set whose shape qualifies, because requiring the hint would mean requiring a
// second entry point nobody asked for in order to make the first one linear.
//
// What is checked here and nowhere else:
//
//   - `find` engages the cache on a quadratic drive and declines on a cheap
//     one, with the SAME adaptive rule the batching entry uses. `ready` is read
//     out of the caller's scratch, so a drive that quietly fell back to the
//     walk cannot pass by being merely correct.
//   - The cache path obeys `find`'s protocol, not the batch entry's. That is
//     precisely where forwarding `find` into `find_batch` would have lost
//     matches: `find` returns the position's TOTAL and writes nothing when it
//     does not fit, so the documented "grow the buffer and retry from the same
//     position" has to keep working when the answer comes from the cache.
//   - The run served is ONE position: every tuple of a call shares a start.

// driveCacheFind runs a whole `find` drive from `offset`, returning every
// tuple. useCache decides whether the descriptor offers a cache at all, so the
// same drive can be compared against the walk it replaces.
//
// wantEngage is asserted at the END of the drive against the header's `ready`
// slot, for the reason the batching test states: a correct answer is no
// evidence about which engine produced it.
func driveCacheFind(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen int32, want engageWant,
) [][3]int {
	return driveCacheFindK(t, pats, input, offset, outCap, useCache, scratchLen, want, 0)
}

// driveCacheFindK is driveCacheFind with the cache's STRIDE forced.
//
// The stride is the caller's to choose — `init` computes it from the same
// formula that sized the allocation — so forcing it needs no compiler knob, and
// that is what makes the block-boundary paths reachable. At the size the
// formula picks, a short test input is ONE block and every boundary case is
// unreachable; at a stride of 1 or 7 the same input has dozens.
// cacheDriveOpt steers a cache drive past what the plain arguments reach, and
// reports what the region looked like when it finished.
//
// The work PRE-ARM exists because the adaptive trigger cannot be reached any
// other way for the degenerate spans: `work > len * costPerByte` needs a drive
// that has genuinely delivered that many matched bytes, and an input of one or
// two positions never will. Writing the counter's own saturation value into
// the header is what a drive that had spent everything would have left there.
type cacheDriveOpt struct {
	stride *int32 // nil: the formula's own. A pointer, so that 0 and a
	// negative — the two MALFORMED strides — are expressible: they are the
	// whole of what the header-validation tests drive, and an int32 field
	// cannot tell "force zero" from "unset".
	preArmWork  bool  // make the FIRST call sweep, whatever it costs
	canaryBytes int32 // bytes of 0xA5 to lay down immediately BELOW the region
	canaryAfter int32 // and immediately ABOVE it

	// Filled in by the drive.
	lastResult int32 // the raw return of the LAST call, negative codes included
	region     int32
	header     []uint32
	cum        []uint32
	canaryBad  int
}

func driveCacheFindK(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen int32, want engageWant, strideOverride int32,
) [][3]int {
	t.Helper()
	k := strideOverride
	opt := &cacheDriveOpt{}
	if k > 0 {
		opt.stride = &k
	}
	return driveCacheFindOpt(t, pats, input, offset, outCap, useCache, scratchLen, want, opt)
}

func driveCacheFindOpt(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen int32, want engageWant, opt *cacheDriveOpt,
) [][3]int {
	t.Helper()
	if opt == nil {
		opt = &cacheDriveOpt{}
	}
	strideOverride := opt.stride
	_, stride := overlapCacheFor(input, pats)
	if strideOverride != nil {
		stride = *strideOverride
	}
	d := newCacheDrive(t, pats, input, cacheLayout{
		scratchLen: scratchLen, offer: useCache, stride: stride, preArmWork: opt.preArmWork,
		canaryBelow: opt.canaryBytes, canaryAbove: opt.canaryAfter,
	})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, descPtr := d.inBase, d.outPtr, d.scratchPtr, d.desc
	opt.region = scratchPtr
	buf := d.buf()

	var out [][3]int
	from := offset
	for calls := 0; ; calls++ {
		if calls > 4*(len(input)+2)*len(pats)+16 {
			t.Fatalf("drive did not terminate over %d bytes (cap %d)", len(input), outCap)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), from, descPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find: %v", err)
		}
		n := res.(int32)
		opt.lastResult = n
		if n <= 0 {
			break
		}
		// `find`'s transactional rule: a position that does not fit writes
		// nothing and reports its total. Grow and retry from the SAME `from`.
		callCap := outCap
		if n > outCap {
			callCap = int32(len(pats))
			res, err = fn.Call(store, inBase, int32(len(input)), from, descPtr, outPtr, callCap)
			if err != nil {
				t.Fatalf("set_find retry: %v", err)
			}
			if got := res.(int32); got != n {
				t.Fatalf("retry at the same position reported %d tuples, the probe said %d", got, n)
			}
		}
		if n > callCap {
			t.Fatalf("a position reported %d tuples for a %d-pattern set", n, len(pats))
		}
		buf = mem.UnsafeData(store)
		start := int32(-1)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			st := int32(readU32(buf, base+4))
			if i == 0 {
				start = st
			} else if st != start {
				t.Fatalf("tuples of one call disagree on start: %d vs %d", start, st)
			}
			out = append(out, [3]int{
				int(int32(readU32(buf, base))),
				int(st),
				int(int32(readU32(buf, base+8))),
			})
		}
		from = start + 1
	}

	buf = mem.UnsafeData(store)
	ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset))
	switch want {
	case engageAlways:
		if ready != 1 {
			t.Fatalf("cache was never engaged (ready=%d): this drive tested the walk, not the sweep", ready)
		}
	case engageNever:
		if ready == 1 {
			t.Fatal("cache engaged on a drive the walk handles cheaply: " +
				"sweeping here is the regression an earlier attempt was reverted for")
		}
	}
	for i := int32(0); i < opt.canaryBytes; i++ {
		if buf[scratchPtr-opt.canaryBytes+i] != 0xA5 {
			opt.canaryBad++
		}
	}
	for i := int32(0); i < opt.canaryAfter; i++ {
		if buf[scratchPtr+scratchLen+i] != 0xA5 {
			opt.canaryBad++
		}
	}
	if useCache {
		opt.header = make([]uint32, config.SetOverlapCheckpointHeaderBytes/4)
		for i := range opt.header {
			opt.header[i] = readU32(buf, int(scratchPtr)+4*i)
		}
		// cum[0..nb]: the block counts, prefix-summed, which is where a block's
		// tuple total is read from now that the header carries no count.
		nb := int32(opt.header[overlapHdrNumBlocksWord])
		// cum[] follows the header and nb checkpoint columns. The header does
		// not store where; every reader derives it from nb. Only a pass writes
		// nb, and only an eligible set has one, so the shape is looked up
		// only then — a drive over a set that declines has no column to size.
		if nb > 0 && nb < 1<<20 {
			cntOff := int32(config.SetOverlapCheckpointHeaderBytes) + nb*int32(overlapShapeOf(t, pats).Cells*4)
			if cntOff > 0 && cntOff+(nb+1)*4 <= scratchLen {
				opt.cum = make([]uint32, nb+1)
				for i := range opt.cum {
					opt.cum[i] = readU32(buf, int(scratchPtr+cntOff)+4*i)
				}
			}
		}
	}
	return out
}

// Header word indices the harness reads. compile/ keeps the constants
// unexported, and a drive that could not see `ready` was how three tests came
// to assert the walk against itself.
const (
	overlapHdrNumBlocksWord = 6 // byte 24
	overlapHdrStrideWord    = config.SetOverlapHdrStrideOff / 4
	overlapHdrFloorWord     = 5  // byte 20
	overlapHdrRowBaseWord   = 10 // byte 40
)

func cacheFindScratchLen(input string, pats []string) int32 {
	n, _ := overlapCacheFor(input, pats)
	return n
}

// TestOverlapCacheFindEngagesOnQuadraticDrives is the reason the refactor
// happened: before it, `find` was handed a cache in its descriptor and ignored
// it, so an overlapping drive through the one-position-per-call export stayed
// quadratic no matter what the caller offered.
//
// Both halves are asserted — the cache's answer against the walk's, and that
// the switch actually happened — and the drive crosses the seam mid-flight, so
// the walk-delivered prefix and the cache-served tail have to meet in
// ascending order with nothing dropped or repeated.
func TestOverlapCacheFindEngagesOnQuadraticDrives(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, offset := range []int32{0, 7} {
			t.Run(fmt.Sprintf("%s/off%d", shape.name, offset), func(t *testing.T) {
				outCap := int32(len(shape.pats))
				scratch := cacheFindScratchLen(shape.input, shape.pats)
				withCache := driveCacheFind(t, shape.pats, shape.input, offset, outCap, true, scratch, engageAlways)
				withoutCache := driveCacheFind(t, shape.pats, shape.input, offset, outCap, false, scratch, engageAny)
				if a, b := canonCache(withCache), canonCache(withoutCache); fmt.Sprint(a) != fmt.Sprint(b) {
					t.Fatalf("cache and walk disagree (%d vs %d tuples)", len(a), len(b))
				}
				if len(withCache) == 0 {
					t.Fatal("no matches at all: this shape cannot exercise the switch")
				}
				// Cache and walk agreeing is not agreeing with the contract: both
				// could share a bug. Go is the third opinion.
				if want := overlapSuffixOracle(t, shape.pats, shape.input, int(offset)); fmt.Sprint(canonCache(withCache)) != fmt.Sprint(want) {
					t.Fatalf("the cache disagrees with Go: %d tuples vs %d", len(withCache), len(want))
				}
				assertAscending(t, withCache)
			})
		}
	}
}

// TestOverlapCacheFindMatchesGoAndDeclines is the cheap-drive half. The walk
// finishes these for far less than a sweep would cost, so `find` must decline
// to sweep and still agree with Go.
func TestOverlapCacheFindMatchesGoAndDeclines(t *testing.T) {
	for si, tc := range overlapCacheSets {
		pats := tc.pats
		for _, input := range overlapCacheInputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				scratch := cacheFindScratchLen(input, pats)
				got := canonCache(driveCacheFind(t, pats, input, 0, int32(len(pats)), true, scratch, engageNever))
				want := overlapCacheOracle(pats, input)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("cache path over %q:\n  got  %v\n  want %v", input, got, want)
				}
			})
		}
	}
}

// TestOverlapCacheFindHonoursTheTransactionalRule drives the cache path at
// capacity 1 on a set whose positions carry SEVERAL tuples.
//
// This is the failure that forwarding `find` into `find_batch` would have
// produced, and it is silent: the batch entry returns what it WROTE, so a
// caller applying `find`'s rule — a return greater than out_cap means grow and
// retry — would read the truncated count as complete and lose the rest of the
// position. Here the undersized call must report the total and write NOTHING,
// and the retry must produce the whole run.
func TestOverlapCacheFindHonoursTheTransactionalRule(t *testing.T) {
	pats := []string{`a+`, `a*`, `[ab]+`}
	input := strings.Repeat("ab", 2000)
	scratch := cacheFindScratchLen(input, pats)
	// The drive helper performs the grow-and-retry itself, so a body that
	// truncated instead of refusing shows up as a mismatch against the walk.
	got := canonCache(driveCacheFind(t, pats, input, 0, 1, true, scratch, engageAlways))
	want := canonCache(driveCacheFind(t, pats, input, 0, int32(len(pats)), false, scratch, engageAny))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("capacity-1 cache drive lost matches: %d tuples vs %d", len(got), len(want))
	}
}

// An armed drive asked for a position PAST the end answers 0 — "nothing found"
// — whatever the position, not only len+1.
//
// The pass's past-the-end arm stored `floor = from` unclamped while serving
// validates `floor <= len + 1`, so from = len+2 swept, published ready = 1, and
// the same call then reported its own header as malformed.
func TestOverlapCacheArmedPastTheEnd(t *testing.T) {
	pats := []string{`a*`, `b+`}
	input := "aaab"
	full, stride := overlapCacheFor(input, pats)
	for _, from := range []int32{int32(len(input)) + 1, int32(len(input)) + 2,
		int32(len(input)) + 100, 0x7FFFFFF0} {
		opt := &cacheDriveOpt{stride: &stride, preArmWork: true}
		got := driveCacheFindOpt(t, pats, input, from, int32(len(pats)), true, full, engageAlways, opt)
		if len(got) != 0 || opt.lastResult != 0 {
			t.Errorf("from=%d: %d tuples, last return %d; want none and 0",
				from, len(got), opt.lastResult)
		}
	}
}

// overlapSuffixOracle is overlapCacheOracle for inputs past a thousand bytes,
// from position `from` on. The whole-input probe cannot reach them: Go's regexp
// refuses a repeat count over 1000, and `\A(?s:.{start})` needs one per start.
// An anchored match on the suffix is the same answer ONLY for a pattern that
// never looks LEFT of where it starts — right context such as `$` still sees the
// real end — so a pattern with a line or text start, or a word boundary, is
// refused rather than answered wrongly.
func overlapSuffixOracle(t *testing.T, pats []string, input string, from int) [][3]int {
	t.Helper()
	var res []*regexp.Regexp
	for _, p := range pats {
		if looksLeft(t, p) {
			t.Fatalf("pattern %q has left context; a suffix match cannot stand in for it", p)
		}
		res = append(res, regexp.MustCompile(`^(?:`+p+`)`))
	}
	var out [][3]int
	for start := from; start <= len(input); start++ {
		for k, re := range res {
			if loc := re.FindStringIndex(input[start:]); loc != nil {
				out = append(out, [3]int{k, start, start + loc[1]})
			}
		}
	}
	return canonCache(out)
}

// looksLeft reports whether a pattern can assert anything about the bytes BEFORE
// its start: a line or text start, or a word boundary. It walks the parse tree,
// because a `^` inside a negated class is not an anchor.
func looksLeft(t *testing.T, pat string) bool {
	t.Helper()
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", pat, err)
	}
	var walk func(*syntax.Regexp) bool
	walk = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpBeginLine, syntax.OpBeginText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			return true
		}
		for _, sub := range r.Sub {
			if walk(sub) {
				return true
			}
		}
		return false
	}
	return walk(re)
}
