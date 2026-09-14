package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"

	"github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// The batching overlapping `find` may sweep the
// input ONCE into a caller-owned tuple cache and then serve each call by
// copying from it — but only once the drive's own walk has cost more than the
// sweep would.
//
// This is the test stage B never had. Its sweep was checked only through the
// same WASM that implemented it, so a bug in the recurrence and a bug in the
// emission would have looked identical. Here the oracle is Go's own regexp,
// and the recurrence has ALREADY been checked separately in Go
// (compile/set_sweep_test.go), so a failure here points at the EMISSION.
//
// Four things are asserted that a correctness-only test would miss:
//
//   - The same drive run with and WITHOUT scratch must agree. The no-scratch
//     path is the ordinary walk, so this pins the cache against the engine it
//     is meant to replace, not only against Go.
//   - The cache must survive being resumed at every capacity, including 1,
//     because the whole point is that the answer is Theta(n) tuples and no
//     single call can hold it.
//   - Cheap drives must NOT engage. Sweeping when the walk is already fast is
//     precisely the regression stage B was reverted for, so "it did not
//     sweep" is an assertion here, not an absence of one.
//   - Expensive drives MUST engage, and must agree across the seam where the
//     walk hands over to the cache mid-drive.

// overlapCacheSets are shapes whose drives are CHEAP: the walk finishes them
// for far less than a sweep would cost, so the engine must decline to sweep.
//
// `engage` is therefore false for all of them, and asserted. A set whose
// patterns carry mandatory literals is refused earlier still — a literal
// bucket's DFA matches only what follows its literal, and the sweep has no
// frontend to find that literal with.
var overlapCacheSets = []struct {
	pats []string
}{
	{[]string{`a+`, `[^\n]*ERROR`, `x?y`}}, // greedy-3, on inputs too short to trigger
	{[]string{`a+`}},
	{[]string{`[^\n]*ERROR`}},
	{[]string{`a+`, `b+`}},
	{[]string{`abc`, `b`, `c`}},
	{[]string{`a*`}},
	{[]string{`[0-9]+`, `[a-z]+`}},
	{[]string{`a`, `aa`, `aaa`}},

	// Shapes the CORPUS found while the cache was still swept
	// unconditionally, kept so they cannot regress:
	//   - a pattern that matches empty AND longer beside one that matches only
	//     empty (this refuted the immediateAccept branch),
	//   - begin- and end-anchored patterns, whose start state differs at
	//     position 0 and whose empty-input case the sweep loop cannot reach.
	{[]string{`a*`, ``}},
	{[]string{`a*`, `a+`, ``, `b?`, `(?:)`, `a|`, `[ab]{0,2}`}},
	{[]string{
		`^(?:(?:.(?:c?)))`, `^(?:^(?:(?:.(?:c?)))$)`, `^(?:^(?:(?:.(?:c?))))`,
		`^(?:(?:(?:.(?:c?)))$)`, `^(?:(?:.|(?:c?)))`, `^(?:^(?:(?:.|(?:c?)))$)`,
		`^(?:^(?:(?:.|(?:c?))))`, `^(?:(?:(?:.|(?:c?)))$)`,
	}},
}

var overlapCacheInputs = []string{
	"",
	"a",
	"aaa",
	"abc",
	"aaa ERROR bbb",
	"ERROR",
	"xy xy xy",
	"123abc456",
	"bbbb",
	"the quick brown fox",
}

func TestOverlapCacheMatchesGo(t *testing.T) {
	for si, tc := range overlapCacheSets {
		pats := tc.pats
		for _, input := range overlapCacheInputs {
			for _, outCap := range []int32{1, 3, 256} {
				name := fmt.Sprintf("set%d/%q/cap%d", si, input, outCap)
				t.Run(name, func(t *testing.T) {
					want := overlapCacheOracle(pats, input)
					// engage=cheap: these drives must DECLINE to sweep.
					withCache := driveOverlapCacheEngage(t, pats, input, 0, outCap, true, engageNever)
					withoutCache := driveOverlapCache(t, pats, input, outCap, false)

					if got := canonCache(withCache); fmt.Sprint(got) != fmt.Sprint(want) {
						t.Fatalf("cache path over %q:\n  got  %v\n  want %v", input, got, want)
					}
					// The walk is the engine the cache replaces; if they ever
					// disagree, one of them is wrong regardless of what Go says.
					if a, b := canonCache(withCache), canonCache(withoutCache); fmt.Sprint(a) != fmt.Sprint(b) {
						t.Fatalf("cache and walk disagree over %q:\n  cache %v\n  walk  %v", input, a, b)
					}
				})
			}
		}
	}
}

// quadraticShapes are drives the walk CANNOT finish cheaply: a pattern whose
// automaton never dies, over an input long enough that walking from every
// start is quadratic. These are the drives stage C exists for, and the ones
// that must engage.
//
// 4000 bytes is chosen to be comfortably past the trigger (which is
// numStates x patterns per input byte) while keeping the test fast.
func quadraticShapes() []struct {
	name  string
	pats  []string
	input string
} {
	return []struct {
		name  string
		pats  []string
		input string
	}{
		{"all-a", []string{`a+`, `[^\n]*ERROR`, `x?y`}, strings.Repeat("a", 4000)},
		{"late-error", []string{`a+`, `[^\n]*ERROR`, `x?y`},
			strings.Repeat("the quick brown fox ", 200) + "ERROR"},

		// Long runs that END, so every answer comes from the recurrence's
		// MID-ACCEPT arm — the walk dies on the 'b' and the last accept seen
		// is the answer — rather than from the recursion reaching EOF.
		//
		// Added because mutation testing caught the gap: breaking that arm
		// changed nothing while the only engaging drives were ones whose
		// matches all ran to the end of the input.
		{"runs", []string{`a+`}, strings.Repeat(strings.Repeat("a", 500)+"b", 8)},
		{"runs-mixed", []string{`a+`, `b+`, `[ab]+`},
			strings.Repeat(strings.Repeat("a", 200)+strings.Repeat("b", 60), 12)},
	}
}

// TestOverlapCacheEngagesOnQuadraticDrives is the other half of the
// engagement rule. The drives here MUST sweep, and their answers must be
// identical to the walk's across the seam where the switch happens
// mid-drive — the walk delivers a prefix, the cache serves the rest, and the
// two halves have to meet in ascending order with nothing dropped or repeated.
func TestOverlapCacheEngagesOnQuadraticDrives(t *testing.T) {
	for _, shape := range quadraticShapes() {
		for _, outCap := range []int32{1, 3, 256} {
			for _, offset := range []int32{0, 7} {
				name := fmt.Sprintf("%s/cap%d/off%d", shape.name, outCap, offset)
				t.Run(name, func(t *testing.T) {
					withCache := driveOverlapCacheEngage(t, shape.pats, shape.input, offset, outCap, true, engageAlways)
					withoutCache := driveOverlapCache2(t, shape.pats, shape.input, offset, outCap, false)
					if a, b := canonCache(withCache), canonCache(withoutCache); fmt.Sprint(a) != fmt.Sprint(b) {
						t.Fatalf("cache and walk disagree (%d vs %d tuples)", len(a), len(b))
					}
					if len(withCache) == 0 {
						t.Fatal("no matches at all: this shape cannot exercise the switch")
					}
					assertAscending(t, withCache)
				})
			}
		}
	}
}

// assertAscending checks the ACROSS-position contract: starts never go
// backwards over a drive. This is what a mid-drive switch could break, and no
// per-call check would catch it.
func assertAscending(t *testing.T, tuples [][3]int) {
	t.Helper()
	prev := -1
	for _, tuple := range tuples {
		if tuple[1] < prev {
			t.Fatalf("start went backwards: %d after %d", tuple[1], prev)
		}
		prev = tuple[1]
	}
}

// engageWant says what the drive must do about the sweep.
type engageWant int

const (
	engageAny engageWant = iota
	// engageNever: the walk is cheap here, so sweeping would be the stage-B
	// regression. Asserted, not merely allowed.
	engageNever
	// engageAlways: the walk is quadratic here, so the sweep must take over.
	engageAlways
)

// canonCache sorts by (start, id, end): docs/sets.md says the order of matches
// WITHIN one position is unspecified, so asserting it would test an
// implementation detail. The ACROSS-position order is a real contract and is
// checked by the drive loop itself.
func canonCache(in [][3]int) [][3]int {
	out := append([][3]int(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][2] < out[j][2]
	})
	return out
}

// overlapCacheOracle is `overlapping: true`'s contract stated directly: at
// every start position, every pattern that matches there, with its
// leftmost-first extent.
//
// The probe is the WHOLE-INPUT one, `\A(?s:.{start})(?:pat)`, not the
// pattern against a slice. `^` is \A and can only match at absolute position
// 0, so a slice would let an anchored pattern match at every start and the
// oracle would be wrong in exactly the cases the anchored sets above exist to
// check.
func overlapCacheOracle(pats []string, input string) [][3]int {
	var out [][3]int
	for start := 0; start <= len(input); start++ {
		for k, p := range pats {
			re := regexp.MustCompile(fmt.Sprintf(`\A(?s:.{%d})(?:%s)`, start, p))
			if m := re.FindStringIndex(input); m != nil {
				out = append(out, [3]int{k, start, m[1]})
			}
		}
	}
	return canonCache(out)
}

func driveOverlapCache(t *testing.T, pats []string, input string, outCap int32, useCache bool) [][3]int {
	t.Helper()
	return driveOverlapCache2(t, pats, input, 0, outCap, useCache)
}

func driveOverlapCache2(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool) [][3]int {
	t.Helper()
	return driveOverlapCacheEngage(t, pats, input, offset, outCap, useCache, engageAny)
}

func driveOverlapCacheEngage(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool, want engageWant) [][3]int {
	t.Helper()
	// Generous scratch: one tuple per pattern per start, which is the worst
	// case the sweep can produce.
	scratchLen, _ := overlapCacheFor(input, pats)
	return driveOverlapCacheScratch(t, pats, input, offset, outCap, useCache, scratchLen, want)
}

func driveOverlapCacheScratch(t *testing.T, pats []string, input string, offset, outCap int32, useCache bool, scratchLen int32, want engageWant) [][3]int {
	t.Helper()
	return driveOverlapCacheStride(t, pats, input, offset, outCap, useCache, scratchLen, want, nil)
}

// driveOverlapCacheStride is the same drive with the header's STRIDE under the
// test's control: nil takes the formula's, a value forces that many positions
// per block. Forcing it is the only way to reach the multi-block paths on an
// input a test can afford — at the formula's stride a few kilobytes is one
// block, and one block never loads a checkpoint or crosses a boundary.
func driveOverlapCacheStride(t *testing.T, pats []string, input string, offset, outCap int32,
	useCache bool, scratchLen int32, want engageWant, strideOverride *int32,
) [][3]int {
	t.Helper()
	_, stride := overlapCacheFor(input, pats)
	if strideOverride != nil {
		stride = *strideOverride
	}
	d := newCacheDrive(t, pats, input, cacheLayout{batch: true, scratchLen: scratchLen, offer: useCache, stride: stride})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, descPtr := d.inBase, d.outPtr, d.scratchPtr, d.desc
	var buf []byte

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out [][3]int
	cursor := int64(offset) << 32
	for calls := 0; ; calls++ {
		if calls > 4*(len(input)+2)*len(pats)+16 {
			t.Fatalf("drive did not terminate over %q (cap %d)", input, outCap)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, descPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		ret := res.(int64)
		// Both reserved position words are read BEFORE the count: all three
		// high halves have the top bit set, and a -4 packed into the count
		// half would decode as a large positive number of tuples nobody wrote.
		if uint32(ret>>32) == config.SetCursorMalformedPos {
			t.Fatalf("find_batch reported a malformed answer-cache header; this test writes "+
				"that header (stride %d), so this is a bug in the harness", stride)
		}
		n := int32(ret & countMask)
		buf = mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, [3]int{
				int(int32(readU32(buf, base))),
				int(int32(readU32(buf, base+4))),
				int(int32(readU32(buf, base+8))),
			})
		}
		if uint32(ret>>32) == 0xFFFFFFFF {
			// The guard against a VACUOUS pass in BOTH directions. A drive
			// that quietly fell back to the walk still matches Go — the walk
			// is correct too — so "the answer was right" is no evidence about
			// which engine produced it. `ready` says which did: 1 swept, 0
			// never asked, -1 asked and was refused.
			ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset))
			switch want {
			case engageAlways:
				if ready != 1 {
					t.Fatalf("cache was never engaged (ready=%d): this drive tested the walk, not the sweep", ready)
				}
			case engageNever:
				if ready == 1 {
					t.Fatalf("cache engaged (ready=1) on a drive the walk handles cheaply: " +
						"sweeping here is the regression an earlier attempt was reverted for")
				}
			}
			return out
		}
		cursor = ret
	}
}

// overlapDPReadyOffset is the byte offset of the cache header's "ready" slot.
// Stated here rather than imported because compile/ keeps it unexported; the
// header width itself is config.SetOverlapCheckpointHeaderBytes, which the
// drive zeroes.
const overlapDPReadyOffset = config.SetOverlapHdrReadyOff

// A drive whose threshold is ABOVE what the work counter can hold still
// engages once the counter saturates.
//
// work is an i32 that saturates at 0x7FFFFFFF, and the trigger compares it with
// `len * 2 * cells` in i64. For classchain-32 any input past about 3 MB has a
// threshold the counter can never exceed, so the cache was offered, sized and
// reserved — and never engaged, leaving the drive quadratic with nothing to say
// so. A saturated counter now counts as over the line.
func TestOverlapCacheEngagesPastCounterSaturation(t *testing.T) {
	pats := classChain32()
	sh := overlapShapeOf(t, pats)
	inputLen := int(int64(0x7FFFFFFF)/int64(2*sh.Cells)) + 4096
	unit := "the quick brown fox " // no digit follows a letter run: nothing matches
	input := strings.Repeat(unit, inputLen/len(unit)+1)[:inputLen]
	if th := int64(len(input)) * int64(2*sh.Cells); th <= 0x7FFFFFFF {
		t.Fatalf("threshold %d is reachable by the counter: lengthen the input", th)
	}
	full, stride := overlapCacheFor(input, pats)
	if full <= int32(config.SetOverlapCheckpointHeaderBytes) {
		t.Fatalf("no region could be sized for a %d-byte input (%d bytes)", len(input), full)
	}
	opt := &cacheDriveOpt{stride: &stride, preArmWork: true}
	got := driveCacheFindOpt(t, pats, input, 0, int32(len(pats)), true, full, engageAlways, opt)
	if len(got) != 0 {
		t.Fatalf("the corpus matches nothing, but the drive returned %d tuples", len(got))
	}
}

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
	// rule is `work > len * 2 * cells` where work is the delivered match
	// bytes. With this shape (9 cells) a 300-byte run delivers 45,150
	// against a threshold of 99,000 and the sweep never runs — which is how the
	// earlier version of this test drove the walk at every stride and compared
	// it with itself. 500 delivers 125,250 and crosses inside the run, so the
	// span the sweep then covers contains the empty middle.
	const lead, tail = 500, 200
	input := strings.Repeat("a", lead) + strings.Repeat(".", 5000) + strings.Repeat("a", tail)
	work := lead*(lead+1)/2 + tail*(tail+1)/2
	if threshold := len(input) * 2 * overlapShapeOf(t, pats).Cells; work <= threshold {
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
	// `ready` tells "never asked" (0) from "asked and refused" (-1), and the
	// difference is the whole test. The pre-armed counter is SATURATED, which
	// the trigger treats as over the line whatever the threshold, so 0 here
	// means the trigger is broken rather than that the shape drifted.
	ready := int32(opt.header[2])
	if ready == 0 {
		t.Fatal("the sweep was never attempted, though the pre-armed work counter is " +
			"saturated and a saturated counter must trigger it")
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

// A cache header the caller got WRONG must be REPORTED, not degraded into a
// silent walk: a header the engine cannot parse is the CALLER's mistake, and
// it is reported rather than guessed at.
//
// The distinction this pins is the whole reason the sentinel exists. A region
// that is merely too small is a legitimate answer — the drive walks, the answer
// is identical, only slower — and a header whose stride is nonsense is a
// mistake. Both look the same from inside the sweep, and left alike the mistake
// is indistinguishable from the engine legitimately declining the shape, on
// exactly the never-dying inputs the cache exists for.
func TestOverlapCacheMalformedHeaderIsReported(t *testing.T) {
	// A shape the corpus already knows drives the trigger: the cache only
	// engages once the walk has proven expensive, and a header nobody looks at
	// reports nothing.
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, stride := overlapCacheFor(input, pats)

	// A stride of ZERO is what a caller who zeroed the header and forgot to
	// fill it in leaves behind, and it is the likeliest form of the mistake.
	if got := driveStride(t, pats, input, full, 0); got != abi.OverlapCacheMalformed {
		t.Fatalf("stride 0: find returned %d, want %d (the malformed-cache error)",
			got, abi.OverlapCacheMalformed)
	}

	// A NEGATIVE stride would index the region backwards.
	if got := driveStride(t, pats, input, full, -7); got != abi.OverlapCacheMalformed {
		t.Fatalf("stride -7: find returned %d, want %d", got, abi.OverlapCacheMalformed)
	}

	// A CORRECT header must not trip it — otherwise the test above passes for
	// the wrong reason and every drive is an error.
	if got := driveStride(t, pats, input, full, stride); got < 0 {
		t.Fatalf("a correct header returned %d; the drive should have answered normally", got)
	}
}

// driveStride runs a `find` drive with a caller-chosen stride and returns what
// the LAST call reported — which for a malformed header is the error itself.
//
// It used to be a whole second copy of the driver, because the shared one read
// a stride of 0 as "unset" and could not force one. The override is a pointer
// now, so the copy is gone.
func driveStride(t *testing.T, pats []string, input string, scratchLen, stride int32) int32 {
	t.Helper()
	opt := &cacheDriveOpt{stride: &stride}
	driveCacheFindOpt(t, pats, input, 0, int32(len(pats)), true, scratchLen, engageAny, opt)
	return opt.lastResult
}

// A header is caller memory, so it is re-checked on EVERY call, not only the
// one that swept.
//
// The pass validated what it was handed and published a layout; nothing looked
// at that layout again. A caller that zeroed the header mid-drive — or two
// scanners sharing one region by mistake — then reached `i32.div_u` by a zero
// stride, which TRAPS. A trap is not an answer: the ABI says a header the
// engine cannot parse is -4, and a trap takes the whole instance down.
func TestOverlapCacheLaterCallValidatesHeader(t *testing.T) {
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, stride := overlapCacheFor(input, pats)

	for _, tc := range []struct {
		name string
		word int32 // header byte offset to corrupt after the sweep
		val  uint32
	}{
		{"stride zeroed", 16, 0},
		{"numBlocks zeroed", 24, 0},
		{"floor past the input", 20, uint32(len(input)) + 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := driveCacheFindCorrupt(t, pats, input, full, stride, tc.word, tc.val)
			if got != abi.OverlapCacheMalformed {
				t.Fatalf("find returned %d after the header was corrupted, want %d",
					got, abi.OverlapCacheMalformed)
			}
		})
	}

	// And a region too small for even the header is a REFUSAL, not an error:
	// the drive walks and the answer is identical.
	if got := driveStride(t, pats, input, 40, stride); got < 0 {
		t.Fatalf("a 40-byte region returned %d; too small to hold the header is a "+
			"fallback to the walk, not an error", got)
	}
}

// `from` past the end of the input is "nothing found" by the ABI, and the arm
// that answers it still has to leave a LAYOUT behind — it publishes `ready`,
// and every later call validates the header it then reads. What it writes is
// the empty one-block layout a real single-position sweep would have produced.
func TestOverlapCachePastEndLeavesAValidLayout(t *testing.T) {
	pats := []string{`a*`, `b+`}
	input := "aaab"
	full, stride := overlapCacheFor(input, pats)
	opt := &cacheDriveOpt{stride: &stride, preArmWork: true}
	got := driveCacheFindOpt(t, pats, input, int32(len(input))+1, int32(len(pats)),
		true, full, engageAlways, opt)
	if len(got) != 0 {
		t.Fatalf("from past the end returned %d tuples, want none", len(got))
	}
	if got := opt.header[overlapHdrNumBlocksWord]; got != 1 {
		t.Fatalf("numBlocks = %d, want 1", got)
	}
	if opt.cum == nil || len(opt.cum) != 2 || opt.cum[0] != 0 || opt.cum[1] != 0 {
		t.Fatalf("cum[] = %v, want [0 0]", opt.cum)
	}
}

// The pass CLAMPS a stride wider than the span it is asked to sweep, and the
// clamped value has to go back to the header: serving divides by the header's
// copy to locate a block, so a pass that kept a different stride to itself
// would have the two disagree about where every block starts.
func TestOverlapCacheClampedStrideIsWrittenBack(t *testing.T) {
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, _ := overlapCacheFor(input, pats)
	// A stride far wider than anything the drive can still have left.
	wide := int32(len(input)) * 4
	opt := &cacheDriveOpt{stride: &wide, preArmWork: true}
	driveCacheFindOpt(t, pats, input, 0, int32(len(pats)), true, full, engageAlways, opt)
	k := opt.header[overlapHdrStrideWord]
	floor := opt.header[overlapHdrFloorWord]
	if want := uint32(len(input)) - floor + 1; k != want {
		t.Fatalf("header stride = %d after clamping, want %d (m = len - floor + 1)", k, want)
	}
}

// driveCacheFindCorrupt runs a drive until the sweep engages, writes `val` into
// the header at byte offset `word`, and returns what the NEXT call reports.
func driveCacheFindCorrupt(t *testing.T, pats []string, input string,
	scratchLen, stride, word int32, val uint32,
) int32 {
	t.Helper()
	d := newCacheDrive(t, pats, input, cacheLayout{scratchLen: scratchLen, offer: true, stride: stride})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, desc := d.inBase, d.outPtr, d.scratchPtr, d.desc
	buf := d.buf()

	from, corrupted := int32(0), false
	for calls := 0; calls < 4*(len(input)+2)*len(pats)+16; calls++ {
		res, err := fn.Call(store, inBase, int32(len(input)), from, desc, outPtr, int32(len(pats)))
		if err != nil {
			t.Fatalf("set_find: %v (a malformed header must be REPORTED, not trapped on)", err)
		}
		n := res.(int32)
		if n < 0 {
			return n
		}
		buf = mem.UnsafeData(store)
		if !corrupted && int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset)) == 1 {
			binary.LittleEndian.PutUint32(buf[scratchPtr+word:], val)
			corrupted = true
			continue // same `from`, now through a header that lies
		}
		if n == 0 {
			if !corrupted {
				t.Fatal("the drive finished without the sweep ever engaging")
			}
			t.Fatal("the corrupted header was accepted: the call answered 'no more matches'")
		}
		from = int32(readU32(buf, int(outPtr)+4)) + 1
	}
	t.Fatal("drive did not terminate")
	return 0
}

// The BATCH entry reports a malformed header too, and the report has to be
// DECODABLE.
//
// Two halves, and both were broken. The mid-flight sweep — the only sweep a
// pure `find_batch` drive can reach, since the entry sweep needs a cursor this
// entry never receives — treated every negative return as "the region is too
// small" and walked, so a nonsense stride was silently accepted. And when the
// error did come out, it was packed into the COUNT half, which every decoder
// masks to countBits: -4 read back as a large positive tuple count, and the
// JS generator then looped over that many tuples nobody wrote.
func TestOverlapCacheBatchReportsMalformedHeader(t *testing.T) {
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, stride := overlapCacheFor(input, pats)

	for _, tc := range []struct {
		name    string
		preArm  bool // pre-arm work: the ENTRY sweep fires on the first call
		stride  int32
		wantErr bool
	}{
		{"entry sweep, stride 0", true, 0, true},
		{"mid-flight sweep, stride 0", false, 0, true},
		{"mid-flight sweep, stride -7", false, -7, true},
		{"a correct header", false, stride, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pos, count := driveBatchMalformed(t, pats, input, full, tc.stride, tc.preArm)
			if !tc.wantErr {
				if pos == config.SetCursorMalformedPos {
					t.Fatal("a correct header was reported as malformed")
				}
				return
			}
			if pos != config.SetCursorMalformedPos {
				t.Fatalf("resume word = 0x%X, want 0x%X (the malformed sentinel); "+
					"a walk here is the silent degradation the sentinel exists to prevent",
					pos, uint32(config.SetCursorMalformedPos))
			}
			if count != 0 {
				t.Fatalf("the sentinel carried a count of %d; it must be zero, since "+
					"nothing was written", count)
			}
		})
	}
}

// driveBatchMalformed runs a batching drive until it stops and returns the last
// call's resume word and count.
func driveBatchMalformed(t *testing.T, pats []string, input string,
	scratchLen, stride int32, preArm bool,
) (uint32, int32) {
	t.Helper()
	d := newCacheDrive(t, pats, input, cacheLayout{
		batch: true, scratchLen: scratchLen, offer: true, stride: stride, preArmWork: preArm,
	})
	defer d.release()
	store, fn := d.store, d.fn
	inBase, outPtr, desc := d.inBase, d.outPtr, d.desc

	countMask := int64(config.SetCursorMaxCount(len(pats)))
	outCap := int32(len(pats))
	cursor := int64(0)
	for calls := 0; calls < 4*(len(input)+2)*len(pats)+16; calls++ {
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, desc, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		ret := res.(int64)
		pos, n := uint32(ret>>32), int32(ret&countMask)
		if pos == config.SetCursorMalformedPos || pos == 0xFFFFFFFF || n == 0 {
			return pos, n
		}
		cursor = ret
	}
	t.Fatal("drive did not terminate")
	return 0, 0
}

// A header whose block count is INFLATED, with every offset recomputed to
// agree with it, must be -4 — and must not write one byte outside the region.
//
// The validator checked each offset against numBlocks but never numBlocks
// against the span, so this header passed every check it made. Serving then
// located a block past the real last one, and that block's rebuild computed a
// row index below zero and wrote a row's mask and ends BELOW the block buffer —
// below the region itself, for a small block index.
func TestOverlapCacheRejectsInflatedBlockCount(t *testing.T) {
	pats := []string{`a*`, `b+`}
	input := strings.Repeat("a", 200)
	const stride = 200
	cellBytes := uint32(overlapShapeOf(t, pats).Cells * 4)
	hdrBytes := uint32(config.SetOverlapCheckpointHeaderBytes)
	// Room for a THREE-block layout plus slack, so the region-fits check is not
	// what catches the lie.
	scratchLen := overlapCacheForK(input, pats, stride) + int32(cellBytes) + 4 + 4096
	hook := func(r []byte) {
		le := binary.LittleEndian
		if nb := le.Uint32(r[overlapHdrNumBlocksWord*4:]); nb != 2 {
			t.Fatalf("a %d-position span at stride %d swept into %d blocks, want 2",
				len(input)+1, stride, nb)
		}
		const nb = 3
		cntOff := hdrBytes + nb*cellBytes
		le.PutUint32(r[overlapHdrNumBlocksWord*4:], nb)
		le.PutUint32(r[28:], 0) // no block materialised, so serving rebuilds
		for i := uint32(0); i <= nb; i++ {
			le.PutUint32(r[cntOff+4*i:], 0)
		}
		le.PutUint32(r[cntOff+4*nb:], 1) // cum[3] = 1: block 2 claims a tuple
	}
	got, canaryBad := driveCacheFindSequence(t, pats, input, scratchLen, stride, 4096, hook,
		[]int32{0, 400, 250})
	for i, n := range got {
		if n != abi.OverlapCacheMalformed {
			t.Errorf("call %d returned %d through an inflated numBlocks, want %d",
				i+1, n, abi.OverlapCacheMalformed)
		}
	}
	if canaryBad != 0 {
		t.Errorf("%d canary bytes below the region were overwritten", canaryBad)
	}
}

// driveCacheFindSequence engages the sweep on the FIRST call — work is
// pre-armed, so froms[0] sweeps whatever it costs — hands the region to hook,
// and returns what each later call in froms[1:] reports, negative codes
// included. canaryBad counts the bytes of the canary laid immediately below the
// region that no longer hold 0xA5.
func driveCacheFindSequence(t *testing.T, pats []string, input string,
	scratchLen, stride, canary int32, hook func(region []byte), froms []int32,
) (results []int32, canaryBad int) {
	t.Helper()
	// scratchLen == 0 offers NO region, which is the drive the best-effort
	// detection cannot see into.
	d := newCacheDrive(t, pats, input, cacheLayout{
		scratchLen: scratchLen, offer: scratchLen != 0, stride: stride, preArmWork: true, canaryBelow: canary,
	})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, desc := d.inBase, d.outPtr, d.scratchPtr, d.desc
	buf := d.buf()

	call := func(from int32) int32 {
		res, err := fn.Call(store, inBase, int32(len(input)), from, desc, outPtr, int32(len(pats)))
		if err != nil {
			t.Fatalf("set_find(from=%d): %v", from, err)
		}
		return res.(int32)
	}
	call(froms[0])
	if scratchLen != 0 {
		buf = mem.UnsafeData(store)
		if ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset)); ready != 1 {
			t.Fatalf("the first call did not engage the sweep (ready=%d)", ready)
		}
		hook(buf[scratchPtr : scratchPtr+scratchLen])
	}
	for _, from := range froms[1:] {
		results = append(results, call(from))
	}
	buf = mem.UnsafeData(store)
	for i := int32(0); i < canary; i++ {
		if buf[scratchPtr-canary+i] != 0xA5 {
			canaryBad++
		}
	}
	return results, canaryBad
}

// A `from` BELOW the floor of an ENGAGED cache is reported as out of order
// rather than served from the floor, which silently dropped every match in
// [from, floor).
//
// Detection is BEST EFFORT: it exists only while the cache is engaged, because
// only then is there a floor to compare with. Both halves are pinned — the
// report, and the absence of a false positive on a drive that offered no
// region at all.
func TestOverlapCacheRejectsBackwardsFrom(t *testing.T) {
	pats := []string{`a*`, `b+`}
	input := "aaab"
	full, stride := overlapCacheFor(input, pats)
	noHook := func([]byte) {}

	got, _ := driveCacheFindSequence(t, pats, input, full, stride, 0, noHook, []int32{2, 0, 2})
	if got[0] != abi.OverlapCacheOutOfOrder {
		t.Errorf("find(0) after the sweep engaged at 2 returned %d, want %d (out of order)",
			got[0], abi.OverlapCacheOutOfOrder)
	}
	if got[1] <= 0 {
		t.Errorf("find(2), EQUAL to the floor, returned %d; want that position's matches", got[1])
	}

	walk, _ := driveCacheFindSequence(t, pats, input, 0, stride, 0, noHook, []int32{2, 0})
	if walk[0] == abi.OverlapCacheOutOfOrder {
		t.Error("a drive offering no region reported out of order: the check needs an engaged cache")
	}
}

// The batch entry reports a backwards resume exactly as `find` reports a
// backwards `from`: the reserved position word, a zero count, and nothing
// written into the caller's buffer.
func TestOverlapCacheBatchRejectsBackwardsResume(t *testing.T) {
	pats := []string{`a*`, `b+`}
	input := "aaab"
	full, stride := overlapCacheFor(input, pats)
	countMask := int64(config.SetCursorMaxCount(len(pats)))

	res, touched := driveBatchSequence(t, pats, input, full, stride, []int64{2 << 32, 0, 2 << 32})
	if pos := uint32(res[0] >> 32); pos != config.SetCursorOutOfOrderPos {
		t.Errorf("resuming at 0 below a floor of 2: position word 0x%X, want 0x%X",
			pos, uint32(config.SetCursorOutOfOrderPos))
	}
	if n := res[0] & countMask; n != 0 {
		t.Errorf("the out-of-order cursor carried a count of %d; nothing was written", n)
	}
	if touched[0] {
		t.Error("the out-of-order call wrote into the caller's buffer")
	}
	if pos, n := uint32(res[1]>>32), res[1]&countMask; pos == config.SetCursorOutOfOrderPos || n == 0 {
		t.Errorf("resuming AT the floor answered position word 0x%X, count %d; want its matches", pos, n)
	}
}

// driveBatchSequence engages the sweep on the first batch call — work is
// pre-armed — and returns what each later cursor in cursors[1:] answers,
// with whether that call changed any byte of the caller's buffer.
func driveBatchSequence(t *testing.T, pats []string, input string,
	scratchLen, stride int32, cursors []int64,
) (results []int64, touched []bool) {
	t.Helper()
	d := newCacheDrive(t, pats, input, cacheLayout{
		batch: true, scratchLen: scratchLen, offer: true, stride: stride, preArmWork: true,
	})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, desc := d.inBase, d.outPtr, d.scratchPtr, d.desc
	buf := d.buf()

	outCap := int32(len(pats))
	span := int(outCap) * 12
	call := func(cursor int64) int64 {
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, desc, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch(cursor=0x%X): %v", cursor, err)
		}
		return res.(int64)
	}
	call(cursors[0])
	buf = mem.UnsafeData(store)
	if ready := int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset)); ready != 1 {
		t.Fatalf("the first call did not engage the sweep (ready=%d)", ready)
	}
	for _, c := range cursors[1:] {
		buf = mem.UnsafeData(store)
		for i := 0; i < span; i++ {
			buf[int(outPtr)+i] = 0xEE
		}
		results = append(results, call(c))
		buf = mem.UnsafeData(store)
		changed := false
		for i := 0; i < span; i++ {
			if buf[int(outPtr)+i] != 0xEE {
				changed = true
				break
			}
		}
		touched = append(touched, changed)
	}
	return results, touched
}

// driveCacheFindHooked runs a whole overlapping drive with the cache offered,
// calling hook ONCE when the sweep first publishes `ready`, and returns every
// tuple the drive reported — or the negative code that ended it.
func driveCacheFindHooked(t *testing.T, pats []string, input string,
	scratchLen, stride int32, hook func(buf []byte, scratchPtr int32),
) ([][3]int32, int32) {
	t.Helper()
	d := newCacheDrive(t, pats, input, cacheLayout{scratchLen: scratchLen, offer: true, stride: stride})
	defer d.release()
	store, mem, fn := d.store, d.mem, d.fn
	inBase, outPtr, scratchPtr, desc := d.inBase, d.outPtr, d.scratchPtr, d.desc
	buf := d.buf()

	var out [][3]int32
	from, hooked := int32(0), false
	for calls := 0; calls < 4*(len(input)+2)*len(pats)+16; calls++ {
		res, err := fn.Call(store, inBase, int32(len(input)), from, desc, outPtr, int32(len(pats)))
		if err != nil {
			t.Fatalf("set_find: %v", err)
		}
		n := res.(int32)
		if n <= 0 {
			if !hooked && hook != nil {
				t.Fatal("the drive finished without the sweep ever engaging")
			}
			return out, n
		}
		buf = mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, [3]int32{int32(readU32(buf, base)), int32(readU32(buf, base+4)), int32(readU32(buf, base+8))})
		}
		from = int32(readU32(buf, int(outPtr)+4)) + 1
		if !hooked && hook != nil && int32(readU32(buf, int(scratchPtr)+overlapDPReadyOffset)) == 1 {
			hook(buf, scratchPtr)
			hooked = true
		}
	}
	t.Fatal("drive did not terminate")
	return nil, 0
}

// TestOverlapCacheIgnoresReservedHeaderSlots: the checkpoint, count and block
// offsets are DERIVED from the block count by every reader, so their three
// header slots are reserved and unread. Garbage there must not change an answer
// or be reported as a malformed header — the validator checks what the engine
// actually reads, and nothing else.
func TestOverlapCacheIgnoresReservedHeaderSlots(t *testing.T) {
	shape := quadraticShapes()[0]
	pats, input := shape.pats, shape.input
	full, stride := overlapCacheFor(input, pats)

	want, code := driveCacheFindHooked(t, pats, input, full, stride, nil)
	if code != 0 {
		t.Fatalf("the clean drive ended with %d", code)
	}
	got, code := driveCacheFindHooked(t, pats, input, full, stride, func(buf []byte, scratchPtr int32) {
		for _, off := range []int32{0, 4, 32, 36, 44} {
			binary.LittleEndian.PutUint32(buf[scratchPtr+off:], 0xDEADBEEF)
		}
	})
	if code != 0 {
		t.Fatalf("garbage in the reserved header slots ended the drive with %d", code)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("garbage in the reserved header slots changed the answer: %d tuples, want %d", len(got), len(want))
	}
}

// The overlapping `find` body runs a once-per-drive
// preflight and keeps its verdict in the caller's gate array, retiring every
// pattern that matches NOWHERE at or after the drive's `from`.
//
// That is an optimisation whose whole job is to make the engine do LESS work,
// which is the dangerous kind: if the verdict is ever wrong in the "dead"
// direction, matches simply stop being reported and nothing crashes. The
// corpus gates reach it only by luck — the preflight needs a scalar frontend
// with a never-dying suffix DFA, which most RE2 chunks are not — so these
// tests aim at it directly.
//
// The shape is greedy-3's, the row the whole change exists for: a set whose
// members are all literal-less, one of which (`[^\n]*ERROR`) has an automaton
// that never dies on newline-free input, so before this it was walked to end
// of input from every start position.

// overlapPreflightSets are set shapes that should reach the preflight. Each
// mixes a pattern that can be proven absent with ones that cannot, because an
// all-dead set is the easy case: the interesting failure is retiring a live
// pattern while its neighbours keep the scan running.
var overlapPreflightSets = [][]string{
	{`a+`, `[^\n]*ERROR`, `x?y`},          // greedy-3 itself
	{`[^\n]*ERROR`, `[^\n]*WARN`},         // two never-dying patterns, both absentable
	{`a+`, `[^\n]*QQQ`},                   // one never-dying, one that always matches
	{`[^\n]*ZZ`, `b*`, `c?d`},             // b* matches empty everywhere: nothing is ever all-dead
	{`.*END`, `[0-9]+`},                   // `.` rather than a negated class
	{`[^\n]*ERROR`, `[^\n]*ERR`, `error`}, // overlapping literals, one anchored to a shorter one
}

// overlapPreflightInputs deliberately includes inputs where the absentable
// pattern is present, absent, present only near the end (so a drive resuming
// past it must NOT have retired it), and present only at the very start.
var overlapPreflightInputs = []string{
	"",
	"aaa",
	"aaabbbccc",
	"ERROR",
	"aaa ERROR bbb",
	"ERROR aaa",
	"aaa bbb ERROR",
	"WARN and ERROR",
	"xy xy xy",
	"the end END",
	"line one\nline two ERROR\nline three",
	"err ERR ERROR error",
	"d cd ccd",
	"ZZ zz ZZ",
	"0123456789 END",
}

// TestOverlappingPreflightMatchesGo drives overlapping `find` to exhaustion and
// compares against Go's every-start-position enumeration.
//
// The oracle is built the way the corpus harness builds its own: per pattern, an anchored
// probe at every start, which is exactly what `overlapping: true` promises.
// Comparing against `FindAllIndex` would be wrong — that is the GATED rule.
func TestOverlappingPreflightMatchesGo(t *testing.T) {
	for si, pats := range overlapPreflightSets {
		for _, input := range overlapPreflightInputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				r := newCapRunner(t, pats, input, true)
				defer r.Close()
				got := canonTuples(driveOverlapFind(t, r, input))
				want := canonTuples(overlapOracle(t, pats, input))
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("overlapping find over %q:\n  got  %v\n  want %v", input, got, want)
				}
			})
		}
	}
}

// TestOverlappingPreflightSurvivesResume is the failure mode the preflight's
// own design invites, and it is invisible to a single call.
//
// The verdict is computed once, at the drive's first `from`, and reused for
// every later call. That is sound only because a pattern alive over
// [from0, len) is alive over every sub-range a later call looks at — the
// verdict may only ever be too GENEROUS as the cursor advances. If the
// implementation ever recomputed per call, or narrowed the range it computed
// over, a pattern whose only match sits late in the input would be retired for
// the calls that could still reach it.
//
// So: start the drive at every legal `from`, and require each partial drive to
// equal the tail of the full one. A stale-or-narrowed verdict shows up here as
// missing matches at the far end.
func TestOverlappingPreflightSurvivesResume(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	for _, input := range []string{
		"aaa bbb ERROR",
		"ERROR aaa xy",
		"aaa xy bbb",
		"xy aaa ERROR xy",
	} {
		t.Run(input, func(t *testing.T) {
			r := newCapRunner(t, pats, input, true)
			defer r.Close()
			for from := 0; from <= len(input); from++ {
				r.resetGates() // a new drive: the caller's own obligation
				got := canonTuples(driveOverlapFindFrom(t, r, input, int32(from)))
				want := canonTuples(overlapOracleFrom(t, pats, input, from))
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("drive from %d over %q:\n  got  %v\n  want %v",
						from, input, got, want)
				}
			}
		})
	}
}

// TestOverlappingPreflightRunsOncePerDrive pins the amortisation itself, which
// is the half of item 11 that the reverted attempt got wrong.
//
// A preflight that re-runs on every call is CORRECT and useless: it was
// measured at 3,724 union passes on one drive, worse than the quadratic it
// replaced. Correctness tests cannot see that, so this one asserts the
// mechanism instead — after the first call of a drive, no gate slot is still
// zero, which is the condition the emitted guard tests. If a future change
// stops marking alive patterns, every alive slot stays zero, the guard re-arms
// and this fails.
func TestOverlappingPreflightRunsOncePerDrive(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	const input = "aaa bbb ccc"
	r := newCapRunner(t, pats, input, true)
	defer r.Close()

	buf := r.mem.UnsafeData(r.store)
	for i := 0; i < len(pats); i++ {
		if v := readU32(buf, int(r.gatePtr)+i*4); v != 0 {
			t.Fatalf("gate[%d] = %d before the drive, want 0", i, v)
		}
	}
	r.call(t, "cap_find", r.inBase, int32(len(input)), int32(0), r.scratchPtr(), r.outPtr, int32(r.npat))

	buf = r.mem.UnsafeData(r.store)
	var zero []int
	for i := 0; i < len(pats); i++ {
		if readU32(buf, int(r.gatePtr)+i*4) == 0 {
			zero = append(zero, i)
		}
	}
	if len(zero) != 0 {
		t.Fatalf("after the first call of a drive, gate slots %v are still zero — "+
			"the preflight guard will re-arm and the pass will run on EVERY call, "+
			"which is the failure an earlier attempt recorded", zero)
	}
}

// canonTuples sorts by (start, id, end) so the comparison tests the SET of
// matches and their positions, not the unspecified within-position order.
func canonTuples(in [][3]int) [][3]int {
	out := append([][3]int(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][2] < out[j][2]
	})
	return out
}

func readU32(buf []byte, at int) uint32 {
	return uint32(buf[at]) | uint32(buf[at+1])<<8 |
		uint32(buf[at+2])<<16 | uint32(buf[at+3])<<24
}

// driveOverlapFind runs a whole drive from 0.
func driveOverlapFind(t *testing.T, r *capRunner, input string) [][3]int {
	t.Helper()
	return driveOverlapFindFrom(t, r, input, 0)
}

// driveOverlapFindFrom iterates `find` the way a generated iterator does:
// call, take every tuple, resume at start+1 (overlapping has no gate to
// advance it for us).
func driveOverlapFindFrom(t *testing.T, r *capRunner, input string, from int32) [][3]int {
	t.Helper()
	var out [][3]int
	prevStart := -1
	for {
		n := r.call(t, "cap_find", r.inBase, int32(len(input)), from,
			r.scratchPtr(), r.outPtr, int32(r.npat)).(int32)
		if n <= 0 {
			return out
		}
		if int(n) > r.npat {
			t.Fatalf("find reported %d tuples at one position for a %d-pattern set", n, r.npat)
		}
		buf := r.mem.UnsafeData(r.store)
		start := int32(-1)
		for i := int32(0); i < n; i++ {
			b := int(r.outPtr) + int(i)*12
			id := int32(readU32(buf, b))
			st := int32(readU32(buf, b+4))
			en := int32(readU32(buf, b+8))
			if i == 0 {
				start = st
			} else if st != start {
				t.Fatalf("tuples in one call disagree on start: %d vs %d", start, st)
			}
			out = append(out, [3]int{int(id), int(st), int(en)})
		}
		if len(out) > int(n) && start < int32(prevStart) {
			t.Fatalf("drive went backwards: reported start %d after %d", start, prevStart)
		}
		prevStart = int(start)
		from = start + 1
		if int(from) > len(input)+1 {
			t.Fatalf("drive failed to terminate: from=%d, len=%d", from, len(input))
		}
	}
}

func overlapOracle(t *testing.T, pats []string, input string) [][3]int {
	t.Helper()
	return overlapOracleFrom(t, pats, input, 0)
}

// overlapOracleFrom is `overlapping: true`'s contract stated directly: at every
// start position s >= from, every pattern that matches there, with its
// leftmost-first extent.
//
// Both sides are canonicalised before comparison, because docs/sets.md states
// that "the order of the matches WITHIN one call is unspecified — not by
// pattern id". Asserting id order here would be testing an implementation
// detail and would fail on a correct compiler; the ACROSS-call order is a real
// contract and is asserted separately, by driveOverlapFindFrom's own
// resume-at-start+1 loop and the non-decreasing check in it.
func overlapOracleFrom(t *testing.T, pats []string, input string, from int) [][3]int {
	t.Helper()
	var out [][3]int
	for s := from; s <= len(input); s++ {
		for k, p := range pats {
			re := regexp.MustCompile(`\A(?:` + p + `)`)
			if m := re.FindStringIndex(input[s:]); m != nil {
				out = append(out, [3]int{k, s, s + m[1]})
			}
		}
	}
	return out
}

// The sweep is hand-emitted WASM. Compiling the Go that emits it proves
// nothing about the bytes; only a validator does.
func TestOverlapDPModuleValidates(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "a", Pattern: `a+`},
			{Name: "e", Pattern: `[^\n]*ERROR`},
			{Name: "x", Pattern: `x?y`},
		},
		Sets: []config.SetConfig{{
			Name:        "s",
			Find:        "cap_find",
			Patterns:    config.PatternSelector{All: true},
			Overlapping: true,
			Hints:       []string{"batch-find"},
		}},
	}
	wasm, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := wasmtime.NewEngine()
	if _, err := wasmtime.NewModule(engine, wasm); err != nil {
		t.Fatalf("emitted module does not validate:\n%v", err)
	}
	t.Logf("validated, %d bytes", len(wasm))
}
