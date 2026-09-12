package fuzz

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

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
		{"ckptOff moved", 32, 64},
		{"cntOff moved", 36, 48},
		{"blockOff moved", 0, 8},
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
	cellBytes := uint32(overlapShapeOf(t, pats).Cells * 4)
	hdrBytes := uint32(config.SetOverlapCheckpointHeaderBytes)
	if got, want := opt.header[overlapHdrCntOffWord], hdrBytes+cellBytes; got != want {
		t.Fatalf("cntOff = %d, want %d: the arm must write the layout the serving "+
			"validator expects, or every such call reports -4", got, want)
	}
	if got, want := opt.header[overlapHdrCkptOffWord], hdrBytes; got != want {
		t.Fatalf("ckptOff = %d, want %d", got, want)
	}
	if got, want := opt.header[overlapHdrBlockOffWord], hdrBytes+cellBytes+8; got != want {
		t.Fatalf("blockOff = %d, want %d", got, want)
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
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
		}},
	}
	w, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "set_find")
	if fn == nil {
		t.Fatal("module missing set_find export")
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	scratchPtr := outPtr + pageSize
	needed := uint64((int64(scratchPtr) + int64(scratchLen) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	copy(buf[inBase:], input)
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	for i := int32(0); i < scratchLen; i++ {
		buf[scratchPtr+i] = 0
	}
	desc := writeFindScratchStride(store, mem, gatePtr, int32(len(pats)), scratchPtr, scratchLen, stride)

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
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "set_find",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
			Hints: []string{"batch-find"},
		}},
	}
	w, _, err := compile.CompileFile(cfg, "")
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
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	scratchPtr := outPtr + pageSize
	needed := uint64((int64(scratchPtr) + int64(scratchLen) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	copy(buf[inBase:], input)
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	for i := int32(0); i < scratchLen; i++ {
		buf[scratchPtr+i] = 0
	}
	desc := writeFindScratchStride(store, mem, gatePtr, int32(len(pats)), scratchPtr, scratchLen, stride)
	if preArm {
		buf = mem.UnsafeData(store)
		binary.LittleEndian.PutUint32(buf[scratchPtr+12:], 0x7FFFFFFF)
	}

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
