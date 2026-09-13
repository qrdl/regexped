package fuzz

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
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
