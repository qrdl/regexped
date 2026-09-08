package compile

import (
	"bytes"
	"testing"
)

// Unit coverage for emitters and helpers whose branches the end-to-end paths do
// not all reach. Each case here is a contract some caller depends on, not a
// line-count exercise — the notes say which caller.

// buildBatchGroupsWrapperBody has THREE shapes, and which one it emits is
// decided by two independent channels. Both are `-1 = absent`, and the wrapper
// has to agree with the capture body it calls about who rebases capture slots:
//
//	winGlobal >= 0       window mode — the body gets the caller's real (ptr,len)
//	                     and the extent out of band; its slots are already
//	                     relative to ptr, so no pass here.
//	capStartGlobal >= 0  the body is handed the match start and writes ABSOLUTE
//	                     slots, so again no pass here.
//	both -1              the body's slots are relative to the narrowed slice, so
//	                     this wrapper must add the match start to each of them.
//
// The third shape is the one nothing else covers. Through the public API it is
// now unreachable — every real compile allocates one channel or the other — but
// it is the documented fallback for a capture body compiled without a module
// global allocator, and a wrapper that stopped emitting the pass would silently
// return slots relative to the wrong base.
//
// Getting this pairing wrong is not hypothetical: the batch wrapper ran its own
// rebase while calling a body that had already added the channel, so slots came
// back doubly rebased after any groups() call on the same instance. That is
// pinned end-to-end in tools/fuzz; this pins the three emitted shapes.
func TestBuildBatchGroupsWrapperBodyChannelShapes(t *testing.T) {
	const (
		findIdx    = 7
		captureIdx = 9
		numGroups  = 3
		capGlobal  = 5
		winGlobal  = 11
	)

	// global.set N — how either channel is handed to the capture body.
	globalSet := func(idx byte) []byte { return []byte{0x24, idx} }

	rebase := buildBatchGroupsWrapperBody(findIdx, captureIdx, numGroups, 0, -1, ffNative, -1)
	absolute := buildBatchGroupsWrapperBody(findIdx, captureIdx, numGroups, 0, -1, ffNative, capGlobal)
	window := buildBatchGroupsWrapperBody(findIdx, captureIdx, numGroups, 0, winGlobal, ffNative, -1)

	for name, body := range map[string][]byte{"rebase": rebase, "absolute": absolute, "window": window} {
		if len(body) == 0 {
			t.Fatalf("%s: emitted nothing", name)
		}
		if body[len(body)-1] != 0x0B {
			t.Errorf("%s: body does not end with `end` (0x0B)", name)
		}
	}

	// The rebasing shape is the only one that walks the slots, so it must be
	// the largest — and strictly so, or the pass is not being emitted.
	if len(rebase) <= len(absolute) {
		t.Errorf("the rebasing shape is %d bytes and the absolute one %d; the per-slot "+
			"pass must make it strictly larger, or it is not being emitted",
			len(rebase), len(absolute))
	}
	if len(rebase) <= len(window) {
		t.Errorf("the rebasing shape is %d bytes and the window one %d; window mode "+
			"skips the same pass", len(rebase), len(window))
	}

	// Each channel appears only in its own shape.
	if bytes.Contains(rebase, globalSet(capGlobal)) {
		t.Error("the rebasing shape writes a capture-start global it was not given")
	}
	if !bytes.Contains(absolute, globalSet(capGlobal)) {
		t.Error("the absolute shape never hands the capture body its start; the body " +
			"would then add whatever the global last held")
	}
	if !bytes.Contains(window, globalSet(winGlobal)) ||
		!bytes.Contains(window, globalSet(winGlobal+1)) {
		t.Error("window mode must write BOTH halves of the (startOff, endOff) pair")
	}

	// A pattern with more groups walks more slots, but only in the rebasing
	// shape — which is what shows the loop is driven by numGroups and not
	// emitted unconditionally.
	wider := buildBatchGroupsWrapperBody(findIdx, captureIdx, numGroups+2, 0, -1, ffNative, -1)
	if len(wider) <= len(rebase) {
		t.Errorf("two more groups produced %d bytes against %d; the per-slot pass does "+
			"not scale with the group count", len(wider), len(rebase))
	}
	widerAbs := buildBatchGroupsWrapperBody(findIdx, captureIdx, numGroups+2, 0, -1, ffNative, capGlobal)
	if len(widerAbs) != len(absolute) {
		t.Errorf("the absolute shape grew from %d to %d bytes with two more groups; it "+
			"emits no per-slot code, so it must not depend on the count",
			len(absolute), len(widerAbs))
	}
}

// gateGroups and appendGateLocalGroup are the two halves of one rule: a body
// declares the gate locals as a TRAILING local group, and the group COUNT in
// its declaration vector has to include that group exactly when the group is
// emitted. The two are written apart, so a body that called one without the
// other would emit a declaration vector whose count disagrees with its
// contents — a module that does not validate.
func TestGateLocalGroupHelpersAgree(t *testing.T) {
	for _, n := range []int{-1, 0} {
		if got := gateGroups(n); got != 0 {
			t.Errorf("gateGroups(%d) = %d, want 0", n, got)
		}
		if got := appendGateLocalGroup([]byte{0xAA}, n); !bytes.Equal(got, []byte{0xAA}) {
			t.Errorf("appendGateLocalGroup(%d) appended %v, want nothing", n, got[1:])
		}
	}
	for _, n := range []int{1, 8, 200} {
		if got := gateGroups(n); got != 1 {
			t.Errorf("gateGroups(%d) = %d, want 1", n, got)
		}
		got := appendGateLocalGroup(nil, n)
		// One local group: a ULEB128 count followed by the i32 type byte.
		if len(got) < 2 || got[len(got)-1] != 0x7F {
			t.Errorf("appendGateLocalGroup(%d) = %v, want a count followed by 0x7F (i32)", n, got)
		}
	}
}

// splatCount tells the packed-pair emitter how many i8x16.splat vectors to
// hoist, and the body declares exactly that many v128 locals. It is the sum of
// both probe columns; counting one column would under-declare the frame.
func TestPackedPairSplatCount(t *testing.T) {
	p := &packedPairPlan{Bytes1: []byte{'a', 'b'}, Bytes2: []byte{'x', 'y', 'z'}}
	if got := p.splatCount(); got != 5 {
		t.Errorf("splatCount() = %d, want 5 (both columns, 2 + 3)", got)
	}
	empty := &packedPairPlan{}
	if got := empty.splatCount(); got != 0 {
		t.Errorf("splatCount() on an empty plan = %d, want 0", got)
	}
}

// choosePackedPair's two refusals. Both are preconditions of the emitted body
// rather than mere tidiness: the probe pins two columns inside every literal,
// so a zero-length literal has no such column, and the frontend chooser sizes
// its budget on at most packedPairMaxLiterals members.
func TestChoosePackedPairRefusals(t *testing.T) {
	if _, ok := choosePackedPair(nil); ok {
		t.Error("an empty literal set produced a packed-pair plan")
	}
	tooMany := make([][]byte, packedPairMaxLiterals+1)
	for i := range tooMany {
		tooMany[i] = []byte{byte('a' + i%26), 'x', 'y', 'z'}
	}
	if _, ok := choosePackedPair(tooMany); ok {
		t.Errorf("%d literals produced a plan; the cap is %d",
			len(tooMany), packedPairMaxLiterals)
	}
	withEmpty := [][]byte{[]byte("abcd"), {}, []byte("efgh")}
	if _, ok := choosePackedPair(withEmpty); ok {
		t.Error("a zero-length literal produced a plan; it has no byte for either probe column")
	}
	// The positive control, so the refusals above are evidence of a working
	// gate rather than of a function that never succeeds.
	if _, ok := choosePackedPair([][]byte{[]byte("abcd"), []byte("abce")}); !ok {
		t.Error("two ordinary 4-byte literals were refused")
	}
}

// btMemoMaxLen is the largest input whose BitState memo bitset fits the budget.
// The clamp at zero is what keeps a pattern too large for any input from
// wrapping into a huge unsigned comparison in the emitted guard — which would
// never fire, and the fill would then run past its reservation.
func TestBTMemoMaxLenClampsAtZero(t *testing.T) {
	// memoBudget*8 < numInsts: no input at all fits, not even the empty one.
	if got := btMemoMaxLen(100, 1); got != 0 {
		t.Errorf("btMemoMaxLen(100, 1) = %d, want 0 — a negative ceiling becomes a "+
			"huge unsigned bound in the emitted guard, which never fires", got)
	}
	// The ordinary case is the plain formula, memoBudget*8/N - 1.
	if got := btMemoMaxLen(25, 128*1024); got != 128*1024*8/25-1 {
		t.Errorf("btMemoMaxLen(25, 128 KB) = %d, want %d", got, 128*1024*8/25-1)
	}
	// And it is monotone in the budget, which is the property the compile-time
	// reservation and the runtime guard both rely on.
	if btMemoMaxLen(25, 64*1024) >= btMemoMaxLen(25, 128*1024) {
		t.Error("a larger budget did not admit a longer input")
	}
}
