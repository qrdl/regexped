package compile

import (
	"bytes"
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
	"github.com/qrdl/regexped/internal/wlocals"
)

// ── The build-time invariant guards ────────────────────────────────────────
//
// Several emitters protect themselves with a panic rather than a fallback,
// deliberately: the alternative in each case is a module that VALIDATES and
// answers wrongly. blockStack's own header makes the argument — a `br 2` where
// `br 3` was meant is well-typed and branches somewhere plausible, and nothing
// but a full corpus run catches it.
//
// A guard that has never fired is a guard nobody has checked. These assert the
// panic happens AND that its message names the problem, since these messages
// are read by whoever is mid-refactor when one finally does fire.

// TestBlockStackGuards covers the two ways a branch-depth question can be
// wrong: asking about a label that is not open, and popping a level that was
// never pushed. Both are emitter bugs that a returned number would hide.
func TestBlockStackGuards(t *testing.T) {
	t.Run("depth of an unopened label", func(t *testing.T) {
		var s blockStack
		s.Push("outer")
		mustPanic(t, "not an open block", func() { s.Depth("nope") })
	})
	t.Run("pop with nothing open", func(t *testing.T) {
		var s blockStack
		mustPanic(t, "no level open", func() { s.Pop() })
	})
	t.Run("depth counts outward", func(t *testing.T) {
		var s blockStack
		s.Push("a")
		s.Push("b")
		s.Push("c")
		if d := s.Depth("c"); d != 0 {
			t.Errorf("Depth(innermost) = %d, want 0", d)
		}
		if d := s.Depth("a"); d != 2 {
			t.Errorf("Depth(outermost of 3) = %d, want 2", d)
		}
		s.Pop()
		if d := s.Depth("b"); d != 0 {
			t.Errorf("after Pop, Depth(new innermost) = %d, want 0", d)
		}
	})
	t.Run("depth past a byte is refused", func(t *testing.T) {
		// A `br` operand is LEB128 in the binary but every emitter here writes
		// it as a single byte, so a depth past 255 would be truncated into a
		// branch to somewhere else entirely. There is no legitimate emitter
		// this deep; the guard exists so that if one ever appears it stops
		// rather than misbranches.
		var s blockStack
		s.Push("target")
		for i := 0; i < 300; i++ {
			s.Push("filler")
		}
		mustPanic(t, "exceeds a byte", func() { s.Depth("target") })
	})
	t.Run("a label may repeat and the nearest wins", func(t *testing.T) {
		var s blockStack
		s.Push("loop")
		s.Push("x")
		s.Push("loop")
		if d := s.Depth("loop"); d != 0 {
			t.Errorf("Depth with a repeated label = %d, want the nearest (0)", d)
		}
	})
}

// TestFindFromModeGuards covers setFind and setCaptureBody's refusal of
// ffUnset.
//
// The zero value being invalid is the entire mechanism: a find body whose mode
// was never claimed would otherwise start every scan at 0 and ignore the
// caller's offset for ever, which is a hang in the host's iteration loop
// rather than a wrong answer. find_from.go records that this shipped twice.
func TestFindFromModeGuards(t *testing.T) {
	t.Run("setFind rejects the zero value", func(t *testing.T) {
		p := &compiledPattern{}
		mustPanic(t, "unset findFromMode", func() { p.setFind([]byte{0x0B}, ffUnset) })
	})
	t.Run("setCaptureBody rejects the zero value", func(t *testing.T) {
		p := &compiledPattern{}
		mustPanic(t, "unset findFromMode", func() { p.setCaptureBody([]byte{0x0B}, ffUnset) })
	})
	t.Run("a claimed mode is recorded", func(t *testing.T) {
		p := &compiledPattern{}
		p.setFind([]byte{0x0B}, ffNative)
		if p.findFromMode != ffNative || len(p.findBody) == 0 {
			t.Errorf("setFind did not record the body and mode: %v, %d bytes",
				p.findFromMode, len(p.findBody))
		}
		p.setCaptureBody([]byte{0x0B}, ffAnchoredZeroOnly)
		if p.captureFromMode != ffAnchoredZeroOnly {
			t.Errorf("setCaptureBody recorded mode %v", p.captureFromMode)
		}
	})
}

// TestDFATableEqualDiscriminates covers dfaTableEqual, which decides whether
// two patterns can SHARE a compiled suffix DFA in a set.
//
// A false positive there merges two patterns onto one automaton and makes one
// of them answer for the other, so the negative cases are the ones that
// matter: every field it compares needs to be able to say no.
func TestDFATableEqualDiscriminates(t *testing.T) {
	base := compileTestDFA(t, `[a-z]{3}x`, true)
	if !dfaTableEqual(base, base) {
		t.Fatal("a table is not equal to itself")
	}
	same := compileTestDFA(t, `[a-z]{3}x`, true)
	if !dfaTableEqual(base, same) {
		t.Error("two compiles of the same pattern produced unequal tables")
	}
	for _, other := range []string{
		`[a-z]{4}x`,   // different state count
		`[a-z]{3}y`,   // same shape, different transitions
		`\b[a-z]+x`,   // word-boundary tracking
		`(?m:^)[a-z]`, // newline-boundary tracking
	} {
		o := compileTestDFA(t, other, true)
		if dfaTableEqual(base, o) {
			t.Errorf("dfaTableEqual said %q equals %q", `[a-z]{3}x`, other)
		}
	}
}

// TestDFATableEqualWideAccepts covers the WIDE accept comparison, which is the
// half of dfaTableEqual that decides sharing for sets past 64 patterns.
//
// On the wide path the narrow u64 masks carry no discriminating power at all —
// every accepting state has bit 0 set — so if the wide lists were not compared
// too, any two wide tables of the same SHAPE would look equal and two patterns
// would share an automaton that answers for only one of them.
func TestDFATableEqualWideAccepts(t *testing.T) {
	// Two structurally identical tables that differ ONLY in the wide lists.
	mk := func(wide map[int][]uint16) *dfaTable {
		t.Helper()
		base := compileTestDFA(t, `[a-z]{3}x`, true)
		cp := *base
		cp.acceptWide = wide
		return &cp
	}
	a := mk(map[int][]uint16{2: {7, 9}})
	b := mk(map[int][]uint16{2: {7, 9}})
	if !dfaTableEqual(a, b) {
		t.Error("tables with identical wide accept lists compared unequal")
	}
	for name, other := range map[string]map[int][]uint16{
		"different id":     {2: {7, 8}},
		"different length": {2: {7}},
		"different state":  {3: {7, 9}},
		"extra state":      {2: {7, 9}, 3: {1}},
		"empty":            {},
	} {
		if dfaTableEqual(a, mk(other)) {
			t.Errorf("wide lists differing by %q compared EQUAL — two patterns "+
				"would share an automaton that answers for one of them", name)
		}
	}
}

// TestAssertGroupsFromWrapperMode covers the guard that stands between a
// groups export and a body that cannot receive its start offset.
//
// The groups-from wrapper seeds the find-from channel, which only an ffNative
// body reads. Exporting groups over a legacy-narrow body would compile, would
// validate, and would then ignore the caller's offset for ever — the exact
// failure find_from.go records as having shipped twice.
func TestAssertGroupsFromWrapperMode(t *testing.T) {
	t.Run("anchored-only needs no channel", func(t *testing.T) {
		// captureBody IS the export, so the mode is never consulted and even
		// the invalid zero value must be tolerated.
		assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffUnset}, true)
	})
	t.Run("native find body passes", func(t *testing.T) {
		assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffNative}, false)
	})
	t.Run("native capture body passes", func(t *testing.T) {
		assertGroupsFromWrapperMode(
			&compiledPattern{anchored: true, captureFromMode: ffNative}, false)
	})
	t.Run("legacy-narrow find body is refused", func(t *testing.T) {
		mustPanic(t, "find body", func() {
			assertGroupsFromWrapperMode(&compiledPattern{findFromMode: ffLegacyNarrow}, false)
		})
	})
	t.Run("non-native capture body is refused", func(t *testing.T) {
		// The message must name the CAPTURE body, not the find one: which of
		// the two carries the channel depends on p.anchored, and a message
		// naming the wrong half sends the reader to the wrong emitter.
		mustPanic(t, "capture body", func() {
			assertGroupsFromWrapperMode(
				&compiledPattern{anchored: true, captureFromMode: ffLegacyNarrow}, false)
		})
	})
}

// TestEmitUnionSkipArmNoStates covers the empty-state guard: a union automaton
// with nothing to stride over must emit NOTHING, not an arm that arms itself
// on a state id that does not exist.
func TestEmitUnionSkipArmNoStates(t *testing.T) {
	before := []byte{0x01, 0x02}
	got := emitUnionSkipArm(append([]byte(nil), before...), &unionScanDFA{}, 7)
	if len(got) != len(before) {
		t.Errorf("emitUnionSkipArm with no skip states appended %d bytes, want 0",
			len(got)-len(before))
	}
}

// TestFutureAcceptsEmptyTable covers the empty-table guards in the liveness
// pass, and the WASM-id conversion's bound check.
//
// futureAccepts answers "can anything still match from here", which the set
// preflight uses to retire a pattern early. On an empty table the honest
// answer is nothing at all — returning a zero-length slice rather than
// indexing it.
func TestFutureAcceptsEmptyTable(t *testing.T) {
	if got := futureAccepts(nil); got != nil {
		t.Errorf("futureAccepts(nil) = %v, want nil", got)
	}
	if got := futureAccepts(&dfaTable{}); got != nil {
		t.Errorf("futureAccepts(empty) = %v, want nil", got)
	}
	// numWASM smaller than the table's state count must be tolerated: the
	// conversion skips states that do not fit rather than panicking, because
	// a caller sizing by a stale numWASM would otherwise take the whole
	// compile down.
	tbl := compileTestDFA(t, `[a-z]{3}x`, true)
	if got := futureAcceptsWASM(tbl, 2); len(got) != 2 {
		t.Errorf("futureAcceptsWASM with a short numWASM returned %d slots, want 2", len(got))
	}
	full := futureAcceptsWASM(tbl, tbl.numStates+1)
	if len(full) != tbl.numStates+1 {
		t.Errorf("futureAcceptsWASM returned %d slots, want %d", len(full), tbl.numStates+1)
	}
	if full[0] != 0 {
		t.Errorf("slot 0 (the dead state) = %#x, want 0 — nothing accepts from dead", full[0])
	}
}

// TestEncodeMemberSetWidths covers the member-set encoder across the widths the
// rectangle cover has to handle, including the one that used to be refused.
//
// Two nibble pairs cover a set of ANY width, which is what removed the old
// 16-byte ceiling; the panic guard exists only so a future change to
// memberSetPairs fails loudly instead of truncating, and truncating is exactly
// the wrong-extent bug the skip must never produce.
func TestEncodeMemberSetWidths(t *testing.T) {
	widths := map[string][]byte{}
	var lower, wordish, wide []byte
	for c := byte('a'); c <= 'z'; c++ {
		lower = append(lower, c)
	}
	for c := 0; c < 256; c++ {
		if c != '\n' {
			wide = append(wide, byte(c))
		}
	}
	wordish = append(append([]byte(nil), lower...), '_', '0', '9')
	widths["single byte"] = []byte{'x'}
	widths["lowercase"] = lower
	widths["word-ish"] = wordish
	widths["all but newline"] = wide

	for name, set := range widths {
		out := encodeMemberSet(set)
		if len(out) != memberSetBytes {
			t.Errorf("%s: encodeMemberSet returned %d bytes, want %d",
				name, len(out), memberSetBytes)
		}
		// The encoding must be EXACT: decode it back through the same
		// arithmetic the emitted SIMD performs and compare membership.
		var want [256]bool
		for _, c := range set {
			want[c] = true
		}
		for c := 0; c < 256; c++ {
			var merged byte
			for p := 0; p < memberSetPairs; p++ {
				lo := out[p*32 : p*32+16]
				hi := out[p*32+16 : p*32+32]
				merged |= lo[c&0x0F] & hi[c>>4]
			}
			if (merged != 0) != want[c] {
				t.Fatalf("%s: byte %#02x membership = %v, want %v",
					name, c, merged != 0, want[c])
			}
		}
	}
}

// TestApplyDominantStateEncodingSkipsOutOfRange covers the bound check: a
// dominant whose state id is past the table is skipped rather than written
// out of bounds. The two arrays are sized independently, so this is a real
// guard rather than a formality.
func TestApplyDominantStateEncodingSkipsOutOfRange(t *testing.T) {
	l := &dfaLayout{numWASM: 3}
	l.midAcceptBytes = make([]byte, 3)
	l.dominantStates = []dominantInfo{
		{state: 1, encodedByte: 128, isMidAccept: true},
		{state: 99, encodedByte: 129, isMidAccept: true}, // past the table
	}
	applyDominantStateEncoding(l, true)
	if l.midAcceptBytes[1] != 128 {
		t.Errorf("in-range dominant not encoded: %#x", l.midAcceptBytes[1])
	}
	// A non-mid dominant must be skipped when encodeNonMid is false.
	l2 := &dfaLayout{numWASM: 3}
	l2.midAcceptBytes = make([]byte, 3)
	l2.dominantStates = []dominantInfo{{state: 1, encodedByte: 254}}
	applyDominantStateEncoding(l2, false)
	if l2.midAcceptBytes[1] != 0 {
		t.Errorf("non-mid dominant encoded despite encodeNonMid=false: %#x",
			l2.midAcceptBytes[1])
	}
}

// recoverContains runs fn and requires it to panic with a message naming want.
func recoverContains(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic naming %q, got none", want)
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, want) {
			t.Errorf("panic = %q, want it to name %q", msg, want)
		}
	}()
	fn()
}

// TestInjectScratchPrologueRejectsNonEntry covers the size-prefix check. The
// splice REWRITES the entry's byte count, so a caller that handed it a bare body
// would produce a code section off by the prologue's length from the first
// spliced function onward — a module that may still validate and misbehaves.
func TestInjectScratchPrologueRejectsNonEntry(t *testing.T) {
	// A well-formed entry, spliced, as the reference: no locals, one `end`.
	body := []byte{0x00, 0x0B}
	entry := append(utils.AppendULEB128(nil, uint32(len(body))), body...)
	got := injectScratchPrologue(entry, 3)
	size, n, err := utils.DecodeULEB128(got)
	if err != nil || int(size)+n != len(got) {
		t.Fatalf("the spliced entry's own count is wrong: size=%d n=%d len=%d err=%v", size, n, len(got), err)
	}
	if len(got) <= len(entry) {
		t.Fatalf("nothing was spliced: %d bytes in, %d out", len(entry), len(got))
	}
	// The magic check the prologue exists for must be in there.
	if !strings.Contains(string(got), string([]byte{0x28, 0x02, abi.FindScratchMagicOff})) {
		t.Error("the spliced prologue does not load the descriptor magic")
	}

	// A count that does not describe the rest.
	recoverContains(t, "not one code entry", func() {
		injectScratchPrologue([]byte{0x7F, 0x00, 0x0B}, 3)
	})
	// And nothing at all, where the count cannot even be read.
	recoverContains(t, "not one code entry", func() {
		injectScratchPrologue(nil, 3)
	})
}

// TestLocalsVectorEndRejectsMalformed covers both parse failures. The offset is
// PARSED rather than assumed because bodies here declare anywhere from zero
// groups to several, and splicing into the middle of a declaration produces a
// module that validates when the bytes happen to read as something.
func TestLocalsVectorEndRejectsMalformed(t *testing.T) {
	if got := localsVectorEnd([]byte{0x00, 0x0B}); got != 1 {
		t.Errorf("localsVectorEnd(no groups) = %d, want 1", got)
	}
	// One group of two i32s: count byte, then the valtype.
	if got := localsVectorEnd([]byte{0x01, 0x02, 0x7F, 0x0B}); got != 3 {
		t.Errorf("localsVectorEnd(one group) = %d, want 3", got)
	}
	// An unterminated LEB128 group count.
	recoverContains(t, "malformed locals vector", func() {
		localsVectorEnd([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})
	})
	// A well-formed group count whose first group's count runs off the end.
	recoverContains(t, "malformed local group", func() {
		localsVectorEnd([]byte{0x01})
	})
}

// TestBuildStartableTableDeclines covers the two shapes that get no first-byte
// table. A sparse bucket is the interesting one: it reads its answer out of
// per-state LISTS and consults no i32 mask at all, so a bucket-local mask table
// is not merely dead weight there but a mask applied to a body that ignores it.
func TestBuildStartableTableDeclines(t *testing.T) {
	if got := buildStartableTable(&bucket{}); got != nil {
		t.Errorf("an empty bucket produced a %d-entry table", len(got))
	}
	one := []*PatternInfo{{}}
	if got := buildStartableTable(&bucket{patterns: one, sparse: true}); got != nil {
		t.Errorf("a sparse bucket produced a %d-entry table", len(got))
	}
	// Past the mask width there are no bucket-local bits left to set.
	wide := make([]*PatternInfo, bucketMaskBits+1)
	for i := range wide {
		wide[i] = &PatternInfo{}
	}
	if got := buildStartableTable(&bucket{patterns: wide}); got != nil {
		t.Errorf("a %d-pattern bucket produced a %d-entry table", len(wide), len(got))
	}
}

// TestSetFindWrapperRequiresGateSlot covers the wrapper's own precondition.
// findGateSlot() is hasFind() by another name, so a set with no `find` reaching
// the wrapper means the emitter was called from a path that does not have one —
// and the six-parameter signature it assumes would then be wrong.
func TestSetFindWrapperRequiresGateSlot(t *testing.T) {
	cs := setEmitCovCompileSet(t, SetSpec{Name: "s", ScanAny: "s_any"},
		[]string{`[0-9][a-c][0-9]`}, CompileSetOptions{})
	if cs.findGateSlot() {
		t.Fatal("a scan-only set claims a gate slot; this fixture no longer isolates the guard")
	}
	recoverContains(t, "no gate slot", func() {
		emitSetFindWrapperBody(cs, 0, -1, -1)
	})
}

// TestSetComponentCacheGeometry covers the constructor's cache sizing. An
// overlapping set with a sweep is the only shape whose resource constructor
// carries a column width and a bucket pattern count, and they are what size the
// answer cache the resource reserves — a component consumer has no gate array to
// put that in.
func TestSetComponentCacheGeometry(t *testing.T) {
	cfg := config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		Regexps: []config.RegexEntry{
			{Name: "p0", Pattern: `[^\n]*[0-2]`},
			{Name: "p1", Pattern: `[^\n]*[3-5]`},
		},
		Sets: []config.SetConfig{{
			Name:        "s",
			Patterns:    config.PatternSelector{All: true},
			Find:        "scan_it",
			Overlapping: true,
		}},
	}

	// The geometry the adapters must be stamped with, read off the same compile.
	sh, err := SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible {
		t.Fatal("this set gets no sweep, so the constructor has no cache geometry to carry")
	}

	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", nil, nil, setComponentNames("s"), nil)
	if err != nil {
		t.Fatalf("CompileFileComponent: %v", err)
	}
	validateWASM(t, core)
	for _, want := range []string{
		"regexped:t/sets#[constructor]scan-it",
		"regexped:t/sets#[method]scan-it.next",
		"regexped:t/sets#[dtor]scan-it",
	} {
		if !strings.Contains(string(core), want) {
			t.Errorf("core module does not export %q", want)
		}
	}
}

// TestOverlapSweepGateMatchesTheRowMask pins the sweep's pattern-count gate to
// the width of the row mask the checkpoint bodies write. That mask is an i32
// (`1 << k`), so a bucket of 33..64 patterns would drop every pattern k >= 32
// from every row, silently. No config reaches it today — the packer caps a
// dense bucket at bucketMaskBits and a larger one goes sparse, which the sweep
// refuses — so the gate is driven with a synthetic bucket.
func TestOverlapSweepGateMatchesTheRowMask(t *testing.T) {
	mk := func(n int) *compiledSet {
		pats := make([]*PatternInfo, n)
		for i := range pats {
			pats[i] = &PatternInfo{}
		}
		return &compiledSet{
			find: "f", overlapping: true,
			buckets: []*bucket{{
				patterns: pats, isFallback: true,
				dp: overlapDPTables{ok: true, l: &dfaLayout{useU8: true}, numWASM: 2},
			}},
			patternIDs: [][]int{make([]int, n)},
		}
	}
	if got := mk(bucketMaskBits).overlapDPBucket(); got != 0 {
		t.Fatalf("a %d-pattern bucket was refused (%d): the synthetic bucket no longer "+
			"passes the other gates, so this test proves nothing", bucketMaskBits, got)
	}
	if got := mk(bucketMaskBits + 1).overlapDPBucket(); got != -1 {
		t.Fatalf("a %d-pattern bucket was admitted to the sweep, whose row mask has %d bits",
			bucketMaskBits+1, bucketMaskBits)
	}
	// The emitter refuses on its own too, so a gate that drifts later cannot
	// reach the i32 mask without a loud failure.
	cs := mk(bucketMaskBits)
	cs.patternIDs = [][]int{make([]int, bucketMaskBits+1)}
	recoverContains(t, "bucketMaskBits", func() { newCkptEmit(cs, 0, 0) })
}

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

// Paths a YAML config cannot select, and exported predicates whose only
// callers live in other MODULES.
//
// Both are gaps a compile-matrix cannot close. The Shufti frontend needs
// Aho-Corasick to decline first, which `compile_api_test.go` arranges with
// `ACBudgetBytes: 1` — an option `BuildConfig` does not expose, and a
// 220-literal set still sat comfortably inside AC's real budget. The
// predicates are called from `tools/fuzz` and `tools/re2test`, separate
// modules whose tests contribute nothing here.
//
// Calling an emitter directly is a weaker check than compiling a module that
// uses it, and it is used here only where the stronger option does not exist.
// What it does establish is that the path still BUILDS and still produces
// well-formed output — which is what would break silently as the emitters
// around it change.

// shuftiCompiledSetOpts builds a set whose frontend is Shufti, by the same
// route compile_api_test.go uses: enough literals that Teddy declines, first bytes
// inside Shufti's 17..64 band, Aho-Corasick pushed out of budget, and the
// LikelyNoMatch bias that selects it.
//
// `over` leaves the options open so a caller can force the ADAPTIVE variant.
// The dense switch is `lnm && !rare`, and this set's byte union is one the
// rarity model calls rare — so the adaptive arm, roughly a third of the
// emitter, is unreachable without WithShuftiAdaptive.
func shuftiCompiledSetOpts(t *testing.T, over func(*CompileSetOptions)) *compiledSet {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var prefixPool, suffixPool dfaPool
	var patterns []*PatternInfo
	var ids []int
	for i := 0; i < teddyMaxLiterals+1; i++ {
		pat := fmt.Sprintf("%cq%02dx[a-z]+", alphabet[i%len(alphabet)], i)
		info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		patterns = append(patterns, info)
		ids = append(ids, i)
	}
	spec := SetSpec{
		Name: "s", Find: "find_all",
		MatchAny: "match_any", MatchAll: "match_all",
		DeclaredPatternCount: len(patterns), IDSpaceSize: len(patterns),
		Patterns: patterns, PatternIDs: ids,
	}
	opts := CompileSetOptions{LikelyMode: LikelyNoMatch, ACBudgetBytes: 1}
	if over != nil {
		over(&opts)
	}
	cs := CompileSet(spec, &prefixPool, &suffixPool, opts)
	if cs.fe != frontendShufti {
		t.Fatalf("expected the Shufti frontend, got %v — this test no longer reaches what it claims", cs.fe)
	}
	return cs
}

// TestShuftiAnchoredBodyEmits covers emitSetMatchFnFinalShufti, the Shufti
// anchored match body.
//
// It is the single largest uncovered function in the package, and unreachable
// through CompileFile: see the file comment. Emitting it directly at least
// pins that it produces a body at all, for both anchored kinds.
func TestShuftiAnchoredBodyEmits(t *testing.T) {
	// Both switch shapes. The adaptive one carries the runtime dense counter
	// and its escape to the scalar tail — a separate locals layout and a
	// separate set of branch depths, so a body that emits only one of them is
	// only half tested. It is reachable ONLY through the test-only override:
	// this set's byte union is rare, and `shuftiAdaptive = lnm && !rare`.
	for _, tc := range []struct {
		name     string
		over     func(*CompileSetOptions)
		adaptive bool
	}{
		{"plain", nil, false},
		{"adaptive", func(o *CompileSetOptions) { *o = o.WithShuftiAdaptive(true) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := shuftiCompiledSetOpts(t, tc.over)
			if cs.shuftiAdaptive != tc.adaptive {
				t.Fatalf("shuftiAdaptive = %v, want %v — this case no longer "+
					"covers the arm it was written for", cs.shuftiAdaptive, tc.adaptive)
			}
			base := cs.funcCount()
			var prev []byte
			for _, mode := range []setCapKind{capMatchAny, capMatchAll} {
				body := emitSetMatchFnFinalShufti(cs, base, base, mode, base)
				if len(body) == 0 {
					t.Fatalf("mode %v: emitted an empty body", mode)
				}
				// A WASM function body is a size-prefixed byte sequence whose
				// last byte is `end` (0x0B). Cheap, but it is what catches a
				// body that stopped being terminated.
				if body[len(body)-1] != 0x0B {
					t.Errorf("mode %v: body does not end with `end` (0x0B), got %#x",
						mode, body[len(body)-1])
				}
				// The two anchored modes emit the SAME body here, and that is
				// correct: newSetFindCtx branches on capFind and capScanAny
				// only, so match_any and match_all are indistinguishable to
				// this emitter — their difference lives in the probe and the
				// accumulation around it. Asserted rather than assumed,
				// because a future mode-dependent arm added here would want
				// this test updated deliberately rather than silently.
				if prev != nil && !bytes.Equal(prev, body) {
					t.Error("match_any and match_all now emit different bodies; " +
						"this emitter used to be mode-independent — update the test " +
						"if that is intended")
				}
				prev = body
			}
		})
	}
}

// TestShuftiAnchoredAdaptiveIsLarger pins that the adaptive arm actually emits
// the extra machinery rather than silently collapsing to the plain shape —
// which is what a wrong `adaptive` test inside the emitter would look like.
func TestShuftiAnchoredAdaptiveIsLarger(t *testing.T) {
	plain := shuftiCompiledSetOpts(t, nil)
	adaptive := shuftiCompiledSetOpts(t, func(o *CompileSetOptions) {
		*o = o.WithShuftiAdaptive(true)
	})
	base := plain.funcCount()
	p := emitSetMatchFnFinalShufti(plain, base, base, capMatchAny, base)
	a := emitSetMatchFnFinalShufti(adaptive, adaptive.funcCount(), adaptive.funcCount(), capMatchAny, adaptive.funcCount())
	if len(a) <= len(p) {
		t.Errorf("adaptive body is %d bytes, plain is %d — the dense counter, "+
			"its gate and the scalar escape should make it strictly larger",
			len(a), len(p))
	}
}

// TestUnionAliveMaskEmits covers emitUnionAliveMask, the preflight's
// union-automaton pass.
//
// The absence prefilter is chosen over it whenever per-pattern absence
// literals exist, which every literal-bearing set in the matrix has — so the
// union arm is the road not taken there and needs reaching directly.
func TestUnionAliveMaskEmits(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	var patterns []*PatternInfo
	var ids []int
	for i, pat := range []string{`a+`, `[^\n]*ERROR`, `x?y`} {
		info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		patterns = append(patterns, info)
		ids = append(ids, i)
	}
	spec := SetSpec{
		Name: "s", ScanAny: "scan_any", Find: "find_all",
		DeclaredPatternCount: len(patterns), IDSpaceSize: len(patterns),
		Patterns: patterns, PatternIDs: ids,
	}
	u := buildUnionScanDFA(spec, 0, false)
	if u == nil {
		t.Skip("no union automaton for this set: nothing to emit")
	}
	body := emitUnionAliveMask(nil, u, 8, 9, 10, 2, 11, 0, nil)
	if len(body) == 0 {
		t.Fatal("emitted an empty alive-mask sequence")
	}
	// fullMask != 0 arms the early exit, which
	// is a different emitted shape and the one every real caller gets.
	withExit := emitUnionAliveMask(nil, u, 8, 9, 10, 2, 11, 0, []uint64{0x7})
	if len(withExit) <= len(body) {
		t.Fatalf("the fullMask early exit emitted no extra bytes: %d vs %d", len(withExit), len(body))
	}
}

// TestSetAdmitsBacktracking is the predicate the STUB GENERATORS use to decide
// which `_all` ABI a set exports, without ever compiling it.
//
// Its only callers are in other modules, so nothing here pinned it. Getting it
// wrong is not a wrong answer but a wrong ARITY — the stub calls a
// three-parameter export with two — which is why re2test reads the answer from
// diagnostics instead and this predicate must agree with what the compiler
// actually did.
func TestSetAdmitsBacktracking(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`}
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sc := config.SetConfig{
		Name: "s", MatchAll: "m_all", Find: "f",
		Patterns: config.PatternSelector{All: true},
	}

	// A generous fallback budget: every member gets a DFA, so no BT.
	roomy := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
	if SetAdmitsBacktracking(sc, roomy) {
		t.Error("a set whose members all fit their DFA budget must not admit Backtracking")
	}
	// A budget no fallback DFA can meet: every member lands on BT.
	cramped := config.BuildConfig{
		Regexps: entries, Sets: []config.SetConfig{sc}, MaxFallbackStates: 1,
	}
	if !SetAdmitsBacktracking(sc, cramped) {
		t.Error("max_fallback_states = 1 must push these members onto Backtracking")
	}
	// And the prediction must match what the compiler DID.
	_, _, diags, err := CompileFileDiag(cramped, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	bt := 0
	for _, b := range diags[0].Buckets {
		if b.Type == "bt-fallback" {
			bt++
		}
	}
	if bt == 0 {
		t.Error("predicate says Backtracking, but the compiler emitted no bt-fallback bucket")
	}
}

// TestFindFromModeString covers the Stringer, which exists for diagnostics and
// panic messages — the places where a mode is printed precisely because
// something has already gone wrong.
//
// The UNSET case is the point of it: findFromMode's zero value is invalid on
// purpose, so a find emitter that never claimed a mode is a BUILD failure
// rather than a silently wrong scan start.
func TestFindFromModeString(t *testing.T) {
	for _, c := range []struct {
		mode findFromMode
		want string
	}{
		{ffLegacyNarrow, "legacy-narrow"},
		{ffNative, "native"},
		{ffAnchoredZeroOnly, "anchored-zero-only"},
		{findFromMode(0), "UNSET"},
		{findFromMode(99), "UNSET"},
	} {
		if got := c.mode.String(); got != c.want {
			t.Errorf("mode %d: String() = %q, want %q", c.mode, got, c.want)
		}
	}
}

// TestAnalyseLitChainBranch covers the analysis that decides whether a pattern
// is a literal chain — a literal followed by a fixed-count class run, which
// lets the find body anchor on the literal and verify outward instead of
// walking every start position.
//
// It is a pure predicate over a parsed pattern, so the shapes it must REFUSE
// are as much of its contract as the ones it accepts, and refusals are what a
// compile matrix reaches least: a pattern it declines simply takes another
// path and nothing records why.
func TestAnalyseLitChainBranch(t *testing.T) {
	for _, c := range []struct {
		pattern string
		want    bool
		why     string
	}{
		// The shape is LITERAL first, then a fixed-count class run — the
		// `AKIA[A-Z0-9]{16}` family. A run BEFORE the literal is a different
		// analysis (the prefixed variants next door).
		{`ghp_[A-Za-z0-9]{36}`, true, "literal then a long fixed run"},
		{`AKIA[A-Z0-9]{16}`, true, "the same shape, shorter run"},
		{`x[a-z]{24}`, true, "a single-byte literal is still a literal"},
		{`[0-9]{8}ghp_`, false, "run BEFORE the literal: the prefixed analysis, not this one"},
		{`[a-z]{24}x`, false, "literal AFTER the run, likewise"},
		{`ghp_[A-Za-z0-9]+`, false, "unbounded run, so no fixed width to anchor on"},
		{`ghp_[A-Za-z0-9]{2,8}`, false, "a RANGE rather than a fixed count"},
		{`abc`, false, "a bare literal has no class run"},
		{`[0-9]{30}`, false, "a class run with no literal to anchor on"},
	} {
		t.Run(c.pattern, func(t *testing.T) {
			re, err := syntax.Parse(c.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// The RAW parse, not re.Simplify(): simplification expands {36}
			// into thirty-six concatenated copies and destroys the Repeat node
			// this analyser matches on. analyseLitChainRe passes the raw tree
			// for exactly that reason.
			info, ok := analyseLitChainBranch(re)
			if ok != c.want {
				t.Errorf("analyseLitChainBranch(%q) = %v, want %v (%s)",
					c.pattern, ok, c.want, c.why)
			}
			if ok && info == nil {
				t.Errorf("%q: reported success with no info", c.pattern)
			}
			if ok && len(info.literal) == 0 {
				t.Errorf("%q: reported a literal chain with an empty literal", c.pattern)
			}
		})
	}
}

// TestNeedsUnicodeSupportExported covers the EXPORTED predicate, which takes a
// pattern string.
//
// compile_api_test.go has a same-named test, but it drives an internal helper over
// a *syntax.Prog — so the exported entry point, the one every fuzz target in
// tools/ calls to decide what to skip, had no test at all. A raw byte scan
// would not do: `\x{263A}` is pure ASCII text that denotes a non-ASCII
// codepoint once parsed, which is the whole reason this function exists
// instead of each caller checking bytes.
func TestNeedsUnicodeSupportExported(t *testing.T) {
	for _, c := range []struct {
		pattern string
		want    bool
	}{
		{`abc`, false},
		{`[a-z]+`, false},
		{`\d{4}`, false},
		{`\x{263A}`, true},
		{`\p{Greek}`, true},
	} {
		got, err := NeedsUnicodeSupport(c.pattern)
		if err != nil {
			t.Errorf("%q: %v", c.pattern, err)
			continue
		}
		if got != c.want {
			t.Errorf("NeedsUnicodeSupport(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
	if _, err := NeedsUnicodeSupport(`(`); err == nil {
		t.Error("an unparseable pattern must report an error rather than a verdict")
	}
}

// TestCompileForcedSelectsTheNamedEngine covers CompileForced, the entry point
// that overrides engine selection for capture paths.
//
// It exists so a differential test can compile the SAME pattern on TDFA and on
// Backtracking and compare — which is only meaningful if the override is
// actually honoured, and nothing here checked that it was.
func TestCompileForcedSelectsTheNamedEngine(t *testing.T) {
	entries := []config.RegexEntry{
		{Name: "p", Pattern: `(a+)(b+)`, GroupsFunc: "p_groups"},
	}
	for _, forced := range []EngineType{EngineTDFA, EngineBacktrack} {
		wasm, _, err := CompileForced(entries, 65536, true, forced)
		if err != nil {
			t.Fatalf("CompileForced(%v): %v", forced, err)
		}
		if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
			t.Fatalf("CompileForced(%v): not a WASM module", forced)
		}
		if !strings.Contains(string(wasm), "p_groups") {
			t.Errorf("CompileForced(%v): module does not export p_groups", forced)
		}
	}
}

// TestFindFromWrapperBodyAllModes covers buildFindFromWrapperBody in each of
// its three modes.
//
// The wrapper is what gives every exported `find` its (ptr, len, from)
// signature while the BODY keeps (ptr, len) — hundreds of hardcoded local
// indices depend on that — so the mode decides whether `from` travels through
// the module-level global, is consumed natively, or is answered without
// calling the body at all. Only the modes a compiled pattern happens to select
// were reached; a mode is a contract, so all three are pinned here.
func TestFindFromWrapperBodyAllModes(t *testing.T) {
	// minLen 0 and 11 both, since a non-zero one adds the early exit and that
	// arm has its own `end` to get right.
	for _, mode := range []findFromMode{ffLegacyNarrow, ffNative, ffAnchoredZeroOnly} {
		for _, minLen := range []int32{0, 11} {
			t.Run(fmt.Sprintf("%v/minLen=%d", mode, minLen), func(t *testing.T) {
				checkFindFromWrapperBody(t, mode, minLen)
			})
		}
	}
}

func checkFindFromWrapperBody(t *testing.T, mode findFromMode, minLen int32) {
	{
		body := buildFindFromWrapperBody(7, mode, minLen)
		if len(body) == 0 {
			t.Fatalf("mode %v: emitted nothing", mode)
		}
		if body[len(body)-1] != 0x0B {
			t.Errorf("mode %v: body does not end with `end` (0x0B), got %#x",
				mode, body[len(body)-1])
		}
		// The local declaration is the first byte: legacy-narrow needs an i64
		// scratch to hold the body's packed return while it is rebased; the
		// other two need no locals at all. Getting this wrong is a validation
		// error, but only once the module is instantiated.
		wantLocals := byte(0x00)
		if mode == ffLegacyNarrow {
			wantLocals = 0x01
		}
		if body[0] != wantLocals {
			t.Errorf("mode %v: local-group count %#x, want %#x", mode, body[0], wantLocals)
		}
	}
}

// TestBuildFindFromWrapperBodyRejectsUnsetMode: findFromMode's zero value is
// invalid ON PURPOSE, so an emitter that never claimed a mode must be a BUILD
// failure rather than a silently wrong scan start. That is what the panic is
// for, and an unexercised panic is a promise nobody has checked.
func TestBuildFindFromWrapperBodyRejectsUnsetMode(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("an unset mode was accepted; the zero value is supposed to be invalid")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "UNSET") {
			t.Errorf("panic message %q does not name the offending mode", msg)
		}
	}()
	buildFindFromWrapperBody(7, findFromMode(0), 0)
}

// TestEmitFindCallFromPos covers the shared call sequence the BATCH wrappers
// use, in both the modes that reach it.
//
// It is shared between the batch find and batch groups wrappers precisely so
// the two cannot end up with subtly different calling conventions — which
// makes it worth pinning that each mode emits something, and that the
// anchored-zero-only mode emits MORE (it has to answer "no match" for pos != 0
// without calling the body at all).
func TestEmitFindCallFromPos(t *testing.T) {
	native := emitFindCallFromPos(nil, 7, ffNative, 4, 5)
	anchored := emitFindCallFromPos(nil, 7, ffAnchoredZeroOnly, 4, 5)
	legacy := emitFindCallFromPos(nil, 7, ffLegacyNarrow, 4, 5)
	for name, got := range map[string][]byte{
		"native": native, "anchored-zero-only": anchored, "legacy-narrow": legacy,
	} {
		if len(got) == 0 {
			t.Errorf("mode %s: emitted nothing", name)
		}
	}
	if len(anchored) <= len(native) {
		t.Errorf("anchored-zero-only emitted %d bytes, native %d: the anchored mode "+
			"must add the pos != 0 guard that answers without calling the body",
			len(anchored), len(native))
	}
}

// TestLocalAllocReproducesHandWrittenGroups pins the property that let the
// conversion of the find emitters be proved by byte identity: allocation order
// is declaration order, and adjacent allocations of one type coalesce into a
// single group.
func TestLocalAllocReproducesHandWrittenGroups(t *testing.T) {
	cases := []struct {
		name string
		fill func(*localAlloc)
		want []byte
	}{
		{"3 i32 + 7 v128 (strict alt)", func(a *localAlloc) {
			a.Reserve(valI32, 3)
			a.Reserve(valV128, 7)
		}, []byte{0x02, 0x03, 0x7F, 0x07, 0x7B}},
		{"7 i32 + 5 v128 + 2 i32 (lenient alt)", func(a *localAlloc) {
			a.Reserve(valI32, 7)
			a.Reserve(valV128, 5)
			a.Reserve(valI32, 2)
		}, []byte{0x03, 0x07, 0x7F, 0x05, 0x7B, 0x02, 0x7F}},
		{"an i32 run split by a cursor still coalesces", func(a *localAlloc) {
			a.Reserve(valI32, 5)
			a.ScanCursor()
			a.Reserve(valI32, 1)
		}, []byte{0x01, 0x07, 0x7F}},
		{"zero-count groups are skipped", func(a *localAlloc) {
			a.Reserve(valI32, 7)
			a.Reserve(valV128, 0)
			a.Reserve(valI32, 0)
		}, []byte{0x01, 0x07, 0x7F}},
		{"no locals at all", func(a *localAlloc) {}, []byte{0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newLocalAlloc(2)
			c.fill(a)
			got := a.EmitDecls(nil)
			if string(got) != string(c.want) {
				t.Errorf("declaration vector\n got  % x\n want % x", got, c.want)
			}
		})
	}
}

// TestScanCursorIndicesFollowAllocation checks the cursor names the local the
// allocation actually gave it — the fact emitFindFromSeed now relies on.
func TestScanCursorIndicesFollowAllocation(t *testing.T) {
	a := newLocalAlloc(2)
	a.Reserve(valI32, 2) // 2, 3
	cur := a.ScanCursor()
	if got := cur.Local(); got != 4 {
		t.Errorf("cursor local = %d, want 4", got)
	}
	if next := a.I32(); next != 5 {
		t.Errorf("allocation after cursor = %d, want 5", next)
	}
}

// TestZeroScanCursorIsRefused is the seal.
//
// wlocals.Cursor's fields are unexported and the package exports no
// constructor, so the only cursor an emitter in this package can write down is
// the zero value — and that one is refused. Seeding a local of one's choosing
// is therefore not expressible, which is the whole point: naming the wrong
// local produced a module that validated, answered from == 0 correctly, and
// ignored `from` for ever after, twice.
func TestZeroScanCursorIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a zero scanCursor was accepted; the seal is not holding")
		}
	}()
	var forged wlocals.Cursor
	_, _ = emitFindFromSeed(nil, forged)
}

// TestModuleGlobalsZeroValueIsOneGlobal pins the property that let the
// allocator be introduced without moving a single byteident fixture: its ZERO
// VALUE must describe exactly the module shape that existed before it — one
// mutable i32 global, the find-from channel, initialised to 0.
//
// If this drifts, every module in the compiler changes size and every fixture
// moves at once, which is a loud failure. The quiet one it also guards against
// is Count() disagreeing with Section(): the indices Alloc hands out are only
// meaningful because the same counter produces the declarations.
func TestModuleGlobalsZeroValueIsOneGlobal(t *testing.T) {
	var g moduleGlobals
	if got := g.Count(); got != 1 {
		t.Errorf("zero value Count() = %d, want 1 (the find-from channel)", got)
	}
	want := []byte{
		0x01,       // one global
		0x7F, 0x01, // mut i32
		0x41, 0x00, // i32.const 0
		0x0B, // end of init expr
	}
	if got := g.Section(); !bytes.Equal(got, want) {
		t.Errorf("zero value Section() = % x, want % x", got, want)
	}
	// The pre-allocator emitter must stay identical to it, since both are
	// still called and a difference would be a silent module-shape change.
	if got := findFromGlobalSection(); !bytes.Equal(got, want) {
		t.Errorf("findFromGlobalSection() = % x, want % x", got, want)
	}
}

// TestModuleGlobalsAlloc checks that indices start above the find-from channel,
// rise in allocation order, and that every one of them is backed by a
// declaration.
//
// The last part is the invariant that matters. An index without a declaration
// does not corrupt anything — the module fails WASM validation at load — but it
// fails for every caller at once, so it is worth catching here.
func TestModuleGlobalsAlloc(t *testing.T) {
	var g moduleGlobals
	var got []uint32
	for i := 0; i < 4; i++ {
		got = append(got, g.Alloc())
	}
	want := []uint32{1, 2, 3, 4}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Alloc #%d = %d, want %d (index 0 is find-from)", i, got[i], want[i])
		}
		if got[i] == findFromGlobalIdx {
			t.Fatalf("Alloc #%d returned the find-from index %d", i, findFromGlobalIdx)
		}
	}
	if c := g.Count(); c != 5 {
		t.Fatalf("Count() after 4 allocations = %d, want 5", c)
	}
	sec := g.Section()
	if sec[0] != 5 {
		t.Errorf("Section() declares %d globals, want 5", sec[0])
	}
	// One 5-byte declaration per global, after the count byte.
	if len(sec) != 1+5*5 {
		t.Errorf("Section() is %d bytes, want %d (count + 5 declarations)", len(sec), 1+5*5)
	}
	for i := uint32(0); i < g.Count(); i++ {
		off := 1 + 5*i
		decl := sec[off : off+5]
		want := []byte{0x7F, 0x01, 0x41, 0x00, 0x0B}
		if !bytes.Equal(decl, want) {
			t.Errorf("global %d declared as % x, want % x (mut i32, init 0)", i, decl, want)
		}
	}
}

// The allocator's contract, checked directly.
//
// The conversion of CompileSet is proved by byte identity — the nine set
// fixtures under testdata/byteident are unchanged by it — but byte identity
// says only that the addresses came out the same. It cannot show that the
// allocator REFUSES the mistakes it exists to refuse, because a correct input
// never triggers them. These do.

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("no panic; wanted one mentioning %q", want)
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, want) {
			t.Fatalf("panic %v, wanted one mentioning %q", r, want)
		}
	}()
	fn()
}

func TestRegionAllocBumpsSequentially(t *testing.T) {
	ra := newRegionAlloc(100)
	if got := ra.Bump("a", 10, 1); got != 100 {
		t.Errorf("first base = %d, want 100", got)
	}
	if got := ra.Bump("b", 10, 1); got != 110 {
		t.Errorf("second base = %d, want 110", got)
	}
	if got := ra.End(); got != 120 {
		t.Errorf("end = %d, want 120", got)
	}
}

func TestRegionAllocAligns(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 1, 1) // 100..101
	if got := ra.Reserve("b", 8); got != 104 {
		t.Errorf("8-aligned base = %d, want 104", got)
	}
	ra.Commit(112)
	if got := ra.End(); got != 112 {
		t.Errorf("end = %d, want 112", got)
	}
}

// A region that ends BELOW where it was reserved means the builder laid its
// table somewhere other than where it was told. Clamping would leave a region
// nobody owns while hiding the discrepancy.
func TestRegionAllocRefusesBackwardCommit(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "below the base", func() { ra.Commit(90) })
}

// Two regions in flight is the shape that produces an overlap: the second base
// would be handed out before the first block's extent is known.
func TestRegionAllocRefusesOverlappingReserve(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "still uncommitted", func() { ra.Reserve("b", 1) })
}

func TestRegionAllocRefusesStrayCommit(t *testing.T) {
	ra := newRegionAlloc(100)
	mustPanic(t, "no Reserve outstanding", func() { ra.Commit(120) })
}

func TestRegionAllocRefusesEndWhilePending(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Reserve("a", 1)
	mustPanic(t, "still uncommitted", func() { ra.End() })
}

// Skip is how a block that reserved a region and then found it unnecessary
// gives the address space back — the union-scan and phase-2 blocks both do it
// when their builder declines.
func TestRegionAllocSkipLeavesFrontier(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 10, 1)
	ra.Reserve("b", 8)
	ra.Skip()
	if got := ra.End(); got != 110 {
		t.Errorf("end after Skip = %d, want 110", got)
	}
	if got := ra.Bump("c", 4, 1); got != 110 {
		t.Errorf("base after Skip = %d, want 110", got)
	}
}
