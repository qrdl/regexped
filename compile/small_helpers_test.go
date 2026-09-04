package compile

import (
	"bytes"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
)

// Small helpers whose second branch no ordinary compile selects. Each is one
// or two statements, but each is also a decision the emitted module depends on
// — a memory index, a released region, a test-only override — and an untested
// branch in any of them fails silently rather than loudly.

// TestAppendTableLoadV128At covers both memory forms of the v128 table load.
//
// Standalone modules keep their tables in memory 0 and use the short encoding;
// embedded ones import the host's memory as 0 and their tables become memory 1
// after wasm-merge, which needs the multi-memory form with an explicit index.
// Emitting the short form for an embedded module would read the HOST's memory
// at the table's offset.
func TestAppendTableLoadV128At(t *testing.T) {
	standalone := appendTableLoadV128At(nil, 0x1234, 0)
	embedded := appendTableLoadV128At(nil, 0x1234, 1)

	// v128.load is 0xFD 0x00; then the memarg. The standalone form has align
	// 0 and no memory index; the embedded one sets the multi-memory flag.
	if len(standalone) < 3 || standalone[0] != 0xFD || standalone[1] != 0x00 {
		t.Fatalf("standalone form does not start with v128.load: % x", standalone)
	}
	if standalone[2] != 0x00 {
		t.Errorf("standalone align byte = %#x, want 0x00", standalone[2])
	}
	if len(embedded) < 4 || embedded[2] != 0x40 {
		t.Fatalf("embedded form does not set the multi-memory flag: % x", embedded)
	}
	if embedded[3] != 0x01 {
		t.Errorf("embedded memory index = %d, want 1", embedded[3])
	}
	// Both must encode the same offset, so the only difference is the memarg.
	if off, _, err := utils.DecodeULEB128(standalone[3:]); err != nil || off != 0x1234 {
		t.Errorf("standalone offset = %d (%v), want 0x1234", off, err)
	}
	if off, _, err := utils.DecodeULEB128(embedded[4:]); err != nil || off != 0x1234 {
		t.Errorf("embedded offset = %d (%v), want 0x1234", off, err)
	}
	if bytes.Equal(standalone, embedded) {
		t.Error("both memory forms emitted identical bytes")
	}
}

// TestRegionAllocSkip covers the release path: a region reserved and then not
// needed must leave the frontier exactly where it was, alignment included, or
// every later region shifts and the tables overlap.
func TestRegionAllocSkip(t *testing.T) {
	ra := newRegionAlloc(100)
	ra.Bump("a", 10, 1)
	before := ra.End()

	ra.Reserve("maybe", 64)
	ra.Skip()
	if got := ra.End(); got != before {
		t.Errorf("End() after Skip = %d, want %d — a skipped region moved the frontier",
			got, before)
	}
	// The allocator must be usable again immediately.
	if got := ra.Bump("b", 8, 1); got != before {
		t.Errorf("next Bump after Skip = %d, want %d", got, before)
	}

	// Skipping with nothing outstanding is an emitter bug, not a no-op.
	ra2 := newRegionAlloc(0)
	mustPanic(t, "Skip with no Reserve", func() { ra2.Skip() })
}

// TestCompileSetOptionsOverrides covers the two test-only knobs.
//
// Both exist because `false` is simultaneously a meaningful setting and the
// zero value, so each carries a separate "was it asked for" flag. A With
// method that forgot to set that flag would look like it worked and change
// nothing.
func TestCompileSetOptionsOverrides(t *testing.T) {
	var zero CompileSetOptions
	if zero.forceFrontend || zero.forceShuftiAdaptive {
		t.Fatal("the zero value already claims an override")
	}

	fe := zero.WithForcedFrontend(frontendShufti)
	if !fe.forceFrontend || fe.ForceFrontend != frontendShufti {
		t.Errorf("WithForcedFrontend: flag=%v value=%v", fe.forceFrontend, fe.ForceFrontend)
	}
	// Forcing the ZERO frontend kind must still register as an override.
	fe0 := zero.WithForcedFrontend(0)
	if !fe0.forceFrontend {
		t.Error("WithForcedFrontend(0) did not record that an override was asked for")
	}

	for _, on := range []bool{true, false} {
		sa := zero.WithShuftiAdaptive(on)
		if !sa.forceShuftiAdaptive || sa.ForceShuftiAdaptive != on {
			t.Errorf("WithShuftiAdaptive(%v): flag=%v value=%v",
				on, sa.forceShuftiAdaptive, sa.ForceShuftiAdaptive)
		}
	}
	// The receiver is a value, so the original must be untouched.
	if zero.forceFrontend || zero.forceShuftiAdaptive {
		t.Error("a With method mutated its receiver")
	}
}

// TestDominantWalkStatesEdges covers the empty-table guard, which is the arm a
// caller reaches when a pattern compiled to nothing at all.
func TestDominantWalkStatesEdges(t *testing.T) {
	if got := dominantWalkStates(nil); got != nil {
		t.Errorf("dominantWalkStates(nil) = %v, want nil", got)
	}
	if got := dominantWalkStates(&dfaTable{}); got != nil {
		t.Errorf("dominantWalkStates(empty) = %v, want nil", got)
	}
	// A real table must report at least one state, or this test is passing on
	// the guards alone. The shape has to be a state that self-loops on nearly
	// EVERY byte with a handful of exceptions — the polarity this detector
	// wants — rather than a narrow class like [a-z], whose 230 exceptions put
	// it far past dominantMaxExceptions.
	tbl := compileTestDFA(t, `"[^"]*"`, true)
	if got := dominantWalkStates(tbl); len(got) == 0 {
		t.Error("a pattern with a wide self-loop reported no dominant walk states")
	}
}
