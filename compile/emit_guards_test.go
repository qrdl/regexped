package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

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

	core, _, err := CompileFileComponent(cfg, "regexped:t/matcher", nil, setComponentNames("s"), nil)
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
