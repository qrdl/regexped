package compile

import (
	"strings"
	"testing"
)

// noSweepSet is a set whose `find` gets no backward sweep: gated rather than
// overlapping. Every accessor below must answer the ORDINARY way for it.
func noSweepSet(t *testing.T) *compiledSet {
	t.Helper()
	spec := SetSpec{Name: "s", Find: "s_find"}
	cs := setEmitCovCompileSet(t, spec, []string{`[0-9][a-c][0-9]`}, CompileSetOptions{})
	if bi := cs.overlapDPBucket(); bi >= 0 {
		t.Fatalf("a gated find got a sweep bucket (%d); this fixture no longer isolates the no-sweep path", bi)
	}
	return cs
}

// TestOverlapAccessorsWithoutSweep covers every derived quantity on a set that
// has no sweep. They are asked for unconditionally by the emitters, so each one
// has to answer rather than assume a bucket exists — and the answers have to be
// the ones that mean "reserve nothing", not zero-sized versions of real ones.
func TestOverlapAccessorsWithoutSweep(t *testing.T) {
	cs := noSweepSet(t)

	if got := cs.overlapCells(); got != 0 {
		t.Errorf("overlapCells() = %d, want 0", got)
	}
	if got := cs.overlapProjFor(); got != nil {
		t.Errorf("overlapProjFor() = %+v, want nil", got)
	}
	// Twice: the memo is set before the bucket is looked up, and a nil pinned by
	// the first call must not be mistaken for a computed projection.
	if got := cs.overlapProjFor(); got != nil {
		t.Errorf("overlapProjFor() on the second call = %+v, want nil", got)
	}
	if got := cs.overlapProjTabBytes(); got != nil {
		t.Errorf("overlapProjTabBytes() = %d bytes, want nil", len(got))
	}
	if got := cs.overlapDPColumnBytes(); got != 0 {
		t.Errorf("overlapDPColumnBytes() = %d, want 0", got)
	}
	// 1, not 0: the trigger DIVIDES by this, and it is compared against work the
	// walk has done, so a zero would either trap or make every drive trigger.
	if got := cs.overlapSweepCostPerByte(); got != 1 {
		t.Errorf("overlapSweepCostPerByte() = %d, want 1", got)
	}
}

// TestBuildOverlapProjDeclines covers each guard on the projection builder.
//
// Every one of them returns the PLAIN column, which is correct at every width —
// declining is the safe direction, and a guard that stopped firing would read a
// table it cannot read and merge states that are not equivalent, which is a
// wrong extent with nothing to signal it.
func TestBuildOverlapProjDeclines(t *testing.T) {
	// A real, projectable bucket to degrade from, so each case below differs
	// from a WORKING one in exactly the field it names.
	spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}
	cs := setEmitCovCompileSet(t, spec, []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}, CompileSetOptions{})
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("the reference bucket gets no sweep; nothing here degrades from a working case")
	}
	good := cs.buckets[bi].dp
	numPat := len(cs.buckets[bi].patterns)
	if buildOverlapProj(good, numPat) == nil {
		t.Fatal("the reference bucket declined the projection; the guards below prove nothing")
	}

	for _, tc := range []struct {
		name string
		dp   func(overlapDPTables) overlapDPTables
		pats int
	}{
		{"not-ok", func(d overlapDPTables) overlapDPTables { d.ok = false; return d }, numPat},
		{"no-layout", func(d overlapDPTables) overlapDPTables { d.l = nil; return d }, numPat},
		{"no-mid-masks", func(d overlapDPTables) overlapDPTables { d.midMasks = nil; return d }, numPat},
		{"no-eof-masks", func(d overlapDPTables) overlapDPTables { d.eofMasks = nil; return d }, numPat},
		{"one-state", func(d overlapDPTables) overlapDPTables { d.numWASM = 1; return d }, numPat},
		{"no-patterns", func(d overlapDPTables) overlapDPTables { return d }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildOverlapProj(tc.dp(good), tc.pats); got != nil {
				t.Errorf("buildOverlapProj declined nothing: got %d cells", got.cells)
			}
		})
	}

	// The two LAYOUT refusals need their own copy: dfaLayout is shared by
	// pointer, so flipping a flag in place would corrupt the reference bucket.
	for _, tc := range []struct {
		name  string
		mutex func(*dfaLayout)
	}{
		{"row-dedup", func(l *dfaLayout) { l.useRowDedup = true }},
		{"u16-ids", func(l *dfaLayout) { l.useU8 = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := *good.l
			tc.mutex(&layout)
			d := good
			d.l = &layout
			if got := buildOverlapProj(d, numPat); got != nil {
				t.Errorf("buildOverlapProj read a layout it cannot read: got %d cells", got.cells)
			}
		})
	}
}

// TestBuildOverlapProjPanicsOnGeometryMismatch pins the transition-table bounds
// check. It is not recoverable and must not be guessed at: answering "dead" for
// an out-of-range cell would turn a geometry mismatch into MISSING MATCHES.
func TestBuildOverlapProjPanicsOnGeometryMismatch(t *testing.T) {
	spec := SetSpec{Name: "s", Find: "s_find", Overlapping: true}
	cs := setEmitCovCompileSet(t, spec, []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}, CompileSetOptions{})
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("no sweep bucket to mismatch")
	}
	good := cs.buckets[bi].dp

	// A table SHORTER than numWASM x cellsPerState: the same disagreement a
	// layout change would introduce.
	layout := *good.l
	layout.tableBytes = layout.tableBytes[:len(layout.tableBytes)/2]
	d := good
	d.l = &layout

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("buildOverlapProj read past the transition table without panicking")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "overlap projection") {
			t.Errorf("panic = %q, want it to name the projection", msg)
		}
	}()
	buildOverlapProj(d, len(cs.buckets[bi].patterns))
}
