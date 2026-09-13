package compile

import (
	"testing"

	"github.com/qrdl/regexped/config"
)

// overlapShapeCfg is a set whose `find` gets the backward sweep: overlapping,
// one fallback bucket, literal-less members so no frontend claims them.
func overlapShapeCfg() (config.SetConfig, config.BuildConfig) {
	patterns := []string{`[0-9][a-c][0-9]`, `[a-c][0-9][a-c]`}
	cfg := config.BuildConfig{Regexps: setEmitCovEntries(patterns)}
	sc := config.SetConfig{
		Name:        "s",
		Find:        "s_find",
		Overlapping: true,
		Patterns:    config.PatternSelector{All: true},
	}
	cfg.Sets = []config.SetConfig{sc}
	return sc, cfg
}

// TestSetOverlapCacheShapeEligible pins the sizing API a stub generator reads.
// It RECOMPILES the set, so what it reports has to be the automaton the real
// build gets — the numbers are cross-checked against the compiled set here for
// that reason, not because either one is interesting on its own.
func TestSetOverlapCacheShapeEligible(t *testing.T) {
	sc, cfg := overlapShapeCfg()
	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible {
		t.Fatal("the sweep refused a literal-less overlapping set; the sizing path is unreachable")
	}

	cs, err := compileSetForInspection(sc, cfg, CompileSetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bi := cs.overlapDPBucket()
	if bi < 0 {
		t.Fatal("inspection and SetOverlapCacheShape disagree about eligibility")
	}
	if got, want := sh.Cells, cs.overlapCells(); got != want {
		t.Errorf("Cells = %d, want the column width %d", got, want)
	}
	if got, want := sh.Patterns, len(cs.buckets[bi].patterns); got != want {
		t.Errorf("Patterns = %d, want the BUCKET's count %d", got, want)
	}

	// And the pair a caller actually asks for: the region is sized FROM the
	// stride, so the two must come from the same shape or the sweep rejects the
	// descriptor it is handed.
	const inputLen = 4096
	bytes, stride, err := SetOverlapCacheSizing(sc, cfg, inputLen)
	if err != nil {
		t.Fatal(err)
	}
	if want := config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns); stride != want {
		t.Errorf("stride = %d, want %d", stride, want)
	}
	if want := config.SetOverlapCheckpointBytes(inputLen, sh.Cells, sh.Patterns); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}
	if bytes <= config.SetOverlapCheckpointHeaderBytes {
		t.Errorf("bytes = %d, which is no more than the header: nothing was reserved", bytes)
	}
}

// TestSetOverlapCacheShapeIneligible covers the ORDINARY answer. A set with no
// sweep is not an error, and the nominal (header, 1) sizing keeps the
// descriptor's shape identical on both paths so a stub has one code path.
func TestSetOverlapCacheShapeIneligible(t *testing.T) {
	// Not overlapping: gated `find` gets no sweep.
	cfg := config.BuildConfig{Regexps: setEmitCovEntries([]string{`[0-9][a-c][0-9]`})}
	sc := config.SetConfig{Name: "s", Find: "s_find", Patterns: config.PatternSelector{All: true}}
	cfg.Sets = []config.SetConfig{sc}

	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Eligible {
		t.Fatal("a gated find reported a sweep")
	}
	if sh.Cells != 0 || sh.Patterns != 0 {
		t.Errorf("ineligible shape carries sizing: %+v", sh)
	}

	bytes, stride, err := SetOverlapCacheSizing(sc, cfg, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != config.SetOverlapCheckpointHeaderBytes || stride != 1 {
		t.Errorf("sizing = (%d, %d), want the nominal (%d, 1)",
			bytes, stride, config.SetOverlapCheckpointHeaderBytes)
	}
}

// TestSetOverlapCacheShapeCompileError covers the error arm of both. A set the
// compiler refuses must report, not answer with a zero shape a caller would
// read as "no cache needed".
func TestSetOverlapCacheShapeCompileError(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "bad", Pattern: `(?P<x>`}},
	}
	sc := config.SetConfig{
		Name: "s", Find: "s_find", Overlapping: true,
		Patterns: config.PatternSelector{All: true},
	}
	cfg.Sets = []config.SetConfig{sc}

	if _, err := SetOverlapCacheShape(sc, cfg); err == nil {
		t.Error("SetOverlapCacheShape accepted an unparseable member")
	}
	if _, _, err := SetOverlapCacheSizing(sc, cfg, 4096); err == nil {
		t.Error("SetOverlapCacheSizing accepted an unparseable member")
	}
}

// TestSetOverlapCacheShapeNamedSubset covers the NAMED selector arm of the
// inspection compile. It is the only configuration in which the set's pattern
// count and its id space differ, and sizing a region off the wrong one is a
// memory-safety fault rather than a wrong answer.
func TestSetOverlapCacheShapeNamedSubset(t *testing.T) {
	patterns := []string{`[0-9][a-c][0-9]`, `[a-c][0-9][a-c]`, `[0-9][0-9][a-c]`}
	cfg := config.BuildConfig{Regexps: setEmitCovEntries(patterns)}
	// The LAST two, so the ids the set reports are 1 and 2 while it holds two
	// patterns.
	sc := config.SetConfig{
		Name: "s", Find: "s_find", Overlapping: true,
		Patterns: config.PatternSelector{Names: []string{"p01", "p02"}},
	}
	cfg.Sets = []config.SetConfig{sc}

	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible {
		t.Fatal("the sweep refused the named subset")
	}
	if sh.Patterns != 2 {
		t.Errorf("Patterns = %d, want the 2 the bucket holds (not the 3-wide id space)", sh.Patterns)
	}

	// An unknown name is an error, not an empty set: an empty set would size a
	// region for a sweep the module does not have.
	bad := sc
	bad.Patterns = config.PatternSelector{Names: []string{"p01", "nope"}}
	if _, err := SetOverlapCacheShape(bad, cfg); err == nil {
		t.Error("SetOverlapCacheShape accepted an unknown pattern name")
	}
}

// TestSetOverlapCacheShapeHandComputed pins one shape by hand. The test above
// compares SetOverlapCacheShape with compileSetForInspection, which is where the
// shape reads its own numbers, so it cannot notice both drifting together:
// {a+, [^\n]*ERROR} is 9 cells over a 2-pattern bucket, and sweeping a byte
// costs two cells' worth.
func TestSetOverlapCacheShapeHandComputed(t *testing.T) {
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{{Name: "p0", Pattern: `a+`}, {Name: "p1", Pattern: `[^\n]*ERROR`}},
		Sets: []config.SetConfig{{
			Name: "s", Find: "s_find", Overlapping: true,
			Patterns: config.PatternSelector{All: true},
		}},
	}
	sh, err := SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !sh.Eligible || sh.Cells != 9 || sh.Patterns != 2 || sh.CostPerByte != 18 {
		t.Errorf("shape = %+v, want eligible, 9 cells, 2 patterns, cost 18 per byte", sh)
	}
}
