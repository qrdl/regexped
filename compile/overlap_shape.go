package compile

import (
	"github.com/qrdl/regexped/config"
)

// OverlapCacheShape is what a STUB GENERATOR needs in order to size an
// overlapping set's answer cache, and the only thing `generate` is allowed to
// learn about a compiled set.
//
// WHY THIS EXISTS AT ALL. The checkpointed cache's size depends on the sweep
// column's width, which falls out of the DFA subset construction and is not
// derivable from the YAML: `generate` can count patterns but cannot know how
// many states their merged automaton has. So `generate` RECOMPILES the set and
// reads the number off the result, rather than the compiler exporting a sizing
// function into the module or the stub baking in a constant that goes stale.
//
// WHY IT RETURNS CELLS AND NOT A STATE COUNT. `cells` is the column WIDTH —
// states x patterns today, projected states under §19's lever C. Returning the
// width rather than its factors keeps every stub and both harnesses indifferent
// to which of those the compiler is doing.
type OverlapCacheShape struct {
	// Eligible is false when this set gets no backward sweep, which is the
	// ORDINARY case and not an error: the sweep is emitted only for an
	// overlapping set with `find`, one fallback bucket, a dense accept mask, no
	// Backtracking member, no word-boundary or newline channel, u8 state ids,
	// and states x patterns within the column bound. A caller that gets false
	// reserves no cache and the drive walks, exactly as today.
	Eligible bool

	// Cells is the sweep column's width. Region arithmetic lives in config
	// (SetOverlapCheckpointBytes); this is its input.
	Cells int

	// Patterns is the bucket's pattern count, which sizes one position's worth
	// of block buffer. It is NOT the set's declared pattern count and NOT its
	// id space: a set whose members were dropped or packed elsewhere has fewer
	// here, and sizing off the wrong one over-reserves or under-reserves.
	Patterns int
}

// SetOverlapCacheShape compiles `sc` and reports what sizing its `find` needs.
//
// THE HAZARD THIS FUNCTION IS BUILT AROUND. It recompiles a set that the real
// build also compiles, so the two must agree EXACTLY — a different automaton
// means a region sized for the wrong sweep. `CmdWriteDiagJSON` re-runs
// CompileSet the same way and shipped a bug by omitting the set's LikelyMode,
// reporting the neutral frontend and body whatever the config's `hints:` said.
// So the options are built by setCompileOptions, the SAME helper CompileFile
// uses, rather than assembled here.
func SetOverlapCacheShape(sc config.SetConfig, cfg config.BuildConfig) (OverlapCacheShape, error) {
	cs, err := compileSetForInspection(sc, cfg)
	if err != nil {
		return OverlapCacheShape{}, err
	}
	bi := cs.overlapDPBucket()
	if bi < 0 {
		return OverlapCacheShape{}, nil
	}
	bkt := cs.buckets[bi]
	// Lever C makes the column one cell per PROJECTION rather than per
	// (state, pattern); overlapCells is the one place that decides which, so a
	// caller cannot size a region for a column the sweep does not have.
	return OverlapCacheShape{
		Eligible: true,
		Cells:    cs.overlapCells(),
		Patterns: len(bkt.patterns),
	}, nil
}

// SetOverlapCacheSizing is the region and stride a caller should reserve for one
// set's answer cache over an input of inputLen bytes.
//
// The pair belongs together and is asked for together: the region is sized FROM
// the stride, and the sweep validates the stride against the region it was
// given, so a caller that computed one of them differently is handed back -4.
// Both harnesses and every stub generator want exactly this, and each had its
// own copy of the two config calls.
//
// A set with no sweep gets (header, 1): a nominal region the drive declines,
// which keeps the descriptor's shape the same on every path.
func SetOverlapCacheSizing(sc config.SetConfig, cfg config.BuildConfig, inputLen int) (bytes, stride int, err error) {
	sh, err := SetOverlapCacheShape(sc, cfg)
	if err != nil {
		return 0, 0, err
	}
	if !sh.Eligible {
		return config.SetOverlapCheckpointHeaderBytes, 1, nil
	}
	return config.SetOverlapCheckpointBytes(inputLen, sh.Cells, sh.Patterns),
		config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns), nil
}
