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
// states x patterns, or fewer cells when the column is projected (see
// set_overlap_proj.go). Returning the
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

	// CostPerByte is the trigger's per-byte rate in the drive's work units: a
	// sixteenth of what sweeping one input byte costs (at least 1), so a
	// drive switches long before its walk has cost a sweep. The engine
	// engages the sweep once the walk's accumulated work
	// passes SweepThreshold (strictly), or once the counter saturates.
	CostPerByte int64
	// SetupWork is the start-up allowance added to the line, at the full
	// per-byte rate.
	SetupWork int64

	// SweepCells and SweepRow are the program sweep's geometry
	// (program_sweep.go), 0 when no split member has one: its column width
	// and a position's row, 4 bytes per swept member. Its answers live after
	// the cache in the same region, checkpointed by the same formula
	// (config.SetOverlapCheckpointSizingRow), so a caller reserves both.
	SweepCells, SweepRow int
}

// Offered reports whether a caller reserves a region for this set's `find`
// at all: for the answer cache, or for the program sweep alone (the cache's
// part is then the bare header).
func (sh OverlapCacheShape) Offered() bool { return sh.Eligible || sh.SweepCells > 0 }

// SweepThreshold is the work past which a drive over inputLen bytes engages
// the sweep: CostPerByte per byte plus SetupWork for starting one. A
// harness asking whether a drive SHOULD have engaged reads it here rather than
// re-deriving the engine's rule.
func (sh OverlapCacheShape) SweepThreshold(inputLen int) int64 {
	return int64(inputLen)*sh.CostPerByte + sh.SetupWork
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
	return SetOverlapCacheShapeOpts(sc, cfg, CompileSetOptions{})
}

// SetOverlapCacheShapeOpts is SetOverlapCacheShape for a module compiled through
// CompileFileOpts with the same overrides. A harness that pins a frontend must
// inspect under that pin too: the bucket a set packs into depends on it.
func SetOverlapCacheShapeOpts(sc config.SetConfig, cfg config.BuildConfig, over CompileSetOptions) (OverlapCacheShape, error) {
	cs, err := compileSetForInspection(sc, cfg, over)
	if err != nil {
		return OverlapCacheShape{}, err
	}
	return overlapShapeOf(cs), nil
}

// overlapShapeOf is a compiled set's OverlapCacheShape.
func overlapShapeOf(cs *compiledSet) OverlapCacheShape {
	var sh OverlapCacheShape
	if ps := cs.progSweep; ps != nil {
		sh.SweepCells, sh.SweepRow = ps.cells(), ps.rowBytes()
	}
	if cs.keptCache != nil {
		// The kept members' own set reads the cache (keptCacheSet).
		cs = cs.keptCache
	}
	sw := cs.sweepSrc()
	if sw == nil {
		return sh
	}
	// Lever C makes the column one cell per PROJECTION rather than per
	// (state, pattern); overlapCells is the one place that decides which, so a
	// caller cannot size a region for a column the sweep does not have.
	sh.Eligible = true
	sh.Cells = cs.overlapCells()
	sh.Patterns = len(sw.ids)
	sh.CostPerByte = cs.overlapSweepCostPerByte()
	sh.SetupWork = cs.overlapSweepSetupWork()
	return sh
}

// bytesPerByte is what the region sh sizes costs per input byte while it is
// one block (up to config.SetOverlapCacheMaxBytes): a row per position, the
// answer cache's and the program sweep's. Past that budget the region grows
// with the square root of the input instead.
func (sh OverlapCacheShape) bytesPerByte() int {
	n := sh.SweepRow
	if sh.Eligible {
		n += config.SetOverlapBlockRowBytes(sh.Patterns)
	}
	return n
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
	return SetOverlapCacheSizingOpts(sc, cfg, inputLen, CompileSetOptions{})
}

// SetOverlapCacheSizingOpts is SetOverlapCacheSizing under CompileFileOpts'
// overrides; see SetOverlapCacheShapeOpts.
func SetOverlapCacheSizingOpts(sc config.SetConfig, cfg config.BuildConfig, inputLen int, over CompileSetOptions) (bytes, stride int, err error) {
	sh, err := SetOverlapCacheShapeOpts(sc, cfg, over)
	if err != nil {
		return 0, 0, err
	}
	bytes, stride = sh.Sizing(inputLen)
	return bytes, stride, nil
}

// sizingRegime numbers the formula Sizing takes for inputLen. It changes only
// where one of three switches flips — the cache leaving single-block mode, the
// program sweep's region leaving it, and that region dropping out past the
// budget. The first two flip once as the input grows; the third can flip BACK
// where the sweep's stride steps up (65,535 cells, 252-byte rows: over at
// 17,043,072 bytes, under at 17,043,139, over at 17,043,200), and flips at
// most once while its stride holds. Within one regime Sizing grows with the
// input except where a checkpointed stride steps up (sizingSegment).
func (sh OverlapCacheShape) sizingRegime(inputLen int) int {
	r := 0
	if sh.Eligible && config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns) != inputLen+1 {
		r |= 1
	}
	if sh.SweepCells > 0 {
		sb, k := config.SetOverlapCheckpointSizingRow(inputLen, sh.SweepCells, sh.SweepRow)
		if k != inputLen+1 {
			r |= 2
		}
		if sb > config.SetOverlapCacheMaxBytes {
			r |= 4
		}
	}
	return r
}

// sizingSegment names the stretch of input lengths over which Sizing is
// nondecreasing: the regime, and the stride of each part that checkpoints.
// With its stride fixed a part's region only grows with the input (one more
// checkpoint every stride bytes), but where the stride steps up it can shrink
// by a few bytes — 262,148 → 262,132 at 50,803,199 bytes for 6 cells and 2
// patterns. The strides are nondecreasing in the input, and with them held
// every regime bit flips at most once, so every segment is one stretch of
// lengths. The sweep's stride is kept while its part is over the budget too:
// that is what tells apart the stretches either side of a length where the
// part drops back under it.
func (sh OverlapCacheShape) sizingSegment(inputLen int) [3]int {
	seg := [3]int{sh.sizingRegime(inputLen)}
	if seg[0]&1 != 0 {
		seg[1] = config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns)
	}
	if seg[0]&2 != 0 {
		_, seg[2] = config.SetOverlapCheckpointSizingRow(inputLen, sh.SweepCells, sh.SweepRow)
	}
	return seg
}

// cachePartBytes is the answer cache's own part of the region Sizing gives —
// the bare header for a set with none — which every caller declines when it is
// over config.SetOverlapCacheMaxBytes (the program sweep's part is dropped on
// its own, inside Sizing). A component adds its allocator's 8-byte header.
func (sh OverlapCacheShape) cachePartBytes(inputLen int) int {
	if !sh.Eligible {
		return config.SetOverlapCheckpointHeaderBytes
	}
	return config.SetOverlapCheckpointBytes(inputLen, sh.Cells, sh.Patterns)
}

// Sizing is SetOverlapCacheSizing for a shape already in hand: a caller that
// sizes many drives of one set learns the shape once and asks this per input.
//
// A program sweep's part follows the cache's, 8-aligned, when it fits the
// budget — the sweep keeps it at the region's end, which for this size is
// right after the cache; the stride is the cache's, the one header field a
// caller writes.
func (sh OverlapCacheShape) Sizing(inputLen int) (bytes, stride int) {
	bytes, stride = config.SetOverlapCheckpointHeaderBytes, 1
	if sh.Eligible {
		bytes = config.SetOverlapCheckpointBytes(inputLen, sh.Cells, sh.Patterns)
		stride = config.SetOverlapCheckpointStride(inputLen, sh.Cells, sh.Patterns)
	}
	if sh.SweepCells > 0 {
		if sb, _ := config.SetOverlapCheckpointSizingRow(inputLen, sh.SweepCells, sh.SweepRow); sb <= config.SetOverlapCacheMaxBytes {
			bytes = (bytes+7)&^7 + sb
		}
	}
	return bytes, stride
}
