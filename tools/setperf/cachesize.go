package main

import (
	"fmt"
	"sort"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// The CACHE MEMORY axis of plans §19.13a's four-way comparison.
//
// It is COMPUTED, not measured, and that is exact rather than approximate: the
// region is a closed-form function of the input length, the sweep column's
// width and the bucket's pattern count, and the first of those is the only one
// that varies per row. Running a drive to observe it would measure the same
// arithmetic through a slower instrument.
//
// It reports several INPUT SIZES per set on purpose. The whole-drive tuple
// cache is linear in the input and every checkpointed form is square-root in
// it, and at one input size those are just two numbers — the shapes only
// separate across a range. The benchmark corpora are all 100 KB, so the sizes
// here are hypothetical inputs for the same set, which is what makes the
// growth column readable.

var cacheSizeInputs = []struct {
	label string
	n     int
}{
	{"100KB", 100 << 10},
	{"1MB", 1 << 20},
	{"10MB", 10 << 20},
	{"100MB", 100 << 20},
}

// reportCacheSizes prints one line per (set, input size) with the region each
// configuration of §19.13a would reserve.
//
// Sets that get no sweep are reported too, with their reason implied by
// "not eligible", because a silently missing row reads as a set that was
// forgotten rather than one the compiler declined.
func reportCacheSizes() error {
	seen := map[string]bool{}
	var names []string
	shapes := map[string]compile.OverlapCacheShape{}

	for _, c := range buildMatrix() {
		if seen[c.name] {
			continue
		}
		seen[c.name] = true
		names = append(names, c.name)

		entries := make([]config.RegexEntry, len(c.patterns))
		pnames := make([]string, len(c.patterns))
		for i, p := range c.patterns {
			pnames[i] = fmt.Sprintf("p%d", i)
			entries[i] = config.RegexEntry{Name: pnames[i], Pattern: p}
		}
		sh, err := overlapShapeFor(c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		shapes[c.name] = sh
	}

	sort.Strings(names)
	for _, n := range names {
		sh := shapes[n]
		if !sh.Eligible {
			fmt.Printf("%s|-|not eligible (no backward sweep)\n", n)
			continue
		}
		for _, in := range cacheSizeInputs {
			// The TUPLE form is no longer built — lever B replaced it — so its
			// number is computed rather than shipped, which is what makes the
			// four-way comparison readable.
			cur := config.SetOverlapCacheBytes(in.n, sh.Patterns)
			ckpt := config.SetOverlapCheckpointBytes(in.n, sh.Cells, sh.Patterns, false)
			row := config.SetOverlapCheckpointBytes(in.n, sh.Cells, sh.Patterns, true)
			fmt.Printf("%s|%s|cells=%d pats=%d|current = %d bytes|checkpoints = %d bytes|checkpoints+B = %d bytes\n",
				n, in.label, sh.Cells, sh.Patterns, cur, ckpt, row)
		}
	}
	return nil
}

// overlapShapeFor reports the sweep column a case's set compiles to, which is
// what sizes its answer cache.
//
// It recompiles the set — the same route a stub generator takes (plans §9.2
// decision 1) — because the column width falls out of the DFA construction and
// nothing in the case's pattern list implies it.
func overlapShapeFor(c setCase) (compile.OverlapCacheShape, error) {
	entries := make([]config.RegexEntry, len(c.patterns))
	pnames := make([]string, len(c.patterns))
	for i, p := range c.patterns {
		pnames[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: pnames[i], Pattern: p}
	}
	// The set MUST be declared exactly as compileCase declares it — every
	// capability, the batch hint, the forced frontend. The bucket a set packs
	// into depends on what it has to serve, so a shape looked up from a
	// reduced config can name a different automaton than the module actually
	// contains, and the region would be sized and strided for the wrong sweep.
	// That is not hypothetical: looking it up from a find-only config made the
	// 256-byte overlap-shape row disagree with the walk while every other row
	// passed.
	hints := []string{"batch-find"}
	if setHints != "" {
		hints = append(hints, setHints)
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name:        "s",
			MatchAny:    "cap_match_any",
			MatchAll:    "cap_match_all",
			ScanAny:     "cap_scan_any",
			ScanAll:     "cap_scan_all",
			Find:        "cap_find",
			Hints:       hints,
			Overlapping: true,
			Patterns:    config.PatternSelector{Names: pnames},
		}},
	}
	return compile.SetOverlapCacheShape(cfg.Sets[0], cfg)
}
