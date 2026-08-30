package main

// The bench shim emitters live in internal/benchshim, shared with the sibling
// harnesses. See that package's doc comment for why: this file and
// tools/likelytest/shims.go were byte-identical hand-assembled WASM, and a
// fix that landed in one of the pair is exactly the failure
// a hand-maintained copy invites.

import "github.com/qrdl/regexped/internal/benchshim"

const (
	// benchIters is the number of iterations run inside WASM per benchmark
	// call. The loop executes entirely within WASM so CGo overhead is paid
	// only once.
	benchIters   = benchshim.Iters
	timingsBytes = benchshim.TimingsBytes
	clockScratch = benchshim.ClockScratch
	shimMemPages = benchshim.MemPages
)

var (
	computeStat          = benchshim.ComputeStat
	buildMatchBenchShim  = benchshim.BuildMatch
	buildFindBenchShim   = benchshim.BuildFind
	buildGroupsBenchShim = benchshim.BuildGroups
)
