// Package abi holds the numeric return-value contract shared between the WASM
// code the compiler emits (compile/) and the host-side stubs it generates
// (generate/). Neither package imports the other, so a constant that must mean
// the same thing on both sides of the WASM boundary lives here.
//
// Every exported matcher signals failure with a negative return value. The
// values are disjoint so a host can tell "the input does not match" from "the
// engine gave up", which is the whole point of this package existing:
//
//	-1  NoMatch          the input does not match — an ordinary, expected answer
//	-2  BTStackOverflow  the Backtracking engine's frame stack was exhausted;
//	                     the answer is UNKNOWN, not "no"
//
// For the i64-returning find exports the same values apply, sign-extended
// (i64.const -1 / -2); a genuine packed (start << 32 | end) result always has
// bit 63 clear because start is a non-negative i32, so no legitimate result can
// be confused with either sentinel.
//
// Adding a value here means updating every stub generator in generate/ — a
// sentinel a host cannot distinguish is worse than no sentinel at all, since it
// silently becomes "no match".
package abi

const (
	// NoMatch is returned when the input genuinely does not match. Hosts map it
	// to None / nil / false / end-of-iteration.
	NoMatch = -1

	// BTStackOverflow is returned when the Backtracking engine runs out of
	// backtrack frames mid-search (btPushFrame's guard in
	// compile/engine_backtrack.go). The frame budget is a compile-time constant
	// sized from the pattern's alternation count (btAllocSizes), while the true
	// requirement scales with input length, so a long enough input can exhaust
	// it. When that happens the engine has abandoned part of the search space
	// and cannot say whether a match exists: reporting NoMatch here would be a
	// false negative that scales in with input size and carries no diagnostic,
	// which is exactly the failure this sentinel exists to prevent.
	//
	// Hosts must surface it as an error, never as "no match". See
	// docs/engines.md ("Backtracking frame budget").
	BTStackOverflow = -2
)
