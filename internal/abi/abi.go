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

import "encoding/binary"

const (
	// NoMatch is returned when the input genuinely does not match. Hosts map it
	// to None / nil / false / end-of-iteration.
	NoMatch = -1

	// BTStackOverflow is returned when the Backtracking engine cannot complete a
	// search because one of its compile-time sized regions is too small for the
	// input. Two independent regions can hit that, and both report this value:
	//
	//   - the backtrack FRAME STACK (btPushFrame's guard in
	//     compile/engine_backtrack.go), sized from the pattern's alternation
	//     count by btAllocSizes;
	//   - the BitState MEMO bitset (emitBTMemoLenGuard, same file), sized from
	//     the pattern's instruction count by btMemoMaxLen.
	//
	// Both budgets are compile-time constants while the true requirement scales
	// with input length, so a long enough input can exhaust either. The two
	// ceilings move independently — one with numAlts, the other with N — so
	// neither guard may be left to the other to catch.
	//
	// When either fires the engine has abandoned part of the search space and
	// cannot say whether a match exists: reporting NoMatch here would be a
	// false negative that scales in with input size and carries no diagnostic,
	// which is exactly the failure this sentinel exists to prevent.
	//
	// They share one value because a host acts identically on both — surface an
	// error, do not treat it as "no match" — and because a new value would have
	// to be threaded through all six stub generators to convey a distinction no
	// caller can act on.
	//
	// Hosts must surface it as an error, never as "no match". See
	// docs/engines.md ("Backtracking frame budget").
	BTStackOverflow = -2

	// OverlapCacheMalformed is returned when an overlapping `find` is handed an
	// answer cache whose HEADER contradicts itself: a stride BELOW 1, or — on a
	// call after the sweep — a layout that is not the one a pass would have
	// written (a floor past the input, a cntOff that does not follow from
	// numBlocks, a block buffer the declared cache_len cannot hold).
	//
	// Two things that look similar are NOT this. A stride WIDER than the span
	// being swept is ordinary and is clamped: `init` sizes the stride for the
	// whole input, and a drive that engages late has fewer positions left than
	// that. A region merely TOO SMALL is refused with -1 and the drive walks —
	// same answer, slower — which is what lets a caller cap what it allocates.
	//
	// It is an ERROR and not a silent decline, which is the whole point of it.
	// The region is CALLER-OWNED memory: the generated `init` fills it correctly
	// by construction, but the raw ABI is documented and usable directly, and a
	// caller who gets it wrong would otherwise see the drive quietly fall back to
	// walking — indistinguishable from the engine legitimately refusing the
	// shape, and quadratic on exactly the inputs the cache exists for.
	//
	// A region that is merely TOO SMALL is NOT this. That is a legitimate answer
	// with its own signal (the sweep refuses, the drive walks, -1 from the sweep
	// internally), because a caller is allowed to offer less than the optimum.
	// Only a self-contradictory header lands here.
	OverlapCacheMalformed = -4
)

// --- the `find` scratch descriptor -----------------------------------------
//
// `find` and `find_batch` take a POINTER TO A DESCRIPTOR where they used to
// take a bare gate-array pointer. The descriptor carries the gate array and,
// optionally, the overlapping answer cache:
//
//	+0  magic      FindScratchMagic
//	+4  gate_ptr   ID_SPACE u32s, zeroed for a clean scan — as before
//	+8  cache_ptr  the overlapping answer cache, or 0 to decline
//	+12 cache_len  its length in bytes
//
// WHY A DESCRIPTOR rather than two more parameters. The cache is the mechanism
// that makes an overlapping drive linear instead of quadratic, and it has to
// live in CALLER-owned memory: a region held inside the module would carry one
// scan's answers into the next, which is the same reason the gate array is the
// caller's. Passing it needs somewhere to put a pointer and a length, and a
// descriptor puts them somewhere that the NEXT piece of scratch can also use
// without changing a signature again. It also collapses `find_batch` from eight
// parameters to six, so the cache is described in one place rather than two.
//
// WHY A MAGIC WORD. The descriptor replaces a parameter of the same type, so a
// caller still passing a bare gate array would have its gate[0] read as a
// pointer — a silent corruption. The magic turns that into an immediate trap:
// a zeroed gate array reads 0 here, which is not the magic, and the module
// executes `unreachable` on the first call. One compare per call buys a loud
// failure instead of a quiet one.
const (
	// FindScratchMagic is "RXFS" in little-endian bytes.
	FindScratchMagic = 0x52584653

	// FindScratchBytes is the descriptor's size. 4-aligned, like everything
	// else the set ABI passes.
	FindScratchBytes = 16

	FindScratchMagicOff    = 0
	FindScratchGateOff     = 4
	FindScratchCacheOff    = 8
	FindScratchCacheLenOff = 12
)

// WriteFindScratch fills a descriptor at buf[off:] — magic, gate pointer, and
// either the answer cache or a declined one (pass 0, 0).
//
// Here rather than in each caller because five harnesses and six stub
// generators all have to agree about the layout, and a field written at the
// wrong offset is a wrong pointer rather than a compile error. The one place
// that CANNOT use it is the generated stub code itself, which is emitted as
// source text in another language — those carry the offsets as constants
// derived from the same block above.
func WriteFindScratch(buf []byte, off int32, gatePtr, cachePtr, cacheLen int32) {
	put := func(at int32, v int32) {
		binary.LittleEndian.PutUint32(buf[off+at:], uint32(v))
	}
	put(FindScratchMagicOff, FindScratchMagic)
	put(FindScratchGateOff, gatePtr)
	put(FindScratchCacheOff, cachePtr)
	put(FindScratchCacheLenOff, cacheLen)
}
