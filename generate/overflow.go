package generate

import (
	"fmt"

	"github.com/qrdl/regexped/internal/abi"
)

// ---------------------------------------------------------------------------
// abi.BTStackOverflow handling in generated stubs.
//
// Every exported matcher can return abi.BTStackOverflow (-2) when the pattern
// compiled to the Backtracking engine and the input exhausted its frame budget.
// It means the engine abandoned part of the search space and does NOT know
// whether the input matches — so a stub that folds it into its existing
// "negative means no match" test turns an engine giving up into a confident
// wrong answer, which is exactly the BT stack-overflow defect.
//
// How each language surfaces it, after this table was rewritten twice:
//
//	Rust        Result<T, Error>
//	Go          an error return; Err() after the loop for the lazy iterators
//	JS, TS      throw
//	C, AS       return the sentinel to the caller
//
// Each is that LANGUAGE's own way of saying "this call cannot be answered", and
// the governing rule is that a stub reads like a native library rather than a
// translation of a shared design. Two shapes that look inconsistent across
// languages are correct if each is right at home.
//
// What changed and why:
//
//   - Rust and Go used to PANIC. A panic unwinding out of an FFI wrapper is a
//     poor fit for the contexts this library targets — under panic = "abort" it
//     is a hard process abort, and a server taking user input cannot have a
//     data-dependent abort in its matcher. Both languages report failure by
//     returning it, so now they do.
//
//   - AS used to be grouped with JS/TS as "throw", and that was WRONG. Verified
//     with the repo's own asc 0.28.13: `try { } catch { }` is rejected outright
//     ("ERROR AS100: Not implemented: Exceptions"), and a `throw` compiles to a
//     call to the imported `abort` — a one-way trap the AS caller cannot handle.
//     A throw there was strictly worse than a sentinel, not equivalent to one.
//     JS and TS are unaffected: exceptions are real and catchable there, and are
//     the normal error channel.
//
//   - C is unchanged. It has no unwinding, and its return types were already
//     integer error codes with a documented negative case.
//
// Whichever mechanism: the requirement is that a caller can tell overflow from
// no-match. Silence is the one unacceptable option — and it WAS the outcome in
// three exports (`match_any` and the narrow `match_all`/`scan_all`) until task
// 62, which folded the sentinel into "no match" and, for the two `_all` forms,
// into "every id except 0 matched".

// btOverflowMsg is the diagnostic text embedded in generated stubs. funcName is
// the public function the caller invoked, so the message names something the
// caller recognises rather than an internal export.
func btOverflowMsg(funcName string) string {
	return fmt.Sprintf("regexped: %s: backtracking stack overflow — input too large "+
		"for this pattern's frame budget; the match result is unknown, not negative "+
		"(see docs/engines.md)", funcName)
}

// btOverflow is abi.BTStackOverflow, for embedding as a literal in generated
// source. Named so generated code reads as a deliberate sentinel comparison
// rather than a magic -2.
const btOverflow = abi.BTStackOverflow
