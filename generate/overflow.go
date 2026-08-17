package generate

import (
	"fmt"

	"github.com/qrdl/regexped/internal/abi"
)

// ---------------------------------------------------------------------------
// abi.BTStackOverflow handling in generated stubs (plans/OPUS.md §N1).
//
// Every exported matcher can return abi.BTStackOverflow (-2) when the pattern
// compiled to the Backtracking engine and the input exhausted its frame budget.
// It means the engine abandoned part of the search space and does NOT know
// whether the input matches — so a stub that folds it into its existing
// "negative means no match" test turns an engine giving up into a confident
// wrong answer, which is exactly the defect §N1 records.
//
// How each language surfaces it:
//
//	Rust, Go        panic
//	JS, TS, AS      throw
//	C               returns the sentinel through to the caller
//
// The split is not arbitrary. Rust's Option<usize>, Go's (int, bool), and the
// JS/TS/AS generator protocols have no room for a third outcome, so reporting
// it in the return value would mean redesigning every public signature (and
// every example and doc that uses them) — far past "make the failure visible".
// An unwind is the idiomatic way each of those languages reports "this call
// cannot be answered". C has no unwinding but its return types are already
// integer error codes with a documented negative case, so extending that case
// is both idiomatic and free.
//
// Whichever mechanism: the requirement is that a caller can tell overflow from
// no-match. Silence is the one unacceptable option.

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
