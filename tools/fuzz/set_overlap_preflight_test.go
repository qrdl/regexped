package fuzz

import (
	"fmt"
	"regexp"
	"sort"
	"testing"
)

// SETS_PLAN item 11 stage A: the overlapping `find` body runs a once-per-drive
// preflight and keeps its verdict in the caller's gate array, retiring every
// pattern that matches NOWHERE at or after the drive's `from`.
//
// That is an optimisation whose whole job is to make the engine do LESS work,
// which is the dangerous kind: if the verdict is ever wrong in the "dead"
// direction, matches simply stop being reported and nothing crashes. The
// corpus gates reach it only by luck — the preflight needs a scalar frontend
// with a never-dying suffix DFA, which most RE2 chunks are not — so these
// tests aim at it directly.
//
// The shape is greedy-3's, the row the whole change exists for: a set whose
// members are all literal-less, one of which (`[^\n]*ERROR`) has an automaton
// that never dies on newline-free input, so before this it was walked to end
// of input from every start position.

// overlapPreflightSets are set shapes that should reach the preflight. Each
// mixes a pattern that can be proven absent with ones that cannot, because an
// all-dead set is the easy case: the interesting failure is retiring a live
// pattern while its neighbours keep the scan running.
var overlapPreflightSets = [][]string{
	{`a+`, `[^\n]*ERROR`, `x?y`},          // greedy-3 itself
	{`[^\n]*ERROR`, `[^\n]*WARN`},         // two never-dying patterns, both absentable
	{`a+`, `[^\n]*QQQ`},                   // one never-dying, one that always matches
	{`[^\n]*ZZ`, `b*`, `c?d`},             // b* matches empty everywhere: nothing is ever all-dead
	{`.*END`, `[0-9]+`},                   // `.` rather than a negated class
	{`[^\n]*ERROR`, `[^\n]*ERR`, `error`}, // overlapping literals, one anchored to a shorter one
}

// overlapPreflightInputs deliberately includes inputs where the absentable
// pattern is present, absent, present only near the end (so a drive resuming
// past it must NOT have retired it), and present only at the very start.
var overlapPreflightInputs = []string{
	"",
	"aaa",
	"aaabbbccc",
	"ERROR",
	"aaa ERROR bbb",
	"ERROR aaa",
	"aaa bbb ERROR",
	"WARN and ERROR",
	"xy xy xy",
	"the end END",
	"line one\nline two ERROR\nline three",
	"err ERR ERROR error",
	"d cd ccd",
	"ZZ zz ZZ",
	"0123456789 END",
}

// TestOverlappingPreflightMatchesGo drives overlapping `find` to exhaustion and
// compares against Go's every-start-position enumeration.
//
// The oracle is built the way §22 builds its own: per pattern, an anchored
// probe at every start, which is exactly what `overlapping: true` promises.
// Comparing against `FindAllIndex` would be wrong — that is the GATED rule.
func TestOverlappingPreflightMatchesGo(t *testing.T) {
	for si, pats := range overlapPreflightSets {
		for _, input := range overlapPreflightInputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				r := newCapRunner(t, pats, input, true)
				defer r.Close()
				got := canonTuples(driveOverlapFind(t, r, input))
				want := canonTuples(overlapOracle(t, pats, input))
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("overlapping find over %q:\n  got  %v\n  want %v", input, got, want)
				}
			})
		}
	}
}

// TestOverlappingPreflightSurvivesResume is the failure mode the preflight's
// own design invites, and it is invisible to a single call.
//
// The verdict is computed once, at the drive's first `from`, and reused for
// every later call. That is sound only because a pattern alive over
// [from0, len) is alive over every sub-range a later call looks at — the
// verdict may only ever be too GENEROUS as the cursor advances. If the
// implementation ever recomputed per call, or narrowed the range it computed
// over, a pattern whose only match sits late in the input would be retired for
// the calls that could still reach it.
//
// So: start the drive at every legal `from`, and require each partial drive to
// equal the tail of the full one. A stale-or-narrowed verdict shows up here as
// missing matches at the far end.
func TestOverlappingPreflightSurvivesResume(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	for _, input := range []string{
		"aaa bbb ERROR",
		"ERROR aaa xy",
		"aaa xy bbb",
		"xy aaa ERROR xy",
	} {
		t.Run(input, func(t *testing.T) {
			r := newCapRunner(t, pats, input, true)
			defer r.Close()
			for from := 0; from <= len(input); from++ {
				r.resetGates() // a new drive: the caller's own obligation
				got := canonTuples(driveOverlapFindFrom(t, r, input, int32(from)))
				want := canonTuples(overlapOracleFrom(t, pats, input, from))
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("drive from %d over %q:\n  got  %v\n  want %v",
						from, input, got, want)
				}
			}
		})
	}
}

// TestOverlappingPreflightRunsOncePerDrive pins the amortisation itself, which
// is the half of item 11 that the reverted attempt got wrong.
//
// A preflight that re-runs on every call is CORRECT and useless: it was
// measured at 3,724 union passes on one drive, worse than the quadratic it
// replaced. Correctness tests cannot see that, so this one asserts the
// mechanism instead — after the first call of a drive, no gate slot is still
// zero, which is the condition the emitted guard tests. If a future change
// stops marking alive patterns, every alive slot stays zero, the guard re-arms
// and this fails.
func TestOverlappingPreflightRunsOncePerDrive(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`, `x?y`}
	const input = "aaa bbb ccc"
	r := newCapRunner(t, pats, input, true)
	defer r.Close()

	buf := r.mem.UnsafeData(r.store)
	for i := 0; i < len(pats); i++ {
		if v := readU32(buf, int(r.gatePtr)+i*4); v != 0 {
			t.Fatalf("gate[%d] = %d before the drive, want 0", i, v)
		}
	}
	r.call(t, "cap_find", r.inBase, int32(len(input)), int32(0), r.gatePtr, r.outPtr, int32(r.npat))

	buf = r.mem.UnsafeData(r.store)
	var zero []int
	for i := 0; i < len(pats); i++ {
		if readU32(buf, int(r.gatePtr)+i*4) == 0 {
			zero = append(zero, i)
		}
	}
	if len(zero) != 0 {
		t.Fatalf("after the first call of a drive, gate slots %v are still zero — "+
			"the preflight guard will re-arm and the pass will run on EVERY call, "+
			"which is the failure SETS_PLAN item 11's attempt log recorded", zero)
	}
}

// canonTuples sorts by (start, id, end) so the comparison tests the SET of
// matches and their positions, not the unspecified within-position order.
func canonTuples(in [][3]int) [][3]int {
	out := append([][3]int(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i][1] != out[j][1] {
			return out[i][1] < out[j][1]
		}
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][2] < out[j][2]
	})
	return out
}

func readU32(buf []byte, at int) uint32 {
	return uint32(buf[at]) | uint32(buf[at+1])<<8 |
		uint32(buf[at+2])<<16 | uint32(buf[at+3])<<24
}

// driveOverlapFind runs a whole drive from 0.
func driveOverlapFind(t *testing.T, r *capRunner, input string) [][3]int {
	t.Helper()
	return driveOverlapFindFrom(t, r, input, 0)
}

// driveOverlapFindFrom iterates `find` the way a generated iterator does:
// call, take every tuple, resume at start+1 (overlapping has no gate to
// advance it for us).
func driveOverlapFindFrom(t *testing.T, r *capRunner, input string, from int32) [][3]int {
	t.Helper()
	var out [][3]int
	prevStart := -1
	for {
		n := r.call(t, "cap_find", r.inBase, int32(len(input)), from,
			r.gatePtr, r.outPtr, int32(r.npat)).(int32)
		if n <= 0 {
			return out
		}
		if int(n) > r.npat {
			t.Fatalf("find reported %d tuples at one position for a %d-pattern set", n, r.npat)
		}
		buf := r.mem.UnsafeData(r.store)
		start := int32(-1)
		for i := int32(0); i < n; i++ {
			b := int(r.outPtr) + int(i)*12
			id := int32(readU32(buf, b))
			st := int32(readU32(buf, b+4))
			en := int32(readU32(buf, b+8))
			if i == 0 {
				start = st
			} else if st != start {
				t.Fatalf("tuples in one call disagree on start: %d vs %d", start, st)
			}
			out = append(out, [3]int{int(id), int(st), int(en)})
		}
		if len(out) > int(n) && start < int32(prevStart) {
			t.Fatalf("drive went backwards: reported start %d after %d", start, prevStart)
		}
		prevStart = int(start)
		from = start + 1
		if int(from) > len(input)+1 {
			t.Fatalf("drive failed to terminate: from=%d, len=%d", from, len(input))
		}
	}
}

func overlapOracle(t *testing.T, pats []string, input string) [][3]int {
	t.Helper()
	return overlapOracleFrom(t, pats, input, 0)
}

// overlapOracleFrom is `overlapping: true`'s contract stated directly: at every
// start position s >= from, every pattern that matches there, with its
// leftmost-first extent.
//
// Both sides are canonicalised before comparison, because docs/sets.md states
// that "the order of the matches WITHIN one call is unspecified — not by
// pattern id". Asserting id order here would be testing an implementation
// detail and would fail on a correct compiler; the ACROSS-call order is a real
// contract and is asserted separately, by driveOverlapFindFrom's own
// resume-at-start+1 loop and the non-decreasing check in it.
func overlapOracleFrom(t *testing.T, pats []string, input string, from int) [][3]int {
	t.Helper()
	var out [][3]int
	for s := from; s <= len(input); s++ {
		for k, p := range pats {
			re := regexp.MustCompile(`\A(?:` + p + `)`)
			if m := re.FindStringIndex(input[s:]); m != nil {
				out = append(out, [3]int{k, s, s + m[1]})
			}
		}
	}
	return out
}
