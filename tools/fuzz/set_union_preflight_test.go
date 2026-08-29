package fuzz

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The UNION-WALK arm of the gated `find` preflight (`emitUnionAliveMask`).
//
// This file exists because a mutation survived everything else in the suite.
// SETS_PLAN item 21 phase 2 put the mid-accept OR of that walk behind the
// accept-first partition, and inverting the guard — so the walk reads the
// accepts of states that cannot accept and skips the ones that can — passed
// `make setcaps`, the whole gated-find suite, and both overlapping-preflight
// suites. The failure it would cause is the worst kind: the alive mask
// UNDER-approximates, patterns that do match are retired as dead, and `find`
// silently stops reporting them.
//
// Nothing covered it because reaching the arm needs a coincidence of four
// things, and the existing fixtures each miss at least one:
//
//   - a scalar frontend and a NEVER-DYING suffix DFA, or no preflight is
//     emitted at all (§16.5.2: a preflight that retires nothing is Candidate A);
//   - every pattern LITERAL-LESS, so G12's absence prefilter declines
//     (buildAbsenceLits needs one pattern with a mandatory literal) and the
//     union walk is what computes the verdict. greedy-3 — the fixture the
//     preflight work was built against — fails exactly here: `ERROR` is an
//     absence literal, so greedy-3 never runs this code;
//   - a SCAN capability declared, because the union automaton is only built
//     when something asks for it, and a find-only gated set asks for nothing;
//   - an input where a pattern's aliveness is established MID-STRING, since
//     the entry-state and end-of-input contributions are separate arms that an
//     inverted guard leaves intact.
//
// `litLessNeverDying` in compile/set_emit_coverage_test.go is the same family,
// and its comment records the first two conditions; this is the behavioural
// half.

// compileUnionPreflightSet compiles pats with the gated `find` AND the scan
// pair, which is the combination that makes the union automaton exist for the
// preflight to walk.
func compileUnionPreflightSet(t *testing.T, pats []string) []byte {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:     "s",
		Find:     "gated_find",
		ScanAny:  "cap_scan_any",
		ScanAll:  "cap_scan_all",
		Patterns: config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileDiag(
		config.BuildConfig{Regexps: entries, Sets: sets}, "")
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	// The union automaton must have been BUILT and must be the narrow form —
	// the preflight emitters read u64 accept tables, and a wide automaton
	// emits none. Without this the test could pass by never reaching the code
	// it is named after.
	if len(diags) != 1 || diags[0].UnionScan == nil || !diags[0].UnionScan.Used {
		t.Fatalf("no union automaton for %v: %+v", pats, diags)
	}
	if diags[0].UnionScan.Wide {
		t.Fatalf("union automaton is WIDE for %v; the preflight cannot use it", pats)
	}
	return w
}

// runUnionPreflightFind drives the gated find to exhaustion from `from`,
// zeroing the gate array first — which is how a caller declares a fresh drive,
// and therefore the thing that arms the preflight.
func runUnionPreflightFind(t *testing.T, w []byte, pats []string, input string, from int32) []setMatch {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "gated_find")
	if fn == nil {
		t.Fatal("module missing gated_find export")
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr := inBase + span
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	if len(input) > 0 {
		copy(buf[inBase:], input)
	}
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}

	var out []setMatch
	pos := from
	outCap := int32(len(pats))
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), pos, gatePtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("gated_find: %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf := mem.UnsafeData(store)
		start := -1
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			rd := func(o int) int {
				return int(int32(uint32(buf[base+o]) | uint32(buf[base+o+1])<<8 |
					uint32(buf[base+o+2])<<16 | uint32(buf[base+o+3])<<24))
			}
			// docs/wasm.md "find tuple layout": +0 pattern_id, +4 start, +8 end.
			m := setMatch{PatternID: rd(0), Start: rd(4), End: rd(8)}
			out = append(out, m)
			start = m.Start
		}
		if start < 0 {
			break
		}
		pos = int32(start + 1)
		if pos > int32(len(input)) {
			break
		}
	}
	return out
}

func TestUnionAliveMaskPreflightMatchesGo(t *testing.T) {
	// Every pattern literal-less (so G12 declines) with a never-dying leading
	// `[^\n]*` (so the preflight is emitted at all).
	sets := [][]string{
		{`[^\n]*[0-2]`, `[^\n]*[3-5]`},
		{`[^\n]*[0-2]`, `[a-c]+`},
		{`[^\n]*[0-2]`, `[^\n]*[3-5]`, `[p-r]{2}`},
		// A NULLABLE member, which is alive only through the ENTRY-STATE arm
		// of the walk — the one that records what accepts at `from` before any
		// byte is consumed (§18.7). It is a separate arm from the loop's, so
		// losing it is a separate bug, and without a pattern that can match
		// empty nothing here would notice.
		{`[^\n]*[0-2]`, `[0-9]*`},
		{`[^\n]*[0-2]`, `\A`},
		// NO never-dying member — shapes the preflight only reaches since
		// SETS_PLAN item 22 fix 2a dropped hasNeverDyingState from its
		// eligibility. Every one of them is nullable, which is the axis that
		// broke: fix 2a's first draft marked ALIVE patterns with gate 1, and
		// while 1 is invisible to the pre-mask and to emitGateJump, the
		// write-time empty-extent rule in emitWriteMatchK is the stricter
		// `2s >= gate[k]` — so an empty match at s == 0 was dropped by every
		// one of these and by 24 corpus cases. The marker is gone; these pin
		// its absence.
		{`(?:.|(?:c?))`},
		{`(?:.|(?:c?))`, `^(?:(?:.|(?:c?)))$`},
		{`[a-c]*`, `[0-9]*`},
		{`(?:x|)`, `[p-r]{2}`},
	}
	inputs := []string{
		"",
		"1",
		"5",
		"xx1xx", // alive ONLY by a mid-string accept: an inverted guard
		"ab4cd", // leaves the mask empty here and drops every match
		"xx1yy4zz",
		"no digits at all",
		"qq pr rr 2",
		"aaa",
		"0123456789",
	}
	for si, pats := range sets {
		w := compileUnionPreflightSet(t, pats)
		for _, input := range inputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				// The gated contract IS Go's FindAllIndex per pattern (§9.6.1),
				// computed independently of anything the emitter believes.
				var want []setMatch
				for k, p := range pats {
					for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
						want = append(want, setMatch{PatternID: k, Start: x[0], End: x[1]})
					}
				}
				got := runUnionPreflightFind(t, w, pats, input, 0)
				sortMatches(want)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%v on %q: want %d matches %v, got %d %v",
						pats, input, len(want), want, len(got), got)
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%v on %q: match %d = %+v, want %+v",
							pats, input, i, got[i], want[i])
					}
				}
			})
		}
	}
}

// TestUnionAliveMaskPreflightResumes drives every legal starting `from`.
//
// The preflight computes its verdict ONCE per drive, over `[from, len)` of the
// FIRST call, and that is sound only because the verdict over-approximates as
// `from` advances. A guard that makes it under-approximate breaks this at every
// resume point rather than only at zero, so starting everywhere is the cheapest
// way to widen the net.
func TestUnionAliveMaskPreflightResumes(t *testing.T) {
	pats := []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}
	w := compileUnionPreflightSet(t, pats)
	for _, input := range []string{"xx1xx", "ab4cd", "1a4b2c5", "none"} {
		for from := 0; from <= len(input); from++ {
			t.Run(fmt.Sprintf("%q/from=%d", input, from), func(t *testing.T) {
				var want []setMatch
				for k, p := range pats {
					re := regexp.MustCompile(p)
					for _, x := range re.FindAllStringIndex(input[from:], -1) {
						want = append(want, setMatch{
							PatternID: k, Start: x[0] + from, End: x[1] + from})
					}
				}
				got := runUnionPreflightFind(t, w, pats, input, int32(from))
				sortMatches(want)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%v on %q from %d: want %d %v, got %d %v",
						pats, input, from, len(want), want, len(got), got)
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%v on %q from %d: match %d = %+v, want %+v",
							pats, input, from, i, got[i], want[i])
					}
				}
			})
		}
	}
}
