package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
)

// The find-from invariant, for the GROUPS export.
//
// find_from_property_test.go asserts this for `find`, and enforcing it turned
// up three emitters that answered with a match starting before the position
// they were asked to search from. `groups` carries the same offset through the
// same channel and has never been swept the same way: the existing coverage is
// TestLitChainGroupsIterate's four shapes, driven through one iteration order.
// On the find side that kind of coverage left SIX of fourteen emitters reached
// by nothing, two of them carrying live bugs, so the prior here is not good.
//
// The contract, identical to find's except that the answer includes slots:
//
//	groups(I, out, f) == the FIRST match of P in I whose start is >= f,
//	                     with every capture slot as Go reports it
//
// and a negative return when there is none. Slots are ABSOLUTE, and ptr/len
// describe the whole buffer, so left context is real — which is why the oracle
// probes the full input rather than running Go against a narrowed slice.
var groupsFromShapes = []struct {
	name, pat, input string
	engine           compile.EngineType // 0 = let the selector choose
}{
	{name: "tdfa_simple", pat: `(\d{2})-(\d{2})`, input: "aa 11-22 bb 33-44 cc"},
	{name: "tdfa_named", pat: `(?P<h>[a-z]+)@(?P<d>[a-z]+)\.com`, input: "x ab@cd.com y ef@gh.com"},
	{name: "tdfa_optional", pat: `(a)(b)?(c)`, input: "ac abc ac"},
	{name: "bt_nongreedy", pat: `(a.*?b)(c+)`, input: "aXbcc aYbc"},
	{name: "bt_forced", pat: `(\w+)-(\w+)`, input: "aa-bb cc-dd", engine: compile.EngineBacktrack},
	{name: "tdfa_forced", pat: `(\w+)-(\w+)`, input: "aa-bb cc-dd", engine: compile.EngineTDFA},
	{name: "litchain_groups", pat: `AKIA([A-Z0-9]{24})`,
		input: "AKIA0123456789ABCDEF01234567 q AKIAFEDCBA9876543210FEDCBA98"},
	{name: "litchain_range_groups", pat: `foo([0-9]{26,30})`,
		input: "foo0123456789012345678901234567 q foo98765432109876543210987654"},
	{name: "alt_groups", pat: `AKIA([A-Z0-9]{24})|ghp_([A-Za-z0-9]{24})`,
		input: "AKIA0123456789ABCDEF01234567 ghp_abcdefghij0123456789abcd"},
	{name: "gap_e_groups", pat: `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
		input: "01234567ghp_abcdefghijklmnopqrstuvwxyz0123456789 tail"},
	{name: "word_boundary_groups", pat: `\b(cat)\b`, input: "cat concat cat"},
	{name: "line_anchor_groups", pat: `(?m:^)(ERR):(.*)(?m:$)`, input: "ERR:one\nok\nERR:two"},
	{name: "adjacent_groups", pat: `(\d)(\d)`, input: "123456"},
	{name: "trivial_whole", pat: `([a-z]+)`, input: "ab cd ef"},
	{name: "nested_groups", pat: `((a+)(b+))`, input: "aabb ab aaabbb"},
	{name: "no_match_groups", pat: `(ZZZ)(\d+)`, input: "nothing here at all"},
	{name: "empty_capable", pat: `(a*)`, input: "baab"},
	// Empty-capable on each capture engine explicitly: the selector's choice
	// is not the point here, reaching both backends with a zero-width-capable
	// pattern is.
	{name: "empty_capable_tdfa", pat: `(a*)`, input: "baab", engine: compile.EngineTDFA},
	{name: "empty_capable_bt", pat: `(a*?)(b?)`, input: "bab", engine: compile.EngineBacktrack},
	{name: "trivial_whole_empty", pat: `([a-z]*)`, input: "ab cd"},
}

// groupsEndsAt returns, for every start position s, the submatch indices of the
// leftmost-first match of pat beginning EXACTLY at s, or nil.
//
// Same whole-input anchored probe as the find sweep — `\A(?s:.{s})(?:pat)` —
// which keeps \b, \B and (?m:^) judging real neighbours. `(?:pat)` is
// non-capturing, so the probe's group N is pat's group N, and every index it
// reports is already absolute. Inputs here are ASCII, so the probe's rune count
// and the byte offset coincide.
func groupsEndsAt(t *testing.T, pat, input string) [][]int {
	t.Helper()
	out := make([][]int, len(input)+1)
	for s := range out {
		probe, err := regexp.Compile(`\A(?s:.{` + strconv.Itoa(s) + `})(?:` + pat + `)`)
		if err != nil {
			t.Skipf("Go rejects probe for %q at %d: %v", pat, s, err)
		}
		if m := probe.FindStringSubmatchIndex(input); m != nil {
			cp := append([]int(nil), m...)
			cp[0] = s // the probe is anchored at 0; the real match starts at s
			out[s] = cp
		}
	}
	return out
}

func groupsFirstFrom(ends [][]int, from int) ([]int, bool) {
	for s := from; s < len(ends); s++ {
		if ends[s] != nil {
			return ends[s], true
		}
	}
	return nil, false
}

func fmtSlots(v []int) string {
	if v == nil {
		return "(none)"
	}
	parts := make([]string, 0, len(v)/2)
	for i := 0; i+1 < len(v); i += 2 {
		if v[i] < 0 {
			parts = append(parts, "-")
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", v[i], v[i+1]))
		}
	}
	return strings.Join(parts, ",")
}

func compileGroupsShape(pat string, eng compile.EngineType) ([]byte, error) {
	if eng != 0 {
		return compileGroupsForced(pat, eng)
	}
	return compileGroups(pat)
}

// TestGroupsFromStartsAtOrAfterFrom drives groups at every start position.
func TestGroupsFromStartsAtOrAfterFrom(t *testing.T) {
	for _, c := range groupsFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			slots := 2 * (re.NumSubexp() + 1)
			w, err := compileGroupsShape(c.pat, c.engine)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := groupsCaller(t, w, c.input, slots)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()
			ends := groupsEndsAt(t, c.pat, c.input)

			for from := 0; from <= len(c.input); from++ {
				got, state := call(from)
				switch state {
				case findHang:
					t.Fatalf("from=%d: watchdog fired", from)
				case findOverflow:
					t.Skipf("from=%d: BT stack overflow", from)
				}
				want, wantOK := groupsFirstFrom(ends, from)

				if state == findNone {
					if wantOK {
						t.Errorf("from=%d: got no-match, want %s", from, fmtSlots(want))
					}
					continue
				}
				if got[0] < from {
					t.Errorf("from=%d: returned start %d precedes from — "+
						"the find-from offset is not reaching this capture body",
						from, got[0])
					continue
				}
				if !wantOK {
					t.Errorf("from=%d: got %s, want no-match", from, fmtSlots(got))
					continue
				}
				if fmtSlots(got) != fmtSlots(want) {
					t.Errorf("from=%d: slots differ\n  got  %s\n  want %s",
						from, fmtSlots(got), fmtSlots(want))
				}
			}
		})
	}
}

// TestGroupsFromShapesReachDistinctBodies is the corpus-collapse detector, with
// the same caveat as its find-side twin: the fingerprint is a proxy, not proof
// that every capture emitter is covered.
func TestGroupsFromShapesReachDistinctBodies(t *testing.T) {
	byFP := map[string][]string{}
	for _, c := range groupsFromShapes {
		w, err := compileGroupsShape(c.pat, c.engine)
		if err != nil {
			t.Skipf("compile %q: %v", c.pat, err)
		}
		fp, err := localsFingerprint(w)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		byFP[fp] = append(byFP[fp], c.name)
	}
	keys := make([]string, 0, len(byFP))
	for k := range byFP {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		short := k
		if len(short) > 48 {
			short = short[:48] + "…"
		}
		t.Logf("%-50s %s", short, strings.Join(byFP[k], ", "))
	}
	const minBodies = 6
	if len(byFP) < minBodies {
		t.Errorf("groups shapes reach only %d distinct bodies, want >= %d — the corpus has shrunk",
			len(byFP), minBodies)
	}
}

// groupsCaller instantiates once and returns a closure calling the groups
// export at a given `from`, decoding the absolute slot buffer.
func groupsCaller(t *testing.T, wasmBytes []byte, input string, slots int) (func(int) ([]int, findState), func(), bool) {
	t.Helper()
	engine, wd := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		mod.Close()
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "groups")
	memExp := inst.GetExport(store, "memory")
	if fn == nil || memExp == nil || memExp.Memory() == nil {
		mod.Close()
		store.Close()
		return nil, nil, false
	}
	mem := memExp.Memory()
	copy(mem.UnsafeData(store)[pathsInputBase:], input)

	call := func(from int) ([]int, findState) {
		wd.Arm(store)
		r, err := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(from))
		wd.Disarm()
		if err != nil {
			if isTimeout(err) {
				return nil, findHang
			}
			t.Fatalf("groups(from=%d): %v", from, err)
		}
		v, ok := r.(int32)
		if !ok {
			t.Fatalf("groups returned %T, want i32", r)
		}
		if int64(v) == abi.BTStackOverflow {
			return nil, findOverflow
		}
		if v < 0 {
			return nil, findNone
		}
		buf := mem.UnsafeData(store)
		out := make([]int, slots)
		for i := 0; i < slots; i++ {
			s := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
			if s < 0 {
				out[i] = -1
			} else {
				out[i] = int(s)
			}
		}
		return out, findMatch
	}
	return call, func() { store.Close(); mod.Close() }, true
}

// TestGroupsFromIterationMatchesGo is half (B) for the groups export.
//
// Task 54's suppression rule — an EMPTY match beginning exactly where the
// previous reported match ended is not reported — shipped into the find
// iterators AND both groups iterators. The find side is checked by
// TestFindFromIterationTerminates; this is the groups half, which had only
// TestLitChainGroupsIterate's four shapes.
//
// The rule is only exercisable by patterns that can match zero bytes, so
// `empty_capable` and `trivial_whole` are the shapes that matter here; the rest
// are along for the ride and confirm the loop does not disturb them.
func TestGroupsFromIterationMatchesGo(t *testing.T) {
	for _, c := range groupsFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			slots := 2 * (re.NumSubexp() + 1)
			w, err := compileGroupsShape(c.pat, c.engine)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := groupsCaller(t, w, c.input, slots)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()

			var got [][]int
			budget := 4*len(c.input) + 16
			off, prevEnd := 0, -1
			for steps := 0; off <= len(c.input); steps++ {
				if steps > budget {
					t.Fatalf("iteration did not terminate within %d steps (off=%d)", budget, off)
				}
				m, state := call(off)
				if state == findHang {
					t.Fatalf("off=%d: watchdog fired", off)
				}
				if state == findOverflow {
					t.Skipf("off=%d: BT stack overflow", off)
				}
				if state == findNone {
					break
				}
				if !(m[0] == m[1] && m[0] == prevEnd) {
					got = append(got, m)
					prevEnd = m[1]
				}
				adv := m[1] - off
				if adv <= 0 {
					adv = 1
				}
				off += adv
			}

			var want [][]int
			for _, m := range re.FindAllStringSubmatchIndex(c.input, -1) {
				want = append(want, m)
			}
			gs, ws := make([]string, len(got)), make([]string, len(want))
			for i, v := range got {
				gs[i] = fmtSlots(v)
			}
			for i, v := range want {
				ws[i] = fmtSlots(v)
			}
			if strings.Join(gs, " | ") != strings.Join(ws, " | ") {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, strings.Join(gs, " | "), strings.Join(ws, " | "))
			}
		})
	}
}
