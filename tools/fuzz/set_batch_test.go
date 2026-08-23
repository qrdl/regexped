package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// find_batch: several consecutive positions per call, resumed by cursor.
//
// The oracle is the same one the gated `find` target uses (§9.6.1): Go's
// FindAllIndex per pattern, tagged with the pattern id. Deriving a reference
// from §19's own cursor arithmetic would only prove the emitter agrees with
// itself.
//
// What makes this target sharp is the out_cap sweep. Batching is only
// interesting where a bufferful ENDS mid-position, and out_cap = 1 forces that
// at every position with more than one match, while out_cap = 2 lands the
// split at a different offset within the position. A body that resumes a split
// position wrongly re-reports or drops exactly the tuples the sweep straddles.

// compileBatchSet compiles pats into a standalone module exporting both `find`
// and `find_batch`, so the two can be compared directly. They are independent
// bodies over shared suffix functions, which is also what makes declaring both
// worth testing: the shared functions must serve either caller.
func compileBatchSet(pats []string, overlapping bool) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Find:        "set_find",
		FindBatch:   "set_find_batch",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	return w, err
}

// runBatchFind drives find_batch to exhaustion with the given buffer capacity,
// exactly as a generated iterator would: allocate the buffer and the gate
// array, start from cursor 0, hand the previous return value back unchanged.
func runBatchFind(t *testing.T, pats []string, input string, outCap int32, overlapping bool) []setMatch {
	t.Helper()
	w, err := compileBatchSet(pats, overlapping)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "set_find_batch")
	if fn == nil {
		t.Fatal("module missing set_find_batch export")
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

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out []setMatch
	cursor := int64(0)
	// A batch call always either reports a tuple or ends the scan, so the
	// number of calls is bounded by the number of matches. The cap turns a
	// non-advancing cursor into a failure instead of a hang.
	maxCalls := 8*(len(input)+1)*(len(pats)+1) + 16
	for calls := 0; ; calls++ {
		if calls > maxCalls {
			t.Fatalf("%v on %q cap=%d: find_batch did not terminate after %d calls",
				pats, input, outCap, calls)
		}
		var args []interface{}
		if overlapping {
			args = []interface{}{inBase, int32(len(input)), cursor, outPtr, outCap}
		} else {
			args = []interface{}{inBase, int32(len(input)), cursor, gatePtr, outPtr, outCap}
		}
		res, err := fn.Call(store, args...)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		if n < 0 || n > outCap {
			t.Fatalf("%v on %q cap=%d: count %d out of range", pats, input, outCap, n)
		}
		buf := mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			})
		}
		if uint32(packed>>32) == 0xFFFFFFFF {
			break
		}
		cursor = packed
	}
	return out
}

// checkBatch compares find_batch against the union-of-FindAllIndex oracle at
// several buffer capacities, including capacities far below one position's
// worst case.
func checkBatch(t *testing.T, pats []string, input string) {
	t.Helper()
	want := gatedOracle(pats, input)
	sortMatches(want)
	for _, outCap := range []int32{1, 2, int32(len(pats)), int32(len(pats)) + 3, 64} {
		if outCap < 1 {
			continue
		}
		got := runBatchFind(t, pats, input, outCap, false)
		sortMatches(got)
		if len(want) != len(got) {
			t.Fatalf("%v on %q cap=%d: expected %d matches %v, got %d %v",
				pats, input, outCap, len(want), want, len(got), got)
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("%v on %q cap=%d: match %d expected %+v, got %+v",
					pats, input, outCap, i, want[i], got[i])
			}
		}
	}
}

func TestFindBatchOneSet(t *testing.T) {
	pats := []string{
		`a*`, `a+`, `a`, `ab`, `[a-z]+X`, `x?`, `(?:)`, `a{2,5}`, `\d+`,
		`foo|foobar`, `(?:ab)+`, `\bcat\b`, `(?m:^)a`, `a(?m:$)`, `\Aab`, `ab\z`,
	}
	inputs := []string{"", "a", "aa", "aaa", "bab", "abcX", "cat cat", "a\nba\n", "abab", "foobar"}
	for _, p := range pats {
		for _, in := range inputs {
			t.Run(p+"|"+in, func(t *testing.T) { checkBatch(t, []string{p}, in) })
		}
	}
}

// TestFindBatchMultiPattern is where a split position actually happens: several
// patterns reporting at ONE start, with a buffer too small to hold them all.
func TestFindBatchMultiPattern(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`a`, `a`, `a`, `a`}, "aaaa"},
		{[]string{`a`, `ab`, `abc`, `abcd`}, "abcdabcd"},
		{[]string{`a*`, `a+`, `a`}, "aaa"},
		{[]string{`foo`, `foobar`, `o`, `oo`}, "foobar foo"},
		{[]string{`x?`, `y?`, `z?`}, "xyz"},
		{[]string{`\bcat\b`, `cat`, `at`, `t`}, "cat concat cat"},
		{[]string{`(?m:^)a`, `a`, `a(?m:$)`}, "a\na\na"},
		{[]string{`\d+`, `\d`, `[0-9]{2}`}, "12345"},
		{[]string{`(?:)`, `a`}, "aaa"},
		{[]string{`ab\z`, `b`, `ab`}, "abab"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) { checkBatch(t, c.pats, c.input) })
	}
}

// TestFindBatchOverlapping covers the mode with no gate array, where a split
// position is resumed through the cursor's k field and the suffix functions'
// `skip` parameter instead.
func TestFindBatchOverlapping(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`a`}, "aaa"},
		{[]string{`a*`}, "aa"},
		{[]string{`a`, `a`, `a`}, "aaa"},
		{[]string{`a`, `ab`, `abc`}, "abcabc"},
		{[]string{`a{2,5}?`}, "aaaaaa"},
		{[]string{`.*?end`, `end`}, "xyzend"},
		{[]string{`foo`, `o`, `oo`}, "foo foo"},
		{[]string{`x?`, `y?`}, "xy"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) {
			var want []setMatch
			for k, p := range c.pats {
				for _, sp := range allStartPositionMatches(regexp.MustCompile(p), c.input) {
					want = append(want, setMatch{PatternID: k, Start: sp[0], End: sp[1]})
				}
			}
			sortMatches(want)
			for _, outCap := range []int32{1, 2, int32(len(c.pats)), 64} {
				got := runBatchFind(t, c.pats, c.input, outCap, true)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%v on %q cap=%d: expected %d %v, got %d %v",
						c.pats, c.input, outCap, len(want), want, len(got), got)
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%v on %q cap=%d: match %d expected %+v, got %+v",
							c.pats, c.input, outCap, i, want[i], got[i])
					}
				}
			}
		})
	}
}

// FuzzFindBatch is the differential target: two arbitrary patterns, driven at a
// buffer capacity of ONE so every multi-match position is split, against the
// union-of-FindAllIndex oracle.
//
// Capacity 1 is the sharpest setting available. It maximises the number of
// resume points, and every one of them exercises the property the whole design
// rests on: re-entering a position enumerates it identically, minus what was
// already delivered.
func FuzzFindBatch(f *testing.F) {
	corpus := seedCorpus(seedFile)
	for i := 0; i+1 < len(corpus) && i < 200; i += 2 {
		f.Add(corpus[i].pattern, corpus[i+1].pattern, corpus[i].input)
	}
	f.Add(`foo`, `bar`, "xxfooyybar")
	f.Add(`a*`, `a`, "aaa")
	f.Add(`\bcat\b`, `cat`, "cat concat")
	f.Add(`(?m:^)a`, `a`, "a\nba\nb")
	f.Add(`(?:)`, `a`, "aa")

	f.Fuzz(func(t *testing.T, pat1, pat2, input string) {
		if len(input) > 48 {
			t.Skip("input too long: the capacity-1 sweep is one WASM call per match")
		}
		pats := []string{pat1, pat2}
		for _, p := range pats {
			if reason := skipPattern(p, input); reason != "" {
				t.Skip(reason)
			}
			if regexp.MustCompile(p).NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
		}
		checkBatch(t, pats, input)
	})
}

// TestFindBatchZeroCap pins the raw-ABI contract for a buffer with no room.
//
// A caller that loops "call, consume count, hand the cursor back, stop on the
// sentinel" is the shape every generated stub has, and it is the only shape the
// cursor supports. With out_cap = 0 the body can deliver nothing, so if it
// returned the caller's own resume position the loop would never advance and
// never stop. It reports the scan finished instead — the buffer, the gate array
// and the count all stay at "nothing happened", and the loop terminates.
//
// This is a deliberate asymmetry with `find`, where out_cap = 0 is a size probe:
// `find` returns a COUNT, which a probe can use, while find_batch returns a
// resumable cursor, which a probe cannot.
func TestFindBatchZeroCap(t *testing.T) {
	for _, overlapping := range []bool{false, true} {
		name := "gated"
		if overlapping {
			name = "overlapping"
		}
		t.Run(name, func(t *testing.T) {
			pats := []string{`a`, `ab`, `b`}
			const input = "abab"

			w, err := compileBatchSet(pats, overlapping)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "set_find_batch")
			if fn == nil {
				t.Fatal("module missing set_find_batch export")
			}
			const pageSize = 65536
			dataTop, err := utils.ParseDataSectionBytes(w)
			if err != nil {
				t.Fatalf("parse data section: %v", err)
			}
			inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
			gatePtr := inBase + pageSize
			outPtr := gatePtr + pageSize
			needed := uint64((int64(outPtr) + 2*pageSize + pageSize - 1) / pageSize)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatalf("grow: %v", err)
				}
			}
			buf := mem.UnsafeData(store)
			copy(buf[inBase:], input)
			for i := int32(0); i < 4*int32(len(pats)); i++ {
				buf[gatePtr+i] = 0
			}
			// Poison the tuple buffer: a body that wrote through a zero-length
			// buffer would clear these.
			for i := int32(0); i < 12*int32(len(pats)); i++ {
				buf[outPtr+i] = 0xAA
			}

			countBits := uint(config.SetCursorCountBits(len(pats)))
			countMask := int64(1)<<countBits - 1

			// The `from` of the very first call is 0, which is also a legal
			// resume position — the value the pre-fix body handed back.
			var args []interface{}
			if overlapping {
				args = []interface{}{inBase, int32(len(input)), int64(0), outPtr, int32(0)}
			} else {
				args = []interface{}{inBase, int32(len(input)), int64(0), gatePtr, outPtr, int32(0)}
			}
			res, err := fn.Call(store, args...)
			if err != nil {
				t.Fatalf("set_find_batch: %v", err)
			}
			packed := res.(int64)
			if got := uint32(packed >> 32); got != 0xFFFFFFFF {
				t.Fatalf("out_cap=0: expected the done sentinel, got resume position %d "+
					"(a caller looping on this cursor spins)", got)
			}
			if n := packed & countMask; n != 0 {
				t.Fatalf("out_cap=0: count %d, want 0", n)
			}
			buf = mem.UnsafeData(store)
			for i := int32(0); i < 12*int32(len(pats)); i++ {
				if buf[outPtr+i] != 0xAA {
					t.Fatalf("out_cap=0: wrote byte %d of the tuple buffer", i)
				}
			}
			for i := int32(0); i < 4*int32(len(pats)); i++ {
				if buf[gatePtr+i] != 0 {
					t.Fatalf("out_cap=0: wrote byte %d of the gate array", i)
				}
			}

			// And the loop a stub writes terminates on the first call.
			if got := runBatchFind(t, pats, input, 0, overlapping); len(got) != 0 {
				t.Fatalf("out_cap=0: yielded %d matches, want none", got)
			}
		})
	}
}
