package fuzz

import (
	"encoding/binary"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// The batch groups export (LM-2) writes several matches per call into a
// caller buffer. It is a SEPARATE path from the one-at-a-time groups export
// and the generated JS/TS stubs prefer it when present, so a defect here is
// invisible to every groups test that drives `groups`.
func TestBatchGroupsMatchesGo(t *testing.T) {
	const outBase, outCap = int32(128 * 1024), int32(64)
	for _, c := range []struct{ pat, input string }{
		{`https?://(?P<host>[a-z.]+)`, "see http://example.com and http://foo.org here"},
		{`(a)(b)`, "abXab"},
		{`\b(foo)`, "foofoo"},
		{`(a*)`, "bab"},
	} {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re := regexp.MustCompile(c.pat)
			nGroups := re.NumSubexp() + 1
			w, _, err := compile.Compile([]config.RegexEntry{{
				Pattern: c.pat, GroupsFunc: "groups", Hints: []string{"batch-find"},
			}}, pathsTableBase, true)
			if err != nil {
				// Fixed, valid fixtures: a compile failure is the regression,
				// not a reason to stop testing.
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "groups_batch")
			if fn == nil {
				// The config above asks for the batch export by name
				// (Hints: batch-find), so its absence IS the regression this
				// test exists to catch.
				t.Fatal("no groups_batch export: the config requested it via " +
					"hints: [batch-find]")
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], c.input)
			res, callErr := fn.Call(store, pathsInputBase, int32(len(c.input)), outBase, outCap, int32(0))
			if callErr != nil {
				t.Fatalf("call: %v", callErr)
			}
			n := int(res.(int32))
			buf := mem.UnsafeData(store)
			rec := 8 + nGroups*8 // (start,end) then numGroups (start,end) slot pairs
			var got [][]int
			for i := 0; i < n; i++ {
				base := int(outBase) + i*rec + 8
				m := make([]int, nGroups*2)
				for j := range m {
					m[j] = int(int32(binary.LittleEndian.Uint32(buf[base+j*4:])))
				}
				got = append(got, m)
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("batch groups over %q (n=%d):\n  got  %s\n  want %s",
					c.input, n, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}
