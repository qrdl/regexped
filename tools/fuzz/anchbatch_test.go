package fuzz

import (
	"encoding/binary"
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// An anchored find compiled WITH a batch export. The batch loop calls the find
// BODY directly, and an ffAnchoredZeroOnly body ignores the find-from channel
// entirely — it always reports the match beginning at 0. So a resumed call at
// pos > 0 must never reach it: before the guard it handed back the same
// position-0 match, from which the wrapper computed a NEGATIVE relative offset.
//
// Nothing else covers this: the exported find is fine (its own wrapper rejects
// from != 0), so the defect is reachable only through the batch entry.
func TestAnchoredBatchDoesNotRepeat(t *testing.T) {
	const outBase, outCap = int32(1 << 16), int32(64)
	for _, c := range []struct{ pat, input string }{
		{`\Aa+`, "aaabaaa"},
		{`\A`, "abc"},
		{`\Aab*`, "abbabb"},
	} {
		w, _, err := compile.Compile([]config.RegexEntry{{
			Pattern: c.pat, FindFunc: "find", Hints: []string{"batch-find"},
		}}, pathsTableBase, true)
		if err != nil {
			t.Fatalf("%q compile: %v", c.pat, err)
		}
		store, inst, mem, release, err := instantiate(w)
		if err != nil {
			release()
			t.Fatalf("%q instantiate: %v", c.pat, err)
		}
		fn := inst.GetFunc(store, "find_batch")
		if fn == nil {
			release()
			t.Fatalf("%q: no find_batch export", c.pat)
		}
		copy(mem.UnsafeData(store), c.input)
		res, callErr := fn.Call(store, int32(0), int32(len(c.input)), outBase, outCap, int32(0))
		if callErr != nil {
			release()
			t.Fatalf("%q call: %v", c.pat, callErr)
		}
		n := int(res.(int32))
		var got [][2]int
		buf := mem.UnsafeData(store)
		for i := 0; i < n; i++ {
			off := int(outBase) + i*8
			got = append(got, [2]int{
				int(int32(binary.LittleEndian.Uint32(buf[off:]))),
				int(int32(binary.LittleEndian.Uint32(buf[off+4:]))),
			})
		}
		release()
		want := goFindAll(regexp.MustCompile(c.pat), c.input)
		if fmtSpans(got) != fmtSpans(want) {
			t.Errorf("%q on %q via find_batch: got %s want %s (n=%d)",
				c.pat, c.input, fmtSpans(got), fmtSpans(want), n)
		}
	}
}
