package fuzz

import (
	"regexp"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// A wholly empty-width word-boundary pattern lost every boundary whose
// PRECEDING byte was a word character and whose following byte was not.
// `\b` over "a b" reported boundaries at 0, 2 and 3 and skipped the one at 1.
//
// ROOT CAUSE. Find mode picks candidate start positions from `firstByteFlags`.
// For a word-boundary pattern that table is built from two sources: the
// byte-consuming transitions out of each start state, and — for a pattern that
// can accept an EMPTY match — the `midAcceptNW/W` tables. The empty-width half
// consulted `midStartState` (prev = non-word) and `startState`, but never
// `midStartWordState` (prev = word). The transitions half had already been
// taught about that state; the accept half had not.
//
// So nothing ever flagged a byte as "a match can begin here with prev=word",
// and every such position was skipped before the boundary was even evaluated.
//
// WHY ONLY BARE `\b` AND `\B`. As soon as a pattern consumes a byte, the
// transitions out of `midStartWordState` set the same flags and the answer
// comes out right — which is why `\b,`, `\b\s`, `\b[^a-z]`, `\bfoo` and
// `\b[a-z]+` were all correct throughout, and why the corpus never noticed.
//
// WHY THE CORPUS NEVER NOTICED. re2-exhaustive.txt carries four columns, so
// col4 (ALL matches) is absent and only the FIRST match is ever checked. For
// bare `\b` the first match is at position 0, which was always found. The
// defect lives entirely in the second and later matches.
//
// It was found by tools/re2test's --high-bytes mode, which synthesises col4
// from a Go oracle, in its high-byte disguise (`\b` over "aâb"). The bug is not
// high-byte specific at all — pure ASCII "a b" fails identically — but the
// high-byte harness was the first thing to check an all-matches column for this
// pattern shape.

func TestEmptyWidthBoundaryFindsEveryPosition(t *testing.T) {
	cases := []struct{ pat, in string }{
		{`\b`, "a b"},
		{`\b`, "a,b"},
		{`\b`, "a\tb"},
		{`\b`, "ab cd ef"},
		{`\b`, "a"},
		{`\b`, " a "},
		{`\b`, "ab"},
		{`\B`, "ab c"},
		{`\B`, "a  b"},
		{`\B`, "abc"},
		// Content-bearing siblings, which always worked. Here so a future
		// change cannot fix the empty case by breaking these.
		{`\b,`, "a,b"},
		{`\b\s`, "a b"},
		{`\b[^a-z]`, "a,b"},
		{`\bfoo`, ",foo foo"},
		{`\b[a-z]+`, "a bc de"},
		{`x\b`, "x y x"},
	}
	for _, c := range cases {
		t.Run(c.pat+"/"+c.in, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: c.pat, FindFunc: "find"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, ierr := instantiate(w)
			defer release()
			if ierr != nil {
				t.Fatalf("instantiate: %v", ierr)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], c.in)
			fn := inst.GetFunc(store, "find")

			var got [][2]int
			for off := 0; off <= len(c.in); {
				r, cerr := fn.Call(store, pathsInputBase, int32(len(c.in)), int32(off))
				if cerr != nil {
					t.Fatalf("find(%d): %v", off, cerr)
				}
				v := r.(int64)
				if v < 0 {
					break
				}
				s, e := int(uint32(v>>32)), int(uint32(v))
				if s < off {
					t.Fatalf("find(%d) returned a match starting at %d, before `from`", off, s)
				}
				got = append(got, [2]int{s, e})
				// The advance rule every generated stub uses: past a
				// zero-length match by one byte.
				if e > s {
					off = e
				} else {
					off = s + 1
				}
			}

			var want [][2]int
			for _, loc := range regexp.MustCompile(c.pat).FindAllStringIndex(c.in, -1) {
				want = append(want, [2]int{loc[0], loc[1]})
			}
			if len(got) != len(want) {
				t.Fatalf("pattern %q over %q: got %v, want %v", c.pat, c.in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("pattern %q over %q: got %v, want %v", c.pat, c.in, got, want)
				}
			}
		})
	}
}

// The same defect in its high-byte disguise, which is how it was found. A high
// byte is not a word character, so "a" followed by 0xE9 is a boundary. Go
// cannot be the oracle here — it decodes UTF-8 — so the expectation is computed
// from the definition of \b over BYTES.
func TestEmptyWidthBoundaryOverHighBytes(t *testing.T) {
	isWord := func(b byte) bool {
		return b == '_' || (b >= '0' && b <= '9') ||
			(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	for _, in := range []string{"a\xe9b", "a\xc3\xa2b", "a\xe9", "\xe9a", "\xe9\xe9", "a\xe9\xe9b"} {
		t.Run(in, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: `\b`, FindFunc: "find"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, ierr := instantiate(w)
			defer release()
			if ierr != nil {
				t.Fatalf("instantiate: %v", ierr)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], in)
			fn := inst.GetFunc(store, "find")

			var got []int
			for off := 0; off <= len(in); off++ {
				r, cerr := fn.Call(store, pathsInputBase, int32(len(in)), int32(off))
				if cerr != nil {
					t.Fatalf("find(%d): %v", off, cerr)
				}
				v := r.(int64)
				if v < 0 {
					break
				}
				s := int(uint32(v >> 32))
				got = append(got, s)
				off = s
			}

			var want []int
			for p := 0; p <= len(in); p++ {
				pw, nw := false, false
				if p > 0 {
					pw = isWord(in[p-1])
				}
				if p < len(in) {
					nw = isWord(in[p])
				}
				if pw != nw {
					want = append(want, p)
				}
			}
			if len(got) != len(want) {
				t.Fatalf(`\b over %q: got %v, want %v`, in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf(`\b over %q: got %v, want %v`, in, got, want)
				}
			}
		})
	}
}
