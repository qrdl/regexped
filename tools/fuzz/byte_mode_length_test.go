package fuzz

import (
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// Regression: under `byte_mode: true` a literal rune 0x80..0xFF means exactly
// that BYTE, so it consumes ONE byte — not the two its UTF-8 encoding would
// take. regexpMinMaxLen sized every such rune by its encoding, which makes it
// an OVER-estimate, and its callers all read it as a true bound:
//
//   - the exported find wrapper turns minLen into an early exit, so an
//     over-estimate REFUSES an input that matches. `\xe9ab` answered -1 for
//     the 3-byte input "\xe9ab" while answering correctly for every longer one
//     — the shortest input for a shape is the only one that shows it, which is
//     why nothing caught this.
//   - the mandatory-literal analyser accumulates it as the literal's offset
//     from the match start, and the lit-anchor emitters take it as a fixed
//     prefix length.
//
// ORACLE. Go's regexp cannot express byte mode, so the expectation comes from
// an ISOMORPHISM instead: under a byte engine, the high byte 0xE9 behaves
// exactly like any other byte that appears nowhere else in the pattern or the
// input. Mapping 0xE9 to 'Q' in both gives a pattern Go can run, over an
// alphabet where the two are interchangeable. That is an independent oracle,
// not a transcript of engine output.
//
// The shapes are chosen to reach different emitters — plain DFA find,
// mandatory-literal lit-anchor, alternation lit-anchor, counted chain — so a
// length bug in any of the analysers that consume regexpMinMaxLen shows up
// here and not only in the wrapper's early exit.

func TestByteModeLengthsAcrossEmitters(t *testing.T) {
	const hiByte = "\xe9"
	const asciiStandIn = "Q"

	shapes := []struct{ name, pat string }{
		{"literal-only", `\xe9ab`},
		{"class-then-lit", `[a-y]\xe9foo`},
		{"plus-then-lit", `\xe9+bar`},
		{"lit-anchor-fixed-prefix", `[a-y]\xe9zzzz`},
		{"alt-lit", `(?:\xe9ab|\xe9cd)`},
		{"mand-lit-mid", `a\xe9b`},
		{"counted", `\xe9{2}xy`},
		{"two-high-bytes", `\xe9\xe9ab`},
		{"high-byte-class", `[\x80-\xff]ab`},
	}

	// The shortest input for each shape is the one that matters: the early
	// exit fires on `len - from < minLen`, so an over-estimate of one byte is
	// invisible at every length above the minimum.
	inputs := []string{
		"", "\xe9", "\xe9a", "\xe9ab", "x\xe9ab", "zz\xe9abzz",
		"a\xe9foo", "qa\xe9fooq", "\xe9bar", "\xe9\xe9bar",
		"m\xe9zzzz", "a\xe9b", "\xe9\xe9xy", "\xe9\xe9ab",
		strings.Repeat("z", 40) + "\xe9ab",
		strings.Repeat("z", 9) + "a\xe9foo",
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, FindFunc: "find", ByteMode: true}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}

			// The isomorphic ASCII twin of the pattern. Go reads its input as
			// UTF-8, so a rune class cannot stand for a raw high BYTE at all —
			// `[\x80-\xff]` becomes the stand-in's own class, which is
			// equivalent as long as 0xE9 is the only high byte in the inputs.
			oraclePat := strings.ReplaceAll(sh.pat, `\xe9`, asciiStandIn)
			oraclePat = strings.ReplaceAll(oraclePat, `[\x80-\xff]`, "["+asciiStandIn+"]")
			re := regexp.MustCompile(`(?s)` + oraclePat)

			for _, in := range inputs {
				copy(mem.UnsafeData(store)[pathsInputBase:], in)
				res, cerr := inst.GetFunc(store, "find").Call(store,
					pathsInputBase, int32(len(in)), int32(0))
				if cerr != nil {
					t.Fatalf("input %q: %v", in, cerr)
				}
				got := res.(int64)

				oracleIn := strings.ReplaceAll(in, hiByte, asciiStandIn)
				loc := re.FindStringIndex(oracleIn)
				var want int64 = -1
				if loc != nil {
					want = int64(loc[0])<<32 | int64(loc[1])
				}
				if got != want {
					t.Errorf("pattern %q input %q (len %d): got %#x, want %#x (oracle %v)\n"+
						"a byte_mode literal rune 0x80..0xFF is ONE byte; an over-estimated "+
						"minimum length refuses inputs that match",
						sh.pat, in, len(in), uint64(got), uint64(want), loc)
				}
			}
		})
	}
}
