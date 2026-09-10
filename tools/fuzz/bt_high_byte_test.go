package fuzz

import (
	"encoding/binary"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// Regression: the Backtracking engine dropped every input byte >= 0x80 from a
// rune RANGE, so a capture pattern over a negated class silently failed to
// match input containing such a byte.
//
// `.` and negated classes consuming ONE BYTE is documented byte semantics
// (docs/engines.md, "Bytes, not codepoints"), so `[^>]` must match 0xE9. The
// DFA agrees: nfaBuildInputMap SATURATES a range at 0xFF. Backtracking
// TRUNCATED at 0x7F instead — `if lo > 0x7F { continue }` in btCheckRuneRanges
// and btEmitSingleRange — and nfaFirstBytes gated its scan prefilter the same
// way, so a match STARTING with a high byte was skipped outright.
//
// Backtracking is a hybrid: the DFA finds the match extent, the NFA fills the
// captures. That is why the defect showed only through `groups` — `find` took
// the DFA's answer and was right, then `groups` re-walked the same input with
// the truncated ranges and reported no match at all.
//
// The affected family is precisely the one the engine-selection gate exists to
// route here: `<([^>]+)>`, `([^,]+),`, `KEY=([^&]+)&` (see CLAUDE.md's
// load-bearing gates section). An inverted class is what sends a capture
// pattern to Backtracking, and an inverted class is what carries the high
// bytes.
//
// ORACLE. An isomorphism, for the same reason byte_mode_length_test.go uses
// one: Go reads its input as UTF-8, so it cannot be asked about a raw 0xE9. A
// byte engine treats 0xE9 exactly like any other byte absent from the pattern,
// so mapping it to an ASCII stand-in that also appears nowhere gives a
// question Go can answer. That is an independent oracle, not a transcript of
// engine output.
//
// NOTE ON COVERAGE. tools/re2test cannot host this case: it skips every input
// containing a byte above 127 (hasUnicode), so no corpus row ever feeds a high
// byte to any engine. That blind spot is why this survived.

const (
	btHiByte   = "\xe9"
	btHiStandI = "Q"
)

func TestBTHighByteInRanges(t *testing.T) {
	shapes := []struct {
		name, pat, input string
		groups           int
	}{
		// The canonical Backtracking family, high byte INSIDE the match.
		{"angle", `<([^>]+)>`, "<caf\xe9>", 1},
		{"comma", `([^,]+),`, "caf\xe9,", 1},
		{"kv", `KEY=([^&]+)&`, "KEY=caf\xe9&", 1},
		{"quoted", `"([^"]*)"`, "\"caf\xe9\"", 1},
		{"nonspace", `(\S+)!`, "caf\xe9!", 1},
		{"two-groups", `<([^>]+)>=([^;]+);`, "<caf\xe9>=va\xe9l;", 2},

		// High byte at the START of the match — the nfaFirstBytes prefilter.
		{"first-byte", `([^,]+),`, "\xe9ab,", 1},
		{"first-byte-only", `([^,]+),`, "\xe9,", 1},

		// High byte at both ends.
		{"both-ends", `([^,]+),`, "\xe9a\xe9,", 1},

		// Pure-ASCII controls: these must not change.
		{"ascii-angle", `<([^>]+)>`, "<cafe>", 1},
		{"ascii-comma", `([^,]+),`, "cafe,", 1},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			eng, serr := compile.SelectEngine(sh.pat, compile.CompileOptions{})
			if serr != nil {
				t.Fatalf("select: %v", serr)
			}
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}

			// The isomorphic twin: 0xE9 -> 'Q' in the input only. No shape
			// here names a high byte in the PATTERN.
			oracleIn := strings.ReplaceAll(sh.input, btHiByte, btHiStandI)
			re := regexp.MustCompile(`(?s)` + sh.pat)
			want := re.FindStringSubmatchIndex(oracleIn)

			got := res.(int32)
			if want == nil {
				if got >= 0 {
					t.Errorf("engine %v: pattern %q over %q matched, want no match", eng, sh.pat, sh.input)
				}
				return
			}
			if got < 0 {
				t.Fatalf("engine %v: pattern %q over %q returned %d (no match), want spans %v\n"+
					"  a negated class must match a byte >= 0x80: `.` and negated classes "+
					"consume ONE BYTE (docs/engines.md)", eng, sh.pat, sh.input, got, want)
			}

			buf := mem.UnsafeData(store)
			slots := (sh.groups + 1) * 2
			for i := 0; i < slots; i++ {
				v := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
				wantV := int32(want[i])
				if v != wantV {
					t.Errorf("engine %v: pattern %q over %q slot %d: got %d, want %d (all spans %v)",
						eng, sh.pat, sh.input, i, v, wantV, want)
				}
			}
		})
	}
}

// The same defect under byte_mode, where the pattern names the high bytes
// itself rather than admitting them through a negated class.
func TestBTHighByteByteMode(t *testing.T) {
	shapes := []struct{ name, pat, input string }{
		{"hi-class-plus", `([\x80-\xff]+)x`, "\xe9\xeax"},
		{"hi-class-one", `a([\x80-\xff])b`, "a\xe9b"},
		{"hi-range-mixed", `([a-\xff]+)!`, "ca\xe9!"},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, GroupsFunc: "groups", ByteMode: true}
			// Forced, because auto-selection sends these to TDFA today. The
			// clamp is Backtracking's, so Backtracking is what must be asked.
			w, _, err := compile.CompileForced([]config.RegexEntry{entry},
				pathsTableBase, true, compile.EngineBacktrack)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], sh.input)
			res, cerr := inst.GetFunc(store, "groups").Call(store,
				pathsInputBase, int32(len(sh.input)), pathsOutBase, int32(0))
			if cerr != nil {
				t.Fatalf("groups call: %v", cerr)
			}
			if got := res.(int32); got < 0 {
				t.Errorf("Backtracking: pattern %q over %q returned %d, want a match\n"+
					"  byte_mode declares runes 0x80-0xFF to mean those BYTES",
					sh.pat, sh.input, got)
			}
		})
	}
}
