package fuzz

import (
	"fmt"
	"regexp"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// Merged-mode (embedded) execution coverage — plans/SETS.md §11 R2 and
// R-TESTS(2).
//
// Every other harness in this repo runs STANDALONE modules, where the module
// declares and exports its own memory and the DFA tables live in the same
// memory as the input. Embedded modules — what `output:` produces, and what
// every Rust/Go/C/AS example ships — instead IMPORT the host's memory as
// memory 0 and keep their tables in memory 1.
//
// That difference is invisible to a standalone test by construction, which is
// how §11 R2 shipped: the zero-width machinery read input bytes through the
// table-memory helper, so in embedded builds every \b, \B, (?m:^) and (?m:$)
// set pattern consulted DFA-table bytes instead of the caller's text — giving
// both false negatives and false positives. Standalone builds were correct
// because there the two memories are the same memory.
//
// These tests therefore run the SAME assertions against BOTH builds. A future
// regression in memory indexing fails here rather than in a user's app.

// compileSetBothModes compiles a one-pattern set twice: standalone, and
// embedded (which is selected by a non-empty Output).
func compileSetBothModes(t *testing.T, pat string, caps func(*config.SetConfig)) (standalone, embedded []byte) {
	t.Helper()
	build := func(output string) []byte {
		sc := config.SetConfig{
			Name:     "s",
			Patterns: config.PatternSelector{Names: []string{"p0"}},
		}
		caps(&sc)
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{{Name: "p0", Pattern: pat}},
			Sets:    []config.SetConfig{sc},
			Output:  output,
		}
		w, _, err := compile.CompileFile(cfg, "")
		if err != nil {
			t.Fatalf("compile %q (output=%q): %v", pat, output, err)
		}
		return w
	}
	return build(""), build("merged.wasm")
}

// runScanStandalone calls `scan` on a standalone module.
func runScanStandalone(t *testing.T, w []byte, input string, from int32) bool {
	t.Helper()
	store, inst, mem, err := instantiate(w)
	if err != nil {
		t.Fatalf("instantiate standalone: %v", err)
	}
	const inBase = int32(1 << 20)
	need := uint64((int64(inBase) + int64(len(input)) + 65535) / 65536)
	if cur := mem.Size(store); need > cur {
		if _, err := mem.Grow(store, need-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	copy(mem.UnsafeData(store)[inBase:], input)
	res, err := inst.GetFunc(store, "s_scan").Call(store, inBase, int32(len(input)), from)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res.(int32) != 0
}

// runScanEmbedded calls `scan` on an embedded module, supplying the host
// memory the module imports as "main"."memory" — the wasm-merge arrangement,
// modelled directly.
func runScanEmbedded(t *testing.T, w []byte, input string, from int32) bool {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("embedded module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	const pages = 32
	mt, err := wasmtime.NewMemoryType(pages, false, 0, false)
	if err != nil {
		t.Fatalf("memory type: %v", err)
	}
	hostMem, err := wasmtime.NewMemory(store, mt)
	if err != nil {
		t.Fatalf("host memory: %v", err)
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{hostMem})
	if err != nil {
		t.Fatalf("instantiate embedded: %v", err)
	}
	const inBase = int32(4096)
	copy(hostMem.UnsafeData(store)[inBase:], input)
	res, err := inst.GetFunc(store, "s_scan").Call(store, inBase, int32(len(input)), from)
	if err != nil {
		t.Fatalf("scan (embedded): %v", err)
	}
	return res.(int32) != 0
}

// TestSetMergedModeAssertions runs the context-assertion classes through both
// builds and against Go, in both the matching and NON-matching direction —
// the false-positive direction matters, because a wrong-memory read of a zero
// byte makes \b hold and \B fail everywhere.
func TestSetMergedModeAssertions(t *testing.T) {
	cases := []struct{ pat, input string }{
		// word boundaries, both directions
		{`\bfoo`, "x foo"},
		{`\bfoo`, "xfoo"},
		{`foo\b`, "foo x"},
		{`foo\b`, "foox"},
		{`x\by`, "xy"},
		{`a\Bb`, "ab"},
		{`\Bfoo`, "xfoo"},
		{`\Bfoo`, " foo"},
		// line anchors, both directions
		{`(?m:^)bar`, "x\nbar"},
		{`(?m:^)bar`, "xbar"},
		{`foo(?m:$)`, "foo\nbar"},
		{`foo(?m:$)`, "foox"},
		{`(?m:^)foo(?m:$)`, "a\nfoo\nb"},
		// mixed contexts in one pattern: the entry-state selection has to
		// handle a bucket carrying BOTH kinds (§11 R4)
		{`(?:\bfoo|(?m:^)bar)`, "x\nbar"},
		{`(?:\bfoo|(?m:^)bar)`, "x foo"},
		{`(?:\bfoo|(?m:^)bar)`, "xfooybarz"},
		// no assertion at all: control rows
		{`foo`, "xfooy"},
		{`foo`, "xbary"},
	}
	setScan := func(sc *config.SetConfig) { sc.Scan = "s_scan" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q", c.pat, c.input), func(t *testing.T) {
			want := regexp.MustCompile(c.pat).MatchString(c.input)
			sa, emb := compileSetBothModes(t, c.pat, setScan)
			gotSA := runScanStandalone(t, sa, c.input, 0)
			gotEmb := runScanEmbedded(t, emb, c.input, 0)
			if gotSA != want {
				t.Errorf("standalone scan = %v, Go says %v", gotSA, want)
			}
			if gotEmb != want {
				t.Errorf("embedded scan = %v, Go says %v "+
					"(embedded reads input from memory 0 and tables from memory 1; "+
					"see plans/SETS.md §11 R2)", gotEmb, want)
			}
			if gotSA != gotEmb {
				t.Errorf("standalone and embedded disagree: %v vs %v", gotSA, gotEmb)
			}
		})
	}
}

// runFindEmbedded drives `find` to exhaustion on an embedded module, with the
// gate array and out buffer in the imported host memory — what a merged
// Rust/Go/C stub does.
func runFindEmbedded(t *testing.T, w []byte, input string) [][2]int {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("embedded module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	mt, err := wasmtime.NewMemoryType(32, false, 0, false)
	if err != nil {
		t.Fatalf("memory type: %v", err)
	}
	hostMem, err := wasmtime.NewMemory(store, mt)
	if err != nil {
		t.Fatalf("host memory: %v", err)
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{hostMem})
	if err != nil {
		t.Fatalf("instantiate embedded: %v", err)
	}
	const (
		inBase  = int32(4096)
		gatePtr = int32(1 << 16)
		outPtr  = int32(1<<16 + 4096)
	)
	buf := hostMem.UnsafeData(store)
	copy(buf[inBase:], input)
	for i := int32(0); i < 4; i++ {
		buf[gatePtr+i] = 0
	}
	fn := inst.GetFunc(store, "s_find")
	var out [][2]int
	from := int32(0)
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), from, gatePtr, outPtr, int32(1))
		if err != nil {
			t.Fatalf("find (embedded): %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf = hostMem.UnsafeData(store)
		start := int32(le32(buf[outPtr+4:]))
		out = append(out, [2]int{int(start), int(le32(buf[outPtr+8:]))})
		from = start + 1
	}
	return out
}

func le32(b []byte) int32 {
	return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}

// TestSetMergedModeFind covers the tuple-writing suffix body in embedded mode.
// TestSetMergedModeAssertions drives `scan`, which goes through the cheap
// bitmask probes — a different emitter with its own copy of the zero-width
// machinery, so both need a merged-mode row (plans/SETS.md §11 R2/R12).
func TestSetMergedModeFind(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`\bfoo\b`, "foo xfoo foo"},
		{`foo\b`, "foox foo"},
		{`a\Bb`, "ab xab"},
		{`(?m:^)bar`, "bar\nxbar\nbar"},
		{`foo(?m:$)`, "foo\nfoox\nfoo"},
		{`(?:\bfoo|(?m:^)bar)`, "x\nbar foo"},
	}
	setFind := func(sc *config.SetConfig) { sc.Find = "s_find" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q", c.pat, c.input), func(t *testing.T) {
			// Gated find's contract IS Go's FindAllIndex rule (§9.6.1).
			var want [][2]int
			for _, m := range regexp.MustCompile(c.pat).FindAllStringIndex(c.input, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			_, emb := compileSetBothModes(t, c.pat, setFind)
			got := runFindEmbedded(t, emb, c.input)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("embedded find = %v, Go FindAllIndex = %v "+
					"(see plans/SETS.md §11 R2)", got, want)
			}
		})
	}
}

// TestSetMergedModeFromResume covers the same machinery at from > 0, where the
// entry state is chosen from the PRECEDING byte — the read most likely to go
// to the wrong memory.
func TestSetMergedModeFromResume(t *testing.T) {
	cases := []struct {
		pat, input string
		from       int32
	}{
		{`\bfoo`, "foo foo", 1},   // from mid-word: the foo at 4 still matches
		{`\bfoo`, "xfoofoo", 1},   // no word boundary anywhere at or after 1
		{`(?m:^)b`, "a\nb\nb", 2}, // resume exactly at a line start
		{`(?m:^)b`, "ab\nb", 1},   // resume just after a non-newline
		{`a\Bb`, "abab", 1},       // \B mid-input at a resume point
	}
	setScan := func(sc *config.SetConfig) { sc.Scan = "s_scan" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q from %d", c.pat, c.input, c.from), func(t *testing.T) {
			// Oracle: does the pattern match at any position >= from, judged on
			// the WHOLE input so assertions see real context (§9.6).
			want := false
			for p := int(c.from); p <= len(c.input); p++ {
				re := regexp.MustCompile(`\A(?s:.{` + itoa(p) + `})(?:` + c.pat + `)`)
				if re.FindStringIndex(c.input) != nil {
					want = true
					break
				}
			}
			sa, emb := compileSetBothModes(t, c.pat, setScan)
			gotSA := runScanStandalone(t, sa, c.input, c.from)
			gotEmb := runScanEmbedded(t, emb, c.input, c.from)
			if gotSA != want || gotEmb != want {
				t.Errorf("standalone=%v embedded=%v, oracle says %v", gotSA, gotEmb, want)
			}
		})
	}
}
