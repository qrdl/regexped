package fuzz

import (
	"encoding/binary"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// The Backtracking FALLBACK body sizes its frame stack and memo from the input
// at call time (compile/bt_scratch.go). Before it did, a call past the ORDINARY
// body's compile-time regions answered abi.BTStackOverflow — "unknown" — at
// sizes a host meets in practice: `^(\w*|)*c` over a matching input of 16,378
// bytes, where the frame stack ran out.
//
// These tests drive every body kind past those regions and require Go's answer,
// in each place the fallback can find its memory:
//
//   - standalone, host global SET: the scratch sits above the host's data and
//     is reused call after call, so memory stops growing after the first call;
//   - standalone, host global left at 0: fresh pages on every call that needs
//     them — still the right answer;
//   - embedded: the module's own memory, above its tables.
//
// Each test first proves its answer can only come from the fallback
// (requireFallbackAnswers). Without that control a later raise of the fast
// body's static stack would let every test here pass without executing a byte
// of bt_scratch.go.
//
// A CAPTURE body's ordinary frame stack is no static region any more: it is
// placed in the same run-time scratch, and grows. A groups case without a
// zero-width cycle therefore exercises that stack, in the same three places,
// and its control is the opposite one: the ordinary body alone must answer.

// btScratchInCap is the input window below the tables; the slots buffer sits
// right above it.
const btScratchInCap = 256 * 1024

// btScratchCase is one pattern driven past the ordinary body's static regions.
type btScratchCase struct {
	name  string
	entry config.RegexEntry
	opts  compile.CompileOptions
	input string
}

func btScratchCases() []btScratchCase {
	w := func(n int) string { return strings.Repeat("w", n) }
	a := func(n int) string { return strings.Repeat("a", n) }
	squeezed := compile.CompileOptions{MaxDFAStates: 1}
	return []btScratchCase{
		// The fast frame stack ends near 16 KB of greedy descent here.
		{"groups/empty-body-loop/match", config.RegexEntry{Pattern: `^(\w*|)*c`, GroupsFunc: "groups"}, compile.CompileOptions{}, w(100000) + "c"},
		{"groups/empty-body-loop/no-match", config.RegexEntry{Pattern: `^(\w*|)*c`, GroupsFunc: "groups"}, compile.CompileOptions{}, w(60000)},
		{"groups/overlapping-branches", config.RegexEntry{Pattern: `^(aa|a)*b`, GroupsFunc: "groups"}, compile.CompileOptions{}, a(80000) + "b"},
		// Composed behind the groups wrapper, in window mode (\b).
		{"groups/window", config.RegexEntry{Pattern: `x(\w*|)*c\b`, GroupsFunc: "groups"}, compile.CompileOptions{}, "--x" + w(70000) + "c--"},
		{"match/empty-body-loop", config.RegexEntry{Pattern: `(\w*|)*c`, MatchFunc: "match"}, squeezed, w(100000) + "c"},
		{"find/empty-body-loop", config.RegexEntry{Pattern: `(\w*|)*c`, FindFunc: "find"}, squeezed, "--" + w(90000) + "c"},
		// A non-greedy loop whose body can match empty: a zero-width cycle, so
		// the fallback alone, over an input far past any compile-time memo.
		{"find/static-memo-ceiling", config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"}, squeezed, a(200000) + "xyz"},
		// `z+`, not `z`: a capture between plain literals takes its span from
		// the match and has no capture body at all.
		{"groups/static-memo-ceiling", config.RegexEntry{Pattern: `((?:a?)+?)xyz+`, GroupsFunc: "groups"}, compile.CompileOptions{}, a(200000) + "xyz"},
	}
}

// want returns what the export must answer for c, as the raw value it returns
// and — for groups — the slots it must write.
func (c btScratchCase) want(t *testing.T) (int64, []int) {
	t.Helper()
	e := c.entry
	switch {
	case e.GroupsFunc != "":
		loc := regexp.MustCompile(e.Pattern).FindStringSubmatchIndex(c.input)
		if loc == nil {
			return abi.NoMatch, nil
		}
		return int64(loc[1]), loc
	case e.MatchFunc != "":
		if regexp.MustCompile(`^(?:` + e.Pattern + `)$`).MatchString(c.input) {
			return int64(len(c.input)), nil
		}
		return abi.NoMatch, nil
	default:
		loc := regexp.MustCompile(e.Pattern).FindStringIndex(c.input)
		if loc == nil {
			return abi.NoMatch, nil
		}
		return int64(loc[0])<<32 | int64(loc[1]), nil
	}
}

// call runs c's export once over memory whose input and slots live in hostMem,
// returning the raw result and the slots written.
func (c btScratchCase) call(t *testing.T, store *wasmtime.Store, inst *wasmtime.Instance, hostMem *wasmtime.Memory, numSlots int) (int64, []int) {
	t.Helper()
	buf := hostMem.UnsafeData(store)
	copy(buf, c.input)
	outBase := int32(btScratchInCap)
	for i := 0; i < numSlots; i++ {
		binary.LittleEndian.PutUint32(buf[int(outBase)+i*4:], 0xFFFFFFFF)
	}
	var res any
	var err error
	_, wd := sharedEngine()
	wd.Arm(store)
	defer wd.Disarm()
	switch e := c.entry; {
	case e.GroupsFunc != "":
		res, err = inst.GetFunc(store, e.GroupsFunc).Call(store, int32(0), int32(len(c.input)), outBase, int32(0))
	case e.MatchFunc != "":
		res, err = inst.GetFunc(store, e.MatchFunc).Call(store, int32(0), int32(len(c.input)))
	default:
		res, err = inst.GetFunc(store, e.FindFunc).Call(store, int32(0), int32(len(c.input)), int32(0))
	}
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var r int64
	switch v := res.(type) {
	case int32:
		r = int64(v)
	case int64:
		r = v
	}
	buf = hostMem.UnsafeData(store)
	slots := make([]int, numSlots)
	for i := range slots {
		slots[i] = int(int32(binary.LittleEndian.Uint32(buf[int(outBase)+i*4:])))
	}
	return r, slots
}

func (c btScratchCase) check(t *testing.T, got int64, slots []int) {
	t.Helper()
	want, wantSlots := c.want(t)
	if got == abi.BTStackOverflow {
		t.Fatalf("answered BTStackOverflow (unknown); want %d", want)
	}
	if got != want {
		t.Fatalf("answered %d, want %d", got, want)
	}
	if wantSlots != nil {
		for i, s := range wantSlots {
			if slots[i] != s {
				t.Fatalf("slot %d = %d, want %d (all: got %v, want %v)", i, slots[i], s, slots[:len(wantSlots)], wantSlots)
			}
		}
	}
}

// requireFallbackAnswers is the control every test here runs first: it proves
// the answer the test then requires can only have come from run-time memory. A
// program with a zero-width cycle gets no ordinary body in any build, so for
// one the proof is the cycle itself. Any other program is built with
// compile.BTWorkBudgetOff — the fast body alone, no fallback — and a match or
// find body must answer -2, having run past its static stack. A capture body
// has none: its stack is the run-time one, so alone it must ANSWER.
func (c btScratchCase) requireFallbackAnswers(t *testing.T) {
	t.Helper()
	pat := c.entry.Pattern
	if c.entry.GroupsFunc == "" {
		pat = withoutCaptures(t, pat) // the program match and find compile
	}
	// The options the build below compiles with, the entry's byte_mode
	// included, as compilePattern adopts it.
	cycOpts := c.opts
	cycOpts.ByteMode = cycOpts.ByteMode || c.entry.ByteMode
	if cyc, err := compile.BacktrackHasZeroWidthCycle(pat, cycOpts); err != nil {
		t.Fatalf("control: %v", err)
	} else if cyc {
		return
	}
	opts := c.opts
	opts.BTWorkBudget = compile.BTWorkBudgetOff
	w, _, err := compile.Compile([]config.RegexEntry{c.entry}, btScratchTableBase, true, opts)
	if err != nil {
		t.Fatalf("control compile: %v", err)
	}
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("control module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, nil)
	if err != nil {
		t.Fatalf("control instantiate: %v", err)
	}
	got, slots := c.call(t, store, inst, inst.GetExport(store, "memory").Memory(), c.numSlots())
	if c.entry.GroupsFunc != "" {
		c.check(t, got, slots)
		return
	}
	if got != abi.BTStackOverflow {
		t.Fatalf("control: the fast body alone answered %d, want %d — the case no longer reaches past its static regions", got, abi.BTStackOverflow)
	}
}

// withoutCaptures is pattern with every capture group made non-capturing —
// the program a match or find export compiles.
func withoutCaptures(t *testing.T, pattern string) string {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", pattern, err)
	}
	var strip func(*syntax.Regexp) *syntax.Regexp
	strip = func(r *syntax.Regexp) *syntax.Regexp {
		for i, sub := range r.Sub {
			r.Sub[i] = strip(sub)
		}
		if r.Op == syntax.OpCapture {
			return r.Sub[0]
		}
		return r
	}
	return strip(re).String()
}

func (c btScratchCase) numSlots() int {
	if c.entry.GroupsFunc == "" {
		return 0
	}
	return 2 * (regexp.MustCompile(c.entry.Pattern).NumSubexp() + 1)
}

// tableBase is where c's tables start: past the input window and a page of
// slots.
const btScratchTableBase = int64(btScratchInCap + 65536)

func TestBTFallbackScratchStandalone(t *testing.T) {
	for _, c := range btScratchCases() {
		t.Run(c.name+"/control", c.requireFallbackAnswers)
		for _, setGlobal := range []bool{true, false} {
			name := c.name + "/global-0"
			if setGlobal {
				name = c.name + "/global-set"
			}
			t.Run(name, func(t *testing.T) {
				w, _, err := compile.Compile([]config.RegexEntry{c.entry}, btScratchTableBase, true, c.opts)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				engine, _ := sharedEngine()
				mod, err := wasmtime.NewModule(engine, w)
				if err != nil {
					t.Fatalf("module: %v", err)
				}
				defer mod.Close()
				store := wasmtime.NewStore(engine)
				defer store.Close()
				store.SetEpochDeadline(1)
				inst, err := wasmtime.NewInstance(store, mod, nil)
				if err != nil {
					t.Fatalf("instantiate: %v", err)
				}
				mem := inst.GetExport(store, "memory").Memory()
				g := inst.GetExport(store, abi.ScratchBaseExport)
				if g == nil || g.Global() == nil {
					t.Fatalf("module exports no %q global", abi.ScratchBaseExport)
				}
				if setGlobal {
					// Everything this host uses lies below the tables.
					if err := g.Global().Set(store, wasmtime.ValI32(int32(btScratchTableBase))); err != nil {
						t.Fatal(err)
					}
				}

				var sizes []uint64
				for i := 0; i < 4; i++ {
					got, slots := c.call(t, store, inst, mem, c.numSlots())
					c.check(t, got, slots)
					sizes = append(sizes, mem.Size(store))
				}
				// No search block is handed over, so the module keeps its own
				// default state: a `find` search that trips gets the kept memo
				// once, on the call after it trips (a `groups` search keeps no
				// memo). From then on nothing may grow.
				first := sizes[0]
				if c.entry.FindFunc != "" {
					first = sizes[1]
				}
				if setGlobal && (sizes[1] != first || sizes[2] != first || sizes[3] != first) {
					t.Errorf("memory kept growing with the host global set: %v pages after each call — the scratch is not being reused", sizes)
				}
			})
		}
	}
}

// TestBTFallbackScratchHostWritesAboveTables is the JS/TS stubs' layout: the
// input lives ABOVE the tables, in memory the module cannot see is in use. With
// the global set past it the fallback must leave it intact; with the global at
// 0 it must take fresh pages instead.
func TestBTFallbackScratchHostWritesAboveTables(t *testing.T) {
	entry := config.RegexEntry{Pattern: `^(\w*|)*c`, GroupsFunc: "groups"}
	input := strings.Repeat("w", 100000) + "c"
	loc := regexp.MustCompile(entry.Pattern).FindStringSubmatchIndex(input)
	btScratchCase{entry: entry, input: input}.requireFallbackAnswers(t)

	w, _, err := compile.Compile([]config.RegexEntry{entry}, 0, true, compile.CompileOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, setGlobal := range []bool{true, false} {
		engine, _ := sharedEngine()
		mod, err := wasmtime.NewModule(engine, w)
		if err != nil {
			t.Fatalf("module: %v", err)
		}
		store := wasmtime.NewStore(engine)
		store.SetEpochDeadline(1)
		inst, err := wasmtime.NewInstance(store, mod, nil)
		if err != nil {
			t.Fatalf("instantiate: %v", err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		staticTop := int32(mem.Size(store) * 65536)
		// input, then slots, then a canary the host keeps: all above the tables.
		inBase := staticTop
		outBase := int32(utils.PageAlign(int64(inBase) + int64(len(input))))
		canary := outBase + 4096
		top := canary + 65536
		if _, err := mem.Grow(store, uint64((int64(top)+65535)/65536)-mem.Size(store)); err != nil {
			t.Fatal(err)
		}
		buf := mem.UnsafeData(store)
		copy(buf[inBase:], input)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(buf[int(outBase)+i*4:], 0xFFFFFFFF)
		}
		for i := int32(0); i < 65536; i++ {
			buf[canary+i] = 0xA5
		}
		if setGlobal {
			if err := inst.GetExport(store, abi.ScratchBaseExport).Global().Set(store, wasmtime.ValI32(top)); err != nil {
				t.Fatal(err)
			}
		}
		_, wd := sharedEngine()
		wd.Arm(store)
		res, err := inst.GetFunc(store, "groups").Call(store, inBase, int32(len(input)), outBase, int32(0))
		wd.Disarm()
		if err != nil {
			t.Fatalf("setGlobal=%v: call: %v", setGlobal, err)
		}
		if got := res.(int32); got != int32(loc[1]) {
			t.Fatalf("setGlobal=%v: answered %d, want %d", setGlobal, got, loc[1])
		}
		buf = mem.UnsafeData(store)
		if string(buf[inBase:int(inBase)+len(input)]) != input {
			t.Fatalf("setGlobal=%v: the host's input was overwritten", setGlobal)
		}
		for i := int32(0); i < 65536; i++ {
			if buf[canary+i] != 0xA5 {
				t.Fatalf("setGlobal=%v: the host's data at %d was overwritten", setGlobal, canary+i)
			}
		}
		store.Close()
		mod.Close()
	}
}

// TestBTSetSplitMemberFollowsTheHostGlobal: inside a set, a Backtracking
// body's scratch starts where the host call's earlier regions end, and the
// module learns that a new host call began from an epoch bumped on entry. The
// merge wrapper a split set exports as `find` did not bump it: only the kept
// body did, and the merge calls the kept body only when its cached lower bound
// is the smallest. Once the kept members have no match left, a call runs the
// split member alone, finds the epoch unchanged, and puts its frame stack where
// the PREVIOUS call's scratch began — over whatever the host has written there
// since and declared by raising regexped:scratch_base past it.
//
// The host first drives the set once, so the module has grown its own default
// search area (which raises the scratch floor past it). Then, before every call
// of a second drive, it writes a canary over the region the module's scratch
// began at in the previous call and raises the global past it; each call must
// leave every such region intact.
func TestBTSetSplitMemberFollowsTheHostGlobal(t *testing.T) {
	// p0 runs on a Backtracking bucket and is kept (its walks are bounded);
	// p1 is not provably linear, so it is split out onto the Backtracking find.
	pats := []string{`(?:a|bc){1,30}?x`, `[a-z]+aX`}
	const input = "baX caX daX eaX faX"
	want := regexp.MustCompile(pats[1]).FindAllStringIndex(input, -1)
	// A batching set's `find` is a wrapper over the merged worker; it starts
	// the host call itself.
	for _, shape := range []struct{ overlapping, batch bool }{{false, false}, {true, false}, {false, true}} {
		overlapping := shape.overlapping
		var hints []string
		if shape.batch {
			hints = []string{"batch-find"}
		}
		cfg := config.BuildConfig{
			MaxFallbackStates: 1, // every member's suffix DFA is over it: Backtracking
			Regexps:           []config.RegexEntry{{Name: "p0", Pattern: pats[0]}, {Name: "p1", Pattern: pats[1]}},
			Sets: []config.SetConfig{{Name: "s", Find: "s_find", Overlapping: overlapping, Hints: hints,
				Patterns: config.PatternSelector{Names: []string{"p0", "p1"}}}},
		}
		w, _, diags, err := compile.CompileFileDiag(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		bt := 0
		for _, b := range diags[0].Buckets {
			if b.Type == "bt-fallback" {
				bt++
			}
		}
		if bt == 0 || len(diags[0].SplitBacktracking) != 1 || diags[0].SplitBacktracking[0] != 1 {
			t.Fatalf("%+v: %d Backtracking buckets, split onto Backtracking %v — the witness no longer has the shape",
				shape, bt, diags[0].SplitBacktracking)
		}
		engine, _ := sharedEngine()
		mod, err := wasmtime.NewModule(engine, w)
		if err != nil {
			t.Fatal(err)
		}
		store := wasmtime.NewStore(engine)
		store.SetEpochDeadline(1)
		inst, err := wasmtime.NewInstance(store, mod, nil)
		if err != nil {
			t.Fatal(err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		global := inst.GetExport(store, abi.ScratchBaseExport).Global()
		setGlobal := func(v int32) {
			if err := global.Set(store, wasmtime.ValI32(v)); err != nil {
				t.Fatal(err)
			}
		}
		growTo := func(top int32) {
			if need := uint64((int64(top) + 65535) / 65536); need > mem.Size(store) {
				if _, err := mem.Grow(store, need-mem.Size(store)); err != nil {
					t.Fatal(err)
				}
			}
		}
		// The input, then a page holding the gate array, descriptor and out
		// buffer: above the tables, where the JS/TS stubs write.
		inBase := int32(mem.Size(store) * 65536)
		gatePtr := inBase + 65536
		descPtr := gatePtr + 1024
		outPtr := gatePtr + 4096
		growTo(gatePtr + 65536)
		copy(mem.UnsafeData(store)[inBase:], input)
		fn := inst.GetFunc(store, "s_find")
		// drive runs one drive; before call k it calls before(k).
		drive := func(before func(call int)) [][]int {
			buf := mem.UnsafeData(store)
			for i := gatePtr; i < descPtr; i++ {
				buf[i] = 0
			}
			abi.WriteFindScratch(buf, descPtr, gatePtr, 0, 0)
			var got [][]int
			from := int32(0)
			for call := 0; call <= len(want); call++ {
				before(call)
				res, err := fn.Call(store, inBase, int32(len(input)), from, descPtr, outPtr, int32(2))
				if err != nil {
					t.Fatalf("%+v: find(from=%d): %v", shape, from, err)
				}
				if res.(int32) <= 0 {
					break
				}
				buf = mem.UnsafeData(store)
				start := le32(buf[outPtr+4:])
				got = append(got, []int{int(start), int(le32(buf[outPtr+8:]))})
				from = start + 1
			}
			return got
		}
		setGlobal(gatePtr + 65536)
		drive(func(int) {})
		const regionLen = 256 * 1024
		base0 := int32(mem.Size(store) * 65536)
		region := func(k int) int32 { return base0 + int32(k)*regionLen }
		check := func(upTo int) {
			buf := mem.UnsafeData(store)
			for k := 0; k < upTo; k++ {
				for i := region(k); i < region(k+1); i++ {
					if buf[i] != 0xA5 {
						t.Fatalf("%+v: a call wrote the host's region %d at %#x, below scratch_base %#x",
							shape, k, i, region(upTo))
					}
				}
			}
		}
		got := drive(func(call int) {
			check(call - 1) // what the calls so far had canaried
			if call > 0 {
				// The host has written the region the previous call's scratch
				// began at, and declares it in use.
				growTo(region(call))
				buf := mem.UnsafeData(store)
				for i := region(call - 1); i < region(call); i++ {
					buf[i] = 0xA5
				}
			}
			setGlobal(region(call))
		})
		check(len(got))
		if len(got) != len(want) {
			t.Fatalf("%+v: matches %v, Go says %v", shape, got, want)
		}
		for i := range want {
			if got[i][0] != want[i][0] || got[i][1] != want[i][1] {
				t.Fatalf("%+v: matches %v, Go says %v", shape, got, want)
			}
		}
		store.Close()
		mod.Close()
	}
}

// TestBTFallbackScratchEmbedded runs the embedded module shape: input in the
// host's memory, the fallback's scratch in the module's own.
func TestBTFallbackScratchEmbedded(t *testing.T) {
	for _, c := range btScratchCases() {
		t.Run(c.name, func(t *testing.T) {
			c.requireFallbackAnswers(t)
			w, _, err := compile.Compile([]config.RegexEntry{c.entry}, 0, false, c.opts)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			engine, _ := sharedEngine()
			mod, err := wasmtime.NewModule(engine, w)
			if err != nil {
				t.Fatalf("module: %v", err)
			}
			defer mod.Close()
			store := wasmtime.NewStore(engine)
			defer store.Close()
			store.SetEpochDeadline(1)
			mt, err := wasmtime.NewMemoryType(uint32(btScratchTableBase/65536), false, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			host, err := wasmtime.NewMemory(store, mt)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{host})
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			if inst.GetExport(store, abi.ScratchBaseExport) != nil {
				t.Errorf("an embedded module exports %q; its memory is its own", abi.ScratchBaseExport)
			}
			for i := 0; i < 2; i++ {
				got, slots := c.call(t, store, inst, host, c.numSlots())
				c.check(t, got, slots)
			}
		})
	}
}

// TestBTFallbackScratchComponent runs a component core module, where the
// fallback's scratch is the space above cabi_realloc's heap top. Both inputs
// are lowered into the heap and adopted by their scanners before either runs,
// so a scratch placed anywhere below the heap top would overwrite one of them.
// `^(aa|a)*b` has no zero-width cycle, so it runs the ordinary capture body,
// whose frame stack is placed there too.
func TestBTFallbackScratchComponent(t *testing.T) {
	for _, c := range []struct {
		pattern  string
		inA, inB string
	}{
		{`^(\w*|)*c`, strings.Repeat("w", 100000) + "c", strings.Repeat("w", 90000) + "c"},
		{`^(aa|a)*b`, strings.Repeat("a", 80000) + "b", strings.Repeat("a", 70001) + "b"},
	} {
		t.Run(c.pattern, func(t *testing.T) {
			pattern := c.pattern
			h, res := newPatternResourceHarness(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
			n := res["g"]
			if h.inst.GetExport(h.store, abi.ScratchBaseExport) != nil {
				t.Errorf("a component core exports %q; its allocator owns the heap", abi.ScratchBaseExport)
			}

			inA, inB := c.inA, c.inB
			for _, in := range []string{inA, inB} {
				btScratchCase{entry: config.RegexEntry{Pattern: pattern, GroupsFunc: "g"}, input: in}.requireFallbackAnswers(t)
			}
			pa, la := h.writeInput(inA)
			a := h.call(n.Constructor, pa, la, int32(0))
			pb, lb := h.writeInput(inB)
			b := h.call(n.Constructor, pb, lb, int32(0))

			// group 0 of groups' next: result<list<option<tuple<u32,u32>>>, error-code>.
			group0 := func(handle int32, input string) {
				t.Helper()
				ret := h.call(n.Next, handle)
				data := h.mem.UnsafeData(h.store)
				if data[ret] == 1 {
					t.Fatalf("next reported an error (backtrack-overflow): the search did not get its memory")
				}
				ptr := int32(h.u32(ret + 4))
				loc := regexp.MustCompile(pattern).FindStringSubmatchIndex(input)
				got := [3]uint32{uint32(h.mem.UnsafeData(h.store)[ptr]), h.u32(ptr + 4), h.u32(ptr + 8)}
				if want := [3]uint32{1, uint32(loc[0]), uint32(loc[1])}; got != want {
					t.Fatalf("group 0 = %v, want %v", got, want)
				}
			}
			group0(b, inB)
			group0(a, inA)
			h.call(n.Dtor, a)
			h.call(n.Dtor, b)
		})
	}
}
