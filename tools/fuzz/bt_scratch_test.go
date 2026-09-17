package fuzz

import (
	"encoding/binary"
	"regexp"
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
// Each test first builds the same case with compile.BTWorkBudgetOff and
// requires -2 (requireFastBodyGivesUp). Without that control a later raise of
// the fast body's static stack or memo would let every test here pass without
// executing a byte of bt_scratch.go.

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
		// A fast body with its OWN static memo, past that memo's ceiling: the
		// length guard hands the call over instead of answering -2.
		{"find/static-memo-ceiling", config.RegexEntry{Pattern: `(?:a?)+?xyz`, FindFunc: "find"}, squeezed, a(200000) + "xyz"},
		{"groups/static-memo-ceiling", config.RegexEntry{Pattern: `((?:a?)+?)xyz`, GroupsFunc: "groups"}, compile.CompileOptions{}, a(200000) + "xyz"},
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

// requireFastBodyGivesUp is the control every test here runs first: the same
// case built with compile.BTWorkBudgetOff — the fast body alone, no fallback —
// must answer -2, so the answer the test then requires can only have come from
// the fallback's run-time memory.
func (c btScratchCase) requireFastBodyGivesUp(t *testing.T) {
	t.Helper()
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
	if got, _ := c.call(t, store, inst, inst.GetExport(store, "memory").Memory(), c.numSlots()); got != abi.BTStackOverflow {
		t.Fatalf("control: the fast body alone answered %d, want %d — the case no longer reaches past its static regions", got, abi.BTStackOverflow)
	}
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
		t.Run(c.name+"/control", c.requireFastBodyGivesUp)
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
				for i := 0; i < 3; i++ {
					got, slots := c.call(t, store, inst, mem, c.numSlots())
					c.check(t, got, slots)
					sizes = append(sizes, mem.Size(store))
				}
				if setGlobal && (sizes[1] != sizes[0] || sizes[2] != sizes[0]) {
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
	btScratchCase{entry: entry, input: input}.requireFastBodyGivesUp(t)

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

// TestBTFallbackScratchEmbedded runs the embedded module shape: input in the
// host's memory, the fallback's scratch in the module's own.
func TestBTFallbackScratchEmbedded(t *testing.T) {
	for _, c := range btScratchCases() {
		t.Run(c.name, func(t *testing.T) {
			c.requireFastBodyGivesUp(t)
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
func TestBTFallbackScratchComponent(t *testing.T) {
	const pattern = `^(\w*|)*c`
	h, res := newPatternResourceHarness(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
	n := res["g"]
	if h.inst.GetExport(h.store, abi.ScratchBaseExport) != nil {
		t.Errorf("a component core exports %q; its allocator owns the heap", abi.ScratchBaseExport)
	}

	inA := strings.Repeat("w", 100000) + "c"
	inB := strings.Repeat("w", 90000) + "c"
	for _, in := range []string{inA, inB} {
		btScratchCase{entry: config.RegexEntry{Pattern: pattern, GroupsFunc: "g"}, input: in}.requireFastBodyGivesUp(t)
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
			t.Fatalf("next reported an error (backtrack-overflow): the fallback did not answer")
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
}
