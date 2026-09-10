package fuzz

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/generate"
	"github.com/qrdl/regexped/internal/abi"
)

// The canonical-ABI adapters are ordinary core functions — `(ptr,len[,start])
// → retptr` — so they can be driven directly, without a Component Model
// runtime. That matters for two things the `wasmtime run --invoke` path cannot
// reach:
//
//   - the -2 (BTStackOverflow) arm, which needs a squeezed compile and a 60 KB
//     input, impossible to express as a WAVE list on a command line;
//   - the post-return reset, since --invoke gives every call a fresh instance
//     and so can never show a leak.
//
// Result-area layouts are §3.3 of the component plan and are asserted here by
// reading the bytes back.

// componentWasm compiles entries as a component core module and returns the
// bytes plus the canonical export name for each configured func name.
func componentWasm(t *testing.T, entries []config.RegexEntry, opts compile.CompileOptions) ([]byte, map[string]string) {
	t.Helper()
	cfg := config.BuildConfig{WasmFormat: "component", ImportModule: "regexps", Regexps: entries}
	names, err := generate.ComponentExportNames(cfg)
	if err != nil {
		t.Fatalf("export names: %v", err)
	}
	prefix, err := generate.WitInterfacePrefix(cfg)
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	opts.Component = true
	opts.ComponentPackage = prefix
	opts.ComponentExportNames = names
	w, _, err := compile.Compile(entries, pathsTableBase, true, opts)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return w, names
}

// adapterResult is one decoded result area.
type adapterResult struct {
	err      bool // result discriminant: true = err(backtrack-overflow)
	some     bool // option discriminant
	a, b     uint32
	listPtr  uint32
	listLen  uint32
	retptr   uint32
	memPages uint32
}

func TestComponentAdaptersOverTheRealABI(t *testing.T) {
	entries := []config.RegexEntry{
		{Pattern: `[a-z]+`, MatchFunc: "m"},
		{Pattern: `ghp_[A-Za-z0-9]{4}`, FindFunc: "f"},
		{Pattern: `(?P<opt>x)?y`, GroupsFunc: "g"},
	}
	w, names := componentWasm(t, entries, compile.CompileOptions{})

	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	call := func(export, input string, extra ...int32) adapterResult {
		fn := inst.GetFunc(store, export)
		if fn == nil {
			t.Fatalf("no %q export", export)
		}
		buf := mem.UnsafeData(store)
		copy(buf[pathsInputBase:], input)
		args := []any{any(int32(pathsInputBase)), any(int32(len(input)))}
		for _, e := range extra {
			args = append(args, any(e))
		}
		res, err := fn.Call(store, args...)
		if err != nil {
			t.Fatalf("%s(%q): %v", export, input, err)
		}
		ret := uint32(res.(int32))
		buf = mem.UnsafeData(store)
		r := adapterResult{
			retptr:   ret,
			err:      buf[ret] == 1,
			some:     buf[ret+4] == 1,
			memPages: uint32(mem.Size(store) / 65536),
		}
		r.a = binary.LittleEndian.Uint32(buf[ret+8:])
		r.b = binary.LittleEndian.Uint32(buf[ret+12:])
		r.listPtr, r.listLen = r.a, r.b
		return r
	}

	t.Run("match", func(t *testing.T) {
		got := call(names["m"], "abc")
		if got.err || !got.some || got.a != 3 {
			t.Errorf("m(abc) = %+v, want ok(some(3))", got)
		}
		if got := call(names["m"], "ABC"); got.err || got.some {
			t.Errorf("m(ABC) = %+v, want ok(none)", got)
		}
	})

	t.Run("find", func(t *testing.T) {
		const in = "xxghp_ab12yy"
		got := call(names["f"], in, 0)
		if got.err || !got.some || got.a != 2 || got.b != 10 {
			t.Errorf("f(%q,0) = %+v, want ok(some((2,10)))", in, got)
		}
		// start beyond any match, at len, and past len: all ok(none), no trap.
		for _, start := range []int32{3, int32(len(in)), int32(len(in)) + 1} {
			if got := call(names["f"], in, start); got.err || got.some {
				t.Errorf("f(%q,%d) = %+v, want ok(none)", in, start, got)
			}
		}
	})

	t.Run("groups with an unset group", func(t *testing.T) {
		buf := func() []byte { return mem.UnsafeData(store) }
		// "xy": both groups participate.
		got := call(names["g"], "xy", 0)
		if got.err || !got.some || got.listLen != 2 {
			t.Fatalf("g(xy) = %+v, want ok(some(list of 2))", got)
		}
		b := buf()
		if b[got.listPtr] != 1 || binary.LittleEndian.Uint32(b[got.listPtr+4:]) != 0 ||
			binary.LittleEndian.Uint32(b[got.listPtr+8:]) != 2 {
			t.Errorf("g(xy) group 0 = %v, want some((0,2))", b[got.listPtr:got.listPtr+12])
		}
		if b[got.listPtr+12] != 1 {
			t.Errorf("g(xy) group 1 must be some")
		}
		// "y": the optional group is UNSET, and must be `none` — the element
		// path a happy-path test never reaches.
		got = call(names["g"], "y", 0)
		if got.err || !got.some || got.listLen != 2 {
			t.Fatalf("g(y) = %+v", got)
		}
		b = buf()
		if b[got.listPtr] != 1 {
			t.Errorf("g(y) group 0 must be some")
		}
		if b[got.listPtr+12] != 0 {
			t.Errorf("g(y) group 1 disc = %d, want 0 (none)", b[got.listPtr+12])
		}
	})

	// The post-return resets the bump pointer to the static top. Without it
	// every call leaks its result area and memory grows without bound; with it,
	// repeated calls land at the SAME retptr and memory never grows.
	t.Run("post-return reset", func(t *testing.T) {
		post := inst.GetFunc(store, "cabi_post_"+names["f"])
		if post == nil {
			t.Fatalf("no post-return export for %q", names["f"])
		}
		// Prime one reset first. The subtests above ran on this same store
		// without ever calling the post-return, so the heap has legitimately
		// advanced; rewinding lands BELOW where they left it, and a baseline
		// taken before the first reset would differ from every later call for
		// that reason alone. The post-return ignores its argument — it resets
		// the bump pointer wholesale — so 0 is a fine retptr here.
		if _, err := post.Call(store, any(int32(0))); err != nil {
			t.Fatalf("priming post: %v", err)
		}
		var baseRetptr, basePages uint32
		for i := 0; i < 1000; i++ {
			got := call(names["f"], "xxghp_ab12yy", 0)
			if !got.some || got.a != 2 || got.b != 10 {
				t.Fatalf("call %d answered %+v, want ok(some((2,10)))", i, got)
			}
			if i == 0 {
				baseRetptr, basePages = got.retptr, got.memPages
			} else {
				if got.retptr != baseRetptr {
					t.Fatalf("call %d landed at %d, the first reset call at %d — the bump pointer is not being reset",
						i, got.retptr, baseRetptr)
				}
				if got.memPages != basePages {
					t.Fatalf("call %d grew memory from %d to %d pages", i, basePages, got.memPages)
				}
			}
			if _, err := post.Call(store, any(int32(got.retptr))); err != nil {
				t.Fatalf("post %d: %v", i, err)
			}
		}
	})
}

// The -2 sentinel means the answer is UNKNOWN, and must lift to
// err(backtrack-overflow) rather than to a definite ok(none). Reaching it needs
// the same squeeze tools/fuzz uses elsewhere: Backtracking forced by a tiny
// MaxDFAStates, a small memo budget, and an input long enough to exhaust the
// frame budget.
func TestComponentAdapterLiftsBacktrackOverflow(t *testing.T) {
	const pattern = `Z(?:a?)+?xyz`
	const length = 60000
	entries := []config.RegexEntry{{Pattern: pattern, FindFunc: "f"}}
	w, names := componentWasm(t, entries, compile.CompileOptions{MaxDFAStates: 1, MemoBudget: 4096})

	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, names["f"])
	if fn == nil {
		t.Fatalf("no %q export", names["f"])
	}
	raw := inst.GetFunc(store, "f")
	if raw == nil {
		t.Fatalf("the raw export is kept under component, and this test needs it")
	}

	busy := strings.Repeat("Z", length) // every position is a candidate
	buf := mem.UnsafeData(store)
	if length > int(pathsOutBase-pathsInputBase) {
		t.Fatalf("input runs into the output window")
	}
	copy(buf[pathsInputBase:], busy)

	// First establish that the underlying body really does answer -2 here; a
	// test that silently stopped overflowing would otherwise pass while
	// checking nothing.
	_, wd := sharedEngine()
	wd.Arm(store)
	rawRes, err := raw.Call(store, any(int32(pathsInputBase)), any(int32(length)), any(int32(0)))
	wd.Disarm()
	if err != nil {
		t.Fatalf("raw find: %v", err)
	}
	if got := rawRes.(int64); got != abi.BTStackOverflow {
		t.Skipf("this shape no longer overflows (raw find returned %d); the -2 arm needs a new one", got)
	}

	wd.Arm(store)
	res, err := fn.Call(store, any(int32(pathsInputBase)), any(int32(length)), any(int32(0)))
	wd.Disarm()
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	ret := uint32(res.(int32))
	buf = mem.UnsafeData(store)
	if buf[ret] != 1 {
		t.Errorf("result discriminant = %d, want 1 (err) — an UNKNOWN answer must not lift to ok(none)", buf[ret])
	}
	if buf[ret+4] != 0 {
		t.Errorf("error enum index = %d, want 0 (backtrack-overflow)", buf[ret+4])
	}
}
