package fuzz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// writeFindScratch lays a scratch descriptor into guest memory and returns its
// address — the argument `find` and `find_batch` take in place of a bare gate
// pointer (internal/abi).
//
// Every test in this package that drives a set's find used to pass the gate
// array directly. They pass this instead, and the magic word is what turned
// each missed call site into an immediate trap rather than a wrong answer: the
// parameter has the same type it always had.
//
// The descriptor is placed immediately above the gate array. Callers here own
// their memory layouts and all of them leave room above it.
func writeFindScratch(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen int32) int32 {
	return writeFindScratchStride(store, mem, gatePtr, idSpaceWords, cachePtr, cacheLen, 0)
}

// writeFindScratchStride is writeFindScratch plus the CHECKPOINTED cache's one
// caller-written header field.
//
// The stride is chosen by whoever allocates the region — a generated `init` in
// a real consumer, these helpers in a test — because the allocation and the
// stride come from the same formula and must agree. A zero stride is a
// malformed header and the sweep reports it rather than guessing, so a test
// that offers a cache must seed this or it is testing the refusal path.
func writeFindScratchStride(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen, stride int32) int32 {
	scratch := gatePtr + idSpaceWords*4
	buf := mem.UnsafeData(store)
	abi.WriteFindScratch(buf, scratch, gatePtr, cachePtr, cacheLen)
	if cachePtr != 0 {
		for i := int32(0); i < config.SetOverlapCheckpointHeaderBytes; i++ {
			buf[cachePtr+i] = 0
		}
		binary.LittleEndian.PutUint32(buf[cachePtr+config.SetOverlapHdrStrideOff:], uint32(stride))
	}
	return scratch
}

// overlapCacheFor sizes and strides a checkpointed cache for one set, the way
// a generated `init` would: it recompiles the set to learn the sweep column,
// then asks config for both numbers so the test and the sweep cannot disagree.
func overlapCacheFor(input string, pats []string) (length, stride int32) {
	sh, err := cachedOverlapShape(pats)
	if err != nil {
		return int32(config.SetOverlapCheckpointHeaderBytes), 1
	}
	// One helper for both numbers: the region is sized FROM the stride, and a
	// harness that computed them separately would hand the sweep a header it
	// reports as malformed.
	bytes, k := sh.Sizing(len(input))
	return int32(bytes), int32(k)
}

// cachedOverlapShape is compile.SetOverlapCacheShape for overlapSizingCfg's set,
// learned once per pattern list: it recompiles the set, and a test driving one
// set many times sized every drive by recompiling it again.
func cachedOverlapShape(pats []string) (compile.OverlapCacheShape, error) {
	cfg := overlapSizingCfg(pats)
	return cachedShape("sizing\x00"+setKey(pats), cfg.Sets[0], cfg)
}

// overlapCacheForK sizes a region for a CHOSEN stride rather than the formula's.
//
// The block-boundary tests force tiny strides, and a region sized at the
// formula's stride does not hold one: at k = 1 the checkpoint array is a column
// per position, which for a 4 KB input is three times the single-block region.
// Sizing it the other way made the sweep refuse, the drive walk, and the test
// compare the walk with itself at every stride below 5.
//
// A split member's program sweep keeps its part in the same region, so the
// region holds the cache's bytes for THIS stride, 8-aligned, and then the
// sweep's, as a caller that writes its own stride sizes it.
func overlapCacheForK(input string, pats []string, k int32) int32 {
	sh, err := cachedOverlapShape(pats)
	if err != nil {
		return int32(config.SetOverlapCheckpointHeaderBytes)
	}
	n := config.SetOverlapCheckpointHeaderBytes
	if sh.Eligible {
		n = config.SetOverlapCheckpointBytesForStride(len(input), sh.Cells, sh.Patterns, int(k))
	}
	if sh.SweepCells > 0 {
		if sb, _ := config.SetOverlapCheckpointSizingRow(len(input), sh.SweepCells, sh.SweepRow); sb <= config.SetOverlapCacheMaxBytes {
			n = (n+7)&^7 + sb
		}
	}
	return int32(n)
}

// overlapSizingCfg is the set overlapCacheFor and overlapCacheForK size a region
// for: an overlapping find over pats, by the pattern names the drives use.
func overlapSizingCfg(pats []string) config.BuildConfig {
	entries := make([]config.PatternEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.PatternEntry{Name: names[i], Regexp: p}
	}
	return config.BuildConfig{
		Patterns: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "find", Overlapping: true,
			Patterns: config.PatternSelector{Names: names},
			Unicode:  setModeKey(),
		}},
	}
}

// cacheLayout is how a cache drive lays out its instance: the entry it drives,
// the region it offers, and what a test steers the header with.
type cacheLayout struct {
	batch       bool  // drive set_find_batch (the set carries the hint) rather than set_find
	scratchLen  int32 // bytes allocated for the answer cache
	offer       bool  // hand that region to the export; false passes no cache at all
	stride      int32 // the stride written into the header
	preArmWork  bool  // saturate `work`, so the first call sweeps whatever it costs
	canaryBelow int32 // bytes of 0xA5 immediately below the region, on a page of their own
	canaryAbove int32 // bytes of 0xA5 immediately above it
	sweepBudget int64 // > 0: the program sweep checkpoints past this many bytes
}

// cacheDrive is one overlapping set compiled, instantiated and laid out for a
// drive: the input, the gate array, the tuple buffer and the region each on
// pages of their own, the descriptor built and the header seeded. Every cache
// drive in this package starts from one; each used to carry its own copy of
// this setup, and the copies had begun to differ in how many pages the input
// got.
type cacheDrive struct {
	store                                     *wasmtime.Store
	mem                                       *wasmtime.Memory
	fn                                        *wasmtime.Func
	release                                   func()
	inBase, gatePtr, outPtr, scratchPtr, desc int32
}

func (d *cacheDrive) buf() []byte { return d.mem.UnsafeData(d.store) }

// compileCacheDriveSet is the overlapping set a cache drive runs, compiled
// once per pattern list, batch flag and sweep budget.
func compileCacheDriveSet(pats []string, batch bool, sweepBudget int64) ([]byte, error) {
	entries := make([]config.PatternEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.PatternEntry{Name: fmt.Sprintf("p%d", i), Regexp: p}
	}
	set := config.SetConfig{
		Name: "s", Find: "set_find",
		Patterns: config.PatternSelector{All: true}, Overlapping: true,
		Unicode: setModeKey(),
	}
	if batch {
		set.Hints = []string{"batch-find"}
	}
	return cachedCompile(fmt.Sprintf("cachedrive\x00%v\x00%d\x00%s", batch, sweepBudget, setKey(pats)), compileJob{
		Kind: jobFile, Config: config.BuildConfig{Patterns: entries, Sets: []config.SetConfig{set}}, SweepBudget: sweepBudget})
}

func newCacheDrive(t *testing.T, pats []string, input string, lay cacheLayout) *cacheDrive {
	t.Helper()
	export := "set_find"
	if lay.batch {
		export = "set_find_batch"
	}
	w, err := compileCacheDriveSet(pats, lay.batch, lay.sweepBudget)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fail := func(format string, args ...any) {
		release()
		t.Fatalf(format, args...)
	}
	if !lay.batch && inst.GetFunc(store, "set_find_batch") != nil {
		fail("the set declared no batch hint but a batch entry was exported")
	}
	fn := inst.GetFunc(store, export)
	if fn == nil {
		fail("module missing %s export", export)
	}
	const pageSize = 65536
	d := &cacheDrive{store: store, mem: mem, fn: fn, release: release}
	if d.inBase, d.gatePtr, d.outPtr, d.scratchPtr, err = cacheDriveAddrs(w, len(input), lay.canaryBelow > 0); err != nil {
		fail("parse data section: %v", err)
	}
	needed := uint64((int64(d.scratchPtr) + int64(lay.scratchLen) + int64(lay.canaryAbove) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			fail("grow: %v", err)
		}
	}
	buf := d.buf()
	copy(buf[d.inBase:], input)
	// The caller zeroes BOTH regions to start a drive — that is the whole
	// contract, for the gates and for the cache header alike.
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[d.gatePtr+i] = 0
	}
	for i := int32(0); i < lay.scratchLen; i++ {
		buf[d.scratchPtr+i] = 0
	}
	for i := int32(0); i < lay.canaryBelow; i++ {
		buf[d.scratchPtr-lay.canaryBelow+i] = 0xA5
	}
	for i := int32(0); i < lay.canaryAbove; i++ {
		buf[d.scratchPtr+lay.scratchLen+i] = 0xA5
	}
	cachePtr, cacheLen := int32(0), int32(0)
	if lay.offer {
		cachePtr, cacheLen = d.scratchPtr, lay.scratchLen
	}
	d.desc = writeFindScratchStride(store, mem, d.gatePtr, int32(len(pats)), cachePtr, cacheLen, lay.stride)
	if lay.preArmWork && lay.offer {
		binary.LittleEndian.PutUint32(d.buf()[d.scratchPtr+config.SetOverlapHdrWorkOff:], 0x7FFFFFFF)
	}
	return d
}

// cacheDriveAddrs is the page layout every cache drive uses: the input above the
// module's data on as many pages as it needs — the megabyte-scale shapes that
// reach the layout arithmetic's 32-bit edges do not fit in one — then a page each
// for the gate array and the tuple buffer, then the region. With a canary it
// sits one page further up, so a write below the region lands in the canary
// rather than in the tuple buffer, where it would pass for ordinary tuples.
func cacheDriveAddrs(w []byte, inputLen int, canaryBelow bool) (inBase, gatePtr, outPtr, regionPtr int32, err error) {
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	inBase = int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((inputLen + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr = inBase + span
	outPtr = gatePtr + pageSize
	regionPtr = outPtr + pageSize
	if canaryBelow {
		regionPtr += pageSize
	}
	return inBase, gatePtr, outPtr, regionPtr, nil
}

// TestSetKeyDistinguishesPatternOrderAndSeparators pins the set module cache's
// key against the collision below.
//
// The cache is keyed by the caller, and the four set callers used to build the
// key with fmt.Sprintf("%v", pats). %v joins a []string with a SPACE, so
// {" ", ""} and {"", " "} both render as "[  ]" — one set then silently got
// the other set's compiled module. A pattern's INDEX is its id, so swapping
// two patterns swaps every id the set reports, and the harness checked one
// module's answers against the other's oracle. Five crasher files came out of
// that, all of which passed when replayed alone.
//
// Joining on a separator does not fix it either, whatever the separator: the
// fuzzer mutates arbitrary bytes and Go's regexp compiles a NUL as an ordinary
// literal, so a NUL join makes {"a\x00b"} and {"a", "b"} collide exactly as %v
// did. Only a length prefix is injective.
//
// The pairs below are the ones that actually collided under each rejected
// scheme, so this test fails if anyone reverts to either.
func TestSetKeyDistinguishesPatternOrderAndSeparators(t *testing.T) {
	pairs := [][2][]string{
		{{" ", ""}, {"", " "}},     // the raw crashers: %v renders both "[  ]"
		{{"a\x00b"}, {"a", "b"}},   // a NUL join would collide here
		{{"a b"}, {"a", "b"}},      // a space join would collide here
		{{""}, {"", ""}},           // arity must matter
		{{"ab", "c"}, {"a", "bc"}}, // the split point must matter
		{{"1:x"}, {"", "x"}},       // the length prefix must not be forgeable
	}
	for _, p := range pairs {
		if a, b := setKey(p[0]), setKey(p[1]); a == b {
			t.Errorf("setKey(%q) == setKey(%q) == %q: two different sets share one cache entry", p[0], p[1], a)
		}
	}
}

// TestSetCacheReturnsThePatternsOwnModule is the end-to-end half: the two
// orderings must not hand back the same bytes, which is what the crashers saw.
func TestSetCacheReturnsThePatternsOwnModule(t *testing.T) {
	first, _, err := compileCaps([]string{" ", ""}, false)
	if err != nil {
		t.Fatalf("compile {\" \", \"\"}: %v", err)
	}
	second, _, err := compileCaps([]string{"", " "}, false)
	if err != nil {
		t.Fatalf("compile {\"\", \" \"}: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal(`compileCaps([" ", ""]) and compileCaps(["", " "]) returned the same module: ` +
			`the cache key does not separate them, so one set is answering with the other's pattern ids`)
	}
}

// TestCompileChildMatchesInProcess runs every kind of compile job both ways —
// in this process (compileJob.run) and through the compile child — and
// requires the same result: the module's bytes, the search blocks, the drops,
// the engine, the shape, and an error with the same message that matches the
// same compile sentinels. A field the job did not carry across the pipe would
// make the child compile a different module, which every budgeted fuzz input
// would then test instead of the one it asked for.
func TestCompileChildMatchesInProcess(t *testing.T) {
	byteOpts := toJobOpts(compile.CompileOptions{ForceByteMode: true})
	uniOpts := toJobOpts(compile.CompileOptions{Unicode: true})
	f, tr := false, true
	set := func(uni *bool, overlapping bool, hints ...string) config.BuildConfig {
		return config.BuildConfig{
			Patterns: []config.PatternEntry{{Name: "p0", Regexp: `foo\w+`}, {Name: "p1", Regexp: `a[a-z]*?z`}},
			Sets: []config.SetConfig{{Name: "s", Find: "set_find", Overlapping: overlapping, Hints: hints,
				Patterns: config.PatternSelector{All: true}, Unicode: uni}},
		}
	}
	shapeCfg := set(&f, true)
	for _, c := range []struct {
		name string
		j    compileJob
		is   error // the sentinel the compile fails with, nil when it succeeds
	}{
		{"sized/find with notes", compileJob{Kind: jobSized, Entries: []config.PatternEntry{{Regexp: `a*b|a`, FindFunc: "find"}},
			Base: tableBase, Opts: byteOpts, Export: "find"}, nil},
		{"sized/unicode", compileJob{Kind: jobSized, Entries: []config.PatternEntry{{Regexp: `\pL+x`, FindFunc: "find"}},
			Base: pathsTableBase, Opts: uniOpts, Export: "find"}, nil},
		{"compile/match", compileJob{Kind: jobCompile, Entries: []config.PatternEntry{{Regexp: `ab+c`, MatchFunc: "match"}},
			Base: pathsTableBase, Opts: byteOpts}, nil},
		{"compile/no options", compileJob{Kind: jobCompile,
			Entries: []config.PatternEntry{{Regexp: `[\x80-\xff]+`, FindFunc: "find", ByteMode: true}}, Base: tableBase, NoOpts: true}, nil},
		{"compile/no capture group", compileJob{Kind: jobCompile, Entries: []config.PatternEntry{{Regexp: `a*`, GroupsFunc: "groups"}},
			Base: pathsTableBase, Opts: byteOpts}, compile.ErrNoCaptureGroup},
		{"forced/tdfa", compileJob{Kind: jobForced, Entries: []config.PatternEntry{{Regexp: `(a)(b+)`, GroupsFunc: "groups"}},
			Base: pathsTableBase, Engine: compile.EngineTDFA, Opts: byteOpts}, nil},
		{"forced/fallback only", compileJob{Kind: jobForced, Entries: []config.PatternEntry{{Regexp: `(a|ab)(c|bcd)(d*)`, GroupsFunc: "groups"}},
			Base: pathsTableBase, Engine: compile.EngineBacktrack,
			Opts: toJobOpts(compile.CompileOptions{ForceByteMode: true, BTWorkBudget: compile.BTWorkBudgetForceFallback})}, nil},
		{"forced/over the instruction limit", compileJob{Kind: jobForced, Entries: []config.PatternEntry{{Regexp: `(a+b+c+d+e+)`, GroupsFunc: "groups"}},
			Base: pathsTableBase, Engine: compile.EngineBacktrack, Opts: toJobOpts(compile.CompileOptions{ForceByteMode: true, MaxDFAStates: -1, MaxBTInstructions: 3})},
			compile.ErrBTProgramTooLarge},
		{"file/byte mode", compileJob{Kind: jobFile, Config: set(&f, false)}, nil},
		{"file/sweep budget", compileJob{Kind: jobFile, Config: set(&tr, true, "batch-find"), SweepBudget: 64}, nil},
		{"file diag", compileJob{Kind: jobFileDiag, Config: set(&f, true)}, nil},
		{"select", compileJob{Kind: jobSelect, Pattern: `(a|ab)(c|bcd)(d*)`, Opts: uniOpts}, nil},
		{"shape", compileJob{Kind: jobShape, Set: shapeCfg.Sets[0], Config: shapeCfg}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			want, wantErr := c.j.run()
			if c.is == nil && wantErr != nil || c.is != nil && !errors.Is(wantErr, c.is) {
				t.Fatalf("in-process: %v, want %v", wantErr, c.is)
			}
			got, gotErr := childRun(c.j, time.Minute)
			if (wantErr == nil) != (gotErr == nil) || wantErr != nil && wantErr.Error() != gotErr.Error() {
				t.Fatalf("error: in-process %v, child %v", wantErr, gotErr)
			}
			for _, s := range compileSentinels {
				if errors.Is(wantErr, s) != errors.Is(gotErr, s) {
					t.Errorf("errors.Is(%v): in-process %v, child %v", s, errors.Is(wantErr, s), errors.Is(gotErr, s))
				}
			}
			if !bytes.Equal(want.Wasm, got.Wasm) {
				t.Errorf("module: in-process %d bytes, child %d bytes, not equal", len(want.Wasm), len(got.Wasm))
			}
			if !reflect.DeepEqual(want.Sizes, got.Sizes) || !reflect.DeepEqual(want.drops(), got.drops()) ||
				want.Engine != got.Engine || want.Shape != got.Shape {
				t.Errorf("in-process %+v %+v %v %+v, child %+v %+v %v %+v",
					want.Sizes, want.drops(), want.Engine, want.Shape, got.Sizes, got.drops(), got.Engine, got.Shape)
			}
		})
	}
}

// TestCompileChildBuildsTheModule: the wasmtime build the child returns
// serialized loads in this process and answers as a module built here does,
// for a compile job (Warm) and for a module alone (jobWarm).
func TestCompileChildBuildsTheModule(t *testing.T) {
	j := compileJob{Kind: jobSized, Entries: []config.PatternEntry{{Regexp: `[a-z]+@[a-z]+\.com`, FindFunc: "find"}},
		Base: tableBase, Opts: toJobOpts(compile.CompileOptions{ForceByteMode: true}), Export: "find", Warm: true}
	r, err := childRun(j, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w, err := childRun(compileJob{Kind: jobWarm, Wasm: r.Wasm, Warm: true}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if w.Wasm != nil {
		t.Error("a warm job sent the module's bytes back")
	}
	engine, _ := sharedEngine()
	for name, ser := range map[string][]byte{"compile": r.Module, "warm": w.Module} {
		if ser == nil {
			t.Fatalf("%s: no module came back", name)
		}
		mod, err := wasmtime.NewModuleDeserialize(engine, ser)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		store := wasmtime.NewStore(engine)
		store.SetEpochDeadline(1)
		inst, err := wasmtime.NewInstance(store, mod, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		input := "mail bob@example.com now"
		copy(inst.GetExport(store, "memory").Memory().UnsafeData(store), input)
		res, err := inst.GetFunc(store, "find").Call(store, int32(0), int32(len(input)), int32(0))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := res.(int64); got != 5<<32|20 {
			t.Errorf("%s: find = [%d,%d), want [5,20)", name, got>>32, got&0xffffffff)
		}
		store.Close()
		mod.Close()
	}
}

// TestCompileChildKilledPastDeadline: a job that does not answer within the
// wait is KILLED — its CPU is not spent — and is errCompileTooSlow, and the
// next job starts a new child.
func TestCompileChildKilledPastDeadline(t *testing.T) {
	if _, err := childRun(compileJob{Kind: jobSelect, Pattern: `ab`, Opts: toJobOpts(compile.CompileOptions{})}, time.Minute); err != nil {
		t.Fatal(err)
	}
	childMu.Lock()
	old := theChild
	childMu.Unlock()
	// Engine selection for this pattern in Unicode mode builds a TDFA it
	// rejects: about 1.4 s.
	slow := compileJob{Kind: jobSelect, Pattern: `[0]+0()00.{31}`, Opts: toJobOpts(compile.CompileOptions{Unicode: true})}
	start := time.Now()
	_, err := childRun(slow, 100*time.Millisecond)
	if !errors.Is(err, errCompileTooSlow) {
		t.Fatalf("err = %v, want errCompileTooSlow", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("returned after %v: the child was waited for, not killed", d)
	}
	if st := old.cmd.ProcessState; st == nil || st.Exited() {
		t.Errorf("the child was not killed: %v", st)
	}
	if r, err := childRun(compileJob{Kind: jobSelect, Pattern: `(a)`, Opts: toJobOpts(compile.CompileOptions{})}, time.Minute); err != nil || r.Engine == 0 {
		t.Fatalf("the job after a kill: %v %v", r.Engine, err)
	}
}

// TestCompileChildDeathIsAFailure: a child that dies by itself — a regexped
// panic in it — is reported with the child's own output, never as a compile
// that was too slow, which would skip the input and hide the panic.
func TestCompileChildDeathIsAFailure(t *testing.T) {
	func() {
		defer func() {
			msg := fmt.Sprint(recover())
			if !strings.Contains(msg, "compile child died") || !strings.Contains(msg, "jobCrash, a compile child that dies by itself") {
				t.Fatalf("recovered %q", msg)
			}
		}()
		childRun(compileJob{Kind: jobCrash}, time.Minute)
	}()
	if _, err := childRun(compileJob{Kind: jobSelect, Pattern: `ab`, Opts: toJobOpts(compile.CompileOptions{})}, time.Minute); err != nil {
		t.Fatalf("the job after a death: %v", err)
	}
}

// TestCompileJobRefusesWhatItCannotCarry: an option jobOpts does not carry, or
// a config field JSON loses, panics instead of compiling something else.
func TestCompileJobRefusesWhatItCannotCarry(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	mustPanic("Report", func() { toJobOpts(compile.CompileOptions{Report: &compile.Reporter{}}) })
	mustPanic("component names", func() { toJobOpts(compile.CompileOptions{ComponentExportNames: map[string]string{"a": "b"}}) })
	mem, err := config.ParseMemorySize("1MB")
	if err != nil {
		t.Fatal(err)
	}
	mustPanic("max_memory", func() { encodeJob(compileJob{Kind: jobFile, Config: config.BuildConfig{MaxMemory: mem}}) })
}

// TestBudgetedCompileKeepsOnlyItsOwnSlowness: a budgeted compile killed after
// the whole of slowCompileDeadline is kept as too slow, so the same compile is
// skipped at once next time; one killed because the INPUT's budget ran out is
// not, since given its own deadline it may finish.
func TestBudgetedCompileKeepsOnlyItsOwnSlowness(t *testing.T) {
	defer func(b, u bool) { budgetForTest, *unicodeMode = b, u }(budgetForTest, *unicodeMode)
	budgetForTest, *unicodeMode = true, true
	// Engine selection alone takes about 6 s here, past slowCompileDeadline.
	pat := `0*(0000{520}000{520}0)`
	key := "budgettest\x00" + pat
	j := compileJob{Kind: jobCompile, Entries: []config.PatternEntry{{Regexp: pat, GroupsFunc: "groups"}},
		Base: pathsTableBase, Opts: toJobOpts(runOpts())}
	cached := func() bool {
		modCacheMu.Lock()
		defer modCacheMu.Unlock()
		_, ok := modCacheIdx[key]
		return ok
	}
	slowCompileMu.Lock()
	inputDeadline = time.Now().Add(200 * time.Millisecond)
	slowCompileMu.Unlock()
	if _, err := cachedCompile(key, j); !errors.Is(err, errCompileTooSlow) {
		t.Fatalf("with 200 ms of the input's budget left: %v, want errCompileTooSlow", err)
	}
	if cached() {
		t.Fatal("a compile cut short by the input's budget was kept as too slow")
	}
	slowCompileMu.Lock()
	inputDeadline = time.Time{}
	slowCompileMu.Unlock()
	if _, err := cachedCompile(key, j); !errors.Is(err, errCompileTooSlow) {
		t.Fatalf("with the whole deadline: %v, want errCompileTooSlow", err)
	}
	if !cached() {
		t.Fatal("a compile killed after the whole deadline was not kept")
	}
	start := time.Now()
	if _, err := cachedCompile(key, j); !errors.Is(err, errCompileTooSlow) || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("again: %v after %v, want errCompileTooSlow at once", err, time.Since(start))
	}
}
