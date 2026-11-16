package fuzz

import (
	"container/list"
	"crypto/sha256"
	"errors"
	"flag"
	"strconv"
	"strings"
	"sync"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/searchblock"
)

// modCacheSize is how many compiled modules one worker process keeps.
//
// Measured on a 60-second FuzzGroups session, four workers, logging every
// pattern that reached a compile in order: 9,067 compiles over 5,057 distinct
// patterns, and 28.7% of them repeated the pattern of the compile immediately
// before. Hit rate by cache size was 1 -> 28.7%, 4 -> 33.5%, 16 -> 35.8%,
// 64 -> 36.3%, 1024 -> 37.3%, unbounded -> 38.1%.
//
// Sixteen is where the curve flattens. The cap is not frugality for its own
// sake: modules are not small — 321 KB and 929 KB for two of the very patterns
// that made this worth doing — so keeping all 5,057 a worker sees in a minute
// would cost hundreds of megabytes to buy the last 2.3 points.
//
// The repeats come from Go's mutator, which changes ONE of the fuzz function's
// values per iteration and resets the pair to its corpus entry every five, so
// roughly half of iterations keep the pattern and the base pattern recurs.
//
// This is a THROUGHPUT measure and nothing more. It cannot stop a slow compile
// being filed as a crasher, because the first sight of any pattern is a miss
// and the miss is what costs.
const modCacheSize = 16

// modCache is a per-process LRU of compiled modules, keyed by the caller's own
// key (a pattern plus whatever else varies its compile).
//
// Callers must treat the returned bytes as READ-ONLY: every hit hands back the
// same slice. Nothing in this package writes to a module after compiling it —
// instantiate copies what it needs — so sharing is safe, and a copy per hit
// would give back most of what the cache saves.
type modCacheEntry struct {
	key   string
	wasm  []byte
	sizes []searchblock.Size // the find export's search blocks, when recorded
	err   error
}

var (
	modCacheMu  sync.Mutex
	modCacheLRU *list.List
	modCacheIdx map[string]*list.Element
)

// cachedCompile returns the module for key, running j on a miss — in this
// process, or in the compile child within the input's budget (budgeted).
//
// Compile ERRORS are cached too. They are deterministic for a given key, and
// the expensive ones are exactly the resource ceilings a slow pattern hits, so
// not caching them would leave the worst case uncached. So is a compile killed
// for being too slow, when it had the whole of slowCompileDeadline.
func cachedCompile(key string, j compileJob) ([]byte, error) {
	wasm, _, err := cachedCompileSized(key, j)
	return wasm, err
}

// errCompileTooSlow is a compile the fuzz harness stopped waiting for: see
// slowCompileDeadline. A resource ceiling of the harness, not of regexped.
var errCompileTooSlow = errors.New("compile ran past the fuzz harness's deadline")

// slowCompileDeadline bounds one budgeted compile (budgeted). Go's fuzz
// worker reports any input that takes over 10s as a crasher, and in Unicode
// mode the instruction-count cap (maxNFAInsts, which is calibrated in byte
// mode) cannot bound compile time: a lowered class makes every TDFA state
// dear, so `[0]+0()00.{31}` — about 40 instructions — builds a 4,004-state
// TDFA it then rejects for its registers in 16.8s alone, more in a worker.
// Only the clock bounds that. A budgeted compile runs in the compile child
// (compilechild.go), which is KILLED when the deadline passes: the input is
// skipped (errCompileTooSlow), and the CPU is not spent. It used to run in a
// goroutine that went on compiling in the background — a 36 s set compile
// cost 36 s however early it was given up, every input meanwhile skipped.
// An unbudgeted compile — byte mode outside FuzzSetRoutes, or any run that
// is not fuzzing — runs in this process and is waited for.
const slowCompileDeadline = 4 * time.Second

// fuzzInputCompileBudget is how long ALL the compiles of one fuzz input may
// take under -unicode, where an input compiles more than once — a set target
// builds its capability module and its gated one, FuzzGroupsBothBodies one
// module per leg (three), FuzzGroupsBothEngines one per engine plus the engine
// selection that decides whether its TDFA leg runs — and two
// compiles each within slowCompileDeadline still overran the worker's 10s in a
// loaded run.
const fuzzInputCompileBudget = 5 * time.Second

var (
	slowCompileMu sync.Mutex
	// inputDeadline is the current fuzz input's compile budget's end, zero
	// outside a target that set one (beginFuzzInput).
	inputDeadline time.Time
	// budgetByteMode puts a target's byte-mode compiles under the budget too:
	// FuzzSetRoutes, whose byte-mode inputs ran to 16 s and were reported as
	// hangs. Set for the duration of such a target only.
	budgetByteMode bool
	// budgetForTest makes budgeted true outside a fuzz run, for the tests of
	// the budget itself.
	budgetForTest bool
)

// beginFuzzInput starts the compile budget of one fuzz input: every budgeted
// compile during it shares fuzzInputCompileBudget. A no-op when the input's
// compiles are not budgeted.
func beginFuzzInput() {
	if !budgeted() {
		return
	}
	slowCompileMu.Lock()
	inputDeadline = time.Now().Add(fuzzInputCompileBudget)
	slowCompileMu.Unlock()
}

// fuzzing reports whether this process is a fuzz run.
func fuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}

// fuzzingUnicode reports whether this process is a fuzz run under -unicode.
func fuzzingUnicode() bool { return *unicodeMode && fuzzing() }

// budgeted reports whether this input's compiles run under the budget, in
// the compile child: a fuzz run's Unicode-mode inputs, and the byte-mode ones
// of a target that set budgetByteMode.
func budgeted() bool {
	return budgetForTest || fuzzing() && (*unicodeMode || budgetByteMode)
}

// runBudgeted runs j in the compile child, within slowCompileDeadline and
// what is left of the input's budget. errCompileTooSlow when the child was
// killed; full reports whether j had the whole slowCompileDeadline, so that
// "too slow" is the job's own and not the input's leftover.
func runBudgeted(j compileJob) (r compileResult, full bool, err error) {
	slowCompileMu.Lock()
	wait := slowCompileDeadline
	if !inputDeadline.IsZero() {
		wait = min(wait, time.Until(inputDeadline))
	}
	slowCompileMu.Unlock()
	if wait <= 0 {
		return r, false, errCompileTooSlow
	}
	r, err = childRun(j, wait)
	return r, wait >= slowCompileDeadline, err
}

// selectEngineWithinBudget is compile.SelectEngine in the run's mode, run
// within the fuzz input's compile budget like a compile (runBudgeted):
// choosing the engine builds the TDFA, which for `0*(0000{520}000{520}0)` took
// 5.1 s on its own, before the budget's builds had begun. false when it ran
// past the budget; an unbudgeted one is waited for.
func selectEngineWithinBudget(pat string) (compile.EngineType, bool) {
	j := compileJob{Kind: jobSelect, Pattern: pat, Opts: toJobOpts(withMode(compile.CompileOptions{}))}
	if !budgeted() {
		r, _ := j.run()
		return r.Engine, true
	}
	r, _, err := runBudgeted(j)
	if errors.Is(err, errCompileTooSlow) {
		return 0, false
	}
	return r.Engine, true // SelectEngine's own error is ignored, as in-process
}

// cachedCompileSized is cachedCompile for a compile that also reports what its
// find export's searches keep (searchblock.Of), which a drive handing the
// per-search block over needs.
func cachedCompileSized(key string, j compileJob) ([]byte, []searchblock.Size, error) {
	modCacheMu.Lock()
	if modCacheIdx == nil {
		modCacheLRU, modCacheIdx = list.New(), map[string]*list.Element{}
	}
	if el, ok := modCacheIdx[key]; ok {
		modCacheLRU.MoveToFront(el)
		e := el.Value.(*modCacheEntry)
		modCacheMu.Unlock()
		if !ensureWarm(e.wasm, e.err) {
			return nil, nil, errCompileTooSlow
		}
		return e.wasm, e.sizes, e.err
	}
	modCacheMu.Unlock()

	if !budgeted() {
		// Compiled OUTSIDE the lock: a compile can take seconds, and holding
		// the lock across it would serialise workers that share a process.
		r, err := j.run()
		return storeCompiled(key, r.Wasm, r.Sizes, err)
	}
	r, err := runBudgetedCompile(j)
	if errors.Is(err, errCompileTooSlow) {
		if r.full {
			storeCompiled(key, nil, nil, errCompileTooSlow)
		}
		return nil, nil, errCompileTooSlow
	}
	return storeCompiled(key, r.Wasm, r.Sizes, err)
}

// budgetedResult is a budgeted compile's result and whether it had the whole
// slowCompileDeadline (runBudgeted).
type budgetedResult struct {
	compileResult
	full bool
}

// runBudgetedCompile runs j in the compile child, with the wasmtime build
// when modules are kept, and keeps the built module.
func runBudgetedCompile(j compileJob) (budgetedResult, error) {
	j.Warm = modulesKept()
	r, full, err := runBudgeted(j)
	if err == nil && r.Module != nil {
		keepSerialized(r.Wasm, r.Module)
	}
	return budgetedResult{r, full}, err
}

// storeCompiled caches a compile's result under key and returns the entry
// the cache holds for it.
func storeCompiled(key string, wasm []byte, sizes []searchblock.Size, err error) ([]byte, []searchblock.Size, error) {
	modCacheMu.Lock()
	defer modCacheMu.Unlock()
	if el, ok := modCacheIdx[key]; ok { // another goroutine won the race
		modCacheLRU.MoveToFront(el)
		e := el.Value.(*modCacheEntry)
		return e.wasm, e.sizes, e.err
	}
	modCacheIdx[key] = modCacheLRU.PushFront(&modCacheEntry{key: key, wasm: wasm, sizes: sizes, err: err})
	for modCacheLRU.Len() > modCacheSize {
		oldest := modCacheLRU.Back()
		modCacheLRU.Remove(oldest)
		delete(modCacheIdx, oldest.Value.(*modCacheEntry).key)
	}
	return wasm, sizes, err
}

// setCacheEntry is a compiled SET plus the per-set fact its callers need
// alongside the bytes (which patterns the compiler dropped, in both scopes —
// see setDrops).
type setCacheEntry struct {
	wasm  []byte
	drops setDrops
	err   error
}

var (
	setCacheMu  sync.Mutex
	setCacheLRU *list.List
	setCacheIdx map[string]*list.Element
)

// cachedCompileSet is cachedCompile for set compiles, which return the dropped
// patterns as well as bytes.
//
// Sets need this more than single patterns do, not less: set compilation is one
// of the two families the compiler's own speed work does not touch (the other
// is TDFA construction inside engine selection), and FuzzSetCaps compiles TWO
// patterns into every capability body on each call. The returned maps are shared, so callers must not write to them —
// none does; dropsFromSet builds them fresh and they are only ever read.
func cachedCompileSet(key string, j compileJob) ([]byte, setDrops, error) {
	setCacheMu.Lock()
	if setCacheIdx == nil {
		setCacheLRU, setCacheIdx = list.New(), map[string]*list.Element{}
	}
	if el, ok := setCacheIdx[key]; ok {
		setCacheLRU.MoveToFront(el)
		e := el.Value.(*setCacheEntry)
		setCacheMu.Unlock()
		if !ensureWarm(e.wasm, e.err) {
			return nil, setDrops{}, errCompileTooSlow
		}
		return e.wasm, e.drops, e.err
	}
	setCacheMu.Unlock()

	if !budgeted() {
		r, err := j.run()
		return storeCompiledSet(key, r.Wasm, r.drops(), err)
	}
	r, err := runBudgetedCompile(j)
	if errors.Is(err, errCompileTooSlow) {
		if r.full {
			storeCompiledSet(key, nil, setDrops{}, errCompileTooSlow)
		}
		return nil, setDrops{}, errCompileTooSlow
	}
	return storeCompiledSet(key, r.Wasm, r.drops(), err)
}

// storeCompiledSet caches a set compile's result under key and returns the
// entry the cache holds for it.
func storeCompiledSet(key string, wasm []byte, drops setDrops, err error) ([]byte, setDrops, error) {
	setCacheMu.Lock()
	defer setCacheMu.Unlock()
	if el, ok := setCacheIdx[key]; ok {
		setCacheLRU.MoveToFront(el)
		e := el.Value.(*setCacheEntry)
		return e.wasm, e.drops, e.err
	}
	setCacheIdx[key] = setCacheLRU.PushFront(&setCacheEntry{wasm: wasm, drops: drops, err: err})
	setKeyOf[setCacheLRU.Front()] = key
	for setCacheLRU.Len() > modCacheSize {
		oldest := setCacheLRU.Back()
		setCacheLRU.Remove(oldest)
		delete(setCacheIdx, setKeyOf[oldest])
		delete(setKeyOf, oldest)
	}
	return wasm, drops, err
}

// cachedShape is compile.SetOverlapCacheShape for sc in cfg, learned once per
// key — within the budget when the input is budgeted. The shape is learned by
// RECOMPILING the set, and when every cache drive of a FuzzSetRoutes input
// learned it again, that cost more than all the input's module compiles
// together. A shape is kept, and so is a compile killed after the whole of
// slowCompileDeadline; any other error is returned and not kept.
func cachedShape(key string, sc config.SetConfig, cfg config.BuildConfig) (compile.OverlapCacheShape, error) {
	shapeMu.Lock()
	e, ok := shapeMemo[key]
	shapeMu.Unlock()
	if ok {
		return e.shape, e.err
	}
	j := compileJob{Kind: jobShape, Set: sc, Config: cfg}
	var (
		r    compileResult
		full bool
		err  error
	)
	if budgeted() {
		r, full, err = runBudgeted(j)
	} else {
		r, err = j.run()
	}
	if err == nil || full && errors.Is(err, errCompileTooSlow) {
		shapeMu.Lock()
		shapeMemo[key] = shapeEntry{r.Shape, err}
		shapeMu.Unlock()
	}
	return r.Shape, err
}

type shapeEntry struct {
	shape compile.OverlapCacheShape
	err   error
}

var (
	shapeMu   sync.Mutex
	shapeMemo = map[string]shapeEntry{}
)

// setKeyOf maps a list element back to its key, so eviction can drop the index
// entry. The single-pattern cache stores the key inside its entry instead;
// this one keeps it beside, because the entry type is shared with callers.
var setKeyOf = map[*list.Element]string{}

// setKey turns a set's pattern list into a cache key.
//
// NOT fmt.Sprintf("%v", pats): that joins with a SPACE, so []string{" ", ""}
// and []string{"", " "} both render as "[  ]" and the second set silently gets
// the first one's module. A pattern's INDEX is its id, so swapping two
// patterns swaps every id the set reports, and the harness then checks one
// module's answers against the other's oracle. That produced five crasher
// files that pass on solo replay.
//
// NOT a joined string either, whatever the separator. The fuzzer mutates
// arbitrary bytes and Go's regexp compiles every one of them — a NUL is an
// ordinary literal, verified — so joining on NUL makes {"a\x00b"} and
// {"a", "b"} collide exactly as %v did. Only a LENGTH PREFIX is injective:
// the reader of the key can always tell where one pattern stops.
func setKey(pats []string) string {
	var b strings.Builder
	// The run's mode (setModeKey) is part of what a set compiles to.
	b.WriteString(strconv.FormatBool(*unicodeMode))
	b.WriteByte('|')
	for _, p := range pats {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}

// Under -unicode a module's own compile by wasmtime can take as long as
// regexped's — a lowered `.{1,700}` on Backtracking is one 4 MB dispatch
// function Cranelift needs 16-19s for — and instantiate is outside every
// compile deadline. So a budgeted compile has the compile child build the
// wasmtime module too, inside the same deadline, and hand it back serialized
// (keepSerialized); instantiate takes it from here. A module too slow to
// build is then the same resource ceiling a slow regexped compile is.
const fuzzModuleCacheSize = 4

var (
	fuzzModuleMu    sync.Mutex
	fuzzModules     = map[[32]byte]*wasmtime.Module{}
	fuzzModuleOrder [][32]byte
	// tooSlowWarm is the modules whose wasmtime build was killed after the
	// whole of slowCompileDeadline: one is skipped at once when it comes back.
	tooSlowWarm = map[[32]byte]bool{}
)

// keepModules makes the module cache serve a target outside a fuzz run under
// -unicode too: FuzzSetRoutes drives each of its few modules through a dozen
// routes, and a wasmtime build of 0.5-2 s per route put one input past the fuzz
// worker's 10 s deadline. Set for the duration of such a target only.
var keepModules bool

// modulesKept reports whether compiled modules are warmed and reused.
func modulesKept() bool { return keepModules || fuzzingUnicode() }

// warmModule compiles wasm with the shared engine, in this process, and keeps
// it for instantiate. A no-op unless modulesKept.
func warmModule(wasm []byte) {
	if !modulesKept() || len(wasm) == 0 || warmedModule(wasm) != nil {
		return
	}
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return // instantiate compiles it again and reports the error
	}
	keepModule(wasm, mod)
}

// keepSerialized keeps the module the compile child built for wasm.
func keepSerialized(wasm, serialized []byte) {
	if !modulesKept() || warmedModule(wasm) != nil {
		return
	}
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModuleDeserialize(engine, serialized)
	if err != nil {
		// The child's engine is this one's, from the same binary, so this is
		// the harness's defect and not a compile's ceiling.
		panic("tools/fuzz: a module the compile child built does not load: " + err.Error())
	}
	keepModule(wasm, mod)
}

// keepModule keeps mod as wasm's module for instantiate.
func keepModule(wasm []byte, mod *wasmtime.Module) {
	key := sha256.Sum256(wasm)
	fuzzModuleMu.Lock()
	defer fuzzModuleMu.Unlock()
	if _, ok := fuzzModules[key]; ok {
		return
	}
	fuzzModules[key] = mod
	fuzzModuleOrder = append(fuzzModuleOrder, key)
	if len(fuzzModuleOrder) > fuzzModuleCacheSize {
		// Not closed: an instance may still use it; the finalizer frees it.
		delete(fuzzModules, fuzzModuleOrder[0])
		fuzzModuleOrder = fuzzModuleOrder[1:]
	}
}

// ensureWarm makes sure a cached compile's module is warm when modules are
// kept, building it when the module cache let it go: within the budget in the
// compile child when the input is budgeted, waited for otherwise. false when
// that build ran past the budget.
func ensureWarm(wasm []byte, err error) bool {
	if !modulesKept() || err != nil || len(wasm) == 0 || warmedModule(wasm) != nil {
		return true
	}
	if !budgeted() {
		warmModule(wasm)
		return true
	}
	key := sha256.Sum256(wasm)
	fuzzModuleMu.Lock()
	slow := tooSlowWarm[key]
	fuzzModuleMu.Unlock()
	if slow {
		return false
	}
	r, full, err := runBudgeted(compileJob{Kind: jobWarm, Wasm: wasm, Warm: true})
	if errors.Is(err, errCompileTooSlow) {
		if full {
			fuzzModuleMu.Lock()
			tooSlowWarm[key] = true
			fuzzModuleMu.Unlock()
		}
		return false
	}
	if r.Module != nil {
		keepSerialized(wasm, r.Module)
	}
	return true
}

// warmedModule is the module kept for wasm, or nil.
func warmedModule(wasm []byte) *wasmtime.Module {
	if !modulesKept() {
		return nil
	}
	key := sha256.Sum256(wasm)
	fuzzModuleMu.Lock()
	defer fuzzModuleMu.Unlock()
	return fuzzModules[key]
}
