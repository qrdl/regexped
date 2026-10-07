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

// cachedCompile returns the module for key, compiling it with build on a miss.
//
// Compile ERRORS are cached too. They are deterministic for a given key, and
// the expensive ones are exactly the resource ceilings a slow pattern hits, so
// not caching them would leave the worst case uncached.
func cachedCompile(key string, build func() ([]byte, error)) ([]byte, error) {
	wasm, _, err := cachedCompileSized(key, func() ([]byte, []searchblock.Size, error) {
		w, err := build()
		return w, nil, err
	})
	return wasm, err
}

// errCompileTooSlow is a compile the fuzz harness stopped waiting for: see
// slowCompileDeadline. A resource ceiling of the harness, not of regexped.
var errCompileTooSlow = errors.New("compile ran past the fuzz harness's deadline")

// slowCompileDeadline bounds how long a fuzzing run under -unicode waits for
// one compile. Go's fuzz worker reports any input that takes over 10s as a
// crasher, and in Unicode mode the instruction-count cap (maxNFAInsts, which
// is calibrated in byte mode) cannot bound compile time: a lowered class
// makes every TDFA state dear, so `[0]+0()00.{31}` — about 40 instructions —
// builds a 4,004-state TDFA it then rejects for its registers in 16.8s alone,
// more in a worker. Only the clock bounds that. A compile past the deadline
// is skipped (errCompileTooSlow) and finishes in the background into the
// cache; while it runs, every compile the cache does not hold is skipped too,
// so slow compiles cannot pile up. Byte mode, and any run that is not
// fuzzing, waits for every compile as before.
const slowCompileDeadline = 4 * time.Second

// fuzzInputCompileBudget is how long ALL the compiles of one fuzz input may
// take under -unicode, where an input compiles more than once — a set target
// builds its capability module and its gated one — and two compiles each
// within slowCompileDeadline still overran the worker's 10s in a loaded run.
const fuzzInputCompileBudget = 5 * time.Second

var (
	slowCompileMu      sync.Mutex
	slowCompileRunning bool
	// inputDeadline is the current fuzz input's compile budget's end, zero
	// outside a target that set one (beginFuzzInput).
	inputDeadline time.Time
)

// beginFuzzInput starts the compile budget of one fuzz input: every compile
// runWithDeadline waits for during it shares fuzzInputCompileBudget. A no-op
// outside a fuzz run under -unicode.
func beginFuzzInput() {
	if !fuzzingUnicode() {
		return
	}
	slowCompileMu.Lock()
	inputDeadline = time.Now().Add(fuzzInputCompileBudget)
	slowCompileMu.Unlock()
}

// fuzzingUnicode reports whether this process is a fuzz run under -unicode.
func fuzzingUnicode() bool {
	f := flag.Lookup("test.fuzz")
	return *unicodeMode && f != nil && f.Value.String() != ""
}

// cachedCompileSized is cachedCompile for a compile that also reports what its
// find export's searches keep (searchblock.Of), which a drive handing the
// per-search block over needs.
func cachedCompileSized(key string, build func() ([]byte, []searchblock.Size, error)) ([]byte, []searchblock.Size, error) {
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

	if fuzzingUnicode() {
		return compileWithDeadline(key, build)
	}
	// Compiled OUTSIDE the lock: a compile can take seconds, and holding the
	// lock across it would serialise workers that share a process.
	wasm, sizes, err := build()
	return storeCompiled(key, wasm, sizes, err)
}

// compileWithDeadline is the compile of a fuzz run under -unicode: see
// slowCompileDeadline.
func compileWithDeadline(key string, build func() ([]byte, []searchblock.Size, error)) ([]byte, []searchblock.Size, error) {
	var (
		wasm  []byte
		sizes []searchblock.Size
		err   error
	)
	if !runWithDeadline(func() {
		wasm, sizes, err = build()
		if err == nil {
			warmModule(wasm)
		}
		storeCompiled(key, wasm, sizes, err)
	}) {
		return nil, nil, errCompileTooSlow
	}
	return wasm, sizes, err
}

// runWithDeadline runs build, waiting at most slowCompileDeadline, and reports
// whether it finished; one that did not finishes in the background (and
// stores what it built), and until it does every other call reports false at
// once, so slow compiles cannot pile up. Whether build finished and whether a
// slow compile is running are decided under one lock, so a build that ends as
// the deadline fires cannot leave the flag set.
func runWithDeadline(build func()) bool {
	slowCompileMu.Lock()
	wait := slowCompileDeadline
	if !inputDeadline.IsZero() {
		wait = min(wait, time.Until(inputDeadline))
	}
	if slowCompileRunning || wait <= 0 {
		slowCompileMu.Unlock()
		return false
	}
	slowCompileMu.Unlock()
	done := make(chan struct{})
	finished := false
	go func() {
		build()
		slowCompileMu.Lock()
		finished = true
		slowCompileRunning = false
		slowCompileMu.Unlock()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		slowCompileMu.Lock()
		defer slowCompileMu.Unlock()
		if finished {
			return true
		}
		slowCompileRunning = true
		return false
	}
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
func cachedCompileSet(key string, build func() ([]byte, setDrops, error)) ([]byte, setDrops, error) {
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

	if fuzzingUnicode() {
		var (
			wasm  []byte
			drops setDrops
			err   error
		)
		if !runWithDeadline(func() {
			wasm, drops, err = build()
			if err == nil {
				warmModule(wasm)
			}
			storeCompiledSet(key, wasm, drops, err)
		}) {
			return nil, setDrops{}, errCompileTooSlow
		}
		return wasm, drops, err
	}
	wasm, drops, err := build()
	return storeCompiledSet(key, wasm, drops, err)
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
// compile deadline. So a fuzz run under -unicode compiles the wasmtime module
// INSIDE the deadline-guarded build (warmModule) and instantiate takes it from
// here: a module too slow to compile is then the same resource ceiling a slow
// regexped compile is.
const fuzzModuleCacheSize = 4

var (
	fuzzModuleMu    sync.Mutex
	fuzzModules     = map[[32]byte]*wasmtime.Module{}
	fuzzModuleOrder [][32]byte
)

// warmModule compiles wasm with the shared engine and keeps it for
// instantiate. A no-op outside a fuzz run under -unicode.
func warmModule(wasm []byte) {
	if !fuzzingUnicode() || len(wasm) == 0 {
		return
	}
	key := sha256.Sum256(wasm)
	fuzzModuleMu.Lock()
	_, ok := fuzzModules[key]
	fuzzModuleMu.Unlock()
	if ok {
		return
	}
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return // instantiate compiles it again and reports the error
	}
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

// ensureWarm makes sure a cached compile's module is warm in a fuzz run under
// -unicode, compiling it under the deadline when the module cache let it go;
// false when that compile ran past it.
func ensureWarm(wasm []byte, err error) bool {
	if !fuzzingUnicode() || err != nil || warmedModule(wasm) != nil {
		return true
	}
	return runWithDeadline(func() { warmModule(wasm) })
}

// warmedModule is the module warmModule compiled for wasm, or nil.
func warmedModule(wasm []byte) *wasmtime.Module {
	if !fuzzingUnicode() {
		return nil
	}
	key := sha256.Sum256(wasm)
	fuzzModuleMu.Lock()
	defer fuzzModuleMu.Unlock()
	return fuzzModules[key]
}
