package fuzz

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
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
// and the miss is what costs — see FUZZER_BUGS bug 83.
const modCacheSize = 16

// modCache is a per-process LRU of compiled modules, keyed by the caller's own
// key (a pattern plus whatever else varies its compile).
//
// Callers must treat the returned bytes as READ-ONLY: every hit hands back the
// same slice. Nothing in this package writes to a module after compiling it —
// instantiate copies what it needs — so sharing is safe, and a copy per hit
// would give back most of what the cache saves.
type modCacheEntry struct {
	key  string
	wasm []byte
	err  error
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
	modCacheMu.Lock()
	if modCacheIdx == nil {
		modCacheLRU, modCacheIdx = list.New(), map[string]*list.Element{}
	}
	if el, ok := modCacheIdx[key]; ok {
		modCacheLRU.MoveToFront(el)
		e := el.Value.(*modCacheEntry)
		modCacheMu.Unlock()
		return e.wasm, e.err
	}
	modCacheMu.Unlock()

	// Compiled OUTSIDE the lock: a compile can take seconds, and holding the
	// lock across it would serialise workers that share a process.
	wasm, err := build()

	modCacheMu.Lock()
	defer modCacheMu.Unlock()
	if el, ok := modCacheIdx[key]; ok { // another goroutine won the race
		modCacheLRU.MoveToFront(el)
		e := el.Value.(*modCacheEntry)
		return e.wasm, e.err
	}
	modCacheIdx[key] = modCacheLRU.PushFront(&modCacheEntry{key: key, wasm: wasm, err: err})
	for modCacheLRU.Len() > modCacheSize {
		oldest := modCacheLRU.Back()
		modCacheLRU.Remove(oldest)
		delete(modCacheIdx, oldest.Value.(*modCacheEntry).key)
	}
	return wasm, err
}

// setCacheEntry is a compiled SET plus the per-set fact its callers need
// alongside the bytes (which patterns the compiler dropped).
type setCacheEntry struct {
	wasm    []byte
	dropped map[int]bool
	err     error
}

var (
	setCacheMu  sync.Mutex
	setCacheLRU *list.List
	setCacheIdx map[string]*list.Element
)

// cachedCompileSet is cachedCompile for set compiles, which return a dropped
// map as well as bytes.
//
// Sets need this more than single patterns do, not less: FUZZER_BUGS bug 83
// names set compilation as one of the two families its speed work does not
// touch, and FuzzSetCaps compiles TWO patterns into every capability body on
// each call. The returned map is shared, so callers must not write to it —
// none does; droppedFromSet builds it fresh and it is only ever read.
func cachedCompileSet(key string, build func() ([]byte, map[int]bool, error)) ([]byte, map[int]bool, error) {
	setCacheMu.Lock()
	if setCacheIdx == nil {
		setCacheLRU, setCacheIdx = list.New(), map[string]*list.Element{}
	}
	if el, ok := setCacheIdx[key]; ok {
		setCacheLRU.MoveToFront(el)
		e := el.Value.(*setCacheEntry)
		setCacheMu.Unlock()
		return e.wasm, e.dropped, e.err
	}
	setCacheMu.Unlock()

	wasm, dropped, err := build()

	setCacheMu.Lock()
	defer setCacheMu.Unlock()
	if el, ok := setCacheIdx[key]; ok {
		setCacheLRU.MoveToFront(el)
		e := el.Value.(*setCacheEntry)
		return e.wasm, e.dropped, e.err
	}
	setCacheIdx[key] = setCacheLRU.PushFront(&setCacheEntry{wasm: wasm, dropped: dropped, err: err})
	setKeyOf[setCacheLRU.Front()] = key
	for setCacheLRU.Len() > modCacheSize {
		oldest := setCacheLRU.Back()
		setCacheLRU.Remove(oldest)
		delete(setCacheIdx, setKeyOf[oldest])
		delete(setKeyOf, oldest)
	}
	return wasm, dropped, err
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
// files that pass on solo replay (FUZZER_BUGS bug 87).
//
// NOT a joined string either, whatever the separator. The fuzzer mutates
// arbitrary bytes and Go's regexp compiles every one of them — a NUL is an
// ordinary literal, verified — so joining on NUL makes {"a\x00b"} and
// {"a", "b"} collide exactly as %v did. Only a LENGTH PREFIX is injective:
// the reader of the key can always tell where one pattern stops.
func setKey(pats []string) string {
	var b strings.Builder
	for _, p := range pats {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}
