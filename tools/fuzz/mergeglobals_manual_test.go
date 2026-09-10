package fuzz

// Multi-global merge check (TODO 75's entry toll), run by hand:
//
//	go test ./tools/fuzz -run TestMergedTwoGlobals \
//	    -args -mergeglobals-std=<std.wasm> -mergeglobals-merged=<merged.wasm>
//
// A regexp module that declares TWO globals — the find-from channel and the
// absolute capture start — must answer identically once wasm-merge renumbers
// them into a host with globals of its own. A wrong renumbering VALIDATES and
// reads the wrong variable, so this compares answers rather than indices.

import (
	"flag"
	"testing"

	"github.com/bytecodealliance/wasmtime-go/v48"
)

var (
	// Prefixed, because these are package-level flags in a package that runs
	// automatically: a bare -std/-merged is the kind of generic name the next
	// hand-run harness added here would collide with.
	mgStd    = flag.String("mergeglobals-std", "", "standalone two-global module")
	mgMerged = flag.String("mergeglobals-merged", "", "the same module merged into a host")
)

const mgInput = "see http://example.com/abc here"

func mgRun(t *testing.T, path string, wasi bool) (int64, []int32) {
	t.Helper()
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(engine)
	if wasi {
		store.SetWasi(wasmtime.NewWasiConfig())
		if err := linker.DefineWasi(); err != nil {
			t.Fatalf("wasi: %v", err)
		}
	}
	mod, err := wasmtime.NewModuleFromFile(engine, path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	inst, err := linker.Instantiate(store, mod)
	if err != nil {
		t.Fatalf("instantiate %s: %v", path, err)
	}
	mem := inst.GetExport(store, "memory").Memory()
	base := int32(mem.DataSize(store)) - 8192
	data := mem.UnsafeData(store)
	copy(data[base:], mgInput)
	out := base + 1024
	for i := out; i < out+256; i++ {
		data[i] = 0
	}
	fr, err := inst.GetExport(store, "url_find").Func().Call(store, base, int32(len(mgInput)), int32(0))
	if err != nil {
		t.Fatalf("url_find %s: %v", path, err)
	}
	if _, err := inst.GetExport(store, "url_groups").Func().Call(store, base, int32(len(mgInput)), out, int32(0)); err != nil {
		t.Fatalf("url_groups %s: %v", path, err)
	}
	data = mem.UnsafeData(store)
	var slots []int32
	for i := 0; i < 8; i++ {
		o := int(out) + i*4
		slots = append(slots, int32(uint32(data[o])|uint32(data[o+1])<<8|uint32(data[o+2])<<16|uint32(data[o+3])<<24))
	}
	return fr.(int64), slots
}

func TestMergedTwoGlobals(t *testing.T) {
	if *mgStd == "" || *mgMerged == "" {
		t.Skip("needs -mergeglobals-std and -mergeglobals-merged")
	}
	f1, g1 := mgRun(t, *mgStd, false)
	f2, g2 := mgRun(t, *mgMerged, true)
	t.Logf("standalone find=%#x groups=%v", uint64(f1), g1)
	t.Logf("merged     find=%#x groups=%v", uint64(f2), g2)
	if f1 != f2 {
		t.Errorf("find differs after merge: standalone %#x, merged %#x", uint64(f1), uint64(f2))
	}
	for i := range g1 {
		if g1[i] != g2[i] {
			t.Errorf("group slot %d differs after merge: standalone %d, merged %d", i, g1[i], g2[i])
		}
	}
}
