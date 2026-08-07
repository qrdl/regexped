package fuzz

import (
	"fmt"
	"strings"
	"sync"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

const (
	// tableBase is the WASM memory offset where DFA tables start. Test
	// input is written at offset 0, so any input at or past tableBase would
	// spill into table data — see inputCap in fuzz_test.go.
	tableBase = int64(65536)

	wasmCallTimeout = 2 * time.Second
)

// compileFind compiles pat into a standalone WASM module exporting a single
// non-anchored find function, with no captures — the DFA/Compiled DFA find
// body (Layer 1's target per plans/FUZZER.md).
func compileFind(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
	wasmBytes, _, err := compile.Compile([]config.RegexEntry{entry}, tableBase, true)
	return wasmBytes, err
}

// One wasmtime engine + watchdog per test process, shared across all fuzz
// iterations — recreating them per call would dominate runtime.
var (
	engineOnce sync.Once
	wtEngine   *wasmtime.Engine
	wd         *watchdog
)

func sharedEngine() (*wasmtime.Engine, *watchdog) {
	engineOnce.Do(func() {
		cfg := wasmtime.NewConfig()
		cfg.SetEpochInterruption(true)
		wtEngine = wasmtime.NewEngineWithConfig(cfg)
		wd = newWatchdog(wtEngine)
	})
	return wtEngine, wd
}

// runWasmFind instantiates wasmBytes and calls its find export on input.
// Returns the matched [start,end) span and ok=true on a match; ok=false with
// a nil err means "no match". hang=true means the watchdog killed a runaway
// call (the O(n^2) hang detector from plans/FUZZER.md item 6); err covers
// any other WASM-level failure (bad module, trap, missing exports).
func runWasmFind(wasmBytes []byte, input string) (span [2]int, ok bool, hang bool, err error) {
	engine, wd := sharedEngine()

	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return span, false, false, err
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		return span, false, false, err
	}
	findFn := inst.GetFunc(store, "find")
	memExp := inst.GetExport(store, "memory")
	if findFn == nil || memExp == nil || memExp.Memory() == nil {
		return span, false, false, fmt.Errorf("module missing find export or memory")
	}
	mem := memExp.Memory()

	if len(input) > 0 {
		buf := mem.UnsafeData(store)
		copy(buf, input) // inputBase = 0
	}

	wd.Arm(store)
	result, callErr := findFn.Call(store, int32(0), int32(len(input)))
	wd.Disarm()
	if callErr != nil {
		if isTimeout(callErr) {
			return span, false, true, nil
		}
		return span, false, false, callErr
	}

	r := result.(int64)
	if r == -1 {
		return span, false, false, nil
	}
	span[0] = int(uint32(r >> 32))
	span[1] = int(uint32(r))
	return span, true, false, nil
}

// watchdog manages a single reusable timeout goroutine, mirroring
// tools/re2test's: Arm before a WASM call, Disarm when it completes
// normally. If the timeout fires first, it increments the engine epoch,
// interrupting the in-flight call.
type watchdog struct {
	arm    chan *wasmtime.Store
	disarm chan struct{}
}

func newWatchdog(eng *wasmtime.Engine) *watchdog {
	w := &watchdog{
		arm:    make(chan *wasmtime.Store),
		disarm: make(chan struct{}),
	}
	go func() {
		for store := range w.arm {
			store.SetEpochDeadline(1)
			select {
			case <-time.After(wasmCallTimeout):
				eng.IncrementEpoch()
				<-w.disarm // consume the disarm that will arrive after interrupt
			case <-w.disarm:
				// call completed before timeout — nothing to do
			}
		}
	}()
	return w
}

func (w *watchdog) Arm(store *wasmtime.Store) { w.arm <- store }
func (w *watchdog) Disarm()                   { w.disarm <- struct{}{} }

// isTimeout reports whether a wasmtime error is an epoch interruption.
func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "interrupt")
}
