package fuzz

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// errBTOverflow reports that an export returned abi.BTStackOverflow: the
// Backtracking engine exhausted its compile-time frame budget, so it does not
// know whether the input matches.
//
// Targets must SKIP on this, not fail. It is a documented runtime ceiling that
// the engine reports honestly — comparing it against the oracle would flag a
// "wrong answer" for an answer the engine explicitly declined to give, which is
// the same class of harness mistake as treating a compile-time ceiling error as
// a bug (see isResourceCeiling).
//
// Before the §N1 fix this was indistinguishable from a genuine no-match, so the
// harness could not have skipped it even in principle — a long-input false
// negative would simply have been reported as an engine bug, or worse, matched
// the oracle by luck.
var errBTOverflow = errors.New("backtracking stack overflow (abi.BTStackOverflow)")

const (
	// tableBase is the WASM memory offset where DFA tables start. Test
	// input is written at offset 0, so any input at or past tableBase would
	// spill into table data — see inputCap in fuzz_test.go.
	tableBase = int64(65536)

	wasmCallTimeout = 2 * time.Second
)

// compileFind compiles pat into a standalone WASM module exporting a single
// non-anchored find function, with no captures — the DFA/Compiled DFA find
// body (Layer 1's target).
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
// call (the O(n^2) hang detector); err covers
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
	if r == abi.BTStackOverflow {
		return span, false, false, errBTOverflow
	}
	if r == abi.NoMatch {
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
		for range w.arm {
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

// Arm sets the store's epoch deadline ON THE CALLING GOROUTINE, then starts
// the timer.
//
// The deadline used to be set inside the watchdog goroutine, which is a data
// race on the Store. `w.arm <- store` returns as
// soon as the goroutine RECEIVES, not after it finishes with the store, so the
// caller went straight into fn.Call while the goroutine was still inside
// SetEpochDeadline on that same store. wasmtime.Store is not thread-safe, so
// that is a race into cgo.
//
// Scope of the claim: the race is established by inspection. It is NOT known
// to have caused any observed failure — it was found while investigating bug
// 49's worker aborts, and those continued unchanged after this fix.
//
// Only eng.IncrementEpoch stays on the goroutine, which is the one operation
// wasmtime explicitly documents as safe to call from another thread.
func (w *watchdog) Arm(store *wasmtime.Store) {
	store.SetEpochDeadline(1)
	w.arm <- store
}
func (w *watchdog) Disarm() { w.disarm <- struct{}{} }

// isTimeout reports whether a wasmtime error is an epoch interruption.
func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "interrupt")
}
