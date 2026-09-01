package main

import (
	"fmt"
	"os"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/wasmwatch"
)

// Liveness for every WASM call this harness makes.
//
// A benchmark cannot tell a hang from a slow pattern by looking, and the one
// host-side loop here — `find` driven to exhaustion — cannot notice either: it
// resumes at whatever start the module reports. When a generated find body
// reported a match starting BEFORE the position it was asked to search from,
// that advance went backwards and the sibling harness sat at 101%% CPU for two
// and a half hours with no output and no clue which case it was on
// (plans/FUZZER_BUGS.md 65). re2test and tools/fuzz already had a watchdog and
// would have named the pattern in seconds.
//
// The timeout is a liveness check, not a latency budget — see wasmwatch.
var wdog *wasmwatch.Watchdog

// wcallCase names the case being measured, so a timeout says WHICH one hung.
var wcallCase string

// wcall is the only way this harness should invoke a WASM function.
func wcall(fn *wasmtime.Func, store *wasmtime.Store, args ...interface{}) (interface{}, error) {
	if wdog == nil {
		return fn.Call(store, args...)
	}
	wdog.Arm(store)
	res, err := fn.Call(store, args...)
	wdog.Disarm()
	if wasmwatch.IsTimeout(err) {
		fmt.Fprintf(os.Stderr,
			"\nWASM call exceeded %s during %q — this is a HANG, not a slow pattern.\n"+
				"Set REGEXPED_WASM_TIMEOUT to raise the bound if the work is genuinely this slow.\n",
			wasmwatch.Timeout(), wcallCase)
	}
	return res, err
}

// newWatchedEngine builds an engine whose calls this harness's watchdog can
// interrupt. Epoch interruption must be enabled on the CONFIG — an engine
// without it cannot be interrupted, and the watchdog would silently do nothing.
func newWatchedEngine(cfg *wasmtime.Config) *wasmtime.Engine {
	if cfg == nil {
		cfg = wasmtime.NewConfig()
	}
	cfg.SetEpochInterruption(true)
	e := wasmtime.NewEngineWithConfig(cfg)
	if wdog == nil {
		wdog = wasmwatch.New(wasmwatch.Timeout())
	}
	wdog.Watch(e)
	return e
}
