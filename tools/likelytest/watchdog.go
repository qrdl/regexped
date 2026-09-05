package main

import (
	"fmt"
	"os"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/wasmwatch"
)

// Liveness for every WASM call this harness makes.
//
// A benchmark cannot tell a hang from a slow pattern by looking, and this
// harness runs all its iterations INSIDE one WASM call, so there is no
// host-side loop to notice either. When a generated find body reported a match
// starting before the position it was asked to search from, the shim's
// `off += end - off` advance went negative and this process sat at 101%% CPU
// for two and a half hours with no output and no clue which case it was on
// (plans/FUZZER_BUGS.md 65). re2test and tools/fuzz already had a watchdog and
// would have named the pattern in seconds.
//
// The timeout is a liveness check, not a latency budget — see wasmwatch.
var wdog *wasmwatch.Watchdog

// wcallCase names the case being measured, so a timeout says WHICH one hung.
var wcallCase string

// inSeries is true while a watchedSeries region is open. wcall then makes the
// call bare, because the region already holds the epoch deadline that would
// interrupt it — see watchedSeries for why the arming must not be per call.
// This harness runs one WASM call at a time by construction, so a plain
// package-level flag is enough.
var inSeries bool

// wcall is the only way this harness should invoke a WASM function.
func wcall(fn *wasmtime.Func, store *wasmtime.Store, args ...interface{}) (interface{}, error) {
	if wdog == nil || inSeries {
		res, err := fn.Call(store, args...)
		reportTimeout(err)
		return res, err
	}
	wdog.Arm(store)
	res, err := fn.Call(store, args...)
	wdog.Disarm()
	reportTimeout(err)
	return res, err
}

// watchedSeries runs body with the watchdog armed ONCE for its whole duration.
//
// The modeSet bench is the one path here that does NOT run its iterations
// inside a single WASM call: it drives the real set export once per sample from
// the host, so anything wcall does per call lands inside the measured interval.
// Arming is an unbuffered channel handoff to the watchdog goroutine plus a
// timer — ~850 ns on the development machine, and more against a live store —
// which is the same order as a scan over a short input and dilutes exactly the
// hint deltas the set cases exist to show. Wrapping the whole series keeps the
// liveness guarantee (a hang in any pass still traps, and still names the case)
// while leaving nothing host-side inside the timing. The trade is that the
// timeout bounds the SERIES rather than one call, which is a bound on wall time
// either way and is what REGEXPED_WASM_TIMEOUT is for.
func watchedSeries(store *wasmtime.Store, body func() error) error {
	if wdog == nil {
		return body()
	}
	wdog.Arm(store)
	inSeries = true
	err := body()
	inSeries = false
	wdog.Disarm()
	return err
}

// reportTimeout tells the user a watchdog interrupt is a hang, not slow work.
func reportTimeout(err error) {
	if !wasmwatch.IsTimeout(err) {
		return
	}
	fmt.Fprintf(os.Stderr,
		"\nWASM call exceeded %s during %q — this is a HANG, not a slow pattern.\n"+
			"Set REGEXPED_WASM_TIMEOUT to raise the bound if the work is genuinely this slow.\n",
		wasmwatch.Timeout(), wcallCase)
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
