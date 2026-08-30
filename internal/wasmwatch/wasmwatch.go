// Package wasmwatch bounds how long a single WASM call may run.
//
// # Why it exists
//
// A defect in a generated find body can make a HOST loop non-terminating
// rather than merely wrong: the iteration rule every stub and bench shim uses
// is `off += end - off`, so a body that reports a match starting before the
// position it was asked to search from sends `off` backwards and the loop
// ping-pongs for ever. That is a real bug (plans/FUZZER_BUGS.md 65), and it
// presented as `tools/perftest` sitting at 101% CPU for two and a half hours
// with no output and no indication of which case it was stuck on.
//
// tools/re2test and tools/fuzz already had a watchdog and would have named the
// pattern in seconds. The four BENCHMARK harnesses had nothing — which is the
// worst place for it to be missing, because a benchmark cannot tell a hang from
// a slow pattern by looking, and perftest in particular runs all its iterations
// INSIDE one WASM call so there is no host-side loop to notice anything.
//
// # Choosing a timeout
//
// The default is deliberately far above any legitimate call. A perftest bench
// shim runs Iters (10,000) iterations inside a single call, so a slow pattern
// on a 100 KB input can legitimately take a second or more; this is not a
// latency budget, it is a liveness check. Override with REGEXPED_WASM_TIMEOUT
// (a Go duration, e.g. "5m") when profiling something genuinely slow.
package wasmwatch

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Store and Engine are the two slices of the wasmtime API this needs. They are
// interfaces so that the ROOT module stays free of the wasmtime dependency —
// wasmtime is a dependency of the harnesses under tools/, never of the
// compiler, and importing it here would make it one.
type Store interface{ SetEpochDeadline(deadline uint64) }

type Engine interface{ IncrementEpoch() }

// DefaultTimeout bounds one WASM call.
const DefaultTimeout = 60 * time.Second

// Timeout is DefaultTimeout unless REGEXPED_WASM_TIMEOUT overrides it.
func Timeout() time.Duration {
	if v := os.Getenv("REGEXPED_WASM_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultTimeout
}

// Watchdog manages one reusable timeout goroutine. Arm before a WASM call,
// Disarm when it returns; if the timeout fires first the engine's epoch is
// incremented, which traps the in-flight call.
type Watchdog struct {
	arm    chan Store
	disarm chan struct{}

	// Engines may be registered after the goroutine starts — the harnesses
	// build a second engine for fuel measurement partway through — so the
	// slice is guarded.
	mu      sync.Mutex
	engines []Engine
}

// Watch registers an engine to interrupt. Safe to call at any time.
func (w *Watchdog) Watch(e Engine) {
	w.mu.Lock()
	w.engines = append(w.engines, e)
	w.mu.Unlock()
}

func (w *Watchdog) fire() {
	w.mu.Lock()
	engines := append([]Engine(nil), w.engines...)
	w.mu.Unlock()
	for _, e := range engines {
		e.IncrementEpoch()
	}
}

// New starts the watchdog goroutine. Every registered engine's config MUST
// have SetEpochInterruption(true); an engine built without it cannot be
// interrupted and the watchdog would silently do nothing.
//
// Several engines may be registered — the harnesses keep a separate one for
// fuel measurement — and all of them are incremented when the timer fires.
// Incrementing an idle engine's epoch is a no-op, so there is no need to track
// which engine the in-flight call belongs to. These harnesses run one call at a
// time by construction, which is what makes that simplification safe.
func New(timeout time.Duration, engines ...Engine) *Watchdog {
	w := &Watchdog{
		arm:     make(chan Store),
		disarm:  make(chan struct{}),
		engines: engines,
	}
	go func() {
		for range w.arm {
			select {
			case <-time.After(timeout):
				w.fire()
				<-w.disarm // consume the disarm that follows the interrupt
			case <-w.disarm:
			}
		}
	}()
	return w
}

// Arm sets the store's epoch deadline ON THE CALLING GOROUTINE, then starts the
// timer.
//
// The deadline must not be set inside the watchdog goroutine: `w.arm <- store`
// returns as soon as that goroutine RECEIVES, not when it is finished with the
// store, so the caller would proceed into the WASM call while the goroutine was
// still inside SetEpochDeadline on the same store. wasmtime.Store is not
// thread-safe, and that is a race into cgo. Only IncrementEpoch stays on the
// goroutine — the one operation wasmtime documents as safe from another thread.
// (tools/fuzz hit exactly this and carries the same note.)
func (w *Watchdog) Arm(store Store) {
	store.SetEpochDeadline(1)
	w.arm <- store
}

// Disarm reports that the call returned.
func (w *Watchdog) Disarm() { w.disarm <- struct{}{} }

// IsTimeout reports whether err is this watchdog's interruption rather than a
// genuine trap.
func IsTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "interrupt")
}
