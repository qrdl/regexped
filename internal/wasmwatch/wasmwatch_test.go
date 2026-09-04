package wasmwatch

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStore records the epoch deadline the watchdog sets, and on which
// goroutine it was set.
//
// The goroutine matters: Arm must set the deadline on the CALLER's goroutine,
// because `w.arm <- store` returns when the watchdog RECEIVES, not when it is
// finished with the store — so setting it inside the watchdog would race the
// caller's own WASM call on a store wasmtime does not make thread-safe.
type fakeStore struct {
	mu       sync.Mutex
	deadline uint64
	set      int
}

func (s *fakeStore) SetEpochDeadline(d uint64) {
	s.mu.Lock()
	s.deadline, s.set = d, s.set+1
	s.mu.Unlock()
}

func (s *fakeStore) calls() (uint64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline, s.set
}

// fakeEngine counts epoch increments, which is the only thing the watchdog
// does to an engine and the thing that traps an in-flight call.
type fakeEngine struct {
	mu sync.Mutex
	n  int
}

func (e *fakeEngine) IncrementEpoch() {
	e.mu.Lock()
	e.n++
	e.mu.Unlock()
}

func (e *fakeEngine) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}

// TestArmDisarmDoesNotFire is the ordinary path: a call that returns before the
// timeout must leave every engine untouched. A watchdog that fired anyway would
// trap healthy calls.
func TestArmDisarmDoesNotFire(t *testing.T) {
	e := &fakeEngine{}
	w := New(time.Minute, e)
	s := &fakeStore{}

	for i := 0; i < 3; i++ {
		w.Arm(s)
		w.Disarm()
	}
	if n := e.count(); n != 0 {
		t.Errorf("engine epoch incremented %d times on calls that returned in time", n)
	}
	// The deadline is set once per Arm, by the caller, before the call runs.
	if d, n := s.calls(); d != 1 || n != 3 {
		t.Errorf("SetEpochDeadline(%d) called %d times, want 1 and 3", d, n)
	}
}

// TestTimeoutFiresAndInterruptsEveryEngine covers the firing path.
//
// Every registered engine is incremented, not just the one the call belongs to:
// incrementing an idle engine is a no-op, and these harnesses run one call at a
// time, which is what makes not tracking ownership safe.
func TestTimeoutFiresAndInterruptsEveryEngine(t *testing.T) {
	e1, e2 := &fakeEngine{}, &fakeEngine{}
	w := New(10*time.Millisecond, e1, e2)
	s := &fakeStore{}

	w.Arm(s)
	// Simulate a call that overruns. The watchdog fires, then waits for the
	// disarm that follows the interrupt.
	deadline := time.After(2 * time.Second)
	for e1.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("watchdog did not fire within 2s")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	w.Disarm() // the disarm that follows an interrupted call

	if n := e2.count(); n != 1 {
		t.Errorf("second engine incremented %d times, want 1 — every registered "+
			"engine must be interrupted", n)
	}

	// The watchdog must be reusable after firing: the goroutine consumes the
	// post-interrupt disarm and returns to waiting, so the next Arm works.
	w.Arm(s)
	w.Disarm()
	if n := e1.count(); n != 1 {
		t.Errorf("engine incremented %d times after a clean call following an "+
			"interrupt, want 1", n)
	}
}

// TestWatchRegistersLate covers Watch, which exists because the harnesses build
// a second engine for fuel measurement partway through a run. An engine
// registered after New must still be interrupted.
func TestWatchRegistersLate(t *testing.T) {
	early := &fakeEngine{}
	w := New(10*time.Millisecond, early)
	late := &fakeEngine{}
	w.Watch(late)

	w.Arm(&fakeStore{})
	deadline := time.After(2 * time.Second)
	for late.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("a late-registered engine was never interrupted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	w.Disarm()
	if n := early.count(); n != 1 {
		t.Errorf("the engine registered at New was incremented %d times, want 1", n)
	}
}

// TestTimeoutEnvOverride covers Timeout's parsing, including the refusals.
//
// A malformed or non-positive value must fall back to the default rather than
// disable the watchdog: a zero timeout would fire instantly and trap every
// call, and a negative one is the same bug wearing a different sign.
func TestTimeoutEnvOverride(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{"unset", false, "", DefaultTimeout},
		{"empty", true, "", DefaultTimeout},
		{"valid", true, "5m", 5 * time.Minute},
		{"valid sub-second", true, "250ms", 250 * time.Millisecond},
		{"malformed", true, "not-a-duration", DefaultTimeout},
		{"zero", true, "0s", DefaultTimeout},
		{"negative", true, "-1s", DefaultTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("REGEXPED_WASM_TIMEOUT", tc.val)
			}
			if got := Timeout(); got != tc.want {
				t.Errorf("Timeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsTimeout separates the watchdog's own interruption from a genuine trap,
// which is what lets a harness report "this pattern hangs" rather than
// misattributing it to the pattern's semantics.
func TestIsTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"epoch interrupt", errors.New("wasm trap: interrupt"), true},
		{"interrupt in a longer message", errors.New("error while executing: interrupt at 0x1234"), true},
		{"unreachable", errors.New("wasm trap: wasm `unreachable` instruction executed"), false},
		{"out of fuel", errors.New("all fuel consumed by WebAssembly"), false},
		{"unrelated", errors.New("failed to instantiate"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTimeout(tc.err); got != tc.want {
				t.Errorf("IsTimeout(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestNewWithNoEngines pins that a watchdog with nothing registered is inert
// rather than a panic: New's variadic makes it easy to build one, and firing
// over an empty slice must be a no-op.
func TestNewWithNoEngines(t *testing.T) {
	w := New(10 * time.Millisecond)
	w.Arm(&fakeStore{})
	time.Sleep(50 * time.Millisecond) // let the timer fire over zero engines
	w.Disarm()
}
