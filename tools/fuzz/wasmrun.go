package fuzz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
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
// Before BT stack overflow got its own sentinel this was indistinguishable
// from a genuine no-match, so the
// harness could not have skipped it even in principle — a long-input false
// negative would simply have been reported as an engine bug, or worse, matched
// the oracle by luck.
var errBTOverflow = errors.New("backtracking stack overflow (abi.BTStackOverflow)")

const (
	// tableBase is the WASM memory offset where DFA tables start. Test
	// input is written at offset 0, so any input at or past tableBase would
	// spill into table data — see inputCap in fuzz_targets_test.go.
	tableBase = int64(65536)

	wasmCallTimeout = 2 * time.Second
)

// compileFind compiles pat into a standalone WASM module exporting a single
// non-anchored find function, with no captures — the DFA/Compiled DFA find
// body (Layer 1's target).
func compileFind(pat string) ([]byte, error) {
	return cachedCompile("find\x00"+pat, func() ([]byte, error) {
		entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
		wasmBytes, _, err := compile.Compile([]config.RegexEntry{entry}, tableBase, true)
		return wasmBytes, err
	})
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
	// The input lives in page 0, below the tables.
	if err := setScratchBase(store, inst, int32(tableBase)); err != nil {
		return span, false, false, err
	}
	mem := memExp.Memory()

	if len(input) > 0 {
		buf := mem.UnsafeData(store)
		copy(buf, input) // inputBase = 0
	}

	wd.Arm(store)
	// find is (ptr, len, from); a one-shot find starts at 0.
	result, callErr := findFn.Call(store, int32(0), int32(len(input)), int32(0))
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

// setScratchBase tells a standalone module's Backtracking fallback the lowest
// address it may use as run-time scratch (abi.ScratchBaseExport): the first
// byte above everything the harness writes. Each runner sets it for its own
// layout — the single-pattern ones write below the tables, the set ones above
// them — because a value below live data is a wrong answer, where leaving it
// at 0 only costs fresh pages on every call that reaches the fallback. A module
// with no Backtracking program has no such global.
func setScratchBase(store *wasmtime.Store, inst *wasmtime.Instance, top int32) error {
	exp := inst.GetExport(store, abi.ScratchBaseExport)
	if exp == nil || exp.Global() == nil {
		return nil
	}
	if err := exp.Global().Set(store, wasmtime.ValI32(top)); err != nil {
		return fmt.Errorf("set %s: %w", abi.ScratchBaseExport, err)
	}
	return nil
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

// blockMode is how a find drive hands the per-search block over (docs/wasm.md,
// "The search block").
type blockMode int

const (
	blockNone  blockMode = iota // the search global left at 0: no counter, no notes
	blockFresh                  // as a generated stub: zeroed per drive, notes on arming
	blockArmed                  // armed before the first call: the MARKED copy answers every call
)

func (m blockMode) String() string {
	return [...]string{"no-block", "fresh-block", "armed-block"}[m]
}

// maxNotesBytes over-allocates the notes; the module checks their capacity.
const maxNotesBytes = 8

// searchRegion is one instance's block and notes, at the end of its memory,
// with the scratch base raised above them. nil when the module takes no block
// or the mode is blockNone; every method is a no-op on nil.
type searchRegion struct {
	global   *wasmtime.Global
	mem      *wasmtime.Memory
	mode     blockMode
	blk      int32
	notesCap int32
}

func newSearchRegion(store *wasmtime.Store, inst *wasmtime.Instance, mem *wasmtime.Memory, textLen int, mode blockMode) (*searchRegion, error) {
	if mode == blockNone {
		return nil, nil
	}
	exp := inst.GetExport(store, abi.SearchExport)
	if exp == nil || exp.Global() == nil {
		return nil, nil
	}
	capacity := int64(textLen+1) * maxNotesBytes
	at := (int64(mem.DataSize(store)) + 65535) &^ 65535
	need := at + abi.SearchBlockBytes + capacity
	if grow := (need - int64(mem.DataSize(store)) + 65535) / 65536; grow > 0 {
		if _, err := mem.Grow(store, uint64(grow)); err != nil {
			return nil, err
		}
	}
	if err := setScratchBase(store, inst, int32((need+65535)&^65535)); err != nil {
		return nil, err
	}
	return &searchRegion{global: exp.Global(), mem: mem, mode: mode, blk: int32(at), notesCap: int32(capacity)}, nil
}

// begin starts a drive: a zeroed block, armed with notes under blockArmed.
func (s *searchRegion) begin(store *wasmtime.Store) {
	if s == nil {
		return
	}
	buf := s.mem.UnsafeData(store)
	clear(buf[s.blk : s.blk+abi.SearchBlockBytes])
	if s.mode == blockArmed {
		binary.LittleEndian.PutUint32(buf[s.blk+abi.SearchArmedOff:], 1)
		s.giveNotes(buf)
	}
}

func (s *searchRegion) giveNotes(buf []byte) {
	notes := s.blk + abi.SearchBlockBytes
	clear(buf[notes : notes+s.notesCap])
	binary.LittleEndian.PutUint32(buf[s.blk+abi.SearchNotesOff:], uint32(notes))
	binary.LittleEndian.PutUint32(buf[s.blk+abi.SearchNotesCapOff:], uint32(s.notesCap))
}

// before hands the block over for the next call.
func (s *searchRegion) before(store *wasmtime.Store) {
	if s != nil {
		_ = s.global.Set(store, wasmtime.ValI32(s.blk))
	}
}

// after runs after a call that reported a match: an armed search gets notes.
func (s *searchRegion) after(store *wasmtime.Store) {
	if s == nil {
		return
	}
	buf := s.mem.UnsafeData(store)
	if binary.LittleEndian.Uint32(buf[s.blk+abi.SearchArmedOff:]) != 0 &&
		binary.LittleEndian.Uint32(buf[s.blk+abi.SearchNotesOff:]) == 0 {
		s.giveNotes(buf)
	}
}
