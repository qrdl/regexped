package fuzz

// The compile child. During a fuzz run, a compile that runs under the input's
// budget (budgeted) runs in a helper process — this test binary started again
// with compileChildEnv set — instead of in the worker, so a compile past the
// budget can be KILLED. In-process, a goroutine the worker stopped waiting for
// kept compiling to its end: a 36 s Unicode set compile cost 36 s of CPU
// however early it was given up, and every input meanwhile was skipped. The
// child is started once per worker and reused, because a start costs ~3.3 ms
// and the byte-mutation targets compile ~37 times a second per worker; it is
// started again only after a kill. It keeps no state between jobs: the worker's
// caches stay the only caches.
//
// A job is the compile a cache helper used to run as a closure, as DATA
// (compileJob), so the child can run it: run() is the one place each kind's
// compile call is written, and the in-process path calls it too, so the two
// cannot compile different things. What a job carries of compile.CompileOptions
// is jobOpts, and toJobOpts refuses an option it does not carry rather than
// dropping it. A child that dies by itself — a regexped panic, an OOM kill — is
// a FAILURE: childRun panics with the child's own output, as the panic would
// have crashed the worker in-process. Only a child this process killed is a
// compile that was too slow.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/searchblock"
)

// compileChildEnv, set to "1", makes this binary serve compile jobs on fds 3
// and 4 instead of running tests (see init).
const compileChildEnv = "REGEXPED_FUZZ_COMPILE_CHILD"

func init() {
	if os.Getenv(compileChildEnv) == "1" {
		serveCompileChild()
		os.Exit(0)
	}
}

// jobKind is which compile call a compileJob makes.
type jobKind uint8

const (
	jobSized    jobKind = iota + 1 // compile.CompileWithSearchSizes, sizes of Export
	jobCompile                     // compile.Compile (no options at all with NoOpts)
	jobForced                      // compile.CompileForced
	jobFile                        // compile.CompileFile, or CompileFileOpts with SweepBudget
	jobFileDiag                    // compile.CompileFileDiag, with the set's drops
	jobSelect                      // compile.SelectEngine
	jobShape                       // compile.SetOverlapCacheShape
	jobWarm                        // nothing to compile: only the wasmtime build of Wasm
	jobCrash                       // tests only: the child panics
)

// compileJob is one compile, as data. Only the fields its Kind reads are set.
type compileJob struct {
	Kind        jobKind
	Entries     []config.PatternEntry
	Config      config.BuildConfig
	Set         config.SetConfig
	Base        int64
	Engine      compile.EngineType
	Opts        jobOpts
	NoOpts      bool
	SweepBudget int64
	Export      string
	Pattern     string
	// Wasm is jobWarm's module.
	Wasm []byte
	// Warm asks the child to build the compiled module with wasmtime too and
	// return it serialized, so a module too slow for Cranelift is killed with
	// the compile.
	Warm bool
}

// jobOpts is the part of compile.CompileOptions a job carries: every exported
// field the harness can set by value. Report, the component maps and
// MaxMemory are not carried; toJobOpts refuses options that set them.
type jobOpts struct {
	Component                                        bool
	ComponentPackage                                 string
	MaxDFAStates, MaxTDFARegs, MaxDFAMemory          int
	MaxBTInstructions                                int
	ByteMode, Unicode, ForceByteMode, LeftmostFirst  bool
	ForceEngine                                      compile.EngineType
	LikelyMode                                       compile.LikelyMode
	CompiledDFAThreshold, BTWorkBudget, BTStackStart int
	KeepUnreadTables, TodayFind, StartAnywhereFind   bool
	StartAnywhereSwitchN                             int
}

// toJobOpts is o as a job carries it. It panics when o sets anything jobOpts
// does not carry: a job compiled without it would test a different module
// from the one the caller asked for, silently.
func toJobOpts(o compile.CompileOptions) jobOpts {
	j := jobOpts{
		Component: o.Component, ComponentPackage: o.ComponentPackage,
		MaxDFAStates: o.MaxDFAStates, MaxTDFARegs: o.MaxTDFARegs, MaxDFAMemory: o.MaxDFAMemory,
		MaxBTInstructions: o.MaxBTInstructions,
		ByteMode:          o.ByteMode, Unicode: o.Unicode, ForceByteMode: o.ForceByteMode, LeftmostFirst: o.LeftmostFirst,
		ForceEngine: o.ForceEngine, LikelyMode: o.LikelyMode,
		CompiledDFAThreshold: o.CompiledDFAThreshold, BTWorkBudget: o.BTWorkBudget, BTStackStart: o.BTStackStart,
		KeepUnreadTables: o.KeepUnreadTables, TodayFind: o.TodayFind, StartAnywhereFind: o.StartAnywhereFind,
		StartAnywhereSwitchN: o.StartAnywhereSwitchN,
	}
	if !reflect.DeepEqual(j.options(), o) {
		panic(fmt.Sprintf("tools/fuzz: compile options the compile child does not carry: %+v", o))
	}
	return j
}

// options is j back as compile.CompileOptions.
func (j jobOpts) options() compile.CompileOptions {
	return compile.CompileOptions{
		Component: j.Component, ComponentPackage: j.ComponentPackage,
		MaxDFAStates: j.MaxDFAStates, MaxTDFARegs: j.MaxTDFARegs, MaxDFAMemory: j.MaxDFAMemory,
		MaxBTInstructions: j.MaxBTInstructions,
		ByteMode:          j.ByteMode, Unicode: j.Unicode, ForceByteMode: j.ForceByteMode, LeftmostFirst: j.LeftmostFirst,
		ForceEngine: j.ForceEngine, LikelyMode: j.LikelyMode,
		CompiledDFAThreshold: j.CompiledDFAThreshold, BTWorkBudget: j.BTWorkBudget, BTStackStart: j.BTStackStart,
		KeepUnreadTables: j.KeepUnreadTables, TodayFind: j.TodayFind, StartAnywhereFind: j.StartAnywhereFind,
		StartAnywhereSwitchN: j.StartAnywhereSwitchN,
	}
}

// compileResult is what a job produced. Over the pipe the error travels as
// Err and the compile sentinels it matched (ErrIs, indices into
// compileSentinels); in-process it stays the compiler's own error value.
type compileResult struct {
	Wasm                    []byte
	Sizes                   []searchblock.Size
	DropsAll, DropsAnchored map[int]bool
	Engine                  compile.EngineType
	Shape                   compile.OverlapCacheShape
	// Module is Wasm built by wasmtime and serialized (Warm), nil when the
	// build failed: instantiate then builds it again and reports the error.
	Module []byte
	HasErr bool
	Err    string
	ErrIs  []int
}

// compileSentinels is every error the compiler exports for errors.Is; a
// child's error matches the same ones in the worker (childError).
var compileSentinels = []error{
	compile.ErrBTProgramTooLarge, compile.ErrBTStackTooLarge, compile.ErrDFAStateLimit,
	compile.ErrFunctionTooLarge, compile.ErrMemoryCapTooSmall, compile.ErrNoCaptureGroup,
	compile.ErrSetMemberFitsNoEngine, compile.ErrTablesOutOfRange,
}

// childError is a compile error that crossed the pipe: the same message, and
// errors.Is true for the same sentinels.
type childError struct {
	msg string
	is  []error
}

func (e *childError) Error() string { return e.msg }

func (e *childError) Is(target error) bool {
	for _, s := range e.is {
		if s == target {
			return true
		}
	}
	return false
}

// run compiles j in this process: the one place each kind's compile call is
// written, for the in-process path and the child alike.
func (j compileJob) run() (compileResult, error) {
	var (
		r   compileResult
		err error
	)
	switch j.Kind {
	case jobSized:
		var sizes map[string]compile.SearchSize
		r.Wasm, _, sizes, err = compile.CompileWithSearchSizes(j.Entries, j.Base, true, j.Engine, j.Opts.options())
		r.Sizes = searchblock.Of(sizes[j.Export])
	case jobCompile:
		if j.NoOpts {
			r.Wasm, _, err = compile.Compile(j.Entries, j.Base, true)
		} else {
			r.Wasm, _, err = compile.Compile(j.Entries, j.Base, true, j.Opts.options())
		}
	case jobForced:
		r.Wasm, _, err = compile.CompileForced(j.Entries, j.Base, true, j.Engine, j.Opts.options())
	case jobFile:
		if j.SweepBudget > 0 {
			r.Wasm, _, _, err = compile.CompileFileOpts(j.Config, "", compile.CompileSetOptions{}.WithSweepBudget(j.SweepBudget))
		} else {
			r.Wasm, _, err = compile.CompileFile(j.Config, "")
		}
	case jobFileDiag:
		var diags []compile.SetDiag
		r.Wasm, _, diags, err = compile.CompileFileDiag(j.Config, "")
		d := dropsFromSet(diags)
		r.DropsAll, r.DropsAnchored = d.all, d.anchored
	case jobSelect:
		r.Engine, err = compile.SelectEngine(j.Pattern, j.Opts.options())
	case jobShape:
		r.Shape, err = compile.SetOverlapCacheShape(j.Set, j.Config)
	case jobWarm:
		r.Wasm = j.Wasm
	case jobCrash:
		panic("tools/fuzz: jobCrash, a compile child that dies by itself")
	default:
		panic(fmt.Sprintf("tools/fuzz: unknown compile job kind %d", j.Kind))
	}
	return r, err
}

// drops is r's drops as the cache keeps them: never nil maps, as
// dropsFromSet builds them, whether or not they crossed the pipe.
func (r compileResult) drops() setDrops {
	d := setDrops{all: r.DropsAll, anchored: r.DropsAnchored}
	if d.all == nil {
		d.all = map[int]bool{}
	}
	if d.anchored == nil {
		d.anchored = map[int]bool{}
	}
	return d
}

// serveCompileChild is the child: jobs in on fd 3, results out on fd 4,
// until the worker closes the pipe or goes away.
func serveCompileChild() {
	// A worker killed by Go's fuzz engine cannot close the pipe for a child in
	// the middle of a compile; the parent-death signal (setChildDeathSignal)
	// kills the child on Linux, and this catches a parent gone anywhere.
	ppid := os.Getppid()
	go func() {
		for {
			time.Sleep(200 * time.Millisecond)
			if os.Getppid() != ppid {
				os.Exit(0)
			}
		}
	}()
	dec := json.NewDecoder(bufio.NewReader(os.NewFile(3, "compile-jobs")))
	enc := json.NewEncoder(os.NewFile(4, "compile-results"))
	for {
		var j compileJob
		if dec.Decode(&j) != nil {
			return
		}
		r, err := j.run()
		if err != nil {
			r.HasErr, r.Err = true, err.Error()
			for k, s := range compileSentinels {
				if errors.Is(err, s) {
					r.ErrIs = append(r.ErrIs, k)
				}
			}
		} else if j.Warm {
			r.Module = buildSerialized(r.Wasm)
		}
		if j.Kind == jobWarm {
			r.Wasm = nil // the worker has it
		}
		if enc.Encode(r) != nil {
			return
		}
	}
}

// buildSerialized is wasm built by wasmtime with the shared engine and
// serialized, or nil when either fails.
func buildSerialized(wasm []byte) []byte {
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil
	}
	defer mod.Close()
	b, err := mod.Serialize()
	if err != nil {
		return nil
	}
	return b
}

// childErr is r's error in the worker, nil when the job succeeded.
func (r compileResult) childErr() error {
	if !r.HasErr {
		return nil
	}
	e := &childError{msg: r.Err}
	for _, k := range r.ErrIs {
		e.is = append(e.is, compileSentinels[k])
	}
	return e
}

// compileChild is the worker's handle on its child.
type compileChild struct {
	cmd  *exec.Cmd
	jobs *os.File
	dec  *json.Decoder
	out  *tailWriter
}

var (
	childMu    sync.Mutex
	theChild   *compileChild
	childStart = startCompileChild // a test replaces it to count starts
)

// startCompileChild starts this binary again as a compile child.
func startCompileChild() *compileChild {
	exe, err := os.Executable()
	if err != nil {
		panic("tools/fuzz: compile child: " + err.Error())
	}
	jobsR, jobsW, err := os.Pipe()
	if err != nil {
		panic("tools/fuzz: compile child: " + err.Error())
	}
	resR, resW, err := os.Pipe()
	if err != nil {
		panic("tools/fuzz: compile child: " + err.Error())
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), compileChildEnv+"=1")
	cmd.ExtraFiles = []*os.File{jobsR, resW} // fds 3 and 4 in the child
	out := &tailWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	setChildDeathSignal(cmd)
	if err := cmd.Start(); err != nil {
		panic("tools/fuzz: compile child: " + err.Error())
	}
	jobsR.Close()
	resW.Close()
	return &compileChild{cmd: cmd, jobs: jobsW, dec: json.NewDecoder(bufio.NewReader(resR)), out: out}
}

// childRun runs j in the child, waiting at most wait. A child that does not
// answer in time is killed — the compile was too slow (errCompileTooSlow) —
// and the next job starts a new one. Any other error is the compile's own.
func childRun(j compileJob, wait time.Duration) (compileResult, error) {
	childMu.Lock()
	defer childMu.Unlock()
	if theChild == nil {
		theChild = childStart()
	}
	c := theChild
	msg := encodeJob(j)
	if _, err := c.jobs.Write(msg); err != nil {
		c.died(err)
	}
	type reply struct {
		r   compileResult
		err error
	}
	got := make(chan reply, 1)
	go func() {
		var r compileResult
		err := c.dec.Decode(&r)
		got <- reply{r, err}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case rep := <-got:
		if rep.err != nil {
			c.died(rep.err)
		}
		return rep.r, rep.r.childErr()
	case <-timer.C:
		c.cmd.Process.Kill()
		<-got
		c.cmd.Wait()
		c.jobs.Close()
		theChild = nil
		return compileResult{}, errCompileTooSlow
	}
}

// encodeJob is j as the child reads it: one line of JSON. It panics when the
// child would read a different job — a field JSON cannot carry, such as an
// unexported one the harness set — since the child would then compile a
// different module from the one asked for, silently. JSON and not gob: gob
// drops a pointer to a zero value — a set's `Unicode: &false` (byte mode)
// would arrive as nil, mode not stated — and refuses config.MemorySize, a
// struct with no exported field, outright.
func encodeJob(j compileJob) []byte {
	b, err := json.Marshal(j)
	if err != nil {
		panic("tools/fuzz: compile job: " + err.Error())
	}
	if j.Kind != jobWarm { // a warm job is its module's bytes and nothing else
		var back compileJob
		if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, j) {
			panic(fmt.Sprintf("tools/fuzz: the compile child would not read this job as written: %+v", j))
		}
	}
	return append(b, '\n')
}

// died reports a child that went away by itself — the worker did not kill it
// — as the failure it is, with what the child wrote.
func (c *compileChild) died(cause error) {
	c.jobs.Close()
	c.cmd.Process.Kill() // a child that answered garbage may still be running
	werr := c.cmd.Wait()
	theChild = nil
	panic(fmt.Sprintf("tools/fuzz: the compile child died (%v; %v); its output:\n%s", cause, werr, c.out.String()))
}

// tailWriter keeps the last max bytes written to it.
type tailWriter struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if over := w.buf.Len() - w.max; over > 0 {
		w.buf.Next(over)
	}
	return len(p), nil
}

func (w *tailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
