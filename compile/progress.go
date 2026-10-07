package compile

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ── Compile progress ──────────────────────────────────────────────────────
//
// Some compiles are long — a Unicode-mode set's union automaton measured
// 173 s, a 2,038-state TDFA 2 min 16 s — and compile time is accepted as the
// price of a faster module. What is not acceptable is a compiler that says
// nothing for minutes, so a user cannot tell it is working. A construction
// that has run past progressAfter prints a line on the CLI's stderr, and
// another every progressEvery after that, naming what it is compiling, the
// step, the states built so far against their limit, and the time spent:
//
//	regexped: compiling set "s": DFA construction, 12400 of 16384 states (38 s)
//
// A fast compile prints nothing. Only the CLI's entry points turn it on
// (Reporter.Progress); a library call such as Compile or CompileFile never
// prints. It is output only: the emitted module does not change.

// progressSink is where an active compile's progress lines go.
type progressSink struct {
	w            io.Writer
	now          func() time.Time
	after, every time.Duration
	subject      atomic.Pointer[string] // what is being compiled: `pattern "x"`, `set "s"`
}

// activeProgress is the progress sink of the compile in flight, nil when none
// asked for one. A construction loop cannot be handed it — newDFAImpl and
// newTDFA are called from dozens of sites — so it is found here.
var activeProgress atomic.Pointer[progressSink]

const (
	progressAfter = 5 * time.Second
	progressEvery = 5 * time.Second
)

// startProgress makes r's progress writer the active sink for one compile
// and returns what ends it. A nil r, or one with no Progress writer, starts
// nothing.
func (r *Reporter) startProgress() (end func()) {
	if r == nil || r.Progress == nil {
		return func() {}
	}
	s := &progressSink{w: r.Progress, now: r.progressNow, after: progressAfter, every: progressEvery}
	if s.now == nil {
		s.now = time.Now
	}
	if r.progressAfter > 0 {
		s.after, s.every = r.progressAfter, r.progressAfter
	}
	subject := "patterns"
	s.subject.Store(&subject)
	prev := activeProgress.Swap(s)
	return func() { activeProgress.Store(prev) }
}

// progressSubject names what the active compile is working on now.
func progressSubject(format string, args ...any) {
	if s := activeProgress.Load(); s != nil {
		subject := fmt.Sprintf(format, args...)
		s.subject.Store(&subject)
	}
}

// progressStep is one long-running construction.
type progressStep struct {
	s     *progressSink
	step  string
	start time.Time
	next  time.Time
	calls int
}

// startProgressStep begins step, or returns nil when no sink is active; every
// method is nil-safe, so a construction loop calls tick unconditionally.
func startProgressStep(step string) *progressStep {
	s := activeProgress.Load()
	if s == nil {
		return nil
	}
	now := s.now()
	return &progressStep{s: s, step: step, start: now, next: now.Add(s.after)}
}

// tick reports the states built so far, of limit, once the step is due. The
// clock is read once every 64 calls.
func (p *progressStep) tick(states, limit int) {
	if p == nil {
		return
	}
	p.calls++
	if p.calls%64 != 0 {
		return
	}
	now := p.s.now()
	if now.Before(p.next) {
		return
	}
	p.next = now.Add(p.s.every)
	fmt.Fprintf(p.s.w, "regexped: compiling %s: %s, %d of %d states so far (%d s)\n",
		*p.s.subject.Load(), p.step, states, limit, int(now.Sub(p.start)/time.Second))
}
