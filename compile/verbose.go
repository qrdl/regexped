package compile

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/qrdl/regexped/config"
)

// ── Verbose compile reporting ──────────────────────────
//
// Every interesting decision this compiler makes is otherwise invisible. Two
// of them are outcomes a user has to act on and cannot currently see:
//
//   - a pattern over max_dfa_states silently becomes a BACKTRACKING pattern,
//     which carries a frame budget and is the only engine that can return the
//     "result unknown" sentinel a host must handle. The remedy — raise the
//     limit — requires knowing it happened;
//   - a pattern whose fallback DFA exceeds max_fallback_states is DROPPED from
//     its set, and a set that does not contain a pattern does not report its
//     matches.
//
// This is deliberately NOT --debug. That flag raises the slog level and exists
// to diagnose the COMPILER; this reports on the user's PATTERNS, and its output
// is a table rather than key=value lines.
//
// Every method is nil-safe, so the compile path calls them unconditionally and
// pays one nil check when reporting is off.

// PatternReport is what the compiler decided about one pattern.
type PatternReport struct {
	Name    string
	Pattern string
	// Expanded is the regexp a pattern written with references stands for,
	// in full; "" for one that used none (config.ExpandReferences).
	Expanded string
	// Mode is "byte" or "unicode": the mode the pattern was compiled in, or
	// asked for when it was refused for it.
	Mode   string
	Engine EngineType
	// Reason names the gate that decided, not just the outcome.
	Reason string
	// Limits carries "what was measured against what", so "1030 of 1024" is
	// visible rather than only the demotion it caused.
	Limits []string
	// Notes are optimisations that fired.
	Notes []string

	// The structured record behind the brief report (report.go), each field
	// set where the emitter that decides it runs.
	//
	// Exports are the export kinds the entry declares, in the order match,
	// find, groups.
	Exports []string
	// Find is the find kind (findKind*) and FindWhy the reason the classifier
	// gave; SwitchTo is what a "switch" find hands over to.
	Find, FindWhy, SwitchTo string
	// scans are the scan strategies the find bodies recorded, each with the
	// index of its note so a discarded body's scan is dropped with its note.
	scans []scanRecord
	// Search is what one search of the find and groups exports keeps in the
	// caller's per-search block (search_notes.go).
	Search SearchSize
	// bt are the pattern's Backtracking bodies, for their run-time scratch.
	bt []btBodyReport
	// TableBytes is the bytes of data the module carries in the pattern's
	// table range [tableStart, tableEnd); CodeBytes its function bodies'
	// bytes (wrappers excluded). Both are filled once the module is assembled.
	TableBytes           int64
	CodeBytes            int
	tableStart, tableEnd int64
}

// Reporter accumulates per-pattern decisions and per-set diagnostics.
type Reporter struct {
	cur      *PatternReport
	Patterns []PatternReport
	Sets     []SetDiag
	// Backtracking: the assembled module carries Backtracking code — a
	// pattern on that engine, a find whose switch hands over to it, or a set
	// member on it — whose memory grows with the input (WarnUnboundedMemory).
	Backtracking bool
	// Progress, when set, receives a line from every construction that runs
	// long (progress.go). The CLI sets it to stderr; a library caller leaves
	// it nil and nothing is printed.
	Progress io.Writer
	// progressNow and progressAfter replace the clock and the delay (and
	// interval) in tests.
	progressNow   func() time.Time
	progressAfter time.Duration
	// sink is the progress sink of the compile in flight (startProgress),
	// which resolvePattern hands to the programs that compile builds.
	sink *progressSink

	// mod is what the report says about the module as a whole (report.go).
	mod moduleReport
	// setMem is each set's memory, in r.Sets' order (report.go).
	setMem map[string]setMemReport
}

// noteModule records what the assembled module carries that the CLI warns
// about. The fallback-scratch globals exist exactly when Backtracking code was
// emitted (bt_scratch.go), so they are the one test that sees every route in.
func (r *Reporter) noteModule(g *moduleGlobals) {
	if r == nil || g == nil {
		return
	}
	if _, ok := g.btScratchGlobals(); ok {
		r.Backtracking = true
	}
}

// WarnUnboundedMemory warns, once, when the module carries Backtracking code
// and the config sets no max_memory: that engine's frame stacks and fallback
// memo grow with the input, so without a cap an adversarial input can grow
// the module's memory until the host runs out of it. With a cap the search
// answers "unknown" (-2) instead. rep is the Reporter the compile filled.
func WarnUnboundedMemory(cfg config.BuildConfig, rep *Reporter) {
	if rep == nil || !rep.Backtracking || cfg.MaxMemory.IsSet() {
		return
	}
	slog.Warn("Backtracking engine selected and max_memory is not set: memory is not limited, possible out-of-memory on adversarial input",
		"hint", "set max_memory (for example `max_memory: 64MiB`): a search that would need more answers \"unknown\" (-2) instead of growing memory",
		"which", "`compile --verbose` names the patterns on Backtracking")
}

// Begin opens a per-pattern scope. Ending one that is already open flushes it,
// so a compile path that returns early cannot lose a record.
func (r *Reporter) Begin(name, pattern string) {
	if r == nil {
		return
	}
	r.End()
	r.cur = &PatternReport{Name: name, Pattern: pattern}
	if name != "" {
		r.progressSubject("pattern %q", name)
	} else {
		r.progressSubject("pattern %q", truncate(pattern, 40))
	}
}

// Expanded records the full text a pattern written with references expands to.
func (r *Reporter) Expanded(text string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Expanded = text
}

// Mode records the pattern's mode.
func (r *Reporter) Mode(mode string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Mode = mode
}

// Engine records the selected engine and the gate that chose it.
func (r *Reporter) Engine(e EngineType, reason string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Engine, r.cur.Reason = e, reason
}

// Limit records a measurement against the bound it was checked against.
func (r *Reporter) Limit(what string, got, limit int) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Limits = append(r.cur.Limits, fmt.Sprintf("%s %d of %d", what, got, limit))
}

// Note records an optimisation that fired.
func (r *Reporter) Note(note string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Notes = append(r.cur.Notes, note)
}

// noteMark is the number of notes the open scope holds, for truncateNotes.
func (r *Reporter) noteMark() int {
	if r == nil || r.cur == nil {
		return 0
	}
	return len(r.cur.Notes)
}

// truncateNotes drops the notes recorded since mark — for a body that was
// described and then replaced, so the report names only what was emitted.
func (r *Reporter) truncateNotes(mark int) {
	if r == nil || r.cur == nil || mark > len(r.cur.Notes) {
		return
	}
	r.cur.Notes = r.cur.Notes[:mark]
	kept := r.cur.scans[:0]
	for _, s := range r.cur.scans {
		if s.note < mark {
			kept = append(kept, s)
		}
	}
	r.cur.scans = kept
}

// HasEngine reports whether the open scope already knows its engine.
func (r *Reporter) HasEngine() bool {
	return r != nil && r.cur != nil && r.cur.Engine != 0
}

// Reason sets the outcome text without naming an engine, for the specialised
// bodies that never build one.
func (r *Reporter) Reason(reason string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Reason = reason
}

// hasReason reports whether the open pattern scope has a reason recorded.
func (r *Reporter) hasReason() bool {
	return r != nil && r.cur != nil && r.cur.Reason != ""
}

// setLastMode replaces the mode of the pattern reported last.
func (r *Reporter) setLastMode(mode string) {
	switch {
	case r == nil:
	case r.cur != nil:
		r.cur.Mode = mode
	case len(r.Patterns) > 0:
		r.Patterns[len(r.Patterns)-1].Mode = mode
	}
}

// End closes the current pattern scope.
func (r *Reporter) End() {
	if r == nil || r.cur == nil {
		return
	}
	r.Patterns = append(r.Patterns, *r.cur)
	r.cur = nil
}

func reportDrops(w io.Writer, label string, refs []PatternRef) {
	if len(refs) == 0 {
		return
	}
	names := make([]string, 0, len(refs))
	for _, p := range refs {
		if p.Name != "" {
			names = append(names, p.Name)
		} else {
			names = append(names, fmt.Sprintf("#%d", p.ID))
		}
	}
	fmt.Fprintf(w, "  %s: %s\n", label, strings.Join(names, ", "))
}

// truncate caps s at n BYTES, ending with an ellipsis when it has to cut.
//
// The cut is made on a rune boundary. Slicing by byte index splits a
// multi-byte rune and emits its lead byte alone, which is invalid UTF-8 going
// straight to the user's terminal: truncate("ααααα", 6) used to yield
// "αα\xce…". Patterns are arbitrary user input and byte_mode ones are not
// even text, so this is reachable rather than theoretical.
//
// n counts bytes because the caller is aligning a column, and the result is
// therefore at most n bytes — possibly fewer, when the boundary falls short.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	budget := n - len(ellipsis)
	if budget < 0 {
		return ellipsis
	}
	// Walk runes and keep the last boundary that still fits.
	cut := 0
	for i := range s {
		if i > budget {
			break
		}
		cut = i
	}
	return s[:cut] + ellipsis
}
