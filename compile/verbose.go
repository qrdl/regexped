package compile

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
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
	// Memory is what a search costs PER INPUT BYTE in working memory, for a
	// Unicode-mode pattern, whose lowered programs make those costs large
	// enough to matter before they are paid: "per-search notes 13 B per input
	// byte, once a search arms".
	Memory []string
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
		progressSubject("pattern %q", name)
	} else {
		progressSubject("pattern %q", truncate(pattern, 40))
	}
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

// Memory records what one of the pattern's searches costs per input byte.
func (r *Reporter) Memory(what string, perByte int, when string) {
	if r == nil || r.cur == nil {
		return
	}
	r.cur.Memory = append(r.cur.Memory, fmt.Sprintf("%s %d B per input byte, %s", what, perByte, when))
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

// End closes the current pattern scope.
func (r *Reporter) End() {
	if r == nil || r.cur == nil {
		return
	}
	r.Patterns = append(r.Patterns, *r.cur)
	r.cur = nil
}

// Render writes the human-readable report.
func (r *Reporter) Render(w io.Writer) {
	if r == nil || w == nil {
		return
	}
	r.End()
	if len(r.Patterns) > 0 {
		fmt.Fprintf(w, "\nPatterns (%d)\n", len(r.Patterns))
		for _, p := range r.Patterns {
			name := p.Name
			if name == "" {
				name = "(unnamed)"
			}
			fmt.Fprintf(w, "  %-20s %s\n", name, truncate(p.Pattern, 60))
			if p.Mode != "" {
				fmt.Fprintln(w, "    mode:   "+p.Mode)
			}
			if p.Engine == 0 {
				// No general engine. Either a specialised body was emitted
				// instead — the literal-chain family never builds one — or the
				// entry contributes no exported function at all. Reason
				// distinguishes them; saying the wrong one is exactly the
				// class of error the SelectEngine fallback made.
				what := "none"
				if p.Reason != "" {
					what = p.Reason
				}
				fmt.Fprintln(w, "    engine: "+what)
			} else {
				line := "    engine: " + p.Engine.String()
				if p.Reason != "" {
					line += " — " + p.Reason
				}
				fmt.Fprintln(w, line)
			}
			for _, l := range p.Limits {
				fmt.Fprintf(w, "    limit:  %s\n", l)
			}
			for _, m := range p.Memory {
				fmt.Fprintf(w, "    memory: %s\n", m)
			}
			if len(p.Notes) > 0 {
				sort.Strings(p.Notes)
				fmt.Fprintf(w, "    opts:   %s\n", strings.Join(p.Notes, ", "))
			}
		}
	}
	for _, d := range r.Sets {
		fmt.Fprintf(w, "\nSet %q\n", d.Name)
		if d.Mode != "" {
			fmt.Fprintf(w, "  mode:       %s\n", d.Mode)
		}
		fmt.Fprintf(w, "  frontend:   %s\n", d.Frontend)
		if len(d.Capabilities) > 0 {
			fmt.Fprintf(w, "  capabilities: %s\n", strings.Join(d.Capabilities, ", "))
		}
		if d.Overlapping {
			fmt.Fprintln(w, "  overlapping: true")
		}
		fmt.Fprintf(w, "  buckets:    %d\n", len(d.Buckets))
		for _, b := range d.Buckets {
			lit := b.Literal
			if lit == "" {
				lit = "(fallback — no literal)"
			}
			// The engine is printed because a Backtracking bucket otherwise
			// reads exactly like a DFA fallback bucket here, and the switch is
			// not free: one such member measured up to 2.2x the fuel of a
			// 16-pattern set's scan_any, scan_all and find (docs/sets.md). It
			// also moves the set's _all pair to the out_ptr form.
			engine := "DFA"
			if b.Type == "bt-fallback" {
				engine = "Backtracking"
			}
			fmt.Fprintf(w, "    #%-3d %-24s %-8s %-12s %2d pattern(s)  %d states  %d bytes\n",
				b.ID, truncate(lit, 24), b.AcceptKind, engine, len(b.Patterns), b.SuffixStates, b.TableBytes)
		}
		// The drops are the whole reason a user needs this: a set that does not
		// contain a pattern does not report its matches, and today that is
		// silent.
		// Four lines, two scopes, never merged. The first TWO cost the
		// pattern EVERY capability; the last two cost it match_any/match_all
		// only, and it still answers on scan_any, scan_all and find. A reader
		// who cannot tell the scopes apart cannot tell "gone from the set"
		// from "gone from two of the five exports".
		reportDrops(w, "dropped (fallback DFA over max_fallback_states)", d.StateLimitDropped)
		reportDrops(w, "dropped (capture-bearing)", d.CaptureBearingDropped)
		reportDrops(w, "dropped from match_any/match_all (anchored DFA over the packer's limits)",
			d.AnchoredStateLimitDropped)
		reportDrops(w, "dropped from match_any/match_all (unparseable)", d.UnparseableDropped)
		if d.IDSpaceSize != len(d.Buckets) && d.IDSpaceSize > 0 {
			fmt.Fprintf(w, "  id space:   %d\n", d.IDSpaceSize)
		}
		if d.FrontendDemotion != nil {
			fmt.Fprintf(w, "  DOWNGRADED frontend: %+v\n", *d.FrontendDemotion)
		}
		// Members served outside the buckets, and the work counters: each
		// changes the set's cost by large factors and shows nowhere else.
		if len(d.SplitMembers) > 0 {
			bt := map[int]bool{}
			for _, id := range d.SplitBacktracking {
				bt[id] = true
			}
			ids := make([]string, len(d.SplitMembers))
			for i, id := range d.SplitMembers {
				ids[i] = fmt.Sprintf("#%d", id)
				if bt[id] {
					ids[i] += " (Backtracking)"
				}
			}
			fmt.Fprintf(w, "  split out (not provably linear; own linear search): %s\n", strings.Join(ids, ", "))
		}
		if u := d.ScanUnion; u != nil {
			switch {
			case u.Direct:
				fmt.Fprintf(w, "  scan pair: one union automaton over every member (%d states)\n", u.States)
			case u.Counter:
				fmt.Fprintf(w, "  scan pair: work counter switching to a union automaton (%d states)\n", u.States)
			}
		}
		if d.InCallCounter {
			fmt.Fprintf(w, "  overlapping find: in-call counter sweeps the answer cache\n")
		}
		if s := d.WholeSetSweep; s != nil {
			fmt.Fprintf(w, "  overlapping find: the answer cache sweeps a whole-set automaton (%d states, %d cells)\n", s.States, s.Cells)
		}
		if n := d.CacheBytesPerByte; n > 0 {
			fmt.Fprintf(w, "  memory:     answer cache %d B per input byte, to 64 MiB; the square root of the input past it\n", n)
		}
		if len(d.NoCacheSplitMembers) > 0 {
			bt := map[int]bool{}
			for _, id := range d.NoCacheSplitBacktracking {
				bt[id] = true
			}
			ids := make([]string, len(d.NoCacheSplitMembers))
			for i, id := range d.NoCacheSplitMembers {
				ids[i] = fmt.Sprintf("#%d", id)
				if bt[id] {
					ids[i] += " (Backtracking)"
				}
			}
			fmt.Fprintf(w, "  overlapping find without a usable cache: companion splits out %s\n", strings.Join(ids, ", "))
		}
	}
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
