package compile

import (
	"fmt"
	"io"
	"sort"
	"strings"
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
	Engine  EngineType
	// Reason names the gate that decided, not just the outcome.
	Reason string
	// Limits carries "what was measured against what", so "1030 of 1024" is
	// visible rather than only the demotion it caused.
	Limits []string
	// Notes are optimisations that fired.
	Notes []string
}

// Reporter accumulates per-pattern decisions and per-set diagnostics.
type Reporter struct {
	cur      *PatternReport
	Patterns []PatternReport
	Sets     []SetDiag
}

// Begin opens a per-pattern scope. Ending one that is already open flushes it,
// so a compile path that returns early cannot lose a record.
func (r *Reporter) Begin(name, pattern string) {
	if r == nil {
		return
	}
	r.End()
	r.cur = &PatternReport{Name: name, Pattern: pattern}
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
			if len(p.Notes) > 0 {
				sort.Strings(p.Notes)
				fmt.Fprintf(w, "    opts:   %s\n", strings.Join(p.Notes, ", "))
			}
		}
	}
	for _, d := range r.Sets {
		fmt.Fprintf(w, "\nSet %q\n", d.Name)
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
			fmt.Fprintf(w, "    #%-3d %-24s %-8s %2d pattern(s)  %d states  %d bytes\n",
				b.ID, truncate(lit, 24), b.AcceptKind, len(b.Patterns), b.SuffixStates, b.TableBytes)
		}
		// The drops are the whole reason a user needs this: a set that does not
		// contain a pattern does not report its matches, and today that is
		// silent.
		reportDrops(w, "dropped (fallback DFA over max_fallback_states)", d.StateLimitDropped)
		reportDrops(w, "dropped (capture-bearing)", d.CaptureBearingDropped)
		reportDrops(w, "dropped (unparseable)", d.UnparseableDropped)
		if d.IDSpaceSize != len(d.Buckets) && d.IDSpaceSize > 0 {
			fmt.Fprintf(w, "  id space:   %d\n", d.IDSpaceSize)
		}
		if d.FrontendDemotion != nil {
			fmt.Fprintf(w, "  DOWNGRADED frontend: %+v\n", *d.FrontendDemotion)
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
