package compile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── The --verbose reporter ─────────────────────────────────────────────────
//
// This is the only output that tells a user their pattern was DEMOTED to
// Backtracking by a state limit, or DROPPED from a set entirely. A dropped
// pattern is the expensive one: a set that does not contain a pattern does not
// report its matches, and nothing else says so.
//
// It is pure formatting over structs, so it is exactly testable — and it was
// almost entirely uncovered, because the unit tests never pass --verbose and
// the harnesses that do never assert on what it prints.

// TestReporterNilSafety pins the contract the compile path depends on: every
// method is nil-safe, so the emitters call them unconditionally and pay one
// nil check when reporting is off. A panic here is a panic in every compile
// that does NOT ask for a report.
func TestReporterNilSafety(t *testing.T) {
	var r *Reporter // nil
	r.Begin("n", "p")
	r.Engine(EngineDFA, "why")
	r.Limit("states", 1, 2)
	r.Note("note")
	r.Reason("reason")
	r.End()
	r.Render(&bytes.Buffer{})
	if r.HasEngine() {
		t.Error("nil Reporter reports HasEngine")
	}

	// Non-nil but with no scope open: same requirement, different branch.
	r2 := &Reporter{}
	r2.Engine(EngineDFA, "why")
	r2.Limit("states", 1, 2)
	r2.Note("note")
	r2.Reason("reason")
	r2.End()
	if r2.HasEngine() {
		t.Error("Reporter with no open scope reports HasEngine")
	}
	if len(r2.Patterns) != 0 {
		t.Errorf("closing an unopened scope recorded %d patterns", len(r2.Patterns))
	}
	// Render on an empty reporter must produce nothing at all, not a header.
	var b bytes.Buffer
	r2.Render(&b)
	if b.Len() != 0 {
		t.Errorf("empty Reporter rendered %q, want nothing", b.String())
	}
	// A nil writer is tolerated too.
	r2.Render(nil)
}

// TestReporterBeginFlushesOpenScope pins the property Begin's comment promises:
// a compile path that returns early between two Begins must not LOSE the first
// record. That is the whole reason Begin calls End.
func TestReporterBeginFlushesOpenScope(t *testing.T) {
	r := &Reporter{}
	r.Begin("first", "a+")
	r.Engine(EngineDFA, "no captures")
	r.Begin("second", "b+") // no End between them
	r.Engine(EngineBacktrack, "captures")
	r.End()
	if len(r.Patterns) != 2 {
		t.Fatalf("got %d patterns, want 2 — an open scope was dropped", len(r.Patterns))
	}
	if r.Patterns[0].Name != "first" || r.Patterns[1].Name != "second" {
		t.Errorf("scopes recorded out of order: %q, %q",
			r.Patterns[0].Name, r.Patterns[1].Name)
	}
}

// TestReporterHasEngine covers the predicate compilePattern uses to decide
// whether a later, more specific gate already named the engine.
func TestReporterHasEngine(t *testing.T) {
	r := &Reporter{}
	r.Begin("n", "p")
	if r.HasEngine() {
		t.Error("HasEngine before any Engine call")
	}
	r.Engine(EngineTDFA, "captures")
	if !r.HasEngine() {
		t.Error("HasEngine false after Engine")
	}
}

// TestReporterRenderPatterns walks every branch of the per-pattern half of
// Render: a named and an unnamed pattern, an engine with and without a reason,
// the no-engine arm in both its spellings, limits, and notes (which are sorted,
// so the emitters need not agree on an order).
func TestReporterRenderPatterns(t *testing.T) {
	r := &Reporter{}
	r.Begin("url", "https?://[^/]+/.*")
	r.Engine(EngineDFA, "no capture groups")
	r.Limit("dfa states", 1030, 1024)
	r.Note("zebra")
	r.Note("alpha")
	r.End()

	r.Begin("", strings.Repeat("x", 80)) // unnamed, and over the 60-col truncation
	r.Engine(EngineBacktrack, "")        // engine with no reason
	r.End()

	r.Begin("litchain", "AKIA[A-Z0-9]{16}")
	r.Reason("literal chain body") // no engine, but a reason
	r.End()

	r.Begin("skipped", "(?:)") // no engine and no reason
	r.End()

	var b bytes.Buffer
	r.Render(&b)
	out := b.String()

	for _, want := range []string{
		"Patterns (4)",
		"url",
		"engine: DFA — no capture groups",
		"limit:  dfa states 1030 of 1024",
		"opts:   alpha, zebra", // sorted, not insertion order
		"(unnamed)",
		"engine: Backtracking\n", // no reason, no em dash
		"engine: literal chain body",
		"engine: none",
		"…", // the truncation marker
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n--- got ---\n%s", want, out)
		}
	}
	// Truncation must cap the pattern column, not merely mark it.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "xxxx") && len(strings.TrimSpace(line)) > 90 {
			t.Errorf("pattern column not truncated: %q", line)
		}
	}
}

// TestReporterRenderSets covers the set half, including the drop lines that
// are the reason this reporter exists.
func TestReporterRenderSets(t *testing.T) {
	r := &Reporter{
		Sets: []SetDiag{{
			Name:         "creds",
			Frontend:     "teddy",
			Capabilities: []string{"find", "scan_any"},
			Overlapping:  true,
			IDSpaceSize:  9, // deliberately != len(Buckets), so the line prints
			Buckets: []BucketDiag{
				{
					ID: 0, Type: "merged", AcceptKind: "bitmask", Literal: "AKIA",
					Patterns: []PatternRef{{ID: 0, Name: "aws"}}, SuffixStates: 12, TableBytes: 340,
				},
				{
					ID: 1, Type: "fallback", AcceptKind: "bitmask", Literal: "",
					Patterns: []PatternRef{{ID: 1}}, SuffixStates: 4, TableBytes: 80,
				},
			},
			StateLimitDropped:     []PatternRef{{ID: 7, Name: "huge"}},
			CaptureBearingDropped: []PatternRef{{ID: 8}}, // unnamed → "#8"
			UnparseableDropped:    []PatternRef{{ID: 9, Name: "bad"}},
			FrontendDemotion:      &FrontendDemotionDiag{From: "ac", To: "shufti", Reason: "budget"},
		}},
	}
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()

	for _, want := range []string{
		`Set "creds"`,
		"frontend:   teddy",
		"capabilities: find, scan_any",
		"overlapping: true",
		"buckets:    2",
		"AKIA",
		"(fallback — no lite…", // truncated to the 24-col bucket-literal width
		"dropped (fallback DFA over max_fallback_states): huge",
		"dropped (capture-bearing): #8", // the unnamed spelling
		"dropped (unparseable): bad",
		"id space:   9",
		"DOWNGRADED frontend:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestReporterRenderSetOmissions is the negative half: the optional lines must
// be ABSENT when they have nothing to say, or the report becomes noise and the
// drop lines stop standing out.
func TestReporterRenderSetOmissions(t *testing.T) {
	r := &Reporter{
		Sets: []SetDiag{{
			Name: "plain", Frontend: "scalar",
			IDSpaceSize: 1,
			Buckets:     []BucketDiag{{ID: 0, Type: "singleton", AcceptKind: "bitmask", Literal: "x"}},
		}},
	}
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()
	for _, unwanted := range []string{
		"capabilities:", "overlapping:", "dropped", "id space:", "DOWNGRADED",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("render includes %q with nothing to report\n--- got ---\n%s", unwanted, out)
		}
	}
}

// TestTruncate pins the helper's boundary, since it decides a column width the
// two Render halves share.
func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcde", 5, "abcde"}, // exactly n is not truncated
		{"abcdef", 5, "ab…"},  // "…" is 3 bytes, so only 2 fit under n=5
		{"", 3, ""},
		// The cut must land on a RUNE boundary. Slicing by byte index here
		// produced "αα\xce…" — a lone lead byte, invalid UTF-8, printed
		// straight to the terminal.
		{"ααααα", 6, "α…"},
		{"日本語です", 9, "日本…"},
		// No room for anything but the marker.
		{"abcdef", 3, "…"},
		{"abcdef", 1, "…"},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// TestVerboseDFAConstructionLimit pins the one --verbose path with no table to
// report on. When newDFA's own ceiling fires, compilePattern holds a nil
// *dfaTable and only the demotion is knowable; reading numStates off it to fill
// the "DFA states N of M" line panicked, so `compile --verbose` crashed on
// exactly the pattern the flag exists to explain.
func TestVerboseDFAConstructionLimit(t *testing.T) {
	// Exponential subset construction: `.*a.{14}b` needs a state per
	// 15-byte window, far past newDFA's internal ceiling.
	re := config.RegexEntry{Name: "blowup", Pattern: `(?s).*a.{14}b`, FindFunc: "find"}
	rep := &Reporter{}
	if _, err := compilePattern(re, 0, 0, CompileOptions{Report: rep, MaxDFAStates: 64}); err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if len(rep.Patterns) != 1 {
		t.Fatalf("reported %d patterns, want 1", len(rep.Patterns))
	}
	got := rep.Patterns[0]
	if got.Engine != EngineBacktrack {
		t.Errorf("engine = %v, want Backtracking", got.Engine)
	}
	if !strings.Contains(got.Reason, "state limit") {
		t.Errorf("reason = %q, want it to name the state limit", got.Reason)
	}
	// No table means no measurement: the limit line must be omitted rather
	// than invented.
	for _, l := range got.Limits {
		if strings.HasPrefix(l, "DFA states") {
			t.Errorf("reported %q with no table constructed", l)
		}
	}
}
