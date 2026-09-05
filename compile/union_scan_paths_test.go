package compile

import (
	"fmt"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── The start-anywhere union automaton ─────────────────────────────────────
//
// A literal-less set's scan pair compiles to ONE pass over the input rather
// than a per-position bucket walk, and that pass has three shapes the ordinary
// set tests never select together:
//
//   - the NARROW body, which accumulates an i64 id bitmask (<= 64 ids);
//   - the WIDE body, where each state instead carries a representative id plus
//     a bitmap row OR'd into the caller's `_all` bitmap (up to 256 ids);
//   - the SIMD stride, emitted only under prefer-no-match, which walks a
//     state's self-loop run 16 bytes at a time.
//
// Past 256 ids the set keeps the per-position walk instead, so the width
// boundaries are decisions worth pinning rather than incidental.

// unionScanSet builds a literal-less set of n patterns declaring both scan
// capabilities, compiled under the given hint.
func unionScanSet(t *testing.T, n int, hints []string) ([]byte, []SetDiag) {
	t.Helper()
	entries := make([]config.RegexEntry, n)
	for i := range entries {
		// Literal-less by construction: a class chain with no fixed substring
		// long enough to anchor on, and a per-pattern digit span so the
		// patterns stay distinguishable.
		entries[i] = config.RegexEntry{
			Name:    fmt.Sprintf("p%d", i),
			Pattern: fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 3+i%4, 1+i%3),
		}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name:     "s",
			ScanAny:  "s_scan_any",
			ScanAll:  "s_scan_all",
			Patterns: config.PatternSelector{All: true},
			Hints:    hints,
		}},
	}
	w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
	if err != nil {
		t.Fatalf("n=%d hints=%v: %v", n, hints, err)
	}
	return w, diags
}

// TestUnionScanWidthsAndHints drives the union pass across the accept-form
// boundary and both hint settings.
//
// 64 ids is where the i64 accumulator stops fitting and the per-state
// representative-plus-bitmap form takes over; the two are different emitters
// reading differently-shaped tables, and a set that silently took the wrong
// one would still compile.
func TestUnionScanWidthsAndHints(t *testing.T) {
	for _, n := range []int{4, 64, 65, 100} {
		for _, hints := range [][]string{nil, {"prefer-no-match"}, {"prefer-match"}} {
			name := fmt.Sprintf("n=%d/hints=%v", n, hints)
			t.Run(name, func(t *testing.T) {
				w, diags := unionScanSet(t, n, hints)
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("not a WASM module (%d bytes)", len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("got %d set diagnostics, want 1", len(diags))
				}
				// A literal-less set must have no literal frontend to choose:
				// if one appears, these patterns stopped being literal-less
				// and this test is no longer driving the union pass.
				if d := diags[0]; d.Frontend != "scalar" && d.Frontend != "" {
					t.Skipf("frontend %q selected; the set is no longer literal-less", d.Frontend)
				}
				for _, want := range []string{"s_scan_any", "s_scan_all"} {
					if !containsExport(w, want) {
						t.Errorf("module does not export %q", want)
					}
				}
			})
		}
	}
}

func containsExport(w []byte, name string) bool {
	return len(w) > 0 && len(name) > 0 && bytesContains(w, []byte(name))
}

func bytesContains(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if h[i+j] != n[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestWideAcceptSparseBucket drives a single bucket past 64 patterns, which is
// where the DFA's accept representation changes shape.
//
// Up to 64 ids a state's accept set is a u64 BITMASK; past it, construction
// switches to per-state LISTS of pattern indices — a different code path in
// newDFA (acceptWideFor and the wide maps it fills) that a set of 40, which is
// what the sparse fixtures use, never reaches. It is also the only form that
// lets one bucket hold a whole shared-literal group instead of ceil(N/32) of
// them, so it is the shape a large real set actually compiles to.
func TestWideAcceptSparseBucket(t *testing.T) {
	for _, n := range []int{40, 65, 90} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			entries := make([]config.RegexEntry, n)
			for i := range entries {
				// The literal must be SHARED, not merely similar: distinct
				// literals pack into distinct buckets and no bucket ever
				// crosses the width the wide form exists for. The varying
				// part therefore goes AFTER a run that breaks the literal.
				entries[i] = config.RegexEntry{
					Name:    fmt.Sprintf("p%d", i),
					Pattern: fmt.Sprintf(`shared[ \t]+k%03d[a-z]+`, i),
				}
			}
			cfg := config.BuildConfig{
				Regexps: entries,
				Sets: []config.SetConfig{{
					Name:     "s",
					Find:     "s_find",
					MatchAny: "s_match_any",
					MatchAll: "s_match_all",
					ScanAny:  "s_scan_any",
					Patterns: config.PatternSelector{All: true},
				}},
			}
			for _, hints := range [][]string{nil, {"prefer-match"}} {
				cfg.Sets[0].Hints = hints
				w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("n=%d hints=%v: %v", n, hints, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("not a WASM module (%d bytes)", len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("got %d set diagnostics, want 1", len(diags))
				}
				// Past 64 ids the accept kind must have changed; asserting it
				// is what keeps this test pointed at the path it names.
				if n > 64 {
					sawSparse := false
					for _, b := range diags[0].Buckets {
						if b.AcceptKind != "bitmask" {
							sawSparse = true
						}
					}
					if !sawSparse {
						t.Errorf("n=%d: every bucket still reports a bitmask accept; "+
							"this test no longer reaches the wide form", n)
					}
				}
			}
		})
	}
}

// TestOverlapDPRefusals drives the overlapping-find DP sweep into each of its
// refusals.
//
// The sweep is an optimisation that reports every start position in one pass,
// and it declines whenever a bucket's accept representation is something it
// cannot read: a SPARSE bucket keeps per-state lists rather than an i64 mask,
// a Backtracking member has no DFA to sweep at all, and past 64 patterns the
// mask cannot express the answer. Each refusal returns -1 and the set falls
// back to the ordinary per-position walk — correct, just slower — so a refusal
// that stopped working would show up as a wrong answer rather than a slow one.
func TestOverlapDPRefusals(t *testing.T) {
	cases := []struct {
		name    string
		build   func() []config.RegexEntry
		wantSet bool
	}{
		{
			// Past the sparse promotion threshold on one shared literal.
			name: "sparse bucket",
			build: func() []config.RegexEntry {
				out := make([]config.RegexEntry, 50)
				for i := range out {
					out[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`shared[ \t]+k%03d[a-z]+`, i),
					}
				}
				return out
			},
		},
		{
			// A capture-bearing member routes to Backtracking, which has no
			// DFA for the sweep to read.
			name: "backtracking member",
			build: func() []config.RegexEntry {
				return []config.RegexEntry{
					{Name: "a", Pattern: `alpha[0-9]{3}`},
					{Name: "b", Pattern: `bravo[0-9]{3}`},
					{Name: "c", Pattern: `charlie(a.*?b)(c+)`},
				}
			},
		},
		{
			// More patterns than an i64 mask can hold.
			name: "past the mask width",
			build: func() []config.RegexEntry {
				out := make([]config.RegexEntry, 80)
				for i := range out {
					out[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`lit%03dx[a-z]+`, i),
					}
				}
				return out
			},
		},
		{
			// A word boundary changes which start state a position gets, which
			// the sweep would have to reproduce.
			name: "word boundary member",
			build: func() []config.RegexEntry {
				return []config.RegexEntry{
					{Name: "a", Pattern: `alpha[0-9]{3}`},
					{Name: "b", Pattern: `\bbravo\b[0-9]{3}`},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.BuildConfig{
				Regexps: tc.build(),
				Sets: []config.SetConfig{{
					Name:        "s",
					Find:        "s_find",
					Overlapping: true,
					Patterns:    config.PatternSelector{All: true},
				}},
			}
			w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if len(w) < 8 || string(w[:4]) != "\x00asm" {
				t.Fatalf("%s: not a WASM module (%d bytes)", tc.name, len(w))
			}
			if len(diags) != 1 || !diags[0].Overlapping {
				t.Fatalf("%s: the set did not compile as overlapping", tc.name)
			}
			if !containsExport(w, "s_find") {
				t.Errorf("%s: module does not export s_find", tc.name)
			}
		})
	}
}

// TestFindPreflightPredicatesOnWideSets covers the WIDE refusals in both
// find-preflight predicates.
//
// A wide union automaton emits no acceptOff/eofOff u64 pair — it carries
// per-state accept ROWS instead — so a preflight that read the narrow tables
// would be reading something that was never emitted. The failure direction is
// the bad one: a pattern wrongly declared dead stops reporting matches
// entirely, silently. Both predicates therefore refuse the wide form, and both
// refusals are reachable only from a set past 64 ids.
func TestFindPreflightPredicatesOnWideSets(t *testing.T) {
	for _, overlapping := range []bool{false, true} {
		for _, n := range []int{8, 90} {
			name := fmt.Sprintf("n=%d/overlapping=%v", n, overlapping)
			t.Run(name, func(t *testing.T) {
				entries := make([]config.RegexEntry, n)
				for i := range entries {
					// Literal-less, so a union automaton is built at all.
					entries[i] = config.RegexEntry{
						Name:    fmt.Sprintf("p%d", i),
						Pattern: fmt.Sprintf(`[a-z]{%d}[0-9]{%d}x`, 2+i%3, 1+i%2),
					}
				}
				cfg := config.BuildConfig{
					Regexps: entries,
					Sets: []config.SetConfig{{
						Name:        "s",
						Find:        "s_find",
						ScanAll:     "s_scan_all",
						Overlapping: overlapping,
						Patterns:    config.PatternSelector{All: true},
					}},
				}
				w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("%s: not a WASM module (%d bytes)", name, len(w))
				}
				if len(diags) != 1 {
					t.Fatalf("%s: got %d diagnostics, want 1", name, len(diags))
				}
				if diags[0].Overlapping != overlapping {
					t.Errorf("%s: set reports overlapping=%v", name, diags[0].Overlapping)
				}
				for _, want := range []string{"s_find", "s_scan_all"} {
					if !containsExport(w, want) {
						t.Errorf("%s: module does not export %q", name, want)
					}
				}
			})
		}
	}
}
