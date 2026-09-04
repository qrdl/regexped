package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── Per-pattern emitters inside the SET assembler ──────────────────────────
//
// assembleModuleWithSets carries its own copy of the per-pattern function and
// export emission, because a set module lays out functions differently from a
// plain one. That copy has arms for every specialised single-pattern body —
// alt-lit-anchor with its deferred dispatcher, lit-anchor's backward/forward
// pair, batch wrappers — and none of them was reached, because every set test
// in the package uses a set ALONE and every single-pattern test uses
// assembleModule instead.
//
// The combination is ordinary in a real config: a `sets:` block beside
// per-pattern `find_func` entries. The dispatcher arm is the one that matters
// most, since it patches function indices that only exist at assembly time —
// exactly the shape that produces a module calling the wrong function.

// setPlusPatternsConfig is a BuildConfig with BOTH a set and standalone
// patterns chosen to select the specialised emitters.
func setPlusPatternsConfig(extra []config.RegexEntry, hints []string) config.BuildConfig {
	base := []config.RegexEntry{
		{Name: "s0", Pattern: `alpha[0-9]{3}`},
		{Name: "s1", Pattern: `bravo[0-9]{3}`},
		{Name: "s2", Pattern: `charlie[0-9]{3}`},
	}
	return config.BuildConfig{
		Regexps: append(base, extra...),
		Sets: []config.SetConfig{{
			Name:     "s",
			Find:     "s_find",
			Patterns: config.PatternSelector{Names: []string{"s0", "s1", "s2"}},
			Hints:    hints,
		}},
	}
}

func TestSetAssemblerPerPatternBodies(t *testing.T) {
	cases := []struct {
		name    string
		entries []config.RegexEntry
		exports []string
	}{
		{
			// Alt-lit-anchor: N backward_scan + N forward_verify functions
			// plus ONE dispatcher built at assembly time from indices that do
			// not exist before then.
			name: "alt lit anchor dispatcher",
			entries: []config.RegexEntry{{
				Name: "alt",
				// The branches need an UNBOUNDED suffix. A bounded one is
				// caught earlier by analyseLitChainAltPrefixed and never
				// reaches the alt-lit-anchor block at all — see
				// TestCompileAltLitAnchorDispatch, which learned the same
				// thing the same way.
				Pattern:  `[0-9]{8}ghp_[^\s]+|[a-f]{8}secret_[^\s]+|[0-9]{8}akey_[^\s]+`,
				FindFunc: "alt_find",
			}},
			exports: []string{"alt_find", "s_find"},
		},
		{
			// Lit-anchor: a backward DFA recovers the match start, and the
			// forward half is generated at assembly time too.
			name: "lit anchor pair",
			entries: []config.RegexEntry{{
				Name:     "mail",
				Pattern:  `[a-z]+@example\.com`,
				FindFunc: "mail_find",
			}},
			exports: []string{"mail_find", "s_find"},
		},
		{
			// A capture body beside a set: the groups wrapper composes a find
			// and a capture function, both indexed by the set assembler.
			name: "groups wrapper",
			entries: []config.RegexEntry{{
				Name:       "grp",
				Pattern:    `<([a-z]+)>`,
				GroupsFunc: "grp_groups",
			}},
			exports: []string{"grp_groups", "s_find"},
		},
		{
			// An anchored match body, which takes the assembler's matchBody
			// arm rather than any find arm.
			name: "match only",
			entries: []config.RegexEntry{{
				Name:      "m",
				Pattern:   `[0-9]{4}-[0-9]{2}`,
				MatchFunc: "m_match",
			}},
			exports: []string{"m_match", "s_find"},
		},
		{
			// Batch wrappers beside a set: a second entry point over the same
			// body, whose index the assembler also has to resolve.
			name: "batch find",
			entries: []config.RegexEntry{{
				Name:     "b",
				Pattern:  `[a-z]+@example\.com`,
				FindFunc: "b_find",
				Hints:    []string{"batch-find"},
			}},
			exports: []string{"b_find", "b_find_batch", "s_find"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, hints := range [][]string{nil, {"prefer-match"}, {"prefer-no-match"}} {
				cfg := setPlusPatternsConfig(tc.entries, hints)
				w, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("hints %v: %v", hints, err)
				}
				if len(w) < 8 || string(w[:4]) != "\x00asm" {
					t.Fatalf("hints %v: not a WASM module (%d bytes)", hints, len(w))
				}
				// The export names are the cheapest proof the assembler
				// resolved every function it laid out: a missing arm drops
				// the export rather than producing a bad one.
				for _, want := range tc.exports {
					if !strings.Contains(string(w), want) {
						t.Errorf("hints %v: module does not export %q", hints, want)
					}
				}
			}
		})
	}
}

// TestSetAssemblerWithReporter drives the same combination with --verbose on,
// which is the set half of the reporting path: SetDiag records rendered beside
// per-pattern ones.
func TestSetAssemblerWithReporter(t *testing.T) {
	cfg := setPlusPatternsConfig([]config.RegexEntry{{
		Name: "mail", Pattern: `[a-z]+@example\.com`, FindFunc: "mail_find",
	}}, nil)
	rep := &Reporter{}
	if _, _, diags, err := CompileFileDiag(cfg, ""); err != nil {
		t.Fatalf("compile: %v", err)
	} else {
		rep.Sets = diags
	}
	if len(rep.Sets) == 0 {
		t.Fatal("compiled a set but reported no SetDiag")
	}
	var out strings.Builder
	rep.Render(&out)
	got := out.String()
	for _, want := range []string{`Set "s"`, "frontend:", "buckets:"} {
		if !strings.Contains(got, want) {
			t.Errorf("set report missing %q\n--- got ---\n%s", want, got)
		}
	}
}
