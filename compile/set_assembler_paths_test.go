package compile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
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
			// A prefer-no-match find whose adaptive Shufti scan emits a
			// NEUTRAL TWIN: two functions from one findBody, the first
			// handing off to the second. funcLayout gained the twin's slot
			// and both assemblers therefore declared it, while only the
			// single-pattern one had a type index for it — so this
			// combination panicked in the set module's function section.
			//
			// The pattern needs a first-byte set in the adaptive band and no
			// mandatory literal, or there is no dense switch to escape and no
			// twin to emit (TestFindNeutralTwinEmission pins that predicate).
			name: "prefer-no-match find twin",
			entries: []config.RegexEntry{{
				Name:     "tw",
				Pattern:  `[a-zA-Z]{20,}`,
				FindFunc: "tw_find",
				Hints:    []string{"prefer-no-match"},
			}},
			exports: []string{"tw_find", "s_find"},
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

// TestSetAssemblerFindTwinHandoff pins that the set assembler emits the neutral
// twin AND patches the handoff call that reaches it.
//
// The export check above cannot see either. A missing twin body leaves the
// module declaring one more function than it emits, which is a section-length
// error rather than a missing export; an unpatched handoff leaves the call
// immediate at its placeholder 0 — the find body itself, whose type matches, so
// the module still validates and merely recurses for ever. Comparing against
// the bytes the shared emitter produces at the pattern's real function index
// catches both, without a WASM parser.
func TestSetAssemblerFindTwinHandoff(t *testing.T) {
	entry := config.RegexEntry{
		Name:     "tw",
		Pattern:  `[a-zA-Z]{20,}`,
		FindFunc: "tw_find",
		Hints:    []string{"prefer-no-match"},
	}
	cfg := setPlusPatternsConfig([]config.RegexEntry{entry}, nil)
	w, _, _, err := CompileFileOpts(cfg, "", CompileSetOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// The same pattern through the same front end, to learn what its find
	// body and twin should look like and where the twin sits.
	p, err := compilePattern(entry, 0, 0, CompileOptions{})
	if err != nil {
		t.Fatalf("compilePattern: %v", err)
	}
	if p.findNeutralBody == nil {
		t.Fatal("pattern emitted no neutral twin — the case no longer covers " +
			"the path it was written for")
	}
	// The twin pattern is the LAST entry, so its base is every earlier
	// pattern's function count. The set members declare no _func fields, so
	// they compile to nothing here and the twin is the module's first — and
	// only — standalone pattern.
	base := 0
	for _, e := range cfg.Regexps[:len(cfg.Regexps)-1] {
		q, cErr := compilePattern(e, 0, 0, CompileOptions{})
		if cErr != nil {
			t.Fatalf("compilePattern(%s): %v", e.Name, cErr)
		}
		if q != nil {
			base += len(q.funcLayout())
		}
	}
	// Being first is also what makes tableBase 0 for it, which is the base the
	// reference build above used. A table-bearing pattern added ahead of it
	// would shift the twin's data offsets and the reconstruction below would
	// no longer be the bytes the assembler emits — so say so here rather than
	// letting the comparison fail as if the assembler were at fault.
	if base != 0 {
		t.Fatalf("twin pattern is no longer the module's first compiled "+
			"pattern (base=%d): rebuild the reference at its real tableBase", base)
	}
	_, _, findOff, _, _ := p.offsets()
	want := p.appendFindBodyWithTwin(nil, base+findOff)
	if !bytes.Contains(w, want) {
		t.Errorf("set module does not contain the find body and its patched "+
			"twin handoff (find at function %d, twin at %d)",
			base+findOff, base+findOff+1)
	}
	// And the unpatched form must NOT appear: that is the placeholder the
	// assembler is responsible for overwriting.
	unpatched := append([]byte(nil), p.findBody...)
	copy(unpatched[p.findTwinCallOff:p.findTwinCallOff+twinCallImmWidth],
		utils.AppendPaddedULEB128(nil, 0, twinCallImmWidth))
	if bytes.Contains(w, unpatched) {
		t.Error("set module contains the find body with an UNPATCHED twin " +
			"handoff — the call still targets function 0")
	}
}
