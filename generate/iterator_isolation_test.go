package generate

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// Standalone JS/TS stubs must COPY the caller's input into WASM memory, because
// WASM cannot read the JS heap. Copying was never the hazard; SHARING one
// staging address was. A generator staged its input, yielded, and resumed — and
// anything the caller ran in between had written its own input over the top, so
// the scan continued across another string's bytes and reported offsets against
// it. No exception, plausible output (TODO 58 / SETS_PLAN item 4).
//
// The fix gives every live call its OWN region, which is the property Rust and
// Go get for free by passing a host pointer. These tests pin the shape of that
// fix in the GENERATED SOURCE, because the failure it prevents is invisible to
// any test that does not interleave two live callers — the runtime proof lives
// in the Node example harness.
func genStubsForIsolation(t *testing.T, ext string, batch bool) string {
	t.Helper()
	sc := config.SetConfig{
		Name: "s", Find: "s_find",
		Patterns: config.PatternSelector{All: true},
	}
	if batch {
		sc.Hints = []string{"batch-find"}
	}
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "w", Pattern: `[a-z]+`, FindFunc: "findWords"},
			{Name: "n", Pattern: `[0-9]+`, MatchFunc: "matchNums"},
			{Name: "g", Pattern: `(?P<a>[a-z])(?P<b>[0-9])`, GroupsFunc: "grp"},
		},
		Sets:     []config.SetConfig{sc},
		StubFile: "out." + ext,
	}
	var src string
	var err error
	if ext == "js" {
		src, err = genJSStubFile(cfg)
	} else {
		src, err = genTSStubFile(cfg)
	}
	if err != nil {
		t.Fatalf("generate %s: %v", ext, err)
	}
	return src
}

// TestGeneratorsOwnTheirRegions is the structural regression: every generator
// must take a region of its own and release it deterministically, and no
// module-level staging address may survive.
func TestGeneratorsOwnTheirRegions(t *testing.T) {
	for _, ext := range []string{"js", "ts"} {
		for _, batch := range []bool{false, true} {
			name := ext
			if batch {
				name += "/batch"
			}
			t.Run(name, func(t *testing.T) {
				src := genStubsForIsolation(t, ext, batch)

				// A shared staging address is the bug itself. `_inBase` and
				// `_outBase` survive only as per-call LOCALS, never as module
				// state, so no assignment to them may appear at top level.
				for _, banned := range []string{
					"let _inBase", "let _outBase",
					"_inBase =", "_outBase =",
				} {
					if strings.Contains(src, banned) {
						t.Errorf("generated %s still has module-level staging (%q): "+
							"one shared address is exactly the aliasing bug", ext, banned)
					}
				}

				// Every generator must reserve and release.
				// "= _open(" so the helper's own definition is not counted as a use.
				nOpen := strings.Count(src, "= _open(input")
				nFinally := strings.Count(src, "finally { _close(); }")
				if nOpen == 0 {
					t.Fatalf("generated %s opens no regions; generators are unprotected", ext)
				}
				if nOpen != nFinally {
					t.Errorf("generated %s: %d _open(...) but %d finally-_close(): "+
						"a generator abandoned via break would never release its region",
						ext, nOpen, nFinally)
				}

				// One-shot exports must NOT reserve: they cannot suspend, so
				// reserving would make a call inside a loop over a live
				// iterator allocate a region per iteration.
				if !strings.Contains(src, "= _stage(input") {
					t.Errorf("generated %s never uses _stage; one-shot calls are "+
						"reserving regions they do not need", ext)
				}

				// Detach safety. memory.grow() detaches EVERY view in the
				// module, whoever owns the region behind it, and a detached
				// view reads as undefined silently — so hoisted views must be
				// re-attachable, which means `let` plus an _att guard.
				if !strings.Contains(src, "_att(") {
					t.Errorf("generated %s has no _att re-attach: a grow by an "+
						"interleaved call silently yields undefined", ext)
				}
				if strings.Contains(src, "const buf = new Int32Array") ||
					strings.Contains(src, "const outBuf = new") ||
					strings.Contains(src, "const slots = new Int32Array") {
					t.Errorf("generated %s hoists a view as const: it cannot be "+
						"re-attached after a grow", ext)
				}
			})
		}
	}
}

// TestOneShotExportsDoNotReserve pins the allocator property that keeps the
// arena from growing per iteration: `matchNums(x)` inside a loop over a live
// iterator must not move the bump pointer.
func TestOneShotExportsDoNotReserve(t *testing.T) {
	for _, ext := range []string{"js", "ts"} {
		src := genStubsForIsolation(t, ext, false)
		i := strings.Index(src, "function matchNums")
		if i < 0 {
			t.Fatalf("%s: matchNums not generated", ext)
		}
		body := src[i:]
		if j := strings.Index(body, "\n}"); j > 0 {
			body = body[:j]
		}
		if strings.Contains(body, "_open(") {
			t.Errorf("%s: matchNums reserves a region; a one-shot call cannot "+
				"suspend and must reuse the space above the bump", ext)
		}
		if !strings.Contains(body, "_stage(") {
			t.Errorf("%s: matchNums does not stage into a region at all", ext)
		}
	}
}
