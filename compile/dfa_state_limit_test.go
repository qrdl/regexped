package compile

import (
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

// TestDFAStateLimitBailsOutFast guards against a real compile-time DoS found
// 2026-08-06: newDFA's subset-construction BFS had no internal state cap.
// [^,]{250,}X[^;]{250,} — two independent bounded-repetition inverted
// classes straddling an ambiguous split point (any 'X' byte is valid inside
// both classes too) — makes the number of distinct reachable NFA-state
// subsets explode with no plateau in sight (confirmed live: 40,000+ DFA
// states generated in 12s with no sign of leveling off, driven entirely by
// map/string-key allocation in the subset-construction worklist).
// CompileOptions.MaxDFAStates was completely ineffective against this,
// because it was only ever checked on newDFA's *output*, after the
// unbounded construction already ran (or hung trying to). This test must
// complete quickly and either succeed with a small compiled pattern or
// cleanly fall back to Backtracking — never hang.
func TestDFAStateLimitBailsOutFast(t *testing.T) {
	const pattern = `[^,]{250,}X[^;]{250,}`
	t.Run("newDFA_bails_out_internally", func(t *testing.T) {
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if _, ok := newDFA(prog, false, true, 1024); ok {
			t.Fatalf("newDFA(%q, maxStates=1024): expected state-limit bail-out (ok=false), got ok=true", pattern)
		}
	})
	t.Run("compile_falls_back_to_backtracking", func(t *testing.T) {
		// End-to-end: MaxDFAStates left at its default (1024) — the pattern
		// must compile successfully (falling back to Backtracking), not
		// hang and not hard-error.
		mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, FindFunc: "f"}})
	})
}
