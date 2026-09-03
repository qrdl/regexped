package compile

import "testing"

// ccpLayout builds a find-mode layout the way appendFindCodeEntry's callers do,
// so the detector is asked about the same tables the emitter would read.
// ccpLayout builds the layout AND the table the way compilePattern does, and —
// critically — applies the dominant-state encoding first, because that is the
// state the detector actually runs in.
//
// Skipping that step is what made this harness disagree with production:
// applyDominantStateEncoding overloads midAcceptBytes with dominant markers,
// and a detector that read those bytes saw accepts that were not there. The
// detector now reads the table's accept maps instead, so the two agree — but
// the harness still applies the encoding, so a future reader of the wrong
// field is caught here rather than in a corpus run.
func ccpLayout(t *testing.T, pattern string) (*dfaLayout, *dfaTable) {
	t.Helper()
	m, err := compile(pattern, CompileOptions{
		MaxDFAStates: 1024, ForceEngine: EngineDFA, LeftmostFirst: true,
	})
	if err != nil {
		t.Fatalf("compile(%q): %v", pattern, err)
	}
	table := dfaTableFrom(m.(*dfa))
	l := buildDFALayout(dfaLayoutParams{
		t: table, tableBase: 0, needFind: true, leftmostFirst: true,
		compiledDFAThreshold: resolveCompiledDFAThreshold(&CompileOptions{}),
		// The LikelyMatch flags are what put dominants in the layout at all,
		// and dominants are what overload midAcceptBytes below.
		lmBareShufti: true, lmNonMidShufti: true, lmWideShufti: true,
		lmClassChain: true,
	})
	applyDominantStateEncoding(l, true)
	return l, table
}

// TestDetectClassChainPrefix pins both halves of the detector: the shapes it
// must find, and — more importantly — the shapes it must REFUSE.
//
// Every refusal below is a case where the emitted probe would be unsound
// rather than merely unhelpful, because it jumps the walk forward without
// consulting the byte before the candidate or the positions it skips over.
func TestDetectClassChainPrefix(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantOK  bool
		wantN   int
		wantLen int // len(class), 0 = don't check
	}{
		{"open tail 20", `[a-zA-Z]{20,}`, true, 20, 52},
		{"open tail 8", `[A-Z]{8,}`, true, 8, 26},
		{"exact count", `[a-z]{5}`, true, 5, 26},

		// Below minClassChainPrefix the probe loses on BOTH arms: it replaces
		// one scalar step with a chunk load, and its range-retirement argument
		// is empty because a non-member at offset 0 retires only the position
		// the scalar scan was about to abandon anyway. These two are the
		// patterns that measured +3.7% and +1.3% against neutral before the
		// floor existed.
		{"single step is refused", `[a-z]+`, false, 0, 0},
		{"inverted single step is refused", `[^,]+`, false, 0, 0},
		{"word single step is refused", `\w+`, false, 0, 0},
		{"just below the floor", `[a-z]{3,}`, false, 0, 0},
		{"exactly at the floor", `[a-z]{4,}`, true, 4, 26},

		// The `{N,}`-followed-by-something shape. Its chain end SELF-LOOPS on
		// the class and exits on a different one, so it accepts nowhere and
		// has two destinations — the single-destination rule alone refuses it.
		// Reaching that state still proves 50 class bytes were consumed, which
		// is all the probe needs.
		{"open tail then another class", `[a-z]{50,}[0-9]`, true, 50, 26},
		{"open tail then a literal", `[a-z]{6,}END`, true, 6, 26},

		// A bounded range is a chain of its MINIMUM length: {5,9} accepts
		// after 5, so the chain ends there and the scalar walk extends it.
		// The skip stays exact — a start at p+i has r-i class bytes ahead, and
		// r < 5 makes r-i < 5 for every i in [0,r].
		{"bounded range is a chain of its minimum", `[a-z]{5,9}`, true, 5, 26},
		// The class changes mid-chain, so it is not one chain.
		{"class changes", `[a-z]{3}[0-9]{3}`, false, 0, 0},
		// A literal prefix is a different (and already handled) shape.
		{"literal prefix", `abc[a-z]{5,}`, false, 0, 0},
		// Word boundaries make the start state depend on the preceding byte,
		// which the probe never reads.
		{"word boundary", `\b[a-z]{5,}`, false, 0, 0},
		// Same, for newline context.
		{"line anchor", `(?m:^)[a-z]{5,}`, false, 0, 0},
		// The start state accepts, so the empty match makes the chain moot.
		{"start accepts", `[a-z]*`, false, 0, 0},
		// Alternation: the start state has two destinations.
		{"alternation", `[a-z]{3}|[0-9]{5}`, false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, tb := ccpLayout(t, tc.pattern)
			got, ok := detectClassChainPrefix(l, tb)
			if ok != tc.wantOK {
				t.Fatalf("detectClassChainPrefix(%q) ok = %v, want %v (n=%d)",
					tc.pattern, ok, tc.wantOK, got.n)
			}
			if !ok {
				return
			}
			if got.n != tc.wantN {
				t.Errorf("n = %d, want %d", got.n, tc.wantN)
			}
			if tc.wantLen > 0 && len(got.class) != tc.wantLen {
				t.Errorf("len(class) = %d, want %d", len(got.class), tc.wantLen)
			}
			if len(got.states) > 16 {
				t.Errorf("states has %d entries, want at most 16", len(got.states))
			}
			if len(got.states) != min(got.n, 16) {
				t.Errorf("states has %d entries, want min(n,16) = %d",
					len(got.states), min(got.n, 16))
			}
		})
	}
}

// TestClassChainPrefixStatesWalk checks the recorded state ids really are the
// states the DFA reaches after k class bytes. A wrong id here produces a module
// that resumes the walk in a plausible but incorrect state — the failure this
// whole mechanism is most exposed to, and one no validator would catch.
func TestClassChainPrefixStatesWalk(t *testing.T) {
	for _, pattern := range []string{`[a-zA-Z]{20,}`, `[A-Z]{8,}`, `[a-z]{5}`} {
		t.Run(pattern, func(t *testing.T) {
			l, tb := ccpLayout(t, pattern)
			got, ok := detectClassChainPrefix(l, tb)
			if !ok {
				t.Fatalf("detectClassChainPrefix(%q) refused", pattern)
			}
			cellsPerState := 256
			if l.useCompression {
				cellsPerState = l.numClasses
			}
			read := func(state, b int) int32 {
				row := state
				if l.useRowDedup {
					row = int(l.rowMapBytes[state])
				}
				cell := b
				if l.useCompression {
					cell = int(l.classMap[b])
				}
				off := row*cellsPerState + cell
				if l.useU8 {
					return int32(l.tableBytes[off])
				}
				return int32(l.tableBytes[2*off]) | int32(l.tableBytes[2*off+1])<<8
			}
			// Walk the class bytes one at a time and compare against states[].
			cur := int32(l.wasmStart)
			for k := range got.states {
				cur = read(int(cur), int(got.class[0]))
				if cur != got.states[k] {
					t.Fatalf("after %d class bytes the DFA is in state %d, "+
						"but states[%d] records %d", k+1, cur, k, got.states[k])
				}
			}
			// Every class byte must lead to the same place at every step.
			cur = int32(l.wasmStart)
			for k := range got.states {
				for _, c := range got.class {
					if next := read(int(cur), int(c)); next != got.states[k] {
						t.Fatalf("step %d: class byte %#02x goes to %d, want %d",
							k, c, next, got.states[k])
					}
				}
				cur = got.states[k]
			}
		})
	}
}
