package fuzz

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// ── The chain-start SIMD probe ─────────────────────────────────────────────
//
// `[class]{N,}` under prefer-match verifies the head of every candidate with
// one SIMD probe instead of walking it, and — on failure — skips the entire
// range the failed probe just disproved. Both halves change which positions
// the engine visits, which is the class of change a byte-comparison cannot
// check and a corpus run only checks if the corpus contains the shape.
//
// It does not: re2-exhaustive.txt holds 4,992 open-ended counted repeats and
// re2-adjusted.txt another 1,920, and NONE of them is over a character class.
// custom-tests.txt Category 33 covers the shape by hand; this file covers it
// by generation, over inputs built to land on the boundaries the emitted code
// actually branches on.

// compileFindLM compiles a find export under prefer-match, which is the only
// mode that emits the probe.
func compileFindLM(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true,
		compile.CompileOptions{LikelyMode: compile.LikelyMatch})
	return w, err
}

// classChainPats spans the decisions detectClassChainPrefix makes: both sides
// of minClassChainPrefix, both kinds of chain end (an accepting state, and a
// state that only self-loops on the class), and chain lengths either side of
// the probe's fixed 16-byte chunk.
var classChainPats = []string{
	`[a-z]{3,}`, // below the floor — no probe; the control
	`[a-z]{4,}`, // exactly at the floor
	`[a-z]{5,}`,
	`[a-z]{15,}`,      // one below a chunk
	`[a-z]{16,}`,      // exactly a chunk
	`[a-z]{17,}`,      // one above: k saturates at 16
	`[a-z]{8}`,        // exact count, accepting end
	`[a-z]{6,9}`,      // bounded range: the chain is its MINIMUM
	`[a-z]{4,}[0-9]`,  // self-loop end, minimal
	`[a-z]{12,}[0-9]`, // self-loop end, longer than the probe
	`[a-z]{6,}END`,    // self-loop end before a literal
	`[a-zA-Z]{20,}`,   // the shape the optimisation was built for
}

// classChainInput builds a string of lowercase runs separated by gaps, with
// the run lengths drawn to cluster around the boundaries the probe branches
// on — 0, the floor, and the 16-byte chunk — rather than uniformly, since a
// uniform draw almost never lands on them.
func classChainInput(rng *rand.Rand, withTail bool) string {
	interesting := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 18, 20, 31, 32, 33}
	var b strings.Builder
	for i := 0; i < 12; i++ {
		n := interesting[rng.Intn(len(interesting))]
		for j := 0; j < n; j++ {
			b.WriteByte(byte('a' + rng.Intn(26)))
		}
		// The separator decides which patterns can match here: a digit
		// completes `{N,}[0-9]`, "END" completes the literal form, and a
		// space kills both.
		switch rng.Intn(4) {
		case 0:
			b.WriteByte(' ')
		case 1:
			b.WriteByte(byte('0' + rng.Intn(10)))
		case 2:
			b.WriteString("END")
		default:
			b.WriteString("  ")
		}
	}
	if withTail {
		// A run flush against the end of the input, where `p + 16 > len`
		// sends the candidate down the scalar fallback — the arm no other
		// input here reaches.
		for j := 0; j < 20; j++ {
			b.WriteByte(byte('a' + rng.Intn(26)))
		}
	}
	return b.String()
}

// TestClassChainFindMatchesGo drives find at EVERY start position over
// generated inputs and compares against an oracle built from whole-input
// anchored probes, the same construction TestFindFromStartsAtOrAfterFrom uses.
//
// Driving every position is the point. The probe's failure arm advances
// attempt_start by ctz(mask)+1, asserting that no start in the range it
// skipped could have matched; a wrong skip shows up ONLY as a missed match at
// one of the positions inside that range, which a from=0 iteration would never
// reveal because it never asks about them.
func TestClassChainFindMatchesGo(t *testing.T) {
	for _, pat := range classChainPats {
		t.Run(pat, func(t *testing.T) {
			if _, err := regexp.Compile(pat); err != nil {
				t.Skipf("Go rejects %q: %v", pat, err)
			}
			w, err := compileFindLM(pat)
			if err != nil {
				t.Skipf("compile %q: %v", pat, err)
			}
			rng := rand.New(rand.NewSource(0x0c4a14))
			for i := 0; i < 12; i++ {
				input := classChainInput(rng, i%3 == 0)
				call, done, ok := findCaller(t, w, input)
				if !ok {
					t.Skip("module would not instantiate")
				}
				ends := endsAt(t, pat, input)
				for from := 0; from <= len(input); from++ {
					got, state := call(from)
					switch state {
					case findHang:
						done()
						t.Fatalf("input %d from=%d: watchdog fired", i, from)
					case findOverflow:
						done()
						t.Skipf("input %d from=%d: BT stack overflow", i, from)
					}
					want, wantOK := goFirstFrom(ends, from)
					if state == findNone {
						if wantOK {
							done()
							t.Fatalf("input %d from=%d: got no match, want [%d,%d) in %q",
								i, from, want[0], want[1], input)
						}
						continue
					}
					if !wantOK {
						done()
						t.Fatalf("input %d from=%d: got [%d,%d), want no match in %q",
							i, from, got[0], got[1], input)
					}
					if got != want {
						done()
						t.Fatalf("input %d from=%d: got [%d,%d), want [%d,%d) in %q",
							i, from, got[0], got[1], want[0], want[1], input)
					}
				}
				done()
			}
		})
	}
}

// TestClassChainAgreesWithNeutral is the differential half: the hinted build
// and the neutral build must report the SAME match at every start position.
//
// It is the stronger statement. The Go oracle test above proves the hinted
// build is right; this one proves the hint changed nothing observable, which
// is the actual contract of a performance hint and the thing that would break
// if the probe ever resumed the walk in the wrong DFA state.
func TestClassChainAgreesWithNeutral(t *testing.T) {
	for _, pat := range classChainPats {
		t.Run(pat, func(t *testing.T) {
			lm, err := compileFindLM(pat)
			if err != nil {
				t.Skipf("compile LM %q: %v", pat, err)
			}
			neutral, err := compileFind(pat)
			if err != nil {
				t.Skipf("compile neutral %q: %v", pat, err)
			}
			rng := rand.New(rand.NewSource(0x9e3779b9))
			for i := 0; i < 10; i++ {
				input := classChainInput(rng, i%2 == 0)
				callLM, doneLM, ok1 := findCaller(t, lm, input)
				if !ok1 {
					t.Skip("LM module would not instantiate")
				}
				callN, doneN, ok2 := findCaller(t, neutral, input)
				if !ok2 {
					doneLM()
					t.Skip("neutral module would not instantiate")
				}
				for from := 0; from <= len(input); from++ {
					g1, s1 := callLM(from)
					g2, s2 := callN(from)
					if s1 != s2 || g1 != g2 {
						doneLM()
						doneN()
						t.Fatalf("input %d from=%d: hinted %v/%v, neutral %v/%v in %q",
							i, from, g1, s1, g2, s2, input)
					}
				}
				doneLM()
				doneN()
			}
		})
	}
}
