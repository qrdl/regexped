package compile

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ---------------------------------------------------------------------------
// FABLE B24. binPack's literal-singleton arm built a bucket's suffix DFA and
// kept a FAILURE silently:
//
//	if ast := patternSuffixAST(p); ast != nil {
//	    if t, _, mergeErr := mergeSuffixDFA(...); mergeErr == nil {
//	        nb.suffixDFA = t
//	    }
//	}   // <- no else; the bucket went live with a nil table
//
// genSuffixWASM answers a nil table with a body that returns 0, which is
// indistinguishable from "no match at this position". So the literal would gate
// candidates into a bucket that reports nothing at all of them, and the pattern
// would silently never match — no warning, no --diag-json entry. The sibling
// fallback packers already refuse exactly this, through admitOrDropFallback,
// so the codebase stated one policy in two places with two different answers.
//
// REACHABILITY, measured 2026-09-09 rather than asserted. The failure branch is
// unreachable today, for a structural reason worth writing down because it is
// what a future change would have to break:
//
//  1. analyzePattern builds the suffix DFA FIRST, with ceiling
//     maxHelperDFAStates and leftmostFirst=FALSE, and returns an error if
//     either the compile or the subset construction fails. A pattern that
//     cannot produce a suffix DFA never reaches a packer at all.
//  2. mergeSuffixDFA rebuilds the same AST with leftmostFirst=TRUE. LF prunes
//     lower-priority threads, so it yields NO MORE states than the non-LF build
//     — measured across a range of alternation shapes, LF was consistently
//     smaller (e.g. (?:a+|b+|ab+){1,9}Q: 2005 non-LF vs 1156 LF).
//  3. So if step 1 succeeded, step 2 succeeds.
//
// FABLE's own note predicted the opposite ("the merge uses leftmostFirst=true
// while analyzePattern's earlier build used false, so state counts can differ
// and failure is possible"). The direction is real; the SIGN is backwards.
//
// Instrumenting the branch with a panic and running the full set corpus
// (make setcaps, ~19.5M checks over 872 patterns) produced no hit, which is the
// evidence behind calling this latent rather than live.
//
// The guard is therefore defence in depth, and the invariant in CompileSet is
// the part that carries the weight: it turns a future regression from "silently
// never matches" into a build failure.

// A nil suffix DFA compiles to a body that returns 0 — the property that makes
// the missing guard silent rather than loud. Pinned so that if the emitter ever
// starts answering nil differently, the reasoning above is revisited too.
func TestNilSuffixDFAEmitsNeverMatchBody(t *testing.T) {
	art, _, _, _ := genSuffixWASM(nil, 0, 0, []int{0}, []int{0}, LikelyNeutral, false, false, nil)
	// ULEB128 size prefix 0x06, then the 6-byte body: one i32 local group
	// (0x01, 0x01, 0x7F), i32.const 0 (0x41 0x00), end (0x0B).
	want := []byte{0x06, 0x01, 0x01, 0x7F, 0x41, 0x00, 0x0B}
	if len(art.fnBody) != len(want) {
		t.Fatalf("genSuffixWASM(nil) body = % x, want % x", art.fnBody, want)
	}
	for i := range want {
		if art.fnBody[i] != want[i] {
			t.Fatalf("genSuffixWASM(nil) body = % x, want % x", art.fnBody, want)
		}
	}
}

// CompileSet must refuse a bucket that has neither a suffix DFA nor a BT
// fallback, rather than emit the never-match body for it.
func TestCompileSetRejectsBucketWithNoSuffixDFA(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("CompileSet accepted a bucket with no suffix DFA and no BT fallback; " +
				"such a bucket is gated, dispatched to, and silently never matches")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "no suffix DFA") {
			t.Fatalf("panic = %v, want one naming the missing suffix DFA", r)
		}
	}()
	assertBucketEmittable(3, &bucket{literal: "KEY", patterns: []*PatternInfo{{fullPattern: `KEY[0-9]+`}}})
}

// binPack must not produce a bucket with a nil suffix DFA for any pattern that
// analyzePattern admitted — the positive half of the invariant, over shapes
// that all take the literal-singleton arm.
func TestBinPackLiteralSingletonAlwaysHasSuffixDFA(t *testing.T) {
	pats := []string{
		`SECRETLITERAL[a-z]+`,
		`KEY=[0-9]{4}`,
		`ghp_[A-Za-z0-9]{36}`,
		`AKIA[A-Z0-9]{16}`,
		`BEGIN(?:a|ab|abc){1,6}END`,
		`prefix(?:[a-z]*[0-9]*){1,4}suffix`,
	}
	for _, pat := range pats {
		t.Run(pat, func(t *testing.T) {
			var prefixPool, suffixPool dfaPool
			info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
			if err != nil {
				t.Skipf("analyzePattern refused %q: %v", pat, err)
			}
			for _, b := range binPack([]*PatternInfo{info}, CompileSetOptions{}, nil) {
				if b.suffixDFA == nil && b.btFallback == nil && !b.sparse {
					t.Errorf("binPack(%q) produced a live bucket with no suffix DFA", pat)
				}
			}
		})
	}
}
