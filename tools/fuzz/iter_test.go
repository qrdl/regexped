package fuzz

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/internal/abi"
)

// Single-pattern ITERATION coverage.
//
// Everything else in this package checks ONE match: fuzz_test.go compares a
// single leftmost find, wasmrun_paths.go a single groups call at ptr 0. The
// defect this file exists for lives only in RE-ENTRY, so none of those can see
// it:
//
//	(A) the iterator resumes on a narrowed slice, so the byte before the
//	    resume point is invisible and \b, \B, ^ and (?m:^) are judged against
//	    the slice edge rather than the real input;
//	(B) Go suppresses an EMPTY match beginning where the previous match ended;
//	    the project's advance rule did not.
//
// Before this file, the ONLY coverage of either was re2test's col4 (225
// hand-picked rows) and col6 (ONE row) — and both were validated against a Go
// loop carrying the identical defects, so they agreed by being wrong the same
// way (FABLE T7).
//
// The oracle here is Go's own FindAllStringIndex / FindAllStringSubmatchIndex
// over the WHOLE input. Nothing re-implements our loop.

// iterSeeds carries one pattern per find-emitter path, so a conversion that
// misses an emitter fails HERE rather than hiding until some later corpus run.
// The path each shape reaches is noted; see compile/compile.go's
// compilePattern dispatch.
var iterSeeds = []struct{ pat, input string }{
	// plain DFA find
	{`a+`, "xaayaaa"},
	{`(?:cat|car)`, "the cat in a car"},
	// empty-matchable — the (B) shapes
	{`a*`, "bab"},
	{`a?`, "a\x00b"},
	{`(?:)`, "abc"},
	// literal-chain / counted-chain emitters
	{`AKIA[A-Z0-9]{16}`, "xxAKIAABCDEFGHIJKLMNOPzz AKIAABCDEFGHIJKLMNOP"},
	{`x[a-f]{3,10}y`, "xabcy xdefy"},
	// literal-anchored find
	{`[a-z]+@example\.com`, "a@example.com b@example.com"},
	// alternation of literal-anchored branches
	{`(?:alpha|beta)[0-9]{4}`, "alpha1234 beta5678"},
	// long class run (Teddy / prefix scan)
	{`(?:alpha|beta|gamma)[0-9a-f]{8}`, "gamma0123abcd"},
	// A zero-width assertion that narrowing CANNOT break, kept as the
	// control for the pendingHalfA list below: re-entry truncates what
	// precedes `from`, never what follows it, so a RIGHT-context assertion
	// sees exactly the same bytes either way. `(?m:$)` was misfiled as a
	// pending half-A shape until TestPendingHalfAStillDiverges was written
	// and reported it as already agreeing with Go.
	{`(?m:$)`, "ab\ncd"},

	// Half (A) acceptance shapes, promoted as their emitters were converted.
	// Each has a LEADING zero-width assertion, so a narrowed re-entry judges
	// it against the slice edge and gets a different answer from Go. They are
	// the only direct evidence that a conversion did anything: the ABI change
	// on its own alters no answer at all.
	{`\Bfoo`, "xfoofoo"}, // mandatory-literal find
	{`\bfoo`, "foofoo"},  // mandatory-literal find
	{`\Ba`, "aaa"},       // mandatory-literal find
	{`(?m:^)a`, "a\naa"}, // mandatory-literal find, line anchor
	{`\B|11*0`, "x110"},  // plain DFA find, assertion in alternation
	{`\B|a+b`, "1112"},   // plain DFA find, assertion in alternation

	// Start-anchored finds. These take the ffAnchoredZeroOnly wrapper, which
	// answers "no match" for any from != 0 WITHOUT calling the body — so if
	// isAnchoredFind ever became true for a pattern that can in fact match
	// later in the input, these are what would catch it.
	{`\Aa+`, "aaabaaa"},
	{`\A`, "abc"},

	// Literal-chain family WITH a leading zero-width assertion. These are the
	// only seeds that can tell whether the lit-chain conversion actually did
	// anything: without a leading assertion a lit-chain pattern gives the same
	// answer narrowed or not.
	{`\bAKIA[A-Z0-9]{16}`, "AKIAABCDEFGHIJKLMNOP xAKIAABCDEFGHIJKLMNOP"},
	{`\bx[a-f]{3,10}y`, "xabcy zxabcy xdefy"},
	{`\B[a-f]{24}`, "aabcdefabcdefabcdefabcdef"},
	{`\b(?:alpha|beta)[0-9]{4}`, "alpha1234 xbeta5678 beta9012"},
	{`(?m:^)[a-z]{26}`, "abcdefghijklmnopqrstuvwxyz\nabcdefghijklmnopqrstuvwxyz"},

	// Literal-anchored find (backward scan + forward verify). These were the
	// last shapes to diverge: the backward scan walks LEFT from the literal,
	// so it needed a floor at the find-from position as well as the seed.
	{`(?m:^)ab`, "ab\nabab"},
	{`^abc`, "abcabc"},
	{`\Aab`, "ababab"},
}

// wasmFindIter drives the find export the way a generated stub does and
// returns every match.
//
// It models the STUB, deliberately: the whole point is to catch a divergence
// between what a host iterating our API sees and what Go reports.
func wasmFindIter(t *testing.T, wasmBytes []byte, input string) ([][2]int, bool) {
	t.Helper()
	engine, wd := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	findFn := inst.GetFunc(store, "find")
	mem := inst.GetExport(store, "memory").Memory()
	if findFn == nil || mem == nil {
		t.Fatal("module missing find export or memory")
	}
	copy(mem.UnsafeData(store), input)

	var out [][2]int
	pos, prevEnd := 0, -1
	for pos <= len(input) {
		wd.Arm(store)
		// The WHOLE buffer plus a start position, which is what every
		// generated stub now passes. Modelling the stub is the point: this
		// target exists to catch a divergence between what a host iterating
		// our API sees and what Go reports.
		//
		// Whether the module then actually USES that left context is the
		// per-emitter question answered one emitter at a time;
		// until an emitter is converted its wrapper narrows internally and
		// this call returns exactly what the narrowed call used to.
		r, callErr := findFn.Call(store, int32(0), int32(len(input)), int32(pos))
		wd.Disarm()
		if callErr != nil {
			if isTimeout(callErr) {
				return nil, false
			}
			t.Fatalf("find call: %v", callErr)
		}
		v := r.(int64)
		if v == abi.BTStackOverflow {
			return nil, false
		}
		if v == abi.NoMatch {
			break
		}
		// Absolute already: the wrapper rebases a narrowed result itself.
		s := int(uint32(v >> 32))
		e := int(uint32(v))
		// (B): Go suppresses an empty match beginning where the previous
		// reported match ended. The advance below is unaffected.
		if !(s == e && s == prevEnd) {
			out = append(out, [2]int{s, e})
			prevEnd = e
		}
		if e > s {
			pos = e
		} else {
			pos = s + 1
		}
	}
	return out, true
}

func goFindAll(re *regexp.Regexp, input string) [][2]int {
	var out [][2]int
	for _, m := range re.FindAllStringIndex(input, -1) {
		out = append(out, [2]int{m[0], m[1]})
	}
	return out
}

func fmtSpans(s [][2]int) string {
	if len(s) == 0 {
		return "(none)"
	}
	out := ""
	for i, m := range s {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%d-%d", m[0], m[1])
	}
	return out
}

// TestFindIterationMatchesGo is the seeded half: every emitter path, checked
// against Go.
func TestFindIterationMatchesGo(t *testing.T) {
	for _, c := range iterSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFind(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goFindAll(re, c.input)
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("find iteration over %q:\n  got  %s\n  want %s", c.input, fmtSpans(got), fmtSpans(want))
			}
		})
	}
}

// pendingHalfA are shapes that still DISAGREE with Go: a leading zero-width
// assertion judged against the slice edge because iteration re-enters
// narrowed. They are deliberately NOT in iterSeeds — a case belongs here
// while it is broken and moves to iterSeeds when it is fixed.
var pendingHalfA = []struct{ pat, input string }{
	// EMPTY. Every shape this task listed now agrees with Go.
	//
	// Keep the list and TestPendingHalfAStillDiverges even so: together they
	// are how a future find emitter that forgets the seed announces itself.
}

// TestPendingHalfAStillDiverges pins the shapes half (A) has not reached yet,
// by asserting they still DISAGREE with Go.
//
// A known-bug list that nothing executes rots silently. This one cannot: the
// moment an emitter conversion makes one of these agree, the test fails and
// names the case, which is the signal to promote it into iterSeeds. It is
// also the only thing standing between "converted an emitter" and "believed
// I converted an emitter" — the wrapper alone changes no answers, so a
// conversion that quietly did nothing looks exactly like success everywhere
// else.
func TestPendingHalfAStillDiverges(t *testing.T) {
	for _, c := range pendingHalfA {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFind(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goFindAll(re, c.input)
			if fmtSpans(got) == fmtSpans(want) {
				t.Errorf("find iteration over %q now AGREES with Go (%s).\n"+
					"Half (A) has reached this emitter — move the case into iterSeeds.",
					c.input, fmtSpans(want))
			}
		})
	}
}

// FuzzFindIteration is the durable half. compileFind and the WASM run are both
// inside one call, so the same maxNFAInsts guard the other targets use applies.
func FuzzFindIteration(f *testing.F) {
	for _, c := range iterSeeds {
		f.Add(c.pat, c.input)
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) > inputCap || len(pat) > 120 {
			t.Skip()
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Skip()
		}
		// Same guards the other targets use: an oversized NFA blows the fuzz
		// worker's 10s hang deadline, and Unicode is out of scope.
		if parsed, perr := syntax.Parse(pat, syntax.Perl); perr == nil {
			if prog, cerr := syntax.Compile(parsed.Simplify()); cerr == nil && len(prog.Inst) > maxNFAInsts() {
				t.Skip()
			}
		}
		if needsUnicode, uerr := compile.NeedsUnicodeSupport(pat); uerr != nil || needsUnicode {
			t.Skip()
		}
		w, err := compileFind(pat)
		if err != nil {
			t.Skip()
		}
		got, ok := wasmFindIter(t, w, input)
		if !ok {
			t.Skip()
		}
		want := goFindAll(re, input)
		if fmtSpans(got) != fmtSpans(want) {
			t.Errorf("find iteration diverges from Go\n  pattern %q\n  input   %q\n  got  %s\n  want %s",
				pat, input, fmtSpans(got), fmtSpans(want))
		}
	})
}
