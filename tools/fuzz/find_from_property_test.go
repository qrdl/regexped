package fuzz

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// The find-from invariant, asserted at EVERY start position.
//
// # Why this file exists
//
// Every exported find receives its start offset through the find-from global
// (compile/find_from.go), and each emitter names BY HAND the local that offset
// is seeded into. Nothing checks that the local named is the one the body's
// scan actually starts from — and WASM locals are zero-initialised, so getting
// it wrong yields a module that validates, compiles, answers `from == 0`
// correctly, and ignores `from` forever after. `ffNative` is returned either
// way, so the mode is no evidence.
//
// That defect has now shipped twice:
//
//   - buildSimplePrefixCheckBody returned `base - count` without a floor, so a
//     literal inside [from, from+M) reported a start BEFORE from
//     (TestSimplePrefixCheckHonoursFrom, the G3 regression).
//   - buildLitChainAltLenientFindBody seeded locAttemptStart, which in that
//     body is DERIVED from the window base rather than being the scan cursor.
//     Every call returned the first match in the buffer regardless of from.
//     A host iterating the export ping-ponged between two positions forever:
//     the exhaust loop advances by `end - from`, which goes NEGATIVE once the
//     returned end precedes from.
//
// Both were found by a human driving one shape. The tests below are the
// emitter-agnostic version: they assert the property that must hold for every
// find body ever emitted, over shapes chosen to spread across the emitters.
//
// # The invariant
//
// For any pattern P, input I and start f in [0, len(I)]:
//
//	find(I, f) == the FIRST match of P in I whose start is >= f
//
// with `-1` when there is none. Two consequences are worth calling out because
// they are what the bugs above actually violated:
//
//   - a returned start may never precede f, and
//   - ptr/len always describe the WHOLE buffer, so left context (\b, \B,
//     (?m:^)) is judged against the real preceding byte — which is why the
//     oracle below filters Go's whole-input match list rather than running Go
//     against a narrowed slice.

// findFromShapes spread across the single-pattern find emitters. Each entry's
// comment names the path it is there for; TestFindFromShapesReachDistinctBodies
// checks the spread is real rather than asserted.
var findFromShapes = []struct{ name, pat, input string }{
	{"dfa_find", `(?:alpha|beta|gamma)[0-9a-f]{4}`, "xx alpha00ff yy beta1234 zz gamma00ab"},
	{"compiled_dfa", `abc[0-9]{2}`, "abc12 q abc34 r abc56"},
	// Count >= 24: below the lit-chain gate these fall through to buildFindBody
	// instead, which is how both of these emitters went unreached.
	{"lit_chain", `AKIA[A-Z0-9]{24}`,
		"AKIA0123456789ABCDEF01234567 q AKIAFEDCBA9876543210FEDCBA98"},
	{"lit_anchor", `[a-z]+@example\.com`, "a@example.com bb@example.com ccc@example.com"},
	{"teddy_prefix", `ghp_[A-Za-z0-9]{8}`, "ghp_abcd1234 ghp_ZZZZ9999 ghp_0000aaaa"},
	{"word_boundary", `\bclass\b`, "class a class b subclass class"},
	{"anchored_find", `[0-9]{3}\z`, "abc123"},
	{"line_anchored", `(?m:^)ERR:.*(?m:$)`, "ERR:one\nok\nERR:two\nERR:three"},
	{"counted_chain", `x[a-f]{3,10}y`, "xabcy xabcdefy xaaay"},
	{"case_folded", `(?i)sel\s+from`, "SEL from q sel FROM r Sel  From"},
	{"strict_alt", `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{20}`,
		"AKIA0123456789ABCDEF ghp_abcdefghij0123456789 AKIAFEDCBA9876543210"},
	{"lenient_alt", `ERROR[0-9]{3}|WARNING[0-9]{3}`, "ERROR123 x WARNING456 y ERROR789"},
	{"lenient_alt_wb", `\bERR[0-9]{2}|WRN[0-9]{2}`, "ERR12 q WRN34 r ERR56"},
	{"alt_range", `foo[0-9]{24,30}|bar[a-f]{24,30}`,
		"foo012345678901234567890123 q barabcdefabcdefabcdefabcdef"},
	{"no_match", `ZZZ[0-9]{4}`, "nothing here at all, no digits either"},
	{"adjacent", `[0-9]{2}`, "123456789"},
	{"single_char", `a`, "aaaa"},
	{"empty_input", `abc`, ""},

	// Empty-CAPABLE shapes: the only ones that can exercise half (B), Go's
	// rule that an empty match beginning exactly where the previous reported
	// match ended is not reported. A lit-chain or alternation body cannot
	// produce one by construction — it always consumes a literal — so this
	// rule lives on the bodies that can match zero bytes.
	{"empty_star", `a*`, "bab"},
	{"empty_opt", `a?`, "xaay"},
	{"empty_alt_assert", `\B|a+b`, "1112"},
	{"empty_alt_digits", `\B|11*0`, "x110"},
	{"empty_only", `(?:)`, "abc"},
	{"empty_trailing", `x*`, "axxbx"},
	// Empty-capable on the BT find fallback and the trivial whole-capture
	// body — the two non-lit-chain find emitters an empty-capable pattern can
	// reach that the shapes above do not.
	{"bt_find_empty", `\B|(?:alpha|beta|gamma)[0-9a-f]{8}`, "xx alpha0123abcd yy"},
	{"trivial_whole_empty", `([a-z]*)`, "ab cd"},

	// Alternation of variable-length-prefix branches: the alt-lit-anchor
	// dispatcher, one of the two paths whose findFromMode comes from a
	// separately-built dispatch body rather than from setFind.
	{"alt_lit_anchor", `[a-z]+@aaa\.com|[0-9]+#bbb\.net`,
		"q a@aaa.com w 12#bbb.net e zz@aaa.com"},
	{"alt_lit_anchor_3", `[a-z]+@aaa\.com|[0-9]+#bbb\.net|[A-Z]+%ccc\.org`,
		"a@aaa.com 9#bbb.net QQ%ccc.org"},
	{"alt_prefixed", `PRE[a-f]{24}|ZZ[0-9]{4,9}X`,
		"PREabcdefabcdefabcdefabcd ZZ12345X PREffffffffffffffffffffffff"},
	{"strict_alt_range", `zz[a-f]{24}|qq[0-9]{26}`,
		"zzabcdefabcdefabcdefabcd qq01234567890123456789012345"},
	{"lit_chain_range", `x[a-f]{24,30}y`,
		"xabcdefabcdefabcdefabcdefy xffffffffffffffffffffffffffy"},

	// LikelyNoMatch-only emitters. buildSimplePrefixCheckBody is the G3
	// regression's owner: two matches within M bytes put the second call's
	// candidate inside the first's backward window.
	// Unbounded self-loop before a mandatory literal: the shape whose DFA
	// never dies, and the one overlapping find's preflight exists for.
	{"dominant_selfloop", `[^\n]*ERROR`, "aa ERROR bb\ncc ERROR dd"},
	// Bounded variable-length prefix — recovery is c - prefixMaxLen, which is
	// why it cannot use the prefix.literal.suffix split (FAILED_IDEAS item 13).
	{"varlen_prefix", `a{0,2}XYZQ`, "q aXYZQ w aaXYZQ e XYZQ"},
	// Literal chain with an alternation SUFFIX rather than an alternation of
	// chains — a different body from both alt paths above.
	{"chain_alt_suffix", `q[a-f]{24}(?:AA|BB)`,
		"qabcdefabcdefabcdefabcdAA qffffffffffffffffffffffffBB"},

	{"lnm_simple_prefix", `[0-9]{4}MARKER`, "1234MARKER5678MARKERyy"},
	{"lnm_lit_anchor", `[a-f]{6}TAIL`, "abcdefTAILabcdefTAIL"},
	{"lnm_lit_chain", `AKIA[A-Z0-9]{16}`, "AKIA0123456789ABCDEF AKIAFEDCBA9876543210"},

	// Six shapes added after compile's TestEveryFindEmitterIsCovered reported
	// that the emitters below were reached by NOTHING — not by this corpus and
	// not by any byteident fixture. The locals fingerprint had hidden it: two
	// of them share a fingerprint with a shape already here, so the count this
	// file checks looked healthy while the bodies went undriven.
	{"lit_chain_range_body", `foo[0-9]{26,30}`,
		"foo0123456789012345678901234567 q foo9876543210987654321098765432"},
	{"lit_chain_prefixed_body", `[a-z]{3}AKIA[A-Z0-9]{24}`,
		"abcAKIA0123456789ABCDEF01234567 q xyzAKIAFEDCBA9876543210FEDCBA98"},
	{"alt_lit_anchor_dispatch", `[a-z]{5}@aaa\.com|[0-9]{5}#bbb\.net`,
		"q abcde@aaa.com w 12345#bbb.net e fghij@aaa.com"},
	{"alt_prefixed_body", `[a-z]{3}AKIA[A-Z0-9]{24}|[0-9]{3}ghp_[A-Za-z0-9]{24}`,
		"abcAKIA0123456789ABCDEF01234567 q 123ghp_abcdefghij0123456789abcd"},
	{"bt_find_fallback", `(?:alpha|beta|gamma)[0-9a-f]{8}`,
		"xx alpha0123abcd yy beta4567ef01 zz gamma89abcdef"},
}

// findFromMaxStates forces a DFA state ceiling for shapes that need one.
// buildBTFindBody is the fallback taken when a find pattern's DFA is too large,
// so no pattern small enough to sweep reaches it at the default limit.
var findFromMaxStates = map[string]int{"bt_find_fallback": 8, "bt_find_empty": 8}

// findFromLNM names the shapes compiled under LikelyNoMatch. Some emitters
// exist ONLY under that mode — buildSimplePrefixCheckBody, whose missing
// find-from floor was the FIRST instance of this defect, is substituted for the
// generic backward scan there and is unreachable from a neutral compile. A
// corpus that only compiled neutrally could not have caught its own precedent.
var findFromLNM = map[string]bool{
	"lnm_simple_prefix": true,
	"lnm_lit_anchor":    true,
	"lnm_lit_chain":     true,
}

// compileFindShape honours a shape's compilation mode.
func compileFindShape(name, pat string) ([]byte, error) {
	if findFromLNM[name] {
		return compileFindLNM(pat)
	}
	if n, ok := findFromMaxStates[name]; ok {
		entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
		w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true,
			compile.CompileOptions{MaxDFAStates: n})
		return w, err
	}
	return compileFind(pat)
}

// endsAt reports, for every start position s in [0, len(input)], the end of the
// leftmost-first match of pat beginning EXACTLY at s, or -1 if none.
//
// The probe is `\A(?s:.{s})(?:pat)`, the same whole-input technique re2test's
// set mode uses. It matters that the probe runs against the FULL input rather
// than input[s:]: an anchored search over a suffix judges \b, \B and (?m:^) at
// the slice edge, while the find-from contract says they see the real preceding
// byte. Anchoring a prefix of exactly s characters instead gives the pattern its
// true left context.
//
// Note the probe counts RUNES; every input in findFromShapes is ASCII, so rune
// and byte offsets coincide.
//
// The naive oracle — "first entry of FindAllStringIndex whose start is >= from"
// — is WRONG, and wrongly failed two shapes when this file was first written.
// FindAll reports non-overlapping matches from a left-to-right scan, so for
// `[a-z]+@example\.com` over "...bb@example.com..." it reports [14,28) and never
// [15,28); but a find that starts at 15 must return [15,28), because
// "b@example.com" is a real match there. What find(I, f) owes is the leftmost
// match at or after f, not the next entry of an iteration that began at 0.
func endsAt(t *testing.T, pat, input string) []int {
	t.Helper()
	out := make([]int, len(input)+1)
	for s := range out {
		probe, err := regexp.Compile(`\A(?s:.{` + strconv.Itoa(s) + `})(?:` + pat + `)`)
		if err != nil {
			t.Skipf("Go rejects probe for %q at %d: %v", pat, s, err)
		}
		if m := probe.FindStringIndex(input); m != nil {
			out[s] = m[1]
		} else {
			out[s] = -1
		}
	}
	return out
}

// goFirstFrom answers find(input, from) from the per-position table.
func goFirstFrom(ends []int, from int) ([2]int, bool) {
	for s := from; s < len(ends); s++ {
		if ends[s] >= 0 {
			return [2]int{s, ends[s]}, true
		}
	}
	return [2]int{}, false
}

// TestFindFromStartsAtOrAfterFrom drives find at every start position.
func TestFindFromStartsAtOrAfterFrom(t *testing.T) {
	for _, c := range findFromShapes {
		t.Run(c.name, func(t *testing.T) {
			if _, err := regexp.Compile(c.pat); err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindShape(c.name, c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := findCaller(t, w, c.input)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()
			ends := endsAt(t, c.pat, c.input)

			for from := 0; from <= len(c.input); from++ {
				got, state := call(from)
				switch state {
				case findHang:
					t.Fatalf("from=%d: watchdog fired", from)
				case findOverflow:
					t.Skipf("from=%d: BT stack overflow", from)
				}
				want, wantOK := goFirstFrom(ends, from)

				if state == findNone {
					if wantOK {
						t.Errorf("from=%d: got -1, want [%d,%d)", from, want[0], want[1])
					}
					continue
				}
				// The property the two shipped bugs violated, checked before
				// the equality so a violation reports as itself.
				if got[0] < from {
					t.Errorf("from=%d: returned start %d precedes from — "+
						"the find-from seed is not reaching this body's scan cursor",
						from, got[0])
					continue
				}
				if !wantOK {
					t.Errorf("from=%d: got [%d,%d), want -1", from, got[0], got[1])
					continue
				}
				if got != want {
					t.Errorf("from=%d: got [%d,%d), want [%d,%d)",
						from, got[0], got[1], want[0], want[1])
				}
			}
		})
	}
}

// TestFindFromIterationTerminates is the host's-eye view of the same defect.
//
// It reproduces the advance rule every generated stub and bench shim uses —
// `off += (end - off) or 1` — which is what turns "returned a start before
// from" into a NON-TERMINATING loop rather than a wrong answer: end - off goes
// negative and off walks backwards. A step budget stands in for the hang.
func TestFindFromIterationTerminates(t *testing.T) {
	for _, c := range findFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindShape(c.name, c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := findCaller(t, w, c.input)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()

			var got [][2]int
			budget := 4*len(c.input) + 16
			off, prevEnd := 0, -1
			for steps := 0; off <= len(c.input); steps++ {
				if steps > budget {
					t.Fatalf("iteration did not terminate within %d steps "+
						"(off=%d, collected %s) — this is the ping-pong a host sees",
						budget, off, fmtSpanList(got))
				}
				sp, state := call(off)
				if state == findHang {
					t.Fatalf("off=%d: watchdog fired", off)
				}
				if state == findOverflow {
					t.Skipf("off=%d: BT stack overflow", off)
				}
				if state == findNone {
					break
				}
				// Half (B): Go does not report an EMPTY match beginning
				// exactly where the previous reported match ended. Every
				// generated stub applies this, and so must the model — without
				// it an empty-capable pattern reports one match too many and
				// the comparison below fails for the wrong reason.
				if !(sp[0] == sp[1] && sp[0] == prevEnd) {
					got = append(got, sp)
					prevEnd = sp[1]
				}
				adv := sp[1] - off
				if adv <= 0 {
					adv = 1
				}
				off += adv
			}

			var want [][2]int
			for _, m := range re.FindAllStringIndex(c.input, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			if fmtSpanList(got) != fmtSpanList(want) {
				t.Errorf("iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpanList(got), fmtSpanList(want))
			}
		})
	}
}

// TestFindFromShapesReachDistinctBodies is a cheap corpus-collapse detector,
// and NOT the coverage authority.
//
// It fingerprints bodies by their locals declarations, which is a proxy: two
// emitters can declare identical locals, so a healthy-looking count can hide an
// emitter that nothing reaches. That is not hypothetical — when this file was
// written the count looked fine while SIX of the fourteen find emitters were
// driven by nothing at all.
//
// compile's TestEveryFindEmitterIsCovered is the authority: it parses the
// package for emitFindFromSeed call sites and traces which ones a corpus
// actually reaches, so it can name the emitter that is missing. Keep this test
// for what it does cheaply — noticing the corpus shrinking — and fix coverage
// gaps there.
func TestFindFromShapesReachDistinctBodies(t *testing.T) {
	byFingerprint := map[string][]string{}
	for _, c := range findFromShapes {
		w, err := compileFindShape(c.name, c.pat)
		if err != nil {
			t.Skipf("compile %q: %v", c.pat, err)
		}
		fp, err := localsFingerprint(w)
		if err != nil {
			t.Fatalf("%s: fingerprint: %v", c.name, err)
		}
		byFingerprint[fp] = append(byFingerprint[fp], c.name)
	}

	keys := make([]string, 0, len(byFingerprint))
	for k := range byFingerprint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-40s %s", k, strings.Join(byFingerprint[k], ", "))
	}

	// Empirical, and a floor rather than a target: a DROP means the corpus
	// shrank. It is NOT evidence that every emitter is covered — see the doc
	// comment, and compile's TestEveryFindEmitterIsCovered for that claim.
	const minBodies = 12
	if len(byFingerprint) < minBodies {
		t.Errorf("find-from shapes reach only %d distinct find bodies, want >= %d — "+
			"the corpus has shrunk; compile's TestEveryFindEmitterIsCovered says "+
			"which emitter is now unreached", len(byFingerprint), minBodies)
	}
}

// ---------------------------------------------------------------------------
// helpers

type findState int

const (
	findMatch findState = iota
	findNone
	findHang
	findOverflow
)

// findCaller instantiates wasmBytes once and returns a closure that calls its
// find export at a given `from`. One instance for the whole sweep: these tests
// make O(len) calls per shape, and re-instantiating per call would dominate.
func findCaller(t *testing.T, wasmBytes []byte, input string) (func(int) ([2]int, findState), func(), bool) {
	t.Helper()
	engine, wd := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		mod.Close()
		t.Fatalf("instantiate: %v", err)
	}
	findFn := inst.GetFunc(store, "find")
	memExp := inst.GetExport(store, "memory")
	if findFn == nil || memExp == nil || memExp.Memory() == nil {
		mod.Close()
		store.Close()
		return nil, nil, false
	}
	copy(memExp.Memory().UnsafeData(store), input)

	call := func(from int) ([2]int, findState) {
		wd.Arm(store)
		r, err := findFn.Call(store, int32(0), int32(len(input)), int32(from))
		wd.Disarm()
		if err != nil {
			if isTimeout(err) {
				return [2]int{}, findHang
			}
			t.Fatalf("find(from=%d): %v", from, err)
		}
		v := r.(int64)
		switch v {
		case abi.BTStackOverflow:
			return [2]int{}, findOverflow
		case abi.NoMatch:
			return [2]int{}, findNone
		}
		return [2]int{int(uint32(v >> 32)), int(uint32(v))}, findMatch
	}
	return call, func() { store.Close(); mod.Close() }, true
}

// localsFingerprint renders every function's locals declaration in a module,
// which is a stable proxy for "which emitter produced this body" — the
// emitters differ in exactly that vector.
func localsFingerprint(w []byte) (string, error) {
	sec, err := wasmSection(w, 10) // code
	if err != nil {
		return "", err
	}
	n, p := uleb(sec, 0)
	var parts []string
	for i := uint32(0); i < n; i++ {
		size, np := uleb(sec, p)
		p = np
		end := p + int(size)
		if end > len(sec) {
			return "", fmt.Errorf("code entry %d overruns section", i)
		}
		groups, q := uleb(sec, p)
		var decl []string
		for g := uint32(0); g < groups; g++ {
			cnt, nq := uleb(sec, q)
			q = nq
			if q >= len(sec) {
				return "", fmt.Errorf("code entry %d: truncated locals", i)
			}
			decl = append(decl, fmt.Sprintf("%d%s", cnt, valType(sec[q])))
			q++
		}
		parts = append(parts, strings.Join(decl, "+"))
		p = end
	}
	return strings.Join(parts, "|"), nil
}

func valType(b byte) string {
	switch b {
	case 0x7F:
		return "i32"
	case 0x7E:
		return "i64"
	case 0x7B:
		return "v128"
	}
	return fmt.Sprintf("t%02x", b)
}

func wasmSection(w []byte, id byte) ([]byte, error) {
	p := 8
	for p < len(w) {
		sid := w[p]
		p++
		size, np := uleb(w, p)
		p = np
		if p+int(size) > len(w) {
			return nil, fmt.Errorf("section %d overruns module", sid)
		}
		if sid == id {
			return w[p : p+int(size)], nil
		}
		p += int(size)
	}
	return nil, fmt.Errorf("section %d not found", id)
}

func uleb(b []byte, p int) (uint32, int) {
	var r uint32
	var s uint
	for p < len(b) {
		r |= uint32(b[p]&0x7F) << s
		p++
		if b[p-1]&0x80 == 0 {
			return r, p
		}
		s += 7
	}
	return r, p
}
