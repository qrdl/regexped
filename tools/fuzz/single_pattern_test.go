package fuzz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/searchblock"
)

// Single-pattern ITERATION coverage.
//
// Everything else in this package checks ONE match: fuzz_targets_test.go compares a
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
// way.
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
	return wasmFindIterMode(t, wasmBytes, nil, input, searchblock.Off)
}

// wasmFindIterMode is wasmFindIter with the per-search block handed over the
// way mode says; sizes is what the find export's searches keep.
func wasmFindIterMode(t *testing.T, wasmBytes []byte, sizes []searchblock.Size, input string, mode searchblock.Mode) ([][2]int, bool) {
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
	sr, err := newSearchRegion(store, inst, mem, len(input), sizes, mode)
	if err != nil {
		t.Fatalf("search region: %v", err)
	}
	if err := sr.begin(store); err != nil {
		t.Fatalf("search block: %v", err)
	}

	var out [][2]int
	pos, prevEnd := 0, -1
	for pos <= len(input) {
		sr.before(store)
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
		if err := sr.after(store); err != nil {
			t.Fatalf("search block: %v", err)
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
	unicodeSeeds(f)
	f.Fuzz(func(t *testing.T, pat, input string) {
		if len(input) > inputCap || len(pat) > 120 {
			t.Skip()
		}
		// In byte mode `.` consumes one byte, and iteration steps past an
		// empty match by one byte where Go steps by one rune (docs/sets.md,
		// "The empty-match rule"). Over non-ASCII input the two disagree by
		// design, so the oracle cannot judge it — the same skip
		// FuzzCorrectness makes. Unicode mode reads runes as Go does.
		if unicodeModeOutOfScope(pat, input) != "" || !*unicodeMode && hasUnsupportedUnicode(input) {
			t.Skip()
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Skip()
		}
		// Same guards the other targets use: an oversized NFA blows the fuzz
		// worker's 10s hang deadline, and a pattern naming a code point above
		// 0x7F is out of scope here (see namedRuneCeiling).
		parsed, perr := syntax.Parse(pat, syntax.Perl)
		if perr != nil {
			t.Skip()
		}
		if prog, cerr := syntax.Compile(parsed.Simplify()); cerr == nil && len(prog.Inst) > maxNFAInsts() {
			t.Skip()
		}
		if namedRuneCeiling(pat, parsed) > 0x7F && !*unicodeMode {
			t.Skip()
		}
		w, sizes, err := compileFindSized(pat)
		if err != nil {
			// The rune gate refusing a pattern that names nothing above ASCII is
			// a compiler defect, not a reason to skip.
			if strings.Contains(err.Error(), "pattern contains the") {
				t.Fatalf("rune gate refused an ASCII pattern: pat=%q: %v", pat, err)
			}
			t.Skip()
		}
		want := goFindAll(re, input)
		// Both copies of a find that keeps per-search notes: the ordinary one a
		// fresh block runs, and the MARKED one a block armed before the first
		// call forces — a wrong note is a missed match, silently.
		for _, mode := range []searchblock.Mode{searchblock.Off, searchblock.Fresh, searchblock.Armed} {
			got, ok := wasmFindIterMode(t, w, sizes, input, mode)
			if !ok {
				t.Skip()
			}
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("find iteration (%s) diverges from Go\n  pattern %q\n  input   %q\n  got  %s\n  want %s",
					mode, pat, input, fmtSpans(got), fmtSpans(want))
			}
		}
	})
}

// The groups half of the find-from channel. The find export now takes a `from`
// position; groups and named_groups still NARROW, so a leading \b, \B or
// (?m:^) is judged against the slice edge on every re-entry.
//
// Nothing covered this before: FuzzGroups is ONE-SHOT (a single call compared
// to a single FindStringSubmatchIndex), and custom-tests.txt has exactly ONE
// row carrying a real col6 value. So the groups path could be converted with
// no way to tell whether it worked.

// groupsIterSeeds: one shape per concern. The leading-assertion cases are the
// ones narrowing gets wrong; the plain ones guard against a conversion
// breaking the ordinary path.
var groupsIterSeeds = []struct {
	pat, input string
}{
	{`(a)`, "aXaXa"},
	{`(a*)`, "bab"},
	{`([a-z]+)@([a-z]+)`, "x@y z@w"},
	// leading zero-width assertions — the (A) shapes
	{`\b(foo)`, "foofoo"},
	{`\B(foo)`, "xfoofoo"},
	{`\B(a)`, "aaa"},
	{`(?m:^)(a)`, "a\naa"},
	// begin-anchored: a match can only start at 0, so iteration must stop
	{`\A(a)(b)`, "abab"},
	{`^(abc)`, "abcabc"},
}

func goGroupsAll(re *regexp.Regexp, input string) [][]int {
	return re.FindAllStringSubmatchIndex(input, -1)
}

func fmtGroups(all [][]int) string {
	if len(all) == 0 {
		return "(none)"
	}
	out := ""
	for i, m := range all {
		if i > 0 {
			out += " | "
		}
		for j := 0; j+1 < len(m); j += 2 {
			if j > 0 {
				out += ","
			}
			out += fmt.Sprintf("%d-%d", m[j], m[j+1])
		}
	}
	return out
}

// runGroupsIter models the generated stubs' groups loop exactly, including
// Go's adjacent-empty suppression rule (half B, already shipped).
func runGroupsIter(t *testing.T, w []byte, input string, numGroups int) ([][]int, bool) {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	// Every call of a Backtracking capture body needs run-time scratch; with the
	// global at 0 each one would take fresh pages.
	if err := setScratchBase(store, inst, int32(pathsTableBase)); err != nil {
		t.Fatal(err)
	}
	fn := inst.GetFunc(store, "groups")
	if fn == nil {
		t.Fatal("module has no groups export")
	}
	copy(mem.UnsafeData(store)[pathsInputBase:], input)

	_, wd := sharedEngine()
	slots := numGroups * 2
	var out [][]int
	pos, prevEnd := 0, -1
	for pos <= len(input) {
		wd.Arm(store)
		// The WHOLE buffer plus a start position, which is what every
		// generated groups stub now passes.
		res, callErr := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(pos))
		wd.Disarm()
		if callErr != nil {
			if isTimeout(callErr) {
				return nil, false
			}
			t.Fatalf("groups call: %v", callErr)
		}
		r := res.(int32)
		if r == int32(abiBTOverflow) {
			return nil, false
		}
		if r < 0 {
			if pos == len(input) {
				break
			}
			pos++
			continue
		}
		buf := mem.UnsafeData(store)
		m := make([]int, slots)
		for i := 0; i < slots; i++ {
			v := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
			if v < 0 {
				m[i] = -1
			} else {
				m[i] = int(v) // absolute already
			}
		}
		absStart, absEnd := m[0], m[0]
		if m[1] >= 0 {
			absEnd = m[1]
		}
		if absEnd > absStart {
			pos = absEnd
		} else {
			pos = absStart + 1
		}
		if absStart == absEnd && prevEnd == absStart {
			continue
		}
		prevEnd = absEnd
		out = append(out, m)
	}
	return out, true
}

const abiBTOverflow = -2

func TestGroupsIterationMatchesGo(t *testing.T) {
	for _, c := range groupsIterSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileGroups(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := runGroupsIter(t, w, c.input, re.NumSubexp()+1)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}

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
//     (TestSimplePrefixCheckHonoursFrom).
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
	// Start-anchored Backtracking finds (an ambiguous word boundary keeps
	// them off the DFA): a search from any position after 0 answers "no
	// match" at once. The first has a zero-width cycle, so its find is the
	// fallback alone.
	{"bt_find_start_anchored", `^(\B|0)*`, "00 0a 00"},
	{"bt_find_start_anchored_fast", `^(?:x\B|x)y`, "xy xy xxy"},
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

	// LikelyNoMatch-only emitters. buildSimplePrefixCheckBody is that
	// regression's owner: two matches within M bytes put the second call's
	// candidate inside the first's backward window.
	// Unbounded self-loop before a mandatory literal: the shape whose DFA
	// never dies, and the one overlapping find's preflight exists for.
	{"dominant_selfloop", `[^\n]*ERROR`, "aa ERROR bb\ncc ERROR dd"},
	// Bounded variable-length prefix — recovery is c - prefixMaxLen, which is
	// why it cannot use the prefix.literal.suffix split.
	{"varlen_prefix", `a{0,2}XYZQ`, "q aXYZQ w aaXYZQ e XYZQ"},
	// Literal chain with an alternation SUFFIX rather than an alternation of
	// chains — a different body from both alt paths above.
	{"chain_alt_suffix", `q[a-f]{24}(?:AA|BB)`,
		"qabcdefabcdefabcdefabcdAA qffffffffffffffffffffffffBB"},

	{"lnm_simple_prefix", `[0-9]{4}MARKER`, "1234MARKER5678MARKERyy"},
	{"lnm_lit_anchor", `[a-f]{6}TAIL`, "abcdefTAILabcdefTAIL"},
	{"lnm_lit_chain", `AKIA[A-Z0-9]{16}`, "AKIA0123456789ABCDEF AKIAFEDCBA9876543210"},
	// A one-byte inner literal behind a wide leading repeat: the literal-
	// anchored find with the counter that charges every failed candidate —
	// matches, near misses, and a run dense enough to hand over.
	{"one_byte_lit_anchor", `[a-z]+-[0-9]+`, "not-a-log-line ab-12 x-y-z-9 " + strings.Repeat("q-r-", 40) + "end-7"},
	{"one_byte_lit_anchor_email", `[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}`, "a@b x.y@ex-ample.com @@ q@r.st @x.yy"},
	{"one_byte_lit_anchor_space", `\w+ \w+`, "ab cd  ef gh-ij kl mn_op qr"},

	// Six shapes added after an emitter-reach check reported that the
	// emitters below were reached by NOTHING — not by this corpus and
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
	w, _, err := compileFindShapeSized(name, pat)
	return w, err
}

// compileFindShapeSized is compileFindShape plus what the find export's
// searches keep.
func compileFindShapeSized(name, pat string) ([]byte, []searchblock.Size, error) {
	if findFromLNM[name] {
		return compileFindOpts("findlnm\x00"+pat, pat, pathsTableBase,
			compile.CompileOptions{LikelyMode: compile.LikelyNoMatch})
	}
	if n, ok := findFromMaxStates[name]; ok {
		return compileFindOpts(fmt.Sprintf("findmax%d\x00%s", n, pat), pat, pathsTableBase,
			compile.CompileOptions{MaxDFAStates: n})
	}
	return compileFindSized(pat)
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
// The probe counts Go's TOKENS — `(?s:.)` reads an invalid byte as a one-byte
// U+FFFD — so it skips the tokens before s, and a position that starts no
// token (inside a character) can start no match: -1, which is Unicode mode's
// rule. Over ASCII the two counts coincide, which is what byte mode needs.
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
	starts := goTokenStarts(input)
	out := make([]int, len(input)+1)
	tokens := 0
	for s := range out {
		out[s] = -1
		if !starts[s] {
			continue
		}
		probe, err := regexp.Compile(`\A(?s:.{` + strconv.Itoa(tokens) + `})(?:` + pat + `)`)
		if err != nil {
			t.Skipf("Go rejects probe for %q at %d: %v", pat, s, err)
		}
		if m := probe.FindStringIndex(input); m != nil {
			out[s] = m[1]
		}
		tokens++
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
	for _, mode := range []searchblock.Mode{searchblock.Off, searchblock.Fresh, searchblock.Armed} {
		n := notesGiven.Load()
		t.Run(mode.String(), func(t *testing.T) { testFindFromStartsAtOrAfterFrom(t, mode) })
		if mode == searchblock.Armed && notesGiven.Load() == n {
			t.Error("the armed run gave no drive notes: the marked copies went unchecked")
		}
	}
}

func testFindFromStartsAtOrAfterFrom(t *testing.T, mode searchblock.Mode) {
	for _, c := range findFromShapes {
		t.Run(c.name, func(t *testing.T) {
			if _, err := regexp.Compile(c.pat); err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, sizes, err := compileFindShapeSized(c.name, c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := findCallerMode(t, w, sizes, c.input, mode, true)
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
	for _, mode := range []searchblock.Mode{searchblock.Off, searchblock.Fresh, searchblock.Armed} {
		t.Run(mode.String(), func(t *testing.T) { testFindFromIterationTerminates(t, mode) })
	}
}

func testFindFromIterationTerminates(t *testing.T, mode searchblock.Mode) {
	for _, c := range findFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, sizes, err := compileFindShapeSized(c.name, c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := findCallerMode(t, w, sizes, c.input, mode, false)
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
// TestEveryEmitterIsReachedBySweeps (fuzz_targets_test.go, run by `make
// from-coverage`) is the authority: it lists every find and capture emitter
// from the compile package's own source and checks, against the coverage
// profile of these sweeps, that each was reached, so it can name the emitter
// that is missing. Keep this test for what it does cheaply — noticing the
// corpus shrinking — and fix coverage gaps there.
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
	// comment, and TestEveryEmitterIsReachedBySweeps for that claim.
	const minBodies = 12
	if len(byFingerprint) < minBodies {
		t.Errorf("find-from shapes reach only %d distinct find bodies, want >= %d — "+
			"the corpus has shrunk; `make from-coverage` (TestEveryEmitterIsReachedBySweeps) "+
			"says which emitter is now unreached", len(byFingerprint), minBodies)
	}
}

// ---------------------------------------------------------------------------
// Unicode mode: where a match may start
//
// In Unicode mode no match starts, and no empty match is reported, inside a
// character: the start positions are exactly where Go's decoding starts a
// token — a valid UTF-8 sequence's first byte, or any byte of invalid input,
// which Go reads as a one-byte U+FFFD. A lowered program consumes only whole
// characters, so only a pattern that can match EMPTY could start anywhere
// else, and only those are here: each reaches one of the find bodies such a
// pattern can reach (TestUnicodeFindShapesReachTheirBodies), and is driven
// from every byte position, inside characters included, over inputs with 2-,
// 3- and 4-byte characters — first, last, alone, adjacent, between ASCII —
// and over invalid input: stray continuation bytes, sequences cut off at 2, 3
// and 4 bytes, overlong and surrogate encodings, bytes no sequence starts
// with.
//
// Invalid input is compared with Go only for a pattern that cannot match
// U+FFFD (canMatchReplacement): in Unicode mode an invalid byte matches
// nothing, RE2's rule, where Go matches it as U+FFFD — the one designed
// difference (docs/re2.md). Every other pattern answers exactly as Go does
// there too, start positions included.

var unicodeStartInputs = []string{
	"", "abc", "é", "ж", "日", "😀", "aé", "éa", "ééé", "a日b", "日本", "😀😀", "x😀y",
	"αβγ δ", "a é b", "é b 日 c 😀", "aa\nжж\n", "é\n",
	// Invalid: stray continuation bytes.
	"\x80", "\x80\x80", "a\x80b", "é\x80", "\x80é", "\xbf\xbf\xbf\xbf",
	// Cut off: 2-, 3- and 4-byte sequences missing their tail.
	"\xc3", "a\xc3", "\xc3a", "\xe2\x82", "a\xe2\x82b", "\xe2\x82é", "\xf0\x9f\x98", "\xf0\x9f\x98a", "日\xe6\x97",
	// Overlong, surrogate, past U+10FFFF, never a lead.
	"\xc0\xaf", "\xe0\x80\xaf", "\xed\xa0\x80", "a\xed\xa0\x80b", "\xf4\x90\x80\x80", "\xff", "é\xffé", "\xf5\x80",
	// A match right after an invalid byte: the start-anywhere find restarts
	// at every byte, invalid ones included.
	"\xffaé", "a\x80bé", "\xe2\x82wé x", "\xff\xffжж",
	// Multi-byte literals for the literal-anchored finds: found, cut off,
	// after an invalid byte, and twice.
	"мы@пример", "x@пример@пример", "@приме", "\xffя@пример", "xxxкотabz yyyпёсz", "кот", "yyyпёс9z",
	// Literals that begin with a non-ASCII character, for the prefix scan's
	// whole-first-character check: the literal after a run of characters
	// sharing its lead byte (о is 0xD0 0xBE, п 0xD0 0xBF) long enough that the
	// start positions put it at every lane of a 16-byte chunk; near misses;
	// cut off; after an invalid byte; a 3-byte script.
	"ооооооооооооооооприветмир", "при привык привет мир", "ппривет", "привет",
	"прив", "12привет", "ab\xffпривет", "приве\xd0", "東京タワー東京", "東京タワ", "x東京タワーy",
	// One-byte literals among multi-byte text.
	"пользователь@пример.рф", "é@ж.日本 @@ a@b.cd", "x@@y.zz", "@\xffж@ю.яя", "日本@語.テキ",
}

// unicodeFindShapes are Unicode-mode finds that can match empty, each with
// the body it must reach ("body": text the pattern's --verbose report shows),
// and the two start-anywhere finds' shapes that cannot: their forward pass
// restarts at EVERY byte, invalid ones included, which is how a match after
// an invalid byte is found at all.
var unicodeFindShapes = []struct {
	name, pat string
	maxStates int  // 0: the default
	fallback  bool // Backtracking's memoised fallback answers every call
	body      string
}{
	{"star", `a*`, 0, false, "Compiled DFA"},
	{"empty", `(?:)`, 0, false, "Compiled DFA"},
	{"quest", `x?`, 0, false, "Compiled DFA"},
	{"word-boundary", `\b`, 0, false, "Compiled DFA"},
	{"no-word-boundary", `\B`, 0, false, "Compiled DFA"},
	{"line-begin", `(?m)^`, 0, false, "Compiled DFA"},
	{"line-end", `(?m)$`, 0, false, "Compiled DFA"},
	{"text-begin", `\A`, 0, false, "matches only at 0"},
	{"text-end", `\z`, 0, false, "Compiled DFA"},
	{"begin", `^`, 0, false, "matches only at 0"},
	{"end", `$`, 0, false, "Compiled DFA"},
	{"alt-a-no-boundary", `a|\B`, 0, false, "Compiled DFA"},
	{"alt-boundary-e", `\b|é`, 0, false, "Compiled DFA"},
	{"alt-quest-ri", `x?|日`, 0, false, "Compiled DFA"},
	{"alt-no-boundary-plus", `\B|a+`, 0, false, "Compiled DFA"},
	{"quest-no-boundary", `é?\B`, 0, false, "Compiled DFA"},
	{"no-boundary-letter", `\B\pL?`, 0, false, "find: today"},
	{"letters", `\pL*`, 0, false, "u16 state ids"},
	// Matches U+FFFD, so it is compared with Go on valid input only.
	{"negated-class", `[^a]*`, 0, false, "Compiled DFA"},
	{"letter-pairs", `(?:\pL\pL)*`, 0, false, "u16 state ids"},
	// Not `(?:é|a)*\b`: a leading repeat of a class holding a character
	// above 0x7F counts as common in text and takes the start-anywhere find
	// alone; an alternation of a character and a pair keeps the switch.
	{"switch-start-anywhere", `(?:é|ab)*\b`, 0, false, "find: switch"},
	{"switch-backtracking", `(?:é|a)*\B`, 0, false, "switch handover: Backtracking"},
	{"start-anywhere", `\pL*\b`, 0, false, "find: start-anywhere"},
	{"start-anywhere-restart", `\w+[éж]`, 0, false, "find: start-anywhere"},
	{"lit-anchor-restart", `\w+é`, 0, false, "literal-anchored find"},
	{"start-anywhere-restart-context", `\pL+\b`, 0, false, "find: start-anywhere"},
	{"bt-no-boundary", `\B`, 1, false, "Backtracking"},
	{"bt-letters", `\pL*`, 1, false, "Backtracking"},
	{"bt-fallback-no-boundary", `\B`, 1, true, "Backtracking"},
	{"bt-fallback-letters", `\pL*\b`, 1, true, "Backtracking"},
	{"lit-anchor-utf8", `[а-я]+@пример`, 0, false, "literal-anchored find"},
	{"alt-lit-anchor-utf8", `x{3}кот\w*z|y{3}пёс\w*z`, 0, false, "alternation literal-anchored find"},
	// The prefix scan checks a literal's whole first character on a hit,
	// through each body that scans for a literal.
	{"char-probe-dfa", `привет\s*\pL+`, 0, false, "first character checked on a hit"},
	{"char-probe-literal", `привет`, 0, false, "Compiled DFA"},
	{"char-probe-cjk", `東京タワー`, 0, false, "Compiled DFA"},
	{"char-probe-mandatory", `\d{0,3}привет`, 0, false, "mandatory literal extracted"},
	{"char-probe-lit-anchor", `[a-z]+привет`, 0, false, "literal-anchored find"},
	{"char-probe-bt", `привет\s*\pL+`, 1, false, "Backtracking"},
	// A one-byte inner literal behind a wide leading repeat, on tables past
	// 256 states (u16 ids).
	{"lit-anchor-u16-email", `[\pL\pN._%+-]+@[\pL\pN-]+\.\pL{2,}`, 0, false, "literal-anchored find"},
	{"lit-anchor-u16-letters", `\pL+@\pL+`, 0, false, "u16 state ids"},
}

func unicodeFindOpts(maxStates int, fallback bool) compile.CompileOptions {
	o := compile.CompileOptions{Unicode: true, MaxDFAStates: maxStates}
	if fallback {
		o.BTWorkBudget = compile.BTWorkBudgetForceFallback
	}
	return o
}

func compileUnicodeFindShape(pat string, maxStates int, fallback bool) ([]byte, []searchblock.Size, error) {
	return compileFindOpts(fmt.Sprintf("findutf8\x00%d\x00%v\x00%s", maxStates, fallback, pat), pat, pathsTableBase,
		unicodeFindOpts(maxStates, fallback))
}

// goTokenStarts reports, for every position of input and its end, whether
// Go's decoding starts a token there.
func goTokenStarts(input string) []bool {
	out := make([]bool, len(input)+1)
	for i := 0; i < len(input); {
		out[i] = true
		_, w := utf8.DecodeRuneInString(input[i:])
		i += w
	}
	out[len(input)] = true
	return out
}

// canMatchReplacement reports whether pat has a rune instruction U+FFFD
// satisfies: the patterns whose answers on invalid input differ from Go's by
// design.
func canMatchReplacement(pat string) bool {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return false
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return false
	}
	for _, in := range prog.Inst {
		switch in.Op {
		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			return true
		case syntax.InstRune, syntax.InstRune1:
			if in.MatchRune(utf8.RuneError) {
				return true
			}
		}
	}
	return false
}

// TestUnicodeFindFromStartPositions drives every Unicode shape from every
// byte position of every input, and through the iteration a stub runs, in
// all three search-block modes — the default state's continuation window
// (Off), a fresh block per search, and a block armed with notes before its
// first call, whose resume point is carried across the calls of a drive.
func TestUnicodeFindFromStartPositions(t *testing.T) {
	// The answer the plan pins: Go's empty matches of `a*` over "é".
	w, sizes, err := compileUnicodeFindShape(`a*`, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	call, done, ok := findCallerMode(t, w, sizes, "é", searchblock.Fresh, false)
	if !ok {
		t.Fatal("module would not instantiate")
	}
	var got [][2]int
	for off := 0; off <= 2; {
		sp, state := call(off)
		if state != findMatch {
			break
		}
		got = append(got, sp)
		off = sp[1] + 1
	}
	done()
	if want := [][2]int{{0, 0}, {2, 2}}; fmtSpanList(got) != fmtSpanList(want) {
		t.Errorf("a* over \"é\": got %s, want %s", fmtSpanList(got), fmtSpanList(want))
	}

	for _, mode := range []searchblock.Mode{searchblock.Off, searchblock.Fresh, searchblock.Armed} {
		n := notesGiven.Load()
		t.Run(mode.String(), func(t *testing.T) {
			skipped := 0
			for _, c := range unicodeFindShapes {
				t.Run(c.name, func(t *testing.T) {
					re := regexp.MustCompile(c.pat)
					w, sizes, err := compileUnicodeFindShape(c.pat, c.maxStates, c.fallback)
					if err != nil {
						t.Fatalf("compile %q: %v", c.pat, err)
					}
					engine, _ := sharedEngine()
					mod, err := wasmtime.NewModule(engine, w)
					if err != nil {
						t.Fatalf("module: %v", err)
					}
					defer mod.Close()
					for _, in := range unicodeStartInputs {
						if !utf8.ValidString(in) && canMatchReplacement(c.pat) {
							skipped++
							continue
						}
						checkUnicodeFindFrom(t, c.pat, mod, sizes, in, mode)
						checkUnicodeFindIteration(t, re, mod, sizes, in, mode)
					}
				})
			}
			if skipped == 0 {
				t.Error("no input was skipped as invalid UTF-8 for a pattern that can match U+FFFD: the skip rule went unexercised")
			}
		})
		if mode == searchblock.Armed && notesGiven.Load() == n {
			t.Error("the armed run gave no drive notes: the notes' resume point went unchecked")
		}
	}
}

func checkUnicodeFindFrom(t *testing.T, pat string, mod *wasmtime.Module, sizes []searchblock.Size, in string, mode searchblock.Mode) {
	t.Helper()
	call, done, ok := findCallerModule(t, mod, sizes, in, mode, true)
	if !ok {
		t.Fatal("module would not instantiate")
	}
	defer done()
	ends := endsAt(t, pat, in)
	for from := 0; from <= len(in); from++ {
		got, state := call(from)
		if state == findHang || state == findOverflow {
			t.Fatalf("%q from=%d: state %d", in, from, state)
		}
		want, wantOK := goFirstFrom(ends, from)
		switch {
		case state == findNone && wantOK:
			t.Errorf("%q from=%d: got -1, want [%d,%d)", in, from, want[0], want[1])
		case state == findMatch && !wantOK:
			t.Errorf("%q from=%d: got [%d,%d), want -1", in, from, got[0], got[1])
		case state == findMatch && got != want:
			t.Errorf("%q from=%d: got [%d,%d), want [%d,%d)", in, from, got[0], got[1], want[0], want[1])
		}
	}
}

// checkUnicodeFindIteration runs a stub's drive — advance to the match's end,
// or one byte past an empty match, and drop an empty match where the last one
// ended — and compares it with Go's FindAllStringIndex.
func checkUnicodeFindIteration(t *testing.T, re *regexp.Regexp, mod *wasmtime.Module, sizes []searchblock.Size, in string, mode searchblock.Mode) {
	t.Helper()
	call, done, ok := findCallerModule(t, mod, sizes, in, mode, false)
	if !ok {
		t.Fatal("module would not instantiate")
	}
	defer done()
	var got [][2]int
	off, prevEnd := 0, -1
	for steps := 0; off <= len(in); steps++ {
		if steps > 4*len(in)+16 {
			t.Fatalf("%q: iteration did not terminate", in)
		}
		sp, state := call(off)
		if state == findHang || state == findOverflow {
			t.Fatalf("%q off=%d: state %d", in, off, state)
		}
		if state == findNone {
			break
		}
		if !(sp[0] == sp[1] && sp[0] == prevEnd) {
			got = append(got, sp)
			prevEnd = sp[1]
		}
		off = max(sp[1], off+1)
	}
	var want [][2]int
	for _, m := range re.FindAllStringIndex(in, -1) {
		want = append(want, [2]int{m[0], m[1]})
	}
	if fmtSpanList(got) != fmtSpanList(want) {
		t.Errorf("iteration over %q:\n  got  %s\n  want %s", in, fmtSpanList(got), fmtSpanList(want))
	}
}

// TestUnicodeFindShapesReachTheirBodies fails when a shape stops reaching the
// find body it is in unicodeFindShapes for, so the start-position tests keep
// driving every body a Unicode pattern that can match empty reaches.
func TestUnicodeFindShapesReachTheirBodies(t *testing.T) {
	for _, c := range unicodeFindShapes {
		rep := &compile.Reporter{}
		o := unicodeFindOpts(c.maxStates, c.fallback)
		o.Report = rep
		if _, _, err := compile.Compile([]config.RegexEntry{{Name: c.name, Pattern: c.pat, FindFunc: "find"}}, pathsTableBase, true, o); err != nil {
			t.Fatalf("%s: compile: %v", c.name, err)
		}
		var b strings.Builder
		rep.Render(&b)
		if !strings.Contains(b.String(), c.body) {
			t.Errorf("%s (%q) no longer reaches %q:\n%s", c.name, c.pat, c.body, b.String())
		}
	}
}

// characterRunShapes are Unicode-mode finds with a state that loops on every
// character, which the find body crosses 16 bytes at a time with the UTF-8
// bulk skip; body is text their --verbose report shows ("" for a shape whose
// skip is in the start-anywhere forward pass, which the report does not name).
var characterRunShapes = []struct{ name, pat, body string }{
	{"negated-class", `[^,]+,`, "over whole UTF-8 characters"},
	{"dot", `.+`, "over whole UTF-8 characters"},
	{"not-newline", `[^\n]+`, "over whole UTF-8 characters"},
	{"dot-all", `(?s).+`, "over whole UTF-8 characters"},
	{"delimited", `x[^y]*y`, "over whole UTF-8 characters"},
	{"accepting-tail", `a.*`, "over whole UTF-8 characters"},
	{"two-exits", `"[^"\\]*"`, "over whole UTF-8 characters"},
	{"line-end", `(?m)[^,]+$`, "over whole UTF-8 characters"},
	{"two-loops", `[^,]+[^ab]*,`, "over whole UTF-8 characters"},
	{"after-literal", `=.+`, "over whole UTF-8 characters"},
	// The switch's start-anywhere forward pass, reached on the inputs whose
	// overlapping walks die far from where they started (characterRunInputs).
	{"forward-pass", `[ab]+[^z]*z`, "find: switch"},
}

// checkUnicodeCharacterRunMatch drives pat's match body, which crosses its
// loop with the skip over whole UTF-8 characters too, over every prefix of each
// input that ends just after an exit byte — where a full match can end — and
// over the whole input, against Go's full match of oracle.
func checkUnicodeCharacterRunMatch(t *testing.T, pat, oracle string, inputs []string) {
	t.Helper()
	w, _, err := compile.Compile([]config.RegexEntry{{Pattern: pat, MatchFunc: "match"}}, pathsTableBase, true, compile.CompileOptions{Unicode: true})
	if err != nil {
		t.Fatalf("compile %q: %v", pat, err)
	}
	// The validity check's first table, emitted once per skip site.
	sig := []byte{0xFD, 0x0C, 2, 2, 2, 2, 2, 2, 2, 2, 128, 128, 128, 128, 33, 1, 21, 73}
	if !bytes.Contains(w, sig) {
		t.Fatalf("%q: the match body takes no skip over whole characters", pat)
	}
	full := regexp.MustCompile(`\A(?:` + oracle + `)\z`)
	for _, in := range inputs {
		cuts := []int{len(in)}
		for i := 0; i < len(in); i++ {
			if strings.IndexByte(",\n\"y>&z", in[i]) >= 0 {
				cuts = append(cuts, i+1)
			}
		}
		for _, cut := range cuts {
			s := in[:cut]
			end, ok, hang, err := runWasmMatch(w, s)
			if err != nil || hang {
				t.Fatalf("%q over %q: err %v, hang %v", pat, s, err, hang)
			}
			if want := full.MatchString(s); ok != want || ok && end != len(s) {
				t.Errorf("%q match over %q: got (%d, %v), want %v", pat, s, end, ok, want)
			}
		}
	}
}

// characterRunGroupsShapes are Unicode-mode captures whose TDFA capture body
// has such a loop — a group of states with identical rows — and crosses it
// with the UTF-8 skip from the arms where the walk enters it, or, with no tag
// ops at all (`()[^,]+,`), from the top of its main loop.
var characterRunGroupsShapes = []string{
	`<([^>]+)>(x)`, `(.+)=(.+)`, `([^,]+)(,)`, `(\w+)=([^&]+)&`, `()[^,]+,`, `^([^,]+)`, `x([^y]*)y`, `"([^"\\]*)"`,
}

// noReplacement returns pat with U+FFFD taken out of every class and of `.`:
// Go's regexp then matches an invalid byte — which it decodes as U+FFFD — with
// nothing, as Unicode mode does, so it is an oracle for invalid input too, on
// any input that holds no real U+FFFD.
func noReplacement(t *testing.T, pat string) string {
	t.Helper()
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	without := func(rs []rune) []rune {
		var out []rune
		for i := 0; i+1 < len(rs); i += 2 {
			lo, hi := rs[i], rs[i+1]
			if lo <= utf8.RuneError && utf8.RuneError <= hi {
				if lo < utf8.RuneError {
					out = append(out, lo, utf8.RuneError-1)
				}
				if hi > utf8.RuneError {
					out = append(out, utf8.RuneError+1, hi)
				}
				continue
			}
			out = append(out, lo, hi)
		}
		return out
	}
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpAnyChar:
			r.Op, r.Rune = syntax.OpCharClass, without([]rune{0, utf8.MaxRune})
		case syntax.OpAnyCharNotNL:
			r.Op, r.Rune = syntax.OpCharClass, without([]rune{0, '\n' - 1, '\n' + 1, utf8.MaxRune})
		case syntax.OpCharClass:
			r.Rune = without(r.Rune)
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return re.String()
}

// characterRunInputs mixes long runs of 1- to 4-byte characters with the
// shapes' exit bytes and every kind of invalid sequence — a stray byte, an
// overlong, a surrogate, a sequence cut short, a lead past U+10FFFF — so the
// skip meets each of its stops at every lane of a chunk: an exit, an error,
// a character the chunk cuts, and the end of the input.
func characterRunInputs() []string {
	r := rand.New(rand.NewSource(20261006))
	chars := []string{"a", "b", "x", "y", "=", " ", "é", "ж", "ω", "東", "タ", "😀", "𝄞"}
	exits := []string{",", "\n", "\"", "\\", "y", "<", ">", "&"}
	invalid := []string{"\xff", "\x80", "\xc0\x80", "\xed\xa0\x80", "\xe2\x82", "\xf0\x9f\x98", "\xf5\x80\x80\x80", "\xf4\x90\x80\x80", "\xc2"}
	var out []string
	for i := 0; i < 60; i++ {
		var b strings.Builder
		width := r.Intn(5) // 0: any character; 1-4: only characters of that width
		for b.Len() < 40+r.Intn(160) {
			for n := r.Intn(40); n > 0; n-- {
				c := chars[r.Intn(len(chars))]
				for width != 0 && len(c) != width {
					c = chars[r.Intn(len(chars))]
				}
				b.WriteString(c)
			}
			switch r.Intn(4) {
			case 0:
				b.WriteString(exits[r.Intn(len(exits))])
			case 1:
				b.WriteString(invalid[r.Intn(len(invalid))])
			}
		}
		out = append(out, b.String())
	}
	// Twenty overlapping walks that each die at an invalid byte a hundred
	// characters on trip the switch's work counter, and the forward pass finds
	// the match after them.
	for _, run := range []string{"ж", "東", "😀", "aé"} {
		for _, bad := range []string{"\xff", "\xe2\x82", "\xed\xa0\x80"} {
			unit := strings.Repeat("a", 20) + strings.Repeat(run, 100) + bad
			out = append(out, strings.Repeat(unit, 4)+"b"+strings.Repeat("東", 30)+"z"+strings.Repeat("ω", 20))
		}
	}
	return out
}

// TestUnicodeCharacterRunSkip drives every characterRunShapes pattern from
// every start position, and through a stub's iteration, in all three
// search-block modes, and its match body; and every characterRunGroupsShapes
// pattern through the groups iteration — all against Go over the same pattern
// without U+FFFD.
func TestUnicodeCharacterRunSkip(t *testing.T) {
	inputs := characterRunInputs()
	for _, in := range inputs {
		if strings.Contains(in, "\uFFFD") {
			t.Fatalf("input holds a real U+FFFD, which the oracle cannot judge: %q", in)
		}
	}
	for _, c := range characterRunShapes {
		t.Run(c.name, func(t *testing.T) {
			rep := &compile.Reporter{}
			opts := compile.CompileOptions{Unicode: true, Report: rep}
			if _, _, err := compile.Compile([]config.RegexEntry{{Name: c.name, Pattern: c.pat, FindFunc: "find"}}, pathsTableBase, true, opts); err != nil {
				t.Fatalf("compile %q: %v", c.pat, err)
			}
			var report strings.Builder
			rep.Render(&report)
			if !strings.Contains(report.String(), c.body) {
				t.Fatalf("%q no longer reaches %q:\n%s", c.pat, c.body, report.String())
			}
			oracle := noReplacement(t, c.pat)
			re := regexp.MustCompile(oracle)
			w, sizes, err := compileUnicodeFindShape(c.pat, 0, false)
			if err != nil {
				t.Fatalf("compile %q: %v", c.pat, err)
			}
			engine, _ := sharedEngine()
			mod, err := wasmtime.NewModule(engine, w)
			if err != nil {
				t.Fatalf("module: %v", err)
			}
			defer mod.Close()
			for _, mode := range []searchblock.Mode{searchblock.Off, searchblock.Fresh, searchblock.Armed} {
				for _, in := range inputs {
					checkUnicodeFindFrom(t, oracle, mod, sizes, in, mode)
					checkUnicodeFindIteration(t, re, mod, sizes, in, mode)
				}
			}
			checkUnicodeCharacterRunMatch(t, c.pat, oracle, inputs)
		})
	}
	for _, pat := range characterRunGroupsShapes {
		t.Run("groups "+pat, func(t *testing.T) {
			if eng, err := compile.SelectEngine(pat, compile.CompileOptions{Unicode: true}); err != nil || eng != compile.EngineTDFA {
				t.Fatalf("%q: engine %v (%v), want TDFA", pat, eng, err)
			}
			w, _, err := compile.Compile([]config.RegexEntry{{Pattern: pat, GroupsFunc: "groups"}}, pathsTableBase, true, compile.CompileOptions{Unicode: true})
			if err != nil {
				t.Fatalf("compile %q: %v", pat, err)
			}
			re := regexp.MustCompile(noReplacement(t, pat))
			for _, in := range inputs {
				got, ok := runGroupsIter(t, w, in, re.NumSubexp()+1)
				if !ok {
					t.Fatalf("%q over %q: watchdog or overflow", pat, in)
				}
				if want := goGroupsAll(re, in); fmtGroups(got) != fmtGroups(want) {
					t.Errorf("%q over %q:\n  got  %s\n  want %s", pat, in, fmtGroups(got), fmtGroups(want))
				}
			}
		})
	}
}

// TestUnicodeGroupsStartPositions is the start-position rule through the
// groups export, from every byte position, and through the batch groups
// export, which carries its next position inside WASM.
func TestUnicodeGroupsStartPositions(t *testing.T) {
	const outBase, outCap = int32(128 * 1024), int32(64)
	for _, pat := range []string{`(a*)`, `(\B)`, `(x?)(é?)`, `(\pL*)\b`, `(é|)\B`, `(?:(\pL)\B)?`} {
		t.Run(pat, func(t *testing.T) {
			re := regexp.MustCompile(pat)
			nGroups := re.NumSubexp() + 1
			w, _, err := compile.Compile([]config.RegexEntry{{Pattern: pat, GroupsFunc: "groups", Hints: []string{"batch-find"}}},
				pathsTableBase, true, compile.CompileOptions{Unicode: true})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			engine, _ := sharedEngine()
			mod, err := wasmtime.NewModule(engine, w)
			if err != nil {
				t.Fatalf("module: %v", err)
			}
			defer mod.Close()
			for _, in := range unicodeStartInputs {
				if !utf8.ValidString(in) && canMatchReplacement(pat) {
					continue
				}
				ends := groupsEndsAt(t, pat, in)
				call, done, ok := groupsCallerModule(t, mod, in, 2*nGroups)
				if !ok {
					t.Fatal("module would not instantiate")
				}
				for from := 0; from <= len(in); from++ {
					got, state := call(from)
					want, wantOK := groupsFirstFrom(ends, from)
					if (state == findMatch) != wantOK || (wantOK && fmtSlots(got) != fmtSlots(want)) {
						t.Errorf("groups %q from=%d: got %s (state %d), want %s", in, from, fmtSlots(got), state, fmtSlots(want))
					}
				}
				done()

				store := wasmtime.NewStore(engine)
				store.SetEpochDeadline(1)
				release := store.Close
				inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
				if err != nil {
					release()
					t.Fatalf("instantiate: %v", err)
				}
				mem := inst.GetExport(store, "memory").Memory()
				copy(mem.UnsafeData(store)[pathsInputBase:], in)
				res, callErr := inst.GetFunc(store, "groups_batch").Call(store, pathsInputBase, int32(len(in)), outBase, outCap, int32(0))
				if callErr != nil {
					release()
					t.Fatalf("batch: %v", callErr)
				}
				buf := mem.UnsafeData(store)
				var batch [][]int
				for i := 0; i < int(res.(int32)); i++ {
					base := int(outBase) + i*(8+nGroups*8) + 8
					m := make([]int, nGroups*2)
					for j := range m {
						m[j] = int(int32(binary.LittleEndian.Uint32(buf[base+j*4:])))
					}
					batch = append(batch, m)
				}
				release()
				if fmtGroups(batch) != fmtGroups(goGroupsAll(re, in)) {
					t.Errorf("batch groups over %q:\n  got  %s\n  want %s", in, fmtGroups(batch), fmtGroups(goGroupsAll(re, in)))
				}
			}
		})
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
	return findCallerMode(t, wasmBytes, nil, input, searchblock.Off, false)
}

// findCallerMode is findCaller with the per-search block handed over the way
// mode says. perCall starts a fresh drive — a new block — on every call, for a
// caller probing positions out of order; otherwise every call continues one
// drive.
func findCallerMode(t *testing.T, wasmBytes []byte, sizes []searchblock.Size, input string, mode searchblock.Mode, perCall bool) (func(int) ([2]int, findState), func(), bool) {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	call, done, ok := findCallerModule(t, mod, sizes, input, mode, perCall)
	if !ok {
		mod.Close()
		return nil, nil, false
	}
	return call, func() { done(); mod.Close() }, true
}

// findCallerModule is findCallerMode over a module already compiled, for a
// caller driving one module over many inputs; done closes the instance only.
func findCallerModule(t *testing.T, mod *wasmtime.Module, sizes []searchblock.Size, input string, mode searchblock.Mode, perCall bool) (func(int) ([2]int, findState), func(), bool) {
	t.Helper()
	engine, wd := sharedEngine()
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	findFn := inst.GetFunc(store, "find")
	memExp := inst.GetExport(store, "memory")
	if findFn == nil || memExp == nil || memExp.Memory() == nil {
		store.Close()
		return nil, nil, false
	}
	copy(memExp.Memory().UnsafeData(store), input)
	sr, err := newSearchRegion(store, inst, memExp.Memory(), len(input), sizes, mode)
	if err != nil {
		t.Fatalf("search region: %v", err)
	}
	if err := sr.begin(store); err != nil {
		t.Fatalf("search block: %v", err)
	}

	call := func(from int) ([2]int, findState) {
		if perCall {
			if err := sr.begin(store); err != nil {
				t.Fatalf("search block: %v", err)
			}
		}
		sr.before(store)
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
		if err := sr.after(store); err != nil {
			t.Fatalf("search block: %v", err)
		}
		return [2]int{int(uint32(v >> 32)), int(uint32(v))}, findMatch
	}
	return call, func() { store.Close() }, true
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

// Regressions that need a RUNNING module:
// each one compiles green and answers wrongly, so only driving it can tell.

// litChainGroupsSeeds are the lit-chain "A.3" groups shapes.
//
// analyseLitChainGroups and its two siblings set compiledPattern.anchored on
// patterns that are NOT anchored — there the flag means "captureBody IS the
// export, no wrapper composition". assembleModule read it as "can only match
// at 0" and emitted the anchoredOnly groups wrapper, which answers -1 for
// EVERY from != 0 without calling the body. The body scans, so a second
// occurrence exists and iteration reported one match where Go reports two.
//
// The gate needs count >= 24, which is why the corpus never hit this.
var litChainGroupsSeeds = []struct{ pat, input string }{
	{`x([a-z]{24})`, "xabcdefghijklmnopqrstuvwx xabcdefghijklmnopqrstuvwx"},
	{`x([a-z]{24})`, "-- xabcdefghijklmnopqrstuvwx"},
	{`A([0-9]{24,30})`, "A012345678901234567890123 A012345678901234567890123"},
	{`(?:foo|bar)([a-z]{24})`, "fooabcdefghijklmnopqrstuvwx barabcdefghijklmnopqrstuvwx"},
}

// TestLitChainGroupsIterate drives the groups export past position 0.
func TestLitChainGroupsIterate(t *testing.T) {
	for _, c := range litChainGroupsSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileGroups(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := runGroupsIter(t, w, c.input, re.NumSubexp()+1)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}

// TestSimplePrefixCheckHonoursFrom pins a find-from regression.
//
// buildSimplePrefixCheckBody replaces the generic backward scan under
// LikelyNoMatch when the lit-anchor prefix is a bare [class]{M}. The rework gave
// the generic scan a find-from FLOOR; this body checked only `base < count`
// against the whole buffer and returned `base - count` unconditionally, so a
// literal at litpos in [from, from+M) yielded a reported start BEFORE `from` —
// which the phase-3 forward verify then genuinely confirms.
//
// The shapes below put two matches within M bytes of each other, so the second
// iteration's candidate sits inside the first's window.
func TestSimplePrefixCheckHonoursFrom(t *testing.T) {
	seeds := []struct{ pat, input string }{
		{`[0-9]{4}MARKER`, "1234MARKER5678MARKER"},
		{`[0-9]{4}MARKER`, "xx1234MARKER5678MARKERyy"},
		{`[a-f]{6}TAIL`, "abcdefTAILabcdefTAIL"},
	}
	for _, c := range seeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileFindLNM(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			var want [][2]int
			for _, m := range re.FindAllStringIndex(c.input, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			if fmtSpanList(got) != fmtSpanList(want) {
				t.Errorf("find iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpanList(got), fmtSpanList(want))
			}
			// The stronger property the floor exists for: no reported start may
			// precede the position it was asked to search from. runFindIter
			// resumes at end (or start+1), so a violation shows as a
			// non-increasing start.
			for i := 1; i < len(got); i++ {
				if got[i][0] <= got[i-1][0] {
					t.Errorf("match %d starts at %d, not past match %d's start %d: "+
						"the find-from floor is not being honoured",
						i, got[i][0], i-1, got[i-1][0])
				}
			}
		})
	}
}

func fmtSpanList(v [][2]int) string {
	if len(v) == 0 {
		return "(none)"
	}
	parts := make([]string, len(v))
	for i, sp := range v {
		parts[i] = fmt.Sprintf("%d-%d", sp[0], sp[1])
	}
	return strings.Join(parts, ",")
}

// compileFindLNM compiles pat with a find export under LikelyNoMatch, which is
// what gates buildSimplePrefixCheckBody's substitution (compile.go).
func compileFindLNM(pat string) ([]byte, error) {
	entry := config.RegexEntry{Pattern: pat, FindFunc: "find"}
	w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true,
		compile.CompileOptions{LikelyMode: compile.LikelyNoMatch})
	return w, err
}

// The find-from invariant, for the GROUPS export.
//
// TestFindFromStartsAtOrAfterFrom asserts this for `find`, and enforcing it turned
// up three emitters that answered with a match starting before the position
// they were asked to search from. `groups` carries the same offset through the
// same channel and has never been swept the same way: the existing coverage is
// TestLitChainGroupsIterate's four shapes, driven through one iteration order.
// On the find side that kind of coverage left SIX of fourteen emitters reached
// by nothing, two of them carrying live bugs, so the prior here is not good.
//
// The contract, identical to find's except that the answer includes slots:
//
//	groups(I, out, f) == the FIRST match of P in I whose start is >= f,
//	                     with every capture slot as Go reports it
//
// and a negative return when there is none. Slots are ABSOLUTE, and ptr/len
// describe the whole buffer, so left context is real — which is why the oracle
// probes the full input rather than running Go against a narrowed slice.
var groupsFromShapes = []struct {
	name, pat, input string
	engine           compile.EngineType // 0 = let the selector choose
}{
	{name: "tdfa_simple", pat: `(\d{2})-(\d{2})`, input: "aa 11-22 bb 33-44 cc"},
	{name: "tdfa_named", pat: `(?P<h>[a-z]+)@(?P<d>[a-z]+)\.com`, input: "x ab@cd.com y ef@gh.com"},
	{name: "tdfa_optional", pat: `(a)(b)?(c)`, input: "ac abc ac"},
	{name: "bt_nongreedy", pat: `(a.*?b)(c+)`, input: "aXbcc aYbc"},
	{name: "bt_forced", pat: `(\w+)-(\w+)`, input: "aa-bb cc-dd", engine: compile.EngineBacktrack},
	{name: "tdfa_forced", pat: `(\w+)-(\w+)`, input: "aa-bb cc-dd", engine: compile.EngineTDFA},
	{name: "litchain_groups", pat: `AKIA([A-Z0-9]{24})`,
		input: "AKIA0123456789ABCDEF01234567 q AKIAFEDCBA9876543210FEDCBA98"},
	{name: "litchain_range_groups", pat: `foo([0-9]{26,30})`,
		input: "foo0123456789012345678901234567 q foo98765432109876543210987654"},
	{name: "alt_groups", pat: `AKIA([A-Z0-9]{24})|ghp_([A-Za-z0-9]{24})`,
		input: "AKIA0123456789ABCDEF01234567 ghp_abcdefghij0123456789abcd"},
	{name: "gap_e_groups", pat: `(?P<digits>[0-9]{8})ghp_(?P<key>[A-Za-z0-9]{36})`,
		input: "01234567ghp_abcdefghijklmnopqrstuvwxyz0123456789 tail"},
	{name: "word_boundary_groups", pat: `\b(cat)\b`, input: "cat concat cat"},
	{name: "line_anchor_groups", pat: `(?m:^)(ERR):(.*)(?m:$)`, input: "ERR:one\nok\nERR:two"},
	{name: "adjacent_groups", pat: `(\d)(\d)`, input: "123456"},
	{name: "trivial_whole", pat: `([a-z]+)`, input: "ab cd ef"},
	{name: "nested_groups", pat: `((a+)(b+))`, input: "aabb ab aaabbb"},
	{name: "no_match_groups", pat: `(ZZZ)(\d+)`, input: "nothing here at all"},
	{name: "empty_capable", pat: `(a*)`, input: "baab"},
	// Empty-capable on each capture engine explicitly: the selector's choice
	// is not the point here, reaching both backends with a zero-width-capable
	// pattern is.
	{name: "empty_capable_tdfa", pat: `(a*)`, input: "baab", engine: compile.EngineTDFA},
	{name: "empty_capable_bt", pat: `(a*?)(b?)`, input: "bab", engine: compile.EngineBacktrack},
	{name: "trivial_whole_empty", pat: `([a-z]*)`, input: "ab cd"},
	// One capture between fixed literals: the span from the match alone.
	{name: "affix_suffix", pat: `([^,]+),`, input: "a,bb,,ccc,d"},
	{name: "affix_both_empty", pat: `<([^>]*)>`, input: "<a> <> x<bc>y <d"},
	{name: "affix_prefix", pat: `key=(\w+)`, input: "key=a key= key=bc"},
	{name: "affix_long", pat: `ab(c*)de`, input: "abde abccde abcd"},
}

// groupsEndsAt returns, for every start position s, the submatch indices of the
// leftmost-first match of pat beginning EXACTLY at s, or nil.
//
// Same whole-input anchored probe as the find sweep — `\A(?s:.{s})(?:pat)` —
// which keeps \b, \B and (?m:^) judging real neighbours. `(?:pat)` is
// non-capturing, so the probe's group N is pat's group N, and every index it
// reports is already absolute. Inputs here are ASCII, so the probe's rune count
// and the byte offset coincide.
func groupsEndsAt(t *testing.T, pat, input string) [][]int {
	t.Helper()
	starts := goTokenStarts(input)
	out := make([][]int, len(input)+1)
	tokens := 0
	for s := range out {
		if !starts[s] {
			continue // inside a character: no match starts here (see endsAt)
		}
		probe, err := regexp.Compile(`\A(?s:.{` + strconv.Itoa(tokens) + `})(?:` + pat + `)`)
		if err != nil {
			t.Skipf("Go rejects probe for %q at %d: %v", pat, s, err)
		}
		if m := probe.FindStringSubmatchIndex(input); m != nil {
			cp := append([]int(nil), m...)
			cp[0] = s // the probe is anchored at 0; the real match starts at s
			out[s] = cp
		}
		tokens++
	}
	return out
}

func groupsFirstFrom(ends [][]int, from int) ([]int, bool) {
	for s := from; s < len(ends); s++ {
		if ends[s] != nil {
			return ends[s], true
		}
	}
	return nil, false
}

func fmtSlots(v []int) string {
	if v == nil {
		return "(none)"
	}
	parts := make([]string, 0, len(v)/2)
	for i := 0; i+1 < len(v); i += 2 {
		if v[i] < 0 {
			parts = append(parts, "-")
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", v[i], v[i+1]))
		}
	}
	return strings.Join(parts, ",")
}

func compileGroupsShape(pat string, eng compile.EngineType) ([]byte, error) {
	if eng != 0 {
		return compileGroupsForced(pat, eng)
	}
	return compileGroups(pat)
}

// TestGroupsFromStartsAtOrAfterFrom drives groups at every start position.
func TestGroupsFromStartsAtOrAfterFrom(t *testing.T) {
	for _, c := range groupsFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			slots := 2 * (re.NumSubexp() + 1)
			w, err := compileGroupsShape(c.pat, c.engine)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := groupsCaller(t, w, c.input, slots)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()
			ends := groupsEndsAt(t, c.pat, c.input)

			for from := 0; from <= len(c.input); from++ {
				got, state := call(from)
				switch state {
				case findHang:
					t.Fatalf("from=%d: watchdog fired", from)
				case findOverflow:
					t.Skipf("from=%d: BT stack overflow", from)
				}
				want, wantOK := groupsFirstFrom(ends, from)

				if state == findNone {
					if wantOK {
						t.Errorf("from=%d: got no-match, want %s", from, fmtSlots(want))
					}
					continue
				}
				if got[0] < from {
					t.Errorf("from=%d: returned start %d precedes from — "+
						"the find-from offset is not reaching this capture body",
						from, got[0])
					continue
				}
				if !wantOK {
					t.Errorf("from=%d: got %s, want no-match", from, fmtSlots(got))
					continue
				}
				if fmtSlots(got) != fmtSlots(want) {
					t.Errorf("from=%d: slots differ\n  got  %s\n  want %s",
						from, fmtSlots(got), fmtSlots(want))
				}
			}
		})
	}
}

// TestGroupsFromShapesReachDistinctBodies is the corpus-collapse detector, with
// the same caveat as its find-side twin: the fingerprint is a proxy, not proof
// that every capture emitter is covered.
func TestGroupsFromShapesReachDistinctBodies(t *testing.T) {
	byFP := map[string][]string{}
	for _, c := range groupsFromShapes {
		w, err := compileGroupsShape(c.pat, c.engine)
		if err != nil {
			t.Skipf("compile %q: %v", c.pat, err)
		}
		fp, err := localsFingerprint(w)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		byFP[fp] = append(byFP[fp], c.name)
	}
	keys := make([]string, 0, len(byFP))
	for k := range byFP {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		short := k
		if len(short) > 48 {
			short = short[:48] + "…"
		}
		t.Logf("%-50s %s", short, strings.Join(byFP[k], ", "))
	}
	const minBodies = 6
	if len(byFP) < minBodies {
		t.Errorf("groups shapes reach only %d distinct bodies, want >= %d — the corpus has shrunk",
			len(byFP), minBodies)
	}
}

// groupsCaller instantiates once and returns a closure calling the groups
// export at a given `from`, decoding the absolute slot buffer.
func groupsCaller(t *testing.T, wasmBytes []byte, input string, slots int) (func(int) ([]int, findState), func(), bool) {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	call, done, ok := groupsCallerModule(t, mod, input, slots)
	if !ok {
		mod.Close()
		return nil, nil, false
	}
	return call, func() { done(); mod.Close() }, true
}

// groupsCallerModule is groupsCaller over a module already compiled; done
// closes the instance only.
func groupsCallerModule(t *testing.T, mod *wasmtime.Module, input string, slots int) (func(int) ([]int, findState), func(), bool) {
	t.Helper()
	engine, wd := sharedEngine()
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "groups")
	memExp := inst.GetExport(store, "memory")
	if fn == nil || memExp == nil || memExp.Memory() == nil {
		store.Close()
		return nil, nil, false
	}
	mem := memExp.Memory()
	copy(mem.UnsafeData(store)[pathsInputBase:], input)

	call := func(from int) ([]int, findState) {
		wd.Arm(store)
		r, err := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(from))
		wd.Disarm()
		if err != nil {
			if isTimeout(err) {
				return nil, findHang
			}
			t.Fatalf("groups(from=%d): %v", from, err)
		}
		v, ok := r.(int32)
		if !ok {
			t.Fatalf("groups returned %T, want i32", r)
		}
		if int64(v) == abi.BTStackOverflow {
			return nil, findOverflow
		}
		if v < 0 {
			return nil, findNone
		}
		buf := mem.UnsafeData(store)
		out := make([]int, slots)
		for i := 0; i < slots; i++ {
			s := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
			if s < 0 {
				out[i] = -1
			} else {
				out[i] = int(s)
			}
		}
		return out, findMatch
	}
	return call, func() { store.Close() }, true
}

// TestGroupsFromIterationMatchesGo is half (B) for the groups export.
//
// The suppression rule — an EMPTY match beginning exactly where the
// previous reported match ended is not reported — shipped into the find
// iterators AND both groups iterators. The find side is checked by
// TestFindFromIterationTerminates; this is the groups half, which had only
// TestLitChainGroupsIterate's four shapes.
//
// The rule is only exercisable by patterns that can match zero bytes, so
// `empty_capable` and `trivial_whole` are the shapes that matter here; the rest
// are along for the ride and confirm the loop does not disturb them.
func TestGroupsFromIterationMatchesGo(t *testing.T) {
	for _, c := range groupsFromShapes {
		t.Run(c.name, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			slots := 2 * (re.NumSubexp() + 1)
			w, err := compileGroupsShape(c.pat, c.engine)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			call, done, ok := groupsCaller(t, w, c.input, slots)
			if !ok {
				t.Skip("module would not instantiate")
			}
			defer done()

			var got [][]int
			budget := 4*len(c.input) + 16
			off, prevEnd := 0, -1
			for steps := 0; off <= len(c.input); steps++ {
				if steps > budget {
					t.Fatalf("iteration did not terminate within %d steps (off=%d)", budget, off)
				}
				m, state := call(off)
				if state == findHang {
					t.Fatalf("off=%d: watchdog fired", off)
				}
				if state == findOverflow {
					t.Skipf("off=%d: BT stack overflow", off)
				}
				if state == findNone {
					break
				}
				if !(m[0] == m[1] && m[0] == prevEnd) {
					got = append(got, m)
					prevEnd = m[1]
				}
				adv := m[1] - off
				if adv <= 0 {
					adv = 1
				}
				off += adv
			}

			var want [][]int
			for _, m := range re.FindAllStringSubmatchIndex(c.input, -1) {
				want = append(want, m)
			}
			gs, ws := make([]string, len(got)), make([]string, len(want))
			for i, v := range got {
				gs[i] = fmtSlots(v)
			}
			for i, v := range want {
				ws[i] = fmtSlots(v)
			}
			if strings.Join(gs, " | ") != strings.Join(ws, " | ") {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, strings.Join(gs, " | "), strings.Join(ws, " | "))
			}
		})
	}
}

// The batch groups export writes several matches per call into a
// caller buffer. It is a SEPARATE path from the one-at-a-time groups export
// and the generated JS/TS stubs prefer it when present, so a defect here is
// invisible to every groups test that drives `groups`.
func TestBatchGroupsMatchesGo(t *testing.T) {
	const outBase, outCap = int32(128 * 1024), int32(64)
	for _, c := range []struct{ pat, input string }{
		{`https?://(?P<host>[a-z.]+)`, "see http://example.com and http://foo.org here"},
		{`(a)(b)`, "abXab"},
		{`\b(foo)`, "foofoo"},
		{`(a*)`, "bab"},
	} {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re := regexp.MustCompile(c.pat)
			nGroups := re.NumSubexp() + 1
			w, _, err := compile.Compile([]config.RegexEntry{{
				Pattern: c.pat, GroupsFunc: "groups", Hints: []string{"batch-find"},
			}}, pathsTableBase, true)
			if err != nil {
				// Fixed, valid fixtures: a compile failure is the regression,
				// not a reason to stop testing.
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "groups_batch")
			if fn == nil {
				// The config above asks for the batch export by name
				// (Hints: batch-find), so its absence IS the regression this
				// test exists to catch.
				t.Fatal("no groups_batch export: the config requested it via " +
					"hints: [batch-find]")
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], c.input)
			res, callErr := fn.Call(store, pathsInputBase, int32(len(c.input)), outBase, outCap, int32(0))
			if callErr != nil {
				t.Fatalf("call: %v", callErr)
			}
			n := int(res.(int32))
			buf := mem.UnsafeData(store)
			rec := 8 + nGroups*8 // (start,end) then numGroups (start,end) slot pairs
			var got [][]int
			for i := 0; i < n; i++ {
				base := int(outBase) + i*rec + 8
				m := make([]int, nGroups*2)
				for j := range m {
					m[j] = int(int32(binary.LittleEndian.Uint32(buf[base+j*4:])))
				}
				got = append(got, m)
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("batch groups over %q (n=%d):\n  got  %s\n  want %s",
					c.input, n, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Regression: the BATCH groups wrapper and the plain groups wrapper call the
// SAME capture body, so they must agree on how that body reports slots.
//
// The absolute-slot channel (compiledPattern.capStartGlobal) hands the capture
// body the match's start through a module global; the body then adds it to
// every slot it writes and the wrapper skips its per-slot rebasing pass. The
// plain groups wrapper sets the global. The batch wrapper did not — it kept
// its own `+adj` pass while calling a body that was already adding whatever the
// global happened to hold. On a fresh instance the global is 0 and the answer
// is right by accident; after ANY groups() call it holds that call's match
// start, and every slot of every batch record comes back shifted by it:
//
//	(\w+)@(\w+) over "xx a@b yy c@d", record 0 (start end g0s g0e g1s g1e g2s g2e)
//	  fresh instance:        3 6 3 6 3 4 5 6   (correct)
//	  after one groups():    6 9 6 9 6 7 8 9   (every value +3)
//
// Both capture engines are covered: the greedy pattern selects TDFA, the
// non-greedy one Backtracking, and each has its own biased register/local init
// and its own slot-write site.
//
// The test drives the batch export BEFORE and AFTER a groups() call and
// requires the two to agree, and separately checks both against Go — so it
// fails on a stale channel (the bug) and on a double rebase (the fix applied
// in one place only).

// batchGroupsRecord is one (start, end, slots...) record of the batch groups
// output, decoded from the module's memory.
type batchGroupsRecord struct {
	start, end int32
	slots      []int32
}

func (r batchGroupsRecord) String() string {
	return fmt.Sprintf("[%d,%d) slots=%v", r.start, r.end, r.slots)
}

func TestBatchGroupsAbsoluteSlotsSurviveAGroupsCall(t *testing.T) {
	const input = "xx a@b yy c@d"

	for _, tc := range []struct {
		name string
		pat  string
	}{
		// Greedy, no word boundaries, no line anchors → TDFA.
		{"tdfa", `(\w+)@(\w+)`},
		// A non-greedy quantifier disqualifies TDFA → Backtracking.
		{"backtracking", `(\w+?)@(\w+)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := config.RegexEntry{
				Pattern:    tc.pat,
				GroupsFunc: "groups",
				Hints:      []string{"batch-find"},
			}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			eng, _ := compile.SelectEngine(tc.pat, compile.CompileOptions{})
			t.Logf("%s → %v", tc.pat, eng)

			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			// Three calls on one instance: see runGroupsIter.
			if err := setScratchBase(store, inst, int32(pathsTableBase)); err != nil {
				t.Fatal(err)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], input)

			numGroups := regexp.MustCompile(tc.pat).NumSubexp() + 1
			recordSize := 8 + numGroups*8
			// The batch buffer sits above the plain groups slot buffer so one
			// call cannot overwrite the other's output.
			batchOut := pathsOutBase + 1024

			readRecords := func(n int) []batchGroupsRecord {
				buf := mem.UnsafeData(store)
				out := make([]batchGroupsRecord, 0, n)
				for i := 0; i < n; i++ {
					base := int(batchOut) + i*recordSize
					rd := func(off int) int32 {
						o := base + off
						return int32(uint32(buf[o]) | uint32(buf[o+1])<<8 |
							uint32(buf[o+2])<<16 | uint32(buf[o+3])<<24)
					}
					rec := batchGroupsRecord{start: rd(0), end: rd(4)}
					for g := 0; g < numGroups*2; g++ {
						rec.slots = append(rec.slots, rd(8+g*4))
					}
					out = append(out, rec)
				}
				return out
			}

			callBatch := func() []batchGroupsRecord {
				fn := inst.GetFunc(store, "groups_batch")
				if fn == nil {
					t.Fatal("module has no groups_batch export")
				}
				res, err := fn.Call(store, pathsInputBase, int32(len(input)),
					batchOut, int32(4), int32(0))
				if err != nil {
					t.Fatalf("groups_batch: %v", err)
				}
				return readRecords(int(res.(int32)))
			}

			// What Go says, as the independent oracle for both wrappers.
			re := regexp.MustCompile(tc.pat)
			var want []batchGroupsRecord
			for _, m := range re.FindAllSubmatchIndex([]byte(input), -1) {
				rec := batchGroupsRecord{start: int32(m[0]), end: int32(m[1])}
				for _, v := range m {
					rec.slots = append(rec.slots, int32(v))
				}
				want = append(want, rec)
			}

			check := func(when string, got []batchGroupsRecord) {
				t.Helper()
				if len(got) != len(want) {
					t.Fatalf("%s: %d records, want %d\ngot  %v\nwant %v",
						when, len(got), len(want), got, want)
				}
				for i := range got {
					if got[i].start != want[i].start || got[i].end != want[i].end {
						t.Errorf("%s: record %d extent = [%d,%d), want [%d,%d)",
							when, i, got[i].start, got[i].end, want[i].start, want[i].end)
					}
					for s := range want[i].slots {
						if got[i].slots[s] != want[i].slots[s] {
							t.Errorf("%s: record %d slot %d = %d, want %d\ngot  %v\nwant %v",
								when, i, s, got[i].slots[s], want[i].slots[s], got[i], want[i])
							break
						}
					}
				}
			}

			before := callBatch()
			check("fresh instance", before)

			// One ordinary groups() call, which is what leaves the absolute-slot
			// channel holding a non-zero start.
			gfn := inst.GetFunc(store, "groups")
			if gfn == nil {
				t.Fatal("module has no groups export")
			}
			if _, err := gfn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(0)); err != nil {
				t.Fatalf("groups: %v", err)
			}

			after := callBatch()
			check("after a groups() call", after)

			for i := range before {
				if before[i].String() != after[i].String() {
					t.Fatalf("record %d differs across a groups() call:\n  before %v\n  after  %v\n"+
						"the batch wrapper and the capture body disagree about who rebases slots",
						i, before[i], after[i])
				}
			}

			// And twice in a row, so a channel left stale BETWEEN the batch
			// loop's own iterations would show up too.
			check("second batch call", callBatch())
		})
	}
}

// x{3}abcdef|y{3}ghijkl routes to the ALT-LIT-ANCHOR emitter (a dispatcher plus
// a backward-scan/forward-verify pair per branch). It is the last find emitter
// still on ffLegacyNarrow, so this pins its behaviour while it is legacy and
// becomes its acceptance test when it is converted.
func TestAltLitAnchorIteration(t *testing.T) {
	for _, c := range []struct{ pat, input string }{
		{`x{3}abcdef|y{3}ghijkl`, "xxxabcdef yyyghijkl xxxabcdef"},
		{`x{3}abcdef|y{3}ghijkl`, "zzz yyyghijkl"},
		{`x{3}abcdef|y{3}ghijkl`, "no match here at all"},
	} {
		t.Run(c.input, func(t *testing.T) {
			w, err := compileFind(c.pat)
			if err != nil {
				// A fixed, valid fixture whose whole purpose is to keep the
				// alt-lit-anchor emitter covered. Skipping here would turn the
				// loss of that entire path into a green test.
				t.Fatalf("compile: %v", err)
			}
			got, ok := wasmFindIter(t, w, c.input)
			if !ok {
				t.Skip("watchdog")
			}
			want := goFindAll(regexp.MustCompile(c.pat), c.input)
			if fmtSpans(got) != fmtSpans(want) {
				t.Errorf("alt-lit-anchor iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtSpans(got), fmtSpans(want))
			}
		})
	}
}

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

// ---------------------------------------------------------------------------
// Regression: under `byte_mode: true` a literal rune 0x80..0xFF means exactly
// that BYTE, so it consumes ONE byte — not the two its UTF-8 encoding would
// take. The length analysis sized every such rune by its encoding, which made it
// an OVER-estimate, and its callers all read it as a true bound:
//
//   - the exported find wrapper turns minLen into an early exit, so an
//     over-estimate REFUSES an input that matches. `\xe9ab` answered -1 for
//     the 3-byte input "\xe9ab" while answering correctly for every longer one
//     — the shortest input for a shape is the only one that shows it, which is
//     why nothing caught this.
//   - the mandatory-literal analyser accumulates it as the literal's offset
//     from the match start, and the lit-anchor emitters take it as a fixed
//     prefix length.
//
// ORACLE. Go's regexp cannot express byte mode, so the expectation comes from
// an ISOMORPHISM instead: under a byte engine, the high byte 0xE9 behaves
// exactly like any other byte that appears nowhere else in the pattern or the
// input. Mapping 0xE9 to 'Q' in both gives a pattern Go can run, over an
// alphabet where the two are interchangeable. That is an independent oracle,
// not a transcript of engine output.
//
// The shapes are chosen to reach different emitters — plain DFA find,
// mandatory-literal lit-anchor, alternation lit-anchor, counted chain — so a
// length bug in any of the analysers that consume the minimum length shows up
// here and not only in the wrapper's early exit.

func TestByteModeLengthsAcrossEmitters(t *testing.T) {
	const hiByte = "\xe9"
	const asciiStandIn = "Q"

	shapes := []struct{ name, pat string }{
		{"literal-only", `\xe9ab`},
		{"class-then-lit", `[a-y]\xe9foo`},
		{"plus-then-lit", `\xe9+bar`},
		{"lit-anchor-fixed-prefix", `[a-y]\xe9zzzz`},
		{"alt-lit", `(?:\xe9ab|\xe9cd)`},
		{"mand-lit-mid", `a\xe9b`},
		{"counted", `\xe9{2}xy`},
		{"two-high-bytes", `\xe9\xe9ab`},
		{"high-byte-class", `[\x80-\xff]ab`},
	}

	// The shortest input for each shape is the one that matters: the early
	// exit fires on `len - from < minLen`, so an over-estimate of one byte is
	// invisible at every length above the minimum.
	inputs := []string{
		"", "\xe9", "\xe9a", "\xe9ab", "x\xe9ab", "zz\xe9abzz",
		"a\xe9foo", "qa\xe9fooq", "\xe9bar", "\xe9\xe9bar",
		"m\xe9zzzz", "a\xe9b", "\xe9\xe9xy", "\xe9\xe9ab",
		strings.Repeat("z", 40) + "\xe9ab",
		strings.Repeat("z", 9) + "a\xe9foo",
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, FindFunc: "find", ByteMode: true}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}

			// The isomorphic ASCII twin of the pattern. Go reads its input as
			// UTF-8, so a rune class cannot stand for a raw high BYTE at all —
			// `[\x80-\xff]` becomes the stand-in's own class, which is
			// equivalent as long as 0xE9 is the only high byte in the inputs.
			oraclePat := strings.ReplaceAll(sh.pat, `\xe9`, asciiStandIn)
			oraclePat = strings.ReplaceAll(oraclePat, `[\x80-\xff]`, "["+asciiStandIn+"]")
			re := regexp.MustCompile(`(?s)` + oraclePat)

			for _, in := range inputs {
				copy(mem.UnsafeData(store)[pathsInputBase:], in)
				res, cerr := inst.GetFunc(store, "find").Call(store,
					pathsInputBase, int32(len(in)), int32(0))
				if cerr != nil {
					t.Fatalf("input %q: %v", in, cerr)
				}
				got := res.(int64)

				oracleIn := strings.ReplaceAll(in, hiByte, asciiStandIn)
				loc := re.FindStringIndex(oracleIn)
				var want int64 = -1
				if loc != nil {
					want = int64(loc[0])<<32 | int64(loc[1])
				}
				if got != want {
					t.Errorf("pattern %q input %q (len %d): got %#x, want %#x (oracle %v)\n"+
						"a byte_mode literal rune 0x80..0xFF is ONE byte; an over-estimated "+
						"minimum length refuses inputs that match",
						sh.pat, in, len(in), uint64(got), uint64(want), loc)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestByteModeLengthsAcrossEmitters' Unicode-mode sibling. In Unicode mode a
// rune is its UTF-8 encoding: a literal weighs 1 to 4 bytes, a `(?i)` literal
// anything from its fold orbit's narrowest to its widest, a class from its
// lowest rune's width to its highest's, and `.` 1 to 4. An over-estimated
// minimum refuses the shortest input that matches and no longer one; an
// under-estimated maximum misplaces a mandatory literal's search window or a
// lit-anchor's fixed prefix. So every shape is driven over its SHORTEST
// matching inputs — one per way its minimum can be reached — and over longer
// ones that reach its maximum.
//
// The oracle is Go itself: in Unicode mode regexped answers as Go does on
// valid UTF-8, and every input here is valid UTF-8.
func TestUnicodeModeLengthsAcrossEmitters(t *testing.T) {
	shapes := []struct {
		name, pat string
		inputs    []string
	}{
		{"literal-only", `éab`, []string{"éab", "éa", "xéab"}},
		{"class-then-lit", `[a-y]éfoo`, []string{"aéfoo", "qaéfooq", "éfoo"}},
		{"plus-then-lit", `é+bar`, []string{"ébar", "ééébar", "bar"}},
		{"lit-anchor-fixed-prefix", `[a-y]ézzzz`, []string{"mézzzz", "zzmézzzzz", "ézzzz"}},
		{"alt-lit", `(?:éab|écd)`, []string{"écd", "xéab", "éa"}},
		{"mand-lit-mid", `aéb`, []string{"aéb", "aaéb", "ab"}},
		{"counted", `é{2}xy`, []string{"ééxy", "éxy", "éééxy"}},
		{"4-byte-literal", `𐀀ab`, []string{"𐀀ab", "x𐀀ab", "𐀀a"}},
		{"dot-then-lit", `.foo`, []string{"afoo", "éfoo", "日foo", "𐀀foo", "foo"}},
		{"dot-mid", `a.b`, []string{"axb", "aéb", "a日b", "a𐀀b", "ab"}},
		{"dot-counted-then-lit", `.{2}foo`, []string{"abfoo", "a𐀀foo", "𐀀𐀀foo", "日éfoo", "afoo"}},
		{"negated-class-then-lit", `[^a]bar`, []string{"xbar", "ébar", "日bar", "𐀀bar", "abar"}},
		{"greek-class", `[α-ω]+x`, []string{"αx", "αβγx", "ax"}},
		{"greek-prefix-lit", `[α-ω]foo`, []string{"αfoo", "zαfoo", "afoo"}},
		{"letter-class-counted", `\pL{2}x`, []string{"abx", "aéx", "日本x", "𐐀𐐀x", "ax"}},
		{"3-byte-class", `[\x{800}-\x{FFFF}]x`, []string{"日x", "z日x", "éx", "x"}},
		{"fold-k", `(?i)kx`, []string{"kx", "Kx", "\u212Ax", "x"}},
		{"fold-s-then-lit", `(?i)sfoo`, []string{"sfoo", "Sfoo", "\u017Ffoo", "foo"}},
		{"fold-word", `(?i)straße`, []string{"straße", "STRAẞE", "ſtraße", "strasse"}},
		{"fold-prefix-lit", `(?i)k=\d`, []string{"k=1", "\u212A=1", "=1"}},
		// A fold scoped to the prefix leaves the literal after it unfolded,
		// so the mandatory-literal search window is the fold's widest width.
		{"scoped-fold-then-lit", `(?i:k)=\d`, []string{"k=1", "\u212A=1", "x\u212A=1", "=1"}},
		{"scoped-fold-s-then-lit", `(?i:s)foo`, []string{"sfoo", "\u017Ffoo", "a\u017Ffoo", "foo"}},
		{"lit-scoped-fold-then-lit", `a(?i:k)foo`, []string{"akfoo", "a\u212Afoo", "za\u212Afoo", "afoo"}},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: sh.pat, FindFunc: "find"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true,
				compile.CompileOptions{Unicode: true})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			re := regexp.MustCompile(sh.pat)
			for _, in := range sh.inputs {
				if !utf8.ValidString(in) {
					t.Fatalf("input %q is not valid UTF-8; Go is not the oracle there", in)
				}
				copy(mem.UnsafeData(store)[pathsInputBase:], in)
				res, cerr := inst.GetFunc(store, "find").Call(store,
					pathsInputBase, int32(len(in)), int32(0))
				if cerr != nil {
					t.Fatalf("input %q: %v", in, cerr)
				}
				got := res.(int64)
				loc := re.FindStringIndex(in)
				var want int64 = -1
				if loc != nil {
					want = int64(loc[0])<<32 | int64(loc[1])
				}
				if got != want {
					t.Errorf("pattern %q input %q (len %d): got %#x, want %#x (oracle %v)\n"+
						"in Unicode mode a rune weighs its UTF-8 encoding; a wrong length "+
						"bound refuses or misplaces a match",
						sh.pat, in, len(in), uint64(got), uint64(want), loc)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unicode mode from a config, end to end: an entry that names a non-ASCII
// character, or sets `unicode: true`, compiles in Unicode mode with no option
// set, and answers as Go does. The literal-anchored shapes carry a non-ASCII
// part beside the anchor literal, which their backward pass reads reversed
// and lowered last byte first; they must reach those bodies, which a guard
// asking a lowered program whether it names refused runes used to decline.
func TestUnicodeModeFromConfig(t *testing.T) {
	yaml := `import_module: uni
wasm_file: uni.wasm
regexps:
  - name: e
    pattern: 'é+'
    find_func: find_e
  - name: mail
    pattern: 'é+@example\.com'
    find_func: find_mail
  - name: prefix
    pattern: '(?:ü|ö)xyz'
    find_func: find_prefix
  - name: alt
    pattern: '[à-ÿ]foo|[α-ω]bar'
    find_func: find_alt
  - name: dot
    pattern: 'a.c'
    unicode: true
    find_func: find_dot
`
	path := filepath.Join(t.TempDir(), "uni.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rep := &compile.Reporter{}
	w, _, err := compile.Compile(cfg.Regexps, pathsTableBase, true, compile.CompileOptions{Report: rep})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var b strings.Builder
	rep.Render(&b)
	report := b.String()
	if strings.Count(report, "mode:   unicode") != len(cfg.Regexps) {
		t.Errorf("not every entry compiled in Unicode mode:\n%s", report)
	}
	for _, want := range []string{"literal-anchored find (SIMD", "alternation literal-anchored find"} {
		if !strings.Contains(report, want) {
			t.Errorf("no pattern reached %q:\n%s", want, report)
		}
	}

	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	for _, c := range []struct {
		fn, pat string
		inputs  []string
	}{
		{"find_e", `é+`, []string{"é", "aéé b é", "e", "日é"}},
		{"find_mail", `é+@example\.com`, []string{"ééé@example.com", "xé@example.com y é@example.com", "@example.com", "e@example.com", "日é@example.com"}},
		{"find_prefix", `(?:ü|ö)xyz`, []string{"üxyz", "aöxyz üxyz", "xyz", "uxyz"}},
		{"find_alt", `[à-ÿ]foo|[α-ω]bar`, []string{"àfoo", "αbar", "ÿfoo ωbar àbaz", "afoo", "日foo"}},
		{"find_dot", `a.c`, []string{"aéc a日c abc a😀c axyc", "ac"}},
	} {
		re := regexp.MustCompile(c.pat)
		f := inst.GetFunc(store, c.fn)
		for _, in := range c.inputs {
			copy(mem.UnsafeData(store)[pathsInputBase:], in)
			var got [][2]int
			for from := 0; from <= len(in); {
				res, err := f.Call(store, pathsInputBase, int32(len(in)), int32(from))
				if err != nil {
					t.Fatalf("%s %q: %v", c.fn, in, err)
				}
				v := res.(int64)
				if v < 0 {
					break
				}
				sp := [2]int{int(uint32(v >> 32)), int(uint32(v))}
				got = append(got, sp)
				from = max(sp[1], sp[0]+1)
			}
			var want [][2]int
			for _, m := range re.FindAllStringIndex(in, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			if fmtSpanList(got) != fmtSpanList(want) {
				t.Errorf("%s over %q:\n  got  %s\n  want %s", c.fn, in, fmtSpanList(got), fmtSpanList(want))
			}
		}
	}
	// The answer the plan pins.
	copy(mem.UnsafeData(store)[pathsInputBase:], "é")
	if res, err := inst.GetFunc(store, "find_e").Call(store, pathsInputBase, int32(2), int32(0)); err != nil || res.(int64) != 2 {
		t.Errorf(`é+ over "é": got %v (%v), want [0,2)`, res, err)
	}
}

// ---------------------------------------------------------------------------
// A wholly empty-width word-boundary pattern lost every boundary whose
// PRECEDING byte was a word character and whose following byte was not.
// `\b` over "a b" reported boundaries at 0, 2 and 3 and skipped the one at 1.
//
// ROOT CAUSE. Find mode picks candidate start positions from `firstByteFlags`.
// For a word-boundary pattern that table is built from two sources: the
// byte-consuming transitions out of each start state, and — for a pattern that
// can accept an EMPTY match — the `midAcceptNW/W` tables. The empty-width half
// consulted `midStartState` (prev = non-word) and `startState`, but never
// `midStartWordState` (prev = word). The transitions half had already been
// taught about that state; the accept half had not.
//
// So nothing ever flagged a byte as "a match can begin here with prev=word",
// and every such position was skipped before the boundary was even evaluated.
//
// WHY ONLY BARE `\b` AND `\B`. As soon as a pattern consumes a byte, the
// transitions out of `midStartWordState` set the same flags and the answer
// comes out right — which is why `\b,`, `\b\s`, `\b[^a-z]`, `\bfoo` and
// `\b[a-z]+` were all correct throughout, and why the corpus never noticed.
//
// WHY THE CORPUS NEVER NOTICED. re2-exhaustive.txt carries four columns, so
// col4 (ALL matches) is absent and only the FIRST match is ever checked. For
// bare `\b` the first match is at position 0, which was always found. The
// defect lives entirely in the second and later matches.
//
// It was found by tools/re2test's --high-bytes mode, which synthesises col4
// from a Go oracle, in its high-byte disguise (`\b` over "aâb"). The bug is not
// high-byte specific at all — pure ASCII "a b" fails identically — but the
// high-byte harness was the first thing to check an all-matches column for this
// pattern shape.

func TestEmptyWidthBoundaryFindsEveryPosition(t *testing.T) {
	cases := []struct{ pat, in string }{
		{`\b`, "a b"},
		{`\b`, "a,b"},
		{`\b`, "a\tb"},
		{`\b`, "ab cd ef"},
		{`\b`, "a"},
		{`\b`, " a "},
		{`\b`, "ab"},
		{`\B`, "ab c"},
		{`\B`, "a  b"},
		{`\B`, "abc"},
		// Content-bearing siblings, which always worked. Here so a future
		// change cannot fix the empty case by breaking these.
		{`\b,`, "a,b"},
		{`\b\s`, "a b"},
		{`\b[^a-z]`, "a,b"},
		{`\bfoo`, ",foo foo"},
		{`\b[a-z]+`, "a bc de"},
		{`x\b`, "x y x"},
	}
	for _, c := range cases {
		t.Run(c.pat+"/"+c.in, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: c.pat, FindFunc: "find"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, ierr := instantiate(w)
			defer release()
			if ierr != nil {
				t.Fatalf("instantiate: %v", ierr)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], c.in)
			fn := inst.GetFunc(store, "find")

			var got [][2]int
			for off := 0; off <= len(c.in); {
				r, cerr := fn.Call(store, pathsInputBase, int32(len(c.in)), int32(off))
				if cerr != nil {
					t.Fatalf("find(%d): %v", off, cerr)
				}
				v := r.(int64)
				if v < 0 {
					break
				}
				s, e := int(uint32(v>>32)), int(uint32(v))
				if s < off {
					t.Fatalf("find(%d) returned a match starting at %d, before `from`", off, s)
				}
				got = append(got, [2]int{s, e})
				// The advance rule every generated stub uses: past a
				// zero-length match by one byte.
				if e > s {
					off = e
				} else {
					off = s + 1
				}
			}

			var want [][2]int
			for _, loc := range regexp.MustCompile(c.pat).FindAllStringIndex(c.in, -1) {
				want = append(want, [2]int{loc[0], loc[1]})
			}
			if len(got) != len(want) {
				t.Fatalf("pattern %q over %q: got %v, want %v", c.pat, c.in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("pattern %q over %q: got %v, want %v", c.pat, c.in, got, want)
				}
			}
		})
	}
}

// The same defect in its high-byte disguise, which is how it was found. A high
// byte is not a word character, so "a" followed by 0xE9 is a boundary. Go
// cannot be the oracle here — it decodes UTF-8 — so the expectation is computed
// from the definition of \b over BYTES.
func TestEmptyWidthBoundaryOverHighBytes(t *testing.T) {
	isWord := func(b byte) bool {
		return b == '_' || (b >= '0' && b <= '9') ||
			(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	for _, in := range []string{"a\xe9b", "a\xc3\xa2b", "a\xe9", "\xe9a", "\xe9\xe9", "a\xe9\xe9b"} {
		t.Run(in, func(t *testing.T) {
			entry := config.RegexEntry{Pattern: `\b`, FindFunc: "find"}
			w, _, err := compile.Compile([]config.RegexEntry{entry}, pathsTableBase, true)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, ierr := instantiate(w)
			defer release()
			if ierr != nil {
				t.Fatalf("instantiate: %v", ierr)
			}
			copy(mem.UnsafeData(store)[pathsInputBase:], in)
			fn := inst.GetFunc(store, "find")

			var got []int
			for off := 0; off <= len(in); off++ {
				r, cerr := fn.Call(store, pathsInputBase, int32(len(in)), int32(off))
				if cerr != nil {
					t.Fatalf("find(%d): %v", off, cerr)
				}
				v := r.(int64)
				if v < 0 {
					break
				}
				s := int(uint32(v >> 32))
				got = append(got, s)
				off = s
			}

			var want []int
			for p := 0; p <= len(in); p++ {
				pw, nw := false, false
				if p > 0 {
					pw = isWord(in[p-1])
				}
				if p < len(in) {
					nw = isWord(in[p])
				}
				if pw != nw {
					want = append(want, p)
				}
			}
			if len(got) != len(want) {
				t.Fatalf(`\b over %q: got %v, want %v`, in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf(`\b over %q: got %v, want %v`, in, got, want)
				}
			}
		})
	}
}

// (?i) over a NEGATED class arrives from Go's parser with holes at the fold
// artifacts of its letters — `(?i)[^a-z]` is [\x7b-\x{17e}] [\x{180}-\x{2129}]
// [\x{212b}-\x{10ffff}], minus U+017F (from s) and U+212A (from k) — and under
// byte_mode (?i) over Latin-1 adds U+212B (from å). The rune gate refused all of
// these; once it accepts them, every emitter has to lower the class to the
// same BYTE set its unfolded twin would give: the high bytes are not letters,
// so `(?i)[^a-z]` must take every byte except A-Z and a-z, 0x80..0xFF included.
//
// Go cannot be the oracle over high bytes (it decodes UTF-8), so each case
// carries the byte set it must accept, from the definition of the class over
// bytes. Every byte goes through find, match, both capture engines, the
// Backtracking find and a set, since each lowers rune ranges on its own.
func TestCaseFoldedNegatedClassesOverAllBytes(t *testing.T) {
	isLetter := func(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
	isWord := func(b byte) bool { return isLetter(b) || (b >= '0' && b <= '9') || b == '_' }
	cases := []struct {
		pat      string
		byteMode bool
		want     func(b byte) bool
	}{
		{`(?i)[^a-z]`, false, func(b byte) bool { return !isLetter(b) }},
		{`(?i)[^a-z]`, true, func(b byte) bool { return !isLetter(b) }},
		{`(?i)\W`, false, func(b byte) bool { return !isWord(b) }},
		{`(?i)[^0-9A-Z_a-z]`, false, func(b byte) bool { return !isWord(b) }},
		{`(?i:[^k])`, false, func(b byte) bool { return b != 'k' && b != 'K' }},
		{`(?i)[^s]`, true, func(b byte) bool { return b != 's' && b != 'S' }},
		{`(?i)[A-Z_a-z\x7f-\xff]`, true, func(b byte) bool { return isLetter(b) || b == '_' || b >= 0x7f }},
		{`(?i)[\x7f-\xff]`, true, func(b byte) bool { return b >= 0x7f }},
		{`[^\x80-\xff]`, true, func(b byte) bool { return b < 0x80 }},
		// Byte-mode folding stays inside the byte range: \xe0-\xfe folds to
		// \xc0-\xde except × (0xD7) and ÷ (0xF7), which have no partner.
		{`(?i)[^\xe0-\xfe]`, true, func(b byte) bool {
			return !((b >= 0xc0 && b <= 0xd6) || (b >= 0xd8 && b <= 0xde) || (b >= 0xe0 && b <= 0xfe))
		}},
	}
	type path struct {
		name  string
		build func(pat string, byteMode bool) ([]byte, error)
		run   func(w []byte, in string) (bool, error)
	}
	const selected = compile.EngineType(0) // the engine the selector picks
	single := func(e config.RegexEntry, base int64, eng compile.EngineType) ([]byte, error) {
		if eng != selected {
			w, _, err := compile.CompileForced([]config.RegexEntry{e}, base, true, eng)
			return w, err
		}
		w, _, err := compile.Compile([]config.RegexEntry{e}, base, true, compile.CompileOptions{})
		return w, err
	}
	groupsRun := func(w []byte, in string) (bool, error) {
		_, ok, _, err := runWasmGroupsPath(w, in, 2)
		return ok, err
	}
	paths := []path{
		{"find", func(p string, bm bool) ([]byte, error) {
			return single(config.RegexEntry{Pattern: p, FindFunc: "find", ByteMode: bm}, tableBase, selected)
		}, func(w []byte, in string) (bool, error) {
			_, ok, _, err := runWasmFind(w, in)
			return ok, err
		}},
		{"find/backtrack", func(p string, bm bool) ([]byte, error) {
			w, _, err := compile.Compile([]config.RegexEntry{{Pattern: p, FindFunc: "find", ByteMode: bm}},
				tableBase, true, compile.CompileOptions{MaxDFAStates: -1})
			return w, err
		}, func(w []byte, in string) (bool, error) {
			_, ok, _, err := runWasmFind(w, in)
			return ok, err
		}},
		{"match", func(p string, bm bool) ([]byte, error) {
			return single(config.RegexEntry{Pattern: p, MatchFunc: "match", ByteMode: bm}, pathsTableBase, selected)
		}, func(w []byte, in string) (bool, error) {
			_, ok, _, err := runWasmMatch(w, in)
			return ok, err
		}},
		{"groups/tdfa", func(p string, bm bool) ([]byte, error) {
			return single(config.RegexEntry{Pattern: "(" + p + ")", GroupsFunc: "groups", ByteMode: bm}, pathsTableBase, compile.EngineTDFA)
		}, groupsRun},
		{"groups/backtrack", func(p string, bm bool) ([]byte, error) {
			return single(config.RegexEntry{Pattern: "(" + p + ")", GroupsFunc: "groups", ByteMode: bm}, pathsTableBase, compile.EngineBacktrack)
		}, groupsRun},
		{"set", func(p string, bm bool) ([]byte, error) {
			cfg := config.BuildConfig{
				Regexps: []config.RegexEntry{{Name: "p0", Pattern: p, ByteMode: bm}},
				Sets: []config.SetConfig{{Name: "s", Find: "set_find", Overlapping: true,
					Patterns: config.PatternSelector{Names: []string{"p0"}}}},
			}
			w, _, _, err := compile.CompileFileDiag(cfg, "")
			return w, err
		}, func(w []byte, in string) (bool, error) {
			m, _, err := runWasmSetFind(w, in, 1)
			return len(m) > 0, err
		}},
	}
	for _, c := range cases {
		for _, p := range paths {
			t.Run(fmt.Sprintf("%s/byteMode=%v/%s", c.pat, c.byteMode, p.name), func(t *testing.T) {
				w, err := p.build(c.pat, c.byteMode)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				var wrong []string
				for b := 0; b < 256; b++ {
					got, err := p.run(w, string([]byte{byte(b)}))
					if err != nil {
						t.Fatalf("byte %#02x: %v", b, err)
					}
					if got != c.want(byte(b)) {
						wrong = append(wrong, fmt.Sprintf("%#02x got %v", b, got))
					}
				}
				if len(wrong) > 0 {
					t.Errorf("%d of 256 bytes wrong: %v", len(wrong), wrong)
				}
			})
		}
	}
}

// Range-overread regression.
//
// emitRangeClassVerify runs the class verify over `countMax` bytes via
// planRangeChunks, which covers [K, K+countMax) rounded up to a 16-byte
// multiple. Every caller only bounds-checks `base + K + countMin <= len`, so
// the trailing chunks read up to `countMax - countMin + 15` bytes past
// `ptr+len`. The values read there never reach the result (match_len is capped
// at `len - base - K` before use), which is exactly why this stayed invisible:
// the only observable symptom is the load itself walking off the end of linear
// memory and trapping.
//
// The test places the input flush against the end of the module's memory, so
// any over-read is a trap rather than a silent read of neighbouring bytes.
// This is not a contrived pointer: the exported match/find functions take an
// arbitrary (ptr, len), and in embedded mode they read the *host's* memory,
// where an input near the last page is ordinary.
//
// Note that the standalone module used here has its DFA tables at page 1, so
// the end of memory is well past them — nothing else is disturbed by writing
// there.
func TestRangeVerifyNoOverreadAtMemoryEnd(t *testing.T) {
	// Each case is a lit-chain range whose countMax − countMin window is wide
	// enough that the chunk plan reaches past the bounds-checked prefix.
	cases := []struct {
		pattern string
		input   string
	}{
		{`A[0-9]{24,60}`, "A" + strings.Repeat("7", 24)},
		{`A[0-9]{24,60}`, "A" + strings.Repeat("7", 40)},
		{`AKIA[A-Z0-9]{16,120}`, "AKIA" + strings.Repeat("Q", 16)},
		{`ghp_[A-Za-z0-9]{36,37}`, "ghp_" + strings.Repeat("z", 36)},
		// Non-greedy: anchored match still runs the full range verify.
		{`A[0-9]{24,60}?`, "A" + strings.Repeat("7", 24)},
		// Wide window: chunks whose clamp distance exceeds 32, where WASM's
		// mod-32 shift count leaves the mask garbage. Harmless (see the
		// emitRangeClassVerify comment) but only if it never traps.
		{`A[0-9]{24,900}`, "A" + strings.Repeat("7", 24)},
	}

	for _, c := range cases {
		entry := config.RegexEntry{Pattern: c.pattern, MatchFunc: "match", FindFunc: "find"}
		wasmBytes, _, err := compile.Compile([]config.RegexEntry{entry}, tableBase, true)
		if err != nil {
			t.Fatalf("pattern=%q compile: %v", c.pattern, err)
		}
		for _, export := range []string{"match", "find"} {
			store, inst, mem, release, err := instantiate(wasmBytes)
			defer release()
			if err != nil {
				t.Fatalf("pattern=%q instantiate: %v", c.pattern, err)
			}
			fn := inst.GetFunc(store, export)
			if fn == nil {
				t.Fatalf("pattern=%q: no %q export", c.pattern, export)
			}
			data := mem.UnsafeData(store)
			ptr := len(data) - len(c.input)
			copy(data[ptr:], c.input)
			args := []any{int32(ptr), int32(len(c.input))}
			if export == "find" {
				args = append(args, int32(0)) // find takes `from`
			}
			if _, err := fn.Call(store, args...); err != nil {
				t.Errorf("pattern=%q %s at ptr=%d (memory size %d): %v",
					c.pattern, export, ptr, len(data), err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Regressions on the TDFA capture path.
//
// All three are silent wrong-answer bugs on patterns the selector itself routes
// to TDFA, so every case here asserts the selector's own choice first: forcing
// TDFA on a pattern the compiler never claimed to handle would be garbage-in,
// exactly as FuzzGroupsBothEngines argues.

// tdfaCase is one (pattern, input) pair checked against Go's
// FindStringSubmatchIndex through the TDFA groups export.
type tdfaCase struct {
	pattern string
	input   string
	desc    string
}

// checkTDFAGroups compiles each case on TDFA and compares the capture slots
// against the stdlib oracle. It fails (rather than skips) when the selector
// would not pick TDFA: these patterns are the bugs' repros, and a selector
// change that quietly routes them elsewhere would turn the regression test into
// a no-op that still reports PASS.
func checkTDFAGroups(t *testing.T, cases []tdfaCase) {
	t.Helper()
	for _, c := range cases {
		name := c.desc
		if name == "" {
			name = c.pattern
		}
		t.Run(name, func(t *testing.T) {
			eng, err := compile.SelectEngine(c.pattern, compile.CompileOptions{})
			if err != nil {
				t.Fatalf("SelectEngine(%q): %v", c.pattern, err)
			}
			if eng != compile.EngineTDFA {
				t.Fatalf("pat=%q: selector picked %v, want TDFA — this repro no longer covers the TDFA path",
					c.pattern, eng)
			}

			wasmBytes, err := compileGroupsForced(c.pattern, compile.EngineTDFA)
			if err != nil {
				t.Fatalf("pat=%q compile: %v", c.pattern, err)
			}

			ref := regexp.MustCompile(c.pattern)
			numGroups := ref.NumSubexp() + 1
			want := ref.FindStringSubmatchIndex(c.input)

			got, ok, hang, runErr := runWasmGroupsPath(wasmBytes, c.input, numGroups)
			if runErr != nil {
				t.Fatalf("pat=%q input=%q: wasm error: %v", c.pattern, abbrev(c.input), runErr)
			}
			if hang {
				t.Fatalf("pat=%q input=%q: hang (watchdog %s)", c.pattern, abbrev(c.input), wasmCallTimeout)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Fatalf("groups mismatch (%s): pat=%q input=%q\n  expected %v\n  got      %v (ok=%v)",
					msg, c.pattern, abbrev(c.input), want, got, ok)
			}
		})
	}
}

// abbrev shortens long inputs in failure messages — several repros need
// hundreds of bytes to trip, and dumping them verbatim buries the diff.
func abbrev(s string) string {
	if len(s) <= 64 {
		return s
	}
	return fmt.Sprintf("%q...%q (len %d)", s[:32], s[len(s)-16:], len(s))
}

// Register-coloring coalescing (minimizeTDFARegisters/remapOps) can map two
// registers in the same parallel-copy batch onto one local, creating a
// read-after-write dependency that did not exist before coloring. The batch was
// correctly sequentialized pre-coloring and is never re-sequentialized after, so
// one op clobbers the value the next op reads.
//
// `(b+){2}c` on "bbbc" is the minimal witness: group 1 must report the LAST
// iteration ([2 3]), and the pre-coloring batch [{0 3} {1 2}] becomes [{1 2}
// {0 1}] once r0 and r2 are coalesced, yielding [0 4 2 2].
func TestTDFARegisterCoalescingOrdering(t *testing.T) {
	checkTDFAGroups(t, []tdfaCase{
		{pattern: `(b+){2}c`, input: "bbbc", desc: "b_plus_rep2"},
		{pattern: `(b+){2}c`, input: "bbbbbc", desc: "b_plus_rep2_longer"},
		{pattern: `(a+){2}(b+){2}c`, input: "aabbbc", desc: "two_coalescing_batches"},
		{pattern: `(ab+){2}c`, input: "abbabc", desc: "multi_byte_body"},
		{pattern: `(b+){3}c`, input: "bbbbc", desc: "rep3"},
		{pattern: `x(a+){2}y`, input: "xaaay", desc: "prefixed"},
	})
}

// The TDFA body hand-rolls its transition load instead of using the shared
// emitU8Transition / emitCompressedU8Transition / emitU16Transition, so it
// diverges from whatever encoding buildDFALayout actually picked.
//
//  1. >256 states → u16 encoding → the hand-rolled operand order produced an
//     invalid module ("expected i32 but nothing on stack"), i.e. instantiation
//     fails outright.
//  2. ≥ ~128 states → byte-class compression kicks in (numWASM*256 > 32KB) and
//     the emitted classMap is never read: the body still indexes
//     tableOff + state<<8 + byte, so transitions come from the wrong cells and
//     the match silently disappears.
//
// The a{N} ladder walks straight through both thresholds; N=120 was the last
// value that agreed with stdlib before the fix, N=125 the first that did not.
func TestTDFATableAddressingEncodings(t *testing.T) {
	var cases []tdfaCase
	for _, n := range []int{100, 120, 125, 130, 200, 260, 300} {
		cases = append(cases, tdfaCase{
			pattern: fmt.Sprintf(`x(a{%d})y`, n),
			input:   "x" + strings.Repeat("a", n) + "y",
			desc:    fmt.Sprintf("a_rep_%d", n),
		})
	}
	// Same thresholds with a non-trivial byte class, so compression has real
	// equivalence classes to collapse rather than a two-symbol alphabet.
	for _, n := range []int{130, 300} {
		cases = append(cases, tdfaCase{
			pattern: fmt.Sprintf(`x([a-f]{%d})y`, n),
			input:   "x" + strings.Repeat("cafe", (n+3)/4)[:n] + "y",
			desc:    fmt.Sprintf("class_rep_%d", n),
		})
	}
	checkTDFAGroups(t, cases)
}

// emitTDFABulkSkip advances over a run of same-state bytes without running
// the per-byte mid-accept bookkeeping the scalar loop does, so lastAcceptPos and
// the eagerly-written captures stay frozen at the value they had when the run
// started. A dead exit byte inside a full 16-byte chunk then reports the stale
// position.
//
// `^([a-z]+)` on 20 a's + "!" + 20 a's returned [0 1 0 1] instead of [0 20 0 20]:
// the very first byte was the last one the scalar loop saw. The run must be long
// enough that the exit byte lands inside a full 16-byte SIMD chunk — a
// scalar-tail exit masks the bug entirely, which is why the short variants below
// are included as controls rather than as repros.
func TestTDFABulkSkipMidAccept(t *testing.T) {
	var cases []tdfaCase
	for _, n := range []int{4, 16, 17, 20, 33, 64, 100} {
		cases = append(cases, tdfaCase{
			pattern: `^([a-z]+)`,
			input:   strings.Repeat("a", n) + "!" + strings.Repeat("a", 20),
			desc:    fmt.Sprintf("lower_run_%d", n),
		})
	}
	cases = append(cases,
		tdfaCase{pattern: `^([a-z]+)`, input: strings.Repeat("a", 40), desc: "no_exit_byte"},
		tdfaCase{pattern: `^([0-9]+)`, input: strings.Repeat("7", 50) + "x", desc: "digits"},
		tdfaCase{pattern: `^([a-z]+)([0-9]*)`, input: strings.Repeat("q", 40) + "!", desc: "two_groups"},
	)
	checkTDFAGroups(t, cases)
}

// findStrategyShapes is one example of every find shape the compile-time
// find classifier distinguishes (compile/start_anywhere.go), with the byte it
// repeats to build that shape's worst-case run and one string it matches.
var findStrategyShapes = []struct {
	pat, fill, needle string
	extra             []string // inputs aimed at one path
}{
	{`a*b`, "a", "aab", nil},
	{`[^,]*,`, "a", "field,", nil},
	{`\w+@\w+`, "a", "joe@example", nil},
	{`[a-z]+[0-9]{3}`, "a", "abc123", nil},
	{`[a-z]+[0-9]+z`, "a", "ab12z", nil},
	{`(?:ab)+c`, "ab", "ababc", nil},
	{`\w+abc\d`, "abc", "xabc1", nil},
	{`\w+_x\d`, "_x", "a_x1", nil},
	{`.*foo\d`, "foo", "foo1", nil},
	{`(?i)select\s+.*\s+from`, "select ", "SELECT a FROM", nil},
	{`ERROR\w*y|WARN\w*z`, "ERROR", "ERRORxy", nil},
	{`foo[a-z]+bar`, "foo", "fooxbar", nil},
	{`a+b`, "a", "aab", nil},
	{`[a-z]+@example\.com`, "a", "joe@example.com", nil},
	{`\w+@\w+\.com`, "a", "joe@x.com", nil},
	{`foo[a-z]+`, "FOO", "foox", nil},
	{`[0-9]{3}-[0-9]{4}`, "1", "555-1234", nil},
	// The literal-anchored find whose backward walks FAIL at the floor.
	{`[0-9]\w+abc\d`, "abc", "1xabc2", nil},
	// The alternation literal-anchored find.
	{`x{3}abc\w*z|y{3}ghi\w*z`, "xxxabc", "xxxabcz", nil},
	// The attempt at 0 walks the whole input and fails, and a match starts at
	// 1: a counter that trips on that walk must resume the search AT 1.
	{`a\w*X|b\w*Y`, "b", "Y", []string{"a" + strings.Repeat("b", 300) + "Y", "aa" + strings.Repeat("b", 300) + "Y"}},
	// Empty-width assertions, served by the start-anywhere find's context
	// passes; every one of the first five is quadratic under today's find on
	// its run. The last two are linear — their loops can only end where the
	// assertion holds — and keep today's.
	{`a+b\b`, "a", "aab", nil},
	{`a*b$`, "a", "ab", nil},
	{`\w+@\w+\b`, "a", "a@b", nil},
	{`\b[a-z ]+X`, "a ", "aX", nil},
	{`a+x(?m:$)`, "a", "ax", nil},
	{`\bfoo\w*\b`, "foo ", "foox", nil},
	{`(?m:^)ERROR:.*(?m:$)`, "ERROR:", "ERROR:x\n", nil},
	// Its start-anywhere automaton is over the state limit (2^11 states for
	// `a[ab]{11}`), so the switch hands over to the Backtracking find.
	{`a[ab]{11}c[a-z]*X`, "abbbbbbbbbbbc", "abbbbbbbbbbbcX", nil},
	// Quadratic under today's find with or without a hint, and a hint does not
	// change its body: it has to be switched under all three modes.
	{`<[^>]+>`, "<", "<b>", nil},
	// Under prefer-no-match its body carries a NEUTRAL TWIN (no mandatory
	// literal, a first-byte set in the adaptive Shufti band): on its run every
	// byte is a candidate, so the hinted body hands the call to the twin,
	// whose own counter then trips.
	{`[a-zA-Z][^;]*[;,]`, "a", "a;", nil},
	// A lenient literal-chain alternation (one branch a literal chain, one a
	// DFA branch starting with a literal): its specialised body carries no
	// counter, so where its failed walks are unbounded it must not be used.
	{`ab?c|x[a-z]*Y`, "x", "xY", nil},
}

// hasEmptyWidthAssertion reports whether pat carries \b, \B, ^, $, \A or \z,
// which the start-anywhere find refuses.
func hasEmptyWidthAssertion(pat string) bool {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return false
	}
	var walk func(*syntax.Regexp) bool
	walk = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
			syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			return true
		}
		for _, s := range r.Sub {
			if walk(s) {
				return true
			}
		}
		return false
	}
	return walk(re)
}

// TestFindStrategiesMatchGo drives every find strategy — today's find, the
// start-anywhere find alone, today's find with a work counter that trips
// almost at once (N = 1), and whatever the classifier picks — at EVERY start
// position, against the whole-input Go oracle. The long inputs are worst-case
// runs, which is what trips the counter, so the handover to the start-anywhere
// find is exercised mid-call and not only on its first attempt.
//
// The hinted rows exist because a hint changes the body the counter is added
// to — under prefer-no-match, sometimes into a pair, the hinted body and the
// neutral twin it hands the call to, each with a counter of its own.
func TestFindStrategiesMatchGo(t *testing.T) {
	strategies := []struct {
		name string
		opts compile.CompileOptions
		note string // the verbose note proving the strategy was served
	}{
		{"today", compile.CompileOptions{TodayFind: true}, "find: today"},
		{"start-anywhere", compile.CompileOptions{StartAnywhereFind: true}, "find: start-anywhere"},
		{"switch-n1", compile.CompileOptions{StartAnywhereSwitchN: 1}, "find: switch"},
		{"classifier", compile.CompileOptions{}, "find: "},
		{"switch-n1/prefer-match", compile.CompileOptions{StartAnywhereSwitchN: 1, LikelyMode: compile.LikelyMatch}, "find: switch"},
		{"switch-n1/prefer-no-match", compile.CompileOptions{StartAnywhereSwitchN: 1, LikelyMode: compile.LikelyNoMatch}, "find: switch"},
		{"classifier/prefer-match", compile.CompileOptions{LikelyMode: compile.LikelyMatch}, "find: "},
		{"classifier/prefer-no-match", compile.CompileOptions{LikelyMode: compile.LikelyNoMatch}, "find: "},
	}
	rng := rand.New(rand.NewSource(105))
	for _, c := range findStrategyShapes {
		alpha := c.fill + c.needle + " ,@"
		inputs := []string{
			strings.Repeat(c.fill, 300/len(c.fill)) + c.needle,
			strings.Repeat(c.fill, 150/len(c.fill)) + c.needle + strings.Repeat(c.fill, 150/len(c.fill)),
		}
		inputs = append(inputs, c.extra...)
		for i := 0; i < 20; i++ {
			b := make([]byte, rng.Intn(40))
			for j := range b {
				b[j] = alpha[rng.Intn(len(alpha))]
			}
			inputs = append(inputs, string(b))
		}
		for _, st := range strategies {
			t.Run(c.pat+"/"+st.name, func(t *testing.T) {
				r := &compile.Reporter{}
				o := st.opts
				o.Report = r
				w, _, err := compile.Compile([]config.RegexEntry{{Pattern: c.pat, FindFunc: "find"}}, pathsTableBase, true, o)
				if err != nil {
					t.Fatal(err)
				}
				r.End()
				served, refused := false, false
				for _, n := range r.Patterns[0].Notes {
					served = served || strings.HasPrefix(n, st.note)
					refused = refused || strings.HasPrefix(n, "switch handover: Backtracking")
				}
				if st.name == "start-anywhere" && refused {
					// Forced, but the automaton is over the limits: the switch
					// with the Backtracking handover serves it instead.
					served = true
				}
				if !served {
					t.Fatalf("not served by %q: notes %v", st.note, r.Patterns[0].Notes)
				}
				for _, in := range inputs {
					call, done, ok := findCaller(t, w, in)
					if !ok {
						t.Fatal("module would not instantiate")
					}
					ends := endsAt(t, c.pat, in)
					for from := 0; from <= len(in); from++ {
						got, state := call(from)
						want, wantOK := goFirstFrom(ends, from)
						switch {
						case state == findHang:
							t.Fatalf("%q from=%d: watchdog fired", in, from)
						case state == findNone && wantOK:
							t.Fatalf("%q from=%d: got -1, want %v", in, from, want)
						case state == findMatch && (!wantOK || got != want):
							t.Fatalf("%q from=%d: got %v, want %v (%v)", in, from, got, want, wantOK)
						}
					}
					done()
				}
			})
		}
	}
}

// TestFindStrategiesLinear pins what the find classifier exists for: every
// shape's find, as compiled by default, is LINEAR on that shape's worst-case
// run. It is measured in fuel over the whole iteration at two lengths 4×
// apart — linear grows ~4×, quadratic ~16× — so a counter that stopped
// charging some walk (the literal-anchored find's failed backward walks, say)
// fails here even though every answer it gives is still right. Under every
// hint too: a hinted pattern kept today's find unswitched once, and `<[^>]+>`
// was quadratic under both hints while linear without one.
func TestFindStrategiesLinear(t *testing.T) {
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	fuelFor := func(mod *wasmtime.Module, in string) uint64 {
		st := wasmtime.NewStore(engine)
		defer st.Close()
		st.SetFuel(1 << 62)
		inst, err := wasmtime.NewInstance(st, mod, nil)
		if err != nil {
			t.Fatal(err)
		}
		copy(inst.GetExport(st, "memory").Memory().UnsafeData(st)[pathsInputBase:], in)
		// Backtracking handovers place their memo above the input.
		if err := setScratchBase(st, inst, pathsInputBase+int32((len(in)+65535)/65536*65536)); err != nil {
			t.Fatal(err)
		}
		fn := inst.GetFunc(st, "find")
		for from := 0; from <= len(in); {
			v, err := fn.Call(st, pathsInputBase, int32(len(in)), int32(from))
			if err != nil {
				t.Fatal(err)
			}
			r := v.(int64)
			if r < 0 {
				break
			}
			s, e := int(uint32(r>>32)), int(uint32(r))
			if e > s {
				from = e
			} else {
				from = e + 1
			}
		}
		left, _ := st.GetFuel()
		return uint64(1<<62) - left
	}
	modes := []struct {
		name string
		lm   compile.LikelyMode
	}{{"neutral", compile.LikelyNeutral}, {"prefer-match", compile.LikelyMatch}, {"prefer-no-match", compile.LikelyNoMatch}}
	for _, c := range findStrategyShapes {
		for _, m := range modes {
			t.Run(c.pat+"/"+m.name, func(t *testing.T) {
				w, _, err := compile.Compile([]config.RegexEntry{{Pattern: c.pat, FindFunc: "find"}}, pathsTableBase, true,
					compile.CompileOptions{LikelyMode: m.lm})
				if err != nil {
					t.Fatal(err)
				}
				mod, err := wasmtime.NewModule(engine, w)
				if err != nil {
					t.Fatal(err)
				}
				defer mod.Close()
				runs := []string{strings.Repeat(c.fill, 4096/len(c.fill)), strings.Repeat(c.fill, 16384/len(c.fill))}
				if len(c.extra) > 0 {
					runs = []string{"a" + strings.Repeat("b", 4096), "a" + strings.Repeat("b", 16384)}
				}
				small, large := fuelFor(mod, runs[0]), fuelFor(mod, runs[1])
				if ratio := float64(large) / float64(small); ratio > 8 {
					t.Errorf("fuel grew %.1f× for a 4× longer worst-case run (%d → %d): quadratic", ratio, small, large)
				}
			})
		}
	}
}

// TestUnicodeModeSelectedGroupsMatchGo: in Unicode mode a capture pattern
// goes to whichever engine the selector picks for it — the selector judging
// the pattern as written, the engine running the lowered program — and its
// groups equal Go's over valid UTF-8.
func TestUnicodeModeSelectedGroupsMatchGo(t *testing.T) {
	cases := []struct {
		pat    string
		inputs []string
	}{
		{`(\pL+)@(\pL+)`, []string{"user@host", "é@ж", "日本@語", "x é@ж y", "a@", "ÀÉ@ü1"}},
		{`([α-ω]+)-(\d+)`, []string{"αβγ-42", "x αβ-7 y", "ΑΒ-1", "α-", "-1", "ωω-9z"}},
		// Wide classes, `.` and folded literals have computed first sets in
		// Unicode mode, so these take a TDFA rather than Backtracking — and the
		// overlapping alternations must still be found ambiguous.
		{`(\pL+)\s(\pN+)`, []string{"Straße 42", "x Straße 42", "日本 ٣٤", "a 1 b 2", "Straße", ""}},
		{`<([^>]+)>`, []string{"<é>", "a<日本>b", "<>", "<a<b>", "<<é>>", "x"}},
		{`([^,]+),`, []string{"привет,мир", ",x", "é,", "日本語,,", "a"}},
		{`(.+)=(.+)`, []string{"a=b=c", "ключ=значение", "=x", "é=", "x\n=y", "é=ж\nz"}},
		{`((\pL)|(\pN))+`, []string{"é٣a1", "!é", "٣", ""}},
		{`((\pL)|(a))`, []string{"a", "é", "1"}},
		{`((?i:é)|(É))`, []string{"É", "é", "e", "xÉ"}},
		{`(\pL+)(\pL)`, []string{"Straße", "日本", "é", "ab"}},
		{`([\pL\pN]+)@(\pL+)\.(\pL{2,})`, []string{"пользователь@пример.рф", "a1@b.cd", "x@y.z", "é@ж.日本"}},
	}
	for _, c := range cases {
		eng, err := compile.SelectEngine(c.pat, compile.CompileOptions{Unicode: true})
		if err != nil {
			t.Fatalf("%s: SelectEngine: %v", c.pat, err)
		}
		w, _, err := compile.Compile([]config.RegexEntry{{Pattern: c.pat, GroupsFunc: "groups"}},
			pathsTableBase, true, compile.CompileOptions{Unicode: true})
		if err != nil {
			t.Fatalf("%s: compile: %v", c.pat, err)
		}
		re := regexp.MustCompile(c.pat)
		for _, in := range c.inputs {
			want := re.FindStringSubmatchIndex(in)
			got, ok, hang, err := runWasmGroupsPath(w, in, re.NumSubexp()+1)
			if err != nil || hang {
				t.Fatalf("%s (%v) over %q: err=%v hang=%v", c.pat, eng, in, err, hang)
			}
			if msg := compareSlots(want, got, ok); msg != "" {
				t.Errorf("%s (%v) over %q (%s): got %v, want %v", c.pat, eng, in, msg, got, want)
			}
		}
	}
}
