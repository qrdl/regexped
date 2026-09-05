package compile

import (
	"bytes"
	"fmt"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// Paths a YAML config cannot select, and exported predicates whose only
// callers live in other MODULES.
//
// Both are gaps a compile-matrix cannot close. The Shufti frontend needs
// Aho-Corasick to decline first, which `hints_test.go` arranges with
// `ACBudgetBytes: 1` — an option `BuildConfig` does not expose, and a
// 220-literal set still sat comfortably inside AC's real budget. The
// predicates are called from `tools/fuzz` and `tools/re2test`, separate
// modules whose tests contribute nothing here.
//
// Calling an emitter directly is a weaker check than compiling a module that
// uses it, and it is used here only where the stronger option does not exist.
// What it does establish is that the path still BUILDS and still produces
// well-formed output — which is what would break silently as the emitters
// around it change.

// shuftiCompiledSetOpts builds a set whose frontend is Shufti, by the same
// route hints_test.go uses: enough literals that Teddy declines, first bytes
// inside Shufti's 17..64 band, Aho-Corasick pushed out of budget, and the
// LikelyNoMatch bias that selects it.
//
// `over` leaves the options open so a caller can force the ADAPTIVE variant.
// The dense switch is `lnm && !rare`, and this set's byte union is one the
// rarity model calls rare — so the adaptive arm, roughly a third of the
// emitter, is unreachable without WithShuftiAdaptive.
func shuftiCompiledSetOpts(t *testing.T, over func(*CompileSetOptions)) *compiledSet {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var prefixPool, suffixPool dfaPool
	var patterns []*PatternInfo
	var ids []int
	for i := 0; i < teddyMaxLiterals+1; i++ {
		pat := fmt.Sprintf("%cq%02dx[a-z]+", alphabet[i%len(alphabet)], i)
		info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		patterns = append(patterns, info)
		ids = append(ids, i)
	}
	spec := SetSpec{
		Name: "s", Find: "find_all",
		MatchAny: "match_any", MatchAll: "match_all",
		DeclaredPatternCount: len(patterns), IDSpaceSize: len(patterns),
		Patterns: patterns, PatternIDs: ids,
	}
	opts := CompileSetOptions{LikelyMode: LikelyNoMatch, ACBudgetBytes: 1}
	if over != nil {
		over(&opts)
	}
	cs := CompileSet(spec, &prefixPool, &suffixPool, opts)
	if cs.fe != frontendShufti {
		t.Fatalf("expected the Shufti frontend, got %v — this test no longer reaches what it claims", cs.fe)
	}
	return cs
}

// TestShuftiAnchoredBodyEmits covers emitSetMatchFnFinalShufti, the Shufti
// anchored match body.
//
// It is the single largest uncovered function in the package, and unreachable
// through CompileFile: see the file comment. Emitting it directly at least
// pins that it produces a body at all, for both anchored kinds.
func TestShuftiAnchoredBodyEmits(t *testing.T) {
	// Both switch shapes. The adaptive one carries the runtime dense counter
	// and its escape to the scalar tail — a separate locals layout and a
	// separate set of branch depths, so a body that emits only one of them is
	// only half tested. It is reachable ONLY through the test-only override:
	// this set's byte union is rare, and `shuftiAdaptive = lnm && !rare`.
	for _, tc := range []struct {
		name     string
		over     func(*CompileSetOptions)
		adaptive bool
	}{
		{"plain", nil, false},
		{"adaptive", func(o *CompileSetOptions) { *o = o.WithShuftiAdaptive(true) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := shuftiCompiledSetOpts(t, tc.over)
			if cs.shuftiAdaptive != tc.adaptive {
				t.Fatalf("shuftiAdaptive = %v, want %v — this case no longer "+
					"covers the arm it was written for", cs.shuftiAdaptive, tc.adaptive)
			}
			base := cs.funcCount()
			var prev []byte
			for _, mode := range []setCapKind{capMatchAny, capMatchAll} {
				body := emitSetMatchFnFinalShufti(cs, base, base, mode, base)
				if len(body) == 0 {
					t.Fatalf("mode %v: emitted an empty body", mode)
				}
				// A WASM function body is a size-prefixed byte sequence whose
				// last byte is `end` (0x0B). Cheap, but it is what catches a
				// body that stopped being terminated.
				if body[len(body)-1] != 0x0B {
					t.Errorf("mode %v: body does not end with `end` (0x0B), got %#x",
						mode, body[len(body)-1])
				}
				// The two anchored modes emit the SAME body here, and that is
				// correct: newSetFindCtx branches on capFind and capScanAny
				// only, so match_any and match_all are indistinguishable to
				// this emitter — their difference lives in the probe and the
				// accumulation around it. Asserted rather than assumed,
				// because a future mode-dependent arm added here would want
				// this test updated deliberately rather than silently.
				if prev != nil && !bytes.Equal(prev, body) {
					t.Error("match_any and match_all now emit different bodies; " +
						"this emitter used to be mode-independent — update the test " +
						"if that is intended")
				}
				prev = body
			}
		})
	}
}

// TestShuftiAnchoredAdaptiveIsLarger pins that the adaptive arm actually emits
// the extra machinery rather than silently collapsing to the plain shape —
// which is what a wrong `adaptive` test inside the emitter would look like.
func TestShuftiAnchoredAdaptiveIsLarger(t *testing.T) {
	plain := shuftiCompiledSetOpts(t, nil)
	adaptive := shuftiCompiledSetOpts(t, func(o *CompileSetOptions) {
		*o = o.WithShuftiAdaptive(true)
	})
	base := plain.funcCount()
	p := emitSetMatchFnFinalShufti(plain, base, base, capMatchAny, base)
	a := emitSetMatchFnFinalShufti(adaptive, adaptive.funcCount(), adaptive.funcCount(), capMatchAny, adaptive.funcCount())
	if len(a) <= len(p) {
		t.Errorf("adaptive body is %d bytes, plain is %d — the dense counter, "+
			"its gate and the scalar escape should make it strictly larger",
			len(a), len(p))
	}
}

// TestUnionAliveMaskEmits covers emitUnionAliveMask, the preflight's
// union-automaton pass.
//
// The G12 absence prefilter is chosen over it whenever per-pattern absence
// literals exist, which every literal-bearing set in the matrix has — so the
// union arm is the road not taken there and needs reaching directly.
func TestUnionAliveMaskEmits(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	var patterns []*PatternInfo
	var ids []int
	for i, pat := range []string{`a+`, `[^\n]*ERROR`, `x?y`} {
		info, err := analyzePattern(config.RegexEntry{Pattern: pat}, &prefixPool, &suffixPool)
		if err != nil {
			t.Fatalf("analyzePattern(%q): %v", pat, err)
		}
		patterns = append(patterns, info)
		ids = append(ids, i)
	}
	spec := SetSpec{
		Name: "s", ScanAny: "scan_any", Find: "find_all",
		DeclaredPatternCount: len(patterns), IDSpaceSize: len(patterns),
		Patterns: patterns, PatternIDs: ids,
	}
	u := buildUnionScanDFA(spec, 0, false)
	if u == nil {
		t.Skip("no union automaton for this set: nothing to emit")
	}
	body := emitUnionAliveMask(nil, u, 8, 9, 10, 2, 11, 0, nil)
	if len(body) == 0 {
		t.Fatal("emitted an empty alive-mask sequence")
	}
	// fullMask != 0 arms the early exit (item 22 fix 2a prerequisite 2), which
	// is a different emitted shape and the one every real caller gets.
	withExit := emitUnionAliveMask(nil, u, 8, 9, 10, 2, 11, 0, []uint64{0x7})
	if len(withExit) <= len(body) {
		t.Fatalf("the fullMask early exit emitted no extra bytes: %d vs %d", len(withExit), len(body))
	}
}

// TestSetAdmitsBacktracking is the predicate the STUB GENERATORS use to decide
// which `_all` ABI a set exports, without ever compiling it.
//
// Its only callers are in other modules, so nothing here pinned it. Getting it
// wrong is not a wrong answer but a wrong ARITY — the stub calls a
// three-parameter export with two — which is why re2test reads the answer from
// diagnostics instead and this predicate must agree with what the compiler
// actually did.
func TestSetAdmitsBacktracking(t *testing.T) {
	pats := []string{`a+`, `[^\n]*ERROR`}
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sc := config.SetConfig{
		Name: "s", MatchAll: "m_all", Find: "f",
		Patterns: config.PatternSelector{All: true},
	}

	// A generous fallback budget: every member gets a DFA, so no BT.
	roomy := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
	if SetAdmitsBacktracking(sc, roomy) {
		t.Error("a set whose members all fit their DFA budget must not admit Backtracking")
	}
	// A budget no fallback DFA can meet: every member lands on BT.
	cramped := config.BuildConfig{
		Regexps: entries, Sets: []config.SetConfig{sc}, MaxFallbackStates: 1,
	}
	if !SetAdmitsBacktracking(sc, cramped) {
		t.Error("max_fallback_states = 1 must push these members onto Backtracking")
	}
	// And the prediction must match what the compiler DID.
	_, _, diags, err := CompileFileDiag(cramped, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	bt := 0
	for _, b := range diags[0].Buckets {
		if b.Type == "bt-fallback" {
			bt++
		}
	}
	if bt == 0 {
		t.Error("predicate says Backtracking, but the compiler emitted no bt-fallback bucket")
	}
}

// TestFindFromModeString covers the Stringer, which exists for diagnostics and
// panic messages — the places where a mode is printed precisely because
// something has already gone wrong.
//
// The UNSET case is the point of it: findFromMode's zero value is invalid on
// purpose, so a find emitter that never claimed a mode is a BUILD failure
// rather than a silently wrong scan start.
func TestFindFromModeString(t *testing.T) {
	for _, c := range []struct {
		mode findFromMode
		want string
	}{
		{ffLegacyNarrow, "legacy-narrow"},
		{ffNative, "native"},
		{ffAnchoredZeroOnly, "anchored-zero-only"},
		{findFromMode(0), "UNSET"},
		{findFromMode(99), "UNSET"},
	} {
		if got := c.mode.String(); got != c.want {
			t.Errorf("mode %d: String() = %q, want %q", c.mode, got, c.want)
		}
	}
}

// TestAnalyseLitChainBranch covers the analysis that decides whether a pattern
// is a literal chain — a literal followed by a fixed-count class run, which
// lets the find body anchor on the literal and verify outward instead of
// walking every start position.
//
// It is a pure predicate over a parsed pattern, so the shapes it must REFUSE
// are as much of its contract as the ones it accepts, and refusals are what a
// compile matrix reaches least: a pattern it declines simply takes another
// path and nothing records why.
func TestAnalyseLitChainBranch(t *testing.T) {
	for _, c := range []struct {
		pattern string
		want    bool
		why     string
	}{
		// The shape is LITERAL first, then a fixed-count class run — the
		// `AKIA[A-Z0-9]{16}` family. A run BEFORE the literal is a different
		// analysis (the prefixed variants next door).
		{`ghp_[A-Za-z0-9]{36}`, true, "literal then a long fixed run"},
		{`AKIA[A-Z0-9]{16}`, true, "the same shape, shorter run"},
		{`x[a-z]{24}`, true, "a single-byte literal is still a literal"},
		{`[0-9]{8}ghp_`, false, "run BEFORE the literal: the prefixed analysis, not this one"},
		{`[a-z]{24}x`, false, "literal AFTER the run, likewise"},
		{`ghp_[A-Za-z0-9]+`, false, "unbounded run, so no fixed width to anchor on"},
		{`ghp_[A-Za-z0-9]{2,8}`, false, "a RANGE rather than a fixed count"},
		{`abc`, false, "a bare literal has no class run"},
		{`[0-9]{30}`, false, "a class run with no literal to anchor on"},
	} {
		t.Run(c.pattern, func(t *testing.T) {
			re, err := syntax.Parse(c.pattern, syntax.Perl)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// The RAW parse, not re.Simplify(): simplification expands {36}
			// into thirty-six concatenated copies and destroys the Repeat node
			// this analyser matches on. analyseLitChainRe passes the raw tree
			// for exactly that reason.
			info, ok := analyseLitChainBranch(re)
			if ok != c.want {
				t.Errorf("analyseLitChainBranch(%q) = %v, want %v (%s)",
					c.pattern, ok, c.want, c.why)
			}
			if ok && info == nil {
				t.Errorf("%q: reported success with no info", c.pattern)
			}
			if ok && len(info.literal) == 0 {
				t.Errorf("%q: reported a literal chain with an empty literal", c.pattern)
			}
		})
	}
}

// TestNeedsUnicodeSupportExported covers the EXPORTED predicate, which takes a
// pattern string.
//
// compile_test.go has a same-named test, but it drives an internal helper over
// a *syntax.Prog — so the exported entry point, the one every fuzz target in
// tools/ calls to decide what to skip, had no test at all. A raw byte scan
// would not do: `\x{263A}` is pure ASCII text that denotes a non-ASCII
// codepoint once parsed, which is the whole reason this function exists
// instead of each caller checking bytes.
func TestNeedsUnicodeSupportExported(t *testing.T) {
	for _, c := range []struct {
		pattern string
		want    bool
	}{
		{`abc`, false},
		{`[a-z]+`, false},
		{`\d{4}`, false},
		{`\x{263A}`, true},
		{`\p{Greek}`, true},
	} {
		got, err := NeedsUnicodeSupport(c.pattern)
		if err != nil {
			t.Errorf("%q: %v", c.pattern, err)
			continue
		}
		if got != c.want {
			t.Errorf("NeedsUnicodeSupport(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
	if _, err := NeedsUnicodeSupport(`(`); err == nil {
		t.Error("an unparseable pattern must report an error rather than a verdict")
	}
}

// TestCompileForcedSelectsTheNamedEngine covers CompileForced, the entry point
// that overrides engine selection for capture paths.
//
// It exists so a differential test can compile the SAME pattern on TDFA and on
// Backtracking and compare — which is only meaningful if the override is
// actually honoured, and nothing here checked that it was.
func TestCompileForcedSelectsTheNamedEngine(t *testing.T) {
	entries := []config.RegexEntry{
		{Name: "p", Pattern: `(a+)(b+)`, GroupsFunc: "p_groups"},
	}
	for _, forced := range []EngineType{EngineTDFA, EngineBacktrack} {
		wasm, _, err := CompileForced(entries, 65536, true, forced)
		if err != nil {
			t.Fatalf("CompileForced(%v): %v", forced, err)
		}
		if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
			t.Fatalf("CompileForced(%v): not a WASM module", forced)
		}
		if !strings.Contains(string(wasm), "p_groups") {
			t.Errorf("CompileForced(%v): module does not export p_groups", forced)
		}
	}
}

// TestFindFromWrapperBodyAllModes covers buildFindFromWrapperBody in each of
// its three modes.
//
// The wrapper is what gives every exported `find` its (ptr, len, from)
// signature while the BODY keeps (ptr, len) — hundreds of hardcoded local
// indices depend on that — so the mode decides whether `from` travels through
// the module-level global, is consumed natively, or is answered without
// calling the body at all. Only the modes a compiled pattern happens to select
// were reached; a mode is a contract, so all three are pinned here.
func TestFindFromWrapperBodyAllModes(t *testing.T) {
	for _, mode := range []findFromMode{ffLegacyNarrow, ffNative, ffAnchoredZeroOnly} {
		body := buildFindFromWrapperBody(7, mode)
		if len(body) == 0 {
			t.Fatalf("mode %v: emitted nothing", mode)
		}
		if body[len(body)-1] != 0x0B {
			t.Errorf("mode %v: body does not end with `end` (0x0B), got %#x",
				mode, body[len(body)-1])
		}
		// The local declaration is the first byte: legacy-narrow needs an i64
		// scratch to hold the body's packed return while it is rebased; the
		// other two need no locals at all. Getting this wrong is a validation
		// error, but only once the module is instantiated.
		wantLocals := byte(0x00)
		if mode == ffLegacyNarrow {
			wantLocals = 0x01
		}
		if body[0] != wantLocals {
			t.Errorf("mode %v: local-group count %#x, want %#x", mode, body[0], wantLocals)
		}
	}
}

// TestBuildFindFromWrapperBodyRejectsUnsetMode: findFromMode's zero value is
// invalid ON PURPOSE, so an emitter that never claimed a mode must be a BUILD
// failure rather than a silently wrong scan start. That is what the panic is
// for, and an unexercised panic is a promise nobody has checked.
func TestBuildFindFromWrapperBodyRejectsUnsetMode(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("an unset mode was accepted; the zero value is supposed to be invalid")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "UNSET") {
			t.Errorf("panic message %q does not name the offending mode", msg)
		}
	}()
	buildFindFromWrapperBody(7, findFromMode(0))
}

// TestEmitFindCallFromPos covers the shared call sequence the BATCH wrappers
// use, in both the modes that reach it.
//
// It is shared between the batch find and batch groups wrappers precisely so
// the two cannot end up with subtly different calling conventions — which
// makes it worth pinning that each mode emits something, and that the
// anchored-zero-only mode emits MORE (it has to answer "no match" for pos != 0
// without calling the body at all).
func TestEmitFindCallFromPos(t *testing.T) {
	native := emitFindCallFromPos(nil, 7, ffNative, 4, 5)
	anchored := emitFindCallFromPos(nil, 7, ffAnchoredZeroOnly, 4, 5)
	legacy := emitFindCallFromPos(nil, 7, ffLegacyNarrow, 4, 5)
	for name, got := range map[string][]byte{
		"native": native, "anchored-zero-only": anchored, "legacy-narrow": legacy,
	} {
		if len(got) == 0 {
			t.Errorf("mode %s: emitted nothing", name)
		}
	}
	if len(anchored) <= len(native) {
		t.Errorf("anchored-zero-only emitted %d bytes, native %d: the anchored mode "+
			"must add the pos != 0 guard that answers without calling the body",
			len(anchored), len(native))
	}
}
