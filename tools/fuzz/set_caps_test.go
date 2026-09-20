package fuzz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"regexp/syntax"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// End-to-end checks of the seven set capabilities against oracle formulas
// built from Go `regexp`. Every expectation is computed live
// via the whole-input technique, so nothing here restates the emitter's own
// rules back at it.

// compileCaps compiles pats into a standalone module exporting all seven
// capabilities under their canonical names.
//
// It returns BOTH drop scopes (setDrops): a pattern the anchored packer alone
// refused still answers on scan_any, scan_all and `find`, so one map cannot
// serve every oracle — that conflation is FUZZER_BUGS bug 91.
func compileCaps(pats []string, overlapping bool) ([]byte, setDrops, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	return cachedCompileSet(fmt.Sprintf("caps\x00%v\x00%s", overlapping, setKey(pats)), func() ([]byte, setDrops, error) {
		w, _, diags, err := compile.CompileFileDiag(config.BuildConfig{Regexps: entries, Sets: sets}, "")
		return w, dropsFromSet(diags), err
	})
}

// capRunner holds an instantiated capability module plus its memory layout.
type capRunner struct {
	store  *wasmtime.Store
	inst   *wasmtime.Instance
	mem    *wasmtime.Memory
	inBase int32
	// gatePtr is the caller-owned array every `find` takes, overlapping
	// included: the default body records match gates in it, the
	// overlapping one keeps its once-per-drive preflight
	// verdict there. Zeroed by newCapRunner; a test that starts a SECOND
	// drive on the same runner must zero it again with resetGates.
	gatePtr int32
	outPtr  int32
	npat    int
	// release frees the wasmtime Store and Module. The runner OUTLIVES
	// newCapRunner, so this cannot be deferred there — every caller must
	// `defer r.Close()` instead.
	release func()
}

// Close frees the runner's wasmtime resources. Using the runner afterwards is
// a use-after-free.
func (r *capRunner) Close() {
	if r != nil && r.release != nil {
		r.release()
		r.release = nil
	}
}

func newCapRunner(t *testing.T, pats []string, input string, overlapping bool) *capRunner {
	t.Helper()
	w, _, err := compileCaps(pats, overlapping)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	return newCapRunnerFrom(t, w, pats, input)
}

// newCapRunnerFrom instantiates an ALREADY-COMPILED capability module. It is
// split out so a caller that had to build its module differently — see
// TestSetShuftiFrontendAgainstOracle, which needs an option the YAML config
// does not expose — gets the same memory layout and gate handling.
func newCapRunnerFrom(t *testing.T, w []byte, pats []string, input string) *capRunner {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	if err != nil {
		release()
		t.Fatalf("instantiate: %v", err)
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		release()
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr := inBase + span
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}
	r := &capRunner{store: store, inst: inst, mem: mem, inBase: inBase,
		gatePtr: gatePtr, outPtr: outPtr, npat: len(pats), release: release}
	r.resetGates()
	return r
}

// resetGates zeroes the gate array, which is how a caller declares the start
// of a drive. One page covers any id space these tests build.
func (r *capRunner) resetGates() {
	buf := r.mem.UnsafeData(r.store)
	for i := int32(0); i < 65536; i++ {
		buf[r.gatePtr+i] = 0
	}
	// The descriptor the export takes in place of the bare gate pointer, laid
	// out above the array inside the same page. Rewritten here, with the gates,
	// because this is what declares a fresh drive (internal/abi).
	abi.WriteFindScratch(buf, r.scratchPtr(), r.gatePtr, 0, 0)
}

// scratchPtr is where the descriptor lives: above the gate array, inside the
// page reserved for it.
func (r *capRunner) scratchPtr() int32 { return r.gatePtr + int32(r.npat)*4 + 64 }

func (r *capRunner) call(t *testing.T, name string, args ...interface{}) interface{} {
	t.Helper()
	fn := r.inst.GetFunc(r.store, name)
	if fn == nil {
		t.Fatalf("missing export %q", name)
	}
	res, err := fn.Call(r.store, args...)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// ---------------------------------------------------------------------------
// Oracles.

// oracleAnchored returns the ids of the patterns matching the WHOLE input.
//
// `dropped` names the patterns the compiler EXCLUDED from the set (nil when
// there are none). They are skipped by all three oracles for the same reason:
// a set that does not contain a pattern reports none of its matches, so
// expecting any is expecting the engine to break its own contract.
func oracleAnchored(pats []string, input string, dropped map[int]bool) []int {
	var out []int
	for k, p := range pats {
		if dropped[k] {
			continue
		}
		if regexp.MustCompile(`\A(?:` + normalizeForOracle(p) + `)\z`).MatchString(input) {
			out = append(out, k)
		}
	}
	return out
}

// oracleScanAll returns the ids of the patterns matching at some position >= from.
func oracleScanAll(pats []string, input string, from int, dropped map[int]bool) []int {
	var out []int
	for k, p := range pats {
		if dropped[k] {
			continue
		}
		if len(startsMatching(p, input, from)) > 0 {
			out = append(out, k)
		}
	}
	return out
}

// oracleFirstPosition returns the smallest start >= from at which any pattern
// matches, together with the ids matching there. Returns -1 when there is none.
func oracleFirstPosition(pats []string, input string, from int, dropped map[int]bool) (int, []int) {
	for p := from; p <= len(input); p++ {
		var ids []int
		for k, pat := range pats {
			if dropped[k] {
				continue
			}
			if matchesAt(pat, input, p) {
				ids = append(ids, k)
			}
		}
		if len(ids) > 0 {
			return p, ids
		}
	}
	return -1, nil
}

// normalizeForOracle re-serialises a pattern through regexp/syntax before it
// is embedded in a wrapper like `\A(?:pat)\z`.
//
// Regexp.String() returns the ORIGINAL source, so a pattern containing `\Q`
// quotes everything after it — including the wrapper's own closing paren —
// and silently builds a different regexp (or fails to compile at all). Parsing
// and re-printing produces a form with no `\Q` in it.
func normalizeForOracle(pat string) string {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		panic("oracle: pattern Go already accepted failed to re-parse: " + err.Error())
	}
	return parsed.String()
}

// probeCache memoises the `\A.{p}(?:pat)` probes matchesAt builds.
//
// Without it the oracle is QUADRATIC in input length per fuzz call, and the
// quadratic is pure waste: oracleScanAll calls startsMatching once per `from`,
// and each of those loops p from `from` to len — so the very same (pat, p)
// probe is recompiled once for every `from` at or below p. Only n distinct
// probes per pattern exist; the old code built O(n^2) of them, each costing
// time proportional to the PATTERN's size.
//
// That is what made a single fuzz call exceed the 10s deadline Go's worker
// arms per call (internal/fuzz.RunFuzzWorker → `panic("deadlocked!")`, whose
// own comment notes the message is never printed). Memoising is exact:
// the probe for a given (pat, p) is a pure
// function of those two values.
//
// Bounded by clearing wholesale: patterns change every fuzz iteration, so an
// unbounded map would grow for the life of the worker.
const probeCacheMax = 4096

var probeCache = map[string]*regexp.Regexp{}

func probeFor(pat string, p int) *regexp.Regexp {
	key := strconv.Itoa(p) + "\x00" + pat
	if re, ok := probeCache[key]; ok {
		return re
	}
	if len(probeCache) >= probeCacheMax {
		probeCache = make(map[string]*regexp.Regexp, probeCacheMax)
	}
	re := regexp.MustCompile(`\A` + dotPrefix(p) + `(?:` + normalizeForOracle(pat) + `)`)
	probeCache[key] = re
	return re
}

func matchesAt(pat, input string, p int) bool {
	return probeFor(pat, p).MatchString(input)
}

func startsMatching(pat, input string, from int) []int {
	var out []int
	for p := from; p <= len(input); p++ {
		if matchesAt(pat, input, p) {
			out = append(out, p)
		}
	}
	return out
}

func idsFromMask(mask uint64, n int) []int {
	var out []int
	for k := 0; k < n; k++ {
		if mask&(uint64(1)<<uint(k)) != 0 {
			out = append(out, k)
		}
	}
	return out
}

func eqIDs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Ints(a)
	sort.Ints(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------

// capCases are pattern sets chosen to cross the structural boundaries the
// emitters branch on: literal-frontend vs fallback bucket, fixed-length
// prefixes, anchors, empty-matchable patterns, and zero-length matches.
var capCases = []struct {
	name   string
	pats   []string
	inputs []string
}{
	{"literals", []string{"foo", "bar"}, []string{"", "foo", "foobar", "xxfooyybarzz", "bar"}},
	{"fixed-prefix", []string{`a.cX`, `X`}, []string{"abcX", "qqabcXqq", "X"}},
	{"anchors", []string{`\Afoo`, `bar\z`, `(?m:^)baz`}, []string{"foo", "foobar", "baz\nbaz", "xbar"}},
	{"empty-matchable", []string{`a*`, `b`}, []string{"", "a", "bab", "aaa"}},
	{"word-boundary", []string{`\bcat\b`, `dog`}, []string{"cat dog", "concat dog", "cat"}},
	{"counted-chain", []string{`AK[A-Z0-9]{4}`, `zz`}, []string{"AKABCD", "xxAKABCDzz", "zz"}},
	{"alternation", []string{`(?:cat|car)+`, `t`}, []string{"catcar", "t", "carcat"}},
}

// allIDs calls a `_all` capability and returns the matching ids, hiding the
// ABI split: the answer is either an i64 mask returned directly, or a count
// with the ids written into a caller-owned BITMAP. Both forms exist in the
// emitters, and a test that knew only the narrow one could not drive any set
// wide enough to select the Shufti frontend — which needs more literals than
// Teddy accepts, so its id space is always past 64.
//
// The form is read off the function's TYPE, never predicted from the pattern
// count, because the count does not decide it. A set holding a member on the
// BACKTRACKING engine takes the bitmap form at ANY width: Backtracking can
// answer "unknown" (abi.BTStackOverflow) and the narrow form's i64 return IS
// the mask, so there is nowhere to put that. Two routes put a member there —
// one over max_fallback_states, and, since bug 77's fix, any member whose
// `\b`/`\B`/`(?m:$)` branch a DFA cannot keep in priority order. The second
// needs two instructions (`\B|`), so a TWO-pattern set can be wide. Keying on
// `npat <= 64` therefore passed two arguments to a three-argument export and
// died before comparing anything (FUZZER_BUGS bug 82). tools/settest reads the
// form this way for the same reason.
func (r *capRunner) allIDs(t *testing.T, fn string, args ...interface{}) []int {
	t.Helper()
	f := r.inst.GetFunc(r.store, fn)
	if f == nil {
		t.Fatalf("missing export %q", fn)
	}
	if len(f.Type(r.store).Params()) == len(args) {
		return idsFromMask(uint64(r.call(t, fn, args...).(int64)), r.npat)
	}
	// The module only ORs bits in and counts 0 -> 1 transitions, so the bitmap
	// must start all-zero or it reports stale patterns (docs/sets.md).
	buf := r.mem.UnsafeData(r.store)
	nbytes := (r.npat + 7) / 8
	for i := 0; i < nbytes; i++ {
		buf[int(r.outPtr)+i] = 0
	}
	count := int(r.call(t, fn, append(args, r.outPtr)...).(int32))
	buf = r.mem.UnsafeData(r.store)
	var got []int
	for k := 0; k < r.npat; k++ {
		if buf[int(r.outPtr)+k/8]&(1<<uint(k%8)) != 0 {
			got = append(got, k)
		}
	}
	if count != len(got) {
		t.Errorf("%s: count = %d but bitmap holds %d ids (%v)", fn, count, len(got), got)
	}
	return got
}

// checkCapsAgainstOracle drives every capability of an instantiated set module
// and compares each answer with a formula built from Go regexp.
//
// Extracted from TestSetCapabilitiesAgainstOracle so a second caller can reuse
// it: TestSetShuftiFrontendAgainstOracle needs exactly these checks against a
// module the YAML config cannot build. Duplicating them would have meant the
// Shufti frontend was checked by a copy that could drift from the original.
func checkCapsAgainstOracle(t *testing.T, r *capRunner, pats []string, input string) {
	t.Helper()
	n := int32(len(input))

	// match: anchored, whole input.
	wantAnchored := oracleAnchored(pats, input, nil)

	// match_any: membership, never value equality.
	gotAny := r.call(t, "cap_match_any", r.inBase, n).(int32)
	if len(wantAnchored) == 0 {
		if gotAny != -1 {
			t.Fatalf("match_any = %d, want -1", gotAny)
		}
	} else if !containsInt(wantAnchored, int(gotAny)) {
		t.Fatalf("match_any = %d, not among %v", gotAny, wantAnchored)
	}

	// match_all: exact set.
	gotAll := r.allIDs(t, "cap_match_all", r.inBase, n)
	if !eqIDs(append([]int(nil), wantAnchored...), gotAll) {
		t.Fatalf("match_all = %v, want %v", gotAll, wantAnchored)
	}

	for from := 0; from <= len(input); from++ {
		f := int32(from)

		wantPos, wantIDs := oracleFirstPosition(pats, input, from, nil)

		wantScanAll := oracleScanAll(pats, input, from, nil)

		// scan_any reports a bare id and NO start, so the id
		// may name any pattern matching
		// anywhere at or after `from` — oracleScanAll's set, not
		// oracleFirstPosition's. wantPos still decides -1: a set
		// with a first position is a set with a match.
		gotAny2 := r.call(t, "cap_scan_any", r.inBase, n, f).(int32)
		if wantPos < 0 {
			if gotAny2 != -1 {
				t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny2)
			}
		} else if !containsInt(wantScanAll, int(gotAny2)) {
			t.Fatalf("scan_any(from=%d) id = %d, not among %v", from, gotAny2, wantScanAll)
		}

		gotScanAll := r.allIDs(t, "cap_scan_all", r.inBase, n, f)
		if !eqIDs(append([]int(nil), wantScanAll...), gotScanAll) {
			t.Fatalf("scan_all(from=%d) = %v, want %v", from, gotScanAll, wantScanAll)
		}

		// find: every tuple at the first matching position.
		total := int(r.call(t, "cap_find", r.inBase, n, f, r.scratchPtr(), r.outPtr, int32(r.npat)).(int32))
		if wantPos < 0 {
			if total != 0 {
				t.Fatalf("find(from=%d) = %d, want 0", from, total)
			}
			continue
		}
		if total != len(wantIDs) {
			t.Fatalf("find(from=%d) total = %d, want %d (ids %v)", from, total, len(wantIDs), wantIDs)
		}
		buf := r.mem.UnsafeData(r.store)
		var gotIDs []int
		for i := 0; i < total; i++ {
			base := int(r.outPtr) + i*12
			id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
			st := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
			en := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
			if st != wantPos {
				t.Fatalf("find(from=%d) tuple %d start = %d, want %d", from, i, st, wantPos)
			}
			wantEnd := anchoredExtent(pats[id], input, wantPos)
			if en != wantEnd {
				t.Fatalf("find(from=%d) pattern %d end = %d, want %d", from, id, en, wantEnd)
			}
			gotIDs = append(gotIDs, id)
		}
		if !eqIDs(append([]int(nil), wantIDs...), gotIDs) {
			t.Fatalf("find(from=%d) ids = %v, want %v", from, gotIDs, wantIDs)
		}
	}
}

func TestSetCapabilitiesAgainstOracle(t *testing.T) {
	for _, tc := range capCases {
		for _, input := range tc.inputs {
			t.Run(tc.name+"/"+input, func(t *testing.T) {
				r := newCapRunner(t, tc.pats, input, true)
				defer r.Close()
				checkCapsAgainstOracle(t, r, tc.pats, input)
			})
		}
	}
}

// anchoredExtent returns the RE2 leftmost-first extent of pat anchored exactly
// at position p, or -1 when it does not match there.
func anchoredExtent(pat, input string, p int) int {
	// Through probeFor, not a fresh Compile: the expression is character-for-
	// character the one probeFor caches, and this is called once per position
	// per pattern per capability, so an uncached compile made the harness's
	// cost scale with PATTERN LENGTH x positions — the term that pushed large
	// patterns past the fuzz worker's 10s deadline.
	m := probeFor(pat, p).FindStringIndex(input)
	if m == nil {
		return -1
	}
	return m[1]
}

func containsInt(v []int, x int) bool {
	for _, e := range v {
		if e == x {
			return true
		}
	}
	return false
}

// TestSetFindOverflowContract pins the overflow contract: the return value is the TOTAL
// at the position, the buffer takes what fits, and an overflowing call stores
// no state — so the grown retry sees exactly the same world.
func TestSetFindOverflowContract(t *testing.T) {
	pats := []string{"ab", "a", "abc"}
	input := "abc"
	r := newCapRunner(t, pats, input, true)
	defer r.Close()
	n := int32(len(input))

	full := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.scratchPtr(), r.outPtr, int32(len(pats))).(int32))
	if full != 3 {
		t.Fatalf("expected all three patterns at position 0, got %d", full)
	}
	for _, cap := range []int32{0, 1, 2} {
		got := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.scratchPtr(), r.outPtr, cap).(int32))
		if got != full {
			t.Fatalf("find with out_cap=%d returned %d, want the total %d", cap, got, full)
		}
	}
	// Idempotence: after the undersized probes, the full-size call must be
	// identical to calling it first.
	again := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.scratchPtr(), r.outPtr, int32(len(pats))).(int32))
	if again != full {
		t.Fatalf("full-size call after undersized probes returned %d, want %d", again, full)
	}
}

// TestSetFromOutOfRange pins the edge contract for from > len.
func TestSetFromOutOfRange(t *testing.T) {
	r := newCapRunner(t, []string{"a", "b"}, "ab", true)
	defer r.Close()
	n := int32(2)
	if got := r.call(t, "cap_scan_any", r.inBase, n, int32(99)).(int32); got != -1 {
		t.Errorf("scan_any(from>len) = %d, want -1", got)
	}
	if got := r.call(t, "cap_scan_all", r.inBase, n, int32(99)).(int64); got != 0 {
		t.Errorf("scan_all(from>len) = %d, want 0", got)
	}
	if got := r.call(t, "cap_find", r.inBase, n, int32(99), r.scratchPtr(), r.outPtr, int32(2)).(int32); got != 0 {
		t.Errorf("find(from>len) = %d, want 0", got)
	}
}

// FuzzSetCaps drives all seven capabilities of a two-pattern set against the
// whole-input oracle formulas at every `from`. It is the multi-capability counterpart
// to FuzzSet, which covers `find` alone.
func FuzzSetCaps(f *testing.F) {
	corpus := seedCorpus(seedFile)
	for i := 0; i+1 < len(corpus) && i < 200; i += 2 {
		f.Add(corpus[i].pattern, corpus[i+1].pattern, corpus[i].input)
	}
	f.Add(`foo`, `bar`, "xxfooyybar")
	f.Add(`\bcat\b`, `dog`, "cat dog concat")
	f.Add(`(?m:^)a`, `b`, "a\nba\nb")
	f.Add(`a*`, `b`, "bab")
	f.Add(`a.cX`, `X`, "abcXX")

	f.Fuzz(func(t *testing.T, pat1, pat2, input string) {
		// The whole-input oracle counts runes in its `.{p}` prefix, and the
		// per-`from` sweep below is quadratic, so keep inputs short and ASCII.
		if len(input) > 64 {
			t.Skip("input too long for the per-from sweep")
		}
		for i := 0; i < len(input); i++ {
			if input[i] >= 0x80 {
				t.Skip("non-ASCII input: the rune-counted whole-input oracle would misalign")
			}
		}
		pats := []string{pat1, pat2}
		for _, p := range pats {
			if reason := skipPattern(p, input); reason != "" {
				t.Skip(reason)
			}
			// Tighter than skipPattern's shared maxNFAInsts, because this
			// target compiles two patterns into eight capability bodies —
			// see maxSetCapsNFAInsts for the measured reason.
			if parsed, err := syntax.Parse(p, syntax.Perl); err == nil {
				if prog, err := syntax.Compile(parsed.Simplify()); err == nil &&
					len(prog.Inst) > maxSetCapsNFAInsts() {
					t.Skip("NFA too large for FuzzSetCaps' eight-body compile (see maxSetCapsNFAInsts)")
				}
			}
			if regexp.MustCompile(p).NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
		}

		w, dropped, err := compileCaps(pats, true)
		if err != nil {
			if isResourceCeiling(err) {
				t.Skip("resource ceiling")
			}
			t.Fatalf("set compile error on patterns Go stdlib accepts: %q + %q: %v", pat1, pat2, err)
		}
		store, inst, mem, release, err := instantiate(w)
		defer release()
		if err != nil {
			t.Fatalf("instantiate: %v", err)
		}
		const pageSize = 65536
		dataTop, err := utils.ParseDataSectionBytes(w)
		if err != nil {
			t.Fatalf("parse data section: %v", err)
		}
		inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
		outPtr := inBase + pageSize
		needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
		if cur := mem.Size(store); needed > cur {
			if _, err := mem.Grow(store, needed-cur); err != nil {
				t.Fatalf("grow: %v", err)
			}
		}
		if len(input) > 0 {
			copy(mem.UnsafeData(store)[inBase:], input)
		}
		r := &capRunner{store: store, inst: inst, mem: mem, inBase: inBase, outPtr: outPtr, npat: len(pats)}
		n := int32(len(input))

		// The anchored oracle gets the ANCHORED scope and the two below get the
		// global one: a pattern the anchored packer alone refused is gone from
		// match_any/match_all and still live for scan and find (bug 91).
		wantAnchored := oracleAnchored(pats, input, dropped.anchored)
		gotAny := int(r.call(t, "cap_match_any", inBase, n).(int32))
		if len(wantAnchored) == 0 {
			if gotAny != -1 {
				t.Fatalf("match_any = %d, want -1: pats=%q,%q input=%q", gotAny, pat1, pat2, input)
			}
		} else if !containsInt(wantAnchored, gotAny) {
			t.Fatalf("match_any = %d, not among %v: pats=%q,%q input=%q", gotAny, wantAnchored, pat1, pat2, input)
		}
		gotAll := r.allIDs(t, "cap_match_all", inBase, n)
		if !eqIDs(append([]int(nil), wantAnchored...), gotAll) {
			t.Fatalf("match_all = %v, want %v: pats=%q,%q input=%q", gotAll, wantAnchored, pat1, pat2, input)
		}

		for from := 0; from <= len(input); from++ {
			f32 := int32(from)
			wantPos, _ := oracleFirstPosition(pats, input, from, dropped.all)

			wantScanAll := oracleScanAll(pats, input, from, dropped.all)

			// See site 1: a bare id, checked against the anywhere-set.
			gotScanAny := r.call(t, "cap_scan_any", inBase, n, f32).(int32)
			if wantPos < 0 {
				if gotScanAny != -1 {
					t.Fatalf("scan_any(from=%d) = %d, want -1: pats=%q,%q input=%q", from, gotScanAny, pat1, pat2, input)
				}
			} else if !containsInt(wantScanAll, int(gotScanAny)) {
				t.Fatalf("scan_any(from=%d) id = %d, not among %v: pats=%q,%q input=%q", from, gotScanAny, wantScanAll, pat1, pat2, input)
			}
			gotScanAll := r.allIDs(t, "cap_scan_all", inBase, n, f32)
			if !eqIDs(append([]int(nil), wantScanAll...), gotScanAll) {
				t.Fatalf("scan_all(from=%d) = %v, want %v: pats=%q,%q input=%q", from, gotScanAll, wantScanAll, pat1, pat2, input)
			}
		}

		// The DEFAULT `find` configuration, against the union oracle.
		// The loop above compiled the set with overlapping: true, so this is
		// the one place the fuzzer reaches the gated body.
		gotGated := runGatedFind(t, pats, input).matches
		wantGated := gatedOracle(pats, input)
		sortMatches(gotGated)
		sortMatches(wantGated)
		if len(gotGated) != len(wantGated) {
			t.Fatalf("gated find: expected %d matches %v, got %d %v: pats=%q,%q input=%q",
				len(wantGated), wantGated, len(gotGated), gotGated, pat1, pat2, input)
		}
		for i := range wantGated {
			if gotGated[i] != wantGated[i] {
				t.Fatalf("gated find: match %d expected %+v, got %+v: pats=%q,%q input=%q",
					i, wantGated[i], gotGated[i], pat1, pat2, input)
			}
		}
	})
}

// TestSetWideAllBitmap exercises the >64-pattern form of match_all/scan_all,
// which switches from an i64 bitmask return to a caller-provided bitmap.
// The bit-per-pattern packing is easy to get wrong at
// exactly one place — bit 7 of a byte is 0x80, which is not a valid bare
// i32.const operand — so this checks ids on both sides of every byte boundary.
func TestSetWideAllBitmap(t *testing.T) {
	const n = 70
	pats := make([]string, n)
	names := make([]string, n)
	entries := make([]config.RegexEntry, n)
	for i := range pats {
		pats[i] = fmt.Sprintf("kw%02dX", i)
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: pats[i]}
	}
	sets := []config.SetConfig{{
		Name: "s", MatchAll: "cap_match_all", ScanAll: "cap_scan_all",
		Find: "cap_find", Overlapping: true,
		Patterns: config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatal(err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	outPtr := inBase + pageSize
	needed := uint64((int64(outPtr) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatal(err)
		}
	}

	// Pick ids straddling byte boundaries: 6,7,8 and 63,64,65 and the last.
	for _, want := range [][]int{{7}, {6, 7, 8}, {63, 64, 65}, {n - 1}, {0, 7, 8, 15, 16, 69}} {
		input := ""
		for _, id := range want {
			input += pats[id][:len(pats[id])] + " "
		}
		buf := mem.UnsafeData(store)
		copy(buf[inBase:], input)
		for i := int32(0); i < 16; i++ {
			buf[outPtr+i] = 0 // ceil(70/8) = 9 bytes; zero a little extra
		}
		fn := inst.GetFunc(store, "cap_scan_all")
		res, err := fn.Call(store, inBase, int32(len(input)), int32(0), outPtr)
		if err != nil {
			t.Fatalf("scan_all: %v", err)
		}
		count := int(res.(int32))
		buf = mem.UnsafeData(store)
		var got []int
		for k := 0; k < n; k++ {
			if buf[int(outPtr)+k/8]&(1<<uint(k%8)) != 0 {
				got = append(got, k)
			}
		}
		if count != len(want) {
			t.Errorf("scan_all(%q) count = %d, want %d (bitmap says %v)", input, count, len(want), got)
		}
		if !eqIDs(append([]int(nil), want...), got) {
			t.Errorf("scan_all(%q) bitmap = %v, want %v", input, got, want)
		}
	}
}

// The gated (default) `find` body: per-pattern non-overlapping output,
// filtered through a caller-owned gate array.
//
// The oracle is deliberately NOT a Go reimplementation of the biased gate
// encoding: a reference derived from the same
// spec paragraph as the emitter proves the two agree, not that either is
// right, and this project has already been bitten by exactly that, when
// re2test's comparison AND its oracle narrowed the input the same way.
//
// Instead Go computes the WHOLE answer: the complete gated output of a set is
// the union, over every pattern k, of `FindAllIndex(pk, input)` tagged with k.
// That holds because pattern k's gate depends only on k's own reported
// matches, the scan visits every position, and the caller advances by exactly
// one position — so each pattern independently performs "first eligible match,
// gate, repeat", which is the definition of FindAllIndex.

// compileGatedSet compiles pats into a standalone module whose `find` is the
// default gated body (no `overlapping:` key).
func compileGatedSet(pats []string) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:     "s",
		Find:     "gated_find",
		Patterns: config.PatternSelector{Names: names},
	}}
	return cachedCompile(fmt.Sprintf("gatedset\x00%s", setKey(pats)), func() ([]byte, error) {
		w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
		return w, err
	})
}

// gatedRun drives the gated find to exhaustion with a zeroed gate array, the
// way a generated iterator does, and returns every reported match plus the
// per-call batches for the structural invariants of the union oracle.
type gatedRun struct {
	matches []setMatch
	batches [][]setMatch
}

func runGatedFind(t *testing.T, pats []string, input string) gatedRun {
	t.Helper()
	w, err := compileGatedSet(pats)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "gated_find")
	if fn == nil {
		t.Fatal("module missing gated_find export")
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	span := int32((len(input) + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	gatePtr := inBase + span
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	if len(input) > 0 {
		copy(buf[inBase:], input)
	}
	// The stub's job: allocate the gate array and zero it. Nothing else.
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	// The scratch descriptor the export takes in place of the bare gate
	// pointer (internal/abi).
	scratchPtr := writeFindScratch(store, mem, gatePtr, int32(len(pats)), 0, 0)

	var run gatedRun
	from := int32(0)
	outCap := int32(len(pats))
	prevStart := -1
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), from, scratchPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("gated_find: %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		if n > int(outCap) {
			t.Fatalf("gated_find reported %d tuples at one position, buffer holds %d", n, outCap)
		}
		buf := mem.UnsafeData(store)
		var batch []setMatch
		start := -1
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
			s := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
			e := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
			if i == 0 {
				start = s
			} else if s != start {
				t.Fatalf("tuples in one call disagree on start: %d vs %d", start, s)
			}
			batch = append(batch, setMatch{PatternID: id, Start: s, End: e})
		}
		if start <= prevStart {
			t.Fatalf("start did not advance: %d after %d", start, prevStart)
		}
		prevStart = start
		run.batches = append(run.batches, batch)
		run.matches = append(run.matches, batch...)
		from = int32(start) + 1
	}
	return run
}

// gatedOracle is the union of Go FindAllIndex, tagged with the pattern id.
func gatedOracle(pats []string, input string) []setMatch {
	var out []setMatch
	for k, p := range pats {
		for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
			out = append(out, setMatch{PatternID: k, Start: x[0], End: x[1]})
		}
	}
	return out
}

func sortMatches(v []setMatch) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].PatternID != v[j].PatternID {
			return v[i].PatternID < v[j].PatternID
		}
		if v[i].Start != v[j].Start {
			return v[i].Start < v[j].Start
		}
		return v[i].End < v[j].End
	})
}

func checkGated(t *testing.T, pats []string, input string) {
	t.Helper()
	run := runGatedFind(t, pats, input)
	want := gatedOracle(pats, input)
	got := append([]setMatch(nil), run.matches...)
	sortMatches(want)
	sortMatches(got)
	if len(want) != len(got) {
		t.Fatalf("%v on %q: expected %d matches %v, got %d %v", pats, input, len(want), want, len(got), got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%v on %q: match %d expected %+v, got %+v", pats, input, i, want[i], got[i])
		}
	}

	// Encoding-independent invariants. These hold whatever the gate
	// formula says, and a wrong bias direction violates them immediately.
	byID := map[int][]setMatch{}
	for _, m := range run.matches {
		byID[m.PatternID] = append(byID[m.PatternID], m)
	}
	for id, ms := range byID {
		sortMatches(ms)
		for i := 1; i < len(ms); i++ {
			if ms[i].Start < ms[i-1].End {
				t.Fatalf("%v on %q: pattern %d reported overlapping matches %+v and %+v",
					pats, input, id, ms[i-1], ms[i])
			}
			if ms[i].Start <= ms[i-1].Start {
				t.Fatalf("%v on %q: pattern %d starts not strictly increasing: %+v then %+v",
					pats, input, id, ms[i-1], ms[i])
			}
		}
	}

	// Re-zeroing the gates and rescanning reproduces the identical sequence.
	again := runGatedFind(t, pats, input)
	if len(again.matches) != len(run.matches) {
		t.Fatalf("%v on %q: rescan produced %d matches, first scan %d", pats, input, len(again.matches), len(run.matches))
	}
	for i := range run.matches {
		if again.matches[i] != run.matches[i] {
			t.Fatalf("%v on %q: rescan differs at %d: %+v vs %+v", pats, input, i, again.matches[i], run.matches[i])
		}
	}
}

// TestGatedFindOneSet runs the corpus of every pattern as a ONE-pattern set,
// where the union oracle degenerates to plain FindAllIndex — the cheapest and
// sharpest check of the gate encoding across empty-match shapes and extents.
func TestGatedFindOneSet(t *testing.T) {
	pats := []string{
		`a*`, `a+`, `a`, `ab`, `[a-z]+X`, `x?`, `(?:)`, `a{2,5}`, `\d+`,
		`foo|foobar`, `(?:ab)+`, `\bcat\b`, `(?m:^)a`, `a(?m:$)`, `\Aab`, `ab\z`,
	}
	inputs := []string{"", "a", "aa", "aaa", "bab", "abcX", "cat cat", "a\nba\n", "abab", "foobar"}
	for _, p := range pats {
		for _, in := range inputs {
			t.Run(p+"|"+in, func(t *testing.T) { checkGated(t, []string{p}, in) })
		}
	}
}

// TestGatedFindInterleaving covers the multi-pattern case the union oracle is
// really for: two patterns whose gates advance independently.
func TestGatedFindInterleaving(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`[a-z]+X`, `b`}, "abXbX"},
		{[]string{`a*`, `b`}, "bab"},
		{[]string{`foo`, `foobar`}, "foobarfoo"},
		{[]string{`a+`, `aa`}, "aaaa"},
		{[]string{`\bcat\b`, `cat`}, "cat concat cat"},
		{[]string{`(?m:^)x`, `x`}, "x\nxx"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) { checkGated(t, c.pats, c.input) })
	}
}

// TestGatedSubsetOfUngated pins the invariant that the gated output is
// a subset of the ungated one for the same set and input.
func TestGatedSubsetOfUngated(t *testing.T) {
	pats := []string{`[a-z]+X`, `b`}
	input := "abXbX"
	gated := runGatedFind(t, pats, input).matches

	w, _, err := compileSet(pats)
	if err != nil {
		t.Fatal(err)
	}
	ungated, hang, err := runWasmSetFind(w, input, len(pats))
	if err != nil || hang {
		t.Fatalf("ungated run: err=%v hang=%v", err, hang)
	}
	inUngated := map[setMatch]bool{}
	for _, m := range ungated {
		inUngated[m] = true
	}
	for _, m := range gated {
		if !inUngated[m] {
			t.Fatalf("gated reported %+v, which the ungated body does not produce", m)
		}
	}
}

// TestGatedOverflowStoresNoState pins the overflow contract: an overflowing call must
// leave the gate array byte-for-byte as it found it, so a grown retry sees the
// identical world. Probing with out_cap 0 then 1 then the full size must give
// the same answer as calling at full size first.
func TestGatedOverflowStoresNoState(t *testing.T) {
	pats := []string{"ab", "a", "abc"}
	input := "abcabc"

	full := runGatedFind(t, pats, input).matches

	// Same scan, but each position is first probed with undersized buffers.
	w, err := compileGatedSet(pats)
	if err != nil {
		t.Fatal(err)
	}
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatal(err)
	}
	fn := inst.GetFunc(store, "gated_find")
	const pageSize = 65536
	dataTop, _ := utils.ParseDataSectionBytes(w)
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + 2*pageSize) / pageSize)
	if cur := mem.Size(store); needed > cur {
		mem.Grow(store, needed-cur) //nolint:errcheck
	}
	copy(mem.UnsafeData(store)[inBase:], input)
	scratchPtr := writeFindScratch(store, mem, gatePtr, int32(len(pats)), 0, 0)

	var got []setMatch
	from := int32(0)
	for {
		// Undersized probes first — these must not touch the gate array.
		for _, cap := range []int32{0, 1} {
			if _, err := fn.Call(store, inBase, int32(len(input)), from, scratchPtr, outPtr, cap); err != nil {
				t.Fatal(err)
			}
		}
		res, err := fn.Call(store, inBase, int32(len(input)), from, scratchPtr, outPtr, int32(len(pats)))
		if err != nil {
			t.Fatal(err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf := mem.UnsafeData(store)
		start := 0
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			m := setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			}
			start = m.Start
			got = append(got, m)
		}
		from = int32(start) + 1
	}
	sortMatches(full)
	sortMatches(got)
	if len(full) != len(got) {
		t.Fatalf("undersized probes changed the scan: %d matches vs %d", len(got), len(full))
	}
	for i := range full {
		if full[i] != got[i] {
			t.Fatalf("undersized probes changed match %d: %+v vs %+v", i, got[i], full[i])
		}
	}
}

// TestGatedLadder is the linearity obligation: the
// `a+`-in-a-set n-ladder that made the case for gating in the first place.
// The ungated scan measured a textbook O(n^2) (x4 per doubling);
// gating must make it linear. Run with -v to see the table.
func TestGatedLadder(t *testing.T) {
	if testing.Short() {
		t.Skip("ladder measurement")
	}
	for _, n := range []int{500, 1000, 2000, 4000, 8000} {
		input := ""
		for i := 0; i < n; i++ {
			input += "a"
		}
		run := runGatedFind(t, []string{`a+`}, input)
		if len(run.matches) != 1 {
			t.Fatalf("n=%d: gated `a+` should report exactly one match, got %d", n, len(run.matches))
		}
		if run.matches[0] != (setMatch{PatternID: 0, Start: 0, End: n}) {
			t.Fatalf("n=%d: expected 0..%d, got %+v", n, n, run.matches[0])
		}
		t.Logf("n=%-5d calls=%d matches=%d", n, len(run.batches), len(run.matches))
	}
}

// TestGatedLadderFuel is the complexity assertion TestGatedLadder above is
// NOT — and the omission mattered.
//
// TestGatedLadder counts calls and matches, both of which are 1 at every n, so
// it read as "linear, as predicted" while the gated body was in fact
// still quadratic in WORK: the mask skip and jump were never emitted, so
// the terminating call ran each suffix DFA to its full extent at every gated
// position — 7.8M fuel at n=500 rising x4 per doubling to 1.98B at n=8000.
//
// The lesson generalised in R-TESTS(3): when the CLAIM is a complexity bound,
// the test has to measure work, not iterations. Fuel is deterministic, so this
// is an exact assertion rather than a timing heuristic.
func TestGatedLadderFuel(t *testing.T) {
	if testing.Short() {
		t.Skip("ladder measurement")
	}
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(cfg)

	w, err := compileGatedSet([]string{`a+`})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	defer mod.Close()

	fuelAt := func(n int) uint64 {
		store := wasmtime.NewStore(engine)
		defer store.Close()
		if err := store.SetFuel(1 << 42); err != nil {
			t.Fatalf("set fuel: %v", err)
		}
		inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
		if err != nil {
			t.Fatalf("instantiate: %v", err)
		}
		mem := inst.GetExport(store, "memory").Memory()
		const pageSize = 65536
		inBase := int32(1 << 20)
		gatePtr := inBase + int32((n/pageSize+2)*pageSize)
		outPtr := gatePtr + pageSize
		need := uint64((int64(outPtr) + 2*pageSize) / pageSize)
		if cur := mem.Size(store); need > cur {
			if _, err := mem.Grow(store, need-cur); err != nil {
				t.Fatalf("grow: %v", err)
			}
		}
		buf := mem.UnsafeData(store)
		for i := 0; i < n; i++ {
			buf[int(inBase)+i] = 'a'
		}
		for i := int32(0); i < 4; i++ {
			buf[gatePtr+i] = 0
		}
		scratchPtr := writeFindScratch(store, mem, gatePtr, 1, 0, 0)
		fn := inst.GetFunc(store, "gated_find")
		var total uint64
		from := int32(0)
		for {
			before, _ := store.GetFuel()
			res, err := fn.Call(store, inBase, int32(n), from, scratchPtr, outPtr, int32(1))
			if err != nil {
				t.Fatalf("gated_find: %v", err)
			}
			after, _ := store.GetFuel()
			total += before - after
			got := int(res.(int32))
			if got <= 0 {
				break
			}
			buf = mem.UnsafeData(store)
			from = le32(buf[int(outPtr)+4:]) + 1
		}
		return total
	}

	prev := uint64(0)
	prevN := 0
	for _, n := range []int{500, 1000, 2000, 4000, 8000} {
		f := fuelAt(n)
		if prev != 0 {
			// Linear would be x2 per doubling; quadratic x4. Assert well below
			// the quadratic line so this catches a regression without being
			// brittle about the exact constant.
			ratio := float64(f) / float64(prev)
			t.Logf("n=%-5d fuel=%-12d ratio vs n=%d: %.2fx", n, f, prevN, ratio)
			if ratio > 3.0 {
				t.Errorf("fuel grew %.2fx from n=%d to n=%d — that is the quadratic "+
					"behaviour the mask skip and jump exist to remove "+
					"(gated find must stay linear in input length)", ratio, prevN, n)
			}
		} else {
			t.Logf("n=%-5d fuel=%d", n, f)
		}
		prev, prevN = f, n
	}
}

// find_batch: several consecutive positions per call, resumed by cursor.
//
// The oracle is the same one the gated `find` target uses: Go's
// FindAllIndex per pattern, tagged with the pattern id. Deriving a reference
// from the emitter's own cursor arithmetic would only prove it agrees with
// itself.
//
// What makes this target sharp is the out_cap sweep. Batching is only
// interesting where a bufferful ENDS mid-position, and out_cap = 1 forces that
// at every position with more than one match, while out_cap = 2 lands the
// split at a different offset within the position. A body that resumes a split
// position wrongly re-reports or drops exactly the tuples the sweep straddles.

// compileBatchSet compiles pats into a standalone module exporting both `find`
// and `find_batch`, so the two can be compared directly. They are independent
// bodies over shared suffix functions, which is also what makes declaring both
// worth testing: the shared functions must serve either caller.
func compileBatchSet(pats []string, overlapping bool) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Find:        "set_find",
		Hints:       []string{"batch-find"},
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	return cachedCompile(fmt.Sprintf("batchset\x00%v\x00%s", overlapping, setKey(pats)), func() ([]byte, error) {
		w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
		return w, err
	})
}

// runBatchFind drives find_batch to exhaustion with the given buffer capacity,
// exactly as a generated iterator would: allocate the buffer and the gate
// array, start from cursor 0, hand the previous return value back unchanged.
//
// Compiles and instantiates per call. checkBatch drives ONE set through ten
// combinations of capacity and cache, so it uses batchRunner below instead and
// compiles once — see the comment there for why that is not just a speed-up.
func runBatchFind(t *testing.T, pats []string, input string, outCap int32, overlapping, withCache bool) []setMatch {
	t.Helper()
	r := newBatchRunner(t, pats, input, overlapping)
	defer r.release()
	return r.drive(t, outCap, withCache)
}

// batchRunner holds one compiled, instantiated set so a caller can drive it
// many times.
//
// The module owns NO state across calls — see docs/sets.md — so every drive is
// independent as long as it re-zeroes the caller-owned arrays, which drive()
// does. That is the contract, so exercising it this way is a check on the
// contract as well as a way to compile once instead of ten times.
//
// It matters for more than speed. A fuzz worker kills a call that takes longer
// than ten seconds, and recompiling per combination put the heaviest seeds
// (`A{1000}` and friends, ~0.9s each even before the cache dimension doubled
// them) close enough to that limit to be killed under load — reported as
// "fuzzing process hung or terminated unexpectedly", which reads like an
// engine hang and is not one.
type batchRunner struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	release  func()
	fn       *wasmtime.Func
	pats     []string
	input    string
	inBase   int32
	gatePtr  int32
	outPtr   int32
	cachePtr int32
	cacheLen int32
	// The checkpointed cache's stride, which the CALLER writes because the
	// caller is what sized the region from it.
	cacheStride int32
}

func newBatchRunner(t *testing.T, pats []string, input string, overlapping bool) *batchRunner {
	t.Helper()
	w, err := compileBatchSet(pats, overlapping)
	if err != nil {
		// A documented construction ceiling is not a defect. FuzzSet already
		// learned this the hard way — see isResourceCeiling's own comment
		// about FuzzSet/40f883ef54d47f63 — and the batch target simply never
		// inherited the skip, so `\baa00\b` beside a pattern whose suffix
		// blows the DFA state limit reported as a fuzz failure.
		if isResourceCeiling(err) {
			t.Skip("resource ceiling")
		}
		t.Fatalf("compile %v: %v", pats, err)
	}
	store, inst, mem, release, err := instantiate(w)
	if err != nil {
		release()
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "set_find_batch")
	if fn == nil {
		t.Fatal("module missing set_find_batch export")
	}
	const pageSize = 65536
	// The overlapping answer cache, offered only when the caller
	// asks. Sized at the sweep's own worst case so "too small" is never the
	// reason a drive declines — that path has its own test.
	inBase, gatePtr, outPtr, cachePtr, err := cacheDriveAddrs(w, len(input), false)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	cacheLen, cacheStride := overlapCacheFor(input, pats)
	needed := uint64((int64(cachePtr) + int64(cacheLen) + 2*pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	buf := mem.UnsafeData(store)
	if len(input) > 0 {
		copy(buf[inBase:], input)
	}
	runtime.KeepAlive(store)
	return &batchRunner{
		store: store, inst: inst, mem: mem, release: release, fn: fn,
		pats: pats, input: input,
		inBase: inBase, gatePtr: gatePtr, outPtr: outPtr,
		cachePtr: cachePtr, cacheLen: cacheLen, cacheStride: cacheStride,
	}
}

// drive runs one complete find_batch drive at the given capacity, offering the
// answer cache or not.
func (r *batchRunner) drive(t *testing.T, outCap int32, withCache bool) []setMatch {
	t.Helper()
	store, mem, fn := r.store, r.mem, r.fn
	pats, input := r.pats, r.input
	inBase, gatePtr, outPtr := r.inBase, r.gatePtr, r.outPtr

	// Every drive starts from a zeroed gate array — the gate contract — and,
	// when one is offered, a zeroed cache header.
	buf := mem.UnsafeData(store)
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	passCache, passCacheLen := int32(0), int32(0)
	if withCache {
		passCache, passCacheLen = r.cachePtr, r.cacheLen
		for i := int32(0); i < config.SetOverlapCheckpointHeaderBytes; i++ {
			buf[passCache+i] = 0
		}
	}
	// The scratch descriptor the export takes in place of the bare gate
	// pointer: it carries the gate array AND the cache, so it is written after
	// the cache has been decided (internal/abi).
	scratchPtr := writeFindScratchStride(store, mem, gatePtr, int32(len(pats)), passCache, passCacheLen, r.cacheStride)
	runtime.KeepAlive(store)

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out []setMatch
	cursor := int64(0)
	// A batch call always either reports a tuple or ends the scan, so the
	// number of calls is bounded by the number of matches. The cap turns a
	// non-advancing cursor into a failure instead of a hang.
	maxCalls := 8*(len(input)+1)*(len(pats)+1) + 16
	for calls := 0; ; calls++ {
		if calls > maxCalls {
			t.Fatalf("%v on %q cap=%d: find_batch did not terminate after %d calls",
				pats, input, outCap, calls)
		}
		// One signature for both flavours: the
		// overlapping entry records no match gates but takes the array as the
		// per-drive home of its preflight verdict.
		res, err := fn.Call(store, inBase, int32(len(input)), cursor,
			scratchPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		if n < 0 || n > outCap {
			t.Fatalf("%v on %q cap=%d: count %d out of range", pats, input, outCap, n)
		}
		buf := mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			})
		}
		if uint32(packed>>32) == 0xFFFFFFFF {
			break
		}
		cursor = packed
	}
	return out
}

// checkBatch compares find_batch against the union-of-FindAllIndex oracle at
// several buffer capacities, including capacities far below one position's
// worst case.
func checkBatch(t *testing.T, pats []string, input string) {
	t.Helper()
	want := gatedOracle(pats, input)
	sortMatches(want)
	// One compile for all ten drives below. This is the difference between
	// ~0.9s and ~9s on the heaviest seeds, which is the difference between a
	// fuzz worker finishing the call and killing it.
	runner := newBatchRunner(t, pats, input, false)
	defer runner.release()
	for _, outCap := range []int32{1, 2, int32(len(pats)), int32(len(pats)) + 3, 64} {
		if outCap < 1 {
			continue
		}
		// BOTH engines behind the one export. Declining the cache drives the
		// ordinary per-position walk; offering it lets the drive switch to
		// the backward sweep once its own work says
		// the walk is expensive. They are two implementations of one
		// contract, and only running both can tell them apart — an answer
		// that matches the oracle says nothing about which produced it.
		for _, withCache := range []bool{false, true} {
			got := runner.drive(t, outCap, withCache)
			sortMatches(got)
			if len(want) != len(got) {
				t.Fatalf("%v on %q cap=%d cache=%v: expected %d matches %v, got %d %v",
					pats, input, outCap, withCache, len(want), want, len(got), got)
			}
			for i := range want {
				if want[i] != got[i] {
					t.Fatalf("%v on %q cap=%d cache=%v: match %d expected %+v, got %+v",
						pats, input, outCap, withCache, i, want[i], got[i])
				}
			}
		}
	}
}

func TestFindBatchOneSet(t *testing.T) {
	pats := []string{
		`a*`, `a+`, `a`, `ab`, `[a-z]+X`, `x?`, `(?:)`, `a{2,5}`, `\d+`,
		`foo|foobar`, `(?:ab)+`, `\bcat\b`, `(?m:^)a`, `a(?m:$)`, `\Aab`, `ab\z`,
	}
	inputs := []string{"", "a", "aa", "aaa", "bab", "abcX", "cat cat", "a\nba\n", "abab", "foobar"}
	for _, p := range pats {
		for _, in := range inputs {
			t.Run(p+"|"+in, func(t *testing.T) { checkBatch(t, []string{p}, in) })
		}
	}
}

// TestFindBatchMultiPattern is where a split position actually happens: several
// patterns reporting at ONE start, with a buffer too small to hold them all.
func TestFindBatchMultiPattern(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`a`, `a`, `a`, `a`}, "aaaa"},
		{[]string{`a`, `ab`, `abc`, `abcd`}, "abcdabcd"},
		{[]string{`a*`, `a+`, `a`}, "aaa"},
		{[]string{`foo`, `foobar`, `o`, `oo`}, "foobar foo"},
		{[]string{`x?`, `y?`, `z?`}, "xyz"},
		{[]string{`\bcat\b`, `cat`, `at`, `t`}, "cat concat cat"},
		{[]string{`(?m:^)a`, `a`, `a(?m:$)`}, "a\na\na"},
		{[]string{`\d+`, `\d`, `[0-9]{2}`}, "12345"},
		{[]string{`(?:)`, `a`}, "aaa"},
		{[]string{`ab\z`, `b`, `ab`}, "abab"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) { checkBatch(t, c.pats, c.input) })
	}
}

// TestFindBatchOverlapping covers the mode with no gate array, where a split
// position is resumed through the cursor's k field and the suffix functions'
// `skip` parameter instead.
func TestFindBatchOverlapping(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`a`}, "aaa"},
		{[]string{`a*`}, "aa"},
		{[]string{`a`, `a`, `a`}, "aaa"},
		{[]string{`a`, `ab`, `abc`}, "abcabc"},
		{[]string{`a{2,5}?`}, "aaaaaa"},
		{[]string{`.*?end`, `end`}, "xyzend"},
		{[]string{`foo`, `o`, `oo`}, "foo foo"},
		{[]string{`x?`, `y?`}, "xy"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pats)+"|"+c.input, func(t *testing.T) {
			var want []setMatch
			for k, p := range c.pats {
				for _, sp := range allStartPositionMatches(regexp.MustCompile(p), c.input) {
					want = append(want, setMatch{PatternID: k, Start: sp[0], End: sp[1]})
				}
			}
			sortMatches(want)
			runner := newBatchRunner(t, c.pats, c.input, true)
			defer runner.release()
			for _, outCap := range []int32{1, 2, int32(len(c.pats)), 64} {
				// Overlapping is the ONLY policy the answer cache serves, so
				// this is where offering it matters most.
				for _, withCache := range []bool{false, true} {
					got := runner.drive(t, outCap, withCache)
					sortMatches(got)
					if len(want) != len(got) {
						t.Fatalf("%v on %q cap=%d cache=%v: expected %d %v, got %d %v",
							c.pats, c.input, outCap, withCache, len(want), want, len(got), got)
					}
					for i := range want {
						if want[i] != got[i] {
							t.Fatalf("%v on %q cap=%d cache=%v: match %d expected %+v, got %+v",
								c.pats, c.input, outCap, withCache, i, want[i], got[i])
						}
					}
				}
			}
		})
	}
}

// FuzzFindBatch is the differential target: two arbitrary patterns, driven at a
// buffer capacity of ONE so every multi-match position is split, against the
// union-of-FindAllIndex oracle.
//
// Capacity 1 is the sharpest setting available. It maximises the number of
// resume points, and every one of them exercises the property the whole design
// rests on: re-entering a position enumerates it identically, minus what was
// already delivered.
func FuzzFindBatch(f *testing.F) {
	corpus := seedCorpus(seedFile)
	for i := 0; i+1 < len(corpus) && i < 200; i += 2 {
		f.Add(corpus[i].pattern, corpus[i+1].pattern, corpus[i].input)
	}
	f.Add(`foo`, `bar`, "xxfooyybar")
	f.Add(`a*`, `a`, "aaa")
	f.Add(`\bcat\b`, `cat`, "cat concat")
	f.Add(`(?m:^)a`, `a`, "a\nba\nb")
	f.Add(`(?:)`, `a`, "aa")

	f.Fuzz(func(t *testing.T, pat1, pat2, input string) {
		if len(input) > 48 {
			t.Skip("input too long: the capacity-1 sweep is one WASM call per match")
		}
		pats := []string{pat1, pat2}
		for _, p := range pats {
			if reason := skipPattern(p, input); reason != "" {
				t.Skip(reason)
			}
			if regexp.MustCompile(p).NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
		}
		checkBatch(t, pats, input)
	})
}

// TestFindBatchZeroCap pins the raw-ABI contract for a buffer with no room.
//
// A caller that loops "call, consume count, hand the cursor back, stop on the
// sentinel" is the shape every generated stub has, and it is the only shape the
// cursor supports. With out_cap = 0 the body can deliver nothing, so if it
// returned the caller's own resume position the loop would never advance and
// never stop. It reports the scan finished instead — the buffer, the gate array
// and the count all stay at "nothing happened", and the loop terminates.
//
// This is a deliberate asymmetry with `find`, where out_cap = 0 is a size probe:
// `find` returns a COUNT, which a probe can use, while find_batch returns a
// resumable cursor, which a probe cannot.
func TestFindBatchZeroCap(t *testing.T) {
	for _, overlapping := range []bool{false, true} {
		name := "gated"
		if overlapping {
			name = "overlapping"
		}
		t.Run(name, func(t *testing.T) {
			pats := []string{`a`, `ab`, `b`}
			const input = "abab"

			w, err := compileBatchSet(pats, overlapping)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "set_find_batch")
			if fn == nil {
				t.Fatal("module missing set_find_batch export")
			}
			const pageSize = 65536
			dataTop, err := utils.ParseDataSectionBytes(w)
			if err != nil {
				t.Fatalf("parse data section: %v", err)
			}
			inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
			gatePtr := inBase + pageSize
			outPtr := gatePtr + pageSize
			needed := uint64((int64(outPtr) + 2*pageSize + pageSize - 1) / pageSize)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatalf("grow: %v", err)
				}
			}
			buf := mem.UnsafeData(store)
			copy(buf[inBase:], input)
			for i := int32(0); i < 4*int32(len(pats)); i++ {
				buf[gatePtr+i] = 0
			}
			// Poison the tuple buffer: a body that wrote through a zero-length
			// buffer would clear these.
			for i := int32(0); i < 12*int32(len(pats)); i++ {
				buf[outPtr+i] = 0xAA
			}

			countBits := uint(config.SetCursorCountBits(len(pats)))
			countMask := int64(1)<<countBits - 1

			// The `from` of the very first call is 0, which is also a legal
			// resume position — the value the pre-fix body handed back.
			desc := writeFindScratch(store, mem, gatePtr, int32(len(pats)), 0, 0)
			res, err := fn.Call(store, inBase, int32(len(input)), int64(0), desc, outPtr, int32(0))
			if err != nil {
				t.Fatalf("set_find_batch: %v", err)
			}
			packed := res.(int64)
			if got := uint32(packed >> 32); got != 0xFFFFFFFF {
				t.Fatalf("out_cap=0: expected the done sentinel, got resume position %d "+
					"(a caller looping on this cursor spins)", got)
			}
			if n := packed & countMask; n != 0 {
				t.Fatalf("out_cap=0: count %d, want 0", n)
			}
			buf = mem.UnsafeData(store)
			for i := int32(0); i < 12*int32(len(pats)); i++ {
				if buf[outPtr+i] != 0xAA {
					t.Fatalf("out_cap=0: wrote byte %d of the tuple buffer", i)
				}
			}
			for i := int32(0); i < 4*int32(len(pats)); i++ {
				if buf[gatePtr+i] != 0 {
					t.Fatalf("out_cap=0: wrote byte %d of the gate array", i)
				}
			}

			// And the loop a stub writes terminates on the first call.
			if got := runBatchFind(t, pats, input, 0, overlapping, false); len(got) != 0 {
				t.Fatalf("out_cap=0: yielded %d matches, want none", got)
			}
		})
	}
}

// TestBatchZeroCapTerminates pins the raw-ABI zero-capacity contract.
//
// find_batch returns a packed i64: bits 63..32 are the resume position, or
// 0xFFFFFFFF when the scan is finished. A caller driving the export directly,
// with no generated stub, loops until it sees that sentinel.
//
// out_cap = 0 is the case that could break the loop: a buffer with no room
// delivers nothing, and returning the caller's own resume position unchanged
// would make such a loop spin forever. set_batch.go therefore reports the scan
// FINISHED at zero capacity. Plain `find` keeps treating out_cap = 0 as a size
// probe instead, which it can because it returns a count rather than a
// resumable cursor — a different function with a different contract, covered by
// make setcaps.
//
// Both the gated and the overlapping entries are checked. They share ONE
// signature — the gate array included, which the overlapping body uses as the
// per-drive home of its "matches nowhere" preflight verdict rather than for
// gating — but they reach the sentinel through different arms.
func TestBatchZeroCapTerminates(t *testing.T) {
	pats := []string{`ab`, `b`}
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	for _, overlapping := range []bool{false, true} {
		t.Run(fmt.Sprintf("overlapping=%v", overlapping), func(t *testing.T) {
			cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{{
				Name: "s", Find: "set_find", Hints: []string{"batch-find"},
				Overlapping: overlapping,
				Patterns:    config.PatternSelector{Names: names},
			}}}
			w, _, _, err := compile.CompileFileDiag(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "set_find_batch")
			if fn == nil {
				t.Fatal("module missing set_find_batch export")
			}
			const pg = 65536
			dataTop, err := utils.ParseDataSectionBytes(w)
			if err != nil {
				t.Fatal(err)
			}
			inBase := int32((dataTop + pg - 1) / pg * pg)
			gate := inBase + pg
			out := gate + pg
			needed := uint64((int64(out) + 2*pg + pg - 1) / pg)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatal(err)
				}
			}
			input := "abab" // deliberately HAS matches: the point is that a
			// full buffer's worth of work is still reported as finished when
			// there is nowhere to put it.
			copy(mem.UnsafeData(store)[inBase:], input)

			// Both flavours take the scratch descriptor, which carries the
			// gate array and (declined here) the answer cache.
			desc := writeFindScratch(store, mem, gate, 4, 0, 0)
			res, err := fn.Call(store, inBase, int32(len(input)), int64(0), desc, out, int32(0))
			if err != nil {
				t.Fatalf("set_find_batch: %v", err)
			}
			packed := uint64(res.(int64))
			if hi := uint32(packed >> 32); hi != 0xFFFFFFFF {
				t.Fatalf("out_cap=0 returned position %#08x, want the 0xFFFFFFFF done "+
					"sentinel — a raw-ABI caller looping on this cursor would spin", hi)
			}
			countBits := uint(config.SetCursorCountBits(len(pats)))
			if n := packed & (1<<countBits - 1); n != 0 {
				t.Fatalf("out_cap=0 reported %d tuples, but nothing can be written", n)
			}
		})
	}
}

// Sparse promotion for the ANCHORED and FALLBACK packers.
//
// The shared-literal find packer got sparse accept first; these are the two
// paths that still split at 32 patterns afterwards, and they pay for a split
// differently from each other:
//
//   - fallback buckets have no literal gating them, so each of the ceil(N/32)
//     walks runs at EVERY input position;
//   - anchored buckets are called in turn by emitSetAnchoredCapBody, so a split
//     is ceil(N/32) full passes over the input per match_any call, whatever the
//     input looks like.
//
// Every case below is sized 33..64 patterns on purpose: above 32 so the packers
// really do split without promotion, at or below 64 so the `_all` capabilities
// keep the narrow i64-mask ABI and the existing oracles apply unchanged. The
// wide ABI over the same code is covered by TestSparsePromotionWideAll.

// sparseFamilies generate patterns that share enough structure for the merged
// DFA to stay inside the construction budgets. That constraint is real rather than
// incidental: 128 mutually unrelated patterns merge to a 416-state u16 table of
// 213 KB against a 64 KB budget, and promoteSparseBuckets correctly refuses it.
var sparseFamilies = []struct {
	name   string
	gen    func(i int) string
	inputs []string
}{
	{
		name:   "classchain",
		gen:    func(i int) string { return fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%6, 1+i/6%6) },
		inputs: []string{"", "a1", "abc123", "zzzz9999", "xx", "abcdef123456xy"},
	},
	{
		name:   "sharedlit",
		gen:    func(i int) string { return fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i%6, 1+i/6%6) },
		inputs: []string{"", "union a1", "union   abc123", "unionabc", "xx union ab12 yy"},
	},
	{
		name:   "alternation",
		gen:    func(i int) string { return fmt.Sprintf(`(?:a%d|b%d)+`, i, i) },
		inputs: []string{"", "a1", "a1a1", "b33", "a1b1a1"},
	},
}

func sparsePats(gen func(int) string, n int) []string {
	pats := make([]string, n)
	for i := range pats {
		pats[i] = gen(i)
	}
	return pats
}

// bucketTypes returns the bucket types the compiler recorded for the set. A
// test that only checked answers would pass just as happily with the promotion
// never firing, so every case below asserts the packing it meant to exercise.
func bucketTypes(t *testing.T, pats []string) (find []string) {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name: "s", MatchAny: "cap_match_any", MatchAll: "cap_match_all",
		ScanAny: "cap_scan_any", ScanAll: "cap_scan_all", Find: "cap_find",
		Patterns: config.PatternSelector{Names: names},
	}}
	_, _, diags, err := compile.CompileFileDiag(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, d := range diags {
		for _, b := range d.Buckets {
			find = append(find, b.Type)
		}
	}
	return find
}

func TestSparsePromotionCapabilities(t *testing.T) {
	const n = 40 // > 32 so the packers split; <= 64 so `_all` stays narrow
	for _, fam := range sparseFamilies {
		pats := sparsePats(fam.gen, n)

		t.Run(fam.name+"/packing", func(t *testing.T) {
			types := bucketTypes(t, pats)
			if len(types) != 1 || types[0] != "sparse-set" {
				t.Fatalf("want one sparse-set bucket for %d patterns, got %v", n, types)
			}
		})

		for _, input := range fam.inputs {
			t.Run(fam.name+"/"+input, func(t *testing.T) {
				r := newCapRunner(t, pats, input, true)
				defer r.Close()
				in := int32(len(input))

				wantAnchored := oracleAnchored(pats, input, nil)

				gotAny := r.call(t, "cap_match_any", r.inBase, in).(int32)
				if len(wantAnchored) == 0 {
					if gotAny != -1 {
						t.Fatalf("match_any = %d, want -1", gotAny)
					}
				} else if !containsInt(wantAnchored, int(gotAny)) {
					t.Fatalf("match_any = %d, not among %v", gotAny, wantAnchored)
				}

				gotAll := idsFromMask(uint64(r.call(t, "cap_match_all", r.inBase, in).(int64)), len(pats))
				if !eqIDs(append([]int(nil), wantAnchored...), gotAll) {
					t.Fatalf("match_all = %v, want %v", gotAll, wantAnchored)
				}

				for from := 0; from <= len(input); from++ {
					f := int32(from)
					wantPos, wantIDs := oracleFirstPosition(pats, input, from, nil)
					wantScanAll := oracleScanAll(pats, input, from, nil)

					gotAny2 := r.call(t, "cap_scan_any", r.inBase, in, f).(int32)
					if wantPos < 0 {
						if gotAny2 != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny2)
						}
					} else if !containsInt(wantScanAll, int(gotAny2)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v", from, gotAny2, wantScanAll)
					}

					gotScanAll := idsFromMask(uint64(r.call(t, "cap_scan_all", r.inBase, in, f).(int64)), len(pats))
					if !eqIDs(append([]int(nil), wantScanAll...), gotScanAll) {
						t.Fatalf("scan_all(from=%d) = %v, want %v", from, gotScanAll, wantScanAll)
					}

					total := int(r.call(t, "cap_find", r.inBase, in, f, r.scratchPtr(), r.outPtr, int32(r.npat)).(int32))
					if wantPos < 0 {
						if total != 0 {
							t.Fatalf("find(from=%d) = %d, want 0", from, total)
						}
						continue
					}
					if total != len(wantIDs) {
						t.Fatalf("find(from=%d) = %d tuples, want %d (ids %v)",
							from, total, len(wantIDs), wantIDs)
					}
				}
			})
		}
	}
}

// TestSparsePromotionRefusal pins the other half of that contract: a merge
// that misses the state or byte budget must be REFUSED, leaving the ordinary
// split packing in place, because a bucket the emitters cannot serve is worse
// than a bucket that costs an extra walk.
//
// 128 mutually unrelated alternations are the shape that does it — they merge
// to a 416-state table, which crosses 256 states into u16 cells and so costs
// 213 KB against the 64 KB budget. The same family at 40 patterns fits and IS
// promoted, which is why TestSparsePromotionCapabilities carries it too: the
// refusal has to come from the budget, not from the family.
func TestSparsePromotionRefusal(t *testing.T) {
	pats := sparsePats(func(i int) string { return fmt.Sprintf(`(?:a%d|b%d)+`, i, i) }, 128)
	types := bucketTypes(t, pats)
	for _, ty := range types {
		if ty == "sparse-set" {
			t.Fatalf("over-budget merge was promoted; buckets %v", types)
		}
	}
	if len(types) < 2 {
		t.Fatalf("expected the ordinary split packing, got %v", types)
	}
}

// TestSparsePromotionWideAll drives the same promoted buckets through the WIDE
// `_all` ABI, where the answer comes back as a caller-owned bitmap plus a count
// instead of an i64 mask.
//
// Worth its own test because emitRecordSparseCount's wide arm is genuinely
// different code from its narrow one — it computes the byte offset and bit
// from a RUNTIME id, and counts only 0->1 transitions so the count stays
// distinct patterns — and because a sparse bucket is the only way to reach that
// arm with more than 32 patterns behind a single probe call.
func TestSparsePromotionWideAll(t *testing.T) {
	const n = 96 // > 64: the `_all` capabilities take the out_ptr/count form
	pats := sparsePats(func(i int) string {
		return fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%8, 1+i/8%8)
	}, n)

	if types := bucketTypes(t, pats); len(types) != 1 || types[0] != "sparse-set" {
		t.Fatalf("want one sparse-set bucket, got %v", types)
	}

	for _, input := range []string{"", "a1", "abc123", "abcdefgh12345678", "zz"} {
		t.Run(input, func(t *testing.T) {
			r := newCapRunner(t, pats, input, true)
			defer r.Close()
			in := int32(len(input))
			nbytes := (n + 7) / 8

			// The wide form ORs into the caller's bitmap, so it REQUIRES an
			// all-zero one on entry (docs/wasm.md).
			clear := func() {
				data := r.mem.UnsafeData(r.store)
				for i := 0; i < nbytes; i++ {
					data[int(r.outPtr)+i] = 0
				}
			}
			bitmapIDs := func() []int {
				data := r.mem.UnsafeData(r.store)
				var out []int
				for k := 0; k < n; k++ {
					if data[int(r.outPtr)+k/8]&(1<<uint(k%8)) != 0 {
						out = append(out, k)
					}
				}
				return out
			}

			wantAnchored := oracleAnchored(pats, input, nil)
			clear()
			gotCount := int(r.call(t, "cap_match_all", r.inBase, in, r.outPtr).(int32))
			got := bitmapIDs()
			if !eqIDs(append([]int(nil), wantAnchored...), append([]int(nil), got...)) {
				t.Fatalf("match_all bitmap = %v, want %v", got, wantAnchored)
			}
			if gotCount != len(wantAnchored) {
				t.Fatalf("match_all count = %d, want %d", gotCount, len(wantAnchored))
			}

			for from := 0; from <= len(input); from++ {
				wantScanAll := oracleScanAll(pats, input, from, nil)
				clear()
				c := int(r.call(t, "cap_scan_all", r.inBase, in, int32(from), r.outPtr).(int32))
				g := bitmapIDs()
				if !eqIDs(append([]int(nil), wantScanAll...), append([]int(nil), g...)) {
					t.Fatalf("scan_all(from=%d) bitmap = %v, want %v", from, g, wantScanAll)
				}
				if c != len(wantScanAll) {
					t.Fatalf("scan_all(from=%d) count = %d, want %d", from, c, len(wantScanAll))
				}
			}
		})
	}
}

// TestSparseSetABIMatrixValidates is the sparse twin of
// TestBTSetABIMatrixValidates, and exists for the same reason: the capability
// set decides WHICH bodies get emitted, so a sparse bucket can be correct in
// one configuration and produce a module that does not load in another.
//
// Two things here are specific to sparse accept. emitSetAnchoredCapBody declares two
// extra i32 locals only when an anchored bucket is sparse, which shifts the i64
// accumulator's local index — a mistake there is an invalid module, not a wrong
// answer. And an anchored-only set emits no literal frontend at all, so the
// anchored sparse probe is reached with none of the find machinery present.
func TestSparseSetABIMatrixValidates(t *testing.T) {
	if _, err := exec.LookPath("wasm-tools"); err != nil {
		t.Skip("wasm-tools not installed")
	}
	shapes := map[string]func(i int) string{
		"classchain": func(i int) string { return fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%6, 1+i/6%6) },
		"sharedlit":  func(i int) string { return fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i%6, 1+i/6%6) },
	}
	caps := []struct {
		name string
		set  config.SetConfig
	}{
		{"anchored-pair", config.SetConfig{MatchAny: "g_match_any", MatchAll: "g_match_all"}},
		{"match-any-only", config.SetConfig{MatchAny: "g_match_any"}},
		{"match-all-only", config.SetConfig{MatchAll: "g_match_all"}},
		{"scan-pair", config.SetConfig{ScanAny: "g_scan_any", ScanAll: "g_scan_all"}},
		{"find", config.SetConfig{Find: "g_find"}},
		{"find-batch", config.SetConfig{Find: "g_find", Hints: []string{"batch-find"}}},
		{"find-overlapping", config.SetConfig{Find: "g_find", Overlapping: true}},
		{"everything", config.SetConfig{
			MatchAny: "g_match_any", MatchAll: "g_match_all",
			ScanAny: "g_scan_any", ScanAll: "g_scan_all", Find: "g_find",
			Hints: []string{"batch-find"}}},
	}
	// 40 keeps `_all` narrow, 96 makes it wide: both reach the sparse bodies.
	for _, n := range []int{40, 96} {
		for shapeName, gen := range shapes {
			pats := sparsePats(gen, n)
			for _, c := range caps {
				t.Run(fmt.Sprintf("%s/n=%d/%s", shapeName, n, c.name), func(t *testing.T) {
					entries := make([]config.RegexEntry, len(pats))
					for i, p := range pats {
						entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
					}
					sc := c.set
					sc.Name = "g"
					sc.Patterns = config.PatternSelector{All: true}
					cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
					w, _, diags, err := compile.CompileFileDiag(cfg, "")
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					sparse := 0
					for _, d := range diags {
						for _, b := range d.Buckets {
							if b.Type == "sparse-set" {
								sparse++
							}
						}
					}
					f := t.TempDir() + "/m.wasm"
					if err := os.WriteFile(f, w, 0644); err != nil {
						t.Fatal(err)
					}
					out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
					if vErr != nil {
						t.Fatalf("module INVALID (%d sparse buckets): %s", sparse, out)
					}
				})
			}
		}
	}
}

// TestSparseZeroLengthMatches is the regression for the defect this work
// uncovered: the sparse accept lists were never recorded for the DFA's
// BOOTSTRAP states.
//
// newDFAImpl builds the start state and the mid-start states before the
// transition-exploration loop, and recordWideSet was only called from inside
// that loop — so those states had accept BITMASKS but no accept LISTS. The
// cost is exactly the zero-length matches, because a nullable pattern accepts
// in the start state and nowhere else: every non-empty match stayed correct,
// which is why nothing caught it until sets larger than 32 patterns reached the
// RE2 corpus (6004 failures at --set-chunk=70, all on empty or empty-matching
// inputs).
//
// The defect predates this change — it shipped with sparse accept's shared-literal path,
// where the corpus never built a >32-pattern group behind one literal — so both
// arrangements are pinned here: nullable patterns behind a shared literal, and
// nullable patterns with no literal at all.
func TestSparseZeroLengthMatches(t *testing.T) {
	cases := []struct {
		name string
		gen  func(i int) string
	}{
		// Nullable SUFFIX behind one shared literal: the sparse-accept path.
		{"shared-literal", func(i int) string { return fmt.Sprintf(`union[a-z]{0,%d}[0-9]*`, 1+i%8) }},
		// Nullable and literal-less: the fallback path.
		{"literal-less", func(i int) string { return fmt.Sprintf(`[a-z]{0,%d}[0-9]*`, 1+i%8) }},
		// Nullable alternations — the shape the corpus failed on, minus the
		// begin anchor. An ANCHORED pattern cannot be promoted at all
		// (promoteSparseBuckets refuses it: its position rule lives in the i32
		// mask, which a sparse body ignores), so using one here would assert a
		// sparse bucket that must not exist.
		{"nullable-alternation", func(i int) string { return fmt.Sprintf(`(?:(?:a*)|b%d)`, i) }},
	}
	for _, c := range cases {
		pats := sparsePats(c.gen, 40)
		t.Run(c.name, func(t *testing.T) {
			if types := bucketTypes(t, pats); len(types) != 1 || types[0] != "sparse-set" {
				t.Fatalf("want one sparse-set bucket, got %v", types)
			}
			// The empty input is the case that was silently wrong; the others
			// keep non-empty matches honest alongside it.
			for _, input := range []string{"", "a", "z9", "union", "unionab12", "xyz"} {
				r := newCapRunner(t, pats, input, true)
				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(pats, input, from, nil)
					got := idsFromMask(uint64(r.call(t, "cap_scan_all",
						r.inBase, int32(len(input)), int32(from)).(int64)), len(pats))
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						r.Close()
						t.Fatalf("scan_all(%q, from=%d) = %v, want %v", input, from, got, want)
					}
				}
				r.Close()
			}
		})
	}
}

// TestSparseGatedBatchDeliversEveryPattern is the regression for the second
// defect this work uncovered: every mask-based shortcut on the candidate path
// is an i32, so none of them can describe a sparse bucket's patterns past
// the 32nd.
//
// emitGateMask clears a bit per pattern for the first 32 only, and
// emitEmptyMaskSkip then leaves the whole group when the mask comes out empty.
// For a sparse bucket that is wrong twice over: the mask never described the
// later patterns, so "empty" means "the first 32 are done", not "there is
// nothing left". A gated batch driven to exhaustion therefore delivered
// EXACTLY 32 tuples of 40 — the bitmask width, which is what makes the symptom
// recognisable.
//
// Capacity 1 is what exposes it: every tuple of the position needs its own
// call, so the gate array really does fill up mid-position and the pre-mask
// really does go empty before the bucket is finished. At capacity N the whole
// position is delivered in one call and the shortcut never fires.
func TestSparseGatedBatchDeliversEveryPattern(t *testing.T) {
	for _, n := range []int{8, 40, 64} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			pats := make([]string, n)
			for i := range pats {
				// Empty-matchable, and deliberately NOT anchored: an anchored
				// pattern is refused promotion (its "only at position 0" rule
				// lives in the i32 group mask, which a sparse body ignores), so
				// anchoring these would test the ordinary bucketed path.
				// On the empty input each still reports exactly one 0-0 tuple,
				// so any loss shows up directly as a count.
				pats[i] = fmt.Sprintf(`(?:(?:)|a%d)*`, i)
			}
			entries := make([]config.RegexEntry, n)
			names := make([]string, n)
			for i, p := range pats {
				names[i] = fmt.Sprintf("p%d", i)
				entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
			}
			cfg := config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{{
				Name: "s", Find: "set_find", Hints: []string{"batch-find"},
				Patterns: config.PatternSelector{Names: names},
			}}}
			w, _, diags, err := compile.CompileFileDiag(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			sparse := false
			for _, d := range diags {
				for _, b := range d.Buckets {
					if b.Type == "sparse-set" {
						sparse = true
					}
				}
			}
			if n > 32 && !sparse {
				t.Fatalf("n=%d did not produce a sparse bucket; the test would prove nothing", n)
			}

			store, inst, mem, release, err := instantiate(w)
			defer release()
			if err != nil {
				t.Fatalf("instantiate: %v", err)
			}
			fn := inst.GetFunc(store, "set_find_batch")
			if fn == nil {
				t.Fatal("module missing set_find_batch export")
			}
			const pg = 65536
			dataTop, err := utils.ParseDataSectionBytes(w)
			if err != nil {
				t.Fatal(err)
			}
			inBase := int32((dataTop + pg - 1) / pg * pg)
			gatePtr := inBase + pg
			outPtr := gatePtr + pg
			needed := uint64((int64(outPtr) + 2*pg + pg - 1) / pg)
			if cur := mem.Size(store); needed > cur {
				if _, err := mem.Grow(store, needed-cur); err != nil {
					t.Fatal(err)
				}
			}
			countBits := uint(config.SetCursorCountBits(n))
			countMask := int64(1)<<countBits - 1

			for _, outCap := range []int32{1, 2, int32(n)} {
				d := mem.UnsafeData(store)
				for i := 0; i < n*4; i++ {
					d[int(gatePtr)+i] = 0
				}
				scratchPtr := writeFindScratch(store, mem, gatePtr, int32(n), 0, 0)
				seen := map[int]int{}
				total := 0
				cursor := int64(0)
				maxCalls := 8*(n+1) + 16
				for calls := 0; ; calls++ {
					if calls > maxCalls {
						t.Fatalf("cap=%d: batch did not terminate after %d calls", outCap, calls)
					}
					res, err := fn.Call(store, inBase, int32(0), cursor, scratchPtr, outPtr, outCap)
					if err != nil {
						t.Fatalf("cap=%d: %v", outCap, err)
					}
					packed := res.(int64)
					cnt := int32(packed & countMask)
					if cnt < 0 || cnt > outCap {
						t.Fatalf("cap=%d: count %d out of range", outCap, cnt)
					}
					buf := mem.UnsafeData(store)
					for i := int32(0); i < cnt; i++ {
						base := int(outPtr) + int(i)*12
						id := int(int32(binary.LittleEndian.Uint32(buf[base:])))
						st := int(int32(binary.LittleEndian.Uint32(buf[base+4:])))
						en := int(int32(binary.LittleEndian.Uint32(buf[base+8:])))
						if st != 0 || en != 0 {
							t.Fatalf("cap=%d: pattern %d reported %d-%d, want 0-0", outCap, id, st, en)
						}
						seen[id]++
						total++
					}
					if uint32(packed>>32) == 0xFFFFFFFF {
						break
					}
					cursor = packed
				}
				if total != n {
					t.Fatalf("cap=%d: %d tuples, want %d (sparse=%v)", outCap, total, n, sparse)
				}
				for id := 0; id < n; id++ {
					if seen[id] != 1 {
						t.Fatalf("cap=%d: pattern %d delivered %d times, want 1", outCap, id, seen[id])
					}
				}
			}
		})
	}
}

// Context-sensitive assertions inside sets: `from` never narrows the input,
// so \b and (?m:^) must judge real neighbouring bytes.
//
// The whole-input oracle here is the "context-sensitive" technique:
// `\A(?s:.{p})(?:pat)` hands `pat` position p with its REAL left context, so
// `\b` and `(?m:^)` judge actual neighbours rather than a slice boundary. The
// `.{p}` prefix counts runes, so every input below is ASCII.
func contextOracle(t *testing.T, pat, input string) [][2]int {
	t.Helper()
	var out [][2]int
	for p := 0; p <= len(input); p++ {
		re := regexp.MustCompile(`\A(?s:.{` + itoa(p) + `})(?:` + pat + `)`)
		if m := re.FindStringIndex(input); m != nil {
			out = append(out, [2]int{p, m[1]})
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// runSetOne compiles a one-pattern `overlapping: true` set and drives its find
// to exhaustion.
func runSetOne(t *testing.T, pat, input string) [][2]int {
	t.Helper()
	w, _, err := compileSet([]string{pat})
	if err != nil {
		t.Fatalf("compile %q: %v", pat, err)
	}
	got, hang, err := runWasmSetFind(w, input, 1)
	if err != nil {
		t.Fatalf("run %q on %q: %v", pat, input, err)
	}
	if hang {
		t.Fatalf("hang on %q / %q", pat, input)
	}
	out := make([][2]int, 0, len(got))
	for _, m := range got {
		out = append(out, [2]int{m.Start, m.End})
	}
	sortSpans(out)
	return out
}

func checkSetContext(t *testing.T, pat, input string) {
	t.Helper()
	want := contextOracle(t, pat, input)
	sortSpans(want)
	got := runSetOne(t, pat, input)
	if len(want) != len(got) {
		t.Fatalf("%q on %q: expected %d matches %v, got %d %v", pat, input, len(want), want, len(got), got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%q on %q: match %d expected %v, got %v", pat, input, i, want[i], got[i])
		}
	}
}

// TestSetLineAnchors covers a fixed defect: (?m:^) in a set used to
// collapse to "position 0 only", so every match after the first line was lost.
func TestSetLineAnchors(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`(?m:^)foo`, "foo\nfoo\nxfoo"},
		{`(?m:^)foo`, "xfoo\nfoo"},
		{`(?m:^)a+`, "aa\nbaa\naa"},
		{`foo(?m:$)`, "foo\nfoox\nfoo"},
		{`(?m:^)foo(?m:$)`, "foo\nfoox\nfoo"},
		{`\Afoo`, "foo\nfoo"},
		{`(?m:^)`, "a\nb\n"},
		{`(?m:^)x?`, "x\nx"},
	}
	for _, c := range cases {
		t.Run(c.pat+" on "+c.input, func(t *testing.T) { checkSetContext(t, c.pat, c.input) })
	}
}

// TestSetTextAnchorIgnoresFrom pins the anchor contract: \A is anchored to real input
// position 0 whatever `from` the caller passed. Driving find to exhaustion
// covers every from value in turn.
func TestSetTextAnchorIgnoresFrom(t *testing.T) {
	got := runSetOne(t, `\Aab`, "abab")
	if len(got) != 1 || got[0] != [2]int{0, 2} {
		t.Fatalf(`\Aab on "abab": expected exactly [[0 2]], got %v`, got)
	}
}

// TestSetWordBoundaries covers a fixed defect: \b patterns in a set used
// to match nothing at all.
func TestSetWordBoundaries(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`\bfoo\b`, "foo bar foo"},
		{`\bfoo`, "foo foofoo xfoo"},
		{`foo\b`, "foo foofoo foox"},
		{`\Bfoo`, "xfoo foo"},
		{`\bcat|\bdog`, "cat dog concat"},
		{`\b\w+\b`, "ab cd"},
	}
	for _, c := range cases {
		t.Run(c.pat+" on "+c.input, func(t *testing.T) { checkSetContext(t, c.pat, c.input) })
	}
}

// Merged-mode (embedded) execution coverage —
// R-TESTS(2).
//
// Every other harness in this repo runs STANDALONE modules, where the module
// declares and exports its own memory and the DFA tables live in the same
// memory as the input. Embedded modules — what `output:` produces, and what
// every Rust/Go/C/AS example ships — instead IMPORT the host's memory as
// memory 0 and keep their tables in memory 1.
//
// That difference is invisible to a standalone test by construction, which is
// how an earlier bug shipped: the zero-width machinery read input bytes through the
// table-memory helper, so in embedded builds every \b, \B, (?m:^) and (?m:$)
// set pattern consulted DFA-table bytes instead of the caller's text — giving
// both false negatives and false positives. Standalone builds were correct
// because there the two memories are the same memory.
//
// These tests therefore run the SAME assertions against BOTH builds. A future
// regression in memory indexing fails here rather than in a user's app.

// compileSetBothModes compiles a one-pattern set twice: standalone, and
// embedded (which is selected by a non-empty Output).
func compileSetBothModes(t *testing.T, pat string, caps func(*config.SetConfig)) (standalone, embedded []byte) {
	t.Helper()
	build := func(output string) []byte {
		sc := config.SetConfig{
			Name:     "s",
			Patterns: config.PatternSelector{Names: []string{"p0"}},
		}
		caps(&sc)
		cfg := config.BuildConfig{
			Regexps: []config.RegexEntry{{Name: "p0", Pattern: pat}},
			Sets:    []config.SetConfig{sc},
			Output:  output,
		}
		w, _, err := compile.CompileFile(cfg, "")
		if err != nil {
			t.Fatalf("compile %q (output=%q): %v", pat, output, err)
		}
		return w
	}
	return build(""), build("merged.wasm")
}

// runScanStandalone calls `scan` on a standalone module.
func runScanStandalone(t *testing.T, w []byte, input string, from int32) bool {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate standalone: %v", err)
	}
	const inBase = int32(1 << 20)
	need := uint64((int64(inBase) + int64(len(input)) + 65535) / 65536)
	if cur := mem.Size(store); need > cur {
		if _, err := mem.Grow(store, need-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	copy(mem.UnsafeData(store)[inBase:], input)
	res, err := inst.GetFunc(store, "s_scan").Call(store, inBase, int32(len(input)), from)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res.(int32) >= 0
}

// runScanEmbedded calls `scan_any` on an embedded module, supplying the host
// memory the module imports as "main"."memory" — the wasm-merge arrangement,
// modelled directly.
func runScanEmbedded(t *testing.T, w []byte, input string, from int32) bool {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("embedded module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.SetEpochDeadline(1)
	const pages = 32
	mt, err := wasmtime.NewMemoryType(pages, false, 0, false)
	if err != nil {
		t.Fatalf("memory type: %v", err)
	}
	hostMem, err := wasmtime.NewMemory(store, mt)
	if err != nil {
		t.Fatalf("host memory: %v", err)
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{hostMem})
	if err != nil {
		t.Fatalf("instantiate embedded: %v", err)
	}
	const inBase = int32(4096)
	copy(hostMem.UnsafeData(store)[inBase:], input)
	res, err := inst.GetFunc(store, "s_scan").Call(store, inBase, int32(len(input)), from)
	if err != nil {
		t.Fatalf("scan (embedded): %v", err)
	}
	return res.(int32) >= 0
}

// TestSetMergedModeAssertions runs the context-assertion classes through both
// builds and against Go, in both the matching and NON-matching direction —
// the false-positive direction matters, because a wrong-memory read of a zero
// byte makes \b hold and \B fail everywhere.
func TestSetMergedModeAssertions(t *testing.T) {
	cases := []struct{ pat, input string }{
		// word boundaries, both directions
		{`\bfoo`, "x foo"},
		{`\bfoo`, "xfoo"},
		{`foo\b`, "foo x"},
		{`foo\b`, "foox"},
		{`x\by`, "xy"},
		{`a\Bb`, "ab"},
		{`\Bfoo`, "xfoo"},
		{`\Bfoo`, " foo"},
		// line anchors, both directions
		{`(?m:^)bar`, "x\nbar"},
		{`(?m:^)bar`, "xbar"},
		{`foo(?m:$)`, "foo\nbar"},
		{`foo(?m:$)`, "foox"},
		{`(?m:^)foo(?m:$)`, "a\nfoo\nb"},
		// mixed contexts in one pattern: the entry-state selection has to
		// handle a bucket carrying BOTH kinds
		{`(?:\bfoo|(?m:^)bar)`, "x\nbar"},
		{`(?:\bfoo|(?m:^)bar)`, "x foo"},
		{`(?:\bfoo|(?m:^)bar)`, "xfooybarz"},
		// no assertion at all: control rows
		{`foo`, "xfooy"},
		{`foo`, "xbary"},
	}
	// `scan` was retired: `scan_any(...) >= 0` is
	// exactly what it returned, which is what runScan* compare against.
	setScan := func(sc *config.SetConfig) { sc.ScanAny = "s_scan" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q", c.pat, c.input), func(t *testing.T) {
			want := regexp.MustCompile(c.pat).MatchString(c.input)
			sa, emb := compileSetBothModes(t, c.pat, setScan)
			gotSA := runScanStandalone(t, sa, c.input, 0)
			gotEmb := runScanEmbedded(t, emb, c.input, 0)
			if gotSA != want {
				t.Errorf("standalone scan = %v, Go says %v", gotSA, want)
			}
			if gotEmb != want {
				t.Errorf("embedded scan = %v, Go says %v "+
					"(embedded reads input from memory 0 and tables from memory 1; "+
					"the input memory is memory 0, the tables memory 1)", gotEmb, want)
			}
			if gotSA != gotEmb {
				t.Errorf("standalone and embedded disagree: %v vs %v", gotSA, gotEmb)
			}
		})
	}
}

// runFindEmbedded drives `find` to exhaustion on an embedded module, with the
// gate array and out buffer in the imported host memory — what a merged
// Rust/Go/C stub does.
func runFindEmbedded(t *testing.T, w []byte, input string) [][2]int {
	t.Helper()
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("embedded module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.SetEpochDeadline(1)
	mt, err := wasmtime.NewMemoryType(32, false, 0, false)
	if err != nil {
		t.Fatalf("memory type: %v", err)
	}
	hostMem, err := wasmtime.NewMemory(store, mt)
	if err != nil {
		t.Fatalf("host memory: %v", err)
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{hostMem})
	if err != nil {
		t.Fatalf("instantiate embedded: %v", err)
	}
	const (
		inBase  = int32(4096)
		gatePtr = int32(1 << 16)
		outPtr  = int32(1<<16 + 4096)
	)
	buf := hostMem.UnsafeData(store)
	copy(buf[inBase:], input)
	for i := int32(0); i < 4; i++ {
		buf[gatePtr+i] = 0
	}
	scratchPtr := writeFindScratch(store, hostMem, gatePtr, 1, 0, 0)
	fn := inst.GetFunc(store, "s_find")
	var out [][2]int
	from := int32(0)
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), from, scratchPtr, outPtr, int32(1))
		if err != nil {
			t.Fatalf("find (embedded): %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf = hostMem.UnsafeData(store)
		start := int32(le32(buf[outPtr+4:]))
		out = append(out, [2]int{int(start), int(le32(buf[outPtr+8:]))})
		from = start + 1
	}
	return out
}

func le32(b []byte) int32 {
	return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}

// TestSetMergedModeFind covers the tuple-writing suffix body in embedded mode.
// TestSetMergedModeAssertions drives `scan`, which goes through the cheap
// bitmask probes — a different emitter with its own copy of the zero-width
// machinery, so both need a merged-mode row.
func TestSetMergedModeFind(t *testing.T) {
	cases := []struct{ pat, input string }{
		{`\bfoo\b`, "foo xfoo foo"},
		{`foo\b`, "foox foo"},
		{`a\Bb`, "ab xab"},
		{`(?m:^)bar`, "bar\nxbar\nbar"},
		{`foo(?m:$)`, "foo\nfoox\nfoo"},
		{`(?:\bfoo|(?m:^)bar)`, "x\nbar foo"},
	}
	setFind := func(sc *config.SetConfig) { sc.Find = "s_find" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q", c.pat, c.input), func(t *testing.T) {
			// Gated find's contract IS Go's FindAllIndex rule.
			var want [][2]int
			for _, m := range regexp.MustCompile(c.pat).FindAllStringIndex(c.input, -1) {
				want = append(want, [2]int{m[0], m[1]})
			}
			_, emb := compileSetBothModes(t, c.pat, setFind)
			got := runFindEmbedded(t, emb, c.input)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("embedded find = %v, Go FindAllIndex = %v "+
					"(the input memory is memory 0, the tables memory 1)", got, want)
			}
		})
	}
}

// TestSetMergedModeFromResume covers the same machinery at from > 0, where the
// entry state is chosen from the PRECEDING byte — the read most likely to go
// to the wrong memory.
func TestSetMergedModeFromResume(t *testing.T) {
	cases := []struct {
		pat, input string
		from       int32
	}{
		{`\bfoo`, "foo foo", 1},   // from mid-word: the foo at 4 still matches
		{`\bfoo`, "xfoofoo", 1},   // no word boundary anywhere at or after 1
		{`(?m:^)b`, "a\nb\nb", 2}, // resume exactly at a line start
		{`(?m:^)b`, "ab\nb", 1},   // resume just after a non-newline
		{`a\Bb`, "abab", 1},       // \B mid-input at a resume point
	}
	// `scan` was retired: `scan_any(...) >= 0` is
	// exactly what it returned, which is what runScan* compare against.
	setScan := func(sc *config.SetConfig) { sc.ScanAny = "s_scan" }
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s on %q from %d", c.pat, c.input, c.from), func(t *testing.T) {
			// Oracle: does the pattern match at any position >= from, judged on
			// the WHOLE input so assertions see real context.
			want := false
			for p := int(c.from); p <= len(c.input); p++ {
				re := regexp.MustCompile(`\A(?s:.{` + itoa(p) + `})(?:` + c.pat + `)`)
				if re.FindStringIndex(c.input) != nil {
					want = true
					break
				}
			}
			sa, emb := compileSetBothModes(t, c.pat, setScan)
			gotSA := runScanStandalone(t, sa, c.input, c.from)
			gotEmb := runScanEmbedded(t, emb, c.input, c.from)
			if gotSA != want || gotEmb != want {
				t.Errorf("standalone=%v embedded=%v, oracle says %v", gotSA, gotEmb, want)
			}
		})
	}
}

// TestVarLenPrefixMustRouteToFallback pins the counterexamples behind
// analyzePattern's variable-length-prefix guard, and with them the reason
//
// The split representation prefix.literal.suffix recovers a match start from a
// literal candidate at c as `c - L` for ONE compile-time L (prefixMaxLen). That
// is exact only while the prefix has a single length. Every pattern below has a
// BOUNDED, ACYCLIC variable-length prefix — `a?`, `a{0,2}`, `(?:xy)?` — so each
// one satisfies the "deferred tier" criterion, under which an acyclic
// backward prefix DFA yields a computable maximum lookback M and the pattern
// may keep its literal frontend.
//
// Measured with the guard lifted, every one of them LOSES matches: `a?a` on
// "a", `a{0,2}b` on "b" and `(?:xy)?Q` on "Q" all report nothing where the
// answer is 0-1. The lost cases are exactly those where the prefix takes a
// length other than its maximum, because `c - prefixMaxLen` cannot address
// them — for the empty-prefix case it is negative.
//
// So boundedness is necessary but NOT sufficient: it fixes the drain bound and
// does nothing for start recovery. Making these patterns work needs the
// backward DFA to report the start it actually reached (not a constant), plus a
// rule for choosing between several starts recoverable from one candidate —
// and that choice follows the prefix's GREEDY structure, which a plain backward
// DFA cannot express (`a?a` and `a??a` on "aa" want different answers from the
// same automaton).
//
// This test asserts the OUTCOME, not the mechanism: whatever routing is chosen,
// these answers must match Go. It therefore stays valid if a better routing is ever
// built.
func TestVarLenPrefixMustRouteToFallback(t *testing.T) {
	cases := []struct {
		pats   []string
		inputs []string
	}{
		{[]string{`a?a`, `zz`}, []string{"a", "aa", "aaa"}},
		{[]string{`a{0,2}b`, `zz`}, []string{"b", "ab", "aab", "aaab"}},
		{[]string{`(?:xy)?Q`, `zz`}, []string{"Q", "xyQ", "xyxyQ"}},
		// Lazy twin of the first case: same automaton, different answer, which
		// is why an extent tie-break cannot substitute for greedy structure.
		{[]string{`a??a`, `zz`}, []string{"a", "aa"}},
	}
	for _, tc := range cases {
		for _, input := range tc.inputs {
			t.Run(fmt.Sprintf("%s/%s", tc.pats[0], input), func(t *testing.T) {
				r := newCapRunner(t, tc.pats, input, true) // overlapping: every start
				defer r.Close()
				total := int(r.call(t, "cap_find",
					r.inBase, int32(len(input)), 0, r.scratchPtr(), r.outPtr, int32(r.npat)).(int32))
				buf := r.mem.UnsafeData(r.store)
				var got [][3]int
				for i := 0; i < total && i < int(r.npat); i++ {
					b := int(r.outPtr) + i*12
					rd := func(o int) int32 {
						return int32(buf[b+o]) | int32(buf[b+o+1])<<8 |
							int32(buf[b+o+2])<<16 | int32(buf[b+o+3])<<24
					}
					got = append(got, [3]int{int(rd(0)), int(rd(4)), int(rd(8))})
				}
				// Oracle: the first start position at which anything matches,
				// and every pattern matching there — `find`'s contract.
				var want [][3]int
				for s := 0; s <= len(input) && len(want) == 0; s++ {
					for k, p := range tc.pats {
						re := regexp.MustCompile(`\A(?:` + p + `)`)
						if m := re.FindStringIndex(input[s:]); m != nil {
							want = append(want, [3]int{k, s, s + m[1]})
						}
					}
				}
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("find(%q) = %v, want %v", input, got, want)
				}
			})
		}
	}
}

// The Shufti frontend, checked against Go for the first time.
//
// `make set-coverage` reported 39 of 40 set emitters reached by the tests that
// check answers. The one exception was `emitSetMatchFnFinalShufti` —
// compile/set_emit.go, 215 lines of SIMD first-byte prefilter — and tracing why
// gave a worse answer than "nobody wrote a shape for it":
//
//   - Shufti is selected only from the SCALAR branch, which needs Aho-Corasick
//     to decline first;
//   - AC declines only when its table would exceed ACBudgetBytes, default
//     512 KB (compile/set.go);
//   - `ACBudgetBytes` lives on CompileSetOptions, which no module-building
//     entry point accepted — `CompileSet` is exported but returns an unexported
//     type, and everything else took only a config.BuildConfig.
//
// So no test that can RUN a module could produce a Shufti one. Two tests in
// package `compile` reach the emitter (`TestSetHintsSelectsShuftiFrontend` and
// `setEmitCovShuftiSet`), but that package has no wasmtime: they assert the
// frontend was SELECTED and that a body was emitted, never what it answers.
//
// The path is not dead code — a large enough literal set exceeds AC's budget in
// production and lands here. `ACBudgetBytes: 1`, via the CompileFileOpts entry
// added for this, simulates that condition without building a set of that size.

// shuftiPatterns builds a set that selects the Shufti frontend: more literals
// than Teddy accepts (teddyMaxLiterals is 64), with first bytes cycling
// \x01..\x1f — 31 distinct, inside Shufti's 17..64 band, and all rarity 0 so
// the adaptive density trigger stays off. Modelled on `setEmitCovShuftiSet` in
// package compile, which established this shape.
func shuftiPatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`\x%02xqq%02dxx[a-z]+`, 1+i%31, i)
	}
	return out
}

// compileCapsShufti is compileCaps with AC forced out of budget.
func compileCapsShufti(t *testing.T, pats []string, overlapping bool) []byte {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileOpts(
		config.BuildConfig{Regexps: entries, Sets: sets}, "",
		compile.CompileSetOptions{ACBudgetBytes: 1})
	if err != nil {
		t.Fatalf("compile shufti set: %v", err)
	}
	// Without this the test silently degrades into a second scalar-frontend
	// case the moment selection changes — which is exactly how the emitter
	// went unchecked in the first place.
	if len(diags) != 1 {
		t.Fatalf("got %d set diagnostics, want 1", len(diags))
	}
	if diags[0].Frontend != "shufti" {
		t.Fatalf("frontend = %q, want \"shufti\" — this set no longer reaches "+
			"emitSetMatchFnFinalShufti, so the test is checking something else",
			diags[0].Frontend)
	}
	if n := len(droppedFromSet(diags)); n != 0 {
		t.Fatalf("%d patterns dropped from the set; the oracle would compare "+
			"against patterns the engine was never asked to build", n)
	}
	return w
}

func TestSetShuftiFrontendAgainstOracle(t *testing.T) {
	pats := shuftiPatterns(65) // one past teddyMaxLiterals

	// Inputs are short on purpose: checkCapsAgainstOracle sweeps every `from`
	// and evaluates all 65 patterns at each, so length is quadratic-ish here.
	inputs := []string{
		"",
		"\x01qq00xxabc",                 // pattern 0 matches
		"zz\x02qq01xxdef",               // pattern 1, not at position 0
		"\x01qq00xxab \x02qq01xxcd",     // two patterns, two positions
		"\x03qq02xx",                    // first bytes present, suffix absent
		"nothing here at all",           // no first byte present
		strings.Repeat("q", 40),         // long, no candidate
		"\x01qq00xxaaaaaaaaaaaaaaaaaaa", // one long match
	}
	for i, input := range inputs {
		t.Run(fmt.Sprintf("input%d", i), func(t *testing.T) {
			w := compileCapsShufti(t, pats, true)
			r := newCapRunnerFrom(t, w, pats, input)
			defer r.Close()
			checkCapsAgainstOracle(t, r, pats, input)
		})
	}
}

// wideUnionAlphabet is the 79 bytes the widened-band patterns start with:
// every alphanumeric plus punctuation that needs no regexp escaping.
const wideUnionAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
	"_~!@#%&=:;,<>/'\"`"

// wideUnionPatterns builds n literals whose first bytes are n distinct members
// of wideUnionAlphabet — so the first-byte union lands ABOVE the 64 that
// bounded Shufti selection before the band was widened.
func wideUnionPatterns(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		body := ""
		for j := 0; j < 6; j++ {
			body += string(rune('a' + (i/len(wideUnionAlphabet)+j)%26))
		}
		out = append(out, fmt.Sprintf("%s%s%02dxx[a-z]+", string(wideUnionAlphabet[i%len(wideUnionAlphabet)]), body, i))
	}
	return out
}

// compileCapsWideUnion is compileCapsShufti for the WIDENED band: the same
// AC-out-of-budget route to the scalar branch, but a first-byte union of 70 —
// which reaches emitSetMatchFnFinalShufti only under set-level
// LikelyNoMatch, and only since the selection ceiling was raised.
func compileCapsWideUnion(t *testing.T, pats []string, overlapping bool) []byte {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Overlapping: overlapping,
		Hints:       []string{"prefer-no-match"},
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileOpts(
		config.BuildConfig{Regexps: entries, Sets: sets}, "",
		compile.CompileSetOptions{ACBudgetBytes: 1})
	if err != nil {
		t.Fatalf("compile wide-union set: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("got %d set diagnostics, want 1", len(diags))
	}
	// Without this the test degrades into a second scalar case the moment the
	// ceiling moves back — the same trap the sibling test above documents.
	if diags[0].Frontend != "shufti" {
		t.Fatalf("frontend = %q, want \"shufti\" — the widened band no longer "+
			"selects Shufti for a 70-byte first-byte union", diags[0].Frontend)
	}
	if n := len(droppedFromSet(diags)); n != 0 {
		t.Fatalf("%d patterns dropped from the set", n)
	}
	return w
}

// The Shufti frontend at a first-byte union WIDER than 64.
//
// emitShuftiPrefixCheck builds one nibble-table pair per 8 set members, so a
// 70-byte union is 9 pairs where the old 64-byte ceiling allowed 8. Nothing
// about the emitter is width-specific, but "nothing about it is width-specific"
// is a claim about code that had never been run past 64 — this runs it, and
// checks every capability against the Go oracle.
func TestSetWideUnionShuftiAgainstOracle(t *testing.T) {
	pats := wideUnionPatterns(70)

	inputs := []string{
		"",
		"Aabcdef00xxabc",               // pattern 0 matches
		"zzBbcdefg01xxdef",             // pattern 1, not at position 0
		"Aabcdef00xxab Bbcdefg01xxcd",  // two patterns, two positions
		"Ccdefgh02xx",                  // first bytes present, suffix absent
		"(((( ))))",                    // nothing in the union at all
		strings.Repeat("(", 40),        // long, no candidate — the skip's win case
		"Aabcdef00xxaaaaaaaaaaaaaaaaa", // one long match
	}
	for i, input := range inputs {
		t.Run(fmt.Sprintf("input%d", i), func(t *testing.T) {
			w := compileCapsWideUnion(t, pats, true)
			r := newCapRunnerFrom(t, w, pats, input)
			defer r.Close()
			checkCapsAgainstOracle(t, r, pats, input)
		})
	}
}

// TestTwoPhaseMixedSets drives the two-phase split: sets holding BOTH
// literal-bearing and literal-less patterns, which is the only shape that
// reaches phase 2.
func TestTwoPhaseMixedSets(t *testing.T) {
	cases := []struct {
		name string
		pats []string
	}{
		{"kw2+card", []string{`error`, `warning`, `[0-9]{16}`}},
		{"kw1+dotstar", []string{`ERROR`, `[^\n]*QQQ`}},
		{"secrets+num", []string{`AKIA[A-Z0-9]{4}`, `ghp_[A-Za-z0-9]{6}`, `[0-9]{8}`}},
		{"many+2fallback", []string{`alpha`, `bravo`, `charlie`, `delta`, `[0-9]{5}`, `[a-c]{4}z`}},
		{"anchored-fallback", []string{`foo`, `^[0-9]+`}},
		{"empty-fallback", []string{`bar`, `[0-9]*`}},
	}
	inputs := []string{
		"", "x", "error here", "warning: 1234567890123456", "1234567890123456",
		"no match at all", "AKIAZZZZ and ghp_abc123", "12345678", "alphabravo",
		"aabbz 99999", "foo", "0123", "\nQQQ", "ERRORQQQ", "abc",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dropped, err := compileCaps(tc.pats, false)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			// anchored is the WIDER scope (it contains all), so this rejects a
			// drop of either kind — which is what this test wants: its
			// expectations assume every pattern is in the set.
			if len(dropped.anchored) != 0 {
				t.Fatalf("patterns dropped: %v", dropped.anchored)
			}
			res := make([]*regexp.Regexp, len(tc.pats))
			for i, p := range tc.pats {
				res[i] = regexp.MustCompile(p)
			}
			for _, input := range inputs {
				r := newCapRunner(t, tc.pats, input, false)
				n := int32(len(input))
				for from := 0; from <= len(input); from++ {
					var want []int
					for i, re := range res {
						if loc := re.FindStringIndex(input[from:]); loc != nil {
							_ = loc
							want = append(want, i)
						}
					}
					// Recompute with real left context via the whole-input probe.
					want = want[:0]
					for i, p := range tc.pats {
						probe := regexp.MustCompile(`(?s)\A.{` + itoa2(from) + `,}?(?:` + p + `)`)
						if probe.MatchString(input) {
							want = append(want, i)
						}
					}
					sort.Ints(want)

					gotAll := idsFromMask(uint64(r.call(t, "cap_scan_all", r.inBase, n, int32(from)).(int64)), len(tc.pats))
					if !eqIDs(append([]int(nil), want...), gotAll) {
						t.Fatalf("scan_all(%q, from=%d) = %v, want %v", input, from, gotAll, want)
					}
					gotAny := r.call(t, "cap_scan_any", r.inBase, n, int32(from)).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(%q, from=%d) = %d, want -1", input, from, gotAny)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(%q, from=%d) = %d, not among %v", input, from, gotAny, want)
					}
				}
				r.Close()
			}
		})
	}
}

func itoa2(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// compileSetBT builds a set with max_fallback_states forced low, so ordinary
// patterns become Backtracking-admitted set members in bulk. This is the same
// trick --force-backtrack uses for single patterns (MaxDFAStates = -1): the
// naturally-dropped population is tiny, so forcing the path is the only way to
// get real coverage of it.
func compileSetBT(pats []string, maxFallback int) ([]byte, map[int]bool, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Find:        "set_find",
		Overlapping: true,
		Patterns:    config.PatternSelector{Names: names},
	}}
	cfg := config.BuildConfig{
		Regexps:           entries,
		Sets:              sets,
		MaxFallbackStates: maxFallback,
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	return w, droppedFromSet(diags), err
}

// The first thing to establish: a set containing a BT bucket is a VALID module.
// Everything else depends on it.
func TestSetBTBucketValidates(t *testing.T) {
	for _, c := range []struct {
		name string
		pats []string
	}{
		{"single", []string{`(?:ab|cd)+xyz`}},
		{"mixed with a literal bucket", []string{`(?:ab|cd)+xyz`, `hello`}},
		{"two BT buckets", []string{`(?:ab|cd)+xyz`, `(?:ef|gh)+qrs`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, dropped, err := compileSetBT(c.pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) == len(c.pats) {
				t.Skip("every pattern still dropped — BT admitted none")
			}
			f := t.TempDir() + "/m.wasm"
			if err := os.WriteFile(f, w, 0644); err != nil {
				t.Fatal(err)
			}
			out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
			if vErr != nil {
				t.Fatalf("module INVALID: %s", out)
			}
			t.Logf("valid, %d bytes, %d dropped", len(w), len(dropped))
		})
	}
}

// The substance: a BT-admitted set member must report the SAME matches the
// same pattern reports when the set gives it a DFA bucket. Both are compared
// against the live-Go oracle rather than against each other, so a shared
// misunderstanding cannot pass.
func TestSetBTMatchesGo(t *testing.T) {
	cases := []struct {
		pats  []string
		input string
	}{
		{[]string{`(?:ab|cd)+xyz`}, "ababxyz cdcdxyz zz"},
		{[]string{`[0-9]{3}-[0-9]{4}`}, "call 555-1234 or 999-0000"},
		{[]string{`(?:ab|cd)+xyz`, `hello`}, "hello ababxyz hello"},
		{[]string{`\bfoo`}, "foo xfoo foo"},
		{[]string{`\Bbar`}, "bar xbar bar"},
		{[]string{`(?m:^)baz`}, "baz\nxbaz\nbaz"},
		{[]string{`a+b`}, "aab ab b aaab"},
		{[]string{`x?y`}, "y xy zy"},
	}
	for _, c := range cases {
		t.Run(c.pats[0]+"/"+c.input, func(t *testing.T) {
			// maxFallback=1 forces every fallback pattern onto BT.
			wBT, droppedBT, err := compileSetBT(c.pats, 1)
			if err != nil {
				t.Skipf("BT compile: %v", err)
			}
			if len(droppedBT) > 0 {
				t.Skipf("BT admitted none of %v", c.pats)
			}
			gotBT, hang, runErr := runWasmSetFind(wBT, c.input, len(c.pats))
			if hang {
				t.Skip("watchdog")
			}
			if errors.Is(runErr, errBTOverflow) {
				t.Skip("BT frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("BT set run: %v", runErr)
			}
			// Oracle: every (start,end) any pattern matches at any position,
			// which is what the ungated/overlapping set find enumerates.
			var want []setMatch
			for i, p := range c.pats {
				re := regexp.MustCompile(p)
				for _, m := range allStartPositionMatches(re, c.input) {
					want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
				}
			}
			if !sameTuples(gotBT, want) {
				t.Errorf("BT set find over %q:\n  got  %v\n  want %v", c.input, gotBT, want)
			}
		})
	}
}

// TestSetBTManyFallbackPatterns is the permanent regression for the shared-region
// shared BT region, and it is deliberately a MULTI-pattern all-fallback set:
// the defect it guards needs a second fallback pattern to exist at all.
//
// compileFallback's bin-packer used to merge later fallback patterns INTO a BT
// bucket. The budgets it checks (budgetStates 512 / budgetBytes 64 KB) are
// unrelated to max_fallback_states, so a merged table small enough to pass them
// was packed in — and since the emitter skips the whole DFA suffix pass for a
// BT bucket while the BT body answers for patternIDs[bi][0] / validMask bit 0
// alone, every merged-in pattern vanished from every bucketed capability with
// no error anywhere. It reported only ONE of these four patterns.
//
// These are the four variants from the corpus block that first exposed it
// (orig 3624). Each is checked against Go rather than against the DFA build, so
// a shared misunderstanding cannot pass.
func TestSetBTManyFallbackPatterns(t *testing.T) {
	pats := []string{
		`(?:.(?:c?))`,
		`^(?:(?:.(?:c?)))$`,
		`^(?:(?:.(?:c?)))`,
		`(?:(?:.(?:c?)))$`,
	}
	for _, input := range []string{"a", "ac", "abc", ""} {
		t.Run(input, func(t *testing.T) {
			w, dropped, err := compileSetBT(pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) > 0 {
				t.Skipf("patterns dropped: %v", dropped)
			}
			got, hang, runErr := runWasmSetFind(w, input, len(pats))
			if hang {
				t.Skip("watchdog")
			}
			if errors.Is(runErr, errBTOverflow) {
				t.Skip("BT frame budget exhausted")
			}
			if runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			var want []setMatch
			for i, p := range pats {
				re := regexp.MustCompile(p)
				for _, m := range allStartPositionMatches(re, input) {
					want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
				}
			}
			if !sameTuples(got, want) {
				t.Errorf("BT set find over %q:\n  got  %v\n  want %v", input, got, want)
			}
		})
	}
}

// TestSetBTCaptureBearingPatterns is the regression for the capture-bearing
// pair of bugs, which turned out to be ONE root cause with two very different
// symptoms.
//
// patternSuffixAST's non-splittable branch re-parsed the pattern WITHOUT
// stripping captures — the only place in the set pipeline that kept them
// (analyzePattern strips, and p.suffixAST is a subtree of that stripped tree).
// The DFA emitters never noticed, because they treat InstCapture as a
// pass-through epsilon. The Backtracking body did: a capture-bearing program
// makes buildBacktrackBody emit capture-slot writes at locals `7 + slot`, while
// admitBTFallback sets numGroups = 0 so no capture locals exist.
//
// Which symptom you got depended purely on how many locals the driver happened
// to declare:
//
//   - fewer locals than `7 + slot`  → the module FAILED WASM VALIDATION
//     ("unknown local 9"), so nothing ran at all.
//   - more locals than `7 + slot`   → the write landed on a VALID index owned
//     by a loop tracker or a window bound and silently clobbered it, so the
//     module ran and returned wrong matches.
//
// Both patterns below carry a capture group and reach a BT bucket. The first
// is the minimal validation failure; the second is the wrong-answer case, whose
// reported (0,5) on "aaaaa" is impossible on its face — 5 is not a sum of 3s
// and 4s, so no match can start at 0.
func TestSetBTCaptureBearingPatterns(t *testing.T) {
	cases := []struct {
		pat    string
		inputs []string
	}{
		{`^(?:(?:(?:(a){2})??))`, []string{"", "a", "aa", "aaa"}},
		{`(?:(?:(?:(a){3,4}){0,}))$`, []string{"aaaa", "aaaaa", "aaaaaa", "aaaaaaa"}},
	}
	for _, c := range cases {
		t.Run(c.pat, func(t *testing.T) {
			pats := []string{c.pat}
			w, dropped, err := compileSetBT(pats, 1)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(dropped) > 0 {
				t.Skipf("pattern dropped: %v", dropped)
			}
			// Validity first: this is the half that used to fail here, and a
			// module that will not parse makes every answer below meaningless.
			f := t.TempDir() + "/m.wasm"
			if err := os.WriteFile(f, w, 0644); err != nil {
				t.Fatal(err)
			}
			if out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput(); vErr != nil {
				t.Fatalf("module INVALID: %s", out)
			}
			re := regexp.MustCompile(c.pat)
			for _, input := range c.inputs {
				got, hang, runErr := runWasmSetFind(w, input, len(pats))
				if hang {
					t.Skip("watchdog")
				}
				if errors.Is(runErr, errBTOverflow) {
					continue
				}
				if runErr != nil {
					t.Fatalf("run %q: %v", input, runErr)
				}
				var want []setMatch
				for _, m := range allStartPositionMatches(re, input) {
					want = append(want, setMatch{PatternID: 0, Start: m[0], End: m[1]})
				}
				if !sameTuples(got, want) {
					t.Errorf("over %q:\n  got  %v\n  want %v", input, got, want)
				}
			}
		})
	}
}

func sameTuples(got, want []setMatch) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[setMatch]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		seen[w]--
		if seen[w] < 0 {
			return false
		}
	}
	return true
}

// A Backtracking member moves a set's `_all` capabilities to the
// out_ptr/count form whenever the set has a Backtracking member, at ANY id
// space. That switch has to reach every emitter that answers an `_all`
// question, and two of them were missed on the first pass — both of which
// implement the NARROW ABI only and so cannot serve a wide capability:
//
//   - the pure union scan, used by a literal-less set
//   - phase 2 of the two-phase split, used by a mixed set
//
// Neither produced a wrong answer: they produced a MODULE THAT DOES NOT LOAD
// ("type mismatch: expected i32, found i64"), which the unit tests could not
// see because they never validated a literal-less BT set with scan_all.
//
// This matrix crosses the shapes that select each frontend and body against the
// capability combinations that select each `_all` path, and validates every
// module. It is deliberately about VALIDITY rather than answers — answers are
// the corpus's job, and a module that will not parse never gets that far.

func TestBTSetABIMatrixValidates(t *testing.T) {
	shapes := map[string][]string{
		// No literal anywhere: the union-scan path.
		"literal-less": {`(?:ab|cd)+`, `(?:ef|gh)+`},
		// Literal + literal-less: the two-phase split's shape.
		"mixed": {`hello[0-9]{3}`, `(?:ab|cd)+`},
		// All literal-bearing: the ordinary bucketed frontend.
		"literals": {`hello[0-9]{3}`, `world[a-z]{2}`, `foo[0-9]+`},
		// Nullable and anchored members, which reach different suffix paths.
		"nullable": {`(?:ab)*`, `(?:ab)*(?:cd)*`},
		"anchored": {`^(?:ab|cd)+$`, `(?:ef|gh)+$`},
		// Wider, to cross more than one bucket.
		"wide-mix": {`hello[0-9]{3}`, `(?:ab|cd)+`, `world[a-z]{2}`,
			`(?:ef|gh)+xyz`, `foo[0-9]+`, `[a-z]{3}bar`, `(?:ij|kl)+`, `baz[0-9]`},
	}
	caps := []struct {
		name string
		set  config.SetConfig
	}{
		{"scan-pair", config.SetConfig{ScanAny: "g_scan_any", ScanAll: "g_scan_all"}},
		{"scan-all-only", config.SetConfig{ScanAll: "g_scan_all"}},
		{"anchored-pair", config.SetConfig{MatchAny: "g_match_any", MatchAll: "g_match_all"}},
		{"find", config.SetConfig{Find: "g_find"}},
		{"find-batch", config.SetConfig{Find: "g_find", Hints: []string{"batch-find"}}},
		{"everything", config.SetConfig{
			MatchAny: "g_match_any", MatchAll: "g_match_all",
			ScanAny: "g_scan_any", ScanAll: "g_scan_all", Find: "g_find",
			Hints: []string{"batch-find"}}},
	}

	for shapeName, pats := range shapes {
		for _, c := range caps {
			for _, mf := range []int{0, 1} {
				name := fmt.Sprintf("%s/%s/mf=%d", shapeName, c.name, mf)
				t.Run(name, func(t *testing.T) {
					entries := make([]config.RegexEntry, len(pats))
					for i, p := range pats {
						entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
					}
					sc := c.set
					sc.Name = "g"
					sc.Patterns = config.PatternSelector{All: true}
					cfg := config.BuildConfig{
						Regexps: entries, MaxFallbackStates: mf,
						Sets: []config.SetConfig{sc},
					}
					w, _, diags, err := compile.CompileFileDiag(cfg, "")
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					nBT := 0
					for _, d := range diags {
						for _, b := range d.Buckets {
							if b.Type == "bt-fallback" {
								nBT++
							}
						}
					}
					// The stub side must agree with what was emitted, since a
					// disagreement there is a wrong signature rather than a
					// failed load.
					if got := compile.SetAdmitsBacktracking(sc, cfg); got != (nBT > 0) {
						t.Errorf("SetAdmitsBacktracking=%v but %d bt-fallback buckets emitted", got, nBT)
					}
					f := t.TempDir() + "/m.wasm"
					if err := os.WriteFile(f, w, 0644); err != nil {
						t.Fatal(err)
					}
					out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
					if vErr != nil {
						t.Fatalf("module INVALID (%d bt buckets): %s", nBT, out)
					}
				})
			}
		}
	}
}

// Parameter 7 of a set suffix function carries
// EITHER a gate-array pointer (gated find) OR the batch skip count (overlapping
// batch) — never both, and the two forms have the same arity, so conflating
// them is a silent wrong answer rather than a validation error.
//
// The BT suffix body read parameter 7 as a gate pointer in both cases. On an
// overlapping batch set that means (a) the empty-extent block
// dereferences `skip + id*4` as an address, and (b) skip is never honoured, so
// a batch resume at a split position re-delivers the BT bucket's tuple.
//
// Catching BOTH halves needs one set that has an empty-extent match (a) and a
// position carrying more than one tuple, driven at capacity 1 so that position
// splits across calls (b).

// compileBTBatchSet compiles an overlapping set exporting both `find` and its
// batch entry, with max_fallback_states forced low so its members land on the
// Backtracking engine. Returns the module and how many BT buckets it holds, so
// a test cannot silently pass by exercising the DFA path instead.
func compileBTBatchSet(pats []string, maxFallback int) ([]byte, int, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps:           entries,
		MaxFallbackStates: maxFallback,
		Sets: []config.SetConfig{{
			Name:        "s",
			Find:        "set_find",
			Hints:       []string{"batch-find"},
			Overlapping: true,
			Patterns:    config.PatternSelector{Names: names},
		}},
	}
	w, _, diags, err := compile.CompileFileDiag(cfg, "")
	if err != nil {
		return nil, 0, err
	}
	nBT := 0
	for _, d := range diags {
		for _, b := range d.Buckets {
			if b.Type == "bt-fallback" {
				nBT++
			}
		}
	}
	return w, nBT, nil
}

// runBTBatch drives the overlapping batch entry to exhaustion at the given
// capacity. Overlapping batch takes no gate array: (ptr, len, cursor, out_ptr,
// out_cap) -> i64.
func runBTBatch(t *testing.T, w []byte, pats []string, input string, outCap int32) []setMatch {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "set_find_batch")
	if fn == nil {
		t.Fatal("module missing set_find_batch export")
	}
	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	// The overlapping batch entry takes the gate array too — not for match gates, which it records none of, but as the
	// per-drive home of the preflight verdict. Zeroed here: that is what
	// declares a fresh drive.
	gatePtr := inBase + pageSize
	outPtr := gatePtr + pageSize
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	for i := int32(0); i < pageSize; i++ {
		mem.UnsafeData(store)[gatePtr+i] = 0
	}
	scratchPtr := writeFindScratch(store, mem, gatePtr, int32(len(pats)), 0, 0)
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}

	countBits := uint(config.SetCursorCountBits(len(pats)))
	countMask := int64(1)<<countBits - 1

	var out []setMatch
	cursor := int64(0)
	maxCalls := 8*(len(input)+1)*(len(pats)+1) + 16
	for calls := 0; ; calls++ {
		if calls > maxCalls {
			t.Fatalf("%v on %q cap=%d: batch did not terminate after %d calls",
				pats, input, outCap, calls)
		}
		res, err := fn.Call(store, inBase, int32(len(input)), cursor, scratchPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("set_find_batch: %v", err)
		}
		packed := res.(int64)
		n := int32(packed & countMask)
		if n < 0 || n > outCap {
			t.Fatalf("%v on %q cap=%d: count %d out of range", pats, input, outCap, n)
		}
		buf := mem.UnsafeData(store)
		for i := int32(0); i < n; i++ {
			base := int(outPtr) + int(i)*12
			out = append(out, setMatch{
				PatternID: int(int32(binary.LittleEndian.Uint32(buf[base:]))),
				Start:     int(int32(binary.LittleEndian.Uint32(buf[base+4:]))),
				End:       int(int32(binary.LittleEndian.Uint32(buf[base+8:]))),
			})
		}
		if uint32(packed>>32) == 0xFFFFFFFF {
			break
		}
		cursor = packed
	}
	return out
}

// TestBTOverlappingBatchHonoursSkip is the skip-parameter regression.
//
// The set deliberately mixes an empty-extent-capable pattern with one that
// shares its start positions, so a single input exercises both halves of the
// parameter-7 defect. The capacity sweep is what makes it sharp: at cap 1 every
// multi-tuple position splits, so a body that ignores skip re-delivers on
// resume, and the totals stop matching the oracle.
func TestBTOverlappingBatchHonoursSkip(t *testing.T) {
	pats := []string{`(?:ab)*`, `(?:ab)*(?:cd)*`}
	const input = "abcd"

	w, nBT, err := compileBTBatchSet(pats, 1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if nBT == 0 {
		t.Skip("no BT bucket was created — nothing of the skip path is exercised")
	}
	t.Logf("%d BT bucket(s)", nBT)

	// Oracle: overlapping find enumerates every match at every start position.
	var want []setMatch
	for i, p := range pats {
		re := regexp.MustCompile(p)
		for _, m := range allStartPositionMatches(re, input) {
			want = append(want, setMatch{PatternID: i, Start: m[0], End: m[1]})
		}
	}

	for _, outCap := range []int32{1, 2, int32(len(pats)), 16} {
		got := runBTBatch(t, w, pats, input, outCap)
		if !sameTuples(got, want) {
			t.Errorf("overlapping batch cap=%d over %q:\n  got  %v\n  want %v",
				outCap, input, got, want)
		}
	}
}

// TestBTOverlappingFindMatchesBatch drives the same set through the plain
// `find` entry, whose forwarded batch argument is zero — the skip == 0 path,
// which must write every tuple. `find` and its batch entry share ONE worker, so
// disagreement between them localises a fault to the batch-only argument.
func TestBTOverlappingFindMatchesBatch(t *testing.T) {
	pats := []string{`(?:ab)*`, `(?:ab)*(?:cd)*`}
	const input = "abcd"

	w, nBT, err := compileBTBatchSet(pats, 1)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if nBT == 0 {
		t.Skip("no BT bucket was created — nothing of the skip path is exercised")
	}

	got, hang, runErr := runWasmSetFind(w, input, len(pats))
	if hang {
		t.Skip("watchdog")
	}
	if runErr != nil {
		t.Fatalf("find: %v", runErr)
	}
	want := runBTBatch(t, w, pats, input, int32(len(pats)))
	if !sameTuples(got, want) {
		t.Errorf("find vs batch over %q disagree:\n  find  %v\n  batch %v", input, got, want)
	}
}

// An anchored find compiled WITH a batch export. The batch loop calls the find
// BODY directly, and an ffAnchoredZeroOnly body ignores the find-from channel
// entirely — it always reports the match beginning at 0. So a resumed call at
// pos > 0 must never reach it: before the guard it handed back the same
// position-0 match, from which the wrapper computed a NEGATIVE relative offset.
//
// Nothing else covers this: the exported find is fine (its own wrapper rejects
// from != 0), so the defect is reachable only through the batch entry.
func TestAnchoredBatchDoesNotRepeat(t *testing.T) {
	const outBase, outCap = int32(1 << 16), int32(64)
	for _, c := range []struct{ pat, input string }{
		{`\Aa+`, "aaabaaa"},
		{`\A`, "abc"},
		{`\Aab*`, "abbabb"},
	} {
		w, _, err := compile.Compile([]config.RegexEntry{{
			Pattern: c.pat, FindFunc: "find", Hints: []string{"batch-find"},
		}}, pathsTableBase, true)
		if err != nil {
			t.Fatalf("%q compile: %v", c.pat, err)
		}
		store, inst, mem, release, err := instantiate(w)
		if err != nil {
			release()
			t.Fatalf("%q instantiate: %v", c.pat, err)
		}
		fn := inst.GetFunc(store, "find_batch")
		if fn == nil {
			release()
			t.Fatalf("%q: no find_batch export", c.pat)
		}
		copy(mem.UnsafeData(store), c.input)
		res, callErr := fn.Call(store, int32(0), int32(len(c.input)), outBase, outCap, int32(0))
		if callErr != nil {
			release()
			t.Fatalf("%q call: %v", c.pat, callErr)
		}
		n := int(res.(int32))
		var got [][2]int
		buf := mem.UnsafeData(store)
		for i := 0; i < n; i++ {
			off := int(outBase) + i*8
			got = append(got, [2]int{
				int(int32(binary.LittleEndian.Uint32(buf[off:]))),
				int(int32(binary.LittleEndian.Uint32(buf[off+4:]))),
			})
		}
		release()
		want := goFindAll(regexp.MustCompile(c.pat), c.input)
		if fmtSpans(got) != fmtSpans(want) {
			t.Errorf("%q on %q via find_batch: got %s want %s (n=%d)",
				c.pat, c.input, fmtSpans(got), fmtSpans(want), n)
		}
	}
}
