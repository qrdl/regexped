package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// End-to-end checks of the seven set capabilities against the plans/SETS.md
// §9.6 oracle formulas. Every expectation is computed live from Go `regexp`
// via the whole-input technique, so nothing here restates the emitter's own
// rules back at it.

// compileCaps compiles pats into a standalone module exporting all seven
// capabilities under their canonical names.
func compileCaps(pats []string, overlapping bool) ([]byte, error) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:        "s",
		Match:       "cap_match",
		MatchAny:    "cap_match_any",
		MatchAll:    "cap_match_all",
		Scan:        "cap_scan",
		ScanAny:     "cap_scan_any",
		ScanAll:     "cap_scan_all",
		Find:        "cap_find",
		Overlapping: overlapping,
		Patterns:    config.PatternSelector{Names: names},
	}}
	w, _, err := compile.CompileFile(config.BuildConfig{Regexps: entries, Sets: sets}, "")
	return w, err
}

// capRunner holds an instantiated capability module plus its memory layout.
type capRunner struct {
	store  *wasmtime.Store
	inst   *wasmtime.Instance
	mem    *wasmtime.Memory
	inBase int32
	outPtr int32
	npat   int
	// release frees the wasmtime Store and Module. The runner OUTLIVES
	// newCapRunner, so this cannot be deferred there — every caller must
	// `defer r.Close()` instead (plans/FUZZER_BUGS.md bug 48).
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
	w, err := compileCaps(pats, overlapping)
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
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
	outPtr := inBase + span
	needed := uint64((int64(outPtr) + pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}
	return &capRunner{store: store, inst: inst, mem: mem, inBase: inBase, outPtr: outPtr, npat: len(pats), release: release}
}

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
// Oracles (plans/SETS.md §9.6).

// oracleAnchored returns the ids of the patterns matching the WHOLE input.
func oracleAnchored(pats []string, input string) []int {
	var out []int
	for k, p := range pats {
		if regexp.MustCompile(`\A(?:` + normalizeForOracle(p) + `)\z`).MatchString(input) {
			out = append(out, k)
		}
	}
	return out
}

// oracleScanAll returns the ids of the patterns matching at some position >= from.
func oracleScanAll(pats []string, input string, from int) []int {
	var out []int
	for k, p := range pats {
		if len(startsMatching(p, input, from)) > 0 {
			out = append(out, k)
		}
	}
	return out
}

// oracleFirstPosition returns the smallest start >= from at which any pattern
// matches, together with the ids matching there. Returns -1 when there is none.
func oracleFirstPosition(pats []string, input string, from int) (int, []int) {
	for p := from; p <= len(input); p++ {
		var ids []int
		for k, pat := range pats {
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
// own comment notes the message is never printed) — see plans/FUZZER_BUGS.md
// bug 49. Memoising is exact: the probe for a given (pat, p) is a pure
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

func TestSetCapabilitiesAgainstOracle(t *testing.T) {
	for _, tc := range capCases {
		for _, input := range tc.inputs {
			t.Run(tc.name+"/"+input, func(t *testing.T) {
				r := newCapRunner(t, tc.pats, input, true)
				defer r.Close()
				n := int32(len(input))

				// match: anchored, whole input.
				wantAnchored := oracleAnchored(tc.pats, input)
				gotMatch := r.call(t, "cap_match", r.inBase, n).(int32)
				if (gotMatch != 0) != (len(wantAnchored) > 0) {
					t.Fatalf("match = %d, want %v (ids %v)", gotMatch, len(wantAnchored) > 0, wantAnchored)
				}

				// match_any: membership, never value equality (§3.5).
				gotAny := r.call(t, "cap_match_any", r.inBase, n).(int32)
				if len(wantAnchored) == 0 {
					if gotAny != -1 {
						t.Fatalf("match_any = %d, want -1", gotAny)
					}
				} else if !containsInt(wantAnchored, int(gotAny)) {
					t.Fatalf("match_any = %d, not among %v", gotAny, wantAnchored)
				}

				// match_all: exact set.
				gotAll := idsFromMask(uint64(r.call(t, "cap_match_all", r.inBase, n).(int64)), len(tc.pats))
				if !eqIDs(append([]int(nil), wantAnchored...), gotAll) {
					t.Fatalf("match_all = %v, want %v", gotAll, wantAnchored)
				}

				for from := 0; from <= len(input); from++ {
					f := int32(from)

					wantPos, wantIDs := oracleFirstPosition(tc.pats, input, from)

					gotScan := r.call(t, "cap_scan", r.inBase, n, f).(int32)
					if (gotScan != 0) != (wantPos >= 0) {
						t.Fatalf("scan(from=%d) = %d, want %v", from, gotScan, wantPos >= 0)
					}

					packed := r.call(t, "cap_scan_any", r.inBase, n, f).(int64)
					if wantPos < 0 {
						if packed != -1 {
							t.Fatalf("scan_any(from=%d) = %#x, want -1", from, packed)
						}
					} else {
						start := int(packed >> 32)
						id := int(packed & 0xFFFFFFFF)
						if start != wantPos {
							t.Fatalf("scan_any(from=%d) start = %d, want %d", from, start, wantPos)
						}
						if !containsInt(wantIDs, id) {
							t.Fatalf("scan_any(from=%d) id = %d, not among %v", from, id, wantIDs)
						}
					}

					wantScanAll := oracleScanAll(tc.pats, input, from)
					gotScanAll := idsFromMask(uint64(r.call(t, "cap_scan_all", r.inBase, n, f).(int64)), len(tc.pats))
					if !eqIDs(append([]int(nil), wantScanAll...), gotScanAll) {
						t.Fatalf("scan_all(from=%d) = %v, want %v", from, gotScanAll, wantScanAll)
					}

					// find: every tuple at the first matching position.
					total := int(r.call(t, "cap_find", r.inBase, n, f, r.outPtr, int32(r.npat)).(int32))
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
						wantEnd := anchoredExtent(tc.pats[id], input, wantPos)
						if en != wantEnd {
							t.Fatalf("find(from=%d) pattern %d end = %d, want %d", from, id, en, wantEnd)
						}
						gotIDs = append(gotIDs, id)
					}
					if !eqIDs(append([]int(nil), wantIDs...), gotIDs) {
						t.Fatalf("find(from=%d) ids = %v, want %v", from, gotIDs, wantIDs)
					}
				}
			})
		}
	}
}

// anchoredExtent returns the RE2 leftmost-first extent of pat anchored exactly
// at position p, or -1 when it does not match there.
func anchoredExtent(pat, input string, p int) int {
	re := regexp.MustCompile(`\A` + dotPrefix(p) + `(?:` + normalizeForOracle(pat) + `)`)
	m := re.FindStringIndex(input)
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

// TestSetFindOverflowContract pins §3.11 / D2: the return value is the TOTAL
// at the position, the buffer takes what fits, and an overflowing call stores
// no state — so the grown retry sees exactly the same world.
func TestSetFindOverflowContract(t *testing.T) {
	pats := []string{"ab", "a", "abc"}
	input := "abc"
	r := newCapRunner(t, pats, input, true)
	defer r.Close()
	n := int32(len(input))

	full := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.outPtr, int32(len(pats))).(int32))
	if full != 3 {
		t.Fatalf("expected all three patterns at position 0, got %d", full)
	}
	for _, cap := range []int32{0, 1, 2} {
		got := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.outPtr, cap).(int32))
		if got != full {
			t.Fatalf("find with out_cap=%d returned %d, want the total %d", cap, got, full)
		}
	}
	// Idempotence: after the undersized probes, the full-size call must be
	// identical to calling it first.
	again := int(r.call(t, "cap_find", r.inBase, n, int32(0), r.outPtr, int32(len(pats))).(int32))
	if again != full {
		t.Fatalf("full-size call after undersized probes returned %d, want %d", again, full)
	}
}

// TestSetFromOutOfRange pins the §4.2 edge contract for from > len.
func TestSetFromOutOfRange(t *testing.T) {
	r := newCapRunner(t, []string{"a", "b"}, "ab", true)
	defer r.Close()
	n := int32(2)
	if got := r.call(t, "cap_scan", r.inBase, n, int32(99)).(int32); got != 0 {
		t.Errorf("scan(from>len) = %d, want 0", got)
	}
	if got := r.call(t, "cap_scan_any", r.inBase, n, int32(99)).(int64); got != -1 {
		t.Errorf("scan_any(from>len) = %d, want -1", got)
	}
	if got := r.call(t, "cap_scan_all", r.inBase, n, int32(99)).(int64); got != 0 {
		t.Errorf("scan_all(from>len) = %d, want 0", got)
	}
	if got := r.call(t, "cap_find", r.inBase, n, int32(99), r.outPtr, int32(2)).(int32); got != 0 {
		t.Errorf("find(from>len) = %d, want 0", got)
	}
}

// FuzzSetCaps drives all seven capabilities of a two-pattern set against the
// §9.6 oracle formulas at every `from`. It is the multi-capability counterpart
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
			if regexp.MustCompile(p).NumSubexp() > 0 {
				t.Skip("capture-bearing patterns are dropped from sets by design")
			}
		}

		w, err := compileCaps(pats, true)
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

		wantAnchored := oracleAnchored(pats, input)
		if got := r.call(t, "cap_match", inBase, n).(int32); (got != 0) != (len(wantAnchored) > 0) {
			t.Fatalf("match = %d, want %v: pats=%q,%q input=%q", got, len(wantAnchored) > 0, pat1, pat2, input)
		}
		gotAny := int(r.call(t, "cap_match_any", inBase, n).(int32))
		if len(wantAnchored) == 0 {
			if gotAny != -1 {
				t.Fatalf("match_any = %d, want -1: pats=%q,%q input=%q", gotAny, pat1, pat2, input)
			}
		} else if !containsInt(wantAnchored, gotAny) {
			t.Fatalf("match_any = %d, not among %v: pats=%q,%q input=%q", gotAny, wantAnchored, pat1, pat2, input)
		}
		gotAll := idsFromMask(uint64(r.call(t, "cap_match_all", inBase, n).(int64)), len(pats))
		if !eqIDs(append([]int(nil), wantAnchored...), gotAll) {
			t.Fatalf("match_all = %v, want %v: pats=%q,%q input=%q", gotAll, wantAnchored, pat1, pat2, input)
		}

		for from := 0; from <= len(input); from++ {
			f32 := int32(from)
			wantPos, wantIDs := oracleFirstPosition(pats, input, from)

			if got := r.call(t, "cap_scan", inBase, n, f32).(int32); (got != 0) != (wantPos >= 0) {
				t.Fatalf("scan(from=%d) = %d, want %v: pats=%q,%q input=%q", from, got, wantPos >= 0, pat1, pat2, input)
			}
			packed := r.call(t, "cap_scan_any", inBase, n, f32).(int64)
			if wantPos < 0 {
				if packed != -1 {
					t.Fatalf("scan_any(from=%d) = %#x, want -1: pats=%q,%q input=%q", from, packed, pat1, pat2, input)
				}
			} else {
				if start := int(packed >> 32); start != wantPos {
					t.Fatalf("scan_any(from=%d) start = %d, want %d: pats=%q,%q input=%q", from, start, wantPos, pat1, pat2, input)
				}
				if id := int(packed & 0xFFFFFFFF); !containsInt(wantIDs, id) {
					t.Fatalf("scan_any(from=%d) id = %d, not among %v: pats=%q,%q input=%q", from, id, wantIDs, pat1, pat2, input)
				}
			}
			wantScanAll := oracleScanAll(pats, input, from)
			gotScanAll := idsFromMask(uint64(r.call(t, "cap_scan_all", inBase, n, f32).(int64)), len(pats))
			if !eqIDs(append([]int(nil), wantScanAll...), gotScanAll) {
				t.Fatalf("scan_all(from=%d) = %v, want %v: pats=%q,%q input=%q", from, gotScanAll, wantScanAll, pat1, pat2, input)
			}
		}

		// The DEFAULT `find` configuration, against §9.6.1's union oracle.
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
// which switches from an i64 bitmask return to a caller-provided bitmap
// (plans/SETS.md §3.13). The bit-per-pattern packing is easy to get wrong at
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
