package fuzz

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// G17 promotion for the ANCHORED and FALLBACK packers (
// item 8).
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

					total := int(r.call(t, "cap_find", r.inBase, in, f, r.gatePtr, r.outPtr, int32(r.npat)).(int32))
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
// Two things here are specific to G17. emitSetAnchoredCapBody declares two
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
// The defect predates this change — it shipped with G17's shared-literal path,
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
