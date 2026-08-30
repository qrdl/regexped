package fuzz

import (
	"fmt"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// The scan pair served by the START-ANYWHERE union
// automaton above 64 ids, where the u64 accumulator every other union set uses
// has run out of bits.
//
// This is a new BODY, not a new capability — same exports, same signatures,
// same answers — so nothing in the existing corpus fails when it is wrong. It
// is reached only by a set that is literal-less (scalar frontend) AND wider
// than 64 ids, and it answers with tables no other body reads. Hence a test of
// its own, and hence every case here asserts the path was TAKEN before it
// asserts an answer: a routing gate that quietly refuses looks exactly like a
// passing test.
//
// The shapes are the ones the ceiling makes possible rather than a sample of
// convenience:
//
//   - 64 vs 65 ids, because 64 is the last narrow set and 65 the first wide
//     one, and a boundary that is off by one is invisible everywhere else;
//   - an id space that is NOT a multiple of 64, because the caller's bitmap is
//     ceil(idSpace/8) BYTES and a whole-word OR at the end of it writes up to
//     seven bytes past the caller's array — silent corruption, not a wrong
//     answer, so a canary sits immediately after every bitmap here;
//   - a NAMED SUBSET, the only configuration where the pattern count and the
//     id space differ, which is also the only way to make the
//     `scan_all` early exit's count target wrong-but-plausible: comparing
//     against the id space instead of the distinct ids would make it dead;
//   - empty input, `from == len` and `from > len`, and nullable /
//     `\A` / `$` members, because the entry-state and end-of-input accepts are
//     separate arms of the body from the loop and each has been a bug before.

// wideUnionSet compiles a set exporting the scan pair (and optionally `find`)
// over the given patterns, selecting `names` when non-nil so a caller can make
// the id space larger than the pattern count.
func wideUnionSet(t *testing.T, pats []string, selected []int, withFind bool) ([]byte, []compile.SetDiag) {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	allNames := make([]string, len(pats))
	for i, p := range pats {
		allNames[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: allNames[i], Pattern: p}
	}
	names := allNames
	if selected != nil {
		names = nil
		for _, k := range selected {
			names = append(names, allNames[k])
		}
	}
	set := config.SetConfig{
		Name:     "s",
		ScanAny:  "cap_scan_any",
		ScanAll:  "cap_scan_all",
		Patterns: config.PatternSelector{Names: names},
	}
	if withFind {
		set.Find = "cap_find"
	}
	w, _, diags, err := compile.CompileFileDiag(
		config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{set}}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return w, diags
}

// assertUnionScan fails unless the scan pair really was served by a union
// automaton of the expected width. --diag-json is the oracle for that: it is
// the only place the body selection is visible, and asserting it is what keeps
// this file from passing on a set that quietly fell back to the bucket walk.
func assertUnionScan(t *testing.T, diags []compile.SetDiag, wantWide bool) {
	t.Helper()
	if len(diags) != 1 || diags[0].UnionScan == nil {
		t.Fatalf("no union-scan diagnostic: %+v", diags)
	}
	u := diags[0].UnionScan
	if !u.Used {
		t.Fatalf("union automaton REFUSED (%s): the scan pair fell back to the "+
			"per-position walk, so this case tests nothing", u.Refused)
	}
	if u.Wide != wantWide {
		t.Fatalf("union wide = %v, want %v (states=%d mask_words=%d)",
			u.Wide, wantWide, u.States, u.MaskWords)
	}
}

// wideRunner is a capRunner with a CANARY byte immediately after the `_all`
// bitmap, so an over-wide store is caught where it happens rather than as a
// mysterious failure in whatever the caller put next.
type wideRunner struct {
	store    *wasmtime.Store
	inst     *wasmtime.Instance
	mem      *wasmtime.Memory
	inBase   int32
	outPtr   int32
	idSpace  int
	nbytes   int
	release  func()
	canaryAt int32
}

const wideCanary = 0xA5

func newWideRunner(t *testing.T, w []byte, input string, idSpace int) *wideRunner {
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
	outPtr := inBase + span
	needed := uint64((int64(outPtr) + 2*pageSize + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			release()
			t.Fatalf("grow: %v", err)
		}
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}
	nb := (idSpace + 7) / 8
	r := &wideRunner{store: store, inst: inst, mem: mem, inBase: inBase,
		outPtr: outPtr, idSpace: idSpace, nbytes: nb, release: release,
		canaryAt: outPtr + int32(nb)}
	return r
}

func (r *wideRunner) Close() {
	if r != nil && r.release != nil {
		r.release()
		r.release = nil
	}
}

// clear zeroes the bitmap — which the wide `_all` ABI requires on entry — and
// re-arms the canary.
func (r *wideRunner) clear() {
	data := r.mem.UnsafeData(r.store)
	for i := 0; i < r.nbytes; i++ {
		data[int(r.outPtr)+i] = 0
	}
	for i := 0; i < 8; i++ {
		data[int(r.canaryAt)+i] = wideCanary
	}
}

func (r *wideRunner) checkCanary(t *testing.T, what string) {
	t.Helper()
	data := r.mem.UnsafeData(r.store)
	for i := 0; i < 8; i++ {
		if got := data[int(r.canaryAt)+i]; got != wideCanary {
			t.Fatalf("%s wrote %d bytes past the caller's %d-byte bitmap "+
				"(canary[%d] = %#x): an id space that is not a multiple of 64 "+
				"has a partial final word", what, i+1, r.nbytes, i, got)
		}
	}
}

func (r *wideRunner) bitmapIDs() []int {
	data := r.mem.UnsafeData(r.store)
	var out []int
	for k := 0; k < r.idSpace; k++ {
		if data[int(r.outPtr)+k/8]&(1<<uint(k%8)) != 0 {
			out = append(out, k)
		}
	}
	return out
}

func (r *wideRunner) call(t *testing.T, name string, args ...interface{}) interface{} {
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

// classChain is the literal-less family the whole item is about: no mandatory
// literal, so the set gets the scalar frontend and the scan pair has nothing to
// skip with.
func classChain(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%8, 1+i/8%8)
	}
	return out
}

func TestWideUnionScanMatchesGo(t *testing.T) {
	inputs := []string{
		"",
		"a1",
		"abc123",
		"zz",
		"abcdefgh12345678",
		"xx abcd12 yy ef345 zz",
		"0123456789",
		"aaaaaaaabbbbbbbb11111111",
	}
	for _, n := range []int{65, 96, 128} {
		pats := classChain(n)
		w, diags := wideUnionSet(t, pats, nil, false)
		assertUnionScan(t, diags, true)
		dropped := droppedFromSet(diags)

		for _, input := range inputs {
			t.Run(fmt.Sprintf("n=%d/%q", n, input), func(t *testing.T) {
				r := newWideRunner(t, w, input, n)
				defer r.Close()
				in := int32(len(input))

				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(pats, input, from, dropped)

					gotAny := r.call(t, "cap_scan_any", r.inBase, in, int32(from)).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v", from, gotAny, want)
					}

					r.clear()
					count := int(r.call(t, "cap_scan_all", r.inBase, in, int32(from), r.outPtr).(int32))
					r.checkCanary(t, "scan_all")
					got := r.bitmapIDs()
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						t.Fatalf("scan_all(from=%d) = %v, want %v", from, got, want)
					}
					if count != len(want) {
						t.Fatalf("scan_all(from=%d) count = %d, want %d", from, count, len(want))
					}
				}

				// Past the end is "nothing", and it is a REAL case
				// rather than a defensive one — the loop guard alone does not
				// deliver it, because the entry-state and end-of-input accept
				// arms both run regardless of how the loop exited.
				past := in + 1
				if got := r.call(t, "cap_scan_any", r.inBase, in, past).(int32); got != -1 {
					t.Fatalf("scan_any(from>len) = %d, want -1", got)
				}
				r.clear()
				if got := int(r.call(t, "cap_scan_all", r.inBase, in, past, r.outPtr).(int32)); got != 0 {
					t.Fatalf("scan_all(from>len) count = %d, want 0", got)
				}
				r.checkCanary(t, "scan_all(from>len)")
				if ids := r.bitmapIDs(); len(ids) != 0 {
					t.Fatalf("scan_all(from>len) bitmap = %v, want empty", ids)
				}
			})
		}
	}
}

// TestWideUnionScanBoundary64 pins the last NARROW set and the first wide one.
// The representation switches between them, and an off-by-one in that test is
// invisible in every other file: both widths answer correctly, so only the
// diagnostic can tell them apart.
func TestWideUnionScanBoundary64(t *testing.T) {
	for _, tc := range []struct {
		n    int
		wide bool
	}{{63, false}, {64, false}, {65, true}} {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			pats := classChain(tc.n)
			w, diags := wideUnionSet(t, pats, nil, false)
			assertUnionScan(t, diags, tc.wide)

			input := "abc123 zz9 abcdefgh12345678"
			dropped := droppedFromSet(diags)
			want := oracleScanAll(pats, input, 0, dropped)

			if tc.wide {
				r := newWideRunner(t, w, input, tc.n)
				defer r.Close()
				r.clear()
				count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(0), r.outPtr).(int32))
				r.checkCanary(t, "scan_all")
				if got := r.bitmapIDs(); !eqIDs(append([]int(nil), want...), got) {
					t.Fatalf("scan_all = %v, want %v", got, want)
				}
				if count != len(want) {
					t.Fatalf("scan_all count = %d, want %d", count, len(want))
				}
				return
			}
			// Narrow: the i64 mask form, unchanged by this work.
			store, inst, mem, release, err := instantiate(w)
			if err != nil {
				release()
				t.Fatalf("instantiate: %v", err)
			}
			defer release()
			const pageSize = 65536
			dataTop, _ := utils.ParseDataSectionBytes(w)
			inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
			if cur := mem.Size(store); uint64(inBase/pageSize)+2 > cur {
				if _, err := mem.Grow(store, uint64(inBase/pageSize)+2-cur); err != nil {
					t.Fatalf("grow: %v", err)
				}
			}
			copy(mem.UnsafeData(store)[inBase:], input)
			fn := inst.GetFunc(store, "cap_scan_all")
			res, err := fn.Call(store, inBase, int32(len(input)), int32(0))
			if err != nil {
				t.Fatalf("scan_all: %v", err)
			}
			if got := idsFromMask(uint64(res.(int64)), tc.n); !eqIDs(append([]int(nil), want...), got) {
				t.Fatalf("scan_all = %v, want %v", got, want)
			}
		})
	}
}

// TestWideUnionScanBitmapEdge is the decisive test for the partial-word write,
// and it exists because the obvious one is WORTHLESS.
//
// A canary after the bitmap does not catch an over-wide store here: the write
// is a read-modify-WRITE OR, and the accept row's bytes past the id space are
// zero, so OR-ing them into the canary leaves it byte-identical. Confirmed by
// mutation — widening the loop to whole words only passed every canary check in
// this file. What an over-wide access actually costs is a TRAP when the
// caller's bitmap sits near the end of its memory, which for an embedded caller
// is a real 13-byte array with something else immediately after it.
//
// So the bitmap is placed at the very TOP of linear memory: with 65 ids it is 9
// bytes, one whole word plus one byte, and a second whole-word load or store
// would reach 6 bytes past the end of memory and trap.
func TestWideUnionScanBitmapEdge(t *testing.T) {
	const n = 65 // 9 bitmap bytes: one full word + one tail byte
	pats := classChain(n)
	w, diags := wideUnionSet(t, pats, nil, false)
	assertUnionScan(t, diags, true)

	input := "abc123 zz9 abcdefgh12345678"
	store, inst, mem, release, err := instantiate(w)
	if err != nil {
		release()
		t.Fatalf("instantiate: %v", err)
	}
	defer release()

	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	want := uint64(inBase/pageSize) + 1
	if cur := mem.Size(store); want > cur {
		if _, err := mem.Grow(store, want-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	top := int32(mem.Size(store) * pageSize)
	nbytes := int32((n + 7) / 8)
	outPtr := top - nbytes // the last byte of the bitmap IS the last byte of memory
	copy(mem.UnsafeData(store)[inBase:], input)
	for i := int32(0); i < nbytes; i++ {
		mem.UnsafeData(store)[outPtr+i] = 0
	}

	fn := inst.GetFunc(store, "cap_scan_all")
	if _, err := fn.Call(store, inBase, int32(len(input)), int32(0), outPtr); err != nil {
		t.Fatalf("scan_all wrote outside the caller's %d-byte bitmap: %v\n"+
			"The final word of an id space that is not a multiple of 64 is "+
			"PARTIAL and must be handled byte at a time.", nbytes, err)
	}

	// The answer must still be right at the edge — a body that avoided the trap
	// by skipping the tail byte would pass the check above and lose ids 64+.
	dropped := droppedFromSet(diags)
	wantIDs := oracleScanAll(pats, input, 0, dropped)
	var got []int
	for k := 0; k < n; k++ {
		if mem.UnsafeData(store)[int(outPtr)+k/8]&(1<<uint(k%8)) != 0 {
			got = append(got, k)
		}
	}
	if !eqIDs(append([]int(nil), wantIDs...), got) {
		t.Fatalf("scan_all at the memory edge = %v, want %v", got, wantIDs)
	}
}

// TestWideUnionScanNamedSubset is the id-space configuration: PATTERN_COUNT and
// ID_SPACE differ, so every structure indexed by an id is larger than the
// number of patterns.
//
// Two things can only fail here. The bitmap is sized by the id space (13 bytes
// for 100 ids), which is not a multiple of 8 — the partial-word write. And
// `scan_all`'s early exit compares its count against the number of DISTINCT IDS
// the set can report; comparing against the id space instead would make it
// unreachable, which no answer-checking test can see, while comparing against
// the pattern count of a set with duplicate ids would cut the scan short.
func TestWideUnionScanNamedSubset(t *testing.T) {
	const total = 100
	pats := classChain(total)
	var selected []int
	for k := 0; k < total; k += 3 { // ids 0,3,...,99 -> id space 100, 34 patterns
		selected = append(selected, k)
	}
	w, diags := wideUnionSet(t, pats, selected, false)
	assertUnionScan(t, diags, true)
	if got := diags[0].IDSpaceSize; got != total {
		t.Fatalf("id space = %d, want %d — the subset did not widen it, so this "+
			"case is not testing what it says", got, total)
	}

	subPats := make([]string, 0, len(selected))
	for _, k := range selected {
		subPats = append(subPats, pats[k])
	}
	for _, input := range []string{"", "a1", "abcdefgh12345678", "zz9 abcd12"} {
		t.Run(input, func(t *testing.T) {
			r := newWideRunner(t, w, input, total)
			defer r.Close()
			for from := 0; from <= len(input); from++ {
				// Oracle in GLOBAL ids: the selected pattern at subset index i
				// reports id selected[i].
				var want []int
				for i, p := range subPats {
					if len(startsMatching(p, input, from)) > 0 {
						want = append(want, selected[i])
					}
				}
				r.clear()
				count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(from), r.outPtr).(int32))
				r.checkCanary(t, "scan_all")
				got := r.bitmapIDs()
				if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
					t.Fatalf("scan_all(from=%d) = %v, want %v", from, got, want)
				}
				if count != len(want) {
					t.Fatalf("scan_all(from=%d) count = %d, want %d", from, count, len(want))
				}
				gotAny := r.call(t, "cap_scan_any", r.inBase, int32(len(input)), int32(from)).(int32)
				if len(want) == 0 {
					if gotAny != -1 {
						t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny)
					}
				} else if !containsInt(want, int(gotAny)) {
					t.Fatalf("scan_any(from=%d) = %d, not among %v", from, gotAny, want)
				}
			}
		})
	}
}

// TestWideUnionScanEarlyExitCompleteness pins the `scan_all` early exit from
// the side that can lose an answer.
//
// The exit fires once the count of distinct ids reaches what the set can
// report, and it is tested after a whole accept row has been OR-ed in. That
// makes an exit target which is too LARGE merely dead — correct answers,
// wasted work, invisible to any oracle — but a target which is too SMALL
// returns while a pattern is still unseen.
//
// Reaching that needs an input where the count passes exactly through
// (target - 1) with one pattern still outstanding, which none of the uniform
// class-chain inputs above can do: they match every pattern at the same
// position, so the count goes from 0 to all-of-them in one row and any
// off-by-one target is crossed by a complete answer. So the set here is built
// deliberately lopsided — 64 patterns that all match in the first few bytes,
// and ONE that matches only at the very end. Confirmed by mutation: with the
// target reduced by one this fails and the uniform cases do not.
func TestWideUnionScanEarlyExitCompleteness(t *testing.T) {
	pats := classChain(64)
	// Id 64, matched only by the tail. It must stay LITERAL-LESS — `qqq[0-9]`
	// gives the set a mandatory literal, which routes it to the two-phase
	// split and a NARROW phase-2 automaton over the remaining 64 ids, testing
	// something else entirely. (Found by writing it that way first: the
	// diagnostic assertion caught it, which is what the assertion is for.)
	pats = append(pats, `[p-r]{3}[0-9]`)
	input := "abcdefgh12345678 filler filler filler qqq7"

	w, diags := wideUnionSet(t, pats, nil, false)
	assertUnionScan(t, diags, true)
	dropped := droppedFromSet(diags)

	r := newWideRunner(t, w, input, len(pats))
	defer r.Close()
	want := oracleScanAll(pats, input, 0, dropped)
	if len(want) != len(pats) {
		t.Fatalf("the input matches %d of %d patterns; this case needs all of "+
			"them, or the early exit is never even reached", len(want), len(pats))
	}
	r.clear()
	count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(0), r.outPtr).(int32))
	r.checkCanary(t, "scan_all")
	got := r.bitmapIDs()
	if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
		t.Fatalf("scan_all = %v, want %v — an early exit that fires one pattern "+
			"short drops exactly the id that matches last", got, want)
	}
	if count != len(want) {
		t.Fatalf("scan_all count = %d, want %d", count, len(want))
	}
}

// TestWideUnionScanZeroWidthMembers drives the two arms of the body that are
// NOT the loop: the entry-state accepts, which are the only place a pattern
// matching EMPTY at `from` is ever reported, and the end-of-input accepts,
// which are the only place `$`/\z is. Both were separate bug fixes in the
// narrow body; the wide body re-implements them and so can lose them
// independently.
func TestWideUnionScanZeroWidthMembers(t *testing.T) {
	pats := classChain(70)
	// Overwrite a few with zero-width and anchored shapes, keeping the set
	// literal-less and above 64 ids.
	pats[0] = `\A`
	pats[1] = `$`
	pats[2] = `[q]*`
	pats[3] = `^[0-9]`
	pats[69] = `[0-9]\z`

	w, diags := wideUnionSet(t, pats, nil, false)
	assertUnionScan(t, diags, true)
	dropped := droppedFromSet(diags)

	for _, input := range []string{"", "0", "q", "a1", "0q9", "zzz"} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			r := newWideRunner(t, w, input, len(pats))
			defer r.Close()
			for from := 0; from <= len(input); from++ {
				want := oracleScanAll(pats, input, from, dropped)
				r.clear()
				count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(from), r.outPtr).(int32))
				r.checkCanary(t, "scan_all")
				got := r.bitmapIDs()
				if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
					t.Fatalf("scan_all(from=%d) = %v, want %v", from, got, want)
				}
				if count != len(want) {
					t.Fatalf("scan_all(from=%d) count = %d, want %d", from, count, len(want))
				}
			}
		})
	}
}

// TestWideUnionTwoPhaseScan covers the MIXED set: a literal frontend over some
// buckets plus fallback buckets the frontend cannot skip, which the two-phase
// 19 splits into phase 1 (the frontend) and phase 2 (a union automaton over the
// fallback patterns only).
//
// It is a separate path from everything above and it moved with this work: the
// fallback patterns keep their GLOBAL ids, so a mixed set wide enough to push
// them past 63 used to lose phase 2 entirely and fall back to the per-position
// walk. Now phase 2 can be wide, which also means the wrapper composing the two
// phases has a third shape — both phases writing one caller bitmap and their
// counts ADDED, which is sound only because a pattern lives in exactly one
// bucket.
//
// The ids are arranged so the fallback half is the HIGH half: literal patterns
// take 0..39 and literal-less ones 40..79, so phase 2's own id space really is
// above 64 rather than merely the set's being so.
func TestWideUnionTwoPhaseScan(t *testing.T) {
	var pats []string
	for i := 0; i < 40; i++ {
		pats = append(pats, fmt.Sprintf(`union[ \t]+[a-z]{%d}[0-9]{%d}`, 1+i%6, 1+i/6%6))
	}
	for i := 0; i < 40; i++ {
		pats = append(pats, fmt.Sprintf(`[a-z]{%d}[0-9]{%d}`, 1+i%8, 1+i/8%8))
	}
	w, diags := wideUnionSet(t, pats, nil, false)
	if len(diags) != 1 || diags[0].UnionScan == nil {
		t.Fatalf("no union-scan diagnostic: %+v", diags)
	}
	u := diags[0].UnionScan
	if !u.Used || !u.Phase2 || !u.Wide {
		t.Fatalf("want a WIDE PHASE-2 automaton, got used=%v phase2=%v wide=%v refused=%q",
			u.Used, u.Phase2, u.Wide, u.Refused)
	}
	dropped := droppedFromSet(diags)

	for _, input := range []string{
		"",
		"union ab12",
		"abc123",
		"union   abcdef123456 and abcdefgh12345678",
		"nothing to see here",
	} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			r := newWideRunner(t, w, input, len(pats))
			defer r.Close()
			for from := 0; from <= len(input); from++ {
				want := oracleScanAll(pats, input, from, dropped)
				r.clear()
				count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(from), r.outPtr).(int32))
				r.checkCanary(t, "scan_all")
				got := r.bitmapIDs()
				if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
					t.Fatalf("scan_all(from=%d) = %v, want %v", from, got, want)
				}
				// The sum of the two phases' counts, which double-counts if the
				// phases ever share an id.
				if count != len(want) {
					t.Fatalf("scan_all(from=%d) count = %d, want %d", from, count, len(want))
				}
				gotAny := r.call(t, "cap_scan_any", r.inBase, int32(len(input)), int32(from)).(int32)
				if len(want) == 0 {
					if gotAny != -1 {
						t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny)
					}
				} else if !containsInt(want, int(gotAny)) {
					t.Fatalf("scan_any(from=%d) = %d, not among %v", from, gotAny, want)
				}
			}
		})
	}
}

// TestUnionScanDegenerateLimits drives the two DEGENERATE forms of the
// mid-accept partition, which are not variations of
// the general case but different emitted code:
//
//   - midAcceptLimit == 0 — no state can accept mid-string, so the bodies emit
//     NO mid-accept arm at all and every answer has to come from the
//     end-of-input arm. `{[a-z]+\z, [0-9]{2}\z}` is that set.
//   - midAcceptLimit == numStates — every state can, so the arm is emitted with
//     NO guard, because the compare could never be false. For `scan_any` that
//     means an unconditional return on the first byte. `{[0-9]*, [a-c]{2}}` is
//     that set: the nullable member matches empty in every state, so every state
//     accepts, while the second member matches MID-string and not at end of
//     input — which is what makes the arm load-bearing rather than something
//     the end-of-input arm could answer instead.
//
// compile/set_union_partition_test.go proves the two limits are REACHED (and
// fails if a fixture stops reaching them); this proves the code emitted for
// them answers correctly. Both halves are needed: the construction being right
// says nothing about the branch that consumes it.
func TestUnionScanDegenerateLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		pats []string
	}{
		{"limit-zero", []string{`[a-z]+\z`, `[0-9]{2}\z`}},
		{"limit-full", []string{`[0-9]*`, `[a-c]{2}`}},
	} {
		w, diags := wideUnionSet(t, tc.pats, nil, false)
		assertUnionScan(t, diags, false) // narrow: two patterns
		dropped := droppedFromSet(diags)

		// "xabz" is load-bearing for limit-full: `[a-c]{2}` matches MID-string
		// there and does NOT match at end of input, so only the mid-accept arm
		// can report it. Without such an input the end-of-input arm answers the
		// whole case on its own and a lost mid arm is invisible — which is
		// exactly what mutation testing showed with the first fixture.
		for _, input := range []string{"", "a", "12", "abc", "ab12", "12ab", "x9", "xabz", "zzabzz"} {
			t.Run(tc.name+"/"+fmt.Sprintf("%q", input), func(t *testing.T) {
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
				if cur := mem.Size(store); uint64(inBase/pageSize)+2 > cur {
					if _, err := mem.Grow(store, uint64(inBase/pageSize)+2-cur); err != nil {
						t.Fatalf("grow: %v", err)
					}
				}
				if len(input) > 0 {
					copy(mem.UnsafeData(store)[inBase:], input)
				}
				in := int32(len(input))
				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(tc.pats, input, from, dropped)

					// Narrow ABI: scan_all returns an i64 mask, scan_any an id.
					res, err := inst.GetFunc(store, "cap_scan_all").
						Call(store, inBase, in, int32(from))
					if err != nil {
						t.Fatalf("scan_all: %v", err)
					}
					got := idsFromMask(uint64(res.(int64)), len(tc.pats))
					if !eqIDs(append([]int(nil), want...), got) {
						t.Fatalf("scan_all(from=%d) = %v, want %v", from, got, want)
					}

					res, err = inst.GetFunc(store, "cap_scan_any").
						Call(store, inBase, in, int32(from))
					if err != nil {
						t.Fatalf("scan_any: %v", err)
					}
					gotAny := res.(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1", from, gotAny)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v", from, gotAny, want)
					}
				}
			})
		}
	}
}

// TestWideUnionScanSingleCapability covers the two configurations where the
// declared capabilities decide which TABLES exist, not just which bodies do.
//
// The accept bitmap rows are `scan_all`'s alone — `scan_any` answers from the
// per-state representative — so a set exporting only `scan_any` emits no rows
// at all, and one exporting only `scan_all` emits them with no `scan_any` body
// to share the representative table with. Each is a distinct table layout, and
// a set declares its capabilities freely, so both are ordinary configurations
// rather than corner cases. Instantiating validates the module: wasmtime
// refuses one whose bodies disagree with its declared types.
func TestWideUnionScanSingleCapability(t *testing.T) {
	const n = 96
	pats := classChain(n)
	entries := make([]config.RegexEntry, n)
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	input := "abcdefgh12345678 zz9"

	for _, tc := range []struct{ name, any_, all string }{
		{"scan_any-only", "cap_scan_any", ""},
		{"scan_all-only", "", "cap_scan_all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := config.SetConfig{Name: "s", ScanAny: tc.any_, ScanAll: tc.all,
				Patterns: config.PatternSelector{All: true}}
			w, _, diags, err := compile.CompileFileDiag(
				config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{set}}, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			assertUnionScan(t, diags, true)
			dropped := droppedFromSet(diags)
			want := oracleScanAll(pats, input, 0, dropped)

			r := newWideRunner(t, w, input, n)
			defer r.Close()
			if tc.any_ != "" {
				got := r.call(t, "cap_scan_any", r.inBase, int32(len(input)), int32(0)).(int32)
				if !containsInt(want, int(got)) {
					t.Fatalf("scan_any = %d, not among %v", got, want)
				}
			}
			if tc.all != "" {
				r.clear()
				count := int(r.call(t, "cap_scan_all", r.inBase, int32(len(input)), int32(0), r.outPtr).(int32))
				r.checkCanary(t, "scan_all")
				if got := r.bitmapIDs(); !eqIDs(append([]int(nil), want...), got) {
					t.Fatalf("scan_all = %v, want %v", got, want)
				}
				if count != len(want) {
					t.Fatalf("scan_all count = %d, want %d", count, len(want))
				}
			}
		})
	}
}

// TestWideUnionDoesNotArmFindPreflight is the trap this change had to avoid,
// and it is a `find` test rather than a scan one.
//
// The gated `find` preflight runs the union automaton once per drive and writes
// its verdict into the caller's gate array as gate sentinels. Its emitters
// read acceptOff/eofOff as [numStates] u64 — tables a WIDE automaton does not
// emit at all. Before item 21 the predicate needed no id-space test, because
// `cs.unionScan != nil` implied 64 ids or fewer; afterwards it does, and
// without it a set like this one would run the preflight against the transition
// table, read garbage as accept masks, and RETIRE patterns that are alive.
//
// The failure would be silent and in the worst direction: matches simply stop
// being reported. So the set here is built to arm the preflight if anything
// still can — scalar frontend, a never-dying member, and the scan pair present
// so the union is built at all — and every match is checked against Go.
func TestWideUnionDoesNotArmFindPreflight(t *testing.T) {
	pats := classChain(70)
	pats[0] = `[^\n]*ERROR` // never dies on newline-free input
	pats[1] = `a+`

	w, diags := wideUnionSet(t, pats, pats2sel(nil), true)
	assertUnionScan(t, diags, true)
	dropped := droppedFromSet(diags)

	inputs := []string{
		"",
		"aaa",
		"no match here at all",
		"aaa and then ERROR at the end",
		"abcd1234 aaa ERROR",
	}
	for _, input := range inputs {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			r := newCapRunnerFromModule(t, w, input, len(pats))
			defer r.Close()
			in := int32(len(input))
			// Drive `find` to exhaustion exactly as a caller would, and compare
			// the FIRST matching position's ids at every `from` — the quantity
			// a wrongly retired pattern changes.
			for from := 0; from <= len(input); from++ {
				r.resetGates()
				wantPos, wantIDs := oracleFirstPosition(pats, input, from, dropped)
				total := int(r.call(t, "cap_find", r.inBase, in, int32(from),
					r.gatePtr, r.outPtr, int32(r.npat)).(int32))
				if wantPos < 0 {
					if total != 0 {
						t.Fatalf("find(from=%d) = %d tuples, want 0", from, total)
					}
					continue
				}
				if total != len(wantIDs) {
					t.Fatalf("find(from=%d) = %d tuples, want %d (ids %v at %d)",
						from, total, len(wantIDs), wantIDs, wantPos)
				}
			}
		})
	}
}

// pats2sel exists so the call above reads as "all patterns" rather than a bare
// nil that could be mistaken for a missing argument.
func pats2sel(sel []int) []int { return sel }

// newCapRunnerFromModule is newCapRunner for an already-compiled module, so a
// test that needs a specific set CONFIGURATION (here: the scan pair present, to
// force the union automaton to exist) does not have to go through compileCaps'
// fixed capability list.
func newCapRunnerFromModule(t *testing.T, w []byte, input string, npat int) *capRunner {
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
			release()
			t.Fatalf("grow: %v", err)
		}
	}
	if len(input) > 0 {
		copy(mem.UnsafeData(store)[inBase:], input)
	}
	r := &capRunner{store: store, inst: inst, mem: mem, inBase: inBase,
		gatePtr: gatePtr, outPtr: outPtr, npat: npat, release: release}
	r.resetGates()
	return r
}
