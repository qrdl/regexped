package fuzz

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
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
// compile/set_sweep_test.go proves the two limits are REACHED (and
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
					r.scratchPtr(), r.outPtr, int32(r.npat)).(int32))
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

// The UNION-WALK arm of the gated `find` preflight (`emitUnionAliveMask`).
//
// This file exists because a mutation survived everything else in the suite.
// The wide accept form put the mid-accept OR of that walk behind the
// accept-first partition, and inverting the guard — so the walk reads the
// accepts of states that cannot accept and skips the ones that can — passed
// `make setcaps`, the whole gated-find suite, and both overlapping-preflight
// suites. The failure it would cause is the worst kind: the alive mask
// UNDER-approximates, patterns that do match are retired as dead, and `find`
// silently stops reporting them.
//
// Nothing covered it because reaching the arm needs a coincidence of four
// things, and the existing fixtures each miss at least one:
//
//   - a scalar frontend and a NEVER-DYING suffix DFA, or no preflight is
//     emitted at all (a preflight that retires nothing is Candidate A);
//   - every pattern LITERAL-LESS, so G12's absence prefilter declines
//     (buildAbsenceLits needs one pattern with a mandatory literal) and the
//     union walk is what computes the verdict. greedy-3 — the fixture the
//     preflight work was built against — fails exactly here: `ERROR` is an
//     absence literal, so greedy-3 never runs this code;
//   - a SCAN capability declared, because the union automaton is only built
//     when something asks for it, and a find-only gated set asks for nothing;
//   - an input where a pattern's aliveness is established MID-STRING, since
//     the entry-state and end-of-input contributions are separate arms that an
//     inverted guard leaves intact.
//
// `litLessNeverDying` in compile/set_emit_test.go is the same family,
// and its comment records the first two conditions; this is the behavioural
// half.

// compileUnionPreflightSet compiles pats with the gated `find` AND the scan
// pair, which is the combination that makes the union automaton exist for the
// preflight to walk.
//
// wide selects which representation the automaton must have come out in, and it
// is an assertion rather than a request: the two are entirely different readers
// of the accept tables (a u64 pair against per-state bitmap rows), so a test
// that silently got the other one would be exercising code it is not named
// after. Which one a set lands in is decided by its id space alone.
func compileUnionPreflightSet(t *testing.T, pats []string) []byte {
	return compileUnionPreflightSetWidth(t, pats, false)
}

func compileUnionPreflightSetWidth(t *testing.T, pats []string, wide bool) []byte {
	t.Helper()
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name:     "s",
		Find:     "gated_find",
		ScanAny:  "cap_scan_any",
		ScanAll:  "cap_scan_all",
		Patterns: config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileDiag(
		config.BuildConfig{Regexps: entries, Sets: sets}, "")
	if err != nil {
		t.Fatalf("compile %v: %v", pats, err)
	}
	// The union automaton must have been BUILT and must be in the form this
	// test set out to drive. Without this the test could pass by never reaching
	// the code it is named after.
	if len(diags) != 1 || diags[0].UnionScan == nil || !diags[0].UnionScan.Used {
		t.Fatalf("no union automaton for %v: %+v", pats, diags)
	}
	if got := diags[0].UnionScan.Wide; got != wide {
		t.Fatalf("union automaton wide=%v for %d patterns, want wide=%v", got, len(pats), wide)
	}
	if wide && diags[0].UnionScan.MaskWords < 2 {
		t.Fatalf("wide union reports %d mask words; the walk would use one accumulator",
			diags[0].UnionScan.MaskWords)
	}
	return w
}

// runUnionPreflightFind drives the gated find to exhaustion from `from`,
// zeroing the gate array first — which is how a caller declares a fresh drive,
// and therefore the thing that arms the preflight.
func runUnionPreflightFind(t *testing.T, w []byte, pats []string, input string, from int32) []setMatch {
	t.Helper()
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
	for i := int32(0); i < int32(4*len(pats)); i++ {
		buf[gatePtr+i] = 0
	}
	// The scratch descriptor the export takes in place of the bare gate
	// pointer (internal/abi).
	scratchPtr := writeFindScratch(store, mem, gatePtr, int32(len(pats)), 0, 0)

	var out []setMatch
	pos := from
	outCap := int32(len(pats))
	for {
		res, err := fn.Call(store, inBase, int32(len(input)), pos, scratchPtr, outPtr, outCap)
		if err != nil {
			t.Fatalf("gated_find: %v", err)
		}
		n := int(res.(int32))
		if n <= 0 {
			break
		}
		buf := mem.UnsafeData(store)
		start := -1
		for i := 0; i < n; i++ {
			base := int(outPtr) + i*12
			rd := func(o int) int {
				return int(int32(uint32(buf[base+o]) | uint32(buf[base+o+1])<<8 |
					uint32(buf[base+o+2])<<16 | uint32(buf[base+o+3])<<24))
			}
			// docs/wasm.md "find tuple layout": +0 pattern_id, +4 start, +8 end.
			m := setMatch{PatternID: rd(0), Start: rd(4), End: rd(8)}
			out = append(out, m)
			start = m.Start
		}
		if start < 0 {
			break
		}
		pos = int32(start + 1)
		if pos > int32(len(input)) {
			break
		}
	}
	return out
}

func TestUnionAliveMaskPreflightMatchesGo(t *testing.T) {
	// Every pattern literal-less (so G12 declines) with a never-dying leading
	// `[^\n]*` (so the preflight is emitted at all).
	sets := [][]string{
		{`[^\n]*[0-2]`, `[^\n]*[3-5]`},
		{`[^\n]*[0-2]`, `[a-c]+`},
		{`[^\n]*[0-2]`, `[^\n]*[3-5]`, `[p-r]{2}`},
		// A NULLABLE member, which is alive only through the ENTRY-STATE arm
		// of the walk — the one that records what accepts at `from` before any
		// byte is consumed. It is a separate arm from the loop's, so
		// losing it is a separate bug, and without a pattern that can match
		// empty nothing here would notice.
		{`[^\n]*[0-2]`, `[0-9]*`},
		{`[^\n]*[0-2]`, `\A`},
		// NO never-dying member — shapes the preflight only reaches since
		// A later fix dropped hasNeverDyingState from its
		// eligibility. Every one of them is nullable, which is the axis that
		// broke: fix 2a's first draft marked ALIVE patterns with gate 1, and
		// while 1 is invisible to the pre-mask and to emitGateJump, the
		// write-time empty-extent rule in emitWriteMatchK is the stricter
		// `2s >= gate[k]` — so an empty match at s == 0 was dropped by every
		// one of these and by 24 corpus cases. The marker is gone; these pin
		// its absence.
		{`(?:.|(?:c?))`},
		{`(?:.|(?:c?))`, `^(?:(?:.|(?:c?)))$`},
		{`[a-c]*`, `[0-9]*`},
		{`(?:x|)`, `[p-r]{2}`},
	}
	inputs := []string{
		"",
		"1",
		"5",
		"xx1xx", // alive ONLY by a mid-string accept: an inverted guard
		"ab4cd", // leaves the mask empty here and drops every match
		"xx1yy4zz",
		"no digits at all",
		"qq pr rr 2",
		"aaa",
		"0123456789",
	}
	for si, pats := range sets {
		w := compileUnionPreflightSet(t, pats)
		for _, input := range inputs {
			t.Run(fmt.Sprintf("set%d/%q", si, input), func(t *testing.T) {
				// The gated contract IS Go's FindAllIndex per pattern,
				// computed independently of anything the emitter believes.
				var want []setMatch
				for k, p := range pats {
					for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
						want = append(want, setMatch{PatternID: k, Start: x[0], End: x[1]})
					}
				}
				got := runUnionPreflightFind(t, w, pats, input, 0)
				sortMatches(want)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%v on %q: want %d matches %v, got %d %v",
						pats, input, len(want), want, len(got), got)
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%v on %q: match %d = %+v, want %+v",
							pats, input, i, got[i], want[i])
					}
				}
			})
		}
	}
}

// TestUnionAliveMaskPreflightResumes drives every legal starting `from`.
//
// The preflight computes its verdict ONCE per drive, over `[from, len)` of the
// FIRST call, and that is sound only because the verdict over-approximates as
// `from` advances. A guard that makes it under-approximate breaks this at every
// resume point rather than only at zero, so starting everywhere is the cheapest
// way to widen the net.
func TestUnionAliveMaskPreflightResumes(t *testing.T) {
	pats := []string{`[^\n]*[0-2]`, `[^\n]*[3-5]`}
	w := compileUnionPreflightSet(t, pats)
	for _, input := range []string{"xx1xx", "ab4cd", "1a4b2c5", "none"} {
		for from := 0; from <= len(input); from++ {
			t.Run(fmt.Sprintf("%q/from=%d", input, from), func(t *testing.T) {
				var want []setMatch
				for k, p := range pats {
					re := regexp.MustCompile(p)
					for _, x := range re.FindAllStringIndex(input[from:], -1) {
						want = append(want, setMatch{
							PatternID: k, Start: x[0] + from, End: x[1] + from})
					}
				}
				got := runUnionPreflightFind(t, w, pats, input, int32(from))
				sortMatches(want)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%v on %q from %d: want %d %v, got %d %v",
						pats, input, from, len(want), want, len(got), got)
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%v on %q from %d: match %d = %+v, want %+v",
							pats, input, from, i, got[i], want[i])
					}
				}
			})
		}
	}
}

// --------------------------------------------------------------------------
// The WIDE alive walk.
//
// Above 64 ids the union automaton emits no u64 accept pair at all, so the
// preflight was refused outright and the set kept the per-position walk for the
// whole drive — the closing board's 0.20x row. The walk now reads the same
// per-state accept ROWS `scan_all` does, one i64 load per 64 ids, into that many
// accumulator locals.
//
// Three things can go wrong that the narrow suite cannot see, and all are
// silent in the direction that loses matches. All three were confirmed CAUGHT
// by mutating the emitter, which is the only evidence worth having here:
//
//   - the WORD index in the write-back. `alive[gid/64]` read as `alive[0]`
//     cross-links two patterns 64 apart, so one is retired on the other's
//     evidence.
//   - the ROW word offset in the walk. Every accumulator ORing the SAME word of
//     the accept row leaves word 1 holding word 0's bits.
//   - the early exit's coverage. Testing only word 0 lets the walk stop while
//     patterns in word 1 have not yet shown alive, and they are then retired.
//
// The BIT index is NOT on that list, and the reason is worth recording so it is
// not "fixed" back into a hazard: shifting by the global id rather than by
// `gid % 64` is the same instruction, because WASM takes an `i64.shr_u` count
// modulo 64. That mutation survives the whole suite. `gid % 64` is written out
// anyway, since a reader should not have to know that rule to see the code is
// right.
//
// `[0-9]{k}` for k = 1..N is the shape that catches the three: under a run of m
// digits, patterns 1..m match and m+1..N match nowhere, so sweeping m across the
// 63/64 boundary puts the alive/dead frontier on either side of the word edge
// and on it.

// digitRunWideSet is N patterns whose aliveness a single digit run decides,
// plus a nullable member at a wide id. Literal-less throughout, so G12's
// absence prefilter declines and the union walk is what computes the verdict —
// which it must, since that prefilter is capped at 64 ids and could not serve
// this set anyway.
func digitRunWideSet(n int) []string {
	pats := make([]string, n)
	for i := range pats {
		pats[i] = fmt.Sprintf(`[0-9]{%d}`, i+1)
	}
	// A nullable pattern above the word edge. Fix 2a's refused first draft
	// marked ALIVE patterns with gate 1, which emitWriteMatchK's empty-extent
	// rule reads as "no empty match at 0"; this is that trap at a wide id.
	pats[n-1] = `[a-c]*`
	return pats
}

func TestWideUnionAliveMaskPreflightMatchesGo(t *testing.T) {
	const n = 70
	pats := digitRunWideSet(n)
	w := compileUnionPreflightSetWidth(t, pats, true)

	inputs := []string{
		"",
		"5",
		"abc",
		// Runs that put the alive/dead frontier just below, on, and just above
		// the 63/64 word edge. Pattern k is alive iff the run is at least k+1
		// long, so these decide ids 61..66 one at a time.
		strings.Repeat("7", 62),
		strings.Repeat("7", 63),
		strings.Repeat("7", 64),
		strings.Repeat("7", 65),
		strings.Repeat("7", 66),
		// Every pattern alive: the fullMask early exit must fire on the LAST
		// word too, not on the first one alone.
		strings.Repeat("7", n+4),
		// Digits present but never enough for the wide ids — the case the
		// preflight exists to retire, with survivors in word 0 only.
		"12 34 56 78",
		"a1b22c333d",
		strings.Repeat("9", 40) + "x" + strings.Repeat("9", 30),
	}
	for _, input := range inputs {
		t.Run(fmt.Sprintf("len=%d", len(input)), func(t *testing.T) {
			var want []setMatch
			for k, p := range pats {
				for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
					want = append(want, setMatch{PatternID: k, Start: x[0], End: x[1]})
				}
			}
			got := runUnionPreflightFind(t, w, pats, input, 0)
			sortMatches(want)
			sortMatches(got)
			if len(want) != len(got) {
				t.Fatalf("%q: want %d matches, got %d", input, len(want), len(got))
			}
			for i := range want {
				if want[i] != got[i] {
					t.Fatalf("%q: match %d = %+v, want %+v", input, i, got[i], want[i])
				}
			}
		})
	}
}

// TestWideUnionAliveMaskPreflightResumes is the wide twin of the narrow resume
// test: the verdict is computed once, over [from, len) of the first call, and
// stays sound only because it over-approximates as `from` advances.
func TestWideUnionAliveMaskPreflightResumes(t *testing.T) {
	const n = 66
	pats := digitRunWideSet(n)
	w := compileUnionPreflightSetWidth(t, pats, true)
	for _, input := range []string{
		"ab" + strings.Repeat("3", 64) + "cd",
		strings.Repeat("1", 65),
		"12a345b",
	} {
		for from := 0; from <= len(input); from += 7 {
			t.Run(fmt.Sprintf("len=%d/from=%d", len(input), from), func(t *testing.T) {
				var want []setMatch
				for k, p := range pats {
					for _, x := range regexp.MustCompile(p).FindAllStringIndex(input[from:], -1) {
						want = append(want, setMatch{
							PatternID: k, Start: x[0] + from, End: x[1] + from})
					}
				}
				got := runUnionPreflightFind(t, w, pats, input, int32(from))
				sortMatches(want)
				sortMatches(got)
				if len(want) != len(got) {
					t.Fatalf("%q from %d: want %d, got %d", input, from, len(want), len(got))
				}
				for i := range want {
					if want[i] != got[i] {
						t.Fatalf("%q from %d: match %d = %+v, want %+v",
							input, from, i, got[i], want[i])
					}
				}
			})
		}
	}
}

// TestWideUnionPreflightFindOnly pins the OTHER half of the fix: a wide set
// exporting `find` and nothing else.
//
// Such a set asks for no scan capability, so before this change no union
// automaton was built for it at all and the accept rows — emitted only for
// `scan_all` — did not exist either. Both are now requested by the preflight
// itself. A regression that restores either condition leaves this set silently
// on the per-position walk, which is slower but still CORRECT, so the assertion
// that the automaton was built is the load-bearing half of this test and the
// answer check is the guard on it.
func TestWideUnionPreflightFindOnly(t *testing.T) {
	const n = 70
	pats := digitRunWideSet(n)
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	sets := []config.SetConfig{{
		Name: "s", Find: "gated_find", Patterns: config.PatternSelector{Names: names},
	}}
	w, _, diags, err := compile.CompileFileDiag(
		config.BuildConfig{Regexps: entries, Sets: sets}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(diags) != 1 || diags[0].UnionScan == nil || !diags[0].UnionScan.Used {
		t.Fatalf("a find-only wide set got no union automaton, so its preflight is dormant: %+v", diags)
	}
	if !diags[0].UnionScan.Wide {
		t.Fatalf("union automaton is narrow for %d patterns", len(pats))
	}
	for _, input := range []string{"", "abc", strings.Repeat("4", 65), "12 345"} {
		var want []setMatch
		for k, p := range pats {
			for _, x := range regexp.MustCompile(p).FindAllStringIndex(input, -1) {
				want = append(want, setMatch{PatternID: k, Start: x[0], End: x[1]})
			}
		}
		got := runUnionPreflightFind(t, w, pats, input, 0)
		sortMatches(want)
		sortMatches(got)
		if len(want) != len(got) {
			t.Fatalf("%q: want %d matches, got %d", input, len(want), len(got))
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("%q: match %d = %+v, want %+v", input, i, got[i], want[i])
			}
		}
	}
}

// Coverage from the PREV-STATE SKIP episode (an optimisation refuted on fuel
// option B — BUILT AND REVERTED 2026-08-28).
//
// The skip made the mid-accept recording conditional on `state != lastOr` and
// was refuted by measurement: the union automaton's parity copies mean a
// saturated run ALTERNATES between two accepting states, so the skip never
// fired and cost +20.9% on its own target row. The code is gone; these tests
// stay, because the shapes were chosen to break any conditional-recording
// change to the union scan's accept arms and none of them existed before:
//
//   - nullable-entry: the ENTRY state's accepts, recorded before any byte is
//     consumed — and after the mid-accept-first renumbering that state can be
//     state 0, which is what a zero-initialised bookkeeping local would alias.
//   - eof-differs: members whose mid-string and end-of-input accept sets
//     differ, so an optimisation of the mid arm wrongly applied to the EOF arm
//     loses `\z`-anchored accepts.
//   - saturated-run / alternating-accepts: the two shapes a per-byte
//     optimisation confuses — one state repeated, and two states alternating,
//     which the union automaton makes of a run of identical bytes.
//
// TestUnionScanSaturatedRunCost is the FUEL pin on the saturated shape, the
// only guard that can see a change which answers correctly at a different
// per-byte cost — in either direction.
//
// Every case asserts through --diag-json that a union automaton served the
// scan pair, and at which width, before it asserts anything else: these bodies
// are reached only by literal-less sets, and one stray mandatory literal routes
// the whole fixture to the bucket walk while still passing.

// prevStateShapes are the four families described above. Each is literal-less,
// which is what keeps the set on the union path at all.
var prevStateShapes = []struct {
	name string
	pats []string
	ins  []string
}{
	{
		// NULLABLE: `[0-9]*` matches empty at every position, so the ENTRY
		// state accepts before a byte is consumed. On an input with no digit
		// p0's empty match is the whole answer, so losing that one recording
		// loses everything — and after the mid-accept-first renumbering the
		// entry state can be state 0, the value a zero-initialised local
		// would alias.
		name: "nullable-entry",
		pats: []string{`[0-9]*`, `[a-c]{2}`},
		ins:  []string{"", "x", "xyz", "abz", "q1q", "aab", "zzzz", "1"},
	},
	{
		// EOF DIFFERS FROM MID: after "abc" the state records p0 mid-string
		// and p0+p1 at end of input. The mid arm runs first on the same state,
		// so mid-arm bookkeeping wrongly applied to the EOF arm drops p1 —
		// while every input NOT ending in the class still passes.
		name: "eof-differs",
		pats: []string{`[a-c]+`, `[a-c]+\z`, `[0-9]$`},
		ins:  []string{"", "a", "abc", "xabc", "abcx", "abc7", "7", "x7", "cba"},
	},
	{
		// SATURATED: `[a-c]+` accepts on every byte of a run — the shape that
		// tempts a conditional-recording change in the first place.
		// Interleaved with bytes that leave the run, so per-drive bookkeeping
		// would have to re-establish itself mid-input rather than only at
		// entry.
		name: "saturated-run",
		pats: []string{`[a-c]+`, `[0-9]{2}`},
		ins: []string{
			"aaaaaaaaaaaaaaaa",
			"aaaa11aaaa",
			"abcabcabcabc",
			"aaaa bbbb cccc",
			strings.Repeat("a", 300),
			strings.Repeat("ab", 150) + "99",
		},
	},
	{
		// ALTERNATING: two DIFFERENT accepting states in succession, and both
		// recordings must happen. This is also what the union automaton's
		// parity copies make of a plain run — the fact that refuted option B —
		// so anything keyed on "the previous byte's state" is exercised here
		// on the shape that actually occurs.
		name: "alternating-accepts",
		pats: []string{`[a-c]`, `[0-9]`, `[a-c][0-9]`},
		ins:  []string{"a1a1a1a1", "1a1a1a1a", "a1", "1a", "abc123", "a1b2c3"},
	},
}

// TestUnionScanAcceptArmsMatchGo drives the four shapes through the NARROW
// scan pair (the i64-accumulator body) against Go.
func TestUnionScanAcceptArmsMatchGo(t *testing.T) {
	for _, sh := range prevStateShapes {
		w, diags := wideUnionSet(t, sh.pats, nil, false)
		assertUnionScan(t, diags, false)
		dropped := droppedFromSet(diags)

		for _, input := range sh.ins {
			t.Run(fmt.Sprintf("%s/%d", sh.name, len(input)), func(t *testing.T) {
				r := newWideRunner(t, w, input, len(sh.pats))
				defer r.Close()
				n := int32(len(input))

				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(sh.pats, input, from, dropped)
					f := int32(from)

					gotAny := r.call(t, "cap_scan_any", r.inBase, n, f).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1 on %q",
								from, gotAny, input)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v on %q",
							from, gotAny, want, input)
					}

					got := idsFromMask(
						uint64(r.call(t, "cap_scan_all", r.inBase, n, f).(int64)),
						len(sh.pats))
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						t.Fatalf("scan_all(from=%d) = %v, want %v on %q",
							from, got, want, input)
					}
				}
			})
		}
	}
}

// TestUnionScanAcceptArmsWide is the same four shapes above 64 ids, where the
// recording is an OR of a bitmap ROW into caller memory plus a popcnt of what
// flipped — so the returned count and the bitmap can drift apart separately,
// and the count is asserted, not just the bitmap.
func TestUnionScanAcceptArmsWide(t *testing.T) {
	for _, sh := range prevStateShapes {
		// Pad to 70 ids with literal-less filler that cannot itself match the
		// shape's inputs, so the shape's own patterns still decide the answer.
		pats := append([]string(nil), sh.pats...)
		for len(pats) < 70 {
			pats = append(pats, fmt.Sprintf(`[p-r]{%d}[5-9]{%d}`,
				1+len(pats)%7, 1+len(pats)/7%5))
		}
		w, diags := wideUnionSet(t, pats, nil, false)
		assertUnionScan(t, diags, true)
		dropped := droppedFromSet(diags)

		for _, input := range sh.ins {
			t.Run(fmt.Sprintf("%s/%d", sh.name, len(input)), func(t *testing.T) {
				r := newWideRunner(t, w, input, len(pats))
				defer r.Close()
				n := int32(len(input))

				for from := 0; from <= len(input); from++ {
					want := oracleScanAll(pats, input, from, dropped)
					f := int32(from)

					gotAny := r.call(t, "cap_scan_any", r.inBase, n, f).(int32)
					if len(want) == 0 {
						if gotAny != -1 {
							t.Fatalf("scan_any(from=%d) = %d, want -1 on %q",
								from, gotAny, input)
						}
					} else if !containsInt(want, int(gotAny)) {
						t.Fatalf("scan_any(from=%d) = %d, not among %v on %q",
							from, gotAny, want, input)
					}

					r.clear()
					count := int(r.call(t, "cap_scan_all",
						r.inBase, n, f, r.outPtr).(int32))
					r.checkCanary(t, "scan_all")
					got := r.bitmapIDs()
					if !eqIDs(append([]int(nil), want...), append([]int(nil), got...)) {
						t.Fatalf("scan_all(from=%d) = %v, want %v on %q",
							from, got, want, input)
					}
					if count != len(want) {
						t.Fatalf("scan_all(from=%d) count = %d, want %d on %q: "+
							"a count that drifts from the bitmap means a "+
							"recording was skipped or double-counted where it "+
							"could still have contributed",
							from, count, len(want), input)
					}
				}
			})
		}
	}
}

// TestUnionScanSaturatedRunCost measures the union scan on a long run that
// keeps the automaton in ACCEPTING states — greedy-3 / 50K a's in miniature,
// the row that episode was about.
//
// It exists as a COST guard because that row has now moved twice on emitter
// changes that no oracle could see, and because measuring it here is what
// refuted the prev-state skip's premise. The skip assumed a saturated run sits
// in ONE accepting state. It does not: the start-anywhere subset construction
// emits PARITY COPIES — greedy-3 steps 0 -> 4 -> 0 -> 4 on a run of a's, both
// accepting — so the state differs on every byte, the skip never fires, and its
// test plus update are pure cost. Measured on greedy-3 / 50K a's / `scan_all`:
// 28.75 fuel/byte without the skip, 34.75 with it.
//
// The bound is a ceiling over both, so this test states the cost rather than
// taking a side on that decision; it fails only on drift far beyond either.
func TestUnionScanSaturatedRunCost(t *testing.T) {
	pats := []string{`[a-c]+`, `[0-9]{2}`}
	w, diags := wideUnionSet(t, pats, nil, false)
	assertUnionScan(t, diags, false)

	const n = 20000
	input := strings.Repeat("a", n)

	// A fuel-metered engine of its own: the shared one is not metered, and
	// turning metering on there would tax every other test in the package.
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetWasmSIMD(true)
	cfg.SetWasmBulkMemory(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	defer engine.Close()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("compile module: %v", err)
	}
	defer mod.Close()
	store := wasmtime.NewStore(engine)
	defer store.Close()
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	mem := inst.GetExport(store, "memory").Memory()

	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(w)
	if err != nil {
		t.Fatalf("parse data section: %v", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	needed := uint64((int64(inBase) + n + 2*pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			t.Fatalf("grow: %v", err)
		}
	}
	copy(mem.UnsafeData(store)[inBase:], input)

	// scan_all rather than scan_any: scan_any returns at the first accepting
	// state and never reaches the run at all.
	fn := inst.GetFunc(store, "cap_scan_all")
	if fn == nil {
		t.Fatal("module missing cap_scan_all export")
	}
	if err := store.SetFuel(1 << 40); err != nil {
		t.Fatalf("set fuel: %v", err)
	}
	before, err := store.GetFuel()
	if err != nil {
		t.Fatalf("get fuel: %v", err)
	}
	if _, err := fn.Call(store, inBase, int32(n), int32(0)); err != nil {
		t.Fatalf("cap_scan_all: %v", err)
	}
	after, err := store.GetFuel()
	if err != nil {
		t.Fatalf("get fuel: %v", err)
	}
	perByte := float64(before-after) / float64(n)

	// Measured 2026-08-28 on this fixture: 28.75 fuel/byte without the
	// prev-state skip, 34.75 with it. 45 clears both with margin.
	const bound = 45.0
	if perByte > bound {
		t.Fatalf("saturated scan_all costs %.2f fuel/byte, over the %.1f bound. "+
			"A run of bytes inside accepting states is the union scan's worst "+
			"shape and the one the refuted skip targeted; a cost this "+
			"far above either recorded figure means the per-byte arm grew.",
			perByte, bound)
	}
	t.Logf("saturated scan_all: %.2f fuel/byte over %d bytes", perByte, n)
}
