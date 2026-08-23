package main

// Task G15: drive EVERY set capability over the corpus.
//
// Before this file, --sets declared one set with `find` OR `find_batch`,
// `patterns: all` and no `overlapping`, so six of the eight capabilities plus a
// whole `find` body had no corpus coverage at all — which is how five
// wrong-answer/crash bugs survived
// 4.94M passing cases.
//
// Everything here computes its expectation from Go `regexp` live, via §9.6's
// whole-input technique, so no oracle restates an emitter rule back at it.
// Where the corpus carries a col4 column the two
// are CROSS-CHECKED against each other rather than one replacing the other.
//
// It found two more on its first runs, in configurations that had never been
// driven at all: overlapping `find_batch` above capacity 1 dropped a tuple
// per call, and `scan`/`scan_all` ignored `from > len`.
//
// Four axes decide what a run covers, and each exists because the corpus alone
// cannot supply it — see the options below: --set-chunk (set SIZE, since the
// corpus has 27 blocks of 132..7020 patterns), --set-shuffle (set MEMBERSHIP),
// --set-subset (a NAMED subset, the only way PATTERN_COUNT and ID_SPACE
// differ), and --set-profiles (which capabilities the module DECLARES, since
// the compiler emits only what the declared ones need).

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v42"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// ---------------------------------------------------------------------------
// Options (package-level, assigned once from main; see setBatchDrive's comment
// for why the set-mode switches are not threaded through run()'s signature).

var (
	// setChunkSize splits a corpus block's patterns into consecutive sets of
	// this many patterns. 0 = one set per block, which is what --sets always
	// did: the RE2 corpus has 27 blocks of 132..7020 patterns each, so without
	// chunking every set is enormous and the frontend/id-space thresholds the
	// compiler specialises on (packed-pair <=16, Teddy <=64, AC >16, wide
	// `_all` >64) are never crossed from below.
	setChunkSize int

	// setShufflePats permutes a block's patterns before chunking. Adjacent
	// corpus patterns are near-duplicates from the same generator family, so
	// unshuffled chunks hold variations of one shape; shuffling manufactures
	// the pattern INTERACTION §22.0 says the corpus cannot otherwise produce.
	// Deterministic: a fixed-seed LCG, so a failure is reproducible.
	setShufflePats bool

	// setSample tests every Nth chunk (1 = every chunk). This is the knob that
	// separates the sampled `make sets` gate from `make sets-exhaustive`.
	setSample = 1

	// setBatchCap1Only restricts find_batch drives to a capacity of ONE.
	setBatchCap1Only bool

	// setSubset makes each set select a NAMED SUBSET of the chunk's patterns
	// (every second one, starting at index 1) instead of `patterns: all`.
	//
	// This is the only configuration in which <SET>_PATTERN_COUNT and
	// <SET>_ID_SPACE differ, and confusing them is a memory-safety bug rather
	// than a wrong answer: pattern_id is the GLOBAL index into `regexps:`, so
	// the gate array and the `_all` bitmap are sized from the id space while
	// the tuple buffer is sized from the pattern count. Sizing the gate array
	// from the count let the module write past the caller's array, and
	// `patterns: all` makes the two equal, so no run that used it
	// could ever have caught that.
	//
	// Starting at index 1 is deliberate: it leaves id 0 unselected, so the ids
	// are sparse from the very first slot and an off-by-one that happens to
	// work for a dense prefix does not survive.
	setSubset bool

	// activeSetProfiles is the resolved --set-profiles selection.
	activeSetProfiles []setProfile
)

// ---------------------------------------------------------------------------
// Capability profiles.
//
// A profile is a whole MODULE: one or more sets, each declaring a subset of
// the eight capabilities. Two things make more than one profile necessary:
//
//   - `overlapping` is a per-set property, so the gated and ungated `find`
//     bodies can only be driven together by declaring two sets; and
//   - the compiler emits only the machinery a set's declared capabilities need
//     (docs/sets.md "What each capability costs"), so a set declaring
//     everything never exercises the specialised emissions — a `match`-only
//     set emits no literal frontend at all, and a `scan`-only set emits no
//     tuple-writing suffix function.

type setCapMask struct {
	setName                   string
	match, matchAny, matchAll bool
	scan, scanAny, scanAll    bool
	find, findBatch           bool
	overlapping               bool
}

type setProfile struct {
	name  string
	specs []setCapMask
}

var setProfileTable = []setProfile{
	// Everything, in one module: a gated set declaring all eight capabilities
	// plus an overlapping set for the other `find`/`find_batch` bodies. This
	// is the default, and its gated-find leg is the run §22.5 requires to keep
	// passing unchanged.
	{"all", []setCapMask{
		{setName: "g", match: true, matchAny: true, matchAll: true,
			scan: true, scanAny: true, scanAll: true, find: true, findBatch: true},
		{setName: "o", find: true, findBatch: true, overlapping: true},
	}},
	// The specialisations. Each drops everything but one family, so the
	// emitter takes the path it only takes when the rest is absent.
	{"anchored", []setCapMask{{setName: "g", match: true, matchAny: true, matchAll: true}}},
	{"scan", []setCapMask{{setName: "g", scan: true, scanAny: true, scanAll: true}}},
	// §3.9: `scan_any` without `find` is its own structural specialisation —
	// it keeps the first-hit-exit probes but none of the extent machinery.
	{"scan-any", []setCapMask{{setName: "g", scanAny: true}}},
	{"find", []setCapMask{{setName: "g", find: true}}},
	{"find-ov", []setCapMask{{setName: "o", find: true, overlapping: true}}},
	{"batch", []setCapMask{{setName: "g", findBatch: true}}},
	{"batch-ov", []setCapMask{{setName: "o", findBatch: true, overlapping: true}}},
}

func lookupSetProfile(name string) (setProfile, bool) {
	for _, p := range setProfileTable {
		if p.name == name {
			return p, true
		}
	}
	return setProfile{}, false
}

func setProfileNamesAll() []string {
	out := make([]string, 0, len(setProfileTable))
	for _, p := range setProfileTable {
		out = append(out, p.name)
	}
	return out
}

// resolveSetProfiles turns the --set-profiles value into profiles.
func resolveSetProfiles(spec string) ([]setProfile, error) {
	if spec == "all-profiles" {
		spec = strings.Join(setProfileNamesAll(), ",")
	}
	var out []setProfile
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		p, ok := lookupSetProfile(name)
		if !ok {
			return nil, fmt.Errorf("unknown set profile %q (known: %s, all-profiles)",
				name, strings.Join(setProfileNamesAll(), ", "))
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--set-profiles selected nothing")
	}
	return out, nil
}

// needs reports what the profile asks of the oracle, so a chunk never pays for
// an expectation nothing compares against. The start-position map is the
// expensive one — it is O(len) Go probe evaluations per (pattern, string).
func (p setProfile) needs() (anchored, spm, findAll bool) {
	for _, s := range p.specs {
		anchored = anchored || s.match || s.matchAny || s.matchAll
		if s.overlapping {
			spm = spm || s.find || s.findBatch
		} else {
			findAll = findAll || s.find || s.findBatch
		}
		spm = spm || s.scan || s.scanAny || s.scanAll
	}
	return
}

// ---------------------------------------------------------------------------
// Statistics.

// setCapStats accumulates per-capability results across the whole run. The
// capability label is the key, so the summary names exactly what was driven
// and a capability that silently never ran shows up as an absent row rather
// than as a green tick.
type setCapStats struct {
	pass     map[string]int
	fail     map[string]int
	order    []string
	timeouts int
	dataErrs int
	chunks   int
	skipped  int // chunks skipped by --sample
	dropped  int // pattern/capability pairs the compiler legitimately excluded
	printed  int // failure reports emitted so far
}

var setStats = setCapStats{pass: map[string]int{}, fail: map[string]int{}}

func (s *setCapStats) note(label string) {
	if _, seen := s.pass[label]; !seen {
		if _, seen2 := s.fail[label]; !seen2 {
			s.order = append(s.order, label)
		}
	}
}

func (s *setCapStats) ok(label string, n int) {
	s.note(label)
	s.pass[label] += n
}

func (s *setCapStats) bad(label string, n int) {
	s.note(label)
	s.fail[label] += n
}

// report prints the per-capability table. setMaxPrint caps the number of
// individual FAIL lines, never the counts.
func (s *setCapStats) report() {
	fmt.Printf("\n=== Set capability coverage ===\n")
	fmt.Printf("chunks compiled: %d", s.chunks)
	if s.skipped > 0 {
		fmt.Printf("  (skipped by --sample: %d)", s.skipped)
	}
	fmt.Println()
	total, totalFail := 0, 0
	for _, label := range s.order {
		p, f := s.pass[label], s.fail[label]
		total += p
		totalFail += f
		flag := ""
		if f > 0 {
			flag = "   <-- FAILURES"
		}
		fmt.Printf("  %-28s pass %10d  fail %6d%s\n", label+":", p, f, flag)
	}
	fmt.Printf("  %-28s pass %10d  fail %6d\n", "TOTAL:", total, totalFail)
	if s.timeouts > 0 {
		fmt.Printf("  timeouts (input skipped):    %d\n", s.timeouts)
	}
	if s.dataErrs > 0 {
		fmt.Printf("  col4/Go disagreements:       %d\n", s.dataErrs)
	}
	if s.dropped > 0 {
		// Documented behaviour, not a failure — but it means those patterns
		// were NOT checked, so it must be visible rather than inferred from a
		// count that quietly does not move.
		fmt.Printf("  patterns dropped by compiler (state limit, excluded from comparison): %d\n", s.dropped)
	}
}

// totalFail is every capability failure, so the process exit status reflects
// all eight capabilities and not only the gated-find leg.
func (s *setCapStats) totalFail() int {
	n := 0
	for _, v := range s.fail {
		n += v
	}
	return n
}

// totalPass mirrors totalFail. run()'s own counter is derived from these two
// rather than kept in parallel: a second counter that only some profiles
// incremented reported 0 for a run whose table showed 4.9M passing checks.
func (s *setCapStats) totalPass() int {
	n := 0
	for _, v := range s.pass {
		n += v
	}
	return n
}

// setMaxPrint bounds the FAIL lines printed; 0 = unlimited. Assigned from
// --max-errors so a chunk that fails on every one of 7020 patterns cannot bury
// the first, most informative report under megabytes of output.
var setMaxPrint int

func setFailf(format string, args ...interface{}) {
	if setMaxPrint > 0 && setStats.printed >= setMaxPrint {
		return
	}
	setStats.printed++
	fmt.Printf(format, args...)
	if setMaxPrint > 0 && setStats.printed == setMaxPrint {
		fmt.Printf("... further set failure reports suppressed (--max-errors=%d); counts continue\n", setMaxPrint)
	}
}

// ---------------------------------------------------------------------------
// Oracles.

// setOracle holds every expectation a profile can need, indexed [pattern][string].
type setOracle struct {
	anchored [][]bool     // \A(?:p)\z over the whole input
	spm      [][][][2]int // every start position at which p matches, with its extent
	// findAllByStr is Go FindAllStringIndex per [pattern][string] — the gated
	// `find` oracle (§9.6.1), and the column the corpus's col4 is checked
	// against rather than replaced by.
	findAllByStr [][][][2]int
}

// buildSetOracle computes the expectations for one chunk.
//
// The start-position map uses §9.6's whole-input technique: `\A(?s:.{p})(?:pat)`
// over the WHOLE input hands `pat` position p with its real left context, so
// `\b`, `\B` and `(?m:^)` judge actual neighbours. The slice technique it
// replaces (`\A(?:pat)` over input[p:]) judges them against a slice boundary —
// which is FABLE B42's mistake, and §22.4's explicit warning.
//
// `.{p}` counts RUNES, so the caller must have excluded non-ASCII inputs.
func buildSetOracle(pats []string, strs []string, needAnchored, needSPM, needFindAll bool) (*setOracle, error) {
	o := &setOracle{}
	if needAnchored {
		o.anchored = make([][]bool, len(pats))
	}
	if needSPM {
		o.spm = make([][][][2]int, len(pats))
	}
	if needFindAll {
		o.findAllByStr = make([][][][2]int, len(pats))
	}
	// Non-ASCII inputs are left with EMPTY expectations, deliberately.
	//
	// The whole-input probe counts RUNES in its `.{p}` prefix, so on a
	// multi-byte input position p would not be the byte offset the module was
	// given and every expectation would be quietly wrong. The drive loop skips
	// these inputs (as the rest of re2test does), so nothing reads these rows —
	// but computing a wrong answer and relying on nobody looking at it is how a
	// harness bug becomes an engine bug report.
	usable := make([]bool, len(strs))
	maxLen := 0
	for si, s := range strs {
		usable[si] = !hasUnicode(s)
		if usable[si] && len(s) > maxLen {
			maxLen = len(s)
		}
	}
	for pi, pat := range pats {
		body, err := normalizeSetOraclePattern(pat)
		if err != nil {
			return nil, fmt.Errorf("oracle: pattern %q: %w", pat, err)
		}
		if needAnchored {
			anch, err := regexp.Compile(`\A(?:` + body + `)\z`)
			if err != nil {
				return nil, fmt.Errorf("oracle: anchored probe for %q: %w", pat, err)
			}
			row := make([]bool, len(strs))
			for si, s := range strs {
				row[si] = usable[si] && anch.MatchString(s)
			}
			o.anchored[pi] = row
		}
		if needFindAll {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("oracle: %q: %w", pat, err)
			}
			row := make([][][2]int, len(strs))
			for si, s := range strs {
				if !usable[si] {
					continue
				}
				for _, m := range re.FindAllStringIndex(s, -1) {
					row[si] = append(row[si], [2]int{m[0], m[1]})
				}
			}
			o.findAllByStr[pi] = row
		}
		if needSPM {
			// One probe per position, built once and reused for every string
			// long enough to have that position. Without the reuse the map is
			// rebuilt per string and the cost is quadratic for no reason.
			probes := make([]*regexp.Regexp, maxLen+1)
			row := make([][][2]int, len(strs))
			for si, s := range strs {
				if !usable[si] {
					continue
				}
				for p := 0; p <= len(s); p++ {
					if probes[p] == nil {
						pr, err := regexp.Compile(`\A` + setDotPrefix(p) + `(?:` + body + `)`)
						if err != nil {
							// Never fall through to "no matches": a broken
							// probe would read as the engine over-reporting.
							return nil, fmt.Errorf("oracle: position-%d probe for %q: %w", p, pat, err)
						}
						probes[p] = pr
					}
					if m := probes[p].FindStringIndex(s); m != nil {
						row[si] = append(row[si], [2]int{p, m[1]})
					}
				}
			}
			o.spm[pi] = row
		}
	}
	return o, nil
}

// normalizeSetOraclePattern re-serialises a pattern through regexp/syntax
// before it is embedded in a wrapper like `\A(?:pat)\z`.
//
// The raw source may contain `\Q`, which quotes everything after it —
// including the wrapper's own closing paren — and would silently build a
// DIFFERENT regexp, then blame the engine for the difference.
func normalizeSetOraclePattern(pat string) (string, error) {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// setDotPrefix builds a regexp matching exactly p runes of anything.
//
// `(?s:.{p})` hits regexp/syntax's maxRepeat ceiling of 1000, and NESTING
// repeats does not lift it (Go rejects on the product). Concatenation has no
// such limit — each term is independently under the ceiling.
func setDotPrefix(p int) string {
	q, r := p/1000, p%1000
	out := "(?s:"
	for i := 0; i < q; i++ {
		out += ".{1000}"
	}
	if r > 0 {
		out += ".{" + strconv.Itoa(r) + "}"
	}
	return out + ")"
}

// anchoredIDs returns the ids matching the whole of strs[si].
func (o *setOracle) anchoredIDs(si int) []int {
	var out []int
	for pi := range o.anchored {
		if o.anchored[pi][si] {
			out = append(out, pi)
		}
	}
	return out
}

// scanAllIDs returns the ids matching at some position >= from. `eligible`
// excludes patterns the compiler dropped, which report nothing by design.
func (o *setOracle) scanAllIDs(si, from int, eligible func(int) bool) []int {
	var out []int
	for pi := range o.spm {
		if !eligible(pi) {
			continue
		}
		for _, sp := range o.spm[pi][si] {
			if sp[0] >= from {
				out = append(out, pi)
				break
			}
		}
	}
	return out
}

// firstPosition returns the smallest start >= from at which anything matches,
// with the ids matching exactly there. Returns -1 when nothing matches.
func (o *setOracle) firstPosition(si, from int, eligible func(int) bool) (int, []int) {
	best := -1
	for pi := range o.spm {
		if !eligible(pi) {
			continue
		}
		for _, sp := range o.spm[pi][si] {
			if sp[0] >= from && (best == -1 || sp[0] < best) {
				best = sp[0]
				break
			}
		}
	}
	if best == -1 {
		return -1, nil
	}
	var ids []int
	for pi := range o.spm {
		if !eligible(pi) {
			continue
		}
		for _, sp := range o.spm[pi][si] {
			if sp[0] == best {
				ids = append(ids, pi)
				break
			}
		}
	}
	return best, ids
}

// overlappingSpans returns every (start, end) pattern pi reports under
// `overlapping: true` — one per start position at which it matches.
func (o *setOracle) overlappingSpans(pi, si int) [][2]int {
	return o.spm[pi][si]
}

// ---------------------------------------------------------------------------
// The chunk runner.

// setChunk is one compiled set: a slice of a block's eligible patterns.
type setChunk struct {
	pats []string // the patterns, in set order (= pattern id order)
	orig []int    // index into the block's entries, for failure messages
	cols [][]string
}

// setRunner is an instantiated profile module plus its memory layout.
type setRunner struct {
	store   *wasmtime.Store
	inst    *wasmtime.Instance
	mem     *wasmtime.Memory
	wd      *watchdog
	release func()

	inBase  int32
	outBase int32
	gatePtr int32
	bmpPtr  int32
	npat    int    // patterns IN THE SET — sizes the tuple buffer and the cursor's k
	idSpace int    // largest reportable global id + 1 — sizes gates and bitmaps
	inSet   []bool // by chunk index: is this pattern a member of the set?
	outCap  int32  // = npat: the exact worst case for one position (§3.11)
	bmpLen  int32
	wide    bool // idSpace > 64: the `_all` capabilities take an out_ptr

	// Patterns this compile excluded; see the dropHandler comment.
	droppedFind     map[int]bool
	droppedAnchored map[int]bool
}

// findEligible reports whether pattern pi can appear in a non-anchored answer:
// it must be a member of the set and not have been dropped by the compiler.
// A pattern that is a member and IS expected to match still counts against the
// engine if it goes missing, and one that is NOT a member must never appear —
// compareSetMatches checks that direction too.
func (r *setRunner) findEligible(pi int) bool { return r.inSet[pi] && !r.droppedFind[pi] }

// anchoredEligible reports whether pattern pi can appear in an anchored answer.
// A fallback-bucket drop removes it from every capability, so both maps count.
func (r *setRunner) anchoredEligible(pi int) bool {
	return r.inSet[pi] && !r.droppedFind[pi] && !r.droppedAnchored[pi]
}

// keepIDs filters an oracle id list down to the patterns the module kept.
func keepIDs(ids []int, eligible func(int) bool) []int {
	out := ids[:0:0]
	for _, id := range ids {
		if eligible(id) {
			out = append(out, id)
		}
	}
	return out
}

func (r *setRunner) fn(name string) *wasmtime.Func { return r.inst.GetFunc(r.store, name) }

// call invokes an export under the watchdog. hang=true means the 2s epoch
// deadline fired; the caller abandons the current input.
func (r *setRunner) call(fn *wasmtime.Func, args ...interface{}) (interface{}, bool, error) {
	r.wd.Arm(r.store)
	res, err := fn.Call(r.store, args...)
	r.wd.Disarm()
	if err != nil {
		if isTimeout(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return res, false, nil
}

func (r *setRunner) buf() []byte { return r.mem.UnsafeData(r.store) }

// zeroGates restores the all-zero gate array that means "a clean scan".
func (r *setRunner) zeroGates() {
	b := r.buf()
	// Sized from the ID SPACE, not the pattern count: the array is indexed by
	// global pattern id.
	for i := int32(0); i < int32(r.idSpace)*4; i++ {
		b[r.gatePtr+i] = 0
	}
}

// zeroBitmap clears the wide `_all` output. The module only ORs bits in and
// counts 0->1 transitions, so a dirty buffer reports stale patterns.
func (r *setRunner) zeroBitmap() {
	b := r.buf()
	for i := int32(0); i < r.bmpLen; i++ {
		b[r.bmpPtr+i] = 0
	}
}

func (r *setRunner) readTuple(i int32) (pid, st, en int32) {
	b := r.buf()
	base := int(r.outBase) + int(i)*setOutTupleBytes
	rd := func(off int) int32 {
		return int32(b[base+off]) | int32(b[base+off+1])<<8 | int32(b[base+off+2])<<16 | int32(b[base+off+3])<<24
	}
	return rd(0), rd(4), rd(8)
}

func (r *setRunner) readBitmap() []int {
	b := r.buf()
	var out []int
	for k := 0; k < r.idSpace; k++ {
		if b[int(r.bmpPtr)+k/8]&(1<<uint(k%8)) != 0 {
			out = append(out, k)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Dropped patterns.
//
// A set can legitimately EXCLUDE a pattern whose suffix DFA exceeds the
// fallback bucket's state budget: the compiler warns, records it in
// --diag-json's `state_limit_dropped`, and compiles the rest (docs/sets.md
// "Fallback buckets can drop patterns"). A dropped pattern
// reports nothing, so comparing it against an oracle that still expects its
// matches would manufacture failures out of documented behaviour.
//
// The drop is captured from the warning itself rather than by re-deriving it:
// re-running the analysis through CmdWriteDiagJSON would double the compile
// cost of every chunk, and the warning is emitted by the very compile whose
// module is about to be driven — there is no way for the two to disagree.
//
// `where` decides the scope: an "anchored bucket" drop removes the pattern
// from match/match_any/match_all only, while a fallback-bucket drop removes it
// from everything non-anchored.

type dropHandler struct {
	find     map[int]bool
	anchored map[int]bool
}

func (h *dropHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *dropHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *dropHandler) WithGroup(string) slog.Handler            { return h }

func (h *dropHandler) Handle(_ context.Context, r slog.Record) error {
	if !strings.HasPrefix(r.Message, "Pattern dropped from set") {
		return nil
	}
	id, where := -1, ""
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "id":
			id = int(a.Value.Int64())
		case "where":
			where = a.Value.String()
		}
		return true
	})
	if id < 0 {
		return nil
	}
	if strings.HasPrefix(where, "anchored bucket") {
		h.anchored[id] = true
	} else {
		h.find[id] = true
	}
	return nil
}

// captureDrops runs fn with the compiler's warnings redirected into a
// recorder, and returns what it dropped.
func captureDrops(fn func()) (find, anchored map[int]bool) {
	h := &dropHandler{find: map[int]bool{}, anchored: map[int]bool{}}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)
	fn()
	return h.find, h.anchored
}

// buildSetProfileConfig turns a profile into a BuildConfig over pats.
func buildSetProfileConfig(pats []string, prof setProfile, hints []string, selected []int) config.BuildConfig {
	entries := make([]config.RegexEntry, len(pats))
	for i, p := range pats {
		entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
	}
	sel := config.PatternSelector{All: true}
	if selected != nil {
		names := make([]string, len(selected))
		for i, id := range selected {
			names[i] = fmt.Sprintf("p%d", id)
		}
		sel = config.PatternSelector{Names: names}
	}
	sets := make([]config.SetConfig, 0, len(prof.specs))
	for _, s := range prof.specs {
		sc := config.SetConfig{
			Name:        s.setName,
			Patterns:    sel,
			Overlapping: s.overlapping,
			Hints:       hints,
		}
		if s.match {
			sc.Match = s.setName + "_match"
		}
		if s.matchAny {
			sc.MatchAny = s.setName + "_match_any"
		}
		if s.matchAll {
			sc.MatchAll = s.setName + "_match_all"
		}
		if s.scan {
			sc.Scan = s.setName + "_scan"
		}
		if s.scanAny {
			sc.ScanAny = s.setName + "_scan_any"
		}
		if s.scanAll {
			sc.ScanAll = s.setName + "_scan_all"
		}
		if s.find {
			sc.Find = s.setName + "_find"
		}
		if s.findBatch {
			sc.FindBatch = s.setName + "_find_batch"
		}
		sets = append(sets, sc)
	}
	return config.BuildConfig{Regexps: entries, Sets: sets}
}

// setSelection returns the global ids a set selects from a chunk of n
// patterns, or nil for `patterns: all`. See setSubset for why it skips id 0.
func setSelection(n int) []int {
	if !setSubset || n < 4 {
		return nil // fewer than 4 leaves under two members: not a set any more
	}
	var out []int
	for i := 1; i < n; i += 2 {
		out = append(out, i)
	}
	return out
}

// newSetRunner compiles and instantiates one profile module for one chunk.
func newSetRunner(
	engine *wasmtime.Engine, wd *watchdog,
	pats []string, strs []string, prof setProfile, hints []string,
) (*setRunner, error) {
	selected := setSelection(len(pats))
	cfg := buildSetProfileConfig(pats, prof, hints, selected)
	var wasmBytes []byte
	var err error
	droppedFind, droppedAnchored := captureDrops(func() {
		wasmBytes, _, err = compile.CompileFile(cfg, "")
	})
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	setStats.dropped += len(droppedFind) + len(droppedAnchored)
	mod, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("NewModule: %w", err)
	}
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	release := func() {
		store.Close()
		mod.Close()
	}
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		release()
		return nil, fmt.Errorf("NewInstance: %w", err)
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		release()
		return nil, fmt.Errorf("module has no exported memory")
	}
	mem := memExp.Memory()

	const pageSize = 65536
	dataTop, err := utils.ParseDataSectionBytes(wasmBytes)
	if err != nil {
		release()
		return nil, fmt.Errorf("parse data section: %w", err)
	}
	inBase := int32((dataTop + pageSize - 1) / pageSize * pageSize)
	maxLen := 0
	for _, s := range strs {
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}
	span := int32((maxLen + pageSize - 1) / pageSize * pageSize)
	if span < pageSize {
		span = pageSize
	}
	// The two sizes are DIFFERENT things and must be derived from different
	// places (docs/sets.md "Pattern ids and the two emitted constants"):
	//   patternCount sizes the tuple buffer and the §19 cursor's k field;
	//   idSpace (largest reportable global id + 1) sizes the gate array, the
	//   `_all` bitmap, and decides which `_all` ABI the module exported.
	// They are equal only for `patterns: all`.
	patternCount := len(pats)
	idSpace := len(pats)
	inSet := make([]bool, len(pats))
	if selected == nil {
		for i := range inSet {
			inSet[i] = true
		}
	} else {
		patternCount = len(selected)
		idSpace = selected[len(selected)-1] + 1
		for _, id := range selected {
			inSet[id] = true
		}
	}
	outBase := inBase + span
	gatePtr := outBase + int32(patternCount)*int32(setOutTupleBytes)
	bmpLen := int32((idSpace + 7) / 8)
	bmpPtr := gatePtr + int32(idSpace)*4
	top := int64(bmpPtr) + int64(bmpLen) + 16
	needed := uint64((top + pageSize - 1) / pageSize)
	if cur := mem.Size(store); needed > cur {
		if _, err := mem.Grow(store, needed-cur); err != nil {
			release()
			return nil, fmt.Errorf("memory.Grow to %d pages: %w", needed, err)
		}
	}
	return &setRunner{
		store: store, inst: inst, mem: mem, wd: wd, release: release,
		inBase: inBase, outBase: outBase, gatePtr: gatePtr, bmpPtr: bmpPtr,
		npat: patternCount, idSpace: idSpace, inSet: inSet,
		outCap: int32(patternCount), bmpLen: bmpLen,
		wide:        idSpace > 64,
		droppedFind: droppedFind, droppedAnchored: droppedAnchored,
	}, nil
}

// setFromValues picks the `from` positions the scan trio is driven at.
//
// Every position for short inputs; for longer ones a spread that keeps the
// boundaries the SIMD frontends turn on: 16 and 32 are block edges and 33 is
// where `simdGuard = MinLen + span - 1` first admits a two-column probe:
// the shared-probe-column defect was invisible below 33 bytes.
func setFromValues(n int) []int {
	if n <= 16 {
		out := make([]int, 0, n+1)
		for i := 0; i <= n; i++ {
			out = append(out, i)
		}
		return out
	}
	cand := []int{0, 1, 2, 15, 16, 17, 31, 32, 33, n / 2, n - 2, n - 1, n}
	seen := map[int]bool{}
	out := make([]int, 0, len(cand))
	for _, v := range cand {
		if v < 0 || v > n || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// ---------------------------------------------------------------------------
// Driving one chunk under one profile.

// runSetProfile compiles the chunk under prof and checks every capability the
// profile declares against the oracle. All accounting goes through setStats;
// the caller derives its own totals from that, so there is no second counter
// to keep in step.
func runSetProfile(
	engine *wasmtime.Engine, wd *watchdog,
	chunk setChunk, strs []string, orc *setOracle, prof setProfile, hints []string,
	verbose bool,
) error {
	r, err := newSetRunner(engine, wd, chunk.pats, strs, prof, hints)
	if err != nil {
		setStats.bad("compile["+prof.name+"]", len(chunk.pats)*len(strs))
		setFailf("FAIL  set chunk compile error (profile %s, %d patterns): %v\n      first pattern: %q\n",
			prof.name, len(chunk.pats), err, chunk.pats[0])
		return nil
	}
	defer r.release()

	// Resolve every export once. A missing export is a compiler bug, not a
	// per-input failure, so it stops the run rather than being counted.
	type capFns struct {
		spec                      setCapMask
		match, matchAny, matchAll *wasmtime.Func
		scan, scanAny, scanAll    *wasmtime.Func
		find, findBatch           *wasmtime.Func
	}
	var fns []capFns
	for _, s := range prof.specs {
		c := capFns{spec: s}
		get := func(want bool, name string) (*wasmtime.Func, error) {
			if !want {
				return nil, nil
			}
			f := r.fn(name)
			if f == nil {
				return nil, fmt.Errorf("profile %s: missing export %q", prof.name, name)
			}
			return f, nil
		}
		var e error
		if c.match, e = get(s.match, s.setName+"_match"); e != nil {
			return e
		}
		if c.matchAny, e = get(s.matchAny, s.setName+"_match_any"); e != nil {
			return e
		}
		if c.matchAll, e = get(s.matchAll, s.setName+"_match_all"); e != nil {
			return e
		}
		if c.scan, e = get(s.scan, s.setName+"_scan"); e != nil {
			return e
		}
		if c.scanAny, e = get(s.scanAny, s.setName+"_scan_any"); e != nil {
			return e
		}
		if c.scanAll, e = get(s.scanAll, s.setName+"_scan_all"); e != nil {
			return e
		}
		if c.find, e = get(s.find, s.setName+"_find"); e != nil {
			return e
		}
		if c.findBatch, e = get(s.findBatch, s.setName+"_find_batch"); e != nil {
			return e
		}
		fns = append(fns, c)
	}

	for si, text := range strs {
		if hasUnicode(text) {
			continue
		}
		if len(text) > 0 {
			copy(r.buf()[r.inBase:], text)
		}
		tlen := int32(len(text))

		for _, c := range fns {
			mode := "gated"
			if c.spec.overlapping {
				mode = "overlap"
			}

			// ---- anchored trio -------------------------------------------
			if c.match != nil || c.matchAny != nil || c.matchAll != nil {
				want := keepIDs(orc.anchoredIDs(si), r.anchoredEligible)
				if c.match != nil {
					res, hang, e := r.call(c.match, r.inBase, tlen)
					if e != nil {
						return e
					}
					if hang {
						setStats.timeouts++
					} else {
						got := res.(int32)
						if (got != 0) == (len(want) > 0) {
							setStats.ok("match", 1)
						} else {
							setStats.bad("match", 1)
							setFailf("FAIL  set match: got %d, want %v (ids %v)\n      input: %q\n      patterns: %s\n",
								got, len(want) > 0, want, text, fmtSetPatterns(chunk.pats))
						}
					}
				}
				if c.matchAny != nil {
					res, hang, e := r.call(c.matchAny, r.inBase, tlen)
					if e != nil {
						return e
					}
					if hang {
						setStats.timeouts++
					} else {
						got := int(res.(int32))
						// §3.5: membership, never value equality — any of the
						// matching ids is a correct answer.
						okAny := (got == -1 && len(want) == 0) || (got != -1 && containsSetID(want, got))
						if okAny {
							setStats.ok("match_any", 1)
						} else {
							setStats.bad("match_any", 1)
							setFailf("FAIL  set match_any: got %d, want one of %v\n      input: %q\n      patterns: %s\n",
								got, want, text, fmtSetPatterns(chunk.pats))
						}
					}
				}
				if c.matchAll != nil {
					got, hang, e := r.callAll(c.matchAll, tlen, -1)
					if e != nil {
						return e
					}
					if hang {
						setStats.timeouts++
					} else if eqSetIDs(got, want) {
						setStats.ok("match_all", 1)
					} else {
						setStats.bad("match_all", 1)
						setFailf("FAIL  set match_all: got %v, want %v\n      input: %q\n      patterns: %s\n",
							got, want, text, fmtSetPatterns(chunk.pats))
					}
				}
			}

			// ---- scan trio -----------------------------------------------
			if c.scan != nil || c.scanAny != nil || c.scanAll != nil {
				for _, from := range setFromValues(len(text)) {
					if c.scan != nil {
						res, hang, e := r.call(c.scan, r.inBase, tlen, int32(from))
						if e != nil {
							return e
						}
						if hang {
							setStats.timeouts++
						} else {
							pos, _ := orc.firstPosition(si, from, r.findEligible)
							got := res.(int32)
							if (got != 0) == (pos >= 0) {
								setStats.ok("scan", 1)
							} else {
								setStats.bad("scan", 1)
								setFailf("FAIL  set scan(from=%d): got %d, want %v\n      input: %q\n      patterns: %s\n",
									from, got, pos >= 0, text, fmtSetPatterns(chunk.pats))
							}
						}
					}
					if c.scanAny != nil {
						res, hang, e := r.call(c.scanAny, r.inBase, tlen, int32(from))
						if e != nil {
							return e
						}
						if hang {
							setStats.timeouts++
						} else {
							packed := res.(int64)
							wantPos, wantIDs := orc.firstPosition(si, from, r.findEligible)
							okAny := false
							var gotPos, gotID int
							if packed == -1 {
								gotPos, gotID = -1, -1
								okAny = wantPos == -1
							} else {
								gotPos = int(packed >> 32)
								gotID = int(int32(uint32(packed)))
								// §9.6: exact on the start, membership on the id.
								okAny = gotPos == wantPos && containsSetID(wantIDs, gotID)
							}
							if okAny {
								setStats.ok("scan_any", 1)
							} else {
								setStats.bad("scan_any", 1)
								setFailf("FAIL  set scan_any(from=%d): got start=%d id=%d, want start=%d id in %v\n      input: %q\n      patterns: %s\n",
									from, gotPos, gotID, wantPos, wantIDs, text, fmtSetPatterns(chunk.pats))
							}
						}
					}
					if c.scanAll != nil {
						got, hang, e := r.callAll(c.scanAll, tlen, int32(from))
						if e != nil {
							return e
						}
						if hang {
							setStats.timeouts++
						} else {
							want := orc.scanAllIDs(si, from, r.findEligible)
							if eqSetIDs(got, want) {
								setStats.ok("scan_all", 1)
							} else {
								setStats.bad("scan_all", 1)
								setFailf("FAIL  set scan_all(from=%d): got %v, want %v\n      input: %q\n      patterns: %s\n",
									from, got, want, text, fmtSetPatterns(chunk.pats))
							}
						}
					}
				}
			}

			// ---- find ----------------------------------------------------
			if c.find != nil {
				gotM, hang, e := r.driveFind(c.find, text, c.spec.overlapping)
				if e != nil {
					return e
				}
				if hang {
					setStats.timeouts++
				} else {
					compareSetMatches(chunk, strs, si, orc, gotM, c.spec.overlapping,
						"find/"+mode, verbose, r.findEligible)
				}
				// The same scan through an under-sized buffer, checking
				// out_cap=0 and the transactional-overflow rule at every
				// position (§3.11 / D2).
				ovM, hang, viol, e := r.driveFindOverflow(c.find, text, c.spec.overlapping)
				if e != nil {
					return e
				}
				switch {
				case hang:
					setStats.timeouts++
				case viol != "":
					setStats.bad("find/"+mode+"/overflow", 1)
					setFailf("FAIL  set find/%s/overflow: %s\n      input: %q\n      set:   %s\n",
						mode, viol, text, fmtSetPatterns(chunk.pats))
				default:
					compareSetMatches(chunk, strs, si, orc, ovM, c.spec.overlapping,
						"find/"+mode+"/overflow", verbose, r.findEligible)
				}
			}

			// ---- find_batch ----------------------------------------------
			if c.findBatch != nil {
				caps := []int32{1, r.outCap}
				if setBatchCap1Only || r.outCap <= 1 {
					caps = caps[:1]
				}
				for _, cap := range caps {
					gotM, hang, e := r.driveFindBatch(c.findBatch, text, c.spec.overlapping, cap)
					if e != nil {
						return e
					}
					if hang {
						setStats.timeouts++
						continue
					}
					label := fmt.Sprintf("find_batch/%s/cap=%s", mode, batchCapLabel(cap, r.outCap))
					compareSetMatches(chunk, strs, si, orc, gotM, c.spec.overlapping, label, verbose, r.findEligible)
				}
			}

			// ---- §4.2 out-of-range `from` --------------------------------
			if e := r.checkFromOutOfRange(c.scan, c.scanAny, c.scanAll, c.find, c.findBatch,
				c.spec.overlapping, tlen, chunk.pats); e != nil {
				return e
			}
		}
	}
	return nil
}

func batchCapLabel(cap, full int32) string {
	if cap == 1 {
		return "1"
	}
	if cap == full {
		return "P"
	}
	return strconv.Itoa(int(cap))
}

// callAll drives a `match_all` / `scan_all` export in whichever ABI its id
// space selected: a bitmask i64 return at <=64, a caller-supplied bitmap plus
// a count above it (docs/sets.md "Output formats"). from < 0 means the
// anchored form, which takes no `from`.
func (r *setRunner) callAll(fn *wasmtime.Func, tlen, from int32) ([]int, bool, error) {
	if r.wide {
		r.zeroBitmap()
		var res interface{}
		var hang bool
		var err error
		if from < 0 {
			res, hang, err = r.call(fn, r.inBase, tlen, r.bmpPtr)
		} else {
			res, hang, err = r.call(fn, r.inBase, tlen, from, r.bmpPtr)
		}
		if err != nil || hang {
			return nil, hang, err
		}
		ids := r.readBitmap()
		if got := int(res.(int32)); got != len(ids) {
			return nil, false, fmt.Errorf("_all returned count %d but its bitmap holds %d ids", got, len(ids))
		}
		return ids, false, nil
	}
	var res interface{}
	var hang bool
	var err error
	if from < 0 {
		res, hang, err = r.call(fn, r.inBase, tlen)
	} else {
		res, hang, err = r.call(fn, r.inBase, tlen, from)
	}
	if err != nil || hang {
		return nil, hang, err
	}
	mask := uint64(res.(int64))
	var ids []int
	for k := 0; k < r.idSpace; k++ {
		if mask&(uint64(1)<<uint(k)) != 0 {
			ids = append(ids, k)
		}
	}
	return ids, false, nil
}

// driveFind iterates a `find` export to exhaustion: call, record, resume at
// start+1. Returns the matches keyed by pattern id.
func (r *setRunner) driveFind(fn *wasmtime.Func, text string, overlapping bool) (map[int32][][2]int, bool, error) {
	got := make(map[int32][][2]int)
	if !overlapping {
		r.zeroGates()
	}
	from := int32(0)
	for {
		var res interface{}
		var hang bool
		var err error
		if overlapping {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), from, r.outBase, r.outCap)
		} else {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), from, r.gatePtr, r.outBase, r.outCap)
		}
		if err != nil || hang {
			return nil, hang, err
		}
		count := res.(int32)
		if count <= 0 {
			return got, false, nil
		}
		if count > r.outCap {
			return nil, false, fmt.Errorf("find reported %d tuples at one position for a %d-pattern set", count, r.outCap)
		}
		var start int32
		for i := int32(0); i < count; i++ {
			pid, st, en := r.readTuple(i)
			if i == 0 {
				start = st
			} else if st != start {
				return nil, false, fmt.Errorf("find tuples in one call disagree on start (%d vs %d)", start, st)
			}
			got[pid] = append(got[pid], [2]int{int(st), int(en)})
		}
		from = start + 1
		if int(from) > len(text)+1 {
			return nil, false, fmt.Errorf("find failed to terminate: from=%d past len=%d", from, len(text))
		}
	}
}

// driveFindBatch iterates a `find_batch` export to exhaustion at the given
// buffer capacity. A capacity of ONE splits every multi-match position, which
// is what makes §19's resume path (delivered-tuple gating when gated, the
// `skip` parameter when overlapping) reachable at corpus scale.
func (r *setRunner) driveFindBatch(fn *wasmtime.Func, text string, overlapping bool, outCap int32) (map[int32][][2]int, bool, error) {
	got := make(map[int32][][2]int)
	if !overlapping {
		r.zeroGates()
	}
	countMask := int64(1)<<uint(config.SetCursorCountBits(r.npat)) - 1
	cursor := int64(0)
	maxCalls := 8*(len(text)+1)*(r.npat+1) + 16
	for calls := 0; ; calls++ {
		if calls > maxCalls {
			return nil, false, fmt.Errorf("find_batch did not terminate after %d calls", calls)
		}
		var res interface{}
		var hang bool
		var err error
		if overlapping {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), cursor, r.outBase, outCap)
		} else {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), cursor, r.gatePtr, r.outBase, outCap)
		}
		if err != nil || hang {
			return nil, hang, err
		}
		packed := res.(int64)
		count := int32(packed & countMask)
		if count < 0 || count > outCap {
			return nil, false, fmt.Errorf("find_batch reported count %d for a buffer of %d", count, outCap)
		}
		for i := int32(0); i < count; i++ {
			pid, st, en := r.readTuple(i)
			got[pid] = append(got[pid], [2]int{int(st), int(en)})
		}
		if uint32(packed>>32) == 0xFFFFFFFF || count == 0 {
			return got, false, nil
		}
		cursor = packed
	}
}

// driveFindOverflow drives a `find` export at a buffer DELIBERATELY too small,
// checking the two contracts a full-capacity drive can never reach
// (docs/sets.md "The gate array"):
//
//   - `out_cap = 0` returns the position's total and delivers no tuples;
//   - an overflowing call (`total > out_cap`) is TRANSACTIONAL: growing the
//     buffer and calling again with the same `from` returns the same total and
//     the same tuples — the retry sees the identical world.
//
// The check is on the ANSWER, not on the bytes of the gate array. A gated find
// on a fresh array may legitimately write eliminations into it before
// delivering anything: the §21 union-scan prologue runs once, and permanently
// gates out every pattern that matches nowhere at or after `from`. That is
// sound (a pattern it eliminates cannot match, so no answer changes) and it is
// where G10's −99.74% comes from — but it does mean docs/sets.md's literal
// "the gate array is left exactly as it was found" is not true byte-for-byte.
// Asserting the bytes would therefore fail on a correct compiler; asserting the
// answer is both what a caller can observe and what the rule exists to protect.
//
// The scan therefore proceeds one position at a time: probe at capacity 0,
// probe at capacity 1, and whenever that overflows, retry at full capacity —
// which is what a real caller who under-sized its buffer must do. The
// collected matches still have to equal the oracle, so the contract is checked
// at every position of the corpus rather than at a handful of hand-picked ones.
func (r *setRunner) driveFindOverflow(fn *wasmtime.Func, text string, overlapping bool) (_ map[int32][][2]int, hangOut bool, violation string, _ error) {
	got := make(map[int32][][2]int)
	if !overlapping {
		r.zeroGates()
	}
	call := func(from, outCap int32) (int32, bool, error) {
		var res interface{}
		var hang bool
		var err error
		if overlapping {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), from, r.outBase, outCap)
		} else {
			res, hang, err = r.call(fn, r.inBase, int32(len(text)), from, r.gatePtr, r.outBase, outCap)
		}
		if err != nil || hang {
			return 0, hang, err
		}
		return res.(int32), false, nil
	}
	from := int32(0)
	for {
		zeroTotal, hang, err := call(from, 0)
		if err != nil || hang {
			return nil, hang, "", err
		}
		total, hang, err := call(from, 1)
		if err != nil || hang {
			return nil, hang, "", err
		}
		if total != zeroTotal {
			return nil, false, fmt.Sprintf("find at from=%d returned %d with out_cap=0 but %d with out_cap=1", from, zeroTotal, total), nil
		}
		if total <= 0 {
			return got, false, "", nil
		}
		n := total
		if total > 1 {
			// Overflowed. The retry must see the identical world: same total,
			// and the tuples it then delivers must still satisfy the oracle,
			// which the caller checks on the collected result.
			retry, hang, err := call(from, r.outCap)
			if err != nil || hang {
				return nil, hang, "", err
			}
			if retry != total {
				return nil, false, fmt.Sprintf("find at from=%d returned %d when overflowing but %d on retry at full capacity", from, total, retry), nil
			}
			n = retry
		}
		if n > r.outCap {
			return nil, false, fmt.Sprintf("find reported %d tuples at one position for a %d-pattern set", n, r.outCap), nil
		}
		var start int32
		for i := int32(0); i < n; i++ {
			pid, st, en := r.readTuple(i)
			if i == 0 {
				start = st
			}
			got[pid] = append(got[pid], [2]int{int(st), int(en)})
		}
		from = start + 1
		if int(from) > len(text)+1 {
			return nil, false, fmt.Sprintf("find failed to terminate: from=%d past len=%d", from, len(text)), nil
		}
	}
}

// checkFromOutOfRange drives every declared capability at `from > len`, which
// §4.2 fixes as the capability's "nothing" result. It is a real caller mistake
// (an iterator that resumed one past the end) and nothing in the corpus reaches
// it, because every ordinary drive stops at len.
func (r *setRunner) checkFromOutOfRange(
	scan, scanAny, scanAll, find, findBatch *wasmtime.Func, overlapping bool, tlen int32,
	pats []string,
) error {
	for _, from := range []int32{tlen + 1, tlen + 7} {
		if scan != nil {
			res, hang, err := r.call(scan, r.inBase, tlen, from)
			if err != nil {
				return err
			}
			if !hang {
				if got := res.(int32); got != 0 {
					setStats.bad("from>len/scan", 1)
					setFailf("FAIL  set scan(from=%d > len=%d): got %d, want 0 (§4.2)\n      set: %s\n", from, tlen, got, fmtSetPatterns(pats))
				} else {
					setStats.ok("from>len/scan", 1)
				}
			}
		}
		if scanAny != nil {
			res, hang, err := r.call(scanAny, r.inBase, tlen, from)
			if err != nil {
				return err
			}
			if !hang {
				if got := res.(int64); got != -1 {
					setStats.bad("from>len/scan_any", 1)
					setFailf("FAIL  set scan_any(from=%d > len=%d): got %#x, want -1 (§4.2)\n      set: %s\n", from, tlen, got, fmtSetPatterns(pats))
				} else {
					setStats.ok("from>len/scan_any", 1)
				}
			}
		}
		if scanAll != nil {
			ids, hang, err := r.callAll(scanAll, tlen, from)
			if err != nil {
				return err
			}
			if !hang {
				if len(ids) != 0 {
					setStats.bad("from>len/scan_all", 1)
					setFailf("FAIL  set scan_all(from=%d > len=%d): got %v, want none (§4.2)\n      set: %s\n", from, tlen, ids, fmtSetPatterns(pats))
				} else {
					setStats.ok("from>len/scan_all", 1)
				}
			}
		}
		if find != nil {
			if !overlapping {
				r.zeroGates()
			}
			var res interface{}
			var hang bool
			var err error
			if overlapping {
				res, hang, err = r.call(find, r.inBase, tlen, from, r.outBase, r.outCap)
			} else {
				res, hang, err = r.call(find, r.inBase, tlen, from, r.gatePtr, r.outBase, r.outCap)
			}
			if err != nil {
				return err
			}
			if !hang {
				if got := res.(int32); got != 0 {
					setStats.bad("from>len/find", 1)
					setFailf("FAIL  set find(from=%d > len=%d): got %d, want 0 (§4.2)\n      set: %s\n", from, tlen, got, fmtSetPatterns(pats))
				} else {
					setStats.ok("from>len/find", 1)
				}
			}
		}
		if findBatch != nil {
			if !overlapping {
				r.zeroGates()
			}
			cursor := int64(from) << 32
			var res interface{}
			var hang bool
			var err error
			if overlapping {
				res, hang, err = r.call(findBatch, r.inBase, tlen, cursor, r.outBase, r.outCap)
			} else {
				res, hang, err = r.call(findBatch, r.inBase, tlen, cursor, r.gatePtr, r.outBase, r.outCap)
			}
			if err != nil {
				return err
			}
			if !hang {
				packed := res.(int64)
				countMask := int64(1)<<uint(config.SetCursorCountBits(r.npat)) - 1
				count := int32(packed & countMask)
				if count != 0 || uint32(packed>>32) != 0xFFFFFFFF {
					setStats.bad("from>len/find_batch", 1)
					setFailf("FAIL  set find_batch(from=%d > len=%d): count=%d done=%v, want count 0 and done (§4.2)\n      set: %s\n",
						from, tlen, count, uint32(packed>>32) == 0xFFFFFFFF, fmtSetPatterns(pats))
				} else {
					setStats.ok("from>len/find_batch", 1)
				}
			}
		}
	}
	return nil
}

// compareSetMatches checks one drive's output against the oracle, per pattern.
func compareSetMatches(
	chunk setChunk, strs []string, si int, orc *setOracle,
	got map[int32][][2]int, overlapping bool, label string, verbose bool,
	eligible func(int) bool,
) (npass, nfail int) {
	// A pattern the set does NOT select, or that the compiler dropped, must
	// report nothing at all. Skipping those ids without checking would let a
	// set that ignores its own `patterns:` selection pass silently — and the
	// selection is exactly what makes the id space sparse.
	for pi := range chunk.pats {
		if eligible(pi) {
			continue
		}
		if extra := got[int32(pi)]; len(extra) > 0 {
			nfail++
			setStats.bad(label, 1)
			setFailf("FAIL  set %s reported %d match(es) for pattern[%d] %q, which is not in the set\n      input: %q\n      got:   %s\n",
				label, len(extra), pi, chunk.pats[pi], strs[si], fmtCol4Wasm(extra))
		}
	}
	for pi := range chunk.pats {
		if !eligible(pi) {
			continue // not a member, or compiler-excluded; checked above
		}
		var want [][2]int
		if overlapping {
			want = append(want, orc.overlappingSpans(pi, si)...)
		} else {
			want = append(want, orc.findAllByStr[pi][si]...)
		}
		g := append([][2]int(nil), got[int32(pi)]...)
		// §3.10 leaves within-call tuple order unspecified, so compare as a
		// multiset; across calls the starts strictly increase anyway.
		sortSpanPairs(g)
		sortSpanPairs(want)
		if col4WasmEqual(g, want) {
			npass++
			setStats.ok(label, 1)
			if verbose {
				fmt.Printf("PASS set %s pattern[%d] %q input=%q\n", label, pi, chunk.pats[pi], strs[si])
			}
		} else {
			nfail++
			setStats.bad(label, 1)
			setFailf("FAIL  set %s pattern[%d] (orig %d): %q\n      input:    %q\n      expected: %s\n      got:      %s\n      set:      %s\n",
				label, pi, chunk.orig[pi], chunk.pats[pi], strs[si], fmtCol4(want), fmtCol4Wasm(g),
				fmtSetPatterns(chunk.pats))
		}
	}
	return
}

func containsSetID(v []int, x int) bool {
	for _, e := range v {
		if e == x {
			return true
		}
	}
	return false
}

func eqSetIDs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]int(nil), a...)
	b = append([]int(nil), b...)
	sort.Ints(a)
	sort.Ints(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fmtSetPatterns renders a chunk's patterns for a failure message, truncated:
// a 7020-pattern chunk's full list helps nobody.
func fmtSetPatterns(pats []string) string {
	const max = 6
	var b strings.Builder
	for i, p := range pats {
		if i == max {
			fmt.Fprintf(&b, " ... (+%d more)", len(pats)-max)
			break
		}
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%q", p)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Chunking.

// setChunksOf splits a block's eligible patterns into the sets to compile.
func setChunksOf(pats []string, orig []int, cols [][]string) []setChunk {
	order := make([]int, len(pats))
	for i := range order {
		order[i] = i
	}
	if setShufflePats {
		// A fixed-seed LCG rather than math/rand: reproducible across Go
		// versions, so a chunk that fails is the same chunk on a rerun.
		state := uint64(0x2545F4914F6CDD1D)
		for i := len(order) - 1; i > 0; i-- {
			state = state*6364136223846793005 + 1442695040888963407
			j := int((state >> 33) % uint64(i+1))
			order[i], order[j] = order[j], order[i]
		}
	}
	size := setChunkSize
	if size <= 0 || size > len(order) {
		size = len(order)
	}
	var out []setChunk
	for start := 0; start < len(order); start += size {
		end := start + size
		if end > len(order) {
			end = len(order)
		}
		if end-start < 2 {
			// A one-pattern set is a single-pattern engine in disguise and
			// tests none of the interaction this task exists to reach. Fold it
			// into the previous chunk instead of dropping the patterns.
			if len(out) > 0 {
				c := &out[len(out)-1]
				for _, idx := range order[start:end] {
					c.pats = append(c.pats, pats[idx])
					c.orig = append(c.orig, orig[idx])
					c.cols = append(c.cols, cols[idx])
				}
				break
			}
			break
		}
		var c setChunk
		for _, idx := range order[start:end] {
			c.pats = append(c.pats, pats[idx])
			c.orig = append(c.orig, orig[idx])
			c.cols = append(c.cols, cols[idx])
		}
		out = append(out, c)
	}
	return out
}
