package compile

import (
	"fmt"
	"log/slog"
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ── Splitting a set: members served by their own start-anywhere find ───────
//
// A set's non-anchored bodies try candidate positions one at a time, like the
// single-pattern find does, and a member whose failed attempts can walk an
// unbounded number of bytes (`\w+@\w+` over a long word, `a*b` over `a`×N)
// makes them quadratic. The single-pattern find proves some shapes linear by
// looking at the body that will run them; a set member is walked by the SET's
// code, so only two proofs carry over: the engine-independent one
// (failedWalkBound: no reachable cycle on which a walk keeps going without
// accepting), and the set's own literal-anchored one (setLiteralMemberLinear).
// Every other member is SPLIT OUT:
//
//   - the buckets serve the members that stay ("kept"), exactly as before;
//   - each split member gets its own linear search: its start-anywhere find's
//     two passes (start_anywhere.go), or the Backtracking find where those
//     cannot be built, past the start-anywhere tables' budget, or for a
//     member the set had put on a Backtracking bucket (splitCand.bt);
//   - `find`, `scan_any` and `scan_all` become MERGE WRAPPERS over the kept
//     body and the split members — unless a start-anywhere union over EVERY
//     member can serve the scan pair, which then answers it alone;
//   - match_any / match_all are anchored and do not change.
//
// A set is split when one of its non-anchored capabilities would otherwise
// stay quadratic: gated `find` always; overlapping `find` when the answer
// cache cannot serve it; the scan pair when no union automaton serves it (a
// literal frontend's counter needs one to switch to). In a set with
// `hints: [batch-find]` the merge sits in the shared per-position WORKER, so
// both entries reach it, and follows the batch resume rules there; such a set
// gets no answer cache once split, because the batch entry serves the cache
// without calling the worker.
//
// THE MERGE (`find`). Each call answers the matches at the smallest start at
// or after `from`, which is the smallest of the kept body's answer and every
// split member's next match. Two per-drive caches keep that linear, both in
// the caller's gate array and both in the gate encoding the kept body already
// reads:
//
//   - a split member's slot holds a LOWER BOUND on its next start (2s after
//     a search found its next match at s; the ordinary report gate after it
//     was reported; dead when it has none left). No other code reads it.
//   - the kept members' slots are raised to 2·p when the kept body answered p
//     but a split member answered earlier: nothing kept starts before p, and
//     the next call skips straight there — or does not call the kept body at
//     all while every split answer is still earlier.
//
// Candidates are processed in the order of their lower bounds, and one whose
// bound is past the best start found so far is not processed at all. So a
// member's search from its bound is repeated only on the call that reports
// it: each byte is walked a bounded number of times over the whole drive.

// splitTableBudget bounds the start-anywhere tables one set's split members
// add to the module. Members get the start-anywhere find smallest tables
// first while the total stays within it; the rest are served by the
// Backtracking find (buildBTFindParts), linear per call too, whose own tables
// are a few scan bytes and whose frame stack all of them share — the merge
// wrapper calls one member at a time. Without a bound a set with hundreds of
// such members compiled hundreds of automata, each up to ~1 MB.
const splitTableBudget = 4 << 20

// splitMember is one member a set serves outside its buckets: by its
// start-anywhere find's two passes, or — bt non-nil — by the Backtracking find.
type splitMember struct {
	id               int    // global pattern id
	fwdBody, revBody []byte // size-prefixed code entries
	// ctx: the passes are the context ones (startAnywherePasses.ctx) — the
	// forward pass reads the whole input from the find-from global and
	// answers an absolute end, the backward one takes (ptr, len, end).
	ctx bool
	bt  *btFindParts
	// notes: the forward pass keeps per-search notes (search_notes.go) in
	// the member's own search block (searchBlocks).
	notes *notesRows
}

// mslot is one of the merge's per-member values: a local, or a word of the
// set's merge state region (compiledSet.mergeState) in the table memory.
type mslot struct {
	local uint32
	mem   bool
	addr  uint32
}

// splitMergeLocalMembers is how many split members a merge keeps in locals.
// Past it the per-member values move to memory: a function with four locals
// per member is one Cranelift cannot compile in 4 GB at seven hundred members
// (the RE2 corpus's whole-block sets), and loading a value costs little
// against the member search the merge is about to run. A variable so a test
// can drive the memory form with a small set.
var splitMergeLocalMembers = 64

// splitMergeSlotBytes is one member's merge state: four i32 words.
const splitMergeSlotBytes = 16

// hasBlock reports whether the member's search keeps state in a search block
// of its own: notes, or a Backtracking find's budget per search.
func (sm splitMember) hasBlock() bool {
	return sm.notes != nil || (sm.bt != nil && sm.bt.search)
}

// block is what the member's search keeps in its block (SearchSize.Blocks).
func (sm splitMember) block() SearchSize {
	var s SearchSize
	if sm.notes != nil {
		s.NotesBytes = int(sm.notes.bytes)
	}
	if sm.bt != nil && sm.bt.search {
		s.BTBudget, s.BTMemoBytes = true, sm.bt.memoBytes
	}
	return s
}

// splitCand is a member the split serves: its index into the set's patterns,
// and how — the Backtracking find (bt), or the start-anywhere find, whose two
// automata take saBytes of tables.
type splitCand struct {
	idx     int
	bt      bool
	saBytes int64
}

// splitAnalysisStates is the state limit setMemberNeedsSplit judges a member's
// automaton under when max_fallback_states is lower.
const splitAnalysisStates = 4096

// anyBTSplit reports whether a candidate is served by the Backtracking find.
func anyBTSplit(split []splitCand) bool {
	for _, c := range split {
		if c.bt {
			return true
		}
	}
	return false
}

// splitIndices is the candidates' pattern indices.
func splitIndices(split []splitCand) []int {
	out := make([]int, len(split))
	for i, c := range split {
		out[i] = c.idx
	}
	return out
}

// budgetSplit gives the start-anywhere find to the candidates with the
// smallest tables while their total stays within budget, and the Backtracking
// find to the rest (a candidate Backtracking cannot take keeps the
// start-anywhere find: over the budget, but linear).
func budgetSplit(cands []splitCand, pats []*PatternInfo, opts CompileSetOptions, budget int64) []splitCand {
	var order []int
	for k, c := range cands {
		if !c.bt {
			order = append(order, k)
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return cands[order[a]].saBytes < cands[order[b]].saBytes })
	var total int64
	for _, k := range order {
		if total+cands[k].saBytes > budget {
			if _, ok := btFindStackSize(pats[cands[k].idx].fullPattern, opts.BTWorkBudget); ok {
				cands[k].bt = true
				continue
			}
		}
		total += cands[k].saBytes
	}
	return cands
}

// keptSpec is spec without the members at the split indices. It keeps the
// full set's pattern count and id space, which size the caller's buffers.
func keptSpec(full SetSpec, split []int) SetSpec {
	if len(split) == 0 {
		return full
	}
	out := full
	out.Patterns, out.PatternIDs = nil, nil
	skip := make(map[int]bool, len(split))
	for _, i := range split {
		skip[i] = true
	}
	for i, p := range full.Patterns {
		if !skip[i] {
			out.Patterns = append(out.Patterns, p)
			out.PatternIDs = append(out.PatternIDs, full.PatternIDs[i])
		}
	}
	out.DeclaredPatternCount = full.patternCount()
	if out.IDSpaceSize <= 0 {
		for _, id := range full.PatternIDs {
			if id+1 > out.IDSpaceSize {
				out.IDSpaceSize = id + 1
			}
		}
	}
	return out
}

// compileSetSplit is CompileSet: it compiles the set, and compiles it again
// with members split out when the first compile shows a capability that
// needs it. Compile time only — CLAUDE.md's second design principle.
//
// A set whose members are all provably linear compiles once, exactly as it
// always has: nothing here — no split, no counter — can change its answers or
// its cost, since the quadratic cases need a member that fails the rule.
func compileSetSplit(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions) *compiledSet {
	cs := compileSetSplitPrimary(spec, prefixPool, suffixPool, opts)
	if cs.sparseCtr != nil {
		cs.attachCompanion(sparseCompanion(spec, prefixPool, suffixPool, opts, cs))
	}
	return cs
}

// sparseCompanion builds what a set's sparse counter hands a drive over to:
// the SAME set with the members of its counted sparse buckets split out, each
// served by its own linear search — `find` only, internal, never exported.
func sparseCompanion(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions, primary *compiledSet) *compiledSet {
	idx := map[*PatternInfo]int{}
	for i, p := range spec.Patterns {
		idx[p] = i
	}
	var cands []splitCand
	for _, bkt := range primary.buckets {
		if !sparseCycle(bkt) {
			continue
		}
		// Only the members that keep the walk going: without them the
		// bucket's walks are bounded again.
		unb := sparseUnboundedMembers(bkt)
		for k, p := range bkt.patterns {
			if !unb[k] {
				continue
			}
			i := idx[p]
			if sa, ok := buildStartAnywherePasses(p.fullPattern, splitPassOpts(p, opts), 0, align8, nil); ok {
				cands = append(cands, splitCand{idx: i, saBytes: sa.end})
			} else if _, ok := btFindStackSize(p.fullPattern, opts.BTWorkBudget); ok {
				cands = append(cands, splitCand{idx: i, bt: true})
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].idx < cands[j].idx })
	c := spec
	c.Name = spec.Name + "\x00sparse"
	c.Find = spec.Find + "\x00sparse" // never exported
	c.MatchAny, c.MatchAll, c.ScanAny, c.ScanAll = "", "", "", ""
	o := opts
	o.noSparseCounter, o.quiet = true, true
	base := max(int64(primary.regionEnd), primary.dataTop())
	o.TableBase = int32(align8(base)) //nolint:gosec // table addresses fit in i32
	comp := compileSetWith(c, prefixPool, suffixPool, o, budgetSplit(cands, spec.Patterns, opts, splitTableBudget), true)
	comp.internal = true
	comp.forceAcceptBlocks = true
	if primary.diag != nil && comp.diag != nil {
		primary.diag.SparseSplitMembers = comp.diag.SplitMembers
	}
	return comp
}

// compileSetSplitPrimary is compileSetSplit before the sparse counter's
// companion is attached.
func compileSetSplitPrimary(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions) *compiledSet {
	cands := setSplitCandidates(spec, opts)
	if len(cands) == 0 {
		return compileSetWith(spec, prefixPool, suffixPool, opts, nil, false)
	}
	if opts.NoSplit {
		// The counters still apply.
		return compileSetWith(spec, prefixPool, suffixPool, opts, nil, true)
	}
	// The trial takes its globals from a copy, so a set that turns out to need
	// the split leaves no allocation of the trial's behind in the module.
	trialOpts := opts
	trialOpts.globals = opts.globals.clone()
	trial := compileSetWith(spec, prefixPool, suffixPool, trialOpts, nil, true)
	cands = trial.keepsOnDFA(spec, cands)
	if len(cands) > 0 && trial.needsSplit() && trial.scanAloneNeedsSplit() {
		if cs := scanSplitOnly(spec, prefixPool, suffixPool, opts, cands); cs != nil {
			return cs
		}
	}
	if len(cands) == 0 || !trial.needsSplit() {
		*opts.globals = *trialOpts.globals
		if len(cands) > 0 {
			trial.attachCompanion(noCacheCompanion(spec, prefixPool, suffixPool, opts, trial, cands))
		}
		return trial
	}
	cands = budgetSplit(cands, spec.Patterns, opts, splitTableBudget)
	// The trial has already warned about every pattern this compile drops or
	// puts on Backtracking: the split members are neither, and the others
	// are packed by the same per-pattern rules.
	opts.quiet = true
	return compileSetWith(spec, prefixPool, suffixPool, opts, cands, true)
}

// noCacheCompanion builds what an overlapping set falls back to when its
// answer cache is what keeps its not-provably-linear members linear and a drive
// has no usable cache: no cache pointer (a raw caller, a C build with
// -DRX_SET_CACHE=0, a component whose region was declined), or a sweep refused.
// There the in-call counter has nothing to hand over to. The companion is the
// SAME set split — those members served by their own linear searches, the rest
// by buckets with no cache at all — compiled beside it, `find` (and the batch
// entry) only, never exported; the exported entries route a cacheless drive to
// it. nil when the set has no such cache to lose.
func noCacheCompanion(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions, primary *compiledSet, cands []splitCand) *compiledSet {
	if !primary.hasFind() || !primary.overlapping || !primary.usesOverlapDP() {
		return nil
	}
	c := spec
	// Internal, and NAMED so: every consumer keyed by a set's name or export
	// name (SetNames, the component resources, the stubs) misses it by
	// construction rather than by each remembering to test cs.internal.
	c.Name = spec.Name + "\x00no-cache"
	c.Find = spec.Find + "\x00no-cache" // never exported
	c.MatchAny, c.MatchAll, c.ScanAny, c.ScanAll = "", "", "", ""
	o := opts
	o.noCache, o.quiet = true, true
	base := max(int64(primary.regionEnd), primary.dataTop())
	o.TableBase = int32(align8(base)) //nolint:gosec // table addresses fit in i32
	comp := compileSetWith(c, prefixPool, suffixPool, o, budgetSplit(cands, spec.Patterns, opts, splitTableBudget), true)
	comp.internal = true
	if primary.diag != nil && comp.diag != nil {
		primary.diag.NoCacheSplitMembers = comp.diag.SplitMembers
		primary.diag.NoCacheSplitBacktracking = comp.diag.SplitBacktracking
	}
	// The companion compiles quietly — its packing repeats the primary's, and
	// so would every warning — but a member it serves by the Backtracking find
	// is the companion's alone, and would otherwise go unmentioned.
	if !opts.quiet && comp.diag != nil {
		for _, id := range comp.diag.SplitBacktracking {
			for k, pid := range spec.PatternIDs {
				if pid == id {
					warnNoCacheOnBacktracking(spec.Patterns[k])
				}
			}
		}
	}
	return comp
}

// warnNoCacheOnBacktracking reports a member the no-cache companion serves by
// the Backtracking find: its start-anywhere find cannot be built, or is past
// the tables' budget.
func warnNoCacheOnBacktracking(p *PatternInfo) {
	ref := patternRefFor(p)
	slog.Warn("Set member runs on Backtracking when no answer cache is offered",
		"pattern", ref.Name, "id", ref.ID,
		"effect", "an overlapping find with no cache (a raw caller, C with -DRX_SET_CACHE=0) searches it with the Backtracking find, which answers 'unknown' when memory cannot grow",
		"hint", "offer the answer cache, as every generated stub does")
}

// setSplitCandidates returns the members the split would serve — those not
// provably linear in a set — and how: the start-anywhere find where it can be
// built for the member, the Backtracking find where it cannot (an empty-width
// assertion, or an automaton over the limits).
func setSplitCandidates(spec SetSpec, opts CompileSetOptions) []splitCand {
	if !spec.HasFind() && spec.ScanAny == "" && spec.ScanAll == "" {
		return nil
	}
	var out []splitCand
	for i, p := range spec.Patterns {
		if !setMemberNeedsSplit(p, opts) {
			continue
		}
		if sa, ok := buildStartAnywherePasses(p.fullPattern, splitPassOpts(p, opts), 0, align8, nil); ok {
			out = append(out, splitCand{idx: i, saBytes: sa.end})
		} else if _, ok := btFindStackSize(p.fullPattern, opts.BTWorkBudget); ok {
			out = append(out, splitCand{idx: i, bt: true})
		}
	}
	return out
}

// setMemberNeedsSplit applies the set's group-A rule — the bounded-walk
// clause, or the set's literal-anchored clause — and reports whether p fails
// it. A member that matches only at 0 is linear; one whose automaton cannot be
// built to be judged is not provably linear.
//
// The automaton is built for the JUDGEMENT under the larger of
// max_fallback_states and splitAnalysisStates: that option bounds the table a
// bucket walks at run time, not what the compiler may examine, and a member it
// puts on a Backtracking bucket (`a+` under max_fallback_states: 1) is still
// linear there when its automaton says so.
func setMemberNeedsSplit(p *PatternInfo, opts CompileSetOptions) bool {
	parsed, err := syntax.Parse(p.fullPattern, syntax.Perl)
	if err != nil {
		return false
	}
	stripCaptures(parsed)
	limit := max(opts.maxFallbackStates(), splitAnalysisStates)
	m, err := compile(p.fullPattern, CompileOptions{MaxDFAStates: limit, ForceEngine: EngineDFA,
		LeftmostFirst: true, ByteMode: p.byteMode})
	if err != nil {
		return true
	}
	t := dfaTableFrom(m.(*dfa))
	if t.numStates > limit {
		return true
	}
	if isAnchoredFind(t) {
		return false
	}
	if _, bounded := failedWalkBound(t); bounded {
		return false
	}
	// The literal clause judges accepts without the context an assertion puts
	// on them, so it does not speak for a member that has one.
	if !hasEmptyWidthAssertion(parsed) && setLiteralMemberLinear(p) {
		return false
	}
	return true
}

// setLiteralMemberLinear is the set's own literal-anchored clause. A member
// placed in a LITERAL bucket is walked only from occurrences of its literal —
// backwards over a fixed-length prefix, forwards over the part after the
// literal. A walk that accepts has matched, and the gate skips the pattern's
// later occurrences inside the match; so what can make the forward walks
// quadratic is ONE walk crossing unboundedly many occurrences without
// accepting. When no walk can, each walk ends within a bounded number of
// occurrences past its own, and each byte is walked a bounded number of
// times. `union[ \t]+k00a+`, `union[ \t]+[a-z]{6}[0-9]{2}` (the literal can be
// read once, in the bounded tail) and `A="[a-z0-9]+"` qualify; `foo[a-z]+bar`
// (the `[a-z]+` loop reads `foo` over and over) does not, and neither does
// `[a-z]+@example\.com`, whose variable-length prefix routes it to a fallback
// bucket.
func setLiteralMemberLinear(p *PatternInfo) bool {
	if p.mandLit == nil || !p.splittable || len(p.mandLit.bytes) == 0 {
		return false
	}
	return !regexpCrossesLiteralUnboundedly(patternSuffixAST(p), p.mandLit.bytes)
}

// maxLiteralCrossingNodes bounds regexpCrossesLiteralUnboundedly's product
// graph; past it the answer is the safe "yes".
const maxLiteralCrossingNodes = 1 << 18

// regexpCrossesLiteralUnboundedly reports whether a walk of re's automaton
// through NON-ACCEPTING states can read lit arbitrarily many times: whether
// the product of those states with a matcher for lit has a cycle containing a
// completed occurrence. Unsure answers are true, the safe direction.
func regexpCrossesLiteralUnboundedly(re *syntax.Regexp, lit []byte) bool {
	// syntax.Compile never returns a non-nil error (see its stdlib source).
	prog, _ := syntax.Compile(re.Simplify())
	d, ok := newDFA(prog, false, false, maxHelperDFAStates)
	if !ok {
		return true
	}
	return dfaCrossesLiteralUnboundedly(dfaTableFrom(d), lit, false)
}

// dfaCrossesLiteralUnboundedly reports whether a walk of t can read lit
// arbitrarily many times: whether the product of t's states with a matcher for
// lit has a cycle containing a completed occurrence. throughAccepts lets the
// walk pass accepting states, as a walk no accept ends does; without it only
// non-accepting states count. Unsure answers are true, the safe direction.
func dfaCrossesLiteralUnboundedly(t *dfaTable, lit []byte, throughAccepts bool) bool {
	L := len(lit)
	if t.numStates*L > maxLiteralCrossingNodes {
		return true
	}
	// The literal matcher: KMP over lit. step[j][c] is the state after c from
	// j (0..L-1); reaching L completes an occurrence and continues from fail[L].
	fail := make([]int, L+1)
	fail[0] = -1
	for i := 1; i <= L; i++ {
		k := fail[i-1]
		for k >= 0 && lit[k] != lit[i-1] {
			k = fail[k]
		}
		fail[i] = k + 1
	}
	next := func(j int, c byte) (int, bool) {
		for j >= 0 && (j == L || lit[j] != c) {
			j = fail[j]
		}
		j++
		if j == L {
			return fail[L], true
		}
		return j, false
	}
	accepting := func(s int) bool {
		return !throughAccepts && (t.midAcceptStates[s] != 0 || t.acceptStates[s] != 0)
	}
	node := func(q, j int) int { return q*L + j }
	// Tarjan's SCC, iteratively, over (state, matcher state) with the state
	// non-accepting; an edge that completes an occurrence inside one SCC is a
	// cycle that reads the literal.
	n := t.numStates * L
	index := make([]int, n)
	low := make([]int, n)
	onStack := make([]bool, n)
	comp := make([]int, n)
	for i := range index {
		index[i], comp[i] = -1, -1
	}
	var stack []int
	counter, ncomp := 0, 0
	type frame struct{ v, c int }
	for root := 0; root < n; root++ {
		if index[root] >= 0 || accepting(root/L) {
			continue
		}
		frames := []frame{{root, 0}}
		index[root], low[root] = counter, counter
		counter++
		stack = append(stack, root)
		onStack[root] = true
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			if f.c < 256 {
				c := f.c
				f.c++
				q, j := f.v/L, f.v%L
				q2 := t.transitions[q*256+c]
				if q2 < 0 || accepting(q2) {
					continue
				}
				j2, _ := next(j, byte(c))
				w := node(q2, j2)
				if index[w] < 0 {
					index[w], low[w] = counter, counter
					counter++
					stack = append(stack, w)
					onStack[w] = true
					frames = append(frames, frame{w, 0})
				} else if onStack[w] && index[w] < low[f.v] {
					low[f.v] = index[w]
				}
				continue
			}
			v := f.v
			frames = frames[:len(frames)-1]
			if len(frames) > 0 {
				if u := frames[len(frames)-1].v; low[v] < low[u] {
					low[u] = low[v]
				}
			}
			if low[v] == index[v] {
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp[w] = ncomp
					if w == v {
						break
					}
				}
				ncomp++
			}
		}
	}
	for v := 0; v < n; v++ {
		if comp[v] < 0 {
			continue
		}
		q, j := v/L, v%L
		for c := 0; c < 256; c++ {
			q2 := t.transitions[q*256+c]
			if q2 < 0 || accepting(q2) {
				continue
			}
			if j2, done := next(j, byte(c)); done && comp[node(q2, j2)] == comp[v] {
				return true
			}
		}
	}
	return false
}

// splitPassOpts is the CompileOptions a split member's two passes are built
// under: the set's state ceiling, and the member's own byte mode.
func splitPassOpts(p *PatternInfo, opts CompileSetOptions) CompileOptions {
	return CompileOptions{MaxDFAStates: opts.maxFallbackStates(), ByteMode: p.byteMode, tableMemIdx: opts.TableMemIdx}
}

func align8(v int64) int64 { return (v + 7) &^ 7 }

// keepsOnDFA filters cands to the members this (unsplit) compile placed in a
// bucket. A member it dropped stays dropped: splitting it out would make the
// set report a pattern it does not otherwise serve. A member it put on a
// Backtracking bucket is split out on the Backtracking find: the bucket's
// visited set lasts one host call, so a drive whose other members match often
// re-walks the member's long failed walks on every call, while the merge's
// lower bound retires a member that cannot match.
func (cs *compiledSet) keepsOnDFA(spec SetSpec, cands []splitCand) []splitCand {
	inBucket, onBT := map[int]bool{}, map[int]bool{}
	for bi, bkt := range cs.buckets {
		for _, id := range cs.patternIDs[bi] {
			inBucket[id] = true
			if bkt.btFallback != nil {
				onBT[id] = true
			}
		}
	}
	var out []splitCand
	for _, c := range cands {
		id := spec.PatternIDs[c.idx]
		if !inBucket[id] {
			continue
		}
		if onBT[id] {
			c.bt = true
		}
		out = append(out, c)
	}
	return out
}

// needsSplit reports whether one of the unsplit set's non-anchored
// capabilities has nothing that makes it linear.
func (cs *compiledSet) needsSplit() bool {
	if cs.gatedFind() {
		return true
	}
	if cs.hasFind() && cs.overlapping && !cs.usesOverlapDP() {
		return true
	}
	for _, kind := range []setCapKind{capScanAny, capScanAll} {
		if cs.capName(kind) != "" && !cs.usesUnionScan(kind) && !cs.scanSwitch(kind) {
			return true
		}
	}
	return false
}

// capName is the export name of a scan capability, "" when not declared. Any
// other kind is a caller's mistake, refused rather than answered with a scan
// capability's name.
func (cs *compiledSet) capName(kind setCapKind) string {
	switch kind {
	case capScanAny:
		return cs.scanAny
	case capScanAll:
		return cs.scanAll
	}
	panic(fmt.Sprintf("compile: capName asked for capability %d, which is not a scan", kind))
}

// clone returns an independent copy of the allocator.
func (g *moduleGlobals) clone() *moduleGlobals {
	c := *g
	if g.inits != nil {
		c.inits = make(map[uint32]int32, len(g.inits))
		for k, v := range g.inits {
			c.inits[k] = v
		}
	}
	if g.i64 != nil {
		c.i64 = make(map[uint32]int64, len(g.i64))
		for k, v := range g.i64 {
			c.i64[k] = v
		}
	}
	return &c
}

// ── The scan pair's own union automaton ──────────────────────────────────

// scanUnionPlan is what planScanUnion decided.
type scanUnionPlan struct {
	target *SetSpec // the members the automaton covers; nil = none
	direct bool     // it IS the scan pair's body (members are split out)
	// counter: the frontend's scan bodies count their probes' walks and
	// switch to the automaton; their probes must stamp how far they walked.
	counter bool
}

// planScanUnion decides the scan pair's union automaton, by a trial build.
//
//   - Members split out: a union over EVERY member answers the scan pair on
//     its own — one linear pass, where the kept body plus one forward pass
//     per split member would cost a pass each.
//   - Otherwise, on a set with literal buckets and a member that is not
//     provably linear: a union over the set is what the frontend's work
//     counter switches to. A literal-less set is served by unionScan already.
//
// Whether the counter is actually emitted is settled later (buildScanUnion),
// once the frontend is final; this decides whether the probes stamp.
func planScanUnion(full, kept SetSpec, split []int, buckets []*bucket, nonLinear, btSplit bool) scanUnionPlan {
	if !nonLinear || (full.ScanAny == "" && full.ScanAll == "") {
		return scanUnionPlan{}
	}
	wide := setWideAll(full, buckets) || btSplit
	if len(split) > 0 && unionServesScan(buildUnionScanDFA(full, 0, false), full, wide) {
		return scanUnionPlan{target: &full, direct: true}
	}
	if len(kept.Patterns) == 0 || !hasLiteralBuckets(buckets) {
		return scanUnionPlan{}
	}
	if unionServesScan(buildUnionScanDFA(kept, 0, false), kept, wide) {
		return scanUnionPlan{target: &kept, counter: true}
	}
	return scanUnionPlan{}
}

// setWideAll is compiledSet.wideAll before the set exists.
func setWideAll(spec SetSpec, buckets []*bucket) bool {
	idSpace := spec.IDSpaceSize
	if idSpace <= 0 {
		for _, id := range spec.PatternIDs {
			if id+1 > idSpace {
				idSpace = id + 1
			}
		}
	}
	return idSpace > wideBitmapThreshold || hasBTBucketIn(buckets)
}

// unionServesScan reports whether u can answer every scan capability spec
// declares under the `_all` ABI wide selects — usesUnionScan's rule.
func unionServesScan(u *unionScanDFA, spec SetSpec, wide bool) bool {
	if u == nil {
		return false
	}
	if spec.ScanAll == "" {
		return true
	}
	if u.isWide() {
		return wide && u.midWordsOff >= 0
	}
	return !wide
}

// buildScanUnion builds the planned automaton at its real address, and
// allocates the counter's global when the frontend the set ended up with
// needs one.
func (cs *compiledSet) buildScanUnion(plan scanUnionPlan, ra *regionAlloc, opts CompileSetOptions) {
	if plan.target == nil {
		return
	}
	if plan.counter {
		served := true
		for _, kind := range []setCapKind{capScanAny, capScanAll} {
			if cs.capName(kind) != "" && !cs.usesUnionScan(kind) {
				served = false
			}
		}
		if served {
			return
		}
	}
	base := ra.Reserve("scan-union", 8)
	u := buildUnionScanDFA(*plan.target, base, false)
	if u == nil {
		// planScanUnion built the same automaton, so this cannot happen.
		panic("compile: the scan pair's union automaton was planned and then refused")
	}
	if u.tableEnd > base {
		ra.Commit(u.tableEnd)
	} else {
		ra.Skip()
	}
	cs.scanUnion = u
	cs.scanUnionDirect = plan.direct
	for _, id := range plan.target.PatternIDs {
		if id < 64 {
			cs.scanUnionMask |= 1 << uint(id)
		}
	}
	if plan.counter {
		cs.scanSwWork = int32(opts.globals.AllocI64(0)) //nolint:gosec // a global index; i64, see emitAddWalk
		if cs.scanAll != "" {
			cs.scanSwMark = int32(opts.globals.AllocI64(0)) //nolint:gosec // a global index
		}
	}
	cs.diag.ScanUnion = &ScanUnionDiag{Direct: plan.direct, Counter: plan.counter,
		States: u.numStates, Wide: u.isWide()}
}

// scanSwitch reports whether kind's bucket body carries the work counter
// that switches to the scan pair's union automaton.
func (cs *compiledSet) scanSwitch(kind setCapKind) bool {
	return (kind == capScanAny || kind == capScanAll) && cs.capName(kind) != "" &&
		cs.scanUnion != nil && !cs.scanUnionDirect && cs.scanSwWork >= 0 && !cs.usesUnionScan(kind)
}

// ── Split members ─────────────────────────────────────────────────────────

// buildSplitMembers builds the split members' two passes, laying their tables
// out through ra, and the global the kept body reports its position in.
func (cs *compiledSet) buildSplitMembers(full SetSpec, split []splitCand, ra *regionAlloc, opts CompileSetOptions) {
	if len(split) == 0 {
		return
	}
	// One frame stack for every Backtracking member: the merge wrappers call
	// one member at a time, and nothing else runs a member's find.
	var stack *[2]int32
	maxStack := 0
	for _, c := range split {
		if c.bt {
			size, _ := btFindStackSize(full.Patterns[c.idx].fullPattern, opts.BTWorkBudget)
			maxStack = max(maxStack, size)
			stack = &[2]int32{}
		}
	}
	if stack != nil {
		base := ra.Reserve("split-bt-stack", 8)
		ra.Commit(base + int32(maxStack)) //nolint:gosec // a stack size
		stack[0], stack[1] = base, base+int32(maxStack)
		if maxStack > 0 {
			// Declare the stack in the data section, as planBTRegions does:
			// callers find free memory from the emitted segments, and an
			// input placed on an undeclared stack is silent corruption.
			cs.splitData = append(cs.splitData, appendDataSegment(nil, stack[1]-1, []byte{0})...)
			cs.splitSegs++
		}
	}
	for _, c := range split {
		p := full.Patterns[c.idx]
		if c.bt {
			base := ra.Reserve("split-bt-member", 8)
			// Its budget lasts the member's search, across the set's calls,
			// in the member's own block, as a pattern's find keeps it.
			o := CompileOptions{ByteMode: p.byteMode, LikelyMode: opts.LikelyMode, BTWorkBudget: opts.BTWorkBudget,
				tableMemIdx: opts.TableMemIdx, globals: opts.globals}
			bt, err := buildBTFindParts(p.fullPattern, nil, findMandatoryLit(p.fullPattern, p.byteMode), int64(base), &o, stack)
			if err != nil {
				panic("compile: a split member Backtracking was classified to take refused it: " + err.Error())
			}
			ra.Commit(int32(bt.end)) //nolint:gosec // table addresses fit in i32
			cs.split = append(cs.split, splitMember{id: full.PatternIDs[c.idx], bt: &bt})
			cs.splitData = append(cs.splitData, bt.data...)
			cs.splitSegs += bt.segs
			continue
		}
		base := ra.Reserve("split-member", 8)
		// The member's own search, across the set's calls, keeps notes in a
		// block of its own (D5: the overrun member stays split, its search
		// counter-armed).
		var nr *walkNotesReq
		if opts.globals != nil {
			nr = &walkNotesReq{globals: opts.globals}
		}
		sa, ok := buildStartAnywherePasses(p.fullPattern, splitPassOpts(p, opts), int64(base), align8, nr)
		if !ok {
			panic("compile: a split member's start-anywhere find was classified buildable and then refused")
		}
		ra.Commit(int32(sa.end)) //nolint:gosec // table addresses fit in i32
		cs.split = append(cs.split, splitMember{id: full.PatternIDs[c.idx], fwdBody: sa.fwdBody, revBody: sa.revBody, ctx: sa.ctx, notes: sa.fwdNotes})
		cs.splitData = append(cs.splitData, sa.data...)
		cs.splitSegs += sa.segs
	}
	cs.mergeState = -1
	if len(cs.split) > splitMergeLocalMembers {
		// The merge's per-member state, in the table memory rather than in
		// four locals per member (mergeSlots).
		base := ra.Reserve("split-merge-state", 8)
		end := base + int32(len(cs.split)*splitMergeSlotBytes) //nolint:gosec // a small size
		ra.Commit(end)
		cs.mergeState = base
		// Declared in the data section, as the frame stack above is.
		cs.splitData = append(cs.splitData, appendDataSegment(nil, end-1, []byte{0})...)
		cs.splitSegs++
	}
	if cs.splitBlocks() {
		cs.splitSearch = opts.globals.Search()
		if cs.mergedWorker() {
			cs.splitBlocksGlobal = opts.globals.Alloc()
		}
	}
	cs.keptEmpty = len(cs.patternIDs) == 0
	if cs.hasFind() && !cs.keptEmpty {
		cs.keptPosGlobal = int32(opts.globals.Alloc()) //nolint:gosec // a global index
	}
}

// mergedCap reports whether kind's export is a merge wrapper over the kept
// body and the split members. A batching set's `find` is not: its export stays
// the wrapper over the shared worker, and the worker is merged instead
// (mergedWorker).
func (cs *compiledSet) mergedCap(kind setCapKind) bool {
	if len(cs.split) == 0 {
		return false
	}
	switch kind {
	case capFind:
		return !cs.batchFind
	case capScanAny, capScanAll:
		return !cs.scanUnionDirect
	}
	return false
}

// mergedWorker reports whether the shared per-position worker of a batching
// set is a merge over the bucket worker and the split members.
func (cs *compiledSet) mergedWorker() bool { return len(cs.split) > 0 && cs.batchFind }

// keptIDs is every global id the buckets serve.
func (cs *compiledSet) keptIDs() []int { return setPatternIDs(cs) }

// ── Function layout: appended after the Backtracking drivers ─────────────

// extraFnBaseOffset is the first function after the Backtracking drivers,
// where everything this file adds sits — so none of it moves an existing
// sub-index.
func (cs *compiledSet) extraFnBaseOffset() int { return cs.btFnBaseOffset() + cs.numBTFns }

// keptCaps is the merged capabilities that call a kept body, in capFns order.
func (cs *compiledSet) keptCaps() []setCapFn {
	if cs.keptEmpty {
		return nil
	}
	var out []setCapFn
	for _, c := range cs.capFns() {
		if cs.mergedCap(c.kind) {
			out = append(out, c)
		}
	}
	return out
}

// switchCaps is the scan capabilities carrying the counter, in capFns order.
func (cs *compiledSet) switchCaps() []setCapFn {
	var out []setCapFn
	for _, c := range cs.capFns() {
		if cs.scanSwitch(c.kind) {
			out = append(out, c)
		}
	}
	return out
}

// keptFnOffset is the index of kind's kept body, or -1.
func (cs *compiledSet) keptFnOffset(kind setCapKind) int {
	for i, c := range cs.keptCaps() {
		if c.kind == kind {
			return cs.extraFnBaseOffset() + i
		}
	}
	return -1
}

// keptWorkerFnOffset is the index of the bucket worker a merged worker calls,
// or -1. It follows the kept capability bodies.
func (cs *compiledSet) keptWorkerFnOffset() int {
	if !cs.mergedWorker() || cs.keptEmpty {
		return -1
	}
	return cs.extraFnBaseOffset() + len(cs.keptCaps())
}

// keptWorkerCount is 1 when the kept worker exists, else 0.
func (cs *compiledSet) keptWorkerCount() int {
	if cs.keptWorkerFnOffset() >= 0 {
		return 1
	}
	return 0
}

// scanSwitchFnOffset is the index of the union body kind's counter switches
// to, or -1.
func (cs *compiledSet) scanSwitchFnOffset(kind setCapKind) int {
	for i, c := range cs.switchCaps() {
		if c.kind == kind {
			return cs.extraFnBaseOffset() + len(cs.keptCaps()) + cs.keptWorkerCount() + i
		}
	}
	return -1
}

// splitFnCount is how many functions member i contributes: its two passes,
// or its Backtracking find and — when it has one — that find's fallback.
func (cs *compiledSet) splitFnCount(i int) int {
	if bt := cs.split[i].bt; bt != nil {
		if bt.fallback != nil {
			return 2
		}
		return 1
	}
	return 2
}

// splitFwdOffset is member i's first function: its forward pass, or its
// Backtracking find. splitRevOffset is a start-anywhere member's backward
// pass, right after.
func (cs *compiledSet) splitFwdOffset(i int) int {
	off := cs.extraFnBaseOffset() + len(cs.keptCaps()) + cs.keptWorkerCount() + len(cs.switchCaps())
	for j := 0; j < i; j++ {
		off += cs.splitFnCount(j)
	}
	return off
}
func (cs *compiledSet) splitRevOffset(i int) int { return cs.splitFwdOffset(i) + 1 }

// extraFnCount is how many functions this file adds.
func (cs *compiledSet) extraFnCount() int {
	n := len(cs.keptCaps()) + cs.keptWorkerCount() + len(cs.switchCaps())
	for i := range cs.split {
		n += cs.splitFnCount(i)
	}
	return n
}

// extraFnTypes lists the added functions' type indices, in layout order.
func (cs *compiledSet) extraFnTypes() []byte {
	var out []byte
	for _, c := range cs.keptCaps() {
		out = append(out, c.typeIdx)
	}
	if cs.keptWorkerCount() > 0 {
		out = append(out, byte(cs.workerTypeIdx()))
	}
	for _, c := range cs.switchCaps() {
		out = append(out, c.typeIdx)
	}
	for i, sm := range cs.split {
		if sm.bt != nil {
			for j := 0; j < cs.splitFnCount(i); j++ {
				out = append(out, setTypeI32I32ToI64)
			}
			continue
		}
		if sm.ctx {
			out = append(out, setTypeI32I32ToI32, setTypeI32x3ToI32)
			continue
		}
		out = append(out, setTypeI32I32ToI32, setTypeI32I32ToI32)
	}
	return out
}

// scanUnionBody is the union automaton's body for a scan capability.
func (cs *compiledSet) scanUnionBody(kind setCapKind, tableMemIdx int) []byte {
	if cs.scanUnion.isWide() {
		return emitUnionScanWideBody(cs.scanUnion, kind, tableMemIdx, cs.unionSkipLNM)
	}
	return emitUnionScanBody(cs.scanUnion, kind, cs.scanUnionMask, tableMemIdx, cs.unionSkipLNM)
}

// ── The merge wrappers ────────────────────────────────────────────────────

// emitSplitFindBody is a split set's exported `find`: the kept body (keptIdx,
// -1 for none) merged with the split members' start-anywhere finds (fwd[i],
// rev[i]). Same signature and contract as the kept body. See the file header
// for the algorithm; the transactional rule is `find`'s: a position that does
// not fit records no gate for any pattern, kept or split.
//
// worker selects the other shape: the per-position WORKER a batching set's
// `find` and batch entry share, merged the same way. It
// takes the gate pointer itself rather than the descriptor, calls the kept
// WORKER, and carries the worker's trailing argument through the batch
// resume rules: gated, `batch_mode` — 1 records a gate for every match
// DELIVERED (index < cap) even when the position overflows, so re-entering
// the position yields exactly the rest; overlapping, `skip` — the first k
// matches of the position are not written. Within a position the kept
// buckets' matches come first, then the split members' in id order, so a
// match's index is the same on every call.
func emitSplitFindBody(cs *compiledSet, keptIdx int, fwd, rev []int, worker bool) []byte {
	const (
		pPtr = iota
		pLen
		pFrom
		pDesc // the gate pointer itself when worker
		pOut
		pCap
		pMode // worker only: batch_mode (gated) or skip (overlapping)
	)
	nparams := uint32(6)
	if worker {
		nparams = 7
	}
	gated := cs.gatedFind()
	m := len(cs.split)
	a := newLocalAlloc(nparams)
	lGate, lK, lS, lR := a.I32(), a.I32(), a.I32(), a.I32()
	lU := a.I32() // how many of the kept body's report gates to undo
	lKeptPos, lKeptDone, lBest, lBestLb := a.I32(), a.I32(), a.I32(), a.I32()
	lQ, lE, lSt, lN, lIdx, lTmp, lDead, lV := a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32()
	// The members' search blocks, and the search global's value at entry,
	// restored after every member call: the global belongs to whoever calls
	// the module next. Byte-indexed, so allocated before the per-member
	// locals, whose count grows with the set.
	notes := cs.splitBlocks()
	var lBlocks, lSaved byte
	if notes {
		lBlocks, lSaved = a.I32(), a.I32()
	}
	// Four values per member — its lower bound, the start and end of its
	// answer, its done flag — in four locals each, or past
	// splitMergeLocalMembers in the set's merge state region; every
	// reference to one goes through lw.
	lLb, lSk, lTk, lDone := make([]mslot, m), make([]mslot, m), make([]mslot, m), make([]mslot, m)
	var lSlot byte
	if cs.mergeState >= 0 {
		lSlot = a.I32()
		for k := 0; k < m; k++ {
			at := uint32(cs.mergeState) + uint32(k*splitMergeSlotBytes) //nolint:gosec // a table address
			lLb[k], lSk[k], lTk[k], lDone[k] = mslot{mem: true, addr: at}, mslot{mem: true, addr: at + 4},
				mslot{mem: true, addr: at + 8}, mslot{mem: true, addr: at + 12}
		}
	} else {
		for k := 0; k < m; k++ {
			lLb[k], lSk[k], lTk[k], lDone[k] = mslot{local: a.I32W()}, mslot{local: a.I32W()}, mslot{local: a.I32W()}, mslot{local: a.I32W()}
		}
	}
	// A Backtracking member's search answers one i64: (start << 32) | end.
	var lR64 mslot
	for _, sm := range cs.split {
		if sm.bt != nil {
			lR64 = mslot{local: a.I64W()}
			break
		}
	}
	lw := func(b []byte, op byte, s mslot) []byte {
		if !s.mem {
			return utils.AppendULEB128(append(b, op), s.local)
		}
		switch op {
		case 0x20: // get
			return appendTableLoad32(append(b, 0x41, 0x00), cs.tableMemIdx, s.addr)
		case 0x21: // set
			b = append(b, 0x21, lSlot, 0x41, 0x00, 0x20, lSlot)
			return appendTableStore32(b, cs.tableMemIdx, s.addr)
		default: // tee
			b = append(b, 0x21, lSlot, 0x41, 0x00, 0x20, lSlot)
			b = appendTableStore32(b, cs.tableMemIdx, s.addr)
			return append(b, 0x20, lSlot)
		}
	}
	// pushSkip pushes how many of the position's first matches are not
	// written: the overlapping worker's `skip`, 0 everywhere else.
	pushSkip := func(b []byte) []byte {
		if worker && !gated {
			return append(b, 0x20, pMode)
		}
		return append(b, 0x41, 0x00)
	}
	// setUndo sets lU: the kept body's report gates are recorded for the
	// matches it DELIVERED under batch_mode, for the whole position or none
	// otherwise (`find`'s transactional rule).
	setUndo := func(b []byte) []byte {
		if worker {
			// batch_mode: min(r, cap) — select's first operand wins when
			// the mode is non-zero.
			b = append(b, 0x20, lR, 0x20, pCap, 0x20, lR, 0x20, pCap, 0x49, 0x1B)
		}
		b = append(b, 0x20, lR, 0x20, pCap, 0x4C) // r <= cap
		b = append(b, 0x04, 0x7F, 0x20, lR, 0x05, 0x41, 0x00, 0x0B)
		if worker {
			b = append(b, 0x20, pMode, 0x1B)
		}
		return append(b, 0x21, lU)
	}
	kept := keptIdx >= 0
	keptIDs := cs.keptIDs()
	loadGate := func(b []byte, id int) []byte {
		b = append(b, 0x20, lGate, 0x28, 0x02)
		return utils.AppendULEB128(b, uint32(id*4)) //nolint:gosec // an id offset
	}
	storeGate := func(b []byte, id int, val func([]byte) []byte) []byte {
		b = append(b, 0x20, lGate)
		b = val(b)
		b = append(b, 0x36, 0x02)
		return utils.AppendULEB128(b, uint32(id*4)) //nolint:gosec // an id offset
	}
	// gate[id] = max(gate[id], local v), unsigned.
	raiseGate := func(b []byte, id int, v byte) []byte {
		b = loadGate(b, id)
		b = append(b, 0x20, v, 0x49, 0x04, 0x40) // gate < v
		b = storeGate(b, id, func(b []byte) []byte { return append(b, 0x20, v) })
		return append(b, 0x0B)
	}
	// For the first lU tuples the kept body wrote, gate[id] = local v: undoes
	// the report gates it recorded for them.
	undoKept := func(b []byte, v byte) []byte {
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = append(b, 0x02, 0x40, 0x03, 0x40) // block, loop
		b = append(b, 0x20, lIdx, 0x20, lU, 0x4E, 0x0D, 0x01)
		b = append(b, 0x20, lGate)
		b = append(b, 0x20, pOut, 0x20, lIdx, 0x41, abi.SetMatchTupleBytes, 0x6C, 0x6A)
		b = append(b, 0x28, 0x02, 0x00) // id
		b = append(b, 0x41, 0x02, 0x74, 0x6A)
		b = append(b, 0x20, v, 0x36, 0x02, 0x00)
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x0C, 0x00, 0x0B, 0x0B)
		return b
	}

	var b []byte
	b = a.EmitDecls(b)

	if worker {
		b = append(b, 0x20, pDesc, 0x21, lGate)
		if notes {
			// The wrapper in front of the worker read the descriptor.
			b = append(b, 0x23)
			b = utils.AppendULEB128(b, cs.splitBlocksGlobal)
			b = append(b, 0x21, lBlocks)
		}
	} else {
		// The descriptor: check the magic, take the gate pointer.
		b = cs.emitScratchMagicCheck(b, pDesc, lTmp)
		b = append(b, 0x20, pDesc, 0x28, 0x02, abi.FindScratchGateOff, 0x21, lGate)
		if notes {
			b = emitScratchBlocks(b, pDesc)
			if base := cs.blocksBase(); base > 0 {
				// Past the blocks before the set's own, or 0 with no blocks.
				b = append(b, 0x22, lBlocks, 0x41)
				b = utils.AppendSLEB128(b, int32(base*abi.SearchBlockBytes)) //nolint:gosec // a small offset
				b = append(b, 0x6A, 0x41, 0x00, 0x20, lBlocks, 0x1B)
			}
			b = append(b, 0x21, lBlocks)
		}
	}
	if notes {
		b = append(b, 0x23)
		b = utils.AppendULEB128(b, cs.splitSearch)
		b = append(b, 0x21, lSaved)
	}
	// from > len answers nothing.
	b = append(b, 0x20, pFrom, 0x20, pLen, 0x4B, 0x04, 0x40, 0x41, 0x00, 0x0F, 0x0B)
	b = append(b, 0x20, pLen, 0x41, 0x01, 0x74, 0x41, 0x02, 0x6A, 0x21, lDead) // 2*len + 2

	// K: nothing kept starts before max(from, min gate >> 1).
	b = append(b, 0x41, 0x7F, 0x21, lK)
	if kept {
		for _, id := range keptIDs {
			b = loadGate(b, id)
			b = append(b, 0x41, 0x01, 0x76, 0x22, lTmp) // >> 1
			b = append(b, 0x20, lK, 0x49, 0x04, 0x40, 0x20, lTmp, 0x21, lK, 0x0B)
		}
		b = append(b, 0x20, lK, 0x20, pFrom, 0x49, 0x04, 0x40, 0x20, pFrom, 0x21, lK, 0x0B)
	}
	// Each split member's lower bound, and its done flag.
	for k, sm := range cs.split {
		b = loadGate(b, sm.id)
		b = lw(append(b, 0x41, 0x01, 0x76), 0x22, lLb[k])
		b = append(lw(append(b, 0x20, pFrom, 0x49, 0x04, 0x40, 0x20, pFrom), 0x21, lLb[k]), 0x0B)
		b = lw(append(b, 0x41, 0x00), 0x21, lDone[k])
		b = lw(append(b, 0x41, 0x7F), 0x21, lSk[k])
	}
	b = append(b, 0x41, 0x7F, 0x21, lS)
	b = append(b, 0x41, 0x00, 0x21, lR)
	b = append(b, 0x41, 0x7F, 0x21, lKeptPos)
	if kept {
		b = append(b, 0x41, 0x00, 0x21, lKeptDone)
	} else {
		b = append(b, 0x41, 0x01, 0x21, lKeptDone)
	}

	// The selection loop: process the unprocessed candidate with the smallest
	// lower bound, while that bound is at or before the best start so far.
	b = append(b, 0x02, 0x40, 0x03, 0x40) // block $exit, loop $sel
	b = append(b, 0x41, 0x7F, 0x21, lBest, 0x41, 0x7F, 0x21, lBestLb)
	consider := func(b []byte, doneLocal, lbLocal mslot, idx int32) []byte {
		b = append(lw(b, 0x20, doneLocal), 0x45)
		b = append(lw(b, 0x20, lbLocal), 0x20, lS, 0x4D, 0x71) // lb <= S
		b = append(lw(b, 0x20, lbLocal), 0x20, lBestLb, 0x49, 0x71)
		b = append(b, 0x04, 0x40, 0x41)
		b = utils.AppendSLEB128(b, idx)
		b = append(lw(append(b, 0x21, lBest), 0x20, lbLocal), 0x21, lBestLb, 0x0B)
		return b
	}
	if kept {
		b = consider(b, mslot{local: uint32(lKeptDone)}, mslot{local: uint32(lK)}, int32(m)) //nolint:gosec // a small count
	}
	for k := 0; k < m; k++ {
		b = consider(b, lDone[k], lLb[k], int32(k)) //nolint:gosec // a small count
	}
	b = append(b, 0x20, lBest, 0x41, 0x7F, 0x46, 0x0D, 0x01) // none → $exit

	if kept {
		b = append(b, 0x20, lBest, 0x41)
		b = utils.AppendSLEB128(b, int32(m)) //nolint:gosec // a small count
		b = append(b, 0x46, 0x04, 0x40)
		b = append(b, 0x20, pPtr, 0x20, pLen, 0x20, lK, 0x20, pDesc, 0x20, pOut, 0x20, pCap)
		if worker {
			b = append(b, 0x20, pMode)
		}
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(keptIdx))                                 //nolint:gosec // a function index
		b = append(b, 0x22, lR, 0x41, 0x00, 0x48, 0x04, 0x40, 0x20, lR, 0x0F, 0x0B) // error: pass it on
		b = append(b, 0x41, 0x01, 0x21, lKeptDone)
		b = append(b, 0x20, lR, 0x04, 0x40)
		b = append(b, 0x23)
		b = utils.AppendULEB128(b, uint32(cs.keptPosGlobal)) //nolint:gosec // a global index
		b = append(b, 0x22, lKeptPos, 0x20, lS, 0x49, 0x04, 0x40, 0x20, lKeptPos, 0x21, lS, 0x0B)
		b = append(b, 0x0B)
		b = append(b, 0x0C, 0x01, 0x0B) // continue $sel; end if
	}
	for k, sm := range cs.split {
		b = append(b, 0x20, lBest, 0x41)
		b = utils.AppendSLEB128(b, int32(k)) //nolint:gosec // a small count
		b = append(b, 0x46, 0x04, 0x40)
		b = lw(append(b, 0x41, 0x01), 0x21, lDone[k])
		b = append(lw(b, 0x20, lLb[k]), 0x21, lQ)
		b = append(b, 0x02, 0x40, 0x03, 0x40) // block $found, loop $retry
		if sm.bt != nil {
			// The Backtracking find from q: (start << 32) | end, -1 for no
			// match, or its "gave up" error, which is this call's answer.
			b = append(b, 0x20, lQ, 0x20, pLen, 0x4B)
			b = append(b, 0x04, 0x7E, 0x42, 0x7F, 0x05) // if (i64) -1 else
			b = append(b, 0x20, lQ)
			b = emitFindFromSetFromStack(b)
			b = cs.emitMemberBlock(b, k, lBlocks)
			b = append(b, 0x20, pPtr, 0x20, pLen, 0x10)
			b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
			b = cs.emitRestoreSearch(b, k, lSaved)
			b = append(b, 0x0B)
			b = lw(b, 0x22, lR64)
			b = append(b, 0x42, 0x00, 0x53, 0x04, 0x40) // r < 0
			b = append(lw(b, 0x20, lR64), 0x42, 0x7F, 0x53, 0x04, 0x40)
			b = append(lw(b, 0x20, lR64), 0xA7, 0x0F, 0x0B) // r < -1: pass the error on
			b = storeGate(b, sm.id, func(b []byte) []byte { return append(b, 0x20, lDead) })
			b = append(b, 0x0C, 0x02, 0x0B) // br $found (with sk = -1)
			b = append(lw(b, 0x20, lR64), 0x42, 0x20, 0x88, 0xA7, 0x21, lSt)
			b = append(lw(b, 0x20, lR64), 0xA7, 0x21, lE)
		} else if sm.ctx {
			// The context passes: both read the whole input, the forward one
			// from q and the backward one down to q, through the global.
			b = append(b, 0x20, lQ, 0x20, pLen, 0x4B)
			b = append(b, 0x04, 0x7F, 0x41, 0x7F, 0x05)
			b = append(b, 0x20, lQ)
			b = emitFindFromSetFromStack(b)
			b = cs.emitMemberBlock(b, k, lBlocks)
			b = append(b, 0x20, pPtr, 0x20, pLen, 0x10)
			b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
			b = cs.emitRestoreSearch(b, k, lSaved)
			b = append(b, 0x0B)
			b = append(b, 0x22, lE, 0x41, 0x00, 0x48, 0x04, 0x40)
			b = storeGate(b, sm.id, func(b []byte) []byte { return append(b, 0x20, lDead) })
			b = append(b, 0x0C, 0x02, 0x0B) // br $found (with sk = -1)
			b = append(b, 0x20, pPtr, 0x20, pLen, 0x20, lE, 0x10)
			b = utils.AppendULEB128(b, uint32(rev[k]))                         //nolint:gosec // a function index
			b = append(b, 0x22, lSt, 0x41, 0x00, 0x48, 0x04, 0x40, 0x00, 0x0B) // the forward pass proved a match
		} else {
			// Past the end, or no match from q: the member is done for the drive.
			b = append(b, 0x20, lQ, 0x20, pLen, 0x4B)
			b = append(b, 0x04, 0x7F, 0x41, 0x7F, 0x05)
			if sm.notes != nil {
				// The pass is handed input[q:]; it reads q from the global.
				b = append(b, 0x20, lQ)
				b = emitFindFromSetFromStack(b)
			}
			b = cs.emitMemberBlock(b, k, lBlocks)
			b = append(b, 0x20, pPtr, 0x20, lQ, 0x6A, 0x20, pLen, 0x20, lQ, 0x6B, 0x10)
			b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
			b = cs.emitRestoreSearch(b, k, lSaved)
			b = append(b, 0x0B)
			b = append(b, 0x22, lE, 0x41, 0x00, 0x48, 0x04, 0x40)
			b = storeGate(b, sm.id, func(b []byte) []byte { return append(b, 0x20, lDead) })
			b = append(b, 0x0C, 0x02, 0x0B) // br $found (with sk = -1)
			b = append(b, 0x20, lE, 0x20, lQ, 0x6A, 0x21, lE)
			b = append(b, 0x20, lQ)
			b = emitFindFromSetFromStack(b)
			b = append(b, 0x20, pPtr, 0x20, lE, 0x41, 0x01, 0x6B, 0x10)
			b = utils.AppendULEB128(b, uint32(rev[k]))                         //nolint:gosec // a function index
			b = append(b, 0x22, lSt, 0x41, 0x00, 0x48, 0x04, 0x40, 0x00, 0x0B) // the forward pass proved a match
		}
		if gated {
			// An empty match where the gate forbids one (right after this
			// member's previous match): the next start may still match.
			b = append(b, 0x20, lSt, 0x20, lE, 0x46)
			b = append(b, 0x20, lSt, 0x41, 0x01, 0x74)
			b = loadGate(b, sm.id)
			b = append(b, 0x49, 0x71, 0x04, 0x40)                                  // 2s < gate
			b = append(b, 0x20, lSt, 0x41, 0x01, 0x6A, 0x21, lQ, 0x0C, 0x01, 0x0B) // retry
		}
		b = lw(append(lw(append(b, 0x20, lSt), 0x21, lSk[k]), 0x20, lE), 0x21, lTk[k])
		b = append(b, 0x20, lSt, 0x41, 0x01, 0x74, 0x21, lV)
		b = raiseGate(b, sm.id, lV)
		b = append(b, 0x20, lSt, 0x20, lS, 0x49, 0x04, 0x40, 0x20, lSt, 0x21, lS, 0x0B)
		b = append(b, 0x0B, 0x0B)       // end loop $retry, end block $found
		b = append(b, 0x0C, 0x01, 0x0B) // continue $sel; end if
	}
	b = append(b, 0x0B, 0x0B) // end loop $sel, end block $exit

	// The kept body's answer lost, or it had none: raise every kept gate to
	// what it proved. Its report gates, recorded when its position fitted,
	// are undone first — the position was not the answer.
	if kept {
		b = append(b, 0x20, lKeptDone, 0x20, lR, 0x45, 0x71, 0x04, 0x40) // processed, no match
		for _, id := range keptIDs {
			b = storeGate(b, id, func(b []byte) []byte { return append(b, 0x20, lDead) })
		}
		b = append(b, 0x0B)
		b = append(b, 0x20, lR, 0x41, 0x00, 0x4A, 0x20, lKeptPos, 0x20, lS, 0x47, 0x71, 0x04, 0x40)
		b = append(b, 0x20, lKeptPos, 0x41, 0x01, 0x74, 0x21, lV)
		if gated {
			b = setUndo(b)
			b = undoKept(b, lV)
		}
		for _, id := range keptIDs {
			b = raiseGate(b, id, lV)
		}
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, lS, 0x41, 0x7F, 0x46, 0x04, 0x40, 0x41, 0x00, 0x0F, 0x0B) // nothing anywhere

	// The answer is the matches at S: the kept body's when its position is S,
	// then every split member whose next match starts there.
	// lIdx is a match's index within the position — kept matches first — and
	// a split member's match is written at out[lIdx] when skip <= lIdx < cap.
	b = append(b, 0x41, 0x00, 0x21, lIdx, 0x41, 0x00, 0x21, lN)
	if kept {
		b = append(b, 0x20, lR, 0x41, 0x00, 0x4A, 0x20, lKeptPos, 0x20, lS, 0x46, 0x71, 0x04, 0x40)
		b = append(b, 0x20, lR, 0x21, lN, 0x20, lR, 0x21, lIdx)
		b = append(b, 0x05, 0x41, 0x00, 0x21, lR, 0x0B) // else: none of its tuples count
	}
	reportGate := func(b []byte, k int, id int) []byte {
		return storeGate(b, id, func(b []byte) []byte {
			b = append(lw(b, 0x20, lTk[k]), 0x41, 0x01, 0x74)
			b = append(lw(lw(append(b, 0x41, 0x01, 0x41, 0x02), 0x20, lTk[k]), 0x20, lSk[k]), 0x4A, 0x1B, 0x6A)
			return b
		})
	}
	for k, sm := range cs.split {
		b = append(lw(b, 0x20, lSk[k]), 0x20, lS, 0x46, 0x04, 0x40)
		b = append(b, 0x20, lN, 0x41, 0x01, 0x6A, 0x21, lN)
		b = append(b, 0x20, lIdx, 0x20, pCap, 0x49) // idx < cap
		if worker && !gated {
			b = append(b, 0x20, lIdx)
			b = pushSkip(b)
			b = append(b, 0x4F, 0x71) // && idx >= skip
		}
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, pOut, 0x20, lIdx, 0x41, abi.SetMatchTupleBytes, 0x6C, 0x6A, 0x22, lTmp)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(sm.id)) //nolint:gosec // a pattern id
		b = append(b, 0x36, 0x02, 0x00)
		b = append(lw(append(b, 0x20, lTmp), 0x20, lSk[k]), 0x36, 0x02, 0x04)
		b = append(lw(append(b, 0x20, lTmp), 0x20, lTk[k]), 0x36, 0x02, 0x08)
		if worker && gated {
			// batch_mode: this match was delivered, so it is gated now.
			b = append(b, 0x20, pMode, 0x04, 0x40)
			b = reportGate(b, k, sm.id)
			b = append(b, 0x0B)
		}
		b = append(b, 0x0B)
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x0B)
	}
	if gated && worker {
		// batch_mode has recorded every gate it owes already.
		b = append(b, 0x20, pMode, 0x45, 0x04, 0x40)
	}
	if gated {
		b = append(b, 0x20, lN, 0x20, pCap, 0x4D, 0x04, 0x40) // total <= cap: record every gate
		for k, sm := range cs.split {
			b = append(lw(b, 0x20, lSk[k]), 0x20, lS, 0x46, 0x04, 0x40)
			b = reportGate(b, k, sm.id)
			b = append(b, 0x0B)
		}
		if kept {
			// Over the buffer: the kept body recorded its gates if ITS count
			// fitted, and the position as a whole did not.
			b = append(b, 0x05)
			b = append(b, 0x20, lR, 0x41, 0x00, 0x4A, 0x20, lR, 0x20, pCap, 0x4C, 0x71, 0x04, 0x40)
			b = append(b, 0x20, lR, 0x21, lU)
			b = append(b, 0x20, lS, 0x41, 0x01, 0x74, 0x21, lV)
			b = undoKept(b, lV)
			b = append(b, 0x0B)
		}
		b = append(b, 0x0B)
	}
	if gated && worker {
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, lN, 0x0B)
	return append(utils.AppendULEB128(nil, uint32(len(b))), b...)
}

// emitSplitScanBody is a split set's exported scan capability: the kept body
// (keptIdx, -1 for none), then each split member's forward pass.
func emitSplitScanBody(cs *compiledSet, kind setCapKind, keptIdx int, fwd []int) []byte {
	const (
		pPtr = iota
		pLen
		pOff
		pOut
	)
	wide := kind == capScanAll && cs.wideAll()
	nparams := uint32(3)
	if wide {
		nparams = 4
	}
	a := newLocalAlloc(nparams)
	lR, lID := a.I32(), a.I32()
	var lAcc byte
	if kind == capScanAll && !wide {
		lAcc = a.I64()
	}
	var lR64 byte
	for _, sm := range cs.split {
		if sm.bt != nil {
			lR64 = a.I64()
			break
		}
	}
	// A member whose pass keeps notes runs with NO block here: a scan is one
	// call, with no search to keep notes across, and the global still holds
	// whatever its last setter left.
	var lSaved byte
	if cs.splitBlocks() {
		lSaved = a.I32()
	}
	var b []byte
	b = a.EmitDecls(b)
	if cs.splitBlocks() {
		b = append(b, 0x23)
		b = utils.AppendULEB128(b, cs.splitSearch)
		b = append(b, 0x21, lSaved)
	}
	noBlock := func(b []byte, k int) []byte {
		if !cs.split[k].hasBlock() {
			return b
		}
		b = append(b, 0x41, 0x00, 0x24)
		return utils.AppendULEB128(b, cs.splitSearch)
	}
	callKept := func(b []byte) []byte {
		for i := uint32(0); i < nparams; i++ {
			b = append(b, 0x20, byte(i))
		}
		b = append(b, 0x10)
		return utils.AppendULEB128(b, uint32(keptIdx)) //nolint:gosec // a function index
	}
	fwdHit := func(b []byte, k int) []byte {
		if cs.split[k].bt != nil {
			// The Backtracking find from off; its "gave up" error is the
			// capability's answer.
			b = append(b, 0x20, pOff)
			b = emitFindFromSetFromStack(b)
			b = noBlock(b, k)
			b = append(b, 0x20, pPtr, 0x20, pLen, 0x10)
			b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
			b = cs.emitRestoreSearch(b, k, lSaved)
			b = append(b, 0x22, lR64, 0x42, 0x7F, 0x53, 0x04, 0x40, 0x20, lR64)
			if kind == capScanAll && !wide {
				b = append(b, 0x0F, 0x0B) // the i64 answer as it is
			} else {
				b = append(b, 0xA7, 0x0F, 0x0B)
			}
			return append(b, 0x20, lR64, 0x42, 0x00, 0x59) // >= 0
		}
		if cs.split[k].ctx {
			b = append(b, 0x20, pOff)
			b = emitFindFromSetFromStack(b)
			b = noBlock(b, k)
			b = append(b, 0x20, pPtr, 0x20, pLen, 0x10)
			b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
			b = cs.emitRestoreSearch(b, k, lSaved)
			return append(b, 0x41, 0x00, 0x4E) // >= 0
		}
		b = noBlock(b, k)
		b = append(b, 0x20, pPtr, 0x20, pOff, 0x6A, 0x20, pLen, 0x20, pOff, 0x6B, 0x10)
		b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
		b = cs.emitRestoreSearch(b, k, lSaved)
		return append(b, 0x41, 0x00, 0x4E) // >= 0
	}
	switch {
	case kind == capScanAny:
		if keptIdx >= 0 {
			b = callKept(b)
			b = append(b, 0x22, lR, 0x41, 0x7F, 0x47, 0x04, 0x40, 0x20, lR, 0x0F, 0x0B)
		}
		b = append(b, 0x20, pOff, 0x20, pLen, 0x4B, 0x04, 0x40, 0x41, 0x7F, 0x0F, 0x0B)
		for k, sm := range cs.split {
			b = fwdHit(b, k)
			b = append(b, 0x04, 0x40, 0x41)
			b = utils.AppendSLEB128(b, int32(sm.id)) //nolint:gosec // a pattern id
			b = append(b, 0x0F, 0x0B)
		}
		b = append(b, 0x41, 0x7F)
	case !wide:
		if keptIdx >= 0 {
			b = callKept(b)
		} else {
			b = append(b, 0x42, 0x00)
		}
		b = append(b, 0x21, lAcc)
		b = append(b, 0x20, pOff, 0x20, pLen, 0x4B, 0x04, 0x40, 0x20, lAcc, 0x0F, 0x0B)
		// Every id is below 64 here: a larger one makes the set wideAll.
		for k, sm := range cs.split {
			b = fwdHit(b, k)
			b = append(b, 0x04, 0x40, 0x20, lAcc, 0x42)
			b = utils.AppendSLEB128_64(b, int64(1)<<uint(sm.id))
			b = append(b, 0x84, 0x21, lAcc, 0x0B)
		}
		b = append(b, 0x20, lAcc)
	default:
		if keptIdx >= 0 {
			b = callKept(b)
			b = append(b, 0x22, lR, 0x41, 0x00, 0x48, 0x04, 0x40, 0x20, lR, 0x0F, 0x0B)
		} else {
			b = append(b, 0x41, 0x00, 0x21, lR)
		}
		b = append(b, 0x20, pOff, 0x20, pLen, 0x4B, 0x04, 0x40, 0x20, lR, 0x0F, 0x0B)
		for k, sm := range cs.split {
			b = fwdHit(b, k)
			b = append(b, 0x04, 0x40, 0x41)
			b = utils.AppendSLEB128(b, int32(sm.id)) //nolint:gosec // a pattern id
			b = append(b, 0x21, lID)
			b = emitWideBitmapSet(b, pOut, lID, lR)
			b = append(b, 0x0B)
		}
		b = append(b, 0x20, lR)
	}
	b = append(b, 0x0B)
	return append(utils.AppendULEB128(nil, uint32(len(b))), b...)
}

// ── The search blocks ────────────────────────────────────────────────────
//
// A set's `find` drive takes one search block per search that spans its
// calls, through the scratch descriptor's second form
// (abi.FindScratchMagicBlocks), in this order:
//
//   - the drive state of a counted sparse bucket (one block, sparseCtr);
//   - the set's OWN blocks (ownBlocks): its split members', one per member
//     in the merge's order when any keeps state, then one per Backtracking
//     bucket member that keeps its budget per search (btBlockMembers);
//   - its companion's own blocks, in the same order.
//
// A caller zeroes them when a scan starts and, after each call, gives a block
// its notes or its Backtracking memo exactly as a single pattern's stub does.

// splitBlocks reports whether any split member's search keeps a block.
func (cs *compiledSet) splitBlocks() bool {
	for _, sm := range cs.split {
		if sm.hasBlock() {
			return true
		}
	}
	return false
}

// ownBlocks is the blocks this set's own code indexes, from blocksBase: its
// split members' (every member's, when any keeps one), then its Backtracking
// bucket members'.
func (cs *compiledSet) ownBlocks() []SearchSize {
	var out []SearchSize
	if cs.splitBlocks() {
		for _, sm := range cs.split {
			out = append(out, sm.block())
		}
	}
	for range cs.btBlockMembers {
		out = append(out, SearchSize{BTBudget: true})
	}
	return out
}

// blocksBase is the index of the set's first own block among the blocks the
// caller passes: past its owner's (blocksSkip) and its sparse counter's.
func (cs *compiledSet) blocksBase() int {
	n := cs.blocksSkip
	if cs.sparseCtr != nil {
		n++
	}
	return n
}

// btBlocksBase is the index of the set's first Backtracking bucket member
// block.
func (cs *compiledSet) btBlocksBase() int {
	n := cs.blocksBase()
	if cs.splitBlocks() {
		n += len(cs.split)
	}
	return n
}

// acceptsBlocks reports whether the set's descriptor parsers accept
// abi.FindScratchMagicBlocks: the set, or the companion its entries route
// to, has a block.
func (cs *compiledSet) acceptsBlocks() bool {
	return len(cs.ownBlocks()) > 0 || cs.forceAcceptBlocks || cs.sparseCtr != nil ||
		(cs.companion != nil && len(cs.companion.ownBlocks()) > 0)
}

// emitScratchMagicCheck traps unless the descriptor in descLocal carries the
// magic — either magic, for a set that accepts blocks (tmp is i32 scratch).
func (cs *compiledSet) emitScratchMagicCheck(b []byte, descLocal, tmp byte) []byte {
	b = append(b, 0x20, descLocal, 0x28, 0x02, abi.FindScratchMagicOff)
	if cs.acceptsBlocks() {
		b = append(b, 0x22, tmp, 0x41)
		b = utils.AppendSLEB128(b, abi.FindScratchMagic)
		b = append(b, 0x47, 0x20, tmp, 0x41)
		b = utils.AppendSLEB128(b, abi.FindScratchMagicBlocks)
		return append(b, 0x47, 0x71, 0x04, 0x40, 0x00, 0x0B) // ne; ne; and; if unreachable
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagic)
	return append(b, 0x47, 0x04, 0x40, 0x00, 0x0B)
}

// emitScratchBlocks pushes the descriptor's blocks pointer: its fifth field
// under abi.FindScratchMagicBlocks, 0 (no blocks) under the plain magic.
func emitScratchBlocks(b []byte, descLocal byte) []byte {
	b = append(b, 0x20, descLocal, 0x28, 0x02, abi.FindScratchMagicOff, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagicBlocks)
	b = append(b, 0x46, 0x04, 0x7F) // eq; if (result i32)
	b = append(b, 0x20, descLocal, 0x28, 0x02, abi.FindScratchBlocksOff)
	return append(b, 0x05, 0x41, 0x00, 0x0B)
}

// searchBlocks is every search block the set's `find` takes, in order
// (fillSetSearchSizes); nil when it takes none.
func (cs *compiledSet) searchBlocks() []SearchSize {
	var out []SearchSize
	if cs.sparseCtr != nil {
		// Block 0 is the drive's sparse counter state.
		out = append(out, SearchSize{})
	}
	out = append(out, cs.ownBlocks()...)
	if cs.companion != nil {
		out = append(out, cs.companion.ownBlocks()...)
	}
	return out
}

// scanAloneNeedsSplit reports whether it is only the scan pair that needs the
// split: `find` is overlapping and served by the answer cache. A split compile
// cannot read the cache, so splitting the whole set for its scan pair's sake
// made that `find` quadratic again on long overlapping matches
// ({`foo\w+`, `k[a-z]+z`, `\bbar\b`} with `scan_all`: 90,441 fuel/byte at
// 8 KB, ×4 per doubling, against 1,342 for the same set without `scan_all`).
func (cs *compiledSet) scanAloneNeedsSplit() bool {
	if !cs.hasFind() || !cs.overlapping || !cs.usesOverlapDP() {
		return false
	}
	for _, kind := range []setCapKind{capScanAny, capScanAll} {
		if cs.capName(kind) != "" && !cs.usesUnionScan(kind) && !cs.scanSwitch(kind) {
			return true
		}
	}
	return false
}

// scanSplitOnly compiles a set whose scan pair alone needs the split as two:
// the set without its scan pair — unsplit, so its `find` keeps the answer
// cache (and the no-cache companion a cacheless drive needs) — and an internal
// SPLIT copy with only the scan pair, to which the set's scan exports forward.
// nil when the two would not agree on the `_all` ABI, which a stub reads off
// the set alone; the caller then splits the whole set as before.
func scanSplitOnly(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions, cands []splitCand) *compiledSet {
	saved := opts.globals.clone()
	ps := spec
	ps.ScanAny, ps.ScanAll = "", ""
	primary := compileSetWith(ps, prefixPool, suffixPool, opts, nil, true)
	if primary.needsSplit() {
		*opts.globals = *saved
		return nil
	}
	primary.attachCompanion(noCacheCompanion(spec, prefixPool, suffixPool, opts, primary, cands))
	sc := spec
	sc.Name = spec.Name + "\x00scan"
	sc.Find, sc.BatchFind, sc.MatchAny, sc.MatchAll = "", false, "", ""
	so := opts
	so.quiet = true
	base := max(int64(primary.regionEnd), primary.dataTop())
	if primary.companion != nil {
		base = max(base, int64(primary.companion.regionEnd), primary.companion.dataTop())
	}
	so.TableBase = int32(align8(base)) //nolint:gosec // table addresses fit in i32
	comp := compileSetWith(sc, prefixPool, suffixPool, so, budgetSplit(cands, spec.Patterns, opts, splitTableBudget), true)
	if comp.wideAll() != primary.wideAll() {
		*opts.globals = *saved
		return nil
	}
	comp.internal = true
	primary.scanComp, primary.fwdScanAny, primary.fwdScanAll = comp, spec.ScanAny, spec.ScanAll
	return primary
}

// attachCompanion makes comp the set's companion, its blocks after the set's
// own; nil leaves the set without one.
func (cs *compiledSet) attachCompanion(comp *compiledSet) {
	cs.companion = comp
	if comp != nil {
		comp.blocksSkip = cs.blocksBase() + len(cs.ownBlocks())
	}
}

// emitWorkerBlocks, in a wrapper in front of a batching set's merged worker,
// hands the worker the descriptor's blocks pointer through
// splitBlocksGlobal.
func (cs *compiledSet) emitWorkerBlocks(b []byte, descLocal byte) []byte {
	if !cs.splitBlocks() || !cs.mergedWorker() {
		return b
	}
	b = emitScratchBlocks(b, descLocal)
	b = append(b, 0x24)
	return utils.AppendULEB128(b, cs.splitBlocksGlobal)
}

// emitMemberBlock hands member k's search its block, when it keeps one —
// none (0) when the caller gave the set no blocks.
func (cs *compiledSet) emitMemberBlock(b []byte, k int, lBlocks byte) []byte {
	if !cs.split[k].hasBlock() {
		return b
	}
	b = append(b, 0x20, lBlocks)
	if k > 0 {
		// lBlocks + k × block, or 0 with no blocks.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(k*abi.SearchBlockBytes)) //nolint:gosec // a small offset
		b = append(b, 0x6A, 0x41, 0x00, 0x20, lBlocks, 0x1B)
	}
	b = append(b, 0x24)
	return utils.AppendULEB128(b, cs.splitSearch)
}

// emitRestoreSearch puts the search global back after member k's search.
func (cs *compiledSet) emitRestoreSearch(b []byte, k int, lSaved byte) []byte {
	if !cs.split[k].hasBlock() {
		return b
	}
	b = append(b, 0x20, lSaved, 0x24)
	return utils.AppendULEB128(b, cs.splitSearch)
}
