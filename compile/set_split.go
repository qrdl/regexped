package compile

import (
	"regexp/syntax"

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
// (failedWalkBound: no reachable cycle of non-accepting states), and the set's
// own literal-anchored one (setLiteralMemberLinear). Every other member that
// the start-anywhere find can serve is SPLIT OUT:
//
//   - the buckets serve the members that stay ("kept"), exactly as before;
//   - each split member gets its own two passes (start_anywhere.go);
//   - `find`, `scan_any` and `scan_all` become MERGE WRAPPERS over the kept
//     body and the split members — unless a start-anywhere union over EVERY
//     member can serve the scan pair, which then answers it alone;
//   - match_any / match_all are anchored and do not change.
//
// A set is split when one of its non-anchored capabilities would otherwise
// stay quadratic: gated `find` always; overlapping `find` when the answer
// cache cannot serve it; the scan pair when no union automaton serves it (a
// literal frontend's counter needs one to switch to). A set with
// `hints: [batch-find]` is never split: its batch entry resumes inside a
// position through its own gate rule, which the merge does not reproduce.
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

// maxSplitMembers bounds how many members one set splits out. The merge
// wrapper keeps four locals per member beside 22 of its own, and addresses
// every local with ONE byte of ULEB128 — below 128.
const maxSplitMembers = 24

// splitMember is one member a set serves outside its buckets.
type splitMember struct {
	id               int    // global pattern id
	fwdBody, revBody []byte // size-prefixed code entries
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
	cands := setSplitCandidates(spec, opts)
	if len(cands) == 0 {
		return compileSetWith(spec, prefixPool, suffixPool, opts, nil, false)
	}
	if spec.BatchFind || opts.NoSplit {
		// Never split (see the file header); the counters still apply.
		return compileSetWith(spec, prefixPool, suffixPool, opts, nil, true)
	}
	// The trial takes its globals from a copy, so a set that turns out to need
	// the split leaves no allocation of the trial's behind in the module.
	trialOpts := opts
	trialOpts.globals = opts.globals.clone()
	trial := compileSetWith(spec, prefixPool, suffixPool, trialOpts, nil, true)
	cands = trial.keepsOnDFA(spec, cands)
	if len(cands) == 0 || len(cands) > maxSplitMembers || !trial.needsSplit() {
		*opts.globals = *trialOpts.globals
		return trial
	}
	// The trial has already warned about every pattern this compile drops or
	// puts on Backtracking: the split members are neither, and the others
	// are packed by the same per-pattern rules.
	opts.quiet = true
	return compileSetWith(spec, prefixPool, suffixPool, opts, cands, true)
}

// setSplitCandidates returns the indices, into spec.Patterns, of the members
// the split would serve: not provably linear in a set, and servable by the
// start-anywhere find.
func setSplitCandidates(spec SetSpec, opts CompileSetOptions) []int {
	if !spec.HasFind() && spec.ScanAny == "" && spec.ScanAll == "" {
		return nil
	}
	var out []int
	for i, p := range spec.Patterns {
		if setMemberNeedsSplit(p, opts) {
			out = append(out, i)
		}
	}
	return out
}

// setMemberNeedsSplit applies the set's group-A rule — the bounded-walk
// clause, or the set's literal-anchored clause — and reports whether p fails
// it and can be served by the start-anywhere find.
func setMemberNeedsSplit(p *PatternInfo, opts CompileSetOptions) bool {
	parsed, err := syntax.Parse(p.fullPattern, syntax.Perl)
	if err != nil {
		return false
	}
	stripCaptures(parsed)
	if hasEmptyWidthAssertion(parsed) {
		return false
	}
	limit := opts.maxFallbackStates()
	m, err := compile(p.fullPattern, CompileOptions{MaxDFAStates: limit, ForceEngine: EngineDFA,
		LeftmostFirst: true, ByteMode: p.byteMode})
	if err != nil {
		return false
	}
	t := dfaTableFrom(m.(*dfa))
	if t.numStates > limit || isAnchoredFind(t) {
		return false
	}
	if _, bounded := failedWalkBound(t); bounded {
		return false
	}
	if setLiteralMemberLinear(p) {
		return false
	}
	_, ok := buildStartAnywherePasses(p.fullPattern, splitPassOpts(p, opts), 0, align8)
	return ok
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
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return true
	}
	d, ok := newDFA(prog, false, false, maxHelperDFAStates)
	if !ok {
		return true
	}
	t := dfaTableFrom(d)
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
	accepting := func(s int) bool { return t.midAcceptStates[s] != 0 || t.acceptStates[s] != 0 }
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

// keepsOnDFA filters cands to the members this (unsplit) compile placed in an
// ordinary DFA bucket. A member it dropped or put on Backtracking stays
// where it is: the split would change what the set reports, or the `_all`
// ABI a Backtracking member selects.
func (cs *compiledSet) keepsOnDFA(spec SetSpec, cands []int) []int {
	onDFA := map[int]bool{}
	for bi, bkt := range cs.buckets {
		if bkt.btFallback != nil {
			continue
		}
		for _, id := range cs.patternIDs[bi] {
			onDFA[id] = true
		}
	}
	var out []int
	for _, i := range cands {
		if onDFA[spec.PatternIDs[i]] {
			out = append(out, i)
		}
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

// capName is the export name of a scan capability, "" when not declared.
func (cs *compiledSet) capName(kind setCapKind) string {
	switch kind {
	case capScanAny:
		return cs.scanAny
	case capScanAll:
		return cs.scanAll
	case capFind:
		return cs.find
	}
	return ""
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
func planScanUnion(full, kept SetSpec, split []int, buckets []*bucket, nonLinear bool) scanUnionPlan {
	if !nonLinear || (full.ScanAny == "" && full.ScanAll == "") {
		return scanUnionPlan{}
	}
	wide := setWideAll(full, buckets)
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
		cs.scanSwWork = int32(opts.globals.Alloc()) //nolint:gosec // a global index
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
func (cs *compiledSet) buildSplitMembers(full SetSpec, split []int, ra *regionAlloc, opts CompileSetOptions) {
	if len(split) == 0 {
		return
	}
	for _, i := range split {
		p := full.Patterns[i]
		base := ra.Reserve("split-member", 8)
		sa, ok := buildStartAnywherePasses(p.fullPattern, splitPassOpts(p, opts), int64(base), align8)
		if !ok {
			panic("compile: a split member's start-anywhere find was classified buildable and then refused")
		}
		ra.Commit(int32(sa.end)) //nolint:gosec // table addresses fit in i32
		cs.split = append(cs.split, splitMember{id: full.PatternIDs[i], fwdBody: sa.fwdBody, revBody: sa.revBody})
		cs.splitData = append(cs.splitData, sa.data...)
		cs.splitSegs += sa.segs
	}
	cs.keptEmpty = len(cs.patternIDs) == 0
	if cs.hasFind() && !cs.keptEmpty {
		cs.keptPosGlobal = int32(opts.globals.Alloc()) //nolint:gosec // a global index
	}
}

// mergedCap reports whether kind's export is a merge wrapper over the kept
// body and the split members.
func (cs *compiledSet) mergedCap(kind setCapKind) bool {
	if len(cs.split) == 0 {
		return false
	}
	switch kind {
	case capFind:
		return true
	case capScanAny, capScanAll:
		return !cs.scanUnionDirect
	}
	return false
}

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

// scanSwitchFnOffset is the index of the union body kind's counter switches
// to, or -1.
func (cs *compiledSet) scanSwitchFnOffset(kind setCapKind) int {
	for i, c := range cs.switchCaps() {
		if c.kind == kind {
			return cs.extraFnBaseOffset() + len(cs.keptCaps()) + i
		}
	}
	return -1
}

// splitFwdOffset / splitRevOffset index member i's two passes.
func (cs *compiledSet) splitFwdOffset(i int) int {
	return cs.extraFnBaseOffset() + len(cs.keptCaps()) + len(cs.switchCaps()) + 2*i
}
func (cs *compiledSet) splitRevOffset(i int) int { return cs.splitFwdOffset(i) + 1 }

// extraFnCount is how many functions this file adds.
func (cs *compiledSet) extraFnCount() int {
	return len(cs.keptCaps()) + len(cs.switchCaps()) + 2*len(cs.split)
}

// extraFnTypes lists the added functions' type indices, in layout order.
func (cs *compiledSet) extraFnTypes() []byte {
	var out []byte
	for _, c := range cs.keptCaps() {
		out = append(out, c.typeIdx)
	}
	for _, c := range cs.switchCaps() {
		out = append(out, c.typeIdx)
	}
	for range cs.split {
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
func emitSplitFindBody(cs *compiledSet, keptIdx int, fwd, rev []int) []byte {
	const (
		pPtr = iota
		pLen
		pFrom
		pDesc
		pOut
		pCap
		nparams
	)
	gated := cs.gatedFind()
	m := len(cs.split)
	a := newLocalAlloc(nparams)
	lGate, lK, lS, lR := a.I32(), a.I32(), a.I32(), a.I32()
	lKeptPos, lKeptDone, lBest, lBestLb := a.I32(), a.I32(), a.I32(), a.I32()
	lQ, lE, lSt, lN, lIdx, lTmp, lDead, lV := a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32(), a.I32()
	lLb, lSk, lTk, lDone := make([]byte, m), make([]byte, m), make([]byte, m), make([]byte, m)
	for k := 0; k < m; k++ {
		lLb[k], lSk[k], lTk[k], lDone[k] = a.I32(), a.I32(), a.I32(), a.I32()
	}
	if lDone[m-1] >= 0x80 {
		panic("compile: a split set's merge wrapper ran out of one-byte local indices")
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
	// For every kept tuple the kept body wrote, gate[id] = local v: undoes
	// the report gates it recorded (lR tuples, all written).
	undoKept := func(b []byte, v byte) []byte {
		b = append(b, 0x41, 0x00, 0x21, lIdx)
		b = append(b, 0x02, 0x40, 0x03, 0x40) // block, loop
		b = append(b, 0x20, lIdx, 0x20, lR, 0x4E, 0x0D, 0x01)
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

	// The descriptor: check the magic, take the gate pointer.
	b = append(b, 0x20, pDesc, 0x28, 0x02, abi.FindScratchMagicOff, 0x41)
	b = utils.AppendSLEB128(b, abi.FindScratchMagic)
	b = append(b, 0x47, 0x04, 0x40, 0x00, 0x0B)
	b = append(b, 0x20, pDesc, 0x28, 0x02, abi.FindScratchGateOff, 0x21, lGate)
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
		b = append(b, 0x41, 0x01, 0x76, 0x22, lLb[k])
		b = append(b, 0x20, pFrom, 0x49, 0x04, 0x40, 0x20, pFrom, 0x21, lLb[k], 0x0B)
		b = append(b, 0x41, 0x00, 0x21, lDone[k])
		b = append(b, 0x41, 0x7F, 0x21, lSk[k])
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
	consider := func(b []byte, doneLocal, lbLocal byte, idx int32) []byte {
		b = append(b, 0x20, doneLocal, 0x45)
		b = append(b, 0x20, lbLocal, 0x20, lS, 0x4D, 0x71) // lb <= S
		b = append(b, 0x20, lbLocal, 0x20, lBestLb, 0x49, 0x71)
		b = append(b, 0x04, 0x40, 0x41)
		b = utils.AppendSLEB128(b, idx)
		b = append(b, 0x21, lBest, 0x20, lbLocal, 0x21, lBestLb, 0x0B)
		return b
	}
	if kept {
		b = consider(b, lKeptDone, lK, int32(m)) //nolint:gosec // a small count
	}
	for k := 0; k < m; k++ {
		b = consider(b, lDone[k], lLb[k], int32(k)) //nolint:gosec // a small count
	}
	b = append(b, 0x20, lBest, 0x41, 0x7F, 0x46, 0x0D, 0x01) // none → $exit

	if kept {
		b = append(b, 0x20, lBest, 0x41)
		b = utils.AppendSLEB128(b, int32(m)) //nolint:gosec // a small count
		b = append(b, 0x46, 0x04, 0x40)
		b = append(b, 0x20, pPtr, 0x20, pLen, 0x20, lK, 0x20, pDesc, 0x20, pOut, 0x20, pCap, 0x10)
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
		b = append(b, 0x41, 0x01, 0x21, lDone[k])
		b = append(b, 0x20, lLb[k], 0x21, lQ)
		b = append(b, 0x02, 0x40, 0x03, 0x40) // block $found, loop $retry
		// Past the end, or no match from q: the member is done for the drive.
		b = append(b, 0x20, lQ, 0x20, pLen, 0x4B)
		b = append(b, 0x04, 0x7F, 0x41, 0x7F, 0x05)
		b = append(b, 0x20, pPtr, 0x20, lQ, 0x6A, 0x20, pLen, 0x20, lQ, 0x6B, 0x10)
		b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
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
		if gated {
			// An empty match where the gate forbids one (right after this
			// member's previous match): the next start may still match.
			b = append(b, 0x20, lSt, 0x20, lE, 0x46)
			b = append(b, 0x20, lSt, 0x41, 0x01, 0x74)
			b = loadGate(b, sm.id)
			b = append(b, 0x49, 0x71, 0x04, 0x40)                                  // 2s < gate
			b = append(b, 0x20, lSt, 0x41, 0x01, 0x6A, 0x21, lQ, 0x0C, 0x01, 0x0B) // retry
		}
		b = append(b, 0x20, lSt, 0x21, lSk[k], 0x20, lE, 0x21, lTk[k])
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
			b = append(b, 0x20, lR, 0x20, pCap, 0x4C, 0x04, 0x40)
			b = undoKept(b, lV)
			b = append(b, 0x0B)
		}
		for _, id := range keptIDs {
			b = raiseGate(b, id, lV)
		}
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, lS, 0x41, 0x7F, 0x46, 0x04, 0x40, 0x41, 0x00, 0x0F, 0x0B) // nothing anywhere

	// The answer is the matches at S: the kept body's when its position is S,
	// then every split member whose next match starts there.
	b = append(b, 0x41, 0x00, 0x21, lIdx, 0x41, 0x00, 0x21, lN)
	if kept {
		b = append(b, 0x20, lR, 0x41, 0x00, 0x4A, 0x20, lKeptPos, 0x20, lS, 0x46, 0x71, 0x04, 0x40)
		b = append(b, 0x20, lR, 0x21, lN)
		b = append(b, 0x20, lR, 0x20, pCap, 0x20, lR, 0x20, pCap, 0x49, 0x1B, 0x21, lIdx) // min(r, cap)
		b = append(b, 0x05, 0x41, 0x00, 0x21, lR, 0x0B)                                   // else: none of its tuples count
	}
	for k, sm := range cs.split {
		b = append(b, 0x20, lSk[k], 0x20, lS, 0x46, 0x04, 0x40)
		b = append(b, 0x20, lN, 0x41, 0x01, 0x6A, 0x21, lN)
		b = append(b, 0x20, lIdx, 0x20, pCap, 0x49, 0x04, 0x40)
		b = append(b, 0x20, pOut, 0x20, lIdx, 0x41, abi.SetMatchTupleBytes, 0x6C, 0x6A, 0x22, lTmp)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(sm.id)) //nolint:gosec // a pattern id
		b = append(b, 0x36, 0x02, 0x00)
		b = append(b, 0x20, lTmp, 0x20, lSk[k], 0x36, 0x02, 0x04)
		b = append(b, 0x20, lTmp, 0x20, lTk[k], 0x36, 0x02, 0x08)
		b = append(b, 0x20, lIdx, 0x41, 0x01, 0x6A, 0x21, lIdx)
		b = append(b, 0x0B, 0x0B)
	}
	if gated {
		b = append(b, 0x20, lN, 0x20, pCap, 0x4D, 0x04, 0x40) // total <= cap: record every gate
		for k, sm := range cs.split {
			b = append(b, 0x20, lSk[k], 0x20, lS, 0x46, 0x04, 0x40)
			b = storeGate(b, sm.id, func(b []byte) []byte {
				b = append(b, 0x20, lTk[k], 0x41, 0x01, 0x74)
				b = append(b, 0x41, 0x01, 0x41, 0x02, 0x20, lTk[k], 0x20, lSk[k], 0x4A, 0x1B, 0x6A)
				return b
			})
			b = append(b, 0x0B)
		}
		if kept {
			// Over the buffer: the kept body recorded its gates if ITS count
			// fitted, and the position as a whole did not.
			b = append(b, 0x05)
			b = append(b, 0x20, lR, 0x41, 0x00, 0x4A, 0x20, lR, 0x20, pCap, 0x4C, 0x71, 0x04, 0x40)
			b = append(b, 0x20, lS, 0x41, 0x01, 0x74, 0x21, lV)
			b = undoKept(b, lV)
			b = append(b, 0x0B)
		}
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
	var b []byte
	b = a.EmitDecls(b)
	callKept := func(b []byte) []byte {
		for i := uint32(0); i < nparams; i++ {
			b = append(b, 0x20, byte(i))
		}
		b = append(b, 0x10)
		return utils.AppendULEB128(b, uint32(keptIdx)) //nolint:gosec // a function index
	}
	fwdHit := func(b []byte, k int) []byte {
		b = append(b, 0x20, pPtr, 0x20, pOff, 0x6A, 0x20, pLen, 0x20, pOff, 0x6B, 0x10)
		b = utils.AppendULEB128(b, uint32(fwd[k])) //nolint:gosec // a function index
		return append(b, 0x41, 0x00, 0x4E)         // >= 0
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
		for k, sm := range cs.split {
			if sm.id >= 64 {
				continue // outside the narrow ABI; unreachable, wideAll would hold
			}
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
