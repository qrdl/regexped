package compile

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/config"
)

// PatternInfo holds the analysis result for a single pattern in a set.
// Populated by analyzePattern; consumed by set composition (Phase 2+).
type PatternInfo struct {
	fullPattern string
	prefixAST   *syntax.Regexp // AST before the mandatory literal; nil when trivial
	suffixAST   *syntax.Regexp // AST after the mandatory literal; nil when trivial
	mandLit     *mandatoryLit  // from findMandatoryLitRec
	splittable  bool           // false when splitAtPath rejects the path (routes to fallback)

	prefixDFA *dfaTable // built from prefixAST (reversed); nil when trivial
	prefixID  int       // index into dedup prefix pool; -1 = trivial

	trivialPrefix     bool // true when prefixAST is nil
	startAnchor       bool // true when original prefixAST (before trimming) had BeginText/BeginLine
	prefixMaxLen      int  // max byte length of prefix (0=trivial, -1=unbounded)
	prefixMinLen      int  // min byte length of prefix (0=trivial)
	varLenEmptySuffix    bool // variable-length prefix + empty suffix: write match tuple directly
	varLenNonEmptySuffix bool // variable-length prefix + non-empty suffix: call suffix DFA with corrected lPos
	isolatedFallback     bool // non-greedy: isolate in own fallback bucket with leftmostFirst=false DFA

	suffixDFA      *dfaTable // built from suffixAST
	suffixClasses  int       // numClasses after computeByteClasses (Phase 2)
	suffixStates   int
	suffixClassMap [256]byte // byte-class map for suffixDFA (Phase 2)
	suffixID       int       // index into dedup suffix pool; -1 when no suffix
}

// dfaPool is a deduplicating pool of canonical (Hopcroft + BFS-relabelled) DFA tables.
// Two DFAs added to the pool return the same ID if and only if they are structurally
// identical (same transitions and accept flags for every state).
type dfaPool struct {
	tables       []*dfaTable
	fingerprints map[uint64][]int // fingerprint → indices into tables
}

// Add inserts t into the pool and returns its ID.
// If an equivalent DFA (same fingerprint AND byte-equal) already exists, its ID
// is returned and t is not stored again.
// Precondition: t must be Hopcroft-minimised AND BFS-relabelled (i.e. built via
// dfaTableFromCanonical).
func (p *dfaPool) Add(t *dfaTable) int {
	if p.fingerprints == nil {
		p.fingerprints = make(map[uint64][]int)
	}
	fp := dfaFingerprint(t)
	for _, id := range p.fingerprints[fp] {
		if dfaTableEqual(p.tables[id], t) {
			return id
		}
	}
	id := len(p.tables)
	p.tables = append(p.tables, t)
	p.fingerprints[fp] = append(p.fingerprints[fp], id)
	return id
}

// dfaFingerprint computes a 64-bit FNV-1a hash of a canonical dfaTable.
// Precondition: t is Hopcroft-minimised AND BFS-relabelled.
func dfaFingerprint(t *dfaTable) uint64 {
	h := fnv.New64a()
	var b8 [8]byte

	writeU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(b8[:], v)
		h.Write(b8[:])
	}

	writeU64(uint64(t.numStates))

	var flags uint8
	if t.hasWordBoundary {
		flags |= 1
	}
	if t.hasNewlineBoundary {
		flags |= 2
	}
	if t.startBeginAccept {
		flags |= 4
	}
	h.Write([]byte{flags})

	for s := 0; s < t.numStates; s++ {
		for b := 0; b < 256; b++ {
			writeU64(uint64(t.transitions[s*256+b] + 1))
		}
		// Hash actual uint64 bitmasks for precision across single- and multi-pattern paths.
		writeU64(t.acceptStates[s])
		writeU64(t.midAcceptStates[s])
		writeU64(t.midAcceptNWStates[s])
		writeU64(t.midAcceptWStates[s])
		writeU64(t.midAcceptNLStates[s])
		writeU64(t.immediateAcceptStates[s])
	}
	return h.Sum64()
}

// dfaTableEqual reports whether two canonical dfaTables are structurally identical.
func dfaTableEqual(a, b *dfaTable) bool {
	if a.numStates != b.numStates ||
		a.startState != b.startState ||
		a.midStartState != b.midStartState ||
		a.midStartWordState != b.midStartWordState ||
		a.hasWordBoundary != b.hasWordBoundary ||
		a.hasNewlineBoundary != b.hasNewlineBoundary ||
		a.startBeginAccept != b.startBeginAccept {
		return false
	}
	if a.hasNewlineBoundary && a.midStartNewlineState != b.midStartNewlineState {
		return false
	}
	if len(a.transitions) != len(b.transitions) {
		return false
	}
	for i, v := range a.transitions {
		if v != b.transitions[i] {
			return false
		}
	}
	eqMaps := func(ma, mb map[int]uint64) bool {
		if len(ma) != len(mb) {
			return false
		}
		for s, va := range ma {
			if mb[s] != va {
				return false
			}
		}
		return true
	}
	return eqMaps(a.acceptStates, b.acceptStates) &&
		eqMaps(a.midAcceptStates, b.midAcceptStates) &&
		eqMaps(a.midAcceptNWStates, b.midAcceptNWStates) &&
		eqMaps(a.midAcceptWStates, b.midAcceptWStates) &&
		eqMaps(a.midAcceptNLStates, b.midAcceptNLStates) &&
		eqMaps(a.immediateAcceptStates, b.immediateAcceptStates)
}

// hasBeginAnchor reports whether re contains a BeginText or BeginLine assertion.
func hasBeginAnchor(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpBeginText, syntax.OpBeginLine:
		return true
	}
	for _, sub := range re.Sub {
		if hasBeginAnchor(sub) {
			return true
		}
	}
	return false
}

// analyzePattern parses re.Pattern, finds the mandatory literal, splits the
// AST around it, and builds canonical prefix and suffix DFAs — deduplicating
// them through the supplied pools.
//
// Patterns where no mandatory literal is found, or where splitAtPath rejects
// the path (quantifier in path), have trivialPrefix=true and splittable=false;
// they will route to the fallback bucket in Phase 3.
func analyzePattern(re config.RegexEntry, prefixPool, suffixPool *dfaPool) (*PatternInfo, error) {
	parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("analyzePattern: parse %q: %w", re.Pattern, err)
	}
	stripCaptures(parsed)

	info := &PatternInfo{
		fullPattern: re.Pattern,
		prefixID:    -1,
		suffixID:    -1,
	}

	// Patterns with non-greedy quantifiers contaminate merged suffix DFAs when mixed
	// with greedy patterns (via immediateAcceptStates). Isolate them in their own
	// fallback bucket; mergeSuffixDFA (leftmostFirst=true) gives correct non-greedy
	// semantics for isolated patterns without contaminating greedy-pattern buckets.
	{
		prog, compErr := syntax.Compile(parsed.Simplify())
		if compErr == nil && hasNonGreedyQuantifiers(prog) {
			info.splittable = false
			info.isolatedFallback = true
			info.startAnchor = hasBeginAnchor(parsed)
			// suffixDFA is built later by compileFallback via mergeSuffixDFA.
			return info, nil
		}
	}

	lit, path := findMandatoryLitRec(parsed, 0, 0)
	info.mandLit = lit

	if lit != nil {
		prefixAST, suffixAST, ok := splitAtPath(parsed, path)
		info.splittable = ok
		if ok {
			// Zero-length prefix: only strip if it's purely a begin-anchor (^).
			// Other zero-length assertions (like $, \b) carry semantic meaning that
			// cannot be dropped; patterns with them route to fallback.
			if prefixAST != nil {
				if _, maxLen := regexpMinMaxLen(prefixAST); maxLen == 0 {
					if hasBeginAnchor(prefixAST) {
						info.startAnchor = true
						prefixAST = nil
					} else {
						// Non-begin zero-length prefix (e.g. $, \b): route to fallback.
						info.splittable = false
						ok = false
					}
				}
			}
			info.prefixAST = prefixAST
			info.suffixAST = suffixAST
		}
		// Fallback patterns with BeginText in the full pattern are also start-anchored.
		if !info.splittable {
			info.startAnchor = hasBeginAnchor(parsed)
		}
	}

	info.trivialPrefix = info.prefixAST == nil
	if !info.trivialPrefix && info.prefixAST != nil {
		minLen, maxLen := regexpMinMaxLen(info.prefixAST)
		info.prefixMinLen = minLen
		info.prefixMaxLen = maxLen // -1 if unbounded
		// Variable-length prefix: match start computed at runtime via backward DFA.
		// Split by suffix presence for different handling in emitComputeValidMask.
		if minLen != maxLen {
			if info.suffixAST == nil {
				info.varLenEmptySuffix = true
			} else {
				info.varLenNonEmptySuffix = true
			}
		}
	}

	// Build prefix DFA (reversed prefix AST).
	if !info.trivialPrefix {
		revRe := reverseRegexp(info.prefixAST)
		revProg, err := syntax.Compile(revRe.Simplify())
		if err != nil {
			return nil, fmt.Errorf("analyzePattern: compile prefix %q: %w", re.Pattern, err)
		}
		revD := newDFA(revProg, false, false)
		prefixTable := dfaTableFromCanonical(revD)
		info.prefixDFA = prefixTable
		info.prefixID = prefixPool.Add(prefixTable)
	}

	// Build suffix DFA (suffix AST, or full pattern when no split).
	var suffixTarget *syntax.Regexp
	if info.suffixAST != nil {
		suffixTarget = info.suffixAST
	} else {
		// No suffix (literal at end, or no split): use the full pattern for the
		// suffix DFA so the pool captures the pattern's overall structure.
		suffixTarget = parsed
	}
	prog, err := syntax.Compile(suffixTarget.Simplify())
	if err != nil {
		return nil, fmt.Errorf("analyzePattern: compile suffix %q: %w", re.Pattern, err)
	}
	d := newDFA(prog, false, false)
	suffixTable := dfaTableFromCanonical(d)
	info.suffixDFA = suffixTable
	info.suffixStates = suffixTable.numStates
	info.suffixClassMap, _, info.suffixClasses = computeByteClasses(suffixTable)
	info.suffixID = suffixPool.Add(suffixTable)

	return info, nil
}

// --------------------------------------------------------------------------
// Phase 2: single-bucket merge

// AcceptKind describes how accept bits are encoded in the merged suffix DFA.
// Phase 6 will add AcceptSparseSet for WAF-scale patterns.
type AcceptKind int

const (
	AcceptBitmask AcceptKind = iota + 1 // one bit per pattern in a u64 per DFA state
)

// CompileSetOptions holds tunable parameters for set composition.
// Zero value uses defaults.
type CompileSetOptions struct {
	BitmaskWidth          int // max patterns per bucket using AcceptBitmask; default 64
	MaxPatternsPerBucket  int // hard cap for AcceptSparseSet (Phase 6); default 4096
	BudgetBytes           int // max merged DFA table bytes per bucket; default 65536
	BudgetStates          int // max DFA states per merged bucket; default 512
	BudgetStatesPreFilter int // pre-filter: suffixStates * combinedClassCount; default 65536
}

func (o CompileSetOptions) bitmaskWidth() int {
	if o.BitmaskWidth > 0 {
		return o.BitmaskWidth
	}
	return 32 // 32 patterns per bucket: fits in the i32 extracted by emitSetMatchFnFinal
}

func (o CompileSetOptions) budgetBytes() int {
	if o.BudgetBytes > 0 {
		return o.BudgetBytes
	}
	return 65536
}

func (o CompileSetOptions) budgetStates() int {
	if o.BudgetStates > 0 {
		return o.BudgetStates
	}
	return 512
}

func (o CompileSetOptions) budgetStatesPreFilter() int {
	if o.BudgetStatesPreFilter > 0 {
		return o.BudgetStatesPreFilter
	}
	return 65536
}

// mergeSuffixASTs builds a canonical union AST from suffix sub-trees.
// Sorts the inputs by re.String() before alternation so patterns sharing
// prefixes converge in the NFA sooner, reducing DFA state count.
func mergeSuffixASTs(asts []*syntax.Regexp) *syntax.Regexp {
	if len(asts) == 0 {
		return nil
	}
	if len(asts) == 1 {
		return deepCopyRegexp(asts[0])
	}
	sorted := make([]*syntax.Regexp, len(asts))
	for i, a := range asts {
		sorted[i] = deepCopyRegexp(a)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].String() < sorted[j].String()
	})
	return &syntax.Regexp{Op: syntax.OpAlternate, Sub: sorted}
}

// combinedClassCount returns the number of byte equivalence classes produced
// by merging class maps a and b. Two bytes are in the same combined class only
// if they are in the same class in both a and b.
func combinedClassCount(a, b [256]byte) int {
	type pair struct{ ca, cb byte }
	seen := make(map[pair]struct{})
	for i := range a {
		seen[pair{a[i], b[i]}] = struct{}{}
	}
	return len(seen)
}

// mergeSuffixDFA builds a merged DFA for the union of suffix ASTs.
// Each suffix AST is compiled individually, then their NFAs are manually
// combined so that each pattern gets a distinct InstMatch. This avoids
// the Go compiler merging shared suffixes into a single accept state.
// Bit k in the patternBits vector identifies pattern k.
//
// Returns error if len(asts) > BitmaskWidth (default 64).
func mergeSuffixDFA(asts []*syntax.Regexp, opts CompileSetOptions) (*dfaTable, AcceptKind, error) {
	bw := opts.BitmaskWidth
	if bw == 0 {
		bw = 32
	}
	if len(asts) == 0 {
		return nil, 0, fmt.Errorf("mergeSuffixDFA: empty pattern list")
	}
	if len(asts) > bw {
		return nil, 0, fmt.Errorf("mergeSuffixDFA: %d patterns exceed bitmaskWidth %d", len(asts), bw)
	}

	// Compile each suffix individually.
	progs := make([]*syntax.Prog, len(asts))
	for k, a := range asts {
		p, err := syntax.Compile(a.Simplify())
		if err != nil {
			return nil, 0, fmt.Errorf("mergeSuffixDFA: compile suffix %d: %w", k, err)
		}
		progs[k] = p
	}

	// Build union NFA manually so each pattern gets a distinct InstMatch.
	unionProg, patternBits := buildUnionProg(progs, bw)

	d := newDFA(unionProg, false, true, patternBits)
	t := dfaTableFromCanonical(d)
	return t, AcceptBitmask, nil
}

// buildUnionProg concatenates individual NFAs into a single union prog with an
// InstAlt chain at the start. Each pattern k's InstMatch instructions are
// assigned bit k in the returned patternBits slice (indexed by instruction PC).
//
// Instruction 0 in each individual prog is always InstFail by convention.
// In the combined prog we reserve position 0 as a shared InstFail; instructions
// from prog k (skipping its own inst 0) start at offsets[k].
func buildUnionProg(progs []*syntax.Prog, bitmaskWidth int) (*syntax.Prog, []uint64) {
	// Compute placement offsets — skip instruction 0 (InstFail) from each prog.
	offsets := make([]int, len(progs))
	offsets[0] = 1 // reserve position 0 for the shared InstFail
	for k := 1; k < len(progs); k++ {
		offsets[k] = offsets[k-1] + len(progs[k-1].Inst) - 1
	}
	// Position after all copied instructions.
	copyEnd := offsets[len(progs)-1] + len(progs[len(progs)-1].Inst) - 1
	// Alt chain: one InstAlt per pattern except the last.
	altCount := len(progs) - 1
	total := copyEnd + altCount

	union := &syntax.Prog{
		Inst:   make([]syntax.Inst, total),
		NumCap: 2,
	}
	union.Inst[0] = syntax.Inst{Op: syntax.InstFail}

	patternBits := make([]uint64, total)

	// adjustPC maps a PC within prog k (with offset off) to the combined-prog PC.
	// PC=0 in any individual prog means InstFail → stays at 0.
	adjustPC := func(pc int, off int) int {
		if pc == 0 {
			return 0
		}
		return pc + off - 1 // -1 because we skip inst 0 from the source prog
	}

	// Copy instructions from each prog (skipping their instruction 0).
	// patternBits[pos] is set for ALL instructions from pattern k (not just
	// InstMatch) so that nfaBuildInputMap can suppress byte-consumers from
	// pattern k once that pattern's InstMatch has been seen.
	for k, p := range progs {
		off := offsets[k]
		for i := 1; i < len(p.Inst); i++ {
			inst := p.Inst[i]
			ni := inst
			ni.Out = uint32(adjustPC(int(inst.Out), off))
			if inst.Op == syntax.InstAlt || inst.Op == syntax.InstAltMatch {
				ni.Arg = uint32(adjustPC(int(inst.Arg), off))
			}
			pos := off + i - 1
			union.Inst[pos] = ni
			if k < bitmaskWidth {
				patternBits[pos] = 1 << uint(k)
			}
		}
	}

	// Compute each pattern's start PC in the combined prog.
	starts := make([]int, len(progs))
	for k, p := range progs {
		starts[k] = adjustPC(p.Start, offsets[k])
	}

	if altCount == 0 {
		union.Start = starts[0]
		return union, patternBits
	}

	// Build the InstAlt chain at copyEnd..copyEnd+altCount-1.
	for k := 0; k < altCount-1; k++ {
		union.Inst[copyEnd+k] = syntax.Inst{
			Op:  syntax.InstAlt,
			Out: uint32(starts[k]),
			Arg: uint32(copyEnd + k + 1), // next link in the chain
		}
	}
	// Last link: branches between the second-to-last and last patterns.
	union.Inst[copyEnd+altCount-1] = syntax.Inst{
		Op:  syntax.InstAlt,
		Out: uint32(starts[len(progs)-2]),
		Arg: uint32(starts[len(progs)-1]),
	}
	union.Start = copyEnd
	return union, patternBits
}

// --------------------------------------------------------------------------
// Phase 4a: multi-pattern Teddy + frontend strategy selection

// frontendKind is the literal-scan strategy chosen for a set.
type frontendKind int

const (
	frontendTeddy  frontendKind = iota // ≤8 literals, 1–4 bytes each
	frontendAC                         // >8 literals → Aho-Corasick
	frontendScalar                     // fallback: byte-by-byte scan
)

func (f frontendKind) String() string {
	switch f {
	case frontendTeddy:
		return "teddy"
	case frontendAC:
		return "ac"
	default:
		return "scalar"
	}
}

// teddyTables holds the precomputed nibble tables for multi-pattern Teddy
// (up to 8 literals × up to 4 bytes each). Each lane bit k (0..7) corresponds
// to literal k in the input list.
type teddyTables struct {
	T0Lo, T0Hi [16]byte // 1-byte Teddy: nibble tables for literal byte[0]
	T1Lo, T1Hi [16]byte // 2-byte Teddy: nibble tables for literal byte[1]
	T2Lo, T2Hi [16]byte // 3-byte Teddy
	T3Lo, T3Hi [16]byte // 4-byte Teddy
	MinLen     int      // minimum literal length across all literals (1–4)
	TwoByte    bool     // T1 tables are valid (all literals ≥ 2 bytes)
	ThreeByte  bool     // T2 tables are valid
	FourByte   bool     // T3 tables are valid
	LaneToID   []int    // LaneToID[laneBit] = index in the original literals slice
}

// buildTeddyTablesMulti builds nibble tables for up to 8 literals of 1–4 bytes.
// Returns (tables, true) on success; (nil, false) if more than 8 literals or
// any literal is empty or longer than 4 bytes.
// Reuses the bit-packing pattern from compile.go:394–419.
func buildTeddyTablesMulti(literals [][]byte) (*teddyTables, bool) {
	if len(literals) == 0 || len(literals) > 8 {
		return nil, false
	}
	for _, lit := range literals {
		if len(lit) == 0 || len(lit) > 4 {
			return nil, false
		}
	}

	t := &teddyTables{LaneToID: make([]int, len(literals))}
	minLen := 4
	for i := range t.LaneToID {
		t.LaneToID[i] = i
		if len(literals[i]) < minLen {
			minLen = len(literals[i])
		}
	}
	t.MinLen = minLen
	t.TwoByte = minLen >= 2
	t.ThreeByte = minLen >= 3
	t.FourByte = minLen >= 4

	for laneBit, lit := range literals {
		bit := byte(1 << uint(laneBit))
		t.T0Lo[lit[0]&0x0F] |= bit
		t.T0Hi[lit[0]>>4] |= bit
		if len(lit) >= 2 {
			t.T1Lo[lit[1]&0x0F] |= bit
			t.T1Hi[lit[1]>>4] |= bit
		}
		if len(lit) >= 3 {
			t.T2Lo[lit[2]&0x0F] |= bit
			t.T2Hi[lit[2]>>4] |= bit
		}
		if len(lit) >= 4 {
			t.T3Lo[lit[3]&0x0F] |= bit
			t.T3Hi[lit[3]>>4] |= bit
		}
	}
	return t, true
}

// chooseLiteralFrontend selects the scan strategy for a set of mandatory
// literals. Teddy is used when ≤8 literals all have length 1–4 bytes; AC
// is used for larger sets; scalar is the final fallback.
func chooseLiteralFrontend(literals [][]byte) frontendKind {
	if len(literals) == 0 {
		return frontendScalar
	}
	if len(literals) <= 8 {
		for _, lit := range literals {
			if len(lit) == 0 || len(lit) > 4 {
				return frontendAC
			}
		}
		return frontendTeddy
	}
	return frontendAC
}

// --------------------------------------------------------------------------
// Phase 3: bin-packing + fallback

// bucket holds a set of patterns whose suffix DFAs have been merged.
type bucket struct {
	literal      string         // string(mandLit.bytes); "" for fallback
	patterns     []*PatternInfo // patterns in placement order (bit k = patterns[k])
	suffixDFA    *dfaTable      // current merged suffix DFA; nil until 2+ patterns merged
	suffixStates int            // suffixDFA.numStates (0 before first merge)
	tableBytes   int            // estimated table bytes
	classMap     [256]byte      // combined byte-class map of all suffix DFAs
	numClasses   int            // number of distinct classes in classMap
	isFallback   bool           // true = no literal, full-pattern DFA
}

// bucketKey is used in the literal grouping map. "~fallback~" is the sentinel
// for patterns without a mandatory literal or with non-splittable paths.
// bucketByLiteral partitions patterns into per-literal groups and a fallback
// slice for patterns with mandLit==nil or splittable==false.
func bucketByLiteral(patterns []*PatternInfo) (map[string][]*PatternInfo, []*PatternInfo) {
	groups := make(map[string][]*PatternInfo)
	var fallback []*PatternInfo
	for _, p := range patterns {
		if p.mandLit == nil || !p.splittable {
			fallback = append(fallback, p)
		} else {
			key := string(p.mandLit.bytes)
			groups[key] = append(groups[key], p)
		}
	}
	return groups, fallback
}

// binPack groups patterns into merged-DFA buckets using first-fit-decreasing
// (sorted by suffixStates ascending). Three constraints gate admission into an
// existing bucket:
//  1. bitmask capacity: len(bucket.patterns) < bitmaskWidth
//  2. class-count pre-filter: bucket.suffixStates * combinedClassCount ≤ budgetStatesPreFilter
//  3. actual merge: merged table bytes ≤ budgetBytes AND merged states ≤ budgetStates
//
// Each rejection is recorded in diag. Non-literal and non-splittable patterns
// are routed to compileFallback instead.
func binPack(patterns []*PatternInfo, opts CompileSetOptions, diag *SetDiag) []*bucket {
	bw := opts.bitmaskWidth()
	prefilterBudget := opts.budgetStatesPreFilter()
	byteBudget := opts.budgetBytes()
	stateBudget := opts.budgetStates()

	literalGroups, fallbackPatterns := bucketByLiteral(patterns)

	// Deterministic iteration: sort literal keys.
	litKeys := make([]string, 0, len(literalGroups))
	for k := range literalGroups {
		litKeys = append(litKeys, k)
	}
	sort.Strings(litKeys)

	var buckets []*bucket

	for _, lit := range litKeys {
		group := literalGroups[lit]
		// Sort group by suffixStates ascending (smallest first).
		sort.Slice(group, func(i, j int) bool {
			if group[i].suffixStates != group[j].suffixStates {
				return group[i].suffixStates < group[j].suffixStates
			}
			return group[i].fullPattern < group[j].fullPattern // tie-break for determinism
		})

		// Track buckets within this literal group.
		var litBuckets []*bucket

		for _, p := range group {
			pRef := patternRefFor(p)
			placed := false

			for bi, b := range litBuckets {
				// Constraint 1: bitmask capacity.
				if len(b.patterns) >= bw {
					if diag != nil {
						diag.Conflicts = append(diag.Conflicts, ConflictDiag{
							Pattern: pRef, CandidateBucket: len(buckets) + bi,
							Reason: "bitmask_cap_full",
							Detail: map[string]interface{}{"bitmask_width": bw},
						})
					}
					continue
				}

				// Constraint 2: class-count pre-filter.
				cc := combinedClassCount(b.classMap, p.suffixClassMap)
				if b.suffixStates > 0 && b.suffixStates*cc > prefilterBudget {
					if diag != nil {
						diag.Conflicts = append(diag.Conflicts, ConflictDiag{
							Pattern: pRef, CandidateBucket: len(buckets) + bi,
							Reason: "class_count_incompatible",
							Detail: map[string]interface{}{
								"combined_classes": cc,
								"prefilter_budget": prefilterBudget,
							},
						})
					}
					continue
				}

				// Constraint 3: actual merge.
				candidateASTs := make([]*syntax.Regexp, len(b.patterns)+1)
				for i, bp := range b.patterns {
					candidateASTs[i] = patternSuffixAST(bp)
				}
				candidateASTs[len(b.patterns)] = patternSuffixAST(p)
				mergedTable, _, mergeErr := mergeSuffixDFA(candidateASTs, opts)
				if mergeErr != nil {
					continue
				}
				mergedBytes := dfaTableBytes(mergedTable)
				if mergedBytes > byteBudget {
					if diag != nil {
						diag.Conflicts = append(diag.Conflicts, ConflictDiag{
							Pattern: pRef, CandidateBucket: len(buckets) + bi,
							Reason: "table_size_exceeded",
							Detail: map[string]interface{}{
								"merged_bytes": mergedBytes,
								"budget_bytes": byteBudget,
							},
						})
					}
					continue
				}
				if mergedTable.numStates > stateBudget {
					if diag != nil {
						diag.Conflicts = append(diag.Conflicts, ConflictDiag{
							Pattern: pRef, CandidateBucket: len(buckets) + bi,
							Reason: "state_count_exceeded",
							Detail: map[string]interface{}{
								"merged_states": mergedTable.numStates,
								"budget_states": stateBudget,
							},
						})
					}
					continue
				}

				// Admitted: update bucket.
				b.patterns = append(b.patterns, p)
				b.suffixDFA = mergedTable
				b.suffixStates = mergedTable.numStates
				b.tableBytes = mergedBytes
				newCM, _, newNC := computeByteClasses(mergedTable)
				b.classMap = newCM
				b.numClasses = newNC
				placed = true
				break
			}

			if !placed {
				// Create a new bucket for this pattern.
				nb := &bucket{
					literal:      lit,
					patterns:     []*PatternInfo{p},
					suffixStates: p.suffixStates,
					tableBytes:   dfaTableBytes(p.suffixDFA),
					classMap:     p.suffixClassMap,
					numClasses:   p.suffixClasses,
				}
				// Build the bucket's suffix DFA with correct bitmask accepts (bit 0 = pattern 0).
				// p.suffixDFA is built without patternBits (for dedup); we need bitmask info for WASM.
				if ast := patternSuffixAST(p); ast != nil {
					if t, _, mergeErr := mergeSuffixDFA([]*syntax.Regexp{ast}, opts); mergeErr == nil {
						nb.suffixDFA = t
					}
				}
				litBuckets = append(litBuckets, nb)
			}
		}
		buckets = append(buckets, litBuckets...)
	}

	// Fallback: compile non-literal / non-splittable patterns.
	if len(fallbackPatterns) > 0 {
		fb := compileFallback(fallbackPatterns, opts, diag)
		buckets = append(buckets, fb...)
	}

	// Build BucketDiag entries.
	if diag != nil {
		for i, b := range buckets {
			btype := "merged"
			if len(b.patterns) == 1 {
				btype = "singleton"
			}
			if b.isFallback {
				btype = "fallback"
			}
			refs := make([]PatternRef, len(b.patterns))
			for j, p := range b.patterns {
				refs[j] = patternRefFor(p)
			}
			diag.Buckets = append(diag.Buckets, BucketDiag{
				ID:           i,
				Type:         btype,
				AcceptKind:   "bitmask",
				Literal:      b.literal,
				Patterns:     refs,
				SuffixStates: b.suffixStates,
				TableBytes:   b.tableBytes,
			})
		}
	}

	return buckets
}

// compileFallback applies the same bin-packing algorithm to patterns that have
// no mandatory literal or whose split path was rejected. These buckets run on
// every input position (no literal scan gate).
func compileFallback(patterns []*PatternInfo, opts CompileSetOptions, diag *SetDiag) []*bucket {
	// Sort by suffixStates ascending.
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].suffixStates != patterns[j].suffixStates {
			return patterns[i].suffixStates < patterns[j].suffixStates
		}
		return patterns[i].fullPattern < patterns[j].fullPattern
	})

	bw := opts.bitmaskWidth()
	byteBudget := opts.budgetBytes()
	stateBudget := opts.budgetStates()

	var buckets []*bucket

	for _, p := range patterns {
		// Isolated patterns (e.g. non-greedy) get their own bucket to prevent
		// their pre-built leftmostFirst=false DFA from being replaced by a merged one.
		if p.isolatedFallback {
			// Build suffix DFA for isolated pattern via mergeSuffixDFA (leftmostFirst=true)
			// so non-greedy patterns get correct semantics without contaminating other buckets.
			isolatedDFA := p.suffixDFA
			if ast := patternSuffixAST(p); ast != nil {
				if t, _, mergeErr := mergeSuffixDFA([]*syntax.Regexp{ast}, opts); mergeErr == nil {
					isolatedDFA = t
				}
			}
			isolatedCM, _, isolatedNC := computeByteClasses(isolatedDFA)
			nb := &bucket{
				literal:      "",
				patterns:     []*PatternInfo{p},
				suffixStates: isolatedDFA.numStates,
				tableBytes:   dfaTableBytes(isolatedDFA),
				classMap:     isolatedCM,
				numClasses:   isolatedNC,
				isFallback:   true,
				suffixDFA:    isolatedDFA,
			}
			buckets = append(buckets, nb)
			continue
		}
		placed := false
		for _, b := range buckets {
			if len(b.patterns) >= bw {
				continue
			}
			candidateASTs := make([]*syntax.Regexp, len(b.patterns)+1)
			for i, bp := range b.patterns {
				candidateASTs[i] = patternSuffixAST(bp)
			}
			candidateASTs[len(b.patterns)] = patternSuffixAST(p)
			mergedTable, _, mergeErr := mergeSuffixDFA(candidateASTs, opts)
			if mergeErr != nil {
				continue
			}
			mergedBytes := dfaTableBytes(mergedTable)
			if mergedBytes > byteBudget || mergedTable.numStates > stateBudget {
				continue
			}
			b.patterns = append(b.patterns, p)
			b.suffixDFA = mergedTable
			b.suffixStates = mergedTable.numStates
			b.tableBytes = mergedBytes
			newCM, _, newNC := computeByteClasses(mergedTable)
			b.classMap = newCM
			b.numClasses = newNC
			placed = true
			break
		}
		if !placed {
			// Build suffix DFA from full pattern (patternSuffixAST), not just the
			// suffix part stored in p.suffixDFA, which may be incomplete for non-splittable patterns.
			nbDFA := p.suffixDFA
			if ast := patternSuffixAST(p); ast != nil {
				if t, _, mergeErr := mergeSuffixDFA([]*syntax.Regexp{ast}, opts); mergeErr == nil {
					nbDFA = t
				}
			}
			nbCM, _, nbNC := computeByteClasses(nbDFA)
			nb := &bucket{
				literal:      "",
				patterns:     []*PatternInfo{p},
				suffixStates: nbDFA.numStates,
				tableBytes:   dfaTableBytes(nbDFA),
				classMap:     nbCM,
				numClasses:   nbNC,
				isFallback:   true,
				suffixDFA:    nbDFA,
			}
			buckets = append(buckets, nb)
		}
	}

	for _, b := range buckets {
		b.isFallback = true
	}
	return buckets
}

// patternSuffixAST returns the suffix AST for p.
// When suffixAST is nil and the pattern was splittable, the mandatory literal
// covers the whole pattern (empty suffix) — return an empty regex so the
// suffix DFA accepts immediately at suffix_start.
// When the pattern was not splittable, fall back to the full pattern AST.
func patternSuffixAST(p *PatternInfo) *syntax.Regexp {
	if !p.splittable {
		// Non-splittable: use the full pattern so the suffix DFA handles all matching.
		re, err := syntax.Parse(p.fullPattern, syntax.Perl)
		if err != nil {
			return nil
		}
		return re
	}
	if p.suffixAST != nil {
		return p.suffixAST
	}
	// The mandatory literal IS the whole pattern; suffix is empty.
	empty, _ := syntax.Parse("", syntax.Perl)
	return empty
}

// patternRefFor builds a PatternRef from a PatternInfo.
// Phase 3 doesn't yet thread global pattern IDs; use 0 as placeholder.
// Phase 4c will replace this with the actual global ID.
func patternRefFor(p *PatternInfo) PatternRef {
	return PatternRef{ID: 0, Name: p.fullPattern}
}
