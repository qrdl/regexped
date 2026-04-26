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

	prefixDFA      *dfaTable // built from prefixAST (reversed); nil when trivial
	prefixClassMap [256]byte // byte-class map for prefixDFA (Phase 2)
	prefixID       int       // index into dedup prefix pool; -1 = trivial

	trivialPrefix bool // true when prefixAST is nil

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

	info := &PatternInfo{
		fullPattern: re.Pattern,
		prefixID:    -1,
		suffixID:    -1,
	}

	lit, path := findMandatoryLitRec(parsed, 0, 0)
	info.mandLit = lit

	if lit != nil {
		prefixAST, suffixAST, ok := splitAtPath(parsed, path)
		info.splittable = ok
		if ok {
			// Trim zero-byte prefix (e.g. purely anchors like ^) — treat as trivial.
			if prefixAST != nil {
				if _, maxLen := regexpMinMaxLen(prefixAST); maxLen == 0 {
					prefixAST = nil
				}
			}
			info.prefixAST = prefixAST
			info.suffixAST = suffixAST
		}
	}

	info.trivialPrefix = info.prefixAST == nil

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
	BitmaskWidth         int // max patterns per bucket using AcceptBitmask; default 64
	MaxPatternsPerBucket int // hard cap for AcceptSparseSet (Phase 6); default 4096
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
		bw = 64
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
			if inst.Op == syntax.InstMatch && k < bitmaskWidth {
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
