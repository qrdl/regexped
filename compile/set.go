package compile

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"regexp/syntax"

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
			// +1 so that -1 (dead) maps to 0, not wrapping.
			writeU64(uint64(t.transitions[s*256+b] + 1))
		}
		var af uint8
		if t.acceptStates[s] {
			af |= 1
		}
		if t.midAcceptStates[s] {
			af |= 2
		}
		if t.midAcceptNWStates[s] {
			af |= 4
		}
		if t.midAcceptWStates[s] {
			af |= 8
		}
		if t.midAcceptNLStates[s] {
			af |= 16
		}
		if t.immediateAcceptStates[s] {
			af |= 32
		}
		h.Write([]byte{af})
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
	eqMaps := func(ma, mb map[int]bool) bool {
		if len(ma) != len(mb) {
			return false
		}
		for s := range ma {
			if !mb[s] {
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
