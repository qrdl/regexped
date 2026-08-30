package compile

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp/syntax"
	"sort"

	"github.com/qrdl/regexped/config"
)

// PatternInfo holds the analysis result for a single pattern in a set.
// Populated by analyzePattern; consumed by set composition (Phase 2+).
type PatternInfo struct {
	fullPattern string
	name        string         // YAML name: field; empty when not set
	globalID    int            // index into cfg.Regexps
	prefixAST   *syntax.Regexp // AST before the mandatory literal; nil when trivial
	suffixAST   *syntax.Regexp // AST after the mandatory literal; nil when trivial
	mandLit     *mandatoryLit  // from findMandatoryLitRec
	splittable  bool           // false when splitAtPath rejects the path (routes to fallback)

	prefixDFA *dfaTable // built from prefixAST (reversed); nil when trivial
	prefixID  int       // index into dedup prefix pool; -1 = trivial

	trivialPrefix    bool // true when prefixAST is nil
	startAnchor      bool // \A / ^ : eligible only at input position 0
	lineAnchor       bool // (?m:^): eligible at position 0 and after any newline
	prefixMaxLen     int  // byte length of the (fixed-length) prefix; 0 = trivial
	isolatedFallback bool // non-greedy: isolate in own fallback bucket with leftmostFirst=false DFA

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
		// The >64-pattern WIDE accept form. Without these three, two tables
		// whose narrow masks have degraded to bit 0 (acceptBitsFor's wide
		// fallback) hash identically no matter which patterns they accept —
		// the aliasing this key exists to prevent. Length-prefixed so `[1,2]` and
		// `[12]` cannot collide.
		for _, m := range []map[int][]uint16{t.acceptWide, t.midAcceptWide, t.immAcceptWide} {
			list := m[s]
			writeU64(uint64(len(list)))
			for _, v := range list {
				writeU64(uint64(v))
			}
		}
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
	// The wide accept lists are compared for the same reason dfaFingerprint
	// hashes them: on the wide path the narrow masks carry no discriminating
	// power at all.
	eqWide := func(ma, mb map[int][]uint16) bool {
		if len(ma) != len(mb) {
			return false
		}
		for s, va := range ma {
			vb, ok := mb[s]
			if !ok || len(va) != len(vb) {
				return false
			}
			for i, v := range va {
				if vb[i] != v {
					return false
				}
			}
		}
		return true
	}
	return eqMaps(a.acceptStates, b.acceptStates) &&
		eqMaps(a.midAcceptStates, b.midAcceptStates) &&
		eqMaps(a.midAcceptNWStates, b.midAcceptNWStates) &&
		eqMaps(a.midAcceptWStates, b.midAcceptWStates) &&
		eqMaps(a.midAcceptNLStates, b.midAcceptNLStates) &&
		eqMaps(a.immediateAcceptStates, b.immediateAcceptStates) &&
		eqWide(a.acceptWide, b.acceptWide) &&
		eqWide(a.midAcceptWide, b.midAcceptWide) &&
		eqWide(a.immAcceptWide, b.immAcceptWide)
}

// hasBeginAnchor reports whether re contains a BeginText or BeginLine
// assertion anywhere, however deeply nested. Expressed through containsOp so
// the two AST walks cannot drift apart.
//
// Note what this does NOT mean: an anchor nested inside *, ? or an alternation
// does not restrict where the pattern can match. Use setTopLevelAnchor when
// deciding eligibility masks; this is for "does the assertion appear at all",
// e.g. rejecting a begin anchor inside a split suffix.
func hasBeginAnchor(re *syntax.Regexp) bool {
	return containsOp(re, syntax.OpBeginText) || containsOp(re, syntax.OpBeginLine)
}

// beginAnchorKind classifies a begin anchor for set eligibility masking.
type beginAnchorKind int

const (
	beginAnchorNone beginAnchorKind = iota
	// beginAnchorText is \A / non-multiline ^: the match can only start at
	// input position 0, whatever `from` the caller passed.
	beginAnchorText
	// beginAnchorLine is (?m:^): the match can start at position 0 or at any
	// position whose preceding byte is a newline. Collapsing this to
	// "position 0 only" was a real defect.
	beginAnchorLine
)

// topLevelBeginAnchorKind classifies the mandatory start of re. Returns
// beginAnchorNone when the leading assertion is not a begin anchor, or when
// the anchor sits inside *, ?, + or an alternation and therefore does not
// restrict the pattern at all.
func topLevelBeginAnchorKind(re *syntax.Regexp) beginAnchorKind {
	if re == nil {
		return beginAnchorNone
	}
	switch re.Op {
	case syntax.OpBeginText:
		return beginAnchorText
	case syntax.OpBeginLine:
		return beginAnchorLine
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return topLevelBeginAnchorKind(re.Sub[0])
		}
	case syntax.OpCapture:
		if len(re.Sub) > 0 {
			return topLevelBeginAnchorKind(re.Sub[0])
		}
	}
	return beginAnchorNone
}

// strippedAnchorKind classifies an only-begin-anchors prefix that is about to
// be replaced by an eligibility mask. \A wins over (?m:^) when both appear,
// because \A is the stricter of the two and the mask must not admit a
// position \A forbids.
func strippedAnchorKind(re *syntax.Regexp) beginAnchorKind {
	if re == nil {
		return beginAnchorNone
	}
	if containsOp(re, syntax.OpBeginText) {
		return beginAnchorText
	}
	if containsOp(re, syntax.OpBeginLine) {
		return beginAnchorLine
	}
	return beginAnchorNone
}

// containsOp reports whether re contains an operator of the given kind.
func containsOp(re *syntax.Regexp, op syntax.Op) bool {
	if re == nil {
		return false
	}
	if re.Op == op {
		return true
	}
	for _, sub := range re.Sub {
		if containsOp(sub, op) {
			return true
		}
	}
	return false
}

// isOnlyBeginAnchors reports whether re consists entirely of BeginText or
// BeginLine assertions (possibly concatenated). Used to decide whether a
// zero-length prefix can be safely stripped to just a startAnchor flag.
func isOnlyBeginAnchors(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	switch re.Op {
	case syntax.OpBeginText, syntax.OpBeginLine:
		return true
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !isOnlyBeginAnchors(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	case syntax.OpCapture:
		return len(re.Sub) == 1 && isOnlyBeginAnchors(re.Sub[0])
	}
	return false
}

// setTopLevelAnchor records the eligibility restriction implied by a fallback
// pattern's leading anchor. The fallback bucket's DFA models the whole pattern
// including the assertion, so this is a pre-filter that saves a DFA run rather
// than the sole implementation of the anchor — but it must not be STRICTER
// than the assertion, which is what collapsing (?m:^) to "position 0" did.
func (info *PatternInfo) setTopLevelAnchor(parsed *syntax.Regexp) {
	switch topLevelBeginAnchorKind(parsed) {
	case beginAnchorText:
		info.startAnchor = true
	case beginAnchorLine:
		info.lineAnchor = true
	}
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
			// setTopLevelAnchor, not hasBeginAnchor: the eligibility mask is a
			// pre-filter over a fallback DFA that already models the assertion,
			// so it must never be STRICTER than the pattern. hasBeginAnchor is
			// the anywhere-in-the-tree scan — it fires for anchors nested in
			// *, ?, or an alternation (which restrict nothing) and collapses
			// (?m:^) to "position 0 only", which is B43. This site was missed
			// when the others were converted.
			info.setTopLevelAnchor(parsed)
			// suffixDFA is built later by compileFallback via mergeSuffixDFA.
			return info, nil
		}
	}

	// Patterns whose minimum match length is 0 can match without consuming their
	// mandatory literal (e.g. (aa)* matches ""). Route them to fallback so the
	// full-pattern DFA runs at every position, including on empty inputs.
	//
	// NO exception for begin-anchored ones. A comment here used to promise
	// that `\z^` and friends were "excluded from sets entirely" because of
	// degenerate DFAs with false EOF accepts; no such exclusion exists
	// anywhere, and the branch below routes them to fallback like every other
	// zero-length-matchable pattern. Their answers are checked against Go in
	// TestZCaretIsNotExcluded.
	if minLen, _ := regexpMinMaxLen(parsed); minLen == 0 {
		info.splittable = false
		info.setTopLevelAnchor(parsed)
		return info, nil
	}

	lit, path := findMandatoryLitRec(parsed, 0, 0)
	info.mandLit = lit

	if lit != nil {
		prefixAST, suffixAST, ok := splitAtPath(parsed, path)
		info.splittable = ok
		if ok {
			// Zero-length prefix: only strip if it consists purely of begin-anchors (^, \A).
			// Mixed prefixes (e.g. ^$, \b) or non-begin zero-length assertions route to fallback.
			if prefixAST != nil {
				if _, maxLen := regexpMinMaxLen(prefixAST); maxLen == 0 {
					if isOnlyBeginAnchors(prefixAST) {
						switch strippedAnchorKind(prefixAST) {
						case beginAnchorLine:
							info.lineAnchor = true
						default:
							info.startAnchor = true
						}
						prefixAST = nil
					} else {
						// Non-begin or mixed zero-length prefix: route to fallback.
						info.splittable = false
					}
				}
			}
			// Begin-anchors in the suffix (e.g. a^) can't fire after the literal has
			// been consumed. Route to fallback so the full-pattern DFA handles it correctly.
			if suffixAST != nil && hasBeginAnchor(suffixAST) {
				info.splittable = false
			}
			// Keep the split ONLY if it survived every rejection above.
			// Retaining prefixAST after a rejection is one of the two
			// mechanisms behind the \b-in-a-set defect: a `\b` prefix is
			// zero-length and not an only-begin-anchor, so the split is
			// rejected — but the retained prefixAST still made the pattern
			// look split, so it got a backward "prefix DFA" for a bare
			// assertion (which accepts nothing) and a suffix DFA for a
			// fragment rather than the whole pattern. The result was a
			// pattern that silently never matched.
			if info.splittable {
				info.prefixAST = prefixAST
				info.suffixAST = suffixAST
			}
		}
		// Fallback patterns: only truly anchored if the begin-anchor is at the
		// mandatory top level (not inside *, ?, etc.).
		if !info.splittable {
			info.setTopLevelAnchor(parsed)
		}
	}

	// Variable-length prefixes route to fallback.
	//
	// The split representation prefix.literal.suffix answers "where does a
	// match starting at s end?" by finding a literal occurrence and walking
	// the backward prefix DFA to recover s. That is exact only while each
	// match start maps to exactly ONE literal position — i.e. while the
	// prefix has a fixed length. With a variable-length prefix one start has
	// several candidate literal positions with DIFFERENT extents, and which
	// one RE2 picks depends on the prefix's greedy structure, which a
	// backward DFA cannot express. Two failures follow directly, both
	// observed on `a?a` over "aa":
	//
	//   - the backward DFA reports the LEFTMOST start it can reach, so the
	//     match at start 1 is never generated at all (only 0-2 is);
	//   - the same start is reported twice with different extents (0-1 from
	//     the empty-prefix candidate, 0-2 from the one-char-prefix
	//     candidate), where RE2 has exactly one answer, 0-2.
	//
	// This is the root cause behind the back-dated-tuple defect.
	// Routing to fallback runs the whole pattern's DFA anchored at each
	// position, which is the only construction that gets the extent right —
	// and it is also what drain class B says such a set must do, since a
	// literal arbitrarily far to the right can serve a match starting here so
	// nothing can be skipped anyway. The cost is the literal frontend, which
	// a class-B set could not have used regardless.
	if info.prefixAST != nil {
		if minLen, maxLen := regexpMinMaxLen(info.prefixAST); minLen != maxLen {
			info.splittable = false
			info.prefixAST = nil
			info.suffixAST = nil
			info.setTopLevelAnchor(parsed)
		}
	}

	// A prefix containing \b or \B routes to fallback for the same reason,
	// by a different mechanism.
	//
	// The prefix is verified by walking a REVERSED DFA leftward from the
	// literal (buildLitAnchorBackScanBody). That walk carries no word-boundary
	// context: it has no prevWasWord bit and never reads the wordChar table,
	// because a backward scan cannot see the byte at input[start-1] that a
	// boundary sitting at the prefix's LEFT EDGE depends on. Emitting it
	// anyway silently loses matches — `\B.0` over "000" splits into prefix
	// `\B.` + literal "0" and returned NOTHING, where [1,3) is a real match.
	//
	// The forward suffix walk is unaffected and needs no guard: it threads
	// exactly that context through midAcceptNW/midAcceptW, which is what
	// FABLE B40 built. Only the backward prefix scan is blind, so only a
	// prefix boundary disqualifies the split.
	if info.prefixAST != nil && regexpHasWordBoundary(info.prefixAST) {
		info.splittable = false
		info.prefixAST = nil
		info.suffixAST = nil
		info.setTopLevelAnchor(parsed)
	}

	// A prefix containing `$`, `\z` or `(?m:$)` routes to fallback, for the
	// third instance of the same blindness.
	//
	// The backward prefix DFA is a plain byte automaton over the reversed
	// prefix. End-of-text is not a byte, so reverseRegexp/newDFA simply drop
	// the assertion, and the walk then accepts a prefix the pattern forbids.
	// Unlike the `\b` case this does not lose matches — it INVENTS them, and
	// the invention can be total: `.$0` cannot match anything at all (nothing
	// follows end-of-text), yet the split reported [0,2) on "00" because the
	// prefix check saw only `.`.
	//
	// Begin-anchors need no such guard and must not get one: `^`/`\A`/`(?m:^)`
	// are modelled positively by startAnchor/lineAnchor and the eligibility
	// masks built from them, which is why `^a0` is already correct.
	//
	// The suffix side is likewise fine — an end-assertion AFTER the literal is
	// exactly what the forward suffix DFA's ecEnd channel expresses, so `0$`
	// keeps its split and its literal frontend.
	if info.prefixAST != nil && regexpHasEndAssertion(info.prefixAST) {
		info.splittable = false
		info.prefixAST = nil
		info.suffixAST = nil
		info.setTopLevelAnchor(parsed)
	}

	info.trivialPrefix = info.prefixAST == nil
	if !info.trivialPrefix && info.prefixAST != nil {
		// Only the MAX is kept: a variable-length prefix is fallback-routed
		// above, so min == max here, and prefixMinLen was a field written and
		// never read.
		_, maxLen := regexpMinMaxLen(info.prefixAST)
		info.prefixMaxLen = maxLen
	}

	// Build prefix DFA (reversed prefix AST).
	if !info.trivialPrefix {
		revRe := reverseRegexp(info.prefixAST)
		revProg, err := syntax.Compile(revRe.Simplify())
		if err != nil {
			return nil, fmt.Errorf("analyzePattern: compile prefix %q: %w", re.Pattern, err)
		}
		revD, revOk := newDFA(revProg, false, false, maxHelperDFAStates)
		if !revOk {
			return nil, fmt.Errorf("analyzePattern: prefix %q: %w", re.Pattern, ErrDFAStateLimit)
		}
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
	d, ok := newDFA(prog, false, false, maxHelperDFAStates)
	if !ok {
		return nil, fmt.Errorf("analyzePattern: suffix %q: %w", re.Pattern, ErrDFAStateLimit)
	}
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
	// AcceptSparseSet: per accepting DFA state, a SORTED list of pattern
	// indices instead of a bitmask. It exists because the
	// bitmask caps a bucket at 64 patterns — 32 in practice, since every mask
	// on the per-candidate path is an i32 — and a set whose patterns share one
	// mandatory literal then splits into ceil(N/32) buckets, each costing its
	// own suffix-DFA call at every candidate position. Measured: 128 patterns
	// sharing a literal cost 3.33x one bucket's work on a literal-dense input.
	AcceptSparseSet
)

// CompileSetOptions holds tunable parameters for set composition.
// Zero value uses defaults.
type CompileSetOptions struct {
	BitmaskWidth          int   // max patterns per bucket using AcceptBitmask; default 32
	MaxPatternsPerBucket  int   // hard cap for AcceptSparseSet (Phase 6); default 4096
	BudgetBytes           int   // max merged DFA table bytes per bucket; default 65536
	BudgetStates          int   // max DFA states per merged bucket; default 512
	BudgetStatesPreFilter int   // pre-filter: suffixStates * combinedClassCount; default 65536
	MaxFallbackStates     int   // max DFA states for a single-pattern fallback bucket; default 1024
	ACBudgetBytes         int   // max Aho-Corasick table bytes for the whole set; default 524288
	TableBase             int32 // byte offset where this set's DFA tables start in memory; default 0
	TableMemIdx           int   // 0 = standalone (single memory), 1 = embedded (multi-memory after merge)
	// AllowSparseAccept permits G17's >32-pattern buckets. Off by default so a
	// caller that has not thought about probes cannot get one: see CompileSet.
	AllowSparseAccept bool

	// LikelyMode is the resolved set-level LikelyMode hint: consumed by the
	// set-frontend density gate (H.3, shipped — forces Shufti for a 17..64-byte
	// first-byte union under LikelyNoMatch).
	LikelyMode LikelyMode
}

// bucketMaskBits is the width of the per-bucket accept bitmask, and it is not
// a tunable: every emitter on the candidate path carries an i32 mask and caps
// its unrolled per-pattern chain at 32 (set_find.go, set_caps.go,
// set_probe.go, startable.go, set_emit.go's group masks). A bucket wider than
// this loses patterns 32.. from every mask, prefix check and probe SILENTLY —
// the exact class G17 was built to end.
const bucketMaskBits = 32

// bitmaskWidth is the number of patterns one BITMASK bucket may hold.
//
// CLAMPED to bucketMaskBits. BitmaskWidth is a test-only knob and only ever
// narrows a bucket usefully; a caller passing 64 used to get buckets whose
// patterns 32..63 vanished from every mask with no panic and no warning.
// Narrowing is still allowed — it is how the tests reach the multi-bucket
// shapes cheaply.
func (o CompileSetOptions) bitmaskWidth() int {
	if o.BitmaskWidth > 0 && o.BitmaskWidth < bucketMaskBits {
		return o.BitmaskWidth
	}
	return bucketMaskBits
}

// maxPatternsPerBucket caps a sparse-set bucket. Pattern indices are u16 in the
// accept lists, so the format's own ceiling is 65,535; the default is far below
// that because a bucket this large is a WAF rule group, not a mistake, and the
// merged DFA still has to fit budgetStates/budgetBytes.
func (o CompileSetOptions) maxPatternsPerBucket() int {
	if o.MaxPatternsPerBucket > 0 {
		return o.MaxPatternsPerBucket
	}
	return 4096
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

func (o CompileSetOptions) maxFallbackStates() int {
	if o.MaxFallbackStates > 0 {
		return o.MaxFallbackStates
	}
	return 1024
}

// acBudgetBytes is the ceiling on total Aho-Corasick table bytes for a set.
//
// It is deliberately much larger than budgetBytes(): that budget sizes ONE of
// many per-bucket DFA tables, while this sizes the single table the whole set
// shares. 512 KB covers every literal shape measured at
// 128 literals with headroom — ~75 KB for a shared-prefix set, ~250 KB for the
// expensive shape where every literal starts with a different byte — and keeps
// the worst case well under the 1.5 MB a regex-automata module costs,
// so the size story survives even at the ceiling.
//
// Denominated in BYTES rather than nodes on purpose. Node count is a poor
// proxy for cost and varies with prefix sharing by more than an order of
// magnitude, which is exactly how the old 32-NODE cap came to bite at 17
// literals for one shape and 26 for another.
func (o CompileSetOptions) acBudgetBytes() int {
	if o.ACBudgetBytes > 0 {
		return o.ACBudgetBytes
	}
	return 512 * 1024
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
// Returns error if len(asts) > BitmaskWidth (default 32).
//
// The AcceptKind return is always AcceptBitmask today; no caller uses it yet.
// It exists so Phase 6 can add
// AcceptSparseSet for WAF-scale buckets (>BitmaskWidth patterns) without
// changing this signature or any call site.
//
//nolint:unparam // second return value is a deliberate Phase 6 extensibility stub, see comment above
func mergeSuffixDFA(asts []*syntax.Regexp, opts CompileSetOptions) (*dfaTable, AcceptKind, error) {
	// Through the accessor, not a second inline default: the two used to be
	// written out separately, which is how a clamp added in one of them would
	// have missed the other.
	bw := opts.bitmaskWidth()
	if len(asts) == 0 {
		return nil, 0, fmt.Errorf("mergeSuffixDFA: empty pattern list")
	}
	if len(asts) > bw {
		return nil, 0, fmt.Errorf("mergeSuffixDFA: %d patterns exceed bitmaskWidth %d", len(asts), bw)
	}

	progs, err := compileSetASTs(asts, "mergeSuffixDFA")
	if err != nil {
		return nil, 0, err
	}

	// Build union NFA manually so each pattern gets a distinct InstMatch.
	unionProg, patternBits := buildUnionProg(progs, bw)

	// maxHelperDFAStates, NOT opts.budgetStates(): callers (binPack) expect
	// a REAL, if over-budget, table back so they can record a precise
	// "state_count_exceeded" diagnostic (merged_states/budget_states) for
	// the common case of a legitimately-large-but-finite merge — the same
	// contract compile.go's primary DFA construction has with
	// resolveMaxDFAStates. Only pathological, effectively-unbounded
	// constructions (beyond maxHelperDFAStates) hit ErrDFAStateLimit.
	d, ok := newDFA(unionProg, false, true, maxHelperDFAStates, patternBits)
	if !ok {
		return nil, 0, ErrDFAStateLimit
	}
	t := dfaTableFromCanonical(d)
	return t, AcceptBitmask, nil
}

// compileSetASTs compiles each AST into its own NFA program, which is the
// first step of all four merge*DFA functions.
//
// The four stay separate on purpose — leftmost-first and narrow/wide are real
// axes with different callers — but this eight-line loop was written out four
// times with nothing but the error prefix differing.
func compileSetASTs(asts []*syntax.Regexp, what string) ([]*syntax.Prog, error) {
	progs := make([]*syntax.Prog, len(asts))
	for k, a := range asts {
		p, err := syntax.Compile(a.Simplify())
		if err != nil {
			return nil, fmt.Errorf("%s: compile pattern %d: %w", what, k, err)
		}
		progs[k] = p
	}
	return progs, nil
}

// buildUnionProg concatenates individual NFAs into a single union prog with an
// InstAlt chain at the start. Each pattern k's InstMatch instructions are
// assigned bit k in the returned patternBits slice (indexed by instruction PC).
//
// Instruction 0 in each individual prog is always InstFail by convention.
// In the combined prog we reserve position 0 as a shared InstFail; instructions
// from prog k (skipping its own inst 0) start at offsets[k].
// mergeSuffixDFASparseSet is mergeSuffixDFA for a bucket that exceeds the
// bitmask width: one merged DFA over ALL the patterns, with per-state accept
// LISTS rather than a u64 mask (G17 sparse accept).
//
// The point is call count, not table size. A candidate position today runs one
// suffix-DFA call per bucket; merging 128 patterns behind their shared literal
// into one bucket makes that one call. The prerequisite — that the merge
// still fits the state and byte budgets — was measured before this was written
// and passes with room: 128 patterns of three WAF-ish shapes come to 15-85
// states and 4-22 KB against 512 states / 64 KB.
//
// Returns the table plus the dfa, because the accept lists live on the latter;
// the caller needs both to emit.
func mergeSuffixDFASparseSet(asts []*syntax.Regexp, opts CompileSetOptions) (*dfaTable, *dfa, error) {
	if len(asts) == 0 {
		return nil, nil, fmt.Errorf("mergeSuffixDFASparseSet: empty pattern list")
	}
	if max := opts.maxPatternsPerBucket(); len(asts) > max {
		return nil, nil, fmt.Errorf("mergeSuffixDFASparseSet: %d patterns exceed maxPatternsPerBucket %d",
			len(asts), max)
	}
	progs, err := compileSetASTs(asts, "mergeSuffixDFASparseSet")
	if err != nil {
		return nil, nil, err
	}
	unionProg, patternIdx := buildUnionProgIndexed(progs)
	d, ok := newDFAWide(unionProg, true, maxHelperDFAStates, patternIdx)
	if !ok {
		return nil, nil, ErrDFAStateLimit
	}
	return dfaTableFromCanonical(d), d, nil
}

// buildUnionProgIndexed is buildUnionProg's >64-pattern twin: instead of a
// per-PC bitmask it returns a per-PC pattern INDEX (-1 for instructions that
// belong to no pattern), which is what lifts the 64-pattern ceiling.
//
// The index is set for EVERY instruction of pattern k, not only its InstMatch,
// mirroring buildUnionProg's bits exactly — nfaBuildInputMap's leftmost-first
// suppression reads it to decide whether a byte-consumer still has a live
// owner, and narrowing it to InstMatch would make that suppression global.
//
// Offsets are recomputed here rather than shared with buildUnionProg because
// that function does not expose them; they must stay in step, which is why
// both derivations sit next to each other and the test asserts every pattern's
// InstMatch is found.
func buildUnionProgIndexed(progs []*syntax.Prog) (*syntax.Prog, []int32) {
	unionProg, _ := buildUnionProg(progs, len(progs))
	idx := make([]int32, len(unionProg.Inst))
	for i := range idx {
		idx[i] = -1
	}
	off := 1 // position 0 is the shared InstFail
	for k, p := range progs {
		for i := 1; i < len(p.Inst); i++ {
			pos := off + i - 1
			if pos < len(idx) {
				idx[pos] = int32(k)
			}
		}
		off += len(p.Inst) - 1
	}
	return unionProg, idx
}

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

// buildStartAnywhereUnionProg wraps buildUnionProg's alternation in a
// `(?s:.)*` prefix, turning the union into an automaton that can begin a match
// at ANY position rather than only at the one it was started from.
//
// This is what lets the scan trio answer "does pattern k match somewhere?" in
// a single left-to-right pass. Without it a set with no mandatory literal has
// to restart every bucket's automaton at every position, which is quadratic on
// unbounded patterns: `[^\n]*ERROR` re-scans to end of line from each of
// 100,000 positions, which measured 151M fuel on a 3-pattern set.
//
// Two instructions are appended:
//
//	dotAlt: Alt(Out: <union alternation>, Arg: dotAny)
//	dotAny: RuneAny(Out: dotAlt)
//
// and Start becomes dotAlt. Because the DFA is built with leftmostFirst=false,
// the epsilon closure keeps BOTH arms live, so at every input position the set
// of live NFA threads includes a fresh start of every pattern. The returned
// patternBits are buildUnionProg's, extended with zeroes for the two new
// instructions — they belong to no pattern and must never contribute an
// accept bit.
//
// The prefix is deliberately `(?s:.)` (InstRuneAny, newline included): the
// question is whether a match exists anywhere in the input, which does not
// stop at line boundaries. Per-pattern `(?m:^)`/`(?m:$)` semantics are a
// different matter and are excluded by the caller.
func buildStartAnywhereUnionProg(progs []*syntax.Prog, bitmaskWidth int) (*syntax.Prog, []uint64) {
	union, patternBits := buildUnionProg(progs, bitmaskWidth)
	appendStartAnywherePrefix(union)
	return union, append(patternBits, 0, 0)
}

// appendStartAnywherePrefix appends the dotAlt/dotAny pair and rewrites Start.
//
// The ONE place the automaton's shape is written down. Its two callers differ
// only in what they say about the appended pair — no pattern owns it, which is
// 0 in a bitmask and -1 in an index — and the comment on the pair used to
// concede they "must stay in step".
func appendStartAnywherePrefix(union *syntax.Prog) {
	n := len(union.Inst)
	dotAlt, dotAny := n, n+1
	union.Inst = append(union.Inst,
		syntax.Inst{Op: syntax.InstAlt, Out: uint32(union.Start), Arg: uint32(dotAny)},
		syntax.Inst{Op: syntax.InstRuneAny, Out: uint32(dotAlt)},
	)
	union.Start = dotAlt
}

// buildStartAnywhereUnionProgIndexed is buildStartAnywhereUnionProg for a set
// whose ids do not fit the u64 accept mask: it
// returns per-PC pattern INDICES for newDFAWide instead of per-PC bitmasks.
//
// The two functions must stay in step — same two appended instructions, same
// new Start — because they are two spellings of one automaton and a divergence
// would make the wide form answer a different question from the narrow one.
// The appended pair belongs to no pattern, so its index entries are -1, which
// is exactly what acceptWideFor skips.
func buildStartAnywhereUnionProgIndexed(progs []*syntax.Prog) (*syntax.Prog, []int32) {
	union, patternIdx := buildUnionProgIndexed(progs)
	appendStartAnywherePrefix(union)
	return union, append(patternIdx, -1, -1)
}

// --------------------------------------------------------------------------
// Phase 4a: multi-pattern Teddy + frontend strategy selection

// frontendKind is the literal-scan strategy chosen for a set.
type frontendKind int

const (
	frontendTeddy  frontendKind = iota // 1–16 literals, any length (>4 bytes: probe first 4, verify rest)
	frontendAC                         // >16 literals → Aho-Corasick (capped by acBudgetBytes)
	frontendScalar                     // fallback: byte-by-byte scan
	// frontendShufti: SIMD first-byte pre-filter wrapping the scalar
	// per-position bucket check. Picked when:
	//   - the set would otherwise have used the scalar path,
	//   - 17 ≤ |unionFirstBytes| ≤ 64,
	//   - AND either `shuftiBeatsScalar(unionFirstBytes)` (density wins)
	//     or set-level LikelyMode is LikelyNoMatch (Gap H.3 Action 5).
	// Requires zero fallback buckets — fallback runs at every position
	// so a first-byte SIMD skip can't safely advance past it.
	frontendShufti
	// frontendPackedPair: two-column byte-equality SIMD prefilter.
	// Two v128 loads, one i8x16.eq per probe
	// byte, one v128.and and one bitmask per 16-byte chunk — flat in literal
	// count and far cheaper per byte than Teddy's four nibble-table lookups.
	// Chosen for small literal sets whose probe window has a rare, narrow
	// two-column signature; see chooseLiteralFrontend for the crossover.
	frontendPackedPair
)

func (f frontendKind) String() string {
	switch f {
	case frontendTeddy:
		return "teddy"
	case frontendAC:
		return "ac"
	case frontendShufti:
		return "shufti"
	case frontendPackedPair:
		return "packed-pair"
	default:
		return "scalar"
	}
}

// teddyTables holds the precomputed nibble tables for multi-pattern Teddy.
// Supports up to 16 literals via two groups of 8 (group A = literals 0-7,
// group B = literals 8-15). Literals longer than 4 bytes use only their first
// 4 bytes as the probe; the Teddy dispatch verifies the remaining bytes.
type teddyTables struct {
	// Group A: literals 0-7
	T0Lo, T0Hi [16]byte
	T1Lo, T1Hi [16]byte
	T2Lo, T2Hi [16]byte
	T3Lo, T3Hi [16]byte
	// Group B: literals 8-15 (only populated when TwoGroups is true)
	BT0Lo, BT0Hi [16]byte
	BT1Lo, BT1Hi [16]byte
	BT2Lo, BT2Hi [16]byte
	BT3Lo, BT3Hi [16]byte

	MinLen    int  // min(litLen, 4) across all literals — how many bytes Teddy probes
	TwoByte   bool // T1 tables valid (all literals ≥ 2 bytes)
	ThreeByte bool // T2 tables valid (all literals ≥ 3 bytes)
	FourByte  bool // T3 tables valid (all literals ≥ 4 bytes)
	TwoGroups bool // true when lanes 8..15 are in use

	// LaneToIDs[k] lists the literals assigned to lane k. Up to 16 lanes
	// (two groups of 8); a lane bit in the Teddy candidate mask means "some
	// literal of this lane may start here".
	//
	// At or below 16 literals each lane holds exactly one literal, and the
	// assignment is the identity — lane k is literal k — which is what the
	// pre-bucketing implementation did, so those sets emit unchanged code.
	// Above 16, several literals share a lane and Bucketed is set.
	LaneToIDs [][]int

	// Bucketed reports that some lane holds more than one literal, so a
	// surviving lane bit no longer identifies a literal and every member must
	// be byte-verified from offset 0. See buildTeddyTablesMulti.
	Bucketed bool
}

// teddyMaxLiterals is the most literals a bucketed Teddy will accept.
//
// 64 matches aho-corasick's packed Teddy, which takes up to 64 literals when
// the shortest is ≥2 bytes and 16 when it is 1 byte (packed/teddy/builder.rs).
// Hyperscan's equivalent limit is its TEDDY_BUCKET_LOAD of 6 literals per
// bucket over 8 buckets, i.e. 48. The binding constraint is verification cost:
// a lane bit only says "some literal in this lane may start here", so every
// member of a hit lane is byte-compared, and lanes grow as literals do.
const teddyMaxLiterals = 64

// teddySingleByteMax is the cap when the shortest literal is one byte. A
// 1-byte fingerprint cannot discriminate, so lane hits become frequent and
// verification dominates; aho-corasick draws the same line at 16.
const teddySingleByteMax = 16

// teddyMinLenForBucketing is the shortest literal a bucketed Teddy will accept.
// Below 2 bytes the fingerprint is one nibble pair and lane hits are constant,
// so the AC automaton is the better structure however many literals there are.
const teddyMinLenForBucketing = 2

// teddyFirstByteCrossover is the number of DISTINCT FIRST BYTES at which
// bucketed Teddy overtakes Aho-Corasick above 16 literals.
//
// Measured, not assumed: at 32 literals over a 100KB
// no-match corpus, AC leads 419K to 669K fuel at one distinct first byte, is
// level at two and three, and falls behind from four onward — 1.19x at four,
// 2.56x at eight, 6.32x at thirty-two — while Teddy stays flat at ~1.04M
// regardless.
//
// It is the same boundary emitSetMatchFnFinalAC uses to switch its prefilter
// from a compare chain to Shufti, and for the same underlying reason: at four
// or more first bytes AC can no longer answer "could a literal start here?"
// with a couple of compares, and its ability to skip input degrades from
// there.
const teddyFirstByteCrossover = 4

// assignTeddyLanes maps each literal to one of 8 or 16 Teddy lanes.
//
// At or below 16 literals the mapping is the identity, preserving the exact
// lane layout (and therefore the exact emitted code) of every set that
// compiled before bucketing existed.
//
// Above 16, literals are grouped by the low nybbles of their probe bytes —
// the same key aho-corasick's Teddy groups on (packed/teddy/generic.rs) —
// so members of a lane agree on every T*Lo entry and only the T*Hi tables can
// produce cross-product false positives. Distinct keys are then handed to the
// least-loaded lane, which bounds the verification work a single lane hit can
// trigger; aho-corasick instead assigns `(BUCKETS-1) - id%BUCKETS`, which it
// needs because its verifier stops at the first match and must not let lane
// order imply match priority. We verify every member of a hit lane, so match
// semantics do not depend on lane order and balance is the only concern.
func assignTeddyLanes(literals [][]byte, minProbe int) []int {
	lanes := make([]int, len(literals))
	if len(literals) <= 16 {
		for i := range lanes {
			lanes[i] = i
		}
		return lanes
	}
	const numLanes = 16
	load := make([]int, numLanes)
	keyLane := make(map[string]int, len(literals))
	for i, lit := range literals {
		n := minProbe
		if n > len(lit) {
			n = len(lit)
		}
		var kb [4]byte
		for j := 0; j < n; j++ {
			kb[j] = lit[j] & 0x0F
		}
		key := string(kb[:n])
		lane, ok := keyLane[key]
		if !ok {
			lane = 0
			for l := 1; l < numLanes; l++ {
				if load[l] < load[lane] {
					lane = l
				}
			}
			keyLane[key] = lane
		}
		lanes[i] = lane
		load[lane]++
	}
	return lanes
}

// buildTeddyTablesMulti builds nibble tables for up to teddyMaxLiterals
// literals of any length. Literals longer than 4 bytes are probed on their
// first 4 bytes; the caller must verify the remaining bytes after a hit.
//
// Up to 16 literals get one lane each (lane k = literal k), and a surviving
// lane bit therefore identifies a literal exactly on the probed bytes.
//
// Above 16 the literals are BUCKETED into the 16 lanes, which is what lifts
// the old hard ceiling. Literals sharing the low nybbles of their probe bytes
// are placed in the same lane, so that lane's T*Lo tables stay exact for its
// members; remaining lanes are handed out least-loaded-first to keep
// verification cost even. A shared lane costs precision: the tables are ORs
// over the lane's members, so bit k survives when SOME member matches the low
// nybble at each position and SOME (possibly different) member matches the
// high nybble — a cross-product false positive. Callers must therefore verify
// a bucketed hit from byte 0, not from MinLen (t.Bucketed says which).
//
// Returns (nil, false) when the set is empty, over the cap, or contains an
// empty literal. chooseLiteralFrontend applies the same conditions, so a
// caller that trusts it will not see false.
func buildTeddyTablesMulti(literals [][]byte) (*teddyTables, bool) {
	if len(literals) == 0 || len(literals) > teddyMaxLiterals {
		return nil, false
	}
	for _, lit := range literals {
		if len(lit) == 0 {
			return nil, false
		}
	}

	minProbe := 4
	for _, lit := range literals {
		pl := len(lit)
		if pl > 4 {
			pl = 4
		}
		if pl < minProbe {
			minProbe = pl
		}
	}
	if minProbe < 2 && len(literals) > teddySingleByteMax {
		return nil, false
	}

	t := &teddyTables{}
	t.MinLen = minProbe
	t.TwoByte = minProbe >= 2
	t.ThreeByte = minProbe >= 3
	t.FourByte = minProbe >= 4

	litLane := assignTeddyLanes(literals, minProbe)
	numLanes := 8
	for _, lane := range litLane {
		if lane >= 8 {
			numLanes = 16
			break
		}
	}
	t.TwoGroups = numLanes > 8
	t.LaneToIDs = make([][]int, numLanes)
	for litIdx, lane := range litLane {
		t.LaneToIDs[lane] = append(t.LaneToIDs[lane], litIdx)
		if len(t.LaneToIDs[lane]) > 1 {
			t.Bucketed = true
		}
	}

	for litIdx, lit := range literals {
		lane := litLane[litIdx]
		k := lane % 8
		bit := byte(1 << uint(k))
		if lane < 8 {
			// Group A
			t.T0Lo[lit[0]&0x0F] |= bit
			t.T0Hi[lit[0]>>4] |= bit
			if len(lit) >= 2 && t.TwoByte {
				t.T1Lo[lit[1]&0x0F] |= bit
				t.T1Hi[lit[1]>>4] |= bit
			}
			if len(lit) >= 3 && t.ThreeByte {
				t.T2Lo[lit[2]&0x0F] |= bit
				t.T2Hi[lit[2]>>4] |= bit
			}
			if len(lit) >= 4 && t.FourByte {
				t.T3Lo[lit[3]&0x0F] |= bit
				t.T3Hi[lit[3]>>4] |= bit
			}
		} else {
			// Group B (literals 8-15)
			t.BT0Lo[lit[0]&0x0F] |= bit
			t.BT0Hi[lit[0]>>4] |= bit
			if len(lit) >= 2 && t.TwoByte {
				t.BT1Lo[lit[1]&0x0F] |= bit
				t.BT1Hi[lit[1]>>4] |= bit
			}
			if len(lit) >= 3 && t.ThreeByte {
				t.BT2Lo[lit[2]&0x0F] |= bit
				t.BT2Hi[lit[2]>>4] |= bit
			}
			if len(lit) >= 4 && t.FourByte {
				t.BT3Lo[lit[3]&0x0F] |= bit
				t.BT3Hi[lit[3]>>4] |= bit
			}
		}
	}
	return t, true
}

// buildTeddyRawBytes serialises the teddyTables nibble tables into a flat byte slice.
// Layout: groupA(T0Lo T0Hi [T1Lo T1Hi] [T2Lo T2Hi] [T3Lo T3Hi])
//
//	[groupB(BT0Lo BT0Hi ...) when TwoGroups]
func buildTeddyRawBytes(t *teddyTables) []byte {
	appendGroup := func(b []byte, t0lo, t0hi, t1lo, t1hi, t2lo, t2hi, t3lo, t3hi *[16]byte) []byte {
		b = append(b, t0lo[:]...)
		b = append(b, t0hi[:]...)
		if t.TwoByte {
			b = append(b, t1lo[:]...)
			b = append(b, t1hi[:]...)
		}
		if t.ThreeByte {
			b = append(b, t2lo[:]...)
			b = append(b, t2hi[:]...)
		}
		if t.FourByte {
			b = append(b, t3lo[:]...)
			b = append(b, t3hi[:]...)
		}
		return b
	}
	var b []byte
	b = appendGroup(b, &t.T0Lo, &t.T0Hi, &t.T1Lo, &t.T1Hi, &t.T2Lo, &t.T2Hi, &t.T3Lo, &t.T3Hi)
	if t.TwoGroups {
		b = appendGroup(b, &t.BT0Lo, &t.BT0Hi, &t.BT1Lo, &t.BT1Hi, &t.BT2Lo, &t.BT2Hi, &t.BT3Lo, &t.BT3Hi)
	}
	return b
}

// teddyGroupABytes returns the byte size of group A in the raw Teddy data.
func teddyGroupABytes(t *teddyTables) int32 {
	n := int32(32) // T0Lo + T0Hi
	if t.TwoByte {
		n += 32
	}
	if t.ThreeByte {
		n += 32
	}
	if t.FourByte {
		n += 32
	}
	return n
}

// litUnionFirstBytes returns the sorted distinct first bytes across `lits`.
// Empty literals are skipped (their first byte is undefined; the standard
// frontend selection already rejects sets with empty literals before this
// helper is called for the Shufti decision in H.3).
func litUnionFirstBytes(lits [][]byte) []byte {
	var seen [256]bool
	for _, lit := range lits {
		if len(lit) == 0 {
			continue
		}
		seen[lit[0]] = true
	}
	out := make([]byte, 0, 64)
	for b := 0; b < 256; b++ {
		if seen[b] {
			out = append(out, byte(b))
		}
	}
	return out
}

// chooseLiteralFrontend selects the scan strategy for a set of mandatory literals.
// Teddy is used for ≤16 non-empty literals of any length (literals >4 bytes use
// their first 4 bytes as the probe; the dispatch verifies remaining bytes).
// AC is used above 16 literals; CompileSet demotes it to scalar if the
// automaton's tables exceed acBudgetBytes, recording that in SetDiag.
func chooseLiteralFrontend(literals [][]byte) frontendKind {
	if len(literals) == 0 {
		return frontendScalar
	}
	minLen := 1 << 30
	var firstBytes [256]bool
	distinctFirst := 0
	for _, lit := range literals {
		if len(lit) == 0 {
			return frontendScalar // empty literal → scalar
		}
		if len(lit) < minLen {
			minLen = len(lit)
		}
		if !firstBytes[lit[0]] {
			firstBytes[lit[0]] = true
			distinctFirst++
		}
	}
	if len(literals) <= 16 {
		// A two-column packed pair beats Teddy whenever one exists: it reads
		// two 16-byte chunks and does one i8x16.eq per probe byte, against
		// Teddy's four chunk loads and four nibble-table swizzle pairs. Both
		// verify candidates the same way, so the pair's only cost is a higher
		// false-positive rate, which choosePackedPair minimises by picking the
		// rarest columns. Measured on the keywords-2/8 shapes at 100KB:
		// Teddy 6.5 fuel/byte, AC 4.1, packed-pair ~1.8.
		if _, ok := choosePackedPair(literals); ok {
			return frontendPackedPair
		}
		// No qualifying pair: one-byte literals (a single probe column), or a
		// probe window whose columns are too wide for byte-equality. Teddy's
		// nibble tables absorb column width that eq-splats cannot, so it stays
		// the fallback.
		//
		// Routing these to AC instead was measured and NOT adopted. On the
		// keywords-2/8 shape AC does beat Teddy by ~37%, but those
		// sets now take packed-pair, so that measurement says nothing about
		// the sets which actually reach this line — and extrapolating it here
		// would put a single one-byte literal through a full Aho-Corasick
		// automaton. Left as Teddy pending a measurement of this branch.
		return frontendTeddy
	}
	// Above 16, Teddy buckets several literals per lane and both
	// frontends are viable. Which wins is decided by FIRST-BYTE DIVERSITY,
	// not by literal count: AC's speed comes from a root-state prefilter that
	// skips input, and its selectivity decays as more bytes can start a
	// literal, while Teddy probes 2-4 bytes at a fixed cost per chunk and is
	// flat in both literal count and first-byte count.
	//
	// Measured at 32 literals on a 100KB no-match corpus, AC is
	// ahead at 1 distinct first byte (419K vs 669K), level at 2-3, and behind
	// from 4 onward, by 1.19x at 4 bytes widening to 6.3x at 32.
	if len(literals) <= teddyMaxLiterals && minLen >= teddyMinLenForBucketing &&
		distinctFirst >= teddyFirstByteCrossover {
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

	// btFallback is set when this bucket's single pattern could not be given a
	// suffix DFA within max_fallback_states and was admitted on the
	// Backtracking engine instead. Mutually exclusive with
	// suffixDFA: a BT bucket has no table, which is the entire point — BT is
	// the only engine here that is not bound by a compiled table size.
	//
	// Always exactly one pattern: BT has no merged form, so there is nothing
	// to share a bucket with.
	btFallback *btBucketInfo

	// sparse marks a bucket whose accept is a per-state LIST rather than a
	// 32-bit mask, which is what lets it hold more patterns
	// than the mask has bits. suffixDFA then carries the wide accept maps and
	// the emitter takes buildSparseSuffixBody instead of buildSetSuffixBody.
	sparse bool
	// sparseScratch is where this bucket's sparse body keeps its working
	// arrays. Decided at EMIT time (genSuffixWASM lays it out after the
	// tables), so it is written back onto the bucket rather than computed
	// twice — two derivations of one address is how they drift apart.
	sparseScratch sparseScratch
	// sparseIDMapOff maps bucket-local index -> global pattern id at runtime.
	sparseIDMapOff int32
	// dp is the table geometry the overlapping backward sweep
	// reads, copied from the very params buildSetSuffixBody was given so the
	// forward and backward readers cannot disagree about where a table is.
	dp overlapDPTables
}

// btBucketInfo carries everything the emitter needs for a Backtracking
// fallback bucket. Built by admitBTFallback at the point the pattern would
// otherwise have been dropped.
type btBucketInfo struct {
	bt      *backtrack // the compiled NFA program driver
	useMemo bool       // BitState memoisation required (needsBitState)
	// stackSize and memoSize are this pattern's own requirements. The set
	// allocates ONE shared region sized to the max over its BT buckets:
	// only one BT call is ever live, because the
	// per-candidate driver calls one suffix function at a time, and the memo
	// re-zeroes itself at the head of every call.
	stackSize int
	memoSize  int
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
// promoteSharedLiteralBuckets is G17 promotion for ONE shared-literal group:
// buckets that split at 32 patterns behind the same literal become one sparse
// bucket, so a position where that literal hits costs one suffix-DFA walk
// instead of ceil(N/32). Measured at 3.33x for 128 patterns against 32
// (setperf's sharedlit rows). The policy itself lives in promoteSparseBuckets.
func promoteSharedLiteralBuckets(litBuckets []*bucket, opts CompileSetOptions) []*bucket {
	if len(litBuckets) == 0 || litBuckets[0].literal == "" {
		// Distinct literals already get a bucket each and gain nothing, and an
		// empty literal here would mean the caller handed us the fallback
		// group, which has its own call site below.
		return litBuckets
	}
	return promoteSparseBuckets(litBuckets, opts, sparsePromotion{
		literal: litBuckets[0].literal,
		astFor:  patternSuffixAST,
		merge:   mergeSuffixDFASparseSet,
	})
}

// sparsePromotion is the part of G17 promotion that differs between the three
// packers. Everything else — the budgets, the refusals, the bucket that comes
// out — is shared, which is the point: the promotion POLICY existing once is
// what keeps the three packers from drifting apart the way they once
// warned they would.
//
// The fields are exactly the differences, and each is semantic rather than
// accidental, which is why this is a strategy struct and not a merged function:
// the anchored packer's DFA is built with leftmost-first pruning DISABLED and
// over full patterns, while both find packers use suffix ASTs and keep pruning.
type sparsePromotion struct {
	// literal every input bucket must agree on; "" for the two literal-less
	// packers, where there is nothing to agree on.
	literal string
	// astFor extracts the AST the merge should see: the suffix for the find
	// packers, the full pattern for the anchored one.
	astFor func(*PatternInfo) *syntax.Regexp
	// merge builds the wide-accept DFA with the right leftmost-first setting.
	merge func([]*syntax.Regexp, CompileSetOptions) (*dfaTable, *dfa, error)
	// isFallback marks the produced bucket as one that runs at every position.
	isFallback bool
	// anchored marks the ANCHORED packer's promotion (match_any / match_all).
	//
	// Three of the refusals below are find-path rationales that simply do not
	// apply there: startAnchor/lineAnchor (an anchored capability matches from
	// position 0, which is exactly where those patterns are eligible),
	// isolatedFallback (there is no per-candidate walk to isolate a pattern
	// from), and the trivial-prefix rule (the anchored body carries no prefix
	// length to subtract and runs no prefix DFA). Keeping them cost a
	// validator set of `^...$` patterns its promotion outright: it paid
	// ceil(N/32) full passes per match_* call, which is the very cost the
	// promotion exists to remove. The word-boundary and newline refusals are
	// NOT lifted — the anchored sparse probe carries no boundary context.
	anchored bool
}

// promoteSparseBuckets merges buckets that split ONLY because the accept
// bitmask ran out of bits into a single SPARSE bucket (G17).
//
// A group of N patterns splits into ceil(N/32) buckets because the accept
// bitmask is an i32 on the per-candidate path — never because the merged DFA
// was too big. Each split costs its own DFA walk: at every candidate position
// for the find packers, and over the whole input for the anchored one. One walk
// over one merged DFA replaces them.
//
// Conservative by construction, because a wrong promotion is worse than no
// promotion. It refuses unless at least two buckets can merge, refuses
// if the merged DFA misses the state or byte budgets — in which case the
// packer would have split it again anyway and nothing is gained — and refuses
// word-boundary or (?m) patterns, whose extra accept channels the sparse bodies
// do not serialise.
//
// Buckets it cannot take are KEPT rather than made to block the promotion, and
// the merged bucket inherits the first candidate's slot so relative order is
// unchanged. That matters most for the fallback packer, where a single
// Backtracking bucket (item 20) or one isolated non-greedy pattern would
// otherwise cost the whole group its promotion.
func promoteSparseBuckets(in []*bucket, opts CompileSetOptions, pr sparsePromotion) []*bucket {
	if !opts.AllowSparseAccept || len(in) < 2 {
		return in
	}
	// A BT bucket has no suffix DFA to merge, and an isolated fallback pattern
	// was given its own bucket precisely so its DFA would not be merged with
	// anyone else's — merging either here would undo the reason it exists.
	eligible := func(b *bucket) bool {
		if b.btFallback != nil || b.literal != pr.literal || b.sparse {
			return false
		}
		for _, p := range b.patterns {
			if p.isolatedFallback && !pr.anchored {
				return false
			}
			// EVERY pattern must have a trivial prefix. Two separate things
			// break otherwise, both of them silent:
			//
			//   - the sparse body carries ONE prefix length for the bucket and
			//     subtracts it from every tuple's start, so a bucket holding
			//     several lengths reports most of its matches at the wrong
			//     start — negative when the candidate is near position 0.
			//   - a non-trivial prefix has a prefix DFA that must RUN to
			//     confirm it, and the machinery that runs them is indexed by a
			//     32-bit mask, so patterns past the 32nd would never have their
			//     prefix checked at all.
			//
			// Both need per-pattern handling inside the body to lift; refusing
			// costs only the mixed-offset shared-literal sets, and the budget is
			// explicit that a wrong promotion is worse than no promotion.
			if !p.trivialPrefix && p.prefixDFA != nil && !pr.anchored {
				return false
			}
			// A \A- or (?m:^)-anchored pattern is eligible only at position 0
			// (or just after a newline), and emitGroupMask enforces that by
			// OR-ing its bit into validMask ONLY where the position allows —
			// the constraint lives in the mask, not in the bucket's DFA. A
			// sparse body ignores validMask, so such a pattern would be
			// eligible at EVERY position and report matches it must not: the
			// corpus showed `^(?:^(?:(?:a|(?:aa)))$)` matching "b" at 0-1.
			//
			// HEAD never hit this because analyzePattern routes anchored
			// patterns to FALLBACK buckets, and until this change fallback
			// buckets were never promoted. Lifting it means teaching the body
			// the position rule per pattern, not just widening a mask.
			if (p.startAnchor || p.lineAnchor) && !pr.anchored {
				return false
			}
		}
		return true
	}
	total := 0
	cands := 0
	for _, b := range in {
		if !eligible(b) {
			continue
		}
		cands++
		total += len(b.patterns)
	}
	if cands < 2 || total > opts.maxPatternsPerBucket() {
		return in
	}
	// The promotion exists because the accept BITMASK ran out of bits. A group
	// that fits one bitmask bucket never split for that reason, so promoting it
	// buys nothing and costs the slowest body shape there is: under LikelyMatch
	// it re-merges two counted-chain singletons that constraint 0 (LM-6)
	// deliberately kept apart, losing the SIMD-verify suffix body for
	// both.
	if total <= opts.bitmaskWidth() {
		return in
	}
	if opts.LikelyMode == LikelyMatch {
		// Same argument, one bucket at a time: a bucket whose single pattern is
		// a counted class chain has a suffix body isCountedClassChain earned it,
		// and merging is what takes it away.
		for _, b := range in {
			if !eligible(b) || len(b.patterns) != 1 {
				continue
			}
			if _, _, ok := isCountedClassChain(b.patterns[0].suffixDFA); ok {
				return in
			}
		}
	}
	merged := make([]*PatternInfo, 0, total)
	asts := make([]*syntax.Regexp, 0, total)
	for _, b := range in {
		if !eligible(b) {
			continue
		}
		for _, p := range b.patterns {
			ast := pr.astFor(p)
			if ast == nil || regexpHasWordBoundary(ast) {
				return in
			}
			merged = append(merged, p)
			asts = append(asts, ast)
		}
	}
	tab, _, err := pr.merge(asts, opts)
	if err != nil {
		return in
	}
	if tab.hasWordBoundary || tab.hasNewlineBoundary {
		return in
	}
	if tab.numStates > opts.budgetStates() || dfaTableBytes(tab) > opts.budgetBytes() {
		return in
	}
	cm, _, nc := computeByteClasses(tab)
	promoted := &bucket{
		literal:      pr.literal,
		patterns:     merged,
		suffixDFA:    tab,
		suffixStates: tab.numStates,
		tableBytes:   dfaTableBytes(tab),
		classMap:     cm,
		numClasses:   nc,
		isFallback:   pr.isFallback,
		sparse:       true,
	}
	out := make([]*bucket, 0, len(in)-cands+1)
	placed := false
	for _, b := range in {
		if eligible(b) {
			if !placed {
				out = append(out, promoted)
				placed = true
			}
			continue
		}
		out = append(out, b)
	}
	return out
}

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
				// Constraint 0 (LM-6, LikelyMatch only): don't merge two
				// counted-chain-eligible patterns. isCountedClassChain requires
				// a single-pattern suffix DFA (see its doc comment), so merging
				// them loses the single-pattern SIMD-verify suffix body for
				// both — under LikelyMatch (match-dense callers) that loss is
				// assumed to outweigh the shared-literal-dispatch win. Checked
				// against each pattern's own isolated suffixDFA (built by
				// analyzePattern, never mutated by merging), not the bucket's
				// merged table.
				if opts.LikelyMode == LikelyMatch {
					if _, _, pOK := isCountedClassChain(p.suffixDFA); pOK {
						conflict := false
						for _, bp := range b.patterns {
							if _, _, bpOK := isCountedClassChain(bp.suffixDFA); bpOK {
								conflict = true
								break
							}
						}
						if conflict {
							if diag != nil {
								diag.Conflicts = append(diag.Conflicts, ConflictDiag{
									Pattern: pRef, CandidateBucket: len(buckets) + bi,
									Reason: "lm_counted_chain_split",
								})
							}
							continue
						}
					}
				}

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
		// G17: buckets that split ONLY because the accept mask ran out of bits
		// are re-merged into one sparse bucket, so a candidate position costs
		// one suffix-DFA walk instead of ceil(N/32). Only for a shared literal:
		// distinct literals already get a bucket each and gain nothing.
		litBuckets = promoteSharedLiteralBuckets(litBuckets, opts)
		buckets = append(buckets, litBuckets...)
	}

	// Fallback: compile non-literal / non-splittable patterns.
	if len(fallbackPatterns) > 0 {
		fb := compileFallback(fallbackPatterns, opts, diag)
		// G17 again, and this is the group that pays most for a split: a
		// fallback bucket has no literal gating it, so every one of the
		// ceil(N/32) walks runs at EVERY input position rather than only where
		// a literal hit.
		fb = promoteSparseBuckets(fb, opts, sparsePromotion{
			astFor:     patternSuffixAST,
			merge:      mergeSuffixDFASparseSet,
			isFallback: true,
		})
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
			// A Backtracking bucket reports as its own type. Without this the
			// diag for a BT-backed set is byte-identical to the DFA one — which
			// is exactly why item 20's under-report took a day to localise: the
			// one artefact that should have shown the difference showed none.
			// Its suffix_states / table_bytes are honestly 0: it has no table.
			if b.btFallback != nil {
				btype = "bt-fallback"
			}
			if b.sparse {
				btype = "sparse-set"
			}
			refs := make([]PatternRef, len(b.patterns))
			for j, p := range b.patterns {
				refs[j] = patternRefFor(p)
			}
			// "sparse" for a G17 bucket. Hardcoding "bitmask" made the diag
			// say the opposite of what the bucket is, and the accept form is
			// the one thing that distinguishes them.
			acceptKind := "bitmask"
			if b.sparse {
				acceptKind = "sparse"
			}
			diag.Buckets = append(diag.Buckets, BucketDiag{
				ID:           i,
				Type:         btype,
				AcceptKind:   acceptKind,
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
// admitOrDropFallback turns one pattern's own suffix DFA into a fallback
// bucket, or — when there is no usable DFA — into a Backtracking bucket, or
// into a warned drop.
//
// The three-step ladder (nil-guard -> newBTBucket -> warnPatternDropped +
// StateLimitDropped) was written out THREE times in compileFallback, and the
// nil-guard was once missing from one of them — a real past crash whose fix
// note is still in the code.
//
// Returns nil when the pattern was dropped; the caller then records nothing
// further. `where` names the site for the warning, exactly as before.
func admitOrDropFallback(p *PatternInfo, dfa *dfaTable, where string, opts CompileSetOptions, diag *SetDiag) *bucket {
	if dfa == nil {
		if nb := newBTBucket(p); nb != nil {
			return nb
		}
		warnPatternDroppedReason(p, where, "its own suffix DFA could not be built",
			"simplify the pattern or move it out of the set", 0, opts.maxFallbackStates())
		if diag != nil {
			diag.StateLimitDropped = append(diag.StateLimitDropped, patternRefFor(p))
		}
		return nil
	}
	if dfa.numStates > opts.maxFallbackStates() {
		if nb := newBTBucket(p); nb != nil {
			return nb
		}
		warnPatternDropped(p, where, dfa.numStates, opts.maxFallbackStates())
		if diag != nil {
			diag.StateLimitDropped = append(diag.StateLimitDropped, patternRefFor(p))
		}
		return nil
	}
	cm, _, nc := computeByteClasses(dfa)
	return &bucket{
		literal:      "",
		patterns:     []*PatternInfo{p},
		suffixStates: dfa.numStates,
		tableBytes:   dfaTableBytes(dfa),
		classMap:     cm,
		numClasses:   nc,
		isFallback:   true,
		suffixDFA:    dfa,
	}
}

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
			// isolatedDFA can still be nil here, and dereferencing it was a
			// crash. analyzePattern returns
			// EARLY for a non-greedy pattern, leaving p.suffixDFA nil with the
			// note that compileFallback will build it — so this is the only
			// place it exists, and the assignment above happens only when the
			// AST is recoverable AND the merge succeeds. `.*?0...........`
			// fails the merge (too many states) and reached the deref.
			//
			// Treated as the drop it already is: an isolated pattern whose own
			// DFA cannot be built is exactly the case the state-limit branch
			// below covers, and is reported the same way.
			if nb := admitOrDropFallback(p, isolatedDFA, "isolated fallback bucket", opts, diag); nb != nil {
				buckets = append(buckets, nb)
			}
			continue
		}
		placed := false
		for bi, b := range buckets {
			// A Backtracking bucket is closed to packing: it has no suffix DFA
			// to merge into, and its emitted body answers for exactly one
			// pattern — buildSetBTSuffixBody hardcodes patternIDs[bi][0] and
			// validMask bit 0. Packing a second pattern into it leaves that
			// pattern with NO emitted code in any bucketed capability
			// (set_emit.go skips the whole DFA suffix pass when
			// btFallback != nil): a silent under-report, not an error. The
			// budgets checked below (budgetStates 512 / budgetBytes 64 KB) are
			// unrelated to maxFallbackStates and do NOT protect this — a merged
			// table small enough to pass them is exactly the case that failed.
			// Every rejection below is RECORDED, as binPack's are: a
			// --diag-json that explains why the shared-literal packer split a
			// group but says nothing about the fallback packer leaves half the
			// bucket layout unexplained.
			pRef := patternRefFor(p)
			reject := func(reason string, detail map[string]interface{}) {
				if diag != nil {
					diag.Conflicts = append(diag.Conflicts, ConflictDiag{
						Pattern: pRef, CandidateBucket: bi,
						Reason: reason, Detail: detail,
					})
				}
			}
			if b.btFallback != nil {
				reject("bt_bucket_closed", nil)
				continue
			}
			if len(b.patterns) >= bw {
				reject("bitmask_cap_full", map[string]interface{}{"bitmask_width": bw})
				continue
			}
			candidateASTs := make([]*syntax.Regexp, len(b.patterns)+1)
			for i, bp := range b.patterns {
				candidateASTs[i] = patternSuffixAST(bp)
			}
			candidateASTs[len(b.patterns)] = patternSuffixAST(p)
			mergedTable, _, mergeErr := mergeSuffixDFA(candidateASTs, opts)
			if mergeErr != nil {
				reject("merge_failed", map[string]interface{}{"error": mergeErr.Error()})
				continue
			}
			mergedBytes := dfaTableBytes(mergedTable)
			if mergedBytes > byteBudget || mergedTable.numStates > stateBudget {
				reject("budget_exceeded", map[string]interface{}{
					"merged_states": mergedTable.numStates,
					"merged_bytes":  mergedBytes,
					"budget_states": stateBudget,
					"budget_bytes":  byteBudget,
				})
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
			// nbDFA can still be nil, and dereferencing it below was a CRASH.
			// analyzePattern returns early for some patterns leaving
			// p.suffixDFA nil, and the merge above can then fail too — e.g.
			// 3000 chained `(?:[a-z]*[0-9]*)`, where the merge exceeds its
			// state limit. The ISOLATED branch above carried exactly this
			// guard, and its comment, for some time; it was simply never added
			// to this sibling — which is what admitOrDropFallback now makes
			// impossible.
			if nb := admitOrDropFallback(p, nbDFA, "new fallback bucket", opts, diag); nb != nil {
				buckets = append(buckets, nb)
			}
		}
	}

	for _, b := range buckets {
		b.isFallback = true
	}
	return buckets
}

// patternSuffixAST returns the suffix AST for p.
// When suffixAST is nil and the pattern was splittable, the mandatory literal
// covers the whole pattern (empty suffix) — return an empty regexp so the
// suffix DFA accepts immediately at suffix_start.
// When the pattern was not splittable, fall back to the full pattern AST.
func patternSuffixAST(p *PatternInfo) *syntax.Regexp {
	if !p.splittable {
		// Non-splittable: use the full pattern so the suffix DFA handles all matching.
		re, err := syntax.Parse(p.fullPattern, syntax.Perl)
		if err != nil {
			return nil
		}
		// Captures must go, and this branch was the ONLY place in the set
		// pipeline that kept them. Everything else is already capture-free:
		// analyzePattern strips the tree it parses, and p.suffixAST below is a
		// SUBTREE of that stripped tree — so this branch alone returned a
		// different representation of the same pattern than the rest of the
		// pipeline uses, which is a bug in its own right.
		//
		// It was invisible to the DFA emitters, which treat InstCapture as a
		// pass-through epsilon, and fatal to the Backtracking one: a
		// capture-bearing program makes buildBacktrackBody emit capture-slot
		// writes at locals `7 + slot`, while admitBTFallback has set
		// numGroups = 0 so no capture locals are declared at all. The result is
		// a module that does not VALIDATE — "unknown local 9: local index out
		// of bounds" for a single `(a)` group. The
		// single-pattern BT path never hit it because compileBTProg strips
		// captures before compiling; this is the same contract, applied here.
		//
		// Mutating in place is safe precisely because this tree is freshly
		// parsed on every call and shared with nobody.
		stripCaptures(re)
		return re
	}
	if p.suffixAST != nil {
		return p.suffixAST
	}
	// The mandatory literal IS the whole pattern; suffix is empty.
	empty, _ := syntax.Parse("", syntax.Perl)
	return empty
}

// warnPatternDropped reports, at warning level, that a pattern has been
// excluded from its set because its suffix DFA exceeded maxFallbackStates.
//
// This must not be nested inside the `if diag != nil` guards that surround the
// StateLimitDropped bookkeeping: CompileSet creates a SetDiag unconditionally
// (set_emit.go) so those guards always pass, but the resulting struct is
// discarded unless the caller asked for --diag-json — its only consumer is
// CmdWriteDiagJSON. Before this warning existed, a normal build dropped the
// pattern with exit code 0 and no output at all, and the set silently never
// matched it.
//
// Warn rather than error: erroring would be a behaviour change for configs that
// build today, and the drop is a resource ceiling rather than a malformed
// input. Promoting it to a hard failure belongs behind a --strict flag.
func warnPatternDropped(p *PatternInfo, where string, states, limit int) {
	warnPatternDroppedReason(p, where, "suffix DFA exceeds state limit",
		"raise max_fallback_states, simplify the pattern, or move it out of the set",
		states, limit)
}

// warnPatternDroppedReason is warnPatternDropped with the REASON spelled out.
//
// The one-message form said "suffix DFA exceeds state limit" — with a
// max_fallback_states hint — for the unparseable-anchored drop too, where
// neither half is true and the hint sends the reader after the wrong knob.
func warnPatternDroppedReason(p *PatternInfo, where, reason, hint string, states, limit int) {
	ref := patternRefFor(p)
	slog.Warn("Pattern dropped from set: "+reason,
		"pattern", ref.Name,
		"id", ref.ID,
		"where", where,
		"states", states,
		"limit", limit,
		"hint", hint)
}

// patternRefFor builds a PatternRef from a PatternInfo.
func patternRefFor(p *PatternInfo) PatternRef {
	name := p.name
	if name == "" {
		name = p.fullPattern
	}
	return PatternRef{ID: p.globalID, Name: name}
}

// --------------------------------------------------------------------------
// Anchored-capability automata.
//
// `match`, `match_any` and `match_all` ask whether a pattern matches the WHOLE
// input, which is `\A(?:p)\z` — and that is NOT a question a leftmost-first
// automaton can answer. Leftmost-first prunes the search the moment the
// highest-priority alternative accepts, so the DFA for `a|ab` has no
// transition out of the state reached by "a", and `a+?` dies after one byte.
// Both patterns match "ab" / "aaa" end-to-end, and both would be reported as
// non-matching by the find-path DFAs.
//
// The anchored capabilities therefore get their own automata: the FULL pattern
// (never the post-literal suffix), merged with leftmostFirst = false so every
// alternative stays live to the end of the input. Compile time is free
// (CLAUDE.md); correctness here is not negotiable.

// patternFullAST returns the whole pattern's AST with captures stripped.
func patternFullAST(p *PatternInfo) *syntax.Regexp {
	re, err := syntax.Parse(p.fullPattern, syntax.Perl)
	if err != nil {
		return nil
	}
	stripCaptures(re)
	return re
}

// mergeAnchoredDFA is mergeSuffixDFA with leftmostFirst disabled.
func mergeAnchoredDFA(asts []*syntax.Regexp, opts CompileSetOptions) (*dfaTable, error) {
	bw := opts.bitmaskWidth()
	if len(asts) == 0 {
		return nil, fmt.Errorf("mergeAnchoredDFA: empty pattern list")
	}
	if len(asts) > bw {
		return nil, fmt.Errorf("mergeAnchoredDFA: %d patterns exceed bitmaskWidth %d", len(asts), bw)
	}
	progs, err := compileSetASTs(asts, "mergeAnchoredDFA")
	if err != nil {
		return nil, err
	}
	unionProg, patternBits := buildUnionProg(progs, bw)
	d, ok := newDFA(unionProg, false, false, maxHelperDFAStates, patternBits)
	if !ok {
		return nil, ErrDFAStateLimit
	}
	return dfaTableFromCanonical(d), nil
}

// mergeAnchoredDFASparseSet is mergeAnchoredDFA's wide twin: per-state accept
// LISTS instead of a u64 mask, so an anchored bucket can hold more than 32
// patterns (G17 sparse accept).
//
// The anchored trio pays for a split differently from `find`. There is no
// literal frontend and no candidate enumeration — emitSetAnchoredCapBody simply
// calls every anchored bucket's probe in turn — so ceil(N/32) buckets means
// ceil(N/32) full passes over the input for one match_any call, regardless of
// what the input looks like.
func mergeAnchoredDFASparseSet(asts []*syntax.Regexp, opts CompileSetOptions) (*dfaTable, *dfa, error) {
	if len(asts) == 0 {
		return nil, nil, fmt.Errorf("mergeAnchoredDFASparseSet: empty pattern list")
	}
	if max := opts.maxPatternsPerBucket(); len(asts) > max {
		return nil, nil, fmt.Errorf("mergeAnchoredDFASparseSet: %d patterns exceed maxPatternsPerBucket %d",
			len(asts), max)
	}
	progs, err := compileSetASTs(asts, "mergeAnchoredDFASparseSet")
	if err != nil {
		return nil, nil, err
	}
	unionProg, patternIdx := buildUnionProgIndexed(progs)
	// leftmostFirst=false, matching mergeAnchoredDFA: an anchored answer is
	// "which patterns match the whole input", and pruning lower-priority
	// alternatives would drop patterns that do.
	d, ok := newDFAWide(unionProg, false, maxHelperDFAStates, patternIdx)
	if !ok {
		return nil, nil, ErrDFAStateLimit
	}
	return dfaTableFromCanonical(d), d, nil
}

// compileAnchoredBuckets packs every pattern of the set into buckets whose
// merged, non-leftmost-first DFA fits the state and byte budgets. Patterns are
// taken in declaration order so a bucket's bit k maps to a stable global id.
func compileAnchoredBuckets(patterns []*PatternInfo, opts CompileSetOptions, diag *SetDiag) ([]*bucket, [][]*PatternInfo) {
	bw := opts.bitmaskWidth()
	byteBudget := opts.budgetBytes()
	stateBudget := opts.budgetStates()

	var buckets []*bucket
	var members [][]*PatternInfo

	for _, p := range patterns {
		ast := patternFullAST(p)
		if ast == nil {
			// Defensive — analyzePattern parsed this once already — but a bare
			// `continue` would drop the pattern from the anchored trio while
			// `find` kept it, with nothing in --diag-json to explain the
			// disagreement.
			warnPatternDroppedReason(p, "anchored bucket", "the pattern could not be parsed for the anchored packing",
				"simplify the pattern or move it out of the set", 0, 0)
			if diag != nil {
				diag.UnparseableDropped = append(diag.UnparseableDropped, patternRefFor(p))
			}
			continue
		}
		placed := false
		for bi := range buckets {
			if len(members[bi]) >= bw {
				continue
			}
			asts := make([]*syntax.Regexp, 0, len(members[bi])+1)
			for _, m := range members[bi] {
				asts = append(asts, patternFullAST(m))
			}
			asts = append(asts, ast)
			merged, err := mergeAnchoredDFA(asts, opts)
			if err != nil {
				continue
			}
			if dfaTableBytes(merged) > byteBudget || merged.numStates > stateBudget {
				continue
			}
			members[bi] = append(members[bi], p)
			buckets[bi].suffixDFA = merged
			buckets[bi].suffixStates = merged.numStates
			buckets[bi].patterns = members[bi]
			placed = true
			break
		}
		if placed {
			continue
		}
		solo, err := mergeAnchoredDFA([]*syntax.Regexp{ast}, opts)
		if err != nil || solo.numStates > opts.maxFallbackStates() {
			states := 0
			if solo != nil {
				states = solo.numStates
			}
			warnPatternDropped(p, "anchored bucket", states, opts.maxFallbackStates())
			if diag != nil {
				diag.StateLimitDropped = append(diag.StateLimitDropped, patternRefFor(p))
			}
			continue
		}
		buckets = append(buckets, &bucket{
			patterns:     []*PatternInfo{p},
			suffixDFA:    solo,
			suffixStates: solo.numStates,
			isFallback:   true,
		})
		members = append(members, []*PatternInfo{p})
	}
	// G17: re-merge buckets that split only on the 32-bit accept mask. Done
	// here rather than by packing differently above so declaration order — and
	// with it the bucket-bit-to-global-id mapping the non-promoted path relies
	// on — is untouched when the promotion is refused.
	buckets = promoteSparseBuckets(buckets, opts, sparsePromotion{
		astFor:   patternFullAST,
		merge:    mergeAnchoredDFASparseSet,
		anchored: true,
	})
	members = members[:0]
	for _, b := range buckets {
		members = append(members, b.patterns)
	}
	return buckets, members
}

// regexpHasWordBoundary reports whether re contains a \b or \B assertion
// anywhere. Used to keep such prefixes out of the backward-scan split, whose
// traversal has no word-boundary context (see analyzePattern).
//
// Expressed through containsOp rather than hand-rolling the walk, the way
// hasBeginAnchor deliberately does: three copies of the same recursion is
// three places for it to diverge.
func regexpHasWordBoundary(re *syntax.Regexp) bool {
	return containsOp(re, syntax.OpWordBoundary) || containsOp(re, syntax.OpNoWordBoundary)
}

// regexpHasEndAssertion reports whether re contains `$`, `\z` or `(?m:$)`.
//
// Its counterpart regexpHasWordBoundary guards the same thing for the same
// reason; the two are siblings, not duplicates, because the begin-anchor
// flavours ARE representable and are handled positively above
// (isOnlyBeginAnchors / setTopLevelAnchor).
func regexpHasEndAssertion(re *syntax.Regexp) bool {
	return containsOp(re, syntax.OpEndText) || containsOp(re, syntax.OpEndLine)
}
