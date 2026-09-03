package compile

import (
	"encoding/binary"
	"fmt"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Phase 4c: per-set WASM compilation

// compiledSet is the WASM artefact for one `sets:` entry.
// The match function body is not stored here — it is built at assemble time
// (when function-table indices are known) by emitSetMatchFnFinal.
type compiledSet struct {
	name string

	// Capability export names; "" = not declared. `match` and `scan` were
	// retired — `match_any(...) >= 0` and
	// `scan_any(...) >= 0` are exactly what they returned.
	matchAny string // anchored, pattern id or -1
	matchAll string // anchored, bitmask / bitmap of ids
	scanAny  string // non-anchored, pattern id or -1
	scanAll  string // non-anchored, bitmask / bitmap of ids
	find     string // non-anchored, tuples at the next matching position
	// batchFind is `hints: [batch-find]` on the set (decision (11)). It adds
	// the batching multi-position export ALONGSIDE `find` — it is no longer a
	// capability of its own, so it cannot be declared without `find`.
	batchFind bool
	// patternCount is the worst-case number of tuples at ONE position, and
	// therefore how many bits the batch cursor reserves for its intra-position
	// index. It is the same quantity the stubs know as <SET>_PATTERN_COUNT.
	patternCount int
	// batchPos is a transient emission flag: while it is set, the shared find
	// emitters build the shared per-position WORKER rather than an exported
	// `find` body. Set and cleared around one emitSetMatchFnFinal call by
	// emitSetWorkerBody; never read outside emission.
	//
	// Under decision (11a) the worker is what BOTH the exported `find` and the
	// batch loop call, so a batching set carries ONE set of bucket code rather
	// than two. The gate rule that used to be chosen here at compile time is
	// now a runtime parameter — see setFindCtx.pBatchMode.
	batchPos bool
	// suffixHasSkip mirrors SetSpec.suffixNeedsSkip: the tuple-writing suffix
	// functions carry a trailing `skip` parameter.
	suffixHasSkip bool

	// overlapping selects the ungated `find` body. The default
	// (false) is the gated, per-pattern non-overlapping body.
	overlapping bool

	// declaredIDSpace is SetSpec.IDSpaceSize — the id-space bound agreed with
	// the stub generators. Zero means "derive it";
	// read it through idSpaceSize(), never directly.
	declaredIDSpace int

	// maxLookback (M) is the largest distance between a mandatory literal and
	// the match start it can serve, over every pattern in the set. It bounds
	// the first-position drain.
	//
	// Never negative. A "-1 = unbounded" state was documented here and is
	// unreachable: a pattern whose prefix is variable-length is fallback-routed
	// by analyzePattern and never contributes a fixed prefix length at all, so
	// setMaxLookback only ever maximises over non-negative values. Nothing at
	// the use site handles a negative, which is what made the sentence a
	// hazard rather than a note.
	maxLookback int

	// prefixLenGroups[bi] partitions bucket bi's patterns by fixed prefix
	// length so each suffix-DFA call covers exactly one match start.
	prefixLenGroups [][]prefixLenGroup

	// suffixFnBodies[i] is the body for bucket i's suffix DFA function.
	suffixFnBodies [][]byte

	// scanProbeBodies[i] is bucket i's cheap bitmask-only probe
	// (compile/set_probe.go), emitted only when the set declares one of the
	// scan capabilities.
	scanProbeBodies [][]byte

	// scanProbeAnyBodies[i] is bucket i's first-hit-exit probe, used by `scan`
	// and `scan_any` only. Empty when the set
	// declares neither; `scan_all` always uses scanProbeBodies.
	scanProbeAnyBodies [][]byte

	// anyProbeIdx[bucket] = slot in scanProbeAnyBodies, or -1 when that
	// bucket has no separate first-hit body (single-pattern buckets, or a set
	// that needs only one exit rule).
	anyProbeIdx []int

	// anchoredBuckets / anchoredIDs / anchoredProbeBodies belong to the
	// anchored trio. They are a SEPARATE packing over the full patterns,
	// merged without leftmost-first pruning, because full consumption is not
	// a question a leftmost-first automaton can answer — see
	// compileAnchoredBuckets.
	anchoredBuckets     []*bucket
	anchoredIDs         [][]int
	anchoredProbeBodies [][]byte
	anchoredDataBytes   []byte
	anchoredDataSegs    int
	// anchoredUnion replaces that packing with ONE automaton when it can be
	// built. Non-nil means anchoredBuckets and
	// anchoredProbeBodies are EMPTY: the two are alternatives, never both, and
	// anchoredIDs then holds the whole set's ids as a single group because the
	// automaton reports for every pattern.
	anchoredUnion *anchoredUnion

	// btFnBodies[i] is the Backtracking driver for the i-th BT fallback bucket
	//: (ptr, len, out_ptr) -> i32, the same shape a
	// single-pattern capture body has. Laid out LAST among a set's functions so
	// adding them moves no existing offset. btRegions is the one shared
	// stack/memo/scratch allocation they all use.
	// numBTFns is the count of Backtracking drivers this set will emit. It is
	// known in CompileSet, whereas btFnBodies is only FILLED at assembleModule
	// time (a driver's suffix body needs function indices). Every layout
	// question — funcCount, the function section, btFnBaseOffset — must use
	// this, never len(btFnBodies), or the declared function count comes up
	// short of the code section and the module fails to parse.
	numBTFns int
	// tableMemIdx is the memory this set's tables live in, kept so emitters
	// reached through setFindCtx can address them.
	tableMemIdx int
	btFnBodies  [][]byte
	btRegions   *btSharedRegions

	// prefixFnBodies[i] is the body for the i-th unique prefix DFA (backward scan).
	// Signature: (ptr i32, scan_end i32) → i32  (type 0)
	prefixFnBodies [][]byte

	// prefixDataBytes/prefixDataSegCount: data segments for prefix DFA tables.
	prefixDataBytes    []byte
	prefixDataSegCount int

	// unionScan is the start-anywhere union automaton serving `scan` and the
	// narrow `scan_all` when the set has no literal frontend to skip with.
	// Nil when the set is ineligible or kept its
	// per-position path.
	unionScan *unionScanDFA

	// phase2Union is the start-anywhere automaton over this set's FALLBACK
	// patterns ONLY, and it exists exactly for the sets unionScan cannot
	// serve: a MIXED set, with a literal frontend AND at least one fallback
	// bucket.
	//
	// Such a set is the expensive shape. One fallback pattern must be tried at
	// every position, which switches the frontend's SIMD skip off for the
	// WHOLE scan, so `error` and `warning` crawl because `[0-9]{16}` is in the
	// same set. Measured ~102 fuel/byte against 27 for a union walk.
	//
	// The split refuses to interleave them: phase 1 runs the literal frontend
	// with its skip intact over the literal buckets alone, phase 2 walks the
	// fallback patterns in one pass. Nil when the set is not mixed, when the
	// fallback subset cannot be determinised (word boundaries, (?m) anchors,
	// ids >= 64, state budget), or when no capability wants it.
	phase2Union *unionScanDFA

	// phase1Only switches the frontend emitters to the phase-1 VIEW of this
	// set: the fallback buckets are not emitted, and the guards that disable a
	// prefilter because fallback buckets exist are lifted. Set only around the
	// phase-1 body emission, the same way set_batch.go drives batchPos.
	phase1Only bool

	// prefixFnIdx[bi][k]: index into prefixFnBodies for pattern at bitPos k in bucket bi.
	// -1 means trivial prefix (always passes; bit is always set in validMask).
	prefixFnIdx [][]int

	// trivialPrefixMasks[bi]: bitmask of patterns in bucket bi with trivial prefix.
	trivialPrefixMasks []uint32

	// startAnchorMasks[bi]: bitmask of patterns anchored with \A / ^ — eligible
	// only at input position 0.
	startAnchorMasks []uint32

	// lineAnchorMasks[bi]: bitmask of patterns anchored with (?m:^) — eligible
	// at position 0 and at any position whose preceding byte is a newline.
	lineAnchorMasks []uint32

	// prefixFixedLens[bi][k]: fixed prefix length for pattern k (minLen==maxLen>0); else 0.
	// Used for compile-time match start adjustment.
	prefixFixedLens [][]int

	// numSuffixFns == len(suffixFnBodies).
	numSuffixFns int

	// Data segments for literal tables, Teddy/AC tables, etc.
	dataBytes    []byte
	dataSegCount int

	// Bucket list and pattern-ID mapping used by the match function.
	buckets    []*bucket
	patternIDs [][]int // patternIDs[bucketIdx][bitPos] = global 0-based pattern index

	// Frontend strategy chosen for this set's literal scan.
	fe frontendKind

	// First-byte eligibility masks, one 256 x u32 table
	// per FALLBACK bucket that has something to clear. startableOff[bi] is the
	// table's address, or -1 when bucket bi has none — which is every bucket
	// on a set that does not qualify, so those sets stay byte-identical.
	startableOff       []int32
	startableDataBytes []byte
	startableDataSegs  int

	// Literal-existence absence prefilter.
	// absenceLits carries one literal per pattern that has one; absenceAlive
	// is the mask of patterns that have none and are therefore always reported
	// alive. absenceOK is false when the prefilter cannot serve this set.
	absenceLits  []absenceLit
	absenceAlive uint64
	absenceOK    bool

	// AC frontend (fe == frontendAC): Aho-Corasick automaton tables.
	acL                 *acLayout
	acDataBytes         []byte
	acDataSegCount      int
	acFirstByteSet      []byte // distinct first bytes for SIMD prefilter
	acFirstByteFlagsOff int32  // data offset of firstByteFlags[256] table

	// Teddy frontend (fe == frontendTeddy): SIMD nibble tables.
	teddyTabs         *teddyTables
	teddyDataOffset   int32
	teddyDataBytes    []byte
	teddyDataSegCount int

	// Shufti frontend (fe == frontendShufti): distinct first bytes of all
	// literal buckets. Tables are inlined as v128.const in the emission,
	// so no data segment is needed.
	shuftiFirstByteSet []byte

	// Packed-pair frontend (fe == frontendPackedPair): the two probe
	// columns. Like Shufti this needs no data segment — the probe bytes are
	// emitted as i32.const/i8x16.splat pairs hoisted out of the scan loop.
	packedPair *packedPairPlan

	// shuftiAdaptive: true when Shufti was selected ONLY because
	// set-level LikelyNoMatch overrode a static verdict that scalar would
	// win (shuftiBeatsScalar(union) == false). Mirrors EmitPrefixScan's
	// `adaptive` gate for the single-pattern path: the
	// static heuristic can't tell "sparse runtime data" (override
	// genuinely wins) from "dense runtime data" (override regresses), so
	// emitSetMatchFnFinalShufti adds a runtime DenseCounter/DenseSkipFlag
	// switch that falls back to the scalar tail once density is confirmed,
	// instead of trusting the static override for the whole scan.
	shuftiAdaptive bool

	// unionSkipLNM enables emitUnionSkip — the SIMD stride through a union
	// state's self-loop run — in this set's scan bodies. Set-level
	// LikelyNoMatch only: the stride wins on input SPARSE in the exit set and
	// pays a probe for nothing on dense input, and the compiler cannot tell
	// the two apart. That is a hint's job, and the runtime staleness counter
	// bounds the cost of a wrong one.
	unionSkipLNM bool

	// overlapDPColOff is the module address of the backward sweep's two
	// working columns. Zero when the set emits no
	// sweep.
	overlapDPColOff int32

	// litToBuckets[litID] = list of bucket indices sharing this literal.
	// Multiple buckets can share a literal when bin-packing splits large groups.
	litToBuckets [][]int
	litLens      []int

	// Diagnostics.
	diag *SetDiag
}

// setCapFn describes one exported capability function of a set.
type setCapFn struct {
	name    string     // WASM export name
	kind    setCapKind // which body to emit
	typeIdx byte       // WASM type-section index for its signature
}

// capFns returns the set's declared capabilities in a fixed order. The order
// is what assigns their function indices, so it must be stable between the
// function, export and code sections.
func (cs *compiledSet) capFns() []setCapFn {
	wide := cs.wideAll()
	allType := byte(setTypeI32I32ToI64)
	if wide {
		allType = setTypeI32x3ToI32
	}
	scanAllType := byte(setTypeI32x3ToI64)
	if wide {
		scanAllType = setTypeI32x4ToI32
	}
	// The gate-array slot is present on BOTH `find` bodies. Under
	// `overlapping: true` the array carries no match gates — it carries the
	// once-per-drive preflight's verdict instead, which is what lets that
	// verdict be computed once rather than on
	// every call. It is declared unconditionally rather than only when a
	// preflight is emitted, because the alternative makes an exported
	// signature depend on pattern analysis the caller cannot predict.
	findType := byte(setTypeI32x6ToI32)
	batchType := byte(setTypeBatchGated)
	batchName := ""
	if cs.batchFind {
		batchName = config.SetBatchExportName(cs.find)
	}
	all := []setCapFn{
		{cs.find, capFind, findType},
		{batchName, capFindBatch, batchType},
		{cs.scanAny, capScanAny, setTypeI32x3ToI32},
		{cs.scanAll, capScanAll, scanAllType},
		{cs.matchAny, capMatchAny, setTypeI32I32ToI32},
		{cs.matchAll, capMatchAll, allType},
	}
	out := all[:0:0]
	for _, c := range all {
		if c.name != "" {
			out = append(out, c)
		}
	}
	return out
}

// funcCount returns the number of WASM functions contributed by this compiled set:
// one per declared capability, plus the per-bucket suffix, prefix and probe helpers.
func (cs *compiledSet) funcCount() int {
	return len(cs.capFns()) + cs.hiddenFnCount() + cs.numSuffixFns + len(cs.prefixFnBodies) +
		len(cs.scanProbeBodies) + len(cs.scanProbeAnyBodies) + len(cs.anchoredProbeBodies) +
		cs.numBTFns
}

// btFnBaseOffset returns the index of the first Backtracking driver, which sit
// last so that adding them moved no existing sub-index.
func (cs *compiledSet) btFnBaseOffset() int {
	return cs.anchoredProbeBaseOffset() + len(cs.anchoredProbeBodies)
}

// suffixFnBaseOffset returns the index of the first suffix function within this
// set's functions (relative to the set's base).
func (cs *compiledSet) suffixFnBaseOffset() int {
	return len(cs.capFns()) + cs.hiddenFnCount()
}

// prefixFnBaseOffset returns the index of the first backward-prefix function.
func (cs *compiledSet) prefixFnBaseOffset() int {
	return cs.suffixFnBaseOffset() + cs.numSuffixFns
}

// scanProbeBaseOffset returns the index of the first scan-probe function.
func (cs *compiledSet) scanProbeBaseOffset() int {
	return cs.prefixFnBaseOffset() + len(cs.prefixFnBodies)
}

// scanProbeAnyBaseOffset returns the index of the first first-hit-exit probe.
// Equal to anchoredProbeBaseOffset when the set emits none.
func (cs *compiledSet) scanProbeAnyBaseOffset() int {
	return cs.scanProbeBaseOffset() + len(cs.scanProbeBodies)
}

// anchoredProbeBaseOffset returns the index of the first anchored-probe function.
func (cs *compiledSet) anchoredProbeBaseOffset() int {
	return cs.scanProbeAnyBaseOffset() + len(cs.scanProbeAnyBodies)
}

// WASM type-section indices used by the set path. The full table is written
// by assembleModuleWithSets; these names keep the emitters readable.
const (
	setTypeI32I32ToI32 = 0 // (i32,i32)→i32      match / match_any / backward prefix
	setTypeI32I32ToI64 = 1 // (i32,i32)→i64      match_all, <= 64 patterns
	setTypeI32x3ToI32  = 2 // (i32,i32,i32)→i32  scan; scan_any; match_all bitmap form
	setMatchTypeSuffix = 3 // (i32×7)→i32        suffix DFA (tuple-writing)
	setTypeI32x5ToI32  = 5 // (i32×5)→i32        per-pattern batch wrappers; the DP sweep
	setTypeI32x4ToI32  = 6 // (i32×4)→i32        bucket probes; scan_all bitmap form
	setTypeI32x3ToI64  = 7 // (i32,i32,i32)→i64  scan_all <= 64 patterns
	setTypeI32x6ToI32  = 8 // (i32×6)→i32        find, gated (default)
	setTypeSuffixGated = 9 // (i32×8)→i32        suffix DFA with a gate pointer

	// find_batch. The cursor is an i64 in and an i64 out: the value the
	// export returns is passed back verbatim as the next call's cursor.
	setTypeBatchGated = 10 // (i32,i32,i64,i32,i32,i32,i32,i32)→i64  find_batch
	//                          ptr, len, cursor, gate, out, cap, scratch, scratch_len
	//
	// There is no separate type for the OVERLAPPING batch entry. Both overlap
	// policies share ONE signature, so the second type was declared in every
	// set module and referenced by none.
)

// batchPosFnOffset returns the index of the set's shared per-position worker,
// or -1 when the set does not batch. It sits immediately after the exported
// capability functions.
func (cs *compiledSet) batchPosFnOffset() int {
	if !cs.batchFind {
		return -1
	}
	return len(cs.capFns())
}

// hiddenFnCount is how many non-exported functions the set contributes between
// its capability functions and its suffix functions.
func (cs *compiledSet) hiddenFnCount() int {
	n := 0
	if cs.batchFind {
		n++
	}
	// Two per split capability: phase 1 (the frontend over the literal
	// buckets) and phase 2 (the union walk over the fallback patterns).
	n += 2 * len(cs.twoPhaseCaps())
	if cs.usesOverlapDP() {
		n++
	}
	return n
}

// overlapDPFnOffset is the index of the backward sweep within this set's
// functions, or -1. It sits after the two-phase bodies, so adding it moves no
// existing sub-index.
func (cs *compiledSet) overlapDPFnOffset() int {
	if !cs.usesOverlapDP() {
		return -1
	}
	n := len(cs.capFns())
	if cs.batchFind {
		n++
	}
	return n + 2*len(cs.twoPhaseCaps())
}

// gatedFind reports whether this set emits the default (per-pattern
// non-overlapping) `find` body, which threads a gate array through the suffix
// functions.
func (cs *compiledSet) gatedFind() bool { return cs.hasFind() && !cs.overlapping }

// findGateSlot reports whether the exported `find`, its batch entry and their
// shared worker carry a gate-array POINTER.
//
// Distinct from gatedFind on purpose, and the distinction is the whole of
// the one-signature ABI. gatedFind asks "does this body apply the
// per-pattern non-overlapping rule"; this asks "is there an array in
// the argument list". An overlapping `find` answers no to the first and yes
// to the second: it applies no match gates, but it needs somewhere
// caller-owned to keep the preflight's verdict across the calls of one drive,
// and the gate array already has exactly the contract that needs — caller
// zeroes it to start a drive, one drive per unchanging input.
//
// The suffix functions are NOT affected: only the top-level body reads the
// array, and only through emitGateMask.
func (cs *compiledSet) findGateSlot() bool { return cs.hasFind() }

// hasFind reports whether either position-reporting capability is declared.
func (cs *compiledSet) hasFind() bool { return cs.find != "" }

// setMatchTypeMatch is kept as the historical alias for the ungated find
// signature, which the per-pattern batch wrappers also reuse.
const setMatchTypeMatch = setTypeI32x5ToI32

// SetSpec is the resolved specification for one set, ready for compilation.
type SetSpec struct {
	Name string

	// Capability export names; "" = not declared. `Match` and `Scan` were
	// retired.
	MatchAny string
	MatchAll string
	ScanAny  string
	ScanAll  string
	Find     string
	// BatchFind is `hints: [batch-find]` on the set (decision (11)): emit the
	// Multi-position batch entry alongside Find, both driven by one shared
	// per-position worker. Meaningless without Find, and rejected at config
	// load in that case.
	BatchFind bool

	Overlapping bool // true = ungated `find` body

	// IDSpaceSize is one past the largest pattern id this set can report —
	// config.SetConfig.IDSpaceSize, the SAME function every stub generator
	// calls, so the two sides provably agree on the size of everything
	// indexed by pattern id (gate array, `_all` bitmap, and the narrow-vs-wide
	// `_all` ABI). Zero means "derive it from the
	// pattern ids", which is what the internal harnesses that build a SetSpec
	// directly (rather than from a config) get.
	IDSpaceSize int

	// DeclaredPatternCount is config.SetConfig.PatternCount — the number of
	// patterns the set SELECTS, before any are dropped for carrying captures
	// or exceeding the state limit. It sizes the stubs' tuple buffer, and with
	// it the batch cursor's k field, so it must be the DECLARED count both sides
	// can compute rather than the surviving one only the compiler sees —
	// a mismatch there is a memory-safety hazard, not a wrong answer.
	// Zero means "use the resolved count",
	// which is what the internal harnesses building a SetSpec directly get.
	DeclaredPatternCount int

	Patterns   []*PatternInfo // resolved, capture-bearing dropped
	PatternIDs []int          // global indices into the regexps list
}

// patternCount is the count the batch cursor and the stubs' buffer are sized
// from: the declared one when the caller supplied it.
func (s SetSpec) patternCount() int {
	if s.DeclaredPatternCount > 0 {
		return s.DeclaredPatternCount
	}
	return len(s.Patterns)
}

// HasFind reports whether the set declares the position-reporting capability.
// It needs the tuple-writing suffix functions and is what Overlapping selects
// between; nothing else is affected.
func (s SetSpec) HasFind() bool { return s.Find != "" }

// gated reports whether the set's find bodies carry a gate array.
func (s SetSpec) gated() bool { return s.HasFind() && !s.Overlapping }

// suffixNeedsSkip reports whether the tuple-writing suffix functions carry the
// batch `skip` parameter. Only the OVERLAPPING batch body needs it: the gated
// one resumes a split position through the gate array instead, since the
// tuples it already delivered have gates recorded for them and the gate
// pre-mask therefore excludes exactly those patterns on re-entry.
//
// The parameter is added for every caller of the suffix function once it
// exists, not just the batch body — `find` passes a constant 0. One extra
// argument and one signed compare, on the tuple-write path only.
func (s SetSpec) suffixNeedsSkip() bool { return s.BatchFind && s.Overlapping }

// needsScanProbes reports whether the set declares one of the non-anchored
// capabilities other than `find`. Those answer "which patterns match here?"
// and use the cheap bitmask probe over the find-path buckets rather than the
// tuple-writing suffix function.
func (s SetSpec) needsScanProbes() bool {
	return s.ScanAny != "" || s.ScanAll != ""
}

// needsFirstHitProbes reports whether the set declares a capability that may
// stop at the first matching bit. `scan_all` is
// deliberately absent: its answer is the full bitmask at a position.
func (s SetSpec) needsFirstHitProbes() bool {
	return s.ScanAny != ""
}

// needsAnchoredBuckets reports whether the set declares one of the anchored
// capabilities, which require their own non-leftmost-first automata.
func (s SetSpec) needsAnchoredBuckets() bool {
	return s.MatchAny != "" || s.MatchAll != ""
}

// CompileSet compiles one set specification into a compiledSet.
// prefixPool and suffixPool are shared dedup pools across all sets in the file.
func CompileSet(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions) *compiledSet {
	diag := &SetDiag{Name: spec.Name}
	// G17's sparse accept. Probes are served too: a sparse probe cannot return
	// a bucket-local bitmask — that is the 32-pattern ceiling it exists to
	// escape — so it returns a COUNT and leaves the matching GLOBAL ids in the
	// bucket's scratch, which emitRecordSparseProbe reads back.
	opts.AllowSparseAccept = true
	buckets := binPack(spec.Patterns, opts, diag)

	// G12: per-pattern absence literals, used by the preflights in place of
	// the union walk when available.
	absLits, absAlive, absOK := buildAbsenceLits(spec)

	// Build per-bucket pattern-ID mapping: patternIDs[bucketIdx][bitPos] = globalID.
	//
	// Through a map built once, not a linear search through spec.Patterns per
	// bucket member — that was O(P^2) in the pattern count, twice over (the
	// anchored packing below repeated it).
	globalIDOf := make(map[*PatternInfo]int, len(spec.Patterns))
	for k, sp := range spec.Patterns {
		globalIDOf[sp] = spec.PatternIDs[k]
	}
	patternIDs := make([][]int, len(buckets))
	for bi, b := range buckets {
		ids := make([]int, len(b.patterns))
		for j, p := range b.patterns {
			ids[j] = globalIDOf[p]
		}
		patternIDs[bi] = ids
	}

	// Determine frontend and collect unique literals.
	var lits [][]byte
	litSeen := make(map[string]bool)
	for _, b := range buckets {
		if !b.isFallback && b.literal != "" {
			if !litSeen[b.literal] {
				litSeen[b.literal] = true
				lits = append(lits, []byte(b.literal))
			}
		}
	}
	fe := chooseLiteralFrontend(lits)
	// TEST-ONLY measurement override (task 71). Placed here, before every
	// structural refusal below, so a forced frontend is still subject to the
	// rules that exist for correctness rather than for speed — a fallback
	// bucket still disables a position-skipping prefilter, AC still demotes
	// over budget, packed-pair still needs a qualifying probe window. Only the
	// crossover VERDICT is overridden.
	if opts.forceFrontend && len(lits) > 0 {
		fe = opts.ForceFrontend
	}

	// First pass: compute per-bucket prefix metadata (before building suffix DFAs).
	prefixFnIdx := make([][]int, len(buckets))
	prefixFixedLens := make([][]int, len(buckets))
	trivialPrefixMasks := make([]uint32, len(buckets))
	startAnchorMasks := make([]uint32, len(buckets))
	lineAnchorMasks := make([]uint32, len(buckets))

	var prefixFnBodies [][]byte
	var prefixDataBytes []byte
	var prefixDataSegCount int
	prefixPoolToFnIdx := make(map[int]int) // prefixID → index in prefixFnBodies
	// prefixTableOffset is set after suffix DFA data; computed after suffix loop below.

	// Pre-compute prefix metadata but defer prefix DFA body generation until after suffix DFAs.
	for bi, bkt := range buckets {
		idxes := make([]int, len(bkt.patterns))
		pml := make([]int, len(bkt.patterns))
		var tm, sam, lam uint32
		for j, p := range bkt.patterns {
			if j >= bucketMaskBits {
				idxes[j] = -1
				continue
			}
			if p.startAnchor {
				sam |= uint32(1) << uint(j)
			}
			if p.lineAnchor {
				lam |= uint32(1) << uint(j)
			}
			if p.trivialPrefix || p.prefixDFA == nil {
				idxes[j] = -1
				tm |= uint32(1) << uint(j)
				// pml[j] = 0 (trivial)
			} else {
				// analyzePattern guarantees a non-trivial prefix is
				// fixed-length: variable-length prefixes route to fallback.
				idxes[j] = p.prefixID
				pml[j] = p.prefixMaxLen
			}
		}
		prefixFnIdx[bi] = idxes
		prefixFixedLens[bi] = pml
		trivialPrefixMasks[bi] = tm
		startAnchorMasks[bi] = sam
		lineAnchorMasks[bi] = lam
	}

	// Build suffix DFA function bodies, one per bucket.
	// The suffix DFA now writes match tuples directly (Option C); no startMask needed.
	needScanProbes := spec.needsScanProbes()
	gatedFind := spec.gated()
	var suffixFnBodies [][]byte
	if spec.HasFind() {
		suffixFnBodies = make([][]byte, len(buckets))
	}
	var scanProbeBodies [][]byte
	if needScanProbes {
		scanProbeBodies = make([][]byte, len(buckets))
	}
	// Two probe variants are only needed when the set wants BOTH exit rules.
	// With no `scan_all` declared, nothing needs the mask-complete walk, so
	// the single probe simply IS the first-hit one and no second body — and
	// no module bytes — are spent.
	// G8's liveness table is only worth its per-byte cost where a preflight
	// will narrow the wanted mask; elsewhere it is the reverted
	// Candidate A all over again — a check that costs every byte and can
	// never fire.
	//
	// The gate therefore mirrors usesScanAnyPreflight's own eligibility as
	// closely as it can this early: `scan_any` declared, scalar frontend, some
	// bucket with a never-dying walk, and NO word-boundary or (?m) pattern.
	// The last is asserted here rather than inherited:
	// buildUnionScanDFA refuses such sets, so they would get the table and the
	// per-byte check with no preflight to make it fire.
	// `spec.ScanAny != ""` was the other half of this condition until TODO
	// A scalar-frontend `scan_any` now compiles to the
	// union walk itself, so no per-bucket liveness table can ever be consulted
	// on its behalf. Only G9's gated-`find` preflight still reads one.
	//
	// Item 11 extends it to the OVERLAPPING body, which now has a preflight of
	// its own and therefore something to make the exit fire.
	//
	// The structural half is overlapCanPreflight; the other half is whether
	// anything can actually COMPUTE the verdict, and that is settled by a
	// trial construction of the union automaton. Deciding it by construction
	// rather than by a predicate is the point: buildUnionScanDFA refuses for
	// reasons no cheap test can predict — a union state count over
	// maxUnionScanStates, most of all — and every one of those refusals would
	// otherwise leave a set carrying the table and the per-byte check with no
	// preflight to fire them, which is the reverted Candidate A.
	// Building it twice costs compile time only, and CLAUDE.md's second
	// design principle spends compile time freely to avoid runtime cost.
	overlapPreflight := overlapCanPreflight(spec, buckets) &&
		((absOK && len(absLits) > 0) || buildUnionScanDFA(spec, 0, false) != nil)
	needLiveness := (spec.gated() || overlapPreflight) && fe == frontendScalar
	if needLiveness {
		anyNeverDying, anyBoundary := false, false
		for _, bkt := range buckets {
			if bkt.suffixDFA == nil {
				// Includes BT fallback buckets, which have no table to
				// inspect. A liveness table is a per-DFA artefact; a BT bucket
				// simply never contributes one.
				continue
			}
			if hasNeverDyingState(bkt.suffixDFA) {
				anyNeverDying = true
			}
			if bkt.suffixDFA.hasWordBoundary || bkt.suffixDFA.hasNewlineBoundary {
				anyBoundary = true
			}
		}
		needLiveness = anyNeverDying && !anyBoundary
	}
	needFirstHit := spec.needsFirstHitProbes()
	soleFirstHit := needFirstHit && spec.ScanAll == ""
	needBothProbes := needFirstHit && spec.ScanAll != ""
	// ...and only for buckets where the two rules can actually differ. A
	// SINGLE-pattern bucket has one bit in validMask, so `lBits == validMask`
	// already fires at the first bit — the variant would be a byte-for-byte
	// duplicate. keywords-* is entirely single-pattern buckets, which is why
	// this check turns a ~21% module-size regression into ~0 there.
	// anyProbeIdx[bi] is the bucket's slot in scanProbeAnyBodies, or -1 to
	// use the ordinary probe.
	var scanProbeAnyBodies [][]byte
	anyProbeIdx := make([]int, len(buckets))
	for bi := range anyProbeIdx {
		anyProbeIdx[bi] = -1
	}
	if needScanProbes && needBothProbes {
		for bi, bkt := range buckets {
			if len(bkt.patterns) > 1 {
				anyProbeIdx[bi] = len(scanProbeAnyBodies)
				scanProbeAnyBodies = append(scanProbeAnyBodies, nil)
			}
		}
	}
	var allDataBytes []byte
	var totalDataSegs int
	tableOffset := opts.TableBase // data segment base for this set's tables

	// The tuple-writing suffix function is `find`'s alone:
	// it is the per-pattern extent machinery, and the other six capabilities
	// answer their question from the bitmask probe instead. A set that does
	// not declare `find` therefore emits no suffix FUNCTIONS at all — only
	// their DFA tables, which the probes share.
	needSuffixFns := spec.HasFind()
	// Suffix-table dedup. Buckets very often share a
	// suffix: `kw%03d[0-9a-z]{3}` gives every pattern its own literal and its
	// own bucket, but one identical `[0-9a-z]{3}` table, re-emitted once per
	// bucket. The tables are the bulk of such a module.
	//
	// Sound because genSuffixWASM's DATA is a function of (table, base) alone:
	// the bitmask tables are built from the table's own accept maps, whose bits
	// are per-bucket BIT POSITIONS, not global pattern ids. Global ids and
	// prefix lengths reach only the BODY, which is why each bucket still calls
	// genSuffixWASM with its own — we reuse the address, never the body.
	//
	// Identity is dfaFingerprint + dfaTableEqual, the same exact test dfaPool
	// uses. Both are exact rather than heuristic, so a table that is not
	// canonical simply fails to dedup; it can never alias onto a different one.
	//
	// The "DATA is a function of (table, base) alone" argument holds ONLY for
	// bitmask buckets. A G17-SPARSE bucket's data additionally carries an
	// idMap of GLOBAL pattern ids plus per-state accept lists sized by its own
	// pattern count — none of which the table identity sees — so two sparse
	// buckets with structurally identical suffix DFAs would alias onto one
	// idMap and report the second bucket's matches under the first bucket's
	// ids (with different pattern counts, under baked offsets that no longer
	// match the emitted layout at all). Sparse buckets therefore never enter
	// the pool and never reuse a base.
	type suffixSlot struct {
		t    *dfaTable
		base int32
	}
	suffixDedup := map[uint64][]suffixSlot{}
	for bi, bkt := range buckets {
		// A Backtracking fallback bucket has no table at all — that is the
		// point of it. Its suffix body is emitted later,
		// once the shared BT regions and the BT body's function index are
		// known, so this pass simply leaves its slot empty and advances
		// nothing.
		if bkt.btFallback != nil {
			continue
		}
		base, reused, fp := tableOffset, false, uint64(0)
		if bkt.suffixDFA != nil && !bkt.sparse {
			fp = dfaFingerprint(bkt.suffixDFA)
			for _, slot := range suffixDedup[fp] {
				if dfaTableEqual(slot.t, bkt.suffixDFA) {
					base, reused = slot.base, true
					break
				}
			}
		}
		art, dataBytes, dataSegs, nextOffset := genSuffixWASM(bkt.suffixDFA, int64(base), opts.TableMemIdx, patternIDs[bi], prefixFixedLens[bi], opts.LikelyMode, needScanProbes, gatedFind, needBothProbes && anyProbeIdx[bi] >= 0, soleFirstHit, needLiveness, spec.suffixNeedsSkip())
		bkt.dp = art.dp
		if art.sparseProbeReady {
			// The scratch address is decided by the emitter; the driver reads
			// probe results from it, so it is written back here rather than
			// recomputed.
			bkt.sparseScratch = art.sparseScratch
			bkt.sparseIDMapOff = art.sparseIDMapOff
		}
		if needSuffixFns {
			suffixFnBodies[bi] = art.fnBody
		}
		if needScanProbes {
			scanProbeBodies[bi] = art.scanProbe
			if needBothProbes && anyProbeIdx[bi] >= 0 {
				scanProbeAnyBodies[anyProbeIdx[bi]] = art.scanProbeAny
			}
		}
		if reused {
			// Bodies point at the tables emitted for the first bucket with
			// this suffix; emitting the identical bytes again would only
			// duplicate them. tableOffset must NOT advance.
			continue
		}
		tableOffset = nextOffset // use actual memory end, not encoded size
		allDataBytes = append(allDataBytes, dataBytes...)
		totalDataSegs += dataSegs
		if bkt.suffixDFA != nil && !bkt.sparse {
			suffixDedup[fp] = append(suffixDedup[fp], suffixSlot{bkt.suffixDFA, base})
		}
	}

	// Second pass: build prefix DFA function bodies (after suffix data, to avoid address overlap).
	prefixTableOffset := tableOffset // start after all suffix DFA data
	for bi, bkt := range buckets {
		// Resolve prefixID → fnIdx for non-trivial patterns in this bucket.
		for j, p := range bkt.patterns {
			if j >= bucketMaskBits || prefixFnIdx[bi][j] < 0 {
				continue // trivial or out of range
			}
			prefixID := p.prefixID
			fnIdx, ok := prefixPoolToFnIdx[prefixID]
			if !ok {
				revL := buildDFALayout(dfaLayoutParams{
					t:                    p.prefixDFA,
					tableBase:            int64(prefixTableOffset),
					needFind:             false,
					leftmostFirst:        false,
					compiledDFAThreshold: 0,
					useAcceptSideTable:   false,
					lmBareShufti:         false,
					lmNonMidShufti:       false,
					lmWideShufti:         false,
				})
				body := buildLitAnchorBackScanBody(revL, p.prefixDFA, opts.TableMemIdx, false)
				fnIdx = len(prefixFnBodies)
				prefixFnBodies = append(prefixFnBodies, body)
				prefixPoolToFnIdx[prefixID] = fnIdx
				rawPfx, cnt := stripSegCount(dfaDataSegments(revL, false, false))
				// buildLitAnchorBackScanBody reads midAcceptOff; emit it explicitly.
				midAccSeg := appendDataSegment(nil, revL.midAcceptOff, revL.midAcceptBytes)
				rawPfx = append(rawPfx, midAccSeg...)
				cnt++
				prefixDataBytes = append(prefixDataBytes, rawPfx...)
				prefixDataSegCount += cnt
				prefixTableOffset += int32(len(rawPfx))
			}
			prefixFnIdx[bi][j] = fnIdx
		}
	}

	// Build literal-to-bucket(s) mapping and frontend data (AC or Teddy).
	// Multiple buckets can share a literal when bin-packing splits large groups
	// (> bitmaskWidth patterns with the same mandatory literal).
	var litToBuckets [][]int
	var litLens []int
	if len(lits) > 0 {
		litToBuckets = make([][]int, len(lits))
		litLens = make([]int, len(lits))
		for litID, lit := range lits {
			litLens[litID] = len(lit)
			for bi, bkt := range buckets {
				if !bkt.isFallback && bkt.literal == string(lit) {
					litToBuckets[litID] = append(litToBuckets[litID], bi)
				}
			}
		}
	}

	var acL *acLayout
	var acDataBytes []byte
	acDataSegCount := 0
	var acFirstByteSet []byte
	var acFirstByteFlagsOff int32
	if fe == frontendAC {
		ac := buildAC(lits)
		// Cap: the AC goto table is the single largest table a set emits, so
		// it gets its own byte budget rather than sharing the per-bucket one.
		//
		// The previous cap was 32 NODES, justified in-comment by "epoch
		// timeouts during re2test instantiation" — a test-harness constraint
		// shaping production codegen, and one that no longer reproduces:
		// instantiating a 128-literal AC module measures ~8 us, flat in AC
		// size. What it cost was 86-414x the
		// scan fuel, because past the cap the set silently lost its literal
		// frontend entirely and visited every input position against every
		// bucket. See acBudgetBytes for why this is denominated in
		// bytes and why the default is what it is.
		// Uncompressed first, byte-class compression only as a RESCUE.
		// Compression costs one table load per input
		// byte to map byte→class, so spending it on a set that already fits
		// would trade fuel — this project's first-priority metric — for
		// module bytes, its second. It earns that cost only against the
		// alternative of losing the literal frontend altogether, which
		// measures 86-414x worse.
		cand := buildACLayoutMode(ac, prefixTableOffset, false)
		acBytes := cand.bytes()
		if acBytes > opts.acBudgetBytes() {
			if packed := buildACLayoutMode(ac, prefixTableOffset, true); packed.compressed && packed.bytes() <= opts.acBudgetBytes() {
				cand = packed
			}
		}
		// Node ids are u16 in the goto table. Compression can fit far more
		// nodes than the id space addresses (see acMaxNodes), so this is
		// checked alongside the budget rather than assumed away.
		acOutputs := acTotalOutputs(ac)
		if len(ac.nodes) > acMaxNodes {
			fe = frontendScalar
			diag.FrontendDemotion = &FrontendDemotionDiag{
				From:   frontendAC.String(),
				To:     frontendScalar.String(),
				Reason: "ac_nodes_exceed_u16",
				Detail: map[string]interface{}{
					"literals":  len(lits),
					"ac_nodes":  len(ac.nodes),
					"max_nodes": acMaxNodes,
				},
			}
		} else if acOutputs > acMaxOutputs {
			// Output OFFSETS are u16 too, and they are bounded by the
			// propagated output count rather than by the node count — a nested
			// literal family reaches the offset limit from a few hundred nodes
			// (see acMaxOutputs). Passing acMaxNodes and acBudgetBytes says
			// nothing about this one, so it gets its own arm.
			fe = frontendScalar
			diag.FrontendDemotion = &FrontendDemotionDiag{
				From:   frontendAC.String(),
				To:     frontendScalar.String(),
				Reason: "ac_outputs_exceed_u16",
				Detail: map[string]interface{}{
					"literals":    len(lits),
					"ac_nodes":    len(ac.nodes),
					"ac_outputs":  acOutputs,
					"max_outputs": acMaxOutputs,
				},
			}
		} else if cand.bytes() <= opts.acBudgetBytes() {
			acL = cand
			acDataBytes = emitACDataSegments(acL)
			acDataSegCount = acDataSegments(acL)
			diag.ACTable = &ACTableDiag{
				Nodes:      acL.numNodes,
				Bytes:      acL.bytes(),
				Compressed: acL.compressed,
			}
			if acL.compressed {
				diag.ACTable.ByteClasses = acL.numClasses
				diag.ACTable.Stride = acL.stride
			}

			// Build firstByteFlags[256] table for SIMD prefilter.
			fbFlags := make([]byte, 256)
			fbSeen := make(map[byte]bool)
			for _, lit := range lits {
				fb := lit[0]
				fbFlags[fb] = 1
				if !fbSeen[fb] {
					fbSeen[fb] = true
					acFirstByteSet = append(acFirstByteSet, fb)
				}
			}
			acFirstByteFlagsOff = acL.tableEnd
			acDataBytes = append(acDataBytes, appendDataSegment(nil, acFirstByteFlagsOff, fbFlags)...)
			acDataSegCount++ // one more segment for firstByteFlags
		} else {
			fe = frontendScalar
			diag.FrontendDemotion = &FrontendDemotionDiag{
				From:   frontendAC.String(),
				To:     frontendScalar.String(),
				Reason: "ac_table_over_budget",
				Detail: map[string]interface{}{
					"literals":         len(lits),
					"ac_nodes":         len(ac.nodes),
					"table_bytes":      acBytes,
					"compressed_bytes": cand.bytes(),
					"byte_classes":     cand.numClasses,
					"budget_bytes":     opts.acBudgetBytes(),
				},
			}
		}
	}

	var teddyTabs *teddyTables
	var teddyTableEnd int32
	var teddyDataOffset int32
	var teddyDataBytes []byte
	teddyDataSegCount := 0
	if fe == frontendTeddy {
		// chooseLiteralFrontend only returns frontendTeddy for 1..16 non-empty
		// literals, which is exactly buildTeddyTablesMulti's success condition.
		tt, _ := buildTeddyTablesMulti(lits)
		teddyTabs = tt
		teddyDataOffset = prefixTableOffset
		rawTeddy := buildTeddyRawBytes(tt)
		teddyDataBytes = appendDataSegment(nil, teddyDataOffset, rawTeddy)
		teddyDataSegCount = 1
		teddyTableEnd = teddyDataOffset + int32(len(rawTeddy))
	}

	// Packed pair: no tables, so nothing is laid out here —
	// only the plan the emitter reads. chooseLiteralFrontend returns this
	// kind only when choosePackedPair succeeded on the same literals.
	var packedPair *packedPairPlan
	if fe == frontendPackedPair {
		packedPair, _ = choosePackedPair(lits)
	}

	// the LikelyMode dispatch design: density-heuristic / Action 5 Shufti for the
	// scalar fallback case. Requires zero fallback buckets (Shufti can't
	// skip positions that fallback patterns must visit) and a first-byte
	// union in the 17..64 band. The selection trigger is either the
	// rarity-based density heuristic or set-level LikelyNoMatch (Action 5).
	var shuftiFirstByteSet []byte
	var shuftiAdaptive bool
	// maxShuftiUnionLNM is the widened upper bound on the first-byte union,
	// under set-level LikelyNoMatch only (task 70). The SIMD probe itself is
	// width-agnostic — emitShuftiPrefixCheck just builds one more nibble-table
	// pair per 8 members — but this body's SCALAR TAIL is not: it tests
	// membership with an unrolled per-first-byte compare chain, which is
	// O(|union|) per byte and runs for the rest of the call once the adaptive
	// density switch disables the probe.
	//
	// So this bound is limited by MEASUREMENT, not by the mechanism. 79 is the
	// widest union measured (−54% fuel on input outside the union, +4% on
	// input dense in it) and 70 is the widest checked against Go
	// (tools/fuzz's TestSetWideUnionShuftiAgainstOracle). 128 stays within
	// interpolation of that; raising it to detectShuftiSelfLoop's 239 is an
	// extrapolation of the tail's cost, and should not happen without either a
	// measurement at that width or replacing the compare chain with a 256-byte
	// membership table — which is what would make the bound mechanism-limited
	// instead.
	const maxShuftiUnionLNM = 128
	if fe == frontendScalar {
		hasFallback := false
		for _, b := range buckets {
			if b.isFallback {
				hasFallback = true
				break
			}
		}
		if !hasFallback {
			union := litUnionFirstBytes(lits)
			lnm := opts.LikelyMode == LikelyNoMatch
			// The band's upper bound is 64 for a static verdict and
			// maxShuftiUnionLNM under LikelyNoMatch. Shufti's nibble tables
			// express any byte set — 64 is a productivity heuristic, not a
			// structural limit, and the single-pattern side already runs the
			// same mechanism at 239 (detectShuftiSelfLoop's maxWidthLM).
			//
			// Above 64 the static heuristic is NOT consulted, and that is
			// deliberate rather than an oversight: shuftiBeatsScalar's density
			// model was calibrated inside the narrow band, so asking it about a
			// 90-byte union is asking a question it was never fitted for. The
			// widened band is therefore force-plus-adapt — LNM asserts it, and
			// shuftiAdaptive's runtime counter is what bounds a wrong
			// assertion.
			hi := 64
			if lnm {
				hi = maxShuftiUnionLNM
			}
			if len(union) >= 17 && len(union) <= hi {
				rare := len(union) <= 64 && shuftiBeatsScalar(union)
				if lnm || rare {
					fe = frontendShufti
					shuftiFirstByteSet = union
					shuftiAdaptive = lnm && !rare
					// TEST-ONLY measurement override (task 74). Inside the
					// selection branch on purpose: it answers "does the switch
					// still earn its cost on a set that ships Shufti", not
					// "emit the switch somewhere it has nothing to guard".
					if opts.forceShuftiAdaptive {
						shuftiAdaptive = opts.ForceShuftiAdaptive
					}
				}
			}
		}
	}

	// Record the frontend actually used (after any fallback to scalar).
	diag.Frontend = fe.String()

	// Member self-loop skip counts, recorded HERE rather than at emission.
	//
	// `--diag-json` is produced by CmdWriteDiagJSON, which re-runs CompileSet
	// and never reaches assembleModuleWithSets — so anything written when the
	// body is emitted is invisible to it. buildMemberSets is a pure function
	// of (suffix DFA, state count), so asking it twice is safe: the emitter
	// and this report cannot disagree about what qualified.
	if opts.LikelyMode == LikelyMatch {
		for bi, bkt := range buckets {
			if bi >= len(diag.Buckets) || bkt.suffixDFA == nil || !bkt.sparse {
				continue
			}
			idTab, setTab := buildMemberSets(bkt.suffixDFA, bkt.suffixDFA.numStates+1)
			n := 0
			for _, id := range idTab {
				if id != 0 {
					n++
				}
			}
			diag.Buckets[bi].MemberSkipStates = n
			diag.Buckets[bi].MemberSkipSets = len(setTab) / memberSetBytes
		}
	}

	// The set match function body is built at assemble time (when function table
	// indices are known). Store nil here; assembleModuleWithSets fills it in.
	// Everything from here down claims its region through `ra`, which tracks a
	// REAL end-of-region rather than a sum of serialized data-segment lengths.
	//
	// Those two differ. A data segment's bytes include its own header, which
	// over-counts, but a REGION can also contain gaps between segments — the
	// anchored automaton leaves one between its transition table and its
	// eofBitmask — and the byte sum under-counts those. The proxy this
	// replaced got it wrong in the unsafe direction: for a set declaring all
	// seven capabilities it placed the union-scan table 8 bytes INSIDE the
	// anchored eofBitmask, silently overwriting the last state's accept mask.
	// That was an anchored false positive which appeared only when
	// unrelated capabilities were also declared.
	//
	// The allocator exists so that class cannot recur by inspection: a base
	// comes only from Reserve, so no block can lay a table at an address
	// derived from a stale cursor, and Commit refuses an extent below the
	// frontier. See compile/region.go.
	frontier := prefixTableOffset
	if acL != nil {
		frontier = acFirstByteFlagsOff + 256 // firstByteFlags is last
	}
	if teddyTableEnd > frontier {
		frontier = teddyTableEnd
	}
	ra := newRegionAlloc(frontier)

	// ── Backtracking fallback buckets ────────────────────
	// Laid out above every other table this set owns, so the regions cannot
	// collide with a suffix, prefix, AC or Teddy table. ONE shared allocation
	// sized to the largest BT bucket: only one BT call is ever live, because
	// the per-candidate driver calls one suffix function at a time and the
	// memo re-zeroes itself at the head of every call.
	btBase := ra.Reserve("bt-fallback", 1)
	btRegions := planBTRegions(buckets, int64(btBase))
	numBTFns := 0
	for bi, bkt := range buckets {
		if bkt.btFallback == nil {
			continue
		}
		// A BT bucket holds exactly ONE pattern: BT has no merged form, and
		// buildSetBTSuffixBody answers for patternIDs[bi][0] / validMask bit 0
		// alone. This invariant was violated silently once — compileFallback's
		// bin-packer merged later fallback patterns INTO a BT bucket, and every
		// merged-in pattern vanished from every bucketed capability with no
		// error anywhere. Panic
		// rather than emit: there is no correct module to produce from this
		// state, and the alternative is another silent under-report.
		if n := len(bkt.patterns); n != 1 {
			panic(fmt.Sprintf("compile: set %q bucket %d is a Backtracking "+
				"fallback holding %d patterns — a BT bucket must hold exactly "+
				"one; the bin-packer merged into it",
				spec.Name, bi, n))
		}
		numBTFns++
	}
	if btRegions == nil {
		ra.Skip()
	}
	if btRegions != nil {
		ra.Commit(btRegions.end)
		// DECLARE the reservation in the data section. The regions hold no
		// initial data — BT zeroes its own memo and its stack starts empty —
		// but a caller has no other way to learn they exist: both
		// utils.WasmMemTop and the harnesses derive "where free memory
		// starts" from the emitted data segments. Without this the input
		// buffer is placed straight on top of the BT stack, which is silent
		// corruption rather than a trap: a mixed set lost matches from the
		// LITERAL bucket too, which is how it was found.
		//
		// One zero byte at the top is enough to move that boundary; carrying
		// the whole region as zeros would add tens of KB to every module.
		allDataBytes = append(allDataBytes, appendDataSegment(nil, btRegions.end-1, []byte{0})...)
		totalDataSegs++
	}

	cs := &compiledSet{
		absenceLits:         absLits,
		absenceAlive:        absAlive,
		absenceOK:           absOK,
		name:                spec.Name,
		matchAny:            spec.MatchAny,
		matchAll:            spec.MatchAll,
		scanAny:             spec.ScanAny,
		scanAll:             spec.ScanAll,
		find:                spec.Find,
		batchFind:           spec.BatchFind,
		patternCount:        spec.patternCount(),
		suffixHasSkip:       spec.suffixNeedsSkip(),
		overlapping:         spec.Overlapping,
		declaredIDSpace:     spec.IDSpaceSize,
		suffixFnBodies:      suffixFnBodies,
		scanProbeBodies:     scanProbeBodies,
		scanProbeAnyBodies:  scanProbeAnyBodies,
		anyProbeIdx:         anyProbeIdx,
		numSuffixFns:        len(suffixFnBodies),
		numBTFns:            numBTFns,
		tableMemIdx:         opts.TableMemIdx,
		btRegions:           btRegions,
		dataBytes:           allDataBytes,
		dataSegCount:        totalDataSegs,
		prefixFnBodies:      prefixFnBodies,
		prefixDataBytes:     prefixDataBytes,
		prefixDataSegCount:  prefixDataSegCount,
		prefixFnIdx:         prefixFnIdx,
		trivialPrefixMasks:  trivialPrefixMasks,
		startAnchorMasks:    startAnchorMasks,
		lineAnchorMasks:     lineAnchorMasks,
		prefixFixedLens:     prefixFixedLens,
		buckets:             buckets,
		patternIDs:          patternIDs,
		fe:                  fe,
		acL:                 acL,
		acDataBytes:         acDataBytes,
		acDataSegCount:      acDataSegCount,
		acFirstByteSet:      acFirstByteSet,
		acFirstByteFlagsOff: acFirstByteFlagsOff,
		teddyTabs:           teddyTabs,
		teddyDataOffset:     teddyDataOffset,
		teddyDataBytes:      teddyDataBytes,
		teddyDataSegCount:   teddyDataSegCount,
		shuftiFirstByteSet:  shuftiFirstByteSet,
		packedPair:          packedPair,
		shuftiAdaptive:      shuftiAdaptive,
		unionSkipLNM:        opts.LikelyMode == LikelyNoMatch,
		litToBuckets:        litToBuckets,
		litLens:             litLens,
		diag:                diag,
	}
	// Anchored-capability automata: a separate packing over the full
	// patterns with leftmost-first pruning disabled.
	//
	// ONE automaton when it can be built, buckets
	// otherwise. The union serves match_any and match_all together — there is
	// no way to give one of them the automaton and the other the buckets, since
	// both read the same packing — so the staging the item describes collapses
	// into a single step, which is recorded there.
	if spec.needsAnchoredBuckets() {
		// Anchored tables go after every other table this set emits; the data
		// segment bytes include their own headers, so this over-estimates the
		// end of the preceding regions, which is harmless.
		// 8-aligned. Every union table this base leads to is read with an
		// i64 or i32 load, and their own internal alignment is relative to
		// it — so a base at an odd address makes the alignment inside the
		// builder a promise it cannot keep.
		anchoredTableBase := ra.Reserve("anchored", 8)
		// Both arms below lay their tables from this base; whichever runs sets
		// anchoredEnd, and the single Commit after them records the extent.
		anchoredEnd := anchoredTableBase
		// The packer runs FIRST, because whether it produces one automaton is
		// itself part of the union's eligibility — see anchoredUnionBeatsBuckets.
		// Its result is discarded when the union wins, which costs compile time
		// only (CLAUDE.md: runtime over compile time).
		abuckets, amembers := compileAnchoredBuckets(spec.Patterns, opts, diag)
		// The union must answer for exactly the patterns the PACKER kept.
		//
		// It is built from a spec, and the packer drops a pattern whose solo
		// anchored DFA exceeds max_fallback_states (and admits no Backtracking
		// member — see docs/sets.md "Backtracking members and the anchored
		// pair"). Building the union from the unfiltered spec made the two
		// halves of one capability disagree: with the union, match_any and
		// match_all reported patterns that with buckets they do not, and the
		// --set-bt corpus leg found exactly that.
		anchoredSpec := spec
		kept := make(map[*PatternInfo]bool, len(spec.Patterns))
		for _, members := range amembers {
			for _, p := range members {
				kept[p] = true
			}
		}
		if len(kept) != len(spec.Patterns) {
			anchoredSpec.Patterns = nil
			anchoredSpec.PatternIDs = nil
			for i, p := range spec.Patterns {
				if kept[p] {
					anchoredSpec.Patterns = append(anchoredSpec.Patterns, p)
					anchoredSpec.PatternIDs = append(anchoredSpec.PatternIDs, spec.PatternIDs[i])
				}
			}
		}
		var au *anchoredUnion
		if len(anchoredSpec.Patterns) > 0 && anchoredUnionBeatsBuckets(abuckets) {
			// The `_all` ABI is cs.wideAll()'s to decide, and the automaton
			// must be built to match it — see buildAnchoredUnionDFA's
			// forceWideAll. cs.idSpaceSize() is not usable here yet (an
			// anchored-only set has no packing to read ids from until this
			// block fills cs.anchoredIDs), so the same quantity is computed
			// from the spec.
			idSpace := spec.IDSpaceSize
			if idSpace <= 0 {
				maxID := -1
				for _, id := range spec.PatternIDs {
					if id > maxID {
						maxID = id
					}
				}
				idSpace = maxID + 1
			}
			forceWideAll := idSpace > wideBitmapThreshold || cs.hasBTMember()
			au = buildAnchoredUnionDFA(anchoredSpec, anchoredTableBase, spec.MatchAll != "", forceWideAll)
		}
		if au != nil {
			cs.anchoredUnion = au
			// The union covers every pattern of the set, so the ids it can
			// report are exactly the set's — no packing to read them from.
			// idSpaceSize and checkIDSpace consult this, and an anchored-only
			// set has no other packing at all.
			cs.anchoredIDs = [][]int{append([]int(nil), anchoredSpec.PatternIDs...)}
			cs.anchoredDataBytes = append(cs.anchoredDataBytes, au.dataBytes...)
			cs.anchoredDataSegs += au.dataSegs
			if au.tableEnd > anchoredEnd {
				anchoredEnd = au.tableEnd
			}
			diag.AnchoredUnion = &AnchoredUnionDiag{
				Used: true, States: au.numStates, Wide: au.isWide(),
				StateWidth: au.stateWidth, NumClasses: au.numClasses,
			}
		} else {
			diag.AnchoredUnion = &AnchoredUnionDiag{Refused: "construction"}
			if !anchoredUnionBeatsBuckets(abuckets) {
				diag.AnchoredUnion.Refused = "single_sparse_bucket"
			}
			cs.anchoredBuckets = abuckets
			cs.anchoredIDs = make([][]int, len(abuckets))
			anchoredOffset := anchoredTableBase
			for bi, ab := range abuckets {
				ids := make([]int, len(ab.patterns))
				for j, ap := range ab.patterns {
					ids[j] = globalIDOf[ap]
				}
				cs.anchoredIDs[bi] = ids
				body, data, segs, next, sp := genAnchoredWASM(ab.suffixDFA, int64(anchoredOffset), opts.TableMemIdx, ids)
				if sp != nil {
					ab.sparseScratch = sp.scratch
					ab.sparseIDMapOff = sp.idMapOff
				}
				cs.anchoredProbeBodies = append(cs.anchoredProbeBodies, body)
				cs.anchoredDataBytes = append(cs.anchoredDataBytes, data...)
				cs.anchoredDataSegs += segs
				anchoredOffset = next
			}
			if anchoredOffset > anchoredEnd {
				anchoredEnd = anchoredOffset
			}
		}
		ra.Commit(anchoredEnd)
	}

	// Start-anywhere union DFA for the scan trio.
	//
	// Built here, last, so its tables sit past every other region this set
	// emits — the anchored automata are laid out immediately above AC/Teddy
	// and would otherwise overlap.
	//
	// Restricted to sets that ended up on the SCALAR frontend. A literal
	// frontend already skips input and beats a table lookup per byte; this
	// path is for the sets that have nothing to skip with, where the
	// alternative is visiting every position with every bucket.
	//
	// A find-only OVERLAPPING set needs it too, for item 11's preflight: the
	// alive verdict is what retires a never-dying pattern from validMask, and
	// without the automaton there is nothing to compute it with.
	//
	// So does a find-only GATED set. Its
	// preflight had always been silently dormant on such a set — the automaton
	// it reads was only ever built for the scan capabilities — which is why
	// the losing classchain row got one at all (setperf declares the scan pair
	// beside `find`) while a `find`-only module got nothing. Building it here
	// is what makes the extended eligibility mean anything.
	needUnionForOverlap := cs.overlapPreflightShape() && !cs.usesAbsencePrefilter()
	needUnionForGated := cs.gatedPreflightShape() && !cs.usesAbsencePrefilter()
	if fe == frontendScalar && (spec.ScanAll != "" || spec.ScanAny != "" || needUnionForOverlap || needUnionForGated) {
		unionBase := ra.Reserve("union-scan", 8) // 8-aligned, see anchoredTableBase
		// needUnionForGated also asks for the per-state accept ROWS, which a
		// WIDE automaton emits only on request and the wide alive walk reads in
		// place of the u64 pair it has no room for (item 22 fix 2a-wide). On a
		// narrow build the flag changes nothing: that arm emits the u64 pair and
		// returns before the rows exist at all.
		cs.unionScan = buildUnionScanDFA(spec, unionBase, needUnionForGated)
		if cs.unionScan != nil && cs.unionScan.tableEnd > unionBase {
			ra.Commit(cs.unionScan.tableEnd)
		} else {
			ra.Skip()
		}
		diag.UnionScan = unionScanDiagOf(cs.unionScan, spec, false)
	} else if spec.ScanAll != "" || spec.ScanAny != "" {
		diag.UnionScan = &UnionScanDiag{Refused: "frontend"}
	}

	// Phase 2 of the two-phase scan, for the MIXED sets
	// the block above cannot serve: a literal frontend plus at least one
	// fallback bucket, where today the fallback's every-position obligation
	// costs the whole set its skip. The automaton covers the FALLBACK
	// patterns only; phase 1 is the frontend over the literal buckets.
	//
	// `scan` is not consulted: it is a retired key.
	//
	// NOT taken when the set has a Backtracking member. Phase 2's union walk
	// answers with an i64 accumulator and
	// has no out_ptr parameter at all — it implements the NARROW `_all` ABI
	// only — while a BT member forces every `_all` capability into the memory
	// form, so emitTwoPhaseScanBody would be composing two phases of different
	// shapes. Skipping the split costs those sets phase 1's skip and nothing
	// else: the ordinary bucketed path serves every pattern, BT buckets
	// included. A set that pays for Backtracking is already the slow case.
	if fe != frontendScalar && (spec.ScanAny != "" || spec.ScanAll != "") &&
		hasSetFallbackBucketsIn(buckets) && hasLiteralBuckets(buckets) &&
		!hasBTBucketIn(buckets) {
		p2Base := ra.Reserve("phase2-union", 8) // 8-aligned, see anchoredTableBase
		sub := fallbackSubSpec(spec, buckets)
		// No accept rows on request: phase 2 serves the scan pair only, and
		// `find` — the preflight's capability — is excluded from the split.
		cs.phase2Union = buildUnionScanDFA(sub, p2Base, false)
		if cs.phase2Union != nil && cs.phase2Union.tableEnd > p2Base {
			ra.Commit(cs.phase2Union.tableEnd)
		} else {
			ra.Skip()
		}
		diag.UnionScan = unionScanDiagOf(cs.phase2Union, sub, true)
	}

	// First-byte eligibility tables, laid out after every other
	// region for the same reason the union DFA is: whatever is built last must
	// start above what is already placed, or two tables share an address.
	//
	// Only the scalar frontend, and only its FALLBACK buckets: a literal
	// frontend has already proved a literal sits at the candidate position, so
	// the first byte tells it nothing it does not know.
	cs.startableOff = make([]int32, len(buckets))
	for bi := range cs.startableOff {
		cs.startableOff[bi] = -1
	}
	// Built for the SCAN pair as well as `find`. The scan bodies take exactly
	// the same per-position probe call on exactly the same fallback buckets —
	// literal-less past 256 ids, or a mixed set whose fallback cannot
	// determinise into phase2Union — so withholding the table from them left
	// every position paying a full probe G16 would have skipped. On `find`
	// that skip was worth 251 -> 94 fuel/byte on greedy-3's no-match row.
	if fe == frontendScalar && (spec.Find != "" || spec.ScanAny != "" || spec.ScanAll != "") {
		for bi, bkt := range buckets {
			if !bkt.isFallback {
				continue
			}
			tab := buildStartableTable(bkt)
			if tab == nil {
				continue
			}
			raw := make([]byte, 256*4)
			for b, m := range tab {
				binary.LittleEndian.PutUint32(raw[b*4:], m)
			}
			off := ra.Bump("startable", int32(len(raw)), 1)
			cs.startableOff[bi] = off
			cs.startableDataBytes = append(cs.startableDataBytes,
				appendDataSegment(nil, off, raw)...)
			cs.startableDataSegs++
		}
	}

	// The sweep's two working columns. Module memory, and that is allowed:
	// they live only for the duration of one call, which is what the
	// no-module-state rule
	// permits. The tuples — the part that must survive BETWEEN calls — go in
	// the caller's scratch.
	//
	// Reserved as a zero-filled DATA SEGMENT even though every byte is written
	// before it is read. That is not waste, it is the contract: a caller
	// decides where its own input may go by asking where the module's data
	// ends, and every harness in this repo does it by walking the data
	// section. A region that exists only in an internal offset is invisible to
	// that question, and the first call lays the column straight over the
	// caller's input — which is exactly what happened when stage B tried it.
	if n := cs.overlapDPColumnBytes(); n > 0 {
		// Bump, not a bare offset: the columns are the last region placed
		// today, and "correct because nothing follows it" is a property of the
		// current order rather than of this code. Leaving a region out of the
		// running end is the accounting slip X1 exists to end.
		cs.overlapDPColOff = ra.Bump("overlap-dp-column", int32(n), 1)
		cs.startableDataBytes = append(cs.startableDataBytes,
			appendDataSegment(nil, cs.overlapDPColOff, make([]byte, n))...)
		cs.startableDataSegs++
	}

	// First-position routing data, derived from the finished bucket list.
	cs.prefixLenGroups = make([][]prefixLenGroup, len(buckets))
	for bi := range buckets {
		cs.prefixLenGroups[bi] = buildPrefixLenGroups(cs, bi)
	}
	cs.checkIDSpace()
	cs.maxLookback = setMaxLookback(cs)
	diag.MaxLookback = cs.maxLookback
	diag.IDSpaceSize = cs.idSpaceSize()
	diag.Overlapping = spec.Overlapping
	for _, c := range []struct{ field, name string }{
		{"match_any", spec.MatchAny}, {"match_all", spec.MatchAll},
		{"scan_any", spec.ScanAny}, {"scan_all", spec.ScanAll},
		{"find", spec.Find},
	} {
		if c.name != "" {
			diag.Capabilities = append(diag.Capabilities, c.field)
		}
	}
	if spec.BatchFind {
		// Not a capability any more (decision (11)), but the module does emit
		// an extra entry for it, so --diag-json must still say so.
		diag.Capabilities = append(diag.Capabilities, "find+batch-find")
	}
	return cs
}

// --------------------------------------------------------------------------
// CompileFile — orchestrates all patterns and sets into one WASM module.

// CompileFile compiles all regexp patterns and sets from cfg into a single WASM module.
// When cfg.Sets is empty, it is byte-identical to the existing Compile() path.
//
// The second return value is ONE PAST the highest address the module's tables
// occupy — set tables included — so a caller can place its input above it.
func CompileFile(cfg config.BuildConfig, output string) ([]byte, int64, error) {
	w, top, _, err := CompileFileDiag(cfg, output)
	return w, top, err
}

// CompileFileOpts is CompileFileDiag with per-set options the YAML config does
// not expose, for tests that need to reach a frontend the config cannot select.
//
// It exists for exactly one such frontend today. Shufti is chosen only from the
// SCALAR branch, which needs Aho-Corasick to decline first — and AC declines
// only when its table would exceed ACBudgetBytes, default 512 KB. A set large
// enough to do that naturally is reachable in production but far too large to
// build in a test, so `ACBudgetBytes: 1` simulates the condition cheaply.
//
// Without this entry point there was no way for a harness that can RUN a module
// to produce a Shufti one: `CompileSet` is exported but returns an unexported
// type, and every module-building path took only a config.BuildConfig. The
// result was 215 lines of SIMD prefilter emitter — emitSetMatchFnFinalShufti —
// whose output nothing had ever executed and compared against an oracle, while
// `make set-coverage` reported every other set emitter reached.
//
// The zero value reproduces CompileFileDiag exactly; only fields the caller
// sets take effect, and none of them is reachable from YAML.
func CompileFileOpts(cfg config.BuildConfig, output string, over CompileSetOptions) ([]byte, int64, []SetDiag, error) {
	return compileFileDiag(cfg, output, over)
}

// CompileFileDiag is CompileFile plus the per-set diagnostics the same compile
// already produced — one SetDiag per entry of cfg.Sets, in that order.
//
// It exists because a set can legitimately EXCLUDE a pattern the caller asked
// for: a suffix DFA over max_dfa_states is dropped with a warning and recorded
// in SetDiag.StateLimitDropped, and a set that does not contain a pattern does
// not report its matches. Any differential test therefore has to know which
// patterns actually made it in, or it compares the engine against an oracle
// for a set the engine was never asked to build.
//
// CmdWriteDiagJSON answers the same question by RE-RUNNING the whole set
// compilation. That is fine for a CLI flag and wrong for a caller in a hot
// loop, which is why this returns what the first compile already knew.
func CompileFileDiag(cfg config.BuildConfig, output string) ([]byte, int64, []SetDiag, error) {
	return compileFileDiag(cfg, output, CompileSetOptions{})
}

// compileFileDiag carries the optional per-set overrides. `over` is the zero
// value on every path but CompileFileOpts.
func compileFileDiag(cfg config.BuildConfig, output string, over CompileSetOptions) ([]byte, int64, []SetDiag, error) {
	return compileFileDiagReport(cfg, output, over, nil)
}

// compileFileDiagReport is compileFileDiag with an optional verbose Reporter.
// nil on every path but `regexped compile --verbose`.
func compileFileDiagReport(cfg config.BuildConfig, output string, over CompileSetOptions, rep *Reporter) ([]byte, int64, []SetDiag, error) {
	if err := config.ValidateSets(&cfg); err != nil {
		return nil, 0, nil, err
	}

	standalone := cfg.Output == ""

	// No sets: delegate to Compile so the output is byte-identical (including
	// per-pattern page alignment and final memory page count). Replicating
	// that logic here is bug-prone — earlier versions produced under-sized
	// memory for standalone modules whose DFA tables exceeded 64 KiB.
	if len(cfg.Sets) == 0 {
		w, top, err := Compile(cfg.Regexps, 0, standalone, CompileOptions{
			MaxDFAStates: cfg.MaxDFAStates,
			MaxTDFARegs:  cfg.MaxTDFARegs,
			Report:       rep,
		})
		return w, top, nil, err
	}

	tableBase := int64(0)

	// Compile per-pattern entries (existing path).
	var compiled []*compiledPattern
	var lastTableEnd int64
	opts := CompileOptions{
		MaxDFAStates: cfg.MaxDFAStates,
		MaxTDFARegs:  cfg.MaxTDFARegs,
		Report:       rep,
	}
	if !standalone {
		opts.tableMemIdx = 1
	}
	// One allocator for the whole module, shared by the per-pattern entries
	// below and by every set — the same rule compileAll follows.
	globals := &moduleGlobals{}
	opts.globals = globals
	for _, re := range cfg.Regexps {
		p, err := compilePattern(re, tableBase, 0, opts)
		if err != nil {
			return nil, 0, nil, err
		}
		// Batch find/groups export trigger — same
		// trigger compileAll applies; see compileAll's comment for the
		// eligibility rules. Only the per-pattern exports get a batch
		// wrapper here: a set's `find` already returns every match at one
		// position per call and needs no batch knob, so
		// assembleModuleWithSets does not add batch wrappers for
		// compiledSet functions.
		if hasBatchHint(re.Hints) {
			if p.findExport != "" {
				p.batchFindExport = p.findExport + "_batch"
			}
			if p.groupsExport != "" {
				p.batchGroupsExport = p.groupsExport + "_batch"
			}
		}
		tableBase = p.tableEnd
		compiled = append(compiled, p)
	}
	if len(compiled) > 0 {
		lastTableEnd = compiled[len(compiled)-1].tableEnd
	}

	// Resolve and compile sets.
	// Build name→index map.
	nameIdx := make(map[string]int, len(cfg.Regexps))
	for i, re := range cfg.Regexps {
		if re.Name != "" {
			nameIdx[re.Name] = i
		}
	}

	var prefixPool, suffixPool dfaPool
	var compiledSets []*compiledSet
	setTableBase := lastTableEnd // each set's tables start after all preceding data
	for _, sc := range cfg.Sets {
		// Resolve patterns.
		var selectedIdx []int
		if sc.Patterns.All {
			for i := range cfg.Regexps {
				selectedIdx = append(selectedIdx, i)
			}
		} else {
			for _, name := range sc.Patterns.Names {
				selectedIdx = append(selectedIdx, nameIdx[name])
			}
		}

		// Drop capture-bearing patterns; build PatternInfos.
		infos, globalIDs, err := setPatternInfos(sc, cfg, selectedIdx, &prefixPool, &suffixPool)
		if err != nil {
			return nil, 0, nil, err
		}

		spec := SetSpec{
			Name:                 sc.Name,
			MatchAny:             sc.MatchAny,
			MatchAll:             sc.MatchAll,
			ScanAny:              sc.ScanAny,
			ScanAll:              sc.ScanAll,
			Find:                 sc.Find,
			BatchFind:            sc.BatchFind(),
			DeclaredPatternCount: sc.PatternCount(cfg),
			Overlapping:          sc.Overlapping,
			IDSpaceSize:          sc.IDSpaceSize(cfg),
			Patterns:             infos,
			PatternIDs:           globalIDs,
		}
		setOpts := CompileSetOptions{
			// Set-level LikelyMode precedence: set hints > neutral.
			// Used by H.3 (frontend density gate).
			LikelyMode: resolveHints(sc.Hints),
			// The knob that decides whether a pattern survives into the set at
			// all: a fallback bucket over this limit is DROPPED, not demoted to
			// another engine. It was unreachable before — CompileSetOptions was
			// built without it, so the default 1024 always won and the drop
			// warning's own "raise max_dfa_states" hint pointed at a field that
			// does not feed this budget.
			MaxFallbackStates: cfg.MaxFallbackStates,
			// Test-only overrides (CompileFileOpts); zero everywhere else.
			ACBudgetBytes: over.ACBudgetBytes,
			// Test-only frontend pin; see CompileSetOptions.ForceFrontend.
			ForceFrontend: over.ForceFrontend,
			forceFrontend: over.forceFrontend,
			// Test-only Shufti density-switch pin; see
			// CompileSetOptions.ForceShuftiAdaptive.
			ForceShuftiAdaptive: over.ForceShuftiAdaptive,
			forceShuftiAdaptive: over.forceShuftiAdaptive,
		}
		if !standalone {
			setOpts.TableMemIdx = 1
		}
		setOpts.TableBase = int32(setTableBase)
		cs := CompileSet(spec, &prefixPool, &suffixPool, setOpts)
		compiledSets = append(compiledSets, cs)
		// Advance to where this set's tables ACTUALLY end. This used to
		// add up the encoded blob lengths, which is not
		// the extent of anything: the blobs carry per-segment headers, and
		// CompileSet places tables at explicit offsets with alignment gaps.
		// The sum ran short, which under-sized the module's memory whenever the
		// shortfall straddled a page boundary — and would have laid a second
		// set's tables on top of this one's.
		if top := cs.dataTop(); top > setTableBase {
			setTableBase = top
		}
	}

	// Compute required memory pages from the largest data address used.
	// setTableBase already holds the end of all set data (per-set accumulation above).
	dataTop := lastTableEnd
	if setTableBase > dataTop {
		dataTop = setTableBase
	}
	// One page minimum, and the clamp below the division is the only one
	// needed: memPages starts at 1 and the ceiling division of a positive
	// dataTop cannot produce less than 1, so the two arms that re-clamped it
	// afterwards were unreachable.
	var memPages int32 = 1
	if dataTop > 0 {
		if n := int32((dataTop + 65535) / 65536); n > 1 {
			memPages = n
		}
	}
	diags := make([]SetDiag, 0, len(compiledSets))
	for _, cs := range compiledSets {
		if cs.diag != nil {
			diags = append(diags, *cs.diag)
		}
	}
	// dataTop, not lastTableEnd. The second return value is "where is it safe
	// to put input", and lastTableEnd covers only the PER-PATTERN tables — a
	// caller trusting it on a set-bearing module wrote its input over the
	// first set's tables. tools/perftest already worked around this by
	// re-parsing the data section; nothing else did.
	return assembleModuleWithSets(compiled, compiledSets, memPages, standalone, globals), dataTop, diags, nil
}

// assembleModuleWithSets builds a WASM module from per-pattern compilations
// plus per-set compiled sets. When sets is empty it produces the same bytes
// as assembleModule.
func assembleModuleWithSets(patterns []*compiledPattern, sets []*compiledSet, memPages int32, standalone bool, globals *moduleGlobals) []byte {
	if globals == nil {
		globals = &moduleGlobals{}
	}
	if len(sets) == 0 {
		return assembleModule(patterns, memPages, standalone, globals)
	}

	// Reuse assembleModule for the base (patterns only), then we'll handle sets separately.
	// For a clean implementation, build the module from scratch.

	// Pre-collect data.
	totalSegs := 0
	var rawData []byte
	for _, p := range patterns {
		totalSegs += p.dataSegCount
		rawData = append(rawData, p.dataBytes...)
	}
	for _, cs := range sets {
		// ONE authority for what a set contributes, shared with dataTop — see
		// dataBlobs.
		for _, blob := range cs.dataBlobs() {
			totalSegs += blob.segs
			rawData = append(rawData, blob.bytes...)
		}
	}

	// Assign function indices.
	baseIdx := make([]int, len(patterns))
	total := 0
	for i, p := range patterns {
		baseIdx[i] = total
		total += p.funcCount()
	}

	// Set suffix DFA functions + match functions.
	// Each set contributes: 1 match fn + N suffix fns.
	setBaseIdx := make([]int, len(sets))
	for si, cs := range sets {
		setBaseIdx[si] = total
		total += cs.funcCount()
	}

	// Count suffix functions and compute their global function indices.
	totalSuffixFns := 0
	suffixFnBase := make([]int, len(sets))
	for si, cs := range sets {
		suffixFnBase[si] = setBaseIdx[si] + cs.suffixFnBaseOffset()
		totalSuffixFns += cs.numSuffixFns
	}

	// Compute prefix function global indices (placed after suffix fns within each set).
	prefixFnBase := make([]int, len(sets))
	for si, cs := range sets {
		prefixFnBase[si] = setBaseIdx[si] + cs.prefixFnBaseOffset()
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// Type section. Index 4 is emitted but referenced by NOTHING: it is a
	// duplicate of type 0 kept only so the indices below do not renumber, and
	// removing it would move every constant in the setType* block. Its comment
	// used to describe it as the prefix backward DFA, which reads as a live
	// slot.
	// Type section: 11 types.
	// 0: (i32,i32)→i32          match/backward-prefix
	// 1: (i32,i32)→i64          find
	// 2: (i32,i32,i32)→i32      capture/groups
	// 3: (i32×7)→i32            suffix DFA (ptr,start,len,lPos,out_ptr,out_cap,validMask)→count
	// 4: (i32,i32)→i32          prefix backward DFA (same as 0, kept for clarity)
	// 5: (i32×5)→i32            per-pattern batch wrappers; the DP sweep
	// 6: (i32×4)→i32            bucket probe / bitmap-form _all
	// 7: (i32×3)→i64            scan_any, scan_all (<= 64 patterns)
	// 8: (i32×6)→i32            set find body, gated (default)
	// 9: (i32×8)→i32            suffix DFA with a gate pointer; also the
	//                            ungated suffix DFA carrying the batch `skip`
	// 10: (i32,i32,i64,i32,i32,i32,i32,i32)→i64  find_batch, BOTH overlap
	//                                             policies (one signature
	//                                             policies)
	typeSection := []byte{
		0x0B,
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E, // type 1
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 2
		0x60, 0x07, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 3
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 4
		0x60, 0x05, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 5
		0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 6
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7E, // type 7
		0x60, 0x06, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 8
		0x60, 0x08, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 9
		0x60, 0x08, 0x7F, 0x7F, 0x7E, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7E, // type 10
	}
	out = appendSection(out, 1, typeSection)

	// Import section.
	if !standalone {
		var importSec []byte
		importSec = utils.AppendULEB128(importSec, 1)
		importSec = appendString(importSec, "main")
		importSec = appendString(importSec, "memory")
		importSec = append(importSec, 0x02, 0x00, 0x00)
		out = appendSection(out, 2, importSec)
	}

	// Function section: patterns + set functions.
	// Walks the SAME funcLayout the single-pattern assembler does; only the
	// TYPE INDICES differ, because this module has its own type table. That
	// remapping is the hazard this indirection exists for — the alt-lit-anchor
	// arm was once missing here entirely — and reading the layout from one place
	// leaves exactly this table to get right.
	setSlotType := map[funcSlotKind]byte{
		slotMatch:             setTypeI32I32ToI32, // (i32,i32)→i32
		slotAltBackScan:       setTypeI32I32ToI32,
		slotAltForwardVerify:  setTypeI32x3ToI64, // (i32,i32,i32)→i64 — 7 here, 3 there
		slotAltDispatch:       setTypeI32I32ToI64,
		slotLitAnchorBackScan: setTypeI32I32ToI32,
		slotLitAnchorFind:     setTypeI32I32ToI64,
		slotFind:              setTypeI32I32ToI64,
		slotCapture:           setTypeI32x3ToI32, // (i32,i32,i32)→i32
		slotGroupsWrapper:     setTypeI32x3ToI32,
		// The LM-2 batch wrappers share the set match body's
		// (i32×5)→i32 shape rather than needing a type of their own.
		slotBatchFind:         setMatchTypeMatch,
		slotBatchGroups:       setMatchTypeMatch,
		slotFindWrapper:       setTypeI32x3ToI64, // 7 here, 3 there
		slotGroupsFromWrapper: setTypeI32x4ToI32, // (i32×4)→i32
	}
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(total))
	for _, p := range patterns {
		for _, slot := range p.funcLayout() {
			t, ok := setSlotType[slot.kind]
			if !ok {
				panic("compile: no set-module type index for function slot kind")
			}
			fs = append(fs, t)
		}
	}
	for _, cs := range sets {
		for _, c := range cs.capFns() {
			fs = append(fs, c.typeIdx)
		}
		// The hidden per-position batch worker. Gated it is `find`'s own
		// signature; ungated it is that signature plus the batch `skip` — which
		// is the same arity, so both are type 8.
		if cs.batchFind {
			fs = append(fs, byte(cs.workerTypeIdx()))
		}
		// The split's hidden phase bodies take and return exactly what the
		// capability they serve does, so they reuse its type.
		for _, kind := range cs.twoPhaseCaps() {
			t := byte(setTypeI32x3ToI32)
			if kind == capScanAll {
				// The wide form takes the caller's bitmap and returns a count,
				// so both phases carry the out_ptr the wrapper threads through.
				t = setTypeI32x3ToI64
				if cs.wideAll() {
					t = setTypeI32x4ToI32
				}
			}
			fs = append(fs, t, t)
		}
		// The backward sweep: (ptr, len, from, scratch_ptr, scratch_len) -> i32.
		if cs.usesOverlapDP() {
			fs = append(fs, byte(setTypeI32x5ToI32))
		}
		suffixType := byte(setMatchTypeSuffix)
		if cs.gatedFind() || cs.suffixHasSkip {
			suffixType = setTypeSuffixGated
		}
		for range cs.suffixFnBodies {
			fs = append(fs, suffixType)
		}
		for range cs.prefixFnBodies {
			fs = append(fs, byte(setTypeI32I32ToI32)) // backward-prefix fn
		}
		for range cs.scanProbeBodies {
			fs = append(fs, byte(setTypeI32x4ToI32))
		}
		for range cs.scanProbeAnyBodies {
			fs = append(fs, byte(setTypeI32x4ToI32))
		}
		for range cs.anchoredProbeBodies {
			fs = append(fs, byte(setTypeI32x4ToI32))
		}
		for i := 0; i < cs.numBTFns; i++ {
			// (ptr, len, out_ptr) -> i32, the capture-body shape.
			fs = append(fs, byte(setTypeI32x3ToI32))
		}
	}
	out = appendSection(out, 3, fs)

	// No function table needed: suffix DFAs are called via direct call, not call_indirect.
	// This avoids multi-table conflicts when merging with host modules (e.g. Go WASM).

	// Memory section.
	{
		var mem []byte
		mem = append(mem, 0x01, 0x00)
		mem = utils.AppendULEB128(mem, uint32(memPages))
		out = appendSection(out, 5, mem)
	}

	// Global section: the find-from channel (see find_from.go), on the same
	// terms as the single-pattern assembler. Set capabilities take their own
	// `from` as a real parameter and do not use it.
	if moduleUsesFindFrom(patterns) || globals.Count() > 1 {
		out = appendSection(out, 6, globals.Section())
	}

	// Export section.
	numExports := 0
	if standalone {
		numExports++
	}
	for _, p := range patterns {
		// The conditions here MUST be character-for-character the ones the
		// emission loop below uses: a count larger than the number of entries
		// written produces a malformed module with no diagnostic, and the two
		// assemblers have drifted before.
		matchOff, _, findOff, _, _ := p.offsets()
		batchFindOff, batchGroupsOff := p.batchOffsets()
		if p.matchExport != "" && matchOff >= 0 {
			numExports++
		}
		if p.findExport != "" && findOff >= 0 {
			numExports++
		}
		if p.hasGroupsFromWrapper() {
			numExports++
		}
		if p.batchFindExport != "" && batchFindOff >= 0 {
			numExports++
		}
		if p.batchGroupsExport != "" && batchGroupsOff >= 0 {
			numExports++
		}
	}
	for _, cs := range sets {
		numExports += len(cs.capFns())
	}

	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02, 0x00)
	}
	for i, p := range patterns {
		base := baseIdx[i]
		matchOff, _, findOff, _, _ := p.offsets()
		if p.matchExport != "" && matchOff >= 0 {
			es = appendString(es, p.matchExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+matchOff))
		}
		if p.findExport != "" && findOff >= 0 {
			// The (ptr, len, from) wrapper, not the body — see find_from.go.
			es = appendString(es, p.findExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+p.findWrapperOffset()))
		}
		gFromOff := p.groupsFromWrapperOffsets()
		if p.hasGroupsFromWrapper() {
			// The (ptr, len, out_ptr, from) wrapper — see find_from.go.
			es = appendString(es, p.groupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+gFromOff))
		}
		batchFindOff, batchGroupsOff := p.batchOffsets()
		if p.batchFindExport != "" && batchFindOff >= 0 {
			es = appendString(es, p.batchFindExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+batchFindOff))
		}
		if p.batchGroupsExport != "" && batchGroupsOff >= 0 {
			es = appendString(es, p.batchGroupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+batchGroupsOff))
		}
	}
	for si, cs := range sets {
		base := setBaseIdx[si]
		for i, c := range cs.capFns() {
			es = appendString(es, c.name)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+i))
		}
	}
	out = appendSection(out, 7, es)

	// Code section.
	var cs_bytes []byte
	cs_bytes = utils.AppendULEB128(cs_bytes, uint32(total))
	for i, p := range patterns {
		base := baseIdx[i]
		_, backwardScanOff, findOff, captureOff, wrapperOff := p.offsets()
		if p.matchBody != nil {
			cs_bytes = append(cs_bytes, p.matchBody...)
		}
		if p.altLitAnchorBranches != nil {
			for _, br := range p.altLitAnchorBranches {
				cs_bytes = append(cs_bytes, br.backScanBody...)
				cs_bytes = append(cs_bytes, br.forwardVerifyBody...)
			}
			// Generate the dispatcher body now that function indices are known.
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			branchFuncIdxs := make([]altLitAnchorFuncIdx, len(p.altLitAnchorBranches))
			for j := range p.altLitAnchorBranches {
				backOff, fwdOff := p.altLitAnchorBranchFuncIdx(j)
				branchFuncIdxs[j] = altLitAnchorFuncIdx{backScan: base + backOff, forwardVerify: base + fwdOff}
			}
			altDispatchBody, altDispatchMode := buildAltLitAnchorFindBody(p, branchFuncIdxs, tableMemIdx)
			p.findFromMode = altDispatchMode
			cs_bytes = utils.AppendULEB128(cs_bytes, uint32(len(altDispatchBody)))
			cs_bytes = append(cs_bytes, altDispatchBody...)
		} else if p.litAnchorBackScanBody != nil {
			cs_bytes = append(cs_bytes, p.litAnchorBackScanBody...)
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			litAnchorFindBody, litAnchorMode := buildLitAnchorFindBody(p.litAnchorFindTable, p.litAnchorFindLayout, p, base+backwardScanOff, tableMemIdx)
			p.findFromMode = litAnchorMode
			cs_bytes = utils.AppendULEB128(cs_bytes, uint32(len(litAnchorFindBody)))
			cs_bytes = append(cs_bytes, litAnchorFindBody...)
		} else if p.findBody != nil {
			cs_bytes = append(cs_bytes, p.findBody...)
		}
		if p.captureBody != nil {
			cs_bytes = append(cs_bytes, p.captureBody...)
			if !p.anchored {
				wrapperTableMemIdx := 0
				if !standalone {
					wrapperTableMemIdx = 1
				}
				winOff := int32(-1)
				if !p.isTDFA {
					winOff = p.winScratchOff
				}
				cs_bytes = appendWrapperCodeEntry(cs_bytes, base+findOff, base+captureOff, p.numGroups, wrapperTableMemIdx, winOff)
			}
		}
		if p.batchFindExport != "" {
			cs_bytes = appendBatchFindWrapperCodeEntry(cs_bytes, base+findOff, p.findFromMode)
		}
		if p.batchGroupsExport != "" {
			if p.anchored {
				cs_bytes = appendBatchLitChainGroupsWrapperCodeEntry(cs_bytes, base+captureOff, p.numGroups, p.captureFromMode)
			} else {
				batchTableMemIdx := 0
				if !standalone {
					batchTableMemIdx = 1
				}
				winOff := int32(-1)
				if !p.isTDFA {
					winOff = p.winScratchOff
				}
				cs_bytes = appendBatchGroupsWrapperCodeEntry(cs_bytes, base+findOff, base+captureOff, p.numGroups, batchTableMemIdx, winOff, p.findFromMode)
			}
		}
		if p.hasFindFunc() {
			if p.findFromMode == ffUnset {
				panic("compile: pattern contributes a find function but no findFromMode was recorded — " +
					"a find emitter bypassed setFind (see find_from.go)")
			}
			cs_bytes = appendFindFromWrapperCodeEntry(cs_bytes, base+findOff, p.findFromMode)
		}
		if p.hasGroupsFromWrapper() {
			inner, anchoredOnly := base+wrapperOff, false
			if p.anchored {
				// See assembleModule's twin: anchored means "captureBody is
				// the export", not "matches only at 0".
				inner = base + captureOff
				anchoredOnly = p.captureFromMode == ffAnchoredZeroOnly
			}
			assertGroupsFromWrapperMode(p, anchoredOnly)
			cs_bytes = appendGroupsFromWrapperCodeEntry(cs_bytes, inner, anchoredOnly)
		}
	}
	// Set function bodies: find fn (if any), anchored match fn (if any), suffix DFA fns, prefix DFA fns.
	tableMemIdx := 0
	if !standalone {
		tableMemIdx = 1
	}
	for si, cs := range sets {
		base := setBaseIdx[si]
		scanProbeBase := base + cs.scanProbeBaseOffset()
		anchoredProbeBase := base + cs.anchoredProbeBaseOffset()
		for _, c := range cs.capFns() {
			switch c.kind {
			case capFind:
				if cs.batchFind {
					// Decision (11a): the export forwards into the shared
					// worker instead of carrying its own copy of the bucket
					// code.
					cs_bytes = append(cs_bytes, emitSetFindWrapperBody(cs, base+cs.batchPosFnOffset())...)
				} else {
					cs_bytes = append(cs_bytes, rebuildSetMatchBody(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx)...)
				}
			case capFindBatch:
				dpIdx := -1
				if off := cs.overlapDPFnOffset(); off >= 0 {
					dpIdx = base + off
				}
				cs_bytes = append(cs_bytes, emitSetFindBatchBody(cs, base+cs.batchPosFnOffset(), dpIdx)...)
			case capMatchAny, capMatchAll:
				if cs.anchoredUnion != nil {
					cs_bytes = append(cs_bytes,
						emitAnchoredUnionBody(cs.anchoredUnion, c.kind, cs.wideAll(), tableMemIdx)...)
					break
				}
				cs_bytes = append(cs_bytes, emitSetAnchoredCapBody(cs, c.kind, anchoredProbeBase)...)
			default:
				var body []byte
				if cs.usesTwoPhaseScan(c.kind) {
					// The exported body is a wrapper; the work is in the two
					// hidden phase bodies emitted below.
					body = emitTwoPhaseScanBody(cs, c.kind, base+cs.twoPhaseFnOffset(c.kind))
				} else if cs.usesUnionScan(c.kind) {
					// One pass over the start-anywhere automaton instead of
					// the per-position bucket walk. Which body depends on the
					// automaton's accept representation, not on the
					// capability: above 64 ids there is no u64 accumulator to
					// answer with.
					if cs.unionScan.isWide() {
						body = emitUnionScanWideBody(cs.unionScan, c.kind, tableMemIdx, cs.unionSkipLNM)
					} else {
						body = emitUnionScanBody(cs.unionScan, c.kind, cs.fullIDMask(), tableMemIdx, cs.unionSkipLNM)
					}
				} else {
					// `scan` / `scan_any` may stop at the first bit and get
					// the first-hit probes; `scan_all` needs every bit at the
					// position and keeps the mask-complete ones.
					body = emitSetMatchFnFinal(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx, c.kind, scanProbeBase)
				}
				cs_bytes = append(cs_bytes, body...)
			}
		}
		if cs.batchFind {
			cs_bytes = append(cs_bytes, emitSetWorkerBody(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx)...)
		}
		// The split's hidden bodies, in twoPhaseCaps order so they line up
		// with twoPhaseFnOffset. Phase 1 is the ordinary frontend emitter
		// run against the phase-1 VIEW of the set; phase 2 is the union walk
		// over the fallback patterns.
		for _, kind := range cs.twoPhaseCaps() {
			cs.phase1Only = true
			p1 := emitSetMatchFnFinal(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx, kind, scanProbeBase)
			cs.phase1Only = false
			cs_bytes = append(cs_bytes, p1...)
			if cs.phase2Union.isWide() {
				cs_bytes = append(cs_bytes, emitUnionScanWideBody(cs.phase2Union, kind, tableMemIdx, cs.unionSkipLNM)...)
			} else {
				cs_bytes = append(cs_bytes, emitUnionScanBody(cs.phase2Union, kind, cs.phase2Mask(), tableMemIdx, cs.unionSkipLNM)...)
			}
		}
		if cs.usesOverlapDP() {
			cs_bytes = append(cs_bytes, emitOverlapDPBody(cs, tableMemIdx, cs.overlapDPColOff)...)
		}
		// A Backtracking fallback bucket's suffix body CALLS its driver, so it
		// can only be built here, where function indices exist. Everything
		// else about it is decided in CompileSet; this fills the slot the
		// suffix pass deliberately left empty.
		btBodies := cs.buildBTBodies(base+cs.btFnBaseOffset(), tableMemIdx)
		for bi, sfn := range cs.suffixFnBodies {
			if repl, ok := btBodies[bi]; ok {
				sfn = repl
			}
			cs_bytes = append(cs_bytes, sfn...)
		}
		for _, pfn := range cs.prefixFnBodies {
			cs_bytes = append(cs_bytes, pfn...)
		}
		for _, pb := range cs.scanProbeBodies {
			cs_bytes = append(cs_bytes, pb...)
		}
		for _, pb := range cs.scanProbeAnyBodies {
			cs_bytes = append(cs_bytes, pb...)
		}
		for _, pb := range cs.anchoredProbeBodies {
			cs_bytes = append(cs_bytes, pb...)
		}
		// Backtracking drivers last, matching btFnBaseOffset.
		for _, bb := range cs.btFnBodies {
			cs_bytes = append(cs_bytes, bb...)
		}
	}
	out = appendSection(out, 10, cs_bytes)

	// Data section.
	if totalSegs > 0 {
		var ds []byte
		if !standalone {
			segs := parseDataSegments(rawData)
			ds = utils.AppendULEB128(ds, uint32(len(segs)))
			for _, seg := range segs {
				ds = appendDataSegmentMem1(ds, seg.offset, seg.data)
			}
		} else {
			ds = utils.AppendULEB128(ds, uint32(totalSegs))
			ds = append(ds, rawData...)
		}
		out = appendSection(out, 11, ds)
	}

	return out
}

// rebuildSetMatchBody re-emits the set match function with correct function indices.
func rebuildSetMatchBody(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	return emitSetMatchFnFinal(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, capFind, 0)
}

// emitSetMatchFnFinal dispatches to the appropriate scan implementation based on the
// frontend strategy chosen during compilation.
//
// mode selects what is recorded at a matching position: capFind writes tuples,
// the scan trio records a bitmask (see setFindCtx.mode). The frontend choice is
// shared, which is the whole point — routing the scan trio through the scalar
// body cost 17x the fuel on a literal-frontend set.
func emitSetMatchFnFinal(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int, mode setCapKind, probeFnBase int) []byte {
	switch cs.fe {
	case frontendAC:
		return emitSetMatchFnFinalAC(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, mode, probeFnBase)
	case frontendTeddy:
		if !hasSetFallbackBuckets(cs) {
			return emitSetMatchFnFinalTeddy(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, mode, probeFnBase)
		}
	case frontendShufti:
		// Selection guarantees no fallback buckets — see set_emit.go gap H.3 block.
		if !hasSetFallbackBuckets(cs) {
			return emitSetMatchFnFinalShufti(cs, suffixFnBase, prefixFnBaseIdx, mode, probeFnBase)
		}
	case frontendPackedPair:
		// Same fallback-bucket rule as Teddy: a fallback pattern must be tried
		// at every position, so a prefilter that skips positions cannot serve
		// it. cs.packedPair is nil only if selection and build disagreed;
		// falling through to scalar is the safe answer if they ever do.
		if !hasSetFallbackBuckets(cs) && cs.packedPair != nil {
			return emitSetMatchFnFinalPackedPair(cs, suffixFnBase, prefixFnBaseIdx, mode, probeFnBase)
		}
	}
	return emitSetMatchFnFinalScalar(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx, mode, probeFnBase)
}

// hasSetFallbackBuckets reports whether the body being emitted must visit
// every position for a fallback bucket.
//
// It answers for the VIEW being emitted, not for the set: under phase1Only the
// fallback buckets belong to phase 2 and are not this body's problem, so the
// prefilters that a fallback bucket would otherwise disable stay on. That is
// the entire mechanism of the two-phase split — the skip is not made safe, the
// work that made it unsafe is moved to a pass of its own.
func hasSetFallbackBuckets(cs *compiledSet) bool {
	if cs.phase1Only {
		return false
	}
	return hasSetFallbackBucketsIn(cs.buckets)
}

// overlapCanPreflight is usesOverlappingFindPreflight's structural half,
// answered from the raw spec and bucket list — early enough to decide whether
// the per-bucket liveness table is worth emitting.
//
// It must refuse everything the real predicate refuses, or a set gets the
// table and the per-byte check with no preflight to make either fire, which
// is the reverted Candidate A: cost on every byte, no exit ever taken.
// The never-dying and boundary tests are applied by the caller, which is
// already walking the buckets for them.
// It must be a SUPERSET of compiledSet.overlapPreflightShape
// (set_union_scan.go), which asks the same question later, from the finished
// compiledSet, to decide whether the union TABLES must be built. If this one
// admits a set the other refuses, the preflight is emitted with no table to
// read. TestOverlapPreflightPredicatesAgree pins the containment.
func overlapCanPreflight(spec SetSpec, buckets []*bucket) bool {
	if spec.Find == "" || !spec.Overlapping {
		return false
	}
	maxID := -1
	for _, bkt := range buckets {
		if bkt.sparse {
			return false
		}
		for _, p := range bkt.patterns {
			if p.globalID > maxID {
				maxID = p.globalID
			}
		}
	}
	if spec.IDSpaceSize > maxID+1 {
		maxID = spec.IDSpaceSize - 1
	}
	return maxID+1 <= 64
}

// hasSetFallbackBucketsIn is the same question about a raw bucket list, for
// use during compilation before a compiledSet exists.
func hasSetFallbackBucketsIn(buckets []*bucket) bool {
	for _, bkt := range buckets {
		if bkt.isFallback {
			return true
		}
	}
	return false
}

// emitSetMatchFnFinalScalar emits the scalar (byte-by-byte) set `find` body.
//
// Signature: (ptr, len, from, out_ptr, out_cap) -> i32,
// returning the TOTAL number of matches at the first matching position at or
// after `from`. See compile/set_find.go for the first-position machinery.
func emitSetMatchFnFinalScalar(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int, mode setCapKind, probeFnBase int) []byte {
	// G8's `scan_any` preflight is GONE. It ran
	// the start-anywhere union automaton once over [from,len) and used the
	// result to drop never-matching patterns from every bucket's validMask —
	// a way to make the per-position walk cheaper for a capability that could
	// not use the union walk directly, because it had to report a START.
	// With the start dropped, `scan_any` IS the union walk (usesUnionScan),
	// so this body is never reached with mode == capScanAny on a set that
	// qualified, and the narrowing has nothing left to narrow.
	// G9: the gated `find` body runs the same union pass once per
	// drive and writes its result back as gate sentinels. Still live —
	// `find` reports positions and cannot become a union walk.
	// Item 11: the OVERLAPPING body runs the same pass, keeping its verdict
	// in the gate array the caller now supplies for exactly this purpose.
	// Without it that body walks a never-dying suffix DFA from every start
	// position and one call is O(n^2).
	overlapPreflight := mode == capFind && cs.usesOverlappingFindPreflight()
	findPreflight := mode == capFind && cs.usesGatedFindPreflight() || overlapPreflight

	// G12: the absence prefilter needs one more i32 (its SIMD mask) and a
	// v128 chunk; the union walk needs neither.
	absence := findPreflight && cs.usesAbsencePrefilter()

	// One further i32 in every arm, LAST in the i32 block: lAllElig, the
	// per-call "every pattern is eligible from here on" bound (item 22 fix
	// 2b). Declared only in this body — see setFindCtx.lAllElig for why the
	// literal-frontend bodies do not get it.
	// A preflight arm carries ONE more i32 still: lEnd, the union walk's
	// `pInPtr + len` bound. It exists because that walk's cursor is an
	// absolute input pointer rather than an offset (see emitUnionTransition),
	// which is what takes three instructions per byte down to one.

	// The alive mask is one i64 per 64 ids (item 22 fix 2a-wide), so the i64
	// group grows with the set's id space. Every other local keeps its index:
	// the extra words are appended AFTER the mask's first word, which is the
	// last local of the narrow preflight arm.
	aliveWords := 1
	if findPreflight {
		aliveWords = cs.preflightAliveWords()
	}
	// F2: one i32 per global id, holding the call-invariant gate value. The
	// count is decided here so the local declaration and the base index below
	// cannot disagree; 0 means the body keeps reading the caller's array.
	gateLocals := 0
	{
		// The trailing locals already declared, in the widest arm, so the
		// 256-index bound is checked against the real frame.
		frame := 17
		if gateLocalsProfitable(cs, cs.gatedFind() && mode == capFind, frame) {
			gateLocals = cs.idSpaceSize()
		}
	}

	var b []byte
	// lFirstByte is E5's hoisted input[lPos], declared in a TRAILING group so
	// every index below it keeps its value — the arms name the i64s and the
	// v128 explicitly, and inserting into an earlier group would move them.
	var lFirstByte byte
	if absence {
		// 13 i32 (pos, search mask, simd mask, allElig, end), 2 i64 (acc, alive), 1 v128,
		// then lFirstByte and the absence drain's candidate position.
		// Always one alive word: the absence prefilter is capped at 64 ids.
		b = append(b, 0x04+gateGroups(gateLocals), 0x0D, 0x7F, 0x02, 0x7E, 0x01, 0x7B, 0x02, 0x7F)
		b = appendGateLocalGroup(b, gateLocals)
	} else if findPreflight {
		// 8 i32 + the union walk's state/pos + allElig + end, then i64 acc + the
		// alive mask's words, then lFirstByte.
		b = append(b, 0x03+gateGroups(gateLocals), 0x0C, 0x7F)
		b = utils.AppendULEB128(b, uint32(1+aliveWords))
		b = append(b, 0x7E)
		b = append(b, 0x01, 0x7F)
		b = appendGateLocalGroup(b, gateLocals)
	} else {
		// locals: 9 x i32, then the scan_all i64 accumulator, then lFirstByte.
		b = append(b, 0x03+gateGroups(gateLocals), 0x09, 0x7F, 0x01, 0x7E, 0x01, 0x7F)
		b = appendGateLocalGroup(b, gateLocals)
	}

	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	c.tableMemIdx = tableMemIdx
	c.perPositionDrain = true
	// lAllElig is the last i32 of each arm; the i64s follow it, so both move
	// up by one against the pre-2b layout.
	c.lAllElig = c.localBase + 8
	c.lAcc = c.localBase + 9
	lFirstByte = c.localBase + 10
	lPos := c.lPos
	pInLen := c.pInLen
	lEnd := byte(0)
	if absence {
		c.lAllElig = c.localBase + 11
		lEnd = c.localBase + 12
		c.lAcc = c.localBase + 13
		c.aliveMask = c.localBase + 14
		lFirstByte = c.localBase + 16 // past the v128 chunk at +15
	} else if findPreflight {
		c.lAllElig = c.localBase + 10
		lEnd = c.localBase + 11
		c.lAcc = c.localBase + 12
		c.aliveMask = c.localBase + 13
		lFirstByte = byte(int(c.localBase) + 13 + aliveWords)
	}

	if gateLocals > 0 {
		// The gate block is the LAST group of every arm, so its base is one
		// past that arm's last local. lFirstByte is the last non-gate local in
		// the plain and preflight arms; lCand is in the absence arm.
		if absence {
			c.gateLocalBase = c.localBase + 18
		} else {
			c.gateLocalBase = lFirstByte + 1
		}
	}

	if findPreflight {
		// Before the prologue: emitGateJump reads the gate array, so the
		// sentinels must already be in place for it to skip ahead correctly.
		// One emitter serves both bodies — see emitFindPreflight's header for
		// why the gated and overlapping forms converged (item 22 fix 2a).
		// The v128 chunk is the last local of the absence arm, so it moves up
		// with the i64s when lAllElig is inserted ahead of them.
		lChunk := byte(c.localBase + 15)
		// The absence drain's candidate position is the LAST local of the
		// absence arm, one past lFirstByte.
		lCand := byte(c.localBase + 17)
		b = emitFindPreflight(b, cs, c.localBase+8, c.localBase+9, c.aliveMask,
			c.pGate, c.pInLen, c.pFrom, lEnd, tableMemIdx, absence, c.localBase+10, lChunk, lCand)
	}
	// AFTER the preflight, which WRITES gate sentinels into the caller's
	// array: locals captured before it hold the pre-preflight values, and the
	// per-candidate pre-mask then clears nothing the preflight had retired.
	// Safe (a gate value is a lower bound, so a stale one only
	// over-approximates eligibility) but measured at +93% fuel on greedy-3's
	// no-match `find` — which is exactly what G10's preflight exists to avoid.
	b = c.emitGateLocalsPrologue(b)
	b = c.emitFindPrologue(b, lPos)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $scan

	// lPos > pInLen: allows position 0 to be processed on empty input (pInLen=0),
	// so patterns like (aa)* that match "" get their zero-length match at position 0.
	// Position pInLen is processed once (for EOF-anchored patterns like (aa)*$);
	// buildSetSuffixBody's eofBitmaskOff table (paired with newDFA's bootstrap-alias
	// guard giving midStart its own correct accept bits) avoids false positives.
	// An out-of-range `from` (> len) lands here on the first iteration and returns
	// 0, which is the documented offset-past-end contract.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen (i32.gt_u)
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Fallback buckets first: they have no literal gate, so they must be
	// evaluated at every position. Skipped entirely under phase1Only, where
	// they are phase 2's pass instead.
	if !cs.phase1Only {
		for bi, bkt := range cs.buckets {
			if !bkt.isFallback {
				continue
			}
			b = c.emitBucketAt(b, bi, 0, lPos)
		}
	}

	// The position's first byte is loaded once for the whole bucket chain: an
	// AC-demoted scalar set can carry dozens to hundreds of buckets, and every
	// one of them opened by reading the same byte again.
	b = c.emitLiteralBucketsHoisted(b, lPos, lFirstByte)

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $scan
	b = append(b, 0x0B) // end block $done

	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitSetMatchFnFinalShufti emits the set match function body using a SIMD
// Shufti first-byte pre-filter. The per-position bucket
// check is identical to the scalar path — the only addition is a 16-bytes-
// per-chunk SIMD skip loop at the top of each iteration that advances lPos
// to the next position where any literal's first byte appears.
//
// Selection in CompileSet guarantees:
//   - no fallback buckets (otherwise we'd need to visit every position),
//   - 17 ≤ |shuftiFirstByteSet| ≤ 64 (matches emitShuftiPrefixCheck's bounds),
//   - rarity-based density supports Shufti OR set-level LikelyNoMatch is set.
//
// When cs.shuftiAdaptive (ported from EmitPrefixScan's own
// DenseCounter/DenseSkipFlag switch): adds a runtime density counter that
// disables the SIMD probe for the rest of the call once `denseSwitchThreshold`
// consecutive "attempts" (one $scan iteration each) found a candidate in the
// very first chunk probed, i.e. gained no real 16-byte skip. Non-adaptive
// sets (rarity-based Shufti selection, no LikelyNoMatch override) emit
// byte-identical code to before this existed — the extra locals and gating
// only appear when shuftiAdaptive is true.
func emitSetMatchFnFinalShufti(cs *compiledSet, suffixFnBase, prefixFnBaseIdx int, mode setCapKind, probeFnBase int) []byte {
	var b []byte
	adaptive := cs.shuftiAdaptive
	// locals: 6 × i32 (lPos, lTotal, lTmp, lValidMask, lOutBase, lSkipMask), 1 × v128 (lChunk),
	// + 2 × i32 (lDenseCounter, lDenseSkipFlag) when adaptive,
	// + 3 × i32 (lMinStart, lBase, lStart) for the first-position state.
	// The per-position first byte is declared in a TRAILING group so that
	// every index above it is untouched: WASM assigns local indices in
	// declaration order, and inserting into an earlier group would move the
	// v128 and i64 the arms below name explicitly.
	if adaptive {
		b = append(b, 0x06)       // 6 local groups
		b = append(b, 0x06, 0x7F) // 6 × i32
		b = append(b, 0x01, 0x7B) // 1 × v128
		b = append(b, 0x02, 0x7F) // 2 × i32
		b = append(b, 0x03, 0x7F) // 3 × i32
		b = append(b, 0x01, 0x7E) // 1 × i64 (scan_all accumulator)
		b = append(b, 0x01, 0x7F) // 1 × i32 (hoisted first byte)
	} else {
		b = append(b, 0x05)       // 5 local groups
		b = append(b, 0x06, 0x7F) // 6 × i32
		b = append(b, 0x01, 0x7B) // 1 × v128
		b = append(b, 0x03, 0x7F) // 3 × i32
		b = append(b, 0x01, 0x7E) // 1 × i64 (scan_all accumulator)
		b = append(b, 0x01, 0x7F) // 1 × i32 (hoisted first byte)
	}

	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	c.perPositionDrain = true
	lPos, lTmp := c.lPos, c.lTmp
	pInPtr, pInLen := c.pInPtr, c.pInLen
	lSkipMask := c.localBase + 5
	lChunk := c.localBase + 6
	lDenseCounter := c.localBase + 7
	lDenseSkipFlag := c.localBase + 8
	// The first-position locals go last so the v128 index is stable.
	c.lMinStart, c.lBase, c.lStart = c.localBase+7, c.localBase+8, c.localBase+9
	c.lAcc = c.localBase + 10
	lFirstByte := c.localBase + 11
	if adaptive {
		c.lMinStart, c.lBase, c.lStart = c.localBase+9, c.localBase+10, c.localBase+11
		c.lAcc = c.localBase + 12
		lFirstByte = c.localBase + 13
	}

	b = c.emitFindPrologue(b, lPos)
	if adaptive {
		b = append(b, 0x41, 0x00, 0x21, lDenseCounter) // DenseCounter = 0
	}

	// Branch depths come from st, not from counted literals — see
	// compile/blockstack.go. This body is the reason that matters: the
	// adaptive $dense_gate adds a level on some paths and not others, so every
	// depth below used to be written twice, once per arm of `if adaptive`.
	st := &blockStack{}
	b = append(b, 0x02, 0x40) // block $batch_done
	st.Push("batch_done")
	b = append(b, 0x03, 0x40) // loop $scan
	st.Push("scan")

	// Exit conditions.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, st.Depth("batch_done")) // lPos > pInLen
	b = c.emitDrainCheck(b, lPos, 0x01)

	if adaptive {
		// Reset once per attempt (one $scan iteration = one search for the
		// next candidate position), NOT per $skip_loop retry — mirrors
		// EmitPrefixScan's reset site, which sits outside its retry loop
		// for the same reason.
		b = append(b, 0x41, 0x00, 0x21, lDenseSkipFlag)
	}

	// --- SIMD pre-filter: advance lPos to the next candidate position ---
	// Block depths inside the prefilter (non-adaptive):
	//   loop $scan (0), block $batch_done (1)
	// After entering $skip_done block, $skip_loop loop:
	//   loop $skip_loop (0), block $skip_done (1), loop $scan (2), block $batch_done (3)
	// When adaptive, the $dense_gate if wraps the SIMD-if (opened below,
	// inside $skip_loop) and adds one level to every depth computed from
	// inside it.
	b = append(b, 0x02, 0x40) // block $skip_done
	st.Push("skip_done")
	b = append(b, 0x03, 0x40) // loop $skip_loop
	st.Push("skip_loop")

	// If lPos >= pInLen: exit $skip_done.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, st.Depth("skip_done"))

	if adaptive {
		// DenseCounter < threshold? If so, try SIMD (+ its scalar
		// tail below, unmodified). Once tripped, the else branch skips
		// BOTH the SIMD probe and the scalar tail's own candidate-membership
		// chain entirely and treats the current lPos as the candidate
		// directly — this is what makes the fallback actually as cheap as
		// the plain scalar frontend: emitSetMatchFnFinalScalar has no
		// first-byte pre-filter of its own at all, it goes straight into
		// the per-bucket check loop below for every position. Falling back
		// to this function's own "scalar tail" instead would re-pay a
		// second full first-byte membership chain on top of the per-bucket
		// loop's own first-byte compares — redundant, and would erase most
		// of the savings this switch exists to deliver.
		b = append(b, 0x20, lDenseCounter)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, denseSwitchThreshold)
		b = append(b, 0x48)       // i32.lt_s
		b = append(b, 0x04, 0x40) // if $dense_gate (void)
		st.Push("dense_gate")
	}

	// SIMD path: lPos + 15 < pInLen → load 16 bytes.
	// Depths inside this `if` (innermost outward), non-adaptive:
	//   0=SIMD if, 1=$skip_loop, 2=$skip_done.
	// Adaptive adds $dense_gate between SIMD-if and $skip_loop/$skip_done.
	b = append(b, 0x20, lPos, 0x41, 15, 0x6A, 0x20, pInLen, 0x49) // lt_u
	b = append(b, 0x04, 0x40)                                     // if (void) — SIMD path
	st.Push("simd_if")
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A) // pInPtr + lPos
	b = append(b, 0xFD, 0x00, 0x00, 0x00)         // v128.load align=0 offset=0
	b = append(b, 0x21, lChunk)                   // local.set lChunk
	b = emitShuftiPrefixCheck(b, cs.shuftiFirstByteSet, lChunk)
	b = append(b, 0x22, lSkipMask) // local.tee lSkipMask
	b = append(b, 0x04, 0x40)      // if mask != 0
	st.Push("mask_if")
	if adaptive {
		// No skip yet this attempt (DenseSkipFlag==0) → this probe bought
		// nothing, bump the streak. Otherwise a skip already happened this
		// attempt → SIMD paid off, reset the streak.
		b = append(b, 0x20, lDenseSkipFlag)
		b = append(b, 0x45)       // i32.eqz
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, lDenseCounter)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A) // i32.add
		b = append(b, 0x21, lDenseCounter)
		b = append(b, 0x05) // else
		b = append(b, 0x41, 0x00)
		b = append(b, 0x21, lDenseCounter)
		b = append(b, 0x0B) // end if
	}
	// Inside the nested mask `if`, non-adaptive: 0=mask if, 1=SIMD if,
	// 2=$skip_loop, 3=$skip_done. Adaptive: 0=mask if, 1=SIMD if,
	// 2=$dense_gate, 3=$skip_loop, 4=$skip_done.
	// Candidate found: lPos += ctz(mask); exit $skip_done.
	b = append(b, 0x20, lPos, 0x20, lSkipMask, 0x68, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, st.Depth("skip_done"))
	b = append(b, 0x0B) // end if mask != 0
	st.Pop()
	// No candidate in chunk: lPos += 16, continue $skip_loop.
	if adaptive {
		b = append(b, 0x41, 0x01)
		b = append(b, 0x21, lDenseSkipFlag) // this attempt did skip ≥16 bytes
	}
	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, st.Depth("skip_loop"))
	b = append(b, 0x0B) // end if SIMD path
	st.Pop()

	// Scalar tail: byte-by-byte. For simplicity check membership via the
	// inline byte set (≤ 64 entries) — emit a chained i32.eq + br.
	// Non-adaptive depths: loop $skip_loop (0), block $skip_done (1).
	// Adaptive: this now lives INSIDE $dense_gate's then-branch (a sibling
	// of the SIMD if above, not a peer of $skip_loop) — depths become
	// $dense_gate (0), $skip_loop (1), $skip_done (2).
	// We need to: if input[lPos] ∈ set → br to $skip_done; else lPos++; br to $skip_loop.
	skipDoneFromTail := byte(0x01)
	skipLoopFromTail := byte(0x00)
	if adaptive {
		skipDoneFromTail = 0x02
		skipLoopFromTail = 0x01
	}
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x2D, 0x00, 0x00, 0x21, lTmp) // lTmp = input[lPos]
	for _, fb := range cs.shuftiFirstByteSet {
		b = append(b, 0x20, lTmp, 0x41)
		b = utils.AppendSLEB128(b, int32(fb))
		b = append(b, 0x46)                   // i32.eq
		b = append(b, 0x0D, skipDoneFromTail) // br_if → $skip_done
	}
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
	b = append(b, 0x0C, skipLoopFromTail)                   // br → $skip_loop

	if adaptive {
		// Dense-confirmed: skip both the SIMD probe and the chained
		// membership check above entirely. lPos already points at the
		// position to process — the per-bucket loop below does its own
		// first-byte compares regardless, exactly like the plain scalar
		// frontend (emitSetMatchFnFinalScalar) which never pre-filters at
		// all. Depths from the else branch: $dense_gate (0, current),
		// $skip_loop (1), $skip_done (2).
		b = append(b, 0x05) // else
		b = append(b, 0x0C, st.Depth("skip_done"))
		b = append(b, 0x0B) // end if $dense_gate
		st.Pop()
	}

	b = append(b, 0x0B) // end loop $skip_loop
	st.Pop()
	b = append(b, 0x0B) // end block $skip_done
	st.Pop()

	// Re-check bounds: prefilter may have walked to lPos >= pInLen with no hit.
	// $batch_done, not $skip_done: the prefilter's block has already closed.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, st.Depth("batch_done"))
	// The prefilter also moved lPos past the drain bound checked at the top of
	// $scan, so re-check it here — that is what keeps perPositionDrain true for
	// this body (the bucket work below sees exactly one candidate position).
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Literal buckets only (selection requires no fallback). Shortest literal
	// first for the same ordering reason as the scalar path, and with the
	// position's first byte loaded once for the whole chain.
	b = c.emitLiteralBucketsHoisted(b, lPos, lFirstByte)

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
	b = append(b, 0x0C, st.Depth("scan"))
	b = append(b, 0x0B) // end loop $scan
	st.Pop()
	b = append(b, 0x0B) // end block $batch_done
	st.Pop()
	if st.Open() != 0 {
		panic("compile: emitSetMatchFnFinalShufti left blocks open")
	}

	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitSetMatchFnFinalAC emits the set match function body using an Aho-Corasick
// automaton for literal scanning. Replaces the O(n*m) scalar path with O(m) AC.
func emitSetMatchFnFinalAC(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int, mode setCapKind, probeFnBase int) []byte {
	acL := cs.acL

	// usePrefilter: apply SIMD first-byte prefilter when at root state and no fallback buckets.
	usePrefilter := !hasSetFallbackBuckets(cs) && len(cs.acFirstByteSet) > 0

	maxLitLen := 0
	for _, l := range cs.litLens {
		if l > maxLitLen {
			maxLitLen = l
		}
	}
	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, maxLitLen-1, mode, probeFnBase)
	lPos := c.lPos
	pInPtr, pInLen := c.pInPtr, c.pInLen
	lACState := c.localBase + 5
	lMatchPos := c.localBase + 6
	lOutIdx := c.localBase + 7
	lACOutEnd := c.localBase + 8
	lLitID := c.localBase + 9
	// Prefilter locals (i32 skip mask, then a v128 chunk).
	lSkipMask := c.localBase + 10
	lChunk := c.localBase + 11
	// The first-position locals go in their own trailing group so the
	// v128 local's index is unaffected by whether the prefilter is emitted.
	c.lMinStart, c.lBase, c.lStart = c.localBase+10, c.localBase+11, c.localBase+12
	c.lAcc = c.localBase + 13
	if usePrefilter {
		c.lMinStart, c.lBase, c.lStart = c.localBase+12, c.localBase+13, c.localBase+14
		c.lAcc = c.localBase + 15
	}

	var b []byte
	if usePrefilter {
		// 11 i32, 1 v128, 3 i32, then the scan_all i64 accumulator.
		b = append(b, 0x04, 0x0B, 0x7F, 0x01, 0x7B, 0x03, 0x7F, 0x01, 0x7E)
	} else {
		// 10 i32, 3 i32, then the scan_all i64 accumulator.
		b = append(b, 0x03, 0x0A, 0x7F, 0x03, 0x7F, 0x01, 0x7E)
	}

	// Init
	b = c.emitFindPrologue(b, lPos)
	b = append(b, 0x41, 0x00, 0x21, lACState)

	// Branch depths come from st, not from counted literals — see
	// compile/blockstack.go. A wrong depth here is a well-typed module that
	// branches to the wrong enclosing block, which no validator rejects.
	st := &blockStack{}
	b = append(b, 0x02, 0x40) // block $batch_done
	st.Push("batch_done")
	b = append(b, 0x03, 0x40) // loop $scan
	st.Push("scan")

	// Exit conditions
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, st.Depth("batch_done")) // lPos > pInLen
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Fallback buckets at every position — phase 2's job under phase1Only.
	if !cs.phase1Only {
		for bi, bkt := range cs.buckets {
			if !bkt.isFallback {
				continue
			}
			b = c.emitBucketAt(b, bi, 0, lPos)
		}
	}

	// AC transition: only when lPos < pInLen (there is a byte to consume)
	b = append(b, 0x02, 0x40) // block $end_ac_pos
	st.Push("end_ac_pos")
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, st.Depth("end_ac_pos")) // lPos >= pInLen

	// SIMD first-byte prefilter: when at root state, fast-skip to next candidate position.
	// Only emitted when there are no fallback buckets (those require visiting every position).
	// Block structure (depths from inside loop $skip_loop):
	//   block $skip_done (1), loop $skip_loop (0)
	//   Inside if(SIMD): depths are 0=if, 1=loop, 2=$skip_done
	//   Inside if(mask): depths are 0=if, 1=outer_if, 2=loop, 3=$skip_done
	if usePrefilter {
		b = append(b, 0x20, lACState, 0x45, 0x04, 0x40) // if lACState == 0 (eqz; if)
		st.Push("ac_state_zero")

		b = append(b, 0x02, 0x40) // block $skip_done
		st.Push("skip_done")
		b = append(b, 0x03, 0x40) // loop $skip_loop
		st.Push("skip_loop")

		// Exhaustion check: if lPos >= pInLen → br 1 → exit $skip_done
		b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, st.Depth("skip_done"))

		// SIMD path: if lPos + 15 < pInLen
		b = append(b, 0x20, lPos, 0x41, 15, 0x6A, 0x20, pInLen, 0x49) // lt_u
		b = append(b, 0x04, 0x40)                                     // if (void) — SIMD path
		st.Push("simd_if")

		// Load 16-byte chunk from memory[0] (input)
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
		b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0

		// Candidate bitmask for this chunk, by one of two strategies.
		//
		// The compare chain below costs 4 SIMD ops PER DISTINCT FIRST BYTE
		// per chunk, so it scales linearly in the size of the first-byte set:
		// 36 distinct first bytes means ~144 ops to probe 16 input bytes,
		// which is what made AC 7-10M fuel on the "diverse" shape against
		// 0.4M on a shared-prefix one. Shufti answers
		// the same membership question in ~7 ops per 8 bytes of the SET —
		// ~35 ops for those same 36 first bytes — because the set lives in
		// nibble tables rather than in the instruction stream.
		//
		// Below the crossover the chain still wins: at 1-3 bytes it is 4-12
		// ops against Shufti's ~7 plus its constant setup, and the chain
		// needs no table constants. The cutoff mirrors aho-corasick's, which
		// uses memchr/memchr2/memchr3 for 1-3 bytes and a different structure
		// above (util/prefilter.rs). Sets at or below 3 first bytes therefore
		// emit byte-identical code to before this split existed.
		if len(cs.acFirstByteSet) > 3 {
			b = append(b, 0x21, lChunk) // local.set lChunk
			b = emitShuftiPrefixCheck(b, cs.acFirstByteSet, lChunk)
		} else {
			b = append(b, 0x22, lChunk) // local.tee lChunk
			// Compute bitmask: OR of bitmask(eq(chunk, splat(fb))) for each first byte.
			b = append(b, 0x41, 0x00) // accumulator = 0
			for _, fb := range cs.acFirstByteSet {
				b = append(b, 0x20, lChunk)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(fb))
				b = append(b, 0xFD, 0x0F) // i8x16.splat
				b = append(b, 0xFD, 0x23) // i8x16.eq
				b = append(b, 0xFD, 0x64) // i8x16.bitmask
				b = append(b, 0x72)       // i32.or
			}
		}
		b = append(b, 0x22, lSkipMask) // local.tee lSkipMask

		// if mask != 0: candidate found at lPos + ctz(mask)
		b = append(b, 0x04, 0x40) // if (void) — mask non-zero
		st.Push("mask_if")
		b = append(b, 0x20, lPos, 0x20, lSkipMask, 0x68, 0x6A, 0x21, lPos) // lPos += ctz(mask)
		b = append(b, 0x0C, st.Depth("skip_done"))
		b = append(b, 0x0B) // end if mask
		st.Pop()

		// No candidate: advance 16 and restart
		b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos) // lPos += 16
		b = append(b, 0x0C, st.Depth("skip_loop"))
		b = append(b, 0x0B) // end if (SIMD path)
		st.Pop()

		// Scalar tail: check firstByteFlags[input[lPos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, cs.acFirstByteFlagsOff)              // firstByteFlags base
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x2D, 0x00, 0x00) // + input[lPos]
		b = append(b, 0x6A)                                             // add → flags address
		b = appendTableLoad8u(b, tableMemIdx)                           // load flag byte
		b = append(b, 0x04, 0x40)                                       // if (void) non-zero
		st.Push("scalar_if")
		b = append(b, 0x0C, st.Depth("skip_done")) // candidate at lPos
		b = append(b, 0x0B)                        // end if
		st.Pop()

		b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
		b = append(b, 0x0C, st.Depth("skip_loop"))
		b = append(b, 0x0B) // end loop $skip_loop
		st.Pop()
		b = append(b, 0x0B) // end block $skip_done
		st.Pop()

		b = append(b, 0x0B) // end if lACState == 0
		st.Pop()

		// Re-check bounds: prefilter may have exhausted input (lPos = pInLen)
		b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, st.Depth("end_ac_pos")) // ge_u
	}

	// lACState = goto_table[lACState * stride*2 + col(input[lPos]) * 2] as u16,
	// where col is the byte itself, or its equivalence class when the table is
	// byte-class compressed (one extra table load per input byte).
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acL.gotoOff)
	b = append(b, 0x20, lACState, 0x41, byte(acL.strideShift), 0x74, 0x6A) // + lACState * stride*2
	if acL.compressed {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, acL.classMapOff)
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A) // pInPtr + lPos
		b = append(b, 0x2D, 0x00, 0x00)               // i32.load8_u (input byte, memory 0)
		b = append(b, 0x6A)                           // classMapOff + byte
		b = appendTableLoad8u(b, tableMemIdx)         // classMap[byte]
	} else {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A) // pInPtr + lPos
		b = append(b, 0x2D, 0x00, 0x00)               // i32.load8_u 0 0 (input byte, memory 0)
	}
	b = append(b, 0x41, 0x01, 0x74, 0x6A) // * 2; add
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lACState)

	// Does this node report anything? ONE unsigned compare against a
	// constant, and the two u16 loads below happen only when it does.
	//
	// buildACLayoutMode renumbers nodes so the root is 0 and every
	// output-bearing node lands in [1, outLimit] (acLayout.outLimit), which
	// makes the test `(state - 1) u< outLimit` — the root's 0 underflows to
	// 0xFFFFFFFF and fails it, as it must. Before this the walk paid two
	// table loads per INPUT BYTE for a list that is empty at almost every
	// position.
	//
	// Emitted as a br_if out of $end_ac_pos rather than an `if` block so no
	// branch depth inside the output machinery moves.
	b = append(b, 0x20, lACState, 0x41, 0x01, 0x6B) // state - 1
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(acL.outLimit))
	b = append(b, 0x4F)                         // i32.ge_u
	b = append(b, 0x0D, st.Depth("end_ac_pos")) // br_if → $end_ac_pos

	// lOutIdx = nodeOut[lACState]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acL.nodeOutOff)
	b = append(b, 0x20, lACState, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lOutIdx)

	// lACOutEnd = nodeOut[lACState + 1]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acL.nodeOutOff+2)
	b = append(b, 0x20, lACState, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lACOutEnd)

	// Inner output loop: while lOutIdx < lACOutEnd
	b = append(b, 0x02, 0x40) // block $no_output
	st.Push("no_output")
	b = append(b, 0x03, 0x40) // loop $outputs
	st.Push("outputs")
	b = append(b, 0x20, lOutIdx, 0x20, lACOutEnd, 0x4F, 0x0D, st.Depth("no_output")) // ge_u

	// lLitID = output[lOutIdx]; lOutIdx++
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acL.outputOff)
	b = append(b, 0x20, lOutIdx, 0x41, 0x01, 0x74, 0x6A)
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lLitID)
	b = append(b, 0x20, lOutIdx, 0x41, 0x01, 0x6A, 0x21, lOutIdx)

	// Dispatch on lLitID via br_table: O(1) jump instead of an O(K) linear
	// if-chain. Structure (case 0 outermost, case K-1 innermost):
	//   block $end
	//     block $default
	//       block $case0
	//         …
	//           block $caseK-1
	//             local.get lLitID
	//             br_table K-1 K-2 … 1 0 K   ;; default → K = $default
	//           end $caseK-1
	//           ;; case K-1 handler ; br $end
	//         …
	//         end $case0
	//         ;; case 0 handler ; br $end
	//       end $default
	//     end $end
	K := len(cs.litToBuckets)
	if K > 0 {
		// Tracked on st even though the br_table below computes its own depths
		// from K: a stack that is silently short while these are open would
		// hand a wrong answer to any Depth() added inside them later.
		b = append(b, 0x02, 0x40) // block $end
		st.Push("brtable_end")
		b = append(b, 0x02, 0x40) // block $default
		st.Push("brtable_default")
		for i := 0; i < K; i++ { // K nested case blocks
			b = append(b, 0x02, 0x40)
			st.Push(fmt.Sprintf("brtable_case%d", i))
		}
		b = append(b, 0x20, lLitID)           // local.get lLitID
		b = append(b, 0x0E)                   // br_table
		b = utils.AppendULEB128(b, uint32(K)) // count
		for i := 0; i < K; i++ {
			b = utils.AppendULEB128(b, uint32(K-1-i))
		}
		b = utils.AppendULEB128(b, uint32(K)) // default depth → $default
		for i := K - 1; i >= 0; i-- {
			b = append(b, 0x0B) // end $case_i
			st.Pop()
			buckets := cs.litToBuckets[i]
			if len(buckets) > 0 {
				litLen := cs.litLens[i]
				// lMatchPos = lPos - (litLen - 1)
				if litLen <= 1 {
					b = append(b, 0x20, lPos, 0x21, lMatchPos)
				} else {
					b = append(b, 0x20, lPos, 0x41)
					b = utils.AppendSLEB128(b, int32(litLen-1))
					b = append(b, 0x6B, 0x21, lMatchPos)
				}
				for _, bucketIdx := range buckets {
					b = c.emitBucketAt(b, bucketIdx, litLen, lMatchPos)
				}
			}
			b = append(b, 0x0C) // br depth (i+1) → $end
			b = utils.AppendULEB128(b, uint32(i+1))
		}
		b = append(b, 0x0B) // end $default
		st.Pop()
		b = append(b, 0x0B) // end $end
		st.Pop()
	}

	b = append(b, 0x0C, st.Depth("outputs"))
	b = append(b, 0x0B) // end loop $outputs
	st.Pop()
	b = append(b, 0x0B) // end block $no_output
	st.Pop()
	b = append(b, 0x0B) // end block $end_ac_pos
	st.Pop()

	// lPos++; restart loop
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, st.Depth("scan"))
	b = append(b, 0x0B) // end loop $scan
	st.Pop()
	b = append(b, 0x0B) // end block $batch_done
	st.Pop()
	if st.Open() != 0 {
		panic("compile: emitSetMatchFnFinalAC left blocks open")
	}
	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitExtractLane extracts the byte at lane lLaneOff (a RUNTIME value, 0-15)
// from v128 local lCands into lLaneBit.
//
// One swizzle, not a 16-way br_table. i8x16.swizzle indexes a vector by
// another vector's bytes, so splatting the lane number and swizzling puts the
// wanted byte in every lane — after which lane 0 is a static extract. The
// br_table form this replaces was 16 nested blocks and 16 handlers, entered
// once per candidate lane (twice under TwoGroups).
//
// Operand order for i8x16.swizzle is DATA then INDICES: the byte at index
// indices[i] of `data` lands in lane i.
func emitExtractLane(b []byte, lCands, lLaneOff, lLaneBit byte) []byte {
	b = append(b, 0x20, lCands)     // v128 data
	b = append(b, 0x20, lLaneOff)   // i32 lane number
	b = append(b, 0xFD, 0x0F)       // i8x16.splat  -> indices
	b = append(b, 0xFD, 0x0E)       // i8x16.swizzle
	b = append(b, 0xFD, 0x16, 0x00) // i8x16.extract_lane_u 0
	b = append(b, 0x21, lLaneBit)
	return b
}

// emitSetMatchFnFinalPackedPair emits the set match body using a two-column
// byte-equality SIMD prefilter.
//
// Per 16-byte chunk it loads the two probe columns, tests each against the
// distinct bytes that column can hold, ANDs the two results and extracts a
// lane mask — against Teddy's four chunk loads and four nibble-table swizzle
// pairs for the same 16 positions. The pair pins only two bytes, so every
// candidate is verified against EVERY literal from offset 0 before any bucket
// runs; correctness therefore does not depend on the pair being selective,
// only its speed does.
//
// Like the Teddy body, this serves `find` AND the scan trio through
// setFindCtx.mode, and is only used when there are no fallback buckets.
func emitSetMatchFnFinalPackedPair(cs *compiledSet, suffixFnBase, prefixFnBaseIdx int, mode setCapKind, probeFnBase int) []byte {
	pp := cs.packedPair
	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	lPos := c.lPos
	pInPtr, pInLen := c.pInPtr, c.pInLen
	lLaneMask := c.localBase + 5
	lMatchPos := c.localBase + 6
	lLaneOff := c.localBase + 7
	numI32 := 8

	// Blocks of 16 bytes handled per loop iteration. The probe
	// work scales linearly with this, but the per-iteration scaffolding —
	// bounds guard, drain check, position bump, loop branch — does not, so
	// widening amortises it. Two blocks fill a 32-bit lane mask exactly,
	// which is why 2 is the measured optimum and 4 would need a second mask.
	blocks := packedPairChunks

	// v128 locals: two input chunks per block, then one hoisted splat per
	// probe byte. Hoisting matters: the splats are loop-invariant and would
	// otherwise cost an i32.const + i8x16.splat per chunk per byte.
	v128Base := c.localBase + byte(numI32)
	next := v128Base
	lChunk1 := make([]byte, blocks)
	lChunk2 := make([]byte, blocks)
	for i := 0; i < blocks; i++ {
		lChunk1[i], lChunk2[i] = next, next+1
		next += 2
	}
	splat1 := make([]byte, len(pp.Bytes1))
	splat2 := make([]byte, len(pp.Bytes2))
	for i := range splat1 {
		splat1[i] = next
		next++
	}
	for i := range splat2 {
		splat2[i] = next
		next++
	}
	numV128 := 2*blocks + pp.splatCount()

	// First-position locals sit after the v128 group so the v128 indices
	// above stay stable.
	c.lMinStart = v128Base + byte(numV128)
	c.lBase = c.lMinStart + 1
	c.lStart = c.lMinStart + 2
	c.lAcc = c.lMinStart + 3

	var b []byte
	// 8 i32, numV128 v128, 3 i32, then the scan_all i64 accumulator.
	b = append(b, 0x04, byte(numI32), 0x7F, byte(numV128), 0x7B, 0x03, 0x7F, 0x01, 0x7E)

	// Hoist the probe-byte splats.
	emitSplat := func(b []byte, val, dst byte) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(int8(val)))
		b = append(b, 0xFD, 0x0F) // i8x16.splat
		return append(b, 0x21, dst)
	}
	for i, v := range pp.Bytes1 {
		b = emitSplat(b, v, splat1[i])
	}
	for i, v := range pp.Bytes2 {
		b = emitSplat(b, v, splat2[i])
	}

	b = c.emitFindPrologue(b, lPos)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen → done
	b = c.emitDrainCheck(b, lPos, 0x01)

	// SIMD guard, identical in shape and reasoning to the Teddy body's: the
	// last lane of the widest block is a literal occupying
	// [lPos+span-1, lPos+span-1+MinLen), and all of it must be inside the
	// input. This also covers every chunk load, whose furthest byte is
	// lPos+span-1+Off2 <= lPos+span-2+MinLen. See the comment on Teddy's
	// simdGuard — the off-by-one there was a real out-of-bounds read that
	// produced a phantom match on a NUL literal.
	span := 16 * blocks
	simdGuard := int32(pp.MinLen + span - 1)

	b = append(b, 0x02, 0x40) // block $not_simd
	b = append(b, 0x20, lPos, 0x41)
	b = utils.AppendSLEB128(b, simdGuard)
	b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00) // lPos+guard > pInLen → $not_simd

	// Load the two probe columns for each block.
	emitChunkLoad := func(b []byte, off int, dst byte) []byte {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
		if off > 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(off))
			b = append(b, 0x6A)
		}
		b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
		return append(b, 0x21, dst)
	}
	// column mask = OR over the column's bytes of i8x16.eq(chunk, splat(b)).
	emitColumnMask := func(b []byte, chunk byte, splats []byte) []byte {
		for i, s := range splats {
			b = append(b, 0x20, chunk, 0x20, s, 0xFD, 0x23) // i8x16.eq
			if i > 0 {
				b = append(b, 0xFD, 0x50) // v128.or
			}
		}
		return b
	}
	for blk := 0; blk < blocks; blk++ {
		b = emitChunkLoad(b, pp.Off1+16*blk, lChunk1[blk])
		b = emitChunkLoad(b, pp.Off2+16*blk, lChunk2[blk])
	}
	// Fold each block's 16-bit bitmask into one lane mask, block k occupying
	// bits [16k, 16k+16). ctz over the combined mask then yields the position
	// offset from lPos directly, exactly as in the single-block case.
	for blk := 0; blk < blocks; blk++ {
		b = emitColumnMask(b, lChunk1[blk], splat1)
		b = emitColumnMask(b, lChunk2[blk], splat2)
		b = append(b, 0xFD, 0x4E) // v128.and — both columns must hit
		// i8x16.eq lanes are 0xFF/0x00, so the bitmask (which reads each
		// lane's high bit) needs no separate compare-against-zero step.
		b = append(b, 0xFD, 0x64) // i8x16.bitmask
		if blk > 0 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(16*blk))
			b = append(b, 0x74, 0x72) // i32.shl; i32.or
		}
	}
	b = append(b, 0x21, lLaneMask)

	// Process candidate lanes.
	b = append(b, 0x02, 0x40)                                                                // block $lanes_done
	b = append(b, 0x03, 0x40)                                                                // loop $lanes
	b = append(b, 0x20, lLaneMask, 0x45, 0x0D, 0x01)                                         // mask == 0 → done
	b = append(b, 0x20, lLaneMask, 0x68, 0x21, lLaneOff)                                     // ctz
	b = append(b, 0x20, lLaneMask, 0x20, lLaneMask, 0x41, 0x01, 0x6B, 0x71, 0x21, lLaneMask) // clear low bit
	b = append(b, 0x20, lPos, 0x20, lLaneOff, 0x6A, 0x21, lMatchPos)                         // lMatchPos = lPos + lLaneOff

	// Verify every literal at lMatchPos, from offset 0.
	//
	// Never stop at the first hit: several literals can genuinely match the
	// same position and each owns buckets that must run. This is the rule
	// bucketed Teddy applies for the same reason (see the comment in
	// emitSetMatchFnFinalTeddy's lane dispatch), and unlike aho-corasick's
	// verify_bucket we have no leftmost-first contract letting us return early.
	for _, bi := range litOrderFor(cs) {
		bkt := cs.buckets[bi]
		lit := []byte(bkt.literal)
		litLen := len(lit)
		b = append(b, 0x02, 0x40) // block $lit_no
		// Fit check: lMatchPos + litLen > pInLen → skip this literal.
		b = append(b, 0x20, lMatchPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00)
		for li, lb := range lit {
			// A probe column may be skipped ONLY when its candidate set holds
			// a single byte.
			//
			// The lane mask is an OR over every literal's probe bytes, so a
			// set lane means "SOME literal's probe bytes matched here", not
			// this one's. Skipping the column unconditionally therefore treats
			// another literal's hit as proof of this literal's — and when a
			// literal's bytes lie entirely inside the two probe columns,
			// nothing is verified at all and every candidate lane fires.
			// `01` + `00` over a run of '0' reported `01` at every SIMD-served
			// start: column 1's set is {'0','1'}, so "00" lit the lane and
			// "01" verified zero bytes.
			//
			// With a one-byte set the union IS this literal's byte, so the
			// original reasoning holds and the skip is kept — which is the
			// common case that made this pay.
			if li == pp.Off1 && len(pp.Bytes1) == 1 {
				continue
			}
			if li == pp.Off2 && len(pp.Bytes2) == 1 {
				continue
			}
			b = append(b, 0x20, pInPtr, 0x20, lMatchPos, 0x6A)
			b = append(b, 0x2D, 0x00)
			b = utils.AppendULEB128(b, uint32(li))
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00) // i32.ne → skip
		}
		b = c.emitBucketAt(b, bi, litLen, lMatchPos)
		b = append(b, 0x0B) // end $lit_no
	}

	b = append(b, 0x0C, 0x00) // br 0 → restart $lanes
	b = append(b, 0x0B)       // end loop $lanes
	b = append(b, 0x0B)       // end block $lanes_done

	b = append(b, 0x20, lPos, 0x41)
	b = utils.AppendSLEB128(b, int32(span))
	b = append(b, 0x6A, 0x21, lPos) // lPos += span
	b = append(b, 0x0C, 0x01)       // br 1 → restart $scan
	b = append(b, 0x0B)             // end block $not_simd

	// Scalar tail: check each literal at lPos, one position at a time.
	// The same per-position literal chain the scalar and Shufti bodies run —
	// verified opcode-identical (same litOrderFor order, same fit test, same
	// compare chain, same emitBucketAt) before being folded into the one
	// emitter.
	b = c.emitLiteralBuckets(b, lPos)

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos += 1
	b = append(b, 0x0C, 0x00)                               // br 0 → restart $scan
	b = append(b, 0x0B)                                     // end loop $scan
	b = append(b, 0x0B)                                     // end block $batch_done
	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitSetMatchFnFinalTeddy emits the set match function body using SIMD Teddy
// for literal scanning. Supports up to 16 literals (two groups of 8) and partial
// probing for literals longer than 4 bytes (first 4 bytes probed; remainder verified
// in the dispatch). Only used when there are no fallback buckets.
func emitSetMatchFnFinalTeddy(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int, mode setCapKind, probeFnBase int) []byte {
	tt := cs.teddyTabs
	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	lPos := c.lPos
	pInPtr, pInLen := c.pInPtr, c.pInLen
	lLaneMask := c.localBase + 5
	lMatchPos := c.localBase + 6
	lLaneBit := c.localBase + 7 // Group A lane bit
	lLaneOff := c.localBase + 8
	lLaneBitB := c.localBase + 9 // Group B lane bit (only used when TwoGroups)
	// v128 locals start after the ten i32 locals.
	v128Base := c.localBase + 10
	lChunk := v128Base
	lTLo := v128Base + 1
	lTHi := v128Base + 2
	lCands := v128Base + 3 // Group A result

	off := byte(4)
	var lChunk1, lT1Lo, lT1Hi, lChunk2, lT2Lo, lT2Hi, lChunk3, lT3Lo, lT3Hi byte
	if tt.TwoByte {
		lChunk1, lT1Lo, lT1Hi = v128Base+off, v128Base+off+1, v128Base+off+2
		off += 3
	}
	if tt.ThreeByte {
		lChunk2, lT2Lo, lT2Hi = v128Base+off, v128Base+off+1, v128Base+off+2
		off += 3
	}
	if tt.FourByte {
		lChunk3, lT3Lo, lT3Hi = v128Base+off, v128Base+off+1, v128Base+off+2
		off += 3
	}
	var lBT0Lo, lBT0Hi, lCandsB, lBT1Lo, lBT1Hi, lBT2Lo, lBT2Hi, lBT3Lo, lBT3Hi byte
	if tt.TwoGroups {
		lBT0Lo, lBT0Hi, lCandsB = v128Base+off, v128Base+off+1, v128Base+off+2
		off += 3
		if tt.TwoByte {
			lBT1Lo, lBT1Hi = v128Base+off, v128Base+off+1
			off += 2
		}
		if tt.ThreeByte {
			lBT2Lo, lBT2Hi = v128Base+off, v128Base+off+1
			off += 2
		}
		if tt.FourByte {
			lBT3Lo, lBT3Hi = v128Base+off, v128Base+off+1
			off += 2
		}
	}
	numV128 := int(off)

	// The first-position locals sit after the v128 group so the v128
	// indices above stay unchanged.
	c.lMinStart = v128Base + byte(numV128)
	c.lBase = c.lMinStart + 1
	c.lStart = c.lMinStart + 2
	c.lAcc = c.lMinStart + 3

	// Collect literal strings for tail-byte verification.
	litStr := make([]string, len(cs.litToBuckets))
	for litID, buckets := range cs.litToBuckets {
		if len(buckets) > 0 {
			litStr[litID] = cs.buckets[buckets[0]].literal
		}
	}

	// emitLitDispatch emits the inner lit_bits loop for one group.
	// groupOffset is 0 for group A, 8 for group B.
	// lLaneBitLocal is the local holding the lane bitmask for this group.
	emitLitDispatch := func(b []byte, groupOffset int, lLaneBitLocal byte) []byte {
		numInGroup := len(tt.LaneToIDs) - groupOffset
		if numInGroup > 8 {
			numInGroup = 8
		}
		b = append(b, 0x02, 0x40)                            // block $lit_bits_done
		b = append(b, 0x03, 0x40)                            // loop $lit_bits
		b = append(b, 0x20, lLaneBitLocal, 0x45, 0x0D, 0x01) // i32.eqz → $lit_bits_done

		b = append(b, 0x20, lLaneBitLocal, 0x68, 0x21, lLaneOff)                                             // ctz
		b = append(b, 0x20, lLaneBitLocal, 0x20, lLaneBitLocal, 0x41, 0x01, 0x6B, 0x71, 0x21, lLaneBitLocal) // clear bit

		for k := 0; k < numInGroup; k++ {
			lane := groupOffset + k
			if lane >= len(tt.LaneToIDs) || len(tt.LaneToIDs[lane]) == 0 {
				continue
			}

			b = append(b, 0x20, lLaneOff, 0x41)
			b = utils.AppendSLEB128(b, int32(k))
			b = append(b, 0x46, 0x04, 0x40) // i32.eq; if

			// Every literal in the lane is checked. A lane bit means only
			// "some member may start here": with one member that is exact on
			// the probed bytes, but a bucketed lane's tables are ORs over its
			// members, so the bit can survive a cross-product that matches no
			// member at all — and, more importantly here, SEVERAL members can
			// genuinely match the same position and every one of them owns
			// patterns that must appear in the result bitmask. So this never
			// stops at the first hit, unlike aho-corasick's verify_bucket,
			// whose leftmost-first contract lets it return immediately.
			for _, litID := range tt.LaneToIDs[lane] {
				litLen := cs.litLens[litID]
				fullLit := litStr[litID]
				// Bucketed lanes must re-check the probe bytes too: the
				// nibble tables no longer pin them for an individual member.
				verifyFrom := tt.MinLen
				if tt.Bucketed {
					verifyFrom = 0
				}
				if verifyFrom < litLen {
					// Wrap in block so verification can break out on mismatch.
					b = append(b, 0x02, 0x40) // block $tail_ok
					// Fit check: lMatchPos + litLen > pInLen → skip
					b = append(b, 0x20, lMatchPos, 0x41)
					b = utils.AppendSLEB128(b, int32(litLen))
					b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00) // gt_u → br 0 ($tail_ok)
					for j := verifyFrom; j < litLen; j++ {
						b = append(b, 0x20, pInPtr, 0x20, lMatchPos, 0x6A)
						b = append(b, 0x2D, 0x00) // i32.load8_u align=0
						b = utils.AppendULEB128(b, uint32(j))
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, int32(fullLit[j]))
						b = append(b, 0x47, 0x0D, 0x00) // i32.ne; br_if 0 ($tail_ok)
					}
					for _, bi := range cs.litToBuckets[litID] {
						b = c.emitBucketAt(b, bi, litLen, lMatchPos)
					}
					b = append(b, 0x0B) // end block $tail_ok
				} else {
					for _, bi := range cs.litToBuckets[litID] {
						b = c.emitBucketAt(b, bi, litLen, lMatchPos)
					}
				}
			}
			b = append(b, 0x0B) // end if
		}
		b = append(b, 0x0C, 0x00) // br 0 → restart $lit_bits
		b = append(b, 0x0B)       // end loop $lit_bits
		b = append(b, 0x0B)       // end block $lit_bits_done
		return b
	}

	var b []byte
	// 10 i32, numV128 v128, 3 i32, then the scan_all i64 accumulator.
	b = append(b, 0x04, 0x0A, 0x7F, byte(numV128), 0x7B, 0x03, 0x7F, 0x01, 0x7E)

	// Pre-load group A Teddy tables (loop-invariant)
	groupAOff := cs.teddyDataOffset
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, groupAOff)
	b = appendTableVLoad(b, tableMemIdx)
	b = append(b, 0x21, lTLo)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, groupAOff+16)
	b = appendTableVLoad(b, tableMemIdx)
	b = append(b, 0x21, lTHi)
	if tt.TwoByte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+32)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT1Lo)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+48)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT1Hi)
	}
	if tt.ThreeByte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+64)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT2Lo)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+80)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT2Hi)
	}
	if tt.FourByte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+96)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT3Lo)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupAOff+112)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lT3Hi)
	}

	// Pre-load group B Teddy tables (if TwoGroups)
	if tt.TwoGroups {
		groupBOff := cs.teddyDataOffset + teddyGroupABytes(tt)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupBOff)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lBT0Lo)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, groupBOff+16)
		b = appendTableVLoad(b, tableMemIdx)
		b = append(b, 0x21, lBT0Hi)
		if tt.TwoByte {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+32)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT1Lo)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+48)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT1Hi)
		}
		if tt.ThreeByte {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+64)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT2Lo)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+80)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT2Hi)
		}
		if tt.FourByte {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+96)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT3Lo)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, groupBOff+112)
			b = appendTableVLoad(b, tableMemIdx)
			b = append(b, 0x21, lBT3Hi)
		}
	}

	b = c.emitFindPrologue(b, lPos)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01)
	b = c.emitDrainCheck(b, lPos, 0x01)

	minLen := tt.MinLen
	// A 16-byte chunk at lPos produces candidates for lanes 0..15, and lane 15
	// is a literal occupying [lPos+15, lPos+15+minLen). All of it must be
	// inside the input, so the SIMD path needs lPos + 15 + minLen <= inLen.
	//
	// This was `minLen + 14`, one short, and the last chunk of an input whose
	// length is 15 mod 16 therefore fingerprinted one byte PAST the end —
	// reading whatever the caller's memory held there. On a fresh WASM page
	// that byte is 0, so a set containing a NUL literal reported a phantom
	// match at the very last position: {"\x00", "0"} over 15 '0's reported
	// the NUL pattern. `find` hid it (the phantom start is never the minimum,
	// so the first-position rule discarded it), but scan_all, which
	// accumulates every pattern seen anywhere, showed it immediately.
	simdGuard := int32(minLen + 15)

	b = append(b, 0x02, 0x40) // block $not_simd
	b = append(b, 0x20, lPos, 0x41)
	b = utils.AppendSLEB128(b, simdGuard)
	b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00) // lPos+guard > pInLen → $not_simd

	// Load input chunks from memory[0]
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0xFD, 0x00, 0x00, 0x00, 0x21, lChunk)
	if tt.TwoByte {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x41, 0x01, 0x6A, 0xFD, 0x00, 0x00, 0x00, 0x21, lChunk1)
	}
	if tt.ThreeByte {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x41, 0x02, 0x6A, 0xFD, 0x00, 0x00, 0x00, 0x21, lChunk2)
	}
	if tt.FourByte {
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x41, 0x03, 0x6A, 0xFD, 0x00, 0x00, 0x00, 0x21, lChunk3)
	}

	// emitNibbleCheck: cands = swizzle(Lo, chunk&0xF) & swizzle(Hi, chunk>>4) [ANDed onto stack]
	emitNibbleCheck := func(b []byte, chunkLocal, loLocal, hiLocal byte, andWithStack bool) []byte {
		b = append(b, 0x20, loLocal, 0x20, chunkLocal, 0x41, 0x0F, 0xFD, 0x0F, 0xFD, 0x4E, 0xFD, 0x0E)
		b = append(b, 0x20, hiLocal, 0x20, chunkLocal, 0x41, 0x04, 0xFD, 0x6D, 0xFD, 0x0E, 0xFD, 0x4E)
		if andWithStack {
			b = append(b, 0xFD, 0x4E) // v128.and with previous result
		}
		return b
	}

	// Compute group A candidates
	b = emitNibbleCheck(b, lChunk, lTLo, lTHi, false)
	if tt.TwoByte {
		b = emitNibbleCheck(b, lChunk1, lT1Lo, lT1Hi, true)
	}
	if tt.ThreeByte {
		b = emitNibbleCheck(b, lChunk2, lT2Lo, lT2Hi, true)
	}
	if tt.FourByte {
		b = emitNibbleCheck(b, lChunk3, lT3Lo, lT3Hi, true)
	}
	b = append(b, 0x21, lCands) // store group A candidates

	// Compute lLaneMask: positions where group A or group B has any hit
	b = append(b, 0x20, lCands, 0x41, 0x00, 0xFD, 0x0F, 0xFD, 0x24, 0xFD, 0x64) // bitmask(A != 0)
	if tt.TwoGroups {
		// Compute group B candidates
		b = emitNibbleCheck(b, lChunk, lBT0Lo, lBT0Hi, false)
		if tt.TwoByte {
			b = emitNibbleCheck(b, lChunk1, lBT1Lo, lBT1Hi, true)
		}
		if tt.ThreeByte {
			b = emitNibbleCheck(b, lChunk2, lBT2Lo, lBT2Hi, true)
		}
		if tt.FourByte {
			b = emitNibbleCheck(b, lChunk3, lBT3Lo, lBT3Hi, true)
		}
		b = append(b, 0x21, lCandsB)                                                 // store group B candidates
		b = append(b, 0x20, lCandsB, 0x41, 0x00, 0xFD, 0x0F, 0xFD, 0x24, 0xFD, 0x64) // bitmask(B != 0)
		b = append(b, 0x72)                                                          // i32.or with mask A
	}
	b = append(b, 0x21, lLaneMask)

	// Process candidate lanes
	b = append(b, 0x02, 0x40) // block $lanes_done
	b = append(b, 0x03, 0x40) // loop $lanes
	b = append(b, 0x20, lLaneMask, 0x45, 0x0D, 0x01)

	b = append(b, 0x20, lLaneMask, 0x68, 0x21, lLaneOff)                                     // ctz → chunk position
	b = append(b, 0x20, lLaneMask, 0x20, lLaneMask, 0x41, 0x01, 0x6B, 0x71, 0x21, lLaneMask) // clear bit
	b = append(b, 0x20, lPos, 0x20, lLaneOff, 0x6A, 0x21, lMatchPos)                         // lMatchPos = lPos + lLaneOff

	// Extract BOTH groups' lane bits before either is dispatched.
	//
	// emitExtractLane selects a byte of the candidate vector using lLaneOff,
	// which at this point holds the position within the 16-byte chunk. But
	// emitLitDispatch reuses lLaneOff as its own scratch (ctz of the lane
	// bitmask), so running group A's dispatch first leaves a LANE INDEX
	// there — and group B would then extract from the wrong chunk position
	// and silently lose every literal in its lanes.
	//
	// The hazard predates bucketing: any set over 8 literals has two groups.
	// It stayed invisible because with one literal per lane a group A
	// candidate meant a true fingerprint match on all probed bytes, so the
	// two groups rarely had candidates at the same position. Bucketed lanes
	// OR several literals into one bit, group A candidates become common, and
	// the clobber fires routinely.
	b = emitExtractLane(b, lCands, lLaneOff, lLaneBit)
	if tt.TwoGroups {
		b = emitExtractLane(b, lCandsB, lLaneOff, lLaneBitB)
	}
	b = emitLitDispatch(b, 0, lLaneBit)
	if tt.TwoGroups {
		b = emitLitDispatch(b, 8, lLaneBitB)
	}

	b = append(b, 0x0C, 0x00) // br 0 → restart $lanes
	b = append(b, 0x0B)       // end loop $lanes
	b = append(b, 0x0B)       // end block $lanes_done

	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x01) // br 1 → restart $scan
	b = append(b, 0x0B)       // end block $not_simd

	// Scalar tail: check each literal at lPos
	// The same per-position literal chain the scalar and Shufti bodies run —
	// verified opcode-identical (same litOrderFor order, same fit test, same
	// compare chain, same emitBucketAt) before being folded into the one
	// emitter.
	b = c.emitLiteralBuckets(b, lPos)

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $scan
	b = append(b, 0x0B) // end block $batch_done
	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}
