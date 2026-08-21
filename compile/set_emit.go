package compile

import (
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

	// Capability export names (plans/SETS.md §3.12); "" = not declared.
	match    string // anchored, 0|1
	matchAny string // anchored, pattern id or -1
	matchAll string // anchored, bitmask / bitmap of ids
	scan     string // non-anchored, 0|1
	scanAny  string // non-anchored, (start<<32)|id, or -1
	scanAll  string // non-anchored, bitmask / bitmap of ids
	find     string // non-anchored, tuples at the next matching position

	// overlapping selects the ungated `find` body (§3.15 / D10). The default
	// (false) is the gated, per-pattern non-overlapping body.
	overlapping bool

	// maxLookback (M) is the largest distance between a mandatory literal and
	// the match start it can serve, over every pattern in the set; -1 when any
	// pattern's prefix is unbounded. It bounds the §9.4 first-position drain.
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

	// prefixFnBodies[i] is the body for the i-th unique prefix DFA (backward scan).
	// Signature: (ptr i32, scan_end i32) → i32  (type 0)
	prefixFnBodies [][]byte

	// prefixDataBytes/prefixDataSegCount: data segments for prefix DFA tables.
	prefixDataBytes    []byte
	prefixDataSegCount int

	// prefixFnIdx[bi][k]: index into prefixFnBodies for pattern at bitPos k in bucket bi.
	// -1 means trivial prefix (always passes; bit is always set in validMask).
	prefixFnIdx [][]int

	// trivialPrefixMasks[bi]: bitmask of patterns in bucket bi with trivial prefix.
	trivialPrefixMasks []uint32

	// startAnchorMasks[bi]: bitmask of patterns anchored with \A / ^ — eligible
	// only at input position 0.
	startAnchorMasks []uint32

	// lineAnchorMasks[bi]: bitmask of patterns anchored with (?m:^) — eligible
	// at position 0 and at any position whose preceding byte is a newline
	// (plans/FABLE.md B43).
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

	// shuftiAdaptive (task 28): true when Shufti was selected ONLY because
	// set-level LikelyNoMatch overrode a static verdict that scalar would
	// win (shuftiBeatsScalar(union) == false). Mirrors EmitPrefixScan's
	// `adaptive` gate (TODO.md task 25) for the single-pattern path: the
	// static heuristic can't tell "sparse runtime data" (override
	// genuinely wins) from "dense runtime data" (override regresses), so
	// emitSetMatchFnFinalShufti adds a runtime DenseCounter/DenseSkipFlag
	// switch that falls back to the scalar tail once density is confirmed,
	// instead of trusting the static override for the whole scan.
	shuftiAdaptive bool

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
	findType := byte(setTypeI32x6ToI32)
	if cs.overlapping {
		findType = setTypeI32x5ToI32
	}
	all := []setCapFn{
		{cs.find, capFind, findType},
		{cs.scan, capScan, setTypeI32x3ToI32},
		{cs.scanAny, capScanAny, setTypeI32x3ToI64},
		{cs.scanAll, capScanAll, scanAllType},
		{cs.match, capMatch, setTypeI32I32ToI32},
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
	return len(cs.capFns()) + cs.numSuffixFns + len(cs.prefixFnBodies) +
		len(cs.scanProbeBodies) + len(cs.anchoredProbeBodies)
}

// suffixFnBaseOffset returns the index of the first suffix function within this
// set's functions (relative to the set's base).
func (cs *compiledSet) suffixFnBaseOffset() int { return len(cs.capFns()) }

// prefixFnBaseOffset returns the index of the first backward-prefix function.
func (cs *compiledSet) prefixFnBaseOffset() int {
	return cs.suffixFnBaseOffset() + cs.numSuffixFns
}

// scanProbeBaseOffset returns the index of the first scan-probe function.
func (cs *compiledSet) scanProbeBaseOffset() int {
	return cs.prefixFnBaseOffset() + len(cs.prefixFnBodies)
}

// anchoredProbeBaseOffset returns the index of the first anchored-probe function.
func (cs *compiledSet) anchoredProbeBaseOffset() int {
	return cs.scanProbeBaseOffset() + len(cs.scanProbeBodies)
}

// WASM type-section indices used by the set path. The full table is written
// by assembleModuleWithSets; these names keep the emitters readable.
const (
	setTypeI32I32ToI32 = 0 // (i32,i32)→i32      match / match_any / backward prefix
	setTypeI32I32ToI64 = 1 // (i32,i32)→i64      match_all, <= 64 patterns
	setTypeI32x3ToI32  = 2 // (i32,i32,i32)→i32  scan; match_all bitmap form
	setMatchTypeSuffix = 3 // (i32×7)→i32        suffix DFA (tuple-writing)
	setTypeI32x5ToI32  = 5 // (i32×5)→i32        find, overlapping: true
	setTypeI32x4ToI32  = 6 // (i32×4)→i32        bucket probes; scan_all bitmap form
	setTypeI32x3ToI64  = 7 // (i32,i32,i32)→i64  scan_any; scan_all <= 64 patterns
	setTypeI32x6ToI32  = 8 // (i32×6)→i32        find, gated (default)
	setTypeSuffixGated = 9 // (i32×8)→i32        suffix DFA with a gate pointer
)

// gatedFind reports whether this set emits the default (per-pattern
// non-overlapping) `find` body, which threads a gate array through the suffix
// functions (plans/SETS.md §3.14-3.16).
func (cs *compiledSet) gatedFind() bool { return cs.find != "" && !cs.overlapping }

// setMatchTypeMatch is kept as the historical alias for the ungated find
// signature, which the per-pattern batch wrappers also reuse.
const setMatchTypeMatch = setTypeI32x5ToI32

// SetSpec is the resolved specification for one set, ready for compilation.
type SetSpec struct {
	Name string

	// Capability export names (plans/SETS.md §3.12); "" = not declared.
	Match    string
	MatchAny string
	MatchAll string
	Scan     string
	ScanAny  string
	ScanAll  string
	Find     string

	Overlapping bool // §3.15 / D10: true = ungated `find` body

	Patterns   []*PatternInfo // resolved, capture-bearing dropped
	PatternIDs []int          // global indices into the regexps list
}

// needsScanProbes reports whether the set declares one of the non-anchored
// capabilities other than `find`. Those answer "which patterns match here?"
// and use the cheap bitmask probe over the find-path buckets rather than the
// tuple-writing suffix function (plans/SETS.md §5).
func (s SetSpec) needsScanProbes() bool {
	return s.Scan != "" || s.ScanAny != "" || s.ScanAll != ""
}

// needsAnchoredBuckets reports whether the set declares one of the anchored
// capabilities, which require their own non-leftmost-first automata.
func (s SetSpec) needsAnchoredBuckets() bool {
	return s.Match != "" || s.MatchAny != "" || s.MatchAll != ""
}

// CompileSet compiles one set specification into a compiledSet.
// prefixPool and suffixPool are shared dedup pools across all sets in the file.
func CompileSet(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions) *compiledSet {
	diag := &SetDiag{Name: spec.Name}
	buckets := binPack(spec.Patterns, opts, diag)

	// Build per-bucket pattern-ID mapping: patternIDs[bucketIdx][bitPos] = globalID.
	patternIDs := make([][]int, len(buckets))
	for bi, b := range buckets {
		ids := make([]int, len(b.patterns))
		for j, p := range b.patterns {
			// Find this pattern in spec.Patterns to get its global ID.
			for k, sp := range spec.Patterns {
				if sp == p {
					ids[j] = spec.PatternIDs[k]
					break
				}
			}
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
			if j >= 32 {
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
	gatedFind := spec.Find != "" && !spec.Overlapping
	var suffixFnBodies [][]byte
	if spec.Find != "" {
		suffixFnBodies = make([][]byte, len(buckets))
	}
	var scanProbeBodies [][]byte
	if needScanProbes {
		scanProbeBodies = make([][]byte, len(buckets))
	}
	var allDataBytes []byte
	var totalDataSegs int
	tableOffset := opts.TableBase // data segment base for this set's tables

	// The tuple-writing suffix function is `find`'s alone (plans/SETS.md §5):
	// it is the per-pattern extent machinery, and the other six capabilities
	// answer their question from the bitmask probe instead. A set that does
	// not declare `find` therefore emits no suffix FUNCTIONS at all — only
	// their DFA tables, which the probes share.
	needSuffixFns := spec.Find != ""
	for bi, bkt := range buckets {
		art, dataBytes, dataSegs, nextOffset := genSuffixWASM(bkt.suffixDFA, int64(tableOffset), opts.TableMemIdx, patternIDs[bi], prefixFixedLens[bi], needScanProbes, gatedFind)
		if needSuffixFns {
			suffixFnBodies[bi] = art.fnBody
		}
		if needScanProbes {
			scanProbeBodies[bi] = art.scanProbe
		}
		tableOffset = nextOffset // use actual memory end, not encoded size
		allDataBytes = append(allDataBytes, dataBytes...)
		totalDataSegs += dataSegs
	}

	// Second pass: build prefix DFA function bodies (after suffix data, to avoid address overlap).
	prefixTableOffset := tableOffset // start after all suffix DFA data
	for bi, bkt := range buckets {
		// Resolve prefixID → fnIdx for non-trivial patterns in this bucket.
		for j, p := range bkt.patterns {
			if j >= 32 || prefixFnIdx[bi][j] < 0 {
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
				body := buildLitAnchorBackScanBody(revL, p.prefixDFA, opts.TableMemIdx)
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
		// Cap: fall back to scalar if the automaton exceeds 32 nodes (goto table > 16 KB).
		// Larger automata cause epoch timeouts during re2test instantiation.
		if len(ac.nodes) <= 32 {
			acL = buildACLayout(ac, prefixTableOffset)
			acDataBytes = emitACDataSegments(acL)
			acDataSegCount = 2 // goto, combined nodeOut+output

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
		}
	}

	var teddyTabs *teddyTables
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
	}

	// LIKELY.md Gap H.3: density-heuristic / Action 5 Shufti for the
	// scalar fallback case. Requires zero fallback buckets (Shufti can't
	// skip positions that fallback patterns must visit) and a first-byte
	// union in the 17..64 band. The selection trigger is either the
	// rarity-based density heuristic or set-level LikelyNoMatch (Action 5).
	var shuftiFirstByteSet []byte
	var shuftiAdaptive bool
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
			if len(union) >= 17 && len(union) <= 64 {
				lnm := opts.LikelyMode == LikelyNoMatch
				rare := shuftiBeatsScalar(union)
				if lnm || rare {
					fe = frontendShufti
					shuftiFirstByteSet = union
					shuftiAdaptive = lnm && !rare
				}
			}
		}
	}

	// Record the frontend actually used (after any fallback to scalar).
	diag.Frontend = fe.String()

	// The set match function body is built at assemble time (when function table
	// indices are known). Store nil here; assembleModuleWithSets fills it in.
	cs := &compiledSet{
		name:                spec.Name,
		match:               spec.Match,
		matchAny:            spec.MatchAny,
		matchAll:            spec.MatchAll,
		scan:                spec.Scan,
		scanAny:             spec.ScanAny,
		scanAll:             spec.ScanAll,
		find:                spec.Find,
		overlapping:         spec.Overlapping,
		suffixFnBodies:      suffixFnBodies,
		scanProbeBodies:     scanProbeBodies,
		numSuffixFns:        len(suffixFnBodies),
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
		shuftiAdaptive:      shuftiAdaptive,
		litToBuckets:        litToBuckets,
		litLens:             litLens,
		diag:                diag,
	}
	// Anchored-capability automata (§3.3): a separate packing over the full
	// patterns with leftmost-first pruning disabled.
	if spec.needsAnchoredBuckets() {
		// Anchored tables go after every other table this set emits; the data
		// segment bytes include their own headers, so this over-estimates the
		// end of the preceding regions, which is harmless.
		anchoredTableBase := prefixTableOffset + int32(len(acDataBytes)) + int32(len(teddyDataBytes))
		abuckets, _ := compileAnchoredBuckets(spec.Patterns, opts, diag)
		cs.anchoredBuckets = abuckets
		cs.anchoredIDs = make([][]int, len(abuckets))
		anchoredOffset := anchoredTableBase
		for bi, ab := range abuckets {
			ids := make([]int, len(ab.patterns))
			for j, ap := range ab.patterns {
				for k, sp := range spec.Patterns {
					if sp == ap {
						ids[j] = spec.PatternIDs[k]
						break
					}
				}
			}
			cs.anchoredIDs[bi] = ids
			body, data, segs, next := genAnchoredWASM(ab.suffixDFA, int64(anchoredOffset), opts.TableMemIdx, len(ab.patterns))
			cs.anchoredProbeBodies = append(cs.anchoredProbeBodies, body)
			cs.anchoredDataBytes = append(cs.anchoredDataBytes, data...)
			cs.anchoredDataSegs += segs
			anchoredOffset = next
		}
	}

	// §9.4 first-position routing data, derived from the finished bucket list.
	cs.prefixLenGroups = make([][]prefixLenGroup, len(buckets))
	for bi := range buckets {
		cs.prefixLenGroups[bi] = buildPrefixLenGroups(cs, bi)
	}
	cs.maxLookback = setMaxLookback(cs)
	diag.MaxLookback = cs.maxLookback
	diag.Overlapping = spec.Overlapping
	for _, c := range []struct{ field, name string }{
		{"match", spec.Match}, {"match_any", spec.MatchAny}, {"match_all", spec.MatchAll},
		{"scan", spec.Scan}, {"scan_any", spec.ScanAny}, {"scan_all", spec.ScanAll},
		{"find", spec.Find},
	} {
		if c.name != "" {
			diag.Capabilities = append(diag.Capabilities, c.field)
		}
	}
	return cs
}

// appendTableLoad64 emits i64.load align=3 offset=0.
// tableMemIdx 0: 0x29 0x03 0x00. tableMemIdx 1: 0x29 0x43 0x01 0x00.
func appendTableLoad64(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x29, 0x03, 0x00)
	}
	return append(b, 0x29, 0x43, byte(tableMemIdx), 0x00)
}

// checkSetCapabilitiesImplemented rejects set capabilities whose emitter has
// not landed yet, so a config never silently gets a body with different
// semantics from the one its keys ask for.
//
// plans/SETS.md §9.1: gating is the DEFAULT configuration but its body lands
// at stage S5, so during S1-S4 every `find:` must opt into `overlapping: true`
// and a plain `find:` is a clear error rather than a silently ungated body.
func checkSetCapabilitiesImplemented(sc config.SetConfig) error {
	return nil
}

// --------------------------------------------------------------------------
// CompileFile — orchestrates all patterns and sets into one WASM module.

// CompileFile compiles all regexp patterns and sets from cfg into a single WASM module.
// When cfg.Sets is empty, it is byte-identical to the existing Compile() path.
func CompileFile(cfg config.BuildConfig, output string) ([]byte, int64, error) {
	if err := config.ValidateSets(&cfg); err != nil {
		return nil, 0, err
	}

	standalone := cfg.Output == ""

	// No sets: delegate to Compile so the output is byte-identical (including
	// per-pattern page alignment and final memory page count). Replicating
	// that logic here is bug-prone — earlier versions produced under-sized
	// memory for standalone modules whose DFA tables exceeded 64 KiB.
	if len(cfg.Sets) == 0 {
		return Compile(cfg.Regexps, 0, standalone, CompileOptions{
			MaxDFAStates: cfg.MaxDFAStates,
			MaxTDFARegs:  cfg.MaxTDFARegs,
		})
	}

	tableBase := int64(0)

	// Compile per-pattern entries (existing path).
	var compiled []*compiledPattern
	var lastTableEnd int64
	opts := CompileOptions{
		MaxDFAStates: cfg.MaxDFAStates,
		MaxTDFARegs:  cfg.MaxTDFARegs,
	}
	if !standalone {
		opts.tableMemIdx = 1
	}
	for _, re := range cfg.Regexps {
		p, err := compilePattern(re, tableBase, 0, opts)
		if err != nil {
			return nil, 0, err
		}
		// Batch find/groups export trigger (plans/TODO.md task 44) — same
		// trigger compileAll applies; see compileAll's comment for the
		// eligibility rules. Only the per-pattern exports get a batch
		// wrapper here: a set's `find` already returns every match at one
		// position per call and needs no batch knob (plans/SETS.md §7.7 /
		// D12), so assembleModuleWithSets does not add batch wrappers for
		// compiledSet functions.
		if hasBatchHint(re.Hints) {
			if p.findExport != "" {
				p.batchFindExport = p.findExport + "_batch"
			}
			groupsBatchName := p.groupsExport
			if groupsBatchName == "" {
				groupsBatchName = p.namedGroupsExport
			}
			if groupsBatchName != "" {
				p.batchGroupsExport = groupsBatchName + "_batch"
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
		if err := checkSetCapabilitiesImplemented(sc); err != nil {
			return nil, 0, err
		}
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
		var infos []*PatternInfo
		var globalIDs []int
		for _, idx := range selectedIdx {
			re := cfg.Regexps[idx]
			if re.CaptureStubsRequested() {
				continue // drop capture-bearing
			}
			info, err := analyzePattern(re, &prefixPool, &suffixPool)
			if err != nil {
				patLabel := re.Name
				if patLabel == "" {
					patLabel = re.Pattern
				}
				return nil, 0, fmt.Errorf("set %q: pattern %q: %w", sc.Name, patLabel, err)
			}
			info.globalID = idx
			info.name = re.Name
			infos = append(infos, info)
			globalIDs = append(globalIDs, idx)
		}

		spec := SetSpec{
			Name:        sc.Name,
			Match:       sc.Match,
			MatchAny:    sc.MatchAny,
			MatchAll:    sc.MatchAll,
			Scan:        sc.Scan,
			ScanAny:     sc.ScanAny,
			ScanAll:     sc.ScanAll,
			Find:        sc.Find,
			Overlapping: sc.Overlapping,
			Patterns:    infos,
			PatternIDs:  globalIDs,
		}
		setOpts := CompileSetOptions{
			// Set-level LikelyMode precedence: set hints > neutral.
			// Used by H.3 (frontend density gate).
			LikelyMode: resolveHints(sc.Hints),
		}
		if !standalone {
			setOpts.TableMemIdx = 1
		}
		setOpts.TableBase = int32(setTableBase)
		cs := CompileSet(spec, &prefixPool, &suffixPool, setOpts)
		compiledSets = append(compiledSets, cs)
		setTableBase += int64(len(cs.dataBytes)) + int64(len(cs.prefixDataBytes)) +
			int64(len(cs.acDataBytes)) + int64(len(cs.teddyDataBytes)) +
			int64(len(cs.anchoredDataBytes))
	}

	// Compute required memory pages from the largest data address used.
	// setTableBase already holds the end of all set data (per-set accumulation above).
	dataTop := lastTableEnd
	if setTableBase > dataTop {
		dataTop = setTableBase
	}
	var memPages int32 = 1
	if dataTop > 0 {
		memPages = int32((dataTop + 65535) / 65536)
		if memPages < 1 {
			memPages = 1
		}
	}
	if standalone && memPages < 1 {
		memPages = 1
	} else if !standalone && lastTableEnd == 0 && setTableBase == 0 {
		memPages = 1
	}
	return assembleModuleWithSets(compiled, compiledSets, memPages, standalone), lastTableEnd, nil
}

// assembleModuleWithSets builds a WASM module from per-pattern compilations
// plus per-set compiled sets. When sets is empty it produces the same bytes
// as assembleModule.
func assembleModuleWithSets(patterns []*compiledPattern, sets []*compiledSet, memPages int32, standalone bool) []byte {
	if len(sets) == 0 {
		return assembleModule(patterns, memPages, standalone)
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
		totalSegs += cs.dataSegCount + cs.prefixDataSegCount + cs.acDataSegCount +
			cs.teddyDataSegCount + cs.anchoredDataSegs
		rawData = append(rawData, cs.dataBytes...)
		rawData = append(rawData, cs.prefixDataBytes...)
		rawData = append(rawData, cs.acDataBytes...)
		rawData = append(rawData, cs.teddyDataBytes...)
		rawData = append(rawData, cs.anchoredDataBytes...)
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

	// Type section: 7 types.
	// 0: (i32,i32)→i32          match/backward-prefix
	// 1: (i32,i32)→i64          find
	// 2: (i32,i32,i32)→i32      capture/groups
	// 3: (i32×7)→i32            suffix DFA (ptr,start,len,lPos,out_ptr,out_cap,validMask)→count
	// 4: (i32,i32)→i32          prefix backward DFA (same as 0, kept for clarity)
	// 5: (i32×5)→i32            set find body, overlapping: true
	// 6: (i32×4)→i32            bucket probe / bitmap-form _all
	// 7: (i32×3)→i64            scan_any, scan_all (<= 64 patterns)
	// 8: (i32×6)→i32            set find body, gated (default)
	// 9: (i32×8)→i32            suffix DFA with a gate pointer
	typeSection := []byte{
		0x0A,
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
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(total))
	for _, p := range patterns {
		if p.matchBody != nil {
			fs = append(fs, 0x00)
		}
		if p.litAnchorBackScanBody != nil {
			fs = append(fs, 0x00)
			fs = append(fs, 0x01)
		} else if p.findBody != nil {
			fs = append(fs, 0x01)
		}
		if p.captureBody != nil {
			fs = append(fs, 0x02)
			if !p.anchored {
				fs = append(fs, 0x02)
			}
			if p.namedGroupsExport != "" {
				fs = append(fs, 0x02)
			}
		}
		// Batch find/groups wrapper (task 44): same signature as the set
		// match body — (i32,i32,i32,i32,i32)→i32 — so it reuses type 5
		// rather than needing a dedicated type.
		if p.batchFindExport != "" {
			fs = append(fs, byte(setMatchTypeMatch))
		}
		if p.batchGroupsExport != "" {
			fs = append(fs, byte(setMatchTypeMatch))
		}
	}
	for _, cs := range sets {
		for _, c := range cs.capFns() {
			fs = append(fs, c.typeIdx)
		}
		suffixType := byte(setMatchTypeSuffix)
		if cs.gatedFind() {
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
		for range cs.anchoredProbeBodies {
			fs = append(fs, byte(setTypeI32x4ToI32))
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

	// Export section.
	numExports := 0
	if standalone {
		numExports++
	}
	for _, p := range patterns {
		if p.matchExport != "" {
			numExports++
		}
		if p.findExport != "" {
			numExports++
		}
		if p.groupsExport != "" {
			numExports++
		}
		if p.namedGroupsExport != "" {
			numExports++
		}
		if p.batchFindExport != "" {
			numExports++
		}
		if p.batchGroupsExport != "" {
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
		matchOff, _, findOff, captureOff, wrapperOff, namedWrapperOff := p.offsets()
		if p.matchExport != "" && matchOff >= 0 {
			es = appendString(es, p.matchExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+matchOff))
		}
		if p.findExport != "" && findOff >= 0 {
			es = appendString(es, p.findExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+findOff))
		}
		if p.groupsExport != "" {
			var groupsFuncIdx int
			if p.anchored {
				groupsFuncIdx = base + captureOff
			} else {
				groupsFuncIdx = base + wrapperOff
			}
			es = appendString(es, p.groupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(groupsFuncIdx))
		}
		if p.namedGroupsExport != "" && namedWrapperOff >= 0 {
			es = appendString(es, p.namedGroupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+namedWrapperOff))
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
		_, backwardScanOff, findOff, captureOff, wrapperOff, _ := p.offsets()
		if p.matchBody != nil {
			cs_bytes = append(cs_bytes, p.matchBody...)
		}
		if p.litAnchorBackScanBody != nil {
			cs_bytes = append(cs_bytes, p.litAnchorBackScanBody...)
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			litAnchorFindBody := buildLitAnchorFindBody(p.litAnchorFindTable, p.litAnchorFindLayout, p, base+backwardScanOff, tableMemIdx)
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
				if p.namedGroupsExport != "" {
					cs_bytes = appendNamedGroupsWrapperCodeEntry(cs_bytes, base+wrapperOff)
				}
			} else if p.namedGroupsExport != "" {
				cs_bytes = appendNamedGroupsWrapperCodeEntry(cs_bytes, base+captureOff)
			}
		}
		if p.batchFindExport != "" {
			cs_bytes = appendBatchFindWrapperCodeEntry(cs_bytes, base+findOff)
		}
		if p.batchGroupsExport != "" {
			if p.anchored {
				cs_bytes = appendBatchLitChainGroupsWrapperCodeEntry(cs_bytes, base+captureOff, p.numGroups)
			} else {
				batchTableMemIdx := 0
				if !standalone {
					batchTableMemIdx = 1
				}
				winOff := int32(-1)
				if !p.isTDFA {
					winOff = p.winScratchOff
				}
				cs_bytes = appendBatchGroupsWrapperCodeEntry(cs_bytes, base+findOff, base+captureOff, p.numGroups, batchTableMemIdx, winOff)
			}
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
				cs_bytes = append(cs_bytes, rebuildSetMatchBody(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx)...)
			case capMatch, capMatchAny, capMatchAll:
				cs_bytes = append(cs_bytes, emitSetAnchoredCapBody(cs, c.kind, anchoredProbeBase)...)
			default:
				body := emitSetMatchFnFinal(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx, c.kind, scanProbeBase)
				cs_bytes = append(cs_bytes, body...)
			}
		}
		for _, sfn := range cs.suffixFnBodies {
			cs_bytes = append(cs_bytes, sfn...)
		}
		for _, pfn := range cs.prefixFnBodies {
			cs_bytes = append(cs_bytes, pfn...)
		}
		for _, pb := range cs.scanProbeBodies {
			cs_bytes = append(cs_bytes, pb...)
		}
		for _, pb := range cs.anchoredProbeBodies {
			cs_bytes = append(cs_bytes, pb...)
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
	}
	return emitSetMatchFnFinalScalar(cs, suffixFnBase, prefixFnBaseIdx, mode, probeFnBase)
}

// hasSetFallbackBuckets reports whether any bucket in the set is a fallback (no literal gate).
func hasSetFallbackBuckets(cs *compiledSet) bool {
	for _, bkt := range cs.buckets {
		if bkt.isFallback {
			return true
		}
	}
	return false
}

// emitSetMatchFnFinalScalar emits the scalar (byte-by-byte) set `find` body.
//
// Signature (plans/SETS.md §4.1): (ptr, len, from, out_ptr, out_cap) -> i32,
// returning the TOTAL number of matches at the first matching position at or
// after `from`. See compile/set_find.go for the first-position machinery.
func emitSetMatchFnFinalScalar(cs *compiledSet, suffixFnBase, prefixFnBaseIdx int, mode setCapKind, probeFnBase int) []byte {
	var b []byte
	// locals: 8 x i32, then the scan_all i64 accumulator.
	b = append(b, 0x02, 0x08, 0x7F, 0x01, 0x7E)

	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	c.perPositionDrain = true
	c.lAcc = c.localBase + 8
	lPos := c.lPos
	pInPtr, pInLen := c.pInPtr, c.pInLen

	b = c.emitFindPrologue(b, lPos)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $scan

	// lPos > pInLen: allows position 0 to be processed on empty input (pInLen=0),
	// so patterns like (aa)* that match "" get their zero-length match at position 0.
	// Position pInLen is processed once (for EOF-anchored patterns like (aa)*$);
	// buildSetSuffixBody's eofBitmaskOff table (paired with newDFA's bootstrap-alias
	// guard giving midStart its own correct accept bits) avoids false positives.
	// An out-of-range `from` (> len) lands here on the first iteration and returns
	// 0, which is the §4.2 contract.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen (i32.gt_u)
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Fallback buckets first: they have no literal gate, so they must be
	// evaluated at every position.
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback {
			continue
		}
		b = c.emitBucketAt(b, bi, 0, lPos)
	}

	for _, bi := range litOrderFor(cs) {
		bkt := cs.buckets[bi]
		lit := []byte(bkt.literal)
		litLen := len(lit)

		b = append(b, 0x02, 0x40) // block $skip_bucket
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00)

		for li, lb := range lit {
			b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
			if li > 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(li))
				b = append(b, 0x6A)
			}
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00)
		}

		b = c.emitBucketAt(b, bi, litLen, lPos)

		b = append(b, 0x0B) // end block $skip_bucket
	}

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
// Shufti first-byte pre-filter (LIKELY.md Gap H.3). The per-position bucket
// check is identical to the scalar path — the only addition is a 16-bytes-
// per-chunk SIMD skip loop at the top of each iteration that advances lPos
// to the next position where any literal's first byte appears.
//
// Selection in CompileSet guarantees:
//   - no fallback buckets (otherwise we'd need to visit every position),
//   - 17 ≤ |shuftiFirstByteSet| ≤ 64 (matches emitShuftiPrefixCheck's bounds),
//   - rarity-based density supports Shufti OR set-level LikelyNoMatch is set.
//
// When cs.shuftiAdaptive (task 28 — ported from EmitPrefixScan's task 25
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
	// + task 28: 2 × i32 (lDenseCounter, lDenseSkipFlag) when adaptive,
	// + 3 × i32 (lMinStart, lBase, lStart) for the §9.4 first-position state.
	if adaptive {
		b = append(b, 0x05)       // 5 local groups
		b = append(b, 0x06, 0x7F) // 6 × i32
		b = append(b, 0x01, 0x7B) // 1 × v128
		b = append(b, 0x02, 0x7F) // 2 × i32
		b = append(b, 0x03, 0x7F) // 3 × i32
		b = append(b, 0x01, 0x7E) // 1 × i64 (scan_all accumulator)
	} else {
		b = append(b, 0x04)       // 4 local groups
		b = append(b, 0x06, 0x7F) // 6 × i32
		b = append(b, 0x01, 0x7B) // 1 × v128
		b = append(b, 0x03, 0x7F) // 3 × i32
		b = append(b, 0x01, 0x7E) // 1 × i64 (scan_all accumulator)
	}

	c := newSetFindCtx(cs, suffixFnBase, prefixFnBaseIdx, 0, mode, probeFnBase)
	c.perPositionDrain = true
	lPos, lTmp := c.lPos, c.lTmp
	pInPtr, pInLen := c.pInPtr, c.pInLen
	lSkipMask := c.localBase + 5
	lChunk := c.localBase + 6
	lDenseCounter := c.localBase + 7
	lDenseSkipFlag := c.localBase + 8
	// The §9.4 first-position locals go last so the v128 index is stable.
	c.lMinStart, c.lBase, c.lStart = c.localBase+7, c.localBase+8, c.localBase+9
	c.lAcc = c.localBase + 10
	if adaptive {
		c.lMinStart, c.lBase, c.lStart = c.localBase+9, c.localBase+10, c.localBase+11
		c.lAcc = c.localBase + 12
	}

	b = c.emitFindPrologue(b, lPos)
	if adaptive {
		b = append(b, 0x41, 0x00, 0x21, lDenseCounter) // DenseCounter = 0
	}

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	// Exit conditions.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen
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
	b = append(b, 0x03, 0x40) // loop $skip_loop

	// If lPos >= pInLen: exit $skip_done.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)

	if adaptive {
		// Task 28: DenseCounter < threshold? If so, try SIMD (+ its scalar
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
	}

	// SIMD path: lPos + 15 < pInLen → load 16 bytes.
	// Depths inside this `if` (innermost outward), non-adaptive:
	//   0=SIMD if, 1=$skip_loop, 2=$skip_done.
	// Adaptive adds $dense_gate between SIMD-if and $skip_loop/$skip_done.
	b = append(b, 0x20, lPos, 0x41, 15, 0x6A, 0x20, pInLen, 0x49) // lt_u
	b = append(b, 0x04, 0x40)                                     // if (void)
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)                 // pInPtr + lPos
	b = append(b, 0xFD, 0x00, 0x00, 0x00)                         // v128.load align=0 offset=0
	b = append(b, 0x21, lChunk)                                   // local.set lChunk
	b = emitShuftiPrefixCheck(b, cs.shuftiFirstByteSet, lChunk)
	b = append(b, 0x22, lSkipMask) // local.tee lSkipMask
	b = append(b, 0x04, 0x40)      // if mask != 0  (adds one more depth)
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
	if adaptive {
		b = append(b, 0x0C, 0x04) // br 4 → $skip_done
	} else {
		b = append(b, 0x0C, 0x03) // br 3 → $skip_done
	}
	b = append(b, 0x0B) // end if mask != 0
	// No candidate in chunk: lPos += 16, continue $skip_loop.
	if adaptive {
		b = append(b, 0x41, 0x01)
		b = append(b, 0x21, lDenseSkipFlag) // this attempt did skip ≥16 bytes
	}
	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)
	if adaptive {
		b = append(b, 0x0C, 0x02) // br 2 → $skip_loop (SIMD if, $dense_gate, $skip_loop)
	} else {
		b = append(b, 0x0C, 0x01) // br 1 → $skip_loop
	}
	b = append(b, 0x0B) // end if SIMD path

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
		b = append(b, 0x05)       // else
		b = append(b, 0x0C, 0x02) // br 2 → $skip_done
		b = append(b, 0x0B)       // end if $dense_gate
	}

	b = append(b, 0x0B) // end loop $skip_loop
	b = append(b, 0x0B) // end block $skip_done

	// Re-check bounds: prefilter may have walked to lPos >= pInLen with no hit.
	// $batch_done is at depth 1 from loop $scan.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)
	// The prefilter also moved lPos past the drain bound checked at the top of
	// $scan, so re-check it here — that is what keeps perPositionDrain true for
	// this body (the bucket work below sees exactly one candidate position).
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Literal buckets only (selection requires no fallback). Shortest literal
	// first for the same ordering reason as the scalar path.
	for _, bi := range litOrderFor(cs) {
		bkt := cs.buckets[bi]
		lit := []byte(bkt.literal)
		litLen := len(lit)

		b = append(b, 0x02, 0x40) // block $skip_bucket
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00)

		for li, lb := range lit {
			b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
			if li > 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(li))
				b = append(b, 0x6A)
			}
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00)
		}

		b = c.emitBucketAt(b, bi, litLen, lPos)

		b = append(b, 0x0B) // end block $skip_bucket
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
	b = append(b, 0x0C, 0x00)                               // br $scan
	b = append(b, 0x0B)                                     // end loop $scan
	b = append(b, 0x0B)                                     // end block $batch_done

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
	// The §9.4 first-position locals go in their own trailing group so the
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

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	// Exit conditions
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen → br $batch_done
	b = c.emitDrainCheck(b, lPos, 0x01)

	// Fallback buckets at every position
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback {
			continue
		}
		b = c.emitBucketAt(b, bi, 0, lPos)
	}

	// AC transition: only when lPos < pInLen (there is a byte to consume)
	b = append(b, 0x02, 0x40)                                 // block $end_ac_pos
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x00) // lPos >= pInLen → br 0 (skip)

	// SIMD first-byte prefilter: when at root state, fast-skip to next candidate position.
	// Only emitted when there are no fallback buckets (those require visiting every position).
	// Block structure (depths from inside loop $skip_loop):
	//   block $skip_done (1), loop $skip_loop (0)
	//   Inside if(SIMD): depths are 0=if, 1=loop, 2=$skip_done
	//   Inside if(mask): depths are 0=if, 1=outer_if, 2=loop, 3=$skip_done
	if usePrefilter {
		b = append(b, 0x20, lACState, 0x45, 0x04, 0x40) // if lACState == 0 (eqz; if)

		b = append(b, 0x02, 0x40) // block $skip_done
		b = append(b, 0x03, 0x40) // loop $skip_loop

		// Exhaustion check: if lPos >= pInLen → br 1 → exit $skip_done
		b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)

		// SIMD path: if lPos + 15 < pInLen
		b = append(b, 0x20, lPos, 0x41, 15, 0x6A, 0x20, pInLen, 0x49) // lt_u
		b = append(b, 0x04, 0x40)                                     // if (void)

		// Load 16-byte chunk from memory[0] (input)
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
		b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
		b = append(b, 0x22, lChunk)           // local.tee lChunk

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
		b = append(b, 0x22, lSkipMask) // local.tee lSkipMask

		// if mask != 0: candidate found at lPos + ctz(mask)
		b = append(b, 0x04, 0x40)                                          // if (void)
		b = append(b, 0x20, lPos, 0x20, lSkipMask, 0x68, 0x6A, 0x21, lPos) // lPos += ctz(mask)
		b = append(b, 0x0C, 0x03)                                          // br 3 → $skip_done
		b = append(b, 0x0B)                                                // end if mask

		// No candidate: advance 16 and restart
		b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos) // lPos += 16
		b = append(b, 0x0C, 0x01)                               // br 1 → restart $skip_loop
		b = append(b, 0x0B)                                     // end if (SIMD path)

		// Scalar tail: check firstByteFlags[input[lPos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, cs.acFirstByteFlagsOff)              // firstByteFlags base
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x2D, 0x00, 0x00) // + input[lPos]
		b = append(b, 0x6A)                                             // add → flags address
		b = appendTableLoad8u(b, tableMemIdx)                           // load flag byte
		b = append(b, 0x04, 0x40)                                       // if (void) non-zero
		b = append(b, 0x0C, 0x02)                                       // br 2 → $skip_done (candidate at lPos)
		b = append(b, 0x0B)                                             // end if

		b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
		b = append(b, 0x0C, 0x00)                               // br 0 → restart $skip_loop
		b = append(b, 0x0B)                                     // end loop $skip_loop
		b = append(b, 0x0B)                                     // end block $skip_done

		b = append(b, 0x0B) // end if lACState == 0

		// Re-check bounds: prefilter may have exhausted input (lPos = pInLen)
		b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x00) // ge_u → br 0 → exit $end_ac_pos
	}

	// lACState = goto_table[lACState * 512 + input[lPos] * 2] as u16
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, acL.gotoOff)
	b = append(b, 0x20, lACState, 0x41, 0x09, 0x74, 0x6A) // + lACState * 512
	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)         // pInPtr + lPos
	b = append(b, 0x2D, 0x00, 0x00)                       // i32.load8_u 0 0 (input byte, memory 0)
	b = append(b, 0x41, 0x01, 0x74, 0x6A)                 // * 2; add
	b = appendTableLoad16u(b, tableMemIdx)
	b = append(b, 0x21, lACState)

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
	b = append(b, 0x02, 0x40)                                       // block $no_output
	b = append(b, 0x03, 0x40)                                       // loop $outputs
	b = append(b, 0x20, lOutIdx, 0x20, lACOutEnd, 0x4F, 0x0D, 0x01) // ge_u → br_if 1 ($no_output)

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
		b = append(b, 0x02, 0x40) // block $end
		b = append(b, 0x02, 0x40) // block $default
		for i := 0; i < K; i++ {  // K nested case blocks
			b = append(b, 0x02, 0x40)
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
		b = append(b, 0x0B) // end $end
	}

	b = append(b, 0x0C, 0x00) // br 0 → restart $outputs
	b = append(b, 0x0B)       // end loop $outputs
	b = append(b, 0x0B)       // end block $no_output
	b = append(b, 0x0B)       // end block $end_ac_pos

	// lPos++; restart loop
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00) // br 0 → restart $scan
	b = append(b, 0x0B)       // end loop $scan
	b = append(b, 0x0B)       // end block $batch_done
	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitExtractLane emits a 16-way br_table dispatch that extracts the byte at lane
// lLaneOff (runtime, 0-15) from v128 local lCands, storing the result in lLaneBit.
func emitExtractLane(b []byte, lCands, lLaneOff, lLaneBit byte) []byte {
	const N = 16
	b = append(b, 0x02, 0x40) // block $end_extract
	for i := 0; i < N; i++ {
		b = append(b, 0x02, 0x40) // block B[i]
	}
	// br_table: case k → depth k; default → N-1
	b = append(b, 0x20, lLaneOff)
	b = append(b, 0x0E)
	b = utils.AppendULEB128(b, uint32(N))
	for i := 0; i < N; i++ {
		b = utils.AppendULEB128(b, uint32(i))
	}
	b = utils.AppendULEB128(b, uint32(N-1)) // default → case 15
	for k := 0; k < N; k++ {
		b = append(b, 0x0B) // end B[k] → handler k falls through
		b = append(b, 0x20, lCands)
		b = append(b, 0xFD, 0x16, byte(k)) // i8x16.extract_lane_u k
		b = append(b, 0x21, lLaneBit)
		if k < N-1 {
			b = append(b, 0x0C, byte(N-1-k)) // br to $end_extract
		}
	}
	b = append(b, 0x0B) // end block $end_extract
	return b
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

	// The §9.4 first-position locals sit after the v128 group so the v128
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
		numInGroup := len(tt.LaneToID) - groupOffset
		if numInGroup > 8 {
			numInGroup = 8
		}
		b = append(b, 0x02, 0x40)                            // block $lit_bits_done
		b = append(b, 0x03, 0x40)                            // loop $lit_bits
		b = append(b, 0x20, lLaneBitLocal, 0x45, 0x0D, 0x01) // i32.eqz → $lit_bits_done

		b = append(b, 0x20, lLaneBitLocal, 0x68, 0x21, lLaneOff)                                             // ctz
		b = append(b, 0x20, lLaneBitLocal, 0x20, lLaneBitLocal, 0x41, 0x01, 0x6B, 0x71, 0x21, lLaneBitLocal) // clear bit

		for k := 0; k < numInGroup; k++ {
			litID := tt.LaneToID[groupOffset+k]
			litLen := cs.litLens[litID]
			fullLit := litStr[litID]

			b = append(b, 0x20, lLaneOff, 0x41)
			b = utils.AppendSLEB128(b, int32(k))
			b = append(b, 0x46, 0x04, 0x40) // i32.eq; if

			if litLen > tt.MinLen {
				// Wrap in block so tail-verification can break out on mismatch.
				b = append(b, 0x02, 0x40) // block $tail_ok
				// Fit check: lMatchPos + litLen > pInLen → skip
				b = append(b, 0x20, lMatchPos, 0x41)
				b = utils.AppendSLEB128(b, int32(litLen))
				b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00) // gt_u → br 0 ($tail_ok)
				// Verify tail bytes MinLen..litLen-1
				for j := tt.MinLen; j < litLen; j++ {
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

	// Group A dispatch
	b = emitExtractLane(b, lCands, lLaneOff, lLaneBit)
	b = emitLitDispatch(b, 0, lLaneBit)

	// Group B dispatch (if TwoGroups)
	if tt.TwoGroups {
		b = emitExtractLane(b, lCandsB, lLaneOff, lLaneBitB)
		b = emitLitDispatch(b, 8, lLaneBitB)
	}

	b = append(b, 0x0C, 0x00) // br 0 → restart $lanes
	b = append(b, 0x0B)       // end loop $lanes
	b = append(b, 0x0B)       // end block $lanes_done

	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x01) // br 1 → restart $scan
	b = append(b, 0x0B)       // end block $not_simd

	// Scalar tail: check each literal at lPos
	for _, bi := range litOrderFor(cs) {
		bkt := cs.buckets[bi]
		lit := []byte(bkt.literal)
		litLen := len(lit)
		b = append(b, 0x02, 0x40)
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00)
		for li, lb := range lit {
			b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
			if li > 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(li))
				b = append(b, 0x6A)
			}
			b = append(b, 0x2D, 0x00, 0x00, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00)
		}
		b = c.emitBucketAt(b, bi, litLen, lPos)
		b = append(b, 0x0B)
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $scan
	b = append(b, 0x0B) // end block $batch_done
	b = c.emitGateWriteback(b, lPos)
	b = c.emitEpilogue(b)
	b = append(b, 0x0B)

	_ = lChunk1
	_ = lChunk2
	_ = lChunk3
	_ = lT3Lo
	_ = lT3Hi
	_ = lBT3Lo
	_ = lBT3Hi
	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}
