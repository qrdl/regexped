package compile

import (
	"sort"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Phase 4c: per-set WASM compilation

// compiledSet is the WASM artefact for one `sets:` entry.
// The match function body is not stored here — it is built at assemble time
// (when function-table indices are known) by emitSetMatchFnFinal.
type compiledSet struct {
	name    string
	findAny string // WASM export name, or ""
	findAll string // WASM export name, or ""
	match   string // WASM export name for anchored match, or ""

	// suffixFnBodies[i] is the body for bucket i's suffix DFA function.
	suffixFnBodies [][]byte

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

	// startAnchorMasks[bi]: bitmask of patterns that have a ^ anchor (only valid at lPos==0).
	startAnchorMasks []uint32

	// varLenMasks[bi]: bitmask of patterns with variable-length prefix and empty suffix.
	// These are handled by direct tuple write in emitComputeValidMask, not via suffix DFA.
	varLenMasks []uint32

	// varLenNonemptyMasks[bi]: bitmask of patterns with variable-length prefix + non-empty suffix.
	// These call the suffix DFA individually with corrected paramLPos (= backward DFA result).
	varLenNonemptyMasks []uint32

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

	// litToBuckets[litID] = list of bucket indices sharing this literal.
	// Multiple buckets can share a literal when bin-packing splits large groups.
	litToBuckets [][]int
	litLens      []int

	// Diagnostics.
	diag *SetDiag
}

// funcCount returns the number of WASM functions contributed by this compiled set.
// = find fn (if findAny or findAll set) + anchored fn (if match set) + N suffix fns + M prefix fns.
func (cs *compiledSet) funcCount() int {
	n := cs.numSuffixFns + len(cs.prefixFnBodies)
	if cs.findAny != "" || cs.findAll != "" {
		n++
	}
	if cs.match != "" {
		n++
	}
	return n
}

// findFnOffset returns the index of the find function within this set's functions
// (relative to the set's base), or -1 if there is no find function.
func (cs *compiledSet) findFnOffset() int {
	if cs.findAny != "" || cs.findAll != "" {
		return 0
	}
	return -1
}

// matchFnOffset returns the index of the anchored match function within this set's
// functions (relative to the set's base), or -1 if there is no match function.
func (cs *compiledSet) matchFnOffset() int {
	if cs.match == "" {
		return -1
	}
	off := 0
	if cs.findAny != "" || cs.findAll != "" {
		off++
	}
	return off
}

// suffixFnBaseOffset returns the index of the first suffix function within this
// set's functions (relative to the set's base).
func (cs *compiledSet) suffixFnBaseOffset() int {
	off := 0
	if cs.findAny != "" || cs.findAll != "" {
		off++
	}
	if cs.match != "" {
		off++
	}
	return off
}

// CompileSetOptions resolved defaults.
const (
	setMatchTypeSuffix = 3 // type index for suffix DFA fn: (i32,i32,i32)→i64
	setMatchTypeMatch  = 5 // type index for set match fn:   (i32,i32,i32,i32,i32)→i32
)

// SetSpec is the resolved specification for one set, ready for compilation.
type SetSpec struct {
	Name       string
	FindAny    string
	FindAll    string
	Match      string         // anchored match export name, or ""
	Patterns   []*PatternInfo // resolved, capture-bearing dropped
	PatternIDs []int          // global indices into the regexps list
}

// CompileSet compiles one set specification into a compiledSet.
// prefixPool and suffixPool are shared dedup pools across all sets in the file.
func CompileSet(spec SetSpec, prefixPool, suffixPool *dfaPool, opts CompileSetOptions) (*compiledSet, error) {
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
	diag.Frontend = fe.String()

	// First pass: compute per-bucket prefix metadata (before building suffix DFAs).
	prefixFnIdx := make([][]int, len(buckets))
	prefixFixedLens := make([][]int, len(buckets))
	trivialPrefixMasks := make([]uint32, len(buckets))
	startAnchorMasks := make([]uint32, len(buckets))
	varLenMasks := make([]uint32, len(buckets))
	varLenNonemptyMasks := make([]uint32, len(buckets))

	var prefixFnBodies [][]byte
	var prefixDataBytes []byte
	var prefixDataSegCount int
	prefixPoolToFnIdx := make(map[int]int) // prefixID → index in prefixFnBodies
	// prefixTableOffset is set after suffix DFA data; computed after suffix loop below.

	// Pre-compute prefix metadata but defer prefix DFA body generation until after suffix DFAs.
	for bi, bkt := range buckets {
		idxes := make([]int, len(bkt.patterns))
		pml := make([]int, len(bkt.patterns))
		var tm, sam, vlm, vlnm uint32
		for j, p := range bkt.patterns {
			if j >= 32 {
				idxes[j] = -1
				continue
			}
			if p.startAnchor {
				sam |= uint32(1) << uint(j)
			}
			if p.trivialPrefix || p.prefixDFA == nil {
				idxes[j] = -1
				tm |= uint32(1) << uint(j)
				// pml[j] = 0 (trivial)
			} else if p.varLenEmptySuffix {
				idxes[j] = p.prefixID
				vlm |= uint32(1) << uint(j)
				// pml[j] = 0 (variable-length, handled via direct tuple write)
			} else if p.varLenNonEmptySuffix {
				idxes[j] = p.prefixID
				vlnm |= uint32(1) << uint(j)
				// pml[j] = 0 (variable-length, handled via individual suffix DFA call)
			} else {
				idxes[j] = p.prefixID
				if p.prefixMinLen > 0 && p.prefixMinLen == p.prefixMaxLen {
					pml[j] = p.prefixMaxLen
				}
			}
		}
		prefixFnIdx[bi] = idxes
		prefixFixedLens[bi] = pml
		trivialPrefixMasks[bi] = tm
		startAnchorMasks[bi] = sam
		varLenMasks[bi] = vlm
		varLenNonemptyMasks[bi] = vlnm
	}

	// Build suffix DFA function bodies, one per bucket.
	// The suffix DFA now writes match tuples directly (Option C); no startMask needed.
	suffixFnBodies := make([][]byte, len(buckets))
	var allDataBytes []byte
	var totalDataSegs int
	var tableOffset int32 = 0 // data segment base for this set's tables

	for bi, bkt := range buckets {
		fnBody, dataBytes, dataSegs := genSuffixWASM(bkt.suffixDFA, int64(tableOffset), opts.TableMemIdx, patternIDs[bi], prefixFixedLens[bi])
		suffixFnBodies[bi] = fnBody
		tableOffset += int32(len(dataBytes))
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
				revL := buildDFALayout(p.prefixDFA, int64(prefixTableOffset), false, false, 0)
				body := buildLitAnchorBackScanBody(revL, p.prefixDFA, opts.TableMemIdx)
				fnIdx = len(prefixFnBodies)
				prefixFnBodies = append(prefixFnBodies, body)
				prefixPoolToFnIdx[prefixID] = fnIdx
				rawPfx, cnt := stripSegCount(dfaDataSegments(revL, false))
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
			acDataSegCount = 3 // goto, failure, output segments

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
		tt, ok := buildTeddyTablesMulti(lits)
		if ok {
			teddyTabs = tt
			teddyDataOffset = prefixTableOffset
			rawTeddy := buildTeddyRawBytes(tt)
			teddyDataBytes = appendDataSegment(nil, teddyDataOffset, rawTeddy)
			teddyDataSegCount = 1
		} else {
			fe = frontendScalar
		}
	}

	// The set match function body is built at assemble time (when function table
	// indices are known). Store nil here; assembleModuleWithSets fills it in.
	cs := &compiledSet{
		name:                spec.Name,
		findAny:             spec.FindAny,
		findAll:             spec.FindAll,
		match:               spec.Match,
		suffixFnBodies:      suffixFnBodies,
		numSuffixFns:        len(suffixFnBodies),
		dataBytes:           allDataBytes,
		dataSegCount:        totalDataSegs,
		prefixFnBodies:      prefixFnBodies,
		prefixDataBytes:     prefixDataBytes,
		prefixDataSegCount:  prefixDataSegCount,
		prefixFnIdx:         prefixFnIdx,
		trivialPrefixMasks:  trivialPrefixMasks,
		startAnchorMasks:    startAnchorMasks,
		varLenMasks:         varLenMasks,
		varLenNonemptyMasks: varLenNonemptyMasks,
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
		litToBuckets:        litToBuckets,
		litLens:             litLens,
		diag:                diag,
	}
	return cs, nil
}

// emitSetMatchFnAnchored emits the WASM function body for the anchored `match`
// export. Signature: (in_ptr i32, in_len i32, out_ptr i32, out_cap i32) → i32.
//
// Checks each bucket's literal at position 0, then calls the suffix DFA which
// writes (patternID, matchStart=0, matchLength) tuples directly to out_ptr.
func emitSetMatchFnAnchored(cs *compiledSet, suffixFnBase int) []byte {
	const (
		pInPtr    = byte(0)
		pInLen    = byte(1)
		pOutPtr   = byte(2)
		pOutCap   = byte(3)
		lOutCount = byte(4)
	)
	var b []byte
	// 1 local: lOutCount i32
	b = append(b, 0x01, 0x01, 0x7F)

	b = append(b, 0x41, 0x00, 0x21, lOutCount) // lOutCount = 0

	for bi, bkt := range cs.buckets {
		lit := []byte(bkt.literal)
		litLen := len(lit)
		if !bkt.isFallback && litLen > 0 {
			// Check literal at position 0.
			b = append(b, 0x02, 0x40) // block $no_lit
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(litLen))
			b = append(b, 0x20, pInLen, 0x4B, 0x0D, 0x00) // litLen > len: br $no_lit
			for li, lb := range lit {
				b = append(b, 0x20, pInPtr)
				if li > 0 {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(li))
					b = append(b, 0x6A)
				}
				b = append(b, 0x2D, 0x00, 0x00) // i32.load8_u
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(lb))
				b = append(b, 0x47, 0x0D, 0x00) // i32.ne + br_if $no_lit
			}
			// For anchored match at position 0: prefix check not possible (nothing before pos 0).
			// validMask = trivial-prefix patterns only.
			validMask := int32(cs.trivialPrefixMasks[bi])
			b = append(b, 0x20, pInPtr)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(litLen)) // start = litLen
			b = append(b, 0x20, pInLen)
			b = append(b, 0x41, 0x00) // lPos = 0
			b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
			b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, validMask) // validMask (7th arg)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
			b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
			b = append(b, 0x0B) // end block $no_lit
		}
	}

	b = append(b, 0x20, lOutCount, 0x0B) // return lOutCount

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// appendTableLoad64 emits i64.load align=3 offset=0.
// tableMemIdx 0: 0x29 0x03 0x00. tableMemIdx 1: 0x29 0x43 0x01 0x00.
func appendTableLoad64(b []byte, tableMemIdx int) []byte {
	if tableMemIdx == 0 {
		return append(b, 0x29, 0x03, 0x00)
	}
	return append(b, 0x29, 0x43, byte(tableMemIdx), 0x00)
}

// --------------------------------------------------------------------------
// CompileFile — orchestrates all patterns and sets into one WASM module.

// CompileFile compiles all regex patterns and sets from cfg into a single WASM module.
// When cfg.Sets is empty, it is byte-identical to the existing Compile() path.
func CompileFile(cfg config.BuildConfig, output string) ([]byte, int64, error) {
	if err := config.ValidateSets(&cfg); err != nil {
		return nil, 0, err
	}

	standalone := cfg.Output == ""
	tableBase := int64(0)
	if !standalone {
		tableBase = 0
	}

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
	for _, re := range cfg.Regexes {
		p, err := compilePattern(re, tableBase, 0, opts)
		if err != nil {
			return nil, 0, err
		}
		tableBase = p.tableEnd
		compiled = append(compiled, p)
	}
	if len(compiled) > 0 {
		lastTableEnd = compiled[len(compiled)-1].tableEnd
	}

	// If no sets: same as Compile().
	if len(cfg.Sets) == 0 {
		var memPages int32 = 1
		if !standalone && lastTableEnd > 0 {
			memPages = int32((lastTableEnd + 65535) / 65536)
		}
		return assembleModule(compiled, memPages, standalone), lastTableEnd, nil
	}

	// Resolve and compile sets.
	// Build name→index map.
	nameIdx := make(map[string]int, len(cfg.Regexes))
	for i, re := range cfg.Regexes {
		if re.Name != "" {
			nameIdx[re.Name] = i
		}
	}

	var prefixPool, suffixPool dfaPool
	var compiledSets []*compiledSet
	for _, sc := range cfg.Sets {
		// Resolve patterns.
		var selectedIdx []int
		if sc.Patterns.All {
			for i := range cfg.Regexes {
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
			re := cfg.Regexes[idx]
			if re.CaptureStubsRequested() {
				continue // drop capture-bearing
			}
			info, err := analyzePattern(re, &prefixPool, &suffixPool)
			if err != nil {
				continue
			}
			infos = append(infos, info)
			globalIDs = append(globalIDs, idx)
		}

		spec := SetSpec{
			Name:       sc.Name,
			FindAny:    sc.FindAny,
			FindAll:    sc.FindAll,
			Match:      sc.Match,
			Patterns:   infos,
			PatternIDs: globalIDs,
		}
		setOpts := CompileSetOptions{}
		if !standalone {
			setOpts.TableMemIdx = 1
		}
		cs, err := CompileSet(spec, &prefixPool, &suffixPool, setOpts)
		if err != nil {
			return nil, 0, err
		}
		compiledSets = append(compiledSets, cs)
	}

	// Compute required memory pages from the largest data address used:
	// max(per-pattern tableEnd, total set DFA data bytes).
	totalSetData := int64(0)
	for _, cs := range compiledSets {
		totalSetData += int64(len(cs.dataBytes))
	}
	dataTop := lastTableEnd
	if totalSetData > dataTop {
		dataTop = totalSetData
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
	} else if !standalone && lastTableEnd == 0 && totalSetData == 0 {
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
		totalSegs += cs.dataSegCount + cs.prefixDataSegCount + cs.acDataSegCount + cs.teddyDataSegCount
		rawData = append(rawData, cs.dataBytes...)
		rawData = append(rawData, cs.prefixDataBytes...)
		rawData = append(rawData, cs.acDataBytes...)
		rawData = append(rawData, cs.teddyDataBytes...)
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
		prefixFnBase[si] = suffixFnBase[si] + cs.numSuffixFns
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
	// 5: (i32×5)→i32            find_any / find_all set match body
	// 6: (i32×4)→i32            anchored match body
	const setMatchTypeAnchored = 6
	typeSection := []byte{
		0x07,
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E, // type 1
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 2
		0x60, 0x07, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 3
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 4
		0x60, 0x05, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 5
		0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 6
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
	}
	for _, cs := range sets {
		if cs.findAny != "" || cs.findAll != "" {
			fs = append(fs, byte(setMatchTypeMatch)) // find fn: type 5
		}
		if cs.match != "" {
			fs = append(fs, byte(setMatchTypeAnchored)) // anchored fn: type 6
		}
		for range cs.suffixFnBodies {
			fs = append(fs, byte(setMatchTypeSuffix)) // suffix fn: type 3
		}
		for range cs.prefixFnBodies {
			fs = append(fs, 0x00) // prefix backward-scan fn: type 0 (i32,i32)→i32
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
	}
	for _, cs := range sets {
		if cs.findAny != "" {
			numExports++
		}
		if cs.findAll != "" {
			numExports++
		}
		if cs.match != "" {
			numExports++
		}
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
	}
	for si, cs := range sets {
		base := setBaseIdx[si]
		if cs.findFnOffset() >= 0 {
			findIdx := uint32(base + cs.findFnOffset())
			if cs.findAny != "" {
				es = appendString(es, cs.findAny)
				es = append(es, 0x00)
				es = utils.AppendULEB128(es, findIdx)
			}
			if cs.findAll != "" {
				es = appendString(es, cs.findAll)
				es = append(es, 0x00)
				es = utils.AppendULEB128(es, findIdx)
			}
		}
		if cs.matchFnOffset() >= 0 {
			es = appendString(es, cs.match)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+cs.matchFnOffset()))
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
				cs_bytes = appendWrapperCodeEntry(cs_bytes, base+findOff, base+captureOff, p.numGroups)
				if p.namedGroupsExport != "" {
					cs_bytes = appendNamedGroupsWrapperCodeEntry(cs_bytes, base+wrapperOff)
				}
			} else if p.namedGroupsExport != "" {
				cs_bytes = appendNamedGroupsWrapperCodeEntry(cs_bytes, base+captureOff)
			}
		}
	}
	// Set function bodies: find fn (if any), anchored match fn (if any), suffix DFA fns, prefix DFA fns.
	tableMemIdx := 0
	if !standalone {
		tableMemIdx = 1
	}
	for si, cs := range sets {
		if cs.findAny != "" || cs.findAll != "" {
			findBody := rebuildSetMatchBody(cs, suffixFnBase[si], prefixFnBase[si], tableMemIdx)
			cs_bytes = append(cs_bytes, findBody...)
		}
		if cs.match != "" {
			anchoredBody := emitSetMatchFnAnchored(cs, suffixFnBase[si])
			cs_bytes = append(cs_bytes, anchoredBody...)
		}
		for _, sfn := range cs.suffixFnBodies {
			cs_bytes = append(cs_bytes, sfn...)
		}
		for _, pfn := range cs.prefixFnBodies {
			cs_bytes = append(cs_bytes, pfn...)
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
	return emitSetMatchFnFinal(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx)
}

// emitSetMatchFnFinal dispatches to the appropriate scan implementation based on the
// frontend strategy chosen during compilation.
func emitSetMatchFnFinal(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	switch cs.fe {
	case frontendAC:
		return emitSetMatchFnFinalAC(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx)
	case frontendTeddy:
		if !hasSetFallbackBuckets(cs) {
			return emitSetMatchFnFinalTeddy(cs, suffixFnBase, prefixFnBaseIdx, tableMemIdx)
		}
	}
	return emitSetMatchFnFinalScalar(cs, suffixFnBase, prefixFnBaseIdx)
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

// emitSetMatchFnFinalScalar emits the scalar (byte-by-byte) set match function body.
// The suffix DFA functions write match tuples directly (Option C).
func emitSetMatchFnFinalScalar(cs *compiledSet, suffixFnBase int, prefixFnBaseIdx int) []byte {
	var b []byte
	// locals: 5 x i32 (lPos, lOutCount, lTmp, lValidMask, lOutBase)
	b = append(b, 0x01, 0x05, 0x7F)

	const (
		pInPtr     = byte(0)
		pInLen     = byte(1)
		pOutPtr    = byte(2)
		pOutCap    = byte(3)
		pStartPos  = byte(4)
		lPos       = byte(5)
		lOutCount  = byte(6)
		lTmp       = byte(7)
		lValidMask = byte(8)
		lOutBase   = byte(9)
	)

	b = append(b, 0x41, 0x00, 0x21, lOutCount)
	b = append(b, 0x20, pStartPos, 0x21, lPos)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	// lPos > pInLen: allows position 0 to be processed on empty input (pInLen=0),
	// so patterns like (aa)* that match "" get their zero-length match at position 0.
	// For non-empty inputs, position pInLen is processed once (for EOF-anchored patterns
	// like (aa)*$); the eofMidBitmask in buildSetSuffixBody avoids false positives.
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01) // lPos > pInLen (i32.gt_u)
	b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x4F, 0x0D, 0x01)

	// emitComputeValidMask: compute lValidMask for bucket bi.
	// Only handles trivial and fixed-length prefix patterns.
	// Variable-length prefix patterns are handled separately by emitVarLen (after the suffix DFA call).
	emitComputeValidMask := func(b []byte, bi int) []byte {
		tm := cs.trivialPrefixMasks[bi]
		sam := cs.startAnchorMasks[bi]
		tmNoAnchor := tm &^ sam
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(tmNoAnchor))
		b = append(b, 0x21, lValidMask)
		if sam != 0 {
			b = append(b, 0x20, lPos, 0x45, 0x04, 0x40) // if lPos==0
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(sam))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		// Fixed-length prefix patterns: call backward prefix DFA and set validMask bit.
		for k, fnIdx := range cs.prefixFnIdx[bi] {
			if k >= 32 || fnIdx < 0 {
				continue
			}
			bit := uint32(1) << uint(k)
			if cs.varLenMasks[bi]&bit != 0 || cs.varLenNonemptyMasks[bi]&bit != 0 {
				continue // handled by emitVarLen after suffix DFA call
			}
			globalIdx := prefixFnBaseIdx + fnIdx
			b = append(b, 0x20, pInPtr)
			b = append(b, 0x20, lPos)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(globalIdx))
			b = append(b, 0x22, lTmp)
			b = append(b, 0x41, 0x00)
			b = append(b, 0x4E) // result >= 0
			b = append(b, 0x04, 0x40)
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		return b
	}

	// emitVarLen: process variable-length prefix patterns for bucket bi.
	// Called AFTER emitCallSuffix so regular patterns get priority in the output buffer.
	emitVarLen := func(b []byte, bi int) []byte {
		if cs.varLenMasks[bi]|cs.varLenNonemptyMasks[bi] == 0 {
			return b
		}
		litLen := len(cs.buckets[bi].literal)
		for k, fnIdx := range cs.prefixFnIdx[bi] {
			if k >= 32 || fnIdx < 0 {
				continue
			}
			bit := uint32(1) << uint(k)
			isVarLenEmpty := cs.varLenMasks[bi]&bit != 0
			isVarLenNonempty := cs.varLenNonemptyMasks[bi]&bit != 0
			if !isVarLenEmpty && !isVarLenNonempty {
				continue
			}
			globalIdx := prefixFnBaseIdx + fnIdx
			b = append(b, 0x20, pInPtr)
			b = append(b, 0x20, lPos)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6B)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(globalIdx))
			b = append(b, 0x22, lTmp)
			b = append(b, 0x41, 0x00)
			b = append(b, 0x4E)
			b = append(b, 0x04, 0x40)
			if isVarLenEmpty {
				// Write tuple directly: matchStart=lTmp, matchEnd=lPos+litLen.
				b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x49, 0x04, 0x40)
				b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A, 0x21, lOutBase)
				b = append(b, 0x20, lOutBase, 0x41)
				b = utils.AppendSLEB128(b, int32(cs.patternIDs[bi][k]))
				b = append(b, 0x36, 0x02, 0x00)
				b = append(b, 0x20, lOutBase, 0x20, lTmp, 0x36, 0x02, 0x04)
				b = append(b, 0x20, lOutBase, 0x20, lPos, 0x41)
				b = utils.AppendSLEB128(b, int32(litLen))
				b = append(b, 0x6A, 0x20, lTmp, 0x6B, 0x36, 0x02, 0x08)
				b = append(b, 0x20, lOutCount, 0x41, 0x01, 0x6A, 0x21, lOutCount)
				b = append(b, 0x0B)
			} else {
				// Call suffix DFA with corrected lPos (= backward DFA result = matchStart).
				b = append(b, 0x20, pInPtr)
				b = append(b, 0x20, lPos, 0x41)
				b = utils.AppendSLEB128(b, int32(litLen))
				b = append(b, 0x6A)
				b = append(b, 0x20, pInLen)
				b = append(b, 0x20, lTmp) // corrected lPos
				b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
				b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(bit))
				b = append(b, 0x10)
				b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
				b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
			}
			b = append(b, 0x0B)
		}
		return b
	}

	// emitCallSuffix: direct call to suffix DFA (avoids call_indirect table issues on merge).
	emitCallSuffix := func(b []byte, litLen, bi int) []byte {
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A)
		b = append(b, 0x20, pInLen)
		b = append(b, 0x20, lPos)
		b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
		b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
		b = append(b, 0x20, lValidMask)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
		b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
		return b
	}

	// Fallback buckets first: their matches may have large lengths that would
	// advance startPos past later positions if processed last in a batch.
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback {
			continue
		}
		b = emitComputeValidMask(b, bi)
		b = emitCallSuffix(b, 0, bi)
		b = emitVarLen(b, bi)
	}

	// Literal buckets: single-char (litLen=1) first so their tuples are always
	// written before cap fills; longer literals after. The last tuple from a
	// single-char bucket has len=1 so the outer loop's startPos = lastStart+1,
	// never skipping positions that have only single-char matches (e.g. anchored $).
	litOrder := make([]int, 0, len(cs.buckets))
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback && bkt.literal != "" {
			litOrder = append(litOrder, bi)
		}
	}
	sort.SliceStable(litOrder, func(i, j int) bool {
		li := len(cs.buckets[litOrder[i]].literal)
		lj := len(cs.buckets[litOrder[j]].literal)
		if li != lj {
			return li < lj // single-char first, then multi-char
		}
		return litOrder[i] > litOrder[j] // within same length: reverse original order
		// binPack assigns buckets ascending by suffix states: the last bucket has
		// the highest-states (e.g. $-suffix) patterns. Processing them first
		// ensures anchor-only matches (which fire only at EOF) are always written
		// before the many empty-suffix patterns that consume capacity.
	})
	for _, bi := range litOrder {
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
			b = append(b, 0x2D, 0x00, 0x00)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x47, 0x0D, 0x00)
		}

		b = emitComputeValidMask(b, bi)
		b = emitCallSuffix(b, litLen, bi)
		b = emitVarLen(b, bi)

		b = append(b, 0x0B)
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B)
	b = append(b, 0x0B)

	b = append(b, 0x20, lOutCount, 0x0B)

	_ = lTmp
	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}

// emitSetMatchFnFinalAC emits the set match function body using an Aho-Corasick
// automaton for literal scanning. Replaces the O(n*m) scalar path with O(m) AC.
func emitSetMatchFnFinalAC(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	acL := cs.acL
	const (
		pInPtr     = byte(0)
		pInLen     = byte(1)
		pOutPtr    = byte(2)
		pOutCap    = byte(3)
		pStartPos  = byte(4)
		lPos       = byte(5)
		lOutCount  = byte(6)
		lTmp       = byte(7)
		lValidMask = byte(8)
		lOutBase   = byte(9)
		lACState   = byte(10)
		lMatchPos  = byte(11)
		lOutIdx    = byte(12)
		lACOutEnd  = byte(13)
		lLitID     = byte(14)
		// Prefilter locals (lSkipMask=15 i32, lChunk=16 v128; only used when prefilter emitted)
		lSkipMask = byte(15)
		lChunk    = byte(16)
	)

	// usePrefilter: apply SIMD first-byte prefilter when at root state and no fallback buckets.
	usePrefilter := !hasSetFallbackBuckets(cs) && len(cs.acFirstByteSet) > 0

	// Parameterised helpers (use posLocal instead of hardcoded lPos).
	emitValidMaskAt := func(b []byte, bi int, posLocal byte) []byte {
		tm := cs.trivialPrefixMasks[bi]
		sam := cs.startAnchorMasks[bi]
		tmNoAnchor := tm &^ sam
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(tmNoAnchor))
		b = append(b, 0x21, lValidMask)
		if sam != 0 {
			b = append(b, 0x20, posLocal, 0x45, 0x04, 0x40)
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(sam))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		for k, fnIdx := range cs.prefixFnIdx[bi] {
			if k >= 32 || fnIdx < 0 {
				continue
			}
			bit := uint32(1) << uint(k)
			if cs.varLenMasks[bi]&bit != 0 || cs.varLenNonemptyMasks[bi]&bit != 0 {
				continue
			}
			globalIdx := prefixFnBaseIdx + fnIdx
			b = append(b, 0x20, pInPtr, 0x20, posLocal, 0x41, 0x01, 0x6B)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(globalIdx))
			b = append(b, 0x22, lTmp, 0x41, 0x00, 0x4E, 0x04, 0x40)
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		return b
	}

	emitCallSuffixAt := func(b []byte, litLen, bi int, posLocal byte) []byte {
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, posLocal, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A) // posLocal + litLen
		b = append(b, 0x20, pInLen)
		b = append(b, 0x20, posLocal)
		b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
		b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
		b = append(b, 0x20, lValidMask)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
		b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
		return b
	}

	emitVarLenAt := func(b []byte, bi int, posLocal byte) []byte {
		if cs.varLenMasks[bi]|cs.varLenNonemptyMasks[bi] == 0 {
			return b
		}
		litLen := len(cs.buckets[bi].literal)
		for k, fnIdx := range cs.prefixFnIdx[bi] {
			if k >= 32 || fnIdx < 0 {
				continue
			}
			bit := uint32(1) << uint(k)
			isVarLenEmpty := cs.varLenMasks[bi]&bit != 0
			isVarLenNonempty := cs.varLenNonemptyMasks[bi]&bit != 0
			if !isVarLenEmpty && !isVarLenNonempty {
				continue
			}
			globalIdx := prefixFnBaseIdx + fnIdx
			b = append(b, 0x20, pInPtr, 0x20, posLocal, 0x41, 0x01, 0x6B)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(globalIdx))
			b = append(b, 0x22, lTmp, 0x41, 0x00, 0x4E, 0x04, 0x40)
			if isVarLenEmpty {
				b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x49, 0x04, 0x40)
				b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A, 0x21, lOutBase)
				b = append(b, 0x20, lOutBase, 0x41)
				b = utils.AppendSLEB128(b, int32(cs.patternIDs[bi][k]))
				b = append(b, 0x36, 0x02, 0x00)
				b = append(b, 0x20, lOutBase, 0x20, lTmp, 0x36, 0x02, 0x04)
				b = append(b, 0x20, lOutBase, 0x20, posLocal, 0x41)
				b = utils.AppendSLEB128(b, int32(litLen))
				b = append(b, 0x6A, 0x20, lTmp, 0x6B, 0x36, 0x02, 0x08)
				b = append(b, 0x20, lOutCount, 0x41, 0x01, 0x6A, 0x21, lOutCount)
				b = append(b, 0x0B)
			} else {
				b = append(b, 0x20, pInPtr)
				b = append(b, 0x20, posLocal, 0x41)
				b = utils.AppendSLEB128(b, int32(litLen))
				b = append(b, 0x6A)
				b = append(b, 0x20, pInLen, 0x20, lTmp)
				b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
				b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(bit))
				b = append(b, 0x10)
				b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
				b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
			}
			b = append(b, 0x0B)
		}
		return b
	}

	var b []byte
	if usePrefilter {
		// 11 i32 locals (5-15) + 1 v128 local (16)
		b = append(b, 0x02, 0x0B, 0x7F, 0x01, 0x7B)
	} else {
		// 10 i32 locals (5-14)
		b = append(b, 0x01, 0x0A, 0x7F)
	}

	// Init
	b = append(b, 0x41, 0x00, 0x21, lOutCount)
	b = append(b, 0x20, pStartPos, 0x21, lPos)
	b = append(b, 0x41, 0x00, 0x21, lACState)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	// Exit conditions
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01)       // lPos > pInLen → br $batch_done
	b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x4F, 0x0D, 0x01) // lOutCount >= pOutCap → br $batch_done

	// Fallback buckets at every position
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback {
			continue
		}
		b = emitValidMaskAt(b, bi, lPos)
		b = emitCallSuffixAt(b, 0, bi, lPos)
		b = emitVarLenAt(b, bi, lPos)
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
		b = append(b, 0x04, 0x40)                                        // if (void)

		// Load 16-byte chunk from memory[0] (input)
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
		b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
		b = append(b, 0x22, lChunk)            // local.tee lChunk

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
		b = append(b, 0x04, 0x40)                                                   // if (void)
		b = append(b, 0x20, lPos, 0x20, lSkipMask, 0x68, 0x6A, 0x21, lPos)         // lPos += ctz(mask)
		b = append(b, 0x0C, 0x03)                                                   // br 3 → $skip_done
		b = append(b, 0x0B)                                                          // end if mask

		// No candidate: advance 16 and restart
		b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos) // lPos += 16
		b = append(b, 0x0C, 0x01)                                 // br 1 → restart $skip_loop
		b = append(b, 0x0B)                                       // end if (SIMD path)

		// Scalar tail: check firstByteFlags[input[lPos]]
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, cs.acFirstByteFlagsOff)       // firstByteFlags base
		b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A, 0x2D, 0x00, 0x00) // + input[lPos]
		b = append(b, 0x6A)                                               // add → flags address
		b = appendTableLoad8u(b, tableMemIdx)                             // load flag byte
		b = append(b, 0x04, 0x40)                                         // if (void) non-zero
		b = append(b, 0x0C, 0x02)                                         // br 2 → $skip_done (candidate at lPos)
		b = append(b, 0x0B)                                               // end if

		b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos) // lPos++
		b = append(b, 0x0C, 0x00)                                 // br 0 → restart $skip_loop
		b = append(b, 0x0B)                                       // end loop $skip_loop
		b = append(b, 0x0B)                                       // end block $skip_done

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

	// Dispatch on lLitID: handle each literal ID (may dispatch to multiple buckets).
	for k, buckets := range cs.litToBuckets {
		litLen := cs.litLens[k]
		b = append(b, 0x20, lLitID, 0x41)
		b = utils.AppendSLEB128(b, int32(k))
		b = append(b, 0x46, 0x04, 0x40) // i32.eq; if
		// lMatchPos = lPos - (litLen - 1)
		if litLen <= 1 {
			b = append(b, 0x20, lPos, 0x21, lMatchPos)
		} else {
			b = append(b, 0x20, lPos, 0x41)
			b = utils.AppendSLEB128(b, int32(litLen-1))
			b = append(b, 0x6B, 0x21, lMatchPos)
		}
		for _, bucketIdx := range buckets {
			b = emitValidMaskAt(b, bucketIdx, lMatchPos)
			b = emitCallSuffixAt(b, litLen, bucketIdx, lMatchPos)
			b = emitVarLenAt(b, bucketIdx, lMatchPos)
		}
		b = append(b, 0x0B) // end if
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
	b = append(b, 0x20, lOutCount, 0x0B)

	_ = lTmp
	_ = lOutBase
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
func emitSetMatchFnFinalTeddy(cs *compiledSet, suffixFnBase, prefixFnBaseIdx, tableMemIdx int) []byte {
	tt := cs.teddyTabs
	const (
		pInPtr     = byte(0)
		pInLen     = byte(1)
		pOutPtr    = byte(2)
		pOutCap    = byte(3)
		pStartPos  = byte(4)
		lPos       = byte(5)
		lOutCount  = byte(6)
		lTmp       = byte(7)
		lValidMask = byte(8)
		lOutBase   = byte(9)
		lLaneMask  = byte(10)
		lMatchPos  = byte(11)
		lLaneBit   = byte(12) // Group A lane bit
		lLaneOff   = byte(13)
		lLaneBitB  = byte(14) // Group B lane bit (only used when TwoGroups)
	)
	// v128 locals start at index 15.
	v128Base := byte(15)
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

	// Collect literal strings for tail-byte verification.
	litStr := make([]string, len(cs.litToBuckets))
	for litID, buckets := range cs.litToBuckets {
		if len(buckets) > 0 {
			litStr[litID] = cs.buckets[buckets[0]].literal
		}
	}

	emitValidMaskAt := func(b []byte, bi int, posLocal byte) []byte {
		tm := cs.trivialPrefixMasks[bi]
		sam := cs.startAnchorMasks[bi]
		tmNoAnchor := tm &^ sam
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(tmNoAnchor))
		b = append(b, 0x21, lValidMask)
		if sam != 0 {
			b = append(b, 0x20, posLocal, 0x45, 0x04, 0x40)
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(sam))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		for k, fnIdx := range cs.prefixFnIdx[bi] {
			if k >= 32 || fnIdx < 0 {
				continue
			}
			bit := uint32(1) << uint(k)
			if cs.varLenMasks[bi]&bit != 0 || cs.varLenNonemptyMasks[bi]&bit != 0 {
				continue
			}
			globalIdx := prefixFnBaseIdx + fnIdx
			b = append(b, 0x20, pInPtr, 0x20, posLocal, 0x41, 0x01, 0x6B)
			b = append(b, 0x10)
			b = utils.AppendULEB128(b, uint32(globalIdx))
			b = append(b, 0x22, lTmp, 0x41, 0x00, 0x4E, 0x04, 0x40)
			b = append(b, 0x20, lValidMask, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x72, 0x21, lValidMask)
			b = append(b, 0x0B)
		}
		return b
	}
	emitCallSuffixAt := func(b []byte, litLen, bi int, posLocal byte) []byte {
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, posLocal, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A)
		b = append(b, 0x20, pInLen, 0x20, posLocal)
		b = append(b, 0x20, pOutPtr, 0x20, lOutCount, 0x41, 12, 0x6C, 0x6A)
		b = append(b, 0x20, pOutCap, 0x20, lOutCount, 0x6B)
		b = append(b, 0x20, lValidMask)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(suffixFnBase+bi))
		b = append(b, 0x20, lOutCount, 0x6A, 0x21, lOutCount)
		return b
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
					b = emitValidMaskAt(b, bi, lMatchPos)
					b = emitCallSuffixAt(b, litLen, bi, lMatchPos)
				}
				b = append(b, 0x0B) // end block $tail_ok
			} else {
				for _, bi := range cs.litToBuckets[litID] {
					b = emitValidMaskAt(b, bi, lMatchPos)
					b = emitCallSuffixAt(b, litLen, bi, lMatchPos)
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
	// 10 i32 locals (5-14) + numV128 v128 locals (15+)
	b = append(b, 0x02, 0x0A, 0x7F, byte(numV128), 0x7B)

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

	b = append(b, 0x41, 0x00, 0x21, lOutCount)
	b = append(b, 0x20, pStartPos, 0x21, lPos)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4B, 0x0D, 0x01)
	b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x4F, 0x0D, 0x01)

	minLen := tt.MinLen
	simdGuard := int32(minLen + 14)

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
	litOrder := make([]int, 0, len(cs.buckets))
	for bi, bkt := range cs.buckets {
		if !bkt.isFallback && bkt.literal != "" {
			litOrder = append(litOrder, bi)
		}
	}
	sort.SliceStable(litOrder, func(i, j int) bool {
		return len(cs.buckets[litOrder[i]].literal) < len(cs.buckets[litOrder[j]].literal)
	})
	for _, bi := range litOrder {
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
		b = emitValidMaskAt(b, bi, lPos)
		b = emitCallSuffixAt(b, litLen, bi, lPos)
		b = append(b, 0x0B)
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $scan
	b = append(b, 0x0B) // end block $batch_done
	b = append(b, 0x20, lOutCount, 0x0B)

	_ = lTmp
	_ = lOutBase
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
