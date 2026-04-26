package compile

import (
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// Phase 4c: per-set WASM compilation

// compiledSet is the WASM artefact for one `sets:` entry.
// The match function body is not stored here — it is built at assemble time
// (when function-table indices are known) by emitSetMatchFnFinal.
type compiledSet struct {
	name     string
	matchAny string // WASM export name, or ""
	matchAll string // WASM export name, or ""

	// suffixFnBodies[i] is the body for bucket i's suffix DFA function.
	suffixFnBodies [][]byte

	// numSuffixFns == len(suffixFnBodies).
	numSuffixFns int

	// Data segments for literal tables, Teddy/AC tables, etc.
	dataBytes    []byte
	dataSegCount int

	// Bucket list and pattern-ID mapping used by the match function.
	buckets    []*bucket
	patternIDs [][]int // patternIDs[bucketIdx][bitPos] = global 0-based pattern index

	// Diagnostics.
	diag *SetDiag
}

// funcCount returns the number of WASM functions contributed by this compiled set.
// = 1 (match fn) + len(suffixFnBodies).
func (cs *compiledSet) funcCount() int {
	return 1 + cs.numSuffixFns
}

// CompileSetOptions resolved defaults.
const (
	setMatchTypeSuffix = 3 // type index for suffix DFA fn: (i32,i32,i32)→i64
	setMatchTypeMatch  = 5 // type index for set match fn:   (i32,i32,i32,i32,i32)→i32
)

// SetSpec is the resolved specification for one set, ready for compilation.
type SetSpec struct {
	Name       string
	MatchAny   string
	MatchAll   string
	Patterns   []*PatternInfo // resolved, capture-bearing dropped
	PatternIDs []int          // global indices into the regexes list
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

	// Build suffix DFA function bodies, one per bucket.
	suffixFnBodies := make([][]byte, len(buckets))
	var allDataBytes []byte
	var totalDataSegs int
	var tableOffset int32 = 0 // data segment base for this set's tables

	for bi, b := range buckets {
		fnBody, dataBytes, dataSegs := emitSuffixDFAFn(b, tableOffset, 0)
		suffixFnBodies[bi] = fnBody
		tableOffset += int32(len(dataBytes))
		allDataBytes = append(allDataBytes, dataBytes...)
		totalDataSegs += dataSegs
	}

	// The set match function body is built at assemble time (when function table
	// indices are known). Store nil here; assembleModuleWithSets fills it in.
	cs := &compiledSet{
		name:           spec.Name,
		matchAny:       spec.MatchAny,
		matchAll:       spec.MatchAll,
		suffixFnBodies: suffixFnBodies,
		numSuffixFns:   len(suffixFnBodies),
		dataBytes:      allDataBytes,
		dataSegCount:   totalDataSegs,
		buckets:        buckets,
		patternIDs:     patternIDs,
		diag:           diag,
	}
	return cs, nil
}

// emitSuffixDFAFn emits the WASM function body for one bucket's suffix DFA.
// Signature: (ptr i32, suffix_start i32, len i32) → i64
// Returns: (funcBody, dataBytes, dataSegCount).
//
// The function runs the DFA from suffix_start and returns the OR of all accept
// bitmasks for states visited during the scan. It stops when it reaches the dead
// state (WASM state 0) or end of input. For multi-pattern suffix DFAs each bit
// in the returned bitmask corresponds to one pattern.
func emitSuffixDFAFn(b *bucket, tableBase int32, tableMemIdx int) (funcBody []byte, dataBytes []byte, dataSegCount int) {
	t := b.suffixDFA
	if t == nil || t.numStates == 0 {
		// Degenerate: no DFA — always returns 0.
		body := []byte{0x01, 0x01, 0x7F} // 1 local i32
		body = append(body, 0x42, 0x00)  // i64.const 0
		body = append(body, 0x0B)        // end
		funcBody = utils.AppendULEB128(nil, uint32(len(body)))
		funcBody = append(funcBody, body...)
		return
	}

	numWASM := t.numStates + 1
	useU8 := numWASM <= 256

	// --- Transition table data segment ---
	// u8 table: [numWASM * 256] bytes, table[state*256+byte] = next WASM state (0 = dead).
	// u16 table: [numWASM * 256 * 2] bytes, little-endian uint16.
	var tableBytesSlice []byte
	if useU8 {
		tableBytesSlice = make([]byte, numWASM*256)
		for gs := 0; gs < t.numStates; gs++ {
			for bv := 0; bv < 256; bv++ {
				if next := t.transitions[gs*256+bv]; next >= 0 {
					tableBytesSlice[(gs+1)*256+bv] = byte(next + 1)
				}
			}
		}
	} else {
		tableBytesSlice = make([]byte, numWASM*256*2)
		for gs := 0; gs < t.numStates; gs++ {
			for bv := 0; bv < 256; bv++ {
				wn := uint16(0)
				if next := t.transitions[gs*256+bv]; next >= 0 {
					wn = uint16(next + 1)
				}
				off := ((gs+1)*256 + bv) * 2
				tableBytesSlice[off] = byte(wn)
				tableBytesSlice[off+1] = byte(wn >> 8)
			}
		}
	}

	// --- Bitmask accept array data segment ---
	// u64 per WASM state: bitmask[ws*8] = accept bitmask for DFA state ws-1.
	bitmaskBytes := make([]byte, numWASM*8)
	for gs, bits := range t.acceptStates {
		if bits != 0 {
			off := (gs + 1) * 8
			for i := 0; i < 8; i++ {
				bitmaskBytes[off+i] = byte(bits >> uint(i*8))
			}
		}
	}

	tableOff := tableBase
	bitmaskOff := tableOff + int32(len(tableBytesSlice))
	dataBytes = appendDataSegment(dataBytes, tableOff, tableBytesSlice)
	dataBytes = appendDataSegment(dataBytes, bitmaskOff, bitmaskBytes)
	dataSegCount = 2

	// --- WASM function body ---
	// Params: ptr(0 i32), suffix_start(1 i32), len(2 i32).
	// Returned i64 is the OR of accept bitmasks of all states visited.
	//
	// Algorithm (same for u8 and u16, only table-load differs):
	//   state = 1  (WASM start state; dead = 0)
	//   pos   = suffix_start
	//   result = 0
	//   block $done:
	//     loop $main:
	//       if pos >= len: br $done          // EOF
	//       byte = mem[ptr + pos]
	//       state = table[state][byte]       // transition
	//       result |= bitmask64[state]       // accumulate accept bitmask
	//       if state == 0: br $done          // dead state
	//       pos++
	//       br $main
	//   return result
	//
	// Locals for u8:  state(3 i32), pos(4 i32), byte(5 i32), result(6 i64)
	// Locals for u16: same
	const (
		paramPtr   = byte(0)
		paramStart = byte(1)
		paramLen   = byte(2)
		lState     = byte(3)
		lPos       = byte(4)
		lByte      = byte(5)
		lResult    = byte(6)
	)
	var body []byte
	// 2 local groups: (3 × i32: state, pos, byte), (1 × i64: result)
	body = append(body, 0x02, 0x03, 0x7F, 0x01, 0x7E)

	body = append(body, 0x41, 0x01, 0x21, lState)     // state = 1
	body = append(body, 0x20, paramStart, 0x21, lPos) // pos = suffix_start
	body = append(body, 0x42, 0x00, 0x24, lResult)    // result = 0

	body = append(body, 0x02, 0x40) // block $done
	body = append(body, 0x03, 0x40) // loop $main

	// if pos >= len: br $done
	body = append(body, 0x20, lPos, 0x20, paramLen, 0x4D, 0x0D, 0x01)

	// byte = mem[ptr + pos]
	body = append(body, 0x20, paramPtr, 0x20, lPos, 0x6A)
	body = append(body, 0x2D, 0x00, 0x00) // i32.load8_u
	body = append(body, 0x21, lByte)

	// state = table[state][byte]
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, tableOff)
	if useU8 {
		body = append(body, 0x20, lState, 0x41, 0x08, 0x74) // state << 8 = state*256
		body = append(body, 0x6A, 0x20, lByte, 0x6A)        // + byte → addr
		body = appendTableLoad8u(body, tableMemIdx)
	} else {
		body = append(body, 0x20, lState, 0x41, 0x09, 0x74) // state << 9 = state*512
		body = append(body, 0x6A)
		body = append(body, 0x20, lByte, 0x41, 0x01, 0x74) // byte << 1 = byte*2
		body = append(body, 0x6A)                          // + → addr
		body = appendTableLoad16u(body, tableMemIdx)
	}
	body = append(body, 0x21, lState) // state = table result

	// result |= bitmask64[state * 8]
	body = append(body, 0x20, lResult)
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, bitmaskOff)
	body = append(body, 0x20, lState, 0x41, 0x03, 0x74, 0x6A) // bitmaskOff + state*8
	body = appendTableLoad64(body, tableMemIdx)
	body = append(body, 0x86, 0x01) // i64.or
	body = append(body, 0x24, lResult)

	// if state == 0: br $done
	body = append(body, 0x20, lState, 0x45, 0x0D, 0x01) // i32.eqz + br_if $done

	// pos++; br $main
	body = append(body, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	body = append(body, 0x0C, 0x00) // br $main

	body = append(body, 0x0B) // end loop $main
	body = append(body, 0x0B) // end block $done

	body = append(body, 0x20, lResult) // return result
	body = append(body, 0x0B)          // end function

	funcBody = utils.AppendULEB128(nil, uint32(len(body)))
	funcBody = append(funcBody, body...)
	return
}

// appendTableLoad64 emits i64.load align=3 offset=0.
// tableMemIdx is reserved for future multi-memory support (Phase 4c.6).
func appendTableLoad64(b []byte, _ int) []byte {
	return append(b, 0x29, 0x03, 0x00)
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
			MatchAny:   sc.MatchAny,
			MatchAll:   sc.MatchAll,
			Patterns:   infos,
			PatternIDs: globalIDs,
		}
		cs, err := CompileSet(spec, &prefixPool, &suffixPool, CompileSetOptions{})
		if err != nil {
			return nil, 0, err
		}
		compiledSets = append(compiledSets, cs)
	}

	var memPages int32 = 1
	if !standalone && lastTableEnd > 0 {
		memPages = int32((lastTableEnd + 65535) / 65536)
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
		totalSegs += cs.dataSegCount
		rawData = append(rawData, cs.dataBytes...)
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

	// Count suffix functions across all sets (for the function table).
	totalSuffixFns := 0
	suffixFnBase := make([]int, len(sets)) // suffixFnBase[si] = first suffix fn global index
	{
		for si, cs := range sets {
			suffixFnBase[si] = setBaseIdx[si] + 1 // +1 for the match fn
			totalSuffixFns += cs.numSuffixFns
		}
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// Type section: 6 types (3 existing + 3 new for set functions).
	typeSection := []byte{
		0x06,
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0: (i32,i32)→i32
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E, // type 1: (i32,i32)→i64
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 2: (i32,i32,i32)→i32
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7E, // type 3: (i32,i32,i32)→i64  [suffix DFA]
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 4: (i32,i32)→i32      [prefix backward DFA]
		0x60, 0x05, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 5: (i32×5)→i32 [set match]
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
		fs = append(fs, byte(setMatchTypeMatch)) // match fn: type 5
		for range cs.suffixFnBodies {
			fs = append(fs, byte(setMatchTypeSuffix)) // suffix fn: type 3
		}
	}
	out = appendSection(out, 3, fs)

	// Table section: one funcref table with enough slots for all suffix DFAs.
	if totalSuffixFns > 0 {
		var tableSec []byte
		tableSec = utils.AppendULEB128(tableSec, 1) // 1 table
		tableSec = append(tableSec, 0x70)           // funcref
		tableSec = append(tableSec, 0x00)           // limits: no max
		tableSec = utils.AppendULEB128(tableSec, uint32(totalSuffixFns))
		out = appendSection(out, 4, tableSec)
	}

	// Memory section.
	{
		var mem []byte
		mem = append(mem, 0x01, 0x00)
		mem = utils.AppendULEB128(mem, uint32(memPages))
		out = appendSection(out, 5, mem)
	}

	// Element section: populate the function table with suffix DFA function indices.
	if totalSuffixFns > 0 {
		var elemSec []byte
		elemSec = utils.AppendULEB128(elemSec, 1) // 1 element segment
		elemSec = append(elemSec, 0x00)           // active, table 0, funcref
		// offset = i32.const 0
		elemSec = append(elemSec, 0x41, 0x00, 0x0B)
		// num elements
		elemSec = utils.AppendULEB128(elemSec, uint32(totalSuffixFns))
		for si, cs := range sets {
			base := suffixFnBase[si]
			for j := 0; j < cs.numSuffixFns; j++ {
				elemSec = utils.AppendULEB128(elemSec, uint32(base+j))
			}
		}
		out = appendSection(out, 9, elemSec)
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
		if cs.matchAny != "" {
			numExports++
		}
		if cs.matchAll != "" {
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
		matchFnIdx := setBaseIdx[si]
		if cs.matchAny != "" {
			es = appendString(es, cs.matchAny)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(matchFnIdx))
		}
		if cs.matchAll != "" {
			es = appendString(es, cs.matchAll)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(matchFnIdx))
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
	// Set function bodies.
	for si, cs := range sets {
		// Patch the call_indirect table indices in the match fn body.
		// The match fn body uses bi as placeholder; the real index is suffixFnBase[si] + bi.
		// For simplicity in this initial version, we rebuild the match fn body with correct indices.
		matchBody := rebuildSetMatchBody(cs, suffixFnBase[si])
		cs_bytes = append(cs_bytes, matchBody...)
		for _, sfn := range cs.suffixFnBodies {
			cs_bytes = append(cs_bytes, sfn...)
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

// rebuildSetMatchBody re-emits the set match function with correct table indices.
// The match fn placeholder uses bi as the table index; the real index is tableBase+bi.
func rebuildSetMatchBody(cs *compiledSet, suffixFnTableBase int) []byte {
	// Re-emit the match fn body with correct call_indirect table indices.
	// For now: delegate to emitSetMatchFnWithBase which takes the base.
	return emitSetMatchFnFinal(cs, suffixFnTableBase)
}

// emitSetMatchFnFinal emits the set match function body with the given suffix-function
// table base index. Uses a scalar literal scan; Teddy/AC is layered on in Phase 5.
func emitSetMatchFnFinal(cs *compiledSet, tableBase int) []byte {
	var b []byte
	b = append(b, 0x01, 0x04, 0x7F) // 4 i32 locals: pos, out_count, tmp1, tmp2

	const (
		pInPtr    = byte(0)
		pInLen    = byte(1)
		pOutPtr   = byte(2)
		pOutCap   = byte(3)
		pStartPos = byte(4)
		lPos      = byte(5)
		lOutCount = byte(6)
		lTmp1     = byte(7)
		lTmp2     = byte(8)
	)

	b = append(b, 0x41, 0x00, 0x21, lOutCount)
	b = append(b, 0x20, pStartPos, 0x21, lPos)

	b = append(b, 0x02, 0x40) // block $batch_done
	b = append(b, 0x03, 0x40) // loop $scan

	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4D, 0x0D, 0x01)
	b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x4D, 0x0D, 0x01)

	for bi, bkt := range cs.buckets {
		if bkt.isFallback || bkt.literal == "" {
			continue
		}
		lit := []byte(bkt.literal)
		litLen := len(lit)

		b = append(b, 0x02, 0x40) // block $no_lit
		b = append(b, 0x20, lPos)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x00)

		for li, lb := range lit {
			b = append(b, 0x20, pInPtr, 0x20, lPos)
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

		// Call suffix DFA via call_indirect.
		b = append(b, 0x20, pInPtr)
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(litLen))
		b = append(b, 0x6A)
		b = append(b, 0x20, pInLen)
		// table index = tableBase + bi
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(tableBase+bi))
		b = append(b, 0x11, byte(setMatchTypeSuffix), 0x00)

		// Wrap i64 bitmask to i32.
		b = append(b, 0xA7, 0x21, lTmp1)

		for bitPos, globalID := range cs.patternIDs[bi] {
			if bitPos >= 32 {
				break
			}
			bit := uint32(1) << uint(bitPos)
			b = append(b, 0x20, lTmp1)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(bit))
			b = append(b, 0x71) // i32.and
			b = append(b, 0x04, 0x40)
			b = append(b, 0x20, lOutCount, 0x20, pOutCap, 0x4D, 0x0D, 0x03)

			b = append(b, 0x20, pOutPtr, 0x20, lOutCount)
			b = append(b, 0x41, 12, 0x6C, 0x6A, 0x21, lTmp2)
			b = append(b, 0x20, lTmp2)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(globalID))
			b = append(b, 0x36, 0x02, 0x00)
			b = append(b, 0x20, lTmp2, 0x20, lPos, 0x36, 0x02, 0x04)
			b = append(b, 0x20, lTmp2, 0x41)
			b = utils.AppendSLEB128(b, int32(litLen))
			b = append(b, 0x36, 0x02, 0x08)
			b = append(b, 0x20, lOutCount, 0x41, 0x01, 0x6A, 0x21, lOutCount)
			b = append(b, 0x0B)
		}

		b = append(b, 0x0B) // end block $no_lit
	}

	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	b = append(b, 0x20, lOutCount, 0x0B)

	funcBody := utils.AppendULEB128(nil, uint32(len(b)))
	funcBody = append(funcBody, b...)
	return funcBody
}
