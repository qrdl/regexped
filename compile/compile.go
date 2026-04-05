package compile

import (
	"fmt"
	"log/slog"
	"os"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// matchMode controls the generated WASM function's matching behaviour.
type matchMode int

const (
	// modeAnchoredMatch generates a function (ptr, len i32) -> i32 that matches
	// the full input anchored at position 0, returning end position or -1.
	modeAnchoredMatch matchMode = 0

	// modeFind generates a function (ptr, len i32) -> i64 that scans the input
	// for the leftmost-longest match, returning packed (start<<32|end) or -1.
	modeFind matchMode = 1
)

// EngineType represents the type of regex engine implementation.
type EngineType byte

const (
	EngineDFA EngineType = iota + 1
	EngineBacktrack
	EngineCompiledDFA // DFA with compiled (br_table) dispatch; no transition table at runtime
	EngineTDFA        // Tagged DFA: O(n) matching with full capture support
)

// String returns the human-readable name of the engine type.
func (e EngineType) String() string {
	switch e {
	case EngineBacktrack:
		return "Backtracking"
	case EngineDFA:
		return "DFA"
	case EngineCompiledDFA:
		return "Compiled DFA"
	case EngineTDFA:
		return "TDFA"
	default:
		return "Unknown"
	}
}

// matcher is the common interface implemented by all regex engines.
type matcher interface {
	Type() EngineType
}

// CompileOptions contains optional parameters for engine selection.
type CompileOptions struct {
	// MaxDFAStates is the maximum number of states allowed when building a DFA
	// (match/find) or TDFA (capture groups). If the DFA/TDFA exceeds this limit
	// the engine falls back to Backtracking. 0 means use the default (1024).
	// Exposed as max_dfa_states in the YAML config.
	MaxDFAStates int
	// MaxTDFARegs is the maximum number of WASM capture registers a TDFA may
	// use before falling back to Backtracking. 0 means use the default (32).
	// Exposed as max_tdfa_regs in the YAML config.
	MaxTDFARegs   int
	MaxDFAMemory  int        // Maximum DFA memory in bytes (default: 102400)
	Unicode       bool       // Enable Unicode support
	ForceEngine   EngineType // If non-zero, skip engine selection and use this engine type
	Mode          matchMode  // modeAnchoredMatch (default) or modeFind
	LeftmostFirst bool       // Use leftmost-first (RE2/Perl) semantics for alternations
	// CompiledDFAThreshold is the maximum minimised WASM state count for which the
	// compiled dispatch path (EngineCompiledDFA) is used instead of the table-driven
	// interpreter. 0 means use the default (256). Capped at 256 (u8 state index
	// constraint). Negative value disables the compiled path entirely.
	// NOT exposed in the YAML config schema — internal/programmatic use only.
	CompiledDFAThreshold int
	// MemoBudget is the maximum bytes allocated for the BitState memoization
	// buffer. Only used when the pattern requires BitState (needsBitState == true).
	// Defaults to 128*1024 (128 KB) when zero.
	MemoBudget  int
	tableMemIdx int // 0 = standalone (own memory[0]), 1 = embedded (memory[1] for tables)
}

// compiledPattern holds the intermediate compilation result for one RegexEntry.
// All function bodies are size-prefixed (ready for the WASM code section).
type compiledPattern struct {
	matchBody   []byte // (i32,i32)→i32; nil if not requested
	findBody    []byte // (i32,i32)→i64; nil if not needed; exported or internal
	captureBody []byte // (i32,i32,i32)→i32; nil if no groups; always internal

	matchExport       string // empty = not exported
	findExport        string // empty = internal-only (for wrapper use)
	groupsExport      string
	namedGroupsExport string

	anchored   bool     // true = pattern anchored at 0; no wrapper needed
	numGroups  int      // capture group count (for wrapper slot adjustment)
	isTDFA     bool     // true = TDFA capture; false = Backtracking (controls sentinel data segment)
	groupNames []string // groupNames[i] = name for group i+1; "" = unnamed

	dataSegCount int    // number of data segments in dataBytes
	dataBytes    []byte // raw data segments (no count prefix)

	tableEnd int64

	// Literal-anchored matching fields.
	// litAnchorBackScanBody != nil means this pattern uses the literal-anchored find path:
	//   an internal backward_scan function + a lit_anchor_find function generated at
	//   assembleModule time (when the function index is known).
	litAnchorBackScanBody []byte     // size-prefixed backward_scan body; nil = no lit-anchor
	litAnchorFindLayout   *dfaLayout // LF DFA layout for the forward scan in lit_anchor_find
	litAnchorFindTable    *dfaTable  // LF DFA table for the forward scan in lit_anchor_find
	// SIMD scan tables for the literal set (stored in data segment, offsets known at compile time).
	litAnchorFirstByteOff   int32
	litAnchorFirstByteFlags [256]byte
	litAnchorFirstBytes     []byte
	litAnchorTeddyLoOff     int32
	litAnchorTeddyHiOff     int32
	litAnchorTeddyLoBytes   []byte
	litAnchorTeddyHiBytes   []byte
	litAnchorTeddyT1LoOff   int32
	litAnchorTeddyT1HiOff   int32
	litAnchorTeddyT1LoBytes []byte
	litAnchorTeddyT1HiBytes []byte
	litAnchorLitSet         [][]byte // raw literals for post-Teddy scalar verification
}

// funcCount returns the number of WASM functions this pattern contributes.
func (p *compiledPattern) funcCount() int {
	n := 0
	if p.matchBody != nil {
		n++
	}
	if p.litAnchorBackScanBody != nil {
		n += 2 // backward_scan + lit_anchor_find
	} else if p.findBody != nil {
		n++
	}
	if p.captureBody != nil {
		n++ // capture_internal
		if !p.anchored {
			n++
		} // groups_wrapper
		if p.namedGroupsExport != "" {
			n++
		} // named_groups_wrapper
	}
	return n
}

// offsets returns the sub-indices of each function within this pattern.
// backwardScanOff is the index of backward_scan (-1 if no split).
// findOff is the index of the find function (normal or lit_anchor_find, -1 if absent).
// Returns -1 for absent functions.
func (p *compiledPattern) offsets() (matchOff, backwardScanOff, findOff, captureOff, wrapperOff, namedWrapperOff int) {
	matchOff, backwardScanOff, findOff, captureOff, wrapperOff, namedWrapperOff = -1, -1, -1, -1, -1, -1
	idx := 0
	if p.matchBody != nil {
		matchOff = idx
		idx++
	}
	if p.litAnchorBackScanBody != nil {
		backwardScanOff = idx
		idx++
		findOff = idx
		idx++
	} else if p.findBody != nil {
		findOff = idx
		idx++
	}
	if p.captureBody != nil {
		captureOff = idx
		idx++
		if !p.anchored {
			wrapperOff = idx
			idx++
		}
		if p.namedGroupsExport != "" {
			namedWrapperOff = idx
			idx++
		}
	}
	return
}

// stripSegCount strips the LEB128 count prefix from a data section payload,
// returning the raw segment bytes and the count.
func stripSegCount(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return nil, 0
	}
	count, n := utils.DecodeULEB128(data)
	return data[n:], int(count)
}

// extractGroupNames returns the capture group names (1-indexed) from a parsed regexp.
// groupNames[i] is the name of group i+1; empty string if unnamed.
func extractGroupNames(re *syntax.Regexp) []string {
	var names []string
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture {
			names = append(names, r.Name)
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return names
}

// compilePattern compiles one RegexEntry into an intermediate compiledPattern.
// It does not build the final WASM module; call assembleModule for that.
// forceGroupsEngine overrides engine selection for the capture path (0 = auto).
func compilePattern(re config.RegexEntry, tableBase int64, forceGroupsEngine EngineType, buildOpts CompileOptions) (*compiledPattern, error) {
	needMatch := re.MatchFunc != ""
	needFind := re.FindFunc != ""
	needGroups := re.CaptureStubsRequested()

	if !needMatch && !needFind && !needGroups {
		return &compiledPattern{tableEnd: tableBase}, nil
	}

	maxStates := resolveMaxDFAStates(&buildOpts)
	memLimit := resolveMaxDFAMemory(&buildOpts)

	// Match function uses LL (leftmostFirst=false): finds the longest full-string
	// match from pos 0, matching RE2/Go anchored-match semantics.
	// Find/groups use LF (leftmostFirst=true): leftmost-first Perl semantics.
	// These require separate DFA compilations.

	var matchBody []byte
	var matchData []byte
	var matchSegCnt int
	var matchEnd int64

	cur := tableBase

	if needMatch {
		// Match uses LL (leftmostFirst=false): all NFA alternative paths are kept in each
		// DFA state, so the DFA can find ANY path that consumes the full input string.
		// LF would discard lower-priority alternatives after a higher-priority one matches,
		// making full-string match fail for patterns like `a|aa` on "aa" (LF picks `a` at
		// pos 0, loses the `aa` path, then can't reach the end of input).
		// This matches Go stdlib semantics: regexp.MustCompile("^(a|aa)$").MatchString("aa") = true.
		llOpts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: false}
		llMatch, llErr := compile(re.Pattern, llOpts)
		if llErr != nil {
			return nil, fmt.Errorf("compile match DFA: %w", llErr)
		}
		llTable := dfaTableFrom(llMatch.(*dfa))
		if llTable.numStates > maxStates || (memLimit > 0 && dfaTableBytes(llTable) > memLimit) {
			// DFA too large — fall back to Backtracking match.
			btProg, btProgErr := compileBTProg(re.Pattern)
			if btProgErr != nil {
				return nil, fmt.Errorf("compile BT match prog: %w", btProgErr)
			}
			bt := newBacktrack(btProg)
			bt.numGroups = 0
			useMemo := needsBitState(btProg)
			btBase := utils.PageAlign(cur)
			matchMemoBudget := resolveMemoBudget(&buildOpts)
			btStackSize, btMemoSize := btAllocSizes(bt, useMemo, 0, matchMemoBudget)
			btStackBase := int32(btBase)
			btStackLimit := btStackBase + int32(btStackSize)
			var btMemoBase int32
			var btMemoMaxLen int32
			if useMemo {
				btMemoBase = btStackLimit
				btMemoMaxLen = int32(btMemoMaxLenFor(btProg, matchMemoBudget))
			}
			matchBody = appendBTMatchCodeEntry(nil, bt, btStackBase, btStackLimit, 8, btMemoBase, btMemoMaxLen, useMemo, buildOpts.tableMemIdx)
			matchEnd = btBase + int64(btStackSize) + int64(btMemoSize)
		} else {
			lm := buildDFALayout(llTable, cur, false, false, resolveCompiledDFAThreshold(&buildOpts))
			matchBody = appendMatchCodeEntry(nil, lm, llTable, lm.hasImmAccept, buildOpts.tableMemIdx)
			rawM, cntM := stripSegCount(dfaDataSegments(lm, false))
			matchData = rawM
			matchSegCnt = cntM
			matchEnd = lm.tableEnd
		}
		cur = utils.PageAlign(matchEnd)
	}

	// LF DFA for find and/or groups.
	lfOpts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: true}
	matcher, err := compile(re.Pattern, lfOpts)
	if err != nil {
		return nil, fmt.Errorf("compile DFA: %w", err)
	}
	table := dfaTableFrom(matcher.(*dfa))

	anchored := isAnchoredFind(table)
	needFindBody := needFind || (needGroups && !anchored)

	// Check if the LF DFA exceeds the state limit — if so, use BT find body.
	dfaTooLarge := table.numStates > maxStates || (memLimit > 0 && dfaTableBytes(table) > memLimit)

	var l *dfaLayout
	if !dfaTooLarge {
		l = buildDFALayout(table, cur, needFindBody, true, resolveCompiledDFAThreshold(&buildOpts))
	}
	patMandLit := findMandatoryLit(re.Pattern)

	p := &compiledPattern{
		matchExport: re.MatchFunc,
		findExport:  re.FindFunc,
		anchored:    anchored,
	}

	if needMatch {
		p.matchBody = matchBody
		p.dataBytes = matchData
		p.dataSegCount = matchSegCnt
		if !needFind && !needGroups {
			p.tableEnd = matchEnd
			return p, nil
		}
	}

	if needFindBody {
		if dfaTooLarge {
			// DFA too large — fall back to Backtracking find.
			btProg, btProgErr := compileBTProg(re.Pattern)
			if btProgErr != nil {
				return nil, fmt.Errorf("compile BT find prog: %w", btProgErr)
			}
			bt := newBacktrack(btProg)
			bt.numGroups = 0
			useMemo := needsBitState(btProg)
			// Choose scan strategy (in priority order):
			//   1. Multi-byte literal prefix from the (large) LF DFA — no data tables, pure SIMD.
			//   2. Mandatory interior literal via two-level outer loop.
			//   3. First-byte SIMD/Teddy tables from NFA (fallback).
			var btScanParams prefixScanParams
			var btScanDataBytes []byte
			var btScanSegCnt int
			var btMandLit *mandatoryLit
			btPrefix := computePrefix(table) // table is always available (even when too large)
			if len(btPrefix) >= 2 {
				// Multi-byte prefix: use SIMD prefix scan; no memory tables needed.
				btScanParams = prefixScanParams{
					Prefix: btPrefix,
					Locals: prefixScanLocals{
						Ptr: 0, Len: 1, AttemptStart: 7, SimdMask: 8, Chunk: 9,
					},
					EngineDepth: 2,
				}
			} else if patMandLit != nil {
				// Mandatory interior literal: two-level outer loop; no first-byte tables needed.
				btMandLit = patMandLit
			} else {
				// Fallback: first-byte SIMD/Teddy tables from NFA.
				btFirstBytes, btFirstByteFlags, btAllBytes := nfaFirstBytes(btProg)
				btScanParams, btScanDataBytes, btScanSegCnt = buildBTScanTables(btFirstBytes, btFirstByteFlags, btAllBytes, cur)
				btScanParams.TableMemIdx = buildOpts.tableMemIdx
			}
			p.dataBytes = append(p.dataBytes, btScanDataBytes...)
			p.dataSegCount += btScanSegCnt
			// Allocate BT stack after SIMD tables.
			btBase := utils.PageAlign(cur + int64(len(btScanDataBytes)))
			memoBudget := resolveMemoBudget(&buildOpts)
			btStackSize, btMemoSize := btAllocSizes(bt, useMemo, 0, memoBudget)
			btStackBase := int32(btBase)
			btStackLimit := btStackBase + int32(btStackSize)
			var btMemoBase int32
			var btMemoMaxLen int32
			if useMemo {
				btMemoBase = btStackLimit
				btMemoMaxLen = int32(btMemoMaxLenFor(btProg, memoBudget))
			}
			frameSize := int32(8) // pos + retryPC only (no cap slots)
			p.findBody = appendBTFindCodeEntry(nil, bt, btScanParams, btStackBase, btStackLimit, frameSize, btMemoBase, btMemoMaxLen, useMemo, btMandLit, buildOpts.tableMemIdx)
			p.tableEnd = utils.PageAlign(btBase + int64(btStackSize) + int64(btMemoSize))
		} else {
			// DFA find path: check for lit-anchor optimisation first.
			lap := findLitAnchorPoint(re.Pattern)
			if lap != nil && l.useU8 && !table.hasWordBoundary {
				// Compile the reversed prefix DFA for the backward scan.
				revRe := reverseRegexp(lap.prefixRe)
				revSimplified := revRe.Simplify()
				revProg, revCompErr := syntax.Compile(revSimplified)
				if revCompErr == nil && !needsUnicodeSupport(revProg) {
					revDFA := newDFA(revProg, false, false)
					revTable := dfaTableFrom(revDFA)
					if revTable.numStates+1 <= 256 &&
						(lap.anchored || (!revTable.acceptStates[revTable.startState] &&
							!revTable.midAcceptStates[revTable.startState])) {
						revTableBase := utils.PageAlign(l.tableEnd)
						revL := buildDFALayout(revTable, revTableBase, true, false, 0)
						bsBody := buildLitAnchorBackScanBody(revL, revTable, buildOpts.tableMemIdx)

						var litFirstBytes []byte
						var litFirstByteFlags [256]byte
						for _, lit := range lap.litSet {
							b0 := lit[0]
							if litFirstByteFlags[b0] == 0 {
								litFirstByteFlags[b0] = 1
								litFirstBytes = append(litFirstBytes, b0)
							}
						}

						litFirstByteOff := int32(revL.tableEnd)
						litTeddyLoOff := litFirstByteOff + 256
						litTeddyHiOff := litTeddyLoOff + 16
						var litTeddyLoBytes, litTeddyHiBytes []byte
						var litTeddyT1LoOff, litTeddyT1HiOff int32
						var litTeddyT1LoBytes, litTeddyT1HiBytes []byte

						if len(litFirstBytes) <= 8 {
							litTeddyLoBytes = make([]byte, 16)
							litTeddyHiBytes = make([]byte, 16)
							for i, fb := range litFirstBytes {
								litTeddyLoBytes[fb&0x0F] |= byte(1 << uint(i))
								litTeddyHiBytes[fb>>4] |= byte(1 << uint(i))
							}
							t1Lo := make([]byte, 16)
							t1Hi := make([]byte, 16)
							fbToBit := make(map[byte]int)
							for i, fb := range litFirstBytes {
								fbToBit[fb] = i
							}
							for _, lit := range lap.litSet {
								bit, ok := fbToBit[lit[0]]
								if !ok {
									continue
								}
								t1Lo[lit[1]&0x0F] |= byte(1 << uint(bit))
								t1Hi[lit[1]>>4] |= byte(1 << uint(bit))
							}
							litTeddyT1LoOff = litTeddyHiOff + 16
							litTeddyT1HiOff = litTeddyT1LoOff + 16
							litTeddyT1LoBytes = t1Lo
							litTeddyT1HiBytes = t1Hi
						}

						revRawData, revSegCnt := stripSegCount(dfaDataSegments(revL, true))
						var litSegs []byte
						litSegCnt := 1
						litSegs = appendDataSegment(litSegs, litFirstByteOff, litFirstByteFlags[:])
						if litTeddyLoBytes != nil {
							litSegs = appendDataSegment(litSegs, litTeddyLoOff, litTeddyLoBytes)
							litSegs = appendDataSegment(litSegs, litTeddyHiOff, litTeddyHiBytes)
							litSegCnt += 2
							if litTeddyT1LoBytes != nil {
								litSegs = appendDataSegment(litSegs, litTeddyT1LoOff, litTeddyT1LoBytes)
								litSegs = appendDataSegment(litSegs, litTeddyT1HiOff, litTeddyT1HiBytes)
								litSegCnt += 2
							}
						}

						p.litAnchorBackScanBody = bsBody
						p.litAnchorFindLayout = l
						p.litAnchorFindTable = table
						p.litAnchorFirstByteOff = litFirstByteOff
						p.litAnchorFirstByteFlags = litFirstByteFlags
						p.litAnchorFirstBytes = litFirstBytes
						p.litAnchorTeddyLoOff = litTeddyLoOff
						p.litAnchorTeddyHiOff = litTeddyHiOff
						p.litAnchorTeddyLoBytes = litTeddyLoBytes
						p.litAnchorTeddyHiBytes = litTeddyHiBytes
						p.litAnchorTeddyT1LoOff = litTeddyT1LoOff
						p.litAnchorTeddyT1HiOff = litTeddyT1HiOff
						p.litAnchorTeddyT1LoBytes = litTeddyT1LoBytes
						p.litAnchorTeddyT1HiBytes = litTeddyT1HiBytes
						p.litAnchorLitSet = lap.litSet
						p.dataBytes = append(p.dataBytes, revRawData...)
						p.dataSegCount += revSegCnt
						p.dataBytes = append(p.dataBytes, litSegs...)
						p.dataSegCount += litSegCnt
						p.tableEnd = int64(litTeddyT1HiOff) + 16
						if litTeddyLoBytes == nil {
							p.tableEnd = int64(litFirstByteOff) + 256
						} else if litTeddyT1LoBytes == nil {
							p.tableEnd = int64(litTeddyHiOff) + 16
						}
					}
				}
			}
			if p.litAnchorBackScanBody == nil {
				p.findBody = appendFindCodeEntry(nil, l, table, patMandLit, buildOpts.tableMemIdx)
			}

			rawData, segCount := stripSegCount(dfaDataSegments(l, needFindBody))
			p.dataBytes = append(p.dataBytes, rawData...)
			p.dataSegCount += segCount
			if p.litAnchorBackScanBody == nil {
				p.tableEnd = l.tableEnd
			}
		}
	} else if !dfaTooLarge {
		// needFindBody is false but we still need the DFA data segments (for match only).
		rawData, segCount := stripSegCount(dfaDataSegments(l, false))
		p.dataBytes = append(p.dataBytes, rawData...)
		p.dataSegCount += segCount
		p.tableEnd = l.tableEnd
	}

	if !needGroups {
		return p, nil
	}

	p.groupsExport = re.GroupsFunc // only set when groups_func explicitly requested
	if re.NamedGroupsFunc != "" {
		p.namedGroupsExport = re.NamedGroupsFunc
	}

	parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return nil, fmt.Errorf("compile NFA: %w", err)
	}
	if needsUnicodeSupport(prog) {
		return nil, fmt.Errorf("pattern contains Unicode features not yet supported")
	}

	p.groupNames = extractGroupNames(parsed)
	groupsEngine := selectBestEngine(prog, prog.NumCap > 2, &buildOpts)
	if forceGroupsEngine != 0 {
		groupsEngine = forceGroupsEngine
	}

	if groupsEngine == EngineTDFA {
		tt, ok := newTDFA(prog, resolveMaxDFAStates(&buildOpts))
		if ok && tt.numRegs > resolveMaxTDFARegs(&buildOpts) {
			ok = false
		}
		if !ok {
			// Fallback: TDFA limit exceeded during actual compilation (should match selector).
			groupsEngine = EngineBacktrack
		} else {
			p.isTDFA = true
			tdfaBase := utils.PageAlign(p.tableEnd)
			tdfaLayout := buildDFALayout(tt.dfaTable, tdfaBase, false, true, resolveCompiledDFAThreshold(&buildOpts))
			p.numGroups = tt.numGroups
			p.captureBody = appendTDFACodeEntry(nil, tt, tdfaLayout, buildOpts.tableMemIdx)
			// TDFA only needs the transition table (no stack/memo).
			p.tableEnd = tdfaLayout.tableEnd
			rawTDFA, cntTDFA := stripSegCount(dfaDataSegments(tdfaLayout, false))
			p.dataBytes = append(p.dataBytes, rawTDFA...)
			p.dataSegCount += cntTDFA
		}
	}

	if groupsEngine == EngineBacktrack {
		bt := newBacktrack(prog)

		// Stack placed directly after all find-mode DFA and lit-anchor tables.
		// p.tableEnd includes lit-anchor reversed-DFA and SIMD tables when active;
		// using l.tableEnd would overlap those tables and corrupt them at runtime.
		btBase := utils.PageAlign(p.tableEnd)
		numCapLocs := bt.numGroups * 2
		frameSize := 4 + numCapLocs*4 + 4
		maxFrames := bt.numAlts * 4096
		if maxFrames < 4096 {
			maxFrames = 4096
		}
		stackSize := maxFrames * frameSize
		stackBase := int32(btBase)
		stackLimit := stackBase + int32(stackSize)

		// Memo table (BitState memoization) — only when the pattern has loops
		// whose body can match zero bytes, which can cause infinite revisiting.
		useMemo := needsBitState(prog)
		var memoTableBase int32
		var memoMaxLen int32
		if useMemo {
			N := len(prog.Inst)
			memoBudget := resolveMemoBudget(&buildOpts)
			memoMaxLen = int32(memoBudget*8/N - 1)
			memoMaxSize := int64((N*(int(memoMaxLen)+1) + 7) / 8)
			if memoMaxSize > int64(memoBudget) {
				return nil, fmt.Errorf(
					"pattern requires %d bytes of memo memory, exceeds budget %d: "+
						"increase CompileOptions.MemoBudget",
					memoMaxSize, memoBudget)
			}
			memoTableBase = stackBase + int32(stackSize)
			p.tableEnd = utils.PageAlign(int64(memoTableBase) + memoMaxSize)
		} else {
			p.tableEnd = utils.PageAlign(btBase + int64(stackSize))
		}

		p.numGroups = bt.numGroups
		p.captureBody = appendBacktrackCodeEntry(nil, bt, stackBase, stackLimit, int32(frameSize), memoTableBase, memoMaxLen, useMemo, buildOpts.tableMemIdx)
	}

	return p, nil
}

// assembleModule builds a single WASM module from multiple compiled patterns.
// standalone=true: module defines its own memory.
// standalone=false: module imports memory from "main" (for wasm-merge).
// Both modes emit active data segments; in non-standalone mode the host stub's
// reservation variable ensures the host runtime declares enough initial memory.
func assembleModule(patterns []*compiledPattern, memPages int32, standalone bool) []byte {
	// Pre-collect data segments.
	totalSegs := 0
	var rawData []byte
	for _, p := range patterns {
		totalSegs += p.dataSegCount
		rawData = append(rawData, p.dataBytes...)
	}

	// Pass 1: assign base function indices.
	baseIdx := make([]int, len(patterns))
	total := 0
	for i, p := range patterns {
		baseIdx[i] = total
		total += p.funcCount()
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// Type section: 3 fixed types (match, find, capture/groups).
	typeSection := []byte{
		0x03,
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0: (i32,i32)→i32
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E, // type 1: (i32,i32)→i64
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 2: (i32,i32,i32)→i32
	}
	out = appendSection(out, 1, typeSection)

	// Import section (embedded only): import "main" memory as memory[0].
	// In the merged binary, main keeps memory[0] and our own memory becomes memory[1].
	// Input data loads use implicit memory[0]; DFA table loads use explicit memory[1].
	if !standalone {
		var importSec []byte
		importSec = utils.AppendULEB128(importSec, 1) // 1 import
		importSec = appendString(importSec, "main")   // module name
		importSec = appendString(importSec, "memory") // field name
		importSec = append(importSec, 0x02)           // kind: memory
		importSec = append(importSec, 0x00)           // limits flags: no max
		importSec = append(importSec, 0x00)           // min = 0 pages
		out = appendSection(out, 2, importSec)
	}

	// Function section: pattern functions only.
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(total))
	for _, p := range patterns {
		if p.matchBody != nil {
			fs = append(fs, 0x00)
		}
		if p.litAnchorBackScanBody != nil {
			fs = append(fs, 0x00) // backward_scan: (i32,i32)->i32
			fs = append(fs, 0x01) // lit_anchor_find: (i32,i32)->i64
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
	out = appendSection(out, 3, fs)

	// Memory section: own memory for both standalone and embedded.
	// standalone modules export it; embedded modules do not (wasm-merge renumbers).
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
	out = appendSection(out, 7, es)

	// Code section.
	var cs []byte
	cs = utils.AppendULEB128(cs, uint32(total))
	for i, p := range patterns {
		base := baseIdx[i]
		_, backwardScanOff, findOff, captureOff, wrapperOff, _ := p.offsets()
		if p.matchBody != nil {
			cs = append(cs, p.matchBody...)
		}
		if p.litAnchorBackScanBody != nil {
			cs = append(cs, p.litAnchorBackScanBody...)
			// Generate lit_anchor_find body now that function indices are known.
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			litAnchorFindBody := buildLitAnchorFindBody(p.litAnchorFindTable, p.litAnchorFindLayout, p, base+backwardScanOff, tableMemIdx)
			cs = utils.AppendULEB128(cs, uint32(len(litAnchorFindBody)))
			cs = append(cs, litAnchorFindBody...)
		} else if p.findBody != nil {
			cs = append(cs, p.findBody...)
		}
		if p.captureBody != nil {
			cs = append(cs, p.captureBody...)
			if !p.anchored {
				cs = appendWrapperCodeEntry(cs, base+findOff, base+captureOff, p.numGroups)
				if p.namedGroupsExport != "" {
					cs = appendNamedGroupsWrapperCodeEntry(cs, base+wrapperOff)
				}
			} else if p.namedGroupsExport != "" {
				cs = appendNamedGroupsWrapperCodeEntry(cs, base+captureOff)
			}
		}
	}
	out = appendSection(out, 10, cs)

	// Data section: active segments targeting the correct memory index.
	if totalSegs > 0 {
		var ds []byte
		if !standalone {
			// Re-encode data segments to target memory[1] (own DFA-table memory).
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

// Compile compiles multiple regex patterns to a single WASM module.
//   - standalone=false: module declares its own memory, no export (for embedding via wasm-merge)
//   - standalone=true:  module declares its own memory and exports it as "memory" (for testing/standalone use)
//   - tableBase: starting address for DFA/capture tables within the module's memory; use 0 for
//     embedded modules (tables start at address 0 of own memory). Callers like re2test/perftest
//     pass a non-zero value to reserve low pages for their own test input buffers.
//
// All patterns must compile successfully; any error stops compilation immediately.
func Compile(patterns []config.RegexEntry, tableBase int64, standalone bool, userOpts ...CompileOptions) ([]byte, int64, error) {
	var opts CompileOptions
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	return compileAll(patterns, tableBase, standalone, 0, opts)
}

func compileAll(patterns []config.RegexEntry, tableBase int64, standalone bool, forceGroupsEngine EngineType, opts CompileOptions) ([]byte, int64, error) {
	if !standalone {
		opts.tableMemIdx = 1
	}
	var compiled []*compiledPattern
	cur := tableBase
	for _, re := range patterns {
		p, err := compilePattern(re, cur, forceGroupsEngine, opts)
		if err != nil {
			return nil, 0, fmt.Errorf("compile pattern %q: %w", re.Pattern, err)
		}
		compiled = append(compiled, p)
		if p.tableEnd > cur {
			cur = utils.PageAlign(p.tableEnd)
		}
	}
	if len(compiled) == 0 {
		return nil, tableBase, nil
	}
	lastTableEnd := compiled[len(compiled)-1].tableEnd
	memPages := int32(utils.PageAlign(lastTableEnd) / 65536)
	if memPages < 1 {
		memPages = 1
	}
	return assembleModule(compiled, memPages, standalone), lastTableEnd, nil
}

// CmdCompile compiles all regex patterns from cfg to a single WASM module.
// output is the output path (absolute, relative to cwd, or "-" for stdout).
// The module declares its own memory (tables start at address 0) and does not
// import memory from any host; use regexped merge to embed it.
func CmdCompile(cfg config.BuildConfig, output string) error {
	outPath := output
	slog.Info("Compiling regexes", "count", len(cfg.Regexes), "output", outPath)

	compOpts := CompileOptions{
		MaxDFAStates: cfg.MaxDFAStates,
		MaxTDFARegs:  cfg.MaxTDFARegs,
	}
	standalone := cfg.Output == ""
	wasmBytes, _, err := Compile(cfg.Regexes, 0, standalone, compOpts)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	if outPath == "-" {
		if _, err := os.Stdout.Write(wasmBytes); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		slog.Info("Done", "bytes", len(wasmBytes))
		return nil
	}
	if err := os.WriteFile(outPath, wasmBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	slog.Info("Done", "bytes", len(wasmBytes))
	return nil
}

// stripCaptures converts all capture groups in the regexp tree to non-capturing
// by replacing each OpCapture node with its single sub-expression in-place.
// Used when the pattern has captures but capture stubs are not requested.
func stripCaptures(re *syntax.Regexp) {
	for _, sub := range re.Sub {
		stripCaptures(sub)
	}
	if re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		*re = *re.Sub[0]
	}
}

// SelectEngine returns the EngineType that would be chosen for the given pattern,
// without actually compiling it. Returns an error if the pattern cannot be parsed
// or compiled to NFA bytecode.
func SelectEngine(pattern string, opts CompileOptions) (EngineType, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, fmt.Errorf("parse error: %w", err)
	}
	hasCapturesBeforeSimplify := re.MaxCap() > 0
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0, fmt.Errorf("compile error: %w", err)
	}
	if needsUnicodeSupport(prog) && !opts.Unicode {
		return 0, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}
	return selectBestEngine(prog, hasCapturesBeforeSimplify, &opts), nil
}

// compile parses the pattern, selects the optimal engine, and returns a compiled matcher.
func compile(pattern string, opts ...CompileOptions) (matcher, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	hasCapturesBeforeSimplify := re.MaxCap() > 0

	simplified := re.Simplify()
	prog, err := syntax.Compile(simplified)
	if err != nil {
		return nil, fmt.Errorf("compile error: %w", err)
	}

	var options CompileOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	if requiresUnicode := needsUnicodeSupport(prog); requiresUnicode && !options.Unicode {
		return nil, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}

	var engineType EngineType
	if options.ForceEngine != 0 {
		engineType = options.ForceEngine
	} else {
		engineType = selectBestEngine(prog, hasCapturesBeforeSimplify, &options)
	}

	switch engineType {
	case EngineDFA:
		return newDFA(prog, options.Unicode, options.LeftmostFirst), nil
	case EngineBacktrack:
		return newBacktrack(prog), nil
	default:
		return nil, fmt.Errorf("engine %v not yet supported by wasm compiler", engineType)
	}
}

// needsUnicodeSupport analyzes whether a compiled program requires Unicode support.
func needsUnicodeSupport(prog *syntax.Prog) bool {
	const maxUnicode = 0x10ffff

	for i := range prog.Inst {
		inst := &prog.Inst[i]

		switch inst.Op {
		case syntax.InstRune, syntax.InstRune1:
			hasASCII := false
			hasNonASCII := false

			for _, r := range inst.Rune {
				if r <= 127 {
					hasASCII = true
				} else if r != maxUnicode {
					hasNonASCII = true
				}
			}

			if hasNonASCII && !hasASCII {
				return true
			}
		}
	}
	return false
}

// buildGroupsWrapperBody emits the WASM body for the exported groups wrapper function.
// See engine_dfa.go for the full documentation — this function was moved to compile.go
// because it is not DFA-specific; it is used by the module assembler.
//
// Signature: (ptr i32, len i32, out_ptr i32) → i32
func buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups int) []byte {
	var b []byte
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F) // 3 × i32
	b = append(b, 0x01, 0x7E) // 1 × i64
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x22, 0x06)
	b = append(b, 0x42, 0x7F)
	b = append(b, 0x51)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x05)
	b = append(b, 0x20, 0x06)
	b = append(b, 0x42, 0x20)
	b = append(b, 0x88)
	b = append(b, 0xA7)
	b = append(b, 0x21, 0x03)
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x20, 0x06)
	b = append(b, 0xA7)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6B)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(captureFuncIdx))
	b = append(b, 0x22, 0x04)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x46)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x05)
	for i := 0; i < numGroups*2; i++ {
		offset := uint32(i * 4)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x28, 0x02)
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x22, 0x05)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4E)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x20, 0x05)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x6A)
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, 0x04)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	return b
}

// appendWrapperCodeEntry appends a size-prefixed groups wrapper body to cs.
func appendWrapperCodeEntry(cs []byte, findFuncIdx, captureFuncIdx, numGroups int) []byte {
	body := buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// appendNamedGroupsWrapperCodeEntry appends a size-prefixed named-groups wrapper body to cs.
// The wrapper calls groupsFuncIdx (the groups wrapper) and maps numbered slot pairs
// to named output slots using compile-time constants from groupNames.
// groupNames[i] is the name for capture group i+1 (empty = unnamed, skip).
//
// Signature: (ptr i32, len i32, out_ptr i32) → i32
//
// The named-groups out_ptr layout is identical to groups out_ptr — the stub
// uses the name→index mapping to present results by name to callers.
// This function is a thin pass-through: it calls the groups wrapper and returns
// its result unchanged; named group mapping is handled entirely in the stub.
func appendNamedGroupsWrapperCodeEntry(cs []byte, groupsFuncIdx int) []byte {
	// Body: call groupsFuncIdx(ptr, len, out_ptr), return result.
	var b []byte
	b = append(b, 0x00)       // 0 local declarations
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x10)       // call
	b = utils.AppendULEB128(b, uint32(groupsFuncIdx))
	b = append(b, 0x0B) // end
	cs = utils.AppendULEB128(cs, uint32(len(b)))
	return append(cs, b...)
}
