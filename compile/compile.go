package compile

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/utils"
)

// MatchMode controls the generated WASM function's matching behaviour.
type MatchMode int

const (
	// ModeAnchoredMatch generates a function (ptr, len i32) -> i32 that matches
	// the full input anchored at position 0, returning end position or -1.
	ModeAnchoredMatch MatchMode = 0

	// ModeFind generates a function (ptr, len i32) -> i64 that scans the input
	// for the leftmost-longest match, returning packed (start<<32|end) or -1.
	ModeFind MatchMode = 1
)

// EngineType represents the type of regex engine implementation.
type EngineType byte

const (
	EngineDFA EngineType = iota + 1
	EngineBacktrack
	EngineOnePass
	EnginePikeVM
	EngineAdaptiveNFA
)

// String returns the human-readable name of the engine type.
func (e EngineType) String() string {
	switch e {
	case EngineBacktrack:
		return "Backtracking"
	case EngineDFA:
		return "DFA"
	case EngineOnePass:
		return "One-Pass DFA"
	case EnginePikeVM:
		return "Pike VM"
	case EngineAdaptiveNFA:
		return "Adaptive NFA"
	default:
		return "Unknown"
	}
}

// Matcher is the common interface implemented by all regex engines.
type Matcher interface {
	Type() EngineType
}

// CompileOptions contains optional parameters for engine selection.
type CompileOptions struct {
	MaxDFAStates       int        // Maximum DFA states before falling back (default: 1000)
	MaxDFAMemory       int        // Maximum DFA memory in bytes (default: 102400)
	Unicode            bool       // Enable Unicode support
	AdaptiveNFACutover int        // Input size in bytes to switch to Pike VM in AdaptiveNFA
	ForceEngine        EngineType // If non-zero, skip engine selection and use this engine type
	Mode               MatchMode  // ModeAnchoredMatch (default) or ModeFind
	LeftmostFirst      bool       // Use leftmost-first (RE2/Perl) semantics for alternations
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
	isOnePass  bool     // true = OnePass capture; false = Backtracking
	groupNames []string // groupNames[i] = name for group i+1; "" = unnamed

	dataSegCount int   // number of data segments in dataBytes
	dataBytes    []byte // raw data segments (no count prefix)

	tableEnd int64
}

// funcCount returns the number of WASM functions this pattern contributes.
func (p *compiledPattern) funcCount() int {
	n := 0
	if p.matchBody != nil { n++ }
	if p.findBody != nil  { n++ }
	if p.captureBody != nil {
		n++ // capture_internal
		if !p.anchored            { n++ } // groups_wrapper
		if p.namedGroupsExport != "" { n++ } // named_groups_wrapper
	}
	return n
}

// offsets returns the sub-indices of each function within this pattern.
// Returns -1 for absent functions.
func (p *compiledPattern) offsets() (matchOff, findOff, captureOff, wrapperOff, namedWrapperOff int) {
	matchOff, findOff, captureOff, wrapperOff, namedWrapperOff = -1, -1, -1, -1, -1
	idx := 0
	if p.matchBody != nil      { matchOff = idx; idx++ }
	if p.findBody != nil       { findOff = idx; idx++ }
	if p.captureBody != nil    {
		captureOff = idx; idx++
		if !p.anchored              { wrapperOff = idx; idx++ }
		if p.namedGroupsExport != "" { namedWrapperOff = idx; idx++ }
	}
	return
}

// stripSegCount strips the LEB128 count prefix from a data section payload,
// returning the raw segment bytes and the count.
func stripSegCount(data []byte) ([]byte, int) {
	if len(data) == 0 { return nil, 0 }
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
func compilePattern(re config.RegexEntry, tableBase int64) (*compiledPattern, error) {
	needMatch  := re.MatchFunc != ""
	needFind   := re.FindFunc != ""
	needGroups := re.CaptureStubsRequested()

	if !needMatch && !needFind && !needGroups {
		return &compiledPattern{tableEnd: tableBase}, nil
	}

	const maxStates = 100000

	// Match function uses LL (leftmostFirst=false): finds the longest full-string
	// match from pos 0, matching RE2/Go anchored-match semantics.
	// Find/groups use LF (leftmostFirst=true): leftmost-first Perl semantics.
	// These require separate DFA compilations.

	var matchBody   []byte
	var matchData   []byte
	var matchSegCnt int
	var matchEnd    int64

	cur := tableBase

	if needMatch {
		// Match uses LL (leftmostFirst=false): all NFA alternative paths are kept in each
		// DFA state, so the DFA can find ANY path that consumes the full input string.
		// LF would discard lower-priority alternatives after a higher-priority one matches,
		// making full-string match fail for patterns like `a|aa` on "aa" (LF picks `a` at
		// pos 0, loses the `aa` path, then can't reach the end of input).
		// This matches Go stdlib semantics: regexp.MustCompile("^(a|aa)$").MatchString("aa") = true.
		llOpts  := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: false}
		llMatch, llErr := compile(re.Pattern, llOpts)
		if llErr != nil { return nil, fmt.Errorf("compile match DFA: %w", llErr) }
		llTable := dfaTableFrom(llMatch.(*dfa))
		if llTable.numStates > maxStates {
			return nil, fmt.Errorf("DFA has %d states, exceeds limit %d", llTable.numStates, maxStates)
		}
		lm := buildDFALayout(llTable, cur, false, false)
		matchBody = appendMatchCodeEntry(nil, lm, lm.hasImmAccept)
		rawM, cntM := stripSegCount(dfaDataSegments(lm, false))
		matchData   = rawM
		matchSegCnt = cntM
		matchEnd    = lm.tableEnd
		cur         = utils.PageAlign(lm.tableEnd)
	}

	// LF DFA for find and/or groups.
	opts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: true}
	matcher, err := compile(re.Pattern, opts)
	if err != nil {
		return nil, fmt.Errorf("compile DFA: %w", err)
	}
	table := dfaTableFrom(matcher.(*dfa))
	if table.numStates > maxStates {
		return nil, fmt.Errorf("DFA has %d states, exceeds limit %d", table.numStates, maxStates)
	}

	anchored      := isAnchoredFind(table)
	needFindBody  := needFind || (needGroups && !anchored)
	l             := buildDFALayout(table, cur, needFindBody, true)
	mandatoryLit  := FindMandatoryLit(re.Pattern)

	p := &compiledPattern{
		matchExport: re.MatchFunc,
		findExport:  re.FindFunc,
		anchored:    anchored,
	}

	if needMatch {
		p.matchBody    = matchBody
		p.dataBytes    = matchData
		p.dataSegCount = matchSegCnt
		if !needFind && !needGroups {
			p.tableEnd = matchEnd
			return p, nil
		}
	}

	if needFindBody { p.findBody = appendFindCodeEntry(nil, l, table, mandatoryLit) }

	rawData, segCount := stripSegCount(dfaDataSegments(l, needFindBody))
	p.dataBytes    = append(p.dataBytes, rawData...)
	p.dataSegCount += segCount
	p.tableEnd      = l.tableEnd

	if !needGroups {
		return p, nil
	}

	p.groupsExport      = re.GroupsFunc  // only set when groups_func explicitly requested
	if re.NamedGroupsFunc != "" {
		p.namedGroupsExport = re.NamedGroupsFunc
	}

	parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
	if err != nil { return nil, fmt.Errorf("parse error: %w", err) }
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil { return nil, fmt.Errorf("compile NFA: %w", err) }
	if needsUnicodeSupport(prog) {
		return nil, fmt.Errorf("pattern contains Unicode features not yet supported")
	}

	p.groupNames = extractGroupNames(parsed)
	groupsEngine := selectBestEngine(prog, prog.NumCap > 2, nil)
	p.isOnePass   = (groupsEngine == EngineOnePass)

	if p.isOnePass {
		op         := newOnePass(prog)
		opBase     := utils.PageAlign(l.tableEnd)
		p.numGroups = op.numGroups
		p.captureBody = appendOnePassCodeEntry(nil, op, int32(opBase))
		p.tableEnd  = utils.PageAlign(opBase + int64(op.numStates*256))
		p.dataBytes  = append(p.dataBytes, onePassDataEntry(op, opBase)...)
		p.dataSegCount++
	} else {
		bt := newBacktrack(prog)

		// Stack placed directly after LF DFA tables — no Phase 1 DFA needed.
		// The wrapper already calls find_internal to locate the match; capture_internal
		// receives the bounded slice (end_LF - start) and runs the NFA directly.
		btBase     := utils.PageAlign(l.tableEnd)
		numCapLocs := bt.numGroups * 2
		frameSize  := 4 + numCapLocs*4 + 4
		maxFrames  := bt.numAlts * 4096
		if maxFrames < 4096 { maxFrames = 4096 }
		stackSize  := maxFrames * frameSize
		stackBase  := int32(btBase)
		stackLimit := stackBase + int32(stackSize)

		p.numGroups   = bt.numGroups
		p.captureBody = appendBacktrackCodeEntry(nil, bt, stackBase, stackLimit, int32(frameSize))
		p.tableEnd    = utils.PageAlign(btBase + int64(stackSize))
	}

	return p, nil
}

// assembleModule builds a single WASM module from multiple compiled patterns.
// standalone=true: module defines its own memory.
// standalone=false: module imports memory from "main" (for wasm-merge).
func assembleModule(patterns []*compiledPattern, memPages int32, standalone bool) []byte {
	// Pass 1: assign base function indices.
	baseIdx := make([]int, len(patterns))
	total   := 0
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
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,        // type 0: (i32,i32)→i32
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E,        // type 1: (i32,i32)→i64
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,  // type 2: (i32,i32,i32)→i32
	}
	out = appendSection(out, 1, typeSection)

	// Import section (if !standalone): import memory from "main".
	if !standalone {
		var imp []byte
		imp = append(imp, 0x01)
		imp = appendString(imp, "main")
		imp = appendString(imp, "memory")
		imp = append(imp, 0x02, 0x00)
		imp = utils.AppendULEB128(imp, 0x00)
		out = appendSection(out, 2, imp)
	}

	// Function section.
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(total))
	for _, p := range patterns {
		if p.matchBody != nil    { fs = append(fs, 0x00) }
		if p.findBody != nil     { fs = append(fs, 0x01) }
		if p.captureBody != nil  {
			fs = append(fs, 0x02)
			if !p.anchored               { fs = append(fs, 0x02) }
			if p.namedGroupsExport != "" { fs = append(fs, 0x02) }
		}
	}
	out = appendSection(out, 3, fs)

	// Memory section (if standalone).
	if standalone {
		var mem []byte
		mem = append(mem, 0x01, 0x00)
		mem = utils.AppendULEB128(mem, uint32(memPages))
		out = appendSection(out, 5, mem)
	}

	// Export section.
	numExports := 0
	if standalone { numExports++ }
	for _, p := range patterns {
		if p.matchExport != ""       { numExports++ }
		if p.findExport != ""        { numExports++ }
		if p.groupsExport != ""      { numExports++ }
		if p.namedGroupsExport != "" { numExports++ }
	}
	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02, 0x00)
	}
	for i, p := range patterns {
		base := baseIdx[i]
		matchOff, findOff, captureOff, wrapperOff, namedWrapperOff := p.offsets()
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
		_, findOff, captureOff, _, _ := p.offsets()
		if p.matchBody != nil { cs = append(cs, p.matchBody...) }
		if p.findBody != nil  { cs = append(cs, p.findBody...) }
		if p.captureBody != nil {
			cs = append(cs, p.captureBody...)
			if !p.anchored {
				cs = appendWrapperCodeEntry(cs, base+findOff, base+captureOff, p.numGroups, p.isOnePass)
				if p.namedGroupsExport != "" {
					_, _, _, wrapperOff, _ := p.offsets()
					cs = appendNamedGroupsWrapperCodeEntry(cs, base+wrapperOff)
				}
			} else if p.namedGroupsExport != "" {
				cs = appendNamedGroupsWrapperCodeEntry(cs, base+captureOff)
			}
		}
	}
	out = appendSection(out, 10, cs)

	// Data section.
	totalSegs := 0
	var rawData []byte
	for _, p := range patterns {
		totalSegs += p.dataSegCount
		rawData    = append(rawData, p.dataBytes...)
	}
	// Non-standalone Backtracking patterns need a sentinel at tableEnd-1 so that
	// regexMemoryTop in merge.go sees the full memory extent (stack is zero-init).
	if !standalone {
		for _, p := range patterns {
			if p.captureBody != nil && !p.isOnePass && p.tableEnd > 0 {
				rawData = appendDataSegment(rawData, int32(p.tableEnd-1), []byte{0x00})
				totalSegs++
			}
		}
	}
	if totalSegs > 0 {
		var ds []byte
		ds = utils.AppendULEB128(ds, uint32(totalSegs))
		ds = append(ds, rawData...)
		out = appendSection(out, 11, ds)
	}

	return out
}

// Compile compiles multiple regex patterns to a single WASM module.
//   - standalone=false: module imports memory from "main" (for wasm-merge with Rust binary)
//   - standalone=true:  module defines its own memory (for testing, future Component Model)
//   - tableBase: starting address for DFA/capture tables; use 0 for standalone CM-style
//
// All patterns must compile successfully; any error stops compilation immediately.
func Compile(patterns []config.RegexEntry, tableBase int64, standalone bool) ([]byte, int64, error) {
	var compiled []*compiledPattern
	cur := tableBase
	for _, re := range patterns {
		p, err := compilePattern(re, cur)
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
	memPages     := int32(utils.PageAlign(lastTableEnd) / 65536)
	if memPages < 1 { memPages = 1 }
	return assembleModule(compiled, memPages, standalone), lastTableEnd, nil
}

// CmdCompile compiles all regex patterns from cfg to a single WASM module.
// wasmInput is the Rust/host WASM used to determine memory layout (rustTop).
// outputFile overrides cfg.WasmFile; if both are empty, returns an error.
// outDir is used to resolve relative output paths.
func CmdCompile(cfg config.BuildConfig, wasmInput, outDir, outputFile string) error {
	rustTop, err := utils.RustMemTop(wasmInput)
	if err != nil {
		return fmt.Errorf("read wasm-input: %w", err)
	}

	outPath := outputFile
	if outPath == "" {
		outPath = cfg.WasmFile
	}
	if outPath == "" {
		return fmt.Errorf("output WASM file not specified: use -o flag or set wasm_file in config")
	}
	if !filepath.IsAbs(outPath) && outDir != "" {
		outPath = filepath.Join(outDir, outPath)
	}

	tableBase := utils.PageAlign(rustTop)
	slog.Info("Compiling regexes", "count", len(cfg.Regexes), "output", outPath)

	wasmBytes, _, err := Compile(cfg.Regexes, tableBase, false)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	if err := os.WriteFile(outPath, wasmBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	slog.Info("Done", "bytes", len(wasmBytes))
	return nil
}

// CompileRegex compiles a single regex pattern to WASM bytes.
// tableBase must be page-aligned and >= 0.
// If standalone is true, the module defines its own memory (suitable for testing);
// otherwise it imports memory from the "main" module.
// Returns the WASM bytes and the next available table base (page-aligned end of this module's data).
// An optional CompileOptions argument overrides the defaults.
func CompileRegex(pattern, exportName string, tableBase int64, standalone bool, userOpts ...CompileOptions) ([]byte, int64, error) {
	opts := CompileOptions{
		MaxDFAStates: 100000,
		Unicode:      false,
		ForceEngine:  EngineDFA,
	}
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	matcher, err := compile(pattern, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("compile error: %w", err)
	}
	if matcher.Type() != EngineDFA {
		return nil, 0, fmt.Errorf("unexpected engine %v (wanted DFA)", matcher.Type())
	}
	table := dfaTableFrom(matcher.(*dfa))

	if opts.MaxDFAStates > 0 && table.numStates > opts.MaxDFAStates {
		return nil, 0, fmt.Errorf("DFA has %d states, exceeds limit %d", table.numStates, opts.MaxDFAStates)
	}

	numWASM := table.numStates + 1
	var dfaSize int64
	switch {
	case numWASM <= 256 && numWASM*256 > 32*1024: // u8 + compression
		_, _, nc := computeByteClasses(table)
		dfaSize = int64(256 + numWASM*nc + numWASM)
	case numWASM <= 256: // u8, no compression
		dfaSize = int64(numWASM*256 + numWASM)
	default: // u16
		dfaSize = int64(numWASM*256*2 + numWASM)
	}
	if opts.Mode == ModeFind {
		dfaSize += int64(numWASM) // midAccept flags
		// firstByte flags (256 bytes) only when there is no literal prefix;
		// with a prefix the skip uses hardcoded comparisons, no table needed.
		if len(computePrefix(table)) == 0 {
			dfaSize += 256
		}
		// wordCharTable (256 bytes) prepended before DFA table for word-boundary patterns.
		// Also add midAcceptNW and midAcceptW flag arrays (numWASM bytes each).
		if table.hasWordBoundary {
			dfaSize += 256 + int64(numWASM)*2
		}
	}
	if opts.LeftmostFirst && len(table.immediateAcceptStates) > 0 {
		dfaSize += int64(numWASM) // immediateAccept flags
	}

	tableEnd := utils.PageAlign(tableBase + dfaSize)
	memPages := int32(tableEnd / 65536)

	matchExport, findExport := "", ""
	if opts.Mode == ModeFind {
		findExport = exportName
	} else {
		matchExport = exportName
	}
	var mandatoryLit *MandatoryLit
	if opts.Mode == ModeFind {
		mandatoryLit = FindMandatoryLit(pattern)
	}
	wasmBytes := genWASM(table, tableBase, matchExport, findExport, standalone, memPages, opts.LeftmostFirst, mandatoryLit)
	return wasmBytes, tableEnd, nil
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

// parseMode converts the YAML mode string to a MatchMode constant.
func parseMode(s string) MatchMode {
	if s == "find" {
		return ModeFind
	}
	return ModeAnchoredMatch
}

// compile parses the pattern, selects the optimal engine, and returns a compiled Matcher.
func compile(pattern string, opts ...CompileOptions) (Matcher, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	hasCapturesBeforeSimplify := re.MaxCap() > 0
	originalMaxCap := re.MaxCap()
	_ = originalMaxCap

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
func buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups int, isOnePass bool) []byte {
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
func appendWrapperCodeEntry(cs []byte, findFuncIdx, captureFuncIdx, numGroups int, isOnePass bool) []byte {
	body := buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups, isOnePass)
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
	b = append(b, 0x00) // 0 local declarations
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x10)       // call
	b = utils.AppendULEB128(b, uint32(groupsFuncIdx))
	b = append(b, 0x0B) // end
	cs = utils.AppendULEB128(cs, uint32(len(b)))
	return append(cs, b...)
}
