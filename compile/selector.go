package compile

import (
	"context"
	"log/slog"
	"regexp/syntax"
)

// selectBestEngine analyses the compiled regex pattern and selects the optimal engine type.
// It considers pattern complexity, feature requirements (captures, word boundaries),
// and estimated resource usage to choose between Backtrack, DFA, TDFA, or CompiledDFA.
//
// The optional CompileOptions parameter can customize DFA selection thresholds.
// When omitted, uses sensible defaults (1000 states, 100KB memory limit).
//
// hadCapturesBeforeSimplify indicates if the original pattern had capture groups before
// Simplify() optimization. This is needed because Simplify() may remove {0} quantifiers
// but we still need to track unset capture groups in the output.
//
// Returns the recommended EngineType for the given pattern.
func selectBestEngine(prog *syntax.Prog, hadCapturesBeforeSimplify bool, opts *CompileOptions) EngineType {
	// Analyse pattern complexity and DFA viability
	analysis := analysePattern(prog)

	// Check for anchors and word boundaries which are incompatible with our DFA implementation
	// Classical DFA cannot properly handle position-dependent matching required by anchors (^, $, \A, \z)
	// The issue: DFA construction doesn't track whether anchors are required or optional.
	// A pattern like `(?:^)?abc` has an optional ^, so it should match "xabc" at position 1,
	// but the DFA's hasBeginAnchor flag treats it as required and won't try other positions.
	// Solution: Route ALL patterns with anchors to engines that handle position-dependent matching.
	hasAnchor := false
	hasWordBoundary := false
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstEmptyWidth {
			emptyOp := syntax.EmptyOp(inst.Arg)
			// Check for line/text anchors
			if emptyOp&syntax.EmptyBeginLine != 0 || emptyOp&syntax.EmptyEndLine != 0 ||
				emptyOp&syntax.EmptyBeginText != 0 || emptyOp&syntax.EmptyEndText != 0 {
				hasAnchor = true
			}
			// Check for word boundaries
			if emptyOp&syntax.EmptyWordBoundary != 0 || emptyOp&syntax.EmptyNoWordBoundary != 0 {
				hasWordBoundary = true
			}
			if hasAnchor && hasWordBoundary {
				break
			}
		}
	}

	// CRITICAL: DFA cannot implement leftmost-first alternation semantics
	// During subset construction, DFA merges states from different alternatives,
	// losing track of which alternative was taken first. This causes it to prefer
	// longer matches instead of leftmost-first when alternatives can match different lengths.
	// Examples that fail with DFA: (?:a|(?:a*)) on "aa" matches "aa" instead of "a"
	// We must exclude DFA for patterns with user alternations (| operator).
	// Note: Quantifier loops (a+, a*) also use InstAlt but don't have this issue.
	hasUserAlternations := hasNonLoopAlternations(prog)

	// CRITICAL: DFA cannot implement leftmost-first semantics for nested quantifiers
	// Classical DFA produces longest-match, not leftmost-first. With nested quantifiers,
	// this causes incorrect behavior. Example: (?:(?:a{3,4}){0,}) on "aaaaaa" should
	// match 4 chars (leftmost-first), but DFA matches all 6 (longest).
	hasNestedQuant := hasNestedQuantifiers(prog)

	// Calculate DFA estimates
	dfaStates := analysis.EstimatedDFAStates
	dfaMem := estimateDFAMemory(dfaStates)

	// Determine complexity label
	complexity := "Simple"
	if analysis.NumAlternations > 5 {
		complexity = "High alternations"
	} else if analysis.HasUnicode {
		complexity = "Unicode"
	} else if dfaStates > 100 {
		complexity = "Complex"
	}

	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		printAnalysis(analysis)
		slog.Debug("Pattern analysis",
			"complexity", complexity,
			"dfa_states", dfaStates,
			"dfa_memory_bytes", dfaMem)
	}

	// Decision logic:
	// 1. Try one-pass DFA first (fastest, but rare)
	// 2. If pattern has capture groups or word boundaries, use Backtracking
	// 3. If DFA is feasible (low state count, fits in memory), use it for speed
	// 4. Otherwise, use Backtracking as the general-purpose default

	// Check if pattern has capture groups
	// NumCap counts: [0]=full match start, [1]=full match end, [2+]=explicit capture groups
	// Simplify() may optimize away captures like (a){0}; if NumCap==2 after simplification,
	// no capture instructions remain in the NFA regardless of hadCapturesBeforeSimplify.
	hasCaptureGroups := prog.NumCap > 2

	// Capture groups: try TDFA first (O(n)), fall back to Backtrack for patterns TDFA
	// cannot correctly handle: non-greedy quantifiers, multiline line anchors,
	// word boundaries (broken \ b start-state construction), or overlapping greedy
	// Alt branches where a quantifier's char class includes the following separator.
	if hasCaptureGroups {
		if !hasNonGreedyQuantifiers(prog) && !hasLineAnchors(prog) &&
			!hasWordBoundary && !hasAmbiguousCaptures(prog) {
			tt, ok := newTDFA(prog, resolveMaxDFAStates(opts))
			if ok && tt.numRegs > resolveMaxTDFARegs(opts) {
				ok = false
				slog.Debug("Engine selected", "engine", "Backtrack", "reason", "TDFA register limit exceeded", "numRegs", tt.numRegs)
			}
			if ok {
				_ = tt // table will be built again in compilePattern; here we only report engine type
				slog.Debug("Engine selected", "engine", "TDFA", "reason", "capture pattern within state limit")
				return EngineTDFA
			}
			if tt != nil {
				slog.Debug("Engine selected", "engine", "Backtrack", "reason", "TDFA state limit exceeded")
			}
		} else {
			slog.Debug("Engine selected", "engine", "Backtrack", "reason", "non-greedy or line-anchor captures")
		}
		return EngineBacktrack
	}

	// DFA handles everything else. Patterns with user alternations or nested quantifiers
	// need leftmost-first semantics; all others use standard leftmost-longest.
	// The MaxDFAStates limit in CompileOptions is the real guard against state explosion.
	if hasUserAlternations || hasNestedQuant {
		if opts != nil {
			opts.LeftmostFirst = true
		}
		slog.Debug("Engine selected", "engine", "DFA", "reason", "leftmost-first semantics for alternations/nested quantifiers", "complexity", complexity, "states", dfaStates)
		return maybeCompiledDFA(EngineDFA, dfaStates, opts)
	}

	slog.Debug("Engine selected", "engine", "DFA", "reason", "simple pattern", "complexity", complexity, "states", dfaStates)
	return maybeCompiledDFA(EngineDFA, dfaStates, opts)
}

// maybeCompiledDFA promotes engine from EngineDFA to EngineCompiledDFA when the
// estimated state count fits within the compiled-DFA threshold.
// The estimate is pre-minimisation; the final decision is confirmed in buildDFALayout.
//
// The check is estimatedStates+1 <= threshold because WASM emission always
// reserves state 0 as the implicit dead state, so a DFA with N logical states
// occupies N+1 WASM state slots.  As a result the effective maximum number of
// logical states is threshold-1, not threshold.
func maybeCompiledDFA(engine EngineType, estimatedStates int, opts *CompileOptions) EngineType {
	if engine != EngineDFA {
		return engine
	}
	threshold := resolveCompiledDFAThreshold(opts)
	if threshold > 0 && estimatedStates+1 <= threshold {
		return EngineCompiledDFA
	}
	return EngineDFA
}

// resolveMaxDFAStates returns the effective DFA/TDFA state limit from opts.
// Zero → default (1024). Negative → disabled (0, meaning TDFA is never used).
func resolveMaxDFAStates(opts *CompileOptions) int {
	if opts == nil || opts.MaxDFAStates == 0 {
		return 1024
	}
	if opts.MaxDFAStates < 0 {
		return 0
	}
	return opts.MaxDFAStates
}

// resolveMaxTDFARegs returns the effective TDFA register limit from opts.
// Zero → default (32). Negative → disabled (0, meaning TDFA always falls back).
func resolveMaxTDFARegs(opts *CompileOptions) int {
	if opts == nil || opts.MaxTDFARegs == 0 {
		return 32
	}
	if opts.MaxTDFARegs < 0 {
		return 0
	}
	return opts.MaxTDFARegs
}

// resolveMaxDFAMemory returns the effective DFA table memory limit in bytes.
// Zero → no limit (default).
func resolveMaxDFAMemory(opts *CompileOptions) int {
	if opts == nil || opts.MaxDFAMemory == 0 {
		return 0
	}
	return opts.MaxDFAMemory
}

// resolveMemoBudget returns the effective BitState memo budget in bytes.
// Zero → default (128 KB).
func resolveMemoBudget(opts *CompileOptions) int {
	if opts == nil || opts.MemoBudget == 0 {
		return 128 * 1024
	}
	return opts.MemoBudget
}

// resolveCompiledDFAThreshold returns the effective compiled-DFA state threshold
// from opts. Zero → default (256). Negative → disabled (0). Capped at 256.
func resolveCompiledDFAThreshold(opts *CompileOptions) int {
	if opts == nil {
		return 256
	}
	switch {
	case opts.CompiledDFAThreshold < 0:
		return 0 // disabled
	case opts.CompiledDFAThreshold == 0:
		return 256 // default
	case opts.CompiledDFAThreshold > 256:
		return 256 // hard ceiling
	default:
		return opts.CompiledDFAThreshold
	}
}

// hasNonGreedyQuantifiers reports whether the NFA contains any non-greedy
// quantifier loop (prefer-exit Alt: Out >= PC, Arg < PC, i.e. try exit first).
func hasNonGreedyQuantifiers(prog *syntax.Prog) bool {
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt {
			pcU32 := uint32(pc)
			// Non-greedy: Out >= PC (exit first), Arg < PC (loop body backward)
			if inst.Out >= pcU32 && inst.Arg < pcU32 {
				return true
			}
		}
	}
	return false
}

// hasLineAnchors reports whether the NFA contains any begin-of-line (^) or
// end-of-line ($) assertions, either multiline (EmptyBeginLine/EmptyEndLine) or
// end-of-text (EmptyEndText = non-multiline $). TDFA does not correctly handle
// these assertions, so patterns with them fall back to backtracking.
func hasLineAnchors(prog *syntax.Prog) bool {
	for i := range prog.Inst {
		inst := &prog.Inst[i]
		if inst.Op == syntax.InstEmptyWidth {
			flag := syntax.EmptyOp(inst.Arg)
			if flag&(syntax.EmptyBeginLine|syntax.EmptyEndLine|syntax.EmptyEndText) != 0 {
				return true
			}
		}
	}
	return false
}

// hasAmbiguousCaptures reports whether any Alt in the NFA has non-disjoint
// first-character sets between its branches. When such an Alt is inside a
// capture group's quantifier, TDFA's LeftmostFirst priority causes the greedy
// loop to over-consume and record wrong capture positions. These patterns must
// use backtracking instead.
func hasAmbiguousCaptures(prog *syntax.Prog) bool {
	for pc, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			if !isAlternationDeterministic(prog, pc) {
				return true
			}
		}
	}
	return false
}

// hasNonLoopAlternations detects user alternations (| operator) vs quantifier loops.
// Quantifier loops like a+ use InstAlt but don't cause leftmost-first issues.
// User alternations like (a|b) or (?:a|(?:a*)) require leftmost-first semantics.
// Returns true if pattern has any InstAlt that is NOT a quantifier loop.
func hasNonLoopAlternations(prog *syntax.Prog) bool {
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt {
			pcU32 := uint32(pc)
			// Quantifier pattern: Out < PC and Arg >= PC
			// This catches a?, a*, a+ reliably
			// True alternations have different patterns (both backward or both forward)
			isQuantifier := inst.Out < pcU32 && inst.Arg >= pcU32
			if !isQuantifier {
				return true
			}
		}
	}
	return false
}

// hasNestedQuantifiers detects patterns where quantifiers are nested inside other quantifiers.
// Classical DFA handles these incorrectly because it produces longest-match semantics
// instead of leftmost-first. Example: (?:(?:a{3,4}){0,}) incorrectly matches all 6 chars
// in "aaaaaa" instead of just 4.
func hasNestedQuantifiers(prog *syntax.Prog) bool {
	inQuantifierLoop := make(map[uint32]bool)

	// First pass: identify all quantifier loop instructions.
	// Greedy loops:     Out < PC (backward body), Arg >= PC (forward exit).
	// Non-greedy loops: Arg < PC (backward body), Out >= PC (forward exit).
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt {
			pcU32 := uint32(pc)
			if inst.Out < pcU32 && inst.Arg >= pcU32 {
				// Greedy loop body: Out..PC-1; include the Alt itself
				for bodyPC := inst.Out; bodyPC < pcU32; bodyPC++ {
					inQuantifierLoop[bodyPC] = true
				}
			} else if inst.Arg < pcU32 && inst.Out >= pcU32 {
				// Non-greedy loop body: Arg..PC-1; include the Alt itself
				for bodyPC := inst.Arg; bodyPC < pcU32; bodyPC++ {
					inQuantifierLoop[bodyPC] = true
				}
			}
		}
	}

	// Second pass: any Alt inside a quantifier loop body = complex nested quantifier.
	// This catches both nested loops AND {m,n} forward-only Alts inside loops.
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt && inQuantifierLoop[uint32(pc)] {
			return true
		}
	}

	return false
}

// estimateDFAMemory estimates memory usage for a DFA.
func estimateDFAMemory(states int) int {
	// Each state: ~60 bytes + transitions
	// Assume average 10 transitions per state at 8 bytes each
	return states * (60 + 10*8)
}

// --------------------------------------------------------------------------
// Pattern analysis

// patternAnalysis contains metrics about a regex pattern.
type patternAnalysis struct {
	// Program metrics
	NumInstructions int
	NumCaptures     int
	NumAlternations int

	// Complexity indicators
	HasLargeCharClass bool
	HasUnicode        bool
	HasAnyRune        bool

	// DFA feasibility
	EstimatedDFAStates      int
	EstimatedDFATransitions int
	DFAMemoryEstimateKB     int
}

// analysePattern examines a compiled pattern and provides metrics
// used by selectBestEngine for engine selection decisions.
func analysePattern(prog *syntax.Prog) *patternAnalysis {
	analysis := &patternAnalysis{
		NumInstructions: len(prog.Inst),
		NumCaptures:     prog.NumCap,
	}

	for pc, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstAlt:
			isLoop := inst.Out < uint32(pc) && inst.Arg >= uint32(pc)
			if !isLoop {
				analysis.NumAlternations++
			}

		case syntax.InstRune:
			totalChars := 0
			for i := 0; i+1 < len(inst.Rune); i += 2 {
				totalChars += int(inst.Rune[i+1] - inst.Rune[i] + 1)
			}
			if totalChars > 256 {
				analysis.HasLargeCharClass = true
			}
			if len(inst.Rune) > 0 && inst.Rune[len(inst.Rune)-1] > 127 {
				analysis.HasUnicode = true
			}

		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			analysis.HasAnyRune = true
		}
	}

	analysis.estimateDFAComplexity()

	return analysis
}

func (a *patternAnalysis) estimateDFAComplexity() {
	baseStates := a.NumInstructions
	multiplier := 1.0

	if a.NumAlternations > 0 {
		multiplier = 1.0 + float64(a.NumAlternations)*0.2
		if multiplier > 3.0 {
			multiplier = 3.0
		}
	}

	a.EstimatedDFAStates = int(float64(baseStates) * multiplier)

	avgTransitionsPerState := 10
	if a.HasLargeCharClass {
		avgTransitionsPerState = 100
	}
	if a.HasUnicode {
		avgTransitionsPerState = 200
	}
	if a.HasAnyRune {
		avgTransitionsPerState = 256
	}

	a.EstimatedDFATransitions = a.EstimatedDFAStates * avgTransitionsPerState
	a.DFAMemoryEstimateKB = (a.EstimatedDFATransitions * 16) / 1024
}

func printAnalysis(a *patternAnalysis) {
	slog.Debug("Pattern metrics",
		"instructions", a.NumInstructions,
		"captures", a.NumCaptures,
		"alternations", a.NumAlternations)

	slog.Debug("Pattern features",
		"large_char_classes", a.HasLargeCharClass,
		"unicode", a.HasUnicode,
		"wildcards", a.HasAnyRune)

	slog.Debug("DFA estimates",
		"states", a.EstimatedDFAStates,
		"transitions", a.EstimatedDFATransitions,
		"memory_kb", a.DFAMemoryEstimateKB)
}

// --------------------------------------------------------------------------
// Alternation determinism helpers

// isEpsilonAccept reports whether pc can reach InstMatch via epsilon transitions
// only (no byte-consuming instructions). Used to detect loop-exit branches.
func isEpsilonAccept(prog *syntax.Prog, pc int) bool {
	visited := make(map[int]bool)
	var check func(int) bool
	check = func(pc int) bool {
		if pc >= len(prog.Inst) || visited[pc] {
			return false
		}
		visited[pc] = true
		inst := &prog.Inst[pc]
		switch inst.Op {
		case syntax.InstMatch:
			return true
		case syntax.InstCapture, syntax.InstNop:
			return check(int(inst.Out))
		case syntax.InstEmptyWidth:
			return check(int(inst.Out))
		case syntax.InstAlt, syntax.InstAltMatch:
			return check(int(inst.Out)) || check(int(inst.Arg))
		}
		return false
	}
	return check(pc)
}

// isAlternationDeterministic checks if an alternation has distinct first characters
// in each branch, making it deterministic.
func isAlternationDeterministic(prog *syntax.Prog, altPC int) bool {
	if altPC >= len(prog.Inst) {
		return false
	}

	alt := &prog.Inst[altPC]
	if alt.Op != syntax.InstAlt && alt.Op != syntax.InstAltMatch {
		return false
	}

	leftEpsilon := isEpsilonAccept(prog, int(alt.Out))
	rightEpsilon := isEpsilonAccept(prog, int(alt.Arg))

	// If one branch accepts without consuming bytes (epsilon → InstMatch) and
	// the other consumes bytes, they are always disjoint.
	if leftEpsilon || rightEpsilon {
		if leftEpsilon && rightEpsilon {
			return false // both epsilon-accept = ambiguous
		}
		return true // one epsilon, one byte-consuming = always disjoint
	}

	leftRunes := getFirstRuneSet(prog, int(alt.Out))
	rightRunes := getFirstRuneSet(prog, int(alt.Arg))

	if len(leftRunes) == 0 || len(rightRunes) == 0 {
		return false // can't determine first chars for at least one branch
	}

	for r := range leftRunes {
		if rightRunes[r] {
			return false
		}
	}

	return true
}

// getFirstRuneSet returns the set of runes that can start execution at the given PC.
func getFirstRuneSet(prog *syntax.Prog, pc int) map[rune]bool {
	if pc >= len(prog.Inst) {
		return make(map[rune]bool)
	}

	runes := make(map[rune]bool)
	visited := make(map[int]bool)

	var collect func(int) bool
	collect = func(pc int) bool {
		if pc >= len(prog.Inst) || visited[pc] {
			return true
		}

		visited[pc] = true
		if len(visited) > 50 {
			return false
		}

		inst := &prog.Inst[pc]

		switch inst.Op {
		case syntax.InstRune1:
			runes[inst.Rune[0]] = true
			return true

		case syntax.InstRune:
			if len(inst.Rune)%2 != 0 {
				return false
			}
			totalChars := 0
			for i := 0; i < len(inst.Rune); i += 2 {
				low, high := inst.Rune[i], inst.Rune[i+1]
				totalChars += int(high - low + 1)
			}
			if totalChars > 256 {
				return false
			}
			for i := 0; i < len(inst.Rune); i += 2 {
				low, high := inst.Rune[i], inst.Rune[i+1]
				for r := low; r <= high; r++ {
					runes[r] = true
				}
			}
			return true

		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			return false

		case syntax.InstCapture, syntax.InstNop:
			return collect(int(inst.Out))

		case syntax.InstEmptyWidth:
			return collect(int(inst.Out))

		case syntax.InstAlt, syntax.InstAltMatch:
			if !collect(int(inst.Out)) {
				return false
			}
			return collect(int(inst.Arg))

		case syntax.InstMatch:
			return false

		default:
			return false
		}
	}

	if !collect(pc) {
		return make(map[rune]bool)
	}

	return runes
}
