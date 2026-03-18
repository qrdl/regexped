package compile

import (
	"context"
	"fmt"
	"log/slog"
	"regexp/syntax"
)

const (
	// defaultMaxDFAStates is the default maximum DFA states before falling back to backtracking
	defaultMaxDFAStates = 1000
	// defaultMaxDFAMemory is the default maximum DFA memory in bytes (100 KB)
	defaultMaxDFAMemory = 100 * 1024
)

// selectBestEngine analyses the compiled regex pattern and selects the optimal engine type.
// It considers pattern complexity, feature requirements (captures, word boundaries),
// and estimated resource usage to choose between Backtrack, DFA, or OnePass engines.
//
// The optional CompileOptions parameter can customize DFA selection thresholds.
// When omitted, uses sensible defaults (1000 states, 100KB memory limit).
//
// hadCapturesBeforeSimplify indicates if the original pattern had capture groups before
// Simplify() optimization. This is needed because Simplify() may remove {0} quantifiers
// but we still need to track unset capture groups in the output.
//
// Returns the recommended EngineType for the given pattern.
func selectBestEngine(prog *syntax.Prog, hadCapturesBeforeSimplify bool, opts ...CompileOptions) EngineType {
	// Analyse pattern complexity and DFA viability
	analysis := analysePattern(prog)

	// Check if pattern is one-pass (best performance)
	isOnePassCandidate := isOnePass(prog)

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

	// Set defaults
	maxDFAStates := defaultMaxDFAStates
	maxDFAMemory := defaultMaxDFAMemory

	// Apply optional parameters
	if len(opts) > 0 {
		if opts[0].MaxDFAStates > 0 {
			maxDFAStates = opts[0].MaxDFAStates
		}
		if opts[0].MaxDFAMemory > 0 {
			maxDFAMemory = opts[0].MaxDFAMemory
		}
	}

	// Check if pattern has capture groups
	// NumCap counts: [0]=full match start, [1]=full match end, [2+]=explicit capture groups
	// However, Simplify() may optimize away captures like (a){0}, so also check the flag
	hasCaptureGroups := prog.NumCap > 2 || hadCapturesBeforeSimplify

	// Try one-pass first if pattern is simple enough
	// OnePass can handle many patterns including some simple alternations
	if isOnePassCandidate && len(prog.Inst) < 50 && !hasWordBoundary {
		slog.Debug("Engine selected", "engine", "OnePass", "reason", "deterministic single-state execution with capture support")
		return EngineOnePass
	}

	// DFA limitations:
	// 1. Classical DFA cannot handle word boundaries (\b, \B)
	// 2. Classical DFA cannot handle capture groups
	// 3. Classical DFA cannot implement leftmost-first for user alternations
	//
	// However, LAZY DFA can handle alternations correctly using priority-based matching!

	// Word boundaries require backtracking specifically
	// Check if pattern has end anchors that interact badly with alternations in lazy DFA
	hasEndAnchor := false
	for _, inst := range prog.Inst {
		if inst.Op == syntax.InstEmptyWidth {
			emptyOp := syntax.EmptyOp(inst.Arg)
			if emptyOp&syntax.EmptyEndLine != 0 || emptyOp&syntax.EmptyEndText != 0 {
				hasEndAnchor = true
				break
			}
		}
	}

	canUsePikeVM := !(hasUserAlternations && hasEndAnchor) && !hasNestedQuant

	// Word boundaries prefer NFA engines; allow AdaptiveNFA when Pike VM is safe
	if hasWordBoundary {
		if canUsePikeVM {
			slog.Debug("Engine selected", "engine", "AdaptiveNFA", "reason", "word boundaries with NFA fallback")
			return EngineAdaptiveNFA
		}
		slog.Debug("Engine selected", "engine", "Backtrack", "reason", "pattern has word boundaries, requires backtracking")
		return EngineBacktrack
	}

	// Use backtracking for patterns with captures
	if hasCaptureGroups {
		if canUsePikeVM {
			slog.Debug("Engine selected", "engine", "AdaptiveNFA", "reason", "captures with NFA fallback")
			return EngineAdaptiveNFA
		}
		slog.Debug("Engine selected", "engine", "Backtrack", "reason", "pattern has captures")
		return EngineBacktrack
	}

	// Lazy DFA can't properly handle alternations with end anchors
	// because empty-width assertions are position-dependent but DFA states are position-independent
	// Pike VM also struggles with alternation priority in these cases
	// Use Backtracking which naturally implements leftmost-first
	if hasUserAlternations && hasEndAnchor {
		slog.Debug("Engine selected", "engine", "Backtrack", "reason", "alternations with end anchor require position-dependent matching and leftmost-first semantics")
		return EngineBacktrack
	}

	// Check if DFA is viable based on complexity analysis
	// Lazy DFA can handle alternations with correct leftmost-first semantics
	// Classical DFA is still faster for patterns WITHOUT alternations or nested quantifiers
	if analysis.Recommendation == PreferDFA &&
		dfaStates < maxDFAStates &&
		dfaMem < maxDFAMemory {

		// Use lazy DFA for patterns with alternations (without end anchors)
		if hasUserAlternations {
			slog.Debug("Engine selected", "engine", "Lazy DFA", "reason", "alternations with leftmost-first semantics", "complexity", complexity, "states", dfaStates)
			return EngineLazyDFA
		}

		// Classical DFA cannot handle nested quantifiers (produces longest-match instead of leftmost-first)
		// Pike VM also struggles with leftmost-first for nested quantifiers
		// Use Backtracking which naturally implements leftmost-first by trying positions sequentially
		if hasNestedQuant {
			slog.Debug("Engine selected", "engine", "Backtrack", "reason", "nested quantifiers require leftmost-first semantics")
			return EngineBacktrack
		}

		// Classical DFA cannot handle anchors (^, $, \A, \z) correctly
		// The issue: DFA can't distinguish required vs optional anchors, leading to incorrect matching
		// Examples: (?:^)?abc , (?:$)? - anchors are optional but DFA treats them as required
		// While simple patterns like ^[a-z]+$ could work with DFA, detecting "simple" vs "complex"
		// anchored patterns is error-prone. Pike VM handles all anchored cases correctly.
		if hasAnchor {
			slog.Debug("Engine selected", "engine", "Pike VM", "reason", "pattern has anchors, requires position-dependent matching")
			return EnginePikeVM
		}

		// Use classical DFA for simple patterns (no alternations, no nested quantifiers, no anchors)
		slog.Debug("Engine selected", "engine", "DFA", "reason", "simple pattern, fits in memory, fastest matching", "complexity", complexity, "states", dfaStates)
		return EngineDFA
	}

	// Default to Backtracking (general-purpose NFA engine with visited tracking)
	if canUsePikeVM {
		slog.Debug("Engine selected", "engine", "AdaptiveNFA", "reason", "general-purpose NFA matching with runtime selection")
		return EngineAdaptiveNFA
	}
	slog.Debug("Engine selected", "engine", "Backtrack", "reason", "general-purpose NFA matching with visited tracking")
	return EngineBacktrack
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
				// This is a user alternation, not a quantifier loop
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
	// Track which PCs are inside a quantified loop
	inQuantifierLoop := make(map[uint32]bool)

	// First pass: identify all quantifier loop instructions
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt {
			pcU32 := uint32(pc)
			// Quantifier pattern: Out < PC and Arg >= PC
			isQuantifier := inst.Out < pcU32 && inst.Arg >= pcU32
			if isQuantifier {
				// Mark all PCs reachable from this quantifier loop
				// The loop body is between inst.Out and pc
				for bodyPC := inst.Out; bodyPC < pcU32; bodyPC++ {
					inQuantifierLoop[bodyPC] = true
				}
			}
		}
	}

	// Second pass: check if any quantifier is inside another quantifier
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if inst.Op == syntax.InstAlt {
			pcU32 := uint32(pc)
			isQuantifier := inst.Out < pcU32 && inst.Arg >= pcU32
			if isQuantifier && inQuantifierLoop[pcU32] {
				// This quantifier is nested inside another quantifier
				return true
			}
		}
	}

	return false
}

// estimateDFAMemory estimates memory usage for a DFA
func estimateDFAMemory(states int) int {
	// Each state: ~60 bytes + transitions
	// Assume average 10 transitions per state at 8 bytes each
	return states * (60 + 10*8)
}

// engineChoice represents the recommended execution engine
type engineChoice int

const (
	PreferNFA engineChoice = iota
	PreferDFA
	OnlyNFA // DFA not possible
)

// patternAnalysis contains metrics about a regex pattern
type patternAnalysis struct {
	// Program metrics
	NumInstructions int
	NumCaptures     int
	NumAlternations int
	NumRepeats      int

	// Complexity indicators
	HasBackreferences bool
	HasLookahead      bool
	HasLookbehind     bool
	HasLargeCharClass bool
	HasUnicode        bool
	HasAnyRune        bool

	// DFA feasibility
	EstimatedDFAStates      int
	EstimatedDFATransitions int
	DFAMemoryEstimateKB     int

	// Recommendation
	Recommendation engineChoice
	Reason         string
}

// analysePattern examines a compiled pattern and provides metrics
// Used by selectBestEngine for engine selection decisions
func analysePattern(prog *syntax.Prog) *patternAnalysis {
	analysis := &patternAnalysis{
		NumInstructions: len(prog.Inst),
		NumCaptures:     prog.NumCap,
	}

	// Scan instructions for features
	for pc, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstAlt:
			// Only count non-loop alternations (user alternations)
			// Loops are quantifiers like a+, a* and don't affect leftmost-first
			isLoop := inst.Out < uint32(pc) && inst.Arg >= uint32(pc)
			if !isLoop {
				analysis.NumAlternations++
			}

		case syntax.InstRune:
			// Check size of character class
			totalChars := 0
			for i := 0; i+1 < len(inst.Rune); i += 2 {
				totalChars += int(inst.Rune[i+1] - inst.Rune[i] + 1)
			}
			if totalChars > 100 {
				analysis.HasLargeCharClass = true
			}
			if len(inst.Rune) > 0 && inst.Rune[len(inst.Rune)-1] > 127 {
				analysis.HasUnicode = true
			}

		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			analysis.HasAnyRune = true

			// Note: syntax.Prog doesn't have backreferences/lookahead
			// Those would be rejected during compilation
		}
	}

	// Estimate DFA complexity using heuristics
	analysis.estimateDFAComplexity()

	// Make recommendation
	analysis.recommend()

	return analysis
}

// estimateDFAComplexity estimates DFA size
func (a *patternAnalysis) estimateDFAComplexity() {
	// Base states: roughly equal to instruction count
	// The instruction count already accounts for all the pattern structure including alternations
	// We don't need to multiply by alternations since they're already counted in instructions
	baseStates := a.NumInstructions

	// DFA may need slightly more states than NFA instructions due to:
	// - Start state
	// - Epsilon closure expansion
	// - Some state splitting for determinization
	// Use a modest multiplier that grows with pattern complexity
	multiplier := 1.0

	// Alternations may cause some state expansion during determinization
	// but NOT exponential - that only happens with nested/quantified alternations
	if a.NumAlternations > 0 {
		// Add 20% overhead per alternation, capped at 3x
		multiplier = 1.0 + float64(a.NumAlternations)*0.2
		if multiplier > 3.0 {
			multiplier = 3.0
		}
	}

	a.EstimatedDFAStates = int(float64(baseStates) * multiplier)

	// Transitions: each state needs transitions for char classes
	// For simple literal patterns, most states only need 1-2 transitions
	// For patterns with char classes, wildcards, etc., more transitions are needed
	avgTransitionsPerState := 10 // reduced default for literal-heavy patterns
	if a.HasLargeCharClass {
		avgTransitionsPerState = 100 // large char classes need more
	}
	if a.HasUnicode {
		avgTransitionsPerState = 200 // Unicode patterns need more
	}
	if a.HasAnyRune {
		avgTransitionsPerState = 256 // wildcards need transition for every byte
	}

	a.EstimatedDFATransitions = a.EstimatedDFAStates * avgTransitionsPerState

	// Memory estimate: roughly 16 bytes per transition (state ID + input + next state)
	a.DFAMemoryEstimateKB = (a.EstimatedDFATransitions * 16) / 1024
}

// recommend makes a recommendation based on analysis
func (a *patternAnalysis) recommend() {
	// Features that make DFA impossible or impractical
	if a.HasBackreferences || a.HasLookahead || a.HasLookbehind {
		a.Recommendation = OnlyNFA
		a.Reason = "Pattern uses features incompatible with DFA (backreferences/lookahead)"
		return
	}

	// Capture groups favor NFA (easier to implement)
	if a.NumCaptures > 4 {
		a.Recommendation = PreferNFA
		a.Reason = fmt.Sprintf("Many capture groups (%d) - easier with NFA", a.NumCaptures)
		return
	}

	// Large estimated DFA size
	if a.EstimatedDFAStates > 1000 {
		a.Recommendation = PreferNFA
		a.Reason = fmt.Sprintf("Pattern would create very large DFA (~%d states)", a.EstimatedDFAStates)
		return
	}

	if a.DFAMemoryEstimateKB > 500 {
		a.Recommendation = PreferNFA
		a.Reason = fmt.Sprintf("DFA would use too much memory (~%d KB)", a.DFAMemoryEstimateKB)
		return
	}

	// Many alternations can cause state explosion, but our estimation should catch that
	// Only reject if alternations are extreme AND we haven't already caught it in state/memory checks
	// (This is a safety net, butmost patterns will be caught by state/memory limits above)
	if a.NumAlternations > 20 {
		a.Recommendation = PreferNFA
		a.Reason = fmt.Sprintf("Too many alternations (%d) for DFA", a.NumAlternations)
		return
	}

	// Unicode patterns are problematic for DFA
	if a.HasUnicode && a.HasLargeCharClass {
		a.Recommendation = PreferNFA
		a.Reason = "Unicode character classes create huge transition tables"
		return
	}

	// "Any" character matching (. or .*) is NOT supported by current DFA implementation
	// because DFA subset construction skips InstRuneAny/InstRuneAnyNotNL during transition building
	// (see dfa.go line ~170 - these instructions are marked "problematic for DFA" and skipped)
	if a.HasAnyRune {
		a.Recommendation = PreferNFA
		a.Reason = "Wildcard matching requires NFA (DFA doesn't support InstRuneAny)"
		return
	}

	// If we got here, DFA is feasible and probably better
	a.Recommendation = PreferDFA
	a.Reason = fmt.Sprintf("Simple pattern (~%d states, ~%d KB) - DFA will be faster",
		a.EstimatedDFAStates, a.DFAMemoryEstimateKB)
}

// printAnalysis outputs analysis results using structured logging
func printAnalysis(a *patternAnalysis) {
	// Log program metrics
	slog.Debug("Pattern metrics",
		"instructions", a.NumInstructions,
		"captures", a.NumCaptures,
		"alternations", a.NumAlternations)

	// Log complexity features
	slog.Debug("Pattern features",
		"large_char_classes", a.HasLargeCharClass,
		"unicode", a.HasUnicode,
		"wildcards", a.HasAnyRune)

	// Log DFA estimates
	slog.Debug("DFA estimates",
		"states", a.EstimatedDFAStates,
		"transitions", a.EstimatedDFATransitions,
		"memory_kb", a.DFAMemoryEstimateKB)

	// Log recommendation
	recommendation := "unknown"
	switch a.Recommendation {
	case PreferNFA:
		recommendation = "NFA"
	case PreferDFA:
		recommendation = "DFA"
	case OnlyNFA:
		recommendation = "NFA (required)"
	}
	slog.Debug("Engine recommendation",
		"recommended", recommendation,
		"reason", a.Reason)
}
