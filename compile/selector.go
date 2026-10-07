package compile

import (
	"context"
	"log/slog"
	"regexp/syntax"
	"sort"
	"unicode"
)

// selectBestEngine analyses the compiled regexp pattern and selects the optimal engine type.
// It considers pattern complexity, feature requirements (captures, word boundaries),
// and estimated resource usage to choose between Backtrack, DFA, TDFA, or CompiledDFA.
//
// The optional CompileOptions parameter can customize DFA selection thresholds.
// When omitted, uses sensible defaults (1000 states, 100KB memory limit).
//
// Returns the recommended EngineType for the given pattern.
func selectBestEngine(mp resolvedProg, opts *CompileOptions) EngineType {
	engine, _ := selectBestEngineWithTDFA(mp, opts)
	return engine
}

// selectBestEngineWithTDFA is selectBestEngine plus the TDFA table it had to
// build to answer the question.
//
// Deciding whether a capture pattern is TDFA-eligible requires actually
// constructing the tagged DFA — the state and register limits are properties of
// the built automaton, not of the pattern text. That table used to be thrown
// away (`_ = tt`, "table will be built again in compilePattern"), so every TDFA
// pattern paid for two identical constructions. newTDFA is the expensive step:
// 88 ms for a 16-state automaton before a strconv fix, ~46 ms after.
//
// The second return value is non-nil ONLY when the returned engine is
// EngineTDFA, i.e. only when the table passed both the state limit and the
// register limit and is exactly the table compilePattern would have rebuilt
// from the same prog and the same CompileOptions. Callers that override the
// engine choice (CompileForced) must therefore still handle a nil table.
//

func selectBestEngineWithTDFA(mp resolvedProg, opts *CompileOptions) (EngineType, *tdfaTable) {
	// Every analysis below reads the program as the pattern wrote it; only
	// the TDFA it may build reads the lowered one (mp). In byte mode the two
	// are the same program. A lowered class is an alternation of byte
	// sequences whose lead bytes distinct scripts share, so on it the
	// alternation, ambiguity and size heuristics would judge the encoding
	// rather than the pattern.
	prog := mp.orig
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

	// Calculate DFA estimates. The size is the one estimate that must read the
	// LOWERED program: a lowered class's states are the automaton's states, and
	// `\pL{5}x`, six instructions as written, is a 1,452-state table — the
	// written program had SelectEngine answer Compiled DFA for it.
	dfaStates := analysis.EstimatedDFAStates
	if mp.unicode() {
		dfaStates = estimatedDFAStates(mp.prog)
	}
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
	// a begin-of-text assertion anywhere but a start-anchored pattern's own
	// start, word boundaries (broken \ b start-state construction), or
	// overlapping greedy Alt branches where a quantifier's char class includes
	// the following separator.
	if hasCaptureGroups {
		if !hasNonGreedyQuantifiers(prog) && !hasLineAnchors(prog) &&
			!hasUnsafeBeginText(prog) && !hasWordBoundary && !hasAmbiguousCaptures(prog, mp.unicode()) {
			tt, ok := newTDFA(mp, resolveMaxDFAStates(opts, mp.unicode()))
			if ok && tt.numRegs > resolveMaxTDFARegs(opts) {
				ok = false
				slog.Debug("Engine selected", "engine", "Backtrack", "reason", "TDFA register limit exceeded", "numRegs", tt.numRegs)
				opts.report().Engine(EngineBacktrack, "TDFA register limit exceeded")
				opts.report().Limit("TDFA registers", tt.numRegs, resolveMaxTDFARegs(opts))
			}
			if ok {
				// Handed back to compilePattern rather than discarded — this is
				// the table it would otherwise rebuild verbatim. See this
				// function's doc comment.
				slog.Debug("Engine selected", "engine", "TDFA", "reason", "capture pattern within state limit")
				opts.report().Engine(EngineTDFA, "captures present, TDFA eligible and within limits")
				opts.report().Limit("TDFA states", tt.numStates, resolveMaxDFAStates(opts, mp.unicode()))
				opts.report().Limit("TDFA registers", tt.numRegs, resolveMaxTDFARegs(opts))
				return EngineTDFA, tt
			}
			// tt == nil is the STATE limit and nothing else: newTDFA is the
			// only thing that can fail here, it returns a nil table when its
			// own ceiling fires, and the register limit above sets ok=false
			// while leaving the table it measured intact.
			//
			// The guard used to read `tt != nil`, which inverted both halves.
			// A register-limit pattern reached this block with its table in
			// hand and had its accurate reason OVERWRITTEN — reported as
			// "raise max_dfa_states" while printing "TDFA states 26 of 1024",
			// i.e. pointing at the one knob that could not help, when
			// max_tdfa_regs was the answer. A genuine state-limit pattern took
			// the opposite fate: tt was nil, so nothing was reported at all
			// and the demotion the flag exists to explain went unexplained.
			if tt == nil {
				slog.Debug("Engine selected", "engine", "Backtrack", "reason", "TDFA state limit exceeded")
				// No Limit line: construction stopped at the ceiling, so there
				// is no final state count, and inventing one would be worse
				// than the number's absence.
				opts.report().Engine(EngineBacktrack, "TDFA state limit exceeded — raise max_dfa_states to keep O(n) captures")
			}
		} else {
			slog.Debug("Engine selected", "engine", "Backtrack", "reason", "non-greedy or line-anchor captures")
			opts.report().Engine(EngineBacktrack, "captures present but TDFA-ineligible (non-greedy quantifier, line anchor, word boundary or ambiguous alternation)")
		}
		return EngineBacktrack, nil
	}

	// DFA handles everything else. Patterns with user alternations or nested quantifiers
	// need leftmost-first semantics; all others use standard leftmost-longest.
	// The MaxDFAStates limit in CompileOptions is the real guard against state explosion.
	if hasUserAlternations || hasNestedQuant {
		if opts != nil {
			opts.LeftmostFirst = true
		}
		slog.Debug("Engine selected", "engine", "DFA", "reason", "leftmost-first semantics for alternations/nested quantifiers", "complexity", complexity, "states", dfaStates)
		return maybeCompiledDFA(EngineDFA, dfaStates, opts, mp.unicode()), nil
	}

	slog.Debug("Engine selected", "engine", "DFA", "reason", "simple pattern", "complexity", complexity, "states", dfaStates)
	return maybeCompiledDFA(EngineDFA, dfaStates, opts, mp.unicode()), nil
}

// maybeCompiledDFA promotes engine from EngineDFA to EngineCompiledDFA when the
// estimated state count fits within the compiled-DFA threshold.
// The estimate is pre-minimisation; the final decision is confirmed in buildDFALayout.
//
// The check is estimatedStates+1 <= threshold because WASM emission always
// reserves state 0 as the implicit dead state, so a DFA with N logical states
// occupies N+1 WASM state slots.  As a result the effective maximum number of
// logical states is threshold-1, not threshold. unicode is the pattern's
// mode, for the state limit the estimate is reported against.
func maybeCompiledDFA(engine EngineType, estimatedStates int, opts *CompileOptions, unicode bool) EngineType {
	if engine != EngineDFA {
		return engine
	}
	threshold := resolveCompiledDFAThreshold(opts)
	opts.report().Limit("DFA states", estimatedStates, resolveMaxDFAStates(opts, unicode))
	if threshold > 0 && estimatedStates+1 <= threshold {
		opts.report().Engine(EngineCompiledDFA, "no captures; promoted to direct-index dispatch under the CompiledDFA threshold")
		opts.report().Limit("CompiledDFA threshold", estimatedStates+1, threshold)
		return EngineCompiledDFA
	}
	opts.report().Engine(EngineDFA, "no captures; over the CompiledDFA threshold, so table-driven")
	opts.report().Limit("CompiledDFA threshold", estimatedStates+1, threshold)
	return EngineDFA
}

// maxHelperDFAStates is a hard safety ceiling for newDFA construction,
// deliberately DECOUPLED from the user-facing CompileOptions.MaxDFAStates
// threshold. It exists purely to bound worst-case subset-construction cost
// against pathological patterns (e.g. two independent bounded-repetition
// inverted classes straddling an ambiguous split point, which makes the
// number of distinct reachable NFA-state subsets explode with no plateau
// in sight — confirmed live: 40,000+ states in 12s, no sign of leveling
// off). It must stay well above any MaxDFAStates value legitimate callers
// configure (including deliberately tiny values like 1 or 4, used by
// several existing tests to force the "DFA too large, fall back to BT"
// path) — those callers still need a REAL, if oversized, dfaTable back:
// buildBTMatchBody/buildBTFindBody's mandatory-literal-prefix optimisation
// (computePrefix) reads that table even when it's far too large to serve as
// the primary matching engine. Using MaxDFAStates itself as this cap would
// silently break that optimisation (and crash on a nil table) for every
// such caller. maxHelperDFAStates is only meant to catch constructions that
// are not just "too large to use as DFA" but "too large to have finished
// computing in reasonable time at all" — comfortably above every state
// count produced by any pattern in this package's test suite (the largest,
// TestCompileLargeStateDFA / a{512}-style patterns, stay in the low
// hundreds to ~1000 states) — 2048 gives 2x headroom above that while
// keeping worst-case pathological construction cost to ~370ms (measured),
// rather than the multi-second-and-climbing cost of a higher ceiling.
const maxHelperDFAStates = 2048

// defaultMaxDFAStates and defaultMaxDFAStatesUnicode are max_dfa_states'
// defaults. A lowered Unicode class costs states per POSITION — about 290 for
// `\pL` — so at 1,024 a pattern with a few of them fell back to Backtracking,
// whose lowered program is as large as the class: `\pL{5}x` cost 25,964
// fuel/byte there against 38.9 as a 1,452-state DFA, with a 2.9 MB module
// against 746 KB, and `\pL{10}` could not be built at all (measured
// 2026-10-05). A table over 256 states is (states + 1) × 512 bytes, so the
// Unicode default allows about 8 MB per DFA.
const (
	defaultMaxDFAStates        = 1024
	defaultMaxDFAStatesUnicode = 16384
)

// resolveMaxDFAStates returns the effective DFA/TDFA state limit from opts,
// for a pattern in a Unicode mode when unicode is set. Zero → the mode's
// default. Negative → disabled (0, meaning TDFA is never used).
func resolveMaxDFAStates(opts *CompileOptions, unicode bool) int {
	if opts == nil || opts.MaxDFAStates == 0 {
		if unicode {
			return defaultMaxDFAStatesUnicode
		}
		return defaultMaxDFAStates
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

// hasUnsafeBeginText reports whether the NFA carries a begin-of-text assertion
// (\A, or ^ outside multiline) in a position TDFA cannot honour.
//
// EmptyBeginText is the one empty-width op the other three gates let through:
// hasLineAnchors covers EmptyBeginLine/EmptyEndLine/EmptyEndText and
// hasWordBoundary covers \b/\B. TDFA does not honour it either. Its subset
// construction is careful — the start closure uses ecBegin and every
// mid-string closure ctx=0 (engine_tdfa.go) — but the capture-op walks that
// decide which tag ops fire on a transition, tdfaEpsCapOps and
// tdfaEpsCapOpsTo, traverse InstEmptyWidth unconditionally. So a `^` reached
// after bytes have been consumed hands out capture positions for a branch
// that cannot run: `0*(0|^)` over "0" reported group 1 as [1,1] (the `^`
// branch, matching empty at 1) where RE2 says [0,1).
//
// Two shapes are unsafe, and one is not:
//
//   - Not start-anchored (StartCond lacks EmptyBeginText). The TDFA body is
//     anchored and runs over the window the find pass picked, whose start need
//     not be 0 — so even a leading `^` would be judged against the wrong
//     position. `(^|x)(a)` over "yxa" is the shape.
//   - Start-anchored but with an assertion reachable after a byte consumer:
//     the window is position 0, but that assertion is false where it sits and
//     the walks follow it anyway. `^(a)^(b)` is the shape.
//   - Start-anchored with every assertion reachable only through epsilons from
//     the start: true exactly where it is tested, which is the ordinary
//     `^(\d{4})-(\d{2})` pattern. Left on TDFA.
func hasUnsafeBeginText(prog *syntax.Prog) bool {
	isBeginText := func(pc int) bool {
		inst := &prog.Inst[pc]
		return inst.Op == syntax.InstEmptyWidth &&
			syntax.EmptyOp(inst.Arg)&syntax.EmptyBeginText != 0
	}
	any := false
	for i := range prog.Inst {
		if isBeginText(i) {
			any = true
			break
		}
	}
	if !any {
		return false
	}
	if prog.StartCond()&syntax.EmptyBeginText == 0 {
		return true
	}
	// Forward walk from the start, carrying "a byte has been consumed on this
	// path". Two visit states per PC, so the walk terminates through loops.
	const (
		fresh = 1 << iota
		consumed
	)
	seen := make([]int, len(prog.Inst))
	queue := []struct{ pc, state int }{{prog.Start, fresh}}
	for len(queue) > 0 {
		it := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if it.pc < 0 || it.pc >= len(prog.Inst) || seen[it.pc]&it.state != 0 {
			continue
		}
		seen[it.pc] |= it.state
		if it.state == consumed && isBeginText(it.pc) {
			return true
		}
		inst := &prog.Inst[it.pc]
		next := it.state
		switch inst.Op {
		case syntax.InstFail, syntax.InstMatch:
			continue
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			next = consumed
		}
		queue = append(queue, struct{ pc, state int }{int(inst.Out), next})
		if inst.Op == syntax.InstAlt || inst.Op == syntax.InstAltMatch {
			queue = append(queue, struct{ pc, state int }{int(inst.Arg), next})
		}
	}
	return false
}

// hasAmbiguousCaptures reports whether any Alt in the NFA has non-disjoint
// first-character sets between its branches. When such an Alt is inside a
// capture group's quantifier, TDFA's LeftmostFirst priority causes the greedy
// loop to over-consume and record wrong capture positions. These patterns must
// use backtracking instead.
//
// Quantifier-loop Alts (Out < PC for the backward loop body, Arg >= PC for the
// forward exit — the same test hasNonLoopAlternations/hasNestedQuantifiers
// use) get a narrower version of the check: isAlternationDeterministic still
// rejects an INDETERMINATE branch (empty first-rune set, e.g. an inverted
// class wider than 256 codepoints — this is the inverted-class protection, see
// CLAUDE.md "Load-bearing engine-selection gates", and must not be relaxed
// here). It only skips the disjoint-ness requirement once both branches are
// computable, since TDFA's LeftmostFirst priority always prefers the loop
// body over the exit — "does this byte continue the loop or start the exit"
// resolves correctly even when the exit's first-byte set overlaps the loop's
// own class (e.g. X([a-zA-Z]+)Y, where Y is itself a class member).
// This used to also require no further quantifier loop
// reachable past the exit branch, working around a bug where a second loop
// over an overlapping alphabet corrupted TDFA's tag-op register-copy
// ordering (e.g. ([a-z]+)(er)([a-z]+)); that bug is now fixed at its root in
// engine_tdfa.go's getOrAddState (sequentializeCopies), so the extra
// exclusion is no longer needed. Genuine user alternations, including one
// nested inside a loop body (e.g. (?:cat|car)+), are a separate InstAlt
// instruction and are still checked in full.
//
// unicode is true when the program runs LOWERED (Unicode mode); prog is still
// the program as written. There the inverted-class protection is lifted: a
// class of any width, `.` and a folded literal have a computable first set
// (firstRuneRanges). The protection exists because Backtracking checks a wide
// class with a few inline compares and is cheaper than a TDFA there — in byte
// mode. Lowered, a wide class is an alternation of byte sequences that
// Backtracking walks branch by branch on every character it rejects: `\pL` is
// an 800-way chain, and `(\pL+)\s(\pN+)` over "Straße 42" cost 101,299 fuel
// on Backtracking against 2,470 on a TDFA. On every capture pattern measured
// the TDFA was the cheaper engine and its module no larger.
func hasAmbiguousCaptures(prog *syntax.Prog, unicode bool) bool {
	for pc, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstAlt:
			pcU32 := uint32(pc)
			isQuantifierLoop := inst.Out < pcU32 && inst.Arg >= pcU32
			if !isAlternationDeterministic(prog, pc, isQuantifierLoop, unicode) {
				return true
			}
		case syntax.InstAltMatch:
			if !isAlternationDeterministic(prog, pc, false, unicode) {
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

// patternAnalysis contains metrics about a regexp pattern.
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

// estimatedDFAStates is analysePattern's EstimatedDFAStates for prog alone,
// without the rune-class walk the rest of the analysis needs.
func estimatedDFAStates(prog *syntax.Prog) int {
	alternations := 0
	for pc, inst := range prog.Inst {
		if inst.Op == syntax.InstAlt && !(inst.Out < uint32(pc) && inst.Arg >= uint32(pc)) {
			alternations++
		}
	}
	return dfaStatesEstimate(len(prog.Inst), alternations)
}

// dfaStatesEstimate is the state estimate from a program's instruction and
// (non-loop) alternation counts.
func dfaStatesEstimate(instructions, alternations int) int {
	multiplier := 1.0
	if alternations > 0 {
		multiplier = min(1.0+float64(alternations)*0.2, 3.0)
	}
	return int(float64(instructions) * multiplier)
}

func (a *patternAnalysis) estimateDFAComplexity() {
	a.EstimatedDFAStates = dfaStatesEstimate(a.NumInstructions, a.NumAlternations)

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
//
// quantifierLoop is true when altPC is a quantifier-loop Alt (see
// hasAmbiguousCaptures' doc comment). For those, an INDETERMINATE branch
// (empty first-rune set — the inverted-class signal, CLAUDE.md
// "Load-bearing engine-selection gates") is still treated as ambiguous; only
// the disjoint-ness requirement between two otherwise-computable branches is
// skipped, since TDFA's LeftmostFirst priority resolves that case
// correctly regardless of overlap. unicode computes the first sets as
// codepoint ranges of any width (hasAmbiguousCaptures).
func isAlternationDeterministic(prog *syntax.Prog, altPC int, quantifierLoop, unicode bool) bool {
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

	if unicode {
		left, okL := firstRuneRanges(prog, int(alt.Out))
		right, okR := firstRuneRanges(prog, int(alt.Arg))
		if !okL || !okR || len(left) == 0 || len(right) == 0 {
			return false
		}
		return quantifierLoop || !rangesOverlap(left, right)
	}

	leftRunes := getFirstRuneSet(prog, int(alt.Out))
	rightRunes := getFirstRuneSet(prog, int(alt.Arg))

	if len(leftRunes) == 0 || len(rightRunes) == 0 {
		return false // can't determine first chars for at least one branch — ambiguous even for quantifier loops
	}

	if quantifierLoop {
		return true // both sides computable; overlap alone doesn't matter for a greedy loop
	}

	for r := range leftRunes {
		if rightRunes[r] {
			return false
		}
	}

	return true
}

// firstRuneRanges is getFirstRuneSet as sorted, merged codepoint ranges
// (lo, hi pairs) with no width limit: a class of any width, `.` and a folded
// literal (its SimpleFold orbit) all have one. ok is false where the set
// cannot be known — the branch can reach Match without consuming, or an
// instruction is malformed. Unicode mode only (hasAmbiguousCaptures).
func firstRuneRanges(prog *syntax.Prog, pc int) (ranges []rune, ok bool) {
	visited := make(map[int]bool)
	var collect func(int) bool
	collect = func(pc int) bool {
		if pc >= len(prog.Inst) {
			return false
		}
		if visited[pc] {
			return true
		}
		visited[pc] = true
		inst := &prog.Inst[pc]
		switch inst.Op {
		case syntax.InstRune1:
			ranges = append(ranges, inst.Rune[0], inst.Rune[0])
			return true
		case syntax.InstRune:
			if len(inst.Rune) == 1 {
				r := inst.Rune[0]
				ranges = append(ranges, r, r)
				if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
					for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
						ranges = append(ranges, f, f)
					}
				}
				return true
			}
			if len(inst.Rune)%2 != 0 || syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
				return false
			}
			ranges = append(ranges, inst.Rune...)
			return true
		case syntax.InstRuneAny:
			ranges = append(ranges, 0, unicode.MaxRune)
			return true
		case syntax.InstRuneAnyNotNL:
			ranges = append(ranges, 0, '\n'-1, '\n'+1, unicode.MaxRune)
			return true
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			return collect(int(inst.Out))
		case syntax.InstAlt, syntax.InstAltMatch:
			return collect(int(inst.Out)) && collect(int(inst.Arg))
		}
		return false
	}
	if !collect(pc) {
		return nil, false
	}
	return mergeRuneRanges(ranges), true
}

// mergeRuneRanges sorts lo, hi pairs and merges the ones that overlap or
// touch.
func mergeRuneRanges(r []rune) []rune {
	pairs := make([][2]rune, 0, len(r)/2)
	for i := 0; i+1 < len(r); i += 2 {
		pairs = append(pairs, [2]rune{r[i], r[i+1]})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	var out []rune
	for _, p := range pairs {
		if n := len(out); n > 0 && p[0] <= out[n-1]+1 {
			out[n-1] = max(out[n-1], p[1])
			continue
		}
		out = append(out, p[0], p[1])
	}
	return out
}

// rangesOverlap reports whether two sorted, merged range lists share a
// codepoint.
func rangesOverlap(a, b []rune) bool {
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i+1] < b[j]:
			i += 2
		case b[j+1] < a[i]:
			j += 2
		default:
			return true
		}
	}
	return false
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

// report returns the options' Reporter, or nil. Every Reporter method is
// nil-safe, so callers need no branch of their own.
func (o *CompileOptions) report() *Reporter {
	if o == nil {
		return nil
	}
	return o.Report
}
