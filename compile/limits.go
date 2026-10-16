package compile

import "github.com/qrdl/regexped/config"

// buildLimits are the configured size limits a pattern is compiled under:
// max_dfa_states and max_bt_instructions. They travel with the pattern's mode
// — on resolvedPattern, resolvedTree and resolvedProg (utf8_lower.go) — so an
// automaton or program built from the pattern, however deep in the compiler
// and however far from the options, is built under the limits its config set.
// No build site names a limit of its own: a site that did was how a set
// member's DFA came to stop at 2,048 states while the set's own limit was
// 16,384 in Unicode mode, and the member was dropped from the set.
//
// The zero value is every default, which is what a carrier built without
// options (a byte-mode probe, a test) gets.
type buildLimits struct {
	// dfaStates is max_dfa_states as configured: 0 is the mode's default,
	// negative is "no DFA" (always Backtracking).
	dfaStates int
	// btInsts is max_bt_instructions as configured: 0 is the default,
	// negative is "no Backtracking".
	btInsts int
}

// limitsOf reads the limits off compile options.
func limitsOf(o *CompileOptions) buildLimits {
	if o == nil {
		return buildLimits{}
	}
	return buildLimits{dfaStates: o.MaxDFAStates, btInsts: o.MaxBTInstructions}
}

// limitsOfConfig reads the limits off a config, as a set's members take them.
func limitsOfConfig(cfg config.BuildConfig) buildLimits {
	return buildLimits{dfaStates: int(cfg.MaxDFAStates), btInsts: int(cfg.MaxBTInstructions)}
}

// dfaStateLimit is the largest DFA a pattern in the mode may USE, as
// resolveMaxDFAStates rules it: the mode's default when unset, 0 when off.
func (l buildLimits) dfaStateLimit(unicode bool) int {
	return resolveMaxDFAStates(&CompileOptions{MaxDFAStates: l.dfaStates}, unicode)
}

// dfaBuildCap is how far any construction in the mode runs before it gives
// up: the larger of the mode's construction cap — maxHelperDFAStates in byte
// mode, defaultMaxDFAStatesUnicode in Unicode mode, where one lowered letter
// class costs hundreds of states — and the state limit, so a configured limit
// above the cap is always reachable. Every helper automaton is built under it
// too: a smaller one would refuse what the limit allows.
func (l buildLimits) dfaBuildCap(unicode bool) int {
	modeCap := maxHelperDFAStates
	if unicode {
		modeCap = defaultMaxDFAStatesUnicode
	}
	return max(modeCap, l.dfaStateLimit(unicode))
}

// btLimit is the largest Backtracking program allowed, in instructions:
// maxBTFallbackInstructions when unset, 0 when Backtracking is off.
func (l buildLimits) btLimit() int {
	switch {
	case l.btInsts < 0:
		return 0
	case l.btInsts == 0:
		return maxBTFallbackInstructions
	}
	return l.btInsts
}

// btOff reports whether max_bt_instructions: 0 forbids Backtracking.
func (l buildLimits) btOff() bool { return l.btInsts < 0 }

// btFits reports whether a Backtracking program of insts instructions may be
// built.
func (l buildLimits) btFits(insts int) bool { return !l.btOff() && insts <= l.btLimit() }

// sameLimits is the limits programs merged into one automaton carry: the
// first one's, as every program of one compile carries the same.
func sameLimits(progs []resolvedProg) buildLimits {
	if len(progs) == 0 {
		return buildLimits{}
	}
	return progs[0].lim
}

// dfaBuildCap is the construction cap for an automaton built from p.
func (p resolvedProg) dfaBuildCap() int { return p.lim.dfaBuildCap(p.unicode()) }
