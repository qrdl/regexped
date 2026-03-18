package compile

import (
	"fmt"
	"regexp/syntax"
)

// CompileOptions contains optional parameters for engine selection.
type CompileOptions struct {
	MaxDFAStates       int        // Maximum DFA states before falling back (default: 1000)
	MaxDFAMemory       int        // Maximum DFA memory in bytes (default: 102400)
	Unicode            bool       // Enable Unicode support
	AdaptiveNFACutover int        // Input size in bytes to switch to Pike VM in AdaptiveNFA
	ForceEngine        EngineType // If non-zero, skip engine selection and use this engine type
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

	prog, err := syntax.Compile(re.Simplify())
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
		engineType = selectBestEngine(prog, hasCapturesBeforeSimplify, opts...)
	}

	switch engineType {
	case EngineDFA:
		return newDFA(prog, options.Unicode), nil
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
