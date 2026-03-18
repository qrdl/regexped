package compile

// EngineType represents the type of regex engine implementation.
type EngineType byte

const (
	EngineDFA        EngineType = iota + 1
	EngineBacktrack
	EngineOnePass
	EnginePikeVM
	EngineLazyDFA
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
	case EngineLazyDFA:
		return "Lazy DFA"
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
