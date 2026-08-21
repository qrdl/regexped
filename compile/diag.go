package compile

import "fmt"

// PatternRef is the canonical pattern reference used in all log events
// and JSON diagnostic output.
type PatternRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"` // empty when entry has no `name:` field
}

func (p PatternRef) String() string {
	return fmt.Sprintf("(%d,%q)", p.ID, p.Name)
}

// Diagnostics is the top-level diagnostic structure produced by CompileFile.
type Diagnostics struct {
	PatternsTotal       int       `json:"patterns_total"`
	CaptureBearing      int       `json:"capture_bearing"`
	InSet               int       `json:"in_set"`
	PrefixDedupPoolSize int       `json:"prefix_dedup_pool_size"`
	Sets                []SetDiag `json:"sets"`
}

// SetDiag holds diagnostics for one set.
type SetDiag struct {
	Name     string `json:"name"`
	Frontend string `json:"frontend"` // "teddy", "ac", "shufti", "scalar"
	// Capabilities lists the set's declared capability keys, in the
	// plans/SETS.md §3.12 grid order.
	Capabilities []string `json:"capabilities,omitempty"`
	// Overlapping mirrors the YAML flag: true = the ungated `find` body.
	Overlapping bool `json:"overlapping"`
	// MaxLookback is the set's first-position drain bound M (§9.4): the
	// largest distance between a mandatory literal and the match start it can
	// serve, or -1 when some pattern's prefix is unbounded and no bound
	// exists. It is what decides whether a set behaves as §9.4 "class A"
	// (bounded drain, literal frontend intact) or "class B" (nothing can be
	// skipped) — confirm a test set's class from here rather than by
	// inspection.
	MaxLookback int `json:"max_lookback"`
	// BareBodyShape records which body shape each declared bare capability
	// received (§3.20 / D9): "collapsed" for the union-automaton fast path,
	// "bucketed" for the early-exit fallback. Keyed by capability name.
	BareBodyShape         map[string]string `json:"bare_body_shape,omitempty"`
	Buckets               []BucketDiag      `json:"buckets"`
	Conflicts             []ConflictDiag    `json:"conflicts"`
	CaptureBearingDropped []PatternRef      `json:"capture_bearing_dropped"`
	StateLimitDropped     []PatternRef      `json:"state_limit_dropped,omitempty"`
}

// BucketDiag describes one merged bucket.
type BucketDiag struct {
	ID           int          `json:"id"`
	Type         string       `json:"type"`        // "merged" | "singleton" | "fallback"
	AcceptKind   string       `json:"accept_kind"` // "bitmask" (Phases 2–5)
	Literal      string       `json:"literal"`
	Patterns     []PatternRef `json:"patterns"`
	SuffixStates int          `json:"suffix_states"`
	TableBytes   int          `json:"table_bytes"`
}

// ConflictDiag records a bin-packing rejection.
type ConflictDiag struct {
	Pattern         PatternRef             `json:"pattern"`
	CandidateBucket int                    `json:"candidate_bucket"`
	Reason          string                 `json:"reason"`
	Detail          map[string]interface{} `json:"detail,omitempty"`
}
