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
	Name                  string         `json:"name"`
	Frontend              string         `json:"frontend"` // "teddy", "ac", "scalar"
	Buckets               []BucketDiag   `json:"buckets"`
	Conflicts             []ConflictDiag `json:"conflicts"`
	CaptureBearingDropped []PatternRef   `json:"capture_bearing_dropped"`
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
