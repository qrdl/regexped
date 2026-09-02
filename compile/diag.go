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
	Frontend string `json:"frontend"` // "packed-pair", "teddy", "ac", "shufti", "scalar"
	// Capabilities lists the set's declared capability keys, in the
	// canonical grid order.
	Capabilities []string `json:"capabilities,omitempty"`
	// Overlapping mirrors the YAML flag: true = the ungated `find` body.
	Overlapping bool `json:"overlapping"`
	// MaxLookback is the set's first-position drain bound M: the
	// largest distance between a mandatory literal and the match start it can
	// serve. It is what decides whether a set behaves as drain "class A"
	// (bounded drain, literal frontend intact) or "class B" (nothing can be
	// skipped) — confirm a test set's class from here rather than by
	// inspection.
	//
	// It is always finite: a variable-length prefix has no usable bound, so
	// analyzePattern routes those patterns to a fallback bucket instead of
	// letting them widen M. An earlier draft of this comment
	// promised -1 for that case; setMaxLookback cannot return it.
	MaxLookback int `json:"max_lookback"`
	// IDSpaceSize is one past the largest pattern id this set can report.
	// For `patterns: all` it equals the pattern count;
	// for a named subset it is the largest selected pattern's global index
	// plus one, and it — not the pattern count — is the size of the gate array
	// and the `_all` bitmap, and what decides the narrow-vs-wide `_all` ABI.
	IDSpaceSize int `json:"id_space_size"`
	// BareBodyShape records which body shape each declared bare capability
	// received, keyed by capability name. Only "bucketed" is
	// emitted today: the union collapse is not built, so
	// this field exists to make that visible rather than to be guessed at, and
	// gains a "collapsed" value if the collapse ever lands.
	BareBodyShape         map[string]string `json:"bare_body_shape,omitempty"`
	Buckets               []BucketDiag      `json:"buckets"`
	Conflicts             []ConflictDiag    `json:"conflicts"`
	CaptureBearingDropped []PatternRef      `json:"capture_bearing_dropped"`
	StateLimitDropped     []PatternRef      `json:"state_limit_dropped,omitempty"`
	// UnparseableDropped lists patterns the anchored packer could not re-parse
	// and therefore excluded from match/match_any/match_all while `find` kept
	// them. Defensive — analyzePattern already parsed these once — but a
	// silent `continue` there would leave the capabilities disagreeing with no
	// diagnostic trail at all.
	UnparseableDropped []PatternRef `json:"unparseable_dropped,omitempty"`
	// FrontendDemotion records that the frontend chooseLiteralFrontend picked
	// was NOT the one emitted, and why. Nil when the chosen frontend shipped.
	//
	// This exists because the demotion it reports used to be silent: an
	// AC automaton over the old 32-node cap fell back to the scalar path with
	// no trace anywhere, and the resulting 86-414x scan-fuel cliff went
	// unnoticed for three months. Whatever the
	// budget is set to, the next person to hit it should find out from
	// --diag-json rather than from a fuel number.
	FrontendDemotion *FrontendDemotionDiag `json:"frontend_demotion,omitempty"`
	// ACTable describes the Aho-Corasick tables when the AC frontend shipped.
	// Nil for every other frontend.
	ACTable *ACTableDiag `json:"ac_table,omitempty"`
	// UnionScan reports what served the scan pair: the start-anywhere
	// one-pass automaton, or the per-position bucket walk, and in the first
	// case which accept representation. Nil for a set with no scan capability.
	//
	// It exists because the difference is a factor of seven in fuel and NOTHING
	// else makes it visible: the same set, same patterns, same answers, one
	// eligibility test apart. That is exactly the shape of the AC demotion
	// FrontendDemotion was added for, and of the wide-accept work itself — six
	// sub-1x rows whose cause was a body selection nobody could see.
	UnionScan *UnionScanDiag `json:"union_scan,omitempty"`
	// AnchoredUnion reports how the ANCHORED capabilities were served
	//: one union automaton, or the bucket packing.
	// Before this field the anchored packer had no diagnostic at all, so the
	// difference between "one automaton" and "four buckets and a probe call
	// each" — which is the whole cost difference between 154 fuel and 700 —
	// was invisible to everything but a disassembler.
	AnchoredUnion *AnchoredUnionDiag `json:"anchored_union,omitempty"`
}

// AnchoredUnionDiag reports the anchored trio's body selection.
type AnchoredUnionDiag struct {
	// Used is false when the automaton was refused and match_any/match_all
	// fell back to the per-bucket probes. Refused is then the reason.
	Used bool `json:"used"`
	// Refused names what failed. "construction" covers everything
	// buildAnchoredUnionDFA decides internally: the state cap, a word or
	// newline boundary, an id space past maxUnionScanIDs, an unparseable
	// pattern.
	Refused string `json:"refused,omitempty"`
	// Wide is the >64-id accept form: a per-state representative id plus a
	// bitmap row, in place of a u64 mask.
	Wide   bool `json:"wide,omitempty"`
	States int  `json:"states,omitempty"`
	// StateWidth and NumClasses describe the emitted table. They are the
	// reason this path exists: unlike the bucket packing's layout, the two are
	// chosen independently, so a 530-state automaton still compresses by byte
	// class instead of costing 512 bytes a row.
	StateWidth int `json:"state_width,omitempty"`
	NumClasses int `json:"num_classes,omitempty"`
}

// UnionScanDiag reports the scan pair's body selection.
type UnionScanDiag struct {
	// Used is false when the automaton was refused and the scan pair fell back
	// to the per-position bucket walk. Refused is then the reason.
	Used bool `json:"used"`
	// Refused names the eligibility test that failed: "construction" covers
	// everything buildUnionScanDFA decides internally (state cap, word
	// boundaries, line anchors, an unparseable pattern), "id_space" is an id
	// beyond maxUnionScanIDs, "frontend" a set with a literal frontend (which
	// uses the two-phase split instead, reported as phase2 below).
	Refused string `json:"refused,omitempty"`
	// Wide is the >64-id accept form: per-state
	// representative id plus a bitmap row, in place of a u64 mask.
	Wide      bool `json:"wide,omitempty"`
	States    int  `json:"states,omitempty"`
	MaskWords int  `json:"mask_words,omitempty"`
	// Phase2 is set when this automaton serves only the FALLBACK half of a
	// mixed set.
	Phase2 bool `json:"phase2,omitempty"`
}

// ACTableDiag reports the shape of the emitted Aho-Corasick tables. Its point
// is to make the budget legible: `bytes` against the set's budget says how
// much headroom is left, and `compressed` says whether byte-class compression
// had to be spent to fit — which costs one extra table load per input byte and
// is therefore only engaged when the alternative is losing the frontend.
type ACTableDiag struct {
	Nodes      int  `json:"nodes"`
	Bytes      int  `json:"bytes"`
	Compressed bool `json:"compressed"`
	// ByteClasses and Stride are meaningful only when Compressed.
	ByteClasses int `json:"byte_classes,omitempty"`
	Stride      int `json:"stride,omitempty"`
}

// FrontendDemotionDiag explains why a literal frontend was downgraded.
type FrontendDemotionDiag struct {
	From   string                 `json:"from"`   // frontend chooseLiteralFrontend selected
	To     string                 `json:"to"`     // frontend actually emitted
	Reason string                 `json:"reason"` // machine-readable cause
	Detail map[string]interface{} `json:"detail,omitempty"`
}

// BucketDiag describes one merged bucket.
type BucketDiag struct {
	ID int `json:"id"`
	// Type is "merged" | "singleton" | "fallback" | "bt-fallback" |
	// "sparse-set".
	// "bt-fallback" is a pattern admitted on the Backtracking engine after its
	// suffix DFA exceeded max_fallback_states; it holds
	// exactly one pattern and has NO table, so SuffixStates and TableBytes are
	// 0 for it rather than unknown. "sparse-set" is G17's >32-pattern bucket
	//: its accept is a per-state LIST rather than a bitmask, which
	// is what lets it hold a whole shared-literal group in one bucket instead
	// of ceil(N/32) of them.
	Type         string       `json:"type"`
	AcceptKind   string       `json:"accept_kind"` // "bitmask" (Phases 2–5)
	Literal      string       `json:"literal"`
	Patterns     []PatternRef `json:"patterns"`
	SuffixStates int          `json:"suffix_states"`
	// MemberSkipStates is how many of this bucket's states carry a member
	// self-loop skip arm, and MemberSkipSets how many distinct byte sets back
	// them. Both zero unless the set is compiled with prefer-match AND the
	// bucket is sparse AND some state self-loops on at most memberMaxBytes.
	//
	// Reported because the skip is otherwise invisible: it changes fuel by
	// ~80% on a bucket with long self-loop runs and by nothing at all on one
	// without, and no other output distinguishes "not eligible" from "eligible
	// and silently stopped firing".
	MemberSkipStates int `json:"member_skip_states,omitempty"`
	MemberSkipSets   int `json:"member_skip_sets,omitempty"`
	TableBytes       int `json:"table_bytes"`
}

// ConflictDiag records a bin-packing rejection.
type ConflictDiag struct {
	Pattern         PatternRef             `json:"pattern"`
	CandidateBucket int                    `json:"candidate_bucket"`
	Reason          string                 `json:"reason"`
	Detail          map[string]interface{} `json:"detail,omitempty"`
}
