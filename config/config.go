package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

// BuildConfig is the top-level structure of the YAML config file.
type BuildConfig struct {
	WasmMerge    string `yaml:"wasm_merge"`     // optional; defaults to "wasm-merge" in $PATH
	Output       string `yaml:"output"`         // output path for merge command; overridable with -o
	WasmFile     string `yaml:"wasm_file"`      // output WASM file for compile command; overridable with -o
	ImportModule string `yaml:"import_module"`  // WASM import module name used by wasm-merge and Rust FFI
	StubFile     string `yaml:"stub_file"`      // stub output file (Rust, Go, JS, TS, AS, or C)
	StubType     string `yaml:"stub_type"`      // stub type: "rust", "go", "js", "ts", "c", "as"; inferred from stub_file extension if absent

	// Namespace prefixes the symbols a stub generates that are NOT named by
	// the user — Span, SetMatch, the error type, the pattern-name helper, C's
	// rx_*_t typedefs. Optional; empty means the names as they have always
	// been.
	//
	// It exists because two stubs generated from two configs into ONE package
	// collide on exactly those shared names. Today only C guards against that,
	// with its REGEXPED_TYPES_DEFINED include guard; Go and TS have no
	// equivalent, and the shared Span and error type of TODO task 62 widen the
	// exposure. A NO-OP for Rust, whose `pub mod <import_module>` wrapper
	// already isolates every stub.
	Namespace string `yaml:"namespace"`
	MaxDFAStates int    `yaml:"max_dfa_states"` // 0 = default (1024)
	MaxTDFARegs  int    `yaml:"max_tdfa_regs"`  // 0 = default (32)
	// MaxFallbackStates caps the suffix DFA of a single-pattern fallback
	// bucket in a SET. It is a different budget from MaxDFAStates: that one
	// bounds a whole single-pattern automaton, this one bounds one bucket of
	// many inside a set, which is why they are separate keys despite sharing
	// a default.
	//
	// It is load-bearing in a way the other two are not. A single pattern over
	// MaxDFAStates falls back to another engine and still matches; a set
	// member over this limit is DROPPED from the set and can never match. So
	// this is the knob that decides whether a set contains what you put in it.
	MaxFallbackStates int          `yaml:"max_fallback_states"` // 0 = default (1024)
	Regexps           []RegexEntry `yaml:"regexps"`
	Sets              []SetConfig  `yaml:"sets"` // optional set composition entries
}

// SetConfig describes one `sets:` entry in the YAML config.
//
// The five capability fields are a 2x2 grid plus `find`. The KEY names the
// capability; the VALUE is the WASM export / generated-function name the user
// picks.
//
//	match_*  — anchored: the match must span the whole input (0..len).
//	scan_*   — non-anchored: takes an `offset`.
//	_any     — one arbitrary matching pattern id (a set is unordered, §3.5).
//	_all     — every matching pattern id.
//	find     — reports positions and extents.
//
// TWO KEYS WERE RETIRED by TODO task 59, and both are load errors rather than
// silently-accepted no-ops (strict YAML decoding does that for free):
//
//   - `match:` and `scan:` — decision (2). `match_any(...) >= 0` is exactly
//     what `match` returned and `scan_any(...) >= 0` what `scan` returned, and
//     the redundancy measured at 1-3% of module size. They are DROPPED rather
//     than repurposed: a surviving `match:` with match_any semantics would
//     leave every existing config compiling while its callers silently
//     switched from reading 0/1 to reading an id — and id 0 would read as "no
//     match". A removed key fails at build; a redefined one fails in
//     production.
//   - `find_batch:` — decision (11). Batching is no longer a second
//     capability but a property of `find`, requested with
//     `hints: [batch-find]` on the set. At the API level the two were never
//     distinguishable — both iterate the same matches in the same order, and
//     the cursor and gate array are stub-owned and invisible. The only
//     caller-visible difference is how much work one host crossing does,
//     which is a parameter, not a name.
type SetConfig struct {
	Name string `yaml:"name"` // set name; must be unique within the file

	MatchAny string `yaml:"match_any"` // anchored, pattern id or -1
	MatchAll string `yaml:"match_all"` // anchored, bitmask / bitmap of ids
	ScanAny  string `yaml:"scan_any"`  // non-anchored, pattern id or -1
	ScanAll  string `yaml:"scan_all"`  // non-anchored, bitmask / bitmap of ids
	Find     string `yaml:"find"`      // non-anchored, positions and extents

	// Overlapping selects which `find` body is emitted. Absent or false
	// (the DEFAULT) emits the gated body:
	// per-pattern non-overlapping output matching Go FindAllIndex's rule.
	// True emits the ungated body, which reports every start position and
	// carries no gate-array parameter. It is a load error on a set without
	// `find:`, since no other capability gates.
	Overlapping bool `yaml:"overlapping"`

	Patterns    PatternSelector `yaml:"patterns"`      // which regexps belong to this set
	EmitNameMap bool            `yaml:"emit_name_map"` // generate pattern_name / patternName helper in stubs (does not change WASM)
	// Hints biases which suffix-DFA optimisation path to favour for this set.
	// Also serves as the per-set default for unhinted patterns in this set
	// when they reach the set's suffix DFA body. Accepted values: nil/empty
	// (no hint), ["prefer-match"], or ["prefer-no-match"] — mutually
	// exclusive with each other.
	// "batch-find" is NOT accepted here — it is a
	// per-pattern, JS/TS-only hint and is a load-time error on a sets: entry.
	Hints []string `yaml:"hints"`
}

// SetCapability is one (yaml key, export name) pair from a set entry.
type SetCapability struct {
	Field string // YAML key, e.g. "scan_any"
	Name  string // user-chosen export / function name
}

// Capabilities returns the set's declared capabilities in a stable order
// (the §3.12 grid order: match_any, match_all, scan_any, scan_all, find).
// Undeclared capabilities are omitted.
func (s SetConfig) Capabilities() []SetCapability {
	all := []SetCapability{
		{"match_any", s.MatchAny},
		{"match_all", s.MatchAll},
		{"scan_any", s.ScanAny},
		{"scan_all", s.ScanAll},
		{"find", s.Find},
	}
	out := all[:0:0]
	for _, c := range all {
		if c.Name != "" {
			out = append(out, c)
		}
	}
	return out
}

// HasExports reports whether the set declares at least one capability.
func (s SetConfig) HasExports() bool { return len(s.Capabilities()) > 0 }

// Gated reports whether this set emits the default gated (per-pattern
// non-overlapping) `find` body, which threads a caller-owned gate array
// through the suffix functions. A set without
// `find:` gates nothing.
func (s SetConfig) Gated() bool {
	return s.Find != "" && !s.Overlapping
}

// HasFind reports whether the set declares the position-reporting capability.
// `overlapping` is meaningful only for it, and only it emits the
// tuple-writing suffix functions.
func (s SetConfig) HasFind() bool { return s.Find != "" }

// BatchFind reports whether this set asked for `find` to work several
// positions ahead per host crossing, via `hints: [batch-find]` (TODO task 59
// decision (11)).
//
// The hint is meaningless without something to batch, so it implies `find`.
// Emission is keyed on the HINT and never on stub_type: docs/cli.md states
// that the language-agnostic rules exist "so that changing stub_type never
// breaks a working config", and keying a module's export surface on it would
// break exactly that — a merged module loaded from more than one host would
// silently lack the export.
func (s SetConfig) BatchFind() bool {
	if s.Find == "" {
		return false
	}
	for _, h := range s.Hints {
		if h == "batch-find" {
			return true
		}
	}
	return false
}

// SanitizeSetName turns a set name into an identifier stem for the constants
// and types the stubs emit for it (<SET>_PATTERN_COUNT, <SET>_ID_SPACE, C's
// scanner struct). `sets[].name` is deliberately not identifier-validated — it
// is a selection key, and shipped configs use names like "sql-validator" — so
// it cannot be interpolated verbatim.
//
// It lives here, rather than in generate/, so ValidateSets can reject two set
// names that sanitize to the SAME stem before they become duplicate
// declarations in generated code.
func SanitizeSetName(name string) string {
	var b []rune
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "SET"
	}
	if b[0] >= '0' && b[0] <= '9' {
		b = append([]rune{'_'}, b...)
	}
	return string(b)
}

// PatternCount returns the number of patterns the set selects.
//
// This is the D16 <SET>_PATTERN_COUNT: the worst-case number of matches at a
// single `find` position, and therefore the size of the tuple buffer. It is
// NOT a bound on pattern id values — see IDSpaceSize.
func (s SetConfig) PatternCount(cfg BuildConfig) int {
	if s.Patterns.All {
		return len(cfg.Regexps)
	}
	return len(s.Patterns.Names)
}

// IDSpaceSize returns one past the largest pattern id this set can report.
//
// A set's pattern_id is the GLOBAL index into `regexps:` in YAML order
// (docs/sets.md), so a set selecting the last two of seventy patterns reports
// ids 68 and 69 even though it holds two patterns. Everything indexed BY that
// id — the gate array, the `_all` bitmask/bitmap, and hence the narrow-vs-wide
// `_all` ABI choice — must be sized from this, not from PatternCount.
//
// Sizing them from PatternCount was a memory-safety defect: the emitted WASM
// wrote gate[68] into a stub-allocated two-slot array, `_all` decode loops
// stopped before the bits the module had set, and the two sides could even
// disagree about which `_all` signature the module exported.
//
// This is deliberately an UPPER BOUND computed from the config alone, and it
// is THE definition for both sides: the compiler calls it (through
// SetSpec.IDSpaceSize) and so does every stub generator, so the two cannot
// drift. Patterns dropped later — capture-bearing ones, or ones over the DFA
// state limit — only lower the ids actually emitted, never raise them, so an
// upper bound stays safe. Deriving it instead from what survived compilation
// would be tighter but unavailable to the generators, which never see the
// compiled module.
func (s SetConfig) IDSpaceSize(cfg BuildConfig) int {
	if s.Patterns.All {
		return len(cfg.Regexps)
	}
	idx := make(map[string]int, len(cfg.Regexps))
	for i, re := range cfg.Regexps {
		if re.Name != "" {
			if _, dup := idx[re.Name]; !dup {
				idx[re.Name] = i
			}
		}
	}
	max := -1
	for _, name := range s.Patterns.Names {
		if i, ok := idx[name]; ok && i > max {
			max = i
		}
	}
	return max + 1
}

// SetBatchExportName is the WASM export a `hints: [batch-find]` set emits
// alongside its `find`.
//
// It lives here, next to the cursor layout, for the same reason: the compiler
// and all six stub generators must agree on it exactly, and a second
// definition anywhere is a module whose stub calls an export that does not
// exist. It is derived rather than configured because decision (11) hides
// batching behind `find`'s optional batchSize parameter — the user never
// writes this name.
func SetBatchExportName(find string) string { return find + "_batch" }

// SetCursorKBits returns how many bits the §19 find_batch cursor reserves for
// its intra-position resume index, for a set of patternCount patterns: the
// smallest width holding every value in [0, patternCount].
//
// It lives here, next to IDSpaceSize and for the same reason: the compiler
// encodes the cursor and all six stub generators decode it,
// so the layout must have ONE definition both sides call rather than two that
// can drift.
//
// Capped at 24 so count keeps at least 8 bits. A set with more than 16M
// patterns is pathological, and the cap costs a shorter batch rather than a
// count that overflows into the k field.
func SetCursorKBits(patternCount int) int {
	kb := 0
	for kb < 24 && (1<<uint(kb)) <= patternCount {
		kb++
	}
	return kb
}

// SetCursorCountBits is the width of the find_batch cursor's count field.
func SetCursorCountBits(patternCount int) int { return 32 - SetCursorKBits(patternCount) }

// SetCursorMaxCount is the largest tuple count one find_batch call can report.
// The emitted body clamps out_cap to it.
func SetCursorMaxCount(patternCount int) int32 {
	return int32(uint32(1)<<uint(SetCursorCountBits(patternCount))) - 1
}

// SetCursorOverflowPos is the resume-position word reserved to mean "the
// Backtracking engine exhausted its frame budget, and this scan's result is
// UNKNOWN" (SETS_PLAN item 20 decision 3). A find_batch call returning it has
// answered nothing: its count field is zero and no tuples were written.
//
// It lives in the POSITION word, beside 0xFFFFFFFF for "done", rather than in
// the return value as a whole. That is forced: every done return already has
// bit 63 set, so "negative means unknown" — the convention every other
// capability uses — cannot work here, and the count and k fields together can
// span all 32 low bits, so no value of the packed word as a whole is reserved
// either. The position word is the only field with room, and it already
// reserves a value for exactly this kind of out-of-band answer.
//
// A real resume position can never collide: it is bounded by the input length,
// and an input long enough to reach 0xFFFFFFFE cannot coexist with the set's
// tables inside a 4 GiB wasm32 memory.
const SetCursorOverflowPos = 0xFFFFFFFE

// PatternSelector selects patterns for a set. It can be the scalar string "all"
// or a list of pattern names.
type PatternSelector struct {
	All   bool     // true when the YAML value was the scalar "all"
	Names []string // pattern names when All is false
}

// UnmarshalYAML implements yaml.InterfaceUnmarshaler for PatternSelector.
// Accepts either the scalar string "all" or a sequence of strings.
func (p *PatternSelector) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		if v == "all" {
			p.All = true
			return nil
		}
		return fmt.Errorf("patterns: expected \"all\" or a list of pattern names, got %q", v)
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("patterns: list items must be strings")
			}
			p.Names = append(p.Names, s)
		}
		return nil
	}
	return fmt.Errorf("patterns: expected \"all\" or a list of pattern names")
}

// ValidHints reports whether hints is a valid `hints:` list for a regexp
// entry: every entry must be "prefer-match", "prefer-no-match", or
// "batch-find"; "prefer-match" and "prefer-no-match" are mutually exclusive
// (both cannot appear in the same list) but "batch-find" may combine with
// either. An empty or nil list is valid (means "no hint"). The same list is
// valid on a sets: entry, where "batch-find" additionally requires `find` —
// checked in validateHints, which can see the whole entry.
func ValidHints(hints []string) bool {
	return validateHintList(hints) == nil
}

// validateHintList returns a descriptive error for the first problem found in
// hints, or nil if the list is valid.
//
// "batch-find" USED TO BE rejected on a sets: entry, on the reasoning that a
// set's `find` returns one complete position per call and there was nothing
// left for a batch knob to size. TODO task 59 decision (11) reverses that: it
// is now how a set asks for batching at all, replacing the retired
// `find_batch:` key. It still requires `find` on the same set — see
// SetConfig.BatchFind — which is checked where the set is validated rather
// than here, since this function sees only the list.
func validateHintList(hints []string) error {
	var hasMatch, hasNoMatch bool
	for _, h := range hints {
		switch h {
		case "prefer-match":
			hasMatch = true
		case "prefer-no-match":
			hasNoMatch = true
		case "batch-find":
			// valid in both contexts now
		default:
			return fmt.Errorf("unknown value %q (want \"prefer-match\", \"prefer-no-match\", or \"batch-find\")", h)
		}
	}
	if hasMatch && hasNoMatch {
		return fmt.Errorf("\"prefer-match\" and \"prefer-no-match\" are mutually exclusive")
	}
	return nil
}

// validateHints checks the hints fields of every regexp and set entry in
// cfg. Returns an error naming the first offending entry and problem found.
func validateHints(cfg *BuildConfig) error {
	for _, re := range cfg.Regexps {
		if err := validateHintList(re.Hints); err != nil {
			label := re.Name
			if label == "" {
				label = re.Pattern
			}
			return fmt.Errorf("regexp %q: hints: %w", label, err)
		}
	}
	for _, sc := range cfg.Sets {
		if err := validateHintList(sc.Hints); err != nil {
			return fmt.Errorf("set %q: hints: %w", sc.Name, err)
		}
		// "batch-find" asks for `find` to work several positions ahead per
		// host crossing. On a set with no `find:` there is nothing to batch,
		// and silently ignoring it would leave the caller believing they had
		// asked for something.
		for _, h := range sc.Hints {
			if h == "batch-find" && sc.Find == "" {
				return fmt.Errorf("set %q: hints: \"batch-find\" requires \"find\" on the same set", sc.Name)
			}
		}
	}
	return nil
}

// ValidateSets validates the `sets:` block against the `regexps:` list.
// Returns an error if any set name is not unique, any pattern reference is
// unknown, a set entry declares none of the five capabilities, or patterns is
// empty. `overlapping` on a set with no `find` is ignored, not rejected — it
// selects between two find bodies, and with no find body it has no effect.
func ValidateSets(cfg *BuildConfig) error {
	// Build name → index map.
	nameIdx := make(map[string]int, len(cfg.Regexps))
	for i, re := range cfg.Regexps {
		if re.Name != "" {
			if _, dup := nameIdx[re.Name]; dup {
				return fmt.Errorf("duplicate regexp name %q", re.Name)
			}
			nameIdx[re.Name] = i
		}
	}

	setNames := make(map[string]bool)
	setStems := make(map[string]string)    // sanitized stem → the set name that claimed it
	exportNames := make(map[string]string) // export name → owner ("set X" or "regexp Y")
	// Seed with per-regexp export names so set exports can't collide with them.
	for _, re := range cfg.Regexps {
		owner := "regexp"
		if re.Name != "" {
			owner = fmt.Sprintf("regexp %q", re.Name)
		} else if re.Pattern != "" {
			owner = fmt.Sprintf("regexp %q", re.Pattern)
		}
		for _, name := range []string{re.MatchFunc, re.FindFunc, re.GroupsFunc} {
			if name == "" {
				continue
			}
			if strings.HasSuffix(name, "_batch") {
				return fmt.Errorf("%s: export name %q must not end in \"_batch\" (reserved for the compiler-synthesized batch export)", owner, name)
			}
			if prior, dup := exportNames[name]; dup {
				return fmt.Errorf("duplicate WASM export name %q (used by %s and %s)", name, prior, owner)
			}
			exportNames[name] = owner
			// Reserve the name the "batch-find" hint would synthesize for this
			// entry, so a later set capability cannot silently claim it. This
			// is why set names ending in "_batch" no longer need a blanket ban:
			// only the names that can actually collide are taken, which leaves
			// `find_batch: my_find_batch` — the obvious name for the §19
			// capability — available.
			exportNames[name+"_batch"] = owner + " (batch export)"
		}
	}
	for _, s := range cfg.Sets {
		if s.Name == "" {
			return fmt.Errorf("sets entry missing required name field")
		}
		if setNames[s.Name] {
			return fmt.Errorf("duplicate set name %q", s.Name)
		}
		setNames[s.Name] = true
		// Two DISTINCT set names can sanitize to one identifier stem
		// ("url-guard" and "url_guard" both give URL_GUARD), which emits the
		// same <SET>_PATTERN_COUNT / <SET>_ID_SPACE constant twice and breaks
		// the generated Rust/Go/C at compile time with no diagnostic from us.
		stem := SanitizeSetName(s.Name)
		if prior, dup := setStems[stem]; dup {
			return fmt.Errorf("set names %q and %q both produce the identifier %q "+
				"used for their generated constants; rename one", prior, s.Name, stem)
		}
		setStems[stem] = s.Name
		caps := s.Capabilities()
		if len(caps) == 0 {
			return fmt.Errorf("set %q: at least one of match_any, match_all, scan_any, scan_all, or find must be set", s.Name)
		}
		// `overlapping` on a set declaring no find is silently IGNORED rather
		// than rejected: it selects between two find bodies, and with no find
		// body to select it simply has no effect. Rejecting it made a harmless
		// key a build failure.
		owner := fmt.Sprintf("set %q", s.Name)
		for _, c := range caps {
			name := c.Name
			// A set's `find` synthesizes <find>_batch under
			// `hints: [batch-find]`, exactly as a pattern's find_func does,
			// so the same rule applies: the user may not name a capability
			// into that space, and the synthesized name is reserved whether
			// or not this set asks for it today. Conditioning the check on
			// the hint would mean ADDING the hint to a working config turns a
			// valid export into a duplicate.
			if strings.HasSuffix(name, "_batch") {
				return fmt.Errorf("%s: export name %q must not end in \"_batch\" (reserved for the compiler-synthesized batch export)", owner, name)
			}
			if prior, dup := exportNames[name]; dup {
				return fmt.Errorf("duplicate WASM export name %q (used by %s and %s)", name, prior, owner)
			}
			exportNames[name] = owner
			if c.Field == "find" {
				exportNames[SetBatchExportName(name)] = owner + " (batch export)"
			}
		}
		if !s.Patterns.All && len(s.Patterns.Names) == 0 {
			return fmt.Errorf("set %q: patterns is required (use \"all\" or a non-empty list of pattern names)", s.Name)
		}
		if !s.Patterns.All {
			seen := make(map[string]bool, len(s.Patterns.Names))
			for _, pname := range s.Patterns.Names {
				if _, ok := nameIdx[pname]; !ok {
					return fmt.Errorf("set %q: unknown pattern name %q", s.Name, pname)
				}
				if seen[pname] {
					return fmt.Errorf("set %q: pattern %q listed more than once", s.Name, pname)
				}
				seen[pname] = true
			}
		}
	}
	return nil
}

// RegexEntry describes a single regexp pattern and the functions to generate for it.
// One or more of the Func fields must be set; only those stubs are generated.
// The WASM export names are derived automatically from the function type.
type RegexEntry struct {
	Name    string `yaml:"name"` // optional; used by sets: for pattern selection
	Pattern string `yaml:"pattern"`

	// Optional function names — only those set are compiled and stubbed.
	MatchFunc  string `yaml:"match_func"`  // anchored match → the end position, or none
	FindFunc   string `yaml:"find_func"`   // non-anchored find → an iterator of (start, end)
	GroupsFunc string `yaml:"groups_func"` // captures → an iterator of matches, each carrying its groups

	// `named_groups_func:` was RETIRED by TODO task 62 and is a load error,
	// which strict YAML decoding gives for free. It was never a separate
	// capability: both stubs called the SAME WASM export, and the two differed
	// only in how the item was assembled — a map keyed by name instead of a
	// slice indexed by number, minus the whole match and minus the groups that
	// did not participate. `groups_func` now carries both, with generated
	// name→index constants and a `<func>_index` lookup, which also gives C and
	// AssemblyScript named access they never had.

	// Hints biases which suffix-DFA optimisation path to favour for this
	// specific pattern, and/or requests extra WASM exports. Accepted values:
	// nil/empty (no hint, falls back to the enclosing set's hints for the
	// suffix-DFA choice), "prefer-match", "prefer-no-match" — mutually
	// exclusive with each other — and "batch-find", which is independent
	// of the other two and may
	// be combined with either (or neither): it requests a `<func>_batch` WASM
	// export for this pattern's find_func/groups_func, consumed only by the
	// JS and TS generators (a no-op for Rust/Go/C/AS stubs).
	Hints []string `yaml:"hints"`
}

// CaptureStubsRequested reports whether any capture-returning stub is requested.
func (r RegexEntry) CaptureStubsRequested() bool {
	return r.GroupsFunc != ""
}

// GroupsExportName returns the WASM export name for the groups function.
func (r RegexEntry) GroupsExportName() string {
	return r.GroupsFunc
}

// LoadConfig reads and parses the YAML config at configPath.
// If configPath is empty it looks for regexped.yaml in the current directory.
func LoadConfig(configPath string) (BuildConfig, error) {
	if configPath == "" {
		configPath = "regexped.yaml"
	}
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return BuildConfig{}, fmt.Errorf("resolve config path: %w", err)
	}
	configDir := filepath.Dir(absConfig)

	raw, err := os.ReadFile(absConfig)
	if err != nil {
		return BuildConfig{}, fmt.Errorf("read config %s: %w", configPath, err)
	}
	// Strict decoding: every unknown YAML key
	// anywhere in the file is a line-numbered load error. That catches the
	// set keys retired by this redesign — find_any, find_all, batch_size —
	// and all future typos (`mach_func:` …), with no tombstone fields and
	// no targeted "renamed to" messages.
	var cfg BuildConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw), yaml.Strict())
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return BuildConfig{}, fmt.Errorf("parse config %s: %w", configPath, err)
	}
	if len(cfg.Regexps) == 0 {
		return BuildConfig{}, fmt.Errorf("config %s has no regexps", configPath)
	}

	// Resolve all paths relative to the config file's directory.
	cfg.Output = resolveFilePath(configDir, cfg.Output)
	cfg.WasmFile = resolveFilePath(configDir, cfg.WasmFile)
	cfg.StubFile = resolveFilePath(configDir, cfg.StubFile)
	cfg.WasmMerge = resolveFilePath(configDir, cfg.WasmMerge)

	// Identifier validation runs first: every later stage interpolates these
	// names into generated source, so nothing should touch them until they are
	// known to be well-formed. See identifier.go.
	if err := ValidateConfig(&cfg); err != nil {
		return BuildConfig{}, fmt.Errorf("config %s: %w", configPath, err)
	}
	if err := ValidateSets(&cfg); err != nil {
		return BuildConfig{}, fmt.Errorf("config %s: %w", configPath, err)
	}
	if err := validateHints(&cfg); err != nil {
		return BuildConfig{}, fmt.Errorf("config %s: %w", configPath, err)
	}

	return cfg, nil
}

// resolveFilePath resolves path relative to base unless path is empty or
// absolute. A leading "~/" is expanded to the user's home directory rather
// than being passed through: every caller of this function feeds the result
// to os.MkdirAll/os.WriteFile/exec, none of which do shell expansion, so a
// pass-through creates a literal "~" directory in cwd.
func resolveFilePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if strings.HasPrefix(path, "~/") {
		return ExpandHome(path)
	}
	return filepath.Join(base, path)
}

// ExpandHome replaces a leading "~/" with the user's home directory. A bare
// "~" and the "~user" form are left alone: only the shell knows how to resolve
// another user's home, and expanding "~" alone would silently turn a relative
// path into an absolute one. If the home directory cannot be determined the
// path is returned unchanged.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
