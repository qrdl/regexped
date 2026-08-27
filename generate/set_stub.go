package generate

import (
	"regexp"
	"strings"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// hasSetExports reports whether cfg has any sets with at least one declared
// capability.
func hasSetExports(cfg config.BuildConfig) bool {
	for _, s := range cfg.Sets {
		if s.HasExports() {
			return true
		}
	}
	return false
}

// hasSuspendableExports reports whether cfg generates any GENERATOR — the only
// exports that suspend, and therefore the only ones that reserve a region of
// their own (_open / _close / _att).
//
// This gates their EMISSION rather than just their use: a stub is a file the
// caller compiles, and TypeScript under --noUnusedLocals rejects a declared
// helper nothing calls. Before regions existed the question could not arise,
// because _w and _resize were used by every shape.
func hasSuspendableExports(cfg config.BuildConfig) bool {
	for _, re := range cfg.Regexps {
		if re.FindFunc != "" || re.GroupsFunc != "" {
			return true
		}
	}
	for _, s := range cfg.Sets {
		if s.Find != "" {
			return true
		}
	}
	return false
}

// hasOneShotExports reports whether cfg generates any export that CANNOT
// suspend, and so stages into the transient area above the bump (_stage)
// instead of reserving. Same emission-gating reason as hasSuspendableExports.
func hasOneShotExports(cfg config.BuildConfig) bool {
	for _, re := range cfg.Regexps {
		if re.MatchFunc != "" {
			return true
		}
	}
	for _, s := range cfg.Sets {
		if s.MatchAny != "" || s.MatchAll != "" || s.ScanAny != "" || s.ScanAll != "" {
			return true
		}
	}
	return false
}

// hasEmitNameMap reports whether any set has emit_name_map: true.
func hasEmitNameMap(cfg config.BuildConfig) bool {
	for _, s := range cfg.Sets {
		if s.EmitNameMap {
			return true
		}
	}
	return false
}

// patternsInSet returns the number of patterns in s — a safe upper bound on
// how many matches `find` can report at a single start position (each pattern
// emits at most once per start), and therefore the size of the tuple buffer.
// Emitted as the public <SET>_PATTERN_COUNT constant under D16.
//
// It is NOT a bound on pattern id VALUES: ids are global indices into
// `regexps:`, so a set holding two patterns can report id 69. Anything indexed
// by a pattern id — gate arrays, `_all` bitmasks and bitmaps — must be sized
// with idSpaceSize instead.
func patternsInSet(s config.SetConfig, cfg config.BuildConfig) int {
	return s.PatternCount(cfg)
}

// idSpaceSize returns one past the largest pattern id this set can report.
//
// This calls the SAME config method the compiler uses (through
// SetSpec.IDSpaceSize), which is what makes the stub's arrays and the emitted
// module's indexing provably agree. Do not re-derive it here.
func idSpaceSize(s config.SetConfig, cfg config.BuildConfig) int {
	return s.IDSpaceSize(cfg)
}

// setConstBase sanitises a set name into an identifier stem for the emitted
// pattern-count and id-space constants.
//
// Delegates to config.SanitizeSetName so that ValidateSets — which rejects two
// set names that collapse to one stem — and the generators cannot disagree
// about what a name sanitises to.
func setConstBase(name string) string {
	return config.SanitizeSetName(name)
}

// screamingCase returns the SCREAMING_SNAKE_CASE form of a sanitised set name,
// inserting an underscore at lower→upper transitions so "sqlValidator" becomes
// "SQL_VALIDATOR" rather than "SQLVALIDATOR".
//
// Delegated, like setConstBase, so that ValidateExports — which must reserve
// the constants these stems name (config.setDerivedNames) — cannot disagree
// with what the generators actually emit.
func screamingCase(name string) string {
	return config.ScreamingSetName(name)
}

// pascalSet returns the PascalCase form of a sanitised set name.
func pascalSet(name string) string {
	return config.PascalSetName(name)
}

// camelSet returns the camelCase form of a sanitised set name.
func camelSet(name string) string {
	return config.CamelSetName(name)
}

// wideAllForm reports whether a set's `_all` capabilities use the out_ptr
// bitmap form rather than an i64 bitmask return.
//
// This MUST track compiledSet.wideAll() exactly. A disagreement is not a build
// error — both sides are just integers to WASM — it is a stub that reads a
// count as a bitmask, so both conditions live here in the same order the
// emitter tests them:
//
//   - ID SPACE > 64: the form exists to carry bit positions, and a bit position
//     is a pattern id. Keying this on the pattern count instead let the stub
//     declare one signature while the module exported the other.
//
//   - A BACKTRACKING MEMBER: BT can answer "unknown" (abi.BTStackOverflow), and
//     the narrow form has nowhere to put it — its i64 return IS the bitmask, so
//     every value is already a legal answer. Moving the bitmap into memory frees
//     the return to carry a count that can go negative (SETS_PLAN item 20
//     decision 3).
//
// The second condition is a COMPILE-time fact, which is why it comes from
// compile.SetAdmitsBacktracking rather than from arithmetic on the config: the
// admission depends on which patterns exceeded max_fallback_states and whether
// BT accepted them. Asking the compiler keeps one source of truth; `generate`
// still needs nothing but the config to run.
func wideAllForm(s config.SetConfig, cfg config.BuildConfig) bool {
	return idSpaceSize(s, cfg) > 64 || compile.SetAdmitsBacktracking(s, cfg)
}

// bitmapBytes is the size of the >64-pattern bitmap: ceil(idSpace/8).
func bitmapBytes(s config.SetConfig, cfg config.BuildConfig) int {
	return (idSpaceSize(s, cfg) + 7) / 8
}

// cursorCountBits is the width of the find_batch cursor's count field for this
// set.
//
// It calls the SAME config function the compiler encodes with, for the reason
// idSpaceSize gives: a layout each side derives independently is a layout that
// can drift. Do not re-derive it here.
func cursorCountBits(s config.SetConfig, cfg config.BuildConfig) int {
	return config.SetCursorCountBits(patternsInSet(s, cfg))
}

// cursorCountMask masks the count out of a find_batch return value.
func cursorCountMask(s config.SetConfig, cfg config.BuildConfig) int64 {
	return int64(1)<<uint(cursorCountBits(s, cfg)) - 1
}

// cursorMaxCount is the largest count one find_batch call can report. The
// emitted body clamps out_cap to it, so a stub must not hand it a larger
// capacity and then expect the extra slots to be filled.
func cursorMaxCount(s config.SetConfig, cfg config.BuildConfig) int64 {
	return int64(config.SetCursorMaxCount(patternsInSet(s, cfg)))
}

// defaultBatchCap is the buffer size a generated batch iterator uses when the
// caller does not name one, in tuples.
//
// 256 is arbitrary but not accidental: at 12 bytes a tuple that is a 3 KB
// buffer, small enough to be uninteresting to allocate and large enough that
// the per-call host crossing find_batch exists to amortise is amortised over a
// few hundred matches. Callers who care pass their own.
//
// It is never below one position's worst case, so a single call always makes
// progress even on a set whose every pattern matches at one spot.
func defaultBatchCap(s config.SetConfig, cfg config.BuildConfig) int {
	n := patternsInSet(s, cfg)
	if n < 256 {
		n = 256
	}
	if max := int(cursorMaxCount(s, cfg)); n > max {
		n = max
	}
	return n
}

// setInlineByteLimit is the byte budget for arrays a generated iterator holds
// BY VALUE. Above it the generator boxes them instead.
//
// The arrays are sized by the set — 12 bytes per pattern for the tuple buffer,
// 4 per id for the gate array — so a large set turns an iterator into a large
// value, and a value is what Rust MOVES: returning it from the constructor,
// handing it to `for`, wrapping it in `.take()` or `.map()`. Measured on a
// 2,000-pattern set, `find(input, 0).take(3).map(..)` compiled to a memset, a
// memcpy and a 60 KB stack frame for a struct of 32,032 bytes.
//
// 4 KB is a threshold, not a measurement: it is roughly a page, it keeps the
// iterator comfortably inside any stack a wasm host provides, and it leaves
// every set small enough to be typed out by hand on the zero-allocation path
// unchanged. A set crosses it at about 250 patterns.
//
// Below the limit nothing changes, which is the point: `find` allocating
// NOTHING is a property worth keeping where it costs nothing (SETS §19.6), and
// only sets that cannot honour it pay an allocation.
const setInlineByteLimit = 4096

// boxSetBuffers reports whether a set's iterator arrays exceed the by-value
// budget and must be boxed. tupleSlots is the number of 12-byte tuples held
// inline (0 when the buffer is the caller's), gateSlots the number of 4-byte
// gate entries (0 when the set's find is not gated).
func boxSetBuffers(tupleSlots, gateSlots int) bool {
	return tupleSlots*12+gateSlots*4 > setInlineByteLimit
}

// ---------------------------------------------------------------------------
// The capability descriptor table (SETS_PLAN item 7 / SETS.md R12).
//
// A set capability's WASM signature is ONE fact. Before this it was six: each
// generator in this package hand-rolled the same chain over the five
// capabilities and restated the parameter list from memory. That duplication is
// what let R1 diverge — a stub sized an array by PATTERN_COUNT where the module
// indexed it by ID_SPACE, which is a memory-safety hazard rather than a wrong
// answer — so the ORDER and MEANING of the parameters live here and nowhere
// else.
//
// What stays per-generator is SPELLING: `ptr: *const u8` against
// `const char *ptr` against `ptr unsafe.Pointer` is each language's own
// business, and C even puts the return type first. A generator therefore
// iterates the descriptor and renders each parameter in its own syntax; it no
// longer decides WHICH parameters there are.

// abiParam is one argument of a set capability's WASM export.
type abiParam int

const (
	// abiInputPtr is a pointer to the input bytes. It always describes the
	// WHOLE input — `abiFrom` bounds where the search starts, it does not
	// truncate what the engine can see behind that point, which is what lets
	// `\b`, `\B` and `(?m:^)` judge the real preceding byte.
	abiInputPtr abiParam = iota
	// abiInputLen is the input length in bytes.
	abiInputLen
	// abiFrom is the position the search starts at.
	abiFrom
	// abiGatePtr is the caller-owned gate array: ID_SPACE u32s, zeroed to
	// start a drive. Sized by ID_SPACE and never by PATTERN_COUNT — a set of
	// two patterns can report id 69. This is the R1 hazard.
	abiGatePtr
	// abiBitmapPtr is the caller-owned `_all` bitmap, ceil(ID_SPACE/8) bytes.
	// Present only in the WIDE form (see wideAllForm).
	abiBitmapPtr
	// abiTuplePtr is the caller-owned tuple buffer: {id, start, end} i32
	// triples, so 12 bytes per tuple.
	abiTuplePtr
	// abiOutCap is the tuple buffer's capacity in TUPLES, not bytes.
	abiOutCap
	// abiCursor is the batch entry's opaque i64 resume cursor.
	abiCursor
)

// abiRet is a capability's WASM return type.
type abiRet int

const (
	abiRetI32 abiRet = iota
	abiRetI64
)

// setCapability describes one DECLARED capability of one set.
//
// Export is the config value verbatim, because that value IS the WASM export
// name (see the "Export-name rules" section of docs/cli.md).
type setCapability struct {
	Kind   string // "match_any", "match_all", "scan_any", "scan_all", "find"
	Export string
	Params []abiParam
	Ret    abiRet
}

// setCapabilities returns every capability this set declares, in a fixed
// order, with the exact parameter list each one's WASM export takes.
//
// The two conditional shapes are resolved HERE rather than in each generator:
//
//   - `_all` takes a memory bitmap and returns a count in the WIDE form, and
//     returns an i64 bitmask in the narrow one. wideAllForm decides, and it
//     must track compiledSet.wideAll() exactly.
//   - `find` ALWAYS takes the gate array, in both the gated and the
//     `overlapping: true` flavours — one signature, both bodies (SETS_PLAN
//     item 11). The overlapping body records no match gates and uses the array
//     as the per-drive home of its "matches nowhere" preflight verdict, which
//     is indistinguishable from the stub's side.
func setCapabilities(s config.SetConfig, cfg config.BuildConfig) []setCapability {
	wide := wideAllForm(s, cfg)
	var caps []setCapability
	add := func(kind, export string, params []abiParam, ret abiRet) {
		if export == "" {
			return
		}
		caps = append(caps, setCapability{Kind: kind, Export: export, Params: params, Ret: ret})
	}

	add("match_any", s.MatchAny, []abiParam{abiInputPtr, abiInputLen}, abiRetI32)
	if wide {
		add("match_all", s.MatchAll, []abiParam{abiInputPtr, abiInputLen, abiBitmapPtr}, abiRetI32)
	} else {
		add("match_all", s.MatchAll, []abiParam{abiInputPtr, abiInputLen}, abiRetI64)
	}
	add("scan_any", s.ScanAny, []abiParam{abiInputPtr, abiInputLen, abiFrom}, abiRetI32)
	if wide {
		add("scan_all", s.ScanAll, []abiParam{abiInputPtr, abiInputLen, abiFrom, abiBitmapPtr}, abiRetI32)
	} else {
		add("scan_all", s.ScanAll, []abiParam{abiInputPtr, abiInputLen, abiFrom}, abiRetI64)
	}
	add("find", s.Find, []abiParam{abiInputPtr, abiInputLen, abiFrom, abiGatePtr, abiTuplePtr, abiOutCap}, abiRetI32)
	return caps
}

// setBatchCapability returns the descriptor for the hidden multi-position
// entry a `hints: [batch-find]` set carries beside `find`, or nil.
//
// Its export name is DERIVED rather than declared, through the same function
// the compiler uses, so the two cannot drift. The cursor replaces `from`: it
// carries the resume position in its high half and the intra-position index in
// its low half.
func setBatchCapability(s config.SetConfig) *setCapability {
	if !s.HasFind() || !s.BatchFind() {
		return nil
	}
	return &setCapability{
		Kind:   "find_batch",
		Export: config.SetBatchExportName(s.Find),
		Params: []abiParam{abiInputPtr, abiInputLen, abiCursor, abiGatePtr, abiTuplePtr, abiOutCap},
		Ret:    abiRetI64,
	}
}

// render spells this capability's parameter list with a per-language speller
// and joins it. The speller receives each abiParam in ABI order and returns
// that language's declaration for it.
func (c setCapability) render(spell func(abiParam) string, sep string) string {
	parts := make([]string, 0, len(c.Params))
	for _, p := range c.Params {
		parts = append(parts, spell(p))
	}
	return strings.Join(parts, sep)
}

// capByKind returns the declared capability of the given kind, or nil. Kinds
// are the config key names: "match_any", "match_all", "scan_any", "scan_all",
// "find".
func capByKind(caps []setCapability, kind string) *setCapability {
	for i := range caps {
		if caps[i].Kind == kind {
			return &caps[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Deriving symbol names from a user's function name (TODO task 62).
//
// Function names are emitted VERBATIM — whatever the user wrote in the config
// is what a caller writes — so anything DERIVED from one has to follow the
// same style, or a config full of snake_case grows camelCase relatives. The
// style is detected from the name itself rather than imposed by the language.
//
// CONSTANTS FOLLOW THE SAME RULE, on purpose. A language's own convention
// (SCREAMING_SNAKE in Rust and C, PascalCase in Go) is NOT imposed on a name
// derived from one the user chose — a config written in snake_case must not
// sprout SCREAMING relatives. Where that produces a name a language's linter
// dislikes, the generator suppresses the lint rather than renaming the symbol:
// Rust gets #[allow(non_upper_case_globals)]. Set constants keep their
// existing SCREAMING form because they derive from a SET NAME, which is not a
// symbol the user calls.

// derivedFuncName joins a user-chosen base name with a suffix in the base's own
// style: url_groups + index -> url_groups_index, urlGroups + index ->
// urlGroupsIndex.
func derivedFuncName(base, suffix string) string {
	if suffix == "" {
		return base
	}
	if isCamelStyle(base) {
		return base + strings.ToUpper(suffix[:1]) + suffix[1:]
	}
	return base + "_" + suffix
}

// isCamelStyle reports whether a name reads as camelCase rather than
// snake_case. An underscore anywhere settles it as snake; otherwise an
// uppercase letter after the first character settles it as camel. A name with
// neither (`find`) is treated as snake, which is what appending `_index` to it
// looks like anyway.
func isCamelStyle(name string) bool {
	if strings.Contains(name, "_") {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return true
		}
	}
	return false
}

// derivedConstName names a constant a function contributes, in the function's
// own style: url_groups + host -> url_groups_host, urlGroups + host ->
// urlGroupsHost. Identical to derivedFuncName — named separately only so a
// call site says which kind of symbol it is asking for.
func derivedConstName(base, suffix string) string {
	return derivedFuncName(base, suffix)
}

// groupNameSlots turns the parser's name→slot map into a slice aligned with
// group INDICES, "" where a group has no name — the shape
// regexp.SubexpNames uses, index 0 (the whole match) included.
//
// numGroups already counts group 0 (extractGroupInfo returns MaxCap()+1), so
// the slice is exactly that long.
func groupNameSlots(numGroups int, namedGroups map[string]int) []string {
	names := make([]string, numGroups)
	for name, idx := range namedGroups {
		if idx >= 0 && idx < len(names) {
			names[idx] = name
		}
	}
	return names
}

// namespaced prefixes a generated symbol with the config's `namespace:`, in
// the namespace's own casing style so the result reads as one name rather than
// two glued together.
//
// It applies ONLY to names the user did not choose — Span, SetMatch, the error
// type, the pattern-name helper, C's typedefs. A user-chosen export name is
// emitted verbatim and never prefixed: the point of the key is to let two
// stubs share a package, not to rename the API.
func namespaced(cfg config.BuildConfig, name string) string {
	if cfg.Namespace == "" {
		return name
	}
	return derivedFuncName(cfg.Namespace, name)
}

// sharedSymbols lists, per stub language, the identifiers a generated file
// declares that are NOT named by the user. These are exactly the names two
// stubs generated into one package collide on.
//
// A user-chosen export name never appears here: the `namespace:` key exists to
// let two stubs coexist, not to rename anyone's API. Nor do symbols DERIVED
// from a user name (`<func>_index`, `<func>_iter_t`), which are already unique
// if the export names are.
var sharedSymbols = map[string][]string{
	"go": {"Span", "ErrBacktrackOverflow", "SetMatch", "PatternName"},
	"js": {"SetMatch", "patternName", "BacktrackOverflowError"},
	"ts": {"SetMatch", "patternName", "BacktrackOverflowError"},
	"as": {"SetMatch", "patternName", "RX_ERR_BT_OVERFLOW", "RX_ITER_ERROR"},
	"c": {
		"rx_match_t", "rx_group_t", "rx_set_match_t", "pattern_name",
		"RX_ERR_BT_OVERFLOW", "RX_ERR_NULL_ARG", "RX_ERR_RANGE",
		"REGEXPED_TYPES_DEFINED",
	},
	// Rust is deliberately absent: `pub mod <import_module>` already isolates
	// every stub, so the key is a no-op there.
}

// applyNamespace rewrites the shared symbols of a finished stub to carry the
// config's `namespace:` prefix.
//
// A whole-file rewrite rather than a parameter threaded through forty emission
// sites. That is a real trade and worth stating: it works because the list
// above is FIXED and every entry is a whole identifier, so a word-boundary
// match cannot touch a substring of something else, and because it runs on
// source this package just generated rather than on anything a user wrote. If
// the list ever grows a name that is also a common English word, thread the
// parameter instead.
func applyNamespace(cfg config.BuildConfig, stubType, src string) string {
	if cfg.Namespace == "" || src == "" {
		return src
	}
	names, ok := sharedSymbols[stubType]
	if !ok {
		return src
	}
	for _, name := range names {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		src = re.ReplaceAllString(src, namespaced(cfg, name))
	}
	return src
}
