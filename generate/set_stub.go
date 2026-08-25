package generate

import (
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
		if re.FindFunc != "" || re.GroupsFunc != "" || re.NamedGroupsFunc != "" {
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

// gatedFind reports whether a set's `find` is the default gated body, which
// carries a gate-array parameter the stub must own and zero (§3.14).
func gatedFind(s config.SetConfig) bool { return s.Gated() }

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
