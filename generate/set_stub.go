package generate

import (
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

// wideAllForm reports whether a set's `_all` capabilities use the >64-pattern
// out_ptr bitmap form rather than an i64 bitmask return.
//
// Keyed on the ID SPACE, matching compiledSet.wideAll(): the form exists to
// carry bit positions, and a bit position is a pattern id. Keying it on the
// pattern count let the stub declare one signature while the module exported
// the other.
func wideAllForm(s config.SetConfig, cfg config.BuildConfig) bool {
	return idSpaceSize(s, cfg) > 64
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

// hasFindBatch reports whether any set in cfg declares find_batch. It gates the
// SetTuple buffer type, which only a batched scan's caller needs — emitting it
// unconditionally would put an unused public type into every set-bearing stub.
func hasFindBatch(cfg config.BuildConfig) bool {
	for _, s := range cfg.Sets {
		if s.FindBatch != "" {
			return true
		}
	}
	return false
}
