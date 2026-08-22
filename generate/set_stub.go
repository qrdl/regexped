package generate

import (
	"github.com/qrdl/regexped/config"
)

// hasSetExports reports whether cfg has any sets with at least one declared
// capability (plans/SETS.md §3.12).
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
// with idSpaceSize instead (plans/SETS.md §11 R1).
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
// pattern-count and id-space constants (plans/SETS.md D16, §11 R1).
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
func screamingCase(name string) string {
	base := setConstBase(name)
	var out []rune
	for i, c := range base {
		if i > 0 && c >= 'A' && c <= 'Z' {
			prev := rune(base[i-1])
			if prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9' {
				out = append(out, '_')
			}
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// pascalSet returns the PascalCase form of a sanitised set name.
func pascalSet(name string) string {
	return config.PascalCaseForValidation(setConstBase(name))
}

// camelSet returns the camelCase form of a sanitised set name.
func camelSet(name string) string {
	p := pascalSet(name)
	if p == "" {
		return p
	}
	r := []rune(p)
	if r[0] >= 'A' && r[0] <= 'Z' {
		r[0] += 'a' - 'A'
	}
	return string(r)
}

// wideAllForm reports whether a set's `_all` capabilities use the >64-pattern
// out_ptr bitmap form rather than an i64 bitmask return (plans/SETS.md §3.13).
//
// Keyed on the ID SPACE, matching compiledSet.wideAll(): the form exists to
// carry bit positions, and a bit position is a pattern id. Keying it on the
// pattern count let the stub declare one signature while the module exported
// the other (plans/SETS.md §11 R1).
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
