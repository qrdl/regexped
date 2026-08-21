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

// patternsInSet returns the number of patterns in s. For sets.patterns: "all"
// this is len(cfg.Regexps); otherwise it is len(s.Patterns.Names). The count
// is a safe upper bound on how many matches the WASM function can emit at a
// single start position (each global pattern ID can emit at most once per
// start in the `find` output — and, under D16, the value emitted as the
// public <SET>_PATTERN_COUNT constant in every stub language, so a stub's
// arrays and a caller's arrays are provably the same size.
func patternsInSet(s config.SetConfig, cfg config.BuildConfig) int {
	if s.Patterns.All {
		return len(cfg.Regexps)
	}
	return len(s.Patterns.Names)
}

// setConstBase sanitises a set name into an identifier stem for the emitted
// pattern-count constant (plans/SETS.md D16).
//
// `sets[].name` is deliberately NOT identifier-validated — it is a selection
// key, and shipped configs use names like "sql-validator" — so it cannot be
// interpolated verbatim. Non-alphanumerics become underscores and a leading
// digit is prefixed. (agent's choice, recorded in plans/SETS.md §9.7.)
func setConstBase(name string) string {
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
func wideAllForm(s config.SetConfig, cfg config.BuildConfig) bool {
	return patternsInSet(s, cfg) > 64
}

// bitmapBytes is the size of the >64-pattern bitmap: ceil(P/8).
func bitmapBytes(s config.SetConfig, cfg config.BuildConfig) int {
	return (patternsInSet(s, cfg) + 7) / 8
}

// gatedFind reports whether a set's `find` is the default gated body, which
// carries a gate-array parameter the stub must own and zero (§3.14).
func gatedFind(s config.SetConfig) bool { return s.Find != "" && !s.Overlapping }
