package generate

import "github.com/qrdl/regexped/config"

// hasSetExports reports whether cfg has any sets with at least one export field.
func hasSetExports(cfg config.BuildConfig) bool {
	for _, s := range cfg.Sets {
		if s.FindAny != "" || s.FindAll != "" || s.Match != "" {
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
// this is len(cfg.Regexes); otherwise it is len(s.Patterns.Names). The count
// is a safe upper bound on how many matches the WASM function can emit at a
// single start position (each global pattern ID can emit at most once per
// start in the find_all output).
func patternsInSet(s config.SetConfig, cfg config.BuildConfig) int {
	if s.Patterns.All {
		return len(cfg.Regexes)
	}
	return len(s.Patterns.Names)
}

// batchSize returns the effective output capacity in tuples for a set. It is
// the maximum of:
//   - the user-configured batch_size (default 256),
//   - 64 (minimum amortisation floor),
//   - patternsInSet(s, cfg) — so a single start position can never emit more
//     matches than the buffer holds. This is required for the "advance to
//     last.start + max(last.length, 1)" resume rule used by the generated
//     wrappers: when out_cap == count the batch may have been truncated
//     mid-position, but with out_cap >= patternsInSet that truncation
//     cannot happen.
func batchSize(s config.SetConfig, cfg config.BuildConfig) int {
	bs := s.BatchSize
	if bs <= 0 {
		bs = 256
	}
	if bs < 64 {
		bs = 64
	}
	if n := patternsInSet(s, cfg); bs < n {
		bs = n
	}
	return bs
}
