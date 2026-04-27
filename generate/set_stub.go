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

// batchSize returns the batch size for a set (default 256).
func batchSize(s config.SetConfig) int {
	if s.BatchSize > 0 {
		return s.BatchSize
	}
	return 256
}
