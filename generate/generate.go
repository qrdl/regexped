package generate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strings"

	"github.com/qrdl/regexped/config"
)

// ResolveStubType determines the stub type from cfg.StubType or the extension
// of cfg.StubFile. Returns one of "rust", "js", "ts", or an error.
func ResolveStubType(cfg config.BuildConfig) (string, error) {
	if cfg.StubType != "" {
		switch cfg.StubType {
		case "rust", "js", "ts", "go", "c", "as":
			return cfg.StubType, nil
		default:
			return "", fmt.Errorf("unknown stub_type %q (expected rust, js, ts, go, c, or as)", cfg.StubType)
		}
	}
	ext := strings.ToLower(filepath.Ext(cfg.StubFile))
	switch ext {
	case ".rs":
		return "rust", nil
	case ".js":
		return "js", nil
	case ".ts":
		return "ts", nil
	case ".go":
		return "go", nil
	case ".h":
		return "c", nil
	default:
		return "", fmt.Errorf("cannot infer stub type from %q: set stub_type in config (rust, js, ts, go, c, or as)", cfg.StubFile)
	}
}

// CmdGenerateStub generates a stub file of the appropriate type for cfg.
// out is the full output path or "-" for stdout.
func CmdGenerateStub(cfg config.BuildConfig, out string) error {
	stubType, err := ResolveStubType(cfg)
	if err != nil {
		return err
	}
	switch stubType {
	case "rust":
		return rustStub(cfg, out)
	case "js":
		return jsStub(cfg, out)
	case "ts":
		return tsStub(cfg, out)
	case "go":
		return goStub(cfg, out)
	case "c":
		return cStub(cfg, out)
	case "as":
		return asStub(cfg, out)
	}
	return fmt.Errorf("unknown stub type: %s", stubType)
}

// writeStub creates the parent directory and writes data to path.
func writeStub(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	slog.Info("Written stub", "file", path)
	return nil
}

// extractGroupInfo parses the pattern and returns:
// - numGroups: total number of capture groups including group 0
// - namedGroups: map from name to group index (1-based) for named groups
func extractGroupInfo(pattern string) (int, map[string]int, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, nil, fmt.Errorf("parse pattern: %w", err)
	}
	numGroups := re.MaxCap() + 1 // +1 for group 0
	named := make(map[string]int)
	collectNamedGroups(re, named)
	return numGroups, named, nil
}

func collectNamedGroups(re *syntax.Regexp, named map[string]int) {
	if re.Op == syntax.OpCapture && re.Name != "" {
		named[re.Name] = re.Cap
	}
	for _, sub := range re.Sub {
		collectNamedGroups(sub, named)
	}
}
