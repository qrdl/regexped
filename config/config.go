package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// BuildConfig is the top-level structure of the YAML config file.
type BuildConfig struct {
	WasmMerge string       `yaml:"wasm_merge"` // optional; defaults to "wasm-merge" in $PATH
	Output    string       `yaml:"output"`     // default output path for merge command
	StubDir   string       `yaml:"stub_dir"`   // default output directory for stub files
	WasmDir   string       `yaml:"wasm_dir"`   // default output directory for compiled WASM files
	Regexes   []RegexEntry `yaml:"regexes"`
}

// RegexEntry describes a single regex→WASM compilation unit.
// One or more of the Func fields must be set; only those stubs are generated.
// The WASM export names are derived automatically from the function type.
type RegexEntry struct {
	WasmFile     string `yaml:"wasm_file"`
	ImportModule string `yaml:"import_module"`
	StubFile     string `yaml:"stub_file"`
	Pattern      string `yaml:"pattern"`

	// Optional function names — only those set are compiled and stubbed.
	MatchFunc       string `yaml:"match_func"`        // anchored match → Option<usize>
	FindFunc        string `yaml:"find_func"`          // non-anchored find → Option<(usize,usize)>
	GroupsFunc      string `yaml:"groups_func"`        // anchored + captures → Option<Vec<Option<(usize,usize)>>>
	NamedGroupsFunc string `yaml:"named_groups_func"`  // anchored + named captures → Option<HashMap<&'static str,(usize,usize)>>
}

// CaptureStubsRequested reports whether any capture-returning stub is requested.
func (r RegexEntry) CaptureStubsRequested() bool {
	return r.GroupsFunc != "" || r.NamedGroupsFunc != ""
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
	var cfg BuildConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return BuildConfig{}, fmt.Errorf("parse config %s: %w", configPath, err)
	}
	if len(cfg.Regexes) == 0 {
		return BuildConfig{}, fmt.Errorf("config %s has no regexes", configPath)
	}

	// Resolve all paths relative to the config file's directory.
	cfg.Output    = resolveRelative(configDir, cfg.Output)
	cfg.WasmMerge = resolveRelative(configDir, cfg.WasmMerge)
	cfg.StubDir   = resolveRelative(configDir, cfg.StubDir)
	cfg.WasmDir   = resolveRelative(configDir, cfg.WasmDir)

	return cfg, nil
}

// resolveRelative resolves path relative to base, unless path is empty,
// already absolute, starts with "~/" (home-relative), or is a bare command
// name with no path separator.
func resolveRelative(base, path string) string {
	if path == "" || filepath.IsAbs(path) || strings.HasPrefix(path, "~/") ||
		!strings.ContainsRune(path, '/') {
		return path
	}
	return filepath.Join(base, path)
}
