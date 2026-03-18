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
	Regexes   []RegexEntry `yaml:"regexes"`
}

// RegexEntry describes a single regex→WASM compilation unit.
type RegexEntry struct {
	WasmFile     string `yaml:"wasm_file"`
	ImportModule string `yaml:"import_module"`
	StubFile     string `yaml:"stub_file"`
	ExportName   string `yaml:"export_name"`
	FuncName     string `yaml:"func_name"`
	Pattern      string `yaml:"pattern"`
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
