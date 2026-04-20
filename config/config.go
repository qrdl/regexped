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
	WasmMerge    string       `yaml:"wasm_merge"`     // optional; defaults to "wasm-merge" in $PATH
	Output       string       `yaml:"output"`         // output path for merge command; overridable with -o
	WasmFile     string       `yaml:"wasm_file"`      // output WASM file for compile command; overridable with -o
	ImportModule string       `yaml:"import_module"`  // WASM import module name used by wasm-merge and Rust FFI
	StubFile     string       `yaml:"stub_file"`      // stub output file (Rust, JS, or TS)
	StubType     string       `yaml:"stub_type"`      // stub type: "rust", "js", "ts"; inferred from stub_file extension if absent
	MaxDFAStates int          `yaml:"max_dfa_states"` // 0 = default (1024)
	MaxTDFARegs  int          `yaml:"max_tdfa_regs"`  // 0 = default (32)
	Regexes      []RegexEntry `yaml:"regexes"`
}

// RegexEntry describes a single regex pattern and the functions to generate for it.
// One or more of the Func fields must be set; only those stubs are generated.
// The WASM export names are derived automatically from the function type.
type RegexEntry struct {
	Pattern string `yaml:"pattern"`

	// Optional function names — only those set are compiled and stubbed.
	MatchFunc       string `yaml:"match_func"`        // anchored match → Option<usize>
	FindFunc        string `yaml:"find_func"`         // non-anchored find → Option<(usize,usize)>
	GroupsFunc      string `yaml:"groups_func"`       // anchored + captures → Option<Vec<Option<(usize,usize)>>>
	NamedGroupsFunc string `yaml:"named_groups_func"` // anchored + named captures → Option<HashMap<&'static str,(usize,usize)>>
}

// CaptureStubsRequested reports whether any capture-returning stub is requested.
func (r RegexEntry) CaptureStubsRequested() bool {
	return r.GroupsFunc != "" || r.NamedGroupsFunc != ""
}

// GroupsExportName returns the WASM export name for the groups function.
// GroupsFunc takes priority; falls back to NamedGroupsFunc.
func (r RegexEntry) GroupsExportName() string {
	if r.GroupsFunc != "" {
		return r.GroupsFunc
	}
	return r.NamedGroupsFunc
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
	cfg.Output = resolveFilePath(configDir, cfg.Output)
	cfg.WasmFile = resolveFilePath(configDir, cfg.WasmFile)
	cfg.StubFile = resolveFilePath(configDir, cfg.StubFile)
	cfg.WasmMerge = resolveFilePath(configDir, cfg.WasmMerge)

	return cfg, nil
}

// resolveFilePath resolves path relative to base unless path is empty or absolute.
func resolveFilePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) || strings.HasPrefix(path, "~/") {
		return path
	}
	return filepath.Join(base, path)
}
