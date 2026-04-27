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
	StubFile     string       `yaml:"stub_file"`      // stub output file (Rust, Go, JS, TS, AS, or C)
	StubType     string       `yaml:"stub_type"`      // stub type: "rust", "go", "js", "ts", "c", "as"; inferred from stub_file extension if absent
	MaxDFAStates int          `yaml:"max_dfa_states"` // 0 = default (1024)
	MaxTDFARegs  int          `yaml:"max_tdfa_regs"`  // 0 = default (32)
	Regexes      []RegexEntry `yaml:"regexes"`
	Sets         []SetConfig  `yaml:"sets"` // optional set composition entries
}

// SetConfig describes one `sets:` entry in the YAML config.
type SetConfig struct {
	Name        string          `yaml:"name"`          // set name; must be unique within the file
	FindAny     string          `yaml:"find_any"`      // export name for find_any (non-anchored, first match)
	FindAll     string          `yaml:"find_all"`      // export name for find_all (non-anchored, all matches)
	Match       string          `yaml:"match"`         // export name for match (anchored at position 0)
	BatchSize   int             `yaml:"batch_size"`    // output buffer hint (default 256); stub-gen only
	Patterns    PatternSelector `yaml:"patterns"`      // which regexes belong to this set
	EmitNameMap bool            `yaml:"emit_name_map"` // include pattern name→ID map in WASM data
}

// PatternSelector selects patterns for a set. It can be the scalar string "all"
// or a list of pattern names.
type PatternSelector struct {
	All   bool     // true when the YAML value was the scalar "all"
	Names []string // pattern names when All is false
}

// UnmarshalYAML implements yaml.Unmarshaler for PatternSelector.
// Accepts either the scalar string "all" or a sequence of strings.
func (p *PatternSelector) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode && value.Value == "all" {
		p.All = true
		return nil
	}
	if value.Kind == yaml.SequenceNode {
		var names []string
		if err := value.Decode(&names); err != nil {
			return err
		}
		p.Names = names
		return nil
	}
	return fmt.Errorf("patterns: expected \"all\" or a list of pattern names, got %s", value.Value)
}

// ValidateSets validates the `sets:` block against the `regexes:` list.
// Returns an error if any name is not unique, any pattern reference is unknown,
// or a set entry has neither find_any nor find_all set.
func ValidateSets(cfg *BuildConfig) error {
	// Build name → index map.
	nameIdx := make(map[string]int, len(cfg.Regexes))
	for i, re := range cfg.Regexes {
		if re.Name != "" {
			if _, dup := nameIdx[re.Name]; dup {
				return fmt.Errorf("duplicate regex name %q", re.Name)
			}
			nameIdx[re.Name] = i
		}
	}

	setNames := make(map[string]bool)
	for _, s := range cfg.Sets {
		if s.Name == "" {
			return fmt.Errorf("sets entry missing required name field")
		}
		if setNames[s.Name] {
			return fmt.Errorf("duplicate set name %q", s.Name)
		}
		setNames[s.Name] = true
		if s.FindAny == "" && s.FindAll == "" && s.Match == "" {
			return fmt.Errorf("set %q: at least one of find_any, find_all, or match must be set", s.Name)
		}
		if !s.Patterns.All {
			for _, pname := range s.Patterns.Names {
				if _, ok := nameIdx[pname]; !ok {
					return fmt.Errorf("set %q: unknown pattern name %q", s.Name, pname)
				}
			}
		}
	}
	return nil
}

// RegexEntry describes a single regex pattern and the functions to generate for it.
// One or more of the Func fields must be set; only those stubs are generated.
// The WASM export names are derived automatically from the function type.
type RegexEntry struct {
	Name    string `yaml:"name"` // optional; used by sets: for pattern selection
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
