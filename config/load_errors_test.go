package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LoadConfig's REFUSALS.
//
// This is the CLI's front door, and every one of these errors is the last
// chance to tell a user something useful. A config that loads and then
// produces a stub which will not compile — a reserved word as a function name,
// a hint the compiler does not know, a set naming a pattern that is not there
// — costs far more to diagnose downstream than at the point of reading the
// file.

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "regexped.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"unparseable YAML",
			"regexps: [oh dear\n",
			"",
		},
		{
			"a reserved word as a function name",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: match\n",
			"",
		},
		{
			"a function name that is not an identifier",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: 'my func'\n",
			"",
		},
		{
			"a set naming a pattern that does not exist",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find: f\n    patterns: [nope]\n",
			"",
		},
		{
			"a set with no patterns key",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find: f\n",
			"patterns",
		},
		{
			"an unknown hint",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\n    match_func: m\n    hints: [go-faster]\n",
			"",
		},
		{
			"two sets exporting the same name",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n" +
				"  - name: s1\n    find: dup\n    patterns: all\n" +
				"  - name: s2\n    find: dup\n    patterns: all\n",
			"",
		},
		{
			"a retired key: named_groups_func",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: '(a)'\n    named_groups_func: g\n",
			"",
		},
		{
			"a retired key: find_batch",
			"stub_file: s.rs\nregexps:\n  - name: p\n    pattern: 'a'\nsets:\n  - name: s\n    find_batch: fb\n    patterns: all\n",
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := func() error {
				_, err := LoadConfig(writeConfig(t, c.body))
				return err
			}()
			if err == nil {
				t.Fatal("accepted a config that should have been refused")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestLoadConfigMissingFile: the path the CLI hands over may simply not exist.
func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("accepted a config path that does not exist")
	}
}

// TestLoadConfigAccepts is the other half: a config exercising the keys the
// refusals above are about must load cleanly, or the checks are simply
// rejecting everything.
func TestLoadConfigAccepts(t *testing.T) {
	path := writeConfig(t, `
wasm_file: out.wasm
stub_file: stubs.rs
import_module: demo
max_dfa_states: 2048
max_tdfa_regs: 48
max_fallback_states: 512
regexps:
  - name: url
    pattern: '(?P<scheme>https?)://(?P<host>[a-z.]+)'
    match_func: url_match
    find_func: url_find
    groups_func: url_groups
    hints: [prefer-match]
  - name: num
    pattern: '[0-9]+'
sets:
  - name: secrets
    match_any: which_secret
    match_all: all_kinds
    scan_any: first_secret
    scan_all: kinds
    find: scan_secrets
    overlapping: true
    hints: [batch-find]
    patterns: all
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	if len(cfg.Regexps) != 2 || len(cfg.Sets) != 1 {
		t.Fatalf("loaded %d regexps and %d sets, want 2 and 1", len(cfg.Regexps), len(cfg.Sets))
	}
	if cfg.MaxDFAStates != 2048 || cfg.MaxTDFARegs != 48 || cfg.MaxFallbackStates != 512 {
		t.Errorf("the numeric limits did not survive loading: %+v", cfg)
	}
	if !cfg.Sets[0].Overlapping || !cfg.Sets[0].BatchFind() {
		t.Error("overlapping / batch-find did not survive loading")
	}
	if !cfg.Sets[0].Patterns.All {
		t.Error("`patterns: all` did not survive loading")
	}
}

// TestPatternSelectorForms covers the selector's two YAML shapes — the scalar
// "all" and a list of names — through the unmarshaller rather than by
// constructing the struct, since the unmarshaller is what a user's file meets.
func TestPatternSelectorForms(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
stub_file: s.rs
regexps:
  - name: a
    pattern: 'a'
  - name: b
    pattern: 'b'
sets:
  - name: s1
    find: f1
    patterns: all
  - name: s2
    find: f2
    patterns: [a]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Sets[0].Patterns.All {
		t.Error("`patterns: all` did not parse as the All form")
	}
	if cfg.Sets[1].Patterns.All || len(cfg.Sets[1].Patterns.Names) != 1 {
		t.Errorf("a name list parsed as %+v", cfg.Sets[1].Patterns)
	}
}
