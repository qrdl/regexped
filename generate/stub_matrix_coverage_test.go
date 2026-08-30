package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// A matrix over the six stub generators.
//
// The existing tests here are mostly assertions about ONE generator's output
// text for ONE shape. That leaves whole arms unreached: a set with no `find`,
// a set with only anchored capabilities, the wide `_all` form, a config with
// no sets at all, a config with several sets, and the batching entry — each of
// which changes what a generator emits, and several of which change it in ALL
// SIX languages at once.
//
// TestGeneratedStubsCompile hands one config to every real compiler and is the
// stronger check; it is also slow and needs four toolchains. This is the cheap
// companion: many shapes, six generators, checking the generator RUNS and
// produces something with the promised names in it.

type stubShape struct {
	name    string
	selects string
	cfg     config.BuildConfig
	// wantAll are substrings every language's output must contain.
	wantAll []string
}

func entry(name, pattern string, match, find, groups bool) config.RegexEntry {
	e := config.RegexEntry{Name: name, Pattern: pattern}
	if match {
		e.MatchFunc = name + "_match"
	}
	if find {
		e.FindFunc = name + "_find"
	}
	if groups {
		e.GroupsFunc = name + "_groups"
	}
	return e
}

func manyEntries(n int) []config.RegexEntry {
	out := make([]config.RegexEntry, n)
	for i := range out {
		out[i] = config.RegexEntry{
			Name: fmt.Sprintf("p%02d", i), Pattern: fmt.Sprintf("lit%02d[a-z]+", i),
		}
	}
	return out
}

func stubShapes() []stubShape {
	base := []config.RegexEntry{
		entry("url", `(?P<scheme>https?)://(?P<host>[a-z.]+)/`, true, true, true),
		entry("num", `[0-9]+`, true, true, false),
	}
	return []stubShape{
		{
			name: "patterns-only", selects: "a config with NO sets: the single-pattern arms alone",
			cfg:     config.BuildConfig{ImportModule: "demo", Regexps: base},
			wantAll: []string{"url_match", "url_find", "url_groups", "num_match"},
		},
		{
			name: "find-only-set", selects: "a set declaring only `find`",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "scan_all", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"scan_all"},
		},
		{
			name: "anchored-only-set", selects: "a set with only the anchored pair, and hence no find machinery",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", MatchAny: "which", MatchAll: "all_kinds",
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"which", "all_kinds"},
		},
		{
			name: "scan-only-set", selects: "a set with only the scan pair",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", ScanAny: "first_hit", ScanAll: "every_hit",
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"first_hit", "every_hit"},
		},
		{
			name: "overlapping-batch-set", selects: "`overlapping: true` plus `hints: [batch-find]` — the answer-cache shape",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "scan_overlapping",
					Patterns:    config.PatternSelector{All: true},
					Overlapping: true, Hints: []string{"batch-find"},
				}},
			},
			wantAll: []string{"scan_overlapping"},
		},
		{
			name: "wide-all-set", selects: "the WIDE `_all` form: past 64 ids the bitmask becomes a memory bitmap",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: manyEntries(70),
				Sets: []config.SetConfig{{
					Name: "s", MatchAll: "wide_all", ScanAll: "wide_scan_all",
					Find: "wide_find", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"wide_all", "wide_scan_all", "wide_find"},
		},
		{
			name: "named-subset-set", selects: "ID_SPACE > PATTERN_COUNT, which sizes the gate array and the bitmap",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: manyEntries(20),
				Sets: []config.SetConfig{{
					Name: "s", Find: "subset_find", MatchAll: "subset_all",
					Patterns: config.PatternSelector{Names: []string{"p00", "p19"}},
				}},
			},
			wantAll: []string{"subset_find", "subset_all"},
		},
		{
			name: "two-sets", selects: "several sets in one config, whose derived constants must not collide",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{
					{Name: "alpha", Find: "alpha_find", Patterns: config.PatternSelector{All: true}},
					{Name: "beta", MatchAny: "beta_any", Patterns: config.PatternSelector{All: true}},
				},
			},
			wantAll: []string{"alpha_find", "beta_any"},
		},
		{
			name: "name-map", selects: "emit_name_map, which adds the pattern-name helper",
			cfg: config.BuildConfig{
				ImportModule: "demo", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "named_find", EmitNameMap: true,
					Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"named_find"},
		},
		{
			name: "namespace", selects: "the optional namespace, which prefixes symbols with no user name to inherit",
			cfg: config.BuildConfig{
				ImportModule: "demo", Namespace: "rx2", Regexps: base,
				Sets: []config.SetConfig{{
					Name: "s", Find: "ns_find", Patterns: config.PatternSelector{All: true},
				}},
			},
			wantAll: []string{"ns_find"},
		},
	}
}

// stubWriters maps a stub type to the file extension its generator writes,
// so each shape can be rendered by all six.
var stubWriters = []struct {
	kind string
	ext  string
	gen  func(config.BuildConfig, string) error
}{
	{"rust", ".rs", rustStub},
	{"go", ".go", goStub},
	{"js", ".js", jsStub},
	{"ts", ".ts", tsStub},
	{"c", ".h", cStub},
	{"as", ".ts", asStub},
}

// TestStubMatrixGenerates renders every shape with every generator.
//
// It checks the generator RUNS and that the export names it was given appear
// in what it wrote. Whether the result COMPILES is TestGeneratedStubsCompile's
// job, and whether it behaves is the runtime isolation test's — this one is
// about breadth of shape rather than depth of check.
func TestStubMatrixGenerates(t *testing.T) {
	for _, shape := range stubShapes() {
		for _, w := range stubWriters {
			t.Run(shape.name+"/"+w.kind, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), shape.cfg.ImportModule)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(dir, "stubs"+w.ext)
				cfg := shape.cfg
				cfg.StubFile = out
				if err := w.gen(cfg, out); err != nil {
					t.Fatalf("%s (selects %s): %v", w.kind, shape.selects, err)
				}
				src := readIfPresent(t, out)
				if src == "" {
					t.Fatalf("%s: wrote nothing", w.kind)
				}
				for _, want := range shape.wantAll {
					if !strings.Contains(src, want) {
						t.Errorf("%s: output does not mention %q", w.kind, want)
					}
				}
			})
		}
	}
}

func readIfPresent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}
