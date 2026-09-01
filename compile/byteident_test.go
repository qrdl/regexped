package compile

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/config"
)

// The byte-identical regression net.
//
// Every fixture under testdata/byteident/ is one SINGLE-PATTERN code path,
// compiled and compared against a checked-in `expected.wasm` byte for byte.
// There is no tolerance: the claim these fixtures exist to defend is byte
// identity, so any difference at all is a failure.
//
// # Why byte identity rather than a behaviour test
//
// The set redesign shares emitters with the single-pattern path. D6 of
// Single-pattern behaviour is out of scope for set work and must not
// change, and the only evidence strong enough for "must not change" is that
// the emitted bytes are the same — a behavioural test proves the cases it
// tries, and a shared-emitter regression is exactly the kind that hides in the
// cases nobody tried.
//
// One fixture per path matters as much as the comparison: a change to a shared
// emitter cannot hide in a path no fixture exercises. Each fixture's YAML
// comment records which path it is for, and TestByteIdenticalPathsAreDistinct
// checks the set actually spreads across engines rather than all landing on
// the same one.
//
// # Regenerating
//
//	go test ./compile -run TestByteIdentical -update-byteident
//
// Regenerate ONLY when a change to the single-pattern path is intended, and
// review the resulting diff — that is the whole point of the fixtures.
var updateByteIdent = flag.Bool("update-byteident", false,
	"regenerate compile/testdata/byteident/*/expected.wasm")

func byteIdentFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "byteident"))
	if err != nil {
		t.Fatalf("read byteident dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no byteident fixtures found")
	}
	return names
}

func loadByteIdentConfig(t *testing.T, name string) config.BuildConfig {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "byteident", name, "patterns.yaml"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var cfg config.BuildConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("%s: parse: %v", name, err)
	}
	return cfg
}

func TestByteIdentical(t *testing.T) {
	for _, name := range byteIdentFixtures(t) {
		t.Run(name, func(t *testing.T) {
			cfg := loadByteIdentConfig(t, name)
			// Standalone (cfg.Output empty) so the module is self-contained
			// and the comparison needs no merge step.
			got, _, err := CompileFile(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			path := filepath.Join("testdata", "byteident", name, "expected.wasm")
			if *updateByteIdent {
				if err := os.WriteFile(path, got, 0644); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
				t.Logf("regenerated %s (%d bytes)", path, len(got))
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s (run with -update-byteident to create it): %v", path, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("emitted WASM differs from the checked-in fixture: got %d bytes, want %d.\n"+
					"Single-pattern output is supposed to be byte-identical. If the\n"+
					"change is intended, rerun with -update-byteident and review the diff.",
					len(got), len(want))
			}
			validateWASM(t, got)
		})
	}
}

// TestByteIdenticalPathsAreDistinct confirms the fixtures actually spread
// across the engines they claim to. A fixture set that silently collapsed onto
// one engine would still pass TestByteIdentical while defending nothing.
func TestByteIdenticalPathsAreDistinct(t *testing.T) {
	seen := map[EngineType]int{}
	for _, name := range byteIdentFixtures(t) {
		cfg := loadByteIdentConfig(t, name)
		for _, re := range cfg.Regexps {
			// The entry's own mode has to be passed: a byte_mode fixture names
			// runes the default mode rejects, so asking the selector about it
			// neutrally is asking about a pattern that does not compile.
			eng, err := SelectEngine(re.Pattern, CompileOptions{ByteMode: re.ByteMode})
			if err != nil {
				t.Fatalf("%s: SelectEngine: %v", name, err)
			}
			seen[eng]++
			t.Logf("%-16s %-24s %v", name, re.Pattern, eng)
		}
	}
	for _, want := range []EngineType{EngineDFA, EngineCompiledDFA, EngineTDFA, EngineBacktrack} {
		if seen[want] == 0 {
			t.Errorf("no byteident fixture reaches engine %v", want)
		}
	}
}

// TestByteIdenticalSetShapesAreDistinct is the set-side twin of
// TestByteIdenticalPathsAreDistinct.
//
// Until these fixtures existed there was NO byte-identity pin on set output at
// all: all fifteen original fixtures were single-pattern, so every set change
// was made without the drift check the single-pattern path has had all along.
// TODO 65 names that gap as a hard prerequisite for splitting CompileSet, whose
// failure mode it also describes — reorder two layout blocks and two table
// regions overlap, which is "not a compile error and not a WASM validation
// error, but a module that reads one table through another's bytes".
//
// The spread is checked rather than asserted in a comment: a fixture set that
// silently collapsed onto one frontend would still pass the byte comparison
// while defending nothing.
func TestByteIdenticalSetShapesAreDistinct(t *testing.T) {
	frontends := map[string][]string{}
	acceptKinds := map[string]int{}
	capabilities := map[string]int{}
	for _, name := range byteIdentFixtures(t) {
		if !strings.HasPrefix(name, "set_") {
			continue
		}
		cfg := loadByteIdentConfig(t, name)
		_, _, diags, err := CompileFileDiag(cfg, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(diags) != 1 {
			t.Fatalf("%s: %d set diagnostics, want 1", name, len(diags))
		}
		d := diags[0]
		frontends[d.Frontend] = append(frontends[d.Frontend], name)
		for _, b := range d.Buckets {
			acceptKinds[b.AcceptKind]++
		}
		for _, c := range d.Capabilities {
			capabilities[c]++
		}
		t.Logf("%-18s frontend=%-12s buckets=%-3d caps=%v", name, d.Frontend, len(d.Buckets), d.Capabilities)
	}
	for _, want := range []string{"packed-pair", "teddy", "ac", "scalar"} {
		if len(frontends[want]) == 0 {
			t.Errorf("no set fixture reaches the %q frontend", want)
		}
	}
	// Shufti is deliberately absent: it is selected only when Aho-Corasick
	// declines on budget, which no YAML config can arrange. See
	// tools/fuzz/set_shufti_test.go, which reaches it through CompileFileOpts.
	if acceptKinds["sparse"] == 0 {
		t.Error("no set fixture produces a SPARSE accept bucket — G17's " +
			"per-state pattern lists are unpinned")
	}
	if acceptKinds["bitmask"] == 0 {
		t.Error("no set fixture produces a bitmask accept bucket")
	}
	for _, want := range []string{"match_any", "match_all", "scan_any", "scan_all", "find"} {
		if capabilities[want] == 0 {
			t.Errorf("no set fixture declares the %q capability", want)
		}
	}
}
