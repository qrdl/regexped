package compile

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/qrdl/regexped/config"
)

// The byte-identical regression net (plans/SETS.md §9.0).
//
// Every fixture under testdata/byteident/ is one SINGLE-PATTERN code path,
// compiled and compared against a checked-in `expected.wasm` byte for byte.
// There is no tolerance: the claim these fixtures exist to defend is byte
// identity, so any difference at all is a failure.
//
// # Why byte identity rather than a behaviour test
//
// The set redesign shares emitters with the single-pattern path. D6 of
// plans/SETS.md says single-pattern behaviour is out of scope and must not
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
					"Single-pattern output is supposed to be byte-identical (plans/SETS.md D6). If the\n"+
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
			eng, err := SelectEngine(re.Pattern, CompileOptions{})
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
