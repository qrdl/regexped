package generate

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── When a pattern will not parse ──────────────────────────────────────────
//
// Every generator reads the pattern back to learn its capture groups, so an
// unparseable one fails INSIDE generation rather than at config load. The
// error then has to travel up through three or four frames to the CLI.
//
// Each of those frames returns the error rather than logging it, and none of
// them was covered. That is the wrong arm to leave untested for a code
// generator: a swallowed error means `regexped generate` reports success and
// writes a stub with the broken entry silently missing, and the next build
// fails somewhere else entirely with an unresolved symbol.
//
// The config layer does not reject this — patterns are validated by the
// COMPILER, and a stub can legitimately be generated without compiling — so
// the path is reachable in ordinary use, not just in tests.
func badPatternCfg(stubType, out string) config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "demo",
		StubFile:     out,
		StubType:     stubType,
		Regexps: []config.RegexEntry{
			// A valid entry first, so the failure happens PART WAY through
			// the loop rather than on its first iteration — the shape that
			// would otherwise let a generator emit a partial file.
			{Name: "ok", Pattern: `[a-z]+`, GroupsFunc: "ok_groups"},
			{Name: "bad", Pattern: `([a-z]+`, GroupsFunc: "bad_groups"},
		},
	}
}

func TestStubGeneratorsPropagateParseErrors(t *testing.T) {
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "stub.out")
			err := CmdGenerateStub(badPatternCfg(stubType, out), out)
			if err == nil {
				t.Fatal("an unparseable pattern generated a stub and reported success")
			}
			// The message must be traceable to the pattern. Without that the
			// user is told only that generation failed, on a config that may
			// hold hundreds of entries.
			if !strings.Contains(err.Error(), "missing closing )") &&
				!strings.Contains(err.Error(), "error parsing regexp") {
				t.Errorf("error %q does not explain what failed to parse", err)
			}
		})
	}
}

// TestStubGeneratorsWriteNothingOnParseError is the half that matters most: a
// failed generation must not leave a partial file behind for the next build to
// pick up.
func TestStubGeneratorsWriteNothingOnParseError(t *testing.T) {
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "stub.out")
			if err := CmdGenerateStub(badPatternCfg(stubType, out), out); err == nil {
				t.Fatal("expected an error")
			}
			entries, err := readDirNames(dir)
			if err != nil {
				t.Fatalf("read temp dir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("a failed generation left %v behind", entries)
			}
		})
	}
}

func readDirNames(dir string) ([]string, error) {
	des, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		out = append(out, filepath.Base(d))
	}
	return out, nil
}
