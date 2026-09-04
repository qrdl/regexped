package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── The two arms every stub writer shares ──────────────────────────────────
//
// Each of the six generators ends the same way: build the content, return
// early if there is none, then write it either to a file or to stdout. Both
// early arms were unreached.
//
// "No content" is not a hypothetical. An entry with a pattern but no `_func`
// fields is explicitly VALID — the compiler skips it silently and emits no
// WASM for it — so a config made entirely of such entries must produce no stub
// rather than an empty file. A file with only a header would look to the next
// build like a stub whose functions had all vanished.

// noFuncCfg is a config whose entries are valid but contribute nothing: a
// pattern with no capability requested.
func noFuncCfg(stubFile string) config.BuildConfig {
	return config.BuildConfig{
		ImportModule: "demo",
		StubFile:     stubFile,
		Regexps: []config.RegexEntry{
			{Name: "a", Pattern: `[a-z]+`},
			{Name: "b", Pattern: `[0-9]+`},
		},
	}
}

// FOUR of the six generators guard against this and write no file at all:
// rust (`allInner == ""`), go (`singleBody == "" && setBody == ""`), c
// (`hContent == ""`) and as (`content == ""`).
//
// JS and TS carry NO such guard and write a zero-byte file instead. That is an
// inconsistency rather than a decision — an empty .js that a build imports
// fails later with "module has no exports", which is the diagnosis the other
// four generators' guards exist to avoid — but changing it changes CLI
// behaviour, so this test records what each one does today and names the
// difference rather than papering over it.
func TestStubWritersProduceNothingWithoutCapabilities(t *testing.T) {
	cases := []struct {
		stubType  string
		wantsFile bool // true = writes a (zero-byte) file rather than skipping
	}{
		{"rust", false},
		{"go", false},
		{"c", false},
		{"as", false},
		{"js", true}, // no empty guard — see the comment above
		{"ts", true},
	}
	for _, tc := range cases {
		t.Run(tc.stubType, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "stub.out")
			cfg := noFuncCfg(out)
			cfg.StubType = tc.stubType
			if err := CmdGenerateStub(cfg, out); err != nil {
				t.Fatalf("CmdGenerateStub: %v", err)
			}
			b, err := os.ReadFile(out)
			switch {
			case tc.wantsFile:
				if os.IsNotExist(err) {
					t.Skipf("%s now skips the write too — the guard was added; "+
						"update this table", tc.stubType)
				}
				if err != nil {
					t.Fatalf("stat: %v", err)
				}
				if len(b) != 0 {
					t.Errorf("wrote %d bytes for a config with no capabilities:\n%s",
						len(b), b)
				}
			default:
				if err == nil {
					t.Errorf("%s wrote a %d-byte stub where it should have "+
						"written nothing", tc.stubType, len(b))
				} else if !os.IsNotExist(err) {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestStubWritersToStdout covers the `-` path, which the CLI uses for
// `regexped generate -o -` and which writes through a different call than the
// file path does.
func TestStubWritersToStdout(t *testing.T) {
	cfg := func(stubType string) config.BuildConfig {
		return config.BuildConfig{
			ImportModule: "demo",
			StubFile:     "stub." + stubType,
			StubType:     stubType,
			Regexps: []config.RegexEntry{
				{Name: "p", Pattern: `[a-z]+`, MatchFunc: "p_match", FindFunc: "p_find"},
			},
		}
	}
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := CmdGenerateStub(cfg(stubType), "-"); err != nil {
					t.Fatalf("CmdGenerateStub(-): %v", err)
				}
			})
			if strings.TrimSpace(out) == "" {
				t.Fatal("stdout path produced nothing")
			}
			// Whatever the language, the generated text must name the export
			// it was asked for — that is the one thing all six share.
			if !strings.Contains(out, "p_match") && !strings.Contains(out, "p_find") {
				t.Errorf("stdout output names neither export:\n%s", out)
			}
		})
	}
}

// captureStdout redirects os.Stdout for the duration of fn. The stub writers
// print rather than taking a writer, so this is the only way to reach that arm.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}

// TestCmdGenerateStubUnknownType covers the dispatcher's default arm.
//
// config.ResolveStubType is what normally rejects an unknown type, so this arm
// is only reachable if the two ever disagree — which is exactly when a silent
// fallthrough would be worst, because the CLI would report success and write
// nothing at all.
func TestCmdGenerateStubUnknownType(t *testing.T) {
	cfg := config.BuildConfig{
		ImportModule: "demo",
		StubFile:     filepath.Join(t.TempDir(), "stub.xyz"),
		Regexps: []config.RegexEntry{
			{Name: "p", Pattern: `[a-z]+`, MatchFunc: "p_match"},
		},
	}
	err := CmdGenerateStub(cfg, cfg.StubFile)
	if err == nil {
		t.Fatal("an unresolvable stub type reported success")
	}
	if !strings.Contains(err.Error(), "xyz") && !strings.Contains(err.Error(), "stub type") {
		t.Errorf("error %q names neither the extension nor the problem", err)
	}
}
