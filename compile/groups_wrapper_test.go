package compile

import (
	"os"
	"os/exec"
	"testing"

	"github.com/qrdl/regexped/config"
)

// A groups export whose capture group can never participate — `(?:(a){0})` —
// gets NO capture body, so there is nothing for the exported
// (ptr, len, out_ptr, from) wrapper to call. Emitting one anyway produced a
// call to function index -1, which wasm-tools rejects as "function index out
// of bounds".
//
// Found by `make groupsonly` on the RE2 corpus, at case 3931250 — the only
// configuration that compiles capture patterns with groups_func alone. Kept
// because the guard it checks is easy to drop again: three places (funcCount,
// the layout, the export/code sections) all have to agree that the wrapper is
// absent, and disagreeing produces a module that only fails at load.
// The guard is not optional politeness. Without it, `exec.Command` fails with
// "executable file not found in $PATH", CombinedOutput returns EMPTY, and every
// case reports `INVALID: ` with nothing after the colon — a module the compiler
// never got wrong, condemned by a missing validator. That is exactly how this
// read in GitHub Actions, where wasm-tools is not preinstalled: ten identical
// failures including plain `(a)`. The same guard is in compile_test.go and
// tools/fuzz/set_sparse_caps_test.go, and this was the one place in compile/
// that shelled out without it.
func TestGroupsWrapperValidWithoutCaptureBody(t *testing.T) {
	if _, err := exec.LookPath("wasm-tools"); err != nil {
		t.Skip("wasm-tools not in PATH: cannot validate the emitted modules")
	}
	for _, pat := range []string{`(?:(a){0})`, `(a){0}`, `(a)`, `\A(a)(b)`, `\b(?P<x>a)`} {
		for _, entry := range []config.RegexEntry{
			{Pattern: pat, GroupsFunc: "groups"},
			{Pattern: pat, GroupsFunc: "groups"},
		} {
			w, _, err := Compile([]config.RegexEntry{entry}, 65536, true)
			if err != nil {
				t.Logf("%-12q compile err=%v", pat, err)
				continue
			}
			f := t.TempDir() + "/m.wasm"
			if err := writeFile(f, w); err != nil {
				t.Fatal(err)
			}
			out, vErr := exec.Command("wasm-tools", "validate", "--features", "all", f).CombinedOutput()
			if vErr != nil {
				// vErr as well as out: a validation failure puts its
				// diagnostic in out, but a failure to RUN the validator
				// leaves out empty and says everything in vErr. Reporting
				// only out is what made the CI failure unreadable.
				t.Errorf("%-12q INVALID: %v\n%s", pat, vErr, out)
			}
		}
	}
}

func writeFile(p string, b []byte) error {
	return os.WriteFile(p, b, 0644)
}
