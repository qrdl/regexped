package generate

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// A Backtracking call that gives up on its ordinary body lands in a fallback
// body that sizes its frame stack and memo from the input AT CALL TIME, growing
// linear memory if they do not fit (compile/bt_scratch.go). In a standalone
// module that memory is the JS stub's: the grow happens inside a WASM call the
// stub made, so the stub never sees it — and a grow detaches every view of the
// old buffer, which then reads as undefined without throwing.
//
// This drives that in node, against the real module, three ways:
//
//	answer    a call that grows memory itself still returns Go's answer
//	suspended an iterator suspended across such a call still reads its own
//	          region correctly afterwards
//	scratch   the module's scratch lands ABOVE every live region: an iterator
//	          suspended across repeated growing calls keeps its input intact
//	bounded   the stub keeps the module's scratch-base global current, so
//	          repeated growing calls reuse one scratch region; with the global
//	          left at 0 each would take fresh pages and memory would climb
func TestJSBacktrackFallbackGrowsMemoryAtRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node against a compiled module; skipped in -short")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	const btPattern = `^(\w*|)*c`
	cfg := config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "words", Pattern: `[a-z]+`, FindFunc: "findWords"},
			{Name: "bt", Pattern: btPattern, GroupsFunc: "btGroups"},
		},
		StubFile: "stubs.js",
	}
	if eng, err := compile.SelectEngine(btPattern, compile.CompileOptions{}); err != nil || eng != compile.EngineBacktrack {
		t.Fatalf("%s selects %v (%v), not Backtracking: the test no longer reaches a fallback", btPattern, eng, err)
	}

	// 100 KB of greedy descent is far past the ordinary body's frame stack, so
	// every call here runs the fallback and grows memory for it.
	big := strings.Repeat("w", 100000) + "c"
	loc := regexp.MustCompile(btPattern).FindStringSubmatchIndex(big)
	want := make([]any, len(loc)/2)
	for i := range want {
		if loc[2*i] < 0 {
			want[i] = nil
		} else {
			want[i] = []int{loc[2*i], loc[2*i+1]}
		}
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	wasm, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	src, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Test-only: the stub exposes no handle on memory, and whether the scratch
	// is REUSED — the global doing its job — is only visible in its size.
	src += "export function __memBytes() { return _exp.memory.buffer.byteLength; }\n"
	driver := strings.NewReplacer("__WANT__", string(wantJSON), "__BIGLEN__", fmt.Sprint(len(big))).Replace(btFallbackDriver)
	for name, data := range map[string][]byte{"m.wasm": wasm, "stubs.js": []byte(src), "drive.mjs": []byte(driver)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeESMPackageJSON(t, dir)

	cmd := exec.Command("node", "drive.mjs")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node reported a failure:\n%s", out)
	}
	got := strings.TrimSpace(string(out))
	var checks int
	if _, err := fmt.Sscanf(got, "OK %d", &checks); err != nil || checks < 20 {
		t.Fatalf("driver ran too few checks (%q): a vacuous pass", got)
	}
}

const btFallbackDriver = `import { readFile } from 'node:fs/promises';
import * as stubs from './stubs.js';
await stubs.init(await readFile(new URL('./m.wasm', import.meta.url)));

let checks = 0;
function eq(actual, expected, what) {
    checks++;
    const a = JSON.stringify(actual), b = JSON.stringify(expected);
    if (a !== b) {
        console.error("FAIL " + what + "\n  got  " + a.slice(0, 300) + "\n  want " + b.slice(0, 300));
        process.exit(1);
    }
}

const big = "w".repeat(__BIGLEN__ - 1) + "c";
const want = __WANT__;
const words = "alpha beta gamma delta epsilon zeta eta theta";
const alone = f => [...f];
// The first match of a groups call, with the iterator released.
const first = it => { const r = it.next().value; it.return(); return r; };

// ---- answer: the call that grows memory returns Go's answer --------------
eq([...stubs.btGroups(big)].slice(0, 1), [want], "groups over the growing call");
// And again: the second call reuses the scratch the first one placed.
eq([...stubs.btGroups(big)].slice(0, 1), [want], "groups, second call");

// ---- suspended: an iterator across a call that grows memory --------------
{
    const wordsAlone = alone(stubs.findWords(words));
    const a = stubs.findWords(words);
    const first = a.next();
    eq(first.done, false, "A yielded nothing to suspend on");
    eq([...stubs.btGroups(big)].slice(0, 1), [want], "groups under a suspended find");
    eq([first.value, ...a], wordsAlone, "find across a growing Backtracking call");
}

// ---- scratch: repeated growing calls under a suspended groups iterator ---
{
    const g = stubs.btGroups(big);
    const gFirst = g.next();
    eq(gFirst.value, want, "groups iterator's first match");
    for (let i = 0; i < 3; i++) eq(first(stubs.btGroups(big)), want, "groups " + i + " under a suspended groups");
    // Its input region must still hold its own bytes: the rest of the scan
    // reads them, and a scratch placed over them would change the answer.
    eq([...g], alone((function* () { const it = stubs.btGroups(big); it.next(); yield* it; })()), "groups iterator resumed after the growing calls");
}

// ---- bounded: repeated growing calls reuse the scratch -------------------
{
    for (let i = 0; i < 2; i++) first(stubs.btGroups(big));
    const settled = stubs.__memBytes();
    for (let i = 0; i < 10; i++) eq(first(stubs.btGroups(big)), want, "groups " + i + " after settling");
    eq(stubs.__memBytes(), settled, "memory after 10 more growing calls");
}

console.log("OK " + checks);
`
