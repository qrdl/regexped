package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// TODO 58 / SETS_PLAN item 4 gave every live JS/TS call its own input and
// scratch region. iterator_isolation_test.go pins the SHAPE of that fix in the
// generated source — `_open`/`_close` pairs, no module-level staging address,
// `_att` guards, no hoisted views.
//
// This file pins the BEHAVIOUR, which no source assertion can reach.
//
// The bug it guards against produced no exception and no obviously-broken
// output. A generator staged its input, yielded, and while it was suspended
// another call wrote a different string over the same address; the generator
// resumed and kept scanning across those other bytes, reporting offsets
// against them. The only way to see that is to actually suspend one iterator,
// run another, resume the first, and compare — so that is what this does, in
// node, against the real WASM.
//
// A structural test would pass on any reimplementation with the right shape
// and the wrong semantics. This one would not, which is the whole point of
// having both.
//
// THREE FAILURE MODES, deliberately separated:
//
//	regions   two live iterators must not share memory (the original bug)
//	grow      memory.grow() detaches EVERY view in the module, whoever owns
//	          the region it points at, and a detached view has length 0 and
//	          reads as undefined SILENTLY rather than throwing — so a
//	          suspended iterator must re-attach. Driven by making the
//	          interleaved call large enough to force a grow.
//	abandon   an iterator dropped before exhaustion must still release its
//	          region through its `finally`, or the bump pointer never resets
//	          and later calls drift onto live memory.
//
// Node is already a soft dependency of this package (TestGeneratedStubsCompile
// runs `node --check`); this executes rather than parses, and skips the same
// way when node is absent.

// isolationPatterns are chosen so a leak is LOUD. `[a-z]+` and `[0-9]+`
// partition their inputs, so a scan that strays onto the other iterator's
// bytes reports matches that cannot exist in its own string rather than a
// subtly shifted span.
func isolationConfig(batch bool) config.BuildConfig {
	set := config.SetConfig{
		Name:     "s",
		Find:     "setFind",
		Patterns: config.PatternSelector{All: true},
	}
	if batch {
		set.Hints = []string{"batch-find"}
	}
	return config.BuildConfig{
		Regexps: []config.RegexEntry{
			{Name: "words", Pattern: `[a-z]+`, FindFunc: "findWords"},
			{Name: "nums", Pattern: `[0-9]+`, FindFunc: "findNums"},
			{Name: "pairs", Pattern: `(?P<letter>[a-z])(?P<digit>[0-9])`, GroupsFunc: "findPairs"},
		},
		Sets:     []config.SetConfig{set},
		StubFile: "stubs.js",
	}
}

func TestJSIteratorIsolationAtRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node against a compiled module; skipped in -short")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	for _, batch := range []bool{false, true} {
		name := "set-find"
		if batch {
			name = "set-find-batch"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := isolationConfig(batch)

			wasm, _, err := compile.CompileFile(cfg, "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "m.wasm"), wasm, 0o644); err != nil {
				t.Fatal(err)
			}
			src, err := genJSStubFile(cfg)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			// The generated module loads its WASM through init(bytes), so the
			// `output` path baked into it is never read here.
			if err := os.WriteFile(filepath.Join(dir, "stubs.js"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "drive.mjs"), []byte(isolationDriver), 0o644); err != nil {
				t.Fatal(err)
			}
			// The stub is an ES module; say so rather than letting node's
			// version-dependent default decide. See writeESMPackageJSON.
			writeESMPackageJSON(t, dir)

			cmd := exec.Command("node", "drive.mjs")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("node reported an isolation failure:\n%s", out)
			}
			// A driver that skipped its own checks would "pass" silently, so
			// the count of executed checks is part of the contract.
			got := strings.TrimSpace(string(out))
			if !strings.HasPrefix(got, "OK ") {
				t.Fatalf("driver did not report success:\n%s", out)
			}
			var checks int
			if _, err := fmt.Sscanf(got, "OK %d", &checks); err != nil || checks < 12 {
				t.Fatalf("driver ran too few checks (%q): a vacuous pass", got)
			}
		})
	}
}

// isolationDriver is the node side. It is deliberately dependency-free and
// exits non-zero with a message on the first disagreement.
const isolationDriver = `import { readFile } from 'node:fs/promises';
import * as stubs from './stubs.js';
await stubs.init(await readFile(new URL('./m.wasm', import.meta.url)));

let checks = 0;
function eq(actual, expected, what) {
    checks++;
    const a = JSON.stringify(actual), b = JSON.stringify(expected);
    if (a !== b) {
        console.error("FAIL " + what + "\n  got  " + a + "\n  want " + b);
        process.exit(1);
    }
}

// Inputs that PARTITION: a scan that strays onto the other iterator's bytes
// reports matches impossible in its own string.
const words = "alpha beta gamma delta epsilon zeta eta theta";
const nums  = "11 222 3333 44444 555555 6666666 77777777";
// Large enough to push the bump allocator past the current memory size while
// another iterator is suspended, which is what forces memory.grow() and
// detaches every view in the module.
const bigWords = ("lorem ipsum dolor sit amet ").repeat(4096);

const alone = f => [...f];

// ---- 1. regions: interleaved iterators must not see each other ----------
{
    const wordsAlone = alone(stubs.findWords(words));
    const numsAlone  = alone(stubs.findNums(nums));

    const a = stubs.findWords(words);
    const first = a.next();                       // A is now SUSPENDED
    eq(first.done, false, "A yielded nothing to suspend on");

    const bAll = alone(stubs.findNums(nums));     // B runs to completion
    eq(bAll, numsAlone, "B interleaved != B alone");

    const aRest = [first.value, ...a];            // A resumes
    eq(aRest, wordsAlone, "A across an interleaved B != A alone");
    eq(alone(stubs.findNums(nums)), numsAlone, "B after the interleave");
}

// ---- 2. grow: a suspended iterator survives memory.grow() ---------------
{
    const wordsAlone = alone(stubs.findWords(words));
    const a = stubs.findWords(words);
    const first = a.next();
    eq(first.done, false, "A yielded nothing before the grow");
    // Big enough that reserving its region grows memory; every typed-array
    // view in the module is detached at that moment, A's included.
    const big = alone(stubs.findWords(bigWords));
    eq(big.length > 1000, true, "the growing scan found too little to have grown");
    eq([first.value, ...a], wordsAlone, "A across a memory.grow()");
}

// ---- 3. abandon: dropping an iterator early still releases its region ---
{
    const wordsAlone = alone(stubs.findWords(words));
    for (let round = 0; round < 3; round++) {
        for (const _m of stubs.findWords(words)) break;   // abandoned mid-scan
    }
    eq(alone(stubs.findWords(words)), wordsAlone, "scan after abandoned iterators");
    // Two abandoned iterators live at once, then a full one on top.
    const x = stubs.findWords(words), y = stubs.findNums(nums);
    x.next(); y.next();
    eq(alone(stubs.findWords(words)), wordsAlone, "scan under two suspended iterators");
    x.return(); y.return();
    eq(alone(stubs.findWords(words)), wordsAlone, "scan after releasing them");
}

// ---- 4. the other generator shapes: groups, and the set find ------------
{
    const src = "a1 b2 c3 d4 e5";
    const pairsAlone = alone(stubs.findPairs(src));
    eq(pairsAlone.length > 0, true, "groups iterator found nothing to interleave");

    const g = stubs.findPairs(src);
    const gFirst = g.next();
    eq(gFirst.done, false, "groups iterator yielded nothing to suspend on");
    eq(alone(stubs.findWords(words)), alone(stubs.findWords(words)), "find under a suspended groups");
    eq([gFirst.value, ...g], pairsAlone, "groups across an interleaved find");

    const setAlone = alone(stubs.setFind(words));
    eq(setAlone.length > 0, true, "set find found nothing to interleave");
    const s = stubs.setFind(words);
    const sFirst = s.next();
    eq(sFirst.done, false, "set find yielded nothing to suspend on");
    eq(alone(stubs.findNums(nums)), alone(stubs.findNums(nums)), "find under a suspended set find");
    eq(alone(stubs.findWords(bigWords)).length > 1000, true, "grow under a suspended set find");
    eq([sFirst.value, ...s], setAlone, "set find across an interleaved find and a grow");
}

console.log("OK " + checks);
`
