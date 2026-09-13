package generate

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// The overlapping answer cache as the GENERATED stubs size and drive it.
//
// Every stub spells the sizing arithmetic in its own language, and the sweep
// validates what it is handed: a stride one apart from config's is a malformed
// header, so a language that rounds differently does not merely allocate oddly,
// its overlapping find stops working. TestGeneratedJSSizingMatchesConfig pins the
// JS spelling; the tests below pin the other four, and then RUN the cache path
// of the JS and C stubs against a real compiled module, which nothing else does.

// ovSizingCfg is literal-less and overlapping, so the set reaches the fallback
// bucket and the cache is emitted.
func ovSizingCfg() config.BuildConfig {
	return config.BuildConfig{
		Output:       "merged.wasm",
		ImportModule: "demo",
		Regexps: []config.RegexEntry{
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "alnum", Pattern: `[a-z0-9]+x?`},
			{Name: "word", Pattern: `\w+`},
		},
		Sets: []config.SetConfig{{
			Name: "ov", Find: "scan_ov",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
		}},
	}
}

// sizingLengths are the input lengths worth checking: the small end, the
// single-block crossover in both directions, large inputs including the largest
// an i32 length can carry, and 300 random ones.
func sizingLengths(cells, pats int) []int {
	var lens []int
	for n := 0; n <= 64; n++ {
		lens = append(lens, n)
	}
	row := config.SetOverlapBlockRowBytes(pats)
	for m := 1; ; m++ {
		if config.SetOverlapCheckpointHeaderBytes+(cells*4+4)+4+m*row > config.SetOverlapCacheMaxBytes {
			for d := -10; d <= 10; d++ {
				lens = append(lens, m-1+d)
			}
			break
		}
	}
	lens = append(lens, 1e6, 1e7, 1<<31-1)
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 300; i++ {
		lens = append(lens, rng.Intn(20_000_000))
	}
	return lens
}

// sizingSnippet lifts the generated sizing lines out of a stub: from the line
// holding `from` through the first later line that starts with `to`.
func sizingSnippet(t *testing.T, src, from, to string) string {
	t.Helper()
	i := strings.Index(src, from)
	if i < 0 {
		t.Fatalf("the generated stub has no sizing line %q", from)
	}
	start := strings.LastIndex(src[:i], "\n") + 1
	rest := src[i:]
	k := -1
	for off := 0; off < len(rest); {
		nl := strings.IndexByte(rest[off:], '\n')
		if nl < 0 {
			break
		}
		line := strings.TrimSpace(rest[off : off+nl])
		if off > 0 && strings.HasPrefix(line, to) {
			k = off + nl + 1
			break
		}
		off += nl + 1
	}
	if k < 0 {
		t.Fatalf("the generated sizing starting at %q has no %q line", from, to)
	}
	return src[start : i+k]
}

// checkSizingOutput compares one line of "stride,bytes" per length with config.
func checkSizingOutput(t *testing.T, out []byte, lens []int, cells, pats int) {
	t.Helper()
	got := strings.Fields(string(out))
	if len(got) != len(lens) {
		t.Fatalf("the probe printed %d lines for %d lengths:\n%s", len(got), len(lens), out)
	}
	for i, n := range lens {
		want := fmt.Sprintf("%d,%d", config.SetOverlapCheckpointStride(n, cells, pats),
			config.SetOverlapCheckpointBytes(n, cells, pats))
		if got[i] != want {
			t.Fatalf("len=%d: the generated arithmetic computes %s, config computes %s", n, got[i], want)
		}
	}
}

func joinInts(lens []int) string {
	s := make([]string, len(lens))
	for i, n := range lens {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// TestGeneratedSizingMatchesConfig runs the Rust, Go, AssemblyScript and C
// spellings of the sizing arithmetic, each lifted verbatim out of its generated
// stub, with only the input length substituted.
func TestGeneratedSizingMatchesConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs four probes; skipped in -short")
	}
	cfg := ovSizingCfg()
	sh := overlapCacheShapeFor(cfg.Sets[0], cfg)
	if !sh.Eligible {
		t.Fatalf("the fixture set is not cache-eligible: %+v", sh)
	}
	cells, pats := sh.Cells, sh.Patterns
	lens := sizingLengths(cells, pats)
	gen := func(t *testing.T, write func(config.BuildConfig, string) error, file string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, file)
		c := cfg
		c.StubFile = file
		if err := write(c, path); err != nil {
			t.Fatalf("generate: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return dir, string(raw)
	}
	need := func(t *testing.T, tools ...string) {
		t.Helper()
		for _, tool := range tools {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s not on PATH; this spelling is unchecked here", tool)
			}
		}
	}

	t.Run("rust", func(t *testing.T) {
		need(t, "rustc")
		dir, src := gen(t, rustStub, "stubs.rs")
		snip := sizingSnippet(t, src, "let m = (input.len() + 1) as u64;", "let bytes = ")
		snip = strings.ReplaceAll(snip, "input.len()", "len")
		prog := "fn size(len: usize) -> (u64, u64) {\n" + snip + "    (k, bytes)\n}\n" +
			"fn main() {\n    for &len in [" + joinInts(lens) + "usize].iter() {\n" +
			"        let (k, b) = size(len);\n        println!(\"{},{}\", k, b);\n    }\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "size.rs"), []byte(prog), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, dir, nil, "rustc", "--edition=2021", "-O", "-o", "size", "size.rs")
		out, err := exec.Command(filepath.Join(dir, "size")).Output()
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		checkSizingOutput(t, out, lens, cells, pats)
	})

	// Go runs as the stub does, on wasip1 under wasmtime.
	t.Run("go", func(t *testing.T) {
		need(t, "go", "wasmtime")
		dir, src := gen(t, goStub, "stubs.go")
		snip := sizingSnippet(t, src, "m := uint64(len(iter.input)) + 1", "nb := (m + k - 1) / k")
		snip = strings.ReplaceAll(snip, "len(iter.input)", "L")
		mm := regexp.MustCompile(`if n := (.+); n <= \d+ \{`).FindStringSubmatch(src)
		if mm == nil {
			t.Fatal("the generated Go stub has no region-size expression")
		}
		prog := "//go:build wasip1\n\npackage main\n\nimport (\n\t\"fmt\"\n\t\"math\"\n)\n\n" +
			"func size(L int) (uint64, uint64) {\n" + snip + "\treturn k, " + mm[1] + "\n}\n\n" +
			"func main() {\n\tfor _, L := range []int{" + joinInts(lens) + "} {\n" +
			"\t\tk, b := size(L)\n\t\tfmt.Printf(\"%d,%d\\n\", k, b)\n\t}\n}\n"
		for name, body := range map[string]string{"main.go": prog, "go.mod": "module sizeprobe\n\ngo 1.23\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Remove(filepath.Join(dir, "stubs.go")); err != nil {
			t.Fatal(err)
		}
		run(t, dir, []string{"GOOS=wasip1", "GOARCH=wasm", "GOFLAGS=-mod=mod"}, "go", "build", "-o", "size.wasm", ".")
		cmd := exec.Command("wasmtime", "size.wasm")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("wasmtime: %v", err)
		}
		checkSizingOutput(t, out, lens, cells, pats)
	})

	t.Run("as", func(t *testing.T) {
		need(t, "asc", "node")
		dir, src := gen(t, asStub, "stubs.ts")
		snip := sizingSnippet(t, src, "const m: u64 = <u64>input.byteLength + 1;", "const bytes: u64 = ")
		snip = strings.ReplaceAll(snip, "input.byteLength", "len")
		prog := "export function sizeK(len: i32): u64 {\n" + snip + "    return k;\n}\n" +
			"export function sizeBytes(len: i32): u64 {\n" + snip + "    return bytes;\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "size.ts"), []byte(prog), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "stubs.ts")); err != nil {
			t.Fatal(err)
		}
		run(t, dir, nil, "asc", "size.ts", "--outFile", "size.wasm", "--runtime", "stub")
		driver := "import { readFileSync } from 'node:fs';\n" +
			"const { instance } = await WebAssembly.instantiate(readFileSync('./size.wasm'), { env: { abort() { throw new Error('abort'); } } });\n" +
			"const out = [];\nfor (const n of [" + joinInts(lens) + "]) out.push(`${instance.exports.sizeK(n)},${instance.exports.sizeBytes(n)}`);\n" +
			"console.log(out.join('\\n'));\n"
		if err := os.WriteFile(filepath.Join(dir, "drive.mjs"), []byte(driver), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("node", "drive.mjs")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		checkSizingOutput(t, out, lens, cells, pats)
	})

	t.Run("c", func(t *testing.T) {
		need(t, "cc")
		dir, hdr := gen(t, cStub, "stubs.h")
		body, err := os.ReadFile(filepath.Join(dir, "stubs.c"))
		if err != nil {
			t.Fatal(err)
		}
		src := hdr + string(body)
		snip := sizingSnippet(t, src, "unsigned long long m = (unsigned long long)len + 1;", "unsigned long long bytes = ")
		def := regexp.MustCompile(`(?m)^#define rx_sqrt_\(x\).*$`).FindString(src)
		if def == "" {
			t.Fatal("the generated C stub has no rx_sqrt_ definition")
		}
		prog := "#include <stdio.h>\n#include <stddef.h>\n" + def + "\n" +
			"static void size(size_t len, unsigned long long *ko, unsigned long long *bo) {\n" + snip +
			"    *ko = k; *bo = bytes;\n}\n" +
			"static const size_t LENS[] = {" + joinInts(lens) + "};\n" +
			"int main(void) {\n    for (size_t i = 0; i < sizeof LENS / sizeof LENS[0]; i++) {\n" +
			"        unsigned long long k, b;\n        size(LENS[i], &k, &b);\n" +
			"        printf(\"%llu,%llu\\n\", k, b);\n    }\n    return 0;\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "size.c"), []byte(prog), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, dir, nil, "cc", "-O2", "-o", "size", "size.c", "-lm")
		out, err := exec.Command(filepath.Join(dir, "size")).Output()
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		checkSizingOutput(t, out, lens, cells, pats)
	})
}

// overlapOracle counts the tuples an overlapping drive reports: at every start
// position, one per pattern with a match starting exactly there. The fixture
// patterns have no left-context assertion, so an anchored match on the suffix
// is the whole answer.
func overlapOracle(t *testing.T, cfg config.BuildConfig, input string) int {
	t.Helper()
	var res []*regexp.Regexp
	for _, r := range cfg.Regexps {
		res = append(res, regexp.MustCompile(`^(?:`+r.Pattern+`)`))
	}
	n := 0
	for s := 0; s <= len(input); s++ {
		for _, re := range res {
			if loc := re.FindStringIndex(input[s:]); loc != nil && loc[1] > 0 {
				n++
			}
		}
	}
	return n
}

// cacheDriveInput is long enough that the drive's work engages the sweep, with
// runs short enough that the Go oracle stays linear.
func cacheDriveInput() string { return strings.Repeat(strings.Repeat("a", 50)+" ", 2000) }

// TestJSStubDrivesTheAnswerCache RUNS the JS stub's plain overlapping find over a
// real compiled module and requires both the right answer and a cache that the
// engine actually built — the header's `ready` word is read back through the
// scratch descriptor the stub handed the export.
func TestJSStubDrivesTheAnswerCache(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node; skipped in -short")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH; the JS cache path is not driven here")
	}
	cfg := ovSizingCfg()
	cfg.Output = ""
	wasm, _, err := compile.CompileFile(cfg, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "re.wasm"), wasm, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := jsStub(cfg, filepath.Join(dir, "stubs.js")); err != nil {
		t.Fatalf("generate: %v", err)
	}
	writeESMPackageJSON(t, dir)
	input := cacheDriveInput()
	driver := `import { readFileSync } from 'node:fs';
const instantiate = WebAssembly.instantiate;
let scratch = -1, mem = null;
WebAssembly.instantiate = async (w, imp) => {
    const r = await instantiate(w, imp);
    const ex = r.instance.exports;
    mem = ex.memory;
    const wrapped = { ...ex, scan_ov: (...a) => { scratch = a[3]; return ex.scan_ov(...a); } };
    return { instance: { exports: wrapped } };
};
const { init, scan_ov } = await import('./stubs.js');
await init(readFileSync('./re.wasm'));
let n = 0;
for (const m of scan_ov(('a'.repeat(50) + ' ').repeat(2000))) n++;
const d = new Uint32Array(mem.buffer, scratch, 4);
const ready = d[2] ? new Int32Array(mem.buffer, d[2] + 8, 1)[0] : 'none';
console.log(n + ',' + d[2] + ',' + ready);
`
	if err := os.WriteFile(filepath.Join(dir, "drive.mjs"), []byte(driver), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "drive.mjs")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	f := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(f) != 3 {
		t.Fatalf("unexpected driver output %q", out)
	}
	if want := strconv.Itoa(overlapOracle(t, cfg, input)); f[0] != want {
		t.Errorf("the JS stub reported %s tuples, Go reports %s", f[0], want)
	}
	if f[1] == "0" {
		t.Error("the stub handed the export no cache")
	}
	if f[2] != "1" {
		t.Errorf("the cache header's ready word is %s after the drive, want 1: the sweep never served it", f[2])
	}
}

// TestJSStubSurvivesAFailedGrow: a region whose cache does not fit under the
// module's memory maximum must not take the instance down with it. The bump
// pointer used to advance BEFORE the grow, so a grow that threw left it past the
// end of memory with no live iterator to reset it, and every later call threw —
// here, a ten-byte match on a module that had room to spare for it.
func TestJSStubSurvivesAFailedGrow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node; skipped in -short")
	}
	for _, tool := range []string{"node", "wasm-tools"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; this check is a no-op here", tool)
		}
	}
	cfg := ovSizingCfg()
	cfg.Sets[0].MatchAny = "which_secret"
	dir := t.TempDir()
	if err := jsStub(cfg, filepath.Join(dir, "stubs.js")); err != nil {
		t.Fatalf("generate: %v", err)
	}
	writeESMPackageJSON(t, dir)
	// A stand-in with a 20-page ceiling: 100 KB of input fits, its answer cache
	// does not.
	wat := `(module
  (memory (export "memory") 2 20)
  (func (export "scan_ov") (param i32 i32 i32 i32 i32 i32) (result i32)
    i32.const -1)
  (func (export "which_secret") (param i32 i32) (result i32)
    i32.const -1))
`
	if err := os.WriteFile(filepath.Join(dir, "fake.wat"), []byte(wat), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("wasm-tools", "parse", filepath.Join(dir, "fake.wat"), "-o",
		filepath.Join(dir, "fake.wasm")).CombinedOutput(); err != nil {
		t.Fatalf("wasm-tools parse: %v\n%s", err, out)
	}
	driver := `import { readFileSync } from 'node:fs';
import { init, scan_ov, which_secret } from './stubs.js';
await init(readFileSync('./fake.wasm'));
try {
    let n = 0;
    for (const m of scan_ov('a'.repeat(100000))) n++;
    console.log('scan: walked, ' + n);
} catch (e) {
    console.log('scan: threw ' + e.name);
}
try {
    which_secret('0123456789');
    console.log('ONESHOT-OK');
} catch (e) {
    console.log('ONESHOT-THREW ' + e.name + ': ' + e.message);
}
`
	if err := os.WriteFile(filepath.Join(dir, "drive.mjs"), []byte(driver), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "drive.mjs")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	t.Logf("%s", out)
	if !strings.Contains(string(out), "ONESHOT-OK") {
		t.Fatalf("a failed grow for one iterator's cache bricked the instance:\n%s", out)
	}
}

// wasmMergeForTest finds wasm-merge on PATH, else the copy get_wasm_merge.sh
// leaves in the repository root.
func wasmMergeForTest(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("wasm-merge"); err == nil {
		return p
	}
	p, err := filepath.Abs(filepath.Join("..", "wasm-merge"))
	if err != nil {
		return ""
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return ""
	}
	t.Logf("wasm-merge: %s (the repository root's copy; not on PATH)", p)
	return p
}

// TestCStubDrivesTheAnswerCache RUNS the MODULE-format C stub's cache path: the
// stub compiled for wasm32 with the cache forced on over a four-line <stdlib.h>
// shim, a guest supplying malloc/free over a static arena, merged with the
// compiled regexp module by `regexped merge`, and driven under wasmtime. The
// answer must match Go's and the header's `ready` word must be 1.
func TestCStubDrivesTheAnswerCache(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a merged module; skipped in -short")
	}
	clang := wasiClang(t)
	if clang == "" {
		t.Skip("no clang that targets wasm32-wasi: the C cache path is not driven here")
	}
	for _, tool := range []string{"go", "wasmtime"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH: the C cache path is not driven here", tool)
		}
	}
	merge := wasmMergeForTest(t)
	if merge == "" {
		t.Skip("wasm-merge not found: the C cache path is not driven here")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "regexped")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/qrdl/regexped").CombinedOutput(); err != nil {
		t.Fatalf("build regexped: %v\n%s", err, out)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("regexped.yaml", `import_module: demo
wasm_file: re.wasm
output: merged.wasm
stub_file: stubs.h
wasm_merge_path: '`+merge+`'
regexps:
  - name: lower
    pattern: '[a-z]+'
  - name: alnum
    pattern: '[a-z0-9]+x?'
  - name: word
    pattern: '\w+'
sets:
  - name: ov
    patterns: all
    find: scan_ov
    overlapping: true
`)
	write("inc/stdlib.h", "#pragma once\n#include <stddef.h>\nvoid *malloc(size_t);\nvoid free(void *);\n")
	write("guest.c", cCacheGuest)
	run(t, dir, nil, bin, "compile", "--config=regexped.yaml")
	run(t, dir, nil, bin, "generate", "--config=regexped.yaml")
	run(t, dir, nil, clang, "--target=wasm32-wasi", "-nostdlib", "-Wl,--no-entry",
		"-DRX_SET_CACHE=1", "-isystem", "inc", "-o", "guest.wasm", "guest.c", "stubs.c")
	run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=guest.wasm", "re.wasm")

	invoke := func(export string) string {
		t.Helper()
		// stdout only: wasmtime warns on stderr that --invoke with a result is
		// experimental.
		cmd := exec.Command("wasmtime", "run", "--invoke", export, "merged.wasm")
		cmd.Dir = dir
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("wasmtime %s: %v\n%s%s", export, err, out, stderr.String())
		}
		return strings.TrimSpace(string(out))
	}
	if got, want := invoke("run"), strconv.Itoa(overlapOracle(t, ovSizingCfg(), cacheDriveInput())); got != want {
		t.Errorf("the C stub reported %s tuples, Go reports %s", got, want)
	}
	if got := invoke("ready"); got != "1" {
		t.Errorf("the cache header's ready word is %s after the drive, want 1 (4294967294 = no cache allocated)", got)
	}
}

// cCacheGuest drives the overlapping set over the same input cacheDriveInput
// builds, and reports the tuple count or the header's ready word.
const cCacheGuest = `#include "stubs.h"

static unsigned char arena[8 << 20];
static size_t used;
void *malloc(size_t n) {
    size_t at = (used + 7) & ~(size_t)7;
    if (at + n > sizeof arena) return 0;
    used = at + n;
    return arena + at;
}
void free(void *p) { (void)p; }

#define RUN 50
#define UNITS 2000
static char input[(RUN + 1) * UNITS];
/* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
static rx_ov_scanner_t sc;
static unsigned ready_word = 0xFFFFFFFFu;

static int drive(void) {
    for (size_t i = 0; i < sizeof input; i++) input[i] = (i % (RUN + 1)) == RUN ? ' ' : 'a';
    used = 0;
    if (scan_ov_init(&sc, input, sizeof input, 0) != 0) return -100;
    rx_set_match_t buf[OV_PATTERN_COUNT];
    int total = 0, got;
    while ((got = scan_ov(&sc, buf, OV_PATTERN_COUNT)) > 0) total += got;
    ready_word = sc.cache ? sc.cache[2] : 0xFFFFFFFEu;
    scan_ov_free(&sc);
    return got < 0 ? got : total;
}

__attribute__((export_name("run")))
int run(void) { return drive(); }

__attribute__((export_name("ready")))
unsigned ready(void) { drive(); return ready_word; }
`
