package generate

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// EVERY generated stub reserves an answer cache for a cache-eligible
// overlapping set, and it does NOT depend on the batching hint.
//
// The cache is read by the plain `find` exactly as it is by the batch entry —
// an overlapping set whose shape qualifies emits the sweep whether or not it
// batches, and `find` becomes a wrapper so the cache can be read before the
// walk. The JS and TS generators built the cache only under `hints:
// [batch-find]` and wrote a descriptor saying "no cache" otherwise, so a
// caller iterating an overlapping set in either language got the quadratic
// walk — against a documented promise that every stub reserves one.
//
// Checked on the GENERATED TEXT rather than by running it, because what went
// wrong was a whole block not being emitted; the runtime behaviour of the
// block that is emitted is covered by the wasm drives in tools/fuzz.
func TestPlainFindReservesTheAnswerCache(t *testing.T) {
	// Literal-less, so the set reaches the fallback bucket and the sweep is
	// emitted. A set of literals compiles no cache code at all.
	eligible := config.BuildConfig{
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
	// The same set with literals: not eligible, so no cache anywhere.
	ineligible := eligible
	ineligible.Regexps = []config.RegexEntry{
		{Name: "aws", Pattern: `AKIA[A-Z0-9]{16}`},
		{Name: "gh", Pattern: `ghp_[0-9a-zA-Z]{36}`},
	}

	for _, lang := range []struct {
		name string
		gen  func(config.BuildConfig) (string, error)
		// The sizing prelude, and the descriptor field that carries the cache.
		prelude, pointer string
	}{
		{"js", genJSStubFile, "const cacheBytes =", "cacheBase, cacheBytes"},
		{"ts", genTSStubFile, "const cacheBytes =", "cacheBase, cacheBytes"},
	} {
		t.Run(lang.name, func(t *testing.T) {
			src, err := lang.gen(eligible)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if !strings.Contains(src, lang.prelude) {
				t.Errorf("a cache-eligible overlapping set with NO batch hint generated no "+
					"cache sizing (%q absent): its find is quadratic", lang.prelude)
			}
			if !strings.Contains(src, lang.pointer) {
				t.Errorf("the descriptor does not carry the cache (%q absent)", lang.pointer)
			}

			src, err = lang.gen(ineligible)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if strings.Contains(src, lang.prelude) {
				t.Error("a set the sweep cannot serve reserved a cache anyway")
			}
		})
	}
}

// The batching shape keeps its cache too: hoisting the block out of that
// branch must not have emptied it.
func TestBatchFindKeepsTheAnswerCache(t *testing.T) {
	cfg := config.BuildConfig{
		Output:       "merged.wasm",
		ImportModule: "demo",
		Regexps: []config.RegexEntry{
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "word", Pattern: `\w+`},
		},
		Sets: []config.SetConfig{{
			Name: "ov", Find: "scan_ov",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
			Hints: []string{"batch-find"},
		}},
	}
	for _, gen := range []func(config.BuildConfig) (string, error){genJSStubFile, genTSStubFile} {
		src, err := gen(cfg)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.Contains(src, "const cacheBytes =") || !strings.Contains(src, "cacheBase, cacheBytes") {
			t.Error("the batching find lost its answer cache")
		}
	}
}

// The GENERATED sizing arithmetic, evaluated by node and compared with config's
// across the interesting lengths.
//
// Six languages spell this formula, and the sweep validates what they computed:
// a stride that does not match the region is reported as a malformed header, so
// a language that rounds differently does not merely allocate oddly — its
// overlapping find stops working. The crossover is where that is most likely,
// because on one side the stride is the whole span and on the other it is a
// square root, and `Math.floor(Math.sqrt(x))` and Go's `int(math.Sqrt(x))` have
// to agree on the boundary.
//
// The generated TEXT is what runs, not a transcription of it: the prelude is
// lifted out of the stub and evaluated as written, with only `_inCap(input)`
// replaced by the length under test.
func TestGeneratedJSSizingMatchesConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node; skipped in -short")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH; this check is a no-op here")
	}
	const cells, pats = 7, 3
	cfg := config.BuildConfig{
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
	sh := overlapCacheShapeFor(cfg.Sets[0], cfg)
	if !sh.Eligible || sh.Cells != cells || sh.Patterns != pats {
		t.Fatalf("the fixture shape moved: %+v", sh)
	}
	src, err := genJSStubFile(cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	const first = "    const _m = _inCap(input) + 1;\n"
	const last = " ? cacheNeeded : 0;\n"
	i := strings.Index(src, first)
	j := strings.Index(src[i:], last)
	if i < 0 || j < 0 {
		t.Fatal("the generated stub has no cache sizing prelude to check")
	}
	prelude := src[i+len(first) : i+j+len(last)]

	// The lengths that matter: the small end, the crossover in both
	// directions, two large inputs, and 200 random ones.
	lens := []int{}
	for n := 0; n <= 64; n++ {
		lens = append(lens, n)
	}
	row := config.SetOverlapBlockRowBytes(pats)
	cross := 0
	for m := 1; ; m++ {
		if config.SetOverlapCheckpointHeaderBytes+(cells*4+4)+4+m*row > config.SetOverlapCacheMaxBytes {
			cross = m - 1
			break
		}
	}
	for d := -10; d <= 10; d++ {
		lens = append(lens, cross+d)
	}
	lens = append(lens, 1e6, 1e7)
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		lens = append(lens, rng.Intn(20_000_000))
	}

	var js strings.Builder
	js.WriteString("function size(_len) {\n    const _m = _len + 1;\n")
	js.WriteString(prelude)
	js.WriteString("    return _k + ',' + cacheBytes;\n}\nconst out = [];\n")
	for _, n := range lens {
		fmt.Fprintf(&js, "out.push(size(%d));\n", n)
	}
	js.WriteString("console.log(out.join('\\n'));\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "size.js")
	if err := os.WriteFile(path, []byte(js.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("node", path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(got) != len(lens) {
		t.Fatalf("node produced %d lines for %d lengths", len(got), len(lens))
	}
	for i, n := range lens {
		k := config.SetOverlapCheckpointStride(n, cells, pats)
		bytes := config.SetOverlapCheckpointBytes(n, cells, pats)
		if bytes > config.SetOverlapCacheMaxBytes {
			bytes = 0 // over budget: the stub declines and reserves nothing
		}
		if want := fmt.Sprintf("%d,%d", k, bytes); got[i] != want {
			t.Fatalf("len=%d: the generated JS computes %s, config computes %s",
				n, got[i], want)
		}
	}
}

// -4 reaches the CALLER, in each language's own way.
//
// Every stub folded it into "n <= 0 means the scan is over": the drive stopped
// and said it had finished, when what it had was no idea. That is the silent
// degradation internal/abi forbids, and the only reason it went unnoticed is
// that no generated stub can provoke it — the descriptor comes from the same
// arithmetic that sized the region. A hand-written caller, or one region shared
// between two scanners, can.
//
// The JS arm RUNS it: a stand-in module whose find export returns -4, handed to
// the generated init, so the generator's own control flow decides what happens.
// The Go arm is a compile check — the sentinel error has to exist and be
// distinct from the backtracking one — since driving it would need the same
// stand-in through a different toolchain.
func TestMalformedCacheReachesTheCaller(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node; skipped in -short")
	}
	for _, tool := range []string{"node", "wasm-tools"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; this check is a no-op here", tool)
		}
	}
	cfg := config.BuildConfig{
		Output:       "merged.wasm",
		ImportModule: "demo",
		Regexps: []config.RegexEntry{
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "word", Pattern: `\w+`},
		},
		Sets: []config.SetConfig{{
			Name: "ov", Find: "scan_ov",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
		}},
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "stubs.js")
	if err := jsStub(cfg, stub); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// The stand-in: one memory, and a find that answers -4 whatever it is
	// asked. The signature is the raw ABI's — (ptr, len, from, scratch, out,
	// cap) -> i32 — so a change to it fails here rather than silently passing.
	wat := `(module
  (memory (export "memory") 2)
  (func (export "scan_ov") (param i32 i32 i32 i32 i32 i32) (result i32)
    i32.const -4))
`
	watPath := filepath.Join(dir, "fake.wat")
	if err := os.WriteFile(watPath, []byte(wat), 0o644); err != nil {
		t.Fatal(err)
	}
	wasmPath := filepath.Join(dir, "fake.wasm")
	if out, err := exec.Command("wasm-tools", "parse", watPath, "-o", wasmPath).CombinedOutput(); err != nil {
		t.Fatalf("wasm-tools parse: %v\n%s", err, out)
	}

	driver := `import { readFileSync } from 'node:fs';
import { init, scan_ov } from './stubs.js';
await init(readFileSync('./fake.wasm'));
try {
    for (const m of scan_ov("abc")) { }
    console.log("NO-THROW");
} catch (e) {
    console.log("THREW: " + e.message);
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
	got := strings.TrimSpace(string(out))
	if !strings.HasPrefix(got, "THREW: ") {
		t.Fatalf("the generated JS reported -4 as a finished scan: %q", got)
	}
	if !strings.Contains(got, "malformed") {
		t.Fatalf("it threw, but not about the cache: %q", got)
	}
	// And NOT the backtracking message, which is the confusion the two
	// sentinels exist to avoid.
	if strings.Contains(got, "backtracking") {
		t.Fatalf("-4 was reported as a backtracking overflow: %q", got)
	}
}

// The Go stub declares a DISTINCT sentinel for it, beside the backtracking one.
func TestGoStubDeclaresMalformedCacheError(t *testing.T) {
	cfg := config.BuildConfig{
		Output:       "merged.wasm",
		ImportModule: "demo",
		Regexps: []config.RegexEntry{
			{Name: "lower", Pattern: `[a-z]+`},
			{Name: "word", Pattern: `\w+`},
		},
		Sets: []config.SetConfig{{
			Name: "ov", Find: "scan_ov",
			Patterns: config.PatternSelector{All: true}, Overlapping: true,
		}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "stubs.go")
	if err := goStub(cfg, path); err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"var ErrMalformedCache = errors.New(",
		"iter.err = ErrMalformedCache",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the generated Go stub is missing %q", want)
		}
	}
}
