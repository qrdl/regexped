package generate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCComponentSetWrappersEndToEnd DRIVES the generated C component set
// wrappers rather than reading their text: a real guest built with the header's
// own recipe, wrapped, composed with the regexp component by `regexped merge`,
// and run under wasmtime.
//
// Every other test of the C component stub compiles it for the HOST or checks
// its source. That is how three defects survived: `_all` and the scanner leaked
// every returned list from the guest's bump heap, the scanner silently discarded
// what did not fit a small buffer while the shared header promised a
// transactional overflow, and re-initialising a live scanner orphaned its
// resource. Each export of the guest below exercises one of them and returns 0
// on success, or the number of the check that failed.
func TestCComponentSetWrappersEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a composed component; skipped in -short")
	}
	clang := wasiClang(t)
	if clang == "" {
		t.Skip("no clang that targets wasm32-wasi: the C component wrappers are not driven here")
	}
	for _, tool := range []string{"go", "wasm-tools", "wac", "wasmtime"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH: the C component wrappers are not driven here", tool)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "regexped")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/qrdl/regexped").CombinedOutput(); err != nil {
		t.Fatalf("build regexped: %v\n%s", err, out)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("regexped.yaml", e2eConfig)
	run(t, dir, nil, bin, "compile", "--config=regexped.yaml")
	run(t, dir, nil, bin, "generate", "--config=regexped.yaml")

	// The generated consumer world imports the interfaces and exports nothing; a
	// component with no exports can be composed but not run.
	consumer, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
	if err != nil {
		t.Fatalf("generate wrote no consumer world: %v", err)
	}
	cw := string(consumer)
	end := strings.LastIndex(cw, "}")
	if end < 0 {
		t.Fatalf("unexpected consumer world:\n%s", cw)
	}
	exports := "    export sanity: func() -> s32;\n    export lists: func() -> s32;\n" +
		"    export small-buffer: func() -> s32;\n    export reinit: func() -> s32;\n"
	write(filepath.Join("wit", "consumer.wit"), cw[:end]+exports+cw[end:])
	write("main.c", e2eGuest)

	run(t, dir, nil, clang, "--target=wasm32-wasi", "-nostdlib", "-Wl,--no-entry",
		"-DRX_SET_CACHE=0", "-DREGEXPED_CABI_HEAP_BYTES=4096",
		"-o", "core.wasm", "main.c", "stub.c")
	run(t, dir, nil, "wasm-tools", "component", "embed", "wit", "core.wasm",
		"--world", "e2e-consumer", "-o", "embedded.wasm")
	run(t, dir, nil, "wasm-tools", "component", "new", "embedded.wasm", "-o", "guest.wasm")
	run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=guest.wasm", "e2e.wasm")

	for _, c := range []struct {
		name, export string
		flags        []string
	}{
		{"sanity", "sanity", nil},
		// 5,000 `_all` calls and a long scan at a 4 KB guest heap: any list the
		// wrappers do not release exhausts it within a few hundred calls.
		{"lists are released", "lists", nil},
		{"a buffer below PATTERN_COUNT is refused", "small-buffer", nil},
		// Each leaked resource holds an input block, gates and a cache inside the
		// regexp component, which grows its memory to hold them. Capped at 64 MiB
		// a leaking build traps well inside 10,000 iterations; a correct one
		// reuses the same blocks every time.
		{"re-init drops the live handle", "reinit",
			[]string{"-W", "max-memory-size=67108864", "-W", "trap-on-grow-failure=y"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"run"}, c.flags...)
			args = append(args, "--invoke", c.export+"()", "composed.wasm")
			cmd := exec.Command("wasmtime", args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("wasmtime %s: %v\n%s", strings.Join(args, " "), err, out)
			}
			if got := strings.TrimSpace(string(out)); got != "0" {
				t.Fatalf("%s() returned %s, want 0 (the number is the failing check)", c.export, got)
			}
		})
	}
}

// e2eConfig is one pattern plus one set with all five capabilities, overlapping
// and cache-eligible: literal-less patterns in one bucket.
const e2eConfig = `wasm_format: component
wit_package: e2e
import_module: e2e
wasm_file: e2e.wasm
output: composed.wasm
stub_file: stub.h
regexps:
  - name: word
    pattern: '[a-z]+'
    match_func: word_match
  - name: digits
    pattern: '[0-9]+'
  - name: upper
    pattern: '[A-Z]+'
sets:
  - name: runs
    patterns: all
    match_any: runs_match_any
    match_all: runs_match_all
    scan_any: runs_scan_any
    scan_all: runs_scan_all
    find: scan_runs
    overlapping: true
`

// e2eGuest is the consumer. No libc: every result comes back as an int.
const e2eGuest = `#include "stub.h"

static const char SHORT[] = "ab12CD ab12CD ab12CD";
#define SHORT_LEN (sizeof SHORT - 1)
#define BIG 65536
static char big[BIG];

static void fill(void) {
    static const char unit[] = "ab12CD ";
    for (int i = 0; i < BIG; i++) big[i] = unit[i % 7];
}

__attribute__((export_name("sanity")))
int sanity(void) {
    int ids[RUNS_PATTERN_COUNT];
    if (word_match("abc", 3) != 3) return 1;
    if (runs_scan_all(SHORT, SHORT_LEN, 0, ids) != 3) return 2;
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    if (scan_runs_init(&s, SHORT, SHORT_LEN, 0) != 0) return 3;
    int total = 0, n;
    while ((n = scan_runs(&s, buf, RUNS_PATTERN_COUNT)) > 0) total += n;
    scan_runs_free(&s);
    if (n < 0) return 4;
    if (total == 0) return 5;
    return 0;
}

__attribute__((export_name("lists")))
int lists(void) {
    int ids[RUNS_PATTERN_COUNT];
    for (int i = 0; i < 5000; i++) {
        if (runs_scan_all(SHORT, SHORT_LEN, 0, ids) != 3) return 1;
        if (runs_match_all("abc", 3, ids) != 1) return 2;
    }
    fill();
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    if (scan_runs_init(&s, big, 16384, 0) != 0) return 3;
    int positions = 0, n;
    while ((n = scan_runs(&s, buf, RUNS_PATTERN_COUNT)) > 0) positions++;
    scan_runs_free(&s);
    if (n < 0) return 4;
    if (positions < 1000) return 5;
    return 0;
}

__attribute__((export_name("small-buffer")))
int small_buffer(void) {
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    unsigned char *raw = (unsigned char *)buf;
    for (unsigned i = 0; i < sizeof buf; i++) raw[i] = 0x5A;
    if (scan_runs_init(&s, SHORT, SHORT_LEN, 0) != 0) return 1;
    if (scan_runs(&s, buf, RUNS_PATTERN_COUNT - 1) != RX_ERR_RANGE) return 2;
    for (unsigned i = 0; i < sizeof buf; i++) if (raw[i] != 0x5A) return 3;
    if (scan_runs(&s, buf, RUNS_PATTERN_COUNT) <= 0) return 4;
    if (buf[0].start != 0) return 5; /* the refused call did not advance */
    scan_runs_free(&s);
    return 0;
}

__attribute__((export_name("reinit")))
int reinit(void) {
    fill();
    /* static: zeroed without a memset call, which a -nostdlib guest cannot link. */
    static rx_runs_scanner_t s;
    rx_set_match_t buf[RUNS_PATTERN_COUNT];
    for (int i = 0; i < 10000; i++) {
        if (scan_runs_init(&s, big, BIG, 0) != 0) return 1;
        if (scan_runs_init(&s, big, BIG, 0) != 0) return 2;
        if (scan_runs(&s, buf, RUNS_PATTERN_COUNT) <= 0) return 3;
        scan_runs_free(&s);
    }
    return 0;
}
`
