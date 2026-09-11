package merge

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/component"
	"github.com/qrdl/regexped/config"
)

// The SOCKET: a consumer component importing TWO regexped interfaces and
// exporting one function that calls both. Hand-written because the point is to
// test composition, not a language toolchain — clang and rustc would drag their
// own wasip2 requirements into a unit test.
//
// The import module string is the canonical interface name
// `regexped:<wit_package>/matcher`, which is what a generated stub emits too.
// A `match` import lowers to `(ptr, len, retptr)` with a 12-byte result area:
// [0] outer result discriminant, [4] option discriminant, [8] the end position
// (§5.4 of the plan, and compile/component.go).
const socketWAT = `(module
  (import "regexped:pkg-a/matcher" "match-a" (func $match_a (param i32 i32 i32)))
  (import "regexped:pkg-b/matcher" "match-b" (func $match_b (param i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 4096))

  (func (export "cabi_realloc") (param $old i32) (param $oldsz i32) (param $align i32) (param $newsz i32) (result i32)
    (local $p i32)
    (local.set $p (i32.and
      (i32.sub (i32.add (global.get $bump) (local.get $align)) (i32.const 1))
      (i32.sub (i32.const 0) (local.get $align))))
    (global.set $bump (i32.add (local.get $p) (local.get $newsz)))
    (local.get $p))

  (func $endOf (param $ret i32) (result i32)
    (if (result i32) (i32.load (local.get $ret))
      (then (i32.const 0))
      (else (if (result i32) (i32.load offset=4 (local.get $ret))
              (then (i32.load offset=8 (local.get $ret)))
              (else (i32.const 0))))))

  (func (export "run") (param $ptr i32) (param $len i32) (result i32)
    (call $match_a (local.get $ptr) (local.get $len) (i32.const 256))
    (call $match_b (local.get $ptr) (local.get $len) (i32.const 512))
    (i32.add
      (i32.mul (call $endOf (i32.const 256)) (i32.const 100))
      (call $endOf (i32.const 512))))
)`

const socketWIT = `package test:socket;

world app {
    import regexped:pkg-a/matcher;
    import regexped:pkg-b/matcher;
    export run: func(input: list<u8>) -> u32;
}
`

// TestMultiPlugComposition is the symmetry gate for `regexped merge`: ONE
// invocation must compose SEVERAL regexp components into a consumer, the way
// one invocation merges several regexp modules.
//
// It also pins the asymmetry recorded on composeComponents. The two configs
// carry DISTINCT wit_package values on purpose — components are matched by
// their WIT interface name, which the socket genuinely imports, so two plugs
// exporting `regexped:same-name/matcher` would be ambiguous where two modules
// sharing an import_module are not.
//
// Skips unless wac, wasm-tools and wasmtime are all installed: this is an
// integration gate, not something to mock.
func TestMultiPlugComposition(t *testing.T) {
	for _, tool := range []string{"wac", "wasm-tools", "wasmtime"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()

	// Two regexp components, different interfaces, different patterns.
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	aCfgPath := write("a.yaml", `wasm_file:   "a.wasm"
wasm_format: component
wit_package: "pkg-a"
import_module: "pkga"
regexps:
  - pattern: '[0-9]+'
    match_func: match_a
`)
	bCfgPath := write("b.yaml", `wasm_file:   "b.wasm"
wasm_format: component
wit_package: "pkg-b"
import_module: "pkgb"
regexps:
  - pattern: '[a-z]+'
    match_func: match_b
`)
	for _, cfgPath := range []string{aCfgPath, bCfgPath} {
		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("load %s: %v", cfgPath, err)
		}
		if err := component.CmdCompile(cfg, cfg.WasmFile, nil); err != nil {
			t.Fatalf("compile %s: %v", cfgPath, err)
		}
	}

	// The socket. `component embed` resolves imported packages from a wit
	// DIRECTORY's deps/, so the two generated .wit files are placed there.
	witDir := filepath.Join(dir, "wit")
	if err := os.MkdirAll(filepath.Join(witDir, "deps"), 0o755); err != nil {
		t.Fatalf("mkdir wit: %v", err)
	}
	for _, pkg := range []string{"a", "b"} {
		src, err := os.ReadFile(filepath.Join(dir, pkg+".wit"))
		if err != nil {
			t.Fatalf("read generated wit: %v", err)
		}
		if err := os.WriteFile(filepath.Join(witDir, "deps", pkg+".wit"), src, 0o644); err != nil {
			t.Fatalf("write dep wit: %v", err)
		}
	}
	write("wit/socket.wit", socketWIT)
	write("socket.wat", socketWAT)

	run := func(name string, args ...string) string {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	run("wasm-tools", "parse", "socket.wat", "-o", "socket.core.wasm")
	run("wasm-tools", "component", "embed", "wit", "socket.core.wasm", "--world", "app", "-o", "socket.embed.wasm")
	run("wasm-tools", "component", "new", "socket.embed.wasm", "-o", "socket.wasm")

	// THE GATE: one merge call, two plugs.
	mergeCfgPath := write("merge.yaml", `output:      "final.wasm"
wasm_format: component
wit_package: "pkg-a"
regexps:
  - pattern: '[0-9]+'
    match_func: match_a
`)
	mergeCfg, err := config.LoadConfig(mergeCfgPath)
	if err != nil {
		t.Fatalf("load merge config: %v", err)
	}
	if err := CmdMerge(mergeCfg, filepath.Join(dir, "socket.wasm"), mergeCfg.Output,
		[]string{filepath.Join(dir, "a.wasm"), filepath.Join(dir, "b.wasm")}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	run("wasm-tools", "validate", "final.wasm")

	// BOTH imports must be gone: a composition that satisfied only the first
	// plug still validates, and would still run until the second is called.
	if wit := run("wasm-tools", "component", "wit", "final.wasm"); strings.Contains(wit, "import regexped:") {
		t.Fatalf("composed component still has an unsatisfied regexped import:\n%s", wit)
	}

	// Answers, not just linkage: "123" matches pkg-a only (3*100), "abcd"
	// matches pkg-b only (4).
	for _, c := range []struct{ invoke, want string }{
		{"run([49,50,51])", "300"},
		{"run([97,98,99,100])", "4"},
	} {
		got := strings.TrimSpace(run("wasmtime", "run", "--invoke", c.invoke, "final.wasm"))
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.invoke, got, c.want)
		}
	}
}
