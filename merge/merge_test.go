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

// TestMain doubles as a mock wasm-merge subprocess. When invoked with
// REGEXPED_MOCK_WASM_MERGE=1, it finds the -o <file> flag, creates that file,
// and exits 0 — mimicking a successful wasm-merge run without the real binary.
func TestMain(m *testing.M) {
	if os.Getenv("REGEXPED_MOCK_WASM_MERGE") == "1" {
		if argvFile := os.Getenv("REGEXPED_MOCK_ARGV"); argvFile != "" {
			_ = os.WriteFile(argvFile, []byte(strings.Join(os.Args[1:], " ")), 0o644)
		}
		args := os.Args
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("mock"), 0o644)
				break
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestModuleNameForWasm(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.BuildConfig
		path string
		want string
	}{
		{"top-level ImportModule", config.BuildConfig{ImportModule: "global"}, "anything.wasm", "global"},
		{"basename fallback", config.BuildConfig{}, "/dir/other.wasm", "other"},
		{"bare filename fallback", config.BuildConfig{}, "tokens.wasm", "tokens"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := moduleNameForWasm(c.cfg, c.path)
			if got != c.want {
				t.Errorf("moduleNameForWasm: got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCmdMerge(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGEXPED_MOCK_WASM_MERGE", "1")

	run := func(t *testing.T, cfg config.BuildConfig) {
		t.Helper()
		dir := t.TempDir()
		mainWasm := filepath.Join(dir, "main.wasm")
		regexWasm := filepath.Join(dir, "regexp.wasm")
		output := filepath.Join(dir, "out.wasm")
		if err := os.WriteFile(mainWasm, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(regexWasm, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CmdMerge(cfg, mainWasm, output, []string{regexWasm}); err != nil {
			t.Fatalf("CmdMerge: %v", err)
		}
		if _, err := os.Stat(output); err != nil {
			t.Errorf("output file not created: %v", err)
		}
	}

	// The test binary is the mock, and it is NOT named wasm-merge: pointing the
	// key at a file uses that file whatever it is called.
	t.Run("binary from config, under another name", func(t *testing.T) {
		run(t, config.BuildConfig{WasmMergePath: exe})
	})
	t.Run("the environment is ignored", func(t *testing.T) {
		t.Setenv("WASM_MERGE", "/garbage/wasm-merge")
		run(t, config.BuildConfig{WasmMergePath: exe})

		t.Setenv("WASM_MERGE", exe)
		t.Setenv("PATH", t.TempDir())
		dir := t.TempDir()
		err := CmdMerge(config.BuildConfig{}, filepath.Join(dir, "main.wasm"),
			filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
		if err == nil || !strings.Contains(err.Error(), "$PATH") {
			t.Errorf("err = %v; with the key omitted only $PATH is consulted, never $WASM_MERGE", err)
		}
	})
}

// The world block is read up to its closing brace; text that never closes it, or
// has no world at all, yields what was seen rather than nothing or a panic.
func TestRegexpedExportsWithoutAClosedWorld(t *testing.T) {
	for _, c := range []struct{ name, wit, want string }{
		{"empty", "", ""},
		{"no world", "package regexped:a;\n\ninterface matcher {\n}\n", ""},
		{"unterminated world", "world root {\n  import wasi:io/streams;\n  export regexped:a/matcher;\n  export regexped:a/sets;\n",
			"regexped:a/matcher,regexped:a/sets"},
	} {
		if got := strings.Join(regexpedExports(c.wit), ","); got != c.want {
			t.Errorf("%s: regexpedExports = %q, want %q", c.name, got, c.want)
		}
	}
}

// CmdMerge's failure paths.
//
// Merging shells out to `wasm-merge`, so the two things that go wrong in
// practice are the tool not being there and the tool failing. Both have to be
// reported as errors: the merged module is what a Rust or Go host links
// against, and a merge that reports success having produced nothing turns into
// a link failure a long way from here.

// TestCmdMergeReportsMissingTool covers the availability check, which runs
// BEFORE any work so the user is told the real problem rather than watching a
// subprocess fail.
func TestCmdMergeReportsMissingTool(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{
		WasmMergePath: filepath.Join(dir, "definitely-not-installed"),
	}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success with no wasm-merge available")
	}
	if !strings.Contains(err.Error(), "definitely-not-installed") &&
		!strings.Contains(strings.ToLower(err.Error()), "wasm-merge") {
		t.Errorf("error %q names neither the tool nor the path", err)
	}
}

// TestCmdMergeReportsToolFailure: when the tool exists but fails — here
// because its inputs do not exist — the exit status has to surface rather than
// be swallowed into a "merged" log line.
func TestCmdMergeReportsToolFailure(t *testing.T) {
	dir := t.TempDir()
	// `false` is on every POSIX system and does nothing but exit non-zero,
	// which is exactly the shape of a wasm-merge that refused its inputs.
	cfg := config.BuildConfig{WasmMergePath: lookPath(t, "false")}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though the merge tool exited non-zero")
	}
}

// TestCmdMergeReportsMissingOutput: a tool that succeeds but writes nothing
// must still be an error, because the next step in the build reads that file.
// `true` models exactly that.
func TestCmdMergeReportsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{WasmMergePath: lookPath(t, "true")}
	err := CmdMerge(cfg, filepath.Join(dir, "main.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though no output file was produced")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("error %q does not explain that the output is missing", err)
	}
}

// The component arm's failure paths mirror the module arm's, because the
// asymmetry to guard against is silent SUCCESS: a component whose imports were
// never satisfied loads fine and traps at the first call, a long way from here.
//
// `wasm_format: component` is set through a config literal rather than a YAML
// file: these tests exercise CmdMerge's dispatch, not config loading.

// componentCfg pairs the wac under test with a mock wasm-tools, which the plug
// pre-check runs before wac.
func componentCfg(t *testing.T, wac string) config.BuildConfig {
	return config.BuildConfig{WasmFormat: "component", WacPath: wac, WasmToolsPath: mockWasmTools(t)}
}

// TestCmdMergeComponentReportsMissingTool: the wac availability check runs
// before any work, and its message must name the format that needed it — a
// module user who has never heard of wac can otherwise reach it by mistake.
func TestCmdMergeComponentReportsMissingTool(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, filepath.Join(dir, "definitely-not-installed")),
		filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"),
		[]string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success with no wac available")
	}
	if !strings.Contains(err.Error(), "definitely-not-installed") {
		t.Errorf("error %q does not name the missing tool", err)
	}
	if !strings.Contains(err.Error(), "component") {
		t.Errorf("error %q does not say which wasm_format needed it", err)
	}
}

func TestCmdMergeComponentReportsToolFailure(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, lookPath(t, "false")), filepath.Join(dir, "guest.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though wac exited non-zero")
	}
	if !strings.Contains(err.Error(), "wac") {
		t.Errorf("error %q does not name wac", err)
	}
}

func TestCmdMergeComponentReportsMissingOutput(t *testing.T) {
	dir := t.TempDir()
	err := CmdMerge(componentCfg(t, lookPath(t, "true")), filepath.Join(dir, "guest.wasm"),
		filepath.Join(dir, "out.wasm"), []string{filepath.Join(dir, "re.wasm")})
	if err == nil {
		t.Fatal("reported success though no output file was produced")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("error %q does not explain that the output is missing", err)
	}
}

// lookPath is the absolute path of a system tool: a tool path key is a PATH, so a
// bare name there would be resolved against the working directory.
func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH", name)
	}
	return p
}

// TestComposeIgnoresTheEnvironmentAndKeepsArgumentOrder: wac is found through
// `wac_path` or `$PATH` and never through $WAC, and `wac plug` gets its plugs,
// output and socket in the documented order — checked without wac installed, by
// a mock that records its argv.
func TestComposeIgnoresTheEnvironmentAndKeepsArgumentOrder(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv")
	t.Setenv("REGEXPED_MOCK_WASM_MERGE", "1")
	t.Setenv("REGEXPED_MOCK_ARGV", argv)
	t.Setenv("WAC", "/garbage/wac")
	mainWasm, out := filepath.Join(dir, "main.wasm"), filepath.Join(dir, "out.wasm")
	a, b := filepath.Join(dir, "a.wasm"), filepath.Join(dir, "b.wasm")
	for _, p := range []string{mainWasm, a, b} {
		if err := os.WriteFile(p, []byte("mock"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CmdMerge(componentCfg(t, exe), mainWasm, out, []string{a, b}); err != nil {
		t.Fatalf("CmdMerge: %v", err)
	}
	got, err := os.ReadFile(argv)
	if err != nil {
		t.Fatalf("the mock recorded no argv: %v", err)
	}
	if want := "plug --plug " + a + " --plug " + b + " -o " + out + " " + mainWasm; string(got) != want {
		t.Errorf("wac argv = %q, want %q", got, want)
	}

	t.Setenv("WAC", exe)
	t.Setenv("PATH", t.TempDir())
	if err := CmdMerge(config.BuildConfig{WasmFormat: "component", WasmToolsPath: mockWasmTools(t)}, mainWasm, out, []string{a}); err == nil ||
		!strings.Contains(err.Error(), "$PATH") {
		t.Errorf("err = %v; with wac_path omitted only $PATH is consulted, never $WAC", err)
	}
}

// mockWasmTools is a stand-in for `wasm-tools component wit <plug>`: it prints
// the canned WIT in `<plug>.mockwit`, or an empty world when there is none, so
// the plug pre-check runs without wasm-tools installed.
func mockWasmTools(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wasm-tools")
	script := "#!/bin/sh\n[ \"$1 $2\" = \"component wit\" ] || exit 3\n" +
		"if [ -f \"$3.mockwit\" ]; then cat \"$3.mockwit\"; else printf 'package root:component;\\n\\nworld root {\\n}\\n'; fi\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// plugWithWit writes an empty plug file and the WIT the mock reports for it.
func plugWithWit(t *testing.T, dir, name string, exports ...string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	wit := "package root:component;\n\nworld root {\n  import wasi:io/error@0.2.0;\n"
	for _, e := range exports {
		wit += "  export " + e + ";\n"
	}
	wit += "}\npackage regexped:x {\n  interface matcher {\n    variant error-code { export }\n  }\n}\n"
	for path, body := range map[string]string{p: "plug", p + ".mockwit": wit} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// TestCmdMergeComponentRefusesDuplicatePlugExports: two plugs exporting the SAME
// regexped interface make `wac plug` fail with the text a genuine name mismatch
// gives. The pre-check names both plugs and the interface instead, and runs
// before wac does anything.
func TestCmdMergeComponentRefusesDuplicatePlugExports(t *testing.T) {
	dir := t.TempDir()
	a := plugWithWit(t, dir, "a.wasm", "regexped:pkg-a/matcher", "regexped:pkg-a/sets")
	b := plugWithWit(t, dir, "b.wasm", "regexped:pkg-b/matcher")
	c := plugWithWit(t, dir, "c.wasm", "regexped:pkg-a/sets")
	argv := filepath.Join(dir, "wac-ran")
	wac := filepath.Join(dir, "wac")
	if err := os.WriteFile(wac, []byte("#!/bin/sh\ntouch "+argv+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: wac, WasmToolsPath: mockWasmTools(t)}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{a, b, c})
	if err == nil {
		t.Fatal("two plugs exporting regexped:pkg-a/sets were composed without complaint")
	}
	for _, want := range []string{a, c, "both export regexped:pkg-a/sets"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if _, statErr := os.Stat(argv); statErr == nil {
		t.Error("wac ran although the plugs were already known to collide")
	}

	// Distinct packages pass the pre-check and reach wac, whose failure is then
	// the one reported. An `export` word inside an interface body is not an export.
	err = CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{a, b})
	if err == nil || !strings.Contains(err.Error(), "wac plug") {
		t.Errorf("err = %v; distinct plugs must reach wac", err)
	}
}

// TestCmdMergeComponentNeedsWasmTools: the pre-check makes wasm-tools a
// requirement of a component merge as well as of a component compile, and its
// absence is reported with the path tried and the format that needed it.
func TestCmdMergeComponentNeedsWasmTools(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-wasm-tools-here")
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: lookPath(t, "true"), WasmToolsPath: missing}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"),
		[]string{plugWithWit(t, dir, "a.wasm", "regexped:a/matcher")})
	if err == nil {
		t.Fatal("reported success with no wasm-tools available")
	}
	for _, want := range []string{missing, "wasm_format: component"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestCmdMergeComponentReportsUnreadablePlug: a plug wasm-tools cannot read is
// named in the error, before wac runs.
func TestCmdMergeComponentReportsUnreadablePlug(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.wasm")
	failing := filepath.Join(dir, "wasm-tools")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\necho 'not a component' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuildConfig{WasmFormat: "component", WacPath: lookPath(t, "true"), WasmToolsPath: failing}
	err := CmdMerge(cfg, filepath.Join(dir, "guest.wasm"), filepath.Join(dir, "out.wasm"), []string{bad})
	if err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "wasm-tools") {
		t.Errorf("err = %v; want wasm-tools named together with the plug %s", err, bad)
	}
}

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

	// The same interface from two plugs is refused by name. wac alone reports it
	// with the text a genuine mismatch gives.
	aCopy := filepath.Join(dir, "a-copy.wasm")
	if data, err := os.ReadFile(filepath.Join(dir, "a.wasm")); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(aCopy, data, 0o644); err != nil {
		t.Fatal(err)
	}
	err = CmdMerge(mergeCfg, filepath.Join(dir, "socket.wasm"), filepath.Join(dir, "dup.wasm"),
		[]string{filepath.Join(dir, "a.wasm"), aCopy})
	if err == nil || !strings.Contains(err.Error(), "both export regexped:pkg-a/matcher") {
		t.Errorf("two plugs exporting regexped:pkg-a/matcher: err = %v", err)
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
