package fuzz

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Emitter reach, measured from the run that checks the answers.
//
// # The problem this solves
//
// A behavioural sweep is worth exactly what its reach can be shown to be. The
// find sweep passed for weeks over shapes that reached eight of fourteen
// emitters; the six it never touched included two that answered with a match
// starting before the position they were asked to search from
// (plans/FUZZER_BUGS.md 65).
//
// The obvious accounting — a second corpus, in package `compile`, driving the
// emitters and recording which fired — proves the wrong thing. It shows that
// SOME list reaches every emitter, not that the list which checks answers does.
// Two corpora drift, and the drift is silent.
//
// So reach is measured here, from the coverage profile of the sweeps
// themselves. One run produces both facts, and they cannot disagree.
//
//	make from-coverage
//
// which is `go test -run 'TestFindFrom|TestGroupsFrom' -coverpkg=…/compile
// -coverprofile=…` followed by this test with REGEXPED_COVERPROFILE set.
// Without that variable it skips, so `go test ./...` stays self-contained.
//
// # Why no hook in `compile`
//
// An earlier version put `seedTrace`/`captureTrace` function variables in the
// compile package and a `traceCaptureEmitter()` call at the top of six
// emitters. It worked, but it is test scaffolding living in production
// emitters, and it still measured a second corpus. Coverage needs neither:
// it observes without disturbing execution, and it crosses the module
// boundary (`tools/fuzz` requires the root module via `replace`, and
// `-coverpkg` instruments it into the same test binary).
//
// # How emitters are enumerated
//
// Not from a hand-written list, which would silently miss a new emitter, and
// not from a marker, which is the scaffolding just removed. From the code's own
// structure:
//
//   - a FIND emitter is any function containing a call to `emitFindFromSeed`,
//     the one thing every find body must do;
//   - a CAPTURE emitter is any function whose result is assigned to
//     `p.captureBody` or passed to `p.setCaptureBody`.
//
// Add an emitter and it joins the list automatically; the test then fails until
// a shape reaches it.

const coverProfileEnv = "REGEXPED_COVERPROFILE"

type emitterDecl struct {
	name, file, kind   string
	startLine, endLine int
}

// compileDir is the compile package's source, relative to this test.
const compileDir = "../../compile"

func enumerateEmitters(t *testing.T) []emitterDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(compileDir)
	if err != nil {
		t.Fatalf("read %s: %v", compileDir, err)
	}
	var out []emitterDecl
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// Capture emitters are named at their CALL sites, so collect those
		// names first, then match them against declarations below.
		captureNames := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "captureBody" && i < len(v.Rhs) {
						if call, ok := v.Rhs[i].(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok {
								captureNames[id.Name] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setCaptureBody" && len(v.Args) > 0 {
					if inner, ok := v.Args[0].(*ast.CallExpr); ok {
						if id, ok := inner.Fun.(*ast.Ident); ok {
							captureNames[id.Name] = true
						}
					}
				}
			}
			return true
		})
		for n := range captureNames {
			out = append(out, emitterDecl{name: n, kind: "capture"})
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "emitFindFromSeed" {
				continue
			}
			seeds := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "emitFindFromSeed" {
						seeds = true
					}
				}
				return true
			})
			if seeds {
				out = append(out, emitterDecl{
					name: fn.Name.Name, file: name, kind: "find",
					startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
				})
			}
		}
	}
	// Resolve declaration ranges for the capture emitters named above.
	decls := map[string]emitterDecl{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				decls[fn.Name.Name] = emitterDecl{
					name: fn.Name.Name, file: name,
					startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
				}
			}
		}
	}
	var final []emitterDecl
	seen := map[string]bool{}
	for _, e := range out {
		if seen[e.name] {
			continue
		}
		seen[e.name] = true
		if e.file == "" {
			d, ok := decls[e.name]
			if !ok {
				t.Fatalf("capture emitter %q named at a call site but not declared in the package", e.name)
			}
			d.kind = e.kind
			e = d
		}
		final = append(final, e)
	}
	sort.Slice(final, func(i, j int) bool { return final[i].name < final[j].name })
	if len(final) == 0 {
		t.Fatal("no emitters enumerated — has emitFindFromSeed or captureBody been renamed?")
	}
	return final
}

// coveredLines returns, per compile-package file, the set of line numbers with
// at least one executed statement.
func coveredLines(t *testing.T, path string) map[string]map[int]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]map[int]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// name.go:startLine.col,endLine.col numStmt count
		colon := strings.LastIndex(line, ":")
		sp := strings.Fields(line[colon+1:])
		if colon < 0 || len(sp) != 3 {
			continue
		}
		count, err := strconv.Atoi(sp[2])
		if err != nil || count == 0 {
			continue
		}
		file := filepath.Base(line[:colon])
		rng := strings.SplitN(sp[0], ",", 2)
		if len(rng) != 2 {
			continue
		}
		start, err1 := strconv.Atoi(strings.SplitN(rng[0], ".", 2)[0])
		end, err2 := strconv.Atoi(strings.SplitN(rng[1], ".", 2)[0])
		if err1 != nil || err2 != nil {
			continue
		}
		if out[file] == nil {
			out[file] = map[int]bool{}
		}
		for l := start; l <= end; l++ {
			out[file][l] = true
		}
	}
	return out
}

func TestEveryEmitterIsReachedBySweeps(t *testing.T) {
	profile := os.Getenv(coverProfileEnv)
	if profile == "" {
		t.Skipf("set %s (see `make from-coverage`) to check emitter reach", coverProfileEnv)
	}
	emitters := enumerateEmitters(t)
	cov := coveredLines(t, profile)

	var missing []string
	for _, e := range emitters {
		hit := false
		for l := e.startLine; l <= e.endLine && !hit; l++ {
			if cov[e.file][l] {
				hit = true
			}
		}
		if !hit {
			missing = append(missing, fmt.Sprintf("%s (%s, %s:%d)", e.name, e.kind, e.file, e.startLine))
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d of %d emitters are never reached by the property sweeps:\n  %s\n\n"+
			"Each is a body whose answers no test checks. Add a shape to "+
			"findFromShapes or groupsFromShapes that reaches it — on the find side, "+
			"two of six unreached emitters turned out to be broken.",
			len(missing), len(emitters), strings.Join(missing, "\n  "))
	}
	t.Logf("%d emitters, all reached by the sweeps", len(emitters))
}

// ── Set emitters ───────────────────────────────────────
//
// The same question for the set path, where the surface is an order of
// magnitude larger: 19,800 lines across compile/set_*.go.
//
// `compile/set_matrix_coverage_test.go` already reaches these emitters by
// COMPILING them, and its opening comment names the exact split this measures
// from the other side:
//
//	"the correctness of what they emit is checked elsewhere … `make setcaps` …
//	 `tools/fuzz` … Both live in SEPARATE MODULES, so neither contributes a
//	 single statement to this package's coverage, and the gap that hid was
//	 total: `set_overlap_dp.go`, 314 statements of backward sweep, sat at 2.5%
//	 while being exercised thousands of times a second by a fuzz target one
//	 directory away."
//
// So the smoke matrix proves a shape still compiles; this proves the tests
// that CHECK ANSWERS actually drive the emitter. Neither implies the other,
// and on the single-pattern path the same measurement found six of fourteen
// emitters undriven, two of them broken.
//
// A set emitter is defined structurally, not by a list: a function declared in
// compile/set_*.go whose name begins build/emit/gen and which returns []byte —
// i.e. something that produces WASM. Their input conventions differ (some take
// `b []byte`, some a `*compiledSet`), so the result type is the reliable mark.

const setCoverProfileEnv = "REGEXPED_SETCOVERPROFILE"

func returnsBytes(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, r := range fn.Type.Results.List {
		if at, ok := r.Type.(*ast.ArrayType); ok {
			if id, ok := at.Elt.(*ast.Ident); ok && id.Name == "byte" && at.Len == nil {
				return true
			}
		}
	}
	return false
}

func enumerateSetEmitters(t *testing.T) []emitterDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(compileDir)
	if err != nil {
		t.Fatalf("read %s: %v", compileDir, err)
	}
	var out []emitterDecl
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "set_") || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(compileDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			n := fn.Name.Name
			if !(strings.HasPrefix(n, "build") || strings.HasPrefix(n, "emit") || strings.HasPrefix(n, "gen")) {
				continue
			}
			if !returnsBytes(fn) {
				continue
			}
			out = append(out, emitterDecl{
				name: n, file: name, kind: "set",
				startLine: fset.Position(fn.Pos()).Line, endLine: fset.Position(fn.End()).Line,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	if len(out) == 0 {
		t.Fatal("no set emitters enumerated — have compile/set_*.go been renamed?")
	}
	return out
}

func TestEverySetEmitterIsReached(t *testing.T) {
	profile := os.Getenv(setCoverProfileEnv)
	if profile == "" {
		t.Skipf("set %s (see `make set-coverage`) to check set emitter reach", setCoverProfileEnv)
	}
	emitters := enumerateSetEmitters(t)
	cov := coveredLines(t, profile)

	var missing []string
	for _, e := range emitters {
		hit := false
		for l := e.startLine; l <= e.endLine && !hit; l++ {
			if cov[e.file][l] {
				hit = true
			}
		}
		if !hit {
			missing = append(missing, fmt.Sprintf("%s (%s:%d, %d lines)",
				e.name, e.file, e.startLine, e.endLine-e.startLine))
		}
	}
	t.Logf("%d set emitters, %d reached, %d not", len(emitters), len(emitters)-len(missing), len(missing))
	if len(missing) > 0 {
		t.Errorf("%d of %d set emitters are never reached by the answer-checking tests:\n  %s",
			len(missing), len(emitters), strings.Join(missing, "\n  "))
	}
}
