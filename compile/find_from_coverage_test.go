package compile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// Per-emitter coverage accounting for the find-from seed.
//
// # Why this is not a fingerprint count
//
// The first version of this check lived in tools/fuzz and counted DISTINCT
// LOCALS DECLARATIONS reached by a shape corpus, against a floor written down
// by hand. That is a proxy twice over: two emitters can declare identical
// locals (twelve of the twenty-nine shapes there share one fingerprint), and a
// floor chosen by running the corpus once can only detect the corpus getting
// SMALLER — never that it was missing an emitter from the start. Missing an
// emitter from the start is exactly how bug 65 shipped: no fixture and no test
// reached either alternation find body.
//
// So this test asks the question directly. It finds every function in the
// package that calls emitFindFromSeed by parsing the source, compiles a corpus,
// and records which of those functions actually ran. An emitter that no shape
// reaches is named in the failure, which is the report that was missing.

// findFromCorpus is chosen to reach every find emitter. When this test fails
// with "never reached", the fix is a shape here — not a lower expectation.
//
// Compilation alone is enough for this accounting, so no wasmtime is needed and
// the corpus can live in the compile package. tools/fuzz's shapes are separate
// on purpose: those exist to CHECK the answers, these to reach the code.
var findFromCorpus = []struct {
	name, pat string
	lnm       bool
	groups    bool
	// maxStates forces the DFA state ceiling. buildBTFindBody is the fallback
	// taken when a find pattern's DFA is too large, so it is unreachable at the
	// default limit by any pattern small enough to keep in a test.
	maxStates int
}{
	{name: "dfa_find", pat: `(?:alpha|beta|gamma)[0-9a-f]{300}`},
	{name: "compiled_dfa", pat: `abc[0-9]{2}`},
	{name: "lit_chain", pat: `AKIA[A-Z0-9]{16}`},
	{name: "lit_chain_range", pat: `x[a-f]{24,30}y`},
	{name: "lit_chain_prefixed", pat: `aaa[0-9]{24}bbb`},
	{name: "lit_anchor", pat: `[a-z]+@example\.com`},
	{name: "alt_lit_anchor", pat: `[a-z]+@aaa\.com|[0-9]+#bbb\.net`},
	{name: "strict_alt", pat: `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{20}`},
	{name: "alt_prefixed", pat: `PRE[a-f]{24}|ZZ[0-9]{4,9}X`},
	{name: "alt_range", pat: `foo[0-9]{24,30}|bar[a-f]{24,30}`},
	{name: "lenient_alt", pat: `ERROR[0-9]{3}|WARNING[0-9]{3}`},
	{name: "teddy_prefix", pat: `ghp_[A-Za-z0-9]{36}`},
	{name: "word_boundary", pat: `\bclass\b`},
	{name: "line_anchored", pat: `(?m:^)ERROR:.*(?m:$)`},
	{name: "dominant_selfloop", pat: `[^\n]*ERROR`},
	{name: "varlen_prefix", pat: `a{0,2}XYZQ`},
	{name: "chain_alt_suffix", pat: `q[a-f]{24}(?:AA|BB)`},
	{name: "lnm_simple_prefix", pat: `[0-9]{4}MARKER`, lnm: true},
	{name: "lnm_lit_anchor", pat: `[a-f]{6}TAIL`, lnm: true},
	{name: "lit_chain_range_body", pat: `foo[0-9]{26,30}`},
	{name: "lit_chain_prefixed_body", pat: `[a-z]{3}AKIA[A-Z0-9]{24}`},
	{name: "alt_lit_anchor_dispatch", pat: `[a-z]{5}@aaa\.com|[0-9]{5}#bbb\.net`},
	{name: "alt_prefixed_body", pat: `[a-z]{3}AKIA[A-Z0-9]{24}|[0-9]{3}ghp_[A-Za-z0-9]{24}`},
	// Capture paths: the three lit-chain groups bodies seed too, and they are
	// reached only when a groups export is requested alongside find.
	{name: "lit_chain_groups", pat: `AKIA([A-Z0-9]{24})`, groups: true},
	{name: "lit_chain_range_groups", pat: `foo([0-9]{26,30})`, groups: true},
	{name: "alt_groups", pat: `AKIA([A-Z0-9]{24})|ghp_([A-Za-z0-9]{24})`, groups: true},
	// Backtracking find: a non-greedy quantifier makes it TDFA-ineligible, and
	// captures are what route it away from the DFA paths.
	{name: "bt_groups", pat: `(a.*?b)(c+)`, groups: true},
	{name: "bt_find_fallback", pat: `(?:alpha|beta|gamma)[0-9a-f]{300}`, maxStates: 8},
}

// seedCallers parses the package's own sources for functions containing a call
// to emitFindFromSeed.
func seedCallers(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "emitFindFromSeed" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "emitFindFromSeed" {
					out[fn.Name.Name] = name
				}
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("no emitFindFromSeed call sites found — has the seed been renamed?")
	}
	return out
}

func TestEveryFindEmitterIsCovered(t *testing.T) {
	want := seedCallers(t)

	seen := map[string]bool{}
	seedTrace = func(emitter string) { seen[emitter] = true }
	defer func() { seedTrace = nil }()

	for _, c := range findFromCorpus {
		entry := config.RegexEntry{Pattern: c.pat, FindFunc: "find"}
		if c.groups {
			entry.GroupsFunc = "groups"
		}
		o := CompileOptions{}
		if c.lnm {
			o.LikelyMode = LikelyNoMatch
		}
		if c.maxStates > 0 {
			o.MaxDFAStates = c.maxStates
		}
		if _, _, err := Compile([]config.RegexEntry{entry}, 1<<18, true, o); err != nil {
			t.Errorf("%s: compile %q: %v", c.name, c.pat, err)
		}
	}

	var missing []string
	for fn, file := range want {
		if !seen[fn] {
			missing = append(missing, fn+" ("+file+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d of %d find emitters are never reached by findFromCorpus:\n  %s\n\n"+
			"Each unreached emitter is a find body whose find-from seed no test "+
			"exercises — the state buildLitChainAltLenientFindBody was in when it "+
			"shipped ignoring `from` entirely. Add a shape that reaches it rather "+
			"than removing it from this check.",
			len(missing), len(want), strings.Join(missing, "\n  "))
	}

	// The reverse direction: a shape that reaches nothing is dead weight, and a
	// trace naming a function the AST scan missed means the scan is wrong.
	for fn := range seen {
		if _, ok := want[fn]; !ok {
			t.Errorf("seed traced to %q, which the source scan did not find as a "+
				"call site — callerFuncName or the scan is wrong", fn)
		}
	}
	t.Logf("%d find emitters, all reached by %d shapes", len(want), len(findFromCorpus))
}
