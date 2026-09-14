package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIdentifier_Shape(t *testing.T) {
	valid := []string{
		"m1", "url_match", "_leading", "a", "A", "x9", "__dunder",
		"find_github_token", "MATCH", "Match",
	}
	for _, name := range valid {
		if err := ValidateIdentifier(name); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",           // empty
		"9lives",     // leading digit
		"has space",  // space
		"has-dash",   // dash
		"has.dot",    // dot
		"has(paren",  // paren
		"has\"quote", // quote — the injection vector
		"has\nnewl",  // newline
		"héllo",      // non-ASCII letter
		"日本語",        // non-ASCII
		"a;b",        // statement separator
		"f{}",        // braces
	}
	for _, name := range invalid {
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want error", name)
		}
	}
}

func TestValidateIdentifier_ReservedWords(t *testing.T) {
	// Reserved words are applied PER GENERATED LANGUAGE (see
	// TestReservedWordsArePerLanguage), so ValidateIdentifier checks shape only.
	// One representative per language, each in its own language's set.
	reserved := []struct{ name, lang string }{
		{"match", "rust"}, {"fn", "rust"}, {"unsafe", "rust"},
		{"func", "go"}, {"select", "go"}, {"chan", "go"},
		{"int", "c"}, {"typedef", "c"}, {"_Atomic", "c"},
		{"delete", "js"}, {"class", "js"}, {"function", "js"},
		{"namespace", "ts"}, {"readonly", "as"},
	}
	for _, r := range reserved {
		if !keywordSets[r.lang][r.name] {
			t.Errorf("%q is not in the %s keyword set", r.name, r.lang)
		}
		if err := ValidateIdentifier(r.name); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v; it checks shape only", r.name, err)
		}
	}

	// Contextual/soft keywords and predeclared identifiers are legal function
	// names in their own language, so they must NOT be rejected. Over-rejecting
	// here would be indistinguishable from a bug to a user.
	allowed := []string{
		"type_",  // not `type` itself, but a near-miss should pass
		"from",   // TS contextual
		"of",     // TS contextual
		"get",    // TS contextual
		"set",    // TS contextual
		"string", // TS contextual
		"number", // TS contextual
		"len",    // Go predeclared
		"cap",    // Go predeclared
		"i32",    // AS builtin type alias, not a keyword
		"find",   // used bare by every internal harness
		"groups", // used bare by every internal harness
	}
	for _, name := range allowed {
		if err := ValidateIdentifier(name); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v, want nil (not a reserved word)", name, err)
		}
		for lang, set := range keywordSets {
			if set[name] {
				t.Errorf("%q is in the %s keyword set, but is a legal function name there", name, lang)
			}
		}
	}
}

// TestValidateConfig_RejectsInjection replays the exact payload demonstrated in
// The injection defect, which produced a syntactically valid extra Rust function
// in the caller's crate.
func TestValidateConfig_RejectsInjection(t *testing.T) {
	payload := `m1 } pub fn pwned() { std::process::Command::new("id").status().unwrap(); `
	cfg := BuildConfig{
		Regexps: []RegexEntry{{Pattern: "abc", MatchFunc: payload}},
	}
	err := ValidateConfig(&cfg)
	if err == nil {
		t.Fatal("ValidateConfig accepted the injection payload, want error")
	}
	if !strings.Contains(err.Error(), "match_func") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

func TestValidateConfig_ReportsAllProblems(t *testing.T) {
	// A Rust stub, so both keywords below are reserved in the generated language.
	cfg := BuildConfig{
		StubFile: "x.rs",
		Regexps: []RegexEntry{
			{Name: "p1", Pattern: "a", MatchFunc: "bad name"},
			{Name: "p2", Pattern: "b", FindFunc: "9lives"},
			{Name: "p3", Pattern: "c", GroupsFunc: "match"},
			{Name: "p4", Pattern: "d", GroupsFunc: "fine_name"},
		},
		Sets: []SetConfig{
			{Name: "s1", ScanAll: "loop"},
		},
	}
	err := ValidateConfig(&cfg)
	if err == nil {
		t.Fatal("ValidateConfig = nil, want error")
	}
	msg := err.Error()
	for _, want := range []string{"bad name", "9lives", `"match"`, `"loop"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q; got:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "fine_name") {
		t.Errorf("error names a valid identifier; got:\n%s", msg)
	}
	// Every offending field reported in one pass, not just the first.
	if n := strings.Count(msg, "\n  "); n != 4 {
		t.Errorf("got %d reported problems, want 4; got:\n%s", n, msg)
	}
}

// TestValidateConfig_IgnoresNameFields pins the deliberate scope decision:
// `regexps[].name` and `sets[].name` are selection keys that reach generated
// code only as quoted string literals, so reserved words are fine there. This
// mirrors examples/node/sql-validator/regexped.yaml, which ships pattern names
// "select" (Go keyword) and "delete" (JS keyword).
func TestValidateConfig_IgnoresNameFields(t *testing.T) {
	cfg := BuildConfig{
		Regexps: []RegexEntry{
			{Name: "select", Pattern: "a", MatchFunc: "match_select"},
			{Name: "delete", Pattern: "b", MatchFunc: "match_delete"},
		},
		Sets: []SetConfig{
			{Name: "class", MatchAny: "validate_sql"},
		},
	}
	if err := ValidateConfig(&cfg); err != nil {
		t.Fatalf("ValidateConfig = %v, want nil (name fields are not identifiers)", err)
	}
}

func TestValidateConfig_AcceptsShippedExampleNames(t *testing.T) {
	// Every export name used by a checked-in example config must still pass.
	names := []string{
		"url_match", "email_match", "find_xss", "match_email", "extract_domain",
		"find_email", "parse_url", "find_csv_row", "parse_csv_row", "is_sqli",
		"find_sqli", "parse_sqli", "find_jwt_token", "find_aws_key",
		"find_github_token", "match_ipv6_url", "scan_url", "scan_secrets",
		"scan_sqli", "validate_sql",
	}
	for _, n := range names {
		if err := ValidateIdentifier(n); err != nil {
			t.Errorf("shipped example export name %q rejected: %v", n, err)
		}
	}
}

func TestValidateConfig_DuplicateCaptureNames(t *testing.T) {
	// regexp/syntax accepts a repeated capture-group name, and
	// generate.collectNamedGroups then maps the name to whichever group it
	// visits last — so named_groups_func would silently expose only one of them.
	t.Run("rejected_for_groups_func", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<a>y)`, GroupsFunc: "ng"},
		}}
		err := ValidateConfig(&cfg)
		if err == nil {
			t.Fatal("ValidateConfig = nil, want an error for a duplicated capture name")
		}
		if !strings.Contains(err.Error(), `capture group name "a" is used more than once`) {
			t.Errorf("ValidateConfig = %v, want a message naming the duplicated group", err)
		}
	})

	// match_func and find_func report no captures at all, so a repeated group
	// name is unambiguous for them and stays legal. groups_func is now the one
	// that turns names into symbols (named_groups_func was retired),
	// so it is the one that rejects.
	t.Run("allowed_without_groups_func", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<a>y)`, MatchFunc: "m"},
			{Pattern: `(?P<a>x)(?P<a>y)`, FindFunc: "f"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil (only groups_func resolves by name)", err)
		}
	})

	t.Run("distinct_names_accepted", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<b>y)`, GroupsFunc: "ng"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil", err)
		}
	})

	// A syntax error is compile's to report; ValidateConfig must not duplicate it.
	t.Run("unparseable_pattern_ignored", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x`, GroupsFunc: "ng"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil (parse errors are reported by compile)", err)
		}
	})

	t.Run("multiple_duplicates_sorted", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<z>1)(?P<z>2)(?P<a>3)(?P<a>4)`, GroupsFunc: "ng"},
		}}
		err := ValidateConfig(&cfg)
		if err == nil {
			t.Fatal("ValidateConfig = nil, want an error")
		}
		ai := strings.Index(err.Error(), `"a"`)
		zi := strings.Index(err.Error(), `"z"`)
		if ai < 0 || zi < 0 || ai > zi {
			t.Errorf("ValidateConfig = %v, want both names reported in sorted order", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Per-stub-type validation

func TestValidateIdentifier_StrictModeRestrictedNames(t *testing.T) {
	// Not reserved words, but unbindable in strict-mode code, which every
	// generated ES module is (verified with `node --check`). Refused for a JS
	// stub, and — per language — legal for a Go one.
	for _, name := range []string{"eval", "arguments"} {
		mk := func(stub string) *BuildConfig {
			return &BuildConfig{ImportModule: "m", StubFile: stub,
				Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: name}}}
		}
		if err := ValidateConfig(mk("x.js")); err == nil {
			t.Errorf("%q with a JS stub = nil, want error", name)
		}
		if err := ValidateConfig(mk("x.go")); err != nil {
			t.Errorf("%q with a Go stub: %v, want nil", name, err)
		}
	}
}

func TestValidateImportModule_PerStubType(t *testing.T) {
	cases := []struct {
		name      string
		stubType  string
		module    string
		wantError bool
	}{
		// Hyphens are fine for JS/TS, which never emit the module name,
		// and invalid for the four languages that do.
		{"hyphen js", "js", "my-mod", false},
		{"hyphen ts", "ts", "my-mod", false},
		{"hyphen rust", "rust", "my-mod", true},
		{"hyphen go", "go", "my-mod", true},
		{"hyphen c", "c", "my-mod", false}, // legal inside the quoted attribute
		{"hyphen as", "as", "my-mod", false},
		// A language keyword breaks only the two that emit an identifier, and
		// only when it is that language's own keyword.
		{"rust keyword rust", "rust", "match", true},
		{"rust keyword go", "go", "match", false},
		{"go keyword go", "go", "package", true},
		{"go keyword rust", "rust", "package", false},
		// The injection vector: a quote closes the emitted attribute string.
		{"quote c", "c", `x"), foo("y`, true},
		{"quote as", "as", `x", "y`, true},
		{"quote rust", "rust", `x"y`, true}, // caught by the identifier shape
		{"newline c", "c", "a\nb", true},
		// Plain names pass everywhere.
		{"plain rust", "rust", "mymod", false},
		{"plain c", "c", "mymod", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &BuildConfig{
				StubType:     c.stubType,
				ImportModule: c.module,
				Regexps:      []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "p_match"}},
			}
			err := ValidateConfig(cfg)
			if c.wantError && err == nil {
				t.Fatalf("stub_type %q import_module %q: accepted, want error", c.stubType, c.module)
			}
			if !c.wantError && err != nil {
				t.Fatalf("stub_type %q import_module %q: %v", c.stubType, c.module, err)
			}
			if c.wantError && !strings.Contains(err.Error(), "import_module") {
				t.Errorf("error does not name import_module: %v", err)
			}
		})
	}
}

func TestValidateExports_HelperCollisions(t *testing.T) {
	// Class 1: a user export named after something the generator declares
	// for itself. Only the generators that declare it are affected.
	cases := []struct {
		stubType  string
		funcName  string
		wantError bool
	}{
		{"js", "init", true},
		{"ts", "init", true},
		{"js", "_stage", true},
		{"js", "patternName", true},
		{"ts", "SetMatch", true},
		{"js", "SetMatch", false}, // the interface is TS-only
		{"rust", "init", false},   // not a Rust helper name
		// `func init(input []byte) (uint, bool, error)` is a Go COMPILE error:
		// init takes no arguments and returns nothing.
		{"go", "init", true},
		// C had no helper check at all until K5; these are real declarations
		// in every generated header.
		{"c", "rx_match_t", true},
		{"c", "pattern_name", true},
		{"c", "url_match", false},
		// Go declares Span and the error value for every stub.
		{"go", "Span", true},
		{"go", "ErrBacktrackOverflow", true},
		// The out-of-order sentinel, declared beside the other two.
		{"go", "ErrOutOfOrder", true},
		{"c", "RX_ERR_OUT_OF_ORDER", true},
		{"as", "RX_ERR_OUT_OF_ORDER", true},
		// C emits ffi_<export> too, and the component stub's resource imports
		// are ffi_<find>__res_new / __res_next / __res_drop.
		{"c", "ffi_x__res_new", true},
		{"c", "ffi_url", true},
		{"js", "url_match", false},
	}
	for _, c := range cases {
		t.Run(c.stubType+"/"+c.funcName, func(t *testing.T) {
			cfg := &BuildConfig{
				StubType: c.stubType, ImportModule: "m",
				Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: c.funcName}},
			}
			err := ValidateConfig(cfg)
			if c.wantError != (err != nil) {
				t.Fatalf("stub_type %q match_func %q: err = %v, wantError = %v", c.stubType, c.funcName, err, c.wantError)
			}
		})
	}
}

func TestValidateExports_SetDerivedConstantCollisions(t *testing.T) {
	// Class 4: a user export named after a constant the generator DERIVES from
	// a set's name. Unlike the helper lists this is config-dependent — the set
	// is called "scanner", so the reserved names are its stem plus the four
	// suffixes — which is why a fixed deny-list could not have caught it.
	cases := []struct {
		stubType  string
		funcName  string
		wantError bool
	}{
		{"ts", "scannerPatternCount", true},
		{"js", "scannerIdSpace", true},
		{"ts", "scannerBatchMaxSize", true}, // reserved even with no batch-find hint
		{"rust", "SCANNER_PATTERN_COUNT", true},
		{"c", "SCANNER_ID_SPACE", true},
		{"as", "SCANNER_BATCH_MAX_SIZE", true},
		// Go's names are VERBATIM so the Pascal-cased constant
		// is the colliding one and the snake_case export is not.
		{"go", "scanner_pattern_count", false},
		{"go", "ScannerPatternCount", true},
		{"go", "ScannerIDSpace", true},

		// The stems are per language: the TS constant is camelCase, so the
		// SCREAMING form is unremarkable there and vice versa.
		{"ts", "SCANNER_PATTERN_COUNT", false},
		{"rust", "scannerPatternCount", false},
		// A different set name reserves different constants.
		{"ts", "otherPatternCount", false},
		{"ts", "scanSecrets", false},
	}
	for _, c := range cases {
		t.Run(c.stubType+"/"+c.funcName, func(t *testing.T) {
			cfg := &BuildConfig{
				StubType: c.stubType, ImportModule: "m",
				Regexps: []RegexEntry{{Name: "p", Pattern: "a"}},
				Sets: []SetConfig{{
					Name:     "scanner",
					ScanAny:  c.funcName,
					Patterns: PatternSelector{All: true},
				}},
			}
			err := ValidateConfig(cfg)
			if c.wantError != (err != nil) {
				t.Fatalf("stub_type %q scan %q: err = %v, wantError = %v", c.stubType, c.funcName, err, c.wantError)
			}
		})
	}

	// The collision is with the SET's constants, so a regexp export collides
	// just as a set capability does.
	cfg := &BuildConfig{
		StubType: "ts", ImportModule: "m",
		Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "scannerPatternCount"}},
		Sets:    []SetConfig{{Name: "scanner", ScanAny: "sc", Patterns: PatternSelector{All: true}}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("regexp match_func colliding with a set constant was accepted, want error")
	}

	// With no sets there is nothing to derive, so the name is fine.
	cfg = &BuildConfig{
		StubType: "ts", ImportModule: "m",
		Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "scannerPatternCount"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("no sets: rejected scannerPatternCount: %v", err)
	}
}

func TestValidateExports_FFIPrefix(t *testing.T) {
	// Class 3: `ffi_x` collides with the private binding generated for an
	// export named `x`.
	for _, st := range []string{"rust", "go"} {
		cfg := &BuildConfig{
			StubType: st, ImportModule: "m",
			Regexps: []RegexEntry{
				{Name: "a", Pattern: "a", MatchFunc: "x"},
				{Name: "b", Pattern: "b", MatchFunc: "ffi_x"},
			},
		}
		if err := ValidateConfig(cfg); err == nil {
			t.Errorf("stub_type %q: accepted ffi_x, want error", st)
		}
	}
	// JS/TS have no ffi_ shim, so the name is unremarkable there.
	cfg := &BuildConfig{
		StubType: "js",
		Regexps:  []RegexEntry{{Name: "b", Pattern: "b", MatchFunc: "ffi_x"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("stub_type js: rejected ffi_x: %v", err)
	}
}

func TestValidateExports_CaseFoldCollision(t *testing.T) {
	// Class 2: distinct WASM exports (so ValidateSets' verbatim dedup is
	// happy) that collapse to one generated Rust iterator type.
	//
	// RUST ONLY. Go dropped out of this — its names are
	// verbatim, so `url_find` and `urlFind` are two perfectly good Go
	// functions declaring two distinct `url_findIter`/`urlFindIter` types.
	cfg := &BuildConfig{
		StubType: "rust", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "a", FindFunc: "url_find"},
			{Name: "b", Pattern: "b", FindFunc: "urlFind"},
		},
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("stub_type rust: accepted url_find + urlFind, want error")
	}
	if !strings.Contains(err.Error(), "UrlFindIter") {
		t.Errorf("stub_type rust: error does not name the collision: %v", err)
	}
	// The two names stay distinct wherever they are emitted verbatim.
	for _, st := range []string{"js", "go"} {
		cfg := &BuildConfig{
			StubType: st, ImportModule: "m",
			Regexps: []RegexEntry{
				{Name: "a", Pattern: "a", FindFunc: "url_find"},
				{Name: "b", Pattern: "b", FindFunc: "urlFind"},
			},
		}
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("stub_type %s: rejected url_find + urlFind: %v", st, err)
		}
	}
	// Go's REAL collision: `find_func: foo` declares `type fooIter`, so a
	// second export literally named fooIter duplicates it.
	dup := &BuildConfig{
		StubType: "go", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "a", FindFunc: "foo"},
			{Name: "b", Pattern: "b", MatchFunc: "fooIter"},
		},
	}
	if err := ValidateConfig(dup); err == nil {
		t.Error("stub_type go: accepted foo + fooIter, want error")
	}
	// `set_match` Pascal-folds onto the SetMatch struct the RUST set stubs
	// declare. Go emits verbatim, so `set_match` is unremarkable there and
	// `SetMatch` is the colliding spelling (checked by the helper-collision
	// test above).
	cfg = &BuildConfig{
		StubType: "rust", ImportModule: "m",
		Regexps: []RegexEntry{{Name: "a", Pattern: "a", MatchFunc: "set_match"}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("stub_type rust: accepted set_match, want error")
	}
	cfg = &BuildConfig{
		StubType: "go", ImportModule: "m",
		Regexps: []RegexEntry{{Name: "a", Pattern: "a", MatchFunc: "set_match"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("stub_type go: rejected set_match, which it emits verbatim: %v", err)
	}
}

func TestValidateConfig_NoStubTypeSkipsPerLanguageChecks(t *testing.T) {
	// A compile-only config generates no source, so none of the per-stub-type
	// rules can break it — including a hyphenated import_module.
	cfg := &BuildConfig{
		ImportModule: "my-mod",
		Regexps:      []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "init"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("compile-only config rejected: %v", err)
	}
}

func TestPascalCaseMatchesGenerators(t *testing.T) {
	// pascalCase must stay in step with generate.goPublicName and
	// generate.iterTypeName; config cannot import generate, so this pins the
	// transform against the cases the collision check depends on.
	cases := map[string]string{
		"url_match": "UrlMatch",
		"urlMatch":  "UrlMatch",
		"UrlMatch":  "UrlMatch",
		"set_match": "SetMatch",
		"a_b_c":     "ABC",
		"_leading":  "Leading",
		"x9":        "X9",
	}
	for in, want := range cases {
		if got := pascalCase(in); got != want {
			t.Errorf("pascalCase(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCaptureGroupNameMayBeAReservedWord pins the correction to the
// group-name validation: a group name is never a standalone identifier, so
// reserved words are fine.
//
// Every language prefixes it with the function's name (`parse_sqli_type`) or
// uses it as a JS/TS object KEY, where reserved words are legal. An earlier
// version of the check rejected `(?P<type>…)` and broke
// examples/wasmtime/go/sql-injection, which had used that name for years.
func TestCaptureGroupNameMayBeAReservedWord(t *testing.T) {
	cfg := BuildConfig{Regexps: []RegexEntry{
		{Pattern: `(?P<type>a)(?P<match>b)(?P<class>c)`, GroupsFunc: "parse"},
	}}
	if err := ValidateConfig(&cfg); err != nil {
		t.Fatalf("ValidateConfig = %v, want nil: group names are always prefixed or used as object keys", err)
	}
}

// TestCaptureGroupNamesCollidingOnCase is the check that DOES apply: two names
// that differ only in case reach one generated constant stem.
func TestCaptureGroupNamesCollidingOnCase(t *testing.T) {
	cfg := BuildConfig{Regexps: []RegexEntry{
		{Pattern: `(?P<host>x)(?P<Host>y)`, GroupsFunc: "parse"},
	}}
	err := ValidateConfig(&cfg)
	if err == nil {
		t.Fatal("ValidateConfig = nil, want an error: host and Host collapse to one constant stem")
	}
	if !strings.Contains(err.Error(), "differ only in case") {
		t.Errorf("error should explain the collision, got: %v", err)
	}
}

// TestValidateNamespace covers the namespace rule: `namespace:` is interpolated
// verbatim into generated identifiers in five languages and was never checked.
func TestValidateNamespace(t *testing.T) {
	for _, c := range []struct {
		ns        string
		wantError bool
	}{
		{"", false},
		{"myns", false},
		{"my_ns", false},
		{"my-ns", true},
		{"9x", true},
		{"x; } func pwn() {", true},
		{"struct", true}, // reserved in at least one stub language
	} {
		cfg := &BuildConfig{
			StubType: "go", ImportModule: "m", Namespace: c.ns,
			Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: "m1"}},
		}
		err := ValidateConfig(cfg)
		if c.wantError != (err != nil) {
			t.Errorf("namespace %q: err = %v, wantError = %v", c.ns, err, c.wantError)
		}
	}
}

// TestValidateExports_DerivedSymbolCollisions covers derived symbols: ones a
// generator derives from ONE export's name colliding with ANOTHER export.
func TestValidateExports_DerivedSymbolCollisions(t *testing.T) {
	// groups_func: parse emits parse_index / parse_names / parse_count.
	cfg := &BuildConfig{
		StubType: "go", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "(?P<x>a)", GroupsFunc: "parse"},
			{Name: "b", Pattern: "b", MatchFunc: "parse_index"},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("accepted match_func parse_index against groups_func parse, want error")
	}
	// camelCase names derive camelCase symbols.
	cfg = &BuildConfig{
		StubType: "ts", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "(?P<x>a)", GroupsFunc: "parseIt"},
			{Name: "b", Pattern: "b", MatchFunc: "parseItIndices"},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("accepted match_func parseItIndices against groups_func parseIt, want error")
	}
	// An unrelated name is fine.
	cfg = &BuildConfig{
		StubType: "go", ImportModule: "m",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "(?P<x>a)", GroupsFunc: "parse"},
			{Name: "b", Pattern: "b", MatchFunc: "other"},
		},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("rejected an unrelated name: %v", err)
	}
	// A capture group named after one of the derived suffixes collides with
	// the helper of the same name within ONE entry.
	cfg = &BuildConfig{
		StubType: "go", ImportModule: "m",
		Regexps: []RegexEntry{{Name: "a", Pattern: "(?P<index>a)", GroupsFunc: "parse"}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Error("accepted a capture group named \"index\", want error")
	}
}

// TestReservedWordsArePerLanguage: a name is checked against the keywords of the
// language whose stub is GENERATED, not against the union of all six. The union
// refused `match_func: defer` for a Rust stub, where it is a perfectly good
// function name; the consequence — the same config failing once stub_type
// switches to Go — is accepted.
func TestReservedWordsArePerLanguage(t *testing.T) {
	for _, c := range []struct{ name, okStub, badStub string }{
		{"defer", "x.rs", "x.go"},    // Go only
		{"loop", "x.go", "x.rs"},     // Rust only
		{"register", "x.go", "x.h"},  // C only
		{"debugger", "x.go", "x.js"}, // JS only
		{"declare", "x.js", "x.ts"},  // TS / AS only
	} {
		cfg := func(stub string) *BuildConfig {
			return &BuildConfig{
				ImportModule: "m", StubFile: stub,
				Regexps: []RegexEntry{{Name: "p", Pattern: "a", MatchFunc: c.name}},
			}
		}
		if err := ValidateConfig(cfg(c.okStub)); err != nil {
			t.Errorf("%q with stub_file %s is not reserved there and must be accepted: %v", c.name, c.okStub, err)
		}
		if err := ValidateConfig(cfg(c.badStub)); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%q with stub_file %s: err = %v, want a reserved-word refusal", c.name, c.badStub, err)
		}
	}
}

// TestResolveStubType covers both halves of the rule: an explicit `stub_type:`
// wins, and otherwise the FILE EXTENSION decides. Both matter, because the
// chosen generator determines which reserved-word list a config is validated
// against — pick the wrong one and a name that is fine in Rust sails through
// into Go, where it is a keyword.
func TestResolveStubType(t *testing.T) {
	cases := []struct {
		name     string
		cfg      BuildConfig
		want     string
		wantErr  bool
		errMatch string
	}{
		{"explicit rust", BuildConfig{StubType: "rust", StubFile: "x.js"}, "rust", false, ""},
		{"explicit js", BuildConfig{StubType: "js"}, "js", false, ""},
		{"explicit ts", BuildConfig{StubType: "ts"}, "ts", false, ""},
		{"explicit go", BuildConfig{StubType: "go"}, "go", false, ""},
		{"explicit c", BuildConfig{StubType: "c"}, "c", false, ""},
		{"explicit as", BuildConfig{StubType: "as"}, "as", false, ""},
		{"explicit overrides the extension", BuildConfig{StubType: "go", StubFile: "stubs.rs"}, "go", false, ""},
		{"unknown stub_type", BuildConfig{StubType: "python"}, "", true, "unknown stub_type"},

		{"from .rs", BuildConfig{StubFile: "src/stubs.rs"}, "rust", false, ""},
		{"from .js", BuildConfig{StubFile: "stubs.js"}, "js", false, ""},
		{"from .ts", BuildConfig{StubFile: "stubs.ts"}, "ts", false, ""},
		{"from .go", BuildConfig{StubFile: "pkg/stubs.go"}, "go", false, ""},
		{"from .h", BuildConfig{StubFile: "stubs.h"}, "c", false, ""},
		// Extension matching is case-insensitive: a path from a
		// case-preserving filesystem must not change the generator.
		{"upper-case extension", BuildConfig{StubFile: "STUBS.RS"}, "rust", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveStubType(c.cfg)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				if c.errMatch != "" && !strings.Contains(err.Error(), c.errMatch) {
					t.Errorf("error %q does not mention %q", err, c.errMatch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestResolveStubTypeRejectsUnknownExtension: an extension nothing recognises
// must be an error rather than a silent default, or a typo picks a generator
// the user did not ask for.
func TestResolveStubTypeRejectsUnknownExtension(t *testing.T) {
	for _, file := range []string{"stubs.py", "stubs", "stubs.txt", ""} {
		if got, err := ResolveStubType(BuildConfig{StubFile: file}); err == nil {
			t.Errorf("ResolveStubType(%q) = %q, want an error", file, got)
		}
	}
}

// TestPascalCaseForValidation pins the copy of the PascalCase transform that
// lives here because `config` cannot import `generate`.
//
// Its doc still names `goPublicName` as the thing it mirrors, and the rework
// DELETED that function — Go stubs now emit the config's name verbatim. So
// what this transform still serves is the RESERVED-NAME check: config must
// know every identifier a generator could derive from a user's name, and the
// derived forms are what it screens. Pinning the transform keeps that list
// honest whatever the generators do with casing.
func TestPascalCaseForValidation(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"url_match", "UrlMatch"},
		{"scan", "Scan"},
		{"a_b_c", "ABC"},
		{"already_Pascal", "AlreadyPascal"},
		{"trailing_", "Trailing"},
		{"", ""},
	} {
		if got := PascalCaseForValidation(c.in); got != c.want {
			t.Errorf("PascalCaseForValidation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSetDerivedNamesForValidation covers the other cross-package escape hatch:
// the list of identifiers a set's name can turn into.
//
// The stems cannot drift — the generators call the same transforms — but the
// SUFFIXES are written out on both sides, so a name a generator emits and this
// list omits is a collision nobody screens for.
func TestSetDerivedNamesForValidation(t *testing.T) {
	set := SetConfig{Name: "secret_scanner", Find: "scan_secrets"}
	for _, stubType := range []string{"rust", "js", "ts", "go", "c", "as"} {
		t.Run(stubType, func(t *testing.T) {
			names := SetDerivedNamesForValidation(set, stubType)
			if len(names) == 0 {
				t.Fatalf("%s: no derived names for a set with a name and a find export", stubType)
			}
			for _, n := range names {
				if n == "" {
					t.Errorf("%s: derived an empty name from %+v", stubType, set)
				}
			}
		})
	}
	// An UNNAMED set still derives names, from SanitizeSetName's "SET"
	// fallback — which is the point of having a fallback: those identifiers
	// are emitted whether or not the user named the set, so they must be
	// screened for collisions either way.
	names := SetDerivedNamesForValidation(SetConfig{}, "rust")
	if len(names) == 0 {
		t.Fatal("an unnamed set derived nothing; its fallback identifiers would go unscreened")
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "SET") {
			t.Errorf("unnamed set derived %q, which does not use the SET fallback", n)
		}
	}
}

// TestSetNameTransforms pins the two casings a set name is rendered in, which
// generated constants are built from (`<set>PatternCount`, `<SET>_PATTERN_COUNT`).
func TestSetNameTransforms(t *testing.T) {
	for _, c := range []struct{ in, screaming, camel string }{
		{"secrets", "SECRETS", "secrets"},
		{"secret_scanner", "SECRET_SCANNER", "secretScanner"},
		{"my-set", "MY_SET", "mySet"},
	} {
		if got := ScreamingSetName(c.in); got != c.screaming {
			t.Errorf("ScreamingSetName(%q) = %q, want %q", c.in, got, c.screaming)
		}
		if got := CamelSetName(c.in); got != c.camel {
			t.Errorf("CamelSetName(%q) = %q, want %q", c.in, got, c.camel)
		}
	}
}

// loadCfgSrc writes src to a temp regexped.yaml and loads it.
func loadCfgSrc(t *testing.T, src string) (BuildConfig, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "regexped.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

const onePattern = "regexps:\n  - pattern: 'abc'\n    find_func: find_abc\n"

func TestKebabIdent(t *testing.T) {
	ok := []struct{ in, want string }{
		{"regexps", "regexps"},
		{"url_ipv6", "url-ipv6"},
		{"urlMatch", "url-match"},
		{"URLMatch", "urlmatch"}, // a run of capitals stays one word
		{"v2_x", "v2-x"},
		{"already-kebab", "already-kebab"},
	}
	for _, c := range ok {
		got, err := KebabIdent(c.in)
		if err != nil || got != c.want {
			t.Errorf("KebabIdent(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
	// Rejected rather than mangled: the user must choose the name.
	for _, bad := range []string{"", "_x", "x__y", "9x", "my.mod", "a b"} {
		if got, err := KebabIdent(bad); err == nil {
			t.Errorf("KebabIdent(%q) = %q, want an error", bad, got)
		}
	}
}

func TestNameRoleFallbacks(t *testing.T) {
	// Nothing set but import_module: every role is import_module, which is how
	// every config that predates these keys must keep behaving.
	cfg := BuildConfig{ImportModule: "regexps"}
	if got := cfg.RustModuleName(); got != "regexps" {
		t.Errorf("RustModuleName = %q, want regexps", got)
	}
	if got := cfg.GoPackageName(); got != "regexps" {
		t.Errorf("GoPackageName = %q, want regexps", got)
	}
	if got, err := cfg.WitPackageName(); err != nil || got != "regexps" {
		t.Errorf("WitPackageName = %q, %v; want regexps, nil", got, err)
	}
	if got, err := cfg.WitWorldName(); err != nil || got != "regexps" {
		t.Errorf("WitWorldName = %q, %v; want regexps, nil", got, err)
	}

	// Each key overrides its own role and nothing else.
	cfg = BuildConfig{ImportModule: "url_ipv6", RustModule: "urlipv6", GoPackage: "urlipv6", WitPackage: "url-v6"}
	if got := cfg.RustModuleName(); got != "urlipv6" {
		t.Errorf("RustModuleName = %q", got)
	}
	if got, err := cfg.WitPackageName(); err != nil || got != "url-v6" {
		t.Errorf("WitPackageName = %q, %v", got, err)
	}
	// wit_world falls back to wit_package, not to import_module.
	if got, err := cfg.WitWorldName(); err != nil || got != "url-v6" {
		t.Errorf("WitWorldName = %q, %v; want url-v6", got, err)
	}
	cfg.WitWorld = "scanner"
	if got, err := cfg.WitWorldName(); err != nil || got != "scanner" {
		t.Errorf("WitWorldName = %q, %v; want scanner", got, err)
	}

	// import_module that cannot be kebabbed is an error naming the escape.
	cfg = BuildConfig{ImportModule: "9x"}
	if _, err := cfg.WitPackageName(); err == nil || !strings.Contains(err.Error(), "wit_package") {
		t.Errorf("WitPackageName error = %v, want one naming wit_package", err)
	}
}

func TestWasmFormatValidation(t *testing.T) {
	cases := []struct {
		name, src, wantErr string
	}{
		{"default is module", onePattern, ""},
		{"explicit module", "wasm_format: module\n" + onePattern, ""},
		{"component", "wasm_format: component\nimport_module: regexps\n" + onePattern, ""},
		{"unknown format", "wasm_format: wasip2\n" + onePattern, `unknown wasm_format "wasip2"`},
		{"component needs a name", "wasm_format: component\n" + onePattern, "is required for wasm_format: component"},
		{"component takes wit_package alone", "wasm_format: component\nwit_package: regexps\n" + onePattern, ""},
		{"unrepresentable name", "wasm_format: component\nimport_module: '9x'\n" + onePattern, "set wit_package explicitly"},
		{"bad wit_package", "wasm_format: component\nwit_package: 'Not_Kebab'\n" + onePattern, "wit_package"},
		{"bad wit_world", "wasm_format: component\nimport_module: regexps\nwit_world: 'Bad World'\n" + onePattern, "wit_world"},
		{"bad semver", "wasm_format: component\nimport_module: regexps\nwit_version: '1.2'\n" + onePattern, "not a semver triple"},
		{"non-numeric semver", "wasm_format: component\nimport_module: regexps\nwit_version: '1.2.x'\n" + onePattern, `non-numeric component "x"`},
		{"good semver", "wasm_format: component\nimport_module: regexps\nwit_version: '2.3.0'\n" + onePattern, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadCfgSrc(t, c.src)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("error %v does not contain %q", err, c.wantErr)
			}
		})
	}
}

// A component config carrying sets is refused rather than half-emitted.
// Sets under `component` LOAD as of phase 3.2: their raw ABI does not cross the
// boundary (`_all` lifts to a list of ids, `find` becomes a resource), so there
// is nothing left to refuse about them.
func TestComponentAcceptsSets(t *testing.T) {
	src := "wasm_format: component\nimport_module: regexps\n" +
		"regexps:\n  - name: a\n    pattern: 'abc'\n" +
		"sets:\n  - name: s\n    find: find_s\n    patterns: all\n"
	if _, err := loadCfgSrc(t, src); err != nil {
		t.Fatalf("a component config with sets must load: %v", err)
	}
}

// `hints: [batch-find]` is the ONE set feature with no component form. It is
// refused rather than ignored: the user asked for a second entry point, and the
// component interface has one position per call through the resource. An ignored
// hint would silently cost them the amortisation they asked for.
func TestComponentRejectsBatchFindHint(t *testing.T) {
	src := "wasm_format: component\nimport_module: regexps\n" +
		"regexps:\n  - name: a\n    pattern: 'abc'\n" +
		"sets:\n  - name: s\n    find: find_s\n    patterns: all\n    hints: [batch-find]\n"
	_, err := loadCfgSrc(t, src)
	if err == nil || !strings.Contains(err.Error(), "batch-find") {
		t.Fatalf("error = %v, want the batch-find refusal", err)
	}
	// The same config is fine as a module.
	if _, err := loadCfgSrc(t, strings.Replace(src, "wasm_format: component\n", "", 1)); err != nil {
		t.Fatalf("batch-find must stay valid for a module: %v", err)
	}
}

// wit_version under `module` is INERT, and inert must mean warn-and-proceed:
// not a load error (a usable module is still produced) and not silence (the
// user believes they versioned their interface).
func TestWitVersionUnderModuleWarnsAndProceeds(t *testing.T) {
	cfg, err := loadCfgSrc(t, "wit_version: '1.2.3'\nimport_module: regexps\n"+onePattern)
	if err != nil {
		t.Fatalf("wit_version under module must not fail the load: %v", err)
	}
	if cfg.WitVersion != "1.2.3" {
		t.Errorf("WitVersion = %q, want it preserved", cfg.WitVersion)
	}
	var warned []string
	c := cfg
	if err := validateFormat(&c, func(f string, a ...any) { warned = append(warned, f) }); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "ignored for wasm_format") {
		t.Errorf("warnings = %v, want exactly one about being ignored", warned)
	}
}

// Two different messages, and the difference is load-bearing: "yet" promises a
// later phase, and go/as are never coming.
func TestStubTypeForFormat(t *testing.T) {
	component := &BuildConfig{WasmFormat: "component", ImportModule: "regexps"}
	for _, st := range []string{"rust", "c", "wit"} {
		if err := validateStubTypeForFormat(component, st); err != nil {
			t.Errorf("%s is a supported component stub type: %v", st, err)
		}
	}
	// js and ts sit with go and as: no JS runtime loads a component, and the
	// module format already serves a JS user without a transpiler.
	for _, st := range []string{"go", "as", "js", "ts"} {
		err := validateStubTypeForFormat(component, st)
		if err == nil {
			t.Fatalf("stub %s under component: want an error", st)
		}
		if strings.HasSuffix(err.Error(), "yet") {
			t.Errorf("stub %s is not a component target; its message must not say \"yet\": %v", st, err)
		}
	}
	if err := validateStubTypeForFormat(component, "wit"); err != nil {
		t.Errorf("wit under component: %v", err)
	}
	// And wit is meaningless without a component.
	module := &BuildConfig{ImportModule: "regexps"}
	if err := validateStubTypeForFormat(module, "wit"); err == nil {
		t.Error("wit under module: want an error")
	}
	for _, st := range []string{"rust", "js", "ts", "go", "c", "as"} {
		if err := validateStubTypeForFormat(module, st); err != nil {
			t.Errorf("stub %s under module must stay valid: %v", st, err)
		}
	}
}

// The per-role identifier rules must apply to the EFFECTIVE value: a config
// setting no role key gets exactly the errors it always got, and setting one
// is the escape hatch that did not exist before.
func TestPerRoleValidationUsesEffectiveValue(t *testing.T) {
	// `match` is a Rust keyword: rejected as it always was...
	cfg := BuildConfig{ImportModule: "match", StubType: "rust"}
	problems := validateImportModule(&cfg, "rust")
	if len(problems) != 1 || !strings.Contains(problems[0], "reserved word") {
		t.Fatalf("problems = %v, want a reserved-word error", problems)
	}
	if !strings.Contains(problems[0], "import_module") {
		t.Errorf("message must name the key that carries the value: %v", problems[0])
	}
	// ...unless rust_module overrides it.
	cfg.RustModule = "matcher"
	if problems := validateImportModule(&cfg, "rust"); len(problems) != 0 {
		t.Errorf("rust_module must be the escape hatch, got %v", problems)
	}
	// The wire name keeps only its own constraint: a keyword is fine for c/as.
	cfg = BuildConfig{ImportModule: "match", StubType: "c"}
	if problems := validateImportModule(&cfg, "c"); len(problems) != 0 {
		t.Errorf("a keyword is a legal wire name for c: %v", problems)
	}
	// But a quote in it is not.
	cfg.ImportModule = `a"b`
	if problems := validateImportModule(&cfg, "c"); len(problems) != 1 {
		t.Errorf("a quote must still be rejected for c: %v", problems)
	}
}

// wit_package and wit_world are as inert under `module` as wit_version, and must
// warn for the same reason: the user believes they named something.
func TestWitPackageAndWorldUnderModuleWarn(t *testing.T) {
	cfg := BuildConfig{ImportModule: "m", WitPackage: "a-b", WitWorld: "c-d"}
	var warned []string
	if err := validateFormat(&cfg, func(f string, a ...any) {
		warned = append(warned, fmt.Sprintf(f, a...))
	}); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 2 {
		t.Fatalf("warnings = %v, want one per inert key", warned)
	}
	for _, want := range []string{"wit_package", "wit_world"} {
		found := false
		for _, w := range warned {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning mentions %s: %v", want, warned)
		}
	}
}

func TestValidateSemverEmptyComponent(t *testing.T) {
	if err := validateSemver("1..3"); err == nil || !strings.Contains(err.Error(), "empty component") {
		t.Errorf("err = %v, want the empty-component message", err)
	}
	if err := validateSemver(".."); err == nil {
		t.Error("`..` must be rejected")
	}
}

// LoadConfig must apply the per-format stub rule, not just the CLI.
func TestLoadConfigRejectsStubTypeForFormat(t *testing.T) {
	for _, st := range []string{"rust", "c"} {
		if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: m\nstub_type: "+st+"\n"+onePattern); err != nil {
			t.Errorf("%s under component must load: %v", st, err)
		}
	}
	// js/ts/go/as remain permanent refusals.
	for _, st := range []string{"js", "ts", "go", "as"} {
		_, err := loadCfgSrc(t, "wasm_format: component\nimport_module: m\nstub_type: "+st+"\n"+onePattern)
		if err == nil || !strings.Contains(err.Error(), "is not supported for wasm_format: component") {
			t.Errorf("%s under component: err = %v", st, err)
		}
		if err != nil && strings.HasSuffix(err.Error(), "yet") {
			t.Errorf("%s must not be described as temporary: %v", st, err)
		}
	}
	if _, err := loadCfgSrc(t, "stub_type: wit\nimport_module: m\n"+onePattern); err == nil ||
		!strings.Contains(err.Error(), "requires wasm_format: component") {
		t.Errorf("wit under module: err = %v", err)
	}
}

// A `.wit` stub_file infers the type, like every other extension.
func TestResolveStubTypeInfersWit(t *testing.T) {
	got, err := ResolveStubType(BuildConfig{StubFile: "out/regexps.wit"})
	if err != nil || got != "wit" {
		t.Errorf("ResolveStubType = %q, %v; want wit", got, err)
	}
	if _, err := ResolveStubType(BuildConfig{StubFile: "out/regexps.xyz"}); err == nil {
		t.Error("an unknown extension must not resolve")
	}
}

// The c/as branch has nothing to check when no name is set; required-ness is the
// CLI's business, not this function's.
func TestValidateImportModuleEmptyNameForCAndAS(t *testing.T) {
	for _, st := range []string{"c", "as"} {
		cfg := BuildConfig{StubType: st}
		if problems := validateImportModule(&cfg, st); len(problems) != 0 {
			t.Errorf("%s with no name: %v", st, problems)
		}
	}
	// Same for the identifier branch.
	for _, st := range []string{"rust", "go"} {
		cfg := BuildConfig{StubType: st}
		if problems := validateImportModule(&cfg, st); len(problems) != 0 {
			t.Errorf("%s with no name: %v", st, problems)
		}
	}
	// And a stub type with no rule at all.
	cfg := BuildConfig{ImportModule: "my-mod", StubType: "js"}
	if problems := validateImportModule(&cfg, "js"); len(problems) != 0 {
		t.Errorf("js has no naming rule: %v", problems)
	}
}

func TestGoPackageOverride(t *testing.T) {
	cfg := BuildConfig{ImportModule: "url_ipv6", GoPackage: "urlipv6"}
	if got := cfg.GoPackageName(); got != "urlipv6" {
		t.Errorf("GoPackageName = %q, want the override", got)
	}
}

// validateWitIdent is reached through several doors; these are the arms the
// public paths cannot produce.
func TestValidateWitIdentDirect(t *testing.T) {
	if err := validateWitIdent(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: %v", err)
	}
	if err := validateWitIdent("a$b"); err == nil || !strings.Contains(err.Error(), "cannot appear") {
		t.Errorf("bad char inside a word: %v", err)
	}
	if err := validateWitIdent("a-"); err == nil || !strings.Contains(err.Error(), "empty word") {
		t.Errorf("trailing hyphen: %v", err)
	}
	if err := validateWitIdent("1a"); err == nil || !strings.Contains(err.Error(), "lowercase letter") {
		t.Errorf("leading digit: %v", err)
	}
	if err := validateWitIdent("a-b2"); err != nil {
		t.Errorf("a valid identifier was rejected: %v", err)
	}
}

// PatternSelector rejects a shape it cannot interpret, rather than guessing.
func TestPatternSelectorUnmarshalError(t *testing.T) {
	var p PatternSelector
	want := errors.New("boom")
	if err := p.UnmarshalYAML(func(any) error { return want }); !errors.Is(err, want) {
		t.Errorf("err = %v, want it propagated", err)
	}
}

// witKeywordList is WIT's full keyword set, every one of which wasm-tools
// rejects as a function name.
var witKeywordList = []string{
	"as", "bool", "borrow", "char", "constructor", "enum", "export", "f32", "f64",
	"flags", "from", "func", "future", "import", "include", "interface", "list",
	"option", "own", "package", "record", "resource", "result", "s8", "s16", "s32",
	"s64", "static", "stream", "string", "tuple", "type", "u8", "u16", "u32", "u64",
	"use", "variant", "with", "world",
}

// Under wasm_format: component every func and capability name becomes a WIT
// identifier, so a WIT keyword is refused at LOAD, naming the key — not later,
// inside `wasm-tools component embed`. A module build with no stub produces no
// WIT and no source, so the same name loads there.
func TestComponentRefusesWITKeywordNames(t *testing.T) {
	for _, kw := range witKeywordList {
		for _, key := range []string{"match_func", "find_func"} {
			comp := "wasm_format: component\nimport_module: t\nregexps:\n  - pattern: 'abc'\n    " +
				key + ": " + kw + "\n"
			if _, err := loadCfgSrc(t, comp); err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("component %s %q: err = %v, want a refusal naming %s", key, kw, err, key)
			}
			if _, err := loadCfgSrc(t, strings.Replace(comp, "wasm_format: component\n", "", 1)); err != nil {
				t.Errorf("module %s %q with no stub must load: %v", key, kw, err)
			}
		}
		set := "wasm_format: component\nimport_module: t\nregexps:\n  - name: a\n    pattern: 'abc'\n" +
			"sets:\n  - name: s\n    scan_all: " + kw + "\n    patterns: all\n"
		if _, err := loadCfgSrc(t, set); err == nil || !strings.Contains(err.Error(), "scan_all") {
			t.Errorf("component set capability %q: err = %v, want a refusal naming scan_all", kw, err)
		}
	}
	for _, c := range []struct{ key, src string }{
		{"wit_package", "wasm_format: component\nwit_package: world\n" + onePattern},
		{"wit_world", "wasm_format: component\nimport_module: t\nwit_world: record\n" + onePattern},
		{"groups_func", "wasm_format: component\nimport_module: t\nregexps:\n  - pattern: '(a)'\n    groups_func: list\n"},
	} {
		if _, err := loadCfgSrc(t, c.src); err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s as a WIT keyword: err = %v, want a refusal naming it", c.key, err)
		}
	}
}

// Two names are not keywords but collide with a TYPE the interface defines:
// `error-code` in both interfaces and `set-match` in `sets`. Escaping cannot fix
// a duplicate, so they are refused under the same gate.
func TestComponentRefusesWITTypeNames(t *testing.T) {
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - pattern: 'abc'\n    find_func: error_code\n"); err == nil ||
		!strings.Contains(err.Error(), "error-code") {
		t.Errorf("find_func error_code: err = %v, want a refusal naming error-code", err)
	}
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - name: a\n    pattern: 'abc'\nsets:\n  - name: s\n    match_all: set_match\n    patterns: all\n"); err == nil ||
		!strings.Contains(err.Error(), "set-match") {
		t.Errorf("set match_all set_match: err = %v, want a refusal naming set-match", err)
	}
	if _, err := loadCfgSrc(t, "wasm_format: component\nimport_module: t\n"+
		"regexps:\n  - pattern: 'abc'\n    find_func: record_x\n"); err != nil {
		t.Errorf("record_x is not a keyword and must load: %v", err)
	}
	if _, err := loadCfgSrc(t, "regexps:\n  - pattern: 'abc'\n    find_func: error_code\n"); err != nil {
		t.Errorf("a module build defines no error-code type, so error_code must load: %v", err)
	}
}

// wit_version is a strict MAJOR.MINOR.PATCH: a component with a leading zero is
// not semver, and ParseUint accepted it.
func TestWitVersionRejectsLeadingZeros(t *testing.T) {
	base := "wasm_format: component\nimport_module: t\n" + onePattern
	for _, v := range []string{"01.2.3", "1.02.3", "1.2.03"} {
		if _, err := loadCfgSrc(t, "wit_version: '"+v+"'\n"+base); err == nil {
			t.Errorf("wit_version %q loaded; a leading zero is not semver", v)
		}
	}
	for _, v := range []string{"0.0.0", "10.20.30"} {
		if _, err := loadCfgSrc(t, "wit_version: '"+v+"'\n"+base); err != nil {
			t.Errorf("wit_version %q must load: %v", v, err)
		}
	}
}

// The world shares the package's item namespace with its interfaces, so a world
// named `matcher` or `sets` is a duplicate item wasm-tools refuses.
func TestWitWorldMayNotNameAnInterface(t *testing.T) {
	for _, w := range []string{"matcher", "sets"} {
		src := "wasm_format: component\nimport_module: t\nwit_world: " + w + "\n" + onePattern
		if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), "wit_world") {
			t.Errorf("wit_world %q: err = %v, want a refusal naming wit_world", w, err)
		}
	}
}

// Regexp-level `hints: [batch-find]` has no component form either: the batch
// groups export it asks for has no WIT shape, and its only consumers, JS and TS,
// are refused under component. Ignoring it silently is what the set-level
// refusal exists to prevent.
func TestComponentRejectsRegexpBatchFindHint(t *testing.T) {
	src := "wasm_format: component\nimport_module: t\nregexps:\n" +
		"  - pattern: '(a)b'\n    groups_func: g\n    hints: [batch-find]\n"
	if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), "batch-find") {
		t.Errorf("err = %v, want the batch-find refusal", err)
	}
	if _, err := loadCfgSrc(t, strings.Replace(src, "wasm_format: component\n", "", 1)); err != nil {
		t.Errorf("batch-find must stay valid for a module: %v", err)
	}
}

// The Rust COMPONENT stub reaches every export through the wit-bindgen binding,
// whose name is the snake_case of the WIT name — not the config spelling. So
// `match_func: Match` passes the case-sensitive Rust list, and the stub then
// calls `matcher::match(...)`; a keyword package produces `use
// super::regexped::loop::matcher;`. Refused where a Rust component stub is
// generated, and only there: WIT itself and C never spell these as Rust.
func TestRustComponentRefusesKeywordBindingNames(t *testing.T) {
	rust := "wasm_format: component\nimport_module: t\nstub_type: rust\n"
	for _, c := range []struct{ key, name string }{
		{"match_func", "Match"}, {"find_func", "Type"}, {"match_func", "Loop"},
	} {
		src := rust + "regexps:\n  - pattern: 'abc'\n    " + c.key + ": " + c.name + "\n"
		if _, err := loadCfgSrc(t, src); err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s %q with a Rust component stub: err = %v, want a refusal naming %s", c.key, c.name, err, c.key)
		}
	}
	pkg := "wasm_format: component\nimport_module: loop\nrust_module: m\nstub_type: rust\n" + onePattern
	if _, err := loadCfgSrc(t, pkg); err == nil || !strings.Contains(err.Error(), "import_module") {
		t.Errorf("a keyword package with a Rust component stub: err = %v, want a refusal naming import_module", err)
	}
	if _, err := loadCfgSrc(t, rust+"regexps:\n  - pattern: 'abc'\n    match_func: matchIt\n"); err != nil {
		t.Errorf("matchIt binds as match_it and must load: %v", err)
	}
	for _, st := range []string{"c", "wit"} {
		src := "wasm_format: component\nimport_module: t\nstub_type: " + st +
			"\nregexps:\n  - pattern: 'abc'\n    match_func: Match\n"
		if _, err := loadCfgSrc(t, src); err != nil {
			t.Errorf("Match with stub_type %s never becomes a Rust identifier and must load: %v", st, err)
		}
	}
}

// TestKebabEdgesPerKey pins the naming edge cases to the DOCUMENTED rules, per
// key, because three keys take three routes. A func name must pass the
// identifier shape and then convert with KebabIdent; import_module converts with
// KebabIdent (and, for a Rust stub, must also be a Rust identifier, since it is
// the `pub mod` name); wit_package must already BE a WIT identifier. An empty
// want means the load is refused. A disagreement here is a finding, not a test
// to bend. wit_package refuses every row, so it has no column.
func TestKebabEdgesPerKey(t *testing.T) {
	for _, c := range []struct {
		in                              string
		findFunc, importWit, importRust string
	}{
		{"My-Mod", "", "my-mod", ""},
		{"a--b", "", "", ""},
		{"aBC", "a-bc", "a-bc", "a-bc"},
		{"A", "a", "a", "a"},
		{"x_", "", "", ""},
		{"_x", "", "", ""},
		{"URLMatch", "urlmatch", "urlmatch", "urlmatch"},
	} {
		src := "wasm_format: component\nimport_module: t\nstub_type: wit\n" +
			"regexps:\n  - pattern: 'abc'\n    find_func: '" + c.in + "'\n"
		_, err := loadCfgSrc(t, src)
		switch {
		case c.findFunc == "" && err == nil:
			t.Errorf("find_func %q loaded; want it refused", c.in)
		case c.findFunc == "" && !strings.Contains(err.Error(), "find_func"):
			t.Errorf("find_func %q refused by a message that does not name the key: %v", c.in, err)
		case c.findFunc != "" && err != nil:
			t.Errorf("find_func %q: %v; want the WIT name %q", c.in, err, c.findFunc)
		case c.findFunc != "":
			if k, _ := KebabIdent(c.in); k != c.findFunc {
				t.Errorf("find_func %q becomes %q, want %q", c.in, k, c.findFunc)
			}
		}

		for _, route := range []struct{ stub, want string }{{"wit", c.importWit}, {"rust", c.importRust}} {
			cfg, err := loadCfgSrc(t, "wasm_format: component\nimport_module: '"+c.in+"'\nstub_type: "+route.stub+"\n"+onePattern)
			switch {
			case route.want == "" && err == nil:
				t.Errorf("import_module %q (stub_type %s) loaded; want it refused", c.in, route.stub)
			case route.want == "" && !strings.Contains(err.Error(), "import_module"):
				t.Errorf("import_module %q (stub_type %s) refused by a message that does not name the key: %v", c.in, route.stub, err)
			case route.want != "" && err != nil:
				t.Errorf("import_module %q (stub_type %s): %v; want package %q", c.in, route.stub, err, route.want)
			case route.want != "":
				if p, _ := cfg.WitPackageName(); p != route.want {
					t.Errorf("import_module %q (stub_type %s) gives package %q, want %q", c.in, route.stub, p, route.want)
				}
			}
		}

		if _, err := loadCfgSrc(t, "wasm_format: component\nwit_package: '"+c.in+"'\nstub_type: wit\n"+onePattern); err == nil {
			t.Errorf("wit_package %q loaded; it is not a WIT identifier", c.in)
		} else if !strings.Contains(err.Error(), "wit_package") {
			t.Errorf("wit_package %q refused by a message that does not name the key: %v", c.in, err)
		}
	}
}
