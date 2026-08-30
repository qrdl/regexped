package config

import (
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
	// One representative per language, plus `match`, which is the name the
	// project used to special-case.
	reserved := []string{
		"match",     // Rust
		"fn",        // Rust
		"unsafe",    // Rust
		"func",      // Go
		"select",    // Go
		"chan",      // Go
		"int",       // C
		"typedef",   // C
		"_Atomic",   // C
		"delete",    // JS
		"class",     // JS
		"function",  // JS
		"namespace", // TS/AS
		"readonly",  // TS/AS
	}
	for _, name := range reserved {
		err := ValidateIdentifier(name)
		if err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want reserved-word error", name)
			continue
		}
		if !strings.Contains(err.Error(), "reserved word") {
			t.Errorf("ValidateIdentifier(%q) = %v, want a reserved-word error", name, err)
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
		t.Fatal("ValidateConfig accepted the §N4 injection payload, want error")
	}
	if !strings.Contains(err.Error(), "match_func") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

func TestValidateConfig_ReportsAllProblems(t *testing.T) {
	cfg := BuildConfig{
		Regexps: []RegexEntry{
			{Name: "p1", Pattern: "a", MatchFunc: "bad name"},
			{Name: "p2", Pattern: "b", FindFunc: "9lives"},
			{Name: "p3", Pattern: "c", GroupsFunc: "match"},
			{Name: "p4", Pattern: "d", GroupsFunc: "fine_name"},
		},
		Sets: []SetConfig{
			{Name: "s1", ScanAll: "delete"},
		},
	}
	err := ValidateConfig(&cfg)
	if err == nil {
		t.Fatal("ValidateConfig = nil, want error")
	}
	msg := err.Error()
	for _, want := range []string{"bad name", "9lives", `"match"`, `"delete"`} {
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
	// B33: not reserved words, but unbindable in strict-mode code, which every
	// generated ES module is. Verified with `node --check`.
	for _, name := range []string{"eval", "arguments"} {
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) = nil, want error", name)
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
		// B32: hyphens are fine for JS/TS, which never emit the module name,
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
	// B34 class 1: a user export named after something the generator declares
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
	// B34 class 3: `ffi_x` collides with the private binding generated for an
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
	// B34 class 2: distinct WASM exports (so ValidateSets' verbatim dedup is
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
