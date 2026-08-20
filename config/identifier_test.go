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
		"has\"quote", // quote — the injection vector in plans/OPUS.md §N4
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
	// project used to special-case (see plans/OPUS.md §N4 and CLAUDE.md).
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
// plans/OPUS.md §N4, which produced a syntactically valid extra Rust function
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
			{Name: "p4", Pattern: "d", NamedGroupsFunc: "fine_name"},
		},
		Sets: []SetConfig{
			{Name: "s1", FindAll: "delete"},
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
			{Name: "class", Match: "validate_sql"},
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
	t.Run("rejected_for_named_groups_func", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<a>y)`, NamedGroupsFunc: "ng"},
		}}
		err := ValidateConfig(&cfg)
		if err == nil {
			t.Fatal("ValidateConfig = nil, want an error for a duplicated capture name")
		}
		if !strings.Contains(err.Error(), `capture group name "a" is used more than once`) {
			t.Errorf("ValidateConfig = %v, want a message naming the duplicated group", err)
		}
	})

	// The other three func kinds never resolve captures by name, so a repeated
	// name is unambiguous for them and must stay legal.
	t.Run("allowed_without_named_groups_func", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<a>y)`, MatchFunc: "m"},
			{Pattern: `(?P<a>x)(?P<a>y)`, FindFunc: "f"},
			{Pattern: `(?P<a>x)(?P<a>y)`, GroupsFunc: "g"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil (only named_groups_func resolves by name)", err)
		}
	})

	t.Run("distinct_names_accepted", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x)(?P<b>y)`, NamedGroupsFunc: "ng"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil", err)
		}
	})

	// A syntax error is compile's to report; ValidateConfig must not duplicate it.
	t.Run("unparseable_pattern_ignored", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<a>x`, NamedGroupsFunc: "ng"},
		}}
		if err := ValidateConfig(&cfg); err != nil {
			t.Fatalf("ValidateConfig = %v, want nil (parse errors are reported by compile)", err)
		}
	})

	t.Run("multiple_duplicates_sorted", func(t *testing.T) {
		cfg := BuildConfig{Regexps: []RegexEntry{
			{Pattern: `(?P<z>1)(?P<z>2)(?P<a>3)(?P<a>4)`, NamedGroupsFunc: "ng"},
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
// Per-stub-type validation (plans/FABLE.md B32, B33, B34)

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
		{"js", "_resize", true},
		{"js", "patternName", true},
		{"ts", "SetMatch", true},
		{"js", "SetMatch", false}, // the interface is TS-only
		{"rust", "init", false},   // not a Rust helper name
		{"go", "init", false},
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
	// happy) that collapse to one generated Go function / Rust iterator type.
	for _, st := range []string{"rust", "go"} {
		cfg := &BuildConfig{
			StubType: st, ImportModule: "m",
			Regexps: []RegexEntry{
				{Name: "a", Pattern: "a", FindFunc: "url_find"},
				{Name: "b", Pattern: "b", FindFunc: "urlFind"},
			},
		}
		err := ValidateConfig(cfg)
		if err == nil {
			t.Fatalf("stub_type %q: accepted url_find + urlFind, want error", st)
		}
		if !strings.Contains(err.Error(), "UrlFind") {
			t.Errorf("stub_type %q: error does not name the collision: %v", st, err)
		}
	}
	// The two names stay distinct in JS/TS, which emit them verbatim.
	cfg := &BuildConfig{
		StubType: "js",
		Regexps: []RegexEntry{
			{Name: "a", Pattern: "a", FindFunc: "url_find"},
			{Name: "b", Pattern: "b", FindFunc: "urlFind"},
		},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("stub_type js: rejected url_find + urlFind: %v", err)
	}
	// And `set_match` collides with the SetMatch struct the set stubs declare.
	for _, st := range []string{"rust", "go"} {
		cfg := &BuildConfig{
			StubType: st, ImportModule: "m",
			Regexps: []RegexEntry{{Name: "a", Pattern: "a", MatchFunc: "set_match"}},
		}
		if err := ValidateConfig(cfg); err == nil {
			t.Errorf("stub_type %q: accepted set_match, want error", st)
		}
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
