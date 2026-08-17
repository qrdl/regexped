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
