package config

import (
	"strings"
	"testing"
)

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
