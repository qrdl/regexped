package config

import (
	"fmt"
	"strings"
)

// This file resolves the NAME ROLES that `import_module` used to serve alone.
//
// `import_module` is a WIRE string: the WASM import-module name, which the
// spec lets be almost any UTF-8. Everything else derived from it is a SOURCE
// IDENTIFIER in some language, and those rules conflict — WIT requires
// hyphens where Rust and Go forbid them, and a Rust or Go keyword is illegal
// where a WASM module name of the same spelling is fine. Each role therefore
// has its own optional key, and each falls back so that a config setting none
// of them behaves exactly as it did before the keys existed.
//
// Read the EFFECTIVE value through these helpers, never the raw field: a raw
// read is empty for every config that relies on the fallback.

// Component reports whether the config asks for a Component Model component
// rather than a core WASM module.
func (c BuildConfig) Component() bool { return c.WasmFormat == formatComponent }

const (
	formatModule    = "module"
	formatComponent = "component"
)

// RustModuleName is the identifier emitted as `pub mod <name>`.
func (c BuildConfig) RustModuleName() string {
	if c.RustModule != "" {
		return c.RustModule
	}
	return c.ImportModule
}

// GoPackageName is the identifier emitted as `package <name>`.
func (c BuildConfig) GoPackageName() string {
	if c.GoPackage != "" {
		return c.GoPackage
	}
	return c.ImportModule
}

// WitPackageName is the WIT package name. Unset, it is the kebab-case form of
// import_module; an import_module that cannot be represented in kebab case is
// an error naming both, never a silent rename.
func (c BuildConfig) WitPackageName() (string, error) {
	if c.WitPackage != "" {
		if err := validateWitIdent(c.WitPackage); err != nil {
			return "", fmt.Errorf("wit_package %q %v", c.WitPackage, err)
		}
		return c.WitPackage, nil
	}
	name, err := KebabIdent(c.ImportModule)
	if err != nil {
		return "", fmt.Errorf("import_module %q cannot be used as a WIT package name (%v): set wit_package explicitly", c.ImportModule, err)
	}
	return name, nil
}

// WitWorldName is the WIT world name: wit_world, else the package name.
//
// The world is the one name in this file that no ABI depends on. It is absent
// from every canonical export name and only names the consumer's generated
// bindings — `<world>.c`, `<world>.h`, the `bindgen!` struct — so changing it
// is always safe, whereas changing the package renames every export.
func (c BuildConfig) WitWorldName() (string, error) {
	if c.WitWorld != "" {
		if err := validateWitIdent(c.WitWorld); err != nil {
			return "", fmt.Errorf("wit_world %q %v", c.WitWorld, err)
		}
		return c.WitWorld, nil
	}
	return c.WitPackageName()
}

// KebabIdent converts a config name to a WIT identifier: split on '_' and on
// lower-to-upper case transitions, lowercase each word, join with '-'.
//
//	url_ipv6 -> url-ipv6
//	urlMatch -> url-match
//
// It reports an error rather than mangling anything it cannot represent, so a
// caller can tell the user to set the key explicitly. WIT identifiers are
// `[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*`.
func KebabIdent(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("is empty")
	}
	var words []string
	var cur strings.Builder
	// A separator ALWAYS ends a word, even an empty one, so `_x`, `x__y` and
	// `x_` produce an empty word and are rejected below. Collapsing them
	// instead would silently rename `_x` to `x`, and §4's rule is that an
	// unrepresentable name is an error the user resolves by setting the key —
	// never a rename we invent.
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '_' || ch == '-':
			words = append(words, cur.String())
			cur.Reset()
		case ch >= 'A' && ch <= 'Z':
			// A lower-to-upper transition starts a new word; a run of capitals
			// (URL) stays one word so that URLMatch does not become u-r-l-match.
			// cur is non-empty by construction here, so this cannot fabricate
			// an empty word.
			if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' {
				words = append(words, cur.String())
				cur.Reset()
			}
			cur.WriteByte(ch - 'A' + 'a')
		case (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'):
			cur.WriteByte(ch)
		default:
			return "", fmt.Errorf("contains %q, which cannot appear in a WIT identifier", string(rune(ch)))
		}
	}
	words = append(words, cur.String())
	out := strings.Join(words, "-")
	if err := validateWitIdent(out); err != nil {
		return "", err
	}
	return out, nil
}

// validateWitIdent checks the WIT identifier grammar:
// `[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*`. Every word must start with a letter, so
// a name whose first character is a digit (`9x`) or whose word is empty
// (`x__y`, a leading or trailing `_`) is rejected.
func validateWitIdent(s string) error {
	if s == "" {
		return fmt.Errorf("is empty")
	}
	for _, word := range strings.Split(s, "-") {
		if word == "" {
			return fmt.Errorf("has an empty word (WIT identifiers are lowercase words joined by single hyphens)")
		}
		if word[0] < 'a' || word[0] > 'z' {
			return fmt.Errorf("has the word %q, which does not start with a lowercase letter", word)
		}
		for i := 0; i < len(word); i++ {
			c := word[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
				return fmt.Errorf("contains %q, which cannot appear in a WIT identifier", string(rune(c)))
			}
		}
	}
	return nil
}
