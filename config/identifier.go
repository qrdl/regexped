package config

import (
	"fmt"
	"regexp/syntax"
	"sort"
	"strings"
)

// Identifier validation for user-supplied export names.
//
// Every `match_func` / `find_func` / `groups_func` / `named_groups_func` value,
// and every set's `find_any` / `find_all` / `match` value, is interpolated
// verbatim into generated source in all six stub languages (see generate/).
// Without a check, a config file can plant arbitrary code in the caller's
// crate/module — see plans/OPUS.md §N4, where this is demonstrated end to end.
//
// The rules, agreed 2026-08-17:
//
//   - Shape: ^[A-Za-z_][A-Za-z0-9_]*$, ASCII only, regardless of what the
//     configured stub_type would itself accept. Rust, Go, JS and TS all permit
//     non-ASCII identifiers; C and AssemblyScript are narrower. One common
//     denominator is simpler to reason about than six.
//   - Reserved words: the union across all six stub languages, applied
//     regardless of stub_type. A name that is legal today would otherwise
//     become a compile error in the caller's project the moment stub_type
//     changes.
//   - Violations are a hard error before any compile or generate work.
//
// Deliberately NOT validated: `regexps[].name` and `sets[].name`. Those are
// selection keys, and they reach generated code only as quoted string literals
// (%q) in the optional name-map helpers — not as identifiers. Applying the
// reserved-word rule to them would reject shipped configs such as
// examples/node/sql-validator/regexped.yaml, whose pattern names include
// "select" (a Go keyword) and "delete" (a JS keyword), for no benefit.
//
// Also deliberately out of scope: duplicate named capture groups within a
// pattern (IMPROVEMENT_PLAN #14). That is a different defect with a different
// symptom — duplicate map keys in the named-groups stub — and shares no code
// with this check. See plans/OPUS.md §N4.

// reservedWords is the union of reserved words across the six stub languages
// regexped can emit: Rust, Go, C, JavaScript, TypeScript and AssemblyScript.
//
// The union is intentional: an export name is written into whichever language
// stub_type selects, and a config that compiles today should not start failing
// because stub_type changed. `match` is in here for exactly that reason — it is
// a Rust keyword, and the Rust generator emits `pub fn <func>` for the public
// wrapper, so a func named "match" produces invalid Rust today with no
// diagnostic (only the FFI declaration is protected, by its ffi_ prefix and
// #[link_name]).
//
// Contextual/soft keywords that are legal identifiers in their language (TS's
// `type`, `from`, `of`, `get`, `set`, `string`, `number`; Go's predeclared
// `len`, `cap`, `new`) are NOT included: they compile fine as function names,
// and rejecting them would be over-reach rather than safety.
var reservedWords = map[string]bool{}

func init() {
	for _, list := range [][]string{rustKeywords, goKeywords, cKeywords, jsKeywords, tsKeywords} {
		for _, w := range list {
			reservedWords[w] = true
		}
	}
}

// rustKeywords covers the 2015/2018/2021 editions' strict keywords plus the
// reserved-for-future-use set (rejecting those keeps a name from breaking on a
// future edition bump in the caller's crate).
var rustKeywords = []string{
	"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else",
	"enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop",
	"match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
	"static", "struct", "super", "trait", "true", "type", "unsafe", "use",
	"where", "while",
	// Reserved for future use.
	"abstract", "become", "box", "do", "final", "macro", "override", "priv",
	"try", "typeof", "unsized", "virtual", "yield",
}

// goKeywords is Go's complete 25-keyword set (spec: Keywords).
var goKeywords = []string{
	"break", "case", "chan", "const", "continue", "default", "defer", "else",
	"fallthrough", "for", "func", "go", "goto", "if", "import", "interface",
	"map", "package", "range", "return", "select", "struct", "switch", "type",
	"var",
}

// cKeywords is C11 plus the C23 additions. The generated C stub is a header
// compiled by the caller's toolchain, so the newer set applies.
var cKeywords = []string{
	"auto", "break", "case", "char", "const", "continue", "default", "do",
	"double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
	"int", "long", "register", "restrict", "return", "short", "signed",
	"sizeof", "static", "struct", "switch", "typedef", "union", "unsigned",
	"void", "volatile", "while",
	"_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
	"_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
	// C23.
	"alignas", "alignof", "bool", "constexpr", "false", "nullptr",
	"static_assert", "thread_local", "true", "typeof",
}

// jsKeywords is ECMAScript's reserved-word set, including the strict-mode
// reserved words (the generated ES modules are strict by definition).
var jsKeywords = []string{
	"await", "break", "case", "catch", "class", "const", "continue", "debugger",
	"default", "delete", "do", "else", "enum", "export", "extends", "false",
	"finally", "for", "function", "if", "import", "in", "instanceof", "new",
	"null", "return", "super", "switch", "this", "throw", "true", "try",
	"typeof", "var", "void", "while", "with", "yield",
	// Strict-mode reserved.
	"implements", "interface", "let", "package", "private", "protected",
	"public", "static",
}

// tsKeywords are the TypeScript/AssemblyScript reserved words that JS does not
// already cover. AssemblyScript is a TypeScript dialect, so its reserved set is
// TS's; its builtin numeric types (i32, u32, f64, v128, …) are type aliases
// rather than keywords and are omitted for the same reason Go's predeclared
// identifiers are.
var tsKeywords = []string{
	"abstract", "declare", "is", "namespace", "readonly", "require",
}

// ValidateIdentifier reports whether name is usable as a generated function
// name in every stub language. See the package comment above for the rules.
func ValidateIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("must not be empty")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			// Always allowed.
		case c >= '0' && c <= '9':
			if i == 0 {
				return fmt.Errorf("must not start with a digit (allowed: ASCII letters, digits and underscore, not starting with a digit)")
			}
		default:
			return fmt.Errorf("contains invalid character %q at offset %d (allowed: ASCII letters, digits and underscore, not starting with a digit)", string(name[i]), i)
		}
	}
	if reservedWords[name] {
		return fmt.Errorf("is a reserved word in at least one stub language (Rust/Go/C/JS/TS/AS) and cannot be used as a generated function name")
	}
	return nil
}

// ValidateConfig checks every user-supplied export name in cfg, and the
// capture-group names of every entry that declares a named_groups_func. It
// reports all violations found rather than stopping at the first, so a config
// with several bad names is fixable in one pass.
//
// Called from LoadConfig, i.e. on the config-file path only. It is deliberately
// NOT called from compile.Compile / compile.CompileFile: the internal
// benchmark and test harnesses (tools/re2test, perftest, likelytest, pattest,
// fuzz, and the compile package's own tests) build config.RegexEntry values
// directly and use bare names such as "match", "find" and "groups". The threat
// model here is a checked-in regexped.yaml, which this placement covers.
func ValidateConfig(cfg *BuildConfig) error {
	var problems []string

	for _, re := range cfg.Regexps {
		owner := "regexp"
		if re.Name != "" {
			owner = fmt.Sprintf("regexp %q", re.Name)
		} else if re.Pattern != "" {
			owner = fmt.Sprintf("regexp %q", re.Pattern)
		}
		for _, f := range []struct{ field, name string }{
			{"match_func", re.MatchFunc},
			{"find_func", re.FindFunc},
			{"groups_func", re.GroupsFunc},
			{"named_groups_func", re.NamedGroupsFunc},
		} {
			if f.name == "" {
				continue
			}
			if err := ValidateIdentifier(f.name); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s %q %v", owner, f.field, f.name, err))
			}
		}
		if re.NamedGroupsFunc != "" {
			for _, dup := range duplicateCaptureNames(re.Pattern) {
				problems = append(problems, fmt.Sprintf("%s: capture group name %q is used more than once; "+
					"named_groups_func maps names to slots, so only the last group of that name would be reachable", owner, dup))
			}
		}
	}

	for _, s := range cfg.Sets {
		owner := fmt.Sprintf("set %q", s.Name)
		for _, f := range []struct{ field, name string }{
			{"find_any", s.FindAny},
			{"find_all", s.FindAll},
			{"match", s.Match},
		} {
			if f.name == "" {
				continue
			}
			if err := ValidateIdentifier(f.name); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s %q %v", owner, f.field, f.name, err))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid config:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// duplicateCaptureNames returns, in sorted order, the capture-group names that
// appear more than once in pattern.
//
// regexp/syntax accepts duplicate names — `(?P<a>x)(?P<a>y)` parses without
// error — but generate.collectNamedGroups builds a name→slot map, so a repeated
// name silently resolves to whichever group is visited last. That only changes
// observable output for named_groups_func (groups_func is positional and
// match_func / find_func ignore captures), so ValidateConfig applies this check
// to named_groups_func entries only, rather than rejecting a pattern that is
// legal and unambiguous everywhere else.
//
// A pattern that fails to parse yields no duplicates: reporting the syntax
// error is compile's job, and doing it here too would double up the message.
func duplicateCaptureNames(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	counts := make(map[string]int)
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture && r.Name != "" {
			counts[r.Name]++
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)

	var dups []string
	for name, n := range counts {
		if n > 1 {
			dups = append(dups, name)
		}
	}
	sort.Strings(dups)
	return dups
}
