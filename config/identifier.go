package config

import (
	"fmt"
	"path/filepath"
	"regexp/syntax"
	"sort"
	"strings"
)

// Identifier validation for user-supplied export names.
//
// Every `match_func` / `find_func` / `groups_func` value, every set capability
// value (`match_any`, `match_all`, `scan_any`, `scan_all`, `find`), and
// `namespace:`, is interpolated verbatim into generated source in all six stub
// languages (see generate/). Without a check, a config file can plant
// arbitrary code in the caller's crate/module.
//
// `named_groups_func` is RETIRED and `match` / `scan` /
// `find_batch` are retired set keys; all four
// are load errors, so none reaches this file.
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
// pattern. That is a different defect with a different
// symptom — duplicate map keys in the named-groups stub — and shares no code
// with this check.

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

// rustKeywords covers the 2015/2018/2021/2024 editions' strict keywords plus
// the reserved-for-future-use set (rejecting those keeps a name from breaking
// on a future edition bump in the caller's crate).
//
// `gen` is 2024's addition and was missing: a stub with
// `pub fn gen` compiles on 2021 and fails the moment the caller's crate moves
// to 2024, which is exactly the breakage the future-use list exists to prevent.
var rustKeywords = []string{
	"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else",
	"enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop",
	"match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
	"static", "struct", "super", "trait", "true", "type", "unsafe", "use",
	"where", "while",
	// 2024 edition.
	"gen",
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
	// Not reserved words, but restricted binding names: strict-mode code may
	// not bind either, and a generated ES module is always strict. So
	// `export function eval(...)` is a SyntaxError even though `eval` passes
	// every reserved-word list.
	"eval", "arguments",
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
	if name == "_" {
		// Shape-legal but not a NAME: `pub fn _` is invalid Rust, `func _()`
		// is invalid Go, and in JS it would silently become an ordinary
		// (shadowable) global.
		return fmt.Errorf("is the blank identifier, which is not a usable function name in Rust or Go")
	}
	if reservedWords[name] {
		return fmt.Errorf("is a reserved word in at least one stub language (Rust/Go/C/JS/TS/AS) and cannot be used as a generated function name")
	}
	return nil
}

// ValidateConfig checks every user-supplied export name in cfg, and the
// capture-group names of every entry that declares a groups_func. It
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
		} {
			if f.name == "" {
				continue
			}
			if err := ValidateIdentifier(f.name); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s %q %v", owner, f.field, f.name, err))
			}
		}
		if re.GroupsFunc != "" {
			for _, problem := range captureNameProblems(re.Pattern) {
				problems = append(problems, fmt.Sprintf("%s: %s", owner, problem))
			}
		}
	}

	for _, s := range cfg.Sets {
		owner := fmt.Sprintf("set %q", s.Name)
		for _, c := range s.Capabilities() {
			if err := ValidateIdentifier(c.Name); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s %q %v", owner, c.Field, c.Name, err))
			}
		}
	}

	// `name:` reaches generated source as a STRING LITERAL when
	// `emit_name_map` is on, quoted with Go's %q — whose escapes (\x00,
	// \u00e9) are not valid in every one of the six languages, and whose
	// output for a control character is a sequence C and AssemblyScript read
	// differently from Go. Restricting the value to printable ASCII without a
	// quote or backslash makes %q's output identical in all six.
	emitsNames := false
	for _, sc := range cfg.Sets {
		if sc.EmitNameMap {
			emitsNames = true
			break
		}
	}
	if emitsNames {
		for _, re := range cfg.Regexps {
			for i := 0; i < len(re.Name); i++ {
				if c := re.Name[i]; c < 0x20 || c > 0x7E || c == '"' || c == '\\' {
					problems = append(problems, fmt.Sprintf(
						"regexp name %q contains %q at offset %d, which cannot be emitted as a string literal in all six stub languages (emit_name_map is on)",
						re.Name, string(rune(c)), i))
					break
				}
			}
		}
	}

	// `namespace:` is interpolated VERBATIM into generated identifiers in
	// Go/JS/TS/AS/C — `derivedFuncName(cfg.Namespace, name)` at every shared
	// symbol — so it is exactly the injection vector every _func value is
	// shape-checked for. It was not checked at all: `namespace: "x; } func
	// pwn() {"` planted code in the caller's package, and the merely-wrong
	// `my-ns` or `9x` produced a file that does not parse.
	if cfg.Namespace != "" {
		if err := ValidateIdentifier(cfg.Namespace); err != nil {
			problems = append(problems, fmt.Sprintf("namespace %q %v", cfg.Namespace, err))
		}
	}

	// Per-stub-type checks (B32, B34). These depend on which generator the
	// config targets, so they are skipped entirely when it targets none — a
	// compile-only config (no stub_type, no stub_file) generates no source and
	// cannot be broken by any of them.
	if stubType, err := ResolveStubType(*cfg); err == nil {
		problems = append(problems, validateImportModule(cfg, stubType)...)
		problems = append(problems, validateExportsForStubType(cfg, stubType)...)
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
// observable output where the NAMES are used — the generated index constants
// and the name->index lookup, which `groups_func` carries
// retired `named_groups_func` — so ValidateConfig applies this check to
// groups_func entries only, rather than rejecting a pattern that is legal and
// unambiguous everywhere else.
//
// A pattern that fails to parse yields no duplicates: reporting the syntax
// error is compile's job, and doing it here too would double up the message.
func captureNameProblems(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	var names []string
	seen := make(map[string]int)
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture && r.Name != "" {
			if seen[r.Name] == 0 {
				names = append(names, r.Name)
			}
			seen[r.Name]++
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)

	var problems []string

	// 1. Exact duplicates. regexp/syntax ACCEPTS these — verified: it parses
	//    `(?P<a>x)(?P<a>y)` with a nil error — so nothing upstream catches it.
	var duplicates []string
	for name, n := range seen {
		if n > 1 {
			duplicates = append(duplicates, name)
		}
	}
	sort.Strings(duplicates)
	for _, name := range duplicates {
		problems = append(problems, fmt.Sprintf("capture group name %q is used more than once; "+
			"group names become generated constants and a name→index lookup, so only one group of that name would be reachable", name))
	}

	// NOT checked: reserved words. A group name never stands alone as an
	// identifier — every language prefixes it with the function's name
	// (`url_groups_type`) or uses it as a JS/TS object KEY, where a reserved
	// word is legal. An earlier version of this check rejected `(?P<type>…)`,
	// which is a perfectly good group name and is used by one of this repo's
	// own examples.
	//
	// Nor the character set: regexp/syntax already refuses anything that is
	// not a word character — verified, `(?P<a b>x)` and `(?P<a-b>x)` are parse
	// errors — and a leading digit is fine once prefixed. A DIGIT-LEADING name
	// used to be a JS/TS hazard for the second reason above (`{ 1a: 3 }` is a
	// SyntaxError, not a legal key); the generators now quote every key, so
	// the waiver holds for that too.

	// 2. Names that collide with the SUFFIXES a generator derives from the
	//    same function's name. `groups_func: url` emits `url_count`,
	//    `url_index`, `url_names` (and `url_indices` in JS/TS) alongside one
	//    constant per named group — so a group called `index` makes
	//    derivedConstName("url","index") and derivedFuncName("url","index")
	//    the same symbol, declared twice in one file.
	var reservedSuffix []string
	for _, name := range names {
		switch name {
		case "index", "names", "count", "indices", "iter":
			reservedSuffix = append(reservedSuffix, name)
		}
	}
	sort.Strings(reservedSuffix)
	for _, name := range reservedSuffix {
		problems = append(problems, fmt.Sprintf("capture group name %q is one of the suffixes the stub generators derive from the groups_func name "+
			"(<func>_index, <func>_names, <func>_count, <func>_indices, <func>_iter), so its constant would collide with the generated helper of the same name", name))
	}

	// 3. Names that COLLIDE after sanitising. `host` and `Host` are two
	//    distinct groups to regexp/syntax — verified, both parse — but one
	//    constant stem, so a generated stub would define the same symbol twice.
	stems := make(map[string][]string)
	for _, name := range names {
		stem := strings.ToUpper(name)
		stems[stem] = append(stems[stem], name)
	}
	var collided []string
	for stem := range stems {
		if len(stems[stem]) > 1 {
			collided = append(collided, stem)
		}
	}
	sort.Strings(collided)
	for _, stem := range collided {
		group := append([]string(nil), stems[stem]...)
		sort.Strings(group)
		problems = append(problems, fmt.Sprintf("capture group names %s differ only in case and collapse to one generated constant stem %q",
			strings.Join(quoteAll(group), " and "), stem))
	}
	return problems
}

// quoteAll quotes each name for an error message.
func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

// ---------------------------------------------------------------------------
// Per-stub-type validation
//
// The `_func` / set-export rule above is deliberately language-agnostic: a name
// legal today must not become a compile error the moment stub_type changes.
// The checks below are the opposite — they are about the *one* generator a
// config actually targets, and enforcing them across all six would reject
// configs that are perfectly fine. Two concrete reasons this distinction was
// drawn (decision 2026-08-20):
//
//   - `import_module: "my-mod"` is invalid Rust (`pub mod my-mod`) and invalid
//     Go (`package my-mod`), but a JS/TS stub never emits it at all, so a
//     hyphenated module name is legitimate for a JS/TS config.
//   - The generators emit different helper names and apply different name
//     transforms, so the collision surface is genuinely per-language.
//
// Everything here is keyed off ResolveStubType(cfg). A config with neither
// stub_type nor a stub_file extension generates nothing, so none of it applies.

// stubSharedSymbols MIRRORS generate.sharedSymbols — the identifiers a
// generated file declares that the user did not name, and therefore the ones
// two stubs in one package collide on and `namespace:` rewrites.
//
// It is a mirror rather than the original because generate imports config and
// not the reverse. generate pins the two against each other
// (TestSharedSymbolsMirrorIsInStep), which is the only thing that keeps a copy
// honest.
var stubSharedSymbols = map[string][]string{
	"go": {"Span", "ErrBacktrackOverflow", "SetMatch", "PatternName"},
	"js": {"patternName"},
	"ts": {"SetMatch", "patternName"},
	"as": {"SetMatch", "patternName", "RX_ERR_BT_OVERFLOW", "RX_ITER_ERROR"},
	"c": {
		"rx_match_t", "rx_group_t", "rx_set_match_t", "pattern_name",
		"RX_ERR_BT_OVERFLOW", "RX_ERR_NULL_ARG", "RX_ERR_RANGE",
		"REGEXPED_TYPES_DEFINED",
	},
	// Rust is deliberately absent from the SHARED list for the same reason it
	// is in generate: `pub mod <import_module>` isolates every stub. Its own
	// declarations are still denied below.
}

// stubPrivateHelpers are the other module-scope names a generator emits that a
// user export can duplicate: file-private helpers, and declarations the
// namespace key does not rewrite.
//
// The JS/TS list is the real set of top-level names genJSStubFile emits, not a
// sample. It was three renames out of date — `_w`, `_resize`, `_inBase` and
// `_outBase` are gone and eleven helpers were missing — which is exactly the
// drift this check exists to prevent.
//
// Names are denied unconditionally rather than conditioned on the current set
// list: otherwise a config that generates fine today starts failing when a set
// is added later, the churn this whole file exists to prevent.
var stubPrivateHelpers = map[string][]string{
	"js": {
		"init", "_exp", "_mem", "_staticTop", "_bump", "_live", "_enc",
		"_align", "_grow", "_inCap", "_write", "_stage", "_open", "_close",
		"_att", "_patternNames",
	},
	// Go declares no private helpers of its own, but `init` is reserved by the
	// LANGUAGE: `func init(input []byte) (uint, bool, error)` is a compile
	// error, since Go's init takes no arguments and returns nothing.
	"go":   {"init"},
	"rust": {"Span", "Error", "Result", "SetMatch"},
	"as":   {"Span"},
}

func init() { stubPrivateHelpers["ts"] = stubPrivateHelpers["js"] }

// stubHelperNames is every module-scope name stubType's generator declares for
// itself: the shared symbols plus the private helpers.
func stubHelperNames(stubType string) []string {
	out := append([]string(nil), stubSharedSymbols[stubType]...)
	return append(out, stubPrivateHelpers[stubType]...)
}

// StubSharedSymbolsForValidation exposes the mirror above so the generate
// package can pin it against the list the generators really use. Not part of
// the config API otherwise.
func StubSharedSymbolsForValidation(stubType string) []string {
	return append([]string(nil), stubSharedSymbols[stubType]...)
}

// rustTransformedReserved are names the Rust generator's PascalCase transform
// can produce a collision with. Rust's iterator types get an "Iter" suffix, so
// only the verbatim struct name can collide.
var rustTransformedReserved = []string{"SetMatch"}

// ResolveStubType determines the stub type from cfg.StubType or the extension
// of cfg.StubFile. Returns one of "rust", "go", "js", "ts", "c", "as", or an
// error. generate.ResolveStubType delegates here so validation and generation
// can never disagree about which language a config targets.
func ResolveStubType(cfg BuildConfig) (string, error) {
	if cfg.StubType != "" {
		switch cfg.StubType {
		case "rust", "js", "ts", "go", "c", "as":
			return cfg.StubType, nil
		default:
			return "", fmt.Errorf("unknown stub_type %q (expected rust, js, ts, go, c, or as)", cfg.StubType)
		}
	}
	switch strings.ToLower(filepath.Ext(cfg.StubFile)) {
	case ".rs":
		return "rust", nil
	case ".js":
		return "js", nil
	case ".ts":
		return "ts", nil
	case ".go":
		return "go", nil
	case ".h":
		return "c", nil
	default:
		return "", fmt.Errorf("cannot infer stub type from %q: set stub_type in config (rust, js, ts, go, c, or as)", cfg.StubFile)
	}
}

// exportRef is one user-supplied export name together with a human-readable
// description of where it came from, for error messages.
type exportRef struct {
	owner string // e.g. `regexp "url"` or `set "keywords"`
	field string // e.g. "find_func"
	name  string
}

// allExportRefs returns every user-supplied export name in cfg, in config
// order. Empty fields are skipped.
func allExportRefs(cfg *BuildConfig) []exportRef {
	var refs []exportRef
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
		} {
			if f.name != "" {
				refs = append(refs, exportRef{owner, f.field, f.name})
			}
		}
	}
	for _, s := range cfg.Sets {
		owner := fmt.Sprintf("set %q", s.Name)
		for _, c := range s.Capabilities() {
			refs = append(refs, exportRef{owner, c.Field, c.Name})
		}
	}
	return refs
}

// validateIdentShape applies only the character-shape rule, without the
// reserved-word union. Used by the per-language import_module checks, which
// need their own language's keyword list rather than the union.
func validateIdentShape(name string) error {
	if name == "" {
		return fmt.Errorf("must not be empty")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return fmt.Errorf("must not start with a digit (allowed: ASCII letters, digits and underscore, not starting with a digit)")
			}
		default:
			return fmt.Errorf("contains invalid character %q at offset %d (allowed: ASCII letters, digits and underscore, not starting with a digit)", string(name[i]), i)
		}
	}
	return nil
}

// keywordSets maps a stub type to that language's own keyword set, for the
// checks that must not use the cross-language union.
var keywordSets = map[string]map[string]bool{}

func init() {
	add := func(k string, lists ...[]string) {
		m := map[string]bool{}
		for _, l := range lists {
			for _, w := range l {
				m[w] = true
			}
		}
		keywordSets[k] = m
	}
	add("rust", rustKeywords)
	add("go", goKeywords)
	add("c", cKeywords)
	add("js", jsKeywords)
	add("ts", jsKeywords, tsKeywords)
	add("as", jsKeywords, tsKeywords)
}

// validateImportModule checks cfg.ImportModule against the requirements of the
// one generator stubType selects.
//
//   - rust: emitted as `pub mod <name>` — needs a real Rust identifier.
//   - go:   emitted as `package <name>` when the stub lands in a directory of
//     that name (generate/go_stub.go:17-20) — needs a real Go identifier.
//   - c/as: emitted only inside a quoted attribute string
//     (`import_module("<name>")`, `@external("<name>", …)`) — anything that
//     cannot survive a C/TS string literal breaks the file, and a bare `"` is
//     an injection vector.
//   - js/ts: never emitted. No constraint at all.
func validateImportModule(cfg *BuildConfig, stubType string) []string {
	name := cfg.ImportModule
	if name == "" {
		return nil // required-ness is main.go's check, not this one
	}
	switch stubType {
	case "rust", "go":
		if err := validateIdentShape(name); err != nil {
			return []string{fmt.Sprintf("import_module %q %v (it is emitted as a %s identifier for stub_type %q)",
				name, err, map[string]string{"rust": "`pub mod`", "go": "`package`"}[stubType], stubType)}
		}
		if keywordSets[stubType][name] {
			return []string{fmt.Sprintf("import_module %q is a reserved word in %s, and is emitted as a %s identifier",
				name, stubType, map[string]string{"rust": "`pub mod`", "go": "`package`"}[stubType])}
		}
	case "c", "as":
		for i := 0; i < len(name); i++ {
			if c := name[i]; c == '"' || c == '\\' || c < 0x20 || c == 0x7F {
				return []string{fmt.Sprintf("import_module %q contains %q at offset %d, which cannot appear in the quoted import attribute the %s generator emits",
					name, string(rune(c)), i, stubType)}
			}
		}
	}
	return nil
}

// validateExportsForStubType applies the collision checks that are specific to
// one generator.
func validateExportsForStubType(cfg *BuildConfig, stubType string) []string {
	var problems []string
	refs := allExportRefs(cfg)

	// (1) Collisions with names the generator emits for itself. Every language
	// including C and Go, which had no such check at all: `rx_match_t` and
	// `pattern_name` are valid C identifiers, and an export named `Span` was a
	// duplicate Go type declaration nothing diagnosed.
	{
		deny := map[string]bool{}
		for _, h := range stubHelperNames(stubType) {
			deny[h] = true
		}
		for _, r := range refs {
			if deny[r.name] {
				problems = append(problems, fmt.Sprintf("%s: %s %q collides with a name the %s stub generator emits itself; pick another name",
					r.owner, r.field, r.name, stubType))
			}
		}
	}

	// (2) Collisions with the generated private FFI binding. Rust emits
	// `ffi_<export>` alongside `pub fn <export>`, and Go emits `ffi_<export>`
	// for the //go:wasmimport shim, so an export literally named `ffi_x`
	// duplicates the shim generated for an export named `x`.
	if stubType == "rust" || stubType == "go" {
		for _, r := range refs {
			if strings.HasPrefix(r.name, "ffi_") {
				problems = append(problems, fmt.Sprintf("%s: %s %q must not start with \"ffi_\": the %s generator emits ffi_<export> for its private FFI binding, so this name can collide with the shim for export %q",
					r.owner, r.field, r.name, stubType, strings.TrimPrefix(r.name, "ffi_")))
			}
		}
	}

	// (3) Collisions created by the RUST generator's name transform: two
	// exports differing only in shape (`a_b` and `aB`) collapse to one
	// PascalCase iterator TYPE (`ABIter`), so both cannot exist in one module.
	//
	// GO IS NOT HERE. Its names have been verbatim so
	// Pascal-folding them rejected valid configs (`url_match` + `urlMatch` are
	// two perfectly good Go functions) while MISSING the collision Go really
	// has — an export literally named `fooIter` against the `type fooIter`
	// that `find_func: foo` declares. That is check (3b) below.
	if stubType == "rust" {
		seen := map[string]exportRef{}
		for _, r := range refs {
			// The iterator type, not the function: two exports may share a
			// PascalCase form without colliding unless both declare one.
			pub := pascalCase(r.name)
			if prior, dup := seen[pub]; dup {
				problems = append(problems, fmt.Sprintf("%s: %s %q and %s %s %q are distinct WASM exports but both generate %s %q; rename one",
					r.owner, r.field, r.name, prior.owner, prior.field, prior.name, stubType, pub+"Iter"))
				continue
			}
			seen[pub] = r
			for _, res := range rustTransformedReserved {
				if pub == res {
					problems = append(problems, fmt.Sprintf("%s: %s %q generates %s %q, which is the name of a type the %s stub generator declares for sets",
						r.owner, r.field, r.name, stubType, pub, stubType))
				}
			}
		}
	}

	// (3b) Go's real collision surface, compared VERBATIM. Every find or
	// groups export X also declares `type XIter`; an export literally named
	// XIter duplicates it. AssemblyScript has the same shape with a
	// PascalCase iterator name.
	if stubType == "go" || stubType == "as" {
		iterOf := func(name string) string {
			if stubType == "as" {
				return pascalCase(name) + "Iter"
			}
			return name + "Iter"
		}
		deny := map[string]exportRef{}
		for _, r := range refs {
			if r.field == "find_func" || r.field == "groups_func" || r.field == "find" {
				deny[iterOf(r.name)] = r
			}
		}
		for _, r := range refs {
			emitted := r.name
			if stubType == "as" {
				emitted = pascalCase(r.name)
			}
			if owner, clash := deny[emitted]; clash && owner.name != r.name {
				problems = append(problems, fmt.Sprintf("%s: %s %q collides with the iterator type the %s generator declares for %s %s %q; rename one",
					r.owner, r.field, r.name, stubType, owner.owner, owner.field, owner.name))
			}
		}
	}

	// (4) Collisions with the constants a generator derives from a SET NAME.
	// Unlike (1), these are not a fixed list: `<SET>_PATTERN_COUNT` and its
	// three siblings are built from the set's own name, so what is reserved
	// depends on the config. Without this check a TS config with a set named
	// `scanner` and a capability exported as `scannerPatternCount` passes
	// validation and then emits both `export const scannerPatternCount` and
	// `export function scannerPatternCount`, which tsc rejects with no
	// diagnostic from us. See setDerivedNames for why all four are reserved
	// even when the set declares no find_batch.
	//
	// Compared against the same form the generator emits the export under,
	// which is the export name VERBATIM in every language.
	{
		deny := map[string]SetConfig{}
		for _, s := range cfg.Sets {
			for _, n := range setDerivedNames(s, stubType) {
				deny[n] = s
			}
		}
		for _, r := range refs {
			// Every generator emits the export name VERBATIM, Go included
			// verbatim — the Pascal-cased comparison that used to
			// live here flagged names verbatim emission cannot collide.
			emitted := r.name
			if s, clash := deny[emitted]; clash {
				problems = append(problems, fmt.Sprintf("%s: %s %q generates %s %q, which is also the name of a constant the %s stub generator derives from set %q; rename one",
					r.owner, r.field, r.name, stubType, emitted, stubType, s.Name))
			}
		}
	}

	// (5) Collisions with symbols a generator DERIVES from another export's
	// name. `groups_func: parse` emits parse_count / parse_index / parse_names
	// (+ parse_indices in JS/TS, parse_iter in AS); a second entry with
	// `match_func: parse_index` passes every check above and then duplicates
	// the symbol, with no diagnostic from us.
	//
	// Derived from find/groups exports only — a match_func contributes no
	// derived symbols — and skipped for Rust, whose per-stub `pub mod` does
	// NOT isolate these (they are inside the same module) but whose derived
	// names follow the same rule, so the same list serves.
	{
		deny := map[string]exportRef{}
		for _, r := range refs {
			for _, suf := range derivedExportSuffixes(r.field, stubType) {
				deny[derivedName(r.name, suf)] = r
			}
		}
		for _, r := range refs {
			if owner, clash := deny[r.name]; clash && owner.name != r.name {
				problems = append(problems, fmt.Sprintf("%s: %s %q collides with a symbol the %s generator derives from %s %s %q; rename one",
					r.owner, r.field, r.name, stubType, owner.owner, owner.field, owner.name))
			}
		}
	}

	return problems
}

// derivedExportSuffixes lists the suffixes stubType's generator appends to one
// export's name. Mirrors the derivedConstName/derivedFuncName call sites in
// generate/{rust,go,c,as,js,ts}_stub.go.
func derivedExportSuffixes(field, stubType string) []string {
	switch field {
	case "groups_func":
		switch stubType {
		case "js", "ts":
			return []string{"indices"}
		case "as":
			return []string{"count", "index", "names", "iter"}
		default:
			return []string{"count", "index", "names"}
		}
	case "find_func", "find":
		if stubType == "as" {
			return []string{"iter"}
		}
		return nil
	}
	return nil
}

// derivedName reproduces generate.derivedFuncName: a name in the base's own
// style, snake_case appending `_suffix` and camelCase appending `Suffix`.
// Pinned against the generator by TestDerivedNameMatchesGenerator.
func derivedName(base, suffix string) string {
	if suffix == "" {
		return base
	}
	if isCamelStyleName(base) {
		return base + strings.ToUpper(suffix[:1]) + suffix[1:]
	}
	return base + "_" + suffix
}

// isCamelStyleName mirrors generate.isCamelStyle: an underscore anywhere
// settles a name as snake, otherwise an uppercase letter after the first
// character settles it as camel.
func isCamelStyleName(name string) bool {
	if strings.Contains(name, "_") {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return true
		}
	}
	return false
}

// The three set-name stem transforms. Each generator names its per-set
// constants by applying one of these to SanitizeSetName(set.Name); they live
// here, and generate/set_stub.go delegates to them, for the reason
// SanitizeSetName gives — a transform each side derives independently is a
// transform that can drift, and setDerivedNames below has to reproduce the
// generators' output EXACTLY or the check it feeds is theatre.

// ScreamingSetName returns the SCREAMING_SNAKE_CASE stem the Rust, C and
// AssemblyScript generators build their per-set constants from, inserting an
// underscore at lower→upper transitions so "sqlValidator" becomes
// "SQL_VALIDATOR" rather than "SQLVALIDATOR".
func ScreamingSetName(name string) string {
	base := SanitizeSetName(name)
	var out []rune
	for i, c := range base {
		if i > 0 && c >= 'A' && c <= 'Z' {
			prev := rune(base[i-1])
			if prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9' {
				out = append(out, '_')
			}
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// PascalSetName returns the PascalCase stem the Go generator uses.
func PascalSetName(name string) string { return pascalCase(SanitizeSetName(name)) }

// CamelSetName returns the camelCase stem the JS and TS generators use.
func CamelSetName(name string) string {
	p := PascalSetName(name)
	if p == "" {
		return p
	}
	r := []rune(p)
	if r[0] >= 'A' && r[0] <= 'Z' {
		r[0] += 'a' - 'A'
	}
	return string(r)
}

// setDerivedNames returns the module-scope names stubType's generator
// synthesizes from one set's NAME — the pattern-count and id-space constants,
// plus JS/TS's batch-size limit.
//
// The batch constant is reserved whether or not the set carries
// `hints: [batch-find]` today, for the reason jsHelperNames denies its list
// unconditionally: conditioning the check on the hint would mean ADDING the
// hint to a working config turns a valid export name into a collision.
//
// It is reserved in every language even though only JS/TS emits it. Decision
// (11) keys batching on the hint and never on stub_type, precisely so that
// changing stub_type cannot break a working config — reserving the name in
// only two of the six would reintroduce exactly that.
//
// This check cannot be name-independent the way the others are: what a set is
// called decides what its constants are called, so unlike the helper lists this
// one has to be computed from cfg.Sets.
func setDerivedNames(s SetConfig, stubType string) []string {
	var stem string
	var suffixes []string
	switch stubType {
	case "rust", "c", "as":
		stem, suffixes = ScreamingSetName(s.Name), []string{
			"_PATTERN_COUNT", "_ID_SPACE", "_BATCH_MAX_SIZE"}
	case "go":
		stem, suffixes = PascalSetName(s.Name), []string{
			"PatternCount", "IDSpace", "BatchMaxSize"}
	case "js", "ts":
		stem, suffixes = CamelSetName(s.Name), []string{
			"PatternCount", "IdSpace", "BatchMaxSize"}
	default:
		return nil
	}
	out := make([]string, len(suffixes))
	for i, suf := range suffixes {
		out[i] = stem + suf
	}
	return out
}

// SetDerivedNamesForValidation exposes setDerivedNames so the generate package
// — which can import config, but not the reverse — can pin this list against
// the constants the generators really emit. The stems cannot drift (the
// generators call the transforms above), but the four SUFFIXES are written out
// on both sides, and a reserved name that no generator emits is as broken as an
// emitted one that is not reserved. Not part of the config API otherwise.
func SetDerivedNamesForValidation(s SetConfig, stubType string) []string {
	return setDerivedNames(s, stubType)
}

// PascalCaseForValidation exposes pascalCase so the generate package — which
// can import config, but not the reverse — can pin this copy against the real
// goPublicName/iterTypeName transforms. Not part of the config API otherwise.
func PascalCaseForValidation(s string) string { return pascalCase(s) }

// pascalCase mirrors generate.goPublicName and generate.iterTypeName (minus the
// "Iter" suffix): underscores are dropped and the following letter uppercased.
// It must stay in step with them — it exists here only because config cannot
// import generate. generate's TestConfigPascalCaseMatchesGenerators enforces
// that.
func pascalCase(s string) string {
	var b strings.Builder
	upper := true
	for _, c := range s {
		if c == '_' {
			upper = true
			continue
		}
		if upper {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			upper = false
		}
		b.WriteRune(c)
	}
	return b.String()
}

// DerivedNameForValidation exposes derivedName so the generate package can pin
// it against generate.derivedFuncName. See StubSharedSymbolsForValidation for
// why the copy exists at all. Not part of the config API otherwise.
func DerivedNameForValidation(base, suffix string) string { return derivedName(base, suffix) }
