package generate

import (
	"fmt"
	"strings"

	"github.com/qrdl/regexped/config"
)

// WIT generation for SETS under `wasm_format: component`.
//
// Sets live in a SECOND interface, `sets`, beside `matcher`. Keeping them apart
// is what lets a consumer bind only what it uses, and it is the same rule the
// single-pattern interface follows: one interface, one concern.
//
// The names are the config's own, exactly as for patterns — `match_any: hits`
// becomes `hits`, not `<set>-match-any`. A generated name would be a second
// naming scheme for a user to learn, and the project's rule since the stub
// rewrite is that a configured name reaches the output verbatim (kebab-cased
// here, because WIT identifiers cannot carry an underscore).
//
// `find` is the exception, and not by choice: it is a RESOURCE, because the
// drive it feeds needs state that outlives one call (§9.2). The resource takes
// the configured name and its method is `next`, so `find: scan_secrets` becomes
// `resource scan-secrets { constructor(...); next: ... }`.

// witSetCap is one stateless set capability as a WIT function.
type witSetCap struct {
	kebab  string // WIT name
	origin string // the config value it came from
	field  string // match_any / match_all / scan_any / scan_all
	doc    string
	sig    string
}

// witSet is one `sets:` entry as WIT.
type witSet struct {
	name     string      // the set's own name, for error messages
	caps     []witSetCap // the stateless capabilities, in config order
	resource string      // kebab name of the find resource, "" when find is not declared
	findOrig string      // the configured `find:` name behind that resource
}

// witSets maps cfg.Sets onto WIT, rejecting anything unrepresentable rather
// than mangling it. `claimed` carries the kebab names already taken by the
// matcher interface's functions: a collision ACROSS interfaces is legal WIT but
// a trap for a reader, and for a generated stub it is a duplicate symbol.
func witSets(cfg config.BuildConfig, claimed map[string]witFunc) ([]witSet, error) {
	if len(cfg.Sets) == 0 {
		return nil, nil
	}
	seen := map[string]string{} // kebab -> the config value that claimed it
	for k, f := range claimed {
		seen[k] = f.origin
	}
	var out []witSet

	for _, s := range cfg.Sets {
		ws := witSet{name: s.Name}
		for _, c := range s.Capabilities() {
			kebab, err := config.KebabIdent(c.Name)
			if err != nil {
				return nil, fmt.Errorf("set %q: %s %q cannot be used as a WIT name (%v): rename it, or use wasm_format: module",
					s.Name, c.Field, c.Name, err)
			}
			if prev, dup := seen[kebab]; dup {
				return nil, fmt.Errorf("set %q: %s %q and %q both map to the WIT name %q: rename one of them",
					s.Name, c.Field, c.Name, prev, kebab)
			}
			seen[kebab] = c.Name
			if c.Field == "find" {
				ws.resource, ws.findOrig = kebab, c.Name
				continue
			}
			ws.caps = append(ws.caps, witSetCap{
				kebab: kebab, origin: c.Name, field: c.Field,
				doc: setCapDoc(c.Field), sig: setCapSig(c.Field),
			})
		}
		out = append(out, ws)
	}
	return out, nil
}

// setCapSig is the WIT signature of a stateless capability.
//
// The `_all` pair returns a LIST OF IDS for both raw ABI widths — the narrow
// i64 bitmask and the wide caller-owned bitmap alike. Measured 2026-09-11: the
// id list beat handing the bitmap over in all twelve shapes tried, because the
// bit scan is the cost and a bitmap does not avoid it, it moves it to the
// consumer and adds the transfer. A shape that varied with pattern count was
// rejected outright: adding a 65th pattern would silently change the interface
// every consumer compiled against.
func setCapSig(field string) string {
	switch field {
	case "match_any":
		return "func(input: list<u8>) -> result<option<u32>, error-code>"
	case "match_all":
		return "func(input: list<u8>) -> result<list<u32>, error-code>"
	case "scan_any":
		return "func(input: list<u8>, start: u32) -> result<option<u32>, error-code>"
	case "scan_all":
		return "func(input: list<u8>, start: u32) -> result<list<u32>, error-code>"
	}
	panic("generate: no WIT signature for set capability " + field)
}

func setCapDoc(field string) string {
	switch field {
	case "match_any":
		return "Anchored over the WHOLE input: some(id) of a pattern that matches it entirely."
	case "match_all":
		return "Anchored over the whole input: the ids of every pattern that matches it,\nascending. Empty means none."
	case "scan_any":
		return "Non-anchored from `start`: some(id) of a pattern that matches somewhere.\nReports NO position — that is what makes it the cheap one."
	case "scan_all":
		return "Non-anchored from `start`: the ids of every pattern that matches somewhere\nat or after it, ascending."
	}
	panic("generate: no WIT doc for set capability " + field)
}

// renderWitSets appends the `sets` interface. Empty when cfg declares no set.
func renderWitSets(sets []witSet) string {
	if len(sets) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("interface sets {\n")
	// Its OWN error-code rather than `use matcher.{error-code}`. A sets-only
	// config would otherwise have to export an interface holding nothing but
	// that enum, and the two interfaces stay independently bindable. Both stubs
	// map the two enums onto one error type, so a consumer never sees the
	// duplication.
	b.WriteString("    /// The Backtracking engine exhausted its frame budget; the answer is unknown.\n")
	b.WriteString("    enum error-code { backtrack-overflow }\n")
	b.WriteString("\n    /// One match: which pattern, and where.\n")
	b.WriteString("    record set-match { id: u32, start: u32, end: u32 }\n")

	for _, s := range sets {
		for _, c := range s.caps {
			b.WriteString("\n")
			for _, line := range strings.Split(c.doc, "\n") {
				fmt.Fprintf(&b, "    /// %s\n", line)
			}
			fmt.Fprintf(&b, "    %s: %s;\n", c.kebab, c.sig)
		}
		if s.resource != "" {
			fmt.Fprintf(&b, `
    /// A scan in progress. `+"`next`"+` answers the matches at ONE position — they all
    /// share a start — and an empty list means the scan is finished.
    ///
    /// It is a resource rather than a function because the drive needs state
    /// between calls: the input, the position, and the per-pattern gates. The
    /// input is copied in ONCE, by the constructor, which is what makes the
    /// per-position cost a call rather than a call plus a copy of the input.
    resource %s {
        constructor(input: list<u8>, start: u32);
        next: func() -> result<list<set-match>, error-code>;
    }
`, s.resource)
		}
	}
	b.WriteString("}\n\n")
	return b.String()
}

// Canonical export names for the sets interface.
//
//	regexped:<pkg>/sets[@<ver>]#<kebab>                      a stateless capability
//	regexped:<pkg>/sets[@<ver>]#[constructor]<res>           the find resource
//	regexped:<pkg>/sets[@<ver>]#[method]<res>.next
//	regexped:<pkg>/sets[@<ver>]#[dtor]<res>
//
// The dtor is NOT reachable from the WIT: `component new` wires it to the
// resource's destructor by name. Omitting it makes dropping a handle a trap.
func setsInterfacePrefix(pkg, version string) string {
	prefix := "regexped:" + pkg + "/sets"
	if version != "" {
		prefix += "@" + version
	}
	return prefix
}

// SetExportNames is the canonical export name of every function one set
// contributes, keyed so compile/ can stamp its adapters without re-deriving a
// single name.
type SetExportNames struct {
	// Caps maps the configured capability name (`match_any: hits` → "hits") to
	// its canonical export name.
	Caps map[string]string
	// Constructor, Next and Dtor are empty unless the set declares `find:`.
	Constructor string
	Next        string
	Dtor        string
	// ResourceImport is the synthetic module name the canon builtins are
	// imported from: "[export]regexped:<pkg>/sets[@<ver>]".
	ResourceImport string
	// ResourceNew is the field name of the resource.new builtin within it.
	ResourceNew string
}

// setExportNames builds the per-set name table from an already validated
// package name.
func setExportNames(prefix string, sets []witSet) map[string]SetExportNames {
	if len(sets) == 0 {
		return nil
	}
	out := make(map[string]SetExportNames, len(sets))
	for _, s := range sets {
		n := SetExportNames{Caps: map[string]string{}}
		for _, c := range s.caps {
			n.Caps[c.origin] = prefix + "#" + c.kebab
		}
		if s.resource != "" {
			n.Constructor = prefix + "#[constructor]" + s.resource
			n.Next = prefix + "#[method]" + s.resource + ".next"
			n.Dtor = prefix + "#[dtor]" + s.resource
			n.ResourceImport = "[export]" + prefix
			n.ResourceNew = "[resource-new]" + s.resource
		}
		out[s.name] = n
	}
	return out
}
