package config

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"
)

// ── Pattern references ─────────────────────────────────
//
// A regexp may use a named top-level pattern: `(?&name)` inserts that
// pattern's regexp as a non-capturing group, `(?<&name>)` inserts it as the
// capture group `name`. Go's parser rejects both spellings, so no regexp that
// compiles today changes meaning. ExpandReferences rewrites every regexp that
// uses one, at load, so compile, generate and merge only ever see ordinary
// regexps, and a pattern written with references compiles to exactly the
// module the same pattern written out by hand compiles to.
//
// The inserted text is always wrapped in a group: pasted bare, `x(?&ab)y`
// with `ab: 'a|b'` would read `xa|by`. Being a group, it keeps a piece's own
// flags inside it and lets the user's flags reach in, as Go nests any group.
// Only the referenced pattern's `regexp:` is used; its mode keys, hints and
// functions belong to it alone.

// Expansion records what reference expansion did to one regexp.
type Expansion struct {
	// Source is the regexp as written, references and all.
	Source string
	// Pieces is every pattern it used, directly or through another, each
	// listed AFTER the pieces it uses itself: the first piece in which a
	// check fails is the one whose own text holds the cause.
	Pieces []PieceUse
	// groups is where each capture group of the expanded regexp came from.
	groups []groupOrigin
}

// PieceUse is one pattern used by reference.
type PieceUse struct {
	Name string // the referenced pattern's name
	Text string // its regexp, with its own references expanded
	// UsedBy is the chain of its users, nearest first: `"ipv4"`, then `"url"`
	// when ipv4 was itself used by url. A user with no name is written
	// `pattern "<its regexp>"`, a set's own regexp `set "s" regexps[0]`.
	UsedBy []string
}

// Describe names the piece and its chain of users, for an error message:
// `piece "octet" (used by "ipv4")`.
func (u PieceUse) Describe() string {
	return fmt.Sprintf("piece %q (%s)", u.Name, usedBy(u.UsedBy))
}

// usedBy spells a chain of users.
func usedBy(chain []string) string {
	parts := make([]string, len(chain))
	for i, c := range chain {
		parts[i] = "used by " + c
	}
	return strings.Join(parts, ", ")
}

// groupOrigin is where one capture group of an expanded regexp was written.
type groupOrigin struct {
	name string
	// what is the text that wrote the group: `piece "hostport"`,
	// `(?<&email>)`, or "its own text" for the regexp being expanded.
	what string
	// chain is the pieces the group passed through on its way up, nearest
	// first, excluding the regexp being expanded.
	chain []string
}

func (g groupOrigin) String() string {
	if len(g.chain) == 0 {
		return g.what
	}
	return fmt.Sprintf("%s (%s)", g.what, usedBy(g.chain))
}

// groupOrigins says where every copy of the named capture group came from,
// for a message about it: "" when nothing needs saying — the regexp used no
// reference, or no copy came in through one.
func (x *Expansion) groupOrigins(name string) string {
	if x == nil {
		return ""
	}
	var from []string
	viaReference := false
	for _, g := range x.groups {
		if g.name != name {
			continue
		}
		from = append(from, g.String())
		if g.what != ownText {
			viaReference = true
		}
	}
	if !viaReference {
		return ""
	}
	return strings.Join(from, ", ")
}

// ownText is the groupOrigin.what of a group the expanded regexp wrote itself.
const ownText = "its own text"

// Written is the regexp as the config wrote it: with its references, when it
// used any.
func (r PatternEntry) Written() string {
	if r.Expanded != nil {
		return r.Expanded.Source
	}
	return r.Regexp
}

// referenceName is the rule for a name a reference can use: Go's rule for a
// capture group name, since `(?<&name>)` makes one of it.
func referenceNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// refToken is one reference in a regexp's text: s[start:end].
type refToken struct {
	start, end int
	name       string
	capture    bool // `(?<&name>)` rather than `(?&name)`
}

// scanReferences finds the references in a regexp. It follows Go's syntax so
// that text Go reads as something else is never taken for one: a character
// class (`[(?&x)]` is five characters), `\Q…\E`, and whatever follows a
// backslash. openQ reports that the text ends inside `\Q…\E`, where a group
// closed after it would be read as a literal `)`. A malformed reference is an
// error; names says which pattern names exist, for its message.
func scanReferences(s string, names map[string]int) (toks []refToken, openQ bool, err error) {
	n := len(s)
	for i := 0; i < n; {
		switch {
		case s[i] == '\\':
			if i+1 < n && s[i+1] == 'Q' {
				end := strings.Index(s[i+2:], `\E`)
				if end < 0 {
					return toks, true, nil
				}
				i += 2 + end + 2
				continue
			}
			i += 2
		case s[i] == '[':
			i = skipClass(s, i)
		case strings.HasPrefix(s[i:], "(?&"), strings.HasPrefix(s[i:], "(?<&"):
			t, err := readReference(s, i, names)
			if err != nil {
				return nil, false, err
			}
			toks = append(toks, t)
			i = t.end
		default:
			i++
		}
	}
	return toks, false, nil
}

// skipClass returns the index just past the character class opening at s[i],
// by Go's rules: a `]` straight after `[` or `[^` is a literal, a backslash
// escapes the next character, and `[:name:]` is one item. An unterminated
// class runs to the end; Go refuses it.
func skipClass(s string, i int) int {
	n := len(s)
	j := i + 1
	if j < n && s[j] == '^' {
		j++
	}
	if j < n && s[j] == ']' {
		j++
	}
	for j < n {
		switch {
		case s[j] == '\\':
			j += 2
		case strings.HasPrefix(s[j:], "[:"):
			if end := strings.Index(s[j+2:], ":]"); end >= 0 {
				j += 2 + end + 2
			} else {
				j++
			}
		case s[j] == ']':
			return j + 1
		default:
			j++
		}
	}
	return n
}

// readReference reads the reference opening at s[i].
func readReference(s string, i int, names map[string]int) (refToken, error) {
	capture := strings.HasPrefix(s[i:], "(?<&")
	open, closer := "(?&", ")"
	if capture {
		open, closer = "(?<&", ">)"
	}
	j := i + len(open)
	k := j
	for k < len(s) && referenceNameByte(s[k]) {
		k++
	}
	name := s[j:k]
	if name != "" && strings.HasPrefix(s[k:], closer) {
		return refToken{start: i, end: k + len(closer), name: name, capture: capture}, nil
	}
	// Malformed. What the user meant decides the message: a pattern whose
	// name a reference cannot spell, a missing name, or a body after one.
	rest := s[j:]
	if end := strings.IndexByte(rest, closer[0]); end >= 0 {
		rest = rest[:end]
	}
	if _, isPattern := names[rest]; isPattern && rest != name {
		return refToken{}, fmt.Errorf("pattern %q cannot be referenced: a name in (?&…) or (?<&…>) is ASCII letters, digits and _ only; rename the pattern", rest)
	}
	if name == "" {
		if rest == "" {
			return refToken{}, fmt.Errorf("reference %s%s has no name", open, closer)
		}
		return refToken{}, fmt.Errorf("invalid reference name %q: a name in (?&…) or (?<&…>) is ASCII letters, digits and _ only", rest)
	}
	return refToken{}, fmt.Errorf("reference %s%s… must end right after the name: a reference takes no body; "+
		"to capture more than the piece, give it a group of its own: (?<group>(?&%s)…)", open, name, name)
}

// skeletonHole stands in for a reference when a regexp's own text is parsed
// alone: an atom, like the group a reference becomes.
const skeletonHole = "(?:)"

// expanded is one regexp after expansion.
type expanded struct {
	text   string
	openQ  bool       // its text ends inside \Q…\E
	uses   []PieceUse // chains stop at this regexp's own user label
	groups []groupOrigin
	refs   bool // it used at least one reference
}

// expander expands the references of one config.
type expander struct {
	cfg    *BuildConfig
	src    []string       // every top-level regexp as written
	byName map[string]int // name → index into src
	memo   map[int]*expanded
	active []int // the pieces being expanded, outermost first: a cycle check
}

// ExpandReferences rewrites every regexp of cfg that uses a reference —
// top-level patterns and sets' own regexps — into the regexp it stands for,
// and records on it what was used (PatternEntry.Expanded,
// SetConfig.Expansions). A config that uses none is left untouched.
//
// Called from LoadConfig, before any other check, so every check reads the
// expanded text. Exported for callers that build a BuildConfig in code.
func ExpandReferences(cfg *BuildConfig) error {
	if !mayReference(cfg) {
		return nil
	}
	x := &expander{cfg: cfg, src: make([]string, len(cfg.Patterns)), byName: make(map[string]int), memo: make(map[int]*expanded)}
	for i, p := range cfg.Patterns {
		x.src[i] = p.Regexp
		if p.Name == "" {
			continue
		}
		// ValidateSets refuses this too, but later: a reference has to
		// resolve to one pattern now.
		if _, dup := x.byName[p.Name]; dup {
			return fmt.Errorf("duplicate pattern name %q", p.Name)
		}
		x.byName[p.Name] = i
	}
	for i := range cfg.Patterns {
		if !strings.Contains(x.src[i], "(?") {
			continue
		}
		e, err := x.pattern(i, nil)
		if err != nil {
			return err
		}
		if e.refs {
			cfg.Patterns[i].Regexp = e.text
			cfg.Patterns[i].Expanded = finish(x.src[i], e)
		}
	}
	for si := range cfg.Sets {
		s := &cfg.Sets[si]
		for k, r := range s.Regexps {
			if !strings.Contains(r, "(?") {
				continue
			}
			label := fmt.Sprintf("set %q regexps[%d]", s.Name, k)
			e, err := x.text(r, label, label, nil, ownText)
			if err != nil {
				return err
			}
			if !e.refs {
				continue
			}
			if s.Expansions == nil {
				s.Expansions = make([]*Expansion, len(s.Regexps))
			}
			s.Regexps[k] = e.text
			s.Expansions[k] = finish(r, e)
		}
	}
	return nil
}

// mayReference reports whether any regexp of cfg could hold a reference.
func mayReference(cfg *BuildConfig) bool {
	has := func(s string) bool { return strings.Contains(s, "(?&") || strings.Contains(s, "(?<&") }
	for _, p := range cfg.Patterns {
		if has(p.Regexp) {
			return true
		}
	}
	for _, s := range cfg.Sets {
		for _, r := range s.Regexps {
			if has(r) {
				return true
			}
		}
	}
	return false
}

// finish turns a top-level regexp's expansion into its record. A piece used
// twice along the same chain is listed once.
func finish(source string, e *expanded) *Expansion {
	out := &Expansion{Source: source, groups: e.groups}
	seen := make(map[string]bool, len(e.uses))
	for _, u := range e.uses {
		key := u.Describe()
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Pieces = append(out.Pieces, u)
	}
	return out
}

// userLabel names top-level pattern i as a user in a chain: its quoted name,
// or `pattern "<its regexp>"` when it has none.
func (x *expander) userLabel(i int) string {
	if name := x.cfg.Patterns[i].Name; name != "" {
		return fmt.Sprintf("%q", name)
	}
	return fmt.Sprintf("pattern %q", x.src[i])
}

// pattern expands top-level pattern i; chain is its users, nearest first,
// for messages (nil when it is expanded as a top-level pattern itself).
func (x *expander) pattern(i int, chain []string) (*expanded, error) {
	// The memo holds the PIECE view, whose groups are described as the
	// piece's; a pattern expanded for itself describes them as its own.
	if e, ok := x.memo[i]; ok && chain != nil {
		return e, nil
	}
	for k, a := range x.active {
		if a == i {
			names := make([]string, 0, len(x.active)-k+1)
			for _, b := range x.active[k:] {
				names = append(names, fmt.Sprintf("%q", x.cfg.Patterns[b].Name))
			}
			names = append(names, fmt.Sprintf("%q", x.cfg.Patterns[i].Name))
			return nil, fmt.Errorf("%s: reference cycle: %s", x.owner(i, chain), strings.Join(names, " → "))
		}
	}
	x.active = append(x.active, i)
	defer func() { x.active = x.active[:len(x.active)-1] }()
	self := ownText
	if chain != nil {
		self = fmt.Sprintf("piece %q", x.cfg.Patterns[i].Name)
	}
	e, err := x.text(x.src[i], x.owner(i, chain), x.userLabel(i), chain, self)
	if err != nil {
		return nil, err
	}
	if chain != nil {
		x.memo[i] = e
	}
	return e, nil
}

// owner names top-level pattern i in an error message, with its users.
func (x *expander) owner(i int, chain []string) string {
	label := "pattern " + x.userLabel(i)
	if x.cfg.Patterns[i].Name == "" {
		label = x.userLabel(i)
	}
	if len(chain) > 0 {
		label += " (" + usedBy(chain) + ")"
	}
	return label
}

// text expands one regexp: owner names it in errors, user is its label as a
// user of the pieces it references, chain its own users (nil for a top-level
// regexp), and self what its own capture groups are described as.
func (x *expander) text(src, owner, user string, chain []string, self string) (*expanded, error) {
	toks, openQ, err := scanReferences(src, x.byName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", owner, err)
	}
	e := &expanded{text: src, openQ: openQ, refs: len(toks) > 0}
	if !e.refs && chain == nil {
		// A top-level regexp with no reference is not this feature's to check.
		return e, nil
	}
	// The regexp's own text, parsed alone: a syntax error is reported against
	// what was written, not against the expanded text.
	var skel strings.Builder
	last := 0
	for _, t := range toks {
		skel.WriteString(src[last:t.start])
		skel.WriteString(skeletonHole)
		last = t.end
	}
	skel.WriteString(src[last:])
	own, err := parseOwn(src, skel.String())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", owner, err)
	}
	for _, name := range own {
		e.groups = append(e.groups, groupOrigin{name: name, what: self})
	}
	if !e.refs {
		return e, nil
	}
	inner := append([]string{user}, chain...)
	var b strings.Builder
	last = 0
	for _, t := range toks {
		b.WriteString(src[last:t.start])
		last = t.end
		j, ok := x.byName[t.name]
		if !ok {
			return nil, fmt.Errorf("%s: no pattern is named %q", owner, t.name)
		}
		p, err := x.pattern(j, inner)
		if err != nil {
			return nil, err
		}
		if t.capture {
			b.WriteString("(?<" + t.name + ">")
			what := fmt.Sprintf("(?<&%s>)", t.name)
			if chain != nil {
				what += fmt.Sprintf(" in %s", self)
			}
			e.groups = append(e.groups, groupOrigin{name: t.name, what: what})
		} else {
			b.WriteString("(?:")
		}
		b.WriteString(p.text)
		if p.openQ {
			b.WriteString(`\E`)
		}
		b.WriteString(")")
		// Its uses first, then itself: deepest first.
		for _, u := range p.uses {
			u.UsedBy = append(append([]string(nil), u.UsedBy...), user)
			e.uses = append(e.uses, u)
		}
		e.uses = append(e.uses, PieceUse{Name: t.name, Text: p.text, UsedBy: []string{user}})
		for _, g := range p.groups {
			if chain != nil {
				// This regexp is itself a piece: the group passes through it.
				g.chain = append(append([]string(nil), g.chain...), user)
			}
			e.groups = append(e.groups, g)
		}
	}
	b.WriteString(src[last:])
	e.text = b.String()
	return e, nil
}

// parseOwn parses a regexp's own text — its references replaced by
// skeletonHole — and returns its capture group names. A syntax error quotes
// what was written: Go's message quotes the text it parsed, which holds the
// stand-ins.
func parseOwn(src, skeleton string) ([]string, error) {
	re, err := syntax.Parse(skeleton, syntax.Perl)
	if err != nil {
		var se *syntax.Error
		if errors.As(err, &se) && skeleton != src && (se.Expr == skeleton || strings.Contains(se.Expr, skeletonHole)) {
			return nil, &syntax.Error{Code: se.Code, Expr: src}
		}
		return nil, err
	}
	var names []string
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture && r.Name != "" {
			names = append(names, r.Name)
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return names, nil
}
