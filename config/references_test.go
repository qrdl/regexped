package config

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// urlConfig is the URL pattern built from named pieces, with a set whose own
// regexp uses one of them too.
const urlConfig = `patterns:
  - name: scheme
    regexp: '[a-zA-Z][a-zA-Z0-9+.-]*'
  - name: credentials
    regexp: '[^:@/\s]+(?::[^@/\s]*)?@'
  - name: hostname
    regexp: '[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*'
  - name: path
    regexp: '[^?#\s]*'
  - name: url
    regexp: '(?&scheme)://(?&credentials)?(?<&hostname>)(?:/(?&path))?'
    groups_func: url_groups
sets:
  - name: links
    find: links_find
    patterns: [url]
    regexps: ['ftp://(?&hostname)', 'mailto:[a-z]+']
`

func TestExpandReferencesURL(t *testing.T) {
	cfg, err := loadCfgSrc(t, urlConfig)
	if err != nil {
		t.Fatal(err)
	}
	url := cfg.Patterns[4]
	want := `(?:[a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^:@/\s]+(?::[^@/\s]*)?@)?(?<hostname>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)(?:/(?:[^?#\s]*))?`
	if url.Regexp != want {
		t.Fatalf("url expands to\n  %s\nwant\n  %s", url.Regexp, want)
	}
	if url.Expanded == nil || url.Written() != `(?&scheme)://(?&credentials)?(?<&hostname>)(?:/(?&path))?` {
		t.Fatalf("url.Written() = %q, Expanded = %+v", url.Written(), url.Expanded)
	}
	var got []string
	for _, u := range url.Expanded.Pieces {
		got = append(got, u.Describe())
	}
	wantPieces := []string{`piece "scheme" (used by "url")`, `piece "credentials" (used by "url")`,
		`piece "hostname" (used by "url")`, `piece "path" (used by "url")`}
	if !reflect.DeepEqual(got, wantPieces) {
		t.Errorf("pieces = %q, want %q", got, wantPieces)
	}
	// A piece is an ordinary pattern: nothing of its own is rewritten.
	for _, p := range cfg.Patterns[:4] {
		if p.Expanded != nil {
			t.Errorf("piece %q got an expansion record", p.Name)
		}
	}
	// The expanded regexp is the URL matcher it stands for, groups and all.
	re := regexp.MustCompile(`^` + url.Regexp + `$`)
	m := re.FindStringSubmatch("https://user:pw@example.com/a/b")
	if m == nil || m[re.SubexpIndex("hostname")] != "example.com" {
		t.Errorf("expanded url over a URL: %q", m)
	}

	s := cfg.Sets[0]
	if s.Regexps[0] != `ftp://(?:[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)` || s.Regexps[1] != `mailto:[a-z]+` {
		t.Errorf("set regexps = %q", s.Regexps)
	}
	if len(s.Expansions) != 2 || s.Expansions[0] == nil || s.Expansions[1] != nil {
		t.Fatalf("set expansions = %v", s.Expansions)
	}
	if d := s.Expansions[0].Pieces[0].Describe(); d != `piece "hostname" (used by set "links" regexps[0])` {
		t.Errorf("set regexp piece = %s", d)
	}
	members := s.Members(cfg)
	if members[1].Entry.Written() != "ftp://(?&hostname)" || members[2].Entry.Expanded != nil {
		t.Errorf("inline members = %+v", members)
	}
	inline := s.InlineEntry(0)
	if inline.Label != "links: regexps[0]" || inline.Written() != "ftp://(?&hostname)" || inline.Regexp != s.Regexps[0] {
		t.Errorf("InlineEntry(0) = %+v", inline)
	}
	if e := s.InlineEntry(1); e.Expanded != nil || e.Label != "links: regexps[1]" {
		t.Errorf("InlineEntry(1) = %+v", e)
	}
}

func TestExpandReferencesNestedPieces(t *testing.T) {
	cfg, err := loadCfgSrc(t, `patterns:
  - {name: c, regexp: 'c'}
  - {name: b, regexp: 'b(?&c)'}
  - {name: a, regexp: '(?&b)a(?&b)', find_func: fa}
  - {regexp: 'x(?&a)', find_func: fx}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Patterns[2].Regexp; got != "(?:b(?:c))a(?:b(?:c))" {
		t.Errorf("a = %q", got)
	}
	if got := cfg.Patterns[3].Regexp; got != "x(?:(?:b(?:c))a(?:b(?:c)))" {
		t.Errorf("unnamed = %q", got)
	}
	// Deepest first, and a piece used twice along one chain listed once.
	var got []string
	for _, u := range cfg.Patterns[3].Expanded.Pieces {
		got = append(got, u.Describe()+" = "+u.Text)
	}
	want := []string{
		`piece "c" (used by "b", used by "a", used by pattern "x(?&a)") = c`,
		`piece "b" (used by "a", used by pattern "x(?&a)") = b(?:c)`,
		`piece "a" (used by pattern "x(?&a)") = (?:b(?:c))a(?:b(?:c))`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pieces =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if got := cfg.Patterns[1].Expanded.Pieces; len(got) != 1 || got[0].Describe() != `piece "c" (used by "b")` {
		t.Errorf("b's pieces = %+v", got)
	}
}

// Text Go reads as something else is never a reference, and a config with no
// reference is not touched at all.
func TestExpandReferencesLeavesOrdinaryText(t *testing.T) {
	for _, re := range []string{
		`[(?&x)]`,          // a class of five characters
		`\Q(?&x)\E`,        // literal text
		`\(?&x\)`,          // an optional "(" then literal "&x)"
		`[](?&x)]`,         // "]" first in a class is a literal
		`[^](?&x)]`,        // and after "^"
		`[[:alpha:](?&x)]`, // a POSIX class is one item
		`[[:(?&x)]`,        // "[:" with no ":]" is a literal "["
		`(?i)abc`,          // a group, no reference
	} {
		if _, err := regexp.Compile(re); err != nil {
			t.Fatalf("%s is not valid Go: %v", re, err)
		}
		src := "patterns:\n  - {name: x, regexp: 'q'}\n  - {regexp: '" + re + "', find_func: f}\n" +
			"sets:\n  - {name: s, find: sf, patterns: [x], regexps: ['" + re + "']}\n"
		cfg, err := loadCfgSrc(t, src)
		if err != nil {
			t.Fatalf("%s: %v", re, err)
		}
		p, s := cfg.Patterns[1], cfg.Sets[0]
		if p.Regexp != re || p.Expanded != nil || s.Regexps[0] != re || s.Expansions != nil {
			t.Errorf("%s was rewritten: %q %+v / %q %v", re, p.Regexp, p.Expanded, s.Regexps[0], s.Expansions)
		}
	}
	// An unterminated class runs to the end, as Go reads it: no reference is
	// expanded, and the syntax error is a load error at its line, as for any
	// pattern.
	cfg0 := BuildConfig{Patterns: []PatternEntry{{Name: "x", Regexp: "q"}, {Regexp: "[a(?&x)", FindFunc: "f"}}}
	if err := ExpandReferences(&cfg0); err != nil || cfg0.Patterns[1].Expanded != nil {
		t.Errorf("unterminated class: %v %+v", err, cfg0.Patterns[1])
	}
	if _, err := loadCfgSrc(t, "patterns:\n  - {name: x, regexp: 'q'}\n  - {regexp: '[a(?&x)', find_func: f}\n"); err == nil ||
		!strings.Contains(err.Error(), "missing closing ]") || !strings.Contains(err.Error(), "[3:") {
		t.Errorf("unterminated class: err = %v, want the syntax error at line 3", err)
	}
	// No "(?&" anywhere: nothing is even scanned.
	cfg := BuildConfig{Patterns: []PatternEntry{{Name: "a", Regexp: "(?i)a"}}}
	if err := ExpandReferences(&cfg); err != nil || cfg.Patterns[0].Expanded != nil {
		t.Errorf("ExpandReferences on a config with no reference: %v %+v", err, cfg.Patterns[0])
	}
}

// A piece ending inside \Q…\E is closed before its group is, or the group's
// ")" would be read as a literal.
func TestExpandReferencesClosesOpenQuote(t *testing.T) {
	cfg, err := loadCfgSrc(t, `patterns:
  - {name: lit, regexp: '\Qa.b'}
  - {name: u, regexp: 'x(?&lit)y', find_func: f}
`)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Patterns[1].Regexp
	if got != `x(?:\Qa.b\E)y` {
		t.Fatalf("u = %q", got)
	}
	re := regexp.MustCompile(got)
	if !re.MatchString("xa.by") || re.MatchString("xaxby") {
		t.Errorf("%s matches the wrong text", got)
	}
}

// Code that builds a config itself expands it with ExpandReferences.
func TestExpandReferencesInCode(t *testing.T) {
	cfg := BuildConfig{Patterns: []PatternEntry{
		{Name: "d", Regexp: `\d+`},
		{Name: "n", Regexp: `(?&d)(?:\.(?&d))?`, FindFunc: "f"},
	}}
	if err := ExpandReferences(&cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Patterns[1].Regexp; got != `(?:\d+)(?:\.(?:\d+))?` {
		t.Errorf("n = %q", got)
	}
	var none *Expansion
	if none.groupOrigins("x") != "" {
		t.Error("a nil expansion describes a group")
	}
	if got := cfg.Patterns[1].Expanded.groupOrigins("missing"); got != "" {
		t.Errorf("origins of a group the regexp lacks = %q", got)
	}
}

func TestExpandReferencesErrors(t *testing.T) {
	const pieces = "  - {name: domain, regexp: '[a-z]+'}\n  - {name: 'Norwegian/Danish', regexp: '[a-z]+'}\n"
	cases := []struct {
		name, body, want string
	}{
		{"unknown name", "  - {name: u, regexp: 'x(?&nope)', find_func: f}",
			`pattern "u": no pattern is named "nope"`},
		{"no name", "  - {name: u, regexp: 'x(?&)', find_func: f}",
			`pattern "u": reference (?&) has no name`},
		{"no name, capturing", "  - {name: u, regexp: 'x(?<&>)', find_func: f}",
			`reference (?<&>) has no name`},
		{"invalid name", "  - {name: u, regexp: 'x(?&-x)', find_func: f}",
			`invalid reference name "-x": a name in (?&…) or (?<&…>) is ASCII letters, digits and _ only`},
		{"name a reference cannot spell", "  - {name: u, regexp: 'x(?&Norwegian/Danish)', find_func: f}",
			`pattern "Norwegian/Danish" cannot be referenced: a name in (?&…) or (?<&…>) is ASCII letters, digits and _ only; rename the pattern`},
		{"same, capturing", "  - {name: u, regexp: 'x(?<&Norwegian/Danish>)', find_func: f}",
			`pattern "Norwegian/Danish" cannot be referenced`},
		{"body", `  - {name: u, regexp: 'x(?&domain\.com)', find_func: f}`,
			`pattern "u": reference (?&domain… must end right after the name: a reference takes no body; ` +
				`to capture more than the piece, give it a group of its own: (?<group>(?&domain)…)`},
		{"body, capturing", `  - {name: u, regexp: 'x(?<&domain>(?::\d+)?)', find_func: f}`,
			`reference (?<&domain… must end right after the name: a reference takes no body`},
		{"capturing, no >", "  - {name: u, regexp: 'x(?<&domain)', find_func: f}",
			`pattern "u": reference (?<&domain) is missing ">": write (?<&domain>)`},
		{"cut short", "  - {name: u, regexp: 'x(?&domain', find_func: f}",
			`pattern "u": reference (?&domain is not closed: expected ")"`},
		{"no closer anywhere", "  - {name: u, regexp: 'x(?&domain abc', find_func: f}",
			`pattern "u": reference (?&domain is not closed: expected ")"`},
		{"cut short, capturing", "  - {name: u, regexp: 'x(?<&domain', find_func: f}",
			`pattern "u": reference (?<&domain is not closed: expected ">)"`},
		{"cycle", "  - {name: a, regexp: 'a(?&b)'}\n  - {name: b, regexp: 'b(?&a)'}",
			`pattern "a" (used by "b", used by "a"): reference cycle: "a" → "b" → "a"`},
		{"self", "  - {name: a, regexp: 'a(?&a)', find_func: f}",
			`pattern "a" (used by "a"): reference cycle: "a" → "a"`},
		{"piece syntax error", "  - {name: octet, regexp: '25[0-5]|2[0-4]\\d|1?\\d?\\d)'}\n  - {name: ipv4, regexp: '(?&octet)(?:\\.(?&octet)){3}', find_func: f}",
			"pattern \"octet\" (used by \"ipv4\"): error parsing regexp: unexpected ): `25[0-5]|2[0-4]\\d|1?\\d?\\d)`"},
		{"error quoting the whole text", "  - {name: p, regexp: '(?&domain)+)'}\n  - {name: u, regexp: 'x(?&p)', find_func: f}",
			"pattern \"p\": error parsing regexp: unexpected ): `(?&domain)+)`"},
		{"error quoting a stand-in", "  - {name: p, regexp: '((?&domain)'}\n  - {name: u, regexp: 'x(?&p)', find_func: f}",
			"pattern \"p\": error parsing regexp: missing closing ): `((?&domain)`"},
		{"error quoting its own fragment", "  - {name: p, regexp: '(?&domain)\\g'}\n  - {name: u, regexp: 'x(?&p)', find_func: f}",
			"pattern \"p\": error parsing regexp: invalid escape sequence: `\\g`"},
		{"top-level syntax error", "  - {name: u, regexp: '(?&domain)(', find_func: f}",
			"pattern \"u\": error parsing regexp: missing closing ): `(?&domain)(`"},
		{"unnamed user", "  - {regexp: 'x(?&nope)', find_func: f}",
			`pattern "x(?&nope)": no pattern is named "nope"`},
		{"set regexp", "  - {name: u, regexp: 'u', find_func: f}\nsets:\n  - {name: s, find: sf, regexps: ['(?&nope)']}",
			`set "s" regexps[0]: no pattern is named "nope"`},
		{"duplicate name", "  - {name: domain, regexp: 'x'}\n  - {name: u, regexp: '(?&domain)', find_func: f}",
			`duplicate pattern name "domain"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadCfgSrc(t, "patterns:\n"+pieces+c.body+"\n")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v\nwant it to contain %s", err, c.want)
			}
		})
	}
}

// A piece's own groups come along wherever it is used, and a group name used
// twice is refused, as it always was — saying which reference brought each
// copy in.
func TestExpandReferencesCaptureGroups(t *testing.T) {
	cfg, err := loadCfgSrc(t, `patterns:
  - {name: hp, regexp: '(?<host>[a-z.]+)(?::(?<port>\d+))?'}
  - {name: u, regexp: 'https?://(?&hp)/', groups_func: g}
`)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(cfg.Patterns[1].Regexp)
	if m := re.FindStringSubmatch("http://a.b:8/"); m == nil || m[re.SubexpIndex("host")] != "a.b" || m[re.SubexpIndex("port")] != "8" {
		t.Errorf("groups over a URL: %q", m)
	}

	const hp = "  - {name: hp, regexp: '(?<host>[a-z.]+)(?::(?<port>\\d+))?'}\n"
	cases := []struct{ name, body, want string }{
		{"one piece captured twice", "  - {name: email, regexp: '[a-z]+@[a-z]+'}\n  - {name: u, regexp: 'from (?<&email>) to (?<&email>)', groups_func: g}",
			`pattern "u": capture group name "email" is used more than once; group names become generated constants and a name→index lookup, ` +
				`so only one group of that name would be reachable; it comes from (?<&email>), (?<&email>)`},
		{"through another piece", hp + "  - {name: mid, regexp: 'h=(?&hp)'}\n  - {name: u, regexp: '(?&mid),(?&hp)', groups_func: g}",
			`capture group name "host" is used more than once; group names become generated constants and a name→index lookup, ` +
				`so only one group of that name would be reachable; it comes from piece "hp" (used by "mid"), piece "hp"`},
		{"captured inside a piece", hp + "  - {name: mid, regexp: 'h=(?<&hp>)'}\n  - {name: u, regexp: '(?&mid),(?<&hp>)', groups_func: g}",
			`capture group name "hp" is used more than once; group names become generated constants and a name→index lookup, ` +
				`so only one group of that name would be reachable; it comes from (?<&hp>) in piece "mid", (?<&hp>)`},
		{"its own and a reference", "  - {name: email, regexp: '[a-z]+'}\n  - {name: u, regexp: '(?<email>x)(?<&email>)', groups_func: g}",
			`it comes from its own text, (?<&email>)`},
		{"used as a piece before its own turn", "  - {name: a, regexp: 'a(?&u)'}\n  - {name: email, regexp: '[a-z]+'}\n  - {name: u, regexp: '(?<email>x)(?<&email>)', groups_func: g}",
			`pattern "u": capture group name "email" is used more than once; group names become generated constants and a name→index lookup, ` +
				`so only one group of that name would be reachable; it comes from its own text, (?<&email>)`},
		{"a generated suffix", "  - {name: index, regexp: '[0-9]+'}\n  - {name: u, regexp: 'i=(?<&index>)', groups_func: g}",
			`capture group name "index" is one of the suffixes the stub generators derive from the groups_func name`},
		{"names differing in case", "  - {name: Host, regexp: '[a-z]+'}\n  - {name: u, regexp: '(?<&Host>)@(?<host>[a-z]+)', groups_func: g}",
			`collapse to one generated constant stem "HOST"; "Host" comes from (?<&Host>)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadCfgSrc(t, "patterns:\n"+c.body+"\n")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v\nwant it to contain %s", err, c.want)
			}
		})
	}
	// A duplicate written by hand says nothing about references.
	_, err = loadCfgSrc(t, "patterns:\n  - {name: p, regexp: 'q'}\n  - {name: u, regexp: '(?<a>x)(?<a>y)(?&p)', groups_func: g}\n")
	if err == nil || strings.Contains(err.Error(), "comes from") {
		t.Errorf("hand-written duplicate: %v", err)
	}
	if !strings.Contains(err.Error(), "suffixes the stub generators derive") {
		// The suffix note is reached only through a reference above; the
		// plain message must still read as before.
		if !strings.Contains(err.Error(), `capture group name "a" is used more than once`) {
			t.Errorf("hand-written duplicate message: %v", err)
		}
	}
}

// Checks that ran on a pattern's text run on the expanded text, and name an
// unnamed pattern by what was written.
func TestExpandReferencesLaterChecksSeeExpandedText(t *testing.T) {
	// Equivalence: an alias of a member is refused, by today's rule.
	_, err := loadCfgSrc(t, `patterns:
  - {name: email, regexp: '[a-z]+@[a-z]+'}
  - {regexp: '(?&email)'}
sets:
  - {name: s, find: sf, patterns: all}
`)
	if err == nil || !strings.Contains(err.Error(), `set "s": pattern "email" and pattern '(?&email)' are equivalent`) {
		t.Errorf("alias in a set: %v", err)
	}
	_, err = loadCfgSrc(t, `patterns:
  - {name: email, regexp: '[a-z]+@[a-z]+'}
sets:
  - {name: s, find: sf, patterns: all, regexps: ['(?&email)']}
`)
	if err == nil || !strings.Contains(err.Error(), `regexp '(?&email)'`) {
		t.Errorf("inline alias in a set: %v", err)
	}
	for _, c := range []struct{ body, want string }{
		{"  - {regexp: 'x(?&p)', find_func: f, hints: [bogus]}", `"x(?&p)"`},
		{"  - {regexp: 'x(?&p)', find_func: f, unicode: true, byte_mode: true}", `x(?&p)`},
		{"  - {regexp: 'x(?&p)', find_func: 'bad name'}", `pattern "x(?&p)"`},
		{"  - {regexp: 'x(?&p)', find_func: f}\n  - {regexp: 'y', find_func: f}", `pattern "x(?&p)"`},
	} {
		_, err := loadCfgSrc(t, "patterns:\n  - {name: p, regexp: 'q'}\n"+c.body+"\n")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to name %s", c.body, err, c.want)
		}
	}
	// The mode guess reads the expanded text: a Unicode piece makes the
	// pattern Unicode; the piece's own byte_mode is not carried over.
	cfg, err := loadCfgSrc(t, "patterns:\n  - {name: b, regexp: '[\\x80-\\xff]+', byte_mode: true}\n  - {name: u, regexp: 'X(?&b)', find_func: f}\n")
	if err != nil {
		t.Fatal(err)
	}
	if u := cfg.Patterns[1]; u.ByteMode || u.Regexp != `X(?:[\x80-\xff]+)` {
		t.Errorf("u = %+v", u)
	}
}

// DisplayName and Owner name an entry in every message: by its name, else by
// its regexp as written.
func TestPatternEntryNames(t *testing.T) {
	refs := PatternEntry{Regexp: `x(?:q)`, Expanded: &Expansion{Source: `x(?&p)`}}
	for _, c := range []struct {
		e              PatternEntry
		display, owner string
	}{
		{PatternEntry{Name: "url", Regexp: `x`}, "url", `pattern "url"`},
		{PatternEntry{Regexp: `a+`}, "a+", `pattern "a+"`},
		{refs, `x(?&p)`, `pattern "x(?&p)"`},
		{PatternEntry{}, "", "pattern"},
	} {
		if got := c.e.DisplayName(); got != c.display {
			t.Errorf("%+v: DisplayName = %q, want %q", c.e, got, c.display)
		}
		if got := c.e.Owner(); got != c.owner {
			t.Errorf("%+v: Owner = %q, want %q", c.e, got, c.owner)
		}
	}
}

// doublingChain is p0 'ab' and p_i = (?&p_{i-1})(?&p_{i-1}), the last one
// exported: its expansion doubles with every level.
func doublingChain(depth int, extra string) string {
	var b strings.Builder
	b.WriteString(extra + "patterns:\n  - {name: p0, regexp: 'ab'}\n")
	for i := 1; i <= depth; i++ {
		b.WriteString("  - {name: p" + itoa(i) + ", regexp: '(?&p" + itoa(i-1) + ")(?&p" + itoa(i-1) + ")'}\n")
	}
	b.WriteString("  - {regexp: '(?&p" + itoa(depth) + ")', find_func: f}\n")
	return b.String()
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestExpandReferencesDoublingChainIsCapped: a 24-level doubling chain is a
// load error naming max_regexp_size, returned at once and without building
// the text: past 20 levels it took over 2 GB. The error names the first
// pattern past the cap and the size to raise it to.
func TestExpandReferencesDoublingChainIsCapped(t *testing.T) {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	_, err := loadCfgSrc(t, doublingChain(24, ""))
	d := time.Since(start)
	runtime.ReadMemStats(&m1)
	if err == nil || !strings.Contains(err.Error(), "max_regexp_size") || !strings.Contains(err.Error(), `pattern "p17"`) {
		t.Fatalf("err = %v, want the max_regexp_size error naming p17", err)
	}
	if d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
		t.Errorf("allocated %d MB to refuse it", alloc>>20)
	}
}

// TestExpandReferencesBookkeepingIsLinear: the per-use record used to double
// with every level of a doubling chain (~1.6 KB per expanded byte, 1 GB at
// depth 16); now a piece is recorded once per chain of users. Depth 16 is
// 655 KB of text, under the default cap.
func TestExpandReferencesBookkeepingIsLinear(t *testing.T) {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	cfg, err := loadCfgSrc(t, doublingChain(16, ""))
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	last := cfg.Patterns[len(cfg.Patterns)-1]
	if n := len(last.Regexp); n != 655356 {
		t.Fatalf("expanded to %d bytes, want 655356", n)
	}
	if n := len(last.Expanded.Pieces); n != 17 {
		t.Errorf("%d pieces recorded, want 17: p16 used directly, p0..p15 through it", n)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
		t.Errorf("allocated %d MB, was 1,027 MB", alloc>>20)
	}
}

// TestMaxRegexpSize: the key raises the cap, lowers it, and also refuses a
// regexp WRITTEN past it, with no reference involved.
func TestMaxRegexpSize(t *testing.T) {
	if _, err := loadCfgSrc(t, doublingChain(18, "max_regexp_size: 4MiB\n")); err != nil {
		t.Errorf("depth 18 (2.6 MB) under max_regexp_size: 4MiB: %v", err)
	}
	_, err := loadCfgSrc(t, doublingChain(4, "max_regexp_size: 40\n"))
	if err == nil || !strings.Contains(err.Error(), "over max_regexp_size (40, 40 bytes)") {
		t.Errorf("depth 4 under max_regexp_size: 40: %v", err)
	}
	_, err = loadCfgSrc(t, "max_regexp_size: 10\npatterns:\n  - {regexp: 'abcdefghijkl', find_func: f}\n")
	if err == nil || !strings.Contains(err.Error(), "is 12 bytes") || !strings.Contains(err.Error(), "at least 12") {
		t.Errorf("a 12-byte regexp under max_regexp_size: 10: %v", err)
	}
	if _, err := loadCfgSrc(t, "max_regexp_size: lots\npatterns:\n  - {regexp: 'a', find_func: f}\n"); err == nil {
		t.Error("max_regexp_size: lots was accepted")
	}
	// A set's own regexp is held to the cap too.
	_, err = loadCfgSrc(t, "max_regexp_size: 10\nsets:\n  - {name: s, find: f, regexps: ['abcdefghijkl']}\n")
	if err == nil || !strings.Contains(err.Error(), `set "s" regexps[0]: is 12 bytes`) {
		t.Errorf("a set's 12-byte regexp under max_regexp_size: 10: %v", err)
	}
	// The size is computed BEFORE the text is built, so it must be the built
	// size exactly: a cap of that size loads, one byte less does not, and the
	// error states that size.
	cfg, err := loadCfgSrc(t, doublingChain(6, "max_regexp_size: 1MiB\n"))
	if err != nil {
		t.Fatal(err)
	}
	n := len(cfg.Patterns[len(cfg.Patterns)-1].Regexp)
	if _, err := loadCfgSrc(t, doublingChain(6, fmt.Sprintf("max_regexp_size: %d\n", n))); err != nil {
		t.Errorf("a cap of the expanded size %d was refused: %v", n, err)
	}
	_, err = loadCfgSrc(t, doublingChain(6, fmt.Sprintf("max_regexp_size: %d\n", n-1)))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("is %d bytes", n)) {
		t.Errorf("a cap one byte under the expanded size %d: %v", n, err)
	}
}
