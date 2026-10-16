// make_adjusted reads re2-exhaustive.txt, extracts sections that contain
// patterns with capture groups, rewrites col0 expectations using Go stdlib
// (LF semantics), and writes re2-adjusted.txt.
//
// Usage: go run ./make_adjusted re2-exhaustive.txt re2-adjusted.txt
//
// With -unicode-variants it instead reads re2-adjusted.txt and writes a
// Unicode-mode corpus: every section's strings replaced by variants carrying
// 2- to 4-byte characters and invalid UTF-8, and every column — col0 and col1
// as above, col4 every match — computed by Go over the pattern with U+FFFD
// taken out of its classes and `.` (noReplacement), so an invalid byte matches
// nothing, as in Unicode mode, and the columns are Unicode mode's own answers.
// The harness reads such a file with -unicode -unicode-oracle.
//
// Usage: go run ./make_adjusted -unicode-variants re2-adjusted.txt re2-unicode.txt
//
// With -unicode-regen it rewrites a hand-written Unicode-mode corpus IN PLACE
// (custom-tests-unicode.txt): its blocks, strings, patterns and comments are
// kept, and every pattern's expectation rows are replaced by Go's answers over
// the pattern without U+FFFD — col0, col1 and col4 as -unicode-variants writes
// them, plus col5 (the first match with captures) and col6 (every match with
// captures) for a pattern tested through the groups export. A pattern either
// oracle cannot take is an error, and the file is then left untouched.
//
// Usage: go run ./make_adjusted -unicode-regen custom-tests-unicode.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/qrdl/regexped/compile"
)

// maxDFAStates mirrors tools/re2test/main.go's own constant of the same
// name — SelectEngine's result (and therefore which of matchFn/groupsFn
// main.go actually tests col0 against) depends on it.
const maxDFAStates = 100000

type regexpEntry struct {
	pattern string
	results []string
}

type section struct {
	name    string
	strings []string
	regexps []regexpEntry
}

func isSectionName(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	if line == "strings" || line == "regexps" {
		return false
	}
	if strings.HasPrefix(line, `"`) {
		return false
	}
	if strings.Contains(line, ";") {
		return false
	}
	if line == "-" {
		return false
	}
	return true
}

func parseSections(path string) ([]section, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sections []section
	var cur *section
	var inStrings, inRegexps bool
	var curPattern string
	var curResults []string

	flushPattern := func() {
		if cur != nil && curPattern != "" {
			cur.regexps = append(cur.regexps, regexpEntry{curPattern, curResults})
			curPattern = ""
			curResults = nil
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		if line == "strings" {
			flushPattern()
			inStrings = true
			inRegexps = false
			continue
		}
		if line == "regexps" {
			inStrings = false
			inRegexps = true
			continue
		}

		// Detect new section name
		if isSectionName(line) {
			flushPattern()
			sections = append(sections, section{name: line})
			cur = &sections[len(sections)-1]
			inStrings = false
			inRegexps = false
			continue
		}

		if inStrings {
			s, err := strconv.Unquote(line)
			if err != nil {
				s = line
			}
			if cur != nil {
				cur.strings = append(cur.strings, s)
			}
			continue
		}
		if inRegexps {
			if strings.HasPrefix(line, `"`) {
				flushPattern()
				p, err := strconv.Unquote(line)
				if err != nil {
					p = line
				}
				curPattern = p
			} else {
				curResults = append(curResults, line)
			}
		}
	}
	flushPattern()
	return sections, scanner.Err()
}

func main() {
	variants := flag.Bool("unicode-variants", false, "read re2-adjusted.txt and write its Unicode-mode variant corpus")
	regen := flag.Bool("unicode-regen", false, "rewrite a Unicode-mode corpus's expectation rows in place, from Go")
	flag.Parse()
	if *regen {
		if flag.NArg() != 1 {
			fmt.Fprintf(os.Stderr, "usage: make_adjusted -unicode-regen <corpus>\n")
			os.Exit(1)
		}
		if err := regenUnicode(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "usage: make_adjusted [-unicode-variants] <input> <output>\n")
		os.Exit(1)
	}

	sections, err := parseSections(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *variants {
		if err := writeUnicodeVariants(sections, flag.Arg(1)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	out, err := os.Create(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer out.Close()
	w := bufio.NewWriter(out)

	nSections, nPatterns, nSkipped := 0, 0, 0

	fmt.Fprintf(w, "# re2-adjusted.txt — RE2 exhaustive patterns with capture groups,\n")
	fmt.Fprintf(w, "# col0 recomputed using Go stdlib (LF semantics).\n")
	fmt.Fprintf(w, "# Generated by: go run ./make_adjusted re2-exhaustive.txt re2-adjusted.txt\n")

	for _, sec := range sections {
		// Keep only sections that have at least one pattern with capture groups.
		hasCapture := false
		for _, rp := range sec.regexps {
			re, err := syntax.Parse(rp.pattern, syntax.Perl)
			if err != nil {
				continue
			}
			if re.MaxCap() > 0 {
				hasCapture = true
				break
			}
		}
		if !hasCapture {
			continue
		}

		fmt.Fprintf(w, "%s\n", sec.name)
		fmt.Fprintf(w, "strings\n")
		for _, s := range sec.strings {
			fmt.Fprintf(w, "%s\n", strconv.Quote(s))
		}
		fmt.Fprintf(w, "regexps\n")
		nSections++

		for _, rp := range sec.regexps {
			if _, parseErr := syntax.Parse(rp.pattern, syntax.Perl); parseErr != nil {
				nSkipped++
				continue
			}

			goRe, compErr := regexp.Compile(rp.pattern)
			if compErr != nil {
				nSkipped++
				continue
			}

			// Which of matchFn/groupsFn tools/re2test/main.go actually tests
			// col0 against is NOT determined by whether the pattern
			// syntactically has capture groups (numGroups) — it's determined
			// by which engine compile.SelectEngine actually picks for it
			// (main.go only wires up groupsFn when the selected engine is
			// Backtrack or TDFA; e.g. `(?:(a){4,5}){0}` has a syntactic
			// capture group but its body is provably unreachable, so the
			// compiler still picks a non-capturing DFA engine and main.go
			// tests it via matchFn instead). Mirror that decision exactly,
			// not the syntactic capture count.
			engineType, selErr := compile.SelectEngine(rp.pattern, compile.CompileOptions{MaxDFAStates: maxDFAStates, ForceByteMode: true})
			testedViaGroups := selErr == nil && (engineType == compile.EngineBacktrack || engineType == compile.EngineTDFA)

			// col0 for a matchFn-tested pattern requires full-input-
			// consumption with leftmost-longest priority (compile/compile.go's
			// needMatch path) — NOT "does the plain leftmost-first match
			// happen to span the whole string". \A(?:...)\z forces the
			// search to consider every full-consuming derivation, matching
			// that contract; a plain unanchored FindStringIndex would miss
			// full-consuming derivations that leftmost-first priority alone
			// wouldn't reach (e.g. lazy quantifiers).
			var goReFull *regexp.Regexp
			if !testedViaGroups {
				var fullErr error
				goReFull, fullErr = regexp.Compile(`\A(?:` + rp.pattern + `)\z`)
				if fullErr != nil {
					nSkipped++
					continue
				}
			}

			fmt.Fprintf(w, "%s\n", strconv.Quote(rp.pattern))
			nPatterns++

			for i, s := range sec.strings {
				// Compute both col0 and col1 using Go stdlib.
				_ = i

				// col1: first find (non-anchored)
				col1 := "-"
				if m := goRe.FindStringIndex(s); m != nil {
					col1 = fmt.Sprintf("%d-%d", m[0], m[1])
				}

				// Recompute col0 using Go stdlib.
				var col0 string
				if testedViaGroups {
					// col0 here is tested against regexped's groupsFn, a
					// non-anchored find-with-captures filtered only by
					// start==0 (NOT also end==len(s) — groupsFn has no
					// full-consumption requirement).
					m := goRe.FindStringSubmatchIndex(s)
					if m == nil || m[0] != 0 {
						col0 = "-"
					} else {
						var slots []string
						for k := 0; k+1 < len(m); k += 2 {
							if m[k] < 0 {
								slots = append(slots, "-")
							} else {
								slots = append(slots, fmt.Sprintf("%d-%d", m[k], m[k+1]))
							}
						}
						col0 = strings.Join(slots, " ")
					}
				} else {
					if m := goReFull.FindStringIndex(s); m == nil {
						col0 = "-"
					} else {
						col0 = fmt.Sprintf("0-%d", m[1])
					}
				}
				fmt.Fprintf(w, "%s;%s;-;-\n", col0, col1)
			}
		}
	}
	w.Flush()
	fmt.Fprintf(os.Stderr, "wrote %d sections, %d patterns (%d skipped)\n",
		nSections, nPatterns, nSkipped)
}

// unicodeVariants returns the inputs one corpus string becomes: a two-byte
// character after its first byte, a three- and a four-byte character around
// it, and invalid UTF-8 — a stray 0xFF in its middle and a sequence cut short
// at its end. An input holding a real U+FFFD gets none: noReplacement's
// oracle cannot judge it.
func unicodeVariants(s string) []string {
	if strings.Contains(s, "\uFFFD") {
		return nil
	}
	mid := len(s) / 2
	first := min(1, len(s))
	return []string{
		s[:first] + "é" + s[first:],
		"日" + s + "😀",
		s[:mid] + "\xff" + s[mid:] + "\xe2\x82",
	}
}

// noReplacement returns pat with U+FFFD taken out of every class and of `.`,
// so Go matches an invalid byte — which it decodes as U+FFFD — with nothing,
// as Unicode mode does.
func noReplacement(pat string) (string, bool) {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return "", false
	}
	without := func(rs []rune) []rune {
		var out []rune
		for i := 0; i+1 < len(rs); i += 2 {
			lo, hi := rs[i], rs[i+1]
			if lo <= utf8.RuneError && utf8.RuneError <= hi {
				if lo < utf8.RuneError {
					out = append(out, lo, utf8.RuneError-1)
				}
				if hi > utf8.RuneError {
					out = append(out, utf8.RuneError+1, hi)
				}
				continue
			}
			out = append(out, lo, hi)
		}
		return out
	}
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpAnyChar:
			r.Op, r.Rune = syntax.OpCharClass, without([]rune{0, utf8.MaxRune})
		case syntax.OpAnyCharNotNL:
			r.Op, r.Rune = syntax.OpCharClass, without([]rune{0, '\n' - 1, '\n' + 1, utf8.MaxRune})
		case syntax.OpCharClass:
			r.Rune = without(r.Rune)
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return re.String(), true
}

// writeUnicodeVariants writes the -unicode-variants corpus (see the file
// comment): col0 as main writes it — groups or full-consumption match by the
// engine Unicode mode selects — col1 the first match, col4 every match.
func writeUnicodeVariants(sections []section, path string) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	fmt.Fprintf(w, "# re2-unicode.txt — re2-adjusted.txt's patterns over Unicode variants of its\n")
	fmt.Fprintf(w, "# strings, every column computed by Go without U+FFFD (Unicode mode's answers).\n")
	fmt.Fprintf(w, "# Generated by: go run ./make_adjusted -unicode-variants re2-adjusted.txt re2-unicode.txt\n")
	nPatterns, nRows := 0, 0
	for _, sec := range sections {
		var strs []string
		for _, s := range sec.strings {
			strs = append(strs, unicodeVariants(s)...)
		}
		if len(strs) == 0 {
			continue
		}
		var pats []unicodeOracle
		for _, rp := range sec.regexps {
			if p, ok := newUnicodeOracle(rp.pattern); ok {
				pats = append(pats, p)
			}
		}
		if len(pats) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\nstrings\n", sec.name)
		for _, s := range strs {
			fmt.Fprintf(w, "%s\n", strconv.Quote(s))
		}
		fmt.Fprintf(w, "regexps\n")
		for _, p := range pats {
			fmt.Fprintf(w, "%s\n", strconv.Quote(p.src))
			nPatterns++
			for _, s := range strs {
				fmt.Fprintf(w, "%s\n", p.row(s, false))
				nRows++
			}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d patterns, %d rows\n", nPatterns, nRows)
	return nil
}

// unicodeOracle is one pattern's Unicode-mode answers, computed by Go over
// the pattern without U+FFFD (noReplacement).
type unicodeOracle struct {
	src  string
	re   *regexp.Regexp
	full *regexp.Regexp // \A(?:pat)\z, for a pattern tested through the match export
	// testedViaGroups mirrors which export tools/re2test/main.go judges col0
	// with: the groups export when the engine Unicode mode selects is
	// Backtracking or TDFA, the match export otherwise.
	testedViaGroups bool
}

func newUnicodeOracle(pattern string) (unicodeOracle, bool) {
	oracle, ok := noReplacement(pattern)
	if !ok {
		return unicodeOracle{}, false
	}
	re, err := regexp.Compile(oracle)
	if err != nil {
		return unicodeOracle{}, false
	}
	eng, err := compile.SelectEngine(pattern, compile.CompileOptions{MaxDFAStates: maxDFAStates, Unicode: true})
	if err != nil {
		return unicodeOracle{}, false
	}
	o := unicodeOracle{src: pattern, re: re, testedViaGroups: eng == compile.EngineBacktrack || eng == compile.EngineTDFA}
	if !o.testedViaGroups {
		if o.full, err = regexp.Compile(`\A(?:` + oracle + `)\z`); err != nil {
			return unicodeOracle{}, false
		}
	}
	return o, true
}

// fmtSubmatch formats one match's slots as the harness's col0/col5 read them:
// "s-e" per group, "-" for a group that took no part.
func fmtSubmatch(m []int) string {
	var slots []string
	for k := 0; k+1 < len(m); k += 2 {
		if m[k] < 0 {
			slots = append(slots, "-")
		} else {
			slots = append(slots, fmt.Sprintf("%d-%d", m[k], m[k+1]))
		}
	}
	return strings.Join(slots, " ")
}

// row is the expectation row for input s: "col0;col1;-;-;col4", and with
// groups set, for a pattern tested through the groups export, ";col5;col6"
// after it.
func (o unicodeOracle) row(s string, groups bool) string {
	col1 := "-"
	if m := o.re.FindStringIndex(s); m != nil {
		col1 = fmt.Sprintf("%d-%d", m[0], m[1])
	}
	col0 := "-"
	if o.testedViaGroups {
		if m := o.re.FindStringSubmatchIndex(s); m != nil && m[0] == 0 {
			col0 = fmtSubmatch(m)
		}
	} else if m := o.full.FindStringIndex(s); m != nil {
		col0 = fmt.Sprintf("0-%d", m[1])
	}
	col4 := "-"
	if all := o.re.FindAllStringIndex(s, -1); len(all) > 0 {
		parts := make([]string, len(all))
		for i, m := range all {
			parts[i] = fmt.Sprintf("%d-%d", m[0], m[1])
		}
		col4 = strings.Join(parts, ",")
	}
	r := fmt.Sprintf("%s;%s;-;-;%s", col0, col1, col4)
	if !groups || !o.testedViaGroups {
		return r
	}
	col5 := "-"
	if m := o.re.FindStringSubmatchIndex(s); m != nil {
		col5 = fmtSubmatch(m)
	}
	col6 := "-"
	if all := o.re.FindAllStringSubmatchIndex(s, -1); len(all) > 0 {
		parts := make([]string, len(all))
		for i, m := range all {
			parts[i] = fmtSubmatch(m)
		}
		col6 = strings.Join(parts, "|")
	}
	return r + ";" + col5 + ";" + col6
}

// regenUnicode rewrites path's expectation rows from Go (see the file
// comment). Comments, block names, strings and patterns pass through; the
// rows after each pattern, whatever they were, are replaced by one row per
// string of its block. Nothing is written unless every pattern was taken.
func regenUnicode(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out, strs []string
	section := ""
	nPatterns, nRows := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		switch {
		case line == "":
			return fmt.Errorf("%s: blank line (the harness refuses them); not rewritten", path)
		case strings.HasPrefix(line, "#"):
			out = append(out, line)
			continue
		case line == "strings":
			section, strs = "strings", strs[:0]
			out = append(out, line)
			continue
		case line == "regexps":
			section = "regexps"
			out = append(out, line)
			continue
		case section == "strings":
			s, err := strconv.Unquote(line)
			if err != nil {
				return fmt.Errorf("%s: string %s: %v; not rewritten", path, line, err)
			}
			strs = append(strs, s)
			out = append(out, line)
			continue
		case section == "regexps" && strings.HasPrefix(line, `"`):
			pat, err := strconv.Unquote(line)
			if err != nil {
				return fmt.Errorf("%s: pattern %s: %v; not rewritten", path, line, err)
			}
			o, ok := newUnicodeOracle(pat)
			if !ok {
				return fmt.Errorf("%s: pattern %q: no Unicode-mode oracle (Go cannot compile it, or Unicode mode refuses it); not rewritten", path, pat)
			}
			out = append(out, line)
			for _, s := range strs {
				if strings.Contains(s, "�") {
					return fmt.Errorf("%s: input %q holds a real U+FFFD, which the oracle cannot judge; not rewritten", path, s)
				}
				out = append(out, o.row(s, true))
				nRows++
			}
			nPatterns++
			continue
		case section == "regexps" && (line[0] == '-' || ('0' <= line[0] && line[0] <= '9')):
			continue // an old row: replaced above
		case isSectionName(line) && 'A' <= line[0] && line[0] <= 'Z':
			section = ""
			out = append(out, line)
			continue
		}
		return fmt.Errorf("%s: unexpected line %q; not rewritten", path, line)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d patterns, %d rows\n", path, nPatterns, nRows)
	return nil
}
