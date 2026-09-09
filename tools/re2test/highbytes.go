package main

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

// ---------------------------------------------------------------------------
// High-byte input coverage.
//
// THE GAP. hasUnicode(text) skips every corpus input containing a byte above
// 0x7F, so no row in the ~9.5M-case exhaustive run ever fed a high byte to any
// engine. That is not a corner: it is why the Backtracking engine could
// truncate every rune range at 0x7F — losing the whole match for `<([^>]+)>`
// over any input carrying a byte >= 0x80, the canonical shape the
// engine-selection gate exists to route there — while the corpus stayed green.
// The fix for that bug had to bring its own test, because no corpus row could
// reach it.
//
// WHY DELETING THE SKIP DOES NOT WORK. The expectation columns are RE2's, and
// RE2 decodes UTF-8 while this is a byte engine. For `.` and negated classes
// the two legitimately disagree: block 26 pairs the pattern `.` with the input
// "\xc2\x80" (U+0080 encoded), where RE2 answers [0,2) and a byte engine
// correctly answers [0,1). Reading those columns as expectations reports
// correct behaviour as failure.
//
// THE ORACLE. Replace each distinct high byte in the INPUT with an ASCII byte
// the pattern cannot tell it apart from, then ask Go about the result. The
// substitution is BYTE-for-byte, not codepoint-for-codepoint, so lengths and
// therefore every reported offset are preserved; the twin is pure ASCII, so
// Go's rune semantics coincide with byte semantics on it. The pattern is left
// alone — no pattern in this corpus names a high byte.
//
// "Cannot tell apart" is the whole correctness argument and is enforced, not
// assumed: see interchangeable below. The first version of this file picked
// substitutes from a pool that led with letters, and `\w` over "±" duly
// reported two matches against a twin of "QZ" — the oracle lying, not the
// engine failing. A high byte is not a word character, so its stand-in must not
// be one either.

// twinCandidates is the pool of substitute bytes, in preference order.
//
// CONTROL characters, because a high byte is outside every positive ASCII class
// — not a letter, digit, underscore or space — and is matched only by `.` and
// by negated classes, which saturate to 0xFF. Control characters share exactly
// those properties and are almost never named by a pattern.
//
// 0x09-0x0D are excluded as \s members (and 0x0A is what `.` excludes); 0x00 is
// excluded because a NUL in a test input buys nothing and confuses harnesses.
var twinCandidates = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F,
}

// byteRange is one rune range from the pattern's AST, evaluated in BYTE space.
type byteRange struct{ lo, hi rune }

// namesByte reports whether the range covers byte b. A range extending past
// 0xFF is clamped, which is exactly what the byte engines do with the
// open-ended tail of a negated class.
func (r byteRange) namesByte(b byte) bool {
	hi := r.hi
	if hi > 0xFF {
		hi = 0xFF
	}
	return rune(b) >= r.lo && rune(b) <= hi
}

// patternByteRanges collects every rune range the pattern names, and whether it
// contains a dot that excludes newline.
func patternByteRanges(pattern string) (ranges []byteRange, hasDotNotNL bool, ok bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false, false
	}
	var walk func(*syntax.Regexp)
	walk = func(n *syntax.Regexp) {
		switch n.Op {
		case syntax.OpLiteral:
			for _, r := range n.Rune {
				ranges = append(ranges, byteRange{r, r})
			}
		case syntax.OpCharClass:
			for i := 0; i+1 < len(n.Rune); i += 2 {
				ranges = append(ranges, byteRange{n.Rune[i], n.Rune[i+1]})
			}
		case syntax.OpAnyCharNotNL:
			hasDotNotNL = true
		}
		for _, sub := range n.Sub {
			walk(sub)
		}
	}
	walk(re)
	return ranges, hasDotNotNL, true
}

// interchangeable reports whether byte c behaves identically to byte h under
// every range the pattern names.
//
// This is what makes the twin an oracle rather than a guess. A byte engine's
// answer depends on an input byte ONLY through which of the pattern's classes
// contain it. If c and h fall inside exactly the same ranges, substituting one
// for the other cannot change any answer, and because the substitution is
// byte-for-byte it cannot move any position either.
//
// \b and \B come along for free: word-ness is membership of [0-9A-Za-z_], so a
// control character and a high byte are both outside it and neither can flip a
// boundary the other would not.
func interchangeable(c, h byte, ranges []byteRange, hasDotNotNL bool) bool {
	if hasDotNotNL && (c == '\n' || h == '\n') {
		return false
	}
	for _, r := range ranges {
		if r.namesByte(c) != r.namesByte(h) {
			return false
		}
	}
	return true
}

// asciiTwin returns an ASCII input isomorphic to text for a byte engine
// running this pattern, or ok=false when one cannot be built.
//
// It refuses when the pattern itself names a high byte: the substitution would
// then have to rewrite the pattern too, and the correspondence argument no
// longer holds. preCheck already skips such patterns, so this is belt and
// braces.
func asciiTwin(text, pattern string) (string, bool) {
	if !hasHighByte(text) {
		return text, true
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] >= 0x80 {
			return "", false
		}
	}
	ranges, hasDotNotNL, ok := patternByteRanges(pattern)
	if !ok {
		return "", false
	}
	// Bytes already in the input are unavailable: a substitute has to stay
	// distinguishable from the input's own ASCII, or two bytes the engine can
	// tell apart would collapse into one.
	var used [256]bool
	for i := 0; i < len(text); i++ {
		used[text[i]] = true
	}
	mapping := make(map[byte]byte)
	out := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b < 0x80 {
			out[i] = b
			continue
		}
		sub, seen := mapping[b]
		if !seen {
			found := false
			for _, cand := range twinCandidates {
				if used[cand] || !interchangeable(cand, b, ranges, hasDotNotNL) {
					continue
				}
				sub, found = cand, true
				break
			}
			if !found {
				return "", false // nothing interchangeable left; skip this row
			}
			used[sub] = true
			mapping[b] = sub
		}
		out[i] = sub
	}
	return string(out), true
}

// hasHighByte reports whether s contains a byte above 0x7F. Distinct from
// hasUnicode, which decodes RUNES (so invalid UTF-8 yields RuneError) and also
// fires on the literal substrings `\p` / `\P` — right for judging a PATTERN,
// wrong for judging whether an INPUT carries a raw high byte.
func hasHighByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// highByteCols recomputes the expectation columns for a high-byte row from Go,
// run against the ASCII twin. ok=false means the row cannot be judged this way
// and must stay skipped.
//
// The columns come back in the corpus's own textual format, so the caller
// substitutes them and every downstream parser and comparison runs unchanged.
//
// col5 and col6 are deliberately left to the caller as "-": both are
// capture-reentry columns carrying more structure than this needs, and col0
// already exercises the capture path under --validate-groups. A separate step,
// not a silent gap.
func highByteCols(pattern, text string) (col0, col1, col4 string, ok bool) {
	twin, ok := asciiTwin(text, pattern)
	if !ok {
		return "", "", "", false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", "", "", false // \C and friends: Go cannot serve as oracle
	}
	// col0 is the ANCHORED, full-consumption answer. The wrapper must be
	// \A(?:pat)\z rather than a find whose span is then checked: `a|ab` over
	// "ab" finds `a` and spans 0-1 while the anchored answer is 0-2 — the trap
	// documented at the --validate-go call site. Wrapping in (?: ) leaves
	// capture numbering untouched.
	anchored, aerr := regexp.Compile(`\A(?:` + pattern + `)\z`)
	if aerr != nil {
		return "", "", "", false
	}
	col0 = "-"
	if m := anchored.FindStringSubmatchIndex(twin); m != nil {
		var sb strings.Builder
		for g := 0; g*2 < len(m); g++ {
			if g > 0 {
				sb.WriteByte(' ')
			}
			if m[g*2] < 0 {
				sb.WriteByte('-')
				continue
			}
			fmt.Fprintf(&sb, "%d-%d", m[g*2], m[g*2+1])
		}
		col0 = sb.String()
	}
	col1 = "-"
	if loc := re.FindStringIndex(twin); loc != nil {
		col1 = fmt.Sprintf("%d-%d", loc[0], loc[1])
	}
	col4 = formatAllMatches(re.FindAllStringIndex(twin, -1))
	return col0, col1, col4, true
}

// formatAllMatches renders Go's FindAll output in the corpus's col4 format.
func formatAllMatches(all [][]int) string {
	if len(all) == 0 {
		return "-"
	}
	parts := make([]string, len(all))
	for i, p := range all {
		parts[i] = fmt.Sprintf("%d-%d", p[0], p[1])
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// The SECOND blind spot: only the FIRST match is ever checked.
//
// re2-exhaustive.txt carries four columns, so col4 — every match — is absent
// for all ~9.5M of its rows, and col1 checks one match per row. A pattern whose
// first match is right and whose later matches are wrong passes.
//
// That is not hypothetical. It is half of why `` could skip every boundary
// whose preceding byte was a word character: the first match of a bare `` is
// at position 0, which was always found, and the defect lived entirely in the
// matches after it. The high-byte harness only caught it because it SYNTHESISES
// col4, so it was checking a column the rest of the corpus never had.
//
// goAllMatchesCol closes that for the ASCII rows, which is the bulk of the
// corpus. No twin is needed: for pure-ASCII input Go's rune semantics already
// coincide with byte semantics, so Go's FindAllStringIndex IS the byte answer.
// High-byte rows are left to highByteCols, which has to go through a twin.
func goAllMatchesCol(pattern, text string) (string, bool) {
	if hasHighByte(text) {
		return "", false // the twin path owns these
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false // \C and friends: Go cannot serve as oracle
	}
	return formatAllMatches(re.FindAllStringIndex(text, -1)), true
}

// ---------------------------------------------------------------------------
// Set mode.
//
// setcaps has the same blind spot one layer down, and papered over rather than
// skipped: every non-ASCII input bypasses the live Go oracle and is compared
// against the corpus's PINNED col4 column instead — gated `find` only, one
// capability of five. `match_any`, `match_all`, `scan_any`, `scan_all` and
// overlapping `find` get NO high-byte coverage at all, and a pinned column is
// a transcript of what was expected once, not an independent oracle.
//
// The stated reason is real: the oracle's whole-input probe counts RUNES in its
// `.{p}` prefix, so on a multi-byte input position p is not the byte offset the
// module was given.
//
// The twin removes that objection. It is pure ASCII, so rune positions and byte
// positions coincide and the probe means what it says; the module is still
// driven over the ORIGINAL bytes. It also resolves, rather than papers over,
// the byte-vs-rune advance on empty matches: Go's rune advance over an ASCII
// twin IS a byte advance, so the oracle now states the engine's contract
// instead of contradicting it.
//
// A set is driven once per input for ALL its patterns, so the substitute has to
// be interchangeable with respect to every pattern in the chunk at once — not
// one, as in the single-pattern path. Where no such byte exists the row falls
// back to the pinned path, which is why that path stays.

// asciiTwinForPatterns is asciiTwin over a whole set: the substitute must be
// interchangeable under EVERY pattern's ranges simultaneously.
func asciiTwinForPatterns(text string, patterns []string) (string, bool) {
	if !hasHighByte(text) {
		return text, true
	}
	var ranges []byteRange
	dotNotNL := false
	for _, pat := range patterns {
		for i := 0; i < len(pat); i++ {
			if pat[i] >= 0x80 {
				return "", false
			}
		}
		rs, dnl, ok := patternByteRanges(pat)
		if !ok {
			return "", false
		}
		ranges = append(ranges, rs...)
		dotNotNL = dotNotNL || dnl
	}
	var used [256]bool
	for i := 0; i < len(text); i++ {
		used[text[i]] = true
	}
	mapping := make(map[byte]byte)
	out := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b < 0x80 {
			out[i] = b
			continue
		}
		sub, seen := mapping[b]
		if !seen {
			found := false
			for _, cand := range twinCandidates {
				if used[cand] || !interchangeable(cand, b, ranges, dotNotNL) {
					continue
				}
				sub, found = cand, true
				break
			}
			if !found {
				return "", false
			}
			used[sub] = true
			mapping[b] = sub
		}
		out[i] = sub
	}
	return string(out), true
}

// setOracleStrings returns, for each input, the string the ORACLE should be
// computed over, plus whether the live oracle can serve that row at all.
//
// ASCII inputs are their own oracle string. A high-byte input becomes its twin
// when one exists. Anything else is left to the pinned path.
func setOracleStrings(pats, strs []string) (oracleStrs []string, live []bool) {
	oracleStrs = make([]string, len(strs))
	live = make([]bool, len(strs))
	for si, s := range strs {
		if !hasHighByte(s) {
			oracleStrs[si], live[si] = s, true
			continue
		}
		if twin, ok := asciiTwinForPatterns(s, pats); ok {
			oracleStrs[si], live[si] = twin, true
			continue
		}
		oracleStrs[si], live[si] = s, false
	}
	return oracleStrs, live
}
