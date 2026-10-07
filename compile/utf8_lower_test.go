package compile

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/qrdl/regexped/config"
)

// bytePat, byteTree, byteProg and their plural forms hand a test a pattern,
// tree or program in byte mode directly. Tests drive internals with values
// the resolver would build; TestProgModeOnlyFromResolver does not read test
// files.
func bytePat(src string) resolvedPattern { return resolvedPattern{src: src, pm: progModeByte} }

func byteTree(re *syntax.Regexp) resolvedTree { return resolvedTree{re: re, pm: progModeByte} }

func unicodeTree(re *syntax.Regexp) resolvedTree { return resolvedTree{re: re, pm: progModeUnicode} }

func unicodePat(src string) resolvedPattern { return resolvedPattern{src: src, pm: progModeUnicode} }

func byteProg(p *syntax.Prog) resolvedProg { return resolvedProg{prog: p, orig: p, pm: progModeByte} }

func byteTrees(res []*syntax.Regexp) []resolvedTree {
	out := make([]resolvedTree, len(res))
	for i, re := range res {
		out[i] = byteTree(re)
	}
	return out
}

func byteProgs(ps []*syntax.Prog) []resolvedProg {
	out := make([]resolvedProg, len(ps))
	for i, p := range ps {
		out[i] = byteProg(p)
	}
	return out
}

// lowerBatteryClasses are the single classes the UTF-8 lowering is checked
// against exhaustively. Beyond the obvious ones, each range is there for a
// split it forces: `[\x{80}-\x{7ff}]` is exactly the two-byte encodings,
// `[\x{d7ff}-\x{e000}]` straddles the surrogates (which must lower to
// nothing), `\x{10ffff}` is the last encodable codepoint, and
// `[a-\x{10ffff}]` crosses every length boundary from ASCII up.
var lowerBatteryClasses = []string{
	`\pL`, `\p{Greek}`, `[^a]`, `.`, `(?s:.)`,
	`[\x{80}-\x{7ff}]`, `[\x{d7ff}-\x{e000}]`, `\x{10ffff}`, `[a-\x{10ffff}]`,
	`[\p{L}\p{N}_]`,
}

// lowerDirs are the two directions the lowering batteries run in. Reverse
// is a reverse program as the compiler builds one — compiled from
// reverseRegexp's tree, lowered by lowerUTF8Reverse — and every byte string
// is fed to it back to front, the way a backward scan reads it.
var lowerDirs = []struct {
	name    string
	reverse bool
}{{"forward", false}, {"reverse", true}}

// lowerOrient returns b as a program of the given direction reads it: b
// itself, or a reversed copy.
func lowerOrient(b []byte, reverse bool) []byte {
	if !reverse {
		return b
	}
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}

// lowerTestProgs compiles pattern the way the compiler does — parse,
// reverseRegexp for a reverse program, Simplify, syntax.Compile — and returns
// the program before and after lowering in that direction, the lowered one
// already checked for the shape engines rely on.
func lowerTestProgs(t *testing.T, pattern string, reverse bool) (orig, low *syntax.Prog) {
	t.Helper()
	re := parseTestRe(t, pattern)
	if reverse {
		re = reverseRegexp(re)
	}
	orig, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("syntax.Compile(%q): %v", pattern, err)
	}
	if reverse {
		low = lowerUTF8Reverse(orig)
	} else {
		low = lowerUTF8(orig)
	}
	checkLoweredShape(t, pattern, low)
	return orig, low
}

// checkLoweredShape asserts what every engine relies on in a lowered
// program: it consumes byte ranges only — InstRune/InstRune1 over
// 0x00-0xFF, with no FoldCase and no InstRuneAny* — and every successor is a
// real PC.
func checkLoweredShape(t *testing.T, pattern string, p *syntax.Prog) {
	t.Helper()
	isPC := func(pc uint32) bool { return int(pc) < len(p.Inst) }
	if p.Start < 0 || p.Start >= len(p.Inst) {
		t.Fatalf("%q: Start %d outside %d instructions", pattern, p.Start, len(p.Inst))
	}
	for pc := range p.Inst {
		inst := &p.Inst[pc]
		switch inst.Op {
		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			t.Fatalf("%q: lowered pc %d is %v, which consumes a codepoint", pattern, pc, inst.Op)
		case syntax.InstRune, syntax.InstRune1:
			if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
				t.Fatalf("%q: lowered pc %d carries FoldCase", pattern, pc)
			}
			if len(inst.Rune) == 0 || (inst.Op == syntax.InstRune && len(inst.Rune)%2 != 0) {
				t.Fatalf("%q: lowered pc %d has malformed ranges %v", pattern, pc, inst.Rune)
			}
			for _, r := range inst.Rune {
				if r < 0 || r > 0xFF {
					t.Fatalf("%q: lowered pc %d consumes %#x, not a byte", pattern, pc, r)
				}
			}
		}
		switch inst.Op {
		case syntax.InstMatch, syntax.InstFail:
		case syntax.InstAlt, syntax.InstAltMatch:
			if !isPC(inst.Out) || !isPC(inst.Arg) {
				t.Fatalf("%q: lowered pc %d branches outside the program", pattern, pc)
			}
		default:
			if !isPC(inst.Out) {
				t.Fatalf("%q: lowered pc %d continues outside the program", pattern, pc)
			}
		}
	}
}

// lowerClosure follows every epsilon edge from pcs and returns the consuming
// instructions reached, sorted, and whether Match was reached. The acceptance
// simulator below runs single classes, which carry no assertion; guessing an
// assertion's context would test nothing, so meeting one fails the test.
func lowerClosure(t *testing.T, p *syntax.Prog, pcs []uint32) ([]uint32, bool) {
	t.Helper()
	seen := make(map[uint32]bool)
	var consume []uint32
	match := false
	stack := slices.Clone(pcs)
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		inst := &p.Inst[pc]
		switch inst.Op {
		case syntax.InstMatch:
			match = true
		case syntax.InstFail:
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, inst.Out, inst.Arg)
		case syntax.InstNop, syntax.InstCapture:
			stack = append(stack, inst.Out)
		case syntax.InstEmptyWidth:
			t.Fatalf("pc %d: the acceptance simulator does not model assertions", pc)
		default:
			consume = append(consume, pc)
		}
	}
	slices.Sort(consume)
	return consume, match
}

// lowerDFA answers whether a lowered program matches an input EXACTLY, by
// Thompson simulation memoised on (thread set, byte) — a lazily built DFA.
// The memo is what makes the exhaustive battery affordable: ~1.1M inputs per
// class, through programs of up to ~2,000 instructions, all starting from the
// same closure. State 0 is the start.
type lowerDFA struct {
	t      *testing.T
	prog   *syntax.Prog
	ids    map[string]int32
	sets   [][]uint32
	accept []bool
	next   [][256]int32 // -1 until built
}

func newLowerDFA(t *testing.T, p *syntax.Prog) *lowerDFA {
	d := &lowerDFA{t: t, prog: p, ids: make(map[string]int32)}
	d.intern(lowerClosure(t, p, []uint32{uint32(p.Start)}))
	return d
}

func (d *lowerDFA) intern(set []uint32, match bool) int32 {
	key := fmt.Sprint(match, set)
	if id, ok := d.ids[key]; ok {
		return id
	}
	id := int32(len(d.sets))
	d.ids[key] = id
	d.sets = append(d.sets, set)
	d.accept = append(d.accept, match)
	var row [256]int32
	for i := range row {
		row[i] = -1
	}
	d.next = append(d.next, row)
	return id
}

func (d *lowerDFA) step(s int32, b byte) int32 {
	if n := d.next[s][b]; n >= 0 {
		return n
	}
	var outs []uint32
	for _, pc := range d.sets[s] {
		if inst := &d.prog.Inst[pc]; inst.MatchRune(rune(b)) {
			outs = append(outs, inst.Out)
		}
	}
	n := d.intern(lowerClosure(d.t, d.prog, outs))
	d.next[s][b] = n
	return n
}

func (d *lowerDFA) accepts(in []byte) bool {
	s := int32(0)
	for _, b := range in {
		s = d.step(s, b)
	}
	return d.accept[s]
}

// count returns how many distinct byte strings the program accepts from
// state s, entered after depth bytes. A class accepts nothing longer than
// four bytes, so a thread still alive after four fails the test rather than
// being followed.
func (d *lowerDFA) count(s int32, depth int, memo map[[2]int32]int) int {
	if n, ok := memo[[2]int32{s, int32(depth)}]; ok {
		return n
	}
	n := 0
	if d.accept[s] {
		n = 1
	}
	if len(d.sets[s]) > 0 {
		if depth == utf8.UTFMax {
			d.t.Fatalf("a thread is still alive after %d bytes", depth)
		}
		for b := range 256 {
			n += d.count(d.step(s, byte(b)), depth+1, memo)
		}
	}
	memo[[2]int32{s, int32(depth)}] = n
	return n
}

// lowerRuneOracle returns the membership test of the single class the
// ORIGINAL program p matches: whether p matches exactly the one-codepoint
// string c. The answer comes from Go's own Inst.MatchRune over codepoints,
// not from anything the lowering computes.
func lowerRuneOracle(t *testing.T, p *syntax.Prog) func(rune) bool {
	type arm struct {
		inst    *syntax.Inst
		accepts bool
	}
	var arms []arm
	start, _ := lowerClosure(t, p, []uint32{uint32(p.Start)})
	for _, pc := range start {
		_, m := lowerClosure(t, p, []uint32{p.Inst[pc].Out})
		arms = append(arms, arm{&p.Inst[pc], m})
	}
	return func(c rune) bool {
		for _, a := range arms {
			if a.accepts && a.inst.MatchRune(c) {
				return true
			}
		}
		return false
	}
}

// TestLowerUTF8ClassBattery checks every lowered battery class against its
// original over the whole codespace: the UTF-8 of every codepoint in the
// class is accepted and that of every codepoint outside it rejected, over
// 0..U+10FFFF minus the surrogates, which have no encoding. That shows the
// lowered language holds exactly the class's encodings among the valid
// ones; counting every byte string the lowered program accepts, and finding
// the class's size, shows it holds nothing else — no invalid sequence either.
//
// It also asserts the suffix sharing: no two consuming instructions agree on
// both their ranges and their successor, where a flat lowering repeats
// [80-BF]→exit once per multi-byte sequence.
//
// Both directions: a reverse program must accept each encoding back to front.
func TestLowerUTF8ClassBattery(t *testing.T) {
	for _, dir := range lowerDirs {
		for _, pat := range lowerBatteryClasses {
			t.Run(dir.name+"/"+pat, func(t *testing.T) {
				lowerClassBattery(t, pat, dir.reverse)
			})
		}
	}
}

func lowerClassBattery(t *testing.T, pat string, reverse bool) {
	orig, low := lowerTestProgs(t, pat, reverse)
	inClass := lowerRuneOracle(t, orig)
	d := newLowerDFA(t, low)
	var buf [utf8.UTFMax]byte
	members := 0
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if c >= 0xD800 && c <= 0xDFFF {
			continue
		}
		want := inClass(c)
		n := utf8.EncodeRune(buf[:], c)
		if got := d.accepts(lowerOrient(buf[:n], reverse)); got != want {
			t.Fatalf("U+%04X (% X): lowered accepts = %v, class membership = %v",
				c, buf[:n], got, want)
		}
		if want {
			members++
		}
	}
	if members == 0 {
		t.Fatal("the class has no members; the case tests nothing")
	}
	if got := d.count(0, 0, make(map[[2]int32]int)); got != members {
		t.Fatalf("the lowered program accepts %d byte strings but the class has %d "+
			"codepoints: it accepts something that encodes none of them", got, members)
	}
	seen := make(map[string]int)
	for pc, inst := range low.Inst {
		if inst.Op != syntax.InstRune && inst.Op != syntax.InstRune1 {
			continue
		}
		k := fmt.Sprint(inst.Rune, inst.Out)
		if prev, ok := seen[k]; ok {
			t.Fatalf("pcs %d and %d are the same range with the same successor: "+
				"a suffix was not shared", prev, pc)
		}
		seen[k] = pc
	}
	// The prefix trie: the arms of every alternation begin on disjoint byte
	// ranges, so a walk takes at most one of them on any byte and Backtracking
	// tries one arm, not every sequence of the class.
	armRanges := func(in syntax.Inst) [][2]rune {
		switch in.Op {
		case syntax.InstRune1:
			return [][2]rune{{in.Rune[0], in.Rune[0]}}
		case syntax.InstRune:
			var out [][2]rune
			for i := 0; i+1 < len(in.Rune); i += 2 {
				out = append(out, [2]rune{in.Rune[i], in.Rune[i+1]})
			}
			return out
		}
		return nil
	}
	for pc, inst := range low.Inst {
		if inst.Op != syntax.InstAlt {
			continue
		}
		var ranges [][2]rune
		for at := uint32(pc); ; {
			a := low.Inst[at]
			ranges = append(ranges, armRanges(low.Inst[a.Out])...)
			if low.Inst[a.Arg].Op != syntax.InstAlt {
				ranges = append(ranges, armRanges(low.Inst[a.Arg])...)
				break
			}
			at = a.Arg
		}
		slices.SortFunc(ranges, func(x, y [2]rune) int { return cmp.Compare(x[0], y[0]) })
		for i := 1; i < len(ranges); i++ {
			if ranges[i][0] <= ranges[i-1][1] {
				t.Fatalf("the alternation at pc %d has arms on overlapping bytes %#x-%#x and %#x-%#x",
					pc, ranges[i-1][0], ranges[i-1][1], ranges[i][0], ranges[i][1])
			}
		}
	}
	t.Logf("%d instructions, %d lowered; %d codepoints", len(orig.Inst), len(low.Inst), members)
}

// TestLowerUTF8LeadArms pins how many arms a lowered class's entry has: one
// per distinct lead byte range, plus the ASCII arm — not one per UTF-8
// sequence, which is what Backtracking used to push a frame for on every
// character a class rejects (`\pL`: 800).
func TestLowerUTF8LeadArms(t *testing.T) {
	for _, c := range []struct {
		pat  string
		arms int
	}{{`\pL`, 34}, {`\p{Han}`, 6}, {`\p{Cyrillic}`, 9}, {`[^,]`, 9}} {
		_, low := lowerTestProgs(t, c.pat, false)
		arms := 1
		for pc := low.Start; low.Inst[pc].Op == syntax.InstAlt; pc = int(low.Inst[pc].Arg) {
			arms++
		}
		if arms != c.arms {
			t.Errorf("%s: the lowered class's entry has %d arms, want %d", c.pat, arms, c.arms)
		}
	}
}

// TestLowerUTF8RejectsInvalid drives byte strings that are not UTF-8 through
// every lowered battery class, and each non-empty prefix of them too: an
// overlong form, a surrogate, a value past U+10FFFF, a stray continuation
// byte and a truncated sequence must all fail, including under `.` and
// `[^a]`, which accept every VALID codepoint. The overlongs sit on the
// boundaries the sequence split cuts at. Every string checked is asserted
// invalid first, so the battery says nothing about a valid one.
//
// A reverse program reads from the right end, so it is fed each non-empty
// SUFFIX instead, back to front.
func TestLowerUTF8RejectsInvalid(t *testing.T) {
	invalid := []struct {
		name string
		b    []byte
	}{
		{"overlong U+0000 in 2 bytes", []byte{0xC0, 0x80}},
		{"overlong U+007F in 2 bytes", []byte{0xC1, 0xBF}},
		{"overlong U+0000 in 3 bytes", []byte{0xE0, 0x80, 0x80}},
		{"overlong U+07FF in 3 bytes", []byte{0xE0, 0x9F, 0xBF}},
		{"overlong U+0000 in 4 bytes", []byte{0xF0, 0x80, 0x80, 0x80}},
		{"overlong U+FFFF in 4 bytes", []byte{0xF0, 0x8F, 0xBF, 0xBF}},
		{"surrogate U+D800", []byte{0xED, 0xA0, 0x80}},
		{"surrogate U+DFFF", []byte{0xED, 0xBF, 0xBF}},
		{"U+110000", []byte{0xF4, 0x90, 0x80, 0x80}},
		{"lead byte F5", []byte{0xF5, 0x80, 0x80, 0x80}},
		{"byte FF", []byte{0xFF}},
		{"stray continuation 80", []byte{0x80}},
		{"stray continuation BF", []byte{0xBF}},
		{"two stray continuations", []byte{0x80, 0xBF}},
		{"truncated U+20AC", []byte{0xE2, 0x82}},
		{"truncated U+1F600", []byte{0xF0, 0x9F, 0x98}},
	}
	for _, dir := range lowerDirs {
		for _, pat := range lowerBatteryClasses {
			_, low := lowerTestProgs(t, pat, dir.reverse)
			d := newLowerDFA(t, low)
			for _, c := range invalid {
				for n := 1; n <= len(c.b); n++ {
					b := c.b[:n]
					if dir.reverse {
						b = c.b[len(c.b)-n:]
					}
					if utf8.Valid(b) {
						t.Fatalf("test data: %s %s % X is valid UTF-8", c.name, dir.name, b)
					}
					if d.accepts(lowerOrient(b, dir.reverse)) {
						t.Errorf("%s %q accepts % X (%s)", dir.name, pat, b, c.name)
					}
				}
			}
		}
	}
}

// TestLowerUTF8SurrogatesLowerToNothing: surrogates have no encoding, so a
// class of nothing else must lower to a program that accepts nothing, and a
// class whose only other member is ASCII to exactly that byte.
func TestLowerUTF8SurrogatesLowerToNothing(t *testing.T) {
	for _, c := range []struct {
		pat  string
		want int
	}{
		{`[\x{d800}-\x{dfff}]`, 0},
		{`[a\x{d800}-\x{dfff}]`, 1},
	} {
		for _, dir := range lowerDirs {
			_, low := lowerTestProgs(t, c.pat, dir.reverse)
			d := newLowerDFA(t, low)
			if got := d.count(0, 0, make(map[[2]int32]int)); got != c.want {
				t.Errorf("%s %q: lowered program accepts %d byte strings, want %d", dir.name, c.pat, got, c.want)
			}
			if c.want == 1 && !d.accepts([]byte("a")) {
				t.Errorf("%s %q: lowered program rejects \"a\"", dir.name, c.pat)
			}
		}
	}
}

// TestLowerUTF8ReversePattern checks whole reverse programs, where
// reverseRegexp has reversed the codepoints of literals and concatenations
// and the lowering must reverse the bytes inside each one: the reverse
// program accepts an input back to front exactly when Go matches the whole
// input forward. As a control, the same program lowered FORWARD — the
// mistake lowerUTF8Reverse exists to prevent — must get some multi-byte
// input wrong, or the inputs would not tell the two lowerings apart.
func TestLowerUTF8ReversePattern(t *testing.T) {
	patterns := []string{
		`é+ж`, `(?i)σx\pL`, `[à-ÿ]{2}日`, `a.b`, `(\pL|1)+é`, `\x{10ffff}\x{80}`,
	}
	inputs := []string{
		"", "é", "ж", "éж", "ééж", "жé", "σxa", "Σxж", "ςxé", "sxa", "σx1",
		"àÿ日", "à日", "日àÿ", "a€b", "aéb", "ab", "a\U0001F600b", "a\nb",
		"1é", "é1é", "日é", "é日", "\U0010FFFF\u0080", "\u0080\U0010FFFF",
	}
	for _, pat := range patterns {
		orig, low := lowerTestProgs(t, pat, true)
		wrong := newLowerDFA(t, lowerUTF8(orig))
		d := newLowerDFA(t, low)
		goRE := regexp.MustCompile(`^(?:` + pat + `)$`)
		caught := false
		for _, in := range inputs {
			want := goRE.MatchString(in)
			b := lowerOrient([]byte(in), true)
			if got := d.accepts(b); got != want {
				t.Errorf("%q over %q back to front: lowered accepts = %v, Go matches = %v", pat, in, got, want)
			}
			if wrong.accepts(b) != want {
				caught = true
			}
		}
		if !caught {
			t.Errorf("%q: no input tells the reverse lowering from the forward one", pat)
		}
	}
}

// lowerPikeFind is a leftmost-first Pike VM — Go regexp's semantics — that
// returns the capture slots of the first match in byte offsets, or nil. With
// runes set it steps prog one decoded codepoint at a time, which is how the
// ORIGINAL program is read; otherwise one byte at a time, each byte handed to
// MatchRune as its value, which is how every engine here reads a lowered one.
func lowerPikeFind(prog *syntax.Prog, in []byte, runes bool) []int {
	type thread struct {
		pc  uint32
		cap []int
	}
	type queue struct {
		th []thread
		on []bool
	}
	symAt := func(pos int) (rune, int) {
		if pos >= len(in) {
			return -1, 0
		}
		if runes {
			return utf8.DecodeRune(in[pos:])
		}
		return rune(in[pos]), 1
	}
	before := func(pos int) rune {
		if pos == 0 {
			return -1
		}
		if runes {
			r, _ := utf8.DecodeLastRune(in[:pos])
			return r
		}
		return rune(in[pos-1])
	}
	var add func(q *queue, pc uint32, pos int, cap []int)
	add = func(q *queue, pc uint32, pos int, cap []int) {
		if q.on[pc] {
			return
		}
		q.on[pc] = true
		switch inst := &prog.Inst[pc]; inst.Op {
		case syntax.InstFail:
		case syntax.InstAlt, syntax.InstAltMatch:
			add(q, inst.Out, pos, cap)
			add(q, inst.Arg, pos, cap)
		case syntax.InstNop:
			add(q, inst.Out, pos, cap)
		case syntax.InstCapture:
			c := slices.Clone(cap)
			if int(inst.Arg) < len(c) {
				c[inst.Arg] = pos
			}
			add(q, inst.Out, pos, c)
		case syntax.InstEmptyWidth:
			after, _ := symAt(pos)
			if syntax.EmptyOp(inst.Arg)&^syntax.EmptyOpContext(before(pos), after) == 0 {
				add(q, inst.Out, pos, cap)
			}
		default:
			q.th = append(q.th, thread{pc, cap})
		}
	}
	run := &queue{on: make([]bool, len(prog.Inst))}
	next := &queue{on: make([]bool, len(prog.Inst))}
	var matched []int
	for pos := 0; ; {
		if matched == nil {
			cap := make([]int, prog.NumCap)
			for i := range cap {
				cap[i] = -1
			}
			cap[0] = pos
			add(run, uint32(prog.Start), pos, cap)
		}
		r, w := symAt(pos)
		for _, th := range run.th {
			inst := &prog.Inst[th.pc]
			if inst.Op == syntax.InstMatch {
				matched = slices.Clone(th.cap)
				matched[1] = pos
				break // every later thread has lower priority
			}
			if w > 0 && inst.MatchRune(r) {
				add(next, inst.Out, pos+w, th.cap)
			}
		}
		if w == 0 || (matched != nil && len(next.th) == 0) {
			return matched
		}
		run, next = next, run
		next.th = next.th[:0]
		clear(next.on)
		pos += w
	}
}

// TestLowerUTF8Priority checks that lowering leaves leftmost-first answers
// alone: the first match of every pattern over every input has the same
// capture slots before lowering (read codepoint by codepoint) and after it
// (read byte by byte), and the codepoint reading agrees with Go's regexp, so
// the simulator is itself checked. A lowered class's arms need no order —
// only the original program's own alternations have a priority to keep.
// `a|\pL` and `[ab]|\pL` are merged into one class by Go's parser; the
// capturing spellings are not, so they make leftmost-first choose between an
// ASCII arm and a lowered class, and between arms of different lengths, which
// is where a reordering would show. Every pattern consumes at least one
// codepoint: an empty match inside a codepoint is a question for the find
// machinery, not for this pass.
func TestLowerUTF8Priority(t *testing.T) {
	patterns := []string{
		`a|\pL`, `[ab]|\pL`,
		`(a)|(\pL)`, `(\pL)|(a)`, `([ab])|(\pL)`,
		`(a)|(\pL\pL)`, `(\pL)|(\pL\pL)`, `(\pL\pL)|(\pL)`,
		`(é)|([^a]+)`, `(\pL+?)(\pL*)`, `(\pL+)@(\pL+)`,
		`^(é|a)+\b`, `(?m)^.$`, `(.)(.)`,
	}
	inputs := []string{
		"", "a", "b", "é", "ab", "aé", "éa", "éé", "1é", "x@y", "é@ж",
		"日本@語", "\U0001D538b", "aK", "x\nй\n", "é\U0001F600a",
	}
	for _, pat := range patterns {
		orig, low := lowerTestProgs(t, pat, false)
		goRE := regexp.MustCompile(pat)
		for _, in := range inputs {
			want := lowerPikeFind(orig, []byte(in), true)
			if goWant := goRE.FindStringSubmatchIndex(in); !slices.Equal(want, goWant) {
				t.Fatalf("simulator disagrees with Go: %q over %q = %v, Go says %v", pat, in, want, goWant)
			}
			if got := lowerPikeFind(low, []byte(in), false); !slices.Equal(got, want) {
				t.Errorf("%q over %q: lowered %v, original %v", pat, in, got, want)
			}
		}
	}
}

// TestLowerUTF8ASCIIUnchanged: an unfolded program with no codepoint past
// 0x7F lowers to an instruction-for-instruction copy of itself, in either
// direction — a rune ≤ 0x7F is its own encoding, and nothing else is
// rewritten.
func TestLowerUTF8ASCIIUnchanged(t *testing.T) {
	for _, dir := range lowerDirs {
		for _, pat := range []string{`abc`, `(a+|b)\bc$`, `[a-z0-9_]*?x`, `(?m)^\w+$`, `a[\x00-\x7f]b`} {
			orig, low := lowerTestProgs(t, pat, dir.reverse)
			same := orig.Start == low.Start && orig.NumCap == low.NumCap &&
				slices.EqualFunc(orig.Inst, low.Inst, func(a, b syntax.Inst) bool {
					return a.Op == b.Op && a.Out == b.Out && a.Arg == b.Arg && slices.Equal(a.Rune, b.Rune)
				})
			if !same {
				t.Errorf("%s %q changed under lowering:\n%v\nbecame\n%v", dir.name, pat, orig, low)
			}
		}
	}
}

// lowerHasFoldCase reports whether any rune instruction of p carries
// syntax.FoldCase. Only rune instructions are read: in an InstEmptyWidth the
// same bit is EmptyBeginLine.
func lowerHasFoldCase(p *syntax.Prog) bool {
	for _, inst := range p.Inst {
		if (inst.Op == syntax.InstRune || inst.Op == syntax.InstRune1) &&
			syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
			return true
		}
	}
	return false
}

// TestLowerUTF8FoldCase checks case folding expanded in codepoint space. Each
// folded literal lowers to exactly the UTF-8 of its unicode.SimpleFold orbit:
// the listed spellings are checked against Go's regexp first, then the whole
// codespace against Inst.MatchRune on the ORIGINAL program, which folds by
// itself, so the oracle never sees the expansion; and the orbit is exactly
// the listed spellings. ß's orbit is {ß, ẞ}: simple folding maps one
// codepoint to one, and "ss" is full folding, which Go does not do. `(?i)a`
// is the literal whose orbit stays ASCII, where the flag must go all the same.
//
// Every battery class runs under `(?i)` too. Go's parser closes a class under
// folding itself, so those programs arrive with no flag; they are here for
// the whole-codespace check and the FoldCase walk over what lowering returns.
//
// Both directions, a reverse program fed each spelling back to front.
func TestLowerUTF8FoldCase(t *testing.T) {
	cases := []lowerFoldSpec{
		{`(?i)k`, []string{"k", "K", "K"}, nil},
		{`(?i)s`, []string{"s", "S", "ſ"}, nil},
		{`(?i)σ`, []string{"σ", "ς", "Σ"}, nil},
		{`(?i)ß`, []string{"ß", "ẞ"}, []string{"ss"}},
		{`(?i)a`, []string{"a", "A"}, nil},
	}
	for _, pat := range lowerBatteryClasses {
		cases = append(cases, lowerFoldSpec{pat: `(?i)` + pat})
	}
	for _, dir := range lowerDirs {
		for _, c := range cases {
			t.Run(dir.name+"/"+c.pat, func(t *testing.T) {
				lowerFoldCase(t, c, dir.reverse)
			})
		}
	}
}

// lowerFoldSpec is one TestLowerUTF8FoldCase case: a pattern and the
// spellings it must accept and reject. A nil accept marks a battery class,
// whose program carries no flag.
type lowerFoldSpec struct {
	pat            string
	accept, reject []string
}

func lowerFoldCase(t *testing.T, c lowerFoldSpec, reverse bool) {
	orig, low := lowerTestProgs(t, c.pat, reverse)
	literal := c.accept != nil
	if literal && !lowerHasFoldCase(orig) {
		t.Fatal("the original program carries no FoldCase; the case tests nothing")
	}
	if lowerHasFoldCase(low) {
		t.Fatal("FoldCase survived lowering")
	}
	d := newLowerDFA(t, low)
	goRE := regexp.MustCompile(`^(?:` + c.pat + `)$`)
	for _, in := range c.accept {
		if !goRE.MatchString(in) {
			t.Fatalf("test data: Go rejects %q", in)
		}
		if !d.accepts(lowerOrient([]byte(in), reverse)) {
			t.Errorf("lowered program rejects %q (% X)", in, in)
		}
	}
	for _, in := range c.reject {
		if goRE.MatchString(in) {
			t.Fatalf("test data: Go accepts %q", in)
		}
		if d.accepts(lowerOrient([]byte(in), reverse)) {
			t.Errorf("lowered program accepts %q (% X)", in, in)
		}
	}
	inClass := lowerRuneOracle(t, orig)
	var buf [utf8.UTFMax]byte
	members := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		want := inClass(r)
		n := utf8.EncodeRune(buf[:], r)
		if got := d.accepts(lowerOrient(buf[:n], reverse)); got != want {
			t.Fatalf("U+%04X (% X): lowered accepts = %v, original matches = %v",
				r, buf[:n], got, want)
		}
		if want {
			members++
		}
	}
	if got := d.count(0, 0, make(map[[2]int32]int)); got != members {
		t.Fatalf("the lowered program accepts %d byte strings but the original "+
			"matches %d codepoints", got, members)
	}
	if literal && members != len(c.accept) {
		t.Fatalf("the orbit has %d codepoints, not the %d listed", members, len(c.accept))
	}
}

// TestProgModeOnlyFromResolver holds the package to "a program's mode comes
// from its pattern's resolution and nowhere else", by reading the syntax tree
// of every non-test file:
//
//   - syntax.Compile is called once, in compileProg, so no program is built
//     without a mode;
//   - reverseRegexp is called only by resolvedTree.reversed (and itself), so
//     no reversed tree keeps the forward mode;
//   - resolvedPattern, resolvedTree, resolvedProg and setMode are
//     constructed, and a pm field is set or named in a literal, only in the
//     functions that make them — the two resolvers and their detector, the
//     methods that hand a mode on, compileProg and the union builder — and in
//     NeedsUnicodeSupport, the byte-only detector;
//   - the modes are named only there, in progMode's own methods, and in the
//     declaration.
//
// Calls are matched under whatever name a file imports regexp/syntax as, so
// an alias cannot hide one, and comments do not count.
func TestProgModeOnlyFromResolver(t *testing.T) {
	allowed := func(names ...string) map[string]bool {
		m := make(map[string]bool)
		for _, n := range names {
			m[n] = true
		}
		return m
	}
	reverseIn := allowed("resolvedTree.reversed", "reverseRegexp")
	constructIn := allowed("resolvePattern", "resolvedPattern.parse", "resolvedPattern.source",
		"resolvedPattern.tree", "resolvedTree.tree", "resolvedTree.reversed", "compileProg",
		"buildUnionProg", "NeedsUnicodeSupport", "detectUnicodeRune", "resolveSetMode", "setMode.member")
	modeNamedIn := allowed("progMode.check", "progMode.reversed", "resolvePattern", "compileProg",
		"NeedsUnicodeSupport", "detectUnicodeRune", "resolveSetMode", "resolvedPattern.unicode", "resolvedTree.unicode", "resolvedProg.unicode")
	carriers := allowed("resolvedPattern", "resolvedTree", "resolvedProg", "setMode")
	modes := allowed("progModeByte", "progModeUnicode", "progModeUnicodeReverse")

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var syntaxCompiles []string
	var bad []string
	fset := token.NewFileSet()
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, fn, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		syntaxName := ""
		for _, imp := range f.Imports {
			if imp.Path.Value == `"regexp/syntax"` {
				syntaxName = "syntax"
				if imp.Name != nil {
					syntaxName = imp.Name.Name
				}
			}
		}
		for _, decl := range f.Decls {
			encl := "(package level)"
			modeDecl := false
			switch d := decl.(type) {
			case *ast.FuncDecl:
				encl = d.Name.Name
				if d.Recv != nil && len(d.Recv.List) == 1 {
					rt := d.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						encl = id.Name + "." + encl
					}
				}
			case *ast.GenDecl:
				// The const block that declares the modes may name them.
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && d.Tok == token.CONST {
						for _, n := range vs.Names {
							if modes[n.Name] {
								modeDecl = true
							}
						}
					}
				}
			}
			report := func(n ast.Node, what string) {
				bad = append(bad, fmt.Sprintf("%s in %s: %s", fset.Position(n.Pos()), encl, what))
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.SelectorExpr:
						if id, ok := fun.X.(*ast.Ident); ok && syntaxName != "" && id.Name == syntaxName && fun.Sel.Name == "Compile" {
							syntaxCompiles = append(syntaxCompiles, fmt.Sprintf("%s in %s", fset.Position(x.Pos()), encl))
						}
					case *ast.Ident:
						if fun.Name == "reverseRegexp" && !reverseIn[encl] {
							report(x, "calls reverseRegexp; reverse a tree with resolvedTree.reversed")
						}
					}
				case *ast.CompositeLit:
					if id, ok := x.Type.(*ast.Ident); ok && carriers[id.Name] && !constructIn[encl] {
						report(x, "constructs a "+id.Name)
					}
					var elt ast.Expr
					switch tt := x.Type.(type) {
					case *ast.ArrayType:
						elt = tt.Elt
					case *ast.MapType:
						elt = tt.Value
					}
					if id, ok := elt.(*ast.Ident); ok && carriers[id.Name] && !constructIn[encl] {
						for _, e := range x.Elts {
							if kv, ok := e.(*ast.KeyValueExpr); ok {
								e = kv.Value
							}
							if c, ok := e.(*ast.CompositeLit); ok && c.Type == nil {
								report(c, "constructs a "+id.Name+" with its type elided")
							}
						}
					}
				case *ast.KeyValueExpr:
					if id, ok := x.Key.(*ast.Ident); ok && id.Name == "pm" && !constructIn[encl] {
						report(x, "names a mode field in a literal")
					}
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "pm" {
							report(x, "assigns a mode field")
						}
					}
				case *ast.Ident:
					if modes[x.Name] && !modeNamedIn[encl] && !modeDecl {
						report(x, "names "+x.Name)
					}
				}
				return true
			})
		}
	}
	if len(syntaxCompiles) != 1 || !strings.HasSuffix(syntaxCompiles[0], " in compileProg") {
		t.Errorf("want exactly one syntax.Compile call, in compileProg; found %d:\n%s",
			len(syntaxCompiles), strings.Join(syntaxCompiles, "\n"))
	}
	if len(bad) > 0 {
		t.Errorf("a mode decided outside resolvePattern:\n%s", strings.Join(bad, "\n"))
	}
}

// TestCompileProgModes checks the one way in. Every pattern resolves to byte
// mode until Unicode mode can be resolved. In byte mode compileProg hands
// back syntax.Compile's own program: the same instructions, and no allocation
// beyond what Simplify and syntax.Compile make themselves — so no copy. In
// the two unicode modes it hands back exactly what lowerUTF8 and
// lowerUTF8Reverse make of that program. Each program keeps its tree's mode,
// a reversed tree flips unicode to unicode-reverse and leaves byte alone, and
// a tree whose mode was never resolved panics.
func TestCompileProgModes(t *testing.T) {
	for _, pat := range []string{`abc`, `(a+|b)\bc$`, `é+`, `(?i)k\pL`, `[^a]`} {
		if got, err := resolvePattern(pat, nil, &CompileOptions{ForceByteMode: true}); err != nil || got.pm != progModeByte {
			t.Errorf("%q forced to byte mode resolved to (%d, %v)", pat, got.pm, err)
		}
		re := parseTestRe(t, pat)
		plain, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		bp, err := compileProg(byteTree(re))
		if err != nil {
			t.Fatal(err)
		}
		if bp.pm != progModeByte || bp.prog.String() != plain.String() {
			t.Errorf("%q: byte mode gave mode %d,\n%v\nwant\n%v", pat, bp.pm, bp.prog, plain)
		}
		want := testing.AllocsPerRun(20, func() { _, _ = syntax.Compile(re.Simplify()) })
		if got := testing.AllocsPerRun(20, func() { _, _ = compileProg(byteTree(re)) }); got != want {
			t.Errorf("%q: byte mode makes %v allocations, syntax.Compile alone %v: it copies", pat, got, want)
		}
		for _, c := range []struct {
			mode  progMode
			lower func(*syntax.Prog) *syntax.Prog
		}{
			{progModeUnicode, lowerUTF8},
			{progModeUnicodeReverse, lowerUTF8Reverse},
		} {
			mp, err := compileProg(resolvedTree{re: re, pm: c.mode})
			if err != nil {
				t.Fatal(err)
			}
			if mp.pm != c.mode {
				t.Errorf("%q: compiled in mode %d, the program says %d", pat, c.mode, mp.pm)
			}
			if want := c.lower(plain).String(); mp.prog.String() != want {
				t.Errorf("%q: mode %d gave\n%v\nwant\n%v", pat, c.mode, mp.prog, want)
			}
			checkLoweredShape(t, pat, mp.prog)
		}
	}
	for m, want := range map[progMode]progMode{
		progModeByte:           progModeByte,
		progModeUnicode:        progModeUnicodeReverse,
		progModeUnicodeReverse: progModeUnicode,
	} {
		tr := resolvedTree{re: parseTestRe(t, `ab`), pm: m}.reversed()
		if tr.pm != want {
			t.Errorf("reversing a mode-%d tree gave mode %d, want %d", m, tr.pm, want)
		}
		if tr.re.String() != "ba" {
			t.Errorf("reversing `ab` gave %q", tr.re.String())
		}
	}
	for _, bad := range []progMode{0, progModeUnicodeReverse + 1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("compileProg in progMode %d did not panic", bad)
				}
			}()
			_, _ = compileProg(resolvedTree{re: parseTestRe(t, `a`), pm: bad})
		}()
	}
}

// TestBuildUnionProgKeepsTheMembersMode: a union is built in its members'
// mode, and programs of different modes cannot be merged into one automaton —
// a lowered and an unlowered member would read the same byte differently.
func TestBuildUnionProgKeepsTheMembersMode(t *testing.T) {
	members := func(modes ...progMode) []resolvedProg {
		var out []resolvedProg
		for i, m := range modes {
			mp, err := compileProg(resolvedTree{re: parseTestRe(t, fmt.Sprintf("é%d", i)), pm: m})
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, mp)
		}
		return out
	}
	for _, m := range []progMode{progModeByte, progModeUnicode} {
		u, _ := buildUnionProg(members(m, m), 64)
		if u.pm != m {
			t.Errorf("a union of mode-%d members has mode %d", m, u.pm)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("merging a byte-mode and a unicode-mode program did not panic")
		}
	}()
	buildUnionProg(members(progModeByte, progModeUnicode), 64)
}

// TestResolvePatternModeFields is CompileOptions' mode truth table, row by
// row: with no field set the pattern resolves (byte for ASCII, Unicode for
// `é`); ByteMode is byte mode with
// 0x80-0xFF as bytes; ForceByteMode is byte mode WITHOUT detection, so `é`
// meets the byte gate's own message; Unicode is Unicode mode, not gated; and
// Unicode with either byte field is a programming error.
func TestResolvePatternModeFields(t *testing.T) {
	type outcome int
	const (
		isByte outcome = iota
		isUnicode
		panics
	)
	for _, c := range []struct {
		name string
		opts CompileOptions
		pat  string
		want outcome
	}{
		{"none, ASCII", CompileOptions{}, `a.c`, isByte},
		{"none, é", CompileOptions{}, `é`, isUnicode},
		{"ByteMode", CompileOptions{ByteMode: true}, `é`, isByte},
		{"ForceByteMode", CompileOptions{ForceByteMode: true}, `é`, isByte},
		{"ForceByteMode+ByteMode", CompileOptions{ForceByteMode: true, ByteMode: true}, `é`, isByte},
		{"Unicode", CompileOptions{Unicode: true}, `a.c`, isUnicode},
		{"Unicode+ForceByteMode", CompileOptions{Unicode: true, ForceByteMode: true}, `a`, panics},
		{"Unicode+ByteMode", CompileOptions{Unicode: true, ByteMode: true}, `a`, panics},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); (r != nil) != (c.want == panics) {
					t.Errorf("panic = %v, want a panic: %v", r, c.want == panics)
				}
			}()
			rp, err := resolvePattern(c.pat, nil, &c.opts)
			switch c.want {
			case isByte, isUnicode:
				if err != nil || rp.unicode() != (c.want == isUnicode) {
					t.Errorf("got (%s, %v), want unicode = %v", rp.modeName(), err, c.want == isUnicode)
				}
			}
		})
	}
	// ForceByteMode leaves the byte gate to refuse `é` with its own message,
	// never the resolver's.
	e := config.RegexEntry{Pattern: `é`, FindFunc: "find"}
	_, _, err := Compile([]config.RegexEntry{e}, 65536, true, CompileOptions{ForceByteMode: true})
	if err == nil || strings.Contains(err.Error(), "Unicode mode") || !strings.Contains(err.Error(), "byte_mode") {
		t.Errorf("ForceByteMode: want the byte gate's message, got %v", err)
	}
}

// TestResolvePatternDetection: a pattern with no key and no byte field picks
// its own mode exactly where the byte gate would refuse it — a written rune
// above U+007F or a Unicode class asks for Unicode mode, while `.`, negated
// classes, the open-ended
// `[a-\x{10ffff}]` and the characters Go's parser adds to `(?i)` over ASCII do
// not. A written ſ asks for it even inside `(?i)`. `[\x80-\xff]` asks for
// Unicode without byte_mode and means bytes with it. The `unicode:` key
// decides over the text, and `unicode: true` with byte_mode contradicts.
func TestResolvePatternDetection(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		pat     string
		key     *bool
		byteKey bool
		unicode bool   // asks for Unicode mode
		errText string // a non-gate error, when set
	}{
		{`[a-zé]`, nil, false, true, ""},
		{`\pL`, nil, false, true, ""},
		{`(?i:[a-z])`, nil, false, false, ""},
		{`(?i)k`, nil, false, false, ""},
		{`[sſ]`, nil, false, true, ""},
		{`(?i)[sſ]`, nil, false, true, ""},
		{`[a-\x{10ffff}]`, nil, false, false, ""},
		{`[^a]`, nil, false, false, ""},
		{`a.c`, nil, false, false, ""},
		{`[\x80-\xff]`, nil, false, true, ""},
		{`[\x80-\xff]`, nil, true, false, ""},
		{`a.c`, &yes, false, true, ""},
		{`\pL`, &no, false, false, ""},
		{`a`, &yes, true, false, "contradict"},
		{`(`, nil, false, false, ""},
	} {
		rp, err := resolvePattern(c.pat, c.key, &CompileOptions{ByteMode: c.byteKey})
		switch {
		case c.errText != "":
			if err == nil || !strings.Contains(err.Error(), c.errText) {
				t.Errorf("%q key=%v byte_mode=%v: err = %v, want %q", c.pat, c.key, c.byteKey, err, c.errText)
			}
		default:
			if err != nil || rp.unicode() != c.unicode {
				t.Errorf("%q key=%v byte_mode=%v: got (%v, %v), want unicode = %v", c.pat, c.key, c.byteKey, rp.pm, err, c.unicode)
			}
		}
	}
}

// TestResolveSetMode is the set rule: all-ASCII members with no key run in
// byte mode, as with `unicode: false`; an explicitly-byte member beside one
// asking for Unicode, a set-level `unicode: true` with a byte member, and a
// set-level `unicode: false` with a member asking for Unicode are errors
// naming the members; and a member asking for Unicode, or the set's own key,
// puts the set in Unicode mode.
func TestResolveSetMode(t *testing.T) {
	yes, no := true, false
	regexps := []config.RegexEntry{
		{Name: "ascii", Pattern: `foo\d+`},
		{Name: "letters", Pattern: `\pL+`},
		{Name: "raw", Pattern: `[\x80-\xff]`, ByteMode: true},
		{Name: "unikey", Pattern: `bar`, Unicode: &yes},
		{Name: "bytekey", Pattern: `baz`, Unicode: &no},
		{Pattern: `\p{Greek}`},
	}
	cfg := config.BuildConfig{Regexps: regexps}
	for _, c := range []struct {
		members []int
		key     *bool
		want    string // "" = byte mode, "unicode" = Unicode mode, else a substring of the error
	}{
		{[]int{0}, nil, ""},
		{[]int{0, 2}, nil, ""},
		{[]int{0, 4}, &no, ""},
		{[]int{0}, &yes, "unicode"},
		{[]int{0, 1}, nil, "unicode"},
		{[]int{0, 3}, nil, "unicode"},
		{[]int{1, 2}, nil, `member "raw" is byte mode`},
		{[]int{3, 4}, nil, `member "bytekey" is byte mode`},
		{[]int{2}, &yes, `unicode: true, but member "raw"`},
		{[]int{1}, &no, `unicode: false, but member "letters"`},
		{[]int{0, 5}, nil, "unicode"},
	} {
		sc := config.SetConfig{Name: "s", Unicode: c.key}
		m, err := resolveSetMode(sc, cfg, c.members)
		switch {
		case c.want == "" || c.want == "unicode":
			if err != nil || m.member("x").unicode() != (c.want == "unicode") {
				t.Errorf("members %v key %v: got (%v, %v), want %q mode", c.members, c.key, m.pm, err, c.want)
			}
		case err == nil || !strings.Contains(err.Error(), c.want):
			t.Errorf("members %v key %v: err = %v, want %q", c.members, c.key, err, c.want)
		}
	}
}

// TestUnicodeSets compiles sets in Unicode mode through every body that keeps
// the start rule — the per-position walk of `find` and of the scan pair, the
// answer cache's sweep, a split member's search in the merge and its program
// sweep — standalone and embedded, and pins which members need it and the
// Unicode default of max_fallback_states. Their answers are checked against
// Go in tools/fuzz and tools/re2test.
func TestUnicodeSets(t *testing.T) {
	yes := true
	cfgFor := func(pats []string, sc config.SetConfig) config.BuildConfig {
		entries := make([]config.RegexEntry, len(pats))
		for i, p := range pats {
			entries[i] = config.RegexEntry{Name: fmt.Sprintf("p%d", i), Pattern: p}
		}
		sc.Name, sc.Unicode, sc.Patterns = "s", &yes, config.PatternSelector{All: true}
		return config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{sc}}
	}
	everything := config.SetConfig{Find: "f", ScanAny: "sa", ScanAll: "sl", MatchAny: "ma", MatchAll: "ml"}
	for _, c := range []struct {
		name  string
		pats  []string
		sc    config.SetConfig
		cache bool // the answer cache is offered
		sweep bool // a split member has a program sweep
	}{
		{"walk", []string{`é+`, `x*`, `\B`}, everything, false, false},
		{"walk-batch", []string{`é+`, `x*`, `\B`}, config.SetConfig{Find: "f", Hints: []string{"batch-find"}}, false, false},
		{"cache", []string{`[a-zé]+`, `a*`}, config.SetConfig{Find: "f", Overlapping: true}, true, false},
		{"cache-batch", []string{`[a-zé]+`, `a*`}, config.SetConfig{Find: "f", Overlapping: true, Hints: []string{"batch-find"}}, true, false},
		{"split", []string{`foo\w+`, `(?:a[a-z]*?z)?`}, config.SetConfig{Find: "f"}, false, false},
		{"split-sweep", []string{`foo\w+`, `(?:a[a-z]*?z)?`}, config.SetConfig{Find: "f", Overlapping: true}, true, true},
		{"split-bt", []string{`foo\w+`, `\B(?:a[a-z]*?z)?`}, config.SetConfig{Find: "f", Overlapping: true}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := cfgFor(c.pats, c.sc)
			sh, err := SetOverlapCacheShape(cfg.Sets[0], cfg)
			if err != nil {
				t.Fatal(err)
			}
			if sh.Offered() != c.cache || (sh.SweepCells > 0) != c.sweep {
				t.Errorf("cache offered %v, program sweep %v; want %v, %v (%+v)", sh.Offered(), sh.SweepCells > 0, c.cache, c.sweep, sh)
			}
			for _, out := range []string{"", "merged.wasm"} {
				cfg.Output = out
				w, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
				if err != nil {
					t.Fatalf("output %q: %v", out, err)
				}
				if len(diags) != 1 || diags[0].Mode != "unicode" {
					t.Fatalf("output %q: diagnostics %+v, want one Unicode-mode set", out, diags)
				}
				if got := diags[0].CacheBytesPerByte; got != sh.bytesPerByte() || (got > 0) != c.cache {
					t.Errorf("output %q: cache bytes per input byte %d, shape says %d, cache offered %v", out, got, sh.bytesPerByte(), c.cache)
				}
				validateWASM(t, w)
			}
		})
	}

	// Which members need the rule, and for which bodies.
	for _, c := range []struct {
		pat        string
		find, scan bool
	}{
		{`é+`, false, false}, // cannot match empty
		{`x*`, true, false},  // empty anywhere: `find` enumerates it inside a character
		{`\B`, true, true},   // `\B` holds inside one: every capability
		{`a?\B`, true, true},
		{`(?:\b|$)`, false, false}, // fixed: never inside a character
		{`(?m:^)x*`, false, false},
	} {
		find, scan := setStartNeeds(unicodePat(c.pat))
		if find != c.find || scan != c.scan {
			t.Errorf("setStartNeeds(%q) = %v, %v; want %v, %v", c.pat, find, scan, c.find, c.scan)
		}
		if find, scan := setStartNeeds(bytePat(c.pat)); find || scan {
			t.Errorf("setStartNeeds(%q) in byte mode = %v, %v; want neither", c.pat, find, scan)
		}
	}

	// max_fallback_states: 16,384 for a Unicode set unless the key says
	// otherwise, and byte mode's 1,024 unchanged. `\pL{4}\pN` needs 1,250.
	btBuckets := func(cfg config.BuildConfig) int {
		_, _, diags, err := CompileFileOpts(cfg, "", CompileSetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, bkt := range diags[0].Buckets {
			if bkt.Type == "bt-fallback" {
				n++
			}
		}
		return n
	}
	cfg := cfgFor([]string{`\pL{4}\pN`, `x`}, config.SetConfig{ScanAll: "sl"})
	if n := btBuckets(cfg); n != 0 {
		t.Errorf("Unicode set, no key: %d Backtracking buckets, want 0", n)
	}
	cfg.MaxFallbackStates = 1024
	if n := btBuckets(cfg); n != 1 {
		t.Errorf("Unicode set, max_fallback_states 1024: %d Backtracking buckets, want 1", n)
	}
	if got := resolveMaxFallbackStates(0, []*PatternInfo{{rp: bytePat(`x`)}}); got != 0 {
		t.Errorf("byte mode, no key: %d, want 0 (the 1,024 default)", got)
	}
}
