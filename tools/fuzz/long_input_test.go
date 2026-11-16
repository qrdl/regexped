package fuzz

// FuzzLongInput: a differential fuzzer whose patterns and inputs are BUILT, not
// mutated. The byte-mutating targets (FuzzCorrectness and friends) never found
// the bugs that live in the SIMD skips — two looping states that can end a
// match, a \b / \B tail after a Teddy tier, a \B inside a prefer-match run, the
// last iteration of a captured counted repeat — because those need a realistic
// pattern shape AND an input that keeps matching it for 16+ bytes, which a
// mutated byte string practically never is. Here a small grammar draws the
// pattern (negated classes, \w, \s, \b, \B, line anchors, counted and lazy
// repeats, groups, alternation) and most inputs are WITNESSES: random walks of
// the pattern itself, an unbounded repeat taking 14-43 iterations and often the
// same one each time, mixed with runs over the pattern's own bytes. With only
// runs over the alphabet a prototype found nothing in 512 patterns; with
// witnesses it found ~2.7 failing patterns a minute on a tree with those bugs.
//
// Go's fuzz engine supplies only the generator's seed and the mode, so a
// failure replays from its seed, and every routine `go test` re-checks the seeds
// below. Each pattern is checked under all three hints, in byte mode or (uni)
// Unicode mode: the find drive as a stub runs it, finds from random positions,
// the anchored match, and for a pattern with captures the groups drive and
// groups from random positions — against Go throughout.
//
//	make -C tools/fuzz fuzz-long-input                 # 5 minutes
//	make -C tools/fuzz fuzz-long-input FUZZTIME=8h

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/searchblock"
)

// longGen draws patterns and inputs from one seeded source.
type longGen struct {
	r   *rand.Rand
	uni bool
}

var (
	longLits    = []string{"a", "b", "c", "x", "z", " ", `\n`, "@", "=", ",", `\.`, "k", "ey", "ab"}
	longClasses = []string{`[a-c]`, `[^ ]`, `[^\n]`, `[^,]`, `\w`, `\d`, `\s`, `.`, `[a-z]`, `[^ab]`,
		`[^a]`, `[ab]`, `[^@]`, `\W`, `[a-z0-9]`, `[^ \n]`}
	longAsserts = []string{`\b`, `\B`, `^`, `$`, `(?m:^)`, `(?m:$)`}

	// The Unicode leg's additions: multi-byte literals and classes, and the
	// non-ASCII members of ASCII letters' fold orbits as (?i) literals.
	longUniLits    = []string{"é", "ж", "日", "ß", "α", `(?i:ſ)`, "(?i:\u212A)", `(?i:k)`, `(?i:s)`, `(?i:ж)`}
	longUniClasses = []string{`[а-я]`, `\pL`, `[^ж]`, `[α-ω]`, `\p{Cyrillic}`, `[é-ü]`, `[^a-zа-я]`}
	longUniAlpha   = []rune("éжЖ日ßſ\u212AkKsSα")
)

func (g longGen) pick(v []string) string { return v[g.r.Intn(len(v))] }

func (g longGen) atom(d int) string {
	n := g.r.Intn(100)
	switch {
	case n < 30:
		if g.uni && g.r.Intn(3) == 0 {
			return g.pick(longUniLits)
		}
		return g.pick(longLits)
	case n < 65:
		if g.uni && g.r.Intn(3) == 0 {
			return g.pick(longUniClasses)
		}
		return g.pick(longClasses)
	case n < 72:
		return g.pick(longAsserts)
	case d > 0 && n < 86:
		capture := ""
		if g.r.Intn(2) == 0 {
			capture = "?:"
		}
		return "(" + capture + g.alt(d-1) + ")"
	default:
		return g.pick(longClasses)
	}
}

func (g longGen) quant(s string) string {
	for _, a := range longAsserts {
		if s == a {
			return s
		}
	}
	n := g.r.Intn(100)
	q := ""
	switch {
	case n < 45:
		return s
	case n < 60:
		q = "*"
	case n < 75:
		q = "+"
	case n < 83:
		q = "?"
	default:
		a := g.r.Intn(4)
		b := a + g.r.Intn(5)
		if g.r.Intn(4) == 0 {
			q = fmt.Sprintf("{%d,}", a)
		} else {
			q = fmt.Sprintf("{%d,%d}", a, b)
		}
	}
	if g.r.Intn(6) == 0 {
		q += "?"
	}
	return s + q
}

func (g longGen) seq(d int) string {
	var b strings.Builder
	for n := 1 + g.r.Intn(4); n > 0; n-- {
		b.WriteString(g.quant(g.atom(d)))
	}
	return b.String()
}

func (g longGen) alt(d int) string {
	s := g.seq(d)
	for g.r.Intn(4) == 0 {
		s += "|" + g.seq(d)
	}
	return s
}

// alphabet is the characters that can matter for pat plus boundary ones.
func (g longGen) alphabet(re *syntax.Regexp) []rune {
	set := map[rune]bool{}
	var walk func(*syntax.Regexp)
	walk = func(re *syntax.Regexp) {
		if re.Op == syntax.OpLiteral {
			for _, r := range re.Rune {
				set[r] = true
			}
		}
		for _, s := range re.Sub {
			walk(s)
		}
	}
	walk(re)
	for _, c := range " \n@=,.aAbz09_-" {
		set[c] = true
	}
	if g.uni {
		for _, c := range longUniAlpha {
			set[c] = true
		}
	}
	var out []rune
	for c := range set {
		if !g.uni && c > 0x7F {
			continue
		}
		out = append(out, c)
	}
	// Map order is random: sort so a seed replays the same input.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// classRunes is what a witness may write for a class: the alphabet's members
// first, else the low end of each range.
func (g longGen) classRunes(re *syntax.Regexp, alpha []rune) []rune {
	in := func(c rune) bool {
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if c >= re.Rune[i] && c <= re.Rune[i+1] {
				return true
			}
		}
		return false
	}
	var pref []rune
	for _, c := range alpha {
		if in(c) {
			pref = append(pref, c)
		}
	}
	if len(pref) > 0 && g.r.Intn(3) != 0 {
		return pref
	}
	var lows []rune
	for i := 0; i+1 < len(re.Rune); i += 2 {
		lo := re.Rune[i]
		if (lo < 0x7F || g.uni) && utf8.ValidRune(lo) && lo != 0 {
			lows = append(lows, lo)
		}
	}
	if len(lows) == 0 {
		return pref
	}
	return lows
}

// witness writes a string re (mostly) matches, with long runs so the SIMD
// skips engage.
func (g longGen) witness(re *syntax.Regexp, b *strings.Builder, alpha []rune) {
	if b.Len() > 400 {
		return
	}
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && g.r.Intn(2) == 0 {
				if f := unicode.SimpleFold(r); g.uni || f < 0x80 {
					r = f
				}
			}
			if g.uni || r < 0x80 {
				b.WriteRune(r)
			}
		}
	case syntax.OpCharClass:
		if c := g.classRunes(re, alpha); len(c) > 0 {
			b.WriteRune(c[g.r.Intn(len(c))])
		}
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		b.WriteRune(alpha[g.r.Intn(len(alpha))])
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		lo, hi := re.Min, re.Max
		switch re.Op {
		case syntax.OpStar:
			lo, hi = 0, -1
		case syntax.OpPlus:
			lo, hi = 1, -1
		case syntax.OpQuest:
			lo, hi = 0, 1
		}
		n := lo
		switch {
		case hi < 0 && g.r.Intn(3) == 0:
			n = lo + g.r.Intn(3)
		case hi < 0:
			n = lo + 14 + g.r.Intn(30)
		case hi > lo:
			n = lo + g.r.Intn(hi-lo+1)
		}
		if g.r.Intn(2) == 0 { // the same iteration n times: a run
			var one strings.Builder
			g.witness(re.Sub[0], &one, alpha)
			for i := 0; i < n; i++ {
				b.WriteString(one.String())
			}
		} else {
			for i := 0; i < n; i++ {
				g.witness(re.Sub[0], b, alpha)
			}
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			g.witness(s, b, alpha)
		}
	case syntax.OpAlternate:
		g.witness(re.Sub[g.r.Intn(len(re.Sub))], b, alpha)
	case syntax.OpCapture:
		g.witness(re.Sub[0], b, alpha)
	}
}

// input is 17-250 bytes: witnesses mixed with runs (witness), or runs over
// the alphabet alone.
func (g longGen) input(re *syntax.Regexp, alpha []rune, witness bool) string {
	n := 17 + g.r.Intn(184)
	var b strings.Builder
	for b.Len() < n {
		if witness && g.r.Intn(2) == 0 {
			g.witness(re, &b, alpha)
			continue
		}
		c := alpha[g.r.Intn(len(alpha))]
		k := 1
		switch g.r.Intn(4) {
		case 0:
			k = 1 + g.r.Intn(40)
		case 1:
			k = 1 + g.r.Intn(4)
		}
		for ; k > 0; k-- {
			b.WriteRune(c)
		}
	}
	s := b.String()
	for len(s) > 250 { // cut at a character boundary
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// longInstance is one instantiated module, a fresh search block per drive.
type longInstance struct {
	t     *testing.T
	store *wasmtime.Store
	inst  *wasmtime.Instance
	mem   *wasmtime.Memory
	sr    *searchRegion
	input string
}

// newLongInstance instantiates mod, built once per compile: a 1.4 MB Unicode
// module costs about a second to build, which per input put one fuzz call past
// the worker's 10 s deadline.
func newLongInstance(t *testing.T, mod *wasmtime.Module, sizes []searchblock.Size, input string) (*longInstance, func()) {
	t.Helper()
	engine, _ := sharedEngine()
	store := wasmtime.NewStore(engine)
	store.SetEpochDeadline(1)
	release := func() { store.Close() }
	inst, err := wasmtime.NewInstance(store, mod, []wasmtime.AsExtern{})
	if err != nil {
		release()
		t.Fatalf("instantiate: %v", err)
	}
	memExp := inst.GetExport(store, "memory")
	if memExp == nil || memExp.Memory() == nil {
		release()
		t.Fatal("module has no exported memory")
	}
	mem := memExp.Memory()
	copy(mem.UnsafeData(store)[pathsInputBase:], input)
	sr, err := newSearchRegion(store, inst, mem, len(input), sizes, searchblock.Fresh)
	if err != nil {
		release()
		t.Fatalf("search region: %v", err)
	}
	if sr == nil { // no block: the Backtracking scratch above everything the module holds
		if err := setScratchBase(store, inst, int32(mem.DataSize(store))); err != nil {
			release()
			t.Fatalf("scratch base: %v", err)
		}
	}
	return &longInstance{t: t, store: store, inst: inst, mem: mem, sr: sr, input: input}, release
}

// longCompile compiles pat's export through the package's compile cache, so
// a fuzz run's Unicode inputs are bounded by its deadlines (an over-long
// compile is errCompileTooSlow, and the input is skipped).
func longCompile(e config.PatternEntry, export, pat string, opts compile.CompileOptions) ([]byte, []searchblock.Size, error) {
	key := fmt.Sprintf("long\x00%d\x00%v\x00%s\x00%s", opts.LikelyMode, opts.Unicode, export, pat)
	return cachedCompileSized(key, compileJob{Kind: jobSized, Entries: []config.PatternEntry{e}, Base: pathsTableBase,
		Opts: toJobOpts(opts), Export: export})
}

// longModule is w built once for a whole leg's inputs — the module the
// compile cache already warmed when there is one; done releases a module
// built here.
func longModule(t *testing.T, w []byte) (*wasmtime.Module, func()) {
	t.Helper()
	if mod := warmedModule(w); mod != nil {
		return mod, func() {}
	}
	engine, _ := sharedEngine()
	mod, err := wasmtime.NewModule(engine, w)
	if err != nil {
		t.Fatalf("module: %v", err)
	}
	return mod, mod.Close
}

// longBigModule is the module size past which a pattern is checked in neutral
// only: such a pattern's compiles run a second or two each, and six of them
// (three hints, find and groups) were most of a fuzz call's 10 s.
const longBigModule = 256 << 10

func (l *longInstance) begin() {
	if err := l.sr.begin(l.store); err != nil {
		l.t.Fatalf("search block: %v", err)
	}
}

// call runs fn with args, mapping a watchdog interrupt to hang.
func (l *longInstance) call(fn string, args ...interface{}) (interface{}, bool) {
	f := l.inst.GetFunc(l.store, fn)
	if f == nil {
		l.t.Fatalf("module has no %s export", fn)
	}
	l.sr.before(l.store)
	_, wd := sharedEngine()
	wd.Arm(l.store)
	r, err := f.Call(l.store, args...)
	wd.Disarm()
	if err != nil {
		if isTimeout(err) {
			return nil, true
		}
		l.t.Fatalf("%s: %v", fn, err)
	}
	return r, false
}

// find is one find call from from: the span, found, and a state for a hang or
// a Backtracking overflow.
func (l *longInstance) find(from int) ([]int, findState) {
	r, hang := l.call("find", pathsInputBase, int32(len(l.input)), int32(from))
	if hang {
		return nil, findHang
	}
	switch v := r.(int64); v {
	case abi.BTStackOverflow:
		return nil, findOverflow
	case abi.NoMatch:
		return nil, findNone
	default:
		if err := l.sr.after(l.store); err != nil {
			l.t.Fatalf("search block: %v", err)
		}
		return []int{int(uint32(v >> 32)), int(uint32(v))}, findMatch
	}
}

// groups is one groups call from from, the slots pre-filled with -1 as every
// stub does.
func (l *longInstance) groups(from, slots int) ([]int, findState) {
	buf := l.mem.UnsafeData(l.store)
	for i := 0; i < slots; i++ {
		binary.LittleEndian.PutUint32(buf[int(pathsOutBase)+4*i:], 0xFFFFFFFF)
	}
	r, hang := l.call("groups", pathsInputBase, int32(len(l.input)), pathsOutBase, int32(from))
	if hang {
		return nil, findHang
	}
	v := r.(int32)
	if int64(v) == abi.BTStackOverflow {
		return nil, findOverflow
	}
	if v < 0 {
		return nil, findNone
	}
	if err := l.sr.after(l.store); err != nil {
		l.t.Fatalf("search block: %v", err)
	}
	buf = l.mem.UnsafeData(l.store)
	out := make([]int, slots)
	for i := range out {
		out[i] = int(int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+4*i:])))
	}
	return out, findMatch
}

// longDrive runs next the way a stub iterates: from the end of each match, one
// past an empty one, an empty match beginning where the previous one ended
// not reported. overflow reports a Backtracking -2, after which the drive's
// answer is unknown.
func longDrive(n int, next func(int) ([]int, findState)) (got [][]int, hang, overflow bool) {
	prevEnd := -1
	for pos := 0; pos <= n; {
		m, st := next(pos)
		switch st {
		case findHang:
			return got, true, false
		case findOverflow:
			return got, false, true
		case findNone:
			return got, false, false
		}
		if m[0] != m[1] || m[0] != prevEnd {
			got = append(got, m)
			prevEnd = m[1]
		}
		if m[1] > m[0] {
			pos = m[1]
		} else {
			pos = m[0] + 1
		}
	}
	return got, false, false
}

func FuzzLongInput(f *testing.F) {
	for _, seed := range []int64{1, 11, 21, 33, 44, 55} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	// Byte-mode seeds that failed before the double SIMD skip, the Teddy
	// tiers' boundary accepts, the prefer-match \B skip and the TDFA's
	// priority order were fixed: `[ab]+\B`, `c\W.*\B`, `[^,]{0,3}[a-c]+[^ab]*|[^@]*`
	// and three more, each now a standing regression.
	for _, seed := range []int64{1109, 1253, 1859, 1917, 1949, 2098} {
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, seed int64, uni bool) {
		// The run's mode, so a fuzz run's Unicode inputs get the package's
		// compile deadlines (cachedCompileSized, beginFuzzInput): a lowered
		// class can make one compile run for seconds, and an input past the
		// worker's 10 s is reported as a hang.
		defer func(v bool) { *unicodeMode = v }(*unicodeMode)
		*unicodeMode = uni
		beginFuzzInput()
		g := longGen{r: rand.New(rand.NewSource(seed)), uni: uni}
		pat := g.alt(2)
		if len(pat) > 60 {
			t.Skip()
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Skip()
		}
		parsed, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Skip()
		}
		if prog, err := syntax.Compile(parsed.Simplify()); err != nil || len(prog.Inst) > maxNFAInsts() {
			t.Skip()
		}
		alpha := g.alphabet(parsed)
		ins := make([]string, 6)
		for i := range ins {
			ins[i] = g.input(parsed, alpha, i%3 != 0)
		}
		whole := regexp.MustCompile(`\A(?:` + pat + `)\z`)
		ncap := re.NumSubexp() + 1
		modes := []compile.LikelyMode{compile.LikelyNeutral, compile.LikelyMatch, compile.LikelyNoMatch}
		for i := 0; i < len(modes); i++ {
			lm := modes[i]
			opts := compile.CompileOptions{LikelyMode: lm, Unicode: uni, ForceByteMode: !uni}
			fail := func(kind, in string, from int, got, want interface{}) {
				t.Errorf("%s, mode %v, unicode=%v, seed %d\n  pattern %q\n  input   %q\n  from    %d\n  got     %v\n  want    %v",
					kind, lm, uni, seed, pat, in, from, got, want)
			}
			entry := config.PatternEntry{Regexp: pat, FindFunc: "find", MatchFunc: "match"}
			w, sizes, err := longCompile(entry, "find", pat, opts)
			if err != nil {
				t.Skip()
			}
			if len(w) > longBigModule {
				modes = modes[:1]
			}
			mod, done := longModule(t, w)
			for _, in := range ins {
				longCheckFind(t, mod, sizes, re, whole, pat, in, g, fail)
			}
			done()
			if ncap == 1 {
				continue
			}
			entry = config.PatternEntry{Regexp: pat, GroupsFunc: "groups"}
			w, sizes, err = longCompile(entry, "groups", pat, opts)
			if err != nil {
				continue // e.g. no group can take part in a match
			}
			mod, done = longModule(t, w)
			for _, in := range ins {
				longCheckGroups(t, mod, sizes, re, pat, in, ncap, g, fail)
			}
			done()
		}
	})
}

// longFromProbe is Go's first match of pat at or after byte from of in (from
// on a character boundary): the WHOLE input, so the bytes before from are the
// match's left context.
func longFromProbe(pat, in string, from int) []int {
	k := utf8.RuneCountInString(in[:from])
	m := regexp.MustCompile(fmt.Sprintf(`\A(?s:.{%d}.*?)(%s)`, k, pat)).FindStringSubmatchIndex(in)
	if m == nil {
		return nil
	}
	return m[2:]
}

// longFrom picks a character boundary of in.
func longFrom(g longGen, in string) int {
	from := g.r.Intn(len(in) + 1)
	for from < len(in) && !utf8.RuneStart(in[from]) {
		from++
	}
	return from
}

func longCheckFind(t *testing.T, mod *wasmtime.Module, sizes []searchblock.Size, re, whole *regexp.Regexp, pat, in string, g longGen,
	fail func(string, string, int, interface{}, interface{})) {
	l, release := newLongInstance(t, mod, sizes, in)
	defer release()
	l.begin()
	got, hang, overflow := longDrive(len(in), l.find)
	if hang {
		fail("find drive: watchdog", in, 0, got, nil)
	} else if !overflow {
		var want [][]int
		for _, m := range re.FindAllStringIndex(in, -1) {
			want = append(want, m)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			fail("find drive", in, 0, got, want)
		}
	}
	for k := 0; k < 6; k++ {
		from := longFrom(g, in)
		l.begin()
		m, st := l.find(from)
		if st == findHang {
			fail("find from: watchdog", in, from, nil, nil)
			continue
		}
		if st == findOverflow {
			continue
		}
		want := longFromProbe(pat, in, from)
		if want != nil {
			want = want[:2]
		}
		if fmt.Sprint(m) != fmt.Sprint(want) {
			fail("find from", in, from, m, want)
		}
	}
	r, hang := l.call("match", pathsInputBase, int32(len(in)))
	if hang {
		fail("match: watchdog", in, 0, nil, nil)
		return
	}
	got32, want := r.(int32), int32(-1)
	if whole.MatchString(in) {
		want = int32(len(in))
	}
	if int64(got32) != abi.BTStackOverflow && got32 != want {
		fail("match", in, 0, got32, want)
	}
}

func longCheckGroups(t *testing.T, mod *wasmtime.Module, sizes []searchblock.Size, re *regexp.Regexp, pat, in string, ncap int, g longGen,
	fail func(string, string, int, interface{}, interface{})) {
	l, release := newLongInstance(t, mod, sizes, in)
	defer release()
	l.begin()
	got, hang, overflow := longDrive(len(in), func(p int) ([]int, findState) { return l.groups(p, 2*ncap) })
	if hang {
		fail("groups drive: watchdog", in, 0, got, nil)
	} else if !overflow {
		want := re.FindAllStringSubmatchIndex(in, -1)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			fail("groups drive", in, 0, got, want)
		}
	}
	for k := 0; k < 6; k++ {
		from := longFrom(g, in)
		l.begin()
		m, st := l.groups(from, 2*ncap)
		if st == findHang {
			fail("groups from: watchdog", in, from, nil, nil)
			continue
		}
		if st == findOverflow {
			continue
		}
		if want := longFromProbe(pat, in, from); fmt.Sprint(m) != fmt.Sprint(want) {
			fail("groups from", in, from, m, want)
		}
	}
}
