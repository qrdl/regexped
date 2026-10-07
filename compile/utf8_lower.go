package compile

import (
	"cmp"
	"fmt"
	"regexp/syntax"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/qrdl/regexped/config"
)

// UTF-8 lowering: a program over codepoints becomes a program over bytes.
//
// Every engine here reads an InstRune's ranges as BYTE values — a range is
// enumerated as byte keys and clamped at 0xFF (nfaBuildInputMap, the
// Backtracking range checks) — so a class reaching past 0x7F cannot be handed
// to any of them as it stands. lowerUTF8 rewrites each rune-consuming
// instruction into the alternation of the UTF-8 byte sequences that encode
// its codepoints, and leaves everything else alone. The engines then run the
// program without learning what a codepoint is: nothing downstream of the
// Prog changes.
//
// # Splitting a range into sequences
//
// A contiguous codepoint range does not in general encode to a product of
// byte ranges. U+0080-U+07FF does, [C2-DF][80-BF]; U+0100-U+0800 does not,
// because its encodings change length at U+0800 and, below that, its second
// byte runs 80-BF under every lead byte except the first. appendUTF8Sequences
// splits the range until every piece does: first where the encoded length
// changes (after U+007F, U+07FF, U+FFFF), then wherever the low 6·i bits of
// the two ends are not all-zeros and all-ones respectively, i.e. wherever a
// trailing byte would not span its whole range while a byte before it varies.
// This is regex-syntax's Utf8Sequences, which is RE2's UTF8RangeSplit.
// Surrogates U+D800-U+DFFF are cut out before anything else: they have no
// valid encoding, and utf8.EncodeRune would silently write U+FFFD for them.
//
// # Suffix sharing
//
// A lowered byte range is keyed by (range, next node), so sequences that end
// alike share their tails and the class becomes an in-tree converging on the
// instruction's Out: `[80-BF]`→Out is one instruction however many sequences
// end in it. Leading bytes are not merged, so the alternation keeps one arm,
// one Alt and one lead instruction per sequence, and what sharing saves is
// only the tails in common. `\pL` has 800 multi-byte sequences, most of them
// narrow and ending in a range of their own: its program lowers to 3,055
// instructions, 800 of them Alts, where the same layout without sharing
// would have 3,500.
//
// Sharing adds no meeting point the original program lacked. Inside one
// class, every byte a thread reads after its first is a continuation byte
// 0x80-0xBF, and no sequence begins with one. The class's entry is a single
// PC, so it is entered at most once per position; two threads on the same
// node at the same step would therefore have entered at different positions,
// and the later one would have read as a lead byte what the earlier one read
// as a continuation. So no node is ever contended, and each thread's path
// through the class is exactly one sequence.
//
// # Why the order of the arms does not matter under leftmost-first
//
// The arms are emitted in ascending codepoint order, but any order gives the
// same answers. The sequences of one class encode disjoint codepoint sets, so
// no byte string is matched by two of them; and UTF-8 is prefix-free — the
// lead byte fixes the length — so no arm's match is a prefix of another's. At
// a given position at most one arm can reach the class's exit, and priority
// among the arms is never consulted. The choices priority does settle are the
// original program's, and every original Alt is copied with its Out/Arg order
// intact. The ranges are sorted and merged before splitting so that
// disjointness holds for any program, not only for the sorted, merged classes
// Go's parser already produces.
//
// # Case folding
//
// A fold is a property of codepoints, not of bytes — `(?i)k` includes
// U+212A, three bytes long — and a byte range cannot carry syntax.FoldCase:
// every engine folds a byte by ASCII ±32, so a lowered 0xC3 with the flag
// would also match 0xE3. An instruction carrying the flag is therefore
// expanded in codepoint space first: foldRanges closes its codepoints under
// unicode.SimpleFold, each joined by its whole orbit, and that set is what is
// lowered, with the flag cleared. Go's compiler sets the flag on one shape
// only, a single-rune literal (a class arrives already closed by the parser),
// and there the orbit is exactly what Inst.MatchRune accepts: `(?i)σ` is
// {Σ, ς, σ}. A flag on any other rune instruction is closed the same way,
// which is how every engine here reads it. Folding is SIMPLE, one codepoint
// to one, as in Go: `(?i)ß` is {ß, ẞ} and does not match "ss". The flag is
// cleared even where the orbit is all ASCII (`(?i)a` becomes [Aa]), so no
// FoldCase survives the pass and no engine's own fold is ever reached from a
// lowered program.
//
// # Reverse programs
//
// A reverse program is compiled from reverseRegexp's tree, which reverses
// the order of CODEPOINTS and leaves each codepoint whole; the program is
// then driven over the input from right to left. Lowered as above, it would
// expect each codepoint's bytes in forward order while reading them
// backwards, and so match neither é (C3 A9, read as A9 C3) nor anything
// else multi-byte. lowerUTF8Reverse lowers it with every sequence's byte
// ranges in reverse order instead — continuation bytes first, the lead byte
// last — and is otherwise lowerUTF8.
//
// Both arguments above still hold. The order of the arms: reversed
// encodings of distinct codepoints are distinct, and still prefix-free,
// since a proper prefix of one is continuation bytes only and every reversed
// encoding ends in a lead or ASCII byte, which is never a continuation byte.
// The sharing: two threads on one node at one step would have the same
// remaining ranges and so read their lead byte at the same position, and a
// lead byte fixes the length, so they entered at the same position too.

// # Where a program's mode comes from
//
// A pattern's mode is decided ONCE, by resolvePattern, and from there it
// travels with the data: the pattern (resolvedPattern), every tree parsed from
// it or cut from such a tree (resolvedTree), and every program compiled from
// one (resolvedProg) — the way Rust's regex keeps "this class is Unicode" in
// the class itself rather than in a flag beside it. No build site names a
// mode: compileProg reads it from the tree it is handed, a reversed tree flips
// it to the reverse lowering, and every engine takes a resolvedProg. So a
// program can be built in no mode but its pattern's, and reaches no engine
// with a mode other than the one it was built in. TestProgModeOnlyFromResolver
// holds the package to it: syntax.Compile is called only in compileProg,
// reverseRegexp only through resolvedTree.reversed, and the three types are
// constructed, and the modes named, only in the functions that make up this
// section, the set union builders, which carry their members' mode, and
// NeedsUnicodeSupport, the byte-only detector.

// progMode is how a pattern's programs treat its runes: as byte values, as
// every program was built before Unicode mode, or as codepoints lowered to
// UTF-8 forward or in reverse. Its zero value is no mode at all, so a value
// that was never resolved fails rather than passing for byte mode.
type progMode uint8

const (
	_ progMode = iota
	// progModeByte: a rune is a byte value. compileProg returns
	// syntax.Compile's program itself.
	progModeByte
	// progModeUnicode: lowered by lowerUTF8.
	progModeUnicode
	// progModeUnicodeReverse: lowered by lowerUTF8Reverse, for a tree
	// reverseRegexp has reversed.
	progModeUnicodeReverse
)

// check panics on a value that names no mode.
func (m progMode) check() {
	if m < progModeByte || m > progModeUnicodeReverse {
		panic(fmt.Sprintf("regexped: invalid progMode %d", m))
	}
}

// reversed is the mode of a tree reverseRegexp has reversed: a codepoint
// sequence is lowered last byte first. A byte stays a byte.
func (m progMode) reversed() progMode {
	switch m {
	case progModeUnicode:
		return progModeUnicodeReverse
	case progModeUnicodeReverse:
		return progModeUnicode
	}
	return m
}

// resolvedPattern is a pattern's source with the mode resolvePattern decided
// for it. Every method panics on a zero value, whose mode was never resolved,
// rather than parse an empty pattern.
type resolvedPattern struct {
	src string
	pm  progMode
}

// resolvePattern is the ONE place a single pattern's mode is decided, from its
// source, its entry's `unicode:` key (nil when unset) and the options it is
// compiled with, in this order:
//
//  1. a caller-set CompileOptions.Unicode or ForceByteMode is authoritative;
//     Unicode together with ForceByteMode or ByteMode is a programming error;
//  2. `unicode: true` is Unicode mode (with ByteMode, a contradiction);
//     `unicode: false` is byte mode;
//  3. ByteMode (`byte_mode: true`) is byte mode;
//  4. otherwise the pattern decides: Unicode when it names a rune the byte
//     gate refuses (detectUnicodeRune), byte mode when it names none.
//
// Sets resolve through resolveSetMode instead.
func resolvePattern(src string, key *bool, opts *CompileOptions) (resolvedPattern, error) {
	var o CompileOptions
	if opts != nil {
		o = *opts
	}
	switch {
	case o.Unicode && o.ForceByteMode:
		panic("regexped: CompileOptions.Unicode and ForceByteMode are both set")
	case o.Unicode && o.ByteMode:
		panic("regexped: CompileOptions.Unicode and ByteMode are both set")
	case o.Unicode:
		return resolvedPattern{src: src, pm: progModeUnicode}, nil
	case o.ForceByteMode:
		return resolvedPattern{src: src, pm: progModeByte}, nil
	}
	if key != nil {
		switch {
		case *key && o.ByteMode:
			return resolvedPattern{}, fmt.Errorf("unicode: true and byte_mode: true contradict each other")
		case *key:
			return resolvedPattern{src: src, pm: progModeUnicode}, nil
		}
		return resolvedPattern{src: src, pm: progModeByte}, nil
	}
	if o.ByteMode {
		return resolvedPattern{src: src, pm: progModeByte}, nil
	}
	if detectUnicodeRune(src) < 0 {
		return resolvedPattern{src: src, pm: progModeByte}, nil
	}
	return resolvedPattern{src: src, pm: progModeUnicode}, nil
}

// detectUnicodeRune returns the rune that makes src ask for Unicode mode, or
// -1: exactly the rune the byte-mode gate refuses (unsupportedRuneIn at the
// ASCII limit), so detection and refusal cannot disagree — the open-ended
// tail of `.` and negated classes and the fold artifacts of `(?i)` over ASCII
// count for neither. A pattern that does not parse asks for nothing; its
// compile reports the parse error.
func detectUnicodeRune(src string) rune {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return -1
	}
	// syntax.Compile never returns a non-nil error (see its stdlib source).
	mp, _ := compileProg(resolvedTree{re: re, pm: progModeByte})
	return unsupportedRuneIn(src, mp.prog, false)
}

// unicode reports whether p is in a Unicode mode.
func (p resolvedPattern) unicode() bool {
	p.pm.check()
	return p.pm != progModeByte
}

// modeName is p's mode as --verbose and --diag-json name it.
func (p resolvedPattern) modeName() string {
	if p.unicode() {
		return "unicode"
	}
	return "byte"
}

// setMode is a set's resolved mode, which every member's pattern takes
// (resolveSetMode).
type setMode struct{ pm progMode }

// member gives src, a member pattern of the set, the set's mode.
func (m setMode) member(src string) resolvedPattern {
	m.pm.check()
	return resolvedPattern{src: src, pm: m.pm}
}

// resolveSetMode is the ONE place a set's mode is decided. A member ASKS FOR
// UNICODE when its entry sets `unicode: true` or its pattern names a rune the
// byte gate refuses; it is EXPLICITLY BYTE when its entry sets
// `byte_mode: true` or `unicode: false`. An explicitly-byte member beside one
// asking for Unicode is an error, as is a set-level `unicode: true` with an
// explicitly-byte member or a set-level `unicode: false` with a member asking
// for Unicode. Otherwise a member asking for Unicode puts the set in Unicode
// mode; failing that the set-level key decides; with neither, byte mode. An
// entry's own exports do not follow it: they resolve as a single pattern.
func resolveSetMode(sc config.SetConfig, cfg config.BuildConfig, selectedIdx []int) (setMode, error) {
	label := func(re config.RegexEntry) string {
		if re.Name != "" {
			return re.Name
		}
		return re.Pattern
	}
	var byteMember, unicodeMember string
	for _, idx := range selectedIdx {
		re := cfg.Regexps[idx]
		if re.CaptureStubsRequested() {
			continue // dropped from the set (setPatternInfos), so no say in its mode
		}
		switch {
		case re.IsByteMode():
			if byteMember == "" {
				byteMember = label(re)
			}
		case re.Unicode != nil && *re.Unicode, detectUnicodeRune(re.Pattern) >= 0:
			if unicodeMember == "" {
				unicodeMember = label(re)
			}
		}
	}
	key := sc.Unicode
	switch {
	case byteMember != "" && unicodeMember != "":
		return setMode{}, fmt.Errorf("set %q: member %q is byte mode (byte_mode: true or unicode: false) "+
			"and member %q asks for Unicode mode; a set runs in one mode", sc.Name, byteMember, unicodeMember)
	case key != nil && *key && byteMember != "":
		return setMode{}, fmt.Errorf("set %q: unicode: true, but member %q is byte mode "+
			"(byte_mode: true or unicode: false)", sc.Name, byteMember)
	case key != nil && !*key && unicodeMember != "":
		return setMode{}, fmt.Errorf("set %q: unicode: false, but member %q asks for Unicode mode",
			sc.Name, unicodeMember)
	}
	if unicodeMember != "" || (key != nil && *key) {
		return setMode{pm: progModeUnicode}, nil
	}
	return setMode{pm: progModeByte}, nil
}

// parse parses p, as syntax.Perl, into a tree carrying p's mode.
func (p resolvedPattern) parse() (resolvedTree, error) {
	p.pm.check()
	re, err := syntax.Parse(p.src, syntax.Perl)
	if err != nil {
		return resolvedTree{}, err
	}
	return resolvedTree{re: re, pm: p.pm}, nil
}

// source gives src, the printed form of a tree parsed from p's source and
// possibly cut down or rewritten since, p's mode.
func (p resolvedPattern) source(src string) resolvedPattern {
	p.pm.check()
	return resolvedPattern{src: src, pm: p.pm}
}

// tree gives re, a tree parsed from p's source and possibly cut down or
// rewritten since, p's mode.
func (p resolvedPattern) tree(re *syntax.Regexp) resolvedTree {
	p.pm.check()
	return resolvedTree{re: re, pm: p.pm}
}

// resolvedTree is a parse tree with the mode of the pattern it came from.
type resolvedTree struct {
	re *syntax.Regexp
	pm progMode
}

// tree gives re, a tree cut from t or built around it, t's mode.
func (t resolvedTree) tree(re *syntax.Regexp) resolvedTree {
	t.pm.check()
	return resolvedTree{re: re, pm: t.pm}
}

// unicode reports whether t is in a Unicode mode.
func (t resolvedTree) unicode() bool {
	t.pm.check()
	return t.pm != progModeByte
}

// reversed is t reversed by reverseRegexp, in the mode that lowers it last
// byte first. It is the only way to reverse a tree, so a reversed tree cannot
// keep the forward mode.
func (t resolvedTree) reversed() resolvedTree {
	t.pm.check()
	return resolvedTree{re: reverseRegexp(t.re), pm: t.pm.reversed()}
}

// resolvedProg is a program with the mode it was compiled in. Every engine
// takes one. orig is the program before lowering — prog itself in byte mode —
// for analyses that judge the pattern's structure, which lowering obscures: a
// lowered class is an alternation of byte sequences, and its first bytes are
// lead bytes that distinct scripts share.
type resolvedProg struct {
	prog *syntax.Prog
	orig *syntax.Prog
	pm   progMode
}

// unicode reports whether p was compiled in a Unicode mode.
func (p resolvedProg) unicode() bool {
	p.pm.check()
	return p.pm != progModeByte
}

// compileProg compiles t.re.Simplify() in t's mode. In byte mode the program
// is syntax.Compile's own — the same pointer, no copy — so a byte-mode build
// cannot change by going through here; in a unicode mode it is lowered.
func compileProg(t resolvedTree) (resolvedProg, error) {
	t.pm.check()
	orig, err := syntax.Compile(t.re.Simplify())
	prog := orig
	if err == nil {
		switch t.pm {
		case progModeUnicode:
			prog = lowerUTF8(orig)
		case progModeUnicodeReverse:
			prog = lowerUTF8Reverse(orig)
		}
	}
	return resolvedProg{prog: prog, orig: orig, pm: t.pm}, err
}

// sameProgMode returns the mode every program in progs was compiled in, for a
// builder that merges them into one; programs of different modes cannot share
// one automaton, and merging them panics.
func sameProgMode(progs []resolvedProg) progMode {
	m := progs[0].pm
	for _, p := range progs[1:] {
		if p.pm != m {
			panic(fmt.Sprintf("regexped: merging programs of progMode %d and %d", m, p.pm))
		}
	}
	return m
}

// utf8Range is one byte position of a UTF-8 sequence: any byte in lo..hi.
type utf8Range struct{ lo, hi byte }

// fragExit is a fragment-local reference to the lowered instruction's own
// Out; it is resolved once every instruction's new PC is known.
const fragExit = ^uint32(0)

// lowerUTF8 returns a copy of prog in which every rune-consuming instruction
// (InstRune, InstRune1, InstRuneAny, InstRuneAnyNotNL) whose codepoints reach
// past 0x7F is replaced by the UTF-8 byte sequences that encode them, as a
// trie of byte-range InstRune/InstRune1 instructions under InstAlt chains —
// one arm per distinct byte range at each level, equal suffixes shared
// (lowerRuneInst). An instruction
// carrying syntax.FoldCase is first given its whole fold set and loses the
// flag, so the copy has no FoldCase anywhere. An unfolded instruction whose
// codepoints are all ASCII is copied as it is — a rune ≤ 0x7F is its own
// encoding. Every other instruction is copied with its PCs renumbered, in the
// original order, each lowered class laid out where its instruction stood.
// prog is not modified and shares no Rune slice with the result.
func lowerUTF8(prog *syntax.Prog) *syntax.Prog { return lowerUTF8Dir(prog, false) }

// lowerUTF8Reverse is lowerUTF8 for a program compiled from reverseRegexp's
// tree and driven backwards: every multi-byte sequence is laid out last byte
// first, so the lead byte is the one read last.
func lowerUTF8Reverse(prog *syntax.Prog) *syntax.Prog { return lowerUTF8Dir(prog, true) }

// lowerUTF8Dir lowers prog with each sequence's byte ranges in forward
// order, or in reverse order when reverse is set.
func lowerUTF8Dir(prog *syntax.Prog, reverse bool) *syntax.Prog {
	frags := make([][]syntax.Inst, len(prog.Inst))
	base := make([]uint32, len(prog.Inst))  // first new PC of each old instruction
	entry := make([]uint32, len(prog.Inst)) // new PC that references to it resolve to
	n := uint32(0)
	for pc := range prog.Inst {
		base[pc], entry[pc] = n, n
		frag, e := lowerRuneInst(&prog.Inst[pc], reverse)
		if frag == nil {
			n++
			continue
		}
		frags[pc] = frag
		entry[pc] = n + e
		n += uint32(len(frag))
	}

	out := &syntax.Prog{
		Inst:   make([]syntax.Inst, 0, n),
		Start:  int(entry[prog.Start]),
		NumCap: prog.NumCap,
	}
	for pc := range prog.Inst {
		inst := &prog.Inst[pc]
		if frag := frags[pc]; frag != nil {
			resolve := func(ref uint32) uint32 {
				if ref == fragExit {
					return entry[inst.Out]
				}
				return base[pc] + ref
			}
			for _, fi := range frag {
				switch fi.Op {
				case syntax.InstAlt:
					fi.Out, fi.Arg = resolve(fi.Out), resolve(fi.Arg)
				case syntax.InstRune, syntax.InstRune1:
					fi.Out = resolve(fi.Out)
				}
				out.Inst = append(out.Inst, fi)
			}
			continue
		}
		c := syntax.Inst{Op: inst.Op, Out: inst.Out, Arg: inst.Arg, Rune: slices.Clone(inst.Rune)}
		switch inst.Op {
		case syntax.InstMatch, syntax.InstFail:
			// No successor: Out is not a PC.
		case syntax.InstAlt, syntax.InstAltMatch:
			c.Out, c.Arg = entry[inst.Out], entry[inst.Arg]
		default:
			// InstCapture's Arg is a slot and InstEmptyWidth's an EmptyOp,
			// so only Out is a PC.
			c.Out = entry[inst.Out]
		}
		out.Inst = append(out.Inst, c)
	}
	return out
}

// lowerRuneInst returns the lowered fragment for one instruction and the
// fragment-local index of its entry, or nil when the instruction is copied as
// it is (not rune-consuming, or ASCII only and unfolded). Out and Arg in the
// fragment are fragment-local indices or fragExit. With reverse set, each
// multi-byte sequence is laid out last byte first.
func lowerRuneInst(inst *syntax.Inst, reverse bool) ([]syntax.Inst, uint32) {
	var ranges []rune
	folded := false
	switch inst.Op {
	case syntax.InstRune, syntax.InstRune1:
		ranges = codepointRanges(inst.Rune)
		if syntax.Flags(inst.Arg)&syntax.FoldCase != 0 {
			ranges, folded = foldRanges(ranges), true
		}
	case syntax.InstRuneAny:
		ranges = []rune{0, unicode.MaxRune}
	case syntax.InstRuneAnyNotNL:
		ranges = []rune{0, '\n' - 1, '\n' + 1, unicode.MaxRune}
	default:
		return nil, 0
	}
	if len(ranges) > 0 && ranges[len(ranges)-1] <= 0x7F {
		if !folded {
			return nil, 0
		}
		// An all-ASCII orbit needs no bytes of its own, only the flag gone.
		return []syntax.Inst{runeRangeInst(ranges, fragExit)}, 0
	}

	var ascii []rune // the one-byte sequences, kept as ONE multi-range instruction
	var multi [][]utf8Range
	for i := 0; i < len(ranges); i += 2 {
		for _, s := range appendUTF8Sequences(nil, ranges[i], ranges[i+1]) {
			if len(s) == 1 {
				ascii = append(ascii, rune(s[0].lo), rune(s[0].hi))
				continue
			}
			if reverse {
				slices.Reverse(s)
			}
			multi = append(multi, s)
		}
	}

	// Build a PREFIX trie of the sequences: each node splits the byte range
	// its sequences continue with into disjoint intervals, one arm per
	// interval — the lead ranges at the top, so Backtracking pushes a frame
	// per distinct lead range rather than per sequence (`\pL`: 33 against
	// 800). Arms are byte-range instructions interned by (range, successor),
	// so equal suffixes still share instructions, and nodes by their arms, so
	// equal subtrees share nodes. All sequences in a node continue by the same
	// number of bytes forward (a lead byte fixes the length) and none ends
	// where another continues in either direction (a sequence ends on its
	// lead or last byte, never on a byte that another continues past).
	type arm struct {
		r    utf8Range
		next uint32 // node index, or fragExit
	}
	var arms []arm
	var armHeight []int
	armIDs := make(map[arm]uint32)
	type node struct {
		arms   []uint32
		height int
	}
	var nodes []node
	nodeIDs := make(map[string]uint32)
	internArm := func(a arm) uint32 {
		if id, ok := armIDs[a]; ok {
			return id
		}
		h := 1
		if a.next != fragExit {
			h += nodes[a.next].height
		}
		id := uint32(len(arms))
		arms = append(arms, a)
		armHeight = append(armHeight, h)
		armIDs[a] = id
		return id
	}
	var build func(tails [][]utf8Range) []uint32
	internNode := func(tails [][]utf8Range) uint32 {
		ids := build(tails)
		key := fmt.Sprint(ids)
		if id, ok := nodeIDs[key]; ok {
			return id
		}
		h := 0
		for _, a := range ids {
			h = max(h, armHeight[a])
		}
		id := uint32(len(nodes))
		nodes = append(nodes, node{ids, h})
		nodeIDs[key] = id
		return id
	}
	// build returns the arms of the node whose sequences are tails.
	build = func(tails [][]utf8Range) []uint32 {
		bounds := make([]int, 0, 2*len(tails))
		for _, t := range tails {
			bounds = append(bounds, int(t[0].lo), int(t[0].hi)+1)
		}
		slices.Sort(bounds)
		bounds = slices.Compact(bounds)
		var out []uint32
		var cur arm
		have := false
		flush := func() {
			if have {
				out = append(out, internArm(cur))
			}
			have = false
		}
		for i := 0; i+1 < len(bounds); i++ {
			lo, hi := bounds[i], bounds[i+1]-1
			var rest [][]utf8Range
			covered, ended := false, false
			for _, t := range tails {
				if int(t[0].lo) <= lo && hi <= int(t[0].hi) {
					covered = true
					if len(t) == 1 {
						ended = true
					} else {
						rest = append(rest, t[1:])
					}
				}
			}
			if !covered {
				flush()
				continue
			}
			if ended && len(rest) > 0 {
				panic("compile: a UTF-8 sequence ends on a byte another one continues past")
			}
			next := fragExit
			if len(rest) > 0 {
				next = internNode(rest)
			}
			if have && cur.next == next && int(cur.r.hi)+1 == lo {
				cur.r.hi = byte(hi)
				continue
			}
			flush()
			cur, have = arm{utf8Range{byte(lo), byte(hi)}, next}, true
		}
		flush()
		return out
	}
	var top []uint32
	if len(multi) > 0 {
		top = build(multi)
	}

	entryArms := len(top)
	if len(ascii) > 0 {
		entryArms++
	}
	if entryArms == 0 {
		// Nothing encodable: an empty class, or surrogates only.
		return []syntax.Inst{{Op: syntax.InstFail}}, 0
	}

	// Layout: the entry's Alt chain over the ASCII arm and the top arms, then
	// the ASCII arm, then by descending height each node with more than one
	// arm as an Alt chain over its arms, and then the arms of that height.
	// Every edge inside the fragment then points FORWARD — an Alt to arms of
	// its own height, laid out after it, an arm to a node lower down — so a
	// reading of the program by PC order cannot mistake an arm for a loop:
	// analysePattern counts an Alt whose Out is behind it and whose Arg is not
	// as a loop, not as an alternation.
	used := make([]bool, len(nodes)) // nodes some arm leads to: the top one is the entry chain
	for _, a := range arms {
		if a.next != fragExit {
			used[a.next] = true
		}
	}
	maxH := 0
	for _, h := range armHeight {
		maxH = max(maxH, h)
	}
	nAlt := entryArms - 1
	pos := make([]uint32, len(arms))
	entryAt := make([]uint32, len(nodes))
	n := uint32(nAlt)
	asciiAt := n
	if len(ascii) > 0 {
		n++
	}
	for h := maxH; h >= 1; h-- {
		for id, nd := range nodes {
			if nd.height == h && used[id] && len(nd.arms) > 1 {
				entryAt[id] = n
				n += uint32(len(nd.arms) - 1)
			}
		}
		for id, ah := range armHeight {
			if ah == h {
				pos[id] = n
				n++
			}
		}
	}
	for id, nd := range nodes {
		if len(nd.arms) == 1 {
			entryAt[id] = pos[nd.arms[0]]
		}
	}
	frag := make([]syntax.Inst, n)
	altChain := func(at uint32, targets []uint32) {
		for j := 0; j < len(targets)-1; j++ {
			arg := at + uint32(j) + 1
			if j == len(targets)-2 {
				arg = targets[j+1]
			}
			frag[at+uint32(j)] = syntax.Inst{Op: syntax.InstAlt, Out: targets[j], Arg: arg}
		}
	}
	targets := make([]uint32, 0, entryArms)
	if len(ascii) > 0 {
		targets = append(targets, asciiAt)
		frag[asciiAt] = runeRangeInst(ascii, fragExit)
	}
	for _, a := range top {
		targets = append(targets, pos[a])
	}
	altChain(0, targets)
	for id, nd := range nodes {
		if used[id] && len(nd.arms) > 1 {
			t := make([]uint32, len(nd.arms))
			for i, a := range nd.arms {
				t[i] = pos[a]
			}
			altChain(entryAt[id], t)
		}
	}
	for id, a := range arms {
		next := fragExit
		if a.next != fragExit {
			next = entryAt[a.next]
		}
		frag[pos[id]] = runeRangeInst([]rune{rune(a.r.lo), rune(a.r.hi)}, next)
	}
	if nAlt > 0 {
		return frag, 0
	}
	return frag, targets[0]
}

// runeRangeInst builds a consuming instruction over the [lo, hi] pairs of
// ranges, in the form Go's compiler gives it: InstRune1 for a single value,
// InstRune otherwise. No flags.
func runeRangeInst(ranges []rune, out uint32) syntax.Inst {
	if len(ranges) == 2 && ranges[0] == ranges[1] {
		return syntax.Inst{Op: syntax.InstRune1, Out: out, Rune: []rune{ranges[0]}}
	}
	return syntax.Inst{Op: syntax.InstRune, Out: out, Rune: slices.Clone(ranges)}
}

// codepointRanges returns an InstRune/InstRune1 Rune slice as sorted, merged
// [lo, hi] pairs clamped to 0..unicode.MaxRune. A one-element slice is a
// single rune (the literal form) and a two-element InstRune1 slice is the
// pair form of the same thing; both read correctly as pairs here.
func codepointRanges(rs []rune) []rune {
	if len(rs) == 1 {
		rs = []rune{rs[0], rs[0]}
	}
	pairs := make([][2]rune, 0, len(rs)/2)
	for i := 0; i+1 < len(rs); i += 2 {
		lo, hi := max(rs[i], 0), min(rs[i+1], unicode.MaxRune)
		if lo <= hi {
			pairs = append(pairs, [2]rune{lo, hi})
		}
	}
	slices.SortFunc(pairs, func(a, b [2]rune) int { return cmp.Compare(a[0], b[0]) })
	merged := make([]rune, 0, 2*len(pairs))
	for _, p := range pairs {
		if n := len(merged); n > 0 && p[0] <= merged[n-1]+1 {
			if p[1] > merged[n-1] {
				merged[n-1] = p[1]
			}
			continue
		}
		merged = append(merged, p[0], p[1])
	}
	return merged
}

// foldRanges closes ranges, sorted and merged [lo, hi] pairs, under simple
// case folding: every codepoint is joined by its whole unicode.SimpleFold
// orbit, and the result is sorted and merged again. The walk is codepoint by
// codepoint; Go's compiler folds a single rune only, so in practice it is one
// orbit.
func foldRanges(ranges []rune) []rune {
	out := slices.Clone(ranges)
	for i := 0; i+1 < len(ranges); i += 2 {
		for c := ranges[i]; c <= ranges[i+1]; c++ {
			for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
				out = append(out, f, f)
			}
		}
	}
	return codepointRanges(out)
}

// appendUTF8Sequences appends to dst the UTF-8 sequences that encode exactly
// the codepoints lo..hi, surrogates excluded, in ascending codepoint order.
// Each sequence is 1-4 byte ranges whose product is exactly the encodings of
// one sub-range; the sub-ranges partition lo..hi minus the surrogates.
func appendUTF8Sequences(dst [][]utf8Range, lo, hi rune) [][]utf8Range {
	type span struct{ lo, hi rune }
	stack := []span{{lo, hi}}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
	split:
		for {
			if r.lo < 0xE000 && r.hi > 0xD7FF {
				// Cut the surrogates out; either side may come out empty.
				stack = append(stack, span{0xE000, r.hi})
				r.hi = 0xD7FF
				continue
			}
			if r.lo > r.hi {
				break
			}
			for _, top := range [...]rune{0x7F, 0x7FF, 0xFFFF} {
				if r.lo <= top && top < r.hi {
					stack = append(stack, span{top + 1, r.hi})
					r.hi = top
					continue split
				}
			}
			if r.hi <= 0x7F {
				dst = append(dst, []utf8Range{{byte(r.lo), byte(r.hi)}})
				break
			}
			for i := 1; i < utf8.UTFMax; i++ {
				m := rune(1)<<(6*i) - 1
				if r.lo&^m == r.hi&^m {
					continue
				}
				if r.lo&m != 0 {
					stack = append(stack, span{r.lo | m + 1, r.hi})
					r.hi = r.lo | m
					continue split
				}
				if r.hi&m != m {
					stack = append(stack, span{r.hi &^ m, r.hi})
					r.hi = r.hi&^m - 1
					continue split
				}
			}
			// Both ends now encode to the same length, and each byte
			// position spans one contiguous range.
			var a, b [utf8.UTFMax]byte
			n := utf8.EncodeRune(a[:], r.lo)
			utf8.EncodeRune(b[:], r.hi)
			s := make([]utf8Range, n)
			for i := range s {
				s[i] = utf8Range{a[i], b[i]}
			}
			dst = append(dst, s)
			break
		}
	}
	return dst
}
