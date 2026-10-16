package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// ── The program sweep: a split member's own overlapping answers ────────────
//
// An overlapping `find` needs, for every start, each member's match there. A
// member the set splits out answers through its own linear search, which gives
// the LEFTMOST match from a position — so over `kaaa…z`×n a non-greedy or
// Backtracking member re-read a long tail for every start: ×4 per doubling
// whatever the rest of the set did (`{foo\w+, a[a-z]*?z}` over `a`×n + `z`:
// 262,528 fuel/byte at 8 KB).
//
// The PROGRAM SWEEP gives every start's answer in one backward pass over the
// member's own syntax.Prog, one column per input position:
//
//	res(r, p) = the end of the highest-priority path from (r, p), or -1
//
// for every ROOT r — the program's start, and the target of every consuming
// instruction — and A[p] = res(start, p). A later call from q reads the first
// s ≥ q with A[s] ≥ 0; the merge's lower bound keeps that scan amortised
// linear. Measured on a prototype: 661 fuel/byte linear on that input, 784-929
// on `(?:a|b)*a(?:a|b){12}c` over `a`×n + `c`; ordinary text +0.2% to +1.1%.
//
// WHY ONE COLUMN IS ENOUGH. The value of a root at p is "the first item of its
// CLOSURE whose continuation succeeds", where the closure is the ordered list
// of consuming and Match instructions a depth-first walk over the epsilon
// edges reaches from r — in priority order, each instruction at most once (Go's
// drop-the-second-arrival rule, which is what terminates a zero-width cycle).
// A consuming item succeeds when it takes the byte at p and its target's value
// at p + 1 is not -1; Match succeeds at once, with end p. The value does not
// depend on how the search reached (r, p): an instruction a higher-priority
// branch already visited at p failed there (or the search would have ended),
// so skipping it, as Go's backtracker does, and failing it again agree. So the
// column at p is a function of the column at p + 1 and the byte at p alone,
// and the closures are computed here, at compile time — once per combination
// of the assertions the program tests (\b, \B, ^, $, (?m)), which are judged
// per column from the bytes either side of p.
//
// The answers live in the caller's cache region, after the cache itself, and
// are CHECKPOINTED exactly as the cache is (set_overlap_ckpt.go, the same
// sizing formula, emitCkptSizing): a column snapshot every `stride` positions
// and one block of answers materialised at a time, so above the 64 MiB budget
// the region is the square root of the input. The sweep's own state — swept,
// the materialised block, the drive's work — is in the cache header's
// reserved words, which the caller zeroes to start a drive.
//
// The sweep runs only once a member's ordinary searches have walked past
// k × len + 64 bytes in the drive (setSweep.emitWorkBound), so ordinary text,
// which never gets there, pays for the counter alone. k is 4 in byte mode. In
// Unicode mode a lowered class gives a column thousands of roots wide, and a
// sweep that costs tens of thousands of fuel per byte must not be bought at the
// first 4 × len walked bytes: k is the sweep's estimated cost per byte over a
// walk's, so the walks spend what the sweep would before it runs — never more
// than twice the cheaper of the two.

// sweepMaxRoots bounds a set's columns (every swept member's roots together),
// and sweepMaxItems the closure items the column step emits: past either the
// member keeps its ordinary search. The Unicode-mode bounds are larger because
// a lowered class multiplies both (sweepLimits).
const (
	sweepMaxRoots        = 4096
	sweepMaxItems        = 1 << 16
	sweepMaxRootsUnicode = 1 << 16
	sweepMaxItemsUnicode = 1 << 20
)

// sweepLimits is sweepMaxRoots and sweepMaxItems for a program of the mode.
func sweepLimits(unicode bool) (roots, items int) {
	if unicode {
		return sweepMaxRootsUnicode, sweepMaxItemsUnicode
	}
	return sweepMaxRoots, sweepMaxItems
}

// The Unicode-mode trigger's two costs (setSweep.workK), calibrated on an
// 8-member set of lowered letter classes (`\pL+\p{Greek}` …) over 16 KB of
// Cyrillic letters: its column step was 505,193 bytes of code and swept at
// 82,350 fuel per input byte, one fuel per sweepCodePerFuel bytes; its members'
// searches, never swept, spent 9.0×10^9 fuel on about 1.3×10^8 charged bytes,
// sweepWalkFuelPerByte each.
const (
	sweepCodePerFuel     = 6
	sweepWalkFuelPerByte = 64
)

// The program sweep's state, in the cache header's reserved words (see
// set_overlap_ckpt.go's header map: +0, +4 and +32 are reserved and unread).
const (
	sweepHdrReady    = 0  // i32: 1 once swept this drive
	sweepHdrCurBlock = 4  // i32: the materialised block, +1 (0 = none)
	sweepHdrWork     = 32 // i64: the swept members' ordinary walks this drive
)

// sweepProg is one member's program sweep.
type sweepProg struct {
	prog  *syntax.Prog
	roots []int       // root pcs; roots[0] is the start
	root  map[int]int // pc -> root index
	// flags is the empty-width assertions the program tests, in bit order:
	// a column's context is the bitmask of those that hold at its position.
	flags []syntax.EmptyOp
	// lists[r][ctx] is root r's closure under context ctx: Match and
	// consuming pcs in priority order.
	lists [][][]int
	base  int // the first of its roots among the set's columns
	// byteTab is each consuming pc's 257-byte membership table (entry 256,
	// for "no byte", always 0), by its address in the table memory.
	byteTab map[int]int32
	// utf8Start: the member's empty match can sit inside a character
	// (PatternInfo.utf8StartFind), so its answer at such a position is -1.
	utf8Start bool
}

// planSweepProg is pattern's program sweep, nil when the member keeps its
// ordinary search (over the size bounds).
func planSweepProg(pattern resolvedPattern) *sweepProg {
	prog := compileBTProg(pattern).prog
	if prog == nil {
		return nil
	}
	sp := &sweepProg{prog: prog, root: map[int]int{}}
	addRoot := func(pc int) {
		if _, ok := sp.root[pc]; !ok {
			sp.root[pc] = len(sp.roots)
			sp.roots = append(sp.roots, pc)
		}
	}
	addRoot(prog.Start)
	var seen uint32
	for _, in := range prog.Inst {
		switch in.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			addRoot(int(in.Out))
		case syntax.InstEmptyWidth:
			seen |= in.Arg
		}
	}
	for _, f := range []syntax.EmptyOp{syntax.EmptyBeginLine, syntax.EmptyEndLine, syntax.EmptyBeginText,
		syntax.EmptyEndText, syntax.EmptyWordBoundary, syntax.EmptyNoWordBoundary} {
		if seen&uint32(f) != 0 {
			sp.flags = append(sp.flags, f)
		}
	}
	maxRoots, maxItems := sweepLimits(pattern.unicode())
	if len(sp.roots) > maxRoots {
		return nil
	}
	combos := 1 << len(sp.flags)
	items := 0
	sp.lists = make([][][]int, len(sp.roots))
	for r, pc := range sp.roots {
		sp.lists[r] = make([][]int, combos)
		for ctx := 0; ctx < combos; ctx++ {
			sp.lists[r][ctx] = sp.closure(pc, sp.ctxOps(ctx))
			items += len(sp.lists[r][ctx])
			if items > maxItems {
				return nil
			}
		}
	}
	return sp
}

// ctxOps is the assertions that hold under context ctx.
func (sp *sweepProg) ctxOps(ctx int) syntax.EmptyOp {
	var ops syntax.EmptyOp
	for i, f := range sp.flags {
		if ctx&(1<<i) != 0 {
			ops |= f
		}
	}
	return ops
}

// closure is the ordered Match and consuming pcs a depth-first walk over the
// epsilon edges reaches from pc, each pc at most once, where the assertions in
// ops hold.
func (sp *sweepProg) closure(pc int, ops syntax.EmptyOp) []int {
	visited := make([]bool, len(sp.prog.Inst))
	var out []int
	var walk func(pc int)
	walk = func(pc int) {
		if visited[pc] {
			return
		}
		visited[pc] = true
		in := sp.prog.Inst[pc]
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			walk(int(in.Out))
			walk(int(in.Arg))
		case syntax.InstNop, syntax.InstCapture:
			walk(int(in.Out))
		case syntax.InstEmptyWidth:
			if syntax.EmptyOp(in.Arg)&^ops == 0 {
				walk(int(in.Out))
			}
		case syntax.InstFail:
		default: // Match and the consuming instructions
			out = append(out, pc)
		}
	}
	walk(pc)
	return out
}

// sweepByteSet is the bytes a consuming instruction takes, as the Backtracking
// engine tests them: a rune range saturates at 0xFF, case folding is Go's.
func sweepByteSet(in syntax.Inst) [257]byte {
	var t [257]byte
	for b := 0; b < 256; b++ {
		var ok bool
		switch in.Op {
		case syntax.InstRuneAny:
			ok = true
		case syntax.InstRuneAnyNotNL:
			ok = b != '\n'
		default:
			ok = in.MatchRune(rune(b))
		}
		if ok {
			t[b] = 1
		}
	}
	return t
}

// setSweep is a set's program sweeps: one per split member that has one.
type setSweep struct {
	members []*sweepProg // by split index; nil keeps its ordinary search
	roots   int          // every member's roots together: the column width
	swept   int          // how many members have one: the row is 4 × swept bytes
	slot    map[int]int  // split index -> its answer's slot in a row
	// unicode: the set is in Unicode mode; workK is the trigger's multiplier
	// (emitWorkBound).
	unicode bool
	workK   int64
	colA    int32 // the two working columns, in the table memory
	colB    int32
}

// placeProgramSweeps plans a sweep for each split member of an overlapping
// `find` and lays out what they share: the byte tables, as data, and the two
// working columns. nil when no member has one.
func placeProgramSweeps(full SetSpec, split []splitCand, ra *regionAlloc) (*setSweep, []byte, int) {
	if !full.Overlapping || full.Find == "" {
		return nil, nil, 0
	}
	sw := &setSweep{members: make([]*sweepProg, len(split)), slot: map[int]int{}, workK: 4}
	for k, c := range split {
		rp := full.Patterns[c.idx].rp
		sp := planSweepProg(rp)
		if maxRoots, _ := sweepLimits(rp.unicode()); sp == nil || sw.roots+len(sp.roots) > maxRoots {
			continue
		}
		sw.unicode = rp.unicode()
		sp.utf8Start = full.Patterns[c.idx].utf8StartFind
		sp.base = sw.roots
		sw.roots += len(sp.roots)
		sw.slot[k] = sw.swept
		sw.swept++
		sw.members[k] = sp
	}
	if sw.swept == 0 {
		return nil, nil, 0
	}
	// One 257-byte table per distinct byte set, shared by every member.
	var data []byte
	segs := 0
	tabs := map[[257]byte]int32{}
	for _, sp := range sw.members {
		if sp == nil {
			continue
		}
		sp.byteTab = map[int]int32{}
		for pc, in := range sp.prog.Inst {
			switch in.Op {
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			default:
				continue
			}
			t := sweepByteSet(in)
			at, ok := tabs[t]
			if !ok {
				at = ra.Reserve("program-sweep-bytes", 1)
				ra.Commit(at + 257)
				tabs[t] = at
				data = append(data, appendDataSegment(nil, at, t[:])...)
				segs++
			}
			sp.byteTab[pc] = at
		}
	}
	sw.colA = ra.Reserve("program-sweep-columns", 8)
	sw.colB = sw.colA + int32(4*sw.roots) //nolint:gosec // bounded by sweepMaxRoots
	end := sw.colB + int32(4*sw.roots)    //nolint:gosec
	ra.Commit(end)
	data = append(data, appendDataSegment(nil, end-1, []byte{0})...)
	segs++
	sw.setWorkK()
	return sw, data, segs
}

// The sweep's geometry in a caller's region, as the cache's: cells are the
// columns' width, a row holds one answer per swept member.
func (sw *setSweep) cells() int     { return sw.roots }
func (sw *setSweep) rowBytes() int  { return 4 * sw.swept }
func (sw *setSweep) cellBytes() int { return 4*sw.roots + 4 }

// emitWorkBound is the work past which a drive's swept members get their
// sweep: workK × len + 64 — abi's search rule (k = 4) over the whole input, as
// a pattern's notes arm, or in Unicode mode the walk bytes that cost what the
// sweep would.
func (sw *setSweep) emitWorkBound(b []byte, pLen byte) []byte {
	b = append(b, 0x20, pLen, 0xAD) // (u64) len
	b = i64c(b, sw.workK)
	b = append(b, 0x7E) // × k
	b = i64c(b, 64)
	return append(b, 0x7C) // + 64
}

// setWorkK sets the Unicode-mode trigger: the sweep's estimated fuel per
// position (its column step's code over sweepCodePerFuel) in charged walk
// bytes, never below byte mode's 4. The walks then spend what the sweep would
// before it runs. Called once the byte tables and columns are placed, since
// the step addresses them.
func (sw *setSweep) setWorkK() {
	if !sw.unicode {
		return
	}
	step := len(sw.emitColumnStep(nil, 0, sweepLocals{}))
	sw.workK = max(4, int64(step/sweepCodePerFuel/sweepWalkFuelPerByte))
}

// sweepLocals is what the column step reads and writes.
type sweepLocals struct {
	pPtr, pLen    byte   // the call's input
	p             uint32 // i32: the position
	byteIdx       uint32 // i32: the byte at p, or 256 at the end
	ctx           uint32 // i32: the assertion context at p
	cur, nxt      uint32 // i32: the two columns' addresses
	v, prev, next uint32 // i32 scratch
}

// emitColumnStep computes every swept member's column at p into cur from the
// column at p + 1 in nxt.
func (sw *setSweep) emitColumnStep(b []byte, tm int, l sweepLocals) []byte {
	// The byte at p (256 at the end), and the bytes either side for the
	// assertions.
	b = lget(b, l.p)
	b = append(b, 0x20, l.pLen, 0x49, 0x04, 0x7F) // p < len (u): if (result i32)
	b = append(b, 0x20, l.pPtr)
	b = lget(b, l.p)
	b = append(b, 0x6A, 0x2D, 0x00, 0x00) // i32.load8_u (input)
	b = append(b, 0x05)
	b = i32c(b, 256)
	b = append(b, 0x0B)
	b = lset(b, l.byteIdx)
	anyFlags := false
	for _, sp := range sw.members {
		if sp != nil && len(sp.flags) > 0 {
			anyFlags = true
		}
	}
	if anyFlags {
		// prev = p > 0 ? input[p-1] : 256; next = byteIdx.
		b = lget(b, l.p)
		b = append(b, 0x04, 0x7F)
		b = append(b, 0x20, l.pPtr)
		b = lget(b, l.p)
		b = append(b, 0x6A, 0x41, 0x01, 0x6B, 0x2D, 0x00, 0x00)
		b = append(b, 0x05)
		b = i32c(b, 256)
		b = append(b, 0x0B)
		b = lset(b, l.prev)
	}
	for _, sp := range sw.members {
		if sp == nil {
			continue
		}
		if len(sp.flags) > 0 {
			b = sp.emitContext(b, l)
		}
		for r := range sp.roots {
			b = sp.emitRoot(b, tm, r, l)
		}
	}
	return b
}

// emitContext leaves this member's assertion context at p in l.ctx: bit i set
// when sp.flags[i] holds, judged as syntax.EmptyOpContext does, with the
// engine's ASCII word characters.
func (sp *sweepProg) emitContext(b []byte, l sweepLocals) []byte {
	isWord := func(b []byte, x uint32) []byte {
		// '0'-'9' | 'A'-'Z' | 'a'-'z' | '_'; 256 is none of them.
		rng := func(b []byte, lo, hi int32) []byte {
			b = lget(b, x)
			b = i32c(b, lo)
			b = append(b, 0x6B) // x - lo
			b = i32c(b, hi-lo+1)
			return append(b, 0x49) // u<
		}
		b = rng(b, '0', '9')
		b = rng(b, 'A', 'Z')
		b = append(b, 0x72)
		b = rng(b, 'a', 'z')
		b = append(b, 0x72)
		b = lget(b, x)
		b = i32c(b, '_')
		return append(b, 0x46, 0x72)
	}
	b = i32c(b, 0)
	for i, f := range sp.flags {
		switch f {
		case syntax.EmptyBeginLine:
			b = lget(b, l.prev)
			b = i32c(b, 256)
			b = append(b, 0x46)
			b = lget(b, l.prev)
			b = i32c(b, '\n')
			b = append(b, 0x46, 0x72)
		case syntax.EmptyEndLine:
			b = lget(b, l.byteIdx)
			b = i32c(b, 256)
			b = append(b, 0x46)
			b = lget(b, l.byteIdx)
			b = i32c(b, '\n')
			b = append(b, 0x46, 0x72)
		case syntax.EmptyBeginText:
			b = lget(b, l.p)
			b = append(b, 0x45)
		case syntax.EmptyEndText:
			b = lget(b, l.byteIdx)
			b = i32c(b, 256)
			b = append(b, 0x46)
		case syntax.EmptyWordBoundary:
			b = isWord(b, l.prev)
			b = isWord(b, l.byteIdx)
			b = append(b, 0x47) // ne
		case syntax.EmptyNoWordBoundary:
			b = isWord(b, l.prev)
			b = isWord(b, l.byteIdx)
			b = append(b, 0x46) // eq
		}
		if i > 0 {
			b = i32c(b, int32(i))
			b = append(b, 0x74) // shl
		}
		b = append(b, 0x72) // or
	}
	return lset(b, l.ctx)
}

// emitRoot computes root r's value at p into cur[base + r].
func (sp *sweepProg) emitRoot(b []byte, tm int, r int, l sweepLocals) []byte {
	b = lget(b, l.cur) // the store's address
	// Group the contexts by identical lists: most roots have one.
	type group struct {
		list []int
		mask uint64
	}
	var groups []group
	for ctx, list := range sp.lists[r] {
		found := false
		for gi := range groups {
			if equalInts(groups[gi].list, list) {
				groups[gi].mask |= 1 << uint(ctx)
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, group{list: list, mask: 1 << uint(ctx)})
		}
	}
	var eval func(b []byte, gi int) []byte
	eval = func(b []byte, gi int) []byte {
		if gi == len(groups)-1 {
			return sp.emitList(b, tm, groups[gi].list, l)
		}
		b = i64c(b, int64(groups[gi].mask)) //nolint:gosec // at most 64 contexts
		b = lget(b, l.ctx)
		b = append(b, 0xAD, 0x88, 0xA7) // >> ctx; wrap
		b = append(b, 0x41, 0x01, 0x71) // & 1
		b = append(b, 0x04, 0x7F)       // if (result i32)
		b = sp.emitList(b, tm, groups[gi].list, l)
		b = append(b, 0x05)
		b = eval(b, gi+1)
		return append(b, 0x0B)
	}
	b = eval(b, 0)
	return appendTableStore32(b, tm, uint32(4*(sp.base+r))) //nolint:gosec // a column offset
}

// emitList pushes the first success over a closure list: p for Match, the
// target's value at p + 1 for a consuming item that takes the byte at p, -1
// when nothing succeeds.
func (sp *sweepProg) emitList(b []byte, tm int, list []int, l sweepLocals) []byte {
	b = append(b, 0x02, 0x7F) // block (result i32)
	for _, pc := range list {
		in := sp.prog.Inst[pc]
		if in.Op == syntax.InstMatch {
			b = lget(b, l.p)
			b = append(b, 0x0C, 0x00) // br: the block's answer
			break
		}
		b = i32c(b, sp.byteTab[pc])
		b = lget(b, l.byteIdx)
		b = append(b, 0x6A)
		b = appendTableLoad8u(b, tm)
		b = append(b, 0x04, 0x40) // takes the byte: if
		b = lget(b, l.nxt)
		b = appendTableLoad32(b, tm, uint32(4*(sp.base+sp.root[int(in.Out)]))) //nolint:gosec // a column offset
		b = ltee(b, l.v)
		b = append(b, 0x41, 0x00, 0x4E) // >= 0
		b = append(b, 0x04, 0x40)
		b = lget(b, l.v)
		b = append(b, 0x0C, 0x02) // br the block: 0 = this if, 1 = takes, 2 = block
		b = append(b, 0x0B, 0x0B)
	}
	b = i32c(b, -1)
	return append(b, 0x0B)
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// utf8Start reports whether some swept member's answers need the Unicode
// start check (sweepProg.utf8Start).
func (sw *setSweep) utf8Start() bool {
	for _, sp := range sw.members {
		if sp != nil && sp.utf8Start {
			return true
		}
	}
	return false
}

// emitWriteRow stores every swept member's answer at p — its start root's
// value — into the block buffer's row for p. rowAddr pushes the row's address.
// With u8 (sw.utf8Start), a member whose empty match can sit inside a
// character answers -1 at a position inside one, where no match starts; inside
// is the i32 local that check leaves 1 or 0 in.
func (sw *setSweep) emitWriteRow(b []byte, tm int, l sweepLocals, u8 *utf8StartLocals, inside uint32, rowAddr func([]byte) []byte) []byte {
	if u8 != nil {
		b = i32c(b, 0)
		b = lset(b, inside)
		b = lget(b, l.p)
		b = lset(b, u8.pos)
		b = emitUTF8Start(b, *u8, func(b []byte) []byte { return lset(i32c(b, 1), inside) })
	}
	for k, sp := range sw.members {
		if sp == nil {
			continue
		}
		b = rowAddr(b)
		if u8 != nil && sp.utf8Start {
			b = i32c(b, -1)
		}
		b = lget(b, l.cur)
		b = appendTableLoad32(b, tm, uint32(4*sp.base)) //nolint:gosec // a column offset
		if u8 != nil && sp.utf8Start {
			b = lget(b, inside)
			b = append(b, 0x1B) // select: -1 inside a character
		}
		b = append(b, 0x36, 0x02)                        // i32.store (the caller's region)
		b = utils.AppendULEB128(b, uint32(4*sw.slot[k])) //nolint:gosec // a row offset
	}
	return b
}

// sweepGeo is the locals a sweep's region arithmetic fills.
type sweepGeo struct {
	region        byte   // i32 param/local: the caller's cache region
	area, k, rows uint32 // i32: the sweep's part of it, its stride, its block buffer
	m64, k64, b64 uint32 // i64 scratch for emitCkptSizing
	cacheB, nb    uint32 // i32 scratch
}

// emitArea computes, for an input of the i32 local pLen bytes, where the
// sweep's part of the caller's region starts — past the cache (its bytes from
// the same formula the caller sized it by, 8-aligned) — and the sweep's stride
// and block buffer, from emitCkptSizing over the sweep's own geometry; and
// leaves 1 on the stack when the region holds it all, 0 when it does not (no
// region, or one sized without the sweep's part).
func (cs *compiledSet) emitSweepArea(b []byte, pLen byte, g sweepGeo) []byte {
	sw := cs.progSweep
	// The cache's bytes: the kept members' set's when it has one, else the
	// nominal header a set with no cache is handed.
	if kc := cs.keptCache; kc != nil && kc.usesOverlapDP() {
		_, _, rowBytes, _ := kc.overlapCacheGeometry()
		b = emitCkptSizing(b, uint32(pLen), g.m64, g.k64, g.b64, kc.overlapCells(), int64(rowBytes))
		b = lget(b, g.b64)
		b = append(b, 0xA7) // i32.wrap_i64
	} else {
		b = i32c(b, ckptHdrBytes)
	}
	b = i32c(b, 7)
	b = append(b, 0x6A)
	b = i32c(b, -8)
	b = append(b, 0x71) // align8
	b = lset(b, g.cacheB)
	b = append(b, 0x20, g.region)
	b = lget(b, g.cacheB)
	b = append(b, 0x6A)
	b = lset(b, g.area)
	// The sweep's stride and bytes.
	b = emitCkptSizingBudget(b, uint32(pLen), g.m64, g.k64, g.b64, sw.cells(), int64(sw.rowBytes()), cs.sweepBudgetBytes())
	b = lget(b, g.k64)
	b = append(b, 0xA7)
	b = lset(b, g.k)
	// nb = ceil(m / k); rows = area + HDR + nb × cell + 4.
	b = lget(b, g.m64)
	b = lget(b, g.k64)
	b = append(b, 0x7C, 0x42, 0x01, 0x7D) // m + k - 1
	b = lget(b, g.k64)
	b = append(b, 0x80, 0xA7) // div_u; wrap
	b = lset(b, g.nb)
	b = lget(b, g.area)
	b = i32c(b, ckptHdrBytes+4)
	b = append(b, 0x6A)
	b = lget(b, g.nb)
	b = i32c(b, int32(sw.cellBytes())) //nolint:gosec // bounded by sweepMaxRoots
	b = append(b, 0x6C, 0x6A)
	b = lset(b, g.rows)
	// Holds it: cacheB + bytes <= the region's length, and the sweep within the
	// budget (emitCkptSizing's bytes are then what the stub reserved).
	b = lget(b, g.b64)
	b = i64c(b, overlapCacheMaxBytes)
	b = append(b, 0x58) // le_u
	return b
}

// sweepBudgetBytes is the size past which the sweep checkpoints.
func (cs *compiledSet) sweepBudgetBytes() int64 {
	if cs.sweepBudget > 0 {
		return cs.sweepBudget
	}
	return overlapCacheMaxBytes
}

// emitSweepFnBody is the sweep's ONE function, (ptr, len, region, arg) →
// i32 0, in two modes chosen by arg's sign:
//
//   - arg = from ≥ 0, the PASS: every swept member's column from position len
//     down to from, a checkpoint every stride positions and the answers into
//     the block buffer, which then holds the block of `from`;
//   - arg = -1 - j < 0, materialise BLOCK j: from checkpoint j — the column at
//     (j + 1) × stride, or none past the end — down to the block's first
//     position.
//
// One function rather than two because the column step is most of either,
// and it is emitted once. The caller has checked the region holds the sweep.
func (cs *compiledSet) emitSweepFnBody(tm int) []byte {
	sw := cs.progSweep
	const pPtr, pLen, pRegion, pArg = 0, 1, 2, 3
	a := newLocalAlloc(4)
	l := sweepLocals{pPtr: pPtr, pLen: pLen}
	i32 := func() uint32 { return uint32(a.I32()) }
	i64 := func() uint32 { return uint32(a.I64()) }
	l.p, l.byteIdx, l.ctx, l.cur, l.nxt, l.v, l.prev, l.next = i32(), i32(), i32(), i32(), i32(), i32(), i32(), i32()
	g := sweepGeo{region: pRegion}
	g.area, g.k, g.rows, g.cacheB, g.nb = i32(), i32(), i32(), i32(), i32()
	lLo, lJ, lCk := i32(), i32(), i32() // lCk: 1 in the pass, which checkpoints
	g.m64, g.k64, g.b64 = i64(), i64(), i64()
	var u8 *utf8StartLocals
	var lInside uint32
	if sw.utf8Start() {
		u8 = &utf8StartLocals{ptr: pPtr, len: pLen, pos: i32(), c: i32(), k: i32(), n: i32()}
		lInside = i32()
	}
	var b []byte
	b = a.EmitDecls(b)
	b = cs.emitSweepArea(b, pLen, g)
	b = append(b, 0x1A) // drop: the caller checked
	b = i32c(b, sw.colA)
	b = lset(b, l.cur)
	b = i32c(b, sw.colB)
	b = lset(b, l.nxt)
	cols := int32(4 * sw.roots) //nolint:gosec // bounded by sweepMaxRoots
	fillNone := func(b []byte) []byte {
		b = lget(b, l.nxt)
		b = i32c(b, -1)
		b = i32c(b, cols)
		return emitMemoryFillMem(b, tm)
	}
	b = append(b, 0x20, pArg, 0x41, 0x00, 0x48, 0x04, 0x40) // arg < 0: if (a block)
	b = append(b, 0x41, 0x7F, 0x20, pArg, 0x6B)             // j = -1 - arg
	b = lset(b, lJ)
	// q = (j + 1) × k: from checkpoint j when q <= len, none past it.
	b = lget(b, lJ)
	b = append(b, 0x41, 0x01, 0x6A)
	b = lget(b, g.k)
	b = append(b, 0x6C)
	b = ltee(b, l.v)
	b = append(b, 0x20, pLen, 0x4D, 0x04, 0x40) // q <= len: if
	b = lget(b, l.nxt)
	b = lget(b, g.area)
	b = i32c(b, ckptHdrBytes)
	b = append(b, 0x6A)
	b = lget(b, lJ)
	b = i32c(b, int32(sw.cellBytes())) //nolint:gosec
	b = append(b, 0x6C, 0x6A)
	b = i32c(b, cols)
	b = emitMemoryCopyMem(b, tm, 0) // to the column, from the caller's region
	b = append(b, 0x05)
	b = fillNone(b)
	b = append(b, 0x0B)
	// The block's last position: min(q, len + 1) - 1; its first: j × k.
	b = lget(b, l.v)
	b = append(b, 0x20, pLen, 0x41, 0x01, 0x6A)
	b = lget(b, l.v)
	b = append(b, 0x20, pLen, 0x41, 0x01, 0x6A)
	b = append(b, 0x49, 0x1B) // lt_u; select: min
	b = append(b, 0x41, 0x01, 0x6B)
	b = lset(b, l.p)
	b = lget(b, lJ)
	b = lget(b, g.k)
	b = append(b, 0x6C)
	b = lset(b, lLo)
	b = append(b, 0x05) // else: the pass, from the end — the column past it is none at all
	b = fillNone(b)
	b = append(b, 0x20, pLen)
	b = lset(b, l.p)
	b = append(b, 0x20, pArg)
	b = lset(b, lLo)
	b = i32c(b, 1)
	b = lset(b, lCk)
	b = append(b, 0x0B)
	b = append(b, 0x02, 0x40, 0x03, 0x40) // block, loop
	b = sw.emitColumnStep(b, tm, l)
	b = sw.emitWriteRow(b, tm, l, u8, lInside, func(b []byte) []byte {
		b = lget(b, g.rows)
		b = lget(b, l.p)
		b = lget(b, g.k)
		b = append(b, 0x70)               // i32.rem_u
		b = i32c(b, int32(sw.rowBytes())) //nolint:gosec
		return append(b, 0x6C, 0x6A)
	})
	// In the pass, a checkpoint: the column at p, when p is a positive
	// multiple of k.
	b = lget(b, lCk)
	b = lget(b, l.p)
	b = lget(b, g.k)
	b = append(b, 0x70, 0x45, 0x71) // p % k == 0; and
	b = lget(b, l.p)
	b = append(b, 0x41, 0x00, 0x47, 0x71, 0x04, 0x40) // && p != 0: if
	b = lget(b, g.area)
	b = i32c(b, ckptHdrBytes)
	b = append(b, 0x6A)
	b = lget(b, l.p)
	b = lget(b, g.k)
	b = append(b, 0x6E, 0x41, 0x01, 0x6B) // p / k - 1
	b = i32c(b, int32(sw.cellBytes()))    //nolint:gosec
	b = append(b, 0x6C, 0x6A)
	b = lget(b, l.cur)
	b = i32c(b, cols)
	b = emitMemoryCopyMem(b, 0, tm) // to the caller's region, from the column
	b = append(b, 0x0B)
	// The column at p becomes the one at p + 1 for the next.
	b = lget(b, l.cur)
	b = lget(b, l.nxt)
	b = lset(b, l.cur)
	b = lset(b, l.nxt)
	b = lget(b, l.p)
	b = lget(b, lLo)
	b = append(b, 0x4D, 0x0D, 0x01) // p <= lo: done
	b = lget(b, l.p)
	b = append(b, 0x41, 0x01, 0x6B)
	b = lset(b, l.p)
	b = append(b, 0x0C, 0x00, 0x0B, 0x0B)
	// The block now in the buffer: j, or the pass's from / k.
	b = append(b, 0x20, pRegion)
	b = lget(b, lCk)
	b = append(b, 0x04, 0x7F) // if (result i32)
	b = lget(b, lLo)
	b = lget(b, g.k)
	b = append(b, 0x6E) // from / k
	b = append(b, 0x05)
	b = lget(b, lJ)
	b = append(b, 0x0B)
	b = append(b, 0x41, 0x01, 0x6A)
	b = st32(b, sweepHdrCurBlock)
	b = i32c(b, 0)
	b = append(b, 0x0B)
	return append(utils.AppendULEB128(nil, uint32(len(b))), b...) //nolint:gosec // a function's size
}

// emitMemoryFillMem is memory.fill on memory mem: (dst, value, n) on the stack.
func emitMemoryFillMem(b []byte, mem int) []byte {
	b = append(b, 0xFC, 0x0B)
	return utils.AppendULEB128(b, uint32(mem)) //nolint:gosec // a memory index
}

// emitMemoryCopyMem is memory.copy from memory src to memory dst: (d, s, n)
// on the stack.
func emitMemoryCopyMem(b []byte, dst, src int) []byte {
	b = append(b, 0xFC, 0x0A)
	b = utils.AppendULEB128(b, uint32(dst))    //nolint:gosec // a memory index
	return utils.AppendULEB128(b, uint32(src)) //nolint:gosec // a memory index
}

// sweepMerge is what the merge wrapper hands a swept member's search.
type sweepMerge struct {
	pPtr, pLen                    byte
	lQ, lSt, lE, lV, lTmp         byte // the merge's own locals
	lRegion, lRegionLen, lLocated byte // the caller's cache region, its length, emitSweepArea done
	g                             sweepGeo
	sweepIdx                      int // emitSweepFnBody's function
}

// emitSweptMember is split member k's search in the merge, when it has a
// program sweep: once the drive has swept, the first s ≥ q whose answer is not
// -1 — none sends the member done with none(b), which branches out of the
// two blocks this opens — and otherwise its ordinary search (search), whose
// walk is charged to the drive's work, sweeping once that passes the bound.
// Either way lSt and lE hold the answer when it falls through.
func (cs *compiledSet) emitSweptMember(b []byte, k int, x sweepMerge, none func([]byte) []byte,
	search func([]byte, func([]byte) []byte) []byte) []byte {
	sw := cs.progSweep
	locate := func(b []byte) []byte {
		// Once per call: where the sweep's part of the region is.
		b = append(b, 0x20, x.lLocated, 0x45, 0x04, 0x40)
		b = cs.emitSweepArea(b, x.pLen, x.g)
		b = append(b, 0x1A) // drop: the caller checked when it swept
		b = append(b, 0x41, 0x01, 0x21, x.lLocated)
		return append(b, 0x0B)
	}
	// Swept: the region is there and its header says so.
	b = append(b, 0x20, x.lRegion, 0x04, 0x7F, 0x20, x.lRegion)
	b = ld32(b, sweepHdrReady)
	b = append(b, 0x05, 0x41, 0x00, 0x0B)
	b = append(b, 0x04, 0x40) // if swept
	b = locate(b)
	b = append(b, 0x02, 0x40) // block $got
	b = append(b, 0x02, 0x40) // block $none
	b = append(b, 0x20, x.lQ, 0x21, x.lSt)
	b = append(b, 0x03, 0x40)                                  // loop $scan
	b = append(b, 0x20, x.lSt, 0x20, x.pLen, 0x4B, 0x0D, 0x01) // s > len: $none
	// The block of s, materialised when it is not the one in the buffer.
	b = append(b, 0x20, x.lSt)
	b = lget(b, x.g.k)
	b = append(b, 0x6E, 0x21, x.lTmp) // j = s / k
	b = append(b, 0x20, x.lRegion)
	b = ld32(b, sweepHdrCurBlock)
	b = append(b, 0x20, x.lTmp, 0x41, 0x01, 0x6A, 0x47, 0x04, 0x40) // != j + 1: if
	b = append(b, 0x20, x.pPtr, 0x20, x.pLen, 0x20, x.lRegion)
	b = append(b, 0x41, 0x7F, 0x20, x.lTmp, 0x6B, 0x10) // -1 - j: block j
	b = utils.AppendULEB128(b, uint32(x.sweepIdx))      //nolint:gosec // a function index
	b = append(b, 0x1A, 0x0B)
	// v = the answer at s.
	b = lget(b, x.g.rows)
	b = append(b, 0x20, x.lSt)
	b = lget(b, x.g.k)
	b = append(b, 0x70)               // s % k
	b = i32c(b, int32(sw.rowBytes())) //nolint:gosec // a row's size
	b = append(b, 0x6C, 0x6A)
	b = append(b, 0x28, 0x02)                               // i32.load (the caller's region)
	b = utils.AppendULEB128(b, uint32(4*sw.slot[k]))        //nolint:gosec // a row offset
	b = append(b, 0x22, x.lE, 0x41, 0x00, 0x4E, 0x0D, 0x02) // v >= 0: $got
	b = append(b, 0x20, x.lSt, 0x41, 0x01, 0x6A, 0x21, x.lSt)
	b = append(b, 0x0C, 0x00, 0x0B) // continue $scan; end loop
	b = append(b, 0x0B)             // end block $none
	b = none(b)
	b = append(b, 0x0B) // end block $got
	b = append(b, 0x05) // else: the member's own search, charged
	charge := func(walked func([]byte) []byte) func([]byte) []byte {
		return func(b []byte) []byte {
			b = append(b, 0x20, x.lRegion, 0x04, 0x40) // a region to keep the work in
			b = append(b, 0x20, x.lRegion, 0x20, x.lRegion)
			b = append(b, 0x29, 0x03) // i64.load
			b = utils.AppendULEB128(b, sweepHdrWork)
			b = walked(b)
			b = append(b, 0xAC, 0x7C) // i64.extend_i32_s; add
			b = st64(b, sweepHdrWork)
			b = append(b, 0x20, x.lRegion, 0x29, 0x03)
			b = utils.AppendULEB128(b, sweepHdrWork)
			b = sw.emitWorkBound(b, x.pLen)
			b = append(b, 0x56, 0x04, 0x40) // work > bound: if
			b = cs.emitSweepArea(b, x.pLen, x.g)
			// …and the region holds the sweep: cacheB + bytes <= its length.
			b = lget(b, x.g.cacheB)
			b = append(b, 0xAD)
			b = lget(b, x.g.b64)
			b = append(b, 0x7C)
			b = append(b, 0x20, x.lRegionLen, 0xAD, 0x58, 0x71) // le_u; and
			b = append(b, 0x04, 0x40)
			b = append(b, 0x41, 0x01, 0x21, x.lLocated)
			b = append(b, 0x20, x.pPtr, 0x20, x.pLen, 0x20, x.lRegion, 0x20, x.lQ, 0x10)
			b = utils.AppendULEB128(b, uint32(x.sweepIdx)) //nolint:gosec // a function index
			b = append(b, 0x1A)
			b = append(b, 0x20, x.lRegion, 0x41, 0x01)
			b = st32(b, sweepHdrReady)
			b = append(b, 0x0B, 0x0B, 0x0B)
			return b
		}
	}
	b = search(b, charge(func(b []byte) []byte { return append(b, 0x20, x.pLen, 0x20, x.lQ, 0x6B) }))
	b = charge(func(b []byte) []byte { return append(b, 0x20, x.lE, 0x20, x.lQ, 0x6B) })(b)
	return append(b, 0x0B) // end if swept
}
