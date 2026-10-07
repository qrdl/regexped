package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// ── The find-from channel ──────────────────────────────
//
// Every exported single-pattern find takes a `from` position, so that
// iterating a pattern over an input re-enters with the WHOLE buffer and a
// start offset instead of a narrowed slice. Narrowing is what makes `\b`,
// `\B`, `(?m:^)` and `(?m:$)` judge the slice edge instead of the real
// neighbouring byte, which is the divergence from Go's regexp this exists to
// remove.
//
// The offset reaches the find body through a module-level mutable i32 GLOBAL
// rather than a third function parameter or a table-memory scratch slot. Both
// alternatives were tried and rejected:
//
//   - A third PARAMETER shifts every local index in the find bodies by one.
//     buildFindBody and buildAnchoredFindBody alone hold 56 hardcoded local
//     references, and there is no test that can prove such a renumbering
//     correct: byteident cannot distinguish a local index from SLEB128 data
//     that happens to hold the same byte.
//
//   - A table-memory SCRATCH SLOT (the shape the groups wrapper once used for its
//     window offsets) has a per-pattern address whose Go zero value — 0 — is a
//     real, writable table offset. That defect landed twice in one attempt.
//     Those window offsets are globals themselves now, for this reason: see
//     compiledPattern.winGlobal.
//
// A global has neither failure mode. The index is a package constant, so
// there is no per-pattern address to forget to initialise, and a body that
// reads the global in a module whose assembler forgot to emit the global
// section does not corrupt anything — it fails WASM VALIDATION, i.e. every
// harness and wasm-tools reject the module at load.
//
// Verified against wasm-merge before any of this was written: a non-exported
// mutable global survives the merge, is renumbered correctly when the main
// module has globals of its own (Rust and Go mains always do), and stays
// independent when several regexp modules are merged into one host.

// findFromGlobalIdx is the index of the find-from global WITHIN a regexp
// module. wasm-merge renumbers it when merging into a host that has globals
// of its own, rewriting every global.get/global.set that refers to it.
const findFromGlobalIdx = 0

// findFromMode records how one pattern's find function receives `from`.
//
// Its zero value is INVALID on purpose. A find function whose mode was never
// set is a missed emitter, and the assemblers panic on it rather than emit a
// module that silently starts every scan at 0 — the failure that sank the
// first attempt at this task, where the symptom was an iteration that never
// terminated instead of a build that stopped.
type findFromMode uint8

const (
	// ffUnset is the zero value: no emitter claimed this find function.
	ffUnset findFromMode = iota

	// ffLegacyNarrow is the original behaviour, moved from the stubs
	// into WASM unchanged: the wrapper hands the body a NARROWED slice and
	// rebases the result. Left-context assertions still judge the slice
	// edge. Every emitter starts here; the mode is retired when the last
	// one is converted, and its absence is then the done criterion.
	ffLegacyNarrow

	// ffNative means the body reads the global and scans the whole buffer
	// from that position, so left context is real. Obtainable only from
	// emitFindFromSeed, which produces it by actually emitting the seed.
	ffNative

	// ffAnchoredZeroOnly means the body can only ever report a match
	// beginning at position 0 (isAnchoredFind), so the wrapper answers
	// "no match" for any from != 0 without calling it at all.
	ffAnchoredZeroOnly

	// ffNativeUTF8 is ffNative for a body that also keeps a Unicode-mode
	// pattern's matches off positions inside a character (startRule):
	// obtainable only from emitFindFromSeedRule, which emits the seed and the
	// rule's rounding of it together.
	ffNativeUTF8
)

func (m findFromMode) String() string {
	switch m {
	case ffLegacyNarrow:
		return "legacy-narrow"
	case ffNative:
		return "native"
	case ffAnchoredZeroOnly:
		return "anchored-zero-only"
	case ffNativeUTF8:
		return "native-utf8"
	}
	return "UNSET"
}

// native reports whether a body in mode m reads the find-from channel and
// scans the whole buffer from it.
func (m findFromMode) native() bool { return m == ffNative || m == ffNativeUTF8 }

// ── Unicode start positions ─────────────────────────────────────────────────
//
// In Unicode mode no match starts, and no empty match is reported, inside a
// character: a position is a start position exactly when Go's decoding
// starts a token there — a valid UTF-8 sequence's first byte, or any byte of
// invalid input, which Go reads as U+FFFD one byte wide. A continuation byte
// is skipped only when the lead byte up to 3 bytes back begins a valid
// sequence that is complete across it.
//
// Which bodies need the rule follows from the lowered program: it consumes
// only whole valid sequences, so a NON-empty match never begins with a
// continuation byte. Only an empty match can sit inside a character, and of
// the assertions only `\B` can hold there (both neighbours are non-word
// bytes; `^ $ \A \z (?m)^ (?m)$` hold only at the input's edges or next to
// `\n`, `\b` never between two non-word bytes). So:
//
//   - a pattern that cannot match empty needs nothing;
//   - one that can, but not through `\B` alone, needs only `from` rounded up
//     to a start position: its empty matches are found where they hold, and
//     they hold only at start positions;
//   - one that can reach an empty match through `\B` with no position-fixing
//     assertion on the way also needs every candidate start checked.
//
// The rule is applied IN the find bodies (the scan loop and the seed), not at
// the entry points: measured 2026-10-05 on `\B` and `a?\B` drives over 64 KB,
// the scan-loop check cost 1-10% less fuel than rounding at the entry points
// and calling a body again after each match inside a character.
type startRule uint8

const (
	// startRuleNone: byte mode, or a pattern that cannot match empty.
	startRuleNone startRule = iota
	// startRuleSeed: round `from` up to a start position.
	startRuleSeed
	// startRuleScan: startRuleSeed, and skip every candidate start that is
	// not a start position.
	startRuleScan
)

// startRuleFor is the rule pattern's find bodies must keep, from its mode
// and its program.
func startRuleFor(pattern resolvedPattern) startRule {
	rule, _, _ := startEmptyMatches(pattern)
	return rule
}

// startEmptyMatches is startRuleFor's rule together with
// emptyMatchesInsideChar's two answers for the pattern's program, from one
// parse and one compile: both false when the rule is startRuleNone.
func startEmptyMatches(pattern resolvedPattern) (rule startRule, anywhere, viaNoWB bool) {
	if !pattern.unicode() {
		return startRuleNone, false, false
	}
	t, err := pattern.parse()
	if err != nil {
		return startRuleNone, false, false
	}
	if minLen, _ := t.minMaxLen(); minLen > 0 {
		return startRuleNone, false, false
	}
	// syntax.Compile never fails on a tree syntax.Parse produced.
	mp, _ := compileProg(t)
	anywhere, viaNoWB = emptyMatchesInsideChar(mp.orig)
	if viaNoWB {
		return startRuleScan, anywhere, viaNoWB
	}
	return startRuleSeed, anywhere, viaNoWB
}

// emptyMatchesInsideChar reports the two ways prog's empty matches can sit
// inside a character: anywhere, an empty path to Match with no assertion that
// fixes the position (`\B` allowed), and viaNoWB, such a path through `\B`.
// Exact: it walks every non-consuming path from the start, carrying the
// assertions seen.
func emptyMatchesInsideChar(prog *syntax.Prog) (anywhere, viaNoWB bool) {
	const fixing = syntax.EmptyBeginLine | syntax.EmptyEndLine | syntax.EmptyBeginText |
		syntax.EmptyEndText | syntax.EmptyWordBoundary
	type node struct {
		pc   uint32
		seen syntax.EmptyOp
	}
	visited := map[node]bool{}
	stack := []node{{uint32(prog.Start), 0}}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n] {
			continue
		}
		visited[n] = true
		in := &prog.Inst[n.pc]
		switch in.Op {
		case syntax.InstMatch:
			if n.seen&fixing == 0 {
				anywhere = true
				if n.seen&syntax.EmptyNoWordBoundary != 0 {
					return true, true
				}
			}
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, node{in.Out, n.seen}, node{in.Arg, n.seen})
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, node{in.Out, n.seen})
		case syntax.InstEmptyWidth:
			stack = append(stack, node{in.Out, n.seen | syntax.EmptyOp(in.Arg)})
		}
	}
	return anywhere, false
}

// setStartNeeds is what a SET member's position bodies need for the start
// rule. A set enumerates candidate starts past `from` — after a gate refuses
// an empty match at one, or at every position when overlapping — so a member
// whose empty match holds anywhere needs every candidate checked in `find`,
// not only the seed. The scan pair answers only whether a member matches, and
// a member whose empty match holds anywhere matches at the next start
// position as surely as inside a character, so there only `\B` counts.
func setStartNeeds(pattern resolvedPattern) (find, scan bool) {
	_, find, scan = startEmptyMatches(pattern)
	return find, scan
}

// utf8StartLocals are the locals emitUTF8Start reads and writes: the input
// (ptr, len), the position it moves, and three i32 scratch locals.
type utf8StartLocals struct {
	ptr, len, pos, c, k, n uint32
}

// emitUTF8Start moves l.pos, when it lies inside a valid UTF-8 sequence of
// the input, to that sequence's end — the next start position — and then
// emits onMove at branch depth 0 of its own block (nil: nothing). A position
// at 0, at or past len, or on a byte that is not a continuation byte is a
// start position, and so is a continuation byte that continues no valid
// sequence, as Go reads it.
//
// About a dozen instructions when pos holds no continuation byte; the lookback
// and the sequence check run only at one. Position 0 needs no test of its own:
// a continuation byte there has no lead before it, and the lookback answers
// "a start position" for it as for any stray continuation byte.
func emitUTF8Start(b []byte, l utf8StartLocals, onMove func([]byte) []byte) []byte {
	get := func(b []byte, x uint32) []byte { return utils.AppendULEB128(append(b, 0x20), x) }
	set := func(b []byte, op byte, x uint32) []byte { return utils.AppendULEB128(append(b, op), x) }
	i32c := func(b []byte, v int32) []byte { return utils.AppendSLEB128(append(b, 0x41), v) }
	// at loads the input byte at pos - k + off (memory 0, the input's).
	at := func(b []byte, off byte) []byte {
		b = get(get(b, l.ptr), l.pos)
		b = append(b, 0x6A)
		b = get(b, l.k)
		return append(b, 0x6B, 0x2D, 0x00, off)
	}
	isCont := func(b []byte) []byte { // (top & 0xC0) == 0x80
		b = i32c(b, 0xC0)
		b = append(b, 0x71)
		b = i32c(b, 0x80)
		return append(b, 0x46)
	}
	eqC := func(b []byte, v int32) []byte { return append(i32c(get(b, l.c), v), 0x46) }

	b = append(b, 0x02, 0x40) // block $done
	b = get(get(b, l.pos), l.len)
	b = append(b, 0x4F, 0x0D, 0x00) // pos >= len → a start position
	b = get(get(b, l.ptr), l.pos)
	b = append(b, 0x6A, 0x2D, 0x00, 0x00)
	b = isCont(b)
	b = append(b, 0x45, 0x0D, 0x00) // not a continuation byte → a start position

	// The lead byte: the first non-continuation byte up to 3 back.
	b = set(i32c(b, 1), 0x21, l.k)
	b = append(b, 0x02, 0x40, 0x03, 0x40) // block $found, loop $back
	b = get(get(b, l.k), l.pos)
	b = append(b, 0x4B, 0x0D, 0x02) // k > pos: no lead → stray → done
	b = at(b, 0)
	b = set(b, 0x22, l.c)
	b = isCont(b)
	b = append(b, 0x45, 0x0D, 0x01) // a lead candidate → $found
	b = get(b, l.k)
	b = append(b, 0x41, 0x01, 0x6A)
	b = set(b, 0x22, l.k)
	b = append(b, 0x41, 0x03, 0x4D, 0x0D, 0x00) // k <= 3 → $back
	b = append(b, 0x0C, 0x02)                   // four continuations → stray → done
	b = append(b, 0x0B, 0x0B)                   // end $back, end $found

	// c is the byte at pos - k. A valid lead is 0xC2..0xF4; its sequence is
	// n = 2, 3 or 4 bytes, and must reach past pos and end within the input.
	b = i32c(get(b, l.c), 0xC2)
	b = append(b, 0x49, 0x0D, 0x00) // c < 0xC2 → done
	b = i32c(get(b, l.c), 0xF5)
	b = append(b, 0x4F, 0x0D, 0x00) // c >= 0xF5 → done
	b = i32c(get(i32c(b, 2), l.c), 0xE0)
	b = append(b, 0x4F, 0x6A)
	b = i32c(get(b, l.c), 0xF0)
	b = append(b, 0x4F, 0x6A)
	b = set(b, 0x21, l.n)
	b = get(get(b, l.n), l.k)
	b = append(b, 0x4D, 0x0D, 0x00) // n <= k: the sequence ends before pos → done
	b = get(get(b, l.pos), l.k)
	b = append(b, 0x6B)
	b = get(b, l.n)
	b = append(b, 0x6A)
	b = get(b, l.len)
	b = append(b, 0x4B, 0x0D, 0x00) // cut off by the end of the input → done

	// The second byte's range depends on the lead (no overlong encoding, no
	// surrogate, nothing past U+10FFFF): (byte - lo) u> (hi - lo) → done.
	b = at(b, 1)
	b = i32c(b, 0xA0)
	b = i32c(b, 0x90)
	b = i32c(b, 0x80)
	b = append(eqC(b, 0xF0), 0x1B)
	b = append(eqC(b, 0xE0), 0x1B, 0x6B) // byte - lo
	b = i32c(b, 0x1F)
	b = i32c(b, 0x2F)
	b = i32c(b, 0x0F)
	b = i32c(b, 0x3F)
	b = append(eqC(b, 0xF4), 0x1B)
	b = append(eqC(b, 0xF0), 0x1B)
	b = eqC(eqC(b, 0xE0), 0xED)
	b = append(b, 0x72, 0x1B)       // or, select → hi - lo
	b = append(b, 0x4B, 0x0D, 0x00) // out of range → done
	for j := byte(2); j <= 3; j++ {
		b = i32c(get(b, l.n), int32(j))
		b = append(b, 0x4B, 0x04, 0x40) // if n > j
		b = isCont(at(b, j))
		b = append(b, 0x45, 0x0D, 0x01, 0x0B) // not a continuation → done; end if
	}
	b = get(get(b, l.pos), l.k)
	b = append(b, 0x6B)
	b = get(b, l.n)
	b = append(b, 0x6A)
	b = set(b, 0x21, l.pos) // pos = the sequence's end
	if onMove != nil {
		b = onMove(b)
	}
	return append(b, 0x0B) // end $done
}

// emitFindFromSeedRule is emitFindFromSeed for a body that keeps rule, and
// returns ffNativeUTF8 for any rule but startRuleNone, so a body's mode says
// which it keeps. Under startRuleSeed the seed is rounded up to a start
// position here. Under startRuleScan it is not: the caller checks every
// candidate start, and the seed is the first of them — rounding it as well
// cost `\B` 10% more fuel over 4 KB of prose, all of it a second check of
// the same position.
func emitFindFromSeedRule(b []byte, cur scanCursor, rule startRule, l utf8StartLocals) ([]byte, findFromMode) {
	b, mode := emitFindFromSeed(b, cur)
	switch rule {
	case startRuleNone:
		return b, mode
	case startRuleSeed:
		l.pos = uint32(cur.Local())
		b = emitUTF8Start(b, l, nil)
	}
	return b, ffNativeUTF8
}

// checkStartRule panics when a pattern's find body does not keep the start
// rule the pattern needs, or keeps one it does not: a body that matches only
// at position 0 needs none.
func checkStartRule(rule startRule, mode findFromMode) {
	switch {
	case mode == ffAnchoredZeroOnly:
	case rule == startRuleNone && mode == ffNativeUTF8:
		panic("compile: a find body keeps a Unicode start rule its pattern does not need")
	case rule != startRuleNone && mode != ffNativeUTF8:
		panic("compile: a Unicode-mode pattern that can match empty has a find body (" + mode.String() +
			") that does not keep its matches off positions inside a character (see startRule)")
	}
}

// emitFindFromSeed appends the two instructions that load the find-from
// global into a find body's SCAN CURSOR, and returns ffNative.
//
// This is the ONLY producer of ffNative, and it returns the mode rather than
// letting the caller assert it: a body is native exactly when it carries this
// seed.
//
// # Why the parameter is a scanCursor and not a local index
//
// It used to take a byte, and "which local is this body's scan start" was then
// one fact per emitter that nothing could check — stated in a const block,
// consumed here, never reconciled. WASM locals are zero-initialised, so naming
// the wrong one yields a module that validates, answers `from == 0` correctly,
// and ignores `from` for ever after; ffNative is returned either way, so the
// mode is no evidence. That defect shipped twice, most recently in
// buildLitChainAltLenientFindBody, whose attempt-start local is DERIVED from
// its window base rather than being the cursor — every exported find returned
// the first match in the buffer, and hosts iterating it never terminated.
//
// A scanCursor comes only from localAlloc.scanCursor(), so the body must
// decide which of its locals is the cursor at the point it allocates them, and
// can then hand that same value to both its scan and this seed. Passing some
// other local is no longer expressible: ordinary locals are bytes, and a byte
// is not a scanCursor.
//
// Placement: immediately after the locals declaration, before the prologue
// that reads the cursor.
func emitFindFromSeed(b []byte, cur scanCursor) ([]byte, findFromMode) {
	b = append(b, 0x23) // global.get
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = append(b, 0x21)
	// LEB128, not a raw byte. Local indices above 0x7F need a continuation
	// byte, and writing one raw produced a truncated index the validator
	// accepts as a DIFFERENT local. No emitter is near 128 locals today, which
	// is exactly why this would be found late.
	b = utils.AppendULEB128(b, uint32(cur.Local()))
	return b, ffNative
}

// emitFindFromSet appends `global.set find_from, <local>`.
func emitFindFromSet(b []byte, srcLocal byte) []byte {
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, uint32(srcLocal)) // local.get src — see emitFindFromSeed
	b = append(b, 0x24)                          // global.set
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	return b
}

// findFromGlobalSection returns the WASM global section payload declaring the
// single mutable i32 find-from global, initialised to 0.
//
// Equivalent to (&moduleGlobals{}).Section(); kept as the name the assemblers
// used before there was an allocator, and as the fixed point the allocator's
// zero value has to reproduce.
func findFromGlobalSection() []byte {
	return (&moduleGlobals{}).Section()
}

// moduleGlobals allocates a regexp module's mutable i32 globals.
//
// Global 0 is always the find-from channel (findFromGlobalIdx); everything
// after it is handed out by Alloc. The zero value therefore describes exactly
// the module shape that existed before this type — one global — and its
// Section() is byte-for-byte what findFromGlobalSection used to return
// literally, which is what lets the allocator be introduced without moving a
// single fixture.
//
// # Why an allocator rather than more consts
//
// The alternative is what the rest of the compiler does for table memory: a
// per-pattern OFFSET computed by arithmetic and stored in a field. That shape
// has a defect class attached to it — the field's Go zero value, 0, is itself a
// valid writable address, so an emitter that forgets to set it corrupts memory
// instead of failing. See this file's header on why the find-from offset is a
// global at all. Two scratch slots still carry that
// hazard.
//
// An index from Alloc has no such failure mode. Every index it returns is
// backed by a declaration in Section(), because both come from the same
// counter; and a body that reads a global the assembler never declared fails
// WASM validation at load rather than reading something else's value.
//
// # Scope and lifetime
//
// One instance per MODULE, threaded through the compile options so that every
// pattern in a module draws from the same counter, and handed to the assembler
// so the declarations match the uses. A global is module-scoped state shared by
// every call into the instance: fine for a performance verdict, wrong for
// anything a correct answer depends on.
type moduleGlobals struct {
	// extra counts globals allocated BEYOND the find-from channel, so the
	// zero value means "just find-from" and needs no constructor.
	extra uint32
	// inits holds a non-zero initialiser for an allocated global, keyed by its
	// index. Absent means zero, which is what every global was before the
	// component allocator needed a heap pointer starting at the static top.
	inits map[uint32]int32
	// btScratchP1 is btScratch.host + 1, or 0 while no Backtracking fallback
	// body has asked for its scratch globals.
	btScratchP1 uint32
	// searchP1 is the search global + 1 (search_notes.go), or 0 while no body
	// has asked for it.
	searchP1 uint32
	// i64 marks the globals AllocI64 made, with their initial values. Every
	// other global is an i32.
	i64 map[uint32]int64
}

// btScratch names the two globals a Backtracking FALLBACK body finds its
// run-time memory through — its frame stack and its memo, both sized from the
// input at call time. See emitBTScratchInit for how a body uses them.
type btScratch struct {
	// host is the lowest address the host lets the fallback use, or 0 when the
	// host has said nothing. Its meaning and initial value are settled by the
	// assembler, per output kind: exported as abi.ScratchBaseExport and 0 in a
	// standalone module; the end of the tables in an embedded one, whose memory
	// nothing else touches; the allocator's heap top in a component.
	host uint32
	// floor is the end of the module's own tables, which no host value may
	// place the scratch below.
	floor uint32
	// An EMBEDDED build keeps a tripped search's memo in the INPUT's memory
	// (the host's: the stub allocates it), while the fallback's own region —
	// frame stack, a per-call memo — is in the table memory. A memory index is
	// an immediate, so the fallback FIND is emitted twice there: searchTwin
	// marks the per-call body, which hands a call whose search has a usable
	// memo to the function right after it; memoInInput marks that body, which
	// reads and writes the memo in memory 0. Neither is set elsewhere.
	searchTwin, memoInInput bool
	// drive is set for a body that runs inside a SET whose Backtracking
	// members keep their fallback regions for the whole host call
	// (btDriveMember): such a body's scratch starts above the last region
	// placed in the current call, never at the base, which would put a frame
	// stack over a member's live memo. nil everywhere else.
	drive *btDrive
}

// BTScratch returns the module's fallback-scratch globals, allocating them on
// the first call. One pair per module: every fallback body shares it, and at
// most one body runs at a time.
func (g *moduleGlobals) BTScratch() btScratch {
	if g.btScratchP1 == 0 {
		host := g.Alloc()
		g.Alloc() // floor, at host+1
		g.btScratchP1 = host + 1
	}
	return btScratch{host: g.btScratchP1 - 1, floor: g.btScratchP1}
}

// btScratchGlobals reports the fallback-scratch pair, if some body allocated it.
func (g *moduleGlobals) btScratchGlobals() (btScratch, bool) {
	if g == nil || g.btScratchP1 == 0 {
		return btScratch{}, false
	}
	return btScratch{host: g.btScratchP1 - 1, floor: g.btScratchP1}, true
}

// setInit gives an already allocated global a non-zero initialiser. For the
// values only the assembler knows, such as the static top.
func (g *moduleGlobals) setInit(idx uint32, init int32) {
	if g.inits == nil {
		g.inits = map[uint32]int32{}
	}
	g.inits[idx] = init
}

// Alloc reserves one more mutable i32 global, initialised to 0, and returns its
// index. Indices are stable in allocation order and start above
// findFromGlobalIdx.
func (g *moduleGlobals) Alloc() uint32 {
	g.extra++
	return findFromGlobalIdx + g.extra
}

// AllocInit is Alloc with a non-zero initial value.
func (g *moduleGlobals) AllocInit(init int32) uint32 {
	idx := g.Alloc()
	if init != 0 {
		if g.inits == nil {
			g.inits = map[uint32]int32{}
		}
		g.inits[idx] = init
	}
	return idx
}

// AllocI64 reserves one more mutable i64 global with the given initial value
// and returns its index, from the same index space as Alloc.
func (g *moduleGlobals) AllocI64(init int64) uint32 {
	idx := g.Alloc()
	if g.i64 == nil {
		g.i64 = map[uint32]int64{}
	}
	g.i64[idx] = init
	return idx
}

// Count is the number of globals Section will declare.
func (g *moduleGlobals) Count() uint32 { return 1 + g.extra }

// Section returns the WASM global section payload: Count() mutable globals, i32
// unless AllocI64 made them, each with its initial value (0 unless set).
//
// The assemblers gate this on the module needing globals at all
// (moduleUsesFindFrom, plus any allocation). A module that declares the section
// when nothing reads it is merely six bytes larger; a module that OMITS it
// while a body reads one does not validate, which is the direction this is
// deliberately wrong in.
func (g *moduleGlobals) Section() []byte {
	n := g.Count()
	out := utils.AppendULEB128(nil, n)
	for i := uint32(0); i < n; i++ {
		if init, ok := g.i64[i]; ok {
			out = append(out, 0x7E, 0x01) // mut i64
			out = append(out, 0x42)       // i64.const
			out = utils.AppendSLEB128_64(out, init)
			out = append(out, 0x0B) // end of init expr
			continue
		}
		out = append(out, 0x7F, 0x01) // mut i32
		out = append(out, 0x41)       // i32.const
		out = utils.AppendSLEB128(out, g.inits[i])
		out = append(out, 0x0B) // end of init expr
	}
	return out
}

// buildFindFromWrapperBody emits the exported find function:
//
//	(ptr i32, len i32, from i32) → i64
//
// It is a separate function from the find body on purpose. The body keeps its
// (ptr, len) signature so that its local indices — which are hardcoded by the
// hundred across the emitters — do not move.
//
// Every mode returns the same thing for from == 0, which is what makes the
// ABI flip separable from the semantic fix: narrowing by zero is a no-op, so
// switching the export to this wrapper while every pattern is still
// ffLegacyNarrow cannot change any answer anywhere.
//
// def, when non-nil, is the export's default search state for a caller that
// hands no block over (default_search.go); only an ffNative find has one.
func buildFindFromWrapperBody(findFuncIdx int, mode findFromMode, minLen int32, def *defaultSearch) []byte {
	var b []byte

	switch {
	case def != nil && mode.native():
		// Locals 3, 4, 5: i32 area and scratch; 6, 7: i64 sizes; 8: i64 r.
		b = append(b, 0x02, 0x03, 0x7F, 0x03, 0x7E)
	case def != nil:
		panic("compile: a default search state on a " + mode.String() + " find")
	case mode == ffLegacyNarrow:
		b = append(b, 0x01, 0x01, 0x7E) // one i64 local: r (local 3)
	case mode.native(), mode == ffAnchoredZeroOnly:
		b = append(b, 0x00) // no locals
	default:
		panic("compile: buildFindFromWrapperBody with " + mode.String() + " mode")
	}

	if mode == ffAnchoredZeroOnly {
		// The body's automaton cannot reach an accepting state from any
		// start position but 0 (isAnchoredFind), so a from > 0 search has
		// no match to find and the body is not called at all. This also
		// covers from > len.
		b = append(b, 0x20, 0x02) // local.get from
		b = append(b, 0x04, 0x40) // if (void)  — from != 0
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
		b = append(b, 0x20, 0x00, 0x20, 0x01)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end function
		return b
	}

	// from > len: nothing to search. Note `from == len` is NOT rejected —
	// an empty match at the very end of the input is a real result Go
	// reports, and the iteration loops depend on the final from == len
	// call happening.
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// len - from < minLen: the remainder is shorter than anything this pattern
	// can match, so there is nothing to scan. Exact at every length —
	// minMaxLen is a true lower bound, and already load-bearing for
	// lmBareShuftiEligible, lit-anchor and set analysis.
	//
	// Emitted HERE rather than in each find body because this wrapper fronts
	// every one of them: one site covers the general DFA, lit-anchor, alt-lit,
	// counted-chain and Backtracking find paths alike. The subtraction is safe
	// because `from > len` has already returned above.
	//
	// Costs 6 fuel on a call that does not take it. Two families already carry
	// their own length exits and do not need this one, but they are cheap to
	// leave alone: the literal-chain match body (engine_compiled_dfa.go) is not
	// a find, and the counted-chain family's exit is inside its body, past this
	// wrapper.
	if minLen > 1 {
		b = append(b, 0x20, 0x01) // local.get len
		b = append(b, 0x20, 0x02) // local.get from
		b = append(b, 0x6B)       // i32.sub
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, minLen)
		b = append(b, 0x49)       // i32.lt_u
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	}

	if mode.native() && def != nil {
		l := defLocals{a: 3, t: 4, s: 5, n: 6, n2: 7}
		b = def.emitEnter(b, 0, 1, 2, l)
		b = emitFindFromSet(b, 0x02)          // find_from = from
		b = append(b, 0x20, 0x00, 0x20, 0x01) // ptr, len — the WHOLE buffer
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x22, 0x08) // local.tee r: the result
		b = def.emitFindWindow(b, l, 8)
		return append(b, 0x0B) // end function
	}
	if mode.native() {
		b = emitFindFromSet(b, 0x02)          // find_from = from
		b = append(b, 0x20, 0x00, 0x20, 0x01) // ptr, len — the WHOLE buffer
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end function; positions are already absolute
		return b
	}

	// ffLegacyNarrow: reproduce, inside WASM, exactly what the generated
	// stubs used to do host-side — call the body on input[from:] and shift
	// the returned pair back up by `from`.
	b = append(b, 0x20, 0x00, 0x20, 0x02, 0x6A) // ptr + from
	b = append(b, 0x20, 0x01, 0x20, 0x02, 0x6B) // len - from
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x21, 0x03) // local.set r

	// Negative returns are status codes, not positions: -1 is "no match"
	// and anything below it is a BT stack overflow the host must see
	// unmodified. Rebasing them would turn an overflow into a position.
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x42, 0x00) // i64.const 0
	b = append(b, 0x53)       // i64.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// r + ((from << 32) | from) — adds `from` to both halves at once. The
	// low half cannot carry into the high half: relEnd <= len - from, so
	// relEnd + from <= len, and len is an i32 count of addressable bytes.
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x84)       // i64.or
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x0B)       // end function
	return b
}

// appendFindFromWrapperCodeEntry appends a size-prefixed find wrapper body.
func appendFindFromWrapperCodeEntry(cs []byte, findFuncIdx int, mode findFromMode, minLen int32, def *defaultSearch) []byte {
	body := buildFindFromWrapperBody(findFuncIdx, mode, minLen, def)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// moduleUsesFindFrom reports whether any function in the module touches the
// find-from channel, and therefore whether the assemblers must declare the
// global.
//
// It is not simply "does any pattern have a find function". A groups-only
// pattern on a lit-chain A.3 path has none at all, yet its capture body reads
// the channel (it SCANS) and its exported wrapper writes it.
// Declaring the global is what keeps that pairing a load-time WASM validation
// question rather than a silent read of the wrong thing.
func moduleUsesFindFrom(patterns []*compiledPattern) bool {
	for _, p := range patterns {
		if p.hasFindFunc() {
			return true
		}
		// The anchored-zero-only groups wrapper answers from != 0 itself and
		// never touches the channel; every other groups wrapper writes it.
		if p.hasGroupsFromWrapper() && p.captureFromMode != ffAnchoredZeroOnly {
			return true
		}
	}
	return false
}

// emitFindCallFromPos emits `rLocal = find(...)` starting the search at
// posLocal, for either mode, in a wrapper whose params are (ptr=0, len=1, ...).
//
// Shared by the batch find and batch groups wrappers because getting the two
// modes' calling conventions subtly different between them is exactly the kind
// of divergence that would show up as one export disagreeing with the other.
func emitFindCallFromPos(b []byte, findFuncIdx int, mode findFromMode, posLocal, rLocal byte) []byte {
	if mode == ffAnchoredZeroOnly {
		// This body reports only matches beginning at 0 and ignores the
		// channel entirely, so a resumed call at pos > 0 must NOT reach it:
		// it would hand back the same position-0 match again, and the caller
		// would either report it forever or compute a negative relative
		// offset from it. Answer "no match" without calling, exactly as the
		// exported wrapper does.
		b = append(b, 0x20, posLocal) // local.get pos
		b = append(b, 0x04, 0x7E)     // if (result i64) — pos != 0
		b = append(b, 0x42, 0x7F)     // i64.const -1
		b = append(b, 0x05)           // else
		b = append(b, 0x20, 0x00, 0x20, 0x01)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end if
		return append(b, 0x21, rLocal)
	}
	if mode == ffLegacyNarrow {
		// The body cannot be told where to start, so it is handed a slice
		// that begins there. Results come back relative to pos.
		b = append(b, 0x20, 0x00, 0x20, posLocal, 0x6A) // ptr + pos
		b = append(b, 0x20, 0x01, 0x20, posLocal, 0x6B) // len - pos
	} else {
		// The body reads the channel, so it gets the whole buffer and the
		// position. Results come back ABSOLUTE.
		b = emitFindFromSet(b, posLocal)
		b = append(b, 0x20, 0x00, 0x20, 0x01)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	return append(b, 0x21, rLocal)
}

// emitUnpackRelative unpacks the packed (start<<32|end) in rLocal into two
// i32 locals expressed RELATIVE to posLocal, whichever way the body reported
// them. Both batch wrappers' downstream code — the advance rule, the absolute
// positions it stores, the empty-match test — is written in those terms, so
// normalising here leaves all of it untouched by the mode.
func emitUnpackRelative(b []byte, mode findFromMode, rLocal, posLocal, relStartLocal, relEndLocal byte) []byte {
	b = append(b, 0x20, rLocal, 0x42, 0x20, 0x88, 0xA7) // wrap(r >> 32u)
	if mode != ffLegacyNarrow {
		b = append(b, 0x20, posLocal, 0x6B) // − pos
	}
	b = append(b, 0x21, relStartLocal)
	b = append(b, 0x20, rLocal, 0xA7) // wrap(r)
	if mode != ffLegacyNarrow {
		b = append(b, 0x20, posLocal, 0x6B) // − pos
	}
	return append(b, 0x21, relEndLocal)
}

// anyGroupsExport reports whether any pattern exports groups or named groups,
// and therefore whether the module needs the 4-argument groups type.
func anyGroupsExport(patterns []*compiledPattern) bool {
	for _, p := range patterns {
		if p.groupsExport != "" {
			return true
		}
	}
	return false
}

// buildGroupsFromWrapperBody emits the exported groups / named_groups
// function:
//
//	(ptr i32, len i32, out_ptr i32, from i32) → i32
//
// Like the find wrapper, this is a separate function rather than an extra
// parameter on the body it fronts: the non-anchored groups wrapper and the
// capture bodies keep their 3-argument signature and their local indices.
//
// anchoredOnly is for the case where the export IS captureBody — a pattern
// anchored at 0. Such a body can only report a match beginning at 0, so any
// from != 0 is answered "no match" without calling it. That case cannot be
// handled by seeding the channel, because captureBody does not read it.
//
// def, when non-nil, is the export's default search state (default_search.go);
// an anchored-only wrapper, one call per drive, has none.
func buildGroupsFromWrapperBody(innerFuncIdx int, anchoredOnly bool, def *defaultSearch) []byte {
	var b []byte
	if def != nil {
		if anchoredOnly {
			panic("compile: a default search state on an anchored-only groups wrapper")
		}
		// Locals 4, 5, 6: i32 area and scratch; 7, 8: i64 sizes; 9: i32 r.
		b = append(b, 0x03, 0x03, 0x7F, 0x02, 0x7E, 0x01, 0x7F)
		l := defLocals{a: 4, t: 5, s: 6, n: 7, n2: 8}
		b = append(b, 0x20, 0x03, 0x20, 0x01, 0x4B) // from > len (u)
		b = append(b, 0x04, 0x40, 0x41, 0x7F, 0x0F, 0x0B)
		b = def.emitEnter(b, 0, 1, 3, l)
		b = emitFindFromSet(b, 0x03)
		b = append(b, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02) // ptr, len, out_ptr
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(innerFuncIdx))
		b = append(b, 0x22, 0x09) // local.tee r: the result
		// The window from the match's group-0 slots: [start, end + 1].
		b = def.emitWindow(b, l,
			func(b []byte) []byte { return append(b, 0x20, 0x09, 0x41, 0x00, 0x4E) }, // r >= 0
			func(b []byte) []byte { return append(b, 0x20, 0x02, 0x28, 0x02, 0x00) },
			func(b []byte) []byte { return append(b, 0x20, 0x02, 0x28, 0x02, 0x04, 0x41, 0x01, 0x6A) })
		return append(b, 0x0B)
	}
	b = append(b, 0x00) // no locals

	if anchoredOnly {
		b = append(b, 0x20, 0x03) // local.get from
		b = append(b, 0x04, 0x40) // if (void) — from != 0
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	} else {
		// from > len: nothing to search. from == len is NOT rejected — an
		// empty match at end of input is a real result.
		b = append(b, 0x20, 0x03, 0x20, 0x01, 0x4B) // from > len (u)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)
		// The inner wrapper runs a find to locate the match; tell it where to
		// start. This is the ONLY writer of the channel on the groups path.
		b = emitFindFromSet(b, 0x03)
	}

	b = append(b, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02) // ptr, len, out_ptr
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerFuncIdx))
	b = append(b, 0x0B) // end function
	return b
}

// appendGroupsFromWrapperCodeEntry appends a size-prefixed groups-from wrapper.
func appendGroupsFromWrapperCodeEntry(cs []byte, innerFuncIdx int, anchoredOnly bool, def *defaultSearch) []byte {
	body := buildGroupsFromWrapperBody(innerFuncIdx, anchoredOnly, def)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// assertGroupsFromWrapperMode enforces the one precondition the non-anchored
// groups-from wrapper has and cannot check for itself.
//
// The wrapper writes the find-from channel and then calls the composed
// (find, capture) wrapper, which calls the find BODY with the whole
// (ptr, len). That is correct only for an ffNative body — one that reads the
// channel. An ffLegacyNarrow body ignores it and scans from 0, so
// groups(from > 0) would report a match BEFORE `from` with no error anywhere:
// "wrong-but-safe" for the find export (whose wrapper narrows and rebases)
// is plain wrong for groups.
//
// buildFindBody has a documented ffLegacyNarrow fallback. Today every emitter
// returns ffNative, so this never fires — but the whole point of the mode
// machinery is that a missed emitter is a BUILD failure (see the findFromMode
// doc above), and this is exactly the hole where the failure would otherwise
// be silent wrong answers.
func assertGroupsFromWrapperMode(p *compiledPattern, anchoredOnly bool) {
	if anchoredOnly {
		// The export IS captureBody; the channel is not consulted at all.
		return
	}
	mode, what := p.findFromMode, "find body"
	if p.anchored {
		// captureBody IS the export; the channel reaches it directly.
		mode, what = p.captureFromMode, "capture body"
	}
	if !mode.native() {
		panic("compile: pattern exports groups over a non-native " + what +
			" (findFromMode " + mode.String() + ") — the groups-from wrapper " +
			"seeds the find-from channel, which only an ffNative body reads " +
			"(see find_from.go)")
	}
	checkStartRule(p.startRule, mode)
}
