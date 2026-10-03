package compile

import (
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ── The module's own search state, for callers that hand none over ─────────
//
// A generated stub gives every drive a per-search block (search_notes.go) —
// and a set's drive its blocks and answer cache — and allocates notes and a
// Backtracking memo when the module asks. A caller that drives the raw ABI
// and hands nothing over got the quadratic drives those exist to prevent:
// `a*b|a` over `a`×8 K 135,303 fuel/byte (×4 per doubling) with no block, 401
// with one.
//
// So a STANDALONE module keeps a default of its own for each export that uses
// state, in memory it grows itself, and uses it only when the caller hands
// nothing over: the search global is 0 — the module puts it back to 0 after a
// call that used the default — or a set's descriptor carries the plain magic
// and offers no cache. Each default lives in an AREA grown on its first use; notes, a memo
// and a cache are grown when first needed and REUSED by later drives (grown
// again, to at least twice the size, only when a drive needs more), so the
// memory a long-lived instance holds is bounded by twice its largest drive's.
// The scratch floor — the lowest address the Backtracking fallback may place
// its frame stack at — is raised past every grown region, so the fallback
// never runs over them whatever the host sets its scratch base to.
//
// One default serves one drive at a time. Its state is reset whenever a call
// is not the CONTINUATION of the previous one: a pattern's export keeps the
// previous answer's window ([start, end + 1] for find and groups, the next
// position for a batch call) and the text's address and length; a set keeps
// the text and the gate array and requires `from` (or the batch cursor) to
// have advanced. A caller that rewrites its text in place and resumes inside
// that window reads the previous text's state — the hazard a stub's iterator
// has over a text changed mid-scan.
//
// Embedded (merged) builds get none of this: their input memory is the
// host's, which the module cannot grow safely, and a second copy of every
// body that reads the state from the module's own memory measured +10% to
// +43% module size. A component needs none: its resources keep their state.
//
// The cost to a caller that DOES hand its state over is the test at entry and
// the window's bookkeeping: ~1-9 fuel per call (+0.07% on a Backtracking drive,
// +2.2% on a find drive making one call per byte).

// Offsets in a pattern export's default area: the search block, then the
// module's own record.
const (
	defLive       = abi.SearchBlockBytes // i32: a drive is in flight
	defPtr        = defLive + 4          // i32: its text
	defLen        = defLive + 8          // i32
	defLo         = defLive + 12         // i32: where it may continue from…
	defHi         = defLive + 16         // i32: …up to here
	defMemo       = defLive + 20         // i32: the memo region kept across drives
	defMemoCap    = defLive + 24         // i32
	defAreaBytes  = defLive + 28
	defPageBytes  = 1 << 16
	defMaxGrowEnd = btScratchMaxEnd // the highest end a grown region may reach
)

// defaultSearch is one pattern export's default.
type defaultSearch struct {
	m     *defaultModule
	area  uint32 // global: the area's address, 0 until first use
	notes int32  // notes bytes per position, 0 for none
	memo  int32  // memo bytes per position, 0 for none
	batch bool   // a batch export: its call runs many finds, so notes up front
}

// defaultModule is what every default in a module shares.
type defaultModule struct {
	globals   *moduleGlobals
	search    uint32 // the search global…
	hasSearch bool   // …when some export uses a search block
	floor     uint32 // the fallback scratch's floor global…
	hasFloor  bool   // …when the module has one
}

// newDefaultModule is the module's shared default state, nil when it gets
// none: not standalone, or a component.
func newDefaultModule(globals *moduleGlobals, standalone, component bool) *defaultModule {
	if !standalone || component || globals == nil {
		return nil
	}
	m := &defaultModule{globals: globals}
	if g, ok := globals.searchGlobal(); ok {
		m.search, m.hasSearch = g, true
	}
	if sc, ok := globals.btScratchGlobals(); ok {
		m.floor, m.hasFloor = sc.floor, true
	}
	return m
}

// forPattern is p's default for one of its exports, nil when the export keeps
// no state (or the module gets none).
func (m *defaultModule) forPattern(p *compiledPattern, batch bool) *defaultSearch {
	if m == nil || !m.hasSearch {
		return nil
	}
	notes := p.notes.bytesPerPos()
	if notes == 0 && !p.btSearch {
		return nil
	}
	return &defaultSearch{m: m, area: m.globals.AllocInit(0), notes: notes, memo: int32(p.btMemoBytes), batch: batch} //nolint:gosec // bytes per position
}

// assignDefaults gives every pattern export and set that keeps state its
// default. m nil (no defaults in this module) clears nothing and assigns none.
func assignDefaults(m *defaultModule, patterns []*compiledPattern, sets []*compiledSet) {
	if m == nil {
		return
	}
	for _, p := range patterns {
		if p.hasFindFunc() && p.findFromMode == ffNative {
			p.defFind = m.forPattern(p, false)
		}
		if p.hasGroupsFromWrapper() && (!p.anchored || p.captureFromMode != ffAnchoredZeroOnly) {
			p.defGroups = m.forPattern(p, false)
		}
		if p.batchFindExport != "" {
			p.defBatchFind = m.forPattern(p, true)
		}
		if p.batchGroupsExport != "" && !p.anchored {
			p.defBatchGroups = m.forPattern(p, true)
		}
	}
	for _, cs := range sets {
		cs.def = m.forSet(cs)
	}
}

// defLocals are the locals a default's entry and exit use.
type defLocals struct {
	a    uint32 // i32: the area, 0 when the default is not in use
	t, s uint32 // i32 scratch
	n    uint32 // i64: a size
	n2   uint32 // i64 scratch
	// m, k, b2: i64 scratch for a set's cache sizing (emitCkptSizing), st
	// the cache's stride; unused by a pattern's default.
	m, k, b2 uint32
	st       uint32
}

func lget(b []byte, l uint32) []byte   { return utils.AppendULEB128(append(b, 0x20), l) }
func lset(b []byte, l uint32) []byte   { return utils.AppendULEB128(append(b, 0x21), l) }
func ltee(b []byte, l uint32) []byte   { return utils.AppendULEB128(append(b, 0x22), l) }
func gget(b []byte, g uint32) []byte   { return utils.AppendULEB128(append(b, 0x23), g) }
func gset(b []byte, g uint32) []byte   { return utils.AppendULEB128(append(b, 0x24), g) }
func i32c(b []byte, v int32) []byte    { return utils.AppendSLEB128(append(b, 0x41), v) }
func i64c(b []byte, v int64) []byte    { return utils.AppendSLEB128_64(append(b, 0x42), v) }
func ld32(b []byte, off uint32) []byte { return utils.AppendULEB128(append(b, 0x28, 0x02), off) }
func st32(b []byte, off uint32) []byte { return utils.AppendULEB128(append(b, 0x36, 0x02), off) }
func st64(b []byte, off uint32) []byte { return utils.AppendULEB128(append(b, 0x37, 0x03), off) }

// emitGrow grows memory 0 by the bytes in the i64 local n, rounded up to
// pages, and leaves the first new byte's address in the i32 local out — 0 when
// memory cannot grow (or the region would pass defMaxGrowEnd): the caller then
// runs without it. The scratch floor is raised past the new end.
func (m *defaultModule) emitGrow(b []byte, n, out uint32) []byte {
	b = lget(b, n)
	b = i64c(b, defMaxGrowEnd)
	b = append(b, 0x56, 0x04, 0x40) // i64.gt_u; if
	b = i32c(b, 0)
	b = lset(b, out)
	b = append(b, 0x05) // else
	b = lget(b, n)
	b = i64c(b, defPageBytes-1)
	b = append(b, 0x7C) // i64.add
	b = i64c(b, 16)
	b = append(b, 0x88, 0xA7)       // i64.shr_u; i32.wrap_i64: pages
	b = append(b, 0x40, 0x00)       // memory.grow 0
	b = ltee(b, out)                //
	b = append(b, 0x41, 0x7F, 0x46) // == -1
	b = append(b, 0x04, 0x40)       // if
	b = i32c(b, 0)
	b = lset(b, out)
	b = append(b, 0x05) // else
	b = lget(b, out)
	b = i32c(b, 16)
	b = append(b, 0x74) // i32.shl: the old end
	b = lset(b, out)
	if m.hasFloor {
		// floor = min(pages, maxPages) << 16: past everything grown so far.
		const maxPages = defMaxGrowEnd >> 16
		b = append(b, 0x3F, 0x00)
		b = i32c(b, maxPages)
		b = append(b, 0x3F, 0x00)
		b = i32c(b, maxPages)
		b = append(b, 0x49, 0x1B) // lt_u; select
		b = i32c(b, 16)
		b = append(b, 0x74)
		b = gset(b, m.floor)
	}
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitNeed leaves (len + 1) × per in the i64 local n.
func emitNeed(b []byte, lenL, n uint32, per int32) []byte {
	b = lget(b, lenL)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = i64c(b, 1)
	b = append(b, 0x7C)
	b = i64c(b, int64(per))
	b = append(b, 0x7E) // i64.mul
	return lset(b, n)
}

// emitRegion makes the region whose address and capacity are the i32 fields
// at blk+ptrOff / blk+capOff hold at least the i64 local n bytes: kept when it
// does, grown otherwise — to max(n, 2 × cap), so a run of slowly growing
// drives grows memory a logarithmic number of times. A region that cannot be
// grown is left as it was. blkFn pushes the record's address; n is not
// changed; l.s and l.n2 are scratch.
func (m *defaultModule) emitRegion(b []byte, blkFn func([]byte) []byte, ptrOff, capOff, n uint32, l defLocals) []byte {
	cap2 := func(b []byte) []byte { // 2 × cap, i64
		b = blkFn(b)
		b = ld32(b, capOff)
		b = append(b, 0xAD)
		b = i64c(b, 1)
		return append(b, 0x86) // i64.shl
	}
	b = blkFn(b)
	b = ld32(b, capOff)
	b = append(b, 0xAD) // cap, i64
	b = lget(b, n)
	b = append(b, 0x54, 0x04, 0x40) // i64.lt_u: too small; if
	b = cap2(b)
	b = lget(b, n)
	b = cap2(b)
	b = lget(b, n)
	b = append(b, 0x56, 0x1B) // i64.gt_u; select: max(2 × cap, n)
	b = lset(b, l.n2)
	b = m.emitGrow(b, l.n2, l.s)
	b = lget(b, l.s)
	b = append(b, 0x04, 0x40) // if grown
	b = blkFn(b)
	b = lget(b, l.s)
	b = st32(b, ptrOff)
	b = blkFn(b)
	b = lget(b, l.n2)
	b = append(b, 0xA7) // i32.wrap_i64
	b = st32(b, capOff)
	b = append(b, 0x0B, 0x0B)
	return b
}

// emitResetBlock zeroes a search block's search state — everything but its
// notes region (notes_ptr, notes_cap) and the high-water mark the module
// clears that region by when the next search arms. blkFn pushes the block.
func emitResetBlock(b []byte, blkFn func([]byte) []byte) []byte {
	for _, off := range []uint32{abi.SearchWastedOff, abi.SearchArmedOff, abi.SearchPtrOff, abi.SearchSeenOff,
		abi.SearchBTBudgetOff, abi.SearchBTMemoOff, abi.SearchBTTextLenOff} {
		b = blkFn(b)
		b = i64c(b, 0)
		b = st64(b, off) // wasted; armed+resume; ptr+len; seen+bt_state; budget; memo+text; text_len+bt_cap
	}
	for _, off := range []uint32{abi.SearchFirstOff, abi.SearchFarOff} {
		b = blkFn(b)
		b = i32c(b, 0)
		b = st32(b, off)
	}
	return b
}

// emitNotesAndMemo gives a default block its notes when its search armed (or
// at once, for a batch call), and its memo when it tripped — what a stub does
// between calls, here at the start of the next. notesPer / memoPer are bytes
// per position (0: the block keeps none); memoOff/memoCapOff address the memo
// region record kept across drives.
func (m *defaultModule) emitNotesAndMemo(b []byte, blkFn func([]byte) []byte, lenL uint32, l defLocals,
	notesPer, memoPer int32, batch bool, rec func([]byte) []byte, memoOff, memoCapOff uint32) []byte {
	if notesPer > 0 {
		if !batch {
			b = blkFn(b)
			b = ld32(b, abi.SearchArmedOff)
			b = append(b, 0x04, 0x40) // if armed
		}
		b = emitNeed(b, lenL, l.n, notesPer)
		// A region from an earlier drive serves when large enough: the module
		// clears it up to `high` when this search arms.
		b = m.emitRegion(b, blkFn, abi.SearchNotesOff, abi.SearchNotesCapOff, l.n, l)
		if !batch {
			b = append(b, 0x0B)
		}
	}
	if memoPer > 0 {
		b = blkFn(b)
		b = ld32(b, abi.SearchBTStateOff)
		b = i32c(b, abi.SearchBTTripped)
		b = append(b, 0x46)
		b = blkFn(b)
		b = ld32(b, abi.SearchBTMemoOff)
		b = append(b, 0x45, 0x71, 0x04, 0x40) // tripped && no memo yet: if
		b = emitNeed(b, lenL, l.n, memoPer)
		b = m.emitRegion(b, rec, memoOff, memoCapOff, l.n, l)
		// Hand it over when it covers this text, zeroed: fresh pages already
		// are, a reused region is not.
		b = rec(b)
		b = ld32(b, memoCapOff)
		b = append(b, 0xAD)
		b = lget(b, l.n)
		b = append(b, 0x5A, 0x04, 0x40) // i64.ge_u; if
		b = rec(b)
		b = ld32(b, memoOff)
		b = i32c(b, 0)
		b = lget(b, l.n)
		b = append(b, 0xA7)
		b = append(b, 0xFC, 0x0B, 0x00) // memory.fill
		b = blkFn(b)
		b = rec(b)
		b = ld32(b, memoOff)
		b = st32(b, abi.SearchBTMemoOff)
		b = blkFn(b)
		b = lget(b, l.n)
		b = append(b, 0xA7)
		b = st32(b, abi.SearchBTMemoCapOff)
		b = append(b, 0x0B, 0x0B)
	}
	return b
}

// emitEnter is a pattern export's entry: when the caller handed no block,
// the default (grown on first use, reset unless this call continues the
// previous one, given notes and a memo as needed) becomes the search block for
// this call, and l.a holds its area; otherwise l.a is 0 and nothing changes.
// lenL / fromL are the call's length and start.
func (d *defaultSearch) emitEnter(b []byte, ptrL, lenL, fromL uint32, l defLocals) []byte {
	m := d.m
	area := func(b []byte) []byte { return lget(b, l.a) }
	// l.a starts at 0, as every local does, and stays 0 unless the default is
	// used: the callers give each entry locals of its own.
	b = gget(b, m.search)
	b = append(b, 0x45, 0x04, 0x40) // eqz; if: the caller handed no block
	b = gget(b, d.area)
	b = ltee(b, l.a)
	b = append(b, 0x45, 0x04, 0x40) // first use: if
	b = i64c(b, defAreaBytes)
	b = lset(b, l.n)
	b = m.emitGrow(b, l.n, l.a)
	b = lget(b, l.a)
	b = gset(b, d.area)
	b = append(b, 0x0B)
	b = lget(b, l.a)
	b = append(b, 0x04, 0x40) // if there is a default
	// The continuation: a drive in flight over this text, called from its
	// window.
	b = area(b)
	b = ld32(b, defLive)
	b = area(b)
	b = ld32(b, defPtr)
	b = lget(b, ptrL)
	b = append(b, 0x46, 0x71)
	b = area(b)
	b = ld32(b, defLen)
	b = lget(b, lenL)
	b = append(b, 0x46, 0x71)
	b = area(b)
	b = ld32(b, defLo)
	b = lget(b, fromL)
	b = append(b, 0x4D, 0x71) // lo <= from (le_u)
	b = lget(b, fromL)
	b = area(b)
	b = ld32(b, defHi)
	b = append(b, 0x4D, 0x71)       // from <= hi
	b = append(b, 0x45, 0x04, 0x40) // not a continuation: if
	b = emitResetBlock(b, area)
	b = area(b)
	b = lget(b, ptrL)
	b = st32(b, defPtr)
	b = area(b)
	b = lget(b, lenL)
	b = st32(b, defLen)
	b = append(b, 0x0B)
	b = m.emitNotesAndMemo(b, area, lenL, l, d.notes, d.memo, d.batch, area, defMemo, defMemoCap)
	b = area(b)
	b = gset(b, m.search)
	b = append(b, 0x0B) // (no memory for one: run without a block)
	return append(b, 0x0B)
}

// emitWindow, after a call that used the default, puts the search global back
// to 0 and records where the drive may continue from: push live, lo and hi
// with the three functions (each an i32). A wrapper must run it on every exit
// after emitEnter; one that returns early (a Backtracking overflow in a batch
// call) leaves the default named, and the next call then runs on it without
// its checks — the right answers, which a -2 already made unknown.
func (d *defaultSearch) emitWindow(b []byte, l defLocals, live, lo, hi func([]byte) []byte) []byte {
	b = lget(b, l.a)
	b = append(b, 0x04, 0x40)
	b = i32c(b, 0)
	b = gset(b, d.m.search)
	for _, f := range []struct {
		push func([]byte) []byte
		off  uint32
	}{{live, defLive}, {lo, defLo}, {hi, defHi}} {
		b = lget(b, l.a)
		b = f.push(b)
		b = st32(b, f.off)
	}
	return append(b, 0x0B)
}

// emitFindWindow is emitWindow after a find call whose packed answer is in the
// i64 local r: [start, end + 1], or no drive when r is negative.
func (d *defaultSearch) emitFindWindow(b []byte, l defLocals, r uint32) []byte {
	return d.emitWindow(b, l,
		func(b []byte) []byte { return append(lget(b, r), 0x42, 0x00, 0x59) }, // r >= 0
		func(b []byte) []byte { return append(lget(b, r), 0x42, 0x20, 0x88, 0xA7) },
		func(b []byte) []byte { return append(lget(b, r), 0xA7, 0x41, 0x01, 0x6A) })
}

// ── Sets ────────────────────────────────────────────────────────────────────

// A set's default area: a descriptor of the module's own, the blocks, the
// record, and each block's memo region.
const (
	sdDesc     = 0  // abi's 24-byte descriptor, second form
	sdBlocks   = 24 // blocksTotal × abi.SearchBlockBytes
	sdRecBytes = 40 // live, ptr, len, gate, cache, cacheCap, from (i64), cacheUse
)

// setDefault is a set's default state, for its exported find and batch entry.
type setDefault struct {
	m         *defaultModule
	area      uint32 // global: the area's address, 0 until first use
	blocks    []SearchSize
	cells     int32 // the answer cache's column, 0 when the set has none
	rowBytes  int32
	hasBlocks bool
	// sweepCells / sweepRow: the program sweep's geometry, 0 for none; its
	// answers follow the cache in the region (program_sweep.go).
	sweepCells, sweepRow int32
}

// hasRegion reports whether the set's `find` takes a cache region at all.
func (d *setDefault) hasRegion() bool { return d.cells > 0 || d.sweepCells > 0 }

// forSet is cs's default, nil when its find takes nothing a caller could
// leave out (or the module gets none).
func (m *defaultModule) forSet(cs *compiledSet) *setDefault {
	if m == nil || cs.internal || !cs.hasFind() {
		return nil
	}
	d := &setDefault{m: m, hasBlocks: cs.acceptsBlocks()}
	if d.hasBlocks {
		d.blocks = cs.searchBlocks()
	}
	cache := cs
	if cs.keptCache != nil {
		cache = cs.keptCache // its kept members' set reads the cache
	}
	if cache.usesOverlapDP() {
		numPat, _, rowBytes, _ := cache.overlapCacheGeometry()
		if numPat > 0 {
			d.cells, d.rowBytes = int32(cache.overlapCells()), rowBytes //nolint:gosec // a column's width
		}
	}
	if ps := cs.progSweep; ps != nil {
		d.sweepCells, d.sweepRow = int32(ps.cells()), int32(ps.rowBytes()) //nolint:gosec // bounded by sweepMaxRoots
	}
	if !d.hasBlocks && !d.hasRegion() {
		return nil
	}
	d.area = m.globals.AllocInit(0)
	return d
}

func (d *setDefault) recOff() uint32 {
	return uint32(sdBlocks + len(d.blocks)*abi.SearchBlockBytes) //nolint:gosec // a small area
}
func (d *setDefault) memoRecOff(k int) uint32 { return d.recOff() + sdRecBytes + uint32(8*k) } //nolint:gosec
func (d *setDefault) areaBytes() int64        { return int64(d.memoRecOff(len(d.blocks))) }

const (
	sdLive     = 0
	sdPtr      = 4
	sdLen      = 8
	sdGate     = 12
	sdCache    = 16
	sdCacheCap = 20
	sdFrom     = 24 // i64: the last call's `from`, or its batch cursor
	sdCacheUse = 32 // i32: the cache bytes this drive hands over, 0 for none
)

// emitEnter goes at the very top of the set's exported find (batch false:
// `from` is the i32 param 2) or batch entry (the i64 cursor is param 2):
// when the caller's descriptor (param 3) leaves out what the set takes —
// the plain magic where it takes blocks, no cache where it has one — the
// module's own descriptor replaces it, naming the caller's gate array and
// cache when given and the module's default blocks and cache otherwise. Locals
// as for a pattern's default.
func (d *setDefault) emitEnter(b []byte, batch bool, l defLocals) []byte {
	const pPtr, pLen, pFrom, pDesc = 0, 1, 2, 3
	m := d.m
	area := func(b []byte) []byte { return lget(b, l.a) }
	rec := func(b []byte) []byte {
		b = area(b)
		return append(i32c(b, int32(d.recOff())), 0x6A) //nolint:gosec // a small offset
	}
	desc := func(b []byte) []byte { return lget(b, pDesc) }
	// Is anything left out? The plain magic where the set takes blocks, no
	// cache where it has one.
	if d.hasBlocks {
		b = desc(b)
		b = ld32(b, abi.FindScratchMagicOff)
		b = i32c(b, abi.FindScratchMagic)
		b = append(b, 0x46)
	}
	if d.hasRegion() {
		b = desc(b)
		b = ld32(b, abi.FindScratchCacheLenOff)
		b = append(b, 0x45)
		if d.hasBlocks {
			b = append(b, 0x72) // or
		}
	}
	b = append(b, 0x04, 0x40) // if something is left out
	b = gget(b, d.area)
	b = ltee(b, l.a)
	b = append(b, 0x45, 0x04, 0x40) // first use: if
	b = i64c(b, d.areaBytes())
	b = lset(b, l.n)
	b = m.emitGrow(b, l.n, l.a)
	b = lget(b, l.a)
	b = gset(b, d.area)
	b = append(b, 0x0B)
	b = lget(b, l.a)
	b = append(b, 0x04, 0x40) // if there is a default
	// The continuation: this text and gate array, and `from` (or the cursor)
	// past the last call's.
	b = rec(b)
	b = ld32(b, sdLive)
	b = rec(b)
	b = ld32(b, sdPtr)
	b = lget(b, pPtr)
	b = append(b, 0x46, 0x71)
	b = rec(b)
	b = ld32(b, sdLen)
	b = lget(b, pLen)
	b = append(b, 0x46, 0x71)
	b = rec(b)
	b = ld32(b, sdGate)
	b = desc(b)
	b = ld32(b, abi.FindScratchGateOff)
	b = append(b, 0x46, 0x71)
	b = lget(b, pFrom)
	if !batch {
		b = append(b, 0xAD) // i64.extend_i32_u
	}
	b = rec(b)
	b = utils.AppendULEB128(append(b, 0x29, 0x03), sdFrom)
	b = append(b, 0x56, 0x71)       // i64.gt_u; and
	b = append(b, 0x45, 0x04, 0x40) // a new drive: if
	if d.hasBlocks {
		b = d.emitBlockRun(b, area, l, 0, len(d.blocks), func(b []byte, blk func([]byte) []byte) []byte {
			return emitResetBlock(b, blk)
		})
	}
	b = rec(b)
	b = i32c(b, 1)
	b = st32(b, sdLive)
	b = rec(b)
	b = lget(b, pPtr)
	b = st32(b, sdPtr)
	b = rec(b)
	b = lget(b, pLen)
	b = st32(b, sdLen)
	b = rec(b)
	b = desc(b)
	b = ld32(b, abi.FindScratchGateOff)
	b = st32(b, sdGate)
	if d.hasRegion() {
		b = d.emitCacheReset(b, rec, l)
	}
	b = append(b, 0x0B)
	// The last call's `from`, for the next one's test.
	b = rec(b)
	b = lget(b, pFrom)
	if !batch {
		b = append(b, 0xAD)
	}
	b = utils.AppendULEB128(append(b, 0x37, 0x03), sdFrom)
	// The module's descriptor: the second magic when the set takes blocks.
	magic := int32(abi.FindScratchMagic)
	if d.hasBlocks {
		magic = abi.FindScratchMagicBlocks
	}
	b = area(b)
	b = i32c(b, magic)
	b = st32(b, abi.FindScratchMagicOff)
	b = area(b)
	b = desc(b)
	b = ld32(b, abi.FindScratchGateOff)
	b = st32(b, abi.FindScratchGateOff)
	// The cache: the caller's when it offered one, else the default.
	b = area(b)
	b = desc(b)
	b = ld32(b, abi.FindScratchCacheOff)
	b = st32(b, abi.FindScratchCacheOff)
	b = area(b)
	b = desc(b)
	b = ld32(b, abi.FindScratchCacheLenOff)
	b = st32(b, abi.FindScratchCacheLenOff)
	if d.hasRegion() {
		b = desc(b)
		b = ld32(b, abi.FindScratchCacheLenOff)
		b = append(b, 0x45, 0x04, 0x40) // none offered: if
		b = area(b)
		b = rec(b)
		b = ld32(b, sdCache)
		b = st32(b, abi.FindScratchCacheOff)
		b = area(b)
		b = rec(b)
		b = ld32(b, sdCacheUse)
		b = st32(b, abi.FindScratchCacheLenOff)
		b = append(b, 0x0B)
	}
	if d.hasBlocks {
		// The blocks: the caller's when it gave them, else the default ones
		// with their notes and memos.
		b = desc(b)
		b = ld32(b, abi.FindScratchMagicOff)
		b = i32c(b, abi.FindScratchMagicBlocks)
		b = append(b, 0x46, 0x04, 0x40) // given: if
		b = area(b)
		b = desc(b)
		b = ld32(b, abi.FindScratchBlocksOff)
		b = st32(b, abi.FindScratchBlocksOff)
		b = area(b)
		b = desc(b)
		b = ld32(b, abi.FindScratchBlocksCountOff)
		b = st32(b, abi.FindScratchBlocksCountOff)
		b = append(b, 0x05) // else
		b = area(b)
		b = area(b)
		b = append(i32c(b, sdBlocks), 0x6A)
		b = st32(b, abi.FindScratchBlocksOff)
		b = area(b)
		b = i32c(b, int32(len(d.blocks))) //nolint:gosec // a small count
		b = st32(b, abi.FindScratchBlocksCountOff)
		// One loop per RUN of blocks that keep the same notes and memo: a
		// set whose split members each have a block (128 in a 128-member
		// no-cache companion) would otherwise carry this code once per block.
		for k0 := 0; k0 < len(d.blocks); {
			sz := d.blocks[k0]
			k1 := k0 + 1
			for k1 < len(d.blocks) && d.blocks[k1].NotesBytes == sz.NotesBytes && d.blocks[k1].BTMemoBytes == sz.BTMemoBytes {
				k1++
			}
			if sz.NotesBytes != 0 || sz.BTMemoBytes != 0 {
				b = d.emitBlockRun(b, area, l, k0, k1, func(b []byte, blk func([]byte) []byte) []byte {
					// The block's memo record, from its address: record k is
					// 8 × k past the first, block k 128 × k past the first.
					memoRec := func(b []byte) []byte {
						b = blk(b)
						b = area(b)
						b = append(b, 0x6B) // - area
						b = i32c(b, sdBlocks)
						b = append(b, 0x6B) // - sdBlocks: 128 × k
						b = i32c(b, int32(abi.SearchBlockBytes/8))
						b = append(b, 0x6E) // / 16: 8 × k
						b = area(b)
						b = append(b, 0x6A)
						return append(i32c(b, int32(d.memoRecOff(0))), 0x6A) //nolint:gosec // a small offset
					}
					return m.emitNotesAndMemo(b, blk, pLen, l,
						int32(sz.NotesBytes), int32(sz.BTMemoBytes), batch, memoRec, 0, 4) //nolint:gosec // bytes per position
				})
			}
			k0 = k1
		}
		b = append(b, 0x0B)
	}
	b = area(b)
	b = lset(b, pDesc)
	b = append(b, 0x0B) // end if there is a default
	return append(b, 0x0B)
}

// emitBlockRun emits body for blocks k0..k1-1: inline for one block, else as
// a loop with the block's address in l.t, so a set with many blocks carries
// the body once.
func (d *setDefault) emitBlockRun(b []byte, area func([]byte) []byte, l defLocals, k0, k1 int,
	body func([]byte, func([]byte) []byte) []byte) []byte {
	if k1-k0 == 1 {
		return body(b, d.blockFn(area, k0))
	}
	b = d.blockFn(area, k0)(b)
	b = lset(b, l.t)
	b = append(b, 0x03, 0x40) // loop
	b = body(b, func(b []byte) []byte { return lget(b, l.t) })
	b = lget(b, l.t)
	b = i32c(b, abi.SearchBlockBytes)
	b = append(b, 0x6A)
	b = ltee(b, l.t)
	b = d.blockFn(area, k1)(b)      // the first block past the run
	b = append(b, 0x49, 0x0D, 0x00) // lt_u; br_if loop
	return append(b, 0x0B)
}

func (d *setDefault) blockFn(area func([]byte) []byte, k int) func([]byte) []byte {
	return func(b []byte) []byte {
		b = area(b)
		return append(i32c(b, int32(sdBlocks+k*abi.SearchBlockBytes)), 0x6A) //nolint:gosec // a small offset
	}
}

// emitCacheReset sizes the default region for this text exactly as a stub
// does — the answer cache (emitCkptSizing, or the bare header for a set with
// none) and, 8-aligned after it, the program sweep's part when it fits the
// budget — grows or reuses the region, and starts it: the header zeroed and the
// stride written. A cache too large for config.SetOverlapCacheMaxBytes gets no
// region (none handed over): the drive then routes as one whose caller declined
// the cache does.
func (d *setDefault) emitCacheReset(b []byte, rec func([]byte) []byte, l defLocals) []byte {
	const pLen = 1
	maxB := int64(config.SetOverlapCacheMaxBytes)
	if d.cells > 0 {
		b = emitCkptSizing(b, pLen, l.m, l.k, l.n, int(d.cells), int64(d.rowBytes))
		b = lget(b, l.k)
		b = append(b, 0xA7)
		b = lset(b, l.st)
	} else {
		b = i64c(b, ckptHdrBytes)
		b = lset(b, l.n)
		b = i32c(b, 1)
		b = lset(b, l.st)
	}
	if d.sweepCells > 0 {
		// + the sweep's bytes, past the cache's 8-aligned, when within budget.
		b = emitCkptSizing(b, pLen, l.m, l.k, l.b2, int(d.sweepCells), int64(d.sweepRow))
		b = lget(b, l.b2)
		b = i64c(b, maxB)
		b = append(b, 0x57, 0x04, 0x40) // le_u: if
		b = lget(b, l.n)
		b = i64c(b, 7)
		b = append(b, 0x7C)
		b = i64c(b, -8)
		b = append(b, 0x83) // i64.and
		b = lget(b, l.b2)
		b = append(b, 0x7C)
		b = lset(b, l.n)
		b = append(b, 0x0B)
	}
	b = lget(b, l.n)
	b = i64c(b, maxB)
	if d.sweepCells > 0 {
		// The two parts are each within the budget; the region may be up to
		// twice it.
		b = i64c(b, 2)
		b = append(b, 0x7E)
	}
	b = append(b, 0x57, 0x04, 0x40) // within the budget; if
	b = d.m.emitRegion(b, rec, sdCache, sdCacheCap, l.n, l)
	b = append(b, 0x0B)
	b = rec(b)
	b = ld32(b, sdCacheCap)
	b = append(b, 0xAD)
	b = lget(b, l.n)
	b = append(b, 0x5A, 0x04, 0x40) // the region holds it: if
	b = rec(b)
	b = ld32(b, sdCache)
	b = i32c(b, 0)
	b = i32c(b, config.SetOverlapCheckpointHeaderBytes)
	b = append(b, 0xFC, 0x0B, 0x00) // the header, zeroed
	b = rec(b)
	b = ld32(b, sdCache)
	b = lget(b, l.st)
	b = st32(b, config.SetOverlapHdrStrideOff)
	b = rec(b)
	b = lget(b, l.n)
	b = append(b, 0xA7)
	b = st32(b, sdCacheUse)
	b = append(b, 0x05) // else: no region for this text
	b = rec(b)
	b = i32c(b, 0)
	b = st32(b, sdCacheUse)
	b = append(b, 0x0B)
	return b
}

// withDefault puts the set's default entry at the top of an exported find
// (kind capFind) or batch entry (capFindBatch) code entry, with the locals it
// needs appended to the entry's own — every index the body already names is
// unchanged. Any other entry, or a set with no default, is returned as is.
func (cs *compiledSet) withDefault(entry []byte, kind setCapKind) []byte {
	if cs.def == nil || (kind != capFind && kind != capFindBatch) {
		return entry
	}
	size, n, err := utils.DecodeULEB128(entry)
	if err != nil || int(size)+n != len(entry) {
		panic("compile: withDefault given something that is not one code entry")
	}
	body := entry[n:]
	groups, gn, err := utils.DecodeULEB128(body)
	if err != nil {
		panic("compile: malformed locals vector in a set entry")
	}
	off, count := gn, uint64(0)
	for i := uint64(0); i < groups; i++ {
		c, cn, err := utils.DecodeULEB128(body[off:])
		if err != nil {
			panic("compile: malformed local group in a set entry")
		}
		count += c
		off += cn + 1
	}
	// Both entries take six parameters (setTypeGated, setTypeBatchGated).
	first := uint32(6 + count) //nolint:gosec // a local count
	l := defLocals{a: first, t: first + 1, s: first + 2, st: first + 3,
		n: first + 4, n2: first + 5, m: first + 6, k: first + 7, b2: first + 8}
	var out []byte
	out = utils.AppendULEB128(out, uint32(groups+2)) //nolint:gosec // a group count
	out = append(out, body[gn:off]...)
	out = append(out, 0x04, 0x7F, 0x05, 0x7E) // 4 × i32, 5 × i64
	out = cs.def.emitEnter(out, kind == capFindBatch, l)
	out = append(out, body[off:]...)
	return append(utils.AppendULEB128(nil, uint32(len(out))), out...) //nolint:gosec // a function's size
}
