package compile

import (
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// A Backtracking FALLBACK body's run-time memory.
//
// The fallback is the body a call lands in when the ordinary body gives up —
// its work budget ran out, or its frame stack — and the only body a program
// with a zero-width cycle has. Its own frame stack and memo are therefore sized
// from the INPUT, at call time, rather than reserved at compile time — a
// compile-time region is exactly the ceiling the fallback exists to remove.
//
// # Layout
//
//	base                 stackBase                          memory end
//	| memo: (span+1) rows |  frame stack, grows upward ...  |
//
// The memo is sized exactly at entry: one row of ceil(N/8) bytes per position
// in the span the search ranges over, so its size is known before the first
// visit and the stack can start right after it. The stack is last because it
// is the region whose need is NOT known in advance; it grows on demand,
// doubling, by growing linear memory past its end.
//
// # Where base comes from
//
// base = the scratch's host global, raised to at least its floor global (the
// end of the module's tables); a host global of 0 means "the host has said
// nothing", and base is then the current end of memory — fresh pages, which
// nothing else can be using. See btScratch and abi.ScratchBaseExport for what
// the host global holds in each output kind.
//
// # Why the memo is cleared as the search reaches it
//
// The region may hold anything: the previous call's bits, or bytes a host
// wrote there before it raised the global. Clearing the whole memo at entry
// would touch — and make a host commit — every page of a region sized for the
// worst case, while a search usually visits a small prefix of it. Rows are
// position-major, so the bytes a search has touched are always below the
// highest row it has reached: `cleared` tracks how far the zeroing has gone,
// and a visit past it zeroes the next stretch first.
//
// # Why a row is whole bytes
//
// A bit's address is base + (pos - origin)·ceil(N/8) + pc/8, bit pc%8, so the
// bit within its byte is a compile-time constant and the address never passes
// through a bit index that would overflow i32 long before memory runs out. It
// costs at most 7 unused bits per position.

// btScratchClearChunk is how far past the byte being visited the lazy clear
// zeroes at once, so a search walking forward pays one memory.fill per stretch
// rather than one per row.
const btScratchClearChunk = 4096

// btScratchMaxEnd is the highest address a scratch region may reach. Page
// 65,536 would end at 2^32, which does not fit an i32 address; stopping one
// page short keeps every end address — and sp + frameSize — representable.
const btScratchMaxEnd = 0xFFFF0000

// btDyn is one fallback body's handle on its run-time memory: the globals it
// finds the region through, and the locals it keeps the region's bounds in.
type btDyn struct {
	scratch btScratch
	// memIdx is the memory the region lives in — the table memory.
	memIdx int
	// frameSize is this body's frame, in bytes.
	frameSize int32
	// rowBytes is one memo row: ceil(N/8).
	rowBytes int32

	memoBase  uint32 // i32 local: the memo's first byte
	cleared   uint32 // i32 local: every memo byte below it is known zero
	stackBase uint32 // i32 local: the frame stack's first byte, one past the memo
	stackTop  uint32 // i32 local: the highest sp a frame may still be pushed at
	tmp64     uint32 // i64 local, for the entry arithmetic

	// member is set for a SET member's fallback, whose memo outlives the call:
	// see btDrive. It adds two locals.
	member  *btDriveMember
	origin  uint32 // i32 local: the position the member's memo rows start at
	memoEnd uint32 // i32 local: one past the member's memo
}

// clearLimit is the local the lazy clear may not zero past: the stack base
// when the memo is this call's alone, the member's own memo end when other
// members' regions may lie between it and the stack.
func (d *btDyn) clearLimit() uint32 {
	if d.member != nil {
		return d.memoEnd
	}
	return d.stackBase
}

func newBTDyn(scratch btScratch, memIdx int, frameSize int32, numInsts int) *btDyn {
	return &btDyn{
		scratch:   scratch,
		memIdx:    memIdx,
		frameSize: frameSize,
		rowBytes:  int32((numInsts + 7) / 8),
	}
}

// emitBTMemEnd pushes the address one past the region memIdx currently ends at,
// capped at btScratchMaxEnd.
func emitBTMemEnd(b []byte, memIdx int) []byte {
	const maxPages = btScratchMaxEnd >> 16
	b = append(b, 0x3F)
	b = utils.AppendULEB128(b, uint32(memIdx)) // memory.size
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, maxPages)
	b = append(b, 0x3F)
	b = utils.AppendULEB128(b, uint32(memIdx)) // memory.size
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, maxPages)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x1B)       // select: min(pages, maxPages)
	b = append(b, 0x41, 0x10) // i32.const 16
	return append(b, 0x74)    // i32.shl
}

// emitBTMemoryGrow emits `memory.grow; if == -1 { then }` with the page count
// already on the stack.
func emitBTMemoryGrowOr(b []byte, memIdx int, then func([]byte) []byte) []byte {
	b = append(b, 0x40)
	b = utils.AppendULEB128(b, uint32(memIdx)) // memory.grow
	b = append(b, 0x41, 0x7F)                  // i32.const -1
	b = append(b, 0x46)                        // i32.eq
	b = append(b, 0x04, 0x40)                  // if
	b = then(b)
	return append(b, 0x0B) // end if
}

// emitBTScratchInit places this call's region, grows memory until the memo and
// one frame fit, and leaves memoBase, cleared, stackBase and stackTop set. span
// pushes the i32 length the memo's positions cover. unknown must leave the
// function: it runs when memory cannot grow far enough, and answers
// abi.BTStackOverflow in the body's own result type.
func emitBTScratchInit(b []byte, d *btDyn, span, unknown func([]byte) []byte) []byte {
	b = emitBTScratchBase(b, d, d.memoBase)

	// stackBase = (base + (span+1)·rowBytes + 3) & ~3, in i64: the product
	// alone passes 2^32 for a long span over a large program.
	b = btLocalGet(b, d.memoBase)
	b = append(b, 0xAD) // i64.extend_i32_u
	b = span(b)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, int64(d.rowBytes))
	b = append(b, 0x7E)       // i64.mul
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x42, 0x03) // i64.const 3
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x42, 0x7C) // i64.const -4
	b = append(b, 0x83)       // i64.and
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, d.tmp64) // local.tee tmp64
	// Past the addressable ceiling even before one frame: unknown.
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, int64(d.frameSize))
	b = append(b, 0x7C) // i64.add
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, btScratchMaxEnd)
	b = append(b, 0x56)       // i64.gt_u
	b = append(b, 0x04, 0x40) // if
	b = unknown(b)
	b = append(b, 0x0B) // end if
	b = btLocalGet(b, d.tmp64)
	b = append(b, 0xA7) // i32.wrap_i64
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.stackBase)

	b = emitBTEnsureStack(b, d, unknown)

	// Nothing of the memo is known to be zero yet.
	b = btLocalGet(b, d.memoBase)
	b = append(b, 0x21)
	return utils.AppendULEB128(b, d.cleared)
}

// emitBTScratchBase leaves in dst where the scratch may start: the host
// global; the current end of memory when that is 0; the floor global when it is
// below the floor.
func emitBTScratchBase(b []byte, d *btDyn, dst uint32) []byte {
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, d.scratch.host) // global.get host
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, dst) // local.tee dst
	b = append(b, 0x45)             // i32.eqz
	b = append(b, 0x04, 0x40)       // if
	b = emitBTMemEnd(b, d.memIdx)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, dst)
	b = append(b, 0x05) // else
	b = btLocalGet(b, dst)
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, d.scratch.floor)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, d.scratch.floor)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, dst)
	b = append(b, 0x0B)    // end if
	return append(b, 0x0B) // end if/else
}

// emitBTEnsureStack grows memory until one frame fits above stackBase, then
// sets stackTop; unknown runs when it cannot.
func emitBTEnsureStack(b []byte, d *btDyn, unknown func([]byte) []byte) []byte {
	// Grow until the memo and one frame fit. stackTop holds the needed end
	// for the moment; it is set to its real value right after.
	b = btLocalGet(b, d.stackBase)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, d.frameSize)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, d.stackTop) // local.tee stackTop (the needed end)
	b = emitBTMemEnd(b, d.memIdx)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	// pages = (need - end) >> 16, plus one: rounds up, and at most one page over.
	b = btLocalGet(b, d.stackTop)
	b = emitBTMemEnd(b, d.memIdx)
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x76)       // i32.shr_u
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add
	b = emitBTMemoryGrowOr(b, d.memIdx, unknown)
	b = append(b, 0x0B) // end if

	b = emitBTSetStackTop(b, d)
	// The cap on the end address can leave the need unmet after a grow that
	// succeeded; say so rather than push past it.
	b = btLocalGet(b, d.stackBase)
	b = btLocalGet(b, d.stackTop)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	b = unknown(b)
	return append(b, 0x0B) // end if
}

// emitBTSetStackTop emits stackTop = end of memory - frameSize.
func emitBTSetStackTop(b []byte, d *btDyn) []byte {
	b = emitBTMemEnd(b, d.memIdx)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, d.frameSize)
	b = append(b, 0x6B) // i32.sub
	b = append(b, 0x21)
	return utils.AppendULEB128(b, d.stackTop)
}

// emitBTDynPushCheck is btPushFrame's guard for a fallback body: when sp is past
// stackTop, grow memory by the stack's current size (doubling it), or by the
// fewest pages one frame needs if that is refused, and run unknown — which must
// leave the function — when even that fails.
//
// A single frame always fits afterwards: sp never exceeds stackTop + frameSize,
// and the smallest grow adds at least frameSize bytes. The re-check covers the
// one exception, the end-address cap.
func emitBTDynPushCheck(b []byte, d *btDyn, unknown func([]byte) []byte) []byte {
	minPages := (d.frameSize + 0xFFFF) >> 16
	if minPages < 1 {
		minPages = 1
	}
	b = append(b, 0x20, localSP)
	b = btLocalGet(b, d.stackTop)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	// max((stackTop + frameSize - stackBase) >> 16, minPages)
	capacityPages := func(b []byte) []byte {
		b = btLocalGet(b, d.stackTop)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, d.frameSize)
		b = append(b, 0x6A) // i32.add
		b = btLocalGet(b, d.stackBase)
		b = append(b, 0x6B)       // i32.sub
		b = append(b, 0x41, 0x10) // i32.const 16
		return append(b, 0x76)    // i32.shr_u
	}
	b = capacityPages(b)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, minPages)
	b = capacityPages(b)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, minPages)
	b = append(b, 0x4B) // i32.gt_u
	b = append(b, 0x1B) // select: max
	b = emitBTMemoryGrowOr(b, d.memIdx, func(b []byte) []byte {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, minPages)
		return emitBTMemoryGrowOr(b, d.memIdx, unknown)
	})
	b = emitBTSetStackTop(b, d)
	b = append(b, 0x20, localSP)
	b = btLocalGet(b, d.stackTop)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	b = unknown(b)
	b = append(b, 0x0B)    // end if
	return append(b, 0x0B) // end if (sp > stackTop)
}

// emitBitStateGuardDyn is a fallback body's BitState guard: "already visited
// (p, pos)? fail : mark visited", over the run-time memo, clearing it as the
// search reaches it. byteAddr and memoByte are scratch locals.
func emitBitStateGuardDyn(b []byte, d *btDyn, p int, byteAddr, memoByte uint32,
	brDepth uint32, memoOriginLocal uint32, hasMemoOrigin bool) []byte {

	// byteAddr = memoBase + (pos - origin)·rowBytes + p/8
	b = append(b, 0x20, localPos)
	if hasMemoOrigin {
		b = btLocalGet(b, memoOriginLocal)
		b = append(b, 0x6B) // i32.sub
	}
	if d.rowBytes != 1 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, d.rowBytes)
		b = append(b, 0x6C) // i32.mul
	}
	if p>>3 != 0 {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(p>>3))
		b = append(b, 0x6A) // i32.add
	}
	b = btLocalGet(b, d.memoBase)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, byteAddr) // local.tee byteAddr

	// Not yet zeroed: zero up to min(byteAddr + chunk, stackBase) first.
	b = btLocalGet(b, d.cleared)
	b = append(b, 0x4F)       // i32.ge_u
	b = append(b, 0x04, 0x40) // if
	b = btLocalGet(b, byteAddr)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, btScratchClearChunk)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, memoByte) // local.tee memoByte (the stretch end)
	b = btLocalGet(b, d.clearLimit())
	b = btLocalGet(b, memoByte)
	b = btLocalGet(b, d.clearLimit())
	b = append(b, 0x49) // i32.lt_u
	b = append(b, 0x1B) // select: min
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, memoByte)
	b = btLocalGet(b, d.cleared)
	b = append(b, 0x41, 0x00) // i32.const 0
	b = btLocalGet(b, memoByte)
	b = btLocalGet(b, d.cleared)
	b = append(b, 0x6B) // i32.sub
	b = appendTableMemoryFill(b, d.memIdx)
	b = btLocalGet(b, memoByte)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.cleared)
	if d.member != nil {
		// The next candidate call starts from this watermark.
		b = btLocalGet(b, d.cleared)
		b = append(b, 0x24)
		b = utils.AppendULEB128(b, d.member.cleared)
	}
	b = append(b, 0x0B) // end if

	mask := int32(1) << (p & 7)
	b = btLocalGet(b, byteAddr)
	b = appendTableLoad8u(b, d.memIdx)
	b = append(b, 0x22)
	b = utils.AppendULEB128(b, memoByte) // local.tee memoByte
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, mask)
	b = append(b, 0x71)       // i32.and
	b = append(b, 0x04, 0x40) // if: already visited
	b = btFail(b, brDepth)
	b = append(b, 0x0B) // end if

	b = btLocalGet(b, byteAddr)
	b = btLocalGet(b, memoByte)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, mask)
	b = append(b, 0x72) // i32.or
	return appendTableStore8(b, d.memIdx)
}

// componentHeapGlobal allocates a component allocator's heap-top global, which
// starts past the free-list head array at the static top. When the module has
// fallback-scratch globals the heap top IS the scratch's host global: a
// fallback runs inside a call, above every block the allocator has handed out,
// and cabi_realloc — which only runs between calls into the body — then carves
// its next block from memory whose contents it never assumes.
func componentHeapGlobal(globals *moduleGlobals, staticTop int32) uint32 {
	init := staticTop + classHeadsBytes
	if sc, ok := globals.btScratchGlobals(); ok {
		globals.setInit(sc.host, init)
		return sc.host
	}
	return globals.AllocInit(init)
}

// placeBTScratch gives the fallback-scratch globals their initial values for
// the output kind being assembled, and reports whether the host global is
// exported (as abi.ScratchBaseExport). Call it after componentHeapGlobal.
//
//   - floor: the static top, in every kind.
//   - host, embedded: the static top too. The module's memory is its own, so
//     the region above its tables is the fallback's alone and is reused call
//     after call.
//   - host, component: the allocator's heap top, set by componentHeapGlobal.
//   - host, standalone: 0 and exported. The host owns everything above the
//     tables and tells the module what it may use.
func placeBTScratch(globals *moduleGlobals, staticTop int32, standalone, component bool) (sc btScratch, export bool) {
	sc, ok := globals.btScratchGlobals()
	if !ok {
		return btScratch{}, false
	}
	globals.setInit(sc.floor, staticTop)
	switch {
	case component:
	case !standalone:
		globals.setInit(sc.host, staticTop)
	default:
		export = true
	}
	return sc, export
}

// appendBTScratchExport appends the standalone host global's export entry.
func appendBTScratchExport(es []byte, sc btScratch) []byte {
	es = appendString(es, abi.ScratchBaseExport)
	es = append(es, 0x03) // kind: global
	return utils.AppendULEB128(es, sc.host)
}

// ── Set members: state that lasts one host call ─────────────────────────────
//
// A set's Backtracking member is driven once per CANDIDATE position, each call
// searching from that candidate to the end of the input. Sized per call, the
// fallback's memory and the ordinary body's budget made one host call pay for
// every candidate separately: each candidate burned a budget sized over the
// rest of the input, then placed and cleared a fresh memo there — quadratic
// work, and with the host global at 0, fresh pages per candidate.
//
// So three things last for the whole host call instead, per member:
//
//   - the SCRATCH REGION: placed at the member's first fallback call, sized for
//     the span from that candidate to the end, and reused by every later
//     candidate. Members get regions of their own, stacked, because the
//     candidates of different members interleave at every position; one region
//     cleared on each switch would be cleared on every call.
//   - the VISITED SET in it. A (pc, pos) bit means "explored from here and
//     failed", and the continuation from (pc, pos) does not depend on which
//     candidate reached it, so a later candidate may cut on an earlier
//     candidate's bits — the sharing the single-pattern find body already does
//     across its attempts. It holds only while the attempts that set the bits
//     failed: a bit set on the way to a match is not a failure. The member's
//     suffix call therefore resets it after any match (buildSetBTSuffixBody).
//   - the WORK BUDGET: one per member per host call, (span+1)·k·N pops with the
//     span taken at the member's first candidate, drawn down across
//     candidates. Once it trips, every later candidate of that member goes
//     straight to the fallback — without that, each candidate's ordinary body
//     would burn the budget again before tripping.
//
// "A host call" is an epoch: a global every exported set capability bumps on
// entry (emitBTDrivePrologue), compared against the epoch each member's state
// was set up in. Component adapters call those same exported functions, so
// they bump it too.

// btDrive names a set's call-scoped globals.
type btDrive struct {
	epoch        uint32 // i64: bumped on entry to every exported set capability
	scratchEpoch uint32 // i64: the epoch scratchTop was placed in
	scratchTop   uint32 // i32: one past every member region placed in that epoch
}

// btDriveMember is one Backtracking member's call-scoped globals.
type btDriveMember struct {
	drive       btDrive
	budgetEpoch uint32 // i64: the epoch budget was set in
	budget      uint32 // i64: pops left for the ordinary body; below 1 once it tripped
	memoEpoch   uint32 // i64: the epoch the region below was placed in
	memoBase    uint32 // i32: the member's memo
	memoOrigin  uint32 // i32: the position its first row stands for
	memoEnd     uint32 // i32: one past its memo
	cleared     uint32 // i32: every memo byte below it is known zero
}

// allocBTDrive allocates a set's call-scoped globals. The epoch starts one
// ahead of every member epoch, so state is set up on first use even in the
// instant before any entry prologue has run.
func allocBTDrive(g *moduleGlobals) btDrive {
	return btDrive{
		epoch:        g.AllocI64(1),
		scratchEpoch: g.AllocI64(0),
		scratchTop:   g.Alloc(),
	}
}

// allocBTDriveMember allocates one member's call-scoped globals.
func allocBTDriveMember(g *moduleGlobals, d btDrive) *btDriveMember {
	return &btDriveMember{
		drive:       d,
		budgetEpoch: g.AllocI64(0),
		budget:      g.AllocI64(0),
		memoEpoch:   g.AllocI64(0),
		memoBase:    g.Alloc(),
		memoOrigin:  g.Alloc(),
		memoEnd:     g.Alloc(),
		cleared:     g.Alloc(),
	}
}

func appendGlobalGet(b []byte, idx uint32) []byte {
	b = append(b, 0x23)
	return utils.AppendULEB128(b, idx)
}

func appendGlobalSet(b []byte, idx uint32) []byte {
	b = append(b, 0x24)
	return utils.AppendULEB128(b, idx)
}

// emitBTDrivePrologue is the code every exported set capability starts with
// when the set has a Backtracking member with a fallback: a new host call.
func emitBTDrivePrologue(d btDrive) []byte {
	var b []byte
	b = appendGlobalGet(b, d.epoch)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7C)       // i64.add
	return appendGlobalSet(b, d.epoch)
}

// injectBTDrivePrologue returns a copy of one code entry with the drive
// prologue at the head of its code.
func injectBTDrivePrologue(entry []byte, d btDrive) []byte {
	size, n, err := utils.DecodeULEB128(entry)
	if err != nil || int(size)+n != len(entry) {
		panic("compile: injectBTDrivePrologue given something that is not one code entry")
	}
	body := entry[n:]
	off := localsVectorEnd(body)
	p := emitBTDrivePrologue(d)
	out := make([]byte, 0, len(body)+len(p))
	out = append(out, body[:off]...)
	out = append(out, p...)
	out = append(out, body[off:]...)
	return append(utils.AppendULEB128(nil, uint32(len(out))), out...)
}

// emitBTWorkInitMember sets the member's budget, once per host call:
// (span + 1) · k · N, with span as emitBTWorkInit takes it.
func emitBTWorkInitMember(b []byte, m *btDriveMember, k, n int, span func([]byte) []byte) []byte {
	b = appendGlobalGet(b, m.budgetEpoch)
	b = appendGlobalGet(b, m.drive.epoch)
	b = append(b, 0x52)       // i64.ne
	b = append(b, 0x04, 0x40) // if
	b = span(b)
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x42)       // i64.const k*N
	b = utils.AppendSLEB128_64(b, int64(k)*int64(n))
	b = append(b, 0x7E) // i64.mul
	b = appendGlobalSet(b, m.budget)
	b = appendGlobalGet(b, m.drive.epoch)
	b = appendGlobalSet(b, m.budgetEpoch)
	return append(b, 0x0B) // end if
}

// emitBTWorkChargeMember is emitBTWorkCharge against the member's budget:
// `if (--budget < 1) trip`. tmp is an i64 local.
func emitBTWorkChargeMember(b []byte, m *btDriveMember, tmp uint32, trip func([]byte) []byte) []byte {
	b = appendGlobalGet(b, m.budget)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x7D)       // i64.sub
	b = append(b, 0x22)       // local.tee tmp
	b = utils.AppendULEB128(b, tmp)
	b = appendGlobalSet(b, m.budget)
	b = btLocalGet(b, tmp)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x53)       // i64.lt_s
	b = append(b, 0x04, 0x40) // if
	b = trip(b)
	return append(b, 0x0B) // end if
}

// btArmTripMember is btArmTrip against the member's budget.
func btArmTripMember(m *btDriveMember) func([]byte, uint32) []byte {
	return func(b []byte, brDepth uint32) []byte {
		b = append(b, 0x42, 0x01) // i64.const 1
		b = appendGlobalSet(b, m.budget)
		return btFail(b, brDepth)
	}
}

// emitBTMemberTripped pushes whether the member's ordinary body has tripped in
// this host call.
func emitBTMemberTripped(b []byte, m *btDriveMember) []byte {
	b = appendGlobalGet(b, m.budgetEpoch)
	b = appendGlobalGet(b, m.drive.epoch)
	b = append(b, 0x51) // i64.eq
	b = appendGlobalGet(b, m.budget)
	b = append(b, 0x42, 0x01) // i64.const 1
	b = append(b, 0x53)       // i64.lt_s
	return append(b, 0x71)    // i32.and
}

// emitBTMemberMatched resets the member's visited set: its bits are failures
// only while every attempt that set them failed. end is the i32 local holding
// the call's answer.
func emitBTMemberMatched(b []byte, m *btDriveMember, end byte) []byte {
	b = append(b, 0x20, end)
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x4E)       // i32.ge_s
	b = append(b, 0x04, 0x40) // if
	b = appendGlobalGet(b, m.memoBase)
	b = appendGlobalSet(b, m.cleared)
	return append(b, 0x0B) // end if
}

// emitBTScratchInitMember is emitBTScratchInit for a set member's fallback. The
// member's region is placed once per host call — at its first fallback call, or
// again if a window ever starts before the region's first row — above
// everything placed so far in that call; later calls load it, and their frame
// stack starts above every member's region. winStart and winEnd are the window
// locals.
func emitBTScratchInitMember(b []byte, d *btDyn, winStart, winEnd uint32, unknown func([]byte) []byte) []byte {
	m := d.member
	b = appendGlobalGet(b, m.memoEpoch)
	b = appendGlobalGet(b, m.drive.epoch)
	b = append(b, 0x52) // i64.ne
	b = btLocalGet(b, winStart)
	b = appendGlobalGet(b, m.memoOrigin)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x72)       // i32.or
	b = append(b, 0x04, 0x40) // if: place the region
	{
		// The first placement in this host call finds the scratch base.
		b = appendGlobalGet(b, m.drive.scratchEpoch)
		b = appendGlobalGet(b, m.drive.epoch)
		b = append(b, 0x52)       // i64.ne
		b = append(b, 0x04, 0x40) // if
		b = emitBTScratchBase(b, d, d.memoBase)
		b = btLocalGet(b, d.memoBase)
		b = appendGlobalSet(b, m.drive.scratchTop)
		b = appendGlobalGet(b, m.drive.epoch)
		b = appendGlobalSet(b, m.drive.scratchEpoch)
		b = append(b, 0x0B) // end if

		// tmp64 = (scratchTop + 3) & ~3, in i64: a host global near 2^32
		// must fail the ceiling test below, not wrap.
		b = appendGlobalGet(b, m.drive.scratchTop)
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x42, 0x03) // i64.const 3
		b = append(b, 0x7C)       // i64.add
		b = append(b, 0x42, 0x7C) // i64.const -4
		b = append(b, 0x83)       // i64.and
		b = append(b, 0x22)
		b = utils.AppendULEB128(b, d.tmp64) // local.tee tmp64
		b = append(b, 0xA7)                 // i32.wrap_i64
		b = append(b, 0x21)
		b = utils.AppendULEB128(b, d.memoBase)

		// tmp64 += (winEnd - winStart + 1) · rowBytes: the memo's end.
		b = btLocalGet(b, d.tmp64)
		b = btLocalGet(b, winEnd)
		b = btLocalGet(b, winStart)
		b = append(b, 0x6B)       // i32.sub
		b = append(b, 0xAD)       // i64.extend_i32_u
		b = append(b, 0x42, 0x01) // i64.const 1
		b = append(b, 0x7C)       // i64.add
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, int64(d.rowBytes))
		b = append(b, 0x7E) // i64.mul
		b = append(b, 0x7C) // i64.add
		b = append(b, 0x22)
		b = utils.AppendULEB128(b, d.tmp64) // local.tee tmp64
		// Past the addressable ceiling with one aligned frame above it: unknown.
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, int64(d.frameSize)+3)
		b = append(b, 0x7C) // i64.add
		b = append(b, 0x42)
		b = utils.AppendSLEB128_64(b, btScratchMaxEnd)
		b = append(b, 0x56)       // i64.gt_u
		b = append(b, 0x04, 0x40) // if
		b = unknown(b)
		b = append(b, 0x0B) // end if

		b = btLocalGet(b, d.tmp64)
		b = append(b, 0xA7) // i32.wrap_i64
		b = append(b, 0x22)
		b = utils.AppendULEB128(b, d.memoEnd) // local.tee memoEnd
		b = appendGlobalSet(b, m.memoEnd)
		b = btLocalGet(b, d.memoEnd)
		b = appendGlobalSet(b, m.drive.scratchTop)
		b = btLocalGet(b, d.memoBase)
		b = appendGlobalSet(b, m.memoBase)
		b = btLocalGet(b, d.memoBase)
		b = appendGlobalSet(b, m.cleared) // nothing of it is known zero
		b = btLocalGet(b, winStart)
		b = appendGlobalSet(b, m.memoOrigin)
		b = appendGlobalGet(b, m.drive.epoch)
		b = appendGlobalSet(b, m.memoEpoch)
	}
	b = append(b, 0x0B) // end if

	b = appendGlobalGet(b, m.memoBase)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.memoBase)
	b = appendGlobalGet(b, m.memoOrigin)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.origin)
	b = appendGlobalGet(b, m.memoEnd)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.memoEnd)
	b = appendGlobalGet(b, m.cleared)
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.cleared)

	// The stack starts above every region placed so far in this host call.
	b = appendGlobalGet(b, m.drive.scratchTop)
	b = append(b, 0x41, 0x03) // i32.const 3
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x41, 0x7C) // i32.const -4
	b = append(b, 0x71)       // i32.and
	b = append(b, 0x21)
	b = utils.AppendULEB128(b, d.stackBase)
	return emitBTEnsureStack(b, d, unknown)
}
