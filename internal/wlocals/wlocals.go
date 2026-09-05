package wlocals

import "github.com/qrdl/regexped/internal/utils"

// ── WASM local allocation ──────────────────────────────
//
// Every emitter in this package used to state each local TWICE, in two places
// nothing cross-checked:
//
//	const locWindowBase byte = 14   // fact 1: what the code believes the index is
//	b = append(b, 0x07, 0x7F)       // fact 2: the declaration vector that decides it
//	b = append(b, 0x05, 0x7B)       // (7 i32 + 5 v128 puts the next i32 at 14)
//	b = append(b, 0x02, 0x7F)
//
// The two can disagree, and nothing catches it: WASM locals are
// zero-initialised, so an index that is merely WRONG rather than out of range
// produces a module that validates and runs. The numbering is also
// un-refactorable by hand — buildLitChainAltLenientFindBody carries two
// declared-but-unused v128 slots for no reason other than that removing them
// would renumber everything after them.
//
// Alloc removes the second fact. Indices are handed out, the declaration
// vector is generated from the same allocation, and neither is written down.
//
// Allocation order IS declaration order, and runs of one type coalesce into a
// single group, so a body that allocates i32 x3 then v128 x7 emits exactly the
// `0x02, 0x03,0x7F, 0x07,0x7B` it used to write by hand. That is what lets the
// conversion be proved by byte identity rather than by review.
type Alloc struct {
	next   uint32
	groups []group
}

type group struct {
	n  uint32
	ty byte
}

// WASM value types, as they appear in a locals declaration.
const (
	ValI32  byte = 0x7F
	ValI64  byte = 0x7E
	ValV128 byte = 0x7B
)

// New starts allocation after nParams function parameters, which
// occupy locals 0..nParams-1 and are not declared.
func New(nParams uint32) *Alloc {
	return &Alloc{next: nParams}
}

func (a *Alloc) alloc(ty byte) byte {
	if n := len(a.groups); n > 0 && a.groups[n-1].ty == ty {
		a.groups[n-1].n++
	} else {
		a.groups = append(a.groups, group{n: 1, ty: ty})
	}
	idx := a.next
	a.next++
	if idx > 0xFF {
		// Every emitter here is far below this, and emitFindFromSeed already
		// documents what a truncated index costs: the validator accepts it as
		// a DIFFERENT local. Fail loudly rather than emit one.
		panic("compile: local index exceeds 255 — the byte-indexed emitters cannot address it")
	}
	return byte(idx)
}

// Next is the index the next allocation will receive — the count of locals
// declared so far plus the parameters. Emitters with a hand-computed layout
// use it to assert their arithmetic still agrees with the allocation.
func (a *Alloc) Next() uint32 { return a.next }

func (a *Alloc) I32() byte  { return a.alloc(ValI32) }
func (a *Alloc) I64() byte  { return a.alloc(ValI64) }
func (a *Alloc) V128() byte { return a.alloc(ValV128) }

// Reserve allocates n locals of type ty and discards their indices. It exists
// for slots a body declares but no longer uses; converting such a body without
// it would renumber every local after the hole and change the emitted bytes.
func (a *Alloc) Reserve(ty byte, n int) {
	for i := 0; i < n; i++ {
		a.alloc(ty)
	}
}

// EmitDecls appends the locals declaration vector.
func (a *Alloc) EmitDecls(b []byte) []byte {
	b = utils.AppendULEB128(b, uint32(len(a.groups)))
	for _, g := range a.groups {
		b = utils.AppendULEB128(b, g.n)
		b = append(b, g.ty)
	}
	return b
}

// ── The scan cursor ────────────────────────────────────
//
// Cursor is the local a find body's scan STARTS FROM — the one the
// find-from offset must be seeded into.
//
// It is a distinct type, and compile.emitFindFromSeed accepts nothing else, because
// "seed the wrong local" is the defect this whole mechanism keeps producing.
// It shipped twice: buildSimplePrefixCheckBody returned a start before `from`
// for want of a floor, and buildLitChainAltLenientFindBody seeded
// locAttemptStart, which in that body is DERIVED from the window base rather
// than being the cursor — so `from` had no effect whatever and a host
// iterating the export never terminated.
//
// A body gets one from wlocals.Alloc.ScanCursor() and passes that same value to
// both its scan and its seed. Handing the seed some other local is no longer
// expressible: plain locals are bytes, and a byte is not a scanCursor.
//
// A body with two candidate locals — the lenient-alt window base and its
// derived attempt-start — must therefore decide which one is the cursor at
// the point it allocates them, which is precisely the decision that was
// previously made implicitly, in a different function, by someone reading a
// const block.
type Cursor struct {
	idx byte
	set bool
}

// ScanCursor allocates the i32 a find body scans from.
func (a *Alloc) ScanCursor() Cursor { return Cursor{idx: a.I32(), set: true} }

// Local is the cursor's index, for the scan emitters that address it as an
// ordinary local once its identity has been established.
//
// The zero Cursor panics rather than answering 0. `set` is what makes the seal
// real: Cursor's fields are unexported and this package exports no way to build
// one, so a caller outside it can write Cursor{} but cannot write a Cursor
// naming a local of its choosing — and the one it can write is refused here.
func (c Cursor) Local() byte {
	if !c.set {
		panic("wlocals: zero Cursor — a scan cursor must come from Alloc.ScanCursor")
	}
	return c.idx
}
