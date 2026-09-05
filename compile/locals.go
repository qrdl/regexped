package compile

import "github.com/qrdl/regexped/internal/wlocals"

// The local allocator and the scan cursor live in internal/wlocals rather than
// here, and that placement is the mechanism, not tidiness.
//
// scanCursor's fields are unexported in THAT package, and it exports no
// constructor, so no emitter in this package can write a cursor naming a local
// of its choosing — the only way to obtain one is to allocate it. A cursor is
// therefore evidence that the local it names is the one the body's own
// allocation designated as its scan start, which is exactly the fact
// emitFindFromSeed needs and previously had to take on trust.
//
// See wlocals' own doc comment for why hand-numbered locals produced the same
// defect twice.
type (
	localAlloc = wlocals.Alloc
	scanCursor = wlocals.Cursor
)

const (
	valI32  = wlocals.ValI32
	valI64  = wlocals.ValI64
	valV128 = wlocals.ValV128
)

func newLocalAlloc(nParams uint32) *localAlloc { return wlocals.New(nParams) }
