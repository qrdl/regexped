package fuzz

import (
	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/internal/abi"
)

// writeFindScratch lays a scratch descriptor into guest memory and returns its
// address — the argument `find` and `find_batch` take in place of a bare gate
// pointer (internal/abi).
//
// Every test in this package that drives a set's find used to pass the gate
// array directly. They pass this instead, and the magic word is what turned
// each missed call site into an immediate trap rather than a wrong answer: the
// parameter has the same type it always had.
//
// The descriptor is placed immediately above the gate array. Callers here own
// their memory layouts and all of them leave room above it.
func writeFindScratch(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen int32) int32 {
	scratch := gatePtr + idSpaceWords*4
	abi.WriteFindScratch(mem.UnsafeData(store), scratch, gatePtr, cachePtr, cacheLen)
	return scratch
}
