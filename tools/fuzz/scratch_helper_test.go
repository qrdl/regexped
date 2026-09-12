package fuzz

import (
	"encoding/binary"
	"fmt"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v48"
	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
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
	return writeFindScratchStride(store, mem, gatePtr, idSpaceWords, cachePtr, cacheLen, 0)
}

// writeFindScratchStride is writeFindScratch plus the CHECKPOINTED cache's one
// caller-written header field.
//
// The stride is chosen by whoever allocates the region — a generated `init` in
// a real consumer, these helpers in a test — because the allocation and the
// stride come from the same formula and must agree. A zero stride is a
// malformed header and the sweep reports it rather than guessing, so a test
// that offers a cache must seed this or it is testing the refusal path.
func writeFindScratchStride(store *wasmtime.Store, mem *wasmtime.Memory, gatePtr, idSpaceWords int32, cachePtr, cacheLen, stride int32) int32 {
	scratch := gatePtr + idSpaceWords*4
	buf := mem.UnsafeData(store)
	abi.WriteFindScratch(buf, scratch, gatePtr, cachePtr, cacheLen)
	if cachePtr != 0 {
		for i := int32(0); i < config.SetOverlapCheckpointHeaderBytes; i++ {
			buf[cachePtr+i] = 0
		}
		binary.LittleEndian.PutUint32(buf[cachePtr+16:], uint32(stride))
	}
	return scratch
}

// overlapCacheFor sizes and strides a checkpointed cache for one set, the way
// a generated `init` would: it recompiles the set to learn the sweep column,
// then asks config for both numbers so the test and the sweep cannot disagree.
func overlapCacheFor(input string, pats []string) (length, stride int32) {
	entries := make([]config.RegexEntry, len(pats))
	names := make([]string, len(pats))
	for i, p := range pats {
		names[i] = fmt.Sprintf("p%d", i)
		entries[i] = config.RegexEntry{Name: names[i], Pattern: p}
	}
	cfg := config.BuildConfig{
		Regexps: entries,
		Sets: []config.SetConfig{{
			Name: "s", Find: "find", Overlapping: true,
			Patterns: config.PatternSelector{Names: names},
		}},
	}
	sh, err := compile.SetOverlapCacheShape(cfg.Sets[0], cfg)
	if err != nil || !sh.Eligible {
		// Not eligible: any region will do, the sweep declines it.
		return int32(config.SetOverlapCheckpointHeaderBytes), 1
	}
	return int32(config.SetOverlapCheckpointBytes(len(input), sh.Cells, sh.Patterns, true)),
		int32(config.SetOverlapCheckpointStride(len(input), sh.Cells, sh.Patterns, true))
}
