package main

// Bench shim WASM modules — programmatically built. Adapted from
// likelytest/shims.go, trimmed to match/find only (pattest has no groups mode).
//
// Each shim:
//   - imports wasi_snapshot_preview1.clock_time_get  (func 0)
//   - imports regexped.<fn>                          (func 1)
//   - has 1 memory page (64KB)
//   - exports "memory" and "bench"
//
// Memory layout (both shims share the same layout):
//
//	[0 .. timingsBytes-1]  timings[benchIters] u32 nanosecond samples
//	[timingsBytes .. +7]   clock scratch (8 bytes for clock_time_get output)
//
// find bench: per outer-iteration, exhausts all matches in the input before
// recording the elapsed time. match bench: one call per iteration.

import (
	"encoding/binary"
	"time"

	"github.com/qrdl/regexped/internal/utils"
)

const (
	timingsBytes = benchIters * 4                     // 400 000 bytes
	clockScratch = int32(timingsBytes)                // 8-byte aligned
	shimMemPages = (timingsBytes + 8 + 65535) / 65536 // ceil to 64KB pages
)

// computeStat reads benchIters u32 nanosecond samples from data and returns
// their average.
func computeStat(data []byte) time.Duration {
	n := len(data) / 4
	var sum uint64
	for i := 0; i < n; i++ {
		sum += uint64(binary.LittleEndian.Uint32(data[i*4:]))
	}
	return time.Duration(sum / uint64(n))
}

// --------------------------------------------------------------------------
// Low-level WASM encoding helpers

func shimSection(id byte, content []byte) []byte {
	b := []byte{id}
	b = utils.AppendULEB128(b, uint32(len(content)))
	return append(b, content...)
}

func shimStr(s string) []byte {
	b := utils.AppendULEB128(nil, uint32(len(s)))
	return append(b, s...)
}

// shimTypeSection builds type section with three types:
//
//	type 0: (i32, i64, i32) → i32   clock_time_get
//	type 1: fnParams → fnResults     the regexp function
//	type 2: benchParams → void       the bench function
func shimTypeSection(fnParams, fnResults, benchParams []byte) []byte {
	c := []byte{0x03} // 3 types

	// type 0: clock_time_get (i32, i64, i32) → i32
	c = append(c, 0x60, 0x03, 0x7F, 0x7E, 0x7F, 0x01, 0x7F)

	// type 1: regexp fn
	c = append(c, 0x60)
	c = utils.AppendULEB128(c, uint32(len(fnParams)))
	c = append(c, fnParams...)
	c = utils.AppendULEB128(c, uint32(len(fnResults)))
	c = append(c, fnResults...)

	// type 2: bench fn (void result)
	c = append(c, 0x60)
	c = utils.AppendULEB128(c, uint32(len(benchParams)))
	c = append(c, benchParams...)
	c = append(c, 0x00) // 0 results

	return shimSection(0x01, c)
}

// shimImportSection imports clock_time_get (type 0) and the regexp fn (type 1).
func shimImportSection(fnModule, fnName string) []byte {
	c := []byte{0x02} // 2 imports
	c = append(c, shimStr("wasi_snapshot_preview1")...)
	c = append(c, shimStr("clock_time_get")...)
	c = append(c, 0x00, 0x00) // extern kind: func, type index 0
	c = append(c, shimStr(fnModule)...)
	c = append(c, shimStr(fnName)...)
	c = append(c, 0x00, 0x01) // extern kind: func, type index 1
	return shimSection(0x02, c)
}

// shimFunctionSection declares 1 function of type 2 (bench, func index 2).
func shimFunctionSection() []byte {
	return shimSection(0x03, []byte{0x01, 0x02})
}

// shimMemorySection declares 1 memory: min=shimMemPages pages, no max.
func shimMemorySection() []byte {
	return shimSection(0x05, []byte{0x01, 0x00, byte(shimMemPages)})
}

// shimExportSection exports "memory" (mem 0) and "bench" (func 2).
func shimExportSection() []byte {
	c := []byte{0x02} // 2 exports
	c = append(c, shimStr("memory")...)
	c = append(c, 0x02, 0x00) // memory, index 0
	c = append(c, shimStr("bench")...)
	c = append(c, 0x00, 0x02) // func, index 2
	return shimSection(0x07, c)
}

// shimCodeSection wraps a function body into a code section (1 function).
func shimCodeSection(body []byte) []byte {
	fnBody := utils.AppendULEB128(nil, uint32(len(body)))
	fnBody = append(fnBody, body...)
	return shimSection(0x0A, append([]byte{0x01}, fnBody...))
}

func assembleShim(sections ...[]byte) []byte {
	b := []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00} // magic + version
	for _, s := range sections {
		b = append(b, s...)
	}
	return b
}

// --------------------------------------------------------------------------
// Instruction emitters (append to b, return b)

// emitClockGet emits: clock_time_get(CLOCK_MONOTONIC=1, precision=0, clockScratch)
// Drops the errno return value. Leaves nothing on stack.
func emitClockGet(b []byte) []byte {
	b = append(b, 0x41, 0x01) // i32.const 1  (CLOCK_MONOTONIC)
	b = append(b, 0x42, 0x00) // i64.const 0  (precision)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, clockScratch)
	b = append(b, 0x10, 0x00) // call 0 (clock_time_get)
	return append(b, 0x1A)    // drop errno
}

// emitLoadClock emits: push i64.load(clockScratch) onto the stack.
func emitLoadClock(b []byte) []byte {
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, clockScratch)
	return append(b, 0x29, 0x03, 0x00) // i64.load align=3 offset=0
}

// emitStoreElapsed emits:
//
//	timings[locals[iLocal]] = u32(i64.load(clockScratch) - locals[tStartLocal])
func emitStoreElapsed(b []byte, iLocal, tStartLocal uint32) []byte {
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, iLocal) // local.get i
	b = append(b, 0x41, 0x04)          // i32.const 4
	b = append(b, 0x6C)                // i32.mul
	b = emitLoadClock(b)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, tStartLocal) // local.get t_start
	b = append(b, 0x7D)                     // i64.sub
	b = append(b, 0xA7)                     // i32.wrap_i64
	return append(b, 0x36, 0x02, 0x00)      // i32.store align=2 offset=0
}

// --------------------------------------------------------------------------
// buildMatchBenchShim
//
// bench(ptr i32, len i32, iters i32) → void
//
// Params:  ptr(0), len(1), iters(2)
// Locals:  i(3 i32), t_prev(4 i64)
func buildMatchBenchShim() []byte {
	var b []byte
	b = append(b, 0x02, 0x01, 0x7F, 0x01, 0x7E) // locals: 1×i32 (i), 1×i64 (t_prev)

	b = emitClockGet(b)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04) // local.set 4 (t_prev)

	b = append(b, 0x02, 0x40) // block void
	b = append(b, 0x03, 0x40) // loop void

	// if i >= iters: break
	b = append(b, 0x20, 0x03, 0x20, 0x02, 0x4E, 0x0D, 0x01)

	// match(ptr, len); drop result
	b = append(b, 0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x1A)

	// t_cur = clock_time_get(); timings[i] = t_cur − t_prev
	b = emitClockGet(b)
	b = emitStoreElapsed(b, 3, 4)

	// t_prev = t_cur
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04)

	// i++
	b = append(b, 0x20, 0x03, 0x41, 0x01, 0x6A, 0x21, 0x03)

	b = append(b, 0x0C, 0x00, 0x0B, 0x0B, 0x0B) // br 0, end loop, end block, end fn

	return assembleShim(
		shimTypeSection([]byte{0x7F, 0x7F}, []byte{0x7F}, []byte{0x7F, 0x7F, 0x7F}),
		shimImportSection("regexped", "match"),
		shimFunctionSection(),
		shimMemorySection(),
		shimExportSection(),
		shimCodeSection(b),
	)
}

// --------------------------------------------------------------------------
// buildFindBenchShim
//
// bench(ptr i32, len i32, iters i32) → void
//
// Params:  ptr(0), len(1), iters(2)
// Locals:  i(3 i32), t_prev(4 i64)
//
// One find() call per iteration — deliberately NOT exhausting all matches
// (unlike likelytest's find shim, which this was originally adapted from).
// benchFuel calls find() exactly once per measurement; if this shim looped
// until find() returned -1, a "matching" input with the match near the
// start would have its measured time dominated by a second find() call
// scanning the entire remainder for more matches — silently turning a
// "matching" bucket's *time* number into a no-match-shaped workload while
// its *fuel* number (single call) stayed a true single-match measurement.
// Keeping both at exactly one call keeps fuel and time comparable.
func buildFindBenchShim() []byte {
	var b []byte
	b = append(b, 0x02, 0x01, 0x7F, 0x01, 0x7E) // locals: 1×i32 (i), 1×i64 (t_prev)

	b = emitClockGet(b)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04) // local.set 4 (t_prev)

	b = append(b, 0x02, 0x40) // block void
	b = append(b, 0x03, 0x40) // loop void

	// if i >= iters: break
	b = append(b, 0x20, 0x03, 0x20, 0x02, 0x4E, 0x0D, 0x01)

	// find(ptr, len); drop i64 result
	b = append(b, 0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x1A)

	// t_cur = clock_time_get(); timings[i] = t_cur − t_prev
	b = emitClockGet(b)
	b = emitStoreElapsed(b, 3, 4)

	// t_prev = t_cur
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04)

	// i++
	b = append(b, 0x20, 0x03, 0x41, 0x01, 0x6A, 0x21, 0x03)

	b = append(b, 0x0C, 0x00, 0x0B, 0x0B, 0x0B) // br 0, end loop, end block, end fn

	return assembleShim(
		shimTypeSection([]byte{0x7F, 0x7F}, []byte{0x7E}, []byte{0x7F, 0x7F, 0x7F}),
		shimImportSection("regexped", "find"),
		shimFunctionSection(),
		shimMemorySection(),
		shimExportSection(),
		shimCodeSection(b),
	)
}
