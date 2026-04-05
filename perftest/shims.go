package main

// Bench shim WASM modules — programmatically built.
//
// Each shim:
//   - imports wasi_snapshot_preview1.clock_time_get  (func 0)
//   - imports regexped.<fn>                          (func 1)
//   - has 1 memory page (64KB)
//   - exports "memory" and "bench"
//
// Memory layout (all three shims share the same layout):
//
//	[0 .. timingsBytes-1]  timings[benchIters] u32 nanosecond samples
//	[timingsBytes .. +7]   clock scratch (8 bytes for clock_time_get output)
//
// find/groups bench: per outer-iteration, exhausts all matches in the input
// before recording the elapsed time.  match bench: one call per iteration.

import (
	"encoding/binary"
	"sort"
	"time"

	"github.com/qrdl/regexped/internal/utils"
)

const (
	timingsBytes = benchIters * 4    // 40 000 bytes
	clockScratch = int32(timingsBytes) // 40 000; 8-byte aligned (40000 = 8×5000)
	shimMemPages = 1                  // 64KB; enough for 40 008 bytes
)

// computeStat reads benchIters u32 nanosecond samples from data and returns
// either their average (pct == 0) or the pct-th percentile.
func computeStat(data []byte, pct int) time.Duration {
	n := len(data) / 4
	vals := make([]uint32, n)
	for i := range vals {
		vals[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	if pct == 0 {
		var sum uint64
		for _, v := range vals {
			sum += uint64(v)
		}
		return time.Duration(sum / uint64(n))
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	idx := pct * n / 100
	if idx >= n {
		idx = n - 1
	}
	return time.Duration(vals[idx])
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
//	type 1: fnParams → fnResults     the regex function
//	type 2: benchParams → void       the bench function
func shimTypeSection(fnParams, fnResults, benchParams []byte) []byte {
	c := []byte{0x03} // 3 types

	// type 0: clock_time_get (i32, i64, i32) → i32
	c = append(c, 0x60, 0x03, 0x7F, 0x7E, 0x7F, 0x01, 0x7F)

	// type 1: regex fn
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

// shimImportSection imports clock_time_get (type 0) and the regex fn (type 1).
func shimImportSection(fnModule, fnName string) []byte {
	c := []byte{0x02} // 2 imports
	// import 0: wasi_snapshot_preview1.clock_time_get = func type 0
	c = append(c, shimStr("wasi_snapshot_preview1")...)
	c = append(c, shimStr("clock_time_get")...)
	c = append(c, 0x00, 0x00) // extern kind: func, type index 0
	// import 1: regexped.<fn> = func type 1
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
	// body already includes local declarations + instructions + end
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
// Drops the errno return value.  Leaves nothing on stack.
func emitClockGet(b []byte) []byte {
	b = append(b, 0x41, 0x01)                // i32.const 1  (CLOCK_MONOTONIC)
	b = append(b, 0x42, 0x00)                // i64.const 0  (precision)
	b = append(b, 0x41)                      // i32.const
	b = utils.AppendSLEB128(b, clockScratch) // 40000
	b = append(b, 0x10, 0x00)               // call 0 (clock_time_get)
	return append(b, 0x1A)                  // drop errno
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
	// address = iLocal * 4  (timingsBase = 0)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, iLocal) // local.get i
	b = append(b, 0x41, 0x04)         // i32.const 4
	b = append(b, 0x6C)               // i32.mul
	// value = i32.wrap_i64(i64.load(clockScratch) - t_start)
	b = emitLoadClock(b)
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, tStartLocal) // local.get t_start
	b = append(b, 0x7D)                    // i64.sub
	b = append(b, 0xA7)                    // i32.wrap_i64
	return append(b, 0x36, 0x02, 0x00)    // i32.store align=2 offset=0
}

// --------------------------------------------------------------------------
// buildMatchBenchShim
//
// bench(ptr i32, len i32, iters i32) → void
//
// Params:  ptr(0), len(1), iters(2)
// Locals:  i(3 i32), t_prev(4 i64)
//
// One clock call per iteration boundary: t_prev is set once before the loop,
// then at the end of each iteration t_cur is recorded, elapsed stored, and
// t_prev = t_cur for the next iteration.
func buildMatchBenchShim() []byte {
	var b []byte
	// locals: 1×i32 (i), 1×i64 (t_prev)
	b = append(b, 0x02, 0x01, 0x7F, 0x01, 0x7E)

	// t_prev = clock_time_get()  — initial timestamp before the loop
	b = emitClockGet(b)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04) // local.set 4 (t_prev)

	b = append(b, 0x02, 0x40) // block void
	b = append(b, 0x03, 0x40) // loop void

	// if i >= iters: break
	b = append(b, 0x20, 0x03, 0x20, 0x02, 0x4E, 0x0D, 0x01) // local.get 3, local.get 2, i32.ge_s, br_if 1

	// match(ptr, len); drop result
	b = append(b, 0x20, 0x00, 0x20, 0x01, 0x10, 0x01, 0x1A)

	// t_cur = clock_time_get(); timings[i] = t_cur − t_prev
	b = emitClockGet(b)
	b = emitStoreElapsed(b, 3, 4)

	// t_prev = t_cur  (clockScratch still holds t_cur)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x04) // local.set 4 (t_prev)

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
// Locals:  i(3 i32), cur_ptr(4 i32), cur_len(5 i32), end(6 i32),
//
//	result(7 i64), t_prev(8 i64)
//
// Per outer iteration: exhausts all find() matches, then records elapsed time.
// Advances by max(end,1) to handle zero-length matches without infinite loop.
// Single clock call per iteration boundary (t_prev = end of prev = start of next).
func buildFindBenchShim() []byte {
	var b []byte
	// locals: 4×i32 (i, cur_ptr, cur_len, end), 2×i64 (result, t_prev)
	b = append(b, 0x02, 0x04, 0x7F, 0x02, 0x7E)

	// t_prev = clock_time_get()  — initial timestamp before the loop
	b = emitClockGet(b)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x08) // local.set 8 (t_prev)

	b = append(b, 0x02, 0x40) // block void  (outer)
	b = append(b, 0x03, 0x40) // loop void   (outer_loop)

	// if i >= iters: br_if 1 (exit outer loop)
	b = append(b, 0x20, 0x03, 0x20, 0x02, 0x4E, 0x0D, 0x01)

	// cur_ptr = ptr; cur_len = len
	b = append(b, 0x20, 0x00, 0x21, 0x04) // local.get 0, local.set 4
	b = append(b, 0x20, 0x01, 0x21, 0x05) // local.get 1, local.set 5

	// inner block + loop: exhaust all matches
	b = append(b, 0x02, 0x40) // block void  (inner)
	b = append(b, 0x03, 0x40) // loop void   (inner_loop)

	// if cur_len <= 0: br_if 1 (exit inner loop)
	b = append(b, 0x20, 0x05, 0x41, 0x00, 0x4C, 0x0D, 0x01)

	// result = find(cur_ptr, cur_len); local.set 7
	b = append(b, 0x20, 0x04, 0x20, 0x05, 0x10, 0x01, 0x21, 0x07)

	// if result == -1i64: br_if 1 (exit inner loop)
	b = append(b, 0x20, 0x07)       // local.get 7 (result)
	b = append(b, 0x42, 0x7F)       // i64.const -1
	b = append(b, 0x51, 0x0D, 0x01) // i64.eq, br_if 1

	// end = i32.wrap_i64(result); local.set 6
	b = append(b, 0x20, 0x07, 0xA7, 0x21, 0x06)

	// advance = end + i32.eqz(end)
	// cur_ptr = cur_ptr + advance
	b = append(b, 0x20, 0x04)             // local.get 4 (cur_ptr)
	b = append(b, 0x20, 0x06, 0x20, 0x06) // local.get 6, local.get 6
	b = append(b, 0x45, 0x6A)             // i32.eqz, i32.add  → advance
	b = append(b, 0x6A, 0x21, 0x04)       // i32.add cur_ptr+advance, local.set 4

	// cur_len = cur_len - advance
	b = append(b, 0x20, 0x05)             // local.get 5 (cur_len)
	b = append(b, 0x20, 0x06, 0x20, 0x06) // local.get 6, local.get 6
	b = append(b, 0x45, 0x6A)             // i32.eqz, i32.add  → advance
	b = append(b, 0x6B, 0x21, 0x05)       // i32.sub cur_len-advance, local.set 5

	b = append(b, 0x0C, 0x00) // br 0 (inner_loop)
	b = append(b, 0x0B, 0x0B) // end inner_loop, end inner block

	// t_cur = clock_time_get(); timings[i] = t_cur − t_prev
	b = emitClockGet(b)
	b = emitStoreElapsed(b, 3, 8)

	// t_prev = t_cur  (clockScratch still holds t_cur)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x08) // local.set 8 (t_prev)

	// i++
	b = append(b, 0x20, 0x03, 0x41, 0x01, 0x6A, 0x21, 0x03)

	b = append(b, 0x0C, 0x00, 0x0B, 0x0B, 0x0B) // br 0, end outer_loop, end outer block, end fn

	return assembleShim(
		shimTypeSection([]byte{0x7F, 0x7F}, []byte{0x7E}, []byte{0x7F, 0x7F, 0x7F}),
		shimImportSection("regexped", "find"),
		shimFunctionSection(),
		shimMemorySection(),
		shimExportSection(),
		shimCodeSection(b),
	)
}

// --------------------------------------------------------------------------
// buildGroupsBenchShim
//
// bench(ptr i32, len i32, out_ptr i32, iters i32) → void
//
// Params:  ptr(0), len(1), out_ptr(2), iters(3)
// Locals:  i(4 i32), cur_ptr(5 i32), cur_len(6 i32), result(7 i32),
//
//	t_prev(8 i64)
//
// Per outer iteration: exhausts all groups() matches, then records elapsed time.
// Single clock call per iteration boundary.
func buildGroupsBenchShim() []byte {
	var b []byte
	// locals: 4×i32 (i, cur_ptr, cur_len, result), 1×i64 (t_prev)
	b = append(b, 0x02, 0x04, 0x7F, 0x01, 0x7E)

	// t_prev = clock_time_get()  — initial timestamp before the loop
	b = emitClockGet(b)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x08) // local.set 8 (t_prev)

	b = append(b, 0x02, 0x40) // block void  (outer)
	b = append(b, 0x03, 0x40) // loop void   (outer_loop)

	// if i >= iters: br_if 1
	b = append(b, 0x20, 0x04, 0x20, 0x03, 0x4E, 0x0D, 0x01)

	// cur_ptr = ptr; cur_len = len
	b = append(b, 0x20, 0x00, 0x21, 0x05)
	b = append(b, 0x20, 0x01, 0x21, 0x06)

	// inner block + loop: exhaust all matches
	b = append(b, 0x02, 0x40)
	b = append(b, 0x03, 0x40)

	// if cur_len <= 0: br_if 1
	b = append(b, 0x20, 0x06, 0x41, 0x00, 0x4C, 0x0D, 0x01)

	// result = groups(cur_ptr, cur_len, out_ptr); local.set 7
	b = append(b, 0x20, 0x05, 0x20, 0x06, 0x20, 0x02, 0x10, 0x01, 0x21, 0x07)

	// if result == -1: br_if 1
	b = append(b, 0x20, 0x07, 0x41, 0x7F, 0x46, 0x0D, 0x01)

	// advance = result + i32.eqz(result)
	// cur_ptr = cur_ptr + advance
	b = append(b, 0x20, 0x05)
	b = append(b, 0x20, 0x07, 0x20, 0x07)
	b = append(b, 0x45, 0x6A)       // i32.eqz, i32.add → advance
	b = append(b, 0x6A, 0x21, 0x05) // cur_ptr + advance, local.set 5

	// cur_len = cur_len - advance
	b = append(b, 0x20, 0x06)
	b = append(b, 0x20, 0x07, 0x20, 0x07)
	b = append(b, 0x45, 0x6A)       // advance
	b = append(b, 0x6B, 0x21, 0x06) // cur_len - advance, local.set 6

	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B, 0x0B) // end inner_loop, end inner block

	// t_cur = clock_time_get(); timings[i] = t_cur − t_prev
	b = emitClockGet(b)
	b = emitStoreElapsed(b, 4, 8)

	// t_prev = t_cur  (clockScratch still holds t_cur)
	b = emitLoadClock(b)
	b = append(b, 0x21, 0x08) // local.set 8 (t_prev)

	// i++
	b = append(b, 0x20, 0x04, 0x41, 0x01, 0x6A, 0x21, 0x04)

	b = append(b, 0x0C, 0x00, 0x0B, 0x0B, 0x0B)

	return assembleShim(
		shimTypeSection([]byte{0x7F, 0x7F, 0x7F}, []byte{0x7F}, []byte{0x7F, 0x7F, 0x7F, 0x7F}),
		shimImportSection("regexped", "groups"),
		shimFunctionSection(),
		shimMemorySection(),
		shimExportSection(),
		shimCodeSection(b),
	)
}
