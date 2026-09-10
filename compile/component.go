package compile

import (
	"errors"

	"github.com/qrdl/regexped/internal/utils"
)

// Canonical-ABI adapters for `wasm_format: component`.
//
// The core module keeps every existing body and every existing export
// untouched; this file APPENDS a small fixed set of functions after all pattern
// functions, so no baseIdx or per-pattern offset moves:
//
//	cabi_realloc  (i32,i32,i32,i32)→i32   bump allocator
//	cm_post       (i32)→()                post-return: reset the bump pointer
//	one adapter per exported pattern function, retptr-shaped
//
// `wasm-tools component new` then lifts those adapters into a component. The
// adapters do the whole canonical-ABI job: allocate a result area, call the
// existing body, and translate the -1 / -2 sentinels into the discriminated
// layouts wasm-tools expects.
//
// Everything here is emitted ONLY under asmOpts.Component. With it off the
// assembler must produce today's bytes exactly, which `make byteident` proves.

// asmOpts carries the assembler's component configuration.
//
// Its ZERO VALUE MEANS MODULE, which is why it is a struct rather than two
// positional parameters: every existing call site passes asmOpts{} and cannot
// accidentally enable a component, and no field sits next to the adjacent
// `standalone` bool waiting to be transposed. Validation is not implied by the
// type — see validate.
type asmOpts struct {
	// Component emits the allocator, the post-return and the adapters.
	Component bool
	// ComponentPackage is the interface prefix every adapter export name is
	// built from, e.g. "regexped:regexps/matcher" (a version, when the config
	// sets one, is already part of it: "regexped:regexps@2.3.0/matcher").
	ComponentPackage string
	// ExportNames maps a pattern's configured func name to the canonical-ABI
	// export name for its adapter. Built by generate.witExportNames so the
	// .wit and the core module cannot disagree about a single name.
	ExportNames map[string]string
}

// validate rejects the states the struct itself allows. A component with no
// package prefix would emit export names missing their package, and
// `wasm-tools component new` would then fail to match them against the WIT —
// late, and with a message about the WIT rather than about the config.
func (o asmOpts) validate() error {
	if !o.Component {
		return nil
	}
	if o.ComponentPackage == "" {
		return errComponentNoPackage
	}
	return nil
}

// errComponentNoPackage is asmOpts.validate's refusal: a component build with
// no interface prefix would name its exports without a package, and the failure
// would surface from wasm-tools rather than from here.
var errComponentNoPackage = errors.New("compile: component requested with no ComponentPackage — every canonical export name is built from it")

// errComponentNeedsStandalone is compileAll's refusal of an embedded component.
var errComponentNeedsStandalone = errors.New("compile: wasm_format: component requires standalone memory (a component owns and exports its own memory; it cannot import \"main\".\"memory\")")

// componentAdapter is one adapter the assembler must emit: which pattern
// function it fronts, and under what name.
type componentAdapter struct {
	kind      adapterKind
	funcIdx   int    // the existing function the adapter calls
	export    string // canonical-ABI export name
	numGroups int    // groups adapters only
}

type adapterKind int

const (
	adapterMatch adapterKind = iota
	adapterFind
	adapterGroups
)

// Result-area sizes and the element size of a groups list. From the canonical
// ABI: discriminants are u8, the area is 4-aligned, and each field sits at its
// own aligned offset.
//
//	result<option<u32>, error-code>                     12
//	  @0 result disc, @4 option disc, @8 payload
//	result<option<tuple<u32,u32>>, error-code>          16
//	  @0 result disc, @4 option disc, @8 start, @12 end
//	result<option<list<option<tuple<u32,u32>>>>, …>     16
//	  @0 result disc, @4 option disc, @8 list ptr, @12 list len
//	element option<tuple<u32,u32>>                      12
//	  @0 option disc, @4 start, @8 end
const (
	areaMatch    = 12
	areaFind     = 16
	areaGroups   = 16
	groupElemLen = 12
	slotPairLen  = 8 // two i32 capture slots per group, as the bodies write them
)

// componentAdapters lists the adapters for a module, in the order their
// functions are appended.
func componentAdapters(patterns []*compiledPattern, names map[string]string) []componentAdapter {
	var out []componentAdapter
	baseIdx, _ := patternBaseIndices(patterns)
	for i, p := range patterns {
		base := baseIdx[i]
		matchOff, _, _, captureOff, _ := p.offsets()
		if p.matchExport != "" && matchOff >= 0 {
			if name, ok := names[p.matchExport]; ok {
				out = append(out, componentAdapter{kind: adapterMatch, funcIdx: base + matchOff, export: name})
			}
		}
		if p.findExport != "" {
			if _, _, findOff, _, _ := p.offsets(); findOff >= 0 {
				if name, ok := names[p.findExport]; ok {
					// The (ptr,len,from) wrapper, exactly what the raw export
					// points at — not the two-argument body it fronts.
					out = append(out, componentAdapter{kind: adapterFind, funcIdx: base + p.findWrapperOffset(), export: name})
				}
			}
		}
		if p.hasGroupsFromWrapper() {
			if name, ok := names[p.groupsExport]; ok {
				inner := base + p.groupsFromWrapperOffsets()
				_ = captureOff
				out = append(out, componentAdapter{
					kind: adapterGroups, funcIdx: inner, export: name, numGroups: p.numGroups,
				})
			}
		}
	}
	return out
}

// patternBaseIndices assigns each pattern its base function index, and returns
// the total. Extracted so the adapter list and the assembler agree by
// construction rather than by both computing it.
func patternBaseIndices(patterns []*compiledPattern) ([]int, int) {
	baseIdx := make([]int, len(patterns))
	total := 0
	for i, p := range patterns {
		baseIdx[i] = total
		total += p.funcCount()
	}
	return baseIdx, total
}

// buildComponentReallocBody emits cabi_realloc:
//
//	(old_ptr, old_size, align, new_size) → ptr
//
// old_ptr and old_size are ignored: nothing here ever reallocates, because a
// result area's size is known before it is allocated. The allocator is a bump
// pointer that grows memory when it must and TRAPS if growth fails — returning
// a bad pointer instead would corrupt the host's read of the result area.
func buildComponentReallocBody(heapGlobal uint32) []byte {
	const (
		pAlign = 0x02 // param 2: align
		pSize  = 0x03 // param 3: new_size
		lP     = 0x04 // local: the aligned allocation start
	)
	var b []byte
	b = append(b, 0x01, 0x01, 0x7F) // 1 local group: one i32

	// p = (heap + align - 1) & -align
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x20, pAlign)
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x20, pAlign)
	b = append(b, 0x6B)     // i32.sub   -> -align
	b = append(b, 0x71)     // i32.and
	b = append(b, 0x21, lP) // local.set p

	// if p + size > memory.size * 65536 { grow, trap on failure }
	b = append(b, 0x02, 0x40) // block
	b = appendHeapEnd(b, lP, pSize)
	b = appendMemBytes(b)
	b = append(b, 0x4D)       // i32.le_u
	b = append(b, 0x0D, 0x00) // br_if 0 — enough room already
	b = appendHeapEnd(b, lP, pSize)
	b = appendMemBytes(b)
	b = append(b, 0x6B)       // i32.sub — shortfall in bytes
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x76)       // i32.shr_u — whole pages
	b = append(b, 0x41, 0x01) // i32.const 1
	b = append(b, 0x6A)       // i32.add   — round up
	b = append(b, 0x40, 0x00) // memory.grow 0
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x00)       // unreachable — out of memory
	b = append(b, 0x0B)       // end if
	b = append(b, 0x0B)       // end block

	// heap = p + size; return p
	b = appendHeapEnd(b, lP, pSize)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x20, lP)
	b = append(b, 0x0B) // end function
	return b
}

// appendHeapEnd pushes p + size.
func appendHeapEnd(b []byte, lP, pSize byte) []byte {
	b = append(b, 0x20, lP)
	b = append(b, 0x20, pSize)
	return append(b, 0x6A) // i32.add
}

// appendMemBytes pushes memory.size * 65536.
func appendMemBytes(b []byte) []byte {
	b = append(b, 0x3F, 0x00) // memory.size 0
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 65536)
	return append(b, 0x6C) // i32.mul
}

// buildComponentPostBody emits cm_post: (retptr i32) → ().
//
// It resets the bump pointer to the static top, which is the ONLY safe place
// to reset it. Resetting at adapter entry would free the input list the host
// lowered into guest memory immediately before the call.
//
// One function serves every export: a WASM function may be exported under any
// number of names.
func buildComponentPostBody(heapGlobal uint32, staticTop int32) []byte {
	var b []byte
	b = append(b, 0x00) // no locals
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, staticTop)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x0B)
	return b
}

// --- small store helpers, so the adapter bodies read as the layout they write.

// storeDisc writes a u8 discriminant at base+off.
//
// A memarg offset is a ULEB128 u32, not a byte: a groups adapter for a pattern
// with 22 capture groups reaches offset 252 and the next one does not fit in a
// byte, so a raw byte here would silently write the wrong address.
func storeDisc(b []byte, baseLocal byte, off int, value byte) []byte {
	b = append(b, 0x20, baseLocal)
	b = append(b, 0x41, value)
	b = append(b, 0x3A, 0x00) // i32.store8, align=0
	return utils.AppendULEB128(b, uint32(off))
}

// storeI32 stores the value on top of the stack at base+off; callers push the
// base pointer, then the value, then call this.
func storeI32(b []byte, off int) []byte {
	b = append(b, 0x36, 0x02) // i32.store, align=2
	return utils.AppendULEB128(b, uint32(off))
}

// loadI32 pushes base+off as an i32 load; callers push the base pointer first.
func loadI32(b []byte, off int) []byte {
	b = append(b, 0x28, 0x02) // i32.load, align=2
	return utils.AppendULEB128(b, uint32(off))
}

// callRealloc pushes a cabi_realloc(0, 0, align, size) call.
func callRealloc(b []byte, reallocIdx int, align, size int32) []byte {
	b = append(b, 0x41, 0x00) // old_ptr
	b = append(b, 0x41, 0x00) // old_size
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, align)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, size)
	b = append(b, 0x10)
	return utils.AppendULEB128(b, uint32(reallocIdx))
}

// buildMatchAdapterBody emits the match adapter: (ptr, len) → retptr.
//
// Inner signature: (ptr, len) → i32, answering an end position, -1 for no
// match, or -2 for a Backtracking frame-budget overflow.
//
//	result<option<u32>, error-code>   @0 result disc, @4 option disc, @8 end
func buildMatchAdapterBody(reallocIdx, innerIdx int) []byte {
	const (
		pPtr = 0x00
		pLen = 0x01
		lR   = 0x02
		lRet = 0x03
	)
	var b []byte
	b = append(b, 0x01, 0x02, 0x7F) // 2 i32 locals: r, ret

	b = callRealloc(b, reallocIdx, 4, areaMatch)
	b = append(b, 0x21, lRet)

	b = append(b, 0x20, pPtr, 0x20, pLen)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lR)

	// -2 first: an UNKNOWN answer is not a "no match", and conflating them
	// would report a definite negative the engine never established.
	b = append(b, 0x20, lR, 0x41, 0x7E, 0x46) // r == -2
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1) // err
	b = storeDisc(b, lRet, 4, 0) // enum index 0: backtrack-overflow
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0) // ok

	b = append(b, 0x20, lR, 0x41, 0x7F, 0x46) // r == -1
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 4, 0) // none
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 4, 1) // some
	b = append(b, 0x20, lRet, 0x20, lR)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// buildFindAdapterBody emits the find adapter: (ptr, len, start) → retptr.
//
// Inner signature: the exported (ptr, len, from) → i64 wrapper, answering
// (start << 32 | end), -1 for no match, or -2 for overflow. `ptr`/`len` always
// describe the WHOLE input, so left-context assertions judge real neighbours.
//
//	result<option<tuple<u32,u32>>, error-code>
//	  @0 result disc, @4 option disc, @8 start, @12 end
func buildFindAdapterBody(reallocIdx, innerIdx int) []byte {
	const (
		pPtr   = 0x00
		pLen   = 0x01
		pStart = 0x02
		lR     = 0x03 // i64
		lRet   = 0x04 // i32
	)
	var b []byte
	// Two local groups: one i64 then one i32, so r is local 3 and ret local 4.
	b = append(b, 0x02, 0x01, 0x7E, 0x01, 0x7F)

	b = callRealloc(b, reallocIdx, 4, areaFind)
	b = append(b, 0x21, lRet)

	b = append(b, 0x20, pPtr, 0x20, pLen, 0x20, pStart)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lR)

	b = append(b, 0x20, lR, 0x42, 0x7E, 0x51) // i64: r == -2
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0)

	b = append(b, 0x20, lR, 0x42, 0x7F, 0x51) // i64: r == -1
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 4, 1)
	// start = wrap(r >> 32)
	b = append(b, 0x20, lRet)
	b = append(b, 0x20, lR, 0x42, 0x20, 0x88, 0xA7) // i64.const 32, i64.shr_u, i32.wrap_i64
	b = storeI32(b, 8)
	// end = wrap(r)
	b = append(b, 0x20, lRet)
	b = append(b, 0x20, lR, 0xA7)
	b = storeI32(b, 12)
	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// buildGroupsAdapterBody emits the groups adapter: (ptr, len, start) → retptr.
//
// Inner signature: the exported (ptr, len, out_ptr, from) → i32 wrapper, which
// fills out_ptr with numGroups PAIRS of i32 slots and answers an end position,
// -1, or -2.
//
//	result<option<list<option<tuple<u32,u32>>>>, error-code>
//	  @0 result disc, @4 option disc, @8 list ptr, @12 list len
//	element option<tuple<u32,u32>>  @0 option disc, @4 start, @8 end
//
// The per-group copy is unrolled: numGroups is a compile-time constant, so a
// loop would cost a counter and a bounds test per group to save nothing.
//
// A group is UNSET iff its START slot is negative — the same test the generated
// stubs apply (generate/rust_stub.go), so all six languages and the component
// agree on which groups participated.
func buildGroupsAdapterBody(reallocIdx, innerIdx, numGroups int) []byte {
	const (
		pPtr   = 0x00
		pLen   = 0x01
		pStart = 0x02
		lR     = 0x03
		lRet   = 0x04
		lSlots = 0x05
		lElems = 0x06
	)
	var b []byte
	b = append(b, 0x01, 0x04, 0x7F) // 4 i32 locals: r, ret, slots, elems

	b = callRealloc(b, reallocIdx, 4, areaGroups)
	b = append(b, 0x21, lRet)
	b = callRealloc(b, reallocIdx, 4, int32(numGroups*slotPairLen))
	b = append(b, 0x21, lSlots)
	b = callRealloc(b, reallocIdx, 4, int32(numGroups*groupElemLen))
	b = append(b, 0x21, lElems)

	b = append(b, 0x20, pPtr, 0x20, pLen, 0x20, lSlots, 0x20, pStart)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerIdx))
	b = append(b, 0x21, lR)

	b = append(b, 0x20, lR, 0x41, 0x7E, 0x46) // r == -2
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 0, 1)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 0, 0)

	b = append(b, 0x20, lR, 0x41, 0x7F, 0x46) // r == -1
	b = append(b, 0x04, 0x40)
	b = storeDisc(b, lRet, 4, 0)
	b = append(b, 0x20, lRet, 0x0F)
	b = append(b, 0x0B)

	b = storeDisc(b, lRet, 4, 1)
	b = append(b, 0x20, lRet, 0x20, lElems)
	b = storeI32(b, 8)
	b = append(b, 0x20, lRet, 0x41)
	b = utils.AppendSLEB128(b, int32(numGroups))
	b = storeI32(b, 12)

	for g := 0; g < numGroups; g++ {
		slotStart := g * slotPairLen
		slotEnd := g*slotPairLen + 4
		elem := g * groupElemLen

		// if slots[start] < 0 { elem.disc = none } else { some(start, end) }
		b = append(b, 0x20, lSlots)
		b = loadI32(b, slotStart)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x48)       // i32.lt_s
		b = append(b, 0x04, 0x40) // if
		b = storeDisc(b, lElems, elem, 0)
		b = append(b, 0x05) // else
		b = storeDisc(b, lElems, elem, 1)
		b = append(b, 0x20, lElems)
		b = append(b, 0x20, lSlots)
		b = loadI32(b, slotStart)
		b = storeI32(b, elem+4)
		b = append(b, 0x20, lElems)
		b = append(b, 0x20, lSlots)
		b = loadI32(b, slotEnd)
		b = storeI32(b, elem+8)
		b = append(b, 0x0B) // end if
	}

	b = append(b, 0x20, lRet)
	b = append(b, 0x0B)
	return b
}

// appendCodeEntry writes one size-prefixed function body into a code section.
func appendCodeEntry(cs []byte, body []byte) []byte {
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// asmOpts projects the component fields of CompileOptions onto the assembler's
// options. Keeping the projection in one place means a new component option is
// added once, not at each assembler.
func (o CompileOptions) asmOpts() asmOpts {
	return asmOpts{
		Component:        o.Component,
		ComponentPackage: o.ComponentPackage,
		ExportNames:      o.ComponentExportNames,
	}
}
