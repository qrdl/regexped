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
	// SetNames is the same thing for `sets:`, keyed by set name. Empty for a
	// config with no sets, which is every config before phase 3.2.
	SetNames map[string]ComponentSetNames
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
// firstFuncIdx is where the module's DEFINED functions begin. It is 0 for the
// single-pattern assembler, which imports no function, and the number of
// imported canon builtins for a set-bearing component — where a `find` resource
// imports `[resource-new]`. Getting it wrong does not fail to build: the
// adapters then call a function one index off, and validation reports a stack
// mismatch in the ADAPTER rather than naming the cause.
func componentAdapters(patterns []*compiledPattern, names map[string]string, firstFuncIdx int) []componentAdapter {
	var out []componentAdapter
	baseIdx, _ := patternBaseIndices(patterns)
	for i, p := range patterns {
		base := firstFuncIdx + baseIdx[i]
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

// ---------------------------------------------------------------------------
// The component allocator.
//
// A component is not a module: some of what it allocates has to OUTLIVE the
// call that allocated it. A `resource` holds its state, and the input it was
// constructed from, until the handle is dropped — and a bump pointer cannot
// serve that. Measured before this was written: 20,000 construct/drop cycles
// over a 4 KB input leaked 82 MB with every handle correctly dropped, because
// `[dtor]` had nowhere to give anything back to.
//
// So this is a real allocator: segregated free lists by power-of-two SIZE
// CLASS, plus a per-call chain that the shared post-return walks.
//
//	block:  [ptr-8] class   [ptr-4] call-chain next / free-list next   [ptr] payload…
//
// Two header words, so the payload of an 8-aligned block is itself 8-aligned —
// the widest alignment the canonical ABI asks of us (`list<u64>`; a `set-match`
// record is 4, a string is 1). A wider request TRAPS rather than returning a
// misaligned pointer the host would then read through.
//
// The word at ptr-4 carries the one piece of cleverness: while the block is
// live it links the per-call chain, and while it is free it links its class's
// free list. A block is never both, so the two uses cannot collide.
//
// WHY A PER-CALL CHAIN and not a saved mark. The canonical ABI lowers a call's
// `list<u8>` argument through cabi_realloc BEFORE the exported function runs,
// so a mark taken at function entry is already too late to cover it — the same
// proof of concept measured that leak at 82 MB over 20,000 calls. A chain has
// no ordering problem: an allocation joins it wherever it is made, and
// post-return frees the lot.
//
// There is no coalescing and no splitting: a block is reused only for a request
// of its own class. That is exactly what makes a repeated identical call FLAT
// in memory — the property this allocator exists to have — and it bounds the
// waste at 2x per allocation instead of trading it for unbounded fragmentation.

const (
	// classHeadsBytes is the free-list head array: one i32 head per size class,
	// indexed by the class exponent directly. 32 entries covers every i32 size;
	// the classes below minClassShift are unreachable and cost 16 bytes of
	// address space.
	//
	// It lives in MEMORY rather than in globals because a WASM global cannot be
	// indexed, and the class is a runtime value.
	classHeadsBytes = 128

	// minClassShift is the smallest class: 16 bytes, the two header words plus
	// an 8-byte payload.
	minClassShift = 4
)

// buildComponentReallocBody emits cabi_realloc:
//
//	(old_ptr, old_size, align, new_size) → ptr
//
//	need  = new_size + 8
//	class = max(ceil_log2(need), minClassShift)
//	ptr   = pop classHeads[class], or carve 1<<class off the bump
//	*(ptr-8) = class ; *(ptr-4) = callList ; callList = ptr
//
// old_ptr/old_size stay ignored. The canonical ABI only reallocates a list it
// is growing, and nothing emitted here grows one: every result area's size is
// known before it is allocated. That is a contract met by never needing it.
func buildComponentReallocBody(heapGlobal, callListGlobal uint32, classHeadsBase int32) []byte {
	const (
		pAlign = 0x02 // param 2: align
		pSize  = 0x03 // param 3: new_size
		lP     = 0x04 // local: the payload pointer
		lClass = 0x05 // local: the size-class exponent
		lHead  = 0x06 // local: &classHeads[class]
		lEnd   = 0x07 // local: end of a freshly carved block
	)
	var b []byte
	b = append(b, 0x01, 0x04, 0x7F) // 1 local group: four i32

	// An alignment wider than the header can promise traps.
	b = append(b, 0x20, pAlign)
	b = append(b, 0x41, 0x08)
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x00)       // unreachable
	b = append(b, 0x0B)       // end if

	// class = 32 - clz(new_size + 7), floored at minClassShift.
	// new_size + 7 is (need - 1) with need = new_size + 8; a zero-size request
	// gives 32-clz(7) = 3, which the floor lifts.
	b = append(b, 0x41, 0x20) // i32.const 32
	b = append(b, 0x20, pSize)
	b = append(b, 0x41, 0x07)
	b = append(b, 0x6A)         // i32.add
	b = append(b, 0x67)         // i32.clz
	b = append(b, 0x6B)         // i32.sub  -> 32 - clz
	b = append(b, 0x22, lClass) // local.tee class
	b = append(b, 0x41, minClassShift)
	b = append(b, 0x49)       // i32.lt_u
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x41, minClassShift)
	b = append(b, 0x21, lClass)
	b = append(b, 0x0B) // end if

	// head = &classHeads[class]
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, classHeadsBase)
	b = append(b, 0x20, lClass)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, lHead)

	// p = *head
	b = append(b, 0x20, lHead)
	b = append(b, 0x28, 0x02, 0x00) // i32.load align=4 offset=0
	b = append(b, 0x22, lP)         // local.tee p
	b = append(b, 0x04, 0x40)       // if p != 0
	// reuse: *head = *(p-4)
	b = append(b, 0x20, lHead)
	b = appendLoadMinus(b, lP, 4)
	b = append(b, 0x36, 0x02, 0x00) // i32.store
	b = append(b, 0x05)             // else — carve a fresh block
	// end = heap + (1 << class)
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x20, lClass)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, lEnd)
	// grow if it does not fit; a failed grow traps rather than handing back a
	// pointer the host would read through.
	b = append(b, 0x02, 0x40) // block
	b = append(b, 0x20, lEnd)
	b = appendMemBytes(b)
	b = append(b, 0x4D)       // i32.le_u
	b = append(b, 0x0D, 0x00) // br_if 0
	b = append(b, 0x20, lEnd)
	b = appendMemBytes(b)
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x76)       // i32.shr_u
	b = append(b, 0x41, 0x01)
	b = append(b, 0x6A)       // i32.add — round up
	b = append(b, 0x40, 0x00) // memory.grow 0
	b = append(b, 0x41, 0x7F) // i32.const -1
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if
	b = append(b, 0x00)       // unreachable
	b = append(b, 0x0B)       // end if
	b = append(b, 0x0B)       // end block
	// p = heap + 8 ; heap = end
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x41, 0x08)
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, lP)
	b = append(b, 0x20, lEnd)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, heapGlobal)
	b = append(b, 0x0B) // end if/else

	// *(p-8) = class
	b = appendAddrMinus(b, lP, 8)
	b = append(b, 0x20, lClass)
	b = append(b, 0x36, 0x02, 0x00)
	// *(p-4) = callList ; callList = p
	b = appendAddrMinus(b, lP, 4)
	b = append(b, 0x23)
	b = utils.AppendULEB128(b, callListGlobal)
	b = append(b, 0x36, 0x02, 0x00)
	b = append(b, 0x20, lP)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, callListGlobal)

	b = append(b, 0x20, lP)
	b = append(b, 0x0B) // end function
	return b
}

// appendAddrMinus pushes (local - off), the address of a header word.
func appendAddrMinus(b []byte, local byte, off byte) []byte {
	b = append(b, 0x20, local)
	b = append(b, 0x41, off)
	return append(b, 0x6B) // i32.sub
}

// appendLoadMinus pushes *(local - off).
func appendLoadMinus(b []byte, local byte, off byte) []byte {
	b = appendAddrMinus(b, local, off)
	return append(b, 0x28, 0x02, 0x00) // i32.load align=4 offset=0
}

// appendMemBytes pushes memory.size * 65536.
func appendMemBytes(b []byte) []byte {
	b = append(b, 0x3F, 0x00) // memory.size 0
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 65536)
	return append(b, 0x6C) // i32.mul
}

// buildComponentFreeBody emits cm_free: (ptr i32) → ().
//
// It returns one block to its class's free list. A separate function rather than
// code inlined in the post-return because a `resource`'s destructor frees the
// same way — the state a handle owns is freed when the handle is dropped, not
// when a call ends — and two copies of a free list's update is two places for it
// to be wrong.
//
//	*(ptr-4) = classHeads[class] ; classHeads[class] = ptr
func buildComponentFreeBody(classHeadsBase int32) []byte {
	const (
		pP    = 0x00 // param 0: the block
		lHead = 0x01 // local: &classHeads[class]
	)
	var b []byte
	b = append(b, 0x01, 0x01, 0x7F) // 1 local group: one i32

	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, classHeadsBase)
	b = appendLoadMinus(b, pP, 8)
	b = append(b, 0x41, 0x02)
	b = append(b, 0x74) // i32.shl
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, lHead)

	b = appendAddrMinus(b, pP, 4)
	b = append(b, 0x20, lHead)
	b = append(b, 0x28, 0x02, 0x00)
	b = append(b, 0x36, 0x02, 0x00)
	b = append(b, 0x20, lHead)
	b = append(b, 0x20, pP)
	b = append(b, 0x36, 0x02, 0x00)
	b = append(b, 0x0B) // end function
	return b
}

// buildComponentPostBody emits cm_post: (retptr i32) → ().
//
// It walks the per-call chain, frees every block on it, then empties the chain.
// That releases the result area AND the arguments the host lowered before the
// call — which a mark taken at function entry could not have covered, since the
// lowering happens first.
//
// One function serves every export: a WASM function may be exported under any
// number of names.
func buildComponentPostBody(callListGlobal uint32, freeIdx int) []byte {
	const (
		lP    = 0x01 // local: the block being freed
		lNext = 0x02 // local: the next block, read BEFORE the free clobbers that word
	)
	var b []byte
	b = append(b, 0x01, 0x02, 0x7F) // 1 local group: two i32

	b = append(b, 0x23)
	b = utils.AppendULEB128(b, callListGlobal)
	b = append(b, 0x21, lP)

	b = append(b, 0x02, 0x40) // block
	b = append(b, 0x03, 0x40) // loop
	b = append(b, 0x20, lP)
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x0D, 0x01) // br_if 1 — chain exhausted
	b = appendLoadMinus(b, lP, 4)
	b = append(b, 0x21, lNext)
	b = append(b, 0x20, lP)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(freeIdx))
	b = append(b, 0x20, lNext)
	b = append(b, 0x21, lP)
	b = append(b, 0x0C, 0x00) // br 0
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block

	b = append(b, 0x41, 0x00)
	b = append(b, 0x24)
	b = utils.AppendULEB128(b, callListGlobal)
	b = append(b, 0x0B) // end function
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
