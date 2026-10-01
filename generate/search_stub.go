package generate

import (
	"fmt"
	"strings"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// ---------------------------------------------------------------------------
// The per-search block (internal/abi, docs/wasm.md "The search block").
//
// A find or groups export whose compiled body keeps per-search notes reads the
// address of the CURRENT search's block before every call, and a generated
// iterator owns that block: one per iterator, zeroed when the iterator is
// created, handed over before every call, and — once the module has marked the
// search armed — given (len + 1) × notes-bytes of zeroed notes. That is what
// keeps a drive linear on input that makes each call read past its match, and
// why two iterators alive at once cannot disturb each other.
//
// An export whose pattern keeps no notes reads nothing, and its stub hands
// nothing over: the generated code for it is unchanged.

// searchSizesFor compiles cfg the way the module is compiled and returns each
// find/groups export's SearchSize. A config that does not compile yields an
// empty map: the stubs then carry no block, which is what an export with no
// notes gets anyway, and the compile error is reported by `compile`.
func searchSizesFor(cfg config.BuildConfig) map[string]compile.SearchSize {
	sizes, err := compile.SearchSizes(cfg)
	if err != nil {
		return map[string]compile.SearchSize{}
	}
	return sizes
}

// anySearchBlock reports whether some export in sizes uses a block — a
// pattern's own, or a set's split members'.
func anySearchBlock(sizes map[string]compile.SearchSize) bool {
	for _, s := range sizes {
		if s.Block() || len(s.Blocks) > 0 {
			return true
		}
	}
	return false
}

// setBlocksBytes is the scratch a set iterator with search blocks carves: the
// descriptor that names them (abi.FindScratchBlocksBytes, padded to 8), then
// the blocks.
func setBlocksBytes(blocks []compile.SearchSize) int {
	return setBlocksAt + len(blocks)*abi.SearchBlockBytes
}

// blocksBTMemo reports whether some block's search keeps a Backtracking memo.
func blocksBTMemo(blocks []compile.SearchSize) bool {
	for _, s := range blocks {
		if s.BTMemoBytes > 0 {
			return true
		}
	}
	return false
}

// setBlocksAt is the first block's offset from that descriptor.
const setBlocksAt = (abi.FindScratchBlocksBytes + abi.SearchBlockAlign - 1) &^ (abi.SearchBlockAlign - 1)

// notesOOMMsg is the diagnostic a stub raises when it cannot get memory for a
// search's notes. It is abi.BTStackOverflow's case — the engine could not get
// the memory the search needs, so the answer is unknown — worded for what
// actually ran out.
func notesOOMMsg(funcName string) string {
	return fmt.Sprintf("regexped: %s: no memory for this search's notes — the match "+
		"result is unknown, not negative (see docs/wasm.md)", funcName)
}

// searchKeeps reports whether some export in sizes, or some set block, keeps
// notes, and whether one keeps a Backtracking memo: a helper nothing calls is
// not emitted (TypeScript refuses an unused one).
func searchKeeps(sizes map[string]compile.SearchSize) (notes, btMemo bool) {
	for _, s := range sizes {
		notes = notes || s.NotesBytes > 0
		btMemo = btMemo || s.BTMemoBytes > 0
		for _, b := range s.Blocks {
			notes = notes || b.NotesBytes > 0
			btMemo = btMemo || b.BTMemoBytes > 0
		}
	}
	return notes, btMemo
}

// jsSearchHelpers is the JS/TS helpers that allocate a search's notes once
// the module has armed it and a Backtracking search's memo once it has
// tripped — each only when sizes has a caller for it. ts adds the
// annotations.
func jsSearchHelpers(ts bool, sizes map[string]compile.SearchSize) string {
	notes, btMemo := searchKeeps(sizes)
	out := ""
	if notes {
		out += jsNotesHelper(ts)
	}
	if btMemo {
		out += jsBTMemoHelper(ts)
	}
	return out
}

// jsNotesHelper is the JS/TS helper that allocates a search's notes once the
// module has armed it.
func jsNotesHelper(ts bool) string {
	sig := "function _notes(blk, len, nb, name) {"
	if ts {
		sig = "function _notes(blk: number, len: number, nb: number, name: string): void {"
	}
	mem := "_exp.memory.buffer"
	if ts {
		mem = "(_exp.memory as WebAssembly.Memory).buffer"
	}
	return fmt.Sprintf(`%[1]s
    // A search the module has marked armed — it read past its matches often
    // enough to go quadratic — gets its notes, which the module then reads and
    // writes on every later call of this search (docs/wasm.md, "The search
    // block"). Carved from the bump like a region, so they live as long as
    // the iterators do.
    const dv = new DataView(%[2]s);
    if (dv.getUint32(blk + %[3]d, true) === 0 || dv.getUint32(blk + %[4]d, true) !== 0) return;
    const n = (len + 1) * nb, at = _align(_bump);
    try {
        _grow(at + n);
    } catch (e) {
        if (e instanceof RangeError) throw new Error("regexped: " + name + ": no memory for this search's notes — the match result is unknown, not negative (see docs/wasm.md)");
        throw e;
    }
    _bump = at + n;
    _mem.fill(0, at, at + n);
    const dw = new DataView(%[2]s);
    dw.setUint32(blk + %[4]d, at, true);
    dw.setUint32(blk + %[5]d, n, true);
}

`, sig, mem, abi.SearchArmedOff, abi.SearchNotesOff, abi.SearchNotesCapOff)
}

// jsBTMemoHelper is the JS/TS helper that gives a Backtracking search that
// TRIPPED its memo (bt_search.go in compile/).
func jsBTMemoHelper(ts bool) string {
	sig := "function _btmemo(blk, len, nb, name) {"
	mem := "_exp.memory.buffer"
	if ts {
		sig = "function _btmemo(blk: number, len: number, nb: number, name: string): void {"
		mem = "(_exp.memory as WebAssembly.Memory).buffer"
	}
	return fmt.Sprintf(`%[1]s
    // A Backtracking search whose work budget ran out gets the memo its
    // fallback then keeps for the rest of the search, so a (state, position)
    // one call ruled out stays ruled out in the next.
    const dv = new DataView(%[2]s);
    if (dv.getUint32(blk + %[3]d, true) !== 2 || dv.getUint32(blk + %[4]d, true) !== 0) return;
    const n = (len + 1) * nb, at = _align(_bump);
    try {
        _grow(at + n);
    } catch (e) {
        if (e instanceof RangeError) throw new Error("regexped: " + name + ": no memory for this search's memo — the match result is unknown, not negative (see docs/wasm.md)");
        throw e;
    }
    _bump = at + n;
    _mem.fill(0, at, at + n);
    const dw = new DataView(%[2]s);
    dw.setUint32(blk + %[4]d, at, true);
    dw.setUint32(blk + %[5]d, n, true);
}
`, sig, mem, abi.SearchBTStateOff, abi.SearchBTMemoOff, abi.SearchBTMemoCapOff)
}

// jsSearchParts are the lines a JS/TS find or groups generator adds when its
// export keeps notes, all empty when it does not.
type jsSearchParts struct {
	open   string // the extra bytes _open reserves, appended to its outBytes
	decl   string // after _open: the block, zeroed
	before string // before every export call: hand the block over
	after  string // after a call that reported a match: notes on arming
}

func jsSearch(funcName string, sz compile.SearchSize, outBytes string, ts bool) jsSearchParts {
	if !sz.Block() {
		return jsSearchParts{}
	}
	global := "_exp['" + abi.SearchExport + "'].value"
	if ts {
		global = "(_exp['" + abi.SearchExport + "'] as WebAssembly.Global).value"
	}
	return jsSearchParts{
		open: fmt.Sprintf(" + %d", abi.SearchBlockBytes),
		decl: fmt.Sprintf("    // This search's block (docs/wasm.md, \"The search block\"): one per\n"+
			"    // iterator, in its own region, so two scans in flight never share notes.\n"+
			"    const _blk = _outBase + (%s);\n"+
			"    _mem.fill(0, _blk, _blk + %d);\n", outBytes, abi.SearchBlockBytes),
		before: global + " = _blk;",
		after:  jsAfterCall(funcName, sz),
	}
}

// jsAfterCall is what a JS/TS iterator runs after a call that reported a
// match: notes for a search that armed, the Backtracking memo for one that
// tripped. "" when the export keeps neither.
func jsAfterCall(funcName string, sz compile.SearchSize) string {
	var parts []string
	if sz.NotesBytes > 0 {
		parts = append(parts, fmt.Sprintf("_notes(_blk, len, %d, '%s');", sz.NotesBytes, funcName))
	}
	if sz.BTMemoBytes > 0 {
		parts = append(parts, fmt.Sprintf("_btmemo(_blk, len, %d, '%s');", sz.BTMemoBytes, funcName))
	}
	return strings.Join(parts, " ")
}

// jsWithSearch adds the search block to a generated JS or TS find/groups
// generator (genJSFindFunc and friends), or returns src unchanged when nb is 0.
// It edits the generated text at anchors it asserts are present, so a template
// change that moves one fails every stub test instead of shipping a generator
// that hands over no block.
//
// The block sits in the iterator's own region after whatever the region's out
// area holds: the batch buffer, or a groups call's slots.
func jsWithSearch(src, funcName string, sz compile.SearchSize, ts, groups bool, slotBytes int) string {
	if !sz.Block() {
		return src
	}
	lines := strings.Split(src, "\n")
	indentOf := func(s string) string { return s[:len(s)-len(strings.TrimLeft(s, " "))] }
	var out []string
	found := map[string]bool{}
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "const [_inBase, _outBase, len] = _open(input, _batched ? ") && strings.HasSuffix(t, " : 0);"):
			expr := strings.TrimSuffix(strings.TrimPrefix(t, "const [_inBase, _outBase, len] = _open(input, "), ");")
			if groups {
				expr = strings.TrimSuffix(expr, " : 0") + fmt.Sprintf(" : %d", (slotBytes+7)&^7)
			}
			p := jsSearch(funcName, sz, expr, ts)
			out = append(out, indentOf(ln)+"const [_inBase, _outBase, len] = _open(input, ("+expr+")"+p.open+");")
			out = append(out, strings.Split(strings.TrimSuffix(p.decl, "\n"), "\n")...)
			found["open"] = true
			continue
		case strings.HasPrefix(t, "const n = ") && strings.Contains(t, "'"+funcName+"_batch'"):
			out = append(out, indentOf(ln)+jsSearch(funcName, sz, "", ts).before)
			found["batch"] = true
		case strings.HasPrefix(t, "const r = ") && strings.Contains(t, "'"+funcName+"'"):
			out = append(out, indentOf(ln)+jsSearch(funcName, sz, "", ts).before)
			found["call"] = true
		}
		out = append(out, ln)
		switch {
		case t == "if (n <= 0) break;":
			if a := jsSearch(funcName, sz, "", ts).after; a != "" {
				out = append(out, indentOf(ln)+a)
			}
			found["batchAfter"] = true
		case !groups && t == "if (r < 0n) break;":
			if a := jsSearch(funcName, sz, "", ts).after; a != "" {
				out = append(out, indentOf(ln)+a)
			}
			found["callAfter"] = true
		case groups && strings.HasPrefix(t, "const matchEnd = ") && i > 0:
			// After the terminal check; the notes may grow memory, which
			// detaches the slots view read just below.
			last := out[len(out)-1]
			out = out[:len(out)-1]
			if a := jsSearch(funcName, sz, "", ts).after; a != "" {
				out = append(out, indentOf(ln)+a,
					indentOf(ln)+fmt.Sprintf("slots = _att(slots, Int32Array, _outBase, %d);", slotBytes/4))
			}
			out = append(out, last)
			found["callAfter"] = true
		}
	}
	for _, k := range []string{"open", "batch", "call", "batchAfter", "callAfter"} {
		if !found[k] {
			panic("generate: jsWithSearch found no " + k + " anchor in the " + funcName + " generator")
		}
	}
	return strings.Join(out, "\n")
}

// rustSearchPreamble is emitted once per Rust stub that has a notes-keeping
// export: the setter import, the block type and the notes helper.
func rustSearchPreamble(importModule string) string {
	return fmt.Sprintf(`#[link(wasm_import_module = %[1]q)]
unsafe extern "C" {
    #[link_name = %[2]q]
    fn ffi_regexped_search(blk: *mut u8);
}

/// One search's block (docs/wasm.md, "The search block"): opaque, zeroed when
/// its iterator is created and handed to the module before every call. It lives
/// INSIDE the iterator, so two iterators in flight never share notes; moving
/// the iterator between calls moves the block with it, which is fine — the
/// module reads it only during a call.
#[repr(C, align(8))]
struct SearchBlock([u8; %[3]d]);

/// Gives a search the module has marked ARMED — it read past its matches often
/// enough to go quadratic — its notes: (len + 1) × nb zeroed bytes, which the
/// module then reads and writes on every later call of the search.
///
/// # Errors
/// Err(Error::BacktrackOverflow) when the notes cannot be allocated: the
/// search cannot continue at its bound, and its answer is unknown.
#[allow(dead_code)]
fn search_notes(blk: &mut SearchBlock, notes: &mut Vec<u8>, len: usize, nb: usize) -> Result<()> {
    let field = |b: &SearchBlock, at: usize| u32::from_le_bytes([b.0[at], b.0[at + 1], b.0[at + 2], b.0[at + 3]]);
    if field(blk, %[4]d) == 0 || field(blk, %[5]d) != 0 {
        return Ok(());
    }
    let n = (len + 1) * nb;
    notes.try_reserve_exact(n).map_err(|_| Error::BacktrackOverflow)?;
    notes.resize(n, 0);
    blk.0[%[5]d..%[5]d + 4].copy_from_slice(&(notes.as_ptr() as usize as u32).to_le_bytes());
    blk.0[%[6]d..%[6]d + 4].copy_from_slice(&(n as u32).to_le_bytes());
    Ok(())
}

/// Gives a Backtracking search whose work budget TRIPPED its memo: (len + 1) ×
/// nb zeroed bytes its fallback keeps for the rest of the search.
///
/// # Errors
/// Err(Error::BacktrackOverflow) when the memo cannot be allocated.
#[allow(dead_code)]
fn search_btmemo(blk: &mut SearchBlock, memo: &mut Vec<u8>, len: usize, nb: usize) -> Result<()> {
    let field = |b: &SearchBlock, at: usize| u32::from_le_bytes([b.0[at], b.0[at + 1], b.0[at + 2], b.0[at + 3]]);
    if field(blk, %[7]d) != 2 || field(blk, %[8]d) != 0 {
        return Ok(());
    }
    let n = (len + 1) * nb;
    memo.try_reserve_exact(n).map_err(|_| Error::BacktrackOverflow)?;
    memo.resize(n, 0);
    blk.0[%[8]d..%[8]d + 4].copy_from_slice(&(memo.as_ptr() as usize as u32).to_le_bytes());
    blk.0[%[9]d..%[9]d + 4].copy_from_slice(&(n as u32).to_le_bytes());
    Ok(())
}

`, importModule, abi.SearchExport, abi.SearchBlockBytes, abi.SearchArmedOff, abi.SearchNotesOff, abi.SearchNotesCapOff,
		abi.SearchBTStateOff, abi.SearchBTMemoOff, abi.SearchBTMemoCapOff)
}

// rustWithSearch adds the block to a generated Rust find or groups iterator
// (genRustFindIterStub / genRustGroupsIterStub), or returns src unchanged when
// nb is 0. Anchors are asserted, as for jsWithSearch.
func rustWithSearch(src, funcName, iterName string, sz compile.SearchSize, groups bool) string {
	if !sz.Block() {
		return src
	}
	rep := func(old, new string) {
		if strings.Count(src, old) != 1 {
			panic("generate: rustWithSearch: anchor not found once in the " + funcName + " iterator: " + old)
		}
		src = strings.Replace(src, old, new, 1)
	}
	// The struct: the block and the notes, after the terminal flag.
	rep("    done: bool,\n}\n", "    done: bool,\n"+
		"    /// This search's block and, once it arms, its notes; once its\n"+
		"    /// Backtracking budget trips, its memo (docs/wasm.md).\n"+
		"    search: SearchBlock,\n    notes: Vec<u8>,\n    btmemo: Vec<u8>,\n}\n")
	// The constructor.
	rep(iterName+" { input, offset, prev_end: None, done: false }",
		fmt.Sprintf("%s { input, offset, prev_end: None, done: false, search: SearchBlock([0; %d]), notes: Vec::new(), btmemo: Vec::new() }",
			iterName, abi.SearchBlockBytes))
	after := func(indent string) string {
		var out string
		if sz.NotesBytes > 0 {
			out += indent + fmt.Sprintf("if let Err(e) = search_notes(&mut self.search, &mut self.notes, self.input.len(), %d) {\n", sz.NotesBytes) +
				indent + "    self.done = true;\n" + indent + "    return Some(Err(e));\n" + indent + "}\n"
		}
		if sz.BTMemoBytes > 0 {
			out += indent + fmt.Sprintf("if let Err(e) = search_btmemo(&mut self.search, &mut self.btmemo, self.input.len(), %d) {\n", sz.BTMemoBytes) +
				indent + "    self.done = true;\n" + indent + "    return Some(Err(e));\n" + indent + "}\n"
		}
		return out
	}
	if !groups {
		rep("        match unsafe { ffi_"+funcName+"(",
			"        unsafe { ffi_regexped_search(self.search.0.as_mut_ptr()) };\n        match unsafe { ffi_"+funcName+"(")
		rep("            n  => {\n", "            n  => {\n"+after("                "))
		return src
	}
	rep("            let r = unsafe {",
		"            unsafe { ffi_regexped_search(self.search.0.as_mut_ptr()) };\n            let r = unsafe {")
	rep("            // Slots are ABSOLUTE: the whole input is passed on every call.\n",
		after("            ")+"            // Slots are ABSOLUTE: the whole input is passed on every call.\n")
	return src
}

// goSearchPreamble is emitted once per Go stub that has a notes-keeping
// export.
func goSearchPreamble(importModule string) string {
	return fmt.Sprintf(`// searchBlock is one search's block (docs/wasm.md, "The search block"):
// opaque, zeroed with its iterator and handed to the module before every call.
// It lives inside the iterator, so two iterators in flight never share notes;
// Go does not move heap objects, so its address holds for the iterator's life.
type searchBlock [%[3]d]uint64

//go:wasmimport %[1]s %[2]s
//go:noescape
func ffi_regexped_search(blk unsafe.Pointer)

// searchNotes gives a search the module has marked ARMED — it read past its
// matches often enough to go quadratic — its notes: (length + 1) × nb zeroed
// bytes the module reads and writes on every later call of the search. A
// failed allocation is fatal here, as every Go allocation is.
func searchNotes(blk *searchBlock, notes *[]byte, length, nb int) {
	w := (*[%[4]d]uint32)(unsafe.Pointer(blk))
	if w[%[5]d] == 0 || w[%[6]d] != 0 {
		return
	}
	*notes = make([]byte, (length+1)*nb)
	w[%[6]d] = uint32(uintptr(unsafe.Pointer(&(*notes)[0])))
	w[%[7]d] = uint32(len(*notes))
}

// searchBTMemo gives a Backtracking search whose work budget TRIPPED its memo:
// (length + 1) × nb zeroed bytes its fallback keeps for the rest of the search.
func searchBTMemo(blk *searchBlock, memo *[]byte, length, nb int) {
	w := (*[%[4]d]uint32)(unsafe.Pointer(blk))
	if w[%[8]d] != 2 || w[%[9]d] != 0 {
		return
	}
	*memo = make([]byte, (length+1)*nb)
	w[%[9]d] = uint32(uintptr(unsafe.Pointer(&(*memo)[0])))
	w[%[10]d] = uint32(len(*memo))
}

`, importModule, abi.SearchExport, abi.SearchBlockBytes/8, abi.SearchBlockBytes/4,
		abi.SearchArmedOff/4, abi.SearchNotesOff/4, abi.SearchNotesCapOff/4,
		abi.SearchBTStateOff/4, abi.SearchBTMemoOff/4, abi.SearchBTMemoCapOff/4)
}

// goWithSearch adds the block to a generated Go find or groups iterator
// (genGoFindStub / genGoGroupsStub), or returns src unchanged when nb is 0.
func goWithSearch(src, funcName, ffi string, sz compile.SearchSize, groups bool) string {
	if !sz.Block() {
		return src
	}
	rep := func(old, new string) {
		if strings.Count(src, old) != 1 {
			panic("generate: goWithSearch: anchor not found once in the " + funcName + " iterator: " + old)
		}
		src = strings.Replace(src, old, new, 1)
	}
	fields := "\t// This search's block and, once it arms, its notes; once its\n" +
		"\t// Backtracking budget trips, its memo (docs/wasm.md).\n" +
		"\tsearch searchBlock\n\tnotes  []byte\n\tbtmemo []byte\n"
	notes := ""
	if sz.NotesBytes > 0 {
		notes += fmt.Sprintf("\t\t\tsearchNotes(&iter.search, &iter.notes, len(input), %d)\n", sz.NotesBytes)
	}
	if sz.BTMemoBytes > 0 {
		notes += fmt.Sprintf("\t\t\tsearchBTMemo(&iter.search, &iter.btmemo, len(input), %d)\n", sz.BTMemoBytes)
	}
	set := "\t\t\tffi_regexped_search(unsafe.Pointer(&iter.search))\n"
	if !groups {
		rep("\tdone bool\n}\n", "\tdone bool\n"+fields+"}\n")
		rep("\t\t\tpacked := "+ffi+"(", set+"\t\t\tpacked := "+ffi+"(")
		rep("\t\t\tstart := int(uint64(packed) >> 32)\n", notes+"\t\t\tstart := int(uint64(packed) >> 32)\n")
		return src
	}
	rep("\tdone   bool\n", "\tdone   bool\n"+fields)
	rep("\t\t\tresult := "+ffi+"(", set+"\t\t\tresult := "+ffi+"(")
	rep("\t\t\tgroups := make([]Span, ", notes+"\t\t\tgroups := make([]Span, ")
	return src
}

// cSearchPreamble is the header part that decides whether the C stub may
// allocate a search's notes; emitted after the answer cache's block, so a
// -nostdlib build's -DRX_SET_CACHE=0 turns this off too.
const cSearchPreamble = `/* A search that re-reads its input gets per-search NOTES (docs/wasm.md, "The
   search block"), allocated with calloc and released by the iterator's _free.
   Detected, not demanded, exactly like RX_SET_CACHE, and switched off with it:
   a -nostdlib build that passes -DRX_SET_CACHE=0 gets RX_SEARCH_NOTES 0 too.

   ON  -> every find and groups scan is linear.
   OFF -> a scan over input that makes each call read past its match stays
          quadratic, with identical answers. */
#ifndef RX_SEARCH_NOTES
#  if defined(RX_SET_CACHE)
#    define RX_SEARCH_NOTES RX_SET_CACHE
#  elif defined(__has_include)
#    if __has_include(<stdlib.h>)
#      define RX_SEARCH_NOTES 1
#    else
#      define RX_SEARCH_NOTES 0
#    endif
#  else
#    define RX_SEARCH_NOTES 0
#  endif
#endif
#if RX_SEARCH_NOTES
#include <stdlib.h>
#endif

`

// cSearchCPreamble is the .c part: the setter import and the notes helper.
func cSearchCPreamble(importModule string) string {
	return fmt.Sprintf(`__attribute__((import_module(%[1]q), import_name(%[2]q)))
extern void rx_search_set_(unsigned long long *blk);

/* Gives a search the module has marked ARMED — it read past its matches often
   enough to go quadratic — its notes: (len + 1) × nb zeroed bytes the module
   reads and writes on every later call of the search. Returns 0, or
   RX_ERR_BT_OVERFLOW when they cannot be allocated: the answer is then
   unknown. Without an allocator (RX_SEARCH_NOTES 0) it does nothing. */
__attribute__((unused)) static int rx_search_notes_(unsigned long long *blk, unsigned char **notes, size_t len, size_t nb) {
#if RX_SEARCH_NOTES
    unsigned *w = (unsigned *)blk;
    if (w[%[3]d] == 0 || w[%[4]d] != 0) return 0;
    size_t n = (len + 1) * nb;
    unsigned char *p = (unsigned char *)calloc(n, 1);
    if (!p) return RX_ERR_BT_OVERFLOW;
    *notes = p;
    w[%[4]d] = (unsigned)(size_t)p;
    w[%[5]d] = (unsigned)n;
#else
    (void)blk; (void)notes; (void)len; (void)nb;
#endif
    return 0;
}

/* Gives a Backtracking search whose work budget TRIPPED its memo: (len + 1) ×
   nb zeroed bytes its fallback keeps for the rest of the search. Returns 0, or
   RX_ERR_BT_OVERFLOW when it cannot be allocated. */
__attribute__((unused)) static int rx_search_btmemo_(unsigned long long *blk, unsigned char **memo, size_t len, size_t nb) {
#if RX_SEARCH_NOTES
    unsigned *w = (unsigned *)blk;
    if (w[%[6]d] != 2 || w[%[7]d] != 0) return 0;
    size_t n = (len + 1) * nb;
    unsigned char *p = (unsigned char *)calloc(n, 1);
    if (!p) return RX_ERR_BT_OVERFLOW;
    *memo = p;
    w[%[7]d] = (unsigned)(size_t)p;
    w[%[8]d] = (unsigned)n;
#else
    (void)blk; (void)memo; (void)len; (void)nb;
#endif
    return 0;
}

`, importModule, abi.SearchExport, abi.SearchArmedOff/4, abi.SearchNotesOff/4, abi.SearchNotesCapOff/4,
		abi.SearchBTStateOff/4, abi.SearchBTMemoOff/4, abi.SearchBTMemoCapOff/4)
}

// cWithSearch adds the block to a generated C find or groups iterator — its
// header part and its .c part — or returns both unchanged when nb is 0.
func cWithSearch(h, c, funcName, iterType, ffi string, sz compile.SearchSize, groups bool) (string, string) {
	if !sz.Block() {
		return h, c
	}
	rep := func(src *string, old, new string) {
		if strings.Count(*src, old) != 1 {
			panic("generate: cWithSearch: anchor not found once in the " + funcName + " iterator: " + old)
		}
		*src = strings.Replace(*src, old, new, 1)
	}
	rep(&h, "    unsigned scratch[2];\n} "+iterType+";",
		"    unsigned scratch[2];\n"+
			"    /* This search's block and, once it arms, its notes (docs/wasm.md, \"The\n"+
			"       search block\"). Opaque; _free releases the notes. */\n"+
			fmt.Sprintf("    unsigned long long search[%d];\n", abi.SearchBlockBytes/8)+
			"    unsigned char *notes, *btmemo;\n} "+iterType+";")
	rep(&c, "    iter->scratch[1] = 0;\n    return 0;\n}",
		fmt.Sprintf("    iter->scratch[1] = 0;\n    for (int w = 0; w < %d; w++) iter->search[w] = 0;\n    iter->notes = 0;\n    iter->btmemo = 0;\n    return 0;\n}",
			abi.SearchBlockBytes/8))
	rep(&c, "    if (!iter) return;\n    iter->done = 1;\n}",
		"    if (!iter) return;\n    iter->done = 1;\n#if RX_SEARCH_NOTES\n"+
			"    /* The notes and memo a search that went bad was given: _free is REQUIRED\n"+
			"       for this iterator under wasm_format: module too. */\n"+
			"    if (iter->notes) { free(iter->notes); iter->notes = 0; }\n"+
			"    if (iter->btmemo) { free(iter->btmemo); iter->btmemo = 0; }\n#endif\n}")
	notes := ""
	if sz.NotesBytes > 0 {
		notes += fmt.Sprintf("        { int nerr = rx_search_notes_(iter->search, &iter->notes, iter->len, %d);\n"+
			"          if (nerr) { iter->done = 1; return nerr; } }\n", sz.NotesBytes)
	}
	if sz.BTMemoBytes > 0 {
		notes += fmt.Sprintf("        { int nerr = rx_search_btmemo_(iter->search, &iter->btmemo, iter->len, %d);\n"+
			"          if (nerr) { iter->done = 1; return nerr; } }\n", sz.BTMemoBytes)
	}
	if !groups {
		rep(&h, "   iterator strands the input copy and the scan state inside the regexp\n"+
			"   component for the life of the process. Under wasm_format: module it is a\n"+
			"   no-op — the iterator is caller-owned, by value, and holds a borrowed input\n"+
			"   pointer — and is emitted anyway so the SAME source compiles against either\n"+
			"   format.\n",
			"   iterator strands the input copy and the scan state inside the regexp\n"+
				"   component for the life of the process. Under wasm_format: module it is\n"+
				"   REQUIRED as well: it frees the notes a scan over input that makes each\n"+
				"   call read past its match was given (docs/wasm.md).\n")
		rep(&c, "        long long packed = "+ffi+"(", "        rx_search_set_(iter->search);\n        long long packed = "+ffi+"(")
		rep(&c, "        if (packed < 0) { iter->done = 1; return 0; }\n",
			"        if (packed < 0) { iter->done = 1; return 0; }\n"+notes)
		return h, c
	}
	rep(&h, "   wasm_format: component it drops the resource handle and is REQUIRED,\n"+
		"   including before initialising the same iterator again. */",
		"   wasm_format: component it drops the resource handle and is REQUIRED,\n"+
			"   including before initialising the same iterator again; under\n"+
			"   wasm_format: module it frees the scan's notes (docs/wasm.md) and is\n"+
			"   REQUIRED too. */")
	rep(&c, "        int status = "+ffi+"(", "        rx_search_set_(iter->search);\n        int status = "+ffi+"(")
	rep(&c, "        size_t start = (size_t)slots[0];\n", notes+"        size_t start = (size_t)slots[0];\n")
	return h, c
}

// asSearchPreamble is emitted once per AssemblyScript stub that has a
// notes-keeping export.
func asSearchPreamble(importModule string) string {
	return fmt.Sprintf(`@external(%[1]q, %[2]q)
declare function _ffi_regexped_search(blk: usize): void;

/** Gives a search the module has marked ARMED — it read past its matches
 *  often enough to go quadratic — its notes: (len + 1) * nb zeroed bytes the
 *  module reads and writes on every later call of the search (docs/wasm.md,
 *  "The search block"). null when it has not armed or already has them. A
 *  failed allocation traps, as every AssemblyScript allocation does. */
function _searchNotes(blk: StaticArray<u64>, len: i32, nb: i32): StaticArray<u8> | null {
  const b = changetype<usize>(blk);
  if (load<u32>(b + %[3]d) == 0 || load<u32>(b + %[4]d) != 0) return null;
  const notes = new StaticArray<u8>((len + 1) * nb);
  store<u32>(b + %[4]d, u32(changetype<usize>(notes)));
  store<u32>(b + %[5]d, u32((len + 1) * nb));
  return notes;
}

/** Gives a Backtracking search whose work budget TRIPPED its memo: (len + 1)
 *  * nb zeroed bytes its fallback keeps for the rest of the search. */
function _searchBTMemo(blk: StaticArray<u64>, len: i32, nb: i32): StaticArray<u8> | null {
  const b = changetype<usize>(blk);
  if (load<u32>(b + %[6]d) != 2 || load<u32>(b + %[7]d) != 0) return null;
  const memo = new StaticArray<u8>((len + 1) * nb);
  store<u32>(b + %[7]d, u32(changetype<usize>(memo)));
  store<u32>(b + %[8]d, u32((len + 1) * nb));
  return memo;
}

`, importModule, abi.SearchExport, abi.SearchArmedOff, abi.SearchNotesOff, abi.SearchNotesCapOff,
		abi.SearchBTStateOff, abi.SearchBTMemoOff, abi.SearchBTMemoCapOff)
}

// asWithSearch adds the block to a generated AssemblyScript find or groups
// iterator, or returns src unchanged when nb is 0.
func asWithSearch(src, funcName, ffi string, sz compile.SearchSize, groups bool) string {
	if !sz.Block() {
		return src
	}
	rep := func(old, new string) {
		if strings.Count(src, old) != 1 {
			panic("generate: asWithSearch: anchor not found once in the " + funcName + " iterator: " + old)
		}
		src = strings.Replace(src, old, new, 1)
	}
	fields := "  // This search's block and, once it arms, its notes (docs/wasm.md). The\n" +
		"  // block is a StaticArray, so its address IS its data and does not move.\n" +
		fmt.Sprintf("  private search: StaticArray<u64> = new StaticArray<u64>(%d);\n", abi.SearchBlockBytes/8) +
		"  private notes: StaticArray<u8> | null = null;\n" +
		"  private btmemo: StaticArray<u8> | null = null;\n"
	set := "      _ffi_regexped_search(changetype<usize>(this.search));\n"
	notes := ""
	if sz.NotesBytes > 0 {
		notes += fmt.Sprintf("      const armed = _searchNotes(this.search, len, %d);\n      if (armed != null) this.notes = armed;\n", sz.NotesBytes)
	}
	if sz.BTMemoBytes > 0 {
		notes += fmt.Sprintf("      const tripped = _searchBTMemo(this.search, len, %d);\n      if (tripped != null) this.btmemo = tripped;\n", sz.BTMemoBytes)
	}
	if !groups {
		rep("  private done: bool = false;\n  constructor", "  private done: bool = false;\n"+fields+"  constructor")
		rep("      const packed = "+ffi+"(", set+"      const packed = "+ffi+"(")
		rep("      if (packed < 0) { this.done = true; return -1; }\n", "      if (packed < 0) { this.done = true; return -1; }\n"+notes)
		return src
	}
	rep("  private slots: Int32Array = new Int32Array(", fields+"  private slots: Int32Array = new Int32Array(")
	rep("      const status = "+ffi+"(", set+"      const status = "+ffi+"(")
	rep("      const start = this.slots[0];\n", notes+"      const start = this.slots[0];\n")
	return src
}

// ---------------------------------------------------------------------------
// A SET's split members (compile/set_split.go) keep a search block each: their
// searches span the set's calls exactly as a pattern's search spans its
// iterator's. The set takes them through a second form of its scratch
// descriptor (abi.FindScratchMagicBlocks), which a set iterator carves beside
// its own scratch: the descriptor first — the four ordinary fields copied, the
// blocks pointer fifth — then one zeroed block per member. After every call,
// an armed member block gets its notes exactly as a pattern's block does.

// jsSetWithBlocks adds the members' blocks to the set's `find` generator and,
// if there is one, its batching form in a generated JS/TS set section, or
// returns section unchanged when blocks is empty. Anchors are asserted.
func jsSetWithBlocks(section, find string, blocks []compile.SearchSize, ts bool) string {
	if len(blocks) == 0 {
		return section
	}
	mem := "_exp.memory.buffer"
	if ts {
		mem = "(_exp.memory as WebAssembly.Memory).buffer"
	}
	notes := func(indent string) string {
		var b strings.Builder
		for k, sz := range blocks {
			if sz.NotesBytes > 0 {
				fmt.Fprintf(&b, "%s_notes(_sd + %d, len, %d, '%s');\n", indent, setBlocksAt+k*abi.SearchBlockBytes, sz.NotesBytes, find)
			}
			if sz.BTMemoBytes > 0 {
				fmt.Fprintf(&b, "%s_btmemo(_sd + %d, len, %d, '%s');\n", indent, setBlocksAt+k*abi.SearchBlockBytes, sz.BTMemoBytes, find)
			}
		}
		return b.String()
	}
	setup := fmt.Sprintf(`    // The split members' search blocks (docs/wasm.md, "The search block"),
    // one per member and per iterator, named by a second descriptor that
    // carries them: the module reads the ordinary one's four fields from it.
    const _sd = _align(_bump), _sdEnd = _sd + %[1]d;
    try {
        _grow(_sdEnd);
    } catch (e) {
        if (e instanceof RangeError) throw new Error("regexped: %[2]s: no memory for this scan's search blocks");
        throw e;
    }
    _bump = _sdEnd;
    _mem.fill(0, _sd, _sdEnd);
    {
        const _d = new Uint32Array(%[3]s, scratchBase, 4);
        new Uint32Array(%[3]s, _sd, 5).set([%[4]d, _d[1], _d[2], _d[3], _sd + %[5]d]);
    }
`, setBlocksBytes(blocks), find, mem, abi.FindScratchMagicBlocks, setBlocksAt)
	edit := func(fn string, batch bool) {
		head := "export function* " + fn + "("
		i := strings.Index(section, head)
		if i < 0 {
			panic("generate: jsSetWithBlocks: no generator " + fn)
		}
		j := strings.Index(section[i:], "\n}\n")
		if j < 0 {
			panic("generate: jsSetWithBlocks: unterminated generator " + fn)
		}
		body := section[i : i+j]
		rep := func(old, new string) {
			if strings.Count(body, old) != 1 {
				panic("generate: jsSetWithBlocks: anchor not found once in " + fn + ": " + old)
			}
			body = strings.Replace(body, old, new, 1)
		}
		// After the ordinary descriptor is written.
		k := strings.Index(body, ", scratchBase, 4).set([")
		if k < 0 {
			panic("generate: jsSetWithBlocks: no descriptor in " + fn)
		}
		e := strings.Index(body[k:], "\n") + k + 1
		body = body[:e] + setup + body[e:]
		if batch {
			rep("_exp['"+config.SetBatchExportName(find)+"'](_inBase, len, cursor, scratchBase, ",
				"_exp['"+config.SetBatchExportName(find)+"'](_inBase, len, cursor, _sd, ")
			rep("        const done = (BigInt.asUintN(64, packed) >> 32n) === 0xFFFFFFFFn;\n",
				"        const done = (BigInt.asUintN(64, packed) >> 32n) === 0xFFFFFFFFn;\n        if (!done) {\n"+notes("            ")+"        }\n")
		} else {
			rep("scratchBase, _outBase, ", "_sd, _outBase, ")
			rep("        if (n <= 0) break;\n", "        if (n <= 0) break;\n"+notes("        "))
		}
		section = section[:i] + body + section[i+j:]
	}
	edit(find, strings.Contains(section, "_exp['"+config.SetBatchExportName(find)+"']("))
	return section
}

// goSetWithBlocks adds the members' blocks to a generated Go set iterator
// (genGoSetBody), or returns body unchanged when blocks is empty.
func goSetWithBlocks(body, find string, blocks []compile.SearchSize) string {
	if len(blocks) == 0 {
		return body
	}
	i := strings.Index(body, "type "+find+"Iter struct {")
	if i < 0 {
		panic("generate: goSetWithBlocks: no iterator for " + find)
	}
	j := strings.Index(body[i+1:], "\ntype ")
	if j < 0 {
		j = len(body)
	} else {
		j += i + 1
	}
	src := body[i:j]
	rep := func(old, new string) {
		if strings.Count(src, old) != 1 {
			panic("generate: goSetWithBlocks: anchor not found once in the " + find + " iterator: " + old)
		}
		src = strings.Replace(src, old, new, 1)
	}
	rep("\tscratch [4]uint32\n", "\tscratch [5]uint32\n"+
		"\t// The set's search blocks (docs/wasm.md, \"The search block\"), named\n"+
		"\t// by the descriptor's fifth field, their notes once one arms and their\n"+
		"\t// Backtracking memos once one trips.\n"+
		"\tblocks  []searchBlock\n\tnotes   [][]byte\n\tbtmemos [][]byte\n")
	rep("\t\titer.scratch[0] = "+fmt.Sprint(abi.FindScratchMagic)+"\n",
		fmt.Sprintf("\t\tif iter.blocks == nil {\n\t\t\titer.blocks = make([]searchBlock, %[1]d)\n\t\t\titer.notes = make([][]byte, %[1]d)\n\t\t\titer.btmemos = make([][]byte, %[1]d)\n\t\t}\n", len(blocks))+
			"\t\titer.scratch[0] = "+fmt.Sprint(abi.FindScratchMagicBlocks)+"\n"+
			"\t\titer.scratch[4] = uint32(uintptr(unsafe.Pointer(&iter.blocks[0])))\n")
	var notes strings.Builder
	for k, sz := range blocks {
		if sz.NotesBytes > 0 {
			fmt.Fprintf(&notes, "\t\t\tsearchNotes(&iter.blocks[%d], &iter.notes[%d], len(input), %d)\n", k, k, sz.NotesBytes)
		}
		if sz.BTMemoBytes > 0 {
			fmt.Fprintf(&notes, "\t\t\tsearchBTMemo(&iter.blocks[%d], &iter.btmemos[%d], len(input), %d)\n", k, k, sz.BTMemoBytes)
		}
	}
	rep("\t\t\titer.pending, iter.consumed = tupleCount, 0\n", notes.String()+"\t\t\titer.pending, iter.consumed = tupleCount, 0\n")
	return body[:i] + src + body[j:]
}
