// Package abi holds the numeric return-value contract shared between the WASM
// code the compiler emits (compile/) and the host-side stubs it generates
// (generate/). Neither package imports the other, so a constant that must mean
// the same thing on both sides of the WASM boundary lives here.
//
// Every exported matcher signals failure with a negative return value. The
// values are disjoint so a host can tell "the input does not match" from "the
// engine gave up", which is the whole point of this package existing:
//
//	-1  NoMatch          the input does not match — an ordinary, expected answer
//	-2  BTStackOverflow  the Backtracking engine ran out of memory for the
//	                     search; the answer is UNKNOWN, not "no"
//
// For the i64-returning find exports the same values apply, sign-extended
// (i64.const -1 / -2); a genuine packed (start << 32 | end) result always has
// bit 63 clear because start is a non-negative i32, so no legitimate result can
// be confused with either sentinel.
//
// Adding a value here means updating every stub generator in generate/ — a
// sentinel a host cannot distinguish is worse than no sentinel at all, since it
// silently becomes "no match".
package abi

import "encoding/binary"

const (
	// NoMatch is returned when the input genuinely does not match. Hosts map it
	// to None / nil / false / end-of-iteration.
	NoMatch = -1

	// BTStackOverflow is returned when the Backtracking engine cannot complete a
	// search for lack of memory. Where it can arise:
	//
	//   - a program compiled with the work budget off
	//     (compile.BTWorkBudgetOff, a test knob): the backtrack FRAME STACK
	//     (btPushFrame's guard in compile/engine_backtrack.go), sized from the
	//     pattern's alternation count by btAllocSizes — compile-time sized while
	//     the requirement scales with the input;
	//   - every other program only when its FALLBACK body, which sizes its
	//     frame stack and memo from the input at call time, cannot grow linear
	//     memory any further (WASM32's 4 GiB, or a lower host limit). The
	//     ordinary body's static stack no longer produces it: running out hands
	//     the call to the fallback.
	//
	// Whichever fires, the engine has abandoned part of the search space and
	// cannot say whether a match exists: reporting NoMatch here would be a
	// false negative that scales in with input size and carries no diagnostic,
	// which is exactly the failure this sentinel exists to prevent.
	//
	// They share one value because a host acts identically on all of them —
	// surface an error, do not treat it as "no match" — and because a new value
	// would have to be threaded through all six stub generators to convey a
	// distinction no caller can act on.
	//
	// Hosts must surface it as an error, never as "no match". See
	// docs/engines.md ("Frame budget and the -2 sentinel").
	BTStackOverflow = -2

	// OverlapCacheMalformed is returned when an overlapping `find` is handed an
	// answer cache whose HEADER contradicts itself: a stride BELOW 1, or — on a
	// call after the sweep — a layout that is not the one a pass would have
	// written (a floor past the input, a cntOff that does not follow from
	// numBlocks, a block buffer the declared cache_len cannot hold).
	//
	// Two things that look similar are NOT this. A stride WIDER than the span
	// being swept is ordinary and is clamped: `init` sizes the stride for the
	// whole input, and a drive that engages late has fewer positions left than
	// that. A region merely TOO SMALL is refused with -1 and the drive walks —
	// same answer, slower — which is what lets a caller cap what it allocates.
	//
	// It is an ERROR and not a silent decline, which is the whole point of it.
	// The region is CALLER-OWNED memory: the generated `init` fills it correctly
	// by construction, but the raw ABI is documented and usable directly, and a
	// caller who gets it wrong would otherwise see the drive quietly fall back to
	// walking — indistinguishable from the engine legitimately refusing the
	// shape, and quadratic on exactly the inputs the cache exists for.
	//
	// A region that is merely TOO SMALL is NOT this. That is a legitimate answer
	// with its own signal (the sweep refuses, the drive walks, -1 from the sweep
	// internally), because a caller is allowed to offer less than the optimum.
	// Only a self-contradictory header lands here.
	OverlapCacheMalformed = -4

	// OverlapCacheOutOfOrder is returned when an overlapping `find` is asked
	// for a `from` BELOW the floor its ENGAGED answer cache was swept from.
	// Within one scan `from` must never go backwards — the gate array and the
	// overlapping preflight already assume it — and a cache served from its
	// floor would silently drop every match in [from, floor).
	//
	// Detection is BEST EFFORT, with no guarantee: only an engaged cache has a
	// floor to compare against. Before the cache engages, with no region
	// offered, or on a set with no cache, a backwards `from` is not detected.
	//
	// -6 rather than -5, and -3 and -5 are RESERVED: the C stubs return
	// RX_ERR_NULL_ARG (-3) and RX_ERR_RANGE (-5) from their own argument
	// checks, and C passes an engine code straight through. Every error code
	// means the same thing in every language, so a new code takes the next
	// value no layer uses.
	OverlapCacheOutOfOrder = -6
)

// --- the `find` scratch descriptor -----------------------------------------
//
// `find` and `find_batch` take a POINTER TO A DESCRIPTOR where they used to
// take a bare gate-array pointer. The descriptor carries the gate array and,
// optionally, the overlapping answer cache:
//
//	+0  magic      FindScratchMagic
//	+4  gate_ptr   ID_SPACE u32s, zeroed for a clean scan — as before
//	+8  cache_ptr  the overlapping answer cache, or 0 to decline
//	+12 cache_len  its length in bytes
//
// WHY A DESCRIPTOR rather than two more parameters. The cache is the mechanism
// that makes an overlapping drive linear instead of quadratic, and it has to
// live in CALLER-owned memory: a region held inside the module would carry one
// scan's answers into the next, which is the same reason the gate array is the
// caller's. Passing it needs somewhere to put a pointer and a length, and a
// descriptor puts them somewhere that the NEXT piece of scratch can also use
// without changing a signature again. It also collapses `find_batch` from eight
// parameters to six, so the cache is described in one place rather than two.
//
// WHY A MAGIC WORD. The descriptor replaces a parameter of the same type, so a
// caller still passing a bare gate array would have its gate[0] read as a
// pointer — a silent corruption. The magic turns that into an immediate trap:
// a zeroed gate array reads 0 here, which is not the magic, and the module
// executes `unreachable` on the first call. One compare per call buys a loud
// failure instead of a quiet one.
const (
	// FindScratchMagic is "RXFS" in little-endian bytes.
	FindScratchMagic = 0x52584653

	// FindScratchBytes is the descriptor's size. 4-aligned, like everything
	// else the set ABI passes.
	FindScratchBytes = 16

	FindScratchMagicOff    = 0
	FindScratchGateOff     = 4
	FindScratchCacheOff    = 8
	FindScratchCacheLenOff = 12
)

// ScratchBaseExport is the export name of the mutable i32 global a STANDALONE
// module carries when it contains a Backtracking program: the lowest address
// the host lets the module use as run-time scratch during a call.
//
// A Backtracking call that exhausts its work budget or its frame stack falls
// over to a memoised fallback body whose frame stack and memo are sized from the
// input at call time — as does every call to a program with a zero-width cycle,
// which has no other body. In a standalone module every byte above the tables
// belongs to the host (the JS/TS stubs carve their input regions there), so the
// module cannot see what is live. The contract:
//
//   - The host sets the global to the first byte at and above which it keeps
//     nothing it needs during a call. It may raise it at any time and must not
//     write at or above it while a call runs.
//   - The module places its scratch at the HIGHER of the global and the end of
//     its own tables, and grows memory when the scratch does not fit.
//   - 0, the initial value, means the host has said nothing: the scratch then
//     takes fresh pages at the end of memory on every call that needs it.
//     Always correct, but memory grows on each such call.
//
// The name carries a colon so no export a config can name collides with it:
// config.ValidateConfig accepts only identifiers. Embedded modules own their
// memory and components own their allocator, so neither exports it.
//
// A module that grows memory during a call detaches every JavaScript view of
// the old buffer; a JS host must read the buffer afresh after each call.
const ScratchBaseExport = "regexped:scratch_base"

// --- the per-search block ----------------------------------------------------
//
// A DRIVE — a stub calling `find` or `groups` until the input is exhausted — can
// cost O(n²) even though every call is linear: a call reads bytes past the match
// it reports, and the next call reads them again. The cure keeps notes across
// the calls of ONE search: "from this (state, position) nothing matches", one
// bit per (state, position), written once and read once. Those notes belong to
// the search, not to the module — two iterators alive over one instance must
// not clear each other's — so they live in a block the STUB owns, one per
// iterator, and the stub tells the module which block the next call belongs to.
//
// The module keeps an ordinary copy of every find that can re-read bytes, plus
// a per-search waste counter; only a search whose waste passes 4 × progress + 64
// ARMS, after which a marked copy that reads and writes the notes serves the
// rest of it. The notes themselves are allocated by the stub when it sees the
// armed flag, so a search that never goes bad costs one block and no notes.
//
// The block, SearchBlockBytes, 8-byte aligned, in the memory the input lives in
// (the host's memory in an embedded build), zeroed by the stub when it creates
// the iterator. Every field starts at 0 and the stub writes only `notes_ptr`,
// `notes_cap` and the two Backtracking memo fields; everything else is the
// module's:
//
//	+0   wasted      i64  bytes read past reported matches, and failed reads
//	                      over 32 bytes, this search
//	+8   first       i32  `from` + 1 of the first call that wasted anything
//	+12  armed       i32  1 once the search has gone bad
//	+16  resume      i32  the resume point the last marked call handed out
//	+20  ptr         i32  the text the notes describe (marked copy)
//	+24  len         i32  its length
//	+28  notes_ptr   i32  STUB: this search's notes, 0 = none yet
//	+32  high        i32  one past the highest position holding a note
//	+36  seen        i32  1 once a marked call has recorded ptr/len/resume
//	+40  bt_state    i32  Backtracking find: 0 new, 1 budget live, 2 tripped
//	+44  notes_cap   i32  STUB: bytes allocated at notes_ptr
//	+48  bt_budget   i64  Backtracking find: work budget left, this search
//	+56  bt_memo_ptr i32  STUB: the Backtracking fallback's kept memo, 0 = none
//	+60 … +67             reserved, 0
//	+68  bt_cap      i32  Backtracking capture body: 2 once a call tripped
//	+72  bt_memo_cap i32  STUB: bytes allocated at bt_memo_ptr
//	+76  far         i32  one past the farthest position a failed walk of the
//	                      general find body has read this search: only a walk
//	                      reaching back below it re-reads, and only that part
//	                      is waste
//	+80 … +127            reserved, 0
//
// The notes: `(len + 1) × notes_bytes` zeroed bytes, where notes_bytes is a
// per-pattern constant the stub generator writes into the stub. The module
// checks `notes_cap` against what it is about to address and treats a short
// region as "no notes", so a stub that disagrees about the constant costs speed,
// never memory safety.
//
// The Backtracking memo: once `bt_state` reads 2 (tripped) the stub allocates
// `(len + 1) × bt_memo_bytes` zeroed bytes, one row per text position starting
// at position 0, where bt_memo_bytes is ⌈instructions / 8⌉ of the pattern's
// program (SearchSize.BTMemoBytes). The module checks `bt_memo_cap` the same
// way and uses a memo of its own for a call it does not cover.
//
// How the module finds the block: SearchExport. The stub hands the block's
// address over before EVERY call of an export whose pattern uses one; the value
// is read by that call only. 0 means "no block", and the search runs exactly as
// it would without this mechanism. A caller that drives the raw exports without
// a generated stub must hand over 0, or a block of its own, before each such
// call — a stale address left by another search is that search's state.
const (
	SearchBlockBytes = 128
	SearchBlockAlign = 8

	SearchWastedOff    = 0
	SearchFirstOff     = 8
	SearchArmedOff     = 12
	SearchResumeOff    = 16
	SearchPtrOff       = 20
	SearchLenOff       = 24
	SearchNotesOff     = 28
	SearchHighOff      = 32
	SearchSeenOff      = 36
	SearchBTStateOff   = 40
	SearchNotesCapOff  = 44
	SearchBTBudgetOff  = 48
	SearchBTMemoOff    = 56
	SearchBTCapOff     = 68
	SearchBTMemoCapOff = 72
	SearchFarOff       = 76
)

// bt_state's values; bt_cap uses SearchBTTripped too.
const (
	SearchBTNew     = 0 // a new search: no budget set up yet
	SearchBTLive    = 1 // the search's budget is live in the block
	SearchBTTripped = 2 // the budget ran out: the fallback serves the rest of the search
)

// SearchExport is the export through which the host names the current search's
// block. Its KIND depends on the output kind, because the hosts differ in what
// they can touch:
//
//   - standalone (JS/TS, the harnesses): a mutable i32 GLOBAL the host writes;
//   - embedded (Rust, Go, C, AssemblyScript through wasm-merge): a FUNCTION
//     `(blk i32) → ()` the host calls, since a merged host can only call the
//     module's exports. Measured against a fourth parameter on every find
//     export: within 1% on every drive measured, and one name instead of a
//     second export per pattern;
//   - component: not exported; the find / groups resource sets it itself.
//
// The colon keeps it out of the namespace a config can name, as
// ScratchBaseExport's does.
const SearchExport = "regexped:search"

// ImportModuleSection is the custom section in which `regexped compile`
// records an EMBEDDED module's import_module, the module name its stubs import
// from. `regexped merge` names each regexp module from it rather than from the
// one config it is given, so modules built from configs with distinct
// import_module values merge into one program, and two modules under the SAME
// name — whose setter exports (SearchExport) the merge would otherwise bind to
// only one of — are refused. The payload is the name's UTF-8 bytes.
const ImportModuleSection = "regexped:import_module"

// SearchRuleMult and SearchRuleSlack are the arming rule, shared with the
// Backtracking per-search budget: a search arms once its waste exceeds
// SearchRuleMult × (progress) + SearchRuleSlack.
const (
	SearchRuleMult  = 4
	SearchRuleSlack = 64
)

// SetMatchTupleBytes is one set match as the find exports write it: {pattern
// id, start, end}, three i32. Every writer of a tuple buffer and every reader
// that sizes or indexes one takes the stride from here.
//
// It is EXACTLY the canonical layout of the component interface's `record
// set-match { id: u32, start: u32, end: u32 }` — size 12, align 4 — so the
// buffer a find body fills IS that list's element array, and the component's
// `next` hands it over without converting anything.
const SetMatchTupleBytes = 12

// WriteFindScratch fills a descriptor at buf[off:] — magic, gate pointer, and
// either the answer cache or a declined one (pass 0, 0).
//
// Here rather than in each caller because five harnesses and six stub
// generators all have to agree about the layout, and a field written at the
// wrong offset is a wrong pointer rather than a compile error. The one place
// that CANNOT use it is the generated stub code itself, which is emitted as
// source text in another language — those carry the offsets as constants
// derived from the same block above.
func WriteFindScratch(buf []byte, off int32, gatePtr, cachePtr, cacheLen int32) {
	put := func(at int32, v int32) {
		binary.LittleEndian.PutUint32(buf[off+at:], uint32(v))
	}
	put(FindScratchMagicOff, FindScratchMagic)
	put(FindScratchGateOff, gatePtr)
	put(FindScratchCacheOff, cachePtr)
	put(FindScratchCacheLenOff, cacheLen)
}

// WriteFindScratchBlocks fills a descriptor that also names a set's split
// member search blocks: FindScratchMagicBlocks, then WriteFindScratch's
// fields, then blocksPtr and the number of blocks there. buf[off:] must hold
// FindScratchBlocksBytes.
func WriteFindScratchBlocks(buf []byte, off int32, gatePtr, cachePtr, cacheLen, blocksPtr, blocksN int32) {
	WriteFindScratch(buf, off, gatePtr, cachePtr, cacheLen)
	binary.LittleEndian.PutUint32(buf[off+FindScratchMagicOff:], FindScratchMagicBlocks)
	binary.LittleEndian.PutUint32(buf[off+FindScratchBlocksOff:], uint32(blocksPtr))
	binary.LittleEndian.PutUint32(buf[off+FindScratchBlocksCountOff:], uint32(blocksN))
}

// --- a split set member's search block ---------------------------------------
//
// A set member whose search is split out of the set's buckets keeps its OWN
// per-search block (the single-pattern block above: same size, layout and
// host protocol), because the member's search spans the set's calls just as a
// pattern's spans its iterator's. A caller hands the blocks over through the
// scratch descriptor, in two fields that only a descriptor carrying
// FindScratchMagicBlocks has:
//
//	+16 blocks_ptr  n × SearchBlockBytes, SearchBlockAlign-aligned, zeroed
//	                when a scan starts; n and each block's notes size are
//	                the set's generated block list
//	+20 blocks_n    n, the number of blocks at blocks_ptr
//
// The module uses the blocks only when blocks_n is the count its set expects
// and otherwise runs every member with no block — correct, only slower — so a
// stub and a module that disagree about the list (a stub generated for another
// build of the config) cannot make the module write past the caller's array.
//
// A second magic rather than a field every descriptor carries, because a
// caller that knows nothing of blocks writes four fields and whatever follows
// them would be read as a pointer the module then writes through. With the
// old magic the module runs every member search with no block: correct, and
// as fast as before blocks existed. Only a set with such members accepts the
// new magic; any other traps on it as on any wrong word.
const (
	// FindScratchMagicBlocks is "RXFB" in little-endian bytes.
	FindScratchMagicBlocks    = 0x52584642
	FindScratchBlocksOff      = 16
	FindScratchBlocksCountOff = 20
	// FindScratchBlocksBytes is the size of a descriptor that names blocks.
	FindScratchBlocksBytes = 24
)
