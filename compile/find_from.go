package compile

import "github.com/qrdl/regexped/internal/utils"

// ── The find-from channel ──────────────────────────────
//
// Every exported single-pattern find takes a `from` position, so that
// iterating a pattern over an input re-enters with the WHOLE buffer and a
// start offset instead of a narrowed slice. Narrowing is what makes `\b`,
// `\B`, `(?m:^)` and `(?m:$)` judge the slice edge instead of the real
// neighbouring byte, which is the divergence from Go's regexp this exists to
// remove.
//
// The offset reaches the find body through a module-level mutable i32 GLOBAL
// rather than a third function parameter or a table-memory scratch slot. Both
// alternatives were tried and rejected:
//
//   - A third PARAMETER shifts every local index in the find bodies by one.
//     buildFindBody and buildAnchoredFindBody alone hold 56 hardcoded local
//     references, and there is no test that can prove such a renumbering
//     correct: byteident cannot distinguish a local index from SLEB128 data
//     that happens to hold the same byte.
//
//   - A table-memory SCRATCH SLOT (the shape B13 used for winScratchOff) has
//     a per-pattern address whose Go zero value — 0 — is a real, writable
//     table offset. That defect landed twice in one attempt, and is the same
//     class as the edgeScratchOff.
//
// A global has neither failure mode. The index is a package constant, so
// there is no per-pattern address to forget to initialise, and a body that
// reads the global in a module whose assembler forgot to emit the global
// section does not corrupt anything — it fails WASM VALIDATION, i.e. every
// harness and wasm-tools reject the module at load.
//
// Verified against wasm-merge before any of this was written: a non-exported
// mutable global survives the merge, is renumbered correctly when the main
// module has globals of its own (Rust and Go mains always do), and stays
// independent when several regexp modules are merged into one host.

// findFromGlobalIdx is the index of the find-from global WITHIN a regexp
// module. wasm-merge renumbers it when merging into a host that has globals
// of its own, rewriting every global.get/global.set that refers to it.
const findFromGlobalIdx = 0

// findFromMode records how one pattern's find function receives `from`.
//
// Its zero value is INVALID on purpose. A find function whose mode was never
// set is a missed emitter, and the assemblers panic on it rather than emit a
// module that silently starts every scan at 0 — the failure that sank the
// first attempt at this task, where the symptom was an iteration that never
// terminated instead of a build that stopped.
type findFromMode uint8

const (
	// ffUnset is the zero value: no emitter claimed this find function.
	ffUnset findFromMode = iota

	// ffLegacyNarrow is the pre-task-54 behaviour, moved from the stubs
	// into WASM unchanged: the wrapper hands the body a NARROWED slice and
	// rebases the result. Left-context assertions still judge the slice
	// edge. Every emitter starts here; the mode is retired when the last
	// one is converted, and its absence is then the done criterion.
	ffLegacyNarrow

	// ffNative means the body reads the global and scans the whole buffer
	// from that position, so left context is real. Obtainable only from
	// emitFindFromSeed, which produces it by actually emitting the seed.
	ffNative

	// ffAnchoredZeroOnly means the body can only ever report a match
	// beginning at position 0 (isAnchoredFind), so the wrapper answers
	// "no match" for any from != 0 without calling it at all.
	ffAnchoredZeroOnly
)

func (m findFromMode) String() string {
	switch m {
	case ffLegacyNarrow:
		return "legacy-narrow"
	case ffNative:
		return "native"
	case ffAnchoredZeroOnly:
		return "anchored-zero-only"
	}
	return "UNSET"
}

// emitFindFromSeed appends the two instructions that load the find-from
// global into a find body's SCAN CURSOR, and returns ffNative.
//
// This is the ONLY producer of ffNative, and it returns the mode rather than
// letting the caller assert it: a body is native exactly when it carries this
// seed.
//
// # Why the parameter is a scanCursor and not a local index
//
// It used to take a byte, and "which local is this body's scan start" was then
// one fact per emitter that nothing could check — stated in a const block,
// consumed here, never reconciled. WASM locals are zero-initialised, so naming
// the wrong one yields a module that validates, answers `from == 0` correctly,
// and ignores `from` for ever after; ffNative is returned either way, so the
// mode is no evidence. That defect shipped twice, most recently in
// buildLitChainAltLenientFindBody, whose attempt-start local is DERIVED from
// its window base rather than being the cursor — every exported find returned
// the first match in the buffer, and hosts iterating it never terminated.
//
// A scanCursor comes only from localAlloc.scanCursor(), so the body must
// decide which of its locals is the cursor at the point it allocates them, and
// can then hand that same value to both its scan and this seed. Passing some
// other local is no longer expressible: ordinary locals are bytes, and a byte
// is not a scanCursor.
//
// Placement: immediately after the locals declaration, before the prologue
// that reads the cursor.
func emitFindFromSeed(b []byte, cur scanCursor) ([]byte, findFromMode) {
	b = append(b, 0x23) // global.get
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	b = append(b, 0x21)
	// LEB128, not a raw byte. Local indices above 0x7F need a continuation
	// byte, and writing one raw produced a truncated index the validator
	// accepts as a DIFFERENT local. No emitter is near 128 locals today, which
	// is exactly why this would be found late.
	b = utils.AppendULEB128(b, uint32(cur.Local()))
	return b, ffNative
}

// emitFindFromSet appends `global.set find_from, <local>`.
func emitFindFromSet(b []byte, srcLocal byte) []byte {
	b = append(b, 0x20)
	b = utils.AppendULEB128(b, uint32(srcLocal)) // local.get src — see emitFindFromSeed
	b = append(b, 0x24)                          // global.set
	b = utils.AppendULEB128(b, findFromGlobalIdx)
	return b
}

// findFromGlobalSection returns the WASM global section payload declaring the
// single mutable i32 find-from global, initialised to 0.
func findFromGlobalSection() []byte {
	return []byte{
		0x01,       // one global
		0x7F, 0x01, // mut i32
		0x41, 0x00, // i32.const 0
		0x0B, // end of init expr
	}
}

// buildFindFromWrapperBody emits the exported find function:
//
//	(ptr i32, len i32, from i32) → i64
//
// It is a separate function from the find body on purpose. The body keeps its
// (ptr, len) signature so that its local indices — which are hardcoded by the
// hundred across the emitters — do not move.
//
// Every mode returns the same thing for from == 0, which is what makes the
// ABI flip separable from the semantic fix: narrowing by zero is a no-op, so
// switching the export to this wrapper while every pattern is still
// ffLegacyNarrow cannot change any answer anywhere.
func buildFindFromWrapperBody(findFuncIdx int, mode findFromMode) []byte {
	var b []byte

	switch mode {
	case ffLegacyNarrow:
		b = append(b, 0x01, 0x01, 0x7E) // one i64 local: r (local 3)
	case ffNative, ffAnchoredZeroOnly:
		b = append(b, 0x00) // no locals
	default:
		panic("compile: buildFindFromWrapperBody with " + mode.String() + " mode")
	}

	if mode == ffAnchoredZeroOnly {
		// The body's automaton cannot reach an accepting state from any
		// start position but 0 (isAnchoredFind), so a from > 0 search has
		// no match to find and the body is not called at all. This also
		// covers from > len.
		b = append(b, 0x20, 0x02) // local.get from
		b = append(b, 0x04, 0x40) // if (void)  — from != 0
		b = append(b, 0x42, 0x7F) // i64.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
		b = append(b, 0x20, 0x00, 0x20, 0x01)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end function
		return b
	}

	// from > len: nothing to search. Note `from == len` is NOT rejected —
	// an empty match at the very end of the input is a real result Go
	// reports, and the iteration loops depend on the final from == len
	// call happening.
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x42, 0x7F) // i64.const -1
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	if mode == ffNative {
		b = emitFindFromSet(b, 0x02)          // find_from = from
		b = append(b, 0x20, 0x00, 0x20, 0x01) // ptr, len — the WHOLE buffer
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end function; positions are already absolute
		return b
	}

	// ffLegacyNarrow: reproduce, inside WASM, exactly what the generated
	// stubs used to do host-side — call the body on input[from:] and shift
	// the returned pair back up by `from`.
	b = append(b, 0x20, 0x00, 0x20, 0x02, 0x6A) // ptr + from
	b = append(b, 0x20, 0x01, 0x20, 0x02, 0x6B) // len - from
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x21, 0x03) // local.set r

	// Negative returns are status codes, not positions: -1 is "no match"
	// and anything below it is a BT stack overflow the host must see
	// unmodified. Rebasing them would turn an overflow into a position.
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x42, 0x00) // i64.const 0
	b = append(b, 0x53)       // i64.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// r + ((from << 32) | from) — adds `from` to both halves at once. The
	// low half cannot carry into the high half: relEnd <= len - from, so
	// relEnd + from <= len, and len is an i32 count of addressable bytes.
	b = append(b, 0x20, 0x03) // local.get r
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x42, 0x20) // i64.const 32
	b = append(b, 0x86)       // i64.shl
	b = append(b, 0x20, 0x02) // local.get from
	b = append(b, 0xAD)       // i64.extend_i32_u
	b = append(b, 0x84)       // i64.or
	b = append(b, 0x7C)       // i64.add
	b = append(b, 0x0B)       // end function
	return b
}

// appendFindFromWrapperCodeEntry appends a size-prefixed find wrapper body.
func appendFindFromWrapperCodeEntry(cs []byte, findFuncIdx int, mode findFromMode) []byte {
	body := buildFindFromWrapperBody(findFuncIdx, mode)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// moduleUsesFindFrom reports whether any function in the module touches the
// find-from channel, and therefore whether the assemblers must declare the
// global.
//
// It is not simply "does any pattern have a find function". A groups-only
// pattern on a lit-chain A.3 path has none at all, yet its capture body reads
// the channel (it SCANS) and its exported wrapper writes it.
// Declaring the global is what keeps that pairing a load-time WASM validation
// question rather than a silent read of the wrong thing.
func moduleUsesFindFrom(patterns []*compiledPattern) bool {
	for _, p := range patterns {
		if p.hasFindFunc() {
			return true
		}
		// The anchored-zero-only groups wrapper answers from != 0 itself and
		// never touches the channel; every other groups wrapper writes it.
		if p.hasGroupsFromWrapper() && p.captureFromMode != ffAnchoredZeroOnly {
			return true
		}
	}
	return false
}

// emitFindCallFromPos emits `rLocal = find(...)` starting the search at
// posLocal, for either mode, in a wrapper whose params are (ptr=0, len=1, ...).
//
// Shared by the batch find and batch groups wrappers because getting the two
// modes' calling conventions subtly different between them is exactly the kind
// of divergence that would show up as one export disagreeing with the other.
func emitFindCallFromPos(b []byte, findFuncIdx int, mode findFromMode, posLocal, rLocal byte) []byte {
	if mode == ffAnchoredZeroOnly {
		// This body reports only matches beginning at 0 and ignores the
		// channel entirely, so a resumed call at pos > 0 must NOT reach it:
		// it would hand back the same position-0 match again, and the caller
		// would either report it forever or compute a negative relative
		// offset from it. Answer "no match" without calling, exactly as the
		// exported wrapper does.
		b = append(b, 0x20, posLocal) // local.get pos
		b = append(b, 0x04, 0x7E)     // if (result i64) — pos != 0
		b = append(b, 0x42, 0x7F)     // i64.const -1
		b = append(b, 0x05)           // else
		b = append(b, 0x20, 0x00, 0x20, 0x01)
		b = append(b, 0x10)
		b = utils.AppendULEB128(b, uint32(findFuncIdx))
		b = append(b, 0x0B) // end if
		return append(b, 0x21, rLocal)
	}
	if mode == ffLegacyNarrow {
		// The body cannot be told where to start, so it is handed a slice
		// that begins there. Results come back relative to pos.
		b = append(b, 0x20, 0x00, 0x20, posLocal, 0x6A) // ptr + pos
		b = append(b, 0x20, 0x01, 0x20, posLocal, 0x6B) // len - pos
	} else {
		// The body reads the channel, so it gets the whole buffer and the
		// position. Results come back ABSOLUTE.
		b = emitFindFromSet(b, posLocal)
		b = append(b, 0x20, 0x00, 0x20, 0x01)
	}
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	return append(b, 0x21, rLocal)
}

// emitUnpackRelative unpacks the packed (start<<32|end) in rLocal into two
// i32 locals expressed RELATIVE to posLocal, whichever way the body reported
// them. Both batch wrappers' downstream code — the advance rule, the absolute
// positions it stores, the empty-match test — is written in those terms, so
// normalising here leaves all of it untouched by the mode.
func emitUnpackRelative(b []byte, mode findFromMode, rLocal, posLocal, relStartLocal, relEndLocal byte) []byte {
	b = append(b, 0x20, rLocal, 0x42, 0x20, 0x88, 0xA7) // wrap(r >> 32u)
	if mode != ffLegacyNarrow {
		b = append(b, 0x20, posLocal, 0x6B) // − pos
	}
	b = append(b, 0x21, relStartLocal)
	b = append(b, 0x20, rLocal, 0xA7) // wrap(r)
	if mode != ffLegacyNarrow {
		b = append(b, 0x20, posLocal, 0x6B) // − pos
	}
	return append(b, 0x21, relEndLocal)
}

// anyGroupsExport reports whether any pattern exports groups or named groups,
// and therefore whether the module needs the 4-argument groups type.
func anyGroupsExport(patterns []*compiledPattern) bool {
	for _, p := range patterns {
		if p.groupsExport != "" {
			return true
		}
	}
	return false
}

// buildGroupsFromWrapperBody emits the exported groups / named_groups
// function:
//
//	(ptr i32, len i32, out_ptr i32, from i32) → i32
//
// Like the find wrapper, this is a separate function rather than an extra
// parameter on the body it fronts: the non-anchored groups wrapper and the
// capture bodies keep their 3-argument signature and their local indices.
//
// anchoredOnly is for the case where the export IS captureBody — a pattern
// anchored at 0. Such a body can only report a match beginning at 0, so any
// from != 0 is answered "no match" without calling it. That case cannot be
// handled by seeding the channel, because captureBody does not read it.
func buildGroupsFromWrapperBody(innerFuncIdx int, anchoredOnly bool) []byte {
	var b []byte
	b = append(b, 0x00) // no locals

	if anchoredOnly {
		b = append(b, 0x20, 0x03) // local.get from
		b = append(b, 0x04, 0x40) // if (void) — from != 0
		b = append(b, 0x41, 0x7F) // i32.const -1
		b = append(b, 0x0F)       // return
		b = append(b, 0x0B)       // end if
	} else {
		// from > len: nothing to search. from == len is NOT rejected — an
		// empty match at end of input is a real result.
		b = append(b, 0x20, 0x03, 0x20, 0x01, 0x4B) // from > len (u)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x41, 0x7F)
		b = append(b, 0x0F)
		b = append(b, 0x0B)
		// The inner wrapper runs a find to locate the match; tell it where to
		// start. This is the ONLY writer of the channel on the groups path.
		b = emitFindFromSet(b, 0x03)
	}

	b = append(b, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02) // ptr, len, out_ptr
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(innerFuncIdx))
	b = append(b, 0x0B) // end function
	return b
}

// appendGroupsFromWrapperCodeEntry appends a size-prefixed groups-from wrapper.
func appendGroupsFromWrapperCodeEntry(cs []byte, innerFuncIdx int, anchoredOnly bool) []byte {
	body := buildGroupsFromWrapperBody(innerFuncIdx, anchoredOnly)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// assertGroupsFromWrapperMode enforces the one precondition the non-anchored
// groups-from wrapper has and cannot check for itself.
//
// The wrapper writes the find-from channel and then calls the composed
// (find, capture) wrapper, which calls the find BODY with the whole
// (ptr, len). That is correct only for an ffNative body — one that reads the
// channel. An ffLegacyNarrow body ignores it and scans from 0, so
// groups(from > 0) would report a match BEFORE `from` with no error anywhere:
// "wrong-but-safe" for the find export (whose wrapper narrows and rebases)
// is plain wrong for groups.
//
// buildFindBody has a documented ffLegacyNarrow fallback. Today every emitter
// returns ffNative, so this never fires — but the whole point of the mode
// machinery is that a missed emitter is a BUILD failure (see the findFromMode
// doc above), and this is exactly the hole where the failure would otherwise
// be silent wrong answers.
func assertGroupsFromWrapperMode(p *compiledPattern, anchoredOnly bool) {
	if anchoredOnly {
		// The export IS captureBody; the channel is not consulted at all.
		return
	}
	mode, what := p.findFromMode, "find body"
	if p.anchored {
		// captureBody IS the export; the channel reaches it directly.
		mode, what = p.captureFromMode, "capture body"
	}
	if mode != ffNative {
		panic("compile: pattern exports groups over a non-native " + what +
			" (findFromMode " + mode.String() + ") — the groups-from wrapper " +
			"seeds the find-from channel, which only an ffNative body reads " +
			"(see find_from.go)")
	}
}
