package compile

import "github.com/qrdl/regexped/internal/utils"

// emitShuftiPrefixCheck emits a SIMD byte-set-membership test (Shufti)
// against the 16-byte chunk currently in `chunkLocal`. Leaves an i32
// bitmask on the stack: bit `k` set ⇔ lane k of the chunk is a byte in
// `firstByteSet`.
//
// Used by `EmitPrefixScan` (LNM Action 3) as the SIMD strategy for
// first-byte sets of 9..64 bytes, replacing the older multi-eq emission
// that did 4×N ops/chunk. Shufti does ~8 SIMD ops per half-of-8-bytes,
// scaling sub-linearly with N.
//
// Encoding (one half, ≤ 8 bytes):
//
//	for i, b := range half {
//	  bit := byte(1) << i              // each set member gets a unique bit position
//	  T_lo[b & 0x0F] |= bit            // mark low nibble
//	  T_hi[b >> 4]   |= bit            // mark high nibble
//	}
//
// For each lane: `T_lo[chunk_lo] & T_hi[chunk_hi]` is non-zero iff the
// chunk byte's (lo, hi) nibble pair matches a set member's. Across
// multiple halves of ≤ 8 each, we OR the per-half results.
//
// Final reduction:
//
//	merged   = (half_0 | half_1 | … | half_{n-1})
//	non_zero = i8x16.ne(merged, splat(0))      ; lane = 0xFF where set, else 0
//	mask     = i8x16.bitmask(non_zero)          ; i32 bitmask
//
// Tables are inlined as `v128.const` (18 bytes each); Cranelift JIT
// hoists them out of the scan loop, so per-iter work is just the SIMD
// ops, not the constant decode.
//
// Pre-conditions:
//   - `chunkLocal` is a v128 local holding the input bytes for the chunk.
//   - `firstByteSet` has 1..64 distinct bytes; the upper bound matches
//     EmitPrefixScan's `useSIMD` gate. (More than 8 just means more halves;
//     more than 64 falls through to scalar.)
//
// Post-conditions:
//   - i32 bitmask on top of stack.
//   - `chunkLocal` unchanged.
//   - No other locals written.
func emitShuftiPrefixCheck(b []byte, firstByteSet []byte, chunkLocal byte) []byte {
	if len(firstByteSet) == 0 {
		// No candidates — push 0 onto stack as a trivial bitmask.
		// (Caller's useSIMD gate makes this unreachable in practice.)
		return append(b, 0x41, 0x00)
	}

	halves := (len(firstByteSet) + 7) / 8 // ceil(N/8)
	for h := 0; h < halves; h++ {
		start := h * 8
		end := start + 8
		if end > len(firstByteSet) {
			end = len(firstByteSet)
		}
		half := firstByteSet[start:end]

		// Build the per-half nibble tables.
		var tLo, tHi [16]byte
		for i, fb := range half {
			bit := byte(1) << uint(i)
			tLo[fb&0x0F] |= bit
			tHi[fb>>4] |= bit
		}

		// swizzle(T_lo, chunk & 0x0F)
		b = append(b, 0xFD, 0x0C) // v128.const
		b = append(b, tLo[:]...)
		b = append(b, 0x20, chunkLocal)
		b = append(b, 0x41, 0x0F)
		b = append(b, 0xFD, 0x0F) // i8x16.splat(0x0F)
		b = append(b, 0xFD, 0x4E) // v128.and  → chunk & 0x0F
		b = append(b, 0xFD, 0x0E) // i8x16.swizzle → T_lo[chunk & 0x0F]

		// swizzle(T_hi, chunk >> 4)
		b = append(b, 0xFD, 0x0C) // v128.const
		b = append(b, tHi[:]...)
		b = append(b, 0x20, chunkLocal)
		b = append(b, 0x41, 0x04)
		b = append(b, 0xFD, 0x6D) // i8x16.shr_u → chunk >> 4
		b = append(b, 0xFD, 0x0E) // i8x16.swizzle → T_hi[chunk >> 4]

		// half_result = lo_bits & hi_bits
		b = append(b, 0xFD, 0x4E) // v128.and

		if h > 0 {
			// merged = merged | half_result
			b = append(b, 0xFD, 0x50) // v128.or
		}
	}

	// Reduce to i32 bitmask of non-zero lanes.
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0xFD, 0x0F) // i8x16.splat
	b = append(b, 0xFD, 0x24) // i8x16.ne
	b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
	return b
}

// prefixScanLocals holds the WASM local variable indices used by emitPrefixScan.
// These indices differ per engine because each engine declares its own local layout.
type prefixScanLocals struct {
	Ptr          byte // i32 param: input buffer base address
	Len          byte // i32 param: input length
	AttemptStart byte // i32 local: current scan position (read/write)
	SimdMask     byte // i32 local: SIMD bitmask accumulator
	Chunk        byte // v128 local: 16-byte chunk at attempt_start
	TLo, THi     byte // v128 locals: T0_lo, T0_hi (1-byte Teddy, pre-loaded)
	Chunk1       byte // v128 local: 16-byte chunk at attempt_start+1 (2-byte Teddy)
	T1Lo, T1Hi   byte // v128 locals: T1_lo, T1_hi (2-byte Teddy, pre-loaded)
	Chunk2       byte // v128 local: 16-byte chunk at attempt_start+2 (3-byte Teddy)
	T2Lo, T2Hi   byte // v128 locals: T2_lo, T2_hi (3-byte Teddy, pre-loaded)
	Chunk3       byte // v128 local: 16-byte chunk at attempt_start+3 (4-byte Teddy)
	T3Lo, T3Hi   byte // v128 locals: T3_lo, T3_hi (4-byte Teddy, pre-loaded)
}

// prefixScanParams configures emitPrefixScan.
type prefixScanParams struct {
	// What to scan for. Exactly one scan strategy is chosen at emit time:
	//   len(Prefix) >= 1            → SIMD hybrid prefix scan
	//   len(FirstByteSet) 1..8      → 2-byte Teddy (when TeddyTwoByte) or 1-byte Teddy
	//   len(FirstByteSet) 9..16     → multi-eq SIMD
	//   len(FirstByteSet) == 0 or
	//   len(FirstByteSet) > 16      → scalar firstByteFlags table lookup
	Prefix         []byte
	FirstByteSet   []byte    // distinct bytes with firstByteFlags[b]==1, pre-computed
	FirstByteFlags [256]byte // full 256-byte flag table (used for scalar tail)
	FirstByteOff   int32     // memory offset of FirstByteFlags data segment

	// Teddy nibble table offsets (used when len(FirstByteSet) <= 8):
	TeddyLoOff, TeddyHiOff     int32 // T0_lo, T0_hi (1-byte Teddy)
	TeddyT1LoOff, TeddyT1HiOff int32 // T1_lo, T1_hi (2-byte Teddy)
	TeddyTwoByte               bool  // whether 2-byte Teddy tables are available
	TeddyT2LoOff, TeddyT2HiOff int32 // T2_lo, T2_hi (3-byte Teddy)
	TeddyThreeByte             bool  // whether 3-byte Teddy tables are available
	TeddyT3LoOff, TeddyT3HiOff int32 // T3_lo, T3_hi (4-byte Teddy)
	TeddyFourByte              bool  // whether 4-byte Teddy tables are available

	// EngineDepth: number of engine-level blocks/loops that surround the scan.
	// For DFA find body: 2  (loop $outer + block $no_match).
	// Used to compute br depths to $no_match from within the scan.
	EngineDepth byte

	// TableMemIdx: memory index for DFA/SIMD table loads.
	// 0 = standalone (own memory[0]), 1 = embedded (memory[1] for tables).
	TableMemIdx int

	// LikelyNoMatch (LNM Action 5 — impossible-byte SIMD skip):
	// when true, the 17..64-byte first-byte set gate ignores the density
	// heuristic and forces Shufti. Set from buildOpts.LikelyMode ==
	// LikelyNoMatch.
	LikelyNoMatch bool

	// MinPatternLen (Task 8 follow-up #1 — EOF-without-match): compile-time
	// minimum byte length of any accepting match. When > 0 the post-scan
	// bound check tightens from `attempt_start > len` to
	// `attempt_start + MinPatternLen > len`, letting patterns with
	// insufficient remaining input short-circuit before running the
	// engine-specific OnMatch body. Zero = disabled (existing behaviour).
	MinPatternLen int32

	Locals prefixScanLocals

	// OnMatch is called after the scan finds a candidate and all scan blocks
	// have closed. attempt_start holds the candidate position.
	// Emits engine-specific setup code (e.g. DFA state/pos initialisation).
	OnMatch func(b []byte) []byte
}

// emitPrefixScan emits the WASM bytes for the prefix/firstByteFlags scan phase.
//
// On success: advances attempt_start to the candidate, calls p.OnMatch, returns.
// On exhaustion: branches to $no_match (depth = p.EngineDepth-1 from the outer
// engine loop after the scan blocks close, or 1+p.EngineDepth from $scalar inside
// the prefix path).
//
// The caller is responsible for the surrounding $no_match/$outer blocks.
func emitPrefixScan(b []byte, p prefixScanParams) []byte {
	l := p.Locals
	ed := p.EngineDepth

	// Task 8 follow-up #1 (EOF-without-match): if the pattern's minimum
	// byte length exceeds the input remaining from attempt_start, no match
	// is possible from THIS or any later start position. Short-circuit to
	// $no_match before any scan work. Applies to both the prefix branch
	// (below at line ~192) and the firstByteFlags branch (else, at line
	// ~322) — checking at the top avoids duplicating the tightening in
	// each branch's own end-checks.
	//
	// Depth from emitPrefixScan's entry: (ed-1) reaches $no_match, since
	// the caller wraps the scan in `block $no_match; loop $outer` with
	// engine depth = ed.
	if p.MinPatternLen > 0 {
		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.MinPatternLen)
		b = append(b, 0x6A) // i32.add
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x0D, ed-1) // br_if → $no_match
	}

	if len(p.Prefix) >= 1 {
		// ── Hybrid SIMD prefix scan ───────────────────────────────────────────
		// Phase A: find prefix[0] in 16-byte chunks.
		// Phase B: verify prefix[1..N-1] from the same v128 register.
		// Step = 17-N ensures boundary positions are covered.
		//
		// Block nesting (depths from inside inner-if):
		//   0=innerif  1=outerif  2=$simd_outer  3=$simd_exhausted
		//   4=$prefix_matched  [engine blocks]
		//
		// From $scalar (depths):
		//   0=$scalar  1=$prefix_matched  [engine blocks]
		//   → br_if (1+ed) = $no_match
		//
		// Phase B verifies prefix[1..N-1] entirely from the single v128 chunk
		// loaded for Phase A (16 bytes). For len(prefix) > 16 this can't work:
		// `i32.shr_u k` for k >= 16 zero-shifts the bitmask, silently
		// collapsing the accumulator to 0 and reporting "no candidate" even
		// where one exists (TODO.md Task 11). Gate Phase A/B to prefixes that
		// fit in one chunk; longer prefixes fall straight through to the
		// scalar tail below, which verifies the full prefix byte-by-byte and
		// has no such length limit.

		prefix := p.Prefix

		b = append(b, 0x02, 0x40) // block $prefix_matched (void)

		if len(prefix) <= 16 {
			step := 17 - len(prefix)
			if step < 1 {
				step = 1
			}

			b = append(b, 0x02, 0x40) // block $simd_exhausted (void)
			b = append(b, 0x03, 0x40) // loop $simd_outer (void)

			// if attempt_start + 15 >= len: br 1 → $simd_exhausted
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41, 0x0F) // i32.const 15
			b = append(b, 0x6A)       // i32.add
			b = append(b, 0x20, l.Len)
			b = append(b, 0x4F)       // i32.ge_u
			b = append(b, 0x0D, 0x01) // br_if 1 → $simd_exhausted

			// Load 16 bytes once into v128 local.
			b = append(b, 0x20, l.Ptr)
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x6A)                   // i32.add
			b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
			b = append(b, 0x21, l.Chunk)          // local.set chunk

			// Phase A: bitmask for prefix[0].
			b = append(b, 0x20, l.Chunk)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(prefix[0]))
			b = append(b, 0xFD, 0x0F)       // i8x16.splat
			b = append(b, 0xFD, 0x23)       // i8x16.eq
			b = append(b, 0xFD, 0x64)       // i8x16.bitmask → i32
			b = append(b, 0x22, l.SimdMask) // local.tee simdMask

			// if mask != 0: prefix[0] found → Phase B
			b = append(b, 0x04, 0x40) // if (void): outer if

			// Phase B: refine with prefix[1..] from same v128 local.
			for k := 1; k < len(prefix); k++ {
				b = append(b, 0x20, l.Chunk)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(prefix[k]))
				b = append(b, 0xFD, 0x0F) // i8x16.splat
				b = append(b, 0xFD, 0x23) // i8x16.eq
				b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(k))
				b = append(b, 0x76) // i32.shr_u (align with prefix[0] positions)
				b = append(b, 0x20, l.SimdMask)
				b = append(b, 0x71) // i32.and
				b = append(b, 0x21, l.SimdMask)
			}

			// if combined != 0: exact match at ctz position — inner if
			b = append(b, 0x20, l.SimdMask)
			b = append(b, 0x04, 0x40) // if (void): inner if
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x20, l.SimdMask)
			b = append(b, 0x68) // i32.ctz
			b = append(b, 0x6A) // i32.add
			b = append(b, 0x21, l.AttemptStart)
			// br 4 exits $prefix_matched (self-contained depth: 0=innerif 1=outerif
			// 2=$simd_outer 3=$simd_exhausted 4=$prefix_matched)
			b = append(b, 0x0C, 0x04) // br 4 → exit $prefix_matched
			b = append(b, 0x0B)       // end inner if

			// combined == 0: advance by step (overlap) and restart.
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(step))
			b = append(b, 0x6A) // i32.add
			b = append(b, 0x21, l.AttemptStart)
			b = append(b, 0x0C, 0x01) // br 1 → restart $simd_outer
			b = append(b, 0x0B)       // end outer if

			// Phase A fast path: no prefix[0] in chunk → advance 16.
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41, 0x10) // i32.const 16
			b = append(b, 0x6A)
			b = append(b, 0x21, l.AttemptStart)
			b = append(b, 0x0C, 0x00) // br 0 → restart $simd_outer

			b = append(b, 0x0B) // end loop $simd_outer
			b = append(b, 0x0B) // end block $simd_exhausted
		}

		// ── Scalar tail (< 16 bytes remaining, or prefix > 16 bytes) ─────────
		// Depths from $scalar: 0=$scalar 1=$prefix_matched [engine blocks]
		// → br_if (1+ed) goes to $no_match.
		b = append(b, 0x03, 0x40) // loop $scalar (void)

		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4F)       // i32.ge_u
		b = append(b, 0x0D, 1+ed) // br_if (1+ed) → $no_match

		for k := 0; k < len(prefix); k++ {
			b = append(b, 0x20, l.Ptr)
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x6A)       // i32.add
			b = append(b, 0x2D, 0x00) // i32.load8_u align=0
			b = utils.AppendULEB128(b, uint32(k))
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(prefix[k]))
			b = append(b, 0x47)       // i32.ne
			b = append(b, 0x04, 0x40) // if (void): mismatch
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41, 0x01)
			b = append(b, 0x6A)
			b = append(b, 0x21, l.AttemptStart)
			b = append(b, 0x0C, 0x01) // br 1 → restart $scalar
			b = append(b, 0x0B)       // end if
		}
		b = append(b, 0x0B) // end loop $scalar (fall-through = full match)
		b = append(b, 0x0B) // end block $prefix_matched

	} else {
		// ── firstByteFlags / SIMD fast-skip ──────────────────────────────────
		// Strategy based on len(p.FirstByteSet):
		//   <= 8:    2-byte Teddy (when TeddyTwoByte) or 1-byte Teddy
		//   9..16:   Shufti — 2-half nibble lookup (LNM Action 3, shipped)
		//   17..64:  Shufti when `shuftiBeatsScalar(set)`, else scalar
		//            (LNM Action 3 deferred portion — density heuristic)
		//   > 64:    scalar 256-byte flag table
		//
		// Shufti for 9..16 strictly beats the prior multi-eq emission
		// (4N ops vs ~17 ops per chunk). For 17..64 we use a byte-rarity
		// classifier (`shuftiBeatsScalar`, [byte_rarity.go]) to predict
		// whether scalar's per-chunk early-exit beats Shufti's fixed cost.
		// Sets whose bytes are individually rare in typical input (sum of
		// per-byte rarities below a threshold) ⇒ Shufti — scalar would
		// scan ~all bytes per chunk before exiting. Sets whose bytes are
		// dense ⇒ scalar — early-exit wins.
		//
		// SIMD block nesting (depths from $simd_outer):
		//   0=$simd_outer 1=$simd_exhausted 2=$found_candidate [engine]
		//
		// Scalar tail depths from $skip (SIMD path):
		//   0=$skip 1=$skipdone 2=$found_candidate [engine]
		// Scalar tail depths from $skip (scalar-only path):
		//   0=$skip 1=$skipdone [engine]

		useSIMD := false
		if n := len(p.FirstByteSet); n > 0 {
			if n <= 16 {
				useSIMD = true
			} else if n <= 64 && (p.LikelyNoMatch || shuftiBeatsScalar(p.FirstByteSet)) {
				useSIMD = true
			}
		}

		if useSIMD {
			// Pre-load Teddy tables (loop-invariant).
			if len(p.FirstByteSet) <= 8 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, p.TeddyLoOff)
				b = appendTableVLoad(b, p.TableMemIdx) // v128.load T0_lo
				b = append(b, 0x21, l.TLo)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, p.TeddyHiOff)
				b = appendTableVLoad(b, p.TableMemIdx) // v128.load T0_hi
				b = append(b, 0x21, l.THi)
				if p.TeddyTwoByte {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, p.TeddyT1LoOff)
					b = appendTableVLoad(b, p.TableMemIdx) // v128.load T1_lo
					b = append(b, 0x21, l.T1Lo)
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, p.TeddyT1HiOff)
					b = appendTableVLoad(b, p.TableMemIdx) // v128.load T1_hi
					b = append(b, 0x21, l.T1Hi)
					if p.TeddyThreeByte {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, p.TeddyT2LoOff)
						b = appendTableVLoad(b, p.TableMemIdx) // v128.load T2_lo
						b = append(b, 0x21, l.T2Lo)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, p.TeddyT2HiOff)
						b = appendTableVLoad(b, p.TableMemIdx) // v128.load T2_hi
						b = append(b, 0x21, l.T2Hi)
						if p.TeddyFourByte {
							b = append(b, 0x41)
							b = utils.AppendSLEB128(b, p.TeddyT3LoOff)
							b = appendTableVLoad(b, p.TableMemIdx) // v128.load T3_lo
							b = append(b, 0x21, l.T3Lo)
							b = append(b, 0x41)
							b = utils.AppendSLEB128(b, p.TeddyT3HiOff)
							b = appendTableVLoad(b, p.TableMemIdx) // v128.load T3_hi
							b = append(b, 0x21, l.T3Hi)
						}
					}
				}
			}

			b = append(b, 0x02, 0x40) // block $found_candidate (void)
			b = append(b, 0x02, 0x40) // block $simd_exhausted (void)
			b = append(b, 0x03, 0x40) // loop $simd_outer (void)

			// Bounds check: need 16 bytes (17 for 2-byte Teddy, 18 for 3-byte Teddy, 19 for 4-byte Teddy).
			b = append(b, 0x20, l.AttemptStart)
			if p.TeddyFourByte && len(p.FirstByteSet) <= 8 {
				b = append(b, 0x41, 0x12) // i32.const 18
			} else if p.TeddyThreeByte && len(p.FirstByteSet) <= 8 {
				b = append(b, 0x41, 0x11) // i32.const 17
			} else if p.TeddyTwoByte && len(p.FirstByteSet) <= 8 {
				b = append(b, 0x41, 0x10) // i32.const 16
			} else {
				b = append(b, 0x41, 0x0F) // i32.const 15
			}
			b = append(b, 0x6A)
			b = append(b, 0x20, l.Len)
			b = append(b, 0x4F)       // i32.ge_u
			b = append(b, 0x0D, 0x01) // br_if 1 → $simd_exhausted

			// Load chunk.
			b = append(b, 0x20, l.Ptr)
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x6A)
			b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
			b = append(b, 0x21, l.Chunk)

			if p.TeddyTwoByte && len(p.FirstByteSet) <= 8 {
				// Load chunk1 = chunk at attempt_start+1.
				b = append(b, 0x20, l.Ptr)
				b = append(b, 0x20, l.AttemptStart)
				b = append(b, 0x6A)
				b = append(b, 0x41, 0x01)
				b = append(b, 0x6A)
				b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
				b = append(b, 0x21, l.Chunk1)
				if p.TeddyThreeByte {
					// Load chunk2 = chunk at attempt_start+2.
					b = append(b, 0x20, l.Ptr)
					b = append(b, 0x20, l.AttemptStart)
					b = append(b, 0x6A)
					b = append(b, 0x41, 0x02)
					b = append(b, 0x6A)
					b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
					b = append(b, 0x21, l.Chunk2)
					if p.TeddyFourByte {
						// Load chunk3 = chunk at attempt_start+3.
						b = append(b, 0x20, l.Ptr)
						b = append(b, 0x20, l.AttemptStart)
						b = append(b, 0x6A)
						b = append(b, 0x41, 0x03)
						b = append(b, 0x6A)
						b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
						b = append(b, 0x21, l.Chunk3)
					}
				}
			}

			// Compute candidate mask.
			if len(p.FirstByteSet) <= 8 {
				// 1-byte Teddy: candidates0 = swizzle(T0_lo, chunk&0xF) & swizzle(T0_hi, chunk>>4)
				b = append(b, 0x20, l.TLo) // local.get T0_lo
				b = append(b, 0x20, l.Chunk)
				b = append(b, 0x41, 0x0F)
				b = append(b, 0xFD, 0x0F)  // i8x16.splat(0x0F)
				b = append(b, 0xFD, 0x4E)  // v128.and → lo_nibbles
				b = append(b, 0xFD, 0x0E)  // i8x16.swizzle → lo_result
				b = append(b, 0x20, l.THi) // local.get T0_hi
				b = append(b, 0x20, l.Chunk)
				b = append(b, 0x41, 0x04) // i32.const 4
				b = append(b, 0xFD, 0x6D) // i8x16.shr_u
				b = append(b, 0xFD, 0x0E) // i8x16.swizzle → hi_result
				b = append(b, 0xFD, 0x4E) // v128.and → candidates0

				if p.TeddyTwoByte {
					// 2-byte: AND with candidates1 from chunk1.
					b = append(b, 0x20, l.T1Lo)
					b = append(b, 0x20, l.Chunk1)
					b = append(b, 0x41, 0x0F)
					b = append(b, 0xFD, 0x0F) // i8x16.splat(0x0F)
					b = append(b, 0xFD, 0x4E) // v128.and
					b = append(b, 0xFD, 0x0E) // i8x16.swizzle → lo1
					b = append(b, 0x20, l.T1Hi)
					b = append(b, 0x20, l.Chunk1)
					b = append(b, 0x41, 0x04)
					b = append(b, 0xFD, 0x6D) // i8x16.shr_u
					b = append(b, 0xFD, 0x0E) // i8x16.swizzle → hi1
					b = append(b, 0xFD, 0x4E) // v128.and → candidates1
					b = append(b, 0xFD, 0x4E) // v128.and c0&c1 → combined
					if p.TeddyThreeByte {
						// 3-byte: AND with candidates2 from chunk2.
						b = append(b, 0x20, l.T2Lo)
						b = append(b, 0x20, l.Chunk2)
						b = append(b, 0x41, 0x0F)
						b = append(b, 0xFD, 0x0F) // i8x16.splat(0x0F)
						b = append(b, 0xFD, 0x4E) // v128.and
						b = append(b, 0xFD, 0x0E) // i8x16.swizzle → lo2
						b = append(b, 0x20, l.T2Hi)
						b = append(b, 0x20, l.Chunk2)
						b = append(b, 0x41, 0x04)
						b = append(b, 0xFD, 0x6D) // i8x16.shr_u
						b = append(b, 0xFD, 0x0E) // i8x16.swizzle → hi2
						b = append(b, 0xFD, 0x4E) // v128.and → candidates2
						b = append(b, 0xFD, 0x4E) // v128.and combined&c2
						if p.TeddyFourByte {
							// 4-byte: AND with candidates3 from chunk3.
							b = append(b, 0x20, l.T3Lo)
							b = append(b, 0x20, l.Chunk3)
							b = append(b, 0x41, 0x0F)
							b = append(b, 0xFD, 0x0F) // i8x16.splat(0x0F)
							b = append(b, 0xFD, 0x4E) // v128.and
							b = append(b, 0xFD, 0x0E) // i8x16.swizzle → lo3
							b = append(b, 0x20, l.T3Hi)
							b = append(b, 0x20, l.Chunk3)
							b = append(b, 0x41, 0x04)
							b = append(b, 0xFD, 0x6D) // i8x16.shr_u
							b = append(b, 0xFD, 0x0E) // i8x16.swizzle → hi3
							b = append(b, 0xFD, 0x4E) // v128.and → candidates3
							b = append(b, 0xFD, 0x4E) // v128.and combined&c3
						}
					}
				}

				// bitmask of nonzero lanes.
				b = append(b, 0x41, 0x00)
				b = append(b, 0xFD, 0x0F) // i8x16.splat(0)
				b = append(b, 0xFD, 0x24) // i8x16.ne
				b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
			} else {
				// Shufti: multi-half nibble lookup for FirstByteSet of 9..64 bytes.
				// Each half of ≤ 8 bytes gets its own (T_lo, T_hi) 16-byte
				// bitmap pair; the SIMD test ORs all halves and reduces to a
				// per-lane non-zero check. See LNM Action 3 / LIKELY.md Phase 5
				// for the broader history of Shufti adoption in regexped.
				b = emitShuftiPrefixCheck(b, p.FirstByteSet, l.Chunk)
			}

			// mask on stack → tee + if mask != 0.
			b = append(b, 0x22, l.SimdMask) // local.tee simdMask
			b = append(b, 0x04, 0x40)       // if (void)
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x20, l.SimdMask)
			b = append(b, 0x68) // i32.ctz
			b = append(b, 0x6A) // i32.add
			b = append(b, 0x21, l.AttemptStart)
			// br 3 exits $found_candidate (0=if 1=$simd_outer 2=$simd_exhausted 3=$found_candidate)
			b = append(b, 0x0C, 0x03) // br 3 → $found_candidate
			b = append(b, 0x0B)       // end if

			// No candidate: advance 16.
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41, 0x10) // i32.const 16
			b = append(b, 0x6A)
			b = append(b, 0x21, l.AttemptStart)
			b = append(b, 0x0C, 0x00) // br 0 → restart $simd_outer

			b = append(b, 0x0B) // end loop $simd_outer
			b = append(b, 0x0B) // end block $simd_exhausted
		}

		// ── Scalar tail / full scalar ──────────────────────────────────────────
		// SIMD path: depths from $skip: 0=$skip 1=$skipdone 2=$found_candidate [engine]
		// Scalar-only: depths from $skip: 0=$skip 1=$skipdone [engine]
		skipdoneDepth := byte(0x01)
		foundCandidateDepth := byte(0x01)
		if useSIMD {
			foundCandidateDepth = 0x02
		}

		b = append(b, 0x02, 0x40) // block $skipdone (void)
		b = append(b, 0x03, 0x40) // loop $skip (void)

		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4F)                // i32.ge_u
		b = append(b, 0x0D, skipdoneDepth) // br_if → $skipdone

		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, p.FirstByteOff)
		b = append(b, 0x20, l.Ptr)
		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x6A)                      // i32.add
		b = append(b, 0x2D, 0x00, 0x00)          // i32.load8_u (byte) - input load
		b = append(b, 0x6A)                      // firstByteOff + byte
		b = appendTableLoad8u(b, p.TableMemIdx)  // i32.load8_u (flag)
		b = append(b, 0x0D, foundCandidateDepth) // br_if → $found_candidate

		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x41, 0x01)
		b = append(b, 0x6A)
		b = append(b, 0x21, l.AttemptStart)
		b = append(b, 0x0C, 0x00) // br 0 → $skip
		b = append(b, 0x0B)       // end loop $skip
		b = append(b, 0x0B)       // end block $skipdone

		if useSIMD {
			b = append(b, 0x0B) // end block $found_candidate
		}

		// After scan: if attempt_start > len, branch to $no_match.
		// Depth from $outer: (ed-1) to $no_match.
		// (The tightened MinPatternLen check runs at emitPrefixScan entry;
		// this check remains as a natural end-of-scan bound.)
		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x0D, ed-1) // br_if (ed-1) → $no_match
	}

	// Scan complete: candidate at attempt_start. Call engine-specific setup.
	if p.OnMatch != nil {
		b = p.OnMatch(b)
	}
	return b
}
