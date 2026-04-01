package compile

import "github.com/qrdl/regexped/internal/utils"

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

	// EngineDepth: number of engine-level blocks/loops that surround the scan.
	// For DFA find body: 2  (loop $outer + block $no_match).
	// Used to compute br depths to $no_match from within the scan.
	EngineDepth byte

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

		prefix := p.Prefix
		step := 17 - len(prefix)
		if step < 1 {
			step = 1
		}

		b = append(b, 0x02, 0x40) // block $prefix_matched (void)
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

		// ── Scalar tail (< 16 bytes remaining) ───────────────────────────────
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
		//   9..16:   multi-eq SIMD
		//   > 16:    scalar 256-byte flag table
		//
		// SIMD block nesting (depths from $simd_outer):
		//   0=$simd_outer 1=$simd_exhausted 2=$found_candidate [engine]
		//
		// Scalar tail depths from $skip (SIMD path):
		//   0=$skip 1=$skipdone 2=$found_candidate [engine]
		// Scalar tail depths from $skip (scalar-only path):
		//   0=$skip 1=$skipdone [engine]

		useSIMD := len(p.FirstByteSet) > 0 && len(p.FirstByteSet) <= 16

		if useSIMD {
			// Pre-load Teddy tables (loop-invariant).
			if len(p.FirstByteSet) <= 8 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, p.TeddyLoOff)
				b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T0_lo
				b = append(b, 0x21, l.TLo)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, p.TeddyHiOff)
				b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T0_hi
				b = append(b, 0x21, l.THi)
				if p.TeddyTwoByte {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, p.TeddyT1LoOff)
					b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T1_lo
					b = append(b, 0x21, l.T1Lo)
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, p.TeddyT1HiOff)
					b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T1_hi
					b = append(b, 0x21, l.T1Hi)
					if p.TeddyThreeByte {
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, p.TeddyT2LoOff)
						b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T2_lo
						b = append(b, 0x21, l.T2Lo)
						b = append(b, 0x41)
						b = utils.AppendSLEB128(b, p.TeddyT2HiOff)
						b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load T2_hi
						b = append(b, 0x21, l.T2Hi)
					}
				}
			}

			b = append(b, 0x02, 0x40) // block $found_candidate (void)
			b = append(b, 0x02, 0x40) // block $simd_exhausted (void)
			b = append(b, 0x03, 0x40) // loop $simd_outer (void)

			// Bounds check: need 16 bytes (17 for 2-byte Teddy, 18 for 3-byte Teddy).
			b = append(b, 0x20, l.AttemptStart)
			if p.TeddyThreeByte && len(p.FirstByteSet) <= 8 {
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
					}
				}

				// bitmask of nonzero lanes.
				b = append(b, 0x41, 0x00)
				b = append(b, 0xFD, 0x0F) // i8x16.splat(0)
				b = append(b, 0xFD, 0x24) // i8x16.ne
				b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
			} else {
				// Multi-eq: OR of bitmask(eq(chunk, splat(b))) for each b in FirstByteSet.
				b = append(b, 0x41, 0x00) // i32.const 0 (accumulator)
				for _, fb := range p.FirstByteSet {
					b = append(b, 0x20, l.Chunk)
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(fb))
					b = append(b, 0xFD, 0x0F) // i8x16.splat
					b = append(b, 0xFD, 0x23) // i8x16.eq
					b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
					b = append(b, 0x72)       // i32.or
				}
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
		b = append(b, 0x2D, 0x00, 0x00)          // i32.load8_u (byte)
		b = append(b, 0x6A)                      // firstByteOff + byte
		b = append(b, 0x2D, 0x00, 0x00)          // i32.load8_u (flag)
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
