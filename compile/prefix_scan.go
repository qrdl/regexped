package compile

import (
	"fmt"

	"github.com/qrdl/regexped/internal/utils"
)

// emitShuftiPrefixCheck emits a SIMD byte-set-membership test (Shufti)
// against the 16-byte chunk currently in `chunkLocal`. Leaves an i32
// bitmask on the stack: bit `k` set ⇔ lane k of the chunk is a byte in
// `firstByteSet`.
//
// Used by `EmitPrefixScan` (LNM Action 3) as the SIMD strategy for
// first-byte sets of 9..64 bytes, replacing the older multi-eq emission
// that did 4×N ops/chunk.
//
// Encoding: see buildShuftiPairs. Bytes are grouped by HIGH NIBBLE and one
// bit is spent per distinct low-nibble row, not per set member, so the
// emission is at most TWO (T_lo, T_hi) pairs — 13 SIMD ops each — for any
// set whatsoever. The older one-bit-per-member scheme needed ceil(N/8)
// pairs: 7 for `[a-zA-Z]`, 12 for `[!-~]`, and every wasted probe or
// skip attempt paid all of them.
//
// For each lane: `T_lo[chunk_lo] & T_hi[chunk_hi]` is non-zero iff the
// chunk byte is a member. Across multiple pairs we OR the per-pair results.
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
//   - `firstByteSet` has 1..256 distinct bytes. EmitPrefixScan's `useSIMD`
//     gate stops at 64 (128 under LikelyNoMatch) for reasons of its own;
//     the emission itself has no upper bound, since 16 high nibbles cannot
//     produce more than 16 distinct rows and therefore never more than two
//     pairs.
//
// Post-conditions:
//   - i32 bitmask on top of stack.
//   - `chunkLocal` unchanged.
//   - No other locals written.
//
// Shufti first-byte band. Below the first bound the static rarity model
// decides; between the two, only a LikelyNoMatch caller that can also supply
// the dense switch gets it.
const (
	maxShuftiFirstBytes    = 64
	maxShuftiFirstBytesLNM = 128
)

// shuftiPrefixPlan is the SINGLE authority on whether the prefix scan emits a
// Shufti membership check for a first-byte set, and whether that emission
// needs the adaptive dense switch.
//
// It exists because this decision used to be stated in four places — the
// emission site below, plus three independent local-reservation sites
// (`numV128ForScan` and `needsDenseSwitch` in engine_dfa.go, `numV128Locals`
// in engine_backtrack.go). When they disagree the module does not merely
// answer wrongly, it FAILS WASM VALIDATION with "expected i32, found v128",
// because the emitter uses a v128 local the caller never declared. That has
// already happened once: engine_backtrack.go's copy sat at 16 after this band
// was widened to 64, and its comment still records the symptom.
//
// Callers pass canAdapt = "I have reserved the two i32 locals the dense
// switch needs". It is a REQUIREMENT above maxShuftiFirstBytes, not a
// preference: past 64 the static rarity model is not consulted at all — it
// was calibrated inside the narrow band and asking it about a 94-byte set is
// asking a question it was never fitted for — so the wide band is
// force-plus-adapt, exactly as the set frontend's equivalent widening is, and
// the runtime counter is the only thing bounding a wrong assertion. A caller
// that cannot adapt therefore stays at 64 rather than being forced blind.
//
// Only meaningful for n > 16; smaller sets take the multi-eq SIMD strategy,
// which is a different shape and is decided by its own bound.
func shuftiPrefixPlan(firstByteSet []byte, likelyNoMatch, canAdapt bool) (useShufti, wantDenseSwitch bool) {
	n := len(firstByteSet)
	switch {
	case n <= 16:
		return false, false
	case n <= maxShuftiFirstBytes:
		rare := shuftiBeatsScalar(firstByteSet)
		if likelyNoMatch {
			return true, !rare && canAdapt
		}
		return rare, false
	case likelyNoMatch && canAdapt && n <= maxShuftiFirstBytesLNM:
		return true, true
	}
	return false, false
}

func emitShuftiPrefixCheck(b []byte, firstByteSet []byte, chunkLocal byte) []byte {
	return emitShuftiMask(b, firstByteSet, chunkLocal, false)
}

// emitShuftiStopMask is emitShuftiPrefixCheck with the opposite polarity: bit k
// is set when lane k is NOT a member of the set.
//
// The bulk skips want exactly this — they advance to the first byte that leaves
// the self-loop class — and used to get it by taking the member mask and
// following it with `i32.const 0xFFFF; i32.xor`. Comparing the merged lanes
// against zero with i8x16.eq instead of i8x16.ne produces it directly, and
// i8x16.bitmask zero-extends the upper 16 bits, so the xor was never doing
// anything the compare could not. Two instructions per attempt and per
// productive 16-byte lap, in every bulk skip in the compiler.
func emitShuftiStopMask(b []byte, set []byte, chunkLocal byte) []byte {
	return emitShuftiMask(b, set, chunkLocal, true)
}

// emitShuftiMask is the shared body. stop=false leaves a member mask (bit k set
// ⇔ lane k IS in the set); stop=true leaves its complement over the 16 relevant
// lanes. The nibble-table emission is identical either way — only the final
// comparison against zero differs — so the two polarities cannot drift apart in
// the table construction, which is the part that has to be exact.
func emitShuftiMask(b []byte, firstByteSet []byte, chunkLocal byte, stop bool) []byte {
	if len(firstByteSet) == 0 {
		// No candidates — push a trivial bitmask. With stop polarity every lane
		// is a non-member, so the honest constant is 0xFFFF rather than 0.
		// (Caller's useSIMD gate makes this unreachable in practice.)
		if stop {
			b = append(b, 0x41)
			return utils.AppendSLEB128(b, int32(0xFFFF))
		}
		return append(b, 0x41, 0x00)
	}

	for i, pair := range buildShuftiPairs(firstByteSet) {
		tLo, tHi := pair[0], pair[1]

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

		// pair_result = lo_bits & hi_bits
		b = append(b, 0xFD, 0x4E) // v128.and

		if i > 0 {
			// merged = merged | pair_result
			b = append(b, 0xFD, 0x50) // v128.or
		}
	}

	// Reduce to an i32 bitmask: lanes that matched (member polarity) or lanes
	// that did not (stop polarity).
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0xFD, 0x0F) // i8x16.splat
	if stop {
		b = append(b, 0xFD, 0x23) // i8x16.eq → lane == 0, i.e. NOT a member
	} else {
		b = append(b, 0xFD, 0x24) // i8x16.ne → lane != 0, i.e. a member
	}
	b = append(b, 0xFD, 0x64) // i8x16.bitmask → i32
	return b
}

// buildShuftiPairs returns the (T_lo, T_hi) nibble-table pairs that test
// membership in `set` EXACTLY — no false positives, no false negatives —
// using at most two pairs for any set of bytes whatsoever.
//
// The construction is a rectangle cover of the 16×16 nibble grid. Group the
// set's bytes by high nibble; row h then holds a 16-bit low-nibble mask
// rows[h]. Give every DISTINCT non-empty row mask one bit, eight bits to a
// pair:
//
//	T_hi[h] = bit(group of rows[h])                  — one bit per non-empty row
//	T_lo[l] = OR of bit(g) over groups g whose mask contains l
//
// A byte (h, l) survives `T_lo[l] & T_hi[h]` iff bit(group of rows[h]) is set
// in T_lo[l], i.e. iff l ∈ rows[h], i.e. iff the byte is in the set. There
// are only 16 rows, so there are at most 16 distinct masks and therefore at
// most ceil(16/8) = 2 pairs — regardless of how many bytes the set holds.
//
// The scheme it replaced spent one bit per MEMBER, so it needed ceil(N/8)
// pairs and 13 SIMD ops each: 7 pairs for `[a-zA-Z]`, 8 for `[a-zA-Z0-9_]`,
// 12 for `[!-~]`. Every one of the classes this compiler meets in practice
// is a handful of contiguous ranges, which is a handful of distinct rows, so
// they all collapse to ONE pair here. That cost was paid per chunk by every
// probe and every skip attempt, including the ones that bought nothing,
// which is what made a wrong hint expensive rather than merely useless.
//
// Returns nil for an empty set; callers gate on that themselves.
func buildShuftiPairs(set []byte) [][2][16]byte {
	var rows [16]uint16
	for _, c := range set {
		rows[c>>4] |= 1 << (c & 0x0F)
	}
	// group identifies which pair a row mask was assigned to and which bit
	// within it. Rows that share a mask share a bit — that is the whole point
	// of the cover: `[a-z]`'s rows 6 and 7 differ, but `[ -~]`'s rows 2..6 are
	// all "every low nibble" and cost one bit between them.
	type group struct{ pair, bit int }
	groups := make(map[uint16]group, 16)
	var pairs [][2][16]byte
	next := 0
	for h := 0; h < 16; h++ {
		mask := rows[h]
		if mask == 0 {
			continue
		}
		g, seen := groups[mask]
		if !seen {
			g = group{pair: next / 8, bit: next % 8}
			groups[mask] = g
			next++
			for g.pair >= len(pairs) {
				pairs = append(pairs, [2][16]byte{})
			}
			for l := 0; l < 16; l++ {
				if mask&(1<<uint(l)) != 0 {
					pairs[g.pair][0][l] |= 1 << uint(g.bit)
				}
			}
		}
		pairs[g.pair][1][h] |= 1 << uint(g.bit)
	}
	return pairs
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

	// DenseCounter / DenseSkipFlag (an earlier task v1 — adaptive dense-data
	// switch, combined with the v128 dead-local trim): only read/written
	// when emitPrefixScan's `adaptive` gate is active (LikelyNoMatch forcing
	// Shufti past what shuftiBeatsScalar would otherwise pick for a
	// 17..64-byte first-byte set). Callers that never hit that combination
	// may leave these at their zero value.
	//
	// DenseCounter persists across attempts (outer-loop re-entries): it is
	// seeded to denseSwitchThreshold and counts DOWN once per attempt where
	// Shufti found a candidate in the very first chunk it loaded, i.e. gained
	// no 16-byte skip. At zero the scan stops probing SIMD for the rest of
	// this call and falls straight through to the scalar tail.
	//
	// It counts down rather than up so that the per-attempt gate is
	// `local.get n; if` — two instructions — instead of the four a
	// `n < threshold` compare costs. That gate is executed on EVERY attempt
	// for the whole remainder of a call once the switch has tripped, which on
	// a 50 KB no-match prose buffer is ~40,000 attempts: the two instructions
	// saved are the entire +3.0% that `prefer-no-match` cost against neutral
	// on `[a-zA-Z]{20,}`. The seed is emitted with the locals (see
	// buildFindBody's seedFindFrom), because a WASM local starts at zero and
	// zero now means "stop".
	// DenseSkipFlag is transient scratch reset at the top of each attempt's
	// gated SIMD section, set when a "no candidate, advance 16" iteration
	// runs, and read once a candidate is found to decide whether to bump or
	// reset DenseCounter.
	DenseCounter, DenseSkipFlag byte
}

// twinCallImmWidth is the reserved width of the handoff call's function-index
// immediate. Five bytes is the maximum a u32 LEB128 can take, so the patch can
// write any index without moving the bytes after it.
const twinCallImmWidth = 5

// denseSwitchThreshold is the number of consecutive no-skip Shufti attempts
// that trip the adaptive switch to scalar, and therefore the value
// DenseCounter is seeded to and counts down from. Chosen by
// initial measurement; see likelytest's alpha-run/word-run/deadskip-near-miss
// cases for the workloads this tunes against.
const denseSwitchThreshold int32 = 8

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

	// AllowDenseSwitch: opts into the adaptive
	// dense-data switch for the LikelyNoMatch-forced-Shufti case (17..64
	// byte first-byte set, static heuristic says scalar would win).
	// Requires the caller to have allocated real, non-colliding WASM
	// local indices for Locals.DenseCounter and Locals.DenseSkipFlag —
	// their zero value aliases Locals.Ptr (index 0), so leaving this
	// false (the default) for callers that haven't reserved those locals
	// is required for correctness, not just an optimisation choice.
	AllowDenseSwitch bool

	// HasTwin says a NEUTRAL twin body exists for this pattern, so the adaptive
	// dense switch can hand off to it the moment its probe budget runs out
	// instead of paying its own gate for the rest of the call.
	HasTwin bool

	Locals prefixScanLocals

	// OnMatch is called after the scan finds a candidate and all scan blocks
	// have closed. attempt_start holds the candidate position.
	// Emits engine-specific setup code (e.g. DFA state/pos initialisation).
	OnMatch func(b []byte) []byte

	// Report, when non-nil, receives the strategy this scan actually chose,
	// for `regexped compile --verbose`. Nil on every path but that flag.
	Report *Reporter
}

// emitPrefixScan emits the WASM bytes for the prefix/firstByteFlags scan phase.
//
// On success: advances attempt_start to the candidate, calls p.OnMatch, returns.
// On exhaustion: branches to $no_match (depth = p.EngineDepth-1 from the outer
// engine loop after the scan blocks close, or 1+p.EngineDepth from $scalar inside
// the prefix path).
//
// The caller is responsible for the surrounding $no_match/$outer blocks.
// emitPrefixScan emits the scan and returns the body bytes plus the offset of
// a twin-call immediate that still needs patching, or -1 when there is none.
// See the handoff in the adaptive block for what that call is.
func emitPrefixScan(b []byte, p prefixScanParams) ([]byte, int) {
	b, patch := emitPrefixScanInner(b, p)
	return b, patch
}

func emitPrefixScanInner(b []byte, p prefixScanParams) ([]byte, int) {
	twinCallPatch := -1
	// The strategy is reported HERE, by the code that chooses it. Deriving it
	// again at the call site would be a second implementation of this
	// if/else — the mistake --verbose already made once with SelectEngine.
	defer func() { p.Report.Note(p.strategyNote()) }()
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
		//
		// Phase B verifies prefix[1..N-1] entirely from the single v128 chunk
		// loaded for Phase A (16 bytes). For len(prefix) > 16 this can't work:
		// `i32.shr_u k` for k >= 16 zero-shifts the bitmask, silently
		// collapsing the accumulator to 0 and reporting "no candidate" even
		// where one exists. Gate Phase A/B to prefixes that
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

		// Bail unless the *entire* prefix fits before len — not just its
		// start. attempt_start alone being < len isn't enough: the k-loop
		// below reads len(prefix) bytes starting there, and without this
		// check it would read past len whenever fewer than len(prefix)
		// bytes remain, silently comparing against whatever garbage sits
		// in WASM memory past the real input (regression test: custom-tests.txt
		// NulByteLiteralOOBRead / x{16}/x{17} cases).
		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(len(prefix)))
		b = append(b, 0x6A) // i32.add: attempt_start + len(prefix)
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4B)       // i32.gt_u
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
		// 9..16: Shufti — 2-half nibble lookup (LNM Action 3, shipped)
		//   17..64:  Shufti when `shuftiBeatsScalar(set)`, else scalar
		// (LNM Action 3 deferred portion — density heuristic)
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
		// an earlier task: `p.LikelyNoMatch` can override the static
		// heuristic and force Shufti even when it predicts scalar wins —
		// by design, since the caller's runtime-only knowledge is exactly
		// what the hint is for. But the static heuristic can't distinguish
		// "same byte class, sparse runtime data" (override genuinely wins)
		// from "same byte class, dense runtime data" (override regresses).
		// `adaptive` marks that override case; the emission below adds a
		// runtime counter that detects density directly and falls back to
		// scalar once it's confirmed, instead of trusting the static guess
		// for the whole scan.
		//
		// SIMD block nesting (depths from $simd_outer):
		//   0=$simd_outer 1=$simd_exhausted 2=$found_candidate [engine]
		//   (adaptive: 2=$dense_gate 3=$found_candidate [engine])
		//
		// Scalar tail depths from $skip (SIMD path):
		//   0=$skip 1=$skipdone 2=$found_candidate [engine]
		// Scalar tail depths from $skip (scalar-only path):
		//   0=$skip 1=$skipdone [engine]

		useSIMD := false
		adaptive := false
		if n := len(p.FirstByteSet); n > 0 {
			if n <= 16 {
				useSIMD = true
			} else {
				// One authority, shared with every site that reserves the
				// locals this emission then uses — see shuftiPrefixPlan.
				useSIMD, adaptive = shuftiPrefixPlan(p.FirstByteSet, p.LikelyNoMatch, p.AllowDenseSwitch)
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

			if adaptive {
				// Still probing? A non-zero DenseCounter says yes. Zero means
				// the switch has tripped: skip SIMD entirely for this attempt
				// and fall straight through to the scalar tail below.
				b = append(b, 0x20, l.DenseCounter)
				b = append(b, 0x04, 0x40) // if $dense_gate (void)
				b = append(b, 0x41, 0x00)
				b = append(b, 0x21, l.DenseSkipFlag) // reset per-attempt skip flag
			}

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
				// per-lane non-zero check. See the LikelyMode work
				// for the broader history of Shufti adoption in regexped.
				b = emitShuftiPrefixCheck(b, p.FirstByteSet, l.Chunk)
			}

			// mask on stack → tee + if mask != 0.
			b = append(b, 0x22, l.SimdMask) // local.tee simdMask
			b = append(b, 0x04, 0x40)       // if (void)
			if adaptive {
				// No skip yet this attempt (DenseSkipFlag==0) → this probe
				// bought nothing, bump the streak. Otherwise a skip already
				// happened this attempt → SIMD paid off, reset the streak.
				b = append(b, 0x20, l.DenseSkipFlag)
				b = append(b, 0x45)       // i32.eqz
				b = append(b, 0x04, 0x40) // if (void)
				b = append(b, 0x20, l.DenseCounter)
				b = append(b, 0x41, 0x01)
				b = append(b, 0x6B) // i32.sub — one probe of the budget spent
				b = append(b, 0x21, l.DenseCounter)
				b = append(b, 0x05) // else — SIMD paid off: refill the budget
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, denseSwitchThreshold)
				b = append(b, 0x21, l.DenseCounter)
				b = append(b, 0x0B) // end if
			}
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x20, l.SimdMask)
			b = append(b, 0x68) // i32.ctz
			b = append(b, 0x6A) // i32.add
			b = append(b, 0x21, l.AttemptStart)
			// br exits $found_candidate: 0=if 1=$simd_outer 2=$simd_exhausted
			// 3=$found_candidate (non-adaptive), or 3=$dense_gate
			// 4=$found_candidate (adaptive, one extra wrapping block).
			if adaptive {
				b = append(b, 0x0C, 0x04) // br 4 → $found_candidate
			} else {
				b = append(b, 0x0C, 0x03) // br 3 → $found_candidate
			}
			b = append(b, 0x0B) // end if

			// No candidate: advance 16.
			if adaptive {
				b = append(b, 0x41, 0x01)
				b = append(b, 0x21, l.DenseSkipFlag) // this attempt did skip ≥16 bytes
			}
			b = append(b, 0x20, l.AttemptStart)
			b = append(b, 0x41, 0x10) // i32.const 16
			b = append(b, 0x6A)
			b = append(b, 0x21, l.AttemptStart)
			b = append(b, 0x0C, 0x00) // br 0 → restart $simd_outer

			b = append(b, 0x0B) // end loop $simd_outer
			b = append(b, 0x0B) // end block $simd_exhausted
			if adaptive {
				if p.HasTwin {
					// The probe budget is spent: this body's prefilter has
					// proved itself useless on THIS input, and every remaining
					// attempt would pay `local.get DenseCounter; if` for the
					// rest of the call — ~40,000 of them on a 50 KB buffer,
					// which is the whole margin by which prefer-no-match cost
					// more than neutral.
					//
					// Hand the rest of the search to the neutral twin instead.
					// The else arm is entered at most ONCE per call (the very
					// first attempt after the trip) and costs nothing on any
					// path that never trips, because the `if` is already here.
					//
					// Exactness: attempt_start has only ever advanced past
					// positions this body proved cannot begin a match — including
					// the skip-safe-on-dead jumps, which are proofs over a
					// range — so a leftmost-first search from it returns the same
					// answer as one from 0. The twin is ffNative and reads the
					// WHOLE buffer, so \b and (?m:^) at that position are judged
					// against the real preceding byte; the two bodies' modes are
					// asserted equal where the twin is built.
					b = append(b, 0x05) // else — DenseCounter == 0
					b = append(b, 0x20, l.AttemptStart)
					b = append(b, 0x24) // global.set $find_from
					b = utils.AppendULEB128(b, findFromGlobalIdx)
					b = append(b, 0x20, l.Ptr)
					b = append(b, 0x20, l.Len)
					// The twin's function index is not known until the module is
					// assembled, so the immediate is five zero-padded LEB128
					// bytes and its offset is reported to the caller to patch.
					b = append(b, 0x10)
					twinCallPatch = len(b)
					b = utils.AppendPaddedULEB128(b, 0, twinCallImmWidth)
					b = append(b, 0x0F) // return
				}
				b = append(b, 0x0B) // end if $dense_gate
			}
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
		b = append(b, 0x20, l.AttemptStart)
		b = append(b, 0x20, l.Len)
		b = append(b, 0x4B)       // i32.gt_u
		b = append(b, 0x0D, ed-1) // br_if (ed-1) → $no_match
	}

	// Scan complete: candidate at attempt_start. Call engine-specific setup.
	if p.OnMatch != nil {
		b = p.OnMatch(b)
	}
	return b, twinCallPatch
}

// strategyNote names the scan strategy these params select, in the words the
// verbose report uses. It repeats the conditions immediately above rather than
// observing them, which is a duplication worth flagging: if that if/else moves,
// this must move with it. The alternative — threading a result out of the
// emitter — costs a return value on a function called from fifteen sites for
// output that is off by default.
func (p prefixScanParams) strategyNote() string {
	if len(p.Prefix) >= 1 {
		if len(p.Prefix) <= 16 {
			return fmt.Sprintf("prefix scan: hybrid SIMD, %d-byte prefix", len(p.Prefix))
		}
		return fmt.Sprintf("prefix scan: scalar (prefix %d bytes, over one chunk)", len(p.Prefix))
	}
	n := len(p.FirstByteSet)
	switch {
	case n == 0:
		return "prefix scan: none"
	case n <= 8 && p.TeddyTwoByte:
		return "prefix scan: 2-byte Teddy"
	case n <= 8:
		return "prefix scan: 1-byte Teddy"
	case n <= 16:
		return "prefix scan: multi-eq SIMD"
	case n <= 64:
		return fmt.Sprintf("prefix scan: Shufti or scalar (%d first bytes)", n)
	}
	return fmt.Sprintf("prefix scan: scalar flag table (%d first bytes)", n)
}
