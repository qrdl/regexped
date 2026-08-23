package compile

import "github.com/qrdl/regexped/internal/utils"

// Bitmask-only bucket probes.
//
// `find` is the only capability that reports positions and extents. The other
// six ask a strictly cheaper question — "which patterns match?" — and §5's
// specialisation table says they must not pay for the machinery `find` needs:
// no per-pattern endPos locals, no immBitmask lookup, no output buffer, no
// leftmost-first extent resolution. What they need is one bitmask.
//
// Two flavours, sharing the DFA tables buildSetSuffixBody already emits:
//
//	scan probe     — pattern k is reported iff the run from `start` accepts for
//	                 k ANYWHERE. That is exactly "does k match beginning at
//	                 this position", which is what the scan trio asks per
//	                 candidate position.
//	anchored probe — pattern k is reported iff the run reaches `len` in a state
//	                 accepting for k. That is full consumption (§3.3), the
//	                 anchored trio's contract: a pattern matching a proper
//	                 prefix does NOT count.
//
// Both have the signature
//
//	(ptr i32, start i32, len i32, validMask i32) -> i32
//
// and return the bucket-local bitmask of matching patterns, already masked by
// validMask. Bits above 31 cannot occur: binPack caps a bucket at 32 patterns.
// probeExit selects when a scan probe stops walking.
//
//   - probeExitMaskComplete: stop once every ELIGIBLE pattern has been seen.
//     Required by `scan_all`, whose answer is the full bitmask at this start.
//   - probeExitFirstHit: stop at the first bit. Legal for `scan` (boolean) and
//     for `scan_any`, which owes the earliest matching START plus AN ARBITRARY
//     id at that start (§3.5) — emitRecordProbe keys on c.lStart, not on walk
//     progress, so exiting early changes at most WHICH arbitrary id is
//     reported, which the contract permits. Using it for `scan_all` would
//     silently drop bits.
//
// The first-hit test is also cheaper than the mask compare it replaces (one
// br_if against three instructions), so scan walks improve even before the
// first accept.
type probeExit int

const (
	probeExitMaskComplete probeExit = iota
	probeExitFirstHit
)

func buildSetProbeBody(p setSuffixParams, anchored bool) []byte {
	return buildSetProbeBodyExit(p, anchored, probeExitMaskComplete)
}

func buildSetProbeBodyExit(p setSuffixParams, anchored bool, exit probeExit) []byte {
	if anchored && exit == probeExitFirstHit {
		// An anchored answer is not monotone: a mid-walk accept says nothing
		// about reaching `len`, so there is no first bit to stop on.
		panic("compile: first-hit exit is not valid for an anchored probe")
	}
	l := p.l
	tableMemIdx := p.tableMemIdx
	n := len(p.patternIDs)
	if n > 32 {
		n = 32
	}
	validBits := uint32(0xFFFFFFFF)
	if n < 32 {
		validBits = uint32(1)<<uint(n) - 1
	}

	const (
		paramPtr       = byte(0)
		paramStart     = byte(1)
		paramLen       = byte(2)
		paramValidMask = byte(3)
		lState         = byte(4)
		lScanPos       = byte(5)
		lByteClass     = byte(6)
		lBits          = byte(7) // i32 accumulator
	)

	// Dominant-state bulk skip, anchored only.
	//
	// Restricted to the uncompressed u8 layout for the same reason G5's unroll
	// is: the compressed and u16 paths route the input byte through a class
	// map or a scaled index. Also skipped for compiled-DFA-style layouts that
	// are not plain direct-index.
	var dom []dominantWalkState
	if anchored && l.useU8 && !l.useCompression && p.dominantSkip != nil {
		dom = p.dominantSkip
	}

	var b []byte
	if len(dom) > 0 {
		// 4 i32 + 1 i32 skip mask, then 1 v128 chunk.
		b = append(b, 0x02, 0x05, 0x7F, 0x01, 0x7B)
	} else {
		b = append(b, 0x01, 0x04, 0x7F) // 4 x i32 locals
	}
	const (
		lSkipMask = byte(8)
		lChunk    = byte(9)
	)

	// Entry state, keyed on paramStart — shared with buildSetSuffixBody, which
	// is where the rule (and the reason it keys on paramStart rather than the
	// match start) is documented. This was a second copy until the two were
	// consolidated; the same defect was present in BOTH copies, which is the argument for
	// the extraction.
	b = emitSetEntryState(b, p, paramPtr, paramStart)
	b = append(b, 0x21, lState)
	b = append(b, 0x20, paramStart, 0x21, lScanPos)
	b = append(b, 0x41, 0x00, 0x21, lBits)

	// orTableBits emits `lBits |= low32(table[lState]) & validMask`.
	orTableBits := func(b []byte, off int32) []byte {
		b = append(b, 0x20, lBits)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, off)
		b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
		b = appendTableLoad64(b, tableMemIdx)
		b = append(b, 0xA7)                       // i32.wrap_i64
		b = append(b, 0x20, paramValidMask, 0x71) // & validMask
		b = append(b, 0x72, 0x21, lBits)          // or; store
		return b
	}

	if !anchored {
		// A start-state mid-accept means the empty match at `start` is a real
		// match for those patterns.
		b = orTableBits(b, p.midBitmaskOff)
	}

	// --- scan loop ---
	b = append(b, 0x02, 0x40) // block $done

	// Anchored fast path: unroll four transitions per iteration.
	//
	// The per-byte loop below is already minimal — 24 WASM instructions, with
	// no accept-table load at all, because every orTableBits call in this
	// function is guarded by !anchored. G5's original hypothesis (a per-byte
	// accept load that only EOF needs) was therefore REFUTED by disassembly;
	// the cost is simply that 24 instructions run per byte, of which 9 are
	// loop scaffolding rather than the transition itself.
	//
	// Unrolling amortises the bounds test, the position increment and the
	// backward branch across four bytes, and folds each byte's input offset
	// into the load's own offset immediate so the position only advances once
	// per block. What it deliberately does NOT amortise is the dead-state
	// test: that stays per byte, so a pattern that dies at position 0 — the
	// overwhelmingly common case for an anchored set, and the reason the
	// keywords-* anchored rows cost 52 fuel — still exits immediately and
	// pays nothing for the unrolling.
	//
	// Restricted to the uncompressed u8 layout: the compressed and u16 paths
	// route the input byte through a class map or a scaled index, so their
	// loads cannot take the offset immediate this depends on. They keep the
	// per-byte loop unchanged.
	unrollAnchored := anchored && l.useU8 && !l.useCompression
	if unrollAnchored {
		const unroll = 4
		b = append(b, 0x02, 0x40) // block $tail
		b = append(b, 0x03, 0x40) // loop $main4

		// Dominant-state bulk skip.
		//
		// Placed at the TOP OF THE WALK, not at function entry: lState only
		// becomes a dominant state after some bytes have been consumed, so an
		// entry-time check never fires (measured: +11 fuel and no skips).
		//
		// Sound by the self-loop property alone. Every byte other than one of
		// this state's exceptions maps the state to itself, so a chunk with no
		// exception leaves the state unchanged and nothing observable is
		// skipped — the anchored probe records NOTHING mid-walk, since every
		// orTableBits call in this function is !anchored-guarded. On a hit the
		// walk resumes AT the first exception byte, whose transition then runs
		// normally.
		//
		// lState is a WASM id (0 = dead, table index + 1) and
		// dominantWalkState.WASMState is in the same space: reorderAcceptFirst
		// has already relabelled the table, and the u8 direct-index path
		// applies no further permutation.
		//
		// Progress is guaranteed: the no-exception arm advances a full chunk,
		// and the exception arm advances by ctz and leaves, after which the
		// unrolled body consumes that byte and changes the state.
		for _, d := range dom {
			b = append(b, 0x20, lState, 0x41)
			b = utils.AppendSLEB128(b, int32(d.WASMState))
			b = append(b, 0x46, 0x04, 0x40) // if lState == d.WASMState   (E)
			b = append(b, 0x02, 0x40)       // block $skip_done            (F)
			b = append(b, 0x03, 0x40)       // loop  $skip                 (G)
			// Whole chunk must be in range, else leave the skip to the walk.
			b = append(b, 0x20, lScanPos, 0x41, 0x10, 0x6A, 0x20, paramLen, 0x4B, 0x0D, 0x01)
			b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A)
			b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
			b = append(b, 0x21, lChunk)
			// Both flavours build ONE mask with the same compare chain; only
			// what the mask means, and therefore the test against it, differs.
			probe := d.Exceptions
			if d.Members != nil {
				probe = d.Members
			}
			b = append(b, 0x41, 0x00) // mask accumulator
			for _, e := range probe {
				b = append(b, 0x20, lChunk)
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(e))
				b = append(b, 0xFD, 0x0F) // i8x16.splat
				b = append(b, 0xFD, 0x23) // i8x16.eq
				b = append(b, 0xFD, 0x64) // i8x16.bitmask
				b = append(b, 0x72)       // i32.or
			}
			b = append(b, 0x22, lSkipMask)
			if d.Members != nil {
				// Member mode: the mask marks bytes that STAY. The whole chunk
				// self-loops iff every lane is set.
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, 0xFFFF)
				b = append(b, 0x46)       // i32.eq
				b = append(b, 0x04, 0x40) // if mask == 0xFFFF            (H)
			} else {
				b = append(b, 0x45, 0x04, 0x40) // if mask == 0           (H)
			}
			b = append(b, 0x20, lScanPos, 0x41, 0x10, 0x6A, 0x21, lScanPos)
			b = append(b, 0x0C, 0x01) // br 1 → restart $skip (G)
			b = append(b, 0x0B)       // end if (H)
			// A byte that leaves the state is in this chunk: resume AT it and
			// leave the skip. Exception mode's mask already marks it; member
			// mode's marks the complement, so invert within the 16 lanes
			// first. ctz is in [0,15] on both paths because the all-stay case
			// was consumed by the branch above — and a ctz of 0 still makes
			// progress, since the walk below then consumes that byte and
			// changes the state.
			if d.Members != nil {
				b = append(b, 0x20, lScanPos, 0x20, lSkipMask, 0x41)
				b = utils.AppendSLEB128(b, 0xFFFF)
				b = append(b, 0x73)                       // i32.xor
				b = append(b, 0x68, 0x6A, 0x21, lScanPos) // ctz; add; set
			} else {
				b = append(b, 0x20, lScanPos, 0x20, lSkipMask, 0x68, 0x6A, 0x21, lScanPos)
			}
			b = append(b, 0x0C, 0x01) // br 1 → $skip_done (F)
			b = append(b, 0x0B)       // end loop $skip (G)
			b = append(b, 0x0B)       // end block $skip_done (F)
			b = append(b, 0x0B)       // end if lState == d (E)
		}

		// Need all `unroll` bytes in range: lScanPos + unroll > paramLen → tail.
		b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x20, paramLen, 0x4B, 0x0D, 0x01)
		for k := 0; k < unroll; k++ {
			// table[state*256 + input[lScanPos + k]] — the +k rides in the
			// load's offset immediate, which is why lScanPos is untouched
			// until the block completes.
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, l.tableOff)
			b = append(b, 0x20, lState, 0x41, 0x08, 0x74, 0x6A)
			b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A)
			b = append(b, 0x2D, 0x00)
			b = utils.AppendULEB128(b, uint32(k)) // input load offset immediate
			b = append(b, 0x6A)
			b = appendTableLoad8u(b, tableMemIdx)
			b = append(b, 0x21, lState)
			// Dead state → $done. lScanPos is left at the block start, which
			// is < paramLen, and that is all the anchored answer needs: the
			// EOF check below is `lScanPos == paramLen`, so any early exit
			// correctly reports "did not consume the whole input". The exact
			// position is never read on this path.
			b = append(b, 0x20, lState, 0x45, 0x0D, 0x02)
		}
		b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x21, lScanPos)
		b = append(b, 0x0C, 0x00) // br 0 → restart $main4
		b = append(b, 0x0B)       // end loop $main4
		b = append(b, 0x0B)       // end block $tail
	}

	b = append(b, 0x03, 0x40) // loop $main
	b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x4F, 0x0D, 0x01)

	if !anchored {
		// Early exit. Only worth it for the scan probe — the anchored probe's
		// answer is not monotone (a mid-accept says nothing about reaching
		// `len`). Which test applies is the caller's choice; see probeExit.
		if p.futureOff != 0 {
			// G8 liveness exit: stop once no WANTED pattern can still accept
			// from here. Strictly stronger than the tests below — it subsumes
			// "all wanted seen" and also fires when the remainder is
			// unreachable. Over-approximating futureAccepts only delays this;
			// see compile/liveness.go on why that direction is the safe one.
			//
			//   future[state] & validMask & ~lBits == 0  ->  done
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, p.futureOff)
			b = append(b, 0x20, lState, 0x41, 0x03, 0x74, 0x6A)
			b = appendTableLoad64(b, tableMemIdx)
			b = append(b, 0xA7) // i32.wrap_i64 — buckets cap at 32 patterns
			b = append(b, 0x20, paramValidMask, 0x71)
			b = append(b, 0x20, lBits, 0x41, 0x7F, 0x73, 0x71) // &^ lBits
			b = append(b, 0x45, 0x0D, 0x01)                    // eqz -> $done
		}
		if exit == probeExitFirstHit {
			// Any bit settles the question.
			b = append(b, 0x20, lBits, 0x0D, 0x01)
		} else {
			// Every eligible pattern already seen: nothing further can change
			// the answer.
			b = append(b, 0x20, lBits, 0x20, paramValidMask, 0x46, 0x0D, 0x01)
		}

		// Zero-width pre-transition accepts, as in buildSetSuffixBody.
		if p.hasWordChar {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, p.wordCharTableOff)
			b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A)
			b = appendInputLoad8u(b)              // INPUT: input[lScanPos]
			b = append(b, 0x6A)                   // wordCharOff + byte
			b = appendTableLoad8u(b, tableMemIdx) // TABLE: wordChar[byte]
			b = append(b, 0x04, 0x40)
			b = orTableBits(b, p.wbWBitmaskOff)
			b = append(b, 0x05)
			b = orTableBits(b, p.wbNWBitmaskOff)
			b = append(b, 0x0B)
		}
		if p.hasNewlineBoundary {
			b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A)
			b = appendInputLoad8u(b) // INPUT byte, not a table read
			b = append(b, 0x41, 0x0A, 0x46)
			b = append(b, 0x04, 0x40)
			b = orTableBits(b, p.nlBitmaskOff)
			b = append(b, 0x0B)
		}
	}

	// DFA transition (shared with buildSetSuffixBody).
	b = emitSetTransition(b, l, lState, lByteClass, paramPtr, lScanPos, tableMemIdx)

	if !anchored {
		b = orTableBits(b, p.midBitmaskOff)
	}

	b = append(b, 0x20, lState, 0x45, 0x0D, 0x01) // dead state: br $done
	b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, lScanPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block

	// EOF accepts count only when the whole input was consumed. A run that
	// died early (dead state) left lScanPos < paramLen, and for the anchored
	// probe that means the pattern did not reach `len` at all.
	b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x46, 0x04, 0x40)
	b = orTableBits(b, p.eofBitmaskOff)
	b = append(b, 0x0B)

	b = append(b, 0x20, lBits)
	if validBits != 0xFFFFFFFF {
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(validBits))
		b = append(b, 0x71)
	}
	b = append(b, 0x0B) // end function
	return b
}

// buildCountedChainProbeBody is the counted-class-chain (task 5) equivalent of
// buildSetProbeBody: the bucket is a single pattern whose suffix is exactly N
// bytes of one class, so "does it match" is one SIMD verification and needs no
// DFA walk at all. Returns bit 0 (the bucket's only pattern) or 0.
func buildCountedChainProbeBody(class []byte, n int, anchored bool) []byte {
	const (
		paramPtr       = byte(0)
		paramStart     = byte(1)
		paramLen       = byte(2)
		paramValidMask = byte(3)
		lEndPos        = byte(4)
		lChunk         = byte(5) // v128
	)
	const patternBit = 1

	var b []byte
	b = append(b, 0x02)       // 2 local groups
	b = append(b, 0x01, 0x7F) // 1 x i32 (lEndPos)
	b = append(b, 0x01, 0x7B) // 1 x v128

	retZero := func(b []byte) []byte { return append(b, 0x41, 0x00, 0x0F) }

	b = append(b, 0x20, paramValidMask, 0x41, patternBit, 0x71, 0x45, 0x04, 0x40)
	b = retZero(b)
	b = append(b, 0x0B)

	// endPos = start + n; must be within the input, and — for the anchored
	// probe — must be exactly `len`, since the anchored contract is full
	// consumption.
	b = append(b, 0x20, paramStart, 0x41)
	b = utils.AppendSLEB128(b, int32(n))
	b = append(b, 0x6A)
	b = append(b, 0x22, lEndPos)
	b = append(b, 0x20, paramLen)
	if anchored {
		b = append(b, 0x47) // i32.ne
	} else {
		b = append(b, 0x4B) // i32.gt_u
	}
	b = append(b, 0x04, 0x40)
	b = retZero(b)
	b = append(b, 0x0B)

	numChunks := (n + 15) / 16
	for i := 0; i < numChunks; i++ {
		chunkOff := i * 16
		bytesInChunk := n - chunkOff
		if bytesInChunk > 16 {
			bytesInChunk = 16
		}
		if bytesInChunk == 16 {
			b = append(b, 0x20, paramPtr, 0x20, paramStart, 0x6A)
			if chunkOff > 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(chunkOff))
				b = append(b, 0x6A)
			}
			b = append(b, 0xFD, 0x00, 0x00, 0x00)
			b = append(b, 0x21, lChunk)
		} else {
			b = append(b, 0xFD, 0x0C)
			b = append(b, make([]byte, 16)...)
			b = append(b, 0x21, lChunk)
			for j := 0; j < bytesInChunk; j++ {
				b = append(b, 0x20, lChunk)
				b = append(b, 0x20, paramPtr, 0x20, paramStart, 0x6A)
				if byteOff := chunkOff + j; byteOff > 0 {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(byteOff))
					b = append(b, 0x6A)
				}
				b = append(b, 0x2D, 0x00, 0x00)
				b = append(b, 0xFD, 0x17, byte(j))
				b = append(b, 0x21, lChunk)
			}
		}
		b = emitShuftiPrefixCheck(b, class, lChunk)
		wantMask := uint32(1)<<uint(bytesInChunk) - 1
		if bytesInChunk < 16 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(wantMask))
			b = append(b, 0x71)
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wantMask))
		b = append(b, 0x47)
		b = append(b, 0x04, 0x40)
		b = retZero(b)
		b = append(b, 0x0B)
	}

	b = append(b, 0x41, patternBit, 0x0F)
	b = append(b, 0x0B)
	return b
}

// genAnchoredWASM emits one anchored bucket's probe function plus the data
// segments it needs: the DFA transition table and a per-state EOF accept
// bitmask. Nothing else — the anchored probe reads no mid-accept, immediate-
// accept or zero-width side table, because "did the run reach `len` in an
// accepting state" is answered entirely at the end.
func genAnchoredWASM(t *dfaTable, tableBase int64, tableMemIdx, numPatterns int) (body []byte, dataBytes []byte, dataSegCount int, nextTableOffset int32) {
	nextTableOffset = int32(tableBase)
	if t == nil || t.numStates == 0 {
		zero := []byte{0x00, 0x41, 0x00, 0x0B}
		body = utils.AppendULEB128(nil, uint32(len(zero)))
		body = append(body, zero...)
		return
	}
	l := buildDFALayout(dfaLayoutParams{
		t:             t,
		tableBase:     tableBase,
		needFind:      false,
		leftmostFirst: false,
	})
	eofBitmaskOff := int32(l.tableEnd)

	bs := make([]byte, l.numWASM*8)
	for gs, bits := range t.acceptStates {
		if bits == 0 {
			continue
		}
		off := (gs + 1) * 8
		for i := 0; i < 8; i++ {
			bs[off+i] = byte(bits >> uint(i*8))
		}
	}
	layoutRaw, layoutCount := stripSegCount(dfaDataSegments(l, false, false))
	dataBytes = append(dataBytes, layoutRaw...)
	dataBytes = append(dataBytes, appendDataSegment(nil, eofBitmaskOff, bs)...)
	dataSegCount = layoutCount + 1
	nextTableOffset = eofBitmaskOff + int32(l.numWASM)*8

	p := setSuffixParams{
		l:             l,
		eofBitmaskOff: eofBitmaskOff,
		wasmStart:     uint32(t.startState + 1),
		wasmMidStart:  uint32(t.midStartState + 1),
		// patternIDs is only read for its LENGTH here — the probe returns a
		// bucket-local bitmask, not global ids — but that length is what caps
		// the returned mask, so an empty slice would mask every bit off.
		patternIDs:  make([]int, numPatterns),
		tableMemIdx: tableMemIdx,
		// G7 + G11: states this anchored walk may bulk-skip through — the
		// wide-self-loop flavour (§18.3) followed by the small-self-loop one
		// (§21.2). Exception mode goes first so it keeps the cheaper compare
		// chain's position when both fire.
		dominantSkip: append(dominantWalkStates(t), memberWalkStates(t)...),
	}
	raw := buildSetProbeBody(p, true)
	body = utils.AppendULEB128(nil, uint32(len(raw)))
	body = append(body, raw...)
	return
}
