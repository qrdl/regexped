package compile

import "github.com/qrdl/regexped/internal/utils"

// Bitmask-only bucket probes (plans/SETS.md §5).
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
func buildSetProbeBody(p setSuffixParams, anchored bool) []byte {
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

	var b []byte
	b = append(b, 0x01, 0x04, 0x7F) // 4 x i32 locals

	// Entry state, keyed on paramStart — shared with buildSetSuffixBody, which
	// is where the rule (and the reason it keys on paramStart rather than the
	// match start) is documented. This was a second copy until plans/SETS.md
	// §11 R12; §11 R4 was present in BOTH copies, which is the argument for
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
	b = append(b, 0x03, 0x40) // loop $main
	b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x4F, 0x0D, 0x01)

	if !anchored {
		// Early exit: every eligible pattern has already been seen to match,
		// so nothing further can change the answer. Only worth it for the scan
		// probe — the anchored probe's answer is not monotone (a mid-accept
		// says nothing about reaching `len`).
		b = append(b, 0x20, lBits, 0x20, paramValidMask, 0x46, 0x0D, 0x01)

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
// accepting state" is answered entirely at the end (plans/SETS.md §3.3).
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
	}
	raw := buildSetProbeBody(p, true)
	body = utils.AppendULEB128(nil, uint32(len(raw)))
	body = append(body, raw...)
	return
}
