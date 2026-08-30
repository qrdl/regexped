package compile

import "github.com/qrdl/regexped/internal/utils"

// isCountedClassChain detects whether t is a pure counted linear class
// chain: a simple forward path from t.startState where every state
// consumes one byte from the SAME byte class C and advances to the next
// state, terminating after exactly N steps in a state with zero live
// transitions (enforcing an exact count, not an open-ended `{N,}`) that is
// the pattern's sole accepting state. No other state may accept (that
// would mean more than one valid length). Requires a single-pattern
// suffix DFA (no bucket merging) and no word/newline-boundary tracking.
//
// an earlier task: AKIA[A-Z0-9]{16},
// ghp_[A-Za-z0-9]{36}, etc. compile to exactly this shape after their
// literal prefix is split off.
func isCountedClassChain(t *dfaTable) (class []byte, n int, ok bool) {
	if t == nil || t.numStates == 0 || t.hasWordBoundary || t.hasNewlineBoundary {
		return nil, 0, false
	}

	// The emitted body verifies N bytes with SIMD and never consults an entry
	// state, so it behaves as if every run began at t.startState. That is only
	// sound when starting mid-input is indistinguishable from starting at
	// position 0 — i.e. when midStart IS startState.
	//
	// A pattern like `\A+a` breaks it: the chain walk from startState sees a
	// one-step class chain and reports a match, silently discarding the `\A`
	// that makes midStart a different (dead) state. Live-verified: as a set
	// member, `\A+a` matched at position 1 of "0a", where Go and our own
	// single-pattern path both correctly report no match. `\Aa` escapes the
	// bug only because its anchor is stripped to a start-anchor MASK before
	// the DFA is built, so it never reaches this detector.
	if t.midStartState != t.startState {
		return nil, 0, false
	}

	// Single-pattern only: exactly one distinct bit across every accept
	// variant. A bucket merging 2+ patterns' suffix ASTs would need
	// per-pattern chain tracking this detector doesn't attempt.
	var bits uint64
	for _, v := range t.acceptStates {
		bits |= v
	}
	for _, v := range t.midAcceptStates {
		bits |= v
	}
	for _, v := range t.immediateAcceptStates {
		bits |= v
	}
	for _, v := range t.midAcceptNWStates {
		bits |= v
	}
	for _, v := range t.midAcceptWStates {
		bits |= v
	}
	for _, v := range t.midAcceptNLStates {
		bits |= v
	}
	if bits == 0 || bits&(bits-1) != 0 {
		return nil, 0, false
	}

	// acceptsAnywhere: does state s accept at an ARBITRARY position, as
	// opposed to only at end of input?
	//
	// acceptStates is the EOF-only map, and the emitted body never consults
	// it — it verifies N class bytes with SIMD and reports a match, with no
	// end-of-input test. So a terminal state that accepts ONLY at EOF makes
	// the shortcut unsound: `.$` compiled to "one byte of any class matches
	// here", and as a set member it reported a match at every position rather
	// than only at the last one (`.$` over "00" yielded [0-1] and [1-2] where
	// Go yields [1-2] alone). Found by tools/fuzz FuzzSet; see
	// tools/re2test/custom-sets.txt Category S10.
	//
	// The intermediate-state test below deliberately stays broader
	// (isAccepting): a mid-chain state accepting at EOF means a SHORTER input
	// also matches, which this fixed-N body cannot express either.
	acceptsAnywhere := func(s int) bool {
		return t.midAcceptStates[s] != 0 || t.immediateAcceptStates[s] != 0
	}

	isAccepting := func(s int) bool {
		if _, ok := t.acceptStates[s]; ok {
			return true
		}
		if _, ok := t.midAcceptStates[s]; ok {
			return true
		}
		if _, ok := t.immediateAcceptStates[s]; ok {
			return true
		}
		if _, ok := t.midAcceptNWStates[s]; ok {
			return true
		}
		if _, ok := t.midAcceptWStates[s]; ok {
			return true
		}
		if _, ok := t.midAcceptNLStates[s]; ok {
			return true
		}
		return false
	}

	const maxChain = 256
	cur := t.startState
	visited := make(map[int]bool, t.numStates)
	steps := 0
	for {
		if visited[cur] {
			return nil, 0, false // cycle — not a bounded chain (e.g. `{N,}` or a real self-loop)
		}
		visited[cur] = true

		var live []byte
		for b := 0; b < 256; b++ {
			if t.transitions[cur*256+b] != -1 {
				live = append(live, byte(b))
			}
		}

		if len(live) == 0 {
			// Terminal: must be the (sole) accepting state, reached after
			// at least one step, and must accept at an arbitrary position
			// rather than only at end of input.
			if steps == 0 || !isAccepting(cur) || !acceptsAnywhere(cur) {
				return nil, 0, false
			}
			return class, steps, true
		}
		if isAccepting(cur) {
			// An intermediate accept means shorter inputs also match —
			// not a fixed exact-N chain (e.g. `{N,M}` with N<M).
			return nil, 0, false
		}
		if steps >= maxChain {
			return nil, 0, false
		}

		dest := t.transitions[cur*256+int(live[0])]
		for _, bt := range live[1:] {
			if t.transitions[cur*256+int(bt)] != dest {
				return nil, 0, false // branches to more than one destination
			}
		}
		if class == nil {
			class = live
		} else if !sameByteSet(class, live) {
			return nil, 0, false // class must be identical at every step
		}
		cur = dest
		steps++
	}
}

func sameByteSet(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildCountedChainSuffixBody emits the WASM function body for a
// counted-class-chain suffix: instead of walking a DFA table N
// times, verify all N bytes at [ptr+start, ptr+start+n) belong to class via
// SIMD (emitShuftiPrefixCheck, ceil(n/16) chunks of ~1 load + a few ops
// each), then write the match tuple directly.
//
// Signature matches buildSetSuffixBody's ABI exactly, so callers (the set
// bucket dispatcher) don't need to know which emitter produced a given
// bucket's suffix function:
//
//	(ptr i32, start i32, len i32, lPos i32, out_ptr i32, out_cap i32, validMask i32) → i32
//
// patternBit is this pattern's bit within the bucket's validMask (always 1,
// i.e. bit 0, since this emitter only ever handles single-pattern buckets).
// prefixMaxLen mirrors buildSetSuffixBody's emitWriteMatchK convention:
// 0/-1 (trivial/variable) ⇒ matchStart = lPos; >0 (fixed) ⇒
// matchStart = lPos - prefixMaxLen. The tuple's third field is the absolute
// end, matching emitWriteMatchK.
func buildCountedChainSuffixBody(class []byte, n int, patternID int, prefixMaxLen int, gated, hasSkip bool) []byte {
	const (
		paramPtr       = byte(0)
		paramStart     = byte(1)
		paramLen       = byte(2)
		paramLPos      = byte(3)
		paramOutPtr    = byte(4)
		paramOutCap    = byte(5)
		paramValidMask = byte(6)
		paramSkip      = byte(7) // batch skip; ungated batch signature only
		// paramGate (7) exists only in the gated signature and is unused here:
		// a counted chain consumes n >= 1 bytes, so its match can never be
		// empty and the write-time empty-match filter is vacuous. The
		// parameter is still declared so the function matches the gated suffix
		// type every find body calls.
	)
	// Local group order below is i32 group first, then v128 group — these
	// indices must track that order, and shift by one in the gated signature.
	localBase := byte(7)
	if gated || hasSkip {
		localBase = 8
	}
	var (
		lEndPos  = localBase     // i32: start + n
		lOutBase = localBase + 1 // i32: output tuple base ptr
		lChunk   = localBase + 2 // v128
	)
	const patternBit = 1 // bit 0 — single-pattern bucket only

	var b []byte
	b = append(b, 0x02)       // 2 local groups
	b = append(b, 0x02, 0x7F) // 2 x i32 (lEndPos, lOutBase)
	b = append(b, 0x01, 0x7B) // 1 x v128 (lChunk)

	retZero := func(b []byte) []byte {
		return append(b, 0x41, 0x00, 0x0F) // i32.const 0; return
	}

	// if (validMask & patternBit) == 0: return 0
	b = append(b, 0x20, paramValidMask, 0x41, patternBit, 0x71, 0x45, 0x04, 0x40)
	b = retZero(b)
	b = append(b, 0x0B)

	// endPos = start + n; if endPos > len: return 0
	b = append(b, 0x20, paramStart, 0x41)
	b = utils.AppendSLEB128(b, int32(n))
	b = append(b, 0x6A)
	b = append(b, 0x22, lEndPos) // local.tee endPos
	b = append(b, 0x20, paramLen)
	b = append(b, 0x4B, 0x04, 0x40) // i32.gt_u; if
	b = retZero(b)
	b = append(b, 0x0B)

	// Verify every byte in [start, start+n) is in class, ceil(n/16) chunks.
	numChunks := (n + 15) / 16
	for i := 0; i < numChunks; i++ {
		chunkOff := i * 16
		bytesInChunk := n - chunkOff
		if bytesInChunk > 16 {
			bytesInChunk = 16
		}

		if bytesInChunk == 16 {
			// Full chunk: chunkOff+16 <= n <= endPos <= len (checked above),
			// so this load can never cross the verified boundary.
			// chunk = v128.load(ptr + start + chunkOff)
			b = append(b, 0x20, paramPtr, 0x20, paramStart, 0x6A)
			if chunkOff > 0 {
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, int32(chunkOff))
				b = append(b, 0x6A)
			}
			b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
			b = append(b, 0x21, lChunk)
		} else {
			// Final partial chunk (n % 16 != 0): a plain 16-byte v128.load
			// here would read up to 15 bytes past endPos, which can be
			// outside valid memory even though endPos <= len holds — the
			// bytes past endPos aren't guaranteed to exist. Build the chunk
			// lane-by-lane from bytesInChunk individual scalar loads
			// instead; each load address is < endPos <= len, so it's always
			// in bounds. Unfilled lanes stay zero and are masked off below.
			b = append(b, 0xFD, 0x0C) // v128.const 0
			b = append(b, make([]byte, 16)...)
			b = append(b, 0x21, lChunk)
			for j := 0; j < bytesInChunk; j++ {
				b = append(b, 0x20, lChunk) // local.get chunk
				b = append(b, 0x20, paramPtr, 0x20, paramStart, 0x6A)
				byteOff := chunkOff + j
				if byteOff > 0 {
					b = append(b, 0x41)
					b = utils.AppendSLEB128(b, int32(byteOff))
					b = append(b, 0x6A)
				}
				b = append(b, 0x2D, 0x00, 0x00)    // i32.load8_u align=0 offset=0
				b = append(b, 0xFD, 0x17, byte(j)) // i8x16.replace_lane j
				b = append(b, 0x21, lChunk)        // local.set chunk
			}
		}

		b = emitShuftiPrefixCheck(b, class, lChunk) // → i32 bitmask, bit k = lane k is a class member

		wantMask := uint32(1)<<uint(bytesInChunk) - 1
		if bytesInChunk < 16 {
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(wantMask))
			b = append(b, 0x71) // and: mask off don't-care lanes past N
		}
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(wantMask))
		b = append(b, 0x47)       // i32.ne
		b = append(b, 0x04, 0x40) // if mismatch
		b = retZero(b)
		b = append(b, 0x0B)
	}

	// Verified: write the tuple at out_ptr (this emitter never writes more
	// than one tuple per call, so out_base == out_ptr) — but only if the
	// caller still has room. The return value is the count FOUND, so an
	// overflowing call still reports its match towards the total.
	// paramOutCap is the signed remaining
	// capacity and can be negative.
	if hasSkip {
		// This emitter's only tuple has position-relative index 0, so it
		// is written when 0 < cap AND skip <= 0.
		//
		// SIGNED. The caller rebases the position-level skip onto this call's
		// tuple index space as `skip - lBase` (setFindCtx.emitSuffixCall), so
		// the value is NEGATIVE whenever tuples are already committed at this
		// position — which is precisely the "write everything" case. An
		// unsigned compare reads -1 as 4294967295 and suppresses the write
		// while `return 1` below still counts the tuple, so the batch call
		// over-reports its count and the caller reads a stale buffer slot.
		b = append(b, 0x41, 0x00, 0x20, paramOutCap, 0x48) // 0 < cap
		b = append(b, 0x20, paramSkip, 0x41, 0x00, 0x4C)   // skip <= 0 (signed)
		b = append(b, 0x71, 0x04, 0x40)                    // and; if
	} else {
		b = append(b, 0x41, 0x00, 0x20, paramOutCap, 0x48, 0x04, 0x40) // if 0 < cap (signed)
	}
	b = append(b, 0x20, paramOutPtr, 0x21, lOutBase)
	b = append(b, 0x20, lOutBase, 0x41)
	b = utils.AppendSLEB128(b, int32(patternID))
	b = append(b, 0x36, 0x02, 0x00) // i32.store offset=0 (patternID)

	if prefixMaxLen > 0 {
		b = append(b, 0x20, lOutBase, 0x20, paramLPos, 0x41)
		b = utils.AppendSLEB128(b, int32(prefixMaxLen))
		b = append(b, 0x6B, 0x36, 0x02, 0x04) // matchStart = lPos - prefixMaxLen
	} else {
		b = append(b, 0x20, lOutBase, 0x20, paramLPos, 0x36, 0x02, 0x04) // matchStart = lPos
	}
	// matchEnd = start + n (absolute).
	b = append(b, 0x20, lOutBase, 0x20, lEndPos, 0x36, 0x02, 0x08)
	b = append(b, 0x0B) // end if room

	b = append(b, 0x41, 0x01, 0x0F) // i32.const 1; return
	b = append(b, 0x0B)             // end function
	return b
}
