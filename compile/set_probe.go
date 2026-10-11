package compile

import "github.com/qrdl/regexped/internal/utils"

// Bitmask-only bucket probes.
//
// `find` is the only capability that reports positions and extents. The other
// six ask a strictly cheaper question — "which patterns match?" — and the
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
//	                 accepting for k. That is full consumption, the
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
//     id at that start — emitRecordProbe keys on c.lStart, not on walk
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
	if n > bucketMaskBits {
		n = 32
	}
	validBits := uint32(0xFFFFFFFF)
	if n < bucketMaskBits {
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
	// Restricted to the uncompressed u8 layout for the same reason the per-byte unroll
	// is: the compressed and u16 paths route the input byte through a class
	// map or a scaled index. Also skipped for compiled-DFA-style layouts that
	// are not plain direct-index.
	var dom []dominantWalkState
	if anchored && l.useU8 && !l.useCompression && p.dominantSkip != nil {
		dom = p.dominantSkip
	}
	unrollAnchored := anchored && l.useU8 && !l.useCompression

	// Run skips over the layout's dominant states (dominantInfo): a run of
	// bytes a state loops on, or — in a Unicode-mode set — of whole
	// characters, crossed 16 bytes at a time by emitDominantBulkSkip, the
	// skip the bucket's find body takes. Sound for both flavours by the
	// self-loop property: the run changes nothing but the position, the
	// anchored probe records nothing mid-walk, and the scan probe's bits for
	// the state were ORed in when the walk entered it. A state with a
	// zero-width word-boundary or newline accept is left out of the scan
	// probe, whose per-byte check of those channels reads the very bytes a
	// skip jumps. The unrolled anchored loop keeps its own byte-run skip (dom
	// above) and takes only the character skip from here, at its top
	// (unrolledSkips); every other walk takes them after its transition
	// (walkSkips). Measured over records with 40-letter Russian values: the
	// scan pair 44.1 fuel/byte without them.
	var walkSkips, unrolledSkips []dominantInfo
	for _, info := range l.dominantStates {
		st := int(info.state)
		if !anchored && ((st < len(l.midAcceptNLBytes) && l.midAcceptNLBytes[st] != 0) ||
			(st < len(l.midAcceptNWBytes) && l.midAcceptNWBytes[st] != 0) ||
			(st < len(l.midAcceptWBytes) && l.midAcceptWBytes[st] != 0)) {
			continue
		}
		switch {
		case !unrollAnchored:
			walkSkips = append(walkSkips, info)
		case info.utf8:
			unrolledSkips = append(unrolledSkips, info)
		}
	}
	// The layout keeps at most two non-accepting dominants (their encoded
	// byte values, 254 and 255, are the find body's); a probe compares state
	// ids instead, so it takes every character loop the layout can prove.
	if l.utf8Text {
		seen := map[int32]bool{}
		for _, info := range l.dominantStates {
			seen[info.state] = true
		}
		for st := int32(1); st < int32(l.numWASM); st++ {
			if seen[st] {
				continue
			}
			if !anchored && ((int(st) < len(l.midAcceptNLBytes) && l.midAcceptNLBytes[st] != 0) ||
				(int(st) < len(l.midAcceptNWBytes) && l.midAcceptNWBytes[st] != 0) ||
				(int(st) < len(l.midAcceptWBytes) && l.midAcceptWBytes[st] != 0)) {
				continue
			}
			ex, ok := l.utf8SelfLoopExits(st, 8)
			if !ok {
				continue
			}
			info := dominantInfo{state: st, exitBytes: ex, utf8: true}
			if unrollAnchored {
				unrolledSkips = append(unrolledSkips, info)
			} else {
				walkSkips = append(walkSkips, info)
			}
		}
	}
	needErr := hasUTF8Dominant(walkSkips) || hasUTF8Dominant(unrolledSkips)

	// The character skips' GATE in the unrolled anchored walk: tested once
	// per stretch of input (a stretch POINT) rather than on every four-byte
	// step, where a long run in a state no skip covers paid for the test
	// throughout (+11.3% fuel). lCheck is the next stretch point, lBound the
	// inner walk's bound, min(lCheck, len).
	gateAnchored := len(unrolledSkips) > 0
	var b []byte
	nV128 := byte(0)
	switch {
	case needErr:
		nV128 = 2 // the chunk and the UTF-8 error lanes
	case len(dom) > 0 || len(walkSkips) > 0:
		nV128 = 1 // the chunk
	}
	nGate := byte(0)
	if gateAnchored {
		nGate = 2 // lCheck, lBound
	}
	switch {
	case nV128 > 0 && nGate > 0:
		b = append(b, 0x03, 0x05, 0x7F, nV128, 0x7B, nGate, 0x7F)
	case nV128 > 0:
		// 4 i32 + 1 i32 skip mask, then the v128s.
		b = append(b, 0x02, 0x05, 0x7F, nV128, 0x7B)
	default:
		b = append(b, 0x01, 0x04, 0x7F) // 4 x i32 locals
	}
	const (
		lSkipMask = byte(8)
		lChunk    = byte(9)
	)
	var lErr byte
	if needErr {
		lErr = 10
	}
	lCheck := 9 + nV128
	lBound := lCheck + 1

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
	// function is guarded by !anchored. The original hypothesis (a per-byte
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
	if unrollAnchored {
		const unroll = 4
		// emitUnrolled emits the four-byte walk; gated, inside the stretch
		// loops (the skips' gate), else as it always was. extra is the
		// nesting it is emitted under.
		emitUnrolled := func(b []byte, gated bool, extra byte) []byte {
			// deadDepth is $done's depth from inside $main4.
			deadDepth := 2 + extra
			if gated {
				deadDepth = 4 + extra
			}
			b = append(b, 0x02, 0x40) // block $tail
			if gated {
				b = append(b, 0x03, 0x40) // loop $outer
				// The stretch point: the character skips, then the next point.
				// `lScanPos + unroll > lCheck` rather than `>=`: a byte-run skip
				// inside the stretch may leave lScanPos short of lCheck by less
				// than a block, and the inner loop exits there too.
				b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x20, lCheck, 0x4B, 0x04, 0x40)
				// A character skip's state holds only between characters, and
				// the walk's four-byte steps put a point inside one as often as
				// not (an odd-length prefix before two-byte letters: always),
				// so the point first reads on a byte at a time to the next
				// character boundary — at most three.
				b = append(b, 0x02, 0x40) // block $aligned
				b = append(b, 0x03, 0x40) // loop $align
				b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x4F, 0x0D, 0x01)
				b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A, 0x2D, 0x00, 0x00)
				b = append(b, 0x41, 0xC0, 0x01, 0x71, 0x41, 0x80, 0x01, 0x47, 0x0D, 0x01) // not a continuation byte
				b = append(b, 0x41)
				b = utils.AppendSLEB128(b, l.tableOff)
				b = append(b, 0x20, lState, 0x41, 0x08, 0x74, 0x6A)
				b = append(b, 0x20, paramPtr, 0x20, lScanPos, 0x6A, 0x2D, 0x00, 0x00, 0x6A)
				b = appendTableLoad8u(b, tableMemIdx)
				b = append(b, 0x22, lState, 0x45, 0x0D, 5+extra) // dead → $done
				b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, lScanPos)
				b = append(b, 0x0C, 0x00) // br $align
				b = append(b, 0x0B)       // end loop $align
				b = append(b, 0x0B)       // end block $aligned
				// The character skip. emitDominantBulkSkip takes the position of
				// the LAST byte read, which here is lScanPos - 1.
				for _, info := range unrolledSkips {
					b = append(b, 0x20, lState, 0x41)
					b = utils.AppendSLEB128(b, info.state)
					b = append(b, 0x46, 0x04, 0x40) // if lState == info.state
					b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6B, 0x21, lScanPos)
					b = emitDominantBulkSkip(b, info, false, lScanPos, paramLen, 0, paramPtr, lChunk, lByteClass, lErr)
					b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, lScanPos)
					b = append(b, 0x0B) // end if
				}
				b = append(b, 0x20, lScanPos, 0x41)
				b = utils.AppendSLEB128(b, probeSkipStretch)
				b = append(b, 0x6A, 0x21, lCheck)
				b = append(b, 0x0B) // end if
				// lBound = min(lCheck, len)
				b = append(b, 0x20, lCheck, 0x20, paramLen, 0x20, lCheck, 0x20, paramLen, 0x49, 0x1B, 0x21, lBound)
				b = append(b, 0x02, 0x40) // block $stretch
			}
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
			// Need all `unroll` bytes in range: lScanPos + unroll > paramLen → tail;
			// under the gate, past the stretch's bound → the stretch point.
			bound := paramLen
			if gated {
				bound = lBound
			}
			b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x20, bound, 0x4B, 0x0D, 0x01)
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
				b = append(b, 0x20, lState, 0x45, 0x0D, deadDepth)
			}
			b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x21, lScanPos)
			b = append(b, 0x0C, 0x00) // br 0 → restart $main4
			b = append(b, 0x0B)       // end loop $main4
			if gated {
				b = append(b, 0x0B) // end block $stretch
				// Out of the stretch: the tail when fewer than a block is left,
				// else the next stretch point.
				b = append(b, 0x20, lScanPos, 0x41, unroll, 0x6A, 0x20, paramLen, 0x4B, 0x0D, 0x01)
				b = append(b, 0x0C, 0x00) // br $outer
				b = append(b, 0x0B)       // end loop $outer
			}
			b = append(b, 0x0B) // end block $tail
			return b
		}
		if gateAnchored {
			// An input shorter than one stretch takes the plain walk: it would
			// never reach a stretch point, and the gate's set-up alone measured
			// +6.4% on a 21-byte call.
			b = append(b, 0x20, paramLen, 0x20, lScanPos, 0x6B, 0x41)
			b = utils.AppendSLEB128(b, probeSkipStretch)
			b = append(b, 0x4F, 0x04, 0x40)             // if len - start >= stretch
			b = append(b, 0x20, lScanPos, 0x21, lCheck) // a stretch point at once
			b = emitUnrolled(b, true, 1)
			b = append(b, 0x05) // else
			b = emitUnrolled(b, false, 1)
			b = append(b, 0x0B) // end if
		} else {
			b = emitUnrolled(b, false, 0)
		}
	}

	b = append(b, 0x03, 0x40) // loop $main
	b = append(b, 0x20, lScanPos, 0x20, paramLen, 0x4F, 0x0D, 0x01)

	if !anchored {
		// Early exit. Only worth it for the scan probe — the anchored probe's
		// answer is not monotone (a mid-accept says nothing about reaching
		// `len`). Which test applies is the caller's choice; see probeExit.
		if p.futureOff != 0 {
			// Liveness exit: stop once no WANTED pattern can still accept
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
	// The run skips (walkSkips above), on the byte just read. A scan probe
	// first takes the exits the loop top would take next — the bits it
	// already holds settle the answer, or no wanted pattern can accept from
	// this state — rather than cross a run it has no use for. Depth 2 from
	// inside the `if` is $done.
	for _, info := range walkSkips {
		b = append(b, 0x20, lState, 0x41)
		b = utils.AppendSLEB128(b, info.state)
		b = append(b, 0x46, 0x04, 0x40) // if lState == info.state
		if !anchored {
			const doneDepth = 2
			if exit == probeExitFirstHit {
				b = append(b, 0x20, lBits, 0x0D, doneDepth)
			} else {
				b = append(b, 0x20, lBits, 0x20, paramValidMask, 0x46, 0x0D, doneDepth)
			}
			if p.futureOff != 0 && int(info.state) < len(p.future) {
				b = append(b, 0x20, paramValidMask, 0x41)
				b = utils.AppendSLEB128(b, int32(uint32(p.future[info.state])))
				b = append(b, 0x71)                                // & future[state]
				b = append(b, 0x20, lBits, 0x41, 0x7F, 0x73, 0x71) // &^ lBits
				b = append(b, 0x45, 0x0D, doneDepth)               // eqz -> $done
			}
		}
		b = emitDominantBulkSkip(b, info, false, lScanPos, paramLen, 0, paramPtr, lChunk, lByteClass, lErr)
		b = append(b, 0x0B) // end if
	}
	b = append(b, 0x20, lScanPos, 0x41, 0x01, 0x6A, 0x21, lScanPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop
	b = append(b, 0x0B) // end block
	if !anchored && p.probeWalkEndP1 > 0 {
		b = append(b, 0x20, lScanPos, 0x24)
		b = utils.AppendULEB128(b, uint32(p.probeWalkEndP1-1)) //nolint:gosec // a global index
	}

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

// buildCountedChainProbeBody is the counted-class-chain equivalent of
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
func genAnchoredWASM(t *dfaTable, tableBase int64, tableMemIdx int, patternIDs []int, utf8Text bool) (body []byte, dataBytes []byte, dataSegCount int, nextTableOffset int32, sparse *sparseAnchoredInfo) {
	numPatterns := len(patternIDs)
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
		// A Unicode-mode set's state looping over whole characters takes the
		// character skip (buildSetProbeBodyExit's run skips).
		utf8Text: utf8Text,
	})

	// Sparse accept: an anchored bucket whose accept is a per-state LIST takes the sparse
	// probe. Same trigger as genSuffixWASM's, and the same reason: it is the
	// only shape that can answer for more patterns than a mask has bits.
	if t.acceptWide != nil {
		// The ANCHORED probe never skips: it walks to prove full consumption,
		// and a skip would have to preserve the same proof. Not attempted.
		tabs := buildSparseAcceptTables(t, int32(l.tableEnd), l.numWASM, false)
		idMapOff := tabs.end
		idMap := make([]byte, numPatterns*4)
		for i, gid := range patternIDs {
			putU32(idMap, i*4, uint32(gid))
		}
		// The anchored probe never skips, so it needs no counter region.
		scratch := planSparseScratch(idMapOff+int32(len(idMap)), numPatterns, 0)
		layoutRaw, layoutCount := stripSegCount(dfaDataSegments(l, false, false))
		dataBytes = append(dataBytes, layoutRaw...)
		dataBytes = append(dataBytes, appendDataSegment(nil, tabs.midOff, tabs.data)...)
		dataBytes = append(dataBytes, appendDataSegment(nil, idMapOff, idMap)...)
		// One zero byte at the top of the scratch so utils.WasmMemTop and the
		// harnesses see the reservation — see genSuffixWASM for why a region
		// nothing declares gets the caller's input written over it.
		dataBytes = append(dataBytes, appendDataSegment(nil, scratch.end-1, []byte{0})...)
		dataSegCount = layoutCount + 3
		nextTableOffset = scratch.end
		raw := buildSparseAnchoredProbeBody(sparseSuffixParams{
			l: l, tabs: tabs, scratch: scratch, globalIDs: patternIDs,
			idMapOff:    idMapOff,
			wasmStart:   uint32(t.startState + 1),
			tableMemIdx: tableMemIdx,
		})
		body = utils.AppendULEB128(nil, uint32(len(raw)))
		body = append(body, raw...)
		sparse = &sparseAnchoredInfo{scratch: scratch, idMapOff: idMapOff}
		return
	}

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
		// States this anchored walk may bulk-skip through — the
		// wide-self-loop flavour followed by the small-self-loop one.
		// Exception mode goes first so it keeps the cheaper compare
		// chain's position when both fire.
		dominantSkip: append(dominantWalkStates(t), memberWalkStates(t)...),
	}
	raw := buildSetProbeBody(p, true)
	body = utils.AppendULEB128(nil, uint32(len(raw)))
	body = append(body, raw...)
	return
}

// probeSkipStretch is the anchored character skips' stretch (the gate in
// buildSetProbeBodyExit): measured, a long run in a loop no skip covers beside
// skippable members cost +3.4% at 64 and +1.7% at 128, a long run skipped 5.48
// against 5.55 fuel/byte, and a run shorter than a stretch is never skipped.
const probeSkipStretch = 128
