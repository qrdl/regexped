package compile

import "github.com/qrdl/regexped/internal/utils"

// --------------------------------------------------------------------------
// Gap F: TDFA capture-body bulk-skip for dominant self-loop states.
//
// Capture patterns with a simple repeated-class body ((\w+), <([a-z]+)>,
// X([a-zA-Z]+)Y) spend most of their runtime byte-stepping through a single
// TDFA state that self-loops on a class of bytes while writing the same
// "set register to current pos" tag op on every iteration. Since a capture
// register is only ever read once, at accept, every intermediate write
// during such a run is dead except the last — the whole run can be skipped
// with a SIMD scan and a single register write for the final position.
//
// This is a different optimization from Task 7's plain-DFA dominant
// self-loop bulk-skip (detectDominantSelfLoop/emitDominantBulkSkip): that
// machinery is tuned for large self-loop / tiny exit-set states (e.g. `.`
// inside a comment body) and is the wrong polarity for Gap F's population,
// which has small self-loop classes (\w=63 bytes, [a-z]=26, [a-zA-Z]=52)
// and large exit sets. Gap F reuses emitShuftiPrefixCheck's technique
// instead (a generalized ≤64-member positive-membership SIMD test).

// tdfaBulkSkipInfo describes one dominant self-loop state in a tdfaTable
// that qualifies for SIMD bulk-skip in the match body.
type tdfaBulkSkipInfo struct {
	wasmState     int32       // gs+1 — compared against the runtime state local
	selfLoopBytes []byte      // 8..64 bytes this state self-loops on, sorted
	ops           []tdfaTagOp // uniform tag-op batch fired on every self-loop byte; every op.src == -1
}

// enableTDFABulkSkip gates the emitter (buildTDFAMatchBody) only; detection
// always runs. Flip to true once the correctness sweep passes, then remove
// entirely (fold into unconditional code) rather than leave a dead toggle.
const enableTDFABulkSkip = true

const (
	tdfaBulkSkipMinBytes = 8
	tdfaBulkSkipMaxBytes = 64
)

// detectTDFABulkSkip scans tt for a single state that:
//   - is not an immediate-accept state (leftmost-first early exit — irrelevant here)
//   - self-loops on between tdfaBulkSkipMinBytes and tdfaBulkSkipMaxBytes distinct bytes
//   - fires the exact same tag-op batch on every one of those self-loop bytes
//   - every op in that batch is a set-to-pos op (src == -1); copy ops are out of
//     v1 scope (see plan Gap F, "Scope decisions")
//
// Returns the state with the largest self-loop class among qualifying states,
// or nil if none qualify. Only one dominant state is supported per pattern.
func detectTDFABulkSkip(tt *tdfaTable) *tdfaBulkSkipInfo {
	var best *tdfaBulkSkipInfo
	for gs := 0; gs < tt.numStates; gs++ {
		if tt.immediateAcceptStates[gs] != 0 {
			continue
		}

		var selfBytes []byte
		var sameOps []tdfaTagOp
		haveOps := false
		allSame := true
		for bv := 0; bv < 256; bv++ {
			idx := gs*256 + bv
			if idx >= len(tt.transitions) || tt.transitions[idx] != gs {
				continue
			}
			selfBytes = append(selfBytes, byte(bv))
			var ops []tdfaTagOp
			if idx < len(tt.tagOps) {
				ops = tt.tagOps[idx]
			}
			if !haveOps {
				sameOps = ops
				haveOps = true
			} else if !tdfaTagOpsEqual(sameOps, ops) {
				allSame = false
				break
			}
		}
		if !haveOps || !allSame {
			continue
		}
		if len(selfBytes) < tdfaBulkSkipMinBytes || len(selfBytes) > tdfaBulkSkipMaxBytes {
			continue
		}

		safeSetOnly := true
		for _, op := range sameOps {
			if op.src != -1 {
				safeSetOnly = false
				break
			}
		}
		if !safeSetOnly {
			continue
		}

		if best == nil || len(selfBytes) > len(best.selfLoopBytes) {
			best = &tdfaBulkSkipInfo{
				wasmState:     int32(gs + 1),
				selfLoopBytes: selfBytes,
				ops:           sameOps,
			}
		}
	}
	return best
}

// emitTDFABulkSkip emits a SIMD bulk-skip for a single dominant self-loop
// TDFA state. Called from buildTDFAMatchBody immediately after the
// "if pos>=len: br $done" check and before "prevState = state", wrapped by
// the caller in `if state == info.wasmState { ... }` ("if A").
//
// On entry: state == info.wasmState, pos < len (guaranteed by the caller's
// pos>=len check just above the wrapping "if A"). On exit, pos has advanced
// by K >= 0 self-loop bytes. If K > 0, info.ops fires exactly once with
// pos = the final skipped position — correct because every op is a
// set-to-pos op and, since a capture register is only ever read once at
// accept, only the last of K intermediate scalar writes would have
// survived anyway. The routine then branches back to the top of loop $main
// (br 2, counting up through this function's own "if pos!=skipStart" body
// (0), the caller's wrapping "if A" (1), to loop $main (2) — this depth is
// NOT self-contained: it assumes the caller wraps this call in exactly one
// "if", directly inside loop $main, with no additional nesting).
// If K == 0 the routine falls through so the caller's unchanged scalar
// path handles the single next byte — guaranteed not to be a self-loop
// byte in that case, since K==0 only happens when the very first byte
// examined already failed the self-loop membership test.
func emitTDFABulkSkip(b []byte, info *tdfaBulkSkipInfo, localPos, localChunk, localMask, localSkipStart, localCapBase uint32) []byte {
	// skipStart = pos
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x21, byte(localSkipStart))

	b = append(b, 0x02, 0x40) // block $skip_done
	b = append(b, 0x03, 0x40) // loop $chunks

	// if pos + 16 > len: br_if 1 -> $skip_done (not enough bytes for a full chunk)
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x0D, 0x01) // br_if 1

	// chunk = v128.load(ptr + pos)
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A)                   // i32.add
	b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
	b = append(b, 0x21, byte(localChunk)) // local.set chunk

	// mask = shufti(selfLoopBytes, chunk) -- bit k=1 ⇔ lane k IS a self-loop byte
	b = emitShuftiPrefixCheck(b, info.selfLoopBytes, byte(localChunk))
	// mask ^= 0xFFFF -- bit k=1 ⇔ lane k is an exit byte (bitmask zero-extends
	// the upper 16 bits, so this only flips the lanes that matter)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, 0xFFFF)
	b = append(b, 0x73)                  // i32.xor
	b = append(b, 0x21, byte(localMask)) // local.set mask

	// if mask == 0: whole chunk is self-loop bytes
	b = append(b, 0x20, byte(localMask))
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void)
	//   pos += 16; br 1 -> continue $chunks
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x21, byte(localPos))
	b = append(b, 0x0C, 0x01) // br 1
	b = append(b, 0x05)       // else
	//   pos += ctz(mask); br 2 -> $skip_done
	b = append(b, 0x20, byte(localMask))
	b = append(b, 0x68) // i32.ctz
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, byte(localPos))
	b = append(b, 0x0C, 0x02) // br 2
	b = append(b, 0x0B)       // end if

	b = append(b, 0x0B) // end loop $chunks
	b = append(b, 0x0B) // end block $skip_done

	// if pos != skipStart: fire the self-loop's tag ops once, loop back to $main
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, byte(localSkipStart))
	b = append(b, 0x47)       // i32.ne
	b = append(b, 0x04, 0x40) // if (void)
	for _, op := range info.ops {
		b = emitTDFATagOp(op, b, localPos, localCapBase)
	}
	b = append(b, 0x0C, 0x02) // br 2 -> loop $main (see doc comment on depth assumption)
	b = append(b, 0x0B)       // end if

	return b
}
