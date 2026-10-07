package compile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/qrdl/regexped/internal/utils"
)

// --------------------------------------------------------------------------
// TDFA capture-body bulk-skip for dominant self-loop states.
//
// Capture patterns with a simple repeated-class body ((\w+), <([a-z]+)>,
// X([a-zA-Z]+)Y) spend most of their runtime byte-stepping through a single
// TDFA state that self-loops on a class of bytes while writing the same
// "set register to current pos" tag op on every iteration. Since a capture
// register is only ever read once, at accept, every intermediate write
// during such a run is dead except the last — the whole run can be skipped
// with a SIMD scan and a single register write for the final position.
//
// This is a different optimization from the plain-DFA dominant
// self-loop bulk-skip (detectDominantSelfLoop/emitDominantBulkSkip): that
// machinery is tuned for large self-loop / tiny exit-set states (e.g. `.`
// inside a comment body) and is the wrong polarity for this skip's population,
// which has small self-loop classes (\w=63 bytes, [a-z]=26, [a-zA-Z]=52)
// and large exit sets. This skip reuses emitShuftiPrefixCheck's technique
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
//     scope
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
//
// midAcceptTail, when non-nil, is emitted just after info.ops in the K > 0
// branch. It carries the per-byte mid-accept bookkeeping the scalar loop
// does and this routine otherwise skips wholesale:
// state is unchanged across the whole run, so if it is mid-accepting then
// every skipped position was an accept of the same state and a single
// check at the final position reproduces the scalar invariant exactly.
// Without it, a dead exit byte after the run falls back to whatever
// lastAcceptPos held before it — `^([a-z]+)` on "aaaa!…" reported [0 1].
// The caller passes nil when the bulk state is not mid-accepting (or when
// the whole lastAccept mechanism is off), so patterns that never needed
// the bookkeeping keep their previous bytes.
func emitTDFABulkSkip(b []byte, info *tdfaBulkSkipInfo, localPos, localChunk, localMask, localSkipStart, localCapBase uint32, midAcceptTail func([]byte) []byte) []byte {
	// skipStart = pos
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x21, byte(localSkipStart))

	b = append(b, 0x02, 0x40) // block $skip_done
	b = append(b, 0x03, 0x40) // loop $chunks

	// pos + 16 > len: not enough bytes for a full chunk at pos. Rather than
	// leave the remainder to the scalar walk, take ONE overlapping chunk
	// backwards from the end and mask off the lanes below pos.
	//
	// Without this the last `len mod 16` bytes of every run are walked one at a
	// time, which is the sawtooth measured on the capture body: the
	// same pattern costs 1,013 fuel at a 15-byte run and 227 at 16, and 1,072 at
	// 31 against 263 at 32. The step is entirely the missing tail.
	//
	// Every byte read is inside the input (guarded on len >= 16), so nothing has
	// to be arranged with the caller. Correctness is the same argument the
	// prefix scan's tail probe uses: the shift drops exactly the lanes for
	// positions before pos, which this attempt has already passed, and a zero
	// mask proves every remaining byte self-loops — so the walk can go straight
	// to len instead of stepping there, which is what the scalar loop would have
	// concluded one byte at a time.
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x4B)       // i32.gt_u
	b = append(b, 0x04, 0x40) // if $tail
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x4F)       // i32.ge_u — a full window exists in the input
	b = append(b, 0x04, 0x40) // if $tail_window

	// chunk = v128.load(ptr + len - 16)
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x6A)       // i32.add
	b = append(b, 0xFD, 0x00, 0x00, 0x00)
	b = append(b, 0x21, byte(localChunk))

	// mask = shufti_stop(chunk) >> (pos - (len - 16))
	b = emitShuftiStopMask(b, info.selfLoopBytes, byte(localChunk))
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x6B)       // i32.sub
	b = append(b, 0x41, 0x10) // i32.const 16
	b = append(b, 0x6A)       // i32.add — shift, in [1,16]
	b = append(b, 0x76)       // i32.shr_u
	b = append(b, 0x21, byte(localMask))

	b = append(b, 0x20, byte(localMask))
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if — every remaining byte self-loops
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x21, byte(localPos))
	b = append(b, 0x05) // else — stop ON the first exit byte at or after pos
	b = append(b, 0x20, byte(localMask))
	b = append(b, 0x68) // i32.ctz
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A) // i32.add
	b = append(b, 0x21, byte(localPos))
	b = append(b, 0x0B) // end if

	b = append(b, 0x0B)       // end if $tail_window
	b = append(b, 0x0C, 0x02) // br 2 -> $skip_done
	b = append(b, 0x0B)       // end if $tail

	// chunk = v128.load(ptr + pos)
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, byte(localPos))
	b = append(b, 0x6A)                   // i32.add
	b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load align=0 offset=0
	b = append(b, 0x21, byte(localChunk)) // local.set chunk

	// mask = shufti_stop(selfLoopBytes, chunk) -- bit k=1 ⇔ lane k is an EXIT
	// byte. The stop polarity comes straight out of the primitive's final
	// compare; it used to be a member mask followed by `xor 0xFFFF`.
	b = emitShuftiStopMask(b, info.selfLoopBytes, byte(localChunk))
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
	if midAcceptTail != nil {
		b = midAcceptTail(b)
	}
	b = append(b, 0x0C, 0x02) // br 2 -> loop $main (see doc comment on depth assumption)
	b = append(b, 0x0B)       // end if

	return b
}

// tdfaUTF8SkipInfo is a TDFA loop over whole UTF-8 characters — a
// Unicode-mode class holding every non-ASCII character, `.`, `[^,]`, lowered
// to a cycle through one state per character byte — that the UTF-8 skip
// crosses 16 bytes at a time (emitTDFAUTF8Skip). The TDFA is not minimized,
// so the loop can be several states with identical rows: `[^>]`'s ASCII is
// two ranges, `<([^>]+)>` keeps one state for each, and every character leads
// back to one of them.
type tdfaUTF8SkipInfo struct {
	wasmStates []int32     // the loop's states, gs+1; identical rows and accept data
	exitBytes  []byte      // its ASCII exits, at most 8
	ops        []tdfaTagOp // fired by every ASCII byte that stays in the loop and every character's last byte; all set-to-pos
}

// maxTDFAUTF8SkipLoops caps the loops, and maxTDFAUTF8SkipLoopStates each
// loop's states, the match body tests for on every byte.
const (
	maxTDFAUTF8SkipLoops      = 2
	maxTDFAUTF8SkipLoopStates = 4
)

// detectTDFAUTF8Skip returns the loops of a Unicode-mode TDFA the UTF-8 skip
// may serve. A loop is a state together with every state whose row (each
// byte's successor and tag ops) and accept data are identical to its own, so
// that any one of them behaves as any other from there on. Every ASCII byte
// but at most eight leads from the loop back into it, firing one batch of
// set-to-pos ops; every valid multi-byte character does too, through states
// outside it that neither accept nor are dead, with that same batch on the
// character's last byte and, before it, only set-to-pos ops on registers the
// batch sets again. A run of such characters and bytes then leaves every
// register the batch sets at the run's end — as one firing of the batch there
// does — and the walk in a state of the loop, which the skip need not name.
func detectTDFAUTF8Skip(tt *tdfaTable) []tdfaUTF8SkipInfo {
	at := func(s, c int) (int, []tdfaTagOp) {
		idx := s*256 + c
		var ops []tdfaTagOp
		if idx < len(tt.tagOps) {
			ops = tt.tagOps[idx]
		}
		return tt.transitions[idx], ops
	}
	// Group the states by row and accept data, once: a loop is a group.
	key := func(s int) string {
		var k strings.Builder
		for c := 0; c < 256; c++ {
			t, o := at(s, c)
			fmt.Fprintf(&k, "%d%v;", t, o)
		}
		var acceptOps []tdfaTagOp
		if s < len(tt.acceptOps) {
			acceptOps = tt.acceptOps[s]
		}
		var regs []int
		if s < len(tt.acceptRegMap) {
			regs = tt.acceptRegMap[s]
		}
		fmt.Fprintf(&k, "|%d|%d|%d|%v|%v", tt.acceptStates[s], tt.midAcceptStates[s], tt.immediateAcceptStates[s], acceptOps, regs)
		return k.String()
	}
	groups := map[string][]int{}
	keys := make([]string, tt.numStates)
	for s := 0; s < tt.numStates; s++ {
		keys[s] = key(s)
		groups[keys[s]] = append(groups[keys[s]], s)
	}
	claimed := map[int]bool{}
	var out []tdfaUTF8SkipInfo
	for gs := 0; gs < tt.numStates && len(out) < maxTDFAUTF8SkipLoops; gs++ {
		if claimed[gs] || tt.immediateAcceptStates[gs] != 0 {
			continue
		}
		members := groups[keys[gs]]
		if len(members) > maxTDFAUTF8SkipLoopStates {
			continue
		}
		loop := map[int]bool{}
		for _, m := range members {
			loop[m] = true
		}
		var exits []byte
		var ops []tdfaTagOp
		haveOps, ok := false, true
		for c := 0; c < 0x80 && ok; c++ {
			next, o := at(gs, c)
			switch {
			case next < 0 || !loop[next]:
				exits = append(exits, byte(c))
				ok = len(exits) <= 8
			case !haveOps:
				ops, haveOps = o, true
			default:
				ok = tdfaTagOpsEqual(ops, o)
			}
		}
		if !ok || !haveOps {
			continue
		}
		sets := map[int]bool{}
		for _, op := range ops {
			if op.src != -1 {
				ok = false
			}
			sets[op.dst] = true
		}
		inner := func(s int, o []tdfaTagOp) bool {
			if s < 0 || loop[s] || tt.immediateAcceptStates[s] != 0 || tt.midAcceptStates[s] != 0 {
				return false
			}
			for _, op := range o {
				if op.src != -1 || !sets[op.dst] {
					return false
				}
			}
			return true
		}
		for _, seq := range utf8Sequences {
			if !ok {
				break
			}
			cur := map[int]bool{}
			for c := int(seq[0][0]); c <= int(seq[0][1]) && ok; c++ {
				next, o := at(gs, c)
				ok = inner(next, o)
				cur[next] = true
			}
			for i, r := range seq[1:] {
				nxt := map[int]bool{}
				for s := range cur {
					for c := int(r[0]); c <= int(r[1]) && ok; c++ {
						t, o := at(s, c)
						if i == len(seq)-2 {
							ok = t >= 0 && loop[t] && tdfaTagOpsEqual(ops, o)
						} else {
							ok = inner(t, o)
						}
						nxt[t] = true
					}
				}
				cur = nxt
			}
		}
		if !ok {
			continue
		}
		info := tdfaUTF8SkipInfo{exitBytes: exits, ops: ops}
		for s := range loop {
			claimed[s] = true
			info.wasmStates = append(info.wasmStates, int32(s+1))
		}
		slices.Sort(info.wasmStates)
		out = append(out, info)
	}
	return out
}

// emitTDFAUTF8Skip emits the UTF-8 skip for info: the dominant DFA skip's
// stops (emitUTF8BulkSkip) with the TDFA loop's positions — pos is the next
// byte to read, so the chunk starts at pos and pos ends on the first byte not
// skipped — and, when anything was skipped, info.ops fired once at the new
// pos, then a jump back to loop $main, mainDepth blocks out from where this
// is emitted. The state is left as it is: every state of the loop behaves
// alike. On entry the state is one of info.wasmStates.
//
// It runs where the walk ENTERS the loop — in the tag-op dispatch's arm of
// every state outside the loop that has a transition into it
// (emitTDFATagOps' hook): a run of whole characters starts only there, since
// the skip leaves the walk in the loop only before a byte that leaves it, a
// character the chunk cuts, invalid UTF-8 or the end of the input, and from
// each of those the walk re-enters, if at all, through such an arm. Tested at
// the top of the main loop instead, the test ran on every byte — `(.+)=(.+)`
// over text with `=` every 15 bytes, whose walk leaves the loop at the first
// `=`, cost 5% more fuel for it.
func emitTDFAUTF8Skip(b []byte, info tdfaUTF8SkipInfo, mainDepth uint32, localPos, localChunk, localMask, localSkipStart, localCapBase uint32, midAcceptTail func([]byte) []byte) []byte {
	pos, chunk, mask := byte(localPos), byte(localChunk), byte(localMask)
	b = append(b, 0x20, pos, 0x21, byte(localSkipStart)) // skipStart = pos
	b = append(b, 0x02, 0x40)                            // block $skip_done
	b = append(b, 0x03, 0x40)                            // loop $chunks
	// pos + 16 > len: br $skip_done
	b = append(b, 0x20, pos, 0x41, 0x10, 0x6A, 0x20, 0x01, 0x4B, 0x0D, 0x01)
	// chunk = v128.load(ptr + pos)
	b = append(b, 0x20, 0x00, 0x20, pos, 0x6A, 0xFD, 0x00, 0x00, 0x00, 0x21, chunk)
	b = emitBulkSkipExitMask(b, info.exitBytes, chunk)
	b = append(b, 0x21, mask)
	// An all-ASCII chunk: stop at the first exit byte, or take all 16.
	b = append(b, 0x20, chunk, 0xFD, 0x64, 0x45, 0x04, 0x40)
	b = append(b, 0x20, mask, 0x45, 0x04, 0x40)
	b = append(b, 0x20, pos, 0x41, 0x10, 0x6A, 0x21, pos, 0x0C, 0x02) // br $chunks
	b = append(b, 0x0B)
	b = append(b, 0x20, mask, 0x68, 0x20, pos, 0x6A, 0x21, pos, 0x0C, 0x02) // br $skip_done
	b = append(b, 0x0B)
	// Invalid UTF-8: stop before the faulty character.
	b = emitUTF8ErrorLanes(b, chunk)
	b = append(b, 0xFD, 0x53, 0x04, 0x40)
	b = emitUTF8ErrorStop(b, chunk, mask)
	b = append(b, 0x20, pos, 0x6A, 0x21, pos, 0x0C, 0x02) // br $skip_done
	b = append(b, 0x0B)
	// No exit byte: to the lead byte of a character the chunk cuts, or 16.
	b = append(b, 0x20, mask, 0x45, 0x04, 0x40)
	b = append(b, 0x20, chunk, 0xFD, 0x0C)
	b = append(b, utf8OpenTail[:]...)
	b = append(b, 0xFD, 0x28, 0xFD, 0x64, 0x41)
	b = utils.AppendSLEB128(b, 0x10000)
	b = append(b, 0x72, 0x68, 0x20, pos, 0x6A, 0x21, pos, 0x0C, 0x01) // br $chunks
	b = append(b, 0x0B)
	b = append(b, 0x20, mask, 0x68, 0x20, pos, 0x6A, 0x21, pos) // on the exit byte
	b = append(b, 0x0B, 0x0B)                                   // end loop, end block
	// if pos != skipStart: fire the ops once, loop back to $main
	b = append(b, 0x20, pos, 0x20, byte(localSkipStart), 0x47, 0x04, 0x40)
	for _, op := range info.ops {
		b = emitTDFATagOp(op, b, localPos, localCapBase)
	}
	if midAcceptTail != nil {
		b = midAcceptTail(b)
	}
	b = append(b, 0x0C) // br -> loop $main
	b = utils.AppendULEB128(b, mainDepth+1)
	b = append(b, 0x0B)
	return b
}

// emitTDFAStateIn pushes whether the state local holds one of states (sorted):
// one compare for one state, a range compare for consecutive ones — the test
// runs on every byte of the match body — and a chain of compares otherwise.
func emitTDFAStateIn(b []byte, states []int32, stateLocal byte) []byte {
	lo, n := states[0], int32(len(states))
	if n == 1 {
		b = append(b, 0x20, stateLocal, 0x41)
		b = utils.AppendSLEB128(b, lo)
		return append(b, 0x46) // i32.eq
	}
	if states[n-1]-lo == n-1 {
		b = append(b, 0x20, stateLocal, 0x41)
		b = utils.AppendSLEB128(b, lo)
		b = append(b, 0x6B, 0x41) // i32.sub
		b = utils.AppendSLEB128(b, n)
		return append(b, 0x49) // i32.lt_u
	}
	for i, st := range states {
		b = append(b, 0x20, stateLocal, 0x41)
		b = utils.AppendSLEB128(b, st)
		b = append(b, 0x46) // i32.eq
		if i > 0 {
			b = append(b, 0x72) // i32.or
		}
	}
	return b
}

// entersFrom reports whether state gs lies outside the loop and has a
// transition into it: the arms emitTDFAUTF8Skip runs in.
func (info tdfaUTF8SkipInfo) entersFrom(tt *tdfaTable, gs int) bool {
	if slices.Contains(info.wasmStates, int32(gs+1)) {
		return false
	}
	for c := 0; c < 256; c++ {
		if t := tt.transitions[gs*256+c]; t >= 0 && slices.Contains(info.wasmStates, int32(t+1)) {
			return true
		}
	}
	return false
}

// tdfaHasTagOps reports whether any transition of tt carries a tag op —
// whether emitTDFATagOps emits a dispatch at all.
func tdfaHasTagOps(tt *tdfaTable) bool {
	for _, ops := range tt.tagOps {
		if len(ops) > 0 {
			return true
		}
	}
	return false
}
