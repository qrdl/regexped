package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// Literal-existence absence prefilter (plans/SETS.md §21.3 / G12).
//
// The G8/G9 preflights only need to know which patterns are PROVEN matchless
// in [from, len); over-approximating "alive" is documented-safe (§18.4). A
// pattern whose mandatory literal does not OCCUR in that range cannot match
// there, and that is an exact absence proof — independent of prefixes, word
// boundaries or context, which is why it is sound to use where the offset-
// recovering machinery is not.
//
// The union-walk preflight it replaces costs 32-36 fuel/byte; this costs 1-2.

const (
	// absenceLitMax bounds the emitted verify chain: each literal byte costs
	// a load and a compare at every candidate position.
	absenceLitMax = 16
	// absenceMaxPatterns is the id-space bound. The alive mask is an i64, so
	// a set with any id at or above 64 keeps the union walk rather than
	// silently dropping those patterns from the proof.
	absenceMaxPatterns = 64
)

// absenceLit pairs a pattern's global id with a literal every match of it must
// contain.
type absenceLit struct {
	gid int
	lit []byte
}

// findAbsenceLit returns a literal that MUST appear inside every match of re,
// or nil when no such literal can be extracted.
//
// Deliberately NOT findMandatoryLitRec. That function exists to recover a
// match START from a literal occurrence, so it tracks the literal's offset and
// gives up once the offset becomes unbounded — which is exactly why
// `[^\n]*ERROR` yields nothing there: `[^\n]*` drives curMax to -1 and the
// next recursion hits the `maxOff < 0` guard. For an ABSENCE proof the offset
// is irrelevant; only occurrence matters. Q5 established that none of B41's
// start-recovery concerns apply to this use.
//
// Returns the LONGEST literal it can find, since selectivity is the whole
// point: a 5-byte literal rules a pattern out far more often than a 1-byte one.
func findAbsenceLit(re *syntax.Regexp) []byte {
	if re == nil {
		return nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		// FoldCase would need a case-insensitive search; non-ASCII would need
		// the UTF-8 encoding of each rune. Neither is worth it here.
		if re.Flags&syntax.FoldCase != 0 {
			return nil
		}
		bs := make([]byte, 0, len(re.Rune))
		for _, r := range re.Rune {
			if r > 127 {
				return nil
			}
			bs = append(bs, byte(r))
		}
		if len(bs) == 0 {
			return nil
		}
		if len(bs) > absenceLitMax {
			bs = bs[:absenceLitMax]
		}
		return bs

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return findAbsenceLit(re.Sub[0])
		}
		return nil

	case syntax.OpPlus:
		// The body runs at least once, so its literal is mandatory.
		if len(re.Sub) == 1 {
			return findAbsenceLit(re.Sub[0])
		}
		return nil

	case syntax.OpRepeat:
		if re.Min >= 1 && len(re.Sub) == 1 {
			return findAbsenceLit(re.Sub[0])
		}
		return nil

	case syntax.OpConcat:
		// Every child is traversed by every match, so ANY child's literal is
		// mandatory — unlike findMandatoryLitRec this need not stop at the
		// first, and picking the longest is strictly better.
		var best []byte
		for _, sub := range re.Sub {
			if lit := findAbsenceLit(sub); len(lit) > len(best) {
				best = lit
			}
		}
		return best

	default:
		// OpAlternate: a literal mandatory in one branch is not mandatory in
		// the match, and requiring it would UNDER-approximate alive — the
		// unsafe direction. OpStar/OpQuest/OpRepeat{0,n}: the body may be
		// skipped entirely. All correctly yield nothing.
		return nil
	}
}

// buildAbsenceLits computes the per-pattern absence literals for a set, plus
// the mask of patterns that have none and are therefore ALWAYS reported alive.
//
// ok is false when the prefilter cannot serve this set at all — no pattern
// carries a literal (it would prove nothing), or an id lies outside the i64
// mask.
func buildAbsenceLits(spec SetSpec) (lits []absenceLit, alwaysAlive uint64, ok bool) {
	for i, p := range spec.Patterns {
		if i >= len(spec.PatternIDs) {
			return nil, 0, false
		}
		gid := spec.PatternIDs[i]
		if gid < 0 || gid >= absenceMaxPatterns {
			return nil, 0, false
		}
		parsed, err := syntax.Parse(p.fullPattern, syntax.Perl)
		if err != nil {
			return nil, 0, false
		}
		stripCaptures(parsed)
		lit := findAbsenceLit(parsed)
		if len(lit) == 0 {
			alwaysAlive |= uint64(1) << uint(gid)
			continue
		}
		lits = append(lits, absenceLit{gid: gid, lit: lit})
	}
	return lits, alwaysAlive, len(lits) > 0
}

// usesAbsencePrefilter reports whether this set's preflight should be the
// literal-existence scan rather than the union walk.
func (cs *compiledSet) usesAbsencePrefilter() bool {
	return cs.absenceOK && len(cs.absenceLits) > 0
}

// emitAbsenceVerify emits, for one candidate position, the check of every
// literal still being searched for. A literal that verifies marks its pattern
// alive and leaves the search set.
func emitAbsenceVerify(b []byte, cs *compiledSet, lPos, lSearch, aliveLocal, pInPtr, pInLen byte) []byte {
	for i, al := range cs.absenceLits {
		bit := uint32(1) << uint(i)
		// if (lSearch & bit) != 0 — skip literals already found.
		b = append(b, 0x20, lSearch, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71, 0x04, 0x40)

		// if lPos + len(lit) <= pInLen — the literal must fit.
		b = append(b, 0x20, lPos, 0x41)
		b = utils.AppendSLEB128(b, int32(len(al.lit)))
		b = append(b, 0x6A, 0x20, pInLen, 0x4D) // i32.add; i32.le_u
		b = append(b, 0x04, 0x40)

		// input[lPos+j] == lit[j], ANDed across the literal.
		for j, lb := range al.lit {
			b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
			b = append(b, 0x2D, 0x00)
			b = utils.AppendULEB128(b, uint32(j)) // load offset immediate
			b = append(b, 0x41)
			b = utils.AppendSLEB128(b, int32(lb))
			b = append(b, 0x46) // i32.eq
			if j > 0 {
				b = append(b, 0x71) // i32.and
			}
		}
		b = append(b, 0x04, 0x40) // if the literal matched here

		// alive |= 1<<gid ; searchMask &= ^bit
		b = append(b, 0x20, aliveLocal, 0x42)
		b = utils.AppendSLEB128_64(b, int64(uint64(1)<<uint(al.gid)))
		b = append(b, 0x84, 0x21, aliveLocal) // i64.or
		b = append(b, 0x20, lSearch, 0x41)
		b = utils.AppendSLEB128(b, int32(^bit))
		b = append(b, 0x71, 0x21, lSearch) // i32.and

		b = append(b, 0x0B) // end if matched
		b = append(b, 0x0B) // end if fits
		b = append(b, 0x0B) // end if still searching
	}
	return b
}

// emitLiteralAbsenceMask leaves in aliveLocal the i64 mask of patterns NOT
// proven matchless in [from, len) — the same contract emitUnionAliveMask has,
// computed by literal search instead of by walking the union automaton.
//
// Structure: a 16-byte SIMD sweep looking for the first bytes of the literals
// still being searched for, falling back to a per-position verify at each
// candidate, then a scalar tail for the final partial chunk. The compare chain
// is built only from literals still in the search set, so a set that finds its
// common literal early stops paying for it — which is what keeps the scan near
// 1 fuel/byte on inputs full of that byte.
func emitLiteralAbsenceMask(b []byte, cs *compiledSet, lPos, lSearch, lMask, lChunk, aliveLocal byte) []byte {
	const (
		pInPtr = 0
		pInLen = 1
		pFrom  = 2
	)
	// alive starts as the patterns nothing can rule out.
	b = append(b, 0x42)
	b = utils.AppendSLEB128_64(b, int64(cs.absenceAlive))
	b = append(b, 0x21, aliveLocal)
	// searchMask starts with a bit per literal.
	searchInit := uint32(0)
	for i := range cs.absenceLits {
		searchInit |= uint32(1) << uint(i)
	}
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(searchInit))
	b = append(b, 0x21, lSearch)
	b = append(b, 0x20, pFrom, 0x21, lPos)

	b = append(b, 0x02, 0x40) // block $done   (br 2 from the loop body)
	b = append(b, 0x02, 0x40) // block $tail   (br 1)
	b = append(b, 0x03, 0x40) // loop  $simd   (br 0)

	// Every literal found: nothing left to prove.
	b = append(b, 0x20, lSearch, 0x45, 0x0D, 0x02)
	// Partial chunk left: hand over to the scalar tail.
	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x20, pInLen, 0x4B, 0x0D, 0x01)

	b = append(b, 0x20, pInPtr, 0x20, lPos, 0x6A)
	b = append(b, 0xFD, 0x00, 0x00, 0x00) // v128.load
	b = append(b, 0x21, lChunk)

	// mask = OR, over literals STILL being searched for, of the lanes equal to
	// that literal's first byte. Gating each arm on lSearch is what makes the
	// scan cheapen as literals are found: once a common first byte is out of
	// the set, chunks full of it stop producing candidates.
	b = append(b, 0x41, 0x00) // accumulator seed
	for i, al := range cs.absenceLits {
		bit := uint32(1) << uint(i)
		b = append(b, 0x20, lSearch, 0x41)
		b = utils.AppendSLEB128(b, int32(bit))
		b = append(b, 0x71)       // i32.and
		b = append(b, 0x04, 0x7F) // if (i32 result)
		b = append(b, 0x20, lChunk)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, int32(al.lit[0]))
		b = append(b, 0xFD, 0x0F) // i8x16.splat
		b = append(b, 0xFD, 0x23) // i8x16.eq
		b = append(b, 0xFD, 0x64) // i8x16.bitmask
		b = append(b, 0x05)       // else
		b = append(b, 0x41, 0x00)
		b = append(b, 0x0B) // end if
		b = append(b, 0x72) // i32.or
	}
	b = append(b, 0x21, lMask)

	b = append(b, 0x20, lMask, 0x45) // mask == 0 ?
	b = append(b, 0x04, 0x40)        // if: whole chunk is free of candidates
	b = append(b, 0x20, lPos, 0x41, 0x10, 0x6A, 0x21, lPos)
	b = append(b, 0x05) // else: verify at the first candidate lane
	b = append(b, 0x20, lPos, 0x20, lMask, 0x68, 0x6A, 0x21, lPos)
	b = emitAbsenceVerify(b, cs, lPos, lSearch, aliveLocal, pInPtr, pInLen)
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0B) // end if

	b = append(b, 0x0C, 0x00) // br $simd
	b = append(b, 0x0B)       // end loop $simd
	b = append(b, 0x0B)       // end block $tail

	// Scalar tail: the final partial chunk, one position at a time.
	b = append(b, 0x03, 0x40) // loop $tail_scan
	b = append(b, 0x20, lSearch, 0x45, 0x0D, 0x01)
	b = append(b, 0x20, lPos, 0x20, pInLen, 0x4F, 0x0D, 0x01)
	b = emitAbsenceVerify(b, cs, lPos, lSearch, aliveLocal, pInPtr, pInLen)
	b = append(b, 0x20, lPos, 0x41, 0x01, 0x6A, 0x21, lPos)
	b = append(b, 0x0C, 0x00)
	b = append(b, 0x0B) // end loop $tail_scan

	b = append(b, 0x0B) // end block $done
	return b
}
