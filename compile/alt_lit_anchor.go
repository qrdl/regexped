package compile

import (
	"regexp/syntax"

	"github.com/qrdl/regexped/internal/utils"
)

// compiledAltLitAnchor holds everything compileAltLitAnchorBranches builds:
// N branches' backward/forward-verify function bodies and DFA data segments,
// plus the shared Teddy/first-byte frontend over the union of all branches'
// literals. Assigned onto compiledPattern by the compile.go call site on
// success.
type compiledAltLitAnchor struct {
	branches       []altLitAnchorCompiledBranch
	fixedPrefixLen int32

	firstByteOff   int32
	firstByteFlags [256]byte
	firstBytes     []byte
	teddyLoOff     int32
	teddyHiOff     int32
	teddyLoBytes   []byte
	teddyHiBytes   []byte
	teddyT1LoOff   int32
	teddyT1HiOff   int32
	teddyT1LoBytes []byte
	teddyT1HiBytes []byte

	dataBytes    []byte
	dataSegCount int
	tableEnd     int64
}

// compileAltLitAnchorBranches compiles each branch's own forward LF DFA and
// reversed-prefix DFA (reusing the exact same per-branch gates and DFA-build
// sequence the single-pattern lit-anchor path already applies — word
// boundary exclusion, reversed-DFA Unicode/u8-fits checks, anchored-or-
// non-accepting-start check), then builds one shared Teddy frontend over the
// union of all branches' literals.
//
// All-or-nothing: any single branch failing any gate rejects the whole
// alternation (ok=false), matching Gap E's existing contract. Callers must
// fall through cleanly to the standard combined-DFA find path on rejection.
func compileAltLitAnchorBranches(branches []altLitAnchorBranch, cur int64, buildOpts CompileOptions) (*compiledAltLitAnchor, bool) {
	maxStates := resolveMaxDFAStates(&buildOpts)
	result := &compiledAltLitAnchor{}

	compiled := make([]altLitAnchorCompiledBranch, 0, len(branches))
	var allLits [][]byte

	for i, br := range branches {
		lfOpts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: true}
		matcher, err := compile(br.branchRe.String(), lfOpts)
		if err != nil {
			return nil, false
		}
		fwdMatcher, ok := matcher.(*dfa)
		if !ok {
			return nil, false
		}
		table := dfaTableFrom(fwdMatcher)
		if table.hasWordBoundary || prefixContainsWordBoundary(br.lap.prefixRe) {
			return nil, false
		}

		l := buildDFALayout(table, cur, true, true, resolveCompiledDFAThreshold(&buildOpts), false, false, false, false)
		if !l.useU8 {
			return nil, false
		}

		// Reversed-prefix DFA for the backward scan (same sequence as the
		// single-pattern lit-anchor path in compile.go).
		revRe := reverseRegexp(br.lap.prefixRe)
		revSimplified := revRe.Simplify()
		revProg, revCompErr := syntax.Compile(revSimplified)
		if revCompErr != nil || needsUnicodeSupport(revProg) {
			return nil, false
		}
		revDFA, revOk := newDFA(revProg, false, false, maxHelperDFAStates)
		if !revOk {
			return nil, false
		}
		revTable := dfaTableFrom(revDFA)
		if revTable.numStates+1 > 256 {
			return nil, false
		}
		if !br.lap.anchored && (revTable.acceptStates[revTable.startState] != 0 ||
			revTable.midAcceptStates[revTable.startState] != 0) {
			return nil, false
		}

		revTableBase := utils.PageAlign(l.tableEnd)
		revL := buildDFALayout(revTable, revTableBase, true, false, 0, false, false, false, false)
		bsBody := buildLitAnchorBackScanBody(revL, revTable, buildOpts.tableMemIdx)

		// Opt 1 (Task 7) — default-on for every mode, same as the
		// single-pattern and whole-alternation find/match bodies.
		// encodeNonMid=false: the forward-verify body dispatches non-mid
		// via state-ID compares and reads midAccept with plain `!= 0`
		// accept semantics (task 38's 254+ value encoding is decoded only
		// by buildFindBody/emitPhase4Dispatch consumers).
		applyDominantStateEncoding(l, false)
		fvBody := buildAltLitAnchorForwardVerifyBody(table, l, buildOpts.tableMemIdx)

		fwdRaw, fwdSegCnt := stripSegCount(dfaDataSegments(l, true, false))
		revRaw, revSegCnt := stripSegCount(dfaDataSegments(revL, true, false))
		result.dataBytes = append(result.dataBytes, fwdRaw...)
		result.dataSegCount += fwdSegCnt
		result.dataBytes = append(result.dataBytes, revRaw...)
		result.dataSegCount += revSegCnt

		cur = utils.PageAlign(revL.tableEnd)

		compiled = append(compiled, altLitAnchorCompiledBranch{
			litSet:            br.lap.litSet,
			backScanBody:      bsBody,
			forwardVerifyBody: fvBody,
		})
		allLits = append(allLits, br.lap.litSet...)

		if i == 0 {
			minLen, _ := regexpMinMaxLen(br.lap.prefixRe)
			result.fixedPrefixLen = int32(minLen)
		}
	}

	result.branches = compiled
	result.tableEnd = cur

	// Shared Teddy/first-byte frontend over the union of all branches'
	// literals — same shape as the single-pattern lit-anchor's own tables,
	// computed over allLits instead of one branch's litSet.
	var unionFirstBytes []byte
	var unionFirstByteFlags [256]byte
	for _, lit := range allLits {
		b0 := lit[0]
		if unionFirstByteFlags[b0] == 0 {
			unionFirstByteFlags[b0] = 1
			unionFirstBytes = append(unionFirstBytes, b0)
		}
	}

	firstByteOff := int32(result.tableEnd)
	teddyLoOff := firstByteOff + 256
	teddyHiOff := teddyLoOff + 16
	var teddyLoBytes, teddyHiBytes []byte
	var teddyT1LoOff, teddyT1HiOff int32
	var teddyT1LoBytes, teddyT1HiBytes []byte

	if len(unionFirstBytes) <= 8 {
		teddyLoBytes = make([]byte, 16)
		teddyHiBytes = make([]byte, 16)
		for i, fb := range unionFirstBytes {
			teddyLoBytes[fb&0x0F] |= byte(1 << uint(i))
			teddyHiBytes[fb>>4] |= byte(1 << uint(i))
		}

		// T1 (2-byte Teddy) is a scan accelerator only — a Teddy hit is
		// always followed by real scalar literal verification (section 3 of
		// the plan), so it's safe to skip T1 entirely rather than build a
		// lossy table: detect any first byte shared by two literals with
		// DIFFERING second bytes and bail out of T1 (not the whole
		// alternation) if found.
		fbToBit := make(map[byte]int, len(unionFirstBytes))
		for i, fb := range unionFirstBytes {
			fbToBit[fb] = i
		}
		fbSecondByte := make(map[byte]byte, len(unionFirstBytes))
		t1Collision := false
		allLenTwoPlus := true
		for _, lit := range allLits {
			if len(lit) < 2 {
				allLenTwoPlus = false
				break
			}
			if prev, ok := fbSecondByte[lit[0]]; ok && prev != lit[1] {
				t1Collision = true
				break
			}
			fbSecondByte[lit[0]] = lit[1]
		}

		if allLenTwoPlus && !t1Collision {
			t1Lo := make([]byte, 16)
			t1Hi := make([]byte, 16)
			for _, lit := range allLits {
				bit := fbToBit[lit[0]]
				t1Lo[lit[1]&0x0F] |= byte(1 << uint(bit))
				t1Hi[lit[1]>>4] |= byte(1 << uint(bit))
			}
			teddyT1LoOff = teddyHiOff + 16
			teddyT1HiOff = teddyT1LoOff + 16
			teddyT1LoBytes = t1Lo
			teddyT1HiBytes = t1Hi
		}
	}

	var teddySegs []byte
	teddySegCnt := 1
	teddySegs = appendDataSegment(teddySegs, firstByteOff, unionFirstByteFlags[:])
	if teddyLoBytes != nil {
		teddySegs = appendDataSegment(teddySegs, teddyLoOff, teddyLoBytes)
		teddySegs = appendDataSegment(teddySegs, teddyHiOff, teddyHiBytes)
		teddySegCnt += 2
		if teddyT1LoBytes != nil {
			teddySegs = appendDataSegment(teddySegs, teddyT1LoOff, teddyT1LoBytes)
			teddySegs = appendDataSegment(teddySegs, teddyT1HiOff, teddyT1HiBytes)
			teddySegCnt += 2
		}
	}
	result.dataBytes = append(result.dataBytes, teddySegs...)
	result.dataSegCount += teddySegCnt

	result.firstByteOff = firstByteOff
	result.firstByteFlags = unionFirstByteFlags
	result.firstBytes = unionFirstBytes
	result.teddyLoOff = teddyLoOff
	result.teddyHiOff = teddyHiOff
	result.teddyLoBytes = teddyLoBytes
	result.teddyHiBytes = teddyHiBytes
	result.teddyT1LoOff = teddyT1LoOff
	result.teddyT1HiOff = teddyT1HiOff
	result.teddyT1LoBytes = teddyT1LoBytes
	result.teddyT1HiBytes = teddyT1HiBytes

	result.tableEnd = int64(teddyT1HiOff) + 16
	if teddyLoBytes == nil {
		result.tableEnd = int64(firstByteOff) + 256
	} else if teddyT1LoBytes == nil {
		result.tableEnd = int64(teddyHiOff) + 16
	}

	return result, true
}
