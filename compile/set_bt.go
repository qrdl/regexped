package compile

import (
	"fmt"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
	"github.com/qrdl/regexped/internal/utils"
)

// ── Backtracking as a set fallback engine ────────────────
//
// A set member whose fallback-bucket DFA exceeds max_fallback_states used to be
// DROPPED: warned, recorded in --diag-json's state_limit_dropped, and then
// absent from every capability of that set at runtime. The same pattern
// compiled on its own falls back to Backtracking and keeps working, so the set
// path was strictly weaker than the single-pattern path on identical input.
//
// BT is the only engine in this tree that is not bound by a compiled table
// size — it walks the NFA with an explicit stack — which is what makes it the
// candidate here.
//
// WHAT A BT BUCKET HAS TO BE. A fallback bucket presents a suffix function
// that is called at EVERY candidate position and answers "does this pattern
// match anchored HERE, and where does it end". Two flags on
// buildBacktrackBody, in combination, give exactly that:
//
//   - WINDOW MODE (winScratchOff >= 0) loads (startOff, endOff) from a table
//     scratch slot, seeds pos = startOff, and takes endOff as the consumption
//     limit — while (ptr, len) remain the caller's TRUE input, which is what
//     lets \b, \B, \A, \z, (?m:^) and (?m:$) see real edges instead of a slice
//     boundary. startOff is the candidate position; endOff is the real length.
//
//   - nativeAnchored drops the "the match must consume the whole window"
//     requirement at InstMatch, so the body accepts at the FIRST
//     (leftmost-first) match end. Without it, window mode is an extent
//     VERIFIER that accepts only at pos == endOff — the wrong contract, since
//     a set knows where a candidate STARTS, not where it ends.
//
// That combination has no other caller today, so it carries its own tests
// rather than inheriting confidence from the single-pattern paths.
//
// BT NARROWS THE DROP SET RATHER THAN EMPTYING IT. A pattern whose NFA exceeds
// maxBTFallbackInstructions, or that fails BT's own loop checks, is still
// dropped and still reported — admitBTFallback returns nil and the caller
// keeps its existing warn-and-continue.

// admitBTFallback tries to build a Backtracking driver for a pattern that is
// about to be dropped from a set. Returns nil when BT cannot take it either,
// in which case the caller drops the pattern exactly as before.
//
// memoBudget is the BitState budget. There is no SET-level knob for it —
// CompileSetOptions has no MemoBudget field — so every caller passes
// resolveMemoBudget(nil), i.e. the single-pattern default of 128 KB. The doc
// here used to name a configured set budget that does not exist
// ; the parameter stays so adding one later is a change at
// the three call sites rather than in this function.
//
// ast is the pattern's full AST (patternSuffixAST), captures already
// irrelevant because sets never report them.
func admitBTFallback(ast *syntax.Regexp, memoBudget int) *btBucketInfo {
	if ast == nil {
		return nil
	}
	prog, err := syntax.Compile(ast.Simplify())
	if err != nil {
		return nil
	}
	if len(prog.Inst) > maxBTFallbackInstructions {
		return nil
	}
	bt := newBacktrack(prog)
	// Sets never report captures, so group 0 is all this body will ever
	// record. This mirrors the single-pattern find fallback in compile.go.
	bt.numGroups = 0
	if err := checkBTLoopCount(bt, false); err != nil {
		return nil
	}
	if err := checkBTEmptyBodyLoopChain(bt); err != nil {
		return nil
	}
	useMemo := needsBitState(prog)
	stackSize, memoSize := btAllocSizes(bt, useMemo, 0, memoBudget)
	return &btBucketInfo{
		bt:        bt,
		useMemo:   useMemo,
		stackSize: stackSize,
		memoSize:  memoSize,
	}
}

// setPatternInfos resolves one set's selected pattern indices into the
// PatternInfos CompileSet works from, dropping capture-bearing entries the way
// a set always has.
//
// Extracted so CompileFileDiag and SetAdmitsBacktracking share ONE
// implementation. They must: the predicate exists to tell `generate` which ABI
// the emitter chose, so any divergence between the two would be a stub whose
// signature disagrees with the WASM it calls — a silently wrong return value
// rather than a build error.
func setPatternInfos(sc config.SetConfig, cfg config.BuildConfig, selectedIdx []int,
	prefixPool, suffixPool *dfaPool) ([]*PatternInfo, []int, error) {

	var infos []*PatternInfo
	var globalIDs []int
	for _, idx := range selectedIdx {
		re := cfg.Regexps[idx]
		if re.CaptureStubsRequested() {
			continue // drop capture-bearing
		}
		info, err := analyzePattern(re, prefixPool, suffixPool)
		if err != nil {
			patLabel := re.Name
			if patLabel == "" {
				patLabel = re.Pattern
			}
			return nil, nil, fmt.Errorf("set %q: pattern %q: %w", sc.Name, patLabel, err)
		}
		info.globalID = idx
		info.name = re.Name
		infos = append(infos, info)
		globalIDs = append(globalIDs, idx)
	}
	return infos, globalIDs, nil
}

// SetAdmitsBacktracking reports whether compiling this set would admit at least
// one pattern on the Backtracking engine.
//
// It exists for the STUB GENERATORS. `generate` is a separate command from
// `compile` and derives every signature from the config alone, but the `_all`
// ABI depends on a compile-time fact: a set with a BT member returns its bitmap
// through memory rather than as an i64 (see compiledSet.wideAll). A stub that guessed would emit the wrong signature and
// read a count as a bitmask.
//
// It re-runs the analysis rather than reading a compile artefact so `generate`
// stays runnable on a config alone, with no ordering dependency on a previous
// `compile`. Compile time is free by this project's stated principle; a wrong
// stub is not. Correctness rests on it walking the SAME code path CompileSet
// does — setPatternInfos then binPack — rather than a reimplementation of the
// admission rule.
//
// An unresolvable pattern reports false: the real compile will fail on it and
// report properly, and this predicate must never be the thing that errors.
func SetAdmitsBacktracking(sc config.SetConfig, cfg config.BuildConfig) bool {
	nameIdx := map[string]int{}
	for i, re := range cfg.Regexps {
		if re.Name != "" {
			nameIdx[re.Name] = i
		}
	}
	var selectedIdx []int
	if sc.Patterns.All {
		for i := range cfg.Regexps {
			selectedIdx = append(selectedIdx, i)
		}
	} else {
		for _, name := range sc.Patterns.Names {
			idx, ok := nameIdx[name]
			if !ok {
				return false
			}
			selectedIdx = append(selectedIdx, idx)
		}
	}
	var prefixPool, suffixPool dfaPool
	infos, _, err := setPatternInfos(sc, cfg, selectedIdx, &prefixPool, &suffixPool)
	if err != nil {
		return false
	}
	opts := CompileSetOptions{
		LikelyMode:        resolveHints(sc.Hints),
		MaxFallbackStates: cfg.MaxFallbackStates,
	}
	return hasBTBucketIn(binPack(infos, opts, nil))
}

// hasBTBucketIn reports whether any bucket was admitted on the Backtracking
// engine. Takes the bucket slice rather than a compiledSet because the decisions
// that need it — chiefly whether the two-phase scan split can be taken — are
// made in CompileSet before the compiledSet exists.
func hasBTBucketIn(buckets []*bucket) bool {
	for _, bkt := range buckets {
		if bkt.btFallback != nil {
			return true
		}
	}
	return false
}

// btSharedRegions is the one stack / memo / scratch allocation a set makes for
// ALL of its BT buckets, sized to the largest of them.
//
// Sharing is safe for two reasons, both verified rather than assumed:
//
//  1. The memo re-zeroes itself at the head of every BT call
//     (emitBTMemoZeroInitTrimmed), so one pattern cannot inherit another's
//     bits.
//  2. The per-candidate driver calls one suffix function at a time via a plain
//     `call` (set_find.go's emitBucketCall) — no nesting, no reentrancy, no
//     threads — so exactly one BT call is ever live.
//
// The stack needs no clearing for a third reason: BT pushes from stackBase and
// unwinds within the call, so it starts empty each time.
type btSharedRegions struct {
	stackBase   int32 // start of the shared BT frame stack
	stackLimit  int32 // one past its end; BT reports overflow on reaching this
	memoBase    int32 // start of the shared BitState memo (0 when unused)
	winScratch  int32 // 8-byte (startOff, endOff) window slot
	slotScratch int32 // 8-byte group-0 (start, end) buffer the BT body writes
	end         int32 // one past everything above
}

// planBTRegions lays the shared regions out above `base` and returns them,
// or nil when the set has no BT bucket. Sizes are the max over BT buckets.
func planBTRegions(buckets []*bucket, base int64) *btSharedRegions {
	maxStack, maxMemo := 0, 0
	any := false
	for _, b := range buckets {
		if b.btFallback == nil {
			continue
		}
		any = true
		if b.btFallback.stackSize > maxStack {
			maxStack = b.btFallback.stackSize
		}
		if b.btFallback.memoSize > maxMemo {
			maxMemo = b.btFallback.memoSize
		}
	}
	if !any {
		return nil
	}
	cur := int32(utils.PageAlign(base))
	r := &btSharedRegions{stackBase: cur}
	r.stackLimit = r.stackBase + int32(maxStack)
	cur = r.stackLimit
	if maxMemo > 0 {
		r.memoBase = cur
		cur += int32(maxMemo)
	}
	r.winScratch = cur
	cur += 8
	r.slotScratch = cur
	cur += 8
	r.end = cur
	return r
}

// newBTBucket builds a Backtracking fallback bucket for p, or returns nil when
// BT cannot take it either — in which case the caller drops the pattern with
// its existing warning, unchanged.
//
// Called at each of set.go's three drop sites. A BT bucket always holds
// exactly one pattern: BT has no merged form, so there is nothing to share
// with.
func newBTBucket(p *PatternInfo) *bucket {
	info := admitBTFallback(patternSuffixAST(p), resolveMemoBudget(nil))
	if info == nil {
		return nil
	}
	return &bucket{
		literal:    "",
		patterns:   []*PatternInfo{p},
		isFallback: true,
		btFallback: info,
	}
}

// buildSetBTSuffixBody emits a fallback bucket's suffix function backed by the
// Backtracking engine, presenting the exact signature a DFA suffix body does so
// the per-candidate driver needs no special case:
//
//	ungated (type 3): (ptr, start, len, lPos, out_ptr, out_cap, validMask) -> i32
//	gated   (type 9): ... , gate_ptr                                       -> i32
//
// Returns the number of matches found (0 or 1 — a BT bucket holds one pattern
// and answers about one position), or a NEGATIVE value when BT exhausted its
// frame budget, which propagates outward as "result unknown".
//
// Params are positional; the locals follow.
const (
	btSufPtr       = 0
	btSufStart     = 1
	btSufLen       = 2
	btSufLPos      = 3 // unused here: a BT bucket has no literal to offset from
	btSufOutPtr    = 4
	btSufOutCap    = 5
	btSufValidMask = 6
	// Parameter 7 carries ONE of two unrelated values, and which one is decided
	// by the set's shape, exactly as buildSetSuffixBody's paramGate/paramSkip
	// pair is. They are mutually exclusive — gatedFind() is `hasFind &&
	// !overlapping`, suffixNeedsSkip() is `BatchFind && Overlapping` — and both
	// forms have the same arity, so conflating them is a silent wrong answer
	// rather than a validation error. It was: the body read parameter 7 as a
	// gate pointer in BOTH cases, so an overlapping batch set dereferenced
	// the batch skip COUNT as an address.
	btSufGatePtr = 7 // gated find only: pointer to the caller's gate array
	btSufSkip    = 7 // overlapping batch only: batch skip count, already rebased
)

// btSufEndLocal is the index of this body's one local — the end position the
// driver returned. It sits after the PARAMS, and the gated and batch forms each
// carry one more of those, so it cannot be a constant: getting this wrong is a
// "local index out of bounds" at validation, which is how it was caught.
func btSufEndLocal(hasTrailingParam bool) byte {
	if hasTrailingParam {
		return 8
	}
	return 7
}

func buildSetBTSuffixBody(regions *btSharedRegions,
	btFuncIdx int, patternID int, patternBit int, gated, hasSkip bool, tableMemIdx int) []byte {

	if gated && hasSkip {
		// Mutually exclusive by construction; both would want parameter 7.
		panic("compile: BT suffix body cannot be both gated and skip-carrying")
	}
	btSufEnd := btSufEndLocal(gated || hasSkip)
	var b []byte
	b = append(b, 0x01, 0x01, 0x7F) // one i32 local: end

	// The prefix machinery already decided this position is worth trying; the
	// valid mask says whether THIS pattern is still wanted. Bit index is the
	// pattern's position within the bucket, which for a BT bucket is always 0,
	// but it is passed in rather than assumed so the check reads the same as
	// every other bucket's.
	b = append(b, 0x20, btSufValidMask)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(1)<<uint(patternBit))
	b = append(b, 0x71)       // i32.and
	b = append(b, 0x45)       // i32.eqz
	b = append(b, 0x04, 0x40) // if (void) — this pattern is not wanted here
	b = append(b, 0x41, 0x00) // i32.const 0
	b = append(b, 0x0F)       // return
	b = append(b, 0x0B)       // end if

	// Window slot = (start, len). The BT body reads these, seeds pos = start,
	// and treats len as its consumption limit — while (ptr, len) stay the true
	// input so \b, \B, \A, \z and the (?m:) anchors see real edges. This is
	// the whole reason a BT bucket needs no left-context side channel.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.winScratch)
	b = append(b, 0x20, btSufStart)
	b = appendTableStore32(b, tableMemIdx, 0)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.winScratch)
	b = append(b, 0x20, btSufLen)
	b = appendTableStore32(b, tableMemIdx, 4)

	// end = bt(ptr, len, slotScratch)
	b = append(b, 0x20, btSufPtr)
	b = append(b, 0x20, btSufLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.slotScratch)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(btFuncIdx))
	b = append(b, 0x21, btSufEnd)

	// Frame budget exhausted: the engine abandoned part of the search space and
	// does NOT know whether this pattern matched. Propagate it as a negative
	// count — the convention `find` already uses for the same condition on the
	// single-pattern batch path — rather than reporting a non-match, which
	// would be a silent wrong answer.
	b = append(b, 0x20, btSufEnd)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if

	// Any other negative is an ordinary no-match.
	b = append(b, 0x20, btSufEnd)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x0F) // return
	b = append(b, 0x0B) // end if

	if gated {
		// The write-time gate rule, and ONLY that. The driver has already applied the gate
		// PRE-MASK before calling — that is what validMask carries — so a
		// second general gate test here is not a refinement, it is a wrong
		// answer: the gate is a DOUBLED `2s+1` encoding, not a start
		// position, so comparing it against `start` rejects live matches.
		// That mistake made gated `find` report nothing while overlapping
		// `find` stayed correct, which is the exact shape of the corpus
		// failure that caught it.
		//
		// What remains is the stricter bound an EMPTY extent needs: the
		// pre-mask proved `2s + 1 >= gate[k]`, and an empty match needs
		// `2s >= gate[k]`. They differ only when gate[k] is exactly 2s+1 —
		// the pattern's previous match ended right here — which is Go's
		// "skip an empty match at the previous end" rule.
		b = append(b, 0x20, btSufEnd)
		b = append(b, 0x20, btSufStart)
		b = append(b, 0x46)       // end == start (empty extent)
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, btSufStart)
		b = append(b, 0x41, 0x01, 0x74) // 2*start
		b = append(b, 0x20, btSufGatePtr)
		b = append(b, 0x28, 0x02)
		b = utils.AppendULEB128(b, uint32(patternID*4))
		b = append(b, 0x49)       // i32.lt_u — 2*start < gate[k]
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x0F) // suppressed
		b = append(b, 0x0B) // end inner if
		b = append(b, 0x0B) // end if empty
	}

	// Write the tuple only if the caller's remaining capacity allows it. The
	// count is returned regardless: the caller distinguishes "found" from
	// "fitted", which is what makes an undersized buffer a transactional
	// overflow rather than a truncation.
	b = append(b, 0x20, btSufOutCap)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x4A) // out_cap > 0
	if hasSkip {
		// Batch resume: the driver rebased the position-level skip onto this
		// call's tuple-index space (emitSuffixCall passes `skip - lBase`,
		// signed). A BT bucket contributes at most ONE tuple, whose local
		// index is 0, so it is wanted exactly when 0 >= skip — i.e. skip <= 0.
		// Negative means "write everything", which is how the non-batch `find`
		// entry's forwarded 0 also reads.
		//
		// The RETURN stays 1 either way: the count is what tells the batch
		// caller how much of this position remains undelivered, so suppressing
		// the count as well would lose the resume point. Only the store is
		// gated — the same split buildSetSuffixBody makes with its
		// `(outCount < cap) & (outCount >= skip)`.
		b = append(b, 0x20, btSufSkip)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4C) // skip <= 0 (signed)
		b = append(b, 0x71) // i32.and
	}
	b = append(b, 0x04, 0x40) // if (void)
	b = emitBTTuple(b, patternID, btSufEnd)
	b = append(b, 0x0B) // end if

	b = append(b, 0x41, 0x01) // one match found
	b = append(b, 0x0B)       // end function
	return b
}

// emitBTTuple writes (patternID, start, end) at out_ptr.
func emitBTTuple(b []byte, patternID int, btSufEnd byte) []byte {
	b = append(b, 0x20, btSufOutPtr)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(patternID))
	b = append(b, 0x36, 0x02, 0x00)
	b = append(b, 0x20, btSufOutPtr)
	b = append(b, 0x20, btSufStart)
	b = append(b, 0x36, 0x02, 0x04)
	b = append(b, 0x20, btSufOutPtr)
	b = append(b, 0x20, btSufEnd)
	b = append(b, 0x36, 0x02, 0x08)
	return b
}

// buildBTBodies builds, for each Backtracking fallback bucket, the suffix
// function that fronts it — keyed by bucket index so the caller can drop them
// into the slots CompileSet left empty.
//
// This runs at assembleModule time rather than in CompileSet because a BT
// suffix body CALLS its driver, and function indices do not exist until the
// module's layout is fixed. btFnBase is the index of this set's first driver.
//
// The drivers themselves are built here too, into cs.btFnBodies, so the two
// stay in lockstep: the k-th BT bucket's suffix body calls btFnBase + k.
func (cs *compiledSet) buildBTBodies(btFnBase, tableMemIdx int) map[int][]byte {
	if cs.btRegions == nil {
		return nil
	}
	out := make(map[int][]byte)
	btIdx := map[int]int{}
	k := 0
	for bi, bkt := range cs.buckets {
		if bkt.btFallback == nil {
			continue
		}
		info := bkt.btFallback
		// The driver: window mode gives it the candidate position and the true
		// input edges; nativeAnchored lets it accept at the first match end
		// rather than only on full consumption. See the file header.
		driver := appendBacktrackCodeEntry(nil, info.bt,
			cs.btRegions.stackBase, cs.btRegions.stackLimit,
			int32(btFrameSize(info.bt)), cs.btRegions.memoBase, info.useMemo,
			true, // nativeAnchored
			tableMemIdx, cs.btRegions.winScratch)
		cs.btFnBodies = append(cs.btFnBodies, driver)

		// gated and skip-carrying are mutually exclusive and mean DIFFERENT
		// things for parameter 7; passing them as one flag made the body read
		// the batch skip count as a gate pointer.
		body := buildSetBTSuffixBody(cs.btRegions, btFnBase+k,
			cs.patternIDs[bi][0], 0, cs.gatedFind(), cs.suffixHasSkip,
			tableMemIdx)
		out[bi] = sizePrefixed(body)
		btIdx[bi] = btFnBase + k
		k++
	}
	// Probes, for the scan and anchored capabilities. A bucket that filled
	// only its suffix slot left these EMPTY — a declared function with no
	// body, which is a module that will not parse.
	for bi, idx := range btIdx {
		if cs.scanProbeBodies != nil {
			cs.scanProbeBodies[bi] = sizePrefixed(
				buildSetBTProbeBody(cs.btRegions, idx, tableMemIdx))
		}
		if cs.scanProbeAnyBodies != nil && cs.anyProbeIdx != nil &&
			bi < len(cs.anyProbeIdx) && cs.anyProbeIdx[bi] >= 0 {
			cs.scanProbeAnyBodies[cs.anyProbeIdx[bi]] = sizePrefixed(
				buildSetBTProbeBody(cs.btRegions, idx, tableMemIdx))
		}
	}
	return out
}

// btFrameSize is the per-frame byte size the driver pushes: pos + loop
// trackers + retryPC, with no capture slots (sets never report captures).
func btFrameSize(bt *backtrack) int {
	return 8 + btNumLoopFrameLocals(bt, false)*4
}

// sizePrefixed wraps a raw body in the LEB128 length the code section wants.
func sizePrefixed(body []byte) []byte {
	out := utils.AppendULEB128(nil, uint32(len(body)))
	return append(out, body...)
}

// buildSetBTProbeBody emits a Backtracking bucket's PROBE — the shape the
// scan and anchored capabilities use instead of a suffix function:
//
//	(ptr i32, start i32, len i32, validMask i32) -> i32
//
// It returns the bucket-local bitmask of patterns matching at `start`, already
// masked by validMask. A BT bucket holds one pattern, so the answer is bit 0
// or nothing.
//
// anchored selects the trio's contract (match_any / match_all / match): the
// pattern must consume the WHOLE input, so a match ending short does not
// count. The scan capabilities take the other branch, where any match at this
// start counts.
//
// This existing alongside the suffix body is not duplication for its own sake:
// `find` needs positions and drives suffix functions, while the scan and
// anchored capabilities only ever need a bitmask and never call a suffix
// function at all. A BT bucket that emitted only one of the two left the other
// capability's slot EMPTY, which is a function declared but not emitted — a
// module that fails to parse, and exactly how this was found.
// There is no `anchored` flavour, and no parameter for one. A Backtracking
// bucket is admitted by the FIND-path packers only: compileAnchoredBuckets
// (set.go) has no newBTBucket call, so a pattern BT-rescued for find/scan is
// simply absent from match_any/match_all — see docs/sets.md "Backtracking
// members and the anchored pair". The parameter and its full-consumption arm
// were once dead code that made the exclusion look like an oversight rather
// than the contract it is.
func buildSetBTProbeBody(regions *btSharedRegions, btFuncIdx int, tableMemIdx int) []byte {
	const (
		pPtr       = 0
		pStart     = 1
		pLen       = 2
		pValidMask = 3
		lEnd       = 4
	)
	var b []byte
	b = append(b, 0x01, 0x01, 0x7F) // one i32 local: end

	// Not wanted here.
	b = append(b, 0x20, pValidMask)
	b = append(b, 0x41, 0x01)
	b = append(b, 0x71) // i32.and — bit 0 is this bucket's only pattern
	b = append(b, 0x45) // i32.eqz
	b = append(b, 0x04, 0x40)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Window slot = (start, len): anchor at start, bound at the true end, keep
	// real left context. Same mechanism the suffix body uses.
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.winScratch)
	b = append(b, 0x20, pStart)
	b = appendTableStore32(b, tableMemIdx, 0)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.winScratch)
	b = append(b, 0x20, pLen)
	b = appendTableStore32(b, tableMemIdx, 4)

	b = append(b, 0x20, pPtr)
	b = append(b, 0x20, pLen)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, regions.slotScratch)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(btFuncIdx))
	b = append(b, 0x21, lEnd)

	// Budget exhausted: the engine abandoned part of the search space and does
	// NOT know whether this pattern matched. Report it DISTINCTLY rather than
	// as "no bits", which would turn giving up into a confident wrong answer.
	//
	// A probe's return is a bucket-local bitmask, and a BT bucket holds exactly
	// one pattern, so its only legal answers are 0 and 1 — every negative value
	// is therefore unambiguous at the call site, which is what lets the caller
	// short-circuit on `< 0` without a second channel.
	b = append(b, 0x20, lEnd)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
	b = append(b, 0x46)       // i32.eq
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41)
	b = utils.AppendSLEB128(b, int32(abi.BTStackOverflow))
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	// Any other negative is an ordinary no-match.
	b = append(b, 0x20, lEnd)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x48)       // i32.lt_s
	b = append(b, 0x04, 0x40) // if (void)
	b = append(b, 0x41, 0x00)
	b = append(b, 0x0F)
	b = append(b, 0x0B)

	b = append(b, 0x41, 0x01) // bit 0
	b = append(b, 0x0B)       // end function
	return b
}
