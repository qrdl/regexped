package compile

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp/syntax"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

// errDFAStateLimitExceeded is returned by compile() when EngineDFA subset
// construction (newDFA) hits its internal state cap. Callers with a BT
// fallback (compile.go's match/find DFA construction) must treat this the
// same as the existing "table.numStates > maxStates" post-construction
// check — NOT as a hard compile failure — since it signals exactly the same
// outcome the post-check exists to catch, just detected earlier and
// cheaply. Callers with an all-or-nothing "fall through cleanly on
// rejection" contract (e.g. compileAltLitAnchorBranches) already handle any
// non-nil error from compile() correctly with no changes needed.
var errDFAStateLimitExceeded = errors.New("compile: DFA state limit exceeded during construction")

// ErrBTProgramTooLarge is returned whenever compile() would route a pattern
// to the Backtracking engine — whether because the primary DFA was rejected
// as too large, TDFA was ineligible for a capture pattern, or ForceEngine
// requested it directly — but the underlying NFA program is itself too
// large for the Backtracking engine's br_table-per-instruction WASM
// emission to produce a module the WASM runtime can load. Without this
// check, such patterns silently compile to a WASM module that fails to
// even parse at load time (observed: a 123,695-instruction program
// produced a 7,966,121-byte module, exceeding wasmtime's own
// ~7,654,321-byte function-body-size limit) instead of failing compilation
// with a clear error.
//
// Exported (unlike errDFAStateLimitExceeded) so external callers — e.g.
// tools/fuzz's FuzzCorrectness — can distinguish this legitimate,
// no-further-fallback-possible resource ceiling from any other compile
// error via errors.Is.
var ErrBTProgramTooLarge = errors.New("compile: backtracking fallback program exceeds size limit")

// maxBTFallbackInstructions caps the NFA program size (len(prog.Inst)) any
// Backtracking engine construction site — no-capture find/match fallback,
// capture-tracking fallback when TDFA is ineligible, and the general
// engine-executor path — is willing to turn into WASM.
// buildBTFindBody/buildBTMatchBody/appendBT{Match,Find}CodeEntry emit one
// br_table case per instruction; the confirmed pathological repro (123,695
// instructions) produced ~64 bytes of WASM per instruction. This cap
// assumes a 3x-worse ratio (~200 bytes/instruction) and targets a
// worst-case body size comfortably below wasmtime's ~7,654,321-byte
// function-body-size limit, while staying well above any NFA program size
// this package's own test suite produces via the legitimate (small-pattern,
// tiny-MaxDFAStates-forced) DFA-too-large fallback path.
const maxBTFallbackInstructions = 20000

// maxBTFallbackPrefixLen caps the length of the mandatory-literal prefix
// (computePrefix's result) used to build the Backtracking find fallback's
// SIMD/scalar prefix-scan optimisation (FUZZER_BUGS.md #31). The prefix is
// purely a candidate pre-filter — the BT matcher re-verifies every
// candidate position independently, so truncating it changes nothing about
// correctness, only how many candidate positions the scan lets through.
// Without a cap, computePrefix(table) can return the DFA-too-large table's
// entire literal chain (confirmed: ~1800-2000 bytes on the repro patterns,
// one DFA state per byte of chain), and emitPrefixScan's scalar tail
// (prefix_scan.go) unrolls one fixed WASM comparison block per prefix byte
// with no length cap of its own — ~24-27 bytes/prefix-byte, additive to
// whatever maxBTFallbackInstructions already allows the rest of the BT
// body to cost. 64 bytes keeps that addition negligible (~1.7KB worst
// case) while still filtering effectively for any realistic literal
// prefix.
const maxBTFallbackPrefixLen = 64

// ErrBTStackTooLarge is returned whenever the Backtracking engine's stack
// reservation (btAllocSizes' stackSize, or the capture-tracking path's
// equivalent inline computation) would push the module's own linear memory
// requirement past what WASM32 can declare (65536 pages × 64KiB = 4GiB).
// stackSize scales with bt.numAlts and per-loop frame-local count, both of
// which grow with ordinary pattern structure (repeated groups, nested
// loops) rather than anything pathological — an unremarkable-looking
// bounded-repeat pattern can cross this ceiling well within this project's
// normal pattern-size range. Without this check, Compile silently returns a
// WASM module whose memory section is already invalid: it fails at
// wasmtime.NewModule/instantiation time with a generic "memory size must be
// at most 0x10000 pages" error instead of failing compilation with a clear,
// attributable error (FUZZER_BUGS.md #32).
var ErrBTStackTooLarge = errors.New("compile: backtracking stack reservation exceeds WASM's 4GiB memory limit")

// maxWasmMemoryBytes is WASM32's hard linear-memory ceiling: a memory
// section cannot declare more than 65536 pages of 65536 bytes each.
const maxWasmMemoryBytes = 1 << 32

// checkBTMemoryBudget returns ErrBTStackTooLarge if base+extra bytes would
// require declaring more linear memory than maxWasmMemoryBytes allows.
// base is the page-aligned address the reservation starts at (btBase);
// extra is the reservation's own size (stack, plus memo table when present).
func checkBTMemoryBudget(base int64, extra int64) error {
	if base+extra > maxWasmMemoryBytes {
		return ErrBTStackTooLarge
	}
	return nil
}

// ErrBTLoopCountTooLarge is returned when a Backtracking construction's
// loop-frame-local count (btNumLoopFrameLocals) is large enough that
// wasmtime's JIT compilation of the resulting module becomes too slow for
// tools/fuzz's `-fuzz` worker to tolerate (FUZZER_BUGS.md #33 — discovered
// via FuzzCorrectness/092700-8c386fe83b176a61, a bug-31 regression-corpus
// entry that still crashed under real `-fuzz` fuzzing, though not under
// plain seed replay).
//
// Root cause, live-verified: this is NOT a Cranelift-internal complexity
// cliff at a specific loop count, and NOT a regexped code-bloat defect.
// The pattern family (?:$*<9-10 literal bytes>){N} (bug 31's repro shape)
// stays on the cheap primary DFA/CompiledDFA path for N up to 113 (its
// literal-chain state count stays under the default 1024-state cap), where
// wasmtime.NewModule takes ~25-30ms regardless of table size. At N=114 the
// chain crosses 1024 states and the pattern falls to the Backtracking
// engine instead — a structurally different, much more expensive-to-JIT
// body — producing the apparent "~50x jump" that first looked like a
// loop-count-triggered cliff but is really an engine-selection regime
// change coincident with this pattern family's specific literal length.
//
// Isolating pure Backtracking-path JIT cost (forcing early BT fallback via
// a tiny MaxDFAStates, independent of the 1024-state crossover) shows
// smooth, non-cliff growth: 78ms at 64 loop-frame locals, 294ms at 128,
// mildly superlinear but not runaway. The real risk this check closes is
// that once a pattern's *natural* structure (large bounded repeats,
// independent loop constructs) pushes it into the Backtracking fallback,
// BT's per-loop JIT cost is high enough per unit that a completely
// ordinary-looking pattern can cost several seconds of uninterruptible
// compile time with zero attribution — e.g. ~1.4s at 228 loop-frame locals,
// ~6.2s at 400, ~12.1s at 510 (bug 32's own ErrBTStackTooLarge already
// rejects this specific family beyond ~510). tools/fuzz's `-fuzz` worker
// treats any single call over ~10s as a hang and reports it as a crasher
// (the same mechanism documented on maxNFAInsts and bug 31); a real caller
// compiling such a pattern at build time would just see an unexplained
// multi-second stall.
var ErrBTLoopCountTooLarge = errors.New("compile: backtracking loop-frame-local count exceeds JIT-safe limit")

// maxBTLoopFrameLocals caps btNumLoopFrameLocals(bt, ...) at every
// Backtracking code-generation site, before any WASM body is built. 64 is
// chosen directly from live measurement (see ErrBTLoopCountTooLarge): at
// exactly this loop-frame-local count, isolated Backtracking-path JIT time
// is ~78ms — comfortably fast — while every measured case that actually
// triggered the fuzz-worker crash (228 loop-frame locals and up) sits
// 3.5x-8x above this cap. Ordinary patterns have at most a handful of
// independent loop constructs; dozens-to-hundreds only arises from
// pathological/adversarial or unrolled-large-{N}-repeat shapes like bug
// 31's repro family, so this cap is not expected to reject realistic
// patterns.
const maxBTLoopFrameLocals = 64

// checkBTLoopCount returns ErrBTLoopCountTooLarge if bt's loop-frame-local
// count is large enough that wasmtime's JIT compilation of the resulting
// Backtracking body risks costing multiple seconds with zero attribution
// (see ErrBTLoopCountTooLarge). withCaptureSnapshots must match the value
// the call site's own btNumLoopFrameLocals call uses (true only for the
// capture-tracking body).
func checkBTLoopCount(bt *backtrack, withCaptureSnapshots bool) error {
	if btNumLoopFrameLocals(bt, withCaptureSnapshots) > maxBTLoopFrameLocals {
		return ErrBTLoopCountTooLarge
	}
	return nil
}

// ErrBTEmptyBodyLoopChainTooLarge is returned when a Backtracking
// construction's count of bt.emptyBodyGreedyLoop heads is large enough that
// a single find/match/groups call risks costing multiple seconds at
// *runtime* — a distinct failure mode from ErrBTLoopCountTooLarge, which
// only bounds one-time JIT compile cost (FUZZER_BUGS.md #34, discovered via
// tools/fuzz/found repros of `(?m:$*$*...$*0$)`-shaped patterns, e.g. 16
// chained `$*`).
//
// Root cause, live-verified: every pushed backtrack frame snapshots *all*
// loop_pos/loop_entry trackers (btNumLoopFrameLocals), not just the pushing
// loop's own. Restoring an EARLIER loop's frame (e.g. during downstream
// unwinding after a later, unrelated match failure) resets every LATER
// loop's tracker back to its pre-visit ("unprimed") value, forcing each
// later loop in the chain to redo its own push-and-resolve cycle from
// scratch — including re-pushing its own first-entry twin frame, which is
// itself indistinguishable from a genuine fresh entry once the trackers are
// unprimed (an emptyBodyGreedyLoop's twin frame cannot be skipped
// unconditionally: its body's "matches empty" branch can be a *conditional*
// zero-width assertion — e.g. `\b` in `.(?:\b|0)*` — that legitimately fails
// at a given position, in which case the twin's pushed frame is the only
// path back to "zero iterations of this star", so removing it breaks
// correctness; confirmed live by a reverted attempt at exactly this skip,
// which produced a wrong "no match" for `.(?:\b|0)*` against `" "`, expected
// `[0,1)`). For N loops chained in straight-line sequence with an
// always-failing tail, the unprimed-replay cost compounds multiplicatively:
// confirmed live via wasmtime call timing on `(?m:` + `$*`×N + `0$)` against
// a non-matching single-byte input — call time crosses 33ms at N=13, 101ms
// at N=14, 342ms at N=15, 1.03s at N=16, 9.9s at N=18 — all while compiled
// WASM size and Compile() time itself stay small and linear, confirming the
// blowup is execution-time-only, invisible to ErrBTLoopCountTooLarge's
// JIT-time-based cap (which permits far more than 14 such loops for this
// pattern shape, well past where runtime cost already becomes
// unacceptable). Per CLAUDE.md's "runtime over compile time" principle, an
// unbounded runtime cost is worse than an unbounded compile-time cost, so
// this is rejected at compile time rather than left for a caller to
// discover as an unexplained multi-second `find`/`match` call.
//
// Eliminating the underlying exponential (e.g. by memoising each
// emptyBodyGreedyLoop head's resolved outcome per-position via the existing
// BitState mechanism, or by snapshotting only the loop trackers actually
// live past a given push instead of all of them) was not attempted here:
// this exact loop-head logic has a documented history of subtle correctness
// regressions from well-intentioned changes (see bt.memoInnerLoop's doc,
// FUZZER_BUGS.md #18's two reverted fix attempts, and this bug's own
// reverted twin-skip attempt above) and deserves its own carefully-measured
// change, not a fix folded into an unrelated bug report. A compile-time cap
// is the safe, narrowly-scoped mitigation for now.
var ErrBTEmptyBodyLoopChainTooLarge = errors.New("compile: backtracking empty-body-loop chain length exceeds runtime-safe limit")

// maxBTEmptyBodyGreedyLoops caps len(bt.emptyBodyGreedyLoop) at every
// Backtracking code-generation site, before any WASM body is built. 12 is
// chosen directly from live measurement (see
// ErrBTEmptyBodyLoopChainTooLarge's doc): call time at N=12 chained `$*` is
// ~9.5ms (comfortably fast, same bar bug 33 used for its own JIT-time cap),
// while N=14 already reaches ~101ms and every couple of steps beyond
// roughly triples again. Ordinary patterns have at most a handful of
// independent nullable loops; a long straight-line chain of them only
// arises from pathological/adversarial or mechanically-unrolled shapes, so
// this cap is not expected to reject realistic patterns.
const maxBTEmptyBodyGreedyLoops = 12

// checkBTEmptyBodyLoopChain returns ErrBTEmptyBodyLoopChainTooLarge if bt
// has more than maxBTEmptyBodyGreedyLoops emptyBodyGreedyLoop heads — see
// ErrBTEmptyBodyLoopChainTooLarge's doc for the runtime-cost mechanism this
// guards against.
func checkBTEmptyBodyLoopChain(bt *backtrack) error {
	if len(bt.emptyBodyGreedyLoop) > maxBTEmptyBodyGreedyLoops {
		return ErrBTEmptyBodyLoopChainTooLarge
	}
	return nil
}

// EngineType represents the type of regexp engine implementation.
type EngineType byte

const (
	EngineDFA EngineType = iota + 1
	EngineBacktrack
	EngineCompiledDFA // DFA with compiled (br_table) dispatch; no transition table at runtime
	EngineTDFA        // Tagged DFA: O(n) matching with full capture support
)

// String returns the human-readable name of the engine type.
func (e EngineType) String() string {
	switch e {
	case EngineBacktrack:
		return "Backtracking"
	case EngineDFA:
		return "DFA"
	case EngineCompiledDFA:
		return "Compiled DFA"
	case EngineTDFA:
		return "TDFA"
	default:
		return "Unknown"
	}
}

// matcher is the common interface implemented by all regexp engines.
type matcher interface {
	Type() EngineType
}

// LikelyMode hints which suffix-DFA optimisation path the compiler should
// favour for a pattern. See plans/LIKELY.md for the underlying structural
// optimisations (SIMD counted-chain verifier, SIMD dominant-self-loop skip).
//
// The field is presently a stub: it is plumbed through CompileOptions but does
// not yet alter WASM emission, so all three modes produce identical output. It
// exists so the likelytest harness can compile every pattern in three modes
// without depending on optimisation work that lands later.
type LikelyMode int

const (
	LikelyNeutral LikelyMode = iota // default; no structural hint
	LikelyMatch                     // bias for fast-accept (counted-chain SIMD verify)
	LikelyNoMatch                   // bias for fast-reject (dominant-self-loop SIMD skip)
)

func (m LikelyMode) String() string {
	switch m {
	case LikelyMatch:
		return "likely-match"
	case LikelyNoMatch:
		return "likely-nomatch"
	default:
		return "neutral"
	}
}

// parseHints converts the YAML `hints:` list form into a LikelyMode value and
// a "set" flag indicating whether the list expressed an explicit choice.
// Unknown/contradictory hints are rejected at config load (config.ValidHints),
// so we treat anything else here as unset defensively.
func parseHints(hints []string) (mode LikelyMode, set bool) {
	for _, h := range hints {
		switch h {
		case "prefer-match":
			return LikelyMatch, true
		case "prefer-no-match":
			return LikelyNoMatch, true
		}
	}
	return LikelyNeutral, false
}

// resolveHints applies the hints precedence chain. The first entry expressing
// an explicit choice wins; if none do, resolves to LikelyNeutral. Order is
// significant — pass hint lists in highest-priority-first order (typically
// pattern, then enclosing set).
func resolveHints(chain ...[]string) LikelyMode {
	for _, hints := range chain {
		if mode, set := parseHints(hints); set {
			return mode
		}
	}
	return LikelyNeutral
}

// hasBatchHint reports whether hints contains "batch-find" (plans/TODO.md
// task 44) — the sole trigger for emitting a pattern's `_batch` WASM export.
// Unlike LikelyMode, this is not a chain/precedence value: it's a per-pattern
// opt-in with no set-level fallback (config.validateHintList rejects
// "batch-find" on a sets: entry, so there is nothing to resolve down from).
// Unknown/contradictory hints are rejected at config load (config.ValidHints),
// so unrecognised entries are silently ignored here, same discipline as
// parseHints.
func hasBatchHint(hints []string) bool {
	for _, h := range hints {
		if h == "batch-find" {
			return true
		}
	}
	return false
}

// CompileOptions contains optional parameters for engine selection.
type CompileOptions struct {
	// MaxDFAStates is the maximum number of states allowed when building a DFA
	// (match/find) or TDFA (capture groups). If the DFA/TDFA exceeds this limit
	// the engine falls back to Backtracking. 0 means use the default (1024).
	// Exposed as max_dfa_states in the YAML config.
	MaxDFAStates int
	// MaxTDFARegs is the maximum number of WASM capture registers a TDFA may
	// use before falling back to Backtracking. 0 means use the default (32).
	// Exposed as max_tdfa_regs in the YAML config.
	MaxTDFARegs   int
	MaxDFAMemory  int        // Maximum DFA memory in bytes (default: 102400)
	Unicode       bool       // Enable Unicode support
	ForceEngine   EngineType // If non-zero, skip engine selection and use this engine type
	LeftmostFirst bool       // Use leftmost-first (RE2/Perl) semantics for alternations
	// LikelyMode hints which suffix-DFA structural optimisation to favour.
	// Currently no-op; reserved for the LIKELY.md fast-accept / fast-reject paths.
	LikelyMode LikelyMode
	// CompiledDFAThreshold is the maximum minimised WASM state count for which the
	// compiled dispatch path (EngineCompiledDFA) is used instead of the table-driven
	// interpreter. 0 means use the default (256). Capped at 256 (u8 state index
	// constraint). Negative value disables the compiled path entirely.
	// NOT exposed in the YAML config schema — internal/programmatic use only.
	CompiledDFAThreshold int
	// MemoBudget is the maximum bytes allocated for the BitState memoization
	// buffer. Only used when the pattern requires BitState (needsBitState == true).
	// Defaults to 128*1024 (128 KB) when zero.
	MemoBudget  int
	tableMemIdx int // 0 = standalone (own memory[0]), 1 = embedded (memory[1] for tables)
}

// compiledPattern holds the intermediate compilation result for one RegexEntry.
// All function bodies are size-prefixed (ready for the WASM code section).
type compiledPattern struct {
	matchBody   []byte // (i32,i32)→i32; nil if not requested
	findBody    []byte // (i32,i32)→i64; nil if not needed; exported or internal
	captureBody []byte // (i32,i32,i32)→i32; nil if no groups; always internal

	matchExport       string // empty = not exported
	findExport        string // empty = internal-only (for wrapper use)
	groupsExport      string
	namedGroupsExport string

	anchored   bool     // true = pattern anchored at 0; no wrapper needed
	numGroups  int      // capture group count (for wrapper slot adjustment)
	isTDFA     bool     // true = TDFA capture; false = Backtracking (controls sentinel data segment)
	groupNames []string // groupNames[i] = name for group i+1; "" = unnamed

	// edgeScratchOff: table-memory offset of an 8-byte (origPtr,origEnd) scratch
	// slot, written by the groups/batch-groups wrapper right before calling
	// captureBody and read by captureBody's word-boundary (\b/\B) checks at the
	// two edges of the DFA-narrowed match slice. Only meaningful when
	// !anchored && !isTDFA (Backtracking captureBody composed behind a find
	// wrapper — see FUZZER_BUGS.md #26). Backtracking's own pos==0/pos==len
	// checks otherwise wrongly treat the narrowed slice's edges as the true
	// start/end of the original input, losing real \b context beyond the
	// match. Zero value (0) is never read unless isTDFA==false && anchored==false,
	// in which case it always holds a real, explicitly-set offset.
	edgeScratchOff int32

	dataSegCount int    // number of data segments in dataBytes
	dataBytes    []byte // raw data segments (no count prefix)

	tableEnd int64

	// Literal-anchored matching fields.
	// litAnchorBackScanBody != nil means this pattern uses the literal-anchored find path:
	//   an internal backward_scan function + a lit_anchor_find function generated at
	//   assembleModule time (when the function index is known).
	litAnchorBackScanBody []byte     // size-prefixed backward_scan body; nil = no lit-anchor
	litAnchorFindLayout   *dfaLayout // LF DFA layout for the forward scan in lit_anchor_find
	litAnchorFindTable    *dfaTable  // LF DFA table for the forward scan in lit_anchor_find
	// SIMD scan tables for the literal set (stored in data segment, offsets known at compile time).
	litAnchorFirstByteOff   int32
	litAnchorFirstByteFlags [256]byte
	litAnchorFirstBytes     []byte
	litAnchorTeddyLoOff     int32
	litAnchorTeddyHiOff     int32
	litAnchorTeddyLoBytes   []byte
	litAnchorTeddyHiBytes   []byte
	litAnchorTeddyT1LoOff   int32
	litAnchorTeddyT1HiOff   int32
	litAnchorTeddyT1LoBytes []byte
	litAnchorTeddyT1HiBytes []byte
	litAnchorLitSet         [][]byte // raw literals for post-Teddy scalar verification
	// Non-mid-accept bulk-skip helper fields (nonMidHelperBody,
	// findBodyCallSites) were extracted to
	// plans/non_mid_extension.go.archive (Section 10).

	// Alternation literal-anchored matching fields (Task 6 v1, 2026-07-05).
	// altLitAnchorBranches != nil means this pattern's top-level op is
	// OpAlternate with every branch independently literal-anchored and
	// sharing the same fixed prefix length (see findAltLitAnchorPoints).
	// Mutually exclusive with litAnchorBackScanBody (OpConcat vs
	// OpAlternate top-level gates never both fire for the same pattern).
	//
	// Unlike the single-pattern case (one backward_scan + one deferred
	// lit_anchor_find), this needs N backward_scan_i + N forward_verify_i
	// functions (both fully built during compilePattern, since neither
	// calls another function by index) plus ONE deferred dispatcher built
	// at assembleModule time once all branch function indices are known
	// (same reason litAnchorFindBody is deferred today).
	altLitAnchorBranches       []altLitAnchorCompiledBranch
	altLitAnchorFixedPrefixLen int32 // same P for every branch (v1 restriction)

	// Shared Teddy/first-byte frontend over the union of all branches'
	// literals — same field shape as litAnchorFirstByte*/litAnchorTeddy*
	// above, computed over the union set instead of one pattern's litSet.
	altLitAnchorFirstByteOff   int32
	altLitAnchorFirstByteFlags [256]byte
	altLitAnchorFirstBytes     []byte
	altLitAnchorTeddyLoOff     int32
	altLitAnchorTeddyHiOff     int32
	altLitAnchorTeddyLoBytes   []byte
	altLitAnchorTeddyHiBytes   []byte
	altLitAnchorTeddyT1LoOff   int32
	altLitAnchorTeddyT1HiOff   int32
	altLitAnchorTeddyT1LoBytes []byte
	altLitAnchorTeddyT1HiBytes []byte
	// altLitAnchorFindBody (the dispatcher) is NOT a field here — like
	// litAnchorFindBody, it's built at assembleModule time and appended
	// directly, since it calls branch functions by index.

	// Batch find/groups exports (multiple matches per host call, modelled on
	// the set find_all ABI; originally LM-2, now task 44). Set by compileAll
	// (not compilePattern) once findExport/groupsExport/namedGroupsExport are
	// known, gated on the pattern's "batch-find" hint (see hasBatchHint) —
	// independent of LikelyMode. Empty = not requested.
	//
	// batchGroupsExport's base name prefers groupsExport, falling back to
	// namedGroupsExport (same priority as config.RegexEntry.GroupsExportName)
	// — a named_groups_func-only pattern gets a batch export too, since at
	// the WASM level namedGroupsExport is always a pass-through wrapper over
	// the same captureFuncIdx (see appendNamedGroupsWrapperCodeEntry), so one
	// batch export correctly serves both consumers.
	//
	// batchGroupsExport covers both shapes: !anchored (composed find+capture,
	// buildBatchGroupsWrapperBody) and anchored (native lit-chain groups body
	// IS captureBody, buildBatchLitChainGroupsWrapperBody — task 44 goal 4,
	// "Path B"); assembleModule's code-section emission branches on
	// p.anchored to pick the right wrapper builder.
	//
	// Always laid out last (see batchOffsets). Wired into both assembleModule
	// and assembleModuleWithSets for a pattern's own find/groups exports; a
	// compiledSet's own find_all/find_any/match are never given a batch
	// wrapper — they already cover multi-match natively.
	batchFindExport   string
	batchGroupsExport string
}

// altLitAnchorCompiledBranch holds one alternation branch's precomputed WASM
// bodies and literal set (Task 6 v1). backScanBody and forwardVerifyBody are
// both fully built during compilePattern — unlike the dispatcher, neither
// calls another function in this module by index, so both can be built
// eagerly instead of deferred to assembleModule time.
type altLitAnchorCompiledBranch struct {
	litSet            [][]byte // this branch's own literal(s), for the scalar verify chain
	backScanBody      []byte   // size-prefixed; built by buildLitAnchorBackScanBody, reused unchanged
	forwardVerifyBody []byte   // size-prefixed; built by buildAltLitAnchorForwardVerifyBody
}

// funcCount returns the number of WASM functions this pattern contributes.
func (p *compiledPattern) funcCount() int {
	n := 0
	if p.matchBody != nil {
		n++
	}
	if p.altLitAnchorBranches != nil {
		n += 1 + 2*len(p.altLitAnchorBranches) // dispatcher + (backward_scan_i, forward_verify_i) per branch
	} else if p.litAnchorBackScanBody != nil {
		n += 2 // backward_scan + lit_anchor_find
	} else if p.findBody != nil {
		n++
	}
	if p.captureBody != nil {
		n++ // capture_internal
		if !p.anchored {
			n++
		} // groups_wrapper
		if p.namedGroupsExport != "" {
			n++
		} // named_groups_wrapper
	}
	// LNM non-mid bulk-skip helper count was here — see archive Section 11.
	if p.batchFindExport != "" {
		n++
	}
	if p.batchGroupsExport != "" {
		n++
	}
	return n
}

// batchOffsets returns the sub-indices of the optional LM-2 batch wrapper
// functions, which are always laid out last (after everything offsets()
// accounts for). -1 if the corresponding export was not requested. Kept
// separate from offsets() so its widely-shared 4-return signature (used by
// both assembleModule and assembleModuleWithSets) does not need to change.
func (p *compiledPattern) batchOffsets() (batchFindOff, batchGroupsOff int) {
	idx := 0
	if p.matchBody != nil {
		idx++
	}
	if p.altLitAnchorBranches != nil {
		idx += 1 + 2*len(p.altLitAnchorBranches)
	} else if p.litAnchorBackScanBody != nil {
		idx += 2
	} else if p.findBody != nil {
		idx++
	}
	if p.captureBody != nil {
		idx++
		if !p.anchored {
			idx++
		}
		if p.namedGroupsExport != "" {
			idx++
		}
	}
	batchFindOff, batchGroupsOff = -1, -1
	if p.batchFindExport != "" {
		batchFindOff = idx
		idx++
	}
	if p.batchGroupsExport != "" {
		batchGroupsOff = idx
	}
	return
}

// offsets returns the sub-indices of each function within this pattern.
// backwardScanOff is the index of backward_scan (-1 if no split).
// findOff is the index of the find function (normal or lit_anchor_find, -1 if absent).
// Returns -1 for absent functions.
//
// When p.altLitAnchorBranches != nil, backwardScanOff is left -1 — there is
// no single backward-scan slot for the multi-branch case (N of them);
// altLitAnchorBranchFuncIdx addresses those individually. findOff is the
// dispatcher, laid out after all branch functions.
func (p *compiledPattern) offsets() (matchOff, backwardScanOff, findOff, captureOff, wrapperOff, namedWrapperOff int) {
	matchOff, backwardScanOff, findOff, captureOff, wrapperOff, namedWrapperOff = -1, -1, -1, -1, -1, -1
	idx := 0
	if p.matchBody != nil {
		matchOff = idx
		idx++
	}
	if p.altLitAnchorBranches != nil {
		idx += 2 * len(p.altLitAnchorBranches) // all branch helpers laid out first
		findOff = idx
		idx++
	} else if p.litAnchorBackScanBody != nil {
		backwardScanOff = idx
		idx++
		findOff = idx
		idx++
	} else if p.findBody != nil {
		findOff = idx
		idx++
	}
	if p.captureBody != nil {
		captureOff = idx
		idx++
		if !p.anchored {
			wrapperOff = idx
			idx++
		}
		if p.namedGroupsExport != "" {
			namedWrapperOff = idx
		}
	}
	return
}

// altLitAnchorBranchFuncIdx returns the (local, pattern-relative) function
// indices of branch i's backward_scan and forward_verify functions — the
// offset to add to baseIdx[patternIndex] in assembleModule. Layout: after
// an optional matchBody slot, branches are laid out as
// [backward_scan_0, forward_verify_0, backward_scan_1, forward_verify_1, ...],
// dispatcher last (see offsets() above).
func (p *compiledPattern) altLitAnchorBranchFuncIdx(i int) (backOff, fwdOff int) {
	base := 0
	if p.matchBody != nil {
		base = 1
	}
	return base + 2*i, base + 2*i + 1
}

// patchPaddedLEB128CallSites and nonMidHelperOff were extracted to
// plans/non_mid_extension.go.archive (Sections 12-13) along with the
// rest of the non-mid bulk-skip helper infrastructure.

// stripSegCount strips the LEB128 count prefix from a data section payload,
// returning the raw segment bytes and the count.
func stripSegCount(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return nil, 0
	}
	count, n := utils.DecodeULEB128(data)
	return data[n:], int(count)
}

// extractGroupNames returns the capture group names (1-indexed) from a parsed regexp.
// groupNames[i] is the name of group i+1; empty string if unnamed.
func extractGroupNames(re *syntax.Regexp) []string {
	var names []string
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture {
			names = append(names, r.Name)
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return names
}

// compilePattern compiles one RegexEntry into an intermediate compiledPattern.
// It does not build the final WASM module; call assembleModule for that.
// forceGroupsEngine overrides engine selection for the capture path (0 = auto).
func compilePattern(re config.RegexEntry, tableBase int64, forceGroupsEngine EngineType, buildOpts CompileOptions) (*compiledPattern, error) {
	needMatch := re.MatchFunc != ""
	needFind := re.FindFunc != ""
	needGroups := re.CaptureStubsRequested()

	if !needMatch && !needFind && !needGroups {
		return &compiledPattern{tableEnd: tableBase}, nil
	}

	// Per-pattern hints (from YAML `hints:`) override whatever the caller
	// passed in buildOpts.LikelyMode, so the precedence resolves to
	// pattern > caller's default. See plans/LIKELY.md gap H.1.
	if mode, set := parseHints(re.Hints); set {
		buildOpts.LikelyMode = mode
	}

	// Counted-chain SIMD verifier (LIKELY.md Opt 2), default-on for every
	// LikelyMode (task 24 — promoted 2026-07-10 after a clean broad sweep;
	// see plans/TODO.md task 24). Replaces the DFA match/find bodies
	// entirely when the pattern matches the strict <literal><charclass>{N,N}
	// shape or a strict alternation of such branches.

	// Capture path (groups_func / named_groups_func): if the pattern is a
	// lit-chain shape with compile-time-resolvable capture offsets, emit a
	// lit-chain findBody alongside an anchored lit-chain captureBody and let
	// the standard groups wrapper compose them. The wrapper handles the
	// scan-to-find-extent → fill-captures pipeline and adjusts slot positions
	// by the match start.
	if needGroups {
		// Gap C: single-pattern range with captures (greedy).
		if lcp, lcc, ok := analyseLitChainGroupsRange(re.Pattern); ok {
			p := &compiledPattern{
				tableEnd:  tableBase,
				numGroups: lcc.numGroups,
				anchored:  true,
			}
			p.groupsExport = re.GroupsFunc
			if re.NamedGroupsFunc != "" {
				p.namedGroupsExport = re.NamedGroupsFunc
			}
			if needFind {
				p.findExport = re.FindFunc
				p.findBody = appendLitChainRangeFindCodeEntry(nil, lcp, buildOpts.tableMemIdx)
			}
			if needMatch {
				p.matchExport = re.MatchFunc
				p.matchBody = appendLitChainRangeMatchCodeEntry(nil, lcp)
			}
			p.captureBody = appendLitChainRangeFindGroupsCodeEntry(nil, lcp, lcc, buildOpts.tableMemIdx)
			parsed, perr := syntax.Parse(re.Pattern, syntax.Perl)
			if perr == nil {
				p.groupNames = extractGroupNames(parsed)
			}
			return p, nil
		}
		if lcp, lcc, ok := analyseLitChainGroups(re.Pattern); ok {
			p := &compiledPattern{
				tableEnd:  tableBase,
				numGroups: lcc.numGroups,
				anchored:  true, // captureBody IS the exported groups function (native A.3 path)
			}
			p.groupsExport = re.GroupsFunc
			if re.NamedGroupsFunc != "" {
				p.namedGroupsExport = re.NamedGroupsFunc
			}
			if needMatch {
				p.matchExport = re.MatchFunc
				p.matchBody = appendLitChainMatchCodeEntry(nil, lcp)
			}
			if needFind {
				p.findExport = re.FindFunc
				p.findBody = appendLitChainFindCodeEntry(nil, lcp, buildOpts.tableMemIdx)
			}
			// Native find-with-captures body — replaces the find+capture wrapper
			// composition. Single SIMD pass with inline slot writes.
			p.captureBody = appendLitChainFindGroupsCodeEntry(nil, lcp, lcc, buildOpts.tableMemIdx)
			parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
			if err == nil {
				p.groupNames = extractGroupNames(parsed)
			}
			return p, nil
		}
		if altp, branchCaps, ok := analyseLitChainAltGroups(re.Pattern); ok {
			if needMatch {
				// Anchored alt match for the capture path is not specialised
				// (Gap B). Fall through to the standard pipeline.
			} else {
				p := &compiledPattern{
					tableEnd:  tableBase,
					numGroups: branchCaps[0].numGroups,
					anchored:  true, // captureBody IS the exported groups function (native A.3 path)
				}
				p.groupsExport = re.GroupsFunc
				if re.NamedGroupsFunc != "" {
					p.namedGroupsExport = re.NamedGroupsFunc
				}
				layout := planLitChainAltLayout(altp, tableBase)
				dataBytes, segCount := buildLitChainAltDataSegments(altp, layout)
				if needFind {
					p.findExport = re.FindFunc
					findBodyInner := buildLitChainAltFindBody(altp, layout, buildOpts.tableMemIdx)
					var findBody []byte
					findBody = utils.AppendULEB128(findBody, uint32(len(findBodyInner)))
					findBody = append(findBody, findBodyInner...)
					p.findBody = findBody
				}
				p.dataBytes = dataBytes
				p.dataSegCount = segCount
				p.tableEnd = layout.tableEnd
				// Native single-function alt find-with-captures.
				p.captureBody = appendLitChainAltFindGroupsCodeEntry(nil, altp, branchCaps, layout, buildOpts.tableMemIdx)
				parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
				if err == nil {
					p.groupNames = extractGroupNames(parsed)
				}
				return p, nil
			}
		}

		// Gap A.4: lenient alternation with captures. Composes the lit-chain
		// lenient-alt findBody (fast Teddy + per-branch verify) with the
		// standard TDFA captureBody via the groups wrapper. Win: replace
		// TDFA's find phase (linear DFA scan) with the Teddy frontend; keep
		// TDFA-correct capture semantics for DFA branches.
		if !needMatch {
			if lenAltp, ok := analyseLitChainAltLenient(re.Pattern, true); ok {
				parsed, perr := syntax.Parse(re.Pattern, syntax.Perl)
				if perr == nil && parsed.MaxCap() > 0 {
					prog, cerr := syntax.Compile(parsed.Simplify())
					if cerr == nil && !needsUnicodeSupport(prog) {
						tt, tok := newTDFA(prog, resolveMaxDFAStates(&buildOpts))
						if tok && tt.numRegs <= resolveMaxTDFARegs(&buildOpts) {
							p := &compiledPattern{
								tableEnd:  tableBase,
								numGroups: tt.numGroups,
								isTDFA:    true,
							}
							p.groupsExport = re.GroupsFunc
							if re.NamedGroupsFunc != "" {
								p.namedGroupsExport = re.NamedGroupsFunc
							}
							p.groupNames = extractGroupNames(parsed)

							// Lenient-alt data + find body.
							lenLayout := planLenAltLayout(lenAltp, tableBase)
							lenData, lenSeg := buildLenAltDataSegments(lenAltp, lenLayout)
							if needFind {
								p.findExport = re.FindFunc
							}
							findBodyInner := buildLitChainAltLenientFindBody(lenAltp, lenLayout, buildOpts.tableMemIdx)
							var findBody []byte
							findBody = utils.AppendULEB128(findBody, uint32(len(findBodyInner)))
							findBody = append(findBody, findBodyInner...)
							p.findBody = findBody
							p.dataBytes = lenData
							p.dataSegCount = lenSeg

							// TDFA capture body placed after lenient-alt tables.
							tdfaBase := utils.PageAlign(lenLayout.tableEnd)
							tdfaLayout := buildDFALayout(tt.dfaTable, tdfaBase, false, true,
								resolveCompiledDFAThreshold(&buildOpts), true, false, false, false)
							p.captureBody = appendTDFACodeEntry(nil, tt, tdfaLayout, buildOpts.tableMemIdx, false)
							rawTDFA, cntTDFA := stripSegCount(dfaDataSegments(tdfaLayout, false, false))
							p.dataBytes = append(p.dataBytes, rawTDFA...)
							p.dataSegCount += cntTDFA
							p.tableEnd = tdfaLayout.tableEnd
							// p.anchored stays false → wrapper composes find + capture.
							return p, nil
						}
					}
				}
			}
		}
	}

	if !needGroups {
		// Gap E: mixed-prefix shape `<class>{M}<literal><class>{N,N}`.
		if lcp, ok := analyseLitChainPrefixed(re.Pattern); ok {
			p := &compiledPattern{
				matchExport: re.MatchFunc,
				findExport:  re.FindFunc,
				anchored:    false,
				tableEnd:    tableBase,
			}
			if needMatch {
				p.matchBody = appendLitChainPrefixedMatchCodeEntry(nil, lcp)
			}
			if needFind {
				p.findBody = appendLitChainPrefixedFindCodeEntry(nil, lcp, buildOpts.tableMemIdx)
			}
			return p, nil
		}
		// LM-1: relax the N≥24 single-pattern gate to N≥1 under LikelyMatch.
		// See plans/LM_TODO.md LM-1.
		litChainMinCount := 24
		if buildOpts.LikelyMode == LikelyMatch {
			litChainMinCount = 1
		}
		if lcp, ok := analyseLitChain(re.Pattern, litChainMinCount); ok {
			p := &compiledPattern{
				matchExport: re.MatchFunc,
				findExport:  re.FindFunc,
				anchored:    false,
				tableEnd:    tableBase,
			}
			if needMatch {
				p.matchBody = appendLitChainMatchCodeEntry(nil, lcp)
			}
			if needFind {
				p.findBody = appendLitChainFindCodeEntry(nil, lcp, buildOpts.tableMemIdx)
			}
			return p, nil
		}
		// Gap C: single-pattern range `{N,M}`.
		if lcp, ok := analyseLitChainRange(re.Pattern, litChainMinCount); ok {
			// Greedy and non-greedy paths split by function:
			//   anchored match: greedy/non-greedy same → range match body
			//   find/groups greedy: range find/groups body
			//   find/groups non-greedy: collapses to {N,N} via existing emission
			//   (just normalise countMax = count and use buildLitChainFindBody)
			p := &compiledPattern{
				matchExport: re.MatchFunc,
				findExport:  re.FindFunc,
				anchored:    false,
				tableEnd:    tableBase,
			}
			if needMatch {
				p.matchBody = appendLitChainRangeMatchCodeEntry(nil, lcp)
			}
			if needFind {
				if lcp.greedy {
					p.findBody = appendLitChainRangeFindCodeEntry(nil, lcp, buildOpts.tableMemIdx)
				} else {
					// Non-greedy find: match length is fixed at K+N. Reuse the
					// {N,N} emission with countMax normalised to count.
					normalised := *lcp
					normalised.countMax = normalised.count
					p.findBody = appendLitChainFindCodeEntry(nil, &normalised, buildOpts.tableMemIdx)
				}
			}
			if needMatch || needFind {
				return p, nil
			}
		}
		// Gap B: anchored match for strict lit-chain alternation.
		if needMatch && !needFind {
			if altp, ok := analyseLitChainAlt(re.Pattern); ok {
				p := &compiledPattern{
					matchExport: re.MatchFunc,
					anchored:    false,
					tableEnd:    tableBase,
				}
				p.matchBody = appendLitChainAltMatchCodeEntry(nil, altp)
				return p, nil
			}
			// Gap B lenient: anchored match for mixed lit-chain + DFA branches.
			if lenAltp, ok := analyseLitChainAltLenient(re.Pattern, false); ok {
				layout := planLenAltLayout(lenAltp, tableBase)
				dataBytes, segCount := buildLenAltDataSegments(lenAltp, layout)
				p := &compiledPattern{
					matchExport:  re.MatchFunc,
					anchored:     false,
					tableEnd:     layout.tableEnd,
					dataBytes:    dataBytes,
					dataSegCount: segCount,
				}
				p.matchBody = appendLenAltMatchCodeEntry(nil, lenAltp, layout, buildOpts.tableMemIdx)
				return p, nil
			}
		}

		// Gap E: strict alt of mixed-prefix branches.
		if needFind && !needMatch {
			if altp, ok := analyseLitChainAltPrefixed(re.Pattern); ok {
				layout := planLitChainAltLayout(altp, tableBase)
				dataBytes, segCount := buildLitChainAltDataSegments(altp, layout)
				p := &compiledPattern{
					findExport:   re.FindFunc,
					anchored:     false,
					findBody:     appendLitChainAltPrefixedFindCodeEntry(nil, altp, layout, buildOpts.tableMemIdx),
					dataBytes:    dataBytes,
					dataSegCount: segCount,
					tableEnd:     layout.tableEnd,
				}
				return p, nil
			}
		}

		// Phase 2: alternation of strict lit-chain branches. Find-mode only;
		// anchored match is handled above. Skipped (falls through to the
		// classic DFA below) only for the specific shape measured to regress
		// there — every branch a simple chain with at least one unbounded
		// (`+`/`*`/open `{N,}`) segment; see shouldTryLitChainAlt.
		if needFind && !needMatch && shouldTryLitChainAlt(re.Pattern) {
			if altp, ok := analyseLitChainAlt(re.Pattern); ok {
				layout := planLitChainAltLayout(altp, tableBase)
				dataBytes, segCount := buildLitChainAltDataSegments(altp, layout)
				body := buildLitChainAltFindBody(altp, layout, buildOpts.tableMemIdx)
				var findBody []byte
				findBody = utils.AppendULEB128(findBody, uint32(len(body)))
				findBody = append(findBody, body...)
				p := &compiledPattern{
					findExport:   re.FindFunc,
					anchored:     false,
					findBody:     findBody,
					dataBytes:    dataBytes,
					dataSegCount: segCount,
					tableEnd:     layout.tableEnd,
				}
				return p, nil
			}
			// Gap C: strict alt of lit-chain branches with at least one range.
			if altp, ok := analyseLitChainAltRange(re.Pattern); ok {
				layout := planLitChainAltLayout(altp, tableBase)
				dataBytes, segCount := buildLitChainAltDataSegments(altp, layout)
				p := &compiledPattern{
					findExport:   re.FindFunc,
					anchored:     false,
					findBody:     appendLitChainAltRangeFindCodeEntry(nil, altp, layout, buildOpts.tableMemIdx),
					dataBytes:    dataBytes,
					dataSegCount: segCount,
					tableEnd:     layout.tableEnd,
				}
				return p, nil
			}
			// Phase 2a: lenient alternation — at least one branch is non-lit-chain
			// but starts with a literal. DFA branches are inlined as anchored DFA
			// verifies from the candidate position.
			if lenAltp, ok := analyseLitChainAltLenient(re.Pattern, true); ok {
				layout := planLenAltLayout(lenAltp, tableBase)
				dataBytes, segCount := buildLenAltDataSegments(lenAltp, layout)
				body := buildLitChainAltLenientFindBody(lenAltp, layout, buildOpts.tableMemIdx)
				var findBody []byte
				findBody = utils.AppendULEB128(findBody, uint32(len(body)))
				findBody = append(findBody, body...)
				p := &compiledPattern{
					findExport:   re.FindFunc,
					anchored:     false,
					findBody:     findBody,
					dataBytes:    dataBytes,
					dataSegCount: segCount,
					tableEnd:     layout.tableEnd,
				}
				return p, nil
			}
		}
	}

	maxStates := resolveMaxDFAStates(&buildOpts)
	memLimit := resolveMaxDFAMemory(&buildOpts)

	// Match function uses LL (leftmostFirst=false): finds the longest full-string
	// match from pos 0, matching RE2/Go anchored-match semantics.
	// Find/groups use LF (leftmostFirst=true): leftmost-first Perl semantics.
	// These require separate DFA compilations.

	var matchBody []byte
	var matchData []byte
	var matchSegCnt int
	var matchEnd int64

	cur := tableBase

	if needMatch {
		// Match uses LL (leftmostFirst=false): all NFA alternative paths are kept in each
		// DFA state, so the DFA can find ANY path that consumes the full input string.
		// LF would discard lower-priority alternatives after a higher-priority one matches,
		// making full-string match fail for patterns like `a|aa` on "aa" (LF picks `a` at
		// pos 0, loses the `aa` path, then can't reach the end of input).
		// This matches Go stdlib semantics: regexp.MustCompile("^(a|aa)$").MatchString("aa") = true.
		llOpts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: false}
		llMatch, llErr := compile(re.Pattern, llOpts)
		if llErr != nil && !errors.Is(llErr, errDFAStateLimitExceeded) {
			return nil, fmt.Errorf("compile match DFA: %w", llErr)
		}
		var llTable *dfaTable
		if llErr == nil {
			llTable = dfaTableFrom(llMatch.(*dfa))
		}
		if llErr != nil || llTable.numStates > maxStates || (memLimit > 0 && dfaTableBytes(llTable) > memLimit) {
			// DFA too large — fall back to Backtracking match.
			btProg := compileBTProg(re.Pattern)
			if len(btProg.Inst) > maxBTFallbackInstructions {
				return nil, ErrBTProgramTooLarge
			}
			bt := newBacktrack(btProg)
			bt.numGroups = 0
			if err := checkBTLoopCount(bt, false); err != nil {
				return nil, err
			}
			if err := checkBTEmptyBodyLoopChain(bt); err != nil {
				return nil, err
			}
			useMemo := needsBitState(btProg)
			btBase := utils.PageAlign(cur)
			matchMemoBudget := resolveMemoBudget(&buildOpts)
			btStackSize, btMemoSize := btAllocSizes(bt, useMemo, 0, matchMemoBudget)
			if err := checkBTMemoryBudget(btBase, int64(btStackSize)+int64(btMemoSize)); err != nil {
				return nil, err
			}
			btStackBase := int32(btBase)
			btStackLimit := btStackBase + int32(btStackSize)
			var btMemoBase int32
			if useMemo {
				btMemoBase = btStackLimit
			}
			matchBody = appendBTMatchCodeEntry(nil, bt, btStackBase, btStackLimit, int32(8+btNumLoopFrameLocals(bt, false)*4), btMemoBase, useMemo, buildOpts.tableMemIdx)
			matchEnd = btBase + int64(btStackSize) + int64(btMemoSize)
		} else {
			lm := buildDFALayout(llTable, cur, false, false, resolveCompiledDFAThreshold(&buildOpts), false, false,
				buildOpts.LikelyMode == LikelyMatch, buildOpts.LikelyMode == LikelyMatch)
			// Task 38 (2026-07-18): non-mid dominants are default-on for
			// every LikelyMode again, replacing task 36's LikelyMatch-only
			// gate, which was lossy in both directions — neutral callers
			// lost the −90% long-run fuel win, LikelyMatch callers still
			// paid the short-run penalty. Two runtime mechanisms make this
			// safe (fuel-verified):
			//   1. encodeNonMid=true: non-mid dispatch piggybacks on the
			//      midAccept[state] load via reserved values 254+, so
			//      bytes outside the dominant state pay zero (the old
			//      per-byte `state == K` compare chain was the dominant
			//      harm — perftest html-tags +474% with zero attempts).
			//   2. emitHystBulkSkip: after nonMidHystStreak consecutive
			//      attempts advancing < 16 bytes, dispatch self-disables
			//      for the rest of the call (bounds attempt waste on
			//      dense short-run inputs).
			// The wall-time "codegen tax" that originally motivated the
			// gate was proven to be instruction-placement noise
			// (padding-scan experiment, 2026-07-18); decisions here are
			// gated on fuel only.
			applyDominantStateEncoding(lm, true)
			matchBody = appendMatchCodeEntry(nil, lm, llTable, lm.hasImmAccept, buildOpts.tableMemIdx)
			rawM, cntM := stripSegCount(dfaDataSegments(lm, false, false))
			matchData = rawM
			matchSegCnt = cntM
			matchEnd = lm.tableEnd
		}
		cur = utils.PageAlign(matchEnd)
	}

	// LF DFA for find and/or groups.
	lfOpts := CompileOptions{MaxDFAStates: maxStates, ForceEngine: EngineDFA, LeftmostFirst: true}
	matcher, err := compile(re.Pattern, lfOpts)
	if err != nil && !errors.Is(err, errDFAStateLimitExceeded) {
		return nil, fmt.Errorf("compile DFA: %w", err)
	}
	// dfaStateLimitExceeded: newDFA's own internal cap already fired, so
	// there is no table to inspect — treat it the same as the ordinary
	// "table.numStates > maxStates" post-construction check below (both
	// mean "DFA too large, fall back to BT"), rather than as a hard error.
	dfaStateLimitExceeded := errors.Is(err, errDFAStateLimitExceeded)
	var table *dfaTable
	var anchored, needFindBody bool
	if !dfaStateLimitExceeded {
		table = dfaTableFrom(matcher.(*dfa))
		anchored = isAnchoredFind(table)
		needFindBody = needFind || (needGroups && !anchored)
	} else {
		// anchored is unknowable without a table; assume false (the safe
		// direction — it only widens needFindBody, it never narrows it, so
		// a genuinely-anchored pattern just gets a find body it technically
		// didn't strictly need, never a missing one for a genuinely
		// non-anchored needGroups-only pattern).
		needFindBody = needFind || needGroups
	}

	// Check if the LF DFA exceeds the state limit — if so, use BT find body.
	// dfaHasOutrankedState (FUZZER_BUGS.md #15): a state whose boundary-gated
	// mid-accept channel outranks the state's own unconditional (ctx=0)
	// mid-accept, e.g. `0*\b|0*` — the find-mode scan loop's ctx=0 check has
	// no priority concept and can let a later, lower-priority hit silently
	// overwrite an already-correct higher-priority one. Routed to
	// Backtracking (correct by construction) rather than patched in the DFA
	// scan-loop codegen — see dfaHasOutrankedState's doc comment.
	// dfaHasAmbiguousBoundaryTarget (FUZZER_BUGS.md #21): a sibling blind
	// spot where resolving a \b/\B/(?m:$) assertion needs one more mandatory
	// byte before Match, and that byte's own Rune is ALSO reachable via some
	// other, already-live, lower-priority path in the same NFA set (e.g.
	// ` (\b|0*)0`) — the ordinary transition table permanently loses the
	// higher-priority derivation, with no dominant/outranked bit to catch
	// it. See nfaBoundaryTargetIsAmbiguous's doc comment.
	dfaTooLarge := dfaStateLimitExceeded || table.numStates > maxStates || (memLimit > 0 && dfaTableBytes(table) > memLimit) ||
		dfaHasOutrankedState(table) || dfaHasAmbiguousBoundaryTarget(table)

	var l *dfaLayout
	if !dfaTooLarge {
		l = buildDFALayout(table, cur, needFindBody, true, resolveCompiledDFAThreshold(&buildOpts), false,
			buildOpts.LikelyMode == LikelyMatch && lmBareShuftiEligible(re.Pattern),
			buildOpts.LikelyMode == LikelyMatch,
			buildOpts.LikelyMode == LikelyMatch)
	}
	patMandLit := findMandatoryLit(re.Pattern)

	p := &compiledPattern{
		matchExport: re.MatchFunc,
		findExport:  re.FindFunc,
		anchored:    anchored,
	}

	if needMatch {
		p.matchBody = matchBody
		p.dataBytes = matchData
		p.dataSegCount = matchSegCnt
		if !needFind && !needGroups {
			p.tableEnd = matchEnd
			return p, nil
		}
	}

	if needFindBody {
		if dfaTooLarge {
			// DFA too large — fall back to Backtracking find.
			btProg := compileBTProg(re.Pattern)
			if len(btProg.Inst) > maxBTFallbackInstructions {
				return nil, ErrBTProgramTooLarge
			}
			bt := newBacktrack(btProg)
			bt.numGroups = 0
			if err := checkBTLoopCount(bt, false); err != nil {
				return nil, err
			}
			if err := checkBTEmptyBodyLoopChain(bt); err != nil {
				return nil, err
			}
			useMemo := needsBitState(btProg)
			// Choose scan strategy (in priority order):
			//   1. Multi-byte literal prefix from the (large) LF DFA — no data tables, pure SIMD.
			//   2. Mandatory interior literal via two-level outer loop.
			//   3. First-byte SIMD/Teddy tables from NFA (fallback).
			var btScanParams prefixScanParams
			var btScanDataBytes []byte
			var btScanSegCnt int
			var btMandLit *mandatoryLit
			// table is nil only in the rare dfaStateLimitExceeded backstop
			// case (construction itself was too expensive to finish, not
			// just "too many states to use as the primary engine") — no
			// prefix optimisation is available then, falls through to
			// btMandLit/nfaFirstBytes below.
			var btPrefix []byte
			if table != nil {
				btPrefix = computePrefix(table)
				if len(btPrefix) > maxBTFallbackPrefixLen {
					btPrefix = btPrefix[:maxBTFallbackPrefixLen]
				}
			}
			if len(btPrefix) >= 2 {
				// Multi-byte prefix: use SIMD prefix scan; no memory tables needed.
				btScanParams = prefixScanParams{
					Prefix: btPrefix,
					Locals: prefixScanLocals{
						Ptr: 0, Len: 1, AttemptStart: 7, SimdMask: 8, Chunk: 9,
					},
					EngineDepth:   2,
					LikelyNoMatch: buildOpts.LikelyMode == LikelyNoMatch,
				}
			} else if patMandLit != nil {
				// Mandatory interior literal: two-level outer loop; no first-byte tables needed.
				btMandLit = patMandLit
			} else {
				// Fallback: first-byte SIMD/Teddy tables from NFA.
				btFirstBytes, btFirstByteFlags, btAllBytes := nfaFirstBytes(btProg)
				btScanParams, btScanDataBytes, btScanSegCnt = buildBTScanTables(btFirstBytes, btFirstByteFlags, btAllBytes, cur)
				btScanParams.TableMemIdx = buildOpts.tableMemIdx
				btScanParams.LikelyNoMatch = buildOpts.LikelyMode == LikelyNoMatch
			}
			p.dataBytes = append(p.dataBytes, btScanDataBytes...)
			p.dataSegCount += btScanSegCnt
			// Allocate BT stack after SIMD tables.
			btBase := utils.PageAlign(cur + int64(len(btScanDataBytes)))
			memoBudget := resolveMemoBudget(&buildOpts)
			btStackSize, btMemoSize := btAllocSizes(bt, useMemo, 0, memoBudget)
			if err := checkBTMemoryBudget(btBase, int64(btStackSize)+int64(btMemoSize)); err != nil {
				return nil, err
			}
			btStackBase := int32(btBase)
			btStackLimit := btStackBase + int32(btStackSize)
			var btMemoBase int32
			if useMemo {
				btMemoBase = btStackLimit
			}
			frameSize := int32(8 + btNumLoopFrameLocals(bt, false)*4) // pos + loop trackers + retryPC (no cap slots)
			p.findBody = appendBTFindCodeEntry(nil, bt, btScanParams, btStackBase, btStackLimit, frameSize, btMemoBase, useMemo, btMandLit, buildOpts.tableMemIdx)
			p.tableEnd = utils.PageAlign(btBase + int64(btStackSize) + int64(btMemoSize))
		} else {
			// DFA find path: check for lit-anchor optimisation first.
			lap := findLitAnchorPoint(re.Pattern)
			// Task 10: reject prefixes containing `\b`/`\B` explicitly. The
			// reversed-prefix DFA doesn't evaluate word boundaries backward,
			// and the lit-anchor find body doesn't verify them at candidate
			// positions. Previously this was blocked only incidentally by
			// the acceptStates[startState] check below (a reversed `\b`-only
			// DFA accepts at its start), but that gate is fragile against
			// future DFA-construction changes.
			//
			// FUZZER_BUGS.md #22: the same class of gap exists for
			// `(?m:^)`/`(?m:$)` in the prefix — reject those too. The forward
			// continuation resumes suffixRe's own freshly-compiled DFA at the
			// backward-verified match-start position with no independent way
			// to re-derive whether that position's own newline-boundary
			// context was correctly resolved, so a prefix containing a line
			// anchor is rejected the same way one containing `\b`/`\B` is.
			//
			// ...unless the prefix is provably line-scoped (TODO.md task 51):
			// a leading `^`/`(?m:^)` followed by nothing that can consume a
			// '\n' makes the backward scan's stop-at-'\n' exact rather than
			// premature, and the forward continuation is already newline-aware
			// (phase 3 picks wasmMidStartNewline; the forward loop emits
			// emitNLPreAcceptCheck). See lineAnchoredPrefixSafe.
			lineAnchorOK := false
			if lap != nil {
				lineAnchorOK = (!table.hasNewlineBoundary && !prefixContainsLineAnchor(lap.prefixRe)) ||
					lineAnchoredPrefixSafe(lap.prefixRe)
			}
			if lap != nil && l.useU8 && !table.hasWordBoundary && lineAnchorOK &&
				!prefixContainsWordBoundary(lap.prefixRe) {
				// Compile the reversed prefix DFA for the backward scan.
				revRe := reverseRegexp(lap.prefixRe)
				revSimplified := revRe.Simplify()
				revProg, revCompErr := syntax.Compile(revSimplified)
				if revCompErr == nil && !needsUnicodeSupport(revProg) {
					revDFA, revOk := newDFA(revProg, false, false, maxHelperDFAStates)
					var revTable *dfaTable
					if revOk {
						revTable = dfaTableFrom(revDFA)
					}
					if revOk && revTable.numStates+1 <= 256 &&
						(lap.anchored || (revTable.acceptStates[revTable.startState] == 0 &&
							revTable.midAcceptStates[revTable.startState] == 0)) {
						revTableBase := utils.PageAlign(l.tableEnd)
						revL := buildDFALayout(revTable, revTableBase, true, false, 0, false, false, false, false)
						bsBody := buildLitAnchorBackScanBody(revL, revTable, buildOpts.tableMemIdx)
						// Task 22: when the prefix is a bare `[class]{M}` (M<=16),
						// a single SIMD chunk verify replaces the scalar reverse
						// walk above with no runtime trade-off. LikelyNoMatch-gated
						// for this initial landing (see buildSimplePrefixCheckBody's
						// doc comment); the unused reverse-DFA table bytes computed
						// above are harmless dead weight when this fires, not wired
						// into anything the WASM module executes.
						if buildOpts.LikelyMode == LikelyNoMatch {
							if tlo, count, ok := simpleClassPrefix(lap.prefixRe); ok {
								bsBody = buildSimplePrefixCheckBody(tlo, count)
							}
						}

						var litFirstBytes []byte
						var litFirstByteFlags [256]byte
						for _, lit := range lap.litSet {
							b0 := lit[0]
							if litFirstByteFlags[b0] == 0 {
								litFirstByteFlags[b0] = 1
								litFirstBytes = append(litFirstBytes, b0)
							}
						}

						litFirstByteOff := int32(revL.tableEnd)
						litTeddyLoOff := litFirstByteOff + 256
						litTeddyHiOff := litTeddyLoOff + 16
						var litTeddyLoBytes, litTeddyHiBytes []byte
						var litTeddyT1LoOff, litTeddyT1HiOff int32
						var litTeddyT1LoBytes, litTeddyT1HiBytes []byte

						if len(litFirstBytes) <= 8 {
							litTeddyLoBytes = make([]byte, 16)
							litTeddyHiBytes = make([]byte, 16)
							for i, fb := range litFirstBytes {
								litTeddyLoBytes[fb&0x0F] |= byte(1 << uint(i))
								litTeddyHiBytes[fb>>4] |= byte(1 << uint(i))
							}
							t1Lo := make([]byte, 16)
							t1Hi := make([]byte, 16)
							fbToBit := make(map[byte]int)
							for i, fb := range litFirstBytes {
								fbToBit[fb] = i
							}
							for _, lit := range lap.litSet {
								// lit[0] is guaranteed present: fbToBit was built from
								// litFirstBytes, which was deduped from this same litSet.
								bit := fbToBit[lit[0]]
								t1Lo[lit[1]&0x0F] |= byte(1 << uint(bit))
								t1Hi[lit[1]>>4] |= byte(1 << uint(bit))
							}
							litTeddyT1LoOff = litTeddyHiOff + 16
							litTeddyT1HiOff = litTeddyT1LoOff + 16
							litTeddyT1LoBytes = t1Lo
							litTeddyT1HiBytes = t1Hi
						}

						revRawData, revSegCnt := stripSegCount(dfaDataSegments(revL, true, false))
						var litSegs []byte
						litSegCnt := 1
						litSegs = appendDataSegment(litSegs, litFirstByteOff, litFirstByteFlags[:])
						if litTeddyLoBytes != nil {
							litSegs = appendDataSegment(litSegs, litTeddyLoOff, litTeddyLoBytes)
							litSegs = appendDataSegment(litSegs, litTeddyHiOff, litTeddyHiBytes)
							litSegCnt += 2
							if litTeddyT1LoBytes != nil {
								litSegs = appendDataSegment(litSegs, litTeddyT1LoOff, litTeddyT1LoBytes)
								litSegs = appendDataSegment(litSegs, litTeddyT1HiOff, litTeddyT1HiBytes)
								litSegCnt += 2
							}
						}

						p.litAnchorBackScanBody = bsBody
						p.litAnchorFindLayout = l
						p.litAnchorFindTable = table
						p.litAnchorFirstByteOff = litFirstByteOff
						p.litAnchorFirstByteFlags = litFirstByteFlags
						p.litAnchorFirstBytes = litFirstBytes
						p.litAnchorTeddyLoOff = litTeddyLoOff
						p.litAnchorTeddyHiOff = litTeddyHiOff
						p.litAnchorTeddyLoBytes = litTeddyLoBytes
						p.litAnchorTeddyHiBytes = litTeddyHiBytes
						p.litAnchorTeddyT1LoOff = litTeddyT1LoOff
						p.litAnchorTeddyT1HiOff = litTeddyT1HiOff
						p.litAnchorTeddyT1LoBytes = litTeddyT1LoBytes
						p.litAnchorTeddyT1HiBytes = litTeddyT1HiBytes
						p.litAnchorLitSet = lap.litSet
						p.dataBytes = append(p.dataBytes, revRawData...)
						p.dataSegCount += revSegCnt
						p.dataBytes = append(p.dataBytes, litSegs...)
						p.dataSegCount += litSegCnt
						// litAnchorPoint.litSet is hard-capped at 8 literals
						// (lit_anchor.go), so litFirstBytes has ≤ 8 entries and
						// the Teddy lo/hi tables above are always populated.
						p.tableEnd = int64(litTeddyT1HiOff) + 16
					}
				}
			}

			// Alternation lit-anchor (Task 6 v1, 2026-07-05) — only tried
			// when the single-pattern check above didn't fire (their
			// top-level Op gates, OpConcat vs OpAlternate, are mutually
			// exclusive, so this check is defensive) and only for find-only
			// patterns (captures are out of scope for v1, matching TODO.md's
			// own non-conflict note). See findAltLitAnchorPoints for the
			// equal-fixed-prefix-length restriction and why it's required
			// for v1's simple "return on first success" dispatch to be
			// correct.
			if p.litAnchorBackScanBody == nil && !needGroups {
				if altBranches, ok := findAltLitAnchorPoints(re.Pattern); ok {
					if altCompiled, altOK := compileAltLitAnchorBranches(altBranches, l.tableEnd, buildOpts); altOK {
						p.altLitAnchorBranches = altCompiled.branches
						p.altLitAnchorFixedPrefixLen = altCompiled.fixedPrefixLen
						p.altLitAnchorFirstByteOff = altCompiled.firstByteOff
						p.altLitAnchorFirstByteFlags = altCompiled.firstByteFlags
						p.altLitAnchorFirstBytes = altCompiled.firstBytes
						p.altLitAnchorTeddyLoOff = altCompiled.teddyLoOff
						p.altLitAnchorTeddyHiOff = altCompiled.teddyHiOff
						p.altLitAnchorTeddyLoBytes = altCompiled.teddyLoBytes
						p.altLitAnchorTeddyHiBytes = altCompiled.teddyHiBytes
						p.altLitAnchorTeddyT1LoOff = altCompiled.teddyT1LoOff
						p.altLitAnchorTeddyT1HiOff = altCompiled.teddyT1HiOff
						p.altLitAnchorTeddyT1LoBytes = altCompiled.teddyT1LoBytes
						p.altLitAnchorTeddyT1HiBytes = altCompiled.teddyT1HiBytes
						p.dataBytes = append(p.dataBytes, altCompiled.dataBytes...)
						p.dataSegCount += altCompiled.dataSegCount
						p.tableEnd = altCompiled.tableEnd
					}
				}
			}

			// Opt 1 — dominant-self-loop SIMD bulk-skip. Default-on for all
			// modes, mid-accept and non-mid-accept alike (Task 7 Step 2,
			// 2026-07-05 — see plans/TODO.md task 7). Non-mid was
			// previously LM-gated because the original side-table dispatch
			// caused a 48-57% no-match regression; replaced with a
			// state-ID-compare emission (commit dbb4dfa9) that shrinks the
			// no-match cost to ~18-21% wall time (0% fuel) on the patterns
			// that show it at all — a real, measured trade-off against a
			// much larger match-path win, not a fully regression-free win.
			// Anchored find uses a separate builder (buildAnchoredFindBody)
			// whose midAccept consumers don't decode the encoding, so we
			// skip it there.
			//
			// Lit-anchor's forward DFA scan (buildLitAnchorFindBody) also
			// decodes the encoding; both channels (mid + non-mid) are kept
			// unconditionally there. History: commit 36f91ab (2026-07-12)
			// dropped the MID channel at this site to fix a fuel-flat
			// wall-time regression on url-find-100kb — that delta was later
			// proven to be instruction-placement noise on the Kaby Lake dev
			// machine (2026-07-18 padding-scan experiment, see plans/TODO.md
			// task 36), and the drop cost a real 20x fuel / ~40x time
			// regression on lit-anchor patterns whose post-literal body IS
			// the mid-accept dominant state (likelytest
			// lit-anchor-dominant-body, `[0-9]{4}INFO:[^\n]+`: match fuel
			// 40,600 -> 813,127, bisect-confirmed to that commit). Reverted
			// 2026-07-18. The non-mid channel here carries bt-find-mand-lit's
			// genuine -58% fuel win (the `.*` before its alternation), so it
			// stays too.
			//
			// Task 38 (2026-07-18): buildFindBody's own call site (the
			// litAnchorBackScanBody == nil branch below) emits the
			// non-mid channel for every LikelyMode again, replacing task
			// 36's LikelyMatch-only gate. The short-run fuel harm that
			// gate protected against (dense short runs in the dominant
			// state — an input property no compile-time gate can see) is
			// now handled at runtime by the hysteresis wrapped around the
			// dispatch (emitNonMidBulkSkipHyst), so neutral callers keep
			// the −90% long-run win and short-run inputs self-disable the
			// channel after nonMidHystStreak wasted attempts.
			canEmitOpt1 := !isAnchoredFind(table)
			if canEmitOpt1 {
				// encodeNonMid only when buildFindBody is the consumer of
				// this layout's midAcceptBytes — the lit-anchor forward
				// scan and alt-lit branches read the table with plain
				// `!= 0` accept semantics and dispatch non-mid via
				// state-ID compares (unchanged by task 38).
				applyDominantStateEncoding(l,
					p.litAnchorBackScanBody == nil && p.altLitAnchorBranches == nil)
			} else {
				l.dominantStates = nil
			}
			l.lnmAction5 = buildOpts.LikelyMode == LikelyNoMatch
			if p.litAnchorBackScanBody == nil && p.altLitAnchorBranches == nil {
				p.findBody = appendFindCodeEntry(nil, l, table, patMandLit, buildOpts.tableMemIdx)
			}

			// Note the asymmetry with the single-pattern lit-anchor case just
			// above: that path unconditionally emits l/table's data segments
			// because it REUSES the whole pattern's forward LF DFA for its
			// own Phase 3 (litAnchorFindLayout/litAnchorFindTable = l/table).
			// The alternation path does NOT reuse l/table at all — each
			// branch compiles its own independent forward DFA inside
			// compileAltLitAnchorBranches — so l's combined-alternation
			// tables would be dead weight here and are skipped.
			rawData, segCount := stripSegCount(dfaDataSegments(l, needFindBody, false))
			if p.altLitAnchorBranches == nil {
				p.dataBytes = append(p.dataBytes, rawData...)
				p.dataSegCount += segCount
			}
			if p.litAnchorBackScanBody == nil && p.altLitAnchorBranches == nil {
				p.tableEnd = l.tableEnd
			}
		}
	} else if !dfaTooLarge {
		// needFindBody is false but we still need the DFA data segments (for match only).
		rawData, segCount := stripSegCount(dfaDataSegments(l, false, false))
		p.dataBytes = append(p.dataBytes, rawData...)
		p.dataSegCount += segCount
		p.tableEnd = l.tableEnd
	}

	if !needGroups {
		return p, nil
	}

	p.groupsExport = re.GroupsFunc // only set when groups_func explicitly requested
	if re.NamedGroupsFunc != "" {
		p.namedGroupsExport = re.NamedGroupsFunc
	}

	parsed, err := syntax.Parse(re.Pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	prog, _ := syntax.Compile(parsed.Simplify())
	if needsUnicodeSupport(prog) {
		return nil, fmt.Errorf("pattern contains Unicode features not yet supported")
	}

	p.groupNames = extractGroupNames(parsed)

	// Task 41: whole-pattern single-capture shortcut. Only valid on the
	// find-wrapper composition path (captureBody re-traverses the
	// wrapper-supplied [start,end) substring, so group 0 there is always
	// (0,len) — a sole capture spanning the whole match is therefore
	// always (0,len) too, with no TDFA/BT re-walk needed). Native/anchored
	// paths above (where captureBody IS the exported groups function) are
	// out of scope and unaffected.
	//
	// !dfaStateLimitExceeded is required too: in that (rare, pathological)
	// case `anchored` is a conservative default, not a real answer — firing
	// this shortcut on an actually-anchored pattern would silently produce
	// wrong (0,len) captures instead of the correct native-anchored body.
	// Falling through to normal TDFA/BT capture construction is always
	// correct regardless of anchoring, just without this fast path.
	if !dfaStateLimitExceeded && !anchored && isWholePatternSingleCapture(parsed) {
		p.numGroups = 2
		p.captureBody = appendTrivialSingleCaptureCodeEntry(nil)
		// edgeScratchOff must be an explicit -1 here: the field's zero value
		// is 0, a real table-memory offset, and this path is !isTDFA &&
		// !anchored — exactly the combination the wrapper-emission call site
		// (compile.go, appendWrapperCodeEntry's edgeOff) treats as "read
		// p.edgeScratchOff", so leaving it unset made the wrapper scribble an
		// 8-byte (origPtr,origEnd) scratch value over table-memory offset 0
		// on every groups() call. In a standalone module (tableMemIdx 0) that
		// memory IS the caller's own memory — offset 0 is the input buffer's
		// own base — so this corrupted the caller's input text in place; in
		// an embedded module (tableMemIdx 1) it corrupts the DFA table's own
		// base instead. Either way, the next find()/groups() call in the
		// same instance reads back garbage. See plans/TODO.md task 50.
		p.edgeScratchOff = -1
		return p, nil
	}

	groupsEngine := selectBestEngine(prog, &buildOpts)
	if forceGroupsEngine != 0 {
		groupsEngine = forceGroupsEngine
	}

	if groupsEngine == EngineTDFA {
		tt, ok := newTDFA(prog, resolveMaxDFAStates(&buildOpts))
		if ok && tt.numRegs > resolveMaxTDFARegs(&buildOpts) {
			ok = false
		}
		if !ok {
			// Fallback: TDFA limit exceeded during actual compilation (should match selector).
			groupsEngine = EngineBacktrack
		} else {
			p.isTDFA = true
			tdfaBase := utils.PageAlign(p.tableEnd)
			tdfaLayout := buildDFALayout(tt.dfaTable, tdfaBase, false, true, resolveCompiledDFAThreshold(&buildOpts), true, false, false, false)
			p.numGroups = tt.numGroups
			p.captureBody = appendTDFACodeEntry(nil, tt, tdfaLayout, buildOpts.tableMemIdx, anchored)
			// TDFA only needs the transition table (no stack/memo).
			p.tableEnd = tdfaLayout.tableEnd
			rawTDFA, cntTDFA := stripSegCount(dfaDataSegments(tdfaLayout, false, false))
			p.dataBytes = append(p.dataBytes, rawTDFA...)
			p.dataSegCount += cntTDFA
		}
	}

	if groupsEngine == EngineBacktrack {
		if len(prog.Inst) > maxBTFallbackInstructions {
			return nil, ErrBTProgramTooLarge
		}
		bt := newBacktrack(prog)
		if err := checkBTLoopCount(bt, true); err != nil {
			return nil, err
		}
		if err := checkBTEmptyBodyLoopChain(bt); err != nil {
			return nil, err
		}

		// Stack placed directly after all find-mode DFA and lit-anchor tables.
		// p.tableEnd includes lit-anchor reversed-DFA and SIMD tables when active;
		// using l.tableEnd would overlap those tables and corrupt them at runtime.
		btBase := utils.PageAlign(p.tableEnd)
		numCapLocs := bt.numGroups * 2
		frameSize := 4 + numCapLocs*4 + btNumLoopFrameLocals(bt, true)*4 + 4
		maxFrames := bt.numAlts * 4096
		if maxFrames < 4096 {
			maxFrames = 4096
		}
		stackSize := maxFrames * frameSize
		if err := checkBTMemoryBudget(btBase, int64(stackSize)); err != nil {
			return nil, err
		}
		stackBase := int32(btBase)
		stackLimit := stackBase + int32(stackSize)

		// Memo table (BitState memoization) — only when the pattern has loops
		// whose body can match zero bytes, which can cause infinite revisiting.
		useMemo := needsBitState(prog)
		var memoTableBase int32
		var memoMaxLen int32
		var memoMaxSize int64
		if useMemo {
			N := len(prog.Inst)
			memoBudget := resolveMemoBudget(&buildOpts)
			memoMaxLen = int32(memoBudget*8/N - 1)
			memoMaxSize = int64((N*(int(memoMaxLen)+1) + 7) / 8)
			if memoMaxSize > int64(memoBudget) {
				return nil, fmt.Errorf(
					"pattern requires %d bytes of memo memory, exceeds budget %d: "+
						"increase CompileOptions.MemoBudget",
					memoMaxSize, memoBudget)
			}
			memoTableBase = stackBase + int32(stackSize)
		}

		// Reserve an 8-byte (origPtr,origEnd) scratch slot for the groups/
		// batch-groups wrapper to stash true-input edge context that
		// captureBody's \b/\B checks need but can't derive from its own
		// (narrowed ptr, narrowed len) params alone — see FUZZER_BUGS.md #26.
		// Only needed when this captureBody is composed behind a find
		// wrapper (!anchored); the native/anchored export sees the caller's
		// real ptr/len directly and has no such gap.
		edgeScratchOff := int32(-1)
		var afterBT int64
		if useMemo {
			afterBT = int64(memoTableBase) + memoMaxSize
		} else {
			afterBT = btBase + int64(stackSize)
		}
		if !anchored && btHasWordBoundary(prog) {
			edgeScratchOff = int32(afterBT)
			afterBT += 8
		}
		p.tableEnd = utils.PageAlign(afterBT)

		p.numGroups = bt.numGroups
		p.edgeScratchOff = edgeScratchOff
		p.captureBody = appendBacktrackCodeEntry(nil, bt, stackBase, stackLimit, int32(frameSize), memoTableBase, useMemo, anchored, buildOpts.tableMemIdx, edgeScratchOff)
	}

	return p, nil
}

// assembleModule builds a single WASM module from multiple compiled patterns.
// standalone=true: module defines its own memory.
// standalone=false: module imports memory from "main" (for wasm-merge).
// Both modes emit active data segments; in non-standalone mode the host stub's
// reservation variable ensures the host runtime declares enough initial memory.
func assembleModule(patterns []*compiledPattern, memPages int32, standalone bool) []byte {
	// Pre-collect data segments.
	totalSegs := 0
	var rawData []byte
	for _, p := range patterns {
		totalSegs += p.dataSegCount
		rawData = append(rawData, p.dataBytes...)
	}

	// Pass 1: assign base function indices.
	baseIdx := make([]int, len(patterns))
	total := 0
	for i, p := range patterns {
		baseIdx[i] = total
		total += p.funcCount()
	}

	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6D)
	out = append(out, 0x01, 0x00, 0x00, 0x00)

	// Type section: 4 fixed types (match, find, capture/groups, and
	// alt-lit-anchor's forward_verify_i — Task 6 v1, 2026-07-05), plus an
	// optional 5th (the LM-2 batch find/groups wrapper signature) — added
	// only when some pattern actually has a batch export, so modules with
	// no LM-2 usage (including LikelyMatch modules where every pattern's
	// batch shape is out of v1 scope) don't pay its few bytes. Nothing else
	// ever references type index 4, so omitting it is always safe.
	// (A different 4th type — for the LNM non-mid bulk-skip helper — was
	// extracted to plans/non_mid_extension.go.archive Section 14; this is
	// an unrelated, newly-added type reusing the same slot number.)
	anyBatch := false
	for _, p := range patterns {
		if p.batchFindExport != "" || p.batchGroupsExport != "" {
			anyBatch = true
			break
		}
	}
	typeSection := []byte{
		0x04,
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0: (i32,i32)→i32
		0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7E, // type 1: (i32,i32)→i64
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, // type 2: (i32,i32,i32)→i32
		0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7E, // type 3: (i32,i32,i32)→i64 — alt-lit-anchor forward_verify_i
	}
	if anyBatch {
		typeSection[0] = 0x05
		typeSection = append(typeSection,
			0x60, 0x05, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F) // type 4: (i32,i32,i32,i32,i32)→i32 — LM-2 batch wrapper
	}
	out = appendSection(out, 1, typeSection)

	// Import section (embedded only): import "main" memory as memory[0].
	// In the merged binary, main keeps memory[0] and our own memory becomes memory[1].
	// Input data loads use implicit memory[0]; DFA table loads use explicit memory[1].
	if !standalone {
		var importSec []byte
		importSec = utils.AppendULEB128(importSec, 1) // 1 import
		importSec = appendString(importSec, "main")   // module name
		importSec = appendString(importSec, "memory") // field name
		importSec = append(importSec, 0x02)           // kind: memory
		importSec = append(importSec, 0x00)           // limits flags: no max
		importSec = append(importSec, 0x00)           // min = 0 pages
		out = appendSection(out, 2, importSec)
	}

	// Function section: pattern functions only.
	var fs []byte
	fs = utils.AppendULEB128(fs, uint32(total))
	for _, p := range patterns {
		if p.matchBody != nil {
			fs = append(fs, 0x00)
		}
		if p.altLitAnchorBranches != nil {
			for range p.altLitAnchorBranches {
				fs = append(fs, 0x00) // backward_scan_i: (i32,i32)->i32
				fs = append(fs, 0x03) // forward_verify_i: (i32,i32,i32)->i64
			}
			fs = append(fs, 0x01) // dispatcher: (i32,i32)->i64
		} else if p.litAnchorBackScanBody != nil {
			fs = append(fs, 0x00) // backward_scan: (i32,i32)->i32
			fs = append(fs, 0x01) // lit_anchor_find: (i32,i32)->i64
		} else if p.findBody != nil {
			fs = append(fs, 0x01)
		}
		if p.captureBody != nil {
			fs = append(fs, 0x02)
			if !p.anchored {
				fs = append(fs, 0x02)
			}
			if p.namedGroupsExport != "" {
				fs = append(fs, 0x02)
			}
		}
		// LNM non-mid bulk-skip helper function-section entry was here —
		// see archive Section 15.
		if p.batchFindExport != "" {
			fs = append(fs, 0x04)
		}
		if p.batchGroupsExport != "" {
			fs = append(fs, 0x04)
		}
	}
	out = appendSection(out, 3, fs)

	// Memory section: own memory for both standalone and embedded.
	// standalone modules export it; embedded modules do not (wasm-merge renumbers).
	{
		var mem []byte
		mem = append(mem, 0x01, 0x00)
		mem = utils.AppendULEB128(mem, uint32(memPages))
		out = appendSection(out, 5, mem)
	}

	// Export section.
	numExports := 0
	if standalone {
		numExports++
	}
	for _, p := range patterns {
		matchOff, _, findOff, captureOff, wrapperOff, namedWrapperOff := p.offsets()
		if p.matchExport != "" && matchOff >= 0 {
			numExports++
		}
		if p.findExport != "" && findOff >= 0 {
			numExports++
		}
		if p.groupsExport != "" && ((p.anchored && captureOff >= 0) || (!p.anchored && wrapperOff >= 0)) {
			numExports++
		}
		if p.namedGroupsExport != "" && namedWrapperOff >= 0 {
			numExports++
		}
		if p.batchFindExport != "" {
			numExports++
		}
		if p.batchGroupsExport != "" {
			numExports++
		}
	}
	var es []byte
	es = utils.AppendULEB128(es, uint32(numExports))
	if standalone {
		es = appendString(es, "memory")
		es = append(es, 0x02, 0x00)
	}
	for i, p := range patterns {
		base := baseIdx[i]
		matchOff, _, findOff, captureOff, wrapperOff, namedWrapperOff := p.offsets()
		if p.matchExport != "" && matchOff >= 0 {
			es = appendString(es, p.matchExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+matchOff))
		}
		if p.findExport != "" && findOff >= 0 {
			es = appendString(es, p.findExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+findOff))
		}
		if p.groupsExport != "" && ((p.anchored && captureOff >= 0) || (!p.anchored && wrapperOff >= 0)) {
			var groupsFuncIdx int
			if p.anchored {
				groupsFuncIdx = base + captureOff
			} else {
				groupsFuncIdx = base + wrapperOff
			}
			es = appendString(es, p.groupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(groupsFuncIdx))
		}
		if p.namedGroupsExport != "" && namedWrapperOff >= 0 {
			es = appendString(es, p.namedGroupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+namedWrapperOff))
		}
		batchFindOff, batchGroupsOff := p.batchOffsets()
		if p.batchFindExport != "" && batchFindOff >= 0 {
			es = appendString(es, p.batchFindExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+batchFindOff))
		}
		if p.batchGroupsExport != "" && batchGroupsOff >= 0 {
			es = appendString(es, p.batchGroupsExport)
			es = append(es, 0x00)
			es = utils.AppendULEB128(es, uint32(base+batchGroupsOff))
		}
	}
	out = appendSection(out, 7, es)

	// Code section.
	var cs []byte
	cs = utils.AppendULEB128(cs, uint32(total))
	for i, p := range patterns {
		base := baseIdx[i]
		_, backwardScanOff, findOff, captureOff, wrapperOff, _ := p.offsets()
		if p.matchBody != nil {
			cs = append(cs, p.matchBody...)
		}
		if p.altLitAnchorBranches != nil {
			for _, br := range p.altLitAnchorBranches {
				cs = append(cs, br.backScanBody...)
				cs = append(cs, br.forwardVerifyBody...)
			}
			// Generate the dispatcher body now that function indices are known.
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			branchFuncIdxs := make([]altLitAnchorFuncIdx, len(p.altLitAnchorBranches))
			for j := range p.altLitAnchorBranches {
				backOff, fwdOff := p.altLitAnchorBranchFuncIdx(j)
				branchFuncIdxs[j] = altLitAnchorFuncIdx{backScan: base + backOff, forwardVerify: base + fwdOff}
			}
			altDispatchBody := buildAltLitAnchorFindBody(p, branchFuncIdxs, tableMemIdx)
			cs = utils.AppendULEB128(cs, uint32(len(altDispatchBody)))
			cs = append(cs, altDispatchBody...)
		} else if p.litAnchorBackScanBody != nil {
			cs = append(cs, p.litAnchorBackScanBody...)
			// Generate lit_anchor_find body now that function indices are known.
			tableMemIdx := 0
			if !standalone {
				tableMemIdx = 1
			}
			litAnchorFindBody := buildLitAnchorFindBody(p.litAnchorFindTable, p.litAnchorFindLayout, p, base+backwardScanOff, tableMemIdx)
			cs = utils.AppendULEB128(cs, uint32(len(litAnchorFindBody)))
			cs = append(cs, litAnchorFindBody...)
		} else if p.findBody != nil {
			// LNM non-mid bulk-skip helper call-site patching was here —
			// see archive Section 16.
			cs = append(cs, p.findBody...)
		}
		if p.captureBody != nil {
			cs = append(cs, p.captureBody...)
			if !p.anchored {
				wrapperTableMemIdx := 0
				if !standalone {
					wrapperTableMemIdx = 1
				}
				edgeOff := int32(-1)
				if !p.isTDFA {
					edgeOff = p.edgeScratchOff
				}
				cs = appendWrapperCodeEntry(cs, base+findOff, base+captureOff, p.numGroups, wrapperTableMemIdx, edgeOff)
				if p.namedGroupsExport != "" {
					cs = appendNamedGroupsWrapperCodeEntry(cs, base+wrapperOff)
				}
			} else if p.namedGroupsExport != "" {
				cs = appendNamedGroupsWrapperCodeEntry(cs, base+captureOff)
			}
		}
		// LNM non-mid bulk-skip helper body append was here —
		// see archive Section 16.
		if p.batchFindExport != "" {
			cs = appendBatchFindWrapperCodeEntry(cs, base+findOff)
		}
		if p.batchGroupsExport != "" {
			if p.anchored {
				// Path B (task 44 goal 4): captureBody IS the exported groups
				// function — no separate find function to compose over.
				cs = appendBatchLitChainGroupsWrapperCodeEntry(cs, base+captureOff, p.numGroups)
			} else {
				batchTableMemIdx := 0
				if !standalone {
					batchTableMemIdx = 1
				}
				edgeOff := int32(-1)
				if !p.isTDFA {
					edgeOff = p.edgeScratchOff
				}
				cs = appendBatchGroupsWrapperCodeEntry(cs, base+findOff, base+captureOff, p.numGroups, batchTableMemIdx, edgeOff)
			}
		}
	}
	out = appendSection(out, 10, cs)

	// Data section: active segments targeting the correct memory index.
	if totalSegs > 0 {
		var ds []byte
		if !standalone {
			// Re-encode data segments to target memory[1] (own DFA-table memory).
			segs := parseDataSegments(rawData)
			ds = utils.AppendULEB128(ds, uint32(len(segs)))
			for _, seg := range segs {
				ds = appendDataSegmentMem1(ds, seg.offset, seg.data)
			}
		} else {
			ds = utils.AppendULEB128(ds, uint32(totalSegs))
			ds = append(ds, rawData...)
		}
		out = appendSection(out, 11, ds)
	}

	return out
}

// Compile compiles multiple regexp patterns to a single WASM module.
//   - standalone=false: module imports "main" memory as memory[0] (input) and declares its own memory for DFA tables (becomes memory[1] after wasm-merge)
//   - standalone=true:  module declares its own memory and exports it as "memory" (for JS/TS/browser direct use)
//   - tableBase: starting address for DFA/capture tables within the module's memory; use 0 for
//     embedded modules (tables start at address 0 of own memory). Callers like re2test/perftest
//     pass a non-zero value to reserve low pages for their own test input buffers.
//
// All patterns must compile successfully; any error stops compilation immediately.
func Compile(patterns []config.RegexEntry, tableBase int64, standalone bool, userOpts ...CompileOptions) ([]byte, int64, error) {
	var opts CompileOptions
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	return compileAll(patterns, tableBase, standalone, 0, opts)
}

// CompileForced is like Compile, but overrides engine selection for the
// capture path (groups_func / named_groups_func) of every pattern that
// requests one, forcing forceGroupsEngine (EngineTDFA or EngineBacktrack)
// instead of letting selectBestEngine choose. Pass 0 for forceGroupsEngine
// to get ordinary auto-selection (equivalent to Compile).
//
// This has no effect on match_func/find_func: those have no independent
// engine-selection axis (always DFA, with Backtracking only as an overflow
// fallback when the DFA exceeds CompileOptions.MaxDFAStates/MaxDFAMemory —
// see the MaxDFAStates doc comment for forcing that path instead). It also
// has no effect on capture-path patterns that hit one of compilePattern's
// literal-chain fast paths (analyseLitChainGroupsRange and friends), which
// bypass selectBestEngine entirely.
func CompileForced(patterns []config.RegexEntry, tableBase int64, standalone bool, forceGroupsEngine EngineType, userOpts ...CompileOptions) ([]byte, int64, error) {
	if forceGroupsEngine != 0 && forceGroupsEngine != EngineTDFA && forceGroupsEngine != EngineBacktrack {
		return nil, 0, fmt.Errorf("CompileForced: forceGroupsEngine must be 0, EngineTDFA, or EngineBacktrack, got %v", forceGroupsEngine)
	}
	var opts CompileOptions
	if len(userOpts) > 0 {
		opts = userOpts[0]
	}
	return compileAll(patterns, tableBase, standalone, forceGroupsEngine, opts)
}

func compileAll(patterns []config.RegexEntry, tableBase int64, standalone bool, forceGroupsEngine EngineType, opts CompileOptions) ([]byte, int64, error) {
	if !standalone {
		opts.tableMemIdx = 1
	}
	var compiled []*compiledPattern
	cur := tableBase
	for _, re := range patterns {
		p, err := compilePattern(re, cur, forceGroupsEngine, opts)
		if err != nil {
			return nil, 0, fmt.Errorf("compile pattern %q: %w", re.Pattern, err)
		}
		// Batch find/groups export trigger (plans/TODO.md task 44). Sole
		// trigger for batchFindExport/batchGroupsExport — independent of
		// LikelyMode. find_func is always eligible; groups_func is eligible
		// for both the composed (!anchored) and native lit-chain (anchored,
		// "Path B") shapes — see the compiledPattern field doc.
		if hasBatchHint(re.Hints) {
			if p.findExport != "" {
				p.batchFindExport = p.findExport + "_batch"
			}
			groupsBatchName := p.groupsExport
			if groupsBatchName == "" {
				groupsBatchName = p.namedGroupsExport
			}
			if groupsBatchName != "" {
				p.batchGroupsExport = groupsBatchName + "_batch"
			}
		}
		compiled = append(compiled, p)
		if p.tableEnd > cur {
			cur = utils.PageAlign(p.tableEnd)
		}
	}
	if len(compiled) == 0 {
		return nil, tableBase, nil
	}
	lastTableEnd := compiled[len(compiled)-1].tableEnd
	memPages := int32(utils.PageAlign(lastTableEnd) / 65536)
	if memPages < 1 {
		memPages = 1
	}
	return assembleModule(compiled, memPages, standalone), lastTableEnd, nil
}

// CmdCompile compiles all regexp patterns (and optional sets) from cfg to a
// single WASM module. When cfg.Sets is non-empty, CompileFile is used instead
// of the bare Compile path, so set-match functions are included in the output.
// output is the output path (absolute, relative to cwd, or "-" for stdout).
// Mode is auto-selected from cfg.Output: empty → standalone; non-empty → embedded.
func CmdCompile(cfg config.BuildConfig, output string) error {
	outPath := output
	slog.Info("Compiling regexps", "count", len(cfg.Regexps), "output", outPath)

	var wasmBytes []byte
	if len(cfg.Sets) > 0 {
		var err error
		wasmBytes, _, err = CompileFile(cfg, output)
		if err != nil {
			return fmt.Errorf("compile: %w", err)
		}
	} else {
		compOpts := CompileOptions{
			MaxDFAStates: cfg.MaxDFAStates,
			MaxTDFARegs:  cfg.MaxTDFARegs,
		}
		standalone := cfg.Output == ""
		var err error
		wasmBytes, _, err = Compile(cfg.Regexps, 0, standalone, compOpts)
		if err != nil {
			return fmt.Errorf("compile: %w", err)
		}
	}

	if outPath == "-" {
		if _, err := os.Stdout.Write(wasmBytes); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		slog.Info("Done", "bytes", len(wasmBytes))
		return nil
	}
	if err := os.WriteFile(outPath, wasmBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	slog.Info("Done", "bytes", len(wasmBytes))
	return nil
}

// CmdWriteDiagJSON re-runs CompileFile, collects set diagnostics, and writes
// the Diagnostics structure as JSON to diagPath (or stdout if diagPath == "-").
// Independent of slog level — the JSON is always complete.
func CmdWriteDiagJSON(cfg config.BuildConfig, output, diagPath string) error {
	if len(cfg.Sets) == 0 {
		return nil
	}
	// Gather diagnostics by re-running CompileFile (it already computed them;
	// for simplicity we re-run rather than threading Diagnostics through CmdCompile).
	var prefixPool, suffixPool dfaPool
	nameIdx := make(map[string]int, len(cfg.Regexps))
	for i, re := range cfg.Regexps {
		if re.Name != "" {
			nameIdx[re.Name] = i
		}
	}
	diag := Diagnostics{PatternsTotal: len(cfg.Regexps)}
	for _, sc := range cfg.Sets {
		var selectedIdx []int
		if sc.Patterns.All {
			for i := range cfg.Regexps {
				selectedIdx = append(selectedIdx, i)
			}
		} else {
			for _, name := range sc.Patterns.Names {
				if idx, ok := nameIdx[name]; ok {
					selectedIdx = append(selectedIdx, idx)
				}
			}
		}
		var infos []*PatternInfo
		var globalIDs []int
		var droppedRefs []PatternRef
		for _, idx := range selectedIdx {
			re := cfg.Regexps[idx]
			if re.CaptureStubsRequested() {
				diag.CaptureBearing++
				droppedRefs = append(droppedRefs, PatternRef{ID: idx, Name: re.Name})
				continue
			}
			info, err := analyzePattern(re, &prefixPool, &suffixPool)
			if err != nil {
				continue
			}
			info.globalID = idx
			info.name = re.Name
			infos = append(infos, info)
			globalIDs = append(globalIDs, idx)
		}
		spec := SetSpec{
			Name:       sc.Name,
			FindAny:    sc.FindAny,
			FindAll:    sc.FindAll,
			Match:      sc.Match,
			Patterns:   infos,
			PatternIDs: globalIDs,
		}
		cs := CompileSet(spec, &prefixPool, &suffixPool, CompileSetOptions{})
		if cs.diag != nil {
			cs.diag.CaptureBearingDropped = droppedRefs
			diag.Sets = append(diag.Sets, *cs.diag)
		}
		diag.InSet += len(infos)
	}
	diag.PrefixDedupPoolSize = len(prefixPool.tables)

	data, _ := json.MarshalIndent(diag, "", "  ")
	data = append(data, '\n')

	if diagPath == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(diagPath, data, 0o644)
}

// stripCaptures converts all capture groups in the regexp tree to non-capturing
// by replacing each OpCapture node with its single sub-expression in-place.
// Used when the pattern has captures but capture stubs are not requested.
func stripCaptures(re *syntax.Regexp) {
	for _, sub := range re.Sub {
		stripCaptures(sub)
	}
	if re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		*re = *re.Sub[0]
	}
}

// NeedsUnicodeSupport reports whether pattern requires CompileOptions.Unicode
// to compile — i.e. its NFA program contains a rune class reachable only via
// non-ASCII codepoints (see needsUnicodeSupport). Exported so external
// correctness harnesses (e.g. tools/fuzz) can pre-filter Unicode-requiring
// patterns using the exact predicate compile() applies internally, instead
// of approximating it by scanning the raw pattern string — which misses
// escapes like `\x80` that are pure ASCII text but denote a non-ASCII
// codepoint once parsed. Returns an error if the pattern cannot be parsed.
func NeedsUnicodeSupport(pattern string) (bool, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false, fmt.Errorf("parse error: %w", err)
	}
	prog, _ := syntax.Compile(re.Simplify())
	return needsUnicodeSupport(prog), nil
}

// SelectEngine returns the EngineType that would be chosen for the given pattern,
// without actually compiling it. Returns an error if the pattern cannot be parsed
// or compiled to NFA bytecode.
func SelectEngine(pattern string, opts CompileOptions) (EngineType, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0, fmt.Errorf("parse error: %w", err)
	}
	prog, _ := syntax.Compile(re.Simplify())
	if needsUnicodeSupport(prog) && !opts.Unicode {
		return 0, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}
	return selectBestEngine(prog, &opts), nil
}

// compile parses the pattern, selects the optimal engine, and returns a compiled matcher.
func compile(pattern string, opts ...CompileOptions) (matcher, error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	simplified := re.Simplify()
	prog, _ := syntax.Compile(simplified)

	var options CompileOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	if requiresUnicode := needsUnicodeSupport(prog); requiresUnicode && !options.Unicode {
		return nil, fmt.Errorf("pattern contains Unicode features but Unicode option not enabled")
	}

	var engineType EngineType
	if options.ForceEngine != 0 {
		engineType = options.ForceEngine
	} else {
		engineType = selectBestEngine(prog, &options)
	}

	switch engineType {
	case EngineDFA:
		// max(maxHelperDFAStates, resolveMaxDFAStates(&options)): callers
		// (compile.go's match/find construction) deliberately set
		// MaxDFAStates arbitrarily low to force a BT fallback while still
		// expecting a real (if oversized) table back for prefix-extraction
		// optimisations — see maxHelperDFAStates' doc comment. But a caller
		// that configures a MaxDFAStates ABOVE maxHelperDFAStates (e.g.
		// re2test's 100000) must have construction actually reach that
		// budget, or the 2048 ceiling silently downgrades DFA-eligible
		// patterns to Backtracking regardless of the configured threshold.
		ceiling := max(maxHelperDFAStates, resolveMaxDFAStates(&options))
		d, ok := newDFA(prog, options.Unicode, options.LeftmostFirst, ceiling)
		if !ok {
			return nil, errDFAStateLimitExceeded
		}
		return d, nil
	case EngineBacktrack:
		if len(prog.Inst) > maxBTFallbackInstructions {
			return nil, ErrBTProgramTooLarge
		}
		return newBacktrack(prog), nil
	default:
		return nil, fmt.Errorf("engine %v not yet supported by wasm compiler", engineType)
	}
}

// needsUnicodeSupport analyzes whether a compiled program requires Unicode support.
func needsUnicodeSupport(prog *syntax.Prog) bool {
	const maxUnicode = 0x10ffff

	for i := range prog.Inst {
		inst := &prog.Inst[i]

		switch inst.Op {
		case syntax.InstRune, syntax.InstRune1:
			hasASCII := false
			hasNonASCII := false

			for _, r := range inst.Rune {
				if r <= 127 {
					hasASCII = true
				} else if r != maxUnicode {
					hasNonASCII = true
				}
			}

			if hasNonASCII && !hasASCII {
				return true
			}
		}
	}
	return false
}

// buildGroupsWrapperBody emits the WASM body for the exported groups wrapper function.
// See engine_dfa.go for the full documentation — this function was moved to compile.go
// because it is not DFA-specific; it is used by the module assembler.
//
// Signature: (ptr i32, len i32, out_ptr i32) → i32
//
// edgeScratchOff (-1 = not applicable, e.g. TDFA or a captureBody with no
// \b/\B) is the table-memory offset of an 8-byte (origPtr,origEnd) scratch
// slot; when set, this wrapper stashes the true (unnarrowed) input's edge
// context there before calling captureFuncIdx, so its \b/\B checks can see
// past the DFA-narrowed match slice — see FUZZER_BUGS.md #26 and
// btWordBoundary in engine_backtrack.go.
func buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups, tableMemIdx int, edgeScratchOff int32) []byte {
	var b []byte
	b = append(b, 0x02)
	b = append(b, 0x03, 0x7F) // 3 × i32
	b = append(b, 0x01, 0x7E) // 1 × i64
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x01)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x22, 0x06)
	b = append(b, 0x42, 0x7F)
	b = append(b, 0x51)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x05)
	if edgeScratchOff >= 0 {
		// scratch[0] = origPtr (this wrapper's own ptr param, never shifted)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = append(b, 0x20, 0x00)
		b = appendTableStore32(b, tableMemIdx, 0)
		// scratch[4] = origEnd (ptr+len)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x6A)
		b = appendTableStore32(b, tableMemIdx, 4)
	}
	b = append(b, 0x20, 0x06)
	b = append(b, 0x42, 0x20)
	b = append(b, 0x88)
	b = append(b, 0xA7)
	b = append(b, 0x21, 0x03)
	b = append(b, 0x20, 0x00)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x20, 0x06)
	b = append(b, 0xA7)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6B)
	b = append(b, 0x20, 0x02)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(captureFuncIdx))
	b = append(b, 0x22, 0x04)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x46)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x41, 0x7F)
	b = append(b, 0x05)
	for i := 0; i < numGroups*2; i++ {
		offset := uint32(i * 4)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x28, 0x02)
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x22, 0x05)
		b = append(b, 0x41, 0x00)
		b = append(b, 0x4E)
		b = append(b, 0x04, 0x40)
		b = append(b, 0x20, 0x02)
		b = append(b, 0x20, 0x05)
		b = append(b, 0x20, 0x03)
		b = append(b, 0x6A)
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, offset)
		b = append(b, 0x0B)
	}
	b = append(b, 0x20, 0x04)
	b = append(b, 0x20, 0x03)
	b = append(b, 0x6A)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	b = append(b, 0x0B)
	return b
}

// appendWrapperCodeEntry appends a size-prefixed groups wrapper body to cs.
func appendWrapperCodeEntry(cs []byte, findFuncIdx, captureFuncIdx, numGroups, tableMemIdx int, edgeScratchOff int32) []byte {
	body := buildGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups, tableMemIdx, edgeScratchOff)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBatchFindWrapperBody emits the WASM body for the LM-2 batch find
// export (plans/LM_TODO.md LM-2). Signature (type 4):
//
//	(ptr i32, len i32, out_ptr i32, out_cap i32, start_pos i32) → i32 (count)
//
// Loops calling the existing find function (findFuncIdx, type 1:
// (i32,i32)→i64, unchanged) at successive scan positions, writing each
// match as a (start, end) u32 pair — absolute, i.e. relative to ptr, same
// convention as a single find call — at out_ptr + count*8, until out_cap
// matches have been written or the scan reaches len or no-match. The
// empty-match advance rule (relEnd > relStart ? relEnd : relStart+1)
// mirrors the host-side loop in the JS/TS find generators exactly.
//
// Locals (beyond params 0-4): 5=pos i32, 6=count i32, 7=r i64,
// 8=relStart i32, 9=relEnd i32.
func buildBatchFindWrapperBody(findFuncIdx int) []byte {
	var b []byte
	// Locals: 2×i32 (pos, count), 1×i64 (r), 2×i32 (relStart, relEnd).
	b = append(b, 0x03)
	b = append(b, 0x02, 0x7F)
	b = append(b, 0x01, 0x7E)
	b = append(b, 0x02, 0x7F)

	// pos = start_pos; count = 0
	b = append(b, 0x20, 0x04, 0x21, 0x05)
	b = append(b, 0x41, 0x00, 0x21, 0x06)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $L

	// if count >= out_cap: br $done
	b = append(b, 0x20, 0x06, 0x20, 0x03, 0x4F, 0x0D, 0x01)
	// if pos > len: br $done
	b = append(b, 0x20, 0x05, 0x20, 0x01, 0x4B, 0x0D, 0x01)

	// r = call find(ptr+pos, len-pos)
	b = append(b, 0x20, 0x00, 0x20, 0x05, 0x6A)
	b = append(b, 0x20, 0x01, 0x20, 0x05, 0x6B)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x21, 0x07)

	// if r < 0: br $done
	b = append(b, 0x20, 0x07, 0x42, 0x00, 0x53, 0x0D, 0x01)

	// relStart = wrap(r >> 32u); relEnd = wrap(r)
	b = append(b, 0x20, 0x07, 0x42, 0x20, 0x88, 0xA7, 0x21, 0x08)
	b = append(b, 0x20, 0x07, 0xA7, 0x21, 0x09)

	// store absolute start at out_ptr + count*8
	b = append(b, 0x20, 0x02, 0x20, 0x06, 0x41, 0x08, 0x6C, 0x6A)
	b = append(b, 0x20, 0x05, 0x20, 0x08, 0x6A)
	b = append(b, 0x36, 0x02, 0x00)
	// store absolute end at out_ptr + count*8 + 4
	b = append(b, 0x20, 0x02, 0x20, 0x06, 0x41, 0x08, 0x6C, 0x6A)
	b = append(b, 0x20, 0x05, 0x20, 0x09, 0x6A)
	b = append(b, 0x36, 0x02, 0x04)

	// count += 1
	b = append(b, 0x20, 0x06, 0x41, 0x01, 0x6A, 0x21, 0x06)

	// pos = relEnd > relStart ? pos+relEnd : pos+relStart+1
	b = append(b, 0x20, 0x09, 0x20, 0x08, 0x4B)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, 0x05, 0x20, 0x09, 0x6A)
	b = append(b, 0x05)
	b = append(b, 0x20, 0x05, 0x20, 0x08, 0x6A, 0x41, 0x01, 0x6A)
	b = append(b, 0x0B)
	b = append(b, 0x21, 0x05)

	b = append(b, 0x0C, 0x00) // br $L (continue)
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	b = append(b, 0x20, 0x06) // return count
	b = append(b, 0x0B)       // end function
	return b
}

// appendBatchFindWrapperCodeEntry appends a size-prefixed batch find wrapper body to cs.
func appendBatchFindWrapperCodeEntry(cs []byte, findFuncIdx int) []byte {
	body := buildBatchFindWrapperBody(findFuncIdx)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBatchGroupsWrapperBody emits the WASM body for the LM-2 batch groups
// export (plans/LM_TODO.md LM-2). Signature (type 4), same as the batch
// find wrapper:
//
//	(ptr i32, len i32, out_ptr i32, out_cap i32, start_pos i32) → i32 (count)
//
// v1 scope: only for the non-anchored (composed find+capture) shape —
// same restriction as buildGroupsWrapperBody itself. Calls findFuncIdx
// (type 1) and captureFuncIdx (type 2, (i32,i32,i32)→i32 — absStart,
// matchLen, slots_out_ptr) directly per match, exactly mirroring
// buildGroupsWrapperBody's composition, but inside a loop writing
// fixed-size records into a caller-provided batch buffer instead of a
// single fixed out_ptr.
//
// Record layout at out_ptr + count*recordSize, recordSize = 8 + numGroups*8:
//
//	[0:4]  start (absolute, i.e. relative to ptr — same convention as find)
//	[4:8]  end
//	[8:]   numGroups*2 × i32 slot values (group i = [8+i*8 : 8+i*8+8]);
//	       group 0 is the whole match, duplicating [0:4]/[4:8] — kept for a
//	       uniform per-group access pattern in the consuming stub.
//
// edgeScratchOff (-1 = not applicable) is the table-memory offset of an
// 8-byte (origPtr,origEnd) scratch slot; when set, this wrapper stashes
// the true (unnarrowed) input's edge context there once, before the scan
// loop, so captureFuncIdx's \b/\B checks can see past each narrowed match
// slice — see FUZZER_BUGS.md #26 and buildGroupsWrapperBody above (this
// wrapper's ptr/len params, unlike absStart/matchLen inside the loop, are
// constant across all iterations, so the write happens exactly once).
//
// Locals (beyond params 0-4): 5=pos i32, 6=count i32, 7=r i64,
// 8=relStart i32, 9=relEnd i32, 10=absStart i32, 11=matchLen i32,
// 12=recBase i32, 13=capRes i32, 14=adj i32, 15=slotVal i32.
func buildBatchGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups, tableMemIdx int, edgeScratchOff int32) []byte {
	recordSize := 8 + numGroups*8

	var b []byte
	// Locals: 2×i32 (pos, count), 1×i64 (r), 8×i32 (relStart, relEnd,
	// absStart, matchLen, recBase, capRes, adj, slotVal).
	b = append(b, 0x03)
	b = append(b, 0x02, 0x7F)
	b = append(b, 0x01, 0x7E)
	b = append(b, 0x08, 0x7F)

	// pos = start_pos; count = 0
	b = append(b, 0x20, 0x04, 0x21, 0x05)
	b = append(b, 0x41, 0x00, 0x21, 0x06)

	if edgeScratchOff >= 0 {
		// scratch[0] = origPtr (param 0); scratch[4] = origEnd (ptr+len) —
		// written once; constant across every iteration of the scan loop.
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = append(b, 0x20, 0x00)
		b = appendTableStore32(b, tableMemIdx, 0)
		b = append(b, 0x41)
		b = utils.AppendSLEB128(b, edgeScratchOff)
		b = append(b, 0x20, 0x00)
		b = append(b, 0x20, 0x01)
		b = append(b, 0x6A)
		b = appendTableStore32(b, tableMemIdx, 4)
	}

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $L

	// if count >= out_cap: br $done
	b = append(b, 0x20, 0x06, 0x20, 0x03, 0x4F, 0x0D, 0x01)
	// if pos > len: br $done
	b = append(b, 0x20, 0x05, 0x20, 0x01, 0x4B, 0x0D, 0x01)

	// r = call find(ptr+pos, len-pos)
	b = append(b, 0x20, 0x00, 0x20, 0x05, 0x6A)
	b = append(b, 0x20, 0x01, 0x20, 0x05, 0x6B)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(findFuncIdx))
	b = append(b, 0x21, 0x07)

	// if r < 0: br $done
	b = append(b, 0x20, 0x07, 0x42, 0x00, 0x53, 0x0D, 0x01)

	// relStart = wrap(r >> 32u); relEnd = wrap(r)
	b = append(b, 0x20, 0x07, 0x42, 0x20, 0x88, 0xA7, 0x21, 0x08)
	b = append(b, 0x20, 0x07, 0xA7, 0x21, 0x09)

	// absStart = ptr + pos + relStart
	b = append(b, 0x20, 0x00, 0x20, 0x05, 0x6A, 0x20, 0x08, 0x6A, 0x21, 0x0A)
	// matchLen = relEnd - relStart
	b = append(b, 0x20, 0x09, 0x20, 0x08, 0x6B, 0x21, 0x0B)
	// recBase = out_ptr + count*recordSize
	b = append(b, 0x20, 0x02, 0x20, 0x06, 0x41)
	b = utils.AppendSLEB128(b, int32(recordSize))
	b = append(b, 0x6C, 0x6A, 0x21, 0x0C)

	// capRes = call capture(absStart, matchLen, recBase+8)
	b = append(b, 0x20, 0x0A, 0x20, 0x0B)
	b = append(b, 0x20, 0x0C, 0x41, 0x08, 0x6A)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(captureFuncIdx))
	b = append(b, 0x21, 0x0D)

	// if capRes < 0: br $done
	b = append(b, 0x20, 0x0D, 0x41, 0x00, 0x48, 0x0D, 0x01)

	// adj = pos + relStart
	b = append(b, 0x20, 0x05, 0x20, 0x08, 0x6A, 0x21, 0x0E)

	// Adjust each of numGroups*2 slot ints at recBase+8+g*4 by +adj (skip
	// unmatched groups, encoded as -1).
	for g := 0; g < numGroups*2; g++ {
		off := uint32(8 + g*4)
		b = append(b, 0x20, 0x0C)
		b = append(b, 0x28, 0x02)
		b = utils.AppendULEB128(b, off)
		b = append(b, 0x22, 0x0F) // tee slotVal
		b = append(b, 0x41, 0x00, 0x4E)
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, 0x0C)
		b = append(b, 0x20, 0x0F, 0x20, 0x0E, 0x6A)
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, off)
		b = append(b, 0x0B) // end if
	}

	// Copy the (now-adjusted) whole-match slot0/slot1 into the record's
	// start/end prefix.
	b = append(b, 0x20, 0x0C, 0x20, 0x0C, 0x28, 0x02, 0x08, 0x36, 0x02, 0x00)
	b = append(b, 0x20, 0x0C, 0x20, 0x0C, 0x28, 0x02, 0x0C, 0x36, 0x02, 0x04)

	// count += 1
	b = append(b, 0x20, 0x06, 0x41, 0x01, 0x6A, 0x21, 0x06)

	// pos = relEnd > relStart ? pos+relEnd : pos+relStart+1
	b = append(b, 0x20, 0x09, 0x20, 0x08, 0x4B)
	b = append(b, 0x04, 0x7F)
	b = append(b, 0x20, 0x05, 0x20, 0x09, 0x6A)
	b = append(b, 0x05)
	b = append(b, 0x20, 0x05, 0x20, 0x08, 0x6A, 0x41, 0x01, 0x6A)
	b = append(b, 0x0B)
	b = append(b, 0x21, 0x05)

	b = append(b, 0x0C, 0x00) // br $L (continue)
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	b = append(b, 0x20, 0x06) // return count
	b = append(b, 0x0B)       // end function
	return b
}

// appendBatchGroupsWrapperCodeEntry appends a size-prefixed batch groups wrapper body to cs.
func appendBatchGroupsWrapperCodeEntry(cs []byte, findFuncIdx, captureFuncIdx, numGroups, tableMemIdx int, edgeScratchOff int32) []byte {
	body := buildBatchGroupsWrapperBody(findFuncIdx, captureFuncIdx, numGroups, tableMemIdx, edgeScratchOff)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// buildBatchLitChainGroupsWrapperBody emits the WASM body for the batch
// groups export over a Path B native lit-chain groups body (plans/TODO.md
// task 44, goal 4). Signature (type 4), same ABI as buildBatchGroupsWrapperBody:
//
//	(ptr i32, len i32, out_ptr i32, out_cap i32, start_pos i32) → i32 (count)
//
// Unlike buildBatchGroupsWrapperBody there is only one function to call:
// captureFuncIdx (type 2, (i32,i32,i32)→i32 meaning (ptr,len,out_ptr), NOT
// buildGroupsWrapperBody's captureFuncIdx meaning (absStart,matchLen,
// slots_out_ptr) — same WASM type, different convention, hence a dedicated
// wrapper rather than reusing buildBatchGroupsWrapperBody) IS the exported
// groups function for this pattern shape (compiledPattern.anchored's native
// A.3 meaning — see appendLitChainFindGroupsCodeEntry and siblings).
//
// captureFuncIdx returns the match end position relative to the ptr passed
// to IT, or -1. It writes group 0 (the whole match) at slots [0:8) — start
// relative to its own ptr, end likewise — exactly like buildGroupsWrapperBody's
// out_ptr convention, so writing directly into the record's slot area
// (recBase+8) lines group 0 up with the record's [8:16) group-0 slots for
// free. This wrapper then adjusts every slot (group 0 included) by the
// running scan offset (pos) and copies the adjusted group-0 start/end into
// the record's [0:8) header — same record layout buildBatchGroupsWrapperBody
// produces, so the JS/TS consumer needs no path-specific branching.
//
// assembleModule also routes here for the general native-anchored TDFA/
// Backtracking capture body (compiledPattern.anchored set via isAnchoredFind
// in compilePattern's non-lit-chain path) whenever it has a batch export —
// that body shares this wrapper's (ptr,len,out_ptr)→i32 ABI but, unlike a
// genuine lit-chain shape, CAN match zero-length (e.g. `^(a*)?` at the end of
// the input). So the advance step cannot assume r always strictly advances;
// it uses the same relEnd>relStart-guarded rule as buildBatchGroupsWrapperBody,
// read back from the record's just-written, already-adjusted start/end
// header (recBase+0/recBase+4) instead of pos+r directly.
//
// Locals (beyond params 0-4): 5=pos i32, 6=count i32, 7=recBase i32,
// 8=r i32, 9=slotVal i32.
func buildBatchLitChainGroupsWrapperBody(captureFuncIdx, numGroups int) []byte {
	recordSize := 8 + numGroups*8

	var b []byte
	// Locals: 5 × i32 (pos, count, recBase, r, slotVal).
	b = append(b, 0x01)
	b = append(b, 0x05, 0x7F)

	// pos = start_pos; count = 0
	b = append(b, 0x20, 0x04, 0x21, 0x05)
	b = append(b, 0x41, 0x00, 0x21, 0x06)

	b = append(b, 0x02, 0x40) // block $done
	b = append(b, 0x03, 0x40) // loop $L

	// if count >= out_cap: br $done
	b = append(b, 0x20, 0x06, 0x20, 0x03, 0x4F, 0x0D, 0x01)
	// if pos > len: br $done
	b = append(b, 0x20, 0x05, 0x20, 0x01, 0x4B, 0x0D, 0x01)

	// recBase = out_ptr + count*recordSize
	b = append(b, 0x20, 0x02, 0x20, 0x06, 0x41)
	b = utils.AppendSLEB128(b, int32(recordSize))
	b = append(b, 0x6C, 0x6A, 0x21, 0x07)

	// r = call capture(ptr+pos, len-pos, recBase+8)
	b = append(b, 0x20, 0x00, 0x20, 0x05, 0x6A)
	b = append(b, 0x20, 0x01, 0x20, 0x05, 0x6B)
	b = append(b, 0x20, 0x07, 0x41, 0x08, 0x6A)
	b = append(b, 0x10)
	b = utils.AppendULEB128(b, uint32(captureFuncIdx))
	b = append(b, 0x21, 0x08)

	// if r < 0: br $done
	b = append(b, 0x20, 0x08, 0x41, 0x00, 0x48, 0x0D, 0x01)

	// Adjust each of numGroups*2 slot ints at recBase+8+g*4 by +pos (skip
	// unmatched groups, encoded as -1).
	for g := 0; g < numGroups*2; g++ {
		off := uint32(8 + g*4)
		b = append(b, 0x20, 0x07)
		b = append(b, 0x28, 0x02)
		b = utils.AppendULEB128(b, off)
		b = append(b, 0x22, 0x09) // tee slotVal
		b = append(b, 0x41, 0x00, 0x4E)
		b = append(b, 0x04, 0x40) // if (void)
		b = append(b, 0x20, 0x07)
		b = append(b, 0x20, 0x09, 0x20, 0x05, 0x6A)
		b = append(b, 0x36, 0x02)
		b = utils.AppendULEB128(b, off)
		b = append(b, 0x0B) // end if
	}

	// Copy the (now-adjusted) whole-match slot0/slot1 into the record's
	// start/end prefix.
	b = append(b, 0x20, 0x07, 0x20, 0x07, 0x28, 0x02, 0x08, 0x36, 0x02, 0x00)
	b = append(b, 0x20, 0x07, 0x20, 0x07, 0x28, 0x02, 0x0C, 0x36, 0x02, 0x04)

	// count += 1
	b = append(b, 0x20, 0x06, 0x41, 0x01, 0x6A, 0x21, 0x06)

	// pos = adjEnd > adjStart ? adjEnd : adjStart + 1, reading the
	// already-adjusted, absolute start/end just written to the record
	// header at recBase+0/recBase+4 (see doc comment: zero-length matches
	// are possible on the general native-anchored path, not just the
	// guaranteed-non-empty lit-chain one).
	b = append(b, 0x20, 0x07, 0x28, 0x02, 0x04) // adjEnd = mem32[recBase+4]
	b = append(b, 0x20, 0x07, 0x28, 0x02, 0x00) // adjStart = mem32[recBase+0]
	b = append(b, 0x4B)                         // i32.gt_u
	b = append(b, 0x04, 0x7F)                   // if (result i32)
	b = append(b, 0x20, 0x07, 0x28, 0x02, 0x04)
	b = append(b, 0x05) // else
	b = append(b, 0x20, 0x07, 0x28, 0x02, 0x00, 0x41, 0x01, 0x6A)
	b = append(b, 0x0B) // end if
	b = append(b, 0x21, 0x05)

	b = append(b, 0x0C, 0x00) // br $L (continue)
	b = append(b, 0x0B)       // end loop
	b = append(b, 0x0B)       // end block $done

	b = append(b, 0x20, 0x06) // return count
	b = append(b, 0x0B)       // end function
	return b
}

// appendBatchLitChainGroupsWrapperCodeEntry appends a size-prefixed Path B
// batch groups wrapper body to cs.
func appendBatchLitChainGroupsWrapperCodeEntry(cs []byte, captureFuncIdx, numGroups int) []byte {
	body := buildBatchLitChainGroupsWrapperBody(captureFuncIdx, numGroups)
	cs = utils.AppendULEB128(cs, uint32(len(body)))
	return append(cs, body...)
}

// appendNamedGroupsWrapperCodeEntry appends a size-prefixed named-groups wrapper body to cs.
// The wrapper calls groupsFuncIdx (the groups wrapper) and maps numbered slot pairs
// to named output slots using compile-time constants from groupNames.
// groupNames[i] is the name for capture group i+1 (empty = unnamed, skip).
//
// Signature: (ptr i32, len i32, out_ptr i32) → i32
//
// The named-groups out_ptr layout is identical to groups out_ptr — the stub
// uses the name→index mapping to present results by name to callers.
// This function is a thin pass-through: it calls the groups wrapper and returns
// its result unchanged; named group mapping is handled entirely in the stub.
func appendNamedGroupsWrapperCodeEntry(cs []byte, groupsFuncIdx int) []byte {
	// Body: call groupsFuncIdx(ptr, len, out_ptr), return result.
	var b []byte
	b = append(b, 0x00)       // 0 local declarations
	b = append(b, 0x20, 0x00) // local.get ptr
	b = append(b, 0x20, 0x01) // local.get len
	b = append(b, 0x20, 0x02) // local.get out_ptr
	b = append(b, 0x10)       // call
	b = utils.AppendULEB128(b, uint32(groupsFuncIdx))
	b = append(b, 0x0B) // end
	cs = utils.AppendULEB128(cs, uint32(len(b)))
	return append(cs, b...)
}
