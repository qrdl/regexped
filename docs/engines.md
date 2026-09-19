# Regexp Engines

Regexped implements four engines: **Compiled DFA**, **DFA**, **TDFA**, and **Backtracking**. The right engine is selected automatically at compile time based on the pattern and the requested function types.

---

## Engine Selection

Selection priority (highest first):

1. **TDFA** — pattern has capture groups AND qualifies for tagged-DFA (no non-greedy quantifiers, no line anchors, no word boundaries, no ambiguous alternations) AND TDFA has ≤ `MaxDFAStates` states AND ≤ `MaxTDFARegs` registers
2. **Backtracking** — pattern has capture groups but fails the TDFA check
3. **Compiled DFA** — no captures; minimised DFA has ≤ 256 states (default threshold)
4. **DFA** — no captures; minimised DFA ≤ `MaxDFAStates` states
5. **Backtracking** — no captures; DFA exceeds `MaxDFAStates` (fallback for match/find)

A pattern qualifies for TDFA if it has no:
- Non-greedy quantifiers (`*?`, `+?`, `??`) anywhere in the pattern
- Line anchors (`^`, `$`) anywhere in the pattern
- Word boundaries (`\b`, `\B`) anywhere in the pattern
- Ambiguous alternations — see below

**"Ambiguous alternation" is narrower than "any alternation with overlapping
branches."** The disjoint-first-character requirement only applies to
*genuine* user alternations (a real `|` between two separately captured
branches, e.g. `((cat)|(car))`, where each branch's own capture prevents
factoring out the shared `ca` prefix — not `(a|ab)c`, which Go's own
regexp/syntax parser normalises into a disjoint form before it ever reaches
engine selection). A user alternation nested inside a quantifier loop, e.g.
`(cat|car)+`, is still checked in full since the `|` itself is a separate
`InstAlt` from the loop's own back-edge — it's TDFA-eligible here too, but
because `cat`/`car` are still distinguishable by their second byte, not
because of the quantifier-loop relaxation described next. A quantifier
loop's own back-edge (e.g. the `+` in `[a-z]+`) is *also* internally an
alternation between "continue the loop" and "exit," but overlap between
those two branches alone no longer disqualifies TDFA (2026-08-01) — TDFA's
LeftmostFirst priority always prefers continuing the loop over exiting it,
so `([a-z]+)(er)([a-z]+)` now selects TDFA even though the loop's exit
(into `er`) starts with a byte the loop's own class also matches. It used
to select Backtracking before this fix, which also corrected a real
register-copy-ordering bug that this pattern shape had been triggering (see
[Register minimization and copy ordering](#register-minimization-and-copy-ordering)
below). The one case that still disqualifies a quantifier loop regardless
of overlap: either branch's first-byte set is *indeterminate* — e.g. an
inverted class wider than 256 codepoints (`[^>]`, `.`) — because TDFA can't
resolve "continue or exit" without knowing what the loop's exit needs.

If a pattern has captures but fails the TDFA check (e.g. `<([^>]+)>`,
`([^,]+),`, `(.*)(foo)` — all disqualified by the indeterminate-branch rule
above, not by mere overlap), the Backtracking engine is used automatically.

---

## Compiled DFA Engine

**Used for:** `match_func`, `find_func`, and the DFA component of groups modules, when the minimised DFA fits within the compiled-DFA threshold (default: 256 states).

**Complexity:** O(n) time.

### How it works

Like the DFA engine, the NFA is converted to a minimised DFA via subset construction and Hopcroft's algorithm. The difference is in how the transition table is indexed and what optimisations are applied on top.

The compiled path uses **pure table-driven transitions** — the same DFA table layout as the regular DFA engine — but with two differences that improve performance for small DFAs:

**1. Direct-index table access (no row deduplication, no `br_table`)**

For uncompressed tables (small DFAs where `numStates × 256 ≤ 32 KB`):

```
// Hybrid uncompressed transition step:
state = table[tableOff + (state << 8) + mem[ptr + pos]]   // shift instead of multiply
```

For compressed tables (larger DFAs where the table would exceed 32 KB, byte-class compression is applied):

```
// Hybrid compressed transition step:
class = classMap[mem[ptr + pos]]                          // 1 load: byte → equivalence class
state = table[tableOff + state * numClasses + class]      // 1 load: next state
```

Row deduplication (used by the regular DFA engine to collapse identical transition rows behind a rowMap) is explicitly **disabled** for the compiled path. The compiled path indexes directly into the full `numStates × stride` table, so the extra indirection level would add cost with no benefit for small DFAs.

**2. Literal-chain prefix optimisation (match mode only)**

If the DFA's start state has a unique sequence of unambiguous single-byte transitions from state 0 (i.e. each state in the chain has exactly one live outgoing byte), those transitions are emitted as hardcoded inline byte comparisons in the WASM function body rather than table lookups:

```
// Emitted once at function entry for a 3-byte literal chain "foo":
if pos + 3 > len: return -1
if mem[ptr + pos] != 'f': return -1;  pos++
if mem[ptr + pos] != 'o': return -1;  pos++
if mem[ptr + pos] != 'o': return -1;  pos++
state = <state after "foo">           // compile-time constant
// now enter the main table-driven loop
```

This eliminates table lookups entirely for the mandatory literal prefix and allows an early-exit check (`pos + chain_len > len → return -1`) that skips the loop for inputs that are too short.

### Design note

An earlier iteration used a two-level `br_table` dispatch that embedded all next-state values as WASM bytecode immediates and eliminated the transition table entirely. In benchmarks `br_table` was slower than table lookups due to branch misprediction costs in Cranelift's JIT — the table approach keeps the hot state value in a register and accesses L1-cached data, while `br_table` on many-entry dispatch creates unpredictable indirect branches. The hybrid approach was adopted as a result.

### When it is used

The hybrid path is activated when:
- the minimised DFA has ≤ the compiled-DFA threshold WASM states (default 256, hard ceiling 256)
- state IDs fit in a u8 (implied by the ≤ 256 limit)
- applies to match, find, and the DFA scan component of groups modules

The threshold can be adjusted (including disabled with a negative value) via `CompileOptions.CompiledDFAThreshold`. This field is not exposed in the YAML config — it is an internal knob for benchmarking and programmatic use.

---

## DFA Engine

**Used for:** `match_func`, `find_func`, and as the DFA half of hybrid modules (match/find alongside groups).

**Complexity:** O(n) time, O(states × 256) space.

### How it works

The NFA produced from the pattern is converted to a DFA via subset construction. Each DFA state represents a set of simultaneously active NFA states. On each input byte, the DFA makes exactly one state transition.

**LeftmostFirst semantics** (RE2/Perl): during epsilon closure, NFA states are sorted by program-counter priority (lower PC = higher priority). This gives leftmost-first match semantics for alternations and correct non-greedy quantifier handling via `immediateAccepting` states — the DFA stops as soon as an accepting state is reached rather than seeking a longer match.

**Word boundaries** (`\b`, `\B`): the state space is doubled with a `prevWasWord` context bit. Two mid-start states (`midStart`, `midStartWord`) are used in find-mode scan loops; a `wordCharTable` data segment provides O(1) byte classification.

**DFA minimization** (Hopcroft's algorithm): after subset construction, equivalent states — states indistinguishable from any starting point — are merged. This reduces state count and table size for complex patterns such as case-insensitive URL regexps, where many states differ only in how they were reached.

### Table formats

State IDs fit in u8 when ≤ 256 states, u16 otherwise. When the table would exceed 32 KB, byte-class compression is applied: many bytes share identical transition rows and are mapped to a smaller set of equivalence classes, shrinking the table significantly. For u16 DFAs, row deduplication is additionally applied: states with identical transition rows share one row via a u8 rowMap, dramatically reducing large tables (e.g. 512KB → 52KB for a 1000-state DFA with 100 unique rows).

Find mode stores additional arrays alongside the transition table: `midAccept` (accepting states reachable mid-scan), `firstByteFlags`/Teddy/Shufti nibble tables (for the SIMD prefix scan), `immediateAccept`, and word-boundary variants.

**Anchor-aware find mode**: when a pattern is anchored at the start (e.g. `^foo.*$`), `midStartState` has no live transitions. In this case a simplified find body is emitted that runs the DFA exactly once from position 0 rather than scanning the input.

### SIMD prefix scan and mandatory literal extraction

In find mode, a compile-time-selected fast-skip prologue avoids testing every byte position. Two mechanisms are used:

**1. Prefix/Teddy scan** (applied when the match must start at the scan position):

| Strategy | Condition |
|---|---|
| **Hybrid prefix** | literal prefix ≥ 1 byte — SIMD check for full prefix within a 16-byte window |
| **Teddy (1/2/3/4-byte tiers)** | 1–8 first-byte candidates; tier picked by how many leading bytes are jointly selective (nibble-table SIMD lookup per tier) |
| **Shufti** | 9–16 first-byte candidates (unconditional), or 17–64 (only when a byte-rarity heuristic predicts it beats scalar, or the pattern was compiled with `hints: [prefer-no-match]`, which forces it regardless of the heuristic) — nibble-table SIMD set-membership test over the candidate set itself, not per-candidate comparisons |
| **Scalar** | 0 first-byte candidates, > 64 candidates, or a 17–64-candidate set the rarity heuristic predicts scalar wins for |

Every Teddy tier promotion (1-byte → 2-byte → 3-byte → 4-byte) additionally
requires that **no** first-byte candidate's next byte lead to a
terminal/dead-end state — a candidate with no further live transitions
after its first byte disqualifies the whole tier and the builder falls back
to the tier below (fixed 2026-07-26; previously this could
silently build an all-zero nibble table and produce wrong scan results for
shorter alternates in a mixed-length alternation).

The 17–64-candidate Shufti path also has a **runtime adaptive fallback**:
if the compile-time rarity heuristic guessed wrong and Shufti is running
against unexpectedly dense match data, the scan self-disables back to
scalar after a bounded number of unproductive attempts, so a wrong guess
only costs a bounded amount rather than paying Shufti's fixed per-chunk
cost for the rest of the input.

**2. Mandatory literal extraction** (applied when the prefix is noisy but a selective literal exists deeper in the pattern): `FindMandatoryLit` analyzes the pattern's syntax tree to find the best fixed byte sequence that must appear in every match (e.g. `://` in `[a-zA-Z]{2,8}://[^\s]+`). The SIMD scan searches for that literal instead; a two-level outer loop (`$lit_outer` / `$outer`) adjusts candidate start positions using the literal's known min/max offset from the match start.

Both mechanisms use WASM SIMD (simd128).

### Literal-anchored find

When a pattern's mandatory literal is at least 2 bytes long (up to 8 byte-alternating variants), the compiler may emit a three-phase find body that is substantially faster than scanning every start position with the full DFA.

**Conditions for activation:**
- find mode (`find_func` requested)
- u8 DFA (≤ 256 states, no word boundaries)
- a qualifying mandatory literal exists: ASCII, length ≥ 2, at most 8 alternates
- the reversed-prefix DFA has ≤ 256 states
- for non-anchored patterns: the reversed-prefix DFA start state does not accept the empty string

**Three-phase runtime execution:**

```
Phase 1 — SIMD scan for the literal set
  (Teddy / multi-eq / scalar, same as standard prefix scan)
  candidate position → literal byte k found at attempt_start

  Post-Teddy scalar verification (if literal > 2 bytes):
    check all bytes of each literal variant at attempt_start
    mismatch on all variants → attempt_start++, back to Phase 1

Phase 2 — Backward DFA scan
  reversed-prefix DFA runs right-to-left from attempt_start-1
  finds the furthest-left position where the prefix matches
  result: rev_result = match start candidate (or -1 → skip to next Phase 1 hit)

Phase 3 — Forward DFA scan
  full leftmost-first DFA starts at rev_result
  runs forward to find the match end
  match: return (rev_result << 32 | match_end)
  no match: attempt_start++, back to Phase 1
```

**Why it is faster than a standard find scan:**

The SIMD scan in Phase 1 typically eliminates ≥ 99% of input positions before any DFA runs — the mandatory literal is rare. The backward DFA in Phase 2 is compiled from the prefix sub-pattern only (typically a handful of states) and runs in reverse for a bounded short distance. The forward DFA in Phase 3 runs from a known candidate start rather than trying every position. The combination avoids the outer DFA loop over all start positions entirely.

**Memory layout** (additional tables placed after the main DFA table):
```
[main LF DFA table] → [reversed-prefix DFA table] → [literal SIMD tables (firstByteFlags / Teddy T0 / Teddy T1)]
```

---

## TDFA Engine (Tagged DFA)

**Used for:** `groups_func` — O(n) capture tracking for patterns that qualify.

**State limit:** the TDFA state count is bounded at compile time (default 1024; adjustable via `CompileOptions.MaxDFAStates`). The register count is also bounded (default 32; adjustable via `CompileOptions.MaxTDFARegs`). Patterns exceeding either limit fall back to Backtracking.

**Complexity:** O(n) time.

### How it works

TDFA implements Laurikari's tagged DFA algorithm. The NFA is extended with "tag" operations that record input positions at capture group boundaries. Subset construction then builds a DFA whose transitions carry register operations — at each transition, one or more WASM locals (registers) are updated to record the current input position or copy from another register.

**Tag operations** on a transition are one of:
- `reg = pos` — record the current input position (an `i32` WASM local)
- `reg = other_reg` — copy (register reconciliation on loop back-edges)

Capture slot values are reconstructed from registers at match acceptance time. The WASM function signature is `(ptr i32, len i32, out_ptr i32) → i32`; output slots are written as `[start0, end0, start1, end1, ...]` at `out_ptr`.

**TDFA eligibility:** TDFA is used when the pattern has no non-greedy quantifiers, no line anchors (`^`/`$`), no word boundaries, and no ambiguous alternations — see [Engine Selection](#engine-selection) above for what "ambiguous" actually excludes (it's narrower than "any alternation with overlapping branches"). Patterns that fail any of these checks use the Backtracking engine instead.

**Whole-match single-capture shortcut:** when a pattern's only capture group spans the entire match (e.g. `(foo.*bar)`), both TDFA and Backtracking skip re-walking the capture body after the scan — the single group's bounds are just the match's own start/end, so no tag ops or capture-tracking NFA pass are needed at all.

#### Register minimization and copy ordering

**Register minimization:** after table construction, a liveness-based graph-coloring pass merges registers whose live ranges do not overlap, reducing WASM local count.

**Copy ordering (`sequentializeCopies`):** when a transition has more than one register-to-register copy tag op, they must take effect as one atomic parallel assignment — every copy reads its source's value from *before* the transition, never a value an earlier copy in the same batch already overwrote. A single fixed emission order (e.g. always descending by destination register) only produces correct results for copy chains that happen to run in that direction; a chain running the other way silently reads an already-clobbered value. `sequentializeCopies` instead walks the actual destination→source dependency graph, emitting each copy only once nothing else still pending needs to read its destination first, and breaks any remaining dependency cycle by spilling one copy through a scratch register. This fixed a real capture-corruption bug (2026-08-01) that patterns like `([a-z]+)(er)([a-z]+)` had been triggering.

**Tag-op emission:** each DFA state's per-byte tag operations are emitted as a `br_table` dispatch in the WASM function body. A majority-group optimization encodes only the minority of differing transitions explicitly; the dominant operation is emitted unconditionally, keeping WASM bytecode size small.



---

## Backtracking Engine (BitState)

**Used for:** `groups_func` when the pattern has captures but is not TDFA-eligible; and `match_func`, `find_func` when the DFA exceeds `MaxDFAStates` states (default 1024).

**Complexity:** every call is bounded by the [work budget](#work-budget-and-the-fallback-body): linear work in the fast body before it either finishes or hands over, then O(numInstructions × inputLen) in the memoised fallback body. Space is the fast body's compile-time stack (plus its bitset, where it needs one); a call that outgrows either is answered by the fallback, whose stack and bitset are sized from the input at call time. The answer is `-2` (unknown) only when linear memory cannot grow far enough for them — never a hang.

### How it works

The NFA is emitted as a WASM `br_table` dispatch loop. Each NFA instruction maps to a handler block. The engine maintains a backtrack stack in WASM linear memory: when an `InstAlt` node is reached, the alternative branch is pushed onto the stack and execution continues with the preferred branch. On failure the stack is popped to try the alternative.

**Stack layout:** each frame stores the saved input position, all capture slots, and the retry program counter. Frame size = `4 + numGroups × 2 × 4 + 4` bytes. The fast body's stack is reserved at compile time in WASM linear memory immediately after the DFA tables.

**Stack overflow guard:** before each frame push, the engine checks `sp + frameSize > stackLimit`. If the limit is exceeded, the fast body hands the call to its [fallback body](#work-budget-and-the-fallback-body) rather than corrupting memory; with the budget off it returns the `-2` sentinel instead — see the next section.

### Frame budget and the `-2` sentinel

The fast body's backtrack stack is sized **at compile time**:

```
maxFrames = max(numAlts × 4096, 4096)      # numAlts = InstAlt count in the NFA
frameSize = 4 + numGroups × 2 × 4 + 4      # + 4 per loop_pos/loop_entry tracker
stackSize = maxFrames × frameSize
```

The real requirement, however, scales with **input length**: a pattern that leaves one live backtrack frame per input byte exhausts a `numAlts × 4096` budget once the input passes that many bytes. So the ceiling is a function of the input, not just the pattern, and no compile-time check can predict it.

When that stack runs out, the fast body does not give up: it arms its work budget to trip on the next frame pop, and the trip hands the call to the fallback body, whose stack grows with the input (see [Work budget and the fallback body](#work-budget-and-the-fallback-body)). Only a build with `compile.BTWorkBudgetOff` still stops at this ceiling.

The engine gives up only when it cannot get the memory a search needs — the fallback's linear memory cannot grow any further (WASM32's 4 GiB, or a lower limit the host set), or, with the budget off, a compile-time region ran out. It has then abandoned part of the search space and **does not know** whether the input matches, so it returns a distinct sentinel:

| value | meaning |
|---|---|
| `-1` | the input does not match — an ordinary, reliable answer |
| `-2` | the engine ran out of memory for the search; the result is **unknown**, not "no match" |

`-2` is returned by every export shape that can host a Backtracking body: `match_func`, `find_func` (as `i64 -2`), `groups_func`, and the `_batch` variants — for the batch exports as a negative count, since a successful call always returns a count ≥ 0. Wrapper functions propagate it instead of folding it into their own "negative means no match" test.

**Which patterns fill the compile-time stack.** The frame has to survive input being consumed, which means an untried *alternation* branch, not merely a quantifier: after `ab` matches in `(?:ab|cd)*?x`, the frame holding "try `cd` here instead" stays live. A non-greedy loop on its own does not accumulate, because its preferred branch fails against the next byte and the frame is popped straight back. The alternation must also survive `regexp/syntax` simplification — `a|b` becomes the char class `[ab]` and `aa|ab` is factored to `a[ab]`, and neither leaves an `InstAlt` to push a frame for. Before this sentinel existed, crossing the ceiling returned `-1`, an input-length-dependent false negative with no diagnostic; today it costs a call the fallback's run, not its answer.

**Host behaviour.** Generated stubs must surface `-2` as an error, never as "no match":

| stub | behaviour |
|---|---|
| Rust | `Err(Error::BacktrackOverflow)` — the iterators put it on the item and are fused |
| Go | an `error` return; `Err()` after the loop for the lazy iterators |
| JS, TS | `throw` |
| C, AssemblyScript | return the sentinel: `RX_ERR_BT_OVERFLOW`, or `RX_ITER_ERROR` where a pointer return has no negative value to spend |

Each is that **language's own** way of saying "this call cannot be answered". Two shapes that look inconsistent across languages are correct if each is right at home.

Rust and Go used to panic. A panic unwinding out of an FFI wrapper is a poor fit for the contexts this library targets — under `panic = "abort"` it is a hard process abort — and both languages report failure by returning it.

AssemblyScript used to be grouped with JS/TS as "throw", and that was **wrong**. Verified against this repo's own `asc` (0.28.13): `try`/`catch` is rejected outright ("ERROR AS100: Not implemented: Exceptions"), and a `throw` compiles to a call to the imported `abort` — a one-way trap the AS caller cannot handle. A throw there was strictly worse than a sentinel, not equivalent to one. JS and TS are unaffected: exceptions are real, catchable, and the normal error channel.

C is unchanged. It has no unwinding, and its return types were already integer error codes with a documented negative case.

**`match_any` used to swallow it** in every language, folding `-2` into "no match". It reports it now.

The NARROW `match_all` / `scan_all` do **not** test for it, and must not: their
`i64` return IS the bitmask, so every 64-bit value is a legal answer. `-2` is
`0xFFFF_FFFF_FFFF_FFFE` — ids 1..63 matched and id 0 did not — which a
sentinel test would report as an engine failure on a perfectly good result.
The real sentinel cannot reach that form at all: a set with a Backtracking
member is compiled to the WIDE `_all` ABI, where the return is a COUNT and
`-2` is unambiguous.

**Beyond the ceiling.** The fallback body's stack grows at run time, so a pattern that fills the fast body's stack keeps getting answers on arbitrarily long input, up to what linear memory can hold. What such a call costs is the fallback's run and its memory; to avoid paying it, shorten the input or restructure the pattern so fewer alternation frames stay live.

Note the contrast with the **compile-time** ceilings (`ErrBTStackTooLarge`, `ErrBTProgramTooLarge`, and the program size cap below), which have always been reported as typed errors. This is the runtime counterpart, and it was the only one that used to be silent.

### Program size cap

The Backtracking engine's WASM emission is `br_table`-based with one case per NFA instruction, so emitted module size scales roughly linearly with the NFA program's instruction count (`len(prog.Inst)` after `regexp/syntax` compilation) — a confirmed pathological pattern (a large literal byte run repeated under an unbounded quantifier) produced a 123,695-instruction program and a 7,966,121-byte module, exceeding wasmtime's own ~7,654,321-byte function-body-size limit and failing to load at runtime.

Every construction site that can route to Backtracking — the no-capture find/match fallback (taken when the primary DFA is rejected as too large), the capture-tracking fallback (taken when a capture pattern is not TDFA-eligible), and the general engine-executor path (`Compile`/`CompileForced`/`SelectEngine` callers, including explicit `ForceEngine: EngineBacktrack`) — checks `len(prog.Inst)` against `maxBTFallbackInstructions` (20,000) before emitting any WASM. Exceeding the cap fails compilation with a clear error (`errBTProgramTooLarge`) instead of silently producing an oversized module that only fails once a WASM runtime tries to load it. The 20,000 threshold assumes a 3x-worse bytes/instruction ratio than the confirmed repro, targeting a worst-case module size comfortably under wasmtime's limit — real-world patterns are nowhere near it; hand-written patterns typically compile to tens or low hundreds of NFA instructions, so the cap only rejects pathological inputs (e.g. fuzzer-generated giant literal runs), not practical usage.

### BitState memoization

Memoization is only enabled when the pattern contains a **non-greedy loop whose body can match zero bytes** — the condition checked by `needsBitState`. Patterns like `(a+)*` or `(?:b*)*` do not need it; patterns like `(?:(?:(a){0,})*?)` do, because the inner loop body can succeed without consuming input, causing the engine to revisit the same `(state, position)` pair infinitely.

When enabled, before executing a non-greedy loop head (`InstAlt` with a backward edge), the engine checks a `(pc, pos)` visited bitset stored in WASM linear memory immediately after the backtrack stack:

```
bitIndex  = pos * numInstructions + pc
byteAddr  = memoTableBase + bitIndex / 8
bit       = 1 << (bitIndex & 7)
```

If the bit is already set, the current thread is discarded — it cannot produce a new result. Otherwise the bit is set and execution continues. This guarantees each `(pc, pos)` pair is visited at most once, bounding runtime to O(numInstructions × inputLen).

The index is **position-major**: all `numInstructions` bits belonging to one input position are adjacent. That is what keeps the clear cheap. The bytes a single search dirties are then one contiguous run from the base of the bitset, and each call zeroes exactly the run the previous call recorded in a 4-byte header word stored immediately below the bitset — rather than a region sized from the input. For a body called once per candidate position (a set's Backtracking bucket) an input-sized clear made the whole scan quadratic; this makes it linear.

In the fast body the bitset's addressable size is `ceil(numInstructions × (inputLen + 1) / 8)` bytes, bounded by the actual input length, while the region reserved for it is a compile-time 128 KB. The two therefore meet at a ceiling:

```
maxInputLen = 128 KB × 8 / numInstructions − 1
```

An input longer than that cannot be memoised in the space reserved, so the fast body hands the call to its [fallback body](#work-budget-and-the-fallback-body), which sizes its own bitset from the input, instead of running the fill past its region. With `compile.BTWorkBudgetOff` it reports `-2` (the same "resource exhausted, answer unknown" sentinel as a backtrack-stack overflow) instead. The ceiling scales inversely with the pattern's instruction count: a 25-instruction pattern memoises inputs up to about 42 KB in the fast body, a 250-instruction one about 4 KB.

The two ceilings — this one and the frame stack — move independently, with `numInstructions` and with `numAlts` respectively, so either can be the one a given pattern and input hits first.

#### What the ceiling is measured against

Past the ceiling the fast body hands over (or, with the budget off, answers `-2`,
which means *the engine did not finish*, never *no match*). Which **length** is
compared against the ceiling differs per body, because each searches a different
span:

| Body | Length compared against the ceiling |
|---|---|
| Anchored `match` | The whole input. |
| Non-anchored `find` | The **remainder**, `len − from`. The memo is rebased onto `from`, so a host iterating a long buffer keeps getting answers as `from` advances. |
| `groups` capture body | The narrowed match extent, or in window mode the window's own length — not the whole input. |
| A set's Backtracking bucket | The span from the candidate position to the end of the input. This is the one case where a long input can pass the ceiling at every candidate; it is bounded by the input, not by the match. |

Two further properties are worth relying on:

* The check happens at the head of the **first attempt**, not at the head of the
  call. A call whose prefilter finds no candidate — no mandatory literal
  anywhere, or no byte that can begin a match — answers `-1` without ever
  consulting the memo, however long the input is.
* Only patterns that need memoisation in the fast body are affected.
  `needsBitState` is narrow: a non-greedy loop whose body can match zero bytes.
  The [fallback body](#work-budget-and-the-fallback-body) memoises every
  program, but reserves nothing at compile time and has no such ceiling.

The levers on how often a call crosses the ceiling are the pattern's instruction
count (the ceiling scales inversely with it) and `CompileOptions.MemoBudget`,
which is not reachable from YAML.

**Memory layout:**
```
[DFA find tables] → [backtrack stack] → [4-byte dirty header] → [BitState memo bitset]
```
All regions are page-aligned and strictly non-overlapping. The input buffer is placed at address 0 by the host and never overlaps with the tables region. The fallback body's run-time memory lies outside all of them; see [Where the fallback's memory comes from](#where-the-fallbacks-memory-comes-from).

**Thread safety:** the memo bitset is allocated at a fixed compile-time address, and the fallback's scratch is found through module globals. Single-threaded use only — concurrent calls on the same module instance would race on both.

### Work budget and the fallback body

**The problem it solves.** A backtracker without memoisation is exponential
whenever a loop can split the same input more than one way, and walks every
split before it fails. Two measured shapes: `^(\w*|)*c` — a loop whose body can
match empty through an alternation branch — over word characters with no `c`
took 3 ms at 12 bytes, 783 ms at 22, and never returned at 40; `^(aa|a)*b` —
overlapping branches in a loop whose body always consumes — took 238 ms over
`a`×32 and never returned at 40. Neither existing bound stops them:

* the zero-progress guard does not fire, because every iteration DOES consume
  bytes;
* the frame budget is not exhausted, because the stack is popped as the search
  goes;
* BitState memoization cannot simply be switched on for the loop. The
  zero-progress guard works by noticing a SECOND arrival at the same
  `(pc, pos)`; a visited bitset forbids that arrival. With both in place,
  `(?:a*|b*)*` over `"b"` answers `end=1` instead of `end=0`: the memo cuts the
  revisit the guard was waiting for, and control falls through to the
  lower-priority `b*` branch.

**How it is bounded.** Every Backtracking program is emitted as TWO functions
(with one exception, below):

1. **The fast body** is the ordinary body plus one `i64` counter, set once per
   call to `(span + 1) × 8 × numInstructions` and decremented on every frame
   POP. `span` is the input length, or the window length when a capture body
   runs in window mode. A call that never backtracks pays nothing for it.
2. **The fallback body** has the same signature and contract, and is what the
   fast body TAIL-CALLS when the counter reaches zero — or when the fast body's
   compile-time frame stack or memo runs out, which arms the counter to trip on
   the next pop or calls the fallback directly. It is the same emitter over the
   same program with no loop heads, no loop trackers and a `(pc, pos)` visited
   bitset at EVERY alternation — Go `regexp`'s bitstate discipline. It restarts
   the call from scratch on the caller's own arguments and globals, and sizes
   its own frame stack and bitset from the input at call time.

Why the fallback is correct: without the loop trackers, `(pc, pos)` is the
program's complete state — the NFA has no return addresses — so the first
arrival at a `(pc, pos)` explores every path out of it in priority order. If one
succeeds the call returns; so a second arrival can only follow a first that
failed, and cutting it loses nothing. Checking only at alternations is enough:
between them the path is deterministic. Why it terminates: every cycle in the
program passes through an alternation, and each alternation is entered at a
given position at most once per call.

**A program with a zero-width cycle gets no ordinary body.** If the program can
go round a cycle without consuming a byte — `^(\w*|)*c`, `(a*?)*?b`, anything
whose loop body can match empty — its fast body is nothing but the tail call,
so the fallback answers every call. The loop trackers that let the ordinary body
cope with such a cycle only approximate Go's rule that a second arrival at an
occupied `(pc, pos)` is dropped, and the approximation is wrong on a whole
class: `(a*?)*?b` over `aab` reported group 1 as `1-2` where Go says `0-2`,
because the outer loop's empty iteration re-entered the inner star
at position 1 and queued a second attempt ahead of the first. A differential
against Go found the ordinary body wrong on 306 of 3,072 systematic nestings and
159 of 12,000 random nested patterns, every one with such a cycle; the fallback
was right on all of them. Without such a cycle a `(pc, pos)` is reached again
only after its first visit has failed, so the ordinary body is exact.

Why counting pops bounds time: every loop iteration passes through an
alternation, which either pushes a frame or takes a guard exit, and a guard exit
cannot repeat without a pop in between. At most `numInstructions × (loops + 1)`
instructions separate two push or pop events, so a fast call does linear work
before it either finishes or trips.

**Why every program, not just the empty-body loop.** The budget was first given
only to programs with an empty-body loop, on the premise that the zero-progress
guard bounds every other one. `^(aa|a)*b` refuted that: it selects Backtracking
(the branches overlap, so TDFA is ineligible), its loop body always consumes a
byte, and it hung. No syntactic rule for "can blow up" is known to be complete,
so there is none. With the budget it answers in about 60 µs over `a`×40.

**What it costs** (`groups_func`, standalone; "off" is the same program compiled
with `compile.BTWorkBudgetOff`, the bytes from before the budget existed).

`^(aa|a)*b` has no zero-width cycle, so it keeps its ordinary body and the
budget:

| | off | on |
|---|---|---|
| module size | 1,676 bytes | 2,809 bytes |
| linear memory reserved | 262,144 bytes | 262,144 bytes — the fallback reserves nothing |
| matching call, `a`×4000 + `b` | 74.0 fuel/byte | 74.0 fuel/byte |
| no-match call, `a`×40 | never returned | 11,534 fuel/byte, answered |
| no-match call, `a`×4000 | never returned | 11,266 fuel/byte, answered |
| same call, fallback body alone | — | 318 fuel/byte |
| matching call, `a`×16,378 + `b` (fast stack full) | `-2` | 132 fuel/byte, answered, +576 KB memory |

`^(\w*|)*c` has one, so every budgeted build answers it with the fallback alone:

| | off | on |
|---|---|---|
| module size | 2,057 bytes | 2,711 bytes |
| linear memory reserved | 720,896 bytes | 65,536 bytes — no ordinary body, so no compile-time stack or memo |
| matching call, `w`×4000 + `c` | 107.4 fuel/byte | 115.3 fuel/byte |
| no-match call, `w`×4000 | never returned | 434 fuel/byte, answered |
| matching call, `w`×16,378 + `c` | `-2` | 115.1 fuel/byte, answered, +576 KB memory |
| matching call, `w`×1,000,000 + `c` | `-2` | 115.0 fuel/byte, answered, +34 MB memory |
| no-match call, `w`×1,000,000 | `-2` | 434 fuel/byte, answered, +34 MB memory |

A call that trips on its budget pays for the budget it burned before the
fallback starts: on the `a`×4000 no-match row that is roughly 35× what the
fallback alone would cost. The multiplier 8 is the lever if trips turn out to be
common. A call that fills the fast body's stack instead hands over as soon as it
does, so its extra cost is the depth it reached — the 132 fuel/byte row is the
fast body's descent plus the fallback's whole run.

#### Where the fallback's memory comes from

The fallback sizes its memory at the head of the call — a find body at its first
attempt, so a call with no candidate never touches it — from the span the search
covers (the input, the window, or `len − from` for a find):

```
base       = scratch base (below)
memo       = (span + 1) × ceil(numInstructions / 8) bytes, one row per position
stack      = everything from the end of the memo to the end of memory,
             doubled with memory.grow whenever a push needs more
```

A memo row is whole bytes, so a bit's position within its byte is a
compile-time constant and no bit index can overflow `i32` before memory runs
out. The memo is not cleared up front: the region may hold a previous call's
bits, and zeroing all of it would touch every page of a worst-case region.
Rows are position-major, so every byte a search has touched lies below the
highest row it has reached, and a visit past the zeroed stretch zeroes the next
4 KB first.

Where `base` is depends on who owns the memory:

| output | scratch base |
|---|---|
| embedded (merged) | the end of the module's tables — its memory is its own, so the region is reused call after call |
| component | `cabi_realloc`'s heap top — the fallback runs inside a call, above every block the allocator has handed out |
| standalone | the higher of the exported `regexped:scratch_base` global and the end of the tables; the host keeps the global above everything it uses. At `0` — a host that does not know it — fresh pages at the end of memory on every call |

The standalone contract, and why a JavaScript host must re-read
`memory.buffer` after a call, are in [wasm.md](wasm.md) "The Backtracking
scratch base". A second, module-private memory would have needed no protocol,
and was rejected because Safari supports only one memory per module.

**In a set.** A set's Backtracking member is called once per candidate
position, each call searching to the end of the input, so the three things
above are kept per member for a whole call to the set capability instead of
per candidate: one work budget, drawn down across the candidates (once it
trips, later candidates skip the fast body); one scratch region, placed at the
member's first fallback call above any other member's; and the visited set in
it, which a later candidate may cut on because a `(pc, pos)` that failed fails
for every candidate. The visited set is reset whenever the member matches — an
attempt that matched leaves marks that are not failures. Every exported set
capability bumps a call counter on entry, which is how a member tells a new call
from its next candidate. Without this, one call over `a`×4000 matching none of
`(\w*|)*c`, `(aa|a)*b` and `bar[0-9]+` cost 110,272,726,505 fuel and grew memory
by 7,984 pages with the host global at 0; with it, 58,597,434 fuel and one page.

`-2` remains only where memory cannot grow: the memo must fit below WASM32's
4 GiB (`numInstructions × inputLen / 8` bytes, so a 20,000-instruction program
over a 1.7 MB input is already too much), and the stack must fit beside it, or
the host has set a lower limit.

**Knobs.** `CompileOptions.BTWorkBudget` and `CompileSetOptions.BTWorkBudget`,
neither reachable from YAML: `0` is the default multiplier of 8, a positive
value replaces it, `compile.BTWorkBudgetOff` emits neither counter nor fallback
(the bytes from before the budget existed), and
`compile.BTWorkBudgetForceFallback` reduces every fast body to the bare tail
call, so the fallback alone answers — sizing its memory at call time on every
call.
That last one is a test knob: re2test's `--bt-fallback-always` drives the whole
corpus through it, and `tools/fuzz`'s `FuzzGroupsBothBodies` checks the fast
body alone, the fallback alone and the two together against Go.

---

## Hybrid Modules

When a config entry sets both `match_func`/`find_func` AND `groups_func`, a single WASM module is generated containing both a DFA function (match and/or find) and a groups function (TDFA or Backtracking depending on the pattern), sharing the same memory region.

---

## Semantics

Regexped implements **RE2 syntax with Perl/RE2 semantics** (leftmost-first match, non-greedy quantifiers prefer shorter matches). POSIX semantics (leftmost-longest) are not supported.

### Bytes, not codepoints

Every engine here operates on **bytes**. `.` consumes one byte, a character
class is a byte class, `\b` is ASCII, and a table row is indexed by a byte
value. There is no UTF-8 decoding step anywhere in the pipeline.

This is a deliberate design point rather than a missing feature, and it has two
visible consequences.

**A pattern naming a rune above U+007F is a compile error** unless the entry
sets [`byte_mode: true`](cli.md#byte_mode--matching-raw-bytes-above-127), which
declares runes `0x80`-`0xFF` to mean those bytes. Runes above `U+00FF` are
rejected in both modes. Before this gate existed, such patterns compiled and
the automaton silently truncated the rune to a byte — `[a-zé]+` over `"zzé"`
returned `[0,2)` where Go returns `[0,4)`.

**Two things are still byte-semantic by declaration**, because no gate can
separate them from ordinary ASCII patterns:

- `.` and negated classes match one byte, so `a.c` does not match `"aéc"`
  (Go, decoding UTF-8, does).
- Case folding stays inside the byte range. `(?i)k` does not match a Kelvin
  sign and `(?i:[a-z]+)` does not match a long s, because Go's parser
  manufactures those runes from the ASCII the pattern actually wrote, and
  rejecting them would reject `(?i)` over any letter class.

If your input is UTF-8 and your pattern is ASCII, none of this is visible: an
ASCII byte never appears inside a multi-byte UTF-8 sequence, so a byte-oriented
match over UTF-8 text finds exactly what a codepoint-oriented one would.

---

## RE2 Test Coverage

The RE2 exhaustive test suite (`tools/re2test/`) reports:

- **~4.94M passing** (DFA + Compiled DFA; match and find)
- **~4.94M passing** (Backtracking engine forced via `--force-backtrack`; match and find)
- **~1.88M passing** (re2-adjusted.txt with `--validate-groups`; includes TDFA and Backtracking capture accuracy)
- **~781K skipped** (exhaustive only)

**Exhaustive test** (`re2-exhaustive.txt`, match/find only):

| Engine | Passing cases |
|---|---|
| DFA | ~334K |
| Compiled DFA | ~4.6M |
| **Total** | **~4.94M** |

**Exhaustive test** (`re2-exhaustive.txt`, match/find, `--force-backtrack`):

| Engine | Passing cases |
|---|---|
| Backtracking | ~4.94M |
| **Total** | **~4.94M** |

**Adjusted test** (`re2-adjusted.txt`, with `--validate-groups`):

| Engine | Passing cases |
|---|---|
| DFA | ~360K |
| Compiled DFA | ~1.2M |
| TDFA | ~41K |
| Backtracking | ~267K |
| **Total** | **~1.88M** |

Skipped cases (exhaustive only):

| Reason | Approximate count |
|---|---|
| Unicode support not implemented | ~270K |
| Unsupported `\C` syntax | ~511K |

The previously-skipped non-deterministic capture category (~251K) is now covered by the Backtracking engine. The remaining skipped categories (Unicode and `\C`) are architectural limitations unrelated to engine selection.

---

## Future

**Unicode support** — expanding character class handling to full Unicode code-point ranges. Currently all engines operate on byte (ASCII) input only.
