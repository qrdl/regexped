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
those two branches alone no longer disqualifies TDFA (task 13, 2026-08-01) — TDFA's
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
to the tier below (fixed in task 43, 2026-07-26; previously this could
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

**Used for:** `groups_func`, `named_groups_func` — O(n) capture tracking for patterns that qualify.

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

**Copy ordering (`sequentializeCopies`):** when a transition has more than one register-to-register copy tag op, they must take effect as one atomic parallel assignment — every copy reads its source's value from *before* the transition, never a value an earlier copy in the same batch already overwrote. A single fixed emission order (e.g. always descending by destination register) only produces correct results for copy chains that happen to run in that direction; a chain running the other way silently reads an already-clobbered value. `sequentializeCopies` instead walks the actual destination→source dependency graph, emitting each copy only once nothing else still pending needs to read its destination first, and breaks any remaining dependency cycle by spilling one copy through a scratch register. This fixed a real capture-corruption bug (task 13, 2026-08-01) that patterns like `([a-z]+)(er)([a-z]+)` had been triggering.

**Tag-op emission:** each DFA state's per-byte tag operations are emitted as a `br_table` dispatch in the WASM function body. A majority-group optimization encodes only the minority of differing transitions explicitly; the dominant operation is emitted unconditionally, keeping WASM bytecode size small.



---

## Backtracking Engine (BitState)

**Used for:** `groups_func`, `named_groups_func` when the pattern has captures but is not TDFA-eligible; and `match_func`, `find_func` when the DFA exceeds `MaxDFAStates` states (default 1024).

**Complexity:** O(n × inputLen) time and space — guaranteed by BitState memoization when enabled (see below).

### How it works

The NFA is emitted as a WASM `br_table` dispatch loop. Each NFA instruction maps to a handler block. The engine maintains a backtrack stack in WASM linear memory: when an `InstAlt` node is reached, the alternative branch is pushed onto the stack and execution continues with the preferred branch. On failure the stack is popped to try the alternative.

**Stack layout:** each frame stores the saved input position, all capture slots, and the retry program counter. Frame size = `4 + numGroups × 2 × 4 + 4` bytes. Stack is reserved at compile time in WASM linear memory immediately after the DFA tables.

**Stack overflow guard:** before each frame push, the engine checks `sp + frameSize > stackLimit`. If the limit is exceeded, execution returns the `-2` stack-overflow sentinel rather than corrupting memory — see the next section.

### Frame budget and the `-2` sentinel

The backtrack stack is sized **at compile time**:

```
maxFrames = max(numAlts × 4096, 4096)      # numAlts = InstAlt count in the NFA
frameSize = 4 + numGroups × 2 × 4 + 4      # + 4 per loop_pos/loop_entry tracker
stackSize = maxFrames × frameSize
```

The real requirement, however, scales with **input length**: a pattern that leaves one live backtrack frame per input byte exhausts a `numAlts × 4096` budget once the input passes that many bytes. So the ceiling is a function of the input, not just the pattern, and no compile-time check can predict it.

When the budget runs out the engine has abandoned part of the search space and **does not know** whether the input matches. It therefore returns a distinct sentinel:

| value | meaning |
|---|---|
| `-1` | the input does not match — an ordinary, reliable answer |
| `-2` | the frame budget was exhausted; the result is **unknown**, not "no match" |

`-2` is returned by every export shape that can host a Backtracking body: `match_func`, `find_func` (as `i64 -2`), `groups_func`, `named_groups_func`, and the `_batch` variants — for the batch exports as a negative count, since a successful call always returns a count ≥ 0. Wrapper functions propagate it instead of folding it into their own "negative means no match" test.

**Which patterns can reach it.** The frame has to survive input being consumed, which means an untried *alternation* branch, not merely a quantifier: after `ab` matches in `(?:ab|cd)*?x`, the frame holding "try `cd` here instead" stays live. A non-greedy loop on its own does not accumulate, because its preferred branch fails against the next byte and the frame is popped straight back. The alternation must also survive `regexp/syntax` simplification — `a|b` becomes the char class `[ab]` and `aa|ab` is factored to `a[ab]`, and neither leaves an `InstAlt` to push a frame for. This combination is why the ceiling is rarely hit in practice, and why it went unnoticed: before this sentinel existed, crossing it returned `-1`, an input-length-dependent false negative with no diagnostic.

**Host behaviour.** Generated stubs must surface `-2` as an error, never as "no match":

| stub | behaviour |
|---|---|
| Rust, Go | panic |
| JS, TS, AssemblyScript | throw |
| C | returns the sentinel: `RX_ERR_BT_OVERFLOW` from a match function, `{RX_ERR_BT_OVERFLOW, RX_ERR_BT_OVERFLOW}` from a find function, `NULL` from a groups function |

C differs because it has no unwinding, and its return types already carry integer error codes. The other languages' public types (`Option<usize>`, `(int, bool)`, generators) have no room for a third outcome, so an unwind is the only way to keep the distinction without redesigning every signature.

**Raising the ceiling.** There is no runtime knob today. The options are to shorten the input, restructure the pattern so fewer alternation frames stay live, or make the engine grow its stack at runtime — the last being the only fix that makes such a pattern work on arbitrarily long input, and it is not implemented.

Note the contrast with the **compile-time** ceilings (`ErrBTStackTooLarge`, `ErrBTProgramTooLarge`, and the program size cap below), which have always been reported as typed errors. This is the runtime counterpart, and it was the only one that used to be silent.

### Program size cap

The Backtracking engine's WASM emission is `br_table`-based with one case per NFA instruction, so emitted module size scales roughly linearly with the NFA program's instruction count (`len(prog.Inst)` after `regexp/syntax` compilation) — a confirmed pathological pattern (a large literal byte run repeated under an unbounded quantifier) produced a 123,695-instruction program and a 7,966,121-byte module, exceeding wasmtime's own ~7,654,321-byte function-body-size limit and failing to load at runtime.

Every construction site that can route to Backtracking — the no-capture find/match fallback (taken when the primary DFA is rejected as too large), the capture-tracking fallback (taken when a capture pattern is not TDFA-eligible), and the general engine-executor path (`Compile`/`CompileForced`/`SelectEngine` callers, including explicit `ForceEngine: EngineBacktrack`) — checks `len(prog.Inst)` against `maxBTFallbackInstructions` (20,000) before emitting any WASM. Exceeding the cap fails compilation with a clear error (`errBTProgramTooLarge`) instead of silently producing an oversized module that only fails once a WASM runtime tries to load it. The 20,000 threshold assumes a 3x-worse bytes/instruction ratio than the confirmed repro, targeting a worst-case module size comfortably under wasmtime's limit — real-world patterns are nowhere near it; hand-written patterns typically compile to tens or low hundreds of NFA instructions, so the cap only rejects pathological inputs (e.g. fuzzer-generated giant literal runs), not practical usage.

### BitState memoization

Memoization is only enabled when the pattern contains a **non-greedy loop whose body can match zero bytes** — the condition checked by `needsBitState`. Patterns like `(a+)*` or `(?:b*)*` do not need it; patterns like `(?:(?:(a){0,})*?)` do, because the inner loop body can succeed without consuming input, causing the engine to revisit the same `(state, position)` pair infinitely.

When enabled, before executing a non-greedy loop head (`InstAlt` with a backward edge), the engine checks a `(pc, pos)` visited bitset stored in WASM linear memory immediately after the backtrack stack:

```
bitIndex  = pc * (inputLen + 1) + pos
byteAddr  = memoTableBase + bitIndex / 8
bit       = 1 << (bitIndex & 7)
```

If the bit is already set, the current thread is discarded — it cannot produce a new result. Otherwise the bit is set and execution continues. This guarantees each `(pc, pos)` pair is visited at most once, bounding runtime to O(numInstructions × inputLen).

The bitset is zero-initialised at the start of each call. Its size is `ceil(numInstructions × (inputLen + 1) / 8)` bytes, computed at runtime from the actual input length. A compile-time budget of 128 KB is reserved in WASM linear memory for the bitset; the memory region is placed last in the layout so longer inputs consume only unused space.

**Memory layout:**
```
[DFA find tables] → [backtrack stack] → [BitState memo bitset]
```
All regions are page-aligned and strictly non-overlapping. The input buffer is placed at address 0 by the host and never overlaps with the tables region.

**Thread safety:** the memo bitset is allocated at a fixed compile-time address. Single-threaded use only — concurrent calls on the same module instance would race on the bitset.

---

## Hybrid Modules

When a config entry sets both `match_func`/`find_func` AND `groups_func`/`named_groups_func`, a single WASM module is generated containing both a DFA function (match and/or find) and a groups function (TDFA or Backtracking depending on the pattern), sharing the same memory region.

---

## Semantics

Regexped implements **RE2 syntax with Perl/RE2 semantics** (leftmost-first match, non-greedy quantifiers prefer shorter matches). POSIX semantics (leftmost-longest) are not supported.

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
