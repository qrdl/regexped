# Regex Engines

Regexped implements three engines: **DFA**, **OnePass**, and **Backtracking**. The right engine is selected automatically at compile time based on the pattern and the requested function types.

---

## Engine Selection

Selection priority (highest first):

1. **OnePass** — pattern has capture groups AND qualifies for one-pass determinism
2. **Backtracking** — pattern has capture groups but fails the OnePass check
3. **DFA** — all other patterns (captures are stripped when only `match_func`/`find_func` are requested)

A pattern qualifies for OnePass if:
- Every `|` alternation has branches with disjoint first-character sets (deterministic at each position)
- No nested or non-greedy quantifiers inside capture groups
- Pattern compiles to ≤ 100 NFA instructions

If a pattern has captures but fails the OnePass check (e.g. `(a|ab)c`, `(a*)(a*)`, `(.*)(foo)`), the Backtracking engine is used automatically.

---

## DFA Engine

**Used for:** `match_func`, `find_func`, and as the DFA half of hybrid modules (match/find alongside groups).

**Complexity:** O(n) time, O(states × 256) space.

### How it works

The NFA produced from the pattern is converted to a DFA via subset construction. Each DFA state represents a set of simultaneously active NFA states. On each input byte, the DFA makes exactly one state transition.

**LeftmostFirst semantics** (RE2/Perl): during epsilon closure, NFA states are sorted by program-counter priority (lower PC = higher priority). This gives leftmost-first match semantics for alternations and correct non-greedy quantifier handling via `immediateAccepting` states — the DFA stops as soon as an accepting state is reached rather than seeking a longer match.

**Word boundaries** (`\b`, `\B`): the state space is doubled with a `prevWasWord` context bit. Two mid-start states (`midStart`, `midStartWord`) are used in find-mode scan loops; a `wordCharTable` data segment provides O(1) byte classification.

**DFA minimization** (Hopcroft's algorithm): after subset construction, equivalent states — states indistinguishable from any starting point — are merged. This reduces state count and table size for complex patterns such as case-insensitive URL regexes, where many states differ only in how they were reached.

### Table formats

State IDs fit in u8 when ≤ 256 states, u16 otherwise. When the table would exceed 32 KB, byte-class compression is applied: many bytes share identical transition rows and are mapped to a smaller set of equivalence classes, shrinking the table significantly. For u16 DFAs, row deduplication is additionally applied: states with identical transition rows share one row via a u8 rowMap, dramatically reducing large tables (e.g. 512KB → 52KB for a 1000-state DFA with 100 unique rows).

Find mode stores additional arrays alongside the transition table: `midAccept` (accepting states reachable mid-scan), `firstByteFlags` or Teddy nibble tables (for the SIMD prefix scan), `immediateAccept`, and word-boundary variants.

**Anchor-aware find mode**: when a pattern is anchored at the start (e.g. `^foo.*$`), `midStartState` has no live transitions. In this case a simplified find body is emitted that runs the DFA exactly once from position 0 rather than scanning the input.

### SIMD prefix scan and mandatory literal extraction

In find mode, a compile-time-selected fast-skip prologue avoids testing every byte position. Two mechanisms are used:

**1. Prefix/Teddy scan** (applied when the match must start at the scan position):

| Strategy | Condition |
|---|---|
| **Hybrid prefix** | literal prefix ≥ 1 byte — SIMD check for full prefix within a 16-byte window |
| **3-byte Teddy** | alternation patterns with ≤ 8 first bytes AND selective 3rd byte |
| **2-byte Teddy** | alternation patterns with ≤ 8 first bytes |
| **1-byte Teddy** | single-byte prefix with multiple candidates |
| **Multi-eq SIMD** | small first-byte set — `i8x16.eq` + bitmask per candidate |
| **Scalar** | fallback for wide first-byte sets |

**2. Mandatory literal extraction** (applied when the prefix is noisy but a selective literal exists deeper in the pattern): `FindMandatoryLit` analyzes the pattern's syntax tree to find the best fixed byte sequence that must appear in every match (e.g. `://` in `[a-zA-Z]{2,8}://[^\s]+`). The SIMD scan searches for that literal instead; a two-level outer loop (`$lit_outer` / `$outer`) adjusts candidate start positions using the literal's known min/max offset from the match start.

Both mechanisms use WASM SIMD (simd128).

---

## OnePass Engine

**Used for:** `groups_func`, `named_groups_func`, and as the groups half of hybrid modules when the pattern is OnePass-eligible.

**Complexity:** O(n) time and space (single forward pass, no thread copying).

### How it works

A pattern is OnePass-eligible when at every position in the input exactly one NFA thread can be active. This means every `|` alternation has branches that begin with disjoint character sets — the automaton can always determine which branch to follow from a single byte without exploring alternatives.

Under this condition, capture groups can be tracked with a fixed set of slot registers updated inline as bytes are consumed. No thread copying (PikeVM), no backtracking stack, and no speculative work.

The OnePass automaton is a u8 transition table (`state × byte → next_state`, 0xFF = dead). Capture slot updates (`open group N`, `close group N`) are emitted as compile-time-known `i32.store` instructions directly in the WASM function body — they are not stored in the table.

---

## Backtracking Engine (BitState)

**Used for:** `groups_func`, `named_groups_func` when the pattern has captures but is not OnePass-eligible, and as the groups half of hybrid modules for such patterns.

**Complexity:** O(n × numStates) time and space — guaranteed by BitState memoization (see below).

### How it works

The NFA is emitted as a WASM `br_table` dispatch loop. Each NFA instruction maps to a handler block. The engine maintains a backtrack stack in WASM linear memory: when an `InstAlt` node is reached, the alternative branch is pushed onto the stack and execution continues with the preferred branch. On failure the stack is popped to try the alternative.

**BitState memoization:** before executing any NFA state at a given input position, the engine checks a `(pc, position)` visited bitset. If the `(state, pos)` pair was already visited, the current thread is immediately discarded — it cannot produce a result not already covered by a previous thread. This prevents infinite loops on patterns with nested zero-matching quantifiers (e.g. `(?:(?:(a){0,})*?)`) and guarantees O(n × numStates) worst-case execution.

The bitset is stored in WASM linear memory immediately after the backtrack stack. Its size is `ceil(numInstructions × (inputLen + 1) / 8)` bytes computed at runtime. It is zero-initialised at the start of each match call. For inputs exceeding `maxMemoLen` (8192 chars), memoization is skipped and the engine falls back to stack-bounded backtracking.

**Limitation:** the memoization bitset is allocated at a fixed compile-time address in the module's linear memory. This is safe for single-threaded WASM (the standard). The WebAssembly threads proposal (Phase 3) would allow shared-memory parallelism, but this is not supported — calling the same pattern's groups function from two concurrent threads would cause a data race on the memo table. Single-threaded use is the only supported mode.

**Stack layout:** each frame stores the saved input position, all capture slots, and the retry program counter. Frame size = `4 + numGroups × 2 × 4 + 4` bytes. Stack is reserved at compile time in WASM linear memory immediately after the DFA tables.

**Stack overflow guard:** before each frame push, the engine checks `sp + frameSize > stackLimit`. If the limit is exceeded, execution returns -1 (no match) rather than corrupting memory.

**Memory layout:**
```
[DFA find tables] → [backtrack stack] → [BitState memo bitset]
```
All regions are page-aligned and strictly non-overlapping. The input buffer is placed at address 0 by the host and never overlaps with the tables region.

---

## Hybrid Modules

When a config entry sets both `match_func`/`find_func` AND `groups_func`/`named_groups_func`, a single WASM module is generated containing both a DFA function (match and/or find) and a groups function (OnePass or Backtracking depending on the pattern), sharing the same memory region.

---

## Semantics

Regexped implements **RE2 syntax with Perl/RE2 semantics** (leftmost-first match, non-greedy quantifiers prefer shorter matches). POSIX semantics (leftmost-longest) are not supported.

---

## RE2 Test Coverage

The RE2 exhaustive test suite (`re2test/`) reports:

- **~4.94M passing** (DFA + OnePass + Backtracking)
- **~781K skipped**

| Engine | Passing cases |
|---|---|
| DFA | ~4.76M |
| OnePass | ~52K |
| Backtracking | ~120K |

Skipped cases:

| Reason | Approximate count |
|---|---|
| Unicode support not implemented | ~270K |
| Unsupported `\C` syntax | ~511K |

The previously-skipped non-deterministic capture category (~251K) is now covered by the Backtracking engine. The remaining skipped categories (Unicode and `\C`) are architectural limitations unrelated to engine selection.

---

## Future

**Unicode support** — expanding character class handling to full Unicode code-point ranges. Currently all engines operate on byte (ASCII) input only.
