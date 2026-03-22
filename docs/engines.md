# Regex Engines

Regexped currently implements two engines: **DFA** and **OnePass**. The right engine is selected automatically at compile time based on the pattern and the requested function types.

---

## Engine Selection

Selection priority (highest first):

1. **OnePass** — pattern has capture groups AND qualifies for one-pass determinism
2. **DFA** — all other patterns (captures are stripped when only `match_func`/`find_func` are requested)

A pattern qualifies for OnePass if:
- Every `|` alternation has branches with disjoint first-character sets (deterministic at each position)
- No nested or non-greedy quantifiers inside capture groups
- Pattern compiles to ≤ 100 NFA instructions

---

## DFA Engine

**Used for:** `match_func`, `find_func`, and as the DFA half of hybrid modules (match/find alongside groups).

**Complexity:** O(n) time, O(states × 256) space.

### How it works

The NFA produced from the pattern is converted to a DFA via subset construction. Each DFA state represents a set of simultaneously active NFA states. On each input byte, the DFA makes exactly one state transition.

**LeftmostFirst semantics** (RE2/Perl): during epsilon closure, NFA states are sorted by program-counter priority (lower PC = higher priority). This gives leftmost-first match semantics for alternations and correct non-greedy quantifier handling via `immediateAccepting` states — the DFA stops as soon as an accepting state is reached rather than seeking a longer match.

**Word boundaries** (`\b`, `\B`): the state space is doubled with a `prevWasWord` context bit. Two mid-start states (`midStart`, `midStartWord`) are used in find-mode scan loops; a `wordCharTable` data segment provides O(1) byte classification.

### Table formats

State IDs fit in u8 when ≤ 256 states, u16 otherwise. When the table would exceed 32 KB, byte-class compression is applied: many bytes share identical transition rows and are mapped to a smaller set of equivalence classes, shrinking the table significantly.

Find mode stores additional arrays alongside the transition table: `midAccept` (accepting states reachable mid-scan), `firstByteFlags` or Teddy nibble tables (for the SIMD prefix scan), `immediateAccept`, and word-boundary variants.

### SIMD prefix scan

In find mode, a compile-time-selected fast-skip prologue avoids testing every byte position:

| Strategy | Condition |
|---|---|
| **2-byte Teddy** | literal prefix ≥ 2 bytes — checks two bytes simultaneously, near-zero false positives |
| **1-byte Teddy** | single-byte prefix with multiple candidates |
| **Multi-eq SIMD** | small first-byte set — `i8x16.eq` + bitmask per candidate |
| **Scalar** | fallback for wide first-byte sets |

Uses WASM SIMD (simd128).

---

## OnePass Engine

**Used for:** `groups_func`, `named_groups_func`, and as the groups half of hybrid modules.

**Complexity:** O(n) time and space (single forward pass, no thread copying).

### How it works

A pattern is OnePass-eligible when at every position in the input exactly one NFA thread can be active. This means every `|` alternation has branches that begin with disjoint character sets — the automaton can always determine which branch to follow from a single byte without exploring alternatives.

Under this condition, capture groups can be tracked with a fixed set of slot registers updated inline as bytes are consumed. No thread copying (PikeVM), no backtracking stack, and no speculative work.

The OnePass automaton is a u8 transition table (`state × byte → next_state`, 0xFF = dead). Capture slot updates (`open group N`, `close group N`) are emitted as compile-time-known `i32.store` instructions directly in the WASM function body — they are not stored in the table.

### Limitations

OnePass is strictly more restrictive than a general capture engine. Patterns with ambiguous alternations (e.g. `(a|ab)c`) are not OnePass-eligible and currently cannot be compiled with capture tracking.

---

## Hybrid Modules

When a config entry sets both `match_func`/`find_func` AND `groups_func`/`named_groups_func`, a single WASM module is generated containing both a DFA function (match and/or find) and a OnePass function (groups), sharing the same memory region.

---

## RE2 Test Coverage

The RE2 exhaustive test suite (`re2test/`) currently reports approximately:

- **~4.68M passing** (DFA + OnePass)
- **~1.03M skipped**

Skipped cases break down as:

| Reason | Approximate count |
|---|---|
| Unicode support not implemented | ~270K |
| Unsupported `\C` syntax | ~511K |
| Non-deterministic captures (not OnePass-eligible) | ~251K |

---

## Future: Backtracking Engine

The largest recoverable skip category is **non-deterministic captures** (~251K cases) — patterns with capture groups that cannot be handled by the OnePass engine because their alternations have overlapping first-character sets. Examples: `(a|ab)`, `(.*)(\w+)`, `(a+)(a*)`.

These require a general capture engine. The planned approach is a **backtracking engine** targeting WASM:

- Implements RE2-compatible leftmost-first capture semantics
- Uses an explicit stack in WASM linear memory (no host call stack)
- Activated when a pattern has captures but fails the `isOnePass` check
- Bounded by a configurable step limit to prevent worst-case O(2ⁿ) blowup on adversarial inputs (matching RE2's safety model)

With a backtracking engine, the remaining ~251K skipped capture-group cases would pass, bringing total RE2 coverage to approximately **~4.93M** passing cases (excluding Unicode and `\C`).

The Unicode skip category (~270K) would require a separate Unicode mode that expands character classes to full code-point ranges — a significant table size increase, considered separately.
