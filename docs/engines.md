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

### Which find a pattern gets: linear on every input

Both find bodies above try start positions one at a time. That is fast on
ordinary text, but some shapes make it **quadratic** on a long run of bytes
that keeps an attempt alive without ever matching: `a*b` over `a`×N (every
attempt walks to the end), `\w+@\w+` over one long word, `\w+abc\d` over
`abc`×N. At 64 KB that is billions of instructions for a single `find`.

The fix is a second find, the **start-anywhere find** (RE2's method), which is
linear on every input:

- a **forward pass** walks the leftmost-first DFA of `(?s:.)*?(?:pat)` once from
  `from`; its last accept is the END of the leftmost-first match;
- a **backward pass** walks the reversed pattern, leftmost-longest, from that
  end back down to `from`; the lowest position it accepts at is the match's
  START.

For a pattern with an empty-width assertion (`\b`, `\B`, `^`, `$`, `\A`, `\z`,
`(?m:^)`, `(?m:$)`) both passes read the whole input rather than a slice
starting at `from`, so every assertion is judged against the real neighbouring
bytes: the forward pass picks the state it starts in from the byte before
`from`, and the backward pass walks the pattern reversed with its assertions
mirrored (`\b` and `\B` unchanged, `^`↔`$`, `\A`↔`\z`, `(?m:^)`↔`(?m:$)`),
judging each against the byte on the far side of the position — below `from`
included.

Its cost, measured at 64 KB over the find test corpus's 29 shapes, each on its
worst-case run, on prose, and on every two-byte alternation of its own bytes
that does not match: the forward pass costs about 29 instructions per byte,
except in a state that loops on nearly every byte — typically one waiting for a
byte that can begin or continue a match, as in `a*b`, `.*foo\d` or
`foo[a-z]+bar` over text without those bytes. Runs in such a state are crossed
with the SIMD bulk skip the ordinary DFA bodies use, at 1.6-4 instructions per
byte; input that enters and leaves the state on every byte costs up to 52
instead (`ERROR\w*y|WARN\w*z` over ` E`×N). A pattern opening with a word-class
repeat (`\w+@\w+`) has no such state on prose and stays at 29. The passes for
a pattern with an assertion cost 34-45. It also walks each match twice, where
the ordinary find costs 1-8 on text its SIMD skip can leap over — so it is not
a replacement. The compiler picks per pattern, at compile time:

| Pattern | Find |
|---|---|
| provably linear: a failed attempt walks a bounded number of bytes (no reachable cycle on which it keeps going without accepting and from which it can still end that way — an accept an assertion conditions counts only where its condition can hold); or, without an assertion, both find-body shape detectors apply, or for a literal-anchored find neither the part before the literal nor the part after it can contain it | the ordinary find, unchanged |
| anchored at 0 | the ordinary find |
| starts with an unbounded repeat of a class common in prose, without the space byte and with no literal to scan for (`\w+@\w+`, `[a-z]+[0-9]{3}`) | the start-anywhere find alone — the ordinary one costs 100+ per byte on such patterns even on ordinary text. `prefer-match` picks the switch, which keeps the ordinary find |
| starts with such a repeat that includes the space byte (`[^,]*,`) | the switch (below); `prefer-no-match` picks the start-anywhere find alone |
| anything else not provably linear, with or without a hint | the **switch** |

**The switch** is the ordinary find plus a work counter, with the start-anywhere
find beside it. The counter adds up the bytes walked by attempts that FAILED;
once that exceeds `4 × (bytes advanced since from) + 64`, the call hands the
rest of the search to the start-anywhere find, resuming just past the last
failed start (or from `from`, for the literal-anchored bodies, whose failed
candidates do not prove every earlier start matchless). The counter is checked
before the current attempt's walk is added, so one long failed walk — which is
linear — does not trip it; the second one does. A failed attempt that walked
32 bytes or fewer is not counted at all: most failed attempts die within a byte
or two, and uncounted work is at most 32 bytes per start position, which is
linear. Ordinary text never trips it,
so it costs what the ordinary find costs plus 0-6%. The literal-anchored
bodies also charge a FAILED backward walk: their backward walker records where
it stopped. On a worst-case run the ordinary body walks the run about twice
before the counter trips, so the switch costs more there than the start-anywhere
find alone: 42-137 instructions per byte on the corpus's switch shapes at 64 KB
(`a*b` over `a`×N: 67.6), against 1.6-45 — linear either way.

The start-anywhere find needs its automata within `max_dfa_states` and the
memory bound, and able to represent every assertion exactly. Where they are
not, the switch hands over to the **Backtracking find** instead: the engine a
pattern whose DFA is too large gets, whose fallback body memoises every
(instruction, position) it tries, so it is linear per call too — slower, up to
236 instructions per byte on the one such corpus shape's worst-case run. The
start-anywhere find's two automata add their tables to the module, as any DFA's
do. `--verbose` reports the choice and the reason for every pattern
(`find: switch — not provably linear`, and `switch handover: Backtracking` with
its reason).

### Linear drives: notes kept for one search

A DRIVE is what a stub does with `find`: call it, resume past the answer, call
it again, until the input is exhausted. Every call above is linear, but a drive
can still be quadratic when a call walks past the match it reports and the
next call reads the same bytes again. `a*b|a` over `a`×N matches at every byte,
yet each call has to read to the end of the run before it may answer
`[p, p+1)` (a `b` there would make the match `[p, N+1)`), and the next call,
one byte on, reads the same run again: N matches cost about N²/2 bytes. Other
examples: `\d+px|\d` over a run of digits, `foo\w+bar|foo` over `foo`×N,
`a+?b|a`, `[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\s+Inc|[A-Z][a-z]+` over a long run
of capitalised words. Go's `regexp` behaves the same way (`FindAllIndex` for
`a*b|a` over 8 KB and 32 KB of `a`: 0.63 s and 10.3 s).

The fix keeps NOTES for one search, in a block the caller owns and hands over
with every call (see [wasm.md](wasm.md), "The search block"; every generated
stub does this). A walk that runs past its last accept and then dies has
proved, for every (state, position) it visited after that accept, that no
match lies ahead of there. That is a fact about the text, not about the call,
so a later call that reaches a noted (state, position) stops at once and
answers what the walk would have. Each point is noted once and hit once, so a
drive costs a constant per byte.

Only a search that has gone bad pays for the notes. A pattern whose find
automaton has a CYCLE STATE — a non-accepting state on a cycle of
non-accepting states, the only place an unboundedly long walk can sit without
accepting — carries two copies of its find:

- the **ordinary copy**, the find described above plus a waste counter in the
  block: the bytes read past each reported match, and the part of each failed
  read of more than 32 bytes that lies below the farthest position an earlier
  failed read of the search reached — the only part read twice. Once the waste
  exceeds `4 × (bytes the search has advanced) + 64`, the search is ARMED.
- the **marked copy**, the same body testing the notes at every byte of a
  cycle state and writing them by walking a wasted tail again. The stub
  allocates the notes (`(len + 1) ×` a few bytes) the first time it sees the
  search armed, and the marked copy serves the rest of the search.

A pattern with no cycle state gets no notes code at all, byte for byte.
Measured on this repository's real patterns: no cost on 85 of 151 drives (no
cycle state), a median of +0.1% on the rest and +5.2% at worst; the bad drives
above cost 130-382 instructions per byte, linear. A caller that passes no block
(0) to a STANDALONE module gets a default block the module keeps itself, which
carries over while the caller keeps driving the same text forward (see
[wasm.md](wasm.md), "Handing the block over"): `a*b|a` over `a`×8 K costs 474
instructions per byte that way. In a merged build a call with no block runs
exactly as described above and these drives stay quadratic; bounding the
higher-priority branch's repeat (`\d{1,10}px|\d`) keeps them linear without a
block. [complexity.md](complexity.md) gathers every mechanism of this kind.

Sets make the same choice per member, with one difference: see
[sets.md](sets.md#members-that-are-not-provably-linear).

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

**Complexity:** every call is bounded by the [work budget](#work-budget-and-the-fallback-body): linear work in the fast body before it either finishes or hands over, then O(numInstructions × inputLen) in the memoised fallback body. Space is the fast body's frame stack — claimed at call time and grown with the search for `groups_func`, reserved at compile time for `match_func` and `find_func`; a call that outgrows it is answered by the fallback, whose stack and bitset are sized from the input at call time. The answer is `-2` (unknown) only when linear memory cannot grow far enough for them — never a hang.

### How it works

The NFA is emitted as a WASM `br_table` dispatch loop. Each NFA instruction maps to a handler block. The engine maintains a backtrack stack in WASM linear memory: when an `InstAlt` node is reached, the alternative branch is pushed onto the stack and execution continues with the preferred branch. On failure the stack is popped to try the alternative.

**Stack layout:** each frame stores the saved input position, all capture slots, and the retry program counter. Frame size = `4 + numGroups × 2 × 4 + 4` bytes. Every body's stack — `match_func`, `find_func`, `groups_func` and a set's members — is claimed when a call starts, not reserved in the module — see [The frame stack](#the-frame-stack).

**Stack overflow guard:** before each frame push, the engine checks that the frame fits. If it does not, the body first grows memory; a body that cannot make room hands the call to its [fallback body](#work-budget-and-the-fallback-body) rather than corrupting memory; with the budget off it returns the `-2` sentinel instead — see the next sections.

### The frame stack

Backtracking bodies used to reserve their stacks in the module — `numAlts × 4096` frames, worked out from the pattern and claimed when the module loaded, whatever the input, and once per set in a set: a pattern with many branches claimed megabytes to match ten bytes, and a 339-set WAF configuration claimed 596 MB of its 643 MB before its first call. None reserves anything now. When a call starts, the stack is placed at the same scratch base as the fallback's memory (see [Where the fallback's memory comes from](#where-the-fallbacks-memory-comes-from)) and given a small starting size (64 KB), growing memory only if it does not already have that much; when a push does not fit, memory grows by the stack's current size, doubling it. The stack is the last thing in memory, so growing copies nothing, and memory never shrinks, so a call that fits in what an earlier call left never grows. Every body and every set uses the same scratch, so the memory a module ends up with is the largest any one search needed, not the sum over its patterns. When memory cannot grow, the body hands over to the fallback.

Inside a set, the members' fallback memos last a whole host call (see below), so a body run from a set starts its stack above every memo already placed in that call rather than at the base. Every exported entry of a set marks the start of a new call — a split set's `find` included, which can run a split member without calling the buckets at all — so a region placed in an earlier call, which the host may have reused since, is never taken for one of this call's.

### Frame budget and the `-2` sentinel

The stack a search needs scales with **input length**: a pattern that leaves one live backtrack frame per input byte needs one frame per byte. When the fast body's stack cannot grow, it does not give up: it arms its work budget to trip on the next frame pop, and the trip hands the call to the fallback body (see [Work budget and the fallback body](#work-budget-and-the-fallback-body)). Only a build with `compile.BTWorkBudgetOff`, a test knob, stops there.

The engine gives up only when it cannot get the memory a search needs — linear memory cannot grow any further (WASM32's 4 GiB, the config's [`max_memory`](cli.md#max_memory--a-cap-on-the-modules-memory), or a lower limit the host set), or, with the budget off, a fast body's stack could not grow. It has then abandoned part of the search space and **does not know** whether the input matches, so it returns a distinct sentinel:

| value | meaning |
|---|---|
| `-1` | the input does not match — an ordinary, reliable answer |
| `-2` | the engine ran out of memory for the search; the result is **unknown**, not "no match" |

`-2` is returned by every export shape that can host a Backtracking body: `match_func`, `find_func` (as `i64 -2`), `groups_func`, and the `_batch` variants — for the batch exports as a negative count, since a successful call always returns a count ≥ 0. Wrapper functions propagate it instead of folding it into their own "negative means no match" test.

**Which patterns grow the stack.** The frame has to survive input being consumed, which means an untried *alternation* branch, not merely a quantifier: after `ab` matches in `(?:ab|cd)*?x`, the frame holding "try `cd` here instead" stays live. A non-greedy loop on its own does not accumulate, because its preferred branch fails against the next byte and the frame is popped straight back. The alternation must also survive `regexp/syntax` simplification — `a|b` becomes the char class `[ab]` and `aa|ab` is factored to `a[ab]`, and neither leaves an `InstAlt` to push a frame for. Before this sentinel existed, crossing the module's then-fixed stack returned `-1`, an input-length-dependent false negative with no diagnostic; today the stack grows instead, and only memory that cannot grow hands the call to the fallback.

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

Only the [fallback body](#work-budget-and-the-fallback-body) memoises. At every alternation it checks a `(pc, pos)` visited bitset: if the bit is already set, the current thread is discarded — it cannot produce a new result; otherwise the bit is set and execution continues. Each `(pc, pos)` pair is visited at most once, bounding runtime to O(numInstructions × inputLen). The bitset is sized from the input at call time — see [Where the fallback's memory comes from](#where-the-fallbacks-memory-comes-from) — so it has no compile-time ceiling.

A find body shares its marks across the attempts of one call: it tracks no captures, so a `(pc, pos)` that failed from one start position fails from every start position. Its memo is rebased onto `from`, so a host iterating a long buffer pays for the remainder being searched, not for the whole buffer. A capture body cannot share them — its state includes the capture registers.

The ordinary (fast) body memoises nothing and carries **no loop guard**. It runs only programs without a zero-width cycle: in such a program every cycle consumes a byte, so a search terminates without one, and a `(pc, pos)` is reached again only after its first visit has failed. A program that can go round a cycle without consuming a byte — a loop whose body can match zero bytes, such as `(?:(?:(a){0,})*?)` — has no ordinary body at all (see below).

**Memory layout:**
```
[DFA find tables] → [backtrack stack]      # match_func / find_func; a groups_func stack is at the scratch base
```
All regions are page-aligned and strictly non-overlapping. The input buffer is placed at address 0 by the host and never overlaps with the tables region. The fallback body's run-time memory lies outside all of them; see [Where the fallback's memory comes from](#where-the-fallbacks-memory-comes-from).

**Thread safety:** a `match_func`/`find_func` backtrack stack is allocated at a fixed compile-time address, and a `groups_func` stack and the fallback's scratch are found through module globals. Single-threaded use only — concurrent calls on the same module instance would race on both.

### Work budget and the fallback body

**The problem it solves.** A backtracker without memoisation is exponential
whenever a loop can split the same input more than one way, and walks every
split before it fails. Two measured shapes: `^(\w*|)*c` — a loop whose body can
match empty through an alternation branch — over word characters with no `c`
took 3 ms at 12 bytes, 783 ms at 22, and never returned at 40; `^(aa|a)*b` —
overlapping branches in a loop whose body always consumes — took 238 ms over
`a`×32 and never returned at 40. The frame stack does not stop them: it is
popped as the search goes, so it is never exhausted.

**How it is bounded.** Every Backtracking program is emitted as TWO functions
(with one exception, below):

1. **The fast body** is the ordinary body plus one `i64` counter, set to
   `(span + 1) × numInstructions` and decremented on every frame POP. `span`
   is the input length, or the window length when a capture body runs in
   window mode. A `find` whose caller passes a search block (every generated
   stub does) gets the counter once per SEARCH and keeps what is left in the
   block, so a scan whose every call would burn it burns it once; otherwise it
   is set once per call (see "Per search" below). A call that never
   backtracks pays nothing for it. The multiplier was 8 until normal text was
   measured never to come near 1 (124 Backtracking patterns, 160 real-pattern
   drives: identical cost at 1, 2, 4, 8 and 16), while adversarial drives were
   41-85% cheaper at 1.
2. **The fallback body** has the same signature and contract, and is what the
   fast body TAIL-CALLS when the counter reaches zero — or when the fast body's
   frame stack runs out because memory cannot grow, which arms the counter to
   trip on the next pop — or, when not even the first frame fits and there is
   nothing to pop, hands over at once. It is the same emitter over the same program with a `(pc, pos)` visited
   bitset at EVERY alternation — Go `regexp`'s bitstate discipline. It restarts
   the call from scratch on the caller's own arguments and globals, and sizes
   its own frame stack and bitset from the input at call time.

Why the fallback is correct: `(pc, pos)` is the program's complete state — the NFA has no return addresses — so the first
arrival at a `(pc, pos)` explores every path out of it in priority order. If one
succeeds the call returns; so a second arrival can only follow a first that
failed, and cutting it loses nothing. Checking only at alternations is enough:
between them the path is deterministic. Why it terminates: every cycle in the
program passes through an alternation, and each alternation is entered at a
given position at most once per call.

**A program with a zero-width cycle gets no ordinary body.** If the program can
go round a cycle without consuming a byte — `^(\w*|)*c`, `(a*?)*?b`, anything
whose loop body can match empty — its fast body is nothing but the tail call,
so the fallback answers every call, under every budget setting,
`compile.BTWorkBudgetOff` included: the ordinary body has no loop guard, so it
could go round such a cycle forever. It used to carry per-loop zero-progress
trackers for these programs instead. They only approximated Go's rule that a
second arrival at an occupied `(pc, pos)` is dropped, and the approximation was
wrong on a whole class: `(a*?)*?b` over `aab` reported group 1 as `1-2` where Go says `0-2`,
because the outer loop's empty iteration re-entered the inner star
at position 1 and queued a second attempt ahead of the first. A differential
against Go found the ordinary body wrong on 306 of 3,072 systematic nestings and
159 of 12,000 random nested patterns, every one with such a cycle; the fallback
was right on all of them. On every other program the trackers could never
change an answer — without such a cycle a `(pc, pos)` is reached again only
after its first visit has failed — and they were deleted. On `tools/perftest`'s
Backtracking rows that took 0.7–5.3% off the fuel of the four measurements that
moved and 38–213 bytes off four modules; the other rows did not change.

Why counting pops bounds time: every cycle in the program passes through an
alternation, and in the fast body every alternation pushes a frame, so at most
`numInstructions` instructions separate two push or pop events and a fast call
does linear work before it either finishes or trips.

**Why every program, not just the empty-body loop.** The budget was first given
only to programs with an empty-body loop, on the premise that the zero-progress
guard the ordinary body then carried bounded every other one. `^(aa|a)*b` refuted that: it selects Backtracking
(the branches overlap, so TDFA is ineligible), its loop body always consumes a
byte, and it hung. No syntactic rule for "can blow up" is known to be complete,
so there is none. With the budget it answers in about 60 µs over `a`×40.

**What it costs** (`groups_func`, standalone; measured when the budget was
introduced, while the ordinary body still carried its loop trackers — "off" is
the same program compiled with the budget off, which then gave every program,
`^(\w*|)*c` included, the ordinary body alone).

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

`^(\w*|)*c` has one, so every build now answers it with the fallback alone —
the "off" column below is the ordinary body it no longer has:

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
fallback alone would cost (measured at the old multiplier of 8; at 1 the burn
is an eighth of that). A call that fills the fast body's stack instead hands
over as soon as it does, so its extra cost is the depth it reached — the 132
fuel/byte row is the fast body's descent plus the fallback's whole run.

#### Per search

A budget that lasted one CALL left a drive quadratic: when every call of a
search burns the budget before the fallback answers, the burn is paid once per
call (`(?:a|b)*a(?:a|b){12}c|a` over `a`×N doubled its cost per byte with every
doubling of N). With the caller's search block the budget lasts the SEARCH:

- the fast body loads what is left from the block and saves it back, so a
  search burns one budget in all;
- once it trips, the search is TRIPPED: every later call goes straight to the
  fallback body, and the stub gives the search one fallback memo,
  `(len + 1) × ⌈instructions / 8⌉` bytes, which it keeps for the rest of the
  search. A failure one call marked stops the next; the marks on the path of a
  match a call reports are cleared before it returns, because they are not
  failures;
- a program with a zero-width cycle, which has no fast body, marks its search
  tripped at the first call, so it keeps its memo from the start;
- a program anchored at the start of the text (`^…`, `\A…`) can match only at
  0, so a `find` from any later position answers "no match" at once
  (`^(\B|0)*` over 400 KB of prose: 20.8 M instructions for the drive before,
  4,577 after);
- a capture body (`groups`) keeps only the tripped flag: its windows already
  add up to the input, so it needs no shared memo.

The memo lives in the memory the input lives in. A merged build's fallback
body keeps its own scratch in the module's memory, so the module carries a
SECOND copy of the fallback body that reads the memo from the host's memory,
and a call whose block names a memo runs that one: merged and standalone builds
keep the memo alike (a merged C drive over 32 KB: 0.6 s, against 24 s with a
fresh memo per call).

Measured on the adversary rows: `find` of `(?:a|b)*a(?:a|b){12}c|a` over
`a`×N is linear at 12,808 instructions per byte, its `groups` at 13,390. With
no block a standalone module uses a default block of its own (12,924 and
13,506); a merged build works as described in the sections above.

#### Why there is no Pike VM

A Pike VM — every thread advanced in lockstep, linear by construction — was
the other candidate for bad inputs, and was measured before anything was
built: 124 Backtracking programs (the 101 `groups` patterns of this
repository's configs, tests and benchmarks that route to Backtracking, and 23
`find` patterns forced onto it), each over prose, logs, mixed text and the
input that cost it most. Against Backtracking with the per-search budget and
its switch to the fallback: on `find` the Pike VM was never cheaper (+234% on
normal text, +702% on bad input); on `groups` it won only on two adversarial
inputs of real-config patterns, by 6-7%, and by large factors only on test
shapes such as `^(\w*|)*c` that no real config has. Every quadratic drive was
already linear without it, so it was not built.

#### Where the fallback's memory comes from

A capture body's ordinary stack is placed at the same base, on every call; the
fallback only ever runs after it has handed over, so the two share the region.

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
the config's `max_memory` or the host has set a lower limit.

**Knobs.** `CompileOptions.BTWorkBudget` and `CompileSetOptions.BTWorkBudget`,
neither reachable from YAML: `0` is the default multiplier of 1, a positive
value replaces it, `compile.BTWorkBudgetOff` emits neither counter nor fallback
— the ordinary body alone, which is how tests drive it by itself; a program
with a zero-width cycle still gets the fallback alone — and
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
