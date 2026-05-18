# WASM Interface and Memory Layout

## Generated WASM exports

Each regexp WASM module exports one or more functions depending on which `_func` fields were set in the config:

```wasm
;; Anchored match: returns end position [0, len] on match, or -1 on no match.
(func $match (param $ptr i32) (param $len i32) (result i32))

;; Non-anchored find: returns packed (start << 32 | end) on match, or -1 on no match.
(func $find (param $ptr i32) (param $len i32) (result i64))

;; Anchored groups: writes numGroups*2 i32 slots to out_ptr, returns end position or -1.
;; Slots layout: [start0, end0, start1, end1, ...]  (group 0 = full match)
(func $groups (param $ptr i32) (param $len i32) (param $out_ptr i32) (result i32))
```

**Embedded mode** (produced when `output` is set in config, for use with `regexped merge`): the regexp WASM **imports** the host's `"main"` memory as `memory[0]` (used for reading input) and declares its own memory for DFA tables. After `wasm-merge`, the host retains `memory[0]` and the regexp module's own memory becomes `memory[1]` (or higher). The multi-memory layout is established at compile time, not by wasm-merge.

**Standalone mode** (produced when `output` is absent, for JS/TS/browser direct load): the regexp WASM declares and exports its own single memory as `"memory"` (`memory[0]`). No import.

For standalone use (JS/TS/browser), the compiled WASM is used directly with no merging. Memory index 0 is exported as `"memory"` so the JS host can read input/output.

---

## Memory layout

### Embedded (Rust/Go via wasm-merge)

```
Regexp module's own memory (index 1 after merge):
┌─────────────────┬─────────────────┬─────┐
│  DFA Table 1    │  DFA Table 2    │ ... │
└─────────────────┴─────────────────┴─────┘
0              tableEnd1         tableEnd2

Host module's memory (index 0):
┌─────────────────┬─────────────────┐
│   Stack         │   Heap          │
│   & Globals     │                 │
└─────────────────┴─────────────────┘
0               memTop
```

Tables start at address 0 of the regexp module's own memory. Each subsequent table starts at `PageAlign(prevTableEnd)`. The host memory is completely separate — no coordination needed.

### Standalone (JS/TS/browser)

```
Single memory (index 0, exported as "memory"):
┌──────────────────┬─────────────────┬─────┐
│  (caller input)  │  DFA Table 1    │ ... │
└──────────────────┴─────────────────┴─────┘
0              tableBase         tableEnd
```

The caller writes input into low pages and passes the pointer. Tables start at `tableBase` (caller-chosen, e.g. page 1 for re2test).

---

## DFA table formats

### u8, no compression (≤ 256 states, table ≤ 32 KB)

```
[transitions: u8[numStates * 256]]   // state × byte → next_state  (0 = dead)
[accept:      u8[numStates]]         // 1 if accepting state
```

### u8, byte-class compressed (≤ 256 states, table > 32 KB)

Many bytes share identical transition rows. Byte-class compression maps 256 byte values to a smaller set of equivalence classes, shrinking the table:

```
[class_map:   u8[256]]                       // byte → equivalence class index
[transitions: u8[numStates * numClasses]]
[accept:      u8[numStates]]
```

### u16 (> 256 states)

```
[transitions: u16[numStates * 256]]
[accept:      u8[numStates]]
```

### u16 with row deduplication

When a u16 DFA has ≤ 255 unique transition rows, a u8 rowMap is prepended. The
table stores only the unique rows, reducing size from `numStates × 512` bytes to
`numStates + numUniqueRows × 512` bytes (e.g. 512 KB → 52 KB for 1000 states /
100 unique rows).

```
[rowMap:      u8[numStates]]                 // state → row index (0-254)
[transitions: u16[numUniqueRows * 256]]
[accept:      u8[numStates]]
```

Runtime lookup: `row = rowMap[state]; state = transitions[row * 256 + byte]`.

### Find-mode extras

Find mode appends additional arrays after the base table:

| Array | Size | Purpose |
|---|---|---|
| `midAccept` | `u8[numStates]` | 1 if state is accepting mid-scan |
| `firstByteFlags` or Teddy tables | varies | fast prefix skip (see below) |
| `immediateAccept` | `u8[numStates]` | 1 if state requires immediate stop (non-greedy) |
| `wordCharTable` | `u8[256]` | `\w` lookup (word-boundary patterns only) |
| `midAcceptNW`, `midAcceptW` | `u8[numStates]` each | word-boundary variants of midAccept |

---

## Find-mode fast-skip

Two compile-time mechanisms skip over input positions that cannot start a match.

### Prefix / Teddy scan

Applied when the match starts at the scanned position:

| Strategy | Condition | Description |
|---|---|---|
| **Hybrid prefix** | literal prefix ≥ 1 byte | SIMD check for full prefix within a 16-byte window |
| **3-byte Teddy** | ≤ 8 first bytes, selective 3rd byte | nibble tables check bytes 0, 1, 2 simultaneously |
| **2-byte Teddy** | ≤ 8 first bytes | nibble tables check bytes 0 and 1 simultaneously |
| **1-byte Teddy** | 1-byte prefix, multiple candidates | T_lo/T_hi nibble tables |
| **Multi-eq SIMD** | small first-byte set | `i8x16.eq` + bitmask per candidate |
| **Scalar** | wide first-byte set | byte-by-byte scan |

### Mandatory literal extraction

Applied when the prefix is low-entropy but a selective fixed byte sequence (mandatory literal) exists deeper in the pattern. `FindMandatoryLit` extracts the literal and its min/max offset from match start at compile time. The WASM find function scans for the literal using the same SIMD strategies above, then derives candidate start positions from each hit. This is implemented as a two-level outer loop (`$lit_outer` / `$outer`) in the find function body.

Example: `[a-zA-Z]{2,8}://[^\s]+` — prefix `[a-zA-Z]` matches 52/256 bytes, but `://` is rare; scanning for `://` skips far more of the input.

Uses WASM SIMD (simd128): `v128.load`, `i8x16.splat`, `i8x16.swizzle`, `i8x16.eq`, `i8x16.bitmask`, `v128.and`.

---

## TDFA table format

TDFA uses the same DFA table format described above (u8 or u16 state IDs,
with optional byte-class compression). Capture register operations are emitted
as inline WASM locals and `br_table` dispatch in the function body — they are
not stored in the table.

---

## Set composition exports

When the config contains a `sets:` block, `regexped compile` emits additional
WASM functions for multi-pattern matching.

### find_any / find_all — non-anchored set match

```wasm
;; Set find function (one body; exported under find_any and/or find_all names).
;; Scans input from start_pos, writes up to out_cap match tuples to out_ptr,
;; returns count of tuples written (0 = exhausted).
(func $find_all
    (param $in_ptr i32) (param $in_len i32)
    (param $out_ptr i32) (param $out_cap i32)
    (param $start_pos i32)
    (result i32))
```

Each tuple written to `out_ptr` is 12 bytes (3 × i32):

| Offset | Field | Notes |
|---|---|---|
| +0 | `pattern_id` i32 | Global YAML order index of the matching pattern |
| +4 | `start` i32 | Absolute byte offset of the match start |
| +8 | `length` i32 | Byte length of the match |

Tuples within a batch are emitted in non-decreasing `start` order.

**Capacity precondition.** The caller MUST size `out_cap` to be at least the
maximum same-start fan-out — that is, the maximum number of tuples the
function may produce at a single `start` position. A safe upper bound is the
number of patterns in the set (each global pattern ID can appear at most
once per `start` in `find_all` output), so `out_cap ≥ patterns_in_set` is
always sufficient. Generated stubs enforce this floor automatically; custom
hosts must enforce it themselves.

**Resume rule.** After a batch of `count` tuples, the host advances

```
start_pos = last.start + 1
```

and re-calls until the function returns 0. The WASM scan is
position-by-position: when the buffer fills it exits at the top of the next
iteration, so the only positions guaranteed to have been visited are those
`≤ last.start`. Advancing by `last.length` (or `end`) would skip positions
inside the last match's span that the scan has not yet visited, silently
dropping matches at those positions.

The capacity precondition above guarantees that when the buffer fills it
does so on a position boundary (no mid-position truncation), so a single
`+1` step is sufficient to resume without losing same-position matches.
Hosts that bypass the precondition and use a smaller `out_cap` must dedupe
`(pattern_id, start)` pairs across batches to handle mid-position
truncation; the ABI provides no continuation token.

`find_any` uses the same function body with `out_cap=1, start_pos=0` and is
exempt from the precondition because it stops at the first match.

### match — anchored set match

```wasm
;; Anchored match: tries all patterns from position 0.
;; Writes up to out_cap match tuples to out_ptr, returns count.
(func $match
    (param $in_ptr i32) (param $in_len i32)
    (param $out_ptr i32) (param $out_cap i32)
    (result i32))
```

Each tuple written to `out_ptr` is 12 bytes (3 × i32), the same layout as
`find_all`/`find_any`:

| Offset | Field | Notes |
|---|---|---|
| +0 | `pattern_id` i32 | Global YAML order index |
| +4 | `start` i32 | Always 0 for anchored match |
| +8 | `length` i32 | Byte length of the match |

Returns the number of matching patterns written (0 if none match anchored
at position 0). Anchored match is not batched — one call returns all matching
patterns, up to `out_cap`. To receive every matching pattern, callers must
size `out_cap` to hold the maximum same-position fan-out;
`out_cap ≥ patterns_in_set` is always sufficient.

> **Note.** The generated `match` wrappers in the Rust/Go/JS/TS/AS/C stubs
> are deliberately "first match" convenience APIs: they call the WASM export
> with `out_cap = 1` and return a single match (or none). This mirrors the
> relationship between `find_any` (first occurrence) and `find_all` (every
> occurrence). Hosts that need every anchored match should call the WASM
> export directly with a larger `out_cap` and decode the tuple buffer as
> described above.

### Suffix DFA functions (internal)

Each literal bucket gets one suffix DFA function. It writes match tuples
directly into the caller's output buffer and returns the count written:

```wasm
;; Runs the merged suffix DFA starting at lPos.
;; Writes (pattern_id i32, start i32, length i32) tuples to out_ptr.
;; May write multiple tuples per call: a bucket can hold several patterns,
;; and every pattern in the bucket whose suffix matches at lPos emits one
;; tuple (up to out_cap and subject to valid_mask). Returns the count.
(func $suffix_dfa_N
    (param $ptr i32) (param $start i32) (param $len i32)
    (param $lPos i32) (param $out_ptr i32) (param $out_cap i32)
    (param $valid_mask i32)
    (result i32))
```

These are called via direct `call` (not `call_indirect`) from the set match
body using statically known function indices, and are not exported.
