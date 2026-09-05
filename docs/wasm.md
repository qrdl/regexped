# WASM Interface and Memory Layout

## Generated WASM exports

Each regexp WASM module exports one or more functions depending on which `_func` fields were set in the config:

```wasm
;; Anchored match: returns end position [0, len] on match, or -1 on no match.
(func $match (param $ptr i32) (param $len i32) (result i32))

;; Non-anchored find: returns packed (start << 32 | end) on match, or -1 on no match.
;; $from is where the SEARCH starts; $ptr/$len always describe the WHOLE input,
;; so zero-width assertions at the search start see their real neighbouring
;; bytes. Positions in the result are absolute. from > len returns -1.
(func $find (param $ptr i32) (param $len i32) (param $from i32) (result i64))

;; Anchored groups: writes numGroups*2 i32 slots to out_ptr, returns end position or -1.
;; Slots layout: [start0, end0, start1, end1, ...]  (group 0 = full match)
(func $groups (param $ptr i32) (param $len i32) (param $out_ptr i32) (param $from i32) (result i32))

;; Named groups: same ABI and slot layout as $groups above.
;; The name→slot-index mapping is resolved in the generated host stub, not in WASM.
(func $named_groups (param $ptr i32) (param $len i32) (param $out_ptr i32) (param $from i32) (result i32))
```

### Negative return values

Every export signals failure with a negative value, and the values are disjoint so a host can tell "does not match" from "could not decide":

| value | name | meaning |
|---|---|---|
| `-1` | `NoMatch` | the input does not match — an ordinary, reliable answer |
| `-2` | `BTStackOverflow` | the Backtracking engine exhausted its compile-time frame budget; whether the input matches is **unknown** |

The same two values apply to the `i64` find exports, sign-extended (`i64.const -1` / `-2`). No legitimate packed `(start << 32 | end)` result can be confused with either, because `start` is a non-negative `i32` so bit 63 is always clear.

For the `_batch` exports, which return a match **count**, `-2` appears as a negative count; a successful call always returns a count ≥ 0. Returning the count collected so far would be a silent truncation the host could not distinguish from a completed scan.

`-2` originates only in Backtracking bodies (the DFA, Compiled DFA and TDFA engines have no such ceiling) and only for a subset of pattern shapes — see [engines.md](engines.md) "Frame budget and the `-2` sentinel" for when it is reachable and how each generated stub surfaces it. The constants are defined once, in `internal/abi`, and shared by the compiler and the stub generators.

`$from` on the capture exports means what it means on `$find`: where the
SEARCH starts, with `$ptr`/`$len` still describing the whole input. Slot
positions come back absolute. For a pattern anchored at 0 the export answers
"no match" for any `$from != 0` — such a pattern has nothing to find later in
the input.

### The find-from channel

A module that exports any `find` also declares one **mutable `i32` global**,
index 0 within the module, holding the position an in-progress find should
start from. The exported `find` is a thin wrapper that sets it and calls the
two-argument body; the body's own signature is unchanged, which is why its
several hundred hardcoded local indices did not have to move.

The capture exports use the same channel: their wrapper sets it and the find
body inside the composed groups path reads it. An anchored capture body reads
nothing — it cannot match past 0, so its wrapper answers -1 instead of calling
it.

Hosts never touch this global — it is not exported, and `wasm-merge` renumbers
it (and every reference to it) when merging into a host that has globals of its
own. Several regexp modules merged into one host each keep their own.

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

State IDs are partitioned by `reorderAcceptFirst`: WASM states `1..acceptLimit` are
accepting and `(acceptLimit+1)..n` are not. The EOF accept check is
`(state-1) u< acceptLimit` — no separate accept array is emitted for DFA paths.
TDFA paths (`useAcceptSideTable=true`) cannot use this partition and instead emit a
per-state `acceptBytes` side table at `acceptOff`.

### u8, no compression (≤ 256 states, table ≤ 32 KB)

```
[transitions: u8[numStates * 256]]   // state × byte → next_state  (0 = dead)
```

### u8, byte-class compressed (≤ 256 states, table > 32 KB)

Many bytes share identical transition rows. Byte-class compression maps 256 byte values to a smaller set of equivalence classes, shrinking the table:

```
[class_map:   u8[256]]                       // byte → equivalence class index
[transitions: u8[numStates * numClasses]]
```

### u16 (> 256 states)

```
[transitions: u16[numStates * 256]]
```

### u16 with row deduplication

When a u16 DFA has ≤ 255 unique transition rows, a u8 rowMap is prepended. The
table stores only the unique rows, reducing size from `numStates × 512` bytes to
`numStates + numUniqueRows × 512` bytes (e.g. 512 KB → 52 KB for 1000 states /
100 unique rows).

```
[rowMap:      u8[numStates]]                 // state → row index (0-254)
[transitions: u16[numUniqueRows * 256]]
```

Runtime lookup: `row = rowMap[state]; state = transitions[row * 256 + byte]`.

### Find-mode extras

Find mode appends additional arrays after the base table:

| Array | Size | Purpose |
|---|---|---|
| `midAccept` | `u8[numStates]` | 1 if state is accepting mid-scan |
| `firstByteFlags` or Teddy/Shufti tables | varies | fast prefix skip (see below) |
| `wordCharTable` | `u8[256]` | `\w` lookup (word-boundary patterns only) |
| `midAcceptNW`, `midAcceptW` | `u8[numStates]` each | word-boundary variants of midAccept |
| `midAcceptNL` | `u8[numStates]` | 1 if state accepts immediately before a `\n` byte — multiline `(?m:$)` patterns only |

For TDFA paths (`useAcceptSideTable=true`) only:

| Array | Size | Purpose |
|---|---|---|
| `acceptBytes` | `u8[numStates]` | 1 if state is EOF-accepting |
| `immediateAccept` | `u8[numStates]` | 1 if state is an immediate (leftmost-first) accept — the engine must stop here rather than continue scanning, whether from a non-greedy quantifier or a higher-priority alternation branch completing before a lower-priority one consumes a byte |

DFA paths use `immAcceptLimit` (state-ID partition, `state u<= immAcceptLimit`) instead of a separate `immediateAccept` array.

### Set bucket accept: bitmask, and the sparse form above 32 patterns

A set's merged suffix DFA answers "which patterns accept in this state", so its
accept arrays are wider than a single pattern's flags. Two encodings exist.

**Bitmask** — the default. Three tables of 8 bytes per state, one bit per
pattern within the bucket:

```
[midBitmask: u64[numStates]]   // accepts at any position
[eofBitmask: u64[numStates]]   // accepts at end of input
[immBitmask: u64[numStates]]   // leftmost-first immediate accept
```

Cheap, but it caps a bucket at 32 patterns in practice — not 64. Every mask on
the per-candidate path (`validMask`, the gate pre-mask, the first-byte
eligibility mask) is an **i32**, so the bucket width follows the narrower of the
two.

**Sparse set** — emitted when a bucket holds more patterns than that. All three
packers can produce one: patterns sharing a mandatory literal, literal-less
patterns in a fallback bucket, and the anchored automata behind `match_any` /
`match_all`. Instead of a bitmask per state, each state names a *list* of
bucket-local pattern indices:

```
[midOff:  {u32 offset, u32 count}[numStates]]   // into midList
[midList: u16[]]                                // pattern indices, sorted
[eofOff:  {u32 offset, u32 count}[numStates]]
[eofList: u16[]]
[immOff:  {u32 offset, u32 count}[numStates]]
[immList: u16[]]
[idMap:   u32[numPatterns]]                     // bucket-local index → global pattern id
[scratch: u32[numPatterns] endPos, u8[numPatterns] seen, u16[numPatterns] fired]
```

Offset-plus-count rather than a list inline after each transition row, because
the row stride has to stay constant for the transition arithmetic; a variable
tail would cost a multiply per input byte to save one load here.

The scratch is working memory, not a table: `endPos` records where each pattern
last accepted, `seen`/`fired` make the per-position pattern set a list rather
than a scan over all patterns. It is never cleared wholesale — the body clears
exactly the entries it set, walking `fired`, so the cost is proportional to
matches rather than to bucket size. Untouched WASM memory starts zeroed, so the
first call sees a clean slate.

Why it matters: a group otherwise splits into `ceil(N/32)` buckets, each costing
its own DFA walk. What that walk costs depends on the packer:

| Packer | A split costs one extra walk... | Measured at 128 patterns |
|---|---|---|
| shared literal | at every position the literal hits | 7.3x `find`, −59% module |
| fallback (no literal) | at **every input position** | 25.3x `find`, 6.3x `scan_all` |
| anchored | per `match_any` / `match_all` call, over the whole input | 6.0x |

The fallback figure is the largest because nothing gates those buckets: with no
literal to skip to, every one of the `ceil(N/32)` walks runs at every position.

A sparse bucket's probe returns a **count**, with the matching global ids left in
`endPos`, rather than the bitmask a normal probe returns — a bitmask would
reimpose the same 32-pattern ceiling on the scan capabilities.

The same ceiling is why nothing on the candidate path may read a mask as
authoritative for a sparse bucket. `validMask` is ignored by the sparse bodies,
which apply the per-pattern gate rule themselves; the gate pre-mask and the
empty-mask group skip are not emitted for such a bucket at all, because an
"empty" i32 mask means only that its first 32 patterns are spent.

Promotion is refused when the merged DFA misses the state or byte budget, in
which case the packer would have split it again anyway. In practice the byte
budget binds first: past 256 states a table switches to u16 cells, and 64 KB of
those is 128 states — so a merge over ~255 states is declined and the group
keeps its split packing.

Three further refusals are about what a sparse body CANNOT see, and each exists
because ignoring it produced wrong answers rather than slow ones:

- any pattern with a **non-trivial prefix** — the body carries one prefix length
  for the whole bucket and subtracts it from every tuple's start, so a bucket
  holding several lengths reports most of its matches at the wrong start
  (negative, near position 0); and the prefix DFAs that confirm such a prefix
  are driven by a 32-bit mask, so patterns past the 32nd would never be checked;
- any pattern anchored with **`\A` or `(?m:^)`** — that eligibility is enforced
  by OR-ing the pattern's bit into `validMask` only where the position allows,
  so the rule lives in the mask rather than the DFA and the body cannot see it;
- any pattern already in a **Backtracking bucket**, which has no table to merge.

The general rule behind all three: for a sparse bucket, any constraint carried
by the driver's i32 mask is invisible to the body. Either refuse the bucket or
move the constraint into the body — never assume the mask still speaks for it.

---

## Find-mode fast-skip

Two compile-time mechanisms skip over input positions that cannot start a match.

### Prefix / Teddy scan

Applied when the match starts at the scanned position:

| Strategy | Condition | Description |
|---|---|---|
| **Hybrid prefix** | literal prefix ≥ 1 byte | SIMD check for full prefix within a 16-byte window |
| **4-byte Teddy** | ≤ 8 first bytes, selective 3rd and 4th bytes | nibble tables check bytes 0–3 simultaneously |
| **3-byte Teddy** | ≤ 8 first bytes, selective 3rd byte | nibble tables check bytes 0, 1, 2 simultaneously |
| **2-byte Teddy** | ≤ 8 first bytes | nibble tables check bytes 0 and 1 simultaneously |
| **1-byte Teddy** | 1-byte prefix, multiple candidates | T_lo/T_hi nibble tables |
| **Shufti** | 9–16 first bytes (unconditional), or 17–64 (rarity heuristic predicts a win, or `hints: [prefer-no-match]` forces it) | nibble-table SIMD set-membership test over the whole candidate set (supersedes an older per-candidate `i8x16.eq`+bitmask emission) |
| **Scalar** | 0 first bytes, > 64, or a 17–64 set the rarity heuristic predicts scalar wins for | byte-by-byte scan; the 17–64 Shufti path also self-disables back to scalar at runtime if the heuristic guessed wrong and match data turns out denser than expected |

Each Teddy tier promotion (1-byte → 2-byte → 3-byte → 4-byte) additionally
requires every first-byte candidate's next byte to lead to a state with at
least one live transition — a candidate that dead-ends right after its
first byte disqualifies the whole tier (fixed 2026-07-26).

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

### The capability exports

```wasm
;; Anchored — the match must span the WHOLE input (0..len).
(func $match_any (param $in_ptr i32) (param $in_len i32) (result i32))            ;; id, or -1
(func $match_all (param $in_ptr i32) (param $in_len i32) (result i64))            ;; bitmask  (<= 64 patterns)
(func $match_all (param $in_ptr i32) (param $in_len i32) (param $out_ptr i32) (result i32))  ;; count + bitmap (> 64)

;; Non-anchored — all take a `from` position bounding the search.
(func $scan_any (param $in_ptr i32) (param $in_len i32) (param $from i32) (result i32))  ;; id, or -1
(func $scan_all (param $in_ptr i32) (param $in_len i32) (param $from i32) (result i64))  ;; bitmask (<= 64)
(func $scan_all (param $in_ptr i32) (param $in_len i32) (param $from i32) (param $out_ptr i32) (result i32))

;; find — ONE signature for both overlap policies. The default body records
;; per-pattern non-overlapping gates in $gate_ptr; the overlapping body
;; records none and uses the array to carry its once-per-drive "matches
;; nowhere" verdict instead. See "The gate array" below.
(func $find
    (param $in_ptr i32) (param $in_len i32) (param $from i32)
    (param $gate_ptr i32) (param $out_ptr i32) (param $out_cap i32)
    (result i32))   ;; TOTAL matches at the reported position

;; <find>_batch — emitted ONLY under `hints: [batch-find]` on the set, alongside
;; $find rather than instead of it. The same matches, several consecutive
;; positions per call. The cursor is an i64 in and an i64 out: pass the previous
;; return value back unchanged. A first call passes `from << 32`.
;;
;; Both entries are driven by ONE shared per-position worker, so a batching set
;; carries one set of bucket code rather than two.
;;
;; $cache_ptr/$cache_len are OPTIONAL scratch — pass 0, 0 to decline. See "The
;; overlapping answer cache" below.
(func $<find>_batch                                  ;; both overlap policies
    (param $in_ptr i32) (param $in_len i32) (param $cursor i64)
    (param $gate_ptr i32) (param $out_ptr i32) (param $out_cap i32)
    (param $cache_ptr i32) (param $cache_len i32)
    (result i64))
```

`in_ptr`/`in_len` always describe the **entire** input; `from` bounds only the
search. Zero-width assertions (`\b`, `\B`, `(?m:^)`, `(?m:$)`) therefore see
real context at any resume index — the same shape as `Input::span` in Rust's
`regex-automata` and Go's internal `doExecute(s, pos)`.

### find tuple layout

Each tuple written to `out_ptr` is 12 bytes (3 × i32), 4-byte aligned:

| Offset | Field | Notes |
|---|---|---|
| +0 | `pattern_id` i32 | Global YAML order index of the matching pattern |
| +4 | `start` i32 | Absolute byte offset — **the same for every tuple in one call** |
| +8 | `end` i32 | Absolute byte offset of the match end (an END, not a length) |

The order of tuples *within* one call is unspecified: not by pattern id, not by
extent, not stable across compiler versions.

### batch cursor layout

The returned `i64` is both the answer and the resume token:

| Bits | Field | Public? |
|---|---|---|
| 63..32 | resume position, or `0xFFFFFFFF` when the scan is finished | only the sentinel |
| 31..`countBits` | `k`, the intra-position resume index | no — opaque |
| `countBits`-1..0 | `count` — valid tuples in the buffer | yes |

`countBits` is `32 - kBits`, where `kBits` is the smallest width holding
`[0, patterns_in_set]`. Treat everything but the sentinel and `count` as opaque
and hand the value straight back.

**These widths are ABI facts, not emitted constants.** No generator exports
them: the stubs decode the cursor for you, and only a direct WASM caller ever
sees it. The one constant that IS emitted is `<set>BatchMaxSize`, the largest
`out_cap` one call can report — JS/TS only, since they are the only stubs with
a batch parameter to bound.

The sentinel is `0xFFFFFFFF` rather than 0 because **0 is a legal resume
position** — a first call whose buffer fills on the matches at position 0
resumes at 0. The done flag arrives on the same call that delivers the final
matches, so a finished scan costs no extra call.

`count` is needed alongside the sentinel because the last call is normally a
partial fill and the buffer is reused: slots past `count` still hold tuples from
the previous call, and `(id=0, start=0, end=0)` is a legal tuple, so no
in-buffer terminator could be unambiguous.

Unlike `find`, the batch entry is **not transactional**: a position whose tuples do
not all fit is delivered in part and resumed inside, so any `out_cap >= 1` makes
progress and tuples of one position may span two calls. `out_cap` is clamped to the count field's
maximum (`<set>BatchMaxSize` in the JS/TS stubs); `out_cap = 0` delivers nothing and returns the **done
sentinel** with count 0, so the ordinary loop terminates rather than spinning on
a cursor that can never advance. This is a deliberate asymmetry with `find`,
where the same input is a legal size probe: `find` returns a count, which a probe
can use, while the batch entry returns a resumable cursor, which a probe cannot.

### The overlapping answer cache

`overlapping: true` reports every start position, so a pattern whose automaton
never dies — `[^\n]*ERROR` on newline-free input — walks to the end of the
input from every one of them, and the drive is quadratic in the input length.

The last two parameters of the batch entry let the caller break that. Given a
region it can fill, the engine may sweep the input **once**, right to left,
computing every `(start, pattern, extent)` tuple in one pass, and then serve
the rest of the drive by copying out of it. The sweep reads the same forward
transition and accept tables the ordinary body reads and emits no tables of its
own.

**Engagement is adaptive, and that is the point.** The sweep costs a flat
`states x patterns` per input byte, while the walk's cost depends on the data —
on most inputs the walk is far cheaper, and sweeping regardless loses badly.
Nor can the choice be made at compile time: `a+` never dies on 50,000 `a`s and
dies on the first byte of ordinary text, so one set wants opposite answers on
different inputs.

So the drive decides for itself. It walks, counting the bytes it has matched,
and switches only once that count exceeds what the sweep would have cost — at
which point the sweep is at worst a second helping of work already spent, and
it removes a quadratic tail. The switch happens at a position boundary and the
sweep covers only the positions not yet delivered, so the handover is invisible
to the caller: matches keep arriving in the same order with none repeated or
dropped. A drive that never crosses the line never sweeps, and costs what it
cost before the cache existed.

| Parameter | Meaning |
|---|---|
| `cache_ptr` | Caller-owned region, or **0 to decline** |
| `cache_len` | Its size in bytes |

The rules:

- **It is optional.** `cache_ptr = 0` is legal and is what a caller who does
  not want to pay for it passes. The drive then walks position by position.
- **Zero the first 16 bytes** before the first call of a drive, exactly as you
  zero the gate array. The header holds the "ready" flag and the drive's
  accumulated work, and zero is the honest starting value for both — so no
  magic value is needed. The rest of the region needs no zeroing: it is written
  before it is read.
- **Too small is not an error.** The sweep refuses a region it cannot fill and
  the drive falls back to walking. The answer is identical, only slower. This
  is the same rule `out_cap` underflow has.
- **Size it at `16 + (in_len + 1) * PATTERN_COUNT * 12`.** Twelve bytes per
  tuple, and the worst case really is one tuple per pattern per start position:
  a pattern that never dies matches from nearly every start, which is the case
  the cache exists for.
- **Offer all of it or none of it.** A short region makes the sweep run and
  *then* discover it cannot finish — the one outcome strictly worse than never
  sweeping. The generated JS/TS stubs cap what they will reserve at 64 MiB and
  pass `0, 0` beyond that rather than pass a truncated region.
- **The cache belongs to one drive.** It holds the answer for one `(input,
  pattern set)` pair; re-zero the header to start a new drive.
- **Same region on every call of a drive, or none.** The sweep writes its
  tuples once and later calls serve out of them by index, so passing a
  different `cache_ptr` (or offering it on some calls and declining on others)
  mid-drive serves indices into a region that no longer holds what they name.
  Offer the same `(cache_ptr, cache_len)` on every call, or `0, 0` on every
  call.

The engine may decline even when offered a large enough region: the sweep is
emitted only where it reproduces the per-position semantics exactly (one
bucket, no anchors, no word-boundary or newline channel, a dense accept mask,
no Backtracking member). Declining is invisible from the caller's side and
costs nothing but speed.

While the cache is live the cursor's high half carries a **tuple index** rather
than a text position. Both are opaque, which is what lets a drive change from
one to the other when it switches: the call that switches returns the first
index-form cursor, and every later call reads it as an index. Pass the value
back unchanged and the change is invisible.

### find return value and overflow

The return value is the **total** number of matches at the position found — not
the number written. `0` means nothing matches at or after `from`. The buffer
receives `min(total, out_cap)` tuples.

```
n = find(input, len, from, gates, buf, cap)
if n == 0   -> done
if n > cap  -> grow buf to n, call again with the same `from`
use buf[0 .. min(n, cap)]
```

`total > out_cap` is the "there is more" signal, so no flag bit or `-1`
sentinel is needed and the caller learns exactly how much to allocate. The
retry is deterministic: same input, same `from`, same tuples. `out_cap = 0` is
a legal size probe — it returns the total and writes nothing.

`out_cap ≥ patterns_in_set` makes overflow impossible: each pattern can report
at most one match per start, so that is the exact worst case for one position.
Every generated stub sizes its buffer that way.

### Resume rule

```
from = start + 1
```

Every tuple in one call shares a start, so reading the first tuple is enough.
There is no continuation token and none is needed: a call returns one complete
position, never a truncated one.

### The gate array

Every `find` body takes `gate_ptr`, pointing at `id_space_size` u32s in
the **caller's** memory (`memory[0]` — the same memory the input lives in).
The parameter does not depend on `overlapping:` — see "Under `overlapping:
true`" below for what changes, which is what the array holds and nothing a
caller does.

It is indexed by **global pattern id**, not by position within the set, so it is
sized from `id_space_size` and not from `patterns_in_set`. Those two differ for
a named subset: a set holding two late-declared patterns has a count of 2 and an
id space large enough to hold their ids. Sizing the array by the count makes the
module write past its end.

- **All zeros = a clean scan.** That is the only operation a caller performs on
  it; the encoding is opaque and will change.
- WASM reads it to decide which patterns are still eligible at each position,
  and writes it after a fully delivered position.
- **An overflowing call writes nothing.** Write-back is gated on
  `total ≤ out_cap`, so a call that overflowed leaves the array byte-for-byte
  as it found it and the grown retry sees the identical world. The same rule
  covers the `out_cap = 0` probe.

Keeping this state in caller memory rather than inside the module is what makes
`find` resumable at any index: nothing is hidden, and zeroing the array
restores a clean scan from anywhere.

#### Under `overlapping: true`

Nothing in the array is a gate: that body reports every match at every start
position and retires nothing on the strength of an earlier one. It uses the
array for the only other thing a caller-owned per-drive allocation is good
for — carrying, across the calls of one drive, the set of patterns proven to
match NOWHERE at or after the drive's first `from`.

That verdict costs one pass over the input and is what retires a pattern whose
automaton never dies (`[^\n]*ERROR` on newline-free text, say) from every
position at once; without somewhere to keep it, the pass would have to run on
every call and would cost more than it saves. The caller's obligations are
identical either way: allocate, zero to begin a drive, pass the pointer, never
read it.

One consequence worth stating, because it is the same one the default body
has: the verdict is written at CALL ENTRY, before any position is evaluated,
so an overflowing call or an `out_cap = 0` probe on a fresh array may still
leave bytes in it. Nothing an eliminated pattern could have matched is lost,
so no answer changes — but the array is not byte-for-byte untouched.

### Edge contracts

- `0 ≤ from ≤ len` (unsigned). `from == len` is a real position and IS
  evaluated — end-anchored and empty-matchable patterns can match there.
- `from > len` yields the capability's "nothing": `scan_any` −1,
  `scan_all` 0, `find` 0.
- `len == 0`: position 0 is evaluated.
- Zero-length matches are ordinary matches; `find` reports them as `(id, p, p)`.
- `out_ptr` and `gate_ptr` must be 4-byte aligned.
- The `>64` bitmap at `out_ptr` is `ceil(P/8)` bytes, little-endian bit order
  (bit k = byte `k/8`, bit `k%8`), where **P is the set's id space**, not its
  pattern count — a set that selects patterns 68 and 69 of seventy needs a
  9-byte bitmap, because a bit position IS a pattern id.
- **The bitmap must be all-zero on entry.** The module only ORs hit bits in and
  counts 0→1 transitions; it never writes a zero, and bytes past the last
  pattern are not written at all. Reusing a dirty buffer therefore reports
  stale patterns and returns a count that disagrees with the bits. Generated
  stubs zero it for you; direct callers must.

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
