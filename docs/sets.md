# Set Composition

Set composition lets you compile multiple regexp patterns into a single
multi-pattern matcher that scans the input once and reports all matches with
their positions and pattern IDs.

## When to use set composition

| Situation | Recommendation |
|---|---|
| Scanning text for any of N patterns, with positions (WAF, secret scanning, log analysis) | Declare `find` |
| "Is anything in here at all?" | Declare `scan` — a boolean, no positions, no extents |
| "Which patterns appear somewhere?" | Declare `scan_all` |
| Classifying whole inputs by which pattern they match (URL validation, SQL type detection) | Declare `match_any` or `match_all` |
| 1–3 patterns, simple scan | Individual `find_func` exports are sufficient |
| N > 4 patterns, same corpus scanned repeatedly | Set composition pays off |

## Pipeline overview

```
regexps: [p1, p2, ..., pN]
            │
            ▼
    analyzePattern()       ← split each pattern at its mandatory literal
            │
            ▼
    bucketByLiteral()      ← group patterns sharing the same mandatory literal
            │
            ▼
    binPack()              ← merge compatible suffix DFAs within each bucket
            │
            ▼
    chooseLiteralFrontend() ← Teddy (≤16), AC (17+, downgrades to scalar
                               past a node-count cap), or Shufti (density/
                               hint-selected prefilter over the scalar path)
            │
            ▼
    assembleModuleWithSets() ← emit WASM: DFA tables, per-capability bodies,
                               plus a second anchored packing when a match_*
                               capability is declared
```

Everything above is the NON-anchored pipeline. The anchored capabilities get
their own packing over the full patterns — see
[below](#the-anchored-capabilities-use-their-own-automata) for why they have
to.

## The eight capabilities

A set declares which questions it needs answered, and the compiler emits only
the machinery those questions require. The **key** names the capability; the
**value** is the WASM export / generated-function name you choose.

```yaml
regexps:
  - name: aws_key          # name: required for sets.patterns list references
    pattern: 'AKIA[0-9A-Z]{16}'
  - name: github_pat
    pattern: 'ghp_[0-9a-zA-Z]{36}'

sets:
  - name: secret_scanner
    # ---- anchored: the match must span the WHOLE input (0..len) ----
    match:      is_secret        # -> yes/no
    match_any:  which_secret     # -> one pattern id, or none
    match_all:  all_secret_kinds # -> every matching pattern id
    # ---- non-anchored: each takes a `from` position ----
    scan:       has_secret       # -> yes/no
    scan_any:   first_secret     # -> one pattern id + where it starts
    scan_all:   secret_kinds     # -> every pattern matching somewhere
    find:       scan_secrets     # -> the matches at the next matching position
    find_batch: scan_secrets_batch # -> the same, several positions per call
    overlapping: false           # optional; see "Overlap policy" below
    patterns:   all
    emit_name_map: true
```

The grid: `match_*` is anchored, `scan_*` is not; bare is a boolean, `_any` is
one arbitrary matching pattern, `_all` is every matching pattern. `find` and
`find_batch` are the only capabilities that report positions and extents; they
report the same matches and differ only in how many positions one call covers.

At least one capability must be declared. Every capability value must be a
valid identifier in all six stub languages (see
[cli.md](cli.md#export-name-rules)).

> **Migration trap.** `match:` used to mean "anchored, returns the matching
> pattern id". It now means "anchored, yes/no". An existing config keeps
> parsing and silently changes capability — no parsing policy can catch that,
> because the key stays valid. If you want the old meaning, use `match_any:`.
> The retired keys `find_any`, `find_all` and `batch_size` are caught loudly:
> config parsing is strict, so they fail as unknown-field errors. `batch_size`
> is retired for good: batching is now `find_batch`, and its buffer is sized by
> the CALLER at run time rather than by a compile-time knob.

### What "anchored" means here

`match`, `match_any` and `match_all` require **full consumption**: the pattern
must match from position 0 to `len`, i.e. `\A(?:p)\z`. A pattern matching a
proper prefix does not count. This is the same rule the single-pattern
`match_func` has always used.

### `find` — the positional capability

```
find(input, from) -> the matches at the FIRST position at or after `from`
                     where anything in the set matches
```

Two invariants make this easy to consume:

- **every match returned by one call shares the same start** — that position is
  the answer to "where", so there is no separate locate step;
- the return value is the **total** number of matches at that position, which
  can exceed the buffer capacity; the buffer takes what fits.

Iterating is therefore "call, use, resume at `start + 1`". The generated stubs
do exactly that and hand you one match at a time.

The order of the matches *within* one call is unspecified — not by pattern id,
not by extent, not stable across compiler versions. Sort what you collect if
you need a specific order.

### `find_batch` — the same matches, several positions per call

```
find_batch(input, cursor, buffer) -> as many matches as the buffer holds,
                                     plus a cursor to resume from
```

`find` returns one position per call, which is the right shape for a caller who
may stop early: nothing is computed for matches you never ask for. That costs
one host-boundary crossing per position, and on a dense input the crossings
dominate.

`find_batch` makes the opposite trade. One call fills the caller's buffer with
the matches of as many CONSECUTIVE positions as fit, so a caller who intends to
consume everything crosses the boundary once per bufferful. It reports exactly
the same matches, in the same order, under the same overlap policy.

They are independent capabilities: declare either, both, or neither. Declaring
both emits two separate bodies over shared machinery — batching speculates, and
a `find` caller must not be charged for speculation it discards.

**Which to use.** `find` when you may stop early (first hit, a bounded number
of results, a user-cancellable scan). `find_batch` when the whole scan will be
consumed.

#### The cursor

The cursor is one `i64`, and it is **opaque**: pass back the value the previous
call returned, unchanged. A first call passes `from << 32`. Only two things
about it are public:

| field | meaning |
|---|---|
| bits 63..32 | `0xFFFFFFFF` means the scan is finished — otherwise this is internal |
| low `<SET>_BATCH_COUNT_BITS` | `count` — how many tuples of the buffer are valid |

The done flag arrives on the **same call that delivers the final matches**, so
a finished scan costs no extra call. `count` is needed alongside it because the
last call is normally a partial fill and the buffer is reused: the slots past
`count` still hold tuples from the previous call.

`0xFFFFFFFF` rather than `0` is the sentinel because **0 is a legal resume
position** — a first call whose buffer fills on the matches at position 0 must
resume at 0.

#### The buffer is the caller's

There is no `batch_size` config key. **You allocate the buffer and hand it to
each scan**, because only you know whether you will consume everything, and how
many scans you are about to do. Its length is the batch size:

```rust
let mut buf = vec![[0i32; 3]; 4096];       // once
for doc in docs {
    for m in rx::scan_secrets_batch(doc, 0, &mut buf) { ... }   // allocates nothing
}
```

```go
buf := make([]rx.SetTuple, 4096)           // once
for _, doc := range docs {
    for m := range rx.ScanSecretsBatch(doc, 0, buf) { ... }     // allocates nothing
}
```

```c
int buf[4096 * 3];                         /* once */
rx_secrets_batch_scanner_t sc;
scan_secrets_batch_init(&sc, 0, buf, 4096);
while (scan_secrets_batch_next(&sc, input, len, &m)) { ... }
```

That is the whole reason the buffer is not stub-owned: `find_batch` exists to
cut per-call overhead, and allocating one per scan would put overhead back at a
different level. Rust, Go, AssemblyScript and C all reach zero allocations in
the steady state. **JavaScript and TypeScript take a capacity number instead**
(default 256) — their buffer lives inside WASM memory, so there is nothing for
a JS caller to hand over.

The gate array is *not* the caller's. Its length is `<SET>_ID_SPACE`, a
compile-time constant, so it is not a size anyone chooses; the stubs keep
owning it and it stays out of their public surface.

**Any capacity of 1 or more makes progress.** A position whose matches do not
all fit is delivered in part and resumed inside — an undersized buffer costs
more calls, never a stall and never a lost match. (`find` is different: it is
transactional, and an overflowing call writes nothing and asks you to grow the
buffer.) The upper bound is `<SET>_BATCH_MAX_COUNT`; the module clamps to it,
and a zero-length buffer yields nothing.

Because tuples of one position can span two calls, group by the `start` field
rather than by call boundary if you need per-position grouping.

### Overlap policy

By default a set's `find` is **per-pattern non-overlapping**: each pattern
reports its matches the way Go's `FindAllIndex` does, independently of the
others. `[a-z]+X` on `"abcX foo"` reports `0-4` once, not `0-4 1-4 2-4`.

```yaml
sets:
  - name: s
    find: scan_all_positions
    overlapping: true      # every start position, no filtering
```

`overlapping: true` opts into the full enumeration: for every start position,
every pattern matching exactly there. It is the right choice when you genuinely
want to see every possible match rather than a non-overlapping selection, and
it is measurably faster to *emit* (no gating code at all) — but on greedy or
unbounded-tail patterns it is quadratic in the input, because every start runs
a DFA to its own extent. The default exists to avoid that.

`overlapping` affects `find` and `find_batch` and nothing else. On a set
declaring neither it is silently ignored — there is no find body for it to
select, so it has no effect.

The empty-match rule follows Go's: after a match ending at `e` the next match
may start at `e`, except an empty match exactly at `e` is skipped; after an
empty match at `e` the search resumes past it. We advance by one **byte** where
Go advances by one rune — the same byte-orientation the single-pattern stub
iterators document.

## The gate array

The default (non-overlapping) `find` needs to remember, per pattern, where that
pattern may match again. That state lives in a **caller-owned array**, not
inside the module:

```
find(ptr, len, from, gate_ptr, out_ptr, out_cap) -> i32
```

- `gate_ptr` points at `id_space_size` u32s in the caller's memory — the array
  is indexed by global pattern id, so it is sized from the id space and not
  from the pattern count (see the constants table below).
- **All zeros means a clean scan.** That is the only operation a caller ever
  performs on it: the encoding is opaque and will change.
- WASM reads and writes it. Zeroing it restarts a scan; keeping it across calls
  continues one.
- An **overflowing call writes nothing** — if the return value exceeds
  `out_cap`, the gate array is left exactly as it was found, so growing the
  buffer and calling again with the same `from` sees the identical world.

The generated stubs own the gate array on your behalf; it never appears in
their public surface. Only a direct WASM caller sees it.

Keeping the state visible is what makes `find` resumable at *any* index: an
array held inside the module would silently carry gates from an earlier scan
into a caller that meant to start fresh.

With `overlapping: true` there is no gate array and no gate parameter at all.

`find_batch` carries the same gate array as `find` when gated, and none when
overlapping. It differs in one respect, and only internally: it records gates
for the matches it DELIVERED rather than only for a position that fitted whole.
That is what lets it resume inside a split position — the patterns already
handed to you are gated out, so re-entering the position yields exactly the
remainder. Callers see no difference; `find`'s transactional rule above is
unchanged.

## What each capability costs

Only `find` reports extents, and only it needs the machinery to resolve them.
Declaring less emits less:

| capability | literal frontend | backward prefix DFA | per-pattern extents | output |
|---|---|---|---|---|
| `match`, `match_any`, `match_all` | ✗ | ✗ | ✗ | bool / id / bitmask |
| `scan`, `scan_any`, `scan_all` | ✓ | ✓ | ✗ | bool / packed id+start / bitmask |
| `find` | ✓ | ✓ | ✓ | tuples (+ gates by default) |

A set that does not declare `find` emits no tuple-writing suffix functions at
all — just the DFA tables, which the cheap bitmask probes share. A
`match`-only set additionally emits no literal frontend: the
packed-pair/Teddy/AC/Shufti tables and skip loop could never execute for it.

Measured on a 100KB no-match corpus with eight literal-prefixed patterns:
`match` 54 fuel, `match_any`/`match_all` 84, `scan` 212K, `scan_any`/`scan_all`
219K, `find` 219K. The anchored trio dies within a byte or two of position 0;
the scan trio is frontend-bound, like `find`, because it shares `find`'s
frontend. (An earlier draft gave the scan trio a scalar position-by-position
scan instead, and measured 17x worse — the literal frontend is what makes
these cheap, not the absence of extent tracking.)

Do not use `scan_any` as a locate step for `find` — calling both at the same
position duplicates one position's work. Pick one.

## Output formats

`find` writes 12-byte tuples, 4-byte aligned:

| offset | field | type |
|---|---|---|
| 0 | `pattern_id` | i32 — index into `regexps:` in YAML order |
| 4 | `start` | i32 — absolute, same for every tuple in one call |
| 8 | `end` | i32 — absolute (an END, not a length) |

`out_cap` is a tuple count. Sizing it at `patterns_in_set` makes overflow
impossible: that is the exact worst case for a single position, since each
pattern can report at most one match per start. Every generated stub sizes its
buffer from the emitted `<SET>_PATTERN_COUNT` constant for that reason, and the
overflow path is reachable only by a direct WASM caller who deliberately
undersizes.

`match_all` and `scan_all` return a **bitmask** — bit *k* set means pattern *k*
matched — as an `i64` return value when the set's id space is 64 or fewer.
Above that they take an `out_ptr` and write a `ceil(P/8)`-byte little-endian
bitmap, returning the count instead. The generated stubs expand either form
into the language's natural list of ids; the bitmask never reaches a stub user.
A direct caller must pass an **all-zero** bitmap: the module only ORs bits in
and counts 0→1 transitions, so a reused dirty buffer reports stale patterns.

### Pattern ids and the two emitted constants

A `pattern_id` is the pattern's **global** index into `regexps:`, so a set that
selects a subset does not renumber: a set holding the last two of seventy
patterns reports ids 68 and 69. Two constants therefore accompany every set,
and they are not interchangeable:

| constant | value | sizes |
|---|---|---|
| `<SET>_PATTERN_COUNT` | patterns in the set | the `find` tuple buffer (`out_cap`), and the width of the `find_batch` cursor's `k` field |
| `<SET>_ID_SPACE` | largest reportable id + 1 | the gate array, the `_all` bitmask/bitmap, and which `_all` ABI is exported |

For `patterns: all` — the common case — the two are equal. They diverge only
for a named subset, and using the wrong one there is a memory-safety bug: the
gate array is indexed by pattern id, so sizing it at the pattern count lets the
module write past the caller's array. Both constants are emitted in all six
stub languages, and every generated declaration is written in terms of the
right one.

`scan_any` returns a packed `(start << 32) | pattern_id` as an `i64`, or `-1`.
Both fields are below 2³¹, so `-1` is unambiguous. Stubs decompose it.

`emit_name_map: true` additionally emits a `pattern_name(id)` helper mapping a
pattern id back to its `name:` string.

## Bin-packing and merge constraints

The bin-packer groups patterns by their mandatory literal and merges compatible
suffix DFAs within each group:

| Constraint | Default | Config field |
|---|---|---|
| Max patterns per bitmask bucket | 32 | `bitmask_width` (internal) |
| Max merged DFA table bytes | 64 KB | `budget_bytes` (internal) |
| Max merged DFA states | 512 | `budget_states` (internal) |
| Pre-filter (states × combined classes) | 65536 | `budget_states_prefilter` (internal) |
| Max fallback-bucket DFA states | 1024 | `max_fallback_states` (internal) |

Patterns that cannot be merged (no mandatory literal, literal inside quantifier,
budget exceeded) route to fallback buckets that scan every input position.
Under the set's own `hints: [prefer-match]`, two patterns that are each
individually eligible for the single-pattern counted-class-chain
optimisation (e.g. `[0-9]{8}`-style bounded class runs) are never merged
into the same bucket, even if they'd otherwise fit — recorded as conflict
reason `lm_counted_chain_split` in diagnostics.

**Fallback buckets can drop patterns, not just deprioritize them.** A
fallback bucket's own merged DFA is still subject to the `max_fallback_states`
budget above; a pattern that would push it over that limit is skipped
entirely rather than merged — it does not appear in the set's compiled
output at all. Check `state_limit_dropped` in diagnostics (see below) to
find any patterns this happened to.

## Diagnostics

Use `--diag-json <path>` with `regexped compile` to write a JSON file
describing how patterns were placed:

```bash
regexped compile --config=regexped.yaml --diag-json=diag.json
```

The JSON contains `patterns_total`, `capture_bearing` (dropped from sets),
`in_set` (patterns actually placed into a set), `prefix_dedup_pool_size`,
and per-set `frontend`
(`"packed-pair"`/`"teddy"`/`"ac"`/`"scalar"`/`"shufti"`), `buckets`,
`conflicts`, `capture_bearing_dropped`, and `state_limit_dropped` (patterns
dropped for exceeding a fallback bucket's state budget — see
[Bin-packing](#bin-packing-and-merge-constraints) above) arrays.

If a set's frontend was **downgraded** from the one its literals selected, the
per-set `frontend_demotion` object says so, with `from`, `to`, a machine-
readable `reason`, and a `detail` object carrying the numbers behind the
decision. This is worth checking whenever a set is slower than expected: the
frontend is the difference between per-byte cost that is flat in set size and
cost that grows with it, and a downgrade is otherwise invisible at runtime.

```json
"frontend_demotion": {
  "from": "ac", "to": "scalar", "reason": "ac_table_over_budget",
  "detail": {"literals": 400, "ac_nodes": 1600,
             "table_bytes": 823296, "budget_bytes": 524288}
}
```

## Literal scan frontend

| Condition | Frontend |
|---|---|
| 1–16 distinct literals | **Teddy** — SIMD nibble fingerprint; literals >4 bytes use their first 4 bytes as the probe and verify remaining bytes in dispatch |
| 17+ distinct literals | **Aho-Corasick** — byte-at-a-time, O(n) regardless of literal count, with a SIMD first-byte prefilter at the root state |
| (AC tables exceed 512 KB) | **Scalar** — AC is capped by *table bytes*, not literal count. The budget holds ~1,000 trie nodes uncompressed, and no set of 128 literals tested so far comes close to it; literals sharing no common prefix consume nodes fastest, since each distinct first byte forks the trie at the root. A demotion is always reported in `--diag-json` as `frontend_demotion` |
| No mandatory literal at all | **Scalar** |

For 9–16 literals Teddy uses two groups of 8 (`TwoGroups=true`), ORing the
results of two independent nibble probes per 16-byte chunk.

Aho-Corasick's root-state prefilter skips ahead to the next position whose byte
could begin some literal. With **1–3 distinct first bytes** it compares against
each in turn; with **4 or more** it uses the same nibble-table membership test
as Shufti below, whose cost depends on the size of the first-byte *set* rather
than growing with every literal added.

### Shufti — SIMD first-byte prefilter for the scalar case

When the frontend would otherwise be scalar (no mandatory literal, or AC
downgraded per the table above), a fourth frontend — **Shufti** — is
considered instead of going straight to scalar. Note that since the AC budget
became large enough to hold real automata, sets with literals reach AC rather
than being downgraded into this path, so in practice Shufti now serves sets
with **no mandatory literal**. It requires:

- **zero fallback buckets** in the set (Shufti can't skip positions that a
  fallback bucket's full-pattern DFA still has to visit for correctness);
- the **union of first bytes** across all bucket literals falls in the
  17–64 range (below 17 it's not worth a dedicated table; above 64 the
  SIMD membership test itself gets expensive);
- and then either a **byte-rarity heuristic** predicts Shufti beats scalar
  for this specific byte set (sum of per-byte rarity scores below a
  threshold — rare bytes mean scalar can't exit early enough to win), **or**
  the set's own `hints: [prefer-no-match]` forces Shufti on regardless of
  what the heuristic predicts.

Shufti tests set membership against the whole first-byte union in one SIMD
nibble-table lookup, rather than a per-candidate comparison. See
[prefer-hints.md](prefer-hints.md) for the `hints:` mechanism and which
shapes it affects.

## The anchored capabilities use their own automata

`match`, `match_any` and `match_all` do NOT read their answer off the
scan-path DFAs. Those are built leftmost-first, which prunes the search the
moment the highest-priority alternative accepts — so the automaton for `a|ab`
has no transition out of the state reached by `"a"`, and `a+?` stops after one
byte. Both patterns match their inputs end to end, and both would be reported
as non-matching.

The anchored capabilities therefore get a second packing over the full
patterns, merged *without* leftmost-first pruning, and answer "did the run from
0 reach `len` in an accepting state". The cost is compile time and table space,
which is the trade this project makes everywhere (see CLAUDE.md's "Runtime over
compile time").

A consequence worth knowing: a `match`-only set emits no literal frontend at
all — the packed-pair/Teddy/AC/Shufti tables and skip loop can never execute
for it.

## Variable-length prefixes route to fallback

A pattern whose mandatory literal sits a *variable* distance from the match
start (`a?foo`, `[a-z]*KEY`, `.*end`) does not use the literal frontend. It is
not a tuning choice: the split representation `prefix·literal·suffix` recovers
the match start by walking a backward DFA from a literal occurrence, and that
is exact only while each start maps to exactly one literal position. With a
variable prefix one start has several candidate literal positions with
different extents, and which one RE2 picks depends on the prefix's greedy
structure — which a backward DFA cannot express. `a?a` over `"aa"` is the
smallest case: the backward walk finds only the leftmost start, so the match at
1 is never generated, and start 0 gets reported twice with different extents.

Such patterns are compiled as whole-pattern DFAs evaluated at every position,
which is both correct and what a set containing them would have to do anyway —
a literal arbitrarily far to the right can serve a match starting here, so
nothing can be skipped.

## Zero-width assertions in a prefix route to fallback

The same backward DFA is a plain *byte* automaton, so any zero-width assertion
sitting between the match start and the mandatory literal has no representation
in it. Rather than drop the assertion, such a pattern gives up the split and is
compiled as a whole-pattern DFA evaluated at every position.

Two flavours are disqualified:

| in the prefix | example | why the backward walk cannot see it |
|---|---|---|
| `\b`, `\B` | `\B.KEY` | The walk carries no `prevWasWord` bit and never reads the wordChar table — a boundary at the prefix's left edge depends on the byte *before* the start, which a backward scan has not reached. |
| `$`, `\z`, `(?m:$)` | `.$KEY` | End-of-text is not a byte, so the assertion simply has no encoding in a byte DFA. |

The two fail in opposite directions, which is why both matter: dropping a `\b`
*loses* matches, while dropping a `$` *invents* them — `.$0` cannot match any
input at all, since nothing can follow end-of-text.

Begin-anchors are **not** in this list and cost you nothing: `^`, `\A` and
`(?m:^)` are modelled positively as per-pattern eligibility masks, so `^KEY`
and `(?m:^)KEY` keep both their split and their literal frontend. An
end-assertion *after* the literal is equally fine — `KEY$` is expressed by the
forward suffix DFA's end-of-text channel — so only a prefix assertion
disqualifies.

## Examples

- [examples/node/sql-validator/](../examples/node/sql-validator/) — anchored `match_any`, SQL statement validation (Node.js / TypeScript)
- [examples/wasmtime/go/secret-scanner/](../examples/wasmtime/go/secret-scanner/) — `find`, secret detection (Go wasip1)
- [examples/wasmtime/rust/secret-scanner/](../examples/wasmtime/rust/secret-scanner/) — `find` called directly from a native Rust host, gate array and all
- [examples/fastedge/url-guard/](../examples/fastedge/url-guard/) — `scan_any`, URL rule matching (FastEdge)
