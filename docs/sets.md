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

## The five capabilities

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
    match_any:  which_secret     # -> one pattern id, or none
    match_all:  all_secret_kinds # -> every matching pattern id
    # ---- non-anchored: each takes an `offset` ----
    scan_any:   first_secret     # -> one pattern id, or none
    scan_all:   secret_kinds     # -> every pattern matching somewhere
    find:       scan_secrets     # -> the matches at the next matching position
    overlapping: false           # optional; see "Overlap policy" below
    hints:      [batch-find]     # optional; work several positions ahead per call
    patterns:   all
    emit_name_map: true
```

The grid: `match_*` is anchored, `scan_*` is not; `_any` is one arbitrary
matching pattern, `_all` is every matching pattern. `find` is the only
capability that reports positions and extents.

At least one capability must be declared. Every capability value must be a
valid identifier in all six stub languages (see
[cli.md](cli.md#export-name-rules)).

> **Retired keys — all load errors, none silent.** Config parsing is strict, so
> a retired key fails as a line-numbered unknown-field error.
>
> - **`match:` and `scan:`** are gone. `match_any(...) >= 0` is exactly what
>   `match` returned and `scan_any(...) >= 0` what `scan` returned, and the
>   redundancy measured at 1-3% of module size. Dropping the KEYS was the
>   point: keeping `match:` with `match_any` semantics would leave every
>   existing config compiling while its callers silently switched from reading
>   0/1 to reading an id — and id 0 would read as "no match". A removed key
>   fails at build; a redefined one fails in production.
> - **`find_batch:`** is gone. Batching is a property of `find` now, requested
>   with `hints: [batch-find]`. The two were never distinguishable at the API
>   level — same matches, same order, cursor and gate array stub-owned — and
>   the only caller-visible difference is how much work one host crossing does.
>   That is a parameter, not a name.
> - **`find_any`, `find_all`, `batch_size`** were retired earlier and stay so.

### What "anchored" means here

`match_any` and `match_all` require **full consumption**: the pattern
must match from position 0 to `len`, i.e. `\A(?:p)\z`. A pattern matching a
proper prefix does not count. This is the same rule the single-pattern
`match_func` has always used.

### The range of `offset`

Valid values are `0 <= offset <= len`. `offset == len` is a **real position and
is evaluated**: end-anchored patterns (`…$`, `…\z`) and empty-matchable ones can
match there. `offset > len` yields the capability's "nothing" result —
`scan_any` −1, `scan_all` no ids, `find` 0, a batching `find` a finished cursor
with count 0 — rather than being an error or wrapping around.

`ptr`/`len` always describe the **whole** input; `offset` bounds only the
search.
That is what lets `^`, `\A`, `\b` and `(?m:^)` judge their real neighbours when
you resume a scan mid-input, instead of treating `from` as a new start of text.

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

The buffer that holds one position's matches is `<SET>_PATTERN_COUNT` tuples,
the exact worst case for a single start, and every stub sizes it that way.

**C is fill-and-count rather than an iterator**, because C has no iterator
protocol and the raw ABI already fills a buffer and returns a count — which is
also the C idiom (`read`, `getdents`, `recv`):

```c
rx_set_match_t buf[SECRET_SCANNER_PATTERN_COUNT];
rx_secret_scanner_scanner_t sc;
if (scan_secrets_init(&sc, input, len, 0) != 0) { /* RX_ERR_* */ }
for (int n; (n = scan_secrets(&sc, buf, SECRET_SCANNER_PATTERN_COUNT)) > 0; )
    for (int i = 0; i < n; i++) { /* buf[i] */ }
```

The scanner holds the INPUT as well as the position: the input never changes
during a scan while the position changes every step, so remembering the
position and taking the input on every step was backwards — and it let a caller
pass a DIFFERENT buffer on a later step with the stored position silently
indexing into it.

The return is the position's TOTAL, which may exceed `cap`: the call is
transactional, so it writes `min(total, cap)`, records no gate and does not
advance, and `n > cap` means "grow and call again, same position". Sizing `cap`
at `<SET>_PATTERN_COUNT` makes overflow impossible. Everywhere else the buffer
stays stub-owned and invisible.

The order of the matches *within* one call is unspecified — not by pattern id,
not by extent, not stable across compiler versions. Sort what you collect if
you need a specific order.

### Batching — the same matches, several positions per call

```yaml
sets:
  - name: secret_scanner
    find:  scan_secrets
    hints: [batch-find]
```

`find` returns one position per call, which is the right shape for a caller who
may stop early: nothing is computed for matches you never ask for. That costs
one host-boundary crossing per position, and on a dense input the crossings
dominate.

`batch-find` makes the opposite trade. One call fills a buffer with the matches
of as many CONSECUTIVE positions as fit, so a caller who intends to consume
everything crosses the boundary once per bufferful. It reports exactly the same
matches, in the same order, under the same overlap policy.

**It is a hint, not a capability, and that is the point.** The two shapes were
never distinguishable at the API level — same matches, same order, and the
cursor and gate array are stub-owned and invisible. The only caller-visible
difference is how much work one host crossing does, and therefore what you have
paid for if you stop early. That is a parameter, not a name: a second function
called `find_batch` reads as "same thing, fewer calls", which invites it as the
default, and it is the wrong default for any scan that stops early.

**It costs module size, which is why it is opt-in.** A batching set emits a
second entry point alongside `find`, plus the cursor and resume loop. Both are
driven by ONE shared per-position worker, so the bucket code is not duplicated.

**Only JavaScript and TypeScript expose it.** Batching amortises host-boundary
crossings and nothing else — SETS §20.1 measures `find` and a batched find
within 12.3% of each other in fuel, with `find` the CHEAPER one in-wasm, while
they differ 45x-76x in wall clock. C, Go, Rust and AssemblyScript are compiled
to wasm and merged, so their call into the module is a direct call inside one
module and there is no boundary to amortise. In those four the hint changes
nothing about the generated API; in JS/TS it adds an optional `batchSize`
parameter to `find` and a `<set>BatchMaxSize` constant:

```ts
// without the hint — no batchSize parameter at all, so TypeScript rejects
// find(input, 0, 64) at build time and no runtime check is needed
export function* scan_secrets(input, offset?): Generator<SetMatch>

// with hints: [batch-find]
export const secretScannerBatchMaxSize: number;
export function* scan_secrets(input, offset?, batchSize?): Generator<SetMatch>
```

`batchSize` sizes a batch of POSITIONS to work ahead, clamped into
`[1, <set>BatchMaxSize]`. The limit is the cursor layout rather than a policy,
and never binds in practice — 524,287 tuples is a 6 MB buffer.

#### The cursor

The cursor is one `i64`, and it is **opaque**: the stub passes back the value
the previous call returned, unchanged. A first call passes `offset << 32`. Only
two things about it are public, and only a direct WASM caller ever sees them:

| field | meaning |
|---|---|
| bits 63..32 | `0xFFFFFFFF` means the scan is finished — otherwise this is internal |
| low count bits | `count` — how many tuples of the buffer are valid |

The done flag arrives on the **same call that delivers the final matches**, so
a finished scan costs no extra call. `count` is needed alongside it because the
last call is normally a partial fill and the buffer is reused: the slots past
`count` still hold tuples from the previous call.

`0xFFFFFFFF` rather than `0` is the sentinel because **0 is a legal resume
position** — a first call whose buffer fills on the matches at position 0 must
resume at 0.

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

`overlapping` affects `find` and nothing else. On a set without it the key is
silently ignored — there is no find body for it to select, so it has no
effect.

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
- An **overflowing call reports no match as delivered** — if the return value
  exceeds `out_cap`, no gate is recorded for the position, so growing the
  buffer and calling again with the same `from` returns the same total and the
  same matches. The guarantee is on the **answer**, not on the bytes: a call on
  a fresh array may still write *eliminations* into it first (a pattern that
  matches nowhere at or after `from` is gated out once, up front, instead of
  being re-tested at every position). An eliminated pattern cannot match, so no
  answer changes — but do not compare the array byte-for-byte and expect it to
  be untouched. The same applies to an `out_cap = 0` size probe.

The generated stubs own the gate array on your behalf; it never appears in
their public surface. Only a direct WASM caller sees it.

Keeping the state visible is what makes `find` resumable at *any* index: an
array held inside the module would silently carry gates from an earlier scan
into a caller that meant to start fresh.

With `overlapping: true` there is no gate array and no gate parameter at all.

A batching `find` carries the same gate array, and none when overlapping. It
differs in one respect, and only internally: it records gates for the matches
it DELIVERED rather than only for a position that fitted whole.
That is what lets it resume inside a split position — the patterns already
handed to you are gated out, so re-entering the position yields exactly the
remainder. Callers see no difference; `find`'s transactional rule above is
unchanged.

## What each capability costs

Only `find` reports extents, and only it needs the machinery to resolve them.
Declaring less emits less:

| capability | literal frontend | backward prefix DFA | per-pattern extents | output |
|---|---|---|---|---|
| `match_any`, `match_all` | ✗ | ✗ | ✗ | id / bitmask |
| `scan_any`, `scan_all` | ✓ | ✓ | ✗ | id / bitmask |
| `find` | ✓ | ✓ | ✓ | tuples (+ gates by default) |

A set that does not declare `find` emits no tuple-writing suffix functions at
all — just the DFA tables, which the cheap bitmask probes share. An
anchored-only set additionally emits no literal frontend: the
packed-pair/Teddy/AC/Shufti tables and skip loop could never execute for it.

Measured on a 100KB no-match corpus with eight literal-prefixed patterns:
`match_any`/`match_all` 84 fuel, `scan_all` 219K, `find` 219K. The anchored trio dies within a byte or two of position 0;
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
Otherwise they take an `out_ptr` and write a `ceil(P/8)`-byte little-endian
bitmap, returning the count instead. The generated stubs expand either form
into the language's natural list of ids; the bitmask never reaches a stub user.
A direct caller must pass an **all-zero** bitmap: the module only ORs bits in
and counts 0→1 transitions, so a reused dirty buffer reports stale patterns.

Two things select the `out_ptr` form, not one. The second is a set containing a
pattern that fell back to the **Backtracking engine** — see "When a set member
falls back to Backtracking" below — and it applies at any id space, including a
two-pattern set. A direct WASM caller cannot assume the form from the pattern
count alone; the generated stubs work it out for you, and `--diag-json` names
the responsible buckets as `"bt-fallback"`.

### Pattern ids and the two emitted constants

A `pattern_id` is the pattern's **global** index into `regexps:`, so a set that
selects a subset does not renumber: a set holding the last two of seventy
patterns reports ids 68 and 69. Two constants therefore accompany every set,
and they are not interchangeable:

| constant | value | sizes |
|---|---|---|
| `<SET>_PATTERN_COUNT` | patterns in the set | the `find` tuple buffer (`out_cap`), and the width of the batch cursor's `k` field |
| `<SET>_ID_SPACE` | largest reportable id + 1 | the gate array, the `_all` bitmask/bitmap, and which `_all` ABI is exported |

For `patterns: all` — the common case — the two are equal. They diverge only
for a named subset, and using the wrong one there is a memory-safety bug: the
gate array is indexed by pattern id, so sizing it at the pattern count lets the
module write past the caller's array. Both constants are emitted in all six
stub languages, and every generated declaration is written in terms of the
right one.

`scan_any` returns a bare pattern id as an `i32`, or `-1`. It reports **no
position**, and that is deliberate rather than an omission: a non-anchored DFA
knows where a match ENDS, not where it began, so reporting the leftmost start
forced an anchored probe at every position — 78 fuel/byte against 27 for the
single union-automaton pass it compiles to now. The id is free either way,
because that pass accumulates an id bitmask. Do not use `scan_any` to locate
something for `find`; use `find`.

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
| Max fallback-bucket DFA states | 1024 | `max_fallback_states` (top-level config key) |

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
find any patterns this happened to, and raise `max_fallback_states` in the
config to admit them.

This is the one budget in the table whose effect is not a slower path but a
MISSING pattern: a single pattern over `max_dfa_states` falls back to another
engine and still matches, while a set member over `max_fallback_states` is
absent from the set and can never match. The build still succeeds, so a
pipeline that only checks the exit code will ship a set that under-reports —
read the warning, or `state_limit_dropped`.

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

## When a set member falls back to Backtracking

A set member whose fallback-bucket DFA exceeds `max_fallback_states` is not
dropped: it is compiled on the **Backtracking engine** instead, so the member
behaves like the same pattern compiled on its own. Backtracking is the only
engine here not bound by a compiled table size — it walks the NFA with an
explicit stack — which is what lets it take a pattern no table budget will fit.

It narrows the drop set rather than emptying it. A pattern whose NFA is larger
than the engine's own instruction cap, or that trips its loop checks, is still
excluded, still warned about, and still recorded in `--diag-json`'s
`state_limit_dropped`. Buckets that were admitted appear there as
`"bt-fallback"`, with `suffix_states` and `table_bytes` of 0 — they have no
table.

**One consequence reaches the ABI.** Every other set engine is table-driven and
always finishes with a definite answer: pattern *k* matched, or it did not.
Backtracking has a third outcome — an exhausted frame budget means it abandoned
part of the search space and does **not know**. Reporting that as "no match"
would turn giving up into a confident wrong answer, so it gets its own channel:

| capability | how "unknown" arrives |
|---|---|
| `scan_any` | the return is `-2`, distinct from `-1` for "no match" |
| `match_all`, `scan_all` | these use the `out_ptr` form for this set at any id space, so the return is a count — and `-2` there is the sentinel |
| `find` | the return is `-2` instead of a match count |
| `find`'s batch entry | the cursor's resume-position word is `0xFFFFFFFE`, beside `0xFFFFFFFF` for "done", with a zero count |

The generated stubs surface it the way that language reports an unanswerable
call — Rust and Go **panic**, JS, TS and AssemblyScript **throw**, C returns
`RX_ERR_BT_OVERFLOW` — matching what they already do for a single pattern that
overflows. What none of them do is quietly report "nothing matched".

A set with no Backtracking member is completely unaffected: it keeps the `i64`
bitmask form and none of these checks are emitted.

## Examples

- [examples/node/sql-validator/](../examples/node/sql-validator/) — anchored `match_any`, SQL statement validation (Node.js / TypeScript)
- [examples/wasmtime/go/secret-scanner/](../examples/wasmtime/go/secret-scanner/) — `find`, secret detection (Go wasip1)
- [examples/wasmtime/rust/secret-scanner/](../examples/wasmtime/rust/secret-scanner/) — `find` called directly from a native Rust host, gate array and all
- [examples/fastedge/url-guard/](../examples/fastedge/url-guard/) — `scan_any`, URL rule matching (FastEdge)
