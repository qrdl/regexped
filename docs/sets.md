# Set Composition

Set composition lets you compile multiple regexp patterns into a single
multi-pattern matcher that scans the input once and reports all matches with
their positions and pattern IDs.

## When to use set composition

| Situation | Recommendation |
|---|---|
| Scanning text for any of N patterns (WAF, secret scanning, log analysis) | Use `find_all` set |
| Classifying input by which pattern matches from position 0 (URL validation, SQL type detection) | Use `match` set |
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
    assembleModuleWithSets() ← emit WASM: suffix DFAs + set match function
```

## YAML configuration

```yaml
regexps:
  - name: aws_key          # name: required for sets.patterns list references
    pattern: 'AKIA[0-9A-Z]{16}'
  - name: github_pat
    pattern: 'ghp_[0-9a-zA-Z]{36}'

sets:
  - name: secret_scanner
    find_all: scan_secrets  # export name for the non-anchored all-matches function
    find_any: scan_first    # export name for the non-anchored first-match function
    match: validate         # export name for the anchored match function
    batch_size: 256         # output buffer size (stub-gen knob; default 256)
    emit_name_map: true     # emit pattern_name(id) helper in generated stubs
    hints: [prefer-no-match] # optional; this set's LikelyMode default (see below)
    patterns:
      - aws_key
      - github_pat
      # or: patterns: "all"   ← include every entry in regexps:
```

At least one of `find_all`, `find_any`, or `match` must be set per entry.

### `hints:` — this set's LikelyMode default

`hints: [prefer-match]` or `hints: [prefer-no-match]` (mutually exclusive)
biases the set's own compiled code shape — see [prefer-hints.md](prefer-hints.md)
for the full mechanism. Concretely, for sets this affects:

- the [literal scan frontend](#literal-scan-frontend) selection below
  (`prefer-no-match` forces Shufti over scalar for a 17–64-byte first-byte
  union, regardless of the density heuristic);
- the [bin-packing](#bin-packing-and-merge-constraints) gate that avoids
  merging counted-class-chain-eligible patterns together under
  `prefer-match`.

**Per-pattern `hints:` on individual `regexps:` entries are not consulted
for patterns placed inside a set** — only the set's own `hints:` field is
read when compiling set members. A pattern's `hints:` only takes effect
when that pattern is also compiled standalone (via its own `match_func`/
`find_func`/`groups_func`/`named_groups_func`).

**`batch-find` (docs/cli.md) is a separate, per-pattern-only mechanism and is
rejected outright on a `sets:` entry's `hints:`** — it is a load-time error,
not a silent no-op. Sets already have their own batching for `find_all` via
`batch_size` (see [Output tuple formats](#output-tuple-formats) below); the
two are unrelated and not interchangeable. A pattern's own `batch-find` hint
still applies normally to that pattern's *own* standalone exports even if the
pattern is also a set member — the set's `find_all`/`find_any`/`match`
exports are unaffected either way.

## Output tuple formats

### find_all / find_any — find tuples (12 bytes each)

```
out_ptr + i*12 + 0 : pattern_id  i32   global YAML order index
out_ptr + i*12 + 4 : start       i32   absolute byte offset of match start
out_ptr + i*12 + 8 : length      i32   byte length of match
```

The host calls with `(in_ptr, in_len, out_ptr, out_cap, start_pos)` and
receives `count` (tuples written). Tuples within a batch are emitted in
strictly non-decreasing `start` order.

**Resume rule.** After a batch of `count` tuples, let `last` be the final
tuple. To resume the scan, advance with

```
start_pos = last.start + 1
```

The WASM scan is position-by-position: it visits each input position in turn,
emits all matches anchored there, then increments. When the buffer fills it
exits at the *top* of the next iteration, so the only positions guaranteed to
have been visited in the batch are those `≤ last.start`. Advancing by
`last.length` (or `end`) would skip positions inside the last match's span
that the WASM has not yet scanned, silently dropping matches at those
positions.

**Mid-position truncation.** When `count == out_cap` the suffix DFA respects
the remaining capacity and stops writing as soon as the buffer is full, even
if more patterns match at `last.start`. To avoid losing same-position
matches, size `out_cap ≥ (number of patterns in the set)` — this guarantees
no single start position can produce more matches than the buffer holds, so
when the buffer fills it does so on a position boundary. Generated stubs
floor the effective capacity at `max(batch_size, 64, patterns_in_set)`, so
they always satisfy this. Hosts that bypass the generated stubs and want to
use a smaller buffer must dedupe `(pattern_id, start)` pairs across batches.

### match — match tuples (12 bytes each)

Same layout as `find_all`/`find_any`:

```
out_ptr + i*12 + 0 : pattern_id  i32   global YAML order index
out_ptr + i*12 + 4 : start       i32   always 0 for anchored match
out_ptr + i*12 + 8 : length      i32   byte length of match
```

The host calls with `(in_ptr, in_len, out_ptr, out_cap)` and receives `count`
(tuples written; 0 if no pattern matches anchored at position 0). Anchored
match is not batched — one call returns all matching patterns, up to `out_cap`.
Each tuple occupies 12 bytes; decode three little-endian i32s at offsets 0, 4,
and 8. `end = start + length` (with `start = 0`).

> **Stub behaviour.** The generated stubs call the anchored `match` export
> with `out_cap = 1` and surface only the first matching pattern. Rust, Go,
> JavaScript, and TypeScript reuse the same `SetMatch { pattern_id, start, end }`
> shape used for `find_all`/`find_any` (with `start == 0`). The C and
> AssemblyScript stubs use a dedicated anchored type — `rx_set_anchor_t`
> (`{ pattern_id, end }`) and `SetAnchorMatch` (`{ patternId, end }`)
> respectively — which omits the always-zero `start` field. This is a
> deliberate ergonomic choice for the common "which pattern matches here?"
> use case. Hosts that need every pattern matching at position 0 must call
> the WASM export directly with `out_cap ≥ patterns_in_set` and decode the
> tuple buffer as described above.

## Batched streaming and batch_size

`find_all` iterators are batched: the WASM function writes up to `out_cap`
tuples per call. The `batch_size` YAML field controls the default buffer size
used in generated stubs (default 256). Tune it:

- **Dense matches** (many matches per KB): increase `batch_size` to amortise
  host↔WASM transition overhead
- **Memory-tight environments**: reduce `batch_size`

The stub generator always raises the effective capacity to at least
`max(64, patterns_in_set)`, so a single start position can never overflow the
buffer and the `last.start + 1` advance rule (see "Resume rule" above)
remains safe regardless of the configured `batch_size`. Custom hosts that
bypass the generated stubs and use a smaller `out_cap` must dedupe
`(pattern_id, start)` pairs to handle mid-position truncation.

`batch_size` is a stub-generation knob and does not affect the WASM binary.

## pattern_name helper

When any set has `emit_name_map: true`, the stub generator emits a single
file-wide `pattern_name(id)` lookup function built from the `name:` fields
in `regexps:`. The function maps a global pattern ID back to the name string.
It is emitted exactly once even when multiple sets opt in; it is never
set-prefixed since pattern IDs are file-wide YAML order indices.

```rust
// Example Rust usage
for m in scan_secrets(input) {
    println!("{} at {}..{}", pattern_name(m.pattern_id), m.start, m.end);
}
```

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
and per-set `frontend` (`"teddy"`/`"ac"`/`"scalar"`/`"shufti"`), `buckets`,
`conflicts`, `capture_bearing_dropped`, and `state_limit_dropped` (patterns
dropped for exceeding a fallback bucket's state budget — see
[Bin-packing](#bin-packing-and-merge-constraints) above) arrays.

## Literal scan frontend

| Condition | Frontend |
|---|---|
| 1–16 distinct literals | **Teddy** — SIMD nibble fingerprint; literals >4 bytes use their first 4 bytes as the probe and verify remaining bytes in dispatch |
| 17+ distinct literals | **Aho-Corasick** attempted first — byte-at-a-time, O(n) regardless of literal count |
| (AC automaton exceeds 32 trie nodes) | **Scalar** — AC is capped by *automaton node count*, not literal count; a set of 17+ literals sharing no common prefixes can blow past 32 nodes and downgrade, while literals with heavy shared prefixes could in principle stay under the cap well past 32 |
| No mandatory literal at all | **Scalar** |

For 9–16 literals Teddy uses two groups of 8 (`TwoGroups=true`), ORing the
results of two independent nibble probes per 16-byte chunk.

### Shufti — SIMD first-byte prefilter for the scalar case

When the frontend would otherwise be scalar (no mandatory literal, or AC
downgraded per the table above), a fourth frontend — **Shufti** — is
considered instead of going straight to scalar. It requires:

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

## Anchored `match` and patterns without a mandatory literal

The anchored `match` export classifies which pattern(s) in a set match the input
starting at position 0. Patterns are routed at compile time into buckets keyed by
their mandatory literal (a fixed byte sequence that must appear in every match).
Patterns with no extractable mandatory literal — most commonly case-insensitive
patterns (those using `(?i)`, whose literals carry `FoldCase` and are excluded
from literal extraction) — route to a **fallback bucket** instead.

For `match`, fallback bucket patterns are evaluated at position 0 by running the
bucket's combined suffix DFA directly: no literal scan is performed, but the
bucket's patterns still participate in matching. They will be reported in the
result tuples just like literal-bucket patterns.

The trade-off is purely a performance one: literal-bucket patterns benefit from
the SIMD/Aho-Corasick prefilter, fallback-bucket patterns do not. For a fixed
keyword vocabulary where you control the casing, writing patterns without `(?i)`
and using a single uppercase literal lets them flow into literal buckets and run
faster — but it is not required for correctness.

## Examples

- [examples/node/sql-validator/](../examples/node/sql-validator/) — anchored `match`, SQL statement validation (Node.js / TypeScript)
- [examples/wasmtime/go/secret-scanner/](../examples/wasmtime/go/secret-scanner/) — `find_all`, secret detection (Go wasip1)
- [examples/wasmtime/rust/secret-scanner/](../examples/wasmtime/rust/secret-scanner/) — `find_all`, secret detection (native Rust host)
- [examples/fastedge/url-guard/](../examples/fastedge/url-guard/) — `find_any`, URL rule matching (FastEdge)
