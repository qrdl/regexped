# Set Composition

Set composition lets you compile multiple regex patterns into a single
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
    chooseLiteralFrontend() ← Teddy (≤16 literals) or AC (17–32) or scalar
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
    patterns:
      - aws_key
      - github_pat
      # or: patterns: "all"   ← include every entry in regexps:
```

At least one of `find_all`, `find_any`, or `match` must be set per entry.

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
tuple. If `count < out_cap` the batch is complete for all positions up to and
including `last.start`; advance with

```
start_pos = last.start + max(last.length, 1)
```

If `count == out_cap` the batch may have been truncated mid-position (the
suffix DFA respects the remaining capacity and stops writing as soon as the
buffer is full, even when more patterns match at `last.start`). To resume
safely in this case the host must either:

- size `out_cap ≥ (number of patterns in the set)` — guaranteeing no single
  start position can produce more matches than the buffer holds, after which
  the advance formula above is always safe; **or**
- resume at `start_pos = last.start` and dedupe any `(pattern_id, start)`
  pairs already emitted in the previous batch.

Generated stubs use the first option: the stub generator floors the effective
capacity at `max(batch_size, 64, patterns_in_set)` (see "Batched streaming and
batch_size" below), so generated stubs are always safe regardless of set size.
Custom hosts that do not apply this floor must use the dedupe-on-truncation
resume rule, or risk missing same-position matches.

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

## Batched streaming and batch_size

`find_all` iterators are batched: the WASM function writes up to `out_cap`
tuples per call. The `batch_size` YAML field controls the default buffer size
used in generated stubs (default 256). Tune it:

- **Dense matches** (many matches per KB): increase `batch_size` to amortise
  host↔WASM transition overhead
- **Memory-tight environments**: reduce `batch_size`

The stub generator always raises the effective capacity to at least
`max(64, patterns_in_set)`, so a single start position can never overflow the
buffer and the standard advance rule (`last.start + max(last.length, 1)`)
remains safe regardless of the configured `batch_size`. Custom hosts that
bypass the generated stubs must apply the same floor themselves or use the
dedupe-on-truncation resume rule described above.

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

Patterns that cannot be merged (no mandatory literal, literal inside quantifier,
budget exceeded) route to fallback buckets that scan every input position.

## Diagnostics

Use `--diag-json <path>` with `regexped compile` to write a JSON file
describing how patterns were placed:

```bash
regexped compile --config=regexped.yaml --diag-json=diag.json
```

The JSON contains `patterns_total`, `capture_bearing` (dropped from sets),
`prefix_dedup_pool_size`, and per-set `buckets` and `conflicts` arrays.

## Literal scan frontend

| Condition | Frontend |
|---|---|
| 1–16 distinct literals | **Teddy** — SIMD nibble fingerprint; literals >4 bytes use their first 4 bytes as the probe and verify remaining bytes in dispatch |
| 17–32 distinct literals | **Aho-Corasick** — byte-at-a-time, O(n) regardless of literal count; capped at 32 automaton nodes |
| >32 literals, or no mandatory literals | **Scalar** — position-by-position check |

For 9–16 literals Teddy uses two groups of 8 (`TwoGroups=true`), ORing the
results of two independent nibble probes per 16-byte chunk.

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
- [examples/fastedge/url-guard/](../examples/fastedge/url-guard/) — `find_all`, URL rule matching (FastEdge)
