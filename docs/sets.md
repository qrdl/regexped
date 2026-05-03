# Set Composition

Set composition lets you compile multiple regex patterns into a single
multi-pattern matcher that scans the input once and reports all matches with
their positions and pattern IDs — in one WASM call.

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
    chooseLiteralFrontend() ← Teddy (≤8 literals) or AC (>8) or scalar
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
receives `count` (tuples written). After each batch, advance
`start_pos = last.start + max(last.length, 1)` and re-call until count = 0.

### match — match tuples (8 bytes each)

```
out_ptr + i*8 + 0 : pattern_id  i32   global YAML order index
out_ptr + i*8 + 4 : end_pos     i32   byte position where match ends
```

`start` is always 0 for anchored match and is not included in the tuple.

## Batched streaming and batch_size

`find_all` iterators are batched: the WASM function writes up to `out_cap`
tuples per call. The `batch_size` YAML field controls the default buffer size
used in generated stubs (default 256). Tune it:

- **Dense matches** (many matches per KB): increase `batch_size` to amortise
  host↔WASM transition overhead
- **Memory-tight environments**: reduce `batch_size`

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
    println!("{} at {}..{}", pattern_name(m.pattern_id as u32), m.start, m.end);
}
```

## Bin-packing and merge constraints

The bin-packer groups patterns by their mandatory literal and merges compatible
suffix DFAs within each group:

| Constraint | Default | Config field |
|---|---|---|
| Max patterns per bitmask bucket | 64 | `bitmask_width` (internal) |
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
| ≤ 8 distinct literals, all 1–4 bytes | **Teddy** — SIMD nibble fingerprint, near-zero false positives |
| > 8 literals, or any literal > 4 bytes | **Aho-Corasick** — byte-at-a-time, O(n) regardless of literal count |
| No mandatory literals (fallback buckets) | **Scalar** — position-by-position check |

> **Future:** multi-pass Teddy (8 literals per pass, OR-ed results) could cover
> 9–64 literals with cost proportional to ⌈N/8⌉ passes, outperforming AC for
> moderate-sized sets. See plan note in `plans/COMPOSING_PATTERNS_PLAN.md`.

## Examples

- [examples/wasmtime/rust/sql-validator/](../examples/wasmtime/rust/sql-validator/) — anchored `match`, SQL statement classification
- [examples/wasmtime/rust/secret-scanner/](../examples/wasmtime/rust/secret-scanner/) — `find_all`, secret detection
- [examples/wasmtime/rust/crs-scanner/](../examples/wasmtime/rust/crs-scanner/) — `find_all`, OWASP CRS WAF rules
