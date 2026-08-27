# `prefer-match` / `prefer-no-match` hints

`prefer-match` and `prefer-no-match` are optional per-pattern (or per-set)
compile hints that tell regexped how you expect a pattern to be used, so the
compiler can bias its code-shape choice toward that expectation. They never
affect match correctness — only which emission strategy is chosen and how big
the resulting WASM is. `re2test` passes its full corpus under both hints and
under no hint at all.

For the third hint value, `batch-find` (a `<func>_batch` WASM export for
draining several matches per host call), see [`hints:`](cli.md#hints--likelymode-and-batch-find-compile-hints)
in the CLI reference — it's an unrelated, independent mechanism and is
JS/TS-only.

## What they do

| Hint | Intent | Trade-off |
|---|---|---|
| *(none)* | Balanced default | Gets every optimisation that's safe for any workload. Most patterns should start here. |
| `prefer-match` | "matches are the common case; a miss is the cold path" | Biases toward faster accept, willing to spend a little more on the reject path. |
| `prefer-no-match` | "misses are the common case; scan-and-exit is the hot path" | Biases toward faster reject/scan, willing to spend a little more when a match does occur. |

They're mutually exclusive — a pattern can't set both.

## Setting the hint

```yaml
regexps:
  - pattern: 'AKIA[A-Z0-9]{16}'
    match_func: aws_key_match
    hints: [prefer-match]

sets:
  - name: creds
    find: creds_find
    patterns: "all"
    hints: [prefer-no-match]
```

A `regexps:` entry's hint governs that pattern's own compiled body
(`match_func`/`find_func`/`groups_func`). A `sets:`
entry's hint governs that set's own frontend and suffix-body choices — it is
not inherited by member patterns' own directly-exported bodies. There's no
enclosing-set or global fallback: each entry that wants a hint sets its own.

## Which shapes actually benefit

A lot of what used to require a hint is now unconditional — every pattern
gets the dominant-self-loop bulk-skip and the counted-chain SIMD verifier
regardless of what you set. Setting a hint only matters for the narrower set
of shapes below; everything else compiles to byte-identical WASM whether you
set a hint or not.

**`prefer-match` targets:**
- A literal-plus-counted-class chain shorter than the unconditional
  threshold — e.g. `AKIA[A-Z0-9]{16}` (16 repeats; chains of 24+ already get
  this treatment unconditionally). Typical of short fixed-format secrets/IDs.
- A bare, no-literal-prefix character class run with a guaranteed minimum
  length of 8+ bytes — e.g. `[A-Z]{8,}`, `[a-zA-Z0-9]{10,}`. Typical of
  identifier/token scanners. A minimum length below 8 (e.g. `(\w+)`) doesn't
  qualify.

**`prefer-no-match` targets:**
- A first-byte set of roughly 17–64 distinct bytes in `find_func` mode (or
  the equivalent shared step inside a non-anchored `groups_func`) — e.g.
  `[a-zA-Z]{8,}`, `[a-zA-Z0-9_]{n,}`. Forces a
  SIMD-driven scan that pays off when most of the input isn't in that byte
  class, with a runtime fallback if the input turns out to be dense in it
  anyway (so it doesn't cost much even when your intuition is wrong).
- A fixed-count single-class literal-anchor prefix, count ≤ 16 — e.g.
  `[0-9]{16}INFO:[^\n]+`. Gets a SIMD chunk-verify instead of a scalar
  reverse walk on the anchor.
- On a **set**, the same first-byte-set situation forces the Shufti frontend
  instead of falling back to scalar for a 17–64-byte union of first bytes
  across the set's patterns.

If your pattern doesn't match one of these shapes, the hint is harmless but
won't change anything.

## The optimisations, briefly

- **Counted-chain SIMD verifier** — verifies a fixed-count character class
  run (`{N}`/`{N,M}`) in SIMD chunks instead of a scalar loop.
- **Dominant-self-loop bulk-skip** — for patterns dominated by one
  "consume anything except a delimiter" state, skips through the run in SIMD
  chunks instead of one byte at a time.
- **Shufti / SIMD prefix scan** — a nibble-table SIMD technique for
  detecting "any byte in this set" over a first-byte set too big for a
  handful of direct SIMD compares but too small to be worth a scalar
  byte-class table lookup.
- **Lit-anchor class-prefix SIMD verify** — same SIMD-chunk idea applied to
  the backward verification step of a literal-anchored find.

## Measure the actual effect on your pattern

The hint is a bet on your workload, not a guarantee — it can make things
*slower* than the default if your real traffic doesn't match the assumption
(e.g. `prefer-no-match` on a byte class that's actually dense in your typical
input). Don't set it on intuition alone; measure it with `tools/pattest`
against a representative sample of your own inputs:

```bash
cd tools/pattest
make run ARGS="-pattern '<your pattern>' -mode find -inputs your_inputs.txt"
```

`-inputs` is a text file, one candidate input per line. `pattest` compiles
your exact pattern under no hint, `prefer-match`, and `prefer-no-match`,
buckets your inputs into matching/non-matching using Go's standard `regexp`
package as ground truth, and reports fuel and average wall-clock time for
each mode against each bucket — so you can see directly whether a hint helps
*your* traffic before shipping it. `make example-lm` / `make example-lnm` /
`make example-combined` (from `tools/pattest`) run pre-built demonstrations
of each case above if you want to see the shape of a real win first.
