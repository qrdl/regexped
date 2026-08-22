# RE2 Test Coverage

Regexped is validated against the RE2 exhaustive test suite, which ships with
the Go standard library at `$GOROOT/src/regexp/testdata/re2-exhaustive.txt.bz2`.

The suite contains ~5.7M test cases covering a wide range of patterns and inputs.
Each case specifies a pattern, an input string, and the expected match result
(end position for anchored match, start+end for non-anchored find, or capture
slot positions).

---

## How to run

```bash
make re2test          # from repo root
# or
make test             # from tools/re2test/
```

Test data is unpacked automatically from the Go standard library.

The `test` target chains ten single-pattern sub-targets — `exhaustive`, `custom`,
`adjusted`, `force-backtrack`, `likelymatch`, `likelynomatch`,
`force-backtrack-likelynomatch` (the last three re-run the corpus under each
`LikelyMode` to verify the mode never changes match correctness, only emitted
code shape — see [prefer-hints.md](prefer-hints.md)), and `matchonly`,
`findonly`, `groupsonly` — plus `sets` and `set-batch`, which exercise the
multi-pattern composition pipeline described in [sets.md](sets.md).

The last three compile each pattern with only one of `match_func`,
`find_func`, `groups_func` set. That is not redundant with the default
combined compile: `compile.go` has call sites gated on `needMatch &&
!needFind` and on `needFind && !needMatch` (the Gap E alt-prefixed find body,
the Gap C alt-range find body, the strict and lenient alt find bodies) which
a match+find compile never reaches at all, so several emitters are invisible
without them.

---

## Current results

**Exhaustive test** (`re2-exhaustive.txt`, match and find only):

| Engine | Passing cases |
|---|---|
| DFA | ~334,000 |
| Compiled DFA | ~4,602,000 |
| **Total passing** | **~4,936,000** |
| **Failed** | **0** |
| **Skipped** | **~781,000** |

**Adjusted test** (`re2-adjusted.txt`, with `--validate-groups`):

| Engine | Passing cases |
|---|---|
| DFA | ~360,000 |
| Compiled DFA | ~1,211,000 |
| TDFA | ~41,000 |
| Backtracking | ~267,000 |
| **Total passing** | **~1,879,000** |
| **Failed** | **0** |

---

## Per-engine breakdown

### DFA / Compiled DFA (~4.94M passing)

The DFA and Compiled DFA engines handle all non-capture patterns (`match_func`,
`find_func`) and the DFA half of hybrid modules.

Tests covered:
- Anchored match (col 0): patterns without captures
- Non-anchored find (col 1): all patterns where find mode is safe (leftmostFirst
  semantics match RE2)

The Compiled DFA path applies when the minimised DFA has ≤ 256 states; it avoids
a runtime transition table and instead uses direct-index table access with a
compile-time literal-chain prefix optimisation.

### TDFA (~41K passing, via `--validate-groups`)

The TDFA engine handles `groups_func` / `named_groups_func` for patterns
where Laurikari's tagged DFA construction is feasible (no non-greedy quantifiers,
no line anchors, no word boundaries, no ambiguous alternations). Each test case
verifies both the match end position and all capture slot positions.

Examples of patterns handled by TDFA:
- `(?P<scheme>https?)://(?P<host>[^/:?#]+)...` — disjoint scheme alternatives
- `(\d{4})-(\d{2})-(\d{2})` — date capture with fixed delimiters
- `([a-z]+)(er)([a-z]+)` — a quantifier loop whose exit overlaps its own
  class no longer disqualifies TDFA on its own (task 13, 2026-08-01); see
  [engines.md](engines.md#engine-selection)

### Backtracking (~267K passing, via `--validate-groups`)

The Backtracking engine handles `groups_func` / `named_groups_func` for patterns
that are not TDFA-eligible — those with ambiguous alternations or overlapping
quantifiers. Each test case verifies both match position and capture slots.

**RE2 semantics are preserved via a hybrid approach** — both phases run inside
the single exported WASM function, with no logic in the host:

1. **Phase 1 (DFA)**: the captures-stripped pattern is run as a standard
   leftmost-longest DFA anchored match to determine the correct match end
   position E. If no match, return -1 immediately.
2. **Phase 2 (Backtracking)**: the NFA backtracking engine runs constrained to
   `pos == E` at `InstMatch`. It fills capture slots within the range `[0, E]`.

This ensures patterns like `(a*)*?` return the same result as RE2 (longest
match), not Perl semantics (shortest match), while keeping all matching logic
inside WASM.

Examples of patterns handled by Backtracking:
- `<([^>]+)>` — the loop's exit branch has an indeterminate first-byte set
  (inverted class wider than 256 codepoints), which stays ambiguous
  regardless of the task 13 quantifier-loop relaxation
- `(.*)(foo)(.*)` — greedy capture consuming into next group (same
  indeterminate-branch reason: `.` can't be resolved to a finite first-byte set)

### Sets (`make sets`)

Set composition is validated by replaying multi-pattern blocks from the RE2
exhaustive suite and a curated `custom-sets.txt` file through the set pipeline
described in [sets.md](sets.md). For every block with at least two patterns the
runner:

1. Compiles all patterns as a single set via `CompileFile` with the default
   (per-pattern non-overlapping) `find`, whose contract is Go `FindAllIndex`'s
   rule — which is exactly what col4 holds.
2. Runs the resulting WASM against every test input in the block.
3. Verifies that the returned `(pattern_id, start, length)` tuples cover all
   per-pattern matches expected by columns 4 / 1 of the RE2 test format.

This exercises all set frontends — SIMD Teddy (≤ 16 literals), Aho-Corasick
(17+ literals, capped by table bytes rather than literal count), SIMD Shufti
(density/hint-selected first-byte prefilter), and the scalar DFA fallback —
together with bucket dispatch and the isolated-fallback path for non-greedy
patterns. Note that the RE2 corpus's set blocks are small, so they cover the
frontends' *semantics* rather than their scaling; per-shape scaling is
measured separately by `tools/setperf` and the fuel ladder in
[plans/SETS.md](../plans/SETS.md) §14. See [sets.md](sets.md) for the exact frontend-selection
rules. Set tests currently run
clean with **0 failures**.

### Batched sets (`make set-batch`)

The same corpus, the same col4 oracle, driving `find_batch` instead of `find`
at a buffer capacity of **one**. That capacity is the point: it makes every
position with more than one match split, so the corpus exercises `find_batch`'s
resume path — and with it the delivered-tuple gate rule of
[plans/SETS.md](../plans/SETS.md) §19 — at every empty-match shape, anchor and
extent it contains, rather than at the handful a hand-written test can think
of. Also runs clean with **0 failures**.

---

## Skipped cases (~781K)

### Unicode support not implemented (~270K)

Patterns or inputs containing characters outside the ASCII range (code points
> 127) require Unicode character class expansion (`\p{L}`, `\p{Digit}`, etc.).
Regexped currently operates on byte-level input only. All such test cases are
skipped.

Skip reason: `requires Unicode support`

### Unsupported `\C` syntax (~511K)

The RE2 test suite includes patterns using `\C`, which matches any single byte
(including bytes that are part of a multi-byte UTF-8 sequence). This syntax is
not supported by Go's `regexp/syntax` package and is rejected at parse time.

Skip reason: `unsupported RE2 syntax (invalid escape sequence)`

---

## What remains unimplemented

| Category | Count | Required feature |
|---|---|---|
| Unicode character classes | ~270K | Unicode mode (large table expansion) |
| `\C` byte escape | ~511K | Depends on Go `regexp/syntax` support |
