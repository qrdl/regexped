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
make test             # from re2test/
```

Test data is unpacked automatically from the Go standard library.

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
- `(GET|POST|PUT):\s+(.+)` — keyword alternatives with disjoint first bytes

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
- `(a|ab)c` — overlapping alternation branches
- `(a+)(a+)` — adjacent greedy quantifiers
- `(.*)(foo)(.*)` — greedy capture consuming into next group

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
