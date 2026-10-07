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
`findonly`, `groupsonly` — plus `sets`, which exercises the multi-pattern
composition pipeline described in [sets.md](sets.md) across all five
capabilities (plus `find`'s batch entry and both overlap policies). `sets-exhaustive` and `set-batch` are the whole-corpus set runs;
they are not part of `test` (see "Sets" below for why). `unicode` re-runs the
corpus's six blocks that hold characters above 0x7F in Unicode mode, against
RE2's own columns (see "Unicode-mode rows" below), and `sets-unicode` does the
same for every set capability (see "Sets in Unicode mode" below).

Three targets outside `test` run Unicode mode over the rest:
`unicode-all` re-runs EVERY block in Unicode mode, the all-ASCII ones included
(`-unicode-all`) — their answers are byte mode's, but each pattern is lowered
and its engine chosen as Unicode mode does, which `unicode`, skipping them,
never exercises (12,364,931 rows, 0 failures); `unicode-groups` is the same over
the capture-adjusted corpus with `--validate-groups`, the corpus's capture
bodies in Unicode mode (3,757,680 rows, 0 failures — TDFA 179,928, Backtracking
488,376); and `custom-unicode` runs `custom-tests.txt` that way, its rows naming
characters above 0x7F — which `custom` skips in byte mode — included (8,658
rows, 0 failures). A row whose input is not valid UTF-8, for a pattern that can
match U+FFFD, is skipped in Unicode mode: its columns are Go's, and Unicode mode
differs from Go there by design ("Invalid UTF-8 in the input", below) — 55 rows
of `custom-tests.txt`; the RE2 corpus has no such input.

`unicode-ext` runs those three and the rest of the byte-mode modes in Unicode
mode over the whole corpus: `unicode-likely` (both hints),
`unicode-force-backtrack`, `unicode-bt-fallback` (every Backtracking program
answered by its memoised fallback alone), `unicode-notes-armed`,
`sets-unicode-all` and `sets-unicode-likely` (the `sets` and `sets-likely`
runs, the all-ASCII blocks included, the batch entry and Backtracking members
too), and `unicode-variants`. That last one is the corpus's multi-byte and
invalid input: `make_adjusted -unicode-variants` rewrites every string of the
capture-adjusted corpus into three variants — a two-byte character inside it,
a three- and a four-byte one around it, a stray 0xFF and a cut sequence — and
computes every column, every match included, with Go over the pattern without
U+FFFD, so the columns are Unicode mode's own answers on invalid input too;
the harness reads such a file with `-unicode-oracle`, which judges every row.
None of these is in `test`. Current results, all 0 failures: `unicode-variants`
14,597,031 checks in each of its three legs (plain, armed notes, forced
Backtracking); `sets-unicode-all` 20,362,084; `sets-unicode-likely`
11,883,952; and every leg of the single-pattern mode targets.

The last three compile each pattern with only one of `match_func`,
`find_func`, `groups_func` set. That is not redundant with the default
combined compile: `compile.go` has call sites gated on `needMatch &&
!needFind` and on `needFind && !needMatch` (the alt-prefixed find body,
the alt-range find body, the strict and lenient alt find bodies) which
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
| **Skipped** | **~781,000** — ~270K need Unicode mode and are checked by `make unicode`; see [Skipped cases](#skipped-cases-781k) |

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

The TDFA engine handles `groups_func` for patterns
where Laurikari's tagged DFA construction is feasible (no non-greedy quantifiers,
no line anchors, no word boundaries, no ambiguous alternations). Each test case
verifies both the match end position and all capture slot positions.

Examples of patterns handled by TDFA:
- `(?P<scheme>https?)://(?P<host>[^/:?#]+)...` — disjoint scheme alternatives
- `(\d{4})-(\d{2})-(\d{2})` — date capture with fixed delimiters
- `([a-z]+)(er)([a-z]+)` — a quantifier loop whose exit overlaps its own
  class no longer disqualifies TDFA on its own (2026-08-01); see
  [engines.md](engines.md#engine-selection)

### Backtracking (~267K passing, via `--validate-groups`)

The Backtracking engine handles `groups_func` for patterns
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

Examples of patterns handled by Backtracking (in byte mode; in Unicode mode
both take a TDFA, see `docs/engines.md`):
- `<([^>]+)>` — the loop's exit branch has an indeterminate first-byte set
  (inverted class wider than 256 codepoints), which stays ambiguous
  regardless of the 2026-08-01 quantifier-loop relaxation
- `(.*)(foo)(.*)` — greedy capture consuming into next group (same
  indeterminate-branch reason: `.` can't be resolved to a finite first-byte set)

### Sets (`make sets`, `make sets-exhaustive`)

Set composition is validated by replaying multi-pattern blocks from the RE2
exhaustive suite and a curated `custom-sets.txt` file through the set pipeline
described in [sets.md](sets.md).

**Every capability is driven, not just `find`.** Until 2026-08-23
 this target declared one set with
`find` OR a batching `find`, `patterns: all` and no `overlapping` — so
`match_any`/`match_all`, `scan_any`/`scan_all` and the
overlapping `find` body had no corpus coverage at all, which is how five
wrong-answer/crash bugs survived 4.94M passing cases. Each chunk is now driven
through:

| driven | oracle |
|---|---|
| `match_any`, `match_all` | `\A(?:p)\z` over the whole input; membership (never value equality) for `_any` |
| `scan_any`, `scan_all` | "matches at some position ≥ `from`", at every `from` for short inputs and at the 16/32/33-byte edges for long ones |
| `find` gated, batching `find` gated at capacity 1 and P | Go `FindAllIndex` — cross-checked against the corpus's own col4 |
| `find` overlapping, batching `find` overlapping at capacity 1 and P | every start position's leftmost-first match |
| `find` through an under-sized buffer | `out_cap = 0` and the transactional-overflow rule |
| every capability at `from > len` | the "nothing" result |

Every expectation is computed **live from Go `regexp`** via a whole-input
technique (`\A(?s:.{p})(?:pat)`, which hands the pattern position `p` with its
real left context), so no oracle restates an emitter's own rule back at it.

Further dimensions matter, because the corpus alone supplies none of them. The
RE2 suite has only **27 blocks, of 132 to 7020 patterns each**, so one set per
block never crosses the thresholds the compiler specialises on from below
(packed-pair ≤ 16, Teddy ≤ 64, Aho-Corasick > 16, wide `_all` > 64):
`--set-chunk` fixes the set size, and `--set-shuffle` deterministically
permutes a block's patterns first, so a set holds unrelated patterns rather
than variations of one generator family. `--set-subset` makes the set select a
**named subset** rather than `patterns: all` — the only configuration in which
`<SET>_PATTERN_COUNT` and `<SET>_ID_SPACE` differ, and confusing those two is a
memory-safety bug rather than a wrong answer, since the gate array and the
`_all` bitmap are sized from the id space while the tuple buffer is sized from
the count. Separately, `--set-profiles` compiles each chunk under several
capability configurations, because the compiler emits only the machinery a
set's declared capabilities need — a `match`-only set emits no literal frontend
at all, and those specialised emissions are invisible to a set that declares
everything.

This exercises all set frontends — packed-pair (≤ 16 literals with a selective
two-byte probe window), SIMD Teddy (≤ 64 literals, 16 when the shortest is one
byte), Aho-Corasick (> 16 literals, capped by table bytes rather than literal
count), SIMD Shufti (density/hint-selected first-byte prefilter), and the
scalar DFA fallback —
together with bucket dispatch and the isolated-fallback path for non-greedy
patterns. Per-shape *scaling* is measured separately by `tools/setperf` and the
fuel ladder.

`make sets` samples the corpus, at **22,244,845 checks** over its ten runs, and
is part of `make test`; `make sets-exhaustive` is the same coverage over every
chunk. Both run clean with **0 failures**,
and the whole-block gated-`find` leg (`make set-batch`, which
`sets-exhaustive` runs last) reports **5,205,664**.

### Sets under a hint (`make sets-likely`)

`make sets` compiles every set **neutral**, so the emitters that only exist
under a hint were not covered by it at all: the SIMD skip in a bucket's suffix
body, the union scan's stride, the widened Shufti band, the counted-chain
packer split, and the forced-Shufti frontend. `make sets-likely` runs the same
capability sweep with `--likelymatch` and `--likelynomatch`, which reach the
set path as set-level `hints:` — so it compiles genuinely different bodies
against the same oracle, at **10,435,992 checks, 0 failures**. It is part of
`make test`.

Fewer configurations than `make sets` on purpose: a hint changes the emitted
body, not which capability is exported or which oracle answers for it, so the
chunk-size, subset and profile axes are already covered by the neutral run.
What is new here is the emission, and one chunk size per hint reaches it
across the whole corpus.

A pattern the compiler legitimately drops from a set — a fallback bucket's
suffix DFA over the `max_fallback_states` budget, or one the anchored packer
alone refused — is excluded from the comparison and counted separately in the
summary, so a documented exclusion cannot masquerade as either a pass or a
failure. The exclusion is taken from the compiler's own drop WARNING rather
than from `--diag-json`, and it is SCOPED by that warning's `where`: an
"anchored bucket" drop excludes the pattern from `match_any`/`match_all` only,
while a fallback-bucket drop excludes it from everything non-anchored. Merging
the two scopes would make the oracle expect matches from a pattern the module
no longer holds, or drop ones it still reports.

### Batched sets (`make set-batch`)

The older single-set-per-block shape, kept because it is the only configuration that compiles sets
of several thousand patterns: one set per corpus block, the same col4 oracle,
driving `find` and then its batch entry at a buffer capacity of **one**. That
capacity is the point: it makes every position with more than one match split,
so the corpus exercises the batch resume path — and with it the
delivered-tuple gate rule of — at every
empty-match shape, anchor and extent it contains, rather than at the handful a
hand-written test can think of. Also runs clean with **0 failures**.

### Sets in Unicode mode (`make sets-unicode`)

The set sweep with `-unicode`: every set is compiled in Unicode mode (the
set-level `unicode:` key states it), and the live oracle reads the input as Go
does — its whole-input probe `\A(?s:.{p})(?:pat)` counts Go's TOKENS, so p
steps through the positions where a character starts, and a position inside
one is expected to start no match, empty ones included. That is the rule the
set bodies keep and the one Go keeps; the scan pair at an `offset` inside a
character is answered from the next start. A high-byte input is its own twin
here: Unicode mode reads it as Go does. Two populations are skipped and
counted: the corpus's all-ASCII blocks, which Unicode mode answers exactly as
byte mode does and the byte-mode targets already check, and input that is not
valid UTF-8 beside a member that can match U+FFFD (where Go and Unicode mode
differ by design). Runs the corpus's blocks with characters above 0x7F,
`custom-sets.txt`, and `custom-sets-unicode.txt` — Go-regenerated blocks of
the shapes whose empty matches could land inside a character (`x*`, `(?:)`,
`\B`, `a?\B`, line and text anchors, `.` and negated classes) over 2- to
4-byte characters, invalid bytes, cut-off, overlong and surrogate sequences,
plus multi-byte literals and members a set splits out — neutral, under both
hints, on Backtracking members and through the batch entry. **34,513,565
checks, 0 failures** over its ten runs, the answer cache swept on every
forced-sweep leg the shape allows.

---

## Skipped cases (~781K)

### Unicode-mode rows (~270K)

Patterns or inputs containing characters outside the ASCII range (code points
> 127) need Unicode mode (`\p{L}`, `\p{Digit}`, `é`, etc.). The byte-mode
targets skip them, under `requires Unicode support`.

`make unicode` (from `tools/re2test/`) checks them: the six blocks that hold
such characters are compiled in Unicode mode and judged against RE2's own
columns — byte offsets, `.` reading a whole character — an oracle that is not
Go, plus Go's every-match column. 698,220 checks pass, 0 fail. Two kinds of
row are left out, each counted under its own reason: 2,696 where RE2's `\B`
holds between two bytes of one character — Go and Unicode mode keep no match
inside a character, and Go's own exhaustive test skips these rows too — and,
for Go's column only, input that is not valid UTF-8 for a pattern that can
match U+FFFD (see "Invalid UTF-8 in the input" below; this corpus has none).
`--high-bytes` cannot be combined with Unicode mode: its ASCII-twin oracle is
sound for byte mode only.

### Unsupported `\C` syntax (~511K)

The RE2 test suite includes patterns using `\C`, which matches any single byte
(including bytes that are part of a multi-byte UTF-8 sequence). This syntax is
not supported by Go's `regexp/syntax` package and is rejected at parse time.

Skip reason: `unsupported RE2 syntax (invalid escape sequence)`

### Backtracking gave up (currently 0)

A Backtracking call that answers `-2` has abandoned part of the search, so its
answer is unknown and the row is skipped rather than compared. Each such row is
printed (the first 50 per run, all of them under `-v`). With
`--bt-fallback-always`, which makes the memoised fallback body answer every
Backtracking call, any `-2` fails the run instead.

Skip reason: `Backtracking overflow (-2, answer unknown)`

### Timeouts (currently 0)

Every WASM call runs under a 2-second watchdog. For a single pattern a timeout
fails the run (`TIMEOUT:`), except under `--force-backtrack`, where it is counted
here instead. In set mode a timed-out call is skipped rather than scored, and
the run fails if timed-out calls exceed 0.1% of the calls checked; that gate is
lifted under `--force-backtrack` and `--set-bt`, which push engines past their
limits on purpose.

Skip reason: `timeout (exponential backtracking)`

---

## Differences from Go's `regexp`

Regexped implements RE2 semantics. Wherever a check above takes its
expectation from Go's `regexp` rather than from the corpus, it relies on Go
giving the same answer; the places where regexped's answers differ from Go's
are listed here. The default byte mode's own differences — `.` and negated
classes match one byte — are in
[Bytes, not codepoints](engines.md#bytes-not-codepoints).

### `byte_mode`: raw bytes Go cannot match

An entry with
[`byte_mode: true`](cli.md#byte_mode--matching-raw-bytes-above-127) reads the
characters `0x80`-`0xFF` in its pattern as those raw BYTES. Go's `regexp` has
no such mode: a character in a pattern is always a codepoint, matched as its
UTF-8 encoding, so no Go pattern can match a raw byte above `0x7F` — Go reads
one as invalid UTF-8. `\xe9` and `é` are the same character to both parsers,
so they behave alike:

| Pattern (`byte_mode: true`) | Input bytes | Go `regexp` | Regexped |
|---|---|---|---|
| `\xe9` | `E9` | no match | `[0,1)` |
| `\xe9` | `C3 A9` (é) | `[0,2)` | no match |
| `é` | `E9` | no match | `[0,1)` |
| `[\xc0-\xdf]` | `C3` | no match | `[0,1)` |
| `[\xc0-\xdf]` | `C3 83` (Ã) | `[0,2)` | `[0,1)` |

Without `byte_mode`, a pattern naming a character above `0x7F` is compiled in
[Unicode mode](engines.md#unicode-mode), where `é` and `\xe9` are the
character U+00E9, as in the Go column above. The raw byte is never taken by
accident: it has to be asked for with `byte_mode`.

### Invalid UTF-8 in the input (Unicode mode)

Unicode mode reads the input as UTF-8, and a
byte that does not belong to a
valid UTF-8 sequence — a stray `0xFF` or continuation byte, a sequence cut
short, an overlong or a surrogate encoding — **matches nothing**: no class,
not even `.` or a negated class, can consume it. This is RE2's behaviour,
and Rust's `regex` behaves the same way. Go's `regexp` instead decodes each such byte as U+FFFD,
one byte wide, which `.`, a negated class and any other class containing
U+FFFD then match:

| Pattern | Input | Go `regexp` | Regexped (Unicode mode) |
|---|---|---|---|
| `.` | `"\xff"` | `[0,1)` | no match |
| `a.c` | `"a\xffc"` | `[0,3)` | no match |
| `[^,]+` | `"x\xffy,z"` | `[0,3)` `[4,5)` | `[0,1)` `[2,3)` `[4,5)` |
| `.+` | `"\xe2\x82A"` | `[0,3)` | `[2,3)` |
| `\pL+` | `"é\xffж"` | `[0,2)` `[3,5)` | `[0,2)` `[3,5)` |

Valid UTF-8 input is not affected. Neither is the default byte mode, where
every byte is a character of its own and there is no such thing as an invalid
one (see [Bytes, not codepoints](engines.md#bytes-not-codepoints)).

Matching Go here would cost more than the rule itself suggests: whether a byte
such as `E2` is one invalid character or the start of `€` depends on the next
one to three bytes (`E2 82 AC` versus `E2 82 41`), so every automaton would
have to confirm a match up to three bytes after it ends.

---

## What remains unimplemented

| Category | Count | Required feature |
|---|---|---|
| `\C` byte escape | ~511K | Depends on Go `regexp/syntax` support |
