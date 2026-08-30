# Byte-identical fixtures

Each directory here is **one single-pattern code path**, checked in with the
exact bytes its `patterns.yaml` compiles to. `compile/byteident_test.go`
recompiles them and compares byte for byte — no tolerance.

They exist because the set redesign shares emitters with the
single-pattern path, and D6 of that plan says single-pattern behaviour must not
change. Byte identity is the only evidence strong enough for "must not change":
a behavioural test proves the cases it tries, and a shared-emitter regression
is exactly the kind that hides in the cases nobody tried.

One fixture per path matters as much as the comparison. A change to a shared
emitter cannot hide in a path no fixture exercises, so if you add a code path,
add a fixture for it.

## What each fixture is for

| fixture | pattern | path it pins | engine |
|---|---|---|---|
| `dfa_find` | `(?:alpha\|beta\|gamma)[0-9a-f]{300}` | plain DFA find body — over 256 states, so it is NOT promoted to CompiledDFA; the alternation forces LeftmostFirst | DFA |
| `compiled_dfa` | `abc[0-9]{2}` | CompiledDFA direct-index dispatch (≤ 256 states) | Compiled DFA |
| `lit_chain` | `AKIA[A-Z0-9]{16}` | literal chain: fixed literal + counted class run | Compiled DFA |
| `lit_anchor` | `[a-z]+@example\.com` | literal-anchored find: variable-length prefix recovered by a backward DFA | Compiled DFA |
| `teddy_prefix` | `ghp_[A-Za-z0-9]{36}` | Teddy nibble-fingerprint prefix scan | Compiled DFA |
| `shufti` | `[a-p][0-9]{4}END` + `prefer-no-match` | Shufti SIMD first-byte membership prefilter | Compiled DFA |
| `word_boundary` | `\bclass\b` | `prevWasWord` doubled state space and `wordCharTable` | Compiled DFA |
| `anchored_find` | `[0-9]{3}\z` | `isAnchoredFind` → `buildAnchoredFindBody` | Compiled DFA |
| `match_only` | `(?:https?)://(?:[^/]+)/(?:.*)` | `match_func` alone: anchored body, no find sibling | Compiled DFA |
| `find_only` | `\d{4}-\d{2}-\d{2}` | `find_func` alone | Compiled DFA |
| `tdfa_groups` | `(?P<scheme>…)://(?P<host>…)/(?P<path>…)` | TDFA capture path with named groups | TDFA |
| `bt_groups` | `(a.*?b)(c+)` | Backtracking capture path (the non-greedy quantifier makes it TDFA-ineligible) | Backtracking |
| `case_folded` | `(?i)select\s+.*\s+from` | `(?i)`: literals carry FoldCase and are excluded from literal extraction | Compiled DFA |
| `line_anchored` | `(?m:^)ERROR:.*(?m:$)` | newline-boundary machinery: `midStartNewline`, the `midAcceptNL` side table | Compiled DFA |
| `counted_chain` | `x[a-f]{3,10}y` | bounded counted repeat `{N,M}` | Compiled DFA |
| `strict_alt` | `AKIA[A-Z0-9]{16}\|ghp_[A-Za-z0-9]{20}` | strict alternation of lit-chain branches — `buildLitChainAltFindBody` | Compiled DFA |
| `lenient_alt` | `ERROR[0-9]{3}\|WARNING[0-9]{3}` | lenient alternation find — `buildLitChainAltLenientFindBody`, the one find body whose scan cursor is NOT `locAttemptStart` | Compiled DFA |
| `lit_chain_prefixed` | `[a-z]{3}AKIA[A-Z0-9]{24}` | lit chain with a fixed-length prefix — `buildLitChainPrefixedFindBody`; reports `attempt_start - M`, so it needs a find-from floor | Compiled DFA |
| `alt_prefixed` | `[a-z]{3}AKIA[A-Z0-9]{24}\|[0-9]{3}ghp_[A-Za-z0-9]{24}` | Gap E: strict alternation of prefixed branches — `buildLitChainAltPrefixedFindBody` | Compiled DFA |

The engine column was taken from `SelectEngine`, and
`TestByteIdenticalPathsAreDistinct` re-checks it on every run — a fixture set
that silently collapsed onto one engine would still pass the byte comparison
while defending nothing.

## Regenerating

```sh
go test ./compile -run TestByteIdentical -update-byteident
```

Do this **only** when a change to the single-pattern path is intended, and
review the resulting diff. That review is the point of the fixtures.

## The find-from cursor

Two of these fixtures exist for a reason worth stating separately. Every
exported `find` receives its start offset through the find-from global, and
each emitter names, by hand, the local that offset is seeded into. Nothing
checks that the local named is the one the scan actually starts from — WASM
locals are zero-initialised, so a wrong name yields a module that validates,
answers `from == 0` correctly, and ignores `from` forever after.

That defect shipped twice. `strict_alt`, `lenient_alt`, `lit_chain_prefixed` and `alt_prefixed`
pin four find bodies that had no fixture at all — the last two were found by
`compile`'s `TestEveryFindEmitterIsCovered`, which reported that six of the
fourteen find emitters were reached by nothing, and both turned out to be
missing the find-from floor; `tools/fuzz`'s
`TestFindFromStartsAtOrAfterFrom` is the behavioural half of the same net and
asserts the invariant the bytes here only freeze.
