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
| `shufti_neutral` | `[A-Z]{8,}` | the byte-rarity model selecting Shufti with NO hint — the path `byteRarity`'s weights govern, which no other fixture reaches | Compiled DFA |
| `shufti_dense_switch` | `[a-zA-Z]{20,}` + `prefer-no-match` | the ADAPTIVE dense switch: a first-byte set the rarity model calls dense, forced onto Shufti by the hint, so the runtime probe-budget counter is emitted. `shufti` above does not reach it — 16 first bytes take the unconditional SIMD branch | Compiled DFA |
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
| `byte_mode` | `caf\xe9[0-9]{4}` + `byte_mode: true` | a pattern naming raw bytes above 127, which every other fixture's mode rejects outright | Compiled DFA |
| `lm_sole_dominant` | `[a-zA-Z]{20,}` + `prefer-match` | the LikelyMatch mid-accept dominant dispatch and its Shufti self-loop bulk skip. `prefer-match` reached NO single-pattern fixture before this one — only the two set fixtures — so every LM-gated emitter in a find body was unpinned | Compiled DFA |

## Set fixtures

Everything above is SINGLE-PATTERN. Until these existed, set output had no
byte-identity pin at all — every set change was made without the drift check the
single-pattern path has had since the beginning, which is the gap TODO 65 names
as a hard prerequisite for splitting `CompileSet`.

The failure mode is the expensive one. `CompileSet` is a memory allocator whose
ordering invariant is enforced by prose: reorder two layout blocks and two table
regions overlap — not a compile error, not a WASM validation error, but a module
that reads one table through another's bytes.

| fixture | shape it pins | frontend |
|---|---|---|
| `set_packed_pair` | <=16 literals, narrow two-column probe (`byte_rank.go`) | packed-pair |
| `set_teddy` | 17..64 literals with DIVERSE first bytes, nibble tables | teddy |
| `set_ac` | >16 literals, LOW first-byte diversity (`aho_corasick.go`) | ac |
| `set_scalar` | no literal to anchor on — no prefilter emitted | scalar |
| `set_sparse` | G17 sparse accept: 40 patterns in ONE bucket, past the 32 a u64 mask allows | packed-pair |
| `set_member_skip` | the SAME sparse shape under `prefer-match`, which adds the member self-loop skip. Paired with `set_sparse` on purpose: that one pins the body without the skip, so a diff that moves both is the body and a diff that moves only this one is the skip | packed-pair |
| `set_anchored` | the anchored pair alone — an anchored-only set emits NO literal frontend | packed-pair |
| `set_scan` | the scan pair: non-anchored, offset-taking, no positions | packed-pair |
| `set_overlap` | `overlapping: true` — every-start enumeration, same signature as gated find | packed-pair |
| `set_batch` | `hints: [batch-find]` — a second entry point over ONE shared worker | packed-pair |

`TestByteIdenticalSetShapesAreDistinct` re-derives the frontend, accept kind and
capability list from the diagnostics on every run, for the same reason the
engine column above is re-checked: a fixture set that silently collapsed onto
one frontend would still pass the byte comparison while defending nothing.

**Shufti is deliberately absent.** It is selected only when Aho-Corasick
declines on budget, which no YAML config can arrange — so it cannot have a
fixture here. It is covered instead by `tools/fuzz/set_shufti_test.go`, which
reaches it through `CompileFileOpts`.


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
