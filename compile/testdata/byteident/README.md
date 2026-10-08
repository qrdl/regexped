# Byte-identical fixtures

Each directory here is **one single-pattern code path**, checked in with the
exact bytes its `patterns.yaml` compiles to. `compile/byteident_test.go`
recompiles them and compares byte for byte — no tolerance.

They exist because the set redesign shares emitters with the
single-pattern path, and single-pattern behaviour must not
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
| `affix_capture` | `<([^>]*)>` | one capture between fixed literals: the groups export's capture body writes group 1 from the match extent minus the literals' bytes, with no walk (`affixSingleCapture`) — the capture engine the selector names is never built | Backtracking |
| `bt_groups` | `(a.*?b)(c+)` | Backtracking capture path (the non-greedy quantifier makes it TDFA-ineligible), with the work budget and fallback body every Backtracking program without a zero-width cycle carries. Its find step — the find `groups` locates a match with — carries the find work counter, so it also pins the dispatcher that `groups` reaches the find through | Backtracking |
| `bt_empty_loop` | `^(\w*\|)*c` | Backtracking capture path over a program with a ZERO-WIDTH CYCLE (the outer `*`'s body can match empty through the `\|` branch). Such a program gets no ordinary body: its fast body is the bare tail call into the FALLBACK body, memoised at every Alt, whose frame stack and memo are sized from the input at call time and found through the module's scratch globals (exported, standalone, as `regexped:scratch_base`). `bt_groups` above pins the other shape — an ordinary body with the WORK BUDGET, an i64 counter charged on every frame pop whose exhaustion tail-calls the same fallback | Backtracking |
| `case_folded` | `(?i)select\s+.*\s+from` | `(?i)`: literals carry FoldCase and are excluded from literal extraction. Not provably linear, so its find carries the work counter | Compiled DFA |
| `line_anchored` | `(?m:^)ERROR:.*(?m:$)` | newline-boundary machinery: `midStartNewline`, the `midAcceptNL` side table | Compiled DFA |
| `counted_chain` | `x[a-f]{3,10}y` | bounded counted repeat `{N,M}` | Compiled DFA |
| `strict_alt` | `AKIA[A-Z0-9]{16}\|ghp_[A-Za-z0-9]{20}` | strict alternation of lit-chain branches — `buildLitChainAltFindBody` | Compiled DFA |
| `lenient_alt` | `ERROR[0-9]{3}\|WARNING[0-9]{3}` | lenient alternation find — `buildLitChainAltLenientFindBody`, the one find body whose scan cursor is NOT `locAttemptStart` | Compiled DFA |
| `lit_chain_prefixed` | `[a-z]{3}AKIA[A-Z0-9]{24}` | lit chain with a fixed-length prefix — `buildLitChainPrefixedFindBody`; reports `attempt_start - M`, so it needs a find-from floor | Compiled DFA |
| `alt_prefixed` | `[a-z]{3}AKIA[A-Z0-9]{24}\|[0-9]{3}ghp_[A-Za-z0-9]{24}` | mixed-prefix: strict alternation of prefixed branches — `buildLitChainAltPrefixedFindBody` | Compiled DFA |
| `byte_mode` | `caf\xe9[0-9]{4}` + `byte_mode: true` | a pattern naming raw bytes above 127, which every other fixture's mode rejects outright | Compiled DFA |
| `lm_sole_dominant` | `[a-zA-Z]{20,}` + `prefer-match` | the LikelyMatch mid-accept dominant dispatch and its Shufti self-loop bulk skip. `prefer-match` reached NO single-pattern fixture before this one — only the two set fixtures — so every LM-gated emitter in a find body was unpinned | Compiled DFA |
| `find_start_anywhere` | `[a-z]+[0-9]{3}` | the START-ANYWHERE find alone: a forward pass over the leftmost-first DFA of `(?s:.)*?(?:pat)` and a backward pass over the reversed pattern, joined by a glue body — what the find classifier picks for a leading repeat of a word class with no literal to scan for | Compiled DFA |
| `one_byte_lit_anchor` | `\w+@\w+` | a ONE-byte inner literal behind a wide leading repeat: the literal-anchored find with the start-anywhere switch's counter charging every failed candidate | Compiled DFA |
| `find_switch` | `a*b` | today's general find WITH the work counter at its failed-attempt exits, the start-anywhere find beside it, and the dispatcher every caller of the find reaches. Its automaton has a cycle state, so it also pins the PER-SEARCH NOTES pair (`search_notes.go`): the ordinary copy's waste counter and the marked copy, with the `regexped:search` export | Compiled DFA |
| `lit_anchor_switch` | `\w+abc\d` | the literal-anchored find with the counter; its backward walker stamps where it stopped, so a FAILED backward walk is charged too | Compiled DFA |
| `alt_lit_switch` | `x{3}abc\w*z\|y{3}ghi\w*z` | the alternation literal-anchored find with the counter; each branch's backward walker and forward verifier stamp where they stopped | Compiled DFA |

## Set fixtures

Everything above is SINGLE-PATTERN. Until these existed, set output had no
byte-identity pin at all — every set change was made without the drift check the
single-pattern path has had since the beginning, a gap that must stay closed
before `CompileSet` can ever be split.

The failure mode is the expensive one. `CompileSet` is a memory allocator whose
ordering invariant is enforced by prose: reorder two layout blocks and two table
regions overlap — not a compile error, not a WASM validation error, but a module
that reads one table through another's bytes.

| fixture | shape it pins | frontend |
|---|---|---|
| `set_packed_pair` | <=16 literals, narrow two-column probe (`byte_rank.go`) | packed-pair |
| `set_teddy` | 17..64 literals with DIVERSE first bytes, nibble tables | teddy |
| `set_ac` | >16 literals, LOW first-byte diversity (`aho_corasick.go`) | ac |
| `set_scalar` | no literal to anchor on — no prefilter emitted. Its letter runs are bounded, so every member is provably linear and stays in the buckets | scalar |
| `set_sparse` | sparse accept: 40 patterns in ONE bucket, past the 32 a u64 mask allows | packed-pair |
| `set_member_skip` | the SAME sparse shape under `prefer-match`, which adds the member self-loop skip. Paired with `set_sparse` on purpose: that one pins the body without the skip, so a diff that moves both is the body and a diff that moves only this one is the skip | packed-pair |
| `set_anchored` | the anchored pair alone — an anchored-only set emits NO literal frontend | packed-pair |
| `set_scan` | the scan pair: non-anchored, offset-taking, no positions | packed-pair |
| `set_overlap` | `overlapping: true` — every-start enumeration, same signature as gated find | packed-pair |
| `set_batch` | `hints: [batch-find]` — a second entry point over ONE shared worker | packed-pair |
| `set_overlap_sweep` | `overlapping: true` over LITERAL-LESS patterns, which is what puts a SWEEP in the module: the checkpoint pass, the block materialiser, the projection table and the successor scratch. `set_overlap` above is eight literals and contains none of them | scalar |
| `set_overlap_sweep_batch` | the same sweep with `hints: [batch-find]`. Only SERVING is per-entry — `find` returns a position's total where the batch entry returns what it wrote — so the two serving paths are separate code and are pinned separately | scalar |
| `set_split` | members that are not provably linear in a set's bodies SPLIT OUT to their own start-anywhere find: the merge wrapper `find` becomes, the member passes, the position global the bucket body stamps, and — the `\b` member refusing a union automaton — the merged scan wrappers | scalar |
| `set_split_batch` | the split in a BATCHING set: the merge sits in the shared per-position worker both entries call, and follows the batch resume rule (gate every match delivered) | packed-pair |
| `set_split_scan_union` | the same split with a union automaton over every member serving the scan pair on its own, so only `find` is merged | packed-pair |
| `set_scan_counter` | a literal frontend's scan pair with a member that is not provably linear and nothing split: the probes stamp their walks, and the scan bodies carry the work counter — charged only for walks that recorded nothing new, checked after the probe is recorded — that hands the call to a union automaton | packed-pair |
| `set_overlap_counter` | an overlapping `find` the answer cache serves, over a member that is not provably linear: the walk's IN-CALL counter, which sweeps as soon as the call's walks cost what the sweep would, and the NO-CACHE COMPANION — the same set split, compiled beside it and never exported — that `find` hands a drive with no usable cache to | scalar |

## Unicode-mode fixtures

Every fixture above is in BYTE mode, which is what proves byte-mode output
unchanged by Unicode mode (`TestByteIdentFixturesResolveToByteMode` checks
that they resolve to it). The `unicode_` fixtures pin the Unicode-mode paths —
lowered programs and the rule that no match or empty match sits inside a
character — and resolve to Unicode mode instead.

| fixture | pattern(s) | path it pins |
|---|---|---|
| `unicode_dfa_find` | `[α-ω0-9]{150}x` | a lowered two-byte class run past 256 states: the plain DFA find over a u16 table |
| `bt_alt_dispatch` | `\b(get\|head\|post\|delete) (\S+)`, `\b(\w+a\|[a-z]+b\|[0-9a-z]+c\|x)(\d)` | the first-byte dispatch at an alternation chain's head, in both encodings: direct for the keywords, compact where most bytes start most arms | Backtracking |
| `unicode_compiled_dfa` | `é[0-9]{2}` | a multi-byte literal, match and find, within 256 states |
| `unicode_tdfa` | `([α-ω]+)-([0-9]+)` | captures around multi-byte classes on TDFA |
| `unicode_bt` | `(é.*?b)(c+)` | captures on Backtracking over a lowered program |
| `unicode_lit_anchor` | `\pL+@example\.com` | the literal-anchored find's backward DFA over the reversed, lowered pattern |
| `unicode_char_probe` | `привет\s+\pL+` | the prefix scan's whole-first-character check for a literal that begins with a non-ASCII character |
| `unicode_char_run` | `[^,]+,` + `unicode: true` | the bulk skip over whole UTF-8 characters, for a state that loops on every character through one state per byte |
| `unicode_match_char_run` | `.+`, `[^,]+,`, `\p{Cyrillic}{14}[^,]*,` + `unicode: true` | the match body's skip over whole UTF-8 characters: a Compiled DFA with an accepting and a non-accepting loop, and a plain DFA over 256 states |
| `unicode_tdfa_char_run` | `<([^>]+)>(x)` + `unicode: true` | the TDFA capture body's skip over whole UTF-8 characters, run from the tag-op dispatch's arms that enter the loop |
| `unicode_start_seed` | `x*` + `unicode: true` | a find that rounds `from` up to a character's first byte |
| `unicode_start_scan` | `a?\B` + `unicode: true` | a find that checks every candidate start (`\B` holds inside a character) |
| `unicode_set_walk` | `[a-zé]+`, `x*`, `\B` | a set's per-position walk skipping candidates inside a character, in `find` and the scan pair, with lead-byte first-byte tables |
| `unicode_set_literals` | `привет`, `москва`, `собака`, `город\d+` | multi-byte literals in a literal frontend |
| `unicode_set_union_scan` | `\pL+\pN`, `\p{Greek}{2,}\pN` | the scan pair's union automaton over lowered members |
| `unicode_set_overlap_sweep` | `[a-zé]+`, `a*` | the answer cache's sweep writing an empty row inside a character |
| `unicode_set_split_overlap` | `foo\w+`, `(?:a[^z]*?z)?` + set-level `unicode: true` | a split member's rounded search position and its program sweep |

`TestByteIdenticalPathsAreDistinct` checks the Unicode fixtures reach all four
engines, and `TestByteIdenticalUnicodeSetFixtures` that each set fixture still
has the shape it is named for.

`TestByteIdenticalSetShapesAreDistinct` re-derives the frontend, accept kind and
capability list from the diagnostics on every run, for the same reason the
engine column above is re-checked: a fixture set that silently collapsed onto
one frontend would still pass the byte comparison while defending nothing.

**Shufti is deliberately absent.** It is selected only when Aho-Corasick
declines on budget, which no YAML config can arrange — so it cannot have a
fixture here. It is covered instead by `tools/fuzz/set_caps_test.go`, which
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
an emitter-reach check (today `tools/fuzz`'s `TestEveryEmitterIsReachedBySweeps`,
run by `make from-coverage`), which reported that six of the
fourteen find emitters were reached by nothing, and both turned out to be
missing the find-from floor; `tools/fuzz`'s
`TestFindFromStartsAtOrAfterFrom` is the behavioural half of the same net and
asserts the invariant the bytes here only freeze.
