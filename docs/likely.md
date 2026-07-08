# LikelyMode

`LikelyMode` is a compile-time hint that lets the caller tell regexped how the
compiled pattern will typically be used. The compiler uses it to choose between
emission strategies that trade off match-path speed against no-match-path speed
(or vice versa) in ways that cannot be safely defaulted on for every workload.

The hint affects emitted WASM code shape and size. It never affects
correctness — re2test passes all corpora under every mode (default,
`--likelymatch`, `--likelynomatch`).

---

## The three modes

```go
type LikelyMode int

const (
    LikelyNeutral  LikelyMode = iota // default; no structural hint
    LikelyMatch                      // bias for fast-accept
    LikelyNoMatch                    // bias for fast-reject
)
```

| Mode | Intent | Effect summary |
|---|---|---|
| `LikelyNeutral` | no hint; assume balanced | Gets every default-on optimisation. No mode-specific code paths fire. |
| `LikelyMatch` | "matches expected, no-match is the cold path" | Unlocks the counted-chain SIMD verifier (Opt 2, lit-chain bodies). The non-mid-accept dominant bulk-skip this row used to unlock is now default-on for every mode (Task 7 Step 2, 2026-07-05) — three pattern shapes pay a ~+18-24% no-match wall-clock cost for it regardless of which mode is set; see *Known gaps* §5 below. |
| `LikelyNoMatch` | "matches rare, scan-and-exit is the hot path" | Forces SIMD prefix-scan routing for first-byte sets in the 17..64-byte band that the density heuristic would otherwise route to scalar. Helps patterns with wide first-byte sets on inputs dominated by "impossible" bytes. |

The three modes are mutually exclusive. `LikelyMatch` does **not** include
`LikelyNoMatch`'s optimisations and vice versa.

---

## How to set the hint

> **Gap (see *Known gaps* §1):** there is currently no per-pattern YAML field
> and no CLI flag to set `LikelyMode`. The hint is reachable only from Go code
> via `compile.CompileOptions`. End users invoking `regexped compile` cannot
> activate `LikelyMatch` or `LikelyNoMatch`.

**Programmatic (Go):**

```go
wasm, _, err := compile.Compile(
    entries,                      // []config.RegexEntry
    /*tableBase=*/ 0,
    /*standalone=*/ true,
    compile.CompileOptions{
        LikelyMode: compile.LikelyMatch,
    },
)
```

The same hint applies to every entry in the call — there is no per-entry
override.

**Test harnesses** drive the hint via flag:

- `re2test --likelymatch` / `--likelynomatch` — exhaustive correctness suites
  under each mode.
- `likelytest` — benchmark harness that compiles every pattern three times
  (one per mode) and prints a `neutral / likely-match / likely-nomatch` matrix
  per case.

---

## What each mode unlocks

### `LikelyNeutral` (default)

Gets every optimisation that is regression-free across all workloads. These are
emitted unconditionally and the hint just confirms the default:

| Optimisation | Where | Notes |
|---|---|---|
| Phase 1 — dominant self-loop detection | `detectDominantSelfLoop` in [compile/engine_dfa.go](../compile/engine_dfa.go) | Identifies DFA states that self-loop on ≥240/256 bytes |
| Phase 2/3/5 — mid-accept dominant bulk-skip in find body | `buildFindBody` → `emitDominantBulkSkip` | 1-byte exit (Phase 2), multi-state (Phase 3), Shufti 2..8-byte exit set (Phase 5) |
| Phase 4 — same dispatch in match body | `buildMatchBody` / `buildHybridMatchBody` → `emitPhase4Dispatch` | Anchored-match counterpart of Phase 2/3/5 |
| Lit-anchor body bulk-skip | `buildLitAnchorFindBody` | Mid-accept dispatch inside the lit-anchor forward DFA scan loop |
| LNM Action 3 — density-heuristic Shufti | `EmitPrefixScan` in [compile/prefix_scan.go](../compile/prefix_scan.go) | 17..64-byte first-byte sets route through Shufti when `shuftiBeatsScalar` returns true |
| Opt 1 — non-mid-accept dominant dispatch, find body | `buildFindBody` non-mid branch, [compile/compile.go:999](../compile/compile.go) | Default-on for all modes since Task 7 Step 2 (2026-07-05) — see *Known trade-off* below |
| Opt 1 — non-mid-accept dominant dispatch, match body | `buildMatchBody` / `buildHybridMatchBody`, [compile/compile.go:734](../compile/compile.go) | Same change, match-body counterpart |
| Opt 1 — non-mid-accept dominant dispatch, lit-anchor body | `buildLitAnchorFindBody` non-mid branch | Shares the same `l.dominantStates` encoding as the find body; benefits from the same change |
| Gap F — TDFA capture-body bulk-skip | `detectTDFABulkSkip` / `emitTDFABulkSkip` in [compile/tdfa_bulk_skip.go](../compile/tdfa_bulk_skip.go) | Shipped 2026-07-06, unconditional for every mode — see *Gap F* section below |

**Non-mid-accept dominant dispatch (moved here from `LikelyMatch` on
2026-07-05, Task 7 Step 2).** Originally gated to `LikelyMatch` because the
first implementation (a memory-side-table dispatch) caused a 48-57%
no-match wall-time regression on some patterns. That dispatch was replaced
with **state-ID compare emission** (`local.get state; i32.const STATE;
i32.eq; if; emitDominantBulkSkip; end` per non-mid entry — see
[plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive)
for the reverted side-table variant), which shrank the no-match cost enough
that re-measurement justified making it default-on for every `LikelyMode`,
not just `LikelyMatch`. The remaining no-match cost is documented in
*Known trade-off* below — it is now a fact of the optimisation itself, not
something users opt into via the hint.

**Known trade-off (was "Known regression" under `LikelyMatch` before
2026-07-05).** Three patterns show a real, reproducible no-match wall-time
cost with 0% fuel change, now identical across all three `LikelyMode`s
(confirmed via `likelytest`: `wasm size` and every `Δ%` column are 0% across
neutral/likely-match/likely-nomatch for these patterns):

| Pattern | Match time | No-match time | No-match fuel |
|---|---|---|---|
| `ctrl-delim` (`\x01[^\x02]+\x02`) | ~4.7-5.0 µs | ~5.1-5.2 µs | 73,618 |
| `comments-mixed` (`//[^\n]+\|/\*(?s:.*?)\*/`, 10 KB) | ~1.2 µs | ~1.1 µs | 14,632 |
| `comments-mixed-large` (same pattern, 50 KB) | ~3.8 µs | ~5.1 µs | 73,618 |

(Current per-mode `likelytest` runs on these three show 0% `Δ%` across
neutral/likely-match/likely-nomatch — confirming the WASM is byte-identical
across modes; the small run-to-run µs variation above is measurement noise,
not a mode effect.) The no-match wall-time cost for these three, measured
against the pre-Opt-1-non-mid baseline when the gate was removed (Task 7
Step 2, 2026-07-05), is ~18-24% (fuel unchanged — a Cranelift JIT codegen
artefact, not extra emitted work; see *Known gaps* §5 below) — a real
reduction from the original 48-57% side-table regression. `xml-tag`,
`bracket-content`, `paren-block`, and `letter-delim` show ~0% no-match cost
and are unaffected.

### `LikelyMatch`

Adds, on top of neutral:

| Optimisation | Where | Gate | Patterns affected |
|---|---|---|---|
| Opt 2 — counted-chain SIMD verifier (no captures) | [compile/compile.go:520](../compile/compile.go) | `LikelyMode == LikelyMatch && !needGroups` | Strict `<lit><charclass>{N}` and strict alts of same |
| Opt 2 — counted-chain SIMD verifier (with captures) | [compile/compile.go:373](../compile/compile.go) | `LikelyMode == LikelyMatch && needGroups` | Same shape, capture path |

> As of 2026-07-05 (Task 7 Step 2), the non-mid-accept dominant dispatch
> that used to be listed here is **default-on for every `LikelyMode`** — see
> the `LikelyNeutral` section above, including its *Known trade-off* note.
> `LikelyMatch`'s own unique contribution is now just Opt 2 (the counted-chain
> SIMD verifier).

### `LikelyNoMatch`

Adds, on top of neutral:

| Optimisation | Where | Gate | Patterns affected |
|---|---|---|---|
| Action 5 — force Shufti for 17..64-byte first-byte sets | `EmitPrefixScan` | `lnmAction5` flag on `dfaLayout`, set from `LikelyMode == LikelyNoMatch` | Patterns whose first-byte set has 17..64 distinct bytes that the neutral-mode density heuristic would route to scalar |

> **Gap (see *Known gaps* §2):** the *real* LNM Action 5 from the original plan
> ("scan the body accept set P for impossible bytes") was never shipped. What
> ships under the `Action 5` name today is a narrower optimisation: it only
> overrides Action 3's first-byte density heuristic in the 17..64 band, it
> doesn't compute or use the body accept set.

---

## Engine support matrix

| Engine | LikelyNeutral | LikelyMatch | LikelyNoMatch |
|---|---|---|---|
| DFA | ✅ all defaults | ✅ Opt 2 active | ✅ Action 5 active |
| Compiled DFA | ✅ | ✅ | ✅ |
| TDFA | ✅ defaults + Gap F bulk-skip (mode-independent) | ⚠️ LM only affects the *DFA fallback path* if a lit-chain shape matches before TDFA is chosen; no LM-specific TDFA code, and none is needed — see *why LM doesn't need TDFA-specific code* below | ✅ Action 5 active — not via TDFA-specific code, but via the shared DFA **find wrapper** that locates the candidate start for non-anchored capture patterns before TDFA extracts captures; see *the find-wrapper mechanism* below |
| Backtracking | ✅ (defaults only — Phase 2/3/5 don't apply since BT is structurally different) | ❌ no BT-specific code, and none is needed — see *why LM doesn't need BT-specific code* below | ✅ Action 5 active on two independent paths — BT's own `find_func`-only DFA-too-large fallback, and the same shared find wrapper TDFA uses for non-anchored capture patterns; see below |

**Compiled DFA** is the DFA emission with hybrid (literal-chain) dispatch
applied; it inherits every LM/LNM code path the DFA engine has.

**TDFA** (Laurikari tagged DFA) is selected for capture-track patterns that
qualify (no non-greedy, no line anchors, no word boundaries, no ambiguous
alternations, ≤ `MaxDFAStates`, ≤ `MaxTDFARegs`). The TDFA emission itself
contains no `LikelyMode` checks — but since 2026-07-06 (Gap F) it does have
its own optimisation, a SIMD bulk-skip for capture patterns with a single
dominant self-loop state (`(\w+)`, `<([a-z]+)>`, etc. — see the *Gap F*
section below). Gap F fires whenever a pattern qualifies, for **every**
`LikelyMode`, the same unconditional-by-design choice as Task 7's Opt 1 —
it is not part of the `LikelyMode` hint mechanism at all. Separately, the
compile pipeline tries the LM lit-chain capture path *before* falling
through to TDFA — so for patterns where a lit-chain capture body exists,
`LikelyMatch` replaces the TDFA emission entirely with a faster lit-chain
emission. If the pattern doesn't qualify for lit-chain, TDFA (with Gap F
applied automatically, if eligible) is used and `LikelyMatch` has no
further effect (verified: `LikelyNeutral` and `LikelyMatch` produce
byte-identical WASM for TDFA-routed patterns that need a find wrapper —
Opt 1, the only thing that could differ, is already unconditional).
`LikelyNoMatch` is a different story — see *the find-wrapper mechanism*
below.

**Backtracking** is selected for patterns the DFA/TDFA can't handle (e.g.
non-greedy quantifiers, large state count, ambiguous captures). The
backtracking capture-body/match-body emission contains no `LikelyMode`
checks, and — for `match_func`/`groups_func` on an anchored pattern — the
hint genuinely has no effect, since anchored bodies start at position 0 and
never run a scan for the hint to influence. But BT's `find_func`-only path
(used when the pattern's DFA exceeds `MaxDFAStates`/`MaxDFAMemory`) *does*
run a scan, via the same shared `emitPrefixScan` the DFA engine uses
(`compile.go:836` threads `LikelyMode == LikelyNoMatch` into
`btScanParams.LikelyNoMatch`) — see *the find-wrapper mechanism* below for
why this was broken until 2026-07-08.

### The find-wrapper mechanism (why LNM reaches TDFA and Backtracking capture patterns too)

A capture pattern that isn't inherently anchored (`needGroups && !anchored`
in `compilePattern`, [compile/compile.go:761](../compile/compile.go)) gets
**two** compiled bodies, not one: a `findBody` that scans for the candidate
match start, and a separate `captureBody` (TDFA or Backtracking) that
re-runs anchored from that candidate to fill in capture slots. The
`findBody` is always the standard DFA find emission
(`appendFindCodeEntry`, [compile/compile.go:1022](../compile/compile.go)) —
completely independent of which engine ends up handling `captureBody` — and
it sets `l.lnmAction5 = buildOpts.LikelyMode == LikelyNoMatch`
unconditionally ([compile/compile.go:1020](../compile/compile.go)), exactly
like a plain `find_func`-only pattern.

This means **`LikelyNoMatch` has a real, measurable effect on patterns
whose captures are extracted by TDFA or Backtracking** — just not through
any TDFA/BT-specific code. Confirmed by direct compilation:
`[a-zA-Z]{20}(\d+)` (routes captures to TDFA, needs a find wrapper) compiles
to 13,812 B under `LikelyNeutral` vs 14,278 B under `LikelyNoMatch`
(byte-different — Action 5 fired); `[a-zA-Z]{20}([^,]+),` (ambiguous
capture, routes to Backtracking) compiles to 9,473 B vs 9,939 B, same
effect. `LikelyMatch` produces byte-identical output to `LikelyNeutral` in
both cases (Opt 1 is already unconditional; Opt 2 doesn't apply outside the
lit-chain shape). This mechanism is exercised across the whole re2-adjusted
corpus by `re2test --likelynomatch --validate-groups` (1,878,840 cases, 0
failures) — it just wasn't called out in this doc, or in the engine/host
support matrices, before 2026-07-08.

### Why LM doesn't need TDFA-specific code

`LikelyMatch`'s only unique contribution is Opt 2, the counted-chain SIMD
verifier for `<lit><charclass>{N}`-shaped bodies. The compile pipeline
checks for that shape and intercepts it — replacing the emission entirely —
*before* the engine selector ever considers TDFA
([compile/compile.go:373](../compile/compile.go), gated on
`LikelyMode == LikelyMatch && needGroups`, runs ahead of the TDFA/BT
selection logic). So by construction, any capture pattern that actually
reaches TDFA already isn't lit-chain-shaped — Opt 2's condition and "reaches
TDFA" are mutually exclusive. There is no missing optimisation to port into
TDFA; the shape LM targets is siphoned off earlier in the pipeline.

### Why LM doesn't need BT-specific code

Investigated directly (see [plans/TODO.md](../plans/TODO.md) task 16). LM's
two mechanisms — the counted-chain SIMD verifier and the dominant
self-loop bulk-skip — both require a DFA-style transition table to detect
"this state is dominant" or "this is a fixed-length class chain." BT is
reached specifically for patterns that already failed those exact
structural gates (ambiguous captures, non-greedy quantifiers, huge state
counts) — precisely the population least likely to have a clean
single-state self-loop or counted chain left to exploit; that's *why* they
fell through past DFA/TDFA in the first place. Porting either mechanism to
BT would mean writing new detection and emission logic from scratch against
BT's stack-based per-instruction dispatch, with no code reuse from the
existing DFA/TDFA implementations, for a payoff nobody has observed yet.
CLAUDE.md's own "Gap I" lesson is the relevant caution here: "looks like an
obvious win" has repeatedly cost real engineering time on this exact
population once actually measured. Confirmed empirically: BT fuel/time was
byte-identical between `LikelyNeutral` and `LikelyMatch` in every
measurement taken during the task 16 investigation. Declined pending a
concrete BT-routed pattern shape that would make the detection cheap.

> **Gap (see *Known gaps* §3):** there is no compile-time warning when a
> user sets `LikelyMatch` on a pattern that ends up on TDFA or Backtracking
> with no lit-chain shape — the hint is silently a no-op beyond what's
> already unconditional. `LikelyNoMatch`, by contrast, is *not* a no-op for
> either engine (see *the find-wrapper mechanism* above), so this gap is
> narrower than it used to be: it's specifically "no warning that
> `LikelyMatch` did nothing extra," not "no warning that the hint did
> nothing at all."

---

## Gap F: TDFA capture-body bulk-skip

Shipped 2026-07-06. Not part of the `LikelyMode` hint mechanism — included
in this doc because it lives in the same performance-optimisation
workstream and because *Known gaps* §3 above depends on understanding it:
TDFA now has a real optimisation, it's just not something `LikelyMode`
controls.

**What it does.** A TDFA capture pattern that compiles down to a single
dominant self-loop state — one state that loops on 8-64 distinct bytes,
firing a uniform, set-to-pos-only tag-op batch on every one of them — gets
a SIMD bulk-skip: `detectTDFABulkSkip` finds the qualifying state at
compile time, `emitTDFABulkSkip` (both in
[compile/tdfa_bulk_skip.go](../compile/tdfa_bulk_skip.go)) emits a 16-byte
chunked scan (`emitShuftiPrefixCheck`, the same SIMD primitive Action 3
uses) that skips the whole self-loop run and fires the tag-op batch once,
instead of once per byte. Hooked into `newTDFA` (detection) and
`buildTDFAMatchBody` (emission) in
[compile/engine_tdfa.go](../compile/engine_tdfa.go).

**Scope (v1).** One dominant state per pattern; copy-ops (register
reconciliation) on the self-loop are excluded, only set-to-pos ops qualify.
Both are documented, intentional limits, not oversights — see
[plans/TODO.md](../plans/TODO.md) task 15.

**Qualifying patterns:** `(\w+)`, `<([a-z]+)>`, `X([a-zA-Z]+)#`. Note the
trailing-literal-inside-the-class shape (`X([a-zA-Z]+)Y`) doesn't reach
TDFA at all by default — it's routed to Backtracking via
`hasAmbiguousCaptures` (see [plans/TODO.md](../plans/TODO.md) task 13,
open). Gap F only fires for patterns that actually reach TDFA.

**Measured wins** and **unconditional, every-mode** framing: see the Gap F
entries under *What each mode unlocks* → `LikelyNeutral`, the *Engine
support matrix* TDFA row, and *Known performance numbers* above.

---

## Host-function support matrix

Each YAML entry can request up to four host functions
([config.RegexEntry](../config/config.go)):

```yaml
regexps:
  - pattern: "AKIA[A-Z0-9]{16}"
    match_func:        "aws_match"        # anchored full-input match
    find_func:         "aws_find"         # non-anchored first find
    groups_func:       "aws_groups"       # anchored + captures
    named_groups_func: "aws_named_groups" # anchored + named captures
```

| Host function | LikelyNeutral | LikelyMatch | LikelyNoMatch |
|---|---|---|---|
| `match_func` | All Phase 4 + Action 3 defaults + non-mid dominant dispatch | Lit-chain match body (Opt 2) | Action 5 |
| `find_func` | All Phase 2/3/5 + lit-anchor + Action 3 defaults + non-mid dominant dispatch | Lit-chain find body (Opt 2) + lit-chain capture body if find+groups combo | Action 5 |
| `groups_func` | TDFA (+ Gap F bulk-skip if eligible) or Backtracking — `LikelyMatch` has no effect *unless* the pattern is a lit-chain capture shape; `LikelyNoMatch` (Action 5) *does* apply, via the shared find wrapper, whenever the pattern isn't fully anchored (needs a scan to locate the candidate before TDFA/BT extracts captures) | Lit-chain capture body (Opt 2 with captures) replaces TDFA/BT entirely | Action 5 on the find wrapper for non-anchored patterns (no effect on fully-anchored patterns — nothing to scan); see *the find-wrapper mechanism* in the *Engine support matrix* section |
| `named_groups_func` | Same as `groups_func` | Same as `groups_func` | Same as `groups_func` |

For capture-returning host functions the rule of thumb is: **`LikelyMatch`
only has an effect** when the pattern is one of the lit-chain capture shapes
(strict alternation of `<lit><charclass>{N,M}` with captures, prefixed
lit-chain `<class>{N}<lit>...`, etc.) — all other capture patterns fall
through to TDFA or Backtracking, both of which ignore `LikelyMatch`.
**`LikelyNoMatch` is different**: it has an effect on any capture pattern
that isn't fully anchored, regardless of which engine (TDFA or Backtracking)
ends up extracting the captures — see *the find-wrapper mechanism* above.

---

## Sets support

> **Gap (see *Known gaps* §4):** `LikelyMode` is **not** propagated to set
> compilation.

When the YAML config contains a `sets:` block, `compile.CmdCompile` dispatches
to `compile.CompileFile` ([compile/set_emit.go:657](../compile/set_emit.go#L657)),
which builds `CompileOptions` from only `MaxDFAStates` and `MaxTDFARegs`.
The `LikelyMode` field is not set anywhere in the sets path.

This means:
- Set-mode exports (`find_any`, `find_all`, `match`) get only `LikelyNeutral`
  optimisations regardless of intent.
- The per-pattern entries that the set is built from are *also* compiled with
  `LikelyNeutral` when sets are present, even though the same patterns would
  see LM/LNM hints if compiled outside a set.

---

## Pattern shape requirements

For the hint to have a measurable effect, the pattern must match one of these
shapes:

### Shapes benefiting from Opt 1 (unconditional — every `LikelyMode`, since 2026-07-05)

**Non-mid-accept dominant body (state-ID compare dispatch):**
- `<lit>[^<exit>]+<lit>` shape — `<[^>]+>`, `/\*.*?\*/`, `"[^"]+"`,
  `\x01[^\x02]+\x02`
- Lit-anchored variant — `<lit-2+-bytes>[^<exit>]+<lit-2+-bytes>` (anchored
  variant where `findLitAnchorPoint` recognises the 2+ byte literal child;
  e.g. `[0-9]{4}INFO:[^\n]+`)

This is not gated by the `LikelyMode` hint at all — patterns matching this
shape get the optimisation regardless of what mode you set (or don't set).
Listed here (not under `LikelyMatch`/`LikelyNoMatch` below) because it used
to be a `LikelyMatch`-only target before Task 7 Step 2.

### `LikelyMatch` targets

**Counted-chain (Opt 2, lit-chain):** — the only shape where the
`LikelyMatch` hint itself still makes a difference.
- `<lit><charclass>{N}` — `AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9]{36}`
- `<lit><charclass>{N,M}` — `AKIA[A-Z0-9]{8,16}`, `secret_[A-Za-z0-9]{24,40}`
- Strict alt of same — `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`
- Prefixed (Gap E) — `[0-9]{8}ghp_[A-Za-z0-9]{36}`
- With `\b` anchors — `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`
- With captures — same shapes wrapped in a single capture or with named groups
- Lenient alt (mixed lit-chain + non-lit-chain branches) — only the lit-chain
  branches benefit

### `LikelyNoMatch` targets

**17..64-byte first-byte set in find mode:**
- `[a-zA-Z]{8,}`, `[a-zA-Z0-9_]{n,}` — patterns whose first-byte set in this
  size band the density heuristic would route to scalar, on inputs dominated
  by bytes outside the set (so the SIMD scan amortises better than the
  byte-by-byte scalar early-exit).

**Same first-byte-set shape, on a non-anchored capture pattern** — e.g.
`[a-zA-Z]{20}(\d+)` or `[a-zA-Z]{20}([^,]+),`: the shared find wrapper that
locates the candidate before TDFA/Backtracking extracts captures uses the
exact same density heuristic and Action 5 override. See *the find-wrapper
mechanism* in the *Engine support matrix* section.

### Shapes benefiting from Gap F (unconditional — every `LikelyMode`, TDFA only, since 2026-07-06)

**TDFA capture pattern with a single dominant self-loop state, 8-64 bytes,
uniform set-to-pos tag ops:**
- `(\w+)`, `<([a-z]+)>`, `X([a-zA-Z]+)#` — see the *Gap F* section below.

Not gated by the hint either — see the *Gap F* section for details and the
scope restrictions (single dominant state, no copy-ops).

If your pattern doesn't match one of these shapes, the `LikelyMode` hint
will compile fine but produce bit-identical WASM to `LikelyNeutral` — though
note Opt 1 and Gap F can still change the WASM relative to *older* versions
of regexped regardless of the hint, since neither is hint-gated anymore.

---

## Known performance numbers

From the [likelytest](../likelytest/) benchmark on 50 KB inputs (unless noted).

### Opt 1 wins (unconditional, every `LikelyMode`, since Task 7 Step 2 2026-07-05)

Deltas below are against the pre-Opt-1-non-mid baseline (i.e. what
`LikelyNeutral` looked like before 2026-07-05) — **not** a comparison
between today's three modes, which now produce byte-identical WASM for
every pattern in this table:

| Pattern | Match Δ | No-match Δ |
|---|---|---|
| `ctrl-delim` (`\x01[^\x02]+\x02`) | **-98%** time | **+18-24%** time |
| `xml-tag` (`<[^>]+>`) | **-98%** time | 0% |
| `bracket-content` (`\[[^\]]+\]`) | **-98%** time | 0% |
| `paren-block` (`\([^)]+\)`) | **-97%** time | 0% |
| `letter-delim` (`a[^b]+b`) | **-98%** time | 0% |
| `comments-mixed` (`//[^\n]+\|/\*(?s:.*?)\*/`, 10 KB) | not separately recorded vs pre-Opt-1 baseline | **+18-24%** time |
| `comments-mixed-large` (same pattern, 50 KB) | **-94%** time | **+18-24%** time |
| `anchored-xml-tag-large` (anchored `<[^>]+>`) | **-97%** time | **-97%** time |
| `lit-anchor-dominant-body` (`[0-9]{4}INFO:[^\n]+`) | -45% fuel | 0% |

The `+48%` figure previously recorded here was from before commit
`dbb4dfa9` replaced the side-table non-mid dispatch with state-ID-compare
emission; `+18-24%` is the correct current figure for the 3 patterns that
show any regression at all.

### `LikelyMatch` wins (Opt 2 — counted-chain SIMD verifier)

No dedicated `likelytest` numbers are recorded in this doc yet for Opt 2
specifically (a documentation gap, not a performance gap — Opt 2 predates
this doc's numbers section). See
[compile/compile_lm_lnm_test.go](../compile/compile_lm_lnm_test.go) for
correctness coverage of the shape.

### `LikelyNoMatch` wins

| Pattern | Match Δ | No-match Δ |
|---|---|---|
| `alpha-run-impossible-bytes` (`[a-zA-Z]{8,}` on prose with impossible bytes) | -21% time / -59% fuel | -19% time / -59% fuel |

### Gap F wins (unconditional, every `LikelyMode`, TDFA only, since 2026-07-06)

10.2-10.4 KB all-self-loop `matchInput`, anchored capture (`groups_func`):

| Pattern | Self-loop size | Fuel Δ | Time Δ |
|---|---|---|---|
| `(\w+)` | 63 bytes | **-39.5%** | **-42.7%** |
| `<([a-z]+)>` | 26 bytes | **-50.9%** | **-44.9%** |
| `X([a-zA-Z]+)#` | 52 bytes | **-47.7%** | **-41.9%** |

No-match (anchored fail at pos 0) fuel/time unaffected in all three cases.

---

## Implementation references (for contributors)

- **Type definition + gate:** [compile/compile.go](../compile/compile.go) —
  `LikelyMode` type at line 53; `CompileOptions.LikelyMode` at line 89;
  the two remaining `LikelyMode`-gated sites (Opt 2 only) at lines 373, 520.
- **Lit-chain capture path:** [compile/compile.go:373](../compile/compile.go#L373) — `LikelyMode == LikelyMatch && needGroups`.
- **Lit-chain match/find path:** [compile/compile.go:520](../compile/compile.go#L520) — `LikelyMode == LikelyMatch && !needGroups`.
- **Opt 1 default-on sites (no `LikelyMode` gate; the only gate left is `isAnchoredFind(table)`, which is unrelated to the hint):** [compile/compile.go:734](../compile/compile.go#L734) (match layout) and [compile/compile.go:999-1018](../compile/compile.go#L999) (find layout, also feeds the lit-anchor body).
- **LNM Action 5 flag:** `dfaLayout.lnmAction5` in [compile/engine_dfa.go](../compile/engine_dfa.go); threaded into `prefixScanParams.LikelyNoMatch` consumed by `EmitPrefixScan` in [compile/prefix_scan.go](../compile/prefix_scan.go).
- **Phase 4 dispatch:** `emitPhase4Dispatch` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **State-ID compare emission for non-mid:** inline in `buildFindBody`, `buildMatchBody`, `buildLitAnchorFindBody`, `emitPhase4Dispatch` — one block per non-mid entry of the form `local.get state; i32.const STATE; i32.eq; if; emitDominantBulkSkip; end`.
- **Dominant detection:** `detectDominantSelfLoop` and `applyDominantStateEncoding` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **Gap F detection + emission:** `detectTDFABulkSkip` / `emitTDFABulkSkip` in [compile/tdfa_bulk_skip.go](../compile/tdfa_bulk_skip.go); hooked into `newTDFA` / `buildTDFAMatchBody` in [compile/engine_tdfa.go](../compile/engine_tdfa.go).
- **Mode-dispatching test harness:** [re2test/main.go](../re2test/main.go) — `--likelymatch` / `--likelynomatch` flags; [likelytest/main.go](../likelytest/main.go) — three-mode matrix output.
- **Pattern coverage tests:** [compile/compile_lm_lnm_test.go](../compile/compile_lm_lnm_test.go) — covers every LM/LNM lit-chain pattern shape.
- **Archived implementation alternatives:** [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — the side-table dispatch variant that was reverted in favour of state-ID compares.

---

## Known gaps

### 1. No CLI flag to set the hint (corrected 2026-07-08 — the YAML field already shipped)

An earlier version of this doc claimed there was no user-facing way to set
`LikelyMode` at all. That's stale — sub-task H.1 from
[plans/LIKELY.md](../plans/LIKELY.md) (Gap H — Sets) has already shipped,
verified directly against the code (2026-07-08): `config.RegexEntry`,
`config.SetConfig`, and `config.BuildConfig` all have a `likely_mode` YAML
field ([config/config.go](../config/config.go), lines 26/44/208), validated
by `ValidLikelyMode`/`validateLikelyModes`, and resolved via the
`resolveLikelyMode` precedence chain (pattern → enclosing set → global
default → `LikelyNeutral`) in both `CmdCompile`
([compile/compile.go:1439](../compile/compile.go)) and `CompileFile`'s
per-pattern and per-set loops
([compile/set_emit.go:704,716,792,801](../compile/set_emit.go)). The
per-pattern override also applies inside `compilePattern` itself
([compile/compile.go:358](../compile/compile.go)) unconditionally — so it
works for direct `compile.Compile()` callers too, not just YAML-driven
`CmdCompile`, as long as the caller populates `RegexEntry.LikelyMode`.

What's genuinely still missing: **no CLI flag.** `regexped compile` accepts
no `--likely-match` / `--likely-no-match` flag — the hint is YAML-only
(`likely_mode: match|nomatch|neutral` in the config file). For a tool whose
primary interface is YAML config rather than ad-hoc CLI flags, this is a
narrow gap, not the "no user-facing way at all" originally claimed.

### 2. `Action 5` doesn't match the original LNM.md spec

The shipped `Action 5` (force Shufti for 17..64-byte first-byte sets in LNM
mode) is a *different* optimisation from the one described in
[plans/LNM.md](../plans/LNM.md). The plan called for deriving
`P = union of all DFA states' accept bytes` and SIMD-detecting bytes outside
`P` as "impossible bytes". The shipped Action 5 only overrides Action 3's
density heuristic — it doesn't compute or use the body accept set.

The real impossible-byte-SIMD scan was not shipped; it remains a candidate
for future work.

### 3. `LikelyMatch` is a no-op on TDFA/Backtracking-routed patterns outside the lit-chain shape (corrected 2026-07-08 — `LikelyNoMatch` is *not* a no-op)

An earlier version of this doc claimed the `LikelyMode` hint "has no effect"
on patterns that compile to TDFA or Backtracking. That was wrong for
`LikelyNoMatch`, and the wrongness hid a real bug (see [plans/TODO.md](../plans/TODO.md)
task 16). Two things are actually true, and they're different for the two
non-neutral modes:

- **`LikelyMatch`** genuinely is a no-op on TDFA/Backtracking-routed
  patterns, outside the lit-chain interception case already covered by the
  engine matrix above — see *why LM doesn't need TDFA-specific code* / *why
  LM doesn't need BT-specific code* in the *Engine support matrix* section.
  Setting it produces bit-identical WASM to `LikelyNeutral` for these
  engines in every other case.
- **`LikelyNoMatch`** is *not* a no-op. It reaches TDFA- and
  Backtracking-routed patterns through the shared DFA find-wrapper (for
  non-anchored capture patterns) and, for Backtracking specifically, through
  BT's own `find_func`-only DFA-too-large fallback — see *the find-wrapper
  mechanism* in the *Engine support matrix* section above for the mechanism
  and measured WASM-size deltas.

The remaining gap is narrower than originally stated: there is no
compile-time warning, log line, or doc note telling a user whether
`LikelyMatch` did anything for their specific pattern (since whether it did
depends on the lit-chain shape check, which the user can't easily predict
without calling `compile.SelectEngine`). There's no such ambiguity for
`LikelyNoMatch` — it either changes the WASM (find-mode or non-anchored
capture patterns) or the pattern is fully anchored and never scans, in which
case no hint could have an effect regardless of engine.

This is also a gap in the *hint-transparency* mechanism specifically, not
in TDFA's optimisation coverage generally — TDFA gained a real,
mode-independent optimisation of its own (Gap F, 2026-07-06) that fires
automatically for qualifying capture patterns regardless of what
`LikelyMode` is set. A user relying on `LikelyMatch` to know whether TDFA
output will be optimised would still be misled (the hint tells them nothing
either way about Gap F), which is the actual remaining gap.

Users can determine which engine a pattern uses via
`compile.SelectEngine(pattern, opts)`. There is currently no mechanism to
emit a "hint had no additional effect" warning, e.g. through `slog`.

### 4. Sets frontend has the hint; sets suffix bodies don't consume their per-pattern hint yet (corrected 2026-07-08)

An earlier version of this doc claimed the sets path drops `LikelyMode`
entirely. That's stale — verified directly against the code (2026-07-08):
`CompileFile` reads `cfg.LikelyMode`, `sc.LikelyMode` (per-set), and
`re.LikelyMode` (per-pattern) and resolves all three through the same
precedence chain as the no-sets path
([compile/set_emit.go:704,716,792,801](../compile/set_emit.go)) — this is
sub-task H.1 from [plans/LIKELY.md](../plans/LIKELY.md) Gap H, shipped. The
per-pattern suffix-DFA bodies (compiled via the same `compilePattern` as
non-set patterns, [compile/set_emit.go:722](../compile/set_emit.go)) get
their own hint correctly. The **set frontend** (Teddy/AC/Shufti/scalar
selection over the union of literal prefixes) also has it — H.3's
density-gate Action 5 override is live (`frontendShufti` in
[compile/set.go:611](../compile/set.go), gated on
`shuftiBeatsScalar(...) || setLikelyMode == LikelyNoMatch`).

What's genuinely still missing: **sub-task H.2** — `buildSetSuffixBody`
(the per-pattern-in-a-set DFA loop that finds match boundaries within a
set, [compile/engine_dfa.go:2405](../compile/engine_dfa.go)) doesn't have
the dominant-self-loop bulk-skip that single-pattern `buildFindBody` has
had since Task 7. The per-pattern resolved hint is computed and stored on
`CompileSetOptions.PatternLikelyModes`
([compile/set_emit.go:797-802](../compile/set_emit.go)) but nothing reads
it yet — the field exists only as plumbing for H.2, which was never
implemented. This is a real, open, narrow gap: sets containing long-body
patterns (e.g. `ERROR:[^\n]+` as a set member) don't get the bulk-skip win
that the same pattern would get compiled standalone. Not tracked as its own
entry in [plans/TODO.md](../plans/TODO.md) — worth adding if this is picked
up.

### 5. Three Opt-1-eligible pattern shapes regress on the no-match path — for every mode, not just `LikelyMatch`

`ctrl-delim` (rare-byte literal), `comments-mixed`, and `comments-mixed-large`
(multi-dominant alternation) reproduce an +18-24% no-match wall-time
regression (0% fuel change) even with the state-ID-compare dispatch that
replaced the original side-table version (which caused +48-57%). Cross-patch
isolation showed this is a Cranelift JIT codegen quirk tied to specific
operand and data-segment byte values; same WASM op count, same loop
structure, different machine code quality. Not addressable from the WASM
layer.

As of Task 7 Step 2 (2026-07-05) this is **no longer an opt-in trade** —
since the non-mid dispatch is unconditional for every `LikelyMode`, all
users of these three pattern shapes see this regression regardless of which
hint they set, including `LikelyNeutral` (the default). This was a
deliberate decision (the re-measured cost was judged acceptable against the
much larger match-path win once the side-table dispatch was fixed) but it
means the framing changed: it's a property of the pattern shape now, not
something users "opt into" via `LikelyMatch`.

### 6. RESOLVED 2026-07-08 — `LikelyMode` is per-pattern, not just per-Compile-call

An earlier version of this doc claimed a single `compile.Compile` invocation
applies one `LikelyMode` to every entry, forcing users with mixed
match-heavy/no-match-heavy patterns to split them across multiple `Compile`
calls. That's stale — sub-task H.1 shipped: `config.RegexEntry.LikelyMode`
lets each pattern carry its own hint, and `compilePattern` applies it
unconditionally ([compile/compile.go:358](../compile/compile.go)) — this
runs for *every* caller of `compilePattern`, including direct
`compile.Compile()` callers who never go through YAML/`CmdCompile` at all,
as long as they populate `RegexEntry.LikelyMode` on each entry.
`CompileOptions.LikelyMode` remains a single per-call value, but it's now
correctly just the *fallback default* for entries that don't set their own
`LikelyMode` — not a hard per-call ceiling. For sets, the dual-level design
(per-pattern + per-set hints, both live — see gap #4 above) lets the set
frontend and per-pattern suffix bodies pick independently, closing the
"mixed-priority sets" motivating case too (modulo H.2 not yet consuming the
per-pattern hint for the suffix-body bulk-skip itself).

---

## Test harness reference

| Harness | Purpose | LM/LNM flag |
|---|---|---|
| `re2test` | Exhaustive correctness across all three corpora | `--likelymatch`, `--likelynomatch` |
| `likelytest` | Per-pattern 3-mode timing/fuel/WASM-size matrix | Always runs all three modes |
| `perftest` | Cross-language perf comparison vs Rust `regex` crate | No mode flag (always neutral) |
| `compile_lm_lnm_test.go` | Pattern-coverage tests for LM/LNM compile paths | Sets `LikelyMode` directly in `CompileOptions` |

---

## Related documents

- [plans/LIKELY.md](../plans/LIKELY.md) — original optimisation plan and phase
  status.
- [plans/LNM.md](../plans/LNM.md) — original LikelyNoMatch action plan
  (Actions 3, 4, 5, 6).
- [plans/TODO.md](../plans/TODO.md) — task 7 (default-on rollout) decisions;
  task 12 (Gap F pre-implementation measurement); task 13 (open —
  `hasAmbiguousCaptures` possibly over-conservative for
  `X([a-zA-Z]+)Y`-shaped patterns); task 15 (Gap F implementation record);
  task 16 (BT's `LikelyNoMatch` find-fallback bug found and fixed; the
  find-wrapper mechanism uncovered as a side effect; `LikelyMatch` on BT
  investigated and declined).
- [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — archived side-table non-mid dispatch (replaced by state-ID compares).
- [docs/engines.md](engines.md) — engine selection rules.
