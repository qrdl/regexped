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
| `LikelyMatch` | "matches expected, no-match is the cold path" | Unlocks aggressive match-path emissions (counted-chain SIMD verifier, lit-chain bodies, non-mid-accept dominant bulk-skip). Two of those add a ~+48% wall-clock cost on the no-match path of certain pattern shapes — see *Known regressions* below. |
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

### `LikelyMatch`

Adds, on top of neutral:

| Optimisation | Where | Gate | Patterns affected |
|---|---|---|---|
| Opt 2 — counted-chain SIMD verifier (no captures) | [compile/compile.go:409](../compile/compile.go) | `LikelyMode == LikelyMatch && !needGroups` | Strict `<lit><charclass>{N}` and strict alts of same |
| Opt 2 — counted-chain SIMD verifier (with captures) | [compile/compile.go:262](../compile/compile.go) | `LikelyMode == LikelyMatch && needGroups` | Same shape, capture path |
| Non-mid-accept dominant dispatch — find body | `buildFindBody` non-mid branch | `LikelyMode == LikelyMatch` | Patterns with a dominant self-loop body state that is NOT mid-accepting (`<[^>]+>`, `/\*.*?\*/`, etc.) |
| Non-mid-accept dominant dispatch — match body | `buildMatchBody` / `buildHybridMatchBody` | `LikelyMode == LikelyMatch` | Anchored match counterpart |
| Non-mid-accept dominant dispatch — lit-anchor body | `buildLitAnchorFindBody` non-mid branch | `LikelyMode == LikelyMatch` | Lit-anchored patterns with non-mid dominant body |

The non-mid dispatch uses **state-ID compare emission** (`local.get state;
i32.const STATE; i32.eq; if; emitDominantBulkSkip; end` per non-mid entry) —
not a memory-side-table lookup. The side-table variant was tried and reverted;
see [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive).

**Known regression**: for two of six canonical non-mid pattern shapes
(`ctrl-delim` rare-byte literal, `comments-mixed-large` multi-dominant
alternation), enabling the non-mid dispatch adds ~+48% wall-clock on the
no-match path while keeping ~-98% match-path speedup. This is a Cranelift JIT
codegen artefact confirmed by cross-patch isolation and is not addressable from
the WASM layer. `LikelyMatch` users opt into this trade by signalling
"matches likely".

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
| DFA | ✅ all defaults | ✅ all LM-gated opts active | ✅ Action 5 active |
| Compiled DFA | ✅ | ✅ | ✅ |
| TDFA | ✅ (defaults only) | ⚠️ no TDFA-specific code; LM only affects the *DFA fallback path* if a lit-chain shape matches before TDFA is chosen | ❌ no LNM-specific code |
| Backtracking | ✅ (defaults only — Phase 2/3/5 don't apply since BT is structurally different) | ❌ no BT-specific code | ❌ no BT-specific code |

**Compiled DFA** is the DFA emission with hybrid (literal-chain) dispatch
applied; it inherits every LM/LNM code path the DFA engine has.

**TDFA** (Laurikari tagged DFA) is selected for capture-track patterns that
qualify (no non-greedy, no line anchors, no word boundaries, no ambiguous
alternations, ≤ `MaxDFAStates`, ≤ `MaxTDFARegs`). The TDFA emission itself
contains no `LikelyMode` checks. However, the compile pipeline tries the
LM lit-chain capture path *before* falling through to TDFA — so for patterns
where a lit-chain capture body exists, `LikelyMatch` replaces the TDFA emission
entirely with a faster lit-chain emission. If the pattern doesn't qualify for
lit-chain, TDFA is used and the hint has no further effect.

**Backtracking** is selected for patterns the DFA/TDFA can't handle (e.g.
non-greedy quantifiers, large state count, ambiguous captures). The
backtracking emission contains no `LikelyMode` checks. The hint has no
effect.

> **Gap (see *Known gaps* §3):** TDFA and Backtracking engines have no
> mode-specific optimisations. Users running these engines see no benefit from
> the hint, and there's no compile-time warning to that effect.

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
| `match_func` | All Phase 4 + Action 3 defaults | Lit-chain match body (Opt 2) + non-mid dominant dispatch | Action 5 |
| `find_func` | All Phase 2/3/5 + lit-anchor + Action 3 defaults | Lit-chain find body (Opt 2) + non-mid dominant dispatch + lit-chain capture body if find+groups combo | Action 5 |
| `groups_func` | TDFA or Backtracking — no LM/LNM effect *unless* the pattern is a lit-chain capture shape | Lit-chain capture body (Opt 2 with captures) replaces TDFA/BT entirely | No effect (still TDFA / BT) |
| `named_groups_func` | Same as `groups_func` | Same as `groups_func` | Same as `groups_func` |

For capture-returning host functions the rule of thumb is: **`LikelyMatch` is
the only setting that has any effect**, and only when the pattern is one of the
lit-chain capture shapes (strict alternation of `<lit><charclass>{N,M}` with
captures, prefixed lit-chain `<class>{N}<lit>...`, etc.). All other capture
patterns fall through to TDFA or Backtracking, both of which ignore
`LikelyMode`.

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

### `LikelyMatch` targets

**Counted-chain (Opt 2, lit-chain):**
- `<lit><charclass>{N}` — `AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9]{36}`
- `<lit><charclass>{N,M}` — `AKIA[A-Z0-9]{8,16}`, `secret_[A-Za-z0-9]{24,40}`
- Strict alt of same — `AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}`
- Prefixed (Gap E) — `[0-9]{8}ghp_[A-Za-z0-9]{36}`
- With `\b` anchors — `\bAKIA[A-Z0-9]{16}\b|\bghp_[A-Za-z0-9]{36}\b`
- With captures — same shapes wrapped in a single capture or with named groups
- Lenient alt (mixed lit-chain + non-lit-chain branches) — only the lit-chain
  branches benefit

**Non-mid-accept dominant body (state-ID compare dispatch):**
- `<lit>[^<exit>]+<lit>` shape — `<[^>]+>`, `/\*.*?\*/`, `"[^"]+"`,
  `\x01[^\x02]+\x02`
- Lit-anchored variant — `<lit-2+-bytes>[^<exit>]+<lit-2+-bytes>` (anchored
  variant where `findLitAnchorPoint` recognises the 2+ byte literal child;
  e.g. `[0-9]{4}INFO:[^\n]+`)

### `LikelyNoMatch` targets

**17..64-byte first-byte set in find mode:**
- `[a-zA-Z]{8,}`, `[a-zA-Z0-9_]{n,}` — patterns whose first-byte set in this
  size band the density heuristic would route to scalar, on inputs dominated
  by bytes outside the set (so the SIMD scan amortises better than the
  byte-by-byte scalar early-exit).

If your pattern doesn't match one of these shapes, the hint will compile
fine but produce bit-identical WASM to `LikelyNeutral`.

---

## Known performance numbers

From the [likelytest](../likelytest/) benchmark on 50 KB inputs:

### `LikelyMatch` wins (vs `LikelyNeutral` baseline)

| Pattern | Match Δ | No-match Δ |
|---|---|---|
| `ctrl-delim` (`\x01[^\x02]+\x02`) | **-98%** time | **+48%** time |
| `xml-tag` (`<[^>]+>`) | **-98%** time | 0% |
| `bracket-content` (`\[[^\]]+\]`) | **-98%** time | 0% |
| `paren-block` (`\([^)]+\)`) | **-97%** time | 0% |
| `letter-delim` (`a[^b]+b`) | **-98%** time | 0% |
| `comments-mixed-large` (`//[^\n]+|/\*(?s:.*?)\*/`) | **-94%** time | **+48%** time |
| `anchored-xml-tag-large` (anchored `<[^>]+>`) | **-97%** time | **-97%** time |
| `lit-anchor-dominant-body` (`[0-9]{4}INFO:[^\n]+`) | -45% fuel | 0% |

### `LikelyNoMatch` wins

| Pattern | Match Δ | No-match Δ |
|---|---|---|
| `alpha-run-impossible-bytes` (`[a-zA-Z]{8,}` on prose with impossible bytes) | -21% time / -59% fuel | -19% time / -59% fuel |

---

## Implementation references (for contributors)

- **Type definition + gate:** [compile/compile.go](../compile/compile.go) —
  `LikelyMode` type at line 53; `CompileOptions.LikelyMode` at line 89;
  per-pattern gates at lines 262, 409, 625, 870.
- **Lit-chain capture path:** [compile/compile.go:262](../compile/compile.go#L262) — `LikelyMode == LikelyMatch && needGroups`.
- **Lit-chain match/find path:** [compile/compile.go:409](../compile/compile.go#L409) — `LikelyMode == LikelyMatch && !needGroups`.
- **Non-mid dominant gate (find layout):** [compile/compile.go:870](../compile/compile.go#L870) — filters non-mid entries out of `l.dominantStates` for non-LM modes.
- **Non-mid dominant gate (match layout):** [compile/compile.go:625](../compile/compile.go#L625) — same filter for `lm.dominantStates`.
- **LNM Action 5 flag:** `dfaLayout.lnmAction5` in [compile/engine_dfa.go](../compile/engine_dfa.go); threaded into `prefixScanParams.LikelyNoMatch` consumed by `EmitPrefixScan` in [compile/prefix_scan.go](../compile/prefix_scan.go).
- **Phase 4 dispatch:** `emitPhase4Dispatch` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **State-ID compare emission for non-mid:** inline in `buildFindBody`, `buildMatchBody`, `buildLitAnchorFindBody`, `emitPhase4Dispatch` — one block per non-mid entry of the form `local.get state; i32.const STATE; i32.eq; if; emitDominantBulkSkip; end`.
- **Dominant detection:** `detectDominantSelfLoop` and `applyDominantStateEncoding` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **Mode-dispatching test harness:** [re2test/main.go](../re2test/main.go) — `--likelymatch` / `--likelynomatch` flags; [likelytest/main.go](../likelytest/main.go) — three-mode matrix output.
- **Pattern coverage tests:** [compile/compile_lm_lnm_test.go](../compile/compile_lm_lnm_test.go) — covers every LM/LNM lit-chain pattern shape.
- **Archived implementation alternatives:** [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — the side-table dispatch variant that was reverted in favour of state-ID compares.

---

## Known gaps

### 1. No user-facing way to set the hint

`LikelyMode` is reachable only through Go API (`compile.CompileOptions`).
Neither `config.BuildConfig` nor `config.RegexEntry` has a `likely_mode` (or
similar) field, and the `regexped compile` CLI accepts no `--likely-match` /
`--likely-no-match` flag.

`CmdCompile` ([compile/compile.go:1227](../compile/compile.go#L1227)) builds
`CompileOptions` from only `MaxDFAStates` and `MaxTDFARegs`.

**Planned fix:** sub-task H.1 in [plans/LIKELY.md](../plans/LIKELY.md) (Gap
H — Sets). Adds three optional `likely_mode` fields — on `RegexEntry`
(per-pattern), on `SetConfig` (per-set, controls frontend strategy), and on
`BuildConfig` (global default) — resolved by a layered precedence rule.
Same change closes gap #6 below.

### 2. `Action 5` doesn't match the original LNM.md spec

The shipped `Action 5` (force Shufti for 17..64-byte first-byte sets in LNM
mode) is a *different* optimisation from the one described in
[plans/LNM.md](../plans/LNM.md). The plan called for deriving
`P = union of all DFA states' accept bytes` and SIMD-detecting bytes outside
`P` as "impossible bytes". The shipped Action 5 only overrides Action 3's
density heuristic — it doesn't compute or use the body accept set.

The real impossible-byte-SIMD scan was not shipped; it remains a candidate
for future work.

### 3. TDFA and Backtracking engines ignore `LikelyMode`

The hint has no effect on patterns that compile to TDFA or Backtracking.
There is no compile-time warning, log line, or doc note pointing this out to
users when they set the hint on a pattern that ends up on one of those
engines.

Users can determine which engine a pattern uses via
`compile.SelectEngine(pattern, opts)`. There is currently no mechanism to
emit a "hint ignored" warning, e.g. through `slog`.

### 4. Sets path drops `LikelyMode`

When the YAML config contains a `sets:` block, the entire compile path —
including per-pattern entries — goes through `CompileFile` which builds
`CompileOptions` from only `MaxDFAStates` and `MaxTDFARegs`. Even if gap 1
were fixed and `LikelyMode` were threaded through `CmdCompile` for the
no-sets path, the sets path would still discard it.

This is a one-line fix in `CompileFile` once gap 1 is resolved (read
`cfg.LikelyMode` and copy it into `opts.LikelyMode`).

### 5. Two LM pattern shapes still regress on the no-match path

`ctrl-delim` (rare-byte literal) and `comments-mixed-large` (multi-dominant
alternation) reproduce a +48% no-match wall-time regression even with the
state-ID-compare dispatch workaround. Cross-patch isolation showed this is a
Cranelift JIT codegen quirk tied to specific operand and data-segment byte
values; same WASM op count, same loop structure, different machine code
quality. Not addressable from the WASM layer.

`LikelyMatch` users opt into this trade by signalling "matches expected", so
the regression is contractually acceptable. But it's worth documenting
explicitly — users running these shapes on no-match-heavy workloads with
`LikelyMatch` set will see a regression.

### 6. `LikelyMode` is per-Compile-call, not per-pattern

A single `compile.Compile` invocation applies one `LikelyMode` to every entry
in the call. If a user has 50 patterns and one of them is match-heavy while
the other 49 are no-match-heavy, they'd need to split the patterns across
multiple Compile calls (and merged WASM modules) to apply different hints.

**Planned fix:** sub-task H.1 in [plans/LIKELY.md](../plans/LIKELY.md) (Gap
H — Sets). Per-pattern `likely_mode` on `RegexEntry` lets each pattern
carry its own hint; `compilePattern` derives `opts.LikelyMode` from a
precedence chain (pattern → enclosing set → global default) instead of
from a single per-call value. Same change closes gap #1 above. For sets,
the dual-level design (per-pattern + per-set hints) lets the set frontend
and per-pattern suffix bodies pick their best strategies independently —
the canonical motivating use case is mixed-priority sets where the
frontend wants one bias and individual patterns want another.

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
- [plans/TODO.md](../plans/TODO.md) — task 7 (default-on rollout) decisions.
- [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — archived side-table non-mid dispatch (replaced by state-ID compares).
- [docs/engines.md](engines.md) — engine selection rules.
