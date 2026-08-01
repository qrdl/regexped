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
| `LikelyNeutral` | no hint; assume balanced | Gets every default-on optimisation — which by now is most of them: Opt 1 (dominant self-loop bulk-skip, mid- and non-mid-accept, with a self-disabling runtime hysteresis — task 38), Opt 2 (counted-chain SIMD verifier — task 24), Gap F (TDFA capture-body bulk-skip), and the sets equivalents of both (tasks 27/28). No mode-specific code paths fire. |
| `LikelyMatch` | "matches expected, no-match is the cold path" | Three narrower, still-live gates: LM-1 lowers the counted-chain SIMD verifier's minimum literal-chain length from 24 to 1 (unlocks shorter shapes like `AKIA[A-Z0-9]{16}`, N=16); LM-4 lifts the bare (no-literal-prefix) moderately-wide-class self-loop bulk-skip gate for patterns with a compile-time-guaranteed minimum match length ≥ 8 bytes (e.g. `[A-Z]{8,}`); LM-2 adds a `<func>_batch` WASM export for `find_func` and non-anchored `groups_func` patterns, letting a caller drain many matches per host call instead of one. Unlike Opt 2 itself (see *Known gaps* §3 for the history), none of these three add a wall-clock cost to any other mode. |
| `LikelyNoMatch` | "matches rare, scan-and-exit is the hot path" | Forces SIMD prefix-scan routing for first-byte sets in the 17..64-byte band that the density heuristic would otherwise route to scalar (Action 5), with a runtime dense-data switch (task 25, ported to sets by task 28) that falls back to scalar after ~8 unproductive attempts so genuinely dense match data doesn't pay for it. Also forces a SIMD chunk-verify for bare `[class]{M}` (M≤16) lit-anchor prefixes instead of a scalar reverse walk (task 22). |

The three modes are mutually exclusive. `LikelyMatch` does **not** include
`LikelyNoMatch`'s optimisations and vice versa.

---

## `LikelyMatch`/`LikelyNoMatch` can be slower than neutral

Both non-neutral modes are hints, not guarantees: they force a strategy
(SIMD bulk-skip, forced Shufti routing, etc.) that pays off when the
caller's assumption about their own workload holds, and costs *more* than
neutral's default-on heuristics when it doesn't. This is expected, measured
behaviour, not a bug — `tools/likelytest`'s matrix reproduces several such
regressions on its fixed benchmark corpus, documented in
[`tools/likelytest/README.md`](../tools/likelytest/README.md#known-regression-cases).
The clearest example: a bare `[a-zA-Z]{20,}`-style pattern under
`LikelyNoMatch` gains up to -58% fuel when the real no-match data is sparse
in that byte class (binary/control-byte data), but *regresses* when the real
no-match data is dense in it (ordinary prose) — same pattern, same compiled
byte class, opposite result, because only the caller's actual runtime data
distinguishes the two cases and the compiler has no way to see it.

**Before setting `LikelyMode` on a pattern you intend to ship, benchmark it
with `tools/pattest` against a representative sample of your own inputs**
rather than assuming the hint that matches your intuition will help:

```bash
cd tools/pattest
make run ARGS="-pattern '<your pattern>' -mode find -inputs your_inputs.txt"
```

This compiles your exact pattern under all three modes and reports fuel and
wall-clock time for each, bucketed into matching/non-matching inputs using
your own sample data — see `tools/pattest/Makefile` for runnable examples.

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
| Opt 1 — non-mid-accept dominant dispatch, find/match/lit-anchor bodies | `buildFindBody`/`buildMatchBody`/`buildHybridMatchBody`/`buildLitAnchorFindBody`, all consuming `l.dominantStates` | Default-on for all modes since task 38 (2026-07-19), which replaced Task 7 Step 2's original always-on gate with a **self-disabling runtime hysteresis**: after `nonMidHystStreak` (2-4) consecutive attempts that advance < 16 bytes, the dispatch disables itself for the rest of the call, bounding the cost on dense short-run inputs. See *Known trade-off* below for a residual, unrelated wall-time cost on three patterns. |
| Opt 2 — counted-chain SIMD verifier | `analyseLitChain`/`analyseLitChainRange`/`analyseLitChainAlt`/`analyseLitChainPrefixed` (Gap E) and their capture-path counterparts, [compile/engine_dfa.go](../compile/engine_dfa.go) | Default-on for all modes since task 24 (2026-07-10) — was `LikelyMatch`-gated before that; see *Known gaps* §3 for the correction history. `LikelyMatch` still narrows the *minimum* qualifying literal-chain length via LM-1 (see the `LikelyMatch` section below). |
| Gap F — TDFA capture-body bulk-skip | `detectTDFABulkSkip` / `emitTDFABulkSkip` in [compile/tdfa_bulk_skip.go](../compile/tdfa_bulk_skip.go) | Shipped 2026-07-06, unconditional for every mode — see *Gap F* section below |
| Sets — non-mid-accept dominant bulk-skip | `genSuffixWASM` in [compile/engine_dfa.go](../compile/engine_dfa.go) | Default-on for all modes since task 27 (2026-07-19) — was `LikelyMatch`-gated per-bucket before that. Set equivalent of the single-pattern Opt 1 row above. |

**Non-mid-accept dominant dispatch (moved here from `LikelyMatch` on
2026-07-05, Task 7 Step 2; mechanism replaced 2026-07-19, task 38).**
Originally gated to `LikelyMatch` because the first implementation (a
memory-side-table dispatch) caused a 48-57% no-match wall-time regression on
some patterns. That dispatch was replaced with **state-ID compare emission**
(`local.get state; i32.const STATE; i32.eq; if; emitDominantBulkSkip; end`
per non-mid entry — see
[plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive)
for the reverted side-table variant), which shrank the no-match cost enough
to justify making it default-on for every `LikelyMode` (Task 7 Step 2).
That in turn was briefly re-gated back to `LikelyMatch`-only (task 36, a
cheap fallback while chasing a separate regression cluster — see *Known
gaps* §5) before task 38 replaced *both* the gate and the dispatch itself
with the current mechanism: **non-mid encoding piggybacks on the existing
`midAccept[state]` load** (reserved values 254+, one load feeds both
channels — the old per-byte `state == K` compare chain was itself a source
of cost) **plus a self-disabling runtime hysteresis** (`emitHystBulkSkip`):
after `nonMidHystStreak` consecutive attempts that advance less than 16
bytes, the dispatch turns itself off for the rest of the call, bounding the
damage on dense short-run inputs that would otherwise churn the dispatch
unproductively. This is default-on for every `LikelyMode` again, and is
fuel-verified clean (long-run wins kept, short-run harm bounded) — see
*Known trade-off* below for a separate, narrower residual cost.

**Known trade-off.** As of the doc's last direct re-measurement (predating
task 38; not independently re-verified in this pass — the three demo
patterns below are no longer present in `tools/likelytest`'s current
corpus, see *Known gaps* §5), three patterns showed a real, reproducible
no-match wall-time cost with 0% fuel change, identical across all three
`LikelyMode`s:

| Pattern | Match time | No-match time | No-match fuel |
|---|---|---|---|
| `ctrl-delim` (`\x01[^\x02]+\x02`) | ~4.7-5.0 µs | ~5.1-5.2 µs | 73,618 |
| `comments-mixed` (`//[^\n]+\|/\*(?s:.*?)\*/`, 10 KB) | ~1.2 µs | ~1.1 µs | 14,632 |
| `comments-mixed-large` (same pattern, 50 KB) | ~3.8 µs | ~5.1 µs | 73,618 |

The no-match wall-time cost for these three, measured against the
pre-Opt-1-non-mid baseline (i.e. before Task 7 Step 2, 2026-07-05), was
~18-24% (fuel unchanged — attributed to a Cranelift JIT codegen artefact,
not extra emitted work; see *Known gaps* §5 below) — a real reduction from
the original 48-57% side-table regression. `xml-tag`, `bracket-content`,
`paren-block`, and `letter-delim` showed ~0% no-match cost and were
unaffected. Whether task 38's encoding/hysteresis changes moved these
specific numbers further has not been re-measured (they target a different
regression shape — dense short-run harm — not this codegen-tax cluster).

### `LikelyMatch`

Adds, on top of neutral:

| Optimisation | Where | Gate | Patterns affected |
|---|---|---|---|
| LM-1 — lower Opt 2's minimum chain length 24→1 | `analyseLitChain`/`analyseLitChainRange`, [compile/compile.go:594-608](../compile/compile.go) | `litChainMinCount := 1` when `LikelyMode == LikelyMatch` (else 24) | Single-pattern, non-capture `<lit><charclass>{N,N}`/`{N,M}` with `1 ≤ N < 24` — e.g. `AKIA[A-Z0-9]{16}` (N=16), previously excluded and compiled as a plain DFA body. Capture-path analysers (`analyseLitChainGroups*`) are **not** relaxed by LM-1 — they keep the N≥24 threshold under every mode. |
| LM-4 — lift the bare-prefix Shufti self-loop gate | `detectShuftiSelfLoop` / `lmBareShuftiEligible`, [compile/compile.go:846](../compile/compile.go) | `LikelyMode == LikelyMatch && lmBareShuftiEligible(pattern)` (requires a compile-time-guaranteed minimum match length ≥ 8 bytes) | Bare moderately-wide-class runs with **no** literal anchor: `[A-Z]{8,}`, `[a-zA-Z0-9]{10,}` — these have a 9-64-byte mid-accept self-loop but empty literal prefix, so the (otherwise default-on) Shufti self-loop bulk-skip doesn't fire for them outside `LikelyMatch`. The min-length gate specifically excludes low-minimum-length shapes like `(\w+)` (matches average a handful of bytes), where the fixed SIMD setup cost isn't recouped. |
| LM-2 — batched find/groups export | `buildBatchFindWrapperBody`/`buildBatchGroupsWrapperBody`, gated in `compileAll`, [compile/compile.go:1568](../compile/compile.go) | effective per-pattern `LikelyMode == LikelyMatch` | Any pattern with `find_func`, or `groups_func` on a non-anchored (composed find+capture) pattern — engine-independent, adds a `<func>_batch(ptr,len,out_ptr,out_cap,start_pos)→count` export alongside the existing one. See *LM-2: batched find/groups export* below. |

> As of 2026-07-05 (Task 7 Step 2) and 2026-07-10 (task 24), the non-mid-accept
> dominant dispatch and Opt 2 (the counted-chain SIMD verifier) that used to
> be listed here are both **default-on for every `LikelyMode`** — see the
> `LikelyNeutral` section above. `LikelyMatch`'s three remaining unique
> contributions, as of 2026-07-23, are LM-1, LM-4, and LM-2 above — none of
> them touch any other mode's WASM output (confirmed: neutral/`LikelyNoMatch`
> `likelytest` fuel and WASM size are byte-identical before/after all three
> shipped).

### LM-2: batched find/groups export

Shipped 2026-07-23. Any pattern compiled with `find_func`, or with
`groups_func` on a pattern that isn't one of the anchored native lit-chain
shapes (`p.anchored`, Gap C — those don't expose a separate find function to
loop over), gets an **additional** WASM export under `LikelyMatch`:
`<func>_batch(ptr, len, out_ptr, out_cap, start_pos) → count`. It loops
internally — calling the same find (and, for groups, capture) function the
normal export uses, by function index — writing up to `out_cap` matches into
the caller's buffer per call, instead of one match per call. Modelled on the
set `find_all` ABI (see [docs/sets.md](sets.md)).

- **find** record: `(start, end)` as a `u32` pair, 8 bytes, positions
  absolute (relative to `ptr`, same convention as the plain find export).
- **groups** record: `(start, end, group0_start, group0_end, ...)`,
  `(2 + numGroups*2) * 4` bytes — group 0 duplicates `start`/`end` for a
  uniform per-group access pattern.
- The engine producing the underlying find/capture bodies (DFA, lit-anchor,
  alt-lit-anchor, lit-chain, TDFA, Backtracking) is irrelevant — the batch
  wrapper is pure composition over the already-compiled function, so this
  is the one `LikelyMatch` mechanism that reaches TDFA- and
  Backtracking-routed capture patterns too (see the *Engine support matrix*
  section's LM-2 note below).
- **Stub wiring (v1 scope): JS only.** The generated JS `find_func`/
  `groups_func` generators feature-detect the batch export at runtime
  (`typeof _exp['<func>_batch'] === 'function'`) and prefer it when present,
  falling back to the standard one-call-per-match loop otherwise — so the
  same generated stub works whether or not the pattern was compiled under
  `LikelyMatch`. Rust/Go/C/TS/AS stubs, named-groups batching, and a
  config-driven batch capacity (`lm2BatchCap = 256` is fixed in v1) are
  follow-ups, not yet built.
- **Measured**: fuel byte-identical to pre-LM-2 in every mode for every
  `likelytest` case (no engine codegen changed); WASM size flat in
  neutral/`LikelyNoMatch`, grows only in `LikelyMatch` for patterns that get
  a batch export. Node wall-clock on dense `AKIA[A-Z0-9]{16}` input: 1.65-2.93×
  speedup from host-call amortization (median of 5×50 trials, sizes 100 to
  20,000 tokens). Full `make test` (8 re2test stages): 0 failures.
  Full detail in [plans/LM_TODO.md](../plans/LM_TODO.md) LM-2.

### `LikelyNoMatch`

Adds, on top of neutral:

| Optimisation | Where | Gate | Patterns affected |
|---|---|---|---|
| Action 5 — force Shufti for 17..64-byte first-byte sets | `EmitPrefixScan` | `lnmAction5` flag on `dfaLayout`, set from `LikelyMode == LikelyNoMatch` | Patterns whose first-byte set has 17..64 distinct bytes that the neutral-mode density heuristic would route to scalar |
| Task 25 — dense-data adaptive switch (memchr-crate style) | `EmitPrefixScan`'s `adaptive` gate, `denseSwitchThreshold = 8`, [compile/prefix_scan.go](../compile/prefix_scan.go) | Active whenever Action 5 overrode a "scalar wins" static verdict (`p.LikelyNoMatch && !shuftiBeatsScalar(...)`) | Bounds Action 5's downside: forcing Shufti helps on genuinely sparse ("impossible byte") no-match data but *hurts* on dense data using the same first-byte class (`alpha-run`/`word-run`: measured +69%/+78% fuel before this shipped). A runtime counter tracks consecutive no-skip Shufti probes; after 8, the scan switches to the existing scalar tail for the rest of the call — sticky, since the switch persists across the caller's outer scan loop. Shipped 2026-07-09; ported to the set frontend's Shufti path by task 28 (2026-07-19, `shuftiAdaptive` on `compiledSet`). |
| Task 22 — SIMD chunk-verify for bare lit-anchor class prefixes | `simpleClassPrefix` in [compile/lit_anchor.go](../compile/lit_anchor.go), swapped in at [compile/compile.go:952](../compile/compile.go) | `LikelyMode == LikelyNoMatch` | Lit-anchor find patterns whose prefix is a bare `[class]{M}` exact-repeat (no anchors, no concatenation) with `M` in `[1,16]` — e.g. `[0-9]{16}INFO:[^\n]+`. Replaces `buildLitAnchorBackScanBody`'s scalar per-byte reverse walk with a single `v128.load` + nibble-swizzle chunk verify. Shipped 2026-07-09 (only surfaced/documented 2026-07-10 — see *Known gaps* history). |

> **Gap (see *Known gaps* §2):** the *real* LNM Action 5 from the original plan
> ("scan the body accept set P for impossible bytes") was never shipped. What
> ships under the `Action 5` name today is a narrower optimisation: it only
> overrides Action 3's first-byte density heuristic in the 17..64 band, it
> doesn't compute or use the body accept set.

---

## Engine support matrix

| Engine | LikelyNeutral | LikelyMatch | LikelyNoMatch |
|---|---|---|---|
| DFA | ✅ all defaults (Opt 1/Opt 2 default-on) | ✅ LM-1 (lower Opt 2's chain-length floor) + LM-2 (batch export) active | ✅ Action 5 + task 22/25 active |
| Compiled DFA | ✅ | ✅ | ✅ |
| TDFA | ✅ defaults + Gap F bulk-skip (mode-independent) | ⚠️ no LM-specific *TDFA codegen* — LM only affects the *DFA fallback path* if a lit-chain shape matches before TDFA is chosen (see *why LM doesn't need TDFA-specific code* below) — **but LM-2's batch export is engine-independent and still applies** to `find_func`/non-anchored `groups_func` patterns that reach TDFA; see the *LM-2 and engine independence* note below | ✅ Action 5 active — not via TDFA-specific code, but via the shared DFA **find wrapper** that locates the candidate start for non-anchored capture patterns before TDFA extracts captures; see *the find-wrapper mechanism* below |
| Backtracking | ✅ (defaults only — Phase 2/3/5 don't apply since BT is structurally different) | ❌ no BT-specific *codegen*, and none is needed for the capture/match body itself — see *why LM doesn't need BT-specific code* below — **but LM-2's batch export still applies** the same way it does for TDFA; see the *LM-2 and engine independence* note below | ✅ Action 5 active on two independent paths — BT's own `find_func`-only DFA-too-large fallback, and the same shared find wrapper TDFA uses for non-anchored capture patterns; see below |

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
compile pipeline tries the lit-chain capture path *before* falling through
to TDFA (unconditionally, since task 24 — not `LikelyMatch`-gated) — so for
patterns where a lit-chain capture body exists, the lit-chain emission
replaces TDFA entirely regardless of mode. If the pattern doesn't qualify
for lit-chain, TDFA (with Gap F applied automatically, if eligible) is used;
**as of LM-2 (2026-07-23), `LikelyMatch` is no longer a total no-op here**
— any such pattern with `find_func` or a non-anchored `groups_func` gets a
`_batch` export (see *LM-2 and engine independence* below), even though the
TDFA emission itself (and Opt 1, already unconditional) produce
byte-identical output to `LikelyNeutral`. `LikelyNoMatch` is a different
story — see *the find-wrapper mechanism* below.

**Backtracking** is selected for patterns the DFA/TDFA can't handle (e.g.
non-greedy quantifiers, large state count, ambiguous captures). The
backtracking capture-body/match-body emission contains no `LikelyMode`
checks, and — for `match_func`/`groups_func` on an anchored pattern — the
hint genuinely has no effect, since anchored bodies start at position 0 and
never run a scan for the hint to influence. But BT's `find_func`-only path
(used when the pattern's DFA exceeds `MaxDFAStates`/`MaxDFAMemory`) *does*
run a scan, via the same shared `emitPrefixScan` the DFA engine uses
([compile/compile.go:893,903](../compile/compile.go#L893) thread
`LikelyMode == LikelyNoMatch` into `btScanParams.LikelyNoMatch` on the two
scan-table construction branches) — see *the find-wrapper mechanism* below for
why this was broken until 2026-07-08.

### The find-wrapper mechanism (why LNM reaches TDFA and Backtracking capture patterns too)

A capture pattern that isn't inherently anchored (`needGroups && !anchored`
in `compilePattern`, [compile/compile.go:838](../compile/compile.go#L838))
gets **two** compiled bodies, not one: a `findBody` that scans for the
candidate match start, and a separate `captureBody` (TDFA or Backtracking)
that re-runs anchored from that candidate to fill in capture slots. The
`findBody` is always the standard DFA find emission
(`appendFindCodeEntry`, [compile/compile.go:1131](../compile/compile.go#L1131)) —
completely independent of which engine ends up handling `captureBody` — and
it sets `l.lnmAction5 = buildOpts.LikelyMode == LikelyNoMatch`
unconditionally ([compile/compile.go:1129](../compile/compile.go#L1129)), exactly
like a plain `find_func`-only pattern.

This means **`LikelyNoMatch` has a real, measurable effect on patterns
whose captures are extracted by TDFA or Backtracking** — just not through
any TDFA/BT-specific code. Confirmed by direct compilation:
`[a-zA-Z]{20}(\d+)` (routes captures to TDFA, needs a find wrapper) compiles
to 13,812 B under `LikelyNeutral` vs 14,278 B under `LikelyNoMatch`
(byte-different — Action 5 fired); `[a-zA-Z]{20}([^,]+),` (ambiguous
capture, routes to Backtracking) compiles to 9,473 B vs 9,939 B, same
effect. `LikelyMatch` produced byte-identical output to `LikelyNeutral` in
both cases as of 2026-07-08 (Opt 1 was already unconditional; Opt 2 doesn't
apply outside the lit-chain shape) — **this is no longer true as of
2026-07-23**: LM-2 (see the `LikelyMatch` section above) adds a
`groups_func_batch` export to `[a-zA-Z]{20}(\d+)`/`[a-zA-Z]{20}([^,]+),`
under `LikelyMatch` regardless of which engine (TDFA/Backtracking) fills in
the captures, since the batch wrapper composes over the existing find/
capture functions by index rather than touching engine codegen. This
mechanism is exercised across the whole re2-adjusted corpus by
`re2test --likelynomatch --validate-groups` (1,878,840 cases, 0 failures)
— it just wasn't called out in this doc, or in the engine/host support
matrices, before 2026-07-08.

### LM-2 and engine independence

LM-2's batch export (see the `LikelyMatch` section above) is a new
composition **on top of** whichever `findBody`/`captureBody` the engine
selector chose — it calls those functions by index, unmodified, from a new
looping wrapper. This means it is the **one** `LikelyMatch` mechanism that
reaches TDFA- and Backtracking-routed patterns: any `find_func`, and any
non-anchored `groups_func` (the find-wrapper composition case just above,
which is exactly the shape both TDFA and Backtracking use for non-anchored
captures), gets a `_batch` export under `LikelyMatch` — with zero change to
the TDFA/BT engine's own emitted code. The *"why LM doesn't need
TDFA/BT-specific code"* arguments below are still correct for what they
claim (no engine-internal codegen is needed), but no longer imply
`LikelyMatch` is a total no-op for these engines' find/groups exports — see
*Known gaps* §3 for the updated framing.

### Why LM doesn't need TDFA-specific code

Opt 2, the counted-chain SIMD verifier for `<lit><charclass>{N}`-shaped
bodies, is unconditional since task 24 (2026-07-10) — it's no longer
`LikelyMatch`'s "unique contribution" (see the `LikelyMatch` section
above), but the structural argument here is unchanged: the compile pipeline
checks for the lit-chain capture shape and intercepts it — replacing the
emission entirely — *before* the engine selector ever considers TDFA (the
`analyseLitChainGroups*` family of checks in `compilePattern`,
[compile/compile.go](../compile/compile.go), run ahead of the TDFA/BT
selection logic, for every mode). So by construction, any capture pattern
that actually reaches TDFA already isn't lit-chain-shaped. `LikelyMatch`'s
only remaining engine-selection-relevant effect is LM-1 lowering Opt 2's
minimum chain length from 24 to 1 — but LM-1 explicitly does **not** thread
through to the capture-path analysers (they keep N≥24 under every mode), so
this doesn't change which capture patterns reach TDFA either. There is no
missing optimisation to port into TDFA; the shapes Opt 2/LM-1 target are
siphoned off earlier in the pipeline, unconditionally. (LM-2 is a separate
story — see *LM-2 and engine independence* above.)

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
> with no lit-chain shape — the hint is silently a no-op *for the engine's
> own emitted code* beyond what's already unconditional. As of LM-2
> (2026-07-23) this is no longer a total no-op, though: `find_func` always,
> and non-anchored `groups_func` patterns, get a `_batch` export under
> `LikelyMatch` regardless of engine (see *LM-2 and engine independence*
> above) — so the residual gap is narrower still: "no warning about whether
> Opt 2/LM-1's *engine-choice* interception applied," not "no warning that
> the hint did anything at all." `LikelyNoMatch`, by contrast, was never a
> no-op for either engine (see *the find-wrapper mechanism* above).

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
| `match_func` | All Phase 4 + Action 3 + non-mid dominant dispatch + Opt 2 (lit-chain match body, default-on since task 24), all defaults | LM-1 only (lowers Opt 2's chain-length floor 24→1) — no LM-4 (match layout doesn't receive the bare-Shufti flag) and no LM-2 (batch is a find/groups iteration concept; match is a single anchored call) | Action 5 |
| `find_func` | All Phase 2/3/5 + lit-anchor + Action 3 + non-mid dominant dispatch + Opt 2 (lit-chain find body), all defaults | LM-1 (chain-length floor) + LM-4 (bare-prefix Shufti self-loop, min length ≥8) + LM-2 (`_batch` export) | Action 5 + task 22 (bare lit-anchor prefix SIMD) + task 25 (dense-data adaptive switch) |
| `groups_func` | TDFA (+ Gap F bulk-skip if eligible) or Backtracking, both with Opt 2's lit-chain capture body as a default-on interception for qualifying shapes (N≥24 always — LM-1 does not lower this floor for captures) | No LM-1 effect (capture-path analysers keep N≥24 under every mode). LM-2's `_batch` export applies to any non-anchored `groups_func` regardless of engine (see *LM-2 and engine independence*) | Action 5 on the find wrapper for non-anchored patterns (no effect on fully-anchored patterns — nothing to scan); see *the find-wrapper mechanism* in the *Engine support matrix* section |
| `named_groups_func` | Same as `groups_func` | Same as `groups_func`, **except** no LM-2 batch export in v1 (named-groups batching isn't built — see the LM-2 section) | Same as `groups_func` |

For capture-returning host functions: **Opt 2's lit-chain capture body is
default-on** for qualifying shapes (strict alternation of
`<lit><charclass>{N,M}` with captures, prefixed lit-chain
`<class>{N}<lit>...`, etc., N≥24 under every mode — LM-1 does **not** lower
this floor for the capture path, only for plain match/find) since task 24 —
all other capture patterns fall through to TDFA or Backtracking. **LM-2
changes the old "`LikelyMatch` is a no-op outside lit-chain" rule of
thumb**: any non-anchored `groups_func` pattern — TDFA- or
Backtracking-routed included — now gets a `_batch` export under
`LikelyMatch`, engine-independent (see *LM-2 and engine independence*
above). **`LikelyNoMatch`** has an effect on any capture pattern that isn't
fully anchored, regardless of which engine ends up extracting the
captures — see *the find-wrapper mechanism* above.

---

## Sets support

`LikelyMode` is fully propagated to set compilation ([plans/LIKELY.md](../plans/LIKELY.md)
Gap H, all three sub-tasks shipped 2026-06-26/2026-07-08). Three independent
hint layers, same precedence chain as the no-sets path (pattern → enclosing
set → global default → `LikelyNeutral`):

- **`config.RegexEntry.LikelyMode`** (per-pattern) and **`config.SetConfig.LikelyMode`**
  (per-set), resolved by `CompileFile` for both the per-pattern suffix-DFA
  bodies and the set frontend
  ([compile/set_emit.go:719,731,806](../compile/set_emit.go)).
- **Set frontend** (Teddy/AC/Shufti/scalar selection over the union of
  literal prefixes): set-level `LikelyNoMatch` force-selects Shufti for a
  17..64-byte first-byte union that would otherwise fall back to scalar
  (`compile/set.go` density gate, gated on
  `shuftiBeatsScalar(...) || setLikelyMode == LikelyNoMatch`). The dense-data
  adaptive switch (task 25) was **ported to this call site by task 28**
  (2026-07-19, `shuftiAdaptive` field on `compiledSet`) — no longer a gap,
  see below.
- **Per-pattern suffix-DFA bodies** (`buildSetSuffixBody`,
  [compile/engine_dfa.go:3018](../compile/engine_dfa.go#L3018)): both
  mid-accept and non-mid-accept dominant bulk-skip are **default-on for
  every `LikelyMode`** as of task 27 (2026-07-19) — the per-bucket
  `LikelyMode == LikelyMatch` gate via `CompileSetOptions.PatternLikelyModes`
  was removed (confirmed byte-identical WASM between every mode's promoted
  output and the pre-promotion `LikelyMatch` output — promotion added no new
  code path). `genSuffixWASM`
  ([compile/engine_dfa.go:2898](../compile/engine_dfa.go#L2898))
  now unconditionally includes non-mid dominant states.

The dense-data-switch gap this section used to note is closed (task 28).
LM-1/LM-4/LM-2 (the single-pattern `LikelyMatch` mechanisms, see the
`LikelyMatch` section above) have **not** been ported to the sets path —
LM-6 in [plans/LM_TODO.md](../plans/LM_TODO.md) tracks a related sets idea
(keeping counted-chain patterns in single-pattern buckets under
`LikelyMatch`), but LM-1's threshold relaxation, LM-4's bare-Shufti lift,
and LM-2's batch export are all single-pattern-only in v1.

---

## Pattern shape requirements

For the hint to have a measurable effect, the pattern must match one of these
shapes:

### Shapes benefiting from Opt 1 (unconditional — every `LikelyMode`, since task 38, 2026-07-19)

**Non-mid-accept dominant body (state-ID compare dispatch + self-disabling hysteresis):**
- `<lit>[^<exit>]+<lit>` shape — `<[^>]+>`, `/\*.*?\*/`, `"[^"]+"`,
  `\x01[^\x02]+\x02`
- Lit-anchored variant — `<lit-2+-bytes>[^<exit>]+<lit-2+-bytes>` (anchored
  variant where `findLitAnchorPoint` recognises the 2+ byte literal child;
  e.g. `[0-9]{4}INFO:[^\n]+`)
- Same shape inside a **set** bucket's suffix DFA — task 27 (2026-07-19)

This is not gated by the `LikelyMode` hint at all — patterns matching this
shape get the optimisation regardless of what mode you set (or don't set).
Listed here (not under `LikelyMatch`/`LikelyNoMatch` below) because it used
to be a `LikelyMatch`-only target before Task 7 Step 2, then briefly
`LikelyMatch`-only again (task 36) before task 38 made it unconditional a
second time with a cheaper, self-disabling mechanism.

### Shapes benefiting from Opt 2 (unconditional — every `LikelyMode`, since task 24, 2026-07-10)

**Counted-chain (lit-chain), N ≥ 24 under every mode:**
- `<lit><charclass>{N}` — `KEYX[A-Z0-9]{64}` (N=64)
- `<lit><charclass>{N,M}` — `secret_[A-Za-z0-9]{24,40}`
- Strict alt of same, prefixed (Gap E), with `\b` anchors, with captures
  (single capture or named groups), lenient alt (mixed lit-chain +
  non-lit-chain branches, only the lit-chain branches benefit)

Not gated by the hint at all (as of task 24) — same caveat as Opt 1 above:
was `LikelyMatch`-only before 2026-07-10.

### `LikelyMatch` targets

**LM-1 — counted-chain with `1 ≤ N < 24`, non-capture match/find only:**
- `AKIA[A-Z0-9]{16}` (N=16), `ghp_[A-Za-z0-9]{36}` fits Opt 2 unconditionally
  already (N=36≥24) — LM-1's own target population is specifically the
  shorter chains Opt 2's N≥24 floor still excludes. Capture-path shapes
  (`groups_func`/`named_groups_func`) are **not** covered by LM-1 — they
  keep the N≥24 floor under every mode.

**LM-4 — bare moderately-wide-class self-loop, no literal anchor, min match length ≥ 8 bytes:**
- `[A-Z]{8,}`, `[a-zA-Z0-9]{10,}` — identifier/token scanners with no
  literal prefix to anchor on. Excludes low-minimum-length shapes like
  `(\w+)` (see the LM-4 row in the `LikelyMatch` section above for why).

**LM-2 — any `find_func`, or non-anchored `groups_func`:**
- Engine-independent — applies regardless of pattern shape, as long as the
  function is requested and (for groups) the pattern isn't one of the
  anchored native lit-chain shapes. See the *LM-2* subsection above.

### `LikelyNoMatch` targets

**17..64-byte first-byte set in find mode, dense-data-adaptive (task 25):**
- `[a-zA-Z]{8,}`, `[a-zA-Z0-9_]{n,}` — patterns whose first-byte set in this
  size band the density heuristic would route to scalar, on inputs dominated
  by bytes outside the set (so the SIMD scan amortises better than the
  byte-by-byte scalar early-exit). The task-25 adaptive switch means dense
  match data (same class, but few "impossible" bytes) no longer pays a
  lasting cost either — it falls back to scalar after ~8 unproductive
  attempts.

**Same first-byte-set shape, on a non-anchored capture pattern** — e.g.
`[a-zA-Z]{20}(\d+)` or `[a-zA-Z]{20}([^,]+),`: the shared find wrapper that
locates the candidate before TDFA/Backtracking extracts captures uses the
exact same density heuristic, adaptive switch, and Action 5 override. See
*the find-wrapper mechanism* in the *Engine support matrix* section.

**Bare `[class]{M}` (M≤16) lit-anchor prefix (task 22):**
- `[0-9]{16}INFO:[^\n]+` — the backward-scan half of a lit-anchor find,
  when the prefix is a fixed-count single class with no other structure,
  gets a SIMD chunk-verify instead of a scalar reverse walk.

### Shapes benefiting from Gap F (unconditional — every `LikelyMode`, TDFA only, since 2026-07-06)

**TDFA capture pattern with a single dominant self-loop state, 8-64 bytes,
uniform set-to-pos tag ops:**
- `(\w+)`, `<([a-z]+)>`, `X([a-zA-Z]+)#` — see the *Gap F* section below.

Not gated by the hint either — see the *Gap F* section for details and the
scope restrictions (single dominant state, no copy-ops).

If your pattern doesn't match any `LikelyMatch`/`LikelyNoMatch`-specific
shape above, the hint will compile fine but produce bit-identical WASM to
`LikelyNeutral` for that mode — though note Opt 1, Opt 2, and Gap F can
still change the WASM relative to *older* versions of regexped regardless
of the hint, since none of the three is hint-gated anymore.

---

## Known performance numbers

From the [likelytest](../tools/likelytest/) benchmark on 50 KB inputs (unless noted).

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
emission; `+18-24%` was the figure measured for the 3 patterns that showed
any regression at all, before task 38's encoding/hysteresis rework (not
independently re-verified against these exact demo cases since they're no
longer part of `tools/likelytest`'s corpus — see *Known gaps* §5).

### `LikelyMatch` wins (Opt 2 — counted-chain SIMD verifier, unconditional since task 24)

No dedicated `likelytest` numbers are recorded in this doc for Opt 2
specifically (a documentation gap, not a performance gap — Opt 2 predates
this doc's numbers section, and has been unconditional since 2026-07-10).
See [compile/compile_lm_lnm_test.go](../compile/compile_lm_lnm_test.go) for
correctness coverage of the shape.

### LM-1 wins (`LikelyMatch`, lit-chain N<24 relaxation)

| Case | Match fuel Δ | No-match fuel Δ |
|---|---|---|
| `dense-akia` (`AKIA[A-Z0-9]{16}`, N=16, ~1,500 tokens) | **-84%** (1,431,378 → 232,782) | 0% (noise) |
| every other `likelytest` case | 0% | 0% |

Full `make test` (8 re2test stages): 0 failures.

### LM-4 wins (`LikelyMatch`, bare-Shufti self-loop lift)

| Case | Match fuel Δ | No-match fuel Δ |
|---|---|---|
| `dense-bare-upper` (`[A-Z]{8,}`, min length 8) | **-39%** | 0% |
| `dense-words-grouped` (`(\w+)`, min length 1 — excluded by the min-8 gate) | 0% (a plain-`LikelyMatch` gate without the min-length check regressed this case +7%; the min-8 gate exists specifically to exclude it) | 0% |

Full `make test` (8 re2test stages): 0 failures.

### LM-2 wins (`LikelyMatch`, batched find/groups export)

Fuel: byte-identical to pre-LM-2 in every mode, every `likelytest` case
(no engine codegen touched). WASM size: flat in neutral/`LikelyNoMatch`;
grows only in `LikelyMatch`, only for patterns that get a batch export.

Wall-clock (Node, `AKIA[A-Z0-9]{16}` over dense synthetic input, median of
5×50 trials, batch export vs. the same pattern compiled neutral with the
standard one-call-per-match loop):

| Input size | Batch | Unbatched | Speedup |
|---|---|---|---|
| 100 tokens (~2.2 KB) | 0.0223 ms | 0.0368 ms | 1.65× |
| 1,000 tokens (~22 KB) | 0.0553 ms | 0.1538 ms | 2.78× |
| 5,000 tokens (~110 KB) | 0.2509 ms | 0.7348 ms | 2.93× |
| 20,000 tokens (~440 KB) | 1.0433 ms | 2.8371 ms | 2.72× |

Full `make test` (8 re2test stages): 0 failures. Full detail, including a
bug this measurement caught (an early cut cost every module +9 bytes
unconditionally, fixed before shipping), in
[plans/LM_TODO.md](../plans/LM_TODO.md) LM-2.

### `LikelyNoMatch` wins

| Pattern | Match Δ | No-match Δ |
|---|---|---|
| `alpha-run-impossible-bytes` (`[a-zA-Z]{8,}` on prose with impossible bytes) | -21% time / -59% fuel | -19% time / -59% fuel |

### Task 22 wins (`LikelyNoMatch`, bare lit-anchor class-prefix SIMD)

| Scenario | Neutral fuel | LikelyNoMatch fuel | Δ |
|---|---|---|---|
| M=16, dense near-miss false positive (`lit-anchor-false-positive-literal`) | 357,563 | 128,943 | **-64%** |
| M=16, match-side (regression check) | 41,355 | 40,873 | -1% (flat) |
| M=16, realistic prose (`INFO:` rare, no digit-noise before it) | 75,915 | 76,010 | ~0% |
| M=32, dense near-miss (beyond v1's 16-byte chunk cap) | 267,598 | 267,598 | 0% — unaccelerated |

### Task 25/28 wins (`LikelyNoMatch`, dense-data adaptive switch)

Before the switch, forcing Shufti on dense (non-sparse) data using the same
first-byte class as the sparse case it's designed for was a real regression:

| Pattern | Before (forced Shufti) | After (adaptive) |
|---|---|---|
| `alpha-run` (single-pattern, `[a-zA-Z]{20,}`) | +69% fuel vs neutral | ~0-2% |
| `word-run` (single-pattern, `[a-zA-Z0-9_]{20,}`) | +78% fuel vs neutral | ~0-2% |
| `set-shufti-dense-harm` (sets, task 28) | +23%/+21% fuel (no-match/match) vs neutral | recovers to near scalar's floor |

Sparse-data wins (`alpha-run-impossible-bytes` above) are unaffected — the
counter never trips when the scan is genuinely productive.

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

*Line numbers below were re-verified 2026-07-23 against current `HEAD`
where noted; this section drifts fast (three rounds of it already have) —
treat exact line numbers as approximate and grep for the named
function/field if they've moved again.*

- **Type definition + gate:** [compile/compile.go](../compile/compile.go) —
  `LikelyMode` type at line 53; `CompileOptions.LikelyMode` field at line 121.
  Opt 2 (lit-chain match/find and capture paths) is **unconditional** since
  task 24 (2026-07-10) — there is no `LikelyMode`-gated call site left for
  it; only its *minimum chain length* is mode-dependent (LM-1, next).
- **LM-1** (lit-chain N<24 relaxation): `litChainMinCount` at
  [compile/compile.go:594-608](../compile/compile.go#L594-L608) — `1` under
  `LikelyMode == LikelyMatch`, else `24`. Capture-path analysers
  (`analyseLitChainGroups*`) are not threaded through this and keep a fixed
  `24`.
- **LM-4** (bare-Shufti self-loop lift): `lmBareShuftiEligible` flag passed
  to `buildDFALayout` at
  [compile/compile.go:846](../compile/compile.go#L846); detector gate at
  `detectShuftiSelfLoop` in [compile/engine_dfa.go](../compile/engine_dfa.go)
  (search for `lmBareShufti`).
- **LM-2** (batched find/groups export): gating in `compileAll` at
  [compile/compile.go:1568](../compile/compile.go#L1568); wrapper bodies
  `buildBatchFindWrapperBody`/`buildBatchGroupsWrapperBody` and
  `batchOffsets()` in [compile/compile.go](../compile/compile.go); JS stub
  consumer in [generate/js_stub.go](../generate/js_stub.go) (`genJSFindFunc`/
  `genJSGroupsFunc`, feature-detects `_batch` at runtime).
- **Opt 1 default-on sites** (no `LikelyMode` gate since task 38,
  2026-07-19; the only remaining gate is `isAnchoredFind(table)`, unrelated
  to the hint): `applyDominantStateEncoding` call for the match layout at
  [compile/compile.go:819](../compile/compile.go#L819); find layout +
  `l.lnmAction5` assignment around
  [compile/compile.go:1124-1129](../compile/compile.go#L1124-L1129) (also
  feeds the lit-anchor body). Self-disabling hysteresis:
  `emitHystBulkSkip` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **Task 22** (bare lit-anchor class-prefix SIMD): `simpleClassPrefix` in
  [compile/lit_anchor.go](../compile/lit_anchor.go), swapped in at
  [compile/compile.go:952](../compile/compile.go#L952) under
  `LikelyMode == LikelyNoMatch`.
- **LNM Action 5 + task 25 dense-adaptive switch:** `dfaLayout.lnmAction5`
  in [compile/engine_dfa.go](../compile/engine_dfa.go); threaded into
  `prefixScanParams.LikelyNoMatch`/`adaptive` consumed by `EmitPrefixScan`
  in [compile/prefix_scan.go](../compile/prefix_scan.go)
  (`denseSwitchThreshold = 8`).
- **Phase 4 dispatch:** `emitPhase4Dispatch` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **State-ID compare emission for non-mid:** inline in `buildFindBody`, `buildMatchBody`, `buildLitAnchorFindBody`, `emitPhase4Dispatch` — one block per non-mid entry of the form `local.get state; i32.const STATE; i32.eq; if; emitDominantBulkSkip; end`.
- **Dominant detection:** `detectDominantSelfLoop` and `applyDominantStateEncoding` in [compile/engine_dfa.go](../compile/engine_dfa.go).
- **Gap F detection + emission:** `detectTDFABulkSkip` / `emitTDFABulkSkip` in [compile/tdfa_bulk_skip.go](../compile/tdfa_bulk_skip.go); hooked into `newTDFA` / `buildTDFAMatchBody` in [compile/engine_tdfa.go](../compile/engine_tdfa.go).
- **Mode-dispatching test harness:** [tools/re2test/main.go](../tools/re2test/main.go) — `--likelymatch` / `--likelynomatch` flags; [likelytest/main.go](../tools/likelytest/main.go) — three-mode matrix output.
- **Pattern coverage tests:** [compile/compile_lm_lnm_test.go](../compile/compile_lm_lnm_test.go) — covers every LM/LNM lit-chain pattern shape, plus `TestLM2BatchExportGating` for LM-2's export gating.
- **Archived implementation alternatives:** [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — the side-table dispatch variant that was reverted in favour of state-ID compares.
- **Sets — per-pattern/per-set precedence (H.1):** `resolveLikelyMode` calls in `CompileFile` at [compile/set_emit.go:719,731,806](../compile/set_emit.go).
- **Sets — suffix-DFA bulk-skip (H.2, promoted default-on by task 27):** `genSuffixWASM` (from [compile/engine_dfa.go:2898](../compile/engine_dfa.go#L2898)) / `buildSetSuffixBody` (from [compile/engine_dfa.go:3018](../compile/engine_dfa.go#L3018)).
- **Sets — frontend density gate (H.3) + task 28 adaptive switch:** density-gate selection in [compile/set_emit.go](../compile/set_emit.go) (search `shuftiBeatsScalar(union)`); `shuftiAdaptive` field on `compiledSet` for the task-28 port.

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
([compile/compile.go:1597](../compile/compile.go#L1597)) and `CompileFile`'s
per-pattern and per-set loops
([compile/set_emit.go:719,731,806](../compile/set_emit.go)). The
per-pattern override also applies inside `compilePattern` itself
([compile/compile.go:414](../compile/compile.go#L414)) unconditionally — so it
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

### 3. `LikelyMatch`'s effect on TDFA/Backtracking-routed patterns (corrected 2026-07-08 for `LikelyNoMatch`; corrected again 2026-07-23 for LM-2)

An earlier version of this doc claimed the `LikelyMode` hint "has no effect"
on patterns that compile to TDFA or Backtracking. That was wrong for
`LikelyNoMatch` even in 2026-07-08 (the wrongness hid a real bug — see
[plans/TODO.md](../plans/TODO.md) task 16) — and as of LM-2 (2026-07-23) it's
now also incomplete for `LikelyMatch`. Three things are true, and they're
different for the two non-neutral modes:

- **`LikelyMatch`'s effect on the TDFA/Backtracking engines' own emitted
  code** genuinely is a no-op outside the lit-chain interception case
  already covered by the engine matrix above — see *why LM doesn't need
  TDFA-specific code* / *why LM doesn't need BT-specific code* in the
  *Engine support matrix* section. The engine's own `captureBody`/find
  emission is bit-identical to `LikelyNeutral` in every other case.
- **`LikelyMatch`'s effect overall is no longer a no-op**, though: LM-2
  (see the `LikelyMatch` section and *LM-2 and engine independence* above)
  adds a `_batch` export to any `find_func`, and to any non-anchored
  `groups_func`, regardless of which engine fills in the underlying
  find/capture bodies. This is a new composition layered on top of the
  engine's output, not a change to the engine's own codegen — but it does
  mean setting `LikelyMatch` on a TDFA- or Backtracking-routed pattern with
  `find_func`/`groups_func` produces byte-*different* WASM from
  `LikelyNeutral` (a bigger module, with one more exported function), even
  when the lit-chain shape doesn't apply.
- **`LikelyNoMatch`** is *not* a no-op either. It reaches TDFA- and
  Backtracking-routed patterns through the shared DFA find-wrapper (for
  non-anchored capture patterns) and, for Backtracking specifically, through
  BT's own `find_func`-only DFA-too-large fallback — see *the find-wrapper
  mechanism* in the *Engine support matrix* section above for the mechanism
  and measured WASM-size deltas.

The remaining gap is narrower than originally stated, and narrower again
after LM-2: there is no compile-time warning, log line, or doc note telling
a user *which* `LikelyMatch` mechanism (if any) fired for their specific
pattern — whether the lit-chain interception applied (bypassing TDFA/BT
outright) versus only the batch export was added (engine untouched, one
extra function) versus (for `match_func` on a non-lit-chain,
non-capture pattern) truly nothing at all. A user can no longer assume
"`LikelyMatch` did nothing" just because their pattern doesn't fit the
lit-chain shape — for `find_func`/`groups_func` it almost always does
*something* now (the batch export), just not necessarily the lit-chain
interception. There's no such ambiguity for `LikelyNoMatch` — it either
changes the WASM (find-mode or non-anchored capture patterns) or the
pattern is fully anchored and never scans, in which case no hint could have
an effect regardless of engine.

This is also a gap in the *hint-transparency* mechanism specifically, not
in TDFA's optimisation coverage generally — TDFA gained a real,
mode-independent optimisation of its own (Gap F, 2026-07-06) that fires
automatically for qualifying capture patterns regardless of what
`LikelyMode` is set. A user relying on `LikelyMatch` to know whether TDFA
output will be optimised would still be misled (the hint tells them nothing
either way about Gap F), which is a separate, still-open part of this gap.

Users can determine which engine a pattern uses via
`compile.SelectEngine(pattern, opts)`. There is currently no mechanism to
emit a "hint had no additional effect" (or "which mechanism fired") warning,
e.g. through `slog`.

### 4. RESOLVED 2026-07-08, further resolved 2026-07-19 (tasks 27/28) — Sets: frontend, per-pattern hints, and suffix-body bulk-skip all consume `LikelyMode`

An earlier version of this doc claimed the sets path drops `LikelyMode`
entirely, then (corrected 2026-07-08) that the frontend and per-pattern
hints worked but sub-task H.2's suffix-body bulk-skip didn't consume its
per-pattern hint yet. Both claims are now stale — verified directly
against the code:

- `CompileFile` reads `cfg.LikelyMode`, `sc.LikelyMode` (per-set), and
  `re.LikelyMode` (per-pattern) and resolves all three through the same
  precedence chain as the no-sets path
  ([compile/set_emit.go:719,731,806](../compile/set_emit.go)) — sub-task
  H.1 from [plans/LIKELY.md](../plans/LIKELY.md) Gap H.
- The per-pattern suffix-DFA bodies (compiled via the same `compilePattern`
  as non-set patterns) get their own hint correctly.
- The **set frontend** (Teddy/AC/Shufti/scalar selection over the union of
  literal prefixes) has H.3's density-gate Action 5 override in
  [compile/set_emit.go](../compile/set_emit.go) (`shuftiBeatsScalar(...) ||
  setLikelyMode == LikelyNoMatch`).
- **Sub-task H.2** — `buildSetSuffixBody`
  ([compile/engine_dfa.go:3018](../compile/engine_dfa.go#L3018)): both
  mid-accept (Task 7) and, as of **task 27 (2026-07-19)**, non-mid-accept
  dominant bulk-skip are **default-on for every mode** in
  `genSuffixWASM` ([compile/engine_dfa.go:2898](../compile/engine_dfa.go#L2898))
  — task 27 removed the per-bucket `LikelyMode == LikelyMatch` gate this
  entry originally described (shipped 2026-07-08 as `LikelyMatch`-only, see
  [plans/TODO.md](../plans/TODO.md) task 17 for the original measured
  numbers: match fuel -74.1%, match time -44.7%, re2test category
  `SetNonMidDominantTags` 92/92 passing).

**Fully resolved as of task 28 (2026-07-19)**: the runtime-adaptive
dense-data switch (task 25) that used to be listed here as "not yet
back-ported to the set frontend" has been — `shuftiAdaptive` on
`compiledSet` in [compile/set_emit.go](../compile/set_emit.go), mirroring
`EmitPrefixScan`'s `adaptive` gate. See *Task 25/28 wins* in *Known
performance numbers* above.

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

**Status note (2026-07-23):** the dispatch mechanism changed again after
this gap was last measured — task 36 briefly re-gated non-mid to
`LikelyMatch`-only as a cheap fallback while this exact cluster was being
chased, then task 38 (2026-07-19) replaced both the gate and the dispatch
encoding with the reserved-value/hysteresis mechanism described in the
`LikelyNeutral` section above. Whether these three patterns' specific
+18-24% numbers moved is unmeasured — the demo cases (`ctrl-delim`,
`comments-mixed`, `comments-mixed-large`) are no longer present in
`tools/likelytest`'s current corpus (see task 38's own note about
"restoring trimmed likelytest demo cases" — not all were restored). Task
38's hysteresis targets a different regression shape (dense short-run
churn) than this one (attributed to Cranelift codegen quality), so there's
no a priori reason to expect it moved these numbers either way.

### 6. RESOLVED 2026-07-08 — `LikelyMode` is per-pattern, not just per-Compile-call

An earlier version of this doc claimed a single `compile.Compile` invocation
applies one `LikelyMode` to every entry, forcing users with mixed
match-heavy/no-match-heavy patterns to split them across multiple `Compile`
calls. That's stale — sub-task H.1 shipped: `config.RegexEntry.LikelyMode`
lets each pattern carry its own hint, and `compilePattern` applies it
unconditionally ([compile/compile.go:414](../compile/compile.go#L414)) — this
runs for *every* caller of `compilePattern`, including direct
`compile.Compile()` callers who never go through YAML/`CmdCompile` at all,
as long as they populate `RegexEntry.LikelyMode` on each entry.
`CompileOptions.LikelyMode` remains a single per-call value, but it's now
correctly just the *fallback default* for entries that don't set their own
`LikelyMode` — not a hard per-call ceiling. For sets, the dual-level design
(per-pattern + per-set hints, both live — see gap #4 above) lets the set
frontend and per-pattern suffix bodies pick independently, closing the
"mixed-priority sets" motivating case too — including the suffix-body
bulk-skip itself, which now consumes the per-pattern hint (H.2, shipped
2026-07-08, see gap #4 above).

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
  investigated and declined); task 22 (bare lit-anchor class-prefix SIMD);
  task 24 (Opt 2 promoted default-on); task 25/28 (dense-data adaptive
  switch, single-pattern and sets); task 27 (sets non-mid bulk-skip promoted
  default-on); task 36/38 (non-mid dispatch mechanism history — side-table →
  state-ID-compare → reserved-value encoding + hysteresis); task 42 (JS/TS
  stub O(n·m) re-copy fix, landed ahead of LM-2's stub measurements).
- [plans/LM_TODO.md](../plans/LM_TODO.md) — the active `LikelyMatch`
  backlog (LM-0 through LM-7). LM-0 (match-dense likelytest cases), LM-1
  (lit-chain N<24 relaxation), LM-4 (bare-Shufti self-loop lift), and LM-2
  (batched find/groups export) are shipped; LM-3/5/6/7 are open.
- [plans/non_mid_extension.go.archive](../plans/non_mid_extension.go.archive) — archived side-table non-mid dispatch (replaced by state-ID compares).
- [docs/engines.md](engines.md) — engine selection rules.
