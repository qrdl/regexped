# likelytest

`likelytest` is a benchmark harness that compiles a fixed, hand-picked set of
regexp patterns under all three `compile.LikelyMode` values — `neutral`,
`likely-match` (LM), `likely-nomatch` (LNM) — and prints a per-pattern matrix
comparing wall-clock time, fuel, and WASM size across the three modes against
both a matching and a non-matching input.

It exists to catch regressions and confirm wins as the `LikelyMode`
optimisations in `compile/` evolve (see `docs/prefer-hints.md` for the
user-facing mechanism). It is **not** a tool for deciding whether *your* pattern should
use `LikelyMatch`/`LikelyNoMatch` — for that, use `tools/pattest` against
your own pattern and representative inputs (see "Before enabling a
non-neutral mode on your own pattern" below).

## Correctness checking

Before a case's fuel/time numbers are trusted, every (pattern, mode, input)
combination that gets measured is first checked against Go's `regexp`
package (same RE2/Perl leftmost-first semantics as this project's own
engines) — `match`/`find`/`groups` exports are called exactly the way the
benchmark itself calls them (including the `exhaustive` re-entry loop for
dense-workload cases), and the result is compared to Go's ground truth. A
mismatch prints `CORRECTNESS FAIL [mode/input]: ...` to stderr and the run
exits non-zero. `modeSet` cases are not checked here — `tools/re2test`'s own
`--sets` mode already exhaustively covers set correctness.

This exists because a `LikelyMode`-specific correctness bug can hide in
exactly this corpus's blind spot: fuel/time numbers look "good" whether the
compiled WASM took a legitimately cheap path or is silently returning the
wrong answer cheaper than the correct one would cost. The case that motivated
adding this check was exactly that: a false negative in a groups-mode capture
composition, sitting undetected in this benchmark's own `gap-e-groups` case
because nothing here validated output, only cost.

## Running it

```bash
make run        # from this directory — prints the full matrix to stdout
make baseline   # captures current output to baseline_likely.txt
```

`baseline_likely.txt` is a point-in-time snapshot, not a maintained fixture —
it goes stale as soon as a new test case is added or a compiler change moves
the numbers. Treat it as a convenience for local diffing across your own
before/after, not as a source of truth to read on its own; when in doubt,
re-run `make run`.

Debugging env vars:
- `LIKELYTEST_FILTER=<substring>` — run only test cases whose name contains
  the substring.
- `DEBUG_STATS=1` — print p50/p90/p99/mean side by side per measurement
  instead of just p50.

## Reading the matrix

```
mode             match-input        no-match-input
neutral          time / fuel        time / fuel
likely-match     time / fuel (Δ%)   time / fuel (Δ%)
likely-nomatch   time / fuel (Δ%)   time / fuel (Δ%)
```

Δ% is relative to the neutral row. Time is the **p50** (median) of 10,000
in-WASM timing samples per cell (see `computeStat` in `shims.go`).

**Trust fuel, not wall-time, for pass/fail decisions.** Fuel is a
deterministic instruction-count proxy; wall-time on this harness has shown
swings up to ±85% between runs of byte-identical WASM, traced to
Cranelift/CPU instruction-placement noise, not a real difference — the
"placement roulette" finding. A case with 0% fuel Δ and a
large time Δ is noise, not a regression. Compare fuel first; use time only to
sanity-check that nothing has gone catastrophically slower in absolute terms.

**"identical WASM — same as neutral, timing/fuel run skipped"** means that
mode's compiled output is byte-for-byte identical to neutral's for this case
— there is nothing to measure, so the run is skipped rather than reporting a
meaningless 0%. If *both* the LM and LNM rows print this for a case, that
case is compile-time-inert: no `LikelyMode` gate in `compile/` currently
affects its output at all. Such cases test nothing and should be removed
(this happened once already — `dense-set-chains`, a negative control for
LM-6's binPack-merge-refusal gate, removed 2026-08-01 once the case it was
guarding against was confirmed unreachable by construction: AKIA/ghp_ share
no literal, so binPack never considers merging them, independent of
`LikelyMode`).

## Test case catalog

Cases fall into a few families (see the comment above each entry in
`main.go` for the specific optimisation it targets):

- **Shufti prefix-scan targets** (`alpha-run`, `word-run`) — patterns with no
  literal anchor, first-byte set of varying width, testing Action 3/5's
  scalar-vs-SIMD prefix scan routing.
- **Lit-anchor targets** (`lit-anchor-*`) — literal-anchored find with a
  bounded-repeat prefix, testing the backward verify scan (task 22).
- **Dense-workload cases** (`dense-*`) — `exhaustive: true` cases that drain
  every match in a 50 KB buffer instead of stopping at the first one, so
  per-match/per-attempt cost (not just scan-to-first-match cost) shows up in
  the total. These are where most of the `LikelyMatch` wins (and the
  regressions documented below) live.
- **Set cases** (`set-shufti-*`, `dense-set-*`) — `CompileFile`/set
  composition frontend (AC/Teddy/Shufti/scalar selection, binPack merging).
- **Harm/hysteresis guard cases** (anything with `-short` or `-dense-harm`
  in the name) — deliberately adversarial inputs (short runs, dense
  no-match data) that are *expected* to show a small, bounded regression
  rather than the win their sibling case demonstrates. Their purpose is to
  prove the cost stays bounded, not to demonstrate a win.

## Known regression cases

`LikelyMatch`/`LikelyNoMatch` are hints, not free lunches: forcing a
SIMD/bulk-skip strategy that assumes dense, long-run, match-likely (or
no-match-likely) data costs more than the scalar path when the assumption
doesn't hold. The cases below currently show a measured fuel regression
against neutral. All of them are the accepted, understood cost of the
optimisation they belong to — reproduced here so they aren't mistaken for
new bugs on a future re-run.

### Family 1 — deliberate harm/guard cases (expected, by design)

These cases exist *specifically* to measure the bounded cost when a
`LikelyMode` assumption is adversarially violated. A regression here is the
finding, not a defect.

| Case | Mode | Fuel Δ | What it's guarding |
|---|---|---|---|
| `dense-quoted-short` | LM (match) | +3% | LM-3 non-mid Shufti self-loop, short-run hysteresis guard |
| `dense-printable-short` | LM (match) | +26% | LM-5 wide-class-band self-loop, at-minimum-length guard |
| `set-shufti-dense-harm` | LNM (match & no-match) | +5% / +5% | task 28: LNM forcing Shufti on a set frontend when no-match data is dense in the tracked first-byte set |

### Family 2 — the task-25 "dense-switch" residual

`LikelyNoMatch` forces the SIMD (Shufti) prefix scan for 17–64-byte
first-byte sets that a static density heuristic would otherwise route to
scalar (Action 5) — because scalar's per-chunk early-exit beats Shufti's
fixed per-chunk cost when the class is common in the real data (e.g. plain
`[a-zA-Z]` over prose). Task 25 added a runtime `DenseCounter`/
`DenseSkipFlag` pair (`compile/prefix_scan.go`) that falls back to scalar
after ~8 unproductive attempts, collapsing what was originally a +69-78%
fuel regression down to a small residual.

That counter is a WASM **local** — it resets to zero on every call to the
compiled find/groups function. The residual left over is therefore a
function of how many attempts the counter gets to accumulate *before the
function returns* (a match found, or `exhaustive` mode calling `find_all`
repeatedly for the next match), not just of the byte class:

| Case | Mode | Fuel Δ | Why the magnitude differs |
|---|---|---|---|
| `alpha-run` | LNM (match) | +15% | One single-call scan across most of 51 KB — counter trips almost immediately, then stays scalar for the rest. |
| `word-run` | LNM (match) | +17% | Same shape as `alpha-run`. |
| `alpha-run` | LNM (no-match) | +3% | The number task 25's fix collapsed this to (was +69% pre-fix). |
| `word-run` | LNM (no-match) | +3% | Same, was +78% pre-fix. |
| `dense-bare-upper` | LNM (match) | +8% | `exhaustive: true`, 10-30-byte runs — enough room between matches for the counter to trip mid-scan some of the time, but not as cleanly as `alpha-run`'s single long scan. |
| `dense-words-grouped` | LNM (match) | +37% | `exhaustive: true`, `(\w+)` matching almost every ~6 bytes — each `find_all` call returns before the counter can accumulate anywhere near the ~8-attempt threshold, so the switch essentially never trips and the whole scan pays the Shufti tax. |

`dense-bare-upper` and `dense-words-grouped`'s numbers are new findings (not
previously written up in `docs/prefer-hints.md`) — same
mechanism as
the `alpha-run`/`word-run` residual, just a larger instance of it because
of how frequently their matches restart the per-call counter. This is a
real, understood limitation of the task-25 mechanism (short/frequent
matches defeat the adaptive switch), not a new class of bug — but the
mechanism has only ever been tuned/measured against `alpha-run`, `word-run`,
`alpha-run-impossible-bytes`, and `deadskip-near-miss`, which is the whole of
task 25's original measurement plan. A future fix would need to
either persist the counter across calls (state stored outside the function,
e.g. a global or memory cell) or accept that exhaustive/frequent-match
workloads are the worst case for this mechanism.

## Cases that win on both sides

Most `LikelyMatch`/`LikelyNoMatch` wins are one-sided by design (the hint
trades the *other* path's speed for the targeted one). A handful of cases
currently show a mode improving fuel on **both** the match-input and the
no-match-input columns at once:

| Mode | Case | Match fuel Δ | No-match fuel Δ | Mechanism |
|---|---|---|---|---|
| LNM | `alpha-run-impossible-bytes` | -58% | -58% | Action 5 forced Shufti skips impossible-byte runs on both inputs at ~16 B/cycle. |
| LNM | `bt-action5-target` | -58% | -58% | Same Action-5 mechanism, BT-routed (Gap G). |
| LM | `minlen-quantifier-skip` | -82% | -82% | LM-4 bare self-loop bulk-skip — `[a-z]{50,}[0-9]` has no literal prefix, so *both* inputs spend nearly their whole scan inside the bulk-skip-eligible self-loop. |
| LNM | `lit-anchor-false-positive-literal` | -1% | -64% | Task 22 SIMD backward-verify; the match-side gain is real but negligible in magnitude. |
| LNM | `set-shufti-lnm` | -97% | -98% | H.3 forced Shufti on the whole 21-pattern set frontend. |

### Should any of these be promoted to default (neutral)?

No, for four of the five — and this table is exactly why: **each of these
has a sibling case in this same suite, using the identical compiled pattern,
that regresses under different runtime data.** The "win" is a property of
the workload the caller's data happens to have, not of the pattern shape,
which is precisely what a default-on promotion cannot safely assume.

- `alpha-run-impossible-bytes` (sparse data, -58%/-58%) vs. `alpha-run` —
  same pattern, same compiled WASM, dense prose instead — loses +15%/+3%
  under the same mode (see Family 2 above). `shuftiBeatsScalar`'s density
  heuristic only sees the abstract byte class (`[a-zA-Z]`), never the
  caller's actual data, so neutral mode has no way to pick correctly here.
- `set-shufti-lnm` (sparse no-match data, -97%/-98%) vs.
  `set-shufti-dense-harm` — the *same 21 patterns*, dense no-match data —
  loses +5%/+5% (Family 1 above). This is the cleanest proof in the suite:
  identical pattern set, opposite result, driven entirely by data density.
- `minlen-quantifier-skip` (-82%/-82%) qualifies for the same LM-4 gate
  (min length ≥ 8) as `alpha-run`/`word-run`, which show a persistent "LM
  contract cost" residual (+22%/+24% match fuel, Family 2 above) under the
  same mechanism. The gate is shape-based (compile-time min length), but
  "min length ≥ 8" doesn't distinguish "long dominant self-loop run" (wins)
  from "one short match buried in a large buffer" (loses) — that
  distinction is workload, not shape.
- `bt-action5-target` inherits the same data-dependence as
  `alpha-run-impossible-bytes` — it's the same Action-5 mechanism, just
  BT-routed.

Promoting any of these to unconditional-default would mean every pattern of
that shape pays the regression the moment its real data doesn't match the
adversarial-sparse/long-run assumption baked into the win case — and for
common classes like letters/word-chars, dense/common-byte data is
arguably the *more* likely real-world case, not the exception.

`lit-anchor-false-positive-literal` (task 22's SIMD backward-verify) is the
one case here **without** a demonstrated sibling regression in the current
suite — it's a plausible future promotion candidate. But "no counter-case
has surfaced yet" isn't "proven safe": every optimisation that *has* been
promoted to unconditional-default in this codebase (Opt 1, Opt 2, Gap F, the
sets bulk-skip) only shipped that way after a dedicated adversarial
counter-case was built and run through the full likelytest matrix plus the
complete 8-stage re2test sweep — and Opt 1 specifically failed that process
on its first design (a 48-57% no-match regression from the original
side-table dispatch) and had to be redesigned before it could go default.
Task 22 hasn't been through that drill yet; see `CLAUDE.md`'s "Load-bearing
engine-selection gates" note for the standing project policy this falls
under — don't relax a gate (or remove one entirely by defaulting it on)
without measuring the specific counter-shape first.

## Before enabling a non-neutral mode on your own pattern

This harness's corpus is fixed and adversarial by design — it exists to
stress specific optimisation gates, not to represent any particular
production pattern or workload. The regressions above are real, but they're
specific to *these* patterns and *these* synthetic inputs. Whether
`LikelyMatch` or `LikelyNoMatch` helps or hurts **your** pattern depends on
your pattern's shape and your actual data's density/run-length
characteristics — the same class (`[a-zA-Z]`) wins big under `LikelyNoMatch`
on sparse data (`alpha-run-impossible-bytes`: -58% fuel) and regresses on
dense prose (`alpha-run`: +15% fuel).

Before setting `LikelyMode` on a pattern you intend to ship, benchmark it
with `tools/pattest` against a representative sample of your own inputs:

```bash
cd tools/pattest
make run ARGS="-pattern '<your pattern>' -mode find -inputs your_inputs.txt"
```

`pattest` compiles your exact pattern under all three modes and reports
fuel and wall-clock time for each, bucketed into matching/non-matching
inputs using your supplied sample — see `tools/pattest/Makefile` for
runnable examples (`make example-lm`, `make example-lnm`,
`make example-combined`).
