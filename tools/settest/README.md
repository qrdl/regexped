# settest

Ad-hoc benchmarking for **one set**, the set analogue of [`tools/pattest`](../pattest).
It answers a single question: **can this set benefit from a `hints:` value?**

```
settest -config <yaml> [-set <name>] [-cap <capability>] -inputs <file>
        [-detailed] [-force-frontend <fe>] [-adaptive on|off] [-iters <n>]
```

`-config` takes the same YAML `regexped compile` reads, so the set under test is
the set you would ship — the patterns, the selector, the declared capabilities,
`overlapping:`, all of it. settest compiles it three times, varying **only** the
set-level `hints:` over neutral / `prefer-match` / `prefer-no-match`.

## What it prints

Three layers, cheapest first.

**1. Did the hint change the module at all?** A hint that compiles
byte-identical to neutral reached no emitter, and no amount of timing will make
it help. That row says so and is not measured — comparing wall-clock across
identical bytes is noise, not signal (swings up to ±137% have been observed on
literally the same module).

**2. What did it change?** Each mode prints its `SetDiag` row — frontend, scan
body, anchored body, bucket count. A body selection is invisible everywhere
else, and it is usually the whole story: the same set, same patterns, same
answers, one eligibility test apart, seven times the fuel.

```
=== Compile ===
  mode               wasm size      Δ%  buckets  frontend     scan body      anchored body
  neutral               23,228       —       21  scalar       —              —
  prefer-match          23,228      0%       21  scalar       —              —   [identical WASM — the hint reached no emitter]
  prefer-no-match       18,949    -18%       21  shufti       —              —
```

**3. Did it pay?** Fuel (deterministic) and wall-clock p50 for one capability
call, against a matching and a non-matching bucket of your own inputs.

```
=== Non-matching inputs (6) ===
  mode                       fuel      Δ%       p50 time      Δ%
  neutral                  30,469       —         8.5 µs       —
  prefer-match     identical WASM — the hint reached no emitter, measurement skipped
  prefer-no-match           8,996    -70%         7.1 µs    -17%
```

**Gate your decision on fuel.** Wall-clock on this dev machine carries
instruction-placement noise large enough to swamp a real win in either
direction; fuel is deterministic and is the number to trust.

Both buckets matter. A hint is a hint precisely because it trades one against
the other — `example-lnm` below wins 75% of the fuel on non-matching input and
*loses* 43% on matching input. Which bucket your traffic lives in is the
decision.

## Inputs

`-inputs` is a text file, one candidate input per line; `#` lines and blank
lines are skipped. Bucketing uses Go's stdlib `regexp` as ground truth: an
input is "matching" when **any** pattern the set actually contains matches it —
anchored over the whole input for `match_any`/`match_all`, unanchored for
`scan_any`/`scan_all`/`find`.

"Actually contains" is doing work there. A pattern the compiler dropped from
the set (over `max_fallback_states`, capture-bearing) can never match, so it is
excluded from the oracle and a warning names it. Otherwise inputs would land in
the wrong bucket and the sanity check below would fail for a reason that is not
a bug.

Before any measurement, settest checks that the driven export agrees with the
oracle about whether each input matches at all. It is not a correctness suite —
`make setcaps` is — but a mis-driven ABI measures the wrong work entirely, and
every number under it would be meaningless rather than merely wrong.

## Capabilities

`-cap` drives any of the five: `match_any`, `match_all`, `scan_any`,
`scan_all`, `find`. It may be omitted when the set declares exactly one.
`find` is driven to exhaustion the way a generated iterator drives it (zero the
gate array, resume at `start + 1`); everything else is one call over the whole
input.

The `_all` ABI — `i64` bitmask below 64 ids, `out_ptr` bitmap above it, and
also `out_ptr` at any width once a set member falls back to Backtracking — is
read off the **function's type** rather than predicted from the pattern count,
because the pattern count cannot tell you which one shipped.

The module is compiled with every capability the config declares, not just the
driven one: that is the module you would ship, so it is the one whose size is
worth reporting. It also makes the identical-WASM verdict conservative in the
right direction — "identical" is a definitive no for every capability at once.

## `-adaptive`

Test-only, and a different kind of knob from the hints: it pins
`shuftiAdaptive`, the runtime density switch a forced-Shufti set carries. That
switch counts consecutive unproductive SIMD probes and disables the prefilter
for the rest of a call once the data turns out to be dense in the tracked first
bytes.

It exists because nothing reachable from YAML compiles both arms. The verdict
is `prefer-no-match && !rare`, deterministic per set, so "is the switch worth
its counter, flag and per-attempt branch" cannot be asked by varying a hint —
only by compiling the same set twice. `make example-adaptive` is that pair.

Measured 2026-09-01 on `examples/dense_harm.yaml`, `find`, prefer-no-match
row, fuel:

| input | adaptive on | adaptive off | switch |
|---|---|---|---|
| dense in [A-U], matching | 387,906 | 463,035 | **−16.2%** |
| dense in [A-U], non-matching | 532,866 | 642,794 | **−17.1%** |
| sparse prose, matching | 33,920 | 33,062 | +2.6% |
| sparse prose, non-matching | 8,996 | 8,224 | +9.4% |

Saves a sixth of the body's fuel on the input it exists for, costs a few
percent where it never fires. That is the trade, and it is live.

## `-force-frontend`

Test-only, mirroring `setperf`'s knob: `teddy`, `ac`, `scalar`, `packed-pair`.

`shufti` is accepted too and is not the same kind of thing. Shufti is reachable
**only** out of the scalar branch, in production only after Aho-Corasick
declines over its 512 KB budget — so asking for it simulates that decline with
a one-byte AC budget and lets the chooser proceed. It lands on Shufti only if
the set's first-byte union is in the band, and on plain scalar otherwise. The
frontend column reports what actually shipped either way.

This knob is what `example-shufti` needs: left alone, the chooser sends its 21
short literals to Teddy, where all three modes emit identical bytes and the run
measures nothing hint-related.

## Examples

```bash
make example-lnm       # literal-less class chains, prefer-no-match union stride
make example-shufti    # 21 [A-U] literals, prefer-no-match forces Shufti
make example-adaptive  # the same set on dense input, Shufti density switch on vs off
make run ARGS="-config myset.yaml -cap find -inputs myinputs.txt"
```

## Relation to the other harnesses

| tool | patterns | inputs | compares |
|---|---|---|---|
| `settest` | your YAML set | your file | the three set-level hints |
| `pattest` | your `-pattern` | your file | the three `LikelyMode`s, one pattern |
| `likelytest` | a curated fixture list | generated | the three modes, patterns *and* sets |
| `setperf` | a fixed corpus | generated | regexped vs `regex-automata` |

`settest` is the one to reach for when the set is *yours*. See
[docs/prefer-hints.md](../../docs/prefer-hints.md) for what each hint actually
changes and [docs/sets.md](../../docs/sets.md) for the capability contract.
