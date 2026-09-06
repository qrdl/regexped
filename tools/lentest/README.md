# lentest — the length-sweep harness

Compiles each case once per **declared** input length and drives it at a range of
**actual** input lengths, reporting fuel and module size, with Δ% against the
unset-declaration build at the same actual length.

```
make run         # fuel + size — deterministic, the form to compare trees with
make time        # adds p50 wall-clock (read the caveat below)
make sets        # the set cases only
make baseline    # capture baseline_len.txt
make check       # diff the current tree against it
LENTEST_FILTER=teddy make run
```

## Why this exists

Every SIMD mechanism in the tree is gated on 16–33 bytes of remaining input, and
every crossover around them was calibrated on a 50 KB or 100 KB corpus. Nothing
else here measures a short input: likelytest's inputs are all 50 KB, setperf's
are all 100 KB, and perftest's short anchored rows carry no SIMD channel at all.

The pattern carries no signal about input length — the win case and the harm
case of a given channel compile the *identical* pattern — so the knowledge has
to come from the caller, as `CompileOptions.InputLength` /
`CompileSetOptions.InputLength`. This tool is how any claim about that hint gets
evidence instead of an instruction count.

That distinction is not academic. Two counted figures from the plan this tool
serves have already proved wrong in opposite directions: one was ~12× too
optimistic because a runtime predicate gated the code it counted, and one was
too pessimistic because the emission it counted ran about 4.5 times per call
rather than once.

## Reading it

**Fuel is the gate.** It is deterministic: a difference is a real difference.

**Wall-clock is opt-in (`make time`) and informative only**, for two independent
reasons. Instruction placement on the development machine swings timings by tens
of percent between runs of *identical bytes*. And this harness drives the real
export from the host once per sample, so every cell carries a wasmtime call
crossing of about **2.4µs** — a 4-byte case does ~98 fuel of work underneath
that, so below roughly 1 KB the column measures the crossing and nothing else.
The floor is the price of driving the same ABI at both ends of a row, which is
what makes the two ends comparable; likelytest avoids it with an in-WASM shim
and pays by measuring a shim rather than the export.

**`identical WASM`** means that declared value compiled to the same bytes as the
unset build, so the row was not measured. While a mechanism is still unwired
that is every row, and it is the honest report — comparing wall-clock across
identical bytes measures nothing.

**`n/a`** means the case's generator cannot produce an input of that exact length
in that match/no-match class — a pattern whose shortest match is 202 bytes has
no matching 8-byte input. It is never filled with something else: a corpus that
silently matched nothing caused three separate incidents in setperf, which is
why `inputGen` returns `ok=false` and the cell says so.

**`BADGEN`** is a harness bug — a generator returned the wrong length — and fails
the run.

## What the first run showed

The short-input penalty is a **cliff**, and it is a property of the ragged tail
rather than of short inputs as such. `x[^\n]+` find, no-match:

| actual bytes | 4 | 8 | 12 | 16 | 24 | 32 | 64 | 100K |
|---|---|---|---|---|---|---|---|---|
| fuel | 98 | 170 | 242 | **49** | 193 | **72** | 118 | 147,226 |

Lengths at a multiple of 16 are cheap; everything else pays about 18 fuel for
each byte of the remainder, against about 0.2 for each byte a SIMD chunk covers.
24 bytes is one chunk plus 8 scalar bytes and costs 193; 32 bytes is two chunks
and costs 72.

The same shape appears in the set cases — classchain `scan_any`, no-match, goes
12→315, 16→102, 24→260, 32→134.

So **every call carries up to ~270 fuel of tail regardless of its length**: 0.2%
of a 100 KB scan, and most of a 32-byte one. That is a larger and more general
statement than "short inputs are slow", and it is measurable without any hint.

## Adding a case

`cases()` in `main.go`. Each case names the LENGTH-HINT.md task it exists to
measure in its `task` field, so a row that moves can be traced to the change
that moved it. Every task in Groups A and B should have a row here *before* it
has a line of emitter code.

The generator must return an input of **exactly** `n` bytes or `false`. Narrow a
case's `actual` axis when its shape does not exist at some lengths, rather than
generating something that is not the shape under test.

A set case needs its capability's real ABI — `set_find` is
`(ptr, len, from, gatePtr, outPtr, outCap)` and the scan pair is
`(ptr, len, offset)` — and its input must go **above** the module's data-section
top, because a set module's DFA tables occupy its low memory. Both are handled
in `planMem`/`drive`; the reason they are centralised is that getting either
wrong produces a plausible number rather than an error.
