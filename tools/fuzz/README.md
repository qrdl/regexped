# fuzz — byte-level correctness fuzzer

Mutates `(pattern, input)` string pairs and compares regexped's compiled WASM
against Go stdlib `regexp` on the same pair.

**Layer 1** covers the no-capture `find` body. **Layer 2** covers the paths
Layer 1 never reaches — anchored `match`, captures under the selector's
engine, captures cross-checked on TDFA *and* Backtracking, repeated `find`
iteration, and the set pipeline — see "Layers" below. Rejects (skips) any pair Go
stdlib itself can't compile, or that regexped can't compile (unsupported
syntax, engine state-limit overflow) — those aren't regexped bugs.

## Usage

```bash
make seed         # Layer 1: replay the seed corpus only (fast, deterministic)
make fuzz         # Layer 1: 1-minute interactive fuzz run
make fuzz-long    # Layer 1: 8-hour overnight run

make seed-all     # every layer's seed corpus (what CI should run)
make seed-match   make fuzz-match     # anchored match
make seed-groups  make fuzz-groups    # captures, selector's engine
make seed-engines make fuzz-engines   # captures, TDFA vs Backtracking
make seed-set     make fuzz-set       # set find (overlapping)
make seed-caps                        # every set capability
make seed-batch                       # set find through the batch entry
make seed-iteration                   # find iterated from successive offsets
```

The last three have no `fuzz-*` goal; fuzz them with `fuzz-budget.sh` (see
"Budgeted runs" below).

Each `fuzz-*` goal pairs `-fuzz` with a matching `-run`. Without the `-run`
filter, `go test -fuzz=X` replays every *other* target's seed corpus first, so a
single open bug anywhere aborts the run before the requested target starts
fuzzing.

or directly:

```bash
go test -run=FuzzCorrectness -v .
go test -fuzz=FuzzCorrectness -fuzztime=10m .
```

A failing case is written under `testdata/fuzz/FuzzCorrectness/` and
replayed on every subsequent `go test` (with or without `-fuzz`) until
fixed or removed — see `go help testflag` ("Fuzzing"). That entry is not a
substitute for a regression test: once a failure is understood, shrink it and
add the minimal repro to `tools/re2test/custom-tests.txt`, which is the
permanent, reviewable home for it.

## Budgeted runs: `fuzz-budget.sh`

`go test -fuzz` stops at the first crasher, and every later run fails again
replaying it from `testdata/fuzz/<TARGET>/`. `fuzz-budget.sh` loops around that:
it moves each new crasher out, resumes with the time that is left, and stops
when the time budget or the crasher limit runs out.

```bash
./fuzz-budget.sh [TIME] [MAX_ERRORS] [TARGET]   # defaults: 10m, 5, FuzzCorrectness
```

The arguments are positional, so naming a target means giving the first two as
well. The script changes into `tools/fuzz` itself and runs from any directory.

Single patterns:

```bash
./fuzz-budget.sh 30m 5                         # FuzzCorrectness: non-anchored find
./fuzz-budget.sh 30m 5 FuzzMatch               # anchored match
./fuzz-budget.sh 30m 5 FuzzGroups              # captures, selector's engine
./fuzz-budget.sh 30m 5 FuzzGroupsBothEngines   # captures, TDFA vs Backtracking
./fuzz-budget.sh 30m 5 FuzzFindIteration       # find iterated from successive offsets
```

Sets:

```bash
./fuzz-budget.sh 30m 5 FuzzSet                 # overlapping set find
./fuzz-budget.sh 30m 5 FuzzSetCaps             # every set capability, at every `from`
./fuzz-budget.sh 30m 5 FuzzFindBatch           # set find through the batch entry, capacity 1
```

An unknown target is refused with the list of the package's fuzz functions. The
name is anchored before it reaches `-fuzz`, which takes a regular expression:
`FuzzSet` alone would also match `FuzzSetCaps`, and `go test` will not fuzz two
targets in one run.

Crashers are moved to `found/<TARGET>/<run-timestamp>/<found-time>-<hash>` — per
target, because the file does not record which target produced it. To replay
one, copy it back under the same target:

```bash
cp found/<TARGET>/<run-timestamp>/<found-time>-<hash> testdata/fuzz/<TARGET>/<hash>
go test -run=<TARGET> .
```

A crasher from a set target belongs in `tools/re2test/custom-sets.txt` once
understood, rather than `custom-tests.txt`.

Things to know before a long run:

- **Run one target at a time.** Two fuzzing runs compete for CPU, and the fuzz
  worker's fixed 10 s per-call deadline then reports merely slow cases as
  crashers.
- **Each round starts with the whole package.** The script passes no `-run`, so
  before fuzzing, `go test` runs the package's tests and every target's seed
  corpus — minutes, not seconds, and again after each crasher. A seed that
  fails anywhere stops the script before fuzzing starts; it says so, rather
  than looping.
- **`FuzzSetCaps` skips patterns over 512 NFA instructions.** Prefix the
  command with `REGEXPED_FUZZ_MAX_CAPS_NFA_INSTS=1000` to explore larger ones.

## Layers

| target | path | oracle |
|---|---|---|
| `FuzzCorrectness` | non-anchored find, no captures | `FindStringIndex` |
| `FuzzFindIteration` | non-anchored find, called repeatedly from successive offsets the way the stubs iterate | `FindAllStringIndex` |
| `FuzzMatch` | anchored match (`match_func`) | `\A(?:pat)\z` full-consumption |
| `FuzzGroups` | captures, selector's engine | `FindStringSubmatchIndex` |
| `FuzzGroupsBothEngines` | captures on TDFA **and** Backtracking, cross-checked | same, plus engine agreement |
| `FuzzSet` | two-pattern set `find`, `overlapping: true` | a match at every start position, probed against the whole input (see below) |
| `FuzzSetCaps` | every capability of a two-pattern set, at every `from` | whole-input anchored probes |
| `FuzzFindBatch` | two-pattern set `find` through its batch entry at a buffer capacity of 1, so every multi-match position is split across calls | union of each pattern's `FindAllStringIndex` |

Three oracle facts worth knowing before touching these, each established
empirically:

- **`match_func` is full-consumption.** It matches only if the pattern consumes
  the *entire* input (`a` vs `"ab"` is NO match). The oracle is `\A(?:pat)\z`,
  not `FindStringIndex`.
- **`groups_func` is NON-anchored**, despite `CLAUDE.md` calling it "anchored +
  captures". `(a)(b)` vs `"xxab"` returns `[2 4 2 3 3 4]`.
- **Set `find` has two output rules.** The default is per-pattern
  non-overlapping — Go's `FindAllStringIndex` rule, applied to each pattern.
  `overlapping: true` instead reports a match at every start position: `a*` vs
  `"a"` gives `[0-1] [1-1]`, and `.*?end` vs `"xyzend"` gives four matches, not
  one. `FuzzSet` compiles its sets with `overlapping: true`.

`FuzzSet`'s oracle probes each start position `p` against the *whole* input —
`\A`, then a `p`-character prefix, then the pattern — so `^ $ \A \z \b \B` are
judged against their real left context. That prefix counts runes, so the target
skips non-ASCII input. It also skips inputs longer than the probe sweep can
price under the fuzz worker's deadline, and capture-bearing patterns, which a
set drops by design.

### `-2` is a skip, not a failure

Every target skips a case when an export returns `abi.BTStackOverflow` (-2):
the Backtracking engine exhausted its compile-time frame budget and is telling
you it does not know the answer (see `docs/engines.md`). Comparing
that against the oracle would report a "wrong answer" for an answer the engine
explicitly declined to give — the same harness mistake as treating a
compile-time ceiling error as a bug (see `isResourceCeiling`).

Before BT stack overflow got its own sentinel this was indistinguishable from a
genuine no-match, so the harness could not have skipped it even in principle: a long-input false negative
would have been reported as an engine bug, or matched the oracle by luck.

## Regression tests (not fuzz targets)

`backtrack_test.go`'s overflow cases are plain tests, not a fuzz target: it pins the
BT-stack-overflow sentinel at exactly `numAlts * 4096 ± 1` frames across all five BT-hosting
export shapes (`match`, `find`, `groups`, `find_batch`, `groups_batch`), and
pins the ceiling itself so a change to `btAllocSizes` fails loudly instead of
silently moving the input size at which callers start seeing errors.

Reproducing an overflow is fiddly enough to be worth reading the file's header
comment before editing it: the pattern needs a live untried *alternation* branch
(a non-greedy loop alone pushes and pops straight back), and that alternation
must survive `regexp/syntax` simplification — `a|b` collapses to `[ab]` and
`aa|ab` factors to `a[ab]`, and neither leaves an `InstAlt` to push a frame for.

## What it catches

- Engine correctness bugs across all five compiled paths.
- Hangs: any WASM call exceeding a 2s watchdog fails the case (see
  `wasmCallTimeout` in `wasmrun.go`), catching O(n²) blowups.
- WASM-level errors: bad module, trap, missing exports.

## Seed corpus

`corpus.go`'s `seedCorpus` parses `tools/re2test/custom-tests.txt` and
cross-products each `strings` block against the following `regexps`
block's patterns — the same pairing `tools/re2test/main.go` uses, minus the
expected-result columns (not needed here: the Go stdlib oracle is
recomputed live).

## Scope

Deliberately out of scope for this pass — the fuzzer starts minimal and
expands only where it earns its keep:

- **Layer 2** (structure-aware AST-grammar pattern generation) — skipped;
  revisit if the ~99% reject rate becomes a throughput bottleneck.
- **Layer 3** (differential DFA-vs-Backtracking fuzzing) — not built yet.
- **CI wiring** — this is a local/overnight tool for now, not part of
  `.github/workflows/ci.yml`.
- **Unicode** — patterns/inputs with any byte > 127 or a `\p`/`\P` escape
  are skipped, mirroring `tools/re2test`'s existing Unicode carve-out.
