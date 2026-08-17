# fuzz — byte-level correctness fuzzer

Mutates `(pattern, input)` string pairs and compares regexped's compiled WASM
against Go stdlib `regexp` on the same pair.

**Layer 1** ([plans/FUZZER.md](../../plans/FUZZER.md)) covers the no-capture
`find` body. **Layer 2** ([plans/OPUS.md](../../plans/OPUS.md) §N7) covers the
four paths Layer 1 never reaches — see "Layers" below. Rejects (skips) any pair Go
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
make seed-set     make fuzz-set       # set find_all
```

> `make seed-groups` and `make seed-engines` currently **fail** on
> `(0$|a0??)`. That is real bug 40
> ([plans/FUZZER_BUGS.md](../../plans/FUZZER_BUGS.md)), not harness flake.
> Don't make it green by weakening the oracle.

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
fixed or removed — see `go help testflag` ("Fuzzing"). Per FUZZER.md's
"Practical concerns", once a failure is understood, shrink it and add the
minimal repro to `tools/re2test/custom-tests.txt` as a permanent regression
test; don't rely on the `testdata/fuzz` entry alone for that.

## Layers

| target | path | oracle |
|---|---|---|
| `FuzzCorrectness` | non-anchored find, no captures | `FindStringIndex` |
| `FuzzMatch` | anchored match (`match_func`) | `\A(?:pat)\z` full-consumption |
| `FuzzGroups` | captures, selector's engine | `FindStringSubmatchIndex` |
| `FuzzGroupsBothEngines` | captures on TDFA **and** Backtracking, cross-checked | same, plus engine agreement |
| `FuzzSet` | set `find_all` | match at every start position (see below) |

Three oracle facts worth knowing before touching these — each was established
empirically, and two contradict the docs:

- **`match_func` is full-consumption.** It matches only if the pattern consumes
  the *entire* input (`a` vs `"ab"` is NO match). The oracle is `\A(?:pat)\z`,
  not `FindStringIndex`.
- **`groups_func` is NON-anchored**, despite CLAUDE.md calling it "anchored +
  captures". `(a)(b)` vs `"xxab"` returns `[2 4 2 3 3 4]`.
- **set `find_all` reports overlapping matches** — one per start position — not
  Go's `FindAllStringIndex`, which skips forward past each match. `a*` vs `"a"`
  gives `[0-1] [1-1]`, and `.*?end` vs `"xyzend"` gives four matches, not one.

`FuzzSet` therefore skips patterns containing `^ $ \A \z \b \B`: its
per-start-position oracle anchors against a *slice* of the input, which cannot
preserve left context for those assertions. Widening that is open work.

### `-2` is a skip, not a failure

Every target skips a case when an export returns `abi.BTStackOverflow` (-2):
the Backtracking engine exhausted its compile-time frame budget and is telling
you it does not know the answer (plans/OPUS.md §N1, docs/engines.md). Comparing
that against the oracle would report a "wrong answer" for an answer the engine
explicitly declined to give — the same harness mistake as treating a
compile-time ceiling error as a bug (see `isResourceCeiling`).

Before the §N1 fix this was indistinguishable from a genuine no-match, so the
harness could not have skipped it even in principle: a long-input false negative
would have been reported as an engine bug, or matched the oracle by luck.

## Regression tests (not fuzz targets)

`bt_overflow_test.go` is a plain test, not a fuzz target: it pins the §N1
sentinel at exactly `numAlts * 4096 ± 1` frames across all five BT-hosting
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

Deliberately out of scope for this pass (see FUZZER.md's own
recommendation — start minimal, expand only if it earns its keep):

- **Layer 2** (structure-aware AST-grammar pattern generation) — skipped;
  revisit if the ~99% reject rate becomes a throughput bottleneck.
- **Layer 3** (differential DFA-vs-Backtracking fuzzing) — not built yet.
- **CI wiring** — this is a local/overnight tool for now, not part of
  `.github/workflows/ci.yml`.
- **Unicode** — patterns/inputs with any byte > 127 or a `\p`/`\P` escape
  are skipped, mirroring `tools/re2test`'s existing Unicode carve-out.
