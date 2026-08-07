# fuzz — byte-level correctness fuzzer

Layer 1 of [plans/FUZZER.md](../../plans/FUZZER.md): mutates `(pattern,
input)` string pairs and compares regexped's compiled WASM `find` body
against Go stdlib `regexp` on the same pair. Rejects (skips) any pair Go
stdlib itself can't compile, or that regexped can't compile (unsupported
syntax, engine state-limit overflow) — those aren't regexped bugs.

## Usage

```bash
make seed        # replay the seed corpus only (fast, deterministic)
make fuzz         # 1-minute interactive fuzz run
make fuzz-long    # 8-hour overnight run
```

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

## What it catches

- Engine correctness bugs in the DFA/Compiled DFA `find` path (no captures —
  Layer 1 targets this shape only; TDFA/Backtracking capture paths are out
  of scope here, see FUZZER.md Layer 2/3).
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
