# Tools

Test, benchmark and measurement harnesses for regexped. Each one is its own Go
module with its own Makefile, and drives compiled WASM through wasmtime. The
root `Makefile` wraps the ones used as gates.

## Correctness

| Tool | What it checks | Run |
|---|---|---|
| [`re2test`](re2test/) | Every engine and every set capability against Go's RE2 exhaustive test corpus, plus the hand-written `custom-tests.txt` and `custom-sets.txt`. Extra runs cover high-byte input, Unicode mode (the corpus's non-ASCII rows, every block, Unicode variants of every string), forced Backtracking, the hints, and per-search notes armed from the first call | `make re2test`, `make setcaps` (root) |
| [`fuzz`](fuzz/) | Mutated `(pattern, input)` pairs against Go's `regexp`, in byte and Unicode mode, plus property tests: `find` from every offset, iteration, sets, components, memory limits. The seed corpora run as ordinary tests | `go test .` in `tools/fuzz`; `make -C tools/fuzz fuzz` for a fuzzing run |
| [`advbench`](advbench/) | Hostile input: drives each entry point at doubling input sizes and fails when the cost grows faster than linear (×2 per doubling is linear, ×4 quadratic) | `make adversary` (root) |

## Performance

| Tool | What it measures | Run |
|---|---|---|
| [`perftest`](perftest/) | Single patterns and sets against the `regex` crate, both compiled to WASM: instructions executed, median time and module size, with a baseline check | `make perftest`, `make perftest-check` (root) |
| [`setperf`](setperf/) | Every set capability against `regex-automata`, the engine under `regex`, plus a cross-engine correctness check (`make -C tools/setperf verify`) | `make setperf`, `make setperf-check`, `make setperf-fuel-cross` (root) |
| [`likelytest`](likelytest/) | The `prefer-match` / `prefer-no-match` hints against neutral, on a fixed list of patterns and sets | `make -C tools/likelytest run` |

## Ad-hoc

| Tool | Use it to | Run |
|---|---|---|
| [`pattest`](pattest/) | Try one pattern under each hint, on your own inputs | `make -C tools/pattest run ARGS="-pattern '[a-z]+' -mode find -inputs inputs.txt"` |
| [`settest`](settest/) | The same for one set, taken from a YAML config | `make -C tools/settest run ARGS="-config set.yaml -cap find -inputs inputs.txt"` |
| [`advbench`](advbench/) | Check whether one pattern or set stays linear on an input shape you choose | `make -C tools/advbench run ARGS="-pattern 'a*b\|a' -fn find -gen rep:a"` |

## Notes

- **Instructions executed** ("fuel", counted by wasmtime) are exact and the same
  on any machine. **Wall-clock times** are noisy: compare ratios against the
  other engine, and never run two measurements at the same time.
- `perftest` and `setperf` share one Rust harness, `perftest/regex_bench`, built
  for `wasm32-wasip1` by their `harnesses` target.
- Tests that need `wasm-merge`, `wasm-tools`, `wac`, a Rust or C toolchain or
  Node.js skip without them, so a green run on a machine missing them checked less.
