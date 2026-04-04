# sql-injection — SQL injection detection

Detects SQL injection patterns in input strings using the **Backtracking engine** (forced via `max_dfa_states: 1`). Demonstrates all three capture modes on the same pattern: anchored match, find, and named groups.

Named groups extracted: `type` (attack type), `payload` (remainder of the matched line).

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Go 1.23+
- [wasm-merge](https://github.com/WebAssembly/binaryen)
- [wasmtime](https://wasmtime.dev)

## Run

```sh
make
```

## Build pipeline

```
regexped generate      →  generate Go stub (//go:wasmimport)
go build (GOOS=wasip1) →  compile Go to WASM
regexped compile       →  compile regex pattern to WASM
regexped merge         →  merge Go WASM + regex WASM into final binary
wasmtime               →  execute
```
