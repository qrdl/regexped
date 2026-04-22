# fastedge/validate — email, URL, and XSS validation

A Gcore FastEdge application that validates email, URL, and description fields in a JSON request body. Uses **DFA anchored match** for email and URL validation and **DFA find** for XSS detection.

See [docs/fastedge.md](../../../docs/fastedge.md) for the full guide.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Rust with `wasm32-wasip1` target (`rustup target add wasm32-wasip1`)
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen)

## Build

```sh
make
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stubs
cargo build         →  compile Rust app to WASM
regexped compile    →  compile regex patterns to WASM
regexped merge      →  merge app WASM + regex WASM into final.wasm
```
