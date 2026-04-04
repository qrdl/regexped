# secrets — credential detection

Searches text for three types of leaked credentials using three independent DFA find-mode patterns compiled into a single merged WASM module.

| Pattern | Example match |
|---|---|
| GitHub PAT | `ghp_` + 36 alphanumeric chars |
| JWT | `eyJ...eyJ...` (three base64url parts) |
| AWS access key | `AKIA` + 16 uppercase alphanumeric |

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Rust with WASI target: `rustup target add wasm32-wasip1`
- [wasm-merge](https://github.com/WebAssembly/binaryen)
- [wasmtime](https://wasmtime.dev)

## Run

```sh
make
```

Expected output:
```
=== clean text ===
No secrets found

=== GitHub personal access token ===
GitHub token at 22..62: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab

=== AWS access key ===
AWS key at 26..46: AKIAIOSFODNN7EXAMPLE
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stubs (all patterns into one file)
cargo build         →  compile Rust to WASM (wasm32-wasip1)
regexped compile    →  compile all regex patterns to WASM
regexped merge      →  merge Rust WASM + regex WASM into final binary
wasmtime run        →  execute
```
