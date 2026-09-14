# fastedge/validate — email, URL, and XSS validation

A FastEdge application that validates email, URL, and description fields in a JSON request body. Uses **DFA anchored match** for email and URL validation and **DFA find** for XSS detection.

See [docs/fastedge.md](../../../docs/fastedge.md) for the full guide.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Rust with the `wasm32-wasip1` target | [rustup](https://rustup.rs), then `rustup target add wasm32-wasip1` |
| `wasm-merge` | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `final.wasm` — the steps below | `regexped`, Rust, `wasm-merge` |
| `make generate` | generates the Rust stub `stubs.rs` | `regexped` |
| `make build` | generates the stub if needed, then `cargo build --target wasm32-wasip1` | `regexped`, Rust |
| `make compile` | compiles the patterns to `regexps.wasm` | `regexped` |
| `make merge` | merges the two into `final.wasm` — the same as `make` | `regexped`, Rust, `wasm-merge` |
| `make run` | nothing: `final.wasm` runs on FastEdge, not locally — see [docs/fastedge.md](../../../docs/fastedge.md) | — |
| `make clean` | removes the build outputs | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead).

## Build

```sh
make
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stubs
cargo build         →  compile Rust app to WASM
regexped compile    →  compile regexp patterns to WASM
regexped merge      →  merge app WASM + regexp WASM into final.wasm
```
