# url-parts — URL parsing into components

Finds all URLs in text and parses each into named capture groups using the **TDFA engine** — a tagged DFA with inline capture slot tracking.

Groups extracted: `scheme`, `host`, `port`, `path`, `query`, `fragment`.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- `clang-19` with `wasm-ld` (`apt install clang-19 lld-19`)
- [wasm-merge](https://github.com/WebAssembly/binaryen)
- [wasmtime](https://wasmtime.dev)

No libc or WASI sysroot required — the example uses direct WASI imports.

## Run

```sh
make
```

Expected output:
```
=== single URL ===
URL:
  scheme     = https
  host       = example.com
  port       = 8080
  path       = /path/to/page
  query      = q=1&r=2
  fragment   = section
```

## Build pipeline

```
regexped generate   →  generate C header stub (stub.h)
clang               →  compile C to WASM (wasm32-wasi, no sysroot)
regexped compile    →  compile regex pattern to WASM
regexped merge      →  merge C WASM + regex WASM into final binary
wasmtime run        →  execute
```
