# url-ipv6 — IPv6 URL validation

Validates that the input is an HTTP/HTTPS URL whose host is an IPv6 address in bracket notation (`[2001:db8::1]`). Uses **DFA anchored match**.

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
=== not a URL ===
Not a valid IPv6 URL

=== IPv4 URL (not matched) ===
Not a valid IPv6 URL

=== IPv6 URL, no port ===
Valid IPv6 URL (matched 25 bytes)

=== IPv6 URL with port ===
Valid IPv6 URL (matched 25 bytes)

=== IPv6 loopback, path and query ===
Valid IPv6 URL (matched 29 bytes)
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stub
cargo build         →  compile Rust to WASM (wasm32-wasip1)
regexped compile    →  compile regex pattern to WASM
regexped merge      →  merge Rust WASM + regex WASM into final binary
wasmtime run        →  execute
```
