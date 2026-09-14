# url-ipv6 — IPv6 URL validation

Validates that the input is an HTTP/HTTPS URL whose host is an IPv6 address in bracket notation (`[2001:db8::1]`). Uses **DFA anchored match**.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Rust with the `wasm32-wasip1` target | [rustup](https://rustup.rs), then `rustup target add wasm32-wasip1` |
| `wasm-merge` | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `final.wasm` — the steps below | `regexped`, Rust, `wasm-merge` |
| `make generate` | generates the Rust stub `stub.rs` | `regexped` |
| `make build` | generates the stub if needed, then `cargo build --target wasm32-wasip1` | `regexped`, Rust |
| `make compile` | compiles the pattern to `url_ipv6.wasm` | `regexped` |
| `make merge` | merges the two into `final.wasm` — the same as `make` | `regexped`, Rust, `wasm-merge` |
| `make run` | builds if needed, then runs `final.wasm` under wasmtime on five inputs | all of the above, plus `wasmtime` |
| `make clean` | removes the build outputs | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead).

## Run

```sh
make       # build final.wasm
make run   # run it
```

Expected output of `make run`:
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
regexped compile    →  compile regexp pattern to WASM
regexped merge      →  merge Rust WASM + regexp WASM into final binary
wasmtime run        →  execute
```
