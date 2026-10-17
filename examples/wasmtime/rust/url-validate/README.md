# url-validate — URL validation

Validates that the whole input is an HTTP or HTTPS URL whose host is an IPv4 address, an IPv6 address in brackets (`[2001:db8::1]`) or a host name, with an optional user, port, path, query and fragment. Uses **DFA anchored match**.

The regexp is built from named pieces — `octet`, `ipv4`, `h16`, `ipv6`, `label`, `hostname`, `port` — each written once in `regexped.yaml` and used by reference, `(?&name)`; see [docs/references.md](../../../../docs/references.md).

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
| `make compile` | compiles the pattern to `url_validate.wasm` | `regexped` |
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
Not a valid URL

=== host name ===
Valid URL (matched 24 bytes)

=== IPv6 URL, no port ===
Valid URL (matched 25 bytes)

=== IPv6 URL with port ===
Valid URL (matched 25 bytes)

=== IPv6 link-local, path and query ===
Valid URL (matched 29 bytes)
```

## Build pipeline

```
regexped generate   →  generate Rust FFI stub
cargo build         →  compile Rust to WASM (wasm32-wasip1)
regexped compile    →  compile regexp pattern to WASM
regexped merge      →  merge Rust WASM + regexp WASM into final binary
wasmtime run        →  execute
```
