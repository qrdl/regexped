# Regexped WASM Examples

Three self-contained examples showing how to compile regex patterns to WASM and call them from Rust.

## Prerequisites

- **regexped** binary: run `make` in the repo root
- **Rust** with the WASI target: `rustup target add wasm32-wasip1`
- **wasmtime**: https://wasmtime.dev
- **wasm-merge** from [Binaryen](https://github.com/WebAssembly/binaryen)

Each example's `regexped.yaml` references wasm-merge via a path relative to the config file (`../../../binaryen/bin/wasm-merge`). Adjust if your Binaryen install is elsewhere.

## Build pipeline

Every example follows the same four steps, driven by `make`:

```
regexped stub     →  generate Rust FFI stub(s) from regexped.yaml
cargo build       →  compile Rust + stubs to WASM (wasm32-wasip1)
regexped compile  →  compile regex pattern(s) to WASM (DFA / OnePass tables)
regexped merge    →  merge Rust WASM + regex WASM(s) into final binary
wasmtime run      →  execute with test inputs
```

Run `make` in any example directory to execute all steps end-to-end.

---

## url-ipv6 — find IPv6-addressed URLs

Scans arbitrary text for HTTP/HTTPS URLs whose host is an IPv6 address in bracket notation (`[2001:db8::1]`). Uses **DFA find mode** (non-anchored scan).

```sh
cd url-ipv6 && make
```

Expected output:
```
=== IPv6 URL, no port ===
Found IPv6 URL at bytes 11..36: https://[2001:db8::1]/api
```

---

## secrets — detect leaked credentials

Searches text for three types of secrets using three independent DFA find-mode patterns compiled to separate WASM modules and merged together:

| Pattern         | Example match                          |
|-----------------|----------------------------------------|
| GitHub PAT      | `ghp_` + 36 alphanumeric chars         |
| JWT             | `eyJ...eyJ...` (three base64url parts) |
| AWS access key  | `AKIA` + 16 uppercase alphanumeric     |

```sh
cd secrets && make
```

Expected output:
```
=== AWS access key ===
GitHub token: not found
JWT:          not found
AWS key:      found at 26..46: AKIAIOSFODNN7EXAMPLE
```

---

## url-parts — parse a URL into components

Parses a URL into named capture groups using the **OnePass engine** — a single-pass DFA with inline capture slot tracking, faster than backtracking for deterministic patterns.

Groups returned: `scheme`, `host`, `port`, `path`, `query`, `fragment`.

```sh
cd url-parts && make
```

Expected output:
```
=== full URL ===
scheme     = https
host       = example.com
port       = 8080
path       = /path/to/page
query      = q=1&r=2
fragment   = section
```

The pattern is anchored — pass the URL itself as the argument, not surrounding text.
