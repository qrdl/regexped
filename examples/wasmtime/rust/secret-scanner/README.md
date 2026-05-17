# wasmtime/rust/secret-scanner — native Rust host embedding a set WASM

Scans text for 10 secret patterns using a **standalone** regexped set WASM
loaded directly by a native Rust binary via the `wasmtime` crate.

This example is architecturally different from all other regexped examples.
In every other example the host application is itself compiled to WASM and
merged with the regex module so that all code runs inside a single WASM
process. Here the host is a **native Rust binary** and the regex module is a
standalone `.wasm` file loaded at runtime — the same pattern you would use
when embedding regexped into a native server, CLI tool, or daemon.

## Patterns detected

| ID | Pattern |
|---|---|
| `aws_key` | AWS access key (`AKIA...`) |
| `aws_secret` | AWS secret key in config format |
| `github_pat` | GitHub personal access token (`ghp_...`) |
| `github_oauth` | GitHub OAuth token (`gho_...`) |
| `github_app` | GitHub App token (`ghu_...`) |
| `jwt` | JSON Web Token (`eyJ...`) |
| `slack_token` | Slack bot/app token (`xox...`) |
| `stripe_live` | Stripe live secret key (`sk_live_...`) |
| `stripe_test` | Stripe test secret key (`sk_test_...`) |
| `google_api` | Google API key (`AIza...`) |

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Rust (native target, no WASI needed)
- `wasmtime` crate (declared in `Cargo.toml`)

## Run

```sh
make
```

Expected output (abbreviated):
```
=== AWS access key ===
[aws_key] at 26..46: AKIAIOSFODNN7EXAMPLE

=== GitHub PAT ===
[github_pat] at 22..62: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789

=== multiple secrets (all reported in one scan pass) ===
[aws_key] at 4..24: AKIAIOSFODNN7EXAMPLE
[github_pat] at 31..71: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
[stripe_live] at 79..107: sk_live_AbCdEfGhIjKlMnOpQrStUvWx
```

## How it works

`regexped compile` produces `secrets.wasm` — a standalone WASM module that
exports its own memory and a `scan_secrets(ptr, len, out_ptr, out_cap, start)
→ count` function. The host:

1. Loads `secrets.wasm` with the `wasmtime` crate.
2. Reads the module's initial memory size (which already covers the compiled
   DFA tables) and grows it by 2 pages: one for input, one for output. The
   total page count depends on how large the tables are.
3. Writes the input bytes into the first grown page and calls `scan_secrets`
   in a loop, advancing `start_pos` after each batch until the function
   returns 0.
4. Reads `(pattern_id i32, start i32, length i32)` tuples (12 bytes each)
   from the output buffer (second grown page).

No generated stub is used. The host interacts with the WASM ABI directly.

## Build pipeline

```
regexped compile   →  compile 10-pattern set to standalone secrets.wasm
cargo build        →  compile native Rust host binary
./secret-scanner   →  load secrets.wasm, scan inputs
```

No `regexped generate` or `wasm-merge` step — the standalone WASM is
self-contained and loaded dynamically at runtime.
