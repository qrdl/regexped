# wasmtime/rust/secret-scanner — native Rust host embedding a set, two ways 🧩

Scans text for 10 secret patterns from a **native Rust binary** that loads
regexped's output at runtime with the `wasmtime` crate.

This example is architecturally different from all other regexped examples.
In every other example the host application is itself compiled to WASM and
merged or composed with the regexp module so that all code runs inside a single
WASM process. Here the host is native and the regexp output is a file it loads —
the same pattern you would use when embedding regexped into a native server,
CLI tool, or daemon.

**It builds BOTH output kinds from the same patterns**, and that contrast is the
second thing it demonstrates:

| | `make` | `make component-run` |
|---|---|---|
| config | `regexped.yaml` | `regexped-component.yaml` |
| output kind | `wasm_format: module` | `wasm_format: component` |
| host source | [main.rs](main.rs) | [main_component.rs](main_component.rs) |
| how it loads | `Module::from_file` + `Instance` | `Component::from_file` + `bindgen!` |
| how it calls `find` | the raw ABI, by hand | a `resource`, from generated host bindings |

`make compare` runs both over the same five inputs and diffs the output. They
report the same matches; what differs is how much the host has to do.

**Neither route uses a generated stub.** A stub is for a guest compiled to WASM;
this binary is native. The module route therefore talks to the WASM ABI directly,
and the component route binds against the `.wit` regexped emits beside the
component.

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
- for the component route only: `wasm-tools` on `$PATH`, which `regexped
  compile` shells out to in order to wrap the core module into a component

## Run

```sh
make
```

Or the component route, and a diff of the two:

```sh
make component-run
make compare
```

Expected output (abbreviated, identical either way):
```
--- input: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
[aws_key] at 25..45: AKIAIOSFODNN7EXAMPLE

1 secret(s) found.

--- input: key=AKIAIOSFODNN7EXAMPLE token=ghp_... stripe=sk_live_...
[aws_key] at 4..24: AKIAIOSFODNN7EXAMPLE
[github_pat] at 31..71: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
[stripe_live] at 81..113: sk_live_AbCdEfGhIjKlMnOpQrStUvWx

3 secret(s) found.
```

## How the module route works

`regexped compile` produces `secrets.wasm` — a standalone WASM module that
exports its own memory and

```
scan_secrets(ptr, len, from, gate_ptr, out_ptr, out_cap) → total
```

Everything that signature needs is the CALLER's, so the host does all of it
([main.rs](main.rs)):

1. Loads `secrets.wasm` with the `wasmtime` crate.
2. Reads the module's initial memory size — which already covers the compiled
   DFA tables — and grows it by 2 pages: one for the input, one for the output
   buffer and the gate array.
3. Writes the input bytes into the first grown page.
4. **Zeroes the gate array**, `<SET>_ID_SPACE` u32s. Its contents are opaque;
   zeroing is the only operation a caller ever performs on it, and it is what
   makes a scan resumable at any position.
5. Calls in a loop, reading `(pattern_id, start, end)` tuples — 12 bytes each —
   out of the output buffer and resuming one past the reported position, until
   a call returns 0.

## How the component route works

`regexped compile --config=regexped-component.yaml` produces
`component/secrets.wasm` plus `component/secrets.wit`. `bindgen!` reads that
`.wit` at compile time and generates the host side, so the five steps above
become ([main_component.rs](main_component.rs)):

```rust
let scan = sets.scan_secrets().call_constructor(&mut store, &input, 0)?;
loop {
    let batch = sets.scan_secrets().call_next(&mut store, scan)??;
    if batch.is_empty() { break; }
    for m in &batch { /* m.id, m.start, m.end */ }
}
scan.resource_drop(&mut store)?;
```

There is no memory layout to choose, no gate array to zero, and no tuple to
unpack: the scan is a `resource` whose state — the input copy, the position and
the gates — lives inside the component. Dropping the handle releases it.

The trade is that each `next` crosses a component boundary rather than being a
direct call into shared memory, and the constructor copies the input in once. See
[docs/component.md](../../../../docs/component.md#sets).

## Build pipeline

```
module route:
  regexped compile                      →  standalone secrets.wasm
  cargo build --bin secret-scanner      →  native host
  ./secret-scanner                      →  load, scan

component route:
  regexped compile --config=regexped-component.yaml
                                        →  component/secrets.wasm + .wit
  cargo build --bin secret-scanner-component
                                        →  native host, bindings from the .wit
  ./secret-scanner-component            →  load, scan
```

Neither route needs `regexped generate` (no stub — the host is native) or
`regexped merge` (nothing is linked into the host; the file is loaded at
runtime).
