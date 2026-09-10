# secrets — credential detection via a WASM **component**

Searches text for three types of leaked credentials using three independent DFA
find-mode patterns, compiled into a single **Component Model component** with a
generated WIT interface.

This is the component-format example. Every other Rust example here uses the
default module format — `regexped generate` for FFI stubs, then `wasm-merge` —
and `../url-ipv6` is the one to read for that.

| Pattern | Example match |
|---|---|
| GitHub PAT | `ghp_` + 36 alphanumeric chars |
| JWT | `eyJ...eyJ...` (three base64url parts) |
| AWS access key | `AKIA` + 16 uppercase alphanumeric |

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Rust (a **native** toolchain — no `wasm32-wasip1` target needed here; the host
  embeds wasmtime rather than being compiled to WASM itself)
- [wasm-tools](https://github.com/bytecodealliance/wasm-tools) — `regexped
  compile` shells out to it to wrap the core module into a component

## Run

```sh
make
```

Expected output:
```
=== clean text ===
No secrets found

=== GitHub personal access token ===
GitHub token at 22..62: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789

=== AWS access key ===
AWS key at 25..45: AKIAIOSFODNN7EXAMPLE
```

## Build pipeline

Three steps rather than the module format's five — there is no stub generation
and no merge:

```
regexped compile   →  secrets.wasm (a component) + secrets.wit (its interface)
cargo build        →  native host; bindgen! reads secrets.wit at COMPILE time
./target/release/secrets  →  execute
```

Because `bindgen!` reads the WIT while the host compiles, an interface that no
longer matches is a build error rather than a runtime surprise.

## What is worth reading in the source

**`regexped.yaml`** — `wasm_format: component`, and the absence of two keys the
module examples need: no `output:` (that is the wasm-merge target, and a
component owns its own memory) and no `stub_file:` (the host binds against the
WIT). `import_module: "secrets"` names the WIT package and the world.

**`main.rs`** — two things the module format hides:

*The host owns the iteration.* `find` answers ONE match, so there is no generated
`FindIter`; the loop, and the advance rule that keeps it terminating over a
zero-length match, are written out:

```rust
start = if span.1 > span.0 { span.1 } else { span.0 + 1 };
```

The whole input is passed on every call, deliberately: `\b`, `\B` and `(?m:^)`
are judged against the real preceding byte, so slicing would change the answer at
the seam.

*"I don't know" is in the type.* A Backtracking pattern that exhausts its frame
budget yields `Err(ErrorCode::BacktrackOverflow)`, which is **not** "no secrets
found" — the engine abandoned part of the search space. For a credential scanner
that distinction is the whole point, so the example exits non-zero rather than
printing a clean bill of health.

See [../../../../docs/component.md](../../../../docs/component.md).
