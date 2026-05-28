# Using Regexped with wasmtime

[wasmtime](https://wasmtime.dev) is the reference standalone runtime for
WebAssembly. It runs WASI modules from the command line and can also be
embedded as a library (`wasmtime-go`, `wasmtime-rs`, `wasmtime-py`, …) into a
host application. Regexped's compiled regexp modules run unmodified on
wasmtime — there is no runtime-specific shim — and wasmtime is the runtime
used by Regexped's own [`re2test/`](../re2test/) and [`perftest/`](../perftest/)
harnesses for validation and benchmarking.

This page covers the **embedded** workflow: a Rust / Go / C / AssemblyScript
program that calls Regexped-generated stubs and is executed by `wasmtime run`.
For pure-WASM in-browser or Node.js usage, see [browser.md](browser.md) and
[node.md](node.md) — those flows use the standalone WASM output and do not
involve `wasm-merge`.

## Prerequisites

- `regexped` binary (`go install github.com/qrdl/regexped@latest` or build from source)
- [`wasm-merge`](https://github.com/WebAssembly/binaryen) (Binaryen toolkit) — combines the host module with the regexp module
- [`wasmtime`](https://wasmtime.dev) CLI
- Toolchain for the host language:
  - **Rust** — `rustup target add wasm32-wasip1`
  - **Go** — Go 1.23+ (compile with `GOOS=wasip1`)
  - **C** — `clang` with `wasm-ld` (`clang-19` works without a WASI sysroot)
  - **AssemblyScript** — Node.js 18+ (`npx asc`)

## Configuration

```yaml
# regexped.yaml
output:        "final.wasm"      # merged output — triggers embedded mode
wasm_file:     "regexps.wasm"    # intermediate regexp WASM
import_module: "regexps"         # module name used by the generated stubs
stub_file:     "stubs.rs"        # .rs / .go / .h / .ts → language inferred from extension

regexps:
  - pattern:    '^https?://\[[0-9a-fA-F:]+\](?::\d+)?(?:/[^\s]*)?$'
    match_func: "url_ipv6_match"
```

The presence of `output` is what switches Regexped into **embedded mode**: the
regexp WASM imports memory from a `"main"` host module instead of owning it, and
`regexped merge` produces a single self-contained WASI module suitable for
`wasmtime run`.

## Build pipeline

```
regexped generate    →  language stub (Rust / Go / C / AS)
<host toolchain>     →  compile host code to WASM (wasm32-wasip1)
regexped compile     →  compile regexp patterns to WASM
regexped merge       →  merge host WASM + regexp WASM via wasm-merge
wasmtime run         →  execute the final module
```

Concrete commands (Rust example):

```bash
regexped generate --config=regexped.yaml          # → stubs.rs
cargo build --target wasm32-wasip1 --release      # → target/.../app.wasm
regexped compile  --config=regexped.yaml          # → regexps.wasm
regexped merge    --config=regexped.yaml \
    --main=target/wasm32-wasip1/release/app.wasm  # → final.wasm
wasmtime run final.wasm
```

`wasm-merge` is invoked with `--enable-multimemory --enable-simd`
`--enable-bulk-memory --enable-bulk-memory-opt`. wasmtime enables SIMD and
multi-memory by default in recent releases — no extra flags are needed at run
time. See [wasm.md](wasm.md) for the underlying memory layout.

## Running

```bash
wasmtime run final.wasm                       # plain run
wasmtime run --dir=. final.wasm <args>        # grant access to the current directory
echo "input" | wasmtime run final.wasm        # pipe stdin
```

Regexped does not require any custom imports beyond the host language's own
WASI surface — anything `wasmtime` supports for plain WASI modules works for a
merged regexp module.

## Embedding wasmtime as a library

The merged module is a standard WASI module, so it can be loaded directly from
any wasmtime embedding (Rust, Go, Python, C API, …). Regexped's own test
harnesses use `wasmtime-go`:

- [`re2test/main.go`](../re2test/main.go) — exhaustive RE2 conformance via wasmtime-go
- [`perftest/main.go`](../perftest/main.go) — fuel-metered benchmarks via wasmtime-go

These are good references for callers that need to load a merged WASM module
into a wasmtime `Store`, write the input bytes into the WASM's linear memory,
and invoke an exported regexp function.

## Examples

Per-language wasmtime examples live under [`examples/wasmtime/`](../examples/wasmtime/):

| Language | Example | Engine | Demonstrates |
|---|---|---|---|
| Rust | [`rust/url-ipv6/`](../examples/wasmtime/rust/url-ipv6/) | DFA | Anchored match — validate IPv6 URLs |
| Rust | [`rust/secrets/`](../examples/wasmtime/rust/secrets/) | DFA find | Three-pattern credential scan (GitHub PAT, JWT, AWS) |
| Rust | [`rust/secret-scanner/`](../examples/wasmtime/rust/secret-scanner/) | Set `find_all` | Multi-pattern secret detection via the set pipeline |
| Go | [`go/csv/`](../examples/wasmtime/go/csv/) | TDFA named groups | CSV parse + email validation |
| Go | [`go/sql-injection/`](../examples/wasmtime/go/sql-injection/) | Backtracking | SQL injection capture groups |
| Go | [`go/secret-scanner/`](../examples/wasmtime/go/secret-scanner/) | Set `find_all` | Set composition from Go (wasip1) |
| C | [`c/url-parts/`](../examples/wasmtime/c/url-parts/) | TDFA named groups | Parse URLs into `scheme`/`host`/`port`/… |
| AssemblyScript | [`as/find-email/`](../examples/wasmtime/as/find-email/) | TDFA | Email extraction with `user`/`domain` groups |
| AssemblyScript | [`as/inject-scanner/`](../examples/wasmtime/as/inject-scanner/) | Set | Injection pattern scanner |

Each example has a `Makefile` that runs the full `generate → host build →
compile → merge → wasmtime run` pipeline.

## Related

- [CLI reference](cli.md) — `compile`, `generate`, `merge` flags
- [WASM internals](wasm.md) — exported functions, memory layout, table formats
- [Pattern sets](sets.md) — multi-pattern composition pipeline
- [Engines](engines.md) — DFA, TDFA, Backtracking selection rules
