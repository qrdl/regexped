# Regexped Examples

The **Format** column is the `wasm_format:` each example builds: `module` is the
core WASM module, `component` is a WASM Component Model component with a
generated WIT interface. Component examples are marked **🧩**. `url-parts` builds
BOTH kinds from one unchanged source — and the component kind by two different
routes (`make`, `make component-run`, `make wasip2-run`).

| Use case | Environment | Language | Patterns | Format | Directory |
|---|---|---|---|---|---|
| IPv6 URL validation | wasmtime | Rust | individual | module | [wasmtime/rust/url-ipv6](wasmtime/rust/url-ipv6) |
| Credential detection | wasmtime | Rust | individual | **component 🧩** | [wasmtime/rust/secrets](wasmtime/rust/secrets) |
| Multi-pattern secret scanning (native host) 🧩 | native Rust + wasmtime crate | Rust | set | **module AND component** | [wasmtime/rust/secret-scanner](wasmtime/rust/secret-scanner) |
| URL parsing into components | wasmtime | C | individual | **module + component 🧩** | [wasmtime/c/url-parts](wasmtime/c/url-parts) |
| CSV parsing and validation | wasmtime | Go | individual | module | [wasmtime/go/csv](wasmtime/go/csv) |
| SQL injection detection | wasmtime | Go | individual | module | [wasmtime/go/sql-injection](wasmtime/go/sql-injection) |
| Multi-pattern secret scanning | wasmtime | Go | set | module | [wasmtime/go/secret-scanner](wasmtime/go/secret-scanner) |
| Email, URL, XSS validation | FastEdge | Rust | individual | module | [fastedge/validate](fastedge/validate) |
| URL guard | FastEdge | Rust | set | module | [fastedge/url-guard](fastedge/url-guard) |
| Email and URL validation | Browser | JavaScript | individual | module | [browser](browser) |
| Domain extraction from URLs | Node.js | TypeScript | individual | module | [node/domain-extract](node/domain-extract) |
| SQL statement validation | Node.js | TypeScript | set | module | [node/sql-validator](node/sql-validator) |
| Credential scanner edge API | Cloudflare Workers | JavaScript | individual | module | [workers](workers) |
| Email extraction with captures | wasmtime | AssemblyScript | individual | module | [wasmtime/as/find-email](wasmtime/as/find-email) |
| Injection scanner | wasmtime | AssemblyScript | 2 sets | module | [wasmtime/as/inject-scanner](wasmtime/as/inject-scanner) |

Run `make` in any example directory to build and run end-to-end.

## Three ways to embed regexped

**1. Merged WASM** — most examples. The host application is itself compiled to
WASM (wasip1 or wasm32), the regexp module is compiled separately, and
`regexped merge` (or `wasm-merge`) links them into a single `.wasm` file. The
final binary runs entirely inside a WASM runtime (`wasmtime`, a browser, or a
CDN worker).

**2. Native host** — `wasmtime/rust/secret-scanner`. The host is a native Rust
binary that loads regexped's output at runtime using the `wasmtime` crate. No
merge step, no WASI, and no generated stub — a stub is for a guest compiled to
WASM. Use this when embedding regexped into a native server, CLI tool, or daemon,
and when you want patterns to be a file you can replace rather than something
linked into the binary.

That example builds BOTH output kinds from the same patterns: `make` loads a
module and drives the raw ABI by hand — memory layout, the gate array, 12-byte
tuples — while `make component-run` loads a component and drives a `resource`
through `bindgen!`-generated bindings, with none of that. `make compare` diffs
the two. It is also the only example that uses a **set** through a component.

**3. Component Model 🧩** — `wasmtime/rust/secrets`. `wasm_format: component`
produces a component plus a sibling `.wit`. The consumer is itself a component
that imports that interface, and `regexped merge` composes the two — the SAME
command the module format uses, which dispatches on `wasm_format` and shells out
to `wac` here where it shells out to `wasm-merge` there. No linear-memory
bookkeeping; each component owns its own.

That example uses a **generated Rust stub**, and its `main.rs` differs from the
module-format version by the module name and one comment: switching
`wasm_format` does not change calling code. `stub_type: rust` and `wit` are the
component stub types; see [../docs/component.md](../docs/component.md) for what
each `stub_type` does under `component`.
