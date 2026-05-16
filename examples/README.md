# Regexped Examples

| Use case | Environment | Language | Patterns | Directory |
|---|---|---|---|---|
| IPv6 URL validation | wasmtime | Rust | individual | [wasmtime/rust/url-ipv6](wasmtime/rust/url-ipv6) |
| Credential detection | wasmtime | Rust | individual | [wasmtime/rust/secrets](wasmtime/rust/secrets) |
| Multi-pattern secret scanning (native host) | native Rust + wasmtime crate | Rust | set | [wasmtime/rust/secret-scanner](wasmtime/rust/secret-scanner) |
| URL parsing into components | wasmtime | C | individual | [wasmtime/c/url-parts](wasmtime/c/url-parts) |
| CSV parsing and validation | wasmtime | Go | individual | [wasmtime/go/csv](wasmtime/go/csv) |
| SQL injection detection | wasmtime | Go | individual | [wasmtime/go/sql-injection](wasmtime/go/sql-injection) |
| Multi-pattern secret scanning | wasmtime | Go | set | [wasmtime/go/secret-scanner](wasmtime/go/secret-scanner) |
| Email, URL, XSS validation | FastEdge | Rust | individual | [fastedge/validate](fastedge/validate) |
| URL guard | FastEdge | Rust | set | [fastedge/url-guard](fastedge/url-guard) |
| Email and URL validation | Browser | JavaScript | individual | [browser](browser) |
| Domain extraction from URLs | Node.js | TypeScript | individual | [node/domain-extract](node/domain-extract) |
| SQL statement validation | Node.js | TypeScript | set | [node/sql-validator](node/sql-validator) |
| Credential scanner edge API | Cloudflare Workers | JavaScript | individual | [workers](workers) |
| Email extraction with captures | wasmtime | AssemblyScript | individual | [wasmtime/as/find-email](wasmtime/as/find-email) |
| Injections scanner | wasmtime | AssemblyScript | 2 sets | [wasmtime/as/inject-scanner](wasmtime/as/inject-scanner) |

Run `make` in any example directory to build and run end-to-end.

## Two ways to embed regexped

All examples except `wasmtime/rust/secret-scanner` use the **merged WASM**
pattern: the host application is itself compiled to WASM (wasip1 or wasm32),
the regex module is compiled separately, and `regexped merge` (or `wasm-merge`)
links them into a single `.wasm` file. The final binary runs entirely inside a
WASM runtime (`wasmtime`, a browser, or a CDN worker).

`wasmtime/rust/secret-scanner` demonstrates the **native host** pattern: the
host is a native Rust binary that loads a standalone regex `.wasm` file at
runtime using the `wasmtime` crate. No merge step, no WASI, no generated stub —
the host talks directly to the WASM ABI. This is the approach to use when
embedding regexped into a native server, CLI tool, or daemon.
