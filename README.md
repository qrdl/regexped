# Regexped

A Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. Regexped compiles regex patterns to optimized DFA, TDFA, or Backtracking engine implementations, generates WASM bytecode, and produces language-specific stubs for host application integration.

Embed high-performance regex matchers directly into WASM applications — no full regex engine needed at runtime.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, LeftmostFirst (RE2/Perl) alternation semantics, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **TDFA engine** — O(n) capture group tracking via Laurikari’s tagged DFA; register-based slot updates on DFA transitions
- **Backtracking engine** — capture group tracking for non-TDFA-eligible patterns, LeftmostFirst (RE2/Perl) semantics, BitState memoization for O(n) worst-case on zero-matchable loops
- Stub generation for **Rust**, **Go** (wasip1), **JavaScript**, **TypeScript**, and **C** — with iterator/generator support (match, find, groups, named groups)
- WASM module merging via `wasm-merge`
- Configurable via YAML

## Installation

```bash
go install github.com/qrdl/regexped@latest
```

Or build from source:

```bash
git clone https://github.com/qrdl/regexped
cd regexped
go build -o regexped .
```

**External dependency:** [`wasm-merge`](https://github.com/WebAssembly/binaryen) (Binaryen toolkit) — required for the `merge` command.

## Documentation

- [CLI reference](docs/cli.md) — commands, flags, config schema, pattern support
- [Rust API](docs/rust-api.md) — generated Rust function signatures and iterator usage
- [Go API](docs/go-api.md) — generated Go stubs (`//go:wasmimport`, `iter.Seq2`, `iter.Seq`)
- [JavaScript API](docs/js-api.md) — generated JS ES module and generator functions
- [TypeScript API](docs/ts-api.md) — generated TS ES module with typed generator functions
- [Browser embedding](docs/browser.md) — loading WASM in the browser, JS/TS stub workflow
- [Engines](docs/engines.md) — DFA, TDFA, Backtracking, engine selection
- [RE2 test coverage](docs/re2.md) — pass/skip counts per engine and skip reasons
- [WASM internals](docs/wasm.md) — WASM interface, memory layout, table formats

## Examples

See [`examples/`](examples/) for self-contained projects with Makefiles:

**Rust (wasmtime)**
- **url-ipv6** — anchored DFA match: validate URLs with IPv6 addresses
- **secrets** — DFA find: scan text for GitHub tokens, JWTs, and AWS keys

**Go (wasip1)**
- **csv** — TDFA named groups: parse and validate CSV rows, extract fields by name
- **sql-injection** — Backtracking: detect SQL injection patterns in query strings

**C (wasmtime)**
- **url-parts** — TDFA named groups: parse URLs into scheme, host, path, and query

**JavaScript / TypeScript**
- **node** — Node.js: extract domains from URLs in text using a TS stub
- **workers** — Cloudflare Worker: credential scanner edge API using a JS stub
- **browser** — browser: email and URL validation via JS + WASM (no bundler required)

## Performance

**DFA/TDFA matching:** O(n) time, O(1) runtime stack — no worst-case blowup.

**Backtracking:** LeftmostFirst (RE2/Perl) semantics for non-deterministic capture patterns. BitState memoization bounds runtime to O(n × numStates) for patterns with zero-matchable loops; stack overflow guard prevents memory corruption on deeply nested patterns.

**SIMD prefix scan:** First-byte and two-byte Teddy algorithm skips non-matching positions in bulk using WASM SIMD instructions, reducing DFA transitions on typical inputs.

## Limitations

- **No Unicode support** — patterns and input are treated as raw bytes (Latin-1/ASCII). Unicode character classes (`\p{L}`, `\p{N}`, etc.), Unicode case folding, and multi-byte Unicode literals are not supported.
- **No WASM Component Model** — generated modules use the core WASM ABI (linear memory + exported functions). WASM Component Model support is planned.

## Requirements

- Go 1.25.7+
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen) (for `merge` command)

## License

See [LICENSE](LICENSE).
