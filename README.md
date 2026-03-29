# Regexped

A Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. Regexped compiles regex patterns to optimized DFA, OnePass, or Backtracking engine implementations, generates WASM bytecode, and produces language-specific stubs for host application integration.

Embed high-performance regex matchers directly into WASM applications — no full regex engine needed at runtime.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, LeftmostFirst (RE2/Perl) alternation semantics, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **OnePass engine** — O(n) capture group tracking for deterministic patterns (disjoint alternations)
- **Backtracking engine** — capture group tracking for non-deterministic patterns, LeftmostFirst (RE2/Perl) semantics, BitState memoization for O(n) worst-case on zero-matchable loops
- Rust FFI stub generation with iterator support (match, find, groups, named groups)
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
- [Rust API](docs/rust-api.md) — generated function signatures and iterator usage
- [Browser embedding](docs/browser.md) — JS ES module workflow, generated JS API
- [Engines](docs/engines.md) — DFA, OnePass, Backtracking, engine selection
- [RE2 test coverage](docs/re2.md) — pass/skip counts per engine and skip reasons
- [WASM internals](docs/wasm.md) — WASM interface, memory layout, table formats

## Examples

See [`examples/`](examples/) for three self-contained projects with Makefiles:

- **url-ipv6** — match a URL with an IPv6 address using anchored DFA
- **secrets** — scan text for GitHub tokens, JWTs, and AWS keys
- **url-parts** — find and parse all URLs in text using the OnePass engine
- **browser** — email and URL validation in the browser via JS + WASM (no Rust, no bundler)

## Performance

**DFA/OnePass matching:** O(n) time, O(1) runtime stack — no worst-case blowup.

**Backtracking:** LeftmostFirst (RE2/Perl) semantics for non-deterministic capture patterns. BitState memoization bounds runtime to O(n × numStates) for patterns with zero-matchable loops; stack overflow guard prevents memory corruption on deeply nested patterns.

**SIMD prefix scan:** First-byte and two-byte Teddy algorithm skips non-matching positions in bulk using WASM SIMD instructions, reducing DFA transitions on typical inputs.

## Requirements

- Go 1.25.7+
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen) (for `merge` command)

## License

See [LICENSE](LICENSE).
