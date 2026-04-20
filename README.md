# Regexped

[![Go Report Card](https://goreportcard.com/badge/github.com/qrdl/regexped)](https://goreportcard.com/report/github.com/qrdl/regexped)
[![Tests](https://github.com/qrdl/regexped/actions/workflows/ci.yml/badge.svg?query=branch%3Amain)](https://github.com/qrdl/regexped/actions/workflows/ci.yml?query=branch%3Amain)

Regexped (pronounced reg-exped, short for REGexp EXPEDited) compiles regular expression patterns into standalone WebAssembly modules. It analyses your patterns, picks the best engine (DFA, TDFA, or Backtracking/BitState), emits WASM bytecode, and generates ready-to-use stubs for Rust, Go, C, JavaScript, TypeScript, and AssemblyScript.

Embed high-performance regex matchers directly into WASM applications — no full regex engine needed at runtime.

Supports RE2/Perl (leftmost-first) semantics. Unicode not yet supported.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **TDFA engine** — O(n) capture group tracking via Laurikari’s tagged DFA; register-based slot updates on DFA transitions
- **Backtracking engine** — capture group tracking for non-TDFA-eligible patterns, BitState memoization for O(n) worst-case on zero-matchable loops
- Stub generation for **Rust**, **Go** (wasip1), **C**, **JavaScript**, **TypeScript**, and **AssemblyScript** — with iterator/generator support (match, find, groups, named groups)
- WASM module merging via `wasm-merge` — WASM Component Model support coming soon
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

Or use the official Docker image — no local install needed:

```bash
docker pull qrdl/regexped
docker run --rm -v $(pwd):/work -w /work qrdl/regexped <command> [flags]
```

See [docs/docker.md](docs/docker.md) for full Docker usage and workflow examples.

## Usage

- **CLI** — see [docs/cli.md](docs/cli.md) for all commands, flags, and config schema.
- **Docker** — see [docs/docker.md](docs/docker.md); official image [`qrdl/regexped`](https://hub.docker.com/r/qrdl/regexped) includes `wasm-merge`.

## Documentation

- [CLI reference](docs/cli.md) — commands, flags, config schema, pattern support
- [Rust API](docs/rust-api.md) — generated Rust function signatures and iterator usage
- [Go API](docs/go-api.md) — generated Go stubs (`//go:wasmimport`, `iter.Seq2`, `iter.Seq`)
- [JavaScript API](docs/js-api.md) — generated JS ES module and generator functions
- [TypeScript API](docs/ts-api.md) — generated TS ES module with typed generator functions
- [AssemblyScript API](docs/as-api.md) — generated AS module with typed iterator classes
- [C API](docs/c-api.md) — generated C header with static iterator functions
- [Browser embedding](docs/browser.md) — loading WASM in the browser, JS/TS stub workflow
- [Engines](docs/engines.md) — DFA, TDFA, Backtracking, engine selection
- [RE2 test coverage](docs/re2.md) — pass/skip counts per engine and skip reasons
- [WASM internals](docs/wasm.md) — WASM interface, memory layout, table formats

## Examples

Examples are available for the following environments: wasmtime, Node.js, Cloudflare Workers, FastEdge, browser.

Languages: Rust, Go, C, JavaScript, TypeScript, AssemblyScript.

See [`examples/README.md`](examples/README.md) for more details.

## Performance

**DFA/TDFA matching:** O(n) time, O(1) runtime stack — no worst-case blowup.

**Backtracking:** LeftmostFirst (RE2/Perl) semantics for non-deterministic capture patterns. BitState memoization bounds runtime to O(n × numStates) for patterns with zero-matchable loops; stack overflow guard prevents memory corruption on deeply nested patterns.

**SIMD prefix scan:** First-byte and two-byte Teddy algorithm skips non-matching positions in bulk using WASM SIMD instructions, reducing DFA transitions on typical inputs.

**Comparison vs [regex crate](https://crates.io/crates/regex)** (benchmarked via wasmtime, measured in fuel consumed and median execution time):

| Scenario | Fuel consumed | Median latency |
|---|---|---|
| Anchored match (email, URL) | 1.1–2.2× less | 1.0–1.6× faster |
| Non-anchored find (secrets, SQL injection) | 1.7–7.8× less | 1.6–7.2× faster |
| Multi-pattern find (combined secrets, 100 KB) | 8.2–8.4× less | 12.9–13.9× faster |
| TDFA capture groups (URL parse) | 2.3–6.9× less | 3.0–5.1× faster |
| Backtracking capture groups | 1.9–12.3× less | 1.7–21.4× faster |
| No-match fast-reject | up to 21.9× less | up to 12.7× faster |

## Limitations

- **No Unicode support** — patterns and input are treated as raw bytes (Latin-1/ASCII). Unicode character classes (`\p{L}`, `\p{N}`, etc.), Unicode case folding, and multi-byte Unicode literals are not supported.
- **No WASM Component Model** — generated modules use the core WASM ABI (linear memory + exported functions). WASM Component Model support is planned.
- **Not thread-safe** — the C, JS, TS, and AS stubs are not safe for concurrent use. Only the Rust and Go stubs are thread-safe.

## Requirements

- Go 1.25
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen) (for `merge` command)

## License

See [LICENSE](LICENSE).
