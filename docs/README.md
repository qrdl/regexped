# Regexped

[![Build](https://github.com/qrdl/regexped/actions/workflows/ci.yml/badge.svg)](https://github.com/qrdl/regexped/actions/workflows/ci.yml)
[![Scan](https://github.com/qrdl/regexped/actions/workflows/codeql.yml/badge.svg)](https://github.com/qrdl/regexped/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/github/qrdl/regexped/graph/badge.svg)](https://codecov.io/github/qrdl/regexped)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://hub.docker.com/r/qrdl/regexped)

Regexped (pronounced reg-exped, short for REGexp EXPEDited) compiles regular expression patterns into standalone WebAssembly modules. It analyses your patterns, picks the best engine (DFA, TDFA, or Backtracking/BitState), emits WASM bytecode, and generates ready-to-use stubs for Rust, Go, C, JavaScript, TypeScript, and AssemblyScript.

Embed high-performance regexp matchers directly into WASM applications — no full regexp engine needed at runtime.

Supports RE2/Perl (leftmost-first) semantics. Unicode not yet supported.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **TDFA engine** — O(n) capture group tracking via Laurikari’s tagged DFA; register-based slot updates on DFA transitions
- **Backtracking engine** — capture group tracking for non-TDFA-eligible patterns, BitState memoization for O(n) worst-case on zero-matchable loops
- **Pattern sets** — compile multiple patterns into a single merged DFA and declare which of five questions you need answered (`match_any`/`match_all` anchored, `scan_any`/`scan_all` non-anchored, `find` for positions and extents); one call scans for all patterns simultaneously, and `find` returns `(pattern_id, start, end)` tuples; a packed-pair SIMD probe (≤16 literals with a usable two-column window), bucketed SIMD Teddy (≤64 literals, given ≥2-byte literals and ≥4 distinct first bytes), Aho-Corasick (the rest, under a 512 KB table budget — it wins where first-byte diversity is low), or a density/hint-selected SIMD Shufti prefilter keep per-byte cost near-constant in set size, with a scalar DFA fallback for sets without mandatory literals
- Stub generation for **Rust**, **Go** (wasip1), **C**, **JavaScript**, **TypeScript**, and **AssemblyScript** — with iterator/generator support (match, find, groups, named groups)
- **Core WASM modules and Component Model components** — `wasm_format:` in the config selects either a core WASM module (the default), merged into a host with `regexped merge`, or a **WASM Component Model component** with a generated WIT interface, composed with its consumer by the same `regexped merge`. Single patterns and pattern sets work in both (a set's `hints: [batch-find]` is module-only); the generated Rust and C stubs have the same API in both, so switching formats changes no calling code
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

Building from source needs Go 1.25 or newer.

**External tools.** `regexped` shells out to three tools, each only where it is
needed. A core-module `compile` and every `generate` need none of them.

| Tool | Needed for |
|---|---|
| [`wasm-merge`](https://github.com/WebAssembly/binaryen) (Binaryen) | `regexped merge` of core modules (`wasm_format: module`) |
| [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools) | components only (`wasm_format: component`): `regexped compile` wraps the core module into a component with it, and `regexped merge` checks each component's exports with it |
| [`wac`](https://github.com/bytecodealliance/wac) | components only: `regexped merge` composes them with it |

Each is found through `wasm_merge_path:`, `wasm_tools_path:` or `wac_path:` in the
config, else on `PATH`. `docker/get_wasm_merge.sh`, `docker/get_wasm_tools.sh`
and `docker/get_wac.sh` in the repository download the latest release of each. Building your own host
code needs its own toolchain (cargo, Go, clang, Node.js…) — see the environment
guides below.

Or use the official Docker image — no local install needed:

```bash
docker pull qrdl/regexped
docker run --rm -v $(pwd):/work -w /work qrdl/regexped <command> [flags]
```

No `--user` flag is needed: everything the image writes is handed to the owner
of the directory it lands in.

See [docker.md](docker.md) for full Docker usage and workflow examples.

## Usage

- **CLI** — see [cli.md](cli.md) for all commands, flags, and config schema.
- **Docker** — see [docker.md](docker.md); official image [`qrdl/regexped`](https://hub.docker.com/r/qrdl/regexped) includes `wasm-merge`, `wasm-tools` and `wac`.

## Documentation

- [CLI reference](cli.md) — commands, flags, config schema, pattern support

**Languages**
- [Rust API](rust-api.md) — generated Rust stubs
- [Go API](go-api.md) — generated Go stubs
- [JavaScript API](js-api.md) — generated JS ES module and generator functions
- [TypeScript API](ts-api.md) — generated TS ES module with typed generator functions
- [AssemblyScript API](as-api.md) — generated AS module with typed iterator classes
- [C API](c-api.md) — generated C header with caller-owned iterators

**Environments**
- [Browser embedding](browser.md) — standalone WASM, JS/TS stub, no merge needed
- [Node.js](node.md) — standalone WASM, TypeScript stub, `readFileSync` + `init()`
- [wasmtime](wasmtime.md) — embedded WASM merged with a Rust/Go/C/AssemblyScript host, or a component composed with its guest, run via the `wasmtime` CLI or any wasmtime embedding
- [Cloudflare Workers](workers.md) — standalone WASM, JS module import, isolate-level init
- [Gcore FastEdge](fastedge.md) — embedded WASM, Rust stubs, merge workflow

**Component Model**
- [Components](component.md) — `wasm_format: component`: the WIT interface, naming, versioning, stubs and costs

**Sets**
- [Pattern sets](sets.md) — multi-pattern composition, YAML schema, output format, frontend selection

**Internals**
- [Engines](engines.md) — DFA, TDFA, Backtracking, engine selection
- [RE2 test coverage](re2.md) — pass/skip counts per engine and skip reasons
- [WASM internals](wasm.md) — WASM interface, memory layout, table formats

## Examples

Examples are available for the following environments: wasmtime, native Rust host, Node.js, Cloudflare Workers, FastEdge, browser.

Languages: Rust, Go, C, JavaScript, TypeScript, AssemblyScript.

Most build a core WASM module. Three build **Component Model components** 🧩: [`wasmtime/rust/secrets`](../examples/wasmtime/rust/secrets) instead of a module, consumed through a generated Rust stub and composed by `regexped merge`; [`wasmtime/rust/secret-scanner`](../examples/wasmtime/rust/secret-scanner) and [`wasmtime/c/url-parts`](../examples/wasmtime/c/url-parts) alongside a module, from the same source — see [component.md](component.md).

See [`examples/README.md`](../examples/README.md) for more details, including which format each example builds.

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
| Pattern sets vs `RegexSet`+rescan (8–20 patterns, 100 KB) | — | 2.0–18.5× faster |

## Limitations

- **No Unicode support** — patterns and input are treated as raw bytes (Latin-1/ASCII). Unicode character classes (`\p{L}`, `\p{N}`, etc.), Unicode case folding, and multi-byte Unicode literals are not supported.
- **Re-entrant, not thread-safe** — every stub keeps its per-scan state with the caller (a caller-owned scanner in C, inside the iterator in Rust, Go and AssemblyScript, a per-call region in JS and TS), so two scans can be in flight at once on one thread. The module itself is not thread-safe in any language: the Backtracking engine keeps its frame stack and BitState memo at fixed addresses in the module's memory, and the find-from position travels to the body through a module-level global. Use one module instance per thread.

## Dependencies

Regexped is almost dependency-free. The only compile-time dependency is [`github.com/goccy/go-yaml`](https://github.com/goccy/go-yaml) for YAML config parsing. All regexp compilation, WASM emission, and stub generation are implemented from scratch with no external libraries.

The `wasmtime-go` binding is used only by the testing and benchmarking tools under `tools/` (`fuzz`, `re2test`, `perftest`, `setperf`, `likelytest`, `pattest`, `settest`) and is not a part of the main tool.

The external tools it shells out to — `wasm-merge`, `wasm-tools` and `wac` — and where each is needed are listed under [Installation](#installation).

## License

See [LICENSE](../LICENSE).
