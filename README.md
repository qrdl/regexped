# Regexped

[![Build](https://github.com/qrdl/regexped/actions/workflows/ci.yml/badge.svg)](https://github.com/qrdl/regexped/actions/workflows/ci.yml)
[![Scan](https://github.com/qrdl/regexped/actions/workflows/codeql.yml/badge.svg)](https://github.com/qrdl/regexped/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/github/qrdl/regexped/graph/badge.svg)](https://codecov.io/github/qrdl/regexped)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://hub.docker.com/r/qrdl/regexped)

- [Features](#features)
- [Capabilities (what you can ask)](#capabilities-what-you-can-ask)
- [Performance](#performance)
- [Resistance to hostile input](#resistance-to-hostile-input)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Documentation](docs/README.md)
- [Dependencies](#dependencies)
- [License](#license)

Regexped (pronounced reg-exped, short for REGexp EXPEDited) compiles regular expression patterns into standalone WebAssembly modules. It analyses your patterns, picks the best engine (DFA, TDFA, or Backtracking/BitState), emits WASM bytecode, and generates ready-to-use stubs for Rust, Go, C, JavaScript, TypeScript, and AssemblyScript.

Embed high-performance regexp matchers directly into WASM applications — no full regexp engine needed at runtime.

Supports RE2/Perl (leftmost-first) semantics, over bytes or — in Unicode mode, chosen per pattern and per set — over UTF-8 characters.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **TDFA engine** — O(n) capture group tracking via Laurikari’s tagged DFA; register-based slot updates on DFA transitions
- **Backtracking engine** — capture group tracking for non-TDFA-eligible patterns, BitState memoization for O(n) worst-case on zero-matchable loops
- **Pattern sets** — compile multiple patterns into a single merged DFA and declare which of five questions you need answered (`match_any`/`match_all` anchored, `scan_any`/`scan_all` non-anchored, `find` for positions and extents); one call scans for all patterns simultaneously, and `find` returns `(pattern_id, start, end)` tuples; a packed-pair SIMD probe (≤16 literals with a usable two-column window), bucketed SIMD Teddy (≤64 literals, given ≥2-byte literals and ≥4 distinct first bytes), Aho-Corasick (the rest, under a 512 KB table budget — it wins where first-byte diversity is low), or a density/hint-selected SIMD Shufti prefilter keep per-byte cost near-constant in set size, with a scalar DFA fallback for sets without mandatory literals
- Stub generation for **Rust**, **Go** (wasip1), **C**, **JavaScript**, **TypeScript**, and **AssemblyScript** — with iterator/generator support (match, find, groups, named groups)
- **Core WASM modules and Component Model components** — `wasm_format:` in the config selects either a core WASM module (the default), merged into a host with `regexped merge`, or a **WASM Component Model component** with a generated WIT interface, composed with its consumer by the same `regexped merge`. Single patterns and pattern sets work in both (a set's `hints: [batch-find]` is module-only); the generated Rust and C stubs have the same API in both, so switching formats changes no calling code
- Configurable via YAML

## Capabilities (what you can ask)

**A single pattern** gets one export per `*_func` key in the config:

| Capability | Question it answers |
|---|---|
| `match_func` | Does the input start with a match, and where does it end? |
| `find_func` | Where is every match? Iterates `(start, end)`. |
| `groups_func` | Where is every match, with its capture groups? Iterates the groups, by number or name. |

**A pattern set** compiles only the questions it declares, each answered for all its patterns in one pass:

| Capability | Question it answers |
|---|---|
| `match_any` | Does any pattern match the whole input? Returns one pattern id. |
| `match_all` | Which patterns match the whole input? |
| `scan_any` | Does any pattern occur anywhere in it? Returns one pattern id. |
| `scan_all` | Which patterns occur anywhere in it? |
| `find` | Where is every match, and of which pattern? Iterates `(pattern, start, end)`; `overlapping: true` reports every start position, and `hints: [batch-find]` adds a variant returning many matches per call. |

See [sets.md](docs/sets.md) for the details.

## Performance

Regexped is on average **4–6× faster than Rust's `regex` and `regex-automata`
crates** (geometric mean of median times over 25 scenarios: single patterns,
Unicode text, pattern sets), with O(n) matching on every DFA and TDFA path.
See [docs/performance.md](docs/performance.md) for the tables.

## Resistance to hostile input

Regexped-generated code is built to withstand ReDoS — input crafted to make a matcher take exponential or quadratic time, or unbounded memory:

- **Linear time.** DFA and TDFA read each byte once; a Backtracking search that exhausts its work budget moves to a memoised body that tries each (instruction, position) pair at most once. Iterating `find`/`groups`, and pattern sets, stay linear over the whole scan, not just per call.
- **Bounded memory.** `max_memory:` caps the module; a search that would need more reports "unknown", never a false "no match". `regexped compile` warns when Backtracking code has no cap.
- **Sandboxed and tested.** Everything runs inside WebAssembly with every caller buffer size-checked; `make adversary` checks that 76 hostile input shapes stay linear.

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

Building from source needs Go 1.26 or newer.

**External tools.** `regexped` shells out to three tools, each only where it is
needed. A core-module `compile` and every `generate` need none of them.

| Tool | Needed for |
|---|---|
| [`wasm-merge`](https://github.com/WebAssembly/binaryen) (Binaryen) | `regexped merge` of core modules (`wasm_format: module`) |
| [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools) | components only (`wasm_format: component`): `regexped compile` wraps the core module into a component with it, and `regexped merge` checks each component's exports with it |
| [`wac`](https://github.com/bytecodealliance/wac) | components only: `regexped merge` composes them with it |

Each is found through `wasm_merge_path:`, `wasm_tools_path:` or `wac_path:` in the
config, else on `PATH`. `docker/get_wasm_merge.sh`, `docker/get_wasm_tools.sh`
and `docker/get_wac.sh` in the repository download the latest release of each —
each takes an optional architecture (`amd64` or `arm64`, default this machine's)
and an optional destination. Building your own host
code needs its own toolchain (cargo, Go, clang, Node.js…) — see the environment
guides below.

Or use the official Docker image — no local install needed:

```bash
docker pull qrdl/regexped
docker run --rm -v $(pwd):/work -w /work qrdl/regexped <command> [flags]
```

See [docker.md](docs/docker.md) for full Docker usage and workflow examples.

## Usage

- **CLI** — see [cli.md](docs/cli.md) for all commands, flags, and config schema.
- **Docker** — see [docker.md](docs/docker.md); official image [`qrdl/regexped`](https://hub.docker.com/r/qrdl/regexped) includes `wasm-merge`, `wasm-tools` and `wac`.

## Examples

Examples are available for the following environments: wasmtime, native Rust host, Node.js, Cloudflare Workers, FastEdge, browser.

Languages: Rust, Go, C, JavaScript, TypeScript, AssemblyScript.

Most build a core WASM module. Four build **Component Model components** 🧩: [`wasmtime/rust/secrets`](examples/wasmtime/rust/secrets) and the FastEdge HTTP app [`fastedge/lang-detect`](examples/fastedge/lang-detect) instead of a module, consumed through a generated Rust stub and composed by `regexped merge`; [`wasmtime/rust/secret-scanner`](examples/wasmtime/rust/secret-scanner) and [`wasmtime/c/url-parts`](examples/wasmtime/c/url-parts) alongside a module, from the same source — see [component.md](docs/component.md).

Two compile their patterns in **Unicode mode**: [`fastedge/lang-detect`](examples/fastedge/lang-detect), which names European languages by the letters of a text, and [`browser/homoglyph`](examples/browser/homoglyph), which marks lookalike letters and invisible and text-direction characters as you type.

See [`examples/README.md`](examples/README.md) for more details, including which format each example builds.

## Documentation

See the [documentation index](docs/README.md).

## Dependencies

Regexped is almost dependency-free. The only compile-time dependency is [`github.com/goccy/go-yaml`](https://github.com/goccy/go-yaml) for YAML config parsing. All regexp compilation, WASM emission, and stub generation are implemented from scratch with no external libraries.

The `wasmtime-go` binding is used only by the testing and benchmarking tools under `tools/` (`fuzz`, `re2test`, `perftest`, `setperf`, `likelytest`, `pattest`, `settest`) and is not a part of the main tool.

The external tools it shells out to — `wasm-merge`, `wasm-tools` and `wac` — and where each is needed are listed under [Installation](#installation).

## License

See [LICENSE](LICENSE).
