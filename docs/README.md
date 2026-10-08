# Regexped documentation

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
- [Performance](performance.md) — regexped against the `regex` crate and `regex-automata`: averages and per-scenario tables
- [Engines](engines.md) — DFA, TDFA, Backtracking, engine selection
- [Keeping time and memory linear](complexity.md) — every mechanism against quadratic scans and unbounded memory, what each costs, and what is still not linear
- [RE2 test coverage](re2.md) — pass/skip counts per engine and skip reasons
- [WASM internals](wasm.md) — WASM interface, memory layout, table formats
