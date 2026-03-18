# Regexped

A Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. Regexped compiles regex patterns to optimized DFA (Deterministic Finite Automaton) implementations, generates WASM bytecode, and produces language-specific stubs for host application integration.

Embed high-performance regex matchers directly into WASM applications — no full regex engine needed at runtime.

## Features

- Compiles regex patterns to DFA-based WASM modules
- O(n) matching with predictable, DoS-resistant performance
- Byte class compression for compact DFA tables
- Rust FFI stub generation
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

## Quick Start

**1. Create a configuration file (`regexped.yaml`):**

```yaml
wasm_merge: "wasm-merge"   # path to wasm-merge binary, defaults to $PATH
output: "merged.wasm"
regexes:
  - wasm_file: "url_regex.wasm"
    import_module: "url_regex"
    stub_file: "url_regex.rs"
    export_name: "url_match_anchored"
    func_name: "url_match"
    pattern: "^https?://[a-z0-9.-]+\\.[a-z]{2,}(/.*)?$"
```

**2. Generate Rust stubs:**

```bash
regexped stub --config=regexped.yaml --out-dir=src --rust
```

**3. Compile patterns to WASM:**

```bash
regexped compile --config=regexped.yaml --wasm-input=main.wasm --out-dir=build
```

**4. Merge modules:**

```bash
regexped merge --config=regexped.yaml --output=final.wasm main.wasm build/url_regex.wasm
```

## Commands

### `stub` — Generate language stubs

```bash
regexped stub --config=<file> --out-dir=<dir> --rust
```

Generates wrapper functions for calling WASM exports from host languages.

**Generated Rust stub example:**

```rust
#[link(wasm_import_module = "url_regex")]
unsafe extern "C" {
    fn url_match_anchored(ptr: *const u8, len: usize) -> i32;
}

pub fn url_match(input: &[u8]) -> Option<usize> {
    match unsafe { url_match_anchored(input.as_ptr(), input.len()) } {
        n if n >= 0 => Some(n as usize),
        _ => None,
    }
}
```

### `compile` — Compile patterns to WASM

```bash
regexped compile --config=<file> --wasm-input=<main.wasm> --out-dir=<dir>
```

Reads the pre-built main WASM module to determine memory layout, then compiles each regex to a separate WASM module with an embedded DFA transition table.

**Output:** One `.wasm` file per pattern, placed in `--out-dir`.

### `merge` — Merge WASM modules

```bash
regexped merge --config=<file> --output=<out.wasm> <main.wasm> [regex.wasm ...]
```

Patches the main module's memory section to accommodate DFA tables, then combines all modules using `wasm-merge`.

## Generated WASM Interface

Each compiled regex module exports a single match function:

```wasm
;; (ptr: i32, len: i32) -> i32
;; Returns: end position [0, len] on match, or -1 on no match
(func $match (param $ptr i32) (param $len i32) (result i32))
```

The module imports memory from the `"main"` module — no separate memory allocation.

## DFA Table Format

DFA transition tables are stored in WASM linear memory as data segments.

**Uncompressed (small DFAs):**
```
[transitions: u8[numStates * 256]]   // state × input_byte → next_state
[flags: u8[numStates]]               // 1 if accepting state
```

**Compressed (large DFAs):**
```
[class_map: u8[256]]                 // byte → equivalence class
[transitions: u8[numStates * numClasses]]
[flags: u8[numStates]]
```

## Memory Layout

```
┌─────────────────┬─────────────────┬─────────────────┬─────┐
│   Rust Stack    │   Rust Heap     │  DFA Table 1    │ ... │
│   & Globals     │   (optional)    │                 │     │
└─────────────────┴─────────────────┴─────────────────┴─────┘
0               rustTop          tableBase1      tableBase2
```

Each DFA table is placed at a 64KB page-aligned address above the Rust module's memory top.

## Pattern Support

The current release supports **DFA-compatible patterns** only:

| Feature | Supported |
|---|---|
| Literal characters | Yes |
| Character classes `[a-z]`, `\d`, `\w` | Yes |
| Anchors `^`, `$` | Yes (anchored mode) |
| Repetition `*`, `+`, `?`, `{n,m}` | Yes |
| Alternation `\|` (simple) | Yes |
| Capture groups `(...)` | No |
| Backreferences `\1` | No |
| Lookahead/lookbehind | No |
| Word boundaries `\b` | No |
| Unicode (beyond ASCII) | Partial |

Patterns requiring captures, backreferences, or leftmost-first alternation semantics are not yet supported for WASM compilation.

## Performance

**Matching:** O(n) time, O(1) runtime stack — no backtracking, no worst-case blowup.

**Compilation:**
- Typical: <100ms per pattern
- DFA state count: 100–5000 states for most patterns
- Table size: 25–65KB per pattern

## Requirements

- Go 1.25.7+
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen) (for `merge` command)

## Roadmap

- Non-anchored find mode (returns `(start, end)` pair)
- Additional engines: Backtracking, PikeVM, LazyDFA, OnePass
- Go and WIT stub generation
- WebAssembly Component Model support

## License

See [LICENSE](LICENSE).
