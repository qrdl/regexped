# Regexped

A Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. Regexped compiles regex patterns to optimized DFA (Deterministic Finite Automaton) or OnePass automaton implementations, generates WASM bytecode, and produces language-specific stubs for host application integration.

Embed high-performance regex matchers directly into WASM applications — no full regex engine needed at runtime.

## Features

- **DFA engine** — O(n) anchored matching and non-anchored find, LeftmostFirst (RE2/Perl) alternation semantics, word boundary assertions (`\b`, `\B`), byte class compression, SIMD prefix scan (Teddy algorithm)
- **OnePass engine** — anchored matching with capture group tracking for deterministic patterns
- Rust FFI stub generation (match, find, groups, named groups)
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
  - wasm_file:     "url_regex.wasm"
    import_module: "url_regex"
    stub_file:     "url_regex.rs"
    pattern:       'https?://[a-z0-9.-]+\.[a-z]{2,}(/[^\s]*)?'
    match_func:    "url_match"      # anchored: Option<usize>
    find_func:     "url_find"       # non-anchored: Option<(usize, usize)>
```

For patterns with capture groups, use `groups_func` or `named_groups_func` instead (requires a deterministic OnePass-eligible pattern):

```yaml
    pattern:          '(?P<scheme>https?)://(?P<host>[^/:?#]+)...'
    named_groups_func: "parse_url"  # Option<HashMap<&'static str, (usize, usize)>>
```

**2. Generate Rust stubs:**

```bash
regexped stub --config=regexped.yaml --out-dir=. --rust
```

**3. Compile patterns to WASM:**

```bash
regexped compile --config=regexped.yaml --wasm-input=main.wasm --out-dir=.
```

**4. Merge modules:**

```bash
regexped merge --config=regexped.yaml main.wasm url_regex.wasm
```

## Commands

### `stub` — Generate language stubs

```bash
regexped stub --config=<file> --out-dir=<dir> --rust
```

Generates `src/<stub_file>` for each regex entry. Four stub types based on which `_func` fields are set:

| Config field | Rust return type |
|---|---|
| `match_func` | `Option<usize>` — end position of anchored match |
| `find_func` | `Option<(usize, usize)>` — (start, end) of leftmost match |
| `groups_func` | `Option<Vec<Option<(usize, usize)>>>` — all capture groups |
| `named_groups_func` | `Option<HashMap<&'static str, (usize, usize)>>` — named groups |

### `compile` — Compile patterns to WASM

```bash
regexped compile --config=<file> --wasm-input=<main.wasm> --out-dir=<dir>
```

Reads the pre-built main WASM module to determine memory layout, then compiles each regex to a separate WASM module with an embedded transition table.

Engine selection is automatic:
- **OnePass** — patterns with captures where alternations are deterministic
- **DFA** — all other patterns (with LeftmostFirst semantics when needed)

**Output:** One `.wasm` file per pattern, placed in `--out-dir`.

### `merge` — Merge WASM modules

```bash
regexped merge --config=<file> [--output=<out.wasm>] <main.wasm> [regex.wasm ...]
```

Patches the main module's memory section to accommodate DFA/OnePass tables, then combines all modules using `wasm-merge`.

## Generated WASM Interface

```wasm
;; Anchored match: (ptr: i32, len: i32) -> i32
;; Returns end position [0, len] on match, or -1 on no match
(func $match (param $ptr i32) (param $len i32) (result i32))

;; Non-anchored find: (ptr: i32, len: i32) -> i64
;; Returns packed (start << 32 | end) on match, or -1 on no match
(func $find (param $ptr i32) (param $len i32) (result i64))

;; Anchored groups: (ptr: i32, len: i32, out_ptr: i32) -> i32
;; Writes numGroups*2 i32 slots [start0,end0,start1,end1,...] to out_ptr
;; Returns end position on match, or -1 on no match
(func $groups (param $ptr i32) (param $len i32) (param $out_ptr i32) (result i32))
```

All modules import memory from the `"main"` module — no separate memory allocation.

## Pattern Support

| Feature | Supported |
|---|---|
| Literal characters | Yes |
| Character classes `[a-z]`, `\d`, `\w` | Yes |
| Anchors `^`, `$` | Yes |
| Repetition `*`, `+`, `?`, `{n,m}` | Yes |
| Non-greedy quantifiers `*?`, `+?` | Yes |
| Alternation `\|` (LeftmostFirst / RE2 semantics) | Yes |
| Word boundaries `\b`, `\B` | Yes |
| Capture groups (deterministic patterns) | Yes — OnePass engine |
| Capture groups (non-deterministic) | No |
| Backreferences `\1` | No |
| Lookahead / lookbehind | No |
| Unicode beyond ASCII | No |

## Memory Layout

```
┌─────────────────┬─────────────────┬─────────────────┬─────┐
│   Rust Stack    │   Rust Heap     │  DFA Table 1    │ ... │
│   & Globals     │   (optional)    │                 │     │
└─────────────────┴─────────────────┴─────────────────┴─────┘
0               rustTop          tableBase1      tableBase2
```

Each regex table is placed at a 64KB page-aligned address above the Rust module's memory top.

## Examples

See [`examples/`](examples/) for three self-contained examples with Makefiles:

- **url-ipv6** — find URLs with IPv6 addresses using DFA find mode
- **secrets** — detect GitHub tokens, JWTs, and AWS keys with three merged DFA modules
- **url-parts** — parse a URL into named components using the OnePass engine

## Performance

**Matching:** O(n) time, O(1) runtime stack — no backtracking, no worst-case blowup.

**SIMD prefix scan:** First-byte and two-byte Teddy algorithm skips non-matching positions in bulk using WASM SIMD instructions, reducing DFA transitions on typical inputs.

## Requirements

- Go 1.25.7+
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen) (for `merge` command)

## Roadmap

- Hybrid WASM modules (match + find + groups in one file, see `HYBRID_WASM_PLAN.md`)
- Backtracking / PikeVM engine for non-deterministic capture patterns
- Go and WIT stub generation

## License

See [LICENSE](LICENSE).
