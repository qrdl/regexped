# Regexped WASM - Project Overview

## Purpose

**Regexped** is a Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. It analyzes regex patterns, compiles them to optimized DFA or OnePass automaton implementations, generates WASM bytecode, and produces language-specific stubs for integration with host applications.

The project enables embedding high-performance regex matchers directly into WASM applications without shipping a full regex engine, reducing binary size and improving performance predictability.

## Architecture

### High-Level Flow

```
YAML Config → Parse Patterns → Select Engine → Compile → Generate WASM → Generate Stubs → Merge Modules
     ↓              ↓               ↓              ↓           ↓              ↓              ↓
  config/      compile/        compile/       compile/    compile/       generate/       merge/
```

### Directory Structure

```
regexped/
├── main.go                    # CLI entry point: generate, compile, merge
├── config/
│   └── config.go              # YAML configuration parsing
├── compile/
│   ├── compile.go             # Public API: CmdCompile, CompileRegex, CompileOnePassGroups, SelectEngine
│   ├── selector.go            # Engine selection + isOnePass detection
│   ├── engine_dfa.go          # DFA subset construction, table generation, WASM emission
│   ├── engine_onepass.go      # OnePass automaton construction and WASM emission
│   ├── prefix_scan.go         # Shared SIMD prefix scan (EmitPrefixScan)
│   └── wasm.go                # WASM binary encoding primitives
├── generate/
│   ├── generate.go            # Stub generation orchestration (CmdStub)
│   ├── rust_stub.go           # Rust FFI stub generator (iterators)
│   └── dummy_main.go          # Dummy main WASM generator (CmdDummyMain)
├── merge/
│   └── merge.go               # WASM module merging with wasm-merge
├── utils/
│   └── bytes.go               # LEB128, page alignment, RustMemTop
├── re2test/
│   ├── main.go                # RE2 exhaustive test runner (wasmtime-based)
│   └── Makefile               # Unpacks test data, runs tests
├── perftest/
│   ├── main.go                # Performance benchmarks vs regex crate
│   └── Makefile               # Builds harnesses, runs benchmarks
├── docs/
│   ├── cli.md                 # CLI reference: commands, flags, config schema
│   ├── rust-api.md            # Generated Rust API: function signatures, iterators
│   └── wasm.md                # WASM interface, memory layout, table formats
└── examples/
    ├── README.md
    ├── Makefile
    ├── url-ipv6/              # DFA anchored match: validate IPv6 URLs
    ├── secrets/               # DFA find: scan text for GitHub/JWT/AWS secrets
    ├── url-parts/             # OnePass named_groups: find and parse all URLs in text
    └── browser/               # Browser demo: email + URL validation via JS + WASM
```

## Components

### 1. Configuration (`config/`)

**File:** `config.go`

Parses YAML configuration files. Schema:

```yaml
wasm_merge: "path/to/wasm-merge"  # optional, defaults to $PATH
output:   "merged.wasm"           # output path for merge command; overridable with -o/--output
wasm_dir: "."                     # default output directory for compiled WASM files; overridable with -d/--out-dir
stub_file: "src/stubs.rs"         # default stub output file (Rust or JS); per-entry overrides
regexes:
  - wasm_file:        "url.wasm"
    import_module:    "url"
    stub_file:        "src/url.rs"  # per-entry override; if absent, uses top-level stub_file
    pattern:          '(?P<scheme>https?)://(?P<host>[^/:?#]+)...'

    # All func fields are optional; an entry with only 'pattern' is silently skipped.
    # Each func name becomes the WASM export name AND the generated function name.
    match_func:        "url_match"         # anchored match → Option<usize> / boolean (JS)
    find_func:         "url_find"          # non-anchored find → FindIter / generator (JS)
    groups_func:       "url_groups"        # anchored + captures → GroupsIter / generator (JS)
    named_groups_func: "url_named_groups"  # anchored + named captures → NamedGroupsIter / generator (JS)
```

Setting `groups_func` or `named_groups_func` triggers capture-tracking compilation (OnePass engine).
Setting only `match_func` and/or `find_func` strips captures from the pattern before compilation.
An entry with no `_func` fields is valid — no WASM file is compiled and no stub is generated for it.

### 2. Compilation (`compile/`)

#### `compile.go` — Public API

- `CmdCompile(cfg, wasmInput, outDir)` — compiles all patterns from config
- `CompileRegex(pattern, exportName, tableBase, standalone, opts)` — DFA compilation
- `CompileOnePassGroups(pattern, exportName, tableBase, standalone)` — OnePass compilation
- `SelectEngine(pattern, opts)` — returns engine type without compiling
- `stripCaptures(re)` — removes capture groups from parsed regexp tree

`compileRegexEntry` dispatches based on which `_func` fields are set:
- `groups_func`/`named_groups_func` → OnePass
- `find_func` only → DFA find mode
- `match_func` only → DFA anchored mode
- no `_func` fields → returns nil (skipped silently)

#### `selector.go` — Engine Selection

Decision tree (in priority order):

1. **OnePass** — has captures + `isOnePass()` + no nested/non-greedy quantifiers
2. **Backtrack** — has captures that don't qualify for OnePass (not yet implemented for WASM)
3. **DFA (LeftmostFirst)** — user alternations (`|`) or nested quantifiers
4. **DFA (standard)** — everything else

`isOnePass` checks:
- All `InstAlt` nodes have disjoint first-character sets (`isAlternationDeterministic`)
- One branch can be epsilon-accept (loop exit) — handled by `isEpsilonAccept`
- Pattern ≤ 100 NFA instructions

#### `engine_dfa.go` — DFA Engine

**Subset construction (`newDFA`):**
- NFA bytecode (`syntax.Prog`) → DFA via epsilon closure + transition computation
- `epsilonClosure` with LeftmostFirst priority ordering (highest-priority NFA state wins)
- `immediateAccepting` states for correct non-greedy quantifier semantics
- Word boundary support via `prevWasWord` context bit — doubles state space, two mid-start states (`midStart`, `midStartWord`)

**Table generation (`dfaTableFrom`):**
- u8 state IDs when ≤ 256 states; u16 otherwise
- `computeByteClasses` — equivalence class compression (reduces table size when many bytes have identical transitions)
- `wordCharTable` — 256-byte lookup for `\w` characters, stored in data segment

**WASM emission (`genWASM`):**
- Imports memory from `"main"` module
- Exports `match` function `(ptr i32, len i32) → i32`  or `find` function `(ptr i32, len i32) → i64`
- DFA execution loop in WASM structured control flow (`block`/`loop`/`br_table`)
- Calls `EmitPrefixScan` for fast-skip prologue in find mode

**Find mode:**
- Non-anchored scan: tries each start position
- Returns packed `(start << 32 | end)` as i64, or -1

#### `prefix_scan.go` — Shared SIMD Prefix Scan

`EmitPrefixScan(b, params)` emits the fast-skip prologue for find mode. Used by `engine_dfa.go`; will be used by OnePass find mode when implemented.

Strategies (chosen at compile time based on pattern):
1. **2-byte Teddy** — if literal prefix has ≥ 2 bytes: T1_lo/T1_hi nibble tables check byte[k] and byte[k+1] simultaneously, near-zero false positives
2. **1-byte Teddy** — if prefix has 1 byte but multiple first-byte candidates: T_lo/T_hi nibble tables
3. **Multi-eq SIMD** — if first-byte set is small: i8x16.eq + bitmask for each candidate
4. **Scalar** — fallback for patterns with many possible first bytes

Uses WASM SIMD (simd128): `v128.load`, `i8x16.splat`, `i8x16.swizzle`, `i8x16.eq`, `i8x16.bitmask`, `v128.and`.

#### `engine_onepass.go` — OnePass Engine

**Automaton construction (`newOnePass`):**
- `transFromPC(prog, pc, byte, visited)` — follows epsilon transitions until a byte-consuming instruction; collects `captureOp` records (open/close group index) along the path
- `eofAcceptFromPC` — checks if EOF can match from a given PC
- Transitions stored as u8: `transitions[state*256 + byte]` = next state, 0xFF = dead
- `captureOps[state*256 + byte]` = operations to apply on this transition

**WASM emission (`genOnePassWASM`):**
- Function signature: `(ptr i32, len i32, out_ptr i32) → i32`
- `out_ptr` points to caller-allocated buffer of `numGroups * 2 * 4` bytes
- Slots written: `[start0, end0, start1, end1, ...]` as little-endian i32
- Group 0 (full match): start hardcoded to 0, end written at each accept point
- Capture ops emitted inline as compile-time-known `i32.store` sequences

#### `wasm.go` — WASM Encoding

- `appendSection(out, id, content)` — encodes a WASM section with LEB128 size
- `appendDataSegment(out, offset, data)` — active data segment at fixed memory offset

### 3. Code Generation (`generate/`)

**WASM export names = func names.** The value of `match_func`, `find_func`, `groups_func`, or `named_groups_func` is used directly as the WASM export name. This ensures unique export names in merged WASMs and removes the need for special-casing `match` (a Rust keyword).

**Rust stubs** (`generate/generate.go` + `rust_stub.go`):

| Field | WASM export | Generated function | Rust type |
|---|---|---|---|
| `match_func` | `<func>` | `<func>(input)` | `Option<usize>` |
| `find_func` | `<func>` | `<func>(input)` | `FindIter` — yields `(usize, usize)` |
| `groups_func` | `<func>` | `<func>(input)` | `GroupsIter` — yields `Vec<Option<(usize,usize)>>` |
| `named_groups_func` | `<func>` | `<func>(input)` | `NamedGroupsIter` — yields `HashMap<&str,(usize,usize)>` |

All FFI declarations use `ffi_<func>` internally with `#[link_name = "<func>"]` to avoid collision with the public Rust wrapper of the same name. Iterators advance past zero-length matches by one byte.

When multiple entries share the same `stub_file`, each is wrapped in `pub mod <import_module> { }`. Single-entry files have no mod block.

**JS stubs** (`generate/js_stub.go`):

Generated as a single ES module using top-level `await`. Loads the merged WASM (`output` field) and exports:

| Field | JS export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `boolean` |
| `find_func` | `function* <func>(input)` | generator of `[start, end]` |
| `groups_func` | `function* <func>(input)` | generator of `Array<[start,end]\|null>` |
| `named_groups_func` | `function* <func>(input)` | generator of `Object` (name→`[start,end]`) |

Input `string` or `Uint8Array`. Capture slot buffer placed at memory offset 1024.

**Dummy main** (`generate/dummy_main.go`): 25-byte WASM with 2-page memory export; used as `--wasm-input` for browser deployments.

### 4. WASM Merging (`merge/`)

**File:** `merge.go`

1. Verify each regex WASM imports memory from `"main"` (`isRegexWasm`)
2. Find highest data segment end across all regex WASMs (`regexMemoryTop`)
3. Patch main module memory section to fit all tables (`patchMemoryMin`)
4. Write patched main to temp file
5. Invoke `wasm-merge`: `wasm-merge <main> main <regex1> <module1> ... --enable-simd -o output`

### 5. Utilities (`utils/`)

**File:** `bytes.go`

- `AppendULEB128` / `DecodeULEB128` — unsigned LEB128
- `AppendSLEB128` / `DecodeSLEB128` — signed LEB128
- `PageAlign(n)` — rounds up to 64KB boundary
- `RustMemTop(path)` — scans WASM data segments and globals to find the highest used address

## Testing

### RE2 exhaustive test (`re2test/`)

```bash
make re2test     # from repo root
# or
make test        # from re2test/
```

Test data is unpacked from `$GOROOT/src/regexp/testdata/re2-exhaustive.txt.bz2`.

**Current results:** ~4.68M passing, 0 failures, ~1.03M skipped
- Skipped: Unicode (270K), unsupported `\C` syntax (511K), non-deterministic captures (251K)

Each pattern is compiled and tested for:
- Col 0: anchored match (DFA or OnePass if captures present)
- Col 1: non-anchored find (LeftmostFirst DFA)

### Performance benchmarks (`perftest/`)

```bash
make perftest                                  # from repo root
make perftest WASM_MERGE=/path/to/wasm-merge  # custom wasm-merge
# or
make run        # from perftest/
```

Benchmarks regexped vs regex crate (via wasmtime), showing per-pattern ns/op and speedup factor.
Harnesses must be pre-built with `make harnesses` if changed.

## Memory Layout

```
┌─────────────────┬─────────────────┬─────────────────┬─────┐
│   Rust Stack    │   Rust Heap     │  DFA Table 1    │ ... │
│   & Globals     │   (optional)    │                 │     │
└─────────────────┴─────────────────┴─────────────────┴─────┘
0               rustTop          tableBase1      tableBase2
```

- **rustTop** = highest address used by Rust code (from `RustMemTop`)
- **tableBase** = `PageAlign(rustTop)` — start of first DFA/OnePass table
- Each regex gets a contiguous region; next regex starts at `PageAlign(prevEnd)`

### DFA Table Format

**u8, no compression** (≤ 256 states, small table):
```
[transitions: u8[numStates * 256]]   // state × byte → next_state (0 = dead)
[accept: u8[numStates]]              // 1 if accepting state
```

**u8, compressed** (≤ 256 states, table > 32KB):
```
[class_map: u8[256]]                 // byte → equivalence class
[transitions: u8[numStates * numClasses]]
[accept: u8[numStates]]
```

**u16** (> 256 states):
```
[transitions: u16[numStates * 256]]
[accept: u8[numStates]]
```

Find mode appends additional arrays: `midAccept`, `firstByteFlags` (or Teddy tables), `immediateAccept`, and (for word-boundary patterns) `wordCharTable`, `midAcceptNW`, `midAcceptW`.

### OnePass Table Format

```
[transitions: u8[numStates * 256]]   // state × byte → next_state (0xFF = dead)
```

Capture operations are emitted as inline WASM code, not stored in memory.

## Plans / Pending Work

- **HYBRID_WASM_PLAN.md** — multi-function WASM modules (match + find + groups in one file)
- **CM_PLAN.md** — WASM Component Model support
- **ONEPASS_PLAN.md** — OnePass implementation (complete, file can be deleted)

## Technical Decisions

### Why DFA?

- O(n) worst-case, predictable timing (DoS-resistant)
- No runtime stack usage (WASM-friendly)
- SIMD prefix scan amortizes transition cost for patterns with rare first bytes

### LeftmostFirst DFA

Classical DFA produces leftmost-longest (greedy). To match RE2/Perl semantics:
- `epsilonClosure` sorts NFA states by priority (lower PC = higher priority)
- `immediateAccepting` states stop the DFA as soon as a match is found rather than seeking a longer one
- Handles `|` alternations and non-greedy quantifiers correctly without a separate LazyDFA engine

### Word Boundaries in DFA

`\b`/`\B` require knowing whether the previous byte was a word character. Implemented by:
- Doubling the DFA state space with a `prevWasWord` context bit
- Two mid-start states (`midStart`, `midStartWord`) for the find-mode scan loop
- `ecWordBoundary`/`ecNoWordBoundary` flags in epsilon closure
- `wordCharTable` data segment for O(1) lookup during find prologue

### OnePass Engine

Viable when every `InstAlt` in the NFA has branches with disjoint first-character sets — at each position exactly one NFA thread is active, so capture slots can be updated in a single forward pass. Avoids thread copying overhead of PikeVM or backtracking cost of a general engine.

## Dependencies

- **Go 1.25.7+**
- **gopkg.in/yaml.v3** — YAML parsing
- **github.com/bytecodealliance/wasmtime-go** — wasmtime bindings (re2test only)
- **wasm-merge** (external, Binaryen) — for `merge` command and perftest

---

**Last Updated:** 2026-03-22
**CLI commands:** `generate` (stubs / dummy_main), `compile`, `merge`
**Docs:** `docs/cli.md` (CLI reference), `docs/rust-api.md` (Rust API), `docs/browser.md` (browser embedding), `docs/engines.md` (engine details + roadmap), `docs/wasm.md` (WASM internals)
**Engines implemented:** DFA (anchored + find, LeftmostFirst, word boundaries, SIMD), OnePass (anchored with captures)
