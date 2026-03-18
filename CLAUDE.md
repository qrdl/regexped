# Regexped WASM - Project Overview

## Purpose

**Regexped** is a Go-based compiler that transforms regular expression patterns into standalone WebAssembly (WASM) modules. It analyzes regex patterns, compiles them to optimized Deterministic Finite Automaton (DFA) implementations, generates WASM bytecode, and produces language-specific stubs for integration with host applications.

The project enables embedding high-performance regex matchers directly into WASM applications without shipping a full regex engine, reducing binary size and improving performance predictability.

## Architecture

### High-Level Flow

```
YAML Config → Parse Patterns → Select Engine → Compile DFA → Generate WASM → Generate Stubs → Merge Modules
     ↓              ↓               ↓              ↓              ↓              ↓              ↓
  config/      compile/        compile/       compile/       compile/      generate/      merge/
```

### Directory Structure

```
regexped_wasm/
├── main.go                    # CLI entry point with subcommands: stub, compile, merge
├── config/
│   └── config.go              # YAML configuration parsing
├── compile/
│   ├── compile.go             # CmdCompile orchestration
│   ├── compile_engine.go      # Pattern compilation entry point
│   ├── selector.go            # Engine selection heuristics
│   ├── engine_types.go        # Engine interface and types
│   ├── dfa_engine.go          # DFA subset construction (NFA→DFA)
│   ├── dfa.go                 # DFA table generation and WASM emission
│   ├── onepass_check.go       # One-pass DFA detection
│   └── wasm.go                # WASM binary encoding primitives
├── generate/
│   ├── generate.go            # Stub generation orchestration
│   └── rust_stub.go           # Rust FFI stub generator
├── merge/
│   └── merge.go               # WASM module merging with wasm-merge
└── utils/
    └── bytes.go               # WASM primitives (LEB128, page alignment)
```

## Components

### 1. Configuration (`config/`)

**Files:** `config.go`

Parses YAML configuration files with the schema:

```yaml
wasm_merge: "path/to/wasm-merge"  # Optional, defaults to $PATH
output: "merged.wasm"             # Default output path
regexes:
  - wasm_file: "url_regex.wasm"
    import_module: "url_regex"
    stub_file: "url_regex.rs"
    export_name: "url_match_anchored"
    func_name: "url_match"
    pattern: "^https?://[a-z0-9.-]+\\.[a-z]{2,}(/.*)?$"
```

**Responsibilities:**
- Load and validate YAML configuration
- Resolve paths relative to config file directory
- Provide structured config to compilation pipeline

### 2. Compilation (`compile/`)

The heart of the project. Converts regex patterns to WASM DFA matchers.

#### Key Files

**`compile.go`** - Orchestrates compilation for all patterns
- Reads pre-built WASM to determine memory layout (`utils.RustMemTop`)
- Compiles each regex sequentially, tracking table base addresses
- Allocates DFA tables at page-aligned memory addresses

**`compile_engine.go`** - Pattern compilation API
- `compile(pattern, opts) -> Matcher` - Main entry point
- Pattern parsing with Go's `regexp/syntax` package
- Unicode support detection
- Engine selection (forced or automatic)

**`selector.go`** - Sophisticated engine selection
- Analyzes pattern complexity (alternations, anchors, captures, quantifiers)
- Estimates DFA state count and memory usage
- Selects optimal engine from: DFA, Backtrack, OnePass, PikeVM, LazyDFA, AdaptiveNFA
- **Currently only DFA is implemented for WASM generation**

Key selection logic:
- **DFA**: Fast, simple patterns without anchors/captures/alternations
- **Backtrack/PikeVM**: Patterns with captures, word boundaries, nested quantifiers
- **LazyDFA**: Patterns with user alternations (leftmost-first semantics)
- **OnePass**: Rare deterministic patterns with captures

**`dfa_engine.go`** - DFA subset construction
- Converts NFA bytecode (`syntax.Prog`) to DFA via subset construction
- Epsilon closure computation
- Case-folding support (Unicode SimpleFold)
- Anchor detection (begin/end anchors)
- Produces `dfa` struct with state transitions

**`dfa.go`** - DFA table generation and WASM emission
- `dfaTableFrom()` - Converts `dfa` struct to flat transition tables
- `computeByteClasses()` - Byte class compression for smaller tables
- `genWASM()` - Emits WASM module with DFA matcher function

WASM module structure:
```wasm
;; Imports memory from "main" module
(import "main" "memory" (memory 1))

;; Exports match function
(export "pattern_match" (func $match))

;; Function: (ptr: i32, len: i32) -> i32
;; Returns: end position (0..len) or -1 (no match)
(func $match (param $ptr i32) (param $len i32) (result i32)
  ;; DFA execution loop
  ;; Transition table stored at fixed memory address
)

;; Data section: DFA transition table
(data (i32.const <table_base>) "...")
```

**`onepass_check.go`** - Detects one-pass patterns
- Checks if alternations have disjoint first character sets
- Validates pattern is small enough (<100 instructions)

**`wasm.go`** - WASM binary encoding helpers
- `appendSection()` - Adds WASM sections (type, import, function, export, code, data)
- `appendDataSegment()` - Embeds DFA tables in WASM data section

#### Engine Selection Details

The selector performs deep pattern analysis:

**Pattern Features Analyzed:**
- Alternations (user vs quantifier loops)
- Nested quantifiers
- Anchors (^, $, \A, \z, \b, \B)
- Capture groups
- Unicode requirements
- DFA state explosion risk

**Decision Tree:**
1. **OnePass** - If deterministic alternations and small (<50 instructions)
2. **Backtrack/AdaptiveNFA** - If word boundaries or captures
3. **PikeVM** - If anchors (position-dependent matching)
4. **LazyDFA** - If user alternations without end anchors
5. **DFA** - If simple pattern fits memory budget
6. **Backtrack** - Default fallback

**Critical Limitations of Classical DFA:**
- Cannot handle leftmost-first semantics for alternations
- Cannot track capture groups
- Cannot implement position-dependent anchors
- Produces longest-match instead of leftmost-first for nested quantifiers

### 3. Stub Generation (`generate/`)

**Files:** `generate.go`, `rust_stub.go`

Generates language-specific wrapper functions that call WASM exports.

**Rust Stub Example:**
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

**Planned extensions:**
- Go stubs
- WIT (WebAssembly Interface Types) bindings

### 4. WASM Merging (`merge/`)

**Files:** `merge.go`

Combines main WASM module with regex WASM modules.

**Process:**
1. Validate regex WASM modules (check for memory import from "main")
2. Calculate required memory from data segments (`regexMemoryTop()`)
3. Patch main module's memory section to accommodate regex tables
4. Invoke external `wasm-merge` tool to combine modules
5. Remap import module names from config

**Why Memory Patching?**
- Regex DFAs are embedded as data segments at compile-time addresses
- Main module must allocate enough initial memory pages
- Memory layout must be consistent: `[Rust data][DFA tables...]`

### 5. Utilities (`utils/`)

**Files:** `bytes.go`

Low-level WASM operations:

- **LEB128 Encoding/Decoding** - WASM variable-length integers
  - `AppendULEB128` / `DecodeULEB128` (unsigned)
  - `AppendSLEB128` / `DecodeSLEB128` (signed)
- **Memory Alignment** - `PageAlign()` rounds to 64KB boundaries
- **WASM Parsing** - `RustMemTop()` scans data segments and globals

## Commands

### `stub` - Generate Language Stubs

```bash
regexped-wasm stub --config=regexped.yaml --out-dir=. --rust
```

Generates Rust FFI wrappers for each regex in config.

### `compile` - Compile Patterns to WASM

```bash
regexped-wasm compile --config=regexped.yaml \
  --wasm-input=main.wasm \
  --out-dir=build
```

**Inputs:**
- Config file with regex patterns
- Pre-built main WASM module (to measure memory layout)

**Outputs:**
- One WASM module per regex (e.g., `url_regex.wasm`)
- DFA tables embedded as data segments

**Process:**
1. Parse `main.wasm` to find Rust memory top
2. For each regex:
   - Compile pattern to DFA
   - Allocate table at page-aligned address
   - Generate WASM module with match function
   - Emit to `out-dir`

### `merge` - Merge WASM Modules

```bash
regexped-wasm merge --config=regexped.yaml \
  --output=final.wasm \
  main.wasm url_regex.wasm email_regex.wasm
```

Patches memory and combines modules using `wasm-merge` tool.

## Planned Extensions

### 1. More Engine Types

Currently only DFA is implemented for WASM. Future engines:

- **Backtracking** - Full RE2 feature support (captures, anchors)
- **LazyDFA** - On-demand DFA construction with leftmost-first
- **PikeVM** - NFA simulation with capture group tracking
- **OnePass** - Optimized DFA for deterministic patterns

### 2. More Stub Languages

Currently only Rust is supported. Planned:

- **Go** - `cgo` or `wazero` bindings
- **WIT** - WebAssembly Component Model interface types
- **JavaScript** - For WASI-compatible runtimes

### 3. Extended Match Modes

From `NONANCHORED_PLAN.md`:

**Current:** Anchored match at position 0
```rust
url_match(input: &[u8]) -> Option<usize>  // Returns end position or None
```

**Planned:** Non-anchored find
```rust
url_find(input: &[u8]) -> Option<(usize, usize)>  // Returns (start, end) or None
```

**Implementation:**
- Build reverse DFA for backward scan
- Forward scan finds end position
- Backward scan from end finds start position
- Return packed i64: `(start << 32) | end`

### 4. WASM Component Model

Target the Component Model for better interoperability:
- Canonical ABI for strings/bytes
- Composable components
- Language-agnostic interfaces

## Technical Decisions & Trade-offs

### Why DFA?

**Advantages:**
- O(n) worst-case performance (vs exponential backtracking)
- Predictable execution time (critical for DoS prevention)
- No stack usage (WASM-friendly)
- Small generated code

**Disadvantages:**
- State explosion for complex patterns
- Cannot support captures or backreferences
- Leftmost-first semantics require special handling
- Memory usage grows with pattern complexity

### Why WASM?

**Advantages:**
- Sandboxed execution
- Near-native performance
- Portable across architectures
- Embeddable in any WASM runtime
- No regex engine dependency at runtime

**Disadvantages:**
- Compile-time pattern fixing (no runtime pattern changes)
- Requires build step
- Module size overhead for small patterns

### Why Go for Compiler?

- Excellent regex parsing via `regexp/syntax`
- Strong WASM binary manipulation support
- Fast compilation
- Cross-platform toolchain

## Dependencies

- **Go 1.25.7+** (go.mod specifies this)
- **gopkg.in/yaml.v3** - YAML configuration parsing
- **wasm-merge** (external) - BINARYEN tool for merging WASM modules

## Development Notes

### Memory Layout

```
┌─────────────────┬─────────────────┬─────────────────┬─────┐
│   Rust Stack    │   Rust Heap     │  DFA Table 1    │ ... │
│   & Globals     │   (optional)    │                 │     │
└─────────────────┴─────────────────┴─────────────────┴─────┘
0               rustTop          tableBase1      tableBase2
                  ↑                  ↑
                  │                  │
            From main.wasm    Page-aligned
```

- **rustTop** = highest address used by Rust code
- **tableBase** = page-aligned address for DFA tables
- Each regex gets a dedicated memory region

### DFA Table Format

**Uncompressed (small DFAs):**
```
[transitions: u8[numStates * 256]]  // Flat array: state × input_byte → next_state
[flags: u8[numStates]]              // Accept flags: 1 if accepting
```

**Compressed (large DFAs):**
```
[class_map: u8[256]]                // Byte → equivalence class
[transitions: u8[numStates * numClasses]]
[flags: u8[numStates]]
```

Classes reduce memory when many bytes have identical transitions.

### Testing Strategy

See `RE2_TEST_PLAN.md` for comprehensive test planning (anchored patterns).

**Current Focus:**
- Anchored matching (`^pattern$` style)
- ASCII patterns
- DFA-compatible patterns only

**Future Testing:**
- Non-anchored find mode
- Unicode patterns
- All engine types

## Refactoring Opportunities

### 1. **compile/** directory is monolithic

**Current Issues:**
- `compile_engine.go`, `selector.go`, `engine_types.go` are conceptually distinct from DFA implementation
- WASM generation mixed with DFA logic
- Future engines will crowd the directory

**Proposed Structure:**
```
compile/
├── compiler.go              # Public API: compile(pattern) -> CompiledRegex
├── selector/
│   ├── selector.go          # Engine selection logic
│   ├── analysis.go          # Pattern complexity analysis
│   └── cost_model.go        # Memory/performance estimation
├── engines/
│   ├── engine.go            # Common Matcher interface
│   ├── dfa/
│   │   ├── dfa.go           # DFA subset construction
│   │   ├── table.go         # Table generation
│   │   └── onepass.go       # One-pass detection
│   ├── backtrack/           # Future
│   ├── pikevm/              # Future
│   └── lazy_dfa/            # Future
└── wasm/
    ├── encoder.go           # WASM binary encoding
    ├── dfa_gen.go           # DFA→WASM code generation
    └── backtrack_gen.go     # Future
```

**Benefits:**
- Clear separation of concerns
- Each engine is self-contained
- WASM generation separated from algorithm
- Easier to add new engines

### 2. **Tight coupling between DFA and WASM generation**

`dfa.go` contains both DFA table logic and WASM emission. Consider:
- `engines/dfa/table.go` - Pure DFA table construction
- `wasm/dfa_gen.go` - WASM encoding of DFA tables

### 3. **Engine interface can be more explicit**

Current `Matcher` interface is minimal. Consider:

```go
type CompiledRegex interface {
    Type() EngineType
    Match(input []byte) int           // Anchored match
    Find(input []byte) (start, end)   // Non-anchored find
    NumStates() int                   // For DFA engines
    EstimateMemory() int
}

type WasmEmitter interface {
    EmitWasm(tableBase int64, exportName string) []byte
}
```

### 4. **Selector logic could use a strategy pattern**

Instead of one massive `selectBestEngine()` function:

```go
type EngineSelector interface {
    CanHandle(analysis *PatternAnalysis) bool
    Priority() int
    Select(analysis *PatternAnalysis) EngineType
}

// Register selectors in priority order
var selectors = []EngineSelector{
    OnePassSelector{},
    WordBoundarySelector{},
    CaptureGroupSelector{},
    DFASelector{},
    BacktrackSelector{},  // Always returns true (fallback)
}
```

### 5. **Configuration could support per-pattern options**

```yaml
regexes:
  - pattern: "^[a-z]+$"
    engine: dfa              # Force DFA
    max_dfa_states: 10000
  - pattern: "(\\w+)@(\\w+)"
    engine: auto             # Let selector choose
```

### 6. **Consider separating CLI from library**

```
cmd/regexped-wasm/        # CLI (current main.go)
pkg/
  ├── config/
  ├── compiler/
  ├── generator/
  └── merger/
```

Enables use as a Go library in other tools.

## Key Insights for Extension

### Adding Go Stubs

```go
//go:wasmimport url_regex url_match_anchored
func urlMatchAnchored(ptr uintptr, len int) int

func UrlMatch(input []byte) (int, bool) {
    if len(input) == 0 {
        return -1, false
    }
    result := urlMatchAnchored(uintptr(unsafe.Pointer(&input[0])), len(input))
    if result >= 0 {
        return result, true
    }
    return -1, false
}
```

### Adding WIT Bindings

```wit
interface regex {
    match: func(input: list<u8>) -> option<u32>
    find: func(input: list<u8>) -> option<tuple<u32, u32>>
}
```

### Implementing Backtracking Engine

Key requirements:
- Stack-based state tracking (challenging in WASM without recursion)
- Visited state set (memoization)
- Instruction pointer traversal
- Consider compiling to WASM loop with explicit stack in linear memory

## Performance Characteristics

**DFA Matching:**
- Time: O(n) where n = input length
- Space: O(1) runtime stack, O(states × alphabet) precomputed table
- Typical: 100-5000 states, 25-65KB memory

**Compilation:**
- Time: O(2^n) worst case (subset construction), O(n²) typical
- Space: O(2^n) worst case (state explosion)
- Typical: <100ms for most patterns

## Related Documentation

- `NONANCHORED_PLAN.md` - Non-anchored find mode design
- `RE2_TEST_PLAN.md` - Test strategy for RE2 compatibility
- `go.mod` - Dependency versions

## Maintainer Notes

**Before adding new engines:**
1. Implement selector logic first
2. Add engine-specific tests
3. Update WASM generator to support new bytecode format
4. Generate stub signatures appropriately

**Before adding new stub languages:**
1. Define stub template
2. Handle type conversions (bytes, strings, options)
3. Update `generate/` package

**Before implementing Component Model:**
1. Evaluate `wit-bindgen` for interface generation
2. Update WASM output format (sections, linkage)
3. Revise stub generation entirely

---

**Last Updated:** 2026-03-18
**Version:** Supports DFA engine only, anchored matching, Rust stubs
