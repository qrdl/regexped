# Regexped CLI Reference

## Configuration File

Regexped is driven by a YAML config file (default: `regexped.yaml` in the current directory).

```yaml
wasm_merge: "wasm-merge"   # path to wasm-merge binary; defaults to $WASM_MERGE env var, then wasm-merge in $PATH
output:   "merged.wasm"    # output path for the merge command; overridable with --output
wasm_file: "regexps.wasm"  # output path for the compile command; overridable with --output
import_module: "mymod"     # WASM module name used by wasm-merge and Rust/Go FFI
stub_file: "src/stubs.rs"  # stub output file; extension determines type: .rs, .js, .ts, .go, .h
stub_type: "rust"          # optional; overrides extension-based type inference: rust, js, ts, go, c, as
max_dfa_states: 1024       # optional; max DFA/TDFA states before falling back to Backtracking (default 1024)
max_tdfa_regs:  32         # optional; max TDFA registers before falling back to Backtracking (default 32)

regexes:
  - pattern: 'https?://...' # RE2 regex pattern

    # One or more func fields — only those set are compiled and stubbed.
    # The func name becomes both the WASM export name and the generated function name.
    # An entry with only 'pattern' is valid; no code is generated for it.
    match_func:        "url_match"         # anchored match
    find_func:         "url_find"          # non-anchored find
    groups_func:       "url_groups"        # anchored match with all capture groups
    named_groups_func: "url_named_groups"  # anchored match with named capture groups
```

All paths in the config file are resolved relative to the config file's directory.

### Engine selection

Setting `groups_func` or `named_groups_func` triggers capture-tracking compilation:
- **TDFA engine** — used when the pattern has no non-greedy quantifiers, no line anchors, no word boundaries, and no ambiguous alternations (Laurikari's tagged DFA, O(n))
- **Backtracking engine** — used automatically as a fallback for patterns that are not TDFA-eligible (e.g. `(a|ab)`, `(a*)(a*)`)

Setting only `match_func` and/or `find_func` uses the **DFA engine**. Capture groups are stripped from the pattern before compilation.

See [engines.md](engines.md) for full details on engine selection and capabilities.

### Pattern support

Regexped uses RE2 syntax. Backreferences are not supported by design.

| Feature | Supported |
|---|---|
| Literal characters | Yes |
| Character classes `[a-z]`, `\d`, `\w` | Yes |
| Anchors `^`, `$` | Yes |
| Repetition `*`, `+`, `?`, `{n,m}` | Yes |
| Non-greedy quantifiers `*?`, `+?` | Yes |
| Alternation `\|` (LeftmostFirst / RE2 semantics) | Yes |
| Word boundaries `\b`, `\B` | Yes |
| Capture groups (TDFA engine — O(n)) | Yes |
| Capture groups (Backtracking engine) | Yes |
| Backreferences `\1` | No |
| Lookahead / lookbehind | No |
| Unicode beyond ASCII | No |

---

## Global flags

These flags must appear before the subcommand name.

| Flag | Default | Description |
|---|---|---|
| `--debug` | off | Enable debug logging. By default only warnings are printed. |

```bash
regexped --debug compile --config=regexped.yaml
```

---

## Commands

All commands validate their required options and config fields before doing any work.

### `generate` — Generate language stubs

```
regexped [--debug] generate [--config=<file>] [--output=<file>|-]
```

Generates a stub file (Rust, JS, TypeScript, Go, or C) from the config. The stub type is determined by:

1. `stub_type` field in YAML (`rust`, `js`, `ts`, `go`, `c`, `as`)
2. Extension of `stub_file` in YAML (`.rs` → rust, `.js` → js, `.ts` → ts, `.go` → go, `.h` → c)
3. Error if neither resolves to a known type

> **Note:** AssemblyScript source files use the `.ts` extension (same as TypeScript). Set `stub_type: "as"` explicitly — extension-based inference always resolves `.ts` to the TypeScript ES module stub.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--output`, `-o` | config `stub_file` | Output file; `-` writes to stdout |

**Required config fields:**

| Field | Notes |
|---|---|
| `stub_file` | Required unless `--output` is given |
| `stub_type` or `stub_file` extension | Determines output language |
| `import_module` | Required for Rust, Go, C, and AS stubs |

#### Rust stubs

All entries are wrapped in a single `pub mod <import_module> { }` block.

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<func>(input)` | `Option<usize>` |
| `find_func` | `<func>(input)` | `FindIter` — yields `(usize, usize)` per match |
| `groups_func` | `<func>(input)` | `GroupsIter` — yields `Vec<Option<(usize, usize)>>` per match |
| `named_groups_func` | `<func>(input)` | `NamedGroupsIter` — yields `HashMap<&'static str, (usize, usize)>` per match |

See [rust-api.md](rust-api.md) for full usage examples.

#### Go stubs (`GOOS=wasip1`)

Generates a `//go:build wasip1` file using `//go:wasmimport` declarations plus a `//go:build !wasip1` host stub for IDE compatibility.
Requires `import_module` in config (used as the Go package name).
Requires Go 1.23+ (iterators use `iter.Seq2` / `iter.Seq`).

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<PascalCase>(input []byte)` | `(int, bool)` — end pos and match flag |
| `find_func` | `<PascalCase>(input []byte)` | `iter.Seq2[int, int]` — (start, end) per match |
| `groups_func` | `<PascalCase>(input []byte)` | `iter.Seq[[][]int]` — slice of [start,end] per match |
| `named_groups_func` | `<PascalCase>(input []byte)` | `iter.Seq[map[string][]int]` — name→[start,end] per match |

Function names are derived by converting `snake_case` config names to `PascalCase`
(e.g. `url_match` → `UrlMatch`).

#### JS stubs

Generates a single ES module. Exports an `init(wasm)` function that must be called with the WASM bytes or a pre-compiled `WebAssembly.Module` before any matcher is used.

| Config field | Generated JS export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `boolean` — true if full input matches |
| `find_func` | `function* <func>(input)` | generator yielding `[start, end]` per match |
| `groups_func` | `function* <func>(input)` | generator yielding `Array<[start,end]\|null>` per match |
| `named_groups_func` | `function* <func>(input)` | generator yielding `Object` (name→`[start,end]`) per match |

#### TS stubs

Same as JS stubs but with TypeScript type annotations.

#### C stubs

Generates a single `#pragma once` header file. Requires `import_module` in config.
No libc or sysroot required — uses `__attribute__((import_module(...), import_name(...)))` for WASM imports.

| Config field | Generated functions | Notes |
|---|---|---|
| `match_func` | `<func>(input, len)` | Returns end position (≥0) or -1 |
| `find_func` | `<func>_next(input, len, *start, *end)` + `<func>_reset()` | Static offset state; call reset before iterating |
| `groups_func` | `<func>_next(input, len, slots[])` + `<func>_reset()` | `slots[i*2]`/`[i*2+1]` = start/end for group i; -1 if absent |
| `named_groups_func` | same as groups + `<func>_get(slots, name, *start, *end)` | Hardcoded name→index mapping |

#### AS stubs (AssemblyScript)

Generates a single AssemblyScript `.ts` file using `@external` declarations. Requires `import_module` in config. Must set `stub_type: "as"` — `.ts` extension alone infers TypeScript.

**`named_groups_func` is not supported for AS stubs.** Use `groups_func` and access slots by index instead.

Input is `ArrayBuffer` (use `String.UTF8.encode(str)` to convert from string). All functions are stateless — the caller passes an `offset` argument and no module-level state is mutated.

| Config field | Generated function | Returns |
|---|---|---|
| `match_func` | `<func>(input: ArrayBuffer): i32` | End position (≥0) or -1 if no match |
| `find_func` | `<func>(input: ArrayBuffer, offset: i32): i64` | Packed `(absStart << 32 \| absEnd)` or -1 if not found |
| `groups_func` | `<func>(input: ArrayBuffer, offset: i32): i32` | `dataStart` pointer to static `Int32Array` slots, or 0 on no match |

See [as-api.md](as-api.md) for full usage examples and slot layout.

---

### `compile` — Compile patterns to WASM

```
regexped [--debug] compile [--config=<file>] [--output=<file>|-]
```

Compiles each regex pattern to a single WASM module. The output mode is selected automatically based on the config:

- **Standalone** (no `output` field in config) — the module owns its memory, DFA/TDFA tables start at address 0. Load directly in JS/TS without merging.
- **Embedded** (`output` field present) — the module imports memory from a `"main"` host module. Use `regexped merge` to combine with a Rust/Go/C host binary.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--output`, `-o` | config `wasm_file` | Output WASM file; `-` writes to stdout |

**Required config fields:**

| Field | Notes |
|---|---|
| `wasm_file` | Required unless `--output` is given |
| `regexes` | One or more patterns to compile |

Entries with no `_func` fields are silently skipped.

---

### `merge` — Merge WASM modules

```
regexped [--debug] merge [--config=<file>] --main=<file> [--output=<file>|-] <regex1.wasm> ...
```

Merges the host main WASM with one or more regex WASM modules into a single binary using `wasm-merge`. Each regex module's memory is kept separate (multi-memory) and renumbered by wasm-merge.

This command is a thin wrapper around `wasm-merge`. You may invoke wasm-merge directly with:

```
wasm-merge --enable-multimemory --enable-simd --enable-bulk-memory --enable-bulk-memory-opt \
  <main.wasm> main <regex.wasm> <module_name> ... \
  --rename-export-conflicts -o output.wasm
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--main` | — | Host main WASM file **(required)** |
| `--output`, `-o` | config `output` | Output WASM file; `-` writes to stdout |

**Positional arguments:** one or more regex WASM files (at least one required).

**Required config fields:**

| Field | Notes |
|---|---|
| `output` | Required unless `--output` is given |
| `wasm_merge` | Optional; path to wasm-merge binary; defaults to `$WASM_MERGE` env var, then `wasm-merge` in $PATH |
| `import_module` | Optional; module name passed to wasm-merge; defaults to basename of the regex WASM |

---

## Typical workflows

### Rust deployment

```bash
# 1. Generate Rust stubs
regexped generate --config=regexped.yaml

# 2. Build your Rust project to WASM
cargo build --target wasm32-wasip1 --release

# 3. Compile regex patterns to WASM (no --main needed)
regexped compile --config=regexped.yaml

# 4. Merge into a single binary
regexped merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm pattern.wasm
```

### Go deployment

```bash
# 1. Generate Go stubs
regexped generate --config=regexped.yaml

# 2. Compile regex patterns to WASM (no --main needed)
regexped compile --config=regexped.yaml

# 3. Build your Go project to WASM
GOOS=wasip1 GOARCH=wasm go build -o app.wasm .

# 4. Merge into a single binary
regexped merge --config=regexped.yaml --main=app.wasm regex.wasm
```

### JS / Browser / Cloudflare Worker deployment

```bash
# 1. Compile regex patterns to WASM (standalone, no merge needed)
regexped compile --config=regexped.yaml

# 2. Generate JS/TS stub
regexped generate --config=regexped.yaml

# 3. Load the compiled WASM directly in your JS/TS code:
#    await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```

See [`examples/`](../examples/) for complete self-contained projects with Makefiles.
